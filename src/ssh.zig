//! SSH user authentication: password and public key, with timing
//! equalization and failure ceilings.
//!
//! Every password denial runs one Argon2id and every public-key denial one
//! key import + compare, so response time does not reveal whether a user
//! exists or which credentials it has.

const std = @import("std");
const c = @import("libssh");
const abuse = @import("abuse.zig");
const audit = @import("audit.zig");
const config = @import("config.zig");
const netmatch = @import("netmatch.zig");
const passhash = @import("passhash.zig");
const sys = @import("sys.zig");

pub fn authenticate(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    session: c.ssh_session,
    ip_str: []const u8,
    deadline_ms: i64,
) !*const config.UserConfig {
    errdefer |err| if (err == error.LoginGraceExpired) {
        audit.log(io, null, "auth.rejected", null, .denied, "login grace expired", ip_str);
    };

    // Two ceilings.
    //
    // HARD failures are real credential rejections: a wrong or unknown-
    // user password, or a password from outside `from`. (libssh drops a
    // key with a bad signature before Zift sees it, so the pubkey
    // `hard_denied` path is defensive.) They feed the abuse table and the backoff,
    // and 6 (OpenSSH's MaxAuthTries) end the session.
    //
    // SOFT operations are `none`, non-auth messages, and public-key
    // probes (offers, unconfigured keys, a public-key `from` miss). A
    // stock client sends one per agent key before trying a password, so
    // they get no backoff and no abuse credit, only a count bound; the
    // login grace bounds the time. A public-key `from` miss is soft so
    // that it cannot be told apart from an unknown user.
    const max_hard_failures: u32 = 6;
    var hard_failures: u32 = 0;
    var soft_ops: u32 = 0;
    while (true) {
        // Suppression by another session applies here too.
        if (abuse.isSuppressed(io, ip_str, sys.monotonicMs())) {
            audit.log(io, null, "auth.rejected", null, .denied, "source suppressed", ip_str);
            return error.LibsshFailure;
        }

        try boundRead(session, cfg.server.idle_timeout_ms, deadline_ms);
        const msg = c.ssh_message_get(session) orelse
            return if (sys.monotonicMs() >= deadline_ms) error.LoginGraceExpired else error.LibsshFailure;
        defer c.ssh_message_free(msg);

        if (c.ssh_message_type(msg) != c.SSH_REQUEST_AUTH) {
            try countSoft(io, &soft_ops, ip_str);
            _ = c.ssh_message_reply_default(msg);
            continue;
        }

        const subtype: c_uint = @intCast(c.ssh_message_subtype(msg));

        // Every auth subtype carries a username; it picks the methods
        // list sent on failure (see `methodsForUser`).
        const username_ptr = c.ssh_message_auth_user(msg);
        const username_for_methods: ?[]const u8 = if (username_ptr != null)
            std.mem.span(username_ptr)
        else
            null;

        // `none` and unknown methods stay soft.
        var is_hard = false;

        if (subtype == c.SSH_AUTH_METHOD_PASSWORD) {
            const password_ptr = c.ssh_message_auth_password(msg);
            if (username_ptr != null and password_ptr != null) {
                const username = std.mem.span(username_ptr);
                const password = std.mem.span(password_ptr);
                const user = cfg.findUser(username);
                const allowed = if (user) |u| netmatch.allowed(u.from, ip_str) else false;
                // An unknown user or a `from` miss still pays the KDF, so
                // timing hides the username.
                if (try verifyPassword(io, allocator, if (allowed) user.?.password_hash else null, password, deadline_ms)) {
                    _ = c.ssh_message_auth_reply_success(msg, 0);
                    audit.log(io, username, "auth.password", null, .ok, "", ip_str);
                    return user.?;
                }
                const detail = if (user == null) "unknown user" else if (!allowed) "source not allowed" else "bad password";
                audit.log(io, username, "auth.password", null, .denied, detail, ip_str);
                is_hard = true;
            }
        } else if (subtype == c.SSH_AUTH_METHOD_PUBLICKEY) {
            const decision = handlePublicKeyMessage(io, allocator, cfg, msg, ip_str);
            switch (decision) {
                .accepted => |user| return user,
                .offered => {
                    // `pk_ok` was sent; wait for the signed follow-up.
                    try countSoft(io, &soft_ops, ip_str);
                    continue;
                },
                .hard_denied => is_hard = true,
                .soft_denied => {},
            }
        }

        if (is_hard) {
            hard_failures += 1;
            const now_ms = sys.monotonicMs();
            abuse.recordFailure(io, ip_str, now_ms);
            // Tripping suppression ends this session now.
            if (abuse.isSuppressed(io, ip_str, now_ms)) {
                audit.log(io, null, "auth.rejected", null, .denied, "source suppressed", ip_str);
                return error.LibsshFailure;
            }
            if (hard_failures >= max_hard_failures) {
                audit.log(io, null, "auth.too_many_attempts", null, .denied, "", ip_str);
                return error.LibsshFailure;
            }
            // Backoff: 250 ms per failure so far, at most 1.25 s.
            std.Io.sleep(io, .fromMilliseconds(hard_failures * 250), .awake) catch {};
        } else {
            try countSoft(io, &soft_ops, ip_str);
        }

        _ = c.ssh_message_auth_set_methods(msg, methodsForUser(cfg, username_for_methods));
        _ = c.ssh_message_reply_default(msg);
    }
}

/// Count one soft operation (see `authenticate`); fails at the bound.
fn countSoft(io: std.Io, soft_ops: *u32, ip_str: []const u8) error{LibsshFailure}!void {
    const max_soft_ops: u32 = 64;
    soft_ops.* += 1;
    if (soft_ops.* < max_soft_ops) return;
    audit.log(io, null, "auth.too_many_attempts", null, .denied, "probes", ip_str);
    return error.LibsshFailure;
}

/// From accept to successful authentication, key exchange included.
/// Fixed, like OpenSSH's LoginGraceTime: libssh restarts the idle timer
/// on every message, so idle alone lets a client hold a pre-auth slot
/// for hours.
pub const login_grace_ms: i64 = 120 * 1000;

/// Bound libssh's next blocking read by the idle timeout (0 = none) and
/// the login deadline.
pub fn boundRead(session: c.ssh_session, idle_ms: u64, deadline_ms: i64) error{LoginGraceExpired}!void {
    setReadTimeout(session, try readTimeoutMs(idle_ms, deadline_ms, sys.monotonicMs()));
}

fn readTimeoutMs(idle_ms: u64, deadline_ms: i64, now_ms: i64) error{LoginGraceExpired}!u64 {
    if (now_ms >= deadline_ms) return error.LoginGraceExpired;
    const left: u64 = @intCast(deadline_ms - now_ms);
    return if (idle_ms == 0) left else @min(idle_ms, left);
}

/// libssh's timeout for each blocking read; 0 waits forever. libssh
/// rounds a total under 1 ms to 0, so callers pass whole milliseconds.
pub fn setReadTimeout(session: c.ssh_session, ms: u64) void {
    const seconds: c_long = @intCast(ms / 1000);
    const usec: c_long = @intCast((ms % 1000) * 1000);
    _ = c.ssh_options_set(session, c.SSH_OPTIONS_TIMEOUT, &seconds);
    _ = c.ssh_options_set(session, c.SSH_OPTIONS_TIMEOUT_USEC, &usec);
}

/// One Argon2id under a KDF slot, against `hash` or, when null, a dummy,
/// so every password denial costs the same as a real verify.
fn verifyPassword(
    io: std.Io,
    allocator: std.mem.Allocator,
    hash: ?[]const u8,
    password: []const u8,
    deadline_ms: i64,
) error{LoginGraceExpired}!bool {
    try acquireKdfSlot(io, deadline_ms);
    defer releaseKdfSlot();
    const ok = passhash.verify(io, allocator, password, hash orelse dummy_hash);
    return ok and hash != null;
}

/// Minted from a random password that was then discarded.
const dummy_hash = "aUCxJ9zfsJYoIY84XNe5oVcKvG2pwBeh";

/// Argon2id runs in flight, process-wide. Each takes 64 MiB, so unbounded
/// a flood of bad logins exhausts memory before the abuse table has
/// counted a single failure.
var kdf_in_use: std.atomic.Value(u32) = .init(0);
/// CPU count clamped to 2..8; 0 until first use.
var kdf_slots: std.atomic.Value(u32) = .init(0);

fn kdfSlots() u32 {
    var n = kdf_slots.load(.monotonic);
    if (n == 0) {
        n = @intCast(std.math.clamp(std.Thread.getCpuCount() catch 2, 2, 8));
        kdf_slots.store(n, .monotonic);
    }
    return n;
}

/// Wait for a KDF slot until `deadline_ms`. Polls: a wait is about one
/// KDF long, and `std.Io.Condition` has no timed wait.
fn acquireKdfSlot(io: std.Io, deadline_ms: i64) error{LoginGraceExpired}!void {
    const slots = kdfSlots();
    while (true) {
        const n = kdf_in_use.load(.monotonic);
        if (n < slots) {
            if (kdf_in_use.cmpxchgWeak(n, n + 1, .acquire, .monotonic) == null) return;
            continue;
        }
        if (sys.monotonicMs() >= deadline_ms) return error.LoginGraceExpired;
        std.Io.sleep(io, .fromMilliseconds(10), .awake) catch {};
    }
}

fn releaseKdfSlot() void {
    _ = kdf_in_use.fetchSub(1, .release);
}

/// Methods list for a `userauth_failure` reply. A password-only user
/// gets `PASSWORD`, so clients stop offering every agent key first;
/// everyone else, including unknown users, gets `PASSWORD|PUBLICKEY`.
///
/// This deliberately reveals that a password-only user exists. Partner
/// usernames are pre-shared, and the noise it removes is real. Operators
/// who want no difference give every user both methods.
fn methodsForUser(cfg: config.Config, username: ?[]const u8) c_int {
    const both: c_int = @intCast(c.SSH_AUTH_METHOD_PASSWORD | c.SSH_AUTH_METHOD_PUBLICKEY);
    const name = username orelse return both;
    const user = cfg.findUser(name) orelse return both;
    if (user.password_hash != null and user.keys.len == 0) {
        return @intCast(c.SSH_AUTH_METHOD_PASSWORD);
    }
    return both;
}

const PublicKeyDecision = union(enum) {
    /// Signature verified and success sent.
    accepted: *const config.UserConfig,
    /// Acceptable key offered and `pk_ok` sent; await the signed request.
    offered,
    /// A configured key with a bad signature. libssh 0.11 rejects those
    /// itself; kept so a libssh that passes them on still counts them.
    hard_denied,
    /// Unknown user, `from` miss, no keys, unconfigured or malformed
    /// offer. Same class as unknown user so it confirms nothing.
    soft_denied,
};

fn handlePublicKeyMessage(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    msg: c.ssh_message,
    ip_str: []const u8,
) PublicKeyDecision {
    const username_ptr = c.ssh_message_auth_user(msg);
    if (username_ptr == null) return .soft_denied;
    const username = std.mem.span(username_ptr);

    const presented = c.ssh_message_auth_pubkey(msg);
    if (presented == null) {
        audit.log(io, username, "auth.publickey", null, .denied, "no key in message", ip_str);
        return .soft_denied;
    }

    const user = cfg.findUser(username) orelse {
        _ = matchAgainstDummyKey(allocator, presented);
        audit.log(io, username, "auth.publickey", null, .denied, "unknown user", ip_str);
        return .soft_denied;
    };

    if (!netmatch.allowed(user.from, ip_str)) {
        // Soft like an unknown user; only the audit detail differs.
        _ = matchAgainstDummyKey(allocator, presented);
        audit.log(io, username, "auth.publickey", null, .denied, "source not allowed", ip_str);
        return .soft_denied;
    }

    if (user.keys.len == 0) {
        _ = matchAgainstDummyKey(allocator, presented);
        audit.log(io, username, "auth.publickey", null, .denied, "no keys configured", ip_str);
        return .soft_denied;
    }

    const matched_idx = matchesAnyConfiguredKey(allocator, user, presented) orelse {
        audit.log(io, username, "auth.publickey", null, .denied, "key not configured", ip_str);
        return .soft_denied;
    };

    const state = c.ssh_message_auth_publickey_state(msg);
    switch (state) {
        c.SSH_PUBLICKEY_STATE_NONE => {
            // An offer: libssh verifies the signed follow-up (STATE_VALID).
            if (c.ssh_message_auth_reply_pk_ok_simple(msg) != c.SSH_OK) {
                audit.log(io, username, "auth.publickey", null, .failed, "pk_ok reply failed", ip_str);
                return .soft_denied;
            }
            return .offered;
        },
        c.SSH_PUBLICKEY_STATE_VALID => {
            _ = c.ssh_message_auth_reply_success(msg, 0);
            audit.log(io, username, "auth.publickey", null, .ok, user.keys[matched_idx].algorithm, ip_str);
            return .{ .accepted = user };
        },
        else => {
            audit.log(io, username, "auth.publickey", null, .denied, "signature invalid", ip_str);
            return .hard_denied;
        },
    }
}

/// Index of the configured key matching `presented`, for the audit line.
fn matchesAnyConfiguredKey(
    allocator: std.mem.Allocator,
    user: *const config.UserConfig,
    presented: c.ssh_key,
) ?usize {
    if (user.keys.len == 0) return null;
    const presented_type = c.ssh_key_type(presented);

    for (user.keys, 0..) |configured, i| {
        const algo_z = allocator.dupeZ(u8, configured.algorithm) catch return null;
        defer allocator.free(algo_z);
        const blob_z = allocator.dupeZ(u8, configured.blob) catch return null;
        defer allocator.free(blob_z);

        const want_type = c.ssh_key_type_from_name(algo_z.ptr);
        if (want_type != presented_type) continue;

        var parsed: c.ssh_key = null;
        const rc = c.ssh_pki_import_pubkey_base64(blob_z.ptr, want_type, &parsed);
        if (rc != c.SSH_OK or parsed == null) continue;
        defer c.ssh_key_free(parsed);

        if (c.ssh_key_cmp(presented, parsed, c.SSH_KEY_CMP_PUBLIC) == 0) {
            return i;
        }
    }
    return null;
}

/// A real Ed25519 public key whose private half is stored nowhere. Only
/// ever compared against, to spend the time a real lookup would.
const dummy_pubkey_algorithm = "ssh-ed25519";
const dummy_pubkey_blob = "AAAAC3NzaC1lZDI1NTE5AAAAIIH9hN3OvKbo/u+wsxJjPXpOAFn4mP+/p1bbyT2bF50K";

/// The import-and-compare work of `matchesAnyConfiguredKey`, against the
/// dummy key. Keep the two symmetric (any caching added there must be
/// added here) or timing reveals which users exist.
fn matchAgainstDummyKey(allocator: std.mem.Allocator, presented: c.ssh_key) bool {
    const algo_z = allocator.dupeZ(u8, dummy_pubkey_algorithm) catch return false;
    defer allocator.free(algo_z);
    const blob_z = allocator.dupeZ(u8, dummy_pubkey_blob) catch return false;
    defer allocator.free(blob_z);

    const want_type = c.ssh_key_type_from_name(algo_z.ptr);
    var parsed: c.ssh_key = null;
    const rc = c.ssh_pki_import_pubkey_base64(blob_z.ptr, want_type, &parsed);
    if (rc != c.SSH_OK or parsed == null) return false;
    defer c.ssh_key_free(parsed);

    _ = c.ssh_key_cmp(presented, parsed, c.SSH_KEY_CMP_PUBLIC);
    return false;
}

const no_deadline = std.math.maxInt(i64);

test "verifyPassword accepts only the right password" {
    var out: [passhash.blob_len]u8 = undefined;
    const hash = try passhash.mint(std.testing.io, std.testing.allocator, "correct horse", &out);
    try std.testing.expect(try verifyPassword(std.testing.io, std.testing.allocator, hash, "correct horse", no_deadline));
    try std.testing.expect(!try verifyPassword(std.testing.io, std.testing.allocator, hash, "wrong horse", no_deadline));
}

test "verifyPassword returns false when user has no password" {
    try std.testing.expect(!try verifyPassword(std.testing.io, std.testing.allocator, null, "anything", no_deadline));
}

test "countSoft ends the loop at the 64th soft operation" {
    var soft_ops: u32 = 0;
    for (0..63) |_| try countSoft(std.testing.io, &soft_ops, "192.0.2.1");
    try std.testing.expectError(error.LibsshFailure, countSoft(std.testing.io, &soft_ops, "192.0.2.1"));
}

test "readTimeoutMs: the login deadline caps the idle timeout" {
    try std.testing.expectEqual(@as(u64, 300_000), try readTimeoutMs(300_000, 1_000_000, 0));
    try std.testing.expectEqual(@as(u64, 5_000), try readTimeoutMs(300_000, 10_000, 5_000));
    // Idle 0 means no idle limit, not no limit at all.
    try std.testing.expectEqual(@as(u64, 1), try readTimeoutMs(0, 10_000, 9_999));
    try std.testing.expectError(error.LoginGraceExpired, readTimeoutMs(0, 10_000, 10_000));
    try std.testing.expectError(error.LoginGraceExpired, readTimeoutMs(300_000, 10_000, 20_000));
}

test "KDF slots bound concurrency, and a wait ends at the deadline" {
    const io = std.testing.io;
    const slots = kdfSlots();
    try std.testing.expect(slots >= 2 and slots <= 8);

    const Probe = struct {
        var running: std.atomic.Value(u32) = .init(0);
        var peak: std.atomic.Value(u32) = .init(0);
        fn run() void {
            acquireKdfSlot(std.testing.io, no_deadline) catch unreachable;
            defer releaseKdfSlot();
            const now = running.fetchAdd(1, .acq_rel) + 1;
            _ = peak.fetchMax(now, .acq_rel);
            std.Io.sleep(std.testing.io, .fromMilliseconds(5), .awake) catch {};
            _ = running.fetchSub(1, .acq_rel);
        }
    };
    var threads: [24]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Probe.run, .{});
    for (threads) |t| t.join();
    try std.testing.expect(Probe.peak.load(.acquire) <= slots);
    try std.testing.expectEqual(@as(u32, 0), kdf_in_use.load(.acquire));

    // All slots busy: a waiter gives up at its deadline.
    kdf_in_use.store(slots, .release);
    defer kdf_in_use.store(0, .release);
    try std.testing.expectError(error.LoginGraceExpired, acquireKdfSlot(io, sys.monotonicMs() + 30));
}
