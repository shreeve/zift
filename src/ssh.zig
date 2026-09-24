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
) !*const config.UserConfig {
    // Two ceilings.
    //
    // HARD failures are real credential rejections: a wrong or unknown-
    // user password, a password from outside `from`, or a matched key
    // with a bad signature. They feed the abuse table and the backoff,
    // and 6 (OpenSSH's MaxAuthTries) end the session.
    //
    // SOFT operations are `none`, non-auth messages, and public-key
    // probes (offers, unconfigured keys, a public-key `from` miss). A
    // stock client sends one per agent key before trying a password, so
    // they get no backoff and no abuse credit, only a loop bound: each
    // message restarts libssh's idle deadline. A public-key `from` miss
    // is soft so that it cannot be told apart from an unknown user.
    const max_hard_failures: u32 = 6;
    const max_soft_ops: u32 = 64;
    var hard_failures: u32 = 0;
    var soft_ops: u32 = 0;
    while (true) {
        // Suppression by another session applies here too.
        if (abuse.isSuppressed(io, ip_str, sys.monotonicMs())) {
            audit.log(io, null, "auth.rejected", null, .denied, "source suppressed", ip_str);
            return error.LibsshFailure;
        }

        const msg = c.ssh_message_get(session) orelse return error.LibsshFailure;
        defer c.ssh_message_free(msg);

        if (c.ssh_message_type(msg) != c.SSH_REQUEST_AUTH) {
            soft_ops += 1;
            if (soft_ops >= max_soft_ops) {
                audit.log(io, null, "auth.too_many_attempts", null, .denied, "probes", ip_str);
                return error.LibsshFailure;
            }
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
                if (cfg.findUser(username)) |user| {
                    if (!netmatch.allowed(user.from, ip_str)) {
                        // Pay the KDF anyway so timing hides the username.
                        runDummyVerify(io, allocator, password);
                        audit.log(io, username, "auth.password", null, .denied, "source not allowed", ip_str);
                        is_hard = true;
                    } else if (verifyPassword(io, allocator, user, password)) {
                        _ = c.ssh_message_auth_reply_success(msg, 0);
                        audit.log(io, username, "auth.password", null, .ok, "", ip_str);
                        abuse.recordSuccess(io, ip_str);
                        return user;
                    } else {
                        audit.log(io, username, "auth.password", null, .denied, "bad password", ip_str);
                        is_hard = true;
                    }
                } else {
                    runDummyVerify(io, allocator, password);
                    audit.log(io, username, "auth.password", null, .denied, "unknown user", ip_str);
                    is_hard = true;
                }
            }
        } else if (subtype == c.SSH_AUTH_METHOD_PUBLICKEY) {
            const decision = handlePublicKeyMessage(io, allocator, cfg, msg, ip_str);
            switch (decision) {
                .accepted => |user| {
                    abuse.recordSuccess(io, ip_str);
                    return user;
                },
                .offered => {
                    // `pk_ok` was sent; wait for the signed follow-up.
                    soft_ops += 1;
                    if (soft_ops >= max_soft_ops) {
                        audit.log(io, null, "auth.too_many_attempts", null, .denied, "pubkey probes", ip_str);
                        return error.LibsshFailure;
                    }
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
            const delay_ms = @min(hard_failures * 250, 2000);
            std.Io.sleep(io, .fromMilliseconds(delay_ms), .awake) catch {};
            if (hard_failures >= max_hard_failures) {
                audit.log(io, null, "auth.too_many_attempts", null, .denied, "", ip_str);
                return error.LibsshFailure;
            }
        } else {
            soft_ops += 1;
            if (soft_ops >= max_soft_ops) {
                audit.log(io, null, "auth.too_many_attempts", null, .denied, "probes", ip_str);
                return error.LibsshFailure;
            }
        }

        _ = c.ssh_message_auth_set_methods(msg, methodsForUser(cfg, username_for_methods));
        _ = c.ssh_message_reply_default(msg);
    }
}

fn verifyPassword(
    io: std.Io,
    allocator: std.mem.Allocator,
    user: *const config.UserConfig,
    password: []const u8,
) bool {
    const hash = user.password_hash orelse {
        // Key-only user: pay the KDF so timing matches the other denials.
        runDummyVerify(io, allocator, password);
        return false;
    };
    return passhash.verify(io, allocator, password, hash);
}

/// One Argon2id against a cached dummy credential, so every password
/// denial costs the same as a real verify.
fn runDummyVerify(io: std.Io, allocator: std.mem.Allocator, password: []const u8) void {
    ensureDummy(io, allocator);
    _ = passhash.verify(io, allocator, password, dummy_blob[0..passhash.blob_len]);
}

var dummy_blob: [passhash.blob_len]u8 = undefined;
var dummy_ready: std.atomic.Value(bool) = .init(false);
var dummy_mutex: std.Io.Mutex = .init;

fn ensureDummy(io: std.Io, allocator: std.mem.Allocator) void {
    if (dummy_ready.load(.acquire)) return;

    dummy_mutex.lockUncancelable(io);
    defer dummy_mutex.unlock(io);
    if (dummy_ready.load(.acquire)) return;

    _ = passhash.mint(io, allocator, "zift-dummy-password", &dummy_blob) catch {
        // Fall back to a structurally valid but unverifiable blob so
        // the verify path still runs KDF work against a real salt.
        @memcpy(dummy_blob[0..passhash.prefix.len], passhash.prefix);
        @memset(dummy_blob[passhash.prefix.len..], '0');
    };
    dummy_ready.store(true, .release);
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
    /// A configured key with a bad signature.
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

fn testUser(password_hash: ?[]const u8) config.UserConfig {
    return .{
        .name = "ally",
        .password_hash = password_hash,
        .keys = &.{},
        .key_files = &.{},
        .from = &.{},
        .root = "/tmp",
        .rules = &.{},
    };
}

test "verifyPassword accepts only the right password" {
    var out: [passhash.blob_len]u8 = undefined;
    const hash = try passhash.mint(std.testing.io, std.testing.allocator, "correct horse", &out);
    const user = testUser(hash);
    try std.testing.expect(verifyPassword(std.testing.io, std.testing.allocator, &user, "correct horse"));
    try std.testing.expect(!verifyPassword(std.testing.io, std.testing.allocator, &user, "wrong horse"));
}

test "verifyPassword returns false when user has no password" {
    const user = testUser(null);
    try std.testing.expect(!verifyPassword(std.testing.io, std.testing.allocator, &user, "anything"));
}
