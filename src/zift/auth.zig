const std = @import("std");
const config = @import("config.zig");

const argon2 = std.crypto.pwhash.argon2;

/// Parameters used by `zift hash-password`. Inside the policy envelope
/// (PLAN.md §8.4) at the lower end so onboarding is fast.
pub const hash_params = argon2.Params{
    .t = 3,
    .m = 64 * 1024,
    .p = 1,
};

/// Upper bound of the policy envelope. The unknown-user dummy hash uses
/// these parameters so its verification timing matches or exceeds any
/// real user's hash, regardless of where in the envelope a real user
/// sits. See PLAN.md §8.4 "Unknown-user timing."
pub const dummy_params = argon2.Params{
    .t = 8,
    .m = 256 * 1024,
    .p = 4,
};

pub fn hashPassword(
    io: std.Io,
    allocator: std.mem.Allocator,
    password: []const u8,
    out: []u8,
) ![]const u8 {
    return argon2.strHash(password, .{
        .allocator = allocator,
        .params = hash_params,
        .mode = .argon2id,
    }, out, io);
}

pub fn verifyPassword(
    io: std.Io,
    allocator: std.mem.Allocator,
    user: *const config.UserConfig,
    password: []const u8,
) bool {
    const hash = user.password_hash orelse return false;
    argon2.strVerify(hash, password, .{ .allocator = allocator }, io) catch return false;
    return true;
}

pub fn verifyLogin(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    username: []const u8,
    password: []const u8,
) bool {
    if (cfg.findUser(username)) |user| {
        return verifyPassword(io, allocator, user, password);
    }

    // Unknown user. Run a real Argon2id verification against a cached
    // dummy hash so the latency of an unknown-user attempt matches the
    // slowest real user's verification. PLAN.md §8.4. The hash itself
    // is computed once at first use and reused for every subsequent
    // unknown-user attempt; the *verification* work is the security
    // property, and that runs on every call. `max-connections`
    // (PLAN.md §6.2) bounds the worst-case concurrent memory cost of
    // an auth-storm.
    const dummy = ensureDummyHash(io, allocator) orelse return false;
    argon2.strVerify(dummy, password, .{ .allocator = allocator }, io) catch {};
    return false;
}

// ----- cached dummy hash --------------------------------------------------
//
// A dummy Argon2id PHC string used to give unknown-user auth attempts the
// same latency as a real user's `strVerify`. Computed once at first use,
// then read by every subsequent unknown-user verifyLogin / pubkey-fallback
// call. Lazy init under a mutex; the produced PHC string lives in a
// process-static buffer for the lifetime of the program.

var dummy_buf: [256]u8 = undefined;
var dummy_ready: std.atomic.Value(bool) = .init(false);
var dummy_mutex: std.Io.Mutex = .init;
var dummy_slice: []const u8 = &.{};

pub fn ensureDummyHash(io: std.Io, allocator: std.mem.Allocator) ?[]const u8 {
    // Fast path: already initialized.
    if (dummy_ready.load(.acquire)) return dummy_slice;

    dummy_mutex.lockUncancelable(io);
    defer dummy_mutex.unlock(io);

    // Re-check under the lock: another thread may have initialized
    // while we were waiting.
    if (dummy_ready.load(.acquire)) return dummy_slice;

    const computed = argon2.strHash("zift-dummy-password", .{
        .allocator = allocator,
        .params = dummy_params,
        .mode = .argon2id,
    }, &dummy_buf, io) catch return null;

    dummy_slice = computed;
    dummy_ready.store(true, .release);
    return dummy_slice;
}

test "hash and verify password" {
    var out: [256]u8 = undefined;
    const hash = try hashPassword(std.testing.io, std.testing.allocator, "correct horse", &out);

    const user: config.UserConfig = .{
        .name = "ally",
        .password_hash = hash,
        .keys = &.{},
        .key_files = &.{},
        .from = &.{},
        .root = "/tmp",
        .rules = &.{},
    };

    try std.testing.expect(verifyPassword(std.testing.io, std.testing.allocator, &user, "correct horse"));
    try std.testing.expect(!verifyPassword(std.testing.io, std.testing.allocator, &user, "wrong horse"));
}

test "verifyPassword returns false when user has no password" {
    const user: config.UserConfig = .{
        .name = "key-only",
        .password_hash = null,
        .keys = &.{},
        .key_files = &.{},
        .from = &.{},
        .root = "/tmp",
        .rules = &.{},
    };
    try std.testing.expect(!verifyPassword(std.testing.io, std.testing.allocator, &user, "anything"));
}
