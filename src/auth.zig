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
    argon2.strVerify(user.password_hash, password, .{ .allocator = allocator }, io) catch return false;
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

    // Unknown user. Run a real Argon2id verification against a dummy hash
    // produced with upper-bound envelope parameters so the latency of an
    // unknown-user attempt matches or exceeds the slowest real user's
    // verification. PLAN.md §8.4. The hash is recomputed on each unknown
    // attempt; this is intentional — the work itself is the security
    // property. `max-connections` (PLAN.md §6.2) bounds the worst-case
    // concurrent memory cost of an auth-storm.
    var dummy_buf: [256]u8 = undefined;
    const dummy_hash = argon2.strHash("zift-dummy-password", .{
        .allocator = allocator,
        .params = dummy_params,
        .mode = .argon2id,
    }, &dummy_buf, io) catch return false;
    argon2.strVerify(dummy_hash, password, .{ .allocator = allocator }, io) catch {};
    return false;
}

test "hash and verify password" {
    var out: [256]u8 = undefined;
    const hash = try hashPassword(std.testing.io, std.testing.allocator, "correct horse", &out);

    const user: config.UserConfig = .{
        .name = "ally",
        .password_hash = hash,
        .root = "/tmp",
        .rules = &.{},
    };

    try std.testing.expect(verifyPassword(std.testing.io, std.testing.allocator, &user, "correct horse"));
    try std.testing.expect(!verifyPassword(std.testing.io, std.testing.allocator, &user, "wrong horse"));
}
