const std = @import("std");
const config = @import("config.zig");

const argon2 = std.crypto.pwhash.argon2;

pub const hash_params = argon2.Params{
    .t = 3,
    .m = 64 * 1024,
    .p = 1,
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

    // Keep the unknown-user path doing password-hash work so auth timing is less revealing.
    var dummy_hash_buf: [256]u8 = undefined;
    const dummy_hash = hashPassword(io, allocator, "zift-dummy-password", &dummy_hash_buf) catch return false;
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
