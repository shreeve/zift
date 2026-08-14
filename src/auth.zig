const std = @import("std");
const config = @import("config.zig");
const passhash = @import("passhash.zig");

/// Mint a Janus-identical `a…` password credential (fixed argon2id).
pub fn hashPassword(
    io: std.Io,
    allocator: std.mem.Allocator,
    password: []const u8,
    out: []u8,
) ![]const u8 {
    return passhash.mint(io, allocator, password, out);
}

pub fn verifyPassword(
    io: std.Io,
    allocator: std.mem.Allocator,
    user: *const config.UserConfig,
    password: []const u8,
) bool {
    const hash = user.password_hash orelse {
        // Known user, but key-only (no password credential). Returning
        // `false` immediately here would take ~0 ms while a real verify
        // or the unknown-user dummy takes a full argon2id (~58 ms),
        // handing an attacker a timing oracle that distinguishes
        // "exists, key-only" from "exists, has password" / "unknown".
        // Run the same dummy work so all password-denial paths cost the
        // same. (See also the `from`-denied path in ssh.zig.)
        runDummyVerify(io, allocator, password);
        return false;
    };
    return passhash.verify(io, allocator, password, hash);
}

/// Run one argon2id verification against the cached dummy credential
/// and discard the result. Used to keep every password-denial path
/// (unknown user, key-only user, source-not-allowed) at the same cost
/// as a real verify so timing cannot enumerate usernames or auth
/// shapes. PLAN §8.4.
pub fn runDummyVerify(io: std.Io, allocator: std.mem.Allocator, password: []const u8) void {
    ensureDummy(io, allocator);
    _ = passhash.verify(io, allocator, password, dummy_blob[0..passhash.blob_len]);
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

    // Unknown user: same argon2id work as a real verify (identical
    // params), against a lazily minted dummy credential — timing does
    // not enumerate the user list.
    runDummyVerify(io, allocator, password);
    return false;
}

// ----- cached dummy passhash blob ------------------------------------------

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

test "hash and verify password" {
    var out: [passhash.blob_len]u8 = undefined;
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
