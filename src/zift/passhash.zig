//! Password credentials (Janus-identical wire format).
//!
//! Stored form is `a` + 31 base62 chars (alphabet `[0-9A-Za-z]`).
//! Always 32 characters. Raw payload is 23 bytes (8-byte salt, 15-byte
//! key). Argon2id parameters are fixed as module constants. The leading
//! letter is a version tag (`a` = v1); future versions may use `b`, …
//!
//! Same wire format and constants as Janus so a blob minted by either
//! project verifies in the other.

const std = @import("std");
const argon2 = std.crypto.pwhash.argon2;

/// Version letter for the current mint format.
pub const prefix = "a";
/// KiB → 64 MiB (Janus memory param).
pub const memory_kib: u32 = 64 * 1024;
pub const time_cost: u32 = 2;
pub const threads: u24 = 1;
pub const salt_len: usize = 8;
pub const key_len: usize = 15;
pub const raw_len: usize = salt_len + key_len; // 23
/// 62^31 > 2^184, so 31 digits hold any 23-byte value.
pub const enc_len: usize = 31;
pub const blob_len: usize = prefix.len + enc_len; // 32

const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

pub const params = argon2.Params{
    .t = time_cost,
    .m = memory_kib,
    .p = threads,
};

pub const Error = error{
    MissingPrefix,
    UnknownVersionTag,
    InvalidAlphabet,
    InvalidEncoding,
    WrongLength,
    KdfFailed,
    BufferTooSmall,
};

/// Mint a fresh `a…` blob from a password into `out` (needs ≥32 bytes).
pub fn mint(io: std.Io, allocator: std.mem.Allocator, password: []const u8, out: []u8) Error![]const u8 {
    if (out.len < blob_len) return error.BufferTooSmall;

    var salt: [salt_len]u8 = undefined;
    io.randomSecure(&salt) catch return error.KdfFailed;

    var digest: [key_len]u8 = undefined;
    kdf(io, allocator, password, &salt, &digest) catch return error.KdfFailed;

    var raw: [raw_len]u8 = undefined;
    @memcpy(raw[0..salt_len], &salt);
    @memcpy(raw[salt_len..], &digest);

    @memcpy(out[0..prefix.len], prefix);
    base62Encode(&raw, out[prefix.len..][0..enc_len]);
    return out[0..blob_len];
}

/// Constant-time verify of `password` against a validated blob.
pub fn verify(io: std.Io, allocator: std.mem.Allocator, password: []const u8, blob: []const u8) bool {
    const raw = decode(blob) catch return false;
    var digest: [key_len]u8 = undefined;
    kdf(io, allocator, password, raw[0..salt_len], &digest) catch return false;
    var expected: [key_len]u8 = undefined;
    @memcpy(&expected, raw[salt_len..][0..key_len]);
    return std.crypto.timing_safe.eql([key_len]u8, digest, expected);
}

/// Parse-time validation: version, alphabet, exact decoded length.
pub fn validate(blob: []const u8) Error!void {
    _ = try decode(blob);
}

/// Decode to the 23 raw bytes (salt‖digest).
pub fn decode(blob: []const u8) Error![raw_len]u8 {
    if (blob.len == 0) return error.MissingPrefix;
    if (blob.len != blob_len) {
        // Legacy `g1…` or future letter versions (`b`…).
        if (std.mem.startsWith(u8, blob, "g1") or (blob[0] >= 'b' and blob[0] <= 'z')) {
            return error.UnknownVersionTag;
        }
        return error.WrongLength;
    }
    if (!std.mem.startsWith(u8, blob, prefix)) {
        return error.UnknownVersionTag;
    }
    const rest = blob[prefix.len..][0..enc_len];
    for (rest) |ch| {
        if (base62Value(ch) == null) return error.InvalidAlphabet;
    }
    return base62Decode(rest) catch return error.InvalidEncoding;
}

fn base62Encode(raw: *const [raw_len]u8, out: *[enc_len]u8) void {
    var buf = raw.*;
    var i: usize = enc_len;
    while (i > 0) {
        i -= 1;
        out[i] = alphabet[divMod62(&buf)];
    }
}

fn base62Decode(src: *const [enc_len]u8) error{InvalidEncoding}![raw_len]u8 {
    var buf = [_]u8{0} ** raw_len;
    for (src.*) |ch| {
        const v = base62Value(ch) orelse return error.InvalidEncoding;
        mulAdd62(&buf, v) catch return error.InvalidEncoding;
    }
    return buf;
}

fn divMod62(buf: *[raw_len]u8) u8 {
    var rem: u16 = 0;
    for (buf) |*b| {
        const cur: u16 = (rem << 8) | b.*;
        b.* = @intCast(cur / 62);
        rem = cur % 62;
    }
    return @intCast(rem);
}

fn mulAdd62(buf: *[raw_len]u8, v: u8) error{Overflow}!void {
    var carry: u32 = v;
    var i: usize = raw_len;
    while (i > 0) {
        i -= 1;
        const cur: u32 = @as(u32, buf[i]) * 62 + carry;
        buf[i] = @intCast(cur & 0xff);
        carry = cur >> 8;
    }
    if (carry != 0) return error.Overflow;
}

fn base62Value(ch: u8) ?u8 {
    return switch (ch) {
        '0'...'9' => ch - '0',
        'A'...'Z' => ch - 'A' + 10,
        'a'...'z' => ch - 'a' + 36,
        else => null,
    };
}

fn kdf(
    io: std.Io,
    allocator: std.mem.Allocator,
    password: []const u8,
    salt: []const u8,
    out: *[key_len]u8,
) !void {
    try argon2.kdf(allocator, out, password, salt, params, .argon2id, io);
}

test "mint and verify round-trip" {
    var buf: [blob_len]u8 = undefined;
    const blob = try mint(std.testing.io, std.testing.allocator, "correct horse", &buf);
    try std.testing.expect(std.mem.startsWith(u8, blob, "a"));
    try std.testing.expectEqual(@as(usize, 32), blob.len);
    try std.testing.expect(std.mem.indexOfAny(u8, blob, "-_~+/=") == null);
    try validate(blob);
    try std.testing.expect(verify(std.testing.io, std.testing.allocator, "correct horse", blob));
    try std.testing.expect(!verify(std.testing.io, std.testing.allocator, "wrong horse", blob));
}

test "validate rejects legacy and bad shapes" {
    try std.testing.expectError(error.MissingPrefix, validate(""));
    try std.testing.expectError(error.UnknownVersionTag, validate("g1" ++ ("0" ** 30)));
    try std.testing.expectError(error.UnknownVersionTag, validate("b" ++ ("0" ** 31)));
    try std.testing.expectError(error.WrongLength, validate("aAAAA"));
    try std.testing.expectError(error.InvalidAlphabet, validate("a" ++ "A" ** 30 ++ "_"));
    try std.testing.expectError(error.InvalidAlphabet, validate("a" ++ "A" ** 30 ++ "-"));
}

test "fixed length" {
    var buf: [blob_len]u8 = undefined;
    const blob = try mint(std.testing.io, std.testing.allocator, "x", &buf);
    try std.testing.expectEqual(@as(usize, 32), blob.len);
    try std.testing.expectEqual(@as(usize, 31), blob.len - prefix.len);
}

test "base62 round-trip extremes" {
    var zero = [_]u8{0} ** raw_len;
    var enc: [enc_len]u8 = undefined;
    base62Encode(&zero, &enc);
    try std.testing.expectEqualStrings("0" ** enc_len, &enc);
    try std.testing.expectEqualSlices(u8, &zero, &(try base62Decode(&enc)));

    var ones = [_]u8{0xff} ** raw_len;
    base62Encode(&ones, &enc);
    try std.testing.expectEqualSlices(u8, &ones, &(try base62Decode(&enc)));
}
