//! Fuzz harnesses over the production parsers, normalizer, and matcher.
//! `zig build test --fuzz` runs them; a plain `zig build test` runs each
//! once on empty input. The corpora seed known-tricky inputs.

const std = @import("std");
const config = @import("config.zig");
const policy = @import("policy.zig");
const vfs_mod = @import("vfs.zig");
const wire = @import("wire.zig");

const Smith = std.testing.Smith;

test "fuzz config parser" {
    return std.testing.fuzz({}, fuzzConfig, .{ .corpus = &.{
        \\server
        \\  listen 127.0.0.1:2222
        \\  host-key /tmp/key
        \\
        \\user ally
        \\  auth a0000000000000000000000000000000
        \\  root /tmp/a
        ,
    } });
}

fn fuzzConfig(_: void, smith: *Smith) !void {
    var buf: [4096]u8 = undefined;
    const len = smith.sliceWithHash(&buf, 0xC0FFEE);
    var cfg = config.parse(std.testing.allocator, buf[0..len]) catch return;
    cfg.deinit();
}

// Input is `pattern\x00value`.
test "fuzz policy glob matching" {
    return std.testing.fuzz({}, fuzzPolicyGlob, .{ .corpus = &.{
        "/pending\x00/pending/file.txt",
        "*.exe\x00/tool.exe",
        "/archive/*\x00/archive/data.csv",
        "/\x00/anything/deep/file",
        "/pending\x00/pendingevil",
    } });
}

fn fuzzPolicyGlob(_: void, smith: *Smith) !void {
    var buf: [2048]u8 = undefined;
    const len = smith.sliceWithHash(&buf, 0xDEADBEEF);
    const input = buf[0..len];

    const sep = std.mem.indexOfScalar(u8, input, 0) orelse return;
    if (sep == 0 or sep + 1 >= input.len) return;
    _ = policy.globMatch(input[0..sep], input[sep + 1 ..]);
}

// Drives passhash validation through the config parser.
test "fuzz passhash credential validation" {
    return std.testing.fuzz({}, fuzzPasshash, .{
        .corpus = &.{
            "a0000000000000000000000000000000",
            "zAAAA", // unknown version letter
            "$argon2id$v=19$m=65536,t=2,p=1$aa$bb",
            "a!!!!",
            "b0000000000000000000000000000000", // future version
        },
    });
}

fn fuzzPasshash(_: void, smith: *Smith) !void {
    var buf: [1024]u8 = undefined;
    const len = smith.sliceWithHash(&buf, 0xABADCAFE);
    const cred = buf[0..len];

    const text = std.fmt.allocPrint(
        std.testing.allocator,
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\nuser fuzz\n  auth {s}\n  root /tmp/a\n",
        .{cred},
    ) catch return;
    defer std.testing.allocator.free(text);
    var cfg = config.parse(std.testing.allocator, text) catch return;
    cfg.deinit();
}

test "fuzz public key line validation" {
    return std.testing.fuzz({}, fuzzPubkeyLine, .{ .corpus = &.{
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBLAH comment",
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYA backup",
        "ssh-rsa AAAAB3NzaC1yc2EAAAA notallowed",
        "ssh-ed25519",
        "ssh-ed25519 !!!invalid!!!",
    } });
}

fn fuzzPubkeyLine(_: void, smith: *Smith) !void {
    var buf: [9216]u8 = undefined; // just over max_keyline_bytes
    const len = smith.sliceWithHash(&buf, 0xFEEDFACE);
    const line = buf[0..len];

    const pk = config.parsePublicKeyLine(std.testing.allocator, line) catch return;
    std.testing.allocator.free(pk.algorithm);
    std.testing.allocator.free(pk.blob);
}

// The parser a remote partner drives directly: any panic is a remote DoS.
test "fuzz sftp wire string parser" {
    return std.testing.fuzz({}, fuzzWireParser, .{ .corpus = &.{
        &.{ 0, 0, 0, 3, 'a', 'b', 'c' },
        &.{ 0xFF, 0xFF, 0xFF, 0xFF, 1, 2, 3, 4 },
        &.{ 0, 0, 0, 4, 0, 0, 0, 7 },
        &.{ 0, 0 },
        &.{},
    } });
}

fn fuzzWireParser(_: void, smith: *Smith) !void {
    var buf: [4096]u8 = undefined;
    const len = smith.sliceWithHash(&buf, 0x5F7B0FF5);
    const input = buf[0..len];

    if (wire.parseString(input)) |parsed| {
        std.debug.assert(parsed.value.len <= input.len);
        std.debug.assert(parsed.rest.len <= input.len);
    } else |_| {}
    _ = wire.parseHandleId(input) catch {};
}

// Authorization runs on this output: it must be rooted, with no `.`,
// `..`, or reserved component left.
test "fuzz normalize into buffer" {
    return std.testing.fuzz({}, fuzzNormalizeInto, .{ .corpus = &.{
        "/pending/../secret",
        "/pending/x.exe/",
        "//a//b/./c",
        "/.zift/staging/x",
        "/.ZIFT/x",
        "/a/../../b",
        "/pending/inbox/file.txt",
        "/a/b/../c/./d",
        "//",
        "/\x00bad",
    } });
}

fn fuzzNormalizeInto(_: void, smith: *Smith) !void {
    var buf: [4096]u8 = undefined;
    const len = smith.sliceWithHash(&buf, 0x2A2A2F2F);
    const input = buf[0..len];

    var out: [vfs_mod.max_virtual_path_bytes + 2]u8 = undefined;
    const normalized = vfs_mod.normalizeVirtualInto(input, &out) catch return;
    std.debug.assert(normalized.len >= 1 and normalized[0] == '/');
    var it = std.mem.tokenizeScalar(u8, normalized, '/');
    while (it.next()) |part| {
        std.debug.assert(!std.mem.eql(u8, part, "."));
        std.debug.assert(!std.mem.eql(u8, part, ".."));
        std.debug.assert(!vfs_mod.isReservedComponent(part));
    }
}
