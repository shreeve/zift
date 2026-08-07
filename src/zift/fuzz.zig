//! Fuzz harnesses for Zift's parser/normalizer/matcher code paths
//! (PLAN §12). Each test draws bytes from a `*std.testing.Smith` and
//! feeds them to the real production function. The corpus list seeds
//! the fuzzer with known-tricky inputs so the search starts somewhere
//! useful instead of from the empty string.
//!
//! Run interactively with:
//!     zig build test --fuzz
//!
//! With no `--fuzz` flag, each test runs once with empty input and
//! returns immediately, so they're cheap to include in the regular
//! `zig build test` suite.

const std = @import("std");
const config = @import("config.zig");
const policy = @import("policy.zig");
const vfs_mod = @import("vfs.zig");

const Smith = std.testing.Smith;

// ---------------------------------------------------------------------------
// Config parser fuzz — exercises every parse path with arbitrary bytes.

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

// ---------------------------------------------------------------------------
// Virtual path normalization fuzz — exercises the §8.3 byte-set rules
// and `..`-traversal handling.

test "fuzz virtual path normalization" {
    return std.testing.fuzz({}, fuzzVirtualPath, .{ .corpus = &.{
        "/pending/inbox/file.txt",
        "/../../etc/passwd",
        "/a/b/../c/./d",
        "/",
        "//",
        "/\x00bad",
    } });
}

fn fuzzVirtualPath(_: void, smith: *Smith) !void {
    var buf: [4096]u8 = undefined;
    const len = smith.sliceWithHash(&buf, 0xBEEFCAFE);
    const input = buf[0..len];

    vfs_mod.Vfs.validateVirtualPath(input) catch return;
    const normalized = vfs_mod.Vfs.normalizeVirtual(std.testing.allocator, input) catch return;
    std.testing.allocator.free(normalized);
}

// ---------------------------------------------------------------------------
// Policy glob matching fuzz — splits Smith's bytes into pattern and
// value and exercises the §6.3 matcher.

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

// ---------------------------------------------------------------------------
// passhash credential validation fuzz — drives parsing through the
// config parser (version letter, alphabet, exact length).

test "fuzz passhash credential validation" {
    return std.testing.fuzz({}, fuzzPasshash, .{ .corpus = &.{
        "a0000000000000000000000000000000",
        "zAAAA", // unknown version letter
        "$argon2id$v=19$m=65536,t=2,p=1$aa$bb",
        "a!!!!",
        "b0000000000000000000000000000000", // future version
    } });
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

// ---------------------------------------------------------------------------
// Public-key line validation fuzz — drives `parsePublicKeyLine`
// directly. v0.7.0 moved key parsing out of the config-line path
// (the inline `key ...` directive is gone; keys come from
// operator-managed files referenced by `auth /path/...`), so the
// fuzz target moved with it.

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
    var buf: [9216]u8 = undefined; // a bit larger than max_keyline_bytes
    const len = smith.sliceWithHash(&buf, 0xFEEDFACE);
    const line = buf[0..len];

    const pk = config.parsePublicKeyLine(std.testing.allocator, line) catch return;
    std.testing.allocator.free(pk.algorithm);
    std.testing.allocator.free(pk.blob);
}
