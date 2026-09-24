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

// Input is `pattern\x00value`. The matcher must agree with the
// reference backtracking matcher below wherever that one finishes.
test "fuzz policy glob matching" {
    return std.testing.fuzz({}, fuzzPolicyGlob, .{ .corpus = &.{
        "/pending\x00/pending/file.txt",
        "*.exe\x00/tool.exe",
        "/archive/*\x00/archive/data.csv",
        "/\x00/anything/deep/file",
        "/pending\x00/pendingevil",
        "/**/b/**/?.csv\x00/a/b/c/\xc3\xa9.csv",
        "**/**/**/**/**/b\x00/a/a/a/a/a/a/a/a/a/a/c",
    } });
}

fn fuzzPolicyGlob(_: void, smith: *Smith) !void {
    var buf: [2048]u8 = undefined;
    const len = smith.sliceWithHash(&buf, 0xDEADBEEF);
    const input = buf[0..len];

    const sep = std.mem.indexOfScalar(u8, input, 0) orelse return;
    const pattern = input[0..sep];
    const value = input[sep + 1 ..];
    const got = policy.globMatch(pattern, value);
    if (referenceGlobMatch(pattern, value)) |want| try std.testing.expectEqual(want, got);
}

test "glob matcher agrees with the reference on random inputs" {
    // Multi-byte characters, plus lone lead and continuation bytes, so
    // `?` meets whole, split, and invalid UTF-8.
    const pattern_atoms = [_][]const u8{ "a", "b", "/", ".", "*", "**", "?", "\xc3\xa9", "\xe2\x82\xac", "\xc3", "\xa9" };
    const value_atoms = [_][]const u8{ "a", "b", "/", ".", "\xc3\xa9", "\xe2\x82\xac", "\xc3", "\xa9" };
    var prng = std.Random.DefaultPrng.init(0x5A1F7);
    const random = prng.random();
    var pattern_buf: [64]u8 = undefined;
    var value_buf: [128]u8 = undefined;
    var matches: usize = 0;
    for (0..200_000) |round| {
        var pattern: []u8 = pattern_buf[0..0];
        var value: []u8 = value_buf[0..0];
        for (0..random.uintLessThan(usize, 11)) |_| {
            const atom = pattern_atoms[random.uintLessThan(usize, pattern_atoms.len)];
            append(&pattern, atom);
            // Every other round, build the value along with the pattern
            // (wildcards as 0-2 random atoms) so that many cases match.
            if (round % 2 == 1) continue;
            if (std.mem.indexOfAny(u8, atom, "*?") == null) {
                append(&value, atom);
            } else for (0..random.uintLessThan(usize, 3)) |_| {
                append(&value, value_atoms[random.uintLessThan(usize, value_atoms.len)]);
            }
        }
        if (round % 2 == 1) for (0..random.uintLessThan(usize, 15)) |_| {
            append(&value, value_atoms[random.uintLessThan(usize, value_atoms.len)]);
        };
        const want = referenceGlobMatch(pattern, value) orelse continue;
        matches += @intFromBool(want);
        if (want != policy.globMatch(pattern, value)) {
            std.debug.print("pattern {f} value {f}: want {}\n", .{ std.ascii.hexEscape(pattern, .lower), std.ascii.hexEscape(value, .lower), want });
            return error.TestUnexpectedResult;
        }
    }
    // Both outcomes must be well represented for the agreement to mean much.
    try std.testing.expect(matches > 20_000 and matches < 180_000);
}

fn append(buf: *[]u8, atom: []const u8) void {
    const len = buf.len;
    buf.* = buf.ptr[0 .. len + atom.len];
    @memcpy(buf.*[len..], atom);
}

/// The recursive backtracking matcher that `policy.globMatch` replaced,
/// kept as its oracle with `?` taking one character. Superlinear, so it
/// has a step budget and returns null when that runs out.
fn referenceGlobMatch(pattern: []const u8, value: []const u8) ?bool {
    if (std.mem.indexOfAny(u8, pattern, "*?") == null) {
        if (std.mem.eql(u8, pattern, "/")) return value.len > 0 and value[0] == '/';
        if (!std.mem.startsWith(u8, value, pattern)) return false;
        return value.len == pattern.len or value[pattern.len] == '/';
    }
    var budget: usize = 1_000_000;
    const result = referenceInner(&budget, pattern, value);
    return if (budget == 0) null else result;
}

fn referenceInner(budget: *usize, pattern: []const u8, value: []const u8) bool {
    if (budget.* == 0) return false;
    budget.* -= 1;

    if (pattern.len == 0) return value.len == 0;

    var stars: usize = 0;
    while (stars < pattern.len and pattern[stars] == '*') stars += 1;
    if (stars >= 2 and stars < pattern.len and pattern[stars] == '/') {
        // `**/`: zero segments, or resume after any `/`.
        const rest = pattern[stars + 1 ..];
        if (referenceInner(budget, rest, value)) return true;
        for (value, 0..) |b, i| {
            if (b == '/' and referenceInner(budget, rest, value[i + 1 ..])) return true;
        }
        return false;
    }
    if (stars >= 2) {
        for (0..value.len + 1) |i| {
            if (referenceInner(budget, pattern[stars..], value[i..])) return true;
        }
        return false;
    }
    if (stars == 1) {
        for (0..value.len + 1) |i| {
            if (referenceInner(budget, pattern[1..], value[i..])) return true;
            if (i < value.len and value[i] == '/') return false;
        }
        return false;
    }

    if (value.len == 0) return false;
    if (pattern[0] == '?') {
        if (value[0] == '/') return false;
        return referenceInner(budget, pattern[1..], value[referenceCharLen(value)..]);
    }
    return pattern[0] == value[0] and referenceInner(budget, pattern[1..], value[1..]);
}

/// The longest prefix, up to 4 bytes, that is exactly one valid UTF-8
/// code point; else 1.
fn referenceCharLen(value: []const u8) usize {
    var n: usize = @min(value.len, 4);
    while (n > 1) : (n -= 1) {
        const count = std.unicode.utf8CountCodepoints(value[0..n]) catch continue;
        if (count == 1) return n;
    }
    return 1;
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
