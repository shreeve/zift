//! Path policy: default deny, any matching `deny` wins, and an `allow`
//! must grant a permission that satisfies the operation.
//!
//! Callers pass the normalized virtual path. Pattern syntax is described
//! at `globMatch` and in docs/configure.md.

const std = @import("std");
const config = @import("config.zig");
const listing = @import("listing.zig");
const vfs = @import("vfs.zig");
const sys = @import("sys.zig");

pub const Operation = enum {
    open_read,
    open_write,
    /// STAT and LSTAT alike.
    stat,
    readdir,
    mkdir,
    remove,
    rmdir,
    rename,
    // The clobber rule: replacing or truncating an existing entry.
    update,
};

pub const Decision = enum {
    allow,
    deny,
};

/// Everything the partner may do at `path`, in one pass over the rules:
/// empty if any `deny` matches, else the union of the matching `allow`s.
/// A path longer than `vfs.max_virtual_path_bytes` gets nothing: no
/// client can name one, and `globMatch` is sized for that bound.
pub fn effective(user: *const config.UserConfig, path: []const u8) config.PermissionSet {
    var granted = config.PermissionSet.initEmpty();
    if (path.len > vfs.max_virtual_path_bytes) return granted;
    for (user.rules) |rule| {
        if (!globMatch(rule.pattern, path)) continue;
        switch (rule.effect) {
            .deny => return config.PermissionSet.initEmpty(),
            .allow => granted.setUnion(rule.permissions),
        }
    }
    return granted;
}

/// Whether `granted` (from `effective`) allows `operation`.
pub fn permits(granted: config.PermissionSet, operation: Operation) bool {
    return granted.intersectWith(permissionsFor(operation)).count() > 0;
}

pub fn check(user: *const config.UserConfig, operation: Operation, virtual_path: []const u8) Decision {
    return if (permits(effective(user, virtual_path), operation)) .allow else .deny;
}

pub fn checkRename(user: *const config.UserConfig, from_path: []const u8, to_path: []const u8) Decision {
    if (check(user, .rename, from_path) == .deny) return .deny;
    if (check(user, .rename, to_path) == .deny) return .deny;
    return .allow;
}

/// Permissions any one of which allows `operation`. Only STAT takes two:
/// `list` already reveals everything STAT returns, and clients such as
/// FileZilla and WinSCP stat a directory before listing it.
fn permissionsFor(operation: Operation) config.PermissionSet {
    return switch (operation) {
        .stat => .initMany(&.{ .read, .list }),
        .open_read => .initOne(.read),
        .open_write => .initOne(.write),
        .readdir => .initOne(.list),
        .mkdir => .initOne(.mkdir),
        .remove, .rmdir => .initOne(.delete),
        .update => .initOne(.update),
        .rename => .initOne(.rename),
    };
}

/// `derivedMode` of the permissions at `vpath`.
pub fn policyDerivedMode(
    user: *const config.UserConfig,
    vpath: []const u8,
    kind_bits: u32,
) u32 {
    return derivedMode(effective(user, vpath), kind_bits);
}

/// A mode for `listing-mode virtual` showing what the partner may do,
/// not what is on disk. The file type is kept; setuid, setgid, sticky,
/// and other bits are always off; group mirrors owner.
///
///   dir:  r = stat, w = any change inside, x = list
///   file: r = download, w = write; never x. Removal is the parent's
///         `w`, as on Unix.
pub fn derivedMode(granted: config.PermissionSet, kind_bits: u32) u32 {
    const file_type = kind_bits & listing.S_IFMT;
    var owner: u32 = 0;
    switch (file_type) {
        listing.S_IFDIR => {
            // Browsable renders `r-x`, as on Unix.
            if (permits(granted, .stat)) owner |= 0o4;
            const changes: config.PermissionSet = .initMany(&.{ .write, .mkdir, .rename, .update, .delete });
            if (granted.intersectWith(changes).count() > 0) owner |= 0o2;
            if (granted.contains(.list)) owner |= 0o1;
        },
        else => {
            // `list` shows the name, not the bytes, so it gives no `r`.
            if (granted.contains(.read)) owner |= 0o4;
            if (granted.contains(.write)) owner |= 0o2;
        },
    }
    return file_type | (owner << 6) | (owner << 3);
}

/// Match a normalized virtual path against a rule pattern.
///
/// A pattern without `*` or `?` is a literal component prefix: `/pending`
/// matches `/pending` and everything below it, never `/pendingfoo`; `/`
/// matches every path that starts with `/`. Any other pattern must match
/// the whole value, where
///
/// - `?` matches one UTF-8 character other than `/` (an invalid byte
///   counts as one character);
/// - `*` matches any run, possibly empty, that contains no `/`;
/// - `**` (two or more stars) matches any run, `/` included;
/// - `**/` also matches nothing at all, so `/a/**/b` matches `/a/b`;
/// - every other byte matches itself, case-sensitively.
///
/// So `/inbox/**` does not match `/inbox`, and since a normalized path
/// starts with `/`, only a pattern starting with `/`, `**`, or `*/` can
/// match one (`*.exe` never does). A value longer than
/// `vfs.max_virtual_path_bytes` matches no wildcard pattern.
///
/// Time is O(len(pattern) * len(value)); space is one fixed buffer.
pub fn globMatch(pattern: []const u8, value: []const u8) bool {
    const head = std.mem.indexOfAny(u8, pattern, "*?") orelse
        return literalPrefixMatch(pattern, value);
    if (value.len > vfs.max_virtual_path_bytes) return false;
    // Cheap rejects: the literal text before the first wildcard and after
    // the last one (and its `/`, which `**/` may skip) must frame the value.
    var tail = std.mem.lastIndexOfAny(u8, pattern, "*?").? + 1;
    if (std.mem.endsWith(u8, pattern[0..tail], "**") and std.mem.startsWith(u8, pattern[tail..], "/")) tail += 1;
    if (!std.mem.startsWith(u8, value, pattern[0..head])) return false;
    if (!std.mem.endsWith(u8, value, pattern[tail..])) return false;

    // reach[i]: the pattern read so far can match exactly value[0..i].
    // Tokens only move offsets forward, so one array updated in place
    // suffices. Every live offset lies in [lo, hi].
    var buf: [vfs.max_virtual_path_bytes + 1]bool = undefined;
    const reach = buf[0 .. value.len + 1];
    @memset(reach, false);
    reach[head] = true;
    var lo = head;
    var hi = head;

    var p = head;
    while (p < pattern.len) {
        const token = pattern[p];
        p += 1;
        if (token != '*') {
            // One character. Descending, so each offset is read before
            // anything lands on it.
            var next_lo: usize = reach.len;
            var next_hi: usize = 0;
            var i = hi + 1;
            while (i > lo) {
                i -= 1;
                if (!reach[i]) continue;
                reach[i] = false;
                if (i == value.len) continue;
                const n: usize = if (token != '?')
                    @intFromBool(value[i] == token)
                else if (value[i] != '/')
                    charLen(value[i..])
                else
                    0;
                if (n == 0) continue;
                reach[i + n] = true;
                next_lo = @min(next_lo, i + n);
                next_hi = @max(next_hi, i + n);
            }
            if (next_lo == reach.len) return false;
            lo = next_lo;
            hi = next_hi;
            continue;
        }
        var stars: usize = 1;
        while (p < pattern.len and pattern[p] == '*') : (p += 1) stars += 1;
        if (stars == 1) {
            // `*`: extend each live offset up to the next `/`.
            var i = lo;
            while (i <= hi and i < value.len) : (i += 1) {
                if (reach[i] and value[i] != '/') {
                    reach[i + 1] = true;
                    hi = @max(hi, i + 1);
                }
            }
        } else if (p < pattern.len and pattern[p] == '/') {
            // `**/`: zero segments (offsets stay live), or resume just
            // past any later `/`.
            p += 1;
            for (value[lo..], lo..) |b, i| {
                if (b == '/') {
                    reach[i + 1] = true;
                    hi = @max(hi, i + 1);
                }
            }
        } else {
            // `**`: anything from the lowest live offset on.
            @memset(reach[lo..], true);
            hi = value.len;
        }
    }
    return reach[value.len];
}

/// Bytes in the character at the start of `s`: a whole valid UTF-8
/// sequence, else one byte. Never covers a `/` after the first byte.
fn charLen(s: []const u8) usize {
    const n = std.unicode.utf8ByteSequenceLength(s[0]) catch return 1;
    if (n > s.len or !std.unicode.utf8ValidateSlice(s[0..n])) return 1;
    return n;
}

fn literalPrefixMatch(pattern: []const u8, value: []const u8) bool {
    if (std.mem.eql(u8, pattern, value)) return true;
    if (std.mem.eql(u8, pattern, "/")) {
        return value.len > 0 and value[0] == '/';
    }
    if (!std.mem.startsWith(u8, value, pattern)) return false;
    if (value.len == pattern.len) return true;
    return value[pattern.len] == '/';
}

fn testUser(rules: []const config.Rule) config.UserConfig {
    return .{
        .name = "ally",
        .password_hash = "hash",
        .keys = &.{},
        .key_files = &.{},
        .from = &.{},
        .root = "/tmp",
        .rules = rules,
    };
}

fn allow(pattern: []const u8, permissions: []const config.Permission) config.Rule {
    return .{ .effect = .allow, .pattern = pattern, .permissions = .initMany(permissions) };
}

fn deny(pattern: []const u8) config.Rule {
    return .{ .effect = .deny, .pattern = pattern, .permissions = .initFull() };
}

const full = std.enums.values(config.Permission);

test "default deny and explicit allow" {
    const user = testUser(&.{allow("/pending", &.{ .read, .write })});
    try std.testing.expectEqual(Decision.allow, check(&user, .open_write, "/pending/file.txt"));
    try std.testing.expectEqual(Decision.deny, check(&user, .readdir, "/pending"));
    try std.testing.expectEqual(Decision.deny, check(&user, .open_write, "/archive/file.txt"));
}

test "deny overrides allow" {
    const user = testUser(&.{ allow("/", full), deny("/*.exe") });
    try std.testing.expectEqual(Decision.deny, check(&user, .open_write, "/tool.exe"));
    try std.testing.expectEqual(Decision.allow, check(&user, .open_write, "/tool.txt"));
}

test "effective: deny empties the set in any rule order, allows unite" {
    const user = testUser(&.{
        allow("/in", &.{.list}),
        deny("/in/*.exe"),
        allow("/in/**", &.{ .read, .write }),
    });
    try std.testing.expect(effective(&user, "/in/a.exe").eql(.initEmpty()));
    try std.testing.expect(effective(&user, "/in/a.csv").eql(.initMany(&.{ .list, .read, .write })));
    try std.testing.expect(effective(&user, "/in").eql(.initOne(.list)));
    try std.testing.expect(permits(effective(&user, "/in"), .stat));
    try std.testing.expect(!permits(effective(&user, "/in"), .open_read));
}

test "effective: a path longer than any client can name gets nothing" {
    const user = testUser(&.{allow("/", full)});
    const long = "/" ++ "a" ** vfs.max_virtual_path_bytes;
    try std.testing.expect(effective(&user, long).eql(.initEmpty()));
    try std.testing.expect(effective(&user, long[0..vfs.max_virtual_path_bytes]).eql(.initFull()));
}

test "pathological patterns match correctly and in linear time" {
    // Each once exhausted the old backtracking matcher's step budget or
    // took tens of milliseconds, and so was denied whatever the rules.
    var path_buf: [vfs.max_virtual_path_bytes]u8 = undefined;
    for (&path_buf, 0..) |*b, i| b.* = if (i % 64 == 0) '/' else 'a';
    const path: []const u8 = &path_buf;
    const user = testUser(&.{
        allow("/", full),
        deny("**/**/**/**/**/b"),
        deny("**a**a**a**a**a**a**a**b"),
        deny("/inbox/**/archive/**/*.csv"),
    });

    const start = sys.monotonicMs();
    try std.testing.expectEqual(Decision.allow, check(&user, .open_read, path));
    path_buf[path_buf.len - 1] = 'b';
    try std.testing.expectEqual(Decision.deny, check(&user, .open_read, path));
    try std.testing.expect(sys.monotonicMs() - start < 250);

    const archive = "/inbox" ++ "/archive" ** 510;
    try std.testing.expect(!globMatch("/inbox/**/archive/**/*.csv", archive));
    try std.testing.expect(globMatch("/inbox/**/archive/**/*.csv", archive ++ "/x.csv"));
}

test "rename checks source and destination" {
    const user = testUser(&.{allow("/pending", &.{.rename})});
    try std.testing.expectEqual(Decision.allow, checkRename(&user, "/pending/a", "/pending/b"));
    try std.testing.expectEqual(Decision.deny, checkRename(&user, "/pending/a", "/archive/b"));
}

test "literal prefix matches at component boundary" {
    try std.testing.expect(globMatch("/pending", "/pending"));
    try std.testing.expect(globMatch("/pending", "/pending/inbox"));
    try std.testing.expect(globMatch("/pending", "/pending/inbox/file.csv"));
    try std.testing.expect(!globMatch("/pending", "/pendingfoo"));
    try std.testing.expect(!globMatch("/pending", "/pendingevil/file"));
    try std.testing.expect(!globMatch("/pending", "/"));
    try std.testing.expect(!globMatch("/pending", "/other"));
}

test "root pattern matches every absolute path" {
    try std.testing.expect(globMatch("/", "/"));
    try std.testing.expect(globMatch("/", "/anything"));
    try std.testing.expect(globMatch("/", "/anything/deep/file"));
}

test "star does not cross path boundary" {
    try std.testing.expect(globMatch("*.exe", "tool.exe"));
    try std.testing.expect(!globMatch("*.exe", "/tool.exe"));
    try std.testing.expect(globMatch("/pending/*.tmp", "/pending/foo.tmp"));
    try std.testing.expect(!globMatch("/pending/*.tmp", "/pending/sub/foo.tmp"));
    try std.testing.expect(globMatch("/pending/*", "/pending/"));
    try std.testing.expect(!globMatch("/pending/*", "/pending/a/"));
}

test "question mark matches one character, not one byte, never `/`" {
    try std.testing.expect(globMatch("/?.txt", "/a.txt"));
    try std.testing.expect(globMatch("/?.txt", "/é.txt"));
    try std.testing.expect(globMatch("/?.txt", "/€.txt"));
    try std.testing.expect(globMatch("/?.txt", "/😀.txt"));
    try std.testing.expect(!globMatch("/??.txt", "/é.txt"));
    try std.testing.expect(!globMatch("/a?b", "/a/b"));
    try std.testing.expect(!globMatch("/?", "/"));
    // A byte that starts no valid character is one character.
    try std.testing.expect(globMatch("/?x", "/\xc3x"));
    try std.testing.expect(globMatch("/??", "/\xa9\xa9"));
}

test "double-star crosses path boundary" {
    // `**.exe` matches any `.exe` at any depth.
    try std.testing.expect(globMatch("**.exe", "tool.exe"));
    try std.testing.expect(globMatch("**.exe", "/tool.exe"));
    try std.testing.expect(globMatch("**.exe", "/dir/tool.exe"));
    try std.testing.expect(globMatch("**.exe", "/a/b/c/tool.exe"));
    try std.testing.expect(!globMatch("**.exe", "tool.txt"));
    try std.testing.expect(!globMatch("**.exe", "/dir/tool.txt"));

    // `/inbox/**` matches every path strictly under `/inbox/`.
    try std.testing.expect(globMatch("/inbox/**", "/inbox/file.csv"));
    try std.testing.expect(globMatch("/inbox/**", "/inbox/sub/file.csv"));
    try std.testing.expect(globMatch("/inbox/**", "/inbox/a/b/c/file.csv"));

    // Not `/inbox` itself; deny that separately.
    try std.testing.expect(!globMatch("/inbox/**", "/inbox"));
    try std.testing.expect(!globMatch("/inbox/**", "/outbox/file.csv"));

    // `/foo/**/bar` — `bar` under any subtree of `/foo/`.
    try std.testing.expect(globMatch("/foo/**/bar", "/foo/bar"));
    try std.testing.expect(globMatch("/foo/**/bar", "/foo/x/bar"));
    try std.testing.expect(globMatch("/foo/**/bar", "/foo/x/y/z/bar"));
    try std.testing.expect(!globMatch("/foo/**/bar", "/foo/baz"));
    try std.testing.expect(!globMatch("/foo/**/bar", "/foo/xbar"));

    // Three or more `*` act as `**`.
    try std.testing.expect(globMatch("***.exe", "/dir/tool.exe"));
    try std.testing.expect(globMatch("****", "/anything/at/all"));
    try std.testing.expect(globMatch("/a/***/b", "/a/b"));

    // `**` alone matches anything (including the empty string).
    try std.testing.expect(globMatch("**", ""));
    try std.testing.expect(globMatch("**", "anything"));
    try std.testing.expect(globMatch("**", "/with/slashes/in/it"));
}

test "deny **.exe denies recursively" {
    // `*.exe` would match only one level; `**.exe` matches every depth.
    const user = testUser(&.{ allow("/", full), deny("**.exe") });
    try std.testing.expectEqual(Decision.deny, check(&user, .open_write, "/tool.exe"));
    try std.testing.expectEqual(Decision.deny, check(&user, .open_write, "/sub/tool.exe"));
    try std.testing.expectEqual(Decision.deny, check(&user, .open_write, "/a/b/c/tool.exe"));
    try std.testing.expectEqual(Decision.allow, check(&user, .open_write, "/tool.txt"));
    try std.testing.expectEqual(Decision.allow, check(&user, .open_write, "/sub/dir/tool.txt"));
}

test "list satisfies STAT but never download" {
    // Browsable everywhere, downloadable in one subtree.
    const user = testUser(&.{ allow("/", &.{.list}), allow("/results", &.{ .read, .list }) });

    try std.testing.expectEqual(Decision.allow, check(&user, .stat, "/"));
    try std.testing.expectEqual(Decision.allow, check(&user, .readdir, "/"));

    // Names are visible, content is not.
    try std.testing.expectEqual(Decision.deny, check(&user, .open_read, "/"));
    try std.testing.expectEqual(Decision.deny, check(&user, .open_read, "/secret.pdf"));

    // ...and it grants nothing else, either.
    try std.testing.expectEqual(Decision.deny, check(&user, .open_write, "/"));
    try std.testing.expectEqual(Decision.deny, check(&user, .mkdir, "/"));
    try std.testing.expectEqual(Decision.deny, check(&user, .remove, "/"));
    try std.testing.expectEqual(Decision.deny, check(&user, .rename, "/"));
    try std.testing.expectEqual(Decision.deny, check(&user, .update, "/"));

    // The subtree that does carry `read` downloads normally.
    try std.testing.expectEqual(Decision.allow, check(&user, .open_read, "/results/a.pdf"));
}

test "deny still overrides list-granted stat" {
    const user = testUser(&.{ allow("/", full), deny("**/.ssh/**") });
    try std.testing.expectEqual(Decision.deny, check(&user, .stat, "/home/.ssh/id_ed25519"));
    try std.testing.expectEqual(Decision.allow, check(&user, .stat, "/home/notes.txt"));
}

test "policy-derived mode: browsable dir renders r-x, its files render ---" {
    const user = testUser(&.{allow("/", &.{.list})});
    // Directory: stat + readdir allowed, no mutation → `r-x`, mirrored
    // into group, world always empty.
    try std.testing.expectEqual(@as(u32, 0o040550), policyDerivedMode(&user, "/", 0o040755));
    // File under a list-only rule: visible in the listing, no download
    // → every permission bit off, file type preserved.
    try std.testing.expectEqual(@as(u32, 0o100000), policyDerivedMode(&user, "/a.pdf", 0o100644));
}

test "policy-derived mode: read grants r on both dirs and files" {
    const user = testUser(&.{allow("/", &.{ .read, .list })});
    try std.testing.expectEqual(@as(u32, 0o040550), policyDerivedMode(&user, "/", 0o040755));
    try std.testing.expectEqual(@as(u32, 0o100440), policyDerivedMode(&user, "/a.pdf", 0o100644));
}
