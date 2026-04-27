const std = @import("std");
const config = @import("config.zig");

pub const Operation = enum {
    open_read,
    open_write,
    stat,
    lstat,
    readdir,
    mkdir,
    remove,
    rmdir,
    rename,
};

pub const Decision = enum {
    allow,
    deny,
};

/// Compose a fictional `mode_t`-shaped value for `vpath` from this
/// user's policy and the entry's real file kind. Used by the virtual
/// listing renderer (`listing-mode virtual`, default in v0.3.0+) so
/// `sftp> ls -la` shows a partner what they can actually DO with each
/// entry rather than what's on disk.
///
/// The mapping has DIFFERENT semantics for files vs directories,
/// because `w` means different things in those two worlds:
///
///   File-type bits        : preserved from the inode (`d` / `-` / `l` / ...)
///   setuid/setgid/sticky  : ALWAYS off — operational, not partner-facing
///
///   For a FILE:
///     r  = `read`   permission grants `SSH_FXP_OPEN(read)` / STAT
///     w  = `write`  permission grants `SSH_FXP_OPEN(write)` —
///          ability to overwrite the byte content. Note: removal is
///          NOT counted toward the file's `w` bit; deletion is a
///          property of the parent directory (you `unlink`-from-the-
///          dir, not `unlink`-the-file).
///     x  = always 0. SFTP doesn't execute files; the bit has no
///          useful meaning to a partner.
///
///   For a DIRECTORY:
///     r  = `read`   permission grants STAT/LSTAT
///     w  = ANY mutation perm (`write` OR `mkdir` OR `rename` OR
///          `remove`) — this directory's *contents* can change. A
///          partner with rename-only or mkdir-only sees `w` even
///          though they can't open files for write at this path.
///     x  = `list`   permission grants `OPENDIR`/`READDIR` and
///          traversal. (Following Unix convention: a dir with
///          traverse-but-not-list is an obscurity, not a security
///          property; we just couple them.)
///
///   Group triplet  : MIRRORS owner — the partner is the only
///                    inhabitant of their jail, "group" doesn't model
///                    anyone else.
///   Other triplet  : ALWAYS `---` — there is no third class of
///                    viewer in the jail, so showing world bits would
///                    imply a reader who doesn't exist.
pub fn policyDerivedMode(
    user: *const config.UserConfig,
    vpath: []const u8,
    kind_bits: u32,
) u32 {
    const file_type = kind_bits & 0o170000;
    const is_dir = file_type == 0o040000;

    const can_read = check(user, .open_read, vpath) == .allow;

    var owner: u32 = 0;
    if (can_read) owner |= 0o4;

    if (is_dir) {
        // Dir: any of the four mutation ops contributes to `w`. Each
        // op corresponds to a DIFFERENT verb in the config DSL
        // (`write`, `mkdir`, `rename`, `remove`), so we must check
        // them all — a partner with `mkdir` but not `write` still
        // gets `w` because they CAN mutate this directory's contents.
        const can_mutate = (check(user, .open_write, vpath) == .allow) or
            (check(user, .mkdir, vpath) == .allow) or
            (check(user, .rename, vpath) == .allow) or
            (check(user, .remove, vpath) == .allow);
        if (can_mutate) owner |= 0o2;
        if (check(user, .readdir, vpath) == .allow) owner |= 0o1;
    } else {
        // File: `w` strictly means "can rewrite byte content"
        // (= `write` permission, which gates `SSH_FXP_OPEN(write)`).
        // Removal of the file is a property of the parent dir's
        // policy, not this file's mode bits — exactly like Unix,
        // where `rm somefile` consults the dir's `w` bit, not the
        // file's.
        if (check(user, .open_write, vpath) == .allow) owner |= 0o2;
    }

    return file_type | (owner << 6) | (owner << 3) | 0;
}

pub fn check(user: *const config.UserConfig, operation: Operation, virtual_path: []const u8) Decision {
    const needed = permissionFor(operation);
    var allowed = false;

    for (user.rules) |rule| {
        if (!globMatch(rule.pattern, virtual_path)) continue;

        switch (rule.effect) {
            .deny => return .deny,
            .allow => {
                if (rule.permissions.contains(needed)) allowed = true;
            },
        }
    }

    return if (allowed) .allow else .deny;
}

pub fn checkRename(user: *const config.UserConfig, from_path: []const u8, to_path: []const u8) Decision {
    if (check(user, .rename, from_path) == .deny) return .deny;
    if (check(user, .rename, to_path) == .deny) return .deny;
    return .allow;
}

fn permissionFor(operation: Operation) config.Permission {
    return switch (operation) {
        .open_read, .stat, .lstat => .read,
        .open_write => .write,
        .readdir => .list,
        .mkdir => .mkdir,
        .remove, .rmdir => .remove,
        .rename => .rename,
    };
}

/// Match a virtual path against a config pattern per PLAN.md §6.3.
///
/// - Patterns with no `*` or `?` are **literal path-component prefix**
///   matches: pattern matches path P iff P equals the pattern, or P
///   starts with the pattern followed by `/`. So `/pending` matches
///   `/pending`, `/pending/inbox`, `/pending/inbox/file.csv`, but
///   never `/pendingfoo`. The root pattern `/` matches every path
///   that begins with `/`.
/// - Patterns containing `*` or `?` are globs. Three wildcards:
///     `*`   — any sequence not including `/` (single component).
///     `?`   — exactly one character that is not `/`.
///     `**`  — any sequence INCLUDING `/` (cross-component). Runs of
///             three or more `*` collapse to one `**`. So
///             `deny **.exe` correctly denies `foo.exe`, `dir/foo.exe`,
///             and `dir/sub/foo.exe` alike. `/inbox/**` matches all
///             contents of `/inbox` at any depth, but NOT `/inbox`
///             itself (matching gitignore convention).
pub fn globMatch(pattern: []const u8, value: []const u8) bool {
    if (std.mem.indexOfAny(u8, pattern, "*?") == null) {
        return literalPrefixMatch(pattern, value);
    }
    return globMatchInner(pattern, value);
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

fn globMatchInner(pattern: []const u8, value: []const u8) bool {
    if (pattern.len == 0) return value.len == 0;

    // `**/` — gitignore-style "zero or more path segments". Allows
    // `/foo/**/bar` to match `/foo/bar` (zero intermediates),
    // `/foo/x/bar` (one), `/foo/x/y/bar` (two), etc. Without this
    // special case the literal `/` in the pattern after `**` would
    // require at least one segment between the two slashes — the
    // surprise behavior the live demo surfaced.
    //
    // Detection: pattern starts with two or more `*` followed by `/`.
    // We collapse the run of `*` and then split on the trailing slash.
    // The wildcard then matches either:
    //   (a) zero segments — `pattern[after_slash..]` runs against `value`
    //       directly, as if `**/` weren't there.
    //   (b) one or more segments — try every `/` position in `value`
    //       as the boundary.
    if (pattern.len >= 3 and pattern[0] == '*' and pattern[1] == '*') {
        var star_end: usize = 2;
        while (star_end < pattern.len and pattern[star_end] == '*') star_end += 1;
        if (star_end < pattern.len and pattern[star_end] == '/') {
            const rest = pattern[star_end + 1 ..];
            if (globMatchInner(rest, value)) return true; // (a)
            var i: usize = 0;
            while (i < value.len) : (i += 1) {
                if (value[i] == '/' and globMatchInner(rest, value[i + 1 ..])) return true; // (b)
            }
            return false;
        }
        // Fall through to the general `**` case (e.g. `**.exe`).
    }

    // General `**` — two or more consecutive `*` not followed by `/`.
    // Matches any sequence of characters INCLUDING `/`. We collapse
    // runs of three or more `*` to a single cross-slash wildcard so
    // `***...*` doesn't blow up the recursion in the pathological
    // pattern case.
    if (pattern.len >= 2 and pattern[0] == '*' and pattern[1] == '*') {
        var rest_idx: usize = 2;
        while (rest_idx < pattern.len and pattern[rest_idx] == '*') rest_idx += 1;
        const rest = pattern[rest_idx..];

        var i: usize = 0;
        while (i <= value.len) : (i += 1) {
            if (globMatchInner(rest, value[i..])) return true;
        }
        return false;
    }

    if (pattern[0] == '*') {
        // `*` does not cross path boundaries (PLAN §6.3).
        var i: usize = 0;
        while (i <= value.len) : (i += 1) {
            if (globMatchInner(pattern[1..], value[i..])) return true;
            if (i < value.len and value[i] == '/') return false;
        }
        return false;
    }

    if (value.len == 0) return false;

    if (pattern[0] == '?') {
        // `?` does not cross path boundaries (PLAN §6.3).
        if (value[0] == '/') return false;
        return globMatchInner(pattern[1..], value[1..]);
    }

    if (pattern[0] == value[0]) {
        return globMatchInner(pattern[1..], value[1..]);
    }

    return false;
}

test "default deny and explicit allow" {
    var rules = [_]config.Rule{
        .{
            .effect = .allow,
            .pattern = "/pending",
            .permissions = blk: {
                var set = config.PermissionSet.initEmpty();
                set.insert(.read);
                set.insert(.write);
                break :blk set;
            },
        },
    };
    const user: config.UserConfig = .{
        .name = "ally",
        .password_hash = "hash",
        .keys = &.{},
        .root = "/tmp",
        .rules = &rules,
    };

    try std.testing.expectEqual(Decision.allow, check(&user, .open_write, "/pending/file.txt"));
    try std.testing.expectEqual(Decision.deny, check(&user, .readdir, "/pending"));
    try std.testing.expectEqual(Decision.deny, check(&user, .open_write, "/archive/file.txt"));
}

test "deny overrides allow" {
    var rules = [_]config.Rule{
        .{
            .effect = .allow,
            .pattern = "/",
            .permissions = config.PermissionSet.initFull(),
        },
        .{
            .effect = .deny,
            .pattern = "/*.exe",
            .permissions = config.PermissionSet.initFull(),
        },
    };
    const user: config.UserConfig = .{
        .name = "ally",
        .password_hash = "hash",
        .keys = &.{},
        .root = "/tmp",
        .rules = &rules,
    };

    try std.testing.expectEqual(Decision.deny, check(&user, .open_write, "/tool.exe"));
    try std.testing.expectEqual(Decision.allow, check(&user, .open_write, "/tool.txt"));
}

test "rename checks source and destination" {
    var rules = [_]config.Rule{
        .{
            .effect = .allow,
            .pattern = "/pending",
            .permissions = blk: {
                var set = config.PermissionSet.initEmpty();
                set.insert(.rename);
                break :blk set;
            },
        },
    };
    const user: config.UserConfig = .{
        .name = "ally",
        .password_hash = "hash",
        .keys = &.{},
        .root = "/tmp",
        .rules = &rules,
    };

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

    // gitignore convention: `/inbox/**` does NOT match `/inbox` itself
    // (no character available for `**` to consume after the trailing
    // `/`). Operators that want to deny the dir too write
    // `deny /inbox` separately.
    try std.testing.expect(!globMatch("/inbox/**", "/inbox"));
    try std.testing.expect(!globMatch("/inbox/**", "/outbox/file.csv"));

    // `/foo/**/bar` — `bar` under any subtree of `/foo/`.
    try std.testing.expect(globMatch("/foo/**/bar", "/foo/bar"));
    try std.testing.expect(globMatch("/foo/**/bar", "/foo/x/bar"));
    try std.testing.expect(globMatch("/foo/**/bar", "/foo/x/y/z/bar"));
    try std.testing.expect(!globMatch("/foo/**/bar", "/foo/baz"));

    // Three or more `*` collapse to `**` (no recursive blowup, no
    // semantic surprise).
    try std.testing.expect(globMatch("***.exe", "/dir/tool.exe"));
    try std.testing.expect(globMatch("****", "/anything/at/all"));

    // `**` alone matches anything (including the empty string).
    try std.testing.expect(globMatch("**", ""));
    try std.testing.expect(globMatch("**", "anything"));
    try std.testing.expect(globMatch("**", "/with/slashes/in/it"));
}

test "deny **.exe denies recursively" {
    // The `*.exe` footgun the live demo surfaced: with single-star
    // semantics, `deny *.exe` only matches `.exe` files in the
    // current directory level. `deny **.exe` does the right thing.
    var rules = [_]config.Rule{
        .{
            .effect = .allow,
            .pattern = "/",
            .permissions = config.PermissionSet.initFull(),
        },
        .{
            .effect = .deny,
            .pattern = "**.exe",
            .permissions = config.PermissionSet.initFull(),
        },
    };
    const user: config.UserConfig = .{
        .name = "ally",
        .password_hash = "hash",
        .keys = &.{},
        .root = "/tmp",
        .rules = &rules,
    };

    try std.testing.expectEqual(Decision.deny, check(&user, .open_write, "/tool.exe"));
    try std.testing.expectEqual(Decision.deny, check(&user, .open_write, "/sub/tool.exe"));
    try std.testing.expectEqual(Decision.deny, check(&user, .open_write, "/a/b/c/tool.exe"));
    try std.testing.expectEqual(Decision.allow, check(&user, .open_write, "/tool.txt"));
    try std.testing.expectEqual(Decision.allow, check(&user, .open_write, "/sub/dir/tool.txt"));
}
