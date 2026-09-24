//! Path policy: default deny, any matching `deny` wins, and an `allow`
//! must grant a permission that satisfies the operation.
//!
//! Callers pass the normalized virtual path. Pattern syntax is described
//! at `globMatch` and in docs/configure.md.

const std = @import("std");
const config = @import("config.zig");

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

/// A mode for `listing-mode virtual` showing what the partner may do at
/// `vpath`, not what is on disk. The file type is kept; setuid, setgid,
/// sticky, and other bits are always off; group mirrors owner.
///
///   file:  r = download, w = write; never x
///   dir:   r = stat, w = any change inside, x = list
pub fn policyDerivedMode(
    user: *const config.UserConfig,
    vpath: []const u8,
    kind_bits: u32,
) u32 {
    const file_type = kind_bits & 0o170000;
    const is_dir = file_type == 0o040000;

    var owner: u32 = 0;

    if (is_dir) {
        // Browsable renders `r-x`, as on Unix.
        if (check(user, .stat, vpath) == .allow) owner |= 0o4;

        const can_mutate = (check(user, .open_write, vpath) == .allow) or
            (check(user, .mkdir, vpath) == .allow) or
            (check(user, .rename, vpath) == .allow) or
            (check(user, .update, vpath) == .allow) or
            (check(user, .remove, vpath) == .allow);
        if (can_mutate) owner |= 0o2;
        if (check(user, .readdir, vpath) == .allow) owner |= 0o1;
    } else {
        // `list` shows the name, not the bytes, so it gives no `r`.
        if (check(user, .open_read, vpath) == .allow) owner |= 0o4;

        // As on Unix, removal belongs to the parent directory's `w`.
        if (check(user, .open_write, vpath) == .allow) owner |= 0o2;
    }

    return file_type | (owner << 6) | (owner << 3) | 0;
}

pub fn check(user: *const config.UserConfig, operation: Operation, virtual_path: []const u8) Decision {
    const sufficient = permissionsFor(operation);
    var allowed = false;

    for (user.rules) |rule| {
        // An exhausted glob budget cannot prove a non-match: deny.
        const matched = globMatchChecked(rule.pattern, virtual_path) orelse return .deny;
        if (!matched) continue;

        switch (rule.effect) {
            .deny => return .deny,
            .allow => {
                if (rule.permissions.intersectWith(sufficient).count() > 0) allowed = true;
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

/// Permissions any one of which allows `operation`. Only STAT takes two:
/// `list` already reveals everything STAT returns, and clients such as
/// FileZilla and WinSCP stat a directory before listing it.
fn permissionsFor(operation: Operation) config.PermissionSet {
    var set = config.PermissionSet.initEmpty();
    switch (operation) {
        .stat => {
            set.insert(.read);
            set.insert(.list);
        },
        .open_read => set.insert(.read),
        .open_write => set.insert(.write),
        .readdir => set.insert(.list),
        .mkdir => set.insert(.mkdir),
        .remove, .rmdir => set.insert(.delete),
        .update => set.insert(.update),
        .rename => set.insert(.rename),
    }
    return set;
}

/// Step budget for one glob match. `**` backtracking is superlinear in
/// the client-controlled path; real patterns need under a thousand steps.
const glob_budget: usize = 1_000_000;

const MatchCtx = struct {
    budget: usize,
    exhausted: bool = false,
};

/// Match a normalized virtual path against a config pattern.
///
/// - No `*` or `?`: a literal component prefix. `/pending` matches
///   `/pending` and `/pending/x`, never `/pendingfoo`; `/` matches all.
/// - `*` matches within one component and `?` one non-`/` byte.
/// - `**` (or more stars) matches across `/`, so `**.exe` matches at any
///   depth. `/inbox/**` does not match `/inbox` itself. `**/` also
///   matches zero segments: `/foo/**/bar` matches `/foo/bar`.
pub fn globMatch(pattern: []const u8, value: []const u8) bool {
    return globMatchChecked(pattern, value) orelse false;
}

/// `globMatch`, or null when the step budget ran out.
pub fn globMatchChecked(pattern: []const u8, value: []const u8) ?bool {
    if (std.mem.indexOfAny(u8, pattern, "*?") == null) {
        return literalPrefixMatch(pattern, value);
    }
    var ctx = MatchCtx{ .budget = glob_budget };
    const result = globMatchInner(&ctx, pattern, value);
    if (ctx.exhausted) return null;
    return result;
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

fn globMatchInner(ctx: *MatchCtx, pattern: []const u8, value: []const u8) bool {
    if (ctx.budget == 0) {
        ctx.exhausted = true;
        return false;
    }
    ctx.budget -= 1;

    if (pattern.len == 0) return value.len == 0;

    // `**/`: zero segments (a), or resume after any `/` in `value` (b).
    if (pattern.len >= 3 and pattern[0] == '*' and pattern[1] == '*') {
        var star_end: usize = 2;
        while (star_end < pattern.len and pattern[star_end] == '*') star_end += 1;
        if (star_end < pattern.len and pattern[star_end] == '/') {
            const rest = pattern[star_end + 1 ..];
            if (globMatchInner(ctx, rest, value)) return true; // (a)
            var i: usize = 0;
            while (i < value.len) : (i += 1) {
                if (value[i] == '/' and globMatchInner(ctx, rest, value[i + 1 ..])) return true; // (b)
            }
            return false;
        }
        // Fall through to the general `**` case (e.g. `**.exe`).
    }

    // `**` not followed by `/`: anything, including `/`.
    if (pattern.len >= 2 and pattern[0] == '*' and pattern[1] == '*') {
        var rest_idx: usize = 2;
        while (rest_idx < pattern.len and pattern[rest_idx] == '*') rest_idx += 1;
        const rest = pattern[rest_idx..];

        var i: usize = 0;
        while (i <= value.len) : (i += 1) {
            if (globMatchInner(ctx, rest, value[i..])) return true;
        }
        return false;
    }

    if (pattern[0] == '*') {
        var i: usize = 0;
        while (i <= value.len) : (i += 1) {
            if (globMatchInner(ctx, pattern[1..], value[i..])) return true;
            if (i < value.len and value[i] == '/') return false;
        }
        return false;
    }

    if (value.len == 0) return false;

    if (pattern[0] == '?') {
        if (value[0] == '/') return false;
        return globMatchInner(ctx, pattern[1..], value[1..]);
    }

    if (pattern[0] == value[0]) {
        return globMatchInner(ctx, pattern[1..], value[1..]);
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
        .key_files = &.{},
        .from = &.{},
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
        .key_files = &.{},
        .from = &.{},
        .root = "/tmp",
        .rules = &rules,
    };

    try std.testing.expectEqual(Decision.deny, check(&user, .open_write, "/tool.exe"));
    try std.testing.expectEqual(Decision.allow, check(&user, .open_write, "/tool.txt"));
}

test "glob budget: pathological pattern fails closed (indeterminate = deny)" {
    // Both an allow and a deny rule must resolve to deny, without hanging.
    const evil_pattern = "**a**a**a**a**a**a**a**b";
    const evil_value = "a" ** 200; // no 'b', so a naive matcher explores exponentially

    {
        var rules = [_]config.Rule{.{
            .effect = .allow,
            .pattern = evil_pattern,
            .permissions = config.PermissionSet.initFull(),
        }};
        const user: config.UserConfig = .{
            .name = "ally",
            .password_hash = "hash",
            .keys = &.{},
            .key_files = &.{},
            .from = &.{},
            .root = "/tmp",
            .rules = &rules,
        };
        try std.testing.expectEqual(Decision.deny, check(&user, .open_read, evil_value));
    }
    {
        var rules = [_]config.Rule{
            .{ .effect = .allow, .pattern = "/", .permissions = config.PermissionSet.initFull() },
            .{ .effect = .deny, .pattern = evil_pattern, .permissions = config.PermissionSet.initFull() },
        };
        const user: config.UserConfig = .{
            .name = "ally",
            .password_hash = "hash",
            .keys = &.{},
            .key_files = &.{},
            .from = &.{},
            .root = "/tmp",
            .rules = &rules,
        };
        // The deny pattern is indeterminate → whole op denied.
        try std.testing.expectEqual(Decision.deny, check(&user, .open_read, evil_value));
    }
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
        .key_files = &.{},
        .from = &.{},
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

    // Not `/inbox` itself; deny that separately.
    try std.testing.expect(!globMatch("/inbox/**", "/inbox"));
    try std.testing.expect(!globMatch("/inbox/**", "/outbox/file.csv"));

    // `/foo/**/bar` — `bar` under any subtree of `/foo/`.
    try std.testing.expect(globMatch("/foo/**/bar", "/foo/bar"));
    try std.testing.expect(globMatch("/foo/**/bar", "/foo/x/bar"));
    try std.testing.expect(globMatch("/foo/**/bar", "/foo/x/y/z/bar"));
    try std.testing.expect(!globMatch("/foo/**/bar", "/foo/baz"));

    // Three or more `*` act as `**`.
    try std.testing.expect(globMatch("***.exe", "/dir/tool.exe"));
    try std.testing.expect(globMatch("****", "/anything/at/all"));

    // `**` alone matches anything (including the empty string).
    try std.testing.expect(globMatch("**", ""));
    try std.testing.expect(globMatch("**", "anything"));
    try std.testing.expect(globMatch("**", "/with/slashes/in/it"));
}

test "deny **.exe denies recursively" {
    // `*.exe` would match only one level; `**.exe` matches every depth.
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
        .key_files = &.{},
        .from = &.{},
        .root = "/tmp",
        .rules = &rules,
    };

    try std.testing.expectEqual(Decision.deny, check(&user, .open_write, "/tool.exe"));
    try std.testing.expectEqual(Decision.deny, check(&user, .open_write, "/sub/tool.exe"));
    try std.testing.expectEqual(Decision.deny, check(&user, .open_write, "/a/b/c/tool.exe"));
    try std.testing.expectEqual(Decision.allow, check(&user, .open_write, "/tool.txt"));
    try std.testing.expectEqual(Decision.allow, check(&user, .open_write, "/sub/dir/tool.txt"));
}

test "list satisfies STAT but never download" {
    // Browsable everywhere, downloadable in one subtree.
    var rules = [_]config.Rule{
        .{
            .effect = .allow,
            .pattern = "/",
            .permissions = blk: {
                var set = config.PermissionSet.initEmpty();
                set.insert(.list);
                break :blk set;
            },
        },
        .{
            .effect = .allow,
            .pattern = "/results",
            .permissions = blk: {
                var set = config.PermissionSet.initEmpty();
                set.insert(.read);
                set.insert(.list);
                break :blk set;
            },
        },
    };
    const user: config.UserConfig = .{
        .name = "ola",
        .password_hash = "hash",
        .keys = &.{},
        .key_files = &.{},
        .from = &.{},
        .root = "/tmp",
        .rules = &rules,
    };

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
    var rules = [_]config.Rule{
        .{ .effect = .allow, .pattern = "/", .permissions = config.PermissionSet.initFull() },
        .{ .effect = .deny, .pattern = "**/.ssh/**", .permissions = config.PermissionSet.initFull() },
    };
    const user: config.UserConfig = .{
        .name = "ola",
        .password_hash = "hash",
        .keys = &.{},
        .key_files = &.{},
        .from = &.{},
        .root = "/tmp",
        .rules = &rules,
    };

    try std.testing.expectEqual(Decision.deny, check(&user, .stat, "/home/.ssh/id_ed25519"));
    try std.testing.expectEqual(Decision.allow, check(&user, .stat, "/home/notes.txt"));
}

test "policy-derived mode: browsable dir renders r-x, its files render ---" {
    var rules = [_]config.Rule{
        .{
            .effect = .allow,
            .pattern = "/",
            .permissions = blk: {
                var set = config.PermissionSet.initEmpty();
                set.insert(.list);
                break :blk set;
            },
        },
    };
    const user: config.UserConfig = .{
        .name = "ola",
        .password_hash = "hash",
        .keys = &.{},
        .key_files = &.{},
        .from = &.{},
        .root = "/tmp",
        .rules = &rules,
    };

    // Directory: stat + readdir allowed, no mutation → `r-x`, mirrored
    // into group, world always empty.
    const dir_mode = policyDerivedMode(&user, "/", 0o040755);
    try std.testing.expectEqual(@as(u32, 0o040550), dir_mode);

    // File under a list-only rule: visible in the listing, no download
    // → every permission bit off, file type preserved.
    const file_mode = policyDerivedMode(&user, "/a.pdf", 0o100644);
    try std.testing.expectEqual(@as(u32, 0o100000), file_mode);
}

test "policy-derived mode: read grants r on both dirs and files" {
    var rules = [_]config.Rule{
        .{
            .effect = .allow,
            .pattern = "/",
            .permissions = blk: {
                var set = config.PermissionSet.initEmpty();
                set.insert(.read);
                set.insert(.list);
                break :blk set;
            },
        },
    };
    const user: config.UserConfig = .{
        .name = "ola",
        .password_hash = "hash",
        .keys = &.{},
        .key_files = &.{},
        .from = &.{},
        .root = "/tmp",
        .rules = &rules,
    };

    try std.testing.expectEqual(@as(u32, 0o040550), policyDerivedMode(&user, "/", 0o040755));
    try std.testing.expectEqual(@as(u32, 0o100440), policyDerivedMode(&user, "/a.pdf", 0o100644));
}
