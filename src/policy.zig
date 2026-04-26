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
/// - Patterns containing `*` or `?` are globs. `*` matches any
///   sequence of characters not including `/`; `?` matches any single
///   character that is not `/`.
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
