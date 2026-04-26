const std = @import("std");

pub const Permission = enum {
    read,
    write,
    list,
    mkdir,
    remove,
    rename,
};

pub const PermissionSet = std.EnumSet(Permission);

pub const RuleEffect = enum {
    allow,
    deny,
};

pub const Rule = struct {
    effect: RuleEffect,
    pattern: []const u8,
    permissions: PermissionSet,
};

pub const LogTarget = union(enum) {
    stderr,
    file: []const u8,
};

pub const ServerConfig = struct {
    listen: []const u8,
    host_key: []const u8,
    reload_interval_ms: u64,
    log: LogTarget,
};

pub const UserConfig = struct {
    name: []const u8,
    password_hash: []const u8,
    root: []const u8,
    rules: []const Rule,
};

pub const Config = struct {
    arena: std.heap.ArenaAllocator,
    server: ServerConfig,
    users: []const UserConfig,

    pub fn deinit(self: *Config) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn findUser(self: Config, name: []const u8) ?*const UserConfig {
        for (self.users) |*user| {
            if (std.mem.eql(u8, user.name, name)) return user;
        }
        return null;
    }
};

const ServerBuilder = struct {
    listen: ?[]const u8 = null,
    host_key: ?[]const u8 = null,
    reload_interval_ms: u64 = 2000,
    log: ?LogTarget = null,
};

const UserBuilder = struct {
    name: []const u8,
    password_hash: ?[]const u8 = null,
    root: ?[]const u8 = null,
    rules: std.ArrayList(Rule) = .empty,
};

const Section = enum {
    none,
    server,
    user,
};

pub const Error = error{
    DuplicateServerSection,
    DuplicateUser,
    EmptyUserName,
    InvalidConfig,
    InvalidDuration,
    InvalidIndent,
    InvalidPermission,
    InvalidUserName,
    MissingHostKey,
    MissingListen,
    MissingPassword,
    MissingRoot,
    MissingRulePattern,
    MissingRulePermissions,
    MissingServerSection,
    OutOfMemory,
    PropertyOutsideSection,
    UnknownKey,
    UnknownSection,
};

pub fn parse(gpa: std.mem.Allocator, text: []const u8) Error!Config {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const allocator = arena.allocator();

    var server: ServerBuilder = .{};
    var seen_server = false;
    var users: std.ArrayList(UserBuilder) = .empty;

    var section: Section = .none;
    var current_user: ?*UserBuilder = null;

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const no_cr = std.mem.trimEnd(u8, raw, "\r");
        const without_comment = stripComment(no_cr);
        const line = std.mem.trim(u8, without_comment, " \t");
        if (line.len == 0) continue;

        const indent = countIndent(no_cr);
        if (indent == 0) {
            current_user = null;
            if (std.mem.eql(u8, line, "server")) {
                if (seen_server) return error.DuplicateServerSection;
                seen_server = true;
                section = .server;
                continue;
            }

            if (std.mem.startsWith(u8, line, "user ")) {
                const name = std.mem.trim(u8, line["user ".len..], " \t");
                if (name.len == 0) return error.EmptyUserName;
                if (!validUserName(name)) return error.InvalidUserName;
                if (findUserBuilder(users.items, name) != null) return error.DuplicateUser;

                const stored_name = try allocator.dupe(u8, name);
                try users.append(allocator, .{ .name = stored_name });
                current_user = &users.items[users.items.len - 1];
                section = .user;
                continue;
            }

            return error.UnknownSection;
        }

        if (indent < 1) return error.InvalidIndent;

        const key, const value = splitKeyValue(line) orelse return error.InvalidConfig;
        switch (section) {
            .none => return error.PropertyOutsideSection,
            .server => try parseServerProperty(allocator, &server, key, value),
            .user => {
                const user = current_user orelse return error.PropertyOutsideSection;
                try parseUserProperty(allocator, user, key, value);
            },
        }
    }

    if (!seen_server) return error.MissingServerSection;

    const final_users = try allocator.alloc(UserConfig, users.items.len);
    for (users.items, 0..) |*builder, i| {
        final_users[i] = .{
            .name = builder.name,
            .password_hash = builder.password_hash orelse return error.MissingPassword,
            .root = builder.root orelse return error.MissingRoot,
            .rules = try builder.rules.toOwnedSlice(allocator),
        };
    }

    return .{
        .arena = arena,
        .server = .{
            .listen = server.listen orelse return error.MissingListen,
            .host_key = server.host_key orelse return error.MissingHostKey,
            .reload_interval_ms = server.reload_interval_ms,
            .log = server.log orelse .stderr,
        },
        .users = final_users,
    };
}

fn parseServerProperty(
    allocator: std.mem.Allocator,
    server: *ServerBuilder,
    key: []const u8,
    value: []const u8,
) Error!void {
    if (std.mem.eql(u8, key, "listen")) {
        server.listen = try dupNonEmpty(allocator, value);
    } else if (std.mem.eql(u8, key, "host-key")) {
        server.host_key = try dupNonEmpty(allocator, value);
    } else if (std.mem.eql(u8, key, "reload-interval")) {
        server.reload_interval_ms = try parseDurationMs(value);
    } else if (std.mem.eql(u8, key, "log")) {
        if (std.mem.eql(u8, value, "stderr")) {
            server.log = .stderr;
        } else {
            server.log = .{ .file = try dupNonEmpty(allocator, value) };
        }
    } else {
        return error.UnknownKey;
    }
}

fn parseUserProperty(
    allocator: std.mem.Allocator,
    user: *UserBuilder,
    key: []const u8,
    value: []const u8,
) Error!void {
    if (std.mem.eql(u8, key, "password")) {
        user.password_hash = try dupNonEmpty(allocator, value);
    } else if (std.mem.eql(u8, key, "root")) {
        user.root = try dupNonEmpty(allocator, value);
    } else if (std.mem.eql(u8, key, "allow")) {
        try parseAllowRule(allocator, user, value);
    } else if (std.mem.eql(u8, key, "deny")) {
        try parseDenyRules(allocator, user, value);
    } else {
        return error.UnknownKey;
    }
}

fn parseAllowRule(allocator: std.mem.Allocator, user: *UserBuilder, value: []const u8) Error!void {
    var parts = std.mem.tokenizeAny(u8, value, " \t");
    const pattern = parts.next() orelse return error.MissingRulePattern;

    var permissions = PermissionSet.initEmpty();
    var saw_permission = false;
    while (parts.next()) |token| {
        permissions.insert(parsePermission(token) orelse return error.InvalidPermission);
        saw_permission = true;
    }
    if (!saw_permission) return error.MissingRulePermissions;

    try user.rules.append(allocator, .{
        .effect = .allow,
        .pattern = try allocator.dupe(u8, pattern),
        .permissions = permissions,
    });
}

fn parseDenyRules(allocator: std.mem.Allocator, user: *UserBuilder, value: []const u8) Error!void {
    var parts = std.mem.tokenizeAny(u8, value, " \t");
    var saw_pattern = false;
    while (parts.next()) |pattern| {
        saw_pattern = true;
        try user.rules.append(allocator, .{
            .effect = .deny,
            .pattern = try allocator.dupe(u8, pattern),
            .permissions = PermissionSet.initFull(),
        });
    }
    if (!saw_pattern) return error.MissingRulePattern;
}

fn parsePermission(token: []const u8) ?Permission {
    inline for (@typeInfo(Permission).@"enum".fields) |field| {
        if (std.mem.eql(u8, token, field.name)) return @field(Permission, field.name);
    }
    return null;
}

fn parseDurationMs(value: []const u8) Error!u64 {
    if (value.len == 0) return error.InvalidDuration;
    if (std.mem.endsWith(u8, value, "ms")) {
        return std.fmt.parseUnsigned(u64, value[0 .. value.len - 2], 10) catch error.InvalidDuration;
    }
    if (std.mem.endsWith(u8, value, "s")) {
        const seconds = std.fmt.parseUnsigned(u64, value[0 .. value.len - 1], 10) catch return error.InvalidDuration;
        return seconds * 1000;
    }
    return std.fmt.parseUnsigned(u64, value, 10) catch error.InvalidDuration;
}

fn dupNonEmpty(allocator: std.mem.Allocator, value: []const u8) Error![]const u8 {
    if (value.len == 0) return error.InvalidConfig;
    return allocator.dupe(u8, value);
}

fn stripComment(line: []const u8) []const u8 {
    const index = std.mem.indexOfScalar(u8, line, '#') orelse return line;
    return line[0..index];
}

fn countIndent(line: []const u8) usize {
    var count: usize = 0;
    while (count < line.len and (line[count] == ' ' or line[count] == '\t')) : (count += 1) {}
    return count;
}

fn splitKeyValue(line: []const u8) ?struct { []const u8, []const u8 } {
    const idx = std.mem.indexOfAny(u8, line, " \t") orelse return null;
    const key = line[0..idx];
    const value = std.mem.trim(u8, line[idx..], " \t");
    if (key.len == 0 or value.len == 0) return null;
    return .{ key, value };
}

fn validUserName(name: []const u8) bool {
    for (name) |ch| {
        const ok = std.ascii.isAlphanumeric(ch) or ch == '_' or ch == '-' or ch == '.';
        if (!ok) return false;
    }
    return true;
}

fn findUserBuilder(users: []const UserBuilder, name: []const u8) ?usize {
    for (users, 0..) |user, i| {
        if (std.mem.eql(u8, user.name, name)) return i;
    }
    return null;
}

test "parse valid config" {
    const text =
        \\server
        \\  listen 127.0.0.1:2222
        \\  host-key /tmp/zift_host_ed25519
        \\  reload-interval 2s
        \\  log stderr
        \\
        \\user ally
        \\  password $argon2id$v=19$m=65536,t=3,p=4$example$hash
        \\  root /tmp/zift/ally
        \\  allow /pending read write list mkdir remove rename
        \\  allow /archive read list
        \\  deny *
        \\
    ;

    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();

    try std.testing.expectEqualStrings("127.0.0.1:2222", cfg.server.listen);
    try std.testing.expectEqual(@as(u64, 2000), cfg.server.reload_interval_ms);
    try std.testing.expectEqual(@as(usize, 1), cfg.users.len);
    const ally = cfg.findUser("ally").?;
    try std.testing.expectEqualStrings("/tmp/zift/ally", ally.root);
    try std.testing.expectEqual(@as(usize, 3), ally.rules.len);
    try std.testing.expect(ally.rules[0].permissions.contains(.write));
}

test "duplicate user is rejected" {
    const text =
        \\server
        \\  listen 127.0.0.1:2222
        \\  host-key /tmp/key
        \\
        \\user ally
        \\  password hash
        \\  root /tmp/a
        \\
        \\user ally
        \\  password hash
        \\  root /tmp/b
        \\
    ;

    try std.testing.expectError(error.DuplicateUser, parse(std.testing.allocator, text));
}

test "unknown keys are rejected" {
    const text =
        \\server
        \\  listen 127.0.0.1:2222
        \\  host-key /tmp/key
        \\  typo nope
        \\
    ;

    try std.testing.expectError(error.UnknownKey, parse(std.testing.allocator, text));
}
