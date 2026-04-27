const std = @import("std");
const vfs = @import("vfs.zig");

/// Errors produced by `validateSemantic` for cross-cutting checks that
/// can only be performed against a live filesystem (PLAN.md §6.2). The
/// individual error names are also written to stderr verbatim by the
/// validator for operator-facing diagnostics; integration tests grep for
/// the specific phrase next to the error to assert the right rejection.
pub const SemanticError = error{
    HostKeyUnreadable,
    UserRootMissing,
    UserRootNotDirectory,
    OverlappingRoots,
    OutOfMemory,
};

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
    /// Per PLAN.md §6.2 default 300_000 (5 minutes). 0 disables the timeout.
    idle_timeout_ms: u64,
    /// Per PLAN.md §6.2 default 128. Excess accepted connections are
    /// disconnected immediately at the SSH layer with an audit line.
    max_connections: u32,
    log: LogTarget,
};

/// A public key authorized for a virtual user. Stored as the raw OpenSSH
/// algorithm name and base64 blob from the config; libssh re-parses these
/// into `ssh_key` values when matching a presented key at auth time.
pub const PublicKey = struct {
    /// One of "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
    /// "ecdsa-sha2-nistp521" (PLAN.md §8.4 accepted algorithms).
    algorithm: []const u8,
    /// Base64 blob (the second field of an OpenSSH public-key line).
    blob: []const u8,
};

pub const UserConfig = struct {
    name: []const u8,
    /// Argon2id PHC string when password auth is provisioned, else null.
    password_hash: ?[]const u8,
    /// Public keys authorized for this user. May be empty.
    keys: []const PublicKey,
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

/// Cross-cutting semantic validation against the live filesystem.
///
/// `parse` only proves the config is *syntactically* well-formed and
/// internally consistent (Argon2id parameter envelope, accepted key
/// algorithms, no users without credentials). PLAN.md §6.2 also
/// requires that, before a config is allowed to take effect:
///
///   - the configured `host-key` path is readable,
///   - every user's `root` exists and is a directory,
///   - no two user roots overlap (one is `==` or path-prefix of another).
///
/// Called from `zift validate`, from `zift serve` startup, and from the
/// runtime reload path. Diagnostics are written to stderr in the
/// canonical `zift: ...` form so the same message appears whether the
/// rejection happens at validate time, startup time, or reload time.
pub fn validateSemantic(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: *const Config,
) SemanticError!void {
    const stderr = std.Io.File.stderr();

    // 1. Host-key file must exist and be readable.
    _ = std.Io.Dir.cwd().statFile(io, cfg.server.host_key, .{}) catch {
        stderr.writeStreamingAll(io, "zift: host-key unreadable: ") catch {};
        stderr.writeStreamingAll(io, cfg.server.host_key) catch {};
        stderr.writeStreamingAll(io, "\n") catch {};
        return error.HostKeyUnreadable;
    };

    // 2. Each user root must exist, be a directory, and canonicalize
    // through symlinks. We canonicalize via realPath so the overlap
    // check below operates on absolute symlink-resolved paths, the
    // same form the per-request `vfs.isInsideRoot` check uses.
    // `realPathFileAbsoluteAlloc` returns a sentinel-terminated slice
    // (`[:0]const u8`), and `Allocator.free` requires the freeing call
    // to use the same sentinel-typed slice it was allocated with — the
    // backing allocation length includes the trailing null. Storing as
    // `[]const u8` strips the sentinel and triggers `Invalid free`.
    var canonical_roots = try allocator.alloc([:0]const u8, cfg.users.len);
    var canonical_count: usize = 0;
    defer {
        for (canonical_roots[0..canonical_count]) |path| allocator.free(path);
        allocator.free(canonical_roots);
    }

    for (cfg.users) |*user| {
        // Resolve the user's root (follows symlinks; fails on missing).
        const real = std.Io.Dir.realPathFileAbsoluteAlloc(io, user.root, allocator) catch {
            stderr.writeStreamingAll(io, "zift: user '") catch {};
            stderr.writeStreamingAll(io, user.name) catch {};
            stderr.writeStreamingAll(io, "' root does not exist or is unreadable: ") catch {};
            stderr.writeStreamingAll(io, user.root) catch {};
            stderr.writeStreamingAll(io, "\n") catch {};
            return error.UserRootMissing;
        };
        // Verify the resolved target is actually a directory.
        const dir = std.Io.Dir.openDirAbsolute(io, real, .{}) catch {
            allocator.free(real);
            stderr.writeStreamingAll(io, "zift: user '") catch {};
            stderr.writeStreamingAll(io, user.name) catch {};
            stderr.writeStreamingAll(io, "' root is not a directory: ") catch {};
            stderr.writeStreamingAll(io, user.root) catch {};
            stderr.writeStreamingAll(io, "\n") catch {};
            return error.UserRootNotDirectory;
        };
        dir.close(io);

        canonical_roots[canonical_count] = real;
        canonical_count += 1;
    }

    // 3. Overlap detection on the canonicalized paths. Two roots
    // overlap iff one is equal to or a path-component prefix of the
    // other (PLAN.md §6.2). Equal roots are caught by `isInsideRoot`'s
    // `eql` short-circuit, so the symmetric check is enough.
    for (canonical_roots[0..canonical_count], 0..) |a, i| {
        for (canonical_roots[i + 1 .. canonical_count], i + 1..) |b, j| {
            if (vfs.isInsideRoot(a, b) or vfs.isInsideRoot(b, a)) {
                stderr.writeStreamingAll(io, "zift: overlapping roots for users '") catch {};
                stderr.writeStreamingAll(io, cfg.users[i].name) catch {};
                stderr.writeStreamingAll(io, "' and '") catch {};
                stderr.writeStreamingAll(io, cfg.users[j].name) catch {};
                stderr.writeStreamingAll(io, "': ") catch {};
                stderr.writeStreamingAll(io, a) catch {};
                stderr.writeStreamingAll(io, " vs ") catch {};
                stderr.writeStreamingAll(io, b) catch {};
                stderr.writeStreamingAll(io, "\n") catch {};
                return error.OverlappingRoots;
            }
        }
    }
}

const ServerBuilder = struct {
    listen: ?[]const u8 = null,
    host_key: ?[]const u8 = null,
    reload_interval_ms: u64 = 2000,
    idle_timeout_ms: u64 = 300_000,
    max_connections: u32 = 128,
    log: ?LogTarget = null,
};

const UserBuilder = struct {
    name: []const u8,
    password_hash: ?[]const u8 = null,
    keys: std.ArrayList(PublicKey) = .empty,
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
    InvalidKeyLine,
    InvalidPermission,
    InvalidUserName,
    MissingCredentials,
    MissingHostKey,
    MissingListen,
    MissingRoot,
    MissingRulePattern,
    MissingRulePermissions,
    MissingServerSection,
    OutOfMemory,
    PasswordHashNotArgon2id,
    PasswordHashMalformed,
    PasswordMemoryOutOfPolicy,
    PasswordPassesOutOfPolicy,
    PasswordParallelismOutOfPolicy,
    PropertyOutsideSection,
    UnknownKey,
    UnknownSection,
    UnsupportedKeyAlgorithm,
};

/// Public-key algorithms accepted in `key` lines, per PLAN.md §8.4.
/// RSA and DSA are deliberately not on this list.
const accepted_key_algorithms = [_][]const u8{
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
};

fn isAcceptedKeyAlgorithm(algo: []const u8) bool {
    for (accepted_key_algorithms) |accepted| {
        if (std.mem.eql(u8, algo, accepted)) return true;
    }
    return false;
}

/// Accepted Argon2id parameter envelope per PLAN.md §8.4. Password property
/// values whose embedded parameters fall outside this envelope are rejected
/// at parse time so the unknown-user dummy hash (PLAN.md §8.4) can use a
/// single upper-bound profile and still time-match every real user.
pub const argon2id_policy = Argon2idPolicy{
    .m_min = 65536, // 64 MiB
    .m_max = 262144, // 256 MiB
    .t_min = 2,
    .t_max = 8,
    .p_min = 1,
    .p_max = 4,
};

pub const Argon2idPolicy = struct {
    m_min: u32,
    m_max: u32,
    t_min: u32,
    t_max: u32,
    p_min: u32,
    p_max: u32,
};

/// Validate a `password` property value: it must be an Argon2id PHC string
/// whose embedded `m`, `t`, and `p` parameters fall inside the envelope.
fn checkArgon2idPolicy(phc: []const u8, policy: Argon2idPolicy) Error!void {
    const prefix = "$argon2id$";
    if (!std.mem.startsWith(u8, phc, prefix)) return error.PasswordHashNotArgon2id;

    var iter = std.mem.splitScalar(u8, phc, '$');
    _ = iter.next(); // leading empty segment
    _ = iter.next(); // "argon2id"
    _ = iter.next() orelse return error.PasswordHashMalformed; // "v=19"
    const params = iter.next() orelse return error.PasswordHashMalformed; // m=...,t=...,p=...
    _ = iter.next() orelse return error.PasswordHashMalformed; // salt
    _ = iter.next() orelse return error.PasswordHashMalformed; // hash

    var m: ?u32 = null;
    var t: ?u32 = null;
    var p: ?u32 = null;
    var pairs = std.mem.splitScalar(u8, params, ',');
    while (pairs.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse return error.PasswordHashMalformed;
        const k = pair[0..eq];
        const v = std.fmt.parseUnsigned(u32, pair[eq + 1 ..], 10) catch return error.PasswordHashMalformed;
        if (std.mem.eql(u8, k, "m")) m = v;
        if (std.mem.eql(u8, k, "t")) t = v;
        if (std.mem.eql(u8, k, "p")) p = v;
    }

    const m_val = m orelse return error.PasswordHashMalformed;
    const t_val = t orelse return error.PasswordHashMalformed;
    const p_val = p orelse return error.PasswordHashMalformed;

    if (m_val < policy.m_min or m_val > policy.m_max) return error.PasswordMemoryOutOfPolicy;
    if (t_val < policy.t_min or t_val > policy.t_max) return error.PasswordPassesOutOfPolicy;
    if (p_val < policy.p_min or p_val > policy.p_max) return error.PasswordParallelismOutOfPolicy;
}

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
        if (builder.password_hash == null and builder.keys.items.len == 0) {
            return error.MissingCredentials;
        }
        final_users[i] = .{
            .name = builder.name,
            .password_hash = builder.password_hash,
            .keys = try builder.keys.toOwnedSlice(allocator),
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
            .idle_timeout_ms = server.idle_timeout_ms,
            .max_connections = server.max_connections,
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
    } else if (std.mem.eql(u8, key, "idle-timeout")) {
        server.idle_timeout_ms = try parseDurationMs(value);
    } else if (std.mem.eql(u8, key, "max-connections")) {
        server.max_connections = std.fmt.parseUnsigned(u32, value, 10) catch return error.InvalidConfig;
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
        try checkArgon2idPolicy(value, argon2id_policy);
        user.password_hash = try dupNonEmpty(allocator, value);
    } else if (std.mem.eql(u8, key, "key")) {
        try parseUserKey(allocator, user, value);
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

fn parseUserKey(allocator: std.mem.Allocator, user: *UserBuilder, value: []const u8) Error!void {
    var parts = std.mem.tokenizeAny(u8, value, " \t");
    const algorithm = parts.next() orelse return error.InvalidKeyLine;
    const blob = parts.next() orelse return error.InvalidKeyLine;
    // Anything after the blob (the comment) is intentionally ignored.

    if (!isAcceptedKeyAlgorithm(algorithm)) return error.UnsupportedKeyAlgorithm;
    if (blob.len == 0) return error.InvalidKeyLine;

    try user.keys.append(allocator, .{
        .algorithm = try allocator.dupe(u8, algorithm),
        .blob = try allocator.dupe(u8, blob),
    });
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

// Reused fixture for tests below: a syntactically valid PHC string with
// parameters inside the policy envelope. The salt and hash bodies are not
// real Argon2id outputs; the parser only validates structure, not crypto.
const valid_test_phc = "$argon2id$v=19$m=65536,t=3,p=1$xxxxxxxxxxxx$yyyyyyyyyyyy";

test "duplicate user is rejected" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  password " ++ valid_test_phc ++ "\n  root /tmp/a\n\n" ++
        "user ally\n  password " ++ valid_test_phc ++ "\n  root /tmp/b\n";
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

test "password rejected when not argon2id" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  password $bcrypt$something\n  root /tmp/a\n";
    try std.testing.expectError(error.PasswordHashNotArgon2id, parse(std.testing.allocator, text));
}

test "password rejected when phc malformed" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  password $argon2id$broken\n  root /tmp/a\n";
    try std.testing.expectError(error.PasswordHashMalformed, parse(std.testing.allocator, text));
}

test "password rejected when memory below envelope" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  password $argon2id$v=19$m=4096,t=3,p=1$xxxxxxxxxxxx$yyyyyyyyyyyy\n  root /tmp/a\n";
    try std.testing.expectError(error.PasswordMemoryOutOfPolicy, parse(std.testing.allocator, text));
}

test "password rejected when memory above envelope" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  password $argon2id$v=19$m=524288,t=3,p=1$xxxxxxxxxxxx$yyyyyyyyyyyy\n  root /tmp/a\n";
    try std.testing.expectError(error.PasswordMemoryOutOfPolicy, parse(std.testing.allocator, text));
}

test "password rejected when passes below envelope" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  password $argon2id$v=19$m=65536,t=1,p=1$xxxxxxxxxxxx$yyyyyyyyyyyy\n  root /tmp/a\n";
    try std.testing.expectError(error.PasswordPassesOutOfPolicy, parse(std.testing.allocator, text));
}

test "password rejected when parallelism above envelope" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  password $argon2id$v=19$m=65536,t=3,p=8$xxxxxxxxxxxx$yyyyyyyyyyyy\n  root /tmp/a\n";
    try std.testing.expectError(error.PasswordParallelismOutOfPolicy, parse(std.testing.allocator, text));
}

test "password accepted at envelope boundaries" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  password $argon2id$v=19$m=262144,t=8,p=4$xxxxxxxxxxxx$yyyyyyyyyyyy\n  root /tmp/a\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
}

test "key-only user accepted" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user runner\n  key ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBLAH runner-1\n  root /tmp/a\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqual(@as(usize, 1), cfg.users.len);
    try std.testing.expectEqual(@as(?[]const u8, null), cfg.users[0].password_hash);
    try std.testing.expectEqual(@as(usize, 1), cfg.users[0].keys.len);
    try std.testing.expectEqualStrings("ssh-ed25519", cfg.users[0].keys[0].algorithm);
    try std.testing.expectEqualStrings("AAAAC3NzaC1lZDI1NTE5AAAAIBLAH", cfg.users[0].keys[0].blob);
}

test "multiple keys per user accepted" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user runner\n" ++
        "  key ssh-ed25519 AAAAC3aaaa primary\n" ++
        "  key ecdsa-sha2-nistp256 AAAAE2bbbb backup\n" ++
        "  root /tmp/a\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqual(@as(usize, 2), cfg.users[0].keys.len);
    try std.testing.expectEqualStrings("ecdsa-sha2-nistp256", cfg.users[0].keys[1].algorithm);
}

test "rsa key rejected" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user runner\n  key ssh-rsa AAAAB3NzaC1yc2EAAAA notallowed\n  root /tmp/a\n";
    try std.testing.expectError(error.UnsupportedKeyAlgorithm, parse(std.testing.allocator, text));
}

test "dsa key rejected" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user runner\n  key ssh-dss AAAAB3NzaC1kc3MAAAA legacy\n  root /tmp/a\n";
    try std.testing.expectError(error.UnsupportedKeyAlgorithm, parse(std.testing.allocator, text));
}

test "key line missing blob rejected" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user runner\n  key ssh-ed25519\n  root /tmp/a\n";
    try std.testing.expectError(error.InvalidKeyLine, parse(std.testing.allocator, text));
}

test "user with neither password nor key rejected" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user empty\n  root /tmp/a\n";
    try std.testing.expectError(error.MissingCredentials, parse(std.testing.allocator, text));
}

test "server defaults applied when properties omitted" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqual(@as(u64, 300_000), cfg.server.idle_timeout_ms);
    try std.testing.expectEqual(@as(u32, 128), cfg.server.max_connections);
}

test "idle-timeout and max-connections parse" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n  idle-timeout 30s\n  max-connections 64\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqual(@as(u64, 30_000), cfg.server.idle_timeout_ms);
    try std.testing.expectEqual(@as(u32, 64), cfg.server.max_connections);
}
