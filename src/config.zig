//! Config file parser and filesystem validation.
//!
//! `parse` checks syntax and internal consistency only; `validateSemantic`
//! then checks the live filesystem (host key, roots, key files) before a
//! config may take effect. Grammar and directives: docs/configure.md.

const std = @import("std");
const passhash = @import("passhash.zig");
const netmatch = @import("netmatch.zig");
const sys = @import("sys.zig");
const vfs = @import("vfs.zig");

/// Filesystem checks that fail `validateSemantic`. Each also writes a
/// specific stderr line, which integration tests grep for.
pub const SemanticError = error{
    HostKeyUnreadable,
    UserRootMissing,
    UserRootNotDirectory,
    OverlappingRoots,
    UnauthCapExceedsTotal,
    AuthKeyFileUnreadable,
    AuthKeyFileTooLarge,
    AuthKeyFileMalformed,
    AuthKeyFileEmpty,
    AuthKeyFileNotRegular,
    AuthKeyFileWritableByOthers,
    OutOfMemory,
};

pub const Permission = enum {
    read,
    write,
    list,
    mkdir,
    delete,
    rename,
    // Overwrite (the clobber rule), separate from `delete` so a partner
    // who re-sends `daily.csv` can replace it without gaining deletion.
    update,
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
    /// 0 disables the timeout.
    idle_timeout_ms: u64,
    max_connections: u32,
    /// Separate cap on pre-auth sessions so a handshake storm cannot
    /// fill `max_connections`. 0 = no separate cap; else ≤ max_connections.
    max_unauth_connections: u32,
    /// How long SIGTERM waits for sessions before force-closing them.
    shutdown_grace_ms: u64,
    log: LogTarget,
    /// `virtual` shows the partner's own name, group `sftp`, and
    /// policy-derived rwx; `reality` passes the inode's owner and mode.
    listing_mode: ListingMode,
    /// Mode of a published upload (0o600, 0o640, or 0o660). In-flight
    /// uploads are protected by the 0700 staging dir, not by this mode.
    publish_mode: u32,
    /// Mode of an SFTP MKDIR (0o2700, 0o2750, or 0o2770). Setgid keeps
    /// the partner tree's group on every new subdirectory.
    mkdir_mode: u32,
};

pub const ListingMode = enum {
    virtual,
    reality,
};

/// An authorized key as text from a key file; libssh re-imports it when
/// matching a presented key.
pub const PublicKey = struct {
    /// One of `accepted_key_algorithms`.
    algorithm: []const u8,
    /// Base64 wire blob (second field of an OpenSSH key line).
    blob: []const u8,
};

pub const UserConfig = struct {
    name: []const u8,
    /// Janus-identical `a…` passhash, or null for key-only users.
    password_hash: ?[]const u8,
    /// Empty after `parse`; filled by `validateSemantic` from `key_files`.
    keys: []const PublicKey,
    /// Paths from `auth /path` lines. Kept so reload can notice a key
    /// file change even when the config file itself did not change.
    key_files: []const []const u8,
    /// Source CIDRs from `from` lines; empty allows any source.
    from: []const netmatch.Cidr,
    root: []const u8,
    rules: []const Rule,
};

pub const Config = struct {
    arena: std.heap.ArenaAllocator,
    server: ServerConfig,
    /// Mutable only so `validateSemantic` can fill each user's `keys`.
    users: []UserConfig,

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

/// The checks of `validateSemantic` that need no filesystem.
fn validatePureNumeric(cfg: *const Config) error{UnauthCapExceedsTotal}!void {
    // A pre-auth cap above the total cap can never fire; it is a typo.
    if (cfg.server.max_unauth_connections != 0 and
        cfg.server.max_unauth_connections > cfg.server.max_connections)
    {
        return error.UnauthCapExceedsTotal;
    }
}

/// Check a parsed config against the live filesystem: host key, user
/// roots (exist, are directories, do not overlap), and key files.
/// Used by `zift validate`, `zift serve`, and reload, so each rejection
/// prints the same `zift: ...` line on stderr wherever it happens.
pub fn validateSemantic(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: *Config,
) SemanticError!void {
    // 1. Numeric checks, before touching the filesystem.
    validatePureNumeric(cfg) catch |err| {
        sys.note(io, "zift: max-unauth-connections ({d}) exceeds max-connections ({d})\n", .{
            cfg.server.max_unauth_connections, cfg.server.max_connections,
        }) catch {};
        return err;
    };

    // 2. Host key: a regular file (not a symlink) with no group-write,
    // group-exec, or other bits, so 0600, 0400, and 0640 root:zift pass.
    // Key bytes never reach the diagnostic.
    const host_key = cfg.server.host_key;
    const host_stat = std.Io.Dir.cwd().statFile(io, host_key, .{
        .follow_symlinks = false,
    }) catch |err| {
        const reason: []const u8 = if (err == error.SymLinkLoop) "symlink" else "unreadable";
        writeHostKeyDiag(io, reason, host_key);
        return error.HostKeyUnreadable;
    };
    if (host_stat.kind == .sym_link) {
        writeHostKeyDiag(io, "symlink", host_key);
        return error.HostKeyUnreadable;
    }
    if (host_stat.kind != .file) {
        writeHostKeyDiag(io, "not a regular file", host_key);
        return error.HostKeyUnreadable;
    }
    const host_mode: u32 = @intCast(host_stat.permissions.toMode() & 0o7777);
    if ((host_mode & 0o037) != 0) {
        writeHostKeyDiag(io, "mode", host_key);
        return error.HostKeyUnreadable;
    }
    var host_file = std.Io.Dir.cwd().openFile(io, host_key, .{
        .mode = .read_only,
        .follow_symlinks = false,
    }) catch |err| {
        const reason: []const u8 = if (err == error.SymLinkLoop) "symlink" else "unreadable";
        writeHostKeyDiag(io, reason, host_key);
        return error.HostKeyUnreadable;
    };
    host_file.close(io);

    // 3. Each root must exist and be a directory. Overlap is checked on
    // the canonical (symlink-resolved) paths. Keep the `[:0]` type: freeing
    // without the sentinel is an invalid free.
    var canonical_roots = try allocator.alloc([:0]const u8, cfg.users.len);
    var canonical_count: usize = 0;
    defer {
        for (canonical_roots[0..canonical_count]) |path| allocator.free(path);
        allocator.free(canonical_roots);
    }

    for (cfg.users) |*user| {
        const real = std.Io.Dir.realPathFileAbsoluteAlloc(io, user.root, allocator) catch {
            sys.note(io, "zift: user '{s}' root does not exist or is unreadable: {s}\n", .{ user.name, user.root }) catch {};
            return error.UserRootMissing;
        };
        const dir = std.Io.Dir.openDirAbsolute(io, real, .{}) catch {
            allocator.free(real);
            sys.note(io, "zift: user '{s}' root is not a directory: {s}\n", .{ user.name, user.root }) catch {};
            return error.UserRootNotDirectory;
        };
        dir.close(io);

        canonical_roots[canonical_count] = real;
        canonical_count += 1;
    }

    // 4. No root may equal or contain another.
    for (canonical_roots[0..canonical_count], 0..) |a, i| {
        for (canonical_roots[i + 1 .. canonical_count], i + 1..) |b, j| {
            if (vfs.isInsideRoot(a, b) or vfs.isInsideRoot(b, a)) {
                sys.note(io, "zift: overlapping roots for users '{s}' and '{s}': {s} vs {s}\n", .{
                    cfg.users[i].name, cfg.users[j].name, a, b,
                }) catch {};
                return error.OverlappingRoots;
            }
        }
    }

    // 5. Load every `auth /path` key file.
    try resolveAuthKeyFiles(io, allocator, cfg);
}

/// Parse every user's key files into `keys` (strings in the config
/// arena; file contents in `gpa`, freed here).
///
/// A file that grants login must be a regular file (not a symlink) with
/// no group- or world-write bit. The parent directory is the operator's
/// responsibility, so layouts like a group-rwx keys directory still work.
fn resolveAuthKeyFiles(
    io: std.Io,
    gpa: std.mem.Allocator,
    cfg: *Config,
) SemanticError!void {
    const arena_alloc = cfg.arena.allocator();

    for (cfg.users) |*user| {
        if (user.key_files.len == 0) continue;

        var combined: std.ArrayList(PublicKey) = .empty;

        for (user.key_files) |path| {
            try resolveOneKeyFile(io, gpa, arena_alloc, &combined, user.name, path);
        }

        user.keys = try combined.toOwnedSlice(arena_alloc);
    }
}

/// Check and parse one key file, appending each key line to `combined`.
fn resolveOneKeyFile(
    io: std.Io,
    gpa: std.mem.Allocator,
    arena_alloc: std.mem.Allocator,
    combined: *std.ArrayList(PublicKey),
    user_name: []const u8,
    path: []const u8,
) SemanticError!void {
    // One NOFOLLOW open; stat and read use that fd, so the inode we
    // check is the inode we parse (no swap between two path lookups).
    var file = std.Io.Dir.cwd().openFile(io, path, .{
        .mode = .read_only,
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.SymLinkLoop => {
            writeKeyFileDiag(io, user_name, path, 0, "symlinks not allowed (use in-place rename for rotation)");
            return error.AuthKeyFileNotRegular;
        },
        else => {
            writeKeyFileDiag(io, user_name, path, 0, "unreadable");
            return error.AuthKeyFileUnreadable;
        },
    };
    defer file.close(io);

    const stat = file.stat(io) catch {
        writeKeyFileDiag(io, user_name, path, 0, "stat failed");
        return error.AuthKeyFileUnreadable;
    };
    switch (stat.kind) {
        .file => {},
        else => {
            writeKeyFileDiag(io, user_name, path, 0, "not a regular file");
            return error.AuthKeyFileNotRegular;
        },
    }
    // Public keys need tamper resistance, not secrecy: only write bits matter.
    const file_mode: u32 = @intCast(stat.permissions.toMode() & 0o7777);
    const writable_by_others_mask: u32 = 0o022;
    if ((file_mode & writable_by_others_mask) != 0) {
        writeKeyFileDiag(io, user_name, path, 0, "writable by group/world (mode)");
        return error.AuthKeyFileWritableByOthers;
    }

    // Room for several keys and comments; larger files get "too large".
    const file_read_cap: usize = max_keyline_bytes * 4;

    var file_reader = file.reader(io, &.{});
    const contents = file_reader.interface.allocRemaining(gpa, .limited(file_read_cap)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => {
            writeKeyFileDiag(io, user_name, path, 0, "too large");
            return error.AuthKeyFileTooLarge;
        },
        error.ReadFailed => {
            writeKeyFileDiag(io, user_name, path, 0, "read failed");
            return error.AuthKeyFileUnreadable;
        },
    };
    defer gpa.free(contents);

    var parsed: usize = 0;
    var line_no: u32 = 0;
    var iter = std.mem.splitScalar(u8, contents, '\n');
    while (iter.next()) |raw| {
        line_no += 1;
        const no_cr = std.mem.trimEnd(u8, raw, "\r");
        const trimmed = std.mem.trim(u8, no_cr, " \t");
        if (trimmed.len == 0) continue;
        if (trimmed[0] == '#') continue;
        if (trimmed.len > max_keyline_bytes) {
            writeKeyFileDiag(io, user_name, path, line_no, "key line too long");
            return error.AuthKeyFileMalformed;
        }
        const pubkey = parsePublicKeyLine(arena_alloc, trimmed) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                writeKeyFileDiag(io, user_name, path, line_no, "malformed public-key line");
                return error.AuthKeyFileMalformed;
            },
        };
        try combined.append(arena_alloc, pubkey);
        parsed += 1;
    }

    if (parsed == 0) {
        writeKeyFileDiag(io, user_name, path, 0, "no public-key lines found");
        return error.AuthKeyFileEmpty;
    }
}

fn writeHostKeyDiag(io: std.Io, reason: []const u8, path: []const u8) void {
    sys.note(io, "zift: host-key {s}: {s}\n", .{ reason, path }) catch {};
}

/// `zift: user '<name>': auth key file '<path>'[ line N]: <reason>`;
/// `line_no` 0 means the whole file.
fn writeKeyFileDiag(
    io: std.Io,
    user_name: []const u8,
    path: []const u8,
    line_no: u32,
    reason: []const u8,
) void {
    if (line_no != 0) {
        sys.note(io, "zift: user '{s}': auth key file '{s}' line {d}: {s}\n", .{ user_name, path, line_no, reason }) catch {};
    } else {
        sys.note(io, "zift: user '{s}': auth key file '{s}': {s}\n", .{ user_name, path, reason }) catch {};
    }
}

const ServerBuilder = struct {
    listen: ?[]const u8 = null,
    host_key: ?[]const u8 = null,
    reload_interval_ms: u64 = 2000,
    idle_timeout_ms: u64 = 300_000,
    max_connections: u32 = 128,
    /// 0 = no separate cap, fall back to `max_connections`.
    max_unauth_connections: u32 = 0,
    shutdown_grace_ms: u64 = 30_000,
    log: ?LogTarget = null,
    listing_mode: ListingMode = .virtual,
    publish_mode: u32 = 0o660,
    mkdir_mode: u32 = 0o2770,
    /// Default root for users without `root`: `<partner-root>/<name>`.
    partner_root: ?[]const u8 = null,
    /// Line each directive was set on (0 = not set). Every server
    /// directive is a single value, so a second one is an error.
    lines: std.EnumArray(ServerKey, u32) = .initFill(0),
};

const ServerKey = enum {
    listen,
    @"host-key",
    @"reload-interval",
    @"idle-timeout",
    @"max-connections",
    @"max-unauth-connections",
    @"shutdown-grace",
    log,
    @"listing-mode",
    @"publish-mode",
    @"mkdir-mode",
    @"partner-root",
};

const UserBuilder = struct {
    name: []const u8,
    /// The `user` header line, for errors found after the whole file.
    line: u32,
    password_hash: ?[]const u8 = null,
    key_files: std.ArrayList([]const u8) = .empty,
    from: std.ArrayList(netmatch.Cidr) = .empty,
    root: ?[]const u8 = null,
    root_line: u32 = 0,
    rules: std.ArrayList(Rule) = .empty,
};

const Section = enum {
    none,
    server,
    user,
};

pub const Error = error{
    DuplicateServerSection,
    DuplicateDirective,
    DuplicateKeyFile,
    DuplicatePassword,
    DuplicateUser,
    EmptyUserName,
    InlineComment,
    InvalidAuth,
    InvalidDuration,
    InvalidKeyLine,
    InvalidListen,
    InvalidListingMode,
    InvalidMode,
    InvalidNumber,
    InvalidPermission,
    InvalidUserName,
    KeyDirectiveRemoved,
    KeyLineTooLong,
    UsernameTooLong,
    MissingCredentials,
    MissingHostKey,
    MissingListen,
    MissingRoot,
    InvalidPattern,
    MissingRulePermissions,
    MissingServerSection,
    MissingValue,
    OutOfMemory,
    PasswordDirectiveRemoved,
    PasswordPhcRemoved,
    InvalidPasshash,
    PropertyOutsideSection,
    RelativePath,
    UnknownKey,
    UnknownSection,
    UnsupportedKeyAlgorithm,
    InvalidFrom,
};

/// Fixed limits, enforced at parse time.
pub const max_username_bytes: usize = 64;
pub const max_keyline_bytes: usize = 8192;

/// Where and why a parse failed: line, section, user, key, and a reason.
/// Strings are copied into inline buffers because the parser's arena is
/// freed on error.
pub const ParseDiag = struct {
    line: u32 = 0,
    section_kind: ?Section = null,
    user_name_buf: [max_username_bytes + 1]u8 = [_]u8{0} ** (max_username_bytes + 1),
    user_name_len: usize = 0,
    key_buf: [64]u8 = [_]u8{0} ** 64,
    key_len: usize = 0,
    reason_buf: [256]u8 = undefined,
    reason_len: usize = 0,

    /// What to change, when the error name alone does not say.
    pub fn reason(self: *const ParseDiag) ?[]const u8 {
        if (self.reason_len == 0) return null;
        return self.reason_buf[0..self.reason_len];
    }

    /// Record a reason (truncated to the buffer) and return `err`.
    fn fail(self: *ParseDiag, err: Error, comptime fmt: []const u8, args: anytype) Error {
        var w = std.Io.Writer.fixed(&self.reason_buf);
        w.print(fmt, args) catch {};
        self.reason_len = w.end;
        return err;
    }

    pub fn userName(self: *const ParseDiag) ?[]const u8 {
        if (self.user_name_len == 0) return null;
        return self.user_name_buf[0..self.user_name_len];
    }

    pub fn keyName(self: *const ParseDiag) ?[]const u8 {
        if (self.key_len == 0) return null;
        return self.key_buf[0..self.key_len];
    }

    fn setUserName(self: *ParseDiag, name: []const u8) void {
        const n = @min(name.len, self.user_name_buf.len);
        @memcpy(self.user_name_buf[0..n], name[0..n]);
        self.user_name_len = n;
    }

    fn setKey(self: *ParseDiag, key: []const u8) void {
        const n = @min(key.len, self.key_buf.len);
        @memcpy(self.key_buf[0..n], key[0..n]);
        self.key_len = n;
    }

    /// `line N: [section] 'key': ErrorName[: reason]` (caller prints the file).
    pub fn format(self: *const ParseDiag, err: anyerror, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        if (self.line != 0) {
            try writer.print("line {d}: ", .{self.line});
        }
        if (self.section_kind) |kind| {
            switch (kind) {
                .server => try writer.writeAll("[server] "),
                .user => if (self.userName()) |name| {
                    try writer.print("[user {s}] ", .{name});
                } else {
                    try writer.writeAll("[user] ");
                },
                .none => {},
            }
        }
        if (self.keyName()) |k| try writer.print("'{s}': ", .{k});
        try writer.writeAll(@errorName(err));
        if (self.reason()) |r| try writer.print(": {s}", .{r});
    }
};

/// RSA and DSA are deliberately absent.
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

/// Read a config file (at most 1 MiB).
pub fn readFile(io: std.Io, gpa: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20));
}

/// Why `load` rejected a config. Only a parse failure carries a message:
/// `validateSemantic` prints its own.
pub const LoadDiag = struct {
    parse: ParseDiag = .{},
    parse_err: ?Error = null,

    /// `line N: [section] 'key': Error`; valid when `parse_err` is set.
    pub fn format(self: LoadDiag, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try self.parse.format(self.parse_err.?, w);
    }
};

/// Parse and validate config text: the one path from a file's contents to
/// a config that may serve (validate, startup, and reload). Reading is
/// separate because reload records the file's stamps between the two.
pub fn load(io: std.Io, gpa: std.mem.Allocator, contents: []const u8, diag: *LoadDiag) (Error || SemanticError)!Config {
    var cfg = parseWithDiag(gpa, contents, &diag.parse) catch |err| {
        diag.parse_err = err;
        return err;
    };
    errdefer cfg.deinit();
    try validateSemantic(io, gpa, &cfg);
    return cfg;
}

pub fn parse(gpa: std.mem.Allocator, text: []const u8) Error!Config {
    return parseWithDiag(gpa, text, null);
}

/// `parse`, also recording where any failure happened into `diag`.
pub fn parseWithDiag(
    gpa: std.mem.Allocator,
    text: []const u8,
    diag: ?*ParseDiag,
) Error!Config {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const allocator = arena.allocator();

    var scratch: ParseDiag = .{};
    const d = diag orelse &scratch;

    var server: ServerBuilder = .{};
    var server_line: u32 = 0;
    var users: std.ArrayList(UserBuilder) = .empty;

    var section: Section = .none;
    var current_user: ?*UserBuilder = null;

    // Snapshotted into `d` on any error.
    var line_no: u32 = 0;
    var key_for_diag: ?[]const u8 = null;
    errdefer {
        d.line = line_no;
        d.section_kind = section;
        if (current_user) |u| d.setUserName(u.name);
        if (key_for_diag) |k| d.setKey(k);
    }

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        line_no += 1;
        key_for_diag = null;

        const no_cr = std.mem.trimEnd(u8, raw, "\r");
        // Only whole-line comments; a `#` after a value is an error.
        const trimmed_for_comment_check = std.mem.trimStart(u8, no_cr, " \t");
        if (trimmed_for_comment_check.len > 0 and trimmed_for_comment_check[0] == '#') {
            continue;
        }
        const line = std.mem.trim(u8, no_cr, " \t");
        if (line.len == 0) continue;
        if (std.mem.indexOfScalar(u8, line, '#') != null) return error.InlineComment;

        const indent = countIndent(no_cr);
        if (indent == 0) {
            // A bad header belongs to no section, not the one before it.
            current_user = null;
            section = .none;
            const head, const rest = splitKeyValue(line);
            if (std.mem.eql(u8, line, "server")) {
                if (server_line != 0) return error.DuplicateServerSection;
                server_line = line_no;
                section = .server;
                continue;
            }

            if (std.mem.eql(u8, head, "user")) {
                const name = rest;
                if (name.len == 0) return error.EmptyUserName;
                if (name.len > max_username_bytes) return error.UsernameTooLong;
                if (!validUserName(name)) return error.InvalidUserName;
                for (users.items) |u| {
                    if (std.mem.eql(u8, u.name, name)) return error.DuplicateUser;
                }

                const stored_name = try allocator.dupe(u8, name);
                try users.append(allocator, .{ .name = stored_name, .line = line_no });
                current_user = &users.items[users.items.len - 1];
                section = .user;
                continue;
            }

            return error.UnknownSection;
        }

        const key, const value = splitKeyValue(line);
        key_for_diag = key;
        if (value.len == 0) return error.MissingValue;
        switch (section) {
            .none => return error.PropertyOutsideSection,
            .server => try parseServerProperty(allocator, d, &server, key, value, line_no),
            .user => try parseUserProperty(allocator, d, current_user.?, key, value, line_no),
        }
    }

    // Errors found after the last line point at the header they concern.
    key_for_diag = null;
    section = .server;
    line_no = server_line;
    if (server_line == 0) {
        section = .none;
        return error.MissingServerSection;
    }
    const listen = server.listen orelse return error.MissingListen;
    const host_key = server.host_key orelse return error.MissingHostKey;

    section = .user;
    const final_users = try allocator.alloc(UserConfig, users.items.len);
    for (users.items, 0..) |*builder, i| {
        current_user = builder;
        line_no = builder.line;
        if (builder.password_hash == null and builder.key_files.items.len == 0) {
            return d.fail(error.MissingCredentials, "add an 'auth' line (passhash or key file)", .{});
        }

        // Default the root from `partner-root`. Never build `//name`:
        // POSIX leaves a leading `//` implementation-defined.
        const root_value: []const u8 = if (builder.root) |r|
            r
        else if (server.partner_root) |pr|
            if (std.mem.eql(u8, pr, "/"))
                try std.fmt.allocPrint(allocator, "/{s}", .{builder.name})
            else
                try std.fmt.allocPrint(allocator, "{s}/{s}", .{ pr, builder.name })
        else
            return d.fail(error.MissingRoot, "add 'root /path' or a server 'partner-root'", .{});

        final_users[i] = .{
            .name = builder.name,
            .password_hash = builder.password_hash,
            .keys = &.{},
            .key_files = try builder.key_files.toOwnedSlice(allocator),
            .from = try builder.from.toOwnedSlice(allocator),
            .root = root_value,
            .rules = try builder.rules.toOwnedSlice(allocator),
        };
    }

    return .{
        .arena = arena,
        .server = .{
            .listen = listen,
            .host_key = host_key,
            .reload_interval_ms = server.reload_interval_ms,
            .idle_timeout_ms = server.idle_timeout_ms,
            .max_connections = server.max_connections,
            .max_unauth_connections = server.max_unauth_connections,
            .shutdown_grace_ms = server.shutdown_grace_ms,
            .log = server.log orelse .stderr,
            .listing_mode = server.listing_mode,
            .publish_mode = server.publish_mode,
            .mkdir_mode = server.mkdir_mode,
        },
        .users = final_users,
    };
}

fn parseServerProperty(
    allocator: std.mem.Allocator,
    d: *ParseDiag,
    server: *ServerBuilder,
    key: []const u8,
    value: []const u8,
    line: u32,
) Error!void {
    const which = std.meta.stringToEnum(ServerKey, key) orelse return error.UnknownKey;
    try firstSetting(d, server.lines.getPtr(which), line);
    switch (which) {
        .listen => {
            try validateListen(value);
            server.listen = try allocator.dupe(u8, value);
        },
        .@"host-key" => server.host_key = try allocator.dupe(u8, value),
        .@"reload-interval" => server.reload_interval_ms = try parseDurationMs(d, value),
        .@"idle-timeout" => {
            const ms = try parseDurationMs(d, value);
            // Above libssh's signed 32-bit ms limit it waits forever.
            if (ms > max_libssh_idle_timeout_ms) return d.fail(error.InvalidDuration, "at most 24d (libssh's limit)", .{});
            server.idle_timeout_ms = ms;
        },
        .@"max-connections" => server.max_connections = try parseCount(d, value),
        .@"max-unauth-connections" => server.max_unauth_connections = try parseCount(d, value),
        .@"shutdown-grace" => server.shutdown_grace_ms = try parseDurationMs(d, value),
        .log => server.log = if (std.mem.eql(u8, value, "stderr"))
            .stderr
        else
            .{ .file = try dupeAbsolute(allocator, d, value) },
        .@"listing-mode" => server.listing_mode = std.meta.stringToEnum(ListingMode, value) orelse
            return d.fail(error.InvalidListingMode, "use 'virtual' or 'reality'", .{}),
        .@"publish-mode" => server.publish_mode = try parsePublishMode(d, value),
        .@"mkdir-mode" => server.mkdir_mode = try parseMkdirMode(d, value),
        .@"partner-root" => {
            // Trailing `/` is trimmed, except for `/` itself.
            var pr = try dupeAbsolute(allocator, d, value);
            while (pr.len > 1 and pr[pr.len - 1] == '/') pr = pr[0 .. pr.len - 1];
            server.partner_root = pr;
        },
    }
}

/// A single-valued directive given twice is ambiguous (a stale copy-paste
/// could silently move a partner's jail), so the second one is an error.
fn firstSetting(d: *ParseDiag, seen_line: *u32, line: u32) Error!void {
    if (seen_line.* != 0) return d.fail(error.DuplicateDirective, "already set on line {d}; keep one", .{seen_line.*});
    seen_line.* = line;
}

/// Paths must be absolute: a relative one would depend on the daemon's
/// cwd, and `realPathFileAbsoluteAlloc` in validateSemantic asserts it
/// (a bad reload must not reach that assert).
fn dupeAbsolute(allocator: std.mem.Allocator, d: *ParseDiag, value: []const u8) Error![]const u8 {
    if (value[0] != '/') return d.fail(error.RelativePath, "must be an absolute path", .{});
    return allocator.dupe(u8, value);
}

/// A decimal count.
fn parseCount(d: *ParseDiag, value: []const u8) Error!u32 {
    return std.fmt.parseUnsigned(u32, value, 10) catch
        d.fail(error.InvalidNumber, "expected a whole number", .{});
}

/// Only 0o600, 0o640, or 0o660: partner data never gets world bits.
fn parsePublishMode(d: *ParseDiag, value: []const u8) Error!u32 {
    const mode = parseOctalMode(value) catch 0;
    if (mode != 0o600 and mode != 0o640 and mode != 0o660) {
        return d.fail(error.InvalidMode, "use 0o600, 0o640, or 0o660", .{});
    }
    return mode;
}

/// Only 0o2700, 0o2750, or 0o2770: setgid, never world bits.
fn parseMkdirMode(d: *ParseDiag, value: []const u8) Error!u32 {
    const mode = parseOctalMode(value) catch 0;
    if (mode != 0o2700 and mode != 0o2750 and mode != 0o2770) {
        return d.fail(error.InvalidMode, "use 0o2700, 0o2750, or 0o2770", .{});
    }
    return mode;
}

/// `0o660`, `0660`, and `660` are all octal, as with chmod.
fn parseOctalMode(value: []const u8) !u32 {
    const slice = if (std.mem.startsWith(u8, value, "0o") or std.mem.startsWith(u8, value, "0O"))
        value[2..]
    else
        value;
    return std.fmt.parseUnsigned(u32, slice, 8);
}

fn parseUserProperty(
    allocator: std.mem.Allocator,
    d: *ParseDiag,
    user: *UserBuilder,
    key: []const u8,
    value: []const u8,
    line: u32,
) Error!void {
    if (std.mem.eql(u8, key, "auth")) {
        try parseAuth(allocator, d, user, value);
    } else if (std.mem.eql(u8, key, "root")) {
        try firstSetting(d, &user.root_line, line);
        user.root = try dupeAbsolute(allocator, d, value);
    } else if (std.mem.eql(u8, key, "from")) {
        try parseFrom(allocator, user, value);
    } else if (std.mem.eql(u8, key, "allow")) {
        try parseAllowRule(allocator, d, user, value);
    } else if (std.mem.eql(u8, key, "deny")) {
        try parseDenyRules(allocator, d, user, value);
    } else if (std.mem.eql(u8, key, "password")) {
        // Removed directives get a specific error, not `UnknownKey`.
        return error.PasswordDirectiveRemoved;
    } else if (std.mem.eql(u8, key, "key")) {
        return error.KeyDirectiveRemoved;
    } else {
        return error.UnknownKey;
    }
}

/// `auth a…` is a passhash (at most one); `auth /…` names a key file
/// (any number); a legacy `$…` PHC string must be reminted.
fn parseAuth(allocator: std.mem.Allocator, d: *ParseDiag, user: *UserBuilder, value: []const u8) Error!void {
    // A leading letter is a passhash version tag. `value` is never empty.
    if (value[0] >= 'a' and value[0] <= 'z') {
        if (user.password_hash != null) return error.DuplicatePassword;
        passhash.validate(value) catch return error.InvalidPasshash;
        user.password_hash = try allocator.dupe(u8, value);
        return;
    }
    if (value[0] == '$') {
        if (user.password_hash != null) return error.DuplicatePassword;
        return error.PasswordPhcRemoved;
    }
    if (value[0] == '/') {
        if (value.len > std.Io.Dir.max_path_bytes) return d.fail(error.InvalidAuth, "key file path too long", .{});
        for (user.key_files.items) |path| {
            if (std.mem.eql(u8, path, value)) return d.fail(error.DuplicateKeyFile, "'{s}' is already listed for this user", .{value});
        }
        try user.key_files.append(allocator, try allocator.dupe(u8, value));
        return;
    }
    return error.InvalidAuth;
}

/// Parse `<algorithm> <blob> [comment]`; the result is allocator-owned.
pub fn parsePublicKeyLine(allocator: std.mem.Allocator, line: []const u8) Error!PublicKey {
    if (line.len > max_keyline_bytes) return error.KeyLineTooLong;

    var parts = std.mem.tokenizeAny(u8, line, " \t");
    const algorithm = parts.next() orelse return error.InvalidKeyLine;
    const blob = parts.next() orelse return error.InvalidKeyLine;

    if (!isAcceptedKeyAlgorithm(algorithm)) return error.UnsupportedKeyAlgorithm;
    if (blob.len == 0) return error.InvalidKeyLine;

    if (!isValidStandardBase64(blob)) return error.InvalidKeyLine;

    return .{
        .algorithm = try allocator.dupe(u8, algorithm),
        .blob = try allocator.dupe(u8, blob),
    };
}

/// Strict padded RFC 4648 base64, the form libssh accepts for key blobs.
fn isValidStandardBase64(data: []const u8) bool {
    if (data.len == 0 or data.len % 4 != 0) return false;
    const decoder = std.base64.standard.Decoder;
    const decoded_len = decoder.calcSizeForSlice(data) catch return false;
    var buf: [8192]u8 = undefined;
    if (decoded_len > buf.len) return false;
    decoder.decode(buf[0..decoded_len], data) catch return false;
    return true;
}

/// One IP or CIDR per `from` line; lines accumulate.
fn parseFrom(allocator: std.mem.Allocator, user: *UserBuilder, value: []const u8) Error!void {
    if (std.mem.indexOfAny(u8, value, " \t") != null) return error.InvalidFrom;
    const cidr = netmatch.parseCidr(value) catch return error.InvalidFrom;
    try user.from.append(allocator, cidr);
}

/// Reject a pattern that can never match. Policy matches the normalized
/// virtual path, which starts with `/` and has no empty, `.`, `..`, or
/// trailing components; a dead `deny` would silently fail open.
fn checkPattern(d: *ParseDiag, pattern: []const u8) Error!void {
    if (pattern[0] != '/' and !std.mem.startsWith(u8, pattern, "**")) {
        return d.fail(error.InvalidPattern, "'{s}' never matches: start it with '/' (top level) or '**/' (any depth)", .{pattern});
    }
    if (pattern.len > 1 and pattern[pattern.len - 1] == '/') {
        return d.fail(error.InvalidPattern, "'{s}' never matches: drop the trailing '/' (a directory pattern already covers its contents)", .{pattern});
    }
    var parts = std.mem.splitScalar(u8, pattern, '/');
    _ = parts.first();
    while (parts.next()) |part| {
        if (part.len == 0 and pattern.len > 1) {
            return d.fail(error.InvalidPattern, "'{s}' never matches: it has an empty component ('//')", .{pattern});
        }
        if (std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) {
            return d.fail(error.InvalidPattern, "'{s}' never matches: paths are matched without '.' or '..' components", .{pattern});
        }
    }
}

fn parseAllowRule(allocator: std.mem.Allocator, d: *ParseDiag, user: *UserBuilder, value: []const u8) Error!void {
    var parts = std.mem.tokenizeAny(u8, value, " \t");
    const pattern = parts.next().?; // `value` is never empty
    try checkPattern(d, pattern);

    var permissions = PermissionSet.initEmpty();
    var saw_permission = false;
    while (parts.next()) |token| {
        if (std.mem.eql(u8, token, "read")) {
            // `read` implies `list`: download-without-listing is only
            // obscurity. `list` alone (browse, no download) still exists.
            permissions.insert(.read);
            permissions.insert(.list);
        } else if (std.mem.eql(u8, token, "full")) {
            // Every permission.
            permissions.insert(.read);
            permissions.insert(.list);
            permissions.insert(.write);
            permissions.insert(.update);
            permissions.insert(.delete);
            permissions.insert(.mkdir);
            permissions.insert(.rename);
        } else {
            // Every other verb is exactly one permission of that name.
            permissions.insert(parsePermission(token) orelse return error.InvalidPermission);
        }
        saw_permission = true;
    }
    if (!saw_permission) return error.MissingRulePermissions;

    try user.rules.append(allocator, .{
        .effect = .allow,
        .pattern = try allocator.dupe(u8, pattern),
        .permissions = permissions,
    });
}

fn parseDenyRules(allocator: std.mem.Allocator, d: *ParseDiag, user: *UserBuilder, value: []const u8) Error!void {
    var parts = std.mem.tokenizeAny(u8, value, " \t");
    while (parts.next()) |pattern| {
        try checkPattern(d, pattern);
        try user.rules.append(allocator, .{
            .effect = .deny,
            .pattern = try allocator.dupe(u8, pattern),
            .permissions = PermissionSet.initFull(),
        });
    }
}

fn parsePermission(token: []const u8) ?Permission {
    inline for (@typeInfo(Permission).@"enum".fields) |field| {
        if (std.mem.eql(u8, token, field.name)) return @field(Permission, field.name);
    }
    return null;
}

/// Reject a `listen` that cannot bind, so `zift validate` catches it
/// instead of the next restart (`listen` is not applied on reload). Only
/// the port is checked; host resolution is left to libssh.
fn validateListen(value: []const u8) Error!void {
    const colon = std.mem.lastIndexOfScalar(u8, value, ':') orelse return error.InvalidListen;
    const port = value[colon + 1 ..];
    if (port.len == 0) return error.InvalidListen;
    const parsed = std.fmt.parseUnsigned(u16, port, 10) catch return error.InvalidListen;
    if (parsed == 0) return error.InvalidListen;
}

/// Unit suffixes, longest first so `ms` is not read as `s`.
const duration_units = [_]struct { []const u8, u64 }{
    .{ "ms", 1 },
    .{ "s", std.time.ms_per_s },
    .{ "m", std.time.ms_per_min },
    .{ "h", std.time.ms_per_hour },
    .{ "d", std.time.ms_per_day },
};

/// Bare `0` means disabled. Any other value needs a unit: a bare number
/// is ambiguous (ms or s?), so it is rejected.
fn parseDurationMs(d: *ParseDiag, value: []const u8) Error!u64 {
    if (std.mem.eql(u8, value, "0")) return 0;
    for (duration_units) |unit| {
        const suffix, const factor = unit;
        if (!std.mem.endsWith(u8, value, suffix)) continue;
        const count = std.fmt.parseUnsigned(u64, value[0 .. value.len - suffix.len], 10) catch break;
        const ms = std.math.mul(u64, count, factor) catch max_duration_ms + 1;
        if (ms > max_duration_ms) return d.fail(error.InvalidDuration, "too long", .{});
        return ms;
    }
    return d.fail(error.InvalidDuration, "use a number with a unit (ms, s, m, h, d), or 0", .{});
}

/// libssh stores the blocking-read timeout as a signed 32-bit
/// millisecond count. Anything above this is treated as wait-forever.
const max_libssh_idle_timeout_ms: u64 = 2147483647;

/// Durations are cast to i64 at runtime, so larger values must be
/// rejected here rather than overflow later.
pub const max_duration_ms: u64 = std.math.maxInt(i64);

fn countIndent(line: []const u8) usize {
    var count: usize = 0;
    while (count < line.len and (line[count] == ' ' or line[count] == '\t')) : (count += 1) {}
    return count;
}

/// Split a trimmed line at its first blank into a key and the trimmed
/// rest (empty when there is none).
fn splitKeyValue(line: []const u8) struct { []const u8, []const u8 } {
    const idx = std.mem.indexOfAny(u8, line, " \t") orelse return .{ line, "" };
    return .{ line[0..idx], std.mem.trim(u8, line[idx..], " \t") };
}

fn validUserName(name: []const u8) bool {
    // The name becomes a path component under `partner-root`, so `.`
    // and `..` (and any leading dot) would alias or escape it.
    if (name.len == 0) return false;
    if (name[0] == '.') return false;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
    for (name) |ch| {
        const ok = std.ascii.isAlphanumeric(ch) or ch == '_' or ch == '-' or ch == '.';
        if (!ok) return false;
    }
    return true;
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
        \\  auth a0000000000000000000000000000000
        \\  root /tmp/zift/ally
        \\  allow /pending read write list mkdir delete rename update
        \\  allow /archive read list
        \\  deny /archive/private
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

test "parse: 'write' is create-only — no mkdir, update, delete, or rename" {
    const text =
        \\server
        \\  listen 127.0.0.1:2222
        \\  host-key /tmp/zift_host_ed25519
        \\  log stderr
        \\
        \\user alice
        \\  auth a0000000000000000000000000000000
        \\  root /tmp/zift/alice
        \\  allow /pending read write
        \\
    ;
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();

    const alice = cfg.findUser("alice").?;
    try std.testing.expectEqual(@as(usize, 1), alice.rules.len);
    const rule = alice.rules[0];
    try std.testing.expectEqualStrings("/pending", rule.pattern);
    // `write` is create-only: a drop box without mkdir, overwrite,
    // delete, or rename.
    try std.testing.expect(rule.permissions.contains(.read));
    try std.testing.expect(rule.permissions.contains(.list));
    try std.testing.expect(rule.permissions.contains(.write));
    try std.testing.expect(!rule.permissions.contains(.mkdir));
    try std.testing.expect(!rule.permissions.contains(.update));
    try std.testing.expect(!rule.permissions.contains(.delete));
    try std.testing.expect(!rule.permissions.contains(.rename));
}

test "parse: listen is validated at parse time" {
    const bad = [_][]const u8{
        "NOT-AN-ADDRESS", // no colon at all
        "127.0.0.1:", // empty port
        "127.0.0.1:http", // non-numeric port
        "127.0.0.1:99999", // out of u16 range
        "127.0.0.1:0", // port 0 never binds usefully
    };
    for (bad) |listen| {
        var buf: [256]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf,
            \\server
            \\  listen {s}
            \\  host-key /tmp/zift_host_ed25519
            \\  log stderr
            \\
        , .{listen});
        try std.testing.expectError(error.InvalidListen, parse(std.testing.allocator, text));
    }
}

test "parse: legitimate listen forms accepted" {
    const good = [_][]const u8{
        "0.0.0.0:2222",
        "127.0.0.1:2222",
        ":2222", // host omitted -> 0.0.0.0
        "[::]:2222", // bracketed IPv6
        "localhost:2222", // hostname: resolution is libssh's job
        "0.0.0.0:65535",
    };
    for (good) |listen| {
        var buf: [256]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf,
            \\server
            \\  listen {s}
            \\  host-key /tmp/zift_host_ed25519
            \\  log stderr
            \\
        , .{listen});
        var cfg = try parse(std.testing.allocator, text);
        defer cfg.deinit();
        try std.testing.expectEqualStrings(listen, cfg.server.listen);
    }
}

test "parse: 'update' grants clobber without granting deletion" {
    // A partner who re-sends the same filename may replace it but never delete.
    const text =
        \\server
        \\  listen 127.0.0.1:2222
        \\  host-key /tmp/zift_host_ed25519
        \\  log stderr
        \\
        \\user feeder
        \\  auth a0000000000000000000000000000000
        \\  root /tmp/zift/feeder
        \\  allow /feed read write update
        \\
    ;
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();

    const rule = cfg.findUser("feeder").?.rules[0];
    try std.testing.expect(rule.permissions.contains(.read));
    try std.testing.expect(rule.permissions.contains(.write));
    try std.testing.expect(rule.permissions.contains(.update));
    // The whole point: create + overwrite, but no deletion, no rename
    // (which destroys a name), and no directory creation.
    try std.testing.expect(!rule.permissions.contains(.delete));
    try std.testing.expect(!rule.permissions.contains(.rename));
    try std.testing.expect(!rule.permissions.contains(.mkdir));
}

test "parse: 'delete' grants deletion without granting clobber" {
    const text =
        \\server
        \\  listen 127.0.0.1:2222
        \\  host-key /tmp/zift_host_ed25519
        \\  log stderr
        \\
        \\user picker
        \\  auth a0000000000000000000000000000000
        \\  root /tmp/zift/picker
        \\  allow /outgoing read delete
        \\
    ;
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();

    const rule = cfg.findUser("picker").?.rules[0];
    try std.testing.expect(rule.permissions.contains(.delete));
    try std.testing.expect(!rule.permissions.contains(.update));
    try std.testing.expect(!rule.permissions.contains(.write));
}

test "parse: retired verbs add/create/remove are rejected" {
    // A retired verb is a hard error, never silently reinterpreted.
    for ([_][]const u8{ "add", "create", "remove" }) |verb| {
        var buf: [256]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf,
            \\server
            \\  listen 127.0.0.1:2222
            \\  host-key /tmp/zift_host_ed25519
            \\  log stderr
            \\
            \\user u
            \\  auth a0000000000000000000000000000000
            \\  root /tmp/zift/u
            \\  allow /pending read {s}
            \\
        , .{verb});
        try std.testing.expectError(error.InvalidPermission, parse(std.testing.allocator, text));
    }
}

test "parse: 'full' includes update" {
    const text =
        \\server
        \\  listen 127.0.0.1:2222
        \\  host-key /tmp/zift_host_ed25519
        \\  log stderr
        \\
        \\user w
        \\  auth a0000000000000000000000000000000
        \\  root /tmp/zift/w
        \\  allow /workspace full
        \\
    ;
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();

    const rule = cfg.findUser("w").?.rules[0];
    inline for (.{ .read, .list, .write, .mkdir, .rename, .delete, .update }) |p| {
        try std.testing.expect(rule.permissions.contains(p));
    }
}

test "parse: 'read' is a superset of 'list'" {
    const text =
        \\server
        \\  listen 127.0.0.1:2222
        \\  host-key /tmp/zift_host_ed25519
        \\  log stderr
        \\
        \\user alice
        \\  auth a0000000000000000000000000000000
        \\  root /tmp/zift/alice
        \\  allow /pending read
        \\
    ;
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    const alice = cfg.findUser("alice").?;
    const rule = alice.rules[0];
    try std.testing.expect(rule.permissions.contains(.read));
    try std.testing.expect(rule.permissions.contains(.list));
    // ...and no mutation.
    try std.testing.expect(!rule.permissions.contains(.write));
    try std.testing.expect(!rule.permissions.contains(.mkdir));
    try std.testing.expect(!rule.permissions.contains(.rename));
    try std.testing.expect(!rule.permissions.contains(.delete));
}

test "parse: bare 'list' grants no download" {
    const text =
        \\server
        \\  listen 127.0.0.1:2222
        \\  host-key /tmp/zift_host_ed25519
        \\  log stderr
        \\
        \\user alice
        \\  auth a0000000000000000000000000000000
        \\  root /tmp/zift/alice
        \\  allow /pending list
        \\
    ;
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    const alice = cfg.findUser("alice").?;
    const rule = alice.rules[0];
    try std.testing.expect(rule.permissions.contains(.list));
    try std.testing.expect(!rule.permissions.contains(.read));
}

test "parse: 'full' grants every permission" {
    const text =
        \\server
        \\  listen 127.0.0.1:2222
        \\  host-key /tmp/zift_host_ed25519
        \\  log stderr
        \\
        \\user alice
        \\  auth a0000000000000000000000000000000
        \\  root /tmp/zift/alice
        \\  allow /workspace full
        \\
    ;
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    const alice = cfg.findUser("alice").?;
    const rule = alice.rules[0];
    try std.testing.expect(rule.permissions.contains(.read));
    try std.testing.expect(rule.permissions.contains(.list));
    try std.testing.expect(rule.permissions.contains(.write));
    try std.testing.expect(rule.permissions.contains(.mkdir));
    try std.testing.expect(rule.permissions.contains(.rename));
    try std.testing.expect(rule.permissions.contains(.delete));
}

test "parse: a composite alongside its own granular verbs is idempotent" {
    // `full` + granular verbs already inside `full`'s expansion should
    // just OR cleanly — no error, no surprise, no double-counting.
    const text =
        \\server
        \\  listen 127.0.0.1:2222
        \\  host-key /tmp/zift_host_ed25519
        \\  log stderr
        \\
        \\user alice
        \\  auth a0000000000000000000000000000000
        \\  root /tmp/zift/alice
        \\  allow /pending full write rename mkdir
        \\
    ;
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    const alice = cfg.findUser("alice").?;
    const rule = alice.rules[0];
    try std.testing.expect(rule.permissions.contains(.write));
    try std.testing.expect(rule.permissions.contains(.mkdir));
    try std.testing.expect(rule.permissions.contains(.rename));
}

// Structurally valid passhash (23 zero bytes). Parser checks shape only.
const valid_test_passhash = "a" ++ ("0" ** 31);

test "duplicate user is rejected" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth " ++ valid_test_passhash ++ "\n  root /tmp/a\n\n" ++
        "user ally\n  auth " ++ valid_test_passhash ++ "\n  root /tmp/b\n";
    try std.testing.expectError(error.DuplicateUser, parse(std.testing.allocator, text));
}

test "publish-mode: defaults to 0o660 when not specified" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth " ++ valid_test_passhash ++ "\n  root /tmp/a\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqual(@as(u32, 0o660), cfg.server.publish_mode);
}

test "publish-mode: accepts 0o600, 0o640, 0o660 — rejects everything else" {
    const cases = .{
        .{ "0o600", @as(?u32, 0o600) },
        .{ "0o640", @as(?u32, 0o640) },
        .{ "0o660", @as(?u32, 0o660) },
        .{ "660", @as(?u32, 0o660) }, // bare-octal also accepted
        .{ "0660", @as(?u32, 0o660) }, // leading-zero octal also accepted
        // World-anything is rejected — protects against accidentally
        // shipping world-readable or world-writable partner data.
        .{ "0o666", @as(?u32, null) },
        .{ "0o644", @as(?u32, null) },
        // Execute bits are rejected — partner data files shouldn't
        // ever be executable.
        .{ "0o770", @as(?u32, null) },
        // Special bits (setuid/setgid/sticky) on regular files are
        // suspect; not in the allowed set.
        .{ "0o2660", @as(?u32, null) },
        // Owner-less is nonsensical for a file the daemon writes.
        .{ "0o060", @as(?u32, null) },
        // Decimal nonsense.
        .{ "abc", @as(?u32, null) },
    };
    inline for (cases) |case| {
        const text =
            "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n  publish-mode " ++ case.@"0" ++ "\n\n" ++
            "user ally\n  auth " ++ valid_test_passhash ++ "\n  root /tmp/a\n";
        if (case.@"1") |expected| {
            var cfg = try parse(std.testing.allocator, text);
            defer cfg.deinit();
            try std.testing.expectEqual(expected, cfg.server.publish_mode);
        } else {
            try std.testing.expectError(error.InvalidMode, parse(std.testing.allocator, text));
        }
    }
}

test "mkdir-mode: defaults to 0o2770 when not specified" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth " ++ valid_test_passhash ++ "\n  root /tmp/a\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqual(@as(u32, 0o2770), cfg.server.mkdir_mode);
}

test "mkdir-mode: accepts 0o2700, 0o2750, 0o2770 — rejects everything else" {
    const cases = .{
        .{ "0o2700", @as(?u32, 0o2700) },
        .{ "0o2750", @as(?u32, 0o2750) },
        .{ "0o2770", @as(?u32, 0o2770) },
        .{ "2770", @as(?u32, 0o2770) },
        // No setgid (the leading 2) → rejected. Setgid is what makes
        // child files inherit `group=zift`; without it the
        // operator-group story breaks.
        .{ "0o770", @as(?u32, null) },
        // World-readable/traversable → rejected.
        .{ "0o2775", @as(?u32, null) },
        // Decimal nonsense.
        .{ "xyz", @as(?u32, null) },
    };
    inline for (cases) |case| {
        const text =
            "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n  mkdir-mode " ++ case.@"0" ++ "\n\n" ++
            "user ally\n  auth " ++ valid_test_passhash ++ "\n  root /tmp/a\n";
        if (case.@"1") |expected| {
            var cfg = try parse(std.testing.allocator, text);
            defer cfg.deinit();
            try std.testing.expectEqual(expected, cfg.server.mkdir_mode);
        } else {
            try std.testing.expectError(error.InvalidMode, parse(std.testing.allocator, text));
        }
    }
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

test "auth $... phc rejected with PasswordPhcRemoved" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth $argon2id$v=19$m=65536,t=2,p=1$aa$bb\n  root /tmp/a\n";
    try std.testing.expectError(error.PasswordPhcRemoved, parse(std.testing.allocator, text));
}

test "auth passhash accepted" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth " ++ valid_test_passhash ++ "\n  root /tmp/a\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqualStrings(valid_test_passhash, cfg.users[0].password_hash.?);
}

test "auth passhash rejected when truncated" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth aAAAA\n  root /tmp/a\n";
    try std.testing.expectError(error.InvalidPasshash, parse(std.testing.allocator, text));
}

// Real-shape OpenSSH ed25519 wire blob: 32-byte length-prefixed
// "ssh-ed25519" string + 32-byte length-prefixed key material.
// 68 base64 chars = 51 bytes decoded.
const valid_ed25519_blob = "AAAAC3NzaC1lZDI1NTE5AAAAIPHj7SuD0g1xj0ZqLELSQ7Ux8RSjGlYBhVMxbfBhPXMd";

// 96 base64 chars = 72 bytes decoded; long enough to look like an
// ECDSA P-256 wire blob.
const valid_ecdsa_blob =
    "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPHj7SuD0g1xj0ZqLELSQ7Ux8RSjGlYBhVMxbfBhPXMd";

test "parsePublicKeyLine: valid ed25519 line" {
    const line = "ssh-ed25519 " ++ valid_ed25519_blob ++ " comment";
    const pk = try parsePublicKeyLine(std.testing.allocator, line);
    defer std.testing.allocator.free(pk.algorithm);
    defer std.testing.allocator.free(pk.blob);
    try std.testing.expectEqualStrings("ssh-ed25519", pk.algorithm);
    try std.testing.expectEqualStrings(valid_ed25519_blob, pk.blob);
}

test "parsePublicKeyLine: non-base64 blob rejected" {
    const line = "ssh-ed25519 not!valid!base64 oops";
    try std.testing.expectError(error.InvalidKeyLine, parsePublicKeyLine(std.testing.allocator, line));
}

test "parsePublicKeyLine: bad base64 length rejected" {
    // 29 chars — strict base64 rejects because length is not a multiple of 4.
    const line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBLAH oops";
    try std.testing.expectError(error.InvalidKeyLine, parsePublicKeyLine(std.testing.allocator, line));
}

test "parsePublicKeyLine: rsa key rejected" {
    try std.testing.expectError(
        error.UnsupportedKeyAlgorithm,
        parsePublicKeyLine(std.testing.allocator, "ssh-rsa AAAAB3NzaC1yc2EAAAA notallowed"),
    );
}

test "parsePublicKeyLine: dsa key rejected" {
    try std.testing.expectError(
        error.UnsupportedKeyAlgorithm,
        parsePublicKeyLine(std.testing.allocator, "ssh-dss AAAAB3NzaC1kc3MAAAA legacy"),
    );
}

test "parsePublicKeyLine: missing blob rejected" {
    try std.testing.expectError(
        error.InvalidKeyLine,
        parsePublicKeyLine(std.testing.allocator, "ssh-ed25519"),
    );
}

test "parsePublicKeyLine: ecdsa key accepted" {
    const line = "ecdsa-sha2-nistp256 " ++ valid_ecdsa_blob ++ " backup";
    const pk = try parsePublicKeyLine(std.testing.allocator, line);
    defer std.testing.allocator.free(pk.algorithm);
    defer std.testing.allocator.free(pk.blob);
    try std.testing.expectEqualStrings("ecdsa-sha2-nistp256", pk.algorithm);
}

test "user with no auth lines rejected" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user empty\n  root /tmp/a\n";
    try std.testing.expectError(error.MissingCredentials, parse(std.testing.allocator, text));
}

test "from cidr lines accumulate" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n" ++
        "  auth " ++ valid_test_passhash ++ "\n" ++
        "  from 203.0.113.40\n" ++
        "  from 198.51.100.0/28\n" ++
        "  root /tmp/a\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqual(@as(usize, 2), cfg.users[0].from.len);
    try std.testing.expect(netmatch.allowed(cfg.users[0].from, "203.0.113.40"));
    try std.testing.expect(netmatch.allowed(cfg.users[0].from, "198.51.100.7"));
    try std.testing.expect(!netmatch.allowed(cfg.users[0].from, "198.51.100.16"));
}

test "from rejects malformed cidr" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n" ++
        "  auth " ++ valid_test_passhash ++ "\n" ++
        "  from 10.0.0.0/99\n" ++
        "  root /tmp/a\n";
    try std.testing.expectError(error.InvalidFrom, parse(std.testing.allocator, text));
}

test "two passhash auth lines for one user are rejected" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n" ++
        "  auth " ++ valid_test_passhash ++ "\n" ++
        "  auth " ++ valid_test_passhash ++ "\n" ++
        "  root /tmp/a\n";
    try std.testing.expectError(error.DuplicatePassword, parse(std.testing.allocator, text));
}

test "duplicate-password check fires before PasswordPhcRemoved" {
    // A second `$...` line after a valid passhash credential reports
    // DuplicatePassword, not PasswordPhcRemoved.
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n" ++
        "  auth " ++ valid_test_passhash ++ "\n" ++
        "  auth $bcrypt$something\n" ++
        "  root /tmp/a\n";
    try std.testing.expectError(error.DuplicatePassword, parse(std.testing.allocator, text));
}

test "partner-root '/' derives single-slash user root (POSIX-safe)" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n  partner-root /\n\n" ++
        "user ally\n  auth " ++ valid_test_passhash ++ "\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqualStrings("/ally", cfg.findUser("ally").?.root);
}

test "auth value that is neither valid passhash nor /path rejected" {
    // Letter-leading junk is attempted as a passhash.
    const cases = [_]struct { []const u8, Error }{
        .{ "./relative", error.InvalidAuth },
        .{ "wat", error.InvalidPasshash },
        .{ "", error.MissingValue },
    };
    for (cases) |case| {
        const val, const want = case;
        const text = try std.fmt.allocPrint(
            std.testing.allocator,
            "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
                "user ally\n  auth {s}\n  root /tmp/a\n",
            .{val},
        );
        defer std.testing.allocator.free(text);
        try std.testing.expectError(want, parse(std.testing.allocator, text));
    }
}

test "username '..' rejected (partner-root path-traversal defense)" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n  partner-root /home/zift\n\n" ++
        "user ..\n  auth " ++ valid_test_passhash ++ "\n";
    try std.testing.expectError(error.InvalidUserName, parse(std.testing.allocator, text));
}

test "username '.' rejected (partner-root path-traversal defense)" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n  partner-root /home/zift\n\n" ++
        "user .\n  auth " ++ valid_test_passhash ++ "\n";
    try std.testing.expectError(error.InvalidUserName, parse(std.testing.allocator, text));
}

test "username with leading dot rejected" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user .hidden\n  auth " ++ valid_test_passhash ++ "\n  root /tmp/a\n";
    try std.testing.expectError(error.InvalidUserName, parse(std.testing.allocator, text));
}

test "password directive removed: clear migration error" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  password " ++ valid_test_passhash ++ "\n  root /tmp/a\n";
    try std.testing.expectError(error.PasswordDirectiveRemoved, parse(std.testing.allocator, text));
}

test "key directive removed: clear migration error" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth " ++ valid_test_passhash ++ "\n  key ssh-ed25519 " ++ valid_ed25519_blob ++ "\n  root /tmp/a\n";
    try std.testing.expectError(error.KeyDirectiveRemoved, parse(std.testing.allocator, text));
}

test "partner-root: trailing slash trimmed before deriving user root" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n  partner-root /home/zift/\n\n" ++
        "user ally\n  auth " ++ valid_test_passhash ++ "\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    // Trimmed `partner-root` stored as `/home/zift`; user root joined
    // as `/home/zift/ally` — no double-slash.
    try std.testing.expectEqualStrings("/home/zift/ally", cfg.findUser("ally").?.root);
}

test "auth /path records path; key file resolved later" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user runner\n" ++
        "  auth /tmp/zift_test_does_not_exist_yet.pub\n" ++
        "  auth /tmp/zift_test_also_pending.pub\n" ++
        "  root /tmp/a\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqual(@as(usize, 2), cfg.users[0].key_files.len);
    try std.testing.expectEqualStrings("/tmp/zift_test_does_not_exist_yet.pub", cfg.users[0].key_files[0]);
    try std.testing.expectEqual(@as(usize, 0), cfg.users[0].keys.len);
    try std.testing.expectEqual(@as(?[]const u8, null), cfg.users[0].password_hash);
}

test "partner-root: explicit user root overrides default" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n  partner-root /home/zift\n\n" ++
        "user override\n  auth " ++ valid_test_passhash ++ "\n  root /custom/path\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqualStrings("/custom/path", cfg.findUser("override").?.root);
}

test "partner-root: missing user root defaults to <partner-root>/<user>" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n  partner-root /home/zift\n\n" ++
        "user ally\n  auth " ++ valid_test_passhash ++ "\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqualStrings("/home/zift/ally", cfg.findUser("ally").?.root);
}

test "partner-root: unset, missing user root still rejected" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth " ++ valid_test_passhash ++ "\n";
    try std.testing.expectError(error.MissingRoot, parse(std.testing.allocator, text));
}

test "partner-root: relative path rejected at parse time" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n  partner-root home/zift\n\n" ++
        "user ally\n  auth " ++ valid_test_passhash ++ "\n";
    try std.testing.expectError(error.RelativePath, parse(std.testing.allocator, text));
}

test "root: relative path rejected at parse time" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth " ++ valid_test_passhash ++ "\n  root home/ally\n";
    try std.testing.expectError(error.RelativePath, parse(std.testing.allocator, text));
}

test "server defaults applied when properties omitted" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqual(@as(u64, 300_000), cfg.server.idle_timeout_ms);
    try std.testing.expectEqual(@as(u32, 128), cfg.server.max_connections);
    try std.testing.expectEqual(@as(u32, 0), cfg.server.max_unauth_connections);
}

test "idle-timeout and max-connections parse" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n  idle-timeout 30s\n  max-connections 64\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqual(@as(u64, 30_000), cfg.server.idle_timeout_ms);
    try std.testing.expectEqual(@as(u32, 64), cfg.server.max_connections);
}

test "idle-timeout above libssh signed-32ms cap (25d) is InvalidDuration" {
    // 25d = 2_160_000_000 ms. libssh treats a millisecond count above
    // 2147483647 as wait-forever. `5m` stays 300000; `0` stays disabled.
    const over =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n  idle-timeout 25d\n";
    try std.testing.expectError(error.InvalidDuration, parse(std.testing.allocator, over));

    const five =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n  idle-timeout 5m\n";
    var cfg = try parse(std.testing.allocator, five);
    defer cfg.deinit();
    try std.testing.expectEqual(@as(u64, 300_000), cfg.server.idle_timeout_ms);

    const off =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n  idle-timeout 0\n";
    var disabled = try parse(std.testing.allocator, off);
    defer disabled.deinit();
    try std.testing.expectEqual(@as(u64, 0), disabled.server.idle_timeout_ms);
}

test "max-unauth-connections parses as a non-negative integer" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n" ++
        "  max-connections 64\n  max-unauth-connections 16\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqual(@as(u32, 64), cfg.server.max_connections);
    try std.testing.expectEqual(@as(u32, 16), cfg.server.max_unauth_connections);
}

test "max-unauth-connections explicit 0 parses (operator-documented opt-out)" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n" ++
        "  max-connections 64\n  max-unauth-connections 0\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqual(@as(u32, 0), cfg.server.max_unauth_connections);
}

test "validatePureNumeric: zero unauth cap accepted (no separate cap)" {
    var cfg = makeNumericTestConfig(.{ .max_total = 64, .max_unauth = 0 });
    defer cfg.deinit();
    try validatePureNumeric(&cfg);
}

test "validatePureNumeric: equal caps accepted" {
    var cfg = makeNumericTestConfig(.{ .max_total = 32, .max_unauth = 32 });
    defer cfg.deinit();
    try validatePureNumeric(&cfg);
}

test "validatePureNumeric: unauth cap below total accepted" {
    var cfg = makeNumericTestConfig(.{ .max_total = 64, .max_unauth = 16 });
    defer cfg.deinit();
    try validatePureNumeric(&cfg);
}

test "validatePureNumeric: unauth cap exceeding total rejected" {
    var cfg = makeNumericTestConfig(.{ .max_total = 8, .max_unauth = 16 });
    defer cfg.deinit();
    try std.testing.expectError(error.UnauthCapExceedsTotal, validatePureNumeric(&cfg));
}

test "validatePureNumeric: unauth cap at u32 max boundary rejected" {
    var cfg = makeNumericTestConfig(.{
        .max_total = 64,
        .max_unauth = std.math.maxInt(u32),
    });
    defer cfg.deinit();
    try std.testing.expectError(error.UnauthCapExceedsTotal, validatePureNumeric(&cfg));
}

test "validateSemantic: host-key mode, symlink, and non-regular file rejected" {
    const io = std.testing.io;
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buf);
    const dir_path = dir_buf[0..dir_len];

    try tmp.dir.writeFile(io, .{ .sub_path = "hostkey", .data = "not-logged" });
    const key_path = try std.fmt.allocPrint(alloc, "{s}/hostkey", .{dir_path});
    defer alloc.free(key_path);

    const legal = [_]u32{ 0o600, 0o400, 0o640 };
    for (legal) |mode| {
        try tmp.dir.setFilePermissions(io, "hostkey", .fromMode(@intCast(mode)), .{
            .follow_symlinks = false,
        });
        var cfg = makeNumericTestConfig(.{ .max_total = 128, .max_unauth = 0 });
        defer cfg.deinit();
        cfg.server.host_key = key_path;
        try validateSemantic(io, alloc, &cfg);
    }

    const illegal = [_]u32{ 0o644, 0o660, 0o664, 0o777 };
    for (illegal) |mode| {
        try tmp.dir.setFilePermissions(io, "hostkey", .fromMode(@intCast(mode)), .{
            .follow_symlinks = false,
        });
        var cfg = makeNumericTestConfig(.{ .max_total = 128, .max_unauth = 0 });
        defer cfg.deinit();
        cfg.server.host_key = key_path;
        try std.testing.expectError(error.HostKeyUnreadable, validateSemantic(io, alloc, &cfg));
    }

    try tmp.dir.symLink(io, "hostkey", "hostlink", .{});
    const link_path = try std.fmt.allocPrint(alloc, "{s}/hostlink", .{dir_path});
    defer alloc.free(link_path);
    {
        var cfg = makeNumericTestConfig(.{ .max_total = 128, .max_unauth = 0 });
        defer cfg.deinit();
        cfg.server.host_key = link_path;
        try std.testing.expectError(error.HostKeyUnreadable, validateSemantic(io, alloc, &cfg));
    }

    try tmp.dir.createDir(io, "notfile", .default_dir);
    const dir_key = try std.fmt.allocPrint(alloc, "{s}/notfile", .{dir_path});
    defer alloc.free(dir_key);
    {
        var cfg = makeNumericTestConfig(.{ .max_total = 128, .max_unauth = 0 });
        defer cfg.deinit();
        cfg.server.host_key = dir_key;
        try std.testing.expectError(error.HostKeyUnreadable, validateSemantic(io, alloc, &cfg));
    }
}

/// Parse `text`, which must fail, and compare the rendered diagnostic.
fn expectDiag(text: []const u8, want: []const u8) !void {
    var diag: ParseDiag = .{};
    var cfg = parseWithDiag(std.testing.allocator, text, &diag) catch |err| {
        var buf: [512]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        try diag.format(err, &w);
        return std.testing.expectEqualStrings(want, w.buffered());
    };
    cfg.deinit();
    return error.TestUnexpectedResult;
}

test "ParseDiag: line, section, user, key, and reason" {
    const srv = "server\n  listen 127.0.0.1:2222\n  host-key /k\n";
    // Post-loop errors name the user whose block is wrong, at its header.
    try expectDiag(srv ++ "\nuser ally\n  root /a\n\nuser bob\n  auth /b.pub\n  root /b\n", "line 5: [user ally] MissingCredentials: add an 'auth' line (passhash or key file)");
    try expectDiag(srv ++ "\nuser ally\n  auth /a.pub\n\nuser bob\n  auth /b.pub\n  root /b\n", "line 5: [user ally] MissingRoot: add 'root /path' or a server 'partner-root'");
    try expectDiag("server\n  host-key /k\n\nuser bob\n  auth /b.pub\n  root /b\n", "line 1: [server] MissingListen");
    try expectDiag("\nserver\n  listen :2222\n", "line 2: [server] MissingHostKey");
    try expectDiag("user bob\n  auth /b.pub\n  root /b\n", "MissingServerSection");
    // A bad header belongs to no section; a key with no value is named.
    try expectDiag(srv ++ "users bob\n", "line 4: UnknownSection");
    try expectDiag("  listen :2222\n", "line 1: 'listen': PropertyOutsideSection");
    try expectDiag("server\n  listen\n", "line 2: [server] 'listen': MissingValue");
    try expectDiag("server\n  reload-interval 5\n", "line 2: [server] 'reload-interval': InvalidDuration: use a number with a unit (ms, s, m, h, d), or 0");
    try expectDiag("server\n  publish-mode 0o644\n", "line 2: [server] 'publish-mode': InvalidMode: use 0o600, 0o640, or 0o660");
    try expectDiag(srv ++ "user bob\n  root bob\n", "line 5: [user bob] 'root': RelativePath: must be an absolute path");
    try expectDiag("server\n  listing-mode real\n", "line 2: [server] 'listing-mode': InvalidListingMode: use 'virtual' or 'reality'");
    try expectDiag("server\n  max-connections many\n", "line 2: [server] 'max-connections': InvalidNumber: expected a whole number");
    try expectDiag("server\nserver\n", "line 2: DuplicateServerSection");
}

test "parse: a tab may separate 'user' from the name" {
    var cfg = try parse(std.testing.allocator, "server\n  listen :2222\n  host-key /k\nuser\tbob\n  auth /b.pub\n  root /b\n");
    defer cfg.deinit();
    try std.testing.expectEqualStrings("bob", cfg.users[0].name);
}

test "parse: durations take each unit and reject overflow" {
    const cases = [_]struct { []const u8, ?u64 }{
        .{ "250ms", 250 },
        .{ "2s", 2_000 },
        .{ "3m", 180_000 },
        .{ "4h", 14_400_000 },
        .{ "5d", 432_000_000 },
        .{ "0", 0 },
        .{ "5", null },
        .{ "s", null },
        .{ "5x", null },
        .{ "-5s", null },
        .{ "106751991167301d", null }, // > maxInt(i64) ms
        .{ "99999999999999999999ms", null }, // > maxInt(u64)
    };
    for (cases) |case| {
        const value, const want = case;
        var buf: [128]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf, "server\n  listen :2222\n  host-key /k\n  shutdown-grace {s}\n", .{value});
        if (want) |ms| {
            var cfg = try parse(std.testing.allocator, text);
            defer cfg.deinit();
            try std.testing.expectEqual(ms, cfg.server.shutdown_grace_ms);
        } else {
            try std.testing.expectError(error.InvalidDuration, parse(std.testing.allocator, text));
        }
    }
}

test "a repeated single-valued directive is rejected, naming the first line" {
    try expectDiag("server\n  listen :2222\n  host-key /k\n  listen :2223\n", "line 4: [server] 'listen': DuplicateDirective: already set on line 2; keep one");
    try expectDiag("server\n  listen :2222\n  host-key /k\nuser u\n  auth /u.pub\n  root /a\n  root /b\n", "line 7: [user u] 'root': DuplicateDirective: already set on line 6; keep one");
    // Every server directive is single-valued.
    const samples = [_][]const u8{
        "listen :2222",       "host-key /k",       "reload-interval 1s",
        "idle-timeout 1s",    "max-connections 4", "max-unauth-connections 1",
        "shutdown-grace 1s",  "log stderr",        "listing-mode virtual",
        "publish-mode 0o600", "mkdir-mode 0o2700", "partner-root /p",
    };
    comptime std.debug.assert(samples.len == @typeInfo(ServerKey).@"enum".fields.len);
    for (samples) |sample| {
        var buf: [128]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf, "server\n  {s}\n  {s}\n", .{ sample, sample });
        try std.testing.expectError(error.DuplicateDirective, parse(std.testing.allocator, text));
    }
    // Accumulating directives still accumulate.
    var cfg = try parse(std.testing.allocator, "server\n  listen :2222\n  host-key /k\nuser u\n  auth /a.pub\n  auth /b.pub\n" ++
        "  from 10.0.0.1\n  from 10.0.0.2\n  allow /a read\n  allow /b read\n  deny /a/x\n  deny /b/x\n  root /r\n");
    defer cfg.deinit();
    try std.testing.expectEqual(@as(usize, 2), cfg.users[0].key_files.len);
    try std.testing.expectEqual(@as(usize, 2), cfg.users[0].from.len);
    try std.testing.expectEqual(@as(usize, 4), cfg.users[0].rules.len);
}

test "the same key file twice for one user is rejected" {
    try std.testing.expectError(error.DuplicateKeyFile, parse(std.testing.allocator, "server\n  listen :2222\n  host-key /k\nuser u\n  auth /a.pub\n  auth /a.pub\n  root /r\n"));
}

test "rule patterns that can never match are rejected" {
    // Each of these is a silent no-op in policy.check: as a `deny` it
    // would fail open. `*` never crosses `/`, and every path starts with it.
    const dead = [_][]const u8{
        "*", "*.exe", "secret", "?x", "pending/*", // no leading `/` or `**`
        "/secret/", "/in/*/", "**/", // trailing `/`
        "//x", "/a//b", // empty component
        "/a/./b", "/a/..", "/../etc", "**/..", "/.", // `.` / `..` component
    };
    for (dead) |pattern| {
        var buf: [256]u8 = undefined;
        const deny = try std.fmt.bufPrint(&buf, "server\n  listen :2222\n  host-key /k\nuser u\n  auth /u.pub\n  root /r\n  deny /ok {s}\n", .{pattern});
        try std.testing.expectError(error.InvalidPattern, parse(std.testing.allocator, deny));
        var buf2: [256]u8 = undefined;
        const allow = try std.fmt.bufPrint(&buf2, "server\n  listen :2222\n  host-key /k\nuser u\n  auth /u.pub\n  root /r\n  allow {s} read\n", .{pattern});
        try std.testing.expectError(error.InvalidPattern, parse(std.testing.allocator, allow));
    }

    const live = [_][]const u8{ "/", "/secret", "/*.exe", "**", "**.exe", "***.exe", "**/secret", "/in/**", "/a/**/b", "/a.b/..c" };
    for (live) |pattern| {
        var buf: [256]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf, "server\n  listen :2222\n  host-key /k\nuser u\n  auth /u.pub\n  root /r\n  deny {s}\n", .{pattern});
        var cfg = try parse(std.testing.allocator, text);
        defer cfg.deinit();
        try std.testing.expectEqualStrings(pattern, cfg.users[0].rules[0].pattern);
    }

    try expectDiag("server\n  listen :2222\n  host-key /k\nuser u\n  deny *.exe\n", "line 5: [user u] 'deny': InvalidPattern: '*.exe' never matches: start it with '/' (top level) or '**/' (any depth)");
}

const NumericTestArgs = struct { max_total: u32, max_unauth: u32 };
fn makeNumericTestConfig(args: NumericTestArgs) Config {
    return .{
        .server = .{
            .listen = "127.0.0.1:2222",
            .host_key = "/dev/null",
            .reload_interval_ms = 0,
            .idle_timeout_ms = 0,
            .max_connections = args.max_total,
            .max_unauth_connections = args.max_unauth,
            .shutdown_grace_ms = 0,
            .log = .stderr,
            .listing_mode = .virtual,
            .publish_mode = 0o660,
            .mkdir_mode = 0o2770,
        },
        .users = &.{},
        .arena = std.heap.ArenaAllocator.init(std.testing.allocator),
    };
}
