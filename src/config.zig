//! Config file parser and filesystem validation.
//!
//! `parse` checks syntax and internal consistency only; `validateSemantic`
//! then checks the live filesystem (host key, log, roots, key files)
//! before a config may take effect. Grammar and directives:
//! docs/configure.md.

const std = @import("std");
const c = @import("libssh");
const listing = @import("listing.zig");
const passhash = @import("passhash.zig");
const netmatch = @import("netmatch.zig");
const sys = @import("sys.zig");
const vfs = @import("vfs.zig");

/// Filesystem checks that fail `validateSemantic`. Each also writes a
/// specific stderr line, which integration tests grep for.
pub const SemanticError = error{
    HostKeyUnreadable,
    LogPathUnusable,
    UserRootMissing,
    UserRootNotDirectory,
    OverlappingRoots,
    PrivateFileInsideRoot,
    AuthKeyFileUnreadable,
    AuthKeyFileTooLarge,
    AuthKeyFileMalformed,
    AuthKeyFileEmpty,
    AuthKeyFileNotRegular,
    AuthKeyFileWritableByOthers,
    AuthKeyFileUntrustedOwner,
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

/// The `server` section. Defaults are those of an omitted directive;
/// `listen` and `host-key` are required.
pub const ServerConfig = struct {
    listen: []const u8 = "",
    host_key: []const u8 = "",
    reload_interval_ms: u64 = 2000,
    /// 0 disables the timeout.
    idle_timeout_ms: u64 = 300_000,
    max_connections: u32 = 128,
    /// Separate cap on pre-auth sessions so a handshake storm cannot
    /// fill `max_connections`. 0 = no separate cap; else ≤ max_connections.
    /// Unset, it is max(1, max_connections / 4).
    max_unauth_connections: u32 = 0,
    /// How long SIGTERM waits for sessions before force-closing them.
    shutdown_grace_ms: u64 = 30_000,
    log: LogTarget = .stderr,
    /// `virtual` shows the partner's own name, group `sftp`, and
    /// policy-derived rwx; `reality` passes the inode's owner and mode.
    listing_mode: ListingMode = .virtual,
    /// Mode of a published upload: owner rw, never world-writable, no
    /// special bits. In-flight uploads are protected by the 0700 staging
    /// dir, not by this mode.
    publish_mode: u32 = 0o660,
    /// Mode of an SFTP MKDIR: owner rwx, never world-writable. Setgid
    /// (on by default) keeps the partner tree's group on new subdirectories.
    mkdir_mode: u32 = 0o2770,
};

pub const ListingMode = enum {
    virtual,
    reality,
};

/// An authorized key as text from a key file; libssh re-imports it when
/// matching a presented key.
pub const PublicKey = struct {
    /// One of `key_algorithms`.
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

/// Check a parsed config against the live filesystem: the host key, the
/// log path, user roots (exist, are directories, do not overlap), key
/// files, and that no daemon-private file sits inside a partner root.
/// Used by `zift validate`, `zift serve`, and reload, so each rejection
/// prints the same `zift: ...` line on stderr wherever it happens; it is
/// also kept in `diag`. `config_path`, when known, is kept out of the
/// roots too.
pub fn validateSemantic(
    io: std.Io,
    gpa: std.mem.Allocator,
    cfg: *Config,
    config_path: ?[]const u8,
    diag: *LoadDiag,
) SemanticError!void {
    const ck: Checker = .{ .io = io, .diag = diag };

    // 1. What `serve` opens before it listens: host key and log.
    try checkHostKey(ck, gpa, cfg.server.host_key);
    switch (cfg.server.log) {
        .stderr => {},
        .file => |path| try checkLogPath(ck, path),
    }

    // 2. Each root must exist and be a directory. Overlap is checked on
    // the canonical (symlink-resolved) paths. Keep the `[:0]` type: freeing
    // without the sentinel is an invalid free.
    const roots = try gpa.alloc([:0]const u8, cfg.users.len);
    var root_count: usize = 0;
    defer {
        for (roots[0..root_count]) |path| gpa.free(path);
        gpa.free(roots);
    }
    for (cfg.users) |*user| {
        roots[root_count] = std.Io.Dir.realPathFileAbsoluteAlloc(io, user.root, gpa) catch
            return ck.fail(error.UserRootMissing, "user '{s}' root does not exist or is unreadable: {s}", .{ user.name, user.root });
        root_count += 1;
        const dir = std.Io.Dir.openDirAbsolute(io, roots[root_count - 1], .{}) catch
            return ck.fail(error.UserRootNotDirectory, "user '{s}' root is not a directory: {s}", .{ user.name, user.root });
        dir.close(io);
    }

    // 3. No root may equal or contain another.
    for (roots, 0..) |a, i| {
        for (roots[i + 1 ..], i + 1..) |b, j| {
            if (insideRoot(a, b) or insideRoot(b, a)) {
                return ck.fail(error.OverlappingRoots, "overlapping roots for users '{s}' and '{s}': {s} vs {s}", .{
                    cfg.users[i].name, cfg.users[j].name, a, b,
                });
            }
        }
    }

    // 4. Load every `auth /path` key file.
    try resolveAuthKeyFiles(ck, gpa, cfg);

    // 5. No daemon-private file inside a root. A partner who can write
    // there could replace a key file and log in as another partner, or
    // read the host key or the audit log.
    try checkOutsideRoots(ck, roots, cfg.users, "host-key", cfg.server.host_key);
    switch (cfg.server.log) {
        .stderr => {},
        .file => |path| try checkOutsideRoots(ck, roots, cfg.users, "log", path),
    }
    if (config_path) |path| try checkOutsideRoots(ck, roots, cfg.users, "config file", path);
    for (cfg.users) |user| {
        for (user.key_files) |path| try checkOutsideRoots(ck, roots, cfg.users, "auth key file", path);
    }
}

/// `path` is `root` or below it. `vfs.isInsideRoot` wants a `/` after
/// the root, so it misses everything under a root of `/` itself.
fn insideRoot(root: []const u8, path: []const u8) bool {
    return std.mem.eql(u8, root, "/") or vfs.isInsideRoot(root, path);
}

/// Reports a semantic failure: `zift: <message>` on stderr, and the
/// message in the LoadDiag.
const Checker = struct {
    io: std.Io,
    diag: *LoadDiag,

    fn fail(self: Checker, err: SemanticError, comptime fmt: []const u8, args: anytype) SemanticError {
        var w = std.Io.Writer.fixed(&self.diag.semantic_buf);
        w.print(fmt, args) catch {};
        self.diag.semantic_len = w.end;
        sys.note(self.io, "zift: " ++ fmt ++ "\n", args) catch {};
        return err;
    }
};

const TrustError = error{ Unreadable, NotRegular, BadMode, BadOwner };

/// Open a file the daemon trusts (host key, key file). Symlinks are
/// followed (Kubernetes Secrets and systemd credentials are symlinks);
/// the file itself must be regular, owned by root or the daemon's user
/// (another local user could rewrite it), with no `forbidden_mode` bits.
/// The checks run on the open fd, so the inode checked is the inode read.
fn openTrusted(io: std.Io, path: []const u8, forbidden_mode: u32) TrustError!std.Io.File {
    // Opening a FIFO would block, so refuse anything else first.
    const pre = std.Io.Dir.cwd().statFile(io, path, .{}) catch return error.Unreadable;
    if (pre.kind != .file) return error.NotRegular;
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return error.Unreadable;
    errdefer file.close(io);
    const st = listing.statFd(file.handle) catch return error.Unreadable;
    if (st.mode & listing.S_IFMT != listing.S_IFREG) return error.NotRegular;
    if (st.mode & forbidden_mode != 0) return error.BadMode;
    if (st.uid != 0 and st.uid != std.c.geteuid()) return error.BadOwner;
    return file;
}

/// Room for any private key file (an 8192-bit RSA PEM is about 6 KiB).
const max_host_key_bytes = 64 * 1024;

/// The host key must be a private key libssh loads without a passphrase,
/// in a trusted file with no group-write, group-exec, or other bits, so
/// 0600, 0400, and 0640 root:zift pass. Key bytes never reach a diagnostic.
fn checkHostKey(ck: Checker, gpa: std.mem.Allocator, path: []const u8) SemanticError!void {
    var file = openTrusted(ck.io, path, 0o037) catch |err| return switch (err) {
        error.Unreadable => ck.fail(error.HostKeyUnreadable, "host-key unreadable: {s}", .{path}),
        error.NotRegular => ck.fail(error.HostKeyUnreadable, "host-key not a regular file: {s}", .{path}),
        error.BadMode => ck.fail(error.HostKeyUnreadable, "host-key mode allows group-write, group-exec, or other access: {s}", .{path}),
        error.BadOwner => ck.fail(error.HostKeyUnreadable, "host-key owned by neither root nor the daemon's user: {s}", .{path}),
    };
    defer file.close(ck.io);

    var reader = file.reader(ck.io, &.{});
    const text = reader.interface.allocRemaining(gpa, .limited(max_host_key_bytes)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return ck.fail(error.HostKeyUnreadable, "host-key unreadable or too large: {s}", .{path}),
    };
    defer {
        std.crypto.secureZero(u8, text);
        gpa.free(text);
    }
    const text_z = try gpa.dupeZ(u8, text);
    defer {
        std.crypto.secureZero(u8, text_z);
        gpa.free(text_z);
    }
    var key: c.ssh_key = null;
    if (c.ssh_pki_import_privkey_base64(text_z.ptr, null, null, null, &key) != c.SSH_OK) {
        return ck.fail(error.HostKeyUnreadable, "host-key is not a private key libssh can load without a passphrase: {s}", .{path});
    }
    c.ssh_key_free(key);
}

/// `serve` opens the log (append, O_NOFOLLOW) before it listens, so its
/// directory must exist and an existing log must be a regular file.
fn checkLogPath(ck: Checker, path: []const u8) SemanticError!void {
    const dir = std.fs.path.dirname(path) orelse "/";
    const dir_stat = std.Io.Dir.cwd().statFile(ck.io, dir, .{}) catch
        return ck.fail(error.LogPathUnusable, "log directory does not exist: {s}", .{path});
    if (dir_stat.kind != .directory) return ck.fail(error.LogPathUnusable, "log directory is not a directory: {s}", .{path});
    const st = std.Io.Dir.cwd().statFile(ck.io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return ck.fail(error.LogPathUnusable, "log unreadable: {s}", .{path}),
    };
    // Same inode kinds the audit sink opens: a file, a FIFO for a log
    // shipper, or a character device such as /dev/null. Never a symlink.
    switch (st.kind) {
        .file, .named_pipe, .character_device => {},
        else => return ck.fail(error.LogPathUnusable, "log must be a regular file, FIFO or character device (symlinks are refused): {s}", .{path}),
    }
}

/// Fail if `path`, as named (its directory resolved) or as it resolves,
/// is inside any user root: a symlink or a not-yet-created log inside a
/// root is caught too. `roots` are canonical and parallel to `users`.
fn checkOutsideRoots(
    ck: Checker,
    roots: []const [:0]const u8,
    users: []const UserConfig,
    what: []const u8,
    path: []const u8,
) SemanticError!void {
    var named_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var real_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const cwd = std.Io.Dir.cwd();
    const named: ?[]const u8 = named: {
        const n = cwd.realPathFile(ck.io, std.fs.path.dirname(path) orelse ".", &named_buf) catch break :named null;
        const sep: usize = if (n == 1) 0 else 1; // the directory is `/`
        const base = std.fs.path.basename(path);
        if (n + sep + base.len > named_buf.len) break :named null;
        named_buf[n] = '/';
        @memcpy(named_buf[n + sep ..][0..base.len], base);
        break :named named_buf[0 .. n + sep + base.len];
    };
    const real: ?[]const u8 = if (cwd.realPathFile(ck.io, path, &real_buf)) |n| real_buf[0..n] else |_| null;
    for (roots, users) |root, user| {
        for ([_]?[]const u8{ named, real }) |candidate| {
            const p = candidate orelse continue;
            if (insideRoot(root, p)) {
                return ck.fail(error.PrivateFileInsideRoot, "{s} {s} is inside user '{s}' root {s}; move it out of every partner root", .{
                    what, path, user.name, root,
                });
            }
        }
    }
}

/// Parse every user's key files into `keys` (strings in the config
/// arena; file contents in `gpa`, freed here).
fn resolveAuthKeyFiles(ck: Checker, gpa: std.mem.Allocator, cfg: *Config) SemanticError!void {
    const arena_alloc = cfg.arena.allocator();
    for (cfg.users) |*user| {
        var combined: std.ArrayList(PublicKey) = .empty;
        for (user.key_files) |path| {
            try resolveOneKeyFile(ck, gpa, arena_alloc, &combined, user.name, path);
        }
        user.keys = try combined.toOwnedSlice(arena_alloc);
    }
}

/// Check and parse one key file, appending each key line to `combined`.
/// A file that grants login must be trusted (see `openTrusted`) and have
/// no group- or world-write bit: public keys need tamper resistance, not
/// secrecy. The parent directory is the operator's responsibility, so
/// layouts like a group-rwx keys directory still work.
fn resolveOneKeyFile(
    ck: Checker,
    gpa: std.mem.Allocator,
    arena_alloc: std.mem.Allocator,
    combined: *std.ArrayList(PublicKey),
    user_name: []const u8,
    path: []const u8,
) SemanticError!void {
    var file = openTrusted(ck.io, path, 0o022) catch |err| return switch (err) {
        error.Unreadable => keyFileFail(ck, error.AuthKeyFileUnreadable, user_name, path, 0, "unreadable"),
        error.NotRegular => keyFileFail(ck, error.AuthKeyFileNotRegular, user_name, path, 0, "not a regular file"),
        error.BadMode => keyFileFail(ck, error.AuthKeyFileWritableByOthers, user_name, path, 0, "writable by group/world (mode)"),
        error.BadOwner => keyFileFail(ck, error.AuthKeyFileUntrustedOwner, user_name, path, 0, "owned by neither root nor the daemon's user"),
    };
    defer file.close(ck.io);

    // Room for several keys and comments; larger files get "too large".
    const file_read_cap: usize = max_keyline_bytes * 4;

    var file_reader = file.reader(ck.io, &.{});
    const contents = file_reader.interface.allocRemaining(gpa, .limited(file_read_cap)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => return keyFileFail(ck, error.AuthKeyFileTooLarge, user_name, path, 0, "too large"),
        error.ReadFailed => return keyFileFail(ck, error.AuthKeyFileUnreadable, user_name, path, 0, "read failed"),
    };
    defer gpa.free(contents);

    var parsed: usize = 0;
    var line_no: u32 = 0;
    var iter = std.mem.splitScalar(u8, contents, '\n');
    while (iter.next()) |raw| {
        line_no += 1;
        const trimmed = std.mem.trim(u8, raw, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        const pubkey = parsePublicKeyLine(arena_alloc, trimmed) catch |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            return keyFileFail(ck, error.AuthKeyFileMalformed, user_name, path, line_no, switch (err) {
                error.KeyLineTooLong => "key line too long",
                error.UnsupportedKeyAlgorithm => "malformed public-key line: unsupported algorithm " ++
                    "(use ssh-ed25519, ecdsa-sha2-nistp256/384/521, or ssh-rsa; no option prefixes)",
                error.KeyAlgorithmMismatch => "malformed public-key line: the key does not match its algorithm name",
                error.InvalidRsaKeySize => "malformed public-key line: RSA keys must be 2048 to 8192 bits",
                else => "malformed public-key line",
            });
        };
        try combined.append(arena_alloc, pubkey);
        parsed += 1;
    }

    if (parsed == 0) return keyFileFail(ck, error.AuthKeyFileEmpty, user_name, path, 0, "no public-key lines found");
}

/// `user '<name>': auth key file '<path>'[ line N]: <reason>`; `line_no`
/// 0 means the whole file.
fn keyFileFail(
    ck: Checker,
    err: SemanticError,
    user_name: []const u8,
    path: []const u8,
    line_no: u32,
    reason: []const u8,
) SemanticError {
    if (line_no != 0) {
        return ck.fail(err, "user '{s}': auth key file '{s}' line {d}: {s}", .{ user_name, path, line_no, reason });
    }
    return ck.fail(err, "user '{s}': auth key file '{s}': {s}", .{ user_name, path, reason });
}

const ServerBuilder = struct {
    cfg: ServerConfig = .{},
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

/// Parse failures; `ParseDiag` says where, and usually what to write.
pub const Error = error{
    DuplicateDirective,
    DuplicateKeyFile,
    DuplicatePassword,
    DuplicateServerSection,
    DuplicateUser,
    EmptyUserName,
    InvalidAuth,
    InvalidDuration,
    InvalidFrom,
    InvalidKeyLine,
    InvalidListen,
    InvalidListingMode,
    InvalidMode,
    InvalidNumber,
    InvalidPasshash,
    InvalidPattern,
    InvalidPermission,
    InvalidRsaKeySize,
    InvalidUserName,
    KeyAlgorithmMismatch,
    KeyDirectiveRemoved,
    KeyLineTooLong,
    MissingCredentials,
    MissingHostKey,
    MissingListen,
    MissingRoot,
    MissingRulePermissions,
    MissingServerSection,
    MissingValue,
    OutOfMemory,
    PasswordDirectiveRemoved,
    PasswordPhcRemoved,
    PropertyOutsideSection,
    RelativePath,
    UnauthCapExceedsTotal,
    UnknownKey,
    UnknownSection,
    UnsupportedKeyAlgorithm,
    UsernameTooLong,
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

/// Accepted key algorithms and the length of the key each blob carries
/// (an ECDSA point is uncompressed: 1 + 2 × field bytes). RSA (0) is
/// checked by modulus size instead; the server accepts only rsa-sha2
/// signatures for it. DSA is deliberately absent.
const key_algorithms = [_]struct { []const u8, usize }{
    .{ "ssh-ed25519", 32 },
    .{ "ecdsa-sha2-nistp256", 65 },
    .{ "ecdsa-sha2-nistp384", 97 },
    .{ "ecdsa-sha2-nistp521", 133 },
    .{ "ssh-rsa", 0 },
};

fn keyMaterialLen(algorithm: []const u8) ?usize {
    for (key_algorithms) |entry| {
        if (std.mem.eql(u8, algorithm, entry[0])) return entry[1];
    }
    return null;
}

/// Largest config file read.
pub const max_file_bytes = 1 << 20;

/// Read a config file (at most `max_file_bytes`).
pub fn readFile(io: std.Io, gpa: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_file_bytes));
}

/// Why `load` rejected a config. A parse failure is only recorded here;
/// a semantic failure is also printed on stderr when it happens.
pub const LoadDiag = struct {
    parse: ParseDiag = .{},
    parse_err: ?Error = null,
    semantic_buf: [512]u8 = undefined,
    semantic_len: usize = 0,

    /// The parse diagnostic (`line N: [section] 'key': Error[: reason]`)
    /// or else the semantic one (as printed, without `zift: `).
    pub fn format(self: LoadDiag, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (self.parse_err) |err| return self.parse.format(err, w);
        try w.writeAll(self.semantic_buf[0..self.semantic_len]);
    }
};

/// Parse and validate config text: the one path from a file's contents to
/// a config that may serve (validate, startup, and reload). Reading is
/// separate because reload records the file's stamps between the two.
/// Prefer `loadPath`, which also keeps the config file out of every root.
pub fn load(io: std.Io, gpa: std.mem.Allocator, contents: []const u8, diag: *LoadDiag) (Error || SemanticError)!Config {
    return loadPath(io, gpa, null, contents, diag);
}

/// `load` for the config read from `path`.
pub fn loadPath(
    io: std.Io,
    gpa: std.mem.Allocator,
    path: ?[]const u8,
    contents: []const u8,
    diag: *LoadDiag,
) (Error || SemanticError)!Config {
    var cfg = parseWithDiag(gpa, contents, &diag.parse) catch |err| {
        diag.parse_err = err;
        return err;
    };
    errdefer cfg.deinit();
    try validateSemantic(io, gpa, &cfg, path, diag);
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

        const no_cr = stripComment(std.mem.trimEnd(u8, raw, "\r"));
        const line = std.mem.trim(u8, no_cr, " \t");
        if (line.len == 0) continue;

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
    if (server.lines.get(.listen) == 0) return error.MissingListen;
    if (server.lines.get(.@"host-key") == 0) return error.MissingHostKey;

    // Unset, handshakes may hold at most a quarter of the slots, so a
    // pile of silent pre-auth sockets cannot starve every partner. An
    // explicit value, 0 (no separate cap) included, is kept as written.
    const unauth_line = server.lines.get(.@"max-unauth-connections");
    const max_unauth = if (unauth_line != 0) server.cfg.max_unauth_connections else @max(1, server.cfg.max_connections / 4);
    if (max_unauth > server.cfg.max_connections) {
        // Such a cap could never fire, so it is a typo.
        line_no = unauth_line;
        key_for_diag = "max-unauth-connections";
        return d.fail(error.UnauthCapExceedsTotal, "max-unauth-connections ({d}) exceeds max-connections ({d})", .{
            max_unauth, server.cfg.max_connections,
        });
    }

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

    server.cfg.max_unauth_connections = max_unauth;
    return .{ .arena = arena, .server = server.cfg, .users = final_users };
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
            _ = parseListen(value) catch
                return d.fail(error.InvalidListen, "use host:port, :port, or [ipv6]:port with a port from 1 to 65535", .{});
            server.cfg.listen = try allocator.dupe(u8, value);
        },
        .@"host-key" => server.cfg.host_key = try allocator.dupe(u8, value),
        // Floors: a shorter poll re-stats every key file on each accept-loop
        // wake-up, and a shorter idle timeout fails every handshake.
        .@"reload-interval" => server.cfg.reload_interval_ms = try parseDurationAtLeast(d, value, 100, "100ms"),
        .@"idle-timeout" => {
            const ms = try parseDurationAtLeast(d, value, std.time.ms_per_s, "1s");
            // Above libssh's signed 32-bit ms limit it waits forever.
            if (ms > max_libssh_idle_timeout_ms) return d.fail(error.InvalidDuration, "at most 24d (libssh's limit)", .{});
            server.cfg.idle_timeout_ms = ms;
        },
        .@"max-connections" => {
            // 0 would refuse every connection; elsewhere 0 means "off".
            server.cfg.max_connections = try parseCount(d, value);
            if (server.cfg.max_connections == 0) return d.fail(error.InvalidNumber, "must be at least 1", .{});
        },
        .@"max-unauth-connections" => server.cfg.max_unauth_connections = try parseCount(d, value),
        .@"shutdown-grace" => server.cfg.shutdown_grace_ms = try parseDurationMs(d, value),
        .log => server.cfg.log = if (std.mem.eql(u8, value, "stderr"))
            .stderr
        else
            .{ .file = try dupeAbsolute(allocator, d, value) },
        .@"listing-mode" => server.cfg.listing_mode = std.meta.stringToEnum(ListingMode, value) orelse
            return d.fail(error.InvalidListingMode, "use 'virtual' or 'reality'", .{}),
        .@"publish-mode" => server.cfg.publish_mode = try parsePublishMode(d, value),
        .@"mkdir-mode" => server.cfg.mkdir_mode = try parseMkdirMode(d, value),
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
    return parseDigits(u32, value, 10) orelse
        d.fail(error.InvalidNumber, "expected a whole number", .{});
}

/// Plain digits only: std's parser also takes `_` separators, which the
/// docs never promised and which read like a typo.
fn parseDigits(comptime T: type, text: []const u8, base: u8) ?T {
    if (text.len == 0) return null;
    for (text) |ch| {
        if (ch < '0' or ch - '0' >= base) return null;
    }
    return std.fmt.parseUnsigned(T, text, base) catch null;
}

/// The daemon must be able to write what it publishes, and partner data
/// is never world-writable. No setuid, setgid, or sticky bit on files.
fn parsePublishMode(d: *ParseDiag, value: []const u8) Error!u32 {
    return parseMode(d, value, 0o600, 0o775, "needs owner rw (0o600), no world-write, and no setuid/setgid/sticky bit");
}

/// Owner rwx so the daemon can use the directory, never world-writable.
/// Setgid is allowed (and the default) so new subdirectories keep the
/// partner tree's group.
fn parseMkdirMode(d: *ParseDiag, value: []const u8) Error!u32 {
    return parseMode(d, value, 0o700, 0o2775, "needs owner rwx (0o700) and no world-write; setgid is the only special bit allowed");
}

/// An octal mode (`0o660`, `0660`, or `660`, as with chmod) that has
/// every `required` bit and nothing outside `allowed`.
fn parseMode(d: *ParseDiag, value: []const u8, required: u32, allowed: u32, comptime hint: []const u8) Error!u32 {
    const digits = if (std.mem.startsWith(u8, value, "0o") or std.mem.startsWith(u8, value, "0O")) value[2..] else value;
    const mode = parseDigits(u32, digits, 8) orelse return d.fail(error.InvalidMode, "not an octal mode", .{});
    if (mode & required != required or mode & ~allowed != 0) return d.fail(error.InvalidMode, hint, .{});
    return mode;
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
/// The blob must decode to a well-formed key of the named algorithm: a
/// mislabelled or truncated key would otherwise pass validation and then
/// silently never match at login.
pub fn parsePublicKeyLine(allocator: std.mem.Allocator, line: []const u8) Error!PublicKey {
    if (line.len > max_keyline_bytes) return error.KeyLineTooLong;

    var parts = std.mem.tokenizeAny(u8, line, " \t");
    const algorithm = parts.next() orelse return error.InvalidKeyLine;
    const blob = parts.next() orelse return error.InvalidKeyLine;
    const key_len = keyMaterialLen(algorithm) orelse return error.UnsupportedKeyAlgorithm;

    // Strict padded RFC 4648 base64, the form libssh accepts.
    const decoder = std.base64.standard.Decoder;
    var raw_buf: [max_keyline_bytes / 4 * 3]u8 = undefined;
    const raw_len = decoder.calcSizeForSlice(blob) catch return error.InvalidKeyLine;
    if (blob.len % 4 != 0 or raw_len > raw_buf.len) return error.InvalidKeyLine;
    decoder.decode(raw_buf[0..raw_len], blob) catch return error.InvalidKeyLine;
    try checkKeyBlob(algorithm, key_len, raw_buf[0..raw_len]);

    return .{
        .algorithm = try allocator.dupe(u8, algorithm),
        .blob = try allocator.dupe(u8, blob),
    };
}

/// RSA below 2048 bits is breakable; mbedTLS cannot load above 8192.
const min_rsa_bits = 2048;
const max_rsa_bits = 8192;

/// Check the SSH wire form (RFC 4253 §6.6, RFC 5656 §3.1): the embedded
/// algorithm name, the ECDSA curve, the key length or RSA modulus size,
/// and nothing trailing.
fn checkKeyBlob(algorithm: []const u8, key_len: usize, raw: []const u8) Error!void {
    var rest = raw;
    const name = sshString(&rest) orelse return error.InvalidKeyLine;
    if (!std.mem.eql(u8, name, algorithm)) return error.KeyAlgorithmMismatch;
    if (key_len == 0) {
        _ = sshString(&rest) orelse return error.InvalidKeyLine; // e
        const n = std.mem.trimStart(u8, sshString(&rest) orelse return error.InvalidKeyLine, "\x00");
        const bits = if (n.len == 0) 0 else n.len * 8 - @clz(n[0]);
        if (bits < min_rsa_bits or bits > max_rsa_bits) return error.InvalidRsaKeySize;
    } else {
        if (std.mem.startsWith(u8, algorithm, "ecdsa-sha2-")) {
            const curve = sshString(&rest) orelse return error.InvalidKeyLine;
            if (!std.mem.eql(u8, curve, algorithm["ecdsa-sha2-".len..])) return error.KeyAlgorithmMismatch;
        }
        const key = sshString(&rest) orelse return error.InvalidKeyLine;
        if (key.len != key_len) return error.InvalidKeyLine;
    }
    if (rest.len != 0) return error.InvalidKeyLine;
}

/// Take one u32-length-prefixed string off the front of `rest`.
fn sshString(rest: *[]const u8) ?[]const u8 {
    if (rest.len < 4) return null;
    const len = std.mem.readInt(u32, rest.*[0..4], .big);
    if (len > rest.len - 4) return null;
    const s = rest.*[4..][0..len];
    rest.* = rest.*[4 + len ..];
    return s;
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

pub const ListenAddress = struct {
    /// Brackets removed from an IPv6 literal; `0.0.0.0` when omitted.
    host: []const u8,
    port: u16,
};

/// Split a `listen` value into what to bind: `host:port`, `:port` (every
/// IPv4 address), or `[ipv6]:port`. The parser uses it so `zift validate`
/// rejects what `serve` could not bind (`listen` is not applied on
/// reload). A hostname is left to libssh to resolve.
pub fn parseListen(value: []const u8) error{InvalidListen}!ListenAddress {
    const colon = std.mem.lastIndexOfScalar(u8, value, ':') orelse return error.InvalidListen;
    const port = parseDigits(u16, value[colon + 1 ..], 10) orelse return error.InvalidListen;
    if (port == 0) return error.InvalidListen;
    var host = value[0..colon];
    if (std.mem.startsWith(u8, host, "[")) {
        if (!std.mem.endsWith(u8, host, "]")) return error.InvalidListen;
        host = host[1 .. host.len - 1];
        _ = std.Io.net.Ip6Address.parse(host, 0) catch return error.InvalidListen;
    } else if (std.mem.indexOfScalar(u8, host, ':') != null) {
        // `::1:2222` is ambiguous; IPv6 hosts must be bracketed.
        return error.InvalidListen;
    }
    // Longer than any DNS name.
    if (host.len > 255) return error.InvalidListen;
    return .{ .host = if (host.len == 0) "0.0.0.0" else host, .port = port };
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
        const count = parseDigits(u64, value[0 .. value.len - suffix.len], 10) orelse break;
        const ms = std.math.mul(u64, count, factor) catch max_duration_ms + 1;
        if (ms > max_duration_ms) return d.fail(error.InvalidDuration, "too long", .{});
        return ms;
    }
    return d.fail(error.InvalidDuration, "use a number with a unit (ms, s, m, h, d), or 0", .{});
}

/// A duration that is 0 (off) or at least `floor_ms`.
fn parseDurationAtLeast(d: *ParseDiag, value: []const u8, floor_ms: u64, comptime floor_text: []const u8) Error!u64 {
    const ms = try parseDurationMs(d, value);
    if (ms != 0 and ms < floor_ms) return d.fail(error.InvalidDuration, "must be 0 (off) or at least " ++ floor_text, .{});
    return ms;
}

/// libssh stores the blocking-read timeout as a signed 32-bit
/// millisecond count. Anything above this is treated as wait-forever.
const max_libssh_idle_timeout_ms: u64 = 2147483647;

/// Durations are cast to i64 at runtime, so larger values must be
/// rejected here rather than overflow later.
pub const max_duration_ms: u64 = std.math.maxInt(i64);

/// Cut a comment: a `#` at the start of the line or after a blank. A `#`
/// inside a token is literal, so paths and patterns may contain one.
fn stripComment(line: []const u8) []const u8 {
    for (line, 0..) |ch, i| {
        if (ch == '#' and (i == 0 or line[i - 1] == ' ' or line[i - 1] == '\t')) return line[0..i];
    }
    return line;
}

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

test "parse: listen is validated at parse time" {
    const bad = [_][]const u8{
        "NOT-AN-ADDRESS", // no colon at all
        "127.0.0.1:", // empty port
        "127.0.0.1:http", // non-numeric port
        "127.0.0.1:99999", // out of u16 range
        "127.0.0.1:0", // port 0 never binds usefully
        "127.0.0.1:+22", // digits only
        "::1:2222", // unbracketed IPv6 is ambiguous
        "[::1:2222", // unclosed bracket
        "[::1]2222", // no ':' after the bracket
        "[localhost]:2222", // brackets hold an IPv6 literal
        "[]:2222",
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

test "parseListen: host and port to bind" {
    const cases = [_]struct { []const u8, []const u8, u16 }{
        .{ "127.0.0.1:2222", "127.0.0.1", 2222 },
        .{ ":22", "0.0.0.0", 22 },
        .{ "[::1]:2222", "::1", 2222 },
        .{ "[::]:65535", "::", 65535 },
        .{ "[2001:db8::7]:2022", "2001:db8::7", 2022 },
        .{ "sftp.example.com:2222", "sftp.example.com", 2222 },
    };
    for (cases) |case| {
        const value, const host, const port = case;
        const got = try parseListen(value);
        try std.testing.expectEqualStrings(host, got.host);
        try std.testing.expectEqual(port, got.port);
    }
    // A host longer than any DNS name (validate used to panic on this).
    try std.testing.expectError(error.InvalidListen, parseListen("a" ** 256 ++ ":22"));
}

// Structurally valid passhash (23 zero bytes). Parser checks shape only.
const valid_test_passhash = "a" ++ ("0" ** 31);

test "verbs: each allow line grants exactly its permissions" {
    const all = &[_]Permission{ .read, .list, .write, .update, .delete, .mkdir, .rename };
    const cases = [_]struct { []const u8, []const Permission }{
        // `read` implies `list`: download-without-listing is only obscurity.
        .{ "read", &.{ .read, .list } },
        // `list` alone browses without downloading.
        .{ "list", &.{.list} },
        // `write` is create-only: a drop box without mkdir, overwrite,
        // delete, or rename.
        .{ "read write", &.{ .read, .list, .write } },
        // Re-sending `daily.csv` may replace it (the clobber rule) without
        // deletion, rename (which destroys a name), or mkdir.
        .{ "read write update", &.{ .read, .list, .write, .update } },
        // Deletion without clobber.
        .{ "read delete", &.{ .read, .list, .delete } },
        .{ "mkdir", &.{.mkdir} },
        .{ "rename", &.{.rename} },
        .{ "full", all },
        // A composite plus verbs it already includes ORs cleanly.
        .{ "full write rename mkdir", all },
        .{ "read write list mkdir delete rename update", all },
    };
    for (cases) |case| {
        const verbs, const want = case;
        var buf: [256]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf, "server\n  listen :2222\n  host-key /k\nuser u\n  auth /u.pub\n  root /r\n  allow /pending {s}\n", .{verbs});
        var cfg = try parse(std.testing.allocator, text);
        defer cfg.deinit();
        var expected = PermissionSet.initEmpty();
        for (want) |p| expected.insert(p);
        try std.testing.expect(expected.eql(cfg.users[0].rules[0].permissions));
        try std.testing.expectEqualStrings("/pending", cfg.users[0].rules[0].pattern);
    }

    // A retired verb is a hard error, never silently reinterpreted.
    for ([_][]const u8{ "add", "create", "remove", "Read" }) |verb| {
        var buf: [256]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf, "server\n  listen :2222\n  host-key /k\nuser u\n  auth /u.pub\n  root /r\n  allow /pending read {s}\n", .{verb});
        try std.testing.expectError(error.InvalidPermission, parse(std.testing.allocator, text));
    }
    try std.testing.expectError(error.MissingRulePermissions, parse(std.testing.allocator, "server\n  listen :2222\n  host-key /k\nuser u\n  auth /u.pub\n  root /r\n  allow /pending\n"));
}

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

test "publish-mode: owner rw, no world-write, no special bits" {
    const cases = .{
        .{ "0o600", @as(?u32, 0o600) },
        .{ "0o640", @as(?u32, 0o640) },
        .{ "0o660", @as(?u32, 0o660) },
        .{ "660", @as(?u32, 0o660) }, // bare-octal also accepted
        .{ "0660", @as(?u32, 0o660) }, // leading-zero octal also accepted
        // Readable by a downstream processor running as another user.
        .{ "0o644", @as(?u32, 0o644) },
        .{ "0o664", @as(?u32, 0o664) },
        // World-writable partner data is never allowed.
        .{ "0o666", @as(?u32, null) },
        .{ "0o602", @as(?u32, null) },
        // Special bits (setuid/setgid/sticky) on regular files.
        .{ "0o2660", @as(?u32, null) },
        .{ "0o4600", @as(?u32, null) },
        .{ "0o1600", @as(?u32, null) },
        // The daemon writes the file, so the owner needs rw.
        .{ "0o060", @as(?u32, null) },
        .{ "0o400", @as(?u32, null) },
        .{ "0o200", @as(?u32, null) },
        .{ "abc", @as(?u32, null) },
        .{ "0o", @as(?u32, null) },
        .{ "0o680", @as(?u32, null) },
        .{ "0o10600", @as(?u32, null) },
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

test "mkdir-mode: owner rwx, no world-write, setgid the only special bit" {
    const cases = .{
        .{ "0o2700", @as(?u32, 0o2700) },
        .{ "0o2750", @as(?u32, 0o2750) },
        .{ "0o2770", @as(?u32, 0o2770) },
        .{ "2770", @as(?u32, 0o2770) },
        // Without setgid, or world-traversable: the operator's choice.
        .{ "0o770", @as(?u32, 0o770) },
        .{ "0o2775", @as(?u32, 0o2775) },
        .{ "0o755", @as(?u32, 0o755) },
        // World-writable, setuid, or sticky: never.
        .{ "0o2777", @as(?u32, null) },
        .{ "0o4770", @as(?u32, null) },
        .{ "0o1770", @as(?u32, null) },
        // The daemon uses the directory, so the owner needs rwx.
        .{ "0o2600", @as(?u32, null) },
        .{ "0o2070", @as(?u32, null) },
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

// Real public keys from `ssh-keygen` (the private halves were discarded).
const p256_blob = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNKeFpUsh1jUHDG+05bmJFHkl2uxDCjdzZHpWB5+qoysGjTdSVeYyLMvCPSfif9sYokbeyXsXjDJYZJ7ki3ncFI=";
const p384_blob = "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBKumS9+/JaZVJ/Cy6DX3wzfwD8UofDcCVAavhN0eOMlz8xd1Qli5lSNOXhQ9CQ14+1QIckZol5yTVMbHkyAYgPI2kkdiaHvkU+r6TR7yZsQ9+p2E/RR7061Gv2eAGId08Q==";
const p521_blob = "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBABtVeJs+6gDDLIYuTlpiRXMpL6rHaxhFsr958i8Q+2232CptIdRPW3Mw9qy15b5TWZiIib5/gCowKElSUcLqmboagD0O+ODB8+hYSEHlmoiF0ZVzY0gvJWNBOSzJuih1jH7L2mcm7dRXYCuRMNizCM7eqLKLml02JQfjkp2tDiQYSpt8w==";
const rsa2048_blob = "AAAAB3NzaC1yc2EAAAADAQABAAABAQDNf82HsFOlWYPeBHDp6nhLVUzGgJT4+D99TPH/fJ2VOmoUq3DHwsbawX0A5NIg9gzMhKauVlbHPy2H7H9vBZ9q6nJIhynI3Fp8QfMQVFg8GxOK42sGGmW0bgu+kbtSFuW26zj4wrBHYPGdDWLiVIqv4gw6a+uAZyuWQBkVAoonto4vJzSyOPRyKxYbMWMV5gI0aYBpCYCERzskqidZNb8AZ7Ky05APp7MYTbLRvJ4lfzXsEaEI+98QF6ukTn11rGgVT6rfhLQFM2WgnxkDCup22bGu7EPTmlbZIRk0JB2chhhTqWPxKKcLdcWyWIbtnPcE+zNgArR3CgMxgdGlPKQh";
const rsa1024_blob = "AAAAB3NzaC1yc2EAAAADAQABAAAAgQDhVYKGNZBL5evydJndB/lNoUz5v6AQMtfSBv4SS3GgXSKDzPvjZkQVDL9mBbamJ9Va/OLKEygtlxowa8yyflT9iers1ISexP/R0bUdEKlGNUuhyahABR4XQbw2Y3snodGgDPq4RU2UpJLp4MpwEPB9kivODfWt3xzML4v63PKLYQ==";

test "parsePublicKeyLine: each algorithm accepted with a matching blob" {
    const good = [_][]const u8{
        "ssh-ed25519 " ++ valid_ed25519_blob ++ " comment",
        "ecdsa-sha2-nistp256 " ++ p256_blob ++ " backup",
        "ecdsa-sha2-nistp384 " ++ p384_blob,
        "ecdsa-sha2-nistp521 " ++ p521_blob,
        "ssh-rsa " ++ rsa2048_blob ++ " old-mft-client",
    };
    for (good) |line| {
        const pk = try parsePublicKeyLine(std.testing.allocator, line);
        std.testing.allocator.free(pk.algorithm);
        std.testing.allocator.free(pk.blob);
    }
}

test "parsePublicKeyLine: blob must match its algorithm and be well formed" {
    const cases = [_]struct { []const u8, Error }{
        // The label names one algorithm, the blob another.
        .{ "ssh-ed25519 " ++ p256_blob, error.KeyAlgorithmMismatch },
        .{ "ecdsa-sha2-nistp384 " ++ p256_blob, error.KeyAlgorithmMismatch },
        .{ "ssh-rsa " ++ valid_ed25519_blob, error.KeyAlgorithmMismatch },
        // Too short to hold a key, or truncated mid-string.
        .{ "ssh-ed25519 AAAA", error.InvalidKeyLine },
        .{ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5", error.InvalidKeyLine },
        .{ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPHj7SuD0g1xj0ZqLELSQ7Ux8RSjGlYBhVMxbfBhPX==", error.InvalidKeyLine },
        // Trailing bytes after the key (a 51-byte blob plus one zero byte).
        .{ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPHj7SuD0g1xj0ZqLELSQ7Ux8RSjGlYBhVMxbfBhPXMdAA==", error.InvalidKeyLine },
        // RSA below 2048 bits.
        .{ "ssh-rsa " ++ rsa1024_blob, error.InvalidRsaKeySize },
        // DSA, FIDO, and authorized_keys option prefixes are not supported.
        .{ "ssh-dss AAAAB3NzaC1kc3MAAAA legacy", error.UnsupportedKeyAlgorithm },
        .{ "sk-ssh-ed25519@openssh.com AAAA", error.UnsupportedKeyAlgorithm },
        .{ "from=\"10.0.0.1\" ssh-ed25519 " ++ valid_ed25519_blob, error.UnsupportedKeyAlgorithm },
        .{ "ssh-ed25519", error.InvalidKeyLine },
    };
    for (cases) |case| {
        const line, const want = case;
        try std.testing.expectError(want, parsePublicKeyLine(std.testing.allocator, line));
    }
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

test "user names: the name becomes a path component, so no dots up front" {
    // `.` and `..` would alias or escape `partner-root`; a leading dot hides.
    for ([_][]const u8{ "..", ".", ".hidden", "a/b", "a b", "ally@example.com" }) |name| {
        var buf: [256]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf, "server\n  listen :2222\n  host-key /k\n  partner-root /home/zift\nuser {s}\n  auth /u.pub\n", .{name});
        try std.testing.expectError(error.InvalidUserName, parse(std.testing.allocator, text));
    }
    var cfg = try parse(std.testing.allocator, "server\n  listen :2222\n  host-key /k\n  partner-root /p\nuser a.b-c_9\n  auth /u.pub\n");
    defer cfg.deinit();
    try std.testing.expectEqualStrings("/p/a.b-c_9", cfg.users[0].root);
}

test "removed directives get a migration error, not UnknownKey" {
    const base = "server\n  listen :2222\n  host-key /k\nuser ally\n  root /a\n  auth " ++ valid_test_passhash ++ "\n";
    try std.testing.expectError(error.PasswordDirectiveRemoved, parse(std.testing.allocator, base ++ "  password " ++ valid_test_passhash ++ "\n"));
    try std.testing.expectError(error.KeyDirectiveRemoved, parse(std.testing.allocator, base ++ "  key ssh-ed25519 " ++ valid_ed25519_blob ++ "\n"));
}

test "root and partner-root: absolute, and the default root is <partner-root>/<user>" {
    const Want = union(enum) { root: []const u8, err: Error };
    const cases = [_]struct { []const u8, []const u8, Want }{
        // { server lines, user lines, outcome }
        .{ "  partner-root /home/zift\n", "", .{ .root = "/home/zift/ally" } },
        // Trailing `/` trimmed: no `//` in the joined root.
        .{ "  partner-root /home/zift/\n", "", .{ .root = "/home/zift/ally" } },
        // POSIX leaves a leading `//` implementation-defined.
        .{ "  partner-root /\n", "", .{ .root = "/ally" } },
        .{ "  partner-root /home/zift\n", "  root /custom/path\n", .{ .root = "/custom/path" } },
        .{ "", "  root /custom/path\n", .{ .root = "/custom/path" } },
        .{ "", "", .{ .err = error.MissingRoot } },
        .{ "  partner-root home/zift\n", "", .{ .err = error.RelativePath } },
        .{ "", "  root home/ally\n", .{ .err = error.RelativePath } },
        .{ "  log var/log/zift.log\n", "  root /r\n", .{ .err = error.RelativePath } },
    };
    for (cases) |case| {
        const server_lines, const user_lines, const want = case;
        var buf: [256]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf, "server\n  listen :2222\n  host-key /k\n{s}user ally\n  auth /a.pub\n{s}", .{ server_lines, user_lines });
        switch (want) {
            .root => |root| {
                var cfg = try parse(std.testing.allocator, text);
                defer cfg.deinit();
                try std.testing.expectEqualStrings(root, cfg.findUser("ally").?.root);
            },
            .err => |err| try std.testing.expectError(err, parse(std.testing.allocator, text)),
        }
    }
}

test "server defaults applied when properties omitted" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqual(@as(u64, 300_000), cfg.server.idle_timeout_ms);
    try std.testing.expectEqual(@as(u32, 128), cfg.server.max_connections);
    try std.testing.expectEqual(@as(u32, 32), cfg.server.max_unauth_connections);
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

test "max-unauth-connections: explicit values kept, default a quarter, never above the total" {
    // { max-connections line, max-unauth-connections line, want (null = UnauthCapExceedsTotal) }
    const cases = [_]struct { []const u8, []const u8, ?u32 }{
        .{ "64", "0", 0 }, // explicit 0: no separate cap
        .{ "32", "32", 32 },
        .{ "64", "16", 16 },
        .{ "8", "16", null },
        .{ "64", "4294967295", null },
        .{ "64", "", 16 }, // unset: max-connections / 4
        .{ "3", "", 1 }, // unset: never below 1
        .{ "1", "", 1 },
        .{ "", "", 32 }, // both unset: 128 / 4
    };
    for (cases) |case| {
        const total, const unauth, const want = case;
        var buf: [256]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        try w.writeAll("server\n  listen :2222\n  host-key /k\n");
        if (total.len != 0) try w.print("  max-connections {s}\n", .{total});
        if (unauth.len != 0) try w.print("  max-unauth-connections {s}\n", .{unauth});
        if (want) |n| {
            var cfg = try parse(std.testing.allocator, w.buffered());
            defer cfg.deinit();
            try std.testing.expectEqual(n, cfg.server.max_unauth_connections);
        } else {
            try std.testing.expectError(error.UnauthCapExceedsTotal, parse(std.testing.allocator, w.buffered()));
        }
    }
    try expectDiag("server\n  listen :2222\n  max-unauth-connections 16\n  max-connections 8\n  host-key /k\n", "line 3: [server] 'max-unauth-connections': UnauthCapExceedsTotal: max-unauth-connections (16) exceeds max-connections (8)");
}

test "numbers: plain digits only, and no zero max-connections" {
    const bad = [_][]const u8{
        "max-connections 0",         "max-connections 1_000", "max-connections +5",
        "max-connections 0x10",      "idle-timeout 1_0s",     "publish-mode 6_60",
        "max-unauth-connections -1",
    };
    for (bad) |line| {
        var buf: [128]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf, "server\n  listen :2222\n  host-key /k\n  {s}\n", .{line});
        if (parse(std.testing.allocator, text)) |cfg| {
            var parsed = cfg;
            parsed.deinit();
            return error.TestUnexpectedResult;
        } else |_| {}
    }
    try expectDiag("server\n  max-connections 0\n", "line 2: [server] 'max-connections': InvalidNumber: must be at least 1");
}

test "idle-timeout and reload-interval: 0 or a sane floor" {
    const cases = [_]struct { []const u8, bool }{
        .{ "idle-timeout 0", true },
        .{ "idle-timeout 1s", true },
        .{ "idle-timeout 999ms", false },
        .{ "idle-timeout 1ms", false },
        .{ "reload-interval 0", true },
        .{ "reload-interval 100ms", true },
        .{ "reload-interval 99ms", false },
        .{ "shutdown-grace 1ms", true }, // no floor: 0 already means "force-close now"
    };
    for (cases) |case| {
        const line, const ok = case;
        var buf: [128]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf, "server\n  listen :2222\n  host-key /k\n  {s}\n", .{line});
        if (ok) {
            var cfg = try parse(std.testing.allocator, text);
            cfg.deinit();
        } else {
            try std.testing.expectError(error.InvalidDuration, parse(std.testing.allocator, text));
        }
    }
    try expectDiag("server\n  idle-timeout 10ms\n", "line 2: [server] 'idle-timeout': InvalidDuration: must be 0 (off) or at least 1s");
}

/// A scratch tree for filesystem validation: `etc/host` (a fresh ed25519
/// host key, 0600), `etc/u.pub` (0644), `log/`, and root `r/`.
const TestTree = struct {
    tmp: std.testing.TmpDir,
    /// Canonical path of the tree; `@` in configs stands for it.
    path: []const u8,

    const config =
        \\server
        \\  listen :2222
        \\  host-key @/etc/host
        \\  log @/log/audit.log
        \\user u
        \\  auth @/etc/u.pub
        \\  root @/r
        \\
    ;

    fn init() !TestTree {
        const io = std.testing.io;
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        for ([_][]const u8{ "etc", "log", "r" }) |sub| try tmp.dir.createDir(io, sub, .default_dir);
        var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const len = try tmp.dir.realPath(io, &buf);
        var tree: TestTree = .{ .tmp = tmp, .path = try std.testing.allocator.dupe(u8, buf[0..len]) };
        try tree.hostKey("etc/host", null);
        try tmp.dir.writeFile(io, .{ .sub_path = "etc/u.pub", .data = "ssh-ed25519 " ++ valid_ed25519_blob ++ "\n" });
        try tree.chmod("etc/u.pub", 0o644);
        return tree;
    }

    fn deinit(self: *TestTree) void {
        std.testing.allocator.free(self.path);
        self.tmp.cleanup();
    }

    /// Write a new ed25519 private key, encrypted when `passphrase` is set.
    fn hostKey(self: *TestTree, sub: []const u8, passphrase: ?[*:0]const u8) !void {
        var key: c.ssh_key = null;
        if (c.ssh_pki_generate(c.SSH_KEYTYPE_ED25519, 0, &key) != c.SSH_OK) return error.KeygenFailed;
        defer c.ssh_key_free(key);
        const full = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/{s}", .{ self.path, sub }, 0);
        defer std.testing.allocator.free(full);
        if (c.ssh_pki_export_privkey_file(key, passphrase, null, null, full.ptr) != c.SSH_OK) return error.KeyExportFailed;
        try self.chmod(sub, 0o600);
    }

    fn chmod(self: *TestTree, sub: []const u8, mode: u32) !void {
        try self.tmp.dir.setFilePermissions(std.testing.io, sub, .fromMode(@intCast(mode)), .{});
    }

    /// Parse `text` with `@` expanded, then run validateSemantic with the
    /// config path `@/<config_sub>` when given.
    fn check(self: *TestTree, text: []const u8, config_sub: ?[]const u8) !void {
        const alloc = std.testing.allocator;
        const expanded = try std.mem.replaceOwned(u8, alloc, text, "@", self.path);
        defer alloc.free(expanded);
        var cfg = try parse(alloc, expanded);
        defer cfg.deinit();
        const config_path = if (config_sub) |sub| try std.fmt.allocPrint(alloc, "{s}/{s}", .{ self.path, sub }) else null;
        defer if (config_path) |p| alloc.free(p);
        var diag: LoadDiag = .{};
        try validateSemantic(std.testing.io, alloc, &cfg, config_path, &diag);
    }

    /// `check` with `from` in the base config replaced by `to`.
    fn checkWith(self: *TestTree, from: []const u8, to: []const u8) !void {
        const text = try std.mem.replaceOwned(u8, std.testing.allocator, config, from, to);
        defer std.testing.allocator.free(text);
        return self.check(text, null);
    }
};

test "validateSemantic: a well-formed tree passes, and the config file is checked too" {
    var tree = try TestTree.init();
    defer tree.deinit();
    try tree.check(TestTree.config, null);
    try tree.check(TestTree.config, "etc/zift.conf");
    try std.testing.expectError(error.PrivateFileInsideRoot, tree.check(TestTree.config, "r/zift.conf"));
}

test "validateSemantic: host key mode, type, and content" {
    var tree = try TestTree.init();
    defer tree.deinit();
    for ([_]u32{ 0o600, 0o400, 0o640 }) |mode| {
        try tree.chmod("etc/host", mode);
        try tree.check(TestTree.config, null);
    }
    for ([_]u32{ 0o644, 0o660, 0o604, 0o610, 0o777 }) |mode| {
        try tree.chmod("etc/host", mode);
        try std.testing.expectError(error.HostKeyUnreadable, tree.check(TestTree.config, null));
    }
    try tree.chmod("etc/host", 0o600);

    // A directory, a missing file, garbage, and a passphrase-protected key
    // all passed `validate` before and failed only at `serve`.
    try std.testing.expectError(error.HostKeyUnreadable, tree.checkWith("@/etc/host", "@/etc"));
    try std.testing.expectError(error.HostKeyUnreadable, tree.checkWith("@/etc/host", "@/etc/none"));
    try tree.tmp.dir.writeFile(std.testing.io, .{ .sub_path = "etc/junk", .data = "garbage" });
    try tree.chmod("etc/junk", 0o600);
    try std.testing.expectError(error.HostKeyUnreadable, tree.checkWith("@/etc/host", "@/etc/junk"));
    try tree.hostKey("etc/locked", "secret");
    try std.testing.expectError(error.HostKeyUnreadable, tree.checkWith("@/etc/host", "@/etc/locked"));
}

test "validateSemantic: host key and key file symlinks are followed, and the target checked" {
    var tree = try TestTree.init();
    defer tree.deinit();
    const io = std.testing.io;
    // Kubernetes Secrets and systemd credentials are symlinks.
    try tree.tmp.dir.symLink(io, "host", "etc/host-link", .{});
    try tree.tmp.dir.symLink(io, "u.pub", "etc/u-link.pub", .{});
    const linked = "server\n  listen :2222\n  host-key @/etc/host-link\nuser u\n  auth @/etc/u-link.pub\n  root @/r\n";
    try tree.check(linked, null);

    try tree.chmod("etc/host", 0o644);
    try std.testing.expectError(error.HostKeyUnreadable, tree.check(linked, null));
    try tree.chmod("etc/host", 0o600);
    try tree.chmod("etc/u.pub", 0o664);
    try std.testing.expectError(error.AuthKeyFileWritableByOthers, tree.check(linked, null));
}

test "validateSemantic: key files hold keys, comments, and blank lines" {
    var tree = try TestTree.init();
    defer tree.deinit();
    const io = std.testing.io;
    const write = struct {
        fn f(t: *TestTree, data: []const u8) !void {
            try t.tmp.dir.writeFile(std.testing.io, .{ .sub_path = "etc/u.pub", .data = data });
            try t.chmod("etc/u.pub", 0o644);
        }
    }.f;

    // Every key line counts; CRLF, comments, and blanks are fine.
    try write(&tree, "# ally's keys\r\n\r\nssh-ed25519 " ++ valid_ed25519_blob ++ " laptop\r\n  ecdsa-sha2-nistp256 " ++ p256_blob ++ "\n");
    {
        const expanded = try std.mem.replaceOwned(u8, std.testing.allocator, TestTree.config, "@", tree.path);
        defer std.testing.allocator.free(expanded);
        var cfg = try parse(std.testing.allocator, expanded);
        defer cfg.deinit();
        var diag: LoadDiag = .{};
        try validateSemantic(io, std.testing.allocator, &cfg, null, &diag);
        try std.testing.expectEqual(@as(usize, 2), cfg.users[0].keys.len);
        try std.testing.expectEqualStrings("ecdsa-sha2-nistp256", cfg.users[0].keys[1].algorithm);
    }

    try write(&tree, "# nothing but a comment\n\n");
    try std.testing.expectError(error.AuthKeyFileEmpty, tree.check(TestTree.config, null));
    try write(&tree, "ssh-ed25519 " ++ valid_ed25519_blob ++ "\nssh-ed25519 AAAA\n");
    try std.testing.expectError(error.AuthKeyFileMalformed, tree.check(TestTree.config, null));
    try write(&tree, "#" ** (max_keyline_bytes * 4 + 1));
    try std.testing.expectError(error.AuthKeyFileTooLarge, tree.check(TestTree.config, null));
    try std.testing.expectError(error.AuthKeyFileNotRegular, tree.checkWith("@/etc/u.pub", "@/etc"));
    try std.testing.expectError(error.AuthKeyFileUnreadable, tree.checkWith("@/etc/u.pub", "@/etc/none.pub"));
}

test "validateSemantic: the log directory must exist and a log must be a regular file" {
    var tree = try TestTree.init();
    defer tree.deinit();
    try std.testing.expectError(error.LogPathUnusable, tree.checkWith("@/log/audit.log", "@/nodir/audit.log"));
    try std.testing.expectError(error.LogPathUnusable, tree.checkWith("@/log/audit.log", "@/etc/u.pub/audit.log"));
    try std.testing.expectError(error.LogPathUnusable, tree.checkWith("@/log/audit.log", "@/log"));
    try tree.tmp.dir.symLink(std.testing.io, "../etc/u.pub", "log/link.log", .{});
    try std.testing.expectError(error.LogPathUnusable, tree.checkWith("@/log/audit.log", "@/log/link.log"));
    try tree.tmp.dir.writeFile(std.testing.io, .{ .sub_path = "log/audit.log", .data = "" });
    try tree.check(TestTree.config, null);
}

test "validateSemantic: a root of / overlaps every other root" {
    var tree = try TestTree.init();
    defer tree.deinit();
    try std.testing.expectError(error.OverlappingRoots, tree.check(TestTree.config ++ "user top\n  auth @/etc/u.pub\n  root /\n", null));
}

test "validateSemantic: no daemon-private file inside a partner root" {
    var tree = try TestTree.init();
    defer tree.deinit();
    const io = std.testing.io;
    try tree.tmp.dir.createDir(io, "r/keys", .default_dir);
    try tree.hostKey("r/keys/host", null);
    try tree.tmp.dir.writeFile(io, .{ .sub_path = "r/keys/u.pub", .data = "ssh-ed25519 " ++ valid_ed25519_blob ++ "\n" });
    try tree.chmod("r/keys/u.pub", 0o644);

    try std.testing.expectError(error.PrivateFileInsideRoot, tree.checkWith("@/etc/host", "@/r/keys/host"));
    try std.testing.expectError(error.PrivateFileInsideRoot, tree.checkWith("@/etc/u.pub", "@/r/keys/u.pub"));
    try std.testing.expectError(error.PrivateFileInsideRoot, tree.checkWith("@/log/audit.log", "@/r/audit.log"));

    // A symlink outside that points in, and one inside that points out.
    try tree.tmp.dir.symLink(io, "../r/keys/u.pub", "etc/in.pub", .{});
    try std.testing.expectError(error.PrivateFileInsideRoot, tree.checkWith("@/etc/u.pub", "@/etc/in.pub"));
    try tree.tmp.dir.symLink(io, "../../etc/u.pub", "r/keys/out.pub", .{});
    try std.testing.expectError(error.PrivateFileInsideRoot, tree.checkWith("@/etc/u.pub", "@/r/keys/out.pub"));

    // A partner whose name matches the key directory under partner-root.
    try std.testing.expectError(error.PrivateFileInsideRoot, tree.check(
        "server\n  listen :2222\n  host-key @/r/../etc/host\n  partner-root @\nuser etc\n  auth @/log/../etc/u.pub\n",
        null,
    ));
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
    try expectDiag("server\n  publish-mode 0o666\n", "line 2: [server] 'publish-mode': InvalidMode: needs owner rw (0o600), no world-write, and no setuid/setgid/sticky bit");
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

test "comments: whole-line, or '#' after a blank; a '#' inside a token is literal" {
    const text =
        "# top\nserver # the only one\n  # indented\n  listen :2222\t# tab before\n  host-key /k#1\n" ++
        "\nuser u # partner\n  auth /u#.pub  # key file\n  root /r\n  deny /a#b /c   # two patterns\n  allow /#in read\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqualStrings(":2222", cfg.server.listen);
    try std.testing.expectEqualStrings("/k#1", cfg.server.host_key);
    const u = cfg.findUser("u").?;
    try std.testing.expectEqualStrings("/u#.pub", u.key_files[0]);
    try std.testing.expectEqual(@as(usize, 3), u.rules.len);
    try std.testing.expectEqualStrings("/a#b", u.rules[0].pattern);
    try std.testing.expectEqualStrings("/c", u.rules[1].pattern);
    try std.testing.expectEqualStrings("/#in", u.rules[2].pattern);
    // `read#write` is one token: not a verb.
    try std.testing.expectError(error.InvalidPermission, parse(std.testing.allocator, text ++ "  allow /x read#write\n"));
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

    const live = [_][]const u8{ "/", "/secret", "/*.exe", "**", "**.exe", "***.exe", "**/secret", "/in/**", "/a/**/b", "/a.b/..c", "/#x", "/a#" };
    for (live) |pattern| {
        var buf: [256]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf, "server\n  listen :2222\n  host-key /k\nuser u\n  auth /u.pub\n  root /r\n  deny {s}\n", .{pattern});
        var cfg = try parse(std.testing.allocator, text);
        defer cfg.deinit();
        try std.testing.expectEqualStrings(pattern, cfg.users[0].rules[0].pattern);
    }

    try expectDiag("server\n  listen :2222\n  host-key /k\nuser u\n  deny *.exe\n", "line 5: [user u] 'deny': InvalidPattern: '*.exe' never matches: start it with '/' (top level) or '**/' (any depth)");
}
