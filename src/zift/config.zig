const std = @import("std");
const netmatch = @import("netmatch.zig");
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
    /// Per PLAN.md §8.4. Independent cap on the number of pre-auth
    /// (unauthenticated) sessions. Bounds handshake-storm pressure so
    /// an attacker cannot consume the entire `max_connections` pool
    /// with stuck pre-auth sockets, leaving authenticated partner
    /// sessions DoS'd. `0` disables the separate cap (= behavior is
    /// the same as having only `max_connections` enforced). When set,
    /// must be ≤ `max_connections`. A value of `max_connections / 4`
    /// is a reasonable starting point for partner deployments.
    max_unauth_connections: u32,
    /// Per PLAN.md §7.1 default 30_000 (30 seconds). Time the server
    /// waits for in-flight sessions to finish naturally on SIGTERM/SIGINT
    /// before actively shutting down their sockets and exiting. Exposed
    /// primarily so integration tests can run drain scenarios in
    /// seconds rather than minutes.
    shutdown_grace_ms: u64,
    log: LogTarget,
    /// How `sftp> ls -la` renders entries to the partner. `virtual`
    /// (default in v0.3.0+) shows the partner's own virtual-user
    /// name, a fixed group of `sftp`, policy-derived rwx bits in the
    /// owner+group triplets, and `---` for world; setuid/setgid/sticky
    /// bits are always cleared. `reality` is the v0.2.x behavior:
    /// the inode's real owner, group, and mode pass through
    /// unchanged — including any setuid/setgid/sticky bits. PLAN
    /// §7.6 (default flipped between v0.2.x and v0.3.0).
    listing_mode: ListingMode,
    /// Mode applied to atomically-published files (the result of
    /// alice's `put report.csv`). v0.6.0 default `0o660` — group
    /// `zift` can read+write, world has nothing. Confidentiality of
    /// partial uploads during transfer is enforced by the
    /// `<root>/.zift/staging/` directory being mode `0o700` regardless
    /// of this setting; it only controls what the file lands at after
    /// the atomic rename. Allowed values: `0o600`, `0o640`, `0o660`.
    /// Anything else is rejected at parse time to prevent operators
    /// from accidentally configuring world-readable or world-writable
    /// modes. PLAN §6.2.
    publish_mode: u32,
    /// Mode applied to directories created via SFTP `MKDIR`. v0.6.0
    /// default `0o2770` — setgid + group rwx + world none, matching
    /// the partner-tree posture set up by the deploy. The setgid bit
    /// ensures any subdirectories alice creates inside also inherit
    /// `group=zift`, so operators in the `zift` group can manage the
    /// whole subtree without UID gymnastics. Allowed values:
    /// `0o2700`, `0o2750`, `0o2770`. PLAN §6.2.
    mkdir_mode: u32,
    /// Optional. When set, a user block without an explicit `root`
    /// directive defaults its root to `${partner-root}/${user-name}`.
    /// Operators pointing every partner at `/home/zift/<name>` no
    /// longer have to copy-paste the same line into every user
    /// block. There is deliberately NO hardcoded default — leaving
    /// `partner-root` unset preserves the v0.6.x behavior where
    /// every user must declare `root` explicitly. v0.7.0.
    partner_root: ?[]const u8,
};

pub const ListingMode = enum {
    virtual,
    reality,
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
    /// Public keys authorized for this user. Empty after `parse`
    /// because v0.7.0 removed inline keys (the `key ssh-ed25519 ...`
    /// directive). Populated by `validateSemantic`, which opens
    /// every `key_files[i]`, parses each non-comment line as a
    /// public key, and stores the merged result here. The runtime
    /// auth path reads only this field.
    keys: []const PublicKey,
    /// Absolute paths to OpenSSH public-key files referenced by
    /// `auth /path/to/key.pub` lines. Recorded by `parse` and
    /// opened by `validateSemantic`. Kept on the resolved config
    /// so a future reload-diff can detect when the operator has
    /// added or removed a key file even when `zift.conf` itself
    /// was unchanged.
    key_files: []const []const u8,
    /// Optional source CIDRs from `from` lines. Empty means any
    /// source IP may attempt auth for this user (still subject to
    /// credentials + built-in abuse suppression). When non-empty,
    /// the peer must match at least one entry.
    from: []const netmatch.Cidr,
    root: []const u8,
    rules: []const Rule,
};

pub const Config = struct {
    arena: std.heap.ArenaAllocator,
    server: ServerConfig,
    /// Mutable so `validateSemantic` can replace each user's `keys`
    /// after resolving `auth /path/...` references. Treat this as
    /// `[]const UserConfig` everywhere except inside the validate
    /// pass — the lifetime is the config arena either way.
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
/// Pure-numeric subset of `validateSemantic` — the part that doesn't
/// touch the filesystem and so can be unit-tested directly without
/// having to construct a `std.Io`. Always called first by
/// `validateSemantic` so an obviously-wrong cap arrangement fails
/// before we waste a stat() on the host-key path. Not `pub`; tests
/// in this file can reach it without expanding the public surface.
fn validatePureNumeric(cfg: *const Config) error{UnauthCapExceedsTotal}!void {
    // The pre-auth cap, if configured (>0), must be ≤ the total cap.
    // A pre-auth cap LARGER than the total cap can't ever fire (the
    // total cap rejects first) and silently letting it slide hides
    // an operator misconfig that's more likely a typo for
    // `max-connections` than intent.
    if (cfg.server.max_unauth_connections != 0 and
        cfg.server.max_unauth_connections > cfg.server.max_connections)
    {
        return error.UnauthCapExceedsTotal;
    }
}

pub fn validateSemantic(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: *Config,
) SemanticError!void {
    const stderr = std.Io.File.stderr();

    // 1. Pure-numeric checks first: a config that has them wrong
    // shouldn't even try to stat the filesystem. Split into a pure
    // function so unit tests can cover the rejection logic without
    // having to construct a `std.Io` (the test surface).
    validatePureNumeric(cfg) catch |err| {
        switch (err) {
            error.UnauthCapExceedsTotal => {
                stderr.writeStreamingAll(io, "zift: max-unauth-connections (") catch {};
                var num_buf: [16]u8 = undefined;
                const u = std.fmt.bufPrint(&num_buf, "{d}", .{cfg.server.max_unauth_connections}) catch num_buf[0..0];
                stderr.writeStreamingAll(io, u) catch {};
                stderr.writeStreamingAll(io, ") exceeds max-connections (") catch {};
                const t = std.fmt.bufPrint(&num_buf, "{d}", .{cfg.server.max_connections}) catch num_buf[0..0];
                stderr.writeStreamingAll(io, t) catch {};
                stderr.writeStreamingAll(io, ")\n") catch {};
            },
        }
        return err;
    };

    // 2. Host-key file must exist and be readable.
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

    // 4. v0.7.0 — resolve every `auth /path/to/key.pub` reference.
    // Each file is opened, permission-checked, and parsed; every
    // non-empty/non-comment line becomes an authorized public key.
    // Errors are user-facing; the diagnostic names the user and
    // the path so operators know exactly which line to fix.
    try resolveAuthKeyFiles(io, allocator, cfg);
}

/// Open every key file referenced by an `auth /path/...` line,
/// parse it, and merge the result into the user's `keys` list. The
/// resolved `PublicKey` strings are allocated in `cfg.arena`; the
/// raw file contents are allocated in the validate-time `gpa` and
/// freed before this function returns so the config arena only
/// holds the parsed data.
///
/// Permission posture (PLAN §6.2 / DEPLOY guidance): a key file
/// that grants login shouldn't be writable by anyone the daemon's
/// service account doesn't already trust. We reject any key file
/// whose mode has the world-write or group-write bit set, and any
/// non-regular file (so symlinks pointing at attacker-controlled
/// paths can't slip past the parent-dir mode). Parent-directory
/// writability is the operator's responsibility (documented in
/// operate.md); enforcing it here would conflict with
/// reasonable layouts like `/home/zift/keys/` group-rwx.
fn resolveAuthKeyFiles(
    io: std.Io,
    gpa: std.mem.Allocator,
    cfg: *Config,
) SemanticError!void {
    const stderr = std.Io.File.stderr();
    const arena_alloc = cfg.arena.allocator();

    for (cfg.users) |*user| {
        if (user.key_files.len == 0) continue;

        var combined: std.ArrayList(PublicKey) = .empty;
        // `user.keys` is empty in v0.7.0 (no inline key directive),
        // but copying through here keeps the structure resilient
        // if a future entry point pre-populates keys before
        // validate runs.
        for (user.keys) |existing| try combined.append(arena_alloc, existing);

        for (user.key_files) |path| {
            try resolveOneKeyFile(io, gpa, stderr, arena_alloc, &combined, user.name, path);
        }

        user.keys = try combined.toOwnedSlice(arena_alloc);
    }
}

/// Read+permission-check+parse a single key file, appending each
/// well-formed public-key line to `combined`. Caller owns lifetime
/// of `combined` (allocated in the config arena).
fn resolveOneKeyFile(
    io: std.Io,
    gpa: std.mem.Allocator,
    stderr: std.Io.File,
    arena_alloc: std.mem.Allocator,
    combined: *std.ArrayList(PublicKey),
    user_name: []const u8,
    path: []const u8,
) SemanticError!void {
    // Open with `follow_symlinks = false` so the open fails early
    // if the path is a symlink — this closes the
    // statFile-then-readFileAlloc TOCTOU window where an attacker
    // could swap a checked regular file for a symlink between the
    // two path resolutions. The single open here gives us a stable
    // fd; both stat and read happen against that fd, so the inode
    // we validate is byte-for-byte the inode we parse.
    var file = std.Io.Dir.cwd().openFile(io, path, .{
        .mode = .read_only,
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        // POSIX/Linux: open() with O_NOFOLLOW on a symlink returns
        // ELOOP, which Zig surfaces as `SymLinkLoop`. We translate
        // that to the more operator-facing "symlinks not allowed"
        // diagnostic + the dedicated `AuthKeyFileNotRegular` tag.
        error.SymLinkLoop => {
            writeKeyFileDiag(io, stderr, user_name, path, 0, "symlinks not allowed (use in-place rename for rotation)");
            return error.AuthKeyFileNotRegular;
        },
        else => {
            writeKeyFileDiag(io, stderr, user_name, path, 0, "unreadable");
            return error.AuthKeyFileUnreadable;
        },
    };
    defer file.close(io);

    // fstat on the opened fd. Because we passed `follow_symlinks =
    // false` to `openFile`, a symlink-at-path would have already
    // errored out above; this fstat checks the regular-file +
    // permission invariants on the actual inode we'll read from.
    const stat = file.stat(io) catch {
        writeKeyFileDiag(io, stderr, user_name, path, 0, "stat failed");
        return error.AuthKeyFileUnreadable;
    };
    switch (stat.kind) {
        .file => {},
        else => {
            writeKeyFileDiag(io, stderr, user_name, path, 0, "not a regular file");
            return error.AuthKeyFileNotRegular;
        },
    }
    // Reject any group-write or world-write bit. Group-read /
    // world-read are fine — public keys are public; the value is
    // in tamper-resistance, not secrecy.
    const file_mode: u32 = @intCast(stat.permissions.toMode() & 0o7777);
    const writable_by_others_mask: u32 = 0o022;
    if ((file_mode & writable_by_others_mask) != 0) {
        writeKeyFileDiag(io, stderr, user_name, path, 0, "writable by group/world (mode)");
        return error.AuthKeyFileWritableByOthers;
    }

    // Generous slack above `max_keyline_bytes` so the formatter's
    // line cap applies per-line, not per-file. A 4 KiB key plus
    // up to 4 KiB of comment headers and trailing whitespace
    // comfortably fits; pathological files exceeding the cap are
    // rejected with a precise diagnostic instead of being treated
    // as "unreadable".
    const file_read_cap: usize = max_keyline_bytes * 4;

    // Read from the open fd (NOT by re-resolving `path`). This is
    // what closes the TOCTOU: the inode we just fstat'd is the
    // inode we're now slurping bytes out of.
    var file_reader = file.reader(io, &.{});
    const contents = file_reader.interface.allocRemaining(gpa, .limited(file_read_cap)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => {
            writeKeyFileDiag(io, stderr, user_name, path, 0, "too large");
            return error.AuthKeyFileTooLarge;
        },
        error.ReadFailed => {
            writeKeyFileDiag(io, stderr, user_name, path, 0, "read failed");
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
            writeKeyFileDiag(io, stderr, user_name, path, line_no, "key line too long");
            return error.AuthKeyFileMalformed;
        }
        const pubkey = parsePublicKeyLine(arena_alloc, trimmed) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                writeKeyFileDiag(io, stderr, user_name, path, line_no, "malformed public-key line");
                return error.AuthKeyFileMalformed;
            },
        };
        try combined.append(arena_alloc, pubkey);
        parsed += 1;
    }

    if (parsed == 0) {
        writeKeyFileDiag(io, stderr, user_name, path, 0, "no public-key lines found");
        return error.AuthKeyFileEmpty;
    }
}

/// Format a key-file diagnostic in the same shape as parse errors:
///
///   `zift: user '<name>': auth key file '<path>': <reason>`           (file-level)
///   `zift: user '<name>': auth key file '<path>' line N: <reason>`    (per-line)
///
/// `line_no = 0` means "no specific line" — used for whole-file
/// failures (mode, regular-file, readability, empty-file).
fn writeKeyFileDiag(
    io: std.Io,
    stderr: std.Io.File,
    user_name: []const u8,
    path: []const u8,
    line_no: u32,
    reason: []const u8,
) void {
    stderr.writeStreamingAll(io, "zift: user '") catch {};
    stderr.writeStreamingAll(io, user_name) catch {};
    stderr.writeStreamingAll(io, "': auth key file '") catch {};
    stderr.writeStreamingAll(io, path) catch {};
    stderr.writeStreamingAll(io, "'") catch {};
    if (line_no != 0) {
        stderr.writeStreamingAll(io, " line ") catch {};
        var num_buf: [16]u8 = undefined;
        const printed = std.fmt.bufPrint(&num_buf, "{d}", .{line_no}) catch num_buf[0..0];
        stderr.writeStreamingAll(io, printed) catch {};
    }
    stderr.writeStreamingAll(io, ": ") catch {};
    stderr.writeStreamingAll(io, reason) catch {};
    stderr.writeStreamingAll(io, "\n") catch {};
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
    partner_root: ?[]const u8 = null,
};

const UserBuilder = struct {
    name: []const u8,
    password_hash: ?[]const u8 = null,
    keys: std.ArrayList(PublicKey) = .empty,
    /// Public-key files referenced by `auth /path/to/key.pub` lines.
    /// The parser only records the path; `validateSemantic` opens
    /// each file, parses its first non-empty/non-comment line as a
    /// public key, and merges the result into `keys`. See
    /// `resolveAuthKeyFiles`.
    key_files: std.ArrayList([]const u8) = .empty,
    from: std.ArrayList(netmatch.Cidr) = .empty,
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
    DuplicatePassword,
    DuplicateUser,
    EmptyUserName,
    InlineComment,
    InvalidAuth,
    InvalidConfig,
    InvalidDuration,
    InvalidIndent,
    InvalidKeyLine,
    InvalidPermission,
    InvalidUserName,
    KeyDirectiveRemoved,
    KeyLineTooLong,
    UsernameTooLong,
    MissingCredentials,
    MissingHostKey,
    MissingListen,
    MissingRoot,
    MissingRulePattern,
    MissingRulePermissions,
    MissingServerSection,
    OutOfMemory,
    PasswordDirectiveRemoved,
    PasswordHashNotArgon2id,
    PasswordHashMalformed,
    PasswordMemoryOutOfPolicy,
    PasswordPassesOutOfPolicy,
    PasswordParallelismOutOfPolicy,
    PropertyOutsideSection,
    UnknownKey,
    UnknownSection,
    UnsupportedKeyAlgorithm,
    InvalidFrom,
};

/// PLAN §7.6 fixed implementation limits. Reject at parse time so a
/// malformed config never reaches runtime; reject during request
/// dispatch (path) so a malicious peer cannot spend server CPU on
/// pathological inputs before we say no.
pub const max_username_bytes: usize = 64;
pub const max_keyline_bytes: usize = 8192;

/// Diagnostic context captured by `parse` on any error. Callers (zift
/// validate, zift serve startup, runtime reload) read `line`,
/// `section_kind`, `userName()`, and `key()` after a `catch` to emit a
/// precise stderr diagnostic — `zift: <file>:<line>: <reason>` —
/// rather than the raw error name. PLAN §6.2 / §7.3 require errors
/// that identify file, line, section/user, and key.
///
/// Strings are stored in fixed inline buffers (sized at PLAN §7.6
/// limits) so the diag survives the arena's `deinit` on the error
/// path. A `?[]const u8` here would dangle once the parser's arena is
/// torn down.
pub const ParseDiag = struct {
    line: u32 = 0,
    section_kind: ?Section = null,
    user_name_buf: [max_username_bytes + 1]u8 = [_]u8{0} ** (max_username_bytes + 1),
    user_name_len: usize = 0,
    key_buf: [64]u8 = [_]u8{0} ** 64,
    key_len: usize = 0,

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

    /// Format the captured context plus an `@errorName` suffix into
    /// `writer`. Caller already has `<file>:` prefix; we add the rest.
    pub fn format(self: *const ParseDiag, err: anyerror, writer: *std.Io.Writer) !void {
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
    }
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
    const version_field = iter.next() orelse return error.PasswordHashMalformed;
    if (!std.mem.eql(u8, version_field, "v=19")) return error.PasswordHashMalformed;
    const params = iter.next() orelse return error.PasswordHashMalformed; // m=...,t=...,p=...
    const salt_field = iter.next() orelse return error.PasswordHashMalformed;
    const hash_field = iter.next() orelse return error.PasswordHashMalformed;
    if (iter.next() != null) return error.PasswordHashMalformed;
    if (salt_field.len == 0 or hash_field.len == 0) return error.PasswordHashMalformed;
    if (!isValidPhcBase64(salt_field) or !isValidPhcBase64(hash_field)) return error.PasswordHashMalformed;

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
    return parseWithDiag(gpa, text, null);
}

/// Same as `parse` but also populates `diag` (when non-null) with the
/// line/section/user context of any failure. Callers use this when
/// they want operator-facing diagnostics with file:line precision.
pub fn parseWithDiag(
    gpa: std.mem.Allocator,
    text: []const u8,
    diag: ?*ParseDiag,
) Error!Config {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const allocator = arena.allocator();

    var server: ServerBuilder = .{};
    var seen_server = false;
    var users: std.ArrayList(UserBuilder) = .empty;

    var section: Section = .none;
    var current_user: ?*UserBuilder = null;

    // Mutable trackers updated as we walk; `errdefer` snapshots them
    // into `diag` on any error path so callers see the location of
    // the failing line, the section it's in, and which user was
    // active (if applicable). The diag's string buffers are inline
    // so they survive the arena's `deinit` that runs on this error
    // path (LIFO errdefer order — both run, but slices into the
    // arena would dangle by the time the caller reads them).
    var line_no: u32 = 0;
    var key_for_diag: ?[]const u8 = null;
    errdefer {
        if (diag) |d| {
            d.line = line_no;
            d.section_kind = section;
            if (current_user) |u| d.setUserName(u.name);
            if (key_for_diag) |k| d.setKey(k);
        }
    }

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        line_no += 1;
        key_for_diag = null;

        const no_cr = std.mem.trimEnd(u8, raw, "\r");
        // PLAN §6.2: only whole-line comments are recognized. A line
        // whose first non-whitespace character is `#` is treated as a
        // comment and skipped; a `#` after a value is a syntax error,
        // not a comment delimiter.
        const trimmed_for_comment_check = std.mem.trimStart(u8, no_cr, " \t");
        if (trimmed_for_comment_check.len > 0 and trimmed_for_comment_check[0] == '#') {
            continue;
        }
        const line = std.mem.trim(u8, no_cr, " \t");
        if (line.len == 0) continue;
        if (std.mem.indexOfScalar(u8, line, '#') != null) return error.InlineComment;

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
                if (name.len > max_username_bytes) return error.UsernameTooLong;
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
        key_for_diag = key;
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
        // A user must declare at least one credential: either a
        // password (PHC string in an `auth $...` line) or a public
        // key file (`auth /...` line). Pure key-only and pure
        // password-only users remain valid. PLAN §6.2 (v0.7.0).
        if (builder.password_hash == null and
            builder.keys.items.len == 0 and
            builder.key_files.items.len == 0)
        {
            return error.MissingCredentials;
        }

        // v0.7.0: derive a default root from `partner-root` when
        // the user didn't declare one explicitly. Skipping this
        // when both are unset preserves the v0.6.x rejection
        // (`error.MissingRoot`) for legacy configs that didn't
        // adopt the new directive. The `partner-root /` edge case
        // is special-cased so a derived root never becomes `//foo`
        // — POSIX leaves leading-`//` paths implementation-defined
        // and we don't want a jail boundary depending on that.
        const root_value: []const u8 = if (builder.root) |r|
            r
        else if (server.partner_root) |pr|
            if (std.mem.eql(u8, pr, "/"))
                try std.fmt.allocPrint(allocator, "/{s}", .{builder.name})
            else
                try std.fmt.allocPrint(allocator, "{s}/{s}", .{ pr, builder.name })
        else
            return error.MissingRoot;

        final_users[i] = .{
            .name = builder.name,
            .password_hash = builder.password_hash,
            .keys = try builder.keys.toOwnedSlice(allocator),
            .key_files = try builder.key_files.toOwnedSlice(allocator),
            .from = try builder.from.toOwnedSlice(allocator),
            .root = root_value,
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
            .max_unauth_connections = server.max_unauth_connections,
            .shutdown_grace_ms = server.shutdown_grace_ms,
            .log = server.log orelse .stderr,
            .listing_mode = server.listing_mode,
            .publish_mode = server.publish_mode,
            .mkdir_mode = server.mkdir_mode,
            .partner_root = server.partner_root,
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
    } else if (std.mem.eql(u8, key, "max-unauth-connections")) {
        server.max_unauth_connections = std.fmt.parseUnsigned(u32, value, 10) catch return error.InvalidConfig;
    } else if (std.mem.eql(u8, key, "shutdown-grace")) {
        server.shutdown_grace_ms = try parseDurationMs(value);
    } else if (std.mem.eql(u8, key, "log")) {
        if (std.mem.eql(u8, value, "stderr")) {
            server.log = .stderr;
        } else {
            // PLAN §7.4: file destinations must be absolute paths so
            // logrotate's "rename old, signal SIGUSR1, recreate" cycle
            // operates on a known stable target. Relative paths are
            // ambiguous (relative to whose cwd?) and rejected at parse
            // time rather than discovered at first reload.
            if (value.len == 0 or value[0] != '/') return error.InvalidConfig;
            server.log = .{ .file = try dupNonEmpty(allocator, value) };
        }
    } else if (std.mem.eql(u8, key, "listing-mode")) {
        if (std.mem.eql(u8, value, "virtual")) {
            server.listing_mode = .virtual;
        } else if (std.mem.eql(u8, value, "reality")) {
            server.listing_mode = .reality;
        } else {
            return error.InvalidConfig;
        }
    } else if (std.mem.eql(u8, key, "publish-mode")) {
        server.publish_mode = try parsePublishMode(value);
    } else if (std.mem.eql(u8, key, "mkdir-mode")) {
        server.mkdir_mode = try parseMkdirMode(value);
    } else if (std.mem.eql(u8, key, "partner-root")) {
        // PLAN §6.2 (v0.7.0): absolute path only — relative paths
        // are ambiguous (relative to whose cwd?) and would silently
        // re-resolve depending on how the daemon was invoked. The
        // path itself is not stat'd here; per-user roots derived
        // from it are validated by `validateSemantic` exactly the
        // same way an explicit `root` directive would be.
        if (value.len == 0 or value[0] != '/') return error.InvalidConfig;
        // Trim trailing `/` so `partner-root /home/zift/` and
        // `partner-root /home/zift` both produce the same derived
        // root. The lone `/` (root) is intentionally preserved.
        var pr = value;
        while (pr.len > 1 and pr[pr.len - 1] == '/') pr = pr[0 .. pr.len - 1];
        server.partner_root = try dupNonEmpty(allocator, pr);
    } else {
        return error.UnknownKey;
    }
}

/// Parse `publish-mode` from a config value. Accepts an octal literal
/// with optional `0o` or `0` prefix. The allowed-set is restricted to
/// `0o600 | 0o640 | 0o660` so a config typo can't accidentally produce
/// world-readable or world-writable partner data files. Operators who
/// genuinely want a stricter mode (e.g., `0o600` to keep files
/// daemon-private) can opt in; anything outside the set is rejected
/// at parse time so a regression is caught at validation, not at
/// publish time.
fn parsePublishMode(value: []const u8) Error!u32 {
    const mode = parseOctalMode(value) catch return error.InvalidConfig;
    if (mode != 0o600 and mode != 0o640 and mode != 0o660) {
        return error.InvalidConfig;
    }
    return mode;
}

/// Parse `mkdir-mode` from a config value. Same shape as
/// `parsePublishMode` but for SFTP-created directories. The allowed
/// set carries the setgid bit (`02000`) so child entries inherit
/// `group=zift` automatically — matching the deploy posture where
/// `<root>/<partner>/` itself is `2770`. Allowed: `0o2700 | 0o2750 |
/// 0o2770`. Rejecting other values prevents operators from creating
/// world-traversable directory trees by accident.
fn parseMkdirMode(value: []const u8) Error!u32 {
    const mode = parseOctalMode(value) catch return error.InvalidConfig;
    if (mode != 0o2700 and mode != 0o2750 and mode != 0o2770) {
        return error.InvalidConfig;
    }
    return mode;
}

/// Parse an octal mode literal. Accepts `0o660`, `0660`, and `660`
/// — all three are equivalent. The `0o` prefix is the modern Zig-
/// canonical form; bare values are interpreted as octal exactly the
/// way `chmod` accepts them (`660` means `0o660`, not decimal 660).
/// PLAN §6.2 octal-literal grammar.
fn parseOctalMode(value: []const u8) !u32 {
    if (value.len == 0) return error.InvalidConfig;
    const slice = if (std.mem.startsWith(u8, value, "0o") or std.mem.startsWith(u8, value, "0O"))
        value[2..]
    else
        value;
    if (slice.len == 0) return error.InvalidConfig;
    return std.fmt.parseUnsigned(u32, slice, 8);
}

fn parseUserProperty(
    allocator: std.mem.Allocator,
    user: *UserBuilder,
    key: []const u8,
    value: []const u8,
) Error!void {
    if (std.mem.eql(u8, key, "auth")) {
        try parseAuth(allocator, user, value);
    } else if (std.mem.eql(u8, key, "root")) {
        user.root = try dupNonEmpty(allocator, value);
    } else if (std.mem.eql(u8, key, "from")) {
        try parseFrom(allocator, user, value);
    } else if (std.mem.eql(u8, key, "allow")) {
        try parseAllowRule(allocator, user, value);
    } else if (std.mem.eql(u8, key, "deny")) {
        try parseDenyRules(allocator, user, value);
    } else if (std.mem.eql(u8, key, "password")) {
        // v0.7.0 removed `password` in favor of unified `auth`.
        // A v0.6.x config that still uses it deserves a precise
        // migration diagnostic, not the generic `UnknownKey`.
        return error.PasswordDirectiveRemoved;
    } else if (std.mem.eql(u8, key, "key")) {
        // v0.7.0 removed inline `key` lines; public keys now live
        // in operator-managed files referenced by `auth /path/...`.
        return error.KeyDirectiveRemoved;
    } else {
        return error.UnknownKey;
    }
}

/// Dispatch a single `auth <value>` line. v0.7.0 unifies the two
/// previous credential directives (`password` and `key`) under a
/// single name; the value's first byte selects which kind:
///
///   - `$` → Argon2id PHC string. Validated against the parameter
///     envelope at parse time (same checks the v0.6.x `password`
///     directive ran). At most one PHC `auth` line per user is
///     accepted; a second is rejected as `error.DuplicatePassword`
///     because the runtime stores a single `password_hash`.
///   - `/` → absolute filesystem path to a public-key file. The
///     path is recorded but NOT opened at parse time — that's
///     `validateSemantic`'s job. Path-shape only is validated
///     here (absolute, length cap); the file's *contents* are
///     parsed when `validateSemantic` reads it.
///   - anything else → `error.InvalidAuth`. We don't try to be
///     clever about distinguishing what the operator meant; the
///     two valid leading bytes (`$`, `/`) are unambiguous.
///
/// Multiple `auth /path/to/key.pub` lines accumulate (multiple
/// authorized public keys), matching the v0.6.x behavior where
/// multiple `key` lines were allowed.
fn parseAuth(allocator: std.mem.Allocator, user: *UserBuilder, value: []const u8) Error!void {
    if (value.len == 0) return error.InvalidAuth;
    switch (value[0]) {
        '$' => {
            // Check duplicate-password BEFORE running PHC validation
            // — otherwise a second `auth $bcrypt$...` line gets
            // rejected with `PasswordHashNotArgon2id`, when the real
            // operator error is "you wrote two password lines for
            // the same user." The duplicate diagnostic is more
            // actionable.
            if (user.password_hash != null) return error.DuplicatePassword;
            try checkArgon2idPolicy(value, argon2id_policy);
            user.password_hash = try dupNonEmpty(allocator, value);
        },
        '/' => {
            // PLAN §7.6 length cap. The same upper bound that
            // protected the inline `key` directive now protects the
            // path field — a 4 KiB path is plenty (PATH_MAX is
            // typically 4096 on Linux); anything longer is almost
            // certainly an attack surface or a typo.
            if (value.len > max_keyline_bytes) return error.KeyLineTooLong;
            try user.key_files.append(allocator, try allocator.dupe(u8, value));
        },
        else => return error.InvalidAuth,
    }
}

/// Parse a single OpenSSH public-key line — `<algorithm> <blob>
/// [comment]`. Pure (no I/O); used both for unit tests and as the
/// per-line parser inside the file-loader called from
/// `validateSemantic`. `algorithm` and `blob` are allocator-duped so
/// the result outlives the input slice. Returns the same errors the
/// v0.6.x inline `key` directive produced (`InvalidKeyLine`,
/// `UnsupportedKeyAlgorithm`, `KeyLineTooLong`) — operator-facing
/// behavior is unchanged from v0.6.x for malformed key content.
pub fn parsePublicKeyLine(allocator: std.mem.Allocator, line: []const u8) Error!PublicKey {
    if (line.len > max_keyline_bytes) return error.KeyLineTooLong;

    var parts = std.mem.tokenizeAny(u8, line, " \t");
    const algorithm = parts.next() orelse return error.InvalidKeyLine;
    const blob = parts.next() orelse return error.InvalidKeyLine;

    if (!isAcceptedKeyAlgorithm(algorithm)) return error.UnsupportedKeyAlgorithm;
    if (blob.len == 0) return error.InvalidKeyLine;

    // Strict RFC 4648 standard base64. Same accept/reject behavior
    // libssh applies on the wire when the partner sends a key.
    if (!isValidStandardBase64(blob)) return error.InvalidKeyLine;

    return .{
        .algorithm = try allocator.dupe(u8, algorithm),
        .blob = try allocator.dupe(u8, blob),
    };
}

/// Strict RFC 4648 standard base64 used for OpenSSH wire blobs:
/// alphabet [A-Za-z0-9+/], length must be %4==0, padding is required
/// where the byte count would otherwise leave 1 or 2 trailing chars.
/// We round-trip through `std.base64.standard.Decoder` so the parser
/// makes the same accept/reject decision libssh would.
fn isValidStandardBase64(data: []const u8) bool {
    if (data.len == 0 or data.len % 4 != 0) return false;
    const decoder = std.base64.standard.Decoder;
    const decoded_len = decoder.calcSizeForSlice(data) catch return false;
    var buf: [8192]u8 = undefined;
    if (decoded_len > buf.len) return false;
    decoder.decode(buf[0..decoded_len], data) catch return false;
    return true;
}

/// PHC base64: same alphabet as RFC 4648 standard, but no `=` padding
/// is allowed and the length is therefore not required to be %4==0.
/// PHC §B encodes 16-byte salts as 22 chars, 32-byte hashes as 43 chars,
/// etc. — all with `len % 4 != 0` after the padding is stripped. Used
/// for the `salt` and `hash` fields of an Argon2id PHC string.
fn isValidPhcBase64(data: []const u8) bool {
    if (data.len == 0) return false;
    for (data) |ch| {
        const ok = (ch >= 'A' and ch <= 'Z') or
            (ch >= 'a' and ch <= 'z') or
            (ch >= '0' and ch <= '9') or
            ch == '+' or ch == '/';
        if (!ok) return false;
    }
    return true;
}

/// Parse one `from <ip-or-cidr>` line. Multiple lines accumulate.
/// Value must be a single token (no spaces); use one directive per
/// source network.
fn parseFrom(allocator: std.mem.Allocator, user: *UserBuilder, value: []const u8) Error!void {
    const token = std.mem.trim(u8, value, " \t");
    if (token.len == 0) return error.InvalidFrom;
    if (std.mem.indexOfAny(u8, token, " \t") != null) return error.InvalidFrom;
    const cidr = netmatch.parseCidr(token) catch return error.InvalidFrom;
    try user.from.append(allocator, cidr);
}

fn parseAllowRule(allocator: std.mem.Allocator, user: *UserBuilder, value: []const u8) Error!void {
    var parts = std.mem.tokenizeAny(u8, value, " \t");
    const pattern = parts.next() orelse return error.MissingRulePattern;

    var permissions = PermissionSet.initEmpty();
    var saw_permission = false;
    while (parts.next()) |token| {
        if (std.mem.eql(u8, token, "read")) {
            // v0.4.0 simplification: `read` is now a superset of
            // `list`. The asymmetry it replaced was confusing —
            // `allow X read` without `list` meant "can download
            // known names but can't `ls`," which is a
            // security-through-obscurity-coded pattern that real
            // partner workflows almost never want. So the
            // recommended `read` verb now grants both
            // SSH_FXP_OPEN(read)/STAT/LSTAT AND OPENDIR/READDIR
            // — what most operators meant when they wrote `read`
            // anyway. The narrower `list` verb still exists
            // (advanced/legacy use case: enumeration without
            // download) but is no longer needed in everyday configs.
            permissions.insert(.read);
            permissions.insert(.list);
        } else if (std.mem.eql(u8, token, "add")) {
            // `add` is a compound verb that grants every "create-or-modify-
            // by-name" operation: file upload, directory creation, and rename
            // of either kind. Symmetric with `remove` (which already covers
            // both file unlink AND rmdir via policy.permissionFor). The
            // granular verbs (`write`, `mkdir`, `rename`) remain valid for
            // operators who genuinely need that distinction (e.g. an
            // immutable-receive workflow that allows uploads but no renames).
            permissions.insert(.write);
            permissions.insert(.mkdir);
            permissions.insert(.rename);
        } else if (std.mem.eql(u8, token, "full")) {
            // `full` = read + add + remove. The everyday three-verb
            // pattern (`read | add | remove`) collapses to a single
            // word for operators who want partners to have complete
            // access to a directory subtree. Equivalent to writing
            // out all six granular verbs but reads as a single
            // intent. NOT a default — operators must opt in
            // explicitly per path; the deny-by-default floor is
            // unchanged.
            permissions.insert(.read);
            permissions.insert(.list);
            permissions.insert(.write);
            permissions.insert(.mkdir);
            permissions.insert(.rename);
            permissions.insert(.remove);
        } else {
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

    // Bare `0` is the documented sentinel for "disabled" (idle-timeout,
    // reload-interval) and means the same thing in any unit — special-
    // cased here so operators don't have to write `0s`.
    if (std.mem.eql(u8, value, "0")) return 0;

    // PLAN §6.2: any non-zero duration requires a unit suffix
    // (`ms`, `s`, `m`, `h`). A bare number is ambiguous (operators
    // expect seconds; the implementation used to treat it as
    // milliseconds) so we reject it rather than guess.
    if (std.mem.endsWith(u8, value, "ms")) {
        return std.fmt.parseUnsigned(u64, value[0 .. value.len - 2], 10) catch error.InvalidDuration;
    }
    if (std.mem.endsWith(u8, value, "s")) {
        const seconds = std.fmt.parseUnsigned(u64, value[0 .. value.len - 1], 10) catch return error.InvalidDuration;
        return seconds * 1000;
    }
    if (std.mem.endsWith(u8, value, "m")) {
        const minutes = std.fmt.parseUnsigned(u64, value[0 .. value.len - 1], 10) catch return error.InvalidDuration;
        return minutes * 60 * 1000;
    }
    if (std.mem.endsWith(u8, value, "h")) {
        const hours = std.fmt.parseUnsigned(u64, value[0 .. value.len - 1], 10) catch return error.InvalidDuration;
        return hours * 60 * 60 * 1000;
    }
    return error.InvalidDuration;
}

fn dupNonEmpty(allocator: std.mem.Allocator, value: []const u8) Error![]const u8 {
    if (value.len == 0) return error.InvalidConfig;
    return allocator.dupe(u8, value);
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
    // v0.7.0: `partner-root <pr>` derives a user root by joining
    // `<pr>/<user-name>` (see the user-finalize loop in `parse`).
    // Reject the two filesystem-reserved component names that
    // would let a hostile config name escape the partner-root:
    //
    //   - `.`  → derived root is `<pr>/.` ≡ `<pr>` (collides with
    //            other partners' roots, breaks isolation)
    //   - `..` → derived root is `<pr>/..` (escapes partner-root)
    //
    // We also reject names that *start* with `.` so dotfile-style
    // names that confuse listing tools and obscure ops dashboards
    // don't sneak through. None of these were valid as a real
    // username anyway (POSIX `.` and `..` are reserved in every
    // directory). Doing the check at parse time makes the bug
    // unreachable from validateSemantic regardless of whether
    // partner-root is in use.
    if (name.len == 0) return false;
    if (name[0] == '.') return false;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
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
        \\  auth $argon2id$v=19$m=65536,t=3,p=4$xxxxxxxxxxxx$yyyyyyyyyyyy
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

test "parse: 'add' verb expands to write+mkdir+rename" {
    const text =
        \\server
        \\  listen 127.0.0.1:2222
        \\  host-key /tmp/zift_host_ed25519
        \\  log stderr
        \\
        \\user alice
        \\  auth $argon2id$v=19$m=65536,t=3,p=4$xxxxxxxxxxxx$yyyyyyyyyyyy
        \\  root /tmp/zift/alice
        \\  allow /pending read list add remove
        \\
    ;
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();

    const alice = cfg.findUser("alice").?;
    try std.testing.expectEqual(@as(usize, 1), alice.rules.len);
    const rule = alice.rules[0];
    try std.testing.expectEqualStrings("/pending", rule.pattern);
    // `add` should have unfolded into the granular trio. `read | list |
    // add | remove` ⇒ {read, list, write, mkdir, rename, remove}. If
    // someone "simplifies" the parser to alias add↔write only, this
    // test catches it (mkdir + rename would go missing).
    try std.testing.expect(rule.permissions.contains(.read));
    try std.testing.expect(rule.permissions.contains(.list));
    try std.testing.expect(rule.permissions.contains(.write));
    try std.testing.expect(rule.permissions.contains(.mkdir));
    try std.testing.expect(rule.permissions.contains(.rename));
    try std.testing.expect(rule.permissions.contains(.remove));
}

test "parse: 'read' is now a superset of 'list' (v0.4.0)" {
    // `read` should grant both `.read` (open-for-read, stat) AND
    // `.list` (readdir). This closes the v0.3.x asymmetry where
    // `allow X read` would let a partner `get` known filenames but
    // refuse `ls`. If a future refactor forgets the `.list` insert,
    // this test catches it.
    const text =
        \\server
        \\  listen 127.0.0.1:2222
        \\  host-key /tmp/zift_host_ed25519
        \\  log stderr
        \\
        \\user alice
        \\  auth $argon2id$v=19$m=65536,t=3,p=4$xxxxxxxxxxxx$yyyyyyyyyyyy
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
    // But `read` should NOT silently grant any mutation.
    try std.testing.expect(!rule.permissions.contains(.write));
    try std.testing.expect(!rule.permissions.contains(.mkdir));
    try std.testing.expect(!rule.permissions.contains(.rename));
    try std.testing.expect(!rule.permissions.contains(.remove));
}

test "parse: bare 'list' keeps its narrow v0.3.x meaning" {
    // `list` alone grants only `.list` — no `.read`, no download.
    // This preserves the rare but valid "see filenames but can't
    // download" workflow (e.g. tokenized-name delivery) and
    // ensures pre-v0.4.0 configs that wrote `allow X list`
    // intending "metadata only" don't silently gain download
    // capability after the upgrade.
    const text =
        \\server
        \\  listen 127.0.0.1:2222
        \\  host-key /tmp/zift_host_ed25519
        \\  log stderr
        \\
        \\user alice
        \\  auth $argon2id$v=19$m=65536,t=3,p=4$xxxxxxxxxxxx$yyyyyyyyyyyy
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
        \\  auth $argon2id$v=19$m=65536,t=3,p=4$xxxxxxxxxxxx$yyyyyyyyyyyy
        \\  root /tmp/zift/alice
        \\  allow /workspace full
        \\
    ;
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    const alice = cfg.findUser("alice").?;
    const rule = alice.rules[0];
    // All six granular permissions should be set.
    try std.testing.expect(rule.permissions.contains(.read));
    try std.testing.expect(rule.permissions.contains(.list));
    try std.testing.expect(rule.permissions.contains(.write));
    try std.testing.expect(rule.permissions.contains(.mkdir));
    try std.testing.expect(rule.permissions.contains(.rename));
    try std.testing.expect(rule.permissions.contains(.remove));
}

test "parse: 'add' alongside granular verbs is idempotent" {
    // `add` + a granular verb that's already in `add`'s expansion should
    // just OR cleanly — no error, no surprise.
    const text =
        \\server
        \\  listen 127.0.0.1:2222
        \\  host-key /tmp/zift_host_ed25519
        \\  log stderr
        \\
        \\user alice
        \\  auth $argon2id$v=19$m=65536,t=3,p=4$xxxxxxxxxxxx$yyyyyyyyyyyy
        \\  root /tmp/zift/alice
        \\  allow /pending read list add write rename
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

// Reused fixture for tests below: a syntactically valid PHC string with
// parameters inside the policy envelope. The salt and hash bodies are not
// real Argon2id outputs; the parser only validates structure, not crypto.
const valid_test_phc = "$argon2id$v=19$m=65536,t=3,p=1$xxxxxxxxxxxx$yyyyyyyyyyyy";

test "duplicate user is rejected" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth " ++ valid_test_phc ++ "\n  root /tmp/a\n\n" ++
        "user ally\n  auth " ++ valid_test_phc ++ "\n  root /tmp/b\n";
    try std.testing.expectError(error.DuplicateUser, parse(std.testing.allocator, text));
}

test "publish-mode: defaults to 0o660 when not specified" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth " ++ valid_test_phc ++ "\n  root /tmp/a\n";
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
        .{ "", @as(?u32, null) },
    };
    inline for (cases) |case| {
        const text =
            "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n  publish-mode " ++ case.@"0" ++ "\n\n" ++
            "user ally\n  auth " ++ valid_test_phc ++ "\n  root /tmp/a\n";
        if (case.@"1") |expected| {
            var cfg = try parse(std.testing.allocator, text);
            defer cfg.deinit();
            try std.testing.expectEqual(expected, cfg.server.publish_mode);
        } else {
            try std.testing.expectError(error.InvalidConfig, parse(std.testing.allocator, text));
        }
    }
}

test "mkdir-mode: defaults to 0o2770 when not specified" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth " ++ valid_test_phc ++ "\n  root /tmp/a\n";
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
        .{ "", @as(?u32, null) },
    };
    inline for (cases) |case| {
        const text =
            "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n  mkdir-mode " ++ case.@"0" ++ "\n\n" ++
            "user ally\n  auth " ++ valid_test_phc ++ "\n  root /tmp/a\n";
        if (case.@"1") |expected| {
            var cfg = try parse(std.testing.allocator, text);
            defer cfg.deinit();
            try std.testing.expectEqual(expected, cfg.server.mkdir_mode);
        } else {
            try std.testing.expectError(error.InvalidConfig, parse(std.testing.allocator, text));
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

test "auth $... rejected when not argon2id" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth $bcrypt$something\n  root /tmp/a\n";
    try std.testing.expectError(error.PasswordHashNotArgon2id, parse(std.testing.allocator, text));
}

test "auth $... rejected when phc malformed" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth $argon2id$broken\n  root /tmp/a\n";
    try std.testing.expectError(error.PasswordHashMalformed, parse(std.testing.allocator, text));
}

test "auth $... rejected when memory below envelope" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth $argon2id$v=19$m=4096,t=3,p=1$xxxxxxxxxxxx$yyyyyyyyyyyy\n  root /tmp/a\n";
    try std.testing.expectError(error.PasswordMemoryOutOfPolicy, parse(std.testing.allocator, text));
}

test "auth $... rejected when memory above envelope" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth $argon2id$v=19$m=524288,t=3,p=1$xxxxxxxxxxxx$yyyyyyyyyyyy\n  root /tmp/a\n";
    try std.testing.expectError(error.PasswordMemoryOutOfPolicy, parse(std.testing.allocator, text));
}

test "auth $... rejected when passes below envelope" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth $argon2id$v=19$m=65536,t=1,p=1$xxxxxxxxxxxx$yyyyyyyyyyyy\n  root /tmp/a\n";
    try std.testing.expectError(error.PasswordPassesOutOfPolicy, parse(std.testing.allocator, text));
}

test "auth $... rejected when parallelism above envelope" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth $argon2id$v=19$m=65536,t=3,p=8$xxxxxxxxxxxx$yyyyyyyyyyyy\n  root /tmp/a\n";
    try std.testing.expectError(error.PasswordParallelismOutOfPolicy, parse(std.testing.allocator, text));
}

test "auth $... accepted at envelope boundaries" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth $argon2id$v=19$m=262144,t=8,p=4$xxxxxxxxxxxx$yyyyyyyyyyyy\n  root /tmp/a\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
}

// Real-shape OpenSSH ed25519 wire blob: 32-byte length-prefixed
// "ssh-ed25519" string + 32-byte length-prefixed key material.
// 68 base64 chars = 51 bytes decoded.
const valid_ed25519_blob = "AAAAC3NzaC1lZDI1NTE5AAAAIPHj7SuD0g1xj0ZqLELSQ7Ux8RSjGlYBhVMxbfBhPXMd";

// 96 base64 chars = 72 bytes decoded; long enough to look like an
// ECDSA P-256 wire blob.
const valid_ecdsa_blob =
    "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPHj7SuD0g1xj0ZqLELSQ7Ux8RSjGlYBhVMxbfBhPXMd";

// Public-key file parsing is now exercised through `parsePublicKeyLine`
// directly. The full file-loading round-trip (file open + first-line
// extraction + parsing) is covered by the integration tests under
// test/cases/ which stand up real key files.

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

test "auth $... real argon2id phc accepted (PHC base64 has no padding)" {
    // 22-char salt + 43-char hash — both `len % 4 != 0`, neither has
    // `=` padding. RFC 9106 / PHC §B explicitly forbids padding so the
    // strict OpenSSH-style validator must NOT be applied here.
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth $argon2id$v=19$m=65536,t=3,p=1" ++
        "$bSki6LMKgGqnScrLG0fo/2hpMLj8InvvY+irrZKEsS4" ++
        "$0HMWjuvAdHzgT2+GA1DdgQL5fdDrC4X0GEezlPDjimQ\n" ++
        "  root /tmp/a\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
}

test "auth $... phc with `=` padding in salt rejected" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth $argon2id$v=19$m=65536,t=3,p=1$xxxx==xx$yyyyyyyyyyyy\n" ++
        "  root /tmp/a\n";
    try std.testing.expectError(error.PasswordHashMalformed, parse(std.testing.allocator, text));
}

test "auth $... phc with non-alphabet char in hash rejected" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth $argon2id$v=19$m=65536,t=3,p=1$xxxxxxxxxxxx$yyyy!yyyyyyy\n" ++
        "  root /tmp/a\n";
    try std.testing.expectError(error.PasswordHashMalformed, parse(std.testing.allocator, text));
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
        "  auth " ++ valid_test_phc ++ "\n" ++
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
        "  auth " ++ valid_test_phc ++ "\n" ++
        "  from 10.0.0.0/99\n" ++
        "  root /tmp/a\n";
    try std.testing.expectError(error.InvalidFrom, parse(std.testing.allocator, text));
}

test "two PHC auth lines for one user are rejected" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n" ++
        "  auth " ++ valid_test_phc ++ "\n" ++
        "  auth " ++ valid_test_phc ++ "\n" ++
        "  root /tmp/a\n";
    try std.testing.expectError(error.DuplicatePassword, parse(std.testing.allocator, text));
}

test "duplicate-password check fires before PHC validation" {
    // A second `$...` auth line with malformed-or-non-argon2id PHC
    // should still report `DuplicatePassword`, not the PHC-shape
    // error. The duplicate is the more actionable operator
    // diagnostic; the malformed-second-line is a downstream
    // consequence of the duplicate.
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n" ++
        "  auth " ++ valid_test_phc ++ "\n" ++
        "  auth $bcrypt$something\n" ++
        "  root /tmp/a\n";
    try std.testing.expectError(error.DuplicatePassword, parse(std.testing.allocator, text));
}

test "partner-root '/' derives single-slash user root (POSIX-safe)" {
    // The lone-`/` partner-root is allowed but the derived user
    // root must NOT be `//ally` — POSIX leaves leading-`//` paths
    // implementation-defined and we don't want a jail boundary
    // depending on that. Joiner special-cases this.
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n  partner-root /\n\n" ++
        "user ally\n  auth " ++ valid_test_phc ++ "\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqualStrings("/ally", cfg.findUser("ally").?.root);
    try std.testing.expectEqualStrings("/", cfg.server.partner_root.?);
}

test "auth value with neither $ nor / leading byte rejected" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth wat\n  root /tmp/a\n";
    try std.testing.expectError(error.InvalidAuth, parse(std.testing.allocator, text));
}

test "auth value with leading byte other than '$' or '/' rejected" {
    // The dispatch byte must be one of the two well-known leading
    // bytes; anything else hits the catch-all `error.InvalidAuth`
    // arm in `parseAuth` regardless of how plausible the rest of
    // the value looks. Tests `./relative`, plus a bare token, plus
    // an empty value.
    const inputs = [_][]const u8{
        "./relative",
        "wat",
        "",
    };
    for (inputs) |val| {
        const text = try std.fmt.allocPrint(
            std.testing.allocator,
            "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
                "user ally\n  auth {s}\n  root /tmp/a\n",
            .{val},
        );
        defer std.testing.allocator.free(text);
        const got = parse(std.testing.allocator, text);
        try std.testing.expect(got == error.InvalidAuth or got == error.InvalidConfig);
    }
}

test "username '..' rejected (partner-root path-traversal defense)" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n  partner-root /home/zift\n\n" ++
        "user ..\n  auth " ++ valid_test_phc ++ "\n";
    try std.testing.expectError(error.InvalidUserName, parse(std.testing.allocator, text));
}

test "username '.' rejected (partner-root path-traversal defense)" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n  partner-root /home/zift\n\n" ++
        "user .\n  auth " ++ valid_test_phc ++ "\n";
    try std.testing.expectError(error.InvalidUserName, parse(std.testing.allocator, text));
}

test "username with leading dot rejected" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user .hidden\n  auth " ++ valid_test_phc ++ "\n  root /tmp/a\n";
    try std.testing.expectError(error.InvalidUserName, parse(std.testing.allocator, text));
}

test "password directive removed: clear migration error" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  password " ++ valid_test_phc ++ "\n  root /tmp/a\n";
    try std.testing.expectError(error.PasswordDirectiveRemoved, parse(std.testing.allocator, text));
}

test "key directive removed: clear migration error" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth " ++ valid_test_phc ++ "\n  key ssh-ed25519 " ++ valid_ed25519_blob ++ "\n  root /tmp/a\n";
    try std.testing.expectError(error.KeyDirectiveRemoved, parse(std.testing.allocator, text));
}

test "partner-root: trailing slash trimmed before deriving user root" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n  partner-root /home/zift/\n\n" ++
        "user ally\n  auth " ++ valid_test_phc ++ "\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    // Trimmed `partner-root` stored as `/home/zift`; user root joined
    // as `/home/zift/ally` — no double-slash.
    try std.testing.expectEqualStrings("/home/zift", cfg.server.partner_root.?);
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
        "user override\n  auth " ++ valid_test_phc ++ "\n  root /custom/path\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqualStrings("/custom/path", cfg.findUser("override").?.root);
}

test "partner-root: missing user root defaults to <partner-root>/<user>" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n  partner-root /home/zift\n\n" ++
        "user ally\n  auth " ++ valid_test_phc ++ "\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqualStrings("/home/zift/ally", cfg.findUser("ally").?.root);
    try std.testing.expectEqualStrings("/home/zift", cfg.server.partner_root.?);
}

test "partner-root: unset, missing user root still rejected" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth " ++ valid_test_phc ++ "\n";
    try std.testing.expectError(error.MissingRoot, parse(std.testing.allocator, text));
}

test "partner-root: relative path rejected at parse time" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n  partner-root home/zift\n\n" ++
        "user ally\n  auth " ++ valid_test_phc ++ "\n";
    try std.testing.expectError(error.InvalidConfig, parse(std.testing.allocator, text));
}

test "server defaults applied when properties omitted" {
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqual(@as(u64, 300_000), cfg.server.idle_timeout_ms);
    try std.testing.expectEqual(@as(u32, 128), cfg.server.max_connections);
    // Pre-auth cap defaults to 0 = no separate cap (preserves the
    // behavior operators see when they don't tune this knob).
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
    // The docs say `0` is the "no separate cap" value. Operators may
    // set it explicitly to document the choice rather than omit the
    // directive. This test pins the parser's acceptance of that form.
    const text =
        "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n" ++
        "  max-connections 64\n  max-unauth-connections 0\n";
    var cfg = try parse(std.testing.allocator, text);
    defer cfg.deinit();
    try std.testing.expectEqual(@as(u32, 0), cfg.server.max_unauth_connections);
}

// The pure-numeric semantic check is called from `validateSemantic`
// before any I/O. We exercise it directly here so unit tests don't
// need a `std.Io` to assert the right rejection behavior.

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
    // The diagnostic formatter in `validateSemantic` writes the two
    // cap values into a `[16]u8` buffer via `bufPrint("{d}", ...)`.
    // 4_294_967_295 (u32 max) is 10 digits and fits easily, but
    // pinning the boundary value here protects us from a future
    // refactor that picks too small a buffer.
    var cfg = makeNumericTestConfig(.{
        .max_total = 64,
        .max_unauth = std.math.maxInt(u32),
    });
    defer cfg.deinit();
    try std.testing.expectError(error.UnauthCapExceedsTotal, validatePureNumeric(&cfg));
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
            .partner_root = null,
        },
        .users = &.{},
        .arena = std.heap.ArenaAllocator.init(std.testing.allocator),
    };
}
