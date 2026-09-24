//! The partner jail: virtual path normalization and descriptor-relative
//! resolution under a partner root.
//!
//! Paths are resolved one component at a time from the root fd with
//! NOFOLLOW, so no symlink can leave the jail or alias a denied path.
//! `<root>/.zift` is reserved (case-insensitively) for Zift and the
//! operator and is unreachable over SFTP.

const std = @import("std");
const listing = @import("listing.zig");

pub const Error = error{
    InvalidPath,
    /// A `.zift` component (see `isReservedComponent`).
    Reserved,
    OutOfMemory,
    PathTooLong,
    PathTraversal,
    /// `<root>/.zift` is not a real directory (e.g. a symlink).
    NamespaceDirCorrupt,
    /// `<root>/.zift` grants group-write or any other-access.
    NamespaceDirUnsafe,
    /// `<root>/.zift/staging` is not a real directory.
    StagingDirCorrupt,
    /// `<root>/.zift/staging` grants any group or other access.
    StagingDirUnsafe,
} || std.Io.Dir.RealPathFileAllocError || std.Io.Dir.OpenError;

/// Limit on the raw client path, checked before normalization.
pub const max_virtual_path_bytes: usize = 4096;

pub const Vfs = struct {
    root: [:0]const u8,

    pub fn init(io: std.Io, allocator: std.mem.Allocator, root_path: []const u8) Error!Vfs {
        // config guarantees an absolute root; realPathFileAbsoluteAlloc asserts it.
        const canonical = try std.Io.Dir.realPathFileAbsoluteAlloc(io, root_path, allocator);
        return .{ .root = canonical };
    }

    pub fn deinit(self: *Vfs, allocator: std.mem.Allocator) void {
        allocator.free(self.root);
        self.* = undefined;
    }

    /// Open, creating if needed, `<root>/.zift/staging/` (caller closes).
    /// See `PrivateDir` for what each level must be; a pre-existing
    /// `.zift` keeps its owner and mode.
    pub fn openStagingDir(self: Vfs, io: std.Io) !std.Io.Dir {
        return self.openStaging(io, true);
    }

    /// Staging dir if it exists and passes the checks; never creates it.
    pub fn tryOpenExistingStagingDir(self: Vfs, io: std.Io) ?std.Io.Dir {
        return self.openStaging(io, false) catch null;
    }

    fn openStaging(self: Vfs, io: std.Io, create: bool) !std.Io.Dir {
        var root = try self.openRoot(io, false);
        defer root.close(io);
        var ns_dir = try openPrivateDir(io, root, namespace_dir, create);
        defer ns_dir.close(io);
        return openPrivateDir(io, ns_dir, staging_dir, create);
    }

    /// The root itself, NOFOLLOW like every step below it. The root is
    /// canonical, so this only keeps a swapped-in symlink from counting.
    pub fn openRoot(self: Vfs, io: std.Io, iterate: bool) std.Io.Dir.OpenError!std.Io.Dir {
        return std.Io.Dir.openDirAbsolute(io, self.root, .{ .iterate = iterate, .follow_symlinks = false });
    }

    /// Length, no C0 control or DEL bytes, and valid UTF-8 (the audit
    /// line must stay valid JSON).
    pub fn validateVirtualPath(virtual_path: []const u8) error{ PathTooLong, InvalidPath }!void {
        if (virtual_path.len > max_virtual_path_bytes) return error.PathTooLong;
        for (virtual_path) |b| {
            if (b < 0x20 or b == 0x7F) return error.InvalidPath;
        }
        if (!std.unicode.utf8ValidateSlice(virtual_path)) return error.InvalidPath;
    }

    pub fn containsRealPath(self: Vfs, real_path: []const u8) bool {
        return isInsideRoot(self.root, real_path);
    }

    pub fn verifyFile(self: Vfs, io: std.Io, file: std.Io.File) Error!void {
        var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const len = try file.realPath(io, &buf);
        if (!self.containsRealPath(buf[0..len])) return error.PathTraversal;
    }

    pub fn verifyDir(self: Vfs, io: std.Io, dir: std.Io.Dir) Error!void {
        var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const len = try dir.realPath(io, &buf);
        if (!self.containsRealPath(buf[0..len])) return error.PathTraversal;
    }

    /// Walk from the canonical root one NOFOLLOW component at a time.
    /// This is both the jail and the policy boundary: no symlink, even
    /// one inside the root, can give a denied path an allowed spelling.
    /// Caller owns the result.
    pub fn openVirtualDir(
        self: Vfs,
        io: std.Io,
        allocator: std.mem.Allocator,
        virtual_path: []const u8,
        iterate: bool,
    ) Error!std.Io.Dir {
        const normalized = try normalizeVirtualPath(allocator, virtual_path);
        defer allocator.free(normalized);

        var current = try self.openRoot(io, iterate);
        errdefer current.close(io);

        var parts = std.mem.tokenizeScalar(u8, normalized, '/');
        while (parts.next()) |part| {
            const next = current.openDir(io, part, .{
                .iterate = iterate,
                .follow_symlinks = false,
            }) catch |err| switch (err) {
                error.SymLinkLoop => return error.PathTraversal,
                // Linux also reports a symlink as ENOTDIR here; only a
                // real non-directory is the honest "no such path".
                error.NotDir => {
                    const info = listing.statAt(current.handle, part) catch return error.PathTraversal;
                    return if (info.mode & listing.S_IFMT == listing.S_IFLNK) error.PathTraversal else error.NotDir;
                },
                else => |e| return e,
            };
            current.close(io);
            current = next;
        }

        try self.verifyDir(io, current);
        return current;
    }

    /// The parent dir fd (same walk as `openVirtualDir`) and a copied
    /// basename, for *at calls on the final component.
    pub fn openVerifiedParent(
        self: Vfs,
        io: std.Io,
        allocator: std.mem.Allocator,
        virtual_path: []const u8,
    ) Error!ParentResolution {
        const normalized = try normalizeVirtualPath(allocator, virtual_path);
        defer allocator.free(normalized);
        if (std.mem.eql(u8, normalized, "/")) return error.InvalidPath;

        const slash = std.mem.lastIndexOfScalar(u8, normalized, '/') orelse unreachable;
        const parent_virtual = if (slash == 0) "/" else normalized[0..slash];
        // Normalized, so the basename is never empty, `.`, or `..`.
        const base_part = normalized[slash + 1 ..];

        const dir = try self.openVirtualDir(io, allocator, parent_virtual, false);
        errdefer dir.close(io);

        const base_owned = try allocator.dupe(u8, base_part);
        return .{ .parent = dir, .base = base_owned };
    }
};

pub const ParentResolution = struct {
    parent: std.Io.Dir,
    base: []u8,

    pub fn deinit(self: *ParentResolution, io: std.Io, allocator: std.mem.Allocator) void {
        self.parent.close(io);
        allocator.free(self.base);
        self.* = undefined;
    }
};

/// Reserved in every virtual path; see `isReservedComponent`.
pub const namespace_dir_name: []const u8 = ".zift";

/// Former staging dir, unused but still reserved and hidden so a
/// partner cannot create it where an operator may still have one.
pub const legacy_staging_dir_name: []const u8 = ".zift-staging";

/// True if anything (lstat) exists at `<root_path>/.zift-staging`, for
/// the startup warning. False on any error.
pub fn legacyStagingDirExists(io: std.Io, root_path: []const u8) bool {
    var root = std.Io.Dir.openDirAbsolute(io, root_path, .{}) catch return false;
    defer root.close(io);
    _ = listing.statAt(root.handle, legacy_staging_dir_name) catch return false;
    return true;
}

/// A reserved directory Zift keeps under the partner root. Both levels
/// must be real directories, never symlinks that could move staging out
/// of the jail. `.zift` holds `staging` (the daemon's) and anything else
/// the operator puts there: no group-write or other access, or a group
/// member could swap `staging`, and owned by the daemon or root.
/// `staging` holds in-flight uploads: no group or other access at all,
/// and owned by the daemon.
const PrivateDir = struct {
    name: []const u8,
    /// For a new directory; set after create because createDir honors umask.
    mode: std.posix.mode_t,
    forbidden: u32,
    root_may_own: bool,
    corrupt: Error,
    unsafe: Error,
};

const namespace_dir: PrivateDir = .{
    .name = namespace_dir_name,
    .mode = 0o750,
    .forbidden = 0o027,
    .root_may_own = true,
    .corrupt = error.NamespaceDirCorrupt,
    .unsafe = error.NamespaceDirUnsafe,
};

const staging_dir: PrivateDir = .{
    .name = "staging",
    .mode = 0o700,
    .forbidden = 0o077,
    .root_may_own = false,
    .corrupt = error.StagingDirCorrupt,
    .unsafe = error.StagingDirUnsafe,
};

/// Open `spec` under `parent`, creating it first if `create`. The open is
/// NOFOLLOW and the checks run on the opened fd, so nothing swapped in
/// between can pass them.
fn openPrivateDir(io: std.Io, parent: std.Io.Dir, spec: PrivateDir, create: bool) !std.Io.Dir {
    var created = false;
    if (create) {
        if (parent.createDir(io, spec.name, .fromMode(spec.mode))) |_| {
            created = true;
        } else |err| if (err != error.PathAlreadyExists) return err;
    }
    var dir = parent.openDir(io, spec.name, .{ .iterate = true, .follow_symlinks = false }) catch |err| switch (err) {
        error.SymLinkLoop, error.NotDir => return spec.corrupt,
        else => |e| return e,
    };
    errdefer dir.close(io);
    if (created) try dir.setPermissions(io, .fromMode(spec.mode));

    const info = try listing.statFd(dir.handle);
    if (info.mode & listing.S_IFMT != listing.S_IFDIR) return spec.corrupt;
    if (info.mode & spec.forbidden != 0) return spec.unsafe;
    if (info.uid != std.c.geteuid() and !(spec.root_may_own and info.uid == 0)) return spec.unsafe;
    return dir;
}

/// `.zift` or `.zift-staging`, ASCII case-insensitively: on APFS/HFS+
/// `/.ZIFT` is the same directory.
pub fn isReservedComponent(part: []const u8) bool {
    return std.ascii.eqlIgnoreCase(part, namespace_dir_name) or
        std.ascii.eqlIgnoreCase(part, legacy_staging_dir_name);
}

/// Normalize into `out` (≥ `max_virtual_path_bytes + 1` bytes): validate
/// bytes, drop `.` and empty components, resolve `..` (never above the
/// root), and refuse a reserved component anywhere. The result, which
/// gains a leading `/` if the input lacked one, is itself held to
/// `max_virtual_path_bytes`, so it is always a valid input again.
pub fn normalizeVirtualInto(
    virtual_path: []const u8,
    out: []u8,
) error{ PathTooLong, InvalidPath, PathTraversal, Reserved }![]u8 {
    std.debug.assert(out.len >= max_virtual_path_bytes + 1);
    try Vfs.validateVirtualPath(virtual_path);

    // Offset of each depth's leading '/', so `..` is an O(1) truncate.
    var starts: [max_virtual_path_bytes / 2 + 2]usize = undefined;
    var depth: usize = 0;
    var len: usize = 0;

    var iter = std.mem.tokenizeScalar(u8, virtual_path, '/');
    while (iter.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".")) continue;
        if (std.mem.eql(u8, part, "..")) {
            if (depth == 0) return error.PathTraversal;
            depth -= 1;
            len = starts[depth];
            continue;
        }
        if (isReservedComponent(part)) return error.Reserved;
        starts[depth] = len;
        depth += 1;
        out[len] = '/';
        len += 1;
        @memcpy(out[len..][0..part.len], part);
        len += part.len;
    }

    if (len == 0) {
        out[0] = '/';
        return out[0..1];
    }
    if (len > max_virtual_path_bytes) return error.PathTooLong;
    return out[0..len];
}

fn normalizeVirtualPath(allocator: std.mem.Allocator, virtual_path: []const u8) Error![]u8 {
    var buf: [max_virtual_path_bytes + 2]u8 = undefined;
    const normalized = try normalizeVirtualInto(virtual_path, &buf);
    return allocator.dupe(u8, normalized);
}

/// `path` is `root` or below it at a component boundary (`/foobar` is
/// not inside `/foo`; everything absolute is inside `/`).
pub fn isInsideRoot(root: []const u8, path: []const u8) bool {
    if (!std.mem.startsWith(u8, path, root)) return false;
    return path.len == root.len or path[root.len] == '/' or std.mem.endsWith(u8, root, "/");
}

fn testNormalize(path: []const u8) ![]const u8 {
    const S = struct {
        var buf: [max_virtual_path_bytes + 2]u8 = undefined;
    };
    return normalizeVirtualInto(path, &S.buf);
}

test "normalize virtual path" {
    const normalized = try testNormalize("/pending//./inbox/file.txt");
    try std.testing.expectEqualStrings("/pending/inbox/file.txt", normalized);
}

test "normalize rejects traversal above root" {
    try std.testing.expectError(
        error.PathTraversal,
        testNormalize("/../../etc/passwd"),
    );
}

test "normalize rejects nul byte" {
    try std.testing.expectError(
        error.InvalidPath,
        testNormalize("/pending/a\x00b"),
    );
}

test "normalize rejects /.zift namespace anywhere in path" {
    try std.testing.expectError(
        error.Reserved,
        testNormalize("/.zift"),
    );
    try std.testing.expectError(
        error.Reserved,
        testNormalize("/.zift/staging/abc123"),
    );
    try std.testing.expectError(
        error.Reserved,
        testNormalize("/.zift/notes.md"),
    );
    // Mid-path too.
    try std.testing.expectError(
        error.Reserved,
        testNormalize("/pending/.zift/something"),
    );
    try std.testing.expectError(
        error.Reserved,
        testNormalize("/.zift-staging"),
    );
    try std.testing.expectError(
        error.Reserved,
        testNormalize("/.zift-staging/legacy.dat"),
    );
    try std.testing.expectError(
        error.Reserved,
        testNormalize("/pending/.zift-staging/something"),
    );
    // Non-reserved dotfiles are fine.
    const ok = try testNormalize("/pending/.cache/foo");
    try std.testing.expectEqualStrings("/pending/.cache/foo", ok);
}

test "reserved .zift component is case-insensitive" {
    for ([_][]const u8{ "/.ZIFT/staging/x", "/.Zift/notes", "/pending/.ZIFT-STAGING/x" }) |p| {
        try std.testing.expectError(error.Reserved, testNormalize(p));
    }
    try std.testing.expect(isReservedComponent(".ZIFT"));
    try std.testing.expect(isReservedComponent(".Zift"));
    try std.testing.expect(!isReservedComponent(".ziftfoo"));
}

test "normalizeVirtualInto resolves .. before authorization" {
    var out: [max_virtual_path_bytes + 2]u8 = undefined;
    const cases = [_]struct { in: []const u8, want: []const u8 }{
        .{ .in = "/pending/../secret", .want = "/secret" },
        .{ .in = "/pending/x.exe/", .want = "/pending/x.exe" },
        .{ .in = "//a//b/./c", .want = "/a/b/c" },
        .{ .in = "/", .want = "/" },
        .{ .in = "/./", .want = "/" },
        .{ .in = "/a/b/..", .want = "/a" },
    };
    for (cases) |case| {
        const got = try normalizeVirtualInto(case.in, &out);
        try std.testing.expectEqualStrings(case.want, got);
    }
    try std.testing.expectError(error.PathTraversal, normalizeVirtualInto("/a/../../b", &out));
}

test "normalized output never exceeds the input limit" {
    var out: [max_virtual_path_bytes + 2]u8 = undefined;
    const name = "a" ** (max_virtual_path_bytes - 1);
    try std.testing.expectEqual(max_virtual_path_bytes, (try normalizeVirtualInto(name, &out)).len);
    try std.testing.expectEqual(max_virtual_path_bytes, (try normalizeVirtualInto("/" ++ name, &out)).len);
    // The added `/` would make it one byte too long.
    try std.testing.expectError(error.PathTooLong, normalizeVirtualInto(name ++ "a", &out));
}

test "isInsideRoot splits at component boundaries, and `/` holds everything" {
    try std.testing.expect(isInsideRoot("/srv/a", "/srv/a"));
    try std.testing.expect(isInsideRoot("/srv/a", "/srv/a/b"));
    try std.testing.expect(!isInsideRoot("/srv/a", "/srv/ab"));
    try std.testing.expect(!isInsideRoot("/srv/a", "/srv"));
    try std.testing.expect(isInsideRoot("/", "/"));
    try std.testing.expect(isInsideRoot("/", "/etc"));
    try std.testing.expect(isInsideRoot("/", "/etc/passwd"));
}

test "directory walk rejects symlinks inside the jail" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDir(std.testing.io, "root", .default_dir);
    try tmp.dir.symLink(std.testing.io, "/etc", "root/outside", .{});

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPathFile(std.testing.io, "root", &root_buf);

    var vfs = try Vfs.init(std.testing.io, std.testing.allocator, root_buf[0..root_len]);
    defer vfs.deinit(std.testing.allocator);

    try std.testing.expectError(error.PathTraversal, vfs.openVirtualDir(
        std.testing.io,
        std.testing.allocator,
        "/outside",
        true,
    ));
}

test "legacyStagingDirExists detects each entry type the operator might find" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPathFile(std.testing.io, ".", &root_buf);
    const root_path = root_buf[0..root_len];

    try std.testing.expect(!legacyStagingDirExists(std.testing.io, root_path));

    try tmp.dir.createDir(std.testing.io, ".zift-staging", .default_dir);
    try std.testing.expect(legacyStagingDirExists(std.testing.io, root_path));
    try tmp.dir.deleteDir(std.testing.io, ".zift-staging");

    // A dangling symlink counts.
    try tmp.dir.symLink(std.testing.io, "/tmp/somewhere", ".zift-staging", .{});
    try std.testing.expect(legacyStagingDirExists(std.testing.io, root_path));
    try tmp.dir.deleteFile(std.testing.io, ".zift-staging");

    {
        const f = try tmp.dir.createFile(std.testing.io, ".zift-staging", .{});
        f.close(std.testing.io);
    }
    try std.testing.expect(legacyStagingDirExists(std.testing.io, root_path));
    try tmp.dir.deleteFile(std.testing.io, ".zift-staging");

    try std.testing.expect(!legacyStagingDirExists(std.testing.io, root_path));
}

test "a file used as a directory is not found, not a traversal" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDir(std.testing.io, "root", .default_dir);
    (try tmp.dir.createFile(std.testing.io, "root/file.txt", .{})).close(std.testing.io);
    try tmp.dir.symLink(std.testing.io, "file.txt", "root/link", .{});

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPathFile(std.testing.io, "root", &root_buf);
    var vfs = try Vfs.init(std.testing.io, std.testing.allocator, root_buf[0..root_len]);
    defer vfs.deinit(std.testing.allocator);

    const io = std.testing.io;
    const gpa = std.testing.allocator;
    try std.testing.expectError(error.NotDir, vfs.openVerifiedParent(io, gpa, "/file.txt/x"));
    try std.testing.expectError(error.NotDir, vfs.openVirtualDir(io, gpa, "/file.txt", false));
    // A symlink stays a traversal whatever it points at.
    try std.testing.expectError(error.PathTraversal, vfs.openVerifiedParent(io, gpa, "/link/x"));
}

test "staging dir: created private, and refused when anything is off" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "root", .default_dir);
    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPathFile(io, "root", &root_buf);
    var vfs = try Vfs.init(io, std.testing.allocator, root_buf[0..root_len]);
    defer vfs.deinit(std.testing.allocator);

    // Missing: only openStagingDir creates it, at 0750 and 0700.
    try std.testing.expectEqual(null, vfs.tryOpenExistingStagingDir(io));
    (try vfs.openStagingDir(io)).close(io);
    try std.testing.expectEqual(@as(u32, 0o750), (try listing.statAt(tmp.dir.handle, "root/.zift")).mode & 0o7777);
    try std.testing.expectEqual(@as(u32, 0o700), (try listing.statAt(tmp.dir.handle, "root/.zift/staging")).mode & 0o7777);
    vfs.tryOpenExistingStagingDir(io).?.close(io);

    const Case = struct { mode: std.posix.mode_t, err: anyerror };
    for ([_]Case{
        .{ .mode = 0o770, .err = error.NamespaceDirUnsafe },
        .{ .mode = 0o755, .err = error.NamespaceDirUnsafe },
    }) |case| {
        try tmp.dir.setFilePermissions(io, "root/.zift", .fromMode(case.mode), .{});
        try std.testing.expectError(case.err, vfs.openStagingDir(io));
        try std.testing.expectEqual(null, vfs.tryOpenExistingStagingDir(io));
    }
    try tmp.dir.setFilePermissions(io, "root/.zift", .fromMode(0o750), .{});
    try tmp.dir.setFilePermissions(io, "root/.zift/staging", .fromMode(0o740), .{});
    try std.testing.expectError(error.StagingDirUnsafe, vfs.openStagingDir(io));

    // A symlink or a file where a directory belongs is corrupt.
    try tmp.dir.deleteDir(io, "root/.zift/staging");
    try tmp.dir.createDir(io, "elsewhere", .fromMode(0o700));
    try tmp.dir.symLink(io, "../../elsewhere", "root/.zift/staging", .{});
    try std.testing.expectError(error.StagingDirCorrupt, vfs.openStagingDir(io));
    try tmp.dir.deleteFile(io, "root/.zift/staging");
    try tmp.dir.deleteDir(io, "root/.zift");
    (try tmp.dir.createFile(io, "root/.zift", .{})).close(io);
    try std.testing.expectError(error.NamespaceDirCorrupt, vfs.openStagingDir(io));
    try tmp.dir.deleteFile(io, "root/.zift");
    try tmp.dir.symLink(io, "../elsewhere", "root/.zift", .{});
    try std.testing.expectError(error.NamespaceDirCorrupt, vfs.openStagingDir(io));
    try std.testing.expectEqual(null, vfs.tryOpenExistingStagingDir(io));
}

test "staging dir: another user's .zift or staging is refused" {
    // Only root can hand a directory to another user.
    if (std.c.geteuid() != 0) return error.SkipZigTest;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "root", .default_dir);
    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPathFile(io, "root", &root_buf);
    var vfs = try Vfs.init(io, std.testing.allocator, root_buf[0..root_len]);
    defer vfs.deinit(std.testing.allocator);
    (try vfs.openStagingDir(io)).close(io);

    var staging = try tmp.dir.openDir(io, "root/.zift/staging", .{});
    try staging.setOwner(io, 65534, null);
    staging.close(io);
    try std.testing.expectError(error.StagingDirUnsafe, vfs.openStagingDir(io));

    var ns = try tmp.dir.openDir(io, "root/.zift", .{});
    try ns.setOwner(io, 65534, null);
    ns.close(io);
    try std.testing.expectError(error.NamespaceDirUnsafe, vfs.openStagingDir(io));
}

test "openVerifiedParent rejects every parent symlink" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDir(std.testing.io, "root", .default_dir);
    // An inside target too: containment alone would let it alias `secret`.
    try tmp.dir.symLink(std.testing.io, "/etc", "root/escape", .{});
    try tmp.dir.createDir(std.testing.io, "root/secret", .default_dir);
    try tmp.dir.symLink(std.testing.io, "secret", "root/alias", .{});

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPathFile(std.testing.io, "root", &root_buf);

    var vfs = try Vfs.init(std.testing.io, std.testing.allocator, root_buf[0..root_len]);
    defer vfs.deinit(std.testing.allocator);

    try std.testing.expectError(
        error.PathTraversal,
        vfs.openVerifiedParent(std.testing.io, std.testing.allocator, "/escape/hosts"),
    );
    try std.testing.expectError(
        error.PathTraversal,
        vfs.openVerifiedParent(std.testing.io, std.testing.allocator, "/alias/file"),
    );
}
