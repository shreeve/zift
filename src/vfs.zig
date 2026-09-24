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
    ///
    /// `<root>/.zift/` is the reserved namespace: `staging/` belongs to
    /// the daemon and anything else there to the operator. Both must be
    /// real directories, never symlinks that could move staging out of
    /// the jail. `.zift` may not grant group-write or other access (a
    /// group member could swap `staging`); `staging` may grant no group
    /// or other access at all (in-flight uploads). New dirs get 0750 and
    /// 0700, set after create because createDir honors umask.
    pub fn openStagingDir(self: Vfs, io: std.Io) !std.Io.Dir {
        var root = try std.Io.Dir.openDirAbsolute(io, self.root, .{});
        defer root.close(io);

        // A pre-existing `.zift` keeps its owner and mode.
        var ns_dir = try openOrCreateNamespaceDir(io, root);
        errdefer ns_dir.close(io);

        const staging = try openOrCreateStagingSubdir(io, ns_dir);
        ns_dir.close(io);
        return staging;
    }

    /// Staging dir if it exists and passes the checks; never creates it.
    pub fn tryOpenExistingStagingDir(self: Vfs, io: std.Io) ?std.Io.Dir {
        var root = std.Io.Dir.openDirAbsolute(io, self.root, .{}) catch return null;
        defer root.close(io);
        var ns_dir = root.openDir(io, namespace_dir_name, .{ .iterate = true, .follow_symlinks = false }) catch return null;
        defer ns_dir.close(io);
        assertOpenedDirMode(ns_dir, 0o027, error.NamespaceDirCorrupt, error.NamespaceDirUnsafe) catch return null;
        var staging = ns_dir.openDir(io, staging_subdir_name, .{ .iterate = true, .follow_symlinks = false }) catch return null;
        assertOpenedDirMode(staging, 0o077, error.StagingDirCorrupt, error.StagingDirUnsafe) catch {
            staging.close(io);
            return null;
        };
        return staging;
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

        var current = try std.Io.Dir.openDirAbsolute(io, self.root, .{
            .iterate = iterate,
            .follow_symlinks = false,
        });
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

const staging_subdir_name: []const u8 = "staging";

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

fn openOrCreateNamespaceDir(io: std.Io, root: std.Io.Dir) !std.Io.Dir {
    const namespace_perm = std.Io.File.Permissions.fromMode(0o750);
    const create_status = root.createDir(io, namespace_dir_name, namespace_perm);
    if (create_status) |_| {
        var dir = try root.openDir(io, namespace_dir_name, .{ .iterate = true, .follow_symlinks = false });
        errdefer dir.close(io);
        try dir.setPermissions(io, namespace_perm);
        try assertOpenedDirMode(dir, 0o027, error.NamespaceDirCorrupt, error.NamespaceDirUnsafe);
        return dir;
    } else |err| switch (err) {
        error.PathAlreadyExists => {
            // lstat, then NOFOLLOW open and fstat the fd, so a swap
            // between the two cannot redirect the namespace.
            const info = try listing.statAt(root.handle, namespace_dir_name);
            if ((info.mode & listing.S_IFMT) != listing.S_IFDIR) return error.NamespaceDirCorrupt;
            if ((info.mode & 0o027) != 0) return error.NamespaceDirUnsafe;
            var dir = try root.openDir(io, namespace_dir_name, .{ .iterate = true, .follow_symlinks = false });
            errdefer dir.close(io);
            try assertOpenedDirMode(dir, 0o027, error.NamespaceDirCorrupt, error.NamespaceDirUnsafe);
            return dir;
        },
        else => return err,
    }
}

fn openOrCreateStagingSubdir(io: std.Io, ns_dir: std.Io.Dir) !std.Io.Dir {
    const private_dir = std.Io.File.Permissions.fromMode(0o700);
    const create_status = ns_dir.createDir(io, staging_subdir_name, private_dir);
    if (create_status) |_| {
        var dir = try ns_dir.openDir(io, staging_subdir_name, .{ .iterate = true, .follow_symlinks = false });
        errdefer dir.close(io);
        try dir.setPermissions(io, private_dir);
        try assertOpenedDirMode(dir, 0o077, error.StagingDirCorrupt, error.StagingDirUnsafe);
        return dir;
    } else |err| switch (err) {
        error.PathAlreadyExists => {
            const info = try listing.statAt(ns_dir.handle, staging_subdir_name);
            if ((info.mode & listing.S_IFMT) != listing.S_IFDIR) return error.StagingDirCorrupt;
            if ((info.mode & 0o077) != 0) return error.StagingDirUnsafe;
            var dir = try ns_dir.openDir(io, staging_subdir_name, .{ .iterate = true, .follow_symlinks = false });
            errdefer dir.close(io);
            try assertOpenedDirMode(dir, 0o077, error.StagingDirCorrupt, error.StagingDirUnsafe);
            return dir;
        },
        else => return err,
    }
}

/// Re-check the opened fd: a directory without `forbidden_mask` bits.
fn assertOpenedDirMode(
    dir: std.Io.Dir,
    forbidden_mask: u32,
    corrupt: anyerror,
    unsafe: anyerror,
) !void {
    const info = try listing.statFd(dir.handle);
    if ((info.mode & listing.S_IFMT) != listing.S_IFDIR) return corrupt;
    if ((info.mode & forbidden_mask) != 0) return unsafe;
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
