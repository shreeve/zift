const std = @import("std");

pub const Error = error{
    EmptyRoot,
    InvalidPath,
    NotAbsoluteRoot,
    OutOfMemory,
    PathTraversal,
} || std.Io.Dir.RealPathFileAllocError;

pub const Vfs = struct {
    root: [:0]const u8,

    pub fn init(io: std.Io, allocator: std.mem.Allocator, root_path: []const u8) Error!Vfs {
        if (root_path.len == 0) return error.EmptyRoot;
        if (!std.Io.Dir.path.isAbsolute(root_path)) return error.NotAbsoluteRoot;
        const canonical = try std.Io.Dir.realPathFileAbsoluteAlloc(io, root_path, allocator);
        return .{ .root = canonical };
    }

    pub fn deinit(self: *Vfs, allocator: std.mem.Allocator) void {
        allocator.free(self.root);
        self.* = undefined;
    }

    pub fn resolveExisting(
        self: Vfs,
        io: std.Io,
        allocator: std.mem.Allocator,
        virtual_path: []const u8,
    ) Error![:0]u8 {
        const normalized = try normalizeVirtualPath(allocator, virtual_path);
        defer allocator.free(normalized);

        const joined = try joinRoot(allocator, self.root, normalized);
        defer allocator.free(joined);

        const real = try std.Io.Dir.realPathFileAbsoluteAlloc(io, joined, allocator);
        errdefer allocator.free(real);
        if (!isInsideRoot(self.root, real)) return error.PathTraversal;
        return real;
    }

    pub fn resolveForCreate(
        self: Vfs,
        io: std.Io,
        allocator: std.mem.Allocator,
        virtual_path: []const u8,
    ) Error![]u8 {
        const normalized = try normalizeVirtualPath(allocator, virtual_path);
        defer allocator.free(normalized);
        if (std.mem.eql(u8, normalized, "/")) return error.InvalidPath;

        const slash = std.mem.lastIndexOfScalar(u8, normalized, '/') orelse unreachable;
        const parent_virtual = if (slash == 0) "/" else normalized[0..slash];
        const base = normalized[slash + 1 ..];
        if (base.len == 0 or std.mem.eql(u8, base, ".") or std.mem.eql(u8, base, "..")) return error.InvalidPath;

        const joined_parent = try joinRoot(allocator, self.root, parent_virtual);
        defer allocator.free(joined_parent);

        const real_parent = try std.Io.Dir.realPathFileAbsoluteAlloc(io, joined_parent, allocator);
        defer allocator.free(real_parent);
        if (!isInsideRoot(self.root, real_parent)) return error.PathTraversal;

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try out.appendSlice(allocator, real_parent);
        try out.append(allocator, '/');
        try out.appendSlice(allocator, base);
        return try out.toOwnedSlice(allocator);
    }

    pub fn normalizeVirtual(allocator: std.mem.Allocator, virtual_path: []const u8) Error![]u8 {
        return normalizeVirtualPath(allocator, virtual_path);
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

    /// Resolves the virtual path's parent directory, opens it as a verified
    /// `std.Io.Dir` whose canonical real path is confirmed to be inside the
    /// jail, and returns the parent directory plus the basename. The caller
    /// then performs operations relative to the parent fd (mkdirat / unlinkat /
    /// renameat) to avoid TOCTOU between path resolution and the operation.
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
        const base_part = normalized[slash + 1 ..];
        if (base_part.len == 0 or std.mem.eql(u8, base_part, ".") or std.mem.eql(u8, base_part, "..")) {
            return error.InvalidPath;
        }

        const joined_parent = try joinRoot(allocator, self.root, parent_virtual);
        defer allocator.free(joined_parent);

        const real_parent = try std.Io.Dir.realPathFileAbsoluteAlloc(io, joined_parent, allocator);
        defer allocator.free(real_parent);
        if (!isInsideRoot(self.root, real_parent)) return error.PathTraversal;

        const dir = std.Io.Dir.openDirAbsolute(io, real_parent, .{}) catch return error.PathTraversal;
        errdefer dir.close(io);
        try self.verifyDir(io, dir);

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

fn normalizeVirtualPath(allocator: std.mem.Allocator, virtual_path: []const u8) Error![]u8 {
    if (std.mem.indexOfScalar(u8, virtual_path, 0) != null) return error.InvalidPath;

    var parts: std.ArrayList([]const u8) = .empty;
    defer parts.deinit(allocator);

    var iter = std.mem.tokenizeScalar(u8, virtual_path, '/');
    while (iter.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".")) continue;
        if (std.mem.eql(u8, part, "..")) {
            if (parts.items.len == 0) return error.PathTraversal;
            _ = parts.pop();
            continue;
        }
        try parts.append(allocator, part);
    }

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, '/');
    for (parts.items, 0..) |part, i| {
        if (i != 0) try out.append(allocator, '/');
        try out.appendSlice(allocator, part);
    }
    return try out.toOwnedSlice(allocator);
}

fn joinRoot(allocator: std.mem.Allocator, root: []const u8, normalized_virtual: []const u8) Error![]u8 {
    if (std.mem.eql(u8, normalized_virtual, "/")) {
        return allocator.dupe(u8, root);
    }

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, root);
    try out.appendSlice(allocator, normalized_virtual);
    return try out.toOwnedSlice(allocator);
}

fn isInsideRoot(root: []const u8, path: []const u8) bool {
    if (std.mem.eql(u8, root, path)) return true;
    if (!std.mem.startsWith(u8, path, root)) return false;
    return path.len > root.len and path[root.len] == '/';
}

test "normalize virtual path" {
    const allocator = std.testing.allocator;
    const normalized = try Vfs.normalizeVirtual(allocator, "/pending//./inbox/file.txt");
    defer allocator.free(normalized);
    try std.testing.expectEqualStrings("/pending/inbox/file.txt", normalized);
}

test "normalize rejects traversal above root" {
    try std.testing.expectError(
        error.PathTraversal,
        Vfs.normalizeVirtual(std.testing.allocator, "/../../etc/passwd"),
    );
}

test "normalize rejects nul byte" {
    try std.testing.expectError(
        error.InvalidPath,
        Vfs.normalizeVirtual(std.testing.allocator, "/pending/a\x00b"),
    );
}

test "resolve blocks symlink escape" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDir(std.testing.io, "root", .default_dir);
    try tmp.dir.symLink(std.testing.io, "/etc", "root/outside", .{});

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPathFile(std.testing.io, "root", &root_buf);

    var vfs = try Vfs.init(std.testing.io, std.testing.allocator, root_buf[0..root_len]);
    defer vfs.deinit(std.testing.allocator);

    try std.testing.expectError(
        error.PathTraversal,
        vfs.resolveExisting(std.testing.io, std.testing.allocator, "/outside/passwd"),
    );
}
