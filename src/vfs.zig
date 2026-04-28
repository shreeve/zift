const std = @import("std");

pub const Error = error{
    EmptyRoot,
    InvalidPath,
    NotAbsoluteRoot,
    OutOfMemory,
    PathTooLong,
    PathTraversal,
    /// `.zift-staging` exists at a partner root but is not a
    /// real directory (could be a symlink, file, FIFO, etc.).
    /// Operators must `rm -f <root>/.zift-staging` to clear and
    /// let zift create the real directory on next session.
    StagingDirCorrupt,
    /// `.zift-staging` is a real directory but has group or
    /// other access bits set. Loose perms let local users
    /// observe in-flight upload names and (if writable) tamper
    /// with staging files between zift's rename-by-path and
    /// the kernel rename syscall. Operators must `chmod 0700
    /// <root>/.zift-staging` (or delete it and let zift
    /// recreate at 0700) before uploads will succeed.
    StagingDirUnsafe,
} || std.Io.Dir.RealPathFileAllocError;

/// PLAN §7.6: maximum virtual path length is 4096 bytes. Applies to
/// the raw client-supplied path before normalization; a path longer
/// than this is rejected before we allocate any per-component
/// storage.
pub const max_virtual_path_bytes: usize = 4096;

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

    /// Open (creating if needed) the partner-root's staging directory
    /// `<root>/.zift-staging/`. v0.5.0+ uses this for atomic-upload
    /// staging — every OPEN(write+CREAT) on a non-existent target
    /// goes to a randomly-named staging file here, then atomically
    /// renames to the real target at CLOSE. The directory name is
    /// reserved by `normalizeVirtualPath` so partners can never
    /// reach staging files via the SFTP wire surface.
    ///
    /// **Hardening (v0.5.1)**:
    ///
    ///  - In v0.4.0 and earlier, `.zift-staging` was a legal partner-
    ///    creatable name. A partner with `add` could have planted a
    ///    SYMLINK with that name pointing OUTSIDE the jail before
    ///    upgrading. Without verification, the upgraded server would
    ///    happily follow that symlink and write upload bytes to the
    ///    attacker-controlled location. We refuse to proceed if
    ///    `.zift-staging` exists and is not a real directory: lstat
    ///    via `statAt` (AT_SYMLINK_NOFOLLOW semantics), reject
    ///    anything whose `S_IFMT` is not `S_IFDIR`. Operators hit by
    ///    this hardening on upgrade should
    ///    `rm -f <root>/.zift-staging` to clear the bad entry.
    ///
    ///  - Created with mode `0o700`. Partial uploads are confidential
    ///    until the partner sends CLOSE — letting other local users
    ///    on the host browse them defeats half the value of staging.
    ///    Pre-existing directories are intentionally NOT chmodded
    ///    (won't silently change operator-customized state) but ARE
    ///    rejected if they grant any group or other access bits
    ///    (`(mode & 0o077) != 0`). A loose-perms staging dir would
    ///    let local users observe in-flight upload names AND, if
    ///    group/other-writable, replace staging files between zift's
    ///    rename-by-path and the kernel's rename syscall — turning a
    ///    confidentiality issue into an integrity one. Operators who
    ///    hit this on upgrade from a v0.5.0 install (which created
    ///    the dir without an explicit mode) should:
    ///
    ///        chmod 0700 <root>/.zift-staging
    ///
    ///    or delete it and let zift recreate at `0o700`.
    ///
    /// Caller owns the returned `Dir` and must close it.
    pub fn openStagingDir(self: Vfs, io: std.Io) !std.Io.Dir {
        var root = try std.Io.Dir.openDirAbsolute(io, self.root, .{});
        defer root.close(io);

        const private_dir = std.Io.File.Permissions.fromMode(0o700);
        const create_status = root.createDir(io, staging_dir_name, private_dir);
        if (create_status) |_| {
            // We just created it with 0o700. Open and return —
            // definitively a real directory at this moment.
            return try root.openDir(io, staging_dir_name, .{ .iterate = true });
        } else |err| switch (err) {
            error.PathAlreadyExists => {
                // Pre-existing entry. lstat it: must be a real
                // directory (not a symlink, FIFO, etc.) AND must
                // not grant group or other access. statAt has
                // AT_SYMLINK_NOFOLLOW semantics so a symlink
                // returns its OWN metadata, not the target's.
                const info = try @import("listing.zig").statAt(root.handle, staging_dir_name);
                const file_type = info.mode & 0o170000;
                if (file_type != 0o040000) return error.StagingDirCorrupt;
                if ((info.mode & 0o077) != 0) return error.StagingDirUnsafe;
                return try root.openDir(io, staging_dir_name, .{ .iterate = true });
            },
            else => return err,
        }
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

    /// Allocation-free validation of a client-supplied virtual path
    /// against PLAN §7.6 (length) and §8.3 (byte set + UTF-8). SFTP
    /// handlers call this immediately after `parseString`, before
    /// policy and audit, so an invalid-UTF-8 path never reaches the
    /// JSON audit encoder and the right `SSH_FX_BAD_MESSAGE` status
    /// surfaces to the client.
    pub fn validateVirtualPath(virtual_path: []const u8) Error!void {
        if (virtual_path.len > max_virtual_path_bytes) return error.PathTooLong;
        for (virtual_path) |b| {
            if (b == 0 or b < 0x20 or b == 0x7F) return error.InvalidPath;
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

    /// Resolves the virtual path's parent directory, opens it as a verified
    /// `std.Io.Dir` whose canonical real path is confirmed to be inside the
    /// jail, and returns the parent directory plus the basename.
    ///
    /// **Path-jail invariant** (PLAN §8.3, ENFORCED HERE — do NOT remove
    /// any step or reorder without re-reading this comment):
    ///
    /// 1. `normalizeVirtualPath`: pure string reduction. Rejects `..` that
    ///    walks above `/`, rejects NUL/control bytes, validates UTF-8.
    ///    No filesystem access yet — the jail starts at the next step.
    ///
    /// 2. `realPathFileAbsoluteAlloc`: resolves `<root><virtual>` through
    ///    every symlink, returning the canonical path string. This is
    ///    racy on its own — between this call and step 4 an attacker
    ///    with write access on any ancestor could swap a directory for
    ///    a symlink targeting outside the jail. We DO NOT trust the
    ///    string-based check at step 3 by itself; it's a fast-path
    ///    rejection for the common case of "user obviously asked for
    ///    something outside their root."
    ///
    /// 3. `isInsideRoot`: string-prefix check — fast, racy, defensive.
    ///    Discards the obvious "../../../etc/passwd" attempts before we
    ///    spend a syscall opening anything.
    ///
    /// 4. `openDirAbsolute`: actual `open(2)` of the canonical path.
    ///    Returns an FD; once captured, the FD points at a specific
    ///    inode no matter how the path is later swapped on disk.
    ///
    /// 5. `verifyDir` (THE INVARIANT-PRESERVING STEP): reads
    ///    `realPath` of the OPEN FD via `/proc/self/fd/N` (Linux) or
    ///    `fcntl(F_GETPATH)` (macOS). This is racefree — the kernel
    ///    asks "what file does this fd actually point at right now?"
    ///    not "what does this string mean right now?" If a swap
    ///    happened between steps 2-4, the FD's real path now resolves
    ///    OUTSIDE the jail, and we close it and reject. The caller
    ///    NEVER sees a usable FD that points outside the jail.
    ///
    /// The combined effect: the jail check is racy in the path-string
    /// world (steps 2-3) but racefree in the FD world (steps 4-5).
    /// Operations on the returned FD use *at() syscalls (mkdirat,
    /// unlinkat, renameat, openat), which inherit the FD's inode
    /// identity rather than re-resolving the path through the
    /// (possibly attacker-controlled) name tree.
    ///
    /// **DO NOT** "simplify" by:
    ///   - dropping `verifyDir` because the string-check passed,
    ///   - replacing `verifyDir` with another `realPathFileAbsoluteAlloc`
    ///     of the original string (that's the same race),
    ///   - reordering so verification happens before opening.
    /// All three break the invariant. Any of those changes needs to
    /// come with an alternative — e.g. on Linux, `openat2` with
    /// `RESOLVE_BENEATH` would let us drop the dance entirely once
    /// macOS catches up.
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

        // Step 2: canonicalize via the path string. RACY by itself.
        const real_parent = try std.Io.Dir.realPathFileAbsoluteAlloc(io, joined_parent, allocator);
        defer allocator.free(real_parent);
        // Step 3: fast-path rejection. Defensive only.
        if (!isInsideRoot(self.root, real_parent)) return error.PathTraversal;

        // Step 4: capture FD identity.
        const dir = std.Io.Dir.openDirAbsolute(io, real_parent, .{}) catch return error.PathTraversal;
        errdefer dir.close(io);
        // Step 5: RACEFREE re-verification via FD's own real path.
        // This is what makes the jail actually safe.
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

/// Reserved directory name (top-level under each partner's root)
/// that zift uses for staging atomic uploads (v0.5.0+). The wire-
/// surface validator rejects any virtual path containing this segment
/// so partners cannot reach staging files via the SFTP protocol —
/// belt-and-suspenders alongside the listing renderer's filter.
pub const staging_dir_name: []const u8 = ".zift-staging";

fn normalizeVirtualPath(allocator: std.mem.Allocator, virtual_path: []const u8) Error![]u8 {
    // PLAN §7.6 max length, §8.3 byte-set restrictions.
    if (virtual_path.len > max_virtual_path_bytes) return error.PathTooLong;
    for (virtual_path) |b| {
        // PLAN §8.3 step 2: reject NUL, all C0 control bytes, and DEL.
        // The space-character (0x20) and printable ASCII are allowed;
        // everything below 0x20 is forbidden including TAB / CR / LF
        // since they're never legitimate inside a single SFTP path.
        if (b == 0 or b < 0x20 or b == 0x7F) return error.InvalidPath;
    }
    if (!std.unicode.utf8ValidateSlice(virtual_path)) return error.InvalidPath;

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
        // v0.5.0: reserve `.zift-staging` as a path component name
        // ANYWHERE in the virtual path. This is the directory zift
        // uses for atomic-upload staging files, which partners must
        // never reach through the SFTP wire surface — neither to
        // read other partners' in-flight uploads, nor to plant
        // entries that the rename-from-staging step would later
        // pick up. Rejecting here, before any policy or filesystem
        // resolution, is the cheapest correct check.
        if (std.mem.eql(u8, part, staging_dir_name)) return error.InvalidPath;
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

/// True iff `path` is `root` or sits inside `root` at a path-component
/// boundary (so `/foo/bar` is inside `/foo` but `/foobar` is not).
/// Used by both the per-request jail check and `config.validateSemantic`
/// to detect overlapping user roots.
pub fn isInsideRoot(root: []const u8, path: []const u8) bool {
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

test "normalize rejects /.zift-staging anywhere in path (v0.5.0)" {
    // Top-level: never reachable.
    try std.testing.expectError(
        error.InvalidPath,
        Vfs.normalizeVirtual(std.testing.allocator, "/.zift-staging"),
    );
    // Any descent into the staging dir.
    try std.testing.expectError(
        error.InvalidPath,
        Vfs.normalizeVirtual(std.testing.allocator, "/.zift-staging/abc123"),
    );
    // Even if it appears mid-path (e.g. operator misconfigured a
    // partner root that contains a `.zift-staging` subdir for some
    // unrelated reason).
    try std.testing.expectError(
        error.InvalidPath,
        Vfs.normalizeVirtual(std.testing.allocator, "/pending/.zift-staging/something"),
    );
    // Non-staging dotfiles are fine.
    const ok = try Vfs.normalizeVirtual(std.testing.allocator, "/pending/.cache/foo");
    defer std.testing.allocator.free(ok);
    try std.testing.expectEqualStrings("/pending/.cache/foo", ok);
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

test "openVerifiedParent blocks parent-symlink escape" {
    // Locks in the path-jail invariant in `openVerifiedParent`. If a
    // future refactor drops either the string-prefix check (step 3)
    // OR the FD-based `verifyDir` re-check (step 5), this test fails
    // — catching the kind of "looks the same, doesn't it?" change
    // that introduces TOCTOU.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDir(std.testing.io, "root", .default_dir);
    // `escape/` is a symlink inside the jail pointing OUTSIDE. Any
    // SFTP request like `/escape/anything` must be rejected.
    try tmp.dir.symLink(std.testing.io, "/etc", "root/escape", .{});

    var root_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPathFile(std.testing.io, "root", &root_buf);

    var vfs = try Vfs.init(std.testing.io, std.testing.allocator, root_buf[0..root_len]);
    defer vfs.deinit(std.testing.allocator);

    // The basename ("hosts") doesn't exist on the symlink target —
    // doesn't matter, we should reject before any open is attempted
    // because the parent dir's canonical path resolves outside the
    // jail. The error is `PathTraversal` regardless of whether the
    // string check or the FD-based check fires first.
    try std.testing.expectError(
        error.PathTraversal,
        vfs.openVerifiedParent(std.testing.io, std.testing.allocator, "/escape/hosts"),
    );
}
