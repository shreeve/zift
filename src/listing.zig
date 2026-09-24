//! Directory-listing support: lstat under a jailed dir fd, uid/gid name
//! lookup, and the `ls -l` style longname that SFTP clients display
//! verbatim (instead of their `?`-filled fallback), e.g.
//!
//!     drwxr-s---   4 ally     sftp             - Apr 24 16:34 inbox
//!     -rw-r-----   1 ally     sftp           41K Apr 27 06:55 hey.txt

const std = @import("std");
const builtin = @import("builtin");
const sys = @import("sys.zig");

/// The stat fields SFTP needs. std's Stat lacks uid/gid, hence our own.
pub const EntryInfo = struct {
    /// Full `st_mode`, file-type bits included.
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    size: u64,
    /// Whole seconds: SFTP v3 carries no finer times.
    mtime_secs: i64,
};

pub const StatError = error{ NotFound, AccessDenied, NameTooLong, Unexpected };

/// NAME_MAX on Linux and macOS. APFS can hold longer UTF-8 names; those
/// are refused rather than cut, since a cut name addresses nothing.
pub const max_name_bytes = 255;

/// lstat of `name` under `dir_fd`: a symlink reports itself, never its
/// target. `dir_fd` must already be inside the jail; this does not check.
pub fn statAt(dir_fd: std.posix.fd_t, name: []const u8) StatError!EntryInfo {
    if (name.len > max_name_bytes) return error.NameTooLong;
    var buf: [max_name_bytes + 1]u8 = undefined;
    @memcpy(buf[0..name.len], name);
    buf[name.len] = 0;
    return stat(dir_fd, buf[0..name.len :0], std.posix.AT.SYMLINK_NOFOLLOW);
}

/// `statAt` for an open fd.
pub fn statFd(fd: std.posix.fd_t) StatError!EntryInfo {
    return stat(fd, "", if (builtin.os.tag == .linux) std.os.linux.AT.EMPTY_PATH else 0);
}

/// An empty `name` stats `fd` itself.
fn stat(fd: std.posix.fd_t, name: [*:0]const u8, flags: u32) StatError!EntryInfo {
    if (builtin.os.tag == .linux) {
        // Raw statx, decoded with `linux.errno`: with libc linked,
        // `std.posix.errno` expects -1/errno and reads a raw -errno as
        // SUCCESS. libc's fstat is not used because std leaves it empty
        // on Linux.
        const linux = std.os.linux;
        var sx: linux.Statx = undefined;
        const mask: linux.STATX = .{ .TYPE = true, .MODE = true, .NLINK = true, .UID = true, .GID = true, .SIZE = true, .MTIME = true };
        const errno = linux.errno(linux.statx(fd, name, flags, mask, &sx));
        if (errno != .SUCCESS) return statError(errno);
        return .{
            .mode = sx.mode,
            .nlink = sx.nlink,
            .uid = sx.uid,
            .gid = sx.gid,
            .size = sx.size,
            .mtime_secs = sx.mtime.sec,
        };
    } else {
        var st: std.c.Stat = undefined;
        const rc = if (name[0] == 0) std.c.fstat(fd, &st) else std.c.fstatat(fd, name, &st, flags);
        if (rc != 0) return statError(std.posix.errno(rc));
        return .{
            .mode = st.mode,
            .nlink = st.nlink,
            .uid = st.uid,
            .gid = st.gid,
            .size = @intCast(st.size),
            .mtime_secs = st.mtime().sec,
        };
    }
}

fn statError(errno: anytype) StatError {
    return switch (errno) {
        .ACCES, .PERM => error.AccessDenied,
        .NOENT, .NOTDIR, .BADF => error.NotFound,
        else => error.Unexpected,
    };
}

/// Per-session uid/gid name cache for `listing-mode reality`, inline and
/// allocation-free. Hosts have few owners, so a full cache stops caching
/// and renders further ids as numbers; a name longer than
/// `max_name_len` or a failed lookup renders as a number too.
pub const NameResolver = struct {
    pub const max_entries: usize = 64;
    pub const max_name_len: usize = 32;

    users: Cache = .{},
    groups: Cache = .{},

    /// The user name, or the number rendered into `numeric_buf`.
    pub fn user(self: *NameResolver, uid: u32, numeric_buf: []u8) []const u8 {
        return self.users.name(uid, numeric_buf, lookupUser);
    }

    pub fn group(self: *NameResolver, gid: u32, numeric_buf: []u8) []const u8 {
        return self.groups.name(gid, numeric_buf, lookupGroup);
    }

    const Cache = struct {
        count: usize = 0,
        entries: [max_entries]Entry = undefined,

        const Entry = struct {
            id: u32,
            /// 0 when the lookup failed.
            len: u8,
            name: [max_name_len]u8,
        };

        fn name(
            self: *Cache,
            id: u32,
            numeric_buf: []u8,
            comptime lookup: fn (u32, *[max_name_len]u8) ?[]const u8,
        ) []const u8 {
            const entry = for (self.entries[0..self.count]) |*e| {
                if (e.id == id) break e;
            } else blk: {
                if (self.count == max_entries) break :blk null;
                const e = &self.entries[self.count];
                self.count += 1;
                e.id = id;
                e.len = if (lookup(id, &e.name)) |found| @intCast(found.len) else 0;
                break :blk e;
            };
            if (entry) |e| if (e.len > 0) return e.name[0..e.len];
            return std.fmt.bufPrint(numeric_buf, "{d}", .{id}) catch numeric_buf[0..0];
        }
    };
};

fn lookupUser(uid: u32, out: *[NameResolver.max_name_len]u8) ?[]const u8 {
    return lookupName(std.c.passwd, std.c.getpwuid_r, uid, out, 4096);
}

fn lookupGroup(gid: u32, out: *[NameResolver.max_name_len]u8) ?[]const u8 {
    return lookupName(std.c.group, std.c.getgrgid_r, gid, out, 4096);
}

/// `getpwuid_r`/`getgrgid_r` into `out`. A record that overflows the
/// scratch buffer (a group with many members) retries with a larger
/// heap buffer, up to 1 MiB. Null on any failure.
fn lookupName(
    comptime Record: type,
    comptime getById: anytype,
    id: u32,
    out: *[NameResolver.max_name_len]u8,
    comptime initial_len: usize,
) ?[]const u8 {
    var stack_buf: [initial_len]u8 = undefined;
    var buf: []u8 = &stack_buf;
    defer if (buf.len > initial_len) std.heap.page_allocator.free(buf);
    while (true) {
        var record: Record = undefined;
        var result: ?*Record = null;
        const rc = getById(id, &record, buf.ptr, buf.len, &result);
        if (rc == @intFromEnum(std.posix.E.RANGE) and buf.len < 1 << 20) {
            const bigger = std.heap.page_allocator.alloc(u8, buf.len * 4) catch return null;
            if (buf.len > initial_len) std.heap.page_allocator.free(buf);
            buf = bigger;
            continue;
        }
        if (rc != 0) return null;
        const name = std.mem.span((result orelse return null).name orelse return null);
        if (name.len == 0 or name.len > out.len) return null;
        @memcpy(out[0..name.len], name);
        return out[0..name.len];
    }
}

/// A GNU `ls -l` style line (see the module doc) into `out`, which
/// should hold at least 256 bytes. Long fields push columns right.
pub fn formatLongname(
    out: []u8,
    info: EntryInfo,
    user_name: []const u8,
    group_name: []const u8,
    entry_name: []const u8,
    now_secs: i64,
) []const u8 {
    var w = std.Io.Writer.fixed(out);

    var mode_buf: [10]u8 = undefined;
    formatModeString(&mode_buf, info.mode);

    var size_buf: [12]u8 = undefined;
    const size_str = formatSize(&size_buf, info.mode, info.size);

    var time_buf: [20]u8 = undefined;
    const time_str = formatMtime(&time_buf, info.mtime_secs, now_secs);

    w.print(
        "{s} {d:>3} {s:<8} {s:<8} {s:>9} {s} {s}",
        .{ mode_buf[0..], info.nlink, user_name, group_name, size_str, time_str, entry_name },
    ) catch return w.buffered();

    return w.buffered();
}

/// `drwxr-xr-x` style, including setuid/setgid/sticky letters.
pub fn formatModeString(out: *[10]u8, mode: u32) void {
    out[0] = switch (mode & S_IFMT) {
        S_IFDIR => 'd',
        S_IFLNK => 'l',
        S_IFCHR => 'c',
        S_IFBLK => 'b',
        S_IFIFO => 'p',
        S_IFSOCK => 's',
        else => '-',
    };

    const r = "r-";
    const w = "w-";
    const x = "x-";

    out[1] = r[if ((mode & 0o400) != 0) 0 else 1];
    out[2] = w[if ((mode & 0o200) != 0) 0 else 1];
    out[3] = blk: {
        const has_x = (mode & 0o100) != 0;
        const has_setuid = (mode & 0o4000) != 0;
        if (has_setuid and has_x) break :blk 's';
        if (has_setuid) break :blk 'S';
        break :blk x[if (has_x) 0 else 1];
    };

    out[4] = r[if ((mode & 0o040) != 0) 0 else 1];
    out[5] = w[if ((mode & 0o020) != 0) 0 else 1];
    out[6] = blk: {
        const has_x = (mode & 0o010) != 0;
        const has_setgid = (mode & 0o2000) != 0;
        if (has_setgid and has_x) break :blk 's';
        if (has_setgid) break :blk 'S';
        break :blk x[if (has_x) 0 else 1];
    };

    out[7] = r[if ((mode & 0o004) != 0) 0 else 1];
    out[8] = w[if ((mode & 0o002) != 0) 0 else 1];
    out[9] = blk: {
        const has_x = (mode & 0o001) != 0;
        const has_sticky = (mode & 0o1000) != 0;
        if (has_sticky and has_x) break :blk 't';
        if (has_sticky) break :blk 'T';
        break :blk x[if (has_x) 0 else 1];
    };
}

/// `-` for directories and special files, else bytes or `1.5K`, `41K`, ...
fn formatSize(out: []u8, mode: u32, size: u64) []const u8 {
    switch (mode & S_IFMT) {
        S_IFDIR, S_IFIFO, S_IFSOCK, S_IFCHR, S_IFBLK => return std.fmt.bufPrint(out, "-", .{}) catch out[0..0],
        else => {},
    }

    if (size < 1024) {
        return std.fmt.bufPrint(out, "{d}", .{size}) catch out[0..0];
    }

    const units = [_]u8{ 'K', 'M', 'G', 'T', 'P' };
    var value: f64 = @floatFromInt(size);
    var unit: u8 = 'B';
    inline for (units) |u| {
        if (value < 1024.0) break;
        value /= 1024.0;
        unit = u;
    }
    if (unit == 'B') {
        return std.fmt.bufPrint(out, "{d}", .{size}) catch out[0..0];
    }
    if (value < 10.0) {
        return std.fmt.bufPrint(out, "{d:.1}{c}", .{ value, unit }) catch out[0..0];
    }
    return std.fmt.bufPrint(out, "{d:.0}{c}", .{ value, unit }) catch out[0..0];
}

/// `Mon DD HH:MM` within ~6 months of now, else `Mon DD  YYYY` (the
/// double space keeps the column width), all in UTC.
fn formatMtime(out: []u8, mtime_secs: i64, now_secs: i64) []const u8 {
    const t = sys.civil(mtime_secs);
    const six_months_secs: i64 = 6 * 30 * 24 * 60 * 60;
    // i128: a junk mtime (e.g. i64 min) must not overflow.
    const diff: i128 = @as(i128, now_secs) - @as(i128, mtime_secs);
    const recent = diff < @as(i128, six_months_secs) and
        diff > -@as(i128, six_months_secs / 2);

    const month = month_abbrev[t.month - 1];
    // Clamped so a junk year prints a bounded number.
    const year: i32 = @intCast(std.math.clamp(t.year, std.math.minInt(i32), std.math.maxInt(i32)));

    if (recent) {
        return std.fmt.bufPrint(
            out,
            "{s} {d:>2} {d:0>2}:{d:0>2}",
            .{ month, t.day, t.hour, t.minute },
        ) catch out[0..0];
    }
    return std.fmt.bufPrint(
        out,
        "{s} {d:>2}  {d}",
        .{ month, t.day, year },
    ) catch out[0..0];
}

const month_abbrev = [_][]const u8{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

// POSIX file-type bits, as u32 to match `EntryInfo.mode`.
pub const S_IFMT: u32 = 0o170000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFBLK: u32 = 0o060000;
pub const S_IFIFO: u32 = 0o010000;
pub const S_IFSOCK: u32 = 0o140000;

// -------- tests --------------------------------------------------------------

test "formatModeString: regular file" {
    var buf: [10]u8 = undefined;
    formatModeString(&buf, S_IFREG | 0o644);
    try std.testing.expectEqualStrings("-rw-r--r--", &buf);
}

test "formatModeString: directory" {
    var buf: [10]u8 = undefined;
    formatModeString(&buf, S_IFDIR | 0o755);
    try std.testing.expectEqualStrings("drwxr-xr-x", &buf);
}

test "formatModeString: setgid directory" {
    var buf: [10]u8 = undefined;
    formatModeString(&buf, S_IFDIR | 0o2750);
    try std.testing.expectEqualStrings("drwxr-s---", &buf);
}

test "formatModeString: symlink, world-writable" {
    var buf: [10]u8 = undefined;
    formatModeString(&buf, S_IFLNK | 0o777);
    try std.testing.expectEqualStrings("lrwxrwxrwx", &buf);
}

test "formatModeString: sticky bit, /tmp-style" {
    var buf: [10]u8 = undefined;
    formatModeString(&buf, S_IFDIR | 0o1777);
    try std.testing.expectEqualStrings("drwxrwxrwt", &buf);
}

test "formatSize: directory shows -" {
    var buf: [12]u8 = undefined;
    try std.testing.expectEqualStrings("-", formatSize(&buf, S_IFDIR | 0o755, 4096));
}

test "formatSize: small regular file shows raw bytes" {
    var buf: [12]u8 = undefined;
    try std.testing.expectEqualStrings("213", formatSize(&buf, S_IFREG | 0o644, 213));
}

test "formatSize: K threshold" {
    var buf: [12]u8 = undefined;
    try std.testing.expectEqualStrings("41K", formatSize(&buf, S_IFREG | 0o644, 41 * 1024));
}

test "formatSize: fractional below 10x unit" {
    var buf: [12]u8 = undefined;
    try std.testing.expectEqualStrings("1.5K", formatSize(&buf, S_IFREG | 0o644, 1536));
}

test "formatMtime: recent uses HH:MM" {
    var buf: [20]u8 = undefined;
    // mtime 60s ago: definitely "recent"
    const now = 1777905300;
    const out = formatMtime(&buf, now - 60, now);
    try std.testing.expect(std.mem.indexOf(u8, out, ":") != null);
}

test "formatMtime: old uses YYYY" {
    var buf: [20]u8 = undefined;
    // mtime ~5 years ago: definitely "old"
    const now: i64 = 1777905300;
    const out = formatMtime(&buf, now - 5 * 365 * 24 * 60 * 60, now);
    try std.testing.expect(std.mem.indexOf(u8, out, ":") == null);
}

test "formatMtime: extreme mtime from corrupted inode does not overflow" {
    var buf: [20]u8 = undefined;
    const now: i64 = 1777300500;
    _ = formatMtime(&buf, std.math.minInt(i64), now);
    _ = formatMtime(&buf, std.math.maxInt(i64), now);
}

test "formatLongname: directory line" {
    var out: [256]u8 = undefined;
    const info: EntryInfo = .{
        .mode = S_IFDIR | 0o2750,
        .nlink = 5,
        .uid = 1000,
        .gid = 1000,
        .size = 4096,
        .mtime_secs = 1777905300, // 2026-05-04 ~
    };
    const line = formatLongname(&out, info, "shreeve", "trust", "alice", 1777905300);
    try std.testing.expect(std.mem.indexOf(u8, line, "drwxr-s---") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "shreeve") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "trust") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "alice") != null);
    // Directory size column should be "-", not "4096".
    try std.testing.expect(std.mem.indexOf(u8, line, "4096") == null);
}

test "formatLongname: file line shows size" {
    var out: [256]u8 = undefined;
    const info: EntryInfo = .{
        .mode = S_IFREG | 0o644,
        .nlink = 1,
        .uid = 0,
        .gid = 1000,
        .size = 41 * 1024,
        .mtime_secs = 1777905300,
    };
    const line = formatLongname(&out, info, "root", "trust", "hey.txt", 1777905300);
    try std.testing.expect(std.mem.indexOf(u8, line, "-rw-r--r--") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "41K") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "hey.txt") != null);
}

test "statAt and statFd report the same entry, and map errors" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(io, "f", .{});
    defer file.close(io);
    try file.writeStreamingAll(io, "hello");

    const by_name = try statAt(tmp.dir.handle, "f");
    const by_fd = try statFd(file.handle);
    try std.testing.expectEqual(by_name, by_fd);
    try std.testing.expectEqual(S_IFREG, by_name.mode & S_IFMT);
    try std.testing.expectEqual(@as(u64, 5), by_name.size);

    try tmp.dir.symLink(io, "f", "link", .{});
    try std.testing.expectEqual(S_IFLNK, (try statAt(tmp.dir.handle, "link")).mode & S_IFMT);
    try std.testing.expectError(error.NotFound, statAt(tmp.dir.handle, "missing"));
    try std.testing.expectError(error.NotFound, statAt(tmp.dir.handle, "f/under-a-file"));
    try std.testing.expectError(error.NameTooLong, statAt(tmp.dir.handle, "n" ** (max_name_bytes + 1)));
    try std.testing.expectError(error.NotFound, statAt(tmp.dir.handle, "n" ** max_name_bytes));
}

test "NameResolver: names, numbers, and a scratch buffer too small to start" {
    var resolver: NameResolver = .{};
    var numeric: [16]u8 = undefined;
    const uid = std.c.getuid();
    var expected_buf: [NameResolver.max_name_len]u8 = undefined;
    const expected = lookupUser(uid, &expected_buf) orelse return error.SkipZigTest;

    try std.testing.expectEqualStrings(expected, resolver.user(uid, &numeric));
    // Cached: the same bytes come back without a lookup.
    try std.testing.expectEqual(resolver.user(uid, &numeric).ptr, resolver.user(uid, &numeric).ptr);
    // No such id: rendered as a number, and remembered as such.
    try std.testing.expectEqualStrings("4000000000", resolver.group(4_000_000_000, &numeric));
    try std.testing.expectEqualStrings("4000000000", resolver.group(4_000_000_000, &numeric));

    // ERANGE from an 8-byte scratch buffer retries with a larger one.
    var small_buf: [NameResolver.max_name_len]u8 = undefined;
    try std.testing.expectEqualStrings(expected, lookupName(std.c.passwd, std.c.getpwuid_r, uid, &small_buf, 8).?);
    var group_buf: [NameResolver.max_name_len]u8 = undefined;
    var group_small: [NameResolver.max_name_len]u8 = undefined;
    if (lookupGroup(std.c.getgid(), &group_buf)) |group_name| {
        try std.testing.expectEqualStrings(group_name, lookupName(std.c.group, std.c.getgrgid_r, std.c.getgid(), &group_small, 8).?);
    }
}
