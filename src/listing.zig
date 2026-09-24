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

pub const StatError = error{ NotFound, AccessDenied, Unexpected };

/// lstat of `name` under `dir_fd`: a symlink reports itself, never its
/// target. `dir_fd` must already be inside the jail; this does not check.
pub fn statAt(dir_fd: std.posix.fd_t, name: []const u8) StatError!EntryInfo {
    if (name.len >= 256) return error.Unexpected;
    var name_buf: [256]u8 = undefined;
    @memcpy(name_buf[0..name.len], name);
    name_buf[name.len] = 0;
    const cname: [*:0]const u8 = @ptrCast(&name_buf);

    const at_flags: u32 = @intCast(std.posix.AT.SYMLINK_NOFOLLOW);

    if (builtin.os.tag == .linux) {
        // Raw statx: decode with `std.os.linux.errno`. With libc linked,
        // `std.posix.errno` expects libc's -1/errno convention and reads
        // every raw -errno return as SUCCESS.
        var sx: std.os.linux.Statx = std.mem.zeroes(std.os.linux.Statx);
        const mask: std.os.linux.STATX = .{
            .TYPE = true,
            .MODE = true,
            .NLINK = true,
            .UID = true,
            .GID = true,
            .SIZE = true,
            .MTIME = true,
        };
        const rc = std.os.linux.statx(dir_fd, cname, at_flags, mask, &sx);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {},
            .ACCES, .PERM => return error.AccessDenied,
            .NOENT, .NOTDIR => return error.NotFound,
            else => return error.Unexpected,
        }
        return EntryInfo{
            .mode = sx.mode,
            .nlink = sx.nlink,
            .uid = sx.uid,
            .gid = sx.gid,
            .size = sx.size,
            .mtime_secs = sx.mtime.sec,
        };
    } else {
        var st: std.c.Stat = std.mem.zeroes(std.c.Stat);
        const rc = std.c.fstatat(dir_fd, cname, &st, at_flags);
        if (rc != 0) {
            return switch (std.posix.errno(rc)) {
                .ACCES, .PERM => error.AccessDenied,
                .NOENT, .NOTDIR => error.NotFound,
                else => error.Unexpected,
            };
        }
        return EntryInfo{
            .mode = @intCast(st.mode),
            .nlink = @intCast(st.nlink),
            .uid = st.uid,
            .gid = st.gid,
            .size = @intCast(st.size),
            .mtime_secs = st.mtime().sec,
        };
    }
}

/// `statAt` for an open fd.
pub fn statFd(fd: std.posix.fd_t) StatError!EntryInfo {
    if (builtin.os.tag == .linux) {
        // Raw statx: `std.os.linux.errno`, as in `statAt`.
        var sx: std.os.linux.Statx = std.mem.zeroes(std.os.linux.Statx);
        const mask: std.os.linux.STATX = .{
            .TYPE = true,
            .MODE = true,
            .NLINK = true,
            .UID = true,
            .GID = true,
            .SIZE = true,
            .MTIME = true,
        };
        const empty: [*:0]const u8 = "";
        const at_empty: u32 = @intCast(std.posix.AT.EMPTY_PATH);
        const rc = std.os.linux.statx(fd, empty, at_empty, mask, &sx);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {},
            .ACCES, .PERM => return error.AccessDenied,
            .BADF, .NOENT => return error.NotFound,
            else => return error.Unexpected,
        }
        return EntryInfo{
            .mode = sx.mode,
            .nlink = sx.nlink,
            .uid = sx.uid,
            .gid = sx.gid,
            .size = sx.size,
            .mtime_secs = sx.mtime.sec,
        };
    } else {
        var st: std.c.Stat = std.mem.zeroes(std.c.Stat);
        const rc = std.c.fstat(fd, &st);
        if (rc != 0) {
            return switch (std.posix.errno(rc)) {
                .ACCES, .PERM => error.AccessDenied,
                .BADF => error.NotFound,
                else => error.Unexpected,
            };
        }
        return EntryInfo{
            .mode = @intCast(st.mode),
            .nlink = @intCast(st.nlink),
            .uid = st.uid,
            .gid = st.gid,
            .size = @intCast(st.size),
            .mtime_secs = st.mtime().sec,
        };
    }
}

/// Per-session uid/gid name cache, inline and allocation-free. Hosts have
/// few owners, so a full cache just stops caching; nothing is evicted.
pub const NameResolver = struct {
    pub const max_entries: usize = 64;
    pub const max_name_len: usize = 32;

    const Entry = struct {
        id: u32,
        len: u8,
        valid: bool,
        name: [max_name_len]u8,
    };

    user_count: u8 = 0,
    user_entries: [max_entries]Entry = std.mem.zeroes([max_entries]Entry),
    group_count: u8 = 0,
    group_entries: [max_entries]Entry = std.mem.zeroes([max_entries]Entry),

    /// The user name, or the number rendered into `numeric_buf`.
    pub fn user(self: *NameResolver, uid: u32, numeric_buf: []u8) []const u8 {
        // Index, don't iterate by value: the returned slice must point
        // into the cache, not a loop-local copy.
        var i: usize = 0;
        while (i < self.user_count) : (i += 1) {
            if (self.user_entries[i].id == uid) {
                if (!self.user_entries[i].valid) {
                    return std.fmt.bufPrint(numeric_buf, "{d}", .{uid}) catch numeric_buf[0..0];
                }
                return self.user_entries[i].name[0..self.user_entries[i].len];
            }
        }
        const name = lookupUid(uid);
        if (self.user_count < self.user_entries.len) {
            const slot_index = self.user_count;
            self.user_count += 1;
            const slot = &self.user_entries[slot_index];
            slot.id = uid;
            slot.valid = name != null;
            if (name) |n| {
                const copy = @min(n.len, max_name_len);
                @memcpy(slot.name[0..copy], n[0..copy]);
                slot.len = @intCast(copy);
                return self.user_entries[slot_index].name[0..self.user_entries[slot_index].len];
            }
        } else if (name) |n| {
            return copyToBuf(numeric_buf, n);
        }
        return std.fmt.bufPrint(numeric_buf, "{d}", .{uid}) catch numeric_buf[0..0];
    }

    pub fn group(self: *NameResolver, gid: u32, numeric_buf: []u8) []const u8 {
        var i: usize = 0;
        while (i < self.group_count) : (i += 1) {
            if (self.group_entries[i].id == gid) {
                if (!self.group_entries[i].valid) {
                    return std.fmt.bufPrint(numeric_buf, "{d}", .{gid}) catch numeric_buf[0..0];
                }
                return self.group_entries[i].name[0..self.group_entries[i].len];
            }
        }
        const name = lookupGid(gid);
        if (self.group_count < self.group_entries.len) {
            const slot_index = self.group_count;
            self.group_count += 1;
            const slot = &self.group_entries[slot_index];
            slot.id = gid;
            slot.valid = name != null;
            if (name) |n| {
                const copy = @min(n.len, max_name_len);
                @memcpy(slot.name[0..copy], n[0..copy]);
                slot.len = @intCast(copy);
                return self.group_entries[slot_index].name[0..self.group_entries[slot_index].len];
            }
        } else if (name) |n| {
            return copyToBuf(numeric_buf, n);
        }
        return std.fmt.bufPrint(numeric_buf, "{d}", .{gid}) catch numeric_buf[0..0];
    }
};

fn copyToBuf(buf: []u8, src: []const u8) []const u8 {
    const n = @min(buf.len, src.len);
    @memcpy(buf[0..n], src[0..n]);
    return buf[0..n];
}

/// `getpwuid_r` into thread-local buffers; null on any failure.
fn lookupUid(uid: u32) ?[]const u8 {
    const S = struct {
        threadlocal var pwd: std.c.passwd = undefined;
        threadlocal var buf: [1024]u8 = undefined;
        threadlocal var name: [NameResolver.max_name_len]u8 = undefined;
    };
    var result: ?*std.c.passwd = null;
    if (std.c.getpwuid_r(uid, &S.pwd, &S.buf, S.buf.len, &result) != 0) return null;
    const r = result orelse return null;
    const pw_name = std.mem.span(@as([*:0]const u8, @ptrCast(r.name)));
    if (pw_name.len == 0 or pw_name.len > S.name.len) return null;
    @memcpy(S.name[0..pw_name.len], pw_name);
    return S.name[0..pw_name.len];
}

fn lookupGid(gid: u32) ?[]const u8 {
    const S = struct {
        threadlocal var grp: std.c.group = undefined;
        threadlocal var buf: [1024]u8 = undefined;
        threadlocal var name: [NameResolver.max_name_len]u8 = undefined;
    };
    var result: ?*std.c.group = null;
    if (std.c.getgrgid_r(gid, &S.grp, &S.buf, S.buf.len, &result) != 0) return null;
    const r = result orelse return null;
    const gr_name = std.mem.span(@as([*:0]const u8, @ptrCast(r.name)));
    if (gr_name.len == 0 or gr_name.len > S.name.len) return null;
    @memcpy(S.name[0..gr_name.len], gr_name);
    return S.name[0..gr_name.len];
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
