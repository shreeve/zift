//! SFTP directory-listing formatter.
//!
//! `ls -la` over SFTP is two questions stitched together:
//!
//!   1. What does each entry actually look like on disk? (mode, nlink,
//!      uid, gid, size, mtime). The SFTP client uses this to render its
//!      own listing if the server hasn't provided a "longname".
//!
//!   2. How does the server choose to *render* that information? The
//!      protocol lets us send a precomputed longname per entry; if we
//!      do, the OpenSSH client uses ours verbatim instead of falling
//!      back to its own renderer (which prints `?` for fields it
//!      doesn't have).
//!
//! Zift answers both: it `fstatat`s each entry under the open dir-fd
//! (path-jail safe — no string-layer resolution past the verified
//! directory), then formats a GNU-`ls`-style line, then sends it to
//! the client along with full SFTP attrs. So `sftp> ls -la` looks like
//!
//!     drwxr-x---  5 shreeve trust    -    Apr 27 07:46 alice
//!     drwxr-s---  4 shreeve trust    -    Apr 24 16:34 ally
//!     -rw-r--r--  1 root    trust  41 K   Apr 27 06:55 hey.txt
//!
//! rather than the client's "?"-laden fallback. The size column is
//! `-` for directories and special files (which match Unix `ls -lh`'s
//! "we don't really care how big the inode is") and shows a real
//! human-readable size for regular files. Numeric uid/gid only appears
//! when `/etc/passwd` lookup fails — the typical local-user setup
//! always resolves to names.
//!
//! All POSIX shape calls (`statx` on Linux, `fstatat` on macOS,
//! `getpwuid_r`/`getgrgid_r` for name resolution) are kept in this
//! module so session.zig stays focused on the SFTP wire protocol.

const std = @import("std");
const builtin = @import("builtin");

/// What we extract from every directory entry. Stays platform-agnostic
/// even though the syscall to populate it differs (statx vs fstatat).
pub const EntryInfo = struct {
    /// Full POSIX `st_mode`, including file-type bits in the high
    /// nibble. Callers extract type via `S_IFMT` mask and permission
    /// bits via `0o777`.
    mode: u32,
    /// Hard-link count. Always ≥1 on any sensible filesystem; clients
    /// surface this in the `ls -l` 2nd column.
    nlink: u32,
    uid: u32,
    gid: u32,
    /// Apparent size in bytes. For directories and most special files
    /// the longname formatter substitutes `-`; this field is still
    /// reported in the SFTP attrs for clients that want it.
    size: u64,
    /// Whole seconds since the Unix epoch. SFTP v3 attrs only carry
    /// 32-bit second-resolution timestamps (`uatime`/`umtime`), so
    /// we don't bother carrying nanos.
    mtime_secs: i64,
};

pub const StatError = error{ NotFound, AccessDenied, Unexpected };

/// `fstatat(dir_fd, name, AT_SYMLINK_NOFOLLOW)` — never follows the
/// final component, so a symlink in the partner's tree returns its own
/// metadata rather than reaching whatever it points at. The dir_fd
/// MUST come from a `Dir` already verified by the path-jail; this
/// function does NOT enforce containment, it just observes.
pub fn statAt(dir_fd: std.posix.fd_t, name: []const u8) StatError!EntryInfo {
    // `fstatat`/`statx` need a NUL-terminated path. NAME_MAX (255 on
    // Linux/macOS) plus the terminator fits in a stack array.
    if (name.len >= 256) return error.Unexpected;
    var name_buf: [256]u8 = undefined;
    @memcpy(name_buf[0..name.len], name);
    name_buf[name.len] = 0;
    const cname: [*:0]const u8 = @ptrCast(&name_buf);

    const at_flags: u32 = @intCast(std.posix.AT.SYMLINK_NOFOLLOW);

    if (builtin.os.tag == .linux) {
        // Linux: statx syscall. Available since kernel 4.11 (2017),
        // covering every reasonable target. We ask for exactly the
        // fields we use; the kernel is allowed to fill more if it's
        // cheap, and we just ignore the extras.
        var sx: std.os.linux.Statx = undefined;
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
        switch (std.posix.errno(rc)) {
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
        // macOS / *BSD / Solaris: libc `fstatat` against `std.c.Stat`.
        // The Stat layout differs per OS; std.c picks the right one.
        // `std.c.errno(rc)` does the right thing here: it checks
        // `rc == -1` and reads the libc thread-local errno on its
        // own. Pass `rc` directly — earlier code wrapped it in a
        // double cast (`@as(usize, @bitCast(@as(isize, rc)))`) that
        // worked only by accident because `usize == -1` happens to
        // coerce correctly on 64-bit. Cargo cult; removed.
        var st: std.c.Stat = undefined;
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

/// `fstat`-equivalent for an already-open file descriptor — used by
/// SFTP `FSTAT` (operating on a handle whose underlying fd is in our
/// hand). Same portable shape as `statAt`.
pub fn statFd(fd: std.posix.fd_t) StatError!EntryInfo {
    if (builtin.os.tag == .linux) {
        // Linux: `statx` with `AT_EMPTY_PATH` against the fd. Same
        // flow as `statAt` minus the path argument.
        var sx: std.os.linux.Statx = undefined;
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
        switch (std.posix.errno(rc)) {
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
        var st: std.c.Stat = undefined;
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

/// Per-session cache for `uid -> name` and `gid -> name` translation.
///
/// Sized for the typical SFTP deployment: a handful of distinct
/// owners across the partner roots (the OS user running zift, root,
/// maybe one or two service accounts). When the cache fills, we fall
/// back to numeric — never evict, because evicting a popular entry
/// to make room for a single one-off file would worsen the next
/// listing's perf and the userbase here is tiny anyway.
///
/// All buffers live inline in the struct, so the resolver itself
/// allocates nothing — useful inside the SFTP read loop where we
/// want predictable behavior under load.
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

    /// Look up `uid` -> name. Returns either a cached/`getpwuid_r`-resolved
    /// name (sliced from the cache slot — not a temporary loop copy)
    /// or a numeric fallback rendered into `numeric_buf` and returned.
    pub fn user(self: *NameResolver, uid: u32, numeric_buf: []u8) []const u8 {
        // CRITICAL: index by `i`, NOT `for (self.user_entries) |entry|`.
        // The latter iterates by VALUE; `entry.name[0..entry.len]` would
        // return a slice into the loop's stack-local copy, going stale
        // the moment we return. Indexing keeps the slice live in the
        // resolver's own backing storage.
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
            // Cache full but we still resolved successfully; return the
            // resolved name in the caller's scratch buffer rather than
            // trying to evict.
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

/// `getpwuid_r` wrapper. Returns the user's `pw_name` if the lookup
/// succeeds, `null` otherwise (uid not present in passwd db, name
/// longer than our buffer, or any libc error). Each call uses a
/// fresh thread-local scratch buffer so concurrent sessions don't
/// share state.
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

/// Format a GNU-`ls`-style listing line into `out`. Returns the slice
/// of `out` that was written. Caller-supplied buffer should be ≥ 256
/// bytes — long enough for the header plus a NAME_MAX filename.
///
/// Layout:
///
///     drwxr-xr-x  3 alice    trust         -    Apr 27 07:46 dirname
///     -rw-r--r--  1 root     trust    41 K     Apr 27 06:55 file.txt
///     lrwxrwxrwx  1 alice    trust         -    Apr 27 07:46 link -> target
///
/// The size column is `-` for directories, FIFOs, sockets, and devices
/// (where the inode size doesn't carry useful information for the
/// SFTP client) and a human-readable byte count for regular files /
/// symlinks. Time format follows `ls -l`'s "recent vs. old" rule: a
/// `Mon DD HH:MM` form for entries within the last ~6 months, and
/// `Mon DD  YYYY` for older ones.
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

    // Field widths chosen to stay readable for a typical SFTP partner
    // setup (one or two service users, group names ≤ 8 chars, sizes
    // up to a few GB rendered with the K/M/G suffix). Long names
    // overflow gracefully — they push subsequent columns rightward
    // rather than truncating.
    w.print(
        "{s} {d:>3} {s:<8} {s:<8} {s:>9} {s} {s}",
        .{ mode_buf[0..], info.nlink, user_name, group_name, size_str, time_str, entry_name },
    ) catch return w.buffered();

    return w.buffered();
}

/// Render the 10-character mode string (`drwxr-xr-x`, `-rw-r--r--`, etc.)
/// into `out`. `out` must be exactly 10 bytes long.
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

/// Render a human-readable size column. Returns the slice of `out`
/// that was written. Directories, FIFOs, sockets, and devices show
/// `-`; regular files and symlinks show a byte count or K/M/G/T
/// suffix once the value reaches 1024.
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

/// Format a Unix timestamp the way GNU `ls` does: `Mon DD HH:MM` if
/// the entry's mtime is within the last ~6 months, otherwise
/// `Mon DD  YYYY` (note the double space, deliberate — it keeps
/// the column width the same as the HH:MM form so dates align).
fn formatMtime(out: []u8, mtime_secs: i64, now_secs: i64) []const u8 {
    const broken = breakTime(mtime_secs);
    const six_months_secs: i64 = 6 * 30 * 24 * 60 * 60;
    const recent = (now_secs - mtime_secs) < six_months_secs and (now_secs - mtime_secs) > -(six_months_secs / 2);

    const month = month_abbrev[@min(broken.month, 11)];

    if (recent) {
        return std.fmt.bufPrint(
            out,
            "{s} {d:>2} {d:0>2}:{d:0>2}",
            .{ month, broken.day, broken.hour, broken.minute },
        ) catch out[0..0];
    }
    return std.fmt.bufPrint(
        out,
        "{s} {d:>2}  {d}",
        .{ month, broken.day, broken.year },
    ) catch out[0..0];
}

const month_abbrev = [_][]const u8{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

const BrokenTime = struct {
    /// Calendar year. `i32` (not `u16`) so pre-1970 timestamps work
    /// without underflow and so any unrealistic mtime from a corrupted
    /// inode never panics ReleaseSafe — `ls -l` over a partner-managed
    /// tree must never crash the session because of a synthetic
    /// timestamp.
    year: i32,
    month: u4, // 0-11
    day: u8, // 1-31
    hour: u8, // 0-23
    minute: u8, // 0-59
};

/// A tiny, dependency-free `gmtime`. Avoids pulling in libc localtime
/// (which links against tz data, allocates, and behaves differently
/// per host); the SFTP audit log already standardizes on UTC for
/// timestamps and the `ls -l` time column is informational, not
/// security-critical, so UTC is fine here too.
///
/// Implementation: Howard Hinnant's `civil_from_days` algorithm
/// (https://howardhinnant.github.io/date_algorithms.html). O(1) — no
/// loops over years/months — so it cannot spin or panic on extreme
/// inputs the way the prior iterative implementation did. Any `i64`
/// second offset within the proleptic Gregorian range converges; a
/// pre-1970 mtime is just as valid as any other.
fn breakTime(secs: i64) BrokenTime {
    const seconds_per_day: i64 = 86400;
    const day = @divFloor(secs, seconds_per_day);
    const seconds_in_day = secs - day * seconds_per_day; // [0, 86399]

    // Shift epoch from 1970-01-01 to 0000-03-01 (the "March 1, year 0"
    // origin Hinnant's algorithm uses). 719468 = days from 0000-03-01
    // to 1970-01-01 in the proleptic Gregorian calendar.
    const z: i64 = day + 719468;
    const era: i64 = if (z >= 0) @divFloor(z, 146097) else @divFloor(z - 146096, 146097);
    const doe: u32 = @intCast(z - era * 146097); // [0, 146096]
    const yoe: u32 = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    const civil_year: i64 = @as(i64, yoe) + era * 400;
    const doy: u32 = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    const mp: u32 = (5 * doy + 2) / 153; // [0, 11], March-based
    const day_of_month: u8 = @intCast(doy - (153 * mp + 2) / 5 + 1); // [1, 31]
    // mp 0-9 = March-December (calendar months 3-12); mp 10-11 = January-February
    // of the FOLLOWING calendar year, so the Jan/Feb adjustment below.
    const month_jan_based: u8 = if (mp < 10) @intCast(mp + 3) else @intCast(mp - 9);
    const calendar_year: i64 = if (month_jan_based <= 2) civil_year + 1 else civil_year;

    return .{
        // Saturate at the i32 range. Any timestamp that produces a
        // year outside ±2 billion is a synthetic value and we don't
        // care about pixel-perfect rendering — we only care about
        // not panicking.
        .year = @intCast(std.math.clamp(calendar_year, std.math.minInt(i32), std.math.maxInt(i32))),
        .month = @intCast(month_jan_based - 1),
        .day = day_of_month,
        .hour = @intCast(@divFloor(seconds_in_day, 3600)),
        .minute = @intCast(@divFloor(@mod(seconds_in_day, 3600), 60)),
    };
}

// POSIX file-type constants. We define our own copies rather than
// pulling them from std.c.S because std.c.S is target-specific (the
// numeric values differ between glibc, musl, and macOS) and we only
// need the canonical POSIX values, which match across all three.
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

test "breakTime: known epoch -> 1970-01-01 00:00" {
    const b = breakTime(0);
    try std.testing.expectEqual(@as(i32, 1970), b.year);
    try std.testing.expectEqual(@as(u4, 0), b.month);
    try std.testing.expectEqual(@as(u8, 1), b.day);
    try std.testing.expectEqual(@as(u8, 0), b.hour);
    try std.testing.expectEqual(@as(u8, 0), b.minute);
}

test "breakTime: 2026-04-27 14:35 UTC" {
    // 2026-04-27T14:35:00Z = 1777905300
    const b = breakTime(1777905300);
    try std.testing.expectEqual(@as(i32, 2026), b.year);
    try std.testing.expectEqual(@as(u4, 3), b.month); // April (0-indexed)
    try std.testing.expectEqual(@as(u8, 27), b.day);
    try std.testing.expectEqual(@as(u8, 14), b.hour);
    try std.testing.expectEqual(@as(u8, 35), b.minute);
}

test "breakTime: pre-1970 timestamps render correctly" {
    // 1969-12-31 23:59:59 UTC = -1
    const b = breakTime(-1);
    try std.testing.expectEqual(@as(i32, 1969), b.year);
    try std.testing.expectEqual(@as(u4, 11), b.month); // December
    try std.testing.expectEqual(@as(u8, 31), b.day);
    try std.testing.expectEqual(@as(u8, 23), b.hour);
    try std.testing.expectEqual(@as(u8, 59), b.minute);
}

test "breakTime: 1900-01-01 (pre-Unix-epoch by 70 years)" {
    // 1900-01-01 00:00:00 UTC = -2208988800 (well before Unix epoch)
    const b = breakTime(-2208988800);
    try std.testing.expectEqual(@as(i32, 1900), b.year);
    try std.testing.expectEqual(@as(u4, 0), b.month); // January
    try std.testing.expectEqual(@as(u8, 1), b.day);
}

test "breakTime: extreme negative timestamp does not panic" {
    // Used to underflow `u16 year` and panic in ReleaseSafe. The
    // exact rendered year doesn't matter; what matters is that the
    // function returns a `BrokenTime` instead of crashing.
    const b = breakTime(std.math.minInt(i64) + 1);
    _ = b;
}

test "breakTime: extreme positive timestamp does not panic" {
    const b = breakTime(std.math.maxInt(i64) - 1);
    _ = b;
}

test "breakTime: i32 year saturation" {
    // `breakTime(maxInt(i64))` would overflow `civil_year` past `i32`'s
    // range. The clamp protects rendering — the `{d}` formatter just
    // prints the saturated value without ever choking on overflow.
    const b = breakTime(std.math.maxInt(i64));
    try std.testing.expect(b.year == std.math.maxInt(i32) or b.year > 0);
}

test "breakTime: leap-year handling (2000-02-29)" {
    // 2000-02-29 12:00:00 UTC = 951825600
    const b = breakTime(951825600);
    try std.testing.expectEqual(@as(i32, 2000), b.year);
    try std.testing.expectEqual(@as(u4, 1), b.month); // February
    try std.testing.expectEqual(@as(u8, 29), b.day);
}

test "breakTime: non-leap century (1900 is NOT a leap year)" {
    // 1900-02-28 23:59:59 UTC = -2203891201
    const b = breakTime(-2203891201);
    try std.testing.expectEqual(@as(i32, 1900), b.year);
    try std.testing.expectEqual(@as(u4, 1), b.month);
    try std.testing.expectEqual(@as(u8, 28), b.day);

    // 1900-03-01 00:00:00 UTC = -2203891200
    const c = breakTime(-2203891200);
    try std.testing.expectEqual(@as(i32, 1900), c.year);
    try std.testing.expectEqual(@as(u4, 2), c.month);
    try std.testing.expectEqual(@as(u8, 1), c.day);
}

test "breakTime: 400-year leap (2000 IS a leap year)" {
    // 2000-02-29 → 2000-03-01 transition
    // 2000-03-01 00:00:00 UTC = 951868800
    const b = breakTime(951868800);
    try std.testing.expectEqual(@as(i32, 2000), b.year);
    try std.testing.expectEqual(@as(u4, 2), b.month);
    try std.testing.expectEqual(@as(u8, 1), b.day);
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

test "formatLongname: directory line" {
    var out: [256]u8 = undefined;
    const info: EntryInfo = .{
        .mode = S_IFDIR | 0o2750,
        .nlink = 5,
        .uid = 1000,
        .gid = 1000,
        .size = 4096,
        .mtime_secs = 1777905300, // 2026-04-04 ~
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
