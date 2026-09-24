//! Structured audit log: one JSON object per line (see docs/operate.md).
//!
//! Field order is fixed so awk/jq recipes can anchor on it:
//!   time, event, user?, operation, result, path?, detail?, ip, truncated?
//! `ip` is always present ("" when unknown); `truncated` marks a line
//! clipped to 4096 bytes.
//!
//! Each line is a single write(2) under a process-wide mutex, so lines
//! never interleave. The destination is stderr or an absolute file opened
//! O_APPEND|O_NOFOLLOW and reopened on SIGUSR1. A symlink or non-regular
//! file is refused; mode 0640 is set only on a file this process created.

const std = @import("std");
const builtin = @import("builtin");
const config = @import("config.zig");
const signals = @import("signals.zig");

pub const Result = enum { ok, denied, failed };

/// Longer lines are shortened and marked `"truncated":true`.
const max_line_bytes: usize = 4096;

/// Where audit lines go. Matches `config.LogTarget` shape but owns the
/// fd so the sink can reopen on SIGUSR1 without disturbing the config
/// snapshot.
pub const Target = union(enum) {
    stderr,
    file: []const u8,
};

pub const Sink = struct {
    target: Target = .stderr,
    /// File fd when target is `.file`; -1 otherwise. Swapped atomically
    /// on reopen.
    fd: std.atomic.Value(c_int) = .init(-1),
    /// Serializes writes and reopen.
    mutex: std.Io.Mutex = .init,
    /// Owned copy of the file path; the config may be freed on reload.
    owned_path: ?[]const u8 = null,
    /// Monotonic ms when a failed reopen is retried; 0 = none pending.
    /// A deadline, not a re-raised signal flag, so a broken path does
    /// not retry (and warn) on every audit line.
    reopen_retry_at_ms: std.atomic.Value(i64) = .init(0),
    /// Monotonic ms of the last reopen-failure stderr line. Guarded
    /// by `mutex`. 0 means a failure has not been reported yet.
    last_reopen_warn_ms: i64 = 0,

    pub fn initFromConfig(
        allocator: std.mem.Allocator,
        target: config.LogTarget,
    ) !Sink {
        switch (target) {
            .stderr => return .{ .target = .stderr },
            .file => |path| {
                const owned = try allocator.dupe(u8, path);
                errdefer allocator.free(owned);
                const fd = try openLogFile(owned);
                return .{
                    .target = .{ .file = owned },
                    .fd = .init(fd),
                    .owned_path = owned,
                };
            },
        }
    }

    pub fn deinit(self: *Sink, allocator: std.mem.Allocator) void {
        const fd = self.fd.swap(-1, .acq_rel);
        if (fd >= 0) _ = std.c.close(fd);
        if (self.owned_path) |path| allocator.free(path);
        self.* = .{};
    }

    /// Honor SIGUSR1 lazily: the next audit line after the signal swaps
    /// in a fresh fd, so an idle server keeps the old fd until then. On
    /// open failure the old fd stays in use and a retry is scheduled.
    fn maybeReopen(self: *Sink, io: std.Io) void {
        const signaled = signals.log_reopen_requested.load(.acquire);
        const retry_at = self.reopen_retry_at_ms.load(.acquire);
        if (!signaled) {
            if (retry_at == 0 or nowMonotonicMs() < retry_at) return;
        }

        const path = switch (self.target) {
            .stderr => {
                _ = signals.log_reopen_requested.swap(false, .acq_rel);
                self.reopen_retry_at_ms.store(0, .release);
                return;
            },
            .file => |p| p,
        };

        self.mutex.lockUncancelable(io);
        // Consume the signal under the mutex so two writers cannot both
        // open; a signal arriving during the open is honored next line.
        const signaled_now = signals.log_reopen_requested.swap(false, .acq_rel);
        const now = nowMonotonicMs();
        const retry_at_now = self.reopen_retry_at_ms.load(.acquire);
        if (!signaled_now and (retry_at_now == 0 or now < retry_at_now)) {
            self.mutex.unlock(io);
            return;
        }

        const new_fd = openLogFile(path) catch |err| {
            const failed_at = nowMonotonicMs();
            self.reopen_retry_at_ms.store(failed_at + warn_min_interval_ms, .release);
            const warn = self.last_reopen_warn_ms == 0 or
                failed_at - self.last_reopen_warn_ms >= warn_min_interval_ms;
            if (warn) self.last_reopen_warn_ms = failed_at;
            self.mutex.unlock(io);
            if (warn) {
                writeStderrRaw("zift: audit log reopen failed: ");
                writeStderrRaw(@errorName(err));
                writeStderrRaw("\n");
            }
            return;
        };

        self.reopen_retry_at_ms.store(0, .release);
        const old_fd = self.fd.swap(new_fd, .acq_rel);
        self.mutex.unlock(io);

        // Close after the swap; the caller's line goes to the new fd.
        if (old_fd >= 0) _ = std.c.close(old_fd);
        writeStderrRaw("zift: audit log reopened\n");
    }

    pub fn log(
        self: *Sink,
        io: std.Io,
        user: ?[]const u8,
        operation: []const u8,
        path: ?[]const u8,
        result: Result,
        detail: []const u8,
        ip: []const u8,
    ) void {
        self.maybeReopen(io);
        var buf: [max_line_bytes]u8 = undefined;
        const line = formatLine(&buf, user, operation, path, result, detail, ip);
        self.write(io, line);
    }

    /// One write(2) per line, so concurrent threads (and other O_APPEND
    /// writers) cannot interleave inside a JSON object.
    fn write(self: *Sink, io: std.Io, line: []const u8) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        const fd: c_int = switch (self.target) {
            .stderr => 2,
            .file => blk: {
                const f = self.fd.load(.acquire);
                if (f < 0) break :blk 2; // fallback: never lose the line
                break :blk f;
            },
        };

        const n = std.c.write(fd, line.ptr, line.len);
        if (n < 0 or @as(usize, @intCast(n)) != line.len) {
            warnWriteFailure(if (n < 0) "WriteFailed" else "ShortWrite");
        }
    }
};

/// Audit-write failures are reported as bare stderr lines, never through
/// the audit pipeline itself, at most once per `warn_min_interval_ms` so
/// a full disk cannot turn into a stderr storm.
const warn_min_interval_ms: i64 = 5_000;
var last_warn_ms: std.atomic.Value(i64) = .init(0);

fn warnWriteFailure(name: []const u8) void {
    const now = nowMonotonicMs();
    const last = last_warn_ms.load(.acquire);
    if (now - last < warn_min_interval_ms and last != 0) return;
    last_warn_ms.store(now, .release);

    writeStderrRaw("zift: audit write failed: ");
    writeStderrRaw(name);
    writeStderrRaw("\n");
}

/// CLOCK_MONOTONIC milliseconds (immune to wall-clock changes).
pub fn nowMonotonicMs() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), std.time.ns_per_ms);
}

fn writeStderrRaw(text: []const u8) void {
    _ = std.c.write(2, text.ptr, text.len);
}

fn openLogFile(path: []const u8) !c_int {
    var path_z: [4096]u8 = undefined;
    if (path.len >= path_z.len) return error.PathTooLong;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;
    const path_c: [*:0]const u8 = @ptrCast(&path_z);

    const mode: std.posix.mode_t = 0o640;
    // EXCL tells "created here" (pin 0640) from "already there" (leave
    // its mode). O_CREAT|O_EXCL returns EEXIST on a symlink, so the
    // NOFOLLOW open below is what rejects one.
    const created = std.c.open(path_c, .{
        .ACCMODE = .WRONLY,
        .APPEND = true,
        .CREAT = true,
        .EXCL = true,
        .CLOEXEC = true,
        .NOFOLLOW = true,
    }, mode);
    if (created >= 0) {
        if (!fdIsRegularFile(created) or std.c.fchmod(created, mode) != 0) {
            _ = std.c.close(created);
            return error.OpenFailed;
        }
        return created;
    }
    if (std.posix.errno(created) != .EXIST) return error.OpenFailed;

    const fd = std.c.open(path_c, .{
        .ACCMODE = .WRONLY,
        .APPEND = true,
        .CLOEXEC = true,
        .NOFOLLOW = true,
    });
    if (fd < 0 or !fdIsRegularFile(fd)) {
        if (fd >= 0) _ = std.c.close(fd);
        return error.OpenFailed;
    }
    return fd;
}

/// Mode bits of an open fd, or null when stat fails.
fn fdFileMode(fd: c_int) ?u32 {
    if (builtin.os.tag == .linux) {
        var sx: std.os.linux.Statx = std.mem.zeroes(std.os.linux.Statx);
        const mask: std.os.linux.STATX = .{
            .TYPE = true,
            .MODE = true,
        };
        const empty: [*:0]const u8 = "";
        const at_empty: u32 = @intCast(std.posix.AT.EMPTY_PATH);
        const rc = std.os.linux.statx(fd, empty, at_empty, mask, &sx);
        if (std.os.linux.errno(rc) != .SUCCESS) return null;
        return sx.mode;
    } else {
        var st: std.c.Stat = std.mem.zeroes(std.c.Stat);
        if (std.c.fstat(fd, &st) != 0) return null;
        return st.mode;
    }
}

fn fdIsRegularFile(fd: c_int) bool {
    const mode = fdFileMode(fd) orelse return false;
    return std.posix.S.ISREG(mode);
}

// ----- process-wide singleton ----------------------------------------------

var global_sink: Sink = .{};

pub fn initGlobal(
    allocator: std.mem.Allocator,
    target: config.LogTarget,
) !void {
    global_sink = try Sink.initFromConfig(allocator, target);
}

pub fn deinitGlobal(allocator: std.mem.Allocator) void {
    global_sink.deinit(allocator);
}

/// Process-wide audit log call; stderr until `initGlobal` runs.
/// Arguments follow the JSON field order. Pass `ip` "" when unknown.
pub fn log(
    io: std.Io,
    user: ?[]const u8,
    operation: []const u8,
    path: ?[]const u8,
    result: Result,
    detail: []const u8,
    ip: []const u8,
) void {
    global_sink.log(io, user, operation, path, result, detail, ip);
}

// ----- formatting ----------------------------------------------------------

fn formatLine(
    buf: []u8,
    user: ?[]const u8,
    operation: []const u8,
    path: ?[]const u8,
    result: Result,
    detail: []const u8,
    ip: []const u8,
) []const u8 {
    // Full line first; then drop detail, then path, then user.
    {
        var w = std.Io.Writer.fixed(buf);
        if (formatLineImpl(&w, user, operation, path, result, detail, ip, false)) |_| {
            return w.buffered();
        } else |_| {}
    }

    {
        var w = std.Io.Writer.fixed(buf);
        if (formatLineImpl(&w, user, operation, path, result, "[truncated]", ip, true)) |_| {
            return w.buffered();
        } else |_| {}
    }

    {
        var w = std.Io.Writer.fixed(buf);
        if (formatLineImpl(&w, user, operation, null, result, "", ip, true)) |_| {
            return w.buffered();
        } else |_| {}
    }

    {
        var w = std.Io.Writer.fixed(buf);
        if (formatLineImpl(&w, null, operation, null, result, "", ip, true)) |_| {
            return w.buffered();
        } else |_| {}
    }

    // Only a huge `operation` gets here. Still valid JSON.
    const fallback = "{\"event\":\"zift.audit\",\"operation\":\"?\",\"result\":\"failed\",\"ip\":\"\",\"truncated\":true}\n";
    const len = @min(fallback.len, buf.len);
    @memcpy(buf[0..len], fallback[0..len]);
    return buf[0..len];
}

fn formatLineImpl(
    w: *std.Io.Writer,
    user: ?[]const u8,
    operation: []const u8,
    path: ?[]const u8,
    result: Result,
    detail: []const u8,
    ip: []const u8,
    truncated: bool,
) !void {
    // `time` leads so shippers and sort(1) get it without parsing.
    var time_buf: [time_buf_len]u8 = undefined;
    const time_str = formatNowRfc3339Utc(&time_buf);
    try w.writeAll("{\"time\":\"");
    try w.writeAll(time_str);
    try w.writeAll("\",\"event\":\"zift.audit\"");
    if (user) |value| {
        try w.writeAll(",\"user\":");
        try writeJsonStringLossy(w, value);
    }
    try w.writeAll(",\"operation\":");
    try writeJsonStringLossy(w, operation);
    try w.writeAll(",\"result\":\"");
    try w.writeAll(@tagName(result));
    try w.writeAll("\"");
    if (path) |value| {
        try w.writeAll(",\"path\":");
        try writeJsonStringLossy(w, value);
    }
    if (detail.len != 0) {
        try w.writeAll(",\"detail\":");
        try writeJsonStringLossy(w, detail);
    }
    try w.writeAll(",\"ip\":");
    try writeJsonStringLossy(w, ip);
    if (truncated) try w.writeAll(",\"truncated\":true");
    try w.writeAll("}\n");
}

/// Emit `s` as a JSON string, replacing invalid UTF-8 with U+FFFD.
///
/// Usernames and some audited strings are raw bytes. std's encoder
/// passes invalid UTF-8 through (making the line invalid JSON, which jq
/// and strict shippers drop, hiding the event) or panics with
/// `escape_unicode`, so we sanitize while encoding.
fn writeJsonStringLossy(w: *std.Io.Writer, s: []const u8) !void {
    const replacement = "\u{FFFD}"; // 3 bytes: EF BF BD
    try w.writeByte('"');
    var i: usize = 0;
    while (i < s.len) {
        const b = s[i];
        if (b < 0x80) {
            switch (b) {
                '"' => try w.writeAll("\\\""),
                '\\' => try w.writeAll("\\\\"),
                0x08 => try w.writeAll("\\b"),
                0x0C => try w.writeAll("\\f"),
                '\n' => try w.writeAll("\\n"),
                '\r' => try w.writeAll("\\r"),
                '\t' => try w.writeAll("\\t"),
                else => {
                    if (b < 0x20) {
                        try w.print("\\u{x:0>4}", .{b});
                    } else {
                        try w.writeByte(b);
                    }
                },
            }
            i += 1;
            continue;
        }
        const seq_len = std.unicode.utf8ByteSequenceLength(b) catch {
            try w.writeAll(replacement);
            i += 1;
            continue;
        };
        if (i + seq_len > s.len or !std.unicode.utf8ValidateSlice(s[i..][0..seq_len])) {
            try w.writeAll(replacement);
            i += 1;
            continue;
        }
        try w.writeAll(s[i..][0..seq_len]);
        i += seq_len;
    }
    try w.writeByte('"');
}

test "audit line stays valid JSON for invalid-UTF-8 path" {
    var buf: [max_line_bytes]u8 = undefined;
    // A filename with a lone 0xFF byte (invalid UTF-8) plus an embedded
    // quote and newline to exercise escaping.
    const nasty = "/pending/\xff\x22\x0aevil";
    const line = formatLine(&buf, "foo", "open_write", nasty, .denied, "", "127.0.0.1");
    // No raw control bytes or lone high bytes leaked; must be parseable.
    for (line[0 .. line.len - 1]) |ch| {
        try std.testing.expect(ch != '\n' or false);
    }
    try std.testing.expect(std.mem.endsWith(u8, line, "}\n"));
    try std.testing.expect(std.unicode.utf8ValidateSlice(line));
    try std.testing.expect(std.mem.indexOf(u8, line, "\u{FFFD}") != null);
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ`.
const time_buf_len: usize = 24;

/// Current wall-clock time as RFC 3339 UTC with milliseconds. A failed
/// clock read yields the epoch rather than garbage digits.
fn formatNowRfc3339Utc(buf: *[time_buf_len]u8) []const u8 {
    var ts: std.c.timespec = .{ .sec = 0, .nsec = 0 };
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return formatRfc3339Utc(buf, ts.sec, ts.nsec);
}

/// Pure form of `formatNowRfc3339Utc`. The year is clamped to
/// [0, 9999] so the field is always exactly 24 bytes.
fn formatRfc3339Utc(buf: *[time_buf_len]u8, sec: i64, nsec_in: i64) []const u8 {
    var nsec: i64 = nsec_in;
    if (nsec < 0) nsec = 0;
    if (nsec >= std.time.ns_per_s) nsec = std.time.ns_per_s - 1;
    const ms: u32 = @intCast(@divTrunc(nsec, std.time.ns_per_ms));

    const civil = civilFromUnix(sec);
    const sec_of_day: u32 = @intCast(@mod(sec, 86400));
    const hour: u32 = @divTrunc(sec_of_day, 3600);
    const minute: u32 = @divTrunc(@mod(sec_of_day, 3600), 60);
    const second: u32 = @mod(sec_of_day, 60);

    const year_clamped: i32 = if (civil.year < 0) 0 else if (civil.year > 9999) 9999 else civil.year;
    const year_u: u32 = @intCast(year_clamped);

    writeFixedDigits(buf[0..4], year_u);
    buf[4] = '-';
    writeFixedDigits(buf[5..7], civil.month);
    buf[7] = '-';
    writeFixedDigits(buf[8..10], civil.day);
    buf[10] = 'T';
    writeFixedDigits(buf[11..13], hour);
    buf[13] = ':';
    writeFixedDigits(buf[14..16], minute);
    buf[16] = ':';
    writeFixedDigits(buf[17..19], second);
    buf[19] = '.';
    writeFixedDigits(buf[20..23], ms);
    buf[23] = 'Z';
    return buf;
}

/// Zero-padded decimal filling `dst`; `value` must fit.
fn writeFixedDigits(dst: []u8, value_in: u32) void {
    var value = value_in;
    var i: usize = dst.len;
    while (i > 0) {
        i -= 1;
        dst[i] = @intCast('0' + (value % 10));
        value /= 10;
    }
}

const Civil = struct { year: i32, month: u8, day: u8 };

/// Howard Hinnant's `civil_from_days` for Unix seconds.
fn civilFromUnix(unix_secs: i64) Civil {
    const z: i64 = @divFloor(unix_secs, 86400) + 719468;
    const era: i64 = if (z >= 0) @divTrunc(z, 146097) else @divTrunc(z - 146096, 146097);
    const doe: u32 = @intCast(z - era * 146097);
    const yoe: u32 = (doe -% (doe / 1460) -% (doe / 36524) +% (doe / 146096)) / 365;
    const y: i64 = @as(i64, yoe) + era * 400;
    const doy: u32 = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const mp: u32 = (5 * doy + 2) / 153;
    const day: u32 = doy - (153 * mp + 2) / 5 + 1;
    const month: u32 = if (mp < 10) mp + 3 else mp - 9;
    const year: i64 = if (month <= 2) y + 1 else y;
    return .{
        .year = @intCast(year),
        .month = @intCast(month),
        .day = @intCast(day),
    };
}

// ----- tests ---------------------------------------------------------------

test "audit line escapes special characters" {
    var buf: [256]u8 = undefined;
    const line = formatLine(&buf, "ally", "open_write", "/pending/\"weird\"\nfile", .ok, "size=11", "10.0.0.1");
    try std.testing.expect(std.mem.indexOf(u8, line, "\\\"weird\\\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, line, "}\n"));
}

test "audit line always includes ip" {
    var buf: [256]u8 = undefined;

    const line_with_ip = formatLine(&buf, "ally", "auth.password", null, .ok, "", "203.0.113.7");
    try std.testing.expect(std.mem.indexOf(u8, line_with_ip, "\"ip\":\"203.0.113.7\"") != null);

    const line_empty_ip = formatLine(&buf, null, "accept", null, .denied, "max-connections reached", "");
    try std.testing.expect(std.mem.indexOf(u8, line_empty_ip, "\"ip\":\"\"") != null);
}

test "audit line follows the fixed field order" {
    var buf: [256]u8 = undefined;
    const line = formatLine(&buf, "ally", "write", "/inbox/x", .ok, "size=10", "10.0.0.1");
    // time must be the leading field; event next; ip after detail.
    const time_idx = std.mem.indexOf(u8, line, "\"time\"").?;
    const event_idx = std.mem.indexOf(u8, line, "\"event\"").?;
    const user_idx = std.mem.indexOf(u8, line, "\"user\"").?;
    const op_idx = std.mem.indexOf(u8, line, "\"operation\"").?;
    const result_idx = std.mem.indexOf(u8, line, "\"result\"").?;
    const path_idx = std.mem.indexOf(u8, line, "\"path\"").?;
    const detail_idx = std.mem.indexOf(u8, line, "\"detail\"").?;
    const ip_idx = std.mem.indexOf(u8, line, "\"ip\"").?;
    try std.testing.expect(time_idx < event_idx);
    try std.testing.expect(event_idx < user_idx);
    try std.testing.expect(user_idx < op_idx);
    try std.testing.expect(op_idx < result_idx);
    try std.testing.expect(result_idx < path_idx);
    try std.testing.expect(path_idx < detail_idx);
    try std.testing.expect(detail_idx < ip_idx);
    // `{"time":"` is 9 bytes; the timestamp then ends with `Z"`.
    try std.testing.expect(std.mem.startsWith(u8, line, "{\"time\":\""));
    try std.testing.expectEqual(@as(u8, 'Z'), line[9 + time_buf_len - 1]);
    try std.testing.expectEqual(@as(u8, '"'), line[9 + time_buf_len]);
}

test "audit time field is RFC 3339 UTC milliseconds (live)" {
    var buf: [time_buf_len]u8 = undefined;
    const ts = formatNowRfc3339Utc(&buf);
    try std.testing.expectEqual(@as(usize, time_buf_len), ts.len);
    try std.testing.expectEqual(@as(u8, '-'), ts[4]);
    try std.testing.expectEqual(@as(u8, '-'), ts[7]);
    try std.testing.expectEqual(@as(u8, 'T'), ts[10]);
    try std.testing.expectEqual(@as(u8, ':'), ts[13]);
    try std.testing.expectEqual(@as(u8, ':'), ts[16]);
    try std.testing.expectEqual(@as(u8, '.'), ts[19]);
    try std.testing.expectEqual(@as(u8, 'Z'), ts[23]);
}

test "formatRfc3339Utc fixed-input fixtures" {
    const Fixture = struct { sec: i64, nsec: i64, want: []const u8 };
    const fixtures = [_]Fixture{
        .{ .sec = 0, .nsec = 0, .want = "1970-01-01T00:00:00.000Z" },
        .{ .sec = 0, .nsec = 123_000_000, .want = "1970-01-01T00:00:00.123Z" },
        .{ .sec = 951_782_400, .nsec = 0, .want = "2000-02-29T00:00:00.000Z" }, // leap day
        .{ .sec = 1_709_251_200, .nsec = 999_000_000, .want = "2024-03-01T00:00:00.999Z" },
        .{ .sec = 4_102_444_800, .nsec = 0, .want = "2100-01-01T00:00:00.000Z" }, // year 2100 not a leap
        .{ .sec = -1, .nsec = 0, .want = "1969-12-31T23:59:59.000Z" },
        // Year-clamp edge: a wildly distant timestamp lands at 9999.
        .{ .sec = 253_402_300_799, .nsec = 0, .want = "9999-12-31T23:59:59.000Z" },
    };
    var buf: [time_buf_len]u8 = undefined;
    for (fixtures) |f| {
        const got = formatRfc3339Utc(&buf, f.sec, f.nsec);
        try std.testing.expectEqualStrings(f.want, got);
    }
}

test "civilFromUnix matches Howard Hinnant fixtures" {
    const Fixture = struct { unix: i64, year: i32, month: u8, day: u8 };
    const fixtures = [_]Fixture{
        .{ .unix = 0, .year = 1970, .month = 1, .day = 1 },
        .{ .unix = 951782400, .year = 2000, .month = 2, .day = 29 }, // leap day
        .{ .unix = 1456704000, .year = 2016, .month = 2, .day = 29 }, // leap day
        .{ .unix = 1709251200, .year = 2024, .month = 3, .day = 1 },
        .{ .unix = 4102444800, .year = 2100, .month = 1, .day = 1 }, // not a leap year
        .{ .unix = -86400, .year = 1969, .month = 12, .day = 31 },
    };
    for (fixtures) |f| {
        const civil = civilFromUnix(f.unix);
        try std.testing.expectEqual(f.year, civil.year);
        try std.testing.expectEqual(f.month, civil.month);
        try std.testing.expectEqual(f.day, civil.day);
    }
}

test "audit line truncates detail when over the line cap" {
    var buf: [max_line_bytes]u8 = undefined;
    var huge: [max_line_bytes]u8 = undefined;
    @memset(&huge, 'x');
    const line = formatLine(&buf, "ally", "write", "/tmp/foo", .ok, &huge, "10.0.0.1");
    try std.testing.expect(line.len <= max_line_bytes);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"truncated\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"ip\":\"10.0.0.1\"") != null);
    try std.testing.expect(std.mem.endsWith(u8, line, "}\n"));
}

fn testJoin(buf: []u8, parent: []const u8, name: []const u8) [:0]u8 {
    const n = parent.len + 1 + name.len;
    std.debug.assert(n < buf.len);
    @memcpy(buf[0..parent.len], parent);
    buf[parent.len] = '/';
    @memcpy(buf[parent.len + 1 ..][0..name.len], name);
    buf[n] = 0;
    return buf[0..n :0];
}

test "openLogFile refuses symlinks and non-regular files and pins 0640 only on create" {
    const io = std.testing.io;
    const Probe = struct {
        extern "c" fn mkfifo(path: [*:0]const u8, mode: std.posix.mode_t) c_int;

        fn perm(path: [*:0]const u8) !u32 {
            if (builtin.os.tag == .linux) {
                var sx: std.os.linux.Statx = std.mem.zeroes(std.os.linux.Statx);
                const mask: std.os.linux.STATX = .{ .TYPE = true, .MODE = true };
                const flags: u32 = @intCast(std.posix.AT.SYMLINK_NOFOLLOW);
                const rc = std.os.linux.statx(std.posix.AT.FDCWD, path, flags, mask, &sx);
                if (std.os.linux.errno(rc) != .SUCCESS) return error.TestUnexpectedResult;
                return @as(u32, sx.mode) & 0o777;
            } else {
                var st: std.c.Stat = std.mem.zeroes(std.c.Stat);
                const flags: u32 = @intCast(std.posix.AT.SYMLINK_NOFOLLOW);
                if (std.c.fstatat(std.posix.AT.FDCWD, path, &st, flags) != 0) return error.TestUnexpectedResult;
                return @as(u32, st.mode) & 0o777;
            }
        }

        fn fdPerm(fd: c_int) !u32 {
            const mode = fdFileMode(fd) orelse return error.TestUnexpectedResult;
            return mode & 0o777;
        }
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "d", .default_dir);
    var dir_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPathFile(io, "d", &dir_buf);
    const dir = dir_buf[0..dir_len];

    {
        var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const path = testJoin(&buf, dir, "created.log");
        // Under umask 077 only the fchmod yields 0640.
        const old_mask = std.c.umask(0o077);
        defer _ = std.c.umask(old_mask);
        const fd = try openLogFile(path);
        defer _ = std.c.close(fd);
        try std.testing.expectEqual(@as(u32, 0o640), try Probe.fdPerm(fd));
        try std.testing.expectEqual(@as(isize, 3), std.c.write(fd, "new", 3));
    }
    {
        var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const path = testJoin(&buf, dir, "created.log");
        try std.testing.expectEqual(@as(c_int, 0), std.c.chmod(path, 0o604));
        const fd = try openLogFile(path);
        defer _ = std.c.close(fd);
        // Pre-existing file: append, keep its mode.
        try std.testing.expectEqual(@as(u32, 0o604), try Probe.fdPerm(fd));
        try std.testing.expectEqual(@as(isize, 3), std.c.write(fd, "end", 3));
    }
    {
        var got: [16]u8 = undefined;
        const body = try tmp.dir.readFile(io, "d/created.log", &got);
        try std.testing.expectEqualStrings("newend", body);
    }

    {
        var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const path = testJoin(&buf, dir, "existing.log");
        const raw = std.c.open(path, .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .EXCL = true,
            .CLOEXEC = true,
            .NOFOLLOW = true,
        }, @as(std.posix.mode_t, 0o600));
        try std.testing.expect(raw >= 0);
        try std.testing.expectEqual(@as(c_int, 0), std.c.fchmod(raw, 0o600));
        try std.testing.expectEqual(@as(isize, 3), std.c.write(raw, "old", 3));
        _ = std.c.close(raw);
        const fd = try openLogFile(path);
        defer _ = std.c.close(fd);
        try std.testing.expectEqual(@as(u32, 0o600), try Probe.fdPerm(fd));
        try std.testing.expectEqual(@as(isize, 3), std.c.write(fd, "NEW", 3));
    }
    {
        var got: [16]u8 = undefined;
        const body = try tmp.dir.readFile(io, "d/existing.log", &got);
        try std.testing.expectEqualStrings("oldNEW", body);
    }

    {
        var target_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const target = testJoin(&target_buf, dir, "target.log");
        const raw = std.c.open(target, .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .EXCL = true,
            .CLOEXEC = true,
            .NOFOLLOW = true,
        }, @as(std.posix.mode_t, 0o600));
        try std.testing.expect(raw >= 0);
        try std.testing.expectEqual(@as(c_int, 0), std.c.fchmod(raw, 0o600));
        try std.testing.expectEqual(@as(isize, 4), std.c.write(raw, "safe", 4));
        _ = std.c.close(raw);

        var link_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const link = testJoin(&link_buf, dir, "link.log");
        try tmp.dir.symLink(io, target, "d/link.log", .{});
        try std.testing.expectError(error.OpenFailed, openLogFile(link));
        try std.testing.expectEqual(@as(u32, 0o600), try Probe.perm(target));
        var got: [16]u8 = undefined;
        const body = try tmp.dir.readFile(io, "d/target.log", &got);
        try std.testing.expectEqualStrings("safe", body);
    }

    try tmp.dir.createDir(io, "d/subdir", .default_dir);
    {
        var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const path = testJoin(&buf, dir, "subdir");
        try std.testing.expectError(error.OpenFailed, openLogFile(path));
    }

    const devnull_before = try Probe.perm("/dev/null");
    try std.testing.expectError(error.OpenFailed, openLogFile("/dev/null"));
    try std.testing.expectEqual(devnull_before, try Probe.perm("/dev/null"));

    {
        var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const path = testJoin(&buf, dir, "audit.fifo");
        try std.testing.expectEqual(@as(c_int, 0), Probe.mkfifo(path, 0o640));
        try std.testing.expectEqual(@as(c_int, 0), std.c.chmod(path, 0o612));
        const Reader = struct {
            fn run(fifo: [*:0]const u8) void {
                const fd = std.c.open(fifo, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
                if (fd < 0) return;
                var scratch: [8]u8 = undefined;
                _ = std.c.read(fd, &scratch, scratch.len);
                _ = std.c.close(fd);
            }
        };
        const thr = try std.Thread.spawn(.{}, Reader.run, .{path});
        defer thr.join();
        // The open unblocks the reader; fstat then rejects the fifo.
        try std.testing.expectError(error.OpenFailed, openLogFile(path));
        try std.testing.expectEqual(@as(u32, 0o612), try Probe.perm(path));
    }
}

test "failed audit reopen retries on a deadline without a stderr storm" {
    const io = std.testing.io;
    const saved_flag = signals.log_reopen_requested.load(.acquire);
    defer signals.log_reopen_requested.store(saved_flag, .release);
    signals.log_reopen_requested.store(false, .release);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "d", .default_dir);
    var dir_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPathFile(io, "d", &dir_buf);
    const dir = dir_buf[0..dir_len];

    var audit_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const audit_path = testJoin(&audit_buf, dir, "audit.jsonl");
    var kept_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const kept_path = testJoin(&kept_buf, dir, "kept.jsonl");
    var other_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const other_path = testJoin(&other_buf, dir, "other.jsonl");

    var sink = try Sink.initFromConfig(std.testing.allocator, .{ .file = audit_path });
    defer sink.deinit(std.testing.allocator);
    const original_fd = sink.fd.load(.acquire);
    try std.testing.expectEqual(@as(c_int, 0), std.c.link(audit_path, kept_path));

    sink.log(io, "u", "before-fail", null, .ok, "", "203.0.113.9");
    try tmp.dir.deleteFile(io, "d/audit.jsonl");
    {
        const other_fd = try openLogFile(other_path);
        _ = std.c.close(other_fd);
    }
    try tmp.dir.symLink(io, other_path, "d/audit.jsonl", .{});

    signals.log_reopen_requested.store(true, .release);
    sink.log(io, "u", "during-fail", null, .ok, "", "203.0.113.9");
    try std.testing.expectEqual(original_fd, sink.fd.load(.acquire));
    try std.testing.expect(sink.last_reopen_warn_ms != 0);
    const warned_at = sink.last_reopen_warn_ms;
    const retry_at = sink.reopen_retry_at_ms.load(.acquire);
    try std.testing.expect(retry_at >= nowMonotonicMs());
    try std.testing.expect(!signals.log_reopen_requested.load(.acquire));

    // Deadline still ahead and no new signal: leave the fd alone.
    sink.maybeReopen(io);
    try std.testing.expectEqual(retry_at, sink.reopen_retry_at_ms.load(.acquire));
    try std.testing.expectEqual(warned_at, sink.last_reopen_warn_ms);
    try std.testing.expectEqual(original_fd, sink.fd.load(.acquire));

    // A fresh SIGUSR1 retries immediately but must not warn again.
    const sentinel = nowMonotonicMs() + 1_000_000;
    sink.reopen_retry_at_ms.store(sentinel, .release);
    signals.log_reopen_requested.store(true, .release);
    sink.maybeReopen(io);
    try std.testing.expect(!signals.log_reopen_requested.load(.acquire));
    try std.testing.expect(sink.reopen_retry_at_ms.load(.acquire) < sentinel);
    try std.testing.expectEqual(warned_at, sink.last_reopen_warn_ms);
    try std.testing.expectEqual(original_fd, sink.fd.load(.acquire));

    // Deadline alone retries, still inside the warn window.
    sink.reopen_retry_at_ms.store(nowMonotonicMs() - 1, .release);
    sink.maybeReopen(io);
    const after_deadline = sink.reopen_retry_at_ms.load(.acquire);
    const now = nowMonotonicMs();
    try std.testing.expect(after_deadline >= now);
    try std.testing.expect(after_deadline <= now + warn_min_interval_ms);
    try std.testing.expectEqual(warned_at, sink.last_reopen_warn_ms);
    try std.testing.expectEqual(original_fd, sink.fd.load(.acquire));

    var kept_read: [2048]u8 = undefined;
    const kept_body = try tmp.dir.readFile(io, "d/kept.jsonl", &kept_read);
    try std.testing.expect(std.mem.indexOf(u8, kept_body, "\"operation\":\"before-fail\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, kept_body, "\"operation\":\"during-fail\"") != null);
    var other_read: [256]u8 = undefined;
    const other_body = try tmp.dir.readFile(io, "d/other.jsonl", &other_read);
    try std.testing.expect(std.mem.indexOf(u8, other_body, "during-fail") == null);

    try tmp.dir.deleteFile(io, "d/audit.jsonl");
    sink.reopen_retry_at_ms.store(nowMonotonicMs() - 1, .release);
    signals.log_reopen_requested.store(false, .release);
    sink.log(io, "u", "after-ok", null, .ok, "", "203.0.113.9");

    const new_fd = sink.fd.load(.acquire);
    try std.testing.expect(new_fd >= 0 and new_fd != original_fd);
    try std.testing.expectEqual(@as(i64, 0), sink.reopen_retry_at_ms.load(.acquire));
    try std.testing.expect(std.c.write(original_fd, "x", 1) < 0);

    var new_read: [2048]u8 = undefined;
    const new_body = try tmp.dir.readFile(io, "d/audit.jsonl", &new_read);
    try std.testing.expect(std.mem.indexOf(u8, new_body, "\"operation\":\"after-ok\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, new_body, "during-fail") == null);
    try std.testing.expect(std.mem.indexOf(u8, new_body, "before-fail") == null);
    var kept_again_buf: [2048]u8 = undefined;
    const kept_again = try tmp.dir.readFile(io, "d/kept.jsonl", &kept_again_buf);
    try std.testing.expect(std.mem.indexOf(u8, kept_again, "\"operation\":\"after-ok\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, kept_again, "\"operation\":\"during-fail\"") != null);
}
