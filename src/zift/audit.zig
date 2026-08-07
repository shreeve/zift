//! Structured audit log for Zift (PLAN §8.5).
//!
//! One JSON object per line, single-write to a destination shared by
//! every worker thread. Default destination is stderr; an absolute file
//! path may be configured (`server.log`) and is reopened on SIGUSR1.
//!
//! Schema and field order are FIXED by PLAN §7.4. The composition
//! recipes in PLAN §11 (awk, jq, log shippers) anchor on this order:
//!
//!   {"event":"zift.audit",
//!    "user":      "<virtual-user>",        -- when known (post-auth)
//!    "operation": "<op-name>",
//!    "result":    "ok"|"denied"|"failed",
//!    "path":      "<virtual-path>",        -- when applicable
//!    "detail":    "<short-message>",       -- when non-empty
//!    "ip":        "<peer-ip>",             -- always present; "" when unknown
//!    "truncated": true                     -- iff line was clipped to 4096 B
//!   }
//!
//! `ip` is mandatory in every line so source-policy and log tools
//! always match. The only path that legitimately emits an empty `ip`
//! is the catch-all formatter fallback when the line is too long even
//! after truncation.
//!
//! Threading: writes are serialized by a process-wide mutex so JSON
//! objects never interleave on stderr or in the file. For file
//! destinations we additionally open with `O_APPEND` so each `write(2)`
//! is positioned atomically by the kernel; this matters under
//! logrotate's "rename old, signal, recreate" sequence and under any
//! other writer touching the same path.

const std = @import("std");
const config = @import("config.zig");
const signals = @import("signals.zig");

pub const Result = enum { ok, denied, failed };

/// PLAN §8.5: 4096-byte cap on each audit line. Lines that would exceed
/// this are truncated with a `"truncated":true` marker.
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
    /// File fd when target is `.file`; -1 otherwise. Loaded with
    /// `acquire` ordering on every write so SIGUSR1-driven reopens
    /// are visible to other threads without a per-write mutex on the
    /// fd itself (the mutex below already serializes writes).
    fd: std.atomic.Value(c_int) = .init(-1),
    /// Serializes writes so concurrent worker threads cannot interleave
    /// JSON objects in a single audit line. Also held during reopen.
    mutex: std.Io.Mutex = .init,
    /// Stable storage for the file-target path so the Sink owns its
    /// strings — the config snapshot may be torn down underneath us.
    owned_path: ?[]const u8 = null,

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

    /// Honor SIGUSR1 (PLAN §7.2) by atomically swapping in a fresh fd
    /// pointing at the configured path. Called from `log` so the next
    /// write after the signal goes to the new fd — no separate
    /// log-rotator thread. Lazy semantics: a low-traffic server with
    /// SIGUSR1 pending holds the old fd open until the next audit
    /// line; logrotate operators should account for that.
    fn maybeReopen(self: *Sink, io: std.Io) void {
        if (!signals.log_reopen_requested.swap(false, .acq_rel)) return;

        // Only file targets have a fd to reopen; stderr is always open.
        const path = switch (self.target) {
            .stderr => return,
            .file => |p| p,
        };

        self.mutex.lockUncancelable(io);
        const new_fd = openLogFile(path) catch |err| {
            self.mutex.unlock(io);
            writeStderrRaw("zift: audit log reopen failed: ");
            writeStderrRaw(@errorName(err));
            writeStderrRaw("\n");
            return;
        };
        const old_fd = self.fd.swap(new_fd, .acq_rel);
        self.mutex.unlock(io);

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

    /// Single-`write(2)` emission for both targets. PLAN §7.4 requires
    /// each audit line to land in one syscall so concurrent threads
    /// (and concurrent processes, on file destinations with `O_APPEND`)
    /// cannot interleave inside a single JSON object.
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

/// Non-JSON, single-syscall stderr complaint when audit writes fail.
/// We deliberately do not try to recurse through the audit pipeline
/// for self-reporting — that would risk recursive lock/format errors
/// during a real outage. Operators see the bare line on stderr.
///
/// Rate-limited to at most one stderr line per `warn_min_interval_ms`
/// (default 5 s) so a runaway destination (full disk, broken pipe to
/// supervisor) can't itself cause a stderr storm. The first failure
/// in any window is always logged; subsequent failures within the
/// window are silently dropped.
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

fn nowMonotonicMs() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), std.time.ns_per_ms);
}

/// Single-syscall raw stderr write. Used for audit-pipeline diagnostic
/// output so we never recurse through the audit pipeline itself.
fn writeStderrRaw(text: []const u8) void {
    _ = std.c.write(2, text.ptr, text.len);
}

fn openLogFile(path: []const u8) !c_int {
    // Local null-terminated copy for libc open().
    var path_z: [4096]u8 = undefined;
    if (path.len >= path_z.len) return error.PathTooLong;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;

    const flags: std.posix.O = .{
        .ACCMODE = .WRONLY,
        .APPEND = true,
        .CREAT = true,
        .CLOEXEC = true,
    };
    const mode: std.posix.mode_t = 0o640;
    const fd = std.c.open(@ptrCast(&path_z), flags, mode);
    if (fd < 0) return error.OpenFailed;
    return fd;
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

/// Process-wide audit log call. Defaults to stderr until `initGlobal`
/// runs, so unit tests and any pre-init failure path still produce
/// audit lines.
///
/// Argument order matches PLAN §7.4's stable JSON field order so the
/// call site reads top-to-bottom in the same order the line emits.
/// `ip` is mandatory (pass "" when unknown — only legitimate at the
/// formatter's catch-all fallback path).
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
    // First attempt: full line, no truncation marker.
    {
        var w = std.Io.Writer.fixed(buf);
        if (formatLineImpl(&w, user, operation, path, result, detail, ip, false)) |_| {
            return w.buffered();
        } else |_| {}
    }

    // Second attempt: detail is the most likely offender — replace it
    // with a sentinel and set `truncated`. Preserves all required
    // PLAN §7.4 fields (event/user/operation/result/ip).
    {
        var w = std.Io.Writer.fixed(buf);
        if (formatLineImpl(&w, user, operation, path, result, "[truncated]", ip, true)) |_| {
            return w.buffered();
        } else |_| {}
    }

    // Third attempt: also drop `path` (rare — only triggers when the
    // virtual path is huge AND detail was already gone).
    {
        var w = std.Io.Writer.fixed(buf);
        if (formatLineImpl(&w, user, operation, null, result, "", ip, true)) |_| {
            return w.buffered();
        } else |_| {}
    }

    // Fourth attempt: minimal line preserving only the required fields
    // PLAN §7.4 mandates. `ip` is preserved so source-aware tools and
    // regexes still match an over-budget line.
    {
        var w = std.Io.Writer.fixed(buf);
        if (formatLineImpl(&w, null, operation, null, result, "", ip, true)) |_| {
            return w.buffered();
        } else |_| {}
    }

    // Last-resort hard-coded sentinel. Used only if `operation` itself
    // is huge and even the minimal line won't fit. Emits valid JSON so
    // log-line consumers don't choke.
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
    // v0.7.0 stable order: time, event, user, operation, result,
    // path, detail, ip, [truncated]. `time` is required and emitted
    // first so log readers can sort/filter by event time without
    // parsing the rest of the line — and so off-host log shippers
    // (rsyslog, vector, etc.) get a real timestamp instead of
    // falling back on file mtime.
    var time_buf: [time_buf_len]u8 = undefined;
    const time_str = formatNowRfc3339Utc(&time_buf);
    try w.writeAll("{\"time\":\"");
    try w.writeAll(time_str);
    try w.writeAll("\",\"event\":\"zift.audit\"");
    if (user) |value| {
        try w.writeAll(",\"user\":");
        try std.json.Stringify.encodeJsonString(value, .{}, w);
    }
    try w.writeAll(",\"operation\":");
    try std.json.Stringify.encodeJsonString(operation, .{}, w);
    try w.writeAll(",\"result\":\"");
    try w.writeAll(@tagName(result));
    try w.writeAll("\"");
    if (path) |value| {
        try w.writeAll(",\"path\":");
        try std.json.Stringify.encodeJsonString(value, .{}, w);
    }
    if (detail.len != 0) {
        try w.writeAll(",\"detail\":");
        try std.json.Stringify.encodeJsonString(detail, .{}, w);
    }
    try w.writeAll(",\"ip\":");
    try std.json.Stringify.encodeJsonString(ip, .{}, w);
    if (truncated) try w.writeAll(",\"truncated\":true");
    try w.writeAll("}\n");
}

/// Length of an RFC 3339 UTC timestamp with millisecond precision:
/// `YYYY-MM-DDTHH:MM:SS.mmmZ` is exactly 24 bytes.
const time_buf_len: usize = 24;

/// Format the current wall-clock time as RFC 3339 / ISO 8601 UTC
/// with millisecond precision. Writes exactly `time_buf_len` bytes
/// to `buf` and returns the same slice. The result is lexically
/// sortable and used as the leading field of every audit line.
///
/// Reads `clock_gettime(CLOCK_REALTIME)` and falls back to the
/// epoch sentinel `1970-01-01T00:00:00.000Z` if the syscall fails
/// (extremely rare in practice — Linux/macOS guarantee `REALTIME`
/// — but skipping the timestamp on failure would give us undefined
/// stack bytes formatted as digits, which is worse).
fn formatNowRfc3339Utc(buf: *[time_buf_len]u8) []const u8 {
    var ts: std.c.timespec = .{ .sec = 0, .nsec = 0 };
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return formatRfc3339Utc(buf, ts.sec, ts.nsec);
}

/// Same as `formatNowRfc3339Utc` but takes the timestamp as input
/// — pure (no `clock_gettime`), test-friendly. Production callers
/// use the `Now` wrapper above.
///
/// Date math uses Howard Hinnant's `civil_from_days` algorithm
/// (same one `listing.zig` uses for `breakTime` formatting). O(1),
/// works for any `i64` second count we'll plausibly encounter.
/// Year is clamped to `[0, 9999]` so the output stays at exactly
/// 24 bytes even for absurd input — RFC 3339 doesn't define
/// negative years and we'd rather emit `0000` or `9999` than
/// silently produce a wrong-length line that breaks the field-
/// position invariants the rest of the audit pipeline relies on.
///
/// The hand-rolled digit emission below is deliberate: by writing
/// the exact 24-byte layout one field at a time, the buffer-size
/// invariant becomes obvious by inspection and we don't depend on
/// any quirks of `std.fmt`'s width handling in this hot audit path.
fn formatRfc3339Utc(buf: *[time_buf_len]u8, sec: i64, nsec_in: i64) []const u8 {
    // Normalize nsec into [0, 1_000_000_000) without panicking on
    // negative nsec. `clock_gettime` shouldn't ever return that
    // shape, but we accept it as a defensive measure for the
    // test-friendly entry point.
    var nsec: i64 = nsec_in;
    if (nsec < 0) nsec = 0;
    if (nsec >= std.time.ns_per_s) nsec = std.time.ns_per_s - 1;
    const ms: u32 = @intCast(@divTrunc(nsec, std.time.ns_per_ms));

    const civil = civilFromUnix(sec);
    const sec_of_day: u32 = @intCast(@mod(sec, 86400));
    const hour: u32 = @divTrunc(sec_of_day, 3600);
    const minute: u32 = @divTrunc(@mod(sec_of_day, 3600), 60);
    const second: u32 = @mod(sec_of_day, 60);

    // Clamp the year into [0, 9999] so the output stays exactly
    // 4 digits. For sane Unix timestamps this is a no-op.
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

/// Write a fixed-width zero-padded decimal into `dst`. Caller
/// guarantees `value` fits in `dst.len` digits. Used by
/// `formatNowRfc3339Utc` for the year/month/day/hour/min/sec/ms
/// fields, all of which have known small ranges.
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

/// Howard Hinnant's `civil_from_days` algorithm, adapted for Unix
/// epoch input. Floor-division semantics handle pre-1970 input
/// correctly. Same algorithm as `listing.breakTime`; duplicated here
/// to avoid an audit-on-formatting cross-module dependency.
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

test "audit line follows PLAN field order" {
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
    // The leading time field is exactly time_buf_len bytes between the quotes.
    try std.testing.expect(std.mem.startsWith(u8, line, "{\"time\":\""));
    // After `{"time":"` (9 bytes), the timestamp ends with `Z"`.
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
