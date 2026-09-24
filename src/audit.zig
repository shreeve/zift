//! Structured audit log: one JSON object per line (see docs/operate.md).
//!
//! Field order is fixed so awk/jq recipes can anchor on it:
//!   time, event, user?, operation, result, path?, detail?, ip, truncated?
//! `ip` is always present ("" when unknown); `truncated` marks a line
//! clipped to 4096 bytes.
//!
//! Lines are written whole under a process-wide mutex, so they never
//! interleave. The destination is stderr or an absolute path opened
//! O_APPEND|O_NOFOLLOW and reopened on SIGUSR1: a regular file, a FIFO
//! (a log shipper) or a character device (/dev/null). A symlink,
//! directory, socket or block device is refused; mode 0640 is set only
//! on a file this process created.

const std = @import("std");
const builtin = @import("builtin");
const config = @import("config.zig");
const signals = @import("signals.zig");
const sys = @import("sys.zig");

pub const Result = enum { ok, denied, failed };

/// Longer lines are shortened and marked `"truncated":true`.
const max_line_bytes: usize = 4096;

pub const Sink = struct {
    /// Owned copy of the `.file` path (the config may be freed on
    /// reload); null when the sink is stderr.
    path: ?[:0]u8 = null,
    /// Destination fd, guarded by `mutex` and swapped on reopen.
    fd: c_int = std.posix.STDERR_FILENO,
    /// Serializes writes and reopen.
    mutex: std.Io.Mutex = .init,
    /// Monotonic ms when a failed reopen is retried; 0 = none pending.
    /// A deadline, not a re-raised signal flag, so a broken path does
    /// not retry (and warn) on every audit line. Atomic because the
    /// lock-free fast path in `maybeReopen` reads it.
    reopen_retry_at_ms: std.atomic.Value(i64) = .init(0),
    /// Monotonic ms of the last reopen-failure and write-failure stderr
    /// lines, guarded by `mutex`. 0 means none reported yet.
    last_reopen_warn_ms: i64 = 0,
    last_write_warn_ms: i64 = 0,

    pub fn initFromConfig(
        io: std.Io,
        allocator: std.mem.Allocator,
        target: config.LogTarget,
    ) !Sink {
        switch (target) {
            .stderr => return .{},
            .file => |path| {
                const owned = try allocator.dupeZ(u8, path);
                errdefer allocator.free(owned);
                var why: OpenFailure = undefined;
                const fd = openLogFile(io, owned, &why) catch |err| {
                    note(io, "zift: cannot open audit log {s}: {f}\n", .{ owned, why });
                    return err;
                };
                return .{ .path = owned, .fd = fd };
            },
        }
    }

    pub fn deinit(self: *Sink, allocator: std.mem.Allocator) void {
        if (self.path) |path| {
            _ = std.c.close(self.fd);
            allocator.free(path);
        }
        self.* = .{};
    }

    /// Honor SIGUSR1 lazily: the next audit line after the signal swaps
    /// in a fresh fd, so an idle server keeps the old fd until then. On
    /// open failure the old fd stays in use and a retry is scheduled.
    fn maybeReopen(self: *Sink, io: std.Io) void {
        const signaled = signals.log_reopen_requested.load(.acquire);
        if (!signaled) {
            const retry_at = self.reopen_retry_at_ms.load(.acquire);
            if (retry_at == 0 or sys.monotonicMs() < retry_at) return;
        }

        const path = self.path orelse {
            _ = signals.log_reopen_requested.swap(false, .acq_rel);
            self.reopen_retry_at_ms.store(0, .release);
            return;
        };

        self.mutex.lockUncancelable(io);
        // Consume the signal under the mutex so two writers cannot both
        // open; a signal arriving during the open is honored next line.
        const signaled_now = signals.log_reopen_requested.swap(false, .acq_rel);
        const retry_at_now = self.reopen_retry_at_ms.load(.acquire);
        if (!signaled_now and (retry_at_now == 0 or sys.monotonicMs() < retry_at_now)) {
            self.mutex.unlock(io);
            return;
        }

        // Cannot block: the open is O_NONBLOCK, so a FIFO without a
        // reader fails with ENXIO instead of wedging every thread that
        // waits on this mutex.
        var why: OpenFailure = undefined;
        const new_fd = openLogFile(io, path, &why) catch {
            const failed_at = sys.monotonicMs();
            self.reopen_retry_at_ms.store(failed_at + warn_min_interval_ms, .release);
            const warn = self.last_reopen_warn_ms == 0 or
                failed_at - self.last_reopen_warn_ms >= warn_min_interval_ms;
            if (warn) self.last_reopen_warn_ms = failed_at;
            self.mutex.unlock(io);
            if (warn) note(io, "zift: audit log reopen failed: {s}: {f}; retrying\n", .{ path, why });
            return;
        };

        self.reopen_retry_at_ms.store(0, .release);
        const old_fd = self.fd;
        self.fd = new_fd;
        self.mutex.unlock(io);

        // Close after the swap; the caller's line goes to the new fd.
        _ = std.c.close(old_fd);
        note(io, "zift: audit log reopened\n", .{});
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

    fn write(self: *Sink, io: std.Io, line: []const u8) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.fd < 0) return; // the discarding test-time global sink
        const err = writeLine(self.fd, line) orelse return;

        // Reported as a bare stderr line, never through the audit
        // pipeline itself, and at most once per interval so a full disk
        // cannot turn into a stderr storm.
        const now = sys.monotonicMs();
        if (self.last_write_warn_ms != 0 and now - self.last_write_warn_ms < warn_min_interval_ms) return;
        self.last_write_warn_ms = now;
        note(io, "zift: audit write failed: {f}\n", .{OpenFailure{ .errno = err }});
    }
};

const warn_min_interval_ms: i64 = 5_000;

/// Write all of `line`, resuming after short writes (a signal on a pipe,
/// a nearly full disk). A write that fails partway ends the fragment
/// with a newline, so the next line still starts clean for every
/// line-oriented consumer. Returns the errno of a failure.
fn writeLine(fd: c_int, line: []const u8) ?std.posix.E {
    var done: usize = 0;
    while (done < line.len) {
        const n = std.c.write(fd, line[done..].ptr, line.len - done);
        if (n > 0) {
            done += @intCast(n);
            continue;
        }
        const err: std.posix.E = if (n < 0) std.posix.errno(n) else .IO;
        if (err == .INTR) continue;
        if (done > 0) _ = std.c.write(fd, "\n", 1);
        return err;
    }
    return null;
}

/// Best effort: a diagnostic that cannot be written is not worth failing
/// an audit write over. (`sys.note` is silent under `zig build test`.)
fn note(io: std.Io, comptime fmt: []const u8, args: anytype) void {
    sys.note(io, fmt, args) catch {};
}

/// Why `openLogFile` refused a path, worded for the operator.
const OpenFailure = union(enum) {
    errno: std.posix.E,
    /// Opened, but not a regular file, FIFO or character device.
    bad_kind: std.Io.File.Kind,

    pub fn format(self: OpenFailure, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .bad_kind => |kind| try w.print(
                "is a {t}; use a regular file, FIFO or character device",
                .{kind},
            ),
            .errno => |e| {
                const why: []const u8 = switch (e) {
                    .LOOP => "is a symlink, which is refused",
                    .NXIO => "FIFO has no reader (start the reader first), or it is a socket",
                    .ISDIR => "is a directory",
                    .ACCES, .PERM => "permission denied",
                    .NOENT => "parent directory does not exist",
                    .ROFS => "read-only file system",
                    .NOSPC => "no space left on device",
                    .PIPE => "reader closed the pipe",
                    else => "failed",
                };
                try w.writeAll(why);
                if (std.enums.tagName(std.posix.E, e)) |name| {
                    try w.print(" (E{s})", .{name});
                } else {
                    try w.print(" (errno {d})", .{@intFromEnum(e)});
                }
            },
        }
    }
};

/// Open (or create) the audit log for appending.
///
/// O_NONBLOCK keeps the open itself from blocking on a FIFO that has no
/// reader: it fails with ENXIO at once, so startup fails loudly and a
/// reopen falls back to its retry. The flag is cleared once open, so
/// writes block (backpressure) exactly as they do on stderr.
fn openLogFile(io: std.Io, path: [:0]const u8, why: *OpenFailure) error{AuditLogOpenFailed}!c_int {
    if (std.mem.indexOfScalar(u8, path, 0) != null) {
        why.* = .{ .errno = .INVAL };
        return error.AuditLogOpenFailed;
    }
    const mode: std.posix.mode_t = 0o640;
    const flags: std.c.O = .{
        .ACCMODE = .WRONLY,
        .APPEND = true,
        .CLOEXEC = true,
        .NOFOLLOW = true,
        .NONBLOCK = true,
    };
    // EXCL tells "created here" (pin 0640) from "already there" (leave
    // its mode). O_CREAT|O_EXCL returns EEXIST on a symlink, so the
    // NOFOLLOW open below is what rejects one.
    var create = flags;
    create.CREAT = true;
    create.EXCL = true;
    var fd = std.c.open(path, create, mode);
    const created = fd >= 0;
    if (!created) {
        const err = std.posix.errno(fd);
        if (err != .EXIST) {
            why.* = .{ .errno = err };
            return error.AuditLogOpenFailed;
        }
        fd = std.c.open(path, flags);
        if (fd < 0) {
            why.* = .{ .errno = std.posix.errno(fd) };
            return error.AuditLogOpenFailed;
        }
    }
    errdefer _ = std.c.close(fd);

    const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
    const st = file.stat(io) catch {
        why.* = .{ .errno = .IO };
        return error.AuditLogOpenFailed;
    };
    switch (st.kind) {
        .file, .named_pipe, .character_device => {},
        else => |kind| {
            why.* = .{ .bad_kind = kind };
            return error.AuditLogOpenFailed;
        },
    }
    if (created and std.c.fchmod(fd, mode) != 0) {
        why.* = .{ .errno = std.posix.errno(-1) };
        return error.AuditLogOpenFailed;
    }
    const fl = std.c.fcntl(fd, std.c.F.GETFL);
    const nonblock: c_int = @bitCast(std.c.O{ .NONBLOCK = true });
    if (fl < 0 or std.c.fcntl(fd, std.c.F.SETFL, fl & ~nonblock) < 0) {
        why.* = .{ .errno = std.posix.errno(-1) };
        return error.AuditLogOpenFailed;
    }
    return fd;
}

// ----- process-wide singleton ----------------------------------------------

/// Unit tests of other modules reach `log` through this sink before any
/// `initGlobal`; under test it discards so their audit lines do not land
/// on the test runner's stderr.
var global_sink: Sink = .{ .fd = if (builtin.is_test) -1 else std.posix.STDERR_FILENO };

pub fn initGlobal(
    io: std.Io,
    allocator: std.mem.Allocator,
    target: config.LogTarget,
) !void {
    global_sink = try Sink.initFromConfig(io, allocator, target);
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
    // The full line; else clip detail to fit; else also drop path; else
    // also drop user.
    const Try = struct { user: bool, path: bool, truncated: bool };
    const tries = [_]Try{
        .{ .user = true, .path = true, .truncated = false },
        .{ .user = true, .path = true, .truncated = true },
        .{ .user = true, .path = false, .truncated = true },
        .{ .user = false, .path = false, .truncated = true },
    };
    for (tries) |t| {
        var w = std.Io.Writer.fixed(buf);
        formatLineImpl(
            &w,
            if (t.user) user else null,
            operation,
            if (t.path) path else null,
            result,
            detail,
            ip,
            t.truncated,
        ) catch continue;
        return w.buffered();
    }

    // Only a huge `operation` or `ip` gets here. Still valid JSON.
    const fallback = "{\"event\":\"zift.audit\",\"operation\":\"?\",\"result\":\"failed\",\"ip\":\"\",\"truncated\":true}\n";
    const len = @min(fallback.len, buf.len);
    @memcpy(buf[0..len], fallback[0..len]);
    return buf[0..len];
}

const truncated_tail = ",\"truncated\":true}\n";

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
        try writeJsonString(w, value, null);
    }
    try w.writeAll(",\"operation\":");
    try writeJsonString(w, operation, null);
    try w.writeAll(",\"result\":\"");
    try w.writeAll(@tagName(result));
    try w.writeAll("\"");
    if (path) |value| {
        try w.writeAll(",\"path\":");
        try writeJsonString(w, value, null);
    }
    const ip_key = ",\"ip\":";
    if (detail.len != 0) {
        const detail_key = ",\"detail\":";
        if (!truncated) {
            try w.writeAll(detail_key);
            try writeJsonString(w, detail, null);
        } else {
            // Keep as much of the detail as fits in front of the fixed
            // tail, rather than losing all of it to a few bytes over.
            const tail = ip_key.len + jsonStringLen(ip) + truncated_tail.len;
            const room = w.buffer.len -| (w.end + detail_key.len + tail);
            if (room > 2) {
                try w.writeAll(detail_key);
                try writeJsonString(w, detail, room);
            }
        }
    }
    try w.writeAll(ip_key);
    try writeJsonString(w, ip, null);
    try w.writeAll(if (truncated) truncated_tail else "}\n");
}

/// Emit `s` as a JSON string, replacing invalid UTF-8 with U+FFFD.
/// With a `limit`, the string (quotes included) is cut at a character
/// boundary to fit in that many bytes.
///
/// Usernames and paths are raw partner-supplied bytes. std's encoder
/// passes invalid UTF-8 through (making the line invalid JSON, which jq
/// and strict shippers drop, hiding the event) or panics with
/// `escape_unicode`, so we sanitize while encoding.
fn writeJsonString(w: *std.Io.Writer, s: []const u8, limit: ?usize) !void {
    try w.writeByte('"');
    var used: usize = 2;
    var i: usize = 0;
    while (i < s.len) {
        var scratch: [6]u8 = undefined;
        const encoded, const consumed = encodeChar(s, i, &scratch);
        if (limit) |max| {
            if (used + encoded.len > max) break;
            used += encoded.len;
        }
        try w.writeAll(encoded);
        i += consumed;
    }
    try w.writeByte('"');
}

fn jsonStringLen(s: []const u8) usize {
    var counter = std.Io.Writer.Discarding.init(&.{});
    writeJsonString(&counter.writer, s, null) catch unreachable;
    return @intCast(counter.fullCount());
}

/// The character of `s` at `i` as it appears inside a JSON string, and
/// the number of input bytes it consumes.
fn encodeChar(s: []const u8, i: usize, scratch: *[6]u8) struct { []const u8, usize } {
    const replacement = "\u{FFFD}";
    const b = s[i];
    if (b < 0x80) {
        const escaped: []const u8 = switch (b) {
            '"' => "\\\"",
            '\\' => "\\\\",
            0x08 => "\\b",
            0x0C => "\\f",
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            0x00...0x07, 0x0B, 0x0E...0x1F, 0x7F => unicodeEscape(scratch, b),
            else => s[i..][0..1],
        };
        return .{ escaped, 1 };
    }
    const len = std.unicode.utf8ByteSequenceLength(b) catch return .{ replacement, 1 };
    if (i + len > s.len) return .{ replacement, 1 };
    const cp = std.unicode.utf8Decode(s[i..][0..len]) catch return .{ replacement, 1 };
    return switch (cp) {
        // Valid JSON raw, but they break lines or reorder text for the
        // tools that read audit logs: C1 controls (U+0085 NEL splits
        // lines in Python, U+009B is a terminal CSI), the JavaScript
        // line separators, and bidi overrides that let a filename
        // visually rearrange the path shown by `tail -F`.
        0x80...0x9F, 0x2028, 0x2029, 0x202A...0x202E, 0x2066...0x2069 => .{ unicodeEscape(scratch, cp), len },
        else => .{ s[i..][0..len], len },
    };
}

fn unicodeEscape(scratch: *[6]u8, cp: u21) []const u8 {
    return std.fmt.bufPrint(scratch, "\\u{x:0>4}", .{cp}) catch unreachable;
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ`.
const time_buf_len: usize = 24;

/// Current wall-clock time as RFC 3339 UTC with milliseconds. A failed
/// clock read yields the epoch rather than garbage digits.
fn formatNowRfc3339Utc(buf: *[time_buf_len]u8) []const u8 {
    const ts = sys.realtime();
    return formatRfc3339Utc(buf, ts.sec, ts.nsec);
}

/// Pure form of `formatNowRfc3339Utc`. The year is clamped to
/// [0, 9999] so the field is always exactly 24 bytes.
fn formatRfc3339Utc(buf: *[time_buf_len]u8, sec: i64, nsec_in: i64) []const u8 {
    var nsec: i64 = nsec_in;
    if (nsec < 0) nsec = 0;
    if (nsec >= std.time.ns_per_s) nsec = std.time.ns_per_s - 1;
    const ms: u32 = @intCast(@divTrunc(nsec, std.time.ns_per_ms));

    const t = sys.civil(sec);
    writeFixedDigits(buf[0..4], @intCast(std.math.clamp(t.year, 0, 9999)));
    buf[4] = '-';
    writeFixedDigits(buf[5..7], t.month);
    buf[7] = '-';
    writeFixedDigits(buf[8..10], t.day);
    buf[10] = 'T';
    writeFixedDigits(buf[11..13], t.hour);
    buf[13] = ':';
    writeFixedDigits(buf[14..16], t.minute);
    buf[16] = ':';
    writeFixedDigits(buf[17..19], t.second);
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

// ----- tests ---------------------------------------------------------------

/// Every audit line must be one JSON object on one line, valid UTF-8,
/// within the cap: what jq and log shippers need to keep the event.
fn expectWellFormedLine(line: []const u8) !void {
    try std.testing.expect(line.len <= max_line_bytes);
    try std.testing.expectEqual(line.len - 1, std.mem.indexOfScalar(u8, line, '\n').?);
    try std.testing.expect(std.unicode.utf8ValidateSlice(line));
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, line, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value == .object);
}

fn expectField(line: []const u8, key: []const u8, want: []const u8) !void {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, line, .{});
    defer parsed.deinit();
    const got = parsed.value.object.get(key) orelse return error.TestExpectedField;
    try std.testing.expectEqualStrings(want, got.string);
}

test "audit line stays valid JSON for invalid-UTF-8 path" {
    var buf: [max_line_bytes]u8 = undefined;
    // A filename with a lone 0xFF byte (invalid UTF-8) plus an embedded
    // quote and newline to exercise escaping.
    const nasty = "/pending/\xff\x22\x0aevil";
    const line = formatLine(&buf, "foo", "open_write", nasty, .denied, "", "127.0.0.1");
    try expectWellFormedLine(line);
    try expectField(line, "path", "/pending/\u{FFFD}\"\nevil");
}

test "audit line escapes characters that split or reorder lines" {
    var buf: [max_line_bytes]u8 = undefined;
    // NEL (C1), LINE SEPARATOR, RIGHT-TO-LEFT OVERRIDE, DEL, and an
    // ordinary non-ASCII letter that must pass through untouched.
    const name = "/in/a\u{85}b\u{2028}c\u{202E}d\x7fé";
    const line = formatLine(&buf, "ally", "write", name, .ok, "", "");
    try expectWellFormedLine(line);
    try std.testing.expect(std.mem.indexOf(u8, line, "a\\u0085b\\u2028c\\u202ed\\u007fé") != null);
    try expectField(line, "path", name);
}

test "audit line escapes special characters" {
    var buf: [256]u8 = undefined;
    const line = formatLine(&buf, "ally", "open_write", "/pending/\"weird\"\nfile", .ok, "size=11", "10.0.0.1");
    try std.testing.expect(std.mem.indexOf(u8, line, "\\\"weird\\\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\\n") != null);
    try expectWellFormedLine(line);
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
        // March 1 outside an era's first century (was a day early).
        .{ .sec = 5_097_600, .nsec = 0, .want = "1970-03-01T00:00:00.000Z" },
        .{ .sec = 4_107_542_400, .nsec = 0, .want = "2100-03-01T00:00:00.000Z" },
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

test "audit line clips detail to fit the line cap" {
    var buf: [max_line_bytes]u8 = undefined;
    var huge: [max_line_bytes]u8 = undefined;
    @memset(&huge, 'x');
    const line = formatLine(&buf, "ally", "write", "/tmp/foo", .ok, &huge, "10.0.0.1");
    try expectWellFormedLine(line);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"truncated\":true") != null);
    try expectField(line, "ip", "10.0.0.1");
    try expectField(line, "path", "/tmp/foo");
    // Clipped, not replaced: nearly the whole line budget is detail.
    try std.testing.expect(std.mem.indexOf(u8, line, "\"detail\":\"xxxx") != null);
    try std.testing.expect(line.len > max_line_bytes - 8);
}

test "audit detail clipping never splits a character or an escape" {
    var buf: [max_line_bytes]u8 = undefined;
    // Each unit is a 3-byte character or a 6-byte escape, so the cut
    // lands mid-unit for some offset in this range.
    var detail: [max_line_bytes]u8 = undefined;
    var i: usize = 0;
    while (i + 3 <= detail.len) : (i += 3) @memcpy(detail[i..][0..3], "\u{20AC}");
    for (0..8) |pad| {
        const user = "u" ** 8;
        const line = formatLine(&buf, user[0..pad], "write", null, .ok, detail[0..i], "10.0.0.1");
        try expectWellFormedLine(line);
    }
    @memset(&detail, 0x01);
    for (0..8) |pad| {
        const user = "u" ** 8;
        const line = formatLine(&buf, user[0..pad], "write", null, .ok, &detail, "10.0.0.1");
        try expectWellFormedLine(line);
    }
}

test "fuzz audit line" {
    return std.testing.fuzz({}, fuzzAuditLine, .{ .corpus = &.{
        "ally\x00write\x00/in/\xff\"\n\x00size=1\xc2\x85\x00203.0.113.7",
        "\x00\x00\xe2\x80\xa8\x00\xe2\x80\xae\x00",
    } });
}

// Input is `user\x00operation\x00path\x00detail\x00ip`; a missing field
// is null (user, path) or empty.
fn fuzzAuditLine(_: void, smith: *std.testing.Smith) !void {
    var input: [2 * max_line_bytes]u8 = undefined;
    const len = smith.sliceWithHash(&input, 0xA0D17106);
    var fields = std.mem.splitScalar(u8, input[0..len], 0);
    const user = fields.next();
    const operation = fields.next() orelse "";
    const path = fields.next();
    const detail = fields.next() orelse "";
    const ip = fields.rest();
    var buf: [max_line_bytes]u8 = undefined;
    try expectWellFormedLine(formatLine(&buf, user, operation, path, .ok, detail, ip));
}

test "writeLine resumes after a short write and ends a failed line" {
    var fds: [2]c_int = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.pipe(&fds));
    defer _ = std.c.close(fds[0]);
    const line = "{\"a\":1}\n";
    try std.testing.expectEqual(@as(?std.posix.E, null), writeLine(fds[1], line));
    var got: [16]u8 = undefined;
    try std.testing.expectEqual(@as(isize, line.len), std.c.read(fds[0], &got, got.len));
    try std.testing.expectEqualStrings(line, got[0..line.len]);

    // A closed fd fails before any byte, so there is no fragment to end.
    _ = std.c.close(fds[1]);
    try std.testing.expectEqual(@as(?std.posix.E, .BADF), writeLine(fds[1], line));
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

const TestProbe = struct {
    extern "c" fn mkfifo(path: [*:0]const u8, mode: std.posix.mode_t) c_int;

    fn perm(path: [:0]const u8) !u32 {
        const st = try std.Io.Dir.cwd().statFile(std.testing.io, path, .{ .follow_symlinks = false });
        return @as(u32, @intCast(st.permissions.toMode())) & 0o777;
    }

    fn fdPerm(fd: c_int) !u32 {
        const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
        const st = try file.stat(std.testing.io);
        return @as(u32, @intCast(st.permissions.toMode())) & 0o777;
    }

    fn open(path: [:0]const u8) !c_int {
        var why: OpenFailure = undefined;
        return openLogFile(std.testing.io, path, &why);
    }

    fn openFails(path: [:0]const u8) !OpenFailure {
        var why: OpenFailure = undefined;
        try std.testing.expectError(error.AuditLogOpenFailed, openLogFile(std.testing.io, path, &why));
        return why;
    }

    fn realDir(tmp: *std.testing.TmpDir, buf: *[std.Io.Dir.max_path_bytes]u8) ![]const u8 {
        try tmp.dir.createDir(std.testing.io, "d", .default_dir);
        const len = try tmp.dir.realPathFile(std.testing.io, "d", buf);
        return buf[0..len];
    }
};

test "openLogFile refuses symlinks and directories and pins 0640 only on create" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir = try TestProbe.realDir(&tmp, &dir_buf);

    {
        var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const path = testJoin(&buf, dir, "created.log");
        // Under umask 077 only the fchmod yields 0640.
        const old_mask = std.c.umask(0o077);
        defer _ = std.c.umask(old_mask);
        const fd = try TestProbe.open(path);
        defer _ = std.c.close(fd);
        try std.testing.expectEqual(@as(u32, 0o640), try TestProbe.fdPerm(fd));
        try std.testing.expectEqual(@as(isize, 3), std.c.write(fd, "new", 3));
    }
    {
        var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const path = testJoin(&buf, dir, "created.log");
        try std.testing.expectEqual(@as(c_int, 0), std.c.chmod(path, 0o604));
        const fd = try TestProbe.open(path);
        defer _ = std.c.close(fd);
        // Pre-existing file: append, keep its mode.
        try std.testing.expectEqual(@as(u32, 0o604), try TestProbe.fdPerm(fd));
        try std.testing.expectEqual(@as(isize, 3), std.c.write(fd, "end", 3));
    }
    {
        var got: [16]u8 = undefined;
        const body = try tmp.dir.readFile(io, "d/created.log", &got);
        try std.testing.expectEqualStrings("newend", body);
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
        try std.testing.expectEqual(OpenFailure{ .errno = .LOOP }, try TestProbe.openFails(link));
        try std.testing.expectEqual(@as(u32, 0o600), try TestProbe.perm(target));
        var got: [16]u8 = undefined;
        const body = try tmp.dir.readFile(io, "d/target.log", &got);
        try std.testing.expectEqualStrings("safe", body);
    }

    try tmp.dir.createDir(io, "d/subdir", .default_dir);
    {
        var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const path = testJoin(&buf, dir, "subdir");
        try std.testing.expectEqual(OpenFailure{ .errno = .ISDIR }, try TestProbe.openFails(path));
    }
    {
        var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const path = testJoin(&buf, dir, "missing/audit.log");
        try std.testing.expectEqual(OpenFailure{ .errno = .NOENT }, try TestProbe.openFails(path));
        var msg: [128]u8 = undefined;
        const text = try std.fmt.bufPrint(&msg, "{f}", .{OpenFailure{ .errno = .NOENT }});
        try std.testing.expectEqualStrings("parent directory does not exist (ENOENT)", text);
    }
}

test "openLogFile accepts a character device without touching its mode" {
    const before = try TestProbe.perm("/dev/null");
    const fd = try TestProbe.open("/dev/null");
    defer _ = std.c.close(fd);
    try std.testing.expectEqual(@as(isize, 3), std.c.write(fd, "bin", 3));
    try std.testing.expectEqual(before, try TestProbe.perm("/dev/null"));
}

test "openLogFile accepts a FIFO with a reader and leaves the fd blocking" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir = try TestProbe.realDir(&tmp, &dir_buf);
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = testJoin(&buf, dir, "audit.fifo");
    try std.testing.expectEqual(@as(c_int, 0), TestProbe.mkfifo(path, 0o640));
    try std.testing.expectEqual(@as(c_int, 0), std.c.chmod(path, 0o612));

    // A non-blocking read open succeeds with no writer yet, standing in
    // for a log shipper that is already listening.
    const reader = std.c.open(path, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
    try std.testing.expect(reader >= 0);
    defer _ = std.c.close(reader);

    const fd = try TestProbe.open(path);
    defer _ = std.c.close(fd);
    const nonblock: c_int = @bitCast(std.c.O{ .NONBLOCK = true });
    try std.testing.expectEqual(@as(c_int, 0), std.c.fcntl(fd, std.c.F.GETFL) & nonblock);
    try std.testing.expectEqual(@as(isize, 4), std.c.write(fd, "line", 4));
    var got: [8]u8 = undefined;
    try std.testing.expectEqual(@as(isize, 4), std.c.read(reader, &got, got.len));
    try std.testing.expectEqualStrings("line", got[0..4]);
    // Not created here, so its mode is the operator's.
    try std.testing.expectEqual(@as(u32, 0o612), try TestProbe.perm(path));
}

test "openLogFile fails fast on a FIFO with no reader" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir = try TestProbe.realDir(&tmp, &dir_buf);
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = testJoin(&buf, dir, "audit.fifo");
    try std.testing.expectEqual(@as(c_int, 0), TestProbe.mkfifo(path, 0o640));

    // Open on a thread so a regression (a blocking open) fails this test
    // instead of hanging the whole run: after the deadline a reader
    // appears, which releases a blocked open.
    const Opener = struct {
        done: std.atomic.Value(bool) = .init(false),
        why: ?OpenFailure = null,

        fn run(self: *@This(), p: [:0]const u8) void {
            var why: OpenFailure = undefined;
            if (openLogFile(std.testing.io, p, &why)) |fd| {
                _ = std.c.close(fd);
            } else |_| {
                self.why = why;
            }
            self.done.store(true, .release);
        }
    };
    var opener: Opener = .{};
    const thread = try std.Thread.spawn(.{}, Opener.run, .{ &opener, path });
    const deadline = sys.monotonicMs() + 5_000;
    while (!opener.done.load(.acquire) and sys.monotonicMs() < deadline) {
        std.Thread.yield() catch {};
    }
    const hung = !opener.done.load(.acquire);
    if (hung) {
        const unblock = std.c.open(path, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
        thread.join();
        if (unblock >= 0) _ = std.c.close(unblock);
        return error.TestOpenBlockedOnFifo;
    }
    thread.join();
    try std.testing.expectEqual(@as(?OpenFailure, .{ .errno = .NXIO }), opener.why);
}

test "reopen onto a FIFO without a reader keeps the old fd and retries" {
    const io = std.testing.io;
    const saved_flag = signals.log_reopen_requested.load(.acquire);
    defer signals.log_reopen_requested.store(saved_flag, .release);
    signals.log_reopen_requested.store(false, .release);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir = try TestProbe.realDir(&tmp, &dir_buf);
    var audit_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const audit_path = testJoin(&audit_buf, dir, "audit.log");

    var sink = try Sink.initFromConfig(io, std.testing.allocator, .{ .file = audit_path });
    defer sink.deinit(std.testing.allocator);
    const original_fd = sink.fd;

    // Rotate: the path becomes a FIFO nobody reads yet.
    try tmp.dir.rename("d/audit.log", tmp.dir, "d/audit.log.1", io);
    try std.testing.expectEqual(@as(c_int, 0), TestProbe.mkfifo(audit_path, 0o640));
    signals.log_reopen_requested.store(true, .release);
    sink.log(io, "u", "no-reader", null, .ok, "", "");
    try std.testing.expectEqual(original_fd, sink.fd);
    try std.testing.expect(sink.reopen_retry_at_ms.load(.acquire) != 0);

    // The shipper starts; the retry deadline picks the FIFO up.
    const reader = std.c.open(audit_path, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true });
    try std.testing.expect(reader >= 0);
    defer _ = std.c.close(reader);
    sink.reopen_retry_at_ms.store(sys.monotonicMs() - 1, .release);
    sink.log(io, "u", "shipped", null, .ok, "", "");
    try std.testing.expect(sink.fd != original_fd);
    var got: [max_line_bytes]u8 = undefined;
    const n = std.c.read(reader, &got, got.len);
    try std.testing.expect(n > 0);
    const line = got[0..@intCast(n)];
    try expectWellFormedLine(line);
    try expectField(line, "operation", "shipped");

    var old: [2048]u8 = undefined;
    const rotated = try tmp.dir.readFile(io, "d/audit.log.1", &old);
    try std.testing.expect(std.mem.indexOf(u8, rotated, "\"operation\":\"no-reader\"") != null);
}

test "failed audit reopen retries on a deadline without a stderr storm" {
    const io = std.testing.io;
    const saved_flag = signals.log_reopen_requested.load(.acquire);
    defer signals.log_reopen_requested.store(saved_flag, .release);
    signals.log_reopen_requested.store(false, .release);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir = try TestProbe.realDir(&tmp, &dir_buf);

    var audit_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const audit_path = testJoin(&audit_buf, dir, "audit.jsonl");
    var kept_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const kept_path = testJoin(&kept_buf, dir, "kept.jsonl");
    var other_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const other_path = testJoin(&other_buf, dir, "other.jsonl");

    var sink = try Sink.initFromConfig(io, std.testing.allocator, .{ .file = audit_path });
    defer sink.deinit(std.testing.allocator);
    const original_fd = sink.fd;
    try std.testing.expectEqual(@as(c_int, 0), std.c.link(audit_path, kept_path));

    sink.log(io, "u", "before-fail", null, .ok, "", "203.0.113.9");
    try tmp.dir.deleteFile(io, "d/audit.jsonl");
    {
        const other_fd = try TestProbe.open(other_path);
        _ = std.c.close(other_fd);
    }
    try tmp.dir.symLink(io, other_path, "d/audit.jsonl", .{});

    signals.log_reopen_requested.store(true, .release);
    sink.log(io, "u", "during-fail", null, .ok, "", "203.0.113.9");
    try std.testing.expectEqual(original_fd, sink.fd);
    try std.testing.expect(sink.last_reopen_warn_ms != 0);
    const warned_at = sink.last_reopen_warn_ms;
    const retry_at = sink.reopen_retry_at_ms.load(.acquire);
    try std.testing.expect(retry_at >= sys.monotonicMs());
    try std.testing.expect(!signals.log_reopen_requested.load(.acquire));

    // Deadline still ahead and no new signal: leave the fd alone.
    sink.maybeReopen(io);
    try std.testing.expectEqual(retry_at, sink.reopen_retry_at_ms.load(.acquire));
    try std.testing.expectEqual(warned_at, sink.last_reopen_warn_ms);
    try std.testing.expectEqual(original_fd, sink.fd);

    // A fresh SIGUSR1 retries immediately but must not warn again.
    const sentinel = sys.monotonicMs() + 1_000_000;
    sink.reopen_retry_at_ms.store(sentinel, .release);
    signals.log_reopen_requested.store(true, .release);
    sink.maybeReopen(io);
    try std.testing.expect(!signals.log_reopen_requested.load(.acquire));
    try std.testing.expect(sink.reopen_retry_at_ms.load(.acquire) < sentinel);
    try std.testing.expectEqual(warned_at, sink.last_reopen_warn_ms);
    try std.testing.expectEqual(original_fd, sink.fd);

    // Deadline alone retries, still inside the warn window.
    sink.reopen_retry_at_ms.store(sys.monotonicMs() - 1, .release);
    sink.maybeReopen(io);
    const after_deadline = sink.reopen_retry_at_ms.load(.acquire);
    const now = sys.monotonicMs();
    try std.testing.expect(after_deadline >= now);
    try std.testing.expect(after_deadline <= now + warn_min_interval_ms);
    try std.testing.expectEqual(warned_at, sink.last_reopen_warn_ms);
    try std.testing.expectEqual(original_fd, sink.fd);

    var kept_read: [2048]u8 = undefined;
    const kept_body = try tmp.dir.readFile(io, "d/kept.jsonl", &kept_read);
    try std.testing.expect(std.mem.indexOf(u8, kept_body, "\"operation\":\"before-fail\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, kept_body, "\"operation\":\"during-fail\"") != null);
    var other_read: [256]u8 = undefined;
    const other_body = try tmp.dir.readFile(io, "d/other.jsonl", &other_read);
    try std.testing.expect(std.mem.indexOf(u8, other_body, "during-fail") == null);

    try tmp.dir.deleteFile(io, "d/audit.jsonl");
    sink.reopen_retry_at_ms.store(sys.monotonicMs() - 1, .release);
    signals.log_reopen_requested.store(false, .release);
    sink.log(io, "u", "after-ok", null, .ok, "", "203.0.113.9");

    const new_fd = sink.fd;
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
