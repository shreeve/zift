//! Structured audit log for Zift (PLAN §8.5).
//!
//! One JSON object per line, single-write to a destination shared by
//! every worker thread. Default destination is stderr; an absolute file
//! path may be configured (`server.log`) and is reopened on SIGUSR1.
//!
//! Schema and field order are FIXED by PLAN §7.4. The composition
//! recipes in PLAN §11 (fail2ban, awk, jq) anchor on this order:
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
//! `ip` is mandatory in every line so fail2ban-style anchored regexes
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
fn warnWriteFailure(name: []const u8) void {
    writeStderrRaw("zift: audit write failed: ");
    writeStderrRaw(name);
    writeStderrRaw("\n");
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
    // PLAN §7.4 mandates. `ip` is preserved so fail2ban-style anchored
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
    // PLAN §7.4 stable order: event, user, operation, result, path,
    // detail, ip, [truncated].
    try w.writeAll("{\"event\":\"zift.audit\"");
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
    // event must come first; ip must come after detail.
    const event_idx = std.mem.indexOf(u8, line, "\"event\"").?;
    const user_idx = std.mem.indexOf(u8, line, "\"user\"").?;
    const op_idx = std.mem.indexOf(u8, line, "\"operation\"").?;
    const result_idx = std.mem.indexOf(u8, line, "\"result\"").?;
    const path_idx = std.mem.indexOf(u8, line, "\"path\"").?;
    const detail_idx = std.mem.indexOf(u8, line, "\"detail\"").?;
    const ip_idx = std.mem.indexOf(u8, line, "\"ip\"").?;
    try std.testing.expect(event_idx < user_idx);
    try std.testing.expect(user_idx < op_idx);
    try std.testing.expect(op_idx < result_idx);
    try std.testing.expect(result_idx < path_idx);
    try std.testing.expect(path_idx < detail_idx);
    try std.testing.expect(detail_idx < ip_idx);
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
