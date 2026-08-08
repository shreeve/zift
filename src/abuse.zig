//! Built-in source abuse controls for Internet-facing partner SFTP.
//!
//! Keeps the normal deploy free of fail2ban/CrowdSec by tracking failed
//! authentication pressure per source IP inside the process:
//!
//!   - temporary suppression after a burst of failures
//!   - cleared on successful authentication
//!
//! This is intentionally small: fixed table, coarse mutex, hardcoded
//! defaults. Operators who need threat feeds or fleet-wide bans are
//! outside Zift's niche.

const std = @import("std");

/// Failed auth events in the window that trigger suppression.
pub const failure_threshold: u32 = 10;
/// Sliding window for counting failures.
pub const window_ms: i64 = 10 * 60 * 1000;
/// How long a source stays rejected after tripping the threshold.
pub const suppress_ms: i64 = 15 * 60 * 1000;
/// Cap concurrent tracked sources. Oldest free / expired slots are reused.
const max_entries: usize = 256;
const max_ip_len: usize = 64;

const Entry = struct {
    ip: [max_ip_len]u8 = undefined,
    ip_len: u8 = 0,
    failures: u32 = 0,
    window_start_ms: i64 = 0,
    suppressed_until_ms: i64 = 0,

    fn ipSlice(self: *const Entry) []const u8 {
        return self.ip[0..self.ip_len];
    }

    fn setIp(self: *Entry, ip: []const u8) void {
        const n = @min(ip.len, max_ip_len);
        @memcpy(self.ip[0..n], ip[0..n]);
        self.ip_len = @intCast(n);
    }
};

var mutex: std.Io.Mutex = .init;
var entries: [max_entries]Entry = @splat(.{});

/// True when `ip` is currently suppressed and should be refused at accept.
pub fn isSuppressed(io: std.Io, ip: []const u8, now_ms: i64) bool {
    if (ip.len == 0) return false;
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    const entry = findEntry(ip) orelse return false;
    return entry.suppressed_until_ms > now_ms;
}

/// Record an authentication failure for `ip`. May begin a suppress window.
pub fn recordFailure(io: std.Io, ip: []const u8, now_ms: i64) void {
    if (ip.len == 0) return;
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    const entry = findOrInsert(ip, now_ms) orelse return;

    if (entry.suppressed_until_ms > now_ms) return;

    if (entry.window_start_ms == 0 or now_ms - entry.window_start_ms > window_ms) {
        entry.window_start_ms = now_ms;
        entry.failures = 0;
    }
    entry.failures += 1;
    if (entry.failures >= failure_threshold) {
        entry.suppressed_until_ms = now_ms + suppress_ms;
        entry.failures = 0;
        entry.window_start_ms = now_ms;
    }
}

/// Clear failure / suppress state after a successful login.
pub fn recordSuccess(io: std.Io, ip: []const u8) void {
    if (ip.len == 0) return;
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    if (findEntry(ip)) |entry| {
        entry.* = .{};
    }
}

fn findEntry(ip: []const u8) ?*Entry {
    for (&entries) |*entry| {
        if (entry.ip_len == 0) continue;
        if (std.mem.eql(u8, entry.ipSlice(), ip)) return entry;
    }
    return null;
}

fn findOrInsert(ip: []const u8, now_ms: i64) ?*Entry {
    if (findEntry(ip)) |entry| return entry;

    for (&entries) |*entry| {
        if (entry.ip_len == 0) {
            entry.setIp(ip);
            return entry;
        }
    }

    // Table full: reuse an expired or least-recently-active slot.
    var best: ?*Entry = null;
    var best_score: i64 = std.math.maxInt(i64);
    for (&entries) |*entry| {
        if (entry.suppressed_until_ms > now_ms) continue;
        const score = @max(entry.window_start_ms, entry.suppressed_until_ms);
        if (score < best_score) {
            best_score = score;
            best = entry;
        }
    }
    if (best) |entry| {
        entry.* = .{};
        entry.setIp(ip);
        return entry;
    }
    return null;
}

test "suppress after threshold failures" {
    const io = std.testing.io;
    // Isolate from other tests by using a unique IP string.
    const ip = "203.0.113.200";
    recordSuccess(io, ip);
    const t0: i64 = 1_000_000;
    var i: u32 = 0;
    while (i < failure_threshold - 1) : (i += 1) {
        recordFailure(io, ip, t0 + i);
        try std.testing.expect(!isSuppressed(io, ip, t0 + i));
    }
    recordFailure(io, ip, t0 + failure_threshold);
    try std.testing.expect(isSuppressed(io, ip, t0 + failure_threshold));
    try std.testing.expect(isSuppressed(io, ip, t0 + failure_threshold + suppress_ms - 1));
    try std.testing.expect(!isSuppressed(io, ip, t0 + failure_threshold + suppress_ms + 1));
    recordSuccess(io, ip);
    try std.testing.expect(!isSuppressed(io, ip, t0 + failure_threshold + 1));
}

test "success clears mid-window failures" {
    const io = std.testing.io;
    const ip = "203.0.113.201";
    recordSuccess(io, ip);
    const t0: i64 = 2_000_000;
    recordFailure(io, ip, t0);
    recordFailure(io, ip, t0 + 1);
    recordSuccess(io, ip);
    var i: u32 = 0;
    while (i < failure_threshold - 1) : (i += 1) {
        recordFailure(io, ip, t0 + 100 + i);
    }
    try std.testing.expect(!isSuppressed(io, ip, t0 + 100 + failure_threshold));
    recordSuccess(io, ip);
}
