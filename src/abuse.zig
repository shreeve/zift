//! Built-in source abuse control, so a normal deploy needs no fail2ban.
//!
//! Tracks failed authentications per source in a fixed table behind one
//! mutex; a burst of failures suppresses the source for a while. A source
//! is an IPv4 address or an IPv6 /64, since one IPv6 host routinely holds
//! a whole /64. A successful login clears nothing: one valid account must
//! not buy fresh guesses against the others, and a partner behind the
//! same NAT must not lift an attacker's suppression. Defaults are
//! hardcoded on purpose.

const std = @import("std");

/// Failed auth events in the window that trigger suppression.
pub const failure_threshold: u32 = 10;
/// Failures count within a fixed window that opens at a source's first
/// failure; the first failure after it ends opens the next one.
pub const window_ms: i64 = 10 * 60 * 1000;
/// How long a source stays rejected after tripping the threshold.
pub const suppress_ms: i64 = 15 * 60 * 1000;
/// Tracked sources. Large enough that filling the table to evict a
/// suppressed source is expensive.
const max_entries: usize = 4096;
/// Longest key: an uncompressed IPv6 /64 is 19 bytes.
const max_key_len: usize = 40;

const Entry = struct {
    key: [max_key_len]u8 = undefined,
    key_len: u8 = 0,
    failures: u32 = 0,
    window_start_ms: i64 = 0,
    suppressed_until_ms: i64 = 0,
    /// Last insert or failure. Eviction picks the least-recently-active
    /// source, not the one closest to tripping the threshold.
    last_seen_ms: i64 = 0,

    fn keySlice(self: *const Entry) []const u8 {
        return self.key[0..self.key_len];
    }

    fn setKey(self: *Entry, key: []const u8) void {
        const n = @min(key.len, max_key_len);
        @memcpy(self.key[0..n], key[0..n]);
        self.key_len = @intCast(n);
    }
};

var mutex: std.Io.Mutex = .init;
var entries: [max_entries]Entry = @splat(.{});

/// The table key for a peer address in the server's format: IPv4 as is,
/// IPv6 cut to its /64, the first four groups (always uncompressed).
fn sourceKey(ip: []const u8) []const u8 {
    var colons: usize = 0;
    for (ip, 0..) |ch, i| {
        if (ch != ':') continue;
        colons += 1;
        if (colons == 4) return ip[0..i];
    }
    return ip;
}

/// True when `ip` is currently suppressed and should be refused at accept.
pub fn isSuppressed(io: std.Io, ip: []const u8, now_ms: i64) bool {
    if (ip.len == 0) return false;
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    const entry = findEntry(sourceKey(ip)) orelse return false;
    return entry.suppressed_until_ms > now_ms;
}

/// Record an authentication failure for `ip`. May begin a suppress window.
pub fn recordFailure(io: std.Io, ip: []const u8, now_ms: i64) void {
    if (ip.len == 0) return;
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    const entry = findOrInsert(sourceKey(ip), now_ms) orelse return;

    if (entry.suppressed_until_ms > now_ms) return;

    entry.last_seen_ms = now_ms;
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

fn findEntry(key: []const u8) ?*Entry {
    for (&entries) |*entry| {
        if (entry.key_len == 0) continue;
        if (std.mem.eql(u8, entry.keySlice(), key)) return entry;
    }
    return null;
}

fn findOrInsert(key: []const u8, now_ms: i64) ?*Entry {
    if (findEntry(key)) |entry| return entry;

    for (&entries) |*entry| {
        if (entry.key_len == 0) {
            entry.* = .{};
            entry.setKey(key);
            entry.last_seen_ms = now_ms;
            return entry;
        }
    }

    // Table full: evict the least-recently-active unsuppressed slot. If
    // every slot is suppressed, evict the one expiring soonest; losing
    // that suppression is a smaller harm than ignoring new sources.
    var lru_unsuppressed: ?*Entry = null;
    var lru_seen: i64 = std.math.maxInt(i64);
    var soonest_expiry: ?*Entry = null;
    var soonest_until: i64 = std.math.maxInt(i64);
    for (&entries) |*entry| {
        if (entry.suppressed_until_ms > now_ms) {
            if (entry.suppressed_until_ms < soonest_until) {
                soonest_until = entry.suppressed_until_ms;
                soonest_expiry = entry;
            }
        } else if (entry.last_seen_ms < lru_seen) {
            lru_seen = entry.last_seen_ms;
            lru_unsuppressed = entry;
        }
    }
    const victim = lru_unsuppressed orelse soonest_expiry orelse return null;
    victim.* = .{};
    victim.setKey(key);
    victim.last_seen_ms = now_ms;
    return victim;
}

/// Tests share the global table; each starts from an empty one.
fn resetForTest(io: std.Io) void {
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    entries = @splat(.{});
}

fn failTimes(io: std.Io, ip: []const u8, n: u32, t0: i64) void {
    var i: u32 = 0;
    while (i < n) : (i += 1) recordFailure(io, ip, t0 + i);
}

test "suppress after threshold failures" {
    const io = std.testing.io;
    resetForTest(io);
    const ip = "203.0.113.200";
    const t0: i64 = 1_000_000;
    failTimes(io, ip, failure_threshold - 1, t0);
    try std.testing.expect(!isSuppressed(io, ip, t0 + failure_threshold));
    recordFailure(io, ip, t0 + failure_threshold);
    try std.testing.expect(isSuppressed(io, ip, t0 + failure_threshold));
    try std.testing.expect(isSuppressed(io, ip, t0 + failure_threshold + suppress_ms - 1));
    try std.testing.expect(!isSuppressed(io, ip, t0 + failure_threshold + suppress_ms + 1));
}

test "failures outside the window start a new count" {
    const io = std.testing.io;
    resetForTest(io);
    const ip = "203.0.113.201";
    failTimes(io, ip, failure_threshold - 1, 1);
    failTimes(io, ip, failure_threshold - 1, window_ms + 10);
    try std.testing.expect(!isSuppressed(io, ip, window_ms + 100));
}

test "an IPv6 /64 is one source; IPv4 addresses are not grouped" {
    const io = std.testing.io;
    resetForTest(io);
    var buf: [64]u8 = undefined;
    var i: u32 = 0;
    while (i < failure_threshold) : (i += 1) {
        const ip = try std.fmt.bufPrint(&buf, "2001:db8:1:2:0:0:0:{x}", .{i});
        recordFailure(io, ip, 1000 + i);
    }
    try std.testing.expect(isSuppressed(io, "2001:db8:1:2:ffff:1:2:3", 2000));
    try std.testing.expect(!isSuppressed(io, "2001:db8:1:3:0:0:0:1", 2000));

    i = 0;
    while (i < failure_threshold) : (i += 1) {
        const ip = try std.fmt.bufPrint(&buf, "198.51.100.{d}", .{i});
        recordFailure(io, ip, 1000 + i);
    }
    try std.testing.expect(!isSuppressed(io, "198.51.100.1", 2000));
}

test "sourceKey" {
    try std.testing.expectEqualStrings("192.0.2.7", sourceKey("192.0.2.7"));
    try std.testing.expectEqualStrings("2001:db8:0:0", sourceKey("2001:db8:0:0:0:0:0:1"));
    try std.testing.expectEqualStrings("", sourceKey(""));
}

test "a full table evicts the least recently active unsuppressed source" {
    const io = std.testing.io;
    resetForTest(io);
    defer resetForTest(io);
    // One suppressed source, seen first, then the table filled.
    failTimes(io, "198.51.100.1", failure_threshold, 1);
    var buf: [64]u8 = undefined;
    var i: u32 = 1;
    while (i < max_entries) : (i += 1) {
        recordFailure(io, try std.fmt.bufPrint(&buf, "10.0.{d}.{d}", .{ i / 256, i % 256 }), 100 + i);
    }
    // A newcomer evicts 10.0.0.1 (oldest unsuppressed), not the suppressed one.
    recordFailure(io, "192.0.2.1", 100_000);
    try std.testing.expect(isSuppressed(io, "198.51.100.1", 100_000));
    try std.testing.expect(findEntry("10.0.0.1") == null);
    try std.testing.expect(findEntry("10.0.0.2") != null);
}
