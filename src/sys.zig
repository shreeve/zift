//! Small process-wide helpers: clocks and UTC calendar math.

const std = @import("std");

/// CLOCK_MONOTONIC milliseconds. libc rather than `std.Io.Clock.awake`,
/// which on macOS is CLOCK_UPTIME_RAW and stops while the host sleeps.
pub fn monotonicMs() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), std.time.ns_per_ms);
}

/// CLOCK_REALTIME, or the epoch if the clock cannot be read.
pub fn realtime() std.c.timespec {
    var ts: std.c.timespec = .{ .sec = 0, .nsec = 0 };
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return ts;
}

pub const Civil = struct {
    year: i64,
    /// 1-12
    month: u8,
    /// 1-31
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
};

/// UTC calendar time for Unix seconds, via Howard Hinnant's
/// `civil_from_days` (https://howardhinnant.github.io/date_algorithms.html).
/// O(1) and panic-free for every i64.
pub fn civil(secs: i64) Civil {
    const day = @divFloor(secs, 86400);
    // `@mod`, not `secs - day * 86400`, which overflows near i64 min.
    const sod: u32 = @intCast(@mod(secs, 86400));

    // Days since 0000-03-01, the algorithm's origin, in 400-year eras.
    const z: i64 = day + 719468;
    const era: i64 = @divFloor(z, 146097);
    const doe: u32 = @intCast(z - era * 146097); // [0, 146096]
    const yoe: u32 = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    const doy: u32 = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    const mp: u32 = (5 * doy + 2) / 153; // March-based month [0, 11]
    const month: u8 = @intCast(if (mp < 10) mp + 3 else mp - 9);
    // January and February belong to the next calendar year.
    const year: i64 = @as(i64, yoe) + era * 400 + @intFromBool(month <= 2);
    return .{
        .year = year,
        .month = month,
        .day = @intCast(doy - (153 * mp + 2) / 5 + 1),
        .hour = @intCast(sod / 3600),
        .minute = @intCast(sod % 3600 / 60),
        .second = @intCast(sod % 60),
    };
}

fn expectCivil(secs: i64, year: i64, month: u8, day: u8) !void {
    const got = civil(secs);
    try std.testing.expectEqual(year, got.year);
    try std.testing.expectEqual(month, got.month);
    try std.testing.expectEqual(day, got.day);
}

test "civil: epoch and a known instant" {
    const epoch = civil(0);
    try std.testing.expectEqual(Civil{ .year = 1970, .month = 1, .day = 1, .hour = 0, .minute = 0, .second = 0 }, epoch);
    // 2026-04-27T14:35:09Z
    const t = civil(1777300509);
    try std.testing.expectEqual(Civil{ .year = 2026, .month = 4, .day = 27, .hour = 14, .minute = 35, .second = 9 }, t);
}

test "civil: pre-1970 timestamps" {
    const t = civil(-1);
    try std.testing.expectEqual(Civil{ .year = 1969, .month = 12, .day = 31, .hour = 23, .minute = 59, .second = 59 }, t);
    try expectCivil(-86400, 1969, 12, 31);
    try expectCivil(-2208988800, 1900, 1, 1);
}

test "civil: leap years" {
    try expectCivil(951825600, 2000, 2, 29); // 400-year leap
    try expectCivil(951868800, 2000, 3, 1);
    try expectCivil(1456704000, 2016, 2, 29);
    try expectCivil(1709251200, 2024, 3, 1);
    try expectCivil(-2203891201, 1900, 2, 28); // 1900 is not a leap year
    try expectCivil(-2203891200, 1900, 3, 1);
    try expectCivil(4102444800, 2100, 1, 1);
}

test "civil: March 1 in a non-first century of an era" {
    // A sign error in the century terms put these a day early
    // (as a February 29 that does not exist).
    try expectCivil(5097600, 1970, 3, 1); // day 59
    try expectCivil(4107456000, 2100, 2, 28);
    try expectCivil(4107542400, 2100, 3, 1); // 2100 is not a leap year
}

test "civil: extreme timestamps do not panic" {
    _ = civil(std.math.minInt(i64));
    _ = civil(std.math.minInt(i64) + 1);
    _ = civil(std.math.maxInt(i64) - 1);
    try std.testing.expect(civil(std.math.maxInt(i64)).year > 0);
}
