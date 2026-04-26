const std = @import("std");

pub const Result = enum {
    ok,
    denied,
    failed,
};

/// Emit a single audit JSON line to stderr. The line is formatted into a
/// stack buffer and written with one call so concurrent threads never
/// interleave inside the same JSON object.
pub fn log(
    io: std.Io,
    user: ?[]const u8,
    operation: []const u8,
    path: ?[]const u8,
    result: Result,
    detail: []const u8,
) void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    formatLine(&w, user, operation, path, result, detail) catch return;

    const stderr = std.Io.File.stderr();
    stderr.writeStreamingAll(io, w.buffered()) catch {};
}

fn formatLine(
    w: *std.Io.Writer,
    user: ?[]const u8,
    operation: []const u8,
    path: ?[]const u8,
    result: Result,
    detail: []const u8,
) !void {
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
    try w.writeAll("}\n");
}

test "audit line escapes special characters" {
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try formatLine(&w, "ally", "open_write", "/pending/\"weird\"\nfile", .ok, "size=11");
    const line = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, line, "\\\"weird\\\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, line, "}\n"));
}
