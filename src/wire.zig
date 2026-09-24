//! SFTP v3 wire encoding: reply packets, attribute blocks, and the
//! length-prefixed string parser (client-controlled, so bounds-checked).

const std = @import("std");
const c = @import("libssh");
const listing = @import("listing.zig");

pub const sftp_max_packet_bytes: usize = 256 * 1024;

pub const DirEntry = struct {
    name_buf: [256]u8 = undefined,
    name_len: usize = 0,
    longname_buf: [320]u8 = undefined,
    longname_len: usize = 0,
    info: listing.EntryInfo = .{
        .mode = 0,
        .nlink = 0,
        .uid = 0,
        .gid = 0,
        .size = 0,
        .mtime_secs = 0,
    },
};

pub fn parentErrorStatus(err: anyerror) c_int {
    return switch (err) {
        error.PathTraversal, error.InvalidPath => c.SSH_FX_PERMISSION_DENIED,
        error.OutOfMemory => c.SSH_FX_FAILURE,
        else => c.SSH_FX_NO_SUCH_FILE,
    };
}

pub fn writeVersion(channel: c.ssh_channel) !void {
    var buf: [9]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], 5, .big);
    buf[4] = @intCast(c.SSH_FXP_VERSION);
    std.mem.writeInt(u32, buf[5..9], 3, .big);
    try writeAll(channel, &buf);
}

pub fn replyName(channel: c.ssh_channel, request_id: u32, name: []const u8) !void {
    // Carries a path of up to 4097 bytes twice (name and longname).
    var buf: [9 * 1024]u8 = undefined;
    var w: PacketWriter = .{ .buf = &buf };
    try w.putU8(@intCast(c.SSH_FXP_NAME));
    try w.putU32(request_id);
    try w.putU32(1);
    try w.string(name);
    try w.string(name);
    try writeDirAttrs(&w);
    try writePayload(channel, w.written());
}

pub fn replyNames(channel: c.ssh_channel, request_id: u32, entries: []const DirEntry) !void {
    // Room for a READDIR batch of 16 at ~620 bytes each.
    var buf: [32 * 1024]u8 = undefined;
    var w: PacketWriter = .{ .buf = &buf };
    try w.putU8(@intCast(c.SSH_FXP_NAME));
    try w.putU32(request_id);
    try w.putU32(@intCast(entries.len));
    for (entries) |entry| {
        try w.string(entry.name_buf[0..@min(entry.name_len, entry.name_buf.len)]);
        try w.string(entry.longname_buf[0..@min(entry.longname_len, entry.longname_buf.len)]);
        try writeFullAttrs(&w, entry.info);
    }
    try writePayload(channel, w.written());
}

pub fn replyHandle(channel: c.ssh_channel, request_id: u32, id: u32) !void {
    var handle_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &handle_bytes, id, .big);

    var buf: [64]u8 = undefined;
    var w: PacketWriter = .{ .buf = &buf };
    try w.putU8(@intCast(c.SSH_FXP_HANDLE));
    try w.putU32(request_id);
    try w.string(&handle_bytes);
    try writePayload(channel, w.written());
}

pub fn replyFullAttrs(channel: c.ssh_channel, request_id: u32, info: listing.EntryInfo) !void {
    var buf: [128]u8 = undefined;
    var w: PacketWriter = .{ .buf = &buf };
    try w.putU8(@intCast(c.SSH_FXP_ATTRS));
    try w.putU32(request_id);
    try writeFullAttrs(&w, info);
    try writePayload(channel, w.written());
}

pub fn replyData(channel: c.ssh_channel, request_id: u32, data: []const u8) !void {
    var header_payload: [9]u8 = undefined;
    header_payload[0] = @intCast(c.SSH_FXP_DATA);
    std.mem.writeInt(u32, header_payload[1..5], request_id, .big);
    std.mem.writeInt(u32, header_payload[5..9], @intCast(data.len), .big);

    var header: [4]u8 = undefined;
    std.mem.writeInt(u32, &header, @intCast(header_payload.len + data.len), .big);
    try writeAll(channel, &header);
    try writeAll(channel, &header_payload);
    try writeAll(channel, data);
}

pub fn replyStatus(channel: c.ssh_channel, request_id: u32, status: c_int, message: []const u8) !void {
    var buf: [512]u8 = undefined;
    var w: PacketWriter = .{ .buf = &buf };
    try w.putU8(@intCast(c.SSH_FXP_STATUS));
    try w.putU32(request_id);
    try w.putU32(@intCast(status));
    try w.string(message);
    try w.string("");
    try writePayload(channel, w.written());
}

/// REALPATH has no inode at hand: claim a 0755 directory of size 0.
fn writeDirAttrs(w: *PacketWriter) !void {
    try w.putU32(@intCast(c.SSH_FILEXFER_ATTR_SIZE | c.SSH_FILEXFER_ATTR_PERMISSIONS));
    try w.putU64(0);
    try w.putU32(listing.S_IFDIR | 0o755);
}

/// SIZE, UIDGID, PERMISSIONS (with file-type bits), and ACMODTIME.
pub fn writeFullAttrs(w: *PacketWriter, info: listing.EntryInfo) !void {
    const flags: u32 = @intCast(
        c.SSH_FILEXFER_ATTR_SIZE |
            c.SSH_FILEXFER_ATTR_UIDGID |
            c.SSH_FILEXFER_ATTR_PERMISSIONS |
            c.SSH_FILEXFER_ATTR_ACMODTIME,
    );
    try w.putU32(flags);
    try w.putU64(info.size);
    try w.putU32(info.uid);
    try w.putU32(info.gid);
    try w.putU32(info.mode);
    // v3 times are u32 seconds: clamp rather than wrap. mtime stands in
    // for atime too.
    const t32: u32 = if (info.mtime_secs < 0) 0 else if (info.mtime_secs > std.math.maxInt(u32)) std.math.maxInt(u32) else @intCast(info.mtime_secs);
    try w.putU32(t32);
    try w.putU32(t32);
}

pub fn writePayload(channel: c.ssh_channel, payload: []const u8) !void {
    var header: [4]u8 = undefined;
    std.mem.writeInt(u32, &header, @intCast(payload.len), .big);
    try writeAll(channel, &header);
    try writeAll(channel, payload);
}

pub fn writeAll(channel: c.ssh_channel, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const n = c.ssh_channel_write(channel, bytes[offset..].ptr, @intCast(bytes.len - offset));
        if (n <= 0) return error.LibsshFailure;
        offset += @intCast(n);
    }
}

pub const PacketWriter = struct {
    buf: []u8,
    index: usize = 0,

    fn written(self: PacketWriter) []const u8 {
        return self.buf[0..self.index];
    }

    fn putU8(self: *PacketWriter, value: u8) !void {
        if (self.index + 1 > self.buf.len) return error.LibsshFailure;
        self.buf[self.index] = value;
        self.index += 1;
    }

    fn putU32(self: *PacketWriter, value: u32) !void {
        if (self.index + 4 > self.buf.len) return error.LibsshFailure;
        std.mem.writeInt(u32, self.buf[self.index..][0..4], value, .big);
        self.index += 4;
    }

    fn putU64(self: *PacketWriter, value: u64) !void {
        if (self.index + 8 > self.buf.len) return error.LibsshFailure;
        std.mem.writeInt(u64, self.buf[self.index..][0..8], value, .big);
        self.index += 8;
    }

    fn string(self: *PacketWriter, value: []const u8) !void {
        try self.putU32(@intCast(value.len));
        if (self.index + value.len > self.buf.len) return error.LibsshFailure;
        @memcpy(self.buf[self.index .. self.index + value.len], value);
        self.index += value.len;
    }
};

pub const ParsedString = struct {
    value: []const u8,
    rest: []const u8,
};

pub fn parseString(payload: []const u8) !ParsedString {
    if (payload.len < 4) return error.LibsshFailure;
    // Widen before adding: `4 + len` in u32 overflows for a hostile len.
    const len: usize = std.mem.readInt(u32, payload[0..4], .big);
    const end = 4 + len;
    if (payload.len < end) return error.LibsshFailure;
    return .{
        .value = payload[4..end],
        .rest = payload[end..],
    };
}

pub fn parseHandleId(payload: []const u8) !u32 {
    const parsed = try parseString(payload);
    if (parsed.value.len != 4) return error.LibsshFailure;
    return std.mem.readInt(u32, parsed.value[0..4], .big);
}

const testing = std.testing;

test "parseString: well-formed" {
    const payload = [_]u8{ 0, 0, 0, 3, 'a', 'b', 'c', 'x', 'y' };
    const parsed = try parseString(&payload);
    try testing.expectEqualStrings("abc", parsed.value);
    try testing.expectEqualStrings("xy", parsed.rest);
}

test "parseString: truncated length prefix" {
    const payload = [_]u8{ 0, 0, 1 };
    try testing.expectError(error.LibsshFailure, parseString(&payload));
}

test "parseString: declared length exceeds buffer" {
    const payload = [_]u8{ 0, 0, 0, 9, 'a', 'b' };
    try testing.expectError(error.LibsshFailure, parseString(&payload));
}

test "parseString: max-u32 length does not overflow (regression)" {
    // In u32, `4 + len` overflows here and a safe build panics.
    inline for ([_]u32{ 0xFFFF_FFFF, 0xFFFF_FFFE, 0xFFFF_FFFD, 0xFFFF_FFFC, 0x8000_0000 }) |big| {
        var payload: [8]u8 = undefined;
        std.mem.writeInt(u32, payload[0..4], big, .big);
        payload[4] = 1;
        payload[5] = 2;
        payload[6] = 3;
        payload[7] = 4;
        try testing.expectError(error.LibsshFailure, parseString(&payload));
    }
}

test "parseHandleId: requires exactly 4 payload bytes" {
    const ok = [_]u8{ 0, 0, 0, 4, 0, 0, 0, 7 };
    try testing.expectEqual(@as(u32, 7), try parseHandleId(&ok));

    const wrong_len = [_]u8{ 0, 0, 0, 3, 1, 2, 3 };
    try testing.expectError(error.LibsshFailure, parseHandleId(&wrong_len));

    var overflow: [8]u8 = undefined;
    std.mem.writeInt(u32, overflow[0..4], 0xFFFF_FFFF, .big);
    try testing.expectError(error.LibsshFailure, parseHandleId(&overflow));
}
