//! SFTP v3 wire encoding: reply packets, attribute blocks, and the
//! length-prefixed string parser (client-controlled, so bounds-checked).

const std = @import("std");
const c = @import("libssh");
const listing = @import("listing.zig");

pub const sftp_max_packet_bytes: usize = 256 * 1024;

/// A READDIR entry: name, longname, and a full attribute block, each
/// length-prefixed.
const max_name_entry_bytes: usize = 4 + listing.max_name_bytes + 4 + listing.max_longname_bytes + 32;

/// Where a DATA reply's payload starts in its frame (length, type,
/// request id, data length).
pub const data_offset: usize = 13;

/// The most one READ returns: a DATA reply that fits the packet limit
/// clients enforce.
pub const max_read_bytes: usize = sftp_max_packet_bytes - data_offset;

pub fn writeVersion(channel: c.ssh_channel) !void {
    var buf: [9]u8 = undefined;
    var w: PacketWriter = .{ .buf = &buf };
    try w.putU8(@intCast(c.SSH_FXP_VERSION));
    try w.putU32(3);
    try w.send(channel);
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
    try w.send(channel);
}

/// A READDIR reply built in place: `begin`, `add` entries while
/// `hasRoom`, then `send`.
pub const NameBatch = struct {
    w: PacketWriter,
    count: u32 = 0,

    pub fn begin(buf: []u8, request_id: u32) !NameBatch {
        var w: PacketWriter = .{ .buf = buf };
        try w.putU8(@intCast(c.SSH_FXP_NAME));
        try w.putU32(request_id);
        try w.putU32(0);
        return .{ .w = w };
    }

    /// Room for one more entry of the largest possible size.
    pub fn hasRoom(self: *const NameBatch) bool {
        return self.w.buf.len - self.w.index >= max_name_entry_bytes;
    }

    pub fn add(self: *NameBatch, name: []const u8, longname: []const u8, info: listing.EntryInfo) !void {
        try self.w.string(name);
        try self.w.string(longname);
        try writeFullAttrs(&self.w, info);
        self.count += 1;
    }

    pub fn send(self: *NameBatch, channel: c.ssh_channel) !void {
        std.mem.writeInt(u32, self.w.buf[9..13], self.count, .big);
        try self.w.send(channel);
    }
};

pub fn replyHandle(channel: c.ssh_channel, request_id: u32, id: u32) !void {
    var handle_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &handle_bytes, id, .big);

    var buf: [32]u8 = undefined;
    var w: PacketWriter = .{ .buf = &buf };
    try w.putU8(@intCast(c.SSH_FXP_HANDLE));
    try w.putU32(request_id);
    try w.string(&handle_bytes);
    try w.send(channel);
}

pub fn replyFullAttrs(channel: c.ssh_channel, request_id: u32, info: listing.EntryInfo) !void {
    var buf: [128]u8 = undefined;
    var w: PacketWriter = .{ .buf = &buf };
    try w.putU8(@intCast(c.SSH_FXP_ATTRS));
    try w.putU32(request_id);
    try writeFullAttrs(&w, info);
    try w.send(channel);
}

/// Send the `len` bytes the caller read into `frame[data_offset..]` as
/// one DATA reply, without copying them. Unlike every other reply, it
/// takes two channel writes, header then data: a 32 KiB read plus its
/// 13-byte header would overflow OpenSSH's 32 KiB channel packet and
/// trail a tiny one, which cost 8% on downloads.
pub fn replyData(channel: c.ssh_channel, frame: []u8, request_id: u32, len: usize) !void {
    var w: PacketWriter = .{ .buf = frame };
    try w.putU8(@intCast(c.SSH_FXP_DATA));
    try w.putU32(request_id);
    try w.putU32(@intCast(len));
    std.mem.writeInt(u32, frame[0..4], @intCast(w.index - 4 + len), .big);
    try writeAll(channel, frame[0..w.index]);
    try writeAll(channel, frame[w.index..][0..len]);
}

/// The message is the standard phrase for `status`; detail belongs in
/// the audit log, never on the wire.
pub fn replyStatus(channel: c.ssh_channel, request_id: u32, status: c_int) !void {
    const message: []const u8 = switch (status) {
        c.SSH_FX_OK => "ok",
        c.SSH_FX_EOF => "end of file",
        c.SSH_FX_NO_SUCH_FILE => "no such file",
        c.SSH_FX_PERMISSION_DENIED => "permission denied",
        c.SSH_FX_BAD_MESSAGE => "bad message",
        c.SSH_FX_OP_UNSUPPORTED => "operation unsupported",
        c.SSH_FX_INVALID_HANDLE => "invalid handle",
        else => "failure",
    };
    var buf: [64]u8 = undefined;
    var w: PacketWriter = .{ .buf = &buf };
    try w.putU8(@intCast(c.SSH_FXP_STATUS));
    try w.putU32(request_id);
    try w.putU32(@intCast(status));
    try w.string(message);
    try w.string("");
    try w.send(channel);
}

/// REALPATH has no inode at hand: claim a 0755 directory of size 0.
fn writeDirAttrs(w: *PacketWriter) !void {
    try w.putU32(@intCast(c.SSH_FILEXFER_ATTR_SIZE | c.SSH_FILEXFER_ATTR_PERMISSIONS));
    try w.putU64(0);
    try w.putU32(listing.S_IFDIR | 0o755);
}

/// SIZE, UIDGID, PERMISSIONS (with file-type bits), and ACMODTIME.
fn writeFullAttrs(w: *PacketWriter, info: listing.EntryInfo) !void {
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

fn writeAll(channel: c.ssh_channel, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const n = c.ssh_channel_write(channel, bytes[offset..].ptr, @intCast(bytes.len - offset));
        if (n <= 0) return error.LibsshFailure;
        offset += @intCast(n);
    }
}

/// Builds one packet, length prefix included, so a reply is a single
/// channel write: libssh sends every write as its own SSH packet and
/// flushes it. `replyData` alone splits header from data, on purpose.
pub const PacketWriter = struct {
    buf: []u8,
    /// Past the length prefix, which `send` fills in.
    index: usize = 4,

    fn send(self: *PacketWriter, channel: c.ssh_channel) !void {
        std.mem.writeInt(u32, self.buf[0..4], @intCast(self.index - 4), .big);
        try writeAll(channel, self.buf[0..self.index]);
    }

    fn put(self: *PacketWriter, bytes: []const u8) !void {
        if (bytes.len > self.buf.len - self.index) return error.PacketOverflow;
        @memcpy(self.buf[self.index..][0..bytes.len], bytes);
        self.index += bytes.len;
    }

    fn putU8(self: *PacketWriter, value: u8) !void {
        try self.put(&.{value});
    }

    fn putU32(self: *PacketWriter, value: u32) !void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .big);
        try self.put(&bytes);
    }

    fn putU64(self: *PacketWriter, value: u64) !void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, value, .big);
        try self.put(&bytes);
    }

    fn string(self: *PacketWriter, value: []const u8) !void {
        try self.putU32(@intCast(value.len));
        try self.put(value);
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

/// What SETSTAT and FSETSTAT act on in a v3 ATTRS block. Fields after
/// the times, the extensions, are not needed.
pub const SetAttrs = struct {
    size: bool,
    /// Permissions or owners, which are ignored but worth an audit note.
    mode_or_owner: bool,
    /// atime, mtime.
    times: ?[2]u32,
};

pub fn parseSetAttrs(payload: []const u8) !SetAttrs {
    if (payload.len < 4) return error.LibsshFailure;
    const flags = std.mem.readInt(u32, payload[0..4], .big);
    const has = struct {
        fn bit(f: u32, b: c_int) bool {
            return f & @as(u32, @intCast(b)) != 0;
        }
    }.bit;
    var offset: usize = 4;
    if (has(flags, c.SSH_FILEXFER_ATTR_SIZE)) offset += 8;
    if (has(flags, c.SSH_FILEXFER_ATTR_UIDGID)) offset += 8;
    if (has(flags, c.SSH_FILEXFER_ATTR_PERMISSIONS)) offset += 4;
    var result: SetAttrs = .{
        .size = has(flags, c.SSH_FILEXFER_ATTR_SIZE),
        .mode_or_owner = has(flags, c.SSH_FILEXFER_ATTR_UIDGID) or has(flags, c.SSH_FILEXFER_ATTR_PERMISSIONS),
        .times = null,
    };
    if (has(flags, c.SSH_FILEXFER_ATTR_ACMODTIME)) {
        if (payload.len < offset + 8) return error.LibsshFailure;
        result.times = .{
            std.mem.readInt(u32, payload[offset..][0..4], .big),
            std.mem.readInt(u32, payload[offset + 4 ..][0..4], .big),
        };
        offset += 8;
    }
    if (payload.len < offset) return error.LibsshFailure;
    return result;
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

test "parseSetAttrs: skips size, owner and mode to reach the times" {
    var buf: [36]u8 = undefined;
    const flags: u32 = @intCast(c.SSH_FILEXFER_ATTR_UIDGID | c.SSH_FILEXFER_ATTR_PERMISSIONS | c.SSH_FILEXFER_ATTR_ACMODTIME);
    std.mem.writeInt(u32, buf[0..4], flags, .big);
    @memset(buf[4..16], 0xAA);
    std.mem.writeInt(u32, buf[16..20], 1000, .big);
    std.mem.writeInt(u32, buf[20..24], 2000, .big);
    const got = try parseSetAttrs(buf[0..24]);
    try testing.expect(!got.size);
    try testing.expect(got.mode_or_owner);
    try testing.expectEqual([2]u32{ 1000, 2000 }, got.times.?);
    try testing.expectError(error.LibsshFailure, parseSetAttrs(buf[0..23]));

    std.mem.writeInt(u32, buf[0..4], @intCast(c.SSH_FILEXFER_ATTR_SIZE), .big);
    try testing.expectError(error.LibsshFailure, parseSetAttrs(buf[0..11]));
    const size_only = try parseSetAttrs(buf[0..12]);
    try testing.expect(size_only.size);
    try testing.expect(!size_only.mode_or_owner);
    try testing.expectEqual(null, size_only.times);
}
