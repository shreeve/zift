const std = @import("std");
const c = @import("libssh");
const listing = @import("listing.zig");

/// PLAN §7.6: maximum SFTP packet size is 256 KiB.
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

pub fn readPacket(channel: c.ssh_channel, payload_buf: []u8) ![]u8 {
    var len_buf: [4]u8 = undefined;
    try readExact(channel, &len_buf);
    const len = readU32(&len_buf);
    if (len > payload_buf.len) return error.LibsshFailure;
    const payload = payload_buf[0..len];
    try readExact(channel, payload);
    return payload;
}

pub fn readExact(channel: c.ssh_channel, out: []u8) !void {
    var offset: usize = 0;
    while (offset < out.len) {
        const n = c.ssh_channel_read(channel, out[offset..].ptr, @intCast(out.len - offset), 0);
        if (n <= 0) return error.LibsshFailure;
        offset += @intCast(n);
    }
}
pub fn writeVersion(channel: c.ssh_channel) !void {
    var buf: [9]u8 = undefined;
    writeU32(buf[0..4], 5);
    buf[4] = @intCast(c.SSH_FXP_VERSION);
    writeU32(buf[5..9], 3);
    try writeAll(channel, &buf);
}

pub fn replyName(channel: c.ssh_channel, request_id: u32, name: []const u8) !void {
    var buf: [512]u8 = undefined;
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
    // 32 KiB per packet: 16 entries × ~(255 name + 320 longname + 28
    // attrs + 12 length-prefix overhead) ≈ 9.8 KiB worst case, with
    // room to spare for any future attr additions. Stack-allocated;
    // the worker thread's stack is 8 MiB.
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
    writeU32(&handle_bytes, id);

    var buf: [64]u8 = undefined;
    var w: PacketWriter = .{ .buf = &buf };
    try w.putU8(@intCast(c.SSH_FXP_HANDLE));
    try w.putU32(request_id);
    try w.string(&handle_bytes);
    try writePayload(channel, w.written());
}

pub fn replyDirAttrs(channel: c.ssh_channel, request_id: u32) !void {
    var buf: [128]u8 = undefined;
    var w: PacketWriter = .{ .buf = &buf };
    try w.putU8(@intCast(c.SSH_FXP_ATTRS));
    try w.putU32(request_id);
    try writeDirAttrs(&w);
    try writePayload(channel, w.written());
}

pub fn replyFullAttrs(channel: c.ssh_channel, request_id: u32, info: listing.EntryInfo) !void {
    // SFTP_FXP_ATTRS reply with the full attribute set (mode + uid +
    // gid + size + atime/mtime). Used by STAT, LSTAT, and FSTAT — so
    // a partner running `sftp> stat foo` and `sftp> ls -la` see the
    // same fields, populated from the same `listing.statAt`-derived
    // EntryInfo.
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
    writeU32(header_payload[1..5], request_id);
    writeU32(header_payload[5..9], @intCast(data.len));

    var header: [4]u8 = undefined;
    writeU32(&header, @intCast(header_payload.len + data.len));
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

pub fn writeDirAttrs(w: *PacketWriter) !void {
    // Synthetic attrs for SFTP_NAME replies that only carry a path
    // without an underlying inode (REALPATH against a virtual root).
    // We claim "directory, mode 0755, size 0" — minimal but well-
    // formed; the next STAT/READDIR fetches the real shape.
    try writeBasicAttrs(w, .directory, 0);
}

/// Synthetic attrs for callers who don't have an actual stat result —
/// REALPATH replies and similar virtual paths. Only fills SIZE +
/// PERMISSIONS with a plausible default. NEW code paths should prefer
/// `writeFullAttrs` with a real `EntryInfo`.
pub fn writeBasicAttrs(w: *PacketWriter, kind: std.Io.File.Kind, size: u64) !void {
    const mode: u32 = switch (kind) {
        .directory => @intCast(c.SSH_S_IFDIR | 0o755),
        else => @intCast(c.SSH_S_IFREG | 0o644),
    };
    try w.putU32(@intCast(c.SSH_FILEXFER_ATTR_SIZE | c.SSH_FILEXFER_ATTR_PERMISSIONS));
    try w.putU64(size);
    try w.putU32(mode);
}

/// Emit an SFTP v3 file-attributes block populated from a real
/// `listing.EntryInfo`. Includes:
///
///   - SIZE         : real byte size (0 for directories/specials)
///   - UIDGID       : real uid + gid for `ls -l` rendering
///   - PERMISSIONS  : real `st_mode` (file-type bits + permission
///                    bits), so the client can render `drwxr-xr-x`
///                    correctly for directories, symlinks, etc.
///   - ACMODTIME    : atime + mtime as seconds since epoch
///
/// The flag word is the OR of the four `SSH_FILEXFER_ATTR_*` bits;
/// each populated field follows in the spec-defined order.
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
    // SFTP v3 stores acmodtime as 32-bit seconds. mtime_secs comes
    // from statx/fstat as i64 to handle pre-1970 files correctly,
    // but SFTP can only carry u32; clamp to the representable range
    // (1970..2106) rather than truncate silently. Same for atime,
    // which we don't track separately — we report mtime for both
    // since SFTP clients use atime only as a fallback for dirs that
    // don't track it.
    const t32: u32 = if (info.mtime_secs < 0) 0
        else if (info.mtime_secs > std.math.maxInt(u32)) std.math.maxInt(u32)
        else @intCast(info.mtime_secs);
    try w.putU32(t32);
    try w.putU32(t32);
}

pub fn writePayload(channel: c.ssh_channel, payload: []const u8) !void {
    var header: [4]u8 = undefined;
    writeU32(&header, @intCast(payload.len));
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
        writeU32(self.buf[self.index .. self.index + 4], value);
        self.index += 4;
    }

    fn putU64(self: *PacketWriter, value: u64) !void {
        if (self.index + 8 > self.buf.len) return error.LibsshFailure;
        self.buf[self.index] = @intCast((value >> 56) & 0xff);
        self.buf[self.index + 1] = @intCast((value >> 48) & 0xff);
        self.buf[self.index + 2] = @intCast((value >> 40) & 0xff);
        self.buf[self.index + 3] = @intCast((value >> 32) & 0xff);
        self.buf[self.index + 4] = @intCast((value >> 24) & 0xff);
        self.buf[self.index + 5] = @intCast((value >> 16) & 0xff);
        self.buf[self.index + 6] = @intCast((value >> 8) & 0xff);
        self.buf[self.index + 7] = @intCast(value & 0xff);
        self.index += 8;
    }

    fn string(self: *PacketWriter, value: []const u8) !void {
        try self.putU32(@intCast(value.len));
        if (self.index + value.len > self.buf.len) return error.LibsshFailure;
        @memcpy(self.buf[self.index .. self.index + value.len], value);
        self.index += value.len;
    }
};

pub fn readU32(bytes: []const u8) u32 {
    return (@as(u32, bytes[0]) << 24) |
        (@as(u32, bytes[1]) << 16) |
        (@as(u32, bytes[2]) << 8) |
        @as(u32, bytes[3]);
}

pub fn readU64(bytes: []const u8) u64 {
    return (@as(u64, bytes[0]) << 56) |
        (@as(u64, bytes[1]) << 48) |
        (@as(u64, bytes[2]) << 40) |
        (@as(u64, bytes[3]) << 32) |
        (@as(u64, bytes[4]) << 24) |
        (@as(u64, bytes[5]) << 16) |
        (@as(u64, bytes[6]) << 8) |
        @as(u64, bytes[7]);
}

pub const ParsedString = struct {
    value: []const u8,
    rest: []const u8,
};

pub fn parseString(payload: []const u8) !ParsedString {
    if (payload.len < 4) return error.LibsshFailure;
    const len = readU32(payload[0..4]);
    if (payload.len < 4 + len) return error.LibsshFailure;
    return .{
        .value = payload[4 .. 4 + len],
        .rest = payload[4 + len ..],
    };
}

pub fn parseHandleId(payload: []const u8) !u32 {
    const parsed = try parseString(payload);
    if (parsed.value.len != 4) return error.LibsshFailure;
    return readU32(parsed.value);
}

pub fn writeU32(out: []u8, value: u32) void {
    out[0] = @intCast((value >> 24) & 0xff);
    out[1] = @intCast((value >> 16) & 0xff);
    out[2] = @intCast((value >> 8) & 0xff);
    out[3] = @intCast(value & 0xff);
}
