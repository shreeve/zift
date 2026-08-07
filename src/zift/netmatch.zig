//! IP / CIDR matching for per-user `from` source policy.
//!
//! Parses operator-facing values like `203.0.113.40` or `198.51.100.0/28`
//! (and the IPv6 equivalents) into a compact form that can be matched
//! against the peer IP string captured at accept time.

const std = @import("std");
const Ip4Address = std.Io.net.Ip4Address;
const Ip6Address = std.Io.net.Ip6Address;

pub const Cidr = union(enum) {
    v4: struct {
        /// Host-order address bits.
        addr: u32,
        /// Host-order mask (`0xffffffff` for /32).
        mask: u32,
    },
    v6: struct {
        addr: [16]u8,
        prefix: u8,
    },
};

pub const ParseError = error{
    InvalidCidr,
    InvalidPrefix,
};

/// Parse a single IP or `IP/prefix` token into a `Cidr`.
pub fn parseCidr(text: []const u8) ParseError!Cidr {
    const slash = std.mem.indexOfScalar(u8, text, '/');
    const addr_text = if (slash) |i| text[0..i] else text;
    const prefix_text: ?[]const u8 = if (slash) |i| text[i + 1 ..] else null;

    if (addr_text.len == 0) return error.InvalidCidr;

    if (std.mem.indexOfScalar(u8, addr_text, ':') != null) {
        const ip6 = Ip6Address.parse(addr_text, 0) catch return error.InvalidCidr;
        const prefix: u8 = if (prefix_text) |p|
            std.fmt.parseUnsigned(u8, p, 10) catch return error.InvalidPrefix
        else
            128;
        if (prefix > 128) return error.InvalidPrefix;
        return .{ .v6 = .{ .addr = ip6.bytes, .prefix = prefix } };
    }

    const ip4 = Ip4Address.parse(addr_text, 0) catch return error.InvalidCidr;
    const prefix: u8 = if (prefix_text) |p|
        std.fmt.parseUnsigned(u8, p, 10) catch return error.InvalidPrefix
    else
        32;
    if (prefix > 32) return error.InvalidPrefix;
    const addr = std.mem.readInt(u32, &ip4.bytes, .big);
    // Top `prefix` bits set: /32 → all ones, /24 → 0xffffff00, /0 → 0.
    const mask: u32 = if (prefix == 0)
        0
    else if (prefix == 32)
        0xffff_ffff
    else
        ~((@as(u32, 1) << @intCast(32 - prefix)) - 1);
    return .{ .v4 = .{ .addr = addr, .mask = mask } };
}

/// True when `ip_text` (no port) falls inside `cidr`.
///
/// IPv4-mapped IPv6 peer addresses (`::ffff:a.b.c.d` and the full-form
/// variant Zift's audit formatter emits) are also matched against IPv4
/// CIDRs so dual-stack listeners still honor `from 203.0.113.40`.
pub fn matches(cidr: Cidr, ip_text: []const u8) bool {
    if (ip_text.len == 0) return false;

    switch (cidr) {
        .v4 => |net| {
            if (parseIpv4Bits(ip_text)) |addr| {
                return (addr & net.mask) == (net.addr & net.mask);
            }
            if (parseIpv4MappedBits(ip_text)) |addr| {
                return (addr & net.mask) == (net.addr & net.mask);
            }
            return false;
        },
        .v6 => |net| {
            const peer = parseIpv6Bytes(ip_text) orelse return false;
            return ipv6PrefixEqual(net.addr, peer, net.prefix);
        },
    }
}

/// True when `from` is empty (no restriction) or any entry matches.
pub fn allowed(from: []const Cidr, ip_text: []const u8) bool {
    if (from.len == 0) return true;
    for (from) |cidr| {
        if (matches(cidr, ip_text)) return true;
    }
    return false;
}

fn parseIpv4Bits(text: []const u8) ?u32 {
    const ip4 = Ip4Address.parse(text, 0) catch return null;
    return std.mem.readInt(u32, &ip4.bytes, .big);
}

fn parseIpv6Bytes(text: []const u8) ?[16]u8 {
    const ip6 = Ip6Address.parse(text, 0) catch return null;
    return ip6.bytes;
}

/// Accept both compressed `::ffff:a.b.c.d` and the uncompressed form
/// Zift writes to audit logs (`0:0:0:0:0:ffff:c000:28b`).
fn parseIpv4MappedBits(text: []const u8) ?u32 {
    const bytes = parseIpv6Bytes(text) orelse return null;
    if (!std.mem.eql(u8, bytes[0..12], &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff }))
        return null;
    return std.mem.readInt(u32, bytes[12..16], .big);
}

fn ipv6PrefixEqual(a: [16]u8, b: [16]u8, prefix: u8) bool {
    if (prefix == 0) return true;
    const full_bytes: usize = prefix / 8;
    const rem_bits: u8 = prefix % 8;
    if (!std.mem.eql(u8, a[0..full_bytes], b[0..full_bytes])) return false;
    if (rem_bits == 0) return true;
    const mask: u8 = @as(u8, 0xff) << @intCast(8 - rem_bits);
    return (a[full_bytes] & mask) == (b[full_bytes] & mask);
}

test "parseCidr ipv4 host and subnet" {
    const host = try parseCidr("203.0.113.40");
    try std.testing.expect(matches(host, "203.0.113.40"));
    try std.testing.expect(!matches(host, "203.0.113.41"));

    const net = try parseCidr("198.51.100.0/28");
    try std.testing.expect(matches(net, "198.51.100.1"));
    try std.testing.expect(matches(net, "198.51.100.15"));
    try std.testing.expect(!matches(net, "198.51.100.16"));
}

test "parseCidr ipv6" {
    const host = try parseCidr("2001:db8::1");
    try std.testing.expect(matches(host, "2001:db8::1"));
    try std.testing.expect(!matches(host, "2001:db8::2"));

    const net = try parseCidr("2001:db8::/32");
    try std.testing.expect(matches(net, "2001:db8:1::1"));
    try std.testing.expect(!matches(net, "2001:db9::1"));
}

test "ipv4-mapped peer matches ipv4 from" {
    const host = try parseCidr("192.0.2.1");
    try std.testing.expect(matches(host, "::ffff:192.0.2.1"));
    try std.testing.expect(matches(host, "0:0:0:0:0:ffff:c000:201"));
}

test "allowed empty means any" {
    try std.testing.expect(allowed(&.{}, "198.51.100.1"));
}

test "parseCidr rejects bad input" {
    try std.testing.expectError(error.InvalidCidr, parseCidr(""));
    try std.testing.expectError(error.InvalidCidr, parseCidr("not-an-ip"));
    try std.testing.expectError(error.InvalidPrefix, parseCidr("10.0.0.0/33"));
    try std.testing.expectError(error.InvalidPrefix, parseCidr("2001:db8::/129"));
}
