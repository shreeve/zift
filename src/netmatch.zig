//! IP / CIDR matching for per-user `from` source policy.
//!
//! Parses operator-facing values like `203.0.113.40` or `198.51.100.0/28`
//! (and the IPv6 equivalents) and matches them against the peer IP string
//! captured at accept time.

const std = @import("std");
const Ip4Address = std.Io.net.Ip4Address;
const Ip6Address = std.Io.net.Ip6Address;

/// One network as a 16-byte address and prefix length. IPv4 is held in
/// its IPv4-mapped form (`::ffff:a.b.c.d`, prefix + 96), so an IPv4
/// address matches the same way whether the rule or the peer is written
/// as IPv4 or as IPv4-mapped IPv6 (as a dual-stack listener reports it).
pub const Cidr = struct {
    addr: [16]u8,
    prefix: u8,
};

pub const ParseError = error{
    InvalidCidr,
    InvalidPrefix,
};

/// Parse a single IP or `IP/prefix` token into a `Cidr`.
pub fn parseCidr(text: []const u8) ParseError!Cidr {
    const slash = std.mem.indexOfScalar(u8, text, '/');
    const addr_text = if (slash) |i| text[0..i] else text;
    const addr = parseIp(addr_text) orelse return error.InvalidCidr;

    // An IPv4 prefix counts bits of the IPv4 address.
    const v4 = std.mem.indexOfScalar(u8, addr_text, ':') == null;
    const max: u8 = if (v4) 32 else 128;
    var prefix = max;
    if (slash) |i| {
        const digits = text[i + 1 ..];
        if (digits.len == 0 or digits.len > 3) return error.InvalidPrefix;
        for (digits) |ch| if (!std.ascii.isDigit(ch)) return error.InvalidPrefix;
        prefix = std.fmt.parseUnsigned(u8, digits, 10) catch return error.InvalidPrefix;
        if (prefix > max) return error.InvalidPrefix;
    }
    return .{ .addr = addr, .prefix = if (v4) prefix + 96 else prefix };
}

/// True when `ip_text` (no port) falls inside `cidr`.
pub fn matches(cidr: Cidr, ip_text: []const u8) bool {
    const peer = parseIp(ip_text) orelse return false;
    return prefixEqual(cidr.addr, peer, cidr.prefix);
}

/// True when `from` is empty (no restriction) or any entry matches.
pub fn allowed(from: []const Cidr, ip_text: []const u8) bool {
    if (from.len == 0) return true;
    const peer = parseIp(ip_text) orelse return false;
    for (from) |cidr| {
        if (prefixEqual(cidr.addr, peer, cidr.prefix)) return true;
    }
    return false;
}

/// The 16-byte form of an IPv4 or IPv6 address. Accepts the compressed
/// `::ffff:a.b.c.d` and the uncompressed form Zift writes to audit logs
/// (`0:0:0:0:0:ffff:c000:28b`).
fn parseIp(text: []const u8) ?[16]u8 {
    if (Ip4Address.parse(text, 0)) |ip4| {
        return [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff } ++ ip4.bytes;
    } else |_| {}
    const ip6 = Ip6Address.parse(text, 0) catch return null;
    return ip6.bytes;
}

fn prefixEqual(a: [16]u8, b: [16]u8, prefix: u8) bool {
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

    const all = try parseCidr("0.0.0.0/0");
    try std.testing.expect(matches(all, "192.0.2.1"));
    try std.testing.expect(!matches(all, "2001:db8::1"));
}

test "parseCidr ipv6" {
    const host = try parseCidr("2001:db8::1");
    try std.testing.expect(matches(host, "2001:db8::1"));
    try std.testing.expect(!matches(host, "2001:db8::2"));

    const net = try parseCidr("2001:db8::/32");
    try std.testing.expect(matches(net, "2001:db8:1::1"));
    try std.testing.expect(!matches(net, "2001:db9::1"));
    try std.testing.expect(!matches(net, "192.0.2.1"));
}

test "ipv4-mapped peer matches ipv4 from" {
    const host = try parseCidr("192.0.2.1");
    try std.testing.expect(matches(host, "::ffff:192.0.2.1"));
    try std.testing.expect(matches(host, "0:0:0:0:0:ffff:c000:201"));
}

test "ipv4-mapped from matches a plain ipv4 peer" {
    // The reverse of the case above used to never match.
    const host = try parseCidr("::ffff:192.0.2.1");
    try std.testing.expect(matches(host, "192.0.2.1"));
    try std.testing.expect(!matches(host, "192.0.2.2"));
    const net = try parseCidr("::ffff:192.0.2.0/120");
    try std.testing.expect(matches(net, "192.0.2.77"));
    try std.testing.expect(matches(net, "::ffff:192.0.2.77"));
    try std.testing.expect(!matches(net, "192.0.3.1"));
}

test "allowed empty means any" {
    try std.testing.expect(allowed(&.{}, "198.51.100.1"));
}

test "allowed parses the peer once and checks every entry" {
    const from = [_]Cidr{ try parseCidr("10.0.0.0/8"), try parseCidr("2001:db8::/32") };
    try std.testing.expect(allowed(&from, "10.1.2.3"));
    try std.testing.expect(allowed(&from, "2001:db8::5"));
    try std.testing.expect(!allowed(&from, "192.0.2.1"));
    try std.testing.expect(!allowed(&from, ""));
    try std.testing.expect(!allowed(&from, "not-an-ip"));
}

test "parseCidr rejects bad input" {
    try std.testing.expectError(error.InvalidCidr, parseCidr(""));
    try std.testing.expectError(error.InvalidCidr, parseCidr("not-an-ip"));
    try std.testing.expectError(error.InvalidPrefix, parseCidr("10.0.0.0/33"));
    try std.testing.expectError(error.InvalidPrefix, parseCidr("2001:db8::/129"));
    try std.testing.expectError(error.InvalidPrefix, parseCidr("10.0.0.0/"));
    try std.testing.expectError(error.InvalidPrefix, parseCidr("10.0.0.0/2_4"));
    try std.testing.expectError(error.InvalidPrefix, parseCidr("10.0.0.0/+8"));
}
