//! CDN/WAF/Cloud IP Range Database
//!
//! Cloudflare and other provider IP ranges embedded at compile time.
//! Uses CIDR matching for O(1) lookup per range.

const std = @import("std");

/// Provider type classification
pub const ProviderType = enum {
    cdn,
    waf,
    cloud,
};

/// Provider identification result
pub const ProviderResult = struct {
    name: []const u8,
    type: ProviderType,
};

/// CIDR range representation
pub const Cidr = struct {
    network: u32, // Network address as u32 (big-endian)
    mask: u5, // Prefix length (0-32)

    const Self = @This();

    /// Check if an IP (as u32) is in this CIDR range
    pub fn contains(self: Self, ip: u32) bool {
        if (self.mask == 0) return true;
        if (self.mask == 32) return ip == self.network;

        // Calculate mask bits: for /24, we want 0xFFFFFF00
        const shift_amt: u5 = @intCast(32 - @as(u6, self.mask));
        const mask_bits: u32 = @as(u32, 0xFFFFFFFF) << shift_amt;
        return (ip & mask_bits) == (self.network & mask_bits);
    }

    /// Parse a CIDR string at comptime
    pub fn parse(comptime cidr_str: []const u8) Self {
        @setEvalBranchQuota(10000);
        const slash_pos = comptime std.mem.indexOfScalar(u8, cidr_str, '/') orelse
            @compileError("Invalid CIDR: missing /");

        const ip_part = cidr_str[0..slash_pos];
        const mask_part = cidr_str[slash_pos + 1 ..];

        return Self{
            .network = comptime parseIpv4(ip_part),
            .mask = comptime std.fmt.parseInt(u5, mask_part, 10) catch
                @compileError("Invalid CIDR mask"),
        };
    }
};

/// Parse IPv4 address string to u32 at comptime
fn parseIpv4(comptime ip_str: []const u8) u32 {
    comptime {
        var result: u32 = 0;
        var octet: u8 = 0;
        var octet_count: u8 = 0;
        var digit_count: u8 = 0;

        for (ip_str) |c| {
            if (c == '.') {
                if (digit_count == 0) @compileError("Invalid IP: empty octet");
                result = (result << 8) | octet;
                octet = 0;
                octet_count += 1;
                digit_count = 0;
            } else if (c >= '0' and c <= '9') {
                octet = octet * 10 + (c - '0');
                digit_count += 1;
            } else {
                @compileError("Invalid IP: unexpected character");
            }
        }

        if (digit_count == 0) @compileError("Invalid IP: empty last octet");
        result = (result << 8) | octet;
        octet_count += 1;

        if (octet_count != 4) @compileError("Invalid IP: wrong number of octets");

        return result;
    }
}

/// Parse runtime IPv4 string to u32
pub fn parseIpv4Runtime(ip_str: []const u8) ?u32 {
    var result: u32 = 0;
    var octet: u32 = 0;
    var octet_count: u8 = 0;
    var digit_count: u8 = 0;

    for (ip_str) |c| {
        if (c == '.') {
            if (digit_count == 0 or octet > 255) return null;
            result = (result << 8) | @as(u32, @intCast(octet));
            octet = 0;
            octet_count += 1;
            digit_count = 0;
        } else if (c >= '0' and c <= '9') {
            octet = octet * 10 + (c - '0');
            digit_count += 1;
            if (digit_count > 3) return null;
        } else {
            return null;
        }
    }

    if (digit_count == 0 or octet > 255) return null;
    result = (result << 8) | @as(u32, @intCast(octet));
    octet_count += 1;

    if (octet_count != 4) return null;
    return result;
}

// Cloudflare IPv4 ranges (source: https://www.cloudflare.com/ips-v4)
pub const CLOUDFLARE_RANGES = [_]Cidr{
    Cidr.parse("173.245.48.0/20"),
    Cidr.parse("103.21.244.0/22"),
    Cidr.parse("103.22.200.0/22"),
    Cidr.parse("103.31.4.0/22"),
    Cidr.parse("141.101.64.0/18"),
    Cidr.parse("108.162.192.0/18"),
    Cidr.parse("190.93.240.0/20"),
    Cidr.parse("188.114.96.0/20"),
    Cidr.parse("197.234.240.0/22"),
    Cidr.parse("198.41.128.0/17"),
    Cidr.parse("162.158.0.0/15"),
    Cidr.parse("104.16.0.0/13"),
    Cidr.parse("104.24.0.0/14"),
    Cidr.parse("172.64.0.0/13"),
    Cidr.parse("131.0.72.0/22"),
};

// Fastly ranges (partial)
pub const FASTLY_RANGES = [_]Cidr{
    Cidr.parse("23.235.32.0/20"),
    Cidr.parse("43.249.72.0/22"),
    Cidr.parse("103.244.50.0/24"),
    Cidr.parse("103.245.222.0/23"),
    Cidr.parse("151.101.0.0/16"),
    Cidr.parse("157.52.64.0/18"),
    Cidr.parse("199.232.0.0/16"),
};

// Akamai ranges (partial)
pub const AKAMAI_RANGES = [_]Cidr{
    Cidr.parse("23.0.0.0/12"),
    Cidr.parse("23.32.0.0/11"),
    Cidr.parse("23.64.0.0/14"),
    Cidr.parse("104.64.0.0/10"),
};

/// Check if an IP string is in Cloudflare's ranges
pub fn isCloudflareIp(ip_str: []const u8) bool {
    const ip = parseIpv4Runtime(ip_str) orelse return false;

    for (CLOUDFLARE_RANGES) |cidr| {
        if (cidr.contains(ip)) return true;
    }
    return false;
}

/// Check IP against all known providers
pub fn checkProvider(ip_str: []const u8) ?ProviderResult {
    const ip = parseIpv4Runtime(ip_str) orelse return null;

    // Check Cloudflare first (most common for this tool)
    for (CLOUDFLARE_RANGES) |cidr| {
        if (cidr.contains(ip)) {
            return ProviderResult{ .name = "cloudflare", .type = .waf };
        }
    }

    // Check Fastly
    for (FASTLY_RANGES) |cidr| {
        if (cidr.contains(ip)) {
            return ProviderResult{ .name = "fastly", .type = .cdn };
        }
    }

    // Check Akamai
    for (AKAMAI_RANGES) |cidr| {
        if (cidr.contains(ip)) {
            return ProviderResult{ .name = "akamai", .type = .cdn };
        }
    }

    return null;
}

// ============================================================================
// Tests
// ============================================================================

test "Cidr.contains correctly matches IPs" {
    const cidr = Cidr.parse("104.16.0.0/13");

    // 104.16.0.0 - 104.23.255.255 should match
    try std.testing.expect(cidr.contains(parseIpv4Runtime("104.16.0.1").?));
    try std.testing.expect(cidr.contains(parseIpv4Runtime("104.16.1.1").?));
    try std.testing.expect(cidr.contains(parseIpv4Runtime("104.23.255.255").?));

    // Outside range
    try std.testing.expect(!cidr.contains(parseIpv4Runtime("104.24.0.0").?));
    try std.testing.expect(!cidr.contains(parseIpv4Runtime("8.8.8.8").?));
}

test "parseIpv4Runtime parses valid IPs" {
    try std.testing.expectEqual(@as(u32, 0x08080808), parseIpv4Runtime("8.8.8.8").?);
    try std.testing.expectEqual(@as(u32, 0xC0A80101), parseIpv4Runtime("192.168.1.1").?);
    try std.testing.expectEqual(@as(u32, 0x00000000), parseIpv4Runtime("0.0.0.0").?);
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), parseIpv4Runtime("255.255.255.255").?);
}

test "parseIpv4Runtime rejects invalid IPs" {
    try std.testing.expect(parseIpv4Runtime("") == null);
    try std.testing.expect(parseIpv4Runtime("1.2.3") == null);
    try std.testing.expect(parseIpv4Runtime("1.2.3.4.5") == null);
    try std.testing.expect(parseIpv4Runtime("256.1.1.1") == null);
    try std.testing.expect(parseIpv4Runtime("a.b.c.d") == null);
}

test "isCloudflareIp identifies Cloudflare IPs" {
    // Known Cloudflare IPs
    try std.testing.expect(isCloudflareIp("104.16.1.1"));
    try std.testing.expect(isCloudflareIp("173.245.48.12"));
    try std.testing.expect(isCloudflareIp("172.64.0.1"));

    // Non-Cloudflare IPs
    try std.testing.expect(!isCloudflareIp("8.8.8.8"));
    try std.testing.expect(!isCloudflareIp("192.168.1.1"));
    try std.testing.expect(!isCloudflareIp("1.2.3.4"));
}

test "checkProvider returns correct provider" {
    // Cloudflare
    const cf_result = checkProvider("104.16.1.1").?;
    try std.testing.expectEqualStrings("cloudflare", cf_result.name);
    try std.testing.expectEqual(ProviderType.waf, cf_result.type);

    // Fastly
    const fastly_result = checkProvider("151.101.1.1").?;
    try std.testing.expectEqualStrings("fastly", fastly_result.name);
    try std.testing.expectEqual(ProviderType.cdn, fastly_result.type);

    // Unknown
    try std.testing.expect(checkProvider("8.8.8.8") == null);
}
