//! DNS Resolver
//!
//! DNS resolution using system resolver and raw UDP queries.

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;

/// DNS Record Types
pub const RecordType = enum(u16) {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    MX = 15,
    TXT = 16,
    AAAA = 28,
};

/// DNS Error
pub const DnsError = error{
    ResolutionFailed,
    InvalidHostname,
    Timeout,
    OutOfMemory,
    NoRecords,
};

/// Resolved IP address
pub const ResolvedIp = struct {
    ip: [4]u8,

    pub fn format(self: ResolvedIp, buf: []u8) ![]u8 {
        return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
            self.ip[0],
            self.ip[1],
            self.ip[2],
            self.ip[3],
        });
    }

    pub fn toU32(self: ResolvedIp) u32 {
        return (@as(u32, self.ip[0]) << 24) |
            (@as(u32, self.ip[1]) << 16) |
            (@as(u32, self.ip[2]) << 8) |
            @as(u32, self.ip[3]);
    }
};

/// DNS Resolver
pub const Resolver = struct {
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{ .allocator = allocator };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// Resolve A records for a hostname using system DNS
    pub fn resolveA(self: *Self, hostname: []const u8) DnsError!std.ArrayList(ResolvedIp) {
        std.debug.assert(hostname.len > 0);
        std.debug.assert(hostname.len <= 253);

        var results = std.ArrayList(ResolvedIp).init(self.allocator);
        errdefer results.deinit();

        // Null-terminate the hostname for C interop
        var hostname_buf: [254]u8 = undefined;
        if (hostname.len >= hostname_buf.len) return error.InvalidHostname;
        @memcpy(hostname_buf[0..hostname.len], hostname);
        hostname_buf[hostname.len] = 0;

        const hints = std.posix.addrinfo{
            .flags = .{},
            .family = std.posix.AF.INET,
            .socktype = std.posix.SOCK.STREAM,
            .protocol = 0,
            .addrlen = 0,
            .addr = null,
            .canonname = null,
            .next = null,
        };

        var res: ?*std.posix.addrinfo = null;
        const rc = std.c.getaddrinfo(@ptrCast(&hostname_buf), null, &hints, &res);
        if (@intFromEnum(rc) != 0) {
            return error.ResolutionFailed;
        }
        defer if (res) |r| std.c.freeaddrinfo(r);

        var current = res;
        while (current) |info| {
            if (info.family == std.posix.AF.INET) {
                const addr: *const std.posix.sockaddr.in = @ptrCast(@alignCast(info.addr));
                const ip_bytes: [4]u8 = @bitCast(addr.addr);
                results.append(.{ .ip = ip_bytes }) catch return error.OutOfMemory;
            }
            current = info.next;
        }

        if (results.items.len == 0) {
            return error.NoRecords;
        }

        return results;
    }

    /// Resolve hostname and return first IP as string
    pub fn resolveFirst(self: *Self, hostname: []const u8, buf: []u8) DnsError![]u8 {
        var results = try self.resolveA(hostname);
        defer results.deinit();

        if (results.items.len == 0) return error.NoRecords;

        return results.items[0].format(buf) catch return error.OutOfMemory;
    }
};

/// SPF parse result
pub const SpfResult = struct {
    ips: [16][15]u8,
    count: u8,
};

/// Parse SPF record to extract IP addresses
pub fn parseSPF(txt: []const u8) SpfResult {
    var result = SpfResult{
        .ips = undefined,
        .count = 0,
    };

    if (!std.mem.startsWith(u8, txt, "v=spf1")) return result;

    var it = std.mem.splitScalar(u8, txt, ' ');
    while (it.next()) |part| {
        if (std.mem.startsWith(u8, part, "ip4:")) {
            const ip = part[4..];
            // Skip CIDR notation for now
            const ip_only = if (std.mem.indexOfScalar(u8, ip, '/')) |slash|
                ip[0..slash]
            else
                ip;

            if (result.count < 16 and ip_only.len <= 15) {
                @memcpy(result.ips[result.count][0..ip_only.len], ip_only);
                result.count += 1;
            }
        }
    }

    return result;
}

// ============================================================================
// Tests
// ============================================================================

test "parseSPF extracts IP addresses" {
    const spf = "v=spf1 ip4:192.168.1.1 ip4:10.0.0.1 include:_spf.google.com ~all";
    const result = parseSPF(spf);

    try std.testing.expectEqual(@as(u8, 2), result.count);
}

test "parseSPF handles CIDR notation" {
    const spf = "v=spf1 ip4:192.168.1.0/24 ~all";
    const result = parseSPF(spf);

    try std.testing.expectEqual(@as(u8, 1), result.count);
}

test "parseSPF returns empty for non-SPF records" {
    const txt = "google-site-verification=abc123";
    const result = parseSPF(txt);

    try std.testing.expectEqual(@as(u8, 0), result.count);
}
