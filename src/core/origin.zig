//! Origin IP Discovery Engine
//!
//! Discovers real origin IPs behind Cloudflare using multiple techniques:
//! - DNS record analysis (subdomains)
//! - Common subdomain enumeration
//! - IP verification

const std = @import("std");
const ip_ranges = @import("../data/ip_ranges.zig");
const dns = @import("../transport/dns.zig");
const http = @import("../transport/http.zig");

const Allocator = std.mem.Allocator;

/// Discovery source - how the candidate was found
pub const DiscoverySource = enum {
    direct_dns,
    subdomain_leak,
    mail_subdomain,
    dev_subdomain,
    api_subdomain,
    admin_subdomain,

    pub fn description(self: DiscoverySource) []const u8 {
        return switch (self) {
            .direct_dns => "Direct DNS resolution",
            .subdomain_leak => "Subdomain leak",
            .mail_subdomain => "Mail subdomain",
            .dev_subdomain => "Development subdomain",
            .api_subdomain => "API subdomain",
            .admin_subdomain => "Admin subdomain",
        };
    }
};

/// A potential origin IP address
pub const OriginCandidate = struct {
    ip: [16]u8, // IPv4 string + null
    ip_len: u8,
    source: DiscoverySource,
    subdomain: [64]u8,
    subdomain_len: u8,
    confidence: f32,
    is_cloudflare: bool,
    verified: bool = false,

    const Self = @This();

    pub fn ipStr(self: *const Self) []const u8 {
        return self.ip[0..self.ip_len];
    }

    pub fn subdomainStr(self: *const Self) []const u8 {
        return self.subdomain[0..self.subdomain_len];
    }
};

/// Result of origin discovery
pub const DiscoveryResult = struct {
    target: []const u8,
    target_is_cloudflare: bool,
    target_ip: ?[16]u8,
    target_ip_len: u8,
    candidates: std.ArrayList(OriginCandidate),
    subdomains_checked: u32,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, target: []const u8) Self {
        std.debug.assert(target.len > 0);

        return Self{
            .target = target,
            .target_is_cloudflare = false,
            .target_ip = null,
            .target_ip_len = 0,
            .candidates = std.ArrayList(OriginCandidate).init(allocator),
            .subdomains_checked = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.candidates.deinit();
    }

    /// Add a candidate IP
    pub fn addCandidate(
        self: *Self,
        ip_str: []const u8,
        source: DiscoverySource,
        subdomain: []const u8,
    ) !void {
        // Check if it's a Cloudflare IP
        const is_cf = ip_ranges.isCloudflareIp(ip_str);

        // Calculate confidence (non-CF IPs are more interesting)
        const confidence: f32 = if (is_cf) 0.1 else 0.8;

        var candidate = OriginCandidate{
            .ip = undefined,
            .ip_len = @intCast(@min(ip_str.len, 15)),
            .source = source,
            .subdomain = undefined,
            .subdomain_len = @intCast(@min(subdomain.len, 63)),
            .confidence = confidence,
            .is_cloudflare = is_cf,
        };

        @memcpy(candidate.ip[0..candidate.ip_len], ip_str[0..candidate.ip_len]);
        @memcpy(candidate.subdomain[0..candidate.subdomain_len], subdomain[0..candidate.subdomain_len]);

        try self.candidates.append(candidate);
    }

    /// Get non-Cloudflare candidates (potential origins)
    pub fn getNonCfCandidates(self: *const Self) []const OriginCandidate {
        // Return slice - caller filters by is_cloudflare
        return self.candidates.items;
    }
};

/// Common subdomains that often leak origin IPs
pub const LEAK_SUBDOMAINS = [_]struct { name: []const u8, source: DiscoverySource }{
    // Direct/origin
    .{ .name = "direct", .source = .subdomain_leak },
    .{ .name = "origin", .source = .subdomain_leak },
    .{ .name = "backend", .source = .subdomain_leak },
    .{ .name = "server", .source = .subdomain_leak },
    .{ .name = "real", .source = .subdomain_leak },
    .{ .name = "direct-connect", .source = .subdomain_leak },
    // Mail
    .{ .name = "mail", .source = .mail_subdomain },
    .{ .name = "smtp", .source = .mail_subdomain },
    .{ .name = "pop", .source = .mail_subdomain },
    .{ .name = "imap", .source = .mail_subdomain },
    .{ .name = "webmail", .source = .mail_subdomain },
    .{ .name = "mx", .source = .mail_subdomain },
    .{ .name = "mx1", .source = .mail_subdomain },
    .{ .name = "mx2", .source = .mail_subdomain },
    // Dev/staging
    .{ .name = "dev", .source = .dev_subdomain },
    .{ .name = "staging", .source = .dev_subdomain },
    .{ .name = "test", .source = .dev_subdomain },
    .{ .name = "beta", .source = .dev_subdomain },
    .{ .name = "uat", .source = .dev_subdomain },
    .{ .name = "preview", .source = .dev_subdomain },
    // API
    .{ .name = "api", .source = .api_subdomain },
    .{ .name = "api2", .source = .api_subdomain },
    .{ .name = "api-internal", .source = .api_subdomain },
    .{ .name = "internal-api", .source = .api_subdomain },
    // Admin
    .{ .name = "admin", .source = .admin_subdomain },
    .{ .name = "panel", .source = .admin_subdomain },
    .{ .name = "cpanel", .source = .admin_subdomain },
    .{ .name = "whm", .source = .admin_subdomain },
    .{ .name = "manage", .source = .admin_subdomain },
    // Other
    .{ .name = "ftp", .source = .subdomain_leak },
    .{ .name = "sftp", .source = .subdomain_leak },
    .{ .name = "ssh", .source = .subdomain_leak },
    .{ .name = "vpn", .source = .subdomain_leak },
    .{ .name = "old", .source = .subdomain_leak },
    .{ .name = "www2", .source = .subdomain_leak },
};

/// Origin Discovery Engine
pub const OriginDiscovery = struct {
    allocator: Allocator,
    dns_resolver: dns.Resolver,
    http_client: http.Client,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .dns_resolver = dns.Resolver.init(allocator),
            .http_client = http.Client.init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.dns_resolver.deinit();
        self.http_client.deinit();
    }

    /// Run full origin discovery on a target
    pub fn discover(self: *Self, target: []const u8) !DiscoveryResult {
        std.debug.assert(target.len > 0);
        std.debug.assert(target.len <= 253);

        var result = DiscoveryResult.init(self.allocator, target);

        // Step 1: Resolve the main target
        var ip_buf: [16]u8 = undefined;
        if (self.dns_resolver.resolveFirst(target, &ip_buf)) |ip_str| {
            result.target_ip = undefined;
            result.target_ip_len = @intCast(ip_str.len);
            @memcpy(result.target_ip.?[0..ip_str.len], ip_str);

            // Check if target is behind Cloudflare
            result.target_is_cloudflare = ip_ranges.isCloudflareIp(ip_str);

            // Add as candidate
            try result.addCandidate(ip_str, .direct_dns, target);
        } else |_| {
            // DNS resolution failed for main target
        }

        // Step 2: Enumerate common subdomains
        for (LEAK_SUBDOMAINS) |entry| {
            var subdomain_buf: [256]u8 = undefined;
            const subdomain = std.fmt.bufPrint(&subdomain_buf, "{s}.{s}", .{
                entry.name,
                target,
            }) catch continue;

            result.subdomains_checked += 1;

            // Try to resolve the subdomain
            if (self.dns_resolver.resolveFirst(subdomain, &ip_buf)) |ip_str| {
                try result.addCandidate(ip_str, entry.source, subdomain);
            } else |_| {
                // Subdomain doesn't resolve - that's fine
            }
        }

        return result;
    }

    /// Check if an IP is in Cloudflare's ranges
    pub fn isCloudflareIp(ip_str: []const u8) bool {
        return ip_ranges.isCloudflareIp(ip_str);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "OriginCandidate.ipStr returns correct string" {
    var candidate = OriginCandidate{
        .ip = undefined,
        .ip_len = 0,
        .source = .direct_dns,
        .subdomain = undefined,
        .subdomain_len = 0,
        .confidence = 0.8,
        .is_cloudflare = false,
    };

    const ip = "192.168.1.1";
    @memcpy(candidate.ip[0..ip.len], ip);
    candidate.ip_len = @intCast(ip.len);

    try std.testing.expectEqualStrings("192.168.1.1", candidate.ipStr());
}

test "DiscoveryResult.init creates empty result" {
    var result = DiscoveryResult.init(std.testing.allocator, "example.com");
    defer result.deinit();

    try std.testing.expectEqualStrings("example.com", result.target);
    try std.testing.expectEqual(@as(usize, 0), result.candidates.items.len);
}

test "LEAK_SUBDOMAINS contains expected entries" {
    var found_mail = false;
    var found_dev = false;
    var found_api = false;

    for (LEAK_SUBDOMAINS) |entry| {
        if (std.mem.eql(u8, entry.name, "mail")) found_mail = true;
        if (std.mem.eql(u8, entry.name, "dev")) found_dev = true;
        if (std.mem.eql(u8, entry.name, "api")) found_api = true;
    }

    try std.testing.expect(found_mail);
    try std.testing.expect(found_dev);
    try std.testing.expect(found_api);
}

test "DiscoverySource.description returns correct text" {
    try std.testing.expectEqualStrings("Direct DNS resolution", DiscoverySource.direct_dns.description());
    try std.testing.expectEqualStrings("Mail subdomain", DiscoverySource.mail_subdomain.description());
}
