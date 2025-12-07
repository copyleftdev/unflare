//! Core data types for unflare
//!
//! Defines the fundamental structures for Cloudflare detection and analysis.

const std = @import("std");

/// CF-Ray header parsed structure
/// Format: "{ray_id}-{datacenter}" e.g., "9aa1da47c8872f56-LAX"
pub const CfRay = struct {
    ray_id: [16]u8,
    datacenter: [3]u8,
    raw: []const u8,

    const Self = @This();

    /// Parse a CF-Ray header value
    /// Returns null if the format is invalid
    pub fn parse(raw: []const u8) ?Self {
        // Assertions: document our expectations
        std.debug.assert(raw.len <= 64); // Reasonable upper bound

        // Format: 16-char hex + "-" + 3-char datacenter = 20 chars minimum
        if (raw.len < 20) return null;

        const dash_pos = std.mem.lastIndexOfScalar(u8, raw, '-') orelse return null;

        // Datacenter code must be exactly 3 characters
        const dc_start = dash_pos + 1;
        if (raw.len - dc_start != 3) return null;

        // Ray ID should be 16 hex characters
        if (dash_pos < 16) return null;

        return Self{
            .ray_id = raw[dash_pos - 16 .. dash_pos][0..16].*,
            .datacenter = raw[dc_start..][0..3].*,
            .raw = raw,
        };
    }

    /// Get datacenter as a string slice
    pub fn datacenterStr(self: *const Self) []const u8 {
        return &self.datacenter;
    }
};

/// Cache status from CF-Cache-Status header
pub const CacheStatus = enum {
    hit,
    miss,
    expired,
    stale,
    bypass,
    dynamic,
    revalidated,
    unknown,

    const Self = @This();

    pub fn parse(value: []const u8) Self {
        const lower = blk: {
            var buf: [16]u8 = undefined;
            const len = @min(value.len, buf.len);
            for (value[0..len], 0..) |c, i| {
                buf[i] = std.ascii.toLower(c);
            }
            break :blk buf[0..len];
        };

        if (std.mem.eql(u8, lower, "hit")) return .hit;
        if (std.mem.eql(u8, lower, "miss")) return .miss;
        if (std.mem.eql(u8, lower, "expired")) return .expired;
        if (std.mem.eql(u8, lower, "stale")) return .stale;
        if (std.mem.eql(u8, lower, "bypass")) return .bypass;
        if (std.mem.eql(u8, lower, "dynamic")) return .dynamic;
        if (std.mem.eql(u8, lower, "revalidated")) return .revalidated;
        return .unknown;
    }

    pub fn isCached(self: Self) bool {
        return self == .hit or self == .stale or self == .revalidated;
    }
};

/// Detection signals - which indicators were found
pub const SignalSet = packed struct {
    server_header: bool = false,
    cf_ray_header: bool = false,
    cf_cache_status: bool = false,
    cf_ip_range: bool = false,
    cdn_cgi_trace: bool = false,
    alt_svc_h3: bool = false,
    nel_cloudflare: bool = false,
    cf_mitigated: bool = false,

    const Self = @This();

    /// Count number of signals detected
    pub fn count(self: Self) u8 {
        var n: u8 = 0;
        if (self.server_header) n += 1;
        if (self.cf_ray_header) n += 1;
        if (self.cf_cache_status) n += 1;
        if (self.cf_ip_range) n += 1;
        if (self.cdn_cgi_trace) n += 1;
        if (self.alt_svc_h3) n += 1;
        if (self.nel_cloudflare) n += 1;
        if (self.cf_mitigated) n += 1;
        return n;
    }
};

/// Detected feature flags
pub const FeatureFlags = packed struct {
    http3_enabled: bool = false,
    waf_active: bool = false,
    bot_management: bool = false,
    workers_detected: bool = false,
    challenge_active: bool = false,
    _padding: u3 = 0,
};

/// Result of Cloudflare detection
pub const DetectionResult = struct {
    target: []const u8,
    is_cloudflare: bool,
    confidence: f32, // 0.0 to 1.0

    signals: SignalSet,
    features: FeatureFlags,

    datacenter: ?[3]u8,
    cf_ray: ?CfRay,

    latency_ns: u64,
    timestamp: i64,

    const Self = @This();

    /// Create a new empty result
    pub fn init(target: []const u8) Self {
        std.debug.assert(target.len > 0);
        std.debug.assert(target.len <= 253); // Max domain length

        return Self{
            .target = target,
            .is_cloudflare = false,
            .confidence = 0.0,
            .signals = .{},
            .features = .{},
            .datacenter = null,
            .cf_ray = null,
            .latency_ns = 0,
            .timestamp = std.time.timestamp(),
        };
    }

    /// Calculate confidence from detected signals
    pub fn calculateConfidence(self: *Self) void {
        const weights = .{
            .server_header = 0.30,
            .cf_ray_header = 0.25,
            .cf_ip_range = 0.20,
            .cdn_cgi_trace = 0.15,
            .cf_cache_status = 0.10,
            .alt_svc_h3 = 0.05,
            .nel_cloudflare = 0.05,
            .cf_mitigated = 0.10,
        };

        var conf: f32 = 0.0;
        if (self.signals.server_header) conf += weights.server_header;
        if (self.signals.cf_ray_header) conf += weights.cf_ray_header;
        if (self.signals.cf_ip_range) conf += weights.cf_ip_range;
        if (self.signals.cdn_cgi_trace) conf += weights.cdn_cgi_trace;
        if (self.signals.cf_cache_status) conf += weights.cf_cache_status;
        if (self.signals.alt_svc_h3) conf += weights.alt_svc_h3;
        if (self.signals.nel_cloudflare) conf += weights.nel_cloudflare;
        if (self.signals.cf_mitigated) conf += weights.cf_mitigated;

        self.confidence = @min(conf, 1.0);
        self.is_cloudflare = self.confidence >= 0.30;

        std.debug.assert(self.confidence >= 0.0 and self.confidence <= 1.0);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "CfRay.parse extracts datacenter code" {
    const ray = CfRay.parse("9aa1da47c8872f56-LAX").?;
    try std.testing.expectEqualStrings("LAX", &ray.datacenter);
    try std.testing.expectEqualStrings("9aa1da47c8872f56", &ray.ray_id);
}

test "CfRay.parse returns null for invalid format" {
    try std.testing.expect(CfRay.parse("invalid") == null);
    try std.testing.expect(CfRay.parse("") == null);
    try std.testing.expect(CfRay.parse("abc-") == null);
    try std.testing.expect(CfRay.parse("-LAX") == null);
    try std.testing.expect(CfRay.parse("short-LAX") == null);
}

test "CfRay.parse handles various valid formats" {
    const test_cases = [_]struct { input: []const u8, dc: []const u8 }{
        .{ .input = "9aa1da47c8872f56-LAX", .dc = "LAX" },
        .{ .input = "abcdef0123456789-SFO", .dc = "SFO" },
        .{ .input = "0000000000000000-NRT", .dc = "NRT" },
    };

    for (test_cases) |tc| {
        const ray = CfRay.parse(tc.input).?;
        try std.testing.expectEqualStrings(tc.dc, &ray.datacenter);
    }
}

test "CacheStatus.parse handles all known statuses" {
    try std.testing.expectEqual(CacheStatus.hit, CacheStatus.parse("HIT"));
    try std.testing.expectEqual(CacheStatus.hit, CacheStatus.parse("hit"));
    try std.testing.expectEqual(CacheStatus.miss, CacheStatus.parse("MISS"));
    try std.testing.expectEqual(CacheStatus.dynamic, CacheStatus.parse("DYNAMIC"));
    try std.testing.expectEqual(CacheStatus.unknown, CacheStatus.parse("INVALID"));
}

test "CacheStatus.isCached returns correct values" {
    try std.testing.expect(CacheStatus.hit.isCached());
    try std.testing.expect(CacheStatus.stale.isCached());
    try std.testing.expect(CacheStatus.revalidated.isCached());
    try std.testing.expect(!CacheStatus.miss.isCached());
    try std.testing.expect(!CacheStatus.dynamic.isCached());
}

test "SignalSet.count returns correct count" {
    var signals = SignalSet{};
    try std.testing.expectEqual(@as(u8, 0), signals.count());

    signals.server_header = true;
    try std.testing.expectEqual(@as(u8, 1), signals.count());

    signals.cf_ray_header = true;
    signals.cf_ip_range = true;
    try std.testing.expectEqual(@as(u8, 3), signals.count());
}

test "DetectionResult.calculateConfidence computes correctly" {
    var result = DetectionResult.init("example.com");

    result.signals.server_header = true; // 0.30
    result.signals.cf_ray_header = true; // 0.25
    result.calculateConfidence();

    try std.testing.expect(result.confidence >= 0.54);
    try std.testing.expect(result.confidence <= 0.56);
    try std.testing.expect(result.is_cloudflare);
}

test "DetectionResult.calculateConfidence caps at 1.0" {
    var result = DetectionResult.init("example.com");

    // Set all signals
    result.signals = .{
        .server_header = true,
        .cf_ray_header = true,
        .cf_cache_status = true,
        .cf_ip_range = true,
        .cdn_cgi_trace = true,
        .alt_svc_h3 = true,
        .nel_cloudflare = true,
        .cf_mitigated = true,
    };
    result.calculateConfidence();

    try std.testing.expectEqual(@as(f32, 1.0), result.confidence);
}
