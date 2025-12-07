//! Cloudflare Detection Engine
//!
//! Multi-signal detection with confidence scoring.

const std = @import("std");
const types = @import("types.zig");
const ip_ranges = @import("../data/ip_ranges.zig");
const http = @import("../transport/http.zig");

const Allocator = std.mem.Allocator;
const DetectionResult = types.DetectionResult;
const SignalSet = types.SignalSet;
const CfRay = types.CfRay;

/// Detection configuration
pub const Config = struct {
    timeout_ms: u32 = 10_000,
    check_trace: bool = true,
    check_ip_range: bool = true,
    confidence_threshold: f32 = 0.30,
};

/// Detection Error
pub const DetectionError = error{
    HttpFailed,
    InvalidTarget,
    Timeout,
    OutOfMemory,
};

/// Cloudflare Detector
pub const Detector = struct {
    allocator: Allocator,
    config: Config,
    http_client: http.Client,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .config = .{},
            .http_client = http.Client.init(allocator),
        };
    }

    pub fn initWithConfig(allocator: Allocator, config: Config) Self {
        std.debug.assert(config.timeout_ms > 0);
        std.debug.assert(config.confidence_threshold >= 0.0);
        std.debug.assert(config.confidence_threshold <= 1.0);

        return Self{
            .allocator = allocator,
            .config = config,
            .http_client = http.Client.init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.http_client.deinit();
    }

    /// Detect Cloudflare on a target domain
    pub fn detect(self: *Self, target: []const u8) DetectionError!DetectionResult {
        std.debug.assert(target.len > 0);
        std.debug.assert(target.len <= 253);

        const start_time = std.time.nanoTimestamp();

        var result = DetectionResult.init(target);

        // Build URL
        var url_buf: [512]u8 = undefined;
        const url = std.fmt.bufPrint(&url_buf, "https://{s}/", .{target}) catch {
            return error.InvalidTarget;
        };

        // Make HTTP request
        var response = self.http_client.get(url) catch {
            // Try without HTTPS
            const http_url = std.fmt.bufPrint(&url_buf, "http://{s}/", .{target}) catch {
                return error.InvalidTarget;
            };
            var http_response = self.http_client.get(http_url) catch {
                return error.HttpFailed;
            };
            defer http_response.deinit();

            self.analyzeResponse(&http_response, &result);
            result.latency_ns = @intCast(std.time.nanoTimestamp() - start_time);
            result.calculateConfidence();
            return result;
        };
        defer response.deinit();

        // Analyze response
        self.analyzeResponse(&response, &result);

        // Check /cdn-cgi/trace if enabled
        if (self.config.check_trace) {
            self.checkTrace(target, &result) catch {};
        }

        result.latency_ns = @intCast(std.time.nanoTimestamp() - start_time);
        result.calculateConfidence();

        std.debug.assert(result.confidence >= 0.0 and result.confidence <= 1.0);

        return result;
    }

    /// Analyze HTTP response for Cloudflare signals
    fn analyzeResponse(self: *Self, response: *http.Response, result: *DetectionResult) void {
        _ = self;

        // Check Server header
        if (response.getHeader("server")) |server| {
            if (std.ascii.indexOfIgnoreCase(server, "cloudflare") != null) {
                result.signals.server_header = true;
            }
        }

        // Check CF-Ray header
        if (response.getHeader("cf-ray")) |ray| {
            if (CfRay.parse(ray)) |parsed| {
                result.signals.cf_ray_header = true;
                result.cf_ray = parsed;
                result.datacenter = parsed.datacenter;
            }
        }

        // Check CF-Cache-Status
        if (response.getHeader("cf-cache-status")) |_| {
            result.signals.cf_cache_status = true;
        }

        // Check Alt-Svc for HTTP/3
        if (response.getHeader("alt-svc")) |alt_svc| {
            if (std.mem.indexOf(u8, alt_svc, "h3=") != null) {
                result.signals.alt_svc_h3 = true;
                result.features.http3_enabled = true;
            }
        }

        // Check NEL header
        if (response.getHeader("nel")) |nel| {
            if (std.ascii.indexOfIgnoreCase(nel, "cloudflare") != null) {
                result.signals.nel_cloudflare = true;
            }
        }

        // Check CF-Mitigated (WAF)
        if (response.getHeader("cf-mitigated")) |_| {
            result.signals.cf_mitigated = true;
            result.features.waf_active = true;
        }
    }

    /// Check /cdn-cgi/trace endpoint
    fn checkTrace(self: *Self, target: []const u8, result: *DetectionResult) !void {
        var response = self.http_client.fetchTrace(target) catch {
            return;
        };
        defer response.deinit();

        // If we get a 200 response, it's likely Cloudflare
        if (response.status_code == 200) {
            const body = response.body.items;
            if (std.mem.indexOf(u8, body, "fl=") != null and
                std.mem.indexOf(u8, body, "colo=") != null)
            {
                result.signals.cdn_cgi_trace = true;

                // Extract datacenter from trace
                if (result.datacenter == null) {
                    if (std.mem.indexOf(u8, body, "colo=")) |pos| {
                        const start = pos + 5;
                        if (start + 3 <= body.len) {
                            result.datacenter = body[start..][0..3].*;
                        }
                    }
                }
            }
        }
    }

    /// Analyze HTTP headers for Cloudflare signals
    pub fn analyzeHeaders(headers: []const Header) SignalSet {
        var signals = SignalSet{};

        for (headers) |header| {
            const name_lower = blk: {
                var buf: [64]u8 = undefined;
                const len = @min(header.name.len, buf.len);
                for (header.name[0..len], 0..) |c, i| {
                    buf[i] = std.ascii.toLower(c);
                }
                break :blk buf[0..len];
            };

            if (std.mem.eql(u8, name_lower, "server")) {
                if (std.ascii.indexOfIgnoreCase(header.value, "cloudflare") != null) {
                    signals.server_header = true;
                }
            } else if (std.mem.eql(u8, name_lower, "cf-ray")) {
                if (CfRay.parse(header.value) != null) {
                    signals.cf_ray_header = true;
                }
            } else if (std.mem.eql(u8, name_lower, "cf-cache-status")) {
                signals.cf_cache_status = true;
            } else if (std.mem.eql(u8, name_lower, "alt-svc")) {
                if (std.mem.indexOf(u8, header.value, "h3=") != null) {
                    signals.alt_svc_h3 = true;
                }
            } else if (std.mem.eql(u8, name_lower, "nel")) {
                if (std.ascii.indexOfIgnoreCase(header.value, "cloudflare") != null) {
                    signals.nel_cloudflare = true;
                }
            } else if (std.mem.eql(u8, name_lower, "cf-mitigated")) {
                signals.cf_mitigated = true;
            }
        }

        std.debug.assert(signals.count() <= 8);

        return signals;
    }
};

/// HTTP Header structure
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

// ============================================================================
// Tests
// ============================================================================

test "Detector.init creates valid detector" {
    var detector = Detector.init(std.testing.allocator);
    defer detector.deinit();

    try std.testing.expectEqual(@as(u32, 10_000), detector.config.timeout_ms);
    try std.testing.expect(detector.config.check_trace);
}

test "Detector.analyzeHeaders detects server header" {
    const headers = [_]Header{
        .{ .name = "Server", .value = "cloudflare" },
        .{ .name = "Content-Type", .value = "text/html" },
    };

    const signals = Detector.analyzeHeaders(&headers);

    try std.testing.expect(signals.server_header);
    try std.testing.expect(!signals.cf_ray_header);
}

test "Detector.analyzeHeaders detects cf-ray header" {
    const headers = [_]Header{
        .{ .name = "cf-ray", .value = "9aa1da47c8872f56-LAX" },
    };

    const signals = Detector.analyzeHeaders(&headers);

    try std.testing.expect(signals.cf_ray_header);
}

test "Detector.analyzeHeaders detects multiple signals" {
    const headers = [_]Header{
        .{ .name = "Server", .value = "cloudflare" },
        .{ .name = "cf-ray", .value = "9aa1da47c8872f56-LAX" },
        .{ .name = "cf-cache-status", .value = "HIT" },
        .{ .name = "alt-svc", .value = "h3=\":443\"; ma=86400" },
    };

    const signals = Detector.analyzeHeaders(&headers);

    try std.testing.expect(signals.server_header);
    try std.testing.expect(signals.cf_ray_header);
    try std.testing.expect(signals.cf_cache_status);
    try std.testing.expect(signals.alt_svc_h3);
    try std.testing.expectEqual(@as(u8, 4), signals.count());
}

test "Detector.analyzeHeaders handles empty headers" {
    const headers = [_]Header{};
    const signals = Detector.analyzeHeaders(&headers);

    try std.testing.expectEqual(@as(u8, 0), signals.count());
}
