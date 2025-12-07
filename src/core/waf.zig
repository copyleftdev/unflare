//! Cloudflare WAF Detection
//!
//! Detects Cloudflare WAF presence and fingerprints security configuration.
//! Identifies security levels, managed rules, and challenge types.

const std = @import("std");
const http = @import("../transport/http.zig");

const Allocator = std.mem.Allocator;

// ============================================================================
// Types
// ============================================================================

/// WAF detection result
pub const WafResult = struct {
    waf_active: bool,
    confidence: f32,
    security_level: SecurityLevel,
    bot_management: bool,
    rate_limiting: bool,
    challenge_type: ?ChallengeType,
    signals: WafSignals,

    pub const SecurityLevel = enum {
        off,
        low,
        medium,
        high,
        under_attack,
        unknown,
    };

    pub const ChallengeType = enum {
        js_challenge,
        managed_challenge,
        interactive_challenge,
        block,
    };
};

/// Detection signals for WAF
pub const WafSignals = struct {
    cf_mitigated_header: bool = false,
    cf_mitigated_value: ?MitigatedValue = null,
    challenge_page: bool = false,
    block_page: bool = false,
    ray_id_in_error: bool = false,
    cf_chl_bypass_cookie: bool = false,

    pub const MitigatedValue = enum {
        challenge,
        block,
        managed,
        js_challenge,
        unknown,
    };

    /// Calculate confidence from signals
    pub fn confidence(self: WafSignals) f32 {
        var score: f32 = 0.0;

        if (self.cf_mitigated_header) score += 0.90;
        if (self.challenge_page) score += 0.85;
        if (self.block_page) score += 0.85;
        if (self.ray_id_in_error) score += 0.30;
        if (self.cf_chl_bypass_cookie) score += 0.70;

        return @min(score, 1.0);
    }
};

/// Errors for WAF detection
pub const WafError = error{
    InvalidTarget,
    ConnectionFailed,
    Timeout,
};

// ============================================================================
// Constants
// ============================================================================

const CF_MITIGATED_HEADER = "cf-mitigated";
const SET_COOKIE_HEADER = "set-cookie";
const CF_CHL_BYPASS = "cf_chl_bypass";

// ============================================================================
// Public API
// ============================================================================

/// Detect WAF presence on target (passive analysis)
pub fn detectWaf(allocator: Allocator, target: []const u8) WafError!WafResult {
    std.debug.assert(target.len > 0);
    std.debug.assert(target.len <= 253);

    var result = WafResult{
        .waf_active = false,
        .confidence = 0.0,
        .security_level = .unknown,
        .bot_management = false,
        .rate_limiting = false,
        .challenge_type = null,
        .signals = .{},
    };

    // Fetch response
    const response = fetchResponse(allocator, target) catch |err| {
        return switch (err) {
            error.ConnectionFailed, error.RequestFailed, error.TlsError => WafError.ConnectionFailed,
            error.Timeout => WafError.Timeout,
            error.InvalidUrl, error.InvalidTarget => WafError.InvalidTarget,
            error.OutOfMemory => WafError.ConnectionFailed,
        };
    };
    defer allocator.free(response.body);
    defer allocator.free(response.headers);

    // Analyze headers for WAF signals
    analyzeHeaders(response.headers, &result);

    // Analyze body for challenge/block pages
    analyzeBody(response.body, &result);

    // Calculate confidence
    result.confidence = result.signals.confidence();
    result.waf_active = result.confidence >= 0.30;

    std.debug.assert(result.confidence >= 0.0 and result.confidence <= 1.0);
    return result;
}

/// Parse cf-mitigated header value
pub fn parseMitigatedValue(value: []const u8) WafSignals.MitigatedValue {
    const trimmed = std.mem.trim(u8, value, " \t");

    if (std.ascii.eqlIgnoreCase(trimmed, "challenge")) {
        return .challenge;
    } else if (std.ascii.eqlIgnoreCase(trimmed, "block")) {
        return .block;
    } else if (std.ascii.eqlIgnoreCase(trimmed, "managed")) {
        return .managed;
    } else if (std.ascii.eqlIgnoreCase(trimmed, "js_challenge")) {
        return .js_challenge;
    }

    return .unknown;
}

/// Get security level description
pub fn getSecurityLevelDescription(level: WafResult.SecurityLevel) []const u8 {
    return switch (level) {
        .off => "Off - No active protection",
        .low => "Low - Only known bad actors",
        .medium => "Medium - Suspicious requests challenged",
        .high => "High - Most non-allowlisted challenged",
        .under_attack => "I'm Under Attack - All requests challenged",
        .unknown => "Unknown",
    };
}

/// Get challenge type description
pub fn getChallengeDescription(challenge: WafResult.ChallengeType) []const u8 {
    return switch (challenge) {
        .js_challenge => "JavaScript Challenge",
        .managed_challenge => "Managed Challenge",
        .interactive_challenge => "Interactive Challenge (Turnstile)",
        .block => "Request Blocked",
    };
}

// ============================================================================
// Internal Functions
// ============================================================================

const Response = struct {
    status: u16,
    headers: []const u8,
    body: []const u8,
};

/// Fetch response from target
fn fetchResponse(allocator: Allocator, target: []const u8) !Response {
    var client = http.HttpClient.init(allocator);
    defer client.deinit();

    var url_buf: [512]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "https://{s}/", .{target}) catch {
        return error.InvalidTarget;
    };

    var http_response = try client.get(url);
    defer http_response.deinit();

    var header_buf = std.ArrayList(u8).init(allocator);
    errdefer header_buf.deinit();

    for (http_response.headers.items) |h| {
        try header_buf.appendSlice(h.name);
        try header_buf.append(':');
        try header_buf.appendSlice(h.value);
        try header_buf.append('\n');
    }

    return .{
        .status = @intCast(http_response.status_code),
        .headers = try header_buf.toOwnedSlice(),
        .body = try allocator.dupe(u8, http_response.body.items),
    };
}

/// Analyze headers for WAF signals
fn analyzeHeaders(headers: []const u8, result: *WafResult) void {
    var lines = std.mem.splitScalar(u8, headers, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;

        const colon_pos = std.mem.indexOf(u8, line, ":") orelse continue;
        const name = std.mem.trim(u8, line[0..colon_pos], " \t");
        const value = std.mem.trim(u8, line[colon_pos + 1 ..], " \t");

        if (std.ascii.eqlIgnoreCase(name, CF_MITIGATED_HEADER)) {
            result.signals.cf_mitigated_header = true;
            result.signals.cf_mitigated_value = parseMitigatedValue(value);

            // Map to challenge type
            if (result.signals.cf_mitigated_value) |v| {
                result.challenge_type = switch (v) {
                    .challenge => .managed_challenge,
                    .block => .block,
                    .managed => .managed_challenge,
                    .js_challenge => .js_challenge,
                    .unknown => null,
                };
            }
        } else if (std.ascii.eqlIgnoreCase(name, SET_COOKIE_HEADER)) {
            // Check for challenge bypass cookie
            if (std.mem.indexOf(u8, value, CF_CHL_BYPASS) != null) {
                result.signals.cf_chl_bypass_cookie = true;
            }
        }
    }
}

/// Analyze body for WAF indicators
fn analyzeBody(body: []const u8, result: *WafResult) void {
    // Check for challenge page indicators
    if (std.mem.indexOf(u8, body, "cf-browser-verification") != null or
        std.mem.indexOf(u8, body, "cf_chl_opt") != null or
        std.mem.indexOf(u8, body, "jschl_vc") != null)
    {
        result.signals.challenge_page = true;
    }

    // Check for block page indicators
    if (std.mem.indexOf(u8, body, "cf-error-details") != null or
        std.mem.indexOf(u8, body, "Access denied") != null)
    {
        result.signals.block_page = true;
        result.challenge_type = .block;
    }

    // Check for Ray ID in error pages
    if (std.mem.indexOf(u8, body, "Ray ID") != null or
        std.mem.indexOf(u8, body, "cf-ray") != null)
    {
        result.signals.ray_id_in_error = true;
    }
}

// ============================================================================
// Tests
// ============================================================================

test "parseMitigatedValue parses known values" {
    try std.testing.expectEqual(WafSignals.MitigatedValue.challenge, parseMitigatedValue("challenge"));
    try std.testing.expectEqual(WafSignals.MitigatedValue.block, parseMitigatedValue("block"));
    try std.testing.expectEqual(WafSignals.MitigatedValue.managed, parseMitigatedValue("managed"));
    try std.testing.expectEqual(WafSignals.MitigatedValue.unknown, parseMitigatedValue("something_else"));
}

test "parseMitigatedValue handles whitespace" {
    try std.testing.expectEqual(WafSignals.MitigatedValue.challenge, parseMitigatedValue("  challenge  "));
    try std.testing.expectEqual(WafSignals.MitigatedValue.block, parseMitigatedValue("\tblock\t"));
}

test "WafSignals confidence calculation" {
    var signals = WafSignals{};
    try std.testing.expectEqual(@as(f32, 0.0), signals.confidence());

    signals.cf_mitigated_header = true;
    try std.testing.expect(signals.confidence() >= 0.85);

    signals = .{ .challenge_page = true };
    try std.testing.expect(signals.confidence() >= 0.80);

    signals = .{ .block_page = true };
    try std.testing.expect(signals.confidence() >= 0.80);
}

test "analyzeHeaders detects cf-mitigated" {
    var result = WafResult{
        .waf_active = false,
        .confidence = 0.0,
        .security_level = .unknown,
        .bot_management = false,
        .rate_limiting = false,
        .challenge_type = null,
        .signals = .{},
    };

    const headers = "cf-mitigated:challenge\ncf-ray:abc123\n";
    analyzeHeaders(headers, &result);

    try std.testing.expect(result.signals.cf_mitigated_header);
    try std.testing.expectEqual(WafSignals.MitigatedValue.challenge, result.signals.cf_mitigated_value.?);
}

test "analyzeBody detects challenge page" {
    var result = WafResult{
        .waf_active = false,
        .confidence = 0.0,
        .security_level = .unknown,
        .bot_management = false,
        .rate_limiting = false,
        .challenge_type = null,
        .signals = .{},
    };

    const body = "<html><script>cf_chl_opt = {};</script></html>";
    analyzeBody(body, &result);

    try std.testing.expect(result.signals.challenge_page);
}

test "getSecurityLevelDescription returns descriptions" {
    try std.testing.expectEqualStrings("Off - No active protection", getSecurityLevelDescription(.off));
    try std.testing.expectEqualStrings("Unknown", getSecurityLevelDescription(.unknown));
}
