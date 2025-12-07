//! Cloudflare Tunnel Detection
//!
//! Detects services exposed via Cloudflare Tunnel (Argo Tunnel).
//! Identifies quick tunnels (*.trycloudflare.com) and named tunnels.

const std = @import("std");
const http = @import("../transport/http.zig");

const Allocator = std.mem.Allocator;

// ============================================================================
// Types
// ============================================================================

/// Tunnel detection result
pub const TunnelResult = struct {
    is_tunnel: bool,
    confidence: f32,
    tunnel_type: TunnelType,
    access_protected: bool,
    error_code: ?u16,
    signals: TunnelSignals,

    pub const TunnelType = enum {
        quick,
        named,
        unknown,
    };
};

/// Detection signals for Tunnel
pub const TunnelSignals = struct {
    trycloudflare_domain: bool = false,
    tunnel_error_page: bool = false,
    tunnel_error_code: ?u16 = null,
    http_530_status: bool = false,
    access_redirect: bool = false,
    no_origin_discoverable: bool = false,

    /// Calculate confidence from signals
    pub fn confidence(self: TunnelSignals) f32 {
        var score: f32 = 0.0;

        // Primary signals
        if (self.trycloudflare_domain) score += 0.95;
        if (self.tunnel_error_page) score += 0.50;
        if (self.http_530_status) score += 0.40;

        // Secondary signals
        if (self.access_redirect) score += 0.35;
        if (self.no_origin_discoverable) score += 0.20;

        return @min(score, 1.0);
    }
};

/// Errors for Tunnel detection
pub const TunnelError = error{
    InvalidTarget,
    ConnectionFailed,
    Timeout,
};

// ============================================================================
// Constants
// ============================================================================

const TRYCLOUDFLARE_SUFFIX = ".trycloudflare.com";

/// Known Cloudflare Tunnel error codes
pub const TunnelErrorCodes = struct {
    pub const CONNECTION_FAILED: u16 = 1033;
    pub const EDGE_IP_RESTRICTED: u16 = 1034;
    pub const INVALID_REQUEST: u16 = 1035;
};

// ============================================================================
// Public API
// ============================================================================

/// Detect if target is served via Cloudflare Tunnel
pub fn detectTunnel(allocator: Allocator, target: []const u8) TunnelError!TunnelResult {
    std.debug.assert(target.len > 0);
    std.debug.assert(target.len <= 253);

    var result = TunnelResult{
        .is_tunnel = false,
        .confidence = 0.0,
        .tunnel_type = .unknown,
        .access_protected = false,
        .error_code = null,
        .signals = .{},
    };

    // Check for quick tunnel domain
    if (isTryCloudflare(target)) {
        result.signals.trycloudflare_domain = true;
        result.tunnel_type = .quick;

        // Validate quick tunnel naming pattern
        if (!isValidQuickTunnelName(target)) {
            // Still a trycloudflare domain but unusual pattern
            result.tunnel_type = .unknown;
        }
    }

    // Fetch response to check for tunnel indicators
    const response = fetchResponse(allocator, target) catch |err| {
        if (result.signals.trycloudflare_domain) {
            result.confidence = result.signals.confidence();
            result.is_tunnel = result.confidence >= 0.30;
            return result;
        }
        return switch (err) {
            error.ConnectionFailed, error.RequestFailed, error.TlsError => TunnelError.ConnectionFailed,
            error.Timeout => TunnelError.Timeout,
            error.InvalidUrl, error.InvalidTarget => TunnelError.InvalidTarget,
            error.OutOfMemory => TunnelError.ConnectionFailed,
        };
    };
    defer allocator.free(response.body);
    defer allocator.free(response.headers);

    // Check HTTP status
    if (response.status == 530) {
        result.signals.http_530_status = true;
    }

    // Check for tunnel error page
    if (isTunnelErrorPage(response.body)) |error_code| {
        result.signals.tunnel_error_page = true;
        result.signals.tunnel_error_code = error_code;
        result.error_code = error_code;
    }

    // Check for Access redirect
    if (isAccessRedirect(response.headers, response.status)) {
        result.signals.access_redirect = true;
        result.access_protected = true;
    }

    // Calculate confidence
    result.confidence = result.signals.confidence();
    result.is_tunnel = result.confidence >= 0.30;

    std.debug.assert(result.confidence >= 0.0 and result.confidence <= 1.0);
    return result;
}

/// Check if domain is a trycloudflare.com quick tunnel
pub fn isTryCloudflare(domain: []const u8) bool {
    std.debug.assert(domain.len > 0);

    if (domain.len <= TRYCLOUDFLARE_SUFFIX.len) return false;

    const suffix_start = domain.len - TRYCLOUDFLARE_SUFFIX.len;
    return std.ascii.eqlIgnoreCase(domain[suffix_start..], TRYCLOUDFLARE_SUFFIX);
}

/// Validate quick tunnel naming pattern: word-word-word-word.trycloudflare.com
pub fn isValidQuickTunnelName(domain: []const u8) bool {
    std.debug.assert(domain.len > 0);

    if (!isTryCloudflare(domain)) return false;

    const subdomain = domain[0 .. domain.len - TRYCLOUDFLARE_SUFFIX.len];

    // Count dashes - should have exactly 3 for 4 words
    var dash_count: usize = 0;
    for (subdomain) |c| {
        if (c == '-') dash_count += 1;
    }

    return dash_count == 3;
}

/// Get error code description
pub fn getErrorDescription(code: u16) []const u8 {
    return switch (code) {
        TunnelErrorCodes.CONNECTION_FAILED => "Tunnel connection failed",
        TunnelErrorCodes.EDGE_IP_RESTRICTED => "Edge IP restricted",
        TunnelErrorCodes.INVALID_REQUEST => "Invalid request",
        else => "Unknown tunnel error",
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

/// Fetch full response from target
fn fetchResponse(allocator: Allocator, target: []const u8) !Response {
    var client = http.HttpClient.init(allocator);
    defer client.deinit();

    var url_buf: [512]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "https://{s}/", .{target}) catch {
        return error.InvalidTarget;
    };

    var http_response = try client.get(url);
    defer http_response.deinit();

    // Build headers string
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

/// Check if response body is a tunnel error page
fn isTunnelErrorPage(body: []const u8) ?u16 {
    // Look for "Cloudflare Tunnel error" in title
    if (std.mem.indexOf(u8, body, "Cloudflare Tunnel error") == null) {
        return null;
    }

    // Extract error code from <span>XXXX</span> pattern
    const error_codes = [_]u16{
        TunnelErrorCodes.CONNECTION_FAILED,
        TunnelErrorCodes.EDGE_IP_RESTRICTED,
        TunnelErrorCodes.INVALID_REQUEST,
    };

    for (error_codes) |code| {
        var code_buf: [32]u8 = undefined;
        const code_str = std.fmt.bufPrint(&code_buf, "<span>{d}</span>", .{code}) catch continue;

        if (std.mem.indexOf(u8, body, code_str) != null) {
            return code;
        }
    }

    // Found tunnel error page but unknown code
    return 0;
}

/// Check if response indicates Access redirect
fn isAccessRedirect(headers: []const u8, status: u16) bool {
    // Access typically redirects with 302/303
    if (status != 302 and status != 303) return false;

    // Check for cloudflareaccess.com in location header
    var lines = std.mem.splitScalar(u8, headers, '\n');
    while (lines.next()) |line| {
        const colon_pos = std.mem.indexOf(u8, line, ":") orelse continue;
        const name = std.mem.trim(u8, line[0..colon_pos], " \t");

        if (std.ascii.eqlIgnoreCase(name, "location")) {
            const value = line[colon_pos + 1 ..];
            if (std.mem.indexOf(u8, value, "cloudflareaccess.com") != null) {
                return true;
            }
        }
    }

    return false;
}

// ============================================================================
// Tests
// ============================================================================

test "isTryCloudflare detects quick tunnel domains" {
    try std.testing.expect(isTryCloudflare("word-word-word-word.trycloudflare.com"));
    try std.testing.expect(isTryCloudflare("test.trycloudflare.com"));
    try std.testing.expect(isTryCloudflare("UPPERCASE.TRYCLOUDFLARE.COM"));

    try std.testing.expect(!isTryCloudflare("trycloudflare.com"));
    try std.testing.expect(!isTryCloudflare("example.com"));
    try std.testing.expect(!isTryCloudflare("faketrycloudflare.com"));
}

test "isValidQuickTunnelName validates pattern" {
    try std.testing.expect(isValidQuickTunnelName("autumn-bird-abc1-def2.trycloudflare.com"));
    try std.testing.expect(isValidQuickTunnelName("word-word-word-word.trycloudflare.com"));

    try std.testing.expect(!isValidQuickTunnelName("single.trycloudflare.com"));
    try std.testing.expect(!isValidQuickTunnelName("two-parts.trycloudflare.com"));
    try std.testing.expect(!isValidQuickTunnelName("example.com"));
}

test "TunnelSignals confidence calculation" {
    var signals = TunnelSignals{};
    try std.testing.expectEqual(@as(f32, 0.0), signals.confidence());

    signals.trycloudflare_domain = true;
    try std.testing.expect(signals.confidence() >= 0.90);

    signals = .{ .http_530_status = true, .tunnel_error_page = true };
    try std.testing.expect(signals.confidence() >= 0.80);
}

test "isTunnelErrorPage detects error codes" {
    const body_1033 = "<html><title>Cloudflare Tunnel error</title><span>1033</span></html>";
    try std.testing.expectEqual(@as(?u16, 1033), isTunnelErrorPage(body_1033));

    const body_normal = "<html><body>Hello World</body></html>";
    try std.testing.expect(isTunnelErrorPage(body_normal) == null);
}

test "getErrorDescription returns descriptions" {
    try std.testing.expectEqualStrings("Tunnel connection failed", getErrorDescription(1033));
    try std.testing.expectEqualStrings("Unknown tunnel error", getErrorDescription(9999));
}
