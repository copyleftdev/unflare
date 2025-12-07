//! Cloudflare Pages Detection
//!
//! Detects Cloudflare Pages deployments on targets.
//! Supports *.pages.dev, preview deployments, and custom domains.

const std = @import("std");
const http = @import("../transport/http.zig");

const Allocator = std.mem.Allocator;

// ============================================================================
// Types
// ============================================================================

/// Pages detection result
pub const PagesResult = struct {
    is_pages: bool,
    confidence: f32,
    project_name: ?[64]u8,
    project_name_len: u8,
    is_preview: bool,
    has_functions: bool,
    signals: PagesSignals,

    /// Get project name as slice
    pub fn getProjectName(self: *const PagesResult) ?[]const u8 {
        if (self.project_name_len == 0) return null;
        return self.project_name.?[0..self.project_name_len];
    }
};

/// Detection signals for Pages
pub const PagesSignals = struct {
    pages_dev_domain: bool = false,
    pages_cname: bool = false,
    etag_header: bool = false,
    cache_control_public: bool = false,
    access_control_allow_origin: bool = false,
    x_content_type_options: bool = false,

    /// Calculate confidence from signals
    pub fn confidence(self: PagesSignals) f32 {
        var score: f32 = 0.0;

        // Primary signals
        if (self.pages_dev_domain) score += 0.95;
        if (self.pages_cname) score += 0.80;

        // Secondary signals (typical of Pages static hosting)
        if (self.etag_header) score += 0.15;
        if (self.cache_control_public) score += 0.10;
        if (self.access_control_allow_origin) score += 0.10;
        if (self.x_content_type_options) score += 0.05;

        return @min(score, 1.0);
    }
};

/// Errors for Pages detection
pub const PagesError = error{
    InvalidTarget,
    ConnectionFailed,
    Timeout,
    DnsResolutionFailed,
};

// ============================================================================
// Constants
// ============================================================================

const PAGES_DEV_SUFFIX = ".pages.dev";
const ETAG_HEADER = "etag";
const CACHE_CONTROL = "cache-control";
const ACCESS_CONTROL = "access-control-allow-origin";
const X_CONTENT_TYPE = "x-content-type-options";

// ============================================================================
// Public API
// ============================================================================

/// Detect if target is a Cloudflare Pages site
pub fn detectPages(allocator: Allocator, target: []const u8) PagesError!PagesResult {
    std.debug.assert(target.len > 0);
    std.debug.assert(target.len <= 253);

    var result = PagesResult{
        .is_pages = false,
        .confidence = 0.0,
        .project_name = null,
        .project_name_len = 0,
        .is_preview = false,
        .has_functions = false,
        .signals = .{},
    };

    // Check domain pattern first
    if (isPagesDev(target)) {
        result.signals.pages_dev_domain = true;

        // Extract project name and check for preview
        if (extractProjectInfo(target)) |info| {
            result.project_name = [_]u8{0} ** 64;
            const len: u8 = @intCast(@min(info.project.len, 64));
            @memcpy(result.project_name.?[0..len], info.project[0..len]);
            result.project_name_len = len;
            result.is_preview = info.is_preview;
        }
    }

    // Fetch headers
    const headers = fetchHeaders(allocator, target) catch |err| {
        if (result.signals.pages_dev_domain) {
            result.confidence = result.signals.confidence();
            result.is_pages = result.confidence >= 0.30;
            return result;
        }
        return switch (err) {
            error.ConnectionFailed, error.RequestFailed, error.TlsError => PagesError.ConnectionFailed,
            error.Timeout => PagesError.Timeout,
            error.InvalidUrl, error.InvalidTarget => PagesError.InvalidTarget,
            error.OutOfMemory => PagesError.ConnectionFailed,
        };
    };
    defer allocator.free(headers);

    // Analyze headers
    analyzeHeaders(headers, &result.signals);

    // Check for Pages Functions (/_worker.js endpoint would indicate this)
    // For now, we'll skip this as it requires an additional request

    // Calculate confidence
    result.confidence = result.signals.confidence();
    result.is_pages = result.confidence >= 0.30;

    std.debug.assert(result.confidence >= 0.0 and result.confidence <= 1.0);
    return result;
}

/// Check if domain is a pages.dev subdomain
pub fn isPagesDev(domain: []const u8) bool {
    std.debug.assert(domain.len > 0);

    if (domain.len <= PAGES_DEV_SUFFIX.len) return false;

    const suffix_start = domain.len - PAGES_DEV_SUFFIX.len;
    return std.ascii.eqlIgnoreCase(domain[suffix_start..], PAGES_DEV_SUFFIX);
}

/// Project info extracted from pages.dev domain
pub const ProjectInfo = struct {
    project: []const u8,
    is_preview: bool,
    preview_hash: ?[]const u8,
};

/// Extract project info from pages.dev domain
/// Pattern: <project>.pages.dev (production)
/// Pattern: <hash>.<project>.pages.dev (preview)
pub fn extractProjectInfo(domain: []const u8) ?ProjectInfo {
    std.debug.assert(domain.len > 0);

    if (!isPagesDev(domain)) return null;

    // Remove .pages.dev suffix
    const without_suffix = domain[0 .. domain.len - PAGES_DEV_SUFFIX.len];

    // Find dots to determine structure
    var dot_count: usize = 0;
    var last_dot: ?usize = null;
    for (without_suffix, 0..) |c, i| {
        if (c == '.') {
            dot_count += 1;
            last_dot = i;
        }
    }

    if (dot_count == 0) {
        // Simple: project.pages.dev
        return .{
            .project = without_suffix,
            .is_preview = false,
            .preview_hash = null,
        };
    } else if (dot_count == 1) {
        // Preview: hash.project.pages.dev
        const hash = without_suffix[0..last_dot.?];
        const project = without_suffix[last_dot.? + 1 ..];
        return .{
            .project = project,
            .is_preview = true,
            .preview_hash = hash,
        };
    }

    return null;
}

// ============================================================================
// Internal Functions
// ============================================================================

/// Fetch headers from target
fn fetchHeaders(allocator: Allocator, target: []const u8) ![]const u8 {
    var client = http.HttpClient.init(allocator);
    defer client.deinit();

    var url_buf: [512]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "https://{s}/", .{target}) catch {
        return error.InvalidTarget;
    };

    var response = try client.head(url);
    defer response.deinit();

    var header_buf = std.ArrayList(u8).init(allocator);
    errdefer header_buf.deinit();

    for (response.headers.items) |h| {
        try header_buf.appendSlice(h.name);
        try header_buf.append(':');
        try header_buf.appendSlice(h.value);
        try header_buf.append('\n');
    }

    return header_buf.toOwnedSlice();
}

/// Analyze headers for Pages signals
fn analyzeHeaders(headers: []const u8, signals: *PagesSignals) void {
    std.debug.assert(headers.len <= 64 * 1024); // Max 64KB headers

    var lines = std.mem.splitScalar(u8, headers, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;

        const colon_pos = std.mem.indexOf(u8, line, ":") orelse continue;
        const name = std.mem.trim(u8, line[0..colon_pos], " \t");
        const value = std.mem.trim(u8, line[colon_pos + 1 ..], " \t");

        if (std.ascii.eqlIgnoreCase(name, ETAG_HEADER)) {
            signals.etag_header = true;
        } else if (std.ascii.eqlIgnoreCase(name, CACHE_CONTROL)) {
            if (std.mem.indexOf(u8, value, "public") != null) {
                signals.cache_control_public = true;
            }
        } else if (std.ascii.eqlIgnoreCase(name, ACCESS_CONTROL)) {
            if (std.mem.eql(u8, value, "*")) {
                signals.access_control_allow_origin = true;
            }
        } else if (std.ascii.eqlIgnoreCase(name, X_CONTENT_TYPE)) {
            signals.x_content_type_options = true;
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

test "isPagesDev detects pages.dev domains" {
    try std.testing.expect(isPagesDev("mysite.pages.dev"));
    try std.testing.expect(isPagesDev("abc123.mysite.pages.dev"));
    try std.testing.expect(isPagesDev("UPPERCASE.PAGES.DEV"));

    try std.testing.expect(!isPagesDev("pages.dev"));
    try std.testing.expect(!isPagesDev("example.com"));
    try std.testing.expect(!isPagesDev("fakepages.dev"));
}

test "extractProjectInfo from production URL" {
    const info = extractProjectInfo("mysite.pages.dev");
    try std.testing.expect(info != null);
    try std.testing.expectEqualStrings("mysite", info.?.project);
    try std.testing.expect(!info.?.is_preview);
    try std.testing.expect(info.?.preview_hash == null);
}

test "extractProjectInfo from preview URL" {
    const info = extractProjectInfo("abc123.mysite.pages.dev");
    try std.testing.expect(info != null);
    try std.testing.expectEqualStrings("mysite", info.?.project);
    try std.testing.expect(info.?.is_preview);
    try std.testing.expectEqualStrings("abc123", info.?.preview_hash.?);
}

test "PagesSignals confidence calculation" {
    var signals = PagesSignals{};
    try std.testing.expectEqual(@as(f32, 0.0), signals.confidence());

    signals.pages_dev_domain = true;
    try std.testing.expect(signals.confidence() >= 0.90);

    signals = .{
        .etag_header = true,
        .cache_control_public = true,
        .access_control_allow_origin = true,
    };
    try std.testing.expect(signals.confidence() >= 0.30);
}

test "analyzeHeaders detects Pages patterns" {
    var signals = PagesSignals{};
    const headers = "etag:\"abc123\"\ncache-control:public, max-age=0\naccess-control-allow-origin:*\n";

    analyzeHeaders(headers, &signals);

    try std.testing.expect(signals.etag_header);
    try std.testing.expect(signals.cache_control_public);
    try std.testing.expect(signals.access_control_allow_origin);
}
