//! Cloudflare Workers Detection
//!
//! Detects Cloudflare Workers deployments on targets.
//! Supports both *.workers.dev and custom domain Workers.

const std = @import("std");
const http = @import("../transport/http.zig");

const Allocator = std.mem.Allocator;

// ============================================================================
// Types
// ============================================================================

/// Workers detection result
pub const WorkersResult = struct {
    is_worker: bool,
    confidence: f32,
    platform: Platform,
    account_hint: ?[64]u8,
    account_hint_len: u8,
    signals: WorkerSignals,

    pub const Platform = enum {
        workers_dev,
        custom_domain,
        unknown,
    };

    /// Get account hint as slice
    pub fn getAccountHint(self: *const WorkersResult) ?[]const u8 {
        if (self.account_hint_len == 0) return null;
        return self.account_hint.?[0..self.account_hint_len];
    }
};

/// Detection signals for Workers
pub const WorkerSignals = struct {
    workers_dev_domain: bool = false,
    cf_placement_header: bool = false,
    cf_worker_header: bool = false,
    nel_report_header: bool = false,
    no_cache_status: bool = false,

    /// Calculate confidence from signals
    pub fn confidence(self: WorkerSignals) f32 {
        var score: f32 = 0.0;

        // Primary signals
        if (self.workers_dev_domain) score += 0.95;
        if (self.cf_placement_header) score += 0.40;
        if (self.cf_worker_header) score += 0.35;

        // Secondary signals
        if (self.nel_report_header) score += 0.10;
        if (self.no_cache_status) score += 0.05;

        return @min(score, 1.0);
    }
};

/// Errors for Workers detection
pub const WorkersError = error{
    InvalidTarget,
    ConnectionFailed,
    Timeout,
    TlsError,
};

// ============================================================================
// Constants
// ============================================================================

const WORKERS_DEV_SUFFIX = ".workers.dev";
const CF_PLACEMENT_HEADER = "cf-placement";
const CF_WORKER_HEADER = "cf-worker";
const NEL_HEADER = "nel";
const CF_CACHE_STATUS = "cf-cache-status";

// ============================================================================
// Public API
// ============================================================================

/// Detect if target is a Cloudflare Worker
pub fn detectWorker(allocator: Allocator, target: []const u8) WorkersError!WorkersResult {
    std.debug.assert(target.len > 0);
    std.debug.assert(target.len <= 253); // Max DNS name length

    var result = WorkersResult{
        .is_worker = false,
        .confidence = 0.0,
        .platform = .unknown,
        .account_hint = null,
        .account_hint_len = 0,
        .signals = .{},
    };

    // Check domain pattern first (no network needed)
    if (isWorkersDev(target)) {
        result.signals.workers_dev_domain = true;
        result.platform = .workers_dev;

        // Extract account hint from subdomain
        if (extractAccountHint(target)) |hint| {
            result.account_hint = [_]u8{0} ** 64;
            const len: u8 = @intCast(@min(hint.len, 64));
            @memcpy(result.account_hint.?[0..len], hint[0..len]);
            result.account_hint_len = len;
        }
    }

    // Fetch headers to detect custom domain Workers
    const headers = fetchHeaders(allocator, target) catch |err| {
        // If we already know it's workers.dev, return what we have
        if (result.signals.workers_dev_domain) {
            result.confidence = result.signals.confidence();
            result.is_worker = result.confidence >= 0.30;
            return result;
        }
        return switch (err) {
            error.ConnectionFailed, error.RequestFailed, error.TlsError => WorkersError.ConnectionFailed,
            error.Timeout => WorkersError.Timeout,
            error.InvalidUrl, error.InvalidTarget => WorkersError.InvalidTarget,
            error.OutOfMemory => WorkersError.ConnectionFailed,
        };
    };
    defer allocator.free(headers);

    // Analyze headers for Worker signals
    analyzeHeaders(headers, &result.signals);

    // Determine platform if not already set
    if (result.platform == .unknown and result.signals.cf_placement_header) {
        result.platform = .custom_domain;
    }

    // Calculate final confidence
    result.confidence = result.signals.confidence();
    result.is_worker = result.confidence >= 0.30;

    std.debug.assert(result.confidence >= 0.0 and result.confidence <= 1.0);
    return result;
}

/// Check if domain is a workers.dev subdomain
pub fn isWorkersDev(domain: []const u8) bool {
    std.debug.assert(domain.len > 0);

    if (domain.len <= WORKERS_DEV_SUFFIX.len) return false;

    const suffix_start = domain.len - WORKERS_DEV_SUFFIX.len;
    return std.ascii.eqlIgnoreCase(domain[suffix_start..], WORKERS_DEV_SUFFIX);
}

/// Extract account hint from workers.dev domain
/// Pattern: <name>.<account>.workers.dev
pub fn extractAccountHint(domain: []const u8) ?[]const u8 {
    std.debug.assert(domain.len > 0);

    if (!isWorkersDev(domain)) return null;

    // Remove .workers.dev suffix
    const without_suffix = domain[0 .. domain.len - WORKERS_DEV_SUFFIX.len];

    // Find the last dot to get account subdomain
    var last_dot: ?usize = null;
    for (without_suffix, 0..) |c, i| {
        if (c == '.') last_dot = i;
    }

    if (last_dot) |pos| {
        // Return the account part (after the last dot)
        return without_suffix[pos + 1 ..];
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

    // Build URL
    var url_buf: [512]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "https://{s}/", .{target}) catch {
        return error.InvalidTarget;
    };

    var response = try client.head(url);
    defer response.deinit();

    // Return raw headers as string
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

/// Analyze headers for Worker signals
fn analyzeHeaders(headers: []const u8, signals: *WorkerSignals) void {
    std.debug.assert(headers.len <= 64 * 1024); // Max 64KB headers

    var has_cache_status = false;

    var lines = std.mem.splitScalar(u8, headers, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;

        // Split header name and value
        const colon_pos = std.mem.indexOf(u8, line, ":") orelse continue;
        const name = std.mem.trim(u8, line[0..colon_pos], " \t");
        const value = std.mem.trim(u8, line[colon_pos + 1 ..], " \t");

        // Check for Worker-specific headers
        if (std.ascii.eqlIgnoreCase(name, CF_PLACEMENT_HEADER)) {
            signals.cf_placement_header = true;
        } else if (std.ascii.eqlIgnoreCase(name, CF_WORKER_HEADER)) {
            signals.cf_worker_header = true;
        } else if (std.ascii.eqlIgnoreCase(name, NEL_HEADER)) {
            // NEL with cf-nel group indicates Cloudflare
            if (std.mem.indexOf(u8, value, "cf-nel") != null) {
                signals.nel_report_header = true;
            }
        } else if (std.ascii.eqlIgnoreCase(name, CF_CACHE_STATUS)) {
            has_cache_status = true;
        }
    }

    // Workers typically don't have cache status
    signals.no_cache_status = !has_cache_status;
}

// ============================================================================
// Tests
// ============================================================================

test "isWorkersDev detects workers.dev domains" {
    try std.testing.expect(isWorkersDev("myapp.workers.dev"));
    try std.testing.expect(isWorkersDev("test.account.workers.dev"));
    try std.testing.expect(isWorkersDev("UPPERCASE.WORKERS.DEV"));

    try std.testing.expect(!isWorkersDev("workers.dev")); // Just the suffix
    try std.testing.expect(!isWorkersDev("example.com"));
    try std.testing.expect(!isWorkersDev("fakeworkers.dev"));
    try std.testing.expect(!isWorkersDev("workers.dev.example.com"));
}

test "extractAccountHint extracts account from workers.dev" {
    const hint1 = extractAccountHint("myapp.account123.workers.dev");
    try std.testing.expect(hint1 != null);
    try std.testing.expectEqualStrings("account123", hint1.?);

    const hint2 = extractAccountHint("app.workers.dev");
    try std.testing.expect(hint2 == null); // No account subdomain

    const hint3 = extractAccountHint("example.com");
    try std.testing.expect(hint3 == null); // Not workers.dev
}

test "WorkerSignals confidence calculation" {
    var signals = WorkerSignals{};

    // Empty signals = 0 confidence
    try std.testing.expectEqual(@as(f32, 0.0), signals.confidence());

    // workers.dev domain = high confidence
    signals.workers_dev_domain = true;
    try std.testing.expect(signals.confidence() >= 0.90);

    // cf-placement header = moderate confidence
    signals = .{ .cf_placement_header = true };
    try std.testing.expect(signals.confidence() >= 0.30);

    // Multiple signals = capped at 1.0
    signals = .{
        .workers_dev_domain = true,
        .cf_placement_header = true,
        .cf_worker_header = true,
    };
    try std.testing.expectEqual(@as(f32, 1.0), signals.confidence());
}

test "analyzeHeaders detects cf-placement" {
    var signals = WorkerSignals{};
    const headers = "cf-placement:local-LAX\ncf-ray:abc123\n";

    analyzeHeaders(headers, &signals);

    try std.testing.expect(signals.cf_placement_header);
    try std.testing.expect(signals.no_cache_status); // No cf-cache-status
}

test "analyzeHeaders detects NEL with cf-nel" {
    var signals = WorkerSignals{};
    const headers = "nel:{\"report_to\":\"cf-nel\",\"max_age\":604800}\n";

    analyzeHeaders(headers, &signals);

    try std.testing.expect(signals.nel_report_header);
}
