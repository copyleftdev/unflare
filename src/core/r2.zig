//! Cloudflare R2 Detection
//!
//! Detects Cloudflare R2 object storage buckets.
//! Supports S3 API endpoints and public bucket access.

const std = @import("std");
const http = @import("../transport/http.zig");

const Allocator = std.mem.Allocator;

// ============================================================================
// Types
// ============================================================================

/// R2 detection result
pub const R2Result = struct {
    is_r2: bool,
    confidence: f32,
    bucket_name: ?[64]u8,
    bucket_name_len: u8,
    account_id: ?[32]u8,
    account_id_len: u8,
    public_access: bool,
    signals: R2Signals,

    /// Get bucket name as slice
    pub fn getBucketName(self: *const R2Result) ?[]const u8 {
        if (self.bucket_name_len == 0) return null;
        return self.bucket_name.?[0..self.bucket_name_len];
    }

    /// Get account ID as slice
    pub fn getAccountId(self: *const R2Result) ?[]const u8 {
        if (self.account_id_len == 0) return null;
        return self.account_id.?[0..self.account_id_len];
    }
};

/// Detection signals for R2
pub const R2Signals = struct {
    r2_storage_domain: bool = false,
    r2_dev_domain: bool = false,
    s3_compatible_headers: bool = false,
    r2_error_response: bool = false,
    valid_account_id: bool = false,

    /// Calculate confidence from signals
    pub fn confidence(self: R2Signals) f32 {
        var score: f32 = 0.0;

        // Primary signals
        if (self.r2_storage_domain) score += 0.95;
        if (self.r2_dev_domain) score += 0.90;

        // Secondary signals
        if (self.s3_compatible_headers) score += 0.30;
        if (self.r2_error_response) score += 0.40;
        if (self.valid_account_id) score += 0.20;

        return @min(score, 1.0);
    }
};

/// Errors for R2 detection
pub const R2Error = error{
    InvalidTarget,
    ConnectionFailed,
    Timeout,
};

// ============================================================================
// Constants
// ============================================================================

const R2_STORAGE_SUFFIX = ".r2.cloudflarestorage.com";
const R2_DEV_SUFFIX = ".r2.dev";
const ACCOUNT_ID_LENGTH = 32;

// ============================================================================
// Public API
// ============================================================================

/// Detect if target is a Cloudflare R2 bucket
pub fn detectR2(_: Allocator, target: []const u8) R2Error!R2Result {
    std.debug.assert(target.len > 0);
    std.debug.assert(target.len <= 253);

    var result = R2Result{
        .is_r2 = false,
        .confidence = 0.0,
        .bucket_name = null,
        .bucket_name_len = 0,
        .account_id = null,
        .account_id_len = 0,
        .public_access = false,
        .signals = .{},
    };

    // Check domain patterns
    if (isR2StorageDomain(target)) {
        result.signals.r2_storage_domain = true;

        if (extractR2Info(target)) |info| {
            // Copy bucket name
            if (info.bucket) |bucket| {
                result.bucket_name = [_]u8{0} ** 64;
                const len: u8 = @intCast(@min(bucket.len, 64));
                @memcpy(result.bucket_name.?[0..len], bucket[0..len]);
                result.bucket_name_len = len;
            }

            // Copy account ID
            result.account_id = [_]u8{0} ** 32;
            @memcpy(result.account_id.?[0..32], info.account_id[0..32]);
            result.account_id_len = 32;

            if (isValidAccountId(info.account_id)) {
                result.signals.valid_account_id = true;
            }
        }
    } else if (isR2DevDomain(target)) {
        result.signals.r2_dev_domain = true;
        result.public_access = true;

        if (extractR2DevInfo(target)) |info| {
            result.bucket_name = [_]u8{0} ** 64;
            const len: u8 = @intCast(@min(info.bucket.len, 64));
            @memcpy(result.bucket_name.?[0..len], info.bucket[0..len]);
            result.bucket_name_len = len;

            result.account_id = [_]u8{0} ** 32;
            @memcpy(result.account_id.?[0..32], info.account_id[0..32]);
            result.account_id_len = 32;
        }
    }

    // Calculate confidence (domain pattern is sufficient for R2)
    result.confidence = result.signals.confidence();
    result.is_r2 = result.confidence >= 0.30;

    std.debug.assert(result.confidence >= 0.0 and result.confidence <= 1.0);
    return result;
}

/// Check if domain is R2 S3 API endpoint
pub fn isR2StorageDomain(domain: []const u8) bool {
    std.debug.assert(domain.len > 0);

    if (domain.len <= R2_STORAGE_SUFFIX.len) return false;

    const suffix_start = domain.len - R2_STORAGE_SUFFIX.len;
    return std.ascii.eqlIgnoreCase(domain[suffix_start..], R2_STORAGE_SUFFIX);
}

/// Check if domain is R2 public bucket (*.r2.dev)
pub fn isR2DevDomain(domain: []const u8) bool {
    std.debug.assert(domain.len > 0);

    if (domain.len <= R2_DEV_SUFFIX.len) return false;

    const suffix_start = domain.len - R2_DEV_SUFFIX.len;
    return std.ascii.eqlIgnoreCase(domain[suffix_start..], R2_DEV_SUFFIX);
}

/// R2 storage domain info
pub const R2Info = struct {
    account_id: []const u8,
    bucket: ?[]const u8,
};

/// Extract info from R2 storage domain
/// Pattern: [bucket.]<account_id>.r2.cloudflarestorage.com
pub fn extractR2Info(domain: []const u8) ?R2Info {
    std.debug.assert(domain.len > 0);

    if (!isR2StorageDomain(domain)) return null;

    const without_suffix = domain[0 .. domain.len - R2_STORAGE_SUFFIX.len];

    // Find dot separator
    const dot_pos = std.mem.indexOf(u8, without_suffix, ".");

    if (dot_pos) |pos| {
        // Has bucket: bucket.account_id
        const bucket = without_suffix[0..pos];
        const account_id = without_suffix[pos + 1 ..];

        if (account_id.len == ACCOUNT_ID_LENGTH) {
            return .{
                .account_id = account_id,
                .bucket = bucket,
            };
        }
    } else {
        // No bucket, just account_id
        if (without_suffix.len == ACCOUNT_ID_LENGTH) {
            return .{
                .account_id = without_suffix,
                .bucket = null,
            };
        }
    }

    return null;
}

/// R2 dev domain info
pub const R2DevInfo = struct {
    bucket: []const u8,
    account_id: []const u8,
};

/// Extract info from R2 dev domain
/// Pattern: <bucket>.<account_id>.r2.dev
pub fn extractR2DevInfo(domain: []const u8) ?R2DevInfo {
    std.debug.assert(domain.len > 0);

    if (!isR2DevDomain(domain)) return null;

    const without_suffix = domain[0 .. domain.len - R2_DEV_SUFFIX.len];

    // Find dot separator
    const dot_pos = std.mem.indexOf(u8, without_suffix, ".") orelse return null;

    const bucket = without_suffix[0..dot_pos];
    const account_id = without_suffix[dot_pos + 1 ..];

    if (account_id.len == ACCOUNT_ID_LENGTH) {
        return .{
            .bucket = bucket,
            .account_id = account_id,
        };
    }

    return null;
}

/// Validate account ID format (32 hex characters)
pub fn isValidAccountId(id: []const u8) bool {
    if (id.len != ACCOUNT_ID_LENGTH) return false;

    for (id) |c| {
        if (!std.ascii.isHex(c)) return false;
    }

    return true;
}

// ============================================================================
// Tests
// ============================================================================

test "isR2StorageDomain detects R2 domains" {
    try std.testing.expect(isR2StorageDomain("944de778fcfb8b1958943b24fcfd8349.r2.cloudflarestorage.com"));
    try std.testing.expect(isR2StorageDomain("bucket.944de778fcfb8b1958943b24fcfd8349.r2.cloudflarestorage.com"));

    try std.testing.expect(!isR2StorageDomain("r2.cloudflarestorage.com"));
    try std.testing.expect(!isR2StorageDomain("example.com"));
}

test "isR2DevDomain detects public R2 domains" {
    try std.testing.expect(isR2DevDomain("bucket.944de778fcfb8b1958943b24fcfd8349.r2.dev"));

    try std.testing.expect(!isR2DevDomain("r2.dev"));
    try std.testing.expect(!isR2DevDomain("example.com"));
}

test "extractR2Info extracts account and bucket" {
    const info = extractR2Info("mybucket.944de778fcfb8b1958943b24fcfd8349.r2.cloudflarestorage.com");
    try std.testing.expect(info != null);
    try std.testing.expectEqualStrings("mybucket", info.?.bucket.?);
    try std.testing.expectEqualStrings("944de778fcfb8b1958943b24fcfd8349", info.?.account_id);
}

test "extractR2Info handles account-only domain" {
    const info = extractR2Info("944de778fcfb8b1958943b24fcfd8349.r2.cloudflarestorage.com");
    try std.testing.expect(info != null);
    try std.testing.expect(info.?.bucket == null);
    try std.testing.expectEqualStrings("944de778fcfb8b1958943b24fcfd8349", info.?.account_id);
}

test "isValidAccountId validates hex format" {
    try std.testing.expect(isValidAccountId("944de778fcfb8b1958943b24fcfd8349"));
    try std.testing.expect(isValidAccountId("abcdef0123456789abcdef0123456789"));

    try std.testing.expect(!isValidAccountId("short"));
    try std.testing.expect(!isValidAccountId("944de778fcfb8b1958943b24fcfd834z")); // Invalid char
}

test "R2Signals confidence calculation" {
    var signals = R2Signals{};
    try std.testing.expectEqual(@as(f32, 0.0), signals.confidence());

    signals.r2_storage_domain = true;
    try std.testing.expect(signals.confidence() >= 0.90);

    signals = .{ .r2_dev_domain = true };
    try std.testing.expect(signals.confidence() >= 0.90);
}
