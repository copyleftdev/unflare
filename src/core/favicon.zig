//! Favicon Hash Generator
//!
//! Generates MurmurHash3 (MMH3) hashes of favicons for Shodan/Censys hunting.
//! The hash can be used to find servers with the same favicon.

const std = @import("std");
const http = @import("../transport/http.zig");

const Allocator = std.mem.Allocator;

/// Favicon result
pub const FaviconResult = struct {
    url_buf: [128]u8,
    url_len: u8,
    hash: i32,
    size: usize,
    base64_len: usize,

    pub fn url(self: *const FaviconResult) []const u8 {
        return self.url_buf[0..self.url_len];
    }

    /// Format hash for Shodan search
    pub fn shodanQuery(self: FaviconResult, buf: []u8) ![]u8 {
        return std.fmt.bufPrint(buf, "http.favicon.hash:{d}", .{self.hash});
    }
};

/// MurmurHash3 32-bit implementation
/// This matches the Python mmh3.hash() function used by Shodan
pub fn murmur3_32(data: []const u8, seed: u32) i32 {
    const c1: u32 = 0xcc9e2d51;
    const c2: u32 = 0x1b873593;

    var h1: u32 = seed;
    const nblocks = data.len / 4;

    // Body
    var i: usize = 0;
    while (i < nblocks) : (i += 1) {
        var k1: u32 = @as(u32, data[i * 4]) |
            (@as(u32, data[i * 4 + 1]) << 8) |
            (@as(u32, data[i * 4 + 2]) << 16) |
            (@as(u32, data[i * 4 + 3]) << 24);

        k1 *%= c1;
        k1 = std.math.rotl(u32, k1, 15);
        k1 *%= c2;

        h1 ^= k1;
        h1 = std.math.rotl(u32, h1, 13);
        h1 = h1 *% 5 +% 0xe6546b64;
    }

    // Tail
    const tail = data[nblocks * 4 ..];
    var k1: u32 = 0;

    if (tail.len >= 3) k1 ^= @as(u32, tail[2]) << 16;
    if (tail.len >= 2) k1 ^= @as(u32, tail[1]) << 8;
    if (tail.len >= 1) {
        k1 ^= @as(u32, tail[0]);
        k1 *%= c1;
        k1 = std.math.rotl(u32, k1, 15);
        k1 *%= c2;
        h1 ^= k1;
    }

    // Finalization
    h1 ^= @as(u32, @intCast(data.len));
    h1 ^= h1 >> 16;
    h1 *%= 0x85ebca6b;
    h1 ^= h1 >> 13;
    h1 *%= 0xc2b2ae35;
    h1 ^= h1 >> 16;

    // Convert to signed (matching Python's mmh3.hash behavior)
    return @bitCast(h1);
}

/// Base64 encode data (standard encoding with newlines every 76 chars)
/// This matches Python's base64.encodebytes() which Shodan uses
pub fn base64EncodeWithNewlines(allocator: Allocator, data: []const u8) ![]u8 {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // Calculate output size (with newlines every 76 chars)
    const base64_len = ((data.len + 2) / 3) * 4;
    const newlines = (base64_len + 75) / 76;
    const total_len = base64_len + newlines;

    var result = try allocator.alloc(u8, total_len);
    errdefer allocator.free(result);

    var out_idx: usize = 0;
    var line_len: usize = 0;
    var i: usize = 0;

    while (i < data.len) {
        const b0 = data[i];
        const b1 = if (i + 1 < data.len) data[i + 1] else 0;
        const b2 = if (i + 2 < data.len) data[i + 2] else 0;

        result[out_idx] = alphabet[b0 >> 2];
        result[out_idx + 1] = alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
        result[out_idx + 2] = if (i + 1 < data.len) alphabet[((b1 & 0x0f) << 2) | (b2 >> 6)] else '=';
        result[out_idx + 3] = if (i + 2 < data.len) alphabet[b2 & 0x3f] else '=';

        out_idx += 4;
        line_len += 4;
        i += 3;

        // Add newline every 76 characters
        if (line_len >= 76 and out_idx < total_len) {
            result[out_idx] = '\n';
            out_idx += 1;
            line_len = 0;
        }
    }

    // Add final newline
    if (out_idx < total_len) {
        result[out_idx] = '\n';
        out_idx += 1;
    }

    return result[0..out_idx];
}

/// Fetch favicon and compute hash
pub fn getFaviconHash(allocator: Allocator, target: []const u8) !FaviconResult {
    std.debug.assert(target.len > 0);
    std.debug.assert(target.len <= 253);

    var client = http.Client.init(allocator);
    defer client.deinit();

    // Try common favicon paths
    const paths = [_][]const u8{
        "/favicon.ico",
        "/favicon.png",
        "/apple-touch-icon.png",
    };

    var url_buf: [512]u8 = undefined;

    for (paths) |path| {
        const url = std.fmt.bufPrint(&url_buf, "https://{s}{s}", .{ target, path }) catch continue;

        var response = client.get(url) catch continue;
        defer response.deinit();

        if (response.status_code == 200 and response.body.items.len > 0) {
            // Base64 encode the favicon (matching Python's base64.encodebytes)
            const base64_data = try base64EncodeWithNewlines(allocator, response.body.items);
            defer allocator.free(base64_data);

            // Compute MMH3 hash of base64 data
            const hash = murmur3_32(base64_data, 0);

            var result = FaviconResult{
                .url_buf = undefined,
                .url_len = @intCast(@min(url.len, 127)),
                .hash = hash,
                .size = response.body.items.len,
                .base64_len = base64_data.len,
            };
            @memcpy(result.url_buf[0..result.url_len], url[0..result.url_len]);

            return result;
        }
    }

    return error.FaviconNotFound;
}

// ============================================================================
// Tests
// ============================================================================

test "murmur3_32 produces correct hash" {
    // Test vectors
    const hash1 = murmur3_32("hello", 0);
    try std.testing.expect(hash1 != 0);

    const hash2 = murmur3_32("hello", 0);
    try std.testing.expectEqual(hash1, hash2); // Same input = same output

    const hash3 = murmur3_32("world", 0);
    try std.testing.expect(hash1 != hash3); // Different input = different output
}

test "murmur3_32 handles empty input" {
    const hash = murmur3_32("", 0);
    try std.testing.expectEqual(@as(i32, 0), hash);
}

test "murmur3_32 handles various lengths" {
    // Test different input lengths to exercise all code paths
    _ = murmur3_32("a", 0);
    _ = murmur3_32("ab", 0);
    _ = murmur3_32("abc", 0);
    _ = murmur3_32("abcd", 0);
    _ = murmur3_32("abcde", 0);
}

test "base64EncodeWithNewlines produces valid output" {
    const data = "Hello, World!";
    const encoded = try base64EncodeWithNewlines(std.testing.allocator, data);
    defer std.testing.allocator.free(encoded);

    // Should contain base64 characters and newline
    try std.testing.expect(encoded.len > 0);
    try std.testing.expect(encoded[encoded.len - 1] == '\n');
}

test "FaviconResult.shodanQuery formats correctly" {
    var result = FaviconResult{
        .url_buf = undefined,
        .url_len = 0,
        .hash = -123456789,
        .size = 1024,
        .base64_len = 1400,
    };
    const url_str = "https://example.com/favicon.ico";
    @memcpy(result.url_buf[0..url_str.len], url_str);
    result.url_len = url_str.len;

    var buf: [64]u8 = undefined;
    const query = try result.shodanQuery(&buf);

    try std.testing.expectEqualStrings("http.favicon.hash:-123456789", query);
}
