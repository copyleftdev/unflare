//! HTTP Client
//!
//! HTTP client using Zig's std.http for Cloudflare detection.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// HTTP Header (stored)
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// HTTP Response with parsed headers and timing
pub const Response = struct {
    status_code: u16,
    headers: std.ArrayList(Header),
    body: std.ArrayList(u8),
    allocator: Allocator,

    // Timing info (nanoseconds)
    total_time_ns: i64 = 0,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .status_code = 0,
            .headers = std.ArrayList(Header).init(allocator),
            .body = std.ArrayList(u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        // Free duplicated header strings
        for (self.headers.items) |header| {
            self.allocator.free(header.name);
            self.allocator.free(header.value);
        }
        self.headers.deinit();
        self.body.deinit();
    }

    /// Get a header value by name (case-insensitive)
    pub fn getHeader(self: *const Self, name: []const u8) ?[]const u8 {
        for (self.headers.items) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) {
                return header.value;
            }
        }
        return null;
    }
};

/// HTTP Client configuration
pub const Config = struct {
    timeout_ns: u64 = 10 * std.time.ns_per_s,
    max_redirects: u8 = 10,
    user_agent: []const u8 = "unflare/0.2.0",
};

/// HTTP Client Error
pub const HttpError = error{
    ConnectionFailed,
    RequestFailed,
    InvalidUrl,
    Timeout,
    TlsError,
    OutOfMemory,
};

/// HTTP Client (aliased as HttpClient for compatibility)
pub const HttpClient = struct {
    allocator: Allocator,
    config: Config,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .config = .{},
        };
    }

    pub fn initWithConfig(allocator: Allocator, config: Config) Self {
        std.debug.assert(config.max_redirects <= 20);

        return Self{
            .allocator = allocator,
            .config = config,
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// Perform a GET request
    pub fn get(self: *Self, url_str: []const u8) HttpError!Response {
        const start_time = std.time.nanoTimestamp();

        var response = Response.init(self.allocator);
        errdefer response.deinit();

        // Parse URL
        const uri = std.Uri.parse(url_str) catch {
            return error.InvalidUrl;
        };

        // Create HTTP client
        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        // Build request
        var header_buf: [8192]u8 = undefined;
        var req = client.open(.GET, uri, .{
            .server_header_buffer = &header_buf,
            .redirect_behavior = .unhandled,
            .extra_headers = &.{
                .{ .name = "User-Agent", .value = self.config.user_agent },
                .{ .name = "Accept", .value = "*/*" },
            },
        }) catch {
            return error.ConnectionFailed;
        };
        defer req.deinit();

        // Send request
        req.send() catch {
            return error.RequestFailed;
        };

        // Wait for response
        req.wait() catch {
            return error.RequestFailed;
        };

        // Store status code
        response.status_code = @intFromEnum(req.response.status);

        // Parse and store response headers
        var it = req.response.iterateHeaders();
        while (it.next()) |header| {
            const name_copy = self.allocator.dupe(u8, header.name) catch {
                return error.OutOfMemory;
            };
            const value_copy = self.allocator.dupe(u8, header.value) catch {
                self.allocator.free(name_copy);
                return error.OutOfMemory;
            };

            response.headers.append(.{
                .name = name_copy,
                .value = value_copy,
            }) catch {
                self.allocator.free(name_copy);
                self.allocator.free(value_copy);
                return error.OutOfMemory;
            };
        }

        // Read body (limited to 64KB for safety)
        const max_body_size = 64 * 1024;
        var total_read: usize = 0;

        while (total_read < max_body_size) {
            var buf: [4096]u8 = undefined;
            const bytes_read = req.read(&buf) catch break;
            if (bytes_read == 0) break;

            response.body.appendSlice(buf[0..bytes_read]) catch {
                return error.OutOfMemory;
            };
            total_read += bytes_read;
        }

        response.total_time_ns = @intCast(std.time.nanoTimestamp() - start_time);

        return response;
    }

    /// Perform a HEAD request (headers only, no body)
    pub fn head(self: *Self, url_str: []const u8) HttpError!Response {
        const start_time = std.time.nanoTimestamp();

        var response = Response.init(self.allocator);
        errdefer response.deinit();

        // Parse URL
        const uri = std.Uri.parse(url_str) catch {
            return error.InvalidUrl;
        };

        // Create HTTP client
        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        // Build request
        var header_buf: [8192]u8 = undefined;
        var req = client.open(.HEAD, uri, .{
            .server_header_buffer = &header_buf,
            .redirect_behavior = .unhandled,
            .extra_headers = &.{
                .{ .name = "User-Agent", .value = self.config.user_agent },
                .{ .name = "Accept", .value = "*/*" },
            },
        }) catch {
            return error.ConnectionFailed;
        };
        defer req.deinit();

        // Send request
        req.send() catch {
            return error.RequestFailed;
        };

        // Wait for response
        req.wait() catch {
            return error.RequestFailed;
        };

        // Store status code
        response.status_code = @intFromEnum(req.response.status);

        // Parse and store response headers
        var it = req.response.iterateHeaders();
        while (it.next()) |header| {
            const name_copy = self.allocator.dupe(u8, header.name) catch {
                return error.OutOfMemory;
            };
            const value_copy = self.allocator.dupe(u8, header.value) catch {
                self.allocator.free(name_copy);
                return error.OutOfMemory;
            };

            response.headers.append(.{
                .name = name_copy,
                .value = value_copy,
            }) catch {
                self.allocator.free(name_copy);
                self.allocator.free(value_copy);
                return error.OutOfMemory;
            };
        }

        // No body for HEAD requests
        response.total_time_ns = @intCast(std.time.nanoTimestamp() - start_time);

        return response;
    }

    /// Fetch just the /cdn-cgi/trace endpoint
    pub fn fetchTrace(self: *Self, host: []const u8) HttpError!Response {
        var url_buf: [512]u8 = undefined;
        const url = std.fmt.bufPrint(&url_buf, "https://{s}/cdn-cgi/trace", .{host}) catch {
            return error.InvalidUrl;
        };
        return self.get(url);
    }
};

/// Backward compatibility alias
pub const Client = HttpClient;

/// Parse URL into components
pub const Url = struct {
    scheme: []const u8,
    host: []const u8,
    port: u16,
    path: []const u8,

    pub fn parse(url_str: []const u8) ?Url {
        // Find scheme
        const scheme_end = std.mem.indexOf(u8, url_str, "://") orelse return null;
        const scheme = url_str[0..scheme_end];

        const after_scheme = url_str[scheme_end + 3 ..];

        // Find path start
        const path_start = std.mem.indexOfScalar(u8, after_scheme, '/') orelse after_scheme.len;
        const host_port = after_scheme[0..path_start];
        const path = if (path_start < after_scheme.len) after_scheme[path_start..] else "/";

        // Parse port
        var host: []const u8 = undefined;
        var port: u16 = undefined;

        if (std.mem.indexOfScalar(u8, host_port, ':')) |colon| {
            host = host_port[0..colon];
            port = std.fmt.parseInt(u16, host_port[colon + 1 ..], 10) catch return null;
        } else {
            host = host_port;
            port = if (std.mem.eql(u8, scheme, "https")) 443 else 80;
        }

        return Url{
            .scheme = scheme,
            .host = host,
            .port = port,
            .path = path,
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Url.parse parses HTTPS URL" {
    const url = Url.parse("https://example.com/path").?;
    try std.testing.expectEqualStrings("https", url.scheme);
    try std.testing.expectEqualStrings("example.com", url.host);
    try std.testing.expectEqual(@as(u16, 443), url.port);
    try std.testing.expectEqualStrings("/path", url.path);
}

test "Url.parse parses URL with port" {
    const url = Url.parse("http://example.com:8080/api").?;
    try std.testing.expectEqualStrings("http", url.scheme);
    try std.testing.expectEqualStrings("example.com", url.host);
    try std.testing.expectEqual(@as(u16, 8080), url.port);
    try std.testing.expectEqualStrings("/api", url.path);
}

test "Url.parse handles root path" {
    const url = Url.parse("https://example.com").?;
    try std.testing.expectEqualStrings("/", url.path);
}

test "Url.parse returns null for invalid URLs" {
    try std.testing.expect(Url.parse("not-a-url") == null);
    try std.testing.expect(Url.parse("") == null);
}
