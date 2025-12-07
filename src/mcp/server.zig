//! MCP Server Implementation
//!
//! Implements a Model Context Protocol server for unflare.
//! Communicates via JSON-RPC 2.0 over stdio.

const std = @import("std");
const Allocator = std.mem.Allocator;
const protocol = @import("protocol.zig");
const tools = @import("tools.zig");

// Core modules
const detection = @import("../core/detection.zig");
const origin = @import("../core/origin.zig");
const favicon = @import("../core/favicon.zig");
const ip_ranges = @import("../data/ip_ranges.zig");
const workers = @import("../core/workers.zig");
const pages = @import("../core/pages.zig");
const tunnel = @import("../core/tunnel.zig");
const r2 = @import("../core/r2.zig");
const waf = @import("../core/waf.zig");
const http = @import("../transport/http.zig");
const datacenters = @import("../data/datacenters.zig");

/// MCP Server
pub const Server = struct {
    allocator: Allocator,
    reader: std.fs.File.Reader,
    writer: std.fs.File.Writer,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .reader = std.io.getStdIn().reader(),
            .writer = std.io.getStdOut().writer(),
        };
    }

    /// Run the MCP server loop
    pub fn run(self: *Self) !void {
        // Log to stderr so it doesn't interfere with JSON-RPC
        const stderr = std.io.getStdErr().writer();
        try stderr.writeAll("unflare MCP server started\n");

        while (true) {
            const line = try protocol.readLine(self.allocator, self.reader);
            if (line == null) break; // EOF
            defer self.allocator.free(line.?);

            if (line.?.len == 0) continue;

            self.handleRequest(line.?) catch |err| {
                try stderr.print("Error handling request: {}\n", .{err});
                try protocol.writeErrorResponse(
                    self.writer,
                    null,
                    .internal_error,
                    "Internal server error",
                );
            };
        }
    }

    /// Handle a single JSON-RPC request
    fn handleRequest(self: *Self, json_str: []const u8) !void {
        const request = protocol.parseRequest(self.allocator, json_str) catch {
            try protocol.writeErrorResponse(self.writer, null, .parse_error, "Parse error");
            return;
        };

        // Route to handler
        if (std.mem.eql(u8, request.method, "initialize")) {
            try self.handleInitialize(request.id);
        } else if (std.mem.eql(u8, request.method, "initialized")) {
            // Notification, no response needed
        } else if (std.mem.eql(u8, request.method, "tools/list")) {
            try self.handleToolsList(request.id);
        } else if (std.mem.eql(u8, request.method, "tools/call")) {
            try self.handleToolsCall(request.id, request.params);
        } else if (std.mem.eql(u8, request.method, "ping")) {
            try protocol.writeRawSuccessResponse(self.writer, request.id, "{}");
        } else {
            try protocol.writeErrorResponse(
                self.writer,
                request.id,
                .method_not_found,
                "Method not found",
            );
        }
    }

    /// Handle initialize request
    fn handleInitialize(self: *Self, id: ?protocol.JsonId) !void {
        const response =
            \\{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"unflare","version":"0.3.0"}}
        ;
        try protocol.writeRawSuccessResponse(self.writer, id, response);
    }

    /// Handle tools/list request
    fn handleToolsList(self: *Self, id: ?protocol.JsonId) !void {
        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();

        try tools.writeToolsJson(buf.writer());
        try protocol.writeRawSuccessResponse(self.writer, id, buf.items);
    }

    /// Handle tools/call request
    fn handleToolsCall(self: *Self, id: ?protocol.JsonId, params: ?std.json.Value) !void {
        if (params == null) {
            try protocol.writeErrorResponse(self.writer, id, .invalid_params, "Missing params");
            return;
        }

        const obj = params.?.object;
        const tool_name = if (obj.get("name")) |v| v.string else {
            try protocol.writeErrorResponse(self.writer, id, .invalid_params, "Missing tool name");
            return;
        };

        const arguments = obj.get("arguments");

        // Execute the tool
        var result_buf = std.ArrayList(u8).init(self.allocator);
        defer result_buf.deinit();

        self.executeTool(tool_name, arguments, result_buf.writer()) catch |err| {
            var err_buf: [256]u8 = undefined;
            const err_msg = std.fmt.bufPrint(&err_buf, "Tool execution failed: {}", .{err}) catch "Tool execution failed";
            try protocol.writeErrorResponse(self.writer, id, .internal_error, err_msg);
            return;
        };

        // Wrap result in content array as per MCP spec
        var response_buf = std.ArrayList(u8).init(self.allocator);
        defer response_buf.deinit();

        try response_buf.writer().writeAll("{\"content\":[{\"type\":\"text\",\"text\":");
        try std.json.stringify(result_buf.items, .{}, response_buf.writer());
        try response_buf.writer().writeAll("}]}");

        try protocol.writeRawSuccessResponse(self.writer, id, response_buf.items);
    }

    /// Execute a tool and write result as JSON
    fn executeTool(self: *Self, name: []const u8, arguments: ?std.json.Value, writer: anytype) !void {
        if (std.mem.eql(u8, name, "unflare_detect")) {
            try self.executeDetect(arguments, writer);
        } else if (std.mem.eql(u8, name, "unflare_probe")) {
            try self.executeProbe(arguments, writer);
        } else if (std.mem.eql(u8, name, "unflare_trace")) {
            try self.executeTrace(arguments, writer);
        } else if (std.mem.eql(u8, name, "unflare_origin")) {
            try self.executeOrigin(arguments, writer);
        } else if (std.mem.eql(u8, name, "unflare_favicon")) {
            try self.executeFavicon(arguments, writer);
        } else if (std.mem.eql(u8, name, "unflare_ipcheck")) {
            try self.executeIpcheck(arguments, writer);
        } else if (std.mem.eql(u8, name, "unflare_workers")) {
            try self.executeWorkers(arguments, writer);
        } else if (std.mem.eql(u8, name, "unflare_pages")) {
            try self.executePages(arguments, writer);
        } else if (std.mem.eql(u8, name, "unflare_tunnel")) {
            try self.executeTunnel(arguments, writer);
        } else if (std.mem.eql(u8, name, "unflare_r2")) {
            try self.executeR2(arguments, writer);
        } else if (std.mem.eql(u8, name, "unflare_waf")) {
            try self.executeWaf(arguments, writer);
        } else {
            return error.UnknownTool;
        }
    }

    /// Execute detect tool
    fn executeDetect(self: *Self, arguments: ?std.json.Value, writer: anytype) !void {
        const target = try getStringArg(arguments, "target");

        var detector = detection.Detector.init(self.allocator);
        defer detector.deinit();

        const result = try detector.detect(target);

        try writer.writeAll("{");
        try writer.print("\"target\":\"{s}\",", .{target});
        try writer.print("\"is_cloudflare\":{},", .{result.is_cloudflare});
        try writer.print("\"confidence\":{d:.2},", .{result.confidence});
        try writer.print("\"signals_count\":{d},", .{result.signals.count()});
        if (result.cf_ray) |ray| {
            try writer.print("\"datacenter\":\"{s}\"", .{ray.datacenter});
        } else {
            try writer.writeAll("\"datacenter\":null");
        }
        try writer.writeAll("}");
    }

    /// Execute probe tool
    fn executeProbe(self: *Self, arguments: ?std.json.Value, writer: anytype) !void {
        const target = try getStringArg(arguments, "target");

        var client = http.HttpClient.init(self.allocator);
        defer client.deinit();

        var url_buf: [512]u8 = undefined;
        const url = std.fmt.bufPrint(&url_buf, "https://{s}/", .{target}) catch return error.InvalidTarget;

        var response = client.get(url) catch {
            try writer.writeAll("{\"error\":\"Connection failed\"}");
            return;
        };
        defer response.deinit();

        try writer.writeAll("{");
        try writer.print("\"status_code\":{d},", .{response.status_code});
        try writer.print("\"response_time_ms\":{d:.2},", .{@as(f64, @floatFromInt(response.total_time_ns)) / 1_000_000.0});
        try writer.writeAll("\"headers\":{");

        for (response.headers.items, 0..) |h, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.writeAll("\"");
            try writeJsonEscaped(writer, h.name);
            try writer.writeAll("\":\"");
            try writeJsonEscaped(writer, h.value);
            try writer.writeAll("\"");
        }
        try writer.writeAll("}}");
    }

    /// Execute trace tool
    fn executeTrace(self: *Self, arguments: ?std.json.Value, writer: anytype) !void {
        const target = try getStringArg(arguments, "target");

        var client = http.HttpClient.init(self.allocator);
        defer client.deinit();

        var response = client.fetchTrace(target) catch {
            try writer.writeAll("{\"error\":\"Failed to fetch trace\"}");
            return;
        };
        defer response.deinit();

        try writer.writeAll("{\"trace\":{");

        // Parse trace response
        var first = true;
        var lines = std.mem.splitScalar(u8, response.body.items, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            if (std.mem.indexOf(u8, line, "=")) |eq_pos| {
                if (!first) try writer.writeAll(",");
                first = false;
                try writer.writeAll("\"");
                try writeJsonEscaped(writer, line[0..eq_pos]);
                try writer.writeAll("\":\"");
                try writeJsonEscaped(writer, line[eq_pos + 1 ..]);
                try writer.writeAll("\"");
            }
        }
        try writer.writeAll("}}");
    }

    /// Execute origin tool
    fn executeOrigin(self: *Self, arguments: ?std.json.Value, writer: anytype) !void {
        const target = try getStringArg(arguments, "target");

        var discovery = origin.OriginDiscovery.init(self.allocator);
        defer discovery.deinit();

        var result = discovery.discover(target) catch {
            try writer.writeAll("{\"error\":\"Origin discovery failed\"}");
            return;
        };
        defer result.deinit();

        try writer.writeAll("{");
        try writer.print("\"target\":\"{s}\",", .{target});
        try writer.print("\"is_cloudflare\":{},", .{result.target_is_cloudflare});
        try writer.print("\"subdomains_checked\":{d},", .{result.subdomains_checked});
        try writer.writeAll("\"candidates\":[");

        for (result.candidates.items, 0..) |candidate, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.writeAll("{");
            try writer.print("\"ip\":\"{s}\",", .{candidate.ip[0..candidate.ip_len]});
            try writer.print("\"source\":\"{s}\",", .{@tagName(candidate.source)});
            try writer.print("\"confidence\":{d:.2},", .{candidate.confidence});
            try writer.print("\"is_cloudflare\":{}", .{candidate.is_cloudflare});
            try writer.writeAll("}");
        }
        try writer.writeAll("]}");
    }

    /// Execute favicon tool
    fn executeFavicon(self: *Self, arguments: ?std.json.Value, writer: anytype) !void {
        const target = try getStringArg(arguments, "target");

        const result = favicon.getFaviconHash(self.allocator, target) catch {
            try writer.writeAll("{\"error\":\"Favicon fetch failed\"}");
            return;
        };

        try writer.writeAll("{");
        try writer.print("\"mmh3_hash\":{d},", .{result.hash});
        try writer.print("\"size\":{d},", .{result.size});
        try writer.print("\"shodan_query\":\"http.favicon.hash:{d}\",", .{result.hash});
        try writer.print("\"censys_query\":\"services.http.response.favicons.md5_hash:{d}\"", .{result.hash});
        try writer.writeAll("}");
    }

    /// Execute ipcheck tool
    fn executeIpcheck(_: *Self, arguments: ?std.json.Value, writer: anytype) !void {
        if (arguments == null) return error.MissingArguments;
        const obj = arguments.?.object;

        const ips_val = obj.get("ips") orelse return error.MissingArguments;
        const ips_arr = ips_val.array;

        try writer.writeAll("{\"results\":[");

        for (ips_arr.items, 0..) |ip_val, i| {
            if (i > 0) try writer.writeAll(",");
            const ip = ip_val.string;
            const result = ip_ranges.checkProvider(ip);

            try writer.writeAll("{");
            try writer.print("\"ip\":\"{s}\",", .{ip});
            if (result) |r| {
                try writer.print("\"provider\":\"{s}\",", .{r.name});
                try writer.print("\"type\":\"{s}\",", .{@tagName(r.type)});
                try writer.writeAll("\"protected\":true");
            } else {
                try writer.writeAll("\"provider\":null,\"type\":null,\"protected\":false");
            }
            try writer.writeAll("}");
        }
        try writer.writeAll("]}");
    }

    /// Execute workers tool
    fn executeWorkers(self: *Self, arguments: ?std.json.Value, writer: anytype) !void {
        const target = try getStringArg(arguments, "target");

        const result = workers.detectWorker(self.allocator, target) catch {
            try writer.writeAll("{\"error\":\"Workers detection failed\"}");
            return;
        };

        try writer.writeAll("{");
        try writer.print("\"target\":\"{s}\",", .{target});
        try writer.print("\"is_worker\":{},", .{result.is_worker});
        try writer.print("\"confidence\":{d:.2},", .{result.confidence});
        try writer.print("\"platform\":\"{s}\"", .{@tagName(result.platform)});
        try writer.writeAll("}");
    }

    /// Execute pages tool
    fn executePages(self: *Self, arguments: ?std.json.Value, writer: anytype) !void {
        const target = try getStringArg(arguments, "target");

        const result = pages.detectPages(self.allocator, target) catch {
            try writer.writeAll("{\"error\":\"Pages detection failed\"}");
            return;
        };

        try writer.writeAll("{");
        try writer.print("\"target\":\"{s}\",", .{target});
        try writer.print("\"is_pages\":{},", .{result.is_pages});
        try writer.print("\"confidence\":{d:.2}", .{result.confidence});
        try writer.writeAll("}");
    }

    /// Execute tunnel tool
    fn executeTunnel(self: *Self, arguments: ?std.json.Value, writer: anytype) !void {
        const target = try getStringArg(arguments, "target");

        const result = tunnel.detectTunnel(self.allocator, target) catch {
            try writer.writeAll("{\"error\":\"Tunnel detection failed\"}");
            return;
        };

        try writer.writeAll("{");
        try writer.print("\"target\":\"{s}\",", .{target});
        try writer.print("\"is_tunnel\":{},", .{result.is_tunnel});
        try writer.print("\"confidence\":{d:.2},", .{result.confidence});
        try writer.print("\"tunnel_type\":\"{s}\"", .{@tagName(result.tunnel_type)});
        try writer.writeAll("}");
    }

    /// Execute r2 tool
    fn executeR2(self: *Self, arguments: ?std.json.Value, writer: anytype) !void {
        const target = try getStringArg(arguments, "target");

        const result = r2.detectR2(self.allocator, target) catch {
            try writer.writeAll("{\"error\":\"R2 detection failed\"}");
            return;
        };

        try writer.writeAll("{");
        try writer.print("\"target\":\"{s}\",", .{target});
        try writer.print("\"is_r2\":{},", .{result.is_r2});
        try writer.print("\"confidence\":{d:.2},", .{result.confidence});
        try writer.print("\"public_access\":{}", .{result.public_access});
        try writer.writeAll("}");
    }

    /// Execute waf tool
    fn executeWaf(self: *Self, arguments: ?std.json.Value, writer: anytype) !void {
        const target = try getStringArg(arguments, "target");

        const result = waf.detectWaf(self.allocator, target) catch {
            try writer.writeAll("{\"error\":\"WAF detection failed\"}");
            return;
        };

        try writer.writeAll("{");
        try writer.print("\"target\":\"{s}\",", .{target});
        try writer.print("\"waf_active\":{},", .{result.waf_active});
        try writer.print("\"confidence\":{d:.2},", .{result.confidence});
        try writer.print("\"security_level\":\"{s}\",", .{@tagName(result.security_level)});
        try writer.print("\"bot_management\":{},", .{result.bot_management});
        try writer.print("\"rate_limiting\":{}", .{result.rate_limiting});
        try writer.writeAll("}");
    }
};

/// Get a string argument from JSON params
fn getStringArg(arguments: ?std.json.Value, key: []const u8) ![]const u8 {
    if (arguments == null) return error.MissingArguments;
    const obj = arguments.?.object;
    const val = obj.get(key) orelse return error.MissingArguments;
    return val.string;
}

/// Write JSON-escaped string
fn writeJsonEscaped(writer: anytype, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    try writer.print("\\u{x:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
}

/// Run MCP server (entry point)
pub fn runServer(allocator: Allocator) !void {
    var server = Server.init(allocator);
    try server.run();
}
