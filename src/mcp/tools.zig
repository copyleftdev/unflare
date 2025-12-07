//! MCP Tool Definitions
//!
//! Defines all unflare tools with their JSON schemas for MCP.

const std = @import("std");

/// Tool definition for MCP
pub const Tool = struct {
    name: []const u8,
    description: []const u8,
    inputSchema: InputSchema,
};

/// JSON Schema for tool input
pub const InputSchema = struct {
    type: []const u8 = "object",
    properties: []const Property,
    required: []const []const u8,
};

/// Property in JSON Schema
pub const Property = struct {
    name: []const u8,
    type: []const u8,
    description: []const u8,
    items_type: ?[]const u8 = null, // For array types
};

/// All available tools
pub const tools = [_]Tool{
    .{
        .name = "unflare_detect",
        .description = "Detect if a domain is behind Cloudflare. Returns detection confidence, signals found, and datacenter location.",
        .inputSchema = .{
            .properties = &[_]Property{
                .{ .name = "target", .type = "string", .description = "Domain or URL to check (e.g., 'cloudflare.com')" },
            },
            .required = &[_][]const u8{"target"},
        },
    },
    .{
        .name = "unflare_probe",
        .description = "Perform detailed HTTP response analysis on a target. Returns headers, response time, and Cloudflare signals.",
        .inputSchema = .{
            .properties = &[_]Property{
                .{ .name = "target", .type = "string", .description = "Domain or URL to probe" },
            },
            .required = &[_][]const u8{"target"},
        },
    },
    .{
        .name = "unflare_trace",
        .description = "Fetch the /cdn-cgi/trace endpoint from a Cloudflare-protected site. Returns visitor IP, datacenter, TLS version, and more.",
        .inputSchema = .{
            .properties = &[_]Property{
                .{ .name = "target", .type = "string", .description = "Domain to fetch trace from" },
            },
            .required = &[_][]const u8{"target"},
        },
    },
    .{
        .name = "unflare_origin",
        .description = "Attempt to discover the origin IP address behind Cloudflare by scanning subdomains and analyzing DNS records.",
        .inputSchema = .{
            .properties = &[_]Property{
                .{ .name = "target", .type = "string", .description = "Domain to find origin IP for" },
            },
            .required = &[_][]const u8{"target"},
        },
    },
    .{
        .name = "unflare_favicon",
        .description = "Generate MMH3 favicon hash for Shodan/Censys searches. Useful for finding related infrastructure.",
        .inputSchema = .{
            .properties = &[_]Property{
                .{ .name = "target", .type = "string", .description = "Domain to fetch favicon from" },
            },
            .required = &[_][]const u8{"target"},
        },
    },
    .{
        .name = "unflare_ipcheck",
        .description = "Check if IP addresses belong to Cloudflare or other CDN/WAF ranges.",
        .inputSchema = .{
            .properties = &[_]Property{
                .{ .name = "ips", .type = "array", .description = "List of IP addresses to check", .items_type = "string" },
            },
            .required = &[_][]const u8{"ips"},
        },
    },
    .{
        .name = "unflare_workers",
        .description = "Detect if a domain is running Cloudflare Workers. Identifies workers.dev subdomains and custom domain Workers.",
        .inputSchema = .{
            .properties = &[_]Property{
                .{ .name = "target", .type = "string", .description = "Domain to check for Workers" },
            },
            .required = &[_][]const u8{"target"},
        },
    },
    .{
        .name = "unflare_pages",
        .description = "Detect if a domain is hosted on Cloudflare Pages. Identifies pages.dev subdomains and custom domain Pages sites.",
        .inputSchema = .{
            .properties = &[_]Property{
                .{ .name = "target", .type = "string", .description = "Domain to check for Pages" },
            },
            .required = &[_][]const u8{"target"},
        },
    },
    .{
        .name = "unflare_tunnel",
        .description = "Detect if a domain is using Cloudflare Tunnel (formerly Argo Tunnel). Identifies trycloudflare.com and tunnel error pages.",
        .inputSchema = .{
            .properties = &[_]Property{
                .{ .name = "target", .type = "string", .description = "Domain to check for Tunnel" },
            },
            .required = &[_][]const u8{"target"},
        },
    },
    .{
        .name = "unflare_r2",
        .description = "Detect if a domain is serving content from Cloudflare R2 storage buckets.",
        .inputSchema = .{
            .properties = &[_]Property{
                .{ .name = "target", .type = "string", .description = "Domain or bucket URL to check for R2" },
            },
            .required = &[_][]const u8{"target"},
        },
    },
    .{
        .name = "unflare_waf",
        .description = "Detect Cloudflare WAF (Web Application Firewall) presence and configuration. Identifies challenge pages, security levels, and bot management.",
        .inputSchema = .{
            .properties = &[_]Property{
                .{ .name = "target", .type = "string", .description = "Domain to check for WAF" },
            },
            .required = &[_][]const u8{"target"},
        },
    },
};

/// Write tools list as JSON
pub fn writeToolsJson(writer: anytype) !void {
    try writer.writeAll("{\"tools\":[");

    for (tools, 0..) |tool, i| {
        if (i > 0) try writer.writeAll(",");
        try writeToolJson(writer, tool);
    }

    try writer.writeAll("]}");
}

/// Write a single tool as JSON
fn writeToolJson(writer: anytype, tool: Tool) !void {
    try writer.writeAll("{\"name\":\"");
    try writer.writeAll(tool.name);
    try writer.writeAll("\",\"description\":\"");
    try writeJsonEscaped(writer, tool.description);
    try writer.writeAll("\",\"inputSchema\":{\"type\":\"object\",\"properties\":{");

    for (tool.inputSchema.properties, 0..) |prop, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.writeAll("\"");
        try writer.writeAll(prop.name);
        try writer.writeAll("\":{\"type\":\"");
        try writer.writeAll(prop.type);
        try writer.writeAll("\",\"description\":\"");
        try writeJsonEscaped(writer, prop.description);
        try writer.writeAll("\"");
        if (prop.items_type) |items| {
            try writer.writeAll(",\"items\":{\"type\":\"");
            try writer.writeAll(items);
            try writer.writeAll("\"}");
        }
        try writer.writeAll("}");
    }

    try writer.writeAll("},\"required\":[");
    for (tool.inputSchema.required, 0..) |req, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.writeAll("\"");
        try writer.writeAll(req);
        try writer.writeAll("\"");
    }
    try writer.writeAll("]}}");
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
            else => try writer.writeByte(c),
        }
    }
}

/// Find a tool by name
pub fn findTool(name: []const u8) ?Tool {
    for (tools) |tool| {
        if (std.mem.eql(u8, tool.name, name)) {
            return tool;
        }
    }
    return null;
}
