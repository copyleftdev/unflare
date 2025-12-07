//! MCP JSON-RPC 2.0 Protocol Handler
//!
//! Implements the JSON-RPC 2.0 protocol for MCP communication.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// JSON-RPC 2.0 Error Codes
pub const ErrorCode = enum(i32) {
    parse_error = -32700,
    invalid_request = -32600,
    method_not_found = -32601,
    invalid_params = -32602,
    internal_error = -32603,
};

/// JSON-RPC Request
pub const Request = struct {
    jsonrpc: []const u8,
    method: []const u8,
    id: ?JsonId = null,
    params: ?std.json.Value = null,
};

/// JSON ID can be string, number, or null
pub const JsonId = union(enum) {
    string: []const u8,
    integer: i64,
    null,

    pub fn jsonStringify(self: JsonId, options: std.json.StringifyOptions, writer: anytype) !void {
        _ = options;
        switch (self) {
            .string => |s| try writer.print("\"{s}\"", .{s}),
            .integer => |i| try writer.print("{d}", .{i}),
            .null => try writer.writeAll("null"),
        }
    }
};

/// Parse a JSON-RPC request from a JSON value
pub fn parseRequest(allocator: Allocator, json_str: []const u8) !Request {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;

    const jsonrpc = if (obj.get("jsonrpc")) |v| v.string else return error.InvalidRequest;
    const method = if (obj.get("method")) |v| v.string else return error.InvalidRequest;

    var id: ?JsonId = null;
    if (obj.get("id")) |id_val| {
        switch (id_val) {
            .string => |s| id = .{ .string = try allocator.dupe(u8, s) },
            .integer => |i| id = .{ .integer = i },
            .null => id = .null,
            else => return error.InvalidRequest,
        }
    }

    // Deep copy params if present
    var params: ?std.json.Value = null;
    if (obj.get("params")) |p| {
        params = try deepCopyJson(allocator, p);
    }

    return Request{
        .jsonrpc = try allocator.dupe(u8, jsonrpc),
        .method = try allocator.dupe(u8, method),
        .id = id,
        .params = params,
    };
}

/// Deep copy a JSON value
fn deepCopyJson(allocator: Allocator, value: std.json.Value) !std.json.Value {
    switch (value) {
        .null => return .null,
        .bool => |b| return .{ .bool = b },
        .integer => |i| return .{ .integer = i },
        .float => |f| return .{ .float = f },
        .string => |s| return .{ .string = try allocator.dupe(u8, s) },
        .array => |arr| {
            var new_arr = std.json.Array.init(allocator);
            for (arr.items) |item| {
                try new_arr.append(try deepCopyJson(allocator, item));
            }
            return .{ .array = new_arr };
        },
        .object => |obj| {
            var new_obj = std.json.ObjectMap.init(allocator);
            var it = obj.iterator();
            while (it.next()) |entry| {
                const key = try allocator.dupe(u8, entry.key_ptr.*);
                const val = try deepCopyJson(allocator, entry.value_ptr.*);
                try new_obj.put(key, val);
            }
            return .{ .object = new_obj };
        },
        .number_string => |s| return .{ .number_string = try allocator.dupe(u8, s) },
    }
}

/// Write a JSON-RPC success response
pub fn writeSuccessResponse(writer: anytype, id: ?JsonId, result: anytype) !void {
    try writer.writeAll("{\"jsonrpc\":\"2.0\",\"result\":");
    try std.json.stringify(result, .{}, writer);
    try writer.writeAll(",\"id\":");
    if (id) |i| {
        try i.jsonStringify(.{}, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll("}\n");
}

/// Write a JSON-RPC success response with raw JSON result
pub fn writeRawSuccessResponse(writer: anytype, id: ?JsonId, raw_result: []const u8) !void {
    try writer.writeAll("{\"jsonrpc\":\"2.0\",\"result\":");
    try writer.writeAll(raw_result);
    try writer.writeAll(",\"id\":");
    if (id) |i| {
        try i.jsonStringify(.{}, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll("}\n");
}

/// Write a JSON-RPC error response
pub fn writeErrorResponse(writer: anytype, id: ?JsonId, code: ErrorCode, message: []const u8) !void {
    try writer.writeAll("{\"jsonrpc\":\"2.0\",\"error\":{\"code\":");
    try writer.print("{d}", .{@intFromEnum(code)});
    try writer.writeAll(",\"message\":\"");
    try writeJsonEscaped(writer, message);
    try writer.writeAll("\"},\"id\":");
    if (id) |i| {
        try i.jsonStringify(.{}, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll("}\n");
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

/// Read a line from stdin (for JSON-RPC over stdio)
pub fn readLine(allocator: Allocator, reader: anytype) !?[]u8 {
    var line = std.ArrayList(u8).init(allocator);
    errdefer line.deinit();

    reader.streamUntilDelimiter(line.writer(), '\n', 1024 * 1024) catch |err| {
        if (err == error.EndOfStream) {
            if (line.items.len == 0) return null;
        } else {
            return err;
        }
    };

    // Trim carriage return if present
    if (line.items.len > 0 and line.items[line.items.len - 1] == '\r') {
        _ = line.pop();
    }

    return try line.toOwnedSlice();
}
