//! CLI Interface
//!
//! Command-line interface with rich terminal output.

const std = @import("std");
const detection = @import("../core/detection.zig");
const origin = @import("../core/origin.zig");
const favicon = @import("../core/favicon.zig");
const types = @import("../core/types.zig");
const datacenters = @import("../data/datacenters.zig");
const ip_ranges = @import("../data/ip_ranges.zig");
const http = @import("../transport/http.zig");

const Allocator = std.mem.Allocator;

/// ANSI color codes
const Color = struct {
    const reset = "\x1b[0m";
    const bold = "\x1b[1m";
    const dim = "\x1b[2m";
    const red = "\x1b[31m";
    const green = "\x1b[32m";
    const yellow = "\x1b[33m";
    const blue = "\x1b[34m";
    const cyan = "\x1b[36m";
};

/// Box drawing characters
const Box = struct {
    const top_left = "╭";
    const top_right = "╮";
    const bottom_left = "╰";
    const bottom_right = "╯";
    const horizontal = "─";
    const vertical = "│";
};

/// CLI Command
pub const Command = enum {
    detect,
    probe,
    trace,
    origin,
    favicon,
    ipcheck,
    help,
    version,
};

/// Parse command from arguments
pub fn parseCommand(args: []const []const u8) ?Command {
    if (args.len < 2) return .help;

    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "detect")) return .detect;
    if (std.mem.eql(u8, cmd, "probe")) return .probe;
    if (std.mem.eql(u8, cmd, "trace")) return .trace;
    if (std.mem.eql(u8, cmd, "origin")) return .origin;
    if (std.mem.eql(u8, cmd, "favicon")) return .favicon;
    if (std.mem.eql(u8, cmd, "ipcheck")) return .ipcheck;
    if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) return .help;
    if (std.mem.eql(u8, cmd, "version") or std.mem.eql(u8, cmd, "--version") or std.mem.eql(u8, cmd, "-V")) return .version;

    return null;
}

/// Main CLI entry point
pub fn run(allocator: Allocator) !void {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const stdout = std.io.getStdOut().writer();

    const command = parseCommand(args) orelse {
        try stdout.print("{s}Error:{s} Unknown command: {s}\n", .{ Color.red, Color.reset, args[1] });
        try printHelp(stdout);
        return error.InvalidCommand;
    };

    switch (command) {
        .detect => try runDetect(allocator, args, stdout),
        .probe => try runProbe(allocator, args, stdout),
        .trace => try runTrace(allocator, args, stdout),
        .origin => try runOrigin(allocator, args, stdout),
        .favicon => try runFavicon(allocator, args, stdout),
        .ipcheck => try runIpCheck(args, stdout),
        .help => try printHelp(stdout),
        .version => try printVersion(stdout),
    }
}

/// Print help message
fn printHelp(writer: anytype) !void {
    try writer.writeAll(
        \\
        \\  ╭─────────────────────────────────────────╮
        \\  │           unflare v0.1.0                │
        \\  │     Cloudflare Intelligence Toolkit     │
        \\  ╰─────────────────────────────────────────╯
        \\
        \\  USAGE:
        \\      unflare <command> [options] <target>
        \\
        \\  COMMANDS:
        \\      detect     Detect Cloudflare on targets
        \\      probe      Detailed response analysis
        \\      trace      Fetch /cdn-cgi/trace data
        \\      origin     Discover origin IP behind Cloudflare
        \\      favicon    Generate favicon hash for hunting
        \\      ipcheck    Check IPs against CDN/WAF ranges
        \\      help       Show this help message
        \\      version    Show version information
        \\
        \\  EXAMPLES:
        \\      unflare detect example.com
        \\      unflare origin example.com
        \\      unflare ipcheck 104.16.1.1 8.8.8.8
        \\
    );
}

/// Print version
fn printVersion(writer: anytype) !void {
    try writer.print("unflare {s}\n", .{"0.1.0"});
}

/// Run detect command
fn runDetect(allocator: Allocator, args: []const []const u8, writer: anytype) !void {
    if (args.len < 3) {
        try writer.print("{s}Error:{s} detect requires at least one target\n", .{ Color.red, Color.reset });
        return error.MissingArgument;
    }

    var detector = detection.Detector.init(allocator);
    defer detector.deinit();

    // Process each target
    for (args[2..]) |target| {
        try writer.print("\n{s}Scanning:{s} {s}\n", .{ Color.cyan, Color.reset, target });

        const result = detector.detect(target) catch |err| {
            try writer.print("  {s}Error:{s} {}\n", .{ Color.red, Color.reset, err });
            continue;
        };

        try printDetectionResult(result, writer);
    }
}

/// Print detection result in a nice box
fn printDetectionResult(result: types.DetectionResult, writer: anytype) !void {
    const status_icon = if (result.is_cloudflare) "✓" else "✗";
    const status_color = if (result.is_cloudflare) Color.green else Color.dim;
    const status_text = if (result.is_cloudflare) "CLOUDFLARE DETECTED" else "Not Cloudflare";

    try writer.print(
        \\
        \\{s}╭─────────────────────── Cloudflare Detection ────────────────────────╮{s}
        \\{s}│{s}   Target        {s:<50}{s}│{s}
        \\{s}│{s}   Status        {s}{s} {s:<43}{s}{s}│{s}
        \\{s}│{s}   Confidence    {d:.0}%{s:<48}{s}│{s}
        \\{s}│{s}   Signals       {d} detected{s:<42}{s}│{s}
        \\{s}╰─────────────────────────────────────────────────────────────────────╯{s}
        \\
    , .{
        Color.blue,
        Color.reset,
        Color.blue,
        Color.reset,
        result.target,
        Color.blue,
        Color.reset,
        Color.blue,
        Color.reset,
        status_color,
        status_icon,
        status_text,
        Color.reset,
        Color.blue,
        Color.reset,
        Color.blue,
        Color.reset,
        result.confidence * 100,
        "",
        Color.blue,
        Color.reset,
        Color.blue,
        Color.reset,
        result.signals.count(),
        "",
        Color.blue,
        Color.reset,
        Color.blue,
        Color.reset,
    });

    // Print datacenter if available
    if (result.datacenter) |dc| {
        var buf: [64]u8 = undefined;
        const dc_info = datacenters.format(&dc, &buf) orelse &dc;
        try writer.print("  Datacenter: {s}\n", .{dc_info});
    }
}

/// Run probe command - detailed response analysis
fn runProbe(allocator: Allocator, args: []const []const u8, writer: anytype) !void {
    if (args.len < 3) {
        try writer.print("{s}Error:{s} probe requires a target\n", .{ Color.red, Color.reset });
        return error.MissingArgument;
    }

    const target = args[2];
    var url_buf: [512]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "https://{s}/", .{target}) catch {
        return error.InvalidArgument;
    };

    var client = http.Client.init(allocator);
    defer client.deinit();

    try writer.print("\n{s}Probing:{s} {s}\n\n", .{ Color.cyan, Color.reset, target });

    var response = client.get(url) catch |err| {
        try writer.print("{s}Error:{s} Connection failed: {}\n", .{ Color.red, Color.reset, err });
        return;
    };
    defer response.deinit();

    // Print status
    try writer.print("{s}Status:{s} {d}\n", .{ Color.bold, Color.reset, response.status_code });
    try writer.print("{s}Response Time:{s} {d:.2}ms\n\n", .{
        Color.bold,
        Color.reset,
        @as(f64, @floatFromInt(response.total_time_ns)) / 1_000_000.0,
    });

    // Print headers
    try writer.print("{s}Headers:{s}\n", .{ Color.bold, Color.reset });
    try writer.writeAll("┌─────────────────────────────────────────────────────────────────┐\n");

    for (response.headers.items) |header| {
        // Highlight Cloudflare-specific headers
        const is_cf_header = std.mem.startsWith(u8, header.name, "cf-") or
            std.mem.startsWith(u8, header.name, "CF-") or
            std.ascii.eqlIgnoreCase(header.name, "server") or
            std.ascii.eqlIgnoreCase(header.name, "nel") or
            std.ascii.eqlIgnoreCase(header.name, "alt-svc");

        if (is_cf_header) {
            try writer.print("│ {s}{s:<20}{s} {s}\n", .{
                Color.yellow,
                header.name,
                Color.reset,
                header.value,
            });
        } else {
            try writer.print("│ {s:<20} {s}\n", .{ header.name, header.value });
        }
    }

    try writer.writeAll("└─────────────────────────────────────────────────────────────────┘\n");

    // Analyze CF signals
    try writer.print("\n{s}Cloudflare Signals:{s}\n", .{ Color.bold, Color.reset });

    // Server header
    if (response.getHeader("server")) |server| {
        const is_cf = std.ascii.indexOfIgnoreCase(server, "cloudflare") != null;
        const icon = if (is_cf) "✓" else "✗";
        const color = if (is_cf) Color.green else Color.dim;
        try writer.print("  {s}{s}{s} Server: {s}\n", .{ color, icon, Color.reset, server });
    }

    // CF-Ray
    if (response.getHeader("cf-ray")) |ray| {
        try writer.print("  {s}✓{s} CF-Ray: {s}\n", .{ Color.green, Color.reset, ray });
        if (types.CfRay.parse(ray)) |parsed| {
            var dc_buf: [64]u8 = undefined;
            const dc_info = datacenters.format(&parsed.datacenter, &dc_buf) orelse &parsed.datacenter;
            try writer.print("    └─ Datacenter: {s}\n", .{dc_info});
        }
    } else {
        try writer.print("  {s}✗{s} CF-Ray: not present\n", .{ Color.dim, Color.reset });
    }

    // CF-Cache-Status
    if (response.getHeader("cf-cache-status")) |status| {
        try writer.print("  {s}✓{s} Cache-Status: {s}\n", .{ Color.green, Color.reset, status });
    }

    // Alt-Svc (HTTP/3)
    if (response.getHeader("alt-svc")) |alt_svc| {
        const has_h3 = std.mem.indexOf(u8, alt_svc, "h3=") != null;
        if (has_h3) {
            try writer.print("  {s}✓{s} HTTP/3: enabled\n", .{ Color.green, Color.reset });
        }
    }
}

/// Run origin command - discover origin IP
fn runOrigin(allocator: Allocator, args: []const []const u8, writer: anytype) !void {
    if (args.len < 3) {
        try writer.print("{s}Error:{s} origin requires a target\n", .{ Color.red, Color.reset });
        return error.MissingArgument;
    }

    const target = args[2];

    try writer.print("\n{s}Origin Discovery:{s} {s}\n", .{ Color.cyan, Color.reset, target });
    try writer.print("{s}Scanning subdomains...{s}\n\n", .{ Color.dim, Color.reset });

    var discovery = origin.OriginDiscovery.init(allocator);
    defer discovery.deinit();

    var result = discovery.discover(target) catch |err| {
        try writer.print("{s}Error:{s} Discovery failed: {}\n", .{ Color.red, Color.reset, err });
        return;
    };
    defer result.deinit();

    // Print target status
    try writer.writeAll("┌─────────────────────────────────────────────────────────────────┐\n");
    try writer.print("│ {s}Target Analysis{s}                                                 │\n", .{
        Color.bold,
        Color.reset,
    });
    try writer.writeAll("├─────────────────────────────────────────────────────────────────┤\n");

    if (result.target_ip) |ip| {
        const ip_str = ip[0..result.target_ip_len];
        const cf_status = if (result.target_is_cloudflare)
            Color.green ++ "✓ Behind Cloudflare" ++ Color.reset
        else
            Color.yellow ++ "✗ Not behind Cloudflare" ++ Color.reset;

        try writer.print("│ Target IP:      {s:<47} │\n", .{ip_str});
        try writer.print("│ Status:         {s:<36} │\n", .{cf_status});
    } else {
        try writer.print("│ Target IP:      {s}Could not resolve{s}                              │\n", .{
            Color.red,
            Color.reset,
        });
    }

    try writer.print("│ Subdomains:     {d:<47} │\n", .{result.subdomains_checked});
    try writer.writeAll("└─────────────────────────────────────────────────────────────────┘\n\n");

    // Count candidates
    var cf_count: usize = 0;
    var non_cf_count: usize = 0;
    for (result.candidates.items) |candidate| {
        if (candidate.is_cloudflare) {
            cf_count += 1;
        } else {
            non_cf_count += 1;
        }
    }

    // Print potential origins (non-CF IPs)
    if (non_cf_count > 0) {
        try writer.print("{s}🎯 Potential Origin IPs ({d} found):{s}\n", .{
            Color.green,
            non_cf_count,
            Color.reset,
        });
        try writer.writeAll("┌──────────────────┬────────────────────────────────┬──────────────┐\n");
        try writer.writeAll("│ IP               │ Source                         │ Confidence   │\n");
        try writer.writeAll("├──────────────────┼────────────────────────────────┼──────────────┤\n");

        for (result.candidates.items) |candidate| {
            if (!candidate.is_cloudflare) {
                try writer.print("│ {s}{s:<16}{s} │ {s:<30} │ {d:>5.0}%       │\n", .{
                    Color.green,
                    candidate.ipStr(),
                    Color.reset,
                    candidate.subdomainStr(),
                    candidate.confidence * 100,
                });
            }
        }
        try writer.writeAll("└──────────────────┴────────────────────────────────┴──────────────┘\n\n");
    }

    // Print Cloudflare IPs found
    if (cf_count > 0) {
        try writer.print("{s}☁️  Cloudflare IPs ({d} found):{s}\n", .{
            Color.dim,
            cf_count,
            Color.reset,
        });
        try writer.writeAll("┌──────────────────┬────────────────────────────────┐\n");
        try writer.writeAll("│ IP               │ Source                         │\n");
        try writer.writeAll("├──────────────────┼────────────────────────────────┤\n");

        for (result.candidates.items) |candidate| {
            if (candidate.is_cloudflare) {
                try writer.print("│ {s:<16} │ {s:<30} │\n", .{
                    candidate.ipStr(),
                    candidate.subdomainStr(),
                });
            }
        }
        try writer.writeAll("└──────────────────┴────────────────────────────────┘\n");
    }

    // Summary
    if (non_cf_count > 0 and result.target_is_cloudflare) {
        try writer.print("\n{s}⚠️  Potential origin leak detected!{s}\n", .{
            Color.yellow,
            Color.reset,
        });
        try writer.print("   Found {d} non-Cloudflare IP(s) that may expose the origin server.\n", .{non_cf_count});
    } else if (non_cf_count == 0 and result.target_is_cloudflare) {
        try writer.print("\n{s}✓ No obvious origin leaks found.{s}\n", .{
            Color.green,
            Color.reset,
        });
    }
}

/// Run trace command - fetch /cdn-cgi/trace
fn runTrace(allocator: Allocator, args: []const []const u8, writer: anytype) !void {
    if (args.len < 3) {
        try writer.print("{s}Error:{s} trace requires a target\n", .{ Color.red, Color.reset });
        return error.MissingArgument;
    }

    const target = args[2];

    var client = http.Client.init(allocator);
    defer client.deinit();

    try writer.print("\n{s}Fetching:{s} https://{s}/cdn-cgi/trace\n\n", .{ Color.cyan, Color.reset, target });

    var response = client.fetchTrace(target) catch |err| {
        try writer.print("{s}Error:{s} Connection failed: {}\n", .{ Color.red, Color.reset, err });
        return;
    };
    defer response.deinit();

    if (response.status_code != 200) {
        try writer.print("{s}Error:{s} Received status {d} (not Cloudflare?)\n", .{
            Color.red,
            Color.reset,
            response.status_code,
        });
        return;
    }

    // Parse and display trace data
    try writer.writeAll("┌─────────────────────────────────────────────────────────────────┐\n");
    try writer.print("│ {s}cdn-cgi/trace Response{s}                                          │\n", .{
        Color.bold,
        Color.reset,
    });
    try writer.writeAll("├─────────────────────────────────────────────────────────────────┤\n");

    var lines = std.mem.splitScalar(u8, response.body.items, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;

        // Parse key=value
        if (std.mem.indexOfScalar(u8, line, '=')) |eq_pos| {
            const key = line[0..eq_pos];
            const value = line[eq_pos + 1 ..];

            // Highlight important fields
            const is_important = std.mem.eql(u8, key, "colo") or
                std.mem.eql(u8, key, "fl") or
                std.mem.eql(u8, key, "warp") or
                std.mem.eql(u8, key, "tls") or
                std.mem.eql(u8, key, "h");

            if (is_important) {
                try writer.print("│ {s}{s:<12}{s} {s}\n", .{
                    Color.yellow,
                    key,
                    Color.reset,
                    value,
                });
            } else {
                try writer.print("│ {s:<12} {s}\n", .{ key, value });
            }
        }
    }

    try writer.writeAll("└─────────────────────────────────────────────────────────────────┘\n");

    // Print datacenter info if available
    if (std.mem.indexOf(u8, response.body.items, "colo=")) |pos| {
        const start = pos + 5;
        if (start + 3 <= response.body.items.len) {
            const colo = response.body.items[start .. start + 3];
            var dc_buf: [64]u8 = undefined;
            if (datacenters.format(colo, &dc_buf)) |dc_info| {
                try writer.print("\n{s}Datacenter:{s} {s}\n", .{ Color.bold, Color.reset, dc_info });
            }
        }
    }
}

/// Run favicon command - generate favicon hash for Shodan/Censys
fn runFavicon(allocator: Allocator, args: []const []const u8, writer: anytype) !void {
    if (args.len < 3) {
        try writer.print("{s}Error:{s} favicon requires a target\n", .{ Color.red, Color.reset });
        return error.MissingArgument;
    }

    const target = args[2];

    try writer.print("\n{s}Favicon Hash:{s} {s}\n", .{ Color.cyan, Color.reset, target });
    try writer.print("{s}Fetching favicon...{s}\n\n", .{ Color.dim, Color.reset });

    const result = favicon.getFaviconHash(allocator, target) catch |err| {
        switch (err) {
            error.FaviconNotFound => {
                try writer.print("{s}Error:{s} No favicon found at common paths\n", .{
                    Color.red,
                    Color.reset,
                });
                try writer.writeAll("  Tried: /favicon.ico, /favicon.png, /apple-touch-icon.png\n");
            },
            else => {
                try writer.print("{s}Error:{s} Failed to fetch favicon: {}\n", .{
                    Color.red,
                    Color.reset,
                    err,
                });
            },
        }
        return;
    };

    // Display results
    try writer.writeAll("┌─────────────────────────────────────────────────────────────────┐\n");
    try writer.print("│ {s}Favicon Analysis{s}                                                │\n", .{
        Color.bold,
        Color.reset,
    });
    try writer.writeAll("├─────────────────────────────────────────────────────────────────┤\n");
    try writer.print("│ URL:            {s:<47} │\n", .{result.url()});
    try writer.print("│ Size:           {d:<47} │\n", .{result.size});
    try writer.print("│ Base64 Length:  {d:<47} │\n", .{result.base64_len});
    try writer.writeAll("├─────────────────────────────────────────────────────────────────┤\n");
    try writer.print("│ {s}MMH3 Hash:      {s}{d:<40}{s}  │\n", .{
        Color.bold,
        Color.green,
        result.hash,
        Color.reset,
    });
    try writer.writeAll("└─────────────────────────────────────────────────────────────────┘\n\n");

    // Print Shodan/Censys queries
    try writer.print("{s}Search Queries:{s}\n", .{ Color.bold, Color.reset });

    var shodan_buf: [64]u8 = undefined;
    const shodan_query = result.shodanQuery(&shodan_buf) catch "error";
    try writer.print("  {s}Shodan:{s}  {s}\n", .{ Color.yellow, Color.reset, shodan_query });
    try writer.print("  {s}Censys:{s}  services.http.response.favicons.md5_hash:{d}\n", .{
        Color.yellow,
        Color.reset,
        result.hash,
    });

    try writer.print("\n{s}Tip:{s} Use these queries to find other servers with the same favicon.\n", .{
        Color.dim,
        Color.reset,
    });
}

/// Run ipcheck command
fn runIpCheck(args: []const []const u8, writer: anytype) !void {
    if (args.len < 3) {
        try writer.print("{s}Error:{s} ipcheck requires at least one IP\n", .{ Color.red, Color.reset });
        return error.MissingArgument;
    }

    try writer.writeAll(
        \\
        \\                 IP Range Check                  
        \\┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━┓
        \\┃ IP            ┃ Provider   ┃ Type ┃ Protected ┃
        \\┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━┩
        \\
    );

    for (args[2..]) |ip| {
        const result = ip_ranges.checkProvider(ip);

        if (result) |r| {
            const type_str = switch (r.type) {
                .cdn => "cdn",
                .waf => "waf",
                .cloud => "cloud",
            };
            try writer.print("│ {s:<14}│ {s:<11}│ {s:<5}│ {s}✓{s}         │\n", .{
                ip,
                r.name,
                type_str,
                Color.green,
                Color.reset,
            });
        } else {
            try writer.print("│ {s:<14}│ {s:<11}│ {s:<5}│ {s}✗{s}         │\n", .{
                ip,
                "-",
                "-",
                Color.dim,
                Color.reset,
            });
        }
    }

    try writer.writeAll("└───────────────┴────────────┴──────┴───────────┘\n");
}

// ============================================================================
// Tests
// ============================================================================

test "parseCommand recognizes valid commands" {
    const detect_args = [_][]const u8{ "unflare", "detect", "example.com" };
    try std.testing.expectEqual(Command.detect, parseCommand(&detect_args).?);

    const help_args = [_][]const u8{ "unflare", "--help" };
    try std.testing.expectEqual(Command.help, parseCommand(&help_args).?);

    const version_args = [_][]const u8{ "unflare", "-V" };
    try std.testing.expectEqual(Command.version, parseCommand(&version_args).?);
}

test "parseCommand returns null for unknown commands" {
    const args = [_][]const u8{ "unflare", "unknown" };
    try std.testing.expect(parseCommand(&args) == null);
}

test "parseCommand returns help for no args" {
    const args = [_][]const u8{"unflare"};
    try std.testing.expectEqual(Command.help, parseCommand(&args).?);
}
