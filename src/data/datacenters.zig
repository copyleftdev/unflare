//! Cloudflare Datacenter Database
//!
//! Maps IATA airport codes to geographic locations.

const std = @import("std");

/// Geographic region
pub const Region = enum {
    north_america,
    south_america,
    europe,
    asia_pacific,
    middle_east,
    africa,
};

/// Datacenter information
pub const Datacenter = struct {
    code: [3]u8,
    city: []const u8,
    country: [2]u8,
    region: Region,
};

/// Datacenter lookup table
pub const DATACENTERS = std.StaticStringMap(Datacenter).initComptime(.{
    // North America
    .{ "LAX", Datacenter{ .code = "LAX".*, .city = "Los Angeles", .country = "US".*, .region = .north_america } },
    .{ "SFO", Datacenter{ .code = "SFO".*, .city = "San Francisco", .country = "US".*, .region = .north_america } },
    .{ "SEA", Datacenter{ .code = "SEA".*, .city = "Seattle", .country = "US".*, .region = .north_america } },
    .{ "ORD", Datacenter{ .code = "ORD".*, .city = "Chicago", .country = "US".*, .region = .north_america } },
    .{ "DFW", Datacenter{ .code = "DFW".*, .city = "Dallas", .country = "US".*, .region = .north_america } },
    .{ "IAD", Datacenter{ .code = "IAD".*, .city = "Washington DC", .country = "US".*, .region = .north_america } },
    .{ "EWR", Datacenter{ .code = "EWR".*, .city = "Newark", .country = "US".*, .region = .north_america } },
    .{ "ATL", Datacenter{ .code = "ATL".*, .city = "Atlanta", .country = "US".*, .region = .north_america } },
    .{ "MIA", Datacenter{ .code = "MIA".*, .city = "Miami", .country = "US".*, .region = .north_america } },
    .{ "YYZ", Datacenter{ .code = "YYZ".*, .city = "Toronto", .country = "CA".*, .region = .north_america } },
    .{ "YVR", Datacenter{ .code = "YVR".*, .city = "Vancouver", .country = "CA".*, .region = .north_america } },

    // Europe
    .{ "LHR", Datacenter{ .code = "LHR".*, .city = "London", .country = "GB".*, .region = .europe } },
    .{ "AMS", Datacenter{ .code = "AMS".*, .city = "Amsterdam", .country = "NL".*, .region = .europe } },
    .{ "FRA", Datacenter{ .code = "FRA".*, .city = "Frankfurt", .country = "DE".*, .region = .europe } },
    .{ "CDG", Datacenter{ .code = "CDG".*, .city = "Paris", .country = "FR".*, .region = .europe } },
    .{ "MAD", Datacenter{ .code = "MAD".*, .city = "Madrid", .country = "ES".*, .region = .europe } },
    .{ "MXP", Datacenter{ .code = "MXP".*, .city = "Milan", .country = "IT".*, .region = .europe } },
    .{ "ARN", Datacenter{ .code = "ARN".*, .city = "Stockholm", .country = "SE".*, .region = .europe } },

    // Asia Pacific
    .{ "NRT", Datacenter{ .code = "NRT".*, .city = "Tokyo", .country = "JP".*, .region = .asia_pacific } },
    .{ "HKG", Datacenter{ .code = "HKG".*, .city = "Hong Kong", .country = "HK".*, .region = .asia_pacific } },
    .{ "SIN", Datacenter{ .code = "SIN".*, .city = "Singapore", .country = "SG".*, .region = .asia_pacific } },
    .{ "SYD", Datacenter{ .code = "SYD".*, .city = "Sydney", .country = "AU".*, .region = .asia_pacific } },
    .{ "ICN", Datacenter{ .code = "ICN".*, .city = "Seoul", .country = "KR".*, .region = .asia_pacific } },
    .{ "BOM", Datacenter{ .code = "BOM".*, .city = "Mumbai", .country = "IN".*, .region = .asia_pacific } },

    // South America
    .{ "GRU", Datacenter{ .code = "GRU".*, .city = "São Paulo", .country = "BR".*, .region = .south_america } },
    .{ "EZE", Datacenter{ .code = "EZE".*, .city = "Buenos Aires", .country = "AR".*, .region = .south_america } },
    .{ "SCL", Datacenter{ .code = "SCL".*, .city = "Santiago", .country = "CL".*, .region = .south_america } },

    // Middle East
    .{ "DXB", Datacenter{ .code = "DXB".*, .city = "Dubai", .country = "AE".*, .region = .middle_east } },
    .{ "TLV", Datacenter{ .code = "TLV".*, .city = "Tel Aviv", .country = "IL".*, .region = .middle_east } },

    // Africa
    .{ "JNB", Datacenter{ .code = "JNB".*, .city = "Johannesburg", .country = "ZA".*, .region = .africa } },
    .{ "CPT", Datacenter{ .code = "CPT".*, .city = "Cape Town", .country = "ZA".*, .region = .africa } },
});

/// Look up datacenter by IATA code
pub fn lookup(code: []const u8) ?Datacenter {
    if (code.len != 3) return null;
    return DATACENTERS.get(code);
}

/// Format datacenter as "CODE (City, Country)"
pub fn format(code: []const u8, buf: []u8) ?[]u8 {
    const dc = lookup(code) orelse return null;

    std.debug.assert(buf.len >= 64);

    return std.fmt.bufPrint(buf, "{s} ({s}, {s})", .{
        code,
        dc.city,
        &dc.country,
    }) catch return null;
}

// ============================================================================
// Tests
// ============================================================================

test "lookup finds known datacenters" {
    const lax = lookup("LAX").?;
    try std.testing.expectEqualStrings("Los Angeles", lax.city);
    try std.testing.expectEqualStrings("US", &lax.country);
    try std.testing.expectEqual(Region.north_america, lax.region);

    const nrt = lookup("NRT").?;
    try std.testing.expectEqualStrings("Tokyo", nrt.city);
    try std.testing.expectEqual(Region.asia_pacific, nrt.region);
}

test "lookup returns null for unknown codes" {
    try std.testing.expect(lookup("XXX") == null);
    try std.testing.expect(lookup("") == null);
    try std.testing.expect(lookup("LA") == null);
    try std.testing.expect(lookup("LAXX") == null);
}

test "format produces correct output" {
    var buf: [64]u8 = undefined;
    const result = format("LAX", &buf).?;
    try std.testing.expectEqualStrings("LAX (Los Angeles, US)", result);
}
