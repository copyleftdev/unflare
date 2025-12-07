//! unflare - Cloudflare Intelligence Toolkit
//!
//! A portable, high-performance tool for detecting and analyzing
//! Cloudflare-protected infrastructure.

const std = @import("std");

// Core modules
pub const detection = @import("core/detection.zig");
pub const origin = @import("core/origin.zig");
pub const favicon = @import("core/favicon.zig");
pub const types = @import("core/types.zig");

// Transport modules
pub const http = @import("transport/http.zig");
pub const dns = @import("transport/dns.zig");

// Data modules
pub const ip_ranges = @import("data/ip_ranges.zig");
pub const datacenters = @import("data/datacenters.zig");

// Re-export main types
pub const DetectionResult = types.DetectionResult;
pub const CfRay = types.CfRay;
pub const OriginCandidate = origin.OriginCandidate;

/// Library version
pub const version = "0.1.0";

test {
    // Run all module tests
    std.testing.refAllDecls(@This());
}
