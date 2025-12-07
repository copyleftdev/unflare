//! MCP (Model Context Protocol) Module
//!
//! Provides an MCP server interface for unflare, allowing AI assistants
//! to use unflare tools via the Model Context Protocol.

pub const server = @import("server.zig");
pub const protocol = @import("protocol.zig");
pub const tools = @import("tools.zig");

pub const runServer = server.runServer;
pub const Server = server.Server;
