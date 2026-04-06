//! Minimal HTTP/0.9 server for quic-interop-runner compatibility.
//!
//! The QUIC interop runner's `transfer` test case uses HTTP/0.9: the client
//! sends a simple request "GET /path\r\n" on a QUIC stream, and the server
//! responds with the raw file contents followed by stream FIN.
//!
//! This module provides request parsing and response building for that
//! protocol, independent of the QUIC transport layer.
//!
//! File root: requests are served from the `/www` directory (interop
//! convention).

const std = @import("std");

pub const www_root: []const u8 = "/www";

/// Maximum request line length (e.g. "GET /index.html\r\n").
pub const max_request_len: usize = 4096;

/// Parsed HTTP/0.9 GET request.
pub const Request = struct {
    path: []const u8,
};

pub const ParseError = error{
    NotAGetRequest,
    MissingPath,
    PathTooLong,
    Incomplete,
};

/// Parse an HTTP/0.9 request from `data`.
///
/// Expects: "GET <path>\r\n" or "GET <path>\n"
/// Returns `error.Incomplete` if the line terminator has not arrived yet.
pub fn parseRequest(data: []const u8) ParseError!Request {
    if (data.len < 5) return error.Incomplete;
    if (!std.mem.startsWith(u8, data, "GET ")) return error.NotAGetRequest;

    const after_get = data[4..];
    // Find line terminator
    const nl = std.mem.indexOfScalar(u8, after_get, '\n') orelse return error.Incomplete;
    var path_end = nl;
    if (path_end > 0 and after_get[path_end - 1] == '\r') path_end -= 1;
    if (path_end == 0) return error.MissingPath;
    const path = after_get[0..path_end];
    if (path.len > 1024) return error.PathTooLong;
    return Request{ .path = path };
}

/// Resolve a request path to a filesystem path under `dir`.
///
/// Security: Rejects paths containing `..` or `//` to prevent directory
/// traversal.
pub fn resolvePath(dir: []const u8, path: []const u8, buf: []u8) error{ PathTooLong, Unsafe }![]u8 {
    if (std.mem.indexOf(u8, path, "..") != null) return error.Unsafe;
    if (std.mem.indexOf(u8, path, "//") != null) return error.Unsafe;
    const resolved = std.fmt.bufPrint(buf, "{s}{s}", .{ dir, path }) catch return error.PathTooLong;
    return resolved;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "http09 server: parse GET request" {
    const testing = std.testing;
    const req = try parseRequest("GET /index.html\r\n");
    try testing.expectEqualSlices(u8, "/index.html", req.path);
}

test "http09 server: parse GET request unix line ending" {
    const req = try parseRequest("GET /foo\n");
    try std.testing.expectEqualSlices(u8, "/foo", req.path);
}

test "http09 server: incomplete request" {
    const result = parseRequest("GET /foo");
    try std.testing.expectError(error.Incomplete, result);
}

test "http09 server: not a GET" {
    const result = parseRequest("POST /foo\r\n");
    try std.testing.expectError(error.NotAGetRequest, result);
}

test "http09 server: resolve path" {
    var buf: [256]u8 = undefined;
    const resolved = try resolvePath("/www", "/hello.txt", &buf);
    try std.testing.expectEqualSlices(u8, "/www/hello.txt", resolved);
}

test "http09 server: reject path traversal" {
    var buf: [256]u8 = undefined;
    try std.testing.expectError(error.Unsafe, resolvePath("/www", "/../etc/passwd", &buf));
}
