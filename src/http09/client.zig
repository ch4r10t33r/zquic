//! Minimal HTTP/0.9 client for quic-interop-runner compatibility.
//!
//! The QUIC interop runner's `transfer` test case expects the client to:
//! 1. Open a new QUIC stream for each requested URL.
//! 2. Send "GET <path>\r\n" on the stream.
//! 3. Receive the raw file bytes until the server closes the stream.
//! 4. Write the received bytes to `/downloads/<filename>`.
//!
//! This module provides request building and response writing helpers.

const std = @import("std");

pub const downloads_root: []const u8 = "/downloads";

/// Maximum URL length accepted by buildRequest.
pub const max_url_len: usize = 2048;

/// Build an HTTP/0.9 GET request line for `path` into `buf`.
///
/// Returns the slice of `buf` that was written.
pub fn buildRequest(path: []const u8, buf: []u8) error{BufferTooSmall}![]u8 {
    const line = std.fmt.bufPrint(buf, "GET {s}\r\n", .{path}) catch return error.BufferTooSmall;
    return line;
}

/// Extract the filename component from a URL path.
///
/// "/foo/bar/baz.txt" → "baz.txt"
/// "/index.html"      → "index.html"
/// "/"               → "index.html" (fallback)
pub fn filenameFromPath(path: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |slash| {
        const after = path[slash + 1 ..];
        if (after.len > 0) return after;
    }
    return "index.html";
}

/// Build the local download destination path for a given URL path.
///
/// dir="/downloads", path="/foo/bar.txt" → "/downloads/bar.txt"
pub fn downloadPath(dir: []const u8, path: []const u8, buf: []u8) error{BufferTooSmall}![]u8 {
    const name = filenameFromPath(path);
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ dir, name }) catch error.BufferTooSmall;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "http09 client: buildRequest" {
    var buf: [64]u8 = undefined;
    const req = try buildRequest("/hello.txt", &buf);
    try std.testing.expectEqualSlices(u8, "GET /hello.txt\r\n", req);
}

test "http09 client: filenameFromPath" {
    const testing = std.testing;
    try testing.expectEqualSlices(u8, "bar.txt", filenameFromPath("/foo/bar.txt"));
    try testing.expectEqualSlices(u8, "index.html", filenameFromPath("/index.html"));
    try testing.expectEqualSlices(u8, "index.html", filenameFromPath("/"));
    try testing.expectEqualSlices(u8, "file", filenameFromPath("/a/b/file"));
}

test "http09 client: downloadPath" {
    var buf: [64]u8 = undefined;
    const p = try downloadPath("/downloads", "/data/result.bin", &buf);
    try std.testing.expectEqualSlices(u8, "/downloads/result.bin", p);
}
