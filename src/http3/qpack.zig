//! QPACK: Header Compression for HTTP/3 (RFC 9204).
//!
//! QPACK is a compression format for HTTP/3 header fields.  It builds on
//! HPACK (RFC 7541) but is adapted for QUIC's out-of-order delivery.
//!
//! QPACK uses two QUIC unidirectional streams per direction:
//!   - Encoder stream: communicates table updates to the peer.
//!   - Decoder stream: sends acknowledgements back.
//!
//! This implementation provides:
//!   - Static table lookup (RFC 9204 Appendix A).
//!   - Literal header encoding (never-indexed, no dynamic table).
//!   - Request/response header block encoding and decoding.
//!
//! Dynamic table support and Huffman coding are out of scope for the
//! initial interop runner test cases.

const std = @import("std");

// ---------------------------------------------------------------------------
// QPACK static table (RFC 9204 Appendix A – first 99 entries)
// ---------------------------------------------------------------------------

pub const StaticEntry = struct {
    name: []const u8,
    value: []const u8,
};

pub const static_table = [_]StaticEntry{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":path", .value = "/" },
    .{ .name = "age", .value = "0" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-length", .value = "0" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = ":method", .value = "CONNECT" },
    .{ .name = ":method", .value = "DELETE" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "HEAD" },
    .{ .name = ":method", .value = "OPTIONS" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":method", .value = "PUT" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "103" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "503" },
    .{ .name = "accept", .value = "*/*" },
    .{ .name = "accept", .value = "application/dns-message" },
    .{ .name = "accept-encoding", .value = "gzip, deflate, br" },
    .{ .name = "accept-ranges", .value = "bytes" },
    .{ .name = "access-control-allow-headers", .value = "cache-control" },
    .{ .name = "access-control-allow-headers", .value = "content-type" },
    .{ .name = "access-control-allow-origin", .value = "*" },
    .{ .name = "cache-control", .value = "max-age=0" },
    .{ .name = "cache-control", .value = "max-age=2592000" },
    .{ .name = "cache-control", .value = "max-age=604800" },
    .{ .name = "cache-control", .value = "no-cache" },
    .{ .name = "cache-control", .value = "no-store" },
    .{ .name = "cache-control", .value = "public, max-age=31536000" },
    .{ .name = "content-encoding", .value = "br" },
    .{ .name = "content-encoding", .value = "gzip" },
    .{ .name = "content-type", .value = "application/dns-message" },
    .{ .name = "content-type", .value = "application/javascript" },
    .{ .name = "content-type", .value = "application/json" },
    .{ .name = "content-type", .value = "application/x-www-form-urlencoded" },
    .{ .name = "content-type", .value = "image/gif" },
    .{ .name = "content-type", .value = "image/jpeg" },
    .{ .name = "content-type", .value = "image/png" },
    .{ .name = "content-type", .value = "text/css" },
    .{ .name = "content-type", .value = "text/html; charset=utf-8" },
    .{ .name = "content-type", .value = "text/plain" },
    .{ .name = "content-type", .value = "text/plain;charset=utf-8" },
    .{ .name = "range", .value = "bytes=0-" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains; preload" },
    .{ .name = "vary", .value = "accept-encoding" },
    .{ .name = "vary", .value = "origin" },
    .{ .name = "x-content-type-options", .value = "nosniff" },
    .{ .name = "x-xss-protection", .value = "1; mode=block" },
    .{ .name = ":status", .value = "100" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "302" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "403" },
    .{ .name = ":status", .value = "421" },
    .{ .name = ":status", .value = "425" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "access-control-allow-credentials", .value = "FALSE" },
    .{ .name = "access-control-allow-credentials", .value = "TRUE" },
    .{ .name = "access-control-allow-headers", .value = "*" },
    .{ .name = "access-control-allow-methods", .value = "get" },
    .{ .name = "access-control-allow-methods", .value = "get, post, options" },
    .{ .name = "access-control-allow-methods", .value = "options" },
    .{ .name = "access-control-allow-origin", .value = "null" },
    .{ .name = "access-control-expose-headers", .value = "content-length" },
    .{ .name = "access-control-request-headers", .value = "content-type" },
    .{ .name = "access-control-request-method", .value = "get" },
    .{ .name = "access-control-request-method", .value = "post" },
    .{ .name = "alt-svc", .value = "clear" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "content-security-policy", .value = "script-src 'none'; object-src 'none'; base-uri 'none'" },
    .{ .name = "early-data", .value = "1" },
    .{ .name = "expect-ct", .value = "" },
    .{ .name = "forwarded", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "origin", .value = "" },
    .{ .name = "purpose", .value = "prefetch" },
    .{ .name = "server", .value = "" },
    .{ .name = "timing-allow-origin", .value = "*" },
    .{ .name = "upgrade-insecure-requests", .value = "1" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "x-forwarded-for", .value = "" },
    .{ .name = "x-frame-options", .value = "deny" },
    .{ .name = "x-frame-options", .value = "sameorigin" },
};

// ---------------------------------------------------------------------------
// Header field representation
// ---------------------------------------------------------------------------

pub const Header = struct {
    name: []const u8,
    value: []const u8,
    sensitive: bool = false,
};

// ---------------------------------------------------------------------------
// Encoder (literal, no dynamic table)
// ---------------------------------------------------------------------------

/// Encode a single header field as a QPACK literal-with-name-reference or
/// literal-without-name-reference.
///
/// Uses "Literal Header Field Without Name Reference" (RFC 9204 §4.5.6)
/// for simplicity (prefix 0b001xxxxx).
///
/// Encoding format:
///   0b00100000 (1 byte: prefix)
///   name length (varint) + name bytes
///   value length (varint) + value bytes
fn encodeLiteralField(buf: []u8, name: []const u8, value: []const u8) error{BufferTooSmall}!usize {
    var pos: usize = 0;

    // Literal Header Field Without Name Reference: 0 0 1 N H Name-Length Name Value-Length Value
    // N=0 (not never-indexed), H=0 (no Huffman).  First byte: 0b00100000 = 0x20.
    if (pos >= buf.len) return error.BufferTooSmall;
    buf[pos] = 0x20;
    pos += 1;

    // Name length + bytes (8-bit prefix integer, RFC 9204 §4.1.1)
    if (pos + 1 + name.len > buf.len) return error.BufferTooSmall;
    buf[pos] = @intCast(name.len);
    pos += 1;
    @memcpy(buf[pos .. pos + name.len], name);
    pos += name.len;

    // Value length + bytes
    if (pos + 1 + value.len > buf.len) return error.BufferTooSmall;
    buf[pos] = @intCast(value.len);
    pos += 1;
    @memcpy(buf[pos .. pos + value.len], value);
    pos += value.len;

    return pos;
}

/// Encode a required insertion count (RIC) and S-bit prefix for a QPACK
/// header block.  With a static-only table (dynamic table capacity = 0):
///   Required Insert Count = 0 (encoded as 0x00)
///   Sign bit = 0, Delta Base = 0 (encoded as 0x00)
fn writeHeaderBlockPrefix(buf: []u8) error{BufferTooSmall}!usize {
    if (buf.len < 2) return error.BufferTooSmall;
    buf[0] = 0x00; // Required Insert Count = 0
    buf[1] = 0x00; // S=0, Delta Base = 0
    return 2;
}

/// Encode a slice of headers into a QPACK header block.
///
/// Uses literal encoding only (no dynamic table, no Huffman).
/// Result is written into `buf`; returns bytes written.
pub fn encodeHeaders(headers: []const Header, buf: []u8) error{BufferTooSmall}!usize {
    var pos: usize = try writeHeaderBlockPrefix(buf);
    for (headers) |h| {
        const n = try encodeLiteralField(buf[pos..], h.name, h.value);
        pos += n;
    }
    return pos;
}

// ---------------------------------------------------------------------------
// Decoder (literal fields only)
// ---------------------------------------------------------------------------

pub const DecodeError = error{
    BufferTooShort,
    TooManyHeaders,
    Unsupported,
};

pub const max_headers: usize = 64;

pub const DecodedHeaders = struct {
    headers: [max_headers]Header,
    count: usize,
};

/// Decode a QPACK header block (literal-only subset).
///
/// Skips the 2-byte Required Insert Count / Base prefix.
/// Decodes "Literal Header Field Without Name Reference" (0b001xxxxx) entries.
/// Returns error.Unsupported for static/dynamic indexed representations.
pub fn decodeHeaders(buf: []const u8, out: *DecodedHeaders) DecodeError!void {
    if (buf.len < 2) return error.BufferTooShort;
    // Skip 2-byte header block prefix (RIC + base).
    var pos: usize = 2;
    out.count = 0;

    while (pos < buf.len) {
        if (out.count >= max_headers) return error.TooManyHeaders;
        const first = buf[pos];

        if (first & 0x80 != 0) {
            // Indexed Field Line (0b1xxxxxxx) — references static/dynamic table.
            // Not supported without a dynamic table; reject if not static.
            return error.Unsupported;
        } else if (first & 0x40 != 0) {
            // Literal Field Line With Name Reference (0b01xxxxxx).
            return error.Unsupported;
        } else if (first & 0x20 != 0) {
            // Literal Field Line Without Name Reference (0b001xxxxx).
            pos += 1; // consume prefix byte
            if (pos >= buf.len) return error.BufferTooShort;
            const name_len = buf[pos];
            pos += 1;
            if (pos + name_len > buf.len) return error.BufferTooShort;
            const name = buf[pos .. pos + name_len];
            pos += name_len;
            if (pos >= buf.len) return error.BufferTooShort;
            const val_len = buf[pos];
            pos += 1;
            if (pos + val_len > buf.len) return error.BufferTooShort;
            const value = buf[pos .. pos + val_len];
            pos += val_len;
            out.headers[out.count] = .{ .name = name, .value = value };
            out.count += 1;
        } else {
            // Other representations not supported.
            return error.Unsupported;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "qpack: encode/decode headers round-trip" {
    const testing = std.testing;
    const headers_in = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/index.html" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    };

    var buf: [256]u8 = undefined;
    const written = try encodeHeaders(&headers_in, &buf);

    var decoded = DecodedHeaders{ .headers = undefined, .count = 0 };
    try decodeHeaders(buf[0..written], &decoded);

    try testing.expectEqual(@as(usize, 4), decoded.count);
    try testing.expectEqualSlices(u8, ":method", decoded.headers[0].name);
    try testing.expectEqualSlices(u8, "GET", decoded.headers[0].value);
    try testing.expectEqualSlices(u8, ":path", decoded.headers[1].name);
    try testing.expectEqualSlices(u8, "/index.html", decoded.headers[1].value);
    try testing.expectEqualSlices(u8, ":authority", decoded.headers[3].name);
    try testing.expectEqualSlices(u8, "example.com", decoded.headers[3].value);
}

test "qpack: static table has correct entries" {
    try std.testing.expectEqualSlices(u8, ":method", static_table[17].name);
    try std.testing.expectEqualSlices(u8, "GET", static_table[17].value);
    try std.testing.expectEqualSlices(u8, ":status", static_table[25].name);
    try std.testing.expectEqualSlices(u8, "200", static_table[25].value);
}

test "qpack: empty header list" {
    const testing = std.testing;
    var buf: [8]u8 = undefined;
    const written = try encodeHeaders(&.{}, &buf);
    var decoded = DecodedHeaders{ .headers = undefined, .count = 0 };
    try decodeHeaders(buf[0..written], &decoded);
    try testing.expectEqual(@as(usize, 0), decoded.count);
}
