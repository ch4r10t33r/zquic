//! QUIC-TLS adapter (RFC 9001).
//!
//! QUIC replaces the TLS record layer with its own packet protection. TLS
//! handshake messages are carried in QUIC CRYPTO frames without TLS record
//! headers. This module adapts tls.zig's NonBlock API — which expects TLS
//! records with 5-byte headers — to the raw-bytes interface that QUIC needs.
//!
//! Wrapping model:
//!   CRYPTO frame bytes (raw TLS handshake) → add 5-byte TLS record header
//!                                          → feed to tls.zig NonBlock.run()
//!   tls.zig NonBlock.run() output          → strip 5-byte TLS record headers
//!                                          → place in CRYPTO frames
//!
//! Key levels:
//!   After the Initial flight, tls.zig derives Handshake keys internally.
//!   After the Handshake flight, it derives the 1-RTT (Application) keys.
//!   The connection layer extracts these keys via `handshakeKeys()` /
//!   `appKeys()` to switch encryption levels.

const std = @import("std");
const keys = @import("keys.zig");

/// Maximum bytes we buffer for a single crypto level's send queue.
pub const send_buf_len = 4096;
/// Maximum bytes we buffer for a single crypto level's recv queue.
pub const recv_buf_len = 4096;

/// TLS content-type for Handshake messages (RFC 8446 §5.1)
const TLS_CONTENT_HANDSHAKE: u8 = 0x16;
/// TLS 1.2 legacy version used in record headers
const TLS_LEGACY_VERSION: u16 = 0x0303;

/// A simple FIFO byte buffer.
pub const ByteBuffer = struct {
    buf: [recv_buf_len]u8 = undefined,
    start: usize = 0,
    end: usize = 0,

    pub fn write(self: *ByteBuffer, data: []const u8) error{Full}!void {
        if (self.end + data.len > self.buf.len) return error.Full;
        @memcpy(self.buf[self.end .. self.end + data.len], data);
        self.end += data.len;
    }

    pub fn read(self: *ByteBuffer, out: []u8) usize {
        const available = self.end - self.start;
        const n = @min(available, out.len);
        @memcpy(out[0..n], self.buf[self.start .. self.start + n]);
        self.start += n;
        if (self.start == self.end) {
            self.start = 0;
            self.end = 0;
        }
        return n;
    }

    pub fn readableSlice(self: *const ByteBuffer) []const u8 {
        return self.buf[self.start..self.end];
    }

    pub fn consume(self: *ByteBuffer, n: usize) void {
        self.start += n;
        if (self.start >= self.end) {
            self.start = 0;
            self.end = 0;
        }
    }

    pub fn len(self: *const ByteBuffer) usize {
        return self.end - self.start;
    }

    pub fn isEmpty(self: *const ByteBuffer) bool {
        return self.start == self.end;
    }
};

/// Wrap raw TLS handshake bytes in a TLS record header (content-type=Handshake).
/// `out` must have at least `data.len + 5` bytes.
pub fn wrapRecord(out: []u8, data: []const u8) usize {
    if (data.len == 0) return 0;
    out[0] = TLS_CONTENT_HANDSHAKE;
    std.mem.writeInt(u16, out[1..3], TLS_LEGACY_VERSION, .big);
    std.mem.writeInt(u16, out[3..5], @intCast(data.len), .big);
    @memcpy(out[5 .. 5 + data.len], data);
    return 5 + data.len;
}

/// Strip TLS record headers from `input` and collect raw handshake bytes into `out`.
/// Returns bytes written to `out`.
pub fn stripRecords(out: []u8, input: []const u8) usize {
    var pos: usize = 0;
    var out_pos: usize = 0;
    while (pos + 5 <= input.len) {
        // Skip content type (1) and legacy version (2)
        pos += 3;
        const length = std.mem.readInt(u16, input[pos..][0..2], .big);
        pos += 2;
        if (pos + length > input.len) break;
        if (out_pos + length <= out.len) {
            @memcpy(out[out_pos .. out_pos + length], input[pos .. pos + length]);
            out_pos += length;
        }
        pos += length;
    }
    return out_pos;
}

/// QUIC transport parameters extension type (RFC 9001 §8.2)
pub const TRANSPORT_PARAMS_EXT_TYPE: u16 = 0xffa5;

/// Build a minimal QUIC transport parameters extension for the client.
/// Returns bytes written to `out`.
pub fn buildClientTransportParams(out: []u8) usize {
    // Transport parameters (also used in Encrypted Extensions for the server role).
    // Flow-control limits must cover interop "transfer" (multi-megabyte files on
    // several client-initiated bidirectional streams at once).
    var pos: usize = 0;

    const write_param = struct {
        fn call(buf: []u8, p: usize, id: u64, val: u64) usize {
            var w_pos = p;
            // ID varint
            var id_buf: [8]u8 = undefined;
            const id_enc = encodeVarintLocal(&id_buf, id);
            @memcpy(buf[w_pos .. w_pos + id_enc.len], id_enc);
            w_pos += id_enc.len;
            // Value varint (in a varint-length field)
            var val_buf: [8]u8 = undefined;
            const val_enc = encodeVarintLocal(&val_buf, val);
            var len_buf: [8]u8 = undefined;
            const len_enc = encodeVarintLocal(&len_buf, val_enc.len);
            @memcpy(buf[w_pos .. w_pos + len_enc.len], len_enc);
            w_pos += len_enc.len;
            @memcpy(buf[w_pos .. w_pos + val_enc.len], val_enc);
            w_pos += val_enc.len;
            return w_pos;
        }
    }.call;

    pos = write_param(out, pos, 0x01, 30_000); // max_idle_timeout
    pos = write_param(out, pos, 0x04, 67_108_864); // initial_max_data (64 MiB)
    pos = write_param(out, pos, 0x05, 16_777_216); // initial_max_stream_data_bidi_local (16 MiB)
    pos = write_param(out, pos, 0x06, 16_777_216); // initial_max_stream_data_bidi_remote (16 MiB)
    pos = write_param(out, pos, 0x07, 16_777_216); // initial_max_stream_data_uni (16 MiB)
    pos = write_param(out, pos, 0x08, 100); // initial_max_streams_bidi
    pos = write_param(out, pos, 0x09, 100); // initial_max_streams_uni
    return pos;
}

fn encodeVarintLocal(buf: []u8, v: u64) []const u8 {
    if (v < 64) {
        buf[0] = @intCast(v);
        return buf[0..1];
    } else if (v < 16384) {
        const w: u16 = @intCast(v | (0b01 << 14));
        std.mem.writeInt(u16, buf[0..2], w, .big);
        return buf[0..2];
    } else if (v < 1073741824) {
        const w: u32 = @intCast(v | (@as(u64, 0b10) << 30));
        std.mem.writeInt(u32, buf[0..4], w, .big);
        return buf[0..4];
    } else {
        const w: u64 = v | (@as(u64, 0b11) << 62);
        std.mem.writeInt(u64, buf[0..8], w, .big);
        return buf[0..8];
    }
}

/// Tracks CRYPTO stream offsets per encryption level for reassembly.
pub const CryptoStream = struct {
    /// Bytes received so far (next expected offset)
    recv_offset: u64 = 0,
    /// Bytes sent so far (next send offset)
    send_offset: u64 = 0,
    /// Pending received bytes (may arrive out of order)
    recv_buf: ByteBuffer = .{},
    /// Bytes ready to send
    send_buf: ByteBuffer = .{},

    /// Feed received CRYPTO frame data into the stream.
    pub fn feedRecv(self: *CryptoStream, offset: u64, data: []const u8) error{Full}!void {
        // Simple in-order reassembly — accept only contiguous data
        if (offset == self.recv_offset) {
            try self.recv_buf.write(data);
            self.recv_offset += data.len;
        }
        // Out-of-order data is dropped for now (TODO: proper reorder buffer)
    }

    /// Enqueue bytes to send as CRYPTO frames.
    pub fn enqueueSend(self: *CryptoStream, data: []const u8) error{Full}!void {
        try self.send_buf.write(data);
    }

    /// Take up to `max` bytes from the send queue.
    /// Returns the offset at which these bytes should appear and the data.
    pub fn takeSend(self: *CryptoStream, buf: []u8) struct { offset: u64, len: usize } {
        const n = self.send_buf.read(buf);
        const offset = self.send_offset;
        self.send_offset += n;
        return .{ .offset = offset, .len = n };
    }
};

test "byte_buffer: write and read" {
    const testing = std.testing;
    var bb = ByteBuffer{};
    try bb.write("hello");
    try bb.write(" world");

    var out: [64]u8 = undefined;
    const n = bb.read(&out);
    try testing.expectEqualSlices(u8, "hello world", out[0..n]);
    try testing.expect(bb.isEmpty());
}

test "wrap_strip: record round-trip" {
    const testing = std.testing;
    const data = "TLSHandshake";

    var wrapped: [64]u8 = undefined;
    const w_len = wrapRecord(&wrapped, data);
    try testing.expectEqual(@as(usize, data.len + 5), w_len);
    try testing.expectEqual(@as(u8, TLS_CONTENT_HANDSHAKE), wrapped[0]);

    var stripped: [64]u8 = undefined;
    const s_len = stripRecords(&stripped, wrapped[0..w_len]);
    try testing.expectEqualSlices(u8, data, stripped[0..s_len]);
}

test "transport_params: builds non-empty" {
    var buf: [256]u8 = undefined;
    const n = buildClientTransportParams(&buf);
    try std.testing.expect(n > 0);
}

test "crypto_stream: in-order feed" {
    const testing = std.testing;
    var cs = CryptoStream{};
    try cs.feedRecv(0, "abc");
    try cs.feedRecv(3, "def");
    try testing.expectEqual(@as(u64, 6), cs.recv_offset);
    try testing.expectEqual(@as(usize, 6), cs.recv_buf.len());
}
