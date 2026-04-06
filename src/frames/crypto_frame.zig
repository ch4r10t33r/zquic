//! CRYPTO frame (RFC 9000 §19.6).
//!
//! Wire format (after type byte 0x06):
//!   Offset (varint)
//!   Length (varint)
//!   Crypto Data (Length bytes)
//!
//! CRYPTO frames carry TLS handshake data. The Offset and Length fields
//! are used to reassemble the handshake stream from potentially
//! out-of-order or fragmented frames.

const std = @import("std");
const varint = @import("../varint.zig");

pub const CryptoFrame = struct {
    /// Byte offset of the start of this CRYPTO data in the handshake stream.
    offset: u64,
    /// The raw TLS handshake bytes.
    data: []const u8,

    /// Parse a CRYPTO frame from `buf` (after the type byte).
    pub fn parse(buf: []const u8) varint.DecodeError!struct { frame: CryptoFrame, consumed: usize } {
        var r = varint.Reader.init(buf);
        const offset = try r.readVarint();
        const length = try r.readVarint();
        const data = try r.readBytes(@intCast(length));
        return .{
            .frame = .{ .offset = offset, .data = data },
            .consumed = r.pos,
        };
    }

    /// Serialize into `buf`. Returns bytes written (includes type byte).
    pub fn serialize(self: CryptoFrame, buf: []u8) (varint.EncodeError || varint.DecodeError)!usize {
        var w = varint.Writer.init(buf);
        try w.writeVarint(0x06);
        try w.writeVarint(self.offset);
        try w.writeVarint(self.data.len);
        try w.writeBytes(self.data);
        return w.pos;
    }
};

test "crypto_frame: parse/serialize round-trip" {
    const testing = std.testing;
    const data = "TLSHandshakeBytes";
    const frame = CryptoFrame{ .offset = 42, .data = data };

    var buf: [64]u8 = undefined;
    const written = try frame.serialize(&buf);

    // Skip type byte
    const r = try CryptoFrame.parse(buf[1..written]);
    try testing.expectEqual(@as(u64, 42), r.frame.offset);
    try testing.expectEqualSlices(u8, data, r.frame.data);
}

test "crypto_frame: offset=0 short data" {
    const testing = std.testing;
    const frame = CryptoFrame{ .offset = 0, .data = "abc" };
    var buf: [16]u8 = undefined;
    const written = try frame.serialize(&buf);

    const r = try CryptoFrame.parse(buf[1..written]);
    try testing.expectEqual(@as(u64, 0), r.frame.offset);
    try testing.expectEqualSlices(u8, "abc", r.frame.data);
}
