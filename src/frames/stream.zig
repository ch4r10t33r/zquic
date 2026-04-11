//! STREAM frame (RFC 9000 §19.8).
//!
//! Wire format (type 0x08..0x0f):
//!   Type bits: 0x08 | OFF_bit | LEN_bit | FIN_bit
//!   Stream ID (varint)
//!   [Offset (varint) if OFF_bit=1]
//!   [Length (varint) if LEN_bit=1]
//!   Stream Data (Length bytes, or to end of packet if LEN_bit=0)
//!
//! FIN_bit = 1: this frame carries the final byte of the stream.

const std = @import("std");
const varint = @import("../varint.zig");

pub const StreamFrame = struct {
    stream_id: u64,
    offset: u64,
    /// Raw application data.
    data: []const u8,
    /// True if this is the final segment of the stream.
    fin: bool,
    /// True if the Length field is present.
    has_length: bool,

    const OFF_BIT: u64 = 0x04;
    const LEN_BIT: u64 = 0x02;
    const FIN_BIT: u64 = 0x01;

    /// Parse a STREAM frame from `buf` (after the type byte).
    /// `ft` is the full frame type byte value (0x08..0x0f).
    pub fn parse(buf: []const u8, ft: u64) varint.DecodeError!struct { frame: StreamFrame, consumed: usize } {
        var r = varint.Reader.init(buf);
        const sid = try r.readVarint();
        const offset: u64 = if (ft & OFF_BIT != 0) try r.readVarint() else 0;
        const fin = (ft & FIN_BIT) != 0;
        const has_length = (ft & LEN_BIT) != 0;

        const data: []const u8 = if (has_length) blk: {
            const length = try r.readVarint();
            break :blk try r.readBytes(@intCast(length));
        } else blk: {
            // Data extends to the end of the packet payload.
            break :blk r.buf[r.pos..];
        };

        const consumed = if (has_length) r.pos else r.pos + r.remaining();

        return .{
            .frame = .{
                .stream_id = sid,
                .offset = offset,
                .data = data,
                .fin = fin,
                .has_length = has_length,
            },
            .consumed = consumed,
        };
    }

    /// Serialize the STREAM frame into `buf`. Returns bytes written.
    /// Always writes the Length field (LEN_BIT=1).
    pub fn serialize(self: StreamFrame, buf: []u8) (varint.EncodeError || varint.DecodeError)!usize {
        var ft: u64 = 0x08 | LEN_BIT;
        if (self.offset != 0) ft |= OFF_BIT;
        if (self.fin) ft |= FIN_BIT;

        var w = varint.Writer.init(buf);
        try w.writeVarint(ft);
        try w.writeVarint(self.stream_id);
        if (self.offset != 0) try w.writeVarint(self.offset);
        try w.writeVarint(self.data.len);
        try w.writeBytes(self.data);
        return w.pos;
    }
};

test "stream: parse/serialize with offset and fin" {
    const testing = std.testing;
    const frame = StreamFrame{
        .stream_id = 4,
        .offset = 1024,
        .data = "hello world",
        .fin = true,
        .has_length = true,
    };
    var buf: [64]u8 = undefined;
    const written = try frame.serialize(&buf);

    // Determine frame type from first byte
    const r_type = try varint.decode(buf[0..written]);
    const r = try StreamFrame.parse(buf[r_type.len..written], r_type.value);
    try testing.expectEqual(@as(u64, 4), r.frame.stream_id);
    try testing.expectEqual(@as(u64, 1024), r.frame.offset);
    try testing.expectEqualSlices(u8, "hello world", r.frame.data);
    try testing.expect(r.frame.fin);
}

test "stream: offset=0 no fin" {
    const testing = std.testing;
    const frame = StreamFrame{
        .stream_id = 0,
        .offset = 0,
        .data = "data",
        .fin = false,
        .has_length = true,
    };
    var buf: [32]u8 = undefined;
    const written = try frame.serialize(&buf);

    const r_type = try varint.decode(buf[0..written]);
    const r = try StreamFrame.parse(buf[r_type.len..written], r_type.value);
    try testing.expectEqual(@as(u64, 0), r.frame.offset);
    try testing.expect(!r.frame.fin);
    try testing.expectEqualSlices(u8, "data", r.frame.data);
}
