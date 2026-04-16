//! Variable-length integer encoding per RFC 9000 §16.
//!
//! The 2 most-significant bits of the first byte encode the total byte length:
//!   00 → 1 byte  (6-bit value, max 63)
//!   01 → 2 bytes (14-bit value, max 16383)
//!   10 → 4 bytes (30-bit value, max 1073741823)
//!   11 → 8 bytes (62-bit value, max 4611686018427387903)

const std = @import("std");

pub const max_value: u64 = (1 << 62) - 1;

pub const EncodeError = error{ValueTooLarge};
pub const DecodeError = error{ BufferTooShort, VarintLengthTooLarge, NonMinimalEncoding };

/// Cast a varint-decoded length to `usize` without silent truncation on small usize targets.
pub fn lenToUsize(len: u64) DecodeError!usize {
    if (len > std.math.maxInt(usize)) return error.VarintLengthTooLarge;
    return @intCast(len);
}

/// Returns the number of bytes needed to encode `v`.
pub fn encodedLen(v: u64) u4 {
    if (v < (1 << 6)) return 1;
    if (v < (1 << 14)) return 2;
    if (v < (1 << 30)) return 4;
    return 8;
}

/// Encode `v` into `buf`. Returns the slice written.
/// Returns error.ValueTooLarge if v >= 2^62.
/// Returns error.BufferTooShort if buf is not large enough.
pub fn encode(buf: []u8, v: u64) (EncodeError || DecodeError)![]u8 {
    if (v > max_value) return error.ValueTooLarge;
    const len = encodedLen(v);
    if (buf.len < len) return error.BufferTooShort;
    switch (len) {
        1 => {
            buf[0] = @intCast(v);
            return buf[0..1];
        },
        2 => {
            const w: u16 = @intCast(v | (@as(u64, 0b01) << 14));
            std.mem.writeInt(u16, buf[0..2], w, .big);
            return buf[0..2];
        },
        4 => {
            const w: u32 = @intCast(v | (@as(u64, 0b10) << 30));
            std.mem.writeInt(u32, buf[0..4], w, .big);
            return buf[0..4];
        },
        else => {
            const w: u64 = v | (@as(u64, 0b11) << 62);
            std.mem.writeInt(u64, buf[0..8], w, .big);
            return buf[0..8];
        },
    }
}

/// Decode a variable-length integer from `buf`.
/// Returns the decoded value and the number of bytes consumed.
///
/// RFC 9000 §16 requires the shortest encoding ("MUST use"); this
/// decoder rejects non-minimal encodings with error.NonMinimalEncoding.
pub fn decode(buf: []const u8) DecodeError!struct { value: u64, len: u4 } {
    if (buf.len == 0) return error.BufferTooShort;
    const prefix: u2 = @intCast(buf[0] >> 6);
    switch (prefix) {
        0b00 => {
            return .{ .value = buf[0] & 0x3f, .len = 1 };
        },
        0b01 => {
            if (buf.len < 2) return error.BufferTooShort;
            const w = std.mem.readInt(u16, buf[0..2], .big);
            const v: u64 = w & 0x3fff;
            // Values < 64 must be encoded in 1 byte.
            if (v < (1 << 6)) return error.NonMinimalEncoding;
            return .{ .value = v, .len = 2 };
        },
        0b10 => {
            if (buf.len < 4) return error.BufferTooShort;
            const w = std.mem.readInt(u32, buf[0..4], .big);
            const v: u64 = w & 0x3fffffff;
            // Values < 16384 must be encoded in 1 or 2 bytes.
            if (v < (1 << 14)) return error.NonMinimalEncoding;
            return .{ .value = v, .len = 4 };
        },
        0b11 => {
            if (buf.len < 8) return error.BufferTooShort;
            const w = std.mem.readInt(u64, buf[0..8], .big);
            const v: u64 = w & 0x3fffffffffffffff;
            // Values < 2^30 must be encoded in 1, 2, or 4 bytes.
            if (v < (1 << 30)) return error.NonMinimalEncoding;
            return .{ .value = v, .len = 8 };
        },
    }
}

/// A reader wrapper that decodes variable-length integers from a stream.
pub const Reader = struct {
    buf: []const u8,
    pos: usize,

    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf, .pos = 0 };
    }

    pub fn readVarint(self: *Reader) DecodeError!u64 {
        const result = try decode(self.buf[self.pos..]);
        self.pos += @as(usize, result.len);
        return result.value;
    }

    pub fn readBytes(self: *Reader, n: usize) DecodeError![]const u8 {
        if (self.pos + n > self.buf.len) return error.BufferTooShort;
        const slice = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return slice;
    }

    pub fn readInt(self: *Reader, comptime T: type) DecodeError!T {
        const size = @sizeOf(T);
        const bytes = try self.readBytes(size);
        return std.mem.readInt(T, bytes[0..size], .big);
    }

    pub fn remaining(self: *const Reader) usize {
        return self.buf.len - self.pos;
    }
};

/// A writer wrapper that encodes variable-length integers into a buffer.
pub const Writer = struct {
    buf: []u8,
    pos: usize,

    pub fn init(buf: []u8) Writer {
        return .{ .buf = buf, .pos = 0 };
    }

    pub fn writeVarint(self: *Writer, v: u64) (EncodeError || DecodeError)!void {
        const enc = try encode(self.buf[self.pos..], v);
        self.pos += enc.len;
    }

    pub fn writeBytes(self: *Writer, bytes: []const u8) DecodeError!void {
        if (self.pos + bytes.len > self.buf.len) return error.BufferTooShort;
        @memcpy(self.buf[self.pos .. self.pos + bytes.len], bytes);
        self.pos += bytes.len;
    }

    pub fn writeInt(self: *Writer, comptime T: type, v: T) DecodeError!void {
        const size = @sizeOf(T);
        if (self.pos + size > self.buf.len) return error.BufferTooShort;
        std.mem.writeInt(T, self.buf[self.pos..][0..size], v, .big);
        self.pos += size;
    }

    pub fn written(self: *const Writer) []const u8 {
        return self.buf[0..self.pos];
    }
};

test "varint: encode and decode round-trip" {
    const testing = std.testing;
    const cases = [_]u64{ 0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, max_value };
    var buf: [8]u8 = undefined;

    for (cases) |v| {
        const encoded = try encode(&buf, v);
        const decoded = try decode(encoded);
        try testing.expectEqual(v, decoded.value);
        try testing.expectEqual(@as(u4, encodedLen(v)), decoded.len);
    }
}

test "varint: 1-byte boundary" {
    const testing = std.testing;
    var buf: [1]u8 = undefined;
    _ = try encode(&buf, 0);
    try testing.expectEqual(@as(u8, 0x00), buf[0]);
    _ = try encode(&buf, 63);
    try testing.expectEqual(@as(u8, 0x3f), buf[0]);
}

test "varint: 2-byte boundary" {
    const testing = std.testing;
    var buf: [2]u8 = undefined;
    _ = try encode(&buf, 64);
    const d = try decode(&buf);
    try testing.expectEqual(@as(u64, 64), d.value);
    try testing.expectEqual(@as(u4, 2), d.len);
}

test "varint: RFC 9000 example — 37" {
    // RFC 9000 Appendix A.1: value 37 encodes to 0x25 (1 byte)
    const testing = std.testing;
    var buf: [1]u8 = undefined;
    _ = try encode(&buf, 37);
    try testing.expectEqual(@as(u8, 0x25), buf[0]);
}

test "varint: error on oversized value" {
    var buf: [8]u8 = undefined;
    try std.testing.expectError(error.ValueTooLarge, encode(&buf, max_value + 1));
}

test "varint: reject non-minimal 2-byte encoding of value < 64" {
    // 0x4001 = 2-byte form encoding value 1; must be rejected.
    const buf = [_]u8{ 0x40, 0x01 };
    try std.testing.expectError(error.NonMinimalEncoding, decode(&buf));
}

test "varint: reject non-minimal 4-byte encoding of value < 16384" {
    // 0x80000001 = 4-byte form encoding value 1; must be rejected.
    const buf = [_]u8{ 0x80, 0x00, 0x00, 0x01 };
    try std.testing.expectError(error.NonMinimalEncoding, decode(&buf));

    // 0x80003fff = 4-byte form encoding 16383 (max of 2-byte form); must be rejected.
    const buf2 = [_]u8{ 0x80, 0x00, 0x3f, 0xff };
    try std.testing.expectError(error.NonMinimalEncoding, decode(&buf2));
}

test "varint: reject non-minimal 8-byte encoding of value < 2^30" {
    // 0xc000000000000001 = 8-byte form encoding value 1; must be rejected.
    const buf = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    try std.testing.expectError(error.NonMinimalEncoding, decode(&buf));
}

test "varint: accept minimum-valid larger encodings" {
    // 0x4040 = 2-byte form encoding 64 (smallest value requiring 2 bytes); OK.
    const b2 = [_]u8{ 0x40, 0x40 };
    const d2 = try decode(&b2);
    try std.testing.expectEqual(@as(u64, 64), d2.value);
    try std.testing.expectEqual(@as(u4, 2), d2.len);

    // 0x80004000 = 4-byte form encoding 16384 (smallest value requiring 4 bytes); OK.
    const b4 = [_]u8{ 0x80, 0x00, 0x40, 0x00 };
    const d4 = try decode(&b4);
    try std.testing.expectEqual(@as(u64, 16384), d4.value);
    try std.testing.expectEqual(@as(u4, 4), d4.len);

    // 0xc000000040000000 = 8-byte form encoding 2^30 (smallest value requiring 8 bytes); OK.
    const b8 = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00 };
    const d8 = try decode(&b8);
    try std.testing.expectEqual(@as(u64, 1 << 30), d8.value);
    try std.testing.expectEqual(@as(u4, 8), d8.len);
}
