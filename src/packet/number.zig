//! Packet number encoding and decoding (RFC 9000 §17.1, §A.3).
//!
//! Packet numbers are encoded in 1–4 bytes on the wire. The sender truncates
//! the full 62-bit packet number to the smallest representation that the
//! receiver can unambiguously decode given its current receive window.
//! The receiver reconstructs the full number via the algorithm in §A.3.

const std = @import("std");

/// Encoded byte length of a packet number (1..4).
pub const EncodedLen = enum(u2) {
    one = 0,
    two = 1,
    three = 2,
    four = 3,

    pub fn bytes(self: EncodedLen) u3 {
        return @as(u3, @intFromEnum(self)) + 1;
    }
};

/// Choose the smallest packet number encoding that covers the in-flight window.
/// `pn` is the packet number to send; `largest_acked` is the largest packet
/// number acknowledged by the peer (or null if none).
pub fn encodeLen(pn: u64, largest_acked: ?u64) EncodedLen {
    // The window the receiver needs to cover is twice the in-flight window.
    const window: u64 = if (largest_acked) |la|
        2 * (pn - la)
    else
        2 * pn + 1;

    if (window < (1 << 8)) return .one;
    if (window < (1 << 16)) return .two;
    if (window < (1 << 24)) return .three;
    return .four;
}

/// Encode `pn` into `buf` using `len` bytes (big-endian, truncated).
pub fn encode(buf: []u8, pn: u64, len: EncodedLen) void {
    const n = len.bytes();
    var i: usize = 0;
    while (i < n) : (i += 1) {
        buf[n - 1 - i] = @truncate(pn >> @intCast(i * 8));
    }
}

/// Decode a packet number from `buf` (big-endian) given the largest
/// successfully processed packet number `largest_pn` (RFC 9000 §A.3).
pub fn decode(buf: []const u8, largest_pn: u64) u64 {
    const n = buf.len;
    var truncated: u64 = 0;
    for (buf) |b| {
        truncated = (truncated << 8) | b;
    }

    const pn_nbits: u6 = @intCast(n * 8);
    const pn_win: u64 = @as(u64, 1) << pn_nbits;
    const pn_hwin: u64 = pn_win >> 1;
    const pn_mask: u64 = pn_win - 1;

    // The expected next packet number is one beyond the largest we processed.
    const expected_pn: u64 = largest_pn + 1;
    // Start with the candidate that has the same high bits as expected_pn.
    var candidate_pn = (expected_pn & ~pn_mask) | truncated;

    // Adjust by pn_win in either direction to find the closest value.
    if (candidate_pn + pn_hwin <= expected_pn and candidate_pn < (std.math.maxInt(u64) - pn_win)) {
        candidate_pn += pn_win;
    } else if (candidate_pn > expected_pn + pn_hwin and candidate_pn >= pn_win) {
        candidate_pn -= pn_win;
    }

    return candidate_pn;
}

test "packet number: encode/decode round-trip" {
    const testing = std.testing;

    var buf: [4]u8 = undefined;

    // Simple case: first packet
    encode(&buf, 0, .one);
    try testing.expectEqual(@as(u64, 0), decode(buf[0..1], 0));

    encode(&buf, 1, .one);
    try testing.expectEqual(@as(u64, 1), decode(buf[0..1], 0));

    // 2-byte encoding
    encode(&buf, 256, .two);
    try testing.expectEqual(@as(u64, 256), decode(buf[0..2], 0));

    // 4-byte encoding
    encode(&buf, 0x1234_5678, .four);
    try testing.expectEqual(@as(u64, 0x1234_5678), decode(buf[0..4], 0));
}

test "packet number: decode wraps correctly" {
    const testing = std.testing;
    // RFC 9000 §A.3 example: largest_pn = 0xa82f30ea, truncated = 0x9b32 (2 bytes)
    // expected candidate: 0xa82f9b32
    var buf = [_]u8{ 0x9b, 0x32 };
    const result = decode(&buf, 0xa82f30ea);
    try testing.expectEqual(@as(u64, 0xa82f9b32), result);
}
