//! QUIC packet header parsing and serialization (RFC 9000 §17).
//!
//! Long header format (RFC 9000 §17.2):
//!   +-+-+-+-+-+-+-+-+
//!   |1|1|T T|X X X X|   first byte: Header Form=1, Fixed Bit=1, Type, flags
//!   +-+-+-+-+-+-+-+-+
//!   |    Version (32 bits)          |
//!   |    DCIL (8) | DCID (0–160)   |
//!   |    SCIL (8) | SCID (0–160)   |
//!   | ...type-specific fields...   |
//!
//! Short header format (RFC 9000 §17.3):
//!   +-+-+-+-+-+-+-+-+
//!   |0|1|S|R R|K|P P|   first byte: Header Form=0, Fixed Bit=1, Spin, …
//!   +-+-+-+-+-+-+-+-+
//!   |    DCID (connection-specific length)                              |
//!   |    Packet Number (1–4 bytes, protected)                          |

const std = @import("std");
const types = @import("../types.zig");
const varint = @import("../varint.zig");

pub const ConnectionId = types.ConnectionId;
pub const Version = types.Version;

pub const ParseError = error{
    BufferTooShort,
    InvalidFixedBit,
    InvalidCidLength,
    UnsupportedVersion,
    TooLong,
};

/// The two possible header forms.
pub const HeaderForm = enum { long, short };

/// Long packet types (encoded in bits 4–5 of the first byte for QUIC v1).
pub const LongType = enum(u2) {
    initial = 0,
    zero_rtt = 1,
    handshake = 2,
    retry = 3,
};

/// Parsed long header common fields (before type-specific fields).
pub const LongHeader = struct {
    packet_type: LongType,
    version: u32,
    dcid: ConnectionId,
    scid: ConnectionId,
    /// Raw first byte (contains type-specific flag bits).
    first_byte: u8,
};

/// Parsed short (1-RTT) header common fields.
pub const ShortHeader = struct {
    spin_bit: bool,
    key_phase: bool,
    /// Number of packet number bytes on the wire (after header protection removal).
    pn_len: u2,
    dcid: ConnectionId,
    /// Raw first byte.
    first_byte: u8,
};

/// Parse a long header from `buf`, advancing the reader.
/// The caller is responsible for providing the correct DCID length for short headers.
pub fn parseLong(buf: []const u8) ParseError!struct { header: LongHeader, consumed: usize } {
    if (buf.len < 7) return error.BufferTooShort;

    const first = buf[0];
    // Bit 7 must be 1 (long header), bit 6 must be 1 (fixed bit).
    if (first & 0x80 == 0) return error.InvalidFixedBit; // should be long
    if (first & 0x40 == 0) return error.InvalidFixedBit; // fixed bit

    const pkt_type: LongType = @enumFromInt((first >> 4) & 0x03);
    const version = std.mem.readInt(u32, buf[1..5], .big);

    var pos: usize = 5;

    // DCID
    const dcid_len = buf[pos];
    pos += 1;
    if (dcid_len > types.max_cid_len) return error.InvalidCidLength;
    if (pos + dcid_len > buf.len) return error.BufferTooShort;
    const dcid = try ConnectionId.fromSlice(buf[pos .. pos + dcid_len]);
    pos += dcid_len;

    // SCID
    if (pos >= buf.len) return error.BufferTooShort;
    const scid_len = buf[pos];
    pos += 1;
    if (scid_len > types.max_cid_len) return error.InvalidCidLength;
    if (pos + scid_len > buf.len) return error.BufferTooShort;
    const scid = try ConnectionId.fromSlice(buf[pos .. pos + scid_len]);
    pos += scid_len;

    return .{
        .header = .{
            .packet_type = pkt_type,
            .version = version,
            .dcid = dcid,
            .scid = scid,
            .first_byte = first,
        },
        .consumed = pos,
    };
}

/// Parse a short (1-RTT) header from `buf`.
/// `dcid_len` must be known out-of-band (connection-specific).
pub fn parseShort(buf: []const u8, dcid_len: usize) ParseError!struct { header: ShortHeader, consumed: usize } {
    if (buf.len < 1 + dcid_len) return error.BufferTooShort;

    const first = buf[0];
    // Bit 7 must be 0 (short header), bit 6 must be 1 (fixed bit).
    if (first & 0x80 != 0) return error.InvalidFixedBit; // should be short
    if (first & 0x40 == 0) return error.InvalidFixedBit; // fixed bit

    const spin = (first & 0x20) != 0;
    const key_phase = (first & 0x04) != 0;
    const pn_len: u2 = @intCast(first & 0x03);

    var pos: usize = 1;
    if (dcid_len > types.max_cid_len) return error.InvalidCidLength;
    const dcid = try ConnectionId.fromSlice(buf[pos .. pos + dcid_len]);
    pos += dcid_len;

    return .{
        .header = .{
            .spin_bit = spin,
            .key_phase = key_phase,
            .pn_len = pn_len,
            .dcid = dcid,
            .first_byte = first,
        },
        .consumed = pos,
    };
}

/// Write a long header into `buf`. Returns the number of bytes written.
pub fn writeLong(
    buf: []u8,
    pkt_type: LongType,
    version: u32,
    dcid: ConnectionId,
    scid: ConnectionId,
    flags: u4,
) error{BufferTooShort}!usize {
    const needed = 1 + 4 + 1 + dcid.len + 1 + scid.len;
    if (buf.len < needed) return error.BufferTooShort;

    var pos: usize = 0;
    // Header Form=1, Fixed Bit=1, Type (2 bits), flags (4 bits)
    buf[pos] = 0xc0 | (@as(u8, @intFromEnum(pkt_type)) << 4) | flags;
    pos += 1;
    std.mem.writeInt(u32, buf[pos..][0..4], version, .big);
    pos += 4;
    buf[pos] = dcid.len;
    pos += 1;
    @memcpy(buf[pos .. pos + dcid.len], dcid.slice());
    pos += dcid.len;
    buf[pos] = scid.len;
    pos += 1;
    @memcpy(buf[pos .. pos + scid.len], scid.slice());
    pos += scid.len;
    return pos;
}

/// Write a short header into `buf`. Returns bytes written.
pub fn writeShort(
    buf: []u8,
    dcid: ConnectionId,
    spin: bool,
    key_phase: bool,
    pn_len: u2,
) error{BufferTooShort}!usize {
    const needed = 1 + dcid.len;
    if (buf.len < needed) return error.BufferTooShort;

    var first: u8 = 0x40; // Fixed Bit = 1, Header Form = 0
    if (spin) first |= 0x20;
    if (key_phase) first |= 0x04;
    first |= pn_len;

    buf[0] = first;
    @memcpy(buf[1 .. 1 + dcid.len], dcid.slice());
    return 1 + dcid.len;
}

test "header: long header round-trip" {
    const testing = std.testing;

    const dcid = try ConnectionId.fromSlice(&[_]u8{ 0xde, 0xad });
    const scid = try ConnectionId.fromSlice(&[_]u8{ 0xbe, 0xef, 0x00 });

    var buf: [64]u8 = undefined;
    const written = try writeLong(&buf, .initial, 0x00000001, dcid, scid, 0x03);

    const parsed = try parseLong(buf[0..written]);
    try testing.expectEqual(LongType.initial, parsed.header.packet_type);
    try testing.expectEqual(@as(u32, 0x00000001), parsed.header.version);
    try testing.expect(ConnectionId.eql(dcid, parsed.header.dcid));
    try testing.expect(ConnectionId.eql(scid, parsed.header.scid));
    try testing.expectEqual(written, parsed.consumed);
}

test "header: short header round-trip" {
    const testing = std.testing;

    const dcid = try ConnectionId.fromSlice(&[_]u8{ 0x01, 0x02, 0x03, 0x04 });
    var buf: [32]u8 = undefined;
    const written = try writeShort(&buf, dcid, false, true, 2);

    const parsed = try parseShort(buf[0..written], dcid.len);
    try testing.expectEqual(false, parsed.header.spin_bit);
    try testing.expectEqual(true, parsed.header.key_phase);
    try testing.expectEqual(@as(u2, 2), parsed.header.pn_len);
    try testing.expect(ConnectionId.eql(dcid, parsed.header.dcid));
}

test "header: fixed bit validation" {
    var buf = [_]u8{0x00} ** 20;
    // Long header with fixed bit cleared — should fail
    buf[0] = 0x80; // Header Form=1, Fixed Bit=0
    try std.testing.expectError(error.InvalidFixedBit, parseLong(&buf));

    // Short header with fixed bit cleared — should fail
    buf[0] = 0x00; // Header Form=0, Fixed Bit=0
    try std.testing.expectError(error.InvalidFixedBit, parseShort(&buf, 4));
}
