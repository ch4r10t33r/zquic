//! QUIC Version Negotiation packet (RFC 9000 §17.2.1).
//!
//! Sent by a server that does not support the QUIC version requested by
//! the client. The packet lists all supported versions.
//!
//! Wire format:
//!   1 byte  : Header form=1, Fixed bit=0, Type=unused (0x80 with random low 7 bits)
//!   4 bytes : Version = 0x00000000 (distinguishes from other Long Header types)
//!   1 byte  : DCID Length
//!   N bytes : DCID (echoed from client Initial)
//!   1 byte  : SCID Length
//!   M bytes : SCID
//!   4*K bytes: Supported Versions list (at least one)

const std = @import("std");

/// QUIC version 1 (RFC 9000).
pub const QUIC_V1: u32 = 0x00000001;

/// QUIC version 2 (RFC 9369).
pub const QUIC_V2: u32 = 0x6b3343cf;

/// Parse error types for Version Negotiation packets.
pub const ParseError = error{
    BufferTooShort,
    NotVersionNegotiation,
    NoSupportedVersions,
};

/// Parsed Version Negotiation packet.
pub const VersionNegotiationPacket = struct {
    dcid: []const u8,
    scid: []const u8,
    /// Slice into the source buffer containing the 4-byte big-endian version words.
    versions_raw: []const u8,

    /// Iterator over supported versions.
    pub fn versions(self: VersionNegotiationPacket) VersionIterator {
        return .{ .raw = self.versions_raw, .pos = 0 };
    }
};

pub const VersionIterator = struct {
    raw: []const u8,
    pos: usize,

    pub fn next(self: *VersionIterator) ?u32 {
        if (self.pos + 4 > self.raw.len) return null;
        const v = std.mem.readInt(u32, self.raw[self.pos..][0..4], .big);
        self.pos += 4;
        return v;
    }
};

/// Parse a Version Negotiation packet from `buf`.
pub fn parse(buf: []const u8) ParseError!VersionNegotiationPacket {
    if (buf.len < 7) return error.BufferTooShort;
    // Must have long header form (bit 7 = 1).
    if (buf[0] & 0x80 == 0) return error.NotVersionNegotiation;
    // Version field must be 0x00000000.
    const ver = std.mem.readInt(u32, buf[1..5], .big);
    if (ver != 0) return error.NotVersionNegotiation;

    var pos: usize = 5;
    if (pos >= buf.len) return error.BufferTooShort;
    const dcid_len = buf[pos];
    pos += 1;
    if (pos + dcid_len > buf.len) return error.BufferTooShort;
    const dcid = buf[pos .. pos + dcid_len];
    pos += dcid_len;

    if (pos >= buf.len) return error.BufferTooShort;
    const scid_len = buf[pos];
    pos += 1;
    if (pos + scid_len > buf.len) return error.BufferTooShort;
    const scid = buf[pos .. pos + scid_len];
    pos += scid_len;

    if (pos + 4 > buf.len) return error.NoSupportedVersions;
    // The remainder must be a multiple of 4.
    const remaining = buf.len - pos;
    const version_bytes = buf[pos .. pos + (remaining - remaining % 4)];
    if (version_bytes.len == 0) return error.NoSupportedVersions;

    return .{
        .dcid = dcid,
        .scid = scid,
        .versions_raw = version_bytes,
    };
}

/// Build a Version Negotiation packet into `buf`.
///
/// `dcid` and `scid` are echoed from the client's Initial packet (dcid becomes
/// the server's scid and vice versa per RFC convention, but callers control this).
/// `supported_versions` must be non-empty.
/// Returns the number of bytes written.
pub fn build(
    buf: []u8,
    dcid: []const u8,
    scid: []const u8,
    supported_versions: []const u32,
) error{BufferTooSmall}!usize {
    const needed = 1 + 4 + 1 + dcid.len + 1 + scid.len + 4 * supported_versions.len;
    if (buf.len < needed) return error.BufferTooSmall;

    var pos: usize = 0;
    // Long header form with Fixed bit=0, random low 7 bits = 0.
    buf[pos] = 0x80;
    pos += 1;
    // Version = 0 signals Version Negotiation.
    std.mem.writeInt(u32, buf[pos..][0..4], 0, .big);
    pos += 4;
    buf[pos] = @intCast(dcid.len);
    pos += 1;
    @memcpy(buf[pos .. pos + dcid.len], dcid);
    pos += dcid.len;
    buf[pos] = @intCast(scid.len);
    pos += 1;
    @memcpy(buf[pos .. pos + scid.len], scid);
    pos += scid.len;
    for (supported_versions) |v| {
        std.mem.writeInt(u32, buf[pos..][0..4], v, .big);
        pos += 4;
    }
    return pos;
}

test "version negotiation: build and parse round-trip" {
    const testing = std.testing;
    const dcid = "\xaa\xbb\xcc\xdd";
    const scid = "\x11\x22";
    const versions_to_send = [_]u32{ QUIC_V1, 0xdeadbeef };

    var buf: [64]u8 = undefined;
    const written = try build(&buf, dcid, scid, &versions_to_send);

    const pkt = try parse(buf[0..written]);
    try testing.expectEqualSlices(u8, dcid, pkt.dcid);
    try testing.expectEqualSlices(u8, scid, pkt.scid);

    var it = pkt.versions();
    try testing.expectEqual(@as(u32, QUIC_V1), it.next().?);
    try testing.expectEqual(@as(u32, 0xdeadbeef), it.next().?);
    try testing.expectEqual(@as(?u32, null), it.next());
}

test "version negotiation: parse rejects QUIC v1 packet" {
    // A normal Long Header packet has version != 0, so parse should reject it.
    var buf: [16]u8 = .{0} ** 16;
    buf[0] = 0xc0; // long header form, Fixed bit=1
    std.mem.writeInt(u32, buf[1..5], QUIC_V1, .big);
    const err = parse(&buf);
    try std.testing.expectError(error.NotVersionNegotiation, err);
}
