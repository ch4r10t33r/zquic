//! QUIC Retry packet integrity verification (RFC 9001 §5.8).
//!
//! The Retry Integrity Tag is an AES-128-GCM tag computed over a
//! "Retry Pseudo-Packet" to prevent off-path attackers from injecting
//! spoofed Retry packets.
//!
//! Retry Integrity Tag:
//!   key  = 0xbe0c690b9f66575a1d766b54e368c84e
//!   nonce = 0x461599d35d632bf2239825bb
//!   Tag = AES-128-GCM(key, nonce, "", retry_pseudo_packet)
//!
//! where the "Retry Pseudo-Packet" is:
//!   ODCID Length (1 byte) + ODCID + Retry packet (without integrity tag)

const std = @import("std");
const aead_mod = @import("../crypto/aead.zig");

/// AES-128-GCM key for Retry integrity tag (RFC 9001 §5.8).
pub const retry_key: [16]u8 = .{
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
};

/// AEAD nonce for Retry integrity tag (RFC 9001 §5.8).
pub const retry_nonce: [12]u8 = .{
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
    0x23, 0x98, 0x25, 0xbb,
};

/// Compute the 16-byte Retry Integrity Tag.
///
/// `odcid` is the Original Destination Connection ID from the Initial packet
/// that triggered the Retry. `retry_packet` is the full Retry packet bytes
/// WITHOUT the 16-byte integrity tag at the end.
pub fn computeIntegrityTag(
    tag: *[16]u8,
    odcid: []const u8,
    retry_packet: []const u8,
) aead_mod.AeadError!void {
    // Build the pseudo-packet: ODCID Length (1 byte) + ODCID + Retry packet
    var pseudo: [512]u8 = undefined;
    if (1 + odcid.len + retry_packet.len > pseudo.len) return error.BufferTooSmall;
    pseudo[0] = @intCast(odcid.len);
    @memcpy(pseudo[1 .. 1 + odcid.len], odcid);
    @memcpy(pseudo[1 + odcid.len .. 1 + odcid.len + retry_packet.len], retry_packet);
    const pseudo_len = 1 + odcid.len + retry_packet.len;

    // AES-128-GCM encrypt empty plaintext → produces only the tag
    var ciphertext: [16]u8 = undefined;
    try aead_mod.encryptAes128Gcm(&ciphertext, &.{}, pseudo[0..pseudo_len], retry_key, retry_nonce);
    @memcpy(tag, ciphertext[0..16]);
}

/// Verify the integrity tag of a received Retry packet.
///
/// Returns true if the tag is valid.
pub fn verifyIntegrityTag(
    odcid: []const u8,
    retry_packet_with_tag: []const u8,
) bool {
    if (retry_packet_with_tag.len < 16) return false;
    const retry_without_tag = retry_packet_with_tag[0 .. retry_packet_with_tag.len - 16];
    const received_tag = retry_packet_with_tag[retry_packet_with_tag.len - 16 ..][0..16];

    var computed: [16]u8 = undefined;
    computeIntegrityTag(&computed, odcid, retry_without_tag) catch return false;
    return std.mem.eql(u8, &computed, received_tag);
}

/// Build a complete Retry packet (including integrity tag) into `buf`.
/// Returns bytes written.
pub fn buildRetryPacket(
    buf: []u8,
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    token: []const u8,
    odcid: []const u8,
) aead_mod.AeadError!usize {
    if (buf.len < 1 + 4 + 1 + dcid.len + 1 + scid.len + token.len + 16) return error.BufferTooSmall;

    var pos: usize = 0;
    // First byte: Header Form=1, Fixed Bit=1, Type=Retry (0b11), random low nibble
    buf[pos] = 0xf0;
    pos += 1;
    std.mem.writeInt(u32, buf[pos..][0..4], version, .big);
    pos += 4;
    buf[pos] = @intCast(dcid.len);
    pos += 1;
    @memcpy(buf[pos .. pos + dcid.len], dcid);
    pos += dcid.len;
    buf[pos] = @intCast(scid.len);
    pos += 1;
    @memcpy(buf[pos .. pos + scid.len], scid);
    pos += scid.len;
    @memcpy(buf[pos .. pos + token.len], token);
    pos += token.len;

    // Compute and append integrity tag
    var tag: [16]u8 = undefined;
    try computeIntegrityTag(&tag, odcid, buf[0..pos]);
    @memcpy(buf[pos .. pos + 16], &tag);
    pos += 16;

    return pos;
}

test "retry: integrity tag round-trip" {
    const testing = std.testing;
    const odcid = "\x83\x94\xc8\xf0\x3e\x51\x57\x08";
    const token = "test-token";
    const dcid = "\xaa\xbb\xcc";
    const scid = "\xdd\xee";

    var buf: [128]u8 = undefined;
    const written = try buildRetryPacket(&buf, 0x00000001, dcid, scid, token, odcid);
    try testing.expect(written > 16);

    // Verify the tag in the built packet
    try testing.expect(verifyIntegrityTag(odcid, buf[0..written]));

    // Tampered tag should fail
    buf[written - 1] ^= 0x01;
    try testing.expect(!verifyIntegrityTag(odcid, buf[0..written]));
}

test "retry: empty token" {
    const odcid = "\x01\x02\x03\x04";
    const dcid = "\x05";
    const scid = "\x06";

    var buf: [64]u8 = undefined;
    const written = try buildRetryPacket(&buf, 0x00000001, dcid, scid, "", odcid);
    try std.testing.expect(verifyIntegrityTag(odcid, buf[0..written]));
}
