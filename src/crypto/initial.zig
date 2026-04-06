//! QUIC Initial packet crypto helpers (RFC 9001 §5).
//!
//! Combines key derivation and AEAD to encrypt/decrypt Initial packets
//! and apply/remove header protection.

const std = @import("std");
const keys = @import("keys.zig");
const aead = @import("aead.zig");

pub const InitialSecrets = keys.InitialSecrets;
pub const KeyMaterial = keys.KeyMaterial;

/// The number of bytes of ciphertext sampled for header protection (RFC 9001 §5.4.2).
pub const hp_sample_len = 16;

/// Offset from start of the encrypted payload to the HP sample.
/// The sample starts 4 bytes after the start of the packet number field.
/// Since the PN can be 1–4 bytes, we always sample at offset `max_pn_len(4)`.
pub const hp_sample_offset = 4;

/// Encrypt a QUIC Initial packet payload and apply header protection.
///
/// `header` must contain the full QUIC long header (up to but not including
/// the packet number). `pn_buf` contains the raw packet number bytes (1–4).
/// `plaintext` is the QUIC payload (frames). `dst` must be large enough.
///
/// Returns the total number of bytes written to `dst` (header + pn + ct + tag).
pub fn protectInitialPacket(
    dst: []u8,
    header: []const u8,
    pn: u64,
    pn_len: u2,
    plaintext: []const u8,
    km: *const KeyMaterial,
) aead.AeadError!usize {
    const actual_pn_len: usize = @as(usize, pn_len) + 1;
    const ct_and_tag_len = plaintext.len + 16; // AES-128-GCM tag

    if (dst.len < header.len + actual_pn_len + ct_and_tag_len) return error.BufferTooSmall;

    // Copy header
    @memcpy(dst[0..header.len], header);
    var pos = header.len;

    // Write packet number (big-endian, truncated)
    var pn_buf: [4]u8 = undefined;
    var i: usize = 0;
    while (i < actual_pn_len) : (i += 1) {
        pn_buf[actual_pn_len - 1 - i] = @truncate(pn >> @intCast(i * 8));
    }
    @memcpy(dst[pos .. pos + actual_pn_len], pn_buf[0..actual_pn_len]);
    pos += actual_pn_len;

    // AAD = header || pn_bytes
    const aad = dst[0..pos];
    const nonce = aead.buildNonce(km.iv, pn);

    // Encrypt payload
    try aead.encryptAes128Gcm(dst[pos .. pos + ct_and_tag_len], plaintext, aad, km.key, nonce);
    pos += ct_and_tag_len;

    // Apply header protection
    // Sample starts at pn_start + 4 (RFC 9001 §5.4.2)
    const pn_start = header.len;
    const sample_start = pn_start + hp_sample_offset;
    if (pos < sample_start + hp_sample_len) return error.BufferTooSmall;
    var sample: [hp_sample_len]u8 = undefined;
    @memcpy(&sample, dst[sample_start .. sample_start + hp_sample_len]);

    const pn_bytes_slice = dst[pn_start .. pn_start + actual_pn_len];
    // Long header: mask first byte with 0x0f (protect reserved bits and PN length)
    aead.HeaderProtection.applyAes128(km.hp, sample, &dst[0], pn_bytes_slice, 0x0f);

    return pos;
}

/// Remove header protection from an Initial packet and decrypt its payload.
///
/// `buf` contains the full received packet. `pn_start` is the byte offset of
/// the start of the (protected) packet number. `km` is the key material for
/// the decrypting side. `dst` receives the decrypted plaintext.
///
/// Returns the decrypted plaintext length.
pub fn unprotectInitialPacket(
    dst: []u8,
    buf: []const u8,
    pn_start: usize,
    payload_end: usize,
    km: *const KeyMaterial,
) (aead.AeadError || error{BufferTooShort})!usize {
    if (buf.len < pn_start + hp_sample_offset + hp_sample_len) return error.BufferTooShort;

    // Sample for header protection removal
    const sample_start = pn_start + hp_sample_offset;
    var sample: [hp_sample_len]u8 = undefined;
    @memcpy(&sample, buf[sample_start .. sample_start + hp_sample_len]);

    // Work on a mutable copy to unmask
    var header_copy: [1600]u8 = undefined;
    if (buf.len > header_copy.len) return error.BufferTooShort;
    @memcpy(header_copy[0..buf.len], buf);

    // Unmask first byte to discover actual PN length
    const first_byte_mask: u8 = if (header_copy[0] & 0x80 != 0) 0x0f else 0x1f;
    // Temporarily unmask first byte alone to read PN length
    var temp_first = header_copy[0];
    const ctx = std.crypto.core.aes.Aes128.initEnc(km.hp);
    var mask: [16]u8 = undefined;
    ctx.encrypt(&mask, &sample);
    temp_first ^= mask[0] & first_byte_mask;

    const actual_pn_len: usize = (temp_first & 0x03) + 1;

    // Now unmask PN bytes
    const pn_bytes = header_copy[pn_start .. pn_start + actual_pn_len];
    for (pn_bytes, 0..) |*b, i| {
        b.* ^= mask[1 + i];
    }
    header_copy[0] ^= mask[0] & first_byte_mask;

    // Reconstruct packet number (simple truncated decode)
    var pn: u64 = 0;
    for (pn_bytes) |b| {
        pn = (pn << 8) | b;
    }

    // AAD = everything up to and including PN
    const aad_end = pn_start + actual_pn_len;
    const aad = header_copy[0..aad_end];
    const nonce = aead.buildNonce(km.iv, pn);
    const ciphertext = buf[aad_end..payload_end];

    if (ciphertext.len < 16) return error.BufferTooShort;
    const plaintext_len = ciphertext.len - 16;
    if (dst.len < plaintext_len) return error.BufferTooSmall;

    try aead.decryptAes128Gcm(dst[0..plaintext_len], ciphertext, aad, km.key, nonce);
    return plaintext_len;
}

/// Encrypt a QUIC 1-RTT packet payload using ChaCha20-Poly1305 and apply
/// ChaCha20-based header protection (RFC 9001 §5.3, §5.4.4).
pub fn protectPacketChaCha20(
    dst: []u8,
    header: []const u8,
    pn: u64,
    pn_len: u2,
    plaintext: []const u8,
    km: *const KeyMaterial,
) aead.AeadError!usize {
    const actual_pn_len: usize = @as(usize, pn_len) + 1;
    const ct_and_tag_len = plaintext.len + 16; // Poly1305 tag

    if (dst.len < header.len + actual_pn_len + ct_and_tag_len) return error.BufferTooSmall;

    @memcpy(dst[0..header.len], header);
    var pos = header.len;

    var pn_buf: [4]u8 = undefined;
    var i: usize = 0;
    while (i < actual_pn_len) : (i += 1) {
        pn_buf[actual_pn_len - 1 - i] = @truncate(pn >> @intCast(i * 8));
    }
    @memcpy(dst[pos .. pos + actual_pn_len], pn_buf[0..actual_pn_len]);
    pos += actual_pn_len;

    const aad_slice = dst[0..pos];
    const nonce = aead.buildNonce(km.iv, pn);

    try aead.encryptChaCha20Poly1305(dst[pos .. pos + ct_and_tag_len], plaintext, aad_slice, km.key32, nonce);
    pos += ct_and_tag_len;

    const pn_start = header.len;
    const sample_start = pn_start + hp_sample_offset;
    if (pos < sample_start + hp_sample_len) return error.BufferTooSmall;
    var sample: [hp_sample_len]u8 = undefined;
    @memcpy(&sample, dst[sample_start .. sample_start + hp_sample_len]);

    const pn_bytes_slice = dst[pn_start .. pn_start + actual_pn_len];
    const first_byte_mask: u8 = if (dst[0] & 0x80 != 0) 0x0f else 0x1f;
    aead.HeaderProtection.applyChaCha20(km.hp32, sample, &dst[0], pn_bytes_slice, first_byte_mask);

    return pos;
}

/// Remove ChaCha20-based header protection and decrypt a QUIC packet payload.
pub fn unprotectPacketChaCha20(
    dst: []u8,
    buf: []const u8,
    pn_start: usize,
    payload_end: usize,
    km: *const KeyMaterial,
) (aead.AeadError || error{BufferTooShort})!usize {
    if (buf.len < pn_start + hp_sample_offset + hp_sample_len) return error.BufferTooShort;

    const sample_start = pn_start + hp_sample_offset;
    var sample: [hp_sample_len]u8 = undefined;
    @memcpy(&sample, buf[sample_start .. sample_start + hp_sample_len]);

    var header_copy: [1600]u8 = undefined;
    if (buf.len > header_copy.len) return error.BufferTooShort;
    @memcpy(header_copy[0..buf.len], buf);

    const first_byte_mask: u8 = if (header_copy[0] & 0x80 != 0) 0x0f else 0x1f;

    // Derive ChaCha20 mask: counter = sample[0..4], nonce = sample[4..16]
    const counter = std.mem.readInt(u32, sample[0..4], .little);
    const cc_nonce = sample[4..16].*;
    var full_mask: [64]u8 = undefined;
    std.crypto.stream.chacha.ChaCha20IETF.xor(&full_mask, &(.{0} ** 64), counter, km.hp32, cc_nonce);

    header_copy[0] ^= full_mask[0] & first_byte_mask;
    const actual_pn_len: usize = (header_copy[0] & 0x03) + 1;

    const pn_bytes = header_copy[pn_start .. pn_start + actual_pn_len];
    for (pn_bytes, 0..) |*b, i| {
        b.* ^= full_mask[1 + i];
    }

    var pn: u64 = 0;
    for (pn_bytes) |b| {
        pn = (pn << 8) | b;
    }

    const aad_end = pn_start + actual_pn_len;
    const aad_slice = header_copy[0..aad_end];
    const nonce = aead.buildNonce(km.iv, pn);
    const ciphertext = buf[aad_end..payload_end];

    if (ciphertext.len < 16) return error.BufferTooShort;
    const plaintext_len = ciphertext.len - 16;
    if (dst.len < plaintext_len) return error.BufferTooSmall;

    try aead.decryptChaCha20Poly1305(dst[0..plaintext_len], ciphertext, aad_slice, km.key32, nonce);
    return plaintext_len;
}

test "initial: encrypt/decrypt round-trip" {
    const testing = std.testing;
    const dcid = "\x83\x94\xc8\xf0\x3e\x51\x57\x08";
    const secrets = InitialSecrets.derive(dcid);

    // Fake header: first byte 0xc0 = LongHeader|FixedBit|Initial|PN_len=0 (1-byte PN)
    const header = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00 };
    const plaintext = "test quic payload data";

    var dst: [512]u8 = undefined;
    const written = try protectInitialPacket(
        &dst,
        &header,
        0, // pn = 0
        0, // pn_len wire = 0 → 1 byte
        plaintext,
        &secrets.client,
    );
    try testing.expect(written > header.len + 1 + plaintext.len);

    // Decrypt
    var decrypted: [128]u8 = undefined;
    const pn_start = header.len;
    const payload_end = written;
    const dec_len = try unprotectInitialPacket(&decrypted, dst[0..written], pn_start, payload_end, &secrets.client);
    try testing.expectEqualSlices(u8, plaintext, decrypted[0..dec_len]);
}
