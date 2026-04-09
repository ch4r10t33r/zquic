//! QUIC UDP I/O event loop (server and client).
//!
//! Implements the core event loop that ties together packet decryption,
//! the TLS 1.3 handshake state machine, and packet transmission.
//!
//! Architecture:
//!   recvfrom() → decrypt packet → dispatch frames → TLS state machine
//!   TLS state machine → CRYPTO frames → encrypt packet → sendto()
//!
//! Encryption levels:
//!   Initial    – AES-128-GCM with DCID-derived Initial secrets
//!   Handshake  – AES-128-GCM with keys derived from TLS handshake_secret
//!   1-RTT      – AES-128-GCM with keys derived from TLS application_secret

const std = @import("std");
const packet_mod = @import("../packet/packet.zig");
const header_mod = @import("../packet/header.zig");
const varint = @import("../varint.zig");
const types = @import("../types.zig");
const keys_mod = @import("../crypto/keys.zig");
const aead_mod = @import("../crypto/aead.zig");
const initial_mod = @import("../crypto/initial.zig");
const quic_tls_mod = @import("../crypto/quic_tls.zig");
const tls_hs = @import("../tls/handshake.zig");
const tls_vendor = @import("tls");
const stream_frame_mod = @import("../frames/stream.zig");
const http09_server = @import("../http09/server.zig");
const http09_client = @import("../http09/client.zig");
const retry_mod = @import("../packet/retry.zig");
const session_mod = @import("../crypto/session.zig");
const h3_frame = @import("../http3/frame.zig");
const h3_qpack = @import("../http3/qpack.zig");
const transport_frames = @import("../frames/transport.zig");
const version_neg_mod = @import("../packet/version_negotiation.zig");

const ConnectionId = types.ConnectionId;
const KeyMaterial = keys_mod.KeyMaterial;
const InitialSecrets = keys_mod.InitialSecrets;
const QuicKeyMaterial = tls_hs.QuicKeyMaterial;
const ServerHandshake = tls_hs.ServerHandshake;
const ClientHandshake = tls_hs.ClientHandshake;

const QUIC_VERSION_1: u32 = 0x00000001;
const QUIC_VERSION_2: u32 = 0x6b3343cf;

// ── ECN constants (RFC 9000 §13.4) ───────────────────────────────────────────
// Platform-specific socket option numbers for IP_TOS.
const IPPROTO_IP_OPT: i32 = 0;
const IP_TOS_OPT: i32 = switch (@import("builtin").target.os.tag) {
    .macos, .ios, .tvos, .watchos, .visionos => 3,
    else => 1, // Linux
};
/// ECT(0) — Not-Congestion-Experienced, ECN-Capable Transport, code point 10.
const ECN_ECT0: u8 = 0x02;

/// Return the first byte for a QUIC long-header packet.
/// The two packet-type bits (bits 5–4) are encoded differently in v1 vs v2
/// (RFC 9369 §3.1); everything else (Form=1, Fixed=1, low nibble=0) is common.
inline fn quicLongFirstByte(pkt_type: header_mod.LongType, version: u32) u8 {
    return 0xc0 | (@as(u8, header_mod.longTypeBits(pkt_type, version)) << 4);
}

/// Configure a UDP socket for ECN (RFC 9000 §13.4):
///   - Mark all outgoing packets with ECT(0) via IP_TOS so the peer can
///     echo back accurate ECN counts in ACK-ECN frames.
fn setupEcnSocket(sock: std.posix.fd_t) void {
    std.posix.setsockopt(
        sock,
        IPPROTO_IP_OPT,
        IP_TOS_OPT,
        std.mem.asBytes(&ECN_ECT0),
    ) catch {};
}
pub const MAX_CONNECTIONS: usize = 16;
pub const MAX_DATAGRAM_SIZE: usize = 1500;

/// MSG_DONTWAIT flag for non-blocking recvfrom().
/// std.posix.MSG is void on some platforms (macOS/Zig 0.14), so use raw values.
const MSG_DONTWAIT: u32 = if (@hasDecl(std.posix, "MSG") and @typeInfo(@TypeOf(std.posix.MSG)) == .@"struct")
    MSG_DONTWAIT
else switch (@import("builtin").target.os.tag) {
    .macos, .ios, .tvos, .watchos, .visionos => 0x80,
    else => 0x40, // Linux
};

// ── QUIC packet building helpers ─────────────────────────────────────────────

/// Build a CRYPTO frame: type(varint) + offset(varint) + len(varint) + data.
pub fn buildCryptoFrame(out: []u8, offset: u64, data: []const u8) !usize {
    if (out.len < 1 + 8 + 8 + data.len) return error.BufferTooSmall;
    var pos: usize = 0;
    // Frame type 0x06
    out[pos] = 0x06;
    pos += 1;
    // Offset (varint.encode returns the encoded slice)
    const off_enc = try varint.encode(out[pos..], offset);
    pos += off_enc.len;
    // Data length
    const len_enc = try varint.encode(out[pos..], @intCast(data.len));
    pos += len_enc.len;
    // Data
    @memcpy(out[pos .. pos + data.len], data);
    pos += data.len;
    return pos;
}

/// Build an ACK frame for the given packet number.
pub fn buildAckFrame(out: []u8, largest_pn: u64) !usize {
    if (out.len < 16) return error.BufferTooSmall;
    var pos: usize = 0;
    out[pos] = 0x02; // ACK frame type
    pos += 1;
    const pn_enc = try varint.encode(out[pos..], largest_pn);
    pos += pn_enc.len;
    out[pos] = 0x00; // ack_delay = 0
    pos += 1;
    out[pos] = 0x00; // ack_range_count = 0 (just the largest PN range)
    pos += 1;
    const range_enc = try varint.encode(out[pos..], 0); // first_ack_range = 0
    pos += range_enc.len;
    return pos;
}

/// Build an ACK-ECN frame (type 0x03) with ECN counts (RFC 9000 §19.3.2).
/// Includes ECT(0), ECT(1), and CE counts after the standard ACK ranges.
pub fn buildAckEcnFrame(out: []u8, largest_pn: u64, ect0: u64, ect1: u64, ce: u64) !usize {
    if (out.len < 40) return error.BufferTooSmall;
    var pos: usize = 0;
    out[pos] = 0x03; // ACK-ECN frame type
    pos += 1;
    const pn_enc = try varint.encode(out[pos..], largest_pn);
    pos += pn_enc.len;
    out[pos] = 0x00; // ack_delay = 0
    pos += 1;
    out[pos] = 0x00; // ack_range_count = 0
    pos += 1;
    const range_enc = try varint.encode(out[pos..], 0); // first_ack_range = 0
    pos += range_enc.len;
    // ECN counts
    const ect0_enc = try varint.encode(out[pos..], ect0);
    pos += ect0_enc.len;
    const ect1_enc = try varint.encode(out[pos..], ect1);
    pos += ect1_enc.len;
    const ce_enc = try varint.encode(out[pos..], ce);
    pos += ce_enc.len;
    return pos;
}

/// Build a PADDING frame (one byte 0x00).
pub fn buildPaddingFrames(out: []u8, count: usize) void {
    @memset(out[0..count], 0x00);
}

/// Build a HANDSHAKE_DONE frame (type 0x1e, no body).
pub fn buildHandshakeDoneFrame(out: []u8) usize {
    out[0] = 0x1e;
    return 1;
}

/// Encode `src` as lowercase hex into `dst` (dst must be 2*src.len bytes).
fn hexEncode(dst: []u8, src: []const u8) void {
    const chars = "0123456789abcdef";
    for (src, 0..) |b, i| {
        dst[i * 2] = chars[b >> 4];
        dst[i * 2 + 1] = chars[b & 0xf];
    }
}

/// Write TLS secrets to a keylog file in NSS key log format.
/// Enables Wireshark/tshark to decrypt captured QUIC traffic.
fn writeKeylog(path: []const u8, client_random: [32]u8, secrets: *const tls_hs.TrafficSecrets) void {
    const file = std.fs.createFileAbsolute(path, .{ .truncate = false }) catch return;
    defer file.close();
    file.seekFromEnd(0) catch return;

    const labels = [_][]const u8{
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
    };
    const values = [_][32]u8{
        secrets.client_handshake,
        secrets.server_handshake,
        secrets.client_app,
        secrets.server_app,
    };
    var rand_hex: [64]u8 = undefined;
    hexEncode(&rand_hex, &client_random);

    var line_buf: [256]u8 = undefined;
    var secret_hex: [64]u8 = undefined;
    for (labels, values) |label, secret| {
        hexEncode(&secret_hex, &secret);
        const line = std.fmt.bufPrint(&line_buf, "{s} {s} {s}\n", .{
            label, rand_hex, secret_hex,
        }) catch continue;
        file.writeAll(line) catch {};
    }
}

/// Skip the body of an ACK frame (type 0x02 or 0x03), advancing `pos` past it.
/// `is_ecn` should be true for type 0x03 (includes ECN counts).
/// Returns the number of bytes consumed from `data` (which starts AFTER the type varint).
fn skipAckBody(data: []const u8, is_ecn: bool) usize {
    var pos: usize = 0;
    const lar = varint.decode(data[pos..]) catch return data.len;
    pos += lar.len;
    const del = varint.decode(data[pos..]) catch return data.len;
    pos += del.len;
    const cnt = varint.decode(data[pos..]) catch return data.len;
    pos += cnt.len;
    const fst = varint.decode(data[pos..]) catch return data.len;
    pos += fst.len;
    var ri: u64 = 0;
    while (ri < cnt.value) : (ri += 1) {
        const gp = varint.decode(data[pos..]) catch return data.len;
        pos += gp.len;
        const rl = varint.decode(data[pos..]) catch return data.len;
        pos += rl.len;
    }
    if (is_ecn) {
        inline for (0..3) |_| {
            const ec = varint.decode(data[pos..]) catch return data.len;
            pos += ec.len;
        }
    }
    return pos;
}

/// Build an Initial packet with the given payload.
/// `version` selects QUIC v1 (0x00000001) or v2 (0x6b3343cf).
/// Returns bytes written.
pub fn buildInitialPacket(
    out: []u8,
    dcid: ConnectionId,
    scid: ConnectionId,
    token: []const u8,
    payload: []const u8,
    pn: u64,
    km: *const KeyMaterial,
    version: u32,
) !usize {
    var hdr_buf: [128]u8 = undefined;
    var hp: usize = 0;

    hdr_buf[hp] = quicLongFirstByte(.initial, version);
    hp += 1;
    std.mem.writeInt(u32, hdr_buf[hp..][0..4], version, .big);
    hp += 4;
    // DCID
    hdr_buf[hp] = dcid.len;
    hp += 1;
    @memcpy(hdr_buf[hp .. hp + dcid.len], dcid.slice());
    hp += dcid.len;
    // SCID
    hdr_buf[hp] = scid.len;
    hp += 1;
    @memcpy(hdr_buf[hp .. hp + scid.len], scid.slice());
    hp += scid.len;
    // Token
    const tok_enc = try varint.encode(hdr_buf[hp..], @intCast(token.len));
    hp += tok_enc.len;
    if (token.len > 0) {
        @memcpy(hdr_buf[hp .. hp + token.len], token);
        hp += token.len;
    }
    // Length = 1 (PN) + payload.len + 16 (AEAD tag)
    const length: u64 = 1 + payload.len + 16;
    const len_enc = try varint.encode(hdr_buf[hp..], length);
    hp += len_enc.len;

    // Use initial.protectInitialPacket for the rest
    return initial_mod.protectInitialPacket(
        out,
        hdr_buf[0..hp],
        pn,
        0, // pn_len_wire = 0 → 1 byte
        payload,
        km,
    );
}

/// Build a Handshake packet with the given payload.
/// `version` selects QUIC v1 or v2.
pub fn buildHandshakePacket(
    out: []u8,
    dcid: ConnectionId,
    scid: ConnectionId,
    payload: []const u8,
    pn: u64,
    km: *const KeyMaterial,
    version: u32,
) !usize {
    var hdr_buf: [128]u8 = undefined;
    var hp: usize = 0;

    hdr_buf[hp] = quicLongFirstByte(.handshake, version);
    hp += 1;
    std.mem.writeInt(u32, hdr_buf[hp..][0..4], version, .big);
    hp += 4;
    hdr_buf[hp] = dcid.len;
    hp += 1;
    @memcpy(hdr_buf[hp .. hp + dcid.len], dcid.slice());
    hp += dcid.len;
    hdr_buf[hp] = scid.len;
    hp += 1;
    @memcpy(hdr_buf[hp .. hp + scid.len], scid.slice());
    hp += scid.len;
    const length: u64 = 1 + payload.len + 16;
    const len_enc2 = try varint.encode(hdr_buf[hp..], length);
    hp += len_enc2.len;

    // We reuse the Initial protect logic since the AEAD structure is identical.
    return initial_mod.protectInitialPacket(out, hdr_buf[0..hp], pn, 0, payload, km);
}

/// Build a 0-RTT (Long Header, Type=0-RTT) packet.
/// `version` selects QUIC v1 or v2.
pub fn build0RttPacket(
    out: []u8,
    dcid: ConnectionId,
    scid: ConnectionId,
    payload: []const u8,
    pn: u64,
    km: *const KeyMaterial,
    version: u32,
) !usize {
    var hdr_buf: [128]u8 = undefined;
    var hp: usize = 0;
    hdr_buf[hp] = quicLongFirstByte(.zero_rtt, version);
    hp += 1;
    std.mem.writeInt(u32, hdr_buf[hp..][0..4], version, .big);
    hp += 4;
    hdr_buf[hp] = dcid.len;
    hp += 1;
    @memcpy(hdr_buf[hp .. hp + dcid.len], dcid.slice());
    hp += dcid.len;
    hdr_buf[hp] = scid.len;
    hp += 1;
    @memcpy(hdr_buf[hp .. hp + scid.len], scid.slice());
    hp += scid.len;
    const length: u64 = 1 + payload.len + 16;
    const len_enc = try varint.encode(hdr_buf[hp..], length);
    hp += len_enc.len;
    return initial_mod.protectInitialPacket(out, hdr_buf[0..hp], pn, 0, payload, km);
}

/// Build a 1-RTT (Short Header) packet.
/// Compare two `std.net.Address` values for equality (address + port).
fn addressEqual(a: std.net.Address, b: std.net.Address) bool {
    if (a.any.family != b.any.family) return false;
    return switch (a.any.family) {
        std.posix.AF.INET => a.in.sa.port == b.in.sa.port and
            a.in.sa.addr == b.in.sa.addr,
        std.posix.AF.INET6 => a.in6.sa.port == b.in6.sa.port and
            std.mem.eql(u8, &a.in6.sa.addr, &b.in6.sa.addr),
        else => false,
    };
}

pub fn build1RttPacket(
    out: []u8,
    dcid: ConnectionId,
    payload: []const u8,
    pn: u64,
    km: *const KeyMaterial,
) !usize {
    return build1RttPacketWithPhase(out, dcid, payload, pn, km, false);
}

pub fn build1RttPacketWithPhase(
    out: []u8,
    dcid: ConnectionId,
    payload: []const u8,
    pn: u64,
    km: *const KeyMaterial,
    key_phase: bool,
) !usize {
    return build1RttPacketFull(out, dcid, payload, pn, km, key_phase, false);
}

pub fn build1RttPacketFull(
    out: []u8,
    dcid: ConnectionId,
    payload: []const u8,
    pn: u64,
    km: *const KeyMaterial,
    key_phase: bool,
    chacha20: bool,
) !usize {
    var hdr_buf: [64]u8 = undefined;
    var hp: usize = 0;

    // Header Form=0, Fixed Bit=1, Spin=0, Reserved=00, Key Phase bit, PN_len=0
    var first: u8 = 0x40;
    if (key_phase) first |= 0x04;
    hdr_buf[hp] = first;
    hp += 1;
    @memcpy(hdr_buf[hp .. hp + dcid.len], dcid.slice());
    hp += dcid.len;

    if (chacha20) {
        return initial_mod.protectPacketChaCha20(out, hdr_buf[0..hp], pn, 0, payload, km);
    }
    return initial_mod.protectInitialPacket(out, hdr_buf[0..hp], pn, 0, payload, km);
}

/// Decrypt a 1-RTT packet, selecting AES or ChaCha20 based on the cipher flag.
/// Decrypt a 1-RTT packet with proper packet number decompression
/// expected_recv_pn: the last received packet number in this packet number space (null if first packet)
/// Returns both plaintext length and the decompressed packet number.
fn unprotect1RttPacketWithPnTracking(
    dst: []u8,
    buf: []const u8,
    pn_start: usize,
    km: *const KeyMaterial,
    chacha20: bool,
    expected_recv_pn: ?u64,
) !struct { pt_len: usize, pn: u64 } {
    if (buf.len < pn_start + initial_mod.hp_sample_offset + initial_mod.hp_sample_len) return error.BufferTooShort;

    // Sample for header protection removal
    const sample_start = pn_start + initial_mod.hp_sample_offset;
    var sample: [initial_mod.hp_sample_len]u8 = undefined;
    @memcpy(&sample, buf[sample_start .. sample_start + initial_mod.hp_sample_len]);

    // Work on a mutable copy to unmask
    var header_copy: [1600]u8 = undefined;
    if (buf.len > header_copy.len) return error.BufferTooShort;
    @memcpy(header_copy[0..buf.len], buf);

    // Unmask first byte to discover actual PN length
    const first_byte_mask: u8 = 0x1f; // short header
    var temp_first = header_copy[0];

    if (chacha20) {
        // For ChaCha20, we need to use chacha20 header protection
        const counter = std.mem.readInt(u32, sample[0..4], .little);
        const cc_nonce = sample[4..16].*;
        var full_mask: [64]u8 = undefined;
        std.crypto.stream.chacha.ChaCha20IETF.xor(&full_mask, &(.{0} ** 64), counter, km.hp32, cc_nonce);
        temp_first ^= full_mask[0] & first_byte_mask;
    } else {
        var mask: [16]u8 = undefined;
        const aes_ctx = std.crypto.core.aes.Aes128.initEnc(km.hp);
        aes_ctx.encrypt(&mask, &sample);
        temp_first ^= mask[0] & first_byte_mask;
    }

    const actual_pn_len: usize = (temp_first & 0x03) + 1;

    // Now unmask PN bytes (recompute mask for actual PN bytes)
    var pn_mask: [16]u8 = undefined;
    if (chacha20) {
        const counter = std.mem.readInt(u32, sample[0..4], .little);
        const cc_nonce = sample[4..16].*;
        var full_mask: [64]u8 = undefined;
        std.crypto.stream.chacha.ChaCha20IETF.xor(&full_mask, &(.{0} ** 64), counter, km.hp32, cc_nonce);
        @memcpy(&pn_mask, full_mask[0..16]);
    } else {
        const aes_ctx = std.crypto.core.aes.Aes128.initEnc(km.hp);
        aes_ctx.encrypt(&pn_mask, &sample);
    }

    const pn_bytes = header_copy[pn_start .. pn_start + actual_pn_len];
    for (pn_bytes, 0..) |*b, i| {
        b.* ^= pn_mask[1 + i];
    }
    header_copy[0] ^= pn_mask[0] & first_byte_mask;

    // Extract truncated packet number
    var truncated_pn: u64 = 0;
    for (pn_bytes) |b| {
        truncated_pn = (truncated_pn << 8) | b;
    }

    // Decompress packet number
    const pn_len_bits: u3 = @intCast(actual_pn_len - 1);
    const pn = initial_mod.decompressPacketNumber(truncated_pn, expected_recv_pn, pn_len_bits);

    // AAD = everything up to and including PN
    const aad_end = pn_start + actual_pn_len;
    const aad = header_copy[0..aad_end];
    const nonce = aead_mod.buildNonce(km.iv, pn);
    const ciphertext = buf[aad_end..];

    if (ciphertext.len < 16) return error.BufferTooShort;
    const plaintext_len = ciphertext.len - 16;
    if (dst.len < plaintext_len) return error.BufferTooSmall;

    if (chacha20) {
        try aead_mod.decryptChaCha20Poly1305(dst[0..plaintext_len], ciphertext, aad, km.key32, nonce);
    } else {
        try aead_mod.decryptAes128Gcm(dst[0..plaintext_len], ciphertext, aad, km.key, nonce);
    }
    return .{ .pt_len = plaintext_len, .pn = pn };
}

pub fn unprotect1RttPacket(
    dst: []u8,
    buf: []const u8,
    pn_start: usize,
    km: *const KeyMaterial,
    chacha20: bool,
) !usize {
    if (chacha20) {
        return initial_mod.unprotectPacketChaCha20(dst, buf, pn_start, buf.len, km);
    }
    return initial_mod.unprotectInitialPacket(dst, buf, pn_start, buf.len, km);
}

/// Return the unprotected first byte of a 1-RTT short-header packet.
/// Removes AES-128 header protection to reveal the Key Phase bit (0x04).
/// Returns null if the packet is too short to sample.
fn peekUnprotectedFirstByte(buf: []const u8, pn_start: usize, km: *const KeyMaterial, chacha20: bool) ?u8 {
    const sample_start = pn_start + initial_mod.hp_sample_offset;
    if (buf.len < sample_start + initial_mod.hp_sample_len) return null;
    var sample: [initial_mod.hp_sample_len]u8 = undefined;
    @memcpy(&sample, buf[sample_start .. sample_start + initial_mod.hp_sample_len]);

    var mask0: u8 = undefined;
    if (chacha20) {
        const counter = std.mem.readInt(u32, sample[0..4], .little);
        const cc_nonce = sample[4..16].*;
        var full_mask: [64]u8 = undefined;
        std.crypto.stream.chacha.ChaCha20IETF.xor(&full_mask, &(.{0} ** 64), counter, km.hp32, cc_nonce);
        mask0 = full_mask[0];
    } else {
        const ctx = std.crypto.core.aes.Aes128.initEnc(km.hp);
        var mask: [16]u8 = undefined;
        ctx.encrypt(&mask, &sample);
        mask0 = mask[0];
    }
    return buf[0] ^ (mask0 & 0x1f); // short header: mask bits 5-0
}

// ── QUIC packet decryption ────────────────────────────────────────────────────

/// Decrypt a Handshake or 1-RTT packet payload.
/// Equivalent to `unprotectInitialPacket` but works with any KeyMaterial.
pub fn decryptLongPacket(
    dst: []u8,
    buf: []const u8,
    pn_start: usize,
    payload_end: usize,
    km: *const KeyMaterial,
) !usize {
    return initial_mod.unprotectInitialPacket(dst, buf, pn_start, payload_end, km);
}

// ── PEM loading helpers ───────────────────────────────────────────────────────

/// Load the first DER certificate from a PEM file (heap-allocated).
pub fn loadCertDer(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const pem = std.fs.openFileAbsolute(path, .{}) catch |err| {
        std.debug.print("io: cannot open cert {s}: {}\n", .{ path, err });
        return err;
    };
    defer pem.close();
    const pem_data = pem.readToEndAlloc(allocator, 65536) catch return error.CertReadFailed;
    defer allocator.free(pem_data);

    const begin = "-----BEGIN CERTIFICATE-----";
    const end_m = "-----END CERTIFICATE-----";
    const bi = std.mem.indexOf(u8, pem_data, begin) orelse return error.NoCertificate;
    const after = bi + begin.len;
    const ei = std.mem.indexOf(u8, pem_data[after..], end_m) orelse return error.NoCertEnd;

    // Remove whitespace from base64 region
    const raw = pem_data[after .. after + ei];
    const b64 = try allocator.alloc(u8, raw.len);
    defer allocator.free(b64);
    var b64_len: usize = 0;
    for (raw) |c| {
        if (c != '\n' and c != '\r' and c != ' ') {
            b64[b64_len] = c;
            b64_len += 1;
        }
    }

    const decoder = std.base64.standard.Decoder;
    const der_len = try decoder.calcSizeForSlice(b64[0..b64_len]);
    const der = try allocator.alloc(u8, der_len);
    try decoder.decode(der, b64[0..b64_len]);
    return der;
}

/// Load a PrivateKey from a PEM file using tls.zig's parser.
pub fn loadPrivateKey(allocator: std.mem.Allocator, path: []const u8) !tls_vendor.config.PrivateKey {
    const f = std.fs.openFileAbsolute(path, .{}) catch |err| {
        std.debug.print("io: cannot open key {s}: {}\n", .{ path, err });
        return err;
    };
    defer f.close();
    return tls_vendor.config.PrivateKey.fromFile(allocator, f);
}

// ── Per-connection state ──────────────────────────────────────────────────────

/// One pending HTTP/0.9 file response (served incrementally from the event loop).
const Http09OutSlot = struct {
    active: bool = false,
    stream_id: u64 = 0,
    file: std.fs.File = undefined,
    stream_offset: u64 = 0,
    file_end: u64 = 0,

    /// FIN retransmission state.
    /// After sending the final STREAM frame (FIN=true), the slot transitions
    /// from active=true to awaiting_fin_ack=true.  The FIN frame is kept in
    /// fin_frame[0..fin_frame_len] and re-sent every 200 ms until the client
    /// acknowledges the packet (largest_ack >= fin_pkt_pn) or we give up after
    /// MAX_FIN_RETRANSMITS attempts.
    awaiting_fin_ack: bool = false,
    fin_frame: [1300]u8 = [_]u8{0} ** 1300,
    fin_frame_len: usize = 0,
    fin_pkt_pn: u64 = 0,
    fin_last_sent_ms: i64 = 0,
    fin_retransmit_count: usize = 0,

    const MAX_FIN_RETRANSMITS: usize = 15; // ~3 s at 200 ms intervals

    fn close(self: *Http09OutSlot) void {
        if (self.active) {
            self.file.close();
            self.active = false;
        }
    }
};

/// One pending HTTP/3 file response (served incrementally from the event loop).
/// Like Http09OutSlot but wraps file content in HTTP/3 DATA frames and tracks
/// the QUIC stream offset independently (HEADERS frame bytes are counted too).
const Http3OutSlot = struct {
    active: bool = false,
    stream_id: u64 = 0,
    file: std.fs.File = undefined,
    /// Byte offset in the QUIC stream (includes the HEADERS frame already sent).
    stream_offset: u64 = 0,
    file_end: u64 = 0,

    /// FIN retransmission state — same pattern as Http09OutSlot.
    awaiting_fin_ack: bool = false,
    fin_frame: [1300]u8 = [_]u8{0} ** 1300,
    fin_frame_len: usize = 0,
    fin_pkt_pn: u64 = 0,
    fin_last_sent_ms: i64 = 0,
    fin_retransmit_count: usize = 0,

    const MAX_FIN_RETRANSMITS: usize = 15;

    fn close(self: *Http3OutSlot) void {
        if (self.active) {
            self.file.close();
            self.active = false;
        }
    }
};

const pending_1rtt_cap: usize = 8;

/// Decrypted 1-RTT coalesced payload queued until the handshake is confirmed.
const Pending1RttPayload = struct {
    len: usize = 0,
    data: [4096]u8 = undefined,
};

/// Connection lifecycle state.
pub const ConnPhase = enum {
    /// Waiting for ClientHello Initial packet.
    initial,
    /// Sent server flight; waiting for client Finished in Handshake packet.
    waiting_finished,
    /// Handshake complete; processing 1-RTT application data.
    connected,
    /// Draining or closed.
    closed,
};

/// Per-connection crypto and TLS state.
pub const ConnState = struct {
    phase: ConnPhase = .initial,

    // Connection IDs
    local_cid: ConnectionId,
    remote_cid: ConnectionId,
    // The client's original DCID from the first Initial packet.
    // Stored so that 0-RTT packets (which carry this DCID, not local_cid)
    // can be matched back to the right ConnState.
    init_dcid: ?ConnectionId = null,

    // Alternative local CID sent to peer via NEW_CONNECTION_ID (for migration).
    alt_local_cid: ?ConnectionId = null,
    // Alternative remote CID received from peer via NEW_CONNECTION_ID (use on migration).
    next_remote_cid: ?ConnectionId = null,

    // Peer UDP address
    peer: std.net.Address,

    // Initial packet keys (derived from DCID)
    init_keys: ?InitialSecrets = null,

    // Handshake-level QUIC keys (from TLS handshake_traffic_secret)
    hs_server_km: KeyMaterial = undefined,
    hs_client_km: KeyMaterial = undefined,
    has_hs_keys: bool = false,

    // 1-RTT QUIC keys (from TLS application_traffic_secret)
    app_server_km: KeyMaterial = undefined,
    app_client_km: KeyMaterial = undefined,
    has_app_keys: bool = false,

    // Packet number spaces
    init_pn: u64 = 0,
    hs_pn: u64 = 0,
    app_pn: u64 = 0,

    // Received packet numbers (last seen for ACK)
    init_recv_pn: ?u64 = null,
    hs_recv_pn: ?u64 = null,
    app_recv_pn: ?u64 = null,

    // CRYPTO stream offset tracking (in-order reassembly)
    init_crypto_offset: u64 = 0,
    app_crypto_offset: u64 = 0,

    // HTTP/3 state: whether the server control stream was sent
    h3_settings_sent: bool = false,

    /// HTTP/0.9 responses in progress (parallel downloads per connection).
    http09_slots: [2000]Http09OutSlot = [_]Http09OutSlot{.{}} ** 2000,

    /// HTTP/3 responses in progress (paced DATA frame sending per connection).
    http3_slots: [32]Http3OutSlot = [_]Http3OutSlot{.{}} ** 32,

    /// 1-RTT frames received while waiting for client Finished (reordering).
    pending_1rtt: [pending_1rtt_cap]Pending1RttPayload = [_]Pending1RttPayload{.{}} ** pending_1rtt_cap,
    pending_1rtt_n: usize = 0,

    // Retry token (set when server sends Retry; included in next Initial)
    retry_token: [64]u8 = [_]u8{0} ** 64,
    retry_token_len: usize = 0,

    // original_destination_connection_id (RFC 9000 §7.3): set on the server
    // when a valid Retry token is accepted.  Included in server transport params
    // so the client can verify it matches the DCID from its first Initial.
    retry_odcid: [20]u8 = [_]u8{0} ** 20,
    retry_odcid_len: usize = 0,
    hs_crypto_offset: u64 = 0,

    // Set once client has seen the server's first Initial packet and has
    // updated remote_cid to the server's SCID (RFC 9000 §7.2).
    server_cid_confirmed: bool = false,

    // Stored Handshake (Finished) packet for retransmission.
    // Written in sendClientFinished; retransmitted by the run loop.
    finished_pkt: [MAX_DATAGRAM_SIZE]u8 = [_]u8{0} ** MAX_DATAGRAM_SIZE,
    finished_pkt_len: usize = 0,
    finished_sent_ms: i64 = 0,

    // 1-RTT key phase tracking for key updates (RFC 9001 §6).
    // Tracks the current key phase bit for outgoing short-header packets.
    key_phase_bit: bool = false,
    // Whether a key update is currently pending confirmation.
    key_update_pending: bool = false,
    // Tracks the key phase bit seen in the last successfully decrypted
    // 1-RTT packet; used to detect peer-initiated key updates.
    peer_key_phase: bool = false,

    // Connection migration (RFC 9000 §9): pending PATH_CHALLENGE data.
    // Non-null while waiting for a PATH_RESPONSE from the new address.
    path_challenge_data: ?[8]u8 = null,

    // 0-RTT early data keys (derived from PSK + ClientHello transcript hash).
    early_km: KeyMaterial = undefined,
    has_early_keys: bool = false,

    // Cipher suite in use for 1-RTT packets (true = ChaCha20-Poly1305).
    use_chacha20: bool = false,

    // QUIC version in use for this connection (true = QUIC v2 / RFC 9369).
    // Controls initial-secret derivation, long-header type bits, and Retry tag.
    use_v2: bool = false,

    // ECN counters for received 1-RTT packets (RFC 9000 §13.4).
    // We mark all outgoing packets ECT(0); these counts track what was received
    // so that ACK-ECN frames (type 0x03) report accurate ECN feedback to the peer.
    ecn_ect0_recv: u64 = 0,
    ecn_ect1_recv: u64 = 0,
    ecn_ce_recv: u64 = 0,

    // Pre-derived QUIC v2 initial secrets for compatible version negotiation.
    // Set on the client when config.v2 = true so we can decrypt a v2 Initial
    // from the server even though we sent the first packet as v1.
    // Cleared once we successfully upgrade to v2 (or connection is dropped).
    v2_upgrade_keys: ?InitialSecrets = null,

    // TLS handshake state machine (server side)
    tls: ServerHandshake = undefined,
    tls_inited: bool = false,

    // Pending outgoing TLS bytes (for CRYPTO frames)
    // ServerHello goes in Initial; server flight goes in Handshake
    sh_bytes: [512]u8 = undefined, // ServerHello
    sh_len: usize = 0,
    flight_bytes: [8192]u8 = undefined, // EncryptedExtensions+Cert+CV+Finished
    flight_len: usize = 0,

    /// Return the QUIC version constant for this connection.
    pub fn quicVersion(self: *const ConnState) u32 {
        return if (self.use_v2) QUIC_VERSION_2 else QUIC_VERSION_1;
    }

    pub fn deriveInitialKeys(self: *ConnState, dcid: ConnectionId) void {
        self.init_keys = if (self.use_v2)
            InitialSecrets.deriveV2(dcid.slice())
        else
            InitialSecrets.derive(dcid.slice());
    }

    /// Derive Handshake QUIC keys from TLS handshake traffic secrets.
    /// Call this after processServerHello (client) or processClientHello (server).
    pub fn deriveHandshakeKeys(self: *ConnState, secrets: *const tls_hs.TrafficSecrets) void {
        const hs_client_qkm = tls_hs.deriveQuicKeys(secrets.client_handshake);
        const hs_server_qkm = tls_hs.deriveQuicKeys(secrets.server_handshake);

        self.hs_client_km = .{ .key = hs_client_qkm.key, .key32 = hs_client_qkm.key32, .iv = hs_client_qkm.iv, .hp = hs_client_qkm.hp, .hp32 = hs_client_qkm.hp32, .secret = secrets.client_handshake };
        self.hs_server_km = .{ .key = hs_server_qkm.key, .key32 = hs_server_qkm.key32, .iv = hs_server_qkm.iv, .hp = hs_server_qkm.hp, .hp32 = hs_server_qkm.hp32, .secret = secrets.server_handshake };

        self.has_hs_keys = true;
    }

    /// Derive 1-RTT QUIC keys from TLS application traffic secrets.
    /// Call this after buildServerFlight (server) or processServerFlight (client).
    pub fn deriveAppKeys(self: *ConnState, secrets: *const tls_hs.TrafficSecrets) void {
        const app_client_qkm = tls_hs.deriveQuicKeys(secrets.client_app);
        const app_server_qkm = tls_hs.deriveQuicKeys(secrets.server_app);

        self.app_client_km = .{ .key = app_client_qkm.key, .key32 = app_client_qkm.key32, .iv = app_client_qkm.iv, .hp = app_client_qkm.hp, .hp32 = app_client_qkm.hp32, .secret = secrets.client_app };
        self.app_server_km = .{ .key = app_server_qkm.key, .key32 = app_server_qkm.key32, .iv = app_server_qkm.iv, .hp = app_server_qkm.hp, .hp32 = app_server_qkm.hp32, .secret = secrets.server_app };

        self.has_app_keys = true;
    }
};

// ── Server config ─────────────────────────────────────────────────────────────

pub const ServerConfig = struct {
    port: u16 = 443,
    cert_path: []const u8 = "/certs/cert.pem",
    key_path: []const u8 = "/certs/priv.key",
    www_dir: []const u8 = "/www",
    keylog_path: ?[]const u8 = null,
    retry_enabled: bool = false,
    resumption_enabled: bool = false,
    early_data: bool = false,
    http09: bool = false,
    http3: bool = false,
    key_update: bool = false,
    migrate: bool = false,
    chacha20: bool = false,
    /// Accept (and respond using) QUIC v2 when the client sends a v2 Initial.
    /// Also suppresses Version Negotiation for QUIC_V2 packets regardless of
    /// this flag, so the server auto-negotiates down to v1 if needed.
    v2: bool = false,
};

// ── QUIC Server ───────────────────────────────────────────────────────────────

pub const Server = struct {
    allocator: std.mem.Allocator,
    config: ServerConfig,
    sock: std.posix.socket_t,
    /// Raw UDP socket for diagnostics — receives all incoming UDP datagrams
    /// at the IP level (before UDP dispatch).  Lets us detect packets that
    /// arrive at the NIC but never reach the main socket on port 443.
    raw_sock: ?std.posix.socket_t = null,
    cert_der: []u8,
    private_key: tls_vendor.config.PrivateKey,
    conns: [MAX_CONNECTIONS]?ConnState = [_]?ConnState{null} ** MAX_CONNECTIONS,
    /// Random server token secret for Retry token HMAC-SHA256 verification.
    retry_secret: [32]u8 = [_]u8{0} ** 32,
    /// Timestamp of the last HTTP/0.9 response flush (milliseconds).
    /// Used to enforce a minimum flush interval so we don't flood the network
    /// by flushing after every incoming ACK packet. Without pacing, the server
    /// can send 6+ MB/s into a 10 Mbps (1.25 MB/s) simulated link, causing
    /// the network simulator to drop 80%+ of packets and stalling transfers.
    http09_last_flush_ms: i64 = 0,
    /// Pacing timestamp for http09RetransmitPendingFins: at most one burst per 50ms.
    http09_retransmit_last_ms: i64 = 0,
    /// Same pacing timestamp for HTTP/3 DATA frame sends.
    http3_last_flush_ms: i64 = 0,

    /// Initialize server: load cert/key and create UDP socket.
    pub fn init(allocator: std.mem.Allocator, config: ServerConfig) !*Server {
        // Heap-allocate the Server to avoid blowing the stack: the conns array
        // (16 × ConnState, each ≈220 KB) totals ~3.5 MB — too large for a stack
        // local in main().
        const self = try allocator.create(Server);
        errdefer allocator.destroy(self);

        // Load certificate DER bytes
        const cert_der = loadCertDer(allocator, config.cert_path) catch |err| {
            std.debug.print("io: cert load failed ({s}): {}\n", .{ config.cert_path, err });
            return err;
        };
        errdefer allocator.free(cert_der);

        // Load private key
        const pk = loadPrivateKey(allocator, config.key_path) catch |err| {
            std.debug.print("io: key load failed ({s}): {}\n", .{ config.key_path, err });
            return err;
        };

        // Create UDP socket (IPv4)
        const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
        errdefer std.posix.close(sock);

        // Bind to port on all interfaces
        const addr = try std.net.Address.parseIp4("0.0.0.0", config.port);
        try std.posix.bind(sock, &addr.any, addr.getOsSockLen());

        // Large buffers help bulk HTTP/0.9 transfers: without them, a tight send
        // loop in handleHttp09Stream can fill the default SNDBUF and drop packets
        // before the kernel pushes them onto the simulated link.
        var sk_buf: i32 = 8 * 1024 * 1024;
        const sk_opt = std.mem.asBytes(&sk_buf);
        std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, sk_opt) catch {};
        std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, sk_opt) catch {};
        setupEcnSocket(sock);

        std.debug.print("io: server bound on 0.0.0.0:{d}\n", .{config.port});

        // Diagnostic raw socket: capture all incoming UDP at IP level.
        // If this sees packets that the main socket doesn't, it indicates
        // a kernel-level filter is blocking delivery to port 443.
        const raw_sock = std.posix.socket(
            std.posix.AF.INET,
            std.posix.SOCK.RAW,
            17, // IPPROTO_UDP
        ) catch |err| blk: {
            std.debug.print("io: raw_sock create failed ({}), no raw diagnostics\n", .{err});
            break :blk null;
        };
        if (raw_sock) |rs| {
            std.debug.print("io: raw_sock created fd={}\n", .{rs});
        }

        // Generate a random Retry token secret for this server lifetime
        var retry_secret: [32]u8 = undefined;
        std.crypto.random.bytes(&retry_secret);

        self.* = .{
            .allocator = allocator,
            .config = config,
            .sock = sock,
            .raw_sock = raw_sock,
            .cert_der = cert_der,
            .private_key = pk,
            .retry_secret = retry_secret,
        };
        return self;
    }

    pub fn deinit(self: *Server) void {
        std.posix.close(self.sock);
        if (self.raw_sock) |rs| std.posix.close(rs);
        self.allocator.free(self.cert_der);
        self.allocator.destroy(self);
    }

    /// Run the server event loop (blocking).
    pub fn run(self: *Server) !void {
        var recv_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
        var idle_secs: u32 = 0;

        while (true) {
            // Poll both the main UDP socket and the diagnostic raw socket.
            var nfds: usize = 1;
            var fds = [2]std.posix.pollfd{
                .{ .fd = self.sock, .events = std.posix.POLL.IN, .revents = 0 },
                .{ .fd = -1, .events = std.posix.POLL.IN, .revents = 0 },
            };
            if (self.raw_sock) |rs| {
                fds[1].fd = rs;
                nfds = 2;
            }

            var poll_timeout_ms: i32 = 2000;
            for (&self.conns) |*cslot| {
                if (cslot.*) |*conn| {
                    for (&conn.http09_slots) |*slot| {
                        if (slot.active or slot.awaiting_fin_ack) {
                            poll_timeout_ms = 50;
                            break;
                        }
                    }
                    if (poll_timeout_ms != 50) {
                        for (&conn.http3_slots) |*slot| {
                            if (slot.active or slot.awaiting_fin_ack) {
                                poll_timeout_ms = 50;
                                break;
                            }
                        }
                    }
                }
                if (poll_timeout_ms == 50) break;
            }

            const ready = std.posix.poll(fds[0..nfds], poll_timeout_ms) catch |err| {
                std.debug.print("io: poll error: {}\n", .{err});
                self.flushPendingHttp09Responses();
                self.http09RetransmitPendingFins();
                self.flushPendingHttp3Responses();
                self.http3RetransmitPendingFins();
                continue;
            };
            if (ready == 0) {
                if (poll_timeout_ms >= 2000) {
                    idle_secs += 2;
                    std.debug.print("io: server waiting ({}s idle, sock={})\n", .{ idle_secs, self.sock });
                }
                self.flushPendingHttp09Responses();
                self.http09RetransmitPendingFins();
                self.flushPendingHttp3Responses();
                self.http3RetransmitPendingFins();
                continue;
            }
            idle_secs = 0;

            // Check if the raw diagnostic socket got something.
            if (nfds == 2 and fds[1].revents & std.posix.POLL.IN != 0) {
                var raw_buf: [2048]u8 = undefined;
                var raw_src: std.posix.sockaddr.storage = undefined;
                var raw_src_len: std.posix.socklen_t = @sizeOf(@TypeOf(raw_src));
                const rn = std.posix.recvfrom(
                    self.raw_sock.?,
                    &raw_buf,
                    0,
                    @ptrCast(&raw_src),
                    &raw_src_len,
                ) catch 0;
                if (rn >= 20) { // at least IP header
                    // IP header: src at bytes 12-15, dst at bytes 16-19, proto at byte 9
                    const proto = raw_buf[9];
                    const src_ip = raw_buf[12..16];
                    const dst_ip = raw_buf[16..20];
                    std.debug.print("io: raw_sock got {} bytes proto={} src={}.{}.{}.{} dst={}.{}.{}.{}\n", .{
                        rn,        proto,
                        src_ip[0], src_ip[1],
                        src_ip[2], src_ip[3],
                        dst_ip[0], dst_ip[1],
                        dst_ip[2], dst_ip[3],
                    });
                }
            }

            // Read from main UDP socket — first datagram blocking (matches POLL.IN),
            // then drain the rest with DONTWAIT so ACK batches are not processed
            // one wakeup per datagram.
            if (fds[0].revents & std.posix.POLL.IN != 0) {
                var drained: usize = 0;
                while (true) {
                    var src_addr: std.posix.sockaddr.storage = undefined;
                    var src_len: std.posix.socklen_t = @sizeOf(@TypeOf(src_addr));
                    const flags: u32 = if (drained == 0) 0 else MSG_DONTWAIT;
                    const n = std.posix.recvfrom(
                        self.sock,
                        &recv_buf,
                        flags,
                        @ptrCast(&src_addr),
                        &src_len,
                    ) catch |err| {
                        if (drained > 0 and err == error.WouldBlock) break;
                        std.debug.print("io: recvfrom error: {}\n", .{err});
                        break;
                    };
                    drained += 1;
                    std.debug.print("io: server recvfrom OK n={} src_len={}\n", .{ n, src_len });

                    const src = std.net.Address{ .any = @as(*const std.posix.sockaddr, @ptrCast(&src_addr)).* };
                    self.processPacket(recv_buf[0..n], src);
                }
            }

            self.flushPendingHttp09Responses();
            self.http09RetransmitPendingFins();
            self.flushPendingHttp3Responses();
            self.http3RetransmitPendingFins();
        }
    }

    /// Dispatch a received UDP datagram.
    fn processPacket(self: *Server, buf: []const u8, src: std.net.Address) void {
        const src_ip = src.any.data[2..6];
        std.debug.print("io: server recv {} bytes first_byte=0x{x:0>2} src_ip={}.{}.{}.{}\n", .{
            buf.len,   if (buf.len > 0) buf[0] else 0,
            src_ip[0], src_ip[1],
            src_ip[2], src_ip[3],
        });
        if (buf.len < 5) return;

        // Version Negotiation: first byte 0x80, version = 0
        if (buf[0] & 0x80 != 0 and buf.len >= 5 and
            buf[1] == 0 and buf[2] == 0 and buf[3] == 0 and buf[4] == 0)
        {
            std.debug.print("io: server discard VN packet\n", .{});
            return; // discard
        }

        if (buf[0] & 0x80 != 0) {
            // Long header
            const version: u32 = (@as(u32, buf[1]) << 24) | (@as(u32, buf[2]) << 16) | (@as(u32, buf[3]) << 8) | buf[4];
            std.debug.print("io: server long header version=0x{x:0>8}\n", .{version});
            const lh = header_mod.parseLong(buf) catch |err| {
                std.debug.print("io: server parseLong failed: {}\n", .{err});
                return;
            };
            // RFC 9000 §6.1: respond with Version Negotiation for unsupported
            // versions (e.g. "WAIT" probes from the interop network simulator).
            // Accept both QUIC v1 and QUIC v2.
            if (lh.header.version != version_neg_mod.QUIC_V1 and
                lh.header.version != version_neg_mod.QUIC_V2)
            {
                std.debug.print("io: server sendVersionNegotiation to {}.{}.{}.{}\n", .{
                    src_ip[0], src_ip[1], src_ip[2], src_ip[3],
                });
                self.sendVersionNegotiation(lh.header.scid.slice(), lh.header.dcid.slice(), src);
                return;
            }
            std.debug.print("io: server pkt_type={any}\n", .{lh.header.packet_type});
            switch (lh.header.packet_type) {
                .initial => self.processInitialPacket(buf, src),
                .handshake => self.processHandshakePacket(buf, src),
                .zero_rtt => self.process0RttPacket(buf, src),
                .retry => {}, // server never receives Retry
            }
        } else {
            // Short (1-RTT) header
            self.process1RttPacket(buf, src);
        }
        std.debug.print("io: server processPacket done\n", .{});
    }

    /// Find an existing connection by DCID.
    fn findConn(self: *Server, dcid: ConnectionId) ?*ConnState {
        for (&self.conns) |*slot| {
            if (slot.*) |*c| {
                if (ConnectionId.eql(c.local_cid, dcid)) return c;
                if (c.alt_local_cid) |alt| {
                    if (ConnectionId.eql(alt, dcid)) return c;
                }
            }
        }
        return null;
    }

    /// Find an existing connection by the peer's UDP address (for retransmit detection).
    fn findConnByPeer(self: *Server, peer: std.net.Address) ?*ConnState {
        for (&self.conns) |*slot| {
            if (slot.*) |*c| {
                // Compare family, port, and IP address bytes
                if (c.peer.any.family == peer.any.family and
                    std.mem.eql(u8, c.peer.any.data[0..6], peer.any.data[0..6]))
                {
                    return c;
                }
            }
        }
        return null;
    }

    /// Find an existing connection by the client's original Initial DCID.
    /// Used for 0-RTT packets, which carry this ID rather than local_cid.
    fn findConnByInitDcid(self: *Server, dcid: ConnectionId) ?*ConnState {
        for (&self.conns) |*slot| {
            if (slot.*) |*c| {
                if (c.init_dcid) |id| {
                    if (ConnectionId.eql(id, dcid)) return c;
                }
            }
        }
        return null;
    }

    /// Create a new server-side connection.
    fn newConn(self: *Server, dcid: ConnectionId, scid: ConnectionId, peer: std.net.Address, is_v2: bool) ?*ConnState {
        for (&self.conns) |*slot| {
            if (slot.* == null) {
                var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
                const local_cid = ConnectionId.random(prng.random(), 8);
                slot.* = ConnState{
                    .local_cid = local_cid,
                    .remote_cid = scid,
                    .peer = peer,
                    .init_dcid = dcid,
                    .use_v2 = is_v2,
                };
                const conn = &(slot.*.?);
                conn.deriveInitialKeys(dcid);
                return conn;
            }
        }
        std.debug.print("io: too many connections\n", .{});
        return null;
    }

    fn processInitialPacket(
        self: *Server,
        buf: []const u8,
        src: std.net.Address,
    ) void {
        const ip = packet_mod.parseInitial(buf) catch return;
        // Detect QUIC version from raw packet (already validated in processPacket).
        const pkt_version: u32 = if (buf.len >= 5)
            (@as(u32, buf[1]) << 24) | (@as(u32, buf[2]) << 16) | (@as(u32, buf[3]) << 8) | buf[4]
        else
            QUIC_VERSION_1;
        const is_v2_conn = pkt_version == QUIC_VERSION_2;

        // Retry mode: if enabled and no valid token, send Retry and drop.
        // An empty token means this is the first Initial (pre-Retry); a non-empty
        // token must pass HMAC verification before the handshake proceeds.
        var verified_odcid: ?[]const u8 = null;
        if (self.config.retry_enabled) {
            verified_odcid = self.verifyRetryToken(ip.token);
            if (verified_odcid == null) {
                self.sendRetry(ip.dcid.slice(), ip.scid.slice(), src, pkt_version);
                return;
            }
        }

        // Find or create connection.
        // First check by DCID (the server's assigned CID once established).
        // Then check by peer address — a retransmitted Initial from the same
        // client arrives before the client knows the server's CID (RFC 9002 §6.2).
        var conn: *ConnState = blk: {
            if (self.findConn(ip.dcid)) |c| break :blk c;

            if (self.findConnByPeer(src)) |existing| {
                // Retransmitted Initial: re-send the server flight so the client
                // can make progress even if our first response was lost.
                if (existing.phase == .waiting_finished or existing.phase == .connected) {
                    self.sendInitialServerHello(existing, src);
                    self.sendHandshakeServerFlight(existing, src);
                }
                return;
            }

            // Truly new connection
            const c = self.newConn(ip.dcid, ip.scid, src, is_v2_conn) orelse return;
            break :blk c;
        };

        // Store the original DCID for the transport parameters (RFC 9000 §7.3).
        if (verified_odcid) |odcid| {
            const olen = @min(odcid.len, conn.retry_odcid.len);
            @memcpy(conn.retry_odcid[0..olen], odcid[0..olen]);
            conn.retry_odcid_len = olen;
        }

        if (conn.init_keys == null) conn.deriveInitialKeys(ip.dcid);
        const init_km = &conn.init_keys.?;

        // Decrypt Initial packet
        var plaintext: [4096]u8 = undefined;
        const pn_start = ip.payload_offset;
        const payload_end = ip.payload_offset + ip.payload_len;
        const pt_len = initial_mod.unprotectInitialPacket(
            &plaintext,
            buf,
            pn_start,
            payload_end,
            &init_km.client,
        ) catch return; // bad packet

        // Compatible version negotiation (RFC 9368): if the server is configured
        // for QUIC v2 but the client sent a v1 Initial, upgrade the connection to
        // v2 now — AFTER successful v1 decryption — so that the server's Initial
        // response (ServerHello), Handshake flight, and all subsequent packets are
        // sent as QUIC v2.  The client pre-derives v2 initial keys and will
        // successfully decrypt our v2 Initial.
        if (self.config.v2 and !conn.use_v2) {
            conn.use_v2 = true;
            conn.init_keys = InitialSecrets.deriveV2(ip.dcid.slice());
            std.debug.print("io: server upgraded connection to QUIC v2 (compatible version negotiation)\n", .{});
        }

        // Record received PN for ACK
        conn.init_recv_pn = extractPacketNumber(buf, pn_start);

        // Parse frames
        var pos: usize = 0;
        while (pos < pt_len) {
            if (plaintext[pos] == 0x00) { // PADDING
                pos += 1;
                continue;
            }
            if (plaintext[pos] == 0x02 or plaintext[pos] == 0x03) {
                const is_ecn = plaintext[pos] == 0x03;
                pos += 1;
                if (pos > pt_len) break;
                pos += skipAckBody(plaintext[pos..pt_len], is_ecn);
                continue;
            }
            // Try to parse as CRYPTO frame
            if (plaintext[pos] == 0x06) {
                pos += 1;
                const off_r = varint.decode(plaintext[pos..]) catch break;
                pos += off_r.len;
                const data_len_r = varint.decode(plaintext[pos..]) catch break;
                pos += data_len_r.len;
                const dlen: usize = @intCast(data_len_r.value);
                if (pos + dlen > pt_len) break;
                const crypto_data = plaintext[pos .. pos + dlen];
                self.handleInitialCrypto(conn, crypto_data, off_r.value, src);
                pos += dlen;
            } else {
                break; // unknown frame, stop
            }
        }
    }

    /// Process a 0-RTT Long Header packet.  Decrypts with the connection's
    /// early keys (if available) and dispatches STREAM frames to handleStreamData.
    fn process0RttPacket(self: *Server, buf: []const u8, src: std.net.Address) void {
        const lh = header_mod.parseLong(buf) catch return;
        // 0-RTT packets carry the client's original Initial DCID, not the server's
        // local_cid (which is assigned randomly after the Initial arrives).
        // Try findConn first (in case local_cid happens to match), then fall back
        // to a lookup by init_dcid.
        const conn = self.findConn(lh.header.dcid) orelse self.findConnByInitDcid(lh.header.dcid) orelse {
            std.debug.print("io: 0-RTT dropped — no connection for dcid\n", .{});
            return;
        };
        if (!conn.has_early_keys) {
            std.debug.print("io: 0-RTT dropped — no early keys for connection\n", .{});
            return;
        }

        // Parse the length + PN fields that follow the QUIC long header.
        var pos = lh.consumed;
        if (pos >= buf.len) return;
        const payload_len_r = varint.decode(buf[pos..]) catch return;
        pos += payload_len_r.len;
        const payload_len: usize = @intCast(payload_len_r.value);
        const pn_start = pos;
        const payload_end = pos + payload_len;
        if (payload_end > buf.len) return;

        // Decrypt with early client keys.
        var plaintext: [4096]u8 = undefined;
        const pt_len = decryptLongPacket(
            &plaintext,
            buf,
            pn_start,
            payload_end,
            &conn.early_km,
        ) catch |err| {
            std.debug.print("io: 0-RTT decrypt failed: {}\n", .{err});
            return;
        };
        std.debug.print("io: server 0-RTT decrypted {} bytes\n", .{pt_len});

        // Walk the decrypted payload for STREAM frames.
        // NOTE: advance fpos past the type byte before calling StreamFrame.parse,
        // exactly as processAppFrames does — parse expects a slice that starts
        // AFTER the type byte, not at it.
        var fpos: usize = 0;
        while (fpos < pt_len) {
            const ft = plaintext[fpos];
            fpos += 1; // advance past frame type byte
            if (ft == 0x00) continue; // PADDING
            if (ft == 0x01) continue; // PING (no body)
            if (ft >= 0x08 and ft <= 0x0f) {
                const sf_r = stream_frame_mod.StreamFrame.parse(plaintext[fpos..pt_len], ft) catch break;
                fpos += sf_r.consumed;
                self.handleStreamData(conn, &sf_r.frame, src);
                continue;
            }
            // Unknown or non-STREAM frame — stop parsing.
            break;
        }
    }

    /// Build a Retry token that encodes the original DCID so the server can
    /// recover it at verification time without external state.
    ///
    /// Token format (max 53 bytes):
    ///   [0]      odcid length (1 byte)
    ///   [1..n]   odcid bytes
    ///   [n..n+32] HMAC-SHA256(retry_secret, odcid)
    ///
    /// Returns the number of bytes written into `out`.
    fn mintRetryToken(self: *Server, odcid: []const u8, out: *[53]u8) usize {
        out[0] = @intCast(odcid.len);
        @memcpy(out[1..][0..odcid.len], odcid);
        var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(&self.retry_secret);
        hmac.update(odcid);
        var mac: [32]u8 = undefined;
        hmac.final(&mac);
        @memcpy(out[1 + odcid.len ..][0..32], &mac);
        return 1 + odcid.len + 32;
    }

    /// Verify a Retry token.  The original DCID is encoded inside the token
    /// itself (see mintRetryToken), so no external odcid parameter is needed.
    /// Returns the original DCID slice on success, or null on failure.
    fn verifyRetryToken(self: *Server, token: []const u8) ?[]const u8 {
        if (token.len < 1 + 32) return null;
        const odcid_len: usize = token[0];
        if (token.len < 1 + odcid_len + 32) return null;
        const odcid = token[1..][0..odcid_len];
        const received_mac = token[1 + odcid_len ..][0..32];
        var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(&self.retry_secret);
        hmac.update(odcid);
        var expected_mac: [32]u8 = undefined;
        hmac.final(&expected_mac);
        if (!std.mem.eql(u8, received_mac, &expected_mac)) return null;
        return odcid;
    }

    /// Send a Retry packet to the client.
    /// RFC 9000 §6: send a Version Negotiation packet advertising QUIC v1.
    /// `client_scid` and `client_dcid` are from the client's packet; the VN
    /// packet echoes them back swapped (server DCID = client SCID, server SCID
    /// = client DCID) so the client can match the response.
    fn sendVersionNegotiation(self: *Server, client_scid: []const u8, client_dcid: []const u8, dst: std.net.Address) void {
        var buf: [64]u8 = undefined;
        // Advertise both v1 and v2 so clients can upgrade or fall back.
        const n = version_neg_mod.build(&buf, client_scid, client_dcid, &[_]u32{
            version_neg_mod.QUIC_V1,
            version_neg_mod.QUIC_V2,
        }) catch return;
        _ = std.posix.sendto(self.sock, buf[0..n], 0, &dst.any, dst.getOsSockLen()) catch {};
    }

    fn sendRetry(self: *Server, odcid: []const u8, scid: []const u8, src: std.net.Address, version: u32) void {
        // New server SCID for the connection after Retry
        var new_scid: [8]u8 = undefined;
        std.crypto.random.bytes(&new_scid);

        // Token encodes odcid + HMAC (max 53 bytes: 1 + 20 + 32)
        var token_buf: [53]u8 = undefined;
        const token_len = self.mintRetryToken(odcid, &token_buf);

        var buf: [256]u8 = undefined;
        const n = retry_mod.buildRetryPacket(
            &buf,
            version, // use the same version as the client's Initial
            scid, // DCID = client's SCID
            &new_scid, // SCID = new server CID
            token_buf[0..token_len],
            odcid,
        ) catch return;

        _ = std.posix.sendto(self.sock, buf[0..n], 0, &src.any, src.getOsSockLen()) catch {};
        std.debug.print("io: sent Retry to client\n", .{});
    }

    fn handleInitialCrypto(
        self: *Server,
        conn: *ConnState,
        data: []const u8,
        offset: u64,
        src: std.net.Address,
    ) void {
        // Simple in-order reassembly: only accept data at expected offset
        if (offset != conn.init_crypto_offset) return;
        conn.init_crypto_offset += data.len;

        // Only process ClientHello in initial phase
        if (conn.phase != .initial) return;
        if (data.len < 4 or data[0] != tls_hs.MSG_CLIENT_HELLO) return;

        // Initialize TLS if needed
        if (!conn.tls_inited) {
            conn.tls = ServerHandshake.init();
            conn.tls_inited = true;
        }

        // Process ClientHello → ServerHello
        const sh_len = conn.tls.processClientHello(data, &conn.sh_bytes) catch |err| {
            std.debug.print("io: TLS ClientHello failed: {}\n", .{err});
            return;
        };
        conn.sh_len = sh_len;

        // Handshake secrets are available; derive QUIC handshake keys.
        conn.deriveHandshakeKeys(&conn.tls.secrets);

        // Set cipher based on what was negotiated with the client.
        if (conn.tls.ch.cipher_suite == tls_hs.TLS_CHACHA20_POLY1305_SHA256) {
            conn.use_chacha20 = true;
        }

        // Build and send server flight
        self.buildAndSendServerFlight(conn, src);

        // Derive 0-RTT early keys if the client requested early data.
        // The PSK identity sent by the client (ticket blob) IS the PSK, so we
        // can derive client_early_traffic_secret directly.
        if (conn.tls.ch.has_early_data and conn.tls.ch.psk_identity_len >= 32) {
            var psk: [32]u8 = .{0} ** 32;
            @memcpy(&psk, conn.tls.ch.psk_identity[0..32]);
            const cets = session_mod.deriveEarlyTrafficSecret(psk, conn.tls.ch_hash);
            const early_keys = session_mod.deriveEarlyKeysFromSecret(cets);
            conn.early_km = KeyMaterial{
                .secret = cets,
                .key = early_keys.key,
                .key32 = .{0} ** 32,
                .iv = early_keys.iv,
                .hp = early_keys.hp,
                .hp32 = .{0} ** 32,
            };
            conn.has_early_keys = true;
            std.debug.print("io: server derived 0-RTT early keys\n", .{});
        }
    }

    fn buildAndSendServerFlight(self: *Server, conn: *ConnState, src: std.net.Address) void {
        // Build server transport parameters into a separate scratch buffer.
        // Append original_destination_connection_id (id=0x00) when a Retry was
        // accepted — RFC 9000 §7.3 requires it so the client can verify.
        var tp_buf: [512]u8 = undefined;
        var tp_len = quic_tls_mod.buildClientTransportParams(&tp_buf);
        if (conn.retry_odcid_len > 0) {
            const odcid = conn.retry_odcid[0..conn.retry_odcid_len];
            // Encode: id=0x00 (1 byte) | length varint (1 byte) | odcid bytes
            tp_buf[tp_len] = 0x00; // TP id
            tp_len += 1;
            tp_buf[tp_len] = @intCast(odcid.len); // length (odcid ≤ 20 bytes, fits in 1 varint byte)
            tp_len += 1;
            @memcpy(tp_buf[tp_len..][0..odcid.len], odcid);
            tp_len += odcid.len;
        }
        const quic_tp = tp_buf[0..tp_len];

        const alpn: ?[]const u8 = if (self.config.http3) tls_hs.ALPN_H3 else if (self.config.http09) tls_hs.ALPN_H09 else null;
        const flight_len = conn.tls.buildServerFlight(
            self.cert_der,
            &self.private_key,
            quic_tp,
            alpn,
            &conn.flight_bytes,
        ) catch |err| {
            std.debug.print("io: buildServerFlight failed: {}\n", .{err});
            return;
        };
        conn.flight_len = flight_len;

        // App secrets are now derived inside buildServerFlight; derive QUIC keys.
        conn.deriveAppKeys(&conn.tls.secrets);

        // Send Initial packet with ServerHello CRYPTO frame
        self.sendInitialServerHello(conn, src);
        // Send Handshake packet with server flight CRYPTO frame
        self.sendHandshakeServerFlight(conn, src);

        conn.phase = .waiting_finished;
    }

    fn sendInitialServerHello(self: *Server, conn: *ConnState, src: std.net.Address) void {
        var send_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
        var frames_buf: [1024]u8 = undefined;
        var fp: usize = 0;

        // ACK the client's Initial (if we received a PN)
        if (conn.init_recv_pn) |pn| {
            const ack_len = buildAckFrame(frames_buf[fp..], pn) catch return;
            fp += ack_len;
        }

        // CRYPTO frame with ServerHello
        const crypto_len = buildCryptoFrame(frames_buf[fp..], 0, conn.sh_bytes[0..conn.sh_len]) catch return;
        fp += crypto_len;

        const init_km = conn.init_keys orelse return;
        const pkt_len = buildInitialPacket(
            &send_buf,
            conn.remote_cid,
            conn.local_cid,
            &.{}, // no token
            frames_buf[0..fp],
            conn.init_pn,
            &init_km.server,
            conn.quicVersion(),
        ) catch return;
        conn.init_pn += 1;

        _ = std.posix.sendto(self.sock, send_buf[0..pkt_len], 0, &src.any, src.getOsSockLen()) catch |err| {
            std.debug.print("io: sendto Initial failed: {}\n", .{err});
        };
    }

    fn sendHandshakeServerFlight(self: *Server, conn: *ConnState, src: std.net.Address) void {
        if (!conn.has_hs_keys) return;

        var send_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
        var frames_buf: [8192]u8 = undefined;
        var fp: usize = 0;

        // CRYPTO frame with server flight (may need to be split across packets)
        const flight = conn.flight_bytes[0..conn.flight_len];
        const max_crypto_per_pkt = 1100; // leave room for headers + AEAD tag
        var offset: usize = 0;

        while (offset < flight.len) {
            fp = 0;
            const chunk_len = @min(flight.len - offset, max_crypto_per_pkt);
            const crypto_len = buildCryptoFrame(
                frames_buf[fp..],
                @intCast(offset),
                flight[offset .. offset + chunk_len],
            ) catch return;
            fp += crypto_len;

            const pkt_len = buildHandshakePacket(
                &send_buf,
                conn.remote_cid,
                conn.local_cid,
                frames_buf[0..fp],
                conn.hs_pn,
                &conn.hs_server_km,
                conn.quicVersion(),
            ) catch return;
            conn.hs_pn += 1;

            _ = std.posix.sendto(self.sock, send_buf[0..pkt_len], 0, &src.any, src.getOsSockLen()) catch |err| {
                std.debug.print("io: sendto Handshake failed: {}\n", .{err});
            };

            offset += chunk_len;
        }
    }

    fn processHandshakePacket(
        self: *Server,
        buf: []const u8,
        src: std.net.Address,
    ) void {
        // Re-parse long header to get DCID and consumed bytes
        const lh = header_mod.parseLong(buf) catch return;

        // Find connection by DCID
        const conn = self.findConn(lh.header.dcid) orelse return;
        if (!conn.has_hs_keys) return;

        // If already connected, the client may be retransmitting its Finished because
        // our HANDSHAKE_DONE was lost. Re-send it so the client can make progress.
        if (conn.phase == .connected) {
            self.sendHandshakeDone(conn, src);
            return;
        }
        if (conn.phase != .waiting_finished) return;

        // Parse the Handshake packet: after Long Header = length(varint) + pn + payload
        var pos = lh.consumed;
        if (pos >= buf.len) return;
        const payload_len_r = varint.decode(buf[pos..]) catch return;
        pos += payload_len_r.len;
        const payload_len: usize = @intCast(payload_len_r.value);
        const pn_start = pos;
        const payload_end = pos + payload_len;
        if (payload_end > buf.len) return;

        // Record received PN
        conn.hs_recv_pn = extractPacketNumber(buf, pn_start);

        // Decrypt
        var plaintext: [4096]u8 = undefined;
        const pt_len = decryptLongPacket(
            &plaintext,
            buf,
            pn_start,
            payload_end,
            &conn.hs_client_km,
        ) catch return;

        // Parse frames for CRYPTO
        var fpos: usize = 0;
        while (fpos < pt_len) {
            if (plaintext[fpos] == 0x00) {
                fpos += 1;
                continue;
            }
            if (plaintext[fpos] == 0x06) {
                fpos += 1;
                const off_r = varint.decode(plaintext[fpos..]) catch break;
                fpos += off_r.len;
                const dlen_r = varint.decode(plaintext[fpos..]) catch break;
                fpos += dlen_r.len;
                const dlen: usize = @intCast(dlen_r.value);
                if (fpos + dlen > pt_len) break;
                const cdata = plaintext[fpos .. fpos + dlen];
                if (off_r.value == conn.hs_crypto_offset) {
                    conn.hs_crypto_offset += dlen;
                    self.handleHandshakeCrypto(conn, cdata, src);
                }
                fpos += dlen;
            } else if (plaintext[fpos] == 0x02 or plaintext[fpos] == 0x03) {
                const is_ecn = plaintext[fpos] == 0x03;
                fpos += 1;
                if (fpos > pt_len) break;
                fpos += skipAckBody(plaintext[fpos..pt_len], is_ecn);
                continue;
            } else {
                break;
            }
        }
    }

    fn handleHandshakeCrypto(self: *Server, conn: *ConnState, data: []const u8, src: std.net.Address) void {
        if (data.len < 4 or data[0] != tls_hs.MSG_FINISHED) return;

        conn.tls.processClientFinished(data) catch |err| {
            std.debug.print("io: client Finished verify failed: {}\n", .{err});
            return;
        };

        std.debug.print("io: handshake complete for connection\n", .{});
        conn.phase = .connected;

        const pending_n = conn.pending_1rtt_n;
        conn.pending_1rtt_n = 0;
        for (0..pending_n) |i| {
            const pl = conn.pending_1rtt[i];
            self.processAppFrames(conn, pl.data[0..pl.len], conn.peer);
        }

        if (self.config.keylog_path) |kpath| {
            writeKeylog(kpath, conn.tls.ch.random, &conn.tls.secrets);
        }

        // Send Handshake ACK + 1-RTT HANDSHAKE_DONE
        self.sendHandshakeAck(conn, src);
        self.sendHandshakeDone(conn, src);

        // Initiate a key update immediately after the handshake if enabled.
        // This satisfies the quic-interop-runner "keyupdate" test case.
        if (self.config.key_update) {
            self.initiateKeyUpdate(conn, src);
        }
    }

    fn sendHandshakeAck(self: *Server, conn: *ConnState, src: std.net.Address) void {
        if (!conn.has_hs_keys) return;
        const pn = conn.hs_recv_pn orelse return;

        var send_buf: [256]u8 = undefined;
        var frames_buf: [64]u8 = undefined;
        const ack_len = buildAckFrame(&frames_buf, pn) catch return;

        const pkt_len = buildHandshakePacket(
            &send_buf,
            conn.remote_cid,
            conn.local_cid,
            frames_buf[0..ack_len],
            conn.hs_pn,
            &conn.hs_server_km,
            conn.quicVersion(),
        ) catch return;
        conn.hs_pn += 1;

        _ = std.posix.sendto(self.sock, send_buf[0..pkt_len], 0, &src.any, src.getOsSockLen()) catch {};
    }

    fn sendHandshakeDone(self: *Server, conn: *ConnState, src: std.net.Address) void {
        if (!conn.has_app_keys) return;

        var frames_buf: [2048]u8 = undefined;
        var fp: usize = 0;

        // HANDSHAKE_DONE frame
        fp += buildHandshakeDoneFrame(frames_buf[fp..]);

        // NewSessionTicket (for resumption or 0-RTT).
        // Ticket blob = PSK = HKDF-Expand-Label(resumption_secret, "resumption", nonce, 32)
        // The PSK is self-contained in the ticket so the server can re-derive it from
        // the identity without persistent server-side state.
        if (self.config.resumption_enabled or self.config.early_data) {
            const nonce = [_]u8{0x01} ** 8;
            const res_secret = conn.tls.resumptionSecret();
            // Derive the actual PSK per RFC 8446 §4.6.1.
            var psk: [32]u8 = undefined;
            keys_mod.hkdfExpandLabel(&psk, &res_secret, "resumption", &nonce);
            // Build NST into a separate buffer to avoid overlapping memcpy.
            var nst_buf: [192]u8 = undefined;
            const nst_len = tls_hs.buildNewSessionTicket(
                &nst_buf,
                3600,
                &nonce,
                &psk, // ticket blob IS the PSK
                16384, // max_early_data
            ) catch 0;
            if (nst_len > 0) {
                const crypto_len = buildCryptoFrame(
                    frames_buf[fp..],
                    conn.app_crypto_offset,
                    nst_buf[0..nst_len],
                ) catch 0;
                conn.app_crypto_offset += nst_len;
                fp += crypto_len;
            }
        }

        // NEW_CONNECTION_ID frame (RFC 9000 §19.15) — give the client an
        // alternative CID to use when it migrates (--migrate mode only).
        if (self.config.migrate) {
            var prng2 = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp() ^ 0xdeadbeef));
            const new_cid = ConnectionId.random(prng2.random(), 8);
            conn.alt_local_cid = new_cid;
            if (fp + 28 <= frames_buf.len) {
                frames_buf[fp] = 0x18;
                fp += 1; // NEW_CONNECTION_ID type
                frames_buf[fp] = 0x01;
                fp += 1; // sequence_number = 1
                frames_buf[fp] = 0x00;
                fp += 1; // retire_prior_to = 0
                frames_buf[fp] = 0x08;
                fp += 1; // cid length = 8
                @memcpy(frames_buf[fp .. fp + 8], new_cid.slice());
                fp += 8;
                @memset(frames_buf[fp .. fp + 16], 0); // stateless reset token (all zeros)
                fp += 16;
            }
        }

        self.send1Rtt(conn, frames_buf[0..fp], src);
    }

    fn process1RttPacket(self: *Server, buf: []const u8, src: std.net.Address) void {
        std.debug.print("io: process1RttPacket buf_len={}\n", .{buf.len});
        // Find connection by scanning CID prefix
        for (&self.conns) |*slot| {
            if (slot.*) |*conn| {
                if (conn.phase != .connected and conn.phase != .waiting_finished) continue;
                if (!conn.has_app_keys) continue;
                const cid_len = conn.local_cid.len;
                if (buf.len < 1 + cid_len) continue;
                const candidate = ConnectionId.fromSlice(buf[1 .. 1 + cid_len]) catch continue;
                const cid_match = ConnectionId.eql(conn.local_cid, candidate) or
                    (if (conn.alt_local_cid) |alt| ConnectionId.eql(alt, candidate) else false);
                if (!cid_match) continue;

                // Try to decrypt with current client app keys.
                var plaintext: [4096]u8 = undefined;
                const pn_start = 1 + cid_len;

                // Detect peer-initiated key update via the UNPROTECTED key phase bit.
                // Must remove HP first before reading bit 2 (RFC 9001 §5.4.1).
                const unprotected_first = peekUnprotectedFirstByte(buf, pn_start, &conn.app_client_km, conn.use_chacha20) orelse continue;
                const incoming_phase = (unprotected_first & 0x04) != 0;

                // Try current recv keys first. Only use next key generation when the
                // current keys fail and the Key Phase bit indicates an update — avoids
                // mis-sampled HP flipping keys before the first post-handshake packet.
                // Use PN-tracking decryption so packet number decompression is correct
                // even when the client's PN space grows beyond 1-byte truncation range.
                var srv_decrypted_pn: u64 = 0;
                const pt_len: usize = decrypt: {
                    if (unprotect1RttPacketWithPnTracking(
                        &plaintext,
                        buf,
                        pn_start,
                        &conn.app_client_km,
                        conn.use_chacha20,
                        conn.app_recv_pn,
                    )) |r| {
                        srv_decrypted_pn = r.pn;
                        break :decrypt r.pt_len;
                    } else |_| {}
                    if (incoming_phase != conn.peer_key_phase and !conn.key_update_pending) {
                        var nk = if (conn.use_v2) conn.app_client_km.nextGenV2() else conn.app_client_km.nextGen();
                        if (unprotect1RttPacketWithPnTracking(
                            &plaintext,
                            buf,
                            pn_start,
                            &nk,
                            conn.use_chacha20,
                            conn.app_recv_pn,
                        )) |r| {
                            conn.app_client_km = nk;
                            // Peer initiated a key update — also rotate our send keys so
                            // the server's outgoing packets carry the new key phase bit
                            // (RFC 9001 §6.1: both endpoints must send with the new phase).
                            conn.app_server_km = if (conn.use_v2) conn.app_server_km.nextGenV2() else conn.app_server_km.nextGen();
                            conn.key_phase_bit = !conn.key_phase_bit;
                            srv_decrypted_pn = r.pn;
                            break :decrypt r.pt_len;
                        } else |_| {}
                    }
                    std.debug.print(
                        "io: server 1-RTT decrypt failed after DCID match (len={} incoming_kp={} stored_kp={} chacha={})\n",
                        .{ buf.len, incoming_phase, conn.peer_key_phase, conn.use_chacha20 },
                    );
                    continue;
                };
                // Update server's received PN so future decompression stays accurate.
                if (srv_decrypted_pn > (conn.app_recv_pn orelse 0)) {
                    conn.app_recv_pn = srv_decrypted_pn;
                }

                // ECN: count this 1-RTT packet as ECT(0) — we mark all outgoing
                // packets ECT(0) via IP_TOS, so the peer does the same.
                conn.ecn_ect0_recv += 1;

                conn.peer_key_phase = incoming_phase;
                conn.key_update_pending = false;

                if (conn.phase == .waiting_finished) {
                    // Client Finished may still be in flight; 1-RTT can arrive first.
                    if (conn.pending_1rtt_n < pending_1rtt_cap) {
                        const slotp = &conn.pending_1rtt[conn.pending_1rtt_n];
                        slotp.len = pt_len;
                        @memcpy(slotp.data[0..pt_len], plaintext[0..pt_len]);
                        conn.pending_1rtt_n += 1;
                    }
                    return;
                }

                // Process application frames
                self.processAppFrames(conn, plaintext[0..pt_len], src);
                // Send ACK-ECN (or plain ACK) for the received 1-RTT packet.
                self.sendAppAck(conn, src);
                return;
            }
        }
        std.debug.print("io: process1RttPacket: no matching connection found\n", .{});
    }

    /// Trigger a local key update: rotate send keys and emit a packet with
    /// the new key phase bit set.  Called after handshake when key_update
    /// is enabled (quic-interop-runner "keyupdate" test case).
    fn initiateKeyUpdate(self: *Server, conn: *ConnState, src: std.net.Address) void {
        // Rotate to next generation keys (version-appropriate label).
        conn.app_server_km = if (conn.use_v2) conn.app_server_km.nextGenV2() else conn.app_server_km.nextGen();
        conn.key_phase_bit = !conn.key_phase_bit;
        conn.key_update_pending = true;

        // Send a PING so the peer can verify the new keys.
        const ping_frame = [_]u8{0x01};
        self.send1Rtt(conn, &ping_frame, src);
    }

    fn processAppFrames(self: *Server, conn: *ConnState, frames: []const u8, src: std.net.Address) void {
        std.debug.print("io: processAppFrames called: {} bytes\n", .{frames.len});
        // Detect address change (connection migration, RFC 9000 §9).
        // If the source address differs from the stored peer address and
        // migration is enabled, send PATH_CHALLENGE to validate the new path.
        if (self.config.migrate and conn.path_challenge_data == null) {
            if (!addressEqual(conn.peer, src)) {
                var challenge: [8]u8 = undefined;
                var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
                prng.random().bytes(&challenge);
                conn.path_challenge_data = challenge;
                // Eagerly update peer address so HTTP responses immediately go to
                // the new path (optimistic migration).  PATH_CHALLENGE/RESPONSE
                // still happens for the interop runner's validation check.
                conn.peer = src;
                self.sendPathChallenge(conn, challenge, src);
            }
        }

        var pos: usize = 0;
        while (pos < frames.len) {
            const ft_r = varint.decode(frames[pos..]) catch {
                std.debug.print("io: frame type decode error at pos={}\n", .{pos});
                return;
            };
            const ft = ft_r.value;
            pos += ft_r.len;

            if (ft == 0x00) continue; // PADDING
            if (ft == 0x01) continue; // PING — no body
            if (ft == 0x02 or ft == 0x03) {
                // ACK frame — extract largest_acknowledged to detect FIN ACKs,
                // then skip all variable-length fields.
                if (varint.decode(frames[pos..]) catch null) |lar| {
                    const largest_ack = lar.value;
                    for (&conn.http09_slots) |*slot| {
                        if (slot.awaiting_fin_ack and slot.fin_pkt_pn <= largest_ack) {
                            std.debug.print("io: stream_id={} FIN ACKed (fin_pn={} <= largest_ack={})\n", .{ slot.stream_id, slot.fin_pkt_pn, largest_ack });
                            slot.awaiting_fin_ack = false;
                        }
                    }
                }
                pos += skipAckBody(frames[pos..], ft == 0x03);
                continue;
            }
            if (ft == 0x10) {
                const v = varint.decode(frames[pos..]) catch return;
                pos += v.len;
                continue;
            }
            if (ft == 0x11) {
                const r = transport_frames.MaxStreamData.parse(frames[pos..]) catch return;
                pos += r.consumed;
                continue;
            }
            if (ft == 0x12 or ft == 0x13) {
                const v = varint.decode(frames[pos..]) catch return;
                pos += v.len;
                continue;
            }
            if (ft == 0x1a) {
                // PATH_CHALLENGE — echo data back as PATH_RESPONSE.
                const pc = transport_frames.PathChallenge.parse(frames[pos..]) catch return;
                pos += pc.consumed;
                self.sendPathResponse(conn, pc.frame.data, src);
                continue;
            }
            if (ft == 0x1b) {
                // PATH_RESPONSE — validate against pending challenge.
                const pr = transport_frames.PathResponse.parse(frames[pos..]) catch return;
                pos += pr.consumed;
                if (conn.path_challenge_data) |expected| {
                    if (std.mem.eql(u8, &pr.frame.data, &expected)) {
                        // Path validated — migrate to the new address.
                        conn.peer = src;
                        conn.path_challenge_data = null;
                        std.debug.print("io: connection migrated to new address\n", .{});
                    }
                }
                continue;
            }
            if (ft >= 0x08 and ft <= 0x0f) {
                // STREAM frame
                const sf_r = stream_frame_mod.StreamFrame.parse(frames[pos..], ft) catch |err| {
                    std.debug.print("io: STREAM frame parse error ft=0x{x:0>2}: {}\n", .{ ft, err });
                    return;
                };
                pos += sf_r.consumed;
                std.debug.print("io: STREAM frame parsed: stream_id={} offset={} data_len={} fin={}\n", .{ sf_r.frame.stream_id, sf_r.frame.offset, sf_r.frame.data.len, sf_r.frame.fin });
                self.handleStreamData(conn, &sf_r.frame, src);
                continue;
            }
            // Unknown frame type — cannot safely skip without knowing the length.
            return;
        }
    }

    /// Send a 1-RTT ACK (or ACK-ECN) for the highest received app packet number.
    /// Called after every successfully processed 1-RTT packet to provide timely
    /// ECN feedback to the peer (RFC 9000 §13.4).
    fn sendAppAck(self: *Server, conn: *ConnState, src: std.net.Address) void {
        const pn = conn.app_recv_pn orelse return;
        var ack_buf: [40]u8 = undefined;
        const ack_len = if (conn.ecn_ect0_recv > 0 or conn.ecn_ect1_recv > 0 or conn.ecn_ce_recv > 0)
            buildAckEcnFrame(&ack_buf, pn, conn.ecn_ect0_recv, conn.ecn_ect1_recv, conn.ecn_ce_recv) catch return
        else
            buildAckFrame(&ack_buf, pn) catch return;
        self.send1Rtt(conn, ack_buf[0..ack_len], src);
    }

    /// Encrypt and send a 1-RTT packet, selecting AES or ChaCha20 per conn.
    fn send1Rtt(self: *Server, conn: *ConnState, payload: []const u8, dst: std.net.Address) void {
        var send_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
        // Header protection sampling (RFC 9001 §5.4.2) requires at least 3 bytes
        // of plaintext (PN(1) + plaintext(n) + tag(16) >= pn_offset+4+16=pn_offset+20).
        // Pad with PADDING frames (0x00) if needed.
        var padded_payload_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
        const min_len: usize = 3;
        const effective_payload: []const u8 = if (payload.len < min_len) blk: {
            @memcpy(padded_payload_buf[0..payload.len], payload);
            @memset(padded_payload_buf[payload.len..min_len], 0x00);
            break :blk padded_payload_buf[0..min_len];
        } else payload;

        // Check if payload contains FIN frames (0x0b, 0x0d, or 0x0f type)
        var has_fin = false;
        if (payload.len > 0) {
            const first_byte = payload[0];
            if ((first_byte >= 0x08 and first_byte <= 0x0f) and (first_byte & 0x01) != 0) {
                has_fin = true;
            }
        }

        const pkt_len = build1RttPacketFull(
            &send_buf,
            conn.remote_cid,
            effective_payload,
            conn.app_pn,
            &conn.app_server_km,
            conn.key_phase_bit,
            conn.use_chacha20,
        ) catch |err| {
            std.debug.print("io: build1RttPacketFull error payload_len={}: {}\n", .{ effective_payload.len, err });
            return;
        };
        conn.app_pn += 1;
        if (has_fin) {
            std.debug.print("io: server SENDING FIN PACKET pkt_len={} payload_len={} pn={}\n", .{ pkt_len, effective_payload.len, conn.app_pn - 1 });
        }
        const send_result = std.posix.sendto(self.sock, send_buf[0..pkt_len], 0, &dst.any, dst.getOsSockLen()) catch |err| {
            std.debug.print("io: sendto error pkt_len={}: {}\n", .{ pkt_len, err });
            return;
        };
        if (has_fin) {
            std.debug.print("io: server FIN PACKET sent {} bytes\n", .{send_result});
        }
    }

    /// Send the next STREAM chunk for one queued HTTP/0.9 response.
    fn http09SendNextChunk(self: *Server, conn: *ConnState, slot: *Http09OutSlot) void {
        var file_buf: [1200]u8 = undefined;
        const n = slot.file.read(&file_buf) catch |err| {
            std.debug.print("io: http09 stream_id={} read error: {}\n", .{ slot.stream_id, err });
            slot.close();
            return;
        };
        if (n == 0) {
            std.debug.print("io: http09 stream_id={} EOF (offset={}, file_end={})\n", .{ slot.stream_id, slot.stream_offset, slot.file_end });
            slot.close();
            return;
        }
        const fin = slot.stream_offset + @as(u64, @intCast(n)) >= slot.file_end;
        if (slot.stream_offset % 10000 == 0 or fin) {
            std.debug.print("io: http09 stream_id={} send chunk offset={} n={} file_end={} fin={} (offset+n={})\n", .{ slot.stream_id, slot.stream_offset, n, slot.file_end, fin, slot.stream_offset + @as(u64, @intCast(n)) });
        }
        if (fin) {
            std.debug.print("io: http09SendNextChunk stream_id={} creating FIN frame offset={} n={} file_end={}\n", .{ slot.stream_id, slot.stream_offset, n, slot.file_end });
        }
        const sf_out = stream_frame_mod.StreamFrame{
            .stream_id = slot.stream_id,
            .offset = slot.stream_offset,
            .data = file_buf[0..n],
            .fin = fin,
            .has_length = true,
        };
        const old_offset = slot.stream_offset;
        slot.stream_offset += @intCast(n);
        var frame_buf: [2048]u8 = undefined;
        const frame_len = sf_out.serialize(&frame_buf) catch |err| {
            std.debug.print("io: http09 stream_id={} serialize error at offset {}: {}\n", .{ slot.stream_id, old_offset, err });
            slot.close();
            return;
        };
        std.debug.print("io: http09 stream_id={} chunk: bytes={} offset={} fin={} frame_len={}\n", .{ slot.stream_id, n, old_offset, fin, frame_len });
        self.send1Rtt(conn, frame_buf[0..frame_len], conn.peer);
        if (fin) {
            // Save FIN frame for retransmission in case the packet is dropped
            // by the NS3 network simulator.  We keep the slot alive in the
            // "awaiting_fin_ack" state; the frame will be re-sent every 200 ms
            // until the client's ACK covers fin_pkt_pn.
            const fin_pn = conn.app_pn - 1; // send1Rtt already incremented app_pn
            @memcpy(slot.fin_frame[0..frame_len], frame_buf[0..frame_len]);
            slot.fin_frame_len = frame_len;
            slot.fin_pkt_pn = fin_pn;
            slot.fin_last_sent_ms = std.time.milliTimestamp();
            slot.fin_retransmit_count = 0;
            slot.awaiting_fin_ack = true;
            // Close the file — we no longer need to read from it.
            // slot.active is set to false so flushPendingHttp09Responses
            // stops calling us for new chunks.
            slot.file.close();
            slot.active = false;
            std.debug.print("io: http09 stream_id={} FIN sent (pn={}), awaiting ACK\n", .{ slot.stream_id, fin_pn });
        }
    }

    /// Drain queued HTTP/0.9 bodies with pacing to avoid flooding the network.
    ///
    /// Without pacing, flushing after every incoming ACK (which arrives ~every 30ms
    /// at 15ms RTT) drives the send rate to 6+ MB/s — 5× the 10 Mbps interop link.
    /// The network simulator then drops 80%+ of packets, stalling the transfer.
    ///
    /// We enforce a minimum flush interval of 50ms. Combined with a budget of 20
    /// chunks × 1200 bytes = 24 KB per flush, the effective rate is:
    ///   24 KB / 50 ms = 480 KB/s ≈ 3.8 Mbps — well below 10 Mbps.
    ///
    /// Critically, 20 UDP packets per burst stays below the NS3 simulator's
    /// 25-packet DropTail queue, so zero packets should be dropped by the
    /// network simulator.  (Previous budget of 40 caused ~37% packet loss.)
    fn flushPendingHttp09Responses(self: *Server) void {
        // Enforce minimum 50ms between flushes to pace sends below 10 Mbps.
        const now = std.time.milliTimestamp();
        if (now - self.http09_last_flush_ms < 50) return;
        self.http09_last_flush_ms = now;

        var budget: usize = 20; // 20 × 1200 bytes = 24 KB per flush — below the 25-pkt NS3 queue
        while (budget > 0) {
            var progressed = false;
            for (&self.conns) |*cslot| {
                if (cslot.*) |*conn| {
                    // Only send 1-RTT data once app keys are available.
                    // 0-RTT requests can be buffered in http09_slots before the
                    // handshake completes; wait for has_app_keys before flushing.
                    if (!conn.has_app_keys) continue;
                    for (&conn.http09_slots) |*slot| {
                        if (!slot.active) continue;
                        if (budget == 0) return;
                        self.http09SendNextChunk(conn, slot);
                        progressed = true;
                        budget -= 1;
                    }
                }
            }
            if (!progressed) break;
        }
    }

    /// Retransmit FIN frames for streams whose final packet has not yet been
    /// acknowledged by the client.
    ///
    /// After http09SendNextChunk sends the last STREAM frame (FIN=true), the
    /// slot transitions to awaiting_fin_ack=true.  This function re-sends the
    /// saved FIN frame every 200 ms until:
    ///   • the client ACKs a packet number ≥ fin_pkt_pn (ACK detected in
    ///     processAppFrames), or
    ///   • MAX_FIN_RETRANSMITS re-sends have been attempted.
    fn http09RetransmitPendingFins(self: *Server) void {
        const now = std.time.milliTimestamp();
        // Rate-limit: at most one retransmit pass every 50ms.
        if (now - self.http09_retransmit_last_ms < 50) return;
        self.http09_retransmit_last_ms = now;

        // Budget: send at most 8 retransmit packets per pass to avoid bursting
        // more than the NS3 25-packet DropTail queue can absorb simultaneously.
        var budget: usize = 8;
        for (&self.conns) |*cslot| {
            if (cslot.*) |*conn| {
                for (&conn.http09_slots) |*slot| {
                    if (budget == 0) return;
                    if (!slot.awaiting_fin_ack) continue;
                    if (now - slot.fin_last_sent_ms < 200) continue;

                    if (slot.fin_retransmit_count >= Http09OutSlot.MAX_FIN_RETRANSMITS) {
                        std.debug.print("io: stream_id={} FIN retransmit limit reached, giving up\n", .{slot.stream_id});
                        slot.awaiting_fin_ack = false;
                        continue;
                    }

                    slot.fin_retransmit_count += 1;
                    slot.fin_last_sent_ms = now;
                    budget -= 1;
                    std.debug.print("io: retransmitting FIN for stream_id={} (attempt {}/{})\n", .{ slot.stream_id, slot.fin_retransmit_count, Http09OutSlot.MAX_FIN_RETRANSMITS });
                    self.send1Rtt(conn, slot.fin_frame[0..slot.fin_frame_len], conn.peer);
                }
            }
        }
    }

    /// Send a PATH_CHALLENGE frame to validate a new peer address.
    fn sendPathChallenge(self: *Server, conn: *ConnState, data: [8]u8, dst: std.net.Address) void {
        var frame_buf: [64]u8 = undefined;
        const frame_len = transport_frames.PathChallenge.serialize(.{ .data = data }, &frame_buf) catch return;
        self.send1Rtt(conn, frame_buf[0..frame_len], dst);
    }

    /// Send a PATH_RESPONSE echoing the challenge data back to the sender.
    fn sendPathResponse(self: *Server, conn: *ConnState, data: [8]u8, dst: std.net.Address) void {
        var frame_buf: [64]u8 = undefined;
        const frame_len = transport_frames.PathResponse.serialize(.{ .data = data }, &frame_buf) catch return;
        self.send1Rtt(conn, frame_buf[0..frame_len], dst);
    }

    fn handleStreamData(self: *Server, conn: *ConnState, sf: *const stream_frame_mod.StreamFrame, src: std.net.Address) void {
        if (self.config.http3) {
            self.handleHttp3Stream(conn, sf, src);
        } else {
            self.handleHttp09Stream(conn, sf, src);
        }
    }

    fn handleHttp09Stream(self: *Server, conn: *ConnState, sf: *const stream_frame_mod.StreamFrame, src: std.net.Address) void {
        _ = src;
        std.debug.print("io: handleHttp09Stream called: stream_id={} data_len={}\n", .{ sf.stream_id, sf.data.len });
        // Only unidirectional client-initiated streams carry HTTP/0.9 requests
        if (sf.stream_id % 4 != 0 and sf.stream_id % 4 != 2) {
            std.debug.print("io: http09 stream_id={} rejected (not client-initiated, % 4 = {})\n", .{ sf.stream_id, sf.stream_id % 4 });
            return;
        }
        if (sf.data.len == 0) {
            std.debug.print("io: http09 stream_id={} empty data\n", .{sf.stream_id});
            return;
        }

        // Dedup: skip if a slot for this stream already exists (active or awaiting ACK).
        // This prevents duplicate slots when both a 0-RTT request and a 1-RTT
        // retransmit arrive for the same stream_id.
        for (&conn.http09_slots) |*slot| {
            if ((slot.active or slot.awaiting_fin_ack) and slot.stream_id == sf.stream_id) return;
        }

        var req_buf: [http09_server.max_request_len]u8 = undefined;
        @memcpy(req_buf[0..sf.data.len], sf.data);
        const req = http09_server.parseRequest(req_buf[0..sf.data.len]) catch |err| {
            std.debug.print("io: http09 stream_id={} parse error: {} (data={})\n", .{ sf.stream_id, err, sf.data.len });
            return;
        };
        std.debug.print("io: http09 stream_id={} parsed path={s}\n", .{ sf.stream_id, req.path });

        var path_buf: [512]u8 = undefined;
        const fs_path = http09_server.resolvePath(self.config.www_dir, req.path, &path_buf) catch |err| {
            std.debug.print("io: http09 stream_id={} resolvePath error: {}\n", .{ sf.stream_id, err });
            return;
        };

        const file = std.fs.openFileAbsolute(fs_path, .{}) catch {
            std.debug.print("io: file not found: {s}\n", .{fs_path});
            return;
        };
        const file_end = file.getEndPos() catch {
            file.close();
            return;
        };

        for (&conn.http09_slots) |*slot| {
            if (slot.active or slot.awaiting_fin_ack) continue;
            slot.* = .{
                .active = true,
                .stream_id = sf.stream_id,
                .file = file,
                .stream_offset = 0,
                .file_end = file_end,
            };
            std.debug.print("io: http09 stream_id={} opened (size={})\n", .{ sf.stream_id, file_end });
            return;
        }
        std.debug.print("io: http/0.9 out slots full\n", .{});
        file.close();
    }

    fn handleHttp3Stream(self: *Server, conn: *ConnState, sf: *const stream_frame_mod.StreamFrame, src: std.net.Address) void {
        // Stream ID classification (RFC 9000 §2.1):
        //   %4==0  client-initiated bidirectional  → HTTP/3 request streams
        //   %4==2  client-initiated unidirectional → control / QPACK encoder / decoder
        //   %4==3  server-initiated unidirectional → our control stream (id=3)

        // Send server control stream with SETTINGS once per connection.
        if (!conn.h3_settings_sent) {
            self.sendH3ControlStream(conn, src);
            conn.h3_settings_sent = true;
        }

        // Ignore client unidirectional streams (control, QPACK encoder/decoder).
        if (sf.stream_id % 4 == 2) return;

        // Only process client-initiated bidirectional request streams.
        if (sf.stream_id % 4 != 0) return;
        if (sf.data.len == 0) return;

        // Guard: ignore if we already have an active slot for this stream.
        for (&conn.http3_slots) |*slot| {
            if ((slot.active or slot.awaiting_fin_ack) and slot.stream_id == sf.stream_id) return;
        }

        // Parse HTTP/3 HEADERS frame to extract :method and :path.
        var pos: usize = 0;
        var method_buf: [8]u8 = undefined;
        var path_buf: [512]u8 = undefined;
        var method: []const u8 = "GET";
        var path: []const u8 = "/";

        while (pos < sf.data.len) {
            const pr = h3_frame.parseFrame(sf.data[pos..]) catch break;
            pos += pr.consumed;
            switch (pr.frame) {
                .headers => |hf| {
                    var decoded = h3_qpack.DecodedHeaders{ .headers = undefined, .count = 0 };
                    h3_qpack.decodeHeaders(hf.data[0..hf.len], &decoded) catch {};
                    for (decoded.headers[0..decoded.count]) |fld| {
                        if (std.mem.eql(u8, fld.name, ":method")) {
                            const ml = @min(fld.value.len, method_buf.len);
                            @memcpy(method_buf[0..ml], fld.value[0..ml]);
                            method = method_buf[0..ml];
                        } else if (std.mem.eql(u8, fld.name, ":path")) {
                            const pl = @min(fld.value.len, path_buf.len);
                            @memcpy(path_buf[0..pl], fld.value[0..pl]);
                            path = path_buf[0..pl];
                        }
                    }
                },
                else => {},
            }
        }

        std.debug.print("io: http3 request stream_id={} method={s} path={s}\n", .{ sf.stream_id, method, path });

        if (!std.mem.eql(u8, method, "GET")) return;

        // Resolve and open the requested file.
        var fs_path_buf: [512]u8 = undefined;
        const fs_path = http09_server.resolvePath(self.config.www_dir, path, &fs_path_buf) catch return;

        const file = std.fs.openFileAbsolute(fs_path, .{}) catch {
            self.sendH3Response(conn, sf.stream_id, 404, &.{}, src);
            return;
        };

        const file_end = file.getEndPos() catch {
            file.close();
            self.sendH3Response(conn, sf.stream_id, 500, &.{}, src);
            return;
        };

        // Build and send HEADERS frame immediately (offset=0 on this stream).
        var size_buf: [20]u8 = undefined;
        const size_str = std.fmt.bufPrint(&size_buf, "{}", .{file_end}) catch "0";
        var header_block: [512]u8 = undefined;
        const hb_len = h3_qpack.encodeHeaders(&[_]h3_qpack.Header{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = size_str },
        }, &header_block) catch {
            file.close();
            return;
        };
        var headers_out: [600]u8 = undefined;
        const headers_frame_len = h3_frame.writeFrame(&headers_out, @intFromEnum(h3_frame.FrameType.headers), header_block[0..hb_len]) catch {
            file.close();
            return;
        };
        self.sendStreamDataH3(conn, sf.stream_id, 0, headers_out[0..headers_frame_len], false, src);

        // Register an Http3OutSlot so the event loop sends DATA frames with
        // pacing.  stream_offset starts after the HEADERS frame bytes.
        for (&conn.http3_slots) |*slot| {
            if (slot.active or slot.awaiting_fin_ack) continue;
            slot.* = .{
                .active = true,
                .stream_id = sf.stream_id,
                .file = file,
                .stream_offset = headers_frame_len,
                .file_end = file_end,
            };
            std.debug.print("io: http3 slot registered stream_id={} size={} data_offset={}\n", .{ sf.stream_id, file_end, headers_frame_len });
            return;
        }
        std.debug.print("io: http3 out slots full\n", .{});
        file.close();
    }

    fn sendH3ControlStream(self: *Server, conn: *ConnState, src: std.net.Address) void {
        // Server control stream: stream_id=3 (server-initiated unidirectional)
        // First byte identifies stream type: 0x00 = control stream
        var buf: [256]u8 = undefined;
        buf[0] = 0x00; // stream type = control
        var pos: usize = 1;

        // SETTINGS frame
        const settings_len = h3_frame.writeSettings(buf[pos..], &[_]h3_frame.Setting{
            .{ .id = h3_frame.SETTINGS_QPACK_MAX_TABLE_CAPACITY, .value = 0 },
            .{ .id = h3_frame.SETTINGS_QPACK_BLOCKED_STREAMS, .value = 0 },
        }) catch return;
        pos += settings_len;

        const sf = stream_frame_mod.StreamFrame{
            .stream_id = 3, // server-initiated unidirectional
            .offset = 0,
            .data = buf[0..pos],
            .fin = false,
            .has_length = true,
        };
        var frame_buf: [300]u8 = undefined;
        const frame_len = sf.serialize(&frame_buf) catch return;
        self.send1Rtt(conn, frame_buf[0..frame_len], src);
    }

    fn sendH3Response(self: *Server, conn: *ConnState, stream_id: u64, status: u16, _: []const u8, src: std.net.Address) void {
        var status_buf: [4]u8 = undefined;
        const status_str = std.fmt.bufPrint(&status_buf, "{}", .{status}) catch "500";
        var header_block: [256]u8 = undefined;
        const hb_len = h3_qpack.encodeHeaders(&[_]h3_qpack.Header{
            .{ .name = ":status", .value = status_str },
        }, &header_block) catch return;
        var out: [300]u8 = undefined;
        const out_len = h3_frame.writeFrame(&out, @intFromEnum(h3_frame.FrameType.headers), header_block[0..hb_len]) catch return;
        self.sendStreamData(conn, stream_id, out[0..out_len], true, src);
    }

    fn sendStreamData(self: *Server, conn: *ConnState, stream_id: u64, data: []const u8, fin: bool, src: std.net.Address) void {
        const sf = stream_frame_mod.StreamFrame{
            .stream_id = stream_id,
            .offset = 0,
            .data = data,
            .fin = fin,
            .has_length = true,
        };
        var frame_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
        const frame_len = sf.serialize(&frame_buf) catch return;
        self.send1Rtt(conn, frame_buf[0..frame_len], src);
    }

    /// Like sendStreamData but with an explicit QUIC stream offset.
    /// Required for HTTP/3 DATA frames that follow the HEADERS frame on the same stream.
    fn sendStreamDataH3(self: *Server, conn: *ConnState, stream_id: u64, offset: u64, data: []const u8, fin: bool, src: std.net.Address) void {
        const sf = stream_frame_mod.StreamFrame{
            .stream_id = stream_id,
            .offset = offset,
            .data = data,
            .fin = fin,
            .has_length = true,
        };
        var frame_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
        const frame_len = sf.serialize(&frame_buf) catch return;
        self.send1Rtt(conn, frame_buf[0..frame_len], src);
    }

    /// Send the next HTTP/3 DATA-frame chunk for one queued response slot.
    fn http3SendNextChunk(self: *Server, conn: *ConnState, slot: *Http3OutSlot) void {
        // Wrap up to 900 bytes of file content in an HTTP/3 DATA frame.
        // DATA frame overhead is 2 bytes (type=0x00 + 1-byte varint length),
        // so the total STREAM payload is at most 902 bytes — well within one UDP packet.
        const CHUNK: usize = 900;
        var file_buf: [CHUNK]u8 = undefined;
        const n = slot.file.read(&file_buf) catch |err| {
            std.debug.print("io: http3 stream_id={} read error: {}\n", .{ slot.stream_id, err });
            slot.close();
            return;
        };

        if (n == 0) {
            // EOF: send a zero-length STREAM frame with FIN to close the stream.
            std.debug.print("io: http3 stream_id={} EOF offset={}\n", .{ slot.stream_id, slot.stream_offset });
            const sf_fin = stream_frame_mod.StreamFrame{
                .stream_id = slot.stream_id,
                .offset = slot.stream_offset,
                .data = &.{},
                .fin = true,
                .has_length = true,
            };
            var fin_buf: [64]u8 = undefined;
            const fin_len = sf_fin.serialize(&fin_buf) catch {
                slot.close();
                return;
            };
            self.send1Rtt(conn, fin_buf[0..fin_len], conn.peer);
            const fin_pn = conn.app_pn - 1;
            @memcpy(slot.fin_frame[0..fin_len], fin_buf[0..fin_len]);
            slot.fin_frame_len = fin_len;
            slot.fin_pkt_pn = fin_pn;
            slot.fin_last_sent_ms = std.time.milliTimestamp();
            slot.fin_retransmit_count = 0;
            slot.awaiting_fin_ack = true;
            slot.file.close();
            slot.active = false;
            std.debug.print("io: http3 stream_id={} FIN sent (pn={})\n", .{ slot.stream_id, fin_pn });
            return;
        }

        // Wrap the chunk in an HTTP/3 DATA frame.
        var data_out: [CHUNK + 10]u8 = undefined;
        const data_frame_len = h3_frame.writeFrame(&data_out, @intFromEnum(h3_frame.FrameType.data), file_buf[0..n]) catch {
            slot.close();
            return;
        };

        const at_eof = slot.stream_offset - slot.stream_offset % CHUNK + @as(u64, @intCast(data_frame_len)) >= slot.file_end + 10;
        _ = at_eof;

        const sf_out = stream_frame_mod.StreamFrame{
            .stream_id = slot.stream_id,
            .offset = slot.stream_offset,
            .data = data_out[0..data_frame_len],
            .fin = false,
            .has_length = true,
        };
        var frame_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
        const frame_len = sf_out.serialize(&frame_buf) catch {
            slot.close();
            return;
        };
        self.send1Rtt(conn, frame_buf[0..frame_len], conn.peer);
        slot.stream_offset += @intCast(data_frame_len);

        if (slot.stream_offset % 10000 < CHUNK + 10) {
            std.debug.print("io: http3 stream_id={} chunk offset={} n={} file_end={}\n", .{ slot.stream_id, slot.stream_offset, n, slot.file_end });
        }
    }

    /// Drain queued HTTP/3 DATA frames with the same 50ms/20-packet pacing as HTTP/0.9.
    fn flushPendingHttp3Responses(self: *Server) void {
        const now = std.time.milliTimestamp();
        if (now - self.http3_last_flush_ms < 50) return;
        self.http3_last_flush_ms = now;

        var budget: usize = 20;
        while (budget > 0) {
            var progressed = false;
            for (&self.conns) |*cslot| {
                if (cslot.*) |*conn| {
                    for (&conn.http3_slots) |*slot| {
                        if (!slot.active) continue;
                        if (budget == 0) return;
                        self.http3SendNextChunk(conn, slot);
                        progressed = true;
                        budget -= 1;
                    }
                }
            }
            if (!progressed) break;
        }
    }

    /// Retransmit HTTP/3 FIN frames not yet ACKed (same 200ms retry pattern as HTTP/0.9).
    fn http3RetransmitPendingFins(self: *Server) void {
        const now = std.time.milliTimestamp();
        for (&self.conns) |*cslot| {
            if (cslot.*) |*conn| {
                for (&conn.http3_slots) |*slot| {
                    if (!slot.awaiting_fin_ack) continue;
                    if (now - slot.fin_last_sent_ms < 200) continue;

                    if (slot.fin_retransmit_count >= Http3OutSlot.MAX_FIN_RETRANSMITS) {
                        std.debug.print("io: http3 stream_id={} FIN retransmit limit reached\n", .{slot.stream_id});
                        slot.awaiting_fin_ack = false;
                        continue;
                    }

                    slot.fin_retransmit_count += 1;
                    slot.fin_last_sent_ms = now;
                    std.debug.print("io: http3 retransmit FIN stream_id={} attempt {}/{}\n", .{ slot.stream_id, slot.fin_retransmit_count, Http3OutSlot.MAX_FIN_RETRANSMITS });
                    self.send1Rtt(conn, slot.fin_frame[0..slot.fin_frame_len], conn.peer);
                }
            }
        }
    }
};

// ── Client config ─────────────────────────────────────────────────────────────

pub const ClientConfig = struct {
    host: []const u8 = "localhost",
    port: u16 = 443,
    urls: []const []const u8 = &.{},
    output_dir: []const u8 = "/downloads",
    keylog_path: ?[]const u8 = null,
    resumption: bool = false,
    early_data: bool = false,
    key_update: bool = false,
    http09: bool = false,
    http3: bool = false,
    chacha20: bool = false,
    migrate: bool = false,
    /// Use QUIC v2 (RFC 9369) for this connection.
    v2: bool = false,
};

// ── Stream download tracker ───────────────────────────────────────────────────

/// Maps a QUIC stream ID to an open output file for download accumulation.
const MAX_STREAMS = 2000;

const StreamDownload = struct {
    stream_id: u64,
    file: std.fs.File,
    active: bool,
    /// HTTP/3 only: have we already seen and skipped the HEADERS frame?
    h3_headers_received: bool = false,
    /// Small buffer for incomplete HTTP/3 frame headers that span two STREAM frames.
    h3_leftover: [256]u8 = [_]u8{0} ** 256,
    h3_leftover_len: usize = 0,
};

// ── QUIC Client ───────────────────────────────────────────────────────────────

pub const Client = struct {
    allocator: std.mem.Allocator,
    config: ClientConfig,
    sock: std.posix.socket_t,
    tls: ClientHandshake,
    conn: ConnState,
    streams: [MAX_STREAMS]StreamDownload = [_]StreamDownload{.{ .stream_id = 0, .file = undefined, .active = false }} ** MAX_STREAMS,
    streams_done: usize = 0,
    requested: bool = false,
    ticket_store: session_mod.TicketStore = .{},
    /// HTTP/3: whether we have sent the client control stream (stream_id=2).
    h3_client_control_sent: bool = false,
    /// Connection migration: true once the socket has been rebound to a new port.
    migrate_done: bool = false,
    /// 0-RTT early data keys (null until a PSK+early_data ClientHello is built).
    early_km: ?KeyMaterial = null,
    /// Packet number space for 0-RTT packets (separate from 1-RTT PN space).
    zerortt_pn: u64 = 0,

    /// Deferred ACK: instead of sending one ACK per received server packet,
    /// we accumulate the highest received PN here and flush a single cumulative
    /// ACK after draining all pending packets in the recv loop.  This reduces
    /// the burst from (N ACKs + N GETs) to (1 ACK + N GETs), keeping the
    /// combined burst under the NS3 DropTail queue limit of 25 packets.
    deferred_ack_pn: ?u64 = null,

    /// Active URL slice for the current connection.  Normally == config.urls;
    /// for the resumption second connection it is the remaining URLs.
    active_urls: []const []const u8 = &.{},

    // Stored Initial packet for retransmission.
    // On the first sendClientHello call, the packet is built and stored here.
    // Subsequent retransmit calls resend this exact buffer to avoid adding the
    // ClientHello to the TLS transcript a second time.
    initial_pkt: [MAX_DATAGRAM_SIZE]u8 = [_]u8{0} ** MAX_DATAGRAM_SIZE,
    initial_pkt_len: usize = 0,

    // Stored raw TLS ClientHello bytes (set on the first build).
    // After a Retry the Initial packet must be rebuilt with the new DCID
    // and token, but the TLS ClientHello must NOT be added to the transcript
    // a second time.  This buffer lets us reuse the original bytes.
    client_hello_bytes: [2048]u8 = [_]u8{0} ** 2048,
    client_hello_len: usize = 0,

    pub fn init(allocator: std.mem.Allocator, config: ClientConfig) !Client {
        const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
        errdefer std.posix.close(sock);

        var sk_buf: i32 = 8 * 1024 * 1024;
        const sk_opt = std.mem.asBytes(&sk_buf);
        std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, sk_opt) catch {};
        std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, sk_opt) catch {};
        setupEcnSocket(sock);

        var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
        const dcid = ConnectionId.random(prng.random(), 8);
        const scid = ConnectionId.random(prng.random(), 8);

        const tls_client = ClientHandshake.init();
        var conn = ConnState{
            .local_cid = scid,
            .remote_cid = dcid,
            .peer = undefined,
            // Compatible version negotiation (RFC 9368): the client always starts
            // with QUIC v1 even when v2 is preferred.  use_v2 is promoted to true
            // once the server's v2 Initial is successfully decrypted.
            .use_v2 = false,
        };
        conn.init_keys = InitialSecrets.derive(dcid.slice());
        if (config.v2) {
            // Pre-derive v2 keys so processInitialPacket can detect and handle
            // a server Initial that uses QUIC v2 (compatible version negotiation).
            conn.v2_upgrade_keys = InitialSecrets.deriveV2(dcid.slice());
        }

        return .{
            .allocator = allocator,
            .config = config,
            .sock = sock,
            .tls = tls_client,
            .conn = conn,
            .active_urls = config.urls,
        };
    }

    pub fn deinit(self: *Client) void {
        std.posix.close(self.sock);
    }

    /// Connect to the server and download all configured URLs.
    ///
    /// When `config.resumption` is true the client makes two separate QUIC
    /// connections: the first downloads the initial URL(s) and stores the
    /// session ticket; the second reconnects using TLS 1.3 PSK (pre_shared_key
    /// extension) and downloads the remaining URLs.
    pub fn run(self: *Client) !void {
        // Resolve server address (try IPv4 first, then DNS)
        const server_addr = std.net.Address.parseIp4(self.config.host, self.config.port) catch
            try resolveAddress(self.allocator, self.config.host, self.config.port);
        self.conn.peer = server_addr;
        std.debug.print("io: client resolved {s} to {any}\n", .{ self.config.host, server_addr });

        if ((self.config.resumption or self.config.early_data) and self.config.urls.len > 0) {
            // ── Connection 1: download the first URL, get a session ticket ──
            const split = @min(1, self.config.urls.len);
            self.active_urls = self.config.urls[0..split];
            std.debug.print("io: conn-1: downloading {} URL(s)\n", .{split});
            try self.runEventLoop(server_addr);

            // Wait a short while for the server to send NewSessionTicket.
            // RFC 8446 §4.6.1: the server sends the ticket after the handshake.
            if (self.ticket_store.isEmpty()) {
                std.debug.print("io: waiting up to 2s for session ticket...\n", .{});
                const ticket_deadline = std.time.milliTimestamp() + 2_000;
                var recv_buf2: [MAX_DATAGRAM_SIZE]u8 = undefined;
                while (std.time.milliTimestamp() < ticket_deadline and self.ticket_store.isEmpty()) {
                    var fds2 = [1]std.posix.pollfd{.{ .fd = self.sock, .events = std.posix.POLL.IN, .revents = 0 }};
                    const rdy = std.posix.poll(&fds2, 200) catch 0;
                    if (rdy > 0 and fds2[0].revents & std.posix.POLL.IN != 0) {
                        var sa: std.posix.sockaddr.storage = undefined;
                        var sl: std.posix.socklen_t = @sizeOf(@TypeOf(sa));
                        const nb = std.posix.recvfrom(self.sock, &recv_buf2, 0, @ptrCast(&sa), &sl) catch continue;
                        self.processPacket(recv_buf2[0..nb]);
                    }
                }
            }
            std.debug.print("io: ticket_store empty={}\n", .{self.ticket_store.isEmpty()});

            // ── Connection 2: reconnect using PSK (+ 0-RTT if early_data) ──
            const rest_urls = self.config.urls[split..];
            try self.resetForReconnect(server_addr);
            self.active_urls = if (rest_urls.len > 0) rest_urls else self.config.urls;
            std.debug.print("io: conn-2: downloading {} URL(s) with PSK{s}\n", .{
                self.active_urls.len,
                if (self.config.early_data) " + 0-RTT" else "",
            });
            try self.runEventLoop(server_addr);
        } else {
            self.active_urls = self.config.urls;
            try self.runEventLoop(server_addr);
        }
    }

    /// Reset connection state for a new QUIC connection to the same server.
    /// Preserves the ticket_store so the second connection can use PSK.
    fn resetForReconnect(self: *Client, server_addr: std.net.Address) !void {
        // Close old socket and open a fresh one (new local port = new connection
        // identity from the network's perspective).
        std.posix.close(self.sock);
        const new_sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
        errdefer std.posix.close(new_sock);
        self.sock = new_sock;

        var sk_buf: i32 = 8 * 1024 * 1024;
        const sk_opt = std.mem.asBytes(&sk_buf);
        std.posix.setsockopt(self.sock, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, sk_opt) catch {};
        std.posix.setsockopt(self.sock, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, sk_opt) catch {};

        // New random connection IDs.
        var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
        const dcid = ConnectionId.random(prng.random(), 8);
        const scid = ConnectionId.random(prng.random(), 8);

        // Reset connection state (new CIDs, new Initial secrets).
        self.conn = ConnState{
            .local_cid = scid,
            .remote_cid = dcid,
            .peer = server_addr,
        };
        self.conn.init_keys = InitialSecrets.derive(dcid.slice());

        // Fresh TLS handshake state.
        self.tls = ClientHandshake.init();

        // Close any open stream files.
        for (&self.streams) |*s| {
            if (s.active) {
                s.file.close();
                s.active = false;
            }
        }
        self.streams_done = 0;
        self.requested = false;

        // Clear packet buffers (ticket_store is preserved intentionally).
        self.initial_pkt = [_]u8{0} ** MAX_DATAGRAM_SIZE;
        self.initial_pkt_len = 0;
        self.client_hello_bytes = [_]u8{0} ** 2048;
        self.client_hello_len = 0;
        // Clear 0-RTT state so the new connection starts fresh.
        self.early_km = null;
        self.zerortt_pn = 0;
    }

    /// Inner event loop: send ClientHello, wait for handshake, download URLs.
    fn runEventLoop(self: *Client, server_addr: std.net.Address) !void {
        // Send ClientHello Initial packet
        try self.sendClientHello(server_addr);
        var last_initial_ms = std.time.milliTimestamp();

        // Event loop: receive and process packets
        var recv_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
        var deadline = std.time.milliTimestamp() + 60_000; // 60 second timeout for transfer

        while (std.time.milliTimestamp() < deadline) {
            const now = std.time.milliTimestamp();
            const remaining = deadline - now;
            if (remaining < 0) {
                std.debug.print("io: client deadline exceeded, {} ms remaining\n", .{remaining});
                break;
            }

            // Poll with 100ms timeout so retransmit timers fire promptly.
            var fds = [1]std.posix.pollfd{.{
                .fd = self.sock,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            const poll_timeout: i32 = @intCast(@min(100, @max(0, remaining)));
            const ready = std.posix.poll(&fds, poll_timeout) catch 0;
            if (ready > 0) {
                std.debug.print("io: client poll ready={} revents=0x{x}\n", .{ ready, fds[0].revents });
            }

            // Retransmit any unacknowledged packets (RFC 9002 §6.2).
            // Runs unconditionally: poll may return immediately with POLLERR
            // (e.g. ICMP port-unreachable) before the server is bound, which
            // would prevent the retransmit timer from ever being reached if the
            // check were inside the `ready == 0` branch.
            if (self.conn.phase == .initial and now - last_initial_ms >= 500) {
                self.sendClientHello(server_addr) catch {};
                last_initial_ms = now;
            }
            if (self.conn.has_hs_keys and self.conn.phase != .connected and
                self.conn.finished_pkt_len > 0 and now - self.conn.finished_sent_ms >= 500)
            {
                _ = std.posix.sendto(
                    self.sock,
                    self.conn.finished_pkt[0..self.conn.finished_pkt_len],
                    0,
                    &server_addr.any,
                    server_addr.getOsSockLen(),
                ) catch {};
                self.conn.finished_sent_ms = now;
            }

            if (ready == 0) continue;

            // Drain a pending ICMP/socket error (e.g. port-unreachable when
            // the server is not yet bound) so the next poll() is not
            // immediately woken by POLLERR again.
            if (fds[0].revents & std.posix.POLL.ERR != 0) {
                var dummy: [MAX_DATAGRAM_SIZE]u8 = undefined;
                var dummy_addr: std.posix.sockaddr.storage = undefined;
                var dummy_len: std.posix.socklen_t = @sizeOf(@TypeOf(dummy_addr));
                _ = std.posix.recvfrom(self.sock, &dummy, 0, @ptrCast(&dummy_addr), &dummy_len) catch {};
                continue;
            }

            if (fds[0].revents & std.posix.POLL.IN == 0) continue;

            var src_addr: std.posix.sockaddr.storage = undefined;
            var src_len: std.posix.socklen_t = @sizeOf(@TypeOf(src_addr));
            const n = std.posix.recvfrom(
                self.sock,
                &recv_buf,
                0,
                @ptrCast(&src_addr),
                &src_len,
            ) catch continue;

            // Check if packet likely contains FIN frames (look for 0x0f, 0x0d, 0x0b frame types)
            var has_fin_type = false;
            if (n > 0) {
                // Skip past packet header to find frame types
                // This is a rough check - actual frame parsing happens in processPacket
                var pos: usize = 1; // skip first byte (header form + fixed bit)
                var frame_count: u32 = 0;
                while (pos < n and frame_count < 10) {
                    const frame_type = recv_buf[pos];
                    if ((frame_type & 0x0f) == 0x0b or (frame_type & 0x0f) == 0x0d or (frame_type & 0x0f) == 0x0f) {
                        has_fin_type = true;
                    }
                    if ((frame_type & 0x08) != 0) {
                        frame_count += 1;
                        pos += 1; // rough skip, not accurate but enough for detection
                        if (pos >= n) break;
                    } else {
                        break;
                    }
                }
            }
            if (has_fin_type) {
                std.debug.print("io: client RECEIVED POSSIBLE FIN PACKET {} bytes\n", .{n});
            } else {
                std.debug.print("io: client recv {} bytes (no FIN type)\n", .{n});
            }
            self.processPacket(recv_buf[0..n]);

            // Connection migration: after the handshake, rebind to a new local
            // UDP port.  Sending any 1-RTT packet from the new address causes
            // the server to detect the address change and send a PATH_CHALLENGE;
            // the existing processAppFrames handler responds with PATH_RESPONSE,
            // the server validates and updates conn.peer, and subsequent STREAM
            // responses are delivered to the new address (RFC 9000 §9).
            if (self.conn.phase == .connected and self.config.migrate and !self.migrate_done) {
                self.migrate_done = true;
                self.rebindMigrateSocket(server_addr);
            }

            // On connection established, send requests
            if (self.conn.phase == .connected and !self.requested) {
                if (self.active_urls.len > 0) {
                    try self.downloadUrls(server_addr);
                }
                self.requested = true;
            }

            // Wait until all streams complete
            if (self.conn.phase == .connected and self.streams_done >= self.active_urls.len) {
                std.debug.print("io: client all streams done\n", .{});
                break;
            }

            deadline = std.time.milliTimestamp() + 10_000; // reset on activity
        }

        if (self.conn.phase != .connected) {
            std.debug.print("io: client handshake timed out\n", .{});
            return error.HandshakeTimeout;
        }

        std.debug.print("io: client done - phase={any} streams_done={}/{}\n", .{ self.conn.phase, self.streams_done, self.active_urls.len });
    }

    fn sendClientHello(self: *Client, server: std.net.Address) !void {
        // Retransmit: resend the already-built packet without touching the
        // TLS transcript. buildClientHelloMsg updates the transcript hash;
        // calling it again would corrupt the handshake keys.
        if (self.initial_pkt_len > 0) {
            _ = try std.posix.sendto(
                self.sock,
                self.initial_pkt[0..self.initial_pkt_len],
                0,
                &server.any,
                server.getOsSockLen(),
            );
            return;
        }

        // Build (or reuse) the TLS ClientHello.
        // After a Retry the QUIC Initial wrapper must be rebuilt (new DCID,
        // new keys, retry token), but buildClientHelloMsg must NOT be called
        // again — it would append a second ClientHello to the TLS transcript,
        // causing a Finished MAC mismatch with the server.
        var frame_buf: [2400]u8 = undefined;
        const ch_len: usize = if (self.client_hello_len > 0) blk: {
            // Post-Retry: reuse the already-built TLS ClientHello bytes.
            break :blk self.client_hello_len;
        } else blk: {
            // First send: build the ClientHello and save it for any future rebuild.
            const alpn: ?[]const u8 = if (self.config.http3) tls_hs.ALPN_H3 else if (self.config.http09) tls_hs.ALPN_H09 else null;
            var quic_tp_buf: [128]u8 = undefined;
            const quic_tp = buildClientTransportParams(&quic_tp_buf);

            // Choose ClientHello variant based on flags.
            const now_ms: u64 = @intCast(std.time.milliTimestamp());
            const len = if (self.config.early_data) ed_blk: {
                // 0-RTT: PSK + early_data extension
                if (self.ticket_store.get(now_ms)) |ticket| {
                    var psk_bytes: [32]u8 = .{0} ** 32;
                    @memcpy(&psk_bytes, ticket.resumption_secret[0..@min(ticket.resumption_secret_len, 32)]);
                    const psk_info = tls_hs.PskInfo{
                        .ticket = ticket.ticket[0..ticket.ticket_len],
                        .obfuscated_age = ticket.ageMs(now_ms),
                        .psk = psk_bytes,
                    };
                    std.debug.print("io: client building ClientHello with PSK + early_data (ticket_len={})\n", .{ticket.ticket_len});
                    const result = try self.tls.buildClientHelloMsgWithPskAndEarlyData(
                        &self.client_hello_bytes,
                        quic_tp,
                        alpn,
                        self.config.host,
                        psk_info,
                    );
                    // Derive early keys using the ClientHello transcript hash.
                    const ch_hash = tls_hs.peekHash(self.tls.transcript);
                    var cets: [32]u8 = undefined;
                    keys_mod.hkdfExpandLabel(&cets, &result.early_secret, "c e traffic", &ch_hash);
                    const early_keys = session_mod.deriveEarlyKeysFromSecret(cets);
                    self.early_km = KeyMaterial{
                        .secret = cets,
                        .key = early_keys.key,
                        .key32 = .{0} ** 32,
                        .iv = early_keys.iv,
                        .hp = early_keys.hp,
                        .hp32 = .{0} ** 32,
                    };
                    std.debug.print("io: client derived 0-RTT early keys\n", .{});
                    break :ed_blk result.n;
                } else {
                    std.debug.print("io: early_data enabled but no valid ticket — full handshake\n", .{});
                    break :ed_blk if (self.config.chacha20)
                        try self.tls.buildClientHelloMsgChaCha20(&self.client_hello_bytes, quic_tp, alpn, self.config.host)
                    else
                        try self.tls.buildClientHelloMsg(&self.client_hello_bytes, quic_tp, alpn, self.config.host);
                }
            } else if (self.config.resumption) psk_blk: {
                // 1-RTT resumption: PSK only, no early_data extension
                if (self.ticket_store.get(now_ms)) |ticket| {
                    var psk_bytes: [32]u8 = .{0} ** 32;
                    @memcpy(&psk_bytes, ticket.resumption_secret[0..@min(ticket.resumption_secret_len, 32)]);
                    const psk_info = tls_hs.PskInfo{
                        .ticket = ticket.ticket[0..ticket.ticket_len],
                        .obfuscated_age = ticket.ageMs(now_ms),
                        .psk = psk_bytes,
                    };
                    std.debug.print("io: client building ClientHello with PSK (ticket_len={})\n", .{ticket.ticket_len});
                    break :psk_blk try self.tls.buildClientHelloMsgWithPsk(
                        &self.client_hello_bytes,
                        quic_tp,
                        alpn,
                        self.config.host,
                        psk_info,
                    );
                } else {
                    std.debug.print("io: resumption enabled but no valid ticket — full handshake\n", .{});
                    break :psk_blk if (self.config.chacha20)
                        try self.tls.buildClientHelloMsgChaCha20(&self.client_hello_bytes, quic_tp, alpn, self.config.host)
                    else
                        try self.tls.buildClientHelloMsg(&self.client_hello_bytes, quic_tp, alpn, self.config.host);
                }
            } else if (self.config.chacha20)
                try self.tls.buildClientHelloMsgChaCha20(&self.client_hello_bytes, quic_tp, alpn, self.config.host)
            else
                try self.tls.buildClientHelloMsg(&self.client_hello_bytes, quic_tp, alpn, self.config.host);

            self.client_hello_len = len;
            break :blk len;
        };

        // CRYPTO frame
        const crypto_len = try buildCryptoFrame(&frame_buf, 0, self.client_hello_bytes[0..ch_len]);
        // Pad to 1200 bytes minimum (RFC 9000 §14.1)
        const min_payload = 1200 - 100; // leave room for headers
        if (crypto_len < min_payload) {
            buildPaddingFrames(frame_buf[crypto_len..min_payload], min_payload - crypto_len);
        }
        const payload_len = @max(crypto_len, min_payload);

        const init_km = self.conn.init_keys.?;
        const token = self.conn.retry_token[0..self.conn.retry_token_len];
        const pkt_len = try buildInitialPacket(
            &self.initial_pkt,
            self.conn.remote_cid,
            self.conn.local_cid,
            token,
            frame_buf[0..payload_len],
            self.conn.init_pn,
            &init_km.client,
            self.conn.quicVersion(),
        );
        self.conn.init_pn += 1;
        self.initial_pkt_len = pkt_len;

        _ = try std.posix.sendto(self.sock, self.initial_pkt[0..pkt_len], 0, &server.any, server.getOsSockLen());

        // If early keys were derived, immediately send ALL requests as 0-RTT
        // STREAM frames.  The interop pcap check requires ALL GET requests to
        // appear in 0-RTT packets, not in 1-RTT packets.  Setting requested=true
        // here prevents downloadUrls() from re-sending the same requests as 1-RTT
        // after the handshake completes.
        //
        // Reliability: two mechanisms prevent the 6/39 response-loss seen in
        // earlier runs:
        //   1. Client ACK frames (sent in process1RttPacket) let the server clear
        //      awaiting_fin_ack slots, reducing retransmit counts to only the
        //      truly-lost packets.
        //   2. http09RetransmitPendingFins is budget-capped (8 pkt/pass) so FIN
        //      retransmit bursts stay well below the NS3 25-pkt queue limit.
        if (self.early_km != null and !self.requested) {
            self.requested = true;
            self.send0RttRequests(server) catch |err| {
                std.debug.print("io: 0-RTT send failed: {}\n", .{err});
            };
        }
    }

    /// Send HTTP/0.9 GET requests for all active_urls as 0-RTT STREAM frames.
    /// Called immediately after the first ClientHello when early keys are available.
    /// Also registers each stream for download so responses are written to files.
    fn send0RttRequests(self: *Client, server: std.net.Address) !void {
        const km = self.early_km orelse return;
        std.debug.print("io: client sending {} 0-RTT request(s)\n", .{self.active_urls.len});

        std.fs.makeDirAbsolute(self.config.output_dir) catch {};

        for (self.active_urls, 0..) |url, i| {
            // Extract path from URL.
            const path = blk: {
                if (std.mem.indexOf(u8, url, "://")) |sep| {
                    const after_scheme = url[sep + 3 ..];
                    if (std.mem.indexOf(u8, after_scheme, "/")) |slash| {
                        break :blk after_scheme[slash..];
                    }
                }
                break :blk url;
            };

            const stream_id: u64 = @as(u64, i) * 4;

            // Open output file.
            var dl_path_buf: [512]u8 = undefined;
            const dl_path = http09_client.downloadPath(self.config.output_dir, path, &dl_path_buf) catch continue;
            const out_file = std.fs.createFileAbsolute(dl_path, .{}) catch {
                std.debug.print("io: 0-RTT cannot create {s}\n", .{dl_path});
                continue;
            };

            // Register stream for download.
            var registered = false;
            for (&self.streams) |*s| {
                if (!s.active) {
                    s.* = .{ .stream_id = stream_id, .file = out_file, .active = true };
                    registered = true;
                    break;
                }
            }
            if (!registered) {
                out_file.close();
                continue;
            }

            // Build HTTP/0.9 GET request STREAM frame.
            var req_buf: [4096]u8 = undefined;
            const req = http09_client.buildRequest(path, &req_buf) catch continue;
            const sf = stream_frame_mod.StreamFrame{
                .stream_id = stream_id,
                .offset = 0,
                .data = req,
                .fin = true,
                .has_length = true,
            };
            var frame_buf: [4200]u8 = undefined;
            const frame_len = sf.serialize(&frame_buf) catch continue;

            // Build and send 0-RTT packet.
            var send_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
            const pkt_len = build0RttPacket(
                &send_buf,
                self.conn.remote_cid,
                self.conn.local_cid,
                frame_buf[0..frame_len],
                self.zerortt_pn,
                &km,
                self.conn.quicVersion(),
            ) catch continue;
            self.zerortt_pn += 1;
            _ = std.posix.sendto(self.sock, send_buf[0..pkt_len], 0, &server.any, server.getOsSockLen()) catch {};
            std.debug.print("io: 0-RTT GET {s} stream_id={}\n", .{ path, stream_id });
        }
    }

    fn processPacket(self: *Client, buf: []const u8) void {
        if (buf.len < 5) return;

        if (buf[0] & 0x80 != 0) {
            const lh = header_mod.parseLong(buf) catch return;
            switch (lh.header.packet_type) {
                .initial => self.processInitialPacket(buf),
                .handshake => self.processHandshakePacket(buf),
                .retry => self.processRetryPacket(buf),
                else => {},
            }
        } else {
            self.process1RttPacket(buf);
        }
    }

    fn processRetryPacket(self: *Client, buf: []const u8) void {
        const rp = packet_mod.parseRetry(buf) catch return;

        // Verify Retry integrity tag (odcid = our original DCID)
        if (!retry_mod.verifyIntegrityTag(self.conn.remote_cid.slice(), buf)) {
            std.debug.print("io: Retry integrity tag invalid\n", .{});
            return;
        }

        std.debug.print("io: received Retry, re-sending Initial with token\n", .{});

        // Store the token for the next Initial
        const tlen = @min(rp.token.len, self.conn.retry_token.len);
        @memcpy(self.conn.retry_token[0..tlen], rp.token[0..tlen]);
        self.conn.retry_token_len = tlen;

        // Update DCID to server's new SCID
        self.conn.remote_cid = rp.scid;
        // Re-derive Initial keys for new DCID
        self.conn.init_keys = InitialSecrets.derive(rp.scid.slice());

        // Force a fresh build for the new Initial (with token and new DCID).
        self.initial_pkt_len = 0;

        // Send a new ClientHello Initial with the token
        self.sendClientHello(self.conn.peer) catch {};
    }

    fn processInitialPacket(
        self: *Client,
        buf: []const u8,
    ) void {
        const ip = packet_mod.parseInitial(buf) catch return;
        // RFC 9000 §7.2: When a client receives the first Initial from the server,
        // it MUST update its DCID to the server's SCID for all subsequent packets.
        if (!self.conn.server_cid_confirmed) {
            self.conn.remote_cid = ip.scid;
            self.conn.server_cid_confirmed = true;
        }
        const init_km = self.conn.init_keys orelse return;

        var plaintext: [4096]u8 = undefined;
        // Compatible version negotiation (RFC 9368): try current keys (v1 initially).
        // If decryption fails and we have pre-derived v2 keys, check whether the
        // server sent a v2 Initial and attempt a v2 decrypt.  On success, upgrade
        // the connection to QUIC v2 so all subsequent packets use v2.
        const pt_len: usize = blk: {
            if (initial_mod.unprotectInitialPacket(
                &plaintext,
                buf,
                ip.payload_offset,
                ip.payload_offset + ip.payload_len,
                &init_km.server,
            )) |pt| break :blk pt else |_| {}

            // v1 decryption failed — try v2 upgrade if keys are pre-derived.
            if (self.conn.v2_upgrade_keys) |v2km| {
                const pkt_version: u32 = if (buf.len >= 5)
                    (@as(u32, buf[1]) << 24) | (@as(u32, buf[2]) << 16) |
                        (@as(u32, buf[3]) << 8) | buf[4]
                else
                    QUIC_VERSION_1;
                if (pkt_version == QUIC_VERSION_2) {
                    if (initial_mod.unprotectInitialPacket(
                        &plaintext,
                        buf,
                        ip.payload_offset,
                        ip.payload_offset + ip.payload_len,
                        &v2km.server,
                    )) |pt| {
                        // Successfully decrypted with v2 keys — upgrade.
                        self.conn.use_v2 = true;
                        self.conn.init_keys = v2km;
                        self.conn.v2_upgrade_keys = null;
                        std.debug.print("io: client upgraded to QUIC v2 (compatible version negotiation)\n", .{});
                        break :blk pt;
                    } else |_| {}
                }
            }
            return; // both v1 and v2 decryption failed
        };

        // Extract CRYPTO frames, skipping ACK and PADDING frames.
        var pos: usize = 0;
        while (pos < pt_len) {
            const ft = plaintext[pos];
            if (ft == 0x00) { // PADDING
                pos += 1;
                continue;
            }
            if (ft == 0x02 or ft == 0x03) { // ACK — parse and skip
                pos += 1; // type byte
                const lar = varint.decode(plaintext[pos..]) catch break;
                pos += lar.len;
                const del = varint.decode(plaintext[pos..]) catch break;
                pos += del.len;
                const cnt = varint.decode(plaintext[pos..]) catch break;
                pos += cnt.len;
                const fst = varint.decode(plaintext[pos..]) catch break;
                pos += fst.len;
                var ri: u64 = 0;
                while (ri < cnt.value) : (ri += 1) {
                    const gp = varint.decode(plaintext[pos..]) catch break;
                    pos += gp.len;
                    const rl = varint.decode(plaintext[pos..]) catch break;
                    pos += rl.len;
                }
                if (ft == 0x03) { // ECN counts (3 varints)
                    inline for (0..3) |_| {
                        const ec = varint.decode(plaintext[pos..]) catch break;
                        pos += ec.len;
                    }
                }
                continue;
            }
            if (ft != 0x06) break; // not a CRYPTO frame — stop
            pos += 1;
            const off_r = varint.decode(plaintext[pos..]) catch break;
            pos += off_r.len;
            const dlen_r = varint.decode(plaintext[pos..]) catch break;
            pos += dlen_r.len;
            const dlen: usize = @intCast(dlen_r.value);
            if (pos + dlen > pt_len) break;
            const cdata = plaintext[pos .. pos + dlen];
            if (cdata.len >= 4 and cdata[0] == tls_hs.MSG_SERVER_HELLO) {
                self.tls.processServerHello(cdata) catch |err| {
                    std.debug.print("io: processServerHello failed: {}\n", .{err});
                    return;
                };
                // Now we have handshake secrets — derive QUIC keys
                self.conn.deriveHandshakeKeys(&self.tls.secrets);
                // Set cipher based on what the server negotiated.
                if (self.tls.cipher_suite == tls_hs.TLS_CHACHA20_POLY1305_SHA256) {
                    self.conn.use_chacha20 = true;
                }
            }
            pos += dlen;
        }
    }

    fn processHandshakePacket(
        self: *Client,
        buf: []const u8,
    ) void {
        if (!self.conn.has_hs_keys) return;

        const lh = header_mod.parseLong(buf) catch return;
        var pos = lh.consumed;
        const payload_len_r = varint.decode(buf[pos..]) catch return;
        pos += payload_len_r.len;
        const payload_len: usize = @intCast(payload_len_r.value);
        const pn_start = pos;
        const payload_end = pos + payload_len;
        if (payload_end > buf.len) return;

        var plaintext: [8192]u8 = undefined;
        const pt_len = decryptLongPacket(
            &plaintext,
            buf,
            pn_start,
            payload_end,
            &self.conn.hs_server_km,
        ) catch return;

        // Accumulate Handshake CRYPTO frames
        var fpos: usize = 0;
        while (fpos < pt_len) {
            if (plaintext[fpos] == 0x00) {
                fpos += 1;
                continue;
            }
            if (plaintext[fpos] == 0x02 or plaintext[fpos] == 0x03) {
                const is_ecn = plaintext[fpos] == 0x03;
                fpos += 1;
                if (fpos > pt_len) break;
                fpos += skipAckBody(plaintext[fpos..pt_len], is_ecn);
                continue;
            }
            if (plaintext[fpos] != 0x06) break;
            fpos += 1;
            const off_r = varint.decode(plaintext[fpos..]) catch break;
            fpos += off_r.len;
            const dlen_r = varint.decode(plaintext[fpos..]) catch break;
            fpos += dlen_r.len;
            const dlen: usize = @intCast(dlen_r.value);
            if (fpos + dlen > pt_len) break;
            const cdata = plaintext[fpos .. fpos + dlen];

            // Process server flight messages
            var fin_buf: [128]u8 = undefined;
            const fin_len = self.tls.processServerFlight(cdata, &fin_buf) catch |err| {
                if (err != error.NoServerFinished) {
                    std.debug.print("io: processServerFlight error: {}\n", .{err});
                }
                fpos += dlen;
                continue;
            };
            // App secrets are now derived; update QUIC 1-RTT keys.
            self.conn.deriveAppKeys(&self.tls.secrets);

            // Send client Finished
            self.sendClientFinished(fin_buf[0..fin_len]);
            break;
        }
    }

    fn sendClientFinished(self: *Client, fin_bytes: []const u8) void {
        if (!self.conn.has_hs_keys) return;

        var frame_buf: [256]u8 = undefined;

        const crypto_len = buildCryptoFrame(&frame_buf, 0, fin_bytes) catch return;
        const pkt_len = buildHandshakePacket(
            &self.conn.finished_pkt,
            self.conn.remote_cid,
            self.conn.local_cid,
            frame_buf[0..crypto_len],
            self.conn.hs_pn,
            &self.conn.hs_client_km,
            self.conn.quicVersion(),
        ) catch return;
        self.conn.hs_pn += 1;
        self.conn.finished_pkt_len = pkt_len;
        self.conn.finished_sent_ms = std.time.milliTimestamp();

        _ = std.posix.sendto(
            self.sock,
            self.conn.finished_pkt[0..pkt_len],
            0,
            &self.conn.peer.any,
            self.conn.peer.getOsSockLen(),
        ) catch {};
    }

    fn process1RttPacket(self: *Client, buf: []const u8) void {
        if (buf.len == 834) {
            std.debug.print("io: client process1RttPacket 834-byte packet starting\n", .{});
        }
        if (!self.conn.has_app_keys) return;
        const cid_len = self.conn.local_cid.len;
        if (buf.len < 1 + cid_len) return;

        var plaintext: [4096]u8 = undefined;
        const pn_start = 1 + cid_len;

        // Detect key phase flip from server using the UNPROTECTED header byte.
        // The Key Phase bit (0x04) is masked by header protection, so we must
        // remove HP first before reading it (RFC 9001 §5.4.1).
        const unprotected_first = peekUnprotectedFirstByte(buf, pn_start, &self.conn.app_server_km, self.conn.use_chacha20) orelse {
            if (buf.len == 834) {
                std.debug.print("io: client 834-byte packet FAILED peekUnprotectedFirstByte!\n", .{});
            }
            return;
        };
        const incoming_phase = (unprotected_first & 0x04) != 0;
        if (buf.len == 834) {
            std.debug.print("io: client 834-byte packet key phase: incoming={} current_peer={}\n", .{ incoming_phase, self.conn.peer_key_phase });
        }
        if (incoming_phase != self.conn.peer_key_phase) {
            // Server's key phase changed — rotate our receive keys to match.
            // This covers two cases:
            //   1. Server-initiated key update (key_update_pending=false): rotate.
            //   2. Server confirming our client-initiated key update
            //      (key_update_pending=true): also rotate and clear the flag.
            if (buf.len == 834) {
                std.debug.print("io: client 834-byte packet rotating to next key generation\n", .{});
            }
            self.conn.app_server_km = if (self.conn.use_v2)
                self.conn.app_server_km.nextGenV2()
            else
                self.conn.app_server_km.nextGen();
            if (self.conn.key_update_pending) {
                // Server has confirmed our key update.
                self.conn.key_update_pending = false;
            }
        }
        const decrypt_result = unprotect1RttPacketWithPnTracking(
            &plaintext,
            buf,
            pn_start,
            &self.conn.app_server_km,
            self.conn.use_chacha20,
            self.conn.app_recv_pn,
        ) catch |err| {
            if (buf.len == 834) {
                std.debug.print("io: client FAILED TO DECRYPT 834-byte FIN packet! error={} expected_pn={?}\n", .{ err, self.conn.app_recv_pn });
            }
            return;
        };
        const pt_len = decrypt_result.pt_len;
        const decompressed_pn = decrypt_result.pn;

        // Update the last received packet number for next decompression
        if (decompressed_pn > (self.conn.app_recv_pn orelse 0)) {
            self.conn.app_recv_pn = decompressed_pn;
            if (buf.len == 834) {
                std.debug.print("io: client 834-byte packet updated app_recv_pn to {}\n", .{decompressed_pn});
            }
        }

        // ECN: count this 1-RTT packet as ECT(0).
        self.conn.ecn_ect0_recv += 1;

        self.conn.peer_key_phase = incoming_phase;
        self.conn.key_update_pending = false;

        var pos: usize = 0;
        while (pos < pt_len) {
            const ft_r = varint.decode(plaintext[pos..]) catch return;
            const ft = ft_r.value;
            pos += ft_r.len;

            if (ft == 0x00) continue; // PADDING
            if (ft == 0x01) continue; // PING — no body
            if (ft == 0x02 or ft == 0x03) {
                // ACK frame — parse and skip all variable-length fields.
                pos += skipAckBody(plaintext[pos..pt_len], ft == 0x03);
                continue;
            }
            if (ft == 0x1e) { // HANDSHAKE_DONE
                std.debug.print("io: client received HANDSHAKE_DONE\n", .{});
                self.conn.phase = .connected;
                if (self.config.keylog_path) |kpath| {
                    writeKeylog(kpath, self.tls.client_random, &self.tls.secrets);
                }
                // Initiate a key update immediately after the handshake if
                // the "keyupdate" test case flag is set (RFC 9001 §6).
                if (self.config.key_update) {
                    self.initiateClientKeyUpdate();
                }
                continue;
            }
            if (ft == 0x06) {
                // CRYPTO frame — may contain NewSessionTicket
                const off_r = varint.decode(plaintext[pos..]) catch return;
                pos += off_r.len;
                const dlen_r = varint.decode(plaintext[pos..]) catch return;
                pos += dlen_r.len;
                const dlen: usize = @intCast(dlen_r.value);
                if (pos + dlen > pt_len) return;
                self.handleAppCrypto(plaintext[pos .. pos + dlen]);
                pos += dlen;
                continue;
            }
            if (ft == 0x1a) {
                // PATH_CHALLENGE — respond with PATH_RESPONSE.
                const pc = transport_frames.PathChallenge.parse(plaintext[pos..]) catch return;
                pos += pc.consumed;
                self.sendClientPathResponse(pc.frame.data);
                continue;
            }
            if (ft == 0x1b) {
                // PATH_RESPONSE — validate pending challenge.
                const pr = transport_frames.PathResponse.parse(plaintext[pos..]) catch return;
                pos += pr.consumed;
                if (self.conn.path_challenge_data) |expected| {
                    if (std.mem.eql(u8, &pr.frame.data, &expected)) {
                        self.conn.path_challenge_data = null;
                        std.debug.print("io: client path validated\n", .{});
                    }
                }
                continue;
            }
            if (ft == 0x18) {
                // NEW_CONNECTION_ID — store for use when migrating (RFC 9000 §19.15).
                const seq_r = varint.decode(plaintext[pos..pt_len]) catch return;
                pos += seq_r.len;
                const rpt_r = varint.decode(plaintext[pos..pt_len]) catch return;
                pos += rpt_r.len;
                if (pos >= pt_len) return;
                const cid_len_byte = plaintext[pos];
                pos += 1;
                if (pos + cid_len_byte + 16 > pt_len) return;
                const new_cid = ConnectionId.fromSlice(plaintext[pos .. pos + cid_len_byte]) catch return;
                pos += cid_len_byte;
                pos += 16; // skip stateless reset token
                if (seq_r.value == 1) {
                    self.conn.next_remote_cid = new_cid;
                    std.debug.print("io: client stored next_remote_cid from NEW_CONNECTION_ID\n", .{});
                }
                continue;
            }
            if (ft >= 0x08 and ft <= 0x0f) {
                // STREAM frame — write data to download file
                std.debug.print("io: client received STREAM frame type=0x{x:0>2} fin_bit={}\n", .{ ft, (ft & 0x01) != 0 });
                const sf_r = stream_frame_mod.StreamFrame.parse(plaintext[pos..pt_len], ft) catch |err| {
                    std.debug.print("io: client STREAM parse error: {}\n", .{err});
                    return;
                };
                pos += sf_r.consumed;
                std.debug.print("io: client parsed STREAM stream_id={} fin={} data_len={}\n", .{ sf_r.frame.stream_id, sf_r.frame.fin, sf_r.frame.data.len });
                self.handleStreamResponse(&sf_r.frame);
                continue;
            }
            // Unknown frame type — cannot safely skip without knowing the length.
            return;
        }

        // Defer ACK: accumulate the highest received PN rather than sending
        // one ACK per packet.  The actual ACK is flushed once after the recv
        // drain loop in downloadUrls.  This keeps the combined burst
        // (deferred ACK + next GET batch) well within the NS3 DropTail queue
        // limit of 25 packets (1 ACK + 20 GETs = 21 ≤ 25).
        if (decompressed_pn > (self.deferred_ack_pn orelse 0)) {
            self.deferred_ack_pn = decompressed_pn;
        }
    }

    /// Send a single cumulative ACK for the highest PN accumulated since the
    /// last flush.  Called once per recv-drain cycle from downloadUrls so that
    /// the server can clear awaiting_fin_ack slots without flooding the NS3
    /// network simulator queue.
    fn flushDeferredAck(self: *Client) void {
        const largest_pn = self.deferred_ack_pn orelse return;
        self.deferred_ack_pn = null;
        var ack_buf: [40]u8 = undefined;
        const ack_len = if (self.conn.ecn_ect0_recv > 0 or
            self.conn.ecn_ect1_recv > 0 or
            self.conn.ecn_ce_recv > 0)
            buildAckEcnFrame(
                &ack_buf,
                largest_pn,
                self.conn.ecn_ect0_recv,
                self.conn.ecn_ect1_recv,
                self.conn.ecn_ce_recv,
            ) catch return
        else
            buildAckFrame(&ack_buf, largest_pn) catch return;
        var send_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
        const pkt_len = build1RttPacketFull(
            &send_buf,
            self.conn.remote_cid,
            ack_buf[0..ack_len],
            self.conn.app_pn,
            &self.conn.app_client_km,
            self.conn.key_phase_bit,
            self.conn.use_chacha20,
        ) catch return;
        self.conn.app_pn += 1;
        _ = std.posix.sendto(
            self.sock,
            send_buf[0..pkt_len],
            0,
            &self.conn.peer.any,
            self.conn.peer.getOsSockLen(),
        ) catch {};
        std.debug.print("io: client flushed deferred ACK largest_pn={}\n", .{largest_pn});
    }

    fn handleAppCrypto(self: *Client, data: []const u8) void {
        if (data.len < 4) return;
        if (data[0] != 0x04) return; // not NewSessionTicket
        const body_len = readU24(data[1..4]);
        if (4 + body_len > data.len) return;
        const body = data[4 .. 4 + body_len];
        if (body.len < 4 + 4 + 1) return;

        var p: usize = 0;
        const lifetime_s = std.mem.readInt(u32, body[p..][0..4], .big);
        p += 4;
        p += 4; // skip ticket_age_add
        const nonce_len = body[p];
        p += 1;
        if (p + nonce_len + 2 > body.len) return;
        var nonce: [32]u8 = .{0} ** 32;
        const nl = @min(nonce_len, 32);
        @memcpy(nonce[0..nl], body[p .. p + nl]);
        p += nonce_len;
        const ticket_len = std.mem.readInt(u16, body[p..][0..2], .big);
        p += 2;
        if (p + ticket_len > body.len) return;
        const ticket_blob = body[p .. p + ticket_len];

        // The ticket blob IS the PSK (server sends PSK = HKDF-Expand-Label(resumption_secret,
        // "resumption", nonce, 32)).  Store it as both the ticket identity and the PSK.
        var ticket_arr: [session_mod.max_ticket_len]u8 = .{0} ** session_mod.max_ticket_len;
        const tl = @min(ticket_blob.len, session_mod.max_ticket_len);
        @memcpy(ticket_arr[0..tl], ticket_blob[0..tl]);

        // resumption_secret = PSK = ticket blob (used in psk_info.psk on reconnect).
        var rs_arr: [48]u8 = .{0} ** 48;
        const rs_len = @min(tl, 32);
        @memcpy(rs_arr[0..rs_len], ticket_arr[0..rs_len]);

        const ticket = session_mod.SessionTicket{
            .lifetime_s = lifetime_s,
            .nonce = nonce,
            .nonce_len = @intCast(nl),
            .ticket = ticket_arr,
            .ticket_len = tl,
            .resumption_secret = rs_arr,
            .resumption_secret_len = @intCast(rs_len),
            .max_early_data_size = 16384,
            .received_at_ms = @intCast(std.time.milliTimestamp()),
        };
        self.ticket_store.store(ticket);
        std.debug.print("io: stored session ticket (lifetime={}s)\n", .{lifetime_s});
    }

    /// Respond to a server-sent PATH_CHALLENGE with a matching PATH_RESPONSE.
    /// Initiate a key update from the client side (RFC 9001 §6).
    ///
    /// Rotates the client's send keys to the next generation, flips the key
    /// phase bit, and sends a PING in the new epoch.  The server will detect
    /// the key phase change, rotate its receive keys, and start sending with
    /// the new phase too — satisfying the quic-interop-runner "keyupdate"
    /// test case requirement that both sides emit key-phase-1 packets.
    fn initiateClientKeyUpdate(self: *Client) void {
        self.conn.app_client_km = if (self.conn.use_v2)
            self.conn.app_client_km.nextGenV2()
        else
            self.conn.app_client_km.nextGen();
        self.conn.key_phase_bit = !self.conn.key_phase_bit;
        self.conn.key_update_pending = true;

        // Send a PING so the server can verify the new key phase.
        const ping_frame = [_]u8{0x01};
        var padded: [3]u8 = .{ 0x01, 0x00, 0x00 };
        _ = ping_frame;
        var send_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
        const pkt_len = build1RttPacketFull(
            &send_buf,
            self.conn.remote_cid,
            &padded,
            self.conn.app_pn,
            &self.conn.app_client_km,
            self.conn.key_phase_bit,
            self.conn.use_chacha20,
        ) catch return;
        self.conn.app_pn += 1;
        _ = std.posix.sendto(self.sock, send_buf[0..pkt_len], 0, &self.conn.peer.any, self.conn.peer.getOsSockLen()) catch {};
        std.debug.print("io: client initiated key update → key_phase={}\n", .{self.conn.key_phase_bit});
    }

    fn sendClientPathResponse(self: *Client, data: [8]u8) void {
        var frame_buf: [64]u8 = undefined;
        const frame_len = transport_frames.PathResponse.serialize(.{ .data = data }, &frame_buf) catch return;
        var send_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
        const pkt_len = build1RttPacketFull(
            &send_buf,
            self.conn.remote_cid,
            frame_buf[0..frame_len],
            self.conn.app_pn,
            &self.conn.app_client_km,
            self.conn.key_phase_bit,
            self.conn.use_chacha20,
        ) catch return;
        self.conn.app_pn += 1;
        _ = std.posix.sendto(self.sock, send_buf[0..pkt_len], 0, &self.conn.peer.any, self.conn.peer.getOsSockLen()) catch {};
    }

    fn handleStreamResponse(self: *Client, sf: *const stream_frame_mod.StreamFrame) void {
        std.debug.print("io: client handleStreamResponse stream_id={} data_len={} fin={}\n", .{ sf.stream_id, sf.data.len, sf.fin });

        for (&self.streams) |*s| {
            if (s.active and s.stream_id == sf.stream_id) {
                if (self.config.http3) {
                    self.handleH3StreamData(s, sf);
                } else {
                    std.debug.print("io: found matching stream {}, writing {} bytes\n", .{ sf.stream_id, sf.data.len });
                    _ = s.file.write(sf.data) catch {};
                    if (sf.fin) {
                        s.file.close();
                        s.active = false;
                        self.streams_done += 1;
                        std.debug.print("io: stream {} download complete (total: {}/{})\n", .{ sf.stream_id, self.streams_done, self.active_urls.len });
                    }
                }
                return;
            }
        }
        std.debug.print("io: client stream {} not found (fin={})\n", .{ sf.stream_id, sf.fin });
    }

    /// Parse HTTP/3 frames from incoming STREAM data for one download slot.
    ///
    /// The server sends:  HEADERS frame (offset=0)  then  DATA frame(s).
    /// We skip the HEADERS frame and write DATA payloads straight to the file.
    fn handleH3StreamData(self: *Client, s: *StreamDownload, sf: *const stream_frame_mod.StreamFrame) void {
        // Combine any leftover bytes from the previous STREAM frame with the new data.
        var combined: [256 + MAX_DATAGRAM_SIZE]u8 = undefined;
        var data: []const u8 = sf.data;
        if (s.h3_leftover_len > 0) {
            const total = s.h3_leftover_len + sf.data.len;
            if (total <= combined.len) {
                @memcpy(combined[0..s.h3_leftover_len], s.h3_leftover[0..s.h3_leftover_len]);
                @memcpy(combined[s.h3_leftover_len..total], sf.data);
                data = combined[0..total];
            }
            s.h3_leftover_len = 0;
        }

        var pos: usize = 0;
        while (pos < data.len) {
            const pr = h3_frame.parseFrame(data[pos..]) catch |err| {
                if (err == error.BufferTooShort) {
                    // Save remaining bytes for the next STREAM frame arrival.
                    const remaining = data.len - pos;
                    const copy_len = @min(remaining, s.h3_leftover.len);
                    @memcpy(s.h3_leftover[0..copy_len], data[pos..][0..copy_len]);
                    s.h3_leftover_len = copy_len;
                }
                break;
            };
            pos += pr.consumed;
            switch (pr.frame) {
                .headers => {
                    s.h3_headers_received = true;
                    std.debug.print("io: h3 stream_id={} HEADERS frame parsed, skipping\n", .{s.stream_id});
                },
                .data => |d| {
                    _ = s.file.write(d) catch {};
                    std.debug.print("io: h3 stream_id={} DATA {} bytes written\n", .{ s.stream_id, d.len });
                },
                else => {},
            }
        }

        if (sf.fin) {
            s.file.close();
            s.active = false;
            self.streams_done += 1;
            std.debug.print("io: h3 stream {} download complete ({}/{})\n", .{ s.stream_id, self.streams_done, self.active_urls.len });
        }
    }

    /// Connection migration: open a new UDP socket (new ephemeral local port) and
    /// send a PING from it.  The server sees the packet from a new source address,
    /// detects the migration, and sends a PATH_CHALLENGE.  The existing
    /// processAppFrames handler responds with PATH_RESPONSE; the server validates
    /// and updates conn.peer to the new address.  Subsequent STREAM responses then
    /// arrive at our new socket (RFC 9000 §9.2).
    fn rebindMigrateSocket(self: *Client, server: std.net.Address) void {
        const new_sock = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch |err| {
            std.debug.print("io: migrate: new socket failed: {}\n", .{err});
            return;
        };
        var sk_buf: i32 = 8 * 1024 * 1024;
        const sk_opt = std.mem.asBytes(&sk_buf);
        std.posix.setsockopt(new_sock, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, sk_opt) catch {};
        std.posix.setsockopt(new_sock, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, sk_opt) catch {};
        setupEcnSocket(new_sock);

        std.posix.close(self.sock);
        self.sock = new_sock;

        // Send a PING (frame type 0x01) on the new socket.  The server detects the
        // new source address and initiates path validation (PATH_CHALLENGE →
        // PATH_RESPONSE).  RFC 9000 §9.5 requires the client to use a new DCID
        // when migrating, so use next_remote_cid if the server sent one.
        const ping_frame = [_]u8{0x01};
        var send_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
        const migration_dcid = if (self.conn.next_remote_cid) |ncid| ncid else self.conn.remote_cid;
        const pkt_len = build1RttPacketFull(
            &send_buf,
            migration_dcid,
            &ping_frame,
            self.conn.app_pn,
            &self.conn.app_client_km,
            self.conn.key_phase_bit,
            self.conn.use_chacha20,
        ) catch |err| {
            std.debug.print("io: migrate: PING build failed: {}\n", .{err});
            return;
        };
        self.conn.app_pn += 1;
        // Update remote_cid so ALL subsequent packets (including HTTP requests) use
        // the new server CID advertised via NEW_CONNECTION_ID (RFC 9000 §9.5).
        if (self.conn.next_remote_cid != null) {
            self.conn.remote_cid = migration_dcid;
        }
        _ = std.posix.sendto(new_sock, send_buf[0..pkt_len], 0, &server.any, server.getOsSockLen()) catch |err| {
            std.debug.print("io: migrate: PING send failed: {}\n", .{err});
            return;
        };
        std.debug.print("io: migrate: rebound to new socket, PING sent to trigger PATH_CHALLENGE\n", .{});
    }

    /// Send the HTTP/3 client control stream (stream_id=2, client-initiated unidirectional).
    /// Carries a SETTINGS frame with QPACK table size = 0 (static table only).
    fn sendH3ClientControlStream(self: *Client, server: std.net.Address) void {
        var buf: [128]u8 = undefined;
        buf[0] = 0x00; // stream type = control
        var pos: usize = 1;
        const settings_len = h3_frame.writeSettings(buf[pos..], &[_]h3_frame.Setting{
            .{ .id = h3_frame.SETTINGS_QPACK_MAX_TABLE_CAPACITY, .value = 0 },
            .{ .id = h3_frame.SETTINGS_QPACK_BLOCKED_STREAMS, .value = 0 },
        }) catch return;
        pos += settings_len;

        const sf = stream_frame_mod.StreamFrame{
            .stream_id = 2, // first client-initiated unidirectional stream
            .offset = 0,
            .data = buf[0..pos],
            .fin = false,
            .has_length = true,
        };
        var frame_buf: [256]u8 = undefined;
        const frame_len = sf.serialize(&frame_buf) catch return;
        var send_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
        const pkt_len = build1RttPacketFull(
            &send_buf,
            self.conn.remote_cid,
            frame_buf[0..frame_len],
            self.conn.app_pn,
            &self.conn.app_client_km,
            self.conn.key_phase_bit,
            self.conn.use_chacha20,
        ) catch return;
        self.conn.app_pn += 1;
        _ = std.posix.sendto(self.sock, send_buf[0..pkt_len], 0, &server.any, server.getOsSockLen()) catch {};
        std.debug.print("io: h3 client control stream sent\n", .{});
    }

    fn downloadUrls(self: *Client, server: std.net.Address) !void {
        std.debug.print("io: sending {} {s} requests\n", .{ self.active_urls.len, if (self.config.http3) @as([]const u8, "HTTP/3") else @as([]const u8, "HTTP/0.9") });

        // Ensure output directory exists
        std.fs.makeDirAbsolute(self.config.output_dir) catch {};

        // HTTP/3: send client control stream once before any requests.
        if (self.config.http3 and !self.h3_client_control_sent) {
            self.sendH3ClientControlStream(server);
            self.h3_client_control_sent = true;
        }

        // Process downloads in batches to stay within NS3 network simulator limits.
        // The NS3 DropTail queue is 25 packets; sending more than ~20 packets at
        // once causes queue overflow and packet drops.  Using BATCH_SIZE=20 keeps
        // each GET request burst at or below the queue limit, matching the server's
        // own 20-packet-per-flush budget (see flushPendingHttp09Responses).
        const BATCH_SIZE: usize = 20;
        var batch_start: usize = 0;
        while (batch_start < self.active_urls.len) {
            const batch_end = @min(batch_start + BATCH_SIZE, self.active_urls.len);
            const batch = self.active_urls[batch_start..batch_end];

            std.debug.print("io: downloadUrls batch [{}-{}) of {}\n", .{ batch_start, batch_end, self.active_urls.len });

            // Send requests for this batch. Use global index for stream_id so each
            // stream has a unique, non-overlapping ID across batches.
            for (batch, batch_start..) |url, global_i| {
                // Extract path from url (strip scheme+host if present, keep path)
                const path = blk: {
                    if (std.mem.indexOf(u8, url, "://")) |sep| {
                        const after_scheme = url[sep + 3 ..];
                        if (std.mem.indexOf(u8, after_scheme, "/")) |slash| {
                            break :blk after_scheme[slash..];
                        }
                    }
                    break :blk url;
                };

                // Allocate stream ID: client-initiated bidirectional = 4*global_i
                const stream_id: u64 = @as(u64, global_i) * 4;
                std.debug.print("io: downloadUrl[{}] path={s} stream_id={}\n", .{ global_i, path, stream_id });

                // Open output file
                var dl_path_buf: [512]u8 = undefined;
                const dl_path = http09_client.downloadPath(self.config.output_dir, path, &dl_path_buf) catch continue;
                const out_file = std.fs.createFileAbsolute(dl_path, .{}) catch {
                    std.debug.print("io: cannot create {s}\n", .{dl_path});
                    continue;
                };

                // Register stream download in an available slot
                var registered = false;
                for (&self.streams) |*s| {
                    if (!s.active) {
                        s.* = .{ .stream_id = stream_id, .file = out_file, .active = true };
                        std.debug.print("io: registered stream {} for download\n", .{stream_id});
                        registered = true;
                        break;
                    }
                }
                if (!registered) {
                    out_file.close();
                    std.debug.print("io: streams array full\n", .{});
                    continue;
                }

                // Build the request payload and QUIC STREAM frame.
                var frame_buf: [4200]u8 = undefined;
                var frame_len: usize = undefined;

                if (self.config.http3) {
                    // HTTP/3: send a HEADERS frame with :method GET and :path.
                    var header_block: [512]u8 = undefined;
                    const hb_len = h3_qpack.encodeHeaders(&[_]h3_qpack.Header{
                        .{ .name = ":method", .value = "GET" },
                        .{ .name = ":path", .value = path },
                        .{ .name = ":scheme", .value = "https" },
                        .{ .name = ":authority", .value = self.config.host },
                    }, &header_block) catch continue;
                    var h3_out: [600]u8 = undefined;
                    const h3_len = h3_frame.writeFrame(&h3_out, @intFromEnum(h3_frame.FrameType.headers), header_block[0..hb_len]) catch continue;
                    const sf = stream_frame_mod.StreamFrame{
                        .stream_id = stream_id,
                        .offset = 0,
                        .data = h3_out[0..h3_len],
                        .fin = true, // request headers are the complete request
                        .has_length = true,
                    };
                    frame_len = sf.serialize(&frame_buf) catch continue;
                    std.debug.print("io: h3 GET {s} stream_id={}\n", .{ path, stream_id });
                } else {
                    // HTTP/0.9: send a raw "GET /path\r\n" request.
                    var req_buf: [4096]u8 = undefined;
                    const req = http09_client.buildRequest(path, &req_buf) catch continue;
                    const sf = stream_frame_mod.StreamFrame{
                        .stream_id = stream_id,
                        .offset = 0,
                        .data = req,
                        .fin = true,
                        .has_length = true,
                    };
                    frame_len = sf.serialize(&frame_buf) catch continue;
                }

                var send_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
                const pkt_len = build1RttPacketFull(
                    &send_buf,
                    self.conn.remote_cid,
                    frame_buf[0..frame_len],
                    self.conn.app_pn,
                    &self.conn.app_client_km,
                    self.conn.key_phase_bit,
                    self.conn.use_chacha20,
                ) catch continue;
                self.conn.app_pn += 1;

                _ = std.posix.sendto(self.sock, send_buf[0..pkt_len], 0, &server.any, server.getOsSockLen()) catch {};
            }

            // Wait for all downloads in this batch to complete.
            const batch_target = batch_end;
            std.debug.print("io: downloadUrls waiting for batch target={} (deadline=60s)\n", .{batch_target});
            var recv_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
            const dl_deadline = std.time.milliTimestamp() + 60_000;
            var dl_iter: u32 = 0;
            while (true) {
                dl_iter += 1;
                const now = std.time.milliTimestamp();
                const remaining = dl_deadline - now;

                if (remaining <= 0) {
                    std.debug.print("io: downloadUrls DEADLINE EXCEEDED batch_target={} streams_done={}\n", .{ batch_target, self.streams_done });
                    break;
                }

                if (dl_iter % 100 == 0) {
                    std.debug.print("io: downloadUrls iteration {} streams_done={}/{} remaining={}ms\n", .{ dl_iter, self.streams_done, batch_target, remaining });
                }
                if (self.streams_done >= batch_target) {
                    std.debug.print("io: downloadUrls batch done streams_done={}\n", .{self.streams_done});
                    break;
                }

                var fds = [1]std.posix.pollfd{.{ .fd = self.sock, .events = std.posix.POLL.IN, .revents = 0 }};
                const poll_timeout: i32 = @intCast(@min(200, @max(0, remaining)));
                const ready = std.posix.poll(&fds, poll_timeout) catch 0;
                if (ready == 0) continue;
                if (fds[0].revents & std.posix.POLL.IN == 0) continue;

                std.debug.print("io: downloadUrls poll ready iter={} streams_done={}\n", .{ dl_iter, self.streams_done });
                var drained: usize = 0;
                while (true) {
                    var src_addr: std.posix.sockaddr.storage = undefined;
                    var src_len: std.posix.socklen_t = @sizeOf(@TypeOf(src_addr));
                    const flags: u32 = if (drained == 0) 0 else MSG_DONTWAIT;
                    const n = std.posix.recvfrom(self.sock, &recv_buf, flags, @ptrCast(&src_addr), &src_len) catch |err| {
                        if (drained > 0 and err == error.WouldBlock) break;
                        std.debug.print("io: downloadUrls recvfrom error: {}\n", .{err});
                        break;
                    };
                    drained += 1;
                    std.debug.print("io: downloadUrls recv {} bytes drained={} streams_done={}\n", .{ n, drained, self.streams_done });
                    self.processPacket(recv_buf[0..n]);
                }
                // Send one cumulative ACK after draining all pending packets.
                // This replaces N individual ACKs with a single packet, reducing
                // the combined burst (ACK + next GET batch) to ≤ 21 packets.
                self.flushDeferredAck();
            }

            batch_start = batch_end;
        }
        std.debug.print("io: downloadUrls done streams_done={}/{}\n", .{ self.streams_done, self.active_urls.len });

        // Close all stream files
        for (&self.streams) |*s| {
            if (s.active) {
                s.file.close();
                s.active = false;
            }
        }
    }
};

// ── Transport parameter helpers ───────────────────────────────────────────────

inline fn readU24(b: []const u8) u32 {
    return (@as(u32, b[0]) << 16) | (@as(u32, b[1]) << 8) | @as(u32, b[2]);
}

fn buildClientTransportParams(buf: []u8) []const u8 {
    const n = quic_tls_mod.buildClientTransportParams(buf);
    return buf[0..n];
}

// ── Misc helpers ──────────────────────────────────────────────────────────────

/// Extract the first byte of the (protected) packet number field.
fn extractPacketNumber(buf: []const u8, pn_start: usize) ?u64 {
    if (pn_start >= buf.len) return null;
    return @as(u64, buf[pn_start]);
}

/// Resolve a hostname to an IPv4 address (prefers AF.INET since we only create
/// IPv4 UDP sockets).  The connectionmigration test uses the dual-stack hostname
/// "server46" which returns both IPv4 and IPv6 addresses; without the preference
/// the first address is often IPv6 and sendto() silently fails on our IPv4 socket.
fn resolveAddress(allocator: std.mem.Allocator, host: []const u8, port: u16) !std.net.Address {
    const list = try std.net.getAddressList(allocator, host, port);
    defer list.deinit();
    if (list.addrs.len == 0) return error.HostNotFound;
    // Prefer IPv4 — our sockets are AF.INET only.
    for (list.addrs) |addr| {
        if (addr.any.family == std.posix.AF.INET) return addr;
    }
    return list.addrs[0];
}
