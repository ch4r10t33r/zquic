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
pub const MAX_CONNECTIONS: usize = 16;
pub const MAX_DATAGRAM_SIZE: usize = 1500;

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
/// Returns bytes written.
pub fn buildInitialPacket(
    out: []u8,
    dcid: ConnectionId,
    scid: ConnectionId,
    token: []const u8,
    payload: []const u8,
    pn: u64,
    km: *const KeyMaterial,
) !usize {
    // Build header (without PN, to match buildInitialHeader from packet.zig logic)
    // First byte: Header Form=1, Fixed Bit=1, Type=initial(00), PN_len=0 (1 byte PN)
    var hdr_buf: [128]u8 = undefined;
    var hp: usize = 0;

    // First byte: 0xc0 | (initial << 4) | (pn_len_wire = 0) = 0xc0
    hdr_buf[hp] = 0xc0; // will be header-protected
    hp += 1;
    // Version
    std.mem.writeInt(u32, hdr_buf[hp..][0..4], QUIC_VERSION_1, .big);
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
pub fn buildHandshakePacket(
    out: []u8,
    dcid: ConnectionId,
    scid: ConnectionId,
    payload: []const u8,
    pn: u64,
    km: *const KeyMaterial,
) !usize {
    var hdr_buf: [128]u8 = undefined;
    var hp: usize = 0;

    // First byte: Header Form=1, Fixed Bit=1, Type=handshake(10), PN_len=0
    hdr_buf[hp] = 0xe0; // 1110_0000: long, fixed, handshake, pn_len=0
    hp += 1;
    std.mem.writeInt(u32, hdr_buf[hp..][0..4], QUIC_VERSION_1, .big);
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

    fn close(self: *Http09OutSlot) void {
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

    // CRYPTO stream offset tracking (in-order reassembly)
    init_crypto_offset: u64 = 0,
    app_crypto_offset: u64 = 0,

    // HTTP/3 state: whether the server control stream was sent
    h3_settings_sent: bool = false,

    /// HTTP/0.9 responses in progress (parallel downloads per connection).
    http09_slots: [8]Http09OutSlot = [_]Http09OutSlot{.{}} ** 8,

    /// 1-RTT frames received while waiting for client Finished (reordering).
    pending_1rtt: [pending_1rtt_cap]Pending1RttPayload = [_]Pending1RttPayload{.{}} ** pending_1rtt_cap,
    pending_1rtt_n: usize = 0,

    // Retry token (set when server sends Retry; included in next Initial)
    retry_token: [64]u8 = [_]u8{0} ** 64,
    retry_token_len: usize = 0,
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

    // Cipher suite in use for 1-RTT packets (true = ChaCha20-Poly1305).
    use_chacha20: bool = false,

    // TLS handshake state machine (server side)
    tls: ServerHandshake = undefined,
    tls_inited: bool = false,

    // Pending outgoing TLS bytes (for CRYPTO frames)
    // ServerHello goes in Initial; server flight goes in Handshake
    sh_bytes: [512]u8 = undefined, // ServerHello
    sh_len: usize = 0,
    flight_bytes: [8192]u8 = undefined, // EncryptedExtensions+Cert+CV+Finished
    flight_len: usize = 0,

    pub fn deriveInitialKeys(self: *ConnState, dcid: ConnectionId) void {
        self.init_keys = InitialSecrets.derive(dcid.slice());
    }

    /// Derive Handshake QUIC keys from TLS handshake traffic secrets.
    /// Call this after processServerHello (client) or processClientHello (server).
    pub fn deriveHandshakeKeys(self: *ConnState, secrets: *const tls_hs.TrafficSecrets) void {
        const hs_client_qkm = tls_hs.deriveQuicKeys(secrets.client_handshake);
        const hs_server_qkm = tls_hs.deriveQuicKeys(secrets.server_handshake);

        self.hs_client_km = .{ .key = hs_client_qkm.key, .iv = hs_client_qkm.iv, .hp = hs_client_qkm.hp, .secret = secrets.client_handshake };
        self.hs_server_km = .{ .key = hs_server_qkm.key, .iv = hs_server_qkm.iv, .hp = hs_server_qkm.hp, .secret = secrets.server_handshake };

        self.has_hs_keys = true;
    }

    /// Derive 1-RTT QUIC keys from TLS application traffic secrets.
    /// Call this after buildServerFlight (server) or processServerFlight (client).
    pub fn deriveAppKeys(self: *ConnState, secrets: *const tls_hs.TrafficSecrets) void {
        const app_client_qkm = tls_hs.deriveQuicKeys(secrets.client_app);
        const app_server_qkm = tls_hs.deriveQuicKeys(secrets.server_app);

        self.app_client_km = .{ .key = app_client_qkm.key, .iv = app_client_qkm.iv, .hp = app_client_qkm.hp, .secret = secrets.client_app };
        self.app_server_km = .{ .key = app_server_qkm.key, .iv = app_server_qkm.iv, .hp = app_server_qkm.hp, .secret = secrets.server_app };

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
    http09: bool = false,
    http3: bool = false,
    key_update: bool = false,
    migrate: bool = false,
    chacha20: bool = false,
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

    /// Initialize server: load cert/key and create UDP socket.
    pub fn init(allocator: std.mem.Allocator, config: ServerConfig) !Server {
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

        return .{
            .allocator = allocator,
            .config = config,
            .sock = sock,
            .raw_sock = raw_sock,
            .cert_der = cert_der,
            .private_key = pk,
            .retry_secret = retry_secret,
        };
    }

    pub fn deinit(self: *Server) void {
        std.posix.close(self.sock);
        if (self.raw_sock) |rs| std.posix.close(rs);
        self.allocator.free(self.cert_der);
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
                        if (slot.active) {
                            poll_timeout_ms = 50;
                            break;
                        }
                    }
                }
                if (poll_timeout_ms == 50) break;
            }

            const ready = std.posix.poll(fds[0..nfds], poll_timeout_ms) catch |err| {
                std.debug.print("io: poll error: {}\n", .{err});
                self.flushPendingHttp09Responses();
                continue;
            };
            if (ready == 0) {
                if (poll_timeout_ms >= 2000) {
                    idle_secs += 2;
                    std.debug.print("io: server waiting ({}s idle, sock={})\n", .{ idle_secs, self.sock });
                }
                // Pending HTTP/0.9 bodies must keep draining even when the socket
                // is not readable (poll timeout); otherwise we stall until the next
                // inbound datagram and the transfer test starves.
                self.flushPendingHttp09Responses();
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
                    const flags: u32 = if (drained == 0) 0 else std.posix.MSG.DONTWAIT;
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
            // RFC 9000 §6.1: respond with Version Negotiation for any
            // unsupported version so that readiness probes (wait-for-it-quic
            // sends version 0x57415449 "WAIT") get a proper reply and do not
            // consume connection slots.
            if (lh.header.version != version_neg_mod.QUIC_V1) {
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
                .zero_rtt => {}, // not supported yet
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

    /// Create a new server-side connection.
    fn newConn(self: *Server, dcid: ConnectionId, scid: ConnectionId, peer: std.net.Address) ?*ConnState {
        for (&self.conns) |*slot| {
            if (slot.* == null) {
                var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
                const local_cid = ConnectionId.random(prng.random(), 8);
                slot.* = ConnState{
                    .local_cid = local_cid,
                    .remote_cid = scid,
                    .peer = peer,
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

        // Retry mode: if enabled and no valid token, send Retry and drop
        if (self.config.retry_enabled) {
            if (!self.verifyRetryToken(ip.token, ip.dcid.slice())) {
                self.sendRetry(ip.dcid.slice(), ip.scid.slice(), src);
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
            const c = self.newConn(ip.dcid, ip.scid, src) orelse return;
            break :blk c;
        };

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

    /// Build a Retry token: HMAC-SHA256(retry_secret, odcid).
    fn mintRetryToken(self: *Server, odcid: []const u8, out: *[32]u8) void {
        var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(&self.retry_secret);
        hmac.update(odcid);
        hmac.final(out);
    }

    /// Verify that `token` is a valid HMAC over `odcid` with our secret.
    fn verifyRetryToken(self: *Server, token: []const u8, odcid: []const u8) bool {
        if (token.len != 32) return false;
        var expected: [32]u8 = undefined;
        self.mintRetryToken(odcid, &expected);
        return std.mem.eql(u8, token, &expected);
    }

    /// Send a Retry packet to the client.
    /// RFC 9000 §6: send a Version Negotiation packet advertising QUIC v1.
    /// `client_scid` and `client_dcid` are from the client's packet; the VN
    /// packet echoes them back swapped (server DCID = client SCID, server SCID
    /// = client DCID) so the client can match the response.
    fn sendVersionNegotiation(self: *Server, client_scid: []const u8, client_dcid: []const u8, dst: std.net.Address) void {
        var buf: [64]u8 = undefined;
        const n = version_neg_mod.build(&buf, client_scid, client_dcid, &[_]u32{version_neg_mod.QUIC_V1}) catch return;
        _ = std.posix.sendto(self.sock, buf[0..n], 0, &dst.any, dst.getOsSockLen()) catch {};
    }

    fn sendRetry(self: *Server, odcid: []const u8, scid: []const u8, src: std.net.Address) void {
        // New server SCID for the connection after Retry
        var new_scid: [8]u8 = undefined;
        std.crypto.random.bytes(&new_scid);

        // Token = HMAC-SHA256(retry_secret, odcid)
        var token: [32]u8 = undefined;
        self.mintRetryToken(odcid, &token);

        var buf: [256]u8 = undefined;
        const n = retry_mod.buildRetryPacket(
            &buf,
            QUIC_VERSION_1,
            scid, // DCID = client's SCID
            &new_scid, // SCID = new server CID
            &token,
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
    }

    fn buildAndSendServerFlight(self: *Server, conn: *ConnState, src: std.net.Address) void {
        // Build server transport parameters into a separate scratch buffer
        var tp_buf: [512]u8 = undefined;
        const tp_len = quic_tls_mod.buildClientTransportParams(&tp_buf);
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

        // NewSessionTicket (if resumption is enabled)
        if (self.config.resumption_enabled) {
            const nonce = [_]u8{0x01} ** 8;
            // Ticket = resumption secret (32 bytes)
            const res_secret = conn.tls.resumptionSecret();
            const nst_len = tls_hs.buildNewSessionTicket(
                frames_buf[fp + 4 + 8 ..], // leave room for CRYPTO frame header
                3600,
                &nonce,
                &res_secret,
                16384, // max_early_data
            ) catch 0;
            if (nst_len > 0) {
                const crypto_len = buildCryptoFrame(
                    frames_buf[fp..],
                    conn.app_crypto_offset,
                    frames_buf[fp + 4 + 8 .. fp + 4 + 8 + nst_len],
                ) catch 0;
                conn.app_crypto_offset += nst_len;
                fp += crypto_len;
            }
        }

        self.send1Rtt(conn, frames_buf[0..fp], src);
    }

    fn process1RttPacket(self: *Server, buf: []const u8, src: std.net.Address) void {
        // Find connection by scanning CID prefix
        for (&self.conns) |*slot| {
            if (slot.*) |*conn| {
                if (conn.phase != .connected and conn.phase != .waiting_finished) continue;
                if (!conn.has_app_keys) continue;
                const cid_len = conn.local_cid.len;
                if (buf.len < 1 + cid_len) continue;
                const candidate = ConnectionId.fromSlice(buf[1 .. 1 + cid_len]) catch continue;
                if (!ConnectionId.eql(conn.local_cid, candidate)) continue;

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
                const pt_len: usize = decrypt: {
                    if (unprotect1RttPacket(
                        &plaintext,
                        buf,
                        pn_start,
                        &conn.app_client_km,
                        conn.use_chacha20,
                    )) |n| {
                        break :decrypt n;
                    } else |_| {}
                    if (incoming_phase != conn.peer_key_phase and !conn.key_update_pending) {
                        var nk = conn.app_client_km.nextGen();
                        if (unprotect1RttPacket(
                            &plaintext,
                            buf,
                            pn_start,
                            &nk,
                            conn.use_chacha20,
                        )) |n| {
                            conn.app_client_km = nk;
                            break :decrypt n;
                        } else |_| {}
                    }
                    std.debug.print(
                        "io: server 1-RTT decrypt failed after DCID match (len={} incoming_kp={} stored_kp={} chacha={})\n",
                        .{ buf.len, incoming_phase, conn.peer_key_phase, conn.use_chacha20 },
                    );
                    continue;
                };

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
                return;
            }
        }
    }

    /// Trigger a local key update: rotate send keys and emit a packet with
    /// the new key phase bit set.  Called after handshake when key_update
    /// is enabled (quic-interop-runner "keyupdate" test case).
    fn initiateKeyUpdate(self: *Server, conn: *ConnState, src: std.net.Address) void {
        // Rotate to next generation keys.
        conn.app_server_km = conn.app_server_km.nextGen();
        conn.key_phase_bit = !conn.key_phase_bit;
        conn.key_update_pending = true;

        // Send a PING so the peer can verify the new keys.
        const ping_frame = [_]u8{0x01};
        self.send1Rtt(conn, &ping_frame, src);
    }

    fn processAppFrames(self: *Server, conn: *ConnState, frames: []const u8, src: std.net.Address) void {
        // Detect address change (connection migration, RFC 9000 §9).
        // If the source address differs from the stored peer address and
        // migration is enabled, send PATH_CHALLENGE to validate the new path.
        if (self.config.migrate and conn.path_challenge_data == null) {
            if (!addressEqual(conn.peer, src)) {
                var challenge: [8]u8 = undefined;
                var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
                prng.random().bytes(&challenge);
                conn.path_challenge_data = challenge;
                self.sendPathChallenge(conn, challenge, src);
            }
        }

        var pos: usize = 0;
        while (pos < frames.len) {
            const ft_r = varint.decode(frames[pos..]) catch return;
            const ft = ft_r.value;
            pos += ft_r.len;

            if (ft == 0x00) continue; // PADDING
            if (ft == 0x01) continue; // PING — no body
            if (ft == 0x02 or ft == 0x03) {
                // ACK frame — parse and skip all variable-length fields.
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
        _ = std.posix.sendto(self.sock, send_buf[0..pkt_len], 0, &dst.any, dst.getOsSockLen()) catch |err| {
            std.debug.print("io: sendto error pkt_len={}: {}\n", .{ pkt_len, err });
        };
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
            std.debug.print("io: http09 stream_id={} complete\n", .{slot.stream_id});
            slot.close();
        }
    }

    /// Drain queued HTTP/0.9 bodies a little at a time so recv/ACK processing can run.
    fn flushPendingHttp09Responses(self: *Server) void {
        var budget: usize = 256;
        while (budget > 0) {
            var progressed = false;
            for (&self.conns) |*cslot| {
                if (cslot.*) |*conn| {
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

        for (&conn.http09_slots) |*slot| {
            if (slot.active and slot.stream_id == sf.stream_id) return;
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
            if (slot.active) continue;
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
        // Server control stream (stream_id=3 is server-initiated unidirectional)
        // Client control stream (stream_id=2), QPACK encoder (stream_id=6)
        // Request streams: client-initiated bidirectional (stream_id=0, 4, 8, ...)

        // Send server control stream with SETTINGS if not done yet
        if (!conn.h3_settings_sent) {
            self.sendH3ControlStream(conn, src);
            conn.h3_settings_sent = true;
        }

        // Ignore client-initiated unidirectional streams (control/QPACK)
        if (sf.stream_id % 4 == 2) return; // unidirectional client-initiated

        // Bidirectional request streams (stream_id % 4 == 0)
        if (sf.stream_id % 4 != 0) return;
        if (sf.data.len == 0) return;

        // Parse HTTP/3 frames
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
                    // Decode QPACK
                    var decoded = h3_qpack.DecodedHeaders{ .headers = undefined, .count = 0 };
                    h3_qpack.decodeHeaders(hf.data[0..hf.len], &decoded) catch {};
                    for (decoded.headers[0..decoded.count]) |f| {
                        if (std.mem.eql(u8, f.name, ":method")) {
                            const ml = @min(f.value.len, method_buf.len);
                            @memcpy(method_buf[0..ml], f.value[0..ml]);
                            method = method_buf[0..ml];
                        } else if (std.mem.eql(u8, f.name, ":path")) {
                            const pl = @min(f.value.len, path_buf.len);
                            @memcpy(path_buf[0..pl], f.value[0..pl]);
                            path = path_buf[0..pl];
                        }
                    }
                },
                else => {},
            }
        }

        // Only handle GET for now
        if (!std.mem.eql(u8, method, "GET")) return;

        // Serve the file
        var fs_path_buf: [512]u8 = undefined;
        const fs_path = http09_server.resolvePath(self.config.www_dir, path, &fs_path_buf) catch return;

        const file = std.fs.openFileAbsolute(fs_path, .{}) catch {
            self.sendH3Response(conn, sf.stream_id, 404, &.{}, src);
            return;
        };
        defer file.close();

        const file_size = file.getEndPos() catch 0;
        var size_buf: [20]u8 = undefined;
        const size_str = std.fmt.bufPrint(&size_buf, "{}", .{file_size}) catch "0";

        // Build response headers
        var header_block: [512]u8 = undefined;
        const hb_len = h3_qpack.encodeHeaders(&[_]h3_qpack.Header{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-length", .value = size_str },
        }, &header_block) catch return;

        // Send HEADERS frame
        var headers_out: [600]u8 = undefined;
        const headers_len = h3_frame.writeFrame(&headers_out, @intFromEnum(h3_frame.FrameType.headers), header_block[0..hb_len]) catch return;
        self.sendStreamData(conn, sf.stream_id, headers_out[0..headers_len], false, src);

        // Send DATA frames
        var data_buf: [1024]u8 = undefined;
        var data_out: [1100]u8 = undefined;
        while (true) {
            const n = file.read(&data_buf) catch break;
            if (n == 0) break;
            const data_len = h3_frame.writeFrame(&data_out, @intFromEnum(h3_frame.FrameType.data), data_buf[0..n]) catch break;
            const eof = (file.getEndPos() catch 0) == (file.getPos() catch 1);
            self.sendStreamData(conn, sf.stream_id, data_out[0..data_len], eof, src);
        }
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
};

// ── Stream download tracker ───────────────────────────────────────────────────

/// Maps a QUIC stream ID to an open output file for download accumulation.
const MAX_STREAMS = 64;

const StreamDownload = struct {
    stream_id: u64,
    file: std.fs.File,
    active: bool,
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
    ticket_store: session_mod.TicketStore = .{},

    // Stored Initial packet for retransmission.
    // On the first sendClientHello call, the packet is built and stored here.
    // Subsequent retransmit calls resend this exact buffer to avoid adding the
    // ClientHello to the TLS transcript a second time.
    initial_pkt: [MAX_DATAGRAM_SIZE]u8 = [_]u8{0} ** MAX_DATAGRAM_SIZE,
    initial_pkt_len: usize = 0,

    pub fn init(allocator: std.mem.Allocator, config: ClientConfig) !Client {
        const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
        errdefer std.posix.close(sock);

        var sk_buf: i32 = 8 * 1024 * 1024;
        const sk_opt = std.mem.asBytes(&sk_buf);
        std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, sk_opt) catch {};
        std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, sk_opt) catch {};

        var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
        const dcid = ConnectionId.random(prng.random(), 8);
        const scid = ConnectionId.random(prng.random(), 8);

        const tls_client = ClientHandshake.init();
        var conn = ConnState{
            .local_cid = scid,
            .remote_cid = dcid,
            .peer = undefined,
        };
        conn.init_keys = InitialSecrets.derive(dcid.slice());

        return .{
            .allocator = allocator,
            .config = config,
            .sock = sock,
            .tls = tls_client,
            .conn = conn,
        };
    }

    pub fn deinit(self: *Client) void {
        std.posix.close(self.sock);
    }

    /// Connect to the server and download all configured URLs.
    pub fn run(self: *Client) !void {
        // Resolve server address (try IPv4 first, then DNS)
        const server_addr = std.net.Address.parseIp4(self.config.host, self.config.port) catch
            try resolveAddress(self.allocator, self.config.host, self.config.port);
        self.conn.peer = server_addr;
        std.debug.print("io: client resolved {s} to {any}\n", .{ self.config.host, server_addr });

        // Send ClientHello Initial packet
        try self.sendClientHello(server_addr);
        var last_initial_ms = std.time.milliTimestamp();

        // Event loop: receive and process packets
        var recv_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
        var deadline = std.time.milliTimestamp() + 10_000; // 10 second timeout

        while (std.time.milliTimestamp() < deadline) {
            // Poll with 100ms timeout so retransmit timers fire promptly.
            var fds = [1]std.posix.pollfd{.{
                .fd = self.sock,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            const ready = std.posix.poll(&fds, 100) catch 0;

            // Retransmit any unacknowledged packets (RFC 9002 §6.2).
            // Runs unconditionally: poll may return immediately with POLLERR
            // (e.g. ICMP port-unreachable) before the server is bound, which
            // would prevent the retransmit timer from ever being reached if the
            // check were inside the `ready == 0` branch.
            const now = std.time.milliTimestamp();
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

            self.processPacket(recv_buf[0..n]);

            if (self.conn.phase == .connected) {
                // Send requests and download
                try self.downloadUrls(server_addr);
                break;
            }

            deadline = std.time.milliTimestamp() + 10_000; // reset on activity
        }

        if (self.conn.phase != .connected) {
            std.debug.print("io: client handshake timed out\n", .{});
            return error.HandshakeTimeout;
        }
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

        // First send: build the ClientHello, updating the transcript once.
        var ch_buf: [2048]u8 = undefined;
        var frame_buf: [2200]u8 = undefined;

        const alpn: ?[]const u8 = if (self.config.http3) tls_hs.ALPN_H3 else if (self.config.http09) tls_hs.ALPN_H09 else null;
        var quic_tp_buf: [128]u8 = undefined;
        const quic_tp = buildClientTransportParams(&quic_tp_buf);

        const ch_len = if (self.config.chacha20)
            try self.tls.buildClientHelloMsgChaCha20(&ch_buf, quic_tp, alpn, self.config.host)
        else
            try self.tls.buildClientHelloMsg(&ch_buf, quic_tp, alpn, self.config.host);

        // CRYPTO frame
        const crypto_len = try buildCryptoFrame(&frame_buf, 0, ch_buf[0..ch_len]);
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
        );
        self.conn.init_pn += 1;
        self.initial_pkt_len = pkt_len;

        _ = try std.posix.sendto(self.sock, self.initial_pkt[0..pkt_len], 0, &server.any, server.getOsSockLen());
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
        const pt_len = initial_mod.unprotectInitialPacket(
            &plaintext,
            buf,
            ip.payload_offset,
            ip.payload_offset + ip.payload_len,
            &init_km.server,
        ) catch return; // bad packet

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
        if (!self.conn.has_app_keys) return;
        const cid_len = self.conn.local_cid.len;
        if (buf.len < 1 + cid_len) return;

        var plaintext: [4096]u8 = undefined;
        const pn_start = 1 + cid_len;

        // Detect key phase flip from server using the UNPROTECTED header byte.
        // The Key Phase bit (0x04) is masked by header protection, so we must
        // remove HP first before reading it (RFC 9001 §5.4.1).
        const unprotected_first = peekUnprotectedFirstByte(buf, pn_start, &self.conn.app_server_km, self.conn.use_chacha20) orelse return;
        const incoming_phase = (unprotected_first & 0x04) != 0;
        if (incoming_phase != self.conn.peer_key_phase and !self.conn.key_update_pending) {
            // Server has rotated its send keys; rotate our receive keys to match.
            self.conn.app_server_km = self.conn.app_server_km.nextGen();
        }
        const pt_len = unprotect1RttPacket(
            &plaintext,
            buf,
            pn_start,
            &self.conn.app_server_km,
            self.conn.use_chacha20,
        ) catch return;

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
            if (ft >= 0x08 and ft <= 0x0f) {
                // STREAM frame — write data to download file
                const sf_r = stream_frame_mod.StreamFrame.parse(plaintext[pos..pt_len], ft) catch return;
                pos += sf_r.consumed;
                self.handleStreamResponse(&sf_r.frame);
                continue;
            }
            // Unknown frame type — cannot safely skip without knowing the length.
            return;
        }
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

        // Use the TLS application_traffic_secret as resumption secret
        const res_secret = self.tls.secrets.client_app;
        var ticket_arr: [session_mod.max_ticket_len]u8 = .{0} ** session_mod.max_ticket_len;
        const tl = @min(ticket_blob.len, session_mod.max_ticket_len);
        @memcpy(ticket_arr[0..tl], ticket_blob[0..tl]);

        var rs_arr: [48]u8 = .{0} ** 48;
        @memcpy(rs_arr[0..32], &res_secret);

        const ticket = session_mod.SessionTicket{
            .lifetime_s = lifetime_s,
            .nonce = nonce,
            .nonce_len = @intCast(nl),
            .ticket = ticket_arr,
            .ticket_len = tl,
            .resumption_secret = rs_arr,
            .resumption_secret_len = 32,
            .max_early_data_size = 16384,
            .received_at_ms = @intCast(std.time.milliTimestamp()),
        };
        self.ticket_store.store(ticket);
        std.debug.print("io: stored session ticket (lifetime={}s)\n", .{lifetime_s});
    }

    /// Respond to a server-sent PATH_CHALLENGE with a matching PATH_RESPONSE.
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
        for (&self.streams) |*s| {
            if (s.active and s.stream_id == sf.stream_id) {
                _ = s.file.write(sf.data) catch {};
                if (sf.fin) {
                    s.file.close();
                    s.active = false;
                    self.streams_done += 1;
                    std.debug.print("io: stream {} download complete\n", .{sf.stream_id});
                }
                return;
            }
        }
    }

    fn downloadUrls(self: *Client, server: std.net.Address) !void {
        std.debug.print("io: sending {} HTTP/0.9 requests\n", .{self.config.urls.len});

        // Ensure output directory exists
        std.fs.makeDirAbsolute(self.config.output_dir) catch {};

        for (self.config.urls, 0..) |url, i| {
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

            // Build HTTP/0.9 request
            var req_buf: [4096]u8 = undefined;
            const req = http09_client.buildRequest(path, &req_buf) catch continue;

            // Allocate stream ID: client-initiated bidirectional = 4*i
            const stream_id: u64 = @as(u64, i) * 4;

            // Open output file
            var dl_path_buf: [512]u8 = undefined;
            const dl_path = http09_client.downloadPath(self.config.output_dir, path, &dl_path_buf) catch continue;
            const out_file = std.fs.createFileAbsolute(dl_path, .{}) catch {
                std.debug.print("io: cannot create {s}\n", .{dl_path});
                continue;
            };

            // Register stream download
            for (&self.streams) |*s| {
                if (!s.active) {
                    s.* = .{ .stream_id = stream_id, .file = out_file, .active = true };
                    break;
                }
            } else {
                out_file.close();
                continue;
            }

            // Build STREAM frame with request payload
            const sf = stream_frame_mod.StreamFrame{
                .stream_id = stream_id,
                .offset = 0,
                .data = req,
                .fin = true,
                .has_length = true,
            };
            var frame_buf: [4200]u8 = undefined;
            const frame_len = sf.serialize(&frame_buf) catch continue;

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

        // Wait for all downloads to complete (receive STREAM data + FIN)
        var recv_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
        const deadline = std.time.milliTimestamp() + 60_000;
        while (std.time.milliTimestamp() < deadline) {
            if (self.streams_done >= self.config.urls.len) break;

            var fds = [1]std.posix.pollfd{.{ .fd = self.sock, .events = std.posix.POLL.IN, .revents = 0 }};
            const ready = std.posix.poll(&fds, 200) catch 0;
            if (ready == 0) continue;
            if (fds[0].revents & std.posix.POLL.IN == 0) continue;

            var drained: usize = 0;
            while (true) {
                var src_addr: std.posix.sockaddr.storage = undefined;
                var src_len: std.posix.socklen_t = @sizeOf(@TypeOf(src_addr));
                const flags: u32 = if (drained == 0) 0 else std.posix.MSG.DONTWAIT;
                const n = std.posix.recvfrom(self.sock, &recv_buf, flags, @ptrCast(&src_addr), &src_len) catch |err| {
                    if (drained > 0 and err == error.WouldBlock) break;
                    break;
                };
                drained += 1;
                self.processPacket(recv_buf[0..n]);
            }
        }

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

/// Resolve a hostname to an IPv6 or IPv4-mapped address.
fn resolveAddress(allocator: std.mem.Allocator, host: []const u8, port: u16) !std.net.Address {
    const list = try std.net.getAddressList(allocator, host, port);
    defer list.deinit();
    if (list.addrs.len == 0) return error.HostNotFound;
    return list.addrs[0];
}
