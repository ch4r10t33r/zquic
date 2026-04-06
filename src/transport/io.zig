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

    // Retry token (set when server sends Retry; included in next Initial)
    retry_token: [64]u8 = [_]u8{0} ** 64,
    retry_token_len: usize = 0,
    hs_crypto_offset: u64 = 0,

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

    /// Derive Handshake and 1-RTT QUIC keys from TLS traffic secrets.
    pub fn deriveHandshakeKeys(self: *ConnState, secrets: *const tls_hs.TrafficSecrets) void {
        const hs_client_qkm = tls_hs.deriveQuicKeys(secrets.client_handshake);
        const hs_server_qkm = tls_hs.deriveQuicKeys(secrets.server_handshake);
        const app_client_qkm = tls_hs.deriveQuicKeys(secrets.client_app);
        const app_server_qkm = tls_hs.deriveQuicKeys(secrets.server_app);

        // Convert QuicKeyMaterial to KeyMaterial
        self.hs_client_km = .{ .key = hs_client_qkm.key, .iv = hs_client_qkm.iv, .hp = hs_client_qkm.hp, .secret = secrets.client_handshake };
        self.hs_server_km = .{ .key = hs_server_qkm.key, .iv = hs_server_qkm.iv, .hp = hs_server_qkm.hp, .secret = secrets.server_handshake };
        self.app_client_km = .{ .key = app_client_qkm.key, .iv = app_client_qkm.iv, .hp = app_client_qkm.hp, .secret = secrets.client_app };
        self.app_server_km = .{ .key = app_server_qkm.key, .iv = app_server_qkm.iv, .hp = app_server_qkm.hp, .secret = secrets.server_app };

        self.has_hs_keys = true;
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

        std.debug.print("io: server bound on 0.0.0.0:{d}\n", .{config.port});

        // Generate a random Retry token secret for this server lifetime
        var retry_secret: [32]u8 = undefined;
        std.crypto.random.bytes(&retry_secret);

        return .{
            .allocator = allocator,
            .config = config,
            .sock = sock,
            .cert_der = cert_der,
            .private_key = pk,
            .retry_secret = retry_secret,
        };
    }

    pub fn deinit(self: *Server) void {
        std.posix.close(self.sock);
        self.allocator.free(self.cert_der);
    }

    /// Run the server event loop (blocking).
    pub fn run(self: *Server) !void {
        var recv_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;

        while (true) {
            var src_addr: std.posix.sockaddr.storage = undefined;
            var src_len: std.posix.socklen_t = @sizeOf(@TypeOf(src_addr));
            const n = std.posix.recvfrom(
                self.sock,
                &recv_buf,
                0,
                @ptrCast(&src_addr),
                &src_len,
            ) catch |err| {
                std.debug.print("io: recvfrom error: {}\n", .{err});
                continue;
            };

            const src = std.net.Address{ .any = @as(*const std.posix.sockaddr, @ptrCast(&src_addr)).* };
            self.processPacket(recv_buf[0..n], src);
        }
    }

    /// Dispatch a received UDP datagram.
    fn processPacket(self: *Server, buf: []const u8, src: std.net.Address) void {
        if (buf.len < 5) return;

        // Version Negotiation: first byte 0x80, version = 0
        if (buf[0] & 0x80 != 0 and buf.len >= 5 and
            buf[1] == 0 and buf[2] == 0 and buf[3] == 0 and buf[4] == 0)
        {
            return; // discard
        }

        if (buf[0] & 0x80 != 0) {
            // Long header
            const lh = header_mod.parseLong(buf) catch return;
            // RFC 9000 §6.1: respond with Version Negotiation for any
            // unsupported version so that readiness probes (wait-for-it-quic
            // sends version 0x57415449 "WAIT") get a proper reply and do not
            // consume connection slots.
            if (lh.header.version != version_neg_mod.QUIC_V1) {
                self.sendVersionNegotiation(lh.header.scid.slice(), lh.header.dcid.slice(), src);
                return;
            }
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

        // Find or create connection
        var conn: *ConnState = self.findConn(ip.dcid) orelse blk: {
            // New connection from client
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

        // Derive QUIC key material from TLS handshake secrets
        // (secrets are now available after processClientHello)
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
        if (conn.phase != .waiting_finished) return;
        if (!conn.has_hs_keys) return;

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
                // ACK frame — skip for now (just advance past it)
                fpos += 1;
                _ = varint.decode(plaintext[fpos..]) catch break; // largest acked
                fpos += (varint.decode(plaintext[fpos..]) catch break).len;
                break; // simplification
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
                if (conn.phase != .connected) continue;
                if (!conn.has_app_keys) continue;
                const cid_len = conn.local_cid.len;
                if (buf.len < 1 + cid_len) continue;
                const candidate = ConnectionId.fromSlice(buf[1 .. 1 + cid_len]) catch continue;
                if (!ConnectionId.eql(conn.local_cid, candidate)) continue;

                // Detect peer-initiated key update via key phase bit flip.
                const incoming_phase = (buf[0] & 0x04) != 0;
                if (incoming_phase != conn.peer_key_phase and !conn.key_update_pending) {
                    // Rotate receive keys to match the peer's new phase.
                    conn.app_client_km = conn.app_client_km.nextGen();
                }

                // Try to decrypt with current client app keys.
                var plaintext: [4096]u8 = undefined;
                const pn_start = 1 + cid_len;
                const pt_len = unprotect1RttPacket(
                    &plaintext,
                    buf,
                    pn_start,
                    &conn.app_client_km,
                    conn.use_chacha20,
                ) catch continue;

                conn.peer_key_phase = incoming_phase;
                conn.key_update_pending = false;

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
            if (ft == 0x01) { // PING — no body, continue
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
                const sf_r = stream_frame_mod.StreamFrame.parse(frames[pos..], ft) catch return;
                pos += sf_r.consumed;
                self.handleStreamData(conn, &sf_r.frame, src);
                continue;
            }
            // Unknown frame — stop parsing
            return;
        }
    }

    /// Encrypt and send a 1-RTT packet, selecting AES or ChaCha20 per conn.
    fn send1Rtt(self: *Server, conn: *ConnState, payload: []const u8, dst: std.net.Address) void {
        var send_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
        const pkt_len = build1RttPacketFull(
            &send_buf,
            conn.remote_cid,
            payload,
            conn.app_pn,
            &conn.app_server_km,
            conn.key_phase_bit,
            conn.use_chacha20,
        ) catch return;
        conn.app_pn += 1;
        _ = std.posix.sendto(self.sock, send_buf[0..pkt_len], 0, &dst.any, dst.getOsSockLen()) catch {};
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
        // Only unidirectional client-initiated streams carry HTTP/0.9 requests
        if (sf.stream_id % 4 != 0 and sf.stream_id % 4 != 2) return;
        if (sf.data.len == 0) return;

        var req_buf: [http09_server.max_request_len]u8 = undefined;
        @memcpy(req_buf[0..sf.data.len], sf.data);
        const req = http09_server.parseRequest(req_buf[0..sf.data.len]) catch return;

        var path_buf: [512]u8 = undefined;
        const fs_path = http09_server.resolvePath(req.path, &path_buf) catch return;

        const file = std.fs.openFileAbsolute(fs_path, .{}) catch {
            std.debug.print("io: file not found: {s}\n", .{fs_path});
            return;
        };
        defer file.close();

        var file_buf: [1024]u8 = undefined;
        var stream_offset: u64 = 0;
        while (true) {
            const n = file.read(&file_buf) catch break;
            if (n == 0) break;

            const fin = (file.getEndPos() catch 0) == (file.getPos() catch 1);
            const sf_out = stream_frame_mod.StreamFrame{
                .stream_id = sf.stream_id,
                .offset = stream_offset,
                .data = file_buf[0..n],
                .fin = fin,
                .has_length = true,
            };
            stream_offset += n;

            var frame_buf: [1200]u8 = undefined;
            const frame_len = sf_out.serialize(&frame_buf) catch break;
            self.send1Rtt(conn, frame_buf[0..frame_len], src);
        }
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
        const fs_path = http09_server.resolvePath(path, &fs_path_buf) catch return;

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

    pub fn init(allocator: std.mem.Allocator, config: ClientConfig) !Client {
        const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
        errdefer std.posix.close(sock);

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

        // Send ClientHello Initial packet
        try self.sendClientHello(server_addr);

        // Event loop: receive and process packets
        var recv_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;
        var deadline = std.time.milliTimestamp() + 10_000; // 10 second timeout

        while (std.time.milliTimestamp() < deadline) {
            // Poll with 100ms timeout
            var fds = [1]std.posix.pollfd{.{
                .fd = self.sock,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            const ready = std.posix.poll(&fds, 100) catch 0;
            if (ready == 0) continue;
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
        var ch_buf: [2048]u8 = undefined;
        var frame_buf: [2200]u8 = undefined;
        var pkt_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;

        // Build ClientHello
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
            &pkt_buf,
            self.conn.remote_cid,
            self.conn.local_cid,
            token,
            frame_buf[0..payload_len],
            self.conn.init_pn,
            &init_km.client,
        );
        self.conn.init_pn += 1;

        _ = try std.posix.sendto(self.sock, pkt_buf[0..pkt_len], 0, &server.any, server.getOsSockLen());
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

        // Send a new ClientHello Initial with the token
        self.sendClientHello(self.conn.peer) catch {};
    }

    fn processInitialPacket(
        self: *Client,
        buf: []const u8,
    ) void {
        const ip = packet_mod.parseInitial(buf) catch return;
        const init_km = self.conn.init_keys orelse return;

        var plaintext: [4096]u8 = undefined;
        const pt_len = initial_mod.unprotectInitialPacket(
            &plaintext,
            buf,
            ip.payload_offset,
            ip.payload_offset + ip.payload_len,
            &init_km.server,
        ) catch return;

        // Extract CRYPTO frames
        var pos: usize = 0;
        while (pos < pt_len) {
            if (plaintext[pos] == 0x00) {
                pos += 1;
                continue;
            }
            if (plaintext[pos] == 0x02 or plaintext[pos] == 0x03) break; // skip ACK
            if (plaintext[pos] != 0x06) break;
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

            // Send client Finished
            self.sendClientFinished(fin_buf[0..fin_len]);
            break;
        }
    }

    fn sendClientFinished(self: *Client, fin_bytes: []const u8) void {
        if (!self.conn.has_hs_keys) return;

        var frame_buf: [256]u8 = undefined;
        var pkt_buf: [MAX_DATAGRAM_SIZE]u8 = undefined;

        const crypto_len = buildCryptoFrame(&frame_buf, 0, fin_bytes) catch return;
        const pkt_len = buildHandshakePacket(
            &pkt_buf,
            self.conn.remote_cid,
            self.conn.local_cid,
            frame_buf[0..crypto_len],
            self.conn.hs_pn,
            &self.conn.hs_client_km,
        ) catch return;
        self.conn.hs_pn += 1;

        _ = std.posix.sendto(
            self.sock,
            pkt_buf[0..pkt_len],
            0,
            &self.conn.peer.any,
            self.conn.peer.getOsSockLen(),
        ) catch {};
    }

    fn process1RttPacket(self: *Client, buf: []const u8) void {
        if (!self.conn.has_app_keys) return;
        const cid_len = self.conn.local_cid.len;
        if (buf.len < 1 + cid_len) return;

        // Detect key phase flip from server (key update initiated by server).
        const incoming_phase = (buf[0] & 0x04) != 0;
        if (incoming_phase != self.conn.peer_key_phase and !self.conn.key_update_pending) {
            // Server has rotated its send keys; rotate our receive keys to match.
            self.conn.app_server_km = self.conn.app_server_km.nextGen();
        }

        var plaintext: [4096]u8 = undefined;
        const pn_start = 1 + cid_len;
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
            if (ft == 0x1e) { // HANDSHAKE_DONE
                std.debug.print("io: client received HANDSHAKE_DONE\n", .{});
                self.conn.phase = .connected;
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
            // Skip unrecognised frame — can't reliably advance, stop
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
            const dl_path = http09_client.downloadPath(path, &dl_path_buf) catch continue;
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
        const deadline = std.time.milliTimestamp() + 30_000;
        while (std.time.milliTimestamp() < deadline) {
            if (self.streams_done >= self.config.urls.len) break;

            var fds = [1]std.posix.pollfd{.{ .fd = self.sock, .events = std.posix.POLL.IN, .revents = 0 }};
            const ready = std.posix.poll(&fds, 200) catch 0;
            if (ready == 0) continue;
            if (fds[0].revents & std.posix.POLL.IN == 0) continue;

            var src_addr: std.posix.sockaddr.storage = undefined;
            var src_len: std.posix.socklen_t = @sizeOf(@TypeOf(src_addr));
            const n = std.posix.recvfrom(self.sock, &recv_buf, 0, @ptrCast(&src_addr), &src_len) catch continue;
            self.processPacket(recv_buf[0..n]);
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
