//! QUIC key derivation utilities (RFC 9001 §5).
//!
//! HKDF-Expand-Label is the core primitive. It wraps HKDF-Expand to produce
//! QUIC-specific keying material with a structured label:
//!
//!   HKDF-Expand-Label(Secret, Label, Context, Length)
//!     = HKDF-Expand(Secret, HkdfLabel, Length)
//!
//!   HkdfLabel = Length || "tls13 " || Label || Context

const std = @import("std");
const crypto = std.crypto;
const Sha256 = crypto.hash.sha2.Sha256;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;

/// Perform HKDF-Expand-Label (TLS 1.3 / RFC 8446 §7.1).
/// `out` receives exactly `out.len` bytes of key material.
pub fn hkdfExpandLabel(
    out: []u8,
    secret: []const u8,
    label: []const u8,
    context: []const u8,
) void {
    // HkdfLabel encoding: u16 length + u8 label_len + "tls13 " + label + u8 ctx_len + context
    var info_buf: [512]u8 = undefined;
    var pos: usize = 0;

    // Length (u16 big-endian)
    const out_len: u16 = @intCast(out.len);
    info_buf[pos] = @intCast(out_len >> 8);
    pos += 1;
    info_buf[pos] = @intCast(out_len & 0xff);
    pos += 1;

    // Label: u8 len + "tls13 " + label
    const tls13_prefix = "tls13 ";
    const label_full_len = tls13_prefix.len + label.len;
    info_buf[pos] = @intCast(label_full_len);
    pos += 1;
    @memcpy(info_buf[pos .. pos + tls13_prefix.len], tls13_prefix);
    pos += tls13_prefix.len;
    @memcpy(info_buf[pos .. pos + label.len], label);
    pos += label.len;

    // Context: u8 len + context
    info_buf[pos] = @intCast(context.len);
    pos += 1;
    @memcpy(info_buf[pos .. pos + context.len], context);
    pos += context.len;

    HkdfSha256.expand(out, info_buf[0..pos], secret[0..Sha256.digest_length].*);
}

/// Derive the initial secrets for a QUIC connection (RFC 9001 §5.2 / RFC 9369 §7.2).
///
/// The initial salt and key-derivation labels are version-specific.
/// Both client and server derive their secrets from the connection's initial
/// DCID (the destination connection ID chosen by the client).
pub const InitialSecrets = struct {
    // RFC 9001 §5.2 — QUIC v1 initial salt
    pub const initial_salt_v1 = "\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a";
    // RFC 9369 §7.2 — QUIC v2 initial salt
    pub const initial_salt_v2 = "\x0d\xed\xe3\xde\xf7\x00\xa6\xdb\x81\x93\x81\xbe\x6e\x26\x9d\xcb\xf9\xbd\x2e\xd9";

    // Kept as alias so existing call sites that use `initial_salt` still compile.
    pub const initial_salt = initial_salt_v1;

    client: KeyMaterial,
    server: KeyMaterial,

    /// Derive QUIC v1 initial secrets (RFC 9001 §5.2).
    pub fn derive(dcid: []const u8) InitialSecrets {
        const initial_secret = HkdfSha256.extract(initial_salt_v1, dcid);
        var client: KeyMaterial = undefined;
        var server: KeyMaterial = undefined;
        hkdfExpandLabel(&client.secret, &initial_secret, "client in", "");
        hkdfExpandLabel(&server.secret, &initial_secret, "server in", "");
        client.expand();
        server.expand();
        return .{ .client = client, .server = server };
    }

    /// Derive QUIC v2 initial secrets (RFC 9369 §7.2).
    /// Uses the v2 salt and "quicv2 *" derivation labels.
    pub fn deriveV2(dcid: []const u8) InitialSecrets {
        const initial_secret = HkdfSha256.extract(initial_salt_v2, dcid);
        var client: KeyMaterial = undefined;
        var server: KeyMaterial = undefined;
        hkdfExpandLabel(&client.secret, &initial_secret, "client in", "");
        hkdfExpandLabel(&server.secret, &initial_secret, "server in", "");
        client.expandV2();
        server.expandV2();
        return .{ .client = client, .server = server };
    }
};

/// Key material for one direction: key, IV, and header protection key.
///
/// `key` (16 bytes) is used for AES-128-GCM.
/// `key32` (32 bytes) is used for ChaCha20-Poly1305.
/// Both are derived unconditionally so the struct can serve either suite.
pub const KeyMaterial = struct {
    secret: [Sha256.digest_length]u8 = undefined,
    key: [16]u8 = undefined,
    key32: [32]u8 = undefined,
    iv: [12]u8 = undefined,
    hp: [16]u8 = undefined,
    hp32: [32]u8 = undefined,

    /// Derive key, IV, and HP from the secret using QUIC v1 labels (RFC 9001 §5.1).
    pub fn expand(self: *KeyMaterial) void {
        hkdfExpandLabel(&self.key, &self.secret, "quic key", "");
        hkdfExpandLabel(&self.key32, &self.secret, "quic key", "");
        hkdfExpandLabel(&self.iv, &self.secret, "quic iv", "");
        hkdfExpandLabel(&self.hp, &self.secret, "quic hp", "");
        hkdfExpandLabel(&self.hp32, &self.secret, "quic hp", "");
    }

    /// Derive key, IV, and HP from the secret using QUIC v2 labels (RFC 9369 §7.1).
    pub fn expandV2(self: *KeyMaterial) void {
        hkdfExpandLabel(&self.key, &self.secret, "quicv2 key", "");
        hkdfExpandLabel(&self.key32, &self.secret, "quicv2 key", "");
        hkdfExpandLabel(&self.iv, &self.secret, "quicv2 iv", "");
        hkdfExpandLabel(&self.hp, &self.secret, "quicv2 hp", "");
        hkdfExpandLabel(&self.hp32, &self.secret, "quicv2 hp", "");
    }

    /// Derive the next-generation key material for QUIC v1 key updates (RFC 9001 §6).
    ///
    /// Only the AEAD key and IV are updated; header-protection keys are
    /// intentionally preserved from the current generation.
    /// RFC 9001 §6.4: "The sending and receiving header protection keys are
    /// not updated during a key update."
    pub fn nextGen(self: *const KeyMaterial) KeyMaterial {
        var next: KeyMaterial = undefined;
        hkdfExpandLabel(&next.secret, &self.secret, "quic ku", "");
        hkdfExpandLabel(&next.key, &next.secret, "quic key", "");
        hkdfExpandLabel(&next.key32, &next.secret, "quic key", "");
        hkdfExpandLabel(&next.iv, &next.secret, "quic iv", "");
        next.hp = self.hp;
        next.hp32 = self.hp32;
        return next;
    }

    /// Derive the next-generation key material for QUIC v2 key updates (RFC 9369 §7.1).
    pub fn nextGenV2(self: *const KeyMaterial) KeyMaterial {
        var next: KeyMaterial = undefined;
        hkdfExpandLabel(&next.secret, &self.secret, "quicv2 ku", "");
        hkdfExpandLabel(&next.key, &next.secret, "quicv2 key", "");
        hkdfExpandLabel(&next.key32, &next.secret, "quicv2 key", "");
        hkdfExpandLabel(&next.iv, &next.secret, "quicv2 iv", "");
        next.hp = self.hp;
        next.hp32 = self.hp32;
        return next;
    }
};

test "keys: RFC 9001 Appendix A initial secrets" {
    // Test vectors from RFC 9001 Appendix A.1 (final RFC, not a draft).
    const testing = std.testing;

    const dcid = "\x83\x94\xc8\xf0\x3e\x51\x57\x08";
    const secrets = InitialSecrets.derive(dcid);

    // client_initial_secret = c00cf151ca5be075ed0ebfb5c80323c4...
    const expected_client_secret = "\xc0\x0c\xf1\x51\xca\x5b\xe0\x75\xed\x0e\xbf\xb5\xc8\x03\x23\xc4\x2d\x6b\x7d\xb6\x78\x81\x28\x9a\xf4\x00\x8f\x1f\x6c\x35\x7a\xea";
    try testing.expectEqualSlices(u8, expected_client_secret, &secrets.client.secret);

    // client key = 1f369613dd76d5467730efcbe3b1a22d
    const expected_client_key = "\x1f\x36\x96\x13\xdd\x76\xd5\x46\x77\x30\xef\xcb\xe3\xb1\xa2\x2d";
    try testing.expectEqualSlices(u8, expected_client_key, &secrets.client.key);

    // client iv = fa044b2f42a3fd3b46fb255c
    const expected_client_iv = "\xfa\x04\x4b\x2f\x42\xa3\xfd\x3b\x46\xfb\x25\x5c";
    try testing.expectEqualSlices(u8, expected_client_iv, &secrets.client.iv);

    // client hp = 9f50449e04a0e810283a1e9933adedd2
    const expected_client_hp = "\x9f\x50\x44\x9e\x04\xa0\xe8\x10\x28\x3a\x1e\x99\x33\xad\xed\xd2";
    try testing.expectEqualSlices(u8, expected_client_hp, &secrets.client.hp);
}

test "keys: RFC 9001 Appendix A server initial secrets" {
    const testing = std.testing;
    const dcid = "\x83\x94\xc8\xf0\x3e\x51\x57\x08";
    const secrets = InitialSecrets.derive(dcid);

    // server key = cf3a5331653c364c88f0f379b6067e37
    const expected_server_key = "\xcf\x3a\x53\x31\x65\x3c\x36\x4c\x88\xf0\xf3\x79\xb6\x06\x7e\x37";
    try testing.expectEqualSlices(u8, expected_server_key, &secrets.server.key);

    // server iv = 0ac1493ca1905853b0bba03e
    const expected_server_iv = "\x0a\xc1\x49\x3c\xa1\x90\x58\x53\xb0\xbb\xa0\x3e";
    try testing.expectEqualSlices(u8, expected_server_iv, &secrets.server.iv);

    // server hp = c206b8d9b9f0f37644430b490eeaa314
    const expected_server_hp = "\xc2\x06\xb8\xd9\xb9\xf0\xf3\x76\x44\x43\x0b\x49\x0e\xea\xa3\x14";
    try testing.expectEqualSlices(u8, expected_server_hp, &secrets.server.hp);
}

test "keys: QUIC v2 initial secrets differ from v1" {
    // Sanity check: v2 derivation (different salt + labels) must produce
    // different keys from v1 for the same DCID.  The exact expected values
    // should be cross-checked against RFC 9369 Appendix A once confirmed.
    const testing = std.testing;
    const dcid = "\x83\x94\xc8\xf0\x3e\x51\x57\x08";
    const v1 = InitialSecrets.derive(dcid);
    const v2 = InitialSecrets.deriveV2(dcid);

    // v2 and v1 must produce different key material.
    try testing.expect(!std.mem.eql(u8, &v1.client.key, &v2.client.key));
    try testing.expect(!std.mem.eql(u8, &v1.server.key, &v2.server.key));
    try testing.expect(!std.mem.eql(u8, &v1.client.iv, &v2.client.iv));

    // Key / IV / HP sizes must be correct.
    try testing.expectEqual(@as(usize, 16), v2.client.key.len);
    try testing.expectEqual(@as(usize, 12), v2.client.iv.len);
    try testing.expectEqual(@as(usize, 16), v2.client.hp.len);

    // v2 derivation must be deterministic.
    const v2b = InitialSecrets.deriveV2(dcid);
    try testing.expectEqualSlices(u8, &v2.client.key, &v2b.client.key);
    try testing.expectEqualSlices(u8, &v2.server.key, &v2b.server.key);
}
