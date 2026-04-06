//! QUIC key update mechanism (RFC 9001 §6).
//!
//! Key updates allow both endpoints to rotate their 1-RTT AEAD keys
//! without interrupting the connection.  The procedure is:
//!
//! 1. Initiator sets the Key Phase bit to the opposite of the current phase
//!    and sends a packet encrypted with the new keys.
//! 2. Responder detects the phase flip, derives its own updated keys, and
//!    begins sending with the new phase bit set.
//!
//! Key derivation (RFC 9001 §6.1):
//!
//!   secret_N+1 = HKDF-Expand-Label(secret_N, "quic ku", "", Hash.length)
//!   [key, iv] = HKDF-Expand-Label(secret_N+1, "quic key"/"quic iv", "", ...)
//!
//! After a successful key update:
//! - Old receive keys are kept briefly for reordered packets.
//! - Old send keys are discarded immediately.
//!
//! This module provides:
//! - `AppKeys`: a single set of 1-RTT AEAD key + IV.
//! - `KeyPhase`: wraps the current and previous key phases.
//! - `updateKeys`: derives the next generation of keys from the current secret.

const std = @import("std");
const crypto_keys = @import("keys.zig");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A 1-RTT AEAD key + IV pair (AES-128-GCM or ChaCha20-Poly1305).
pub const AppKeys = struct {
    /// AEAD write key (16 bytes for AES-128-GCM).
    key: [16]u8,
    /// AEAD nonce IV (12 bytes).
    iv: [12]u8,
    /// Header protection key (16 bytes).
    hp: [16]u8,
    /// The 64-byte traffic secret from which key/iv/hp are derived.
    secret: [64]u8,
    secret_len: u8,
};

/// Key phase bit value (0 or 1), matching the K bit in the Short Header.
pub const KeyPhase = enum(u1) { zero = 0, one = 1 };

/// State for both current and previous key generations per direction.
pub const KeyPhaseState = struct {
    /// Current outgoing phase.
    phase: KeyPhase = .zero,
    /// Keys for the current phase.
    current: AppKeys,
    /// Keys kept from the previous phase (for reordered packets).
    /// Null before the first key update.
    previous: ?AppKeys = null,

    /// True when we are waiting for the peer to confirm the key update
    /// (i.e., we have sent at least one packet with the new phase bit but
    /// have not yet received a packet back in the new phase).
    update_pending: bool = false,

    /// Flip the phase and derive new keys.
    pub fn rotate(self: *KeyPhaseState) void {
        self.previous = self.current;
        self.current = updateKeys(&self.current);
        self.phase = if (self.phase == .zero) .one else .zero;
        self.update_pending = true;
    }

    /// Called when the peer's key update is confirmed (a packet with the
    /// new phase bit was successfully decrypted).
    pub fn confirmUpdate(self: *KeyPhaseState) void {
        self.update_pending = false;
        // Previous keys are still needed briefly; they are freed by
        // discardPrevious() once all in-flight packets are acknowledged.
    }

    /// Discard the previous generation keys once they are no longer needed.
    pub fn discardPrevious(self: *KeyPhaseState) void {
        self.previous = null;
    }
};

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derive the next generation of 1-RTT AEAD keys from `current`.
///
/// RFC 9001 §6.1:
///   next_secret = HKDF-Expand-Label(current_secret, "quic ku", "", Hash.length)
///   next_key    = HKDF-Expand-Label(next_secret, "quic key", "", key.length)
///   next_iv     = HKDF-Expand-Label(next_secret, "quic iv",  "", iv.length)
///   next_hp     = hp is NOT rotated during key updates — same HP key
pub fn updateKeys(current: *const AppKeys) AppKeys {
    const secret_len = current.secret_len;
    var next_secret: [64]u8 = .{0} ** 64;

    // HKDF-Expand-Label with label "quic ku" and empty context.
    crypto_keys.hkdfExpandLabel(next_secret[0..secret_len], current.secret[0..secret_len], "quic ku", &.{});

    var next_key: [16]u8 = undefined;
    var next_iv: [12]u8 = undefined;
    crypto_keys.hkdfExpandLabel(&next_key, next_secret[0..secret_len], "quic key", &.{});
    crypto_keys.hkdfExpandLabel(&next_iv, next_secret[0..secret_len], "quic iv", &.{});

    return AppKeys{
        .key = next_key,
        .iv = next_iv,
        // HP key is NOT updated on key update (RFC 9001 §6.1 footnote).
        .hp = current.hp,
        .secret = next_secret,
        .secret_len = secret_len,
    };
}

/// Initialise an `AppKeys` from a raw traffic secret.
pub fn keysFromSecret(secret: []const u8) AppKeys {
    std.debug.assert(secret.len <= 64);
    var app: AppKeys = undefined;
    app.secret_len = @intCast(secret.len);
    app.secret = .{0} ** 64;
    @memcpy(app.secret[0..secret.len], secret);

    crypto_keys.hkdfExpandLabel(&app.key, secret, "quic key", &.{});
    crypto_keys.hkdfExpandLabel(&app.iv, secret, "quic iv", &.{});
    crypto_keys.hkdfExpandLabel(&app.hp, secret, "quic hp", &.{});
    return app;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "key_update: updateKeys produces different key material" {
    const testing = std.testing;

    const secret = [_]u8{0x11} ** 32;
    const gen0 = keysFromSecret(&secret);
    const gen1 = updateKeys(&gen0);
    const gen2 = updateKeys(&gen1);

    // Each generation's key should differ.
    try testing.expect(!std.mem.eql(u8, &gen0.key, &gen1.key));
    try testing.expect(!std.mem.eql(u8, &gen1.key, &gen2.key));
    try testing.expect(!std.mem.eql(u8, &gen0.key, &gen2.key));

    // IV should also differ.
    try testing.expect(!std.mem.eql(u8, &gen0.iv, &gen1.iv));
    try testing.expect(!std.mem.eql(u8, &gen1.iv, &gen2.iv));

    // HP key must stay the SAME across updates (RFC 9001 §6.1).
    try testing.expectEqualSlices(u8, &gen0.hp, &gen1.hp);
    try testing.expectEqualSlices(u8, &gen1.hp, &gen2.hp);
}

test "key_update: KeyPhaseState rotation" {
    const testing = std.testing;

    const secret = [_]u8{0x22} ** 32;
    var state = KeyPhaseState{
        .current = keysFromSecret(&secret),
    };

    try testing.expectEqual(KeyPhase.zero, state.phase);
    const key_before = state.current.key;

    state.rotate();
    try testing.expectEqual(KeyPhase.one, state.phase);
    try testing.expect(state.update_pending);
    try testing.expect(!std.mem.eql(u8, &key_before, &state.current.key));
    try testing.expect(state.previous != null);

    state.confirmUpdate();
    try testing.expect(!state.update_pending);

    state.rotate();
    try testing.expectEqual(KeyPhase.zero, state.phase);

    state.discardPrevious();
    try testing.expectEqual(@as(?AppKeys, null), state.previous);
}

test "key_update: keysFromSecret deterministic" {
    const secret = [_]u8{0x33} ** 32;
    const a = keysFromSecret(&secret);
    const b = keysFromSecret(&secret);
    try std.testing.expectEqualSlices(u8, &a.key, &b.key);
    try std.testing.expectEqualSlices(u8, &a.iv, &b.iv);
    try std.testing.expectEqualSlices(u8, &a.hp, &b.hp);
}
