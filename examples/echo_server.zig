//! Example: QUIC cryptographic primitives
//!
//! Demonstrates using zquic's library modules to:
//!   1. Derive Initial packet keys from a destination connection ID.
//!   2. Encode and decode a variable-length integer.
//!   3. Encrypt and decrypt a payload with AES-128-GCM.
//!
//! Build:
//!   zig build examples
//!
//! Run:
//!   ./zig-out/bin/echo_server

const std = @import("std");
const zquic = @import("zquic");

const varint = zquic.varint;
const types = zquic.types;
const crypto_keys = zquic.crypto.keys;
const aead_mod = zquic.crypto.aead;

fn printHex(label: []const u8, bytes: []const u8) void {
    std.debug.print("{s}: ", .{label});
    for (bytes) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});
}

pub fn main() !void {
    std.debug.print("zquic crypto-primitives example\n", .{});
    std.debug.print("────────────────────────────────\n", .{});

    // ── 1. Connection ID and Initial key derivation ─────────────────────────
    // In a real server the DCID comes from the client's first Initial packet.
    const dcid_bytes = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const dcid = try types.ConnectionId.fromSlice(&dcid_bytes);
    printHex("DCID      ", dcid.slice());

    // Derive Initial packet secrets (RFC 9001 §5.2).
    const secrets = crypto_keys.InitialSecrets.derive(dcid.slice());
    printHex("Client key", &secrets.client.key);
    printHex("Client IV ", &secrets.client.iv);
    printHex("Server key", &secrets.server.key);

    // ── 2. Variable-length integer codec ────────────────────────────────────
    var buf: [8]u8 = undefined;
    const encoded = try varint.encode(&buf, 15293);
    std.debug.print("varint(15293) → {} bytes: ", .{encoded.len});
    for (encoded) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});

    const decoded = try varint.decode(encoded);
    std.debug.assert(decoded.value == 15293);
    std.debug.print("decoded back  → {}\n", .{decoded.value});

    // ── 3. AES-128-GCM encrypt / decrypt round-trip ─────────────────────────
    const plaintext = "hello quic";
    const nonce = [_]u8{0x00} ** 12;
    const aad = "additional data";

    var ciphertext: [26]u8 = undefined; // 10 plaintext + 16 tag
    try aead_mod.encryptAes128Gcm(
        &ciphertext,
        plaintext,
        aad,
        secrets.client.key,
        nonce,
    );
    printHex("Ciphertext", &ciphertext);

    var recovered: [10]u8 = undefined;
    try aead_mod.decryptAes128Gcm(
        &recovered,
        &ciphertext,
        aad,
        secrets.client.key,
        nonce,
    );
    std.debug.print("Decrypted  → {s}\n", .{recovered});
    std.debug.assert(std.mem.eql(u8, &recovered, plaintext));

    std.debug.print("\nAll primitives working correctly.\n", .{});
}
