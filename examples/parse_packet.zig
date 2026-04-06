//! Example: parse a raw QUIC Initial packet header
//!
//! Demonstrates using zquic to:
//!   1. Detect packet type from the first byte.
//!   2. Parse a Long Header (Initial packet) using parseLong.
//!   3. Derive Initial secrets from the parsed DCID.
//!
//! The example uses the RFC 9001 Appendix A sample DCID so it produces
//! deterministic output you can verify against the spec.
//!
//! Build:
//!   zig build examples
//!
//! Run:
//!   ./zig-out/bin/parse_packet

const std = @import("std");
const zquic = @import("zquic");

const header_mod = zquic.packet.header;
const crypto_keys = zquic.crypto.keys;

fn printHex(label: []const u8, bytes: []const u8) void {
    std.debug.print("{s}: ", .{label});
    for (bytes) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});
}

pub fn main() !void {
    std.debug.print("zquic parse-packet example\n", .{});
    std.debug.print("──────────────────────────\n", .{});

    // Manually constructed Long Header Initial packet (partial).
    // Header format: 1 byte flags | 4 bytes version | 1 byte DCID len |
    //                8 bytes DCID | 1 byte SCID len | ...
    const raw: []const u8 = &[_]u8{
        // Long header byte: Initial packet type (0xc0) | pn_len=2 (0x03)
        0xc3,
        // Version: QUIC v1
        0x00,
        0x00,
        0x00,
        0x01,
        // DCID length (8) + DCID (RFC 9001 Appendix A sample)
        0x08,
        0x83,
        0x94,
        0xc8,
        0xf0,
        0x3e,
        0x51,
        0x57,
        0x08,
        // SCID length (0)
        0x00,
        // Token length (0) — note: parseLong stops at SCID end
        0x00,
    };

    // parseLong returns { header: LongHeader, consumed: usize }
    const result = try header_mod.parseLong(raw);
    const hdr = result.header;
    std.debug.print("Packet type  : {}\n", .{hdr.packet_type});
    std.debug.print("Version      : 0x{x:0>8}\n", .{hdr.version});
    std.debug.print("DCID length  : {}\n", .{hdr.dcid.len});
    printHex("DCID         ", hdr.dcid.slice());
    std.debug.print("SCID length  : {}\n", .{hdr.scid.len});
    std.debug.print("Bytes consumed: {}\n", .{result.consumed});

    // Derive Initial secrets from DCID (RFC 9001 §5.2).
    const secrets = crypto_keys.InitialSecrets.derive(hdr.dcid.slice());
    printHex("Client key   ", &secrets.client.key);
    printHex("Client IV    ", &secrets.client.iv);
    printHex("Client HP    ", &secrets.client.hp);

    std.debug.print("\nPacket parsed successfully.\n", .{});
}
