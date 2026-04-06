//! Example: session ticket store and 0-RTT key derivation
//!
//! Shows how to:
//!   1. Create and store a session ticket (as received from a server).
//!   2. Retrieve a valid ticket from the store.
//!   3. Derive 0-RTT AEAD keys from the ticket's resumption secret.
//!   4. Serialise/deserialise a ticket for persistent storage.
//!
//! Build:
//!   zig build examples
//!
//! Run:
//!   ./zig-out/bin/session_resumption

const std = @import("std");
const zquic = @import("zquic");

const session = zquic.crypto.session;

fn printHex(label: []const u8, bytes: []const u8) void {
    std.debug.print("{s}: ", .{label});
    for (bytes) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});
}

pub fn main() !void {
    std.debug.print("zquic session-resumption example\n", .{});
    std.debug.print("─────────────────────────────────\n", .{});

    // Simulate a session ticket received from the server after the first
    // handshake.  In a real implementation this is parsed from a TLS
    // NewSessionTicket message inside a QUIC CRYPTO frame.
    const ticket = session.SessionTicket{
        .lifetime_s = 3600, // 1-hour lifetime
        .nonce = [_]u8{0x42} ** 32,
        .nonce_len = 8,
        .ticket = [_]u8{0xab} ** session.max_ticket_len,
        .ticket_len = 64,
        // Resumption secret derived during the first handshake.
        .resumption_secret = [_]u8{0x7f} ** 48,
        .resumption_secret_len = 32,
        .max_early_data_size = 16384, // server allows 0-RTT
        .received_at_ms = 1_700_000_000_000,
    };

    std.debug.print("Ticket lifetime : {}s\n", .{ticket.lifetime_s});
    std.debug.print("0-RTT allowed   : {}\n", .{ticket.earlyDataAllowed()});
    std.debug.print("Max early data  : {} bytes\n", .{ticket.max_early_data_size});

    // ── Store the ticket ────────────────────────────────────────────────────
    var store = session.TicketStore{};
    store.store(ticket);

    // ── Retrieve on next connection ─────────────────────────────────────────
    const now_ms: u64 = 1_700_000_001_000; // 1 second later — still valid
    const retrieved = store.get(now_ms) orelse {
        std.debug.print("No valid ticket found\n", .{});
        return;
    };
    std.debug.print("Retrieved ticket (valid: {})\n", .{retrieved.isValid(now_ms)});

    // ── Derive 0-RTT keys ───────────────────────────────────────────────────
    const early_keys = session.deriveEarlyKeys(retrieved);
    printHex("0-RTT key ", &early_keys.key);
    printHex("0-RTT iv  ", &early_keys.iv);
    printHex("0-RTT hp  ", &early_keys.hp);

    // ── Serialise for persistent storage ───────────────────────────────────
    var wire_buf: [2048]u8 = undefined;
    const wire_len = try ticket.serialise(&wire_buf);
    std.debug.print("Serialised ticket: {} bytes\n", .{wire_len});

    const restored = try session.SessionTicket.deserialise(wire_buf[0..wire_len]);
    std.debug.assert(restored.lifetime_s == ticket.lifetime_s);
    std.debug.print("Restored ticket lifetime: {}s\n", .{restored.lifetime_s});
    std.debug.print("\nSession resumption flow complete.\n", .{});
}
