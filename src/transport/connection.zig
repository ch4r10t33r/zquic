//! QUIC connection state machine (RFC 9000).
//!
//! Manages the lifecycle of a single QUIC connection from Initial through
//! Handshake to Connected (1-RTT data transfer), and finally to Draining /
//! Closed states.
//!
//! State transitions:
//!
//!   Initial → Handshaking → Connected → DataTransfer → Draining → Closed

const std = @import("std");
const types = @import("../types.zig");
const varint = @import("../varint.zig");
const frames = @import("../frames/frame.zig");
const crypto_keys = @import("../crypto/keys.zig");
const quic_tls = @import("../crypto/quic_tls.zig");

pub const ConnectionId = types.ConnectionId;
pub const TransportError = types.TransportError;

/// Connection state per RFC 9000 §4
pub const State = enum {
    /// Sending/receiving Initial packets; TLS handshake in progress.
    initial,
    /// Initial complete; sending/receiving Handshake packets.
    handshaking,
    /// Handshake complete; sending/receiving 1-RTT packets.
    connected,
    /// CONNECTION_CLOSE sent or received; waiting for draining period.
    draining,
    /// Connection fully terminated.
    closed,
};

/// Role of this endpoint.
pub const Role = enum { client, server };

/// Per-packet-number-space send state.
pub const PnSpaceState = struct {
    next_pn: u64 = 0,
    largest_acked: ?u64 = null,

    pub fn allocatePn(self: *PnSpaceState) u64 {
        const pn = self.next_pn;
        self.next_pn += 1;
        return pn;
    }
};

/// Sent-packet metadata for loss detection.
pub const SentPacket = struct {
    pn: u64,
    send_time_ms: u64,
    size: usize,
    ack_eliciting: bool,
    in_flight: bool,
};

/// Connection-level statistics.
pub const Stats = struct {
    packets_sent: u64 = 0,
    packets_recv: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_recv: u64 = 0,
    handshake_rtt_ms: ?u64 = null,
};

/// ACK manager: tracks received packets that need to be acknowledged.
pub const AckManager = struct {
    const max_ranges = 32;

    /// Largest packet number seen so far.
    largest_recv: u64 = 0,
    /// Number of filled ranges.
    range_count: usize = 0,
    /// Received packet ranges (not yet sent in ACK frame).
    ranges: [max_ranges][2]u64 = undefined,
    /// True when an ACK needs to be sent.
    needs_ack: bool = false,

    /// Record a received packet number.
    pub fn observe(self: *AckManager, pn: u64) void {
        if (pn > self.largest_recv) self.largest_recv = pn;
        self.needs_ack = true;
        // Simple tracking: merge into the last range if contiguous.
        if (self.range_count == 0) {
            self.ranges[0] = .{ pn, pn };
            self.range_count = 1;
            return;
        }
        const last = &self.ranges[self.range_count - 1];
        if (pn == last[0] - 1) {
            last[0] = pn;
        } else if (pn == last[1] + 1) {
            last[1] = pn;
        } else if (self.range_count < max_ranges) {
            self.ranges[self.range_count] = .{ pn, pn };
            self.range_count += 1;
        }
    }

    /// Build an ACK frame and clear the pending state.
    pub fn buildAck(self: *AckManager) @import("../frames/ack.zig").AckFrame {
        const ack_frame = @import("../frames/ack.zig");
        var f = ack_frame.AckFrame{
            .largest_acknowledged = self.largest_recv,
            .ack_delay = 0,
            .ranges = undefined,
            .range_count = 0,
            .ecn = null,
        };
        // Build ranges (largest first)
        var i = self.range_count;
        while (i > 0 and f.range_count < ack_frame.max_ack_ranges) {
            i -= 1;
            f.ranges[f.range_count] = .{
                .smallest = self.ranges[i][0],
                .largest = self.ranges[i][1],
            };
            f.range_count += 1;
        }
        self.needs_ack = false;
        return f;
    }
};

/// A QUIC connection.
pub const Connection = struct {
    role: Role,
    state: State = .initial,

    /// Local and remote connection IDs.
    local_cid: ConnectionId,
    remote_cid: ConnectionId,

    /// Per-packet-number-space state.
    initial_pn: PnSpaceState = .{},
    handshake_pn: PnSpaceState = .{},
    app_pn: PnSpaceState = .{},

    /// ACK managers per packet number space.
    initial_ack: AckManager = .{},
    handshake_ack: AckManager = .{},
    app_ack: AckManager = .{},

    /// Crypto streams per encryption level.
    initial_crypto: quic_tls.CryptoStream = .{},
    handshake_crypto: quic_tls.CryptoStream = .{},
    app_crypto: quic_tls.CryptoStream = .{},

    /// Initial packet crypto keys (derived from DCID).
    initial_keys: ?crypto_keys.InitialSecrets = null,

    /// Connection-level flow control limit (bytes we can send).
    max_data: u64 = 0,
    /// Bytes sent so far (for flow control).
    data_sent: u64 = 0,

    /// Close error, if any.
    close_error: ?TransportError = null,

    /// Statistics.
    stats: Stats = .{},

    pub fn init(role: Role, local_cid: ConnectionId, remote_cid: ConnectionId) Connection {
        return .{
            .role = role,
            .local_cid = local_cid,
            .remote_cid = remote_cid,
        };
    }

    /// Derive Initial packet keys using the destination CID.
    pub fn deriveInitialKeys(self: *Connection, dcid: ConnectionId) void {
        self.initial_keys = crypto_keys.InitialSecrets.derive(dcid.slice());
    }

    /// Returns true once the TLS handshake is complete (state = connected).
    pub fn isConnected(self: *const Connection) bool {
        return self.state == .connected;
    }

    /// Returns the appropriate packet number space for the current state.
    pub fn currentPnSpace(self: *Connection) *PnSpaceState {
        return switch (self.state) {
            .initial => &self.initial_pn,
            .handshaking => &self.handshake_pn,
            .connected, .draining, .closed => &self.app_pn,
        };
    }

    /// Transition to a new state (validates transitions).
    pub fn transition(self: *Connection, new_state: State) error{InvalidTransition}!void {
        const valid = switch (self.state) {
            .initial => new_state == .handshaking or new_state == .draining or new_state == .closed,
            .handshaking => new_state == .connected or new_state == .draining or new_state == .closed,
            .connected => new_state == .draining or new_state == .closed,
            .draining => new_state == .closed,
            .closed => false,
        };
        if (!valid) return error.InvalidTransition;
        self.state = new_state;
    }

    /// Close the connection with a transport error.
    pub fn closeWithError(self: *Connection, err: TransportError) void {
        self.close_error = err;
        self.state = .draining;
    }
};

test "connection: state machine transitions" {
    const testing = std.testing;

    const dcid = try ConnectionId.fromSlice(&[_]u8{ 0x01, 0x02, 0x03 });
    const scid = try ConnectionId.fromSlice(&[_]u8{ 0x04, 0x05 });
    var conn = Connection.init(.client, scid, dcid);

    try testing.expectEqual(State.initial, conn.state);

    try conn.transition(.handshaking);
    try testing.expectEqual(State.handshaking, conn.state);

    try conn.transition(.connected);
    try testing.expectEqual(State.connected, conn.state);

    try conn.transition(.draining);
    try testing.expectEqual(State.draining, conn.state);

    try conn.transition(.closed);
    try testing.expectEqual(State.closed, conn.state);
}

test "connection: invalid transition" {
    const dcid = try ConnectionId.fromSlice(&[_]u8{0x01});
    const scid = try ConnectionId.fromSlice(&[_]u8{0x02});
    var conn = Connection.init(.server, scid, dcid);

    try std.testing.expectError(error.InvalidTransition, conn.transition(.connected));
}

test "connection: initial key derivation" {
    const testing = std.testing;

    const dcid = try ConnectionId.fromSlice("\x83\x94\xc8\xf0\x3e\x51\x57\x08");
    const scid = try ConnectionId.fromSlice(&[_]u8{0x00});
    var conn = Connection.init(.client, scid, dcid);
    conn.deriveInitialKeys(dcid);

    try testing.expect(conn.initial_keys != null);
    const expected_key = "\x1f\x36\x96\x13\xdd\x76\xd5\x46\x77\x30\xef\xcb\xe3\xb1\xa2\x2d";
    try testing.expectEqualSlices(u8, expected_key, &conn.initial_keys.?.client.key);
}

test "ack_manager: single packet observation" {
    const testing = std.testing;
    var mgr = AckManager{};

    mgr.observe(5);
    mgr.observe(6);
    mgr.observe(7);
    try testing.expect(mgr.needs_ack);
    try testing.expectEqual(@as(u64, 7), mgr.largest_recv);

    const ack = mgr.buildAck();
    try testing.expect(ack.acknowledges(6));
    try testing.expect(!mgr.needs_ack);
}
