//! Core QUIC types shared across the implementation.

const std = @import("std");

// QUIC version identifiers (RFC 9000 §15)
pub const Version = enum(u32) {
    quic_v1 = 0x00000001,
    quic_v2 = 0x6b3343cf,
    _,

    pub fn isReserved(v: u32) bool {
        // Reserved version numbers have the pattern 0x?a?a?a?a (RFC 9000 §17.2.1)
        return (v & 0x0f0f0f0f) == 0x0a0a0a0a;
    }
};

// Connection IDs are 0–20 bytes in QUIC v1 (RFC 9000 §17.2)
pub const max_cid_len = 20;

pub const ConnectionId = struct {
    bytes: [max_cid_len]u8 = undefined,
    len: u5 = 0,

    pub fn fromSlice(s: []const u8) error{TooLong}!ConnectionId {
        if (s.len > max_cid_len) return error.TooLong;
        var cid = ConnectionId{ .len = @intCast(s.len) };
        @memcpy(cid.bytes[0..s.len], s);
        return cid;
    }

    pub fn slice(self: *const ConnectionId) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn eql(a: ConnectionId, b: ConnectionId) bool {
        if (a.len != b.len) return false;
        return std.mem.eql(u8, a.bytes[0..a.len], b.bytes[0..b.len]);
    }

    pub fn random(rng: std.Random, len: u5) ConnectionId {
        var cid = ConnectionId{ .len = len };
        rng.bytes(cid.bytes[0..len]);
        return cid;
    }

    pub fn format(
        self: ConnectionId,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("{}", .{std.fmt.fmtSliceHexLower(self.slice())});
    }
};

// Packet number spaces (RFC 9000 §12.3)
pub const PacketNumberSpace = enum {
    initial,
    handshake,
    application,
};

// Packet numbers are 62-bit unsigned integers (RFC 9000 §12.3)
pub const PacketNumber = u62;

// Encryption levels map 1-to-1 to packet number spaces
pub const EncryptionLevel = enum {
    initial,
    zero_rtt,
    handshake,
    one_rtt,

    pub fn pnSpace(self: EncryptionLevel) PacketNumberSpace {
        return switch (self) {
            .initial => .initial,
            .zero_rtt, .one_rtt => .application,
            .handshake => .handshake,
        };
    }
};

// QUIC transport error codes (RFC 9000 §20.1)
pub const TransportError = enum(u62) {
    no_error = 0x00,
    internal_error = 0x01,
    connection_refused = 0x02,
    flow_control_error = 0x03,
    stream_limit_error = 0x04,
    stream_state_error = 0x05,
    final_size_error = 0x06,
    frame_encoding_error = 0x07,
    transport_parameter_error = 0x08,
    connection_id_limit_error = 0x09,
    protocol_violation = 0x0a,
    invalid_token = 0x0b,
    application_error = 0x0c,
    crypto_buffer_exceeded = 0x0d,
    key_update_error = 0x0e,
    aead_limit_reached = 0x0f,
    no_viable_path = 0x10,
    _,
};

// Stream identifier (RFC 9000 §2.1)
pub const StreamId = struct {
    id: u62,

    pub const Initiator = enum { client, server };
    pub const Type = enum { bidirectional, unidirectional };

    pub fn init(id: u62) StreamId {
        return .{ .id = id };
    }

    pub fn initiator(self: StreamId) Initiator {
        return if (self.id & 1 == 0) .client else .server;
    }

    pub fn streamType(self: StreamId) Type {
        return if (self.id & 2 == 0) .bidirectional else .unidirectional;
    }

    pub fn nextClientBidirectional(n: u62) StreamId {
        return .{ .id = n * 4 };
    }

    pub fn nextClientUnidirectional(n: u62) StreamId {
        return .{ .id = n * 4 + 2 };
    }
};

// Maximum UDP datagram size we accept
pub const max_udp_payload_size: usize = 65527;

// QUIC v1 minimum MTU (RFC 9000 §14.1)
pub const min_initial_mtu: usize = 1200;

test "ConnectionId: basic operations" {
    const testing = std.testing;

    const cid = try ConnectionId.fromSlice(&[_]u8{ 0x01, 0x02, 0x03 });
    try testing.expectEqual(@as(u5, 3), cid.len);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, cid.slice());

    var cid2 = try ConnectionId.fromSlice(&[_]u8{ 0x01, 0x02, 0x03 });
    try testing.expect(ConnectionId.eql(cid, cid2));
    cid2.bytes[0] = 0xff;
    try testing.expect(!ConnectionId.eql(cid, cid2));

    try testing.expectError(error.TooLong, ConnectionId.fromSlice(&[_]u8{0} ** 21));
}

test "StreamId: type and initiator" {
    const testing = std.testing;

    // Stream 0: client-initiated bidirectional
    const s0 = StreamId.init(0);
    try testing.expectEqual(StreamId.Initiator.client, s0.initiator());
    try testing.expectEqual(StreamId.Type.bidirectional, s0.streamType());

    // Stream 1: server-initiated bidirectional
    const s1 = StreamId.init(1);
    try testing.expectEqual(StreamId.Initiator.server, s1.initiator());

    // Stream 2: client-initiated unidirectional
    const s2 = StreamId.init(2);
    try testing.expectEqual(StreamId.Type.unidirectional, s2.streamType());
}

test "Version: reserved" {
    try std.testing.expect(Version.isReserved(0x0a0a0a0a));
    try std.testing.expect(Version.isReserved(0x1a2a3a4a));
    try std.testing.expect(!Version.isReserved(0x00000001));
}
