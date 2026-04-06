//! QUIC flow control (RFC 9000 §4).
//!
//! QUIC provides two levels of flow control:
//!   - Connection-level: limits the total bytes across all streams.
//!   - Stream-level: limits bytes on a single stream.
//!
//! Both use credit-based windows: the receiver advertises a maximum offset
//! up to which the sender may send. When the window is consumed, the receiver
//! issues MAX_DATA / MAX_STREAM_DATA frames to grant more credit.

const std = @import("std");

/// Connection-level flow control.
pub const ConnectionFlowControl = struct {
    /// Maximum offset the local side may receive (advertised by us).
    local_max_data: u64,
    /// Maximum offset the remote side may send (advertised by peer).
    remote_max_data: u64,
    /// Total bytes received across all streams.
    bytes_received: u64 = 0,
    /// Total bytes sent across all streams.
    bytes_sent: u64 = 0,

    pub fn init(local_max: u64, remote_max: u64) ConnectionFlowControl {
        return .{ .local_max_data = local_max, .remote_max_data = remote_max };
    }

    /// Returns the number of bytes the sender may still send.
    pub fn sendCredit(self: *const ConnectionFlowControl) u64 {
        return self.remote_max_data -| self.bytes_sent;
    }

    /// Called when data is sent; returns false if it would exceed the window.
    pub fn onSend(self: *ConnectionFlowControl, length: u64) bool {
        if (self.bytes_sent + length > self.remote_max_data) return false;
        self.bytes_sent += length;
        return true;
    }

    /// Called when data is received.
    pub fn onReceive(self: *ConnectionFlowControl, offset_end: u64) bool {
        if (offset_end > self.local_max_data) return false;
        if (offset_end > self.bytes_received) self.bytes_received = offset_end;
        return true;
    }

    /// Update the remote max_data (from a MAX_DATA frame).
    pub fn updateRemoteMax(self: *ConnectionFlowControl, new_max: u64) void {
        if (new_max > self.remote_max_data) self.remote_max_data = new_max;
    }

    /// True if we should send a MAX_DATA frame (consumed > 50% of window).
    pub fn shouldAdvertise(self: *const ConnectionFlowControl) bool {
        return self.bytes_received * 2 >= self.local_max_data;
    }

    /// Returns the new MAX_DATA value to advertise.
    pub fn nextAdvertise(self: *const ConnectionFlowControl) u64 {
        return self.bytes_received + self.local_max_data;
    }
};

/// Stream-level flow control.
pub const StreamFlowControl = struct {
    /// Max offset the sender may use (advertised by receiver).
    send_max: u64,
    /// Max offset the receiver will accept (we advertised this).
    recv_max: u64,
    /// Highest offset received so far.
    highest_recv: u64 = 0,
    /// Highest offset sent so far.
    highest_sent: u64 = 0,
    /// True if the stream's final size is known (FIN received).
    final_size: ?u64 = null,

    pub fn init(send_max: u64, recv_max: u64) StreamFlowControl {
        return .{ .send_max = send_max, .recv_max = recv_max };
    }

    /// Returns the number of bytes the sender may still send on this stream.
    pub fn sendCredit(self: *const StreamFlowControl) u64 {
        return self.send_max -| self.highest_sent;
    }

    /// Called when data is sent. Returns false if it would exceed the window.
    pub fn onSend(self: *StreamFlowControl, offset: u64, length: u64) bool {
        const end = offset + length;
        if (end > self.send_max) return false;
        if (end > self.highest_sent) self.highest_sent = end;
        return true;
    }

    /// Called when data is received. Returns false on flow control violation.
    pub fn onReceive(self: *StreamFlowControl, offset: u64, length: u64) bool {
        const end = offset + length;
        if (end > self.recv_max) return false;
        if (end > self.highest_recv) self.highest_recv = end;
        return true;
    }

    /// Update the send window (from a MAX_STREAM_DATA frame).
    pub fn updateSendMax(self: *StreamFlowControl, new_max: u64) void {
        if (new_max > self.send_max) self.send_max = new_max;
    }
};

test "connection flow control: credit tracking" {
    const testing = std.testing;
    var fc = ConnectionFlowControl.init(1_000_000, 500_000);

    try testing.expectEqual(@as(u64, 500_000), fc.sendCredit());

    try testing.expect(fc.onSend(200_000));
    try testing.expectEqual(@as(u64, 300_000), fc.sendCredit());

    try testing.expect(!fc.onSend(400_000)); // exceeds window
    try testing.expectEqual(@as(u64, 300_000), fc.sendCredit());
}

test "connection flow control: receive and max update" {
    const testing = std.testing;
    var fc = ConnectionFlowControl.init(1_000_000, 500_000);

    try testing.expect(fc.onReceive(600_000));
    try testing.expect(!fc.onReceive(1_500_000)); // exceeds local max

    fc.updateRemoteMax(800_000);
    try testing.expectEqual(@as(u64, 800_000), fc.remote_max_data);
}

test "stream flow control: basic credit" {
    const testing = std.testing;
    var sfc = StreamFlowControl.init(1_000, 2_000);

    try testing.expect(sfc.onSend(0, 500));
    try testing.expect(sfc.onSend(500, 500));
    try testing.expect(!sfc.onSend(1000, 1)); // would exceed send_max

    sfc.updateSendMax(2_000);
    try testing.expect(sfc.onSend(1000, 500));
}
