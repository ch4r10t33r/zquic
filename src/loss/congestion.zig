//! New Reno congestion control (RFC 9002 §7, RFC 5681).
//!
//! States:
//!   Slow Start: cwnd grows by one MSS per ACK (doubles per RTT)
//!   Congestion Avoidance: cwnd grows by MSS²/cwnd per byte ACKed
//!   Recovery: after loss, cwnd = ssthresh = max(cwnd/2, 2*MSS)

const std = @import("std");

/// Maximum segment size (bytes). QUIC uses the full MTU; we default to 1200.
pub const mss: u64 = 1200;
/// Maximum congestion window (bytes).
const max_cwnd: u64 = 64 * 1024 * 1024; // 64 MB

pub const CcState = enum {
    slow_start,
    congestion_avoidance,
    recovery,
};

/// New Reno congestion controller.
pub const NewReno = struct {
    /// Congestion window in bytes.
    cwnd: u64 = 10 * mss,
    /// Slow start threshold.
    ssthresh: u64 = max_cwnd,
    /// Bytes in flight.
    bytes_in_flight: u64 = 0,
    /// State.
    state: CcState = .slow_start,
    /// Number of bytes ACKed since entering congestion avoidance.
    bytes_acked_ca: u64 = 0,
    /// Largest ACKed packet number in the current recovery period.
    end_of_recovery: ?u64 = null,

    pub fn init() NewReno {
        return .{};
    }

    /// Called when packets are acknowledged.
    pub fn onAck(self: *NewReno, bytes_acked: u64) void {
        self.bytes_in_flight -|= bytes_acked;

        if (self.state == .recovery) {
            // Exit recovery once the end-of-recovery packet is acked.
            self.state = .congestion_avoidance;
            self.end_of_recovery = null;
        }

        if (self.state == .slow_start) {
            self.cwnd +|= bytes_acked;
            if (self.cwnd >= self.ssthresh) {
                self.state = .congestion_avoidance;
            }
        } else if (self.state == .congestion_avoidance) {
            // Increase cwnd by MSS²/cwnd for each byte ACKed
            self.bytes_acked_ca += bytes_acked;
            while (self.bytes_acked_ca >= self.cwnd) {
                self.bytes_acked_ca -= self.cwnd;
                self.cwnd = @min(self.cwnd + mss, max_cwnd);
            }
        }
    }

    /// Called on packet loss.
    pub fn onLoss(self: *NewReno, largest_lost_pn: u64) void {
        // Only react to loss once per flight (RFC 9002 §7.3.2)
        if (self.end_of_recovery) |eor| {
            if (largest_lost_pn <= eor) return;
        }

        self.end_of_recovery = largest_lost_pn;
        self.ssthresh = @max(self.cwnd / 2, 2 * mss);
        self.cwnd = self.ssthresh;
        self.bytes_acked_ca = 0;
        self.state = .recovery;
    }

    /// Called when a packet is sent.
    pub fn onPacketSent(self: *NewReno, bytes: u64) void {
        self.bytes_in_flight +|= bytes;
    }

    /// Returns the send credit (bytes allowed to be in flight).
    pub fn sendCredit(self: *const NewReno) u64 {
        return self.cwnd -| self.bytes_in_flight;
    }

    /// True if we may send more data (sender-side congestion check).
    pub fn canSend(self: *const NewReno, packet_size: u64) bool {
        return self.bytes_in_flight + packet_size <= self.cwnd;
    }
};

/// Tagged union wrapping available congestion controllers.
/// All variants expose the same interface so callers use `cc.onAck(...)` etc.
pub const CongestionController = union(enum) {
    new_reno: NewReno,
    cubic: @import("cubic.zig").Cubic,

    pub fn init(comptime tag: std.meta.Tag(CongestionController)) CongestionController {
        return switch (tag) {
            .new_reno => .{ .new_reno = NewReno.init() },
            .cubic => .{ .cubic = @import("cubic.zig").Cubic.init() },
        };
    }

    pub fn onAck(self: *CongestionController, bytes_acked: u64) void {
        switch (self.*) {
            inline else => |*cc| cc.onAck(bytes_acked),
        }
    }

    pub fn onLoss(self: *CongestionController, largest_lost_pn: u64) void {
        switch (self.*) {
            inline else => |*cc| cc.onLoss(largest_lost_pn),
        }
    }

    pub fn onPacketSent(self: *CongestionController, bytes: u64) void {
        switch (self.*) {
            inline else => |*cc| cc.onPacketSent(bytes),
        }
    }

    pub fn sendCredit(self: *const CongestionController) u64 {
        switch (self.*) {
            inline else => |*cc| return cc.sendCredit(),
        }
    }

    pub fn canSend(self: *const CongestionController, packet_size: u64) bool {
        switch (self.*) {
            inline else => |*cc| return cc.canSend(packet_size),
        }
    }

    pub fn getBytesInFlight(self: *const CongestionController) u64 {
        switch (self.*) {
            inline else => |cc| return cc.bytes_in_flight,
        }
    }

    pub fn setBytesInFlight(self: *CongestionController, val: u64) void {
        switch (self.*) {
            inline else => |*cc| cc.bytes_in_flight = val,
        }
    }

    pub fn subBytesInFlight(self: *CongestionController, val: u64) void {
        switch (self.*) {
            inline else => |*cc| cc.bytes_in_flight -|= val,
        }
    }
};

test "new_reno: slow start growth" {
    const testing = std.testing;
    var cc = NewReno.init();
    try testing.expectEqual(CcState.slow_start, cc.state);
    const initial_cwnd = cc.cwnd;

    cc.onPacketSent(mss);
    cc.onAck(mss);
    // In slow start, cwnd should grow by bytes_acked
    try testing.expectEqual(initial_cwnd + mss, cc.cwnd);
}

test "new_reno: loss triggers recovery" {
    const testing = std.testing;
    var cc = NewReno.init();
    cc.cwnd = 10 * mss; // artificial cwnd
    cc.bytes_in_flight = 5 * mss;

    cc.onLoss(5);
    try testing.expectEqual(CcState.recovery, cc.state);
    try testing.expectEqual(@as(u64, 5 * mss), cc.ssthresh);
    try testing.expectEqual(@as(u64, 5 * mss), cc.cwnd);
}

test "new_reno: congestion avoidance" {
    const testing = std.testing;
    var cc = NewReno.init();
    cc.ssthresh = 10 * mss;
    cc.cwnd = 10 * mss;
    cc.state = .congestion_avoidance;

    const initial_cwnd = cc.cwnd;
    // ACK a full cwnd worth of bytes → cwnd increases by 1 MSS
    cc.onAck(cc.cwnd);
    try testing.expectEqual(initial_cwnd + mss, cc.cwnd);
}

test "new_reno: can_send check" {
    const testing = std.testing;
    var cc = NewReno.init();
    cc.cwnd = 2 * mss;
    cc.bytes_in_flight = 2 * mss;

    try testing.expect(!cc.canSend(1));
    cc.onAck(mss);
    try testing.expect(cc.canSend(mss));
}

test "congestion_controller: tagged union dispatches correctly" {
    const testing = std.testing;

    // NewReno variant
    var nr = CongestionController.init(.new_reno);
    nr.onPacketSent(mss);
    try testing.expectEqual(@as(u64, mss), nr.getBytesInFlight());
    try testing.expect(nr.canSend(mss));
    nr.onAck(mss);
    try testing.expectEqual(@as(u64, 0), nr.getBytesInFlight());

    // CUBIC variant
    var cubic = CongestionController.init(.cubic);
    cubic.onPacketSent(mss);
    try testing.expectEqual(@as(u64, mss), cubic.getBytesInFlight());
    try testing.expect(cubic.canSend(mss));
    cubic.onLoss(1);
    // After loss, CUBIC sets cwnd = cwnd × β (0.7).
    try testing.expect(cubic.canSend(mss));
}
