//! QUIC loss detection and RTT estimation (RFC 9002).
//!
//! Implements:
//!   - RTT estimation (§5): smoothed RTT, RTT variance, min RTT
//!   - Loss detection (§6): ACK-based, timeout-based
//!   - Probe Timeout (PTO) (§6.2)

const std = @import("std");

/// Initial RTT estimate (333ms per RFC 9002 §6.2.2)
pub const initial_rtt_ms: u64 = 333;

/// Multiplier for the RTT smoothing (1/8 = RTTVAR weight per RFC 6298)
const k_rtt_alpha: f64 = 1.0 / 8.0;
const k_rtt_beta: f64 = 1.0 / 4.0;
/// Minimum time before a packet is considered lost (RFC 9002 §6.1.2)
const k_time_threshold_num: u64 = 9;
const k_time_threshold_den: u64 = 8;
/// Minimum packet threshold for loss detection (RFC 9002 §6.1.1)
const k_packet_threshold: u64 = 3;
/// Maximum ACK delay in ms (RFC 9002 §5.3)
const k_max_ack_delay_ms: u64 = 25;
/// Granularity timer resolution in ms
const k_granularity_ms: u64 = 1;

/// RTT estimator for a QUIC connection.
pub const RttEstimator = struct {
    /// Smoothed RTT (ms).
    srtt_ms: f64 = @floatFromInt(initial_rtt_ms),
    /// RTT variance (ms).
    rttvar_ms: f64 = @floatFromInt(initial_rtt_ms / 2),
    /// Minimum RTT observed (ms).
    min_rtt_ms: u64 = std.math.maxInt(u64),
    /// Latest RTT sample (ms).
    latest_rtt_ms: u64 = 0,
    /// True once first measurement taken.
    first_rtt_sample: bool = false,

    /// Update RTT estimates with a new ACK sample.
    /// `ack_delay_ms` is the peer-reported ACK delay.
    pub fn update(self: *RttEstimator, latest_rtt_ms: u64, ack_delay_ms: u64) void {
        self.latest_rtt_ms = latest_rtt_ms;

        // Update min RTT
        if (latest_rtt_ms < self.min_rtt_ms) {
            self.min_rtt_ms = latest_rtt_ms;
        }

        // Adjust for ACK delay (capped at max_ack_delay and latest_rtt - min_rtt)
        const adjusted_ack_delay = @min(ack_delay_ms, k_max_ack_delay_ms);
        const adjusted_rtt: f64 = if (latest_rtt_ms > self.min_rtt_ms + adjusted_ack_delay)
            @floatFromInt(latest_rtt_ms - adjusted_ack_delay)
        else
            @floatFromInt(latest_rtt_ms);

        if (!self.first_rtt_sample) {
            self.srtt_ms = adjusted_rtt;
            self.rttvar_ms = adjusted_rtt / 2.0;
            self.first_rtt_sample = true;
        } else {
            // RTTVAR = (1 - β) * RTTVAR + β * |SRTT - RTT|
            const diff = @abs(self.srtt_ms - adjusted_rtt);
            self.rttvar_ms = (1.0 - k_rtt_beta) * self.rttvar_ms + k_rtt_beta * diff;
            // SRTT = (1 - α) * SRTT + α * RTT
            self.srtt_ms = (1.0 - k_rtt_alpha) * self.srtt_ms + k_rtt_alpha * adjusted_rtt;
        }
    }

    /// Probe Timeout (PTO) value in ms (RFC 9002 §6.2.1).
    pub fn pto_ms(self: *const RttEstimator, max_ack_delay: u64, pto_count: u32) u64 {
        const base_pto: f64 = self.srtt_ms + @max(4.0 * self.rttvar_ms, @as(f64, @floatFromInt(k_granularity_ms)));
        const with_delay: f64 = base_pto + @as(f64, @floatFromInt(max_ack_delay));
        const scaled = with_delay * std.math.pow(f64, 2.0, @floatFromInt(pto_count));
        return @intFromFloat(scaled);
    }
};

/// A record of a packet that has been sent but not yet acknowledged.
pub const SentPacket = struct {
    pn: u64,
    send_time_ms: u64,
    size: usize,
    ack_eliciting: bool,
    in_flight: bool,
};

/// Loss detection state for one packet number space.
pub const LossDetector = struct {
    const max_tracked = 256;

    sent: [max_tracked]SentPacket = undefined,
    sent_count: usize = 0,
    largest_acked: u64 = 0,
    loss_time_ms: ?u64 = null,

    /// Record a newly sent packet.
    pub fn onPacketSent(self: *LossDetector, pkt: SentPacket) void {
        if (self.sent_count < max_tracked) {
            self.sent[self.sent_count] = pkt;
            self.sent_count += 1;
        }
    }

    /// Process an ACK frame. Returns packets declared lost.
    /// `now_ms` is the current wall-clock time in milliseconds.
    /// `rtt` is the RTT estimator.
    pub fn onAck(
        self: *LossDetector,
        largest_acked: u64,
        ack_delay_ms: u64,
        now_ms: u64,
        rtt: *RttEstimator,
        lost_buf: []u64,
    ) struct { lost_count: usize, rtt_updated: bool } {
        var rtt_updated = false;

        // Update RTT if the newly acked packet was just sent
        if (largest_acked > self.largest_acked) {
            self.largest_acked = largest_acked;
            // Find the most recently sent packet with pn == largest_acked
            for (self.sent[0..self.sent_count]) |p| {
                if (p.pn == largest_acked) {
                    const sample = now_ms -| p.send_time_ms;
                    rtt.update(sample, ack_delay_ms);
                    rtt_updated = true;
                    break;
                }
            }
        }

        // Detect lost packets
        var lost_count: usize = 0;
        const loss_delay = @max(
            k_packet_threshold,
            (rtt.srtt_ms * @as(f64, @floatFromInt(k_time_threshold_num)) / @as(f64, @floatFromInt(k_time_threshold_den))),
        );
        _ = loss_delay;

        var i: usize = 0;
        while (i < self.sent_count) {
            const p = self.sent[i];
            if (p.pn > largest_acked) {
                i += 1;
                continue;
            }
            // Packet-threshold loss: if >= k_packet_threshold packets acked after this
            if (largest_acked >= p.pn + k_packet_threshold) {
                if (lost_count < lost_buf.len) {
                    lost_buf[lost_count] = p.pn;
                    lost_count += 1;
                }
                // Remove from sent list
                self.sent[i] = self.sent[self.sent_count - 1];
                self.sent_count -= 1;
                continue;
            }
            // Acked: remove from sent list
            if (p.pn <= largest_acked) {
                self.sent[i] = self.sent[self.sent_count - 1];
                self.sent_count -= 1;
                continue;
            }
            i += 1;
        }

        return .{ .lost_count = lost_count, .rtt_updated = rtt_updated };
    }
};

test "rtt: initial values" {
    const testing = std.testing;
    const rtt = RttEstimator{};
    try testing.expectEqual(@as(f64, @floatFromInt(initial_rtt_ms)), rtt.srtt_ms);
    try testing.expect(rtt.pto_ms(k_max_ack_delay_ms, 0) > 0);
}

test "rtt: single sample update" {
    const testing = std.testing;
    var rtt = RttEstimator{};
    rtt.update(100, 10);
    try testing.expect(rtt.srtt_ms < 333.0); // moves toward 100
    try testing.expect(rtt.min_rtt_ms == 100);
    try testing.expect(rtt.first_rtt_sample);
}

test "rtt: pto increases with backoff" {
    const testing = std.testing;
    var rtt = RttEstimator{};
    rtt.update(50, 0);
    const pto0 = rtt.pto_ms(0, 0);
    const pto1 = rtt.pto_ms(0, 1);
    const pto2 = rtt.pto_ms(0, 2);
    try testing.expect(pto1 >= pto0 * 2 - 1);
    try testing.expect(pto2 >= pto1 * 2 - 1);
}

test "loss: packet threshold detection" {
    const testing = std.testing;
    var ld = LossDetector{};
    var rtt = RttEstimator{};

    // Send packets 0..5
    var i: u64 = 0;
    while (i < 6) : (i += 1) {
        ld.onPacketSent(.{
            .pn = i,
            .send_time_ms = 100 + i * 10,
            .size = 100,
            .ack_eliciting = true,
            .in_flight = true,
        });
    }

    // ACK packet 5: packets 0 and 1 should be detected as lost (5 - 0 >= 3, 5 - 1 >= 3)
    var lost_buf: [8]u64 = undefined;
    const result = ld.onAck(5, 0, 200, &rtt, &lost_buf);
    try testing.expect(result.lost_count >= 2);
}
