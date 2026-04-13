//! QUIC stream multiplexing (RFC 9000 §2, §3).
//!
//! Stream IDs encode the initiator and directionality:
//!   Bit 0: 0=client-initiated, 1=server-initiated
//!   Bit 1: 0=bidirectional, 1=unidirectional
//!
//! Each stream has a state machine:
//!   Idle → Open → Half-Closed (local) → Closed
//!             └─→ Half-Closed (remote) ┘

const std = @import("std");
const types = @import("../types.zig");
const flow_control = @import("flow_control.zig");
const stream_frame = @import("../frames/stream.zig");
const frames = @import("../frames/transport.zig");

pub const StreamId = types.StreamId;
pub const FlowControl = flow_control.StreamFlowControl;

/// Stream state (RFC 9000 §3)
pub const StreamState = enum {
    idle,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
    reset_sent,
    reset_received,
};

/// A single QUIC stream.
pub const Stream = struct {
    id: StreamId,
    state: StreamState = .idle,
    fc: FlowControl,
    /// Receive buffer (in-order bytes ready for application consumption).
    recv_buf: [8192]u8 = undefined,
    recv_buf_start: usize = 0,
    recv_buf_end: usize = 0,
    /// Highest contiguous offset received.
    recv_offset: u64 = 0,
    /// Offset at which we've consumed (app has read).
    read_offset: u64 = 0,
    /// Send offset (next byte to send).
    send_offset: u64 = 0,
    /// True if the local side sent FIN.
    fin_sent: bool = false,
    /// True if the remote side sent FIN.
    fin_received: bool = false,
    /// Final size (if fin_received).
    fin_size: u64 = 0,

    pub fn init(id: StreamId, send_max: u64, recv_max: u64) Stream {
        return .{
            .id = id,
            .fc = FlowControl.init(send_max, recv_max),
        };
    }

    /// Write `data` into the receive buffer. Returns false on flow control
    /// violation or out-of-order data that doesn't fit in the buffer.
    pub fn onRecvData(self: *Stream, offset: u64, data: []const u8, fin: bool) bool {
        if (!self.fc.onReceive(offset, data.len)) return false;

        // Accept only in-order data for simplicity.
        if (offset == self.recv_offset) {
            const avail = self.recv_buf.len - self.recv_buf_end;
            if (data.len > avail) return false; // buffer full
            @memcpy(self.recv_buf[self.recv_buf_end .. self.recv_buf_end + data.len], data);
            self.recv_buf_end += data.len;
            self.recv_offset += data.len;
        }

        if (fin) {
            const new_fin_size = offset + data.len;
            // RFC 9000 §3.5 / §19.4: final size must match across STREAM and RESET_STREAM.
            if (self.fin_received and new_fin_size != self.fin_size) return false;
            self.fin_received = true;
            self.fin_size = new_fin_size;
            if (self.state == .half_closed_local) {
                self.state = .closed;
            } else {
                self.state = .half_closed_remote;
            }
        }
        return true;
    }

    /// Read up to `out.len` bytes from the receive buffer into `out`.
    pub fn read(self: *Stream, out: []u8) usize {
        const available = self.recv_buf_end - self.recv_buf_start;
        const n = @min(available, out.len);
        @memcpy(out[0..n], self.recv_buf[self.recv_buf_start .. self.recv_buf_start + n]);
        self.recv_buf_start += n;
        self.read_offset += n;
        if (self.recv_buf_start == self.recv_buf_end) {
            self.recv_buf_start = 0;
            self.recv_buf_end = 0;
        }
        return n;
    }

    /// Mark local side as finished (FIN will be sent in next STREAM frame).
    pub fn closeLocal(self: *Stream) void {
        if (self.state == .closed or self.state == .reset_sent) return;
        self.fin_sent = true;
        if (self.state == .half_closed_remote) {
            self.state = .closed;
        } else {
            self.state = .half_closed_local;
        }
    }
};

/// Manages all streams for a connection.
pub const StreamManager = struct {
    const max_streams = 64;

    role: types.StreamId.Initiator,
    streams: [max_streams]?Stream = [_]?Stream{null} ** max_streams,
    stream_count: usize = 0,

    /// Limits for stream creation.
    max_bidi_streams: u64 = 100,
    max_uni_streams: u64 = 100,

    /// Next stream IDs to create.
    next_bidi_id: u62 = 0,
    next_uni_id: u62 = 0,

    pub fn init(role: types.StreamId.Initiator) StreamManager {
        return .{ .role = role };
    }

    /// Open a new bidirectional stream. Returns the stream or null if at limit.
    pub fn openBidi(self: *StreamManager) ?*Stream {
        const n = self.next_bidi_id;
        if (n >= self.max_bidi_streams) return null;
        const sid = switch (self.role) {
            .client => StreamId.nextClientBidirectional(n),
            .server => StreamId{ .id = n * 4 + 1 },
        };
        self.next_bidi_id += 1;
        return self.allocStream(sid);
    }

    /// Open a new unidirectional stream.
    pub fn openUni(self: *StreamManager) ?*Stream {
        const n = self.next_uni_id;
        if (n >= self.max_uni_streams) return null;
        const sid = switch (self.role) {
            .client => StreamId.nextClientUnidirectional(n),
            .server => StreamId{ .id = n * 4 + 3 },
        };
        self.next_uni_id += 1;
        return self.allocStream(sid);
    }

    fn allocStream(self: *StreamManager, sid: StreamId) ?*Stream {
        if (self.stream_count >= max_streams) return null;
        for (&self.streams) |*slot| {
            if (slot.* == null) {
                slot.* = Stream.init(sid, 256_000, 256_000);
                slot.*.?.state = .open;
                self.stream_count += 1;
                return &(slot.*.?);
            }
        }
        return null;
    }

    /// Find a stream by ID.
    pub fn findStream(self: *StreamManager, sid: StreamId) ?*Stream {
        for (&self.streams) |*slot| {
            if (slot.*) |*s| {
                if (s.id.id == sid.id) return s;
            }
        }
        return null;
    }

    /// Process an incoming STREAM frame.
    pub fn onStreamFrame(self: *StreamManager, f: stream_frame.StreamFrame) bool {
        const sid = StreamId.init(@intCast(f.stream_id));
        if (self.findStream(sid)) |s| {
            return s.onRecvData(f.offset, f.data, f.fin);
        }
        // Auto-create stream for peer-initiated streams
        if (self.allocStream(sid)) |s| {
            return s.onRecvData(f.offset, f.data, f.fin);
        }
        return false;
    }
};

test "stream: basic read/write" {
    const testing = std.testing;
    const sid = StreamId.init(0);
    var s = Stream.init(sid, 100_000, 100_000);
    s.state = .open;

    try testing.expect(s.onRecvData(0, "hello", false));
    try testing.expect(s.onRecvData(5, " world", true));

    var out: [32]u8 = undefined;
    const n = s.read(&out);
    try testing.expectEqualSlices(u8, "hello world", out[0..n]);
    try testing.expect(s.fin_received);
}

test "stream_manager: open and find streams" {
    const testing = std.testing;
    var mgr = StreamManager.init(.client);

    const s1 = mgr.openBidi();
    try testing.expect(s1 != null);
    try testing.expectEqual(@as(u62, 0), s1.?.id.id);

    const s2 = mgr.openBidi();
    try testing.expect(s2 != null);
    try testing.expectEqual(@as(u62, 4), s2.?.id.id);

    const found = mgr.findStream(StreamId.init(0));
    try testing.expect(found != null);
}

test "stream_manager: process stream frame" {
    const testing = std.testing;
    var mgr = StreamManager.init(.server);

    const f = stream_frame.StreamFrame{
        .stream_id = 0, // client-initiated bidi
        .offset = 0,
        .data = "ping",
        .fin = false,
        .has_length = true,
    };
    try testing.expect(mgr.onStreamFrame(f));

    const s = mgr.findStream(StreamId.init(0));
    try testing.expect(s != null);
    var buf: [8]u8 = undefined;
    const n = s.?.read(&buf);
    try testing.expectEqualSlices(u8, "ping", buf[0..n]);
}

test "flow_control: stream flow control violation" {
    const testing = std.testing;
    const sid = StreamId.init(0);
    var s = Stream.init(sid, 100_000, 10); // recv_max = 10

    try testing.expect(s.onRecvData(0, "hello", false)); // 5 bytes OK
    try testing.expect(!s.onRecvData(5, " world!", false)); // 7 more = 12 total > 10
}
