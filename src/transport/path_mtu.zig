//! Path MTU limits for QUIC datagrams (RFC 9000 §14).
//!
//! Full DPLPMTUD (probing, ICMP, black-hole detection) is not implemented yet.
//! This module clamps a configured maximum UDP payload and derives the largest
//! application chunk size that still fits under typical 1-RTT + STREAM headers.

const std = @import("std");
const types = @import("../types.zig");

/// Conservative overhead below `max_udp_payload` for 1-RTT short header + STREAM + AEAD tag.
const quic_stream_overhead: usize = 150;

/// Cap on per-chunk app data so fixed stack buffers in `io.zig` stay bounded.
pub const max_app_stream_chunk_cap: usize = types.max_datagram_size - 64;

/// Clamp user/configured max UDP payload to RFC 9000 §14.1 minimum and RFC max UDP payload.
pub fn clampMaxUdpPayload(requested: u16) u16 {
    const lo: u16 = @intCast(types.min_initial_mtu);
    const hi: u16 = @truncate(types.max_udp_payload_size);
    return std.math.clamp(requested, lo, hi);
}

/// Largest HTTP/0.9 or HTTP/3 DATA chunk (bytes of file/content) per QUIC STREAM frame.
pub fn appStreamChunkBytes(max_udp_payload: u16) usize {
    const up = @as(usize, max_udp_payload);
    const raw = @max(400, up -| quic_stream_overhead);
    return @min(raw, max_app_stream_chunk_cap);
}

/// Result for initializing `ConnState` path fields from optional config.
pub fn initFromConfig(max_udp_payload_opt: ?u16) struct { max_udp_payload: u16, app_stream_chunk: usize } {
    const requested: u16 = max_udp_payload_opt orelse @as(u16, @truncate(types.max_datagram_size));
    const max_udp_payload = clampMaxUdpPayload(requested);
    return .{
        .max_udp_payload = max_udp_payload,
        .app_stream_chunk = appStreamChunkBytes(max_udp_payload),
    };
}

test "path_mtu: clamp and chunk" {
    const t = std.testing;
    try t.expectEqual(@as(u16, 1200), clampMaxUdpPayload(1000));
    try t.expectEqual(@as(u16, 1500), clampMaxUdpPayload(1500));
    try t.expect(appStreamChunkBytes(1500) >= 1300);
    try t.expectEqual(@as(usize, 1050), appStreamChunkBytes(1200));
    try t.expect(appStreamChunkBytes(65527) <= max_app_stream_chunk_cap);
}
