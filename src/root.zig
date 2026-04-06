//! zquic — a pure Zig implementation of QUIC (RFC 9000 / 9001 / 9002).
//!
//! Protocol coverage:
//!   - RFC 9000  QUIC: A UDP-Based Multiplexed and Secure Transport
//!   - RFC 9001  Using TLS to Secure QUIC
//!   - RFC 9002  QUIC Loss Detection and Congestion Control
//!   - RFC 9114  HTTP/3
//!   - RFC 9204  QPACK: Header Compression for HTTP/3

pub const varint = @import("varint.zig");
pub const types = @import("types.zig");

test {
    _ = @import("varint.zig");
    _ = @import("types.zig");
}
