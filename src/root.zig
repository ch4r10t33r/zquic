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
pub const packet = struct {
    pub const header = @import("packet/header.zig");
    pub const number = @import("packet/number.zig");
    pub const pkt = @import("packet/packet.zig");
};
pub const crypto = struct {
    pub const keys = @import("crypto/keys.zig");
    pub const aead = @import("crypto/aead.zig");
    pub const initial = @import("crypto/initial.zig");
    pub const quic_tls = @import("crypto/quic_tls.zig");
};
pub const frames = struct {
    pub const frame = @import("frames/frame.zig");
    pub const ack = @import("frames/ack.zig");
    pub const crypto_frame = @import("frames/crypto_frame.zig");
    pub const stream = @import("frames/stream.zig");
    pub const transport = @import("frames/transport.zig");
};

test {
    _ = @import("varint.zig");
    _ = @import("types.zig");
    _ = @import("packet/header.zig");
    _ = @import("packet/number.zig");
    _ = @import("packet/packet.zig");
    _ = @import("crypto/keys.zig");
    _ = @import("crypto/aead.zig");
    _ = @import("crypto/initial.zig");
    _ = @import("crypto/quic_tls.zig");
    _ = @import("frames/frame.zig");
    _ = @import("frames/ack.zig");
    _ = @import("frames/crypto_frame.zig");
    _ = @import("frames/stream.zig");
    _ = @import("frames/transport.zig");
}
