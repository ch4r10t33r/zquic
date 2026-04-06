const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

pub const max_ciphertext_record_len = @import("cipher.zig").max_ciphertext_record_len;

/// Buffer of this size will fit any tls ciphertext record sent by other side.
/// To decrytp we need full record, smalled buffer will not work in general
/// case. Bigger can be used for performance reason.
pub const input_buffer_len = max_ciphertext_record_len; // 16645 bytes

/// Needed output buffer during handshake is the size of the tls hello message,
/// which is (when client authentication is not used) ~1600 bytes. After
/// handshake it limits how big tls record can be produced. This suggested value
/// can hold max ciphertext record produced with this implementation.
pub const output_buffer_len = @import("cipher.zig").max_encrypted_record_len; // 16469 bytes

// Stream-based TLS Connection API removed — connection.zig not vendored.
// This vendored copy is used only for PrivateKey loading and NonBlock handshake primitives.

pub const config = struct {
    const proto = @import("protocol.zig");
    const common = @import("handshake_common.zig");

    pub const CipherSuite = @import("cipher.zig").CipherSuite;
    pub const PrivateKey = @import("PrivateKey.zig");
    pub const NamedGroup = proto.NamedGroup;
    pub const Version = proto.Version;
    pub const cert = common.cert;
    pub const CertKeyPair = common.CertKeyPair;

    pub const cipher_suites = @import("cipher.zig").cipher_suites;
    pub const key_log = @import("key_log.zig");

    pub const Client = @import("handshake_client.zig").Options;
    pub const Server = @import("handshake_server.zig").Options;
};

/// Non-blocking client/server handshake. Handshake produces
/// cipher used to encrypt/decrypt data.
pub const nonblock = struct {
    pub const Client = @import("handshake_client.zig").NonBlock;
    pub const Server = @import("handshake_server.zig").NonBlock;
};

test "nonblock handshake" {
    const testing = @import("std").testing;

    // data from server to the client
    var sc_buf: [max_ciphertext_record_len]u8 = undefined;
    // data from client to the server
    var cs_buf: [max_ciphertext_record_len]u8 = undefined;

    var cli = nonblock.Client.init(.{
        .root_ca = .{},
        .host = &.{},
        .insecure_skip_verify = true,
    });
    var srv = nonblock.Server.init(.{ .auth = null });

    // client flight1; client hello is in buf1
    var cr = try cli.run(&sc_buf, &cs_buf);
    try testing.expectEqual(0, cr.recv_pos);
    try testing.expect(cr.send.len > 0);
    try testing.expect(!cli.done());

    { // short read, partial buffer received
        for (0..cr.send_pos) |i| {
            const sr = try srv.run(cs_buf[0..i], &sc_buf);
            try testing.expectEqual(0, sr.recv_pos);
            try testing.expectEqual(0, sr.send_pos);
        }
    }

    // server flight 1; server parses client hello from buf2 and writes server hello into buf1
    var sr = try srv.run(&cs_buf, &sc_buf);
    try testing.expectEqual(sr.recv_pos, cr.send_pos);
    try testing.expect(sr.send.len > 0);
    try testing.expect(!srv.done());

    { // short read, partial buffer received
        for (0..sr.send_pos) |i| {
            cr = try cli.run(sc_buf[0..i], &cs_buf);
            try testing.expectEqual(0, cr.recv_pos);
            try testing.expectEqual(0, cr.send_pos);
        }
    }

    // client flight 2; client parses server hello from buf1 and writes finished into buf2
    cr = try cli.run(&sc_buf, &cs_buf);
    try testing.expectEqual(sr.send_pos, cr.recv_pos);
    try testing.expect(cr.send.len > 0);
    try testing.expect(cli.done()); // client is done
    try testing.expect(cli.cipher() != null);

    // server parses client finished
    sr = try srv.run(&cs_buf, &sc_buf);
    try testing.expectEqual(sr.recv_pos, cr.send_pos);
    try testing.expectEqual(0, sr.send.len);
    try testing.expect(srv.done()); // server is done
    try testing.expect(srv.cipher() != null);
}

test {
    _ = @import("handshake_common.zig");
    _ = @import("handshake_server.zig");
    _ = @import("handshake_client.zig");

    _ = @import("cipher.zig");
    _ = @import("record.zig");
    _ = @import("transcript.zig");
    _ = @import("PrivateKey.zig");
}
