//! HTTP/3 frame encoding and decoding (RFC 9114 §7).
//!
//! HTTP/3 frames are carried on QUIC streams.  Each frame has:
//!   Type   (variable-length integer)
//!   Length (variable-length integer, number of payload bytes)
//!   Payload
//!
//! Frame types defined in RFC 9114:
//!   DATA        (0x00) – request/response body bytes
//!   HEADERS     (0x01) – QPACK-compressed header block
//!   CANCEL_PUSH (0x03) – cancel a server push
//!   SETTINGS    (0x04) – connection-level settings
//!   PUSH_PROMISE(0x05) – server push promise
//!   GOAWAY      (0x07) – graceful shutdown
//!   MAX_PUSH_ID (0x0d) – upper bound on push IDs
//!
//! Note: Server Push (PUSH_PROMISE / CANCEL_PUSH / MAX_PUSH_ID) is
//! intentionally not implemented.  Server push is optional per RFC 9114 §4.6,
//! has been deprecated by all major browsers, and introduces significant
//! complexity with minimal real-world benefit.  The frame types are parsed for
//! protocol correctness but never generated.

const std = @import("std");
const varint = @import("../varint.zig");

// ---------------------------------------------------------------------------
// Frame type codes
// ---------------------------------------------------------------------------

pub const FrameType = enum(u64) {
    data = 0x00,
    headers = 0x01,
    cancel_push = 0x03,
    settings = 0x04,
    push_promise = 0x05,
    goaway = 0x07,
    max_push_id = 0x0d,
    _,
};

// ---------------------------------------------------------------------------
// SETTINGS
// ---------------------------------------------------------------------------

/// A single HTTP/3 setting parameter.
pub const Setting = struct {
    id: u64,
    value: u64,
};

/// Well-known SETTINGS identifiers (RFC 9114 §7.2.4.1, RFC 9204).
pub const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
pub const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x06;
pub const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;

/// Maximum settings per frame (sanity bound for stack allocation).
pub const max_settings: usize = 16;

pub const SettingsFrame = struct {
    settings: [max_settings]Setting,
    count: usize,
};

// ---------------------------------------------------------------------------
// HEADERS
// ---------------------------------------------------------------------------

/// Maximum QPACK-compressed header block that fits in a stack buffer.
pub const max_header_block: usize = 4096;

pub const HeadersFrame = struct {
    /// Encoded field section (QPACK output).
    data: [max_header_block]u8,
    len: usize,
};

// ---------------------------------------------------------------------------
// Frame union
// ---------------------------------------------------------------------------

/// An unknown / extension frame type.
pub const UnknownFrame = struct {
    frame_type: u64,
    len: u64,
};

pub const FrameTag = enum {
    data,
    headers,
    cancel_push,
    settings,
    push_promise,
    goaway,
    max_push_id,
    unknown,
};

pub const Frame = union(FrameTag) {
    data: []const u8,
    headers: HeadersFrame,
    cancel_push: u64,
    settings: SettingsFrame,
    push_promise: []const u8,
    goaway: u64,
    max_push_id: u64,
    unknown: UnknownFrame,
};

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

pub const ParseError = error{
    BufferTooShort,
    FrameTooLarge,
    InvalidSettings,
};

/// Frame parse result: the decoded frame and the number of bytes consumed.
pub const ParseResult = struct {
    frame: Frame,
    consumed: usize,
};

/// Parse a single HTTP/3 frame from `buf`.
///
/// Returns `error.BufferTooShort` if more bytes are needed.
pub fn parseFrame(buf: []const u8) ParseError!ParseResult {
    var reader = varint.Reader{ .buf = buf, .pos = 0 };

    const raw_type = reader.readVarint() catch return error.BufferTooShort;
    const payload_len_val = reader.readVarint() catch return error.BufferTooShort;
    const header_len = reader.pos;

    if (payload_len_val > 1 << 30) return error.FrameTooLarge;
    const plen: usize = @intCast(payload_len_val);

    if (buf.len < header_len + plen) return error.BufferTooShort;
    const payload = buf[header_len .. header_len + plen];

    const frame_type: FrameType = @enumFromInt(raw_type);
    const frame: Frame = switch (frame_type) {
        .data => .{ .data = payload },
        .headers => blk: {
            if (plen > max_header_block) return error.FrameTooLarge;
            var hf = HeadersFrame{ .data = undefined, .len = plen };
            @memcpy(hf.data[0..plen], payload);
            break :blk .{ .headers = hf };
        },
        .cancel_push => blk: {
            var r = varint.Reader{ .buf = payload, .pos = 0 };
            const id = r.readVarint() catch return error.BufferTooShort;
            break :blk .{ .cancel_push = id };
        },
        .settings => blk: {
            var sf = SettingsFrame{ .settings = undefined, .count = 0 };
            var r = varint.Reader{ .buf = payload, .pos = 0 };
            while (r.pos < payload.len and sf.count < max_settings) {
                const id = r.readVarint() catch break;
                const val = r.readVarint() catch return error.InvalidSettings;
                sf.settings[sf.count] = .{ .id = id, .value = val };
                sf.count += 1;
            }
            break :blk .{ .settings = sf };
        },
        .goaway => blk: {
            var r = varint.Reader{ .buf = payload, .pos = 0 };
            const id = r.readVarint() catch return error.BufferTooShort;
            break :blk .{ .goaway = id };
        },
        .max_push_id => blk: {
            var r = varint.Reader{ .buf = payload, .pos = 0 };
            const id = r.readVarint() catch return error.BufferTooShort;
            break :blk .{ .max_push_id = id };
        },
        .push_promise => .{ .push_promise = payload },
        _ => .{ .unknown = .{ .frame_type = raw_type, .len = payload_len_val } },
    };

    return ParseResult{
        .frame = frame,
        .consumed = header_len + plen,
    };
}

// ---------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------

/// Write a varint-framed HTTP/3 frame (type + length + payload) into `buf`.
/// Returns bytes written.
pub fn writeFrame(buf: []u8, frame_type: u64, payload: []const u8) error{BufferTooSmall}!usize {
    var writer = varint.Writer{ .buf = buf, .pos = 0 };
    writer.writeVarint(frame_type) catch return error.BufferTooSmall;
    writer.writeVarint(payload.len) catch return error.BufferTooSmall;
    if (writer.pos + payload.len > buf.len) return error.BufferTooSmall;
    @memcpy(buf[writer.pos .. writer.pos + payload.len], payload);
    return writer.pos + payload.len;
}

/// Write a SETTINGS frame from a slice of `Setting` values.
pub fn writeSettings(buf: []u8, settings: []const Setting) error{BufferTooSmall}!usize {
    // Build the payload first.
    var payload_buf: [512]u8 = undefined;
    var writer = varint.Writer{ .buf = &payload_buf, .pos = 0 };
    for (settings) |s| {
        writer.writeVarint(s.id) catch return error.BufferTooSmall;
        writer.writeVarint(s.value) catch return error.BufferTooSmall;
    }
    return writeFrame(buf, @intFromEnum(FrameType.settings), payload_buf[0..writer.pos]);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "http3 frame: DATA round-trip" {
    const testing = std.testing;
    const body = "Hello, HTTP/3!";

    var buf: [64]u8 = undefined;
    const written = try writeFrame(&buf, @intFromEnum(FrameType.data), body);

    const result = try parseFrame(buf[0..written]);
    try testing.expectEqual(written, result.consumed);
    try testing.expectEqualSlices(u8, body, result.frame.data);
}

test "http3 frame: SETTINGS round-trip" {
    const testing = std.testing;
    const settings_in = [_]Setting{
        .{ .id = SETTINGS_QPACK_MAX_TABLE_CAPACITY, .value = 4096 },
        .{ .id = SETTINGS_MAX_FIELD_SECTION_SIZE, .value = 16384 },
    };

    var buf: [64]u8 = undefined;
    const written = try writeSettings(&buf, &settings_in);

    const result = try parseFrame(buf[0..written]);
    const sf = result.frame.settings;
    try testing.expectEqual(@as(usize, 2), sf.count);
    try testing.expectEqual(SETTINGS_QPACK_MAX_TABLE_CAPACITY, sf.settings[0].id);
    try testing.expectEqual(@as(u64, 4096), sf.settings[0].value);
    try testing.expectEqual(SETTINGS_MAX_FIELD_SECTION_SIZE, sf.settings[1].id);
    try testing.expectEqual(@as(u64, 16384), sf.settings[1].value);
}

test "http3 frame: GOAWAY" {
    var buf: [16]u8 = undefined;
    var payload: [8]u8 = undefined;
    var w = varint.Writer{ .buf = &payload, .pos = 0 };
    w.writeVarint(42) catch unreachable;
    const written = try writeFrame(&buf, @intFromEnum(FrameType.goaway), payload[0..w.pos]);
    const result = try parseFrame(buf[0..written]);
    try std.testing.expectEqual(@as(u64, 42), result.frame.goaway);
}

test "http3 frame: BufferTooShort" {
    const buf = [_]u8{0x00}; // type=DATA but no length
    try std.testing.expectError(error.BufferTooShort, parseFrame(&buf));
}

test "http3 frame: GOAWAY in control stream body" {
    // Simulate the body of a server control stream: SETTINGS then GOAWAY.
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    // SETTINGS with two entries
    const settings_len = writeSettings(buf[pos..], &[_]Setting{
        .{ .id = SETTINGS_QPACK_MAX_TABLE_CAPACITY, .value = 4096 },
    }) catch unreachable;
    pos += settings_len;
    // GOAWAY with last_stream_id=8
    var goaway_payload: [4]u8 = undefined;
    var w = @import("../varint.zig").Writer{ .buf = &goaway_payload, .pos = 0 };
    w.writeVarint(8) catch unreachable;
    const goaway_len = writeFrame(buf[pos..], @intFromEnum(FrameType.goaway), goaway_payload[0..w.pos]) catch unreachable;
    pos += goaway_len;

    // Parse the whole body as a sequence of frames.
    var off: usize = 0;
    var saw_goaway = false;
    while (off < pos) {
        const pr = parseFrame(buf[off..pos]) catch break;
        off += pr.consumed;
        switch (pr.frame) {
            .goaway => |sid| {
                try testing.expectEqual(@as(u64, 8), sid);
                saw_goaway = true;
            },
            else => {},
        }
    }
    try testing.expect(saw_goaway);
}
