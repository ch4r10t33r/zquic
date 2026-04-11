//! QPACK: Header Compression for HTTP/3 (RFC 9204).
//!
//! QPACK is a compression format for HTTP/3 header fields.  It builds on
//! HPACK (RFC 7541) but is adapted for QUIC's out-of-order delivery.
//!
//! QPACK uses two QUIC unidirectional streams per direction:
//!   - Encoder stream (type 0x02): communicates dynamic table updates to the peer.
//!   - Decoder stream (type 0x03): sends Section Acknowledgements, Insert Count
//!     Increments, and Stream Cancellations back to the encoder.
//!
//! This implementation supports:
//!   - Static table lookup and encoding (RFC 9204 Appendix A, 99 entries).
//!   - Indexed Field Line encoding/decoding using the static table (§4.5.2).
//!   - Literal Field Line With Static Name Reference encoding/decoding (§4.5.4).
//!   - Literal Field Line Without Name Reference encoding/decoding (§4.5.6).
//!   - Dynamic table data structure (circular buffer, capacity-bounded, §3.2).
//!   - Encoder stream instruction encoding/decoding (§3.2.4, §4.3).
//!   - Decoder stream instruction encoding (§4.4).
//!
//! Dynamic table insertions in outgoing HEADERS blocks require advertising a
//! non-zero SETTINGS_QPACK_MAX_TABLE_CAPACITY and setting up encoder/decoder
//! streams; see the EncodeOptions.table field.

const std = @import("std");

// ---------------------------------------------------------------------------
// QPACK static table (RFC 9204 Appendix A – 99 entries, indices 0-98)
// ---------------------------------------------------------------------------

pub const StaticEntry = struct {
    name: []const u8,
    value: []const u8,
};

pub const static_table = [_]StaticEntry{
    .{ .name = ":authority", .value = "" }, // 0
    .{ .name = ":path", .value = "/" }, // 1
    .{ .name = "age", .value = "0" }, // 2
    .{ .name = "content-disposition", .value = "" }, // 3
    .{ .name = "content-length", .value = "0" }, // 4
    .{ .name = "cookie", .value = "" }, // 5
    .{ .name = "date", .value = "" }, // 6
    .{ .name = "etag", .value = "" }, // 7
    .{ .name = "if-modified-since", .value = "" }, // 8
    .{ .name = "if-none-match", .value = "" }, // 9
    .{ .name = "last-modified", .value = "" }, // 10
    .{ .name = "link", .value = "" }, // 11
    .{ .name = "location", .value = "" }, // 12
    .{ .name = "referer", .value = "" }, // 13
    .{ .name = "set-cookie", .value = "" }, // 14
    .{ .name = ":method", .value = "CONNECT" }, // 15
    .{ .name = ":method", .value = "DELETE" }, // 16
    .{ .name = ":method", .value = "GET" }, // 17
    .{ .name = ":method", .value = "HEAD" }, // 18
    .{ .name = ":method", .value = "OPTIONS" }, // 19
    .{ .name = ":method", .value = "POST" }, // 20
    .{ .name = ":method", .value = "PUT" }, // 21
    .{ .name = ":scheme", .value = "http" }, // 22
    .{ .name = ":scheme", .value = "https" }, // 23
    .{ .name = ":status", .value = "103" }, // 24
    .{ .name = ":status", .value = "200" }, // 25
    .{ .name = ":status", .value = "304" }, // 26
    .{ .name = ":status", .value = "404" }, // 27
    .{ .name = ":status", .value = "503" }, // 28
    .{ .name = "accept", .value = "*/*" }, // 29
    .{ .name = "accept", .value = "application/dns-message" }, // 30
    .{ .name = "accept-encoding", .value = "gzip, deflate, br" }, // 31
    .{ .name = "accept-ranges", .value = "bytes" }, // 32
    .{ .name = "access-control-allow-headers", .value = "cache-control" }, // 33
    .{ .name = "access-control-allow-headers", .value = "content-type" }, // 34
    .{ .name = "access-control-allow-origin", .value = "*" }, // 35
    .{ .name = "cache-control", .value = "max-age=0" }, // 36
    .{ .name = "cache-control", .value = "max-age=2592000" }, // 37
    .{ .name = "cache-control", .value = "max-age=604800" }, // 38
    .{ .name = "cache-control", .value = "no-cache" }, // 39
    .{ .name = "cache-control", .value = "no-store" }, // 40
    .{ .name = "cache-control", .value = "public, max-age=31536000" }, // 41
    .{ .name = "content-encoding", .value = "br" }, // 42
    .{ .name = "content-encoding", .value = "gzip" }, // 43
    .{ .name = "content-type", .value = "application/dns-message" }, // 44
    .{ .name = "content-type", .value = "application/javascript" }, // 45
    .{ .name = "content-type", .value = "application/json" }, // 46
    .{ .name = "content-type", .value = "application/x-www-form-urlencoded" }, // 47
    .{ .name = "content-type", .value = "image/gif" }, // 48
    .{ .name = "content-type", .value = "image/jpeg" }, // 49
    .{ .name = "content-type", .value = "image/png" }, // 50
    .{ .name = "content-type", .value = "text/css" }, // 51
    .{ .name = "content-type", .value = "text/html; charset=utf-8" }, // 52
    .{ .name = "content-type", .value = "text/plain" }, // 53
    .{ .name = "content-type", .value = "text/plain;charset=utf-8" }, // 54
    .{ .name = "range", .value = "bytes=0-" }, // 55
    .{ .name = "strict-transport-security", .value = "max-age=31536000" }, // 56
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains" }, // 57
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains; preload" }, // 58
    .{ .name = "vary", .value = "accept-encoding" }, // 59
    .{ .name = "vary", .value = "origin" }, // 60
    .{ .name = "x-content-type-options", .value = "nosniff" }, // 61
    .{ .name = "x-xss-protection", .value = "1; mode=block" }, // 62
    .{ .name = ":status", .value = "100" }, // 63
    .{ .name = ":status", .value = "204" }, // 64
    .{ .name = ":status", .value = "206" }, // 65
    .{ .name = ":status", .value = "302" }, // 66
    .{ .name = ":status", .value = "400" }, // 67
    .{ .name = ":status", .value = "403" }, // 68
    .{ .name = ":status", .value = "421" }, // 69
    .{ .name = ":status", .value = "425" }, // 70
    .{ .name = ":status", .value = "500" }, // 71
    .{ .name = "accept-language", .value = "" }, // 72
    .{ .name = "access-control-allow-credentials", .value = "FALSE" }, // 73
    .{ .name = "access-control-allow-credentials", .value = "TRUE" }, // 74
    .{ .name = "access-control-allow-headers", .value = "*" }, // 75
    .{ .name = "access-control-allow-methods", .value = "get" }, // 76
    .{ .name = "access-control-allow-methods", .value = "get, post, options" }, // 77
    .{ .name = "access-control-allow-methods", .value = "options" }, // 78
    .{ .name = "access-control-allow-origin", .value = "null" }, // 79
    .{ .name = "access-control-expose-headers", .value = "content-length" }, // 80
    .{ .name = "access-control-request-headers", .value = "content-type" }, // 81
    .{ .name = "access-control-request-method", .value = "get" }, // 82
    .{ .name = "access-control-request-method", .value = "post" }, // 83
    .{ .name = "alt-svc", .value = "clear" }, // 84
    .{ .name = "authorization", .value = "" }, // 85
    .{ .name = "content-security-policy", .value = "script-src 'none'; object-src 'none'; base-uri 'none'" }, // 86
    .{ .name = "early-data", .value = "1" }, // 87
    .{ .name = "expect-ct", .value = "" }, // 88
    .{ .name = "forwarded", .value = "" }, // 89
    .{ .name = "if-range", .value = "" }, // 90
    .{ .name = "origin", .value = "" }, // 91
    .{ .name = "purpose", .value = "prefetch" }, // 92
    .{ .name = "server", .value = "" }, // 93
    .{ .name = "timing-allow-origin", .value = "*" }, // 94
    .{ .name = "upgrade-insecure-requests", .value = "1" }, // 95
    .{ .name = "user-agent", .value = "" }, // 96
    .{ .name = "x-forwarded-for", .value = "" }, // 97
    .{ .name = "x-frame-options", .value = "deny" }, // 98
    .{ .name = "x-frame-options", .value = "sameorigin" }, // 99 — note: len=100
};

// ---------------------------------------------------------------------------
// Compile-time static table lookup maps (O(1) hash lookups)
// ---------------------------------------------------------------------------

/// Number of distinct header names in the static table (computed at comptime).
const STATIC_UNIQUE_NAME_COUNT: usize = blk: {
    @setEvalBranchQuota(200_000);
    var names: [static_table.len][]const u8 = undefined;
    var n: usize = 0;
    outer: for (static_table) |e| {
        for (names[0..n]) |s| {
            if (std.mem.eql(u8, s, e.name)) continue :outer;
        }
        names[n] = e.name;
        n += 1;
    }
    break :blk n;
};

/// Comptime KV array: unique name → first static table index with that name.
const static_name_kvs: [STATIC_UNIQUE_NAME_COUNT]struct { []const u8, usize } = blk: {
    @setEvalBranchQuota(200_000);
    var kvs: [STATIC_UNIQUE_NAME_COUNT]struct { []const u8, usize } = undefined;
    var n: usize = 0;
    outer: for (static_table, 0..) |e, i| {
        for (kvs[0..n]) |kv| {
            if (std.mem.eql(u8, kv[0], e.name)) continue :outer;
        }
        kvs[n] = .{ e.name, i };
        n += 1;
    }
    break :blk kvs;
};

/// O(1) compile-time hash map: name → first static table index.
const static_name_map = std.StaticStringMap(usize).initComptime(static_name_kvs);

/// Comptime KV array: "name\x00value" → static table index (all 100 entries).
/// The \x00 separator is safe because HTTP header names/values cannot contain NUL.
const static_entry_kvs: [static_table.len]struct { []const u8, usize } = blk: {
    @setEvalBranchQuota(2_000_000);
    var kvs: [static_table.len]struct { []const u8, usize } = undefined;
    for (static_table, 0..) |e, i| {
        kvs[i] = .{ std.fmt.comptimePrint("{s}\x00{s}", .{ e.name, e.value }), i };
    }
    break :blk kvs;
};

/// O(1) compile-time hash map: "name\x00value" → static table index.
const static_entry_map = std.StaticStringMap(usize).initComptime(static_entry_kvs);

// ---------------------------------------------------------------------------
// Header field representation
// ---------------------------------------------------------------------------

pub const Header = struct {
    name: []const u8,
    value: []const u8,
    sensitive: bool = false,
};

// ---------------------------------------------------------------------------
// RFC 9204 §4.1.1 — Prefix-integer encoding/decoding (used for all indices,
// name lengths, and value lengths in QPACK field representations).
// ---------------------------------------------------------------------------

/// Encode `value` as a prefix integer with `prefix_bits` low bits.
/// `first_byte_flags` is OR'd into the first byte's high bits (e.g. 0xC0).
/// Returns bytes written into `buf`.
fn encodeInteger(
    buf: []u8,
    comptime prefix_bits: u4,
    first_byte_flags: u8,
    value: u64,
) error{BufferTooSmall}!usize {
    const max_prefix: u64 = (@as(u64, 1) << prefix_bits) - 1;
    if (value < max_prefix) {
        if (buf.len < 1) return error.BufferTooSmall;
        buf[0] = first_byte_flags | @as(u8, @intCast(value));
        return 1;
    }
    // Multi-byte encoding: first byte saturated, then 7-bit groups.
    if (buf.len < 1) return error.BufferTooSmall;
    buf[0] = first_byte_flags | @as(u8, @intCast(max_prefix));
    var remaining = value - max_prefix;
    var pos: usize = 1;
    while (remaining >= 128) {
        if (pos >= buf.len) return error.BufferTooSmall;
        buf[pos] = @as(u8, @intCast(remaining & 0x7F)) | 0x80;
        pos += 1;
        remaining >>= 7;
    }
    if (pos >= buf.len) return error.BufferTooSmall;
    buf[pos] = @as(u8, @intCast(remaining));
    return pos + 1;
}

const IntDecodeResult = struct { value: u64, consumed: usize };

/// Decode a prefix integer from `buf[0]` with `prefix_bits` low bits.
/// Returns value and total bytes consumed (including the first byte).
fn decodeInteger(
    buf: []const u8,
    comptime prefix_bits: u4,
) error{BufferTooShort}!IntDecodeResult {
    if (buf.len < 1) return error.BufferTooShort;
    const max_prefix: u64 = (@as(u64, 1) << prefix_bits) - 1;
    const first: u64 = buf[0] & @as(u8, @intCast(max_prefix));
    if (first < max_prefix) return .{ .value = first, .consumed = 1 };
    // Multi-byte: read 7-bit continuation groups.
    var value: u64 = max_prefix;
    var shift: u6 = 0;
    var pos: usize = 1;
    while (true) {
        if (pos >= buf.len) return error.BufferTooShort;
        const b = buf[pos];
        pos += 1;
        value += @as(u64, b & 0x7F) << shift;
        shift += 7;
        if (b & 0x80 == 0) break;
        if (shift >= 63) return error.BufferTooShort; // overflow guard
    }
    return .{ .value = value, .consumed = pos };
}

// ---------------------------------------------------------------------------
// Static table helpers
// ---------------------------------------------------------------------------

/// Find an exact name+value match in the static table.  Returns the index
/// (0-based) or null if not found.
///
/// O(1) via a compile-time perfect-hash map keyed on "name\x00value".
/// A 512-byte stack buffer is used to construct the lookup key without
/// heap allocation; all real HTTP header name+value pairs are well under
/// this limit.
fn findStaticEntry(name: []const u8, value: []const u8) ?usize {
    var key_buf: [512]u8 = undefined;
    const total = name.len + 1 + value.len;
    if (total > key_buf.len) return null;
    @memcpy(key_buf[0..name.len], name);
    key_buf[name.len] = 0; // NUL separator
    @memcpy(key_buf[name.len + 1 ..][0..value.len], value);
    return static_entry_map.get(key_buf[0..total]);
}

/// Find the first static table entry whose name matches `name`.
/// Returns the index or null if not found.
///
/// O(1) via a compile-time perfect-hash map.
fn findStaticName(name: []const u8) ?usize {
    return static_name_map.get(name);
}

// ---------------------------------------------------------------------------
// Dynamic table (RFC 9204 §3.2)
// ---------------------------------------------------------------------------

/// Maximum bytes for name+value stored inline per entry.
/// Entry wire-size = name.len + value.len + 32 (§3.2.1).
/// Headers with longer fields fall back to literal-without-name-ref encoding.
pub const MAX_DYN_ENTRY_BYTES: usize = 256;

/// Maximum number of dynamic table entries (at default capacity 4096,
/// with minimum entry wire-size 32, that is at most 128 entries).
pub const MAX_DYN_ENTRIES: usize = 128;

/// Default dynamic table capacity advertised in SETTINGS
/// (SETTINGS_QPACK_MAX_TABLE_CAPACITY).
pub const DEFAULT_DYN_TABLE_CAPACITY: usize = 4096;

/// A single dynamic table entry stored inline (no heap allocation).
pub const DynEntry = struct {
    name_len: u16 = 0,
    value_len: u16 = 0,
    /// name bytes followed immediately by value bytes.
    buf: [MAX_DYN_ENTRY_BYTES]u8 = undefined,

    pub fn name(self: *const DynEntry) []const u8 {
        return self.buf[0..self.name_len];
    }
    pub fn value(self: *const DynEntry) []const u8 {
        return self.buf[self.name_len .. self.name_len + self.value_len];
    }
    /// Wire size as defined in RFC 9204 §3.2.1.
    pub fn wireSize(self: *const DynEntry) usize {
        return @as(usize, self.name_len) + @as(usize, self.value_len) + 32;
    }
};

/// QPACK dynamic table (RFC 9204 §3.2).
///
/// Entries are stored in a circular buffer indexed by their absolute insertion
/// index.  The oldest entry has absolute index `insertion_count - count`; the
/// newest has absolute index `insertion_count - 1`.
///
/// Relative index (used inside a header block when Base is known):
///   relative = Base - 1 - absolute
///
/// Post-base index (for entries added after Base):
///   post_base = absolute - Base
pub const DynamicTable = struct {
    entries: [MAX_DYN_ENTRIES]DynEntry = [_]DynEntry{.{}} ** MAX_DYN_ENTRIES,
    /// Circular-buffer head: slot of the oldest live entry.
    head: usize = 0,
    /// Number of live entries currently in the table.
    count: usize = 0,
    /// Total insertions ever made (= absolute index of the next entry).
    insertion_count: usize = 0,
    /// Current capacity limit in bytes (set via Set Dynamic Table Capacity).
    capacity: usize = 0,
    /// Sum of wireSize() for all live entries.
    used_bytes: usize = 0,

    /// Maximum number of entries permitted at the current capacity.
    /// RFC 9204 §3.2.2: maxEntries = floor(capacity / 32).
    pub fn maxEntries(self: *const DynamicTable) usize {
        return self.capacity / 32;
    }

    /// Absolute index of the oldest live entry, or insertion_count when empty.
    pub fn oldestAbsolute(self: *const DynamicTable) usize {
        return self.insertion_count - self.count;
    }

    /// Insert a new (name, value) entry, evicting oldest entries as needed.
    /// Returns error.EntryTooLarge if the single entry exceeds capacity.
    /// Returns error.NameTooLong / error.ValueTooLong if combined bytes > MAX_DYN_ENTRY_BYTES.
    pub fn insert(
        self: *DynamicTable,
        name_bytes: []const u8,
        value_bytes: []const u8,
    ) error{ EntryTooLarge, NameTooLong, ValueTooLong }!void {
        if (name_bytes.len > MAX_DYN_ENTRY_BYTES) return error.NameTooLong;
        if (value_bytes.len > MAX_DYN_ENTRY_BYTES) return error.ValueTooLong;
        if (name_bytes.len + value_bytes.len > MAX_DYN_ENTRY_BYTES) return error.NameTooLong;
        const entry_wire = name_bytes.len + value_bytes.len + 32;
        if (entry_wire > self.capacity) return error.EntryTooLarge;

        // Evict oldest entries until there is room.
        while (self.count > 0 and self.used_bytes + entry_wire > self.capacity) {
            const oldest_slot = self.head % MAX_DYN_ENTRIES;
            self.used_bytes -= self.entries[oldest_slot].wireSize();
            self.head = (self.head + 1) % MAX_DYN_ENTRIES;
            self.count -= 1;
        }

        // Write new entry at the tail slot.
        const tail_slot = (self.head + self.count) % MAX_DYN_ENTRIES;
        var e = &self.entries[tail_slot];
        e.name_len = @intCast(name_bytes.len);
        e.value_len = @intCast(value_bytes.len);
        @memcpy(e.buf[0..name_bytes.len], name_bytes);
        @memcpy(e.buf[name_bytes.len .. name_bytes.len + value_bytes.len], value_bytes);
        self.count += 1;
        self.insertion_count += 1;
        self.used_bytes += entry_wire;
    }

    /// Retrieve an entry by its absolute insertion index.
    /// Returns null if the index is out of the current live range.
    pub fn getByAbsolute(self: *const DynamicTable, abs: usize) ?*const DynEntry {
        if (self.count == 0) return null;
        const oldest = self.insertion_count - self.count;
        if (abs < oldest or abs >= self.insertion_count) return null;
        const slot = (self.head + (abs - oldest)) % MAX_DYN_ENTRIES;
        return &self.entries[slot];
    }

    /// Scan for an exact name+value match.  Returns the absolute index or null.
    pub fn findExact(self: *const DynamicTable, name_bytes: []const u8, value_bytes: []const u8) ?usize {
        if (self.count == 0) return null;
        const oldest = self.insertion_count - self.count;
        for (0..self.count) |i| {
            const slot = (self.head + i) % MAX_DYN_ENTRIES;
            const e = &self.entries[slot];
            if (std.mem.eql(u8, e.name(), name_bytes) and std.mem.eql(u8, e.value(), value_bytes)) {
                return oldest + i;
            }
        }
        return null;
    }

    /// Scan for the first name-only match (newest first for best compression).
    /// Returns the absolute index or null.
    pub fn findName(self: *const DynamicTable, name_bytes: []const u8) ?usize {
        if (self.count == 0) return null;
        const oldest = self.insertion_count - self.count;
        // Scan newest-first so we get the best (lowest relative index) match.
        var i = self.count;
        while (i > 0) {
            i -= 1;
            const slot = (self.head + i) % MAX_DYN_ENTRIES;
            const e = &self.entries[slot];
            if (std.mem.eql(u8, e.name(), name_bytes)) {
                return oldest + i;
            }
        }
        return null;
    }

    /// Set the table capacity.  If the new capacity is smaller than the current
    /// used_bytes, evict entries from oldest until within budget.
    pub fn setCapacity(self: *DynamicTable, new_capacity: usize) void {
        self.capacity = new_capacity;
        while (self.count > 0 and self.used_bytes > self.capacity) {
            const oldest_slot = self.head % MAX_DYN_ENTRIES;
            self.used_bytes -= self.entries[oldest_slot].wireSize();
            self.head = (self.head + 1) % MAX_DYN_ENTRIES;
            self.count -= 1;
        }
    }
};

// ---------------------------------------------------------------------------
// Encoder options
// ---------------------------------------------------------------------------

/// Controls how encodeHeaders produces field representations.
pub const EncodeOptions = struct {
    /// If non-null, the encoder may look up and emit indexed dynamic table
    /// references (and the caller is responsible for also sending insertion
    /// instructions on the encoder stream before this block is used).
    /// Currently: insertion into `table` must be done by the caller separately.
    table: ?*const DynamicTable = null,

    /// Maximum capacity the peer advertised (from SETTINGS_QPACK_MAX_TABLE_CAPACITY).
    /// Unused until dynamic insertions are implemented; reserved for Phase 3b.
    peer_max_capacity: u64 = 0,

    /// When true (default), attempt to find each header in the static table
    /// and emit a compact Indexed Field Line (1 byte for indices 0-62).
    /// Falls back to Literal Field Line Without Name Reference if not found.
    use_static_index: bool = true,
};

// ---------------------------------------------------------------------------
// Encoder helpers
// ---------------------------------------------------------------------------

/// Emit an Indexed Field Line referencing the static table.
/// Format (RFC 9204 §4.5.2): 1 T Index(6+)  where T=1 for static.
fn encodeIndexedStatic(buf: []u8, index: usize) error{BufferTooSmall}!usize {
    // First byte: 1 1 <6-bit prefix integer>
    return encodeInteger(buf, 6, 0xC0, index);
}

/// Emit an Indexed Field Line referencing the dynamic table by absolute index.
/// The caller must supply `base` (the Required Insert Count) so we can compute
/// the relative index (base - 1 - abs) or post-base index (abs - base).
fn encodeIndexedDynamic(buf: []u8, abs: usize, base: usize) error{BufferTooSmall}!usize {
    if (abs < base) {
        // Relative index: base - 1 - abs
        const rel = base - 1 - abs;
        // Format: 1 0 <6-bit prefix integer>
        return encodeInteger(buf, 6, 0x80, rel);
    } else {
        // Post-base index: abs - base
        const pb = abs - base;
        // Format: 0 0 0 1 <4-bit prefix integer>
        return encodeInteger(buf, 4, 0x10, pb);
    }
}

/// Emit a Literal Field Line Without Name Reference (RFC 9204 §4.5.6).
/// Format: 0 0 1 N H NameLen(3+) Name ValueLen(7+) Value
/// N=0 (not never-indexed), H=0 (no Huffman).
fn encodeLiteralField(buf: []u8, name: []const u8, value: []const u8) error{BufferTooSmall}!usize {
    var pos: usize = 0;
    // First byte: 0 0 1 0 0 <3-bit name-length prefix>
    // Prefix for name length is 3 bits; flags = 0x20 (bits 7..5 = 001, N=0, H=0).
    pos += try encodeInteger(buf[pos..], 3, 0x20, name.len);
    if (pos + name.len > buf.len) return error.BufferTooSmall;
    @memcpy(buf[pos .. pos + name.len], name);
    pos += name.len;
    // Value: H=0 flag in bit 7, 7-bit prefix integer for value length.
    pos += try encodeInteger(buf[pos..], 7, 0x00, value.len);
    if (pos + value.len > buf.len) return error.BufferTooSmall;
    @memcpy(buf[pos .. pos + value.len], value);
    pos += value.len;
    return pos;
}

/// Emit a Literal Field Line With Static Name Reference (RFC 9204 §4.5.4).
/// Format: 0 1 N T NameIdx(4+) H ValueLen(7+) Value
/// N=0, T=1 (static).  First byte high nibble = 0b0101 = 0x50.
fn encodeLiteralWithStaticNameRef(buf: []u8, static_idx: usize, value: []const u8) error{BufferTooSmall}!usize {
    var pos: usize = 0;
    // First byte: 0 1 N=0 T=1 <4-bit name-index prefix>; flags = 0x50.
    pos += try encodeInteger(buf[pos..], 4, 0x50, static_idx);
    // Value length with H=0 flag in bit 7, 7-bit prefix.
    pos += try encodeInteger(buf[pos..], 7, 0x00, value.len);
    if (pos + value.len > buf.len) return error.BufferTooSmall;
    @memcpy(buf[pos .. pos + value.len], value);
    pos += value.len;
    return pos;
}

/// Write the Required Insert Count / Base 2-byte prefix for a header block.
/// When RIC = 0 (no dynamic table references), both bytes are 0x00.
/// RFC 9204 §4.5.1.
fn writeHeaderBlockPrefix(buf: []u8, ric: usize, base: usize, max_entries: usize) error{BufferTooSmall}!usize {
    if (buf.len < 2) return error.BufferTooSmall;
    if (ric == 0) {
        buf[0] = 0x00; // Required Insert Count = 0
        buf[1] = 0x00; // S=0, Delta Base = 0
        return 2;
    }
    // encoded_ric = (ric % (2 * max_entries)) + 1
    const encoded_ric: usize = if (max_entries > 0) (ric % (2 * max_entries)) + 1 else ric;
    var pos: usize = 0;
    pos += try encodeInteger(buf[pos..], 8, 0x00, encoded_ric);
    // S bit and delta: if base >= ric, S=0 and delta = base - ric;
    // if base < ric, S=1 and delta = ric - base - 1.
    if (base >= ric) {
        pos += try encodeInteger(buf[pos..], 7, 0x00, base - ric);
    } else {
        pos += try encodeInteger(buf[pos..], 7, 0x80, ric - base - 1);
    }
    return pos;
}

/// Encode a slice of headers into a QPACK header block.
///
/// With `opts.use_static_index = true` (default), headers that match a static
/// table entry exactly are encoded as a 1-byte Indexed Field Line.  Headers
/// whose name matches a static entry are encoded as a Literal Field Line With
/// Static Name Reference (2–3 bytes for most short values).  All others fall
/// back to Literal Without Name Reference.
///
/// No dynamic table references are emitted unless `opts.table` is non-null
/// and the caller has pre-populated it with the entries to reference.
///
/// Returns the number of bytes written into `buf`.
pub fn encodeHeaders(headers: []const Header, buf: []u8, opts: EncodeOptions) error{BufferTooSmall}!usize {
    // We need to know the Required Insert Count (RIC) before writing the prefix,
    // but RIC is only known after encoding all fields.  Strategy: reserve 4 bytes
    // for the prefix (enough for any realistic table size — see below), encode
    // fields into buf[4..], then write the actual prefix and shift bytes left if
    // the prefix is shorter than 4 bytes.
    //
    // Prefix byte budget:
    //   RIC: 8-bit prefix integer.  With maxEntries=128, encoded_ric ≤ 256 →
    //        at most 2 bytes.
    //   Base delta: 7-bit prefix integer.  When base = RIC the delta is 0 → 1 byte.
    //   Total ≤ 3 bytes; 4 bytes is always sufficient.
    const prefix_reserve: usize = 4;
    if (buf.len < prefix_reserve) return error.BufferTooSmall;

    const base: usize = if (opts.table) |tbl| tbl.insertion_count else 0;
    var max_ric: usize = 0;
    var pos: usize = prefix_reserve;

    for (headers) |h| {
        if (h.sensitive) {
            // Sensitive headers: always use literal-without-name-ref, never index.
            pos += try encodeLiteralField(buf[pos..], h.name, h.value);
            continue;
        }

        if (opts.use_static_index) {
            // 1. Check dynamic table for exact match first (best compression).
            if (opts.table) |tbl| {
                if (tbl.findExact(h.name, h.value)) |abs| {
                    max_ric = @max(max_ric, abs + 1);
                    pos += try encodeIndexedDynamic(buf[pos..], abs, base);
                    continue;
                }
            }

            // 2. Check static table for exact match → Indexed Field Line (1 byte).
            if (findStaticEntry(h.name, h.value)) |idx| {
                pos += try encodeIndexedStatic(buf[pos..], idx);
                continue;
            }

            // 3. Check static table name-only match → Literal With Static Name Ref.
            if (findStaticName(h.name)) |idx| {
                pos += try encodeLiteralWithStaticNameRef(buf[pos..], idx, h.value);
                continue;
            }
        }

        // 4. Fallback: Literal Without Name Reference.
        pos += try encodeLiteralField(buf[pos..], h.name, h.value);
    }

    // Write the actual prefix now that we know RIC.
    const max_entries: usize = if (opts.table) |tbl| tbl.maxEntries() else 0;
    var prefix_buf: [4]u8 = undefined;
    const prefix_len = try writeHeaderBlockPrefix(&prefix_buf, max_ric, base, max_entries);
    @memcpy(buf[0..prefix_len], prefix_buf[0..prefix_len]);

    // Shift field bytes left to close any gap between prefix_len and prefix_reserve.
    if (prefix_len < prefix_reserve) {
        const field_bytes = pos - prefix_reserve;
        std.mem.copyForwards(u8, buf[prefix_len .. prefix_len + field_bytes], buf[prefix_reserve..pos]);
        pos = prefix_len + field_bytes;
    }
    // prefix_len == prefix_reserve: field bytes already in the right place.
    // prefix_len > prefix_reserve: structurally impossible with 4-byte reserve.

    return pos;
}

// ---------------------------------------------------------------------------
// Decoder (RFC 9204 §4.5)
// ---------------------------------------------------------------------------

pub const DecodeError = error{
    BufferTooShort,
    TooManyHeaders,
    Unsupported,
    InvalidStaticIndex,
    InvalidDynamicIndex,
    BlockedStream,
};

pub const max_headers: usize = 64;

pub const DecodedHeaders = struct {
    headers: [max_headers]Header,
    count: usize,
};

/// Decode a QPACK header block.
///
/// `table` may be null if the header block contains no dynamic table
/// references (RIC = 0).  Pass a pointer to the connection's decoder
/// DynamicTable once encoder stream integration is complete.
///
/// Supported field representations:
///   0b11xxxxxx — Indexed Field Line, T=1 (static table)
///   0b10xxxxxx — Indexed Field Line, T=0 (dynamic table, requires table≠null)
///   0b0001xxxx — Indexed Field Line With Post-Base Index (dynamic, Phase 3)
///   0b01xxxxxx — Literal Field Line With Name Reference
///                  T=1 (static name), T=0 (dynamic name, requires table≠null)
///   0b0000xxxx — Literal Field Line With Post-Base Name Reference (Phase 3)
///   0b001xxxxx — Literal Field Line Without Name Reference
pub fn decodeHeaders(
    buf: []const u8,
    table: ?*const DynamicTable,
    out: *DecodedHeaders,
) DecodeError!void {
    if (buf.len < 2) return error.BufferTooShort;

    // --- Parse header block prefix (Required Insert Count + Base) ---
    const ric_result = decodeInteger(buf[0..], 8) catch return error.BufferTooShort;
    const encoded_ric = ric_result.value;
    var pos: usize = ric_result.consumed;

    if (pos >= buf.len) return error.BufferTooShort;
    const s_and_delta = decodeInteger(buf[pos..], 7) catch return error.BufferTooShort;
    const s_bit = (buf[pos] & 0x80) != 0;
    const delta = s_and_delta.value;
    pos += s_and_delta.consumed;

    // Decode Required Insert Count.
    var ric: usize = 0;
    if (encoded_ric != 0) {
        if (table) |tbl| {
            const max_entries = tbl.maxEntries();
            const full_range: usize = if (max_entries > 0) 2 * max_entries else 1;
            const max_value = tbl.insertion_count + max_entries;
            const rounded = (max_value / full_range) * full_range;
            ric = rounded + (encoded_ric - 1);
            if (ric > max_value) ric -= full_range;
            // If the decoder doesn't yet have `ric` entries, the stream is blocked.
            if (ric > tbl.insertion_count) return error.BlockedStream;
        } else {
            // Non-zero RIC with no table provided — cannot decode dynamic refs.
            // Treat as blocked rather than hard error so the caller can buffer.
            return error.BlockedStream;
        }
    }

    // Compute Base.
    const base: usize = if (ric == 0)
        0
    else if (!s_bit)
        ric + delta
    else
        ric - delta - 1;

    out.count = 0;

    while (pos < buf.len) {
        if (out.count >= max_headers) return error.TooManyHeaders;
        const first = buf[pos];

        if (first & 0x80 != 0) {
            // ---------------------------------------------------------------
            // Indexed Field Line (0b1xxxxxxx)
            // T=1 (bit 6): static table reference
            // T=0 (bit 6): dynamic table reference (relative to base)
            // ---------------------------------------------------------------
            const t_static = (first & 0x40) != 0;
            if (t_static) {
                // Static indexed: 1 1 Index(6+)
                const r = decodeInteger(buf[pos..], 6) catch return error.BufferTooShort;
                pos += r.consumed;
                const idx = r.value;
                if (idx >= static_table.len) return error.InvalidStaticIndex;
                const e = &static_table[idx];
                out.headers[out.count] = .{ .name = e.name, .value = e.value };
                out.count += 1;
            } else {
                // Dynamic indexed: 1 0 RelIndex(6+)
                const r = decodeInteger(buf[pos..], 6) catch return error.BufferTooShort;
                pos += r.consumed;
                const rel = r.value;
                if (table) |tbl| {
                    if (base == 0 or rel >= base) return error.InvalidDynamicIndex;
                    const abs = base - 1 - rel;
                    const entry = tbl.getByAbsolute(abs) orelse return error.InvalidDynamicIndex;
                    out.headers[out.count] = .{ .name = entry.name(), .value = entry.value() };
                    out.count += 1;
                } else {
                    return error.Unsupported;
                }
            }
        } else if (first & 0x40 != 0) {
            // ---------------------------------------------------------------
            // Literal Field Line With Name Reference (0b01xxxxxx)
            // Bits: 0 1 N T NameIndex(4+)
            // N = never-indexed (bit 5), T = static/dynamic (bit 4)
            // ---------------------------------------------------------------
            const t_static = (first & 0x10) != 0;
            const r_idx = decodeInteger(buf[pos..], 4) catch return error.BufferTooShort;
            pos += r_idx.consumed;

            // Read value: H=0 bit (bit 7), then 7-bit prefix length.
            if (pos >= buf.len) return error.BufferTooShort;
            const val_r = decodeInteger(buf[pos..], 7) catch return error.BufferTooShort;
            pos += val_r.consumed;
            const val_len: usize = @intCast(val_r.value);
            if (pos + val_len > buf.len) return error.BufferTooShort;
            const value = buf[pos .. pos + val_len];
            pos += val_len;

            if (t_static) {
                const idx = r_idx.value;
                if (idx >= static_table.len) return error.InvalidStaticIndex;
                const e = &static_table[idx];
                out.headers[out.count] = .{ .name = e.name, .value = value };
                out.count += 1;
            } else {
                // Dynamic name reference.
                if (table) |tbl| {
                    const rel = r_idx.value;
                    if (base == 0 or rel >= base) return error.InvalidDynamicIndex;
                    const abs = base - 1 - rel;
                    const entry = tbl.getByAbsolute(abs) orelse return error.InvalidDynamicIndex;
                    out.headers[out.count] = .{ .name = entry.name(), .value = value };
                    out.count += 1;
                } else {
                    return error.Unsupported;
                }
            }
        } else if (first & 0x20 != 0) {
            // ---------------------------------------------------------------
            // Literal Field Line Without Name Reference (0b001xxxxx)
            // Bits: 0 0 1 N H NameLen(3+) Name H ValueLen(7+) Value
            // ---------------------------------------------------------------
            const r_nlen = decodeInteger(buf[pos..], 3) catch return error.BufferTooShort;
            pos += r_nlen.consumed;
            const name_len: usize = @intCast(r_nlen.value);
            if (pos + name_len > buf.len) return error.BufferTooShort;
            const name = buf[pos .. pos + name_len];
            pos += name_len;

            if (pos >= buf.len) return error.BufferTooShort;
            const r_vlen = decodeInteger(buf[pos..], 7) catch return error.BufferTooShort;
            pos += r_vlen.consumed;
            const val_len: usize = @intCast(r_vlen.value);
            if (pos + val_len > buf.len) return error.BufferTooShort;
            const value = buf[pos .. pos + val_len];
            pos += val_len;

            out.headers[out.count] = .{ .name = name, .value = value };
            out.count += 1;
        } else if (first & 0x10 != 0) {
            // ---------------------------------------------------------------
            // Indexed Field Line With Post-Base Index (0b0001xxxx)
            // Dynamic only; requires table != null.
            // ---------------------------------------------------------------
            const r = decodeInteger(buf[pos..], 4) catch return error.BufferTooShort;
            pos += r.consumed;
            if (table) |tbl| {
                const abs = base + r.value;
                const entry = tbl.getByAbsolute(abs) orelse return error.InvalidDynamicIndex;
                out.headers[out.count] = .{ .name = entry.name(), .value = entry.value() };
                out.count += 1;
            } else {
                return error.Unsupported;
            }
        } else {
            // ---------------------------------------------------------------
            // Literal Field Line With Post-Base Name Reference (0b0000xxxx)
            // Dynamic only; requires table != null.
            // Bits: 0 0 0 0 N PostBaseNameIdx(3+)
            // ---------------------------------------------------------------
            const r_idx = decodeInteger(buf[pos..], 3) catch return error.BufferTooShort;
            pos += r_idx.consumed;
            if (pos >= buf.len) return error.BufferTooShort;
            const r_vlen = decodeInteger(buf[pos..], 7) catch return error.BufferTooShort;
            pos += r_vlen.consumed;
            const val_len: usize = @intCast(r_vlen.value);
            if (pos + val_len > buf.len) return error.BufferTooShort;
            const value = buf[pos .. pos + val_len];
            pos += val_len;

            if (table) |tbl| {
                const abs = base + r_idx.value;
                const entry = tbl.getByAbsolute(abs) orelse return error.InvalidDynamicIndex;
                out.headers[out.count] = .{ .name = entry.name(), .value = value };
                out.count += 1;
            } else {
                return error.Unsupported;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Encoder stream instructions (RFC 9204 §3.2.4, §4.3)
// Written by the encoder to teach the decoder about new dynamic table entries.
// ---------------------------------------------------------------------------

/// Write a "Set Dynamic Table Capacity" instruction (RFC 9204 §3.2.3).
/// Format: 0 0 1 Capacity(5+)
pub fn writeSetCapacity(buf: []u8, capacity: usize) error{BufferTooSmall}!usize {
    return encodeInteger(buf, 5, 0x20, capacity);
}

/// Write an "Insert With Name Reference" instruction (RFC 9204 §4.3.1).
/// T=1 for static table name reference.
/// Format: 1 T NameIndex(6+) H ValueLen(7+) Value
pub fn writeInsertWithStaticNameRef(buf: []u8, static_idx: usize, value: []const u8) error{BufferTooSmall}!usize {
    var pos: usize = 0;
    // T=1: first byte flags = 0b11xxxxxx = 0xC0
    pos += try encodeInteger(buf[pos..], 6, 0xC0, static_idx);
    // Value: H=0, 7-bit prefix for length.
    pos += try encodeInteger(buf[pos..], 7, 0x00, value.len);
    if (pos + value.len > buf.len) return error.BufferTooSmall;
    @memcpy(buf[pos .. pos + value.len], value);
    pos += value.len;
    return pos;
}

/// Write an "Insert With Literal Name" instruction (RFC 9204 §4.3.2).
/// Format: 0 1 H NameLen(5+) Name H ValueLen(7+) Value
pub fn writeInsertWithLiteralName(buf: []u8, name: []const u8, value: []const u8) error{BufferTooSmall}!usize {
    var pos: usize = 0;
    // H=0 for name: flags = 0b01xxxxxx = 0x40
    pos += try encodeInteger(buf[pos..], 5, 0x40, name.len);
    if (pos + name.len > buf.len) return error.BufferTooSmall;
    @memcpy(buf[pos .. pos + name.len], name);
    pos += name.len;
    // Value: H=0
    pos += try encodeInteger(buf[pos..], 7, 0x00, value.len);
    if (pos + value.len > buf.len) return error.BufferTooSmall;
    @memcpy(buf[pos .. pos + value.len], value);
    pos += value.len;
    return pos;
}

/// Parse and apply one encoder stream instruction from `data` to `table`.
/// Returns the number of bytes consumed, or error.NeedMoreData if the buffer
/// is incomplete, or error.InvalidInstruction for malformed data.
pub fn processEncoderStreamInstruction(
    table: *DynamicTable,
    data: []const u8,
) error{ NeedMoreData, InvalidInstruction, EntryTooLarge, NameTooLong, ValueTooLong }!usize {
    if (data.len == 0) return error.NeedMoreData;
    const first = data[0];

    if (first & 0x80 != 0) {
        // ----------------------------------------------------------------
        // Insert With Name Reference (RFC 9204 §4.3.1): 1 T NameIdx(6+)
        // T=1: static name; T=0: dynamic name (relative to current head)
        // ----------------------------------------------------------------
        const t_static = (first & 0x40) != 0;
        const r_idx = decodeInteger(data, 6) catch return error.NeedMoreData;
        var pos = r_idx.consumed;
        if (pos >= data.len) return error.NeedMoreData;
        // Value: H=0 bit, 7-bit prefix length.
        const r_vlen = decodeInteger(data[pos..], 7) catch return error.NeedMoreData;
        pos += r_vlen.consumed;
        const val_len: usize = @intCast(r_vlen.value);
        if (pos + val_len > data.len) return error.NeedMoreData;
        const value = data[pos .. pos + val_len];
        pos += val_len;

        if (t_static) {
            const idx = r_idx.value;
            if (idx >= static_table.len) return error.InvalidInstruction;
            try table.insert(static_table[idx].name, value);
        } else {
            const rel = r_idx.value;
            const oldest = table.insertion_count - table.count;
            if (table.count == 0 or rel >= table.count) return error.InvalidInstruction;
            const abs = table.insertion_count - 1 - rel;
            _ = oldest;
            const entry = table.getByAbsolute(abs) orelse return error.InvalidInstruction;
            // We need to copy name before inserting (insert may evict entry).
            var name_buf: [MAX_DYN_ENTRY_BYTES]u8 = undefined;
            const name_bytes = entry.name();
            if (name_bytes.len > MAX_DYN_ENTRY_BYTES) return error.NameTooLong;
            @memcpy(name_buf[0..name_bytes.len], name_bytes);
            try table.insert(name_buf[0..name_bytes.len], value);
        }
        return pos;
    } else if (first & 0x40 != 0) {
        // ----------------------------------------------------------------
        // Insert With Literal Name (RFC 9204 §4.3.2): 0 1 H NameLen(5+)
        // ----------------------------------------------------------------
        const r_nlen = decodeInteger(data, 5) catch return error.NeedMoreData;
        var pos = r_nlen.consumed;
        const name_len: usize = @intCast(r_nlen.value);
        if (pos + name_len > data.len) return error.NeedMoreData;
        const name_bytes = data[pos .. pos + name_len];
        pos += name_len;
        if (pos >= data.len) return error.NeedMoreData;
        const r_vlen = decodeInteger(data[pos..], 7) catch return error.NeedMoreData;
        pos += r_vlen.consumed;
        const val_len: usize = @intCast(r_vlen.value);
        if (pos + val_len > data.len) return error.NeedMoreData;
        const value = data[pos .. pos + val_len];
        pos += val_len;
        try table.insert(name_bytes, value);
        return pos;
    } else if (first & 0x20 != 0) {
        // ----------------------------------------------------------------
        // Set Dynamic Table Capacity (RFC 9204 §3.2.3): 0 0 1 Capacity(5+)
        // ----------------------------------------------------------------
        const r = decodeInteger(data, 5) catch return error.NeedMoreData;
        table.setCapacity(@intCast(r.value));
        return r.consumed;
    } else {
        return error.InvalidInstruction;
    }
}

// ---------------------------------------------------------------------------
// Header block prefix helpers
// ---------------------------------------------------------------------------

/// Returns true when the QPACK header block's Required Insert Count is > 0,
/// meaning at least one field references the dynamic table.
///
/// RFC 9204 §4.5.1: the first byte of the block is the encoded Required Insert
/// Count.  When RIC = 0 the encoded value is 0x00; any other first byte means
/// RIC > 0.
pub fn headerBlockHasDynamicRefs(buf: []const u8) bool {
    return buf.len > 0 and buf[0] != 0x00;
}

// ---------------------------------------------------------------------------
// Decoder stream instructions (RFC 9204 §4.4)
// Written by the decoder back to the encoder: Section Acks, ICIs, Cancellations.
// ---------------------------------------------------------------------------

/// Write a Section Acknowledgement (RFC 9204 §4.4.1): 1 StreamID(7+)
pub fn writeSectionAck(buf: []u8, stream_id: u64) error{BufferTooSmall}!usize {
    return encodeInteger(buf, 7, 0x80, stream_id);
}

/// Write an Insert Count Increment (RFC 9204 §4.4.3): 0 0 Increment(6+)
pub fn writeInsertCountIncrement(buf: []u8, increment: usize) error{BufferTooSmall}!usize {
    return encodeInteger(buf, 6, 0x00, increment);
}

/// Write a Stream Cancellation (RFC 9204 §4.4.2): 0 1 StreamID(6+)
pub fn writeStreamCancellation(buf: []u8, stream_id: u64) error{BufferTooSmall}!usize {
    return encodeInteger(buf, 6, 0x40, stream_id);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "qpack: static table has correct entries" {
    try std.testing.expectEqualSlices(u8, ":method", static_table[17].name);
    try std.testing.expectEqualSlices(u8, "GET", static_table[17].value);
    try std.testing.expectEqualSlices(u8, ":status", static_table[25].name);
    try std.testing.expectEqualSlices(u8, "200", static_table[25].value);
}

test "qpack: encodeInteger single-byte small values" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    // 6-bit prefix: values 0-62 fit in one byte
    try testing.expectEqual(@as(usize, 1), try encodeInteger(&buf, 6, 0xC0, 0));
    try testing.expectEqual(@as(u8, 0xC0), buf[0]);
    try testing.expectEqual(@as(usize, 1), try encodeInteger(&buf, 6, 0xC0, 17));
    try testing.expectEqual(@as(u8, 0xD1), buf[0]);
    try testing.expectEqual(@as(usize, 1), try encodeInteger(&buf, 6, 0xC0, 62));
    try testing.expectEqual(@as(u8, 0xFE), buf[0]);
}

test "qpack: encodeInteger multi-byte" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    // 6-bit prefix: value 63 requires two bytes (0xFF, 0x00)
    const n = try encodeInteger(&buf, 6, 0xC0, 63);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqual(@as(u8, 0xFF), buf[0]); // 0xC0 | 63 = 0xFF
    try testing.expectEqual(@as(u8, 0x00), buf[1]); // remainder = 0
    // Value 200: prefix=6, max=63; 200-63=137=1*128+9; bytes: 0xFF, 0x89, 0x01
    const n2 = try encodeInteger(&buf, 6, 0xC0, 200);
    try testing.expectEqual(@as(usize, 3), n2);
}

test "qpack: decodeInteger round-trip" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    for ([_]u64{ 0, 1, 62, 63, 64, 127, 128, 200, 1000, 16383, 16384 }) |v| {
        const written = try encodeInteger(&buf, 6, 0xC0, v);
        const r = try decodeInteger(buf[0..written], 6);
        try testing.expectEqual(v, r.value);
        try testing.expectEqual(written, r.consumed);
    }
}

test "qpack: encodeHeaders literal-only (no static lookup)" {
    const testing = std.testing;
    const headers_in = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/index.html" },
    };
    var buf: [256]u8 = undefined;
    const written = try encodeHeaders(&headers_in, &buf, .{ .use_static_index = false });
    // First two bytes: RIC=0, base=0
    try testing.expectEqual(@as(u8, 0x00), buf[0]);
    try testing.expectEqual(@as(u8, 0x00), buf[1]);
    // Third byte: literal without name ref prefix 0x20 | (name_len & mask)
    try testing.expectEqual(@as(u8, 0x20 | 7), buf[2]); // name_len=7, 3-bit prefix ≤ 7 fits
    try testing.expect(written > 10);
}

test "qpack: encode :method GET as static index" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    const written = try encodeHeaders(&[_]Header{
        .{ .name = ":method", .value = "GET" },
    }, &buf, .{});
    // Prefix 2 bytes, then 1-byte indexed field line: 0xC0 | 17 = 0xD1
    try testing.expectEqual(@as(usize, 3), written);
    try testing.expectEqual(@as(u8, 0x00), buf[0]);
    try testing.expectEqual(@as(u8, 0x00), buf[1]);
    try testing.expectEqual(@as(u8, 0xC0 | 17), buf[2]); // index 17 = :method GET
}

test "qpack: encode :status 200 as static index" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    const written = try encodeHeaders(&[_]Header{
        .{ .name = ":status", .value = "200" },
    }, &buf, .{});
    try testing.expectEqual(@as(usize, 3), written);
    try testing.expectEqual(@as(u8, 0xC0 | 25), buf[2]); // index 25 = :status 200
}

test "qpack: encode literal-with-static-name-ref for unknown value" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    // :status 999 — name found (index 24 is :status 103, but any :status idx works),
    // value not found → literal with static name ref.
    const written = try encodeHeaders(&[_]Header{
        .{ .name = ":status", .value = "999" },
    }, &buf, .{});
    // Should be: 2-byte prefix + literal-with-name-ref bytes (> 3 total)
    try testing.expect(written > 3);
    // First field byte: 0b01xxxxxx = 0x40..0x7F
    try testing.expect(buf[2] & 0x40 != 0);
    try testing.expect(buf[2] & 0x80 == 0);
}

test "qpack: decode indexed static :method GET" {
    const testing = std.testing;
    // Manually craft: RIC=0, base=0, then 0xD1 (indexed static 17)
    const raw = [_]u8{ 0x00, 0x00, 0xD1 };
    var decoded = DecodedHeaders{ .headers = undefined, .count = 0 };
    try decodeHeaders(&raw, null, &decoded);
    try testing.expectEqual(@as(usize, 1), decoded.count);
    try testing.expectEqualSlices(u8, ":method", decoded.headers[0].name);
    try testing.expectEqualSlices(u8, "GET", decoded.headers[0].value);
}

test "qpack: decode indexed static :status 200" {
    const testing = std.testing;
    const raw = [_]u8{ 0x00, 0x00, 0xC0 | 25 };
    var decoded = DecodedHeaders{ .headers = undefined, .count = 0 };
    try decodeHeaders(&raw, null, &decoded);
    try testing.expectEqual(@as(usize, 1), decoded.count);
    try testing.expectEqualSlices(u8, ":status", decoded.headers[0].name);
    try testing.expectEqualSlices(u8, "200", decoded.headers[0].value);
}

test "qpack: decode literal-with-static-name-ref" {
    const testing = std.testing;
    // Encode a header with static name ref and decode it.
    var buf: [64]u8 = undefined;
    // Write prefix + literal-with-static-name-ref for :status "999"
    var pos: usize = 2;
    buf[0] = 0x00;
    buf[1] = 0x00;
    pos += try encodeLiteralWithStaticNameRef(buf[pos..], 24, "999"); // 24 = :status 103 (name match)
    var decoded = DecodedHeaders{ .headers = undefined, .count = 0 };
    try decodeHeaders(buf[0..pos], null, &decoded);
    try testing.expectEqual(@as(usize, 1), decoded.count);
    try testing.expectEqualSlices(u8, ":status", decoded.headers[0].name);
    try testing.expectEqualSlices(u8, "999", decoded.headers[0].value);
}

test "qpack: encode/decode static-indexed round-trip for common request headers" {
    const testing = std.testing;
    const headers_in = [_]Header{
        .{ .name = ":method", .value = "GET" }, // static idx 17
        .{ .name = ":path", .value = "/" }, // static idx 1
        .{ .name = ":scheme", .value = "https" }, // static idx 23
        .{ .name = ":authority", .value = "example.com" }, // static name ref (idx 0)
    };
    var buf: [256]u8 = undefined;
    const written = try encodeHeaders(&headers_in, &buf, .{});
    // :method GET  → 1 byte (indexed)
    // :path /      → 1 byte (indexed)
    // :scheme https→ 1 byte (indexed)
    // :authority   → literal-with-static-name-ref (name idx 0, value "example.com")
    // Total: 2 (prefix) + 1 + 1 + 1 + (1 + 11 + 1) ≈ 18 bytes  (far less than literal-only)
    try testing.expect(written < 30);

    var decoded = DecodedHeaders{ .headers = undefined, .count = 0 };
    try decodeHeaders(buf[0..written], null, &decoded);
    try testing.expectEqual(@as(usize, 4), decoded.count);
    try testing.expectEqualSlices(u8, ":method", decoded.headers[0].name);
    try testing.expectEqualSlices(u8, "GET", decoded.headers[0].value);
    try testing.expectEqualSlices(u8, ":path", decoded.headers[1].name);
    try testing.expectEqualSlices(u8, "/", decoded.headers[1].value);
    try testing.expectEqualSlices(u8, ":scheme", decoded.headers[2].name);
    try testing.expectEqualSlices(u8, "https", decoded.headers[2].value);
    try testing.expectEqualSlices(u8, ":authority", decoded.headers[3].name);
    try testing.expectEqualSlices(u8, "example.com", decoded.headers[3].value);
}

test "qpack: decode interleaved static-indexed and literal fields" {
    const testing = std.testing;
    const headers_in = [_]Header{
        .{ .name = ":method", .value = "GET" }, // will be indexed
        .{ .name = "x-custom", .value = "value" }, // will be literal (not in static table)
        .{ .name = ":status", .value = "200" }, // will be indexed
    };
    var buf: [256]u8 = undefined;
    const written = try encodeHeaders(&headers_in, &buf, .{});
    var decoded = DecodedHeaders{ .headers = undefined, .count = 0 };
    try decodeHeaders(buf[0..written], null, &decoded);
    try testing.expectEqual(@as(usize, 3), decoded.count);
    try testing.expectEqualSlices(u8, ":method", decoded.headers[0].name);
    try testing.expectEqualSlices(u8, "GET", decoded.headers[0].value);
    try testing.expectEqualSlices(u8, "x-custom", decoded.headers[1].name);
    try testing.expectEqualSlices(u8, "value", decoded.headers[1].value);
    try testing.expectEqualSlices(u8, ":status", decoded.headers[2].name);
    try testing.expectEqualSlices(u8, "200", decoded.headers[2].value);
}

test "qpack: encode/decode round-trip (literal-only)" {
    const testing = std.testing;
    const headers_in = [_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/index.html" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    };
    var buf: [256]u8 = undefined;
    const written = try encodeHeaders(&headers_in, &buf, .{ .use_static_index = false });
    var decoded = DecodedHeaders{ .headers = undefined, .count = 0 };
    try decodeHeaders(buf[0..written], null, &decoded);
    try testing.expectEqual(@as(usize, 4), decoded.count);
    try testing.expectEqualSlices(u8, ":method", decoded.headers[0].name);
    try testing.expectEqualSlices(u8, "GET", decoded.headers[0].value);
    try testing.expectEqualSlices(u8, ":path", decoded.headers[1].name);
    try testing.expectEqualSlices(u8, "/index.html", decoded.headers[1].value);
    try testing.expectEqualSlices(u8, ":authority", decoded.headers[3].name);
    try testing.expectEqualSlices(u8, "example.com", decoded.headers[3].value);
}

test "qpack: empty header list" {
    const testing = std.testing;
    var buf: [8]u8 = undefined;
    const written = try encodeHeaders(&.{}, &buf, .{});
    var decoded = DecodedHeaders{ .headers = undefined, .count = 0 };
    try decodeHeaders(buf[0..written], null, &decoded);
    try testing.expectEqual(@as(usize, 0), decoded.count);
}

test "qpack: non-zero RIC with null table returns BlockedStream" {
    const testing = std.testing;
    // Craft a header block with encoded_ric = 1 (non-zero, requires dynamic table)
    const raw = [_]u8{ 0x01, 0x00 }; // encoded_ric=1, S=0, delta=0
    var decoded = DecodedHeaders{ .headers = undefined, .count = 0 };
    const result = decodeHeaders(&raw, null, &decoded);
    try testing.expectError(error.BlockedStream, result);
}

// --- Dynamic table tests ---

test "qpack dynamic table: insert and lookup by absolute index" {
    const testing = std.testing;
    var tbl = DynamicTable{};
    tbl.capacity = 4096;
    try tbl.insert("x-foo", "bar");
    try tbl.insert("x-baz", "qux");
    try testing.expectEqual(@as(usize, 2), tbl.count);
    try testing.expectEqual(@as(usize, 2), tbl.insertion_count);
    const e0 = tbl.getByAbsolute(0).?;
    try testing.expectEqualSlices(u8, "x-foo", e0.name());
    try testing.expectEqualSlices(u8, "bar", e0.value());
    const e1 = tbl.getByAbsolute(1).?;
    try testing.expectEqualSlices(u8, "x-baz", e1.name());
    try testing.expectEqualSlices(u8, "qux", e1.value());
    try testing.expect(tbl.getByAbsolute(2) == null);
}

test "qpack dynamic table: eviction when capacity exceeded" {
    const testing = std.testing;
    var tbl = DynamicTable{};
    // Set capacity to exactly hold 2 entries of wire size 32+5+3=40 each → 80 bytes.
    tbl.capacity = 80;
    try tbl.insert("x-foo", "bar"); // wire size = 5+3+32 = 40
    try tbl.insert("x-baz", "qux"); // wire size = 5+3+32 = 40; total = 80
    try testing.expectEqual(@as(usize, 2), tbl.count);
    // Insert third entry (40 bytes): evicts first entry.
    try tbl.insert("x-qux", "val"); // wire size = 5+3+32 = 40
    try testing.expectEqual(@as(usize, 2), tbl.count); // oldest evicted
    try testing.expectEqual(@as(usize, 3), tbl.insertion_count);
    // Absolute index 0 (first entry) is no longer accessible.
    try testing.expect(tbl.getByAbsolute(0) == null);
    try testing.expect(tbl.getByAbsolute(1) != null);
    try testing.expect(tbl.getByAbsolute(2) != null);
}

test "qpack dynamic table: findExact and findName" {
    const testing = std.testing;
    var tbl = DynamicTable{};
    tbl.capacity = 4096;
    try tbl.insert("x-foo", "bar");
    try tbl.insert("x-foo", "baz");
    // findExact: exact match
    try testing.expectEqual(@as(?usize, 0), tbl.findExact("x-foo", "bar"));
    try testing.expectEqual(@as(?usize, 1), tbl.findExact("x-foo", "baz"));
    try testing.expectEqual(@as(?usize, null), tbl.findExact("x-foo", "other"));
    // findName: newest-first, so returns abs=1
    try testing.expectEqual(@as(?usize, 1), tbl.findName("x-foo"));
    try testing.expectEqual(@as(?usize, null), tbl.findName("x-other"));
}

test "qpack dynamic table: EntryTooLarge" {
    const testing = std.testing;
    var tbl = DynamicTable{};
    tbl.capacity = 20; // less than 32 (minimum wire size)
    const result = tbl.insert("a", "b"); // wire size = 1+1+32 = 34 > 20
    try testing.expectError(error.EntryTooLarge, result);
}

test "qpack dynamic table: setCapacity evicts entries" {
    const testing = std.testing;
    var tbl = DynamicTable{};
    tbl.capacity = 4096;
    try tbl.insert("x-foo", "bar"); // wire size = 40
    try tbl.insert("x-baz", "qux"); // wire size = 40
    try testing.expectEqual(@as(usize, 2), tbl.count);
    // Shrink capacity to only hold one entry.
    tbl.setCapacity(40);
    try testing.expectEqual(@as(usize, 1), tbl.count);
    // Oldest (abs=0) should be evicted.
    try testing.expect(tbl.getByAbsolute(0) == null);
    try testing.expect(tbl.getByAbsolute(1) != null);
}

test "qpack dynamic table: maxEntries" {
    const testing = std.testing;
    var tbl = DynamicTable{};
    tbl.capacity = 4096;
    try testing.expectEqual(@as(usize, 128), tbl.maxEntries()); // 4096 / 32 = 128
    tbl.capacity = 0;
    try testing.expectEqual(@as(usize, 0), tbl.maxEntries());
}

// --- Encoder stream instruction tests ---

test "qpack encoder stream: Set Dynamic Table Capacity" {
    const testing = std.testing;
    var buf: [8]u8 = undefined;
    const n = try writeSetCapacity(&buf, 4096);
    var tbl = DynamicTable{};
    const consumed = try processEncoderStreamInstruction(&tbl, buf[0..n]);
    try testing.expectEqual(n, consumed);
    try testing.expectEqual(@as(usize, 4096), tbl.capacity);
}

test "qpack encoder stream: Insert With Static Name Ref" {
    const testing = std.testing;
    var buf: [32]u8 = undefined;
    const n = try writeInsertWithStaticNameRef(&buf, 17, "value"); // static idx 17 = :method GET name
    var tbl = DynamicTable{};
    tbl.capacity = 4096;
    const consumed = try processEncoderStreamInstruction(&tbl, buf[0..n]);
    try testing.expectEqual(n, consumed);
    try testing.expectEqual(@as(usize, 1), tbl.count);
    const e = tbl.getByAbsolute(0).?;
    try testing.expectEqualSlices(u8, ":method", e.name()); // static_table[17].name = ":method"
    try testing.expectEqualSlices(u8, "value", e.value());
}

test "qpack encoder stream: Insert With Literal Name" {
    const testing = std.testing;
    var buf: [32]u8 = undefined;
    const n = try writeInsertWithLiteralName(&buf, "x-custom", "hello");
    var tbl = DynamicTable{};
    tbl.capacity = 4096;
    const consumed = try processEncoderStreamInstruction(&tbl, buf[0..n]);
    try testing.expectEqual(n, consumed);
    try testing.expectEqual(@as(usize, 1), tbl.count);
    const e = tbl.getByAbsolute(0).?;
    try testing.expectEqualSlices(u8, "x-custom", e.name());
    try testing.expectEqualSlices(u8, "hello", e.value());
}

test "qpack encoder stream: multiple instructions in one buffer" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    pos += try writeSetCapacity(buf[pos..], 4096);
    pos += try writeInsertWithLiteralName(buf[pos..], "x-a", "1");
    pos += try writeInsertWithLiteralName(buf[pos..], "x-b", "2");
    var tbl = DynamicTable{};
    var off: usize = 0;
    while (off < pos) {
        const consumed = try processEncoderStreamInstruction(&tbl, buf[off..pos]);
        off += consumed;
    }
    try testing.expectEqual(@as(usize, 4096), tbl.capacity);
    try testing.expectEqual(@as(usize, 2), tbl.count);
}

test "qpack encoder stream: NeedMoreData on partial buffer" {
    const testing = std.testing;
    var buf: [32]u8 = undefined;
    const n = try writeInsertWithLiteralName(&buf, "x-custom", "hello");
    var tbl = DynamicTable{};
    tbl.capacity = 4096;
    // Supply only part of the instruction — should get NeedMoreData.
    const result = processEncoderStreamInstruction(&tbl, buf[0 .. n - 1]);
    try testing.expectError(error.NeedMoreData, result);
}

// --- Decoder stream instruction tests ---

test "qpack decoder stream: Section Acknowledgement" {
    const testing = std.testing;
    var buf: [8]u8 = undefined;
    const n = try writeSectionAck(&buf, 4);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u8, 0x80 | 4), buf[0]);
}

test "qpack decoder stream: Insert Count Increment" {
    const testing = std.testing;
    var buf: [8]u8 = undefined;
    const n = try writeInsertCountIncrement(&buf, 3);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u8, 3), buf[0]);
}

test "qpack decoder stream: Stream Cancellation" {
    const testing = std.testing;
    var buf: [8]u8 = undefined;
    const n = try writeStreamCancellation(&buf, 4);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u8, 0x40 | 4), buf[0]);
}

// --- Dynamic encode+decode round-trip with dynamic table ---

test "qpack: headerBlockHasDynamicRefs" {
    const testing = std.testing;
    // RIC = 0: both prefix bytes are 0x00.
    try testing.expect(!headerBlockHasDynamicRefs(&[_]u8{ 0x00, 0x00 }));
    // Empty slice.
    try testing.expect(!headerBlockHasDynamicRefs(&[_]u8{}));
    // RIC > 0: first byte is encoded_ric = (ric % (2*maxEntries)) + 1 >= 1.
    try testing.expect(headerBlockHasDynamicRefs(&[_]u8{ 0x02, 0x00 }));
    try testing.expect(headerBlockHasDynamicRefs(&[_]u8{ 0x01, 0x00 }));
}

test "qpack: headerBlockHasDynamicRefs from encoded block" {
    const testing = std.testing;
    // A block with no dynamic refs (static-only encoding) must report false.
    var buf: [64]u8 = undefined;
    const written = try encodeHeaders(&[_]Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
    }, &buf, .{});
    try testing.expect(!headerBlockHasDynamicRefs(buf[0..written]));

    // A block encoded with a dynamic table reference must report true.
    var tbl = DynamicTable{};
    tbl.capacity = 4096;
    try tbl.insert(":status", "200");
    const w2 = try encodeHeaders(&[_]Header{
        .{ .name = ":status", .value = "200" },
    }, &buf, .{ .table = &tbl });
    try testing.expect(headerBlockHasDynamicRefs(buf[0..w2]));
}

test "qpack: dynamic table encode/decode round-trip" {
    const testing = std.testing;
    // Simulate encoder and decoder sharing the same table state.
    var enc_tbl = DynamicTable{};
    enc_tbl.capacity = 4096;
    try enc_tbl.insert("x-custom", "myvalue");

    var dec_tbl = DynamicTable{};
    dec_tbl.capacity = 4096;
    try dec_tbl.insert("x-custom", "myvalue"); // decoder applies same insertion

    var buf: [64]u8 = undefined;
    // Encode using dynamic table (exact match at absolute index 0)
    const written = try encodeHeaders(&[_]Header{
        .{ .name = "x-custom", .value = "myvalue" },
    }, &buf, .{ .table = &enc_tbl });

    // Decode with the decoder's table
    var decoded = DecodedHeaders{ .headers = undefined, .count = 0 };
    try decodeHeaders(buf[0..written], &dec_tbl, &decoded);
    try testing.expectEqual(@as(usize, 1), decoded.count);
    try testing.expectEqualSlices(u8, "x-custom", decoded.headers[0].name);
    try testing.expectEqualSlices(u8, "myvalue", decoded.headers[0].value);
}

// --- Blocked stream tests (RFC 9204 §2.1.2) ---

test "qpack: decodeHeaders returns BlockedStream when decoder table is empty" {
    const testing = std.testing;

    // Encode a HEADERS block that references a dynamic table entry.
    var enc_tbl = DynamicTable{};
    enc_tbl.capacity = 4096;
    try enc_tbl.insert(":status", "200");

    var buf: [64]u8 = undefined;
    const written = try encodeHeaders(&[_]Header{
        .{ .name = ":status", .value = "200" },
    }, &buf, .{ .table = &enc_tbl });

    // A decoder table with no insertions cannot satisfy RIC=1 — must block.
    var dec_tbl = DynamicTable{};
    dec_tbl.capacity = 4096;
    var out = DecodedHeaders{ .headers = undefined, .count = 0 };
    const result = decodeHeaders(buf[0..written], &dec_tbl, &out);
    try testing.expectError(error.BlockedStream, result);
}

test "qpack: decodeHeaders succeeds after decoder table catches up" {
    const testing = std.testing;

    // Encoder inserts ":custom: value", then encodes a HEADERS block using it.
    var enc_tbl = DynamicTable{};
    enc_tbl.capacity = 4096;
    try enc_tbl.insert(":custom", "value");

    var buf: [64]u8 = undefined;
    const written = try encodeHeaders(&[_]Header{
        .{ .name = ":custom", .value = "value" },
    }, &buf, .{ .table = &enc_tbl });

    // Simulated decoder table with no entries yet → stream is blocked.
    var dec_tbl = DynamicTable{};
    dec_tbl.capacity = 4096;
    var out = DecodedHeaders{ .headers = undefined, .count = 0 };
    try testing.expectError(error.BlockedStream, decodeHeaders(buf[0..written], &dec_tbl, &out));

    // Simulate receiving encoder-stream instruction: decoder applies same insertion.
    try dec_tbl.insert(":custom", "value");

    // Now the decoder table has insertion_count=1 which satisfies RIC=1.
    out = DecodedHeaders{ .headers = undefined, .count = 0 };
    try decodeHeaders(buf[0..written], &dec_tbl, &out);
    try testing.expectEqual(@as(usize, 1), out.count);
    try testing.expectEqualSlices(u8, ":custom", out.headers[0].name);
    try testing.expectEqualSlices(u8, "value", out.headers[0].value);
}
