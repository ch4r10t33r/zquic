//! Crypto path microbenchmark.
//!
//! Measures the throughput of the two most-changed hot paths:
//!
//!   Path A — HP mask computation + AAD copy (improvements #1 and #2):
//!     OLD: 2× Aes128.initEnc + 2× encrypt + 1600-byte memcpy per packet
//!     NEW: 1× Aes128.initEnc + 1× encrypt +   32-byte memcpy per packet
//!
//!   Path B — Full 1-RTT packet decrypt (AES-128-GCM):
//!     Measures end-to-end decrypt throughput in MB/s.
//!
//! Run:
//!   zig build bench            (ReleaseFast, recommended)
//!   zig build bench -Ddebug    (Debug, shows absolute overhead)

const std = @import("std");
const crypto = std.crypto;
const Aes128 = crypto.core.aes.Aes128;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;

// ── Benchmark harness ────────────────────────────────────────────────────────

const WARMUP = 50_000;
const ITERS = 500_000;

const Result = struct {
    ns_per_op: f64,
    ops_per_sec: f64,
    mb_per_sec: f64, // assuming 1200-byte packet

    fn print(self: Result, label: []const u8) void {
        std.debug.print(
            "  {s:<42} {d:>8.1} ns/op   {d:>9.0} ops/s   {d:>8.1} MB/s\n",
            .{ label, self.ns_per_op, self.ops_per_sec, self.mb_per_sec },
        );
    }
};

fn bench(comptime func: fn () void, packet_bytes: usize) Result {
    // Warmup
    var i: usize = 0;
    while (i < WARMUP) : (i += 1) func();

    // Timed run
    var timer = std.time.Timer.start() catch unreachable;
    i = 0;
    while (i < ITERS) : (i += 1) func();
    const elapsed_ns = timer.read();

    const ns_per_op = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(ITERS));
    const ops_per_sec = 1e9 / ns_per_op;
    const mb_per_sec = ops_per_sec * @as(f64, @floatFromInt(packet_bytes)) / (1024.0 * 1024.0);
    return .{ .ns_per_op = ns_per_op, .ops_per_sec = ops_per_sec, .mb_per_sec = mb_per_sec };
}

// ── Shared test fixtures ─────────────────────────────────────────────────────

// A realistic 1-RTT short-header packet (1 + 8-byte DCID + 1-byte PN + payload).
// pn_start = 9 (1 first-byte + 8 DCID bytes).
const PKT_LEN = 1200;
const PN_START = 9;
// Initialized at runtime in main() via initFakePacket().
var fake_packet: [PKT_LEN]u8 = [_]u8{0} ** PKT_LEN;

fn initFakePacket() void {
    fake_packet[0] = 0x40; // short header, fixed bit set, 1-byte PN
    var j: usize = 1;
    while (j < 9) : (j += 1) fake_packet[j] = @as(u8, @intCast(j * 3));
    while (j < PKT_LEN) : (j += 1) fake_packet[j] = @as(u8, @intCast(j & 0xff));
}

const hp_key: [16]u8 = .{
    0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
    0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
};

// ── Benchmark A1: OLD HP mask path (2× AES initEnc + encrypt) ───────────────

fn benchOldHpMask() void {
    const pn_start = PN_START;
    const sample_start = pn_start + 4; // hp_sample_offset = 4
    var sample: [16]u8 = undefined;
    @memcpy(&sample, fake_packet[sample_start .. sample_start + 16]);

    // Call 1: unmask first byte
    {
        const aes = Aes128.initEnc(hp_key);
        var mask: [16]u8 = undefined;
        aes.encrypt(&mask, &sample);
        _ = mask[0]; // use result
    }
    // Call 2: unmask PN bytes (identical computation — this is the redundancy)
    {
        const aes = Aes128.initEnc(hp_key);
        var mask: [16]u8 = undefined;
        aes.encrypt(&mask, &sample);
        _ = mask[1]; // use result
    }
    // Old full-packet copy
    var header_copy: [1600]u8 = undefined;
    @memcpy(header_copy[0..PKT_LEN], &fake_packet);
    std.mem.doNotOptimizeAway(&header_copy);
}

// ── Benchmark A2: NEW HP mask path (1× AES initEnc + encrypt + 32B copy) ───

fn benchNewHpMask() void {
    const pn_start = PN_START;
    const sample_start = pn_start + 4;
    var sample: [16]u8 = undefined;
    @memcpy(&sample, fake_packet[sample_start .. sample_start + 16]);

    // Single mask computation
    const aes = Aes128.initEnc(hp_key);
    var mask: [16]u8 = undefined;
    aes.encrypt(&mask, &sample);

    // Small AAD copy (25 bytes max instead of 1600)
    const aad_end = pn_start + 1; // 1-byte PN
    var aad_buf: [32]u8 = undefined;
    @memcpy(aad_buf[0..aad_end], fake_packet[0..aad_end]);
    aad_buf[0] ^= mask[0] & 0x1f;
    aad_buf[pn_start] ^= mask[1];
    std.mem.doNotOptimizeAway(&aad_buf);
}

// ── Benchmark B: AES-128-GCM full packet decrypt ─────────────────────────────

const aes_key: [16]u8 = .{
    0x17, 0x26, 0x35, 0x44, 0x53, 0x62, 0x71, 0x80,
    0x8f, 0x9e, 0xad, 0xbc, 0xcb, 0xda, 0xe9, 0xf8,
};
const aes_iv: [12]u8 = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };

// Pre-encrypt a packet once so we have a valid ciphertext to decrypt.
var ciphertext_buf: [PKT_LEN + 16]u8 = undefined;
var aad_for_gcm: [25]u8 = [_]u8{0xab} ** 25;
var plaintext_buf: [PKT_LEN]u8 = undefined;
var ct_ready = false;

fn ensureCiphertext() void {
    if (ct_ready) return;
    var pt: [PKT_LEN]u8 = undefined;
    for (&pt, 0..) |*b, i| b.* = @as(u8, @intCast(i & 0xff));
    var tag: [16]u8 = undefined;
    Aes128Gcm.encrypt(ciphertext_buf[0..PKT_LEN], &tag, &pt, &aad_for_gcm, aes_iv, aes_key);
    @memcpy(ciphertext_buf[PKT_LEN..], &tag);
    ct_ready = true;
}

fn benchAesGcmDecrypt() void {
    Aes128Gcm.decrypt(
        &plaintext_buf,
        ciphertext_buf[0..PKT_LEN],
        ciphertext_buf[PKT_LEN..][0..16].*,
        &aad_for_gcm,
        aes_iv,
        aes_key,
    ) catch {};
    std.mem.doNotOptimizeAway(&plaintext_buf);
}

// ── Benchmark C: memcpy cost comparison ──────────────────────────────────────

fn benchMemcpy1600() void {
    var dst: [1600]u8 = undefined;
    @memcpy(dst[0..PKT_LEN], &fake_packet);
    std.mem.doNotOptimizeAway(&dst);
}

fn benchMemcpy32() void {
    var dst: [32]u8 = undefined;
    @memcpy(&dst, fake_packet[0..32]);
    std.mem.doNotOptimizeAway(&dst);
}

// ── Main ─────────────────────────────────────────────────────────────────────

pub fn main() !void {
    initFakePacket();
    ensureCiphertext();

    std.debug.print("\n=== zquic crypto path benchmark ({d} iterations) ===\n\n", .{ITERS});

    std.debug.print("A. HP mask computation (per received 1-RTT packet)\n", .{});
    std.debug.print("   Simulates the header-protection removal on a {d}-byte packet.\n\n", .{PKT_LEN});
    const old_hp = bench(benchOldHpMask, PKT_LEN);
    const new_hp = bench(benchNewHpMask, PKT_LEN);
    old_hp.print("OLD: 2× AES initEnc + 1600B copy");
    new_hp.print("NEW: 1× AES initEnc +   32B copy");
    std.debug.print("   Speedup: {d:.1}×\n\n", .{old_hp.ns_per_op / new_hp.ns_per_op});

    std.debug.print("B. AES-128-GCM decrypt ({d}-byte payload)\n", .{PKT_LEN});
    std.debug.print("   Baseline throughput of the AEAD cipher itself.\n\n", .{});
    const gcm = bench(benchAesGcmDecrypt, PKT_LEN);
    gcm.print("AES-128-GCM decrypt");
    std.debug.print("\n", .{});

    std.debug.print("C. memcpy cost (raw copy overhead)\n\n", .{});
    const cp1600 = bench(benchMemcpy1600, PKT_LEN);
    const cp32 = bench(benchMemcpy32, PKT_LEN);
    cp1600.print("memcpy 1600 bytes (old header_copy)");
    cp32.print("memcpy   32 bytes (new aad_buf)");
    std.debug.print("   Speedup: {d:.1}×\n\n", .{cp1600.ns_per_op / cp32.ns_per_op});

    std.debug.print("D. Theoretical packet-receive throughput ceiling\n\n", .{});
    // The bottleneck is the slowest of: HP mask + AEAD
    const hp_limited = new_hp.mb_per_sec;
    const gcm_limited = gcm.mb_per_sec;
    std.debug.print("   HP mask limited:      {d:.0} MB/s\n", .{hp_limited});
    std.debug.print("   AES-GCM limited:      {d:.0} MB/s\n", .{gcm_limited});
    std.debug.print("   Combined ceiling:     {d:.0} MB/s  ({d:.0} Gbps)\n\n", .{
        @min(hp_limited, gcm_limited),
        @min(hp_limited, gcm_limited) * 8.0 / 1024.0,
    });
}
