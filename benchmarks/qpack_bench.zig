//! QPACK header encoding microbenchmark.
//!
//! Measures encodeHeaders throughput, which exercises the two static-table
//! lookup paths:
//!   - findStaticEntry: O(1) perfect-hash lookup (was O(N=100) linear scan)
//!   - findStaticName:  O(1) perfect-hash lookup (was O(N=100) linear scan)
//!
//! Benchmark C encodes a 7-header GET block in a tight loop, giving a
//! realistic measure of the full encode path including both lookup functions.
//!
//! Run:
//!   zig build bench-qpack          (ReleaseFast, recommended)

const std = @import("std");
const qpack = @import("zquic").http3.qpack;

// ── Benchmark harness ────────────────────────────────────────────────────────

const WARMUP = 100_000;
const ITERS = 1_000_000;

const Result = struct {
    ns_per_op: f64,
    ops_per_sec: f64,

    fn print(self: Result, label: []const u8) void {
        std.debug.print(
            "  {s:<52} {d:>8.1} ns/op   {d:>10.0} ops/s\n",
            .{ label, self.ns_per_op, self.ops_per_sec },
        );
    }
};

fn bench(comptime func: fn () void) Result {
    var i: usize = 0;
    while (i < WARMUP) : (i += 1) func();

    var timer = std.time.Timer.start() catch unreachable;
    i = 0;
    while (i < ITERS) : (i += 1) func();
    const elapsed_ns = timer.read();

    const ns_per_op = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(ITERS));
    return .{ .ns_per_op = ns_per_op, .ops_per_sec = 1e9 / ns_per_op };
}

// ── Header sets ──────────────────────────────────────────────────────────────

/// Typical HTTP/3 GET request — all headers are in the static table.
/// Each encodeHeaders call exercises 7× findStaticEntry + 7× findStaticName.
const get_headers = [_]qpack.Header{
    .{ .name = ":method", .value = "GET" }, // exact match idx 17
    .{ .name = ":path", .value = "/index.html" }, // name match  idx 1
    .{ .name = ":scheme", .value = "https" }, // exact match idx 23
    .{ .name = ":authority", .value = "example.com" }, // name match  idx 0
    .{ .name = "accept", .value = "*/*" }, // exact match idx 29
    .{ .name = "accept-encoding", .value = "gzip, deflate, br" }, // exact idx 31
    .{ .name = "user-agent", .value = "zquic/1.0" }, // name match  idx 96
};

/// Typical HTTP/3 200 response with content-type, cache-control.
const response_headers = [_]qpack.Header{
    .{ .name = ":status", .value = "200" }, // exact match idx 25
    .{ .name = "content-type", .value = "text/html; charset=utf-8" }, // exact idx 52
    .{ .name = "content-length", .value = "4096" }, // name match  idx 4
    .{ .name = "cache-control", .value = "no-cache" }, // exact match idx 39
    .{ .name = "vary", .value = "accept-encoding" }, // exact match idx 59
};

/// Headers that are NOT in the static table — exercises the "not found" path.
const custom_headers = [_]qpack.Header{
    .{ .name = "x-request-id", .value = "abc123" },
    .{ .name = "x-custom-header", .value = "foo" },
    .{ .name = "x-trace-id", .value = "xyz789" },
};

var encode_buf: [4096]u8 = undefined;

fn benchEncodeGet() void {
    const n = qpack.encodeHeaders(&get_headers, &encode_buf, .{}) catch 0;
    std.mem.doNotOptimizeAway(n);
}

fn benchEncodeResponse() void {
    const n = qpack.encodeHeaders(&response_headers, &encode_buf, .{}) catch 0;
    std.mem.doNotOptimizeAway(n);
}

fn benchEncodeCustom() void {
    const n = qpack.encodeHeaders(&custom_headers, &encode_buf, .{}) catch 0;
    std.mem.doNotOptimizeAway(n);
}

// ── Main ─────────────────────────────────────────────────────────────────────

pub fn main() !void {
    std.debug.print("\n=== zquic QPACK header encoding benchmark ({d} iterations) ===\n", .{ITERS});
    std.debug.print("    Static table: O(1) perfect-hash lookups (was O(N=100) scan)\n\n", .{});

    std.debug.print("A. Encode typical GET request ({d} headers; mix of exact + name matches)\n\n", .{get_headers.len});
    bench(benchEncodeGet).print("encodeHeaders — GET request");
    std.debug.print("\n", .{});

    std.debug.print("B. Encode typical 200 response ({d} headers; mostly exact matches)\n\n", .{response_headers.len});
    bench(benchEncodeResponse).print("encodeHeaders — 200 response");
    std.debug.print("\n", .{});

    std.debug.print("C. Encode custom headers ({d} headers; all NOT in static table)\n\n", .{custom_headers.len});
    bench(benchEncodeCustom).print("encodeHeaders — custom (not in table)");
    std.debug.print("\n", .{});

    std.debug.print("Note: each header field encodes in O(1) amortized time.\n", .{});
    std.debug.print("      Before this change: O(100) string comparisons per field.\n\n", .{});
}
