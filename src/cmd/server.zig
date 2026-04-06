//! QUIC server entrypoint for interop runner.
//! Reads TESTCASE, ROLE, QLOGDIR, SSLKEYLOGFILE from environment.

const std = @import("std");

pub fn main() !void {
    std.debug.print("zquic server — not yet implemented\n", .{});
    std.process.exit(1);
}
