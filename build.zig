const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const verbose = b.option(bool, "verbose", "Enable verbose debug output") orelse false;

    // Build-options module (verbose flag accessible as @import("build_options").verbose)
    const opts = b.addOptions();
    opts.addOption(bool, "verbose", verbose);

    // tls module (vendored)
    const tls_mod = b.createModule(.{
        .root_source_file = b.path("vendor/tls/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Main library module
    const zquic_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    zquic_mod.addImport("tls", tls_mod);
    zquic_mod.addOptions("build_options", opts);

    const lib = b.addLibrary(.{
        .name = "zquic",
        .root_module = zquic_mod,
        .linkage = .static,
    });
    b.installArtifact(lib);

    // Server binary
    const server_mod = b.createModule(.{
        .root_source_file = b.path("src/cmd/server.zig"),
        .target = target,
        .optimize = optimize,
    });
    server_mod.addImport("zquic", zquic_mod);
    server_mod.addImport("tls", tls_mod);
    server_mod.addOptions("build_options", opts);
    const server = b.addExecutable(.{
        .name = "server",
        .root_module = server_mod,
    });
    b.installArtifact(server);

    // Client binary
    const client_mod = b.createModule(.{
        .root_source_file = b.path("src/cmd/client.zig"),
        .target = target,
        .optimize = optimize,
    });
    client_mod.addImport("zquic", zquic_mod);
    client_mod.addImport("tls", tls_mod);
    client_mod.addOptions("build_options", opts);
    const client = b.addExecutable(.{
        .name = "client",
        .root_module = client_mod,
    });
    b.installArtifact(client);

    // Unit tests
    const unit_tests = b.addTest(.{
        .root_module = zquic_mod,
    });
    const run_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    // Examples
    const examples_step = b.step("examples", "Build all examples");
    const example_files = [_][]const u8{
        "examples/echo_server.zig",
        "examples/parse_packet.zig",
        "examples/session_resumption.zig",
    };
    for (example_files) |src| {
        const base = std.fs.path.stem(src);
        const ex_mod = b.createModule(.{
            .root_source_file = b.path(src),
            .target = target,
            .optimize = optimize,
        });
        ex_mod.addImport("zquic", zquic_mod);
        const ex = b.addExecutable(.{
            .name = base,
            .root_module = ex_mod,
        });
        const ex_install = b.addInstallArtifact(ex, .{});
        examples_step.dependOn(&ex_install.step);
    }
}
