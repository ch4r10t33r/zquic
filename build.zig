const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

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
}
