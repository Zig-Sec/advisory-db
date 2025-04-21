const std = @import("std");

const Advisory = @import("src/Advisory.zig");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = try buildAdvisoryModule(b, target, optimize);

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "validate",
        .root_module = exe_mod,
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const tool = b.addExecutable(.{
        .name = "advisory_gen",
        .root_source_file = b.path("advisory_gen.zig"),
        .target = b.graph.host,
    });
    const tool_step = b.addRunArtifact(tool);

    const tool_run_step = b.step("advisories", "Generate advisory pages.");
    tool_run_step.dependOn(&tool_step.step);
}

fn buildAdvisoryModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) !*std.Build.Module {
    const advisory_module = b.addModule("advisory", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    try b.modules.put(b.dupe("advisory"), advisory_module);

    // Creates a step for unit testing.
    const mod_tests = b.addTest(.{
        .root_module = advisory_module,
    });

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&b.addRunArtifact(mod_tests).step);

    return advisory_module;
}
