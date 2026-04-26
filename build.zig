const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const libssh = b.addTranslateC(.{
        .root_source_file = b.path("src/libssh_root.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    libssh.addIncludePath(.{ .cwd_relative = "/opt/homebrew/include" });
    libssh.linkSystemLibrary("ssh", .{});

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", "0.1.0");
    build_options.addOption([]const u8, "optimize", @tagName(optimize));
    const target_triple = b.fmt("{s}-{s}", .{
        @tagName(target.result.cpu.arch),
        @tagName(target.result.os.tag),
    });
    build_options.addOption([]const u8, "target", target_triple);

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    exe_mod.addImport("libssh", libssh.createModule());
    exe_mod.addOptions("build_options", build_options);
    exe_mod.linkSystemLibrary("ssh", .{});
    exe_mod.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });
    exe_mod.addRPath(.{ .cwd_relative = "/opt/homebrew/lib" });

    const exe = b.addExecutable(.{
        .name = "zift",
        .root_module = exe_mod,
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    const run_step = b.step("run", "Run zift");
    run_step.dependOn(&run_cmd.step);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_mod.addImport("libssh", libssh.createModule());
    test_mod.addOptions("build_options", build_options);
    test_mod.linkSystemLibrary("ssh", .{});
    test_mod.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });
    test_mod.addRPath(.{ .cwd_relative = "/opt/homebrew/lib" });

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
