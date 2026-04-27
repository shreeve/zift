const std = @import("std");

const zift_version = "0.1.0";

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Homebrew on macOS installs libssh under /opt/homebrew. Linux uses
    // distro packages on the default search path, so leave those alone.
    const is_macos = target.result.os.tag == .macos;

    const libssh = b.addTranslateC(.{
        .root_source_file = b.path("src/libssh_root.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    if (is_macos) libssh.addIncludePath(.{ .cwd_relative = "/opt/homebrew/include" });
    libssh.linkSystemLibrary("ssh", .{});

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", zift_version);
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
    if (is_macos) {
        exe_mod.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });
        exe_mod.addRPath(.{ .cwd_relative = "/opt/homebrew/lib" });
    }

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
    if (is_macos) {
        test_mod.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });
        test_mod.addRPath(.{ .cwd_relative = "/opt/homebrew/lib" });
    }

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // -----------------------------------------------------------------
    // Release target (PLAN §13)
    //
    // `zig build release` produces a versioned, target-tagged binary
    // under `zig-out/release/zift-{version}-{target}` along with a
    // `SHA256SUMS` line so partners can verify the bytes they got.
    //
    // Today this step still links DYNAMICALLY against the host's
    // libssh: cross-compilation works only if a libssh sysroot is
    // available for the target. Static linking against vendored
    // libssh + libcrypto sources is the next milestone (TODOS.md
    // P1: "No release target, no SHA256 manifest, no signature step"
    // — this commit lands the FIRST two of those three; signing
    // and the static-linking story are follow-ups). Once vendored,
    // the same `zig build release -Dtarget=...` invocation will
    // produce a cross-target static binary without further changes
    // to this step.
    //
    // Tip: the release artifact is ALWAYS built ReleaseSafe, ignoring
    // the global `-Doptimize=...` flag. Release binaries get the same
    // safety checks integration tests run against; we trade a bit of
    // throughput for the ability to attribute crashes precisely.
    // -----------------------------------------------------------------
    // The release build_options report `optimize = "ReleaseSafe"` in
    // `zift version`, regardless of any `-Doptimize=...` flag the
    // operator may have set for the dev target. Release binaries
    // ALWAYS get ReleaseSafe — operators reading `zift version` on a
    // production host should see that, not whatever the dev was
    // compiling with at the moment.
    const release_build_options = b.addOptions();
    release_build_options.addOption([]const u8, "version", zift_version);
    release_build_options.addOption([]const u8, "optimize", @tagName(.ReleaseSafe));
    release_build_options.addOption([]const u8, "target", target_triple);

    const release_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
        .link_libc = true,
    });
    const release_libssh = b.addTranslateC(.{
        .root_source_file = b.path("src/libssh_root.h"),
        .target = target,
        .optimize = .ReleaseSafe,
        .link_libc = true,
    });
    if (is_macos) release_libssh.addIncludePath(.{ .cwd_relative = "/opt/homebrew/include" });
    release_libssh.linkSystemLibrary("ssh", .{});
    release_mod.addImport("libssh", release_libssh.createModule());
    release_mod.addOptions("build_options", release_build_options);
    release_mod.linkSystemLibrary("ssh", .{});
    if (is_macos) {
        release_mod.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });
        release_mod.addRPath(.{ .cwd_relative = "/opt/homebrew/lib" });
    }

    const release_exe = b.addExecutable(.{
        .name = "zift",
        .root_module = release_mod,
    });

    const artifact_name = b.fmt("zift-{s}-{s}", .{ zift_version, target_triple });
    const install_release = b.addInstallArtifact(release_exe, .{
        .dest_dir = .{ .override = .{ .custom = "release" } },
        .dest_sub_path = artifact_name,
    });

    // SHA256SUMS line for the artifact. `shasum -a 256` is portable on
    // both macOS (default) and Ubuntu (perl-base, always installed),
    // produces the same `<hash>  <filename>` format `sha256sum` does,
    // and is what GitHub's actions/upload-artifact downloaders verify
    // against. Output is rewritten on every release build so partial
    // / stale checksums never linger.
    const checksum_cmd = b.addSystemCommand(&.{ "sh", "-c" });
    checksum_cmd.addArg(b.fmt(
        "cd zig-out/release && shasum -a 256 '{s}' > SHA256SUMS && cat SHA256SUMS",
        .{artifact_name},
    ));
    checksum_cmd.step.dependOn(&install_release.step);

    // Verify the release artifact's runtime dependency surface against
    // a known allowlist. Today's allowlist accepts the small set of
    // dynamic deps the build legitimately produces (libssh + libc on
    // Linux, libssh + libSystem on macOS). When static linking lands
    // (vendored libssh + libcrypto via build.zig.zon), `verify-release.sh`
    // gets a one-line allowlist tightening that turns this into the
    // literal "zero NEEDED" check PLAN §13 promises for Linux. The
    // script itself dispatches on ELF vs Mach-O magic so it works on
    // any host inspecting any target binary.
    const verify_cmd = b.addSystemCommand(&.{
        "build/verify-release.sh",
        b.fmt("zig-out/release/{s}", .{artifact_name}),
    });
    verify_cmd.step.dependOn(&install_release.step);

    const release_step = b.step("release", "Build a versioned release binary into zig-out/release/");
    release_step.dependOn(&install_release.step);
    release_step.dependOn(&checksum_cmd.step);
    release_step.dependOn(&verify_cmd.step);
}
