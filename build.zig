const std = @import("std");
const builtin = @import("builtin");

/// Default version for local builds. The release CI workflow overrides
/// this via `-Dversion=...` extracted from the pushed git tag, so the
/// shipped artifact name matches the tag exactly. Local `zig build release`
/// invocations without `-Dversion=...` use this value as a stable fallback.
const default_version = "0.2.2";

/// libssh version we vendor. Must match the tag in `build.zig.zon`'s
/// `libssh_source` URL. Tracked here in source rather than parsed at
/// build time because both the version header and a few CMake config
/// fields are populated from it.
const libssh_major: u32 = 0;
const libssh_minor: u32 = 11;
const libssh_patch: u32 = 3;

/// Per-target shape we want to produce: a libssh static archive (built
/// from the vendored upstream source via our own build steps), the
/// matching translate-c module for the `@import("libssh")` Zig surface,
/// and the build-options container that exposes our own version /
/// optimize / target metadata to `src/build_options`. Keeping the
/// construction in one helper means `zig build`, `zig build test`, and
/// `zig build release` produce binaries linked against the SAME libssh
/// build (same version, same crypto backend, same flags).
const Linkage = struct {
    libssh_lib: *std.Build.Step.Compile,
    libssh_module: *std.Build.Module,
    build_options: *std.Build.Step.Options,
};

fn buildLinkage(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    zift_version: []const u8,
    target_triple: []const u8,
    optimize_label: []const u8,
) Linkage {
    // mbedTLS provides our crypto backend. Picked over OpenSSL because
    // the OpenSSL Zig package only supports Linux and we want a
    // statically-linked binary on every supported target. mbedTLS is
    // also notably smaller (~600 KB vs OpenSSL's ~3 MB) — fine for
    // SFTP, which uses a small subset of crypto primitives.
    // `threading = true` defines `MBEDTLS_THREADING_PTHREAD` in the
    // mbedTLS build, which makes libssh's `crypto_thread_init`
    // (src/threads/mbedtls.c) accept the pthread callback set we
    // install via `HAVE_PTHREAD = true` below. Without it, libssh
    // returns SSH_ERROR from `ssh_threads_init` because the only
    // accepted thread-callback type when mbedTLS isn't threaded
    // is "threads_noop".
    const mbedtls_dep = b.dependency("mbedtls", .{
        .target = target,
        .optimize = optimize,
        .threading = true,
    });
    const mbedtls_lib = mbedtls_dep.artifact("mbedtls");

    // zlib provides on-the-wire compression for SSH channels. Optional
    // per the SSH spec but real value for SFTP partner workflows that
    // ship text-heavy payloads (CSVs, JSON, logs) — typical 50-80%
    // size reduction. OpenSSH clients negotiate `zlib@openssh.com`
    // when available.
    const zlib_dep = b.dependency("zlib", .{
        .target = target,
        .optimize = optimize,
    });
    const zlib_lib = zlib_dep.artifact("z");

    const libssh_lib = buildLibssh(b, target, optimize, mbedtls_lib, zlib_lib);

    // The C-to-Zig translator needs the libssh public headers at
    // generate time. The libssh artifact installs them via
    // `installHeadersDirectory` into its emitted include tree;
    // grabbing that LazyPath gives us the same headers the linker
    // will resolve symbols against.
    const libssh_translate = b.addTranslateC(.{
        .root_source_file = b.path("src/libssh_root.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    libssh_translate.addIncludePath(libssh_lib.getEmittedIncludeTree());

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", zift_version);
    build_options.addOption([]const u8, "optimize", optimize_label);
    build_options.addOption([]const u8, "target", target_triple);

    return .{
        .libssh_lib = libssh_lib,
        .libssh_module = libssh_translate.createModule(),
        .build_options = build_options,
    };
}

/// Compile libssh from vendored source as a static library. Mirrors
/// what `thomashn/libssh`'s build.zig does, ported to Zig 0.16 API
/// (`Compile.foo` -> `Compile.root_module.foo` everywhere) and
/// trimmed to just the features Zift uses: server side, SFTP, mbedTLS
/// crypto backend, zlib compression, ECC + curve25519, no GSSAPI,
/// no NaCl, no debug crypto/packet output, no PKCS#11.
fn buildLibssh(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    mbedtls_lib: *std.Build.Step.Compile,
    zlib_lib: *std.Build.Step.Compile,
) *std.Build.Step.Compile {
    const src = b.dependency("libssh_source", .{});

    // Reproducible-build flag for libssh's C compilation. Any time
    // libssh's source uses `__FILE__` (assert macros, `SSH_LOG`,
    // some error paths) the C preprocessor bakes the absolute path
    // of the .c file into the binary's `.rodata`. That path is
    // build-host-specific:
    //
    //   local Mac : /Users/shreeve/Data/Code/zift/zig-pkg/<hash>/src/foo.c
    //   GitHub CI : /home/runner/work/zift/zift/zig-pkg/<hash>/src/foo.c
    //
    // so two builds of the SAME source tree produce different
    // binaries (a 16-byte rodata delta from one path string,
    // cascading through all section offsets). `-ffile-prefix-map`
    // remaps the source-root prefix to a fixed string at compile
    // time, making the embedded `__FILE__` independent of where the
    // source sits on disk. Local cross-compile and CI builds then
    // produce byte-identical binaries (verified against v0.2.1).
    //
    // We point the remap at our own pinned libssh version string so
    // the rewritten `__FILE__` is still informative if it shows up
    // in a real error message: `/libssh-0.11.3/src/packet_crypt.c`
    // tells an operator both the library and the file. Just stripping
    // the path prefix entirely would lose that context.
    const libssh_src_path = src.path("").getPath3(b, null);
    const libssh_src_abs = b.fmt("{s}/{s}", .{
        libssh_src_path.root_dir.path orelse ".",
        libssh_src_path.sub_path,
    });
    // `-ffile-prefix-map=OLD=NEW` rewrites paths whose prefix matches
    // OLD by literal substitution. clang's substitution doesn't add
    // its own separator. Note: `LazyPath.getPath3` returns a path
    // that ALREADY ends with `/` for a directory dep, so we don't
    // append one to OLD (doing so produced `<hash>//` which never
    // matched the single-slash `<hash>/src/file.c` in `__FILE__`).
    // We DO add `/` to NEW so the rewritten path reads cleanly:
    // `/libssh-0.11.3/src/packet_crypt.c` (vs `/libssh-0.11.3src/...`).
    const libssh_remap = b.fmt(
        "-ffile-prefix-map={s}=/libssh-{d}.{d}.{d}/",
        .{ libssh_src_abs, libssh_major, libssh_minor, libssh_patch },
    );
    const libssh_cflags: []const []const u8 = &.{libssh_remap};

    const is_unix = target.result.os.tag == .linux or target.result.os.tag == .macos;
    const is_linux = target.result.os.tag == .linux;
    const is_macos = target.result.os.tag == .macos;
    const is_musl = target.result.abi == .musl;

    // -------- generated headers ---------------------------------------------
    const version_header = b.addConfigHeader(.{
        .style = .{ .cmake = src.path("include/libssh/libssh_version.h.cmake") },
        .include_path = "libssh/libssh_version.h",
    }, .{
        .libssh_VERSION_MAJOR = libssh_major,
        .libssh_VERSION_MINOR = libssh_minor,
        .libssh_VERSION_PATCH = libssh_patch,
    });

    const config_header = b.addConfigHeader(.{
        .style = .{ .cmake = src.path("config.h.cmake") },
        .include_path = "config.h",
    }, .{
        .PROJECT_NAME = "libssh",
        .PROJECT_VERSION = b.fmt("{d}.{d}.{d}", .{ libssh_major, libssh_minor, libssh_patch }),
        // Most of these are paths CMake would template into the
        // source. None are reached at runtime in our build because
        // we never load /etc/ssh/* config files (PLAN §5: explicit
        // config only, no /etc lookups). Setting them to harmless
        // strings keeps the build hermetic.
        .SYSCONFDIR = "/etc",
        .BINARYDIR = "/usr/local/bin",
        .SOURCEDIR = "/src/libssh",
        .USR_GLOBAL_BIND_CONFIG = "/etc/ssh/libssh_server_config",
        .GLOBAL_BIND_CONFIG = "/etc/ssh/libssh_server_config",
        .USR_GLOBAL_CLIENT_CONFIG = "/etc/ssh/ssh_config",
        .GLOBAL_CLIENT_CONFIG = "/etc/ssh/ssh_config",

        // Platform feature detection. Hardcoded based on target
        // properties rather than CMake-style probing — Zig's cross-
        // compile means every target is a known shape.
        .HAVE_ARGP_H = is_linux and !is_musl,
        .HAVE_ARPA_INET_H = is_unix,
        .HAVE_GLOB_H = is_unix,
        .HAVE_VALGRIND_VALGRIND_H = false,
        .HAVE_PTY_H = is_linux,
        .HAVE_UTMP_H = 1,
        .HAVE_UTIL_H = is_macos,
        .HAVE_LIBUTIL_H = false,
        .HAVE_SYS_TIME_H = 1,
        .HAVE_SYS_UTIME_H = 0,
        .HAVE_IO_H = 1,
        .HAVE_TERMIOS_H = is_unix,
        .HAVE_UNISTD_H = 1,
        .HAVE_STDINT_H = 1,
        .HAVE_IFADDRS_H = is_unix,
        .HAVE_OPENSSL_AES_H = false,
        .HAVE_WSPIAPI_H = 1,
        .HAVE_OPENSSL_DES_H = false,
        .HAVE_OPENSSL_ECDH_H = false,
        .HAVE_OPENSSL_EC_H = false,
        .HAVE_OPENSSL_ECDSA_H = false,
        .HAVE_PTHREAD_H = 1,
        .HAVE_OPENSSL_ECC = false,
        .HAVE_GCRYPT_ECC = false,
        .HAVE_ECC = 1,
        .HAVE_GLOB_GL_FLAGS_MEMBER = !is_musl,
        .HAVE_GCRYPT_CHACHA_POLY = false,
        .HAVE_OPENSSL_EVP_CHACHA20 = false,
        .HAVE_OPENSSL_EVP_KDF_CTX = false,
        .HAVE_OPENSSL_FIPS_MODE = false,

        // Stdlib features we know exist on every modern target we ship.
        .HAVE_SNPRINTF = 1,
        .HAVE__SNPRINTF = 1,
        .HAVE__SNPRINTF_S = 1,
        .HAVE_VSNPRINTF = 1,
        .HAVE__VSNPRINTF = 1,
        .HAVE__VSNPRINTF_S = 1,
        .HAVE_ISBLANK = 1,
        .HAVE_STRNCPY = 1,
        .HAVE_STRNDUP = is_unix,
        .HAVE_CFMAKERAW = 1,
        .HAVE_GETADDRINFO = 1,
        .HAVE_POLL = is_unix,
        .HAVE_SELECT = 1,
        .HAVE_CLOCK_GETTIME = 1,
        .HAVE_NTOHLL = 0,
        .HAVE_HTONLL = 0,
        .HAVE_STRTOULL = 1,
        .HAVE___STRTOULL = 1,
        .HAVE__STRTOUI64 = 1,
        .HAVE_GLOB = is_unix,
        .HAVE_EXPLICIT_BZERO = is_linux,
        .HAVE_MEMSET_S = is_unix,
        .HAVE_SECURE_ZERO_MEMORY = 1,
        .HAVE_CMOCKA_SET_TEST_FILTER = false,

        // Crypto backend selection. mbedTLS only.
        .HAVE_BLOWFISH = false,
        .HAVE_LIBCRYPTO = false,
        .HAVE_LIBGCRYPT = false,
        .HAVE_LIBMBEDCRYPTO = true,

        // Threading. Zift IS multi-threaded — one OS thread per
        // accepted SFTP session. While each `ssh_session` itself is
        // owned by exactly one worker, libssh has process-global
        // state (one-time crypto init, allocator hooks, callbacks)
        // that would race without the locks `threads/pthread.c`
        // installs at `ssh_init` time. The previous `noop` shim
        // worked in practice but only because most of libssh's
        // global init happens before workers start; an attacker who
        // could trigger reload-during-handshake could in theory
        // race the global state. `HAVE_PTHREAD = true` makes the
        // safety property structural rather than incidental.
        // pthread is part of glibc/musl/Apple libc, so static
        // builds get it free without a separate `-lpthread`.
        .HAVE_PTHREAD = true,
        .HAVE_CMOCKA = false,

        // Compiler attribute support. Zig's clang frontend supports
        // all of these on every target; the GCC/MSVC variants are
        // unused.
        .HAVE_GCC_THREAD_LOCAL_STORAGE = 1,
        .HAVE_MSC_THREAD_LOCAL_STORAGE = 0,
        .HAVE_FALLTHROUGH_ATTRIBUTE = 1,
        .HAVE_UNUSED_ATTRIBUTE = 1,
        .HAVE_WEAK_ATTRIBUTE = 1,
        .HAVE_CONSTRUCTOR_ATTRIBUTE = 1,
        .HAVE_DESTRUCTOR_ATTRIBUTE = 1,
        .HAVE_GCC_VOLATILE_MEMORY_PROTECTION = 0,
        .HAVE_COMPILER__FUNC__ = 1,
        .HAVE_COMPILER__FUNCTION__ = 1,
        .HAVE_GCC_BOUNDED_ATTRIBUTE = 0,

        // libssh feature toggles. Server + SFTP + GEX + zlib on, the
        // rest off.
        .WITH_GSSAPI = false,
        .WITH_ZLIB = true,
        .WITH_SFTP = true,
        .WITH_SERVER = true,
        .WITH_GEX = true,
        .WITH_INSECURE_NONE = false,
        .WITH_EXEC = false,
        .WITH_BLOWFISH_CIPHER = false,
        .DEBUG_CRYPTO = false,
        .DEBUG_PACKET = false,
        .WITH_PCAP = true,
        .DEBUG_CALLTRACE = false,
        .WITH_NACL = false,
        .WITH_PKCS11_URI = false,
        .WITH_PKCS11_PROVIDER = false,
        .WORDS_BIGENDIAN = 0,
    });

    // -------- the static library --------------------------------------------
    const lib = b.addLibrary(.{
        .name = "libssh",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    lib.root_module.addCMacro("LIBSSH_STATIC", "1");
    // Match the mbedTLS threading config we set on the mbedtls
    // dependency above. `mbedtls/threading.h` gates type
    // declarations on `MBEDTLS_THREADING_C` and the pthread-mode
    // `mbedtls_threading_xxx` functions on `MBEDTLS_THREADING_PTHREAD`.
    // libssh's `src/threads/mbedtls.c` includes that header; without
    // these macros visible here too, libssh sees the no-threading
    // shape of the API and `ssh_threads_init` returns SSH_ERROR.
    lib.root_module.addCMacro("MBEDTLS_THREADING_C", "");
    lib.root_module.addCMacro("MBEDTLS_THREADING_PTHREAD", "");
    lib.root_module.addConfigHeader(version_header);
    lib.root_module.addConfigHeader(config_header);
    lib.root_module.addIncludePath(src.path("include"));

    // Public headers: install everything under `include/` so our
    // translate-c step can find them via `getEmittedIncludeTree`.
    lib.installHeadersDirectory(
        src.path("include"),
        ".",
        .{ .include_extensions = &.{ ".h", ".hpp" } },
    );
    lib.installConfigHeader(config_header);
    lib.installConfigHeader(version_header);

    lib.root_module.linkLibrary(mbedtls_lib);
    lib.root_module.linkLibrary(zlib_lib);

    // -------- libssh source files ------------------------------------------
    // Core SSH client + protocol surface. Same list as thomashn's
    // build.zig, kept here so we don't lose track when libssh's
    // upstream adds/removes files in a future update — we'll need to
    // re-sync against the upstream CMakeLists.txt at every libssh
    // version bump.
    lib.root_module.addCSourceFiles(.{
        .root = src.path("src"),
        .files = &.{
            "agent.c",
            "auth.c",
            "base64.c",
            "bignum.c",
            "buffer.c",
            "callbacks.c",
            "channels.c",
            "client.c",
            "config.c",
            "connect.c",
            "connector.c",
            "crypto_common.c",
            "curve25519.c",
            "dh.c",
            "ecdh.c",
            "error.c",
            "getpass.c",
            "gzip.c",
            "init.c",
            "kdf.c",
            "kex.c",
            "known_hosts.c",
            "knownhosts.c",
            "legacy.c",
            "log.c",
            "match.c",
            "messages.c",
            "misc.c",
            "options.c",
            "packet.c",
            "packet_cb.c",
            "packet_crypt.c",
            "pcap.c",
            "pki.c",
            "pki_container_openssh.c",
            "poll.c",
            "session.c",
            "scp.c",
            "socket.c",
            "string.c",
            "threads.c",
            "ttyopts.c",
            "wrapper.c",
            "external/bcrypt_pbkdf.c",
            "external/blowfish.c",
            "config_parser.c",
            "token.c",
            "pki_ed25519_common.c",
        },
        .flags = libssh_cflags,
    });

    // Threading shim. With `HAVE_PTHREAD = true` (see config above),
    // libssh's `threads/pthread.c` provides the mutex/cond locks
    // around process-global state. Required for safe use from
    // multiple worker threads.
    lib.root_module.addCSourceFiles(.{
        .root = src.path("src"),
        .files = &.{"threads/pthread.c"},
        .flags = libssh_cflags,
    });

    // mbedTLS crypto backend. Includes ed25519 from libssh's external/
    // since mbedTLS doesn't ship that algorithm.
    lib.root_module.addCSourceFiles(.{
        .root = src.path("src"),
        .files = &.{
            "threads/mbedtls.c",
            "libmbedcrypto.c",
            "mbedcrypto_missing.c",
            "pki_mbedcrypto.c",
            "ecdh_mbedcrypto.c",
            "getrandom_mbedcrypto.c",
            "md_mbedcrypto.c",
            "dh_key.c",
            "pki_ed25519.c",
            "external/ed25519.c",
            "external/fe25519.c",
            "external/ge25519.c",
            "external/sc25519.c",
            "external/chacha.c",
            "external/poly1305.c",
            "chachapoly.c",
        },
        .flags = libssh_cflags,
    });

    // SFTP wire protocol + server.
    lib.root_module.addCSourceFiles(.{
        .root = src.path("src"),
        .files = &.{
            "sftp.c",
            "sftp_common.c",
            "sftp_aio.c",
            "sftpserver.c",
        },
        .flags = libssh_cflags,
    });

    // SSH server side (bind, accept, message dispatch).
    lib.root_module.addCSourceFiles(.{
        .root = src.path("src"),
        .files = &.{
            "server.c",
            "bind.c",
            "bind_config.c",
        },
        .flags = libssh_cflags,
    });

    // DH group exchange (key-exchange algorithm family).
    lib.root_module.addCSourceFiles(.{
        .root = src.path("src"),
        .files = &.{"dh-gex.c"},
        .flags = libssh_cflags,
    });

    // Curve25519 reference implementation.
    lib.root_module.addCSourceFiles(.{
        .root = src.path("src"),
        .files = &.{"external/curve25519_ref.c"},
        .flags = libssh_cflags,
    });

    return lib;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zift_version = b.option(
        []const u8,
        "version",
        "Override the version string (e.g. -Dversion=0.2.1). Defaults to the source-tree default.",
    ) orelse default_version;

    const target_triple = b.fmt("{s}-{s}", .{
        @tagName(target.result.cpu.arch),
        @tagName(target.result.os.tag),
    });

    // ----- default `zig build` and `zig build run` ---------------------------
    const dev = buildLinkage(b, target, optimize, zift_version, target_triple, @tagName(optimize));

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    exe_mod.addImport("libssh", dev.libssh_module);
    exe_mod.addOptions("build_options", dev.build_options);

    const exe = b.addExecutable(.{
        .name = "zift",
        .root_module = exe_mod,
    });
    exe.root_module.linkLibrary(dev.libssh_lib);

    // Install the dev binary at `<project>/bin/zift` rather than the
    // default `zig-out/bin/zift`. `dest_dir = "../bin"` is relative to
    // the install prefix (`zig-out`), so it resolves to the project
    // root's `bin/`. Operationally this means `zig build && bin/zift`
    // works without `cd zig-out/bin/...` ceremony, and the binary
    // sits next to the source tree where editors and tools find it.
    // Release artifacts still go to `zig-out/release/` (see the
    // `release` step below) — only the local dev binary moves.
    const install_exe = b.addInstallArtifact(exe, .{
        .dest_dir = .{ .override = .{ .custom = "../bin" } },
    });
    b.getInstallStep().dependOn(&install_exe.step);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run zift");
    run_step.dependOn(&run_cmd.step);

    // ----- `zig build test` --------------------------------------------------
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_mod.addImport("libssh", dev.libssh_module);
    test_mod.addOptions("build_options", dev.build_options);

    const unit_tests = b.addTest(.{ .root_module = test_mod });
    unit_tests.root_module.linkLibrary(dev.libssh_lib);

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // ----- `zig build release` (PLAN §13) -----------------------------------
    //
    // Produces `./release/zift-{version}-{target}` plus a per-target
    // `SHA256SUMS-{target}` line. Always linked ReleaseSafe
    // regardless of the global `-Doptimize=...` so production
    // binaries get the same safety checks integration tests run
    // against.
    //
    // Dev/test/release all use the SAME vendored libssh + mbedTLS +
    // zlib (the shared `buildLinkage` helper). No partner ever needs
    // `apt install libssh-4`; every release artifact is self-contained
    // (`verify-release.sh` confirms zero `DT_NEEDED` on Linux, only
    // `libSystem` on macOS).
    const release = buildLinkage(b, target, .ReleaseSafe, zift_version, target_triple, @tagName(.ReleaseSafe));

    const release_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
        .link_libc = true,
    });
    release_mod.addImport("libssh", release.libssh_module);
    release_mod.addOptions("build_options", release.build_options);

    const release_exe = b.addExecutable(.{
        .name = "zift",
        .root_module = release_mod,
    });
    release_exe.root_module.linkLibrary(release.libssh_lib);

    const artifact_name = b.fmt("zift-{s}-{s}", .{ zift_version, target_triple });
    // `dest_dir = "../release"` resolves through the install prefix
    // (`zig-out`) up one level into the project root, so release
    // artifacts land at `<project>/release/...`. Same trick as the
    // dev binary's `../bin` install — keeps the `zig-out/` dance out
    // of the project root entirely. The CI release workflow uploads
    // straight from this path.
    const install_release = b.addInstallArtifact(release_exe, .{
        .dest_dir = .{ .override = .{ .custom = "../release" } },
        .dest_sub_path = artifact_name,
    });

    // Per-target SHA256SUMS file. Naming the output `SHA256SUMS-{target}`
    // means multiple `zig build release -Dtarget=...` runs in the same
    // workspace produce ADJACENT files rather than overwriting a single
    // SHA256SUMS — important now that cross-compile works, because
    // `zig build release -Dtarget=x86_64-linux` followed by
    // `... -Dtarget=aarch64-linux` would otherwise lose the first hash.
    // The release CI workflow concatenates these into one canonical
    // SHA256SUMS at publish time before signing.
    const checksum_cmd = b.addSystemCommand(&.{ "sh", "-c" });
    checksum_cmd.addArg(b.fmt(
        "cd release && shasum -a 256 '{s}' > 'SHA256SUMS-{s}' && cat 'SHA256SUMS-{s}'",
        .{ artifact_name, target_triple, target_triple },
    ));
    checksum_cmd.step.dependOn(&install_release.step);

    const verify_cmd = b.addSystemCommand(&.{
        "build/verify-release.sh",
        b.fmt("release/{s}", .{artifact_name}),
    });
    verify_cmd.step.dependOn(&install_release.step);

    const release_step = b.step("release", "Build a versioned, fully-static release binary into ./release/");
    release_step.dependOn(&install_release.step);
    release_step.dependOn(&checksum_cmd.step);
    release_step.dependOn(&verify_cmd.step);

    _ = builtin; // referenced for cross-platform branches, kept around for future targets.
}
