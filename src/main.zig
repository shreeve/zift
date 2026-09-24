//! Command-line entry point: `serve`, `validate`, `hash-password`, `version`.
//!
//! Operational status goes to stderr; stdout carries only what scripts
//! consume (the passhash, the version, and validate's ok line).

const std = @import("std");
const c = @import("libssh");
const build_options = @import("build_options");
const audit = @import("audit.zig");
const config = @import("config.zig");
const passhash = @import("passhash.zig");
const server = @import("server.zig");
const signals = @import("signals.zig");
const sys = @import("sys.zig");
const vfs = @import("vfs.zig");

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    const cmd = if (args.len >= 2) args[1] else "";
    const code: u8 = if (std.mem.eql(u8, cmd, "serve") and args.len == 3)
        serve(io, init.gpa, args[2])
    else if (std.mem.eql(u8, cmd, "validate") and args.len == 3)
        try validate(io, init.gpa, args[2])
    else if (std.mem.eql(u8, cmd, "hash-password"))
        try hashPassword(io, init.gpa)
    else if (std.mem.eql(u8, cmd, "version"))
        try version(io)
    else
        try usage(io);
    // Return rather than exit, so a Debug build's allocator reports leaks.
    return code;
}

fn usage(io: std.Io) !u8 {
    try std.Io.File.stderr().writeStreamingAll(io,
        \\usage:
        \\  zift serve <config>
        \\  zift validate <config>
        \\  zift hash-password
        \\  zift version
        \\
    );
    return 1;
}

fn version(io: std.Io) !u8 {
    try std.Io.File.stdout().writeStreamingAll(io, "zift " ++ build_options.version ++ "\n" ++
        "build: " ++ build_options.target ++ " " ++ build_options.optimize ++ "\n");
    return 0;
}

/// Read, parse, and validate `path`, reporting any failure as
/// `<prefix>: ...` on stderr. A semantic failure prints its own line.
fn loadConfig(io: std.Io, gpa: std.mem.Allocator, path: []const u8, prefix: []const u8) ?config.Config {
    const contents = config.readFile(io, gpa, path) catch |err| {
        sys.note(io, "{s}: cannot read {s}: {s}\n", .{ prefix, path, @errorName(err) }) catch {};
        return null;
    };
    defer gpa.free(contents);

    var diag: config.LoadDiag = .{};
    return config.loadPath(io, gpa, path, contents, &diag) catch {
        if (diag.parse_err != null) sys.note(io, "{s}: {s}: {f}\n", .{ prefix, path, diag }) catch {};
        return null;
    };
}

fn validate(io: std.Io, gpa: std.mem.Allocator, path: []const u8) !u8 {
    var cfg = loadConfig(io, gpa, path, "zift validate") orelse return 1;
    defer cfg.deinit();

    var buf: [256]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    try stdout.interface.print("ok: {s} ({d} user{s}, listen {s})\n", .{
        path,
        cfg.users.len,
        if (cfg.users.len == 1) "" else "s",
        cfg.server.listen,
    });
    try stdout.interface.flush();
    return 0;
}

/// Run the server until shutdown. Every failure is reported here as one
/// line, after the resources taken so far are released.
fn serve(io: std.Io, gpa: std.mem.Allocator, path: []const u8) u8 {
    runServer(io, gpa, path) catch |err| {
        // A rejected config has already said why.
        if (err != error.ConfigRejected) sys.note(io, "zift: serve failed: {s}\n", .{@errorName(err)}) catch {};
        return 1;
    };
    return 0;
}

fn runServer(io: std.Io, gpa: std.mem.Allocator, path: []const u8) !void {
    const rc = c.ssh_init();
    if (rc != c.SSH_OK) return error.LibsshInitFailed;
    defer _ = c.ssh_finalize();

    // Before any worker thread exists.
    signals.install();

    // Announce the running version before reading the config. After an
    // upgrade `zift version` reports the file on disk, not this process;
    // this line is the journal's record, even when startup then fails.
    try std.Io.File.stderr().writeStreamingAll(io, "zift: starting zift " ++ build_options.version ++
        " (" ++ build_options.target ++ " " ++ build_options.optimize ++ ")\n");

    var cfg = loadConfig(io, gpa, path, "zift") orelse return error.ConfigRejected;
    // `server.run` owns `cfg` once called; free it on any failure before.
    startup(io, gpa, path, &cfg) catch |err| {
        cfg.deinit();
        return err;
    };
    defer audit.deinitGlobal(gpa);
    try server.run(io, gpa, path, cfg);
}

/// What runs between a valid config and the server: warnings, the audit
/// sink (after validation, before any worker thread), and the banner.
fn startup(io: std.Io, gpa: std.mem.Allocator, path: []const u8, cfg: *const config.Config) !void {
    // Informational: the legacy staging dir is never used any more.
    for (cfg.users) |*user| {
        if (vfs.legacyStagingDirExists(io, user.root)) {
            try sys.note(io, "zift: warning: legacy staging dir at {s}/.zift-staging is ignored by v0.8.0+; " ++
                "sweep with `rm -rf` once no in-flight sessions need it\n", .{user.root});
        }
    }

    try audit.initGlobal(io, gpa, cfg.server.log);
    errdefer audit.deinitGlobal(gpa);

    try sys.note(io, "zift: libssh initialized\nzift: config path: {s}\nzift: listen: {s}\n", .{
        path, cfg.server.listen,
    });
}

/// Password on stdin, passhash on stdout, no prompt:
/// `printf '%s\n' "$pw" | zift hash-password`. Only the first line is
/// the password, less its line ending, exactly as Janus's `passhash`
/// reads piped input; anything after it is ignored.
fn hashPassword(io: std.Io, gpa: std.mem.Allocator) !u8 {
    var reader_buffer: [4096]u8 = undefined;
    defer std.crypto.secureZero(u8, &reader_buffer);
    var reader = std.Io.File.stdin().readerStreaming(io, &reader_buffer);
    const line = reader.interface.takeDelimiter('\n') catch |err| switch (err) {
        error.StreamTooLong => {
            try sys.note(io, "zift: password line longer than {d} bytes\n", .{reader_buffer.len});
            return 1;
        },
        error.ReadFailed => return reader.err.?,
    };
    const password = std.mem.trimEnd(u8, line orelse "", "\r\n");
    if (password.len == 0) {
        try sys.note(io, "zift: password must not be empty\n", .{});
        return 1;
    }

    var hash_buffer: [passhash.blob_len]u8 = undefined;
    const hash = try passhash.mint(io, gpa, password, &hash_buffer);
    var out_buffer: [passhash.blob_len + 1]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &out_buffer);
    try stdout.interface.print("{s}\n", .{hash});
    try stdout.interface.flush();
    return 0;
}
