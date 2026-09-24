//! Command-line entry point: `serve`, `validate`, `hash-password`, `version`.
//!
//! Operational status goes to stderr; stdout carries only what scripts
//! consume (the passhash and the version).

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

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len < 2) {
        try usage(io);
        std.process.exit(1);
    }

    const cmd = args[1];

    if (std.mem.eql(u8, cmd, "serve")) {
        try serve(io, init.gpa, args);
        return;
    }

    if (std.mem.eql(u8, cmd, "hash-password")) {
        try hashPassword(io, init.gpa);
        return;
    }

    if (std.mem.eql(u8, cmd, "validate")) {
        const code = try validate(io, init.gpa, args);
        std.process.exit(code);
    }

    if (std.mem.eql(u8, cmd, "version")) {
        try version(io);
        return;
    }

    try usage(io);
    std.process.exit(1);
}

fn usage(io: std.Io) !void {
    const stderr = std.Io.File.stderr();
    try stderr.writeStreamingAll(io,
        \\usage:
        \\  zift serve <config>
        \\  zift validate <config>
        \\  zift hash-password
        \\  zift version
        \\
    );
}

fn version(io: std.Io) !void {
    try std.Io.File.stdout().writeStreamingAll(io, "zift " ++ build_options.version ++ "\n" ++
        "build: " ++ build_options.target ++ " " ++ build_options.optimize ++ "\n");
}

fn validate(io: std.Io, gpa: std.mem.Allocator, args: []const []const u8) !u8 {
    const stderr = std.Io.File.stderr();
    if (args.len != 3) {
        try stderr.writeStreamingAll(io, "usage: zift validate <config>\n");
        return 1;
    }

    const path = args[2];

    const contents = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20)) catch |err| {
        try sys.note(io, "zift validate: cannot read {s}: {s}\n", .{ path, @errorName(err) });
        return 1;
    };
    defer gpa.free(contents);

    var diag: config.ParseDiag = .{};
    var cfg = config.parseWithDiag(gpa, contents, &diag) catch |err| {
        var msg_buf: [512]u8 = undefined;
        var w = std.Io.Writer.fixed(&msg_buf);
        w.writeAll("zift validate: ") catch {};
        w.writeAll(path) catch {};
        w.writeAll(": ") catch {};
        diag.format(err, &w) catch {};
        w.writeAll("\n") catch {};
        try stderr.writeStreamingAll(io, w.buffered());
        return 1;
    };
    defer cfg.deinit();

    // validateSemantic has already printed the diagnostic.
    config.validateSemantic(io, gpa, &cfg) catch return 1;

    const stdout = std.Io.File.stdout();
    var buf: [4096]u8 = undefined;
    const summary = std.fmt.bufPrint(&buf, "ok: {s} ({d} user{s}, listen {s})\n", .{
        path,
        cfg.users.len,
        if (cfg.users.len == 1) "" else "s",
        cfg.server.listen,
    }) catch unreachable;
    try stdout.writeStreamingAll(io, summary);
    return 0;
}

fn serve(io: std.Io, gpa: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len != 3) {
        try usage(io);
        return;
    }

    const rc = c.ssh_init();
    if (rc != c.SSH_OK) return error.LibsshInitFailed;
    defer _ = c.ssh_finalize();

    // Before any worker thread exists.
    signals.install();

    const stderr = std.Io.File.stderr();

    // Announce the running version before reading the config. After an
    // upgrade `zift version` reports the file on disk, not this process;
    // this line is the journal's record, even when startup then fails.
    try stderr.writeStreamingAll(io, "zift: starting zift " ++ build_options.version ++
        " (" ++ build_options.target ++ " " ++ build_options.optimize ++ ")\n");

    const contents = try std.Io.Dir.cwd().readFileAlloc(io, args[2], gpa, .limited(1 << 20));
    defer gpa.free(contents);

    var diag: config.ParseDiag = .{};
    var cfg = config.parseWithDiag(gpa, contents, &diag) catch |err| {
        var msg_buf: [512]u8 = undefined;
        var w = std.Io.Writer.fixed(&msg_buf);
        w.writeAll("zift: ") catch {};
        w.writeAll(args[2]) catch {};
        w.writeAll(": ") catch {};
        diag.format(err, &w) catch {};
        w.writeAll("\n") catch {};
        try stderr.writeStreamingAll(io, w.buffered());
        return err;
    };

    config.validateSemantic(io, gpa, &cfg) catch |err| {
        cfg.deinit();
        return err;
    };

    // Informational: the legacy staging dir is never used any more.
    for (cfg.users) |*user| {
        if (vfs.legacyStagingDirExists(io, user.root)) {
            try sys.note(io, "zift: warning: legacy staging dir at {s}/.zift-staging is ignored by v0.8.0+; " ++
                "sweep with `rm -rf` once no in-flight sessions need it\n", .{user.root});
        }
    }

    // After validation, before any worker thread.
    try audit.initGlobal(io, gpa, cfg.server.log);
    defer audit.deinitGlobal(gpa);

    try sys.note(io, "zift: libssh initialized\nzift: config path: {s}\nzift: listen: {s}\n", .{
        args[2], cfg.server.listen,
    });
    try server.run(io, gpa, args[2], cfg);
}

fn hashPassword(io: std.Io, gpa: std.mem.Allocator) !void {
    // Password on stdin, passhash on stdout, no prompt:
    // `printf '%s\n' "$pw" | zift hash-password`.
    const stdin = std.Io.File.stdin();
    const stdout = std.Io.File.stdout();

    var reader_buffer: [256]u8 = undefined;
    var reader = stdin.readerStreaming(io, &reader_buffer);
    const input = try reader.interface.allocRemaining(gpa, .limited(4096));
    defer gpa.free(input);

    const password = std.mem.trimEnd(u8, input, "\r\n");
    if (password.len == 0) {
        const stderr = std.Io.File.stderr();
        try stderr.writeStreamingAll(io, "zift: password must not be empty\n");
        std.process.exit(1);
    }
    var hash_buffer: [128]u8 = undefined;
    const hash = try passhash.mint(io, gpa, password, &hash_buffer);
    var line: [passhash.blob_len + 1]u8 = undefined;
    try stdout.writeStreamingAll(io, std.fmt.bufPrint(&line, "{s}\n", .{hash}) catch unreachable);
}
