//! Command-line entry point: `serve`, `validate`, `hash-password`, `version`.
//!
//! Operational status goes to stderr; stdout carries only what scripts
//! consume (the passhash and the version).

const std = @import("std");
const c = @import("libssh");
const build_options = @import("build_options");
const audit = @import("audit.zig");
const auth = @import("auth.zig");
const config = @import("config.zig");
const server = @import("server.zig");
const signals = @import("signals.zig");
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
    const stdout = std.Io.File.stdout();
    try stdout.writeStreamingAll(io, "zift ");
    try stdout.writeStreamingAll(io, build_options.version);
    try stdout.writeStreamingAll(io, "\n");
    try stdout.writeStreamingAll(io, "build: ");
    try stdout.writeStreamingAll(io, build_options.target);
    try stdout.writeStreamingAll(io, " ");
    try stdout.writeStreamingAll(io, build_options.optimize);
    try stdout.writeStreamingAll(io, "\n");
}

fn validate(io: std.Io, gpa: std.mem.Allocator, args: []const []const u8) !u8 {
    const stderr = std.Io.File.stderr();
    if (args.len != 3) {
        try stderr.writeStreamingAll(io, "usage: zift validate <config>\n");
        return 1;
    }

    const path = args[2];

    const contents = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20)) catch |err| {
        try stderr.writeStreamingAll(io, "zift validate: cannot read ");
        try stderr.writeStreamingAll(io, path);
        try stderr.writeStreamingAll(io, ": ");
        try stderr.writeStreamingAll(io, @errorName(err));
        try stderr.writeStreamingAll(io, "\n");
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
    try stderr.writeStreamingAll(io, "zift: starting zift ");
    try stderr.writeStreamingAll(io, build_options.version);
    try stderr.writeStreamingAll(io, " (");
    try stderr.writeStreamingAll(io, build_options.target);
    try stderr.writeStreamingAll(io, " ");
    try stderr.writeStreamingAll(io, build_options.optimize);
    try stderr.writeStreamingAll(io, ")\n");

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
            try stderr.writeStreamingAll(io, "zift: warning: legacy staging dir at ");
            try stderr.writeStreamingAll(io, user.root);
            try stderr.writeStreamingAll(io, "/.zift-staging is ignored by v0.8.0+; ");
            try stderr.writeStreamingAll(io, "sweep with `rm -rf` once no in-flight sessions need it\n");
        }
    }

    // After validation, before any worker thread.
    try audit.initGlobal(gpa, cfg.server.log);
    defer audit.deinitGlobal(gpa);

    try stderr.writeStreamingAll(io, "zift: libssh initialized\n");
    try stderr.writeStreamingAll(io, "zift: config path: ");
    try stderr.writeStreamingAll(io, args[2]);
    try stderr.writeStreamingAll(io, "\n");
    try stderr.writeStreamingAll(io, "zift: listen: ");
    try stderr.writeStreamingAll(io, cfg.server.listen);
    try stderr.writeStreamingAll(io, "\n");
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
    const hash = try auth.hashPassword(io, gpa, password, &hash_buffer);
    try stdout.writeStreamingAll(io, hash);
    try stdout.writeStreamingAll(io, "\n");
}
