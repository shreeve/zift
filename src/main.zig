const std = @import("std");
const c = @import("libssh");
const build_options = @import("build_options");
const audit = @import("audit.zig");
const auth = @import("auth.zig");
const config = @import("config.zig");
const session = @import("session.zig");
const signals = @import("signals.zig");

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

    var cfg = config.parse(gpa, contents) catch |err| {
        try stderr.writeStreamingAll(io, "zift validate: ");
        try stderr.writeStreamingAll(io, path);
        try stderr.writeStreamingAll(io, ": ");
        try stderr.writeStreamingAll(io, @errorName(err));
        try stderr.writeStreamingAll(io, "\n");
        return 1;
    };
    defer cfg.deinit();

    // Cross-cutting semantic checks against the live filesystem
    // (PLAN.md §6.2). Diagnostics already written to stderr by the
    // validator; we only need to translate the error into the exit
    // code.
    config.validateSemantic(io, gpa, &cfg) catch return 1;

    const stdout = std.Io.File.stdout();
    var buf: [128]u8 = undefined;
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

    // Install operational signal handlers before any worker threads exist.
    signals.install();

    const stdout = std.Io.File.stdout();
    const contents = try std.Io.Dir.cwd().readFileAlloc(io, args[2], gpa, .limited(1 << 20));
    defer gpa.free(contents);
    var cfg = try config.parse(gpa, contents);

    // Refuse to start serving until the live-filesystem invariants
    // hold (PLAN.md §6.2). Diagnostics already written to stderr.
    config.validateSemantic(io, gpa, &cfg) catch |err| {
        cfg.deinit();
        return err;
    };

    // Audit destination is determined by `server.log` (default stderr,
    // or an absolute path that is opened O_APPEND and reopened on
    // SIGUSR1). PLAN §7.4. Initialized AFTER semantic validation but
    // BEFORE session.run starts spawning worker threads.
    try audit.initGlobal(gpa, cfg.server.log);
    defer audit.deinitGlobal(gpa);

    try stdout.writeStreamingAll(io, "zift: libssh initialized\n");
    try stdout.writeStreamingAll(io, "zift: config path: ");
    try stdout.writeStreamingAll(io, args[2]);
    try stdout.writeStreamingAll(io, "\n");
    try stdout.writeStreamingAll(io, "zift: listen: ");
    try stdout.writeStreamingAll(io, cfg.server.listen);
    try stdout.writeStreamingAll(io, "\n");
    try session.run(io, gpa, args[2], cfg);
}

fn hashPassword(io: std.Io, gpa: std.mem.Allocator) !void {
    const stdin = std.Io.File.stdin();
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    try stderr.writeStreamingAll(io, "password: ");

    var reader_buffer: [256]u8 = undefined;
    var reader = stdin.readerStreaming(io, &reader_buffer);
    const input = try reader.interface.allocRemaining(gpa, .limited(4096));
    defer gpa.free(input);

    const password = std.mem.trimEnd(u8, input, "\r\n");
    var hash_buffer: [256]u8 = undefined;
    const hash = try auth.hashPassword(io, gpa, password, &hash_buffer);
    try stdout.writeStreamingAll(io, hash);
    try stdout.writeStreamingAll(io, "\n");
}
