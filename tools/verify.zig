//! `verify <artifact>`: fail `zig build release` if a release binary
//! gained a runtime dependency.
//!
//! Linux ELF must have no DT_NEEDED entries (fully static). Every Mach-O
//! dylib load must be libSystem, libc++, or a system framework.

const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len != 2) {
        try printTo(stderr, io, "usage: verify <artifact-path>\n", .{});
        std.process.exit(2);
    }

    const path = args[1];
    const data = std.Io.Dir.cwd().readFileAlloc(io, path, init.gpa, .limited(64 * 1024 * 1024)) catch |err| {
        try printTo(stderr, io, "verify: cannot read {s}: {s}\n", .{ path, @errorName(err) });
        std.process.exit(2);
    };
    defer init.gpa.free(data);

    if (data.len < 4) {
        try printTo(stderr, io, "verify: file too small to identify: {s}\n", .{path});
        std.process.exit(2);
    }

    const elf_magic = [_]u8{ 0x7f, 'E', 'L', 'F' };
    if (std.mem.eql(u8, data[0..4], &elf_magic)) {
        const code = try verifyElf(io, path, data);
        std.process.exit(code);
    }

    // Mach-O 32/64-bit, fat, both endians.
    const macho_magics = [_][4]u8{
        .{ 0xfe, 0xed, 0xfa, 0xce },
        .{ 0xce, 0xfa, 0xed, 0xfe },
        .{ 0xfe, 0xed, 0xfa, 0xcf },
        .{ 0xcf, 0xfa, 0xed, 0xfe },
        .{ 0xca, 0xfe, 0xba, 0xbe },
        .{ 0xbe, 0xba, 0xfe, 0xca },
    };
    for (macho_magics) |m| {
        if (std.mem.eql(u8, data[0..4], &m)) {
            const code = try verifyMachO(io, path, data);
            std.process.exit(code);
        }
    }

    try printTo(stderr, io, "verify: unknown binary magic in {s}\n", .{path});
    std.process.exit(2);
}

fn verifyElf(io: std.Io, path: []const u8, data: []const u8) !u8 {
    var reader = std.Io.Reader.fixed(data);
    const hdr = std.elf.Header.read(&reader) catch {
        try printTo(stderr, io, "verify: malformed ELF header in {s}\n", .{path});
        return 2;
    };

    var dyn_off: u64 = 0;
    var dyn_size: u64 = 0;
    var ph_iter = hdr.iterateProgramHeadersBuffer(data);
    while (try ph_iter.next()) |phdr| {
        if (phdr.p_type == std.elf.PT_DYNAMIC) {
            dyn_off = phdr.p_offset;
            dyn_size = phdr.p_filesz;
            break;
        }
    }

    var needed: usize = 0;
    if (dyn_size > 0) {
        var dyn_iter = hdr.iterateDynamicSectionBuffer(data, dyn_off, dyn_size);
        while (try dyn_iter.next()) |entry| {
            if (entry.d_tag == std.elf.DT_NEEDED) needed += 1;
        }
    }

    if (needed > 0) {
        try printTo(stderr, io, "verify: FAIL — {s} has {d} DT_NEEDED entries (expected zero, fully static)\n", .{ path, needed });
        return 1;
    }

    try printTo(stdout, io, "verify: OK — DT_NEEDED (ELF) in {s}:\n  (zero entries — fully static)\n", .{path});
    return 0;
}

fn verifyMachO(io: std.Io, path: []const u8, data: []const u8) !u8 {

    // Only 64-bit Mach-O ships.
    if (data.len < @sizeOf(std.macho.mach_header_64)) {
        try printTo(stderr, io, "verify: Mach-O too small in {s}\n", .{path});
        return 2;
    }
    const is_64 = data[3] == 0xcf or data[0] == 0xcf;
    if (!is_64) {
        try printTo(stderr, io, "verify: only 64-bit Mach-O supported: {s}\n", .{path});
        return 2;
    }

    const hdr: *const std.macho.mach_header_64 = @ptrCast(@alignCast(data.ptr));
    const ncmds = hdr.ncmds;
    var off: usize = @sizeOf(std.macho.mach_header_64);

    var unexpected_count: usize = 0;
    var ok_count: usize = 0;
    var report_buf: [4096]u8 = undefined;
    var report_w = std.Io.Writer.fixed(&report_buf);

    var i: u32 = 0;
    while (i < ncmds) : (i += 1) {
        if (off + @sizeOf(std.macho.load_command) > data.len) {
            try printTo(stderr, io, "verify: truncated load command in {s}\n", .{path});
            return 2;
        }
        const lc: *const std.macho.load_command = @ptrCast(@alignCast(data.ptr + off));
        const cmdsize = lc.cmdsize;
        if (off + cmdsize > data.len) {
            try printTo(stderr, io, "verify: load command overflows file in {s}\n", .{path});
            return 2;
        }

        switch (lc.cmd) {
            .LOAD_DYLIB, .LOAD_WEAK_DYLIB, .REEXPORT_DYLIB => {
                const dl: *const std.macho.dylib_command = @ptrCast(@alignCast(data.ptr + off));
                const name_off = dl.dylib.name;
                if (name_off >= cmdsize) {
                    try printTo(stderr, io, "verify: dylib name offset out of bounds\n", .{});
                    return 2;
                }
                const name_start = off + name_off;
                const remaining = data[name_start .. off + cmdsize];
                const nul = std.mem.indexOfScalar(u8, remaining, 0) orelse remaining.len;
                const name = remaining[0..nul];

                if (isAllowedDylib(name)) {
                    ok_count += 1;
                } else {
                    unexpected_count += 1;
                    report_w.writeAll("    ") catch {};
                    report_w.writeAll(name) catch {};
                    report_w.writeAll("\n") catch {};
                }
            },
            else => {},
        }

        off += cmdsize;
    }

    if (unexpected_count > 0) {
        try printTo(stderr, io, "verify: FAIL — {s} has {d} unexpected LC_LOAD_DYLIB entries\n{s}" ++
            \\  Either the build picked up a non-system dylib (regression)
            \\  or tools/verify.zig's allowlist needs updating to match a
            \\  deliberate change in our dependency surface.
            \\
        , .{ path, unexpected_count, report_w.buffered() });
        return 1;
    }

    try printTo(stdout, io, "verify: OK — LC_LOAD_DYLIB (Mach-O) in {s}: {d} system entr{s}\n", .{ path, ok_count, if (ok_count == 1) @as([]const u8, "y") else "ies" });
    return 0;
}

fn isAllowedDylib(name: []const u8) bool {
    if (std.mem.eql(u8, name, "/usr/lib/libSystem.B.dylib")) return true;
    if (std.mem.startsWith(u8, name, "/usr/lib/libc++.") and std.mem.endsWith(u8, name, ".dylib")) return true;
    if (std.mem.startsWith(u8, name, "/System/Library/Frameworks/")) return true;
    return false;
}

const stdout = std.Io.File.stdout();
const stderr = std.Io.File.stderr();

fn printTo(file: std.Io.File, io: std.Io, comptime fmt: []const u8, args: anytype) !void {
    var buf: [1024]u8 = undefined;
    var w = file.writerStreaming(io, &buf);
    try w.interface.print(fmt, args);
    try w.interface.flush();
}
