//! verify.zig — assert a release artifact's runtime dependency surface
//! matches what we promised.
//!
//! Run as: verify <artifact-path>
//!
//! Wired into `zig build release` so a regression in the release
//! dependency surface fails the build, not the deploy.
//!
//! Linux ELF: asserts zero DT_NEEDED entries (fully static via the
//!     vendored libssh + mbedTLS + zlib build graph).
//! macOS Mach-O: asserts every LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB /
//!     LC_REEXPORT_DYLIB entry is libSystem, libc++, or a system
//!     framework. A Homebrew or third-party dylib path would mean the
//!     static-link broke and the binary went back to dynamic.

const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    const stderr = std.Io.File.stderr();
    if (args.len != 2) {
        try stderr.writeStreamingAll(io, "usage: verify <artifact-path>\n");
        std.process.exit(2);
    }

    const path = args[1];
    const data = std.Io.Dir.cwd().readFileAlloc(io, path, init.gpa, .limited(64 * 1024 * 1024)) catch |err| {
        try stderr.writeStreamingAll(io, "verify: cannot read ");
        try stderr.writeStreamingAll(io, path);
        try stderr.writeStreamingAll(io, ": ");
        try stderr.writeStreamingAll(io, @errorName(err));
        try stderr.writeStreamingAll(io, "\n");
        std.process.exit(2);
    };
    defer init.gpa.free(data);

    if (data.len < 4) {
        try stderr.writeStreamingAll(io, "verify: file too small to identify: ");
        try stderr.writeStreamingAll(io, path);
        try stderr.writeStreamingAll(io, "\n");
        std.process.exit(2);
    }

    const elf_magic = [_]u8{ 0x7f, 'E', 'L', 'F' };
    if (std.mem.eql(u8, data[0..4], &elf_magic)) {
        const code = try verifyElf(io, init.gpa, path, data);
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

    try stderr.writeStreamingAll(io, "verify: unknown binary magic in ");
    try stderr.writeStreamingAll(io, path);
    try stderr.writeStreamingAll(io, "\n");
    std.process.exit(2);
}

/// Linux release contract: zero DT_NEEDED entries. We don't need to
/// resolve string names because the count alone tells us pass or fail.
fn verifyElf(io: std.Io, gpa: std.mem.Allocator, path: []const u8, data: []const u8) !u8 {
    _ = gpa;
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    var reader = std.Io.Reader.fixed(data);
    const hdr = std.elf.Header.read(&reader) catch {
        try stderr.writeStreamingAll(io, "verify: malformed ELF header in ");
        try stderr.writeStreamingAll(io, path);
        try stderr.writeStreamingAll(io, "\n");
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
        var buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf,
            "verify: FAIL — {s} has {d} DT_NEEDED entries (expected zero, fully static)\n",
            .{ path, needed }) catch unreachable;
        try stderr.writeStreamingAll(io, msg);
        return 1;
    }

    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf,
        "verify: OK — DT_NEEDED (ELF) in {s}:\n  (zero entries — fully static)\n",
        .{path}) catch unreachable;
    try stdout.writeStreamingAll(io, msg);
    return 0;
}

/// macOS release contract: every LC_LOAD_DYLIB entry is libSystem,
/// libc++, or a system framework. Anything else (Homebrew, system
/// libssh, etc.) means the static-link broke.
fn verifyMachO(io: std.Io, path: []const u8, data: []const u8) !u8 {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    // Read mach_header_64 (we only ship 64-bit Mach-O). Layout:
    //   u32 magic, u32 cputype, u32 cpusubtype, u32 filetype,
    //   u32 ncmds, u32 sizeofcmds, u32 flags, u32 reserved
    if (data.len < @sizeOf(std.macho.mach_header_64)) {
        try stderr.writeStreamingAll(io, "verify: Mach-O too small in ");
        try stderr.writeStreamingAll(io, path);
        try stderr.writeStreamingAll(io, "\n");
        return 2;
    }
    const is_64 = data[3] == 0xcf or data[0] == 0xcf;
    if (!is_64) {
        try stderr.writeStreamingAll(io, "verify: only 64-bit Mach-O supported: ");
        try stderr.writeStreamingAll(io, path);
        try stderr.writeStreamingAll(io, "\n");
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
            try stderr.writeStreamingAll(io, "verify: truncated load command in ");
            try stderr.writeStreamingAll(io, path);
            try stderr.writeStreamingAll(io, "\n");
            return 2;
        }
        const lc: *const std.macho.load_command = @ptrCast(@alignCast(data.ptr + off));
        const cmdsize = lc.cmdsize;
        if (off + cmdsize > data.len) {
            try stderr.writeStreamingAll(io, "verify: load command overflows file in ");
            try stderr.writeStreamingAll(io, path);
            try stderr.writeStreamingAll(io, "\n");
            return 2;
        }

        switch (lc.cmd) {
            .LOAD_DYLIB, .LOAD_WEAK_DYLIB, .REEXPORT_DYLIB => {
                const dl: *const std.macho.dylib_command = @ptrCast(@alignCast(data.ptr + off));
                const name_off = dl.dylib.name;
                if (name_off >= cmdsize) {
                    try stderr.writeStreamingAll(io, "verify: dylib name offset out of bounds\n");
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
        var head_buf: [256]u8 = undefined;
        const head = std.fmt.bufPrint(&head_buf,
            "verify: FAIL — {s} has {d} unexpected LC_LOAD_DYLIB entries\n",
            .{ path, unexpected_count }) catch unreachable;
        try stderr.writeStreamingAll(io, head);
        try stderr.writeStreamingAll(io, report_w.buffered());
        try stderr.writeStreamingAll(io,
            \\  Either the build picked up a non-system dylib (regression)
            \\  or tools/verify.zig's allowlist needs updating to match a
            \\  deliberate change in our dependency surface.
            \\
        );
        return 1;
    }

    var buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf,
        "verify: OK — LC_LOAD_DYLIB (Mach-O) in {s}: {d} system entr{s}\n",
        .{ path, ok_count, if (ok_count == 1) @as([]const u8, "y") else "ies" }) catch unreachable;
    try stdout.writeStreamingAll(io, msg);
    return 0;
}

/// The macOS allowlist: libSystem, any versioned libc++, and any
/// system framework path. Mirrors the regex
///   ^(/usr/lib/libSystem\.B\.dylib|/usr/lib/libc\+\+\..*\.dylib|
///     /System/Library/Frameworks/.*\.framework/.*)$
/// from the previous shell implementation.
fn isAllowedDylib(name: []const u8) bool {
    if (std.mem.eql(u8, name, "/usr/lib/libSystem.B.dylib")) return true;
    if (std.mem.startsWith(u8, name, "/usr/lib/libc++.") and std.mem.endsWith(u8, name, ".dylib")) return true;
    if (std.mem.startsWith(u8, name, "/System/Library/Frameworks/")) return true;
    return false;
}
