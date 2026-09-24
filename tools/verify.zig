//! `verify <artifact> [name]`: fail `zig build release` if a release
//! binary gained a runtime dependency, else print its sha256.
//!
//! A Linux ELF must be fully static: no DT_NEEDED entries and no
//! PT_INTERP. A macOS Mach-O (64-bit little-endian, the only kind
//! shipped) may load exactly one dylib, /usr/lib/libSystem.B.dylib.

const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2 and args.len != 3) {
        try printTo(stderr, io, "usage: verify <artifact-path> [display-name]\n", .{});
        std.process.exit(2);
    }
    const path = args[1];
    const name = if (args.len == 3) args[2] else path;

    const data = std.Io.Dir.cwd().readFileAlloc(io, path, init.gpa, .limited(64 * 1024 * 1024)) catch |err| {
        try printTo(stderr, io, "verify: cannot read {s}: {s}\n", .{ path, @errorName(err) });
        std.process.exit(2);
    };
    defer init.gpa.free(data);

    const problem: ?[]const u8 = if (std.mem.startsWith(u8, data, "\x7fELF"))
        try checkElf(data)
    else if (std.mem.startsWith(u8, data, "\xcf\xfa\xed\xfe"))
        try checkMachO(io, name, data)
    else
        "not a 64-bit little-endian Mach-O or an ELF file";

    if (problem) |why| {
        try printTo(stderr, io, "verify: FAIL {s}: {s}\n", .{ name, why });
        std.process.exit(1);
    }

    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    try printTo(stdout, io, "verify: OK {s}: no runtime dependencies beyond the allowlist\n{x}  {s}\n", .{
        name, &digest, name,
    });
}

fn checkElf(data: []const u8) !?[]const u8 {
    var reader = std.Io.Reader.fixed(data);
    const hdr = std.elf.Header.read(&reader) catch return "malformed ELF header";

    var ph_iter = hdr.iterateProgramHeadersBuffer(data);
    while (try ph_iter.next()) |phdr| {
        switch (phdr.p_type) {
            std.elf.PT_INTERP => return "has PT_INTERP (needs a dynamic loader)",
            std.elf.PT_DYNAMIC => {
                var dyn_iter = hdr.iterateDynamicSectionBuffer(data, phdr.p_offset, phdr.p_filesz);
                while (try dyn_iter.next()) |entry| {
                    if (entry.d_tag == std.elf.DT_NEEDED) return "has DT_NEEDED entries (expected fully static)";
                }
            },
            else => {},
        }
    }
    return null;
}

/// Walks the load commands by offset with explicit little-endian reads,
/// so a malformed file is reported rather than misread.
fn checkMachO(io: std.Io, name: []const u8, data: []const u8) !?[]const u8 {
    const header_len = @sizeOf(std.macho.mach_header_64);
    if (data.len < header_len) return "Mach-O header truncated";
    const ncmds = std.mem.readInt(u32, data[16..20], .little);

    var bad = false;
    var off: usize = header_len;
    for (0..ncmds) |_| {
        if (data.len - off < 8) return "load command truncated";
        const cmd = std.mem.readInt(u32, data[off..][0..4], .little);
        const size = std.mem.readInt(u32, data[off + 4 ..][0..4], .little);
        if (size < 8 or size > data.len - off) return "load command overflows the file";
        const lc = data[off..][0..size];
        off += size;

        switch (@as(std.macho.LC, @enumFromInt(cmd))) {
            .LOAD_DYLIB, .LOAD_WEAK_DYLIB, .REEXPORT_DYLIB, .LAZY_LOAD_DYLIB, .LOAD_UPWARD_DYLIB => {
                if (lc.len < 12) return "dylib command truncated";
                const name_off = std.mem.readInt(u32, lc[8..12], .little);
                if (name_off >= lc.len) return "dylib name offset out of bounds";
                const dylib = std.mem.sliceTo(lc[name_off..], 0);
                if (!std.mem.eql(u8, dylib, "/usr/lib/libSystem.B.dylib")) {
                    try printTo(stderr, io, "verify: {s} loads {s}\n", .{ name, dylib });
                    bad = true;
                }
            },
            else => {},
        }
    }
    return if (bad) "loads a dylib other than libSystem" else null;
}

const stdout = std.Io.File.stdout();
const stderr = std.Io.File.stderr();

fn printTo(file: std.Io.File, io: std.Io, comptime fmt: []const u8, args: anytype) !void {
    var buf: [1024]u8 = undefined;
    var w = file.writerStreaming(io, &buf);
    try w.interface.print(fmt, args);
    try w.interface.flush();
}
