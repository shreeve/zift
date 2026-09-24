//! Root of `zig build test`: pulls in every module's tests.

comptime {
    _ = @import("abuse.zig");
    _ = @import("audit.zig");
    _ = @import("config.zig");
    _ = @import("passhash.zig");
    _ = @import("netmatch.zig");
    _ = @import("policy.zig");
    _ = @import("listing.zig");
    _ = @import("vfs.zig");
    _ = @import("wire.zig");
    _ = @import("sftp.zig");
    _ = @import("ssh.zig");
    _ = @import("sys.zig");
    _ = @import("fuzz.zig");
}
