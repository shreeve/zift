//! Signal flags and the registry of live session sockets.
//!
//!     SIGHUP             force a config reload, changed or not
//!     SIGTERM / SIGINT   graceful shutdown with grace period
//!     SIGUSR1            reopen the audit log file (no-op on stderr)
//!     SIGPIPE            ignored
//!
//! Handlers only store an atomic flag (async-signal-safe), on whichever
//! thread receives the signal; the accept loop and workers poll the flags.

const std = @import("std");

/// Set by SIGTERM / SIGINT. Accept loop exits, drain begins.
pub var shutdown_requested: std.atomic.Value(bool) = .init(false);

/// Set by SIGHUP. Accept loop forces a config reload on next iteration,
/// even if nothing on disk changed.
pub var reload_requested: std.atomic.Value(bool) = .init(false);

/// Set by SIGUSR1. The audit log writer reopens its file destination on
/// next write. No-op when logging to stderr (default).
pub var log_reopen_requested: std.atomic.Value(bool) = .init(false);

/// TCP socket fds of in-flight sessions. When the shutdown grace period
/// expires, the accept thread `shutdown(2)`s each one so blocked libssh
/// reads return and workers exit cleanly. `shutdown` from another thread
/// is safe. The accept thread registers an fd before its worker starts;
/// the worker unregisters it before libssh closes it, so a force-close
/// never reaches a reused descriptor.
var sessions_mutex: std.Io.Mutex = .init;
var session_fds: std.ArrayList(c_int) = .empty;

pub fn registerSessionFd(io: std.Io, allocator: std.mem.Allocator, fd: c_int) !void {
    sessions_mutex.lockUncancelable(io);
    defer sessions_mutex.unlock(io);
    try session_fds.append(allocator, fd);
}

pub fn unregisterSessionFd(io: std.Io, fd: c_int) void {
    sessions_mutex.lockUncancelable(io);
    defer sessions_mutex.unlock(io);
    for (session_fds.items, 0..) |entry, i| {
        if (entry == fd) {
            _ = session_fds.swapRemove(i);
            return;
        }
    }
}

/// Shut down every registered session socket (best effort); returns the
/// count.
pub fn forceCloseAll(io: std.Io) usize {
    sessions_mutex.lockUncancelable(io);
    defer sessions_mutex.unlock(io);
    const SHUT_RDWR: c_int = 2;
    for (session_fds.items) |fd| {
        _ = std.c.shutdown(fd, SHUT_RDWR);
    }
    return session_fds.items.len;
}

pub fn deinitSessionRegistry(io: std.Io, allocator: std.mem.Allocator) void {
    sessions_mutex.lockUncancelable(io);
    defer sessions_mutex.unlock(io);
    session_fds.deinit(allocator);
    session_fds = .empty;
}

test "session registry: force-close shuts down registered sockets only" {
    const io = std.testing.io;
    const alloc = std.testing.allocator;
    const posix = std.posix;
    const socketpair = @extern(*const fn (c_uint, c_uint, c_uint, *[2]c_int) callconv(.c) c_int, .{ .name = "socketpair" });

    var a: [2]c_int = undefined;
    var b: [2]c_int = undefined;
    try std.testing.expectEqual(@as(c_int, 0), socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &a));
    try std.testing.expectEqual(@as(c_int, 0), socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &b));
    defer for (a ++ b) |fd| {
        _ = std.c.close(fd);
    };

    try registerSessionFd(io, alloc, a[0]);
    try registerSessionFd(io, alloc, b[0]);
    unregisterSessionFd(io, b[0]);
    try std.testing.expectEqual(@as(usize, 1), forceCloseAll(io));

    // The registered socket's peer sees EOF; the unregistered one is live.
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(isize, 0), std.c.read(a[1], &byte, 1));
    try std.testing.expectEqual(@as(isize, 1), std.c.write(b[1], "x", 1));
    try std.testing.expectEqual(@as(isize, 1), std.c.read(b[0], &byte, 1));

    unregisterSessionFd(io, a[0]);
    try std.testing.expectEqual(@as(usize, 0), forceCloseAll(io));
    deinitSessionRegistry(io, alloc);
}

fn handleShutdown(_: std.posix.SIG) callconv(.c) void {
    shutdown_requested.store(true, .release);
}

fn handleReload(_: std.posix.SIG) callconv(.c) void {
    reload_requested.store(true, .release);
}

fn handleLogReopen(_: std.posix.SIG) callconv(.c) void {
    log_reopen_requested.store(true, .release);
}

/// Call once from main, before any worker thread is spawned.
pub fn install() void {
    const empty_mask = std.mem.zeroes(std.posix.sigset_t);

    var act_shutdown: std.posix.Sigaction = .{
        .handler = .{ .handler = handleShutdown },
        .mask = empty_mask,
        .flags = std.posix.SA.RESTART,
    };
    var act_reload: std.posix.Sigaction = .{
        .handler = .{ .handler = handleReload },
        .mask = empty_mask,
        .flags = std.posix.SA.RESTART,
    };
    var act_log_reopen: std.posix.Sigaction = .{
        .handler = .{ .handler = handleLogReopen },
        .mask = empty_mask,
        .flags = std.posix.SA.RESTART,
    };
    var act_ignore: std.posix.Sigaction = .{
        .handler = .{ .handler = std.posix.SIG.IGN },
        .mask = empty_mask,
        .flags = 0,
    };

    std.posix.sigaction(std.posix.SIG.TERM, &act_shutdown, null);
    std.posix.sigaction(std.posix.SIG.INT, &act_shutdown, null);
    std.posix.sigaction(std.posix.SIG.HUP, &act_reload, null);
    std.posix.sigaction(std.posix.SIG.USR1, &act_log_reopen, null);
    std.posix.sigaction(std.posix.SIG.PIPE, &act_ignore, null);
}
