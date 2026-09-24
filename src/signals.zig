//! Signal flags and the registry of live session sockets.
//!
//!     SIGHUP             force a config reload regardless of mtime
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
/// regardless of the config file's mtime.
pub var reload_requested: std.atomic.Value(bool) = .init(false);

/// Set by SIGUSR1. The audit log writer reopens its file destination on
/// next write. No-op when logging to stderr (default).
pub var log_reopen_requested: std.atomic.Value(bool) = .init(false);

/// TCP socket fds of in-flight sessions. When the shutdown grace period
/// expires, the accept thread `shutdown(2)`s each one so blocked libssh
/// reads return and workers exit cleanly. `shutdown` from another thread
/// is safe; only the worker ever `close`s its fd.
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
