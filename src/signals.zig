//! Process-level signal state for the SFTP server.
//!
//! Per PLAN.md §7.2:
//!
//!     SIGHUP             force a config reload regardless of mtime
//!     SIGTERM / SIGINT   graceful shutdown with grace period
//!     SIGUSR1            reopen the audit log file (no-op on stderr)
//!     SIGPIPE            ignored
//!
//! Signal handlers are by definition restricted to async-signal-safe
//! operations. All this module's handlers do is set an atomic flag, which
//! is safe. The accept loop and the per-session worker threads poll those
//! flags between operations and act on them in normal context.
//!
//! Zift does not use thread-directed signals; the process-wide handler
//! reaches whichever thread the kernel happens to deliver the signal to.
//! That's fine: the work is just `store(true)`.

const std = @import("std");

/// Set by SIGTERM / SIGINT. Accept loop exits, drain begins.
pub var shutdown_requested: std.atomic.Value(bool) = .init(false);

/// Set by SIGHUP. Accept loop forces a config reload on next iteration,
/// regardless of the config file's mtime.
pub var reload_requested: std.atomic.Value(bool) = .init(false);

/// Set by SIGUSR1. The audit log writer reopens its file destination on
/// next write. No-op when logging to stderr (default).
pub var log_reopen_requested: std.atomic.Value(bool) = .init(false);

/// Live count of in-flight session worker threads. Bumped by accept,
/// decremented when each detached worker exits. Read by the accept loop
/// to enforce `max-connections` and to wait for graceful drain.
pub var active_sessions: std.atomic.Value(u32) = .init(0);

fn handleShutdown(_: std.posix.SIG) callconv(.c) void {
    shutdown_requested.store(true, .release);
}

fn handleReload(_: std.posix.SIG) callconv(.c) void {
    reload_requested.store(true, .release);
}

fn handleLogReopen(_: std.posix.SIG) callconv(.c) void {
    log_reopen_requested.store(true, .release);
}

/// Install handlers for the operational signals. Must be called once,
/// from main, before any worker threads are spawned.
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
