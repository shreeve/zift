const std = @import("std");
const c = @import("libssh");
const abuse = @import("abuse.zig");
const audit = @import("audit.zig");
const config = @import("config.zig");
const sftp = @import("sftp.zig");
const signals = @import("signals.zig");
const ssh = @import("ssh.zig");

pub const Error = error{
    InvalidListenAddress,
    LibsshFailure,
    OutOfMemory,
};

/// Live count of in-flight session worker threads. Bumped by accept,
/// decremented when each detached worker exits. Enforces
/// `max-connections` and graceful drain.
pub var active_sessions: std.atomic.Value(u32) = .init(0);

/// Live count of pre-auth workers. Bumped at accept; decremented at
/// successful auth or session exit. Enforces `max-unauth-connections`
/// independently so handshake storms cannot starve authenticated
/// partners (PLAN §8.4).
pub var unauth_sessions: std.atomic.Value(u32) = .init(0);

/// Format the peer IP of `session`'s underlying TCP socket into `buf`.
/// Returns a slice into `buf` on success, `null` on any error (no
/// socket, getpeername fails, unknown family). The returned slice
/// contains only the address — no port, no brackets — so the audit
/// schema's `ip` field is consistent across IPv4/IPv6 and lookup-able
/// by jq/awk and Zift's own source policy.
fn capturePeerIp(session: c.ssh_session, buf: []u8) ?[]const u8 {
    const fd = c.ssh_get_fd(session);
    if (fd < 0) return null;

    var ss: std.posix.sockaddr.storage align(8) = undefined;
    var ss_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
    std.posix.getpeername(fd, @ptrCast(@alignCast(&ss)), &ss_len) catch return null;

    const family = @as(*const std.posix.sockaddr, @ptrCast(@alignCast(&ss))).family;
    switch (family) {
        std.posix.AF.INET => {
            const sa: *const std.posix.sockaddr.in = @ptrCast(@alignCast(&ss));
            const bytes: [4]u8 = @bitCast(sa.addr);
            return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
                bytes[0], bytes[1], bytes[2], bytes[3],
            }) catch null;
        },
        std.posix.AF.INET6 => {
            const sa: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(&ss));
            return formatIPv6(&sa.addr, buf);
        },
        else => return null,
    }
}

/// Minimal IPv6 address formatter. Produces colon-hex form without
/// `::` zero-run compression — operationally fine for audit logs and
/// keeps the helper allocation-free.
fn formatIPv6(addr: *const [16]u8, buf: []u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, "{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}", .{
        std.mem.readInt(u16, addr[0..2], .big),
        std.mem.readInt(u16, addr[2..4], .big),
        std.mem.readInt(u16, addr[4..6], .big),
        std.mem.readInt(u16, addr[6..8], .big),
        std.mem.readInt(u16, addr[8..10], .big),
        std.mem.readInt(u16, addr[10..12], .big),
        std.mem.readInt(u16, addr[12..14], .big),
        std.mem.readInt(u16, addr[14..16], .big),
    }) catch null;
}

pub fn run(
    io: std.Io,
    allocator: std.mem.Allocator,
    config_path: []const u8,
    initial_config: config.Config,
) !void {
    var active = ActiveConfig{
        .io = io,
        .allocator = allocator,
        .current = try ConfigRef.create(allocator, initial_config),
    };
    defer active.releaseActive();

    // Snapshot the restart-only settings that are bound exactly once,
    // below, so `applyReload` can tell the operator when a reload tries
    // to change one and is silently ineffective.
    active.bound_listen = try allocator.dupe(u8, active.current.config.server.listen);
    active.bound_host_key = try allocator.dupe(u8, active.current.config.server.host_key);
    active.bound_log = try allocator.dupe(u8, logTargetLabel(active.current.config.server.log));
    defer {
        allocator.free(active.bound_listen);
        allocator.free(active.bound_host_key);
        allocator.free(active.bound_log);
    }

    // Size the process file-descriptor limit against the worst case:
    // every session holding its socket plus the per-session handle cap.
    // Without this, `max-connections × max_handles_per_session` (128 ×
    // 256 by default) dwarfs a typical soft `RLIMIT_NOFILE` (1024 on
    // Linux, 256 on macOS), so a few busy partners exhaust the fd table
    // and every other session's OPEN/OPENDIR fails. Best-effort: raise
    // the soft limit toward the hard limit; warn (don't fail) if the
    // ceiling is still short.
    ensureFdBudget(io, active.current.config.server.max_connections);

    const bind = c.ssh_bind_new() orelse return error.LibsshFailure;
    defer c.ssh_bind_free(bind);

    var config_mtime = try currentConfigMtime(io, config_path);

    const listen = try parseListen(allocator, active.current.config.server.listen);
    defer listen.deinit(allocator);

    const host_key = try allocator.dupeZ(u8, active.current.config.server.host_key);
    defer allocator.free(host_key);

    try setBindOption(bind, c.SSH_BIND_OPTIONS_BINDADDR, listen.host.ptr);
    try setBindOption(bind, c.SSH_BIND_OPTIONS_BINDPORT_STR, listen.port.ptr);
    try setBindOption(bind, c.SSH_BIND_OPTIONS_HOSTKEY, host_key.ptr);

    if (c.ssh_bind_listen(bind) != c.SSH_OK) {
        try logLibsshError(io, "ssh_bind_listen", bind, .note);
        return error.LibsshFailure;
    }

    // Drive the accept loop with poll() against libssh's listening fd so
    // operational signals (SIGTERM / SIGHUP) interrupt within ~poll-timeout
    // ms instead of being trapped behind a blocking ssh_bind_accept.
    c.ssh_bind_set_blocking(bind, 0);
    const bind_fd = c.ssh_bind_get_fd(bind);
    var pfd = [1]std.posix.pollfd{.{
        .fd = bind_fd,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};

    // PLAN §7.4: human-readable status goes to stderr; stdout is
    // reserved for things scripts genuinely consume.
    const status = std.Io.File.stderr();
    try status.writeStreamingAll(io, "zift: listening on ");
    try status.writeStreamingAll(io, active.current.config.server.listen);
    try status.writeStreamingAll(io, "\n");

    // Mtime-based reload polling: PLAN §7.3 says the polling interval
    // is `reload-interval` (default 2 s); `0` disables runtime mtime
    // polling entirely (SIGHUP still works). We track a next-deadline
    // in monotonic-ms and only call `reloadIfChanged` when it's hit,
    // independent of how busy the accept fd is.
    var next_reload_ms: i64 = audit.nowMonotonicMs() +
        @as(i64, @intCast(active.current.config.server.reload_interval_ms));

    accept_loop: while (true) {
        if (signals.shutdown_requested.load(.acquire)) break :accept_loop;

        // SIGHUP forces a reload regardless of mtime (PLAN §7.2).
        if (signals.reload_requested.swap(false, .acq_rel)) {
            active.forceReload(config_path, &config_mtime);
            next_reload_ms = audit.nowMonotonicMs() +
                @as(i64, @intCast(active.current.config.server.reload_interval_ms));
        }

        // mtime watcher fires only on a per-config-interval cadence.
        // `reload_interval_ms == 0` disables it (PLAN §7.3); only
        // SIGHUP can re-read the file in that mode.
        const reload_interval = active.current.config.server.reload_interval_ms;
        if (reload_interval > 0 and audit.nowMonotonicMs() >= next_reload_ms) {
            try active.reloadIfChanged(config_path, &config_mtime);
            next_reload_ms = audit.nowMonotonicMs() +
                @as(i64, @intCast(active.current.config.server.reload_interval_ms));
        }

        const ready = std.posix.poll(&pfd, 1000) catch continue :accept_loop;
        if (ready == 0) continue :accept_loop;

        const session = c.ssh_new() orelse return error.LibsshFailure;
        const accept_rc = c.ssh_bind_accept(bind, session);
        if (accept_rc != c.SSH_OK) {
            try logLibsshError(io, "ssh_bind_accept", bind, .note);
            c.ssh_free(session);
            continue :accept_loop;
        }

        var ip_buf: [64]u8 = undefined;
        const peer_ip = capturePeerIp(session, &ip_buf) orelse "";

        // Built-in abuse floor: temporarily refuse sources that recently
        // burned through auth failures. No external ban daemon required.
        if (abuse.isSuppressed(io, peer_ip, audit.nowMonotonicMs())) {
            audit.log(io, null, "accept.rejected", null, .denied, "source suppressed", peer_ip);
            c.ssh_disconnect(session);
            c.ssh_free(session);
            continue :accept_loop;
        }

        const max = active.current.config.server.max_connections;
        if (active_sessions.load(.acquire) >= max) {
            audit.log(io, null, "accept.rejected", null, .denied, "max-connections reached", peer_ip);
            c.ssh_disconnect(session);
            c.ssh_free(session);
            continue :accept_loop;
        }

        // Independent pre-auth cap (PLAN §8.4). When configured (>0),
        // bounds handshake-storm pressure so an attacker can't consume
        // the entire `max-connections` pool with stuck pre-auth sockets.
        // `0` falls back to the global cap above, preserving the
        // behavior operators see when they don't tune this knob.
        const max_unauth_cfg = active.current.config.server.max_unauth_connections;
        if (max_unauth_cfg != 0 and
            unauth_sessions.load(.acquire) >= max_unauth_cfg)
        {
            audit.log(io, null, "accept.rejected", null, .denied, "max-unauth-connections reached", peer_ip);
            c.ssh_disconnect(session);
            c.ssh_free(session);
            continue :accept_loop;
        }

        const ref = active.acquire();
        const args = allocator.create(SessionArgs) catch |err| {
            ref.release(allocator);
            c.ssh_free(session);
            return err;
        };
        args.* = .{
            .io = io,
            .allocator = allocator,
            .config_ref = ref,
            .session = session,
        };

        // Reserve both slots before spawn so subsequent accepts see
        // them. Pre-auth slot is released at successful auth (or at
        // session exit if auth never completes); total slot is
        // released at session exit unconditionally.
        _ = active_sessions.fetchAdd(1, .acq_rel);
        _ = unauth_sessions.fetchAdd(1, .acq_rel);

        const thread = std.Thread.spawn(.{}, sessionThread, .{args}) catch |err| {
            _ = active_sessions.fetchSub(1, .acq_rel);
            _ = unauth_sessions.fetchSub(1, .acq_rel);
            ref.release(allocator);
            c.ssh_free(session);
            allocator.destroy(args);
            try logLibsshError(io, @errorName(err), session, .note);
            continue :accept_loop;
        };
        thread.detach();
    }

    // Graceful drain. The listening socket is closed implicitly on
    // return via `defer ssh_bind_free`; workers keep their own session
    // sockets. We wait for the active-sessions counter to drain on its
    // own up to `shutdown_grace_ms`; if it doesn't, we actively
    // `shutdown(2)` every still-registered session FD so libssh reads
    // unblock, workers tear down their state, and we don't have to
    // rely on kernel reap at process exit (PLAN §7.1).
    const stderr = std.Io.File.stderr();
    try stderr.writeStreamingAll(io, "zift: shutdown signal received, draining sessions\n");

    // PLAN §7.1: close the listening socket FIRST so no fresh TCP
    // connections land during the grace window. The `defer
    // ssh_bind_free` at function entry still tears down libssh's bind
    // state on return; this just unbinds the port immediately.
    _ = std.c.close(bind_fd);

    const grace_ms: i64 = @intCast(active.current.config.server.shutdown_grace_ms);
    const drain_deadline = audit.nowMonotonicMs() + grace_ms;
    while (active_sessions.load(.acquire) != 0 and audit.nowMonotonicMs() < drain_deadline) {
        std.Io.sleep(io, .fromMilliseconds(100), .awake) catch {};
    }

    if (active_sessions.load(.acquire) == 0) {
        try stderr.writeStreamingAll(io, "zift: all sessions drained, exiting\n");
    } else {
        // Force-close path. Snapshot the count, shut down every
        // registered FD, then give workers a brief window to finish
        // their cleanup before we return up the stack.
        const closed = signals.forceCloseAll(io);
        var buf: [128]u8 = undefined;
        const line = std.fmt.bufPrint(
            &buf,
            "zift: grace period expired, force-closing {d} session(s)\n",
            .{closed},
        ) catch unreachable;
        try stderr.writeStreamingAll(io, line);

        // 500 ms is generous: every libssh read on a shut-down socket
        // returns immediately; the worker's deferred decrement is one
        // mutex acquisition + atomic op away.
        const final_deadline = audit.nowMonotonicMs() + 500;
        while (active_sessions.load(.acquire) != 0 and audit.nowMonotonicMs() < final_deadline) {
            std.Io.sleep(io, .fromMilliseconds(20), .awake) catch {};
        }

        const stragglers = active_sessions.load(.acquire);
        if (stragglers == 0) {
            try stderr.writeStreamingAll(io, "zift: all sessions drained after force-close, exiting\n");
        } else {
            const line2 = std.fmt.bufPrint(
                &buf,
                "zift: {d} session(s) still alive after force-close; exiting anyway\n",
                .{stragglers},
            ) catch unreachable;
            try stderr.writeStreamingAll(io, line2);
        }
    }

    // Only free the session-fd registry when every worker has actually
    // exited. A straggler on its way out still calls
    // `unregisterSessionFd`, which iterates the registry — freeing it
    // here (as the old code did unconditionally, including down the
    // "still alive after force-close" branch) is a use-after-free. If
    // stragglers remain, leak the registry: the process is exiting and
    // the OS reclaims it in microseconds.
    if (active_sessions.load(.acquire) == 0) {
        signals.deinitSessionRegistry(io, allocator);
    }
}

/// Human-comparable label for a `LogTarget` ("stderr" or the file
/// path), so the restart-only reload check can diff the audit
/// destination as a plain string.
fn logTargetLabel(target: config.LogTarget) []const u8 {
    return switch (target) {
        .stderr => "stderr",
        .file => |path| path,
    };
}

/// Best-effort raise of `RLIMIT_NOFILE` to cover the worst-case fd
/// demand, warning if the ceiling is still short. See the call site in
/// `run` for the rationale.
fn ensureFdBudget(io: std.Io, max_connections: u32) void {
    // Per session: one socket, a couple of libssh internal fds, plus the
    // per-session handle cap. Round up with slack.
    const per_session: u64 = sftp.max_handles_per_session + 8;
    const needed: u64 = @as(u64, max_connections) * per_session + 64;

    const lim = std.posix.getrlimit(.NOFILE) catch return;
    if (@as(u64, lim.cur) >= needed) return;

    const target: u64 = @min(@as(u64, lim.max), needed);
    var raised = lim;
    raised.cur = @intCast(target);
    std.posix.setrlimit(.NOFILE, raised) catch {};

    const after = std.posix.getrlimit(.NOFILE) catch return;
    if (@as(u64, after.cur) >= needed) return;

    const stderr = std.Io.File.stderr();
    var buf: [320]u8 = undefined;
    const line = std.fmt.bufPrint(
        &buf,
        "zift: warning: file-descriptor soft limit {d} is below the worst case {d} " ++
            "(max-connections {d} × {d} handles/session); lower max-connections or raise LimitNOFILE\n",
        .{ after.cur, needed, max_connections, sftp.max_handles_per_session },
    ) catch return;
    stderr.writeStreamingAll(io, line) catch {};
}

const ConfigRef = struct {
    refs: std.atomic.Value(usize) = .init(1),
    config: config.Config,

    fn create(allocator: std.mem.Allocator, cfg: config.Config) !*ConfigRef {
        const ref = try allocator.create(ConfigRef);
        ref.* = .{ .config = cfg };
        return ref;
    }

    fn acquire(self: *ConfigRef) *ConfigRef {
        _ = self.refs.fetchAdd(1, .acquire);
        return self;
    }

    fn release(self: *ConfigRef, allocator: std.mem.Allocator) void {
        if (self.refs.fetchSub(1, .acq_rel) == 1) {
            self.config.deinit();
            allocator.destroy(self);
        }
    }
};

const ActiveConfig = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    mutex: std.Io.Mutex = .init,
    current: *ConfigRef,
    /// Tracks the warned-state for repeated stat failures on the
    /// config file. Set on first failure (warning emitted), cleared
    /// when the file becomes readable again. PLAN §7.3.
    stat_warned: bool = false,
    /// True while the on-disk config has been rejected and the daemon is
    /// serving the PREVIOUS (in-memory) config instead — i.e. on-disk and
    /// in-memory have diverged. Set at every reject site, cleared when a
    /// good config finally loads (which announces recovery). Makes the
    /// divergence a tracked state rather than a single log line that
    /// scrolls past, so `is-active` staying green can't hide it.
    reload_degraded: bool = false,
    /// The `listen`, `host-key`, and `log` values actually in force —
    /// bound once at startup and never re-applied on reload. Owned
    /// copies (the startup config's arena may be freed once its last
    /// session drops it). Used to warn the operator when a reload
    /// changes one of these restart-only settings, instead of silently
    /// printing "config reloaded" while the change has no effect.
    bound_listen: []const u8 = "",
    bound_host_key: []const u8 = "",
    bound_log: []const u8 = "",

    fn acquire(self: *ActiveConfig) *ConfigRef {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.current.acquire();
    }

    fn releaseActive(self: *ActiveConfig) void {
        self.current.release(self.allocator);
    }

    fn reloadIfChanged(
        self: *ActiveConfig,
        path: []const u8,
        known_mtime: *std.Io.Timestamp,
    ) !void {
        const mtime = currentConfigMtime(self.io, path) catch |err| {
            // PLAN §7.3: a deleted or unreadable config logs a single
            // warning and keeps the previous config running. Repeated
            // failures are suppressed until the file becomes readable
            // again, then we log the recovery.
            if (!self.stat_warned) {
                const stderr = std.Io.File.stderr();
                stderr.writeStreamingAll(self.io, "zift: cannot stat config file: ") catch {};
                stderr.writeStreamingAll(self.io, path) catch {};
                stderr.writeStreamingAll(self.io, ": ") catch {};
                stderr.writeStreamingAll(self.io, @errorName(err)) catch {};
                stderr.writeStreamingAll(self.io, " (keeping previous config)\n") catch {};
                self.stat_warned = true;
            }
            return;
        };

        if (self.stat_warned) {
            const stderr = std.Io.File.stderr();
            stderr.writeStreamingAll(self.io, "zift: config file readable again\n") catch {};
            self.stat_warned = false;
        }

        // PLAN §7.3: reload triggers only when mtime moves forward.
        // Atomic-deploy patterns that preserve or rewind mtime rely on
        // SIGHUP (which uses `forceReload` and skips this check).
        if (mtime.nanoseconds <= known_mtime.nanoseconds) return;
        try self.applyReload(path, mtime, known_mtime);
    }

    /// Reload triggered by SIGHUP. Skips the mtime comparison so atomic
    /// deploy patterns that preserve or rewind mtime still take effect
    /// (PLAN §7.3 mtime caveat).
    fn forceReload(
        self: *ActiveConfig,
        path: []const u8,
        known_mtime: *std.Io.Timestamp,
    ) void {
        const mtime = currentConfigMtime(self.io, path) catch std.Io.Timestamp.zero;
        self.applyReload(path, mtime, known_mtime) catch {};
    }

    fn applyReload(
        self: *ActiveConfig,
        path: []const u8,
        mtime: std.Io.Timestamp,
        known_mtime: *std.Io.Timestamp,
    ) !void {
        const stderr = std.Io.File.stderr();

        const contents = std.Io.Dir.cwd().readFileAlloc(self.io, path, self.allocator, .limited(1 << 20)) catch |err| {
            // A *read* failure may be transient (EMFILE/EACCES/transient
            // I/O). Do NOT advance `known_mtime` here: a later `chmod
            // 000`->`644` (which does not bump mtime) or easing fd
            // pressure must be retried on the next `reload-interval`.
            try stderr.writeStreamingAll(self.io, "zift: config reload read failed: ");
            try stderr.writeStreamingAll(self.io, @errorName(err));
            try stderr.writeStreamingAll(self.io, "\n");
            return;
        };
        defer self.allocator.free(contents);

        // The read succeeded, so from here on advance `known_mtime` to the
        // file's current mtime: a config that keeps failing to *parse* (a
        // saved typo) must not be re-read, re-parsed, and re-logged every
        // `reload-interval` forever. The next genuine edit moves mtime
        // forward again and triggers a fresh attempt. SIGHUP always
        // retries regardless.
        known_mtime.* = mtime;

        var diag: config.ParseDiag = .{};
        var next_config = config.parseWithDiag(self.allocator, contents, &diag) catch |err| {
            var msg_buf: [512]u8 = undefined;
            var w = std.Io.Writer.fixed(&msg_buf);
            diag.format(err, &w) catch {};
            self.noteReloadRejected(stderr, path, w.buffered());
            return;
        };
        errdefer next_config.deinit();

        // Cross-cutting semantic checks (PLAN.md §6.2). On failure, the
        // running config keeps serving; validateSemantic has already
        // written the specific diagnostic (e.g. "host-key unreadable")
        // to stderr, so the audit detail here is the generic reason.
        config.validateSemantic(self.io, self.allocator, &next_config) catch {
            next_config.deinit();
            self.noteReloadRejected(stderr, path, "semantic validation failed (see preceding diagnostic)");
            return;
        };

        // Warn about restart-only settings that changed. `listen`,
        // `host-key`, and `log` are bound exactly once at startup and
        // are NOT re-applied here, so silently reporting "config
        // reloaded" would mislead an operator who just repointed the
        // audit log or the listen address. The reload still applies to
        // users/rules/timeouts; these three keep their startup values
        // until a full restart.
        try self.warnRestartOnly(stderr, "listen", self.bound_listen, next_config.server.listen);
        try self.warnRestartOnly(stderr, "host-key", self.bound_host_key, next_config.server.host_key);
        try self.warnRestartOnly(stderr, "log", self.bound_log, logTargetLabel(next_config.server.log));

        const next_ref = try ConfigRef.create(self.allocator, next_config);

        self.mutex.lockUncancelable(self.io);
        const old_ref = self.current;
        self.current = next_ref;
        self.mutex.unlock(self.io);

        old_ref.release(self.allocator);

        // If we were serving a stale config because earlier edits were
        // rejected, this successful load ends the divergence. Announce the
        // recovery loudly and in the audit stream so the degraded window
        // has a visible close, then clear the flag.
        if (self.reload_degraded) {
            self.reload_degraded = false;
            try stderr.writeStreamingAll(self.io, "zift: config reload recovered — on-disk config valid again; now serving it\n");
            audit.log(self.io, null, "config.reload", path, .ok, "recovered; on-disk config now serving", "");
        }

        try stderr.writeStreamingAll(self.io, "zift: config reloaded (users/rules/timeouts applied to new sessions)\n");
    }

    /// Emit the loud, monitorable signal for a rejected reload and mark
    /// the running config degraded (on-disk differs from what's served).
    /// Called from every reject site. Keeps the `config reload rejected`
    /// substring existing tooling/tests grep for, while making the
    /// divergence explicit, and lands a structured `config.reload` event
    /// in the JSON audit stream operators already pipe to jq. The daemon
    /// stays degraded (see the applyReload success path) until a good
    /// config loads, so a rejected reload can't quietly scroll past while
    /// `systemctl is-active` still reports active.
    fn noteReloadRejected(
        self: *ActiveConfig,
        stderr: std.Io.File,
        path: []const u8,
        detail: []const u8,
    ) void {
        self.reload_degraded = true;
        stderr.writeStreamingAll(self.io, "zift: config reload rejected — SERVING PREVIOUS CONFIG; fix ") catch {};
        stderr.writeStreamingAll(self.io, path) catch {};
        stderr.writeStreamingAll(self.io, " and it will auto-apply") catch {};
        if (detail.len != 0) {
            stderr.writeStreamingAll(self.io, ": ") catch {};
            stderr.writeStreamingAll(self.io, detail) catch {};
        }
        stderr.writeStreamingAll(self.io, "\n") catch {};
        audit.log(
            self.io,
            null,
            "config.reload",
            path,
            .failed,
            if (detail.len != 0) detail else "rejected; serving previous config",
            "",
        );
    }

    fn warnRestartOnly(
        self: *ActiveConfig,
        stderr: std.Io.File,
        name: []const u8,
        bound: []const u8,
        proposed: []const u8,
    ) !void {
        if (std.mem.eql(u8, bound, proposed)) return;
        try stderr.writeStreamingAll(self.io, "zift: warning: '");
        try stderr.writeStreamingAll(self.io, name);
        try stderr.writeStreamingAll(self.io, "' changed in config but is applied only at startup; still using '");
        try stderr.writeStreamingAll(self.io, bound);
        try stderr.writeStreamingAll(self.io, "' — restart zift to apply\n");
    }
};

const SessionArgs = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    config_ref: *ConfigRef,
    session: c.ssh_session,
};

fn sessionThread(args: *SessionArgs) void {
    const io = args.io;
    const allocator = args.allocator;
    const ref = args.config_ref;
    const ssh_session = args.session;
    allocator.destroy(args);

    // Register this session's TCP FD so the graceful-drain path can
    // actively shut down the socket if grace expires before the worker
    // finishes naturally (PLAN §7.1). Failure to register isn't fatal —
    // we still serve the request, just without forced-close visibility.
    const session_fd = c.ssh_get_fd(ssh_session);
    var registered = false;
    if (session_fd >= 0) {
        signals.registerSessionFd(io, allocator, session_fd) catch |err| {
            logLibsshError(io, @errorName(err), ssh_session, .note) catch {};
        };
        registered = true;

        configureSocket(session_fd);
    }

    // PLAN §8.4: the pre-auth slot is owned by `sessionThread` until
    // either (a) `handleSession` flips this flag at successful auth
    // and decrements the counter directly, or (b) the session exits
    // before reaching that point and the defer below releases the
    // slot on the way out. The flag prevents double-decrement.
    var auth_completed = false;

    defer {
        if (!auth_completed) _ = unauth_sessions.fetchSub(1, .acq_rel);
        if (registered) signals.unregisterSessionFd(io, session_fd);
        ref.release(allocator);
        _ = active_sessions.fetchSub(1, .acq_rel);
    }
    handleSession(io, allocator, ref.config, ssh_session, &auth_completed) catch |err| {
        logLibsshError(io, @errorName(err), ssh_session, .skip) catch {};
    };
}

fn currentConfigMtime(io: std.Io, path: []const u8) !std.Io.Timestamp {
    const stat = try std.Io.Dir.cwd().statFile(io, path, .{});
    return stat.mtime;
}

fn handleSession(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    session: c.ssh_session,
    auth_completed: *bool,
) !void {
    defer c.ssh_free(session);

    // Capture peer IP at session start so every audit line emitted by
    // this session — accept-time, handshake, auth, SFTP ops — carries
    // it. Lifetime of `peer_ip` is the stack frame of handleSession,
    // and every callee runs synchronously from here, so pointing into
    // `ip_buf` is safe.
    var ip_buf: [64]u8 = undefined;
    const peer_ip: ?[]const u8 = capturePeerIp(session, &ip_buf);

    // Apply the configured idle-timeout to all blocking libssh reads
    // BEFORE the handshake. Without this, a TCP-only "client" that
    // never speaks SSH pins a worker thread + a max-connections slot
    // forever; PLAN §6.2 says the timeout applies across the session
    // lifecycle, not just after auth completes.
    setSessionTimeout(session, cfg.server.idle_timeout_ms);

    if (c.ssh_handle_key_exchange(session) != c.SSH_OK) {
        audit.log(io, null, "handshake.failed", null, .failed, "", peer_ip orelse "");
        return error.LibsshFailure;
    }

    const user = try ssh.authenticate(io, allocator, cfg, session, peer_ip);

    // Auth succeeded: release the pre-auth slot immediately so the next
    // handshake-storm packet has a slot. Set the flag BEFORE the
    // decrement so a defer in sessionThread that unwinds via panic
    // (Zig's `defer` runs on panic too) does not double-decrement.
    auth_completed.* = true;
    _ = unauth_sessions.fetchSub(1, .acq_rel);

    const channel = try sftp.acceptSftpSubsystem(session);

    try sftp.runSftp(io, allocator, channel, user, cfg.server, peer_ip);
    // ssh_disconnect sends SSH2_MSG_DISCONNECT (clients log "disconnect").
    // Channel lifetime is owned by the session — ssh_free below frees it.
    // Explicit channel_free here would double-free and abort.
    c.ssh_disconnect(session);
}

/// Configure the per-session blocking-read timeout. libssh stores this
/// in `ssh_session.opts.timeout` and applies it to every blocking
/// socket read (handshake, key-exchange, USERAUTH messages, channel
/// open/subsystem). Once we hand off to `runSftp` the per-call
/// `ssh_channel_read_timeout` takes precedence for the SFTP read loop.
/// `idle_timeout_ms == 0` means PLAN §6.2's "disabled" mode: do not set
/// a timeout, leave libssh's default in place.
fn setSessionTimeout(session: c.ssh_session, idle_timeout_ms: u64) void {
    if (idle_timeout_ms == 0) return;
    const seconds: c_long = @intCast(idle_timeout_ms / 1000);
    const usec: c_long = @intCast((idle_timeout_ms % 1000) * 1000);
    _ = c.ssh_options_set(session, c.SSH_OPTIONS_TIMEOUT, &seconds);
    _ = c.ssh_options_set(session, c.SSH_OPTIONS_TIMEOUT_USEC, &usec);
}

/// Apply the socket options every accepted connection should have.
/// All best-effort: a failed setsockopt leaves the option at its
/// default and we still serve the session.
///
///   TCP_NODELAY    Disable Nagle. SFTP is tight request/response —
///                  Nagle adds ~40ms of delayed-ACK latency per
///                  round trip otherwise. Same constant on Linux +
///                  macOS (1).
///   SO_KEEPALIVE   Enable TCP keepalive probes so a dead peer (NAT
///                  rebind, partner network drop, hung client) is
///                  detected and the kernel drops the socket. Constant
///                  values for `SOL_SOCKET`/`SO_KEEPALIVE` differ
///                  between Linux and macOS; we use Zig's platform-
///                  aware `std.posix` so we don't accidentally pass
///                  a Linux value on a macOS host (which silently
///                  configures a different option entirely — see
///                  `TCP_NOPUSH=4` on Darwin which is what an
///                  innocent-looking `TCP_KEEPIDLE=4` would hit).
///   TCP_KEEPIDLE   Linux only. Wait 60s of idle before starting
///                  probes — much faster than the 7200s default.
///                  macOS uses `TCP_KEEPALIVE` for the same idea
///                  but Linux is our primary deploy target so we
///                  only tighten the timing there. macOS keeps
///                  defaults (still gets the basic SO_KEEPALIVE on).
///   TCP_KEEPINTVL  Linux only. Probe every 10s.
///   TCP_KEEPCNT    Linux only. Give up after 6 probes
///                  (~60s idle + 60s probing = ~120s to declare dead).
fn configureSocket(fd: c_int) void {
    if (fd < 0) return;
    const enable: c_int = 1;
    _ = std.c.setsockopt(
        fd,
        std.posix.IPPROTO.TCP,
        std.posix.TCP.NODELAY,
        @ptrCast(&enable),
        @sizeOf(c_int),
    );
    _ = std.c.setsockopt(
        fd,
        std.posix.SOL.SOCKET,
        std.posix.SO.KEEPALIVE,
        @ptrCast(&enable),
        @sizeOf(c_int),
    );

    if (@import("builtin").os.tag == .linux) {
        const idle_seconds: c_int = 60;
        const intvl_seconds: c_int = 10;
        const probe_count: c_int = 6;
        // These three are Linux-specific TCP keepalive timing knobs;
        // on macOS they don't exist (or have entirely different values
        // that mean entirely different things), so we don't touch them.
        _ = std.c.setsockopt(fd, std.posix.IPPROTO.TCP, std.posix.TCP.KEEPIDLE, @ptrCast(&idle_seconds), @sizeOf(c_int));
        _ = std.c.setsockopt(fd, std.posix.IPPROTO.TCP, std.posix.TCP.KEEPINTVL, @ptrCast(&intvl_seconds), @sizeOf(c_int));
        _ = std.c.setsockopt(fd, std.posix.IPPROTO.TCP, std.posix.TCP.KEEPCNT, @ptrCast(&probe_count), @sizeOf(c_int));
    }
}


const Listen = struct {
    host: [:0]u8,
    port: [:0]u8,

    fn deinit(self: Listen, allocator: std.mem.Allocator) void {
        allocator.free(self.host);
        allocator.free(self.port);
    }
};

fn parseListen(allocator: std.mem.Allocator, listen: []const u8) !Listen {
    const colon = std.mem.lastIndexOfScalar(u8, listen, ':') orelse return error.InvalidListenAddress;
    const raw_host = listen[0..colon];
    const raw_port = listen[colon + 1 ..];
    if (raw_port.len == 0) return error.InvalidListenAddress;
    const host = if (raw_host.len == 0) "0.0.0.0" else raw_host;
    return .{
        .host = try allocator.dupeZ(u8, host),
        .port = try allocator.dupeZ(u8, raw_port),
    };
}

fn setBindOption(bind: c.ssh_bind, option: c.enum_ssh_bind_options_e, value: [*:0]const u8) !void {
    if (c.ssh_bind_options_set(bind, option, value) != c.SSH_OK) return error.LibsshFailure;
}

/// What to do when libssh has no error text to contribute.
const NoDetail = enum {
    /// Log anyway, with a placeholder. For failures that are fatal or
    /// otherwise have no audit record of their own -- the stderr line
    /// is the only evidence they happened, so silence would lose them.
    note,
    /// Emit nothing at all. For per-session failures, which already
    /// produce a structured audit record carrying operation, result,
    /// and peer IP.
    ///
    /// This is not tidiness. An internet-facing port is probed
    /// continuously; each scanner that opens a connection and walks
    /// away mid-handshake produced `zift: LibsshFailure:` -- a line
    /// whose entire informational content was "something failed",
    /// which the audit record already said, with the IP attached.
    /// libssh legitimately has no message for a peer that simply
    /// disconnected, so the empty string is the normal case here, not
    /// an anomaly. Logging it buried real failures in noise.
    skip,
};

fn logLibsshError(io: std.Io, where: []const u8, handle: ?*anyopaque, no_detail: NoDetail) !void {
    // A non-null pointer to an EMPTY string is the common case, so
    // checking only for null (as this did) emitted a line that ended at
    // the colon with nothing after it.
    const raw = c.ssh_get_error(handle);
    const detail: []const u8 = if (raw != null) std.mem.span(raw) else "";
    if (detail.len == 0 and no_detail == .skip) return;

    const stderr = std.Io.File.stderr();
    try stderr.writeStreamingAll(io, "zift: ");
    try stderr.writeStreamingAll(io, where);
    try stderr.writeStreamingAll(io, ": ");
    try stderr.writeStreamingAll(io, if (detail.len > 0) detail else "no detail from libssh");
    try stderr.writeStreamingAll(io, "\n");
}
