const std = @import("std");
const c = @import("libssh");
const audit = @import("audit.zig");
const auth = @import("auth.zig");
const config = @import("config.zig");
const listing = @import("listing.zig");
const policy = @import("policy.zig");
const signals = @import("signals.zig");
const vfs_mod = @import("vfs.zig");

pub const Error = error{
    InvalidListenAddress,
    LibsshFailure,
    OutOfMemory,
};

/// PLAN §7.6: maximum SFTP packet size is 256 KiB. Frames that declare
/// a larger length on the wire are treated as malformed and the session
/// is torn down (we cannot reply `BAD_MESSAGE` for the packet itself
/// because the request_id lives inside the body we refuse to read).
const sftp_max_packet_bytes: usize = 256 * 1024;

/// Maximum number of simultaneously-open file/dir handles per SFTP
/// session. Without a cap the client can pipeline OPEN/OPENDIR
/// requests forever, leaking ~200 bytes of `Handle` state apiece
/// until idle-timeout fires — a slow but reliable per-session memory
/// DoS that bypasses `max-connections` (each connection drives its
/// own footprint up). 256 is comfortably above any well-behaved
/// client's working set (`scp -r`, `rsync` over SFTP, paramiko
/// recursive walkers all stay well under 32) but bounds total
/// handle memory at ~50 KiB per session under attack.
const max_handles_per_session: usize = 256;

/// Monotonic-clock millisecond reading. Used for idle-timeout deadlines
/// and graceful-shutdown drain timing. The Linux/macOS `CLOCK_MONOTONIC`
/// is unaffected by wall-clock changes.
fn nowMs() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), std.time.ns_per_ms);
}

/// Wall-clock seconds since the Unix epoch — needed by the listing
/// renderer to decide between `Mon DD HH:MM` (recent) and
/// `Mon DD  YYYY` (old) for `ls -l` mtime formatting. Distinct from
/// `nowMs()` which reads CLOCK_MONOTONIC for interval timing.
fn nowUnixSecs() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return @as(i64, ts.sec);
}

/// Format the peer IP of `session`'s underlying TCP socket into `buf`.
/// Returns a slice into `buf` on success, `null` on any error (no
/// socket, getpeername fails, unknown family). The returned slice
/// contains only the address — no port, no brackets — so the audit
/// schema's `ip` field is consistent across IPv4/IPv6 and lookup-able
/// by composition tools (fail2ban, awk, etc.).
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
        try logLibsshError(io, "ssh_bind_listen", bind);
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
    var next_reload_ms: i64 = nowMs() +
        @as(i64, @intCast(active.current.config.server.reload_interval_ms));

    accept_loop: while (true) {
        if (signals.shutdown_requested.load(.acquire)) break :accept_loop;

        // SIGHUP forces a reload regardless of mtime (PLAN §7.2).
        if (signals.reload_requested.swap(false, .acq_rel)) {
            active.forceReload(config_path, &config_mtime);
            next_reload_ms = nowMs() +
                @as(i64, @intCast(active.current.config.server.reload_interval_ms));
        }

        // mtime watcher fires only on a per-config-interval cadence.
        // `reload_interval_ms == 0` disables it (PLAN §7.3); only
        // SIGHUP can re-read the file in that mode.
        const reload_interval = active.current.config.server.reload_interval_ms;
        if (reload_interval > 0 and nowMs() >= next_reload_ms) {
            try active.reloadIfChanged(config_path, &config_mtime);
            next_reload_ms = nowMs() +
                @as(i64, @intCast(active.current.config.server.reload_interval_ms));
        }

        const ready = std.posix.poll(&pfd, 1000) catch continue :accept_loop;
        if (ready == 0) continue :accept_loop;

        const session = c.ssh_new() orelse return error.LibsshFailure;
        const accept_rc = c.ssh_bind_accept(bind, session);
        if (accept_rc != c.SSH_OK) {
            try logLibsshError(io, "ssh_bind_accept", bind);
            c.ssh_free(session);
            continue :accept_loop;
        }

        const max = active.current.config.server.max_connections;
        if (signals.active_sessions.load(.acquire) >= max) {
            var ip_buf: [64]u8 = undefined;
            const peer_ip = capturePeerIp(session, &ip_buf) orelse "";
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
            signals.unauth_sessions.load(.acquire) >= max_unauth_cfg)
        {
            var ip_buf: [64]u8 = undefined;
            const peer_ip = capturePeerIp(session, &ip_buf) orelse "";
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
        _ = signals.active_sessions.fetchAdd(1, .acq_rel);
        _ = signals.unauth_sessions.fetchAdd(1, .acq_rel);

        const thread = std.Thread.spawn(.{}, sessionThread, .{args}) catch |err| {
            _ = signals.active_sessions.fetchSub(1, .acq_rel);
            _ = signals.unauth_sessions.fetchSub(1, .acq_rel);
            ref.release(allocator);
            c.ssh_free(session);
            allocator.destroy(args);
            try logLibsshError(io, @errorName(err), session);
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
    const drain_deadline = nowMs() + grace_ms;
    while (signals.active_sessions.load(.acquire) != 0 and nowMs() < drain_deadline) {
        std.Io.sleep(io, .fromMilliseconds(100), .awake) catch {};
    }

    if (signals.active_sessions.load(.acquire) == 0) {
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
        const final_deadline = nowMs() + 500;
        while (signals.active_sessions.load(.acquire) != 0 and nowMs() < final_deadline) {
            std.Io.sleep(io, .fromMilliseconds(20), .awake) catch {};
        }

        const stragglers = signals.active_sessions.load(.acquire);
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

    signals.deinitSessionRegistry(io, allocator);
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
            try stderr.writeStreamingAll(self.io, "zift: config reload read failed: ");
            try stderr.writeStreamingAll(self.io, @errorName(err));
            try stderr.writeStreamingAll(self.io, "\n");
            return;
        };
        defer self.allocator.free(contents);

        var diag: config.ParseDiag = .{};
        var next_config = config.parseWithDiag(self.allocator, contents, &diag) catch |err| {
            var msg_buf: [512]u8 = undefined;
            var w = std.Io.Writer.fixed(&msg_buf);
            w.writeAll("zift: config reload rejected: ") catch {};
            w.writeAll(path) catch {};
            w.writeAll(": ") catch {};
            diag.format(err, &w) catch {};
            w.writeAll("\n") catch {};
            try stderr.writeStreamingAll(self.io, w.buffered());
            return;
        };
        errdefer next_config.deinit();

        // Cross-cutting semantic checks (PLAN.md §6.2). On failure, the
        // running config keeps serving; diagnostics already on stderr.
        config.validateSemantic(self.io, self.allocator, &next_config) catch {
            next_config.deinit();
            try stderr.writeStreamingAll(self.io, "zift: config reload rejected (kept previous)\n");
            return;
        };

        const next_ref = try ConfigRef.create(self.allocator, next_config);

        self.mutex.lockUncancelable(self.io);
        const old_ref = self.current;
        self.current = next_ref;
        known_mtime.* = mtime;
        self.mutex.unlock(self.io);

        old_ref.release(self.allocator);
        try stderr.writeStreamingAll(self.io, "zift: config reloaded\n");
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
            logLibsshError(io, @errorName(err), ssh_session) catch {};
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
        if (!auth_completed) _ = signals.unauth_sessions.fetchSub(1, .acq_rel);
        if (registered) signals.unregisterSessionFd(io, session_fd);
        ref.release(allocator);
        _ = signals.active_sessions.fetchSub(1, .acq_rel);
    }
    handleSession(io, allocator, ref.config, ssh_session, &auth_completed) catch |err| {
        logLibsshError(io, @errorName(err), ssh_session) catch {};
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

    const user = try authenticate(io, allocator, cfg, session, peer_ip);

    // Auth succeeded: release the pre-auth slot immediately so the next
    // handshake-storm packet has a slot. Set the flag BEFORE the
    // decrement so a defer in sessionThread that unwinds via panic
    // (Zig's `defer` runs on panic too) does not double-decrement.
    auth_completed.* = true;
    _ = signals.unauth_sessions.fetchSub(1, .acq_rel);

    const channel = try acceptSftpSubsystem(session);

    try runSftp(io, allocator, channel, user, cfg.server.idle_timeout_ms, cfg.server.listing_mode, peer_ip);
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

fn authenticate(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    session: c.ssh_session,
    peer_ip: ?[]const u8,
) !*const config.UserConfig {
    const allowed_methods: c_int = @intCast(c.SSH_AUTH_METHOD_PASSWORD | c.SSH_AUTH_METHOD_PUBLICKEY);

    // PLAN §8.4 implies a finite ceiling on auth attempts per session.
    // 6 matches OpenSSH's `MaxAuthTries` default. Successes return
    // early; pubkey "offered" (probing) does not count because libssh
    // gives us a `pk_ok` follow-up where the real signature verify
    // happens. Only a `denied` outcome consumes an attempt.
    const max_auth_attempts: u32 = 6;
    var failed_attempts: u32 = 0;

    while (true) {
        const msg = c.ssh_message_get(session) orelse return error.LibsshFailure;
        defer c.ssh_message_free(msg);

        if (c.ssh_message_type(msg) != c.SSH_REQUEST_AUTH) {
            _ = c.ssh_message_reply_default(msg);
            continue;
        }

        const subtype: c_uint = @intCast(c.ssh_message_subtype(msg));

        if (subtype == c.SSH_AUTH_METHOD_PASSWORD) {
            const username_ptr = c.ssh_message_auth_user(msg);
            const password_ptr = c.ssh_message_auth_password(msg);
            if (username_ptr != null and password_ptr != null) {
                const username = std.mem.span(username_ptr);
                const password = std.mem.span(password_ptr);
                if (cfg.findUser(username)) |user| {
                    if (auth.verifyPassword(io, allocator, user, password)) {
                        _ = c.ssh_message_auth_reply_success(msg, 0);
                        audit.log(io, username, "auth.password", null, .ok, "", peer_ip orelse "");
                        return user;
                    }
                    audit.log(io, username, "auth.password", null, .denied, "bad password", peer_ip orelse "");
                } else {
                    _ = auth.verifyLogin(io, allocator, cfg, username, password);
                    audit.log(io, username, "auth.password", null, .denied, "unknown user", peer_ip orelse "");
                }
            }
        } else if (subtype == c.SSH_AUTH_METHOD_PUBLICKEY) {
            const decision = handlePublicKeyMessage(io, allocator, cfg, msg, peer_ip);
            switch (decision) {
                .accepted => |user| return user,
                .offered => continue,
                .denied => {},
            }
        }

        // Reaching here means this attempt failed (or the message
        // wasn't a recognized auth method). Count it; disconnect when
        // the ceiling is hit.
        failed_attempts += 1;
        if (failed_attempts >= max_auth_attempts) {
            audit.log(io, null, "auth.too_many_attempts", null, .denied, "", peer_ip orelse "");
            return error.LibsshFailure;
        }

        _ = c.ssh_message_auth_set_methods(msg, allowed_methods);
        _ = c.ssh_message_reply_default(msg);
    }
}

const PublicKeyDecision = union(enum) {
    /// Signature verified and the key matches a configured key for the user.
    /// Reply success was already sent; caller should return this user.
    accepted: *const config.UserConfig,
    /// Client offered an acceptable key (no signature yet). `pk_ok` was
    /// already sent; caller should continue the loop and wait for the
    /// follow-up signed message.
    offered,
    /// Anything else: unknown user, unmatched key, malformed offer, signature
    /// failure. Caller should run the default-deny path.
    denied,
};

fn handlePublicKeyMessage(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    msg: c.ssh_message,
    peer_ip: ?[]const u8,
) PublicKeyDecision {
    const username_ptr = c.ssh_message_auth_user(msg);
    if (username_ptr == null) return .denied;
    const username = std.mem.span(username_ptr);

    const ip_str = peer_ip orelse "";

    const presented = c.ssh_message_auth_pubkey(msg);
    if (presented == null) {
        audit.log(io, username, "auth.publickey", null, .denied, "no key in message", ip_str);
        return .denied;
    }

    const user = cfg.findUser(username) orelse {
        // Unknown user. Run dummy key-import + compare so the timing
        // matches what a known-user-but-wrong-key attempt would take.
        // Without this, an attacker can probe valid usernames by
        // measuring the response time difference. PLAN §8.4: failed
        // authentication does not reveal whether the username exists.
        _ = matchAgainstDummyKey(allocator, presented);
        audit.log(io, username, "auth.publickey", null, .denied, "unknown user", ip_str);
        return .denied;
    };

    if (user.keys.len == 0) {
        // Known user, password-only. Same dummy work so the timing
        // discriminator (does this user accept keys?) is also masked.
        _ = matchAgainstDummyKey(allocator, presented);
        audit.log(io, username, "auth.publickey", null, .denied, "no keys configured", ip_str);
        return .denied;
    }

    const matched_idx = matchesAnyConfiguredKey(allocator, user, presented) orelse {
        audit.log(io, username, "auth.publickey", null, .denied, "key not configured", ip_str);
        return .denied;
    };

    const state = c.ssh_message_auth_publickey_state(msg);
    switch (state) {
        c.SSH_PUBLICKEY_STATE_NONE => {
            // Client is asking "would this key work?". Answer yes; libssh
            // will then receive a signed follow-up that comes back with
            // SSH_PUBLICKEY_STATE_VALID after libssh verifies the signature.
            if (c.ssh_message_auth_reply_pk_ok_simple(msg) != c.SSH_OK) {
                audit.log(io, username, "auth.publickey", null, .failed, "pk_ok reply failed", ip_str);
                return .denied;
            }
            return .offered;
        },
        c.SSH_PUBLICKEY_STATE_VALID => {
            _ = c.ssh_message_auth_reply_success(msg, 0);
            // Audit the algorithm of the *matched* key, not always
            // keys[0]: a user with multiple configured keys would
            // otherwise look like every login used the first key.
            audit.log(io, username, "auth.publickey", null, .ok, user.keys[matched_idx].algorithm, ip_str);
            return .{ .accepted = user };
        },
        else => {
            // SSH_PUBLICKEY_STATE_WRONG, SSH_PUBLICKEY_STATE_ERROR, anything else.
            audit.log(io, username, "auth.publickey", null, .denied, "signature invalid", ip_str);
            return .denied;
        },
    }
}

/// Return the index of the first configured key that matches the
/// presented key, or `null` if none match. Returning the index lets
/// the audit log identify which configured key the client used —
/// `user.keys[0]` would lie for users with multiple keys.
fn matchesAnyConfiguredKey(
    allocator: std.mem.Allocator,
    user: *const config.UserConfig,
    presented: c.ssh_key,
) ?usize {
    if (user.keys.len == 0) return null;
    const presented_type = c.ssh_key_type(presented);

    for (user.keys, 0..) |configured, i| {
        // Per-attempt scratch dupes go through the session's allocator
        // (PLAN §5: no global allocator). Lifetime is one loop iteration;
        // each `defer free` runs before the next attempt. A future
        // optimization may cache the parsed `ssh_key` per session to
        // skip the import on repeat lookups (see SECURITY-AUDIT.md).
        const algo_z = allocator.dupeZ(u8, configured.algorithm) catch return null;
        defer allocator.free(algo_z);
        const blob_z = allocator.dupeZ(u8, configured.blob) catch return null;
        defer allocator.free(blob_z);

        const want_type = c.ssh_key_type_from_name(algo_z.ptr);
        if (want_type != presented_type) continue;

        var parsed: c.ssh_key = null;
        const rc = c.ssh_pki_import_pubkey_base64(blob_z.ptr, want_type, &parsed);
        if (rc != c.SSH_OK or parsed == null) continue;
        defer c.ssh_key_free(parsed);

        if (c.ssh_key_cmp(presented, parsed, c.SSH_KEY_CMP_PUBLIC) == 0) {
            return i;
        }
    }
    return null;
}

/// Hardcoded dummy Ed25519 public-key blob (an existing public key —
/// the matching private key is intentionally not stored anywhere; we
/// only ever compare against this, never accept a signature from it).
/// Used to give unknown-user / no-keys-configured pubkey attempts the
/// same import-and-compare timing as a real lookup, so an attacker
/// cannot probe valid usernames by measuring response time. PLAN §8.4.
const dummy_pubkey_algorithm = "ssh-ed25519";
const dummy_pubkey_blob = "AAAAC3NzaC1lZDI1NTE5AAAAIIH9hN3OvKbo/u+wsxJjPXpOAFn4mP+/p1bbyT2bF50K";

/// Run the same import-and-compare work matchesAnyConfiguredKey does
/// for a real configured key, but against a dummy that will never
/// match. Always returns `false`. The point is the *cost* — masking
/// the timing channel between "this user exists / has keys" and "this
/// user does not."
fn matchAgainstDummyKey(allocator: std.mem.Allocator, presented: c.ssh_key) bool {
    // Same allocator path `matchesAnyConfiguredKey` uses (PLAN §5).
    // Symmetry matters: any caching added there must also be added
    // here, or known-user vs unknown-user paths develop a measurable
    // timing difference that re-opens the username-enumeration channel
    // PLAN §8.4 closed via the dummy-import cost.
    const algo_z = allocator.dupeZ(u8, dummy_pubkey_algorithm) catch return false;
    defer allocator.free(algo_z);
    const blob_z = allocator.dupeZ(u8, dummy_pubkey_blob) catch return false;
    defer allocator.free(blob_z);

    const want_type = c.ssh_key_type_from_name(algo_z.ptr);
    var parsed: c.ssh_key = null;
    const rc = c.ssh_pki_import_pubkey_base64(blob_z.ptr, want_type, &parsed);
    if (rc != c.SSH_OK or parsed == null) return false;
    defer c.ssh_key_free(parsed);

    _ = c.ssh_key_cmp(presented, parsed, c.SSH_KEY_CMP_PUBLIC);
    return false;
}

fn acceptSftpSubsystem(session: c.ssh_session) !c.ssh_channel {
    var channel: c.ssh_channel = null;

    while (channel == null) {
        const msg = c.ssh_message_get(session) orelse return error.LibsshFailure;
        defer c.ssh_message_free(msg);

        if (c.ssh_message_type(msg) == c.SSH_REQUEST_CHANNEL_OPEN and
            c.ssh_message_subtype(msg) == c.SSH_CHANNEL_SESSION)
        {
            channel = c.ssh_message_channel_request_open_reply_accept(msg);
            continue;
        }

        _ = c.ssh_message_reply_default(msg);
    }

    while (true) {
        const msg = c.ssh_message_get(session) orelse return error.LibsshFailure;
        defer c.ssh_message_free(msg);

        if (c.ssh_message_type(msg) == c.SSH_REQUEST_CHANNEL and
            c.ssh_message_subtype(msg) == c.SSH_CHANNEL_REQUEST_SUBSYSTEM)
        {
            const subsystem_ptr = c.ssh_message_channel_request_subsystem(msg);
            if (subsystem_ptr != null and std.mem.eql(u8, std.mem.span(subsystem_ptr), "sftp")) {
                if (c.ssh_message_channel_request_reply_success(msg) != c.SSH_OK) return error.LibsshFailure;
                return channel;
            }
        }

        _ = c.ssh_message_reply_default(msg);
    }
}

fn runSftp(
    io: std.Io,
    allocator: std.mem.Allocator,
    channel: c.ssh_channel,
    user: *const config.UserConfig,
    idle_timeout_ms: u64,
    listing_mode: config.ListingMode,
    peer_ip: ?[]const u8,
) !void {
    var jail = try vfs_mod.Vfs.init(io, allocator, user.root);
    defer jail.deinit(allocator);

    const start_ms = nowMs();
    var state = SftpState{
        .io = io,
        .allocator = allocator,
        .channel = channel,
        .user = user,
        .peer_ip = peer_ip,
        .vfs = jail,
        .idle_timeout_ms = idle_timeout_ms,
        .listing_mode = listing_mode,
        .last_activity_ms = start_ms,
        .session_started_ms = start_ms,
    };
    defer state.deinit();

    // PLAN §7.6: maximum SFTP packet size is 256 KiB. Allocate on the
    // heap so we don't push the worker thread stack past Zig's default
    // (8 MB on Darwin, 8 MB on glibc). One allocation per session, freed
    // at session exit.
    const payload_buf = try allocator.alloc(u8, sftp_max_packet_bytes);
    defer allocator.free(payload_buf);

    const ip_str = peer_ip orelse "";
    const first_payload = readPacketTimed(&state, payload_buf) catch |err| switch (err) {
        error.IdleTimeout => {
            audit.log(io, user.name, "idle.timeout", null, .ok, "", ip_str);
            return;
        },
        else => return err,
    };
    if (first_payload.len < 5 or first_payload[0] != c.SSH_FXP_INIT) return error.LibsshFailure;
    try writeVersion(channel);
    state.last_activity_ms = nowMs();

    while (true) {
        const payload = readPacketTimed(&state, payload_buf) catch |err| switch (err) {
            error.IdleTimeout => {
                state.emitSessionEnded("idle timeout", .ok, ip_str);
                return;
            },
            error.ChannelEof => {
                // Clean half-close: client sent SSH_MSG_CHANNEL_EOF
                // (the standard "I'm done writing" signal). Normal
                // session exit; nothing's wrong on either side.
                state.emitSessionEnded("client closed channel", .ok, ip_str);
                return;
            },
            error.LibsshFailure => {
                // Real transport / libssh failure. Capture libssh's
                // last-error string so an operator can see WHY the
                // wire dropped — "Socket error: disconnected", "Read
                // (socket)…", or "spurious-eof cap reached" when
                // libssh wedged itself reporting EOF forever.
                var lib_buf: [128]u8 = undefined;
                var lw = std.Io.Writer.fixed(&lib_buf);
                lw.writeAll("LibsshFailure: ") catch {};
                const lib_err = c.ssh_get_error(@as(?*anyopaque, @ptrCast(state.channel)));
                if (lib_err != null) lw.writeAll(std.mem.span(lib_err)) catch {};
                state.emitSessionEnded(lw.buffered(), .failed, ip_str);
                return;
            },
            // No `else` — `readPacketTimed`'s error union is fully
            // enumerated above. ReleaseSafe's exhaustiveness check
            // rejects an unreachable `else` prong.
        };
        state.last_activity_ms = nowMs();
        if (payload.len < 5) return error.LibsshFailure;

        const msg_type = payload[0];
        const request_id = readU32(payload[1..5]);
        switch (msg_type) {
            c.SSH_FXP_REALPATH => try state.handleRealpath(request_id, payload[5..]),
            c.SSH_FXP_STAT, c.SSH_FXP_LSTAT => try state.handleStat(request_id, payload[5..]),
            c.SSH_FXP_FSTAT => try state.handleFstat(request_id, payload[5..]),
            c.SSH_FXP_OPENDIR => try state.handleOpendir(request_id, payload[5..]),
            c.SSH_FXP_READDIR => try state.handleReaddir(request_id, payload[5..]),
            c.SSH_FXP_OPEN => try state.handleOpen(request_id, payload[5..]),
            c.SSH_FXP_READ => try state.handleRead(request_id, payload[5..]),
            c.SSH_FXP_WRITE => try state.handleWrite(request_id, payload[5..]),
            c.SSH_FXP_CLOSE => try state.handleClose(request_id, payload[5..]),
            c.SSH_FXP_MKDIR => try state.handleMkdir(request_id, payload[5..]),
            c.SSH_FXP_REMOVE => try state.handleRemove(request_id, payload[5..]),
            c.SSH_FXP_RMDIR => try state.handleRmdir(request_id, payload[5..]),
            c.SSH_FXP_RENAME => try state.handleRename(request_id, payload[5..]),
            // PLAN §7.6 explicitly lists these as rejected with
            // SSH_FX_OP_UNSUPPORTED. Clients (rsync, scp -p, paramiko's
            // chmod/symlink/readlink) probe these; the right reply
            // surfaces "this op isn't supported" — typically translated
            // to errno.ENOSYS by the client — rather than the generic
            // FAILURE that means "I tried and broke."
            c.SSH_FXP_SETSTAT,
            c.SSH_FXP_FSETSTAT,
            c.SSH_FXP_READLINK,
            c.SSH_FXP_SYMLINK,
            c.SSH_FXP_EXTENDED,
            => try replyStatus(channel, request_id, c.SSH_FX_OP_UNSUPPORTED, "unsupported"),
            // Truly unknown opcode. Same answer per PLAN §7.6 — the
            // session continues; we only disconnect on persistent
            // malformed traffic, which the read-side enforces by
            // rejecting oversize frames before parsing.
            else => try replyStatus(channel, request_id, c.SSH_FX_OP_UNSUPPORTED, "unsupported"),
        }
    }
}

const HandleKind = enum {
    dir,
    file,
};

const Handle = struct {
    id: u32,
    kind: HandleKind,
    dir: ?std.Io.Dir = null,
    dir_iter: ?std.Io.Dir.Iterator = null,
    dir_done: bool = false,
    /// Virtual path the dir was opened with (e.g., "/pending"). Stored
    /// verbatim so the listing renderer can ask the policy "what can
    /// this user do at <dir_vpath>/<entry_name>?" — necessary for
    /// virtual-mode rendering, since the per-entry policy decision
    /// depends on the path, not the inode. Borrowed pointer; the
    /// path string itself is allocated in `addDirHandle` and freed
    /// when the slot is `swapRemove`d in `closeHandle`.
    dir_vpath: ?[]const u8 = null,
    file: ?std.Io.File = null,
    /// Whether SSH_FXP_READ is permitted against this handle. Set at
    /// OPEN time from the SFTP open flags + matching `.open_read` policy.
    /// PLAN §6.3: `read` controls SSH_FXP_READ.
    can_read: bool = false,
    /// Whether SSH_FXP_WRITE is permitted against this handle. Set at
    /// OPEN time from the SFTP open flags + matching `.open_write` policy.
    /// PLAN §6.3: `write` controls SSH_FXP_WRITE.
    can_write: bool = false,
    /// Set when OPEN included `SSH_FXF_APPEND`. WRITE on an append
    /// handle writes at the current end-of-file regardless of the
    /// offset the client supplies. PLAN §7.6 commits to ordinary
    /// SFTP v3 semantics; SSH_FXF_APPEND is the standard "all writes
    /// go to the end" mode (rsync-over-sftp uses this).
    is_append: bool = false,
    /// v0.5.0 staging-rename: when this handle was opened with
    /// CREAT against a non-existent target, the actual fd points at
    /// `<root>/.zift-staging/<staging_basename>` instead of the
    /// target path. At CLOSE we atomically rename the staging file
    /// to `staging_target_vpath`. Until that rename succeeds, the
    /// target path doesn't exist on the operator-visible filesystem
    /// — so an operator-side processor never sees a partial file.
    /// Both fields are heap-allocated in `addStagedHandle` and
    /// freed in `closeHandle`.
    staging_target_vpath: ?[]const u8 = null,
    staging_basename: ?[]const u8 = null,
    /// Set when OPEN included `SSH_FXF_EXCL`. Honored at CLOSE
    /// time for staged handles: if the target appeared during the
    /// upload (race with another partner / operator), reply EEXIST
    /// instead of overwriting.
    staging_excl: bool = false,
};

const SftpState = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    channel: c.ssh_channel,
    user: *const config.UserConfig,
    /// Peer IP captured at session accept (PLAN §8.5). Borrowed; the
    /// underlying buffer lives on `handleSession`'s stack frame for
    /// the life of this state.
    peer_ip: ?[]const u8 = null,
    vfs: vfs_mod.Vfs,
    /// Configured `idle-timeout` in ms. 0 disables the check.
    idle_timeout_ms: u64 = 0,
    /// Monotonic timestamp of the last successfully-read SFTP message.
    last_activity_ms: i64 = 0,
    /// Monotonic timestamp captured when this session entered runSftp.
    /// Used to populate `duration_ms` in the `session.ended` audit so
    /// operators can see how long sessions ran.
    session_started_ms: i64 = 0,
    /// Tally of `ssh_channel_read_timeout` returns of 0 that
    /// `ssh_channel_is_eof` immediately disagreed with — i.e. libssh
    /// telling us the channel is at EOF when it actually isn't. We
    /// retry these (rc.4 fix) but track how often it happens. Logged
    /// in `session.ended`'s detail when non-zero so a deployment
    /// where libssh is misbehaving leaves an empirical trail.
    spurious_eof_count: u32 = 0,
    next_handle: u32 = 1,
    handles: std.ArrayList(Handle) = .empty,
    /// Per-session cache for uid/gid -> name resolution used while
    /// formatting `ls -l`-style longnames in directory listings.
    /// Lives inside the state struct (no allocations) and shares
    /// nothing across sessions — keeps cache poisoning between
    /// concurrent partners impossible by construction.
    /// Only consulted in `listing-mode reality`; in `virtual` mode
    /// (the v0.3.0 default) we render the partner's own user name
    /// and a fixed group of "sftp" without ever calling getpwuid_r.
    name_resolver: listing.NameResolver = .{},
    /// `listing-mode` from the server config. `virtual` (default)
    /// hides on-disk identities and renders policy-derived rwx;
    /// `reality` shows the real uid/gid/mode for operators who
    /// want the on-disk view.
    listing_mode: config.ListingMode = .virtual,
    /// v0.5.0 staging-rename: open Dir fd to `<root>/.zift-staging/`,
    /// shared across all handles in this session. Lazily opened the
    /// first time a partner does an OPEN(write+CREAT) on a
    /// non-existent target — most sessions never need it, so we
    /// don't pay the mkdir+open syscalls until the partner's
    /// workflow actually requires staging.
    staging_dir: ?std.Io.Dir = null,

    fn deinit(self: *SftpState) void {
        // closeHandle handles per-handle cleanup, including
        // unlinking any staging file whose CLOSE never ran (partner
        // disconnected mid-upload, or session ended via SIGTERM
        // before the partner sent SSH_FXP_CLOSE). The staging dir
        // itself stays around — if other concurrent sessions for
        // this partner are still running, they'd be using it.
        //
        // CROSS-RESTART ORPHANS: if zift itself crashes mid-upload,
        // the staging files persist after restart. zift does NOT
        // currently sweep them at startup (tracked as a P3 follow-
        // up). Operators with a hard zift crash can manually clear:
        //
        //     rm -f <root>/.zift-staging/*
        //
        // Safe to do anytime — partners can never reach those paths
        // via the SFTP wire surface (path-validator rejects them).
        for (self.handles.items) |*handle| {
            self.closeHandle(handle);
        }
        self.handles.deinit(self.allocator);
        if (self.staging_dir) |*dir| dir.close(self.io);
        self.staging_dir = null;
    }

    /// Emit the canonical `session.ended` audit line with operator-
    /// facing telemetry tacked onto the detail field:
    ///   - duration_ms : monotonic ms since runSftp started
    ///   - spurious_eof: count of spurious-EOF retries we absorbed
    ///                   (only printed when non-zero — keeps the
    ///                   line short for healthy sessions while still
    ///                   surfacing libssh quality issues empirically)
    fn emitSessionEnded(
        self: *const SftpState,
        reason: []const u8,
        result: audit.Result,
        ip_str: []const u8,
    ) void {
        var buf: [320]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        const duration_ms: i64 = nowMs() - self.session_started_ms;
        w.writeAll(reason) catch {};
        w.print(" (duration_ms={d}", .{duration_ms}) catch {};
        if (self.spurious_eof_count != 0) {
            w.print(", spurious_eof={d}", .{self.spurious_eof_count}) catch {};
        }
        w.writeAll(")") catch {};
        audit.log(self.io, self.user.name, "session.ended", null, result, w.buffered(), ip_str);
    }

    /// Validate a freshly-parsed client path against PLAN §7.6 (length)
    /// and §8.3 (byte set + UTF-8). On failure: send `SSH_FX_BAD_MESSAGE`
    /// and return `false` so the caller short-circuits the rest of the
    /// handler. `true` means the path passed all early-gate checks and
    /// is safe to feed into policy + audit + filesystem resolution.
    /// Returning a bool (rather than an error) keeps the malformed-path
    /// case out of `runSftp`'s session-fatal error path — only THIS
    /// request fails; the session continues per PLAN §7.6.
    fn ensureValidPath(self: *SftpState, request_id: u32, value: []const u8) !bool {
        vfs_mod.Vfs.validateVirtualPath(value) catch {
            try replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
            return false;
        };
        return true;
    }

    /// Translate a real `EntryInfo` (from fstatat/fstat) into what the
    /// SFTP attrs reply will carry, honoring `listing_mode`.
    ///
    /// In `virtual` mode (default), uid+gid are zeroed and mode bits
    /// are derived from the user's policy at `vpath`. In `reality`
    /// mode, the inode's values pass through unchanged — including
    /// setuid/setgid/sticky bits, since "reality" should be honest
    /// about reality, not a cosmetically-censored half-truth.
    ///
    /// `vpath` may be null for `FSTAT` on a file handle (the partner
    /// holds a handle, not a path). Without a vpath we can't ask the
    /// policy what they can do at this exact entry. We fall back to
    /// kind-correct conservative defaults: `rwx` for dirs, `rw-` for
    /// files (no execute on files in our world). The partner already
    /// passed an OPEN policy check to get the handle, so showing
    /// permissive bits is consistent — they really can read/write
    /// against this handle, modulo the per-handle access flags
    /// (`can_read`/`can_write`) we tracked at OPEN time.
    fn applyListingMode(self: *const SftpState, real: listing.EntryInfo, vpath: ?[]const u8) listing.EntryInfo {
        switch (self.listing_mode) {
            .reality => return real,
            .virtual => {
                var v = real;
                v.uid = 0;
                v.gid = 0;
                if (vpath) |p| {
                    v.mode = policy.policyDerivedMode(self.user, p, real.mode);
                } else {
                    const file_type = real.mode & 0o170000;
                    const is_dir = file_type == 0o040000;
                    // Dir: rwx (read + mutate + traverse) for owner+group.
                    // File: rw- — no `x` because SFTP files are data,
                    // not executables, and showing `x` would mislead
                    // partners (and any client that switches behavior
                    // based on the bit).
                    const owner: u32 = if (is_dir) 0o7 else 0o6;
                    v.mode = file_type | (owner << 6) | (owner << 3);
                }
                return v;
            },
        }
    }

    fn auditOk(self: *SftpState, op: []const u8, vpath: ?[]const u8, detail: []const u8) void {
        audit.log(self.io, self.user.name, op, vpath, .ok, detail, self.peer_ip orelse "");
    }

    fn auditDenied(self: *SftpState, op: []const u8, vpath: ?[]const u8) void {
        audit.log(self.io, self.user.name, op, vpath, .denied, "", self.peer_ip orelse "");
    }

    fn auditFailed(self: *SftpState, op: []const u8, vpath: ?[]const u8, detail: []const u8) void {
        audit.log(self.io, self.user.name, op, vpath, .failed, detail, self.peer_ip orelse "");
    }

    fn handleRealpath(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const parsed = parseString(payload) catch
            return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");

        const normalized = vfs_mod.Vfs.normalizeVirtual(self.allocator, parsed.value) catch |err| {
            const status: c_int = if (err == error.PathTraversal) c.SSH_FX_PERMISSION_DENIED else c.SSH_FX_NO_SUCH_PATH;
            return replyStatus(self.channel, request_id, status, "bad path");
        };
        defer self.allocator.free(normalized);

        try replyName(self.channel, request_id, normalized);
    }

    /// SSH_FXP_FSTAT — stat-by-handle (PLAN §7.6 "Inherits the open's
    /// permission"). The client opened the file via SSH_FXP_OPEN, which
    /// already ran `.open_read`/`.open_write` policy and stamped per-
    /// handle access bits, so FSTAT itself does not consult policy
    /// again — it just reports the underlying fd's stat. This matches
    /// OpenSSH's sftp-server.
    fn handleFstat(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const id = parseHandleId(payload) catch
            return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad handle");
        const handle = self.findHandle(id, .file) orelse
            return replyStatus(self.channel, request_id, c.SSH_FX_INVALID_HANDLE, "bad handle");

        // `listing.statFd` returns the same shape we use for READDIR
        // (real mode, uid, gid, size, mtime), so STAT/FSTAT/READDIR
        // are now consistent — partner gets the same fields whether
        // they ask via "ls -la" or "stat <file>".
        const info = listing.statFd(handle.file.?.handle) catch
            return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "fstat failed");

        // For virtual mode, FSTAT can't ask the policy what the
        // partner can do here (no vpath available — the partner
        // holds a handle, not a path), so the generic null-vpath
        // fallback in `applyListingMode` would lie about a
        // read-only handle by reporting `rw-`. Instead, derive the
        // mode bits from the per-handle access flags we recorded at
        // OPEN time: those ARE the truth about what's permitted on
        // this fd, and they were already gated by policy when the
        // handle was created.
        var display = self.applyListingMode(info, null);
        if (self.listing_mode == .virtual) {
            const file_type = info.mode & 0o170000;
            var owner: u32 = 0;
            if (handle.can_read) owner |= 0o4;
            if (handle.can_write) owner |= 0o2;
            display.mode = file_type | (owner << 6) | (owner << 3);
        }
        try replyFullAttrs(self.channel, request_id, display);
    }

    fn handleStat(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const path = parseString(payload) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
        if (!try self.ensureValidPath(request_id, path.value)) return;
        if (policy.check(self.user, .stat, path.value) == .deny) {
            // PLAN §8.5: emit audit AFTER replying. `defer` guarantees
            // the audit fires once the reply syscall returns, so a slow
            // audit destination (file on a hung NFS mount) cannot block
            // the client's status reply.
            defer self.auditDenied("stat", path.value);
            return replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }

        // Special-case the root: openVerifiedParent rejects "/" because
        // it has no parent inside the jail. STAT of root means stat the
        // jail directory itself.
        if (std.mem.eql(u8, path.value, "/") or std.mem.eql(u8, path.value, "")) {
            // STAT of "/" means stat the jail root itself. Open the
            // root dir to get a stable fd, fstat it, then close.
            // Going through an fd (rather than a path-string stat)
            // matches PLAN §8.3 and gives us full uid/gid/mode for
            // the listing renderer.
            var root_dir = std.Io.Dir.cwd().openDir(self.io, self.vfs.root, .{ .iterate = false }) catch {
                return replyStatus(self.channel, request_id, c.SSH_FX_NO_SUCH_FILE, "not found");
            };
            defer root_dir.close(self.io);
            const root_info = listing.statFd(root_dir.handle) catch
                return replyStatus(self.channel, request_id, c.SSH_FX_NO_SUCH_FILE, "not found");
            return replyFullAttrs(self.channel, request_id, self.applyListingMode(root_info, "/"));
        }

        // FD-based stat (PLAN §8.3 — no string-layer authorization
        // artifacts). Resolve the parent through `openVerifiedParent`,
        // which canonicalizes through any symlinks in the parent path
        // and verifies the result is inside the jail. Then `statFile`
        // against the parent FD with `follow_symlinks = false` so a
        // symlink at the final component returns its own metadata
        // (PLAN §7.6: "STAT and LSTAT behave identically. Zift does
        // not expose dangling-symlink semantics distinct from stat.")
        // — and crucially, never crosses out of the jail to read the
        // target.
        var parent = self.vfs.openVerifiedParent(self.io, self.allocator, path.value) catch |err| {
            const status = parentErrorStatus(err);
            return replyStatus(self.channel, request_id, status, "denied or not found");
        };
        defer parent.deinit(self.io, self.allocator);

        // `listing.statAt` against the verified parent FD (PLAN §8.3
        // path-jail invariant) with `AT_SYMLINK_NOFOLLOW`. Returns
        // the full POSIX shape — mode bits with file-type encoded,
        // nlink, uid, gid, size, mtime — which `replyFullAttrs`
        // hands to the client so it can render `ls -l` / `stat`
        // output correctly.
        const info = listing.statAt(parent.parent.handle, parent.base) catch
            return replyStatus(self.channel, request_id, c.SSH_FX_NO_SUCH_FILE, "not found");
        try replyFullAttrs(self.channel, request_id, self.applyListingMode(info, path.value));
    }

    fn handleOpendir(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const path = parseString(payload) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
        if (!try self.ensureValidPath(request_id, path.value)) return;
        if (policy.check(self.user, .readdir, path.value) == .deny) {
            defer self.auditDenied("opendir", path.value);
            return replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }

        // Per-session handle cap (PLAN §8.4 DoS hardening). Check
        // BEFORE opening the dir so we don't have to clean up an FD on
        // the cap-exceeded path. Single-threaded per session, so no
        // TOCTOU between this check and the matching `addDirHandle`.
        if (self.handles.items.len >= max_handles_per_session) {
            defer self.auditFailed("opendir", path.value, "handle limit reached");
            return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "too many open handles");
        }

        const real = self.vfs.resolveExisting(self.io, self.allocator, path.value) catch {
            return replyStatus(self.channel, request_id, c.SSH_FX_NO_SUCH_FILE, "not found");
        };
        defer self.allocator.free(real);

        const dir = std.Io.Dir.openDirAbsolute(self.io, real, .{ .iterate = true }) catch {
            defer self.auditFailed("opendir", path.value, "open dir failed");
            return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "open dir failed");
        };
        self.vfs.verifyDir(self.io, dir) catch {
            dir.close(self.io);
            defer self.auditDenied("opendir", path.value);
            return replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        };
        const id = try self.addDirHandle(dir, path.value);
        defer self.auditOk("opendir", path.value, "");
        try replyHandle(self.channel, request_id, id);
    }

    fn handleReaddir(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const id = parseHandleId(payload) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad handle");
        const handle = self.findHandle(id, .dir) orelse return replyStatus(self.channel, request_id, c.SSH_FX_INVALID_HANDLE, "bad handle");
        if (handle.dir_done) return replyStatus(self.channel, request_id, c.SSH_FX_EOF, "eof");

        // Batch up to `batch_size` entries per READDIR reply. Smaller
        // than v0.1.x's 32 because we now carry per-entry longnames
        // (~120 bytes apiece) plus full attrs (~28 bytes), and the
        // wire-side packet buffer is 32 KiB. 16 × ~280 bytes ≈ 4.5
        // KiB worst-case packet, well under the limit, and the round-
        // trip cost of two READDIRs vs one is dominated by network
        // RTT regardless of batch size.
        const batch_size = 16;
        var entries: [batch_size]DirEntry = undefined;
        var count: usize = 0;

        const dir_fd = handle.dir.?.handle;
        // Wall-clock seconds for the "recent vs old" heuristic in
        // `formatLongname`. Captured once per READDIR call so all
        // entries in this batch use a consistent reference point.
        const now_secs: i64 = nowUnixSecs();

        // The dir_vpath invariant: every dir handle is created via
        // `addDirHandle(dir, vpath)` which always sets `dir_vpath` to
        // a heap-duped non-null string. If we observe a null here it
        // means a future refactor broke the invariant — fail loud.
        const dir_vpath = handle.dir_vpath orelse {
            return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "internal: dir handle missing vpath");
        };

        // Re-used across all entries in this batch. Sized to PATH_MAX
        // because `<dir-vpath>/<entry-name>` could be up to that long
        // in pathological cases. Hoisted out of the per-entry loop so
        // we don't push 4 KiB onto the stack 16 times per READDIR.
        var vpath_buf: [std.posix.PATH_MAX]u8 = undefined;

        while (count < entries.len) {
            const entry = handle.dir_iter.?.next(self.io) catch {
                return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "read dir failed");
            } orelse {
                handle.dir_done = true;
                break;
            };

            // v0.5.0: hide the staging directory from listings. Every
            // partner root has `<root>/.zift-staging/` (created lazily
            // on first upload). The path-validator already rejects
            // any virtual path containing this segment, so a partner
            // can't OPEN/REMOVE/STAT the staging dir or its contents.
            // But READDIR walks the real filesystem and would surface
            // the entry as "exists with no permissions" — leaking
            // the implementation detail and cluttering listings.
            // Skip it here, before the stat call, so it never reaches
            // the partner's view at all.
            if (std.mem.eql(u8, entry.name, vfs_mod.staging_dir_name)) continue;

            // `fstatat(dir_fd, name, AT_SYMLINK_NOFOLLOW)`. Stays inside
            // the path-jail because `dir_fd` was opened through the
            // verified-parent path and we never leave it. A symlink at
            // `name` returns the symlink's own metadata rather than
            // following it — so a partner can't trick us into reaching
            // outside the jail just to render a listing.
            const info = listing.statAt(dir_fd, entry.name) catch {
                // An entry vanishing between readdir and statAt (race
                // with another process unlinking it) is a normal
                // filesystem condition. Skip rather than failing the
                // whole READDIR — the next call sees the updated
                // directory.
                continue;
            };

            entries[count].name_len = entry.name.len;
            const name_copy_len = @min(entry.name.len, entries[count].name_buf.len);
            @memcpy(entries[count].name_buf[0..name_copy_len], entry.name[0..name_copy_len]);

            // `display_info` is what we expose to the client. In
            // `virtual` mode (the default since v0.3.0) we override
            // owner/group/mode with policy-derived values so the
            // partner sees themselves, not the OS user running zift.
            // In `reality` mode we pass the real inode-derived info
            // through unchanged. The size + mtime come from the real
            // inode either way (they're operationally relevant and
            // not host-identifying).
            var display_info = info;

            // uid/gid → name. The resolver caches lookups and falls
            // back to numeric on `getpwuid_r`/`getgrgid_r` failure.
            // `numeric_*` is the fallback scratch when the cache is
            // full or when libc returns no entry.
            var numeric_user: [16]u8 = undefined;
            var numeric_group: [16]u8 = undefined;
            var user_name: []const u8 = undefined;
            var group_name: []const u8 = undefined;

            switch (self.listing_mode) {
                .virtual => {
                    // Construct the full virtual path of this entry:
                    // `<dir-vpath>/<entry-name>`, the same shape
                    // `policy.check` consumes for any other op against
                    // this entry. We want the policy view to be
                    // CONSISTENT — what the partner sees in `ls -la`
                    // should match what the partner can actually do
                    // when they later try to OPEN/REMOVE/etc. that
                    // entry.
                    //
                    // Use `entry.name` (not the truncated
                    // `name_copy_len`) for the policy lookup because
                    // policy decisions must reflect the REAL filename
                    // — truncating could match the wrong rule (e.g. a
                    // 256-char name truncated to 255 chars might no
                    // longer match a literal prefix).
                    //
                    // On overflow (vpath > PATH_MAX, vanishingly
                    // unlikely after VFS validation but possible at
                    // the end of legal VFS path lengths) we fall back
                    // to the parent dir's vpath. This is INACCURATE:
                    // a child-specific deny rule (`deny **.exe`) could
                    // be lost. For now we accept the inaccuracy on
                    // the display side rather than allocating a
                    // fallback string at every entry. Tracked as a
                    // P3 follow-up — if real partners ever hit this
                    // path the fix is a heap allocation here.
                    const sep: []const u8 = if (std.mem.endsWith(u8, dir_vpath, "/")) "" else "/";
                    const vpath = std.fmt.bufPrint(&vpath_buf, "{s}{s}{s}", .{
                        dir_vpath, sep, entry.name,
                    }) catch dir_vpath;
                    display_info.mode = policy.policyDerivedMode(self.user, vpath, info.mode);
                    display_info.uid = 0;
                    display_info.gid = 0;
                    user_name = self.user.name;
                    group_name = "sftp";
                },
                .reality => {
                    user_name = self.name_resolver.user(info.uid, &numeric_user);
                    group_name = self.name_resolver.group(info.gid, &numeric_group);
                },
            }

            entries[count].info = display_info;

            const longname = listing.formatLongname(
                &entries[count].longname_buf,
                display_info,
                user_name,
                group_name,
                entry.name[0..name_copy_len],
                now_secs,
            );
            entries[count].longname_len = longname.len;

            count += 1;
        }

        if (count == 0) return replyStatus(self.channel, request_id, c.SSH_FX_EOF, "eof");
        try replyNames(self.channel, request_id, entries[0..count]);
    }

    fn handleOpen(self: *SftpState, request_id: u32, payload: []const u8) !void {
        var cursor = payload;
        const path = parseString(cursor) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
        if (!try self.ensureValidPath(request_id, path.value)) return;
        cursor = path.rest;
        if (cursor.len < 4) return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad flags");
        const flags = readU32(cursor[0..4]);

        // Per RFC draft-ietf-secsh-filexfer-02 §6.3: SSH_FXF_READ controls
        // read access; SSH_FXF_WRITE/APPEND/CREAT/TRUNC imply write. We
        // derive the requested access *bits* before anything else so policy
        // and the per-handle access record stay aligned.
        const want_write = (flags & @as(u32, @intCast(
            c.SSH_FXF_WRITE | c.SSH_FXF_APPEND | c.SSH_FXF_CREAT | c.SSH_FXF_TRUNC,
        ))) != 0;
        // SFTP clients (notably OpenSSH `sftp get`) sometimes send no
        // explicit flags, expecting read-mode by default. Honor that.
        var want_read = (flags & @as(u32, @intCast(c.SSH_FXF_READ))) != 0;
        if (!want_read and !want_write) want_read = true;

        // Both policies must allow the bits the client requested. PLAN §6.3.
        if (want_write and policy.check(self.user, .open_write, path.value) == .deny) {
            defer self.auditDenied("open_write", path.value);
            return replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }
        if (want_read and policy.check(self.user, .open_read, path.value) == .deny) {
            defer self.auditDenied("open_read", path.value);
            return replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }

        const op_label: []const u8 = if (want_write) "open_write" else "open_read";

        // Per-session handle cap (PLAN §8.4 DoS hardening). Same
        // pre-check as `handleOpendir` — refuse before opening so
        // we never have to clean up an FD on the cap-exceeded path.
        if (self.handles.items.len >= max_handles_per_session) {
            defer self.auditFailed(op_label, path.value, "handle limit reached");
            return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "too many open handles");
        }

        const want_creat = (flags & @as(u32, @intCast(c.SSH_FXF_CREAT))) != 0;
        const want_excl = (flags & @as(u32, @intCast(c.SSH_FXF_EXCL))) != 0;
        const want_trunc = (flags & @as(u32, @intCast(c.SSH_FXF_TRUNC))) != 0;
        const want_append = (flags & @as(u32, @intCast(c.SSH_FXF_APPEND))) != 0;

        // Resolve the parent directory through `openVerifiedParent`,
        // which canonicalizes through any symlinks in the parent path
        // and verifies the result is inside the user's jail. From here
        // on we operate exclusively on `parent.parent` (an FD) plus
        // the basename string — never on a real-path string that the
        // OS could follow back outside the jail. PLAN §8.3.
        var parent = self.vfs.openVerifiedParent(self.io, self.allocator, path.value) catch |err| {
            const status = parentErrorStatus(err);
            defer {
                if (status == c.SSH_FX_PERMISSION_DENIED) self.auditDenied(op_label, path.value)
                else self.auditFailed(op_label, path.value, @errorName(err));
            }
            return replyStatus(self.channel, request_id, status, "denied or not found");
        };
        defer parent.deinit(self.io, self.allocator);

        const open_mode: std.Io.Dir.OpenFileOptions.Mode = blk: {
            if (want_write and want_read) break :blk .read_write;
            if (want_write) break :blk .write_only;
            break :blk .read_only;
        };

        // First open the existing basename with O_NOFOLLOW. A symlink at
        // the final component is rejected unconditionally — the spec
        // invariant is that an SFTP operation never affects state outside
        // the jail, and following a symlink at the basename would let
        // the kernel reach files we never validated.
        var file = parent.parent.openFile(self.io, parent.base, .{
            .mode = open_mode,
            .follow_symlinks = false,
            .allow_directory = false,
        }) catch |err| switch (err) {
            error.FileNotFound => {
                if (!want_creat or !want_write) {
                    return replyStatus(self.channel, request_id, c.SSH_FX_NO_SUCH_FILE, "not found");
                }
                // v0.5.0 atomic-upload: create-on-non-existent goes
                // through a staging file in `<root>/.zift-staging/`,
                // not the target path. The fd we hand back to the
                // partner is the staging file's; partner's WRITE
                // requests land there. At CLOSE time, we atomically
                // rename staging → target. The operator's view of
                // the partner directory never shows a partial file:
                // either the target is absent (upload in progress)
                // or it is fully present (CLOSE succeeded).
                //
                // Failure modes are bounded: if the partner
                // disconnects mid-upload, `closeHandle`'s orphan-
                // cleanup unlinks the staging file. If the rename
                // at CLOSE fails for any reason, the staging file
                // is also unlinked — no half-states leak.
                var staging = self.ensureStagingDir() catch {
                    defer self.auditFailed(op_label, path.value, "staging dir unavailable");
                    return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "open failed");
                };

                var staging_name_buf: [32]u8 = undefined;
                generateStagingName(&staging_name_buf) catch {
                    // Refusing to continue with a non-random staging
                    // name is the safe choice — every other guarantee
                    // (no collision, no predictable target paths) hangs
                    // off this entropy. Vanishingly rare in practice
                    // (only fires on Linux < 3.17 with /dev/urandom
                    // also unavailable, or post-fork crypto state
                    // damage) but the failure mode must not be silent.
                    defer self.auditFailed(op_label, path.value, "no entropy for staging name");
                    return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "open failed");
                };
                const staging_name = staging_name_buf[0..];

                const created = staging.createFile(self.io, staging_name, .{
                    .read = want_read,
                    .truncate = false,
                    .exclusive = true,
                    // Confidentiality: partial-upload bytes must
                    // not be readable by other local users on the
                    // host. Default `createFile` mode is 0o666
                    // masked by umask, which can land at 0o644 —
                    // world-readable. Force 0o600 so only the
                    // user zift runs as can see staging files
                    // before the partner publishes them.
                    .permissions = .fromMode(0o600),
                }) catch {
                    defer self.auditFailed(op_label, path.value, "staging create failed");
                    return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "open failed");
                };

                // Truncate request is moot here (we just created an
                // empty file). EXCL is honored at CLOSE-time via
                // the existence re-check.
                const id = self.addStagedHandle(
                    created,
                    path.value,
                    staging_name,
                    want_read,
                    want_write,
                    want_append,
                    want_excl,
                ) catch |alloc_err| {
                    // addStagedHandle failed (OOM in dupe). The
                    // errdefer inside it closes `created`, but we
                    // also need to unlink the file we created in
                    // staging — otherwise it'd be an orphan.
                    staging.deleteFile(self.io, staging_name) catch {};
                    defer self.auditFailed(op_label, path.value, @errorName(alloc_err));
                    return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "open failed");
                };
                defer self.auditOk(op_label, path.value, "staged");
                return replyHandle(self.channel, request_id, id);
            },
            error.SymLinkLoop => {
                // Final component IS a symlink. Refuse outright.
                defer self.auditDenied(op_label, path.value);
                return replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
            },
            else => {
                defer self.auditFailed(op_label, path.value, @errorName(err));
                return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "open failed");
            },
        };

        // EXCL means "create exclusively". The file existed → fail.
        if (want_creat and want_excl) {
            file.close(self.io);
            return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "exists");
        }

        // Belt-and-suspenders FD verification. If the platform's
        // O_NOFOLLOW had any quirk, this catches a fd that resolves
        // outside the jail before any state-changing operation runs.
        self.vfs.verifyFile(self.io, file) catch {
            file.close(self.io);
            defer self.auditDenied(op_label, path.value);
            return replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        };

        // CLOBBER RULE (v0.4.0): we got here because OPEN(write) on an
        // EXISTING file succeeded. The partner is about to either
        // truncate it (TRUNC), partially overwrite it (pwrite at
        // offset), or append to it (APPEND) — three different ways
        // to mutate someone else's existing content. All of them
        // require the partner to have BOTH "add"-style (already
        // checked above as `.open_write`) AND `.remove` permission
        // on this path. The `.remove` half is the new check: it
        // generalizes the v0.3.0 rename-overwrite guard to every
        // write-open of an existing entry. Without this, an
        // `add`-only partner could destroy the operator's files via
        // OPEN(write+TRUNC), pwrite-at-offset, or APPEND mode — see
        // attack scenarios B3, B4, B5 in the threat model.
        //
        // Race note: the existence check is implicit in "openFile
        // succeeded vs returned FileNotFound" — no separate stat,
        // so no TOCTOU window between probe and act. The fd we
        // hold IS the existing file we're checking authorization
        // for.
        if (want_write and policy.check(self.user, .remove, path.value) == .deny) {
            file.close(self.io);
            defer self.auditDenied(op_label, path.value);
            return replyStatus(
                self.channel,
                request_id,
                c.SSH_FX_PERMISSION_DENIED,
                "would clobber an existing entry; partner lacks remove",
            );
        }

        // Truncation only after the FD is proven inside the jail
        // AND the clobber check has passed.
        if (want_trunc and want_write) {
            file.setLength(self.io, 0) catch {
                file.close(self.io);
                defer self.auditFailed(op_label, path.value, "truncate failed");
                return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "truncate failed");
            };
        }

        const id = try self.addFileHandle(file, want_read, want_write, want_append);
        defer self.auditOk(op_label, path.value, "");
        try replyHandle(self.channel, request_id, id);
    }

    fn handleRead(self: *SftpState, request_id: u32, payload: []const u8) !void {
        var cursor = payload;
        const id = parseHandleId(cursor) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad handle");
        cursor = cursor[8..];
        if (cursor.len < 12) return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad read");
        const offset = readU64(cursor[0..8]);
        const len = @min(readU32(cursor[8..12]), 32 * 1024);
        const handle = self.findHandle(id, .file) orelse return replyStatus(self.channel, request_id, c.SSH_FX_INVALID_HANDLE, "bad handle");

        // Per PLAN §6.3, `read` permission gates SSH_FXP_READ. Enforcing
        // this only at OPEN time would let a write-only-permitted client
        // exfiltrate via the same handle they wrote to.
        if (!handle.can_read) {
            defer self.auditDenied("read", null);
            return replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }

        var buf = try self.allocator.alloc(u8, len);
        defer self.allocator.free(buf);
        const n = handle.file.?.readPositionalAll(self.io, buf, offset) catch {
            return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "read failed");
        };
        if (n == 0) return replyStatus(self.channel, request_id, c.SSH_FX_EOF, "eof");
        try replyData(self.channel, request_id, buf[0..n]);
    }

    fn handleWrite(self: *SftpState, request_id: u32, payload: []const u8) !void {
        var cursor = payload;
        const id = parseHandleId(cursor) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad handle");
        cursor = cursor[8..];
        if (cursor.len < 8) return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad write");
        const client_offset = readU64(cursor[0..8]);
        const data = parseString(cursor[8..]) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad data");
        const handle = self.findHandle(id, .file) orelse return replyStatus(self.channel, request_id, c.SSH_FX_INVALID_HANDLE, "bad handle");

        // Per PLAN §6.3, `write` permission gates SSH_FXP_WRITE.
        if (!handle.can_write) {
            defer self.auditDenied("write", null);
            return replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }

        // SSH_FXF_APPEND mode (PLAN §7.6): the client's offset is
        // ignored; every write goes to the current end-of-file. Stat
        // the open fd to learn the current size, then pwrite there.
        // SFTP handles are single-threaded per session, so no other
        // worker can race the size between stat and write on this fd.
        const offset: u64 = blk: {
            if (!handle.is_append) break :blk client_offset;
            const file_stat = handle.file.?.stat(self.io) catch
                return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "stat for append failed");
            break :blk file_stat.size;
        };

        handle.file.?.writePositionalAll(self.io, data.value, offset) catch {
            return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "write failed");
        };
        try replyStatus(self.channel, request_id, c.SSH_FX_OK, "ok");
    }

    fn handleClose(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const id = parseHandleId(payload) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad handle");
        // Walk by index (not pointer) so we can `swapRemove` the slot
        // when we find it. swapRemove keeps the array dense — closed
        // handles free their slot, so a long-running session that
        // opens-and-closes 10000 files still uses bounded memory and
        // can keep opening up to the per-session cap.
        var i: usize = 0;
        while (i < self.handles.items.len) : (i += 1) {
            if (self.handles.items[i].id == id) {
                const handle = &self.handles.items[i];

                // v0.5.0 staging-rename: if this is a staged handle,
                // CLOSE means "publish the upload" — atomically
                // rename the staging file to its real target.
                // We must do this BEFORE closeHandle (which would
                // unlink the staging file as orphan cleanup if the
                // staging_basename is still set).
                if (handle.staging_basename != null and handle.staging_target_vpath != null) {
                    // CRITICAL: capture the target vpath into a
                    // stack-local copy BEFORE closeHandle frees the
                    // heap allocation, and BEFORE swapRemove moves
                    // the slot. Otherwise the audit log path below
                    // would dereference a stale pointer to either
                    // freed memory (closeHandle freed the buffer)
                    // or a different handle (swapRemove relocated
                    // a sibling slot into this index). v0.5.0
                    // shipped this UAF; v0.5.1 fixes it. Buffer
                    // sized to the path validator's 4096-byte
                    // ceiling — silent truncation here would
                    // collide audit entries for two attacker-
                    // controlled paths sharing a prefix, defeating
                    // the audit log's evidentiary value.
                    var audit_target_buf: [4096]u8 = undefined;
                    const audit_target = blk: {
                        const tv = handle.staging_target_vpath.?;
                        const n = @min(tv.len, audit_target_buf.len);
                        @memcpy(audit_target_buf[0..n], tv[0..n]);
                        break :blk audit_target_buf[0..n];
                    };

                    const close_status = self.publishStagedHandle(handle) catch |err| {
                        // Publish failed. closeHandle will then
                        // unlink the staging file (since
                        // staging_basename is still set). The
                        // partner gets a FAILURE reply but the
                        // session continues.
                        self.closeHandle(handle);
                        _ = self.handles.swapRemove(i);
                        self.auditFailed("close", audit_target, @errorName(err));
                        return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "publish failed");
                    };
                    // publishStagedHandle clears staging_basename
                    // on success so closeHandle doesn't unlink the
                    // (now-renamed) target.
                    self.closeHandle(handle);
                    _ = self.handles.swapRemove(i);

                    // Map the wire-status to a human-readable reply
                    // message so audit logs and partner errors agree
                    // about WHY a close failed. v0.5.0 used the
                    // literal "ok" for every status; that confused
                    // operators reading audit lines for a denied or
                    // failed publish.
                    const reply_msg: []const u8 = switch (close_status) {
                        c.SSH_FX_OK => "ok",
                        c.SSH_FX_PERMISSION_DENIED => "publish denied: target appeared and partner lacks remove",
                        c.SSH_FX_FAILURE => "publish failed: target appeared with EXCL set",
                        else => "publish status",
                    };
                    if (close_status == c.SSH_FX_OK) {
                        self.auditOk("publish", audit_target, "");
                    }
                    return replyStatus(self.channel, request_id, close_status, reply_msg);
                }

                self.closeHandle(handle);
                _ = self.handles.swapRemove(i);
                return replyStatus(self.channel, request_id, c.SSH_FX_OK, "ok");
            }
        }
        try replyStatus(self.channel, request_id, c.SSH_FX_INVALID_HANDLE, "bad handle");
    }

    /// Rename a staged file from `<root>/.zift-staging/<basename>`
    /// to its target virtual path. Called from `handleClose`. On
    /// success, clears `staging_basename` so the subsequent
    /// `closeHandle` won't try to unlink the (now-renamed) file.
    /// On any failure, leaves `staging_basename` intact so the
    /// caller's cleanup unlinks the orphan.
    fn publishStagedHandle(self: *SftpState, handle: *Handle) !c_int {
        const target_vpath = handle.staging_target_vpath.?;
        const staging_basename = handle.staging_basename.?;
        const staging = self.staging_dir.?;

        // Close the file fd FIRST. POSIX rename atomically replaces
        // the target inode whether or not the source file is open,
        // but closing first means the rename happens against a
        // freshly-flushed file (no half-buffered state) and any
        // delayed-write errors surface here, before the rename.
        if (handle.file) |f| {
            f.close(self.io);
            handle.file = null;
        }

        // Re-resolve the target's parent (the destination dir may
        // have been removed/created by another session during the
        // upload). openVerifiedParent re-runs the path-jail dance,
        // so even if the operator restructured the partner root
        // mid-upload, the rename target is still inside the jail.
        var to_parent = self.vfs.openVerifiedParent(self.io, self.allocator, target_vpath) catch |err| {
            return err;
        };
        defer to_parent.deinit(self.io, self.allocator);

        // DEBUG INSTRUMENTATION (v0.5.3 root-cause hunt). Compare
        // statAt and faccessat side by side. Both should agree on
        // existence. If they disagree, the buggy path is statAt;
        // log the actual rc/errno/fields so we can determine
        // whether the kernel returned ENOENT (errno mishandling)
        // or returned 0 (statx-of-a-different-file or kernel bug).
        const stat_result = listing.statAt(to_parent.parent.handle, to_parent.base);
        const access_exists = existsAtParent(to_parent.parent.handle, to_parent.base);
        const stat_says_exists = if (stat_result) |info| blk: {
            std.debug.print("[v053] statAt OK target={s} mode=0x{x} size={d} nlink={d} uid={d}\n", .{
                target_vpath, info.mode, info.size, info.nlink, info.uid,
            });
            break :blk true;
        } else |err| blk: {
            std.debug.print("[v053] statAt err target={s} err={s}\n", .{ target_vpath, @errorName(err) });
            break :blk false;
        };
        std.debug.print("[v053] faccessat says exists={} for target={s}\n", .{ access_exists, target_vpath });
        if (stat_says_exists != access_exists) {
            std.debug.print("[v053] !!! DISAGREEMENT: statAt={} access={}\n", .{ stat_says_exists, access_exists });
        }
        // Use the BUGGY path so we reproduce the v0.4.0+ symptom on
        // CI and the artifact upload-on-failure step archives the
        // diagnostic prints from above.
        const dest_exists = stat_says_exists;

        if (dest_exists) {
            if (handle.staging_excl) {
                // EXCL was set at OPEN — fail if target appeared.
                self.auditDenied("close", target_vpath);
                return c.SSH_FX_FAILURE;
            }
            if (policy.check(self.user, .remove, target_vpath) == .deny) {
                self.auditDenied("close", target_vpath);
                return c.SSH_FX_PERMISSION_DENIED;
            }
        }

        // The atomic publish step.
        std.Io.Dir.rename(
            staging,
            staging_basename,
            to_parent.parent,
            to_parent.base,
            self.io,
        ) catch |err| return err;

        // Rename succeeded — clear staging_basename so closeHandle
        // doesn't unlink the file we just published.
        self.allocator.free(staging_basename);
        handle.staging_basename = null;

        return c.SSH_FX_OK;
    }

    fn handleMkdir(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const path = parseString(payload) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
        if (!try self.ensureValidPath(request_id, path.value)) return;
        if (policy.check(self.user, .mkdir, path.value) == .deny) {
            defer self.auditDenied("mkdir", path.value);
            return replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }
        var parent = self.vfs.openVerifiedParent(self.io, self.allocator, path.value) catch |err| {
            const status = parentErrorStatus(err);
            defer {
                if (status == c.SSH_FX_PERMISSION_DENIED) self.auditDenied("mkdir", path.value)
                else self.auditFailed("mkdir", path.value, @errorName(err));
            }
            return replyStatus(self.channel, request_id, status, "denied or not found");
        };
        defer parent.deinit(self.io, self.allocator);

        parent.parent.createDir(self.io, parent.base, .default_dir) catch {
            defer self.auditFailed("mkdir", path.value, "createDir failed");
            return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "mkdir failed");
        };
        defer self.auditOk("mkdir", path.value, "");
        try replyStatus(self.channel, request_id, c.SSH_FX_OK, "ok");
    }

    fn handleRemove(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const path = parseString(payload) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
        if (!try self.ensureValidPath(request_id, path.value)) return;
        if (policy.check(self.user, .remove, path.value) == .deny) {
            defer self.auditDenied("remove", path.value);
            return replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }
        var parent = self.vfs.openVerifiedParent(self.io, self.allocator, path.value) catch |err| {
            const status = parentErrorStatus(err);
            defer {
                if (status == c.SSH_FX_PERMISSION_DENIED) self.auditDenied("remove", path.value)
                else self.auditFailed("remove", path.value, @errorName(err));
            }
            return replyStatus(self.channel, request_id, status, "denied or not found");
        };
        defer parent.deinit(self.io, self.allocator);

        parent.parent.deleteFile(self.io, parent.base) catch {
            defer self.auditFailed("remove", path.value, "deleteFile failed");
            return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "remove failed");
        };
        defer self.auditOk("remove", path.value, "");
        try replyStatus(self.channel, request_id, c.SSH_FX_OK, "ok");
    }

    fn handleRmdir(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const path = parseString(payload) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
        if (!try self.ensureValidPath(request_id, path.value)) return;
        if (policy.check(self.user, .rmdir, path.value) == .deny) {
            defer self.auditDenied("rmdir", path.value);
            return replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }
        var parent = self.vfs.openVerifiedParent(self.io, self.allocator, path.value) catch |err| {
            const status = parentErrorStatus(err);
            defer {
                if (status == c.SSH_FX_PERMISSION_DENIED) self.auditDenied("rmdir", path.value)
                else self.auditFailed("rmdir", path.value, @errorName(err));
            }
            return replyStatus(self.channel, request_id, status, "denied or not found");
        };
        defer parent.deinit(self.io, self.allocator);

        parent.parent.deleteDir(self.io, parent.base) catch {
            defer self.auditFailed("rmdir", path.value, "deleteDir failed");
            return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "rmdir failed");
        };
        defer self.auditOk("rmdir", path.value, "");
        try replyStatus(self.channel, request_id, c.SSH_FX_OK, "ok");
    }

    fn handleRename(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const from = parseString(payload) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad source");
        const to = parseString(from.rest) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad destination");
        if (!try self.ensureValidPath(request_id, from.value)) return;
        if (!try self.ensureValidPath(request_id, to.value)) return;
        if (policy.checkRename(self.user, from.value, to.value) == .deny) {
            defer self.auditDenied("rename", from.value);
            return replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }
        var from_parent = self.vfs.openVerifiedParent(self.io, self.allocator, from.value) catch |err| {
            const status = parentErrorStatus(err);
            defer {
                if (status == c.SSH_FX_PERMISSION_DENIED) self.auditDenied("rename", from.value)
                else self.auditFailed("rename", from.value, @errorName(err));
            }
            return replyStatus(self.channel, request_id, status, "denied or not found");
        };
        defer from_parent.deinit(self.io, self.allocator);
        var to_parent = self.vfs.openVerifiedParent(self.io, self.allocator, to.value) catch |err| {
            const status = parentErrorStatus(err);
            defer {
                if (status == c.SSH_FX_PERMISSION_DENIED) self.auditDenied("rename", to.value)
                else self.auditFailed("rename", to.value, @errorName(err));
            }
            return replyStatus(self.channel, request_id, status, "denied or not found");
        };
        defer to_parent.deinit(self.io, self.allocator);

        // POSIX `rename(2)` ATOMICALLY OVERWRITES the destination if
        // it exists — meaning a partner with `rename` permission can
        // destroy any existing entry by `rename src dest`, even if
        // they have NO `remove` permission. This breaks the v0.3.0
        // compound-verb story (where `add` grants rename but NOT
        // remove): without this guard, `add`-only access would
        // silently grant equivalent-to-remove power via overwrite.
        //
        // Guard: `lstat` the destination via the verified parent FD,
        // not `openFile` — a directory, symlink, FIFO, socket, or
        // device entry at the destination would all be missed by
        // openFile (which only succeeds on regular openable files)
        // but is correctly detected as "exists" by lstat. If the
        // destination exists in any form, require `.remove`
        // permission on the destination path.
        //
        // Bounded TOCTOU: this stat-then-rename window is racy. Two
        // SFTP sessions from the same partner (or two pipelined
        // requests on one session) could exploit it: session A stats
        // and finds dest absent, session B creates dest, session A
        // proceeds with rename and overwrites B's entry. The race
        // is closed hermetically only by Linux's `renameat2(...,
        // RENAME_NOREPLACE)` and macOS's `renamex_np(...,
        // RENAME_EXCL)`. We use the portable check today and accept
        // the bounded race. Tracked as a P2 follow-up to switch to
        // the platform-specific no-replace primitives.
        const dest_exists = blk: {
            _ = listing.statAt(to_parent.parent.handle, to_parent.base) catch |err| switch (err) {
                error.NotFound => break :blk false,
                else => {
                    defer self.auditFailed("rename", to.value, "stat dest failed");
                    return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "stat dest failed");
                },
            };
            break :blk true;
        };
        if (dest_exists and policy.check(self.user, .remove, to.value) == .deny) {
            // Audit against the DESTINATION path — that's where the
            // policy denied us (overwrite requires `remove` on dest).
            // Auditing the source would mislead operators reading
            // logs into thinking the source rule was wrong.
            defer self.auditDenied("rename", to.value);
            return replyStatus(
                self.channel,
                request_id,
                c.SSH_FX_PERMISSION_DENIED,
                "rename would overwrite an existing entry; partner lacks remove on destination",
            );
        }

        std.Io.Dir.rename(from_parent.parent, from_parent.base, to_parent.parent, to_parent.base, self.io) catch {
            defer self.auditFailed("rename", from.value, "rename failed");
            return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "rename failed");
        };
        defer self.auditOk("rename", from.value, to.value);
        try replyStatus(self.channel, request_id, c.SSH_FX_OK, "ok");
    }

    fn addDirHandle(self: *SftpState, dir: std.Io.Dir, vpath: []const u8) !u32 {
        // ON FAILURE we MUST close `dir` — the caller has already
        // transferred ownership to us. Without this errdefer, an
        // OOM (or any future failure path) at append time leaks
        // both the heap allocation and the open dir-fd until the
        // session ends. Same audit done for `addFileHandle`.
        var dir_local = dir;
        errdefer dir_local.close(self.io);

        const id = self.nextHandleId();
        // dup the vpath so it survives the caller's `path` going out of
        // scope (the parser hands us a slice into the SFTP packet
        // buffer that gets reused on the next request).
        const vpath_owned = try self.allocator.dupe(u8, vpath);
        errdefer self.allocator.free(vpath_owned);
        try self.handles.append(self.allocator, .{
            .id = id,
            .kind = .dir,
            .dir = dir_local,
            .dir_iter = dir_local.iterate(),
            .dir_vpath = vpath_owned,
        });
        return id;
    }

    fn addFileHandle(
        self: *SftpState,
        file: std.Io.File,
        can_read: bool,
        can_write: bool,
        is_append: bool,
    ) !u32 {
        // Same fd-leak guard as `addDirHandle`: the caller has
        // transferred ownership of `file` to us, so an append failure
        // (OOM, etc.) must close it. Without errdefer the fd would
        // leak until session shutdown.
        var file_local = file;
        errdefer file_local.close(self.io);

        const id = self.nextHandleId();
        try self.handles.append(self.allocator, .{
            .id = id,
            .kind = .file,
            .file = file_local,
            .can_read = can_read,
            .can_write = can_write,
            .is_append = is_append,
        });
        return id;
    }

    /// v0.5.0 staging-rename: register a write handle whose underlying
    /// fd points at a randomly-named file in `<root>/.zift-staging/`,
    /// not at the target path. The Handle remembers the target so
    /// CLOSE can atomically rename staging → target. If the partner
    /// disconnects before CLOSE, `closeHandle` will unlink the
    /// staging file as orphan cleanup.
    fn addStagedHandle(
        self: *SftpState,
        file: std.Io.File,
        target_vpath: []const u8,
        staging_basename: []const u8,
        can_read: bool,
        can_write: bool,
        is_append: bool,
        excl: bool,
    ) !u32 {
        var file_local = file;
        errdefer file_local.close(self.io);

        const target_owned = try self.allocator.dupe(u8, target_vpath);
        errdefer self.allocator.free(target_owned);
        const staging_owned = try self.allocator.dupe(u8, staging_basename);
        errdefer self.allocator.free(staging_owned);

        const id = self.nextHandleId();
        try self.handles.append(self.allocator, .{
            .id = id,
            .kind = .file,
            .file = file_local,
            .can_read = can_read,
            .can_write = can_write,
            .is_append = is_append,
            .staging_target_vpath = target_owned,
            .staging_basename = staging_owned,
            .staging_excl = excl,
        });
        return id;
    }

    /// Lazily open `<root>/.zift-staging/`, creating it if needed.
    /// First call per-session pays the mkdir+open cost; subsequent
    /// calls just return the cached handle. Sessions that never
    /// stage anything (read-only partners, all uploads-to-existing-
    /// files clobber paths) never create the dir at all.
    fn ensureStagingDir(self: *SftpState) !std.Io.Dir {
        if (self.staging_dir) |dir| return dir;
        const dir = try self.vfs.openStagingDir(self.io);
        self.staging_dir = dir;
        return dir;
    }

    /// Generate a stage-unique filename: 32 hex chars from the OS's
    /// CSPRNG. 16 random bytes = 2^128 namespace, so collision
    /// probability across all concurrent staging files for a partner
    /// is negligible: max-handles-per-session caps the in-flight
    /// count at 256, and 256 random draws from a 2^128 space
    /// collide with probability ~256² / 2 / 2^128 ≈ 2^-113.
    ///
    /// Robustness contract (v0.5.1):
    ///   - On any platform, this MUST either fill `raw` with high-
    ///     entropy bytes or return an error. Never hex-encode
    ///     undefined bytes — that would produce predictable
    ///     filenames and break the staging-collision argument.
    ///   - Linux: prefer `getrandom(2)` (kernel 3.17+); on older
    ///     kernels (`ENOSYS`) fall back to reading `/dev/urandom`.
    ///     Handle `EINTR` (signal during getrandom) by retrying.
    ///   - macOS / *BSD: `arc4random_buf(3)` is documented to
    ///     never fail, so a single call is sufficient.
    fn generateStagingName(out: *[32]u8) !void {
        var raw: [16]u8 = undefined;
        try fillRandomBytes(&raw);
        const hex = "0123456789abcdef";
        for (raw, 0..) |b, i| {
            out[i * 2 + 0] = hex[(b >> 4) & 0xF];
            out[i * 2 + 1] = hex[b & 0xF];
        }
    }

    /// Block until `buf` is full of cryptographic-grade random bytes
    /// or return `error.RandomFailed` if the OS can't provide them.
    /// Used by staging-name generation; must NEVER return
    /// silently-zeroed or partially-filled output.
    fn fillRandomBytes(buf: []u8) !void {
        if (@import("builtin").os.tag == .linux) {
            // Loop until the buffer is full. `getrandom` short-reads
            // only when interrupted by a signal; we retry on EINTR
            // and fall back to /dev/urandom on ENOSYS (Linux < 3.17,
            // e.g. very old embedded distros).
            var filled: usize = 0;
            while (filled < buf.len) {
                const rc = std.os.linux.getrandom(
                    buf.ptr + filled,
                    buf.len - filled,
                    0,
                );
                switch (std.posix.errno(rc)) {
                    .SUCCESS => {
                        // Defense against a hypothetical
                        // SUCCESS+rc=0 return — would otherwise
                        // spin forever. The kernel doesn't return
                        // this today, but the loop guard is cheap.
                        if (rc == 0) return error.RandomFailed;
                        filled += @intCast(rc);
                    },
                    .INTR => continue,
                    // ENOSYS happens on the first call, before any
                    // bytes are filled; the slice we pass is
                    // therefore always `buf` here, not `buf[filled..]`.
                    // But forwarding the unfilled tail is correct
                    // even if a future kernel quirk made this
                    // mid-loop reachable.
                    .NOSYS => return readFromUrandom(buf[filled..]),
                    else => return error.RandomFailed,
                }
            }
        } else {
            // arc4random_buf is documented to never fail.
            std.c.arc4random_buf(buf.ptr, buf.len);
        }
    }

    /// Linux fallback when `getrandom(2)` is unavailable (kernel <
    /// 3.17 — vanishingly rare in 2026 but worth handling correctly).
    /// Read from `/dev/urandom` directly via raw syscalls (Zig 0.16's
    /// std.posix doesn't expose `open` on all targets, and we don't
    /// need to thread an Io through this fallback). Once the entropy
    /// pool is seeded — which any running userspace satisfies —
    /// `/dev/urandom` never blocks and short-reads only on signal.
    fn readFromUrandom(buf: []u8) !void {
        const linux = std.os.linux;
        const path: [*:0]const u8 = "/dev/urandom";
        const fd_rc = linux.open(path, .{ .ACCMODE = .RDONLY }, 0);
        switch (std.posix.errno(fd_rc)) {
            .SUCCESS => {},
            else => return error.RandomFailed,
        }
        const fd: i32 = @intCast(fd_rc);
        defer _ = linux.close(fd);

        var filled: usize = 0;
        while (filled < buf.len) {
            const rc = linux.read(fd, buf.ptr + filled, buf.len - filled);
            switch (std.posix.errno(rc)) {
                .SUCCESS => {
                    if (rc == 0) return error.RandomFailed;
                    filled += @intCast(rc);
                },
                .INTR => continue,
                else => return error.RandomFailed,
            }
        }
    }

    fn nextHandleId(self: *SftpState) u32 {
        const id = self.next_handle;
        self.next_handle += 1;
        return id;
    }

    fn findHandle(self: *SftpState, id: u32, kind: HandleKind) ?*Handle {
        for (self.handles.items) |*handle| {
            if (handle.id == id and handle.kind == kind) return handle;
        }
        return null;
    }

    fn closeHandle(self: *SftpState, handle: *Handle) void {
        if (handle.dir) |dir| dir.close(self.io);
        if (handle.file) |file| file.close(self.io);
        if (handle.dir_vpath) |vp| self.allocator.free(vp);
        // Staging cleanup: if a staged handle reaches closeHandle WITH
        // staging_basename still set, it means CLOSE never ran the
        // rename-to-target step (partner disconnected mid-upload,
        // or the rename itself failed and we left the staging file
        // for cleanup). Either way, unlink the staging file so it
        // doesn't accumulate as an orphan. Best-effort — if the
        // unlink fails (FS error, dir gone) there's nothing useful
        // we can do besides leak the bytes.
        if (handle.staging_basename) |sb| {
            if (self.staging_dir) |*dir| {
                dir.deleteFile(self.io, sb) catch {};
            }
            self.allocator.free(sb);
        }
        if (handle.staging_target_vpath) |tv| self.allocator.free(tv);
        handle.dir = null;
        handle.file = null;
        handle.dir_vpath = null;
        handle.staging_basename = null;
        handle.staging_target_vpath = null;
    }
};

/// One directory entry's worth of READDIR reply state. All buffers
/// live inline so we can stack-allocate the batch — no per-entry
/// heap traffic in the hot path.
///
/// `name_buf` holds the raw entry name (NAME_MAX = 255 bytes on
/// Linux/macOS); `longname_buf` holds the formatted GNU-`ls`-style
/// line we send as the SFTP `longname`. The 320-byte longname budget
/// is `name_max + ~64` to fit the "permissions nlink owner group
/// size mtime" header alongside the longest reasonable filename.
const DirEntry = struct {
    name_buf: [256]u8 = undefined,
    name_len: usize = 0,
    longname_buf: [320]u8 = undefined,
    longname_len: usize = 0,
    info: listing.EntryInfo = .{
        .mode = 0,
        .nlink = 0,
        .uid = 0,
        .gid = 0,
        .size = 0,
        .mtime_secs = 0,
    },
};

fn parentErrorStatus(err: anyerror) c_int {
    return switch (err) {
        error.PathTraversal, error.InvalidPath => c.SSH_FX_PERMISSION_DENIED,
        error.OutOfMemory => c.SSH_FX_FAILURE,
        else => c.SSH_FX_NO_SUCH_FILE,
    };
}

fn readPacket(channel: c.ssh_channel, payload_buf: []u8) ![]u8 {
    var len_buf: [4]u8 = undefined;
    try readExact(channel, &len_buf);
    const len = readU32(&len_buf);
    if (len > payload_buf.len) return error.LibsshFailure;
    const payload = payload_buf[0..len];
    try readExact(channel, payload);
    return payload;
}

fn readExact(channel: c.ssh_channel, out: []u8) !void {
    var offset: usize = 0;
    while (offset < out.len) {
        const n = c.ssh_channel_read(channel, out[offset..].ptr, @intCast(out.len - offset), 0);
        if (n <= 0) return error.LibsshFailure;
        offset += @intCast(n);
    }
}

/// Idle-timeout-aware variant of `readPacket`. Returns `error.IdleTimeout`
/// if the per-session idle-timeout (PLAN §6.2) elapses without progress.
fn readPacketTimed(state: *SftpState, payload_buf: []u8) ![]u8 {
    var len_buf: [4]u8 = undefined;
    try readExactTimed(state, &len_buf);
    const len = readU32(&len_buf);

    // PLAN §7.6: maximum SFTP packet size is 256 KiB. If the declared
    // length exceeds that, reply `SSH_FX_BAD_MESSAGE` for the request
    // (so the client gets a structured rejection it can log) and then
    // tear down the session — we cannot resync because we'd have to
    // drain `len` bytes of attacker-controlled traffic to find the
    // next packet boundary.
    if (len > payload_buf.len) {
        var head: [5]u8 = undefined;
        // Best-effort: try to read msg_type + request_id so we can
        // reference the original request in our reply. If even that
        // fails, just disconnect — the client violated the protocol.
        readExactTimed(state, &head) catch return error.LibsshFailure;
        const request_id = readU32(head[1..5]);
        replyStatus(state.channel, request_id, c.SSH_FX_BAD_MESSAGE, "packet too large") catch {};
        return error.LibsshFailure;
    }

    const payload = payload_buf[0..len];
    try readExactTimed(state, payload);
    return payload;
}

fn readExactTimed(state: *SftpState, out: []u8) !void {
    // Slice ssh_channel_read into ~1-second polls so we can enforce the
    // per-session idle deadline (PLAN §6.2) without rewriting libssh's
    // I/O. We deliberately do NOT consult the process-wide shutdown flag
    // here: PLAN §7.1 specifies that in-flight sessions are *granted* a
    // grace period to finish naturally; the process-level 30-second drain
    // then exits if any worker overstays its welcome.
    //
    // libssh return-code semantics for ssh_channel_read_timeout:
    //   > 0          bytes read
    //   == 0         end-of-file
    //   SSH_AGAIN    timeout elapsed without data
    //   SSH_ERROR    transport / channel failure
    //
    // Slice = 200ms. Two competing concerns:
    //   - SHORTER  reduces worst-case lag in the libssh-spurious-EOF
    //              retry path (where we re-poll after `is_eof == 0`)
    //              and improves responsiveness of the idle-deadline
    //              check.
    //   - LONGER   reduces wakeups per session (lower CPU when many
    //              concurrent sessions are mostly idle).
    // 200ms strikes the balance: 5 wakeups/sec/session is cheap, and
    // lag from a single spurious-EOF retry is bounded to ~200ms (one
    // perceptible "beat" rather than the previous 1-second stall).
    const slice_ms: c_int = 200;
    var offset: usize = 0;
    while (offset < out.len) {
        const n = c.ssh_channel_read_timeout(
            state.channel,
            out[offset..].ptr,
            @intCast(out.len - offset),
            0,
            slice_ms,
        );
        if (n == c.SSH_ERROR) return error.LibsshFailure;
        if (n == 0) {
            // `ssh_channel_read_timeout` returns 0 either (a) genuinely
            // — the peer sent SSH_MSG_CHANNEL_EOF — or (b) spuriously
            // because libssh 0.10.x's internal state thinks `remote_eof`
            // is set when it isn't. (b) is observable when we mix the
            // message API for channel-open/subsystem with the channel
            // API for I/O after `env` requests have flowed through
            // ssh_message_reply_default. Cross-check via ssh_channel_is_eof:
            // if it reports the channel is NOT actually EOF, treat the
            // bogus 0 as a transient and try again. The idle-timeout
            // path still bounds the max wait.
            //
            // Cap consecutive spurious returns to avoid an infinite
            // spin if libssh ever lands in a permanently-stuck state.
            // 1000 is generous (~200s of 200ms slices) — well past
            // anything we've observed in practice.
            const spurious_eof_cap: u32 = 1000;
            if (c.ssh_channel_is_eof(state.channel) == 0) {
                state.spurious_eof_count += 1;
                if (state.spurious_eof_count >= spurious_eof_cap) {
                    return error.LibsshFailure;
                }
                if (state.idle_timeout_ms != 0) {
                    const elapsed: i64 = nowMs() - state.last_activity_ms;
                    if (elapsed >= @as(i64, @intCast(state.idle_timeout_ms))) {
                        return error.IdleTimeout;
                    }
                }
                continue;
            }
            return error.ChannelEof;
        }
        if (n == c.SSH_AGAIN) {
            if (state.idle_timeout_ms != 0) {
                const elapsed: i64 = nowMs() - state.last_activity_ms;
                if (elapsed >= @as(i64, @intCast(state.idle_timeout_ms))) {
                    return error.IdleTimeout;
                }
            }
            continue;
        }
        offset += @intCast(n);
    }
}

fn writeVersion(channel: c.ssh_channel) !void {
    var buf: [9]u8 = undefined;
    writeU32(buf[0..4], 5);
    buf[4] = @intCast(c.SSH_FXP_VERSION);
    writeU32(buf[5..9], 3);
    try writeAll(channel, &buf);
}

fn replyName(channel: c.ssh_channel, request_id: u32, name: []const u8) !void {
    var buf: [512]u8 = undefined;
    var w: PacketWriter = .{ .buf = &buf };
    try w.putU8(@intCast(c.SSH_FXP_NAME));
    try w.putU32(request_id);
    try w.putU32(1);
    try w.string(name);
    try w.string(name);
    try writeDirAttrs(&w);
    try writePayload(channel, w.written());
}

fn replyNames(channel: c.ssh_channel, request_id: u32, entries: []const DirEntry) !void {
    // 32 KiB per packet: 16 entries × ~(255 name + 320 longname + 28
    // attrs + 12 length-prefix overhead) ≈ 9.8 KiB worst case, with
    // room to spare for any future attr additions. Stack-allocated;
    // the worker thread's stack is 8 MiB.
    var buf: [32 * 1024]u8 = undefined;
    var w: PacketWriter = .{ .buf = &buf };
    try w.putU8(@intCast(c.SSH_FXP_NAME));
    try w.putU32(request_id);
    try w.putU32(@intCast(entries.len));
    for (entries) |entry| {
        try w.string(entry.name_buf[0..@min(entry.name_len, entry.name_buf.len)]);
        try w.string(entry.longname_buf[0..@min(entry.longname_len, entry.longname_buf.len)]);
        try writeFullAttrs(&w, entry.info);
    }
    try writePayload(channel, w.written());
}

fn replyHandle(channel: c.ssh_channel, request_id: u32, id: u32) !void {
    var handle_bytes: [4]u8 = undefined;
    writeU32(&handle_bytes, id);

    var buf: [64]u8 = undefined;
    var w: PacketWriter = .{ .buf = &buf };
    try w.putU8(@intCast(c.SSH_FXP_HANDLE));
    try w.putU32(request_id);
    try w.string(&handle_bytes);
    try writePayload(channel, w.written());
}

fn replyDirAttrs(channel: c.ssh_channel, request_id: u32) !void {
    var buf: [128]u8 = undefined;
    var w: PacketWriter = .{ .buf = &buf };
    try w.putU8(@intCast(c.SSH_FXP_ATTRS));
    try w.putU32(request_id);
    try writeDirAttrs(&w);
    try writePayload(channel, w.written());
}

fn replyFullAttrs(channel: c.ssh_channel, request_id: u32, info: listing.EntryInfo) !void {
    // SFTP_FXP_ATTRS reply with the full attribute set (mode + uid +
    // gid + size + atime/mtime). Used by STAT, LSTAT, and FSTAT — so
    // a partner running `sftp> stat foo` and `sftp> ls -la` see the
    // same fields, populated from the same `listing.statAt`-derived
    // EntryInfo.
    var buf: [128]u8 = undefined;
    var w: PacketWriter = .{ .buf = &buf };
    try w.putU8(@intCast(c.SSH_FXP_ATTRS));
    try w.putU32(request_id);
    try writeFullAttrs(&w, info);
    try writePayload(channel, w.written());
}

fn replyData(channel: c.ssh_channel, request_id: u32, data: []const u8) !void {
    var header_payload: [9]u8 = undefined;
    header_payload[0] = @intCast(c.SSH_FXP_DATA);
    writeU32(header_payload[1..5], request_id);
    writeU32(header_payload[5..9], @intCast(data.len));

    var header: [4]u8 = undefined;
    writeU32(&header, @intCast(header_payload.len + data.len));
    try writeAll(channel, &header);
    try writeAll(channel, &header_payload);
    try writeAll(channel, data);
}

fn replyStatus(channel: c.ssh_channel, request_id: u32, status: c_int, message: []const u8) !void {
    var buf: [512]u8 = undefined;
    var w: PacketWriter = .{ .buf = &buf };
    try w.putU8(@intCast(c.SSH_FXP_STATUS));
    try w.putU32(request_id);
    try w.putU32(@intCast(status));
    try w.string(message);
    try w.string("");
    try writePayload(channel, w.written());
}

fn writeDirAttrs(w: *PacketWriter) !void {
    // Synthetic attrs for SFTP_NAME replies that only carry a path
    // without an underlying inode (REALPATH against a virtual root).
    // We claim "directory, mode 0755, size 0" — minimal but well-
    // formed; the next STAT/READDIR fetches the real shape.
    try writeBasicAttrs(w, .directory, 0);
}

/// Synthetic attrs for callers who don't have an actual stat result —
/// REALPATH replies and similar virtual paths. Only fills SIZE +
/// PERMISSIONS with a plausible default. NEW code paths should prefer
/// `writeFullAttrs` with a real `EntryInfo`.
fn writeBasicAttrs(w: *PacketWriter, kind: std.Io.File.Kind, size: u64) !void {
    const mode: u32 = switch (kind) {
        .directory => @intCast(c.SSH_S_IFDIR | 0o755),
        else => @intCast(c.SSH_S_IFREG | 0o644),
    };
    try w.putU32(@intCast(c.SSH_FILEXFER_ATTR_SIZE | c.SSH_FILEXFER_ATTR_PERMISSIONS));
    try w.putU64(size);
    try w.putU32(mode);
}

/// Emit an SFTP v3 file-attributes block populated from a real
/// `listing.EntryInfo`. Includes:
///
///   - SIZE         : real byte size (0 for directories/specials)
///   - UIDGID       : real uid + gid for `ls -l` rendering
///   - PERMISSIONS  : real `st_mode` (file-type bits + permission
///                    bits), so the client can render `drwxr-xr-x`
///                    correctly for directories, symlinks, etc.
///   - ACMODTIME    : atime + mtime as seconds since epoch
///
/// The flag word is the OR of the four `SSH_FILEXFER_ATTR_*` bits;
/// each populated field follows in the spec-defined order.
fn writeFullAttrs(w: *PacketWriter, info: listing.EntryInfo) !void {
    const flags: u32 = @intCast(
        c.SSH_FILEXFER_ATTR_SIZE |
            c.SSH_FILEXFER_ATTR_UIDGID |
            c.SSH_FILEXFER_ATTR_PERMISSIONS |
            c.SSH_FILEXFER_ATTR_ACMODTIME,
    );
    try w.putU32(flags);
    try w.putU64(info.size);
    try w.putU32(info.uid);
    try w.putU32(info.gid);
    try w.putU32(info.mode);
    // SFTP v3 stores acmodtime as 32-bit seconds. mtime_secs comes
    // from statx/fstat as i64 to handle pre-1970 files correctly,
    // but SFTP can only carry u32; clamp to the representable range
    // (1970..2106) rather than truncate silently. Same for atime,
    // which we don't track separately — we report mtime for both
    // since SFTP clients use atime only as a fallback for dirs that
    // don't track it.
    const t32: u32 = if (info.mtime_secs < 0) 0
        else if (info.mtime_secs > std.math.maxInt(u32)) std.math.maxInt(u32)
        else @intCast(info.mtime_secs);
    try w.putU32(t32);
    try w.putU32(t32);
}

fn writePayload(channel: c.ssh_channel, payload: []const u8) !void {
    var header: [4]u8 = undefined;
    writeU32(&header, @intCast(payload.len));
    try writeAll(channel, &header);
    try writeAll(channel, payload);
}

fn writeAll(channel: c.ssh_channel, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const n = c.ssh_channel_write(channel, bytes[offset..].ptr, @intCast(bytes.len - offset));
        if (n <= 0) return error.LibsshFailure;
        offset += @intCast(n);
    }
}

const PacketWriter = struct {
    buf: []u8,
    index: usize = 0,

    fn written(self: PacketWriter) []const u8 {
        return self.buf[0..self.index];
    }

    fn putU8(self: *PacketWriter, value: u8) !void {
        if (self.index + 1 > self.buf.len) return error.LibsshFailure;
        self.buf[self.index] = value;
        self.index += 1;
    }

    fn putU32(self: *PacketWriter, value: u32) !void {
        if (self.index + 4 > self.buf.len) return error.LibsshFailure;
        writeU32(self.buf[self.index .. self.index + 4], value);
        self.index += 4;
    }

    fn putU64(self: *PacketWriter, value: u64) !void {
        if (self.index + 8 > self.buf.len) return error.LibsshFailure;
        self.buf[self.index] = @intCast((value >> 56) & 0xff);
        self.buf[self.index + 1] = @intCast((value >> 48) & 0xff);
        self.buf[self.index + 2] = @intCast((value >> 40) & 0xff);
        self.buf[self.index + 3] = @intCast((value >> 32) & 0xff);
        self.buf[self.index + 4] = @intCast((value >> 24) & 0xff);
        self.buf[self.index + 5] = @intCast((value >> 16) & 0xff);
        self.buf[self.index + 6] = @intCast((value >> 8) & 0xff);
        self.buf[self.index + 7] = @intCast(value & 0xff);
        self.index += 8;
    }

    fn string(self: *PacketWriter, value: []const u8) !void {
        try self.putU32(@intCast(value.len));
        if (self.index + value.len > self.buf.len) return error.LibsshFailure;
        @memcpy(self.buf[self.index .. self.index + value.len], value);
        self.index += value.len;
    }
};

/// Existence check for a path component under a directory FD, used
/// by `publishStagedHandle` for the CLOSE-time clobber re-check.
/// Goes through `faccessat(2)` because:
///
///  - It's a real libc function call. The compiler must honor the
///    calling convention and treat memory as fully clobbered. No
///    UB-license to constant-propagate. The companion `listing.statAt`
///    on Linux uses the inline-asm `statx` syscall, which Zig 0.16
///    ReleaseSafe miscompiles (the asm declares `:.{ .memory = true }`
///    but the optimizer still propagates the pre-syscall init value
///    of the destination buffer through to the field reads — every
///    "missing file" lookup returns SUCCESS with zero/0xAA fields).
///
///  - We only need the boolean "does this path exist". `faccessat`
///    answers exactly that, with no metadata to corrupt.
///
///  - `AT_SYMLINK_NOFOLLOW` semantics are preserved: a dangling
///    symlink at the basename returns 0 (entry exists, even though
///    the symlink target doesn't). This is the right answer for
///    clobber: a symlink IS an existing entry that the rename would
///    overwrite.
///
/// Implementation notes:
///   - Linux's std.c.faccessat is intentionally `void` in Zig 0.16
///     (Zig nudges Linux callers toward the syscall path). We
///     declare the libc symbol ourselves; both glibc and musl
///     export it from libc.
///   - On macOS / *BSD, std.c.faccessat is a real wrapper.
///   - Returns false on ENOENT, ENOTDIR (the parent isn't a dir
///     anymore — same effective answer for clobber). Returns true
///     on success or any other error (conservative: prefer false-
///     positive existence over a false-negative that would let an
///     attacker overwrite a file).
fn existsAtParent(parent_fd: std.posix.fd_t, base: []const u8) bool {
    if (base.len >= 256) return false;
    var name_buf: [256]u8 = undefined;
    @memcpy(name_buf[0..base.len], base);
    name_buf[base.len] = 0;
    const cname: [*:0]const u8 = @ptrCast(&name_buf);
    const at_flags: c_int = @intCast(std.posix.AT.SYMLINK_NOFOLLOW);
    const F_OK: c_int = 0;
    const rc = libc_faccessat(parent_fd, cname, F_OK, at_flags);
    if (rc == 0) return true;
    return switch (std.posix.errno(rc)) {
        .NOENT, .NOTDIR => false,
        else => true,
    };
}

const libc_faccessat = if (@import("builtin").os.tag == .linux)
    @extern(*const fn (
        dirfd: std.posix.fd_t,
        path: [*:0]const u8,
        mode: c_int,
        flags: c_int,
    ) callconv(.c) c_int, .{ .name = "faccessat" })
else
    struct {
        fn shim(
            dirfd: std.posix.fd_t,
            path: [*:0]const u8,
            mode: c_int,
            flags: c_int,
        ) c_int {
            return std.c.faccessat(dirfd, path, @intCast(mode), @intCast(flags));
        }
    }.shim;

fn readU32(bytes: []const u8) u32 {
    return (@as(u32, bytes[0]) << 24) |
        (@as(u32, bytes[1]) << 16) |
        (@as(u32, bytes[2]) << 8) |
        @as(u32, bytes[3]);
}

fn readU64(bytes: []const u8) u64 {
    return (@as(u64, bytes[0]) << 56) |
        (@as(u64, bytes[1]) << 48) |
        (@as(u64, bytes[2]) << 40) |
        (@as(u64, bytes[3]) << 32) |
        (@as(u64, bytes[4]) << 24) |
        (@as(u64, bytes[5]) << 16) |
        (@as(u64, bytes[6]) << 8) |
        @as(u64, bytes[7]);
}

const ParsedString = struct {
    value: []const u8,
    rest: []const u8,
};

fn parseString(payload: []const u8) !ParsedString {
    if (payload.len < 4) return error.LibsshFailure;
    const len = readU32(payload[0..4]);
    if (payload.len < 4 + len) return error.LibsshFailure;
    return .{
        .value = payload[4 .. 4 + len],
        .rest = payload[4 + len ..],
    };
}

fn parseHandleId(payload: []const u8) !u32 {
    const parsed = try parseString(payload);
    if (parsed.value.len != 4) return error.LibsshFailure;
    return readU32(parsed.value);
}

fn writeU32(out: []u8, value: u32) void {
    out[0] = @intCast((value >> 24) & 0xff);
    out[1] = @intCast((value >> 16) & 0xff);
    out[2] = @intCast((value >> 8) & 0xff);
    out[3] = @intCast(value & 0xff);
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

fn logLibsshError(io: std.Io, where: []const u8, handle: ?*anyopaque) !void {
    const stderr = std.Io.File.stderr();
    try stderr.writeStreamingAll(io, "zift: ");
    try stderr.writeStreamingAll(io, where);
    try stderr.writeStreamingAll(io, ": ");
    const err = c.ssh_get_error(handle);
    if (err != null) {
        try stderr.writeStreamingAll(io, std.mem.span(err));
    } else {
        try stderr.writeStreamingAll(io, "unknown libssh error");
    }
    try stderr.writeStreamingAll(io, "\n");
}
