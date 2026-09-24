//! Accept loop, config reload, graceful drain, and per-session threads.
//!
//! Each accepted connection gets a detached worker thread holding a
//! reference to the config that was current at accept time; a reload
//! swaps in a new config for later sessions only. `listen`, `host-key`,
//! and `log` are bound once at startup.

const std = @import("std");
const builtin = @import("builtin");
const c = @import("libssh");
const abuse = @import("abuse.zig");
const audit = @import("audit.zig");
const config = @import("config.zig");
const sftp = @import("sftp.zig");
const signals = @import("signals.zig");
const ssh = @import("ssh.zig");
const sys = @import("sys.zig");

/// In-flight session threads; enforces `max-connections` and drain.
pub var active_sessions: std.atomic.Value(u32) = .init(0);

/// Sessions not yet authenticated; enforces `max-unauth-connections`.
pub var unauth_sessions: std.atomic.Value(u32) = .init(0);

/// The peer address (no port, no brackets) formatted into `buf`, or null.
/// An IPv4-mapped IPv6 address prints as IPv4: a dual-stack listener
/// then logs and rate-limits IPv4 clients per address, not all as one
/// IPv6 /64.
fn formatPeer(ss: *const std.posix.sockaddr.storage, buf: []u8) ?[]const u8 {
    const family = @as(*const std.posix.sockaddr, @ptrCast(ss)).family;
    switch (family) {
        std.posix.AF.INET => {
            const sa: *const std.posix.sockaddr.in = @ptrCast(@alignCast(ss));
            const bytes: [4]u8 = @bitCast(sa.addr);
            return formatIPv4(bytes, buf);
        },
        std.posix.AF.INET6 => {
            const sa: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(ss));
            const v4_mapped_prefix = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff };
            if (std.mem.eql(u8, sa.addr[0..12], &v4_mapped_prefix)) return formatIPv4(sa.addr[12..16].*, buf);
            return formatIPv6(&sa.addr, buf);
        },
        else => return null,
    }
}

fn formatIPv4(bytes: [4]u8, buf: []u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3] }) catch null;
}

/// Colon-hex IPv6 without `::` compression (netmatch accepts this form).
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

/// Why a new connection from `peer_ip` is refused, or null to admit it.
/// Admission takes one of the source's pre-auth slots.
fn refusal(io: std.Io, cfg: config.ServerConfig, peer_ip: []const u8, now_ms: i64) ?[]const u8 {
    if (active_sessions.load(.acquire) >= cfg.max_connections) return "max-connections reached";
    // 0 = no separate pre-auth cap.
    if (cfg.max_unauth_connections != 0 and
        unauth_sessions.load(.acquire) >= cfg.max_unauth_connections)
    {
        return "max-unauth-connections reached";
    }
    return switch (abuse.admit(io, peer_ip, now_ms)) {
        .admitted => null,
        .suppressed => "source suppressed",
        .busy => "too many pre-auth connections from source",
    };
}

/// Give back a session's pre-auth slots: the global one and its source's.
fn releasePreauth(io: std.Io, peer_ip: []const u8) void {
    _ = unauth_sessions.fetchSub(1, .acq_rel);
    abuse.releasePreauth(io, peer_ip);
}

/// Hand an accepted connection to a detached worker. On error `fd` is
/// closed and every reservation released.
fn startSession(
    io: std.Io,
    allocator: std.mem.Allocator,
    active: *ActiveConfig,
    bind: c.ssh_bind,
    fd: c_int,
    ip_buf: [64]u8,
    ip_len: u8,
) !void {
    errdefer abuse.releasePreauth(io, ip_buf[0..ip_len]);
    const session = c.ssh_new() orelse {
        _ = std.c.close(fd);
        return error.OutOfMemory;
    };
    if (c.ssh_bind_accept_fd(bind, session, fd) != c.SSH_OK) {
        // Out of memory only. By now libssh may or may not own `fd`, and
        // may have left the session's socket half-built, so close the fd
        // and leak the session rather than risk a double close or free.
        logLibsshError(io, "ssh_bind_accept_fd", bind, .note);
        _ = std.c.close(fd);
        return error.LibsshFailure;
    }
    errdefer c.ssh_free(session); // closes fd

    // Registered here, not in the worker, so a drain that starts before
    // the worker runs still force-closes it.
    try signals.registerSessionFd(io, allocator, fd);
    errdefer signals.unregisterSessionFd(io, fd);

    const args = try allocator.create(SessionArgs);
    errdefer allocator.destroy(args);
    const ref = active.acquire();
    errdefer ref.release(allocator);
    args.* = .{
        .io = io,
        .allocator = allocator,
        .config_ref = ref,
        .session = session,
        .session_fd = fd,
        .login_deadline_ms = sys.monotonicMs() + ssh.login_grace_ms,
        .ip_buf = ip_buf,
        .ip_len = ip_len,
    };

    // Reserve both slots before spawn so the next accept sees them. The
    // worker releases the pre-auth slot at auth (or exit) and the total
    // slot at exit.
    _ = active_sessions.fetchAdd(1, .acq_rel);
    errdefer _ = active_sessions.fetchSub(1, .acq_rel);
    _ = unauth_sessions.fetchAdd(1, .acq_rel);
    errdefer _ = unauth_sessions.fetchSub(1, .acq_rel);

    const thread = try std.Thread.spawn(.{}, sessionThread, .{args});
    thread.detach();
}

fn setNonblocking(fd: c_int, on: bool) void {
    const flags = std.c.fcntl(fd, std.posix.F.GETFL);
    if (flags < 0) return;
    const nonblock: c_int = @bitCast(std.posix.O{ .NONBLOCK = true });
    _ = std.c.fcntl(fd, std.posix.F.SETFL, if (on) flags | nonblock else flags & ~nonblock);
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

    // Restart-only settings, so a reload that changes one can warn.
    active.bound_listen = try allocator.dupe(u8, active.current.config.server.listen);
    active.bound_host_key = try allocator.dupe(u8, active.current.config.server.host_key);
    active.bound_log = try allocator.dupe(u8, logTargetLabel(active.current.config.server.log));
    defer {
        allocator.free(active.bound_listen);
        allocator.free(active.bound_host_key);
        allocator.free(active.bound_log);
    }

    // 128 sessions × 256 handles dwarfs a typical soft RLIMIT_NOFILE, so
    // a few busy partners could starve everyone's OPEN. Raise it, or warn.
    ensureFdBudget(io, active.current.config.server.max_connections);

    const bind = c.ssh_bind_new() orelse return error.LibsshFailure;
    defer c.ssh_bind_free(bind);

    active.stamp = try configStamp(io, config_path, active.current.config);

    const listen = try parseListen(allocator, active.current.config.server.listen);
    defer listen.deinit(allocator);

    const host_key = try allocator.dupeZ(u8, active.current.config.server.host_key);
    defer allocator.free(host_key);

    try setBindOption(bind, c.SSH_BIND_OPTIONS_BINDADDR, listen.host.ptr);
    try setBindOption(bind, c.SSH_BIND_OPTIONS_BINDPORT_STR, listen.port.ptr);
    try setBindOption(bind, c.SSH_BIND_OPTIONS_HOSTKEY, host_key.ptr);
    // The config file is the only config: without this, ssh_bind_listen
    // also reads /etc/ssh/libssh_server_config, which can add host keys
    // and change the algorithms.
    const process_config = false;
    try setBindOption(bind, c.SSH_BIND_OPTIONS_PROCESS_CONFIG, &process_config);
    // libssh verifies SHA-1 `ssh-rsa` user signatures unless the accepted
    // list excludes it; RSA is allowed with SHA-2 only, and at 2048 bits.
    try setBindOption(bind, c.SSH_BIND_OPTIONS_PUBKEY_ACCEPTED_KEY_TYPES, signature_algorithms);
    try setBindOption(bind, c.SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS, signature_algorithms);
    const rsa_min_bits: c_int = 2048;
    try setBindOption(bind, c.SSH_BIND_OPTIONS_RSA_MIN_SIZE, &rsa_min_bits);

    if (c.ssh_bind_listen(bind) != c.SSH_OK) {
        logLibsshError(io, "ssh_bind_listen", bind, .note);
        return error.LibsshFailure;
    }

    // Zift polls and accepts on libssh's listening fd itself: signals
    // are seen within a second, the peer address comes with the accept,
    // and a refused connection is just closed. Non-blocking, so a
    // connection reset between poll and accept cannot stall the loop.
    const bind_fd = c.ssh_bind_get_fd(bind);
    setNonblocking(bind_fd, true);
    var pfd = [1]std.posix.pollfd{.{
        .fd = bind_fd,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};

    try sys.note(io, "zift: listening on {s}\n", .{active.current.config.server.listen});

    // Change polling every `reload-interval`; 0 leaves only SIGHUP.
    var next_reload_ms: i64 = sys.monotonicMs() +
        @as(i64, @intCast(active.current.config.server.reload_interval_ms));
    var accept_backoff_ms: i64 = 0;

    accept_loop: while (true) {
        if (signals.shutdown_requested.load(.acquire)) break :accept_loop;

        // SIGHUP reloads whether or not anything changed.
        if (signals.reload_requested.swap(false, .acq_rel)) {
            active.forceReload(config_path);
            next_reload_ms = sys.monotonicMs() +
                @as(i64, @intCast(active.current.config.server.reload_interval_ms));
        }

        // Stats the config and its authorized-key files.
        const reload_interval = active.current.config.server.reload_interval_ms;
        if (reload_interval > 0 and sys.monotonicMs() >= next_reload_ms) {
            active.reloadIfChanged(config_path);
            next_reload_ms = sys.monotonicMs() +
                @as(i64, @intCast(active.current.config.server.reload_interval_ms));
        }

        const ready = std.posix.poll(&pfd, 1000) catch continue :accept_loop;
        if (ready == 0) continue :accept_loop;

        var ss: std.posix.sockaddr.storage align(8) = undefined;
        var ss_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
        const fd = std.c.accept(bind_fd, @ptrCast(&ss), &ss_len);
        if (fd < 0) {
            switch (std.posix.errno(fd)) {
                .AGAIN, .INTR, .CONNABORTED => {},
                else => |e| {
                    // EMFILE and the like leave the connection queued, so
                    // poll fires again at once: back off instead of spinning.
                    accept_backoff_ms = std.math.clamp(accept_backoff_ms * 2, 10, 1000);
                    sys.note(io, "zift: accept failed: E{s}\n", .{@tagName(e)}) catch {};
                    std.Io.sleep(io, .fromMilliseconds(accept_backoff_ms), .awake) catch {};
                },
            }
            continue :accept_loop;
        }
        accept_backoff_ms = 0;
        // BSD sockets inherit O_NONBLOCK from the listener; libssh wants blocking.
        setNonblocking(fd, false);

        var ip_buf: [64]u8 = undefined;
        const peer_ip = formatPeer(&ss, &ip_buf) orelse "";
        const now_ms = sys.monotonicMs();
        if (refusal(io, active.current.config.server, peer_ip, now_ms)) |reason| {
            if (abuse.rejectionLogDue(io, peer_ip, now_ms)) {
                audit.log(io, null, "accept.rejected", null, .denied, reason, peer_ip);
            }
            _ = std.c.close(fd);
            continue :accept_loop;
        }
        startSession(io, allocator, &active, bind, fd, ip_buf, @intCast(peer_ip.len)) catch |err| {
            sys.note(io, "zift: cannot start session: {s}\n", .{@errorName(err)}) catch {};
        };
    }

    // Unbind now so no connection lands during the grace window. Then
    // clear libssh's copy of the fd: ssh_bind_free would close it again,
    // possibly hitting a descriptor a worker has since reused.
    _ = std.c.close(bind_fd);
    c.ssh_bind_set_fd(bind, @as(@TypeOf(bind_fd), -1));
    drain(io, active.current.config.server.shutdown_grace_ms);
    signals.deinitSessionRegistry(io, allocator);
}

/// Wait up to `grace_ms` for sessions to end, then shutdown(2) every
/// remaining session socket so workers unblock and clean up. Status
/// lines are best effort: a failed stderr write must not skip the drain.
fn drain(io: std.Io, grace_ms: u64) void {
    sys.note(io, "zift: shutdown signal received, draining sessions\n", .{}) catch {};
    if (waitForSessions(io, @intCast(grace_ms), 100)) {
        sys.note(io, "zift: all sessions drained, exiting\n", .{}) catch {};
        return;
    }

    const closed = signals.forceCloseAll(io);
    sys.note(io, "zift: grace period expired, force-closing {d} session(s)\n", .{closed}) catch {};
    // Reads on a shut-down socket return at once; 500 ms is ample.
    if (waitForSessions(io, 500, 20)) {
        sys.note(io, "zift: all sessions drained after force-close, exiting\n", .{}) catch {};
        return;
    }

    // Returning would let main free the audit sink and finalize libssh
    // under the stragglers' feet; end the process here instead.
    sys.note(io, "zift: {d} session(s) still alive after force-close; exiting anyway\n", .{active_sessions.load(.acquire)}) catch {};
    std.process.exit(0);
}

/// True once no session is active; false if `timeout_ms` passes first.
fn waitForSessions(io: std.Io, timeout_ms: i64, step_ms: i64) bool {
    const deadline = sys.monotonicMs() + timeout_ms;
    while (active_sessions.load(.acquire) != 0) {
        if (sys.monotonicMs() >= deadline) return false;
        std.Io.sleep(io, .fromMilliseconds(step_ms), .awake) catch {};
    }
    return true;
}

/// "stderr" or the file path, for the restart-only comparison.
fn logTargetLabel(target: config.LogTarget) []const u8 {
    return switch (target) {
        .stderr => "stderr",
        .file => |path| path,
    };
}

/// Raise the soft `RLIMIT_NOFILE` toward the worst case; warn if short.
fn ensureFdBudget(io: std.Io, max_connections: u32) void {
    // Socket, libssh's own fds, and the handle cap, with slack.
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

    sys.note(
        io,
        "zift: warning: file-descriptor soft limit {d} is below the worst case {d} " ++
            "(max-connections {d} × {d} handles/session); lower max-connections or raise LimitNOFILE\n",
        .{ after.cur, needed, max_connections, sftp.max_handles_per_session },
    ) catch {};
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

/// The serving config. Only the accept thread reads or swaps `current`;
/// workers touch only their own `ConfigRef`'s atomic count.
const ActiveConfig = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    current: *ConfigRef,
    /// `configStamp` taken before the last reload attempt whose read
    /// succeeded (even a rejected one, so a saved typo is not re-parsed
    /// every poll).
    stamp: u64 = 0,
    /// One warning per run of config stat failures.
    stat_warned: bool = false,
    /// The on-disk config was rejected and the previous one is still
    /// serving. Cleared, loudly, when a good config loads.
    reload_degraded: bool = false,
    /// Restart-only values in force (owned: the startup config may be
    /// freed when its last session ends).
    bound_listen: []const u8 = "",
    bound_host_key: []const u8 = "",
    bound_log: []const u8 = "",

    fn acquire(self: *ActiveConfig) *ConfigRef {
        return self.current.acquire();
    }

    fn releaseActive(self: *ActiveConfig) void {
        self.current.release(self.allocator);
    }

    /// Reload when the stamp differs in any way, so a deploy that keeps
    /// or rewinds mtimes is seen too. Errors stay in here: leaving `run`
    /// would drop every live session.
    fn reloadIfChanged(self: *ActiveConfig, path: []const u8) void {
        const stamp = configStamp(self.io, path, self.current.config) catch |err| {
            // Warn once and keep the previous config until it is back.
            if (!self.stat_warned) {
                sys.note(self.io, "zift: cannot stat config file: {s}: {s} (keeping previous config)\n", .{ path, @errorName(err) }) catch {};
                self.stat_warned = true;
            }
            return;
        };

        if (self.stat_warned) {
            sys.note(self.io, "zift: config file readable again\n", .{}) catch {};
            self.stat_warned = false;
        }
        if (stamp != self.stamp) self.applyReload(path, stamp);
    }

    /// SIGHUP: reload even when nothing looks changed.
    fn forceReload(self: *ActiveConfig, path: []const u8) void {
        self.applyReload(path, configStamp(self.io, path, self.current.config) catch 0);
    }

    /// `stamp` is taken before the read, so an edit that lands during
    /// the load differs from it and reloads again on the next poll. When
    /// a reload changes which key files are named, the next poll reloads
    /// once more, now stamping the new set.
    fn applyReload(self: *ActiveConfig, path: []const u8, stamp: u64) void {
        const contents = config.readFile(self.io, self.allocator, path) catch |err| {
            // A read failure may be transient (EMFILE, a chmod), so keep
            // the old stamp and retry next poll.
            sys.note(self.io, "zift: config reload read failed: {s}\n", .{@errorName(err)}) catch {};
            return;
        };
        defer self.allocator.free(contents);
        self.stamp = stamp;

        var diag: config.LoadDiag = .{};
        var next_config = config.load(self.io, self.allocator, contents, &diag) catch {
            if (diag.parse_err == null) {
                // validateSemantic already printed the specific diagnostic.
                self.noteReloadRejected(path, "semantic validation failed (see preceding diagnostic)");
                return;
            }
            var msg_buf: [512]u8 = undefined;
            var w = std.Io.Writer.fixed(&msg_buf);
            w.print("{f}", .{diag}) catch {};
            self.noteReloadRejected(path, w.buffered());
            return;
        };

        // These are not re-applied; say so rather than imply they were.
        // A warning that fails to print must not discard a good config.
        self.warnRestartOnly("listen", self.bound_listen, next_config.server.listen);
        self.warnRestartOnly("host-key", self.bound_host_key, next_config.server.host_key);
        self.warnRestartOnly("log", self.bound_log, logTargetLabel(next_config.server.log));

        const next_ref = ConfigRef.create(self.allocator, next_config) catch |err| {
            next_config.deinit();
            sys.note(self.io, "zift: config reload failed: {s} (keeping previous config)\n", .{@errorName(err)}) catch {};
            return;
        };

        // `next_ref` owns `next_config` now; once published it stays,
        // even if a later status write fails.
        const old_ref = self.current;
        self.current = next_ref;
        old_ref.release(self.allocator);
        ensureFdBudget(self.io, self.current.config.server.max_connections);

        if (self.reload_degraded) {
            self.reload_degraded = false;
            sys.note(self.io, "zift: config reload recovered — on-disk config valid again; now serving it\n", .{}) catch {};
            audit.log(self.io, null, "config.reload", path, .ok, "recovered; on-disk config now serving", "");
        }

        sys.note(self.io, "zift: config reloaded (users/rules/timeouts applied to new sessions)\n", .{}) catch {};
    }

    /// Report a rejected reload on stderr and in the audit log, and mark
    /// the daemon degraded until a good config loads. Tooling and tests
    /// grep for `config reload rejected`.
    fn noteReloadRejected(
        self: *ActiveConfig,
        path: []const u8,
        detail: []const u8,
    ) void {
        self.reload_degraded = true;
        const sep: []const u8 = if (detail.len != 0) ": " else "";
        sys.note(self.io, "zift: config reload rejected — SERVING PREVIOUS CONFIG; fix {s} and it will auto-apply{s}{s}\n", .{ path, sep, detail }) catch {};
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
        name: []const u8,
        bound: []const u8,
        proposed: []const u8,
    ) void {
        if (std.mem.eql(u8, bound, proposed)) return;
        sys.note(self.io, "zift: warning: '{s}' changed in config but is applied only at startup; still using '{s}' — restart zift to apply\n", .{ name, bound }) catch {};
    }
};

const SessionArgs = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    config_ref: *ConfigRef,
    session: c.ssh_session,
    /// Already registered with `signals`.
    session_fd: c_int,
    /// Monotonic ms by which authentication must succeed.
    login_deadline_ms: i64,
    /// Peer address captured at accept; "" when unknown.
    ip_buf: [64]u8,
    ip_len: u8,
};

fn sessionThread(args: *SessionArgs) void {
    const io = args.io;
    const allocator = args.allocator;
    const ref = args.config_ref;
    const session = args.session;
    const session_fd = args.session_fd;
    const deadline_ms = args.login_deadline_ms;
    const ip_buf = args.ip_buf;
    const peer_ip = ip_buf[0..args.ip_len];
    allocator.destroy(args);

    configureSocket(session_fd);

    // Set by `handleSession` when it releases the pre-auth slot at auth.
    var auth_completed = false;
    const ok = if (handleSession(io, allocator, ref.config, session, peer_ip, deadline_ms, &auth_completed)) true else |err| blk: {
        // The error text lives in the session, so read it before ssh_free.
        logLibsshError(io, @errorName(err), session, .skip);
        break :blk false;
    };

    // Unregister while the fd is still open: once libssh closes it, the
    // number can be reused and a force-close would hit another socket.
    signals.unregisterSessionFd(io, session_fd);
    if (ok) c.ssh_disconnect(session);
    c.ssh_free(session);

    if (!auth_completed) releasePreauth(io, peer_ip);
    ref.release(allocator);
    _ = active_sessions.fetchSub(1, .acq_rel);
}

/// Hash of the size, mtime, ctime, and inode of the config file and each
/// key file it names; ctime catches an edit that puts the mtime back. A
/// key file that cannot be stat'ed hashes as missing; only the config
/// file itself failing is an error.
fn configStamp(io: std.Io, path: []const u8, cfg: config.Config) !u64 {
    var h: std.hash.Wyhash = .init(0);
    hashStat(&h, try std.Io.Dir.cwd().statFile(io, path, .{}));
    for (cfg.users) |user| {
        for (user.key_files) |key_path| {
            h.update(key_path);
            hashStat(&h, std.Io.Dir.cwd().statFile(io, key_path, .{}) catch null);
        }
    }
    return h.final();
}

fn hashStat(h: *std.hash.Wyhash, stat: ?std.Io.File.Stat) void {
    const s = stat orelse return h.update("missing");
    std.hash.autoHash(h, .{ s.size, s.mtime.nanoseconds, s.ctime.nanoseconds, s.inode });
}

fn handleSession(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    session: c.ssh_session,
    peer_ip: []const u8,
    login_deadline_ms: i64,
    auth_completed: *bool,
) !void {
    // Before the handshake, or a silent TCP client pins a worker.
    try ssh.boundRead(session, cfg.server.idle_timeout_ms, login_deadline_ms);

    if (c.ssh_handle_key_exchange(session) != c.SSH_OK) {
        audit.log(io, null, "handshake.failed", null, .failed, "", peer_ip);
        return error.LibsshFailure;
    }

    const user = try ssh.authenticate(io, allocator, cfg, session, peer_ip, login_deadline_ms);

    // Release the pre-auth slots now; the flag tells sessionThread not
    // to release it again.
    auth_completed.* = true;
    releasePreauth(io, peer_ip);

    // Plain idle from here (the SFTP loop enforces idle itself).
    ssh.setReadTimeout(session, cfg.server.idle_timeout_ms);
    const channel = try sftp.acceptSftpSubsystem(session);

    // The session owns the channel; freeing it here would double-free.
    try sftp.runSftp(io, allocator, channel, user, cfg.server, peer_ip);
}

/// Best-effort socket options. TCP_NODELAY: SFTP is request/response,
/// and Nagle adds delayed-ACK latency. SO_KEEPALIVE drops dead peers; on
/// Linux the probes start after 60s idle and give up after 6 × 10s.
/// Option numbers differ by OS (Darwin's 4 is TCP_NOPUSH, not
/// KEEPIDLE), so they come from `std.posix` and the timing knobs are
/// Linux-only.
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

    if (builtin.os.tag == .linux) {
        const idle_seconds: c_int = 60;
        const intvl_seconds: c_int = 10;
        const probe_count: c_int = 6;
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

/// User-key and host-key signature algorithms: the key types the config
/// accepts, with RSA limited to its SHA-2 signatures.
const signature_algorithms = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521," ++
    "rsa-sha2-512,rsa-sha2-256";

fn setBindOption(bind: c.ssh_bind, option: c.enum_ssh_bind_options_e, value: *const anyopaque) !void {
    if (c.ssh_bind_options_set(bind, option, value) != c.SSH_OK) return error.LibsshFailure;
}

/// What to do when libssh has no error text to contribute.
const NoDetail = enum {
    /// Log a placeholder: the failure has no audit record of its own.
    note,
    /// Log nothing: per-session failures already have an audit record,
    /// and a scanner that hangs up mid-handshake leaves libssh with no
    /// message at all. Logging those buried real failures in noise.
    skip,
};

/// Best effort: a failed stderr write is not worth failing a caller over.
fn logLibsshError(io: std.Io, where: []const u8, handle: ?*anyopaque, no_detail: NoDetail) void {
    // Usually a non-null pointer to an empty string.
    const raw = c.ssh_get_error(handle);
    const detail: []const u8 = if (raw != null) std.mem.span(raw) else "";
    if (detail.len == 0 and no_detail == .skip) return;

    sys.note(io, "zift: {s}: {s}\n", .{ where, if (detail.len > 0) detail else "no detail from libssh" }) catch {};
}

test "configStamp changes on any change to the config or a key file" {
    const io = std.testing.io;
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];

    const conf_path = try std.fmt.allocPrint(alloc, "{s}/zift.conf", .{dir});
    defer alloc.free(conf_path);
    const text = try std.fmt.allocPrint(alloc, "server\n  listen 127.0.0.1:2222\n  host-key /tmp/key\n\n" ++
        "user ally\n  auth {s}/keys.pub\n  root /tmp/ally\n  allow / read\n", .{dir});
    defer alloc.free(text);
    try tmp.dir.writeFile(io, .{ .sub_path = "zift.conf", .data = text });
    try tmp.dir.writeFile(io, .{ .sub_path = "keys.pub", .data = "key one" });
    var cfg = try config.parse(alloc, text);
    defer cfg.deinit();

    const s0 = try configStamp(io, conf_path, cfg);
    try std.testing.expectEqual(s0, try configStamp(io, conf_path, cfg));

    // A key file's mtime moving backwards counts (it used to need SIGHUP).
    const y2000: std.Io.File.SetTimestamp = .{ .new = .fromNanoseconds(946684800 * std.time.ns_per_s) };
    try tmp.dir.setTimestamps(io, "keys.pub", .{ .modify_timestamp = y2000 });
    const s1 = try configStamp(io, conf_path, cfg);
    try std.testing.expect(s1 != s0);

    // Same size with the mtime put back: ctime still moves. The sleep
    // clears coarse filesystem clocks.
    try std.Io.sleep(io, .fromMilliseconds(20), .awake);
    try tmp.dir.writeFile(io, .{ .sub_path = "keys.pub", .data = "key two" });
    try tmp.dir.setTimestamps(io, "keys.pub", .{ .modify_timestamp = y2000 });
    const s2 = try configStamp(io, conf_path, cfg);
    try std.testing.expect(s2 != s1);

    try tmp.dir.deleteFile(io, "keys.pub");
    try std.testing.expect(try configStamp(io, conf_path, cfg) != s2);

    try tmp.dir.deleteFile(io, "zift.conf");
    try std.testing.expectError(error.FileNotFound, configStamp(io, conf_path, cfg));
}

fn expectPeer(expected: []const u8, sa: anytype) !void {
    var ss: std.posix.sockaddr.storage align(8) = undefined;
    @as(*@TypeOf(sa), @ptrCast(@alignCast(&ss))).* = sa;
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings(expected, formatPeer(&ss, &buf).?);
}

test "formatPeer: IPv4, IPv6 uncompressed, IPv4-mapped as IPv4" {
    try expectPeer("192.0.2.7", std.posix.sockaddr.in{ .port = 0, .addr = @bitCast([4]u8{ 192, 0, 2, 7 }) });
    const v6 = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try expectPeer("2001:db8:0:0:0:0:0:1", std.posix.sockaddr.in6{ .port = 0, .flowinfo = 0, .addr = v6, .scope_id = 0 });
    const mapped = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff, 198, 51, 100, 9 };
    try expectPeer("198.51.100.9", std.posix.sockaddr.in6{ .port = 0, .flowinfo = 0, .addr = mapped, .scope_id = 0 });
}
