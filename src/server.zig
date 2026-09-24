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

    var config_mtime = try currentConfigMtime(io, config_path);
    // Advanced together with `config_mtime` on every reload attempt,
    // even a rejected one, so the poll does not spin.
    var key_stamps = try KeyStamps.collect(allocator, io, active.current.config);
    defer key_stamps.deinit(allocator);

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

    // Poll libssh's listening fd so signals are seen within a second
    // instead of waiting behind a blocking ssh_bind_accept.
    c.ssh_bind_set_blocking(bind, 0);
    const bind_fd = c.ssh_bind_get_fd(bind);
    var pfd = [1]std.posix.pollfd{.{
        .fd = bind_fd,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};

    try sys.note(io, "zift: listening on {s}\n", .{active.current.config.server.listen});

    // mtime polling every `reload-interval`; 0 leaves only SIGHUP.
    var next_reload_ms: i64 = sys.monotonicMs() +
        @as(i64, @intCast(active.current.config.server.reload_interval_ms));

    accept_loop: while (true) {
        if (signals.shutdown_requested.load(.acquire)) break :accept_loop;

        // SIGHUP reloads regardless of mtime.
        if (signals.reload_requested.swap(false, .acq_rel)) {
            active.forceReload(config_path, &config_mtime, &key_stamps);
            next_reload_ms = sys.monotonicMs() +
                @as(i64, @intCast(active.current.config.server.reload_interval_ms));
        }

        // Also stats the running config's authorized-key files.
        const reload_interval = active.current.config.server.reload_interval_ms;
        if (reload_interval > 0 and sys.monotonicMs() >= next_reload_ms) {
            active.reloadIfChanged(config_path, &config_mtime, &key_stamps);
            next_reload_ms = sys.monotonicMs() +
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

        if (abuse.isSuppressed(io, peer_ip, sys.monotonicMs())) {
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

        // 0 = no separate pre-auth cap.
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

        // Reserve both slots before spawn so the next accept sees them.
        // The worker releases the pre-auth slot at auth (or exit) and
        // the total slot at exit.
        _ = active_sessions.fetchAdd(1, .acq_rel);
        _ = unauth_sessions.fetchAdd(1, .acq_rel);

        const thread = std.Thread.spawn(.{}, sessionThread, .{args}) catch |err| {
            _ = active_sessions.fetchSub(1, .acq_rel);
            _ = unauth_sessions.fetchSub(1, .acq_rel);
            // Before ssh_free: ssh_get_error reads the session.
            try logLibsshError(io, @errorName(err), session, .note);
            ref.release(allocator);
            c.ssh_free(session);
            allocator.destroy(args);
            continue :accept_loop;
        };
        thread.detach();
    }

    // Graceful drain: wait up to `shutdown_grace_ms`, then shutdown(2)
    // every remaining session socket so workers unblock and clean up.
    try sys.note(io, "zift: shutdown signal received, draining sessions\n", .{});

    // Unbind now so no connection lands during the grace window. Then
    // clear libssh's copy of the fd: ssh_bind_free would close it again,
    // possibly hitting a descriptor a worker has since reused.
    _ = std.c.close(bind_fd);
    c.ssh_bind_set_fd(bind, @as(@TypeOf(bind_fd), -1));

    const grace_ms: i64 = @intCast(active.current.config.server.shutdown_grace_ms);
    const drain_deadline = sys.monotonicMs() + grace_ms;
    while (active_sessions.load(.acquire) != 0 and sys.monotonicMs() < drain_deadline) {
        std.Io.sleep(io, .fromMilliseconds(100), .awake) catch {};
    }

    if (active_sessions.load(.acquire) == 0) {
        try sys.note(io, "zift: all sessions drained, exiting\n", .{});
    } else {
        const closed = signals.forceCloseAll(io);
        try sys.note(io, "zift: grace period expired, force-closing {d} session(s)\n", .{closed});

        // Reads on a shut-down socket return at once; 500 ms is ample.
        const final_deadline = sys.monotonicMs() + 500;
        while (active_sessions.load(.acquire) != 0 and sys.monotonicMs() < final_deadline) {
            std.Io.sleep(io, .fromMilliseconds(20), .awake) catch {};
        }

        const stragglers = active_sessions.load(.acquire);
        if (stragglers == 0) {
            try sys.note(io, "zift: all sessions drained after force-close, exiting\n", .{});
        } else {
            try sys.note(io, "zift: {d} session(s) still alive after force-close; exiting anyway\n", .{stragglers});
        }
    }

    // A straggler still calls `unregisterSessionFd`, so free the registry
    // only when none remain; otherwise leak it to process exit.
    if (active_sessions.load(.acquire) == 0) {
        signals.deinitSessionRegistry(io, allocator);
    }
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

const ActiveConfig = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    mutex: std.Io.Mutex = .init,
    current: *ConfigRef,
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
        key_stamps: *KeyStamps,
    ) void {
        const mtime = currentConfigMtime(self.io, path) catch |err| {
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

        // Reload when the config mtime moves forward or a key-file stamp
        // changes; deploys that keep mtime need SIGHUP. Errors stay in
        // here: leaving `run` would drop every live session.
        if (mtime.nanoseconds <= known_mtime.nanoseconds and
            !key_stamps.changed(self.io, self.current.config))
        {
            return;
        }
        self.applyReload(path, mtime, known_mtime, key_stamps);
    }

    /// SIGHUP: reload without the mtime comparison.
    fn forceReload(
        self: *ActiveConfig,
        path: []const u8,
        known_mtime: *std.Io.Timestamp,
        key_stamps: *KeyStamps,
    ) void {
        const mtime = currentConfigMtime(self.io, path) catch std.Io.Timestamp.zero;
        self.applyReload(path, mtime, known_mtime, key_stamps);
    }

    fn applyReload(
        self: *ActiveConfig,
        path: []const u8,
        mtime: std.Io.Timestamp,
        known_mtime: *std.Io.Timestamp,
        key_stamps: *KeyStamps,
    ) void {
        const contents = std.Io.Dir.cwd().readFileAlloc(self.io, path, self.allocator, .limited(1 << 20)) catch |err| {
            // A read failure may be transient (EMFILE, a chmod that does
            // not bump mtime), so keep the stamps and retry next poll.
            sys.note(self.io, "zift: config reload read failed: {s}\n", .{@errorName(err)}) catch {};
            return;
        };
        defer self.allocator.free(contents);

        // Read succeeded: advance the stamps now, so a saved typo or a
        // bad key file is not re-parsed and re-logged every poll. The next
        // edit (or SIGHUP) retries. A successful swap re-snapshots below.
        known_mtime.* = mtime;
        key_stamps.remember(self.allocator, self.io, self.current.config);

        var diag: config.ParseDiag = .{};
        var next_config = config.parseWithDiag(self.allocator, contents, &diag) catch |err| {
            var msg_buf: [512]u8 = undefined;
            var w = std.Io.Writer.fixed(&msg_buf);
            diag.format(err, &w) catch {};
            self.noteReloadRejected(path, w.buffered());
            return;
        };

        // validateSemantic already printed the specific diagnostic.
        config.validateSemantic(self.io, self.allocator, &next_config) catch {
            next_config.deinit();
            self.noteReloadRejected(path, "semantic validation failed (see preceding diagnostic)");
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
        self.mutex.lockUncancelable(self.io);
        const old_ref = self.current;
        self.current = next_ref;
        self.mutex.unlock(self.io);

        old_ref.release(self.allocator);
        key_stamps.remember(self.allocator, self.io, self.current.config);

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
};

fn sessionThread(args: *SessionArgs) void {
    const io = args.io;
    const allocator = args.allocator;
    const ref = args.config_ref;
    const ssh_session = args.session;
    allocator.destroy(args);

    // Registered so drain can force-close it; failure is not fatal.
    const session_fd = c.ssh_get_fd(ssh_session);
    var registered = false;
    if (session_fd >= 0) {
        signals.registerSessionFd(io, allocator, session_fd) catch |err| {
            logLibsshError(io, @errorName(err), ssh_session, .note) catch {};
        };
        registered = true;

        configureSocket(session_fd);
    }

    // Set by `handleSession` when it releases the pre-auth slot at auth;
    // otherwise the defer below releases it.
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

fn statKeyMtime(io: std.Io, path: []const u8) ?std.Io.Timestamp {
    const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch return null;
    return stat.mtime;
}

/// Mtimes of the serving config's key files, advanced on every reload
/// attempt whose read succeeded (even a rejected one).
const KeyStamps = struct {
    entries: []Entry = &.{},

    const Entry = struct {
        path: []u8,
        /// null after a failed stat; a later success triggers a reload.
        mtime: ?std.Io.Timestamp,
    };

    const Lookup = union(enum) {
        absent,
        failed,
        mtime: std.Io.Timestamp,
    };

    fn deinit(self: *KeyStamps, allocator: std.mem.Allocator) void {
        for (self.entries) |e| allocator.free(e.path);
        allocator.free(self.entries);
        self.* = .{};
    }

    fn lookup(self: *const KeyStamps, path: []const u8) Lookup {
        for (self.entries) |e| {
            if (!std.mem.eql(u8, e.path, path)) continue;
            if (e.mtime) |ts| return .{ .mtime = ts };
            return .failed;
        }
        return .absent;
    }

    /// Newer than the last recorded stamp, missing after a successful
    /// stamp, present after a failed stamp, or not recorded yet.
    fn changed(self: *const KeyStamps, io: std.Io, cfg: config.Config) bool {
        for (cfg.users) |user| {
            for (user.key_files) |kpath| {
                switch (self.lookup(kpath)) {
                    .absent => return true,
                    .failed => {
                        if (statKeyMtime(io, kpath) != null) return true;
                    },
                    .mtime => |prev| {
                        const now = statKeyMtime(io, kpath) orelse return true;
                        if (now.nanoseconds > prev.nanoseconds) return true;
                    },
                }
            }
        }
        return false;
    }

    /// Restat `cfg`'s key files. Shared paths update in place first, so
    /// a failed allocation for a changed path set still records them.
    fn remember(self: *KeyStamps, allocator: std.mem.Allocator, io: std.Io, cfg: config.Config) void {
        for (self.entries) |*e| {
            if (configHasKeyFile(cfg, e.path)) e.mtime = statKeyMtime(io, e.path);
        }
        if (self.samePaths(cfg)) return;
        const fresh = collect(allocator, io, cfg) catch return;
        self.deinit(allocator);
        self.* = fresh;
    }

    fn samePaths(self: *const KeyStamps, cfg: config.Config) bool {
        for (cfg.users) |user| {
            for (user.key_files) |p| {
                switch (self.lookup(p)) {
                    .absent => return false,
                    else => {},
                }
            }
        }
        for (self.entries) |e| {
            if (!configHasKeyFile(cfg, e.path)) return false;
        }
        return true;
    }

    fn collect(allocator: std.mem.Allocator, io: std.Io, cfg: config.Config) !KeyStamps {
        var list: std.ArrayList(Entry) = .empty;
        errdefer {
            for (list.items) |e| allocator.free(e.path);
            list.deinit(allocator);
        }
        for (cfg.users) |user| {
            for (user.key_files) |p| {
                if (listHas(list.items, p)) continue;
                const owned = try allocator.dupe(u8, p);
                const mtime = statKeyMtime(io, p);
                list.append(allocator, .{ .path = owned, .mtime = mtime }) catch |err| {
                    allocator.free(owned);
                    return err;
                };
            }
        }
        if (list.items.len == 0) return .{};
        return .{ .entries = try list.toOwnedSlice(allocator) };
    }

    fn listHas(entries: []const Entry, path: []const u8) bool {
        for (entries) |e| {
            if (std.mem.eql(u8, e.path, path)) return true;
        }
        return false;
    }

    fn configHasKeyFile(cfg: config.Config, path: []const u8) bool {
        for (cfg.users) |user| {
            for (user.key_files) |p| {
                if (std.mem.eql(u8, p, path)) return true;
            }
        }
        return false;
    }
};

fn handleSession(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    session: c.ssh_session,
    auth_completed: *bool,
) !void {
    defer c.ssh_free(session);

    var ip_buf: [64]u8 = undefined;
    const peer_ip: ?[]const u8 = capturePeerIp(session, &ip_buf);

    // Before the handshake, or a silent TCP client pins a worker forever.
    setSessionTimeout(session, cfg.server.idle_timeout_ms);

    if (c.ssh_handle_key_exchange(session) != c.SSH_OK) {
        audit.log(io, null, "handshake.failed", null, .failed, "", peer_ip orelse "");
        return error.LibsshFailure;
    }

    const user = try ssh.authenticate(io, allocator, cfg, session, peer_ip);

    // Release the pre-auth slot now; the flag tells sessionThread's
    // defer not to release it again.
    auth_completed.* = true;
    _ = unauth_sessions.fetchSub(1, .acq_rel);

    const channel = try sftp.acceptSftpSubsystem(session);

    try sftp.runSftp(io, allocator, channel, user, cfg.server, peer_ip);
    // The session owns the channel; freeing it here would double-free.
    c.ssh_disconnect(session);
}

/// Timeout for every blocking libssh read before SFTP starts (the SFTP
/// loop enforces idle itself). 0 leaves libssh's default.
fn setSessionTimeout(session: c.ssh_session, idle_timeout_ms: u64) void {
    if (idle_timeout_ms == 0) return;
    const seconds: c_long = @intCast(idle_timeout_ms / 1000);
    const usec: c_long = @intCast((idle_timeout_ms % 1000) * 1000);
    _ = c.ssh_options_set(session, c.SSH_OPTIONS_TIMEOUT, &seconds);
    _ = c.ssh_options_set(session, c.SSH_OPTIONS_TIMEOUT_USEC, &usec);
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

fn setBindOption(bind: c.ssh_bind, option: c.enum_ssh_bind_options_e, value: [*:0]const u8) !void {
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

fn logLibsshError(io: std.Io, where: []const u8, handle: ?*anyopaque, no_detail: NoDetail) !void {
    // Usually a non-null pointer to an empty string.
    const raw = c.ssh_get_error(handle);
    const detail: []const u8 = if (raw != null) std.mem.span(raw) else "";
    if (detail.len == 0 and no_detail == .skip) return;

    try sys.note(io, "zift: {s}: {s}\n", .{ where, if (detail.len > 0) detail else "no detail from libssh" });
}
