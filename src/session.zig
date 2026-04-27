const std = @import("std");
const c = @import("libssh");
const audit = @import("audit.zig");
const auth = @import("auth.zig");
const config = @import("config.zig");
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

/// Monotonic-clock millisecond reading. Used for idle-timeout deadlines
/// and graceful-shutdown drain timing. The Linux/macOS `CLOCK_MONOTONIC`
/// is unaffected by wall-clock changes.
fn nowMs() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), std.time.ns_per_ms);
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

    const stdout = std.Io.File.stdout();
    try stdout.writeStreamingAll(io, "zift: listening on ");
    try stdout.writeStreamingAll(io, active.current.config.server.listen);
    try stdout.writeStreamingAll(io, "\n");

    accept_loop: while (true) {
        if (signals.shutdown_requested.load(.acquire)) break :accept_loop;

        // SIGHUP forces a reload regardless of mtime (PLAN §7.2).
        if (signals.reload_requested.swap(false, .acq_rel)) {
            active.forceReload(config_path, &config_mtime);
        }

        const ready = std.posix.poll(&pfd, 1000) catch continue :accept_loop;
        if (ready == 0) {
            // Idle tick: piggyback the mtime watcher here so reload remains
            // a same-thread, lock-protected operation.
            try active.reloadIfChanged(config_path, &config_mtime);
            continue :accept_loop;
        }

        const session = c.ssh_new() orelse return error.LibsshFailure;
        const accept_rc = c.ssh_bind_accept(bind, session);
        if (accept_rc != c.SSH_OK) {
            try logLibsshError(io, "ssh_bind_accept", bind);
            c.ssh_free(session);
            continue :accept_loop;
        }

        try active.reloadIfChanged(config_path, &config_mtime);

        const max = active.current.config.server.max_connections;
        if (signals.active_sessions.load(.acquire) >= max) {
            var ip_buf: [64]u8 = undefined;
            const peer_ip = capturePeerIp(session, &ip_buf) orelse "";
            audit.log(io, null, "accept", null, .denied, "max-connections reached", peer_ip);
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

        // Reserve the slot before spawn so subsequent accepts see it.
        _ = signals.active_sessions.fetchAdd(1, .acq_rel);

        const thread = std.Thread.spawn(.{}, sessionThread, .{args}) catch |err| {
            _ = signals.active_sessions.fetchSub(1, .acq_rel);
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
        const mtime = currentConfigMtime(self.io, path) catch return;
        if (mtime.nanoseconds == known_mtime.nanoseconds) return;
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

        var next_config = config.parse(self.allocator, contents) catch |err| {
            try stderr.writeStreamingAll(self.io, "zift: config reload rejected: ");
            try stderr.writeStreamingAll(self.io, @errorName(err));
            try stderr.writeStreamingAll(self.io, "\n");
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
    }

    defer {
        if (registered) signals.unregisterSessionFd(io, session_fd);
        ref.release(allocator);
        _ = signals.active_sessions.fetchSub(1, .acq_rel);
    }
    handleSession(io, allocator, ref.config, ssh_session) catch |err| {
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
    const channel = try acceptSftpSubsystem(session);

    try runSftp(io, allocator, channel, user, cfg.server.idle_timeout_ms, peer_ip);
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

fn authenticate(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    session: c.ssh_session,
    peer_ip: ?[]const u8,
) !*const config.UserConfig {
    const allowed_methods: c_int = @intCast(c.SSH_AUTH_METHOD_PASSWORD | c.SSH_AUTH_METHOD_PUBLICKEY);

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
            const decision = handlePublicKeyMessage(io, cfg, msg, peer_ip);
            switch (decision) {
                .accepted => |user| return user,
                .offered => continue,
                .denied => {},
            }
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
        audit.log(io, username, "auth.publickey", null, .denied, "unknown user", ip_str);
        return .denied;
    };

    if (!matchesAnyConfiguredKey(user, presented)) {
        audit.log(io, username, "auth.publickey", null, .denied, "key not configured", ip_str);
        return .denied;
    }

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
            audit.log(io, username, "auth.publickey", null, .ok, user.keys[0].algorithm, ip_str);
            return .{ .accepted = user };
        },
        else => {
            // SSH_PUBLICKEY_STATE_WRONG, SSH_PUBLICKEY_STATE_ERROR, anything else.
            audit.log(io, username, "auth.publickey", null, .denied, "signature invalid", ip_str);
            return .denied;
        },
    }
}

fn matchesAnyConfiguredKey(user: *const config.UserConfig, presented: c.ssh_key) bool {
    if (user.keys.len == 0) return false;
    const presented_type = c.ssh_key_type(presented);

    for (user.keys) |configured| {
        const algo_z = std.heap.page_allocator.dupeZ(u8, configured.algorithm) catch return false;
        defer std.heap.page_allocator.free(algo_z);
        const blob_z = std.heap.page_allocator.dupeZ(u8, configured.blob) catch return false;
        defer std.heap.page_allocator.free(blob_z);

        const want_type = c.ssh_key_type_from_name(algo_z.ptr);
        if (want_type != presented_type) continue;

        var parsed: c.ssh_key = null;
        const rc = c.ssh_pki_import_pubkey_base64(blob_z.ptr, want_type, &parsed);
        if (rc != c.SSH_OK or parsed == null) continue;
        defer c.ssh_key_free(parsed);

        if (c.ssh_key_cmp(presented, parsed, c.SSH_KEY_CMP_PUBLIC) == 0) {
            return true;
        }
    }
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
    peer_ip: ?[]const u8,
) !void {
    var jail = try vfs_mod.Vfs.init(io, allocator, user.root);
    defer jail.deinit(allocator);

    var state = SftpState{
        .io = io,
        .allocator = allocator,
        .channel = channel,
        .user = user,
        .peer_ip = peer_ip,
        .vfs = jail,
        .idle_timeout_ms = idle_timeout_ms,
        .last_activity_ms = nowMs(),
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
                audit.log(io, user.name, "idle.timeout", null, .ok, "", ip_str);
                return;
            },
            else => return,
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
    file: ?std.Io.File = null,
    /// Whether SSH_FXP_READ is permitted against this handle. Set at
    /// OPEN time from the SFTP open flags + matching `.open_read` policy.
    /// PLAN §6.3: `read` controls SSH_FXP_READ.
    can_read: bool = false,
    /// Whether SSH_FXP_WRITE is permitted against this handle. Set at
    /// OPEN time from the SFTP open flags + matching `.open_write` policy.
    /// PLAN §6.3: `write` controls SSH_FXP_WRITE.
    can_write: bool = false,
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
    next_handle: u32 = 1,
    handles: std.ArrayList(Handle) = .empty,

    fn deinit(self: *SftpState) void {
        for (self.handles.items) |*handle| {
            self.closeHandle(handle);
        }
        self.handles.deinit(self.allocator);
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

        const file_stat = handle.file.?.stat(self.io) catch
            return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "fstat failed");
        try replyAttrs(self.channel, request_id, file_stat);
    }

    fn handleStat(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const path = parseString(payload) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
        if (policy.check(self.user, .stat, path.value) == .deny) {
            // PLAN §8.5: emit audit AFTER replying. `defer` guarantees
            // the audit fires once the reply syscall returns, so a slow
            // audit destination (file on a hung NFS mount) cannot block
            // the client's status reply.
            defer self.auditDenied("stat", path.value);
            return replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }

        const real = self.vfs.resolveExisting(self.io, self.allocator, path.value) catch {
            return replyStatus(self.channel, request_id, c.SSH_FX_NO_SUCH_FILE, "not found");
        };
        defer self.allocator.free(real);

        const stat = std.Io.Dir.cwd().statFile(self.io, real, .{}) catch {
            return replyStatus(self.channel, request_id, c.SSH_FX_NO_SUCH_FILE, "not found");
        };
        try replyAttrs(self.channel, request_id, stat);
    }

    fn handleOpendir(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const path = parseString(payload) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
        if (policy.check(self.user, .readdir, path.value) == .deny) {
            defer self.auditDenied("opendir", path.value);
            return replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
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
        const id = try self.addDirHandle(dir);
        defer self.auditOk("opendir", path.value, "");
        try replyHandle(self.channel, request_id, id);
    }

    fn handleReaddir(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const id = parseHandleId(payload) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad handle");
        const handle = self.findHandle(id, .dir) orelse return replyStatus(self.channel, request_id, c.SSH_FX_INVALID_HANDLE, "bad handle");
        if (handle.dir_done) return replyStatus(self.channel, request_id, c.SSH_FX_EOF, "eof");

        var names: [32]DirName = undefined;
        var count: usize = 0;
        while (count < names.len) {
            const entry = handle.dir_iter.?.next(self.io) catch {
                return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "read dir failed");
            } orelse {
                handle.dir_done = true;
                break;
            };
            names[count] = .{
                .name = try self.allocator.dupe(u8, entry.name),
                .kind = entry.kind,
            };
            count += 1;
        }
        defer for (names[0..count]) |name| self.allocator.free(name.name);

        if (count == 0) return replyStatus(self.channel, request_id, c.SSH_FX_EOF, "eof");
        try replyNames(self.channel, request_id, names[0..count]);
    }

    fn handleOpen(self: *SftpState, request_id: u32, payload: []const u8) !void {
        var cursor = payload;
        const path = parseString(cursor) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
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

        const want_creat = (flags & @as(u32, @intCast(c.SSH_FXF_CREAT))) != 0;
        const want_excl = (flags & @as(u32, @intCast(c.SSH_FXF_EXCL))) != 0;
        const want_trunc = (flags & @as(u32, @intCast(c.SSH_FXF_TRUNC))) != 0;

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
                // Race-free create at the verified parent. `exclusive=true`
                // ensures we don't blindly clobber a file (or symlink) that
                // appeared between our no-follow probe and this createFile.
                // Truncation is deferred until after verifyFile so a
                // hypothetical kernel quirk that defeated O_NOFOLLOW in the
                // probe still can't truncate an outside-jail target.
                const created = parent.parent.createFile(self.io, parent.base, .{
                    .read = want_read,
                    .truncate = false,
                    .exclusive = true,
                }) catch {
                    defer self.auditFailed(op_label, path.value, "create failed");
                    return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "open failed");
                };
                self.vfs.verifyFile(self.io, created) catch {
                    created.close(self.io);
                    defer self.auditDenied(op_label, path.value);
                    return replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
                };
                const id = try self.addFileHandle(created, want_read, want_write);
                defer self.auditOk(op_label, path.value, "");
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

        // Truncation only after the FD is proven inside the jail.
        if (want_trunc and want_write) {
            file.setLength(self.io, 0) catch {
                file.close(self.io);
                defer self.auditFailed(op_label, path.value, "truncate failed");
                return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "truncate failed");
            };
        }

        const id = try self.addFileHandle(file, want_read, want_write);
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
        const offset = readU64(cursor[0..8]);
        const data = parseString(cursor[8..]) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad data");
        const handle = self.findHandle(id, .file) orelse return replyStatus(self.channel, request_id, c.SSH_FX_INVALID_HANDLE, "bad handle");

        // Per PLAN §6.3, `write` permission gates SSH_FXP_WRITE.
        if (!handle.can_write) {
            defer self.auditDenied("write", null);
            return replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }

        handle.file.?.writePositionalAll(self.io, data.value, offset) catch {
            return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "write failed");
        };
        try replyStatus(self.channel, request_id, c.SSH_FX_OK, "ok");
    }

    fn handleClose(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const id = parseHandleId(payload) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad handle");
        for (self.handles.items) |*handle| {
            if (handle.id == id) {
                self.closeHandle(handle);
                handle.kind = .file;
                handle.id = 0;
                return replyStatus(self.channel, request_id, c.SSH_FX_OK, "ok");
            }
        }
        try replyStatus(self.channel, request_id, c.SSH_FX_INVALID_HANDLE, "bad handle");
    }

    fn handleMkdir(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const path = parseString(payload) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
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

        std.Io.Dir.rename(from_parent.parent, from_parent.base, to_parent.parent, to_parent.base, self.io) catch {
            defer self.auditFailed("rename", from.value, "rename failed");
            return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "rename failed");
        };
        defer self.auditOk("rename", from.value, to.value);
        try replyStatus(self.channel, request_id, c.SSH_FX_OK, "ok");
    }

    fn addDirHandle(self: *SftpState, dir: std.Io.Dir) !u32 {
        const id = self.nextHandleId();
        try self.handles.append(self.allocator, .{
            .id = id,
            .kind = .dir,
            .dir = dir,
            .dir_iter = dir.iterate(),
        });
        return id;
    }

    fn addFileHandle(
        self: *SftpState,
        file: std.Io.File,
        can_read: bool,
        can_write: bool,
    ) !u32 {
        const id = self.nextHandleId();
        try self.handles.append(self.allocator, .{
            .id = id,
            .kind = .file,
            .file = file,
            .can_read = can_read,
            .can_write = can_write,
        });
        return id;
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
        handle.dir = null;
        handle.file = null;
    }
};

const DirName = struct {
    name: []const u8,
    kind: std.Io.File.Kind,
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
    if (len > payload_buf.len) return error.LibsshFailure;
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
    const slice_ms: c_int = 1000;
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
        if (n == 0) return error.LibsshFailure; // EOF
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

fn replyNames(channel: c.ssh_channel, request_id: u32, names: []const DirName) !void {
    var buf: [8192]u8 = undefined;
    var w: PacketWriter = .{ .buf = &buf };
    try w.putU8(@intCast(c.SSH_FXP_NAME));
    try w.putU32(request_id);
    try w.putU32(@intCast(names.len));
    for (names) |name| {
        try w.string(name.name);
        try w.string(name.name);
        try writeBasicAttrs(&w, name.kind, 0);
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

fn replyAttrs(channel: c.ssh_channel, request_id: u32, stat: std.Io.File.Stat) !void {
    var buf: [128]u8 = undefined;
    var w: PacketWriter = .{ .buf = &buf };
    try w.putU8(@intCast(c.SSH_FXP_ATTRS));
    try w.putU32(request_id);
    try writeBasicAttrs(&w, stat.kind, stat.size);
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
    try writeBasicAttrs(w, .directory, 0);
}

fn writeBasicAttrs(w: *PacketWriter, kind: std.Io.File.Kind, size: u64) !void {
    const mode: u32 = switch (kind) {
        .directory => @intCast(c.SSH_S_IFDIR | 0o755),
        else => @intCast(c.SSH_S_IFREG | 0o644),
    };
    try w.putU32(@intCast(c.SSH_FILEXFER_ATTR_SIZE | c.SSH_FILEXFER_ATTR_PERMISSIONS));
    try w.putU64(size);
    try w.putU32(mode);
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
