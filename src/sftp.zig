const std = @import("std");
const builtin = @import("builtin");
const c = @import("libssh");
const audit = @import("audit.zig");
const config = @import("config.zig");
const listing = @import("listing.zig");
const policy = @import("policy.zig");
const vfs_mod = @import("vfs.zig");
const wire = @import("wire.zig");

/// Floor for staging-orphan age before unlink. Concurrent sessions for
/// the same partner may still be writing; never delete files younger
/// than this even when idle-timeout is short or disabled.
const staging_orphan_min_age_ms: i64 = 15 * 60 * 1000;

/// macOS exclusive rename (same role as Linux renameat2 NOREPLACE).
const RENAME_EXCL: c_uint = 0x00000004;
extern "c" fn renameatx_np(c_int, [*:0]const u8, c_int, [*:0]const u8, c_uint) c_int;

const sftp_max_packet_bytes = wire.sftp_max_packet_bytes;
const DirEntry = wire.DirEntry;
const parentErrorStatus = wire.parentErrorStatus;
const writeVersion = wire.writeVersion;
const replyName = wire.replyName;
const replyNames = wire.replyNames;
const replyHandle = wire.replyHandle;
const replyDirAttrs = wire.replyDirAttrs;
const replyFullAttrs = wire.replyFullAttrs;
const replyData = wire.replyData;
const replyStatus = wire.replyStatus;
const readU32 = wire.readU32;
const readU64 = wire.readU64;
const parseString = wire.parseString;
const parseHandleId = wire.parseHandleId;

/// Maximum simultaneously-open file/dir handles per SFTP session.
pub const max_handles_per_session: usize = 256;

fn nowUnixSecs() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return @as(i64, ts.sec);
}

pub fn acceptSftpSubsystem(session: c.ssh_session) !c.ssh_channel {
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

pub fn runSftp(
    io: std.Io,
    allocator: std.mem.Allocator,
    channel: c.ssh_channel,
    user: *const config.UserConfig,
    server_cfg: config.ServerConfig,
    peer_ip: ?[]const u8,
) !void {
    var jail = try vfs_mod.Vfs.init(io, allocator, user.root);
    defer jail.deinit(allocator);

    const start_ms = audit.nowMonotonicMs();
    var state = SftpState{
        .io = io,
        .allocator = allocator,
        .channel = channel,
        .user = user,
        .peer_ip = peer_ip,
        .vfs = jail,
        .idle_timeout_ms = server_cfg.idle_timeout_ms,
        .listing_mode = server_cfg.listing_mode,
        .publish_mode = server_cfg.publish_mode,
        .mkdir_mode = server_cfg.mkdir_mode,
        .last_activity_ms = start_ms,
        .session_started_ms = start_ms,
    };
    defer state.deinit();

    // Post-login sweep of crash orphans under this partner's staging
    // dir only. Other partners' roots are never touched; in-flight
    // files younger than the age floor are left alone.
    state.sweepStagingOrphans();

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
    state.last_activity_ms = audit.nowMonotonicMs();

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
        state.last_activity_ms = audit.nowMonotonicMs();
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
    /// `<root>/.zift/staging/<staging_basename>` instead of the
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
    /// `publish-mode` from the server config (v0.6.0+). Mode applied
    /// to atomically-published files at OPEN time; preserved by
    /// rename(2) so this is also the on-disk mode partners' uploads
    /// land at after CLOSE. Default `0o660`.
    publish_mode: u32 = 0o660,
    /// `mkdir-mode` from the server config (v0.6.0+). Mode applied
    /// to directories created via SFTP `MKDIR`. Carries the setgid
    /// bit so subdirectories inherit the partner-tree's group
    /// ownership. Default `0o2770`.
    mkdir_mode: u32 = 0o2770,
    /// v0.5.0 staging-rename: open Dir fd to `<root>/.zift/staging/`,
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
        // Crash orphans are also swept at next login for this partner
        // (see sweepStagingOrphans). Per-handle unlink covers clean
        // disconnect mid-upload.
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
        const duration_ms: i64 = audit.nowMonotonicMs() - self.session_started_ms;
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
    /// Validate and NORMALIZE a client-supplied path before it is used
    /// for either authorization or filesystem resolution. Returns the
    /// normalized slice (living in `out`), or null after replying an
    /// error status to the client.
    ///
    /// This is the fix for the normalize-after-authorize bypass: every
    /// path handler now runs `policy.check` against the SAME normalized
    /// string the VFS layer will resolve, so `/pending/../secret` and
    /// `/pending/x.exe/` can no longer smuggle past a `deny`/scope rule.
    ///
    /// Status mapping preserves prior behavior: malformed bytes /
    /// invalid UTF-8 / over-length → BAD_MESSAGE; traversal above root
    /// and the reserved `.zift` namespace → PERMISSION_DENIED.
    fn normalizedPath(self: *SftpState, request_id: u32, raw: []const u8, out: []u8) !?[]const u8 {
        vfs_mod.Vfs.validateVirtualPath(raw) catch {
            try replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
            return null;
        };
        return vfs_mod.normalizeVirtualInto(raw, out) catch {
            try replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
            return null;
        };
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
        // FSTAT works on either a file OR a directory handle — OpenSSH's
        // sftp-server permits FSTAT on an open dir handle, and some
        // clients rely on it. Look up either kind.
        const handle = self.findHandle(id, .file) orelse
            self.findHandle(id, .dir) orelse
            return replyStatus(self.channel, request_id, c.SSH_FX_INVALID_HANDLE, "bad handle");

        // `listing.statFd` returns the same shape we use for READDIR
        // (real mode, uid, gid, size, mtime), so STAT/FSTAT/READDIR
        // are now consistent — partner gets the same fields whether
        // they ask via "ls -la" or "stat <file>".
        const fd = switch (handle.kind) {
            .file => handle.file.?.handle,
            .dir => handle.dir.?.handle,
        };
        const info = listing.statFd(fd) catch
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
            switch (handle.kind) {
                .file => {
                    // No vpath for a file handle; derive the mode from
                    // the per-handle access bits recorded at OPEN time —
                    // those are the truth about what's permitted here.
                    const file_type = info.mode & 0o170000;
                    var owner: u32 = 0;
                    if (handle.can_read) owner |= 0o4;
                    if (handle.can_write) owner |= 0o2;
                    display.mode = file_type | (owner << 6) | (owner << 3);
                },
                .dir => {
                    // A dir handle DOES carry its vpath, so we can render
                    // the same policy-derived mode READDIR would show.
                    if (handle.dir_vpath) |vpath| {
                        display.mode = policy.policyDerivedMode(self.user, vpath, info.mode);
                    }
                    display.uid = 0;
                    display.gid = 0;
                },
            }
        }
        try replyFullAttrs(self.channel, request_id, display);
    }

    fn handleStat(self: *SftpState, request_id: u32, payload: []const u8) !void {
        var path = parseString(payload) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
        var vbuf: [vfs_mod.max_virtual_path_bytes + 2]u8 = undefined;
        path.value = (try self.normalizedPath(request_id, path.value, &vbuf)) orelse return;
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
        if (std.mem.eql(u8, path.value, "/")) {
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
        var path = parseString(payload) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
        var vbuf: [vfs_mod.max_virtual_path_bytes + 2]u8 = undefined;
        path.value = (try self.normalizedPath(request_id, path.value, &vbuf)) orelse return;
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

            // v0.8.0: hide the zift namespace dir from listings. Every
            // partner root has a `<root>/.zift/` once a session has
            // uploaded (lazy-created by openStagingDir; may also be
            // pre-created by the operator to hold notes alongside).
            // The path-validator already rejects any virtual path
            // containing `.zift` (or the legacy `.zift-staging`), so a
            // partner can't OPEN/REMOVE/STAT anything inside via the
            // SFTP wire surface. But READDIR walks the real filesystem
            // and would surface the entry as "exists with no
            // permissions" — leaking the implementation detail and
            // cluttering listings. Skip it here, before the stat call,
            // so it never reaches the partner's view at all.
            //
            // Also hide a stray legacy `.zift-staging` directory left
            // behind by an unswept v0.5.x–v0.7.x install. The validator
            // already rejects it as a path component; this just keeps
            // it out of READDIR results during the transition.
            if (vfs_mod.isReservedComponent(entry.name)) continue;

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
                    // Overflow (legal but very long paths) heap-
                    // allocates so child-specific deny rules stay
                    // accurate in virtual listings.
                    const sep: []const u8 = if (std.mem.endsWith(u8, dir_vpath, "/")) "" else "/";
                    const stacked = std.fmt.bufPrint(&vpath_buf, "{s}{s}{s}", .{
                        dir_vpath, sep, entry.name,
                    });
                    var heap_vpath: ?[]u8 = null;
                    defer if (heap_vpath) |p| self.allocator.free(p);
                    const vpath: []const u8 = stacked catch blk: {
                        heap_vpath = std.fmt.allocPrint(self.allocator, "{s}{s}{s}", .{
                            dir_vpath, sep, entry.name,
                        }) catch break :blk dir_vpath;
                        break :blk heap_vpath.?;
                    };
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
        var path = parseString(cursor) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
        cursor = path.rest;
        var vbuf: [vfs_mod.max_virtual_path_bytes + 2]u8 = undefined;
        path.value = (try self.normalizedPath(request_id, path.value, &vbuf)) orelse return;
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
                // through a staging file in `<root>/.zift/staging/`,
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

                // The staging file is created with the configured
                // `publish-mode` (default 0o660) so it lands at the
                // target with the right mode after the atomic rename
                // — POSIX rename(2) preserves the inode and its mode.
                // Confidentiality of partial uploads during transfer
                // is enforced by `<root>/.zift/staging/` itself being
                // mode 0o700 (only the zift UID can traverse it),
                // independent of the file's own mode. The explicit
                // `setPermissions` after `createFile` is required to
                // defeat the daemon's umask, which would otherwise
                // mask the requested mode bits.
                const publish_mode = self.publish_mode;
                const created = staging.createFile(self.io, staging_name, .{
                    .read = want_read,
                    .truncate = false,
                    .exclusive = true,
                    .permissions = .fromMode(@intCast(publish_mode)),
                }) catch {
                    defer self.auditFailed(op_label, path.value, "staging create failed");
                    return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "open failed");
                };
                created.setPermissions(self.io, .fromMode(@intCast(publish_mode))) catch {
                    var f = created;
                    f.close(self.io);
                    staging.deleteFile(self.io, staging_name) catch {};
                    defer self.auditFailed(op_label, path.value, "staging chmod failed");
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
        // checked above as `.open_write`) AND `.update` permission
        // on this path. The `.update` half is the clobber check: it
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
        if (want_write and policy.check(self.user, .update, path.value) == .deny) {
            file.close(self.io);
            defer self.auditDenied(op_label, path.value);
            return replyStatus(
                self.channel,
                request_id,
                c.SSH_FX_PERMISSION_DENIED,
                "permission denied",
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

        // A 64-bit offset above i64::MAX cannot be a real file position;
        // the kernel would reject it (or, in a Debug build, the std
        // pread path bit-casts it negative and panics). Reject cleanly.
        if (offset > std.math.maxInt(i64)) {
            return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad offset");
        }

        // Per PLAN §6.3, `read` permission gates SSH_FXP_READ. Enforcing
        // this only at OPEN time would let a write-only-permitted client
        // exfiltrate via the same handle they wrote to.
        if (!handle.can_read) {
            defer self.auditDenied("read", null);
            return replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }

        // A legitimate 0-byte read gets a 0-byte DATA reply, not EOF —
        // EOF here would be a spurious end-of-file for a client that
        // deliberately asked for nothing.
        if (len == 0) return replyData(self.channel, request_id, "");

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

        // Reject an out-of-range write offset up front (same reasoning
        // as READ). Append mode ignores the client offset entirely.
        if (client_offset > std.math.maxInt(i64)) {
            return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad offset");
        }

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
                    // sized to the normalizer's output ceiling. The
                    // stored target is the *normalized* virtual path,
                    // and normalizeVirtualInto can emit one byte more
                    // than its input (a bare `a` gains a leading `/`),
                    // so the bound is max_virtual_path_bytes + 1, not
                    // the raw validator's 4096. Hard-asserting `tv.len`
                    // is within bounds (rather than silently
                    // truncating) so a path-validator regression that
                    // let a longer path through can't make two
                    // attacker-controlled prefixes collide in the
                    // audit log.
                    var audit_target_buf: [vfs_mod.max_virtual_path_bytes + 1]u8 = undefined;
                    const audit_target = blk: {
                        const tv = handle.staging_target_vpath.?;
                        std.debug.assert(tv.len <= audit_target_buf.len);
                        @memcpy(audit_target_buf[0..tv.len], tv);
                        break :blk audit_target_buf[0..tv.len];
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
                        return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "failure");
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
                    // Wire-facing reply messages use SFTP-standard
                    // terminology only — partners should not see
                    // zift-internal vocabulary like "publish",
                    // "staging", "clobber", or "partner". The audit
                    // log keeps the full diagnostic detail server-
                    // side; the wire reply just maps each SSH_FX
                    // status to its standard human-readable phrase.
                    const reply_msg: []const u8 = switch (close_status) {
                        c.SSH_FX_OK => "ok",
                        c.SSH_FX_PERMISSION_DENIED => "permission denied",
                        c.SSH_FX_FAILURE => "file exists",
                        else => "failure",
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

    /// Rename a staged file from `<root>/.zift/staging/<basename>`
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

        // Re-check the clobber rule at CLOSE time. The OPEN-time
        // check fired only if the target existed THEN; in the gap
        // between OPEN and CLOSE another session could have created
        // the target. lstat the destination via the verified parent
        // FD using the AT_SYMLINK_NOFOLLOW path. A dangling symlink
        // counts as "exists" — rename would replace the symlink
        // entry, which is exactly the clobber we want to gate on.
        const dest_exists = blk: {
            _ = listing.statAt(to_parent.parent.handle, to_parent.base) catch |err| switch (err) {
                error.NotFound => break :blk false,
                else => return err,
            };
            break :blk true;
        };

        const may_replace = !handle.staging_excl and
            policy.check(self.user, .update, target_vpath) == .allow;

        if (dest_exists and !may_replace) {
            if (handle.staging_excl) {
                self.auditDenied("close", target_vpath);
                return c.SSH_FX_FAILURE;
            }
            self.auditDenied("close", target_vpath);
            return c.SSH_FX_PERMISSION_DENIED;
        }

        // Atomic publish. When the partner must not clobber, use the
        // platform no-replace rename so a create-between-stat-and-
        // rename race cannot overwrite. When replace is authorized,
        // POSIX rename replaces atomically.
        if (may_replace) {
            std.Io.Dir.rename(
                staging,
                staging_basename,
                to_parent.parent,
                to_parent.base,
                self.io,
            ) catch |err| return err;
        } else {
            renameNoReplace(
                staging,
                staging_basename,
                to_parent.parent,
                to_parent.base,
                self.io,
            ) catch |err| switch (err) {
                error.PathAlreadyExists => {
                    if (handle.staging_excl) {
                        self.auditDenied("close", target_vpath);
                        return c.SSH_FX_FAILURE;
                    }
                    self.auditDenied("close", target_vpath);
                    return c.SSH_FX_PERMISSION_DENIED;
                },
                else => return err,
            };
        }

        // Rename succeeded — clear staging_basename so closeHandle
        // doesn't unlink the file we just published.
        self.allocator.free(staging_basename);
        handle.staging_basename = null;

        return c.SSH_FX_OK;
    }

    fn handleMkdir(self: *SftpState, request_id: u32, payload: []const u8) !void {
        var path = parseString(payload) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
        var vbuf: [vfs_mod.max_virtual_path_bytes + 2]u8 = undefined;
        path.value = (try self.normalizedPath(request_id, path.value, &vbuf)) orelse return;
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

        // Mode is the configured `mkdir-mode` (default 0o2770). The
        // setgid bit propagates `group=zift` to descendants so any
        // subdirectories alice creates within get the same operator-
        // group ownership as the partner-tree root, without zift
        // having to chmod after creation.
        const dir_mode = std.Io.File.Permissions.fromMode(@intCast(self.mkdir_mode));
        parent.parent.createDir(self.io, parent.base, dir_mode) catch {
            defer self.auditFailed("mkdir", path.value, "createDir failed");
            return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "mkdir failed");
        };
        // `createDir` honors umask, so the on-disk mode at this
        // moment may be more restrictive than `mkdir-mode`. Reopen +
        // setPermissions to pin the exact mode regardless of umask.
        // If either step fails we roll back the createDir so the
        // partner sees a clean failure and an honest result code —
        // returning SSH_FX_OK on a directory whose mode doesn't match
        // the configured `mkdir-mode` would be a silent contract
        // violation.
        var created_dir = parent.parent.openDir(self.io, parent.base, .{}) catch {
            parent.parent.deleteDir(self.io, parent.base) catch {};
            defer self.auditFailed("mkdir", path.value, "openDir-after-create failed");
            return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "mkdir failed");
        };
        created_dir.setPermissions(self.io, dir_mode) catch {
            created_dir.close(self.io);
            // Best-effort rollback. deleteDir naturally fails if
            // something raced and populated the dir between create
            // and rollback; that's fine — leave whatever's there
            // and report failure.
            parent.parent.deleteDir(self.io, parent.base) catch {};
            defer self.auditFailed("mkdir", path.value, "setPermissions failed");
            return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "mkdir failed");
        };
        created_dir.close(self.io);
        defer self.auditOk("mkdir", path.value, "");
        try replyStatus(self.channel, request_id, c.SSH_FX_OK, "ok");
    }

    fn handleRemove(self: *SftpState, request_id: u32, payload: []const u8) !void {
        var path = parseString(payload) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
        var vbuf: [vfs_mod.max_virtual_path_bytes + 2]u8 = undefined;
        path.value = (try self.normalizedPath(request_id, path.value, &vbuf)) orelse return;
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
        var path = parseString(payload) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
        var vbuf: [vfs_mod.max_virtual_path_bytes + 2]u8 = undefined;
        path.value = (try self.normalizedPath(request_id, path.value, &vbuf)) orelse return;
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
        var from = parseString(payload) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad source");
        var to = parseString(from.rest) catch return replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad destination");
        var from_buf: [vfs_mod.max_virtual_path_bytes + 2]u8 = undefined;
        var to_buf: [vfs_mod.max_virtual_path_bytes + 2]u8 = undefined;
        from.value = (try self.normalizedPath(request_id, from.value, &from_buf)) orelse return;
        to.value = (try self.normalizedPath(request_id, to.value, &to_buf)) orelse return;
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
        // destination exists in any form, require `.update`
        // permission on the destination path.
        //
        // Overwrite requires `.update` on the destination. When the
        // partner lacks it, use a no-replace rename so a create-
        // between-check-and-rename race cannot clobber. When replace
        // is authorized, POSIX rename replaces atomically.
        const may_replace = policy.check(self.user, .update, to.value) == .allow;
        if (may_replace) {
            std.Io.Dir.rename(from_parent.parent, from_parent.base, to_parent.parent, to_parent.base, self.io) catch {
                defer self.auditFailed("rename", from.value, "rename failed");
                return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "rename failed");
            };
        } else {
            renameNoReplace(from_parent.parent, from_parent.base, to_parent.parent, to_parent.base, self.io) catch |err| switch (err) {
                error.PathAlreadyExists => {
                    defer self.auditDenied("rename", to.value);
                    return replyStatus(
                        self.channel,
                        request_id,
                        c.SSH_FX_PERMISSION_DENIED,
                        "permission denied",
                    );
                },
                else => {
                    defer self.auditFailed("rename", from.value, "rename failed");
                    return replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "rename failed");
                },
            };
        }
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

        const id = try self.nextHandleId();
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

        const id = try self.nextHandleId();
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
    /// fd points at a randomly-named file in `<root>/.zift/staging/`,
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

        const id = try self.nextHandleId();
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

    /// Lazily open `<root>/.zift/staging/`, creating it if needed.
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

    /// Unlink crash orphans under this partner's `<root>/.zift/staging/`.
    /// Safe across partners (each jail is separate). Safe with concurrent
    /// sessions for the same partner by only deleting files older than
    /// `max(idle_timeout, 15m)`.
    fn sweepStagingOrphans(self: *SftpState) void {
        var dir = self.vfs.tryOpenExistingStagingDir(self.io) orelse return;
        defer dir.close(self.io);

        const age_floor_ms: i64 = @max(@as(i64, @intCast(self.idle_timeout_ms)), staging_orphan_min_age_ms);
        const now_secs = nowUnixSecs();
        const min_age_secs: i64 = @divTrunc(age_floor_ms + 999, 1000);

        var it = dir.iterate();
        while (it.next(self.io) catch null) |entry| {
            if (entry.kind != .file) continue;
            const info = listing.statAt(dir.handle, entry.name) catch continue;
            if (now_secs - info.mtime_secs < min_age_secs) continue;
            dir.deleteFile(self.io, entry.name) catch {};
        }
    }

    /// Rename that fails with PathAlreadyExists instead of replacing.
    /// Linux: renameat2(NOREPLACE). macOS: renameatx_np(RENAME_EXCL).
    fn renameNoReplace(
        old_dir: std.Io.Dir,
        old_sub_path: []const u8,
        new_dir: std.Io.Dir,
        new_sub_path: []const u8,
        io: std.Io,
    ) !void {
        if (builtin.os.tag == .linux) {
            try std.Io.Dir.renamePreserve(old_dir, old_sub_path, new_dir, new_sub_path, io);
            return;
        }
        if (builtin.os.tag == .macos) {
            var old_buf: [std.fs.max_name_bytes + 1]u8 = undefined;
            var new_buf: [std.fs.max_name_bytes + 1]u8 = undefined;
            if (old_sub_path.len >= old_buf.len or new_sub_path.len >= new_buf.len)
                return error.NameTooLong;
            @memcpy(old_buf[0..old_sub_path.len], old_sub_path);
            old_buf[old_sub_path.len] = 0;
            @memcpy(new_buf[0..new_sub_path.len], new_sub_path);
            new_buf[new_sub_path.len] = 0;
            const rc = renameatx_np(
                old_dir.handle,
                @ptrCast(&old_buf),
                new_dir.handle,
                @ptrCast(&new_buf),
                RENAME_EXCL,
            );
            if (rc == 0) return;
            return switch (std.posix.errno(rc)) {
                .EXIST => error.PathAlreadyExists,
                .NOENT => error.FileNotFound,
                .ACCES, .PERM => error.AccessDenied,
                .NOTDIR => error.NotDir,
                .ISDIR => error.IsDir,
                .INVAL => error.Unexpected,
                else => error.Unexpected,
            };
        }
        // Other platforms: Zig's renamePreserve falls back to
        // hardlink+unlink, which is still no-replace for files.
        try std.Io.Dir.renamePreserve(old_dir, old_sub_path, new_dir, new_sub_path, io);
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
                // `std.os.linux.errno`, NOT `std.posix.errno` — see
                // src/listing.zig statAt for the long-form rationale
                // on why those two converters disagree on raw-syscall
                // returns when libc is linked. Using the wrong one
                // here would have masked every getrandom failure
                // (EINTR, ENOSYS, etc.) as SUCCESS with rc=0, then
                // eaten the rc==0 guard below as the only remaining
                // signal. Same fix applied at every other raw-syscall
                // site in zift.
                switch (std.os.linux.errno(rc)) {
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
        // `std.os.linux.errno` for raw-syscall returns; see statAt.
        switch (linux.errno(fd_rc)) {
            .SUCCESS => {},
            else => return error.RandomFailed,
        }
        const fd: i32 = @intCast(fd_rc);
        defer _ = linux.close(fd);

        var filled: usize = 0;
        while (filled < buf.len) {
            const rc = linux.read(fd, buf.ptr + filled, buf.len - filled);
            switch (linux.errno(rc)) {
                .SUCCESS => {
                    if (rc == 0) return error.RandomFailed;
                    filled += @intCast(rc);
                },
                .INTR => continue,
                else => return error.RandomFailed,
            }
        }
    }

    fn nextHandleId(self: *SftpState) !u32 {
        // Monotonic and never reused, which is what makes use-after-close
        // structurally impossible. Refuse to wrap: at u32::MAX we return
        // an error (the caller replies FAILURE) rather than `+= 1`
        // panicking in a safe build, and rather than wrapping — which
        // would reintroduce id reuse and the aliasing it prevents. A
        // session that opens 2^32 handles is pathological churn; it can
        // reconnect.
        if (self.next_handle == std.math.maxInt(u32)) return error.HandleSpaceExhausted;
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
                    const elapsed: i64 = audit.nowMonotonicMs() - state.last_activity_ms;
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
                const elapsed: i64 = audit.nowMonotonicMs() - state.last_activity_ms;
                if (elapsed >= @as(i64, @intCast(state.idle_timeout_ms))) {
                    return error.IdleTimeout;
                }
            }
            continue;
        }
        // Real bytes arrived: the channel is making progress, so clear
        // the spurious-EOF counter. Without this reset it accumulates
        // across the whole session lifetime, so a long-lived healthy
        // connection that absorbs 1000 spurious EOFs over many hours
        // would eventually be dropped mid-transfer.
        state.spurious_eof_count = 0;
        offset += @intCast(n);
    }
}
