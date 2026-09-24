//! SFTP v3 request loop and handlers for one authenticated session.
//!
//! Every path is normalized once and authorized on that same string, then
//! resolved by a NOFOLLOW descriptor walk from the partner root (vfs). New
//! files are written under `<root>/.zift/staging/` and renamed into place
//! at CLOSE, so a partial upload is never visible. Overwriting an existing
//! entry needs `update` (the clobber rule). See docs/security.md.

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
/// than this even when idle-timeout is short or disabled. Names still
/// registered to a live handle are kept regardless of age.
const staging_orphan_min_age_ms: i64 = 15 * 60 * 1000;

/// Serializes namespace changes across sessions, so a directory rename's
/// subtree authorization sees the same tree the rename then moves.
/// Operator-side changes are outside the threat model.
var namespace_mutation_mutex: std.Io.Mutex = .init;

const StagingLive = struct {
    root: []u8,
    name: [32]u8,
};

/// Live staging names (partner root + 32-byte name). Lock order is
/// `namespace_mutation_mutex` then `staging_live_mutex`; never acquire
/// `namespace_mutation_mutex` while holding `staging_live_mutex`.
var staging_live_mutex: std.Io.Mutex = .init;
var staging_live: std.ArrayList(StagingLive) = .empty;

/// Ignored SSH messages tolerated before the sftp subsystem is accepted.
const max_ignored_pre_subsystem: u32 = 64;

/// Bound the work a single directory rename can force. A larger tree
/// fails closed instead of monopolizing a session thread indefinitely.
const max_rename_scan_entries: usize = 100_000;
const max_rename_scan_depth: usize = 256;

/// macOS exclusive rename (same role as Linux renameat2 NOREPLACE).
const RENAME_EXCL: c_uint = 0x00000004;
extern "c" fn renameatx_np(c_int, [*:0]const u8, c_int, [*:0]const u8, c_uint) c_int;

/// Maximum simultaneously-open file/dir handles per SFTP session.
pub const max_handles_per_session: usize = 256;

fn nowUnixSecs() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return @as(i64, ts.sec);
}

fn appendVirtualChild(
    allocator: std.mem.Allocator,
    parent: []const u8,
    name: []const u8,
) ![]u8 {
    const path = if (std.mem.eql(u8, parent, "/"))
        try std.fmt.allocPrint(allocator, "/{s}", .{name})
    else
        try std.fmt.allocPrint(allocator, "{s}/{s}", .{ parent, name });
    if (path.len > vfs_mod.max_virtual_path_bytes) {
        allocator.free(path);
        return error.RenameDenied;
    }
    return path;
}

pub fn acceptSftpSubsystem(session: c.ssh_session) !c.ssh_channel {
    var channel: c.ssh_channel = null;
    var ignored: u32 = 0;

    while (channel == null) {
        const msg = c.ssh_message_get(session) orelse return error.LibsshFailure;
        defer c.ssh_message_free(msg);

        if (c.ssh_message_type(msg) == c.SSH_REQUEST_CHANNEL_OPEN and
            c.ssh_message_subtype(msg) == c.SSH_CHANNEL_SESSION)
        {
            channel = c.ssh_message_channel_request_open_reply_accept(msg);
            if (channel != null) continue;
            try noteIgnoredPreSubsystem(&ignored);
            continue;
        }

        try noteIgnoredPreSubsystem(&ignored);
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

        try noteIgnoredPreSubsystem(&ignored);
        _ = c.ssh_message_reply_default(msg);
    }
}

fn noteIgnoredPreSubsystem(count: *u32) error{LibsshFailure}!void {
    if (preSubsystemIgnoreSaturated(count.*)) return error.LibsshFailure;
    count.* += 1;
}

fn preSubsystemIgnoreSaturated(ignored: u32) bool {
    return ignored >= max_ignored_pre_subsystem;
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

    state.sweepStagingOrphans();

    // On the heap: 256 KiB is too much for a worker stack.
    const payload_buf = try allocator.alloc(u8, wire.sftp_max_packet_bytes);
    defer allocator.free(payload_buf);

    const ip_str = peer_ip orelse "";
    const first_payload = readPacketTimed(&state, payload_buf) catch |err| switch (err) {
        error.IdleTimeout => {
            audit.log(io, user.name, "idle.timeout", null, .ok, "", ip_str);
            return;
        },
        else => return err,
    };
    try acceptInitPayload(first_payload);
    try wire.writeVersion(channel);
    state.last_activity_ms = audit.nowMonotonicMs();

    while (true) {
        const payload = readPacketTimed(&state, payload_buf) catch |err| switch (err) {
            error.IdleTimeout => {
                state.emitSessionEnded("idle timeout", .ok, ip_str);
                return;
            },
            error.ChannelEof => {
                state.emitSessionEnded("client closed channel", .ok, ip_str);
                return;
            },
            error.LibsshFailure => {
                // Record libssh's reason. `ssh_get_error` must get the
                // session, not the channel: it casts its argument to the
                // error struct that only a session begins with.
                var lib_buf: [128]u8 = undefined;
                var lw = std.Io.Writer.fixed(&lib_buf);
                lw.writeAll("LibsshFailure: ") catch {};
                const session = c.ssh_channel_get_session(state.channel);
                const lib_err = if (session != null)
                    c.ssh_get_error(@as(?*anyopaque, @ptrCast(session)))
                else
                    null;
                const lib_msg: []const u8 = if (lib_err != null) std.mem.span(lib_err) else "";

                // libssh turns every SSH_MSG_DISCONNECT into SSH_FATAL, so
                // a client's ordinary goodbye (reason 11, how GUI clients
                // close) lands here. Only that code counts as a clean end.
                if (disconnectReason(lib_msg)) |code| {
                    if (code == ssh2_disconnect_by_application) {
                        state.emitSessionEnded("client disconnected", .ok, ip_str);
                        return;
                    }
                }

                lw.writeAll(lib_msg) catch {};
                state.emitSessionEnded(lw.buffered(), .failed, ip_str);
                return;
            },
        };
        state.last_activity_ms = audit.nowMonotonicMs();
        if (payload.len < 5) return error.LibsshFailure;

        const msg_type = payload[0];
        const request_id = wire.readU32(payload[1..5]);
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
            // Clients probe these; OP_UNSUPPORTED (not FAILURE) tells them
            // the operation does not exist here.
            c.SSH_FXP_SETSTAT,
            c.SSH_FXP_FSETSTAT,
            c.SSH_FXP_READLINK,
            c.SSH_FXP_SYMLINK,
            c.SSH_FXP_EXTENDED,
            => try wire.replyStatus(channel, request_id, c.SSH_FX_OP_UNSUPPORTED, "unsupported"),
            else => try wire.replyStatus(channel, request_id, c.SSH_FX_OP_UNSUPPORTED, "unsupported"),
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
    /// The iterator failed; later READDIRs fail rather than skip names.
    dir_failed: bool = false,
    /// Owned virtual path of a dir handle, so listings can ask the policy
    /// about `<dir_vpath>/<name>`.
    dir_vpath: ?[]const u8 = null,
    file: ?std.Io.File = null,
    /// Access granted at OPEN; READ and WRITE check it again, so a
    /// write-only handle cannot be used to read.
    can_read: bool = false,
    can_write: bool = false,
    /// SSH_FXF_APPEND: fd has O_APPEND and WRITE ignores the offset.
    is_append: bool = false,
    /// Staged upload: the fd is `<root>/.zift/staging/<staging_basename>`
    /// and CLOSE renames it to `staging_target_vpath`. Both owned.
    staging_target_vpath: ?[]const u8 = null,
    staging_basename: ?[]const u8 = null,
    /// SSH_FXF_EXCL on a staged handle: a target that appeared during the
    /// upload fails the CLOSE instead of being replaced.
    staging_excl: bool = false,
};

const SftpState = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    channel: c.ssh_channel,
    user: *const config.UserConfig,
    /// Borrowed from `handleSession`, which outlives this state.
    peer_ip: ?[]const u8 = null,
    vfs: vfs_mod.Vfs,
    /// 0 disables the idle check.
    idle_timeout_ms: u64 = 0,
    last_activity_ms: i64 = 0,
    session_started_ms: i64 = 0,
    /// Consecutive false EOFs from libssh (see `readExactTimed`); reported
    /// in `session.ended`.
    spurious_eof_count: u32 = 0,
    next_handle: u32 = 1,
    handles: std.ArrayList(Handle) = .empty,
    /// uid/gid names for `listing-mode reality`; per session, so no
    /// partner can influence another's cache.
    name_resolver: listing.NameResolver = .{},
    listing_mode: config.ListingMode = .virtual,
    publish_mode: u32 = 0o660,
    mkdir_mode: u32 = 0o2770,
    /// `<root>/.zift/staging/`, opened on the first staged upload.
    staging_dir: ?std.Io.Dir = null,

    fn deinit(self: *SftpState) void {
        // Unlinks staging files whose CLOSE never came. Crash orphans are
        // swept at the partner's next login instead.
        for (self.handles.items) |*handle| {
            self.closeHandle(handle);
        }
        self.handles.deinit(self.allocator);
        if (self.staging_dir) |*dir| dir.close(self.io);
        self.staging_dir = null;
    }

    /// `session.ended` with `(duration_ms=N[, spurious_eof=N])` appended.
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

    /// Normalize a client path into `out`, or reply an error and return
    /// null (the session continues). Policy must see the same string the
    /// filesystem resolves, or `/pending/../secret` slips past a rule.
    /// Bad bytes or length: BAD_MESSAGE. Traversal or `.zift`: DENIED.
    fn normalizedPath(self: *SftpState, request_id: u32, raw: []const u8, out: []u8) !?[]const u8 {
        vfs_mod.Vfs.validateVirtualPath(raw) catch {
            try wire.replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
            return null;
        };
        return vfs_mod.normalizeVirtualInto(raw, out) catch {
            try wire.replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
            return null;
        };
    }

    /// Attrs as the partner sees them. `virtual`: uid/gid 0 and
    /// policy-derived mode at `vpath`. `reality`: the inode unchanged.
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
        const parsed = wire.parseString(payload) catch
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
        var vbuf: [vfs_mod.max_virtual_path_bytes + 2]u8 = undefined;
        const normalized = (try self.normalizedPath(request_id, parsed.value, &vbuf)) orelse return;
        try wire.replyName(self.channel, request_id, normalized);
    }

    /// FSTAT inherits the OPEN's authorization; no new policy check.
    fn handleFstat(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const id = wire.parseHandleId(payload) catch
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad handle");
        // Dir handles too, as OpenSSH's sftp-server allows.
        const handle = self.findHandle(id, .file) orelse
            self.findHandle(id, .dir) orelse
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_INVALID_HANDLE, "bad handle");

        const fd = switch (handle.kind) {
            .file => handle.file.?.handle,
            .dir => handle.dir.?.handle,
        };
        const info = listing.statFd(fd) catch
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "fstat failed");

        var display = self.applyListingMode(info, null);
        if (self.listing_mode == .virtual) {
            switch (handle.kind) {
                .file => {
                    // No path: the handle's own access is the truth.
                    const file_type = info.mode & 0o170000;
                    var owner: u32 = 0;
                    if (handle.can_read) owner |= 0o4;
                    if (handle.can_write) owner |= 0o2;
                    display.mode = file_type | (owner << 6) | (owner << 3);
                },
                .dir => {
                    if (handle.dir_vpath) |vpath| {
                        display.mode = policy.policyDerivedMode(self.user, vpath, info.mode);
                    }
                    display.uid = 0;
                    display.gid = 0;
                },
            }
        }
        try wire.replyFullAttrs(self.channel, request_id, display);
    }

    fn handleStat(self: *SftpState, request_id: u32, payload: []const u8) !void {
        var path = wire.parseString(payload) catch return wire.replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
        var vbuf: [vfs_mod.max_virtual_path_bytes + 2]u8 = undefined;
        path.value = (try self.normalizedPath(request_id, path.value, &vbuf)) orelse return;
        if (policy.check(self.user, .stat, path.value) == .deny) {
            // Audit via `defer`, after the reply, so a slow audit
            // destination never delays the client.
            defer self.auditDenied("stat", path.value);
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }

        // "/" has no parent in the jail; stat the root itself.
        if (std.mem.eql(u8, path.value, "/")) {
            var root_dir = std.Io.Dir.cwd().openDir(self.io, self.vfs.root, .{ .iterate = false }) catch {
                return wire.replyStatus(self.channel, request_id, c.SSH_FX_NO_SUCH_FILE, "not found");
            };
            defer root_dir.close(self.io);
            const root_info = listing.statFd(root_dir.handle) catch
                return wire.replyStatus(self.channel, request_id, c.SSH_FX_NO_SUCH_FILE, "not found");
            return wire.replyFullAttrs(self.channel, request_id, self.applyListingMode(root_info, "/"));
        }

        // STAT and LSTAT both lstat the final component under the verified
        // parent fd, so a symlink is reported, never followed.
        var parent = self.vfs.openVerifiedParent(self.io, self.allocator, path.value) catch |err| {
            const status = wire.parentErrorStatus(err);
            return wire.replyStatus(self.channel, request_id, status, "denied or not found");
        };
        defer parent.deinit(self.io, self.allocator);

        const info = listing.statAt(parent.parent.handle, parent.base) catch
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_NO_SUCH_FILE, "not found");
        try wire.replyFullAttrs(self.channel, request_id, self.applyListingMode(info, path.value));
    }

    fn handleOpendir(self: *SftpState, request_id: u32, payload: []const u8) !void {
        var path = wire.parseString(payload) catch return wire.replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
        var vbuf: [vfs_mod.max_virtual_path_bytes + 2]u8 = undefined;
        path.value = (try self.normalizedPath(request_id, path.value, &vbuf)) orelse return;
        if (policy.check(self.user, .readdir, path.value) == .deny) {
            defer self.auditDenied("opendir", path.value);
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }

        // Checked before opening, so the cap path owns no fd.
        if (self.handles.items.len >= max_handles_per_session) {
            defer self.auditFailed("opendir", path.value, "handle limit reached");
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "too many open handles");
        }

        const dir = self.vfs.openVirtualDir(self.io, self.allocator, path.value, true) catch |err| {
            const status = wire.parentErrorStatus(err);
            defer self.auditFailed("opendir", path.value, "open dir failed");
            return wire.replyStatus(self.channel, request_id, status, "open dir failed");
        };
        const id = self.addDirHandle(dir, path.value) catch |err| {
            defer self.auditFailed("opendir", path.value, @errorName(err));
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "open dir failed");
        };
        defer self.auditOk("opendir", path.value, "");
        try wire.replyHandle(self.channel, request_id, id);
    }

    fn handleReaddir(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const id = wire.parseHandleId(payload) catch return wire.replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad handle");
        const handle = self.findHandle(id, .dir) orelse return wire.replyStatus(self.channel, request_id, c.SSH_FX_INVALID_HANDLE, "bad handle");
        if (handle.dir_failed) return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "read dir failed");
        if (handle.dir_done) return wire.replyStatus(self.channel, request_id, c.SSH_FX_EOF, "eof");

        // 16 entries of at most ~620 bytes fit wire.replyNames' 32 KiB.
        const batch_size = 16;
        var entries: [batch_size]wire.DirEntry = undefined;
        var count: usize = 0;

        const dir_fd = handle.dir.?.handle;
        // One reference time per batch for "recent" vs "old" dates.
        const now_secs: i64 = nowUnixSecs();

        // `addDirHandle` always sets it.
        const dir_vpath = handle.dir_vpath orelse {
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "internal: dir handle missing vpath");
        };

        var vpath_buf: [std.posix.PATH_MAX]u8 = undefined;

        while (count < entries.len) {
            const entry = handle.dir_iter.?.next(self.io) catch {
                // Send what we have; the next READDIR reports the failure.
                handle.dir_failed = true;
                break;
            } orelse {
                handle.dir_done = true;
                break;
            };

            // Paths through `.zift` are already refused; hide the entry too.
            if (vfs_mod.isReservedComponent(entry.name)) continue;

            // lstat under the jailed dir fd. An entry that vanished since
            // readdir is simply skipped.
            const info = listing.statAt(dir_fd, entry.name) catch continue;

            entries[count].name_len = entry.name.len;
            const name_copy_len = @min(entry.name.len, entries[count].name_buf.len);
            @memcpy(entries[count].name_buf[0..name_copy_len], entry.name[0..name_copy_len]);

            var display_info = info;
            var numeric_user: [16]u8 = undefined;
            var numeric_group: [16]u8 = undefined;
            var user_name: []const u8 = undefined;
            var group_name: []const u8 = undefined;

            switch (self.listing_mode) {
                .virtual => {
                    // Mode from the policy at the entry's full, untruncated
                    // path, so `ls -la` matches what the partner can do.
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

        switch (readdirFollowup(count, handle.dir_failed)) {
            .send_batch => {},
            .eof => return wire.replyStatus(self.channel, request_id, c.SSH_FX_EOF, "eof"),
            .fail => return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "read dir failed"),
        }
        try wire.replyNames(self.channel, request_id, entries[0..count]);
    }

    fn handleOpen(self: *SftpState, request_id: u32, payload: []const u8) !void {
        var cursor = payload;
        var path = wire.parseString(cursor) catch return wire.replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
        cursor = path.rest;
        var vbuf: [vfs_mod.max_virtual_path_bytes + 2]u8 = undefined;
        path.value = (try self.normalizedPath(request_id, path.value, &vbuf)) orelse return;
        if (cursor.len < 4) return wire.replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad flags");
        const flags = wire.readU32(cursor[0..4]);

        // WRITE/APPEND/CREAT/TRUNC all imply write access.
        const want_write = (flags & @as(u32, @intCast(
            c.SSH_FXF_WRITE | c.SSH_FXF_APPEND | c.SSH_FXF_CREAT | c.SSH_FXF_TRUNC,
        ))) != 0;
        // No flags at all means read (some clients rely on it).
        var want_read = (flags & @as(u32, @intCast(c.SSH_FXF_READ))) != 0;
        if (!want_read and !want_write) want_read = true;

        if (want_write and policy.check(self.user, .open_write, path.value) == .deny) {
            defer self.auditDenied("open_write", path.value);
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }
        if (want_read and policy.check(self.user, .open_read, path.value) == .deny) {
            defer self.auditDenied("open_read", path.value);
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }

        const op_label: []const u8 = if (want_write) "open_write" else "open_read";

        if (self.handles.items.len >= max_handles_per_session) {
            defer self.auditFailed(op_label, path.value, "handle limit reached");
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "too many open handles");
        }

        const want_creat = (flags & @as(u32, @intCast(c.SSH_FXF_CREAT))) != 0;
        const want_excl = (flags & @as(u32, @intCast(c.SSH_FXF_EXCL))) != 0;
        const want_trunc = (flags & @as(u32, @intCast(c.SSH_FXF_TRUNC))) != 0;
        const want_append = (flags & @as(u32, @intCast(c.SSH_FXF_APPEND))) != 0;

        // From here on only the parent fd plus basename are used.
        var parent = self.vfs.openVerifiedParent(self.io, self.allocator, path.value) catch |err| {
            // A missing parent is NO_SUCH_FILE. A caller who cannot stat
            // would learn the parent exists by comparing that with the
            // PERMISSION_DENIED a present file returns.
            const may_stat = policy.check(self.user, .stat, path.value) == .allow;
            const status = openStatusForCaller(may_stat, wire.parentErrorStatus(err));
            defer {
                if (status == c.SSH_FX_PERMISSION_DENIED) self.auditDenied(op_label, path.value) else self.auditFailed(op_label, path.value, @errorName(err));
            }
            const text: []const u8 = if (status == c.SSH_FX_PERMISSION_DENIED) "denied" else "denied or not found";
            return wire.replyStatus(self.channel, request_id, status, text);
        };
        defer parent.deinit(self.io, self.allocator);

        const open_mode: std.Io.Dir.OpenFileOptions.Mode = blk: {
            if (want_write and want_read) break :blk .read_write;
            if (want_write) break :blk .write_only;
            break :blk .read_only;
        };

        // O_NOFOLLOW: a symlink as the final component is always refused.
        var file = parent.parent.openFile(self.io, parent.base, .{
            .mode = open_mode,
            .follow_symlinks = false,
            .allow_directory = false,
        }) catch |err| switch (err) {
            error.FileNotFound => {
                if (!want_creat or !want_write) {
                    // Write without read/list must not distinguish a
                    // missing path from a present one.
                    const may_stat = policy.check(self.user, .stat, path.value) == .allow;
                    const status = openExistenceStatus(may_stat, .missing);
                    if (!may_stat) {
                        defer self.auditDenied(op_label, path.value);
                        return wire.replyStatus(self.channel, request_id, status, "denied");
                    }
                    return wire.replyStatus(self.channel, request_id, status, "not found");
                }
                // A new file is written in staging and renamed into place
                // at CLOSE, so the target is either absent or complete.
                // An abandoned or failed upload unlinks its staging file.
                var staging = self.ensureStagingDir() catch {
                    defer self.auditFailed(op_label, path.value, "staging dir unavailable");
                    return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "open failed");
                };

                var staging_name_buf: [32]u8 = undefined;
                generateStagingName(&staging_name_buf) catch {
                    // Never fall back to a predictable name.
                    defer self.auditFailed(op_label, path.value, "no entropy for staging name");
                    return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "open failed");
                };
                const staging_name = staging_name_buf[0..];
                self.registerStagingName(staging_name) catch {
                    defer self.auditFailed(op_label, path.value, "staging register failed");
                    return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "open failed");
                };

                // Created at `publish-mode`, which rename(2) keeps; the
                // 0700 staging dir hides it meanwhile. Set the mode again
                // after create because umask masks it.
                const publish_mode = self.publish_mode;
                const created = staging.createFile(self.io, staging_name, .{
                    .read = want_read,
                    .truncate = false,
                    .exclusive = true,
                    .permissions = .fromMode(@intCast(publish_mode)),
                }) catch {
                    // createFile failed, so the name is not ours to unlink.
                    self.unregisterStagingName(staging_name);
                    defer self.auditFailed(op_label, path.value, "staging create failed");
                    return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "open failed");
                };
                created.setPermissions(self.io, .fromMode(@intCast(publish_mode))) catch {
                    self.rollbackStagingCreate(staging, staging_name, created);
                    defer self.auditFailed(op_label, path.value, "staging chmod failed");
                    return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "open failed");
                };
                if (want_append) {
                    setFdAppend(created.handle) catch {
                        self.rollbackStagingCreate(staging, staging_name, created);
                        defer self.auditFailed(op_label, path.value, "append flag failed");
                        return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "open failed");
                    };
                }

                // TRUNC is moot on a new file; EXCL is checked at CLOSE.
                const id = self.addStagedHandle(
                    created,
                    path.value,
                    staging_name,
                    want_read,
                    want_write,
                    want_append,
                    want_excl,
                ) catch |alloc_err| {
                    // Its errdefer already closed `created`.
                    self.rollbackStagingCreate(staging, staging_name, null);
                    defer self.auditFailed(op_label, path.value, @errorName(alloc_err));
                    return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "open failed");
                };
                defer self.auditOk(op_label, path.value, "staged");
                return wire.replyHandle(self.channel, request_id, id);
            },
            error.SymLinkLoop => {
                defer self.auditDenied(op_label, path.value);
                return wire.replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
            },
            else => {
                // A directory where a file was asked for is FAILURE.
                // Concealing that from a caller who cannot stat matches
                // the missing-file reply.
                if (err == error.IsDir and policy.check(self.user, .stat, path.value) == .deny) {
                    defer self.auditDenied(op_label, path.value);
                    return wire.replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
                }
                defer self.auditFailed(op_label, path.value, @errorName(err));
                return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "open failed");
            },
        };

        // EXCL on an existing file fails, without revealing existence to
        // a partner who cannot stat.
        if (want_creat and want_excl) {
            file.close(self.io);
            const may_stat = policy.check(self.user, .stat, path.value) == .allow;
            const status = openExistenceStatus(may_stat, .excl_exists);
            if (!may_stat) {
                defer self.auditDenied(op_label, path.value);
                return wire.replyStatus(self.channel, request_id, status, "denied");
            }
            return wire.replyStatus(self.channel, request_id, status, "exists");
        }

        // Defense in depth before anything is modified.
        self.vfs.verifyFile(self.io, file) catch {
            file.close(self.io);
            defer self.auditDenied(op_label, path.value);
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        };

        // The clobber rule: writing to an existing file (truncate,
        // overwrite, or append) also needs `update`. Existence is the
        // open itself, so there is no check-then-act window.
        if (want_write and policy.check(self.user, .update, path.value) == .deny) {
            file.close(self.io);
            defer self.auditDenied(op_label, path.value);
            return wire.replyStatus(
                self.channel,
                request_id,
                openExistenceStatus(policy.check(self.user, .stat, path.value) == .allow, .present_no_update),
                "permission denied",
            );
        }

        // Before truncate: an exhausted id must not zero the file and
        // then kill the session. Ids are not recycled.
        if (!handleIdAvailable(self.next_handle)) {
            file.close(self.io);
            defer self.auditFailed(op_label, path.value, "handle id exhausted");
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "open failed");
        }

        if (want_append) {
            setFdAppend(file.handle) catch {
                file.close(self.io);
                defer self.auditFailed(op_label, path.value, "append flag failed");
                return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "open failed");
            };
        }

        if (want_trunc and want_write) {
            file.setLength(self.io, 0) catch {
                file.close(self.io);
                defer self.auditFailed(op_label, path.value, "truncate failed");
                return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "truncate failed");
            };
        }

        const id = self.addFileHandle(file, want_read, want_write, want_append) catch |err| {
            defer self.auditFailed(op_label, path.value, @errorName(err));
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "open failed");
        };
        defer self.auditOk(op_label, path.value, "");
        try wire.replyHandle(self.channel, request_id, id);
    }

    fn handleRead(self: *SftpState, request_id: u32, payload: []const u8) !void {
        var cursor = payload;
        const id = wire.parseHandleId(cursor) catch return wire.replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad handle");
        cursor = cursor[8..];
        if (cursor.len < 12) return wire.replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad read");
        const offset = wire.readU64(cursor[0..8]);
        const len = @min(wire.readU32(cursor[8..12]), 32 * 1024);
        const handle = self.findHandle(id, .file) orelse return wire.replyStatus(self.channel, request_id, c.SSH_FX_INVALID_HANDLE, "bad handle");

        // Above i64 max, std's pread path would panic in a safe build.
        if (offset > std.math.maxInt(i64)) {
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad offset");
        }

        if (!handle.can_read) {
            defer self.auditDenied("read", null);
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }

        // A 0-byte read gets empty DATA, not EOF.
        if (len == 0) return wire.replyData(self.channel, request_id, "");

        var buf = try self.allocator.alloc(u8, len);
        defer self.allocator.free(buf);
        const n = handle.file.?.readPositionalAll(self.io, buf, offset) catch {
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "read failed");
        };
        if (n == 0) return wire.replyStatus(self.channel, request_id, c.SSH_FX_EOF, "eof");
        try wire.replyData(self.channel, request_id, buf[0..n]);
    }

    fn handleWrite(self: *SftpState, request_id: u32, payload: []const u8) !void {
        var cursor = payload;
        const id = wire.parseHandleId(cursor) catch return wire.replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad handle");
        cursor = cursor[8..];
        if (cursor.len < 8) return wire.replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad write");
        const client_offset = wire.readU64(cursor[0..8]);
        const data = wire.parseString(cursor[8..]) catch return wire.replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad data");
        const handle = self.findHandle(id, .file) orelse return wire.replyStatus(self.channel, request_id, c.SSH_FX_INVALID_HANDLE, "bad handle");

        // Same bound as READ; append ignores the offset.
        if (!handle.is_append and client_offset > std.math.maxInt(i64)) {
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad offset");
        }

        if (!handle.can_write) {
            defer self.auditDenied("write", null);
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }

        // SSH_FXF_APPEND: write(2) honors the O_APPEND set at OPEN,
        // including writes from other sessions. pwrite does not.
        if (handle.is_append) {
            handle.file.?.writeStreamingAll(self.io, data.value) catch {
                return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "write failed");
            };
        } else {
            handle.file.?.writePositionalAll(self.io, data.value, client_offset) catch {
                return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "write failed");
            };
        }
        try wire.replyStatus(self.channel, request_id, c.SSH_FX_OK, "ok");
    }

    fn handleClose(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const id = wire.parseHandleId(payload) catch return wire.replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad handle");
        var i: usize = 0;
        while (i < self.handles.items.len) : (i += 1) {
            if (self.handles.items[i].id == id) {
                const handle = &self.handles.items[i];

                // A staged CLOSE publishes, before closeHandle would unlink.
                if (handle.staging_basename != null and handle.staging_target_vpath != null) {
                    // Copy the target for the audit line: closeHandle frees
                    // it and swapRemove moves the slot. A normalized path
                    // can be one byte longer than the raw limit.
                    var audit_target_buf: [vfs_mod.max_virtual_path_bytes + 1]u8 = undefined;
                    const audit_target = blk: {
                        const tv = handle.staging_target_vpath.?;
                        std.debug.assert(tv.len <= audit_target_buf.len);
                        @memcpy(audit_target_buf[0..tv.len], tv);
                        break :blk audit_target_buf[0..tv.len];
                    };

                    const close_status = self.publishStagedHandle(handle) catch |err| {
                        // closeHandle unlinks the staging file.
                        self.closeHandle(handle);
                        _ = self.handles.swapRemove(i);
                        self.auditFailed("close", audit_target, @errorName(err));
                        return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "failure");
                    };
                    self.closeHandle(handle);
                    _ = self.handles.swapRemove(i);

                    // Standard SFTP phrases only; internal detail stays in
                    // the audit log.
                    const reply_msg: []const u8 = switch (close_status) {
                        c.SSH_FX_OK => "ok",
                        c.SSH_FX_PERMISSION_DENIED => "permission denied",
                        c.SSH_FX_FAILURE => "file exists",
                        else => "failure",
                    };
                    if (close_status == c.SSH_FX_OK) {
                        self.auditOk("publish", audit_target, "");
                    }
                    return wire.replyStatus(self.channel, request_id, close_status, reply_msg);
                }

                self.closeHandle(handle);
                _ = self.handles.swapRemove(i);
                return wire.replyStatus(self.channel, request_id, c.SSH_FX_OK, "ok");
            }
        }
        try wire.replyStatus(self.channel, request_id, c.SSH_FX_INVALID_HANDLE, "bad handle");
    }

    /// Rename the staged file to its target. Success clears
    /// `staging_basename`; on failure it stays set so cleanup unlinks it.
    fn publishStagedHandle(self: *SftpState, handle: *Handle) !c_int {
        const target_vpath = handle.staging_target_vpath.?;
        const staging_basename = handle.staging_basename.?;
        const staging = self.staging_dir.?;

        // Close first so delayed write errors surface before the rename.
        if (handle.file) |f| {
            f.close(self.io);
            handle.file = null;
        }

        namespace_mutation_mutex.lockUncancelable(self.io);
        defer namespace_mutation_mutex.unlock(self.io);

        // The parent may have changed during the upload; walk it again.
        var to_parent = self.vfs.openVerifiedParent(self.io, self.allocator, target_vpath) catch |err| {
            return err;
        };
        defer to_parent.deinit(self.io, self.allocator);

        // Re-check the clobber rule: the target may have appeared since
        // OPEN. lstat, so even a dangling symlink counts as existing.
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

        // Without replace rights use a no-replace rename, so a target
        // created after the lstat above still cannot be clobbered.
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

        self.unregisterStagingName(staging_basename);
        self.allocator.free(staging_basename);
        handle.staging_basename = null;

        return c.SSH_FX_OK;
    }

    fn handleMkdir(self: *SftpState, request_id: u32, payload: []const u8) !void {
        var path = wire.parseString(payload) catch return wire.replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
        var vbuf: [vfs_mod.max_virtual_path_bytes + 2]u8 = undefined;
        path.value = (try self.normalizedPath(request_id, path.value, &vbuf)) orelse return;
        if (policy.check(self.user, .mkdir, path.value) == .deny) {
            defer self.auditDenied("mkdir", path.value);
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }
        namespace_mutation_mutex.lockUncancelable(self.io);
        defer namespace_mutation_mutex.unlock(self.io);
        var parent = self.vfs.openVerifiedParent(self.io, self.allocator, path.value) catch |err| {
            const status = wire.parentErrorStatus(err);
            defer {
                if (status == c.SSH_FX_PERMISSION_DENIED) self.auditDenied("mkdir", path.value) else self.auditFailed("mkdir", path.value, @errorName(err));
            }
            return wire.replyStatus(self.channel, request_id, status, "denied or not found");
        };
        defer parent.deinit(self.io, self.allocator);

        const dir_mode = std.Io.File.Permissions.fromMode(@intCast(self.mkdir_mode));
        parent.parent.createDir(self.io, parent.base, dir_mode) catch {
            defer self.auditFailed("mkdir", path.value, "createDir failed");
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "mkdir failed");
        };
        // umask applied to createDir, so set the mode again (rolling
        // back on failure). `iterate` keeps Zig off O_PATH, which cannot
        // fchmod.
        var created_dir = parent.parent.openDir(self.io, parent.base, .{
            .follow_symlinks = false,
            .iterate = true,
        }) catch {
            parent.parent.deleteDir(self.io, parent.base) catch {};
            defer self.auditFailed("mkdir", path.value, "openDir-after-create failed");
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "mkdir failed");
        };
        created_dir.setPermissions(self.io, dir_mode) catch {
            created_dir.close(self.io);
            // Fails harmlessly if something already populated it.
            parent.parent.deleteDir(self.io, parent.base) catch {};
            defer self.auditFailed("mkdir", path.value, "setPermissions failed");
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "mkdir failed");
        };
        created_dir.close(self.io);
        defer self.auditOk("mkdir", path.value, "");
        try wire.replyStatus(self.channel, request_id, c.SSH_FX_OK, "ok");
    }

    fn handleRemove(self: *SftpState, request_id: u32, payload: []const u8) !void {
        var path = wire.parseString(payload) catch return wire.replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
        var vbuf: [vfs_mod.max_virtual_path_bytes + 2]u8 = undefined;
        path.value = (try self.normalizedPath(request_id, path.value, &vbuf)) orelse return;
        if (policy.check(self.user, .remove, path.value) == .deny) {
            defer self.auditDenied("remove", path.value);
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }
        namespace_mutation_mutex.lockUncancelable(self.io);
        defer namespace_mutation_mutex.unlock(self.io);
        var parent = self.vfs.openVerifiedParent(self.io, self.allocator, path.value) catch |err| {
            const status = wire.parentErrorStatus(err);
            defer {
                if (status == c.SSH_FX_PERMISSION_DENIED) self.auditDenied("remove", path.value) else self.auditFailed("remove", path.value, @errorName(err));
            }
            return wire.replyStatus(self.channel, request_id, status, "denied or not found");
        };
        defer parent.deinit(self.io, self.allocator);

        parent.parent.deleteFile(self.io, parent.base) catch {
            defer self.auditFailed("remove", path.value, "deleteFile failed");
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "remove failed");
        };
        defer self.auditOk("remove", path.value, "");
        try wire.replyStatus(self.channel, request_id, c.SSH_FX_OK, "ok");
    }

    fn handleRmdir(self: *SftpState, request_id: u32, payload: []const u8) !void {
        var path = wire.parseString(payload) catch return wire.replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad path");
        var vbuf: [vfs_mod.max_virtual_path_bytes + 2]u8 = undefined;
        path.value = (try self.normalizedPath(request_id, path.value, &vbuf)) orelse return;
        if (policy.check(self.user, .rmdir, path.value) == .deny) {
            defer self.auditDenied("rmdir", path.value);
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }
        namespace_mutation_mutex.lockUncancelable(self.io);
        defer namespace_mutation_mutex.unlock(self.io);
        var parent = self.vfs.openVerifiedParent(self.io, self.allocator, path.value) catch |err| {
            const status = wire.parentErrorStatus(err);
            defer {
                if (status == c.SSH_FX_PERMISSION_DENIED) self.auditDenied("rmdir", path.value) else self.auditFailed("rmdir", path.value, @errorName(err));
            }
            return wire.replyStatus(self.channel, request_id, status, "denied or not found");
        };
        defer parent.deinit(self.io, self.allocator);

        parent.parent.deleteDir(self.io, parent.base) catch {
            defer self.auditFailed("rmdir", path.value, "deleteDir failed");
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "rmdir failed");
        };
        defer self.auditOk("rmdir", path.value, "");
        try wire.replyStatus(self.channel, request_id, c.SSH_FX_OK, "ok");
    }

    fn handleRename(self: *SftpState, request_id: u32, payload: []const u8) !void {
        var from = wire.parseString(payload) catch return wire.replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad source");
        var to = wire.parseString(from.rest) catch return wire.replyStatus(self.channel, request_id, c.SSH_FX_BAD_MESSAGE, "bad destination");
        var from_buf: [vfs_mod.max_virtual_path_bytes + 2]u8 = undefined;
        var to_buf: [vfs_mod.max_virtual_path_bytes + 2]u8 = undefined;
        from.value = (try self.normalizedPath(request_id, from.value, &from_buf)) orelse return;
        to.value = (try self.normalizedPath(request_id, to.value, &to_buf)) orelse return;
        if (policy.checkRename(self.user, from.value, to.value) == .deny) {
            defer self.auditDenied("rename", from.value);
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        }
        namespace_mutation_mutex.lockUncancelable(self.io);
        defer namespace_mutation_mutex.unlock(self.io);
        var from_parent = self.vfs.openVerifiedParent(self.io, self.allocator, from.value) catch |err| {
            const status = wire.parentErrorStatus(err);
            defer {
                if (status == c.SSH_FX_PERMISSION_DENIED) self.auditDenied("rename", from.value) else self.auditFailed("rename", from.value, @errorName(err));
            }
            return wire.replyStatus(self.channel, request_id, status, "denied or not found");
        };
        defer from_parent.deinit(self.io, self.allocator);
        var to_parent = self.vfs.openVerifiedParent(self.io, self.allocator, to.value) catch |err| {
            const status = wire.parentErrorStatus(err);
            defer {
                if (status == c.SSH_FX_PERMISSION_DENIED) self.auditDenied("rename", to.value) else self.auditFailed("rename", to.value, @errorName(err));
            }
            return wire.replyStatus(self.channel, request_id, status, "denied or not found");
        };
        defer to_parent.deinit(self.io, self.allocator);

        const source_info = listing.statAt(from_parent.parent.handle, from_parent.base) catch |err| {
            defer self.auditFailed("rename", from.value, @errorName(err));
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_NO_SUCH_FILE, "not found");
        };

        self.verifyRenameNode(source_info.mode, from.value, to.value) catch {
            defer self.auditDenied("rename", from.value);
            return wire.replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
        };

        // A directory rename respells every descendant's path; check each
        // one at both spellings so denied children cannot be carried into
        // an allowed subtree.
        if ((source_info.mode & listing.S_IFMT) == listing.S_IFDIR) {
            var source_dir = from_parent.parent.openDir(self.io, from_parent.base, .{
                .iterate = true,
                .follow_symlinks = false,
            }) catch |err| {
                defer self.auditFailed("rename", from.value, @errorName(err));
                return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "rename preflight failed");
            };
            defer source_dir.close(self.io);

            var scanned: usize = 0;
            self.verifyRenameSubtree(source_dir, from.value, to.value, &scanned, 0) catch |err| {
                switch (err) {
                    error.RenameDenied, error.RenameScanLimit => {
                        defer self.auditDenied("rename", from.value);
                        return wire.replyStatus(self.channel, request_id, c.SSH_FX_PERMISSION_DENIED, "denied");
                    },
                    else => {
                        defer self.auditFailed("rename", from.value, @errorName(err));
                        return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "rename preflight failed");
                    },
                }
            };
        }

        // rename(2) silently replaces the destination, so replacing needs
        // `update` there (the clobber rule). Without it, a no-replace
        // rename refuses any existing entry, with no check-then-act race.
        const may_replace = policy.check(self.user, .update, to.value) == .allow;
        if (may_replace) {
            std.Io.Dir.rename(from_parent.parent, from_parent.base, to_parent.parent, to_parent.base, self.io) catch {
                defer self.auditFailed("rename", from.value, "rename failed");
                return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "rename failed");
            };
        } else {
            renameNoReplace(from_parent.parent, from_parent.base, to_parent.parent, to_parent.base, self.io) catch |err| switch (err) {
                error.PathAlreadyExists => {
                    defer self.auditDenied("rename", to.value);
                    return wire.replyStatus(
                        self.channel,
                        request_id,
                        c.SSH_FX_PERMISSION_DENIED,
                        "permission denied",
                    );
                },
                else => {
                    defer self.auditFailed("rename", from.value, "rename failed");
                    return wire.replyStatus(self.channel, request_id, c.SSH_FX_FAILURE, "rename failed");
                },
            };
        }
        defer self.auditOk("rename", from.value, to.value);
        try wire.replyStatus(self.channel, request_id, c.SSH_FX_OK, "ok");
    }

    /// Require rename permission at both old and new spellings, then
    /// reject any new capability over an existing object. Requiring
    /// descendant rename permission also enforces explicit deny rules:
    /// moving a denied object is itself manipulation of that object,
    /// even when the destination would remain denied.
    fn verifyRenameNode(self: *SftpState, mode: u32, old_path: []const u8, new_path: []const u8) !void {
        if (policy.checkRename(self.user, old_path, new_path) == .deny) return error.RenameDenied;

        const common_ops = [_]policy.Operation{ .stat, .update };
        for (common_ops) |op| {
            if (policy.check(self.user, op, new_path) == .allow and
                policy.check(self.user, op, old_path) == .deny)
            {
                return error.RenameDenied;
            }
        }

        switch (mode & listing.S_IFMT) {
            listing.S_IFDIR => {
                const dir_ops = [_]policy.Operation{ .readdir, .rmdir };
                for (dir_ops) |op| {
                    if (policy.check(self.user, op, new_path) == .allow and
                        policy.check(self.user, op, old_path) == .deny)
                    {
                        return error.RenameDenied;
                    }
                }
            },
            listing.S_IFREG => {
                const file_ops = [_]policy.Operation{ .open_read, .open_write, .remove };
                for (file_ops) |op| {
                    if (policy.check(self.user, op, new_path) == .allow and
                        policy.check(self.user, op, old_path) == .deny)
                    {
                        return error.RenameDenied;
                    }
                }
            },
            else => {
                if (policy.check(self.user, .remove, new_path) == .allow and
                    policy.check(self.user, .remove, old_path) == .deny)
                {
                    return error.RenameDenied;
                }
            },
        }
    }

    fn verifyRenameSubtree(
        self: *SftpState,
        dir: std.Io.Dir,
        old_parent: []const u8,
        new_parent: []const u8,
        scanned: *usize,
        depth: usize,
    ) !void {
        if (depth >= max_rename_scan_depth) return error.RenameScanLimit;

        var it = dir.iterate();
        while (try it.next(self.io)) |entry| {
            scanned.* += 1;
            if (scanned.* > max_rename_scan_entries) return error.RenameScanLimit;

            // A local operator can create names that the SFTP protocol
            // intentionally cannot represent. Moving those entries
            // cannot be authorized accurately, so fail closed.
            vfs_mod.Vfs.validateVirtualPath(entry.name) catch return error.RenameDenied;
            if (vfs_mod.isReservedComponent(entry.name)) return error.RenameDenied;

            const old_path = try appendVirtualChild(self.allocator, old_parent, entry.name);
            defer self.allocator.free(old_path);
            const new_path = try appendVirtualChild(self.allocator, new_parent, entry.name);
            defer self.allocator.free(new_path);

            const info = try listing.statAt(dir.handle, entry.name);
            try self.verifyRenameNode(info.mode, old_path, new_path);

            if ((info.mode & listing.S_IFMT) == listing.S_IFDIR) {
                var child = try dir.openDir(self.io, entry.name, .{
                    .iterate = true,
                    .follow_symlinks = false,
                });
                defer child.close(self.io);
                try self.verifyRenameSubtree(child, old_path, new_path, scanned, depth + 1);
            }
        }
    }

    fn addDirHandle(self: *SftpState, dir: std.Io.Dir, vpath: []const u8) !u32 {
        // Owns `dir` from here, even on failure.
        var dir_local = dir;
        errdefer dir_local.close(self.io);

        const id = try self.nextHandleId();
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
        // Owns `file` from here, even on failure.
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

    /// A write handle on a staging file that CLOSE renames to `target_vpath`.
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

    /// Open (creating if needed) the staging dir on first use.
    fn ensureStagingDir(self: *SftpState) !std.Io.Dir {
        if (self.staging_dir) |dir| return dir;
        const dir = try self.vfs.openStagingDir(self.io);
        self.staging_dir = dir;
        return dir;
    }

    /// Unlink this partner's crash orphans: staging files no live handle
    /// owns and older than `max(idle_timeout, 15m)`.
    fn sweepStagingOrphans(self: *SftpState) void {
        var dir = self.vfs.tryOpenExistingStagingDir(self.io) orelse return;
        defer dir.close(self.io);

        const age_floor_ms: i64 = @max(@as(i64, @intCast(self.idle_timeout_ms)), staging_orphan_min_age_ms);
        const now_secs = nowUnixSecs();
        const min_age_secs: i64 = @divTrunc(age_floor_ms + 999, 1000);

        var it = dir.iterate();
        while (it.next(self.io) catch null) |entry| {
            if (entry.kind != .file) continue;
            const live = self.stagingNameIsLive(entry.name);
            const age_secs: i64 = if (live) 0 else blk: {
                const info = listing.statAt(dir.handle, entry.name) catch continue;
                break :blk now_secs - info.mtime_secs;
            };
            if (!sweepUnlinksStagingFile(live, age_secs, min_age_secs)) continue;
            dir.deleteFile(self.io, entry.name) catch {};
        }
    }

    fn registerStagingName(self: *SftpState, name: []const u8) !void {
        std.debug.assert(name.len == 32);
        const root_copy = try self.allocator.dupe(u8, self.vfs.root);
        staging_live_mutex.lockUncancelable(self.io);
        defer staging_live_mutex.unlock(self.io);
        var copied: [32]u8 = undefined;
        @memcpy(&copied, name[0..32]);
        staging_live.append(self.allocator, .{
            .root = root_copy,
            .name = copied,
        }) catch |err| {
            self.allocator.free(root_copy);
            return err;
        };
    }

    fn unregisterStagingName(self: *SftpState, name: []const u8) void {
        staging_live_mutex.lockUncancelable(self.io);
        defer staging_live_mutex.unlock(self.io);
        var i: usize = 0;
        while (i < staging_live.items.len) : (i += 1) {
            const entry = staging_live.items[i];
            if (!stagingIdentityMatches(self.vfs.root, name, entry.root, &entry.name)) continue;
            const root = entry.root;
            _ = staging_live.swapRemove(i);
            self.allocator.free(root);
            return;
        }
    }

    fn stagingNameIsLive(self: *SftpState, name: []const u8) bool {
        staging_live_mutex.lockUncancelable(self.io);
        defer staging_live_mutex.unlock(self.io);
        for (staging_live.items) |entry| {
            if (stagingIdentityMatches(self.vfs.root, name, entry.root, &entry.name)) return true;
        }
        return false;
    }

    fn rollbackStagingCreate(self: *SftpState, staging: std.Io.Dir, name: []const u8, file: ?std.Io.File) void {
        if (file) |f| f.close(self.io);
        staging.deleteFile(self.io, name) catch {};
        self.unregisterStagingName(name);
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

    /// 32 hex chars from 16 CSPRNG bytes; collisions are negligible.
    /// Fails rather than ever produce a predictable name.
    fn generateStagingName(out: *[32]u8) !void {
        var raw: [16]u8 = undefined;
        try fillRandomBytes(&raw);
        const hex = "0123456789abcdef";
        for (raw, 0..) |b, i| {
            out[i * 2 + 0] = hex[(b >> 4) & 0xF];
            out[i * 2 + 1] = hex[b & 0xF];
        }
    }

    fn fillRandomBytes(buf: []u8) !void {
        if (builtin.os.tag == .linux) {
            var filled: usize = 0;
            while (filled < buf.len) {
                const rc = std.os.linux.getrandom(
                    buf.ptr + filled,
                    buf.len - filled,
                    0,
                );
                switch (std.os.linux.errno(rc)) {
                    .SUCCESS => {
                        if (rc == 0) return error.RandomFailed;
                        filled += @intCast(rc);
                    },
                    .INTR => continue,
                    .NOSYS => return readFromUrandom(buf[filled..]),
                    else => return error.RandomFailed,
                }
            }
        } else {
            std.c.arc4random_buf(buf.ptr, buf.len);
        }
    }

    fn readFromUrandom(buf: []u8) !void {
        const linux = std.os.linux;
        const path: [*:0]const u8 = "/dev/urandom";
        const fd_rc = linux.open(path, .{ .ACCMODE = .RDONLY }, 0);
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
        // Ids are never reused, so a closed handle can never alias a new
        // one. At u32 max we fail instead of wrapping.
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
        // Still set means the upload was never published: unlink it.
        if (handle.staging_basename) |sb| {
            if (self.staging_dir) |*dir| {
                dir.deleteFile(self.io, sb) catch {};
            }
            self.unregisterStagingName(sb);
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

/// Read one length-prefixed packet, or `error.IdleTimeout`.
fn readPacketTimed(state: *SftpState, payload_buf: []u8) ![]u8 {
    var len_buf: [4]u8 = undefined;
    try readExactTimed(state, &len_buf);
    const len = wire.readU32(&len_buf);

    // Oversized: reply BAD_MESSAGE to the request, then end the session,
    // since resyncing would mean draining attacker-sized input.
    if (len > payload_buf.len) {
        var head: [5]u8 = undefined;
        readExactTimed(state, &head) catch return error.LibsshFailure;
        const request_id = wire.readU32(head[1..5]);
        wire.replyStatus(state.channel, request_id, c.SSH_FX_BAD_MESSAGE, "packet too large") catch {};
        return error.LibsshFailure;
    }

    const payload = payload_buf[0..len];
    try readExactTimed(state, payload);
    return payload;
}

/// RFC 4254 §11.1 SSH_DISCONNECT_BY_APPLICATION: the peer closed the
/// connection because its application asked to, which is what every
/// ordinary client does at the end of a session.
const ssh2_disconnect_by_application: u32 = 11;

/// Extract the numeric reason from libssh's disconnect error text.
///
/// libssh exposes no accessor for the code. `ssh_get_disconnect_message`
/// returns only the peer's free-text message, and the disconnect callback
/// formats the number into the session error string and nowhere else, in
/// a fixed shape:
///
///     Received SSH_MSG_DISCONNECT: <code>:<message>
///
/// Returns null for any other libssh error, so a message we do not
/// recognize is never mistaken for a graceful close.
fn disconnectReason(text: []const u8) ?u32 {
    const marker = "Received SSH_MSG_DISCONNECT: ";
    const start = std.mem.indexOf(u8, text, marker) orelse return null;
    const rest = text[start + marker.len ..];
    const end = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
    return std.fmt.parseInt(u32, rest[0..end], 10) catch null;
}

fn readExactTimed(state: *SftpState, out: []u8) !void {
    // Read in 200 ms slices so the idle deadline is enforced; the slice
    // also bounds the delay of a spurious-EOF retry. The shutdown flag is
    // not checked: sessions get the drain grace period to finish.
    // ssh_channel_read_timeout: >0 bytes, 0 EOF, SSH_AGAIN timeout.
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
            // libssh can return 0 without a real EOF (seen after `env`
            // requests went through ssh_message_reply_default). If
            // ssh_channel_is_eof disagrees, retry, capped so a wedged
            // channel cannot spin forever.
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
        // Progress: the cap counts consecutive false EOFs only.
        state.spurious_eof_count = 0;
        offset += @intCast(n);
    }
}

fn acceptInitPayload(payload: []const u8) error{LibsshFailure}!void {
    if (payload.len < 5 or payload[0] != c.SSH_FXP_INIT) return error.LibsshFailure;
    if (wire.readU32(payload[1..5]) < 3) return error.LibsshFailure;
}

fn handleIdAvailable(next_handle: u32) bool {
    return next_handle != std.math.maxInt(u32);
}

const OpenExistence = enum { missing, excl_exists, present_no_update };

fn openExistenceStatus(may_stat: bool, kind: OpenExistence) c_int {
    if (!may_stat) return c.SSH_FX_PERMISSION_DENIED;
    return switch (kind) {
        .missing => c.SSH_FX_NO_SUCH_FILE,
        .excl_exists => c.SSH_FX_FAILURE,
        .present_no_update => c.SSH_FX_PERMISSION_DENIED,
    };
}

/// A caller who cannot stat must not learn that a parent or a
/// directory-shaped final component is absent versus present.
/// Statuses that are already permission-denied stay that way.
/// Out-of-memory stays a failure.
fn openStatusForCaller(may_stat: bool, status: c_int) c_int {
    if (may_stat) return status;
    return switch (status) {
        c.SSH_FX_NO_SUCH_FILE => c.SSH_FX_PERMISSION_DENIED,
        else => status,
    };
}

const ReaddirFollowup = enum { send_batch, eof, fail };

fn readdirFollowup(copied: usize, failed: bool) ReaddirFollowup {
    if (copied != 0) return .send_batch;
    if (failed) return .fail;
    return .eof;
}

fn sweepUnlinksStagingFile(live: bool, age_secs: i64, min_age_secs: i64) bool {
    if (live) return false;
    return age_secs >= min_age_secs;
}

fn stagingIdentityMatches(root: []const u8, name: []const u8, entry_root: []const u8, entry_name: []const u8) bool {
    return name.len == 32 and entry_name.len == 32 and
        std.mem.eql(u8, root, entry_root) and
        std.mem.eql(u8, name, entry_name);
}

/// Zig 0.16 OpenFileOptions has no append bit, and pwrite ignores
/// O_APPEND. F_SETFL is what makes WRITE atomic across sessions.
fn setFdAppend(fd: std.posix.fd_t) error{AppendFlagFailed}!void {
    const append_bit: c_int = @intCast(@as(u32, 1) << @bitOffsetOf(std.c.O, "APPEND"));
    const current: c_int = getfl: while (true) {
        const rc = std.c.fcntl(fd, @as(c_int, std.c.F.GETFL), @as(c_int, 0));
        switch (std.posix.errno(rc)) {
            .SUCCESS => break :getfl rc,
            .INTR => continue,
            else => return error.AppendFlagFailed,
        }
    };
    while (true) {
        const rc = std.c.fcntl(fd, @as(c_int, std.c.F.SETFL), current | append_bit);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return,
            .INTR => continue,
            else => return error.AppendFlagFailed,
        }
    }
}

test "disconnectReason: the graceful goodbye is recognized" {
    // The exact text libssh's disconnect callback produces. Real clients
    // send an empty message, which is what the trailing colon carries.
    try std.testing.expectEqual(
        @as(?u32, 11),
        disconnectReason("Received SSH_MSG_DISCONNECT: 11:"),
    );
    try std.testing.expectEqual(
        @as(?u32, 11),
        disconnectReason("Received SSH_MSG_DISCONNECT: 11:disconnected by user"),
    );
}

test "disconnectReason: other codes are distinguished, not swallowed" {
    // These name real problems and must keep their `failed` result.
    try std.testing.expectEqual(
        @as(?u32, 2),
        disconnectReason("Received SSH_MSG_DISCONNECT: 2:protocol error"),
    );
    try std.testing.expectEqual(
        @as(?u32, 10),
        disconnectReason("Received SSH_MSG_DISCONNECT: 10:connection lost"),
    );
    // A prefix of 11 must not be read as 11.
    try std.testing.expectEqual(
        @as(?u32, 110),
        disconnectReason("Received SSH_MSG_DISCONNECT: 110:nonsense"),
    );
}

test "disconnectReason: unrelated libssh errors stay unrecognized" {
    // Anything we cannot parse must return null so it is reported as the
    // failure it is, rather than being mistaken for a graceful close.
    try std.testing.expectEqual(@as(?u32, null), disconnectReason(""));
    try std.testing.expectEqual(@as(?u32, null), disconnectReason("Socket error: disconnected"));
    try std.testing.expectEqual(@as(?u32, null), disconnectReason("Received SSH_MSG_DISCONNECT: "));
    try std.testing.expectEqual(@as(?u32, null), disconnectReason("Received SSH_MSG_DISCONNECT: abc:x"));
    try std.testing.expectEqual(@as(?u32, null), disconnectReason("Received SSH_MSG_DISCONNECT: 11"));
}

test "init below version 3 drops; version 3 and above are accepted" {
    const init: u8 = @intCast(c.SSH_FXP_INIT);
    try std.testing.expectError(error.LibsshFailure, acceptInitPayload(&[_]u8{ init, 0, 0, 0 }));
    try std.testing.expectError(error.LibsshFailure, acceptInitPayload(&[_]u8{ 2, 0, 0, 0, 3 }));
    try std.testing.expectError(error.LibsshFailure, acceptInitPayload(&[_]u8{ init, 0, 0, 0, 2 }));
    try acceptInitPayload(&[_]u8{ init, 0, 0, 0, 3 });
    // Trailing extension bytes are ignored.
    try acceptInitPayload(&[_]u8{ init, 0, 0, 0, 6, 0, 1, 2, 3 });
}

test "handle ids stop before u32 wrap" {
    try std.testing.expect(handleIdAvailable(1));
    try std.testing.expect(handleIdAvailable(std.math.maxInt(u32) - 1));
    try std.testing.expect(!handleIdAvailable(std.math.maxInt(u32)));
}

test "write-only open conceals existence unless stat is allowed" {
    const denied: c_int = c.SSH_FX_PERMISSION_DENIED;
    const missing: c_int = c.SSH_FX_NO_SUCH_FILE;
    const failure: c_int = c.SSH_FX_FAILURE;
    try std.testing.expectEqual(denied, openExistenceStatus(false, .missing));
    try std.testing.expectEqual(denied, openExistenceStatus(false, .excl_exists));
    try std.testing.expectEqual(denied, openExistenceStatus(false, .present_no_update));
    try std.testing.expectEqual(missing, openExistenceStatus(true, .missing));
    try std.testing.expectEqual(failure, openExistenceStatus(true, .excl_exists));
    try std.testing.expectEqual(denied, openExistenceStatus(true, .present_no_update));
    try std.testing.expectEqual(denied, openStatusForCaller(false, missing));
    try std.testing.expectEqual(missing, openStatusForCaller(true, missing));
    try std.testing.expectEqual(failure, openStatusForCaller(false, failure));
}

test "readdir keeps a partial batch and fails the empty one" {
    try std.testing.expectEqual(ReaddirFollowup.send_batch, readdirFollowup(3, true));
    try std.testing.expectEqual(ReaddirFollowup.fail, readdirFollowup(0, true));
    try std.testing.expectEqual(ReaddirFollowup.eof, readdirFollowup(0, false));
    try std.testing.expectEqual(ReaddirFollowup.send_batch, readdirFollowup(16, false));
}

test "staging sweep skips live names and young orphans" {
    try std.testing.expect(!sweepUnlinksStagingFile(true, 10_000, 60));
    try std.testing.expect(!sweepUnlinksStagingFile(true, 0, 60));
    try std.testing.expect(!sweepUnlinksStagingFile(false, 59, 60));
    try std.testing.expect(sweepUnlinksStagingFile(false, 60, 60));
    try std.testing.expect(!sweepUnlinksStagingFile(false, -1, 60));
}

test "staging registry key is root plus the 32-byte name" {
    const name = "0123456789abcdef0123456789abcdef";
    const other = "ffffffffffffffffffffffffffffffff";
    try std.testing.expect(stagingIdentityMatches("/jails/a", name, "/jails/a", name));
    try std.testing.expect(!stagingIdentityMatches("/jails/a", name, "/jails/b", name));
    try std.testing.expect(!stagingIdentityMatches("/jails/a", name, "/jails/a", other));
    try std.testing.expect(!stagingIdentityMatches("/jails/a", "short", "/jails/a", name));
}

test "pre-subsystem ignore cap is 64" {
    try std.testing.expect(!preSubsystemIgnoreSaturated(0));
    try std.testing.expect(!preSubsystemIgnoreSaturated(63));
    try std.testing.expect(preSubsystemIgnoreSaturated(64));
}
