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
const sys = @import("sys.zig");
const policy = @import("policy.zig");
const vfs_mod = @import("vfs.zig");
const wire = @import("wire.zig");

/// Floor for staging-orphan age before unlink. Concurrent sessions for
/// the same partner may still be writing; never delete files younger
/// than this even when idle-timeout is short or disabled. Names still
/// registered to a live handle are kept regardless of age.
const staging_orphan_min_age_ms: i64 = 15 * 60 * 1000;

/// Serialize namespace changes within a partner root, so a directory
/// rename's subtree authorization sees the same tree the rename then
/// moves. Roots never overlap, so striping by root keeps that guarantee
/// without making one partner's slow rename stall everyone else.
/// Operator-side changes are outside the threat model.
var namespace_locks: [64]std.Io.Mutex = @splat(.init);

fn namespaceLockFor(root: []const u8) *std.Io.Mutex {
    return &namespace_locks[std.hash.Wyhash.hash(0, root) % namespace_locks.len];
}

/// Staging names held by open uploads in every session. A name is 128
/// random bits, so the partner root would add nothing to the key. Lock
/// order is a namespace lock then `staging_live_mutex`; never take a
/// namespace lock while holding `staging_live_mutex`, and never hold two
/// namespace locks.
var staging_live_mutex: std.Io.Mutex = .init;
var staging_live: std.ArrayList([32]u8) = .empty;

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

/// A normalized virtual path, which can be one byte longer than the raw
/// limit (a leading `/` is added).
const PathBuf = [vfs_mod.max_virtual_path_bytes + 2]u8;

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
                // Nothing reads messages from here on, and libssh would
                // queue every later channel open or request for the life
                // of the session. Refuse them as they arrive instead, and
                // refuse any already queued.
                c.ssh_set_message_callback(session, refuseMessage, null);
                if (c.ssh_execute_message_callbacks(session) != c.SSH_OK) return error.LibsshFailure;
                return channel;
            }
        }

        try noteIgnoredPreSubsystem(&ignored);
        _ = c.ssh_message_reply_default(msg);
    }
}

/// 1 tells libssh to send its default (refusing) reply and free the message.
fn refuseMessage(_: c.ssh_session, _: c.ssh_message, _: ?*anyopaque) callconv(.c) c_int {
    return 1;
}

fn noteIgnoredPreSubsystem(count: *u32) error{LibsshFailure}!void {
    if (count.* >= max_ignored_pre_subsystem) return error.LibsshFailure;
    count.* += 1;
}

pub fn runSftp(
    io: std.Io,
    allocator: std.mem.Allocator,
    channel: c.ssh_channel,
    user: *const config.UserConfig,
    server_cfg: config.ServerConfig,
    peer_ip: []const u8,
) !void {
    var jail = try vfs_mod.Vfs.init(io, allocator, user.root);
    defer jail.deinit(allocator);

    // On the heap: 256 KiB is too much for a worker stack.
    const payload_buf = try allocator.alloc(u8, wire.sftp_max_packet_bytes);
    defer allocator.free(payload_buf);

    const start_ms = sys.monotonicMs();
    var state = SftpState{
        .io = io,
        .allocator = allocator,
        .channel = channel,
        .user = user,
        .peer_ip = peer_ip,
        .vfs = jail,
        .namespace_lock = namespaceLockFor(jail.root),
        .idle_timeout_ms = server_cfg.idle_timeout_ms,
        .listing_mode = server_cfg.listing_mode,
        .publish_mode = server_cfg.publish_mode,
        .mkdir_mode = server_cfg.mkdir_mode,
        .last_activity_ms = start_ms,
        .session_started_ms = start_ms,
    };
    defer state.deinit();

    state.sweepStagingOrphans();

    const first_payload = readPacketTimed(&state, payload_buf) catch |err| switch (err) {
        error.IdleTimeout => {
            audit.log(io, user.name, "idle.timeout", null, .ok, "", peer_ip);
            return;
        },
        else => return err,
    };
    try acceptInitPayload(first_payload);
    try wire.writeVersion(channel);
    state.last_activity_ms = sys.monotonicMs();

    while (true) {
        const payload = readPacketTimed(&state, payload_buf) catch |err| switch (err) {
            error.IdleTimeout => {
                state.emitSessionEnded("idle timeout", .ok);
                return;
            },
            error.ChannelEof => {
                state.emitSessionEnded("client closed channel", .ok);
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
                        state.emitSessionEnded("client disconnected", .ok);
                        return;
                    }
                }

                lw.writeAll(lib_msg) catch {};
                state.emitSessionEnded(lw.buffered(), .failed);
                return;
            },
        };
        state.last_activity_ms = sys.monotonicMs();
        if (payload.len < 5) return error.LibsshFailure;

        const id = std.mem.readInt(u32, payload[1..5], .big);
        const args = payload[5..];
        switch (payload[0]) {
            c.SSH_FXP_REALPATH => try state.handleRealpath(id, args),
            // STAT and LSTAT both lstat, so a symlink is reported, never
            // followed.
            c.SSH_FXP_STAT, c.SSH_FXP_LSTAT => try state.handleStat(id, args),
            c.SSH_FXP_FSTAT => try state.handleFstat(id, args),
            c.SSH_FXP_OPENDIR => try state.handleOpendir(id, args),
            c.SSH_FXP_READDIR => try state.handleReaddir(id, args),
            c.SSH_FXP_OPEN => try state.handleOpen(id, args),
            c.SSH_FXP_READ => try state.handleRead(id, args),
            c.SSH_FXP_WRITE => try state.handleWrite(id, args),
            c.SSH_FXP_CLOSE => try state.handleClose(id, args),
            c.SSH_FXP_MKDIR => try state.handleMkdir(id, args),
            c.SSH_FXP_REMOVE => try state.handleUnlink(id, args, .file),
            c.SSH_FXP_RMDIR => try state.handleUnlink(id, args, .dir),
            c.SSH_FXP_RENAME => try state.handleRename(id, args),
            // OP_UNSUPPORTED (not FAILURE) tells a probing client the
            // operation does not exist here.
            else => try state.status(id, c.SSH_FX_OP_UNSUPPORTED),
        }
    }
}

const FileHandle = struct {
    file: std.Io.File,
    /// Access granted at OPEN; READ and WRITE check it again, so a
    /// write-only handle cannot be used to read.
    can_read: bool,
    can_write: bool,
    /// SSH_FXF_APPEND: fd has O_APPEND and WRITE ignores the offset.
    is_append: bool,
    staged: ?Staged = null,
};

/// A new file written as `<root>/.zift/staging/<name>` and renamed to
/// `target` at CLOSE.
const Staged = struct {
    name: [32]u8,
    /// Owned.
    target: []const u8,
    /// SSH_FXF_EXCL: a target that appeared during the upload fails the
    /// CLOSE instead of being replaced.
    excl: bool,
    published: bool = false,
};

const DirHandle = struct {
    dir: std.Io.Dir,
    iter: std.Io.Dir.Iterator,
    /// Owned, so listings can ask the policy about `<vpath>/<name>`.
    vpath: []const u8,
    done: bool = false,
    /// The iterator failed; later READDIRs fail rather than skip names.
    failed: bool = false,
};

const Handle = struct {
    id: u32,
    kind: union(enum) { file: FileHandle, dir: DirHandle },
};

const SftpState = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    channel: c.ssh_channel,
    user: *const config.UserConfig,
    /// Borrowed from the session thread, which outlives this state.
    peer_ip: []const u8 = "",
    vfs: vfs_mod.Vfs,
    namespace_lock: *std.Io.Mutex,
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
        for (self.handles.items) |handle| self.closeHandle(handle);
        self.handles.deinit(self.allocator);
        if (self.staging_dir) |*dir| dir.close(self.io);
        self.staging_dir = null;
    }

    /// `session.ended` with `(duration_ms=N[, spurious_eof=N])` appended.
    fn emitSessionEnded(
        self: *const SftpState,
        reason: []const u8,
        result: audit.Result,
    ) void {
        var buf: [320]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        const duration_ms: i64 = sys.monotonicMs() - self.session_started_ms;
        w.writeAll(reason) catch {};
        w.print(" (duration_ms={d}", .{duration_ms}) catch {};
        if (self.spurious_eof_count != 0) {
            w.print(", spurious_eof={d}", .{self.spurious_eof_count}) catch {};
        }
        w.writeAll(")") catch {};
        audit.log(self.io, self.user.name, "session.ended", null, result, w.buffered(), self.peer_ip);
    }

    fn status(self: *SftpState, request_id: u32, code: c_int) !void {
        return wire.replyStatus(self.channel, request_id, code);
    }

    /// Reply PERMISSION_DENIED, then audit it. Audits follow the reply so
    /// a slow audit destination never delays the client.
    fn deny(self: *SftpState, request_id: u32, op: []const u8, vpath: ?[]const u8) !void {
        defer self.auditDenied(op, vpath);
        return self.status(request_id, c.SSH_FX_PERMISSION_DENIED);
    }

    /// Reply `code`, then audit it as denied (PERMISSION_DENIED) or
    /// failed with `detail`.
    fn reject(self: *SftpState, request_id: u32, code: c_int, op: []const u8, vpath: ?[]const u8, detail: []const u8) !void {
        if (code == c.SSH_FX_PERMISSION_DENIED) return self.deny(request_id, op, vpath);
        defer self.auditFailed(op, vpath, detail);
        return self.status(request_id, code);
    }

    /// Reply `code` to a caller who may stat the path. Anyone else gets
    /// PERMISSION_DENIED, so the reply never tells a missing path from a
    /// present one.
    fn hide(self: *SftpState, request_id: u32, may_stat: bool, code: c_int, op: []const u8, vpath: []const u8) !void {
        if (!may_stat) return self.deny(request_id, op, vpath);
        return self.status(request_id, code);
    }

    fn auditOk(self: *SftpState, op: []const u8, vpath: ?[]const u8, detail: []const u8) void {
        audit.log(self.io, self.user.name, op, vpath, .ok, detail, self.peer_ip);
    }

    fn auditDenied(self: *SftpState, op: []const u8, vpath: ?[]const u8) void {
        audit.log(self.io, self.user.name, op, vpath, .denied, "", self.peer_ip);
    }

    fn auditFailed(self: *SftpState, op: []const u8, vpath: ?[]const u8, detail: []const u8) void {
        audit.log(self.io, self.user.name, op, vpath, .failed, detail, self.peer_ip);
    }

    /// Parse and normalize a path argument into `buf`, or reply and return
    /// null. The policy must see the same string the filesystem resolves,
    /// or `/pending/../secret` slips past a rule. Bad bytes or length:
    /// BAD_MESSAGE. Traversal or `.zift`: PERMISSION_DENIED.
    fn pathArg(self: *SftpState, request_id: u32, payload: []const u8, buf: *PathBuf) !?wire.ParsedString {
        var arg = wire.parseString(payload) catch {
            try self.status(request_id, c.SSH_FX_BAD_MESSAGE);
            return null;
        };
        arg.value = vfs_mod.normalizeVirtualInto(arg.value, buf) catch |err| {
            try self.status(request_id, switch (err) {
                error.PathTooLong, error.InvalidPath => c.SSH_FX_BAD_MESSAGE,
                error.PathTraversal, error.Reserved => c.SSH_FX_PERMISSION_DENIED,
            });
            return null;
        };
        return arg;
    }

    /// `pathArg` for a request whose only argument is a path on which
    /// `op` must be allowed; a denial is audited as `label`.
    fn authorizedPath(
        self: *SftpState,
        request_id: u32,
        payload: []const u8,
        buf: *PathBuf,
        op: policy.Operation,
        label: []const u8,
    ) !?[]const u8 {
        const arg = (try self.pathArg(request_id, payload, buf)) orelse return null;
        if (policy.check(self.user, op, arg.value) == .deny) {
            try self.deny(request_id, label, arg.value);
            return null;
        }
        return arg.value;
    }

    /// The verified parent of `vpath`, or null after replying and auditing.
    fn parentOrReply(self: *SftpState, request_id: u32, op: []const u8, vpath: []const u8) !?vfs_mod.ParentResolution {
        return self.vfs.openVerifiedParent(self.io, self.allocator, vpath) catch |err| {
            try self.reject(request_id, wire.parentErrorStatus(err), op, vpath, @errorName(err));
            return null;
        };
    }

    /// Attrs as the partner sees them. `virtual`: uid/gid 0 and
    /// policy-derived mode at `vpath`. `reality`: the inode unchanged.
    fn applyListingMode(self: *const SftpState, real: listing.EntryInfo, vpath: []const u8) listing.EntryInfo {
        switch (self.listing_mode) {
            .reality => return real,
            .virtual => {
                var v = real;
                v.uid = 0;
                v.gid = 0;
                v.mode = policy.policyDerivedMode(self.user, vpath, real.mode);
                return v;
            },
        }
    }

    /// lstat `vpath` under its verified parent. "/" has no parent in the
    /// jail; it is the root itself.
    fn lstatVirtual(self: *SftpState, vpath: []const u8) !listing.EntryInfo {
        if (std.mem.eql(u8, vpath, "/")) {
            var root = try std.Io.Dir.openDirAbsolute(self.io, self.vfs.root, .{});
            defer root.close(self.io);
            return listing.statFd(root.handle);
        }
        var parent = try self.vfs.openVerifiedParent(self.io, self.allocator, vpath);
        defer parent.deinit(self.io, self.allocator);
        return listing.statAt(parent.parent.handle, parent.base);
    }

    fn handleRealpath(self: *SftpState, request_id: u32, payload: []const u8) !void {
        var buf: PathBuf = undefined;
        const path = (try self.pathArg(request_id, payload, &buf)) orelse return;
        try wire.replyName(self.channel, request_id, path.value);
    }

    fn handleStat(self: *SftpState, request_id: u32, payload: []const u8) !void {
        var buf: PathBuf = undefined;
        const path = (try self.authorizedPath(request_id, payload, &buf, .stat, "stat")) orelse return;
        const info = self.lstatVirtual(path) catch |err| {
            return self.status(request_id, switch (err) {
                error.NotFound => c.SSH_FX_NO_SUCH_FILE,
                else => wire.parentErrorStatus(err),
            });
        };
        try wire.replyFullAttrs(self.channel, request_id, self.applyListingMode(info, path));
    }

    /// FSTAT inherits the OPEN's authorization; no new policy check. Dir
    /// handles too, as OpenSSH's sftp-server allows.
    fn handleFstat(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const id = wire.parseHandleId(payload) catch return self.status(request_id, c.SSH_FX_BAD_MESSAGE);
        const handle = self.findHandle(id) orelse return self.status(request_id, c.SSH_FX_INVALID_HANDLE);
        const info = switch (handle.kind) {
            .file => |f| listing.statFd(f.file.handle),
            .dir => |d| listing.statFd(d.dir.handle),
        } catch return self.status(request_id, c.SSH_FX_FAILURE);

        const display = switch (handle.kind) {
            .dir => |d| self.applyListingMode(info, d.vpath),
            .file => |f| if (self.listing_mode == .reality) info else blk: {
                // No path: the handle's own access is the truth.
                var owner: u32 = 0;
                if (f.can_read) owner |= 0o4;
                if (f.can_write) owner |= 0o2;
                var v = info;
                v.uid = 0;
                v.gid = 0;
                v.mode = (info.mode & listing.S_IFMT) | (owner << 6) | (owner << 3);
                break :blk v;
            },
        };
        try wire.replyFullAttrs(self.channel, request_id, display);
    }

    fn handleOpendir(self: *SftpState, request_id: u32, payload: []const u8) !void {
        var buf: PathBuf = undefined;
        const path = (try self.authorizedPath(request_id, payload, &buf, .readdir, "opendir")) orelse return;

        // Checked before opening, so the cap path owns no fd.
        if (self.handles.items.len >= max_handles_per_session) {
            return self.reject(request_id, c.SSH_FX_FAILURE, "opendir", path, "handle limit reached");
        }

        const dir = self.vfs.openVirtualDir(self.io, self.allocator, path, true) catch |err| {
            return self.reject(request_id, wire.parentErrorStatus(err), "opendir", path, "open dir failed");
        };
        const vpath = self.allocator.dupe(u8, path) catch |err| {
            dir.close(self.io);
            return self.reject(request_id, c.SSH_FX_FAILURE, "opendir", path, @errorName(err));
        };
        const id = self.addHandle(.{ .dir = .{ .dir = dir, .iter = dir.iterate(), .vpath = vpath } }) catch |err| {
            return self.reject(request_id, c.SSH_FX_FAILURE, "opendir", path, @errorName(err));
        };
        defer self.auditOk("opendir", path, "");
        try wire.replyHandle(self.channel, request_id, id);
    }

    fn handleReaddir(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const id = wire.parseHandleId(payload) catch return self.status(request_id, c.SSH_FX_BAD_MESSAGE);
        const handle = self.findDir(id) orelse return self.status(request_id, c.SSH_FX_INVALID_HANDLE);
        if (handle.failed) return self.status(request_id, c.SSH_FX_FAILURE);
        if (handle.done) return self.status(request_id, c.SSH_FX_EOF);

        // 16 entries of at most ~620 bytes fit wire.replyNames' 32 KiB.
        var entries: [16]wire.DirEntry = undefined;
        var count: usize = 0;
        // One reference time per batch for "recent" vs "old" dates.
        const now_secs: i64 = sys.realtime().sec;
        var vpath_buf: [std.posix.PATH_MAX]u8 = undefined;

        while (count < entries.len) {
            const entry = handle.iter.next(self.io) catch {
                // Send what we have; the next READDIR reports the failure.
                handle.failed = true;
                break;
            } orelse {
                handle.done = true;
                break;
            };

            // Paths through `.zift` are already refused; hide the entry too.
            if (vfs_mod.isReservedComponent(entry.name)) continue;

            // lstat under the jailed dir fd. An entry that vanished since
            // readdir is simply skipped.
            const info = listing.statAt(handle.dir.handle, entry.name) catch continue;

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
                    const sep: []const u8 = if (std.mem.endsWith(u8, handle.vpath, "/")) "" else "/";
                    const stacked = std.fmt.bufPrint(&vpath_buf, "{s}{s}{s}", .{
                        handle.vpath, sep, entry.name,
                    });
                    var heap_vpath: ?[]u8 = null;
                    defer if (heap_vpath) |p| self.allocator.free(p);
                    const vpath: []const u8 = stacked catch blk: {
                        heap_vpath = std.fmt.allocPrint(self.allocator, "{s}{s}{s}", .{
                            handle.vpath, sep, entry.name,
                        }) catch break :blk handle.vpath;
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

        switch (readdirFollowup(count, handle.failed)) {
            .send_batch => {},
            .eof => return self.status(request_id, c.SSH_FX_EOF),
            .fail => return self.status(request_id, c.SSH_FX_FAILURE),
        }
        try wire.replyNames(self.channel, request_id, entries[0..count]);
    }

    fn handleOpen(self: *SftpState, request_id: u32, payload: []const u8) !void {
        var buf: PathBuf = undefined;
        const arg = (try self.pathArg(request_id, payload, &buf)) orelse return;
        const path = arg.value;
        if (arg.rest.len < 4) return self.status(request_id, c.SSH_FX_BAD_MESSAGE);
        const flags = std.mem.readInt(u32, arg.rest[0..4], .big);
        const want_creat = hasFlag(flags, c.SSH_FXF_CREAT);
        const want_excl = hasFlag(flags, c.SSH_FXF_EXCL);
        const want_trunc = hasFlag(flags, c.SSH_FXF_TRUNC);
        const want_append = hasFlag(flags, c.SSH_FXF_APPEND);
        // WRITE/APPEND/CREAT/TRUNC all imply write access.
        const want_write = want_creat or want_trunc or want_append or hasFlag(flags, c.SSH_FXF_WRITE);
        // No flags at all means read (some clients rely on it).
        const want_read = hasFlag(flags, c.SSH_FXF_READ) or !want_write;

        if (want_write and policy.check(self.user, .open_write, path) == .deny) {
            return self.deny(request_id, "open_write", path);
        }
        if (want_read and policy.check(self.user, .open_read, path) == .deny) {
            return self.deny(request_id, "open_read", path);
        }
        const op: []const u8 = if (want_write) "open_write" else "open_read";

        if (self.handles.items.len >= max_handles_per_session) {
            return self.reject(request_id, c.SSH_FX_FAILURE, op, path, "handle limit reached");
        }

        // Write without read or list must not tell a missing path from a
        // present one.
        const may_stat = policy.check(self.user, .stat, path) == .allow;

        // From here on only the parent fd plus basename are used.
        var parent = self.vfs.openVerifiedParent(self.io, self.allocator, path) catch |err| {
            return self.reject(request_id, concealed(may_stat, wire.parentErrorStatus(err)), op, path, @errorName(err));
        };
        defer parent.deinit(self.io, self.allocator);

        // O_NOFOLLOW: a symlink as the final component is always refused.
        const file = parent.parent.openFile(self.io, parent.base, .{
            .mode = if (!want_write) .read_only else if (want_read) .read_write else .write_only,
            .follow_symlinks = false,
            .allow_directory = false,
        }) catch |err| switch (err) {
            error.FileNotFound => {
                if (want_creat) return self.openStaged(request_id, op, path, want_read, want_append, want_excl);
                return self.hide(request_id, may_stat, c.SSH_FX_NO_SUCH_FILE, op, path);
            },
            error.SymLinkLoop => return self.deny(request_id, op, path),
            // A directory where a file was asked for.
            error.IsDir => return self.hide(request_id, may_stat, c.SSH_FX_FAILURE, op, path),
            else => return self.reject(request_id, c.SSH_FX_FAILURE, op, path, @errorName(err)),
        };
        var owned: ?std.Io.File = file;
        defer if (owned) |f| f.close(self.io);

        // EXCL on an existing file fails.
        if (want_creat and want_excl) return self.hide(request_id, may_stat, c.SSH_FX_FAILURE, op, path);

        // Defense in depth before anything is modified.
        self.vfs.verifyFile(self.io, file) catch return self.deny(request_id, op, path);

        // The clobber rule: writing to an existing file (truncate,
        // overwrite, or append) also needs `update`. Existence is the
        // open itself, so there is no check-then-act window.
        if (want_write and policy.check(self.user, .update, path) == .deny) {
            return self.deny(request_id, op, path);
        }

        // Before truncate: an exhausted id must not zero the file and
        // then kill the session. Ids are not recycled.
        if (!handleIdAvailable(self.next_handle)) {
            return self.reject(request_id, c.SSH_FX_FAILURE, op, path, "handle id exhausted");
        }
        if (want_append) setFdAppend(file.handle) catch {
            return self.reject(request_id, c.SSH_FX_FAILURE, op, path, "append flag failed");
        };
        if (want_trunc) file.setLength(self.io, 0) catch {
            return self.reject(request_id, c.SSH_FX_FAILURE, op, path, "truncate failed");
        };

        owned = null;
        const id = self.addHandle(.{ .file = .{
            .file = file,
            .can_read = want_read,
            .can_write = want_write,
            .is_append = want_append,
        } }) catch |err| return self.reject(request_id, c.SSH_FX_FAILURE, op, path, @errorName(err));
        defer self.auditOk(op, path, "");
        try wire.replyHandle(self.channel, request_id, id);
    }

    /// Create a new file in staging; CLOSE renames it into place, so the
    /// target is either absent or complete. An abandoned or failed upload
    /// unlinks its staging file. TRUNC is moot on a new file; EXCL is
    /// checked again at CLOSE.
    fn openStaged(
        self: *SftpState,
        request_id: u32,
        op: []const u8,
        path: []const u8,
        want_read: bool,
        want_append: bool,
        want_excl: bool,
    ) !void {
        const staging = self.ensureStagingDir() catch {
            return self.reject(request_id, c.SSH_FX_FAILURE, op, path, "staging dir unavailable");
        };
        var name: [32]u8 = undefined;
        // Never fall back to a predictable name.
        generateStagingName(self.io, &name) catch {
            return self.reject(request_id, c.SSH_FX_FAILURE, op, path, "no entropy for staging name");
        };
        self.registerStagingName(name) catch {
            return self.reject(request_id, c.SSH_FX_FAILURE, op, path, "staging register failed");
        };

        // Created at `publish-mode`, which rename(2) keeps; the 0700
        // staging dir hides it meanwhile. Set the mode again after create
        // because umask masks it.
        const permissions = std.Io.File.Permissions.fromMode(@intCast(self.publish_mode));
        const file = staging.createFile(self.io, &name, .{
            .read = want_read,
            .exclusive = true,
            .permissions = permissions,
        }) catch {
            // Not created, so not ours to unlink.
            self.unregisterStagingName(&name);
            return self.reject(request_id, c.SSH_FX_FAILURE, op, path, "staging create failed");
        };
        const setup_failure: ?[]const u8 = blk: {
            file.setPermissions(self.io, permissions) catch break :blk "staging chmod failed";
            if (want_append) setFdAppend(file.handle) catch break :blk "append flag failed";
            break :blk null;
        };
        const target = if (setup_failure == null) self.allocator.dupe(u8, path) catch null else null;
        if (target == null) {
            file.close(self.io);
            staging.deleteFile(self.io, &name) catch {};
            self.unregisterStagingName(&name);
            return self.reject(request_id, c.SSH_FX_FAILURE, op, path, setup_failure orelse "OutOfMemory");
        }

        const id = self.addHandle(.{ .file = .{
            .file = file,
            .can_read = want_read,
            .can_write = true,
            .is_append = want_append,
            .staged = .{ .name = name, .target = target.?, .excl = want_excl },
        } }) catch |err| return self.reject(request_id, c.SSH_FX_FAILURE, op, path, @errorName(err));
        defer self.auditOk(op, path, "staged");
        try wire.replyHandle(self.channel, request_id, id);
    }

    fn handleRead(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const id = wire.parseHandleId(payload) catch return self.status(request_id, c.SSH_FX_BAD_MESSAGE);
        if (payload.len < 20) return self.status(request_id, c.SSH_FX_BAD_MESSAGE);
        const offset = std.mem.readInt(u64, payload[8..16], .big);
        const len = @min(std.mem.readInt(u32, payload[16..20], .big), 32 * 1024);
        const handle = self.findFile(id) orelse return self.status(request_id, c.SSH_FX_INVALID_HANDLE);

        // Above i64 max, std's pread path would panic in a safe build.
        if (offset > std.math.maxInt(i64)) return self.status(request_id, c.SSH_FX_BAD_MESSAGE);
        if (!handle.can_read) return self.deny(request_id, "read", null);

        // A 0-byte read gets empty DATA, not EOF.
        if (len == 0) return wire.replyData(self.channel, request_id, "");

        const buf = try self.allocator.alloc(u8, len);
        defer self.allocator.free(buf);
        const n = handle.file.readPositionalAll(self.io, buf, offset) catch {
            return self.status(request_id, c.SSH_FX_FAILURE);
        };
        if (n == 0) return self.status(request_id, c.SSH_FX_EOF);
        try wire.replyData(self.channel, request_id, buf[0..n]);
    }

    fn handleWrite(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const id = wire.parseHandleId(payload) catch return self.status(request_id, c.SSH_FX_BAD_MESSAGE);
        if (payload.len < 16) return self.status(request_id, c.SSH_FX_BAD_MESSAGE);
        const offset = std.mem.readInt(u64, payload[8..16], .big);
        const data = wire.parseString(payload[16..]) catch return self.status(request_id, c.SSH_FX_BAD_MESSAGE);
        const handle = self.findFile(id) orelse return self.status(request_id, c.SSH_FX_INVALID_HANDLE);

        // Same bound as READ; append ignores the offset.
        if (!handle.is_append and offset > std.math.maxInt(i64)) {
            return self.status(request_id, c.SSH_FX_BAD_MESSAGE);
        }
        if (!handle.can_write) return self.deny(request_id, "write", null);

        // SSH_FXF_APPEND: write(2) honors the O_APPEND set at OPEN,
        // including writes from other sessions. pwrite does not.
        const written = if (handle.is_append)
            handle.file.writeStreamingAll(self.io, data.value)
        else
            handle.file.writePositionalAll(self.io, data.value, offset);
        written catch return self.status(request_id, c.SSH_FX_FAILURE);
        try self.status(request_id, c.SSH_FX_OK);
    }

    fn handleClose(self: *SftpState, request_id: u32, payload: []const u8) !void {
        const id = wire.parseHandleId(payload) catch return self.status(request_id, c.SSH_FX_BAD_MESSAGE);
        var handle = self.takeHandle(id) orelse return self.status(request_id, c.SSH_FX_INVALID_HANDLE);
        defer self.closeHandle(handle);

        const staged = switch (handle.kind) {
            .file => |*f| if (f.staged) |*s| s else null,
            .dir => null,
        } orelse return self.status(request_id, c.SSH_FX_OK);

        const code = self.publish(staged) catch |err| {
            return self.reject(request_id, c.SSH_FX_FAILURE, "close", staged.target, @errorName(err));
        };
        if (code == c.SSH_FX_OK) {
            defer self.auditOk("publish", staged.target, "");
            return self.status(request_id, code);
        }
        try self.status(request_id, code);
    }

    /// Rename a staged upload to its target, walking the target's parent
    /// again since it may have changed during the upload. Returns OK, or
    /// the status of an audited refusal.
    fn publish(self: *SftpState, staged: *Staged) !c_int {
        const staging = self.staging_dir.?;
        self.namespace_lock.lockUncancelable(self.io);
        defer self.namespace_lock.unlock(self.io);

        var parent = try self.vfs.openVerifiedParent(self.io, self.allocator, staged.target);
        defer parent.deinit(self.io, self.allocator);

        // The clobber rule again: the target may have appeared since OPEN.
        // Without replace rights a no-replace rename refuses any existing
        // entry, even a dangling symlink, with no check-then-act window.
        const may_replace = !staged.excl and policy.check(self.user, .update, staged.target) == .allow;
        if (may_replace) {
            try std.Io.Dir.rename(staging, &staged.name, parent.parent, parent.base, self.io);
        } else {
            renameNoReplace(staging, &staged.name, parent.parent, parent.base, self.io) catch |err| switch (err) {
                error.PathAlreadyExists => {
                    // EXCL reports FAILURE ("exists"), otherwise it is the
                    // clobber rule.
                    self.auditDenied("close", staged.target);
                    return if (staged.excl) c.SSH_FX_FAILURE else c.SSH_FX_PERMISSION_DENIED;
                },
                else => return err,
            };
        }
        staged.published = true;
        return c.SSH_FX_OK;
    }

    fn handleMkdir(self: *SftpState, request_id: u32, payload: []const u8) !void {
        var buf: PathBuf = undefined;
        const path = (try self.authorizedPath(request_id, payload, &buf, .mkdir, "mkdir")) orelse return;
        self.namespace_lock.lockUncancelable(self.io);
        defer self.namespace_lock.unlock(self.io);
        var parent = (try self.parentOrReply(request_id, "mkdir", path)) orelse return;
        defer parent.deinit(self.io, self.allocator);

        const permissions = std.Io.File.Permissions.fromMode(@intCast(self.mkdir_mode));
        parent.parent.createDir(self.io, parent.base, permissions) catch {
            return self.reject(request_id, c.SSH_FX_FAILURE, "mkdir", path, "createDir failed");
        };
        // umask applied to createDir, so set the mode again, rolling back
        // on failure. `iterate` keeps Zig off O_PATH, which cannot fchmod.
        const mode_failure: ?[]const u8 = blk: {
            var created = parent.parent.openDir(self.io, parent.base, .{
                .follow_symlinks = false,
                .iterate = true,
            }) catch break :blk "openDir-after-create failed";
            defer created.close(self.io);
            created.setPermissions(self.io, permissions) catch break :blk "setPermissions failed";
            break :blk null;
        };
        if (mode_failure) |detail| {
            // Fails harmlessly if something already populated it.
            parent.parent.deleteDir(self.io, parent.base) catch {};
            return self.reject(request_id, c.SSH_FX_FAILURE, "mkdir", path, detail);
        }
        defer self.auditOk("mkdir", path, "");
        try self.status(request_id, c.SSH_FX_OK);
    }

    /// REMOVE (`.file`) and RMDIR (`.dir`).
    fn handleUnlink(self: *SftpState, request_id: u32, payload: []const u8, kind: enum { file, dir }) !void {
        const op: policy.Operation, const label: []const u8 = switch (kind) {
            .file => .{ .remove, "remove" },
            .dir => .{ .rmdir, "rmdir" },
        };
        var buf: PathBuf = undefined;
        const path = (try self.authorizedPath(request_id, payload, &buf, op, label)) orelse return;
        self.namespace_lock.lockUncancelable(self.io);
        defer self.namespace_lock.unlock(self.io);
        var parent = (try self.parentOrReply(request_id, label, path)) orelse return;
        defer parent.deinit(self.io, self.allocator);

        const removed = switch (kind) {
            .file => parent.parent.deleteFile(self.io, parent.base),
            .dir => parent.parent.deleteDir(self.io, parent.base),
        };
        removed catch |err| return self.reject(request_id, c.SSH_FX_FAILURE, label, path, @errorName(err));
        defer self.auditOk(label, path, "");
        try self.status(request_id, c.SSH_FX_OK);
    }

    fn handleRename(self: *SftpState, request_id: u32, payload: []const u8) !void {
        var from_buf: PathBuf = undefined;
        var to_buf: PathBuf = undefined;
        const from_arg = (try self.pathArg(request_id, payload, &from_buf)) orelse return;
        const from = from_arg.value;
        const to = ((try self.pathArg(request_id, from_arg.rest, &to_buf)) orelse return).value;
        if (policy.checkRename(self.user, from, to) == .deny) return self.deny(request_id, "rename", from);

        self.namespace_lock.lockUncancelable(self.io);
        defer self.namespace_lock.unlock(self.io);
        var from_parent = (try self.parentOrReply(request_id, "rename", from)) orelse return;
        defer from_parent.deinit(self.io, self.allocator);
        var to_parent = (try self.parentOrReply(request_id, "rename", to)) orelse return;
        defer to_parent.deinit(self.io, self.allocator);

        const source = listing.statAt(from_parent.parent.handle, from_parent.base) catch |err| {
            return self.reject(request_id, c.SSH_FX_NO_SUCH_FILE, "rename", from, @errorName(err));
        };
        if (gainsCapability(self.user, source.mode, from, to)) return self.deny(request_id, "rename", from);

        // A directory rename respells every descendant's path; check each
        // one at both spellings so denied children cannot be carried into
        // an allowed subtree.
        if ((source.mode & listing.S_IFMT) == listing.S_IFDIR) {
            self.verifyRenameTree(from_parent, from, to) catch |err| switch (err) {
                error.RenameDenied, error.RenameScanLimit => return self.deny(request_id, "rename", from),
                else => return self.reject(request_id, c.SSH_FX_FAILURE, "rename", from, @errorName(err)),
            };
        }

        // rename(2) silently replaces the destination, so replacing needs
        // `update` there (the clobber rule). Without it, a no-replace
        // rename refuses any existing entry, with no check-then-act race.
        if (policy.check(self.user, .update, to) == .allow) {
            std.Io.Dir.rename(from_parent.parent, from_parent.base, to_parent.parent, to_parent.base, self.io) catch {
                return self.reject(request_id, c.SSH_FX_FAILURE, "rename", from, "rename failed");
            };
        } else {
            renameNoReplace(from_parent.parent, from_parent.base, to_parent.parent, to_parent.base, self.io) catch |err| {
                if (err == error.PathAlreadyExists) return self.deny(request_id, "rename", to);
                return self.reject(request_id, c.SSH_FX_FAILURE, "rename", from, "rename failed");
            };
        }
        defer self.auditOk("rename", from, to);
        try self.status(request_id, c.SSH_FX_OK);
    }

    fn verifyRenameTree(self: *SftpState, parent: vfs_mod.ParentResolution, from: []const u8, to: []const u8) !void {
        var dir = try parent.parent.openDir(self.io, parent.base, .{ .iterate = true, .follow_symlinks = false });
        defer dir.close(self.io);
        var scan: RenameScan = .{ .state = self };
        @memcpy(scan.old[0..from.len], from);
        @memcpy(scan.new[0..to.len], to);
        try scan.walk(dir, from.len, to.len, 0);
    }

    fn addHandle(self: *SftpState, kind: @FieldType(Handle, "kind")) !u32 {
        // Owns `kind`'s resources from here, even on failure.
        var handle: Handle = .{ .id = 0, .kind = kind };
        errdefer self.closeHandle(handle);
        handle.id = try self.nextHandleId();
        try self.handles.append(self.allocator, handle);
        return handle.id;
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
        const now_secs = sys.realtime().sec;
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

    fn registerStagingName(self: *SftpState, name: [32]u8) !void {
        staging_live_mutex.lockUncancelable(self.io);
        defer staging_live_mutex.unlock(self.io);
        try staging_live.append(self.allocator, name);
    }

    fn unregisterStagingName(self: *SftpState, name: *const [32]u8) void {
        staging_live_mutex.lockUncancelable(self.io);
        defer staging_live_mutex.unlock(self.io);
        for (staging_live.items, 0..) |*live, i| {
            if (std.mem.eql(u8, live, name)) {
                _ = staging_live.swapRemove(i);
                return;
            }
        }
    }

    fn stagingNameIsLive(self: *SftpState, name: []const u8) bool {
        staging_live_mutex.lockUncancelable(self.io);
        defer staging_live_mutex.unlock(self.io);
        for (staging_live.items) |*live| {
            if (std.mem.eql(u8, live, name)) return true;
        }
        return false;
    }

    fn nextHandleId(self: *SftpState) !u32 {
        // Ids are never reused, so a closed handle can never alias a new
        // one. At u32 max we fail instead of wrapping.
        if (!handleIdAvailable(self.next_handle)) return error.HandleSpaceExhausted;
        const id = self.next_handle;
        self.next_handle += 1;
        return id;
    }

    fn findHandle(self: *SftpState, id: u32) ?*Handle {
        for (self.handles.items) |*handle| {
            if (handle.id == id) return handle;
        }
        return null;
    }

    fn findFile(self: *SftpState, id: u32) ?*FileHandle {
        const handle = self.findHandle(id) orelse return null;
        return switch (handle.kind) {
            .file => |*f| f,
            .dir => null,
        };
    }

    fn findDir(self: *SftpState, id: u32) ?*DirHandle {
        const handle = self.findHandle(id) orelse return null;
        return switch (handle.kind) {
            .dir => |*d| d,
            .file => null,
        };
    }

    /// Remove the handle from the table; the caller closes it.
    fn takeHandle(self: *SftpState, id: u32) ?Handle {
        for (self.handles.items, 0..) |handle, i| {
            if (handle.id == id) return self.handles.swapRemove(i);
        }
        return null;
    }

    fn closeHandle(self: *SftpState, handle: Handle) void {
        switch (handle.kind) {
            .dir => |d| {
                d.dir.close(self.io);
                self.allocator.free(d.vpath);
            },
            .file => |f| {
                f.file.close(self.io);
                const staged = f.staged orelse return;
                // Never published: the upload was abandoned or failed.
                if (!staged.published) {
                    if (self.staging_dir) |dir| dir.deleteFile(self.io, &staged.name) catch {};
                }
                self.unregisterStagingName(&staged.name);
                self.allocator.free(staged.target);
            },
        }
    }
};

/// Checks every descendant of a directory being renamed at both
/// spellings. Each level writes `/<name>` after its parent's path in
/// `old` and `new`, so the scan allocates nothing.
const RenameScan = struct {
    state: *SftpState,
    old: PathBuf = undefined,
    new: PathBuf = undefined,
    scanned: usize = 0,

    fn walk(scan: *RenameScan, dir: std.Io.Dir, old_len: usize, new_len: usize, depth: usize) !void {
        if (depth >= max_rename_scan_depth) return error.RenameScanLimit;
        const io = scan.state.io;
        const user = scan.state.user;

        var it = dir.iterate();
        while (try it.next(io)) |entry| {
            scan.scanned += 1;
            if (scan.scanned > max_rename_scan_entries) return error.RenameScanLimit;

            // A local operator can create names that the SFTP protocol
            // intentionally cannot represent. Moving those entries
            // cannot be authorized accurately, so fail closed.
            vfs_mod.Vfs.validateVirtualPath(entry.name) catch return error.RenameDenied;
            if (vfs_mod.isReservedComponent(entry.name)) return error.RenameDenied;

            const old = try appendChild(&scan.old, old_len, entry.name);
            const new = try appendChild(&scan.new, new_len, entry.name);
            const info = try listing.statAt(dir.handle, entry.name);
            if (policy.checkRename(user, old, new) == .deny or gainsCapability(user, info.mode, old, new)) {
                return error.RenameDenied;
            }

            if ((info.mode & listing.S_IFMT) == listing.S_IFDIR) {
                var child = try dir.openDir(io, entry.name, .{ .iterate = true, .follow_symlinks = false });
                defer child.close(io);
                try scan.walk(child, old.len, new.len, depth + 1);
            }
        }
    }

    /// `buf[0..len] ++ "/" ++ name`, refused past the virtual path limit.
    fn appendChild(buf: *PathBuf, len: usize, name: []const u8) ![]const u8 {
        const end = len + 1 + name.len;
        if (end > vfs_mod.max_virtual_path_bytes) return error.RenameDenied;
        buf[len] = '/';
        @memcpy(buf[len + 1 .. end], name);
        return buf[0..end];
    }
};

/// Whether moving an object from `old_path` to `new_path` would give the
/// partner a capability over it they lack today. Requiring rename at both
/// spellings (checked separately) also enforces explicit deny rules:
/// moving a denied object is itself manipulation of that object.
fn gainsCapability(user: *const config.UserConfig, mode: u32, old_path: []const u8, new_path: []const u8) bool {
    const kind_ops: []const policy.Operation = switch (mode & listing.S_IFMT) {
        listing.S_IFDIR => &.{ .readdir, .rmdir },
        listing.S_IFREG => &.{ .open_read, .open_write, .remove },
        else => &.{.remove},
    };
    for ([_][]const policy.Operation{ &.{ .stat, .update }, kind_ops }) |ops| {
        for (ops) |op| {
            if (policy.check(user, op, new_path) == .allow and policy.check(user, op, old_path) == .deny) return true;
        }
    }
    return false;
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
            else => error.Unexpected,
        };
    }
    // Linux: renameat2(NOREPLACE). Elsewhere Zig falls back to
    // hardlink+unlink, which is still no-replace for files.
    try std.Io.Dir.renamePreserve(old_dir, old_sub_path, new_dir, new_sub_path, io);
}

/// 32 hex chars from 16 CSPRNG bytes; collisions are negligible.
/// Fails rather than ever produce a predictable name.
fn generateStagingName(io: std.Io, out: *[32]u8) !void {
    var raw: [16]u8 = undefined;
    try io.randomSecure(&raw);
    out.* = std.fmt.bytesToHex(raw, .lower);
}

fn hasFlag(flags: u32, bit: c_int) bool {
    return flags & @as(u32, @intCast(bit)) != 0;
}

/// Read one length-prefixed packet, or `error.IdleTimeout`.
fn readPacketTimed(state: *SftpState, payload_buf: []u8) ![]u8 {
    var len_buf: [4]u8 = undefined;
    try readExactTimed(state, &len_buf);
    const len = std.mem.readInt(u32, &len_buf, .big);

    // Oversized: reply BAD_MESSAGE to the request, then end the session,
    // since resyncing would mean draining attacker-sized input.
    if (len > payload_buf.len) {
        var head: [5]u8 = undefined;
        readExactTimed(state, &head) catch return error.LibsshFailure;
        const request_id = std.mem.readInt(u32, head[1..5], .big);
        state.status(request_id, c.SSH_FX_BAD_MESSAGE) catch {};
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
                if (idleExpired(state)) return error.IdleTimeout;
                continue;
            }
            return error.ChannelEof;
        }
        if (n == c.SSH_AGAIN) {
            if (idleExpired(state)) return error.IdleTimeout;
            continue;
        }
        // Progress: the cap counts consecutive false EOFs only.
        state.spurious_eof_count = 0;
        offset += @intCast(n);
    }
}

fn idleExpired(state: *const SftpState) bool {
    if (state.idle_timeout_ms == 0) return false;
    return sys.monotonicMs() - state.last_activity_ms >= @as(i64, @intCast(state.idle_timeout_ms));
}

fn acceptInitPayload(payload: []const u8) error{LibsshFailure}!void {
    if (payload.len < 5 or payload[0] != c.SSH_FXP_INIT) return error.LibsshFailure;
    if (std.mem.readInt(u32, payload[1..5], .big) < 3) return error.LibsshFailure;
}

fn handleIdAvailable(next_handle: u32) bool {
    return next_handle != std.math.maxInt(u32);
}

/// A caller who may not stat a path must not learn that it, or its
/// parent, is missing.
fn concealed(may_stat: bool, code: c_int) c_int {
    if (!may_stat and code == c.SSH_FX_NO_SUCH_FILE) return c.SSH_FX_PERMISSION_DENIED;
    return code;
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

test "a caller who cannot stat never learns a path is missing" {
    const denied: c_int = c.SSH_FX_PERMISSION_DENIED;
    const missing: c_int = c.SSH_FX_NO_SUCH_FILE;
    const failure: c_int = c.SSH_FX_FAILURE;
    try std.testing.expectEqual(denied, concealed(false, missing));
    try std.testing.expectEqual(missing, concealed(true, missing));
    try std.testing.expectEqual(failure, concealed(false, failure));
    try std.testing.expectEqual(denied, concealed(true, denied));
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

test "pre-subsystem ignore cap is 64" {
    var count: u32 = 0;
    for (0..64) |_| try noteIgnoredPreSubsystem(&count);
    try std.testing.expectError(error.LibsshFailure, noteIgnoredPreSubsystem(&count));
}

test "rename scan paths stop at the virtual path limit" {
    var buf: PathBuf = undefined;
    @memcpy(buf[0..2], "/a");
    try std.testing.expectEqualStrings("/a/b", try RenameScan.appendChild(&buf, 2, "b"));
    const long = [_]u8{'x'} ** (vfs_mod.max_virtual_path_bytes - 3);
    try std.testing.expectEqual(vfs_mod.max_virtual_path_bytes, (try RenameScan.appendChild(&buf, 2, &long)).len);
    try std.testing.expectError(error.RenameDenied, RenameScan.appendChild(&buf, 2, long ++ "y"));
}
