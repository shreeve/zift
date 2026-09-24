# TODO

The items below were fixed on the `revamp` branch, except the deferred
list at the bottom. Unit tests: 150 passed. Integration tests: 39 passed,
on macOS. Linux was not re-run here.

Audit of the tree as of 2026-09-21. Five read-only passes covered the
session layer, authentication, the SFTP handlers, the jail, and reload.
The severe items were re-checked against the Zig 0.16 standard library.
Two were reproduced on macOS.

The libssh comments in the session layer are workarounds that hold.
The idle-timer and spurious-EOF paths do what they say. The real
defects are elsewhere.

Fix the relative-root abort and the `MKDIR` reopen first. Both are
small, and the first one takes the process down.

## What those comments actually are

These are not bugs. Leave them unless a change is required for one of
the items below.

- [x] Spurious EOF is handled. `readExactTimed` in `src/sftp.zig`
  treats a libssh `0` as a real end-of-file only when
  `ssh_channel_is_eof` agrees. A disagreeing `0` is retried, still
  counts toward the idle deadline, and the counter resets when real
  bytes arrive. A stuck channel hits the cap and the session ends. It
  does not hang, and it does not drop a healthy transfer after a
  lifetime of glitches.
- [x] A client `SSH_MSG_DISCONNECT` is recorded by libssh as a fatal
  error (the upstream comment says it still needs a graceful-disconnect
  path). Zift parses that text and audits reason 11 as a normal
  goodbye. Other codes stay failures.
- [x] Connection slots are reserved before the thread starts and
  released on every exit, including spawn failure.

## Confirmed defects

### 1. A relative `root` aborts the process

- [x] Reject a non-absolute `root` at parse time, the way `partner-root`
  is rejected, and return a config error instead of asserting.

`parse` stores `root ally` after checking only that it is non-empty
(`src/config.zig` around line 960). `partner-root` is required to be
absolute. `validateSemantic` then calls `realPathFileAbsoluteAlloc`,
whose first act is `assert(path.isAbsolute)`. Running that call on a
relative path panics with "reached unreachable code" inside the
assert, and the `catch` around it does not run. Release builds are
`ReleaseSafe`, so this abort is in the shipping binary. It runs on
the accept thread during the mtime reload, so one bad edit drops
every live session. `zift validate` dies the same way, which means a
`systemctl reload` happens to be saved by `ExecReload` failing before
`SIGHUP`. A direct `SIGHUP`, the 2-second mtime poll, and startup are
not.

### 2. `MKDIR` reopens the new directory with the default options, which follow symlinks

- [x] Open the directory just created with `follow_symlinks: false`
  and `iterate: true`, matching the namespace helpers in `src/vfs.zig`.

`handleMkdir` does `createDir`, then `openDir(parent.base, .{})`, then
`setPermissions` (`src/sftp.zig` 1385–1398). Empty options mean
`follow_symlinks = true`. The namespace and staging opens a few
hundred lines away in `src/vfs.zig` pass `follow_symlinks: false` and
`iterate: true` on purpose. Reproduced on macOS: a symlink planted
under that name, opened with default options, and
`setPermissions(0o2770)` changed the target directory from `0700` to
`02770`.

A remote partner cannot plant that symlink (`SYMLINK` is rejected,
and the namespace mutex serializes other SFTP sessions). A local
process can. Recommended partner directories are mode `02770`, so a
local user in group `zift` can write the parent, rename the new
directory away, and point the same name at `<root>/.zift/staging` in
the gap between `mkdirat` and `openat`. Staging is supposed to stay
`0700` so that group cannot read in-flight uploads. This chmod undoes
that.

Ubuntu CI case 37 passed, which means `setPermissions` itself
succeeds on the shipping Linux binary. The same default also leaves
`O_NOFOLLOW` off there, so the race is not macOS-only. The reading
"chmod fails so mkdir always errors" is inconsistent with that
passing case.

### 3. Anything that is not an auth request holds a connection slot indefinitely

- [x] Count non-auth SSH messages against the soft-op ceiling in both
  `authenticate` and `acceptSftpSubsystem`.
- [ ] Add an integration test that completes key exchange and then sends
  service or global requests faster than `idle-timeout`. The cap is
  unit-tested. The existing idle tests only hold a silent TCP socket.

`authenticate` caps password failures at 6 and key probes at 64
because each `ssh_message_get` starts a fresh idle deadline. Messages
that are not `SSH_REQUEST_AUTH` are `reply_default`'d and the loop
continues with neither counter incremented (`src/ssh.zig` 45–47).
After login, `acceptSftpSubsystem` has the same unbounded loop until
an `sftp` subsystem request arrives (`src/sftp.zig` 78–105). A peer
that finishes the key exchange and sends a service request or a
global request more often than `idle-timeout` keeps both the session
slot and the pre-auth slot. The default is `max-connections 128` and
`max-unauth-connections 0`, so the separate pre-auth cap is off and
128 of these fill the server.

### 4. A `from` miss is distinguishable on the public-key path

- [x] Make a public-key probe for a real user outside `from` look like
  the unknown-user probe: same delay class, same soft-vs-hard
  accounting. The audit line stays `source not allowed`.
- [ ] Add an integration test that configures `from`. The classification
  is in `src/ssh.zig` and is not covered by a live client yet.

An unknown user probed with any key is a soft failure: no delay, and
the session survives until 64 probes. A real user whose address
misses `from` is a hard failure: 250 ms, then 500 ms, up to 2 s, and
the session dies at 6 (`src/ssh.zig` 252–260 and 141–159). The method
list still says `password,publickey`, so this is a separate leak from
the accepted password-only narrowing. Password denials do not have
this split. They all pay one Argon2id and all count as hard failures.

### 5. Source suppression applies only to the next accept

- [x] Re-check `isSuppressed` inside the auth loop, and stop the session
  that records the 10th failure instead of letting it finish its own
  6 attempts.

The 10-failures / 10-minutes / 15-minute-suppress numbers match the
docs. `isSuppressed` runs in the accept loop and is not consulted
again inside authentication. Sessions already accepted keep guessing,
up to 6 hard attempts each. With the pre-auth cap off, one source can
land on the order of `max-connections × 6` guesses in parallel, and
the session that records the 10th failure is allowed to finish its
own 6. New connections from that address are refused.

### 6. Concurrent append loses bytes

- [x] Open `SSH_FXF_APPEND` handles with `O_APPEND` and `write(2)`, so
  two sessions cannot snapshot the same size and overwrite each other.
- [ ] Extend case 24, which covers one client, to two sessions.

`SSH_FXF_APPEND` is implemented as `stat` the fd, then `pwrite` at
that size (`src/sftp.zig` 1133–1148). The open does not request
append mode. Two sessions of the same partner can snapshot the same
size and overwrite each other. Both still get `SSH_FX_OK`. The
comment says a session is single-threaded, which is true, and each
session is its own thread.

### 7. A second login can delete an upload the first session still has open

- [x] Sweep skips staging names a live session has registered. The age
  floor still removes crash orphans.

Every login sweeps `<root>/.zift/staging/` and unlinks regular files
older than `max(idle-timeout, 15 minutes)` (`src/sftp.zig`
1766–1784). Idle does not have to fire. Any other SFTP request
refreshes the session, and `idle-timeout 0` never kills it. `unlink`
of an open file succeeds, later `WRITE`s return success into the
unlinked inode, and `CLOSE` fails because the staging name is gone.
The comment describes the age floor as protection for concurrent
sessions. It measures mtime, not open handles.

### 8. A failed status write on the mtime reload exits the process

- [x] Status-write and allocation failures on the mtime reload path stay
  in process. A bad file still keeps the previous config. A good file
  stays in service if the announcement cannot be printed.

Parse failures are swallowed and the previous config stays in
service. `reloadIfChanged` is `try`'d from the accept loop
(`src/server.zig` 169–170), so a failed stderr write after a good
swap, or a failed allocation of the new config ref, returns from
`run` and drops every session. The documented "invalid reload keeps
the old config" guarantee covers a bad file, and this path is a good
file plus a failed log write.

### 9. The host key is not held to the authorized-key checks

- [x] Stat the host key with `follow_symlinks: false`, require a
  regular file, and reject mode bits in `0o037`. `0640` stays legal.
- [x] Reload when an authorized-key file's mtime changes, on the same
  interval as `zift.conf`, and on `SIGHUP`.

Partner key files are opened with `follow_symlinks = false`, must be
regular files, and are rejected if group or world can write them. The
host key is a `stat` that follows symlinks, with no mode check
(`src/config.zig` 251–257). A `0644` or group-writable private key is
accepted. The running process also does not notice an edited
`ally.pub` until `zift.conf` itself changes or someone sends
`SIGHUP`.

### 10. Graceful shutdown closes the listen socket twice

- [x] After the explicit `close` of the listen fd, `ssh_bind_set_fd`
  stores `-1` so `ssh_bind_free` does not close that number again.

The drain path `close`s libssh's listen fd so the port unbinds
immediately (`src/server.zig` 265–269). `ssh_bind_free` on the way
out closes that same number. During the grace window workers are
still opening files, so the second close can hit whatever was
assigned that descriptor. On a clean drain every worker has finished
and the second close is `EBADF`. The dangerous window is the "still
alive after force-close" exit.

## Smaller items

- [x] `SSH_FXP_REALPATH` of `/.zift` returns a non-v3 status
  (`SSH_FX_NO_SUCH_PATH`, code 10). Every other handler returns
  permission denied. No access. Route `REALPATH` through
  `normalizedPath` so the status matches.
- [x] The SFTP version in `SSH_FXP_INIT` is never read. The server
  always answers version 3, including to a client that offered 1 or
  2. Read the version and refuse anything below 3.
- [x] Handle ids start at 1 and are never recycled. After `2^32 - 1`
  opens in one session, an existing-file `TRUNC` can truncate and
  then the `try` on `nextHandleId` drops the connection with no
  status. The live cap of 256 is enforced. Reply with failure before
  truncate, or recycle ids.
- [x] `write` without `list` or `read` can tell whether a guessed name
  exists: missing is `NO_SUCH_FILE`, present is `PERMISSION_DENIED`
  after the `update` check. An explicit `deny` still hides the name.
  Decide whether a write-only drop box should return the same status
  for both.
- [x] A `READDIR` iterator error discards the names already pulled into
  that batch, and the handle continues past them. Send the names
  already copied, or fail the handle so the client cannot resume
  past the gap.
- [x] `deny **/.ssh/**`, which is the example in the docs, does not
  match the `.ssh` directory itself. `READDIR` of that directory
  lists key names. `OPEN` of the key file is still denied. Change
  the example, or make that pattern cover the directory node.
- [x] On APFS, a byte-exact `deny` misses the same filename in the
  other Unicode normalization. The documented caveat is ASCII case
  (`TOOL.EXE`). `.zift` is ASCII, so the reserved namespace is
  unaffected. Linux partner roots do not have this lookup. Document
  it next to the case caveat, or fold names before the glob compare
  on case-insensitive volumes.
- [x] `idle-timeout` above about 24.8 days becomes "wait forever" in
  libssh, because libssh stores the timeout as a 32-bit millisecond
  count and saturates to infinite. The SFTP read loop still enforces
  it. The default of 5 minutes is fine. Cap the value that is passed
  into `SSH_OPTIONS_TIMEOUT`.
- [x] An empty password can be minted with `zift hash-password` and
  will verify. A non-empty hash still rejects `""`. Reject empty
  input in `hash-password` and in `parseAuth`.
- [x] A world-open audit path, or a symlink at the log path, is
  followed. Open the audit file with `O_NOFOLLOW` and pin the mode
  of a file the daemon created. `SIGUSR1` reopen that fails to open
  the new file is forgotten, and later lines stay on the old inode.
  Put the flag back if the open fails.
- [x] An in-place rewrite of `zift.conf` can be read as a valid prefix
  (the first user block, missing the later `deny` rules). An atomic
  rename avoids it. Document that, or reload only after the file is
  stable across two stats.

## Deferred

Left on purpose. None of these is a remote jail escape.

- A second integration test for the non-auth message cap, for `from`,
  and for two concurrent appenders. The behavior is unit-tested or
  covered by the single-client append case.
- `max-connections 0` refuses every connection. Other `0` values mean
  "disabled". Rejecting `0` here would be clearer.
- The session-fd registry can, during shutdown, `shutdown` a reused
  descriptor number. `shutdown` on a non-socket returns `ENOTSOCK`.
- The first password denial after process start pays two Argon2id
  runs, until the dummy hash is cached.
- A public-key probe whose algorithm matches none of the user's keys
  skips the dummy import, so it can be slightly faster.
- libssh 0.11 drops a bad public-key signature before Zift sees the
  message, so those packets do not increment the attempt ceiling.
- Audit lines may contain U+2028 or U+2029. `jq` accepts them. A
  splitter that breaks on those characters can still splice a line.
- APFS Unicode-normalization equivalence is documented, not folded.
  Folding can make two different names the same file.
- `**/.ssh/**` still does not match the `.ssh` directory itself. The
  docs now show `deny **/.ssh` as well. The `**` rule is unchanged.
- One zift process does not see another process's staging registry.
  Two daemons on the same partner root can still sweep each other's
  old uploads.

## What held up

No work queued. Recorded so a later pass does not re-file them.

- The jail walk is fd-relative and `O_NOFOLLOW` on every component a
  partner names. `..` is collapsed before the walk. Final-component
  symlinks are refused.
- `write` does not imply `update`, and publish re-checks that under
  the namespace mutex with a no-replace rename.
- `deny` wins regardless of order, and an over-budget glob fails
  closed.
- Password denial of an unknown user, a key-only user, and a `from`
  miss each pay one Argon2id. The digest compare is constant-time.
- A session keeps a refcounted config snapshot across reload, so a
  reload does not free a config a worker is still using.
- Audit encoding stops a partner filename from breaking the JSON line.
- IPv4-mapped peers match IPv4 `from` rules, including the
  uncompressed form the audit logger writes.
