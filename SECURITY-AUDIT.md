# Zift Security Audit

Focused manual audit of every module on the remote trust boundary. Findings
are categorized as **OK** (verified safe), **CAVEAT** (acceptable with
documented trade-off), or **FINDING** (actionable issue with recommended fix).

---

## 1. session.zig — Remote Attack Surface

### Accept loop and connection management

- **OK**: `poll()` with 1-second slices keeps the accept loop responsive to
  signals without blocking indefinitely on `ssh_bind_accept`.
- **OK**: `max-connections` enforced post-accept with immediate disconnect and
  audit line for rejected connections.
- **OK**: Listening socket closed immediately at drain start (`std.c.close(bind_fd)`)
  so no new TCP connections land during grace period. PLAN §7.1.
- **CAVEAT**: `max-connections` is a single global cap covering both
  pre-auth and post-auth sessions. The `idle-timeout` on pre-auth
  sessions reaps stuck slots within the timeout window so the cap
  remains meaningful under handshake-storm pressure, but a future
  enhancement should split it into independent pre-auth and post-auth
  limits and track each via a separate atomic counter. Tracked in
  TODOS.md as a P1.

### SSH handshake and authentication

- **OK**: `setSessionTimeout` applies `SSH_OPTIONS_TIMEOUT` before
  `ssh_handle_key_exchange`, so TCP-only "clients" that never speak SSH are
  reaped within `idle-timeout`.
- **OK**: Password auth uses `auth.verifyLogin` with dummy Argon2id verification
  for unknown users, masking timing differences. PLAN §8.4.
- **OK**: `max_auth_attempts = 6` matches OpenSSH `MaxAuthTries` default.
  Pubkey "offered" probes do not consume attempts.
- **CAVEAT**: `pk_ok` reveals whether a (user, key) pair is configured. This is
  inherent to the SSH protocol's two-phase pubkey flow. Documented as an
  explicit caveat rather than a code fix.
- **FINDING (low)**: `matchesAnyConfiguredKey` reparses each configured key blob
  via `ssh_pki_import_pubkey_base64` on every auth attempt, allocating with
  `page_allocator`. Functionally correct but wastes CPU and memory under
  auth-storm conditions. **Recommended**: parse keys once at config load, cache
  the libssh key handle on `UserConfig`, free at config dispose.

### SFTP packet parsing

- **OK**: `readPacketTimed` reads a 4-byte length prefix, then rejects frames
  exceeding the 256 KiB cap with `SSH_FX_BAD_MESSAGE` before disconnecting.
- **OK**: `parseString` checks `payload.len < 4` and `payload.len < 4 + len`
  before slicing. No integer overflow risk on the 64-bit targets we
  ship (PLAN §4.7 lists Linux x86_64 / aarch64 and macOS x86_64 / aarch64
  as the supported set); on a hypothetical 32-bit target the `4 + len`
  expression in `usize` would still bound-check correctly because both
  operands are `usize` and the SFTP `length` field cannot exceed the
  packet cap (256 KiB) before `readPacketTimed` rejects it.
- **OK**: `readU32` / `readU64` operate on fixed-size slices passed by callers
  after length checks. No out-of-bounds risk.
- **OK**: `parseHandleId` validates the handle string is exactly 4 bytes.
- **OK**: Every handler that takes a client path calls `ensureValidPath` (which
  calls `Vfs.validateVirtualPath`) before policy or filesystem operations.

### SFTP dispatch and handle management

- **OK**: All unsupported opcodes (`SETSTAT`, `FSETSTAT`, `READLINK`, `SYMLINK`,
  `EXTENDED`, unknown) reply `SSH_FX_OP_UNSUPPORTED` and the session continues.
- **OK**: `Handle.can_read` / `can_write` / `is_append` are set at OPEN time
  from the SFTP flag bitmask and enforced at every READ/WRITE.
- **OK**: Append mode uses stat+pwrite to write at end-of-file. Single-threaded
  per-session semantics make the stat-then-write window safe within Zift's
  model.
- **OK**: `handleClose` clears the dir/file on the handle, preventing
  double-close.
- **CAVEAT**: `nextHandleId` is a simple incrementing `u32`. It will wrap after
  ~4 billion operations per session. Not a practical concern for SFTP sessions.

---

## 2. vfs.zig — Path Jail

- **OK**: `normalizeVirtualPath` rejects NUL, C0 controls, DEL, and invalid
  UTF-8 before any allocation. Paths exceeding 4096 bytes are rejected.
- **OK**: `..` traversal above root returns `error.PathTraversal` during
  normalization (not just at the filesystem layer).
- **OK**: `resolveExisting` canonicalizes via `realPathFileAbsoluteAlloc` and
  checks `isInsideRoot` on the canonical result.
- **OK**: `openVerifiedParent` opens the parent directory as an fd, verifies it
  via `verifyDir` (reads back fd's real path), then returns the fd + basename.
  All mutation operations (mkdir, remove, rename) operate relative to this
  verified parent fd.
- **OK**: `resolveForCreate` validates the basename is not `.` or `..`.
- **OK**: `isInsideRoot` checks at a path-component boundary (`/`) to prevent
  `/foo` matching `/foobar`.
- **OK**: `handleOpen` uses `follow_symlinks = false` on the basename, so a
  symlink at the final component is rejected. Belt-and-suspenders `verifyFile`
  runs post-open.
- **OK**: Truncation (`setLength(0)`) runs only after `verifyFile` confirms the
  fd is inside the jail.

---

## 3. config.zig — Config Parser

- **OK**: Line-oriented, indentation-based grammar with no expression language,
  no includes, no interpolation. Attack surface is minimal.
- **OK**: Inline comments (`#` after a value) are rejected as `InlineComment`.
- **OK**: Username max 64 bytes, key line max 8192 bytes, enforced at parse time.
- **OK**: Duplicate users rejected. Duplicate `server` section rejected.
- **OK**: Argon2id PHC strings validated for `v=19`, `m`/`t`/`p` parameters
  within the policy envelope, salt and hash field presence, base64 validity
  of salt and hash, and no extra `$` segments.
- **OK**: Public-key blobs validated as strict base64 at parse time.
- **OK**: `validateSemantic` canonicalizes user roots via
  `realPathFileAbsoluteAlloc` and rejects overlapping roots using `isInsideRoot`.
- **OK**: Host-key readability checked at validate/startup/reload time.

---

## 4. auth.zig — Credential Verification

- **OK**: `verifyPassword` delegates to `std.crypto.pwhash.argon2.strVerify`.
  No hand-rolled crypto.
- **OK**: `verifyLogin` runs dummy Argon2id verification for unknown users.
  The dummy hash is computed once (lazy-init under mutex) and reused; the
  *verification* runs every call.
- **OK**: Dummy hash uses `dummy_params` (upper bound of the policy envelope)
  so verification time always matches or exceeds any real user's hash.
- **OK**: `ensureDummyHash` uses double-checked locking with acquire/release
  atomics for thread-safe lazy initialization.

---

## 5. policy.zig — Authorization

- **OK**: Default deny. Explicit `allow` rules grant specific permissions;
  `deny` rules override `allow` unconditionally.
- **OK**: `literalPrefixMatch` checks at path-component boundaries.
  `/pending` does not match `/pendingfoo`.
- **OK**: Glob `*` does not cross `/` boundaries. `?` does not match `/`.
- **OK**: `checkRename` evaluates policy on both source and destination paths.
- **CAVEAT**: Glob matching is recursive. A pathological pattern like
  `*****...` against a long path could be expensive, but the 4096-byte path
  limit and the restricted pattern syntax (`*` and `?` only, no `**`) bound
  the practical cost.

---

## 6. audit.zig — Structured Logging

- **OK**: JSON field order matches PLAN §7.4 stable schema.
- **OK**: `encodeJsonString` from `std.json` handles all JSON-special characters.
- **OK**: 4096-byte line cap with 4-tier truncation fallback that preserves
  required fields (event, operation, result, ip) and emits `"truncated":true`.
- **OK**: Write-failure rate-limited to one stderr warning per 5 seconds via
  `last_warn_ms` atomic.
- **OK**: File destinations opened with `O_APPEND | O_CREAT | O_CLOEXEC`.
- **OK**: Mutex serializes all writes so JSON objects never interleave.
- **OK**: SIGUSR1 reopen handled via atomic fd swap under the write mutex.
- **CAVEAT**: Audit is not fail-closed. A hung audit destination (NFS mount,
  full disk) delays the next audit line for that worker thread but does not
  block client replies (audit runs via `defer` after reply). Operators who
  need fail-closed audit should monitor the log sink externally.

---

## 7. signals.zig — Signal and Lifecycle State

- **OK**: All signal handlers only set atomic flags. No heap allocation, no
  locks, no I/O in signal context.
- **OK**: `SA_RESTART` set on all handlers so libssh reads inside worker
  threads are not interrupted.
- **OK**: `forceCloseAll` iterates the session fd registry and calls
  `shutdown(fd, SHUT_RDWR)` on each. Workers' blocked reads return; deferred
  cleanup chains run.
- **OK**: `registerSessionFd` / `unregisterSessionFd` are mutex-protected.
  The accept thread only iterates after the accept loop has exited, so
  there is no register-during-iterate race.

---

## 8. Reload Behavior (session.zig ActiveConfig)

- **OK**: Config reload is refcounted. Live sessions hold their own `ConfigRef`;
  a reload swaps in a new snapshot without touching active sessions.
- **OK**: Reload only triggers when mtime moves forward. Atomic-deploy patterns
  that rewind mtime do not cause unexpected reloads.
- **OK**: Config file stat failures are warned once (transition-based) and the
  previous config keeps serving.
- **OK**: `validateSemantic` runs on reload; a bad config is rejected with a
  stderr warning and the previous config continues.

---

## Summary

| Module | Findings |
|--------|----------|
| session.zig | 1 low (key reparsing per attempt) + 1 caveat (single cap) |
| vfs.zig | 0 |
| config.zig | 0 |
| auth.zig | 0 |
| policy.zig | 0 |
| audit.zig | 0 (1 caveat: not fail-closed by design) |
| signals.zig | 0 |
| reload | 0 |

**Overall assessment**: The codebase is in good shape for public exposure
on a port-2222-style deployment with partner IP allowlisting. The
remaining P1 items tracked in TODOS.md — pre-parsing public keys at
config load, splitting `max-connections` into pre-auth and post-auth
caps, and a static-link / signed-release pipeline — are operational
hardenings rather than known security defects in the runtime path.

**This audit is a snapshot.** It should be re-run before any release
that touches `session.zig`, `vfs.zig`, `config.zig`, or `auth.zig`,
and after any change to the SFTP wire surface.
