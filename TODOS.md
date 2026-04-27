# Zift TODOs

Living gap list between the implementation and PLAN.md. Reviewed jointly by the in-Cursor agent (Claude Opus) and the peer agent (GPT-5.5) on 2026-04-26 against the current `main` branch.

Conventions:

- One bullet = one actionable task. Tick the box when it lands.
- When a bullet completes, move it (preserving its `[x]` state and citation) to `## DONE` at the top.
- Keep PLAN.md citations on every bullet so we can re-derive intent if the issue resurfaces.
- Severity: **P0** = production blocker, **P1** = major spec gap, **P2** = polish/ergonomics, **P3** = nit/bikeshed.
- The "Disputed" section lists items the peer review raised that we deliberately do not accept; they live there for the record.

---

## DONE

- [x] Build scaffold: Zig 0.16, libssh 0.12 via translateC, build_options module, `.gitignore`.
- [x] Config DSL parser: indentation-based grammar, `server` and `user` sections, `allow`/`deny` rules, `password` PHC validation, `key` ed25519/ECDSA validation, line-oriented errors at the file level (PLAN §6.2, §6.3).
- [x] Argon2id parameter envelope enforcement (m: 64–256 MiB, t: 2–8, p: 1–4) with rejection at parse time (PLAN §8.4).
- [x] Argon2id dummy-hash path for unknown users using upper-bound parameters (PLAN §8.4).
- [x] Path jail: `normalizeVirtualPath`, `joinRoot`, `isInsideRoot`, `verifyFile`/`verifyDir` post-open FD verification, `openVerifiedParent` for TOCTOU-safe mutations (PLAN §8.3).
- [x] Policy engine with literal-prefix and `*`/`?` matchers respecting `/` boundaries (PLAN §6.3).
- [x] SFTP v3 raw framing over libssh: `INIT` → `VERSION`, `REALPATH`, `STAT`/`LSTAT`, `OPENDIR`/`READDIR`, `OPEN`/`READ`/`WRITE`/`CLOSE`, `MKDIR`/`REMOVE`/`RMDIR`/`RENAME`.
- [x] `REALPATH` echoes the client's normalized virtual path (PLAN §7.6).
- [x] Public-key authentication, two-phase libssh flow, ed25519 + ECDSA only, RSA/DSA rejected at config load (PLAN §8.4).
- [x] mtime-based config reload with refcounted immutable snapshots, sessions hold their own snapshot for life (PLAN §7.3).
- [x] Thread-per-connection with detached worker threads (PLAN §7.5).
- [x] Audit JSON to stderr: stable field order, JSON-string escaping for path/detail (PLAN §8.5).
- [x] CLI: `zift serve <config>`, `zift validate <config>`, `zift hash-password`, `zift version` (PLAN §4.8).
- [x] Operational signal cluster: `SIGTERM`/`SIGINT` → graceful drain with 30s grace cap, `SIGHUP` → forced reload regardless of mtime, `SIGUSR1` → flag (consumer pending), `SIGPIPE` → ignored (PLAN §7.2).
- [x] `idle-timeout` enforced at the SFTP read loop with `idle.timeout` audit line (PLAN §6.2).
- [x] `max-connections` enforced post-accept with `accept` denial audit line (PLAN §6.2).
- [x] Accept loop driven by `poll(bind_fd)` so signals are visible within ~1 second.
- [x] **Integration test harness** (`test/`): bash runner, paramiko venv, per-test scratch dir + unique TCP port, `bg`/`wait_bg` helpers that don't conflict with the backgrounded zift, baseline coverage for smoke/idle-timeout/max-connections/SIGHUP/SIGTERM. Each case starts with `# Test: …` so `test/run.sh --list` is self-documenting.
- [x] **Per-handle access mode tracking** (`session.zig` `Handle.can_read`/`can_write`). OPEN parses the SFTP flag bitmask precisely (READ/WRITE/APPEND/CREAT/TRUNC), gates BOTH `.open_read` and `.open_write` policies if both bits are requested, and stamps the resulting access on the handle. `handleRead`/`handleWrite` now return `SSH_FX_PERMISSION_DENIED` with `read|write result=denied` audit lines when the handle lacks the bit. PLAN §6.3. Regression: `test/cases/10-handle-access-mode.sh` (paramiko probe).
- [x] **Symlink-escape closed in `SSH_FXP_OPEN`** (`session.zig` `handleOpen`). Replaced the path-string `createFile`-then-verify pattern with FD-relative open via `openVerifiedParent` plus `follow_symlinks = false` on the basename, post-open `verifyFile` belt-and-suspenders, and deferred truncation (`file.setLength(0)` runs *only* after verification). `SSH_FXF_CREAT` uses `exclusive=true` for race-free creation; `SSH_FXF_EXCL` and `SSH_FXF_TRUNC` honored explicitly. A symlink at the final component now returns `SSH_FX_PERMISSION_DENIED` and never modifies the target. PLAN §8.3. Regression: `test/cases/11-symlink-escape.sh` (oracle = byte-exact comparison of an outside-jail file before vs after the attack).
- [x] **SFTP wire surface matches PLAN §7.6** (`session.zig` dispatch + new `handleFstat` + 256 KiB packet buffer). Three concerns in one change. (a) Explicit cases for `SSH_FXP_SETSTAT`, `FSETSTAT`, `READLINK`, `SYMLINK`, `EXTENDED` reply `SSH_FX_OP_UNSUPPORTED` instead of the previous catch-all `SSH_FX_FAILURE`. The default arm (truly unknown opcode) also replies `OP_UNSUPPORTED` per PLAN — the session continues, no disconnect. Clients (rsync, `scp -p`, paramiko's chmod/symlink/readlink) now see "this op isn't supported" rather than "I tried and broke", which lets them fall back gracefully. (b) `SSH_FXP_FSTAT` implemented via `handle.file.?.stat()`. PLAN §7.6: "Inherits the open's permission" — no policy check at FSTAT time because OPEN already gated `.open_read`/`.open_write`. (c) SFTP packet buffer bumped from 8 KiB stack array to 256 KiB heap allocation (one per session, freed at session exit). PLAN §7.6 limit. Frames declaring length > 256 KiB are rejected as malformed and the session is torn down. Regression: `test/cases/18-sftp-wire-surface.sh` (paramiko-based raw-protocol probe with six scenarios: setstat/readlink/symlink/extended/unknown all reply OP_UNSUPPORTED; fstat returns valid attrs).
- [x] **Audit emits AFTER reply** (PLAN §8.5). Every SftpState handler now does `defer self.auditXxx(...); return replyStatus(...);` so the client gets its status reply on the wire before the audit syscall runs. A hung audit destination (file on a stalled NFS mount, FIFO with no reader, etc.) cannot delay the client's reply — it can only delay the next audit line for that worker thread. The change is a 1-line addition per call site (~30 sites across `handleStat`, `handleOpendir`, `handleOpen`, `handleRead`/`Write`, `handleMkdir`/`Remove`/`Rmdir`/`Rename`); no functional behavior visible to clients in the happy path, but the timing contract from PLAN now holds.
- [x] **Audit pipeline overhaul** (`audit.zig` rewrite + `session.zig` peer-IP capture + `main.zig` wiring + `config.zig` parser strictness). Single coherent change closes five P1 bullets. (a) `LogTarget.file` actually writes to a file: `Sink.initFromConfig` opens the path with `O_WRONLY|O_APPEND|O_CREAT|O_CLOEXEC` and stores the fd; the global singleton is initialized in `serve` after `validateSemantic`. (b) `SIGUSR1` reopen consumer: `Sink.maybeReopen` runs before every write, swaps in a fresh fd, closes the old one — full logrotate "rename old, signal, recreate" cycle works. (c) `ip` field always present: peer IP captured in `handleSession` via `getpeername` on `ssh_get_fd(session)`, threaded through `authenticate`/`handlePublicKeyMessage`/`runSftp`/`SftpState`, plus a fresh capture for the accept-loop max-connections denial. PLAN §7.4 stable order honored: `event, user, operation, result, path, detail, ip, [truncated]`. (d) Truncation: 4-tier predictive fallback (full → detail-clipped → no-path → minimal-with-ip) so over-budget lines preserve required PLAN fields and emit `"truncated":true`; never silently drops content. (e) Single-syscall writes: `std.c.write(fd, ptr, len)` for both stderr (`fd=2`) and file destinations, no `writeStreamingAll`. Rejects relative `log` paths at parse time (PLAN §7.4 absolute-only). Regressions: `15-audit-ip-field`, `16-audit-file-target`, `17-audit-sigusr1-reopen` (3 new cases, all green).
- [x] **Forced-close on grace expiration is server-driven** (`signals.{registerSessionFd,unregisterSessionFd,forceCloseAll}`). Workers register their TCP socket FD on entry and unregister on exit. When the SIGTERM/SIGINT drain wall expires, the accept thread iterates the registry and calls `shutdown(fd, SHUT_RDWR)` on every still-live session. The worker's blocked libssh read returns, the deferred cleanup chain runs (audit line, `active_sessions` decrement, ref release), and the process exits zero — the contract PLAN §7.1 makes, instead of relying on kernel-reap-on-process-exit. New `shutdown-grace` server-config knob (default 30 s, also exposed for fast integration tests). Regression: `test/cases/14-forced-close.sh` (sabotage-tested for discrimination — sabotaged code FAILs, real code PASSes).
- [x] **`zift validate` does full semantic validation** (`config.validateSemantic`). One pass that runs against the live filesystem and is shared by `zift validate`, `serve` startup, and the runtime reload path: rejects an unreadable `host-key`, rejects any user `root` that's missing or not a directory, and rejects two users whose canonicalized roots are equal or path-component-prefixes of each other. Roots are canonicalized via `realPathFileAbsoluteAlloc` so `vfs.isInsideRoot` (now `pub`) is reused for the overlap check, matching the same semantics the per-request jail uses. Diagnostics name the offending user(s) and path(s). PLAN §6.2. Closes the "validate is parse-only", "roots not canonicalized at config load", and "overlapping roots not rejected" P0s. Regression: `test/cases/13-validate-semantic.sh` (seven sub-scenarios — happy path, missing root, root-is-a-file, unreadable host-key, prefix overlap, equal roots, plus a check that `serve` refuses to start with a missing root).
- [x] **Pre-auth idle timeout enforced** (`session.zig` `setSessionTimeout`). `SSH_OPTIONS_TIMEOUT` and `SSH_OPTIONS_TIMEOUT_USEC` set on each session before `ssh_handle_key_exchange`, so libssh's blocking reads during banner exchange / KEX / USERAUTH / subsystem-open all respect the configured idle-timeout. `idle_timeout_ms == 0` disables the cap (PLAN §6.2). A new `handshake.failed` audit line gives operators visibility into pre-auth slot churn. This single change closes the "no idle timeout pre-auth" P0 *and* the "max-connections doesn't bound pre-auth" P0: stuck pre-auth slots are now reaped within the timeout window, so the slot count remains a meaningful cap under attack. Regression: `test/cases/12-pre-auth-idle.sh` (`max-connections=1`, stuck Python TCP client, oracle = does a legit `sftp` client land within `idle-timeout + slack`).

---

## P0 — Blockers

These break a security promise PLAN.md makes by name. None of them is shippable as-is.

- [ ] **`SSH_FXF_APPEND` is not yet honored.** Post-symlink-fix `handleOpen` parses the APPEND bit (it contributes to `want_write`) but doesn't translate it into per-write append behavior. `handleWrite` always uses `writePositionalAll(offset)`, ignoring whether the open requested APPEND mode. PLAN §7.6 commits to ordinary SFTP v3 semantics. Fix: track `is_append` on the handle and route writes through an append-aware writer (or `pwrite` with `lseek(SEEK_END)`).
_(no remaining P0 entries — all closed)_

---

## P1 — Major

PLAN.md promises that the code does not yet keep, but no immediate security regression.

### Audit pipeline

_(Audit pipeline overhaul landed: see DONE entries below.)_
- [ ] **Audit write-failure warning is not actually rate-limited** despite the comment. `audit.zig:warnWriteFailure` writes one stderr line per failure. Add a per-second / per-100-line dampener with a `last_warn_ms` field on `Sink` (already commented) so a runaway destination can't itself cause a stderr storm.

### Config parser & validator

- [ ] **Username length not enforced.** PLAN §6.2 says max 64 bytes. `config.zig` accepts arbitrarily long usernames. Fix: reject during `user` line parse with a line-numbered error.
- [ ] **Public-key line length not enforced.** PLAN §6.2 says max 8192 bytes per `key` value. Fix: reject during property parse.
- [ ] **Path length not enforced.** PLAN §6.2 says max virtual-path length is 4096 bytes. `vfs.zig:143` accepts any length. Fix: in `normalizeVirtualPath`, reject `virtual_path.len > 4096` up-front. Apply to incoming SFTP path strings as well (consistency: same limit, same error surface).
- [ ] **Path validation accepts ASCII control bytes and invalid UTF-8.** `vfs.zig:144` rejects only NUL. PLAN §8.3 says no NUL, no `0x01–0x1F`, no `0x7F`, valid UTF-8. Fix: pre-scan for control bytes and `std.unicode.utf8ValidateSlice` before normalization.
- [ ] **Public-key blob is not validated at config load.** `config.zig` accepts the algorithm but not the base64 blob. PLAN §8.4 says malformed key lines are rejected at parse time so config-with-bad-key never goes live. Fix: base64-decode the blob during parse; reject if invalid or if the embedded algorithm string disagrees with the prefix.
- [ ] **PHC parser is hand-rolled and partial.** `config.zig:149` doesn't validate `v=19`, encoded salt/hash field syntax, or extra `$` segments. Fix: route through `std.crypto.pwhash.argon2.strVerify` parsing primitives, or a dedicated `auth.zig` PHC validator with full coverage; centralize the error type.
- [ ] **Reload errors are unstructured.** `session.zig:244-256` prints `@errorName(err)` only. PLAN §6.2/§7.3 say config errors identify file, line, section/user, and key. Fix: introduce `ConfigError { line: u32, user: ?[]const u8, key: ?[]const u8, reason: enum }` and route every parser/validator failure through it.
- [ ] **Parser tracks no line numbers.** `config.zig:183` line-loops without per-line context. PLAN §6.2 expects line-level diagnostics. Fix: lex into `{line_no, indent, body}` first, then parse.
- [ ] **`reload-interval` is hardcoded in the accept loop.** `session.zig` polls every 1000 ms regardless of `cfg.server.reload_interval_ms`. PLAN §7.3 says polling interval is `reload-interval`, default 2 s, **and `0` disables runtime mtime polling** (SIGHUP still works). Fix: read `reload_interval_ms` from the active config; skip the mtime check when 0.
- [ ] **Reload triggers on any mtime inequality.** `session.zig:131` reloads when `mtime != known_mtime`. PLAN §7.3 says reload triggers when mtime moves forward; rewound mtimes (atomic-swap deploys) require SIGHUP. Fix: change to `mtime > known_mtime`. SIGHUP path already uses `forceReload` so it's unaffected.
- [ ] **Failed mtime stat silently aborts the iteration.** `session.zig:130` does `currentConfigMtime(...) catch return`. PLAN §7.3 says deleted/unreadable config logs a single warning and keeps the previous config. Fix: log the warning on first failure, suppress repeats until the file becomes readable again.
- [ ] **`log` accepts non-absolute file paths.** `config.zig:272` accepts any non-empty value. PLAN §7.4 says `log` is `stderr` or an absolute path. Fix: reject relative paths during parse.
- [ ] **Bare-number durations are accepted as milliseconds.** `config.zig`'s `parseDurationMs` accepts `300` as 300 ms. PLAN §6.2 documents `s`/`m`/`h` suffixes only. Fix: require a suffix; reject bare numbers with a line-numbered error.
- [ ] **Inline `#` comments are accepted.** `config.zig:372` strips `#…` from anywhere in a line. PLAN §6.2 grammar allows only whole-line comments. Fix: only treat `#` as a comment when it is the first non-whitespace character.
- [ ] **Reload doesn't validate host-key readability.** A new config that points at a missing/unreadable host-key file passes reload. PLAN §7.3 says the running listener keeps its host key but reload should still reject incoherent configs. Fix: in `config.validate`, stat the host-key path.

### SFTP protocol surface

_(Wire-surface protocol items landed: see DONE entries below.)_

- [ ] **Oversize-packet handling could be more graceful.** `readPacketTimed` rejects frames declaring length > 256 KiB by returning `error.LibsshFailure`, which tears the session down. PLAN §7.6's preferred behavior is to reply `SSH_FX_BAD_MESSAGE` and continue unless malformed traffic persists. We can't reply for the oversize frame itself (no request_id available without reading the body), so a small refinement would be: read 5 bytes (msg_type + request_id), reply `BAD_MESSAGE`, then disconnect. Currently we just disconnect — operationally fine, slightly less informative to the client.
- [ ] **STAT path is path-based, not FD-based.** `handleStat` (the LSTAT/STAT paths, NOT FSTAT) does `resolveExisting` + `statFile(real)`; the real-path string is the authorization artifact, not an FD. PLAN §8.3 disallows string-layer TOCTOU defense. Fix: same pattern the symlink-escape commit used for OPEN — `openVerifiedParent` + `openFile(.follow_symlinks = false, .path_only = true)` for the metadata path, `verifyFile`, `file.stat()`, close. (FSTAT is already FD-based by definition; this only applies to STAT/LSTAT.)

### Authentication

- [ ] **Pubkey auth for unknown users returns immediately.** `session.zig:413-450` short-circuits to deny when `cfg.findUser(username)` is null. Pubkey path doesn't run dummy work. PLAN §8.4 ("unknown-user timing should not reveal existence") covers both auth methods. Fix: dummy ECDSA/Ed25519 verify against a fixed throwaway key when the user is unknown; same applies to known users with no `keys`.
- [ ] **`pk_ok` reveals whether (user, key) is configured.** `session.zig` follows libssh's two-phase pubkey flow honestly: `pk_ok` only fires for valid pairs. PLAN §8.4 promises auth doesn't reveal user existence; SSH protocol itself fights this. Fix options: (a) accept the leak and document it explicitly in PLAN as an SSH-protocol-level caveat, or (b) emit `pk_ok` to *every* known username regardless of key match (still rejects at the signed-response phase). Pick one and write it down.
- [ ] **Dummy hash is recomputed every unknown-user attempt.** `auth.zig:67-71` hashes "zift-dummy-password" on the fly. The work *is* the timing property, so this is correct under high-cost params, but it's also pure waste. Fix: lazy-init a process-global dummy PHC string at startup using `dummy_params`, then `strVerify` against it. Same timing, lower allocator pressure.
- [ ] **Per-connection auth attempt limit is missing.** PLAN §8.4 implies finite attempts; current code lets a client cycle USERAUTH messages indefinitely until idle-timeout (which is also currently absent pre-SFTP). Fix: cap attempts at 6 (or whatever PLAN ratifies) and disconnect with audit on overage.
- [ ] **Public-key matching reparses keys on every attempt.** `session.zig:matchesAnyConfiguredKey` decodes each configured key on every try. Fix: parse once at config load, store a libssh-keypair handle (or equivalent canonical form) on `UserConfig`, free at config dispose.
- [ ] **Pubkey matching uses `std.heap.page_allocator` inside auth.** PLAN's discipline (§5) is "no global allocator." Fix: thread the session allocator through `matchesAnyConfiguredKey`; better yet, eliminate the allocation by parsing once at config load.

### Operational

- [ ] **No tracking of unauthenticated vs. SFTP-authenticated session counts.** `signals.active_sessions` counts both. PLAN §8.4 implies pre-auth slots are bounded separately so an auth-storm can't DoS the legit-user slot pool. Fix: add `unauth_sessions` and `sftp_sessions` atomics; cap each independently (the totals can share a single config knob until that proves insufficient).
- [ ] **Drain doesn't drop the listening socket.** When SIGTERM arrives we exit the accept loop but don't `close` the bind fd until `defer ssh_bind_free` runs at function return. New TCP connections during the 30-s drain race the bind being torn down. PLAN §7.1 says the listener is closed first. Fix: explicitly close the listening fd at the top of the drain block.
- [ ] **Operational status (startup, "listening on …", reload notices) goes to stdout.** `main.zig:88, 99` and `session.zig:73` write to `std.Io.File.stdout()`. PLAN §7.4 says human-readable diagnostics go to stderr; stdout is reserved for things like `hash-password` output. Fix: swap to stderr.

### Build & release

- [ ] **`build.zig` hardcodes Homebrew paths.** `/opt/homebrew/include`, `/opt/homebrew/lib`, RPATH. PLAN §13 promises macOS releases have no Homebrew runtime dependency and Linux releases are static against musl + vendored libssh + libcrypto. Fix: keep current path as a development convenience behind a `-Dbrew=true` flag; add a `release` target that fetches/builds libssh and libcrypto via `build.zig.zon` packages and links statically on Linux, vendored on macOS.
- [ ] **No release target, no SHA256 manifest, no signature step.** PLAN §13 lists those as deliverables. Fix: `zig build release` produces `zift-{version}-{target}` binaries + `SHA256SUMS` + `SHA256SUMS.asc`; CI reproduces deterministically.
- [ ] **No integration test harness.** Tests are `zig build test` only. PLAN §12 promises real-client (`sftp`/`lftp`/`paramiko`/`golang.org/x/crypto/ssh`) integration, malformed-packet probes, reload-during-session, parallel load, idle-timeout, symlink-escape. Fix: add a `tests/integration/` directory with a launcher script that builds the binary, spins it up against a tmp-dir fixture, runs each scenario, and tears down. Wire to `zig build test-integration`.
- [ ] **No fuzz targets.** PLAN §12 promises fuzz tests for the config parser and the SFTP packet parser. Fix: add fuzz entrypoints under `tests/fuzz/`; document the harness (`afl++` / Zig's built-in fuzzer when available).
- [ ] **No CI configuration in-repo.** Fix: add `.github/workflows/ci.yml` (or equivalent) running `zig build test`, `zig build test-integration`, and a `ReleaseSafe` build.
- [ ] **No static-link verification.** Fix: post-release CI step runs `ldd zift` (or `otool -L`) on the published artifact and asserts the expected set of dynamic dependencies (none on Linux, system frameworks only on macOS).

---

## P2 — Minor / Polish

- [ ] **`ConfigRef` lifetime is correct but untested under load.** PLAN §7.3 mandates that an existing session keeps its old config alive across reloads. Add a stress test: 32 concurrent sessions, hammer config reloads on a separate thread, observe no use-after-free / double-free.
- [ ] **`active_sessions` lives in `signals.zig`.** It isn't signal state. Move to a `server_state.zig` or attach to `ActiveConfig`.
- [ ] **`channel` cleanup on session exit.** `handleSession` doesn't explicitly `ssh_channel_send_eof` / `ssh_channel_close` / `ssh_channel_free`. We removed an explicit close earlier because of a segfault, but the right fix is to call EOF + close + free in a single defer, in the right order.
- [ ] **`hash-password` writes a `password: ` prompt to stderr.** PLAN §11.3 wants the utility to be cleanly scriptable. Fix: drop the prompt; if a TTY is attached, echo a one-liner to stderr explaining what's expected.
- [ ] **Successful pubkey audit logs `user.keys[0].algorithm` instead of the matched key.** Fix: have `matchesAnyConfiguredKey` return the matched index (or fingerprint); audit that.
- [ ] **Reload poll cadence is coupled to accept readiness.** Fix: compute a `next_reload_ms` deadline; when poll wakes (timeout or accept), check whether we've crossed it.
- [ ] **`max-connections` audit line uses `operation: "accept"`.** Renaming to `accept.rejected` is a one-line change that gives `jq` users a stable filter. Bikeshed but cheap.

---

## P3 — Nits

- [ ] **`read`/`write` SFTP messages are not individually audited.** PLAN §8.5 reads as "every privileged operation"; we treat OPEN as the privileged step (audit happens there) and consider subsequent read/write within an authorized handle non-privileged. If we change our mind, audit at `READ`/`WRITE` would log-storm normal transfers; pre-decision is intentional. **Disputed by GPT-5.5; we'd document this explicitly in PLAN rather than start auditing every chunk.**
- [ ] **`REALPATH`, `STAT`, `LSTAT`, `READDIR` aren't audited.** Same reasoning as above — these don't mutate state and don't reveal content. **Disputed by GPT-5.5; we'd audit only failures, not successes, if we audit at all.**
- [ ] **`SA_RESTART` set on operational signal handlers.** GPT-5.5 flagged this; deliberately chosen because the accept loop polls with 1-second slices and we don't want to interrupt syscalls inside libssh. Documenting the choice rather than reverting it.
- [ ] **`std.posix.sigaction` "return value ignored" claim.** In Zig 0.16 the function returns `void` and is `unreachable` on EINVAL — there is no return value to check. GPT-5.5 misread; no action needed.

---

## Disputed / Won't fix

- **"Audit every READ/WRITE"** — see P3 entry. PLAN can be amended to say "OPEN audits the privilege; subsequent chunks aren't separately audited." We prefer that to log-storming.
- **"Audit every REALPATH/STAT/LSTAT"** — same reasoning. Failures may be worth auditing if they're frequent enough to indicate probing; success isn't.
- **"Build hardcodes /opt/homebrew is a blocker"** — only as a *release* concern. Development builds against system libssh are fine; the release pipeline will vendor.
