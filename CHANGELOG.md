# Changelog

User-visible changes to Zift. Dates are those of the release commit.
Versions marked "untagged" were released from a commit, not a git tag.

## 0.12.0 — 2026-09-24

To upgrade, run `zift validate` on your config with the new binary, as
the service user (`sudo -u zift zift validate …`), before you restart.
It catches every breaking change below and names the line (or the
file) and the reason.

### Security

- A failed session's libssh error text was read after the session was
  freed, so heap bytes could reach stderr and the journal. Any peer
  could trigger it before login.
- Password checks are bounded. Each Argon2id check (64 MiB, real or
  dummy) takes one of clamp(CPU count, 2, 8) slots. Before, 60 parallel
  bad logins reached 3.9 GiB against the unit's `MemoryMax=4G`; a
  40-login flood now peaks near 520 MiB.
- Pre-auth connections are bounded:
  - a fixed 120 s login grace runs from accept to successful auth, key
    exchange included, and audits `auth.rejected` "login grace expired"
    (`handshake.failed` when it expires during key exchange);
  - each source may hold at most 8 pre-auth connections; extras are
    refused with `accept.rejected` "too many pre-auth connections from
    source";
  - `accept.rejected` lines are rate-limited to one per minute per
    source.
- Non-auth SSH messages count toward the 64-operation soft limit before
  login and before the SFTP subsystem starts. After it starts, extra
  channel opens and channel or global requests (`env`, `exec`,
  `pty-req`, `tcpip-forward`) are refused at once instead of queuing in
  memory without bound.
- A successful login no longer clears a source's failure count or
  suppression. Before, one valid account bought unlimited guesses
  against the others.
- Source suppression is checked inside authentication, and the session
  that trips it ends at once.
- Abuse tracking keys IPv6 sources by /64 (IPv4 by address).
- A public-key probe for a real user outside `from` looks the same to
  the client as one for an unknown user (for a user with keys; a
  password-only user is distinguishable, see "Method narrowing" in
  `docs/security.md`).
- Configs that failed open or checked the wrong file are now rejected:
  dead rule patterns, IPv6 `from` prefixes that match every IPv4 peer,
  loose or hard-linked host and key files, and a relative `host-key`.
  Each is under Breaking changes.
- READDIR listed the name, size and date of entries that STAT refused.
  It now hides every entry STAT of the same path would refuse, and names
  with control bytes or invalid UTF-8.
- Write-only partners get the same status for a missing and an existing
  parent or target on OPEN, MKDIR, REMOVE, RMDIR and RENAME.
- MKDIR no longer follows a symlink planted between the create and the
  chmod, which could have opened `.zift/staging` to group `zift`.
- `.zift` must be owned by the daemon's user or root, and `.zift/staging`
  by the daemon's user. The partner root is opened NOFOLLOW everywhere.
- Opening an existing FIFO, device or socket over SFTP fails at once
  instead of hanging the session. Only regular files open.
- The host key and key files are opened non-blocking, so a FIFO put in
  their place cannot hang a reload.
- `validate` refuses daemon-private files (host key, key files, audit
  log, the config itself) inside any partner root, including through a
  symlink.
- libssh no longer reads `/etc/ssh/libssh_server_config`; the Zift
  config is the only config.
- The audit log is opened NOFOLLOW, so a symlink at its path is refused.
  An audit FIFO with no reader no longer hangs startup or a SIGUSR1
  reopen.
- Audit strings escape C1 controls, DEL, U+2028, U+2029 and the bidi
  override and isolate characters as `\uXXXX`.
- `zift hash-password` rejects an empty password, and an empty password
  never authenticates.

### Breaking changes

- Patterns must be able to match: `deny *.exe` used to protect nothing.
  A pattern that does not start with `/` or `**`, ends in `/` (other
  than `/` itself), or contains `//`, `.`, `..` or a reserved
  `.zift`/`.zift-staging` component is `InvalidPattern`. Migration:
  `deny *.exe` becomes `deny /*.exe` (top level) or `deny **.exe` (any
  depth); `/dir/` becomes `/dir`.
- A single-valued directive given twice (`listen`, `host-key`, `root`,
  `log`, `partner-root`, `publish-mode`, `mkdir-mode`, durations and
  counts) is `DuplicateDirective`; the same `auth /path` twice for one
  user is `DuplicateKeyFile`. Migration: delete the stale copy.
- `max-connections 0`, a non-zero `idle-timeout` under 1s, a non-zero
  `reload-interval` under 100ms, and `_` digit separators are rejected.
  Migration: use `max-connections 1` or more, `0` to disable a timer,
  and plain digits.
- An unbracketed IPv6 `listen` (`::1:2222`), and a host with `*`, a
  blank or a `%` zone, is rejected. Migration: write `[::1]:2222`, or
  `:2222` for every IPv4 address. Bracketed forms now bind; before,
  they passed validate and failed at serve.
- `validate` checks more of what `serve` opens. The host key must load
  as an unencrypted private key, the log's directory must exist, an
  existing log must be a regular file, FIFO or character device (never
  a symlink), and each public-key blob must match its algorithm name,
  carry a sane RSA exponent and modulus or an uncompressed ECDSA point,
  and load in libssh as login would load it. Migration: fix what
  `validate` names.
- Error names changed. `InvalidConfig` became `MissingValue`,
  `InvalidNumber`, `InvalidMode`, `RelativePath` or
  `InvalidListingMode`; `MissingRulePattern` became `MissingValue`;
  `InlineComment` and `InvalidIndent` are gone; an over-long `auth
  /path` is `InvalidAuth`; `UnauthCapExceedsTotal` is a parse
  diagnostic naming its line. Migration: update any script that matches
  on the old names. Diagnostics now end with `: <reason>` and name the
  right line and user.
- A relative `root` or `host-key` is rejected at parse time. Before, a
  relative root aborted the daemon, and a relative host key was read
  from the cwd, so `validate` could check another file than `serve`
  under systemd (cwd `/`) loads. Migration: use an absolute path.
- An IPv6 `from` prefix under /96 that covers `::ffff:0:0/96` matched
  every IPv4 peer, and is now `InvalidFrom`. Migration: write
  `::ffff:203.0.113.0/24` as `203.0.113.0/24`; `::/0` still means any
  source.
- An `idle-timeout` over libssh's limit (2147483647 ms, about 24.8
  days) is rejected. Migration: use `24d` or less, or `0`.
- A host key that grants group-write, group-exec or any other access
  (`0644`, `0660`) is rejected, and so is a host key or key file owned by
  anyone but root or the daemon's user or with a second hard link.
  Migration: `chown root:zift`, `chmod 0640` (or `0600`), and copy
  instead of hard-linking.

### Added

- Trailing comments: `<whitespace># ...` ends a line. A `#` inside a
  token is literal (`root /srv/a#1`), and values may contain spaces
  (`root /srv/sp ace`), but never a blank followed by `#`.
- Symlinked `host-key` and `auth` key files. The target is checked
  (regular file, mode, owner), which fits Kubernetes Secrets and systemd
  credentials.
- `ssh-rsa` keys of 2048 to 8192 bits, verified only with `rsa-sha2-256`
  or `rsa-sha2-512` signatures. SHA-1 signatures, smaller RSA keys and
  DSA are rejected. libssh leaves a bad or SHA-1 signature unanswered,
  so such a client waits for its own timeout.
- `log` may be a FIFO or a character device such as `/dev/null`.
- `publish-mode` accepts any mode with owner `rw` and only read and
  write bits, without other-write (for example `0o644`; at most
  `0o664`). `mkdir-mode` accepts any mode with
  owner `rwx` and no other-write; setgid is allowed.
- SETSTAT and FSETSTAT set atime and mtime, so `put -p` and WinSCP's
  timestamp preservation work. SETSTAT needs `update`; FSETSTAT is
  allowed on the partner's own write handle. Mode and owner changes are
  accepted and ignored; size changes return OP_UNSUPPORTED. New audit
  operations `setstat` and `fsetstat`.
- Reload also triggers when an `auth` key file changes.
- A session that ends on an error is audited as `session.ended` with
  result `failed`.
- `tests/run.sh` honors `ZIFT_TEST_PORT_BASE` (default 22200).

### Changed

- When `max-unauth-connections` is unset it is max(1, max-connections /
  4), which is 32 at the default of 128. An explicit value, including 0
  (no separate cap), keeps its meaning.
- Reload triggers on any change to the size, mtime, ctime or inode of
  the config or of an `auth` key file, so a rewound mtime (`rsync -t`, a
  restore) reloads without SIGHUP. A rejected reload's audit event
  carries the reason, and reload re-checks that the config file lies
  outside every root.
- Policy matching runs in O(pattern × path) time, with no backtracking
  and no step budget; `?` matches one
  UTF-8 character; a policy path over 4096 bytes gets no permissions.
- `from ::ffff:a.b.c.d` matches plain IPv4 peers, and `from ::/0`
  matches IPv4 peers. IPv4-mapped peers are audited as plain IPv4.
- READDIR replies fill up to about 64 KiB instead of 16 entries, and
  READ returns up to 256 KiB − 13 bytes instead of 32 KiB. Large
  downloads and big listings are roughly twice as fast.
- One partner's namespace changes (mkdir, remove, rename, publish) no
  longer wait on another partner's.
- Status codes: only a missing entry, or a file used as a directory
  (`/file.txt/x`), is NO_SUCH_FILE. Running out of descriptors or
  memory and host permission errors are FAILURE, with the error name in
  the audit detail. Hitting the rename scan limit is FAILURE with detail
  `rename scan limit`. Status messages are the standard phrase for each
  code.
- A refused READ or WRITE is audited once per handle, with the path.
- `listing-mode virtual`: a file shows `w` only with both `write` and
  `update`; symlinks, FIFOs, sockets and devices show no permission
  bits. `listing-mode reality` resolves owners through a 64-entry cache;
  beyond it owners show as numbers.
- Auth backoff caps at 1.25 s, and the sixth hard failure disconnects
  without sleeping first. Pubkey probe exhaustion audits "probes".
- An over-long audit `detail` is clipped to fit instead of being
  replaced with `[truncated]`.
- Audit open failures name the path and errno. At startup: `zift:
  cannot open audit log <path>: <reason> (E…)`, then `zift: serve
  failed: AuditLogOpenFailed`. A failed SIGUSR1 reopen keeps the old log
  and retries every 5 s.
- CLI: `hash-password` hashes only the first line of stdin. A missing
  config prints `cannot read <path>: <reason>`; a parse error prints
  once; other startup failures print one `zift: serve failed: X` line.
- macOS gets the same TCP keepalive as Linux (60 s idle, 10 s interval,
  6 probes).
- systemd unit: `LimitNOFILE=65536` (the defaults need about 34,000
  fds), an explicit allowance for raising the soft fd limit, and a
  memory comment with the real arithmetic.
- Release binaries are stripped (x86_64-linux 10.3 MB → 1.9 MB,
  aarch64-macos 1.6 MB → 1.2 MB), so panics print addresses without
  symbols, and no build-host paths are embedded. The dev `zig build`
  binary is PIE. `zig build release` works from any directory and with
  `--prefix`, and a glibc Linux target fails at once, naming the
  `-linux-musl` target to use, and it no longer writes `SHA256SUMS-*`
  (the verify step prints the sha256). The version comes only from
  `build.zig.zon`; `default_version` in `build.zig` is gone.
- Releases are one archive per platform,
  `zift-vX.Y.Z-{linux-amd64,linux-arm64,osx-arm64,osx-amd64}.tar.gz`,
  holding the binary, its installer, `zift.service`, the README and the
  licenses, plus `zift-vX.Y.Z-checksums.txt` and its cosign bundle. This
  is the layout janus and harbor use. Bare binaries, `SHA256SUMS` and
  `zift-deploy-X.Y.Z.tar.gz` are gone.
- `install.sh` is the installer janus and harbor share. It no longer
  needs cosign: it checks the archive against the checksums file, as
  theirs do; verifying the signature is the by-hand path in
  `docs/operate.md`. The archive's own installer replaces the binary
  with an atomic rename that a failure or Ctrl-C never leaves half done,
  prints the exact line to add its directory to `PATH`, and
  `--uninstall` also looks in `/usr/local/bin` and `~/.local/bin`.

### Fixed

- The audit date routine had two sign errors: dates outside
  2000-03-01..2100-02-28 were a day off. Current timestamps were not
  affected.
- A short audit write is resumed, so it no longer leaves a partial JSON
  line. A write that fails midway (ENOSPC, EPIPE) can still leave a
  newline-terminated fragment.
- Two sessions appending to one file could overwrite each other; append
  now uses `O_APPEND`.
- A second login could delete an upload another session still had open
  in staging.
- A failed stderr write or allocation during reload could exit the
  daemon and drop every session.
- Shutdown closed the listen socket twice.
- REALPATH of `/.zift` returned a non-v3 status; it is PERMISSION_DENIED
  like every other request. REALPATH of a 4096-byte relative path is
  BAD_MESSAGE instead of a 4097-byte reply.
- A client offering SFTP version 1 or 2 got version 3 anyway; it is now
  refused.
- A READDIR iterator error dropped names already read.
- Long names and user names are no longer truncated in listings.
- The staging-orphan sweep works on filesystems that don't report entry
  types.
- The fd-budget warning can reappear after a reload raises
  `max-connections`.
- `serve` with the wrong number of arguments exits 1, not 0.
- `accept()` failures log `zift: accept failed: E<errno>` and back off
  instead of spinning.
- Sessions still alive after the force-close no longer outlive the
  process's cleanup; the process exits 0.

## 0.11.0 — 2026-09-08

- The jail walks every path component with NOFOLLOW from the partner
  root. Directory symlinks are listed but never traversed, so a symlink
  cannot alias a denied path or `.zift`.
- A rename can no longer increase access. A file rename that would grant
  access the source lacked is denied; a directory rename checks every
  existing descendant at both paths, and fails closed above 100,000
  entries or 256 levels.
- libssh 0.11.5 (a zero maximum packet size on a channel open no longer
  loops) and mbedTLS 3.6.7.
- install.sh requires cosign and verifies against the exact release
  workflow identity and tag.

## 0.10.3 — 2026-09-08

- A client that disconnects normally (SSH reason 11) ends its session
  `ok` with detail `client disconnected`, not `failed`.

## 0.10.2 — 2026-09-08

- `list` satisfies STAT, so a list-only directory can be browsed with
  FileZilla, WinSCP and OpenSSH `sftp`, which all stat before listing.

## 0.10.1 — 2026-08-14 (untagged)

- A rejected reload is loud. The daemon logs `config reload rejected —
  SERVING PREVIOUS CONFIG`, audits `config.reload` `failed`, and stays
  degraded until a valid config loads (`config reload recovered`,
  `config.reload` `ok`).
- The unit's `ExecReload` runs `zift validate` first, so `systemctl
  reload` fails on an invalid config and never signals the daemon.

## 0.10.0 — 2026-08-14 (untagged)

- **Breaking:** the verbs `add`, `create` and `remove` are gone and
  rejected as `InvalidPermission`. Migration: `add` and `create` become
  `write`; `remove` becomes `delete`, plus `update` where the partner
  must overwrite.

## 0.9.5, 0.9.4, 0.9.3 — 2026-08-14 (untagged)

- 0.9.5: no more contentless `zift: LibsshFailure:` lines; a failed
  handshake is recorded by its `handshake.failed` audit line.
- 0.9.4: `validate` checks `listen` (a port from 1 to 65535).
- 0.9.3: startup logs `zift: starting zift X.Y.Z (<target> <mode>)`
  before reading the config.

## 0.9.2 — 2026-08-14 (untagged)

- Overwriting an existing file needs the new `update` verb instead of
  `remove`, so a partner can replace a file without gaining deletion.
  `remove` stayed as an alias until 0.10.0.

## 0.9.0 — 2026-08-07

- **Breaking:** passwords use the compact `a…` passhash, and
  `$argon2id$` PHC strings are rejected. Migration: remint with `zift
  hash-password`.
- Built-in abuse controls (per-user `from`, auth backoff, temporary
  source suppression) replace the CrowdSec, fail2ban and logrotate
  packaging.

## 0.8.0 — 2026-05-11 (untagged)

- **Breaking:** staging moved from `<root>/.zift-staging/` to
  `<root>/.zift/staging/`, and `.zift` and `.zift-staging` are reserved
  anywhere in a path. Migration: before upgrading, run `find /home/zift
  -name .zift -o -name .zift-staging` and rename any partner data that
  uses those names. Startup warns about a leftover
  `<root>/.zift-staging`; remove it once no session needs it.

## 0.7.1 — 2026-04-29 (untagged)

- A password-only user's auth failures advertise only `password`, so
  clients stop offering every agent key first.

## 0.7.0 — 2026-04-29 (untagged)

- **Breaking:** `auth` replaces the `password` and `key` directives,
  which are rejected as `PasswordDirectiveRemoved` and
  `KeyDirectiveRemoved`. Migration: `auth <hash>` and `auth
  /path/to/key.pub`.
- `partner-root`, and a leading `time` field on every audit line.

Earlier releases: see the git history.
