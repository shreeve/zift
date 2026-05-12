# Security Model

Zift is an SFTP server on a remote trust boundary. Its security posture
comes from narrow scope, default-deny policy, explicit filesystem roots,
and avoiding runtime features that add state or code execution inside
the daemon.

This document describes what Zift is designed to protect, what it does
not protect, and which caveats operators should understand before
exposing it to partners.

## Threat Model

Zift is primarily concerned with:

- An authenticated partner trying to read or write outside their virtual
  root.
- An authenticated partner trying to exceed their configured
  permissions.
- An authenticated partner trying to destroy, overwrite, or replace data
  they were only allowed to create or read.
- An authenticated partner trying to exploit symlinks, `..`, malformed
  paths, or SFTP protocol edge cases.
- An unauthenticated network client trying to consume connection slots,
  enumerate users, or abuse authentication.
- A local unprivileged user trying to observe partner data or in-flight
  uploads through host filesystem permissions.

Zift does not protect against:

- root compromise of the host
- a malicious operator
- kernel vulnerabilities
- filesystem drivers that lie about canonical fd paths
- libssh or crypto-library vulnerabilities
- disk exhaustion by allowed uploads
- downstream processors that mishandle files after Zift writes them
- partner credential compromise

Run Zift as a dedicated unprivileged OS user. Treat that as mandatory,
not cosmetic.

## Security Boundary

The boundary is:

```text
remote SFTP client
  -> SSH transport via libssh
  -> Zift auth
  -> Zift path normalization
  -> Zift policy check
  -> verified filesystem operation under user's root
```

Every virtual user has:

- a name
- one password hash and/or one or more public keys
- one real filesystem root
- allow/deny rules

Virtual users are not OS users. They have no shell, no UID, no home
directory in `/etc/passwd`, and no independent host permissions. Zift
itself performs filesystem operations as the single OS user running the
daemon.

## Default Deny

Authorization starts from deny.

A user with valid credentials but no `allow` rules can authenticate but
cannot browse, download, upload, rename, or delete useful paths.

`allow` grants specific verbs on matching virtual paths. `deny`
overrides `allow`.

This is the central policy invariant:

```zift
user ally
  auth $argon2id$...
  allow /pending read add
  deny **.exe
```

The user may create new non-`.exe` files under `/pending`, but may not
delete or overwrite existing files because `remove` was not granted.

## Path Validation

Zift validates client-supplied virtual paths before policy or audit:

- maximum 4096 bytes
- valid UTF-8
- no NUL byte
- no ASCII control characters
- no DEL byte
- no traversal above virtual root
- normalized `.` and `..`
- reserved `.zift` path component rejected (and legacy `.zift-staging` for upgrade safety)

Policy is checked against the normalized virtual path, not against the
host filesystem path.

## Jail Enforcement

Zift does not rely on string-prefix checks alone.

For filesystem operations, paths are resolved under the user's root and
the opened file or directory descriptor is verified against the
canonical path reported by the kernel.

Mutation operations use parent-directory file descriptors where
possible:

- open the parent directory
- verify the parent fd is inside the user's root
- perform the operation relative to that fd

This is designed to block common symlink and time-of-check/time-of-use
escape patterns where a string looked safe before open but resolves
outside the jail at operation time.

## Filesystem Assumptions

Zift assumes the kernel reports truthful canonical paths for file
descriptors.

On Linux this depends on `/proc/self/fd`. On macOS this depends on
`F_GETPATH`.

Do not place partner roots on unusual filesystems that synthesize or lie
about fd paths if you depend on jail enforcement. Prefer ordinary local
filesystems for partner roots.

## Authentication

### Passwords

Passwords are stored as Argon2id PHC strings:

```zift
auth $argon2id$v=19$m=65536,t=3,p=1$...
```

Generate with:

```sh
printf '%s\n' 'secret' | zift hash-password
```

Accepted Argon2id parameters are bounded:

- memory: 64 MiB to 256 MiB
- passes: 2 to 8
- parallelism: 1 to 4
- version: `v=19`

Plaintext passwords are never accepted in config.

Unknown-user password attempts run a dummy Argon2id verification so the
password path does not trivially reveal whether a username exists by
timing alone.

### Public Keys

Public keys live in operator-managed files:

```zift
auth /home/zift/keys/ally.pub
```

Accepted algorithms:

- `ssh-ed25519`
- `ecdsa-sha2-nistp256`
- `ecdsa-sha2-nistp384`
- `ecdsa-sha2-nistp521`

Rejected:

- RSA
- DSA
- malformed key lines
- key files that are not regular files
- key files writable by group or world

### Auth Attempt Limits

Each session has a finite authentication attempt limit. Pre-auth
connections are also subject to `idle-timeout`.

Set `max-unauth-connections` to keep unauthenticated connection churn
from consuming all `max-connections` slots.

### Auth Method Caveat

SSH public-key auth is a two-phase protocol. Some response shapes can
reveal information about whether a username/key combination is
configured.

Zift narrows failure methods for password-only known users so ordinary
clients do not waste time offering every SSH agent key before showing a
password prompt. That means a password-only known user can be
distinguished from an unknown user by a probing client.

For partner deployments where usernames are pre-shared, this is usually
the right operational tradeoff. If username non-enumerability is more
important, provision both password and key auth consistently so response
shapes stay less distinguishable.

## Permission Safety

The important destructive-operation rule is:

Any operation that modifies or replaces an existing entry requires
`remove` permission on that entry's path.

This applies to:

- overwriting a file
- truncating a file
- appending to an existing file
- renaming over an existing destination
- deleting a file
- removing a directory

`add` by itself allows creation of new entries. It does not grant
authority to destroy existing entries.

## Atomic Uploads

New uploads are written into `<root>/.zift/staging/` and published to
the final path when the client closes the file handle. The parent
`<root>/.zift/` is zift's reserved per-partner namespace (see
"Per-Partner Namespace" below).

Security properties:

- partners cannot list `.zift` (or anything inside it)
- partners cannot reference `.zift` through SFTP paths (the legacy
  `.zift-staging` name from v0.5.0–v0.7.x is still reserved for
  upgrade-safety)
- fresh staging directories are mode `0o700`
- staging files are private while in flight
- disconnect cleanup removes unfinished staging files
- publish re-checks policy and clobber authority at close time

Operational caveats:

- Staging happens under the partner root, not the target parent. Default
  ACLs and setgid inheritance on subdirectories such as `/pending` do
  not apply at staging-file create time. Use `publish-mode`, root-level
  defaults, or downstream fixup if processors rely on exact ownership or
  ACLs.
- Partner root and target directory must be on the same filesystem.
  Cross-filesystem rename returns `EXDEV`; Zift refuses the publish
  rather than copy bytes non-atomically.
- A process crash can leave orphaned staging files. Operators may remove
  them when no upload session is active.
- The current publish-time no-clobber guard has a known stat-then-rename
  window. Closing it completely requires platform no-replace rename
  primitives: `renameat2(RENAME_NOREPLACE)` on Linux and
  `renamex_np(RENAME_EXCL)` on macOS.

## Per-Partner Namespace

Every partner root has a reserved per-partner namespace directory at
`<root>/.zift/`. This is zift's hidden drawer for the partner: a
place to store both daemon-managed state and operator-managed notes
without exposing any of it through the SFTP wire surface.

Layout:

```text
<root>/.zift/                       reserved per-partner namespace
├── staging/                        daemon-owned, mode 0700
│                                   atomic-upload in-flight files
└── (operator-managed)              notes.md, contracts, scripts,
                                    audit reviews — anything the
                                    operator wants alongside the
                                    partner's data tree
```

Security properties:

- `.zift` is rejected as a virtual-path component by the path
  validator. Every SFTP operation (OPENDIR, STAT, OPEN, MKDIR,
  REMOVE, RMDIR, RENAME, ...) on any path crossing `.zift/`
  returns `permission denied` to the partner.
- The listing renderer also skips `.zift` (and the legacy
  `.zift-staging`) when emitting READDIR results — partners
  never observe the entry exists.
- The daemon writes only to `<root>/.zift/staging/`. The namespace
  parent and any other path inside it are operator-managed; the
  daemon traverses them but does not read or write their contents.

Recommended operator workflow for per-partner metadata:

```sh
# Pre-create with operator ownership so the daemon can traverse
# (group zift) but cannot modify (root-owned parent).
sudo install -d -o root -g zift -m 0750 /home/zift/<partner>/.zift

# Drop notes, contracts, anything you want hidden from the partner.
sudoedit /home/zift/<partner>/.zift/notes.md
```

If the operator does not pre-create `.zift/`, the daemon creates it
at mode `0o750 zift:zift` on first upload — operators in group zift
can still add files later. The mode of a pre-existing `.zift/` is
left alone; the daemon only enforces that it is a real directory,
not a symlink (which could redirect the staging area outside the
jail).

This namespace is forward-extensible: future per-partner state that
zift might add (staging-orphan sweep queues, resume indexes, etc.)
would land in `<root>/.zift/<subdir>/` without any further
path-validator changes.

## Audit Logging

Zift emits structured JSON audit lines for auth and privileged or
denied operations.

Audit is designed for operational visibility, not as a fail-closed
security control.

If the audit destination fails, Zift warns on stderr and continues
serving. Availability wins over blocking all partner traffic because a
log sink is unavailable.

If your environment requires fail-closed audit semantics, put the log
destination on storage partners cannot influence, ship logs off-host,
monitor stderr, and use supervisor policy to stop the service when log
delivery fails.

## Recommended Host Posture

Use the shipped systemd unit as the baseline.

The recommended posture:

- dedicated `zift` OS user
- no root privileges
- empty capability bounding set
- `NoNewPrivileges=true`
- restricted address families
- strict filesystem namespace
- `/home/zift` as the only writable tree
- root-owned config and host key, group-readable by `zift`
- partner roots owned by `zift:zift`
- partner directories mode `2770`
- audit log mode `0640`
- private staging directories mode `0700`

Recommended top-level modes:

```text
/home/zift/                         0750 root:zift
/home/zift/zift.conf                0640 root:zift
/home/zift/host_ed25519             0640 root:zift
/home/zift/audit.jsonl              0640 zift:zift
/home/zift/keys/                    0750 root:zift
/home/zift/keys/<partner>.pub       0640 root:zift
/home/zift/<partner>/               2770 zift:zift
/home/zift/<partner>/.zift/         0750 zift:zift  (or root:zift if operator pre-creates)
/home/zift/<partner>/.zift/staging  0700 zift:zift
```

## Network Posture

Zift listens on the configured TCP address. It does not implement:

- IP allowlists
- rate limiting
- bans
- geo rules
- TLS termination
- HTTP health endpoints

Use:

- cloud firewall rules
- host firewall rules
- fail2ban on audit logs
- supervisor health checks
- TCP probes

Prefer partner IP allowlists for public deployments.

## SFTP Protocol Surface

Zift intentionally implements the SFTP v3 operations needed for file
transfer and rejects metadata mutation and extension operations. Requests
such as `SETSTAT`, `FSETSTAT`, `READLINK`, `SYMLINK`, and `EXTENDED`
return "operation unsupported" and the session continues. Clients cannot
set server-side mtime, chmod/chown files through SFTP, create symlinks,
or rely on protocol extensions.

## Supply Chain

Release builds:

- use Zig `0.16.0`
- vendor libssh, mbedTLS, and zlib via `build.zig.zon`
- produce static Linux binaries
- produce macOS binaries with system libSystem only
- publish SHA256 checksums
- sign `SHA256SUMS` with cosign keyless via GitHub Actions OIDC

Operators should verify `SHA256SUMS.bundle` and the downloaded binary
hash before installing.

Source builds are reproducible from the pinned dependency graph, but a
local build does not carry the GitHub Actions OIDC identity. Use release
artifacts when provenance matters.

## Known Caveats

These are accepted limitations or follow-up hardening items, not hidden
promises:

- Publish-time no-clobber is not yet hermetic against a target that
  appears between the destination stat and rename. Platform no-replace
  rename primitives should close this.
- `openStagingDir` verifies existing `.zift/` and `.zift/staging/`
  with lstat before opening them. A local attacker with write access
  to the partner root could theoretically race that check. SFTP
  clients cannot create or access `.zift/` or its contents; this is
  a local filesystem hardening issue.
- Crash-time staging orphans are not automatically swept at startup.
- Glob matching supports `**`, which is useful but recursive. Patterns
  are operator-controlled, not remote-client-controlled.
- Fuzz harnesses exist, but the CI random fuzz job is disabled until the
  pinned Zig toolchain's fuzz runner issue is resolved.
- Audit is not fail-closed.
- Quotas and disk-full behavior are delegated to the OS.

## Security Review Checklist

Before exposing a deployment:

- `zift validate /path/to/zift.conf` succeeds as the service user.
- Zift runs as a dedicated unprivileged OS user.
- Config and host key are not writable by the daemon.
- Public-key files are not writable by group or world.
- Partner roots do not overlap.
- Partner roots are not on FUSE or unusual network filesystems.
- Partner roots that receive staged uploads are on a single filesystem.
- `max-connections`, `max-unauth-connections`, and systemd `MemoryMax`
  are consistent with Argon2id memory settings.
- Firewall allows only expected partner IPs to reach the SFTP port.
- Audit logs are shipped, rotated, or monitored according to your
  retention requirements.
- fail2ban or equivalent is configured if public auth attempts are
  expected.
- Rollback binary and config backup are available.

