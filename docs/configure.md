# Configure Zift

Zift is configured by one text file. The file defines one `server`
block and one `user <name>` block per virtual user.

There is no include system, no variables, no environment interpolation,
no inheritance, no embedded expressions, and no runtime database. The
file on disk is the configuration.

## Example

```zift
server
  listen 0.0.0.0:2222
  host-key /home/zift/host_ed25519
  partner-root /home/zift
  reload-interval 2s
  idle-timeout 5m
  max-connections 14
  max-unauth-connections 4
  shutdown-grace 30s
  log stderr
  listing-mode virtual
  publish-mode 0o660
  mkdir-mode 0o2770

user ally
  from 203.0.113.40
  from 198.51.100.0/28
  auth a…
  auth /home/zift/keys/ally.pub
  allow / read
  allow /pending full
  allow /archive read
  deny **.exe
  deny **/.ssh/**
```

Validate before serving:

```sh
zift validate /home/zift/zift.conf
```

Run:

```sh
zift serve /home/zift/zift.conf
```

## File Shape

The grammar is intentionally small:

- A section header is either `server` or `user <name>`.
- Properties are indented under a section.
- Blank lines are ignored.
- Whole-line comments are ignored when the first non-whitespace
  character is `#`.
- Inline comments are not accepted. Put comments on their own lines.
- User names may contain ASCII letters, digits, `_`, `-`, and `.`.
- User names may not be empty, may not start with `.`, and may not be
  `.` or `..`.
- User names are limited to 64 bytes.
- Virtual paths are UTF-8 and limited to 4096 bytes.

Durations require a suffix: `ms`, `s`, `m`, or `h`. Bare `0` is allowed
for settings where zero disables a behavior.

## Server Directives

### `listen`

Required.

TCP listen address:

```zift
listen 127.0.0.1:2222
listen 0.0.0.0:2222
```

Prefer per-user `from` source policy in the user block (see below).
A host or cloud firewall is optional defense-in-depth, not required.

### `host-key`

Required.

Path to an unencrypted SSH host private key:

```zift
host-key /home/zift/host_ed25519
```

Generate one with:

```sh
ssh-keygen -t ed25519 -f /home/zift/host_ed25519 -N ""
```

The file must be readable by the `zift` process. In hardened
deployments, make it `root:zift` and mode `0640` so the daemon can read
but not rewrite its own server identity.

### `partner-root`

Optional.

Base directory for users that do not declare an explicit `root`.

```zift
partner-root /home/zift
```

With this setting:

```zift
user ally
  auth a…
```

defaults to:

```zift
root /home/zift/ally
```

Explicit `root` still wins. `partner-root` must be an absolute path.
Trailing slashes are normalized.

### `reload-interval`

Optional. Default: `2s`.

How often Zift checks the config file mtime for changes:

```zift
reload-interval 2s
```

Set to `0` to disable polling. `SIGHUP` still forces a reload.

Valid reloads apply to new sessions only; see [Reloads](#reloads) below
and [`operate.md`](operate.md). Changing `host-key` requires a restart.

### `idle-timeout`

Optional. Default: `5m`.

Disconnects idle sessions, including pre-auth sessions:

```zift
idle-timeout 5m
```

Set to `0` to disable.

### `max-connections`

Optional. Default: `128`.

Maximum total concurrent sessions:

```zift
max-connections 14
```

Size this with password-verify memory in mind. Each passhash verification
uses a fixed 64 MiB argon2id profile. The shipped systemd unit sets
`MemoryMax=4G`; production configs typically keep
`max-connections` / `max-unauth-connections` modest so a handshake
storm cannot pin every worker on KDF work.

### `max-unauth-connections`

Optional. Default: `0`.

Maximum concurrent pre-auth sessions:

```zift
max-unauth-connections 4
```

`0` disables the separate cap. When set, it must be less than or equal
to `max-connections`.

This protects authenticated partner traffic from being crowded out by
handshake storms or clients that connect and never authenticate.

### `shutdown-grace`

Optional. Default: `30s`.

How long graceful shutdown waits for active sessions before Zift closes
their sockets:

```zift
shutdown-grace 30s
```

This is mostly useful to reduce wait time in tests or tightly managed
deployments.

### `log`

Optional. Default: `stderr`.

Audit destination:

```zift
log stderr
log /home/zift/audit.jsonl
```

Prefer `stderr` in production so the supervisor (journald, Docker,
Kubernetes) owns retention. Use a file path only when you already have
a log-shipping preference. File paths must be absolute. File
destinations are opened append-only by the process and reopened on
`SIGUSR1`, which supports ordinary external rotation workflows (send
`SIGUSR1` after renaming the file).
### `listing-mode`

Optional. Default: `virtual`.

Controls long directory listing output:

```zift
listing-mode virtual
listing-mode reality
```

`virtual` shows the partner their virtual user name, a fixed group of
`sftp`, and policy-derived mode bits. It hides host filesystem owner,
group, and mode details.

`reality` passes through on-disk owner/group/mode. Use it mainly for
debugging.

### `publish-mode`

Optional. Default: `0o660`.

Mode applied to files after a successful staged upload publish:

```zift
publish-mode 0o660
```

Allowed values:

- `0o600`
- `0o640`
- `0o660`

The allowed set prevents accidental world-readable or world-writable
partner data.

### `mkdir-mode`

Optional. Default: `0o2770`.

Mode applied to directories created through SFTP:

```zift
mkdir-mode 0o2770
```

Allowed values:

- `0o2700`
- `0o2750`
- `0o2770`

The defaults match the recommended `/home/zift/<partner>` layout where
setgid directories keep group ownership consistent for operators.

## User Directives

### `auth`

Required: each user needs at least one credential.

`auth` accepts either a password hash or an absolute path to a public
key file.

Password (Janus-identical `a…` passhash — argon2id with fixed
params, `a` + 31 base62 chars — always 32 chars, alphabet `[0-9A-Za-z]`):

```zift
auth a…
```

Generate it with:

```sh
printf '%s\n' 'secret' | zift hash-password
```

Legacy `$argon2id$…` PHC strings are rejected; remint with
`zift hash-password`.

Public-key file:

```zift
auth /home/zift/keys/ally.pub
```

A user may have:

- one password hash
- zero or more public-key files
- both password and public-key auth

Multiple `auth /path/to/file.pub` lines accumulate. At most one
password hash is allowed per user.

Public-key files:

- must use absolute paths
- must be regular files
- must not be group-writable or world-writable
- must not be symlinks
- must contain at least one public-key line
- may contain multiple OpenSSH-style public-key lines
- accept `ssh-ed25519`, `ecdsa-sha2-nistp256`,
  `ecdsa-sha2-nistp384`, and `ecdsa-sha2-nistp521`

RSA and DSA keys are not accepted.

### `from`

Optional. Repeatable.

Restrict which source IPs may authenticate as this user:

```zift
from 203.0.113.40
from 198.51.100.0/28
from 2001:db8::/32
```

Each line is a single IPv4/IPv6 address or CIDR. When one or more
`from` lines are present, the peer must match at least one of them
before password or public-key auth can succeed. When omitted, any
source may attempt auth (still subject to credentials and Zift's
built-in abuse suppression).

This is the preferred B2B hardening: partner identity + partner
network + path policy in one reviewable file.

### `root`

Optional when `server.partner-root` is set. Required otherwise.

Maps the virtual user's `/` to a real filesystem directory:

```zift
root /home/zift/ally
```

The root must exist and be a directory when the config is validated,
loaded, or reloaded.

Zift rejects configs with overlapping roots. Two virtual users cannot
share the same root, and one user root cannot be inside another. Roots
are canonicalized through symlinks before this check, which keeps the
per-user policy model honest.

### `allow`

Grants permissions on matching virtual paths:

```zift
allow / read
allow /pending full
allow /archive read
```

Policy is default-deny. A user with credentials and no `allow` rules
can authenticate but cannot do useful SFTP work.

### `deny`

Denies matching virtual paths:

```zift
deny **.exe
deny **/.ssh/**
```

`deny` overrides `allow`.

## Permission Model

Zift's everyday vocabulary is CRUD plus one bundle:

| Verb | Grants |
| --- | --- |
| `read` | download **and** list (stat, directory listing, download) |
| `write` | create a **new** file (no overwrite, no directory creation) |
| `update` | overwrite, truncate, or append to a file that **already exists** |
| `delete` | delete files and directories |
| `full` | everything: read, write, update, delete, plus `mkdir` and `rename` |

Those five cover almost every real policy. `read` and `full` are the two
you reach for most; `write` / `update` / `delete` are the individual CRUD
letters for finer control. `full` is exactly `read write update delete
mkdir rename`.

Three granular verbs exist for unusual policies:

| Verb | Grants |
| --- | --- |
| `list` | directory listing without download (the rare inverse of `read`) |
| `mkdir` | directory creation only |
| `rename` | rename only, checked on both source and destination |

There are no aliases and no legacy spellings — every verb names exactly
one capability, or (for `read` and `full`) one obvious bundle. In
particular, `write` never silently grants directory creation: say
`mkdir` or `full` when you want that.

### The Clobber Rule

`write` creates; `update` modifies. They are deliberately separate.

Creating a **new** file needs `write`. Overwriting, truncating, or
appending to a file that **already exists** additionally needs `update`
— the "clobber" right. Splitting them lets you express two opposite
intents a single write verb cannot.

With:

```zift
allow /pending read write
```

a partner can create new files under `/pending`, but cannot overwrite,
truncate, append to, rename over, or delete an existing one — an
append-only submit box (a claim, once dropped, cannot be quietly
retracted).

With:

```zift
allow /pending read write update
```

the partner can also replace their own files (the daily-resend case),
but still cannot delete. Add `delete` for that, or use `full` for
complete control of the subtree.

## Pattern Matching

Patterns match virtual paths, not host filesystem paths.

Literal patterns are path-component prefix matches:

```zift
allow /pending read
```

matches:

- `/pending`
- `/pending/file.csv`
- `/pending/deep/file.csv`

It does not match:

- `/pendingfoo`
- `/pending-archive`

Glob patterns support:

| Pattern | Meaning |
| --- | --- |
| `*` | any sequence except `/` |
| `?` | one character except `/` |
| `**` | any sequence including `/` |

Examples:

```zift
deny /*.exe      # .exe files directly under the virtual root
deny **.exe      # .exe files at any depth
deny **/.ssh/**  # anything inside .ssh at any depth
```

Prefer explicit patterns over clever ones. The config language is meant
to stay small.

## Common Policies

Drop zone: partner can upload new files but not overwrite or delete.

```zift
allow / read
allow /incoming write
```

Pickup directory: partner can download and delete after pickup, but not
overwrite in place.

```zift
allow / read
allow /reports read delete
```

Archive: partner can browse and download only.

```zift
allow / read
allow /archive read
```

Mutable workspace:

```zift
allow /workspace full
```

Block common dangerous names everywhere:

```zift
deny **/.ssh/**
deny **.exe
```

## Atomic Uploads

New file uploads are staged under `<root>/.zift/staging/` and published
with an atomic rename when the client closes the file handle.
Processors watching a partner-visible directory therefore do not see
half-uploaded files.

`.zift` (and legacy `.zift-staging`) is reserved: hidden from listings
and rejected in virtual paths. Use `publish-mode` for the final file
mode after publish. Partner root and target directory must share one
filesystem.

Full namespace model, hardening, and caveats:
[`security.md`](security.md). Upgrade notes for the v0.8.0 path change:
[`operate.md`](operate.md).

## SFTP Surface

Zift speaks SFTP v3. It supports the request types needed for ordinary
file transfer:

- `REALPATH`
- `STAT`, `LSTAT`, and `FSTAT`
- `OPENDIR` and `READDIR`
- `OPEN`, `READ`, `WRITE`, and `CLOSE`
- `MKDIR`, `REMOVE`, `RMDIR`, and `RENAME`

Unsupported operations such as `SETSTAT`, `FSETSTAT`, `READLINK`,
`SYMLINK`, and `EXTENDED` return "operation unsupported" and the
session continues. Clients that try to set mtime, chmod, chown, create
symlinks, or use protocol extensions should treat those as unsupported
features rather than transfer failures.

## Reloads

Zift reloads for new sessions when the config mtime moves forward, or
immediately on `SIGHUP`. Existing sessions keep the snapshot they
authenticated with. Invalid reloads are rejected; the previous config
keeps serving.

`listen`, `host-key`, and `log` are bound once at startup and are
**not** re-applied by a reload. If a reload changes one of them, Zift
logs a warning naming the setting and keeps the value it started with —
apply the change with a full restart. Everything else (users, rules,
timeouts, connection caps, modes) applies to new sessions.

Operator runbook (validate-then-HUP, mtime caveats, partner add/remove):
[`operate.md`](operate.md).

