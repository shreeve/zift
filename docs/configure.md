# Configure Zift

Zift is configured by one text file: one `server` block, then one
`user <name>` block per partner. There are no includes, variables,
environment interpolation or runtime database. The file on disk is the
configuration.

## Example

```zift
server
  listen 0.0.0.0:2222
  host-key /home/zift/host_ed25519
  partner-root /home/zift
  log stderr

user ally
  from 203.0.113.40
  from 198.51.100.0/28
  auth a…                        # passhash from `zift hash-password`
  auth /home/zift/keys/ally.pub
  allow / read
  allow /pending full
  deny **.exe
```

Check it, then serve it:

```sh
zift validate /home/zift/zift.conf
zift serve /home/zift/zift.conf
```

`validate` runs the checks `serve` runs on a config at startup and on
every reload. It does not open the log, bind the port, or check that
the service may bind it:

- the file parses (errors name the line, section, directive and reason);
- the host key loads as an unencrypted private key and passes the file
  checks under [`host-key`](#host-key);
- the log's directory exists, and an existing log is a regular file,
  FIFO or character device, never a symlink;
- every root exists, is a directory, and overlaps no other root after
  symlinks are resolved;
- every key file passes the checks under [`auth`](#auth);
- the config file, host key, key files and log all lie outside every
  partner root, through symlinks too.

Run it as the service user (`sudo -u zift zift validate …`): file
ownership is checked against the user running it.

## File Shape

- A section header starts in column 0: `server` or `user <name>`.
- Directives are indented under a section, one per line: `name value`.
- Blank lines are ignored. `#` starts a comment at the start of a line
  or after a space or tab; a `#` inside a token is literal.
- A value runs to the end of the line or comment and may contain
  spaces (`root /srv/sp ace`) and `#` inside a token (`root /srv/a#1`),
  but never a blank followed by `#`, which always starts a comment.
- User names use ASCII letters, digits, `_`, `-` and `.`, are at most 64
  bytes, and may not start with `.`.
- Durations need a unit: `ms`, `s`, `m`, `h` or `d` (`30s`, `5m`). A bare
  `0` turns the setting off where that is allowed.
- Numbers are plain decimal digits. Modes are octal: `0o660`, `0660` and
  `660` are the same.
- A directive that takes one value may appear once per section
  (`DuplicateDirective`).
- Paths (`host-key`, `partner-root`, `root`, `log`, key files) must be
  absolute.

## Server Directives

| Directive | Default | Meaning |
| --- | --- | --- |
| `listen` | required | `host:port`, `:port` (every IPv4 address), or `[ipv6]:port` such as `[::]:2222`; a hostname binds the first address it resolves to; no zones (`%lo0`) |
| `host-key` | required | SSH host private key |
| `partner-root` | none | base for users without `root`: user `ally` gets `<partner-root>/ally` |
| `reload-interval` | `2s` | how often to check the config and key files for changes; `0` (SIGHUP only) or at least `100ms` |
| `idle-timeout` | `5m` | close a session idle this long; `0` (never) or `1s` up to about 24.8 days |
| `max-connections` | `128` | concurrent sessions, at least 1 |
| `max-unauth-connections` | a quarter of `max-connections` (at least 1) | concurrent sessions not yet logged in; `0` = no separate cap; at most `max-connections` |
| `shutdown-grace` | `30s` | how long SIGTERM waits for sessions before closing them |
| `log` | `stderr` | audit destination: `stderr` or an absolute path |
| `listing-mode` | `virtual` | `virtual` or `reality` |
| `publish-mode` | `0o660` | mode of a finished upload |
| `mkdir-mode` | `0o2770` | mode of a directory made over SFTP |

### `host-key`

Generate one with `ssh-keygen -t ed25519 -f /home/zift/host_ed25519 -N
""`. The file must be a regular file (a symlink is followed and its
target checked) with one hard link, owned by root or the daemon's user,
with no group-write, group-exec or other bits: `0600` and `0640` pass, `0644`
and `0660` do not. `root:zift 0640` lets the daemon read its identity
but not rewrite it.

### `max-connections` and `max-unauth-connections`

`max-connections` bounds everything; `max-unauth-connections` keeps
connections that never log in from filling it. Password checks are
bounded separately (see [Limits](#limits)), so the defaults are safe
under the shipped unit's `MemoryMax`. The arithmetic is in
[`operate.md`](operate.md#sizing).

### `log`

Prefer `stderr`, so the supervisor (journald, Docker, Kubernetes) owns
retention. A path is opened append-only and never through a symlink. It
may be a regular file, a FIFO read by a log shipper, or a character
device such as `/dev/null`; a FIFO's reader must be running before Zift
starts. A file Zift creates gets mode `0640`; an existing file keeps its
mode. `SIGUSR1` reopens the path for rotation (see
[`operate.md`](operate.md#log-rotation)). A log that cannot be opened at
startup stops `serve`; after that, write failures are reported on
stderr and serving continues.

### `listing-mode`

`virtual` shows the partner their own user name, group `sftp`, and mode
bits derived from their policy, not the host's owner and mode.
`reality` passes the on-disk owner, group and mode through; use it for
debugging.

### `publish-mode` and `mkdir-mode`

`publish-mode` needs owner `rw` and takes only read and write bits,
without other-write: at most `0o664`. `mkdir-mode` needs owner `rwx`,
may not include other-write, setuid or sticky, and may include setgid,
which keeps new directories in the partner tree's group.

## User Directives

### `auth`

At least one per user. The value is a password hash or an absolute path
to a public-key file:

```zift
auth a…
auth /home/zift/keys/ally.pub
```

A user may have one password hash and any number of key files. Mint the
hash with:

```sh
printf '%s\n' 'secret' | zift hash-password
```

It reads the first line of stdin, refuses an empty password, and prints
a 32-character `a…` passhash (format in [`security.md`](security.md#passwords)).
Plaintext passwords and old `$argon2id$…` strings are rejected.

A key file holds OpenSSH public-key lines (`<algorithm> <base64>
[comment]`); blank lines and `#` lines are skipped, and option prefixes
are not allowed. Accepted algorithms: `ssh-ed25519`,
`ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, and
`ssh-rsa` from 2048 to 8192 bits. RSA keys authenticate only with
`rsa-sha2-256` or `rsa-sha2-512` signatures, never SHA-1; DSA is
rejected. The file must be a regular file (a symlink is followed and its
target checked, so Kubernetes Secrets and systemd credentials work)
with one hard link, owned by root or the daemon's user, not group- or world-writable, and
contain at least one key. Each key must be well formed and load in
libssh exactly as it would at login.

### `from`

Optional and repeatable: one IPv4 or IPv6 address or CIDR per line.

```zift
from 203.0.113.40
from 198.51.100.0/28
from 2001:db8::/32
```

With any `from` line, a peer that matches none of them cannot log in as
this user. A password attempt from elsewhere is still timed and counted
like a bad password, so it reveals nothing; a key attempt is refused
like an unknown user's. This is the cheapest hardening there is when
partners have stable egress addresses.

IPv4 peers are matched as `::ffff:a.b.c.d`, so `::ffff:` forms match
plain IPv4 peers. An IPv6 prefix counts all 128 bits: one shorter than
/96 that covers that space, such as `::ffff:203.0.113.0/24` or `::/80`,
would admit every IPv4 peer and is rejected (write `203.0.113.0/24`).
`::/0` is allowed and deliberately matches every peer, IPv4 included.

### `root`

The host directory that is this user's `/`. Required unless
`partner-root` is set. It must exist and be a directory, and no two
users' roots may be equal or nested, after symlinks are resolved.

### `allow` and `deny`

```zift
allow /pending read write
deny **.exe /archive/private
```

`allow <pattern> <verb>...` grants verbs on matching paths. `deny
<pattern>...` takes one or more patterns and no verbs, because it
removes everything. See [Permissions](#permissions) and
[Patterns](#patterns).

## Permissions

Policy is default-deny: a user with credentials and no `allow` lines can
log in and do nothing. Rules match the normalized virtual path the
partner sees, never a host path. If any `deny` matches, the path gets
nothing, whatever the order or specificity of the `allow` lines.
Otherwise the path gets the union of every matching `allow`.

| Verb | Grants |
| --- | --- |
| `read` | download, stat and list (`read` includes `list`) |
| `write` | create a **new** file |
| `update` | overwrite, truncate or append to an **existing** file, rename over one, and set its times |
| `delete` | remove a file or an empty directory |
| `full` | all of the above plus `mkdir` and `rename` |
| `list` | stat and list without download |
| `mkdir` | create a directory |
| `rename` | rename, checked at both the old and the new path |

The first five cover almost every policy. `write` never implies
`mkdir` or `rename`.

**The clobber rule.** `write` creates; `update` replaces. With `allow
/pending read write`, a partner can drop new files but cannot
overwrite, truncate, append to or rename over an existing one, so a
submitted file cannot be quietly retracted. Add `update` for a feed
that re-sends `daily.csv` every morning, and `delete` only if they
should clean up.

**Renames follow the object.** A rename needs `rename` at both paths,
plus `update` to replace an existing target, and is denied if it would
give the entry more access than it had. A directory rename checks every
existing descendant at both paths, so a permitted parent cannot carry a
denied child somewhere allowed; trees too large to scan fail closed.

**A browsable root.** A literal pattern covers everything below it, so
`allow / read` grants download over the whole jail. To let a partner
browse `/` but download only from named subtrees, give the root `list`:

```zift
allow /                list
allow /orders          read
allow /orders/pending  write update delete rename
```

A directory added under `/` later grants nothing until you say so.

## Patterns

A pattern without `*` or `?` is a literal component prefix: `/pending`
matches `/pending`, `/pending/a.csv` and `/pending/deep/a.csv`, but not
`/pendingfoo`. `/` matches every path.

Any other pattern must match the whole path:

| Token | Matches |
| --- | --- |
| `*` | any run of characters except `/`, possibly empty |
| `?` | one character except `/` |
| `**` | any run of characters, `/` included |
| `**/` | also nothing at all, so `/a/**/b` matches `/a/b` |

Matching is case-sensitive and byte-exact apart from `?`, which takes
one whole UTF-8 character.

Paths are normalized before matching: they start with `/` and have no
`.`, `..`, empty or trailing components, and never name the reserved
`.zift` or `.zift-staging` in any letter case. A pattern that could
never match such a path is rejected with `InvalidPattern`:

| Rejected | Write instead |
| --- | --- |
| `*.exe`, `secret`, `*/a` | `/*.exe` (top level) or `**.exe`, `**/secret` (any depth) |
| `/dir/` | `/dir` |
| `/a//b`, `/a/./b` | `/a/b` |
| `/a/../b` | `/b` |
| `/.zift`, `/in/.zift/**` | nothing: partners can never reach it |

`/dir/**` matches everything below `/dir` but not `/dir` itself. So
`deny **/.ssh/**` refuses every file under any `.ssh` directory, and
because READDIR hides what STAT refuses, listing `.ssh` shows nothing.
Add `deny **/.ssh` if the directory itself should be invisible too.

## Common Policies

```zift
# blind drop: upload new files, see nothing
allow /incoming write

# drop zone: browse, upload new files, never change or delete them
allow / read
allow /incoming write

# recurring feed: may replace their own file, never delete
allow / read
allow /feed write update

# pickup: download, and delete after collection
allow / read
allow /outgoing read delete

# two-way exchange
allow / read
allow /incoming write
allow /outgoing read delete

# workspace they fully manage
allow /workspace full

# reconcile a manifest without fetching contents
allow / list
```

Add carve-outs that must hold whatever else is granted:

```zift
deny **.exe
deny **/.ssh/**
deny **/.git/**
```

## Reloads

Zift checks the config file and every `auth` key file each
`reload-interval`, and reloads when any of their size, mtime, ctime or
inode changes. `SIGHUP` reloads at once, changed or not. A valid config
applies to new connections; each connection keeps the config that was
current when it was accepted until it ends. An invalid one is rejected
and the previous config keeps serving (see
[`operate.md`](operate.md#reload)).

Directories are not watched: after creating a partner root or fixing its
mode, reload by hand. Write config changes atomically (write a
temporary file and rename it into place), or a poll can read a half
written file.

`listen`, `host-key` and `log` are bound at startup. A reload that
changes one logs a warning and keeps the old value; restart to apply
it. `max-connections`, `max-unauth-connections`, `reload-interval` and
`shutdown-grace` apply at once; everything else applies to new
connections.

## SFTP Surface

Zift speaks SFTP version 3 and refuses clients that offer less. It
serves REALPATH, STAT, LSTAT, FSTAT, OPENDIR, READDIR, OPEN, READ,
WRITE, CLOSE, MKDIR, REMOVE, RMDIR, RENAME, SETSTAT and FSETSTAT.
READLINK, SYMLINK, hard links and every EXTENDED request return
OP_UNSUPPORTED, and the session continues.

- **Uploads are atomic.** A new file is written under
  `<root>/.zift/staging/` and renamed into place when the client closes
  it, so a processor watching the target directory never sees a partial
  file. The partner root and the target must be on one filesystem.
  Overwriting an existing file (with `update`) writes in place.
- **SETSTAT and FSETSTAT set times only.** SETSTAT needs `update` on the
  path and never follows a final symlink. FSETSTAT is allowed on the
  partner's own write handle, so `put -p` works into a write-only drop.
  Mode and owner changes are accepted and ignored, since host modes
  belong to the daemon; a size change returns OP_UNSUPPORTED.
- **Listings hide what the partner cannot stat.** READDIR skips any
  entry STAT would refuse, `.zift`, and names with control bytes or
  invalid UTF-8.
- **Symlinks are not followed.** STAT reports a symlink as a symlink,
  directory symlinks cannot be traversed, and OPEN of a symlink, FIFO,
  socket or device is refused.
- **A write-only partner learns nothing about what exists.** Without
  `read` or `list`, a missing and an existing path get the same status.
- Only a missing entry, or a file used as a directory, is NO_SUCH_FILE.
  A server-side problem (out of descriptors, a host permission error) is
  FAILURE, with the reason in the audit line.

## Limits

Fixed in the binary; none is configurable.

| Limit | Value |
| --- | --- |
| Open handles per session | 256 |
| SFTP packet | 256 KiB |
| READ reply | 256 KiB − 13 bytes |
| READDIR reply | about 64 KiB |
| Virtual path | 4096 bytes |
| File name, in any request or listing | 255 bytes |
| Directory rename scan | 100,000 entries, 256 levels |
| Config file | 1 MiB |
| Key file | 32 KiB, and 8 KiB per line |
| Host key file | 64 KiB |
| User name | 64 bytes |
| Audit line | 4096 bytes (longer lines are clipped and marked `truncated`) |
| Login grace, from accept to successful login | 120 s |
| Hard auth failures per connection (bad password, password from outside `from`) | 6 |
| Soft auth operations per connection (key offers, `none`, other messages) | 64 |
| Backoff after the nth hard failure | 250 ms × n |
| Source suppression | 10 hard failures within 10 min block the source for 15 min |
| Pre-auth connections per source | 8 |
| Concurrent password checks | CPU count, clamped to 2..8; 64 MiB each |
| Non-auth messages before the SFTP subsystem | 64 |

A source is an IPv4 address or an IPv6 /64. Abuse controls are described
in [`security.md`](security.md#abuse-controls).
