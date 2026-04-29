# Zift

A single-binary SFTP server with virtual users and a small attack surface.
No web UI. No database. No OS users. No chroot games. One reloadable config
file. Designed for partner file transfers where reliability beats features.

## Install

Pick the right binary for your host. Every release ships fully-static
binaries with zero runtime dependencies — drop in on any Linux 3.x+ host
or macOS 11+ without `apt install` / `brew install` anything.

```sh
# Linux x86_64 (most common)
curl -fsSLO https://github.com/shreeve/zift/releases/latest/download/zift-0.2.2-x86_64-linux
chmod +x zift-0.2.2-x86_64-linux
sudo install -m 0755 zift-0.2.2-x86_64-linux /usr/local/bin/zift

# Linux aarch64 (Graviton, ARM servers, RPi)
curl -fsSLO https://github.com/shreeve/zift/releases/latest/download/zift-0.2.2-aarch64-linux

# macOS Apple Silicon
curl -fsSLO https://github.com/shreeve/zift/releases/latest/download/zift-0.2.2-aarch64-macos

# macOS Intel
curl -fsSLO https://github.com/shreeve/zift/releases/latest/download/zift-0.2.2-x86_64-macos

zift version
```

### Verify provenance + integrity (recommended for partner deploys)

Every release is signed with [cosign keyless](https://docs.sigstore.dev/cosign/signing/overview/)
through GitHub Actions OIDC, so partners can verify a binary genuinely
came from this repo's release workflow at the tagged commit:

```sh
curl -fsSLO https://github.com/shreeve/zift/releases/latest/download/SHA256SUMS
curl -fsSLO https://github.com/shreeve/zift/releases/latest/download/SHA256SUMS.bundle
cosign verify-blob \
    --bundle SHA256SUMS.bundle \
    --certificate-identity-regexp 'https://github.com/shreeve/zift/.+' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    SHA256SUMS
sha256sum -c SHA256SUMS
```

## Build from source

Requires only Zig 0.16.0. libssh, mbedTLS, and zlib are vendored via
`build.zig.zon` and compiled from source — no system packages.

```sh
zig build
bin/zift version
```

The dev binary lands at `bin/zift`. Run unit tests with `zig build test`.
The integration suite (paramiko + expect, requires Python 3) is
`test/run.sh`.

## Local releases (cross-compile)

`zig build release` produces a versioned, fully-static artifact for
any of the four supported targets. ~10 seconds per target on a modern
laptop. Output lands in `./release/`.

```sh
# Pick one (or run all four in a loop):
zig build release -Dtarget=x86_64-linux-musl   -Dversion=0.2.2-dev   # Linux x86_64
zig build release -Dtarget=aarch64-linux-musl  -Dversion=0.2.2-dev   # Linux aarch64
zig build release -Dtarget=aarch64-macos       -Dversion=0.2.2-dev   # Apple Silicon
zig build release -Dtarget=x86_64-macos        -Dversion=0.2.2-dev   # Intel Mac

# Or all at once:
for t in x86_64-linux-musl aarch64-linux-musl x86_64-macos aarch64-macos; do
    zig build release -Dtarget=$t -Dversion=0.2.2-dev
done
ls release/
```

The `-Dversion=` flag is optional — defaults to the value in
`build.zig`. Use a `-dev` suffix to keep dev binaries distinguishable
from CI-published releases.

The locally-built binary's executable code is byte-identical to the
CI release (verified by `llvm-strip`-ing both and comparing SHA256).
Only the DWARF debug paths differ. So a local cross-compile is a
fully-functional drop-in replacement for the CI artifact — it just
won't have the cosign signature, since the OIDC identity binding is
what proves a binary came from CI rather than your laptop.

## Tagged releases (CI publish)

Push a `vX.Y.Z` tag and the release workflow builds + signs + publishes
all four binaries to a GitHub Release in ~5 minutes:

```sh
# Bump default_version in build.zig, then:
git tag -a v0.2.3 -m "release notes..."
git push origin v0.2.3
```

Tag format: `vX.Y.Z[-prerelease]`. Prerelease tags (`v0.3.0-rc.1`)
auto-flag as GitHub prereleases.

## Run

Generate a host key and provision per-partner credentials. Each
partner can authenticate by password, key, or both:

```sh
ssh-keygen -t ed25519 -f /tmp/zift_host_ed25519 -N ""

# Option A — password (Argon2id PHC string).
printf 'secret\n' | bin/zift hash-password
# → $argon2id$v=19$m=65536,t=3,p=1$...

# Option B — public key. Generate one (or accept the partner's
# `id_ed25519.pub`) and store it in an operator-managed file.
ssh-keygen -t ed25519 -f /tmp/zift/keys/ally -N "" -C "ally"
# → /tmp/zift/keys/ally.pub
```

Create the partner's root, edit `example.zift`, then start:

```sh
mkdir -p /tmp/zift/ally/{pending,archive}
bin/zift serve example.zift
```

Connect with any stock SFTP client:

```sh
sftp -P 2222 ally@127.0.0.1
```

## Config

Zift watches the config file's mtime and reloads for new sessions
when it changes. Adding a user is copy/paste/edit/save — no restart,
no SIGHUP needed (though `kill -HUP $PID` forces an immediate reload
if you want).

```text
server
  listen 127.0.0.1:2222
  host-key /tmp/zift_host_ed25519
  reload-interval 2s
  idle-timeout 5m
  max-connections 128
  max-unauth-connections 32
  log stderr
  # When set, a user without an explicit `root` directive defaults
  # to `<partner-root>/<user-name>`. Skip the directive entirely if
  # you'd rather declare each root explicitly per-user.
  partner-root /tmp/zift

user ally
  # `auth <value>` — v0.7.0 unified credential directive.
  #   - $argon2id...   ⇒ password (Argon2id PHC string; one per user)
  #   - /absolute/path ⇒ public-key file (operator-managed; multiple OK)
  auth $argon2id$v=19$m=65536,t=3,p=1$...
  auth /tmp/zift/keys/ally.pub
  # `partner-root` above makes `root /tmp/zift/ally` the default.
  allow /             read              # `read` covers list+stat+download
  allow /pending      read add remove   # full mutate (or `full` for short)
  allow /archive      read              # read-only browse
  # `**` crosses path boundaries (gitignore-style); `*` does not.
  deny **.exe
  deny **/.ssh/**
```

### Common workflow patterns

```zift
# Drop-zone: vendor uploads, can't read others' files, can't delete.
allow /          read      # ls /, see one's own uploads
allow /incoming  add       # upload only; clobber rule blocks overwriting

# Pickup-and-clear: partner downloads + deletes after consumption.
allow /          read
allow /reports   read remove

# Read-only archive.
allow /          read

# Mutable workspace (full r/w/d).
allow /workspace full
```

### Atomic uploads (v0.5.0+)

Zift uploads new files through a server-side staging area before
publishing them at their target path. Partners do `OPEN(write+CREAT,
/pending/report.csv)` and zift writes to a randomly-named file under
`/.zift-staging/` instead. Only when the partner sends `CLOSE` does
zift atomically rename the staging file to the real target.

This means an operator's processor watching `/pending` never sees a
half-uploaded file. Partial bytes only ever exist at the staging
path (which is hidden from partners' listings AND rejected by the
SFTP path-validator). When `report.csv` appears at the partner-
visible path, it's complete.

Effects worth knowing:

- **The classic `temp + rename` idiom is still safe but no longer
  necessary.** Partners can upload directly with the final filename.
  The atomicity is automatic.
- **Disconnect during upload = clean state.** If the partner's
  connection drops mid-upload, the staging file is unlinked when
  the session tears down. The target was never published.
- **Clobber checked at CLOSE.** If another session created the
  target between this session's OPEN and CLOSE, the publish step
  re-runs the clobber rule. Without `remove` permission on the
  destination, the upload is refused and the racer's content
  survives. Like the rename-over-existing guard, this has a small
  stat-then-rename TOCTOU window: a target that appears between
  zift's lstat and rename calls would still be overwritten. Closing
  this race hermetically requires `renameat2(RENAME_NOREPLACE)` on
  Linux / `renamex_np(RENAME_EXCL)` on macOS, tracked as P2.
- **Staging files cost the same disk space as the target.** A 1 GB
  upload occupies ~1 GB in `.zift-staging/` until CLOSE renames
  it, then 0 in staging and 1 GB at the target.
- **Write-on-existing-files bypasses staging.** If the target
  already exists at OPEN time, the v0.4.0 clobber rule kicks in:
  either the partner has `remove` (direct write to existing
  inode, no staging) or the OPEN is denied. Staging only applies
  to creating-new-file workflows.

#### Filesystem caveats

Zift's staging directory lives at `<root>/.zift-staging/`, sibling
to every partner-visible subdirectory. The atomic rename at CLOSE
moves bytes from this single staging location to the actual target
path, which means:

- **Same-filesystem requirement.** If a partner-visible directory
  (e.g. `/pending`) is a bind mount or separate filesystem from
  the partner root, the rename fails with `EXDEV` and the upload
  is refused at CLOSE. Keep partner roots on a single filesystem
  per partner. (Cross-filesystem staging would require copy-then-
  unlink, which loses atomicity — not a tradeoff zift makes.)
- **Default ACLs and `setgid` directories don't transfer.** A
  `setgid` group bit on `/pending`, or a default POSIX ACL on the
  target parent, applies at file-create time — which under zift
  staging happens in `.zift-staging/`, not the target parent. The
  rename inherits the original create-time ownership and ACLs
  unchanged. If your processor relies on group-inheritance via
  `setgid` directories, set the equivalent default ACL on the
  partner root itself, or apply group-fixup in your processor.

#### Operator notes

- **Staging directory is created lazily** on first upload.
  Operators don't need to provision it.
- **Cross-restart orphan sweep.** If zift itself crashes mid-
  upload, staging files persist after restart. Zift does not
  currently sweep them at startup (tracked as P3). Operators with
  a hard zift crash can manually clear:

      rm -f <partner-root>/.zift-staging/*

  Always safe — partners can never reach that path via the SFTP
  wire surface (the path-validator rejects any path containing
  `.zift-staging`, regardless of operation).
- **Confidentiality.** Fresh staging directories are created
  `0o700` and staging files `0o600` — partial-upload bytes are
  not readable by other local users on the host.
- **v0.5.0 → v0.5.1 upgraders, read this:** in v0.4.0 and
  earlier, `.zift-staging` was a legal partner-creatable name,
  so a partner with `add` could have planted a SYMLINK with that
  name pointing outside their jail. v0.5.0 created the directory
  with the default mode (often `0o755`, world-listable). v0.5.1
  rejects both shapes:
    - Non-directory `<root>/.zift-staging` (symlink, regular file,
      FIFO, etc.) → `error.StagingDirCorrupt`. Fix: `rm -f
      <root>/.zift-staging` and zift recreates at `0o700`.
    - Real directory but group/other-accessible (any of `0o077`
      bits set) → `error.StagingDirUnsafe`. Fix: `chmod 0700
      <root>/.zift-staging` (or `rm -rf` and recreate). The
      strict mode requirement protects in-flight bytes from
      local users AND prevents the rename-by-path syscall from
      racing against an attacker who can mutate the staging
      directory's contents.

### Permission verbs

> **v0.3.x → v0.4.0 migration note.** In v0.3.x, `read` granted
> stat + download only; you had to write `read list` to also allow
> `ls`/readdir. Starting in v0.4.0, **bare `read` includes `list`**.
> This affects existing configs: `allow /pending read` now permits
> directory listing in addition to download. The narrow form `list`
> still means "stat + readdir, no download" (so this is not a
> download privilege expansion, but it is a discovery/enumeration
> expansion). If your v0.3.x config relied on read-without-list
> as a partial-information defense (rare), audit those rules and
> swap to bare `list` where appropriate.

Three primary verbs cover every SFTP wire op a partner can perform:

| Verb | Grants |
|---|---|
| `read` | stat + readdir + download (covers SSH_FXP_OPEN(read), STAT, LSTAT, OPENDIR, READDIR) |
| `add` | upload + mkdir + rename (covers SSH_FXP_OPEN(write), MKDIR, RENAME) |
| `remove` | unlink + rmdir + clobber authority (covers SSH_FXP_REMOVE, RMDIR; required to modify or rename-over an existing entry) |

Plus one shorthand:

| Verb | Grants |
|---|---|
| `full` | `read + add + remove` |

And four advanced/granular escapes for tight-control workflows:

| Verb | Grants |
|---|---|
| `list` | stat + readdir only, **no download** (rare; e.g. tokenized-name delivery) |
| `write` | upload only (no mkdir, no rename) — for immutable-receive workflows |
| `mkdir` | create directories only |
| `rename` | rename only (still subject to the clobber rule on the destination) |

Permissions are **default-deny**. `deny` rules override `allow` rules.

### The clobber rule

A core security invariant of zift v0.4.0+:

> **Any operation that would modify or replace an existing entry
> requires `remove` permission on that entry's path, in addition to
> whatever verb (`add`, `write`, `rename`) authorizes the operation
> itself.**

Concretely, with `add` granted but `remove` NOT granted, a partner
can:

- Create new files, directories, and symlinks (where the destination
  doesn't already exist).
- Rename their own creations to fresh names (where the destination
  doesn't already exist).

But CANNOT:

- Truncate-and-rewrite an existing file (`SSH_FXP_OPEN(write+TRUNC)`).
- Modify bytes of an existing file in place (partial pwrite, append).
- Rename over an existing file/dir (would destroy the destination).
- Delete files or directories.

To get those, grant `remove` (or use `full = read + add + remove`).

The rule applies uniformly across all destructive paths — write-open,
rename, and (transitively) the temp+rename idiom that classical SFTP
clients use for "atomic upload."

| Setup | Create new file | Overwrite existing file | Rename to new name | Rename over existing | Delete |
|---|---|---|---|---|---|
| `read` | no | no | no | no | no |
| `read add` | yes | **no** | yes | **no** | no |
| `read add remove` (= `full`) | yes | yes | yes | yes | yes |
| `read remove` | no | no (no add) | no (no add) | no (no add) | yes |

The rename-over-existing guard has a small stat-then-rename TOCTOU
window — closing it hermetically requires `renameat2(RENAME_NOREPLACE)`
on Linux or `renamex_np(RENAME_EXCL)` on macOS, tracked as a P2
follow-up. Write-open's clobber check is race-free (the existence
test is implicit in `openFile` returning either a usable fd OR
`FileNotFound`, with no separate stat).

### Listing mode

By default (`listing-mode virtual`, the v0.3.0+ default), `sftp> ls -la`
shows partners their own virtual-user name, a fixed group of `sftp`,
and policy-derived `rwx` bits — they see what they CAN DO, not who
owns the file on the server's disk. The world triplet is always `---`
(there's no third class of viewer in their jail). Setuid/setgid/sticky
bits are stripped from the displayed mode.

Add `listing-mode reality` to the `server` block if you want the
on-disk owner/group/mode to pass through unchanged (rare; mostly
useful for debugging).

## Migrating v0.6.x configs to v0.7.0

v0.7.0 makes three breaking changes to the config grammar. There is
no backward compatibility — Zift refuses to load a v0.6.x config until
you update it. The error messages name the directive and the migration:

| v0.6.x                          | v0.7.0                                | Notes                                                                 |
| ------------------------------- | ------------------------------------- | --------------------------------------------------------------------- |
| `password $argon2id$...`        | `auth $argon2id$...`                  | Same Argon2id PHC string; one per user.                               |
| `key ssh-ed25519 AAAA... alice` | `auth /home/zift/keys/alice.pub`      | Public keys move to operator-managed files; multiple `auth /path` lines accumulate. |
| `root /home/zift/alice` per user | `partner-root /home/zift` (server-level) | Optional shorthand: `root` defaults to `<partner-root>/<user-name>`. Explicit per-user `root` still wins. |

`zift validate` on a v0.6.x config now emits one of:

```text
zift: zift.conf:line N: [user alice] 'password': PasswordDirectiveRemoved
zift: zift.conf:line N: [user alice] 'key': KeyDirectiveRemoved
```

so the spot to edit is unambiguous. A typical v0.6 → v0.7 migration:

```diff
 server
   listen 0.0.0.0:2222
   host-key /home/zift/host_ed25519
+  partner-root /home/zift

 user alice
-  password $argon2id$v=19$m=65536,t=3,p=1$...
-  key ssh-ed25519 AAAA... alice@laptop
-  root /home/zift/alice
+  auth $argon2id$v=19$m=65536,t=3,p=1$...
+  auth /home/zift/keys/alice.pub
   allow /inbox  read add
   allow /outbox read
```

Public-key files are validated at config load:

- The path must be absolute.
- The file must be a regular file (no FIFOs / devices / dangling symlinks).
- The file's mode must NOT have group-write or world-write bits — a writable key file is equivalent to a writable password hash, and Zift refuses to load a config that points at one. Recommended: `chmod 0640` and `chown root:zift /home/zift/keys/<partner>.pub`.
- Each non-empty/non-comment line is parsed as a `<algorithm> <blob> [comment]` triple, exactly like a single-line `.pub` file.

Audit logs gain a leading `time` field (RFC 3339 UTC milliseconds,
e.g. `"time":"2026-04-29T10:17:39.124Z"`). Existing `jq`/awk
filters that key on `event` / `operation` / `result` / `ip` continue
to work; downstream consumers that asserted the line started with
`{"event":...` need a one-character fix.

## Production deployment

See [`deploy/DEPLOY.md`](deploy/DEPLOY.md) for the full runbook:
systemd unit, fail2ban filter, ZFS-backed roots, log rotation, and
the recommended user/group/permissions layout.
