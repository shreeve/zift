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

Generate a host key and a password hash for a virtual user:

```sh
ssh-keygen -t ed25519 -f /tmp/zift_host_ed25519 -N ""
printf 'secret\n' | bin/zift hash-password
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

user ally
  password $argon2id$v=19$m=65536,t=3,p=1$...
  root /tmp/zift/ally
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

# Atomic upload (the SFTP-classic temp+rename idiom).
allow /          read
allow /staging   add        # tmp file + rename; clobber prevents overwriting
```

### Permission verbs

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

## Production deployment

See [`deploy/DEPLOY.md`](deploy/DEPLOY.md) for the full runbook:
systemd unit, fail2ban filter, ZFS-backed roots, log rotation, and
the recommended user/group/permissions layout.
