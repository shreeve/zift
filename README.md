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
  allow /pending read write list mkdir remove rename
  allow /archive read list
  allow / read list
  # `**` crosses path boundaries (gitignore-style); `*` does not.
  deny **.exe
  deny **/.ssh/**
```

Permissions are default-deny. `deny` rules override `allow` rules.

## Production deployment

See [`deploy/DEPLOY.md`](deploy/DEPLOY.md) for the full runbook:
systemd unit, fail2ban filter, ZFS-backed roots, log rotation, and
the recommended user/group/permissions layout.
