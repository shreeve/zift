# Zift

Zift is a single-binary SFTP server for partner file transfer.

It is built for the common B2B case where OpenSSH `internal-sftp` plus
OS users has become awkward, but a managed file transfer platform is too
large, too stateful, or too expensive to trust for a narrow job.

Zift has:

- no web UI
- no database
- no OS users per partner
- no chroot setup
- no plugin system
- no telemetry
- one reloadable config file
- one SFTP listener
- virtual users with path-scoped policy
- structured JSON audit logs
- static Linux release binaries

The goal is boring software: install it, configure partner roots and
credentials, then let ordinary SFTP clients move files.

## Should I Use It?

Use Zift if you operate file exchange for a modest number of external
partners, want onboarding to be a text-file edit, and prefer a small
runtime surface over a feature platform.

Do not use Zift if you need a browser UI, SSO, LDAP/AD/PAM, FTP/FTPS,
AS2, scheduling, EDI parsing, clustering, self-service users, quotas,
or a database-backed management plane.

Start with [`docs/evaluate.md`](docs/evaluate.md).

## Quick Install

Pick the binary for your host from a GitHub release.

```sh
# Linux x86_64
ZIFT_VERSION=0.7.1
curl -fsSLO "https://github.com/shreeve/zift/releases/download/v${ZIFT_VERSION}/zift-${ZIFT_VERSION}-x86_64-linux"
chmod +x "zift-${ZIFT_VERSION}-x86_64-linux"
sudo install -m 0755 "zift-${ZIFT_VERSION}-x86_64-linux" /usr/local/bin/zift

zift version
```

Release artifacts also include a `SHA256SUMS` manifest and
`SHA256SUMS.bundle` signature. Production installs should verify both:

```sh
curl -fsSLO "https://github.com/shreeve/zift/releases/download/v${ZIFT_VERSION}/SHA256SUMS"
curl -fsSLO "https://github.com/shreeve/zift/releases/download/v${ZIFT_VERSION}/SHA256SUMS.bundle"

cosign verify-blob \
  --bundle SHA256SUMS.bundle \
  --certificate-identity-regexp 'https://github.com/shreeve/zift/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS

sha256sum -c SHA256SUMS --ignore-missing
```

On macOS, use `shasum -a 256 -c SHA256SUMS --ignore-missing` if
`sha256sum` is not installed.

For a production runbook, read [`docs/operate.md`](docs/operate.md).

## Build From Source

Zift requires Zig `0.16.0`.

`libssh`, `mbedTLS`, and `zlib` are pinned in `build.zig.zon` and built
from source by the Zig build. No system package is required for release
builds.

```sh
zig build
bin/zift version
zig build test
```

Integration tests require Python 3, Paramiko, OpenSSH client tools,
`expect`, and `lsof`:

```sh
test/run.sh
```

Contributor details are in [`docs/develop.md`](docs/develop.md).

## Minimal Example

Generate a host key and a partner password hash:

```sh
ssh-keygen -t ed25519 -f /tmp/zift_host_ed25519 -N ""
printf '%s\n' 'partner-secret' | bin/zift hash-password
```

Create a partner root:

```sh
mkdir -p /tmp/zift/ally/{pending,archive}
```

Write a config to `/tmp/zift/example.zift`. Paste the full Argon2id hash
printed by `bin/zift hash-password` in place of the abbreviated
`$argon2id$...` line:

```zift
server
  listen 127.0.0.1:2222
  host-key /tmp/zift_host_ed25519
  partner-root /tmp/zift
  reload-interval 2s
  idle-timeout 5m
  max-connections 128
  max-unauth-connections 32
  log stderr

user ally
  auth $argon2id$v=19$m=65536,t=3,p=1$...
  allow / read
  allow /pending read add remove
  allow /archive read
  deny **.exe
  deny **/.ssh/**
```

Run it:

```sh
bin/zift validate /tmp/zift/example.zift
bin/zift serve /tmp/zift/example.zift
```

Connect with any normal SFTP client:

```sh
sftp -P 2222 ally@127.0.0.1
```

Configuration details are in [`docs/configure.md`](docs/configure.md).

## Documentation

- [`docs/evaluate.md`](docs/evaluate.md): product rationale, audience,
  tradeoffs, and comparisons.
- [`docs/operate.md`](docs/operate.md): installation, deployment,
  supervision, reloads, logs, backups, and rollback.
- [`docs/configure.md`](docs/configure.md): config grammar, virtual
  users, auth, roots, permissions, patterns, and examples.
- [`docs/security.md`](docs/security.md): threat model, guarantees,
  caveats, audit posture, and deployment hardening.
- [`docs/develop.md`](docs/develop.md): source layout, build system,
  tests, CI, release workflow, and maintenance notes.

