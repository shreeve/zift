<p align="center">
  <img src="https://raw.githubusercontent.com/shreeve/zift/main/docs/zift-social.png" alt="Logo" width="640">
</p>

# Zift

> Zift is a small SFTP server for partner file transfer.

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
- no CrowdSec / fail2ban requirement
- one reloadable config file
- one SFTP listener
- virtual users with path-scoped policy
- optional per-user source IP (`from`) policy
- built-in auth backoff and temporary source suppression
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
ZIFT_VERSION=0.10.0
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
tests/run.sh
```

Contributor details are in [`docs/develop.md`](docs/develop.md).

## Minimal Example

Add a partner `foo` with password `bar` and the usual B2B path
policy: browse `/`, upload under `/pending`, read `/archive`.

```sh
# host key + partner directories (partner-root /tmp/zift => root /tmp/zift/foo)
ssh-keygen -t ed25519 -f /tmp/zift_host_ed25519 -N ""
mkdir -p /tmp/zift/foo/{pending,archive}

# password hash — paste the full a… line into the config below
printf '%s\n' 'bar' | bin/zift hash-password
```

Write `/tmp/zift/example.zift` (replace `a…` with the hash you just
printed):

```zift
server
  listen 127.0.0.1:2222
  host-key /tmp/zift_host_ed25519
  partner-root /tmp/zift
  reload-interval 2s
  idle-timeout 5m
  max-connections 14
  max-unauth-connections 4
  log stderr

user foo
  from 127.0.0.1
  auth a…
  allow / read
  allow /pending write read update delete
  allow /archive read
  deny **.exe
  deny **/.ssh/**
```

Validate and serve:

```sh
bin/zift validate /tmp/zift/example.zift
bin/zift serve /tmp/zift/example.zift
```

Connect with any normal SFTP client (password `bar`):

```sh
sftp -P 2222 foo@127.0.0.1
```

For production onboarding (service user, directory modes, reload),
see [`docs/operate.md`](docs/operate.md). Full grammar is in
[`docs/configure.md`](docs/configure.md).

## Permissions

Policy is default-deny and path-scoped. A partner with valid credentials
and no `allow` lines can authenticate and do nothing.

There are exactly two kinds of rule:

- **`allow <pattern> <verbs…>`** grants verbs on matching virtual paths.
- **`deny <pattern>`** refuses matching virtual paths outright. It takes
  no verbs, because it removes everything.

**`deny` always wins.** Order does not matter, and neither does
specificity: the first matching `deny` ends the decision, so a broad
`deny **.exe` overrides a narrow `allow /incoming write`. Use `allow` to
describe the shape of the job and `deny` to carve out what must never
happen regardless.

Four verbs cover almost every policy:

| Verb | Grants |
| --- | --- |
| `read` | stat, list, and download |
| `write` | bring a **new** file into existence |
| `update` | replace, truncate, or append to an entry that **already exists** |
| `delete` | remove an entry |

`full` is shorthand for `read list write update delete mkdir rename`.

Three granular verbs exist for narrower policies. Reach for them only
when the four above cannot say what you mean:

| Verb | Grants |
| --- | --- |
| `list` | stat and listing, without download |
| `mkdir` | directory creation only |
| `rename` | rename only, checked on both source and destination |

`rename` is not one of the everyday verbs because it is not one
operation: it destroys a name and creates another. Granting it means
granting both halves, which is why `write` alone never implies it — a
write-only partner could otherwise hide a file by renaming it.

### `write` is not `update`

`write` brings a **new** name into existence. Replacing something that
already exists is `update`. That includes overwriting, truncating,
appending, and renaming over an existing file.

```zift
allow /pending read write           # upload new files; cannot touch existing ones
allow /pending read write update    # ...and may replace their own files
allow /pending full                 # ...and may delete them too
```

Keeping these separate is what makes the most common B2B feed
expressible: a partner who re-sends `daily.csv` every morning needs
`update`, and should almost never need `delete`.

Before v0.9.2 these were one verb (`remove`), so overwriting required
granting deletion. The `add`, `create`, and `remove` verbs were retired
in 0.10.0 and are now rejected outright — configs that used them must
migrate to the CRUD verbs (`add` and `create` become `write`; `remove`
becomes `delete`). New configs should say what they mean.

### Patterns

Patterns match virtual paths, never host paths.

Literal patterns match whole path components, so `/pending` matches
`/pending`, `/pending/file.csv`, and `/pending/deep/file.csv` — but not
`/pendingfoo` or `/pending-archive`.

| Pattern | Meaning |
| --- | --- |
| `*` | any sequence except `/` |
| `?` | one character except `/` |
| `**` | any sequence including `/` |

`deny` always overrides `allow`, whatever the order or specificity.
Prefer explicit patterns over clever ones.

### Policies that cover most of the real cases

```zift
# blind drop: send files, cannot see or retrieve anything
allow /incoming write

# drop zone: browse, upload new files, never modify or delete
allow / read
allow /incoming write

# recurring feed: may replace their own file, may never delete
allow / read
allow /feed write update

# drop zone they can fully manage
allow / read
allow /incoming write update delete

# pickup: download and clean up after collection
allow / read
allow /outgoing read delete

# archive: browse and download, nothing else
allow / read

# two-way exchange
allow / read
allow /incoming write
allow /outgoing read delete

# mutable workspace
allow /workspace full

# reconcile a manifest without being able to fetch the contents
allow / list
```

Add these to any policy — they cost nothing and close common mistakes:

```zift
deny **.exe
deny **/.ssh/**
deny **/.git/**
```

### Restrict the network too

Path policy answers *what*. `from` answers *from where*, and it is
checked before authentication is attempted:

```zift
user ally
  from 203.0.113.40
  from 198.51.100.0/28
  auth a…
  allow / read
  allow /incoming write
```

Each line is one IPv4/IPv6 address or CIDR. With any `from` present, a
peer that matches none of them cannot authenticate at all. If your
partners have stable egress addresses, this is the cheapest hardening
available: partner identity, partner network, and path policy in one
reviewable block.

### Two things that will cost you time

**A partner's `root` must already exist.** If it does not, the whole
config is rejected — not just that user. Zift keeps serving the previous
config, so the partner you just added simply does not exist, and their
client reports a generic `Permission denied` that looks exactly like a
bad password. Create the directory first:

```sh
sudo install -d -o zift -g zift -m 2770 /home/zift/ally
```

**Always validate before reloading.** A rejected config is never
applied, which is the safe behavior, but it is also silent from the
client's point of view. `validate` tells you the reason immediately:

```sh
zift validate /home/zift/zift.conf   # ok: ... (1 user, listen 0.0.0.0:2222)
sudo systemctl reload zift
journalctl -u zift -f                # what the daemon actually did
```

Reloads apply to new sessions only, and are triggered by the config file
mtime moving forward or by `SIGHUP`. Changing anything *around* the
config — creating a partner root, adding a key file, fixing modes —
leaves the mtime untouched, so reload by hand after those.

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

## License

Zift is released under the [MIT License](LICENSE).

Release binaries statically link libssh (LGPL-2.1), mbedTLS (Apache-2.0),
and zlib (zlib license). See
[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md) for attribution and
license texts.

## Security

To report a suspected vulnerability privately, see
[`SECURITY.md`](SECURITY.md). For deployment hardening and threat model,
see [`docs/security.md`](docs/security.md).
