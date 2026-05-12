# Operate Zift

This guide describes a production-style Linux deployment.

The recommended layout keeps all Zift runtime state under one tree:

```text
/home/zift/
├── zift.conf
├── host_ed25519
├── host_ed25519.pub
├── audit.jsonl
├── keys/
│   └── ally.pub
├── ally/
│   ├── pending/
│   ├── archive/
│   └── .zift/
│       ├── staging/                (daemon-owned upload staging)
│       └── notes.md                (optional operator-managed; partner-invisible)
└── other-partner/
    └── ...
```

This is a convention, not a hardcoded path. Zift only cares about the
paths in its config.

## Install The Binary

Download the binary for your host:

```sh
ZIFT_VERSION=0.8.0
ARCH=$(uname -m)

curl -fsSLO "https://github.com/shreeve/zift/releases/download/v${ZIFT_VERSION}/zift-${ZIFT_VERSION}-${ARCH}-linux"
sudo install -m 0755 "zift-${ZIFT_VERSION}-${ARCH}-linux" /usr/local/bin/zift
zift version
```

Supported release targets:

- `x86_64-linux`
- `aarch64-linux`
- `x86_64-macos`
- `aarch64-macos`

Linux release binaries are static musl binaries. They do not require
`libssh`, `mbedTLS`, `zlib`, or libc packages on the target host.

## Verify Release Provenance

Production installs should verify both the signed checksum manifest and
the binary hash.

```sh
ZIFT_VERSION=0.8.0

curl -fsSLO "https://github.com/shreeve/zift/releases/download/v${ZIFT_VERSION}/SHA256SUMS"
curl -fsSLO "https://github.com/shreeve/zift/releases/download/v${ZIFT_VERSION}/SHA256SUMS.bundle"

cosign verify-blob \
  --bundle SHA256SUMS.bundle \
  --certificate-identity-regexp 'https://github.com/shreeve/zift/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS

sha256sum -c SHA256SUMS --ignore-missing
```

The cosign certificate binds the signature to the GitHub Actions
workflow for this repository. The checksum check binds the downloaded
binary bytes to the signed manifest.

## Create The Service User

Create a dedicated unprivileged user:

```sh
sudo useradd --system --create-home --home-dir /home/zift \
  --shell /usr/sbin/nologin zift
```

Harden the top-level directory so the daemon can traverse it but cannot
rewrite the config or host key when those files are owned by `root:zift`:

```sh
sudo chown root:zift /home/zift
sudo chmod 0750 /home/zift
```

Create the audit file before starting the daemon:

```sh
sudo touch /home/zift/audit.jsonl
sudo chown zift:zift /home/zift/audit.jsonl
sudo chmod 0640 /home/zift/audit.jsonl
```

## Generate The Host Key

```sh
sudo ssh-keygen -t ed25519 -f /home/zift/host_ed25519 -N ""
sudo chown root:zift /home/zift/host_ed25519 /home/zift/host_ed25519.pub
sudo chmod 0640 /home/zift/host_ed25519
sudo chmod 0644 /home/zift/host_ed25519.pub
```

The daemon needs read access to the private key. It does not need write
access.

## Create Partner Credentials

Password credential:

```sh
printf '%s\n' 'ally-secret' | zift hash-password
```

Public-key credential:

```sh
sudo install -d -o root -g zift -m 0750 /home/zift/keys
sudo install -o root -g zift -m 0640 ally.pub /home/zift/keys/ally.pub
```

Here `ally.pub` is the partner's OpenSSH public key, supplied out of
band. Public-key files must not be group-writable or world-writable. A
writable key file is equivalent to a writable credential.

## Create Partner Roots

```sh
sudo install -d -o zift -g zift -m 2770 /home/zift/ally
sudo install -d -o zift -g zift -m 2770 /home/zift/ally/pending
sudo install -d -o zift -g zift -m 2770 /home/zift/ally/archive
```

The setgid bit keeps new directories in group `zift`, which makes
operator access predictable.

## Operator Access

Operators who need host-side access can join group `zift`:

```sh
sudo usermod -aG zift "$USER"
```

Log out and back in before relying on the new group membership. When
dropping files into partner directories from the host side, use
`install -m 0660 -g zift ...` or set `umask 007` first. The setgid bit
keeps the group as `zift`, but an ordinary shell umask still controls
the file mode.

Config and host key stay `root:zift` and not group-writable so a daemon
compromise cannot edit its own config or server identity. The audit log
is readable by group `zift`, but only the daemon should write it.

## Write The Config

Install the starter config:

```sh
sudo install -o root -g zift -m 0640 packaging/deploy/zift.conf.example /home/zift/zift.conf
sudo -e /home/zift/zift.conf
```

Minimal production shape:

```zift
server
  listen 0.0.0.0:2222
  host-key /home/zift/host_ed25519
  partner-root /home/zift
  reload-interval 2s
  idle-timeout 5m
  max-connections 14
  max-unauth-connections 4
  log /home/zift/audit.jsonl
  listing-mode virtual
  publish-mode 0o660
  mkdir-mode 0o2770

user ally
  auth $argon2id$v=19$m=65536,t=3,p=1$...
  auth /home/zift/keys/ally.pub
  allow / read
  allow /pending read add remove
  allow /archive read
  deny **.exe
  deny **/.ssh/**
```

Validate:

```sh
sudo -u zift zift validate /home/zift/zift.conf
```

Validation checks syntax plus live filesystem invariants:

- host key is readable
- partner roots exist
- partner roots are directories
- partner roots do not overlap after symlink resolution
- public-key files are readable, non-symlink regular files, not
  group-writable or world-writable, non-empty, and parse as supported
  OpenSSH public keys
- pre-auth cap does not exceed total connection cap

## Install systemd Unit

The repository ships `packaging/systemd/zift.service`, configured for
`/home/zift`.

```sh
sudo install -m 0644 packaging/systemd/zift.service /etc/systemd/system/zift.service
sudo systemd-analyze verify /etc/systemd/system/zift.service
sudo systemctl daemon-reload
sudo systemctl enable --now zift
sudo systemctl status zift
```

The unit runs as `zift:zift`, confines filesystem access to
`/home/zift`, restricts address families to IPv4/IPv6, removes
capabilities, applies syscall filters, and sets `MemoryMax=4G`.

To rotate the SSH host key, generate the new key, update `host-key` if
the path changes, restart Zift, and notify partners that the host
fingerprint changed. `SIGHUP` reloads config for new sessions but does
not rotate the running host key.

Pair `MemoryMax` with config values. At the top Argon2id envelope,
password verification may use 256 MiB per in-flight verification.
The starter config keeps `max-connections * 256 MiB` below the unit's
4G memory limit.

## Firewall

Zift does not implement IP allowlists. Use your host or cloud firewall.

UFW example:

```sh
sudo ufw allow from PARTNER_IP_1 to any port 2222 proto tcp
sudo ufw allow from PARTNER_IP_2 to any port 2222 proto tcp
sudo ufw deny 2222/tcp
```

UFW processes these rules in order; the earlier partner `allow` rules
win before the final deny.

Keep SSH admin access separate from the Zift SFTP port.

## Start, Stop, Reload

Start:

```sh
sudo systemctl start zift
```

Stop:

```sh
sudo systemctl stop zift
```

Restart:

```sh
sudo systemctl restart zift
```

Force config reload:

```sh
sudo systemctl kill -s HUP zift
```

Zift also watches the config mtime according to `reload-interval`.
Reloads affect new sessions only. Existing sessions keep their current
config snapshot until disconnect.

mtime polling only notices config files whose timestamp moves forward.
If your deploy tool preserves or rewinds mtimes, send `SIGHUP` after the
file is in place.

## Add A Partner

1. Create the partner data tree.
2. Create or install credentials.
3. Edit `zift.conf`.
4. Validate.
5. Send `SIGHUP` or wait for `reload-interval`.

Example:

```sh
sudo install -d -o zift -g zift -m 2770 /home/zift/vendor/incoming
sudo install -d -o zift -g zift -m 2770 /home/zift/vendor/archive
printf '%s\n' 'vendor-secret' | zift hash-password
sudo -e /home/zift/zift.conf
sudo -u zift zift validate /home/zift/zift.conf
sudo systemctl kill -s HUP zift
```

If the edited config is invalid, the running daemon keeps the previous
config. Validate anyway so mistakes are caught before operators rely on
reload behavior.

## Remove A Partner

Delete or comment out the `user <name>` block and reload.

Existing sessions authenticated before the reload continue until they
disconnect. New auth attempts for that user fail.

To immediately cut off active sessions, restart the service after
removing the user.

## Logs

Zift writes two kinds of output:

- human-readable operational messages to stderr
- structured audit JSON lines to `server.log`

When `log stderr` is used, both go to the supervisor. When `log` points
to a file, audit lines go to that file and operational warnings still
go to stderr.

Audit lines are one JSON object per line. Typical fields include:

- `time`
- `event`
- `user`
- `operation`
- `result`
- `path`
- `detail`
- `ip`
- `truncated`

Use line-oriented tools:

```sh
tail -F /home/zift/audit.jsonl
jq -c 'select(.result=="denied")' /home/zift/audit.jsonl
```

## Log Rotation

Install the shipped logrotate rule:

```sh
sudo install -m 0644 packaging/logrotate/zift.conf /etc/logrotate.d/zift
sudo logrotate -d /etc/logrotate.d/zift
```

The postrotate hook sends `SIGUSR1`, which tells Zift to reopen the log
file.

## fail2ban

Install the shipped filter and jail:

```sh
sudo install -m 0644 packaging/fail2ban/zift-filter.conf /etc/fail2ban/filter.d/zift.conf

if [ -f /etc/fail2ban/jail.local ]; then
  sudo tee -a /etc/fail2ban/jail.local < packaging/fail2ban/zift-jail.conf
else
  sudo install -m 0644 packaging/fail2ban/zift-jail.conf /etc/fail2ban/jail.local
fi

sudo fail2ban-client -t
sudo systemctl restart fail2ban
sudo fail2ban-client status zift
```

The filter is for auth-layer failures and accept rejections, not normal
policy denials by authenticated partners.

The shipped jail uses `backend = polling` so fail2ban tails
`/home/zift/audit.jsonl` directly on systems where `auto` would default
to journald. The shipped filter also has a `datepattern` for Zift's RFC
3339 audit timestamps; if an older fail2ban cannot parse it, comment
that line out and fail2ban will fall back to file mtime.

## CrowdSec

CrowdSec is an alternative to fail2ban. The same audit log is the
input; the difference is that CrowdSec uses leaky-bucket scenarios
that decay over time and can optionally share decisions across a
fleet via the CrowdSec Console.

The integration ships in `packaging/crowdsec/` (parser, three
scenarios, collection manifest, acquisition config) with its own
`README.md` for install and tuning. Pick one of fail2ban or CrowdSec
— running both on the same audit log produces duplicate bans in two
different state stores.

## Health Checks

Zift intentionally has no HTTP health endpoint.

Basic TCP probe:

```sh
nc -z -w2 127.0.0.1 2222
```

SSH banner/auth-path probe:

```sh
echo | timeout 5 ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -p 2222 nobody@127.0.0.1
```

The SSH probe intentionally reaches the auth path. It creates auth
failure audit entries and may trip fail2ban if run frequently without an
allowlist; use the TCP probe for quiet liveness checks.

Deep SFTP probes require a real configured user. Use them only if the
monitor can safely store that credential.

## Backup

Back up:

- `/usr/local/bin/zift`
- `/home/zift/zift.conf`
- `/home/zift/host_ed25519`
- `/home/zift/keys/`
- partner root directories
- audit logs if retention requires it

There is no database to dump.

Example:

```sh
sudo tar czf zift-backup.tgz /usr/local/bin/zift /home/zift
```

Filesystem snapshots, `rsync`, `restic`, `borg`, ZFS, btrfs, and LVM
all work because Zift state is just files.

## Rollback

Keep the previous binary:

```sh
sudo cp /usr/local/bin/zift /usr/local/bin/zift.prev
sudo install -m 0755 zift-new /usr/local/bin/zift
sudo systemctl restart zift
```

Rollback:

```sh
sudo install -m 0755 /usr/local/bin/zift.prev /usr/local/bin/zift
sudo systemctl restart zift
```

Check whether the config grammar changed before rolling across major
versions. `zift validate` is the first command to run after any binary
change.

## Troubleshooting

Validate config:

```sh
sudo -u zift zift validate /home/zift/zift.conf
```

Check service logs:

```sh
journalctl -u zift -n 100 --no-pager
```

Check listener:

```sh
ss -ltnp | grep 2222
```

Check recent audit:

```sh
tail -n 50 /home/zift/audit.jsonl
```

Common failures:

| Symptom | Likely cause |
| --- | --- |
| startup fails | bad config, unreadable host key, missing root, port in use |
| reload warning | edited config is invalid; previous config is still active |
| auth denied | wrong credential, missing key file, unsupported key type |
| upload fails at close | target collision, policy denial, cross-filesystem publish |
| uploads fail after crash | orphaned files under `<root>/.zift/staging/` (or legacy `<root>/.zift-staging/` on pre-v0.8.0 installs); inspect and clear when no sessions are active |
| no audit file writes | file missing, permissions wrong, filesystem full |
| partners see unexpected `ls -l` owner/mode | `listing-mode reality` is enabled |

## Alternative Layouts

An FHS-style layout works:

```text
/etc/zift/zift.conf
/etc/zift/host_ed25519
/srv/sftp/<partner>/
/var/log/zift/audit.jsonl
```

Adjust:

- `server.host-key`
- `server.log`
- `server.partner-root` or per-user `root`
- `packaging/systemd/zift.service` `ExecStart`
- systemd `ReadWritePaths`
- systemd `ReadOnlyPaths`

The single-tree `/home/zift` layout is recommended because it is easy
to reason about and easy to bind into a hardened systemd namespace.

