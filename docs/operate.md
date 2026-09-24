# Operate Zift

This guide sets up and runs Zift as a Linux service. It keeps every
piece of Zift state under one tree:

```text
/home/zift/                     0750 root:zift
├── zift.conf                   0640 root:zift
├── host_ed25519                0640 root:zift
├── keys/                       0750 root:zift
│   └── ally.pub                0640 root:zift
├── ally/                       2770 zift:zift   partner root
│   ├── pending/
│   └── .zift/                  reserved; see security.md
└── other-partner/
```

The layout is a convention; Zift only uses the paths in its config.
The daemon can read the config, host key and keys but not change them,
and can write only inside partner roots. For another layout, see
[Alternative Layouts](#alternative-layouts).

## Install

Install `cosign` and run the installer as in the
[README](../README.md#install). It checks the cosign signature on
`SHA256SUMS` against the exact release workflow and tag, checks the
binary against `SHA256SUMS`, and installs the binary only.

- On a host with a `zift.service` unit it installs to `/usr/local/bin`,
  the path the unit runs, and uses `sudo` for that one write, saying so
  first. The download and checks never run as root. If `sudo` is
  unavailable it installs to `~/.local/bin` and warns that the service
  will not see it.
- Anywhere else it installs to `~/.local/bin` (as root, to
  `/usr/local/bin`), which is enough for
  `zift hash-password` and `zift validate`.
- `BIN=/some/dir` overrides both and is never elevated.
- `bash -s vX.Y.Z` pins a release; `bash -s -- --uninstall` removes the
  binary and nothing else.

### By hand

The examples below use `ZIFT_VERSION`; set it to the release you want.

```sh
ZIFT_VERSION=0.12.0
ARCH=$(uname -m)          # x86_64 or aarch64
BASE=https://github.com/shreeve/zift/releases/download/v${ZIFT_VERSION}

curl -fsSLO "$BASE/zift-${ZIFT_VERSION}-${ARCH}-linux"
curl -fsSLO "$BASE/SHA256SUMS"
curl -fsSLO "$BASE/SHA256SUMS.bundle"

cosign verify-blob \
  --bundle SHA256SUMS.bundle \
  --certificate-identity "https://github.com/shreeve/zift/.github/workflows/release.yml@refs/tags/v${ZIFT_VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing    # macOS: shasum -a 256 -c SHA256SUMS --ignore-missing

sudo install -m 0755 "zift-${ZIFT_VERSION}-${ARCH}-linux" /usr/local/bin/zift
zift version
```

cosign binds `SHA256SUMS` to this repository's release workflow; the
checksum binds the binary to `SHA256SUMS`. Releases ship
`x86_64-linux`, `aarch64-linux`, `x86_64-macos` and `aarch64-macos`
binaries. Linux binaries are static and need no libraries on the host.

### Upgrade and rollback

Read the [changelog](../CHANGELOG.md) first, and run `zift validate` on
your config with the new binary before restarting. Replace the binary
with `install` (or the installer), never `cp`: `cp` writes into the
running file and fails with "Text file busy".

```sh
sudo cp /usr/local/bin/zift /usr/local/bin/zift.prev
sudo install -m 0755 "zift-${ZIFT_VERSION}-${ARCH}-linux" /usr/local/bin/zift
sudo -u zift zift validate /home/zift/zift.conf
sudo systemctl restart zift
```

The running daemon keeps executing the old binary until it restarts
(`readlink /proc/<pid>/exe` shows `(deleted)`), and a restart drops live
sessions. `systemctl reload` does not load a new binary. The journal's
`zift: starting zift X.Y.Z` line records what each start ran. To roll
back, install `zift.prev` the same way and restart.

## Set Up The Host

Run these in order.

**1. Service user.** The daemon runs as `zift`, which may read but not
change the top of its tree:

```sh
sudo useradd --system --create-home --home-dir /home/zift --shell /usr/sbin/nologin zift
sudo chown root:zift /home/zift
sudo chmod 0750 /home/zift
```

**2. Host key.**

```sh
sudo ssh-keygen -t ed25519 -f /home/zift/host_ed25519 -N ""
sudo chown root:zift /home/zift/host_ed25519 /home/zift/host_ed25519.pub
sudo chmod 0640 /home/zift/host_ed25519
```

To rotate it later, replace the file, restart Zift, and tell partners
the fingerprint changed; a reload does not change the running host key.

**3. Credentials.** A password becomes a passhash for the config:

```sh
printf '%s\n' 'ally-secret' | zift hash-password
```

A partner's public key, received out of band, goes in a key file that
only root can change:

```sh
sudo install -d -o root -g zift -m 0750 /home/zift/keys
sudo install -o root -g zift -m 0640 ally.pub /home/zift/keys/ally.pub
```

**4. Partner root.** Create the root first, then its subdirectories:

```sh
sudo install -d -o zift -g zift -m 2770 /home/zift/ally
sudo install -d -o zift -g zift -m 2770 /home/zift/ally/pending /home/zift/ally/archive
```

`install -d` gives missing parents root ownership and mode 0755, so
creating `ally/pending` alone would leave `ally` unwritable by the
daemon and every upload would fail. The setgid bit keeps new
directories in group `zift`.

**5. Config.** Write `/home/zift/zift.conf` (grammar in
[`configure.md`](configure.md)), make it `root:zift 0640`, and validate
it as the service user:

```zift
server
  listen 0.0.0.0:2222
  host-key /home/zift/host_ed25519
  partner-root /home/zift
  log stderr

user ally
  from 203.0.113.40
  auth /home/zift/keys/ally.pub
  allow / read
  allow /pending write update
  deny **.exe
```

```sh
sudo chown root:zift /home/zift/zift.conf
sudo chmod 0640 /home/zift/zift.conf
sudo -u zift zift validate /home/zift/zift.conf
```

Keep `log stderr` so journald owns retention. If you log to a file
instead, the daemon cannot create files in `/home/zift`, so create it
first: `sudo install -o zift -g zift -m 0640 /dev/null
/home/zift/audit.jsonl`.

**6. systemd unit.** The unit, set up for `/home/zift`, is
`packaging/systemd/zift.service` in the repository and
`zift-deploy-X.Y.Z/zift.service` in each release's
`zift-deploy-X.Y.Z.tar.gz`:

```sh
curl -fsSLO "https://github.com/shreeve/zift/releases/download/v${ZIFT_VERSION}/zift-deploy-${ZIFT_VERSION}.tar.gz"
tar -xzf "zift-deploy-${ZIFT_VERSION}.tar.gz"
sudo install -m 0644 "zift-deploy-${ZIFT_VERSION}/zift.service" /etc/systemd/system/zift.service
sudo systemctl daemon-reload
sudo systemctl enable --now zift
systemctl status zift
```

The unit runs as `zift:zift` with no capabilities, makes everything but
`/home/zift` read-only, hides the rest of `/home`, forbids executing
anything under `/home/zift`, allows only IPv4 and IPv6 sockets, filters
system calls, and sets `MemoryMax=4G`, `LimitNOFILE=65536` and
`TasksMax=512`. `systemctl status` and `is-active` need no `sudo`;
`start`, `stop`, `restart` and `reload` do.

To serve on a port below 1024, such as 22, grant the one capability
that needs (`sudo systemctl edit zift`):

```ini
[Service]
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

### Sizing

The defaults fit the shipped unit. If you change them, keep these in
step:

- **Memory.** Each password check uses 64 MiB, and at most
  clamp(CPU count, 2, 8) run at once, so password checks peak at
  512 MiB whatever the load. Each SFTP session adds a 256 KiB packet
  buffer, 32 MiB at `max-connections 128`. `MemoryMax=4G` leaves ample
  headroom; if it is ever reached, the kernel kills the daemon and every
  session with it.
- **File descriptors.** A session can hold 256 handles plus its socket
  and libssh's own, so the worst case is `max-connections` × 264 + 64:
  33,856 at 128. Zift raises its soft limit toward that at startup and
  on reload, and warns when it can't. Raise `LimitNOFILE` with
  `max-connections`.
- **Threads.** One per connection. Keep `TasksMax` above
  `max-connections`.
- **Pre-auth slots.** Connections that have not logged in are capped at
  `max-unauth-connections` (32 by default) and 8 per source, and each
  gets 120 s to log in.

## Operator Access

Operators who need host-side access join group `zift` (`sudo usermod
-aG zift "$USER"`, then log in again). When dropping files into a
partner directory from the host, use `install -m 0660 -g zift …` or
`umask 007`: setgid keeps the group, but your umask still sets the
mode. Config and host key stay `root:zift` and not group-writable, so
neither operators in the group nor a compromised daemon can change
them.

## Reload

```sh
sudo systemctl reload zift
```

The unit's reload runs `zift validate` on the on-disk config first. If
that fails, the reload command fails (non-zero, shown in `systemctl
status` and the journal) and the daemon is never signalled.
`systemctl kill -s HUP zift` skips that check. Zift also reloads by
itself when the config or a key file changes (see
[`configure.md`](configure.md#reloads)).

When the daemon rejects a config it keeps serving the previous one and
says so loudly:

- stderr: `zift: config reload rejected — SERVING PREVIOUS CONFIG; fix
  <path> and it will auto-apply: <reason>`;
- audit: `config.reload` with result `failed` and the reason as detail.

It stays in that degraded state until a valid config loads, then logs
`config reload recovered` and audits `config.reload` `ok`. A partner
added by the rejected edit just sees "Permission denied", so watch the
journal:

```sh
journalctl -u zift -o cat | grep '"operation":"config.reload"'
```

`systemctl is-active` still says `active` while degraded. The reliable
check is: the service is active **and** `zift validate` of the on-disk
config fails. Then the daemon is serving rules that a restart would
refuse to load.

## Signals

| Signal | Effect |
| --- | --- |
| `SIGHUP` | reload the config now, changed or not |
| `SIGTERM`, `SIGINT` | stop accepting, wait up to `shutdown-grace` for sessions, close the rest, exit |
| `SIGUSR1` | reopen the audit log file, on the next audit line (no effect with `log stderr`) |
| `SIGPIPE` | ignored |

The unit's `TimeoutStopSec=60` must stay above `shutdown-grace`.

## Add A Partner

Edit a copy, validate it, then move it into place, so the running
daemon never sees a half-written or invalid file:

```sh
sudo install -d -o zift -g zift -m 2770 /home/zift/vendor
sudo install -d -o zift -g zift -m 2770 /home/zift/vendor/incoming
printf '%s\n' 'vendor-secret' | zift hash-password
sudo cp -p /home/zift/zift.conf /home/zift/zift.conf.new
sudo -e /home/zift/zift.conf.new        # add the user block
sudo -u zift zift validate /home/zift/zift.conf.new
sudo mv /home/zift/zift.conf.new /home/zift/zift.conf
sudo systemctl reload zift
```

A root that does not exist rejects the whole config, not just that
user, and the partner sees only "Permission denied". That is why the
root comes first.

## Remove A Partner

Delete the `user` block the same way and reload. New connections for
that user fail at once, but connections accepted before the reload
keep the old config until they end.
To cut a partner off immediately, restart the service; that drops every
session.

## Logs

Zift writes human-readable status lines to stderr and one JSON audit
object per line to `log`. With `log stderr` both reach the journal;
with a file, only status lines do.

Fields appear in this order: `time` (RFC 3339 UTC, milliseconds),
`event` (always `zift.audit`), `user`, `operation`, `result` (`ok`,
`denied` or `failed`), `path`, `detail`, `ip`, and `truncated` when a
line was clipped at 4096 bytes. `user` and `path` are omitted when they
do not apply and `detail` when empty; `ip` is always present. A clipped
line shortens `detail` first, then drops `path`, then `user`.

| `operation` | Meaning |
| --- | --- |
| `accept.rejected` | connection refused at accept; detail `max-connections reached`, `max-unauth-connections reached`, `source suppressed` or `too many pre-auth connections from source` (at most one line per source per minute) |
| `handshake.failed` | key exchange failed |
| `auth.password` | password login; denied detail `unknown user`, `source not allowed` or `bad password` |
| `auth.publickey` | key login; ok detail is the key algorithm; denied detail `unknown user`, `source not allowed`, `no keys configured`, `key not configured`, `no key in message` or `signature invalid`; failed detail `pk_ok reply failed` |
| `auth.rejected` | login ended: `source suppressed`, or `login grace expired` after key exchange (during it, the expiry is a `handshake.failed`) |
| `auth.too_many_attempts` | six hard failures, or detail `probes` after 64 soft operations |
| `config.reload` | reload rejected (`failed`, reason in detail) or recovered (`ok`) |
| `idle.timeout` | session closed for idleness before the client sent SFTP INIT; later, `session.ended` with detail `idle timeout` |
| `session.ended` | session over; detail is the reason and `duration_ms`; `failed` when it ended on an error |
| `opendir`, `open_read`, `open_write` | directory or file opened; a new upload's `open_write` has detail `staged` |
| `publish` | upload renamed into place at close |
| `close` | an upload that could not be published at close: refused (the target appeared, or the clobber rule) or failed |
| `read`, `write` | refused on a handle opened without that access (once per handle) |
| `stat` | STAT refused (successes are not logged) |
| `mkdir`, `remove`, `rmdir`, `rename`, `setstat`, `fsetstat` | as named; `rename`'s detail is the new path |

```sh
journalctl -u zift -o cat | grep '^{' | jq -c 'select(.result=="denied")'
tail -F /home/zift/audit.jsonl | jq -c 'select(.operation=="publish")'
```

## Log Rotation

With `log stderr`, journald rotates for you. With a file, rotate it
with logrotate and signal a reopen. Because the daemon cannot create
files in `/home/zift`, logrotate must create the new file:

```text
/home/zift/audit.jsonl {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 zift zift
    postrotate
        systemctl kill -s USR1 zift
    endscript
}
```

The reopen happens on the next audit line, so until then the old file
still receives writes; `delaycompress` leaves it alone for one cycle. If
the reopen fails, Zift keeps the old file, warns on stderr, and retries
every 5 s.

## Health Checks

Zift has no HTTP endpoint. For liveness, probe the TCP port:

```sh
nc -z -w2 127.0.0.1 2222
```

Each probe is a connection: it holds a pre-auth slot for a moment and
writes a `handshake.failed` audit line and a `zift: LibsshFailure:
Socket error: …` status line. A probe that goes further, such
as an `ssh` login attempt, writes more audit lines, and a failed
password counts toward source suppression. `from` does not exempt a source. A monitor that must log in
needs a real user with real credentials.

## Backup

Back up `/usr/local/bin/zift`, `/home/zift/zift.conf`, the host key,
`/home/zift/keys/`, the partner roots, and the audit log if you keep
one. There is no database; `tar`, `rsync`, `restic`, or filesystem
snapshots all work.

## Troubleshooting

```sh
sudo -u zift zift validate /home/zift/zift.conf
journalctl -u zift -n 100 --no-pager
ss -ltnp | grep 2222
```

| Symptom | Likely cause |
| --- | --- |
| startup fails | invalid config, host key rejected, missing root, audit log cannot be opened, port in use |
| `ssh_bind_listen` fails with permission denied | a port below 1024 without `CAP_NET_BIND_SERVICE`; see the [unit drop-in](#set-up-the-host) |
| `config reload rejected` | the edited config is invalid and the previous one is serving; fix the file (it applies itself) or run `systemctl reload` to see the error |
| login denied | wrong credential, `from` mismatch, source suppressed, or the partner's key is not in their key file |
| every new upload fails with `staging dir unavailable` | the partner root or its `.zift` is not writable or owned as required (see [`security.md`](security.md#uploads-and-the-per-partner-namespace)) |
| upload fails at close | the target appeared meanwhile, policy denial, or the target is on another filesystem |
| rename or upload fails on NFS or SMB | the filesystem lacks no-replace rename (see [`security.md`](security.md#known-caveats)) |
| startup warns about `.zift-staging` | leftover from 0.7.x or earlier; remove it once no session needs it |
| partners see host owners and modes | `listing-mode reality` |

## Alternative Layouts

An FHS layout works, for example:

```text
/etc/zift/zift.conf          0640 root:zift
/etc/zift/host_ed25519       0640 root:zift
/srv/sftp/<partner>/         2770 zift:zift
/var/log/zift/audit.jsonl
```

Set `host-key`, `log`, and `partner-root` (or each `root`) in the
config, and change these unit lines, or uploads and the audit log fail
with a read-only filesystem:

```ini
ExecStart=/usr/local/bin/zift serve /etc/zift/zift.conf
ExecReload=/usr/local/bin/zift validate /etc/zift/zift.conf
ReadWritePaths=/srv/sftp
NoExecPaths=/srv/sftp
LogsDirectory=zift
```

Remove `BindPaths=/home/zift`, which fails when that directory does not
exist; `ProtectHome=tmpfs` can stay. `LogsDirectory=zift` creates
`/var/log/zift`, owned by `zift` and writable by the service.
