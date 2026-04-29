# Zift Deployment Guide

Production deployment of Zift on a Linux host. The whole deploy lives
in a single tree at `/home/zift/` — config, host key, partner data,
and audit log. One service user owns it; the systemd unit confines
the daemon to that subtree and nothing else.

## Layout at a glance

```text
/home/zift/
├── zift.conf             # ExecStart=... serve /home/zift/zift.conf
├── host_ed25519          # host-key in zift.conf
├── host_ed25519.pub
├── audit.jsonl           # log /home/zift/audit.jsonl
├── alice/                # user alice — root /home/zift/alice
│   ├── inbox/
│   ├── outbox/
│   └── .zift-staging/    # auto-created on first upload (0o700, hidden)
└── bob/                  # add more partners by editing zift.conf
    ├── …
    └── .zift-staging/
```

Adding a partner = `sudo -u zift mkdir -p /home/zift/<name>/<subdirs>`,
edit `zift.conf` to add the `user <name>` block, save. Reload picks
it up within `reload-interval` (default 2 s) or on `SIGHUP`.

## File manifest

Every config artifact zift needs is bundled into the
`zift-deploy-X.Y.Z.tar.gz` release asset. Untar it on the install host
and you have the full deploy tree:

```
zift-deploy-X.Y.Z/
├── DEPLOY.md                  # this runbook
├── zift.conf.example          # → /home/zift/zift.conf
├── zift.service               # → /etc/systemd/system/zift.service
├── fail2ban-zift.conf         # → /etc/fail2ban/filter.d/zift.conf
├── fail2ban-zift-jail.conf    # → append to /etc/fail2ban/jail.local
└── logrotate-zift.conf        # → /etc/logrotate.d/zift
```

Detailed mapping:

| Source | Destination | Owner / mode | Required? |
|---|---|---|---|
| `zift.conf.example` | `/home/zift/zift.conf` | `zift:zift` `0600` | mandatory |
| `zift.service` | `/etc/systemd/system/zift.service` | `root:root` `0644` | mandatory |
| `fail2ban-zift.conf` | `/etc/fail2ban/filter.d/zift.conf` | `root:root` `0644` | optional (fail2ban) |
| `fail2ban-zift-jail.conf` | append to `/etc/fail2ban/jail.local` | `root:root` `0644` | optional (fail2ban) |
| `logrotate-zift.conf` | `/etc/logrotate.d/zift` | `root:root` `0644` | optional (logrotate) |

You can also clone the repo and use `deploy/<file>` directly — same
files. Tarball is just the no-git-required option.

Plus one generated artifact: `/home/zift/host_ed25519` (the SSH host
private key — generated on first install, see step 3 below).

If you skip fail2ban + logrotate, the deploy is just two install steps
(copy `zift.service`, copy/edit `zift.conf.example`) plus the
`useradd` + `ssh-keygen` ceremony.

## Quickstart

Copy-paste runbook for an install on a fresh host. The detailed
sections below explain each step's reasoning + cover the optional
provenance verification, firewall, and health-check steps.

```bash
# --- 0. Download the binary + deploy bundle. ----------------------
ZIFT_VERSION=v0.5.3
ARCH=$(uname -m)
cd /tmp
curl -fsSLO "https://github.com/shreeve/zift/releases/download/${ZIFT_VERSION}/zift-${ZIFT_VERSION#v}-${ARCH}-linux"
curl -fsSLO "https://github.com/shreeve/zift/releases/download/${ZIFT_VERSION}/zift-deploy-${ZIFT_VERSION#v}.tar.gz"
tar -xzf "zift-deploy-${ZIFT_VERSION#v}.tar.gz"
cd "zift-deploy-${ZIFT_VERSION#v}"

# --- 1. Install the binary. ---------------------------------------
sudo install -m 0755 "/tmp/zift-${ZIFT_VERSION#v}-${ARCH}-linux" /usr/local/bin/zift

# --- 2. Service user with a real home. ----------------------------
sudo useradd --system --create-home --home-dir /home/zift \
    --shell /usr/sbin/nologin zift
sudo chmod 0750 /home/zift

# --- 3. Host key. -------------------------------------------------
sudo -u zift ssh-keygen -t ed25519 -f /home/zift/host_ed25519 -N ""

# --- 4. zift config (edit before service starts). -----------------
sudo install -o zift -g zift -m 0600 zift.conf.example /home/zift/zift.conf
# Generate a real Argon2id hash for your partner:
printf '%s\n' 'alice-secret' | zift hash-password
# Paste the resulting $argon2id$... string into /home/zift/zift.conf
# (replacing REPLACE-WITH-REAL-SALT$REPLACE-WITH-REAL-HASH).
sudo -u zift "${EDITOR:-nano}" /home/zift/zift.conf
sudo -u zift mkdir -p /home/zift/alice/inbox /home/zift/alice/outbox
sudo -u zift zift validate /home/zift/zift.conf

# --- 5. systemd unit. ---------------------------------------------
sudo install -m 0644 zift.service /etc/systemd/system/zift.service
sudo systemd-analyze verify /etc/systemd/system/zift.service
sudo systemctl daemon-reload
sudo systemctl enable --now zift
sudo systemctl status zift

# --- 6. fail2ban (optional). --------------------------------------
sudo install -m 0644 fail2ban-zift.conf /etc/fail2ban/filter.d/zift.conf
if [ -f /etc/fail2ban/jail.local ]; then
    sudo tee -a /etc/fail2ban/jail.local < fail2ban-zift-jail.conf
else
    sudo install -m 0644 fail2ban-zift-jail.conf /etc/fail2ban/jail.local
fi
sudo fail2ban-client -t
sudo systemctl restart fail2ban
sleep 2
sudo fail2ban-client status zift   # expect: File list: /home/zift/audit.jsonl

# --- 7. logrotate (optional). -------------------------------------
sudo install -m 0644 logrotate-zift.conf /etc/logrotate.d/zift
sudo logrotate -d /etc/logrotate.d/zift   # dry-run, no errors

# --- 8. Smoke test + cleanup. -------------------------------------
nc -z -w2 127.0.0.1 2222 && echo "tcp:2222 reachable"
sudo systemctl is-active zift
sudo fail2ban-client status zift 2>/dev/null | grep 'File list'
cd / && rm -rf "/tmp/zift-deploy-${ZIFT_VERSION#v}" \
                "/tmp/zift-deploy-${ZIFT_VERSION#v}.tar.gz" \
                "/tmp/zift-${ZIFT_VERSION#v}-${ARCH}-linux"
```

## Prerequisites

- Linux 3.x+ (kernel-only requirement; zift v0.2.0+ binaries are fully
  static — no `apt install libssh-4` needed). Ubuntu, Debian, RHEL,
  Alpine, distroless images, etc. all work.
- `fail2ban` installed (optional but recommended).
- SSH admin access on port 22, key-only, IP-restricted (separate from
  Zift's port 2222).
- `systemd` 247+ for the `ProtectProc` / `ProcSubset` directives.

## 1. Install the binary

Each tagged release publishes target-specific binaries plus a
`SHA256SUMS` manifest signed by the release workflow's GitHub
identity (cosign keyless via Sigstore). Pick the artifact for your
host's architecture.

```bash
ZIFT_VERSION=v0.5.3
ARCH=$(uname -m)        # x86_64 or aarch64

curl -fsSLO "https://github.com/shreeve/zift/releases/download/${ZIFT_VERSION}/zift-${ZIFT_VERSION#v}-${ARCH}-linux"
sudo install -m 0755 "zift-${ZIFT_VERSION#v}-${ARCH}-linux" /usr/local/bin/zift
zift version
```

### Verify provenance + integrity (optional but recommended)

The signature attests that **this** workflow run on `shreeve/zift`
produced the manifest. Verify before installing on any host you care
about:

```bash
ZIFT_VERSION=v0.5.3
gh release download "$ZIFT_VERSION" \
    --repo shreeve/zift \
    --pattern 'SHA256SUMS' \
    --pattern 'SHA256SUMS.bundle'

# 1. Verify the signature against Sigstore's public good instance.
cosign verify-blob \
    --bundle SHA256SUMS.bundle \
    --certificate-identity-regexp 'https://github.com/shreeve/zift/.+' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    SHA256SUMS

# 2. Verify the binary's bytes match the manifest.
shasum -a 256 -c SHA256SUMS --ignore-missing
```

Both must succeed. If either fails, **stop** — either the download was
tampered with or the trust root has shifted.

## 2. Create the service user with a real home

```bash
sudo useradd \
    --system \
    --create-home --home-dir /home/zift \
    --shell /usr/sbin/nologin \
    zift
sudo chmod 0750 /home/zift
```

`0750` keeps other local users on the host from enumerating partner
directories or reading partial uploads via the filesystem side. Only
the `zift` user (and group) can traverse the tree.

## 3. Generate the host key

```bash
sudo -u zift ssh-keygen -t ed25519 -f /home/zift/host_ed25519 -N ""
sudo chmod 0600 /home/zift/host_ed25519
```

## 4. Generate partner password hashes + lay out partner roots

```bash
# One per partner.
sudo -u zift mkdir -p /home/zift/alice/inbox /home/zift/alice/outbox

# Generate the Argon2id PHC string the partner will authenticate with.
printf '%s\n' 'alice-secret' | zift hash-password
# → $argon2id$v=19$m=65536,t=3,p=1$...
```

## 5. Write the config

Copy the starter config from `deploy/zift.conf.example`, then edit
the two things you have to customize (the password hash and the
partner block). Comments inside the file flag every spot you'd
typically touch.

```bash
sudo install -o zift -g zift -m 0600 deploy/zift.conf.example /home/zift/zift.conf
sudo -u zift "${EDITOR:-nano}" /home/zift/zift.conf
# Paste your real Argon2id hash where the file says
# REPLACE-WITH-REAL-SALT$REPLACE-WITH-REAL-HASH; tune the partner
# block to your policy.
```

A note on `max-connections`: pick it so that
`max-connections * Argon2id-worst-case-memory` fits under the cgroup's
`MemoryMax` (default 4 GiB in the shipped systemd unit, which leaves
headroom for ~14 concurrent password verifications at the upper
envelope of `m=262144`). Either drop `max-connections` to 14, raise
`MemoryMax` in the unit, or lower the Argon2id `m` parameter on the
hashes you generate — but make all three numbers consistent.

`max-unauth-connections` is an independent cap on the pre-auth slot
pool (PLAN §8.4). It bounds handshake-storm pressure: with the default
`max-unauth-connections 0` (no separate cap), an attacker can pin the
entire `max-connections` pool with stuck pre-auth sockets until each
`idle-timeout` elapses. Setting it to roughly `max-connections / 4`
preserves headroom for authenticated partners. Must be
`≤ max-connections`.

### Validate before going live

```bash
sudo -u zift zift validate /home/zift/zift.conf
```

Validates the grammar, checks the host-key is readable, the partner
roots exist + are real directories, and that no two partner roots
overlap.

## 6. Install the systemd unit

The shipped `deploy/zift.service` is already configured for the
`/home/zift/` layout — `ExecStart` points at `/home/zift/zift.conf`,
`ReadWritePaths=/home/zift` is the only writable path, and
`ProtectHome=tmpfs` + `BindPaths=/home/zift` hide every other user's
home directory from zift.

```bash
sudo cp deploy/zift.service /etc/systemd/system/
sudo systemd-analyze verify /etc/systemd/system/zift.service   # should print nothing
sudo systemctl daemon-reload
sudo systemctl enable --now zift
sudo systemctl status zift
journalctl -u zift -n 50 --no-pager
```

If you have the binary but not the repo on the host, paste the unit
file from
<https://github.com/shreeve/zift/blob/main/deploy/zift.service>
into `/etc/systemd/system/zift.service` directly.

### Adding partners later

Edit the config, save, and the running server picks it up within
`reload-interval` (default 2 s). Force a reload immediately with:

```bash
sudo systemctl kill -s HUP zift
```

The config is owned by `zift:zift` with mode `0600`. Edit through
sudo:

```bash
sudo -u zift "${EDITOR:-nano}" /home/zift/zift.conf
sudo -u zift zift validate /home/zift/zift.conf
```

Validating BEFORE saving over a known-good config protects against
typos that would crash a reload.

## 7. fail2ban (optional)

Two files: the **filter** (regex that recognizes a ban-worthy line) and
the **jail** (which file to watch + ban thresholds). Both are
pre-written; install and restart fail2ban.

```bash
# Filter: regex that matches zift's auth-failure JSON.
sudo install -m 0644 deploy/fail2ban-zift.conf /etc/fail2ban/filter.d/zift.conf

# Jail: append to /etc/fail2ban/jail.local (or create it if absent).
if [ -f /etc/fail2ban/jail.local ]; then
    sudo tee -a /etc/fail2ban/jail.local < deploy/fail2ban-zift-jail.conf
else
    sudo install -m 0644 deploy/fail2ban-zift-jail.conf /etc/fail2ban/jail.local
fi

# Verify + restart.
sudo fail2ban-client -t                       # syntax check
sudo systemctl restart fail2ban
sleep 2                                       # let the control socket open
sudo fail2ban-client status zift
```

The status output should show `File list: /home/zift/audit.jsonl` —
that's the line that confirms fail2ban is tailing the file rather
than the systemd journal. (The shipped jail explicitly sets
`backend = polling` to force file-watching; without that line,
fail2ban's `auto` backend on Debian/Ubuntu defaults to systemd-journald
and silently ignores the `logpath`.)

The shipped filter matches only auth-layer failures
(`auth.password` / `auth.publickey` / `accept.rejected` /
`handshake.failed` / `auth.too_many_attempts`). Policy-layer denials
(an authenticated partner hitting `deny /elsewhere`) do **not**
trigger bans — those are normal access-control events.

End-to-end smoke test (one bad-password attempt should bump
`Total failed` from 0 to 1):

```bash
sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -P 2222 alice@127.0.0.1
# type a wrong password, Ctrl-C
sleep 2
sudo fail2ban-client status zift              # Total failed: 1
```

## 8. Log rotation (optional)

```bash
sudo install -m 0644 deploy/logrotate-zift.conf /etc/logrotate.d/zift
sudo logrotate -d /etc/logrotate.d/zift       # dry-run, doesn't actually rotate
```

`SIGUSR1` (fired by the postrotate hook) triggers zift's audit-log
reopen handler — the rotated file keeps its buffered writes, the new
file picks up subsequent lines without restarting the daemon.

## 9. Firewall

### Cloud allowlist (GCP example)

```bash
gcloud compute firewall-rules create allow-zift \
  --project=your-project \
  --network=default \
  --direction=INGRESS \
  --priority=1000 \
  --action=ALLOW \
  --rules=tcp:2222 \
  --source-ranges=PARTNER_IP_1/32,PARTNER_IP_2/32 \
  --target-tags=zift-host
```

### Host firewall (UFW, defense in depth)

```bash
sudo ufw allow from PARTNER_IP_1 to any port 2222 proto tcp
sudo ufw allow from PARTNER_IP_2 to any port 2222 proto tcp
```

Keep SSH admin access separate and restricted:

```bash
sudo ufw allow from YOUR_ADMIN_IP to any port 22 proto tcp
```

## 10. Health checks

Zift has no HTTP endpoint by design. Use TCP probes:

```bash
# Basic TCP probe.
nc -z -w2 127.0.0.1 2222 && echo ok || echo down

# SSH banner probe (non-interactive).
echo | timeout 5 ssh -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -p 2222 nobody@127.0.0.1 2>&1 | head -1
```

For deeper probes, create a dedicated `healthcheck` user with read-only
access to an empty directory and test with `sftp`.

## Rollback

The binary is a single file. Keep the previous version:

```bash
sudo cp /usr/local/bin/zift /usr/local/bin/zift.prev
sudo install -m 0755 zift-new /usr/local/bin/zift
sudo systemctl restart zift
```

Partner data: `/home/zift/` is a regular directory tree, so any tool
you already use for backups works — `rsync`, `restic`, `borg`,
filesystem-level snapshots (ZFS / btrfs / LVM), etc. There's no
zift-specific backup story.

## Verification checklist

```bash
# zift itself
sudo systemctl is-active zift                                       # active
sudo systemctl is-enabled zift                                      # enabled
sudo -u zift zift validate /home/zift/zift.conf                     # no errors
sudo systemd-analyze verify /etc/systemd/system/zift.service        # silent

# fail2ban (skip if not installed)
sudo fail2ban-client -t                                             # OK
sudo fail2ban-client status zift | grep -E 'File list|Total failed' # File list: /home/zift/audit.jsonl

# logrotate (skip if not installed)
sudo logrotate -d /etc/logrotate.d/zift 2>&1 | tail -5              # no errors

# Live activity
journalctl -u zift --since "5 min ago" --no-pager
tail -n 20 /home/zift/audit.jsonl                                   # recent audit events

# Network
sudo ufw status verbose                                             # if ufw is in use
nc -z -w2 127.0.0.1 2222 && echo "tcp:2222 reachable"
```

A one-shot health summary you can run anytime:

```bash
systemctl is-active zift && systemctl is-enabled zift
sudo fail2ban-client status zift 2>/dev/null | grep -q 'File list' \
    && echo "fail2ban: tailing /home/zift/audit.jsonl" \
    || echo "fail2ban: not configured"
nc -z -w2 127.0.0.1 2222 && echo "tcp:2222 reachable" || echo "tcp:2222 down"
```

## Alternative: FHS-style layout

If your environment requires the conventional layout
(`/etc/zift/zift.conf`, `/srv/sftp/<partner>/`, `/var/log/zift/`),
nothing in zift's code requires the `/home/zift/` tree — it's a
deploy convention, not a hard dependency. Adapt the systemd unit's
`ExecStart`, `ReadWritePaths`, drop `BindPaths`, set `ProtectHome=true`
(no need to bring any home directory into the namespace), and put each
matching path where you want it. The grandfathered example:

```ini
ExecStart=/usr/local/bin/zift serve /etc/zift/zift.conf
ProtectHome=true
ReadWritePaths=/srv/sftp /var/log/zift
ReadOnlyPaths=/etc/zift
```

Pair that with the equivalent `useradd --home-dir /nonexistent` flow
and `mkdir -p /etc/zift /srv/sftp /var/log/zift` provisioning.
Functionally identical from zift's perspective; just more directories
to remember.
