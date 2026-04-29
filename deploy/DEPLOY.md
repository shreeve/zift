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

```bash
sudo -u zift tee /home/zift/zift.conf > /dev/null << 'EOF'
server
  listen 0.0.0.0:2222
  host-key /home/zift/host_ed25519
  idle-timeout 5m
  max-connections 14
  max-unauth-connections 4
  reload-interval 2s
  log /home/zift/audit.jsonl

user alice
  password $argon2id$v=19$m=65536,t=3,p=1$...paste-hash-here...
  root /home/zift/alice
  allow /inbox  read add
  allow /outbox read
  deny **.exe
  deny **/.ssh/**
EOF
sudo chmod 0600 /home/zift/zift.conf
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

## 7. fail2ban

```bash
sudo cp deploy/fail2ban-zift.conf /etc/fail2ban/filter.d/zift.conf

sudo tee -a /etc/fail2ban/jail.local << 'EOF'

[zift]
enabled  = true
port     = 2222
filter   = zift
logpath  = /home/zift/audit.jsonl
maxretry = 5
bantime  = 3600
findtime = 600
EOF

sudo systemctl restart fail2ban
sudo fail2ban-client status zift
```

The shipped filter matches only auth-layer failures
(`auth.password` / `auth.publickey` / `accept.rejected` /
`handshake.failed` / `auth.too_many_attempts`). Policy-layer denials
(an authenticated partner hitting `deny /elsewhere`) do **not**
trigger bans — those are normal access-control events.

## 8. Log rotation

```bash
sudo tee /etc/logrotate.d/zift << 'EOF'
/home/zift/audit.jsonl {
    daily
    rotate 30
    compress
    missingok
    notifempty
    postrotate
        systemctl kill -s USR1 zift
    endscript
}
EOF
```

`SIGUSR1` triggers zift's audit-log reopen handler — the rotated file
keeps the old fd's buffered writes, the new file picks up subsequent
lines.

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
sudo systemctl status zift
sudo -u zift zift validate /home/zift/zift.conf
sudo systemd-analyze verify /etc/systemd/system/zift.service
sudo fail2ban-client status zift
sudo ufw status verbose
journalctl -u zift --since "5 min ago" --no-pager
tail -n 20 /home/zift/audit.jsonl   # last 20 audit events
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
