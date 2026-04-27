# Zift Deployment Guide

Production deployment of Zift on an Ubuntu host with ZFS-backed partner roots.

## Prerequisites

- Linux 3.x+ (kernel-only requirement; Zift v0.2.0+ binaries are fully
  statically linked — no `apt install libssh-4` needed). Ubuntu, Debian,
  RHEL, Alpine, distroless images, etc. all work.
- ZFS pool for partner data (recommended)
- `fail2ban` installed
- SSH admin access on port 22, key-only, IP-restricted (separate from Zift)

## Install the binary

### Download from GitHub Releases

Each tagged release publishes target-specific binaries plus a
`SHA256SUMS` manifest signed by the release workflow's GitHub
identity (cosign keyless via Sigstore). Pick the artifact for your
host's architecture.

```bash
# Pick the version you want.
ZIFT_VERSION=v0.1.0

gh release download "$ZIFT_VERSION" \
    --repo shreeve/zift \
    --pattern 'zift-*' \
    --pattern 'SHA256SUMS' \
    --pattern 'SHA256SUMS.bundle'
```

### Verify provenance + integrity

The signature attests that THIS workflow run on `shreeve/zift` produced
the manifest. Verify before installing:

```bash
# 1. Verify the signature against Sigstore's public good instance.
#    This proves SHA256SUMS was signed by the release.yml workflow on
#    shreeve/zift, not by an attacker who compromised the release page.
cosign verify-blob \
    --bundle SHA256SUMS.bundle \
    --certificate-identity-regexp 'https://github.com/shreeve/zift/.+' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    SHA256SUMS

# 2. Verify the binary's bytes match the manifest.
shasum -a 256 -c SHA256SUMS
```

Both must succeed before installing. If either fails, **stop** —
either the download was tampered with or the trust root has shifted.

### Install

```bash
sudo install -m 0755 zift-*-linux-x86_64 /usr/local/bin/zift
zift version
```

## Create the service user

```bash
sudo useradd --system --shell /usr/sbin/nologin --home-dir /nonexistent zift
```

## Set up the config and host key

```bash
sudo mkdir -p /etc/zift
sudo ssh-keygen -t ed25519 -f /etc/zift/host_ed25519 -N ""
sudo chown root:zift /etc/zift/host_ed25519
sudo chmod 0640 /etc/zift/host_ed25519
```

Generate a password hash for a partner:

```bash
printf '%s\n' 'partner-password' | zift hash-password
```

Write the config:

Pick `max-connections` so that `max-connections * Argon2id-worst-case-memory`
fits under the cgroup's `MemoryMax` (default 4 GiB in the shipped systemd
unit, which leaves headroom for ~14 concurrent password verifications at
the upper envelope of `m=262144`). Either drop `max-connections` to 14,
raise `MemoryMax` in the unit, or lower the Argon2id `m` parameter on the
hashes you generate — but make all three numbers consistent.

`max-unauth-connections` is an independent cap on the pre-auth slot
pool (PLAN §8.4). It bounds handshake-storm pressure: with the default
`max-unauth-connections=0` (no separate cap), an attacker can pin the
entire `max-connections` pool with stuck pre-auth sockets until each
`idle-timeout` elapses. Setting it to roughly `max-connections / 4`
preserves headroom for authenticated partners. Must be `≤ max-connections`.

```bash
sudo tee /etc/zift/zift.conf << 'EOF'
server
  listen 0.0.0.0:2222
  host-key /etc/zift/host_ed25519
  idle-timeout 5m
  max-connections 14
  max-unauth-connections 4
  reload-interval 2s
  log /var/log/zift/audit.jsonl

user acme
  password $argon2id$v=19$m=65536,t=3,p=1$...paste-hash-here...
  root /zfs/sftp/acme
  allow /inbox read write list mkdir
  allow /outbox read list
  deny **.exe
  deny **/.ssh/**
EOF
sudo chown root:zift /etc/zift/zift.conf
sudo chmod 0640 /etc/zift/zift.conf
```

## Create partner roots on ZFS

```bash
sudo zfs create zfs/sftp
sudo zfs create zfs/sftp/acme
sudo mkdir -p /zfs/sftp/acme/inbox /zfs/sftp/acme/outbox
sudo chown -R zift:zift /zfs/sftp/acme
```

Snapshots come free:

```bash
sudo zfs snapshot zfs/sftp/acme@$(date +%Y%m%d)
```

## Create the audit log directory

```bash
sudo mkdir -p /var/log/zift
sudo chown zift:zift /var/log/zift
```

## Install the systemd unit

```bash
sudo cp deploy/zift.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable zift
sudo systemctl start zift
sudo systemctl status zift
```

## Validate the config before reload

The config is owned by `root:zift` with mode 0640, so an admin who is
not in group `zift` must run validate via sudo (either as root or as
the zift user). Either form is fine; running as the service user is a
slightly stronger sanity check because it exercises the same path
permissions the running process will see.

```bash
sudo -u zift zift validate /etc/zift/zift.conf   # preferred
# or:
sudo zift validate /etc/zift/zift.conf
```

Adding a partner: edit the config, save, and the server picks it up within
`reload-interval` (default 2 seconds). Or force it:

```bash
sudo systemctl kill -s HUP zift
```

## Install fail2ban filter

```bash
sudo cp deploy/fail2ban-zift.conf /etc/fail2ban/filter.d/zift.conf

sudo tee -a /etc/fail2ban/jail.local << 'EOF'

[zift]
enabled  = true
port     = 2222
filter   = zift
logpath  = /var/log/zift/audit.jsonl
maxretry = 5
bantime  = 3600
findtime = 600
EOF

sudo systemctl restart fail2ban
sudo fail2ban-client status zift
```

## Firewall (cloud and host)

### GCP firewall rule (allowlist partner IPs)

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

### UFW (host firewall, defense in depth)

```bash
sudo ufw allow from PARTNER_IP_1 to any port 2222 proto tcp
sudo ufw allow from PARTNER_IP_2 to any port 2222 proto tcp
```

Keep SSH admin access separate and restricted:

```bash
sudo ufw allow from YOUR_ADMIN_IP to any port 22 proto tcp
```

## Health checks

Zift has no HTTP endpoint by design. Use TCP probes:

```bash
# Basic TCP probe
nc -z -w2 127.0.0.1 2222 && echo ok || echo down

# SSH banner probe (non-interactive)
echo | timeout 5 ssh -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -p 2222 nobody@127.0.0.1 2>&1 | head -1
```

For deeper probes, create a dedicated `healthcheck` user with read-only
access to an empty directory and test with `sftp`.

## Log rotation

```bash
sudo tee /etc/logrotate.d/zift << 'EOF'
/var/log/zift/audit.jsonl {
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

## Rollback

The binary is a single file. Keep the previous version:

```bash
sudo cp /usr/local/bin/zift /usr/local/bin/zift.prev
sudo install -m 0755 zift-new /usr/local/bin/zift
sudo systemctl restart zift
```

ZFS snapshots provide data rollback:

```bash
sudo zfs rollback zfs/sftp/acme@20260426
```

## Verification checklist

```bash
sudo systemctl status zift
zift validate /etc/zift/zift.conf
sudo fail2ban-client status zift
sudo ufw status verbose
sudo zfs list -t snapshot -r zfs/sftp
journalctl -u zift --since "5 min ago" --no-pager
```
