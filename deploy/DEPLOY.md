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
├── fail2ban-zift-filter.conf  # → /etc/fail2ban/filter.d/zift.conf
├── fail2ban-zift-jail.conf    # → append to /etc/fail2ban/jail.local
└── logrotate-zift.conf        # → /etc/logrotate.d/zift
```

Detailed mapping:

| Source | Destination | Owner / mode | Required? |
|---|---|---|---|
| `zift.conf.example` | `/home/zift/zift.conf` | `root:zift` `0640` | mandatory |
| `zift.service` | `/etc/systemd/system/zift.service` | `root:root` `0644` | mandatory |
| `fail2ban-zift-filter.conf` | `/etc/fail2ban/filter.d/zift.conf` | `root:root` `0644` | optional (fail2ban) |
| `fail2ban-zift-jail.conf` | append to `/etc/fail2ban/jail.local` | `root:root` `0644` | optional (fail2ban) |
| `logrotate-zift.conf` | `/etc/logrotate.d/zift` | `root:root` `0644` | optional (logrotate) |

(In v0.5.x and earlier the filter file was named `fail2ban-zift.conf`.
v0.6.0 renamed it to `fail2ban-zift-filter.conf` to make the
filter-vs-jail roles obvious at a glance. Old installs work unchanged
— only the source file in the deploy bundle moved.)

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
ZIFT_VERSION=v0.7.0
ARCH=$(uname -m)
cd /tmp
curl -fsSLO "https://github.com/shreeve/zift/releases/download/${ZIFT_VERSION}/zift-${ZIFT_VERSION#v}-${ARCH}-linux"
curl -fsSLO "https://github.com/shreeve/zift/releases/download/${ZIFT_VERSION}/zift-deploy-${ZIFT_VERSION#v}.tar.gz"
tar -xzf "zift-deploy-${ZIFT_VERSION#v}.tar.gz"
cd "zift-deploy-${ZIFT_VERSION#v}"

# --- 1. Install the binary. ---------------------------------------
sudo install -m 0755 "/tmp/zift-${ZIFT_VERSION#v}-${ARCH}-linux" /usr/local/bin/zift

# --- 2. Service user. /home/zift is root-owned so a daemon -------
#       compromise cannot replace top-level files (config, host key)
#       via DAC. Daemon still has group `r-x` on the parent and can
#       traverse + read.
sudo useradd --system --create-home --home-dir /home/zift \
    --shell /usr/sbin/nologin zift
sudo chown root:zift /home/zift
sudo chmod 0750 /home/zift

# --- 2.5. Pre-create audit.jsonl. Daemon can no longer create
#         top-level files in /home/zift since we just made it root-
#         owned, so the audit file has to exist before zift starts.
sudo touch /home/zift/audit.jsonl
sudo chown zift:zift /home/zift/audit.jsonl
sudo chmod 0640 /home/zift/audit.jsonl

# --- 3. Host key. /home/zift is root-owned now, so we generate as
#       root rather than as user `zift` (which has only group r-x on
#       the parent and cannot create files there). Final ownership
#       is root:zift 0640 — daemon reads, daemon-compromise cannot
#       rewrite the server's identity.
sudo ssh-keygen -t ed25519 -f /home/zift/host_ed25519 -N ""
sudo chown root:zift /home/zift/host_ed25519 /home/zift/host_ed25519.pub
sudo chmod 0640 /home/zift/host_ed25519
sudo chmod 0644 /home/zift/host_ed25519.pub

# --- 4. zift config (edit before service starts). Owned by
#       root:zift, mode 0640 — daemon reads, daemon cannot rewrite.
sudo install -o root -g zift -m 0640 zift.conf.example /home/zift/zift.conf
# Generate a real Argon2id hash for your partner:
printf '%s\n' 'alice-secret' | zift hash-password
# Edit /home/zift/zift.conf with sudoedit, paste the $argon2id$... hash:
sudo -e /home/zift/zift.conf

# --- 4.5. Create the partner's data tree. /home/zift is root-owned
#         so `sudo -u zift mkdir` would fail; create as root, then
#         chown to zift and apply the 2770 mode (setgid + group rwx).
sudo mkdir -p /home/zift/alice/inbox /home/zift/alice/outbox
sudo chown -R zift:zift /home/zift/alice
sudo find /home/zift/alice -type d -exec chmod 2770 {} +
sudo -u zift zift validate /home/zift/zift.conf

# --- 5. systemd unit. ---------------------------------------------
sudo install -m 0644 zift.service /etc/systemd/system/zift.service
sudo systemd-analyze verify /etc/systemd/system/zift.service
sudo systemctl daemon-reload
sudo systemctl enable --now zift
sudo systemctl status zift

# --- 6. fail2ban (optional). --------------------------------------
sudo install -m 0644 fail2ban-zift-filter.conf /etc/fail2ban/filter.d/zift.conf
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

# --- 8. Operator group (optional but recommended). Add yourself
#       to group `zift` for read+write access to partner data + the
#       audit log without sudo. Log out + back in after.
sudo usermod -aG zift "$USER"

# --- 9. Smoke test + cleanup. -------------------------------------
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
ZIFT_VERSION=v0.7.0
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
ZIFT_VERSION=v0.7.0
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

## 4. Provision partner credentials + lay out partner roots

v0.7.0 unifies the two old credential directives (`password`,
`key`) under a single `auth <value>` line in the config. Generate
**one or both** of the following per partner; mix and match.

### 4a. Password (Argon2id PHC)

```bash
# One per partner you want to authenticate by password.
printf '%s\n' 'alice-secret' | zift hash-password
# → $argon2id$v=19$m=65536,t=3,p=1$...
```

Paste the full `$argon2id$...` string into the partner's user
block as `auth $argon2id$...`. At most one PHC `auth` line per
user (`error.DuplicatePassword` at parse time otherwise).

### 4b. Public key (operator-managed file)

If the partner sends you a `.pub` key (or you generate one for
them), drop it under `/home/zift/keys/` and reference it from the
config:

```bash
sudo install -d -o root -g zift -m 0750 /home/zift/keys
sudo install -o root -g zift -m 0640 /path/to/alice.pub /home/zift/keys/alice.pub
```

Add `auth /home/zift/keys/alice.pub` to the partner's user block.
Multiple `auth /path/...` lines accumulate (multiple authorized
keys — handy for rotation).

### 4c. Lay out partner roots

```bash
# One per partner. With `partner-root /home/zift` set in the
# server block, you can skip the `root /...` line in the user
# block and the daemon will default to /home/zift/<partner-name>.
sudo install -d -o zift -g zift -m 2770 /home/zift/alice
sudo install -d -o zift -g zift -m 2770 /home/zift/alice/inbox /home/zift/alice/outbox
```

## 5. Write the config

Copy the starter config from `deploy/zift.conf.example`, then edit
the two things you have to customize (the partner credentials and
the allow/deny rules). Comments inside the file flag every spot
you'd typically touch.

```bash
sudo install -o root -g zift -m 0640 deploy/zift.conf.example /home/zift/zift.conf
sudo -e /home/zift/zift.conf  # sudoedit — daemon never sees a writable handle
# Paste your real Argon2id hash where the file says
# REPLACE-WITH-REAL-SALT$REPLACE-WITH-REAL-HASH (and/or uncomment
# the `auth /home/zift/keys/<partner>.pub` line); tune the partner
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

The config is owned by `root:zift` with mode `0640` (daemon reads but
cannot rewrite). Edit through `sudoedit`:

```bash
sudo -e /home/zift/zift.conf            # opens in $EDITOR as your user
sudo -u zift zift validate /home/zift/zift.conf
sudo systemctl kill -s HUP zift         # force-reload (or wait reload-interval)
```

`sudoedit` (also written `sudo -e`) is the right tool because it
opens a copy in your editor as your user, then writes back the
result with `sudo` privileges — you don't need to `sudo $EDITOR`
and inherit root's editor environment. Validation BEFORE the HUP
keeps a typo'd config from interrupting service: zift's reload path
keeps the previous config if validation fails, but it's better to
fail validation explicitly than to discover the issue at reload time.

If you want bulletproof atomic config replacement (the daemon's
mtime watcher never sees a half-written intermediate), use a staging
file:

```bash
sudo cp -a /home/zift/zift.conf /home/zift/zift.conf.new
sudo -e /home/zift/zift.conf.new
sudo -u zift zift validate /home/zift/zift.conf.new
sudo mv /home/zift/zift.conf.new /home/zift/zift.conf  # atomic rename
sudo systemctl kill -s HUP zift
```

## 6.5 Operator group (recommended)

The deploy ships with a host-level group `zift` that operators can
join to gain read+write access to partner data and read access to
the audit log without `sudo`. Two layers compose:

- **POSIX layer (host-side)**: group `zift` reads + writes anything
  partner-data-related; world has nothing.
- **SFTP layer (wire-side)**: partners (alice et al.) see only what
  their `allow`/`deny` rules grant. The on-disk POSIX mode does not
  leak into alice's view — virtual listing mode hides it.

To add yourself to the group:

```bash
sudo usermod -aG zift "$USER"
# Log out + back in (or `newgrp zift` in a single shell).
groups   # should now include zift
```

After re-login, you can:

```bash
ls -la /home/zift/                    # works, no sudo
cat /home/zift/audit.jsonl            # works (group reads)
ls /home/zift/alice/inbox/            # works
cp report.csv /home/zift/alice/outbox/  # works (drop a file for alice)
```

**Operator umask gotcha.** Host-side file drops inside the partner
tree inherit `group=zift` (thanks to setgid on the `2770` parent),
but the *mode* depends on your umask:

- `umask 022` (typical default) → new files land at `0644`
  (group reads only — alice can't fetch them via SFTP if she has
  `read` access).
- `umask 002` → `0664` (group r+w, world reads — too loose for the
  "world none" policy).
- `umask 007` → `0660` (group r+w, world none — the right answer).

When doing host-side partner-data work, set `umask 007` first or
use `install` with explicit mode:

```bash
umask 007                                                # session-wide
cp report.csv /home/zift/alice/outbox/

# Or per-file:
install -m 0660 -g zift report.csv /home/zift/alice/outbox/report.csv
```

This only affects manual operator workflows. SFTP-uploaded files
(via partners' clients) always land at the configured `publish-mode`
regardless of umask.

Three host-side files are deliberately NOT group-writable, with
specific reasoning:

| File | Mode | Owner | Why this exception |
|---|---|---|---|
| `audit.jsonl` | `0640` | `zift:zift` | Group **reads** for forensics; only the daemon writes. Group write would defeat audit integrity. |
| `zift.conf` | `0640` | `root:zift` | `root`-owned so a daemon compromise cannot self-modify the config. Edit via `sudoedit`. |
| `host_ed25519` | `0640` | `root:zift` | Same hardening as the config: daemon cannot rewrite its own SSH identity. |

Plus one fourth, hidden-by-design exception: `/<partner>/.zift-staging/`
is `0700 zift:zift` even though the partner directories above it are
`2770`. Group operators cannot inspect partial uploads in transit
without `sudo -u zift`. The directory is invisible to partners
entirely (path-validator reserves the name; listing-renderer filters
it out).

### Filesystem permissions cheat sheet

```
/home/zift/                       0750 root:zift   parent (daemon r-x)
/home/zift/<partner>/             2770 zift:zift   setgid; group rwx, world none
/home/zift/<partner>/**/*         0660 zift:zift   group rw, world none
/home/zift/<partner>/.zift-staging  0700 zift:zift  daemon-only (partial uploads)
/home/zift/audit.jsonl            0640 zift:zift   group reads only
/home/zift/zift.conf              0640 root:zift   daemon r-only (sudoedit)
/home/zift/host_ed25519           0640 root:zift   daemon r-only (sudo to rotate)
/home/zift/host_ed25519.pub       0644 root:zift   public, world readable
```

The mode applied to partner uploads is configurable via the
`publish-mode` directive (allowed: `0o600`, `0o640`, `0o660`;
default `0o660`). The mode applied to SFTP-created directories is
configurable via `mkdir-mode` (allowed: `0o2700`, `0o2750`, `0o2770`;
default `0o2770`).

### Honest framing of what each protection covers

- The config + host-key hardening protects against a daemon
  compromise pivoting to "self-edit my own config" persistence. It
  does **not** protect against a `root` privesc — anything that gets
  root can rewrite anything. That's outside the threat model.
- The audit-log read-only-for-group protects against accidental
  operator writes (a typo in a redirect, a scripted log-cleanup that
  hits the wrong file). It does **not** protect against a daemon
  compromise — the daemon owns the file and can rewrite arbitrary
  content via its existing fd. Stronger audit integrity (off-host
  log shipping, `chattr +a`) is documented as a follow-up; not on by
  default in v0.6.0.
- World-denied across the entire tree means other unprivileged users
  on the host cannot enumerate partner data or read partial uploads
  via the filesystem. They also can't read the audit log. The only
  way to reach partner data without group `zift` membership is via
  the SFTP wire — which is policy-mediated.

## 7. fail2ban (optional)

Two files: the **filter** (regex that recognizes a ban-worthy line) and
the **jail** (which file to watch + ban thresholds). Both are
pre-written; install and restart fail2ban.

```bash
# Filter: regex that matches zift's auth-failure JSON.
sudo install -m 0644 fail2ban-zift-filter.conf /etc/fail2ban/filter.d/zift.conf

# Jail: append to /etc/fail2ban/jail.local (or create it if absent).
if [ -f /etc/fail2ban/jail.local ]; then
    sudo tee -a /etc/fail2ban/jail.local < fail2ban-zift-jail.conf
else
    sudo install -m 0644 fail2ban-zift-jail.conf /etc/fail2ban/jail.local
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

## Migrating v0.6.x configs to v0.7.0

v0.7.0 makes three breaking changes to the config grammar. There is
no backward compatibility — `zift validate` refuses to load a v0.6.x
config until you update it. Apply this migration before upgrading
the binary in place:

| v0.6.x                          | v0.7.0                                | Notes                                                                       |
| ------------------------------- | ------------------------------------- | --------------------------------------------------------------------------- |
| `password $argon2id$...`        | `auth $argon2id$...`                  | Same Argon2id PHC string; one per user.                                     |
| `key ssh-ed25519 AAAA... alice` | `auth /home/zift/keys/alice.pub`      | Public keys move to operator-managed files. Multiple `auth /path` lines accumulate. |
| `root /home/zift/alice` per user | `partner-root /home/zift` (optional) | When set, `root` defaults to `<partner-root>/<user-name>`. Explicit `root` per user still wins. |

Removed-directive rejections are explicit:

```text
zift: zift.conf:line N: [user alice] 'password': PasswordDirectiveRemoved
zift: zift.conf:line N: [user alice] 'key': KeyDirectiveRemoved
```

A typical edit:

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

- Path must be absolute.
- File must be a regular file (no FIFOs, devices, or non-`file` types).
- Mode must NOT have group-write or world-write bits set. A writable
  key file is equivalent to a writable password hash; Zift refuses to
  load a config that points at one. Recommended: `chmod 0640` and
  `chown root:zift /home/zift/keys/<partner>.pub`.
- Each non-empty/non-comment line is parsed as a `<algorithm> <blob>
  [comment]` triple — same shape as `~/.ssh/authorized_keys`. Multiple
  keys per file are accumulated in order.

Audit log changes worth knowing:

- Every line now leads with `"time":"YYYY-MM-DDTHH:MM:SS.mmmZ"` (RFC
  3339 UTC, millisecond precision).
- The included `fail2ban-zift-filter.conf` adds a `datepattern` so
  fail2ban reads event time from the line itself instead of relying
  on file mtime — gives accurate findtime/bantime windows even when
  the audit log is rotated or shipped off-host. If your fail2ban
  version doesn't recognize the pattern, comment the `datepattern`
  line out and fail2ban falls back to file mtime (same as v0.6.x
  behavior).
- Existing `jq`/awk filters that key on `event` / `operation` /
  `result` / `ip` continue to work unchanged.

After editing, validate before restarting the daemon:

```bash
sudo -u zift zift validate /home/zift/zift.conf
sudo systemctl reload-or-restart zift
```

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
