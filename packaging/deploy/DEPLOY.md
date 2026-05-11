# Zift Deploy Bundle

This file is included in the release deploy bundle. The full operations
guide lives at `docs/operate.md` in the source tree. The commands below
are the short production path for the bundled `/home/zift` layout.

## Bundle Contents

```text
zift-deploy-X.Y.Z/
├── LICENSE
├── THIRD_PARTY_LICENSES.md
├── DEPLOY.md
├── zift.conf.example
├── zift.service
├── fail2ban-zift-filter.conf
├── fail2ban-zift-jail.conf
└── logrotate-zift.conf
```

## Install Binary

```sh
ZIFT_VERSION=0.7.1
ARCH=$(uname -m)

curl -fsSLO "https://github.com/shreeve/zift/releases/download/v${ZIFT_VERSION}/zift-${ZIFT_VERSION}-${ARCH}-linux"
sudo install -m 0755 "zift-${ZIFT_VERSION}-${ARCH}-linux" /usr/local/bin/zift
zift version
```

Verify release provenance:

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

## Create Service User And Runtime Tree

```sh
sudo useradd --system --create-home --home-dir /home/zift \
  --shell /usr/sbin/nologin zift

sudo chown root:zift /home/zift
sudo chmod 0750 /home/zift

sudo touch /home/zift/audit.jsonl
sudo chown zift:zift /home/zift/audit.jsonl
sudo chmod 0640 /home/zift/audit.jsonl
```

## Host Key

```sh
sudo ssh-keygen -t ed25519 -f /home/zift/host_ed25519 -N ""
sudo chown root:zift /home/zift/host_ed25519 /home/zift/host_ed25519.pub
sudo chmod 0640 /home/zift/host_ed25519
sudo chmod 0644 /home/zift/host_ed25519.pub
```

## Partner Root And Key Directory

```sh
sudo install -d -o root -g zift -m 0750 /home/zift/keys
sudo install -d -o zift -g zift -m 2770 /home/zift/ally
sudo install -d -o zift -g zift -m 2770 /home/zift/ally/pending
sudo install -d -o zift -g zift -m 2770 /home/zift/ally/archive
```

Generate a password hash:

```sh
printf '%s\n' 'ally-secret' | zift hash-password
```

Or install a public key:

```sh
sudo install -o root -g zift -m 0640 ally.pub /home/zift/keys/ally.pub
```

Here `ally.pub` is the partner's OpenSSH public key, supplied out of
band.

## Config

```sh
sudo install -o root -g zift -m 0640 zift.conf.example /home/zift/zift.conf
sudo -e /home/zift/zift.conf
sudo -u zift zift validate /home/zift/zift.conf
```

Use `auth $argon2id...` for password auth and
`auth /home/zift/keys/<partner>.pub` for public-key auth. With
`partner-root /home/zift`, user `ally` defaults to root
`/home/zift/ally`.

## systemd

```sh
sudo install -m 0644 zift.service /etc/systemd/system/zift.service
sudo systemd-analyze verify /etc/systemd/system/zift.service
sudo systemctl daemon-reload
sudo systemctl enable --now zift
sudo systemctl status zift
```

Reload config after edits:

```sh
sudo -u zift zift validate /home/zift/zift.conf
sudo systemctl kill -s HUP zift
```

## Optional fail2ban

```sh
sudo install -m 0644 fail2ban-zift-filter.conf /etc/fail2ban/filter.d/zift.conf

if [ -f /etc/fail2ban/jail.local ]; then
  sudo tee -a /etc/fail2ban/jail.local < fail2ban-zift-jail.conf
else
  sudo install -m 0644 fail2ban-zift-jail.conf /etc/fail2ban/jail.local
fi

sudo fail2ban-client -t
sudo systemctl restart fail2ban
sudo fail2ban-client status zift
```

## Optional logrotate

```sh
sudo install -m 0644 logrotate-zift.conf /etc/logrotate.d/zift
sudo logrotate -d /etc/logrotate.d/zift
```

The logrotate rule signals Zift with `SIGUSR1` so it reopens the audit
log after rotation.

## Smoke Checks

```sh
sudo systemctl is-active zift
sudo -u zift zift validate /home/zift/zift.conf
nc -z -w2 127.0.0.1 2222
tail -n 20 /home/zift/audit.jsonl
```

For rationale, configuration details, and security caveats, read the
source-tree docs:

- `docs/evaluate.md`
- `docs/configure.md`
- `docs/operate.md`
- `docs/security.md`
- `docs/develop.md`

