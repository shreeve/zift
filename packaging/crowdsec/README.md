# CrowdSec Integration For Zift

This directory ships a CrowdSec parser, three scenarios, and a
collection manifest for the Zift SFTP server.

CrowdSec is an alternative to the fail2ban configuration that ships
in `packaging/fail2ban/`. The two tools solve the same problem
(translating Zift audit-log failures into bans) but differ in
operational shape:

- **fail2ban** is local, simple, and keeps state in a SQLite file
  on this host.
- **CrowdSec** is local-with-optional-network, has scenarios that
  understand time decay, and can share decisions across a fleet
  via a central LAPI or the CrowdSec Console.

Pick one. Running both on the same audit log can produce duplicate
bans.

## What This Ships

```text
packaging/crowdsec/
├── README.md
├── acquis-zift.yaml                # log acquisition config
├── parsers/
│   └── s01-parse/
│       └── zift-logs.yaml          # parse audit JSONL, normalize log_type
├── scenarios/
│   ├── zift-bf.yaml                # fast brute force, ban
│   ├── zift-slow-bf.yaml           # slow brute force, ban
│   └── zift-dos.yaml               # pre-auth connection storm, alert-only
└── collections/
    └── zift.yaml                   # bundle manifest
```

Naming convention: every component uses the `shreeve/zift-*`
namespace, mirroring CrowdSec Hub conventions (e.g.
`crowdsecurity/sshd`). If you fork or relabel this package, update
the `name:` field inside each file and the `parsers:` / `scenarios:`
lists inside `collections/zift.yaml` to match.

## What The Parser Produces

For every audit line where `event == "zift.audit"`, the parser
populates these event metas:

| Meta field            | Value                                                |
| --------------------- | ---------------------------------------------------- |
| `service`             | `zift`                                               |
| `source_ip`           | client IP from the `ip` field                        |
| `zift_user`           | virtual username from the `user` field, when known   |
| `zift_operation`      | the full operation string (e.g. `auth.password`)     |
| `zift_result`         | `ok`, `denied`, or `failed`                          |
| `zift_detail`         | short reason (e.g. `bad password`, `unknown user`)   |
| `log_type`            | `zift_auth_fail`, `zift_conn_fail`, or `zift_audit`  |

The `log_type` is the field the shipped scenarios filter on:

- `zift_auth_fail` — denied/failed `auth.password`, `auth.publickey`,
  or `auth.too_many_attempts`. Authentication-layer failures.
- `zift_conn_fail` — denied `accept.rejected` (`max-connections`
  reached) or failed `handshake.failed`. Pre-auth.
- `zift_audit` — everything else. Successful operations, idle
  timeouts, session lifecycle, and policy denials by an
  authenticated partner (e.g. a partner with `allow /inbox add`
  trying to upload `**.exe`).

Policy denials are deliberately not classified as `zift_auth_fail`.
A partner hitting a `deny` rule is exercising the policy, not
attacking it.

## Threshold Summary

| Scenario          | Trigger                                     | Bans by default? |
| ----------------- | ------------------------------------------- | ---------------- |
| `zift-bf`         | 5 auth failures from one IP, fast           | yes              |
| `zift-slow-bf`    | 30 auth failures from one IP, slow          | yes              |
| `zift-dos`        | 30 pre-auth connection failures per minute  | **no (alert)**   |

`zift-dos` is alert-only because pre-auth failures can be a
legitimate partner hitting concurrency limits. Flip
`remediation: true` in `scenarios/zift-dos.yaml` (or write a
matching rule in `/etc/crowdsec/profiles.yaml`) if your environment
needs it to ban.

The ban duration itself is not set in these scenario files. It is
set in `/etc/crowdsec/profiles.yaml` — adjust there if the default
profile duration (4 hours, on most distros) is too short or long.

## Install (Local Files)

Use this path if you want to deploy the integration alongside your
Zift install before this collection is published to the CrowdSec
Hub. CrowdSec must already be running on the host.

```sh
sudo install -m 0644 acquis-zift.yaml /etc/crowdsec/acquis.d/zift.yaml

sudo install -d /etc/crowdsec/parsers/s01-parse
sudo install -m 0644 parsers/s01-parse/zift-logs.yaml \
  /etc/crowdsec/parsers/s01-parse/zift-logs.yaml

sudo install -d /etc/crowdsec/scenarios
sudo install -m 0644 scenarios/zift-bf.yaml      /etc/crowdsec/scenarios/zift-bf.yaml
sudo install -m 0644 scenarios/zift-slow-bf.yaml /etc/crowdsec/scenarios/zift-slow-bf.yaml
sudo install -m 0644 scenarios/zift-dos.yaml     /etc/crowdsec/scenarios/zift-dos.yaml

sudo install -d /etc/crowdsec/collections
sudo install -m 0644 collections/zift.yaml /etc/crowdsec/collections/zift.yaml

sudo systemctl reload crowdsec
```

## Install (Hub, future)

Once `shreeve/zift` is published to the CrowdSec Hub:

```sh
sudo cscli collections install shreeve/zift
sudo install -m 0644 acquis-zift.yaml /etc/crowdsec/acquis.d/zift.yaml
sudo systemctl reload crowdsec
```

The acquis file is still local — Hub publication covers the parser
and scenarios, not which log file to read.

## Verify

After reload, confirm CrowdSec sees everything:

```sh
sudo cscli parsers list   | grep zift
sudo cscli scenarios list | grep zift
sudo cscli collections list | grep zift
```

Tail acquisition to confirm lines are being claimed by the parser:

```sh
sudo cscli metrics show acquisition
sudo cscli metrics show parsers     | grep -E "zift|Lines"
sudo cscli metrics show scenarios   | grep zift
```

Trigger a synthetic auth failure to exercise the pipeline (using
an SFTP client with a bad password against a real configured user):

```sh
sftp -P 2222 ally@SERVER   # type a wrong password 5+ times
sudo cscli alerts list
sudo cscli decisions list
```

You should see an alert (and, depending on profile, a decision)
attributed to `shreeve/zift-bf`.

## Customize

### Partner IP allowlist

Do not edit the shipped parser or scenarios to skip partner IPs.
Use CrowdSec's standard whitelist parser instead. Create
`/etc/crowdsec/parsers/s02-enrich/zift-whitelists.yaml`:

```yaml
name: local/zift-whitelists
description: "Local Zift partner IP whitelist"
whitelist:
  reason: "trusted Zift partner egress IPs"
  ip:
    - "198.51.100.10/32"
    - "203.0.113.0/24"
```

Reload CrowdSec. Whitelisted IPs are still parsed but never overflow
a bucket. This keeps the configuration in your local domain rather
than the upstream package.

### Username-enumeration scenario (optional)

The parser exposes `evt.Meta.zift_detail`, so a scenario keyed on
`unknown user` is one file away. We deliberately do not ship one
because partner-side typos are easy to misclassify. If you want it:

```yaml
type: leaky
name: local/zift-user-enum
description: "Detect Zift SFTP username enumeration"
filter: |
  evt.Meta.log_type == "zift_auth_fail" &&
  evt.Meta.zift_detail == "unknown user" &&
  evt.Meta.source_ip != ""
groupby: evt.Meta.source_ip
distinct: evt.Meta.zift_user
capacity: 15
leakspeed: 30m
blackhole: 1h
labels:
  service: zift
  type: bruteforce
  remediation: true
```

The `distinct: evt.Meta.zift_user` line means the bucket only fills
on a *new* attempted username, so a partner hammering one bad
username won't trigger it — only an IP cycling through ≥15 distinct
nonexistent usernames will.

### Tuning thresholds

Edit `capacity`, `leakspeed`, and `blackhole` in the scenario files
directly. Watch for partner false-positives by tailing
`sudo cscli alerts list` for a week after any change.

## Mutual Exclusion With fail2ban

If you already installed the fail2ban filter from
`packaging/fail2ban/`, remove it before turning on CrowdSec on the
same audit log:

```sh
sudo rm -f /etc/fail2ban/filter.d/zift.conf
sudo sed -i '/^\[zift\]/,/^$/d' /etc/fail2ban/jail.local
sudo systemctl restart fail2ban
```

Running both will not corrupt anything — it will just ban the same
IPs twice, in two different state stores, with two different ban
durations and clean-up policies. That is a maintenance trap, not a
defense in depth.
