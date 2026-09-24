<p align="center">
  <img src="https://raw.githubusercontent.com/shreeve/zift/main/docs/zift-social.png" alt="Logo" width="640">
</p>

# Zift

> Zift is a small SFTP server for partner file exchange.

It is for teams that run file drops and pickups for external partners
and have outgrown OpenSSH `internal-sftp` with an OS account per
partner, but do not want a managed file transfer platform with a
database, a web UI and a much larger attack surface.

- Virtual users, their credentials and their path rules live in one
  config file that reloads without a restart.
- Policy is default-deny and path-scoped. `write` creates new files;
  replacing one needs `update`.
- Each partner is jailed to their root, which symlinks cannot escape,
  and uploads appear atomically.
- Per-user source addresses, auth backoff, source suppression and
  connection caps are built in. No fail2ban needed.
- Every login and change is a JSON audit line.
- No shell, web UI, database, plugins, telemetry or OS account per
  partner. Static Linux release binaries.

Not a fit if you need a browser UI, SSO or LDAP, FTP or AS2, workflows,
quotas, clustering or self-service users. See
[`docs/evaluate.md`](docs/evaluate.md).

## Install

Install [`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/)
first; the installer uses it to verify the release. Then:

```sh
curl -fsSL https://raw.githubusercontent.com/shreeve/zift/main/install.sh | bash
```

This installs the verified binary only: to `/usr/local/bin` on a host
that runs the `zift` service, otherwise to `~/.local/bin`. Setting up the
service is [`docs/operate.md`](docs/operate.md). To build from source,
see [`docs/develop.md`](docs/develop.md).

## Quickstart

Serve a partner `foo` with password `bar`, who may browse, upload new
files and replace them under `/pending`, and download from `/archive`:

```sh
mkdir -p /tmp/zift/foo/pending /tmp/zift/foo/archive
ssh-keygen -q -t ed25519 -f /tmp/zift/host_ed25519 -N ""
HASH=$(printf '%s\n' 'bar' | zift hash-password)

cat > /tmp/zift/zift.conf <<EOF
server
  listen 127.0.0.1:2222
  host-key /tmp/zift/host_ed25519
  partner-root /tmp/zift
  log stderr

user foo
  auth $HASH
  allow / read
  allow /pending write update
  deny **.exe
EOF

zift validate /tmp/zift/zift.conf
zift serve /tmp/zift/zift.conf
```

In another terminal, log in with password `bar`:

```sh
sftp -P 2222 foo@127.0.0.1
```

Stop the server with Ctrl-C. `partner-root /tmp/zift` makes
`/tmp/zift/foo` the root for user `foo`.

## Permissions In Brief

A user can do nothing until an `allow` line grants it. `allow <pattern>
<verbs>` grants verbs on matching paths; `deny <pattern>` refuses them
outright and always wins.

| Verb | Grants |
| --- | --- |
| `read` | download, stat and list |
| `write` | create a new file |
| `update` | replace, truncate or append to an existing file |
| `delete` | remove an entry |
| `full` | all of these, plus `mkdir` and `rename` |

`/pending` covers everything below it; `*`, `?` and `**` are globs, and
every pattern starts with `/` or `**`. The full grammar, the granular
verbs and common policies are in [`docs/configure.md`](docs/configure.md).

## Documentation

- [`docs/evaluate.md`](docs/evaluate.md): who Zift is for, and the
  alternatives.
- [`docs/configure.md`](docs/configure.md): the config file,
  permissions, patterns, reloads and limits.
- [`docs/operate.md`](docs/operate.md): install, service setup, reload,
  signals, logs and runbooks.
- [`docs/security.md`](docs/security.md): threat model, guarantees and
  known caveats.
- [`docs/develop.md`](docs/develop.md): building, testing and releasing.
- [`CHANGELOG.md`](CHANGELOG.md): what changed, and how to migrate.

## License

Zift is released under the [MIT License](LICENSE). Release binaries
statically link libssh (LGPL-2.1), mbedTLS (Apache-2.0) and zlib; see
[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md).

To report a vulnerability privately, see [`SECURITY.md`](SECURITY.md).
