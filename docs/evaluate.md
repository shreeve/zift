# Should I Use Zift?

Zift is a small SFTP server for partner file transfer.

It exists because many organizations need a reliable place for external
partners to drop and pick up files, but the usual choices force one of
two bad fits:

- OpenSSH `internal-sftp` is battle-tested, but partner onboarding is
  tied to OS users, UIDs, chroot setup, filesystem ACLs, and `sshd`
  configuration.
- Managed file transfer products solve onboarding by adding databases,
  web applications, APIs, workflow engines, protocol bundles, and a much
  larger attack surface than the file-transfer job requires.

Zift is for the space between those two answers.

## The Product In One Sentence

Zift lets you run an SFTP endpoint with virtual users, file-based
configuration, path-scoped permissions, and structured audit logs from a
single binary.

## Who Zift Is For

Zift is a good fit when:

- You run partner file exchange for roughly 1 to 200 external partners.
- Partners are onboarded by operators, not by public self-service.
- You want credentials, roots, and permissions to live in reviewable
  files.
- You want to add or remove a partner by editing one config file.
- You already have a process supervisor such as systemd, launchd,
  Docker, Kubernetes, supervisord, runit, or similar.
- You want the service to keep working without a database, UI, plugin
  runtime, or external control plane.
- You care more about operational predictability than feature breadth.

Zift is especially natural for B2B integration flows such as:

- vendor upload drop zones
- customer report pickup
- payroll or claims file exchange
- CSV/JSON/EDI handoff where parsing happens outside the transfer
  service
- internal systems that need to expose SFTP to partners with stock
  clients

## Who Should Not Use Zift

Do not choose Zift if you need:

- Web-based administration.
- Browser-based file management.
- LDAP, Active Directory, PAM, Kerberos, OAuth, OIDC, SAML, or SSO.
- FTP, FTPS, AS2, WebDAV, HTTP download links, or multi-protocol MFT.
- Built-in scheduling, retry queues, transfer orchestration, EDI
  parsing, antivirus, PGP, or post-transfer scripting.
- External user self-service, password reset, invitations, or account
  lifecycle workflows.
- Multi-node clustering, active-active replication, or leader election.
- Per-user quotas or bandwidth shaping inside the SFTP daemon.
- Windows server deployment.
- Vendor support contracts or compliance certifications that require a
  commercial MFT provider.

Those are valid needs. They are just different products.

## Why Not OpenSSH?

OpenSSH `internal-sftp` is the right answer when the deployment is
small and OS users are acceptable.

Prefer OpenSSH if:

- You have only a few partners.
- Creating OS users is not a burden.
- Coarse filesystem permissions are enough.
- You do not need a per-operation JSON audit log.
- You are already comfortable with `sshd_config`, `Match` blocks,
  chroots, and filesystem ACLs.

Zift becomes interesting when that setup stops being simple. Zift users
are virtual. A partner is a block in `zift.conf`, not an entry in
`/etc/passwd`. Policy is expressed in SFTP terms such as `read`, `write`,
`update`, and `delete`, scoped to virtual paths. Reloading the config affects new
sessions without restarting `sshd` or changing OS account state.

## Why Not SFTPGo Or MFT?

SFTPGo and commercial MFT platforms are better when you actually want a
platform.

They provide features Zift intentionally does not have: web UI, database
state, API management, multi-protocol support, workflows, roles,
external identity, and self-service. Those features are valuable when
they are requirements.

Zift chooses the opposite tradeoff. It removes whole categories of
failure by refusing to own them:

- no DB backups or schema migrations
- no admin session cookies
- no CSRF surface
- no web asset pipeline
- no plugin API
- no background workers
- no vendor control plane
- no telemetry endpoint
- no hidden runtime state

The cost is obvious: if you need those features, Zift will not grow them
for you.

## What Zift Is, And Is Not

Zift serves SFTP version 3 to virtual users from one config file, with
default-deny path rules, jailed roots, per-user source addresses,
built-in abuse controls, JSON audit lines, hot reload and atomic
uploads (see the [README](../README.md)). It has no database, web UI,
management API, plugins, scheduler, metrics endpoint, external
identity, clustering, automatic updates or telemetry: each would be one
more thing on a trust boundary to fail, misconfigure or patch. A
supervisor starts it, a log shipper takes the audit lines, snapshots
cover backups, and external watchers handle post-upload processing.

## Current Maturity

Zift is a compact Zig codebase on libssh, with unit tests, fuzzing, and
an integration suite that drives real OpenSSH and Paramiko clients
against the same static release binary users run. Releases are signed
with cosign.

Read the [known caveats](security.md#known-caveats) before deciding. The
ones most likely to matter: partner roots need a filesystem with
no-replace rename (not NFS or SMB), a reload does not cut off a partner
who is already connected, and overwrites are not atomic.

## The Evaluation Test

Ask these questions:

1. Can every partner be represented as a virtual user, a root directory,
   one or more credentials, and a handful of path rules?
2. Is SFTP the only protocol you need this daemon to speak?
3. Are operators, not external users, responsible for onboarding?
4. Can post-transfer work happen outside the SFTP server?
5. Is a plain-text config file a better source of truth for your team
   than a database-backed UI?

If yes, Zift is probably a strong fit.

If no, use OpenSSH for the small/simple case or a real MFT platform for
the platform case.

