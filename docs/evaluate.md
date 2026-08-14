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

## What Zift Does

Zift provides:

- SFTP version 3 service over SSH.
- Virtual users defined in a text config file.
- Password auth using compact versioned passhashes (`a…`, argon2id; shared with Janus).
- Public-key auth using operator-managed key files.
- Per-user filesystem roots.
- Optional `partner-root` shorthand for `/home/zift/<user>` style
  layouts.
- Path-scoped allow/deny rules.
- A small permission vocabulary: `read`, `write`, `update`, `delete`,
  `full`, plus granular `list`, `mkdir`, and `rename`.
- Default-deny authorization.
- Structured JSON audit logs.
- Hot config reload for new sessions.
- Graceful shutdown and forced close after a configured grace period.
- Atomic publish of new uploads through a private staging directory.
- Virtualized directory listings that show partner-facing permissions
  rather than host filesystem ownership.
- Static Linux release binaries and signed release manifests.

## What Zift Refuses To Do

Zift does not contain:

- A database.
- A web UI.
- A management API.
- A plugin system.
- A scripting runtime.
- A scheduler.
- A queue.
- A transfer processor.
- A metrics endpoint.
- External identity integration.
- Cluster coordination.
- Automatic updates.
- Telemetry.

The intended model is self-contained for the normal case: one binary,
one config, built-in connection caps, auth backoff, temporary source
suppression, and optional per-user `from` CIDRs. Use a process
supervisor (systemd) if you want autostart. Pipe JSON audit logs
wherever you already ship logs. Filesystem snapshots cover backups;
external watchers handle post-upload processing. Zift does not require
fail2ban, CrowdSec, or a separate ban daemon.

## Why The Narrowness Is A Feature

SFTP servers sit on a remote trust boundary. Every feature added to the
daemon becomes something that can fail, be misconfigured, or need
patching at the worst possible time.

Zift treats operational simplicity as a security property:

- One binary is easier to inspect and roll back.
- One config file is easier to review.
- No database means no schema, migrations, connection pools, or DB
  corruption mode.
- No web UI means no browser attack surface.
- No external auth means no availability dependency on directory or
  identity systems.
- No plugin system means no third-party code execution inside the
  daemon.

This does not make Zift universally safer than larger systems. It makes
its failure modes smaller and easier to reason about for the job it
chooses to do.

## Current Maturity

The implementation is a compact Zig codebase using libssh for the SSH
transport. Release builds vendor libssh, mbedTLS, and zlib through the
Zig package graph.

The repository includes:

- unit tests via `zig build test`
- integration tests using OpenSSH clients, shell scripts, Expect, and
  Paramiko probes
- CI that builds a static Linux release-style binary and runs the
  integration suite against it
- a release workflow that builds Linux and macOS artifacts, emits
  `SHA256SUMS`, signs the manifest with cosign keyless, and publishes a
  deploy bundle
- a security guide that covers the threat model, invariants, deployment
  hardening, and known caveats

Remaining known caveats are documented in [`security.md`](security.md).
The most important are filesystem edge cases around no-replace rename
semantics and cross-filesystem atomic uploads.

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

