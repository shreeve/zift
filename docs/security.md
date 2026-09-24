# Security Model

Zift is an SFTP server on a trust boundary. Its posture comes from
narrow scope, default-deny policy, explicit filesystem roots, and no
runtime features that add state or run code inside the daemon. This
page says what Zift protects, what it does not, and the caveats to
understand before exposing it to partners.

## Threat Model

Zift defends against:

- an authenticated partner reaching outside their root, exceeding their
  permissions, or destroying or replacing data they could only create
  or read;
- an authenticated partner using symlinks, `..`, malformed paths or SFTP
  protocol edge cases to do any of that;
- an unauthenticated client consuming connection slots or memory,
  enumerating users, or guessing credentials;
- a local unprivileged user reading partner data or in-flight uploads
  through host permissions.

It does not defend against root compromise of the host, a malicious
operator, kernel, filesystem-driver, libssh or crypto-library bugs, disk
exhaustion by allowed uploads, downstream processors that mishandle
files, or a stolen partner credential.

Run Zift as a dedicated unprivileged user. That is mandatory, not
cosmetic: virtual users have no UID, shell or home directory, and every
filesystem operation runs as the daemon's user.

## Request Path

```text
remote SFTP client
  -> SSH transport (libssh)
  -> Zift authentication
  -> path normalization
  -> policy check
  -> filesystem operation, resolved inside the user's root
```

Policy is default-deny and any matching `deny` wins
([`configure.md`](configure.md#permissions)). `write` alone never
destroys: replacing an existing file needs `update`.

## Paths And The Jail

Every client path is validated before policy or audit: at most 4096
bytes, valid UTF-8, no control bytes or DEL, `.` and `..` resolved but
never above the root, and no `.zift` (or legacy `.zift-staging`)
component anywhere, in any letter case. Policy sees the normalized
virtual path, never a host path.

Zift then walks from the partner root one component at a time with
descriptor-relative `NOFOLLOW` opens and acts relative to the parent
descriptor. A symlink inside a root is listed but never traversed, and a
final-component symlink is never opened, so no spelling can alias a
denied path, `.zift`, or anything outside the root. Opened files are
also checked against the root through the kernel's view of the
descriptor path (`/proc/self/fd` on Linux, `F_GETPATH` on macOS); keep
partner roots on ordinary local filesystems that report those honestly.

## Authentication

### Passwords

A password is stored as a 32-character passhash: `a` (the format
version) and 31 base62 characters encoding an 8-byte salt and a 15-byte
Argon2id key (64 MiB, 2 passes, 1 lane). The format and parameters are
the same as Janus, a sibling project, so a hash minted by either
verifies in the other. The digest comparison is constant-time.

Every password denial costs one Argon2id: a wrong password, an unknown
user, a key-only user and a `from` miss all run the same check against a
dummy hash when there is nothing real to check. Response time therefore
does not reveal which users exist or how they authenticate.

### Public keys

Keys live in operator-managed files (rules in
[`configure.md`](configure.md#auth)). User keys may be Ed25519, ECDSA
P-256, P-384 or P-521, or RSA of 2048 to 8192 bits, which must sign with
`rsa-sha2-256` or `rsa-sha2-512`; SHA-1 RSA signatures and DSA are
refused. The host key may be any unencrypted key libssh loads, smaller
RSA included, and never signs with SHA-1.

A public-key probe for an unknown user and for a known user with keys
outside `from` look the same to the client; only the audit detail
differs. A password-only user is distinguishable (see Method narrowing).

### Method narrowing

A password-only user's failure replies advertise only `password`, so
clients stop offering every agent key first. That lets a probing client
tell a password-only user from an unknown one. Partner names are usually
pre-shared, so this is the right trade; if it matters, give every user
both a password and a key.

## Abuse Controls

These are built in and always on; there is nothing to install or
enable. Their numbers are in the [Limits](configure.md#limits) table.

- **Login grace.** A connection must log in within a fixed time from
  accept, key exchange included, however busy it keeps the server.
- **Per-connection ceilings.** Hard failures (a bad password, a
  password from outside `from`) back off a little longer each time and
  end the connection after a few. Soft operations (key offers, `none`,
  other SSH messages) are only counted, with a higher ceiling.
- **Source suppression.** A burst of hard failures from one source
  refuses that source for a while, including its connections still
  logging in. A successful login does not clear the count. A source is
  an IPv4 address or an IPv6 /64.
- **Connection caps.** `max-connections` bounds all sessions,
  `max-unauth-connections` those not yet logged in, and each source
  gets a small share of pre-auth connections. Refusals are audited at
  most once a minute per source.
- **Bounded password work.** Only a few Argon2id checks run at once, so
  a flood of bad logins cannot exhaust memory; the rest wait within
  their login grace.
- **No shell or forwarding.** After the SFTP subsystem starts, extra
  channels and channel or global requests (`exec`, `pty-req`,
  `tcpip-forward`, ...) are refused.

Prefer `from` for partners with stable addresses. A host firewall is
optional defense in depth; keep administrative SSH on a different port.
Serving on port 22 needs `CAP_NET_BIND_SERVICE`, which the shipped unit
withholds; [`operate.md`](operate.md#set-up-the-host) has the drop-in.

## Uploads And The Per-Partner Namespace

New uploads are written to `<root>/.zift/staging/` and renamed into
place when the client closes them. Staging files are private while in
flight, publish re-checks policy and the clobber rule, and an upload
abandoned by a disconnect is removed. Orphans left by a crash are swept
at that partner's next login once older than `max(idle-timeout, 15m)`;
the sweep skips uploads still open in this process.

`<root>/.zift/` is reserved: partners cannot name it in any request or
see it in any listing. Besides `staging/`, which only the daemon uses,
operators may keep per-partner notes there. Zift checks both levels when
a session starts and again before its first upload, and new uploads fail with "staging dir unavailable" if
either is wrong; logins and downloads still work.

| Path | Must be | Created as |
| --- | --- | --- |
| `.zift` | a real directory owned by the daemon's user or root, with no group-write and no other access | `0750`, daemon's user |
| `.zift/staging` | a real directory owned by the daemon's user, with no group or other access | `0700`, daemon's user |

Zift creates both on the first upload. To keep notes there and stop the
daemon from changing `.zift` itself, create it root-owned, and then
create `staging` yourself, since the daemon can no longer do it:

```sh
sudo install -d -o root -g zift -m 0750 /home/zift/<partner>/.zift
sudo install -d -o zift -g zift -m 0700 /home/zift/<partner>/.zift/staging
sudoedit /home/zift/<partner>/.zift/notes.md
```

Staging lives under the partner root, not the target directory, so
default ACLs and setgid inheritance on `/pending` do not apply while a
file is staged; use `publish-mode` or downstream fixups if processors
depend on them. The partner root and the target must be on one
filesystem: Zift refuses a cross-filesystem publish rather than copy
bytes non-atomically.

## Audit Logging

Every login, open, change and refusal is audited as one JSON object per line
([`operate.md`](operate.md#logs)). Partner-supplied fields (user name,
path, detail) are escaped so a line is always valid JSON and cannot be
split or forged: invalid UTF-8 becomes U+FFFD, and control characters,
C1 controls, DEL, U+2028, U+2029 and the bidi override and isolate
characters are written as `\uXXXX`.

Audit favors availability. If the log cannot be opened at startup,
`serve` exits. Once running, a failed write or reopen is reported on
stderr and serving continues. If you need fail-closed audit, keep the
log where partners cannot fill it, ship it off-host, and have your
supervisor stop the service when delivery fails.

## Host Posture

Use the shipped systemd unit and the layout in
[`operate.md`](operate.md): a dedicated `zift` user with no
capabilities, config, host key and key files owned by `root:zift` and
not writable by the daemon, partner roots `2770 zift:zift`, and the
daemon's writable tree marked non-executable. `validate` refuses a
config whose host key, key files, audit log or config file lie inside a
partner root, where a partner could read or replace them.

## Supply Chain

Release binaries are built by GitHub Actions with Zig 0.16.0 from
libssh, mbedTLS and zlib pinned in `build.zig.zon`. Linux binaries are
static; macOS binaries link only libSystem. `SHA256SUMS` covers every
published file and is signed with cosign keyless through the release
workflow's OIDC identity. The installer checks the checksum only; to
verify the signature too, install by hand
([`operate.md`](operate.md#by-hand)). A local build carries no such
provenance.

## Known Caveats

- **Reload does not revoke live sessions.** A removed partner, a changed
  password or a new `deny` applies to new sessions only. Restart to cut
  off open sessions.
- **Clobber protection needs a no-replace rename.** Publish and rename
  without `update` use `renameat2(RENAME_NOREPLACE)` on Linux or
  `renameatx_np(RENAME_EXCL)` on macOS. On NFS, SMB and some FUSE
  mounts that lack it, they fail rather than risk replacing a file.
- **Overwrites are not atomic.** Only new uploads are staged. A partner
  with `update` who overwrites a file writes it in place, so a reader
  can see it half-written.
- **Bad key signatures are not counted or answered.** libssh drops a
  public-key request with an invalid signature, or a SHA-1 `ssh-rsa`
  signature, before Zift sees it: the client gets no reply and waits
  for its own timeout, and the attempt does not count toward the auth
  ceiling. The login grace still frees the slot. Clients that can only
  sign RSA with SHA-1 cannot log in with an RSA key.
- **Case and Unicode on macOS.** Matching is byte-exact and
  case-sensitive, but APFS and HFS+ are case-insensitive and treat
  Unicode normalization forms as the same name. There, `deny **.exe`
  misses `TOOL.EXE`, and a deny of an NFC name misses its NFD spelling.
  `.zift` is matched case-insensitively and is ASCII, so it is not
  affected, and Linux filesystems are not affected. Prefer
  case-sensitive filesystems for partner roots.
- **Unreachable names.** Names that are not valid UTF-8, contain control
  bytes, or exceed 255 bytes cannot be named over SFTP and
  are left out of listings.
- **Shared addresses share a counter.** Partners behind one NAT, or in
  one IPv6 /64, share suppression and the per-source pre-auth cap. One
  of them guessing badly can lock the others out until the suppression
  expires.
- **One daemon per partner root.** Two Zift processes serving the same
  root can sweep each other's in-flight uploads.
- **Public-key timing is close, not identical.** Password denials cost
  exactly one Argon2id; public-key denials differ by microseconds of key
  parsing.
- **No quotas.** Disk space and full disks are the operating system's
  business.

## Review Checklist

Before exposing a deployment:

- `zift validate` succeeds as the service user.
- Zift runs as a dedicated unprivileged user under the shipped unit.
- The config, host key and key files are not writable by the daemon.
- Partner roots are on local filesystems that support no-replace
  rename, one filesystem per root.
- Partners with stable egress addresses have `from` lines.
- Audit logs go to the journal or a monitored file, and someone watches
  for `config.reload` failures.
- The previous binary and a config backup are at hand.
