# Zift Design Plan

> **At runtime Zift requires one config file, one host key, one or more directories, and one TCP socket; if `log` is set to a path it additionally writes to that file. It does not talk to any other process, service, database, or network endpoint. If the machine is up and the filesystem is sound, Zift is up.**

Zift is a single-binary SFTP server. It has no web UI, no database, no plugin system, no clustering, no scripting language, no HTTP API, and no telemetry. It speaks SFTP on the wire so that any unmodified client can connect to it. Internally it runs virtual users defined in a single text config file that auto-reloads when its mtime changes. Adding a partner is a vim session and a save.

Zift is small enough that a single reviewer can read the whole codebase in a single sitting. Zig is the implementation language because the build artifact is one statically-linked binary on Linux and because the standard library threads an explicit `Io` value through every blocking call, rather than relying on hidden global state. The design and the config DSL are independent of the language: nothing in this document depends on the implementation being Zig.

This document is the canonical specification for what Zift is and is not. It exists to be challenged. If you are reviewing this, your job is to make the design sharper or to surface a contradiction we missed. The success criterion for this document is that the tool it describes will still be running, untouched, in production five years from now.

---

## How to read this document

The reading path is who-comes-first: by section 1 you should know whether Zift is even for you, by section 2 you should know what to use instead if it is not, and only then does the document explain why the design is the way it is.

- Sections 1 and 2 are decision-relevant: who Zift is for, and how it compares to alternatives. Read these first.
- Section 3 (the boring software thesis) is the philosophical commitment that drives every later decision. If you disagree with it, you'll disagree with everything else.
- Section 5 is the constitutional limit on scope. Every later "should we add X" question is answered against it.
- Section 9 is where the design meets reality. Reviewers should attack this section first.
- Sections 6 through 8 are the concrete contract. Section 10 is what we refuse to do, with reasons. Section 11 is how to compose Zift with standard tools to get the things it refuses to do natively.
- Sections 12 and 13 are operational and downstream. They follow from the rest.

---

## 1. Audience

**This is for you if:**

- You run an SFTP service for between 1 and 200 external partners.
- Your partners come and go on a timescale of days to months and you want partner onboarding to be a paste-and-save operation.
- You want every Zift-related configuration, secret, and policy to live in files that you can git-track, diff, review, and roll back.
- You already use Linux or macOS supervision (systemd, launchd, supervisord, runit, Docker, Kubernetes Deployment, anything that restarts a crashed process). You do not need Zift to also be a process supervisor.
- You consider operational simplicity a security feature.
- You think a server you don't have to think about is the highest praise software can earn.

**This is not for you if:**

- You need a multi-tenant SaaS platform with self-service partner onboarding by external users.
- You need a graphical interface for partners or for non-technical staff to manage transfers.
- You need to integrate authentication with corporate SSO (LDAP, Active Directory, OAuth, SAML). Use a jump host with key auth in front of Zift, or use Zift only for partners who pre-share a credential.
- You need transfer scheduling, server-side scripting, post-transfer hooks, format conversion, virus scanning, EDI parsing, AS2, FTPS, FTP, or any protocol other than SFTP.
- You need horizontal scaling or active-active replication. Zift is single-host by design. For HA, run a hot standby on a separate host and use DNS or a TCP load balancer for failover; this works fine, but Zift does not coordinate with itself.
- You need an HTTP management API. There isn't one and there won't be one.

If none of the first list applies, OpenSSH `internal-sftp` is genuinely a better answer than Zift, and section 2 says so.

---

## 2. Comparison

> **Zift is worse than every product in this table at the thing that product does best. It is better than all of them at doing only one thing and never breaking.**

The honest comparison.

| Tool                              | Best when                                                                                                                            | Why Zift is different                                                                                                                                                                                                                   |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OpenSSH `internal-sftp` + `Match` | Few partners (single-digit). OS-user model is acceptable. Operations team is comfortable with sshd config and `/etc/passwd` edits.   | Zift uses virtual users (no `useradd`), supports per-user per-path per-operation policy, and reloads independently of `sshd`. OpenSSH 9.5+ added `-P` for coarse request-type filtering of the entire `sftp-server` invocation, but `-P` is per-server-binary, not per-user, and cannot express path-scoped rules. OpenSSH `sftp-server -l VERBOSE` writes per-transaction text logs; Zift's audit log is structured JSON with stable fields including the matched virtual user and the policy `result` (`ok` / `denied` / `failed`) for every operation, designed for direct ingestion by line-based aggregators. |
| SFTPGo                            | You actually want a web UI and you want a database (it defaults to SQLite but supports BoltDB, MySQL, PostgreSQL, and CockroachDB).  | Zift refuses both. SFTPGo's flexibility is its cost; the install pulls a database, a web framework, and a configuration surface measured in hundreds of options. Zift's narrowness is its cost. Pick the one whose cost you can afford. |
| FileZilla Server                  | Windows-first, GUI admin.                                                                                                            | Zift is Unix-first and headless. We do not target Windows.                                                                                                                                                                              |
| Bitvise SFTP Server               | Windows-only deployment with AD integration and commercial support.                                                                  | Zift does not run on Windows and has no AD story. Different platform, different audience.                                                                                                                                               |
| ProFTPD with mod_sftp             | You already run ProFTPD for FTP and need SFTP on the same instance.                                                                  | Zift is SFTP-only. We do not carry the FTP legacy or the mod ecosystem. mod_sftp activity has slowed considerably; verify maintenance status before depending on it.                                                                    |
| Commercial MFT (GoAnywhere, MOVEit, IBM Sterling) | Compliance frameworks that require named vendor support, AS2/EDIINT certifications, or signed contracts. | Zift is free, narrow, and has none of those. Note that complexity in this category has produced mass-impact incidents; MOVEit's CVE-2023-34362 SQL injection in 2023 compromised thousands of organizations through a feature surface unrelated to its core file-transfer function. The boring software thesis is in part a reaction to that pattern. |
| `rsync` over SSH                  | Internal automation between machines you control on both sides.                                                                      | Zift speaks the standard SFTP wire protocol, so partners with stock clients can connect without changing anything. `rsync` requires `rsync` on both ends.                                                                                |

The honest case **for** OpenSSH `internal-sftp` instead of Zift: if you have fewer than five partners, you are comfortable with OS users, you do not need per-operation policy, and you do not need operation-level audit logs, OpenSSH is already on your machine and is genuinely the right answer. Use it. Zift exists for the case where that model has stopped being simple.

---

## 3. The boring software thesis

Software for moving files between businesses has bifurcated into two failure modes. On one end, OpenSSH's `internal-sftp` is universally available and battle-tested, but it requires real OS users, real chroots, real UIDs, and `/etc/passwd` edits per partner. The moment your partner count exceeds your patience for `useradd` and `setfacl`, OpenSSH stops being simple and starts being a liability. On the other end, SFTPGo, FileZilla Server, Bitvise, GoAnywhere, and similar products solve the multi-tenant onboarding problem by adding a database, a web UI, plugin systems, REST APIs, event hooks, and a worldview where every partner relationship is a row in a table that you click on. They make the easy case complicated.

The space between these two failure modes is where most B2B file transfer actually lives: a small business, a consulting shop, a SaaS data ingest pipeline, an EDI clearinghouse desk, a payroll integrator, a healthcare claims operator. Tens of partners, not thousands. Onboarding cadence in days, not seconds. Operators who would rather edit a text file than click a wizard and would rather read source code than read a manual.

Zift is for that space. Zift is **boring software**: the kind of thing you install, configure, and forget about. The 18-month test for boring software is whether the operator is still confident the process is running, still trusts the audit log, and has not been forced to learn a new feature, migrate a database schema, or adapt to a UI redesign. Boring software does not chase relevance. It chases zero surprises.

Boring software has a small set of properties:

- **One artifact.** No package layouts, no installer wizards, no dependency trees. You drop a binary into `/usr/local/bin` and you are done.
- **One source of truth.** Config lives in one file, in plain text, that you can read in a browser tab and diff in git.
- **No background coordination.** No license servers, no telemetry endpoints, no cloud sync, no plugin auto-update, no DNS-dependent auth, no out-of-process state.
- **Loud failures only.** When something goes wrong, the operator notices immediately and can diagnose with `ls`, `ss`, `tail`, and `grep`. There are no silent degradations.
- **Frozen contracts.** The config you wrote two years ago still works today. The clients that worked then still work now.

The thesis is that this set of properties is achievable for SFTP-based file transfer if and only if the project resists feature accretion as the primary engineering discipline. Every tool in section 2's "complex" failure mode started simple and became unwearable through reasonable-sounding additions. Zift exists because we believe the discipline is possible and the value is high.

---

## 4. The product promise

Zift's complete capability envelope is the following list. This list is closed. Items not on it are not in scope. Adding to it requires meeting the criteria in section 5.

1. **SFTP service.** Zift accepts SFTP connections from any client speaking SFTP version 3 (the de-facto standard, defined by `draft-ietf-secsh-filexfer-02`; SFTP was never ratified as an RFC, and v3 is what every modern client speaks). Higher protocol versions requested by clients are negotiated down to v3 per the draft. Zift's compatibility targets — exercised in the test matrix — are OpenSSH `sftp`, WinSCP, FileZilla, Cyberduck, Java JSch, .NET SSH.NET, Python Paramiko, Go `x/crypto/ssh`, and libcurl. Other conforming SFTP v3 clients are expected to interoperate, but only the listed clients are tested. The exact set of supported and rejected SFTP request types is in section 7.6.
2. **Virtual users.** A user in Zift is a name, a password hash and/or one or more public keys, a real-filesystem root directory, and a list of allow/deny rules. Zift users are not OS users. They have no `/etc/passwd` entry, no shell, and no UID. The mapping from virtual user to filesystem is explicit in the config.
3. **Per-path policy.** Each user's rules are evaluated on every operation. A rule is `allow <pattern> <permissions...>` or `deny <pattern...>`. Default is deny. Permissions are explicit tokens: `read`, `write`, `list`, `mkdir`, `remove`, `rename`. Deny overrides allow.
4. **Path-jail enforcement.** Every filesystem operation is path-resolved against the user's real-filesystem root, then verified post-open by reading back the canonical path of the underlying file descriptor. Symlink escapes are blocked at the fd layer, not at the string layer.
5. **Auto-reload on config change.** When the config file's mtime changes, Zift parses it. If the new config is valid, new sessions use it. If it is invalid, the operator gets a stderr warning and the previous config keeps serving. Existing sessions are never yanked mid-transfer.
6. **Structured audit log.** Every authentication attempt and every privileged or denied operation emits a single JSON line to the configured audit destination (default stderr; an absolute path in the `log` server property opens a file). Operators pipe stderr to whatever log infrastructure they already use, or point `log` at a path their log shipper tails.
7. **Password and public-key authentication.** Passwords are stored as Argon2id PHC strings. Public keys are stored as `authorized_keys`-style lines in the config. Failed authentication does not reveal whether the username exists.
8. **Companion utilities.** `zift hash-password` reads a password from stdin and prints an Argon2id PHC string. `zift validate <config>` parses a config file, prints any validation errors, and exits non-zero on failure. `zift version` prints the build metadata.

These eight items are the entire surface area. There are no other commands, modes, or behaviors.

---

## 5. The discipline rule

> Zift does not grow features. The capability list in section 4 is closed. Capabilities not on it must be achieved by composing Zift with external tools.

This is the constitutional rule. It exists because every project we are trying not to become started simple and became something else by accepting reasonable-sounding additions. The bar for adding a capability to Zift is intentionally severe.

**A new capability may be considered for inclusion only if it satisfies all of the following:**

- It cannot be achieved by composition. A wrapper script, a cron job, a reverse proxy, a sidecar process, a logrotate rule, a filesystem ACL, an inotify watcher, or a `tee` from stderr is not Zift's job.
- It does not introduce a new runtime dependency outside the existing set (libssh, libc, the host filesystem, one TCP socket).
- It does not add a new configuration concept. The user model, the rule model, and the per-server settings are exhaustive.
- It does not require a new persistent state location. There is no database. There is no cache directory. There is no spool. There is no key store outside the config file.
- It is requested by at least three independent operators using Zift in production for at least six months. Theoretical demand does not count.

**Things that look like features but are not:**

- New SFTP protocol message support (e.g. SFTP v4+) is a protocol change, not a feature, and is gated by stable client demand. SFTP v3 is what every client speaks today.
- Bug fixes are not features. Behavior that contradicts this document or the SFTP spec gets fixed without ceremony.
- Performance improvements that do not change observable behavior are not features.
- Platform support (a new OS target, a new CPU architecture) is not a feature; it is distribution.

**Things explicitly forbidden by this rule:**

- Web UI of any kind, including a "minimal admin page."
- Database, including SQLite, BoltDB, embedded RocksDB, or a serialized state file.
- HTTP control plane, including health checks. Use `pgrep zift` or `ss -ltn`.
- Plugin system. There is no API surface for third-party code.
- Embedded scripting language. There is no Lua, Wren, Starlark, JS, or anything else.
- External authentication providers. No LDAP, no AD, no OIDC, no PAM, no Kerberos.
- Built-in TLS termination, FTPS, FTP, HTTP file access, WebDAV, AS2, or any non-SFTP protocol.
- Telemetry, update checks, or any phone-home behavior of any kind.
- Cluster coordination, leader election, or replication.

If the user community needs any of these, the user community needs a different product. We would rather Zift remain useful and small than become unrecognizable and large.

---

## 6. The config DSL

The config is a single text file. It is line-oriented and indentation-sensitive. There is no quoting, no escaping for the common case, no nested objects, no inheritance, no includes, and no environment variable interpolation. The format is designed so that a new partner is added by copying and pasting a five-line block, changing four values, and saving.

### 6.1 Grammar

```
config       = block*
block        = section_header (NL property)*
section_header = "server" | "user " name
property     = INDENT key " " value
key          = lowercase ASCII, hyphens allowed
value        = remainder of line until newline
NL           = "\n"
INDENT       = one or more spaces or tabs
comment      = line whose first non-whitespace character is "#" (whole line ignored; no inline comments after a value)
blank line   = ignored
name         = ASCII letters, digits, "_", "-", "."
```

There is no lexical scope, no expression language, and no macro system. Everything in the file is data.

### 6.2 Sections and properties

**The `server` section** appears exactly once.

| Property          | Type          | Required | Default    | Meaning                                                                          |
| ----------------- | ------------- | -------- | ---------- | -------------------------------------------------------------------------------- |
| `listen`          | host:port     | yes      | —          | TCP listen address. Use `0.0.0.0:port` to listen on all interfaces.              |
| `host-key`        | path          | yes      | —          | Path to an unencrypted SSH private key (Ed25519 recommended).                    |
| `reload-interval` | duration      | no       | `2s`       | How often the config mtime is polled. Set to `0` to disable runtime reload.     |
| `log`             | `stderr`/path | no       | `stderr`   | Where audit JSON lines go. Default is stderr; an absolute path opens that file. |
| `idle-timeout`    | duration      | no       | `300s`     | Disconnect after this much idle time on a session. `0` disables.                |
| `max-connections` | integer       | no       | `128`      | Maximum concurrent SFTP sessions. Excess connections are rejected at TCP.        |

**The `user <name>` section** appears once per virtual user.

| Property   | Type           | Required          | Default | Meaning                                                                                       |
| ---------- | -------------- | ----------------- | ------- | --------------------------------------------------------------------------------------------- |
| `password` | Argon2id PHC   | one of pwd or key | —       | Password hash from `zift hash-password`. Single line. Verified at login.                      |
| `key`      | OpenSSH pubkey | one of pwd or key | —       | One key per `key` line. Multiple `key` lines per user are allowed.                            |
| `root`     | absolute path  | yes               | —       | Real-filesystem root for this user. Must exist and be a directory at config load.             |
| `allow`    | rule           | zero or more      | —       | `allow <virtual-pattern> <permission...>`. Permissions: `read write list mkdir remove rename`. |
| `deny`     | pattern list   | zero or more      | —       | `deny <pattern...>`. A matched pattern denies all permissions on the matched virtual path.    |

The default policy with no `allow` rules is deny everything.

**Permission semantics.** Each token controls a specific set of SFTP request types:

- `read`: open-for-read (`SSH_FXP_OPEN` without write flags), and the stat-family requests on a path (`SSH_FXP_STAT`, `LSTAT`, `FSTAT`). `SSH_FXP_READ` follows from a successful read-open. `SSH_FXP_REALPATH` does not require any permission; it returns a normalized virtual path and never reveals real-filesystem paths.
- `write`: open-for-write/create/truncate, and `SSH_FXP_WRITE` (positional).
- `list`: `SSH_FXP_OPENDIR` and `SSH_FXP_READDIR`.
- `mkdir`: `SSH_FXP_MKDIR`.
- `remove`: `SSH_FXP_REMOVE` for files and `SSH_FXP_RMDIR` for directories.
- `rename`: `SSH_FXP_RENAME`. The token must be granted on both the source and destination virtual paths.

**Overlapping roots are rejected.** `zift validate` and the runtime config loader reject configs in which two users' `root` paths overlap (one is a path prefix of the other, or both canonicalize to the same real path). Sharing filesystem state between virtual users would defeat the per-user policy model and is not supported.

### 6.3 Pattern matching

Patterns match against the **virtual path** (what the SFTP client sees, always rooted at `/`), not the real filesystem path. Glob semantics are intentionally limited:

- `*` matches any sequence of characters that does not include `/`.
- `?` matches any single character that is not `/`.
- All other characters match literally.
- A pattern with no `*` or `?` is a literal **path-component** prefix match. A pattern `P` matches a virtual path `V` if and only if `V` equals `P`, or `V` starts with `P` followed by `/`. So `allow /pending read write list` permits operations on `/pending`, `/pending/inbox`, and `/pending/inbox/file.csv`, but does **not** match `/pendingfoo` or `/pendingevil`. The literal prefix never matches a sibling whose name shares a prefix.
- For `deny <pattern...>`, each pattern in the line is evaluated independently. Any matching pattern denies the path. An invalid pattern makes the whole config invalid (rejected at validate, startup, or reload).

There is no character-class syntax, no `**`, no regex, no negation, no alternation, and no anchoring beyond the implicit start-of-path. **The pattern syntax does not expand.** If a use case calls for more expressiveness, the answer is to add a more specific rule, not a more powerful pattern language. This is a hard line because pattern languages are the most common way that simple config files become small programming languages.

### 6.4 Worked example

```
# /etc/zift/zift.conf

server
  listen 0.0.0.0:2222
  host-key /etc/zift/host_ed25519
  idle-timeout 300s
  log /var/log/zift/audit.jsonl

# Acme's outbound integration.
# To rotate Acme's password: zift hash-password < newpw.txt > tmp; paste below; save.
user acme
  password $argon2id$v=19$m=65536,t=3,p=1$abcd$efgh
  root /srv/sftp/acme
  allow /pending read write list mkdir
  allow /pending/* remove rename
  allow /archive read list
  deny /archive/*.lock

# Pubkey-only user. Three keys allowed.
user payroll-prod
  key ssh-ed25519 AAAAC3NzaC1l... payroll-runner-1
  key ssh-ed25519 AAAAC3NzaC1l... payroll-runner-2
  key ssh-ed25519 AAAAC3NzaC1l... payroll-runner-failover
  root /srv/sftp/payroll
  allow / read list
  allow /uploads write mkdir

# Disabled partner. Just leave the user removed; no enable/disable knob exists.
# user vendor-q4
#   password $argon2id$...
#   root /srv/sftp/vendor-q4
#   allow / read list write mkdir remove rename
```

To onboard a new partner: copy a `user` block, change the four obvious fields, save, ask the partner to log in. The reload watcher picks it up within `reload-interval`.

To disable a partner: comment out their block, or remove it. There is no "disabled" flag because removing the block is the same operation, and we refuse to have two ways to do one thing.

To rotate a key: edit the `key` line. Save. Done.

### 6.5 Password property semantics

- The `password` value must be a complete Argon2id PHC string starting with `$argon2id$`. Generate it with `zift hash-password`.
- If the value of a `password` property is not a syntactically valid Argon2id PHC string, **Zift refuses to start** (or refuses the reload) and prints a single line on stderr identifying the user and the offending line number. Plaintext passwords are never accepted, even briefly, even with a warning. There is no "I'll fix it later" mode.
- Argon2id parameters (`m`, `t`, `p`) are embedded in the PHC string itself, so each hash carries the parameters it was produced with. Different parameter choices coexist in the same config file.
- The DSL relies on PHC hash strings containing no whitespace. The Argon2id PHC format satisfies that requirement.

### 6.6 What the config does not do

- It does not have variables, includes, or templating. If you want a templated config, generate it with whatever tool you already use and write the result to disk.
- It does not have conditional logic. There is no "if dev environment, allow X."
- It does not have units beyond duration suffixes. Memory limits, byte counts, and rate limits are not Zift's job.
- It does not have inheritance. Every user is independent. Copy-paste is the inheritance.
- It does not have a per-directory permissions concept. Permissions live on rules, rules match patterns, and a pattern can match a directory.
- It does not have a `version` field. The format is what it is. There is no schema to migrate, no compatibility matrix to consult, and no upgrade ritual.

---

## 7. Operational model

### 7.1 Process lifecycle

Zift is a single foreground process. It is intended to run under whatever supervisor you already use. We provide example unit files for systemd and launchd in the repository; we do not bundle, install, or configure a supervisor.

- **Startup.** Zift parses the config. If parsing fails, Zift exits non-zero with the parse error on stderr. If the host key is missing or unreadable, Zift exits non-zero. If a user's `root` directory does not exist, Zift exits non-zero. There is no daemonization; there is no pidfile; there is no fork.
- **Steady state.** Zift listens on the configured TCP socket. Each accepted connection runs in its own OS thread. The accept thread also polls the config file mtime once per `reload-interval`.
- **Reload.** Detected via mtime change. The new config is parsed. If valid, an internal pointer to the active config is atomically swapped under a mutex. New sessions use the new config; existing sessions continue with the config they authenticated against until they disconnect. If invalid, the new config is rejected with an error to stderr and the previous config remains in force. Reload is also triggered by `SIGHUP` if you prefer explicit control.
- **Shutdown.** `SIGTERM` and `SIGINT` initiate graceful shutdown: the listening socket is closed, no new sessions are accepted, in-flight sessions are given a 30-second grace period to finish, then any remaining sessions are forcibly closed and the process exits zero. The 30-second grace period is a fixed implementation constant; there is no `shutdown-grace` config knob. `SIGKILL` causes immediate termination; the OS reclaims the sockets and fds. SFTP has no transfer resume in v3, so an interrupted transfer must be retried by the client.

### 7.2 Signals

| Signal                | Effect                                                                                                  |
| --------------------- | ------------------------------------------------------------------------------------------------------- |
| `SIGHUP`              | Force a config reload immediately, regardless of mtime. Standard Unix convention; never causes exit.   |
| `SIGTERM` / `SIGINT`  | Graceful shutdown with grace period (default 30s) for in-flight sessions.                              |
| `SIGUSR1`             | Reopen the log file (only meaningful when `log` is set to a file path; ignored when logging to stderr). |
| `SIGKILL`             | Immediate termination. Not handled, by definition.                                                     |
| `SIGPIPE`             | Ignored. SFTP channels are written through libssh, not directly to a pipe.                             |

Zift does **not** write a PID file. The supervisor knows the PID. `pgrep zift` finds it. `pidof zift` finds it. PID files are an old Unix workaround for absent supervisors and a small but real source of bugs (stale files after crashes, races on rotation). If your supervisor wants a PID file, write it from the supervisor unit, not from Zift.

### 7.3 Reload semantics in detail

- The config file is polled by `mtime`. A reload is triggered when the file's mtime moves forward. Reloads can also be forced explicitly with `SIGHUP`, which is the canonical trigger when mtime polling is not enough.
- **mtime caveat.** Restore-from-backup, `rsync -t`, atomic-deploy patterns that preserve timestamps, and `touch -r` can produce a replaced file whose mtime is equal to or earlier than the previous one. Zift will not detect such a change via mtime polling alone. If you deploy config that way, send `SIGHUP` after the file is in place.
- A reload is a pure replacement. There is no diff or merge. The new file is the truth. Removing a `user` block in a reloaded config means new connection attempts for that user fail authentication; existing connections continue until they disconnect on their own.
- A reload that succeeds writes a single human-readable line to stderr (`zift: config reloaded`). A reload that fails (parse error, missing required field, missing user root, unreadable host key, out-of-policy Argon2id parameters, overlapping roots) writes a single human-readable line to stderr identifying the cause and the previous config remains active. The operator's editor save did not break the running system.
- The host key is loaded once at startup. Changing `host-key` in the config does not rotate the running host key; restart Zift to pick up a new host key. This is intentional: silently rotating a host key without operator action would surprise SFTP clients with a host key warning at the worst possible moment.

### 7.4 Logging and observability

- **Stderr is the recommended log destination.** Default behavior writes audit JSON lines to stderr, where any modern supervisor (systemd, launchd, runit, supervisord, Docker, k8s) captures them by default. You almost never need anything else.
- The `log` property accepts an absolute file path as a secondary mode, for operators who want Zift to write directly to a log file rather than have the supervisor route stderr. When `log` points at a file, `SIGUSR1` reopens that file (the standard logrotate handshake). `SIGUSR1` is a no-op when logging to stderr.
- All audit lines are one JSON object per line. Each line is emitted with a single `write(2)` call, capped at 4096 bytes (`PIPE_BUF` on macOS and Linux). File destinations are opened `O_APPEND`, so concurrent writes from different threads are atomic at the OS level and never interleave inside a single line. A line that would exceed the cap is truncated and a `"truncated":true` field is appended; this prevents a malicious or unusual value (e.g. an oversize path) from breaking line atomicity.
- **Audit log schema.** Each audit line is a single JSON object with the fields `event` (always `"zift.audit"`), `user`, `operation`, `result` (one of `ok`, `denied`, `failed`), `path` (optional; the virtual path the operation referenced — never a real filesystem path), `detail` (optional), and `ip` (the connecting client's IP address). Field order is stable: `event`, `user`, `operation`, `result`, `path`, `detail`, `ip`. The composition recipes in section 11 depend on this layout.
- There is no Prometheus endpoint, no `/metrics`, and no health-check HTTP server. The supervisor's notion of "is the process running?" is the health check.
- There is no distinct error log. Operational errors (libssh failures, reload rejections, accept failures) go to stderr in human-readable form, distinguishable from audit lines because they are not JSON.

### 7.5 Backup and disaster recovery

- The complete state needed to restore Zift on a new host is: the binary, the config file, the host key, and the directories the config references. Copy those four things to the new host and start the process.
- There is no database to back up, no migration to run, and no schema to worry about.
- Host key rotation is an operator action: generate the new key, update the config, restart, then notify partners that the host fingerprint changed. We do not automate this because the partner notification is the hard part.

### 7.6 SFTP request surface

Zift implements the subset of SFTP version 3 needed for ordinary file transfer. Unsupported request types receive `SSH_FX_OP_UNSUPPORTED` and the session continues.

| Request type                              | Status      | Notes                                                                                                                                                                              |
| ------------------------------------------ | ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SSH_FXP_INIT` / `VERSION`                 | implemented | Negotiation pinned to v3.                                                                                                                                                          |
| `SSH_FXP_REALPATH`                         | implemented | Returns a normalized virtual path. Never returns a real-filesystem path. Requires no permission.                                                                                   |
| `SSH_FXP_STAT`, `LSTAT`                    | implemented | Both behave identically. Zift does not expose dangling-symlink semantics distinct from `stat`. Requires `read`.                                                                    |
| `SSH_FXP_FSTAT`                            | implemented | Operates on an open handle. Inherits the open's permission.                                                                                                                        |
| `SSH_FXP_OPENDIR`, `READDIR`, `CLOSE`      | implemented | Standard directory listing. Requires `list`.                                                                                                                                       |
| `SSH_FXP_OPEN`, `READ`, `WRITE`, `CLOSE`   | implemented | Read and write are positional (offset-correct, `pread` / `pwrite`).                                                                                                                |
| `SSH_FXP_MKDIR`, `RMDIR`                   | implemented | `*at`-relative; jail-verified.                                                                                                                                                     |
| `SSH_FXP_REMOVE`                           | implemented | `unlinkat`-based; jail-verified.                                                                                                                                                   |
| `SSH_FXP_RENAME`                           | implemented | Both source and destination jail-verified; both paths policy-checked for `rename`.                                                                                                 |
| `SSH_FXP_SETSTAT`, `FSETSTAT`              | rejected    | Returns `SSH_FX_OP_UNSUPPORTED`. Clients that try to set mtime, permissions, or owner after upload (e.g. `scp -p`, rsync over sftp) see a non-fatal failure for that op only; the file itself is delivered. |
| `SSH_FXP_READLINK`, `SYMLINK`              | rejected    | Returns `SSH_FX_OP_UNSUPPORTED`. Symlinks in the jail are not user-creatable.                                                                                                      |
| `SSH_FXP_EXTENDED` (any extension)         | rejected    | Returns `SSH_FX_OP_UNSUPPORTED`. No OpenSSH extensions (`posix-rename`, `fsync`, `statvfs`, `hardlink`, `copy-data`, etc.) are recognized.                                          |
| Unknown / malformed request types          | rejected    | Returns `SSH_FX_OP_UNSUPPORTED` (unknown type) or `SSH_FX_BAD_MESSAGE` (malformed). The session continues unless malformed traffic persists.                                       |

**File modes.** Zift creates files with mode `0644` and directories with mode `0755`, both subject to the Zift OS user's `umask`. Clients cannot influence these modes (`SETSTAT` is rejected).

**Limits.** Maximum SFTP packet size is 256 KiB. Maximum path length is 4096 bytes. Maximum username length is 64 bytes. Maximum public-key line length is 8192 bytes. Audit lines are bounded to 4096 bytes per line as described in 7.4. These limits are fixed implementation constants; they are not exposed as config knobs.

---

## 8. Security model

### 8.1 Threat model

The relevant adversaries are:

1. **An authenticated partner trying to read or write outside their jail.** This is the primary threat. Partners are not trusted; they are given precisely the policy in the config and nothing else.
2. **An authenticated partner trying to escalate their permissions on shared infrastructure** (write a setuid binary, drop a `.ssh/authorized_keys`, replace a system file via symlink). Zift's job is to make this impossible regardless of operator config mistakes.
3. **An unauthenticated network attacker.** Mitigated by the SSH transport itself, the absence of a non-SSH attack surface, and the small size of Zift's auth code.
4. **An attacker with read access to the config file.** They can read password hashes (Argon2id, expensive to crack) and public keys. They cannot recover plaintext passwords. The host key is a separate file and should have stricter permissions.

Out of scope: kernel-level attacks, hypervisor escape, supply-chain attacks on libssh, and operator compromise.

### 8.2 Default deny

The policy engine starts from "everything is denied." Permissions are added by `allow` rules, which require both a pattern match and an explicit permission token. `deny` rules override `allow` rules. There is no "implicit allow on the user's own root." If the config has no `allow` rules, the user can authenticate but cannot do anything; this is intentional.

### 8.3 Path resolution

Every operation goes through the same pipeline:

1. Parse the virtual path from the SFTP message.
2. Reject if it contains a NUL byte (`0x00`), any other ASCII control character (`0x01`–`0x1F` or `0x7F`), or is not valid UTF-8. Reject if normalization (step 3) would walk above the virtual root.
3. Normalize: collapse `//`, resolve `.`, resolve `..` against the virtual path so that `..` past the virtual root is rejected as `PathTraversal`.
4. Run the policy engine on the normalized virtual path. Deny short-circuits.
5. Map the virtual path to a real path under the user's `root`.
6. **For read/write opens:** open the file or directory, then read back the canonical path of the resulting file descriptor (via `F_GETPATH` on macOS, `/proc/self/fd/N` readlink on Linux). If that path is not inside the user's `root`, close the fd and return `SSH_FX_PERMISSION_DENIED`. The verification establishes that the *opened fd* refers to a file inside the jail; subsequent renames of that file by the same user (or anyone) do not change the fd's identity, and any rename that would relocate the file outside the jail is blocked at its own `rename` verification (step 8). This closes the symlink-escape race that string-only checks cannot.
7. **For single-parent mutating ops (`mkdir`, `remove`, `rmdir`):** open the parent directory as a verified `Dir` fd, perform the operation as `*at`-relative (via `mkdirat` or `unlinkat`). The parent fd is verified the same way as in step 6.
8. **For `rename`:** the policy engine is run on both the normalized source virtual path and the normalized destination virtual path. Both must permit `rename`; either denial fails the request. Both source-parent and destination-parent directories are opened and fd-verified as in step 6. The actual move is then issued as `renameat(source_parent_fd, source_basename, dest_parent_fd, dest_basename)`. Either fd verification failing fails the request before any filesystem state is changed.
9. After the operation, emit one audit line.

A consequence: even if the operator misconfigures and a user's `root` contains a symlink to `/etc`, the fd verification will refuse operations whose resolved path leaves the jail. The protection is at the fd layer, not the config layer.

**Caveat.** The fd verification on Linux uses `readlink("/proc/self/fd/N", ...)` and on macOS uses `fcntl(fd, F_GETPATH)`. Both are kernel best-effort. A FUSE filesystem or an unusual network filesystem could in principle return a misleading canonical path. **Zift assumes the kernel truthfully reports fd paths.** Jail roots on FUSE, certain network filesystems, or anything else that synthesizes paths are not supported configurations. Use a regular local filesystem, or accept that the symlink-escape protection is only as strong as the filesystem's `F_GETPATH` honesty.

### 8.4 Authentication

- **Passwords.** Stored as Argon2id PHC strings. The accepted parameter envelope is `m` (memory) in the inclusive range 65536 to 262144 KiB (i.e. 64 to 256 MiB), `t` (passes) in 2 to 8, and `p` (parallelism) in 1 to 4. Password property values whose parameters fall outside this envelope are rejected at startup or reload, with a stderr line naming the user and the offending parameter; the previous config remains active. `zift hash-password` produces strings inside the envelope by default.
- **Unknown-user timing.** On a connection attempt for a username that does not exist in the config, Zift runs an Argon2id verification against a fixed dummy hash that uses the **upper bound** of the parameter envelope (`m`=262144 KiB, `t`=8, `p`=4). The dummy timing therefore matches or exceeds any real user's timing. An attacker measuring auth latency sees a high-cost computation regardless of whether the username exists. Operators who want every authentication attempt to be timing-indistinguishable should provision all users with identical Argon2id parameters; Zift does not require this.
- **Concurrent Argon2id work.** Argon2id verifications run on the per-connection thread. The maximum concurrent verification work is therefore bounded by `max-connections` (default 128). At the upper-bound profile (`m`=256 MiB), 128 simultaneous unauthenticated peers would request up to 32 GiB of transient memory; lower `max-connections` if your host cannot absorb this auth-storm worst case.
- **Public keys.** Stored as one or more `key <algo> <base64> [comment]` lines per user. Accepted algorithms: `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`. RSA and DSA keys are not accepted. A presented key is verified against the configured set via libssh's server-side SSH user-auth flow.
- **No keyboard-interactive, GSSAPI, host-based, or PAM auth.** Adding these would mean adding state outside the config. The discipline rule applies.
- **No account lockout.** Lockout creates state; the supervisor plus a fail2ban-style external rate limiter is the right answer if you need it (recipe in 11.5). Zift logs every failed auth so that any standard tool can act on it.

### 8.5 Audit log: best-effort, not fail-closed

The audit log is **best-effort operational telemetry with availability priority**, not a fail-closed security control. The distinction matters and Zift commits to one side of it:

- Every operation handler emits its audit line after replying to the client. Logging is not optional in the data path, but if the log writer fails (disk full, file unwritable, file destination removed underneath Zift), Zift writes a human-readable failure line to stderr and **continues serving**. Losing audit lines is preferred to losing service. This is the boring-software thesis applied to telemetry: the SFTP service stays up; the operator notices the broken log destination because stderr says so.
- An authenticated partner who can fill or block the audit destination can therefore continue transferring while the audit log goes silent. If your threat model treats the audit log as a non-repudiable security control, **do not rely on Zift's default behavior**. Run Zift under a wrapper that fails the service when audit writes fail, or place the log destination on storage the partner cannot influence (a separate filesystem, a remote sink read-only to Zift's user, or an append-only mount).
- The log schema is fixed. See 7.4 for fields and ordering.

### 8.6 Deployment posture

The expected deployment is:

- Zift runs as a **dedicated unprivileged OS user** (suggested name: `zift`). It does not need root and should not be given root.
- Each virtual user's `root` directory is owned by the Zift OS user (or a group it belongs to) with restrictive permissions. The Zift OS user has read/write access to those directories and nothing else.
- The host key file is readable only by the Zift OS user. `chmod 0400 /etc/zift/host_ed25519`.
- The config file is readable only by the operator and the Zift OS user. `chmod 0640 /etc/zift/zift.conf`. Do not check it into a public repo (it contains password hashes).
- Zift does **not** call `chroot()`, `seccomp()`, `pledge()`, `unveil()`, or platform sandbox APIs. It relies on the OS user's filesystem permissions and on Zift's own jail enforcement. If your threat model requires kernel-level sandboxing, run Zift inside a container, a `systemd` unit with appropriate `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=`, `NoNewPrivileges=true`, and `RestrictAddressFamilies=AF_INET AF_INET6` directives, or a FreeBSD jail.

### 8.7 What we do not protect against

- A malicious operator. If the person editing the config wants to give a user `/`, they can. The product cannot prevent intentional misconfiguration.
- A compromised host. If root is hostile, no application-level mitigations help.
- Side channels in the SSH transport. Zift uses libssh; if a CVE lands, the project ships a new release built against the patched library and the operator installs that release and restarts. Source builds dynamically linked against the system libssh/libcrypto can instead update the system package and rebuild. Zift does not embed its own crypto.
- Quota exhaustion. If a partner uploads a 10 TB file and fills the disk, Zift returns `SSH_FX_FAILURE` to the next write and the disk is full. Use OS-level quotas, partition layout, or `prlimit` to bound.
- A bug in Zift itself that allows a jail escape. If this happens, the blast radius is the privileges of the Zift OS user. That is why running as an unprivileged user with a tightly scoped filesystem footprint is mandatory, not optional.

---

## 9. Failure modes

This section enumerates concrete failures and what the operator observes. It is the most important section for production deployment, because boring software is software whose failure modes are short, predictable, and diagnosable with standard tools.

| Failure                                       | Operator-visible behavior                                                                                       | Diagnostic                                                            |
| --------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| Config file unreadable at startup             | `exit 1` with parse error on stderr.                                                                            | `zift validate /etc/zift/zift.conf`                                   |
| Config file unreadable on reload              | Previous config remains active; warning to stderr.                                                              | Read stderr; the running process is fine.                             |
| Config file syntactically valid but logically broken (e.g. duplicate user) | `exit 1` at startup. On reload, previous config remains.                                | `zift validate` shows the exact line.                                 |
| Host key file missing or unreadable           | `exit 1` at startup with the libssh error message.                                                              | `ls -l` the host-key path. Permissions should allow Zift's user to read. |
| Host key file is passphrase-protected         | `exit 1` at startup with libssh "could not load host key."                                                      | Re-generate with `ssh-keygen -t ed25519 -f path -N ""`.               |
| User's `root` directory missing at startup    | `exit 1` at startup naming the offending user.                                                                  | `mkdir -p` the directory or fix the path.                             |
| Reloaded config references a missing user `root`           | Reload rejected; previous config remains active; one stderr line names the user and missing path.              | Read stderr.                                                          |
| Active user's `root` directory deleted after a successful load | Operations under that user fail with `SSH_FX_NO_SUCH_FILE`; other users unaffected; per-operation audit lines record the failures. | Recreate the directory.                                               |
| Listen port already in use                    | `exit 1` at startup with libssh's bind error.                                                                   | `ss -ltn` to find the conflicting process.                            |
| Disk full during upload                       | Client receives `SSH_FX_FAILURE`. Audit log records the failure with the user and path.                         | Check disk usage; check audit log.                                    |
| Read-only filesystem under jail               | Same as disk full. Operations that need write fail with `SSH_FX_FAILURE`.                                       | Check filesystem mount options.                                       |
| Idle session                                  | Disconnected after `idle-timeout`; one audit line `idle.timeout`.                                               | Audit log.                                                            |
| Too many concurrent sessions                  | Excess connections rejected at the TCP layer. Existing sessions unaffected.                                     | Audit log shows accept-rejected lines.                                |
| Client sends malformed SFTP message           | Client receives `SSH_FX_BAD_MESSAGE`; session continues. Persistent malformed traffic causes session close.     | Audit log.                                                            |
| Client tries to escape jail via symlink       | Operation returns `SSH_FX_PERMISSION_DENIED`. Audit log records `denied`.                                       | Audit log.                                                            |
| Client tries `..` traversal                   | Operation returns `SSH_FX_PERMISSION_DENIED` after path normalization rejects the request.                      | Audit log.                                                            |
| Reload happens during an active large upload  | Active session continues with the config it authenticated against; new sessions see the new config; no transfer interruption. One `zift: config reloaded` line on stderr. | Expected behavior, not a failure.                                     |
| libssh or libcrypto CVE                       | The Zift project ships a new release built against the patched dependency. The operator installs that release and restarts. (Source builds dynamically linked against system libssh/libcrypto may instead update the system package and rebuild.) | Standard CVE workflow.                                                |
| Zift crash (SIGSEGV)                          | Supervisor restarts Zift. In-flight transfers lost (SFTP v3 has no resume). Crash captured by core dump if enabled. | Supervisor logs; operator files a bug.                                |
| Operator deletes config file                  | Reload watcher sees the file vanish; logs a warning; previous config remains active. Restart will fail.        | Recreate the file from git.                                           |
| Operator's editor writes a partial file       | mtime fires once; the partial file fails parse; one stderr line records the rejection; previous config remains. When the editor finishes the write, mtime fires again and the complete file loads, with a `zift: config reloaded` line on stderr. | Read stderr if you want to see the intermediate rejection.            |
| `SIGHUP` on a system where the operator doesn't expect a reload | A reload is performed. If the config didn't change, the running config is replaced with itself; behavior is identical. | None.                                                                 |
| Bug in Zift allows a jail escape              | An authenticated partner can read or write outside their `root`, with the privileges of the Zift OS user. They cannot become root, write `/etc/passwd`, or read other users' SSH keys, provided Zift is running as a dedicated unprivileged user as documented in 8.6. | Operational signal: audit log shows unexpected paths or operations. Mitigation: revoke the partner's credentials, file a CVE, upgrade. |
| Audit log destination unwritable              | Zift logs the failure to stderr and continues serving. Audit lines for the failed period may be lost.            | Monitor stderr. Run a separate alert on stderr error patterns.        |

The pattern across this table is uniform: failures are loud, audit-logged, and bounded in blast radius. An operator with `tail`, `grep`, and `ls` can diagnose any of these.

---

## 10. Explicit non-goals with reasoning

This list is not "things we plan to do later." It is "things we have decided not to do, ever, with the reason." It is explicit so that future contributors and reviewers do not have to re-derive the rationale.

| Non-goal                                                  | Reason                                                                                                                                                      |
| --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Web UI                                                    | A web UI requires HTTP, sessions, CSRF tokens, asset bundling, accessibility, browser compatibility, and a long-tail of UI dependencies. The config file is the UI.                                                                                                                                          |
| Database                                                  | Adds backup, migration, schema versioning, locking, and corruption modes. We have no need to query state. The config file is the data.                                                                                                       |
| Plugin system                                             | Plugins import a stability promise we cannot maintain. The discipline rule precludes the kind of internal API that plugins would need.                                                                                                       |
| Embedded scripting                                        | Scripts are write-once, debug-forever. Operations that need scripting belong in a wrapper around Zift, not inside it.                                                                                                                         |
| Clustering, replication, leader election                  | Single-host scope is a hard constraint of the boring-software thesis. HA is provided by external load balancers and standby hosts, not by Zift coordinating with itself.                                                                       |
| OAuth, SAML, OIDC, LDAP, Active Directory, PAM, Kerberos  | Each adds an external runtime dependency, violates the no-coordination constraint, and recreates the integration surface that Zift is trying to escape.                                                                                       |
| Account lockout, automatic IP banning                     | Lockout is state. State is the enemy. Operators run fail2ban or its equivalent on top of the audit log if they need this. Section 11 has a recipe.                                                                                            |
| Custom protocols (FTP, FTPS, WebDAV, AS2, HTTP)           | Each is a separate product. "Multi-protocol" is the lie that turns simple servers into MFT platforms.                                                                                                                                          |
| Built-in scheduling, retries, transfer queues             | Schedule with cron, retry from the client, queue with the filesystem. None of this is Zift's job.                                                                                                                                              |
| Built-in PGP, virus scanning, EDI parsing, format conversion | Pipelines belong upstream or downstream of Zift. Zift moves bytes.                                                                                                                                                                            |
| Quota enforcement                                         | OS-level quotas, partitions, or `prlimit` exist for this. Zift would need to track per-user usage in persistent state, which the no-state constraint forbids.                                                                                  |
| Bandwidth limiting                                        | Use `tc`, `iptables`, or similar. Per-user shaping in Zift would mean a scheduler in Zift.                                                                                                                                                     |
| Telemetry, update checks, license verification, phone-home | Violates the no-coordination constraint. Any "Zift dialed home" failure mode is an availability problem we refuse to introduce.                                                                                                                |
| Self-update                                               | Replace the binary with a new binary. Restart. Done. Zift has no embedded updater.                                                                                                                                                              |
| Multi-tenant SaaS mode                                    | Different product. There is a real product to be built there, but it is not Zift.                                                                                                                                                              |
| User self-service password reset                          | Operators reset passwords by editing the config. Self-service requires email, tokens, and a web surface, all forbidden.                                                                                                                       |
| GUI installer                                             | The install is `cp zift /usr/local/bin/`.                                                                                                                                                                                                      |
| Browser-based file management                             | Use `sftp` or any of the dozens of cross-platform SFTP clients.                                                                                                                                                                                |
| Configurable cipher / kex / MAC / hostkey-algos lists     | We use libssh's defaults. If libssh's defaults are wrong, we update libssh. Allowing operators to tune crypto suite lists is an attractive nuisance; almost every misconfiguration in this area weakens security.                              |

---

## 11. Composition patterns

The non-goal list is long, and the response to most of those non-goals is "compose Zift with a tool you already use." Here are the canonical recipes for the most common requests, so the non-goals read as design discipline and not as user hostility. These recipes depend on the audit log schema in section 7.4.

### 11.1 Post-upload triggers

A partner uploads a file and you need to react: move it, parse it, call an API, send a Slack message.

```sh
# Linux. Watch close_write AND moved_to: many SFTP clients write to a
# temporary name (e.g. file.csv.filepart) and rename on completion, so
# the final filename appears via moved_to, not close_write.
inotifywait -m -e close_write -e moved_to --format '%w%f %e' /srv/sftp/acme/inbound \
    | while read path event; do
        case "$path" in
          *.filepart|*.tmp|.*) continue ;;     # skip temp files
        esac
        /usr/local/bin/process-acme-upload "$path"
      done

# macOS. fswatch fires on the renamed file as well, but emits no event
# type, so the same temp-file filtering applies.
fswatch /srv/sftp/acme/inbound | while read path; do
    case "$path" in *.filepart|*.tmp|.*) continue ;; esac
    /usr/local/bin/process-acme-upload "$path"
done
```

Run this script under the same supervisor that runs Zift. Zift writes the file; `inotifywait` or `fswatch` reacts. The temp-file pattern is real: WinSCP, FileZilla, and OpenSSH `sftp` all do partial-then-rename uploads by default. Filter accordingly.

### 11.2 Audit log shipping and alerting

```sh
# Send denied operations to a webhook
tail -F /var/log/zift/audit.jsonl \
    | jq -c 'select(.result=="denied")' \
    | while read line; do curl -sX POST -d "$line" https://alerts.example.com/zift; done

# Stream to Loki / Vector / Fluent Bit
tail -F /var/log/zift/audit.jsonl | vector --config /etc/vector/zift.toml
```

The audit log is one JSON object per line, atomic at the OS write level. Any line-based aggregator works.

### 11.3 Adding and removing partners

Adding:

```sh
# Run this interactively. The plaintext password is written to stdout
# exactly once so the operator can deliver it to the partner; do not run
# this under a shell that captures stdout to disk (no `script(1)`, no
# supervisor unit that journals stdout, no `tee`).

# 1. Create the user's filesystem root FIRST. If you append the config
#    block before the directory exists, Zift's auto-reload will see a
#    user with a missing root and reject the whole reload.
mkdir -p /srv/sftp/newpartner/uploads
chown -R zift:zift /srv/sftp/newpartner

# 2. Generate plaintext, show it once, hash it, drop it.
PASS=$(openssl rand -base64 32)
printf 'partner credential, deliver through your existing secure channel: %s\n' "$PASS"
HASH=$(printf '%s' "$PASS" | zift hash-password)
unset PASS

# 3. Append the user block. Zift picks it up on the next mtime tick.
cat >> /etc/zift/zift.conf <<EOF

user newpartner
  password $HASH
  root /srv/sftp/newpartner
  allow / read list
  allow /uploads write mkdir
EOF
```

Removing: delete or comment out the partner's `user` block. Save.

### 11.4 Health checking

Zift has no `/health` endpoint and never will. Pick the right depth of probe for your monitor:

```sh
# Liveness only (cheapest, no Zift-side cost beyond a TCP accept):
nc -z 127.0.0.1 2222 && echo OK || echo FAIL

# SSH banner (proves the SSH transport is up but does not authenticate):
ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
    -o PreferredAuthentications=none -p 2222 nobody@127.0.0.1 2>&1 \
  | grep -q "Permission denied" && echo OK || echo FAIL

# Full deep probe (proves auth + SFTP subsystem actually work):
sftp -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
     -P 2222 healthchecker@127.0.0.1 <<<"quit" \
     && echo OK || echo FAIL
```

The deep probe requires a real `healthchecker` user in the config with an empty allow list, plus its credential available to the monitor — that's a real operational cost. For most deployments, the TCP-port liveness check plus supervisor "is the process running" is enough; reach for the deep probe only when you're chasing intermittent issues that the lighter probes cannot see.

### 11.5 Rate limiting and IP allowlists

Use the OS firewall, not Zift:

```sh
# nftables: only let known partner IPs reach Zift
nft add rule inet filter input tcp dport 2222 ip saddr { 198.51.100.0/24, 203.0.113.5 } accept
nft add rule inet filter input tcp dport 2222 drop

# fail2ban: ban IPs after N denied auths.
# Zift's audit JSON emits fields in a stable order
# (event, user, operation, result, path, detail, ip),
# so the regex below is anchored on operation, result, and ip.
# /etc/fail2ban/filter.d/zift.conf
failregex = "operation":"auth\.password","result":"denied".*"ip":"<HOST>"
```

### 11.6 Backup

```sh
# Everything Zift needs to come back, on a new host
tar czf zift-backup.tgz /etc/zift/zift.conf /etc/zift/host_ed25519 /srv/sftp
```

That's it. There is no database to dump.

---

## 12. Testing and quality bar

The quality bar is set by what an operator can and should be able to assume.

- **Unit tests** cover every observable behavior of the config parser, the policy engine, the path normalizer, the jail verifier, the audit serializer, and the auth verifier. Tests are part of `zig build test` and run on every commit.
- **Integration tests** drive a running Zift with the stock OpenSSH `sftp` client and verify operations end-to-end: login, ls, get, put, mkdir, rm, rmdir, rename, denial paths, traversal blocking, symlink-escape blocking, reload-during-session, parallel client load, idle-timeout disconnect, malformed message handling.
- **Fuzz tests** run on the SFTP message parser and the config parser. Crashes are blockers; surprises are bugs.
- **Reproducible builds** are a release requirement. The same source on the same Zig toolchain produces a byte-identical binary. Distribution publishes SHA256 sums and the source archive used to produce them.
- **Static linkage of Linux releases is verified in CI.** `ldd zift` on a Linux release binary reports "not a dynamic executable."
- **No flaky tests are tolerated.** A test that fails intermittently is treated as a bug in the test or in Zift, not as noise to retry past.
- **Static analysis** in CI: Zig's compile-time checks, lint rules where applicable, and `zig build -Doptimize=ReleaseSafe` runs in addition to debug.
- **Memory discipline.** Zift uses Zig's allocator interface explicitly throughout. Tests run with `DebugAllocator` to catch leaks. Production binaries use the platform's general-purpose allocator. There are no global allocations, no `var foo: [N]u8 = undefined` in shared state.

---

## 13. Distribution

- **Single binary per platform.** Zift releases a stripped, optimized binary for each supported target: `macos-arm64`, `macos-x86_64`, `linux-arm64`, `linux-x86_64`. Other targets are best-effort source builds.
- **Linkage.**
  - **Linux:** Released binaries are **fully statically linked** against musl libc, libssh, and libcrypto (or libmbedtls, whichever libssh is configured against). There are no runtime shared-library dependencies; you can `scp` the binary to any modern Linux host and run it. Static linkage is verified in CI (section 12). This is what makes the opening promise of the document literally true on Linux.
  - **macOS:** Released binaries link the system libc (Apple does not ship a static libc) and a vendored libssh. There is no Homebrew dependency for end users; the only runtime requirement is the system shared libraries that ship with macOS.
  Zift does not maintain a fork of libssh. The libssh build is pinned and documented in the release notes.
- **Install.** `cp zift /usr/local/bin/zift && chmod +x /usr/local/bin/zift`. There is no installer, no postinstall script, and no package-manager hook.
- **Supervisor units.** Example `zift.service` for systemd and `com.zift.daemon.plist` for launchd live in the repo. They are not bundled with the binary; copy the one you need.
- **Hash and signature.** Each release publishes SHA256 sums and a detached signature from the project's release key. Verification is part of the install instructions, not optional.
- **Source.** The repository ships under a permissive open-source license. The build system is `zig build`; no other build tool is required to compile from source. A `make release` target produces all distribution targets in a reproducible build environment.

---

## Closing constraint

Every section of this document exists in service of one operational property: an operator installs Zift, configures it once, and ignores it. The process keeps doing exactly what they configured it to do. Any change to Zift that would compromise this property is not made, regardless of how reasonable it seems in isolation.

> If you cannot describe a proposed Zift change without using the word "and," it is at least two changes, and probably one of them does not belong.
