# Develop Zift

This guide is for contributors and maintainers.

Zift is a Zig project. It builds one SFTP server binary and a small set
of companion test/fuzz targets. The runtime depends on libssh for SSH,
mbedTLS for crypto, and zlib for SSH compression. Release builds vendor
those dependencies through `build.zig.zon`.

## Toolchain

Required:

- Zig `0.16.0`
- a POSIX-like host for development
- Python 3 for integration probes
- OpenSSH client tools for integration tests
- `expect` for password-driven SFTP tests

On Linux integration-test hosts:

```sh
sudo apt-get update
sudo apt-get install -y expect openssh-client python3-venv lsof
```

## Source Layout

```text
src/
├── main.zig              # CLI: serve, validate, hash-password, version
├── server.zig            # accept loop, reload, session threads, bind
├── ssh.zig               # SSH userauth (password / public key)
├── sftp.zig              # SFTP v3 state and request handlers
├── wire.zig              # SFTP packet codec
├── config.zig            # config parser, semantic validation, key-file loading
├── policy.zig            # allow/deny engine and glob matching
├── vfs.zig               # virtual path normalization and jail verification
├── auth.zig              # password verify (wraps passhash)
├── passhash.zig          # versioned password credential codec (a…)
├── abuse.zig             # auth backoff + temporary source suppression
├── netmatch.zig          # IP/CIDR matching for per-user `from`
├── audit.zig             # JSON audit sink (+ shared monotonic clock)
├── listing.zig           # virtual/reality directory listing renderer
├── signals.zig           # signal flags, session fd registry, forced close
├── tests.zig             # unit-test root
├── fuzz.zig              # fuzz harnesses
└── ext/
    └── libssh_root.h     # translate-c tip for @import("libssh")
```

Other important paths:

```text
build.zig                           # build graph, vendored C dependency build
build.zig.zon                       # pinned dependency graph
tools/verify.zig                    # release-artifact dep-surface verifier
packaging/systemd/zift.service      # optional systemd unit
tests/run.sh                        # integration-test runner
tests/cases/*.sh                    # integration cases
tests/lib/*.py                      # Paramiko/raw protocol probes
.github/workflows/ci.yml            # CI
.github/workflows/release.yml
```

## Build

Debug-style local build:

```sh
zig build
bin/zift version
```

ReleaseSafe local build:

```sh
zig build -Doptimize=ReleaseSafe
bin/zift version
```

The normal development binary lands at `bin/zift`.

## Unit Tests

```sh
zig build test
```

Unit tests cover parser behavior, policy matching, auth validation,
path normalization, listing formatting, audit serialization, and other
pure or mostly-pure logic.

## Integration Tests

Run all integration tests:

```sh
tests/run.sh
```

List cases:

```sh
tests/run.sh --list
```

Run selected cases:

```sh
tests/run.sh 00-smoke 34-clobber 35-atomic-upload
```

Keep a passing case's scratch directory:

```sh
tests/run.sh --keep 00-smoke
```

Each case gets:

- an isolated temp directory
- a unique TCP port
- a fresh config
- access to `ZIFT_BIN`

Cases cover smoke behavior, idle timeouts, connection caps, reloads,
graceful shutdown, handle access modes, symlink escapes, semantic
validation, audit file targets, signal-driven log reopen, unsupported
SFTP operations, path limits, auth hardening, config grammar, append
semantics, unauthenticated DoS pressure, reload stress, log sink
failure, readdir edge cases, virtual listings, clobber protection,
atomic uploads, staging hardening, publish/mkdir modes, and v0.7 auth
migrations.

## Fuzzing

Fuzz harnesses live in `src/fuzz.zig` and are imported into the
test build.

They cover:

- config parser
- virtual path normalization
- policy glob matching
- passhash credential validation via parser paths
- public-key line validation

The harnesses compile and run once during ordinary `zig build test`.

The CI random fuzz job is currently disabled because the pinned Zig
`0.16.0` test runner has an upstream fuzz-runner type mismatch. When
the toolchain is updated or patched, re-enable the `fuzz-short` job in
`.github/workflows/ci.yml`.

## Local Release Builds

Build one release artifact:

```sh
zig build release -Dtarget=x86_64-linux-musl -Dversion=0.8.0-dev
```

Supported release targets:

```sh
zig build release -Dtarget=x86_64-linux-musl  -Dversion=0.8.0-dev
zig build release -Dtarget=aarch64-linux-musl -Dversion=0.8.0-dev
zig build release -Dtarget=x86_64-macos       -Dversion=0.8.0-dev
zig build release -Dtarget=aarch64-macos      -Dversion=0.8.0-dev
```

Output lands under `release/`.

Linux release targets must use `*-linux-musl`, not plain `*-linux`, so
the binary is fully static and does not depend on the build host's
glibc.

## Vendored C Dependencies

`build.zig.zon` pins:

- libssh `0.11.3`
- mbedTLS `3.6.4`
- zlib `1.3.2`

`build.zig` compiles libssh as a static library configured for the
server-side SFTP surface Zift needs. It disables unused libssh features
and wires libssh to the vendored mbedTLS and zlib builds.

This is intentionally in the Zig build graph rather than a shell script
that downloads tarballs at build time. A release tag pins the exact
source revisions used for the shipped binary.

## CI

`.github/workflows/ci.yml` runs on pushes and pull requests to `main`.

Jobs:

- `unit-tests`: install Zig and run `zig build test`.
- `build-release-safe`: build the static `x86_64-linux-musl`
  ReleaseSafe binary, assert zero ELF `DT_NEEDED` entries, verify the
  systemd unit, and run smoke commands.
- `integration-tests`: run `tests/run.sh` against the binary built by
  the ReleaseSafe job.
- `fuzz-short`: present but disabled pending the Zig fuzz-runner issue.

The important CI design choice is that integration tests run against
the same static-musl shape users run in production, not a dynamic glibc
binary that only exists in CI.

## Release Workflow

`.github/workflows/release.yml` triggers on tags matching:

```text
vX.Y.Z
vX.Y.Z-rc.1
```

Prerelease suffixes may contain ASCII letters, digits, and dots.

The workflow:

1. Validates the tag shape.
2. Extracts `X.Y.Z` and passes it as `-Dversion`.
3. Builds four targets:
   - `x86_64-linux-musl`
   - `aarch64-linux-musl`
   - `x86_64-macos`
   - `aarch64-macos`
4. Bundles the optional `packaging/systemd/zift.service` unit.
5. Aggregates checksums into `SHA256SUMS`.
6. Signs `SHA256SUMS` with cosign keyless using GitHub Actions OIDC.
7. Publishes a GitHub Release.

Release artifacts are named for end users:

```text
zift-X.Y.Z-x86_64-linux
zift-X.Y.Z-aarch64-linux
zift-X.Y.Z-x86_64-macos
zift-X.Y.Z-aarch64-macos
zift-deploy-X.Y.Z.tar.gz
SHA256SUMS
SHA256SUMS.bundle
```

## Versioning

`build.zig` contains `default_version` for local builds.

Release CI overrides it with:

```sh
-Dversion="${GITHUB_REF_NAME#v}"
```

Before tagging a release:

1. Update `default_version` if the source-tree fallback should move.
2. Ensure docs mention the same current version.
3. Run unit and integration tests.
4. Push an annotated tag.

Example:

```sh
git tag -a v0.8.0 -m "Zift 0.8.0"
git push origin v0.8.0
```

## Coding Principles

Zift is intentionally conservative.

Prefer:

- explicit invariants over permissive fallback behavior
- small config surface over convenience knobs
- built-in abuse floor over external ban daemons
- supervisor + stderr logs over a Zift logging platform
- structured errors that tell operators what to fix
- tests that discriminate the bug, not just cover the happy path
- release artifacts that match what CI tested

Avoid:

- new runtime state locations (databases, Redis, ban DBs on disk)
- background coordination
- embedded scripting
- HTTP control planes
- plugin interfaces
- CrowdSec/fail2ban/threat-feed integrations as product surface
- unbounded parsing
- accepting malformed config with warnings
- hidden compatibility shims for unreleased branch behavior

## Adding Features

Most feature requests should be solved outside Zift — unless they are
the boring necessities that make “launch and relax” true (source
policy, connection caps, auth backoff, temporary suppress).

Before adding anything to the daemon, ask:

1. Does this make “I need an SFTP server” easier without becoming an
   MFT platform?
2. Can this be done with a wrapper, cron, log shipper, filesystem ACL,
   inotify/fswatch, or downstream processor instead?
3. Does this require new persistent state?
4. Does this add a new config concept?
5. Does this broaden the remote attack surface?
6. Does this make failure modes harder to explain with `ls`, `ss`,
   `tail`, and `jq`?

If the answer points outside Zift, keep it outside Zift.

## Maintenance Backlog

No known P0 or P1 items are open. Current follow-ups are hardening,
tests, or polish:

- Add a reload lifetime stress test with many active sessions while the
  config is reloaded repeatedly.
- Consider moving session counters out of `signals.zig` into server
  state.
- Revisit explicit libssh channel EOF/close/free cleanup order on
  session exit.
- Close publish-time no-clobber races with
  `renameat2(RENAME_NOREPLACE)` on Linux and `renamex_np(RENAME_EXCL)`
  on macOS.
- Harden `.zift/staging/` open with an open-no-follow plus fstat pattern
  where the platform APIs make that practical.
- Add a Linux-only regression test for raw-syscall errno handling around
  missing files.
- Consider sweeping orphaned files under `<root>/.zift/staging/` (and
  the legacy `<root>/.zift-staging/`) at startup.
- Consider per-session parsed public-key handle caching, but only if the
  configured-key and dummy-key auth paths keep matching timing behavior.

## Documentation Maintenance

Current docs are:

- `README.md`
- `docs/evaluate.md`
- `docs/operate.md`
- `docs/configure.md`
- `docs/security.md`
- `docs/develop.md`

When changing config grammar, release behavior, deployment posture,
security invariants, or SFTP protocol behavior, update docs in the same
change as the code.

## Useful Commands

```sh
# build
zig build

# version
bin/zift version

# unit tests
zig build test

# integration tests
tests/run.sh

# list integration tests
tests/run.sh --list

# local release artifact
zig build release -Dtarget=x86_64-linux-musl -Dversion=0.8.0-dev

# inspect release output
ls -la release/
```

