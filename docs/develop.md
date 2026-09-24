# Develop Zift

This guide is for contributors and maintainers. Zift is one Zig binary
built with libssh (SSH), mbedTLS (crypto) and zlib (compression), all
compiled from source pinned in `build.zig.zon`. No system packages are
needed.

## Toolchain

- Zig `0.16.0`
- a Linux or macOS host
- for integration tests: Python 3 with Paramiko, the OpenSSH client,
  `expect` and `lsof`

```sh
sudo apt-get install -y expect openssh-client python3-venv lsof   # Linux; macOS has these
python3 -m venv tests/.venv
tests/.venv/bin/pip install paramiko
```

## Source Layout

```text
src/
├── main.zig        CLI: serve, validate, hash-password, version
├── server.zig      accept loop, admission, reload, drain, session threads
├── ssh.zig         SSH authentication: password, public key, KDF slots, login grace
├── abuse.zig       per-source failure counts, suppression, pre-auth cap
├── netmatch.zig    IP/CIDR matching for `from`
├── passhash.zig    the `a…` password hash format
├── config.zig      config parser and filesystem validation
├── policy.zig      allow/deny evaluation and glob matching
├── sftp.zig        SFTP v3 request handlers, staging and publish
├── vfs.zig         path normalization and the NOFOLLOW jail walk
├── wire.zig        SFTP packet encoding and parsing
├── listing.zig     directory listing rendering and stat helpers
├── audit.zig       JSON audit sink
├── signals.zig     signal flags and the session socket registry
├── sys.zig         clocks, civil time, one-write stderr helper
├── tests.zig       unit-test root
├── fuzz.zig        fuzz harnesses
└── ext/            libssh translate-c header
tools/verify.zig    checks a release binary's dynamic dependencies
packaging/systemd/zift.service
tests/run.sh, tests/cases/*.sh, tests/lib/
```

## Build

```sh
zig build                              # Debug, PIE, to bin/zift
zig build -Doptimize=ReleaseSafe
bin/zift version
```

A release binary is ReleaseSafe, stripped, and checked by
`tools/verify.zig` (no dynamic dependencies on Linux, only libSystem on
macOS). It lands in `release/zift-<version>-<arch>-<os>`:

```sh
zig build release -Dtarget=x86_64-linux-musl
zig build release -Dtarget=aarch64-linux-musl
zig build release -Dtarget=x86_64-macos
zig build release -Dtarget=aarch64-macos
```

Linux targets must be `-linux-musl`; a glibc target fails at once and
names the musl target to use. The step works from any directory and
with `--prefix`, and prints the artifact's sha256.

## Versioning

The version lives only in `build.zig.zon` (`.version`). Every build
uses it unless `-Dversion=…` overrides it, which the release workflow
does with the tag minus its leading `v`. To release:

1. Set `.version` in `build.zig.zon`.
2. Rename `## Unreleased` in `CHANGELOG.md` to `## X.Y.Z — <date>`.
3. Run the unit and integration tests.
4. Tag and push: `git tag -a vX.Y.Z -m "Zift X.Y.Z" && git push origin
   vX.Y.Z`.

## Unit Tests And Fuzzing

```sh
zig build test
zig build test -Dtarget=x86_64-linux-musl          # the libc that ships
zig build test -Doptimize=ReleaseSafe --fuzz=200K
```

`src/fuzz.zig` fuzzes the config parser, glob matching (against a
reference matcher), passhash validation, public-key lines, the SFTP
string parser and path normalization. A plain `zig build test` runs each
harness once. Fuzz in ReleaseSafe: Zig 0.16.0's Debug `--fuzz` fails to
build.

## Integration Tests

```sh
tests/run.sh                     # every case
tests/run.sh --list              # case names and descriptions
tests/run.sh 00-smoke 34-clobber # selected cases
tests/run.sh --keep 00-smoke     # keep a passing case's scratch dir
```

Each case is a bash script in `tests/cases/` that sources
`tests/lib/common.sh` and gets its own `TEST_TMP` directory, a
`TEST_PORT`, its `TEST_NAME`, and `ZIFT_BIN`. It exits 0 to pass, and
calls `skip <reason>`, which exits 77, when a prerequisite is missing.
The first `# Test:` line is its description in `--list`.

The runner reads:

| Variable | Effect |
| --- | --- |
| `ZIFT_BIN` | test this binary instead of building one |
| `ZIFT_TEST_PORT_BASE` | ports start here, one per case (default 22200) |
| `ZIFT_REQUIRE_ALL=1` | a skipped case fails the run, except slow cases |
| `ZIFT_TEST_SLOW=1` | also run slow cases, such as the 120 s login grace |
| `ZIFT_TEST_TIMEOUT` | per-case timeout |

## CI

`.github/workflows/ci.yml` runs on pushes and pull requests to `main`:

- **Unit tests** on Linux and macOS; on Linux also `zig fmt --check` and
  the unit tests built for `x86_64-linux-musl`.
- **Release build** of `x86_64-linux-musl` and `aarch64-macos` with
  `zig build release`, exactly as a release does. On Linux it also runs
  `systemd-analyze verify` on the unit and fails on any output. Then
  `version` and `validate` smoke tests.
- **Integration tests** on Linux and macOS against that release
  artifact, with `ZIFT_REQUIRE_ALL=1`, and a check that the binary under
  test was not replaced.
- **Fuzz** with `--fuzz=200K` in ReleaseSafe; anything but a clean exit
  fails.

## Release Workflow

`.github/workflows/release.yml` runs on a pushed tag matching
`vX.Y.Z` or `vX.Y.Z-<prerelease>` (letters, digits and dots). It:

1. rejects any other tag shape;
2. strips the leading `v` and passes the rest as `-Dversion`;
3. runs the unit tests, then builds the four release targets;
4. packs the systemd unit into `zift-deploy-X.Y.Z.tar.gz`;
5. writes `SHA256SUMS` over exactly the files it publishes and signs it
   with cosign keyless through GitHub's OIDC identity;
6. publishes a GitHub release, marked prerelease if the tag has a `-`.

Artifacts: `zift-X.Y.Z-{x86_64,aarch64}-{linux,macos}`,
`zift-deploy-X.Y.Z.tar.gz`, `SHA256SUMS`, `SHA256SUMS.bundle`.

## Principles

Zift is deliberately conservative. Prefer explicit invariants over
permissive fallbacks, a small config surface over knobs, a built-in
abuse floor over external ban daemons, supervisor-owned logs over a
logging platform, errors that tell the operator what to fix, tests that
fail without the fix, and release artifacts that are exactly what CI
tested.

Avoid new runtime state (databases, ban lists on disk), background
coordination, embedded scripting, HTTP control planes, plugins,
unbounded parsing, and accepting a malformed config with a warning.

Most feature requests belong outside Zift. Before adding one, ask:
does it keep Zift an SFTP server rather than an MFT platform? Could a
wrapper, cron job, log shipper, filesystem ACL or downstream processor
do it instead? Does it add persistent state, a config concept, or
remote attack surface? Does it make failures harder to explain with
`ls`, `ss`, `tail` and `jq`? If the answers point outside, keep it
outside.

Update the docs and `CHANGELOG.md` in the same change as the code.
