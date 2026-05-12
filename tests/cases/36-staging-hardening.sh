#!/usr/bin/env bash
# Test: v0.8.0 namespace + staging-dir hardening + reserved-path coverage.
#
# v0.5.0 introduced atomic-upload staging at `<root>/.zift-staging/`.
# v0.5.1 hardened that path against symlink-substitution and loose
# perms (GPT-5.5's hostile review).
# v0.8.0 reshaped the layout into a two-tier namespace:
#
#     <root>/.zift/             reserved per-partner namespace
#     <root>/.zift/staging/     daemon-owned upload staging (the actual
#                                staging area; same hardening rules as
#                                v0.5.1, just moved one level deeper)
#
# This test re-establishes the v0.5.1 hardening invariants on the new
# path AND extends them to the namespace level. Specifically:
#
#  1. Pre-existing `<root>/.zift/` as a symlink → NamespaceDirCorrupt
#     (a malicious symlink with that name could redirect the daemon's
#     staging directory creation outside the jail).
#  2. Pre-existing `<root>/.zift/staging/` as a symlink → StagingDirCorrupt
#     (same threat, one level deeper).
#  3. Pre-existing `<root>/.zift/staging/` with group/other access bits
#     → StagingDirUnsafe (loose perms let local users observe in-flight
#     upload names and tamper with staging files mid-rename).
#  4. Reserved-path coverage: every SFTP op on `/.zift/*` AND legacy
#     `/.zift-staging/*` must be rejected — partners must never reach
#     anything inside the namespace via the SFTP wire surface.
#
# Covers:  src/vfs.zig openOrCreateNamespaceDir + openOrCreateStagingSubdir
#          hardening; src/vfs.zig normalizeVirtualPath reservation against
#          ALL ops, not just listing.

source "$(dirname "$0")/../lib/common.sh"

VENV="$(dirname "$0")/../.venv"
PY="$VENV/bin/python3"

if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing at $VENV"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)

mkdir -p "$TEST_TMP/data/pending"
mkdir -p "$TEST_TMP/elsewhere"

# Shared config for every cycle below. Partner has `full` on `/` so
# any per-op failure is unambiguously due to reserved-name validation
# (not a policy denial that would mask a validator bug).
write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user partner
  auth $hash
  root $TEST_TMP/data
  allow / full
EOF

# --- 1. Pre-existing namespace dir as a SYMLINK is rejected -----------
# Simulates a v0.4.0-then-upgrade scenario where the partner's `add`
# permission planted a symlink with this name before v0.8.0 reserved
# `.zift` as a path component. v0.8.0's openOrCreateNamespaceDir
# lstat-verifies the entry.
ln -s "$TEST_TMP/elsewhere" "$TEST_TMP/data/.zift"

start_zift
"$PY" - <<EOF
import paramiko, socket, sys
sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="partner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)
try:
    f = sftp.file("/pending/should-fail-ns.bin", "wb")
    f.write(b"this should never be staged")
    f.close()
    print("FAIL: upload succeeded despite malicious .zift namespace symlink")
    sys.exit(1)
except IOError as exc:
    print(f"ok: upload refused with .zift as symlink: {exc}")
import os
leaked = os.listdir("$TEST_TMP/elsewhere")
assert leaked == [], f"FAIL: bytes leaked outside jail to elsewhere/: {leaked}"
print("ok: no bytes written outside jail via namespace symlink")
sftp.close()
t.close()
EOF
stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
rm -f "$TEST_TMP/data/.zift"

# --- 2. Pre-existing staging subdir as a SYMLINK is rejected ---------
# Plant `.zift/` as a real directory but `.zift/staging` as a symlink
# pointing outside the jail. openOrCreateStagingSubdir's lstat check
# should refuse and abort the upload.
mkdir -m 0750 "$TEST_TMP/data/.zift"
ln -s "$TEST_TMP/elsewhere" "$TEST_TMP/data/.zift/staging"

start_zift
"$PY" - <<EOF
import paramiko, socket, sys
sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="partner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)
try:
    f = sftp.file("/pending/should-fail-staging.bin", "wb")
    f.write(b"this should never be staged either")
    f.close()
    print("FAIL: upload succeeded despite malicious .zift/staging symlink")
    sys.exit(1)
except IOError as exc:
    print(f"ok: upload refused with .zift/staging as symlink: {exc}")
import os
leaked = os.listdir("$TEST_TMP/elsewhere")
assert leaked == [], f"FAIL: bytes leaked outside jail to elsewhere/: {leaked}"
print("ok: no bytes written outside jail via staging symlink")
sftp.close()
t.close()
EOF
stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
rm -rf "$TEST_TMP/data/.zift"

# --- 3. UNSAFE-PERMS staging subdir is rejected ----------------------
# Plant a real `.zift/staging` directory at 0o755 (world-listable).
# openOrCreateStagingSubdir refuses any pre-existing dir whose mode
# grants group or other access bits — partial uploads would otherwise
# be observable, and (if group/other-writable) substitutable mid-rename.
mkdir -m 0750 "$TEST_TMP/data/.zift"
mkdir -m 0755 "$TEST_TMP/data/.zift/staging"

start_zift
"$PY" - <<EOF
import paramiko, socket, sys
sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="partner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)
try:
    f = sftp.file("/pending/should-fail-perms.bin", "wb")
    f.write(b"x")
    f.close()
    print("FAIL: upload succeeded with 0o755 staging dir")
    sys.exit(1)
except IOError as exc:
    print(f"ok: upload refused with 0o755 staging dir: {exc}")
sftp.close()
t.close()
EOF
stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
rm -rf "$TEST_TMP/data/.zift"

# --- 4. Reserved-path coverage: every op on /.zift/* and /.zift-staging/* ---
# Let zift create the namespace + staging dirs cleanly via a first
# upload, then plant a real file inside `.zift/staging/` from the
# harness side (so REMOVE/RENAME-from can't pass via NotFound).
start_zift
"$PY" - <<EOF
import paramiko, socket
sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="partner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)
f = sftp.file("/pending/seed.bin", "wb")
f.write(b"seed")
f.close()
sftp.close()
t.close()
EOF

# Plant known files inside `.zift/` (operator-managed notes drawer)
# and `.zift/staging/` (daemon-managed staging area) so REMOVE-of-real-
# file would succeed if reserved-path validation were bypassed.
echo "operator-only"   > "$TEST_TMP/data/.zift/notes.md"
echo "harness-planted" > "$TEST_TMP/data/.zift/staging/known-victim.txt"

"$PY" - <<EOF
import paramiko, socket, sys

sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="partner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)

# Partner has 'full' permission on / (so policy can't accidentally
# explain failures), and the harness planted real files inside both
# `.zift/` and `.zift/staging/` so REMOVE and RENAME-from can't
# pass via NotFound.
denials = []
def expect_deny(label, fn):
    try:
        fn()
        denials.append(("FAIL", label, "succeeded"))
    except IOError as exc:
        denials.append(("ok", label, str(exc)))

# Namespace dir itself (v0.8.0 reservation):
expect_deny("OPENDIR /.zift",                       lambda: sftp.listdir("/.zift"))
expect_deny("STAT /.zift",                          lambda: sftp.stat("/.zift"))
expect_deny("MKDIR /.zift",                         lambda: sftp.mkdir("/.zift"))
expect_deny("RMDIR /.zift",                         lambda: sftp.rmdir("/.zift"))
expect_deny("OPENDIR /.zift/staging",               lambda: sftp.listdir("/.zift/staging"))
expect_deny("OPEN /.zift/notes.md (real op-file)",  lambda: sftp.file("/.zift/notes.md", "rb").close())
expect_deny("REMOVE /.zift/notes.md (real op-file)", lambda: sftp.remove("/.zift/notes.md"))
expect_deny("RENAME from /.zift/notes.md",          lambda: sftp.rename("/.zift/notes.md", "/pending/stolen.md"))
expect_deny("OPEN-write /.zift/x",                  lambda: sftp.file("/.zift/x", "wb").close())
expect_deny("MKDIR /.zift/sub",                     lambda: sftp.mkdir("/.zift/sub"))
expect_deny("RENAME to /.zift/x",                   lambda: sftp.rename("/pending/seed.bin", "/.zift/x"))

# Reach into the staging subdir (the real file we planted there):
expect_deny("REMOVE /.zift/staging/known-victim.txt",
    lambda: sftp.remove("/.zift/staging/known-victim.txt"))
expect_deny("RENAME from /.zift/staging/known-victim.txt",
    lambda: sftp.rename("/.zift/staging/known-victim.txt", "/pending/stolen.txt"))

# Legacy `.zift-staging` name (v0.5.0–v0.7.x) — still reserved at
# the validator level on v0.8.0 even though the daemon no longer
# uses it, so a partner can't `mkdir` it under a freshly-upgraded
# root and confuse operators who haven't yet swept the old path.
expect_deny("OPENDIR /.zift-staging",        lambda: sftp.listdir("/.zift-staging"))
expect_deny("STAT /.zift-staging",           lambda: sftp.stat("/.zift-staging"))
expect_deny("MKDIR /.zift-staging",          lambda: sftp.mkdir("/.zift-staging"))
expect_deny("OPEN-write /.zift-staging/x",   lambda: sftp.file("/.zift-staging/x", "wb").close())
expect_deny("RENAME to /.zift-staging/x",    lambda: sftp.rename("/pending/seed.bin", "/.zift-staging/x"))

# Dot-segment escape: path normalizer should catch the `..` traversal
# OR reserved-name validator should catch the final component.
expect_deny("OPENDIR /pending/../.zift",
    lambda: sftp.listdir("/pending/../.zift"))
expect_deny("OPENDIR /pending/../.zift-staging",
    lambda: sftp.listdir("/pending/../.zift-staging"))

failed = [d for d in denials if d[0] == "FAIL"]
for d in denials:
    print(f"  {d[0]:<4} {d[1]}: {d[2]}")
if failed:
    print(f"FAIL: {len(failed)} reserved-path operations were not denied")
    sys.exit(1)
print(f"ok: all {len(denials)} reserved-path operations denied")

# Verify the harness-planted files STILL EXIST — the rename and
# remove attempts above must not have actually moved/deleted them.
import os
assert os.path.exists("$TEST_TMP/data/.zift/notes.md"), \
    "FAIL: operator notes file was removed/moved despite denial"
assert os.path.exists("$TEST_TMP/data/.zift/staging/known-victim.txt"), \
    "FAIL: harness-planted staging file was removed/moved despite denial"
print("ok: planted .zift/notes.md and .zift/staging/known-victim.txt survived all attempts")

sftp.close()
t.close()
EOF

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
