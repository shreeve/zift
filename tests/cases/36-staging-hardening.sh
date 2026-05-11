#!/usr/bin/env bash
# Test: v0.5.1 staging-dir hardening + reserved-path coverage gaps.
#
# v0.5.0 added `.zift-staging` as a reserved name but had two
# weaknesses GPT-5.5's hostile review caught:
#
#  1. Pre-existing `.zift-staging` (planted by a v0.4.0 partner with
#     `add` permission, before the name was reserved) could be a
#     SYMLINK pointing OUTSIDE the partner root. Without verification,
#     the upgraded server would happily follow it and write upload
#     bytes to attacker-chosen locations. v0.5.1 lstat-verifies the
#     pre-existing entry and refuses unless it's a real directory.
#
#  2. v0.5.0 only verified `OPENDIR/STAT/OPEN-read` were rejected on
#     `/.zift-staging`. Other operations (MKDIR, RENAME, REMOVE,
#     OPEN-write) need the same coverage so a misbehaving partner
#     can't bypass via a less-traveled syscall path.
#
# Covers:  src/vfs.zig openStagingDir lstat-verify; the
#          normalizeVirtualPath reservation against ALL ops, not just
#          listing.

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

# --- SETUP: plant a malicious pre-existing .zift-staging symlink ---
# Simulates the v0.4.0-then-upgrade scenario: the partner's `add`
# permission was used to create a symlink with this name before the
# upgrade reserved it. Symlink points outside the jail.
ln -s "$TEST_TMP/elsewhere" "$TEST_TMP/data/.zift-staging"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user partner
  auth $hash
  root $TEST_TMP/data
  # Grant 'full' (read + add + remove) on the entire jail. We
  # specifically want the partner to have permission for every
  # operation we'll attempt under /.zift-staging — so that any
  # failure is unambiguously due to the reserved-name validator,
  # not a policy denial that would mask a validator bug.
  allow / full
EOF

start_zift

"$PY" - <<EOF
import paramiko, socket, sys

# --- 1. Upload attempt MUST fail when .zift-staging is a symlink ---
# v0.5.1 openStagingDir lstat-verifies and refuses non-directories.
sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="partner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)

try:
    f = sftp.file("/pending/should-fail.bin", "wb")
    f.write(b"this should never be staged")
    f.close()
    print("FAIL: upload succeeded despite malicious .zift-staging symlink")
    sys.exit(1)
except IOError as exc:
    print(f"ok: upload refused with .zift-staging as symlink: {exc}")

# Confirm: nothing was written outside the jail.
import os
leaked = os.listdir("$TEST_TMP/elsewhere")
assert leaked == [], f"FAIL: bytes leaked outside jail to elsewhere/: {leaked}"
print("ok: no bytes written outside jail")

sftp.close()
t.close()
EOF

# Clear the malicious symlink and restart for clean reserved-path tests.
rm -f "$TEST_TMP/data/.zift-staging"
stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true

# --- 1b. UNSAFE-PERMS pre-existing dir is rejected --------------------
# v0.5.0 created .zift-staging without an explicit mode, so an
# upgrade lands on (typically) 0o755 — world-listable. v0.5.1
# rejects any pre-existing dir with group or other access bits.
mkdir -m 0755 "$TEST_TMP/data/.zift-staging"
start_zift
"$PY" - <<EOF
import paramiko, socket, sys
sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="partner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)
try:
    f = sftp.file("/pending/should-also-fail.bin", "wb")
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

# Clear and let zift recreate at 0o700.
rm -rf "$TEST_TMP/data/.zift-staging"

start_zift

# Plant a real file inside /.zift-staging from the test harness side
# (bypasses zift) so REMOVE and RENAME-from cannot be explained by
# "NotFound" — they MUST be reserved-name denials. We'll let zift
# create the staging dir via a real upload first, then plant the
# file directly.
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

# Plant a known file inside the just-created staging dir.
echo "harness-planted" > "$TEST_TMP/data/.zift-staging/known-victim.txt"

"$PY" - <<EOF
import paramiko, socket, sys

sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="partner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)

# --- 2. Reserved-path coverage: every op must reject /.zift-staging ---
# v0.5.0 only tested OPENDIR/STAT/OPEN-read. Partner has 'full'
# permission on / (so policy can't accidentally explain failures),
# and the harness planted a real file inside .zift-staging so
# REMOVE and RENAME-from can't pass via NotFound.
denials = []

def expect_deny(label, fn):
    try:
        fn()
        denials.append(("FAIL", label, "succeeded"))
    except IOError as exc:
        denials.append(("ok", label, str(exc)))

expect_deny("OPEN-write /.zift-staging/x",
    lambda: sftp.file("/.zift-staging/x", "wb").close())

expect_deny("MKDIR /.zift-staging/sub",
    lambda: sftp.mkdir("/.zift-staging/sub"))

expect_deny("MKDIR /.zift-staging (the dir name itself)",
    lambda: sftp.mkdir("/.zift-staging"))

# REMOVE the harness-planted real file: would succeed if reserved-
# name validation were bypassed (the file exists and partner has
# remove permission). Must be denied at validator layer.
expect_deny("REMOVE /.zift-staging/known-victim.txt (real file)",
    lambda: sftp.remove("/.zift-staging/known-victim.txt"))

# RENAME-from on the same real file: same trap.
expect_deny("RENAME from /.zift-staging/known-victim.txt",
    lambda: sftp.rename("/.zift-staging/known-victim.txt", "/pending/stolen.txt"))

expect_deny("RENAME to /.zift-staging/x",
    lambda: sftp.rename("/pending/seed.bin", "/.zift-staging/x"))

# RMDIR: the staging dir itself, AND a subdirectory we plant
# from the harness side (via mkdir -p, since the partner can't).
import os
os.makedirs("$TEST_TMP/data/.zift-staging/sub", exist_ok=True)
expect_deny("RMDIR /.zift-staging/sub",
    lambda: sftp.rmdir("/.zift-staging/sub"))
expect_deny("RMDIR /.zift-staging (the dir itself)",
    lambda: sftp.rmdir("/.zift-staging"))

# Dot-segment escape: path normalizer should catch the .. traversal
# OR reserved-name validator should catch the final component.
expect_deny("OPENDIR /pending/../.zift-staging",
    lambda: sftp.listdir("/pending/../.zift-staging"))

failed = [d for d in denials if d[0] == "FAIL"]
for d in denials:
    print(f"  {d[0]:<4} {d[1]}: {d[2]}")
if failed:
    print(f"FAIL: {len(failed)} reserved-path operations were not denied")
    sys.exit(1)
print(f"ok: all {len(denials)} reserved-path operations denied")

# Verify the harness-planted file STILL EXISTS — the rename and
# remove attempts above must not have actually moved/deleted it,
# even by accident.
import os
assert os.path.exists("$TEST_TMP/data/.zift-staging/known-victim.txt"), \
    "FAIL: harness-planted file was removed/moved despite denial"
print("ok: harness-planted file at /.zift-staging/known-victim.txt survived all attempts")

sftp.close()
t.close()
EOF

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
