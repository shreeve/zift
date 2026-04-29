#!/usr/bin/env bash
# Test: v0.5.0 server-side staging-rename for atomic uploads.
#
# Every OPEN(write+CREAT) on a non-existent target goes through a
# random-name staging file in <root>/.zift-staging/. The target path
# only appears on the operator-visible filesystem when the partner
# sends SSH_FXP_CLOSE — at which point an atomic rename publishes
# the file. Operators who watch the partner directory never see a
# partial upload.
#
# Covers:  src/vfs.zig openStagingDir + staging_dir_name reservation
#          in normalizeVirtualPath; src/session.zig staged Handle
#          flow (handleOpen create-new path, handleClose
#          publishStagedHandle, closeHandle orphan cleanup); the
#          listing renderer's .zift-staging filter.

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

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user partner
  password $hash
  root $TEST_TMP/data
  allow / read
  allow /pending read add
EOF

start_zift

"$PY" - <<EOF
import paramiko, socket, os, time, sys, threading, io

# --- 1. ATOMIC APPEARANCE: target doesn't exist until CLOSE ------------
sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="partner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)

f = sftp.file("/pending/large.bin", "wb")
# Write a chunk, then PAUSE — confirm target is not yet visible.
f.write(b"X" * 4096)
f.flush()
# Server-side filesystem check (we have direct disk access here)
target_path = "$TEST_TMP/data/pending/large.bin"
assert not os.path.exists(target_path), \
    f"target should NOT exist mid-upload, but it does: {target_path}"
print("ok: target absent from operator's view during upload")

# v0.6.0: the in-flight staging file's mode is the configured
# `publish-mode` (default 0o660), so it lands at the target with
# the right mode after the atomic rename — POSIX rename(2) preserves
# the inode's mode. Confidentiality of partial uploads is enforced
# by the staging directory itself being 0o700 (only the daemon UID
# can traverse it), independent of the file's own mode.
import stat
staging_dir = "$TEST_TMP/data/.zift-staging"
dir_mode = stat.S_IMODE(os.stat(staging_dir).st_mode)
assert dir_mode == 0o700, f"staging dir mode should be 0o700, got 0o{dir_mode:o}"
staging_files = os.listdir(staging_dir)
assert len(staging_files) == 1, f"expected 1 staging file mid-upload, got {staging_files}"
sf_path = os.path.join(staging_dir, staging_files[0])
file_mode = stat.S_IMODE(os.stat(sf_path).st_mode)
assert file_mode == 0o660, f"staging file mode should be 0o660 (publish-mode default), got 0o{file_mode:o}"
print(f"ok: staging dir is 0o{dir_mode:o} and staging file is 0o{file_mode:o} mid-upload")

# Write more, then CLOSE.
f.write(b"Y" * 4096)
f.close()
# Now the rename has fired. Target should exist with full content.
assert os.path.exists(target_path), "target should exist after CLOSE"
size = os.path.getsize(target_path)
assert size == 8192, f"expected 8192 bytes after CLOSE, got {size}"
print("ok: target appears at CLOSE with full content (8192 bytes)")

# v0.6.0: the published file's mode is the configured `publish-mode`
# (default 0o660). rename(2) preserves the inode's mode, so the
# file should appear at the target with exactly the same mode it
# had in staging — operators in group `zift` can read+write it,
# world has nothing.
target_mode = stat.S_IMODE(os.stat(target_path).st_mode)
assert target_mode == 0o660, f"published file mode should be 0o660, got 0o{target_mode:o}"
print(f"ok: published file mode is 0o{target_mode:o} (publish-mode default)")

# --- 2. STAGING DIR INVISIBLE TO PARTNER -------------------------------
# /.zift-staging is reserved by the path-validator AND filtered from
# listings. Confirm both layers.
listing = sftp.listdir("/")
assert ".zift-staging" not in listing, \
    f"staging dir leaked into / listing: {listing}"
print(f"ok: .zift-staging hidden from listing of / (sees {listing})")

# Direct OPENDIR/STAT/OPEN attempts on the staging path must fail.
try:
    sftp.listdir("/.zift-staging")
    print("FAIL: partner could OPENDIR /.zift-staging")
    sys.exit(1)
except IOError as exc:
    print(f"ok: OPENDIR /.zift-staging denied: {exc}")
try:
    sftp.stat("/.zift-staging")
    print("FAIL: partner could STAT /.zift-staging")
    sys.exit(1)
except IOError as exc:
    print(f"ok: STAT /.zift-staging denied: {exc}")
try:
    sftp.file("/.zift-staging/anything", "rb")
    print("FAIL: partner could OPEN under /.zift-staging")
    sys.exit(1)
except IOError as exc:
    print(f"ok: OPEN under /.zift-staging denied: {exc}")

# --- 3. ORPHAN CLEANUP: disconnect mid-upload removes staging file ----
# Open a write handle, write some data, but DON'T close — just drop
# the connection. The session deinit's per-handle cleanup must
# unlink the staging file so it doesn't accumulate.
import paramiko, socket
sock2 = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t2 = paramiko.Transport(sock2)
t2.connect(username="partner", password="secret")
sftp2 = paramiko.SFTPClient.from_transport(t2)
f2 = sftp2.file("/pending/orphaned.bin", "wb")
f2.write(b"PARTIAL")
# Don't close f2; just kill the transport.
t2.close()
# Give the server a moment to deinit and clean up.
time.sleep(0.5)
# Target was never published.
assert not os.path.exists("$TEST_TMP/data/pending/orphaned.bin"), \
    "orphaned target should not exist on disk"
# And the staging dir should not have leftover files.
staging_dir = "$TEST_TMP/data/.zift-staging"
if os.path.isdir(staging_dir):
    leftover = os.listdir(staging_dir)
    assert leftover == [], f"orphaned staging files leaked: {leftover}"
print("ok: disconnect mid-upload cleaned up staging file (no orphan)")

# --- 4. CLOBBER PROTECTION AT CLOSE: target appearing during upload ---
# Even without partner-supplied EXCL, an add-only partner cannot
# clobber an existing target. Open a staged upload, race a second
# entity (we use direct disk write here, simulating a second SFTP
# session or operator process) creating the target, then send CLOSE.
# The publish-step re-checks the clobber rule and refuses to
# overwrite the racer's content.
#
# paramiko's SFTPFile.close() silently swallows server-side errors,
# so we can't observe the SSH_FX_PERMISSION_DENIED directly. Instead
# we check the on-disk content: if the clobber check worked, the
# racer's bytes survive; if it didn't, the partner's bytes overwrite.
sock4 = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t4 = paramiko.Transport(sock4)
t4.connect(username="partner", password="secret")
sftp4 = paramiko.SFTPClient.from_transport(t4)
f4 = sftp4.file("/pending/race-test.bin", "wb")
f4.write(b"FROM-PARTNER")
with open("$TEST_TMP/data/pending/race-test.bin", "wb") as comp:
    comp.write(b"FROM-RACER")
f4.close()  # publish step: lstat finds racer's file, no remove perm, denied
sftp4.close()
t4.close()
# Give the server a moment to finalize cleanup.
time.sleep(0.2)
with open("$TEST_TMP/data/pending/race-test.bin", "rb") as ver:
    content = ver.read()
assert content == b"FROM-RACER", \
    f"clobber check FAILED — partner overwrote racer: got {content!r}"
print("ok: target appearing during upload preserved (CLOSE-time clobber check denied overwrite)")

sftp.close()
t.close()
EOF

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
