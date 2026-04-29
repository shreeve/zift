#!/usr/bin/env bash
# Test: v0.6.0 publish-mode and mkdir-mode directives + scrubbed
# wire-facing error messages.
#
# Three behaviors covered in one case:
#
#  1. `publish-mode 0o640` overrides the default `0o660` — partner
#     uploads land at the configured mode, not the default.
#  2. `mkdir-mode 0o2750` overrides the default `0o2770` — directories
#     alice creates via SFTP land at the configured mode (with setgid
#     preserved so subdirectories inherit `group=...`).
#  3. Wire-facing error messages are scrubbed of zift-internal
#     vocabulary. A clobber denial says "permission denied", not
#     "would clobber an existing entry; partner lacks remove".
#
# Covers:  src/config.zig parsePublishMode + parseMkdirMode;
#          src/session.zig publish_mode/mkdir_mode threading through
#          handleOpen + handleMkdir; the v0.6.0 error-message scrub.

source "$(dirname "$0")/../lib/common.sh"

VENV="$(dirname "$0")/../.venv"
PY="$VENV/bin/python3"

if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing at $VENV"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)

mkdir -p "$TEST_TMP/data/inbox"
# Pre-existing file we'll try to clobber to verify the scrubbed error.
echo "EXISTING-CONTENT" > "$TEST_TMP/data/inbox/existing.txt"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr
  publish-mode 0o640
  mkdir-mode 0o2750

user partner
  password $hash
  root $TEST_TMP/data
  # add-only — no remove. So clobber attempts return permission denied.
  allow / read add
EOF

start_zift

"$PY" - <<EOF
import paramiko, socket, os, stat, sys

sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="partner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)

# --- 1. publish-mode override: file lands at 0o640, not 0o660. ----
with sftp.file("/inbox/upload.txt", "wb") as f:
    f.write(b"hello, world")
# Confirm on disk.
on_disk = "$TEST_TMP/data/inbox/upload.txt"
assert os.path.exists(on_disk), "upload should land at /inbox/upload.txt"
mode = stat.S_IMODE(os.stat(on_disk).st_mode)
assert mode == 0o640, f"publish-mode override failed: expected 0o640, got 0o{mode:o}"
print(f"ok: publish-mode 0o640 honored (file lands at 0o{mode:o})")

# --- 2. mkdir-mode override: directory lands at 0o2750. ------------
sftp.mkdir("/inbox/subdir")
sub = "$TEST_TMP/data/inbox/subdir"
assert os.path.isdir(sub), "mkdir should create the directory"
sub_mode = stat.S_IMODE(os.stat(sub).st_mode)
# 0o2750 is setgid (02000) + 0o750 (rwxr-x---).
assert sub_mode == 0o2750, f"mkdir-mode override failed: expected 0o2750, got 0o{sub_mode:o}"
print(f"ok: mkdir-mode 0o2750 honored (dir lands at 0o{sub_mode:o})")

# --- 3. Scrubbed error messages: clobber denial says ---------------
#        "permission denied", not zift-internal vocabulary.
try:
    with sftp.file("/inbox/existing.txt", "wb") as f:
        f.write(b"OVERWRITE-ATTEMPT")
    print("FAIL: clobber attempt succeeded against add-only partner")
    sys.exit(1)
except IOError as exc:
    msg = str(exc).lower()
    # Must NOT mention zift-internal vocabulary on the wire. The
    # status code already conveys the error class (SSH_FX_PERMISSION_
    # DENIED in this case); the human-readable message field should
    # be a generic SFTP-standard phrase.
    forbidden = [
        "clobber", "publish", "partner",
        "staged", "staging",
        "zift", "target appeared",
        "lacks remove",
    ]
    leaked = [w for w in forbidden if w in msg]
    if leaked:
        print(f"FAIL: error message leaked zift-internal terms {leaked}: {exc}")
        sys.exit(1)
    # Should be a clean SFTP-standard phrase. paramiko prepends its
    # own context ("[Errno 13] ..."); the inner text is what we
    # control. Anything containing "denied" or "permission" is fine.
    assert "denied" in msg or "permission" in msg, \
        f"clobber error should mention 'denied' or 'permission', got: {exc}"
    print(f"ok: clobber error scrubbed of zift-internal vocabulary: {exc}")

# Verify the existing file's contents survived the rejected attempt.
with open("$TEST_TMP/data/inbox/existing.txt") as f:
    survived = f.read().strip()
assert survived == "EXISTING-CONTENT", \
    f"existing file content corrupted: got {survived!r}"
print("ok: existing file content survived rejected clobber")

sftp.close()
t.close()
EOF

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
