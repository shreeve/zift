#!/usr/bin/env bash
# Test: per-session handle cap stops a client from leaking unbounded
# `Handle` state by pipelining OPEN/OPENDIR requests and never
# closing them. The cap prevents the session-memory DoS that
# bypassed `max-connections` in v0.1.x and v0.2.0 (every connection
# could grow its own handle list to gigabytes before idle-timeout
# fired).
#
# Covers:  PLAN §8.4 DoS hardening, src/session.zig
#          `max_handles_per_session`, swapRemove on close.
# Oracle:  open N files, expect first 256 to succeed, 257th to fail
#          with the SFTP protocol error; close one, verify the next
#          open succeeds (slot reuse).

source "$(dirname "$0")/../lib/common.sh"

VENV="$(dirname "$0")/../.venv"
PY="$VENV/bin/python3"

if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing at $VENV"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)

# Pre-create 300 files so the test isn't gated on creating files
# during the loop (which is slower and makes the failure mode
# ambiguous between "too many handles" and "can't create").
mkdir -p "$TEST_TMP/data"
for i in $(seq 1 300); do
    touch "$TEST_TMP/data/file_$(printf '%03d' $i)"
done

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  idle-timeout 30s
  log stderr

user runner
  password $hash
  root $TEST_TMP/data
  allow / read list
EOF

start_zift

"$PY" - <<EOF
import paramiko, socket, sys

sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="runner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)

CAP = 256

# --- 1. open up to the cap, all should succeed ---------------------------
opened = []
for i in range(1, CAP + 1):
    name = "file_%03d" % i
    try:
        f = sftp.file("/" + name, "r")
        opened.append(f)
    except IOError as exc:
        print(f"fail: open #{i} ('{name}') unexpectedly failed before cap: {exc}")
        sys.exit(1)
print(f"ok: opened {len(opened)} handles up to the cap")

# --- 2. one more should fail ---------------------------------------------
try:
    extra = sftp.file("/file_257", "r")
    print(f"fail: open #{CAP+1} should have been rejected by the cap")
    extra.close()
    sys.exit(1)
except IOError as exc:
    # paramiko raises IOError with errno from SFTP status on the wire
    print(f"ok: open #{CAP+1} rejected: {exc}")

# --- 3. close one handle, verify a new open succeeds (slot reuse) --------
opened[0].close()
opened.pop(0)
try:
    reopened = sftp.file("/file_258", "r")
    opened.append(reopened)
    print("ok: closing one handle frees a slot for the next open")
except IOError as exc:
    print(f"fail: open after close should have succeeded, got: {exc}")
    sys.exit(1)

# --- 4. clean up: close everything still open ----------------------------
for f in opened:
    f.close()
print(f"ok: cleaned up {len(opened)} open handles")

# --- 5. session keeps working after stress -------------------------------
# After hitting the cap and recovering, the session should still be
# usable (no permanent corruption).
listing = sftp.listdir("/")
assert len(listing) >= 300, f"directory listing broken after cap stress: {len(listing)} entries"
print(f"ok: session usable after cap stress (listed {len(listing)} files)")

sftp.close()
t.close()
EOF

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
