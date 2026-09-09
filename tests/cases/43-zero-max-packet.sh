#!/usr/bin/env bash
# Regression for libssh CVE-2026-59843: an authenticated channel-open
# request advertising a zero maximum packet size must be rejected rather
# than sending the server into an unbounded packetization loop.

source "$(dirname "$0")/../lib/common.sh"

VENV="$(dirname "$0")/../.venv"
PY="$VENV/bin/python3"

if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing at $VENV"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)
mkdir -p "$TEST_TMP/data"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  idle-timeout 2s
  log stderr

user partner
  auth $hash
  root $TEST_TMP/data
  allow / read list
EOF

start_zift

"$PY" - <<EOF
import socket
import time
import paramiko

# Paramiko normally clamps this field to a safe minimum. Override that
# client-side guard solely to put the malicious wire value on the test
# connection.
transport = paramiko.Transport(("127.0.0.1", $TEST_PORT))
transport.connect(username="partner", password="secret")
sanitize = transport._sanitize_packet_size
transport._sanitize_packet_size = lambda value: 0 if value is None else sanitize(value)

started = time.monotonic()
rejected = False
try:
    channel = transport.open_session(timeout=3)
    channel.invoke_subsystem("sftp")
except (EOFError, OSError, paramiko.SSHException):
    rejected = True
elapsed = time.monotonic() - started
transport.close()

assert rejected, "server accepted a channel advertising max-packet-size=0"
assert elapsed < 3.0, f"malformed channel was not rejected promptly ({elapsed:.2f}s)"
print(f"ok: zero max-packet channel rejected in {elapsed:.2f}s")

# The malformed connection must not consume a spinning worker or damage
# process-global libssh state. A clean session should still work.
normal = paramiko.Transport(("127.0.0.1", $TEST_PORT))
normal.connect(username="partner", password="secret")
sftp = paramiko.SFTPClient.from_transport(normal)
assert sftp.listdir("/") == []
sftp.close()
normal.close()
print("ok: server remains responsive after malformed channel")
EOF

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
