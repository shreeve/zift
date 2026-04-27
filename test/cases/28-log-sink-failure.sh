#!/usr/bin/env bash
# Test: when the audit log file becomes unwritable, sftp sessions still
#       complete — audit is not fail-closed (PLAN §8.5).
# Covers: PLAN §8.5, audit.zig rate-limited write-failure warnings
# Oracle: sftp session completes despite chmod 000 on the audit log

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
touch "$TEST_TMP/audit.jsonl"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  idle-timeout 10s
  shutdown-grace 2s
  log $TEST_TMP/audit.jsonl

user runner
  password $hash
  root $TEST_TMP/data
  allow / read write list mkdir
EOF

start_zift

# Make the audit log unwritable mid-flight. The server should keep
# serving SFTP requests; only stderr gets a rate-limited warning.
chmod 000 "$TEST_TMP/audit.jsonl"

"$PY" - <<EOF
import paramiko, socket, sys

sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="runner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)

sftp.mkdir("/testdir")
with sftp.open("/testdir/file.txt", "w") as f:
    f.write(b"hello despite broken log")

with sftp.open("/testdir/file.txt", "r") as f:
    data = f.read()

assert data == b"hello despite broken log", f"unexpected: {data!r}"

sftp.close()
t.close()
EOF
rc=$?

# Restore so trap-cleanup can remove the directory.
chmod 644 "$TEST_TMP/audit.jsonl"

[[ $rc -eq 0 ]] \
    && ok "sftp session completed despite unwritable audit log" \
    || fail "sftp session failed when audit log was unwritable"

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
