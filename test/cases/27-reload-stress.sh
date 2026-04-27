#!/usr/bin/env bash
# Test: rapid SIGHUP-driven reloads while a session is active do not
#       disrupt the in-flight session (PLAN §7.3 ConfigRef refcounting).
# Covers: PLAN §7.3 reload safety
# Oracle: pre-reload and post-reload writes both complete with correct content

source "$(dirname "$0")/../lib/common.sh"

VENV="$(dirname "$0")/../.venv"
PY="$VENV/bin/python3"

if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing at $VENV"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)

mkdir -p "$TEST_TMP/data/uploads"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  reload-interval 0
  idle-timeout 30s
  shutdown-grace 5s
  log stderr

user runner
  password $hash
  root $TEST_TMP/data
  allow / read write list mkdir remove rename
EOF

start_zift

"$PY" - <<EOF
import paramiko, socket, os, signal, time

sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="runner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)

with sftp.open("/uploads/stress.txt", "w") as f:
    f.write(b"BEFORE_RELOAD")

# Hammer the server with SIGHUPs while we still have an open session.
for _ in range(5):
    os.kill($ZIFT_PID, signal.SIGHUP)
    time.sleep(0.1)

with sftp.open("/uploads/stress2.txt", "w") as f:
    f.write(b"AFTER_RELOAD")

sftp.close()
t.close()
EOF

content1=$(cat "$TEST_TMP/data/uploads/stress.txt")
content2=$(cat "$TEST_TMP/data/uploads/stress2.txt")

[[ "$content1" == "BEFORE_RELOAD" ]] || fail "pre-reload file corrupted: '$content1'"
ok "pre-reload write survived"

[[ "$content2" == "AFTER_RELOAD" ]] || fail "post-reload file corrupted: '$content2'"
ok "post-reload write completed successfully"

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
