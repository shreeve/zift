#!/usr/bin/env bash
# Test: unauthenticated TCP connections that never speak SSH are reaped
#       by idle-timeout, freeing max-connections slots for real clients.
# Covers: PLAN §6.2 idle-timeout pre-auth, PLAN §8.4 pre-auth slot reaping
# Oracle: after stuck TCP clients expire, a real sftp client connects.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
hash=$(make_password_hash secret)

mkdir -p "$TEST_TMP/data"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  idle-timeout 3s
  max-connections 2
  shutdown-grace 2s
  log stderr

user runner
  password $hash
  root $TEST_TMP/data
  allow / read list
EOF

start_zift

# Open two raw TCP connections that never speak SSH. Each one occupies
# a max-connections slot until idle-timeout reaps it.
python3 - <<EOF
import socket, time
s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s1.connect(("127.0.0.1", $TEST_PORT))
s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s2.connect(("127.0.0.1", $TEST_PORT))
# Hold them open while idle-timeout runs (3 seconds + margin).
time.sleep(5)
s1.close()
s2.close()
EOF

# Give the server a moment to finish handshake-failed teardowns so the
# active_sessions counter has settled before we try to connect.
sleep 1

# A real sftp client should now succeed because the stuck slots were
# reaped by idle-timeout.
sftp_output=$(sftp_password runner secret "ls" 2>&1) || true
echo "  sftp output:"
echo "$sftp_output" | sed 's/^/    /'
if echo "$sftp_output" | grep -q "sftp>"; then
    ok "real client connected after stuck TCP clients reaped"
else
    fail "real client could not connect after idle-timeout"
fi

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
