#!/usr/bin/env bash
# Test: SIGTERM triggers graceful drain; in-flight client finishes; clean exit
# Covers: PLAN §7.1 graceful shutdown
# TODOS: DONE (SIGTERM drain in operational signal cluster)

source "$(dirname "$0")/../lib/common.sh"

make_host_key
hash=$(make_password_hash secret)

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user runner
  auth $hash
  root $TEST_TMP
  allow / read list
EOF

start_zift

# Hold a session, then send SIGTERM mid-flight.
hold_session() {
    expect <<EOF >"$TEST_TMP/client.log" 2>&1
set timeout 30
spawn sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\
    -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 \\
    -P $TEST_PORT runner@127.0.0.1
expect "password:"
send "secret\r"
expect "sftp>"
sleep 3
send "bye\r"
expect eof
EOF
}
bg hold_session

sleep 1
kill -TERM "$ZIFT_PID"

wait_bg
for _ in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$ZIFT_PID" 2>/dev/null || break
    sleep 0.5
done

kill -0 "$ZIFT_PID" 2>/dev/null && fail "server did not exit after drain"
log_contains "shutdown signal received" || fail "no shutdown notice"
log_contains "all sessions drained" || fail "no clean drain (saw forced grace expiration)"
ok "graceful drain completed before grace deadline"
