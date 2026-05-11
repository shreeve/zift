#!/usr/bin/env bash
# Test: idle-timeout disconnects an authenticated client past the deadline
# Covers: PLAN §6.2 idle-timeout, §8.5 idle.timeout audit line
# TODOS: DONE (idle-timeout in operational signal cluster)

source "$(dirname "$0")/../lib/common.sh"

make_host_key
hash=$(make_password_hash secret)

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  idle-timeout 3s
  log stderr

user runner
  auth $hash
  root $TEST_TMP
  allow / read list
EOF

start_zift

# Connect, sit idle past the 3s timeout, observe the disconnect.
expect <<EOF >"$TEST_TMP/client.log" 2>&1
set timeout 15
spawn sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\
    -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 \\
    -P $TEST_PORT runner@127.0.0.1
expect "password:"
send "secret\r"
expect "sftp>"
sleep 5
send "ls\r"
expect eof
EOF

grep -q 'idle.timeout' "$ZIFT_LOG" || fail "no idle.timeout audit line"
ok "idle.timeout audit line emitted"

grep -q 'disconnect' "$TEST_TMP/client.log" || fail "client did not see disconnect"
ok "client received disconnect"

stop_zift TERM
