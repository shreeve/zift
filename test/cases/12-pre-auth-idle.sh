#!/usr/bin/env bash
# Test: idle-timeout reaps clients stuck mid-handshake (pre-auth)
# Covers: PLAN §6.2 idle-timeout applied across the full session lifecycle
# TODOS: P0 No idle timeout pre-auth + P0 max-connections doesn't bound pre-auth
#
# A client that opens TCP and then never speaks SSH must not pin a worker
# thread or a max-connections slot indefinitely. With idle-timeout=2s and
# max-connections=1, a stuck pre-auth connection should be reaped within
# the timeout window so a legitimate client can use the slot.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
hash=$(make_password_hash secret)

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  idle-timeout 2s
  max-connections 1
  log stderr

user ally
  password $hash
  root $TEST_TMP
  allow / read list
EOF

start_zift

# Stick a client mid-handshake: open a raw TCP connection, read the
# SSH banner, but never send our own banner back. libssh's
# ssh_handle_key_exchange will block on the second-half banner read
# until idle-timeout fires (after the fix) or forever (before).
stuck_client() {
    python3 -c '
import socket, sys, time
s = socket.create_connection(("127.0.0.1", '"$TEST_PORT"'))
# Read whatever the server sends (its SSH banner) but never speak SSH.
s.settimeout(15)
try:
    while True:
        data = s.recv(4096)
        if not data:
            break
except (socket.timeout, OSError):
    pass
'
}
bg stuck_client

# Give the server a beat to accept the stuck connection and start its
# pre-auth wait, then a beat more for idle-timeout to fire (2s + slack).
sleep 1
echo "  stuck client connected, waiting past idle-timeout..."
sleep 4

# Oracle: with max-connections=1, a fresh legitimate client can only
# succeed if the stuck slot was reaped. If the stuck connection still
# holds the slot, accept will deny with "max-connections reached" and
# the new client will see "Connection closed".
expect <<EOF >"$TEST_TMP/legit.log" 2>&1
set timeout 15
spawn sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\
    -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 \\
    -P $TEST_PORT ally@127.0.0.1
expect {
    "password:" { send "secret\r" ; exp_continue }
    "sftp>"    { send "bye\r" ; expect eof }
    eof        { }
}
EOF

stop_zift TERM
wait_bg

# Did the legit client land?
if grep -q "Connected to" "$TEST_TMP/legit.log"; then
    ok "legit client connected — pre-auth slot was reaped"
elif grep -q "Connection closed" "$TEST_TMP/legit.log"; then
    fail "legit client refused — stuck pre-auth client still holding the only slot"
else
    fail "unexpected legit-client outcome; see $TEST_TMP/legit.log"
fi

# Belt-and-suspenders: count successful auths in the audit log. Should be
# exactly 1 (the legit client). The stuck client never authed.
auth_ok=$(grep -c '"operation":"auth.password","result":"ok"' "$ZIFT_LOG" || true)
[[ "$auth_ok" == "1" ]] || fail "expected 1 auth.password ok, got $auth_ok"
ok "audit log shows the legit client authenticated"
