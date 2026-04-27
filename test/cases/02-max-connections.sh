#!/usr/bin/env bash
# Test: max-connections refuses excess concurrent sessions with audit
# Covers: PLAN §6.2 max-connections, accept denial audit line
# TODOS: DONE (max-connections in operational signal cluster)

source "$(dirname "$0")/../lib/common.sh"

make_host_key
hash=$(make_password_hash secret)

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  max-connections 2
  log stderr

user runner
  password $hash
  root $TEST_TMP
  allow / read list
EOF

start_zift

hold_session() {
    local label="$1"
    expect <<EOF >"$TEST_TMP/client-$label.log" 2>&1
set timeout 30
spawn sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\
    -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 \\
    -P $TEST_PORT runner@127.0.0.1
expect "password:"
send "secret\r"
expect "sftp>"
sleep 5
send "bye\r"
expect eof
EOF
}

bg hold_session a
bg hold_session b
sleep 1
bg hold_session c
# Client c is expected to fail (denied at SSH level). wait_bg ignores
# child exit codes; the audit log is the actual oracle.
wait_bg

# Two should have authed successfully; one should have been refused.
auth_count=$(grep -c '"operation":"auth.password","result":"ok"' "$ZIFT_LOG" || true)
deny_count=$(grep -c '"operation":"accept","result":"denied"' "$ZIFT_LOG" || true)

[[ "$auth_count" == "2" ]] || fail "expected 2 successful auths, got $auth_count"
ok "two sessions admitted"

[[ "$deny_count" -ge "1" ]] || fail "expected at least 1 accept denial, got $deny_count"
ok "excess connection denied with audit"

stop_zift TERM
