#!/usr/bin/env bash
# Test: every audit line carries an `ip` field with the connecting IP
# Covers: PLAN §7.4 audit schema (`ip` is mandatory and stable-ordered last)
# TODOS: P1 audit pipeline overhaul (ip field)

source "$(dirname "$0")/../lib/common.sh"

make_host_key
hash=$(make_password_hash secret)

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user ally
  auth $hash
  root $TEST_TMP
  allow / read list
EOF

start_zift

# A successful auth followed by a denied auth gives us two audit lines
# that should both carry `"ip":"127.0.0.1"`.
expect <<EOF >"$TEST_TMP/c1.log" 2>&1
set timeout 15
spawn sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\
    -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 \\
    -P $TEST_PORT ally@127.0.0.1
expect "password:"
send "secret\r"
expect "sftp>"
send "bye\r"
expect eof
EOF

expect <<EOF >"$TEST_TMP/c2.log" 2>&1
set timeout 15
spawn sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\
    -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 \\
    -P $TEST_PORT ally@127.0.0.1
expect "password:"
send "wrong\r"
expect eof
EOF

stop_zift TERM
sleep 1

# Every JSON audit line must contain "ip": with a value.
total=$(grep -c '"event":"zift.audit"' "$ZIFT_LOG" || true)
with_ip=$(grep -c '"ip":"' "$ZIFT_LOG" || true)
[[ "$total" -ge "2" ]] || fail "expected at least 2 audit lines, got $total"
[[ "$total" == "$with_ip" ]] || fail "expected ip field in every audit line ($total total, $with_ip with ip)"
ok "every audit line carries an ip field ($total/$total)"

# IP value matches the loopback address the test connected from.
loopback_count=$(grep -c '"ip":"127.0.0.1"' "$ZIFT_LOG" || true)
[[ "$loopback_count" -ge "2" ]] || fail "expected ip=127.0.0.1, none found"
ok "ip field carries the actual peer address (127.0.0.1)"

# v0.7.0 stable order: time, event, user, operation, result, path, detail, ip.
# Pick one auth.password line and verify the leading-time invariant
# plus the relative ordering of the rest.
sample=$(grep '"operation":"auth.password"' "$ZIFT_LOG" | head -1)
[[ -n "$sample" ]] || fail "no auth.password line to inspect"
echo "  sample: $sample"
time_pos=$(echo "$sample" | awk '{print index($0,"\"time\"")}')
event_pos=$(echo "$sample" | awk '{print index($0,"\"event\"")}')
op_pos=$(echo "$sample" | awk '{print index($0,"\"operation\"")}')
result_pos=$(echo "$sample" | awk '{print index($0,"\"result\"")}')
ip_pos=$(echo "$sample" | awk '{print index($0,"\"ip\"")}')
[[ "$time_pos" == "2" ]] \
    || fail "expected time at position 2 (immediately after opening '{'), got $time_pos"
[[ "$time_pos" -lt "$event_pos" ]] || fail "expected time before event"
[[ "$event_pos" -lt "$op_pos" ]] || fail "expected event before operation"
[[ "$op_pos" -lt "$result_pos" ]] || fail "expected operation before result"
[[ "$result_pos" -lt "$ip_pos" ]] || fail "expected result before ip (got result=$result_pos ip=$ip_pos)"
ok "field order matches v0.7.0 schema: time(1) < event < operation < result < ip"

# Every audit line carries an RFC 3339 UTC timestamp with millisecond
# precision: `YYYY-MM-DDTHH:MM:SS.mmmZ` — exactly 24 chars between
# the quotes after `"time":`.
ts_count=$(grep -cE '"time":"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z"' "$ZIFT_LOG" || true)
[[ "$ts_count" == "$total" ]] \
    || fail "expected RFC3339 ms timestamp on every audit line ($ts_count/$total)"
ok "every audit line carries an RFC 3339 UTC ms timestamp ($ts_count/$total)"
