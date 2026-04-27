#!/usr/bin/env bash
# Test: `log /absolute/path` routes audit lines to the file, not stderr
# Covers: PLAN §7.4 file destination + O_APPEND atomic writes
# TODOS: P1 audit pipeline overhaul (LogTarget.file actually used)

source "$(dirname "$0")/../lib/common.sh"

make_host_key
hash=$(make_password_hash secret)

AUDIT_PATH="$TEST_TMP/audit.jsonl"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log $AUDIT_PATH

user ally
  password $hash
  root $TEST_TMP
  allow / read list
EOF

start_zift

# One successful auth produces an auth.password ok audit line.
expect <<EOF >"$TEST_TMP/client.log" 2>&1
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

stop_zift TERM
sleep 1

# Oracle 1: audit file exists with the JSON line in it.
[[ -f "$AUDIT_PATH" ]] || fail "audit file was not created at $AUDIT_PATH"
grep -q '"event":"zift.audit"' "$AUDIT_PATH" \
    || fail "audit file does not contain a zift.audit line; contents:\n$(cat "$AUDIT_PATH")"
grep -q '"operation":"auth.password","result":"ok"' "$AUDIT_PATH" \
    || fail "auth.password ok line missing from audit file"
ok "audit lines landed in the configured file"

# Oracle 2: stderr does NOT contain the audit JSON. zift.log captures
# stderr, so it should hold operational messages but no audit JSON.
if grep -q '"event":"zift.audit"' "$ZIFT_LOG"; then
    fail "audit JSON leaked to stderr when log destination is a file"
fi
ok "stderr is free of audit JSON when file destination is configured"

# Oracle 3: the audit file is readable JSON-per-line, no truncated bytes.
while IFS= read -r line; do
    [[ "${line:0:1}" == "{" ]] || fail "non-JSON line in audit file: $line"
    [[ "${line: -1}" == "}" ]] || fail "audit line missing closing brace: $line"
done < "$AUDIT_PATH"
ok "every line in the audit file is JSON-shaped"

# Oracle 4: the file is opened with O_APPEND so a second startup that
# also writes to the same path appends rather than truncates. We simulate
# this by restarting zift against the same config and checking the
# pre-existing line is still there.
PRE_LINES=$(wc -l < "$AUDIT_PATH" | tr -d ' ')
start_zift
expect <<EOF >"$TEST_TMP/client2.log" 2>&1
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
stop_zift TERM
sleep 1
POST_LINES=$(wc -l < "$AUDIT_PATH" | tr -d ' ')

[[ "$POST_LINES" -gt "$PRE_LINES" ]] \
    || fail "second run did not append (pre=$PRE_LINES post=$POST_LINES)"
ok "second run appends rather than truncates ($PRE_LINES → $POST_LINES lines)"
