#!/usr/bin/env bash
# Test: SIGUSR1 closes and reopens the audit log file
# Covers: PLAN §7.2 SIGUSR1 + §7.4 logrotate handshake
# TODOS: P1 audit pipeline overhaul (SIGUSR1 reopen consumer)

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
  auth $hash
  root $TEST_TMP
  allow / read list
EOF

start_zift

# Round 1: produce one audit line into $AUDIT_PATH.
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
sleep 1

# Mimic logrotate: rename the active log out of the way, then re-create
# an empty file at the original path. The old file holds the round-1
# line; the new file is empty and waiting for round 2.
mv "$AUDIT_PATH" "$AUDIT_PATH.1"
: > "$AUDIT_PATH"

# Send SIGUSR1 to the running zift binary (NOT the wrapper shell).
ZIFT_BINARY_PID=$(pgrep -x zift | head -1)
[[ -n "$ZIFT_BINARY_PID" ]] || fail "could not find running zift binary pid"
kill -USR1 "$ZIFT_BINARY_PID"
sleep 1

# Round 2: produce another audit line. With SIGUSR1 honored, this lands
# in the freshly-created file at the original path. Without the fix, it
# would still land in the rotated-away file (the kernel still has the
# old fd open).
expect <<EOF >"$TEST_TMP/c2.log" 2>&1
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

# Oracle: round-1 line lives in .1; round-2 line lives in the recreated
# file. Both files present; both populated.
[[ -s "$AUDIT_PATH.1" ]] || fail "rotated audit file is empty (round-1 line not written before rotate)"
[[ -s "$AUDIT_PATH" ]]   || fail "post-SIGUSR1 audit file is empty (reopen did not fire)"
ok "rotated file has $(wc -l < "$AUDIT_PATH.1" | tr -d ' ') line(s); new file has $(wc -l < "$AUDIT_PATH" | tr -d ' ') line(s)"

# Stderr should mention the reopen (operational status line).
log_contains "audit log reopened" || fail "no 'audit log reopened' message on stderr"
ok "server logged 'audit log reopened'"
