#!/usr/bin/env bash
# Test: SIGUSR1 closes and reopens the audit log file
# The logrotate handshake: after a rename, new lines go to the new file.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
AUDIT="$TEST_TMP/audit.jsonl"
basic_config "log $AUDIT"
start_zift

sftp_password ally secret >"$TEST_TMP/c1.log" 2>&1 || fail "round 1 login failed"
wait_for_log '"operation":"session.ended"' 10 "$AUDIT" || fail "round 1 session never ended"

mv "$AUDIT" "$AUDIT.1"
: > "$AUDIT"
kill -USR1 "$ZIFT_PID"
# The reopen happens at the next audit write.
sftp_password ally secret >"$TEST_TMP/c2.log" 2>&1 || fail "round 2 login failed"
stop_zift TERM
log_contains "audit log reopened" || fail "no 'audit log reopened' message on stderr"
ok "server logged 'audit log reopened'"

log_contains '"operation":"auth.password","result":"ok"' "$AUDIT.1" \
    || fail "rotated file lacks the round 1 login"
log_contains '"operation":"auth.password","result":"ok"' "$AUDIT" \
    || fail "the reopened file lacks the round 2 login (reopen did not take)"
[[ $(count_log '"operation":"auth.password","result":"ok"' "$AUDIT.1") == 1 ]] \
    || fail "round 2 still went to the rotated file"
ok "round 1 is in the rotated file, round 2 in the new one"
