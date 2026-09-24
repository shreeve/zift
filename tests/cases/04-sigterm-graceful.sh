#!/usr/bin/env bash
# Test: SIGTERM triggers graceful drain; in-flight client finishes; clean exit
# A restart must not cut off a partner mid-transfer.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
basic_config
start_zift

bg sftp_password ally secret "@until $TEST_TMP/release" "ls" >"$TEST_TMP/client.log" 2>&1
wait_for_log '"operation":"auth.password","result":"ok"' || fail "session never logged in"

kill -TERM "$ZIFT_PID"
wait_for_log "shutdown signal received" || fail "no shutdown notice"
sleep 0.5
kill -0 "$ZIFT_PID" 2>/dev/null || fail "server exited with a session still open"
ok "server waits for the open session"

touch "$TEST_TMP/release"
wait_bg || fail "in-flight client did not finish: $(cat "$TEST_TMP/client.log")"
ok "in-flight client finished its commands"

wait_zift
[[ "$ZIFT_RC" == 0 ]] || fail "server exited $ZIFT_RC"
log_contains "all sessions drained" || fail "no clean drain (saw forced grace expiration)"
ok "graceful drain completed before grace deadline"
