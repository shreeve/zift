#!/usr/bin/env bash
# Test: an audit FIFO with no reader fails fast, never hangs the server
# At startup it is a clean error naming the path; at a SIGUSR1 reopen
# the server keeps serving on the old log and retries until a reader
# appears.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
AUDIT="$TEST_TMP/audit.log"

# --- a) startup ----------------------------------------------------------
mkfifo "$AUDIT"
basic_config "log $AUDIT"
"$ZIFT_BIN" serve "$TEST_TMP/zift.conf" >"$TEST_TMP/startup.log" 2>&1 &
pid=$!
PIDS+=("$pid")
wait_exit "$pid" 5 || fail "serve blocked opening a FIFO with no reader"
rc=0
wait "$pid" || rc=$?
((rc != 0)) || fail "serve exited 0 with an unopenable audit log"
grep -q "cannot open audit log $AUDIT: .*ENXIO" "$TEST_TMP/startup.log" \
    || fail "startup error does not name the path and ENXIO: $(cat "$TEST_TMP/startup.log")"
ok "startup with a readerless FIFO fails fast (rc=$rc) and names the path"

# --- b) reopen onto a readerless FIFO ------------------------------------
rm -f "$AUDIT"
start_zift
sftp_password ally secret "ls" >"$TEST_TMP/c1.log" 2>&1 || fail "session 1 failed"
mv "$AUDIT" "$AUDIT.1"
mkfifo "$AUDIT"
kill -USR1 "$ZIFT_PID"
# The reopen happens at the next audit write.
sftp_password ally secret "ls" >"$TEST_TMP/c2.log" 2>&1 \
    || fail "session after reopening onto a readerless FIFO failed (server wedged?)"
log_contains "audit log reopen failed: $AUDIT: " || fail "no reopen-failure warning naming the path: $(cat "$ZIFT_LOG")"
grep -q "audit log reopen failed: $AUDIT: .*ENXIO" "$ZIFT_LOG" || fail "the reopen failure does not say ENXIO"
n=$(count_log '"operation":"auth.password","result":"ok"' "$AUDIT.1")
((n >= 2)) || fail "old log should still receive lines after the failed reopen (got $n auth lines)"
ok "failed reopen keeps serving and keeps writing the old log"

# --- c) the retry picks up a reader --------------------------------------
cat "$AUDIT" >"$TEST_TMP/shipped.log" &
READER=$!
PIDS+=("$READER")
sleep 5.2  # the retry is due 5 s after the failure; the next write carries it
sftp_password ally secret "ls" >"$TEST_TMP/c3.log" 2>&1 || fail "session 3 failed"
log_contains "audit log reopened" || fail "retry never reopened the FIFO: $(cat "$ZIFT_LOG")"
stop_zift TERM
wait_exit "$READER" 5 || fail "reader never saw EOF"
log_contains '"operation":"auth.password","result":"ok"' "$TEST_TMP/shipped.log" \
    || fail "reader got no audit lines: $(cat "$TEST_TMP/shipped.log")"
ok "retry reopened onto the FIFO once a reader appeared"
