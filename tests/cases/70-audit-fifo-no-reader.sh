#!/usr/bin/env bash
# Test: an audit FIFO with no reader fails fast, never hangs the server
# Covers: audit.zig openLogFile O_NONBLOCK open, errno-specific startup
#         message, SIGUSR1 reopen onto a readerless FIFO + retry.
# Oracle: a) `serve` with `log <fifo>` and no reader exits non-zero within
#            seconds and names the path and ENXIO; b) a running server
#            reopened onto a readerless FIFO keeps serving and keeps its
#            old log; c) once a reader appears, the retry picks it up.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
hash=$(make_password_hash secret)
mkdir -p "$TEST_TMP/data"
AUDIT="$TEST_TMP/audit.log"

config_with_log() {
    write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log $1

user ally
  auth $hash
  root $TEST_TMP/data
  allow / read list
EOF
}

# Wait up to $2 tenths of a second for pid $1 to exit.
exits_within() {
    local pid="$1" n=0
    while kill -0 "$pid" 2>/dev/null; do
        n=$((n + 1))
        (( n > $2 )) && return 1
        sleep 0.1
    done
}

# --- a) startup ----------------------------------------------------------
mkfifo "$AUDIT"
config_with_log "$AUDIT"
"$ZIFT_BIN" serve "$TEST_TMP/zift.conf" >"$TEST_TMP/startup.log" 2>&1 &
pid=$!
if ! exits_within "$pid" 50; then
    kill -KILL "$pid" 2>/dev/null || true
    fail "serve blocked opening a FIFO with no reader"
fi
rc=0
wait "$pid" || rc=$?
(( rc != 0 )) || fail "serve exited 0 with an unopenable audit log"
grep -q "cannot open audit log $AUDIT: .*ENXIO" "$TEST_TMP/startup.log" \
    || fail "startup error does not name the path and ENXIO: $(cat "$TEST_TMP/startup.log")"
ok "startup with a readerless FIFO fails fast (rc=$rc) and names the path"

# --- b) reopen onto a readerless FIFO ------------------------------------
rm -f "$AUDIT"
config_with_log "$AUDIT"
start_zift

sftp_password ally secret "ls" >"$TEST_TMP/c1.log" 2>&1 || fail "session 1 failed"
mv "$AUDIT" "$AUDIT.1"
mkfifo "$AUDIT"
kill -USR1 "$ZIFT_PID"
sleep 0.3

sftp_password ally secret "ls" >"$TEST_TMP/c2.log" 2>&1 \
    || fail "session after reopening onto a readerless FIFO failed (server wedged?)"
grep -q "audit log reopen failed: $AUDIT: .*ENXIO" "$ZIFT_LOG" \
    || fail "no reopen-failure warning naming the path: $(cat "$ZIFT_LOG")"
n=$(grep -c '"operation":"auth.password","result":"ok"' "$AUDIT.1" || true)
(( n >= 2 )) || fail "old log should still receive lines after the failed reopen (got $n auth lines)"
ok "failed reopen keeps serving and keeps writing the old log"

# --- c) the retry picks up a reader --------------------------------------
cat "$AUDIT" >"$TEST_TMP/shipped.log" &
READER=$!
# The retry deadline is 5 s after the failure; a session after that
# carries the reopen.
sleep 5.5
sftp_password ally secret "ls" >"$TEST_TMP/c3.log" 2>&1 || fail "session 3 failed"
log_contains "audit log reopened" || fail "retry never reopened the FIFO: $(cat "$ZIFT_LOG")"
stop_zift TERM
exits_within "$ZIFT_PID" 100 || fail "server did not stop"
exits_within "$READER" 50 || { kill "$READER" 2>/dev/null; fail "reader never saw EOF"; }
grep -q '"operation":"auth.password","result":"ok"' "$TEST_TMP/shipped.log" \
    || fail "reader got no audit lines: $(cat "$TEST_TMP/shipped.log")"
ok "retry reopened onto the FIFO once a reader appeared"
