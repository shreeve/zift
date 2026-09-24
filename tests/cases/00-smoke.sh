#!/usr/bin/env bash
# Test: server starts, logs "listening on", exits cleanly on SIGTERM
# The baseline every other case builds on.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
basic_config
start_zift
log_contains "listening on 127.0.0.1:$TEST_PORT" || fail "no listening line"
ok "server listening on $TEST_PORT"

kill -TERM "$ZIFT_PID"
wait_zift 3  # an idle server drains at once; the 15 s default would hide a slow exit
[[ "$ZIFT_RC" == 0 ]] || fail "server exited $ZIFT_RC on SIGTERM"
log_contains "shutdown signal received" || fail "no shutdown notice"
log_contains "all sessions drained" || fail "no drain confirmation"
ok "clean shutdown, exit 0"
