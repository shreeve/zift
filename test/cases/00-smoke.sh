#!/usr/bin/env bash
# Test: server starts, logs "listening on", exits cleanly on SIGTERM
# Covers: PLAN §7.1 graceful shutdown, baseline startup
# TODOS: DONE (operational signal cluster)

source "$(dirname "$0")/../lib/common.sh"

make_host_key
hash=$(make_password_hash secret)

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user runner
  password $hash
  root $TEST_TMP
  allow / read list
EOF

start_zift
log_contains "listening on 127.0.0.1:$TEST_PORT" || fail "no listening line"
ok "server listening on $TEST_PORT"

stop_zift TERM
for _ in 1 2 3 4 5; do
    kill -0 "$ZIFT_PID" 2>/dev/null || break
    sleep 0.5
done
kill -0 "$ZIFT_PID" 2>/dev/null && fail "server did not exit on SIGTERM"
log_contains "shutdown signal received" || fail "no shutdown notice"
log_contains "all sessions drained" || fail "no drain confirmation"
ok "clean shutdown"
