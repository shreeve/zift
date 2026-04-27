#!/usr/bin/env bash
# Test: SIGHUP forces a config reload regardless of mtime
# Covers: PLAN §7.2 SIGHUP, §7.3 reload semantics
# TODOS: DONE (SIGHUP in operational signal cluster)

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

# Pin the config's mtime to a known instant so a SIGHUP-triggered reload
# can't be confused with the mtime watcher.
touch -t 200001010000 "$TEST_TMP/zift.conf"
sleep 1

before=$(grep -c "config reloaded" "$ZIFT_LOG" || true)
kill -HUP "$ZIFT_PID"
sleep 2
after=$(grep -c "config reloaded" "$ZIFT_LOG" || true)

[[ "$after" -gt "$before" ]] || fail "SIGHUP did not produce a 'config reloaded' line"
ok "SIGHUP forced reload (saw $((after - before)) new reload notice)"

stop_zift TERM
