#!/usr/bin/env bash
# Test: PLAN §7.3 reload semantics — interval cadence, forward-only mtime,
#       stat-failure warnings, host-key check on reload
# Covers: PLAN §7.3 (auto-reload semantics)
# TODOS: P1 reload semantics cluster (4 items)

source "$(dirname "$0")/../lib/common.sh"

make_host_key
hash=$(make_password_hash secret)

# ---------- (a) reload-interval honored; mtime-forward triggers reload ----------
cat > "$TEST_TMP/zift.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  reload-interval 1s
  log stderr

user ally
  password $hash
  root $TEST_TMP
  allow / read list
EOF

start_zift
sleep 1

# Touch the config to bump mtime forward. The 1-second reload interval
# should pick up the change within ~2 seconds.
sleep 1
touch "$TEST_TMP/zift.conf"
sleep 2

grep -q 'config reloaded' "$ZIFT_LOG" \
    || fail "expected forward-mtime change to trigger reload, log:\n$(cat "$ZIFT_LOG")"
ok "forward-mtime change triggered a reload within the interval"

# ---------- (b) rewinding mtime does NOT trigger reload ----------
RELOADS_BEFORE=$(grep -c 'config reloaded' "$ZIFT_LOG" || true)
touch -t 200001010000 "$TEST_TMP/zift.conf"
sleep 2
RELOADS_AFTER=$(grep -c 'config reloaded' "$ZIFT_LOG" || true)
[[ "$RELOADS_AFTER" == "$RELOADS_BEFORE" ]] \
    || fail "rewinding mtime should not trigger reload (before=$RELOADS_BEFORE after=$RELOADS_AFTER)"
ok "rewinding mtime did NOT trigger reload (forward-only honored)"

# ---------- (c) stat failure logs once, recovery logs once ----------
# Move the file out of the way (server can't stat it), wait for the
# warning, then move it back and observe the recovery line.
mv "$TEST_TMP/zift.conf" "$TEST_TMP/zift.conf.hidden"
sleep 2

WARN_COUNT=$(grep -c 'cannot stat config file' "$ZIFT_LOG" || true)
[[ "$WARN_COUNT" == "1" ]] \
    || fail "expected exactly 1 'cannot stat config file' warning, got $WARN_COUNT"
ok "exactly one stat-failure warning emitted"

mv "$TEST_TMP/zift.conf.hidden" "$TEST_TMP/zift.conf"
# Bump mtime so reloadIfChanged actually does something on recovery.
touch "$TEST_TMP/zift.conf"
sleep 2

grep -q 'config file readable again' "$ZIFT_LOG" \
    || fail "expected 'config file readable again' on recovery, log:\n$(grep -E 'config|stat' "$ZIFT_LOG")"
ok "recovery message emitted when file became readable again"

stop_zift TERM

# ---------- (d) reload-interval=0 disables mtime polling ----------
# Use a different port so we don't race with the previous instance's
# socket still being in TIME_WAIT.
DISABLED_PORT=$((TEST_PORT + 100))
cat > "$TEST_TMP/zift_disabled.conf" <<EOF
server
  listen 127.0.0.1:$DISABLED_PORT
  host-key $TEST_TMP/host_ed25519
  reload-interval 0
  log stderr

user ally
  password $hash
  root $TEST_TMP
  allow / read list
EOF

# Start a second instance with reload polling disabled.
"$ZIFT_BIN" serve "$TEST_TMP/zift_disabled.conf" >"$TEST_TMP/disabled.log" 2>&1 &
DISABLED_PID=$!
disown
for _ in 1 2 3 4 5; do
    grep -q 'listening on' "$TEST_TMP/disabled.log" 2>/dev/null && break
    sleep 0.5
done

# Forward-bump mtime; with interval=0 there should be NO reload.
sleep 1
touch "$TEST_TMP/zift_disabled.conf"
sleep 3
grep -q 'config reloaded' "$TEST_TMP/disabled.log" \
    && fail "reload-interval=0 should disable mtime polling, but a reload happened"
ok "reload-interval=0 suppresses mtime-driven reload"

# SIGHUP must still trigger a reload even with interval=0.
DISABLED_BIN_PID=$(pgrep -x zift | head -1)
[[ -n "$DISABLED_BIN_PID" ]] || fail "could not find disabled zift binary pid"
kill -HUP "$DISABLED_BIN_PID"
sleep 2
grep -q 'config reloaded' "$TEST_TMP/disabled.log" \
    || fail "SIGHUP should reload even when interval=0, log:\n$(cat "$TEST_TMP/disabled.log")"
ok "SIGHUP still forces reload when reload-interval=0"

kill -TERM "$DISABLED_BIN_PID" 2>/dev/null || true
wait "$DISABLED_PID" 2>/dev/null || true

# ---------- (e) reload rejects a config with an unreadable host-key ----------
cat > "$TEST_TMP/zift.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  reload-interval 1s
  log stderr

user ally
  password $hash
  root $TEST_TMP
  allow / read list
EOF

start_zift
sleep 1

# Replace the running config with one pointing at a non-existent
# host-key path. The reload pass must reject it (validateSemantic
# fails on host-key readability) and keep the previous config.
cat > "$TEST_TMP/zift.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/missing-host-key
  reload-interval 1s
  log stderr

user ally
  password $hash
  root $TEST_TMP
  allow / read list
EOF
touch "$TEST_TMP/zift.conf"
sleep 2

grep -q 'host-key unreadable' "$ZIFT_LOG" \
    || fail "expected 'host-key unreadable' diagnostic on reload, log:\n$(cat "$ZIFT_LOG")"
ok "reload rejected a config with an unreadable host-key"

grep -q 'config reload rejected' "$ZIFT_LOG" \
    || fail "expected 'config reload rejected' line, log:\n$(cat "$ZIFT_LOG")"
ok "reload-rejected diagnostic emitted (kept previous config)"

# Sanity: server is still serving with the OLD config — auth still works.
expect <<EOF >"$TEST_TMP/auth.log" 2>&1
set timeout 10
spawn sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\
    -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 \\
    -P $TEST_PORT ally@127.0.0.1
expect "password:"
send "secret\r"
expect "sftp>"
send "bye\r"
expect eof
EOF
grep -q "Connected to" "$TEST_TMP/auth.log" \
    || fail "server stopped serving after rejected reload — should keep previous config"
ok "previous config still serves after rejected reload"

stop_zift TERM
