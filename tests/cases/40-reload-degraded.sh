#!/usr/bin/env bash
# Test: reload divergence is LOUD, not silent (0.10.1).
#       A rejected reload must (a) keep serving the previous config,
#       (b) emit the `config reload rejected` + `SERVING PREVIOUS CONFIG`
#       diagnostic, (c) emit a structured `config.reload result=failed`
#       audit event, and (d) on the next good config, announce recovery
#       with a `config.reload result=ok` audit event and apply the new
#       rules. Reproduces the production incident (an inline `#` comment
#       on an `allow` line) that a reload silently rejected.
# Covers: 0.10.1 silent-reload hazard fix

source "$(dirname "$0")/../lib/common.sh"

make_host_key
hash=$(make_password_hash secret)
late_hash=$(make_password_hash later-secret)

# Distinct, non-overlapping roots (a user root may not contain another's).
mkdir -p "$TEST_TMP/ally_root" "$TEST_TMP/late_root"

# ---------- (a) start with a valid config ----------
cat > "$TEST_TMP/zift.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  reload-interval 1s
  log stderr

user ally
  auth $hash
  root $TEST_TMP
  allow / read list
EOF

start_zift
sleep 1

# ---------- (b) replace it with an INVALID config (inline comment) ----------
# This is the exact shape of the production incident: a trailing `#`
# comment on an `allow` line, which the parser rejects (InlineComment).
cat > "$TEST_TMP/zift.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  reload-interval 1s
  log stderr

user ally
  auth $hash
  root $TEST_TMP
  allow / read list  # this inline comment makes the config invalid
EOF
touch "$TEST_TMP/zift.conf"
sleep 2

# The rejection must be LOUD: both the back-compat substring and the new
# "serving previous config" framing.
grep -q 'config reload rejected' "$ZIFT_LOG" \
    || fail "expected 'config reload rejected' line, log:\n$(cat "$ZIFT_LOG")"
grep -q 'SERVING PREVIOUS CONFIG' "$ZIFT_LOG" \
    || fail "expected loud 'SERVING PREVIOUS CONFIG' framing, log:\n$(cat "$ZIFT_LOG")"
ok "rejected reload is logged loudly (serving previous config)"

# ...and it must land in the JSON audit stream operators monitor.
grep -q '"operation":"config.reload","result":"failed"' "$ZIFT_LOG" \
    || fail "expected a 'config.reload result=failed' audit event, log:\n$(cat "$ZIFT_LOG")"
ok "rejected reload emits a structured config.reload audit event"

# ---------- (c) the daemon must keep serving the PREVIOUS config ----------
expect <<EOF >"$TEST_TMP/auth_stale.log" 2>&1
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
grep -q "Connected to" "$TEST_TMP/auth_stale.log" \
    || fail "server stopped serving after rejected reload — must keep previous config"
ok "previous config still serves while degraded"

# ---------- (d) a subsequent GOOD config recovers and applies ----------
# Add a brand-new user `late` that did not exist before, to prove the
# recovered config is actually observable to new sessions.
cat > "$TEST_TMP/zift.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  reload-interval 1s
  log stderr

user ally
  auth $hash
  root $TEST_TMP/ally_root
  allow / read list

user late
  auth $late_hash
  root $TEST_TMP/late_root
  allow / read list
EOF
touch "$TEST_TMP/zift.conf"
sleep 2

grep -q 'config reload recovered' "$ZIFT_LOG" \
    || fail "expected 'config reload recovered' after a good config loaded, log:\n$(cat "$ZIFT_LOG")"
grep -q '"operation":"config.reload","result":"ok"' "$ZIFT_LOG" \
    || fail "expected a 'config.reload result=ok' recovery audit event, log:\n$(cat "$ZIFT_LOG")"
ok "recovery is announced loudly and in the audit stream"

# The recovered config must be live: `late` (new) can now authenticate.
expect <<EOF >"$TEST_TMP/auth_late.log" 2>&1
set timeout 10
spawn sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\
    -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 \\
    -P $TEST_PORT late@127.0.0.1
expect "password:"
send "later-secret\r"
expect "sftp>"
send "bye\r"
expect eof
EOF
grep -q "Connected to" "$TEST_TMP/auth_late.log" \
    || fail "recovered config not observable — new user 'late' could not authenticate"
ok "recovered config is applied to new sessions"

stop_zift TERM
