#!/usr/bin/env bash
# Test: `log /dev/null` (a character device) is an accepted audit sink
# Covers: audit.zig openLogFile accepts S_IFCHR and leaves its mode alone.
# Oracle: the server starts, serves a session, and /dev/null keeps its mode.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
hash=$(make_password_hash secret)
mkdir -p "$TEST_TMP/data"

mode_of() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }
before=$(mode_of /dev/null)

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log /dev/null

user ally
  auth $hash
  root $TEST_TMP/data
  allow / read list
EOF

start_zift
sftp_password ally secret "ls" >"$TEST_TMP/client.log" 2>&1 \
    || fail "session failed with log /dev/null"
ok "server with log /dev/null serves a session"

if grep -q '"event":"zift.audit"' "$ZIFT_LOG"; then
    fail "audit JSON went to stderr instead of /dev/null"
fi
[[ "$(mode_of /dev/null)" == "$before" ]] || fail "/dev/null mode changed from $before"
ok "audit lines went to the device and its mode is untouched"
