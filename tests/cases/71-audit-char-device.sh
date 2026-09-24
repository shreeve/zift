#!/usr/bin/env bash
# Test: `log /dev/null` (a character device) is an accepted audit sink
# Oracle: the server starts, serves a session, and /dev/null keeps its mode.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
mode_of() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }
before=$(mode_of /dev/null)
basic_config "log /dev/null"
start_zift

sftp_password ally secret "ls" >"$TEST_TMP/client.log" 2>&1 || fail "session failed with log /dev/null"
ok "server with log /dev/null serves a session"
log_contains '"event":"zift.audit"' && fail "audit JSON went to stderr instead of /dev/null"
[[ "$(mode_of /dev/null)" == "$before" ]] || fail "/dev/null mode changed from $before"
ok "audit lines went to the device and its mode is untouched"
