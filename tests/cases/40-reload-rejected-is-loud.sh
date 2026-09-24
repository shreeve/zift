#!/usr/bin/env bash
# Test: a rejected reload is loud (stderr and audit), keeps serving the
#       previous config, and the next good config announces recovery
# A mistyped verb must not silently leave the daemon on stale rules.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
hash=$(make_password_hash secret)
mkdir -p "$TEST_TMP/root" "$TEST_TMP/ally_root" "$TEST_TMP/late_root"
config() {
    write_config <<EOF
$(config_head "reload-interval 1s")

user ally
  auth $hash
  root $1
  allow / read $2
$3
EOF
    touch -t "$4" "$TEST_TMP/zift.conf"
}

config "$TEST_TMP/root" list "" 200001010000
start_zift

config "$TEST_TMP/root" lsit "" 200101010000
wait_for_log 'config reload rejected' 5 || fail "no 'config reload rejected' line: $(cat "$ZIFT_LOG")"
log_contains 'SERVING PREVIOUS CONFIG' || fail "no loud 'SERVING PREVIOUS CONFIG' framing"
ok "the rejected reload is logged loudly"
wait_for_log '"operation":"config.reload","result":"failed"' || fail "no config.reload failed audit event"
ok "the rejected reload is a config.reload audit event"
sftp_password ally secret >"$TEST_TMP/stale.log" 2>&1 || fail "the previous config stopped serving"
ok "the previous config still serves"

config "$TEST_TMP/ally_root" list "
user late
  auth $(make_password_hash later-secret)
  root $TEST_TMP/late_root
  allow / read list" 200201010000
wait_for_log 'config reload recovered' 5 || fail "no 'config reload recovered' line"
wait_for_log '"operation":"config.reload","result":"ok"' || fail "no config.reload ok audit event"
ok "recovery is announced on stderr and in the audit stream"
sftp_password late later-secret >"$TEST_TMP/late.log" 2>&1 || fail "user 'late' from the recovered config cannot log in"
ok "the recovered config applies to new sessions"
