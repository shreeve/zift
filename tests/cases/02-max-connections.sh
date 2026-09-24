#!/usr/bin/env bash
# Test: max-connections refuses excess concurrent sessions with audit
# The global cap bounds what logged-in partners can hold at once.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
# Pre-auth cap off: this case is about max-connections alone.
basic_config "max-connections 2" "max-unauth-connections 0"
start_zift

bg sftp_password ally secret "@until $TEST_TMP/release" >"$TEST_TMP/a.log" 2>&1
bg sftp_password ally secret "@until $TEST_TMP/release" >"$TEST_TMP/b.log" 2>&1
wait_for_count '"operation":"auth.password","result":"ok"' 2 || fail "two sessions never logged in"

sftp_password ally secret >"$TEST_TMP/c.log" 2>&1 && fail "a third session was admitted"
wait_for_log '"operation":"accept.rejected","result":"denied"' || fail "no accept denial audited"
ok "excess connection denied with audit"

touch "$TEST_TMP/release"
wait_bg || fail "a held session did not finish cleanly"
[[ $(count_log '"operation":"auth.password","result":"ok"') == 2 ]] \
    || fail "expected exactly 2 successful auths"
ok "exactly two sessions admitted, and both finished"
