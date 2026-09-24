#!/usr/bin/env bash
# Test: every audit line carries an `ip` field with the connecting IP
# Also the field order (time first, ip last) and the RFC 3339 millisecond
# UTC timestamp that log shippers parse.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
basic_config
start_zift

sftp_password ally secret >"$TEST_TMP/c1.log" 2>&1 || fail "login failed: $(cat "$TEST_TMP/c1.log")"
sftp_password ally wrong >"$TEST_TMP/c2.log" 2>&1 && fail "a wrong password logged in"
stop_zift TERM

total=$(count_log '"event":"zift.audit"')
((total >= 2)) || fail "expected at least 2 audit lines, got $total"
[[ $(count_log '"ip":"') == "$total" ]] || fail "an audit line has no ip field"
ok "every audit line carries an ip field ($total/$total)"
(($(count_log '"ip":"127.0.0.1"') >= 2)) || fail "expected ip=127.0.0.1"
ok "ip field carries the actual peer address (127.0.0.1)"

sample=$(grep '"operation":"auth.password"' "$ZIFT_LOG" | head -1)
[[ -n "$sample" ]] || fail "no auth.password line to inspect"
pos() { awk -v k="\"$1\"" '{print index($0, k)}' <<<"$sample"; }
[[ $(pos time) == 2 ]] || fail "time is not the first field: $sample"
(($(pos time) < $(pos event) && $(pos event) < $(pos operation) &&
  $(pos operation) < $(pos result) && $(pos result) < $(pos ip))) \
    || fail "field order is not time < event < operation < result < ip: $sample"
ok "field order: time(first) < event < operation < result < ip"

ts=$(grep -cE '"time":"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z"' "$ZIFT_LOG" || true)
[[ "$ts" == "$total" ]] || fail "RFC 3339 ms timestamp on only $ts/$total audit lines"
ok "every audit line carries an RFC 3339 UTC ms timestamp"
