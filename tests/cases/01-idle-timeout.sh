#!/usr/bin/env bash
# Test: idle-timeout disconnects an authenticated client past the deadline
# A logged-in partner who goes quiet must not hold a session forever.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
basic_config "idle-timeout 1s"
start_zift

sftp_password ally secret "@eof" >"$TEST_TMP/client.log" 2>&1 \
    || fail "client was not disconnected: $(cat "$TEST_TMP/client.log")"
grep -q 'Received disconnect' "$TEST_TMP/client.log" || fail "client saw no SSH disconnect"
ok "client received disconnect"

wait_for_log '"operation":"session.ended","result":"ok","detail":"idle timeout' \
    || fail "no idle timeout audit line"
ok "idle timeout audited"
