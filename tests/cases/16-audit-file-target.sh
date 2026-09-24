#!/usr/bin/env bash
# Test: `log /absolute/path` routes audit lines to the file, not stderr
# The file holds whole JSON lines and is opened for append, so a restart
# never truncates the record.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
AUDIT="$TEST_TMP/audit.jsonl"
basic_config "log $AUDIT"

start_zift
sftp_password ally secret >"$TEST_TMP/c1.log" 2>&1 || fail "login failed: $(cat "$TEST_TMP/c1.log")"
stop_zift TERM

[[ -f "$AUDIT" ]] || fail "audit file was not created"
log_contains '"event":"zift.audit"' "$AUDIT" || fail "no zift.audit line in the file: $(cat "$AUDIT")"
log_contains '"operation":"auth.password","result":"ok"' "$AUDIT" || fail "auth.password ok line missing from the file"
ok "audit lines landed in the configured file"

log_contains '"event":"zift.audit"' && fail "audit JSON leaked to stderr"
ok "stderr is free of audit JSON"

while IFS= read -r line; do
    [[ "${line:0:1}" == "{" && "${line: -1}" == "}" ]] || fail "not a whole JSON line: $line"
done < "$AUDIT"
ok "every line in the audit file is JSON-shaped"

before=$(wc -l < "$AUDIT")
start_zift
sftp_password ally secret >"$TEST_TMP/c2.log" 2>&1 || fail "second login failed"
stop_zift TERM
after=$(wc -l < "$AUDIT")
((after > before)) || fail "second run did not append (before=$before after=$after)"
ok "a restart appends rather than truncates ($before -> $after lines)"
