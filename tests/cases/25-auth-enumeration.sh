#!/usr/bin/env bash
# Test: a wrong password and an unknown user both get a full
#       `auth.password denied` line; only the unknown one says so
# The audit side of the timing-safe dummy hash (ssh.zig and its unit
# tests cover the timing): operators can grep for enumeration probes.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
AUDIT="$TEST_TMP/audit.jsonl"
basic_config "log $AUDIT"
start_zift

"$PY" - <<'EOF'
from client import *
for user, password in (("ally", "wrongpassword"), ("nonexistent", "anything")):
    if can_login(user, password):
        fail(f"{user} logged in with {password!r}")
EOF
stop_zift TERM

known='"user":"ally","operation":"auth.password","result":"denied"'
unknown='"user":"nonexistent","operation":"auth.password","result":"denied"'
(($(count_log "$known" "$AUDIT") >= 1)) || fail "no denied line for the known user"
ok "known user, bad password: denied line"
(($(count_log "$unknown" "$AUDIT") >= 1)) || fail "no denied line for the unknown user"
ok "unknown user: denied line"
log_contains "$unknown,\"detail\":\"unknown user\"" "$AUDIT" || fail "unknown-user line lacks the 'unknown user' detail"
ok "the unknown-user line carries 'unknown user'"
grep -q '"user":"ally".*"detail":"unknown user"' "$AUDIT" && fail "the known user's line says 'unknown user'"
ok "the known user's line does not"
