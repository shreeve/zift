#!/usr/bin/env bash
# Test: an unset max-unauth-connections defaults to max-connections / 4,
#       and an explicit 0 turns the pre-auth cap off
# Silent sockets must not be able to hold every slot by default.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
AUDIT="$TEST_TMP/audit.jsonl"

# third_admitted: hold two silent pre-auth sockets, then report whether a
# third one gets the SSH banner.
third_admitted() {
    "$PY" - <<'EOF'
import socket, sys
from client import *
def banner(s):
    try:
        return s.recv(64).startswith(b"SSH-")
    except OSError:
        return False
held = [socket.create_connection(("127.0.0.1", PORT), timeout=3) for _ in range(2)]
if not all(banner(s) for s in held):
    fail("one of the two held connections was refused")
sys.exit(0 if banner(socket.create_connection(("127.0.0.1", PORT), timeout=3)) else 1)
EOF
}
cap_line='"operation":"accept.rejected","result":"denied","detail":"max-unauth-connections reached"'

basic_config "max-connections 8" "log $AUDIT"
start_zift
third_admitted && fail "default cap: a third silent connection was admitted"
wait_for_log "$cap_line" 5 "$AUDIT" || fail "default cap: no refusal audited"
ok "unset max-unauth-connections caps pre-auth sessions at max-connections / 4"
stop_zift TERM

: > "$AUDIT"
basic_config "max-connections 8" "max-unauth-connections 0" "log $AUDIT"
start_zift
third_admitted || fail "explicit 0: a third silent connection was refused"
log_contains '"operation":"accept.rejected"' "$AUDIT" && fail "explicit 0: a connection was refused"
ok "explicit max-unauth-connections 0 means no separate cap"
