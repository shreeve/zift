#!/usr/bin/env bash
# Test: an unset max-unauth-connections defaults to max-connections / 4,
#       and `from ::ffff:a.b.c.d` admits the same peer seen as IPv4
# Silent sockets must not hold every slot by default (explicit 0 still
# turns the cap off); an IPv4-mapped `from` must match a plain IPv4 peer.

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
stop_zift TERM

# from_config <from line>: user ally admitted only from there.
from_config() {
    write_config <<EOF
$(config_head)

user ally
  auth $(make_password_hash secret)
  root $TEST_TMP/root
  $1
  allow / read list
EOF
}
from_config "from ::ffff:127.0.0.1"
start_zift
"$PY" -c 'from client import *; import sys; sys.exit(0 if can_login("ally") else 1)' \
    || fail "from ::ffff:127.0.0.1 did not admit 127.0.0.1"
ok "from ::ffff:127.0.0.1 admits the peer 127.0.0.1"
stop_zift TERM

from_config "from ::ffff:10.9.8.7"
start_zift
"$PY" -c 'from client import *; import sys; sys.exit(1 if can_login("ally") else 0)' \
    || fail "from ::ffff:10.9.8.7 admitted 127.0.0.1"
ok "from ::ffff:10.9.8.7 still refuses 127.0.0.1"
