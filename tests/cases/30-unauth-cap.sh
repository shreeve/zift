#!/usr/bin/env bash
# Test: `max-unauth-connections` caps pre-auth sessions on its own
# The cap fires with its own audit detail, frees a slot when a pre-auth
# session ends, and counts pre-auth sessions only, not logged-in ones.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
AUDIT="$TEST_TMP/audit.jsonl"
mkdir -p "$TEST_TMP/data"
write_config <<EOF
$(config_head "idle-timeout 30s" "max-connections 8" "max-unauth-connections 2" "log $AUDIT")

user runner
  auth $(user_key)
  root $TEST_TMP/data
  allow / read write list mkdir
EOF
start_zift

# `hold <n> <marker>`: n raw sockets that take the banner and never speak
# SSH, held until $TEST_TMP/release appears.
hold() {
    "$PY" - "$@" <<'EOF'
import os, socket, sys, time
from client import *
held = [socket.create_connection(("127.0.0.1", PORT), timeout=5) for _ in range(int(sys.argv[1]))]
if not all(s.recv(64).startswith(b"SSH-") for s in held):
    fail("a held connection got no banner")
open(sys.argv[2], "w").close()
while not os.path.exists(os.path.join(TMP, "release")):
    time.sleep(0.05)
EOF
}
# `probe`: 0 when a fresh connection is admitted (gets a banner).
probe() {
    "$PY" - <<'EOF'
import socket, sys
from client import *
s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
try:
    sys.exit(0 if s.recv(64).startswith(b"SSH-") else 1)
except OSError:
    sys.exit(1)
EOF
}

# ---------- the cap fires, attributed to the pre-auth cap ----------
bg hold 2 "$TEST_TMP/held"
wait_for_file "$TEST_TMP/held" || fail "two pre-auth connections were not admitted"
probe && fail "a third pre-auth connection was admitted"
wait_for_log '"operation":"accept.rejected","result":"denied","detail":"max-unauth-connections reached"' 5 "$AUDIT" \
    || fail "no 'max-unauth-connections reached' audit line: $(cat "$AUDIT")"
log_contains '"detail":"max-connections reached"' "$AUDIT" && fail "rejection attributed to max-connections"
ok "the third pre-auth connection was refused by the pre-auth cap, not the global cap"

# ---------- a pre-auth slot is released when its session ends ----------
touch "$TEST_TMP/release"
wait_bg || fail "holder errored"
wait_for_count '"operation":"handshake.failed"' 2 10 "$AUDIT" || fail "held sessions never ended"
# The slot is released just after that audit line; a leaked slot would
# refuse every retry.
wait_until 5 probe || fail "fresh connections stay refused after the held ones closed: unauth_sessions leaked"
ok "a fresh connection is admitted once the held ones close"

# ---------- logged-in sessions do not count against the cap ----------
# `session <i> [hold]`: log in and write file_<i>.txt; with `hold`, stay
# logged in until $TEST_TMP/done appears.
session() {
    "$PY" - "$@" <<'EOF'
import os, sys, time
from client import *
i = sys.argv[1]
sftp = connect("runner")
with sftp.open(f"/file_{i}.txt", "w") as f:
    f.write(f"session-{i}".encode())
open(os.path.join(TMP, f"auth_ok_{i}"), "w").close()
while len(sys.argv) > 2 and not os.path.exists(os.path.join(TMP, "done")):
    time.sleep(0.05)
EOF
}
bg session 0 hold
wait_for_file "$TEST_TMP/auth_ok_0" || fail "session 0 never logged in"
bg session 1 hold
wait_for_file "$TEST_TMP/auth_ok_1" || fail "session 1 never logged in"
# Two logged-in sessions, zero pre-auth: a cap keyed on all sessions
# would now refuse (2 >= 2).
session 2 || fail "a third session was refused while two logged-in sessions were open"
touch "$TEST_TMP/done"
wait_bg || fail "a held session errored"
for i in 0 1 2; do
    [[ "$(cat "$TEST_TMP/data/file_$i.txt")" == "session-$i" ]] || fail "file_$i.txt missing or wrong"
done
ok "three sessions logged in and wrote while the cap was 2"
