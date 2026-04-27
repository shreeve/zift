#!/usr/bin/env bash
# Test: independent `max-unauth-connections` cap (PLAN §8.4).
# Covers: signals.unauth_sessions counter, accept-time cap, audit line
#         distinguishing total vs pre-auth rejections.
# Oracle: with `max-connections=8 max-unauth-connections=2`, the third
#         raw TCP client gets `accept.rejected` with detail
#         "max-unauth-connections reached" — NOT "max-connections" —
#         while the global pool still has 6 slots free for legitimate
#         partner traffic.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
hash=$(make_password_hash secret)

mkdir -p "$TEST_TMP/data"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  idle-timeout 30s
  max-connections 8
  max-unauth-connections 2
  shutdown-grace 2s
  log $TEST_TMP/audit.jsonl

user runner
  password $hash
  root $TEST_TMP/data
  allow / read list
EOF

start_zift

# Open two raw TCP sockets that never speak SSH. Each one occupies a
# pre-auth slot for the duration of `idle-timeout`. With
# max-unauth-connections=2, the third connection must be rejected at
# accept time even though the global pool has 6 free slots.
python3 - <<EOF >"$TEST_TMP/raw.log" 2>&1 &
import socket, time
# Hold two stuck slots open well past the third client's connect.
s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s1.connect(("127.0.0.1", $TEST_PORT))
s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s2.connect(("127.0.0.1", $TEST_PORT))
time.sleep(4)
s1.close(); s2.close()
EOF
RAW_PID=$!

# Give the two stuck connections time to land on the server side.
sleep 0.5

# Third connection should hit the pre-auth cap and produce an
# accept.rejected audit line with the new "max-unauth-connections"
# detail. We use a raw TCP probe (not sftp) so the rejection is at
# the accept-loop layer — sftp_password would also work but adds an
# extra layer of timing variance from libssh/expect.
python3 - <<EOF
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
s.connect(("127.0.0.1", $TEST_PORT))
# Server immediately ssh_disconnect()s us; the read may return some
# SSH version banner before EOF or just EOF, both are fine.
try:
    _ = s.recv(64)
except Exception:
    pass
s.close()
EOF

# Wait for the audit line to land.
sleep 0.5

wait "$RAW_PID" 2>/dev/null || true
stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true

# The audit log should contain the new pre-auth-cap rejection.
if grep -q '"operation":"accept.rejected","result":"denied","detail":"max-unauth-connections reached"' "$TEST_TMP/audit.jsonl"; then
    ok "third pre-auth connection rejected with 'max-unauth-connections reached'"
else
    fail "expected pre-auth-cap audit line; got:"
    sed 's/^/    /' "$TEST_TMP/audit.jsonl" >&2
fi

# Sanity: the global cap line should NOT appear because total is 3
# and `max-connections=8`. Without separate caps a buggy implementation
# might mis-attribute the rejection; this check discriminates that.
if grep -q '"detail":"max-connections reached"' "$TEST_TMP/audit.jsonl"; then
    fail "rejection attributed to max-connections (should be max-unauth)"
fi
ok "rejection correctly attributed to pre-auth cap, not global cap"
