#!/usr/bin/env bash
# Test: a client that keeps sending auth probes is still cut off at the
#       fixed 120 s login grace, although each probe restarts the idle
#       timer.
# Oracle: disconnect 115-135 s after connect, and an
#         `auth.rejected` "login grace expired" audit line.
# Slow (about 2 minutes): runs only with ZIFT_TEST_SLOW=1.

source "$(dirname "$0")/../lib/common.sh"

need_slow
need_paramiko

make_host_key
hash=$(make_password_hash secret)

mkdir -p "$TEST_TMP/root" # partner root; host key, config and log stay outside it
write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  idle-timeout 10s
  log stderr

user ally
  auth $hash
  root $TEST_TMP/root
  allow / read list
EOF

start_zift

elapsed=$("$PY" - <<EOF
import paramiko, socket, time
t0 = time.monotonic()
sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=30)
t = paramiko.Transport(sock)
t.start_client(timeout=30)
while time.monotonic() - t0 < 200:
    try:
        t.auth_none("ally")
    except paramiko.BadAuthenticationType:
        pass
    except Exception:
        break
    time.sleep(5)
print(int(time.monotonic() - t0))
EOF
)
echo "  disconnected after ${elapsed}s"
[[ "$elapsed" -ge 115 && "$elapsed" -le 135 ]] \
    || fail "expected a disconnect at the 120 s login grace, got ${elapsed}s"
ok "probing client cut off at the login grace"

log_contains '"operation":"auth.rejected","result":"denied","detail":"login grace expired"' \
    || fail "missing 'login grace expired' audit line"
ok "login grace expiry audited"

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
