#!/usr/bin/env bash
# Test: a client that keeps sending auth probes is still cut off at the
#       fixed 120 s login grace, although each probe restarts the idle
#       timer
# Slow (about 2 minutes): runs only with ZIFT_TEST_SLOW=1.

source "$(dirname "$0")/../lib/common.sh"
need_slow
need_paramiko

make_host_key
basic_config "idle-timeout 10s"
start_zift

elapsed=$("$PY" - <<'EOF'
import socket, time, paramiko
from client import *
t0 = time.monotonic()
t = paramiko.Transport(socket.create_connection(("127.0.0.1", PORT), timeout=30))
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
[[ "$elapsed" -ge 115 && "$elapsed" -le 135 ]] || fail "expected a disconnect at the 120 s login grace, got ${elapsed}s"
ok "probing client cut off at the login grace"
log_contains '"operation":"auth.rejected","result":"denied","detail":"login grace expired"' \
    || fail "missing 'login grace expired' audit line"
ok "login grace expiry audited"
