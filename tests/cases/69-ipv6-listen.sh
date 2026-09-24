#!/usr/bin/env bash
# Test: `listen [::]:port` binds (brackets used to reach libssh's
#       resolver and fail), serves IPv6 clients, and on a dual-stack
#       socket audits an IPv4 client by its plain IPv4 address.
# Oracle: logins over ::1 and 127.0.0.1 both succeed, audited with ip
#         "0:0:0:0:0:0:0:1" and "127.0.0.1".
# Skips when the host has no IPv6 loopback.

source "$(dirname "$0")/../lib/common.sh"

VENV="$(dirname "$0")/../.venv"
PY="$VENV/bin/python3"

if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing at $VENV"
    exit 0
fi
if ! "$PY" -c "import socket; s = socket.socket(socket.AF_INET6); s.bind(('::1', 0))" 2>/dev/null; then
    echo "skip: no IPv6 loopback"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)

mkdir -p "$TEST_TMP/root" # partner root; host key, config and log stay outside it
write_config <<EOF
server
  listen [::]:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user ally
  auth $hash
  root $TEST_TMP/root
  allow / read list
EOF

start_zift

for host in ::1 127.0.0.1; do
    "$PY" - "$host" <<EOF || fail "login over $host failed"
import paramiko, socket, sys
t = paramiko.Transport(socket.create_connection((sys.argv[1], $TEST_PORT), timeout=10))
t.connect(username="ally", password="secret")
t.close()
EOF
done
ok "logins over ::1 and 127.0.0.1 succeeded"

log_contains '"operation":"auth.password","result":"ok","ip":"0:0:0:0:0:0:0:1"' \
    || fail "IPv6 login not audited with its address"
log_contains '"operation":"auth.password","result":"ok","ip":"127.0.0.1"' \
    || fail "IPv4 login on the dual-stack socket not audited as 127.0.0.1"
ok "audit ip fields are 0:0:0:0:0:0:0:1 and 127.0.0.1"

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
