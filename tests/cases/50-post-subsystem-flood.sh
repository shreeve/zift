#!/usr/bin/env bash
# Test: SSH requests after the sftp subsystem starts are refused and
#       freed, not queued: memory stays bounded and SFTP keeps working
# Oracle: RSS growth under an env/exec/pty-req/channel-open/tcpip-forward
#         flood stays small; want-reply requests are refused promptly

source "$(dirname "$0")/../lib/common.sh"

PROBE="$(dirname "$0")/../lib/probe_channel_flood.py"
PY="$(dirname "$0")/../.venv/bin/python3"
if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)
mkdir -p "$TEST_TMP/jail"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  idle-timeout 60s
  log stderr

user flood
  auth $hash
  root $TEST_TMP/jail
  allow / full
EOF

start_zift

set +e
"$PY" "$PROBE" --port "$TEST_PORT" --user flood --password secret --pid "$ZIFT_PID" \
    > "$TEST_TMP/probe.out" 2>&1
rc=$?
set -e
sed 's/^/    /' "$TEST_TMP/probe.out"

kill -0 "$ZIFT_PID" 2>/dev/null || fail "zift exited during the flood"

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true

case "$rc" in
    0) ok "flood refused with bounded memory" ;;
    2) fail "a flood check failed; see above" ;;
    *) fail "probe environment error (rc=$rc)" ;;
esac
