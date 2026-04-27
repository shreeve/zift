#!/usr/bin/env bash
# Test: per-handle access mode is enforced (write-only handle cannot READ)
# Covers: PLAN §6.3 ("read controls SSH_FXP_READ, write controls SSH_FXP_WRITE")
# TODOS: P0 per-handle access mode

source "$(dirname "$0")/../lib/common.sh"

PROBE="$(dirname "$0")/../lib/probe_handle_access.py"
VENV="$(dirname "$0")/../.venv"
PY="$VENV/bin/python3"

if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing at $VENV (run 'python3 -m venv test/.venv && test/.venv/bin/pip install paramiko')"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)

mkdir -p "$TEST_TMP/jail/inbox"
# Pre-place a "secret" file the drop-box user must NOT be able to read.
# Their config grants `write list` on /inbox, but NOT `read`.
echo "TOP-SECRET" > "$TEST_TMP/jail/inbox/secret.txt"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user drop
  password $hash
  root $TEST_TMP/jail
  allow /inbox write list
EOF

start_zift

# The probe opens /inbox/secret.txt with WRITE flag (no TRUNC), then issues
# a raw SSH_FXP_READ against the handle. PLAN §6.3 says READ must be denied
# because the user has no `read` permission on /inbox. The probe exits:
#     0  denial as expected (fix in place)
#     2  bypass (bug present)
#     3  test environment failure
set +e
"$PY" "$PROBE" \
    --host 127.0.0.1 --port "$TEST_PORT" \
    --user drop --pass secret \
    --path /inbox/secret.txt \
    > "$TEST_TMP/probe.out" 2>&1
rc=$?
set -e

echo "  probe: $(cat "$TEST_TMP/probe.out")"
case "$rc" in
    0) ok "READ on a WRITE-only handle was denied" ;;
    2) fail "bypass: server returned file content via a WRITE-only handle" ;;
    *) fail "probe environment error (rc=$rc); see $TEST_TMP/probe.out" ;;
esac

stop_zift TERM
