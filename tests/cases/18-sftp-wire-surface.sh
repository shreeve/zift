#!/usr/bin/env bash
# Test: SFTP protocol surface matches PLAN §7.6 — explicit OP_UNSUPPORTED
#       for SETSTAT/FSETSTAT/READLINK/SYMLINK/EXTENDED/unknown, FSTAT works
# Covers: PLAN §7.6 SFTP request surface table
# TODOS: P1 SFTP wire surface cluster (OP_UNSUPPORTED + FSTAT)

source "$(dirname "$0")/../lib/common.sh"

PROBE="$(dirname "$0")/../lib/probe_sftp_surface.py"
VENV="$(dirname "$0")/../.venv"
PY="$VENV/bin/python3"

if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing at $VENV"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)

mkdir -p "$TEST_TMP/jail/inbox"
echo "test-content" > "$TEST_TMP/jail/inbox/file.txt"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user user1
  auth $hash
  root $TEST_TMP/jail
  allow / read list
  allow /inbox read write list mkdir delete update rename
EOF

start_zift

set +e
"$PY" "$PROBE" \
    --host 127.0.0.1 --port "$TEST_PORT" \
    --user user1 --pass secret \
    --testfile /inbox/file.txt \
    > "$TEST_TMP/probe.out" 2>&1
rc=$?
set -e

echo "  probe results:"
sed 's/^/    /' "$TEST_TMP/probe.out"

stop_zift TERM

case "$rc" in
    0) ok "every scenario matched PLAN §7.6" ;;
    2) fail "at least one wire-surface scenario diverged from spec; see above" ;;
    *) fail "probe environment error (rc=$rc)" ;;
esac
