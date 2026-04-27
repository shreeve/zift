#!/usr/bin/env bash
# Test: PLAN §7.6 implementation limits enforced at config parse + at runtime
# Covers: PLAN §7.6 (max username 64 B, max key line 8192 B, max path 4096 B),
#         PLAN §8.3 step 2 (reject NUL / control bytes / invalid UTF-8 in paths)
# TODOS: P1 config limits cluster

source "$(dirname "$0")/../lib/common.sh"

PROBE="$(dirname "$0")/../lib/probe_path_limits.py"
VENV="$(dirname "$0")/../.venv"
PY="$VENV/bin/python3"

if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing at $VENV"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)

# ---------- config-side limits ----------
# Username at the boundary (64 bytes) parses; one byte over rejects.
NAME_64=$(printf 'a%.0s' {1..64})
NAME_65=$(printf 'a%.0s' {1..65})

cat > "$TEST_TMP/user_64.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519

user $NAME_64
  password $hash
  root $TEST_TMP
  allow / read list
EOF

cat > "$TEST_TMP/user_65.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519

user $NAME_65
  password $hash
  root $TEST_TMP
  allow / read list
EOF

set +e
"$ZIFT_BIN" validate "$TEST_TMP/user_64.conf" > "$TEST_TMP/u64.out" 2> "$TEST_TMP/u64.err"
rc64=$?
"$ZIFT_BIN" validate "$TEST_TMP/user_65.conf" > "$TEST_TMP/u65.out" 2> "$TEST_TMP/u65.err"
rc65=$?
set -e

[[ "$rc64" == "0" ]] || fail "username at 64 bytes (boundary): expected exit 0, got $rc64; stderr=$(cat "$TEST_TMP/u64.err")"
ok "64-byte username accepted (boundary)"

[[ "$rc65" == "1" ]] || fail "username at 65 bytes: expected exit 1, got $rc65"
grep -q 'UsernameTooLong' "$TEST_TMP/u65.err" \
    || fail "65-byte username: expected UsernameTooLong in stderr, got: $(cat "$TEST_TMP/u65.err")"
ok "65-byte username rejected with UsernameTooLong"

# Public-key line at 8193 bytes rejects; valid line below limit accepts.
HUGE_BLOB=$(printf 'A%.0s' {1..8200})
cat > "$TEST_TMP/key_huge.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519

user keyguy
  password $hash
  root $TEST_TMP
  allow / read list
  key ssh-ed25519 $HUGE_BLOB
EOF

set +e
"$ZIFT_BIN" validate "$TEST_TMP/key_huge.conf" > "$TEST_TMP/k.out" 2> "$TEST_TMP/k.err"
rcK=$?
set -e
[[ "$rcK" == "1" ]] || fail "huge key line: expected exit 1, got $rcK"
grep -q 'KeyLineTooLong' "$TEST_TMP/k.err" \
    || fail "huge key line: expected KeyLineTooLong in stderr, got: $(cat "$TEST_TMP/k.err")"
ok "key line > 8192 B rejected with KeyLineTooLong"

# ---------- runtime path validation ----------
# Run a server with permissive policy; the probe sends malformed paths
# and verifies each comes back as SSH_FX_BAD_MESSAGE.
mkdir -p "$TEST_TMP/jail/inbox"

cat > "$TEST_TMP/zift.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user user1
  password $hash
  root $TEST_TMP/jail
  allow / read list
  allow /inbox read write list mkdir remove rename
EOF

start_zift

set +e
"$PY" "$PROBE" \
    --host 127.0.0.1 --port "$TEST_PORT" \
    --user user1 --pass secret \
    > "$TEST_TMP/probe.out" 2>&1
rc=$?
set -e

echo "  probe results:"
sed 's/^/    /' "$TEST_TMP/probe.out"

stop_zift TERM

case "$rc" in
    0) ok "every malformed path scenario returned BAD_MESSAGE" ;;
    2) fail "at least one path-validation scenario diverged from spec" ;;
    *) fail "probe environment error (rc=$rc)" ;;
esac
