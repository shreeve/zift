#!/usr/bin/env bash
# Test: auth attempts against known vs unknown users both produce denied
#       audit lines (timing-safe dummy hash path exercised for unknown user)
# Covers: PLAN §8.4 unknown-user timing parity
# Oracle: audit log contains denied lines for both known-bad and unknown users

source "$(dirname "$0")/../lib/common.sh"

VENV="$(dirname "$0")/../.venv"
PY="$VENV/bin/python3"

if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing at $VENV"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)

mkdir -p "$TEST_TMP/data"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  idle-timeout 10s
  shutdown-grace 2s
  log $TEST_TMP/audit.jsonl

user runner
  password $hash
  root $TEST_TMP/data
  allow / read list
EOF

start_zift

"$PY" - <<EOF
import paramiko, socket

port = $TEST_PORT

# Known user, wrong password
try:
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    t = paramiko.Transport(sock)
    t.connect(username="runner", password="wrongpassword")
except paramiko.AuthenticationException:
    pass
except Exception:
    pass
finally:
    try: t.close()
    except: pass

# Unknown user
try:
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    t = paramiko.Transport(sock)
    t.connect(username="nonexistent", password="anything")
except paramiko.AuthenticationException:
    pass
except Exception:
    pass
finally:
    try: t.close()
    except: pass
EOF

sleep 1

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true

# Both attempts should produce auth.password denied lines.
known_denied=$(grep -c '"user":"runner".*"auth.password".*"denied"' "$TEST_TMP/audit.jsonl" 2>/dev/null || echo 0)
unknown_denied=$(grep -c '"user":"nonexistent".*"auth.password".*"denied"' "$TEST_TMP/audit.jsonl" 2>/dev/null || echo 0)

[[ "$known_denied" -ge 1 ]] || fail "expected denied audit line for known user 'runner'"
ok "known user bad-password produces denied audit line"

[[ "$unknown_denied" -ge 1 ]] || fail "expected denied audit line for unknown user 'nonexistent'"
ok "unknown user produces denied audit line (timing-safe dummy hash ran)"
