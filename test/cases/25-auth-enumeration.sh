#!/usr/bin/env bash
# Test: known-bad-password and unknown-user attempts both produce a
#       fully-formed `auth.password denied` audit line on the same path.
#       This is the *audit-side* observable for the timing-safe dummy
#       hash work — actual timing parity isn't asserted here because
#       wall-clock measurements are unreliable in CI; the parity is
#       enforced in `auth.zig` and exercised by the unit tests there.
# Covers: PLAN §8.4 audit symmetry for known vs unknown users.
# Oracle: a) both attempts produce a denied auth.password audit line;
#         b) both lines carry the username the client offered; c) the
#         unknown-user line carries the documented "unknown user" detail
#         so operators can grep for enumeration probes.

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

# Both attempts produce auth.password denied lines. The audit JSON
# field order is documented in audit.zig as event/user/operation/
# result/.../ip — the regex relies on that order being stable.
known_denied=$(grep -c '"user":"runner","operation":"auth.password","result":"denied"' "$TEST_TMP/audit.jsonl" 2>/dev/null || echo 0)
unknown_denied=$(grep -c '"user":"nonexistent","operation":"auth.password","result":"denied"' "$TEST_TMP/audit.jsonl" 2>/dev/null || echo 0)

[[ "$known_denied" -ge 1 ]] || fail "expected denied audit line for known user 'runner'"
ok "known user bad-password produces denied audit line"

[[ "$unknown_denied" -ge 1 ]] || fail "expected denied audit line for unknown user 'nonexistent'"
ok "unknown user produces denied audit line"

# Cross-reference: only the unknown-user line should carry the
# "unknown user" detail. This is the operator-facing signal that an
# enumeration probe is happening; without it, the symmetry of the
# audit lines would make probes invisible.
if grep -q '"user":"nonexistent","operation":"auth.password","result":"denied","detail":"unknown user"' "$TEST_TMP/audit.jsonl"; then
    ok "unknown-user audit line carries 'unknown user' detail"
else
    fail "expected 'unknown user' detail on unknown-user audit line"
fi
if grep -q '"user":"runner".*"detail":"unknown user"' "$TEST_TMP/audit.jsonl"; then
    fail "known user line should NOT carry 'unknown user' detail"
fi
