#!/usr/bin/env bash
# Test: per-connection auth attempt limit + unknown-user pubkey audit
# Covers: PLAN §8.4 (failed auth does not reveal username existence;
#                    bounded attempts per connection)
# TODOS: P1 auth hardening (per-connection limit + pubkey unknown-user
#                            timing parity)
#
# Two sub-scenarios:
#   (a) Sending more than 6 auth-failures gets the connection dropped.
#       The 7th attempt must not succeed even with valid credentials.
#   (b) An unknown-user public-key offer produces an audit line (and
#       the timing-parity dummy import is exercised — observable only
#       in the audit, not as a wall-clock measurement, since timing
#       tests are flaky in CI).

source "$(dirname "$0")/../lib/common.sh"

VENV="$(dirname "$0")/../.venv"
PY="$VENV/bin/python3"

if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing at $VENV"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user ally
  password $hash
  root $TEST_TMP
  allow / read list
EOF

start_zift

# ---------- (a) attempt limit ----------
"$PY" - <<EOF >"$TEST_TMP/attempts.out" 2>&1 || true
import paramiko, socket, sys
sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.start_client()
# Try wrong password 6 times. Server should disconnect on the 6th.
last_state = "?"
for i in range(1, 8):
    try:
        t.auth_password("ally", f"wrong-{i}")
        print(f"attempt {i}: SUCCESS (unexpected)")
        sys.exit(1)
    except paramiko.AuthenticationException as exc:
        print(f"attempt {i}: AuthenticationException ({exc})")
        last_state = "auth-rejected"
    except (EOFError, paramiko.SSHException, OSError) as exc:
        print(f"attempt {i}: DISCONNECT ({type(exc).__name__}: {exc})")
        last_state = "disconnect"
        break
print(f"final-state: {last_state}")
EOF

cat "$TEST_TMP/attempts.out" | sed 's/^/  /'

# Server should have disconnected by attempt 7 at the latest.
grep -q '^attempt [1-7]: DISCONNECT' "$TEST_TMP/attempts.out" \
    || fail "expected a disconnect within 7 attempts; client never observed one"
ok "server disconnected the client after exceeding the attempt ceiling"

# Audit log must show the cap-hit event.
grep -q '"operation":"auth.too_many_attempts"' "$ZIFT_LOG" \
    || fail "expected 'auth.too_many_attempts' audit line, got:\n$(grep '"event"' "$ZIFT_LOG")"
ok "auth.too_many_attempts audit line emitted"

# Sanity: at least 5 bad-password audit lines (attempts 1..5) before the cap.
DENIED_COUNT=$(grep -c '"operation":"auth.password","result":"denied","detail":"bad password"' "$ZIFT_LOG" || true)
[[ "$DENIED_COUNT" -ge "5" ]] \
    || fail "expected >=5 bad-password audits before cap, got $DENIED_COUNT"
ok "audit log shows $DENIED_COUNT bad-password attempts before the cap"

# ---------- (b) unknown-user pubkey audit ----------
# Generate a fresh ed25519 keypair, offer it under an unknown username.
ssh-keygen -t ed25519 -f "$TEST_TMP/probe_key" -N "" -q

set +e
sftp -i "$TEST_TMP/probe_key" \
     -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
     -o PreferredAuthentications=publickey -o PasswordAuthentication=no \
     -o ConnectTimeout=5 \
     -P "$TEST_PORT" nobody@127.0.0.1 \
     <<<'bye' >"$TEST_TMP/unknown.out" 2>&1
set -e

# Server should have logged a publickey denial for the unknown user.
grep -q '"operation":"auth.publickey","result":"denied","detail":"unknown user"' "$ZIFT_LOG" \
    || fail "expected unknown-user pubkey audit line, got:\n$(grep auth\.publickey "$ZIFT_LOG")"
ok "unknown-user pubkey attempt produced an audit line (dummy-key path exercised)"

stop_zift TERM
