#!/usr/bin/env bash
# Test: per-connection auth attempt limit + unknown-user pubkey audit
# Six wrong passwords end the connection, so one connection cannot guess
# forever; a key offered for an unknown user is still audited.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
basic_config
start_zift

"$PY" - <<'EOF'
import paramiko, socket
from client import *
t = paramiko.Transport(socket.create_connection(("127.0.0.1", PORT), timeout=15))
t.start_client()
for i in range(1, 8):
    try:
        t.auth_password("ally", f"wrong-{i}")
        fail(f"attempt {i} with a wrong password succeeded")
    except paramiko.AuthenticationException:
        print(f"  attempt {i}: rejected")
    except (EOFError, paramiko.SSHException, OSError) as exc:
        ok(f"attempt {i}: disconnected ({type(exc).__name__})")
        break
else:
    fail("no disconnect within 7 attempts")
EOF

log_contains '"operation":"auth.too_many_attempts"' || fail "no auth.too_many_attempts audit line"
ok "auth.too_many_attempts audited"
denied=$(count_log '"operation":"auth.password","result":"denied","detail":"bad password"')
((denied >= 5)) || fail "expected >= 5 bad-password audit lines before the cap, got $denied"
ok "$denied bad-password attempts audited before the cap"

ssh-keygen -q -t ed25519 -N "" -f "$TEST_TMP/probe_key"
sftp -i "$TEST_TMP/probe_key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=publickey -o BatchMode=yes -o ConnectTimeout=5 \
    -P "$TEST_PORT" nobody@127.0.0.1 <<<'bye' >"$TEST_TMP/unknown.out" 2>&1 \
    && fail "an unknown user logged in"
log_contains '"operation":"auth.publickey","result":"denied","detail":"unknown user"' \
    || fail "no unknown-user publickey audit line: $(grep auth.publickey "$ZIFT_LOG")"
ok "unknown-user pubkey attempt audited"
