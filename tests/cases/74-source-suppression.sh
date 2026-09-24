#!/usr/bin/env bash
# Test: 10 failed logins from one source suppress it, and a successful
#       login in between does not reset the count
# Built-in fail2ban: the session that trips the threshold is cut off and
# new connections from the source are refused. A partner's valid login
# behind the same NAT must not buy an attacker fresh guesses.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
basic_config
start_zift

"$PY" - <<'EOF'
import socket, threading, paramiko
from client import *

def wrong(i):
    """One wrong password on a fresh connection: 'denied' when the
    server answers and keeps the session, 'disconnected' when it hangs up
    (paramiko reports both as an AuthenticationException)."""
    t = paramiko.Transport(socket.create_connection(("127.0.0.1", PORT), timeout=15))
    try:
        t.start_client(timeout=15)
        t.auth_password("ally", f"wrong-{i}")
        fail(f"wrong password {i} logged in")
    except (paramiko.SSHException, EOFError):
        return "denied" if t.is_active() else "disconnected"
    finally:
        t.close()

# 8 at once (the per-source pre-auth cap), then one more: 9 failures.
results = []
threads = [threading.Thread(target=lambda i=i: results.append(wrong(i))) for i in range(8)]
for th in threads: th.start()
for th in threads: th.join()
results.append(wrong(8))
if results != ["denied"] * 9:
    fail(f"the first 9 failures got {results}")
if not can_login("ally", "secret"):
    fail("the source was suppressed after only 9 failures")
ok("9 failures, then a successful login")

# The 10th failure trips suppression despite the success; the session
# that recorded it is cut off instead of getting a failure reply.
if wrong(9) != "disconnected":
    fail("the 10th failure, after a success, did not trip suppression")
ok("the 10th failure (after the success) disconnected its session")

try:
    transport("ally", "secret").close()
    fail("a suppressed source logged in with the right password")
except (paramiko.SSHException, EOFError, OSError):
    pass
ok("a new connection from the suppressed source is refused, right password or not")
EOF

[[ $(count_log '"operation":"auth.password","result":"denied","detail":"bad password"') == 10 ]] \
    || fail "expected 10 bad-password audit lines"
log_contains '"operation":"auth.rejected","result":"denied","detail":"source suppressed"' \
    || fail "the tripping session's suppression was not audited"
log_contains '"operation":"accept.rejected","result":"denied","detail":"source suppressed"' \
    || fail "the refused connection was not audited: $(tail -3 "$ZIFT_LOG")"
[[ $(count_log '"operation":"auth.password","result":"ok"') == 1 ]] || fail "expected exactly one successful login"
ok "failures, the suppression and the refusal are audited"
