#!/usr/bin/env bash
# Test: one source holds at most 8 pre-auth connections; authenticated
#       sessions do not count; refusals are audited once per minute.
# Oracle: the 9th silent connection is closed without an SSH banner and
#         audited as "too many pre-auth connections from source"; two
#         logged-in sessions plus 8 silent ones are all admitted; 10
#         more refusals add no audit line; closing the silent sockets
#         frees the slots.

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
  max-connections 64
  max-unauth-connections 64
  log stderr

user ally
  auth $hash
  root $TEST_TMP
  allow / read list
EOF

start_zift

"$PY" - <<EOF || fail "per-source pre-auth cap misbehaved (see above)"
import paramiko, socket, sys, time

def banner(sock):
    sock.settimeout(3)
    try:
        return sock.recv(64).startswith(b"SSH-")
    except OSError:
        return False

def connect():
    return socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=5)

# Two logged-in sessions: their pre-auth slots are released at auth.
held = []
for _ in range(2):
    t = paramiko.Transport(connect())
    t.connect(username="ally", password="secret")
    held.append(t)

time.sleep(0.5)  # the server releases the slot just after it sends success
silent = [connect() for _ in range(8)]
if not all(banner(s) for s in silent):
    print("fail: one of 8 pre-auth connections was refused"); sys.exit(1)
print("ok: 2 authenticated + 8 pre-auth connections admitted")

for _ in range(11):
    if banner(connect()):
        print("fail: a 9th pre-auth connection was admitted"); sys.exit(1)
print("ok: further pre-auth connections refused")

for s in silent: s.close()
time.sleep(0.5)
if not banner(connect()):
    print("fail: slots not released after the silent sockets closed"); sys.exit(1)
print("ok: slots released")
for t in held: t.close()
EOF

n=$(grep -c '"operation":"accept.rejected","result":"denied","detail":"too many pre-auth connections from source"' "$ZIFT_LOG" || true)
[[ "$n" == "1" ]] || fail "expected exactly 1 rate-limited rejection line, got $n"
ok "11 refusals produced one audit line"

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
