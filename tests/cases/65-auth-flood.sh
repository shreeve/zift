#!/usr/bin/env bash
# Test: a flood of concurrent wrong-password logins stays within memory
#       and leaves stderr clean.
# Covers: the process-wide Argon2id slot limit (each run takes 64 MiB),
#         and session teardown reading libssh's error text before the
#         session is freed (it used to print freed heap bytes).
# Oracle: peak RSS under 1 GiB, the server still accepting, and every
#         stderr line valid UTF-8 with no control characters.

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

# Sample the server's RSS (KiB) until the flood is over.
( trap - EXIT
  while [[ ! -f "$TEST_TMP/flood.done" ]]; do
      ps -o rss= -p "$ZIFT_PID" 2>/dev/null >>"$TEST_TMP/rss.samples" || true
      sleep 0.05
  done ) &
SAMPLER=$!

"$PY" - <<EOF >"$TEST_TMP/flood.out" 2>&1 || true
import paramiko, socket, threading

def attempt(i):
    try:
        sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=30)
        t = paramiko.Transport(sock)
        t.start_client(timeout=30)
        t.auth_password("nobody-%d" % i, "wrong-%d" % i)
    except Exception as exc:
        print(i, type(exc).__name__)

threads = [threading.Thread(target=attempt, args=(i,)) for i in range(40)]
for t in threads: t.start()
for t in threads: t.join()
EOF
touch "$TEST_TMP/flood.done"
wait "$SAMPLER" 2>/dev/null || true

peak=$(sort -n "$TEST_TMP/rss.samples" | tail -1)
echo "  peak RSS: ${peak} KiB"
[[ -n "$peak" && "$peak" -lt 1048576 ]] || fail "peak RSS ${peak} KiB is not under 1 GiB"
ok "peak RSS under 1 GiB during the flood"

kill -0 "$ZIFT_PID" 2>/dev/null || fail "server died during the flood"
"$PY" -c "import socket; socket.create_connection(('127.0.0.1', $TEST_PORT), timeout=5).close()" \
    || fail "server no longer accepts connections"
ok "server still up and accepting"

"$PY" - "$ZIFT_LOG" <<'EOF' || fail "stderr has invalid UTF-8 or control bytes (freed memory?)"
import sys
data = open(sys.argv[1], "rb").read()
text = data.decode("utf-8")  # raises on invalid UTF-8
bad = [c for c in text if (ord(c) < 32 and c not in "\n\t") or ord(c) == 127]
sys.exit(1 if bad else 0)
EOF
ok "stderr is clean text"

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
