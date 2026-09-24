#!/usr/bin/env bash
# Test: a flood of concurrent wrong-password logins stays within memory
#       and leaves stderr clean
# Each Argon2id run takes 64 MiB, so runs are capped process-wide; and
# teardown must read libssh's error text before freeing the session.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
basic_config "max-connections 64" "max-unauth-connections 64"
start_zift

sample_rss() {
    until [[ -e "$TEST_TMP/flood.done" ]]; do
        ps -o rss= -p "$ZIFT_PID" >>"$TEST_TMP/rss.samples" 2>/dev/null || true
        sleep 0.05
    done
}
bg sample_rss

"$PY" - <<'EOF' >"$TEST_TMP/flood.out" 2>&1 || true
import paramiko, socket, threading
from client import *
def attempt(i):
    try:
        t = paramiko.Transport(socket.create_connection(("127.0.0.1", PORT), timeout=30))
        t.start_client(timeout=30)
        t.auth_password("nobody-%d" % i, "wrong-%d" % i)
    except Exception as exc:
        print(i, type(exc).__name__)
threads = [threading.Thread(target=attempt, args=(i,)) for i in range(40)]
for t in threads: t.start()
for t in threads: t.join()
EOF
touch "$TEST_TMP/flood.done"
wait_bg

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
text = open(sys.argv[1], "rb").read().decode("utf-8")  # raises on invalid UTF-8
sys.exit(1 if any((ord(c) < 32 and c not in "\n\t") or ord(c) == 127 for c in text) else 0)
EOF
ok "stderr is clean text"
