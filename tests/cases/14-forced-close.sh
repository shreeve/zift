#!/usr/bin/env bash
# Test: SIGTERM grace expiration force-closes remaining sessions
# After shutdown-grace the server itself must shut down each session's
# socket (the kernel reaping threads at exit is not enough), then exit 0.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
# idle-timeout 0 keeps the stuck pre-auth read alive past the grace.
basic_config "idle-timeout 0" "shutdown-grace 2s"
start_zift

# A client that reads the banner and never speaks SSH; it records
# whether its read ends in EOF (a FIN from the server) or an error.
python3 - "$TEST_PORT" "$TEST_TMP/stuck.out" >/dev/null 2>&1 <<'EOF' &
import socket, sys
out = open(sys.argv[2], "w", buffering=1)
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=20)
out.write(f"banner_len={len(s.recv(4096))}\n")
try:
    while s.recv(4096):
        pass
    out.write("eof\n")
except OSError as exc:
    out.write(f"error kind={type(exc).__name__}\n")
EOF
PIDS+=("$!")
wait_for_log banner_len 10 "$TEST_TMP/stuck.out" || fail "stuck client got no banner"

now_ms() { python3 -c 'import time; print(int(time.monotonic() * 1000))'; }
start_ms=$(now_ms)
kill -TERM "$ZIFT_PID"
wait_zift 6
exited_after_ms=$(($(now_ms) - start_ms))
[[ "$ZIFT_RC" == 0 ]] || fail "server exited $ZIFT_RC after force-close"
ok "server exited 0, ${exited_after_ms} ms after SIGTERM"

# Necessary but not sufficient: a no-op force-close would still print it.
grep -qE 'grace period expired, force-closing [1-9][0-9]* session' "$ZIFT_LOG" \
    || fail "no force-close log line with a positive count"
ok "server logged force-close with a positive session count"

# The worker's cleanup only runs if shutdown(fd) unblocked its libssh read.
log_contains '"operation":"handshake.failed"' \
    || fail "worker did not run cleanup; force-close did not unblock the read"
ok "worker's deferred cleanup ran (handshake.failed audit emitted)"

log_contains "all sessions drained after force-close, exiting" \
    || fail "active sessions did not reach zero after force-close: $(tail -3 "$ZIFT_LOG")"
ok "active_sessions reached zero after force-close"

# A smoke check: exit-time reaping also delivers a FIN.
wait_until 5 grep -qx eof "$TEST_TMP/stuck.out" \
    || fail "stuck client outcome: $(cat "$TEST_TMP/stuck.out")"
ok "stuck client received a clean EOF"

# 2 s grace + at most 500 ms post-shutdown wall, with slack.
((exited_after_ms <= 4500)) || fail "drain took ${exited_after_ms} ms"
ok "exit within grace + slack"
