#!/usr/bin/env bash
# Test: SIGTERM grace expiration force-closes remaining sessions
# Covers: PLAN §7.1 ("any remaining sessions are forcibly closed and
#         the process exits zero")
# TODOS: P0 forced-close after grace doesn't actually force-close anything
#
# Without the fix, the drain loop simply returned after `shutdown_grace_ms`
# and the OS reaped the detached worker threads at process exit. The
# spec says the *server* must close the sessions, not the kernel. After
# the fix, the accept thread iterates a registry of session FDs and
# calls `shutdown(fd, SHUT_RDWR)` on each, observable as:
#
#   - "force-closing N session(s)" stderr line on the server
#   - the stuck client's TCP read returns 0 (EOF) — proving the FIN
#     came from the server, not from kernel-reap-on-exit (which would
#     deliver an RST on a Mac unless the socket linger is configured)
#
# Idle-timeout=0 keeps the stuck client's pre-auth read alive past the
# grace deadline so we can observe the force-close path.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
hash=$(make_password_hash secret)

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  idle-timeout 0
  shutdown-grace 2s
  log stderr

user ally
  auth $hash
  root $TEST_TMP
  allow / read list
EOF

start_zift

# Stuck client: open TCP, read whatever the server sends, never speak
# SSH back. Records when the read returns 0 (EOF, server-initiated FIN)
# vs when the connection breaks abnormally.
stuck_client() {
    python3 - "$TEST_PORT" "$TEST_TMP/stuck.out" <<'PY'
import os, socket, sys, time
port = int(sys.argv[1])
out = open(sys.argv[2], "w")
s = socket.create_connection(("127.0.0.1", port), timeout=30)
s.settimeout(20)
banner = s.recv(4096)
out.write(f"banner_len={len(banner)}\n")
out.flush()
start = time.monotonic()
try:
    while True:
        data = s.recv(4096)
        if not data:
            elapsed = time.monotonic() - start
            out.write(f"eof_after_ms={int(elapsed * 1000)}\n")
            break
except (socket.timeout, OSError) as exc:
    elapsed = time.monotonic() - start
    out.write(f"error_after_ms={int(elapsed * 1000)} kind={type(exc).__name__}\n")
out.flush()
out.close()
PY
}
bg stuck_client

# Let the stuck client land and the server observe it.
sleep 1

ZIFT_PID_LOCAL="$ZIFT_PID"
echo "  sending SIGTERM at t=0"
start_ms=$(python3 -c 'import time; print(int(time.monotonic()*1000))')
kill -TERM "$ZIFT_PID_LOCAL"

# Server should drain for ~2s then force-close. Wait up to 6s for
# the process to exit; record how long it took.
exited_after_ms=""
for _ in $(seq 1 60); do
    if ! kill -0 "$ZIFT_PID_LOCAL" 2>/dev/null; then
        now_ms=$(python3 -c 'import time; print(int(time.monotonic()*1000))')
        exited_after_ms=$((now_ms - start_ms))
        break
    fi
    sleep 0.1
done

[[ -n "$exited_after_ms" ]] || fail "server did not exit within 6 s after SIGTERM"
ok "server exited ${exited_after_ms} ms after SIGTERM"

wait_bg

# Oracle 1: server logged the force-close path with a non-zero count.
# A regression that no-ops `forceCloseAll` would still print this line,
# so it's necessary but not sufficient — the next two oracles do the
# real discrimination.
if grep -qE 'grace period expired, force-closing [1-9][0-9]* session' "$ZIFT_LOG"; then
    ok "server logged force-close with a positive session count"
else
    fail "no force-close log line; see $ZIFT_LOG"
fi

# Oracle 2: the worker's deferred cleanup ran, which only happens if the
# shutdown(fd) call actually unblocked the libssh read. Workers that
# get reaped via process-exit-only never reach the `handshake.failed`
# audit line. This is the strongest signal that force-close did real
# work, not just printed a banner.
if grep -q '"operation":"handshake.failed"' "$ZIFT_LOG"; then
    ok "worker's deferred cleanup ran (handshake.failed audit emitted)"
else
    fail "worker thread did not run cleanup; force-close did not actually unblock the libssh read"
fi

# Oracle 3: secondary drain wall after force-close went to zero. This
# requires the worker to decrement active_sessions before the 500 ms
# post-shutdown window expires. Without the shutdown(fd), the counter
# would still be non-zero and the server would log "still alive after
# force-close; exiting anyway" instead.
if grep -q "all sessions drained after force-close, exiting" "$ZIFT_LOG"; then
    ok "active_sessions reached zero after force-close (active server-side shutdown)"
elif grep -q "still alive after force-close" "$ZIFT_LOG"; then
    fail "force-close did not drain workers; counter still non-zero at exit"
else
    fail "no post-force-close drain status line in log"
fi

# Oracle 4: stuck client's read returned EOF rather than an error. Both
# the fixed and unfixed code happen to satisfy this (kernel-reap on
# process exit also delivers FIN), so this is a smoke check, not a
# discriminator.
if grep -q '^eof_after_ms=' "$TEST_TMP/stuck.out"; then
    ok "stuck client received clean EOF"
else
    fail "stuck client outcome was unexpected: $(cat "$TEST_TMP/stuck.out")"
fi

# Oracle 5: timing. Drain should fire shortly after the 2 s grace; the
# 500 ms post-shutdown wall adds at most 500 ms more. Allow generous
# shell+ssl handshake slack (4500 ms total).
if [[ "$exited_after_ms" -le 4500 ]]; then
    ok "exit happened within grace + slack (${exited_after_ms} ms)"
else
    fail "drain took longer than expected: ${exited_after_ms} ms"
fi
