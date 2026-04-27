#!/usr/bin/env bash
# Test: independent `max-unauth-connections` cap (PLAN §8.4).
# Covers: signals.unauth_sessions counter, accept-time cap, audit line
#         distinguishing total vs pre-auth rejections, decrement on
#         successful auth, decrement on session exit before auth.
#
# Three sabotage-discriminating phases:
#
#   Phase 1: pre-auth cap fires.
#     `max-unauth=2` with 2 stuck raw TCP clients; the 3rd is rejected
#     with `detail="max-unauth-connections reached"` (NOT `max-
#     connections reached` — a buggy implementation that mis-attributes
#     the rejection still emits an audit line, just with the wrong
#     detail).
#
#   Phase 2: pre-auth slot is RELEASED on session exit.
#     After the stuck clients drop, a fresh raw connection is admitted.
#     A buggy implementation that increments `unauth_sessions` but
#     never decrements would leave the counter pinned at 2 forever and
#     the fresh connection would also get rejected.
#
#   Phase 3: cap is checked against `unauth_sessions`, not `active_sessions`.
#     With `max-unauth=2`, three concurrent AUTHENTICATED sftp sessions
#     are opened. All three must succeed: each one starts as pre-auth
#     (unauth_sessions: 0→1→2→1→2→1 across the auth sequence) and the
#     slot is released at successful auth. A buggy implementation that
#     checks `active_sessions >= max_unauth_connections` would reject
#     the third session (active=2 >= max-unauth=2) even though the
#     unauth slot is free.

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
  idle-timeout 3s
  max-connections 8
  max-unauth-connections 2
  shutdown-grace 2s
  log $TEST_TMP/audit.jsonl

user runner
  password $hash
  root $TEST_TMP/data
  allow / read write list mkdir
EOF

start_zift

# Helper: poll the audit log for a specific JSON pattern, up to N
# attempts at 200ms intervals. Returns 0 when found, 1 on timeout.
poll_audit() {
    local pattern="$1"
    local max_attempts="${2:-25}"  # 5 seconds default
    local i=0
    while [[ $i -lt $max_attempts ]]; do
        if grep -q "$pattern" "$TEST_TMP/audit.jsonl" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
        i=$((i + 1))
    done
    return 1
}

# ============================================================
# Phase 1: pre-auth cap fires with the right audit detail.
# ============================================================

# Two raw TCP sockets that never speak SSH. Each occupies a pre-auth
# slot until they close. We write the python source to a file because
# `bg` runs the command in a backgrounded subshell and bash redirects
# its stdin to /dev/null — heredocs do not survive that.
cat > "$TEST_TMP/stuck.py" <<EOF
import socket, time
sock_a = socket.socket(); sock_a.connect(("127.0.0.1", $TEST_PORT))
sock_b = socket.socket(); sock_b.connect(("127.0.0.1", $TEST_PORT))
time.sleep(2.5)
sock_a.close(); sock_b.close()
EOF
bg "$PY" "$TEST_TMP/stuck.py" >"$TEST_TMP/raw1.log" 2>&1
# bash 3.2 (macOS default) lacks negative array subscripts; index by
# computed length instead.
RAW_PID="${BG_PIDS[$((${#BG_PIDS[@]} - 1))]}"

# Wait for both stuck connections to be visible to the server. Using
# a deterministic poll of zift's stderr ("listening on" appeared at
# start_zift; we're past that). The 0.6s settle window allows accept
# loop to process two connect() events on a slow CI runner.
sleep 0.6

# Third raw probe must be rejected with the new pre-auth audit line.
"$PY" - <<EOF >/dev/null 2>&1
import socket
s = socket.socket()
s.settimeout(2)
s.connect(("127.0.0.1", $TEST_PORT))
try: s.recv(64)
except Exception: pass
s.close()
EOF

if poll_audit '"operation":"accept.rejected","result":"denied","detail":"max-unauth-connections reached"'; then
    ok "phase 1: third pre-auth connection rejected with 'max-unauth-connections reached'"
else
    fail "phase 1: expected 'max-unauth-connections reached' audit line; got:"
    sed 's/^/    /' "$TEST_TMP/audit.jsonl" >&2
fi

# Sanity: the global cap line should NOT appear (only 3 in flight,
# global cap is 8). A buggy implementation that mis-attributes the
# rejection to the global cap fails this check.
if grep -q '"detail":"max-connections reached"' "$TEST_TMP/audit.jsonl"; then
    fail "phase 1: rejection attributed to max-connections (should be max-unauth)"
fi
ok "phase 1: rejection correctly attributed to pre-auth cap, not global cap"

# ============================================================
# Phase 2: pre-auth slot is released on session exit.
# ============================================================

# Wait for the stuck Python connections to drop by idle-timeout (3s)
# or python's own sleep ending (2.5s + close).
wait "$RAW_PID" 2>/dev/null || true
sleep 1  # ensure server-side teardowns finished and decremented

# A fresh raw connection should now be ADMITTED (no rejection).
# Snapshot the current rejection count so we can prove no NEW rejection
# happens during this phase.
rej_before=$(grep -c '"operation":"accept.rejected"' "$TEST_TMP/audit.jsonl" 2>/dev/null || echo 0)

"$PY" - <<EOF
import socket, time
s = socket.socket()
s.settimeout(2)
s.connect(("127.0.0.1", $TEST_PORT))
time.sleep(0.3)
s.close()
EOF

# Allow the server to process this connection's lifecycle (it'll hit
# idle-timeout, but the question we care about is "was it rejected at
# accept time"). 0.5s is enough to see an accept-time rejection if it
# would have happened.
sleep 0.5
rej_after=$(grep -c '"operation":"accept.rejected"' "$TEST_TMP/audit.jsonl" 2>/dev/null || echo 0)

if [[ "$rej_before" == "$rej_after" ]]; then
    ok "phase 2: post-drop fresh connection accepted (unauth_sessions decremented)"
else
    fail "phase 2: fresh connection rejected after stuck slots dropped — leak in unauth_sessions"
    grep '"operation":"accept.rejected"' "$TEST_TMP/audit.jsonl" | tail -3 | sed 's/^/    /'
fi

# ============================================================
# Phase 3: cap is checked against unauth_sessions, not active_sessions.
# ============================================================
#
# The discriminator: with `max-unauth-connections=2` and two already-
# authenticated sessions held open (active_sessions=2, unauth=0), a
# fresh sftp client must STILL connect — the new connection's accept-
# time check should see `unauth_sessions=0 < 2` and admit. A buggy
# impl that compared `active_sessions` instead would see `2 >= 2` and
# reject before the new client could even start the handshake.
#
# We build the prerequisite serially (open 1, wait for auth, open 2,
# wait for auth, then probe 3) so the test does not race itself: with
# max-unauth=2 a true parallel triple-arrival will always reject the
# third at accept time, regardless of which counter is checked.

cat > "$TEST_TMP/phase3_holder.py" <<EOF
import paramiko, socket, sys, time, os
sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="runner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)
idx = sys.argv[1]
with sftp.open(f"/file_{idx}.txt", "w") as f:
    f.write(f"session-{idx}".encode())
# Touch a sentinel file so the test runner knows auth completed and
# the session is in the post-auth (active, but not unauth) state.
open(f"$TEST_TMP/auth_ok_{idx}", "w").close()
# Hold the session open until the parent removes the keepalive file.
while os.path.exists(f"$TEST_TMP/keepalive"):
    time.sleep(0.1)
sftp.close(); t.close()
EOF

touch "$TEST_TMP/keepalive"

# Open and authenticate session 0, wait for the sentinel that proves
# it's reached post-auth (so unauth_sessions has decremented).
bg "$PY" "$TEST_TMP/phase3_holder.py" 0 >"$TEST_TMP/p3_0.log" 2>&1
HOLDER_0_PID="${BG_PIDS[$((${#BG_PIDS[@]} - 1))]}"
poll_for_file() {
    local path="$1"
    local i=0
    while [[ $i -lt 50 ]]; do
        [[ -f "$path" ]] && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
poll_for_file "$TEST_TMP/auth_ok_0" || fail "phase 3: holder 0 never reached post-auth"

# Same for session 1.
bg "$PY" "$TEST_TMP/phase3_holder.py" 1 >"$TEST_TMP/p3_1.log" 2>&1
HOLDER_1_PID="${BG_PIDS[$((${#BG_PIDS[@]} - 1))]}"
poll_for_file "$TEST_TMP/auth_ok_1" || fail "phase 3: holder 1 never reached post-auth"

# At this moment: active_sessions=2, unauth_sessions=0. With
# max-unauth=2 a buggy impl checking active_sessions would already
# reject the next accept (2 >= 2). Probe with a real sftp client.
"$PY" - <<EOF || fail "phase 3: third session rejected — cap is mis-keyed against active_sessions"
import paramiko, socket
sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="runner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)
with sftp.open("/file_2.txt", "w") as f:
    f.write(b"session-2")
sftp.close(); t.close()
EOF
ok "phase 3: third sftp session admitted while two prior sessions held active"

# Release the holders so cleanup runs cleanly.
rm -f "$TEST_TMP/keepalive"
wait "$HOLDER_0_PID" 2>/dev/null || true
wait "$HOLDER_1_PID" 2>/dev/null || true

# Sanity: the three files must all exist on disk.
for i in 0 1 2; do
    [[ -f "$TEST_TMP/data/file_$i.txt" ]] \
        || fail "phase 3: file_$i.txt missing — session never reached SFTP layer"
done
ok "phase 3: all three sessions reached the SFTP layer and wrote their payloads"

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
