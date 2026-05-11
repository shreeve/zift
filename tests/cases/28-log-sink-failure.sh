#!/usr/bin/env bash
# Test: when audit log writes start failing (broken pipe), sftp sessions
#       still complete — audit is not fail-closed (PLAN §8.5).
# Covers: PLAN §8.5 audit-not-fail-closed, audit.zig::warnWriteFailure
#         rate-limiting, signals.zig SIGPIPE-ignored.
# Oracle: a) sftp transfer succeeds while the FIFO reader is alive (audit
#            lines flow), and b) sftp transfer ALSO succeeds after we kill
#            the reader and audit `write(2)` starts returning EPIPE,
#            and c) stderr contains a rate-limited "audit write failed"
#            warning so operators see the outage.

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

# Use a FIFO so we can break the pipe deterministically: any write(2)
# after the reader exits returns -1 with errno=EPIPE (and SIGPIPE is
# ignored process-wide, so the worker thread keeps running). chmod 000
# does NOT discriminate on Linux because permissions are checked at
# open(2), not write(2).
FIFO="$TEST_TMP/audit.fifo"
mkfifo "$FIFO"

# Reader has to be running BEFORE zift opens the fifo — otherwise the
# server's open(O_WRONLY) on the fifo blocks indefinitely.
cat "$FIFO" > "$TEST_TMP/audit.captured" &
READER_PID=$!

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  idle-timeout 10s
  shutdown-grace 2s
  log $FIFO

user runner
  auth $hash
  root $TEST_TMP/data
  allow / read write list mkdir
EOF

start_zift
ZIFT_STDERR="$TEST_TMP/zift.log"

run_sftp() {
    local label="$1"
    "$PY" - <<PY
import paramiko, socket, sys
sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="runner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)
with sftp.open("/$label.txt", "w") as f:
    f.write(b"$label payload")
with sftp.open("/$label.txt", "r") as f:
    assert f.read() == b"$label payload"
sftp.close(); t.close()
PY
}

# Phase 1: reader alive — audit pipe healthy. Use this as a baseline so
# we know the test setup is sound before we sabotage it.
run_sftp before-break || fail "phase 1 sftp failed (reader alive)"
ok "phase 1: sftp succeeded with audit pipe healthy"

# Phase 2: kill the reader. Subsequent zift writes to the fifo now
# return EPIPE. SIGPIPE is ignored (signals.zig:139) so the worker
# thread keeps running. The audit pipeline must not stop SFTP.
kill "$READER_PID" 2>/dev/null || true
wait "$READER_PID" 2>/dev/null || true

# Force the server to attempt at least one audit write through the
# now-broken pipe before phase-2 sftp, so we know the warning fires.
sleep 0.3

run_sftp after-break || fail "phase 2 sftp failed when audit pipe was broken"
ok "phase 2: sftp succeeded after audit pipe was broken (audit not fail-closed)"

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true

# Phase 3: zift's stderr should contain a rate-limited warning so
# operators are not blind to the outage. Without rate-limiting we'd
# see one line per failed write; the warning is intentionally noisy
# enough to be noticed but not a storm.
if grep -q "audit write failed" "$ZIFT_STDERR"; then
    ok "phase 3: stderr contains rate-limited 'audit write failed' warning"
else
    fail "phase 3: expected 'audit write failed' on stderr; got:"
    sed 's/^/    /' "$ZIFT_STDERR" >&2
fi

# Phase 4: confirm both file-payloads landed correctly so we know the
# sftp 'success' wasn't a paramiko false-positive.
[[ "$(cat "$TEST_TMP/data/before-break.txt")" == "before-break payload" ]] \
    || fail "phase 4: before-break payload corrupted"
[[ "$(cat "$TEST_TMP/data/after-break.txt")" == "after-break payload" ]] \
    || fail "phase 4: after-break payload corrupted"
ok "phase 4: both transfer payloads correct on disk"
