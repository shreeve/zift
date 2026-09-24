#!/usr/bin/env bash
# Test: when audit log writes start failing (broken pipe), sftp sessions
#       still complete — audit is not fail-closed
# A dead log shipper must not stop partner transfers; stderr carries a
# rate-limited warning so the outage is seen.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
# A FIFO breaks deterministically: once the reader exits, write(2)
# returns EPIPE (SIGPIPE is ignored). The reader must exist before zift
# opens it.
FIFO="$TEST_TMP/audit.fifo"
mkfifo "$FIFO"
cat "$FIFO" > "$TEST_TMP/audit.captured" &
READER=$!
PIDS+=("$READER")
mkdir -p "$TEST_TMP/data"
write_config <<EOF
$(config_head "log $FIFO")

user runner
  auth $(user_key)
  root $TEST_TMP/data
  allow / read write list mkdir
EOF
start_zift

transfer() {
    "$PY" - "$1" <<'EOF'
import io, sys
from client import *
name = sys.argv[1]
sftp = connect("runner")
sftp.putfo(io.BytesIO(f"{name} payload".encode()), f"/{name}.txt")
with sftp.open(f"/{name}.txt") as f:
    assert f.read() == f"{name} payload".encode()
EOF
}

transfer before-break || fail "transfer failed with the audit pipe healthy"
ok "transfer succeeded with the audit pipe healthy"

kill "$READER"
wait "$READER" 2>/dev/null || true
transfer after-break || fail "transfer failed once the audit pipe broke"
ok "transfer succeeded after the audit pipe broke (audit is not fail-closed)"

stop_zift TERM
log_contains "audit write failed" || fail "no 'audit write failed' warning on stderr: $(cat "$ZIFT_LOG")"
ok "stderr warns 'audit write failed'"

[[ "$(cat "$TEST_TMP/data/before-break.txt")" == "before-break payload" ]] || fail "before-break payload corrupted"
[[ "$(cat "$TEST_TMP/data/after-break.txt")" == "after-break payload" ]] || fail "after-break payload corrupted"
log_contains '"operation":"publish","result":"ok","path":"/before-break.txt"' "$TEST_TMP/audit.captured" \
    || fail "the reader got no audit lines while the pipe was healthy"
ok "both payloads correct on disk; audit flowed until the break"
