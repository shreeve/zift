#!/usr/bin/env bash
# Test: SSH_FXF_APPEND honored — write at end-of-file regardless of offset
# A WRITE at offset 0 on an APPEND handle lands at the end; a plain
# write handle still truncates and writes.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
mkdir -p "$TEST_TMP/jail/inbox"
printf 'hello-world' > "$TEST_TMP/jail/inbox/log.txt"
# `update`: appending to an existing file is a clobber.
write_config <<EOF
$(config_head)

user user1
  auth $(make_password_hash secret)
  root $TEST_TMP/jail
  allow / read list
  allow /inbox read write list delete update
EOF
start_zift

"$PY" - <<'EOF'
from client import *
sftp = connect("user1")
# paramiko's "a" mode seeks client-side, so send the flags and a
# deliberately wrong offset of 0 by hand.
kind, reply = raw(sftp, CMD_OPEN, "/inbox/log.txt", FXF_WRITE | FXF_APPEND, SFTPAttributes())
if kind != CMD_HANDLE:
    fail("OPEN(WRITE|APPEND) refused")
handle = reply.get_binary()
status(sftp, CMD_WRITE, handle, int64(0), b"-extra")
status(sftp, CMD_CLOSE, handle)
EOF
stop_zift TERM
[[ "$(cat "$TEST_TMP/jail/inbox/log.txt")" == "hello-world-extra" ]] \
    || fail "append did not land at end-of-file: $(cat "$TEST_TMP/jail/inbox/log.txt")"
ok "WRITE on an SSH_FXF_APPEND handle landed at end-of-file"

write_fresh() {
    "$PY" - <<'EOF'
from client import *
with connect("user1").open("/inbox/log.txt", "wb") as f:
    f.write(b"FRESH-CONTENT")
EOF
}
write_fresh >"$TEST_TMP/probe2.out" 2>&1 || true  # the server is stopped
start_zift
write_fresh
stop_zift TERM
[[ "$(cat "$TEST_TMP/jail/inbox/log.txt")" == "FRESH-CONTENT" ]] || fail "regular write mode broken"
ok "regular (non-append) write still works"
