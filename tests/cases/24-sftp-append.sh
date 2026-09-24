#!/usr/bin/env bash
# Test: SSH_FXF_APPEND honored — write at end-of-file regardless of offset
# A WRITE at offset 0 on an APPEND handle lands at the end; a plain
# write handle still writes where the client says.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
mkdir -p "$TEST_TMP/jail/inbox"
printf 'hello-world' > "$TEST_TMP/jail/inbox/log.txt"
# `update`: appending to an existing file is a clobber.
write_config <<EOF
$(config_head)

user user1
  auth $(user_key)
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
if status(sftp, CMD_WRITE, handle, int64(0), b"-extra") != FX_OK:
    fail("WRITE on the append handle failed")
status(sftp, CMD_CLOSE, handle)
got = read("jail/inbox/log.txt")
if got != b"hello-world-extra":
    fail(f"append did not land at end-of-file: {got!r}")
ok("WRITE on an SSH_FXF_APPEND handle landed at end-of-file")

with sftp.open("/inbox/log.txt", "r+") as f:
    f.seek(6)
    f.write(b"WORLD")
got = read("jail/inbox/log.txt")
if got != b"hello-WORLD-extra":
    fail(f"a positional write went astray: {got!r}")
ok("a plain write handle still writes at the client's offset")

with sftp.open("/inbox/log.txt", "wb") as f:
    f.write(b"FRESH-CONTENT")
if read("jail/inbox/log.txt") != b"FRESH-CONTENT":
    fail("truncate-and-write mode broken")
ok("truncate-and-write still works")
EOF
