#!/usr/bin/env bash
# Test: per-handle access mode is enforced (write-only handle cannot READ)
# `read` controls READ and `write` controls WRITE, per handle: a drop-box
# partner must not read back a file through a handle opened for writing.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
mkdir -p "$TEST_TMP/jail/inbox"
echo "TOP-SECRET" > "$TEST_TMP/jail/inbox/secret.txt"

# `update` satisfies the clobber rule for OPEN(write) of an existing
# file, so the only thing refusing the READ is the handle's mode.
write_config <<EOF
$(config_head)

user drop
  auth $(user_key)
  root $TEST_TMP/jail
  allow /inbox write list update
EOF
start_zift

"$PY" - <<'EOF'
from client import *
sftp = connect("drop")
kind, reply = raw(sftp, CMD_OPEN, "/inbox/secret.txt", FXF_WRITE, SFTPAttributes())
if kind != CMD_HANDLE:
    fail(f"OPEN for write was refused (reply {kind})")
handle = reply.get_binary()
kind, reply = raw(sftp, CMD_READ, handle, int64(0), 4096)
if kind == CMD_DATA:
    fail(f"bypass: READ on a write-only handle returned {reply.get_binary()!r}")
code = reply.get_int() if kind == CMD_STATUS else kind
if code != FX_PERMISSION_DENIED:
    fail(f"READ on a write-only handle got {code}, want PERMISSION_DENIED")
ok("READ on a WRITE-only handle was denied")
EOF
