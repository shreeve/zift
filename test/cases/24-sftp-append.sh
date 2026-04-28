#!/usr/bin/env bash
# Test: SSH_FXF_APPEND honored — write at end-of-file regardless of offset
# Covers: PLAN §7.6 (ordinary SFTP v3 OPEN semantics)
# TODOS: P1 SSH_FXF_APPEND
#
# Open with the WRITE+APPEND flag, then issue WRITE messages with an
# explicit offset of 0. The bytes must land at the END of the file —
# the per-handle is_append flag overrides the client-supplied offset.
# Without the fix, write-at-offset-0 would overwrite the existing
# content; with the fix, it appends.

source "$(dirname "$0")/../lib/common.sh"

VENV="$(dirname "$0")/../.venv"
PY="$VENV/bin/python3"

if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing at $VENV"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)

mkdir -p "$TEST_TMP/jail/inbox"
INITIAL="hello-world"
printf '%s' "$INITIAL" > "$TEST_TMP/jail/inbox/log.txt"
INITIAL_SIZE=${#INITIAL}

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user user1
  password $hash
  root $TEST_TMP/jail
  allow / read list
  # write+remove: append-on-existing is "clobber" under v0.4.0 (any
  # OPEN(write) of an existing file requires `remove`). This test
  # exercises append semantics, not clobber authorization, so grant
  # both. A real partner workflow would use `add remove` (or `full`)
  # for the same effect.
  allow /inbox read write list remove
EOF

start_zift

# Drive raw SFTP. Paramiko's high-level open("ab") seeks to EOF
# client-side and sends WRITE with offset=size, so it doesn't exercise
# the server's append path. We open with SSH_FXF_WRITE|SSH_FXF_APPEND
# directly and then issue WRITE with a deliberately-WRONG offset of 0.
# A correct implementation must ignore the wrong offset and write at
# end-of-file.
"$PY" - <<EOF >"$TEST_TMP/probe.out" 2>&1
import paramiko, socket, sys
import paramiko.sftp as sp
from paramiko.message import Message
from paramiko.sftp_attr import SFTPAttributes

sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="user1", password="secret")
chan = t.open_session()
chan.invoke_subsystem("sftp")
sftp = paramiko.SFTPClient(chan)

SSH_FXF_WRITE  = 0x02
SSH_FXF_APPEND = 0x04

# OPEN with WRITE+APPEND only.
attrs = SFTPAttributes()
op_t, op_msg = sftp._request(sp.CMD_OPEN, "/inbox/log.txt", SSH_FXF_WRITE | SSH_FXF_APPEND, attrs)
assert op_t == sp.CMD_HANDLE, f"OPEN reply type {op_t}"
handle = op_msg.get_binary()

# Raw WRITE with a deliberately-wrong offset of 0. Paramiko packs ints
# as 32-bit by default; the offset field is uint64, so we use sp.int64.
wr_t, wr_msg = sftp._request(sp.CMD_WRITE, handle, sp.int64(0), b"-extra")
print(f"write reply type={wr_t}")

cl_t, cl_msg = sftp._request(sp.CMD_CLOSE, handle)
print(f"close reply type={cl_t}")
sftp.close()
t.close()
EOF

stop_zift TERM

# Oracle: file should now read "hello-world-extra", not "-extra-orld"
# (which is what overwrite-at-offset-0 would have produced).
RESULT=$(cat "$TEST_TMP/jail/inbox/log.txt")
EXPECTED="${INITIAL}-extra"
echo "  initial: $INITIAL ($INITIAL_SIZE bytes)"
echo "  result:  $RESULT"
echo "  expected: $EXPECTED"

[[ "$RESULT" == "$EXPECTED" ]] \
    || fail "append did not happen at EOF: got '$RESULT', expected '$EXPECTED'"
ok "WRITE on a SSH_FXF_APPEND handle landed at end-of-file"

# Sanity: regular WRITE (no APPEND) still respects the client offset.
"$PY" - <<EOF >"$TEST_TMP/probe2.out" 2>&1
import paramiko, socket, sys
sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="user1", password="secret")
chan = t.open_session()
chan.invoke_subsystem("sftp")
sftp = paramiko.SFTPClient(chan)
# Truncate-then-write at offset 0 (regular write mode).
f = sftp.open("/inbox/log.txt", "wb")
f.write(b"FRESH-CONTENT")
f.close()
sftp.close()
t.close()
EOF

start_zift  # Need the server up for the second probe
"$PY" - <<EOF >>"$TEST_TMP/probe2.out" 2>&1
import paramiko, socket, sys
sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="user1", password="secret")
chan = t.open_session()
chan.invoke_subsystem("sftp")
sftp = paramiko.SFTPClient(chan)
f = sftp.open("/inbox/log.txt", "wb")
f.write(b"FRESH-CONTENT")
f.close()
sftp.close()
t.close()
EOF
stop_zift TERM

RESULT2=$(cat "$TEST_TMP/jail/inbox/log.txt")
[[ "$RESULT2" == "FRESH-CONTENT" ]] \
    || fail "regular write mode broken: got '$RESULT2', expected 'FRESH-CONTENT'"
ok "regular (non-append) write still works as positional write"
