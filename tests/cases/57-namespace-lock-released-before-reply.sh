#!/usr/bin/env bash
# Test: a namespace change releases the partner's namespace lock before
#       it replies, so a client that stops reading cannot stall others
# A raw session fills its channel window with one READ's DATA, then sends
# MKDIR. The server makes the directory but cannot send the reply. A
# second session on the same root must still MKDIR at once.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
mkdir -p "$TEST_TMP/jail"
head -c 65536 /dev/zero > "$TEST_TMP/jail/big.bin"

write_config <<EOF
$(config_head "idle-timeout 30s")

user runner
  auth $(user_key)
  root $TEST_TMP/jail
  allow / full
EOF
start_zift

"$PY" - <<'EOF'
import os, struct
from client import *

def string(b):
    return struct.pack(">I", len(b)) + b

def packet(kind, req, body=b""):
    return struct.pack(">IBI", len(body) + 5, kind, req) + body

def recv_exact(chan, n):
    out = b""
    while len(out) < n:
        chunk = chan.recv(n - len(out))
        if not chunk:
            fail("channel closed early")
        out += chunk
    return out

# paramiko's smallest window. It sends WINDOW_ADJUST only once a tenth
# of the window has been read, so the 26 bytes read below never refill it.
WINDOW = 32768
VERSION_LEN, HANDLE_LEN, DATA_HEAD, STATUS_LEN = 9, 17, 13, 23
chan = transport("runner").open_session(window_size=WINDOW)
chan.settimeout(10)
chan.invoke_subsystem("sftp")
chan.sendall(struct.pack(">IBI", 5, 1, 3))
chan.sendall(packet(3, 1, string(b"/big.bin") + struct.pack(">II", 1, 0)))
head = recv_exact(chan, VERSION_LEN + HANDLE_LEN)
if head[4] != 2 or head[VERSION_LEN + 4] != 102:
    fail(f"unexpected replies to INIT and OPEN: {head!r}")
handle = head[VERSION_LEN + 9:]

# Leave the window a few bytes short of a STATUS reply, with slack for
# either side of the count.
spare = STATUS_LEN // 2
length = WINDOW - VERSION_LEN - HANDLE_LEN - DATA_HEAD - spare
chan.sendall(packet(5, 2, handle + struct.pack(">QI", 0, length)))
chan.sendall(packet(14, 3, string(b"/stuck") + struct.pack(">I", 0)))
if not wait_for(lambda: os.path.isdir(host("jail/stuck"))):
    fail("the server never made the stalled session's directory")
if not wait_for(lambda: len(chan.in_buffer) >= DATA_HEAD + length):
    fail("the READ's DATA never arrived")
if len(chan.in_buffer) >= DATA_HEAD + length + STATUS_LEN:
    fail("the MKDIR reply was not stalled, so this check proves nothing")
ok("the stalled session's MKDIR ran, and its reply is held by the window")

other = connect("runner", timeout=5)
expect("MKDIR from another session on the same root", "ok", other.mkdir, "/other")
expect("RENAME from another session on the same root", "ok", other.rename, "/other", "/other2")
expect("RMDIR from another session on the same root", "ok", other.rmdir, "/other2")
chan.get_transport().close()
EOF
