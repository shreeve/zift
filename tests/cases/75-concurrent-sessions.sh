#!/usr/bin/env bash
# Test: concurrent sessions: parallel uploads stay intact, two appenders
#       lose no record, and of two racing creates exactly one publishes
# Partners share nothing but a server; one session's traffic must never
# corrupt, interleave with or silently replace another's.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
key=$(user_key)
mkdir -p "$TEST_TMP/data/logs" "$TEST_TMP/drop"
: > "$TEST_TMP/data/logs/shared.log"
write_config <<EOF
$(config_head)

user busy
  auth $key
  root $TEST_TMP/data
  allow / full

user dropper
  auth $key
  root $TEST_TMP/drop
  allow / read list write
EOF
start_zift

"$PY" - <<'EOF'
import hashlib, os, threading
from client import *

def run_all(fns):
    errors = []
    def wrap(fn):
        try:
            fn()
        except BaseException as exc:
            errors.append(repr(exc))
    threads = [threading.Thread(target=wrap, args=(fn,)) for fn in fns]
    for t in threads: t.start()
    for t in threads: t.join()
    if errors:
        fail(f"a session failed: {errors}")

# --- 8 parallel uploads, each read back ------------------------------
def upload(i):
    data = hashlib.sha256(str(i).encode()).digest() * 8192  # 256 KiB
    sftp = connect("busy")
    with sftp.open(f"/up-{i}.bin", "wb") as f:
        f.write(data)
    with sftp.open(f"/up-{i}.bin", "rb") as f:
        if f.read() != data:
            raise AssertionError(f"up-{i}.bin read back wrong")
    close(sftp)
run_all([lambda i=i: upload(i) for i in range(8)])
for i in range(8):
    if read(f"data/up-{i}.bin") != hashlib.sha256(str(i).encode()).digest() * 8192:
        fail(f"up-{i}.bin is wrong on disk")
ok("8 parallel 256 KiB uploads are intact on disk and on read-back")

# --- two appenders on one file ---------------------------------------
def append(tag):
    sftp = connect("busy")
    kind, reply = raw(sftp, CMD_OPEN, "/logs/shared.log", FXF_WRITE | FXF_APPEND, SFTPAttributes())
    handle = reply.get_binary()
    for n in range(200):
        line = f"{tag} {n:04d} ".ljust(63, "x").encode() + b"\n"
        if status(sftp, CMD_WRITE, handle, int64(0), line) != FX_OK:
            raise AssertionError("append WRITE failed")
    status(sftp, CMD_CLOSE, handle)
    close(sftp)
run_all([lambda: append("A"), lambda: append("B")])
lines = read("data/logs/shared.log").split(b"\n")[:-1]
for tag in (b"A", b"B"):
    mine = [l for l in lines if l.startswith(tag + b" ")]
    if [int(l.split()[1]) for l in mine] != list(range(200)):
        fail(f"appender {tag.decode()} lost or reordered records")
if len(lines) != 400 or any(len(l) != 63 for l in lines):
    fail(f"{len(lines)} lines, or a torn one: concurrent appends overwrote each other")
ok("two concurrent appenders: all 400 records present and whole")

# --- two write-only sessions race to create the same file ------------
a, b = connect("dropper"), connect("dropper")
fa, fb = a.open("/race.bin", "wb"), b.open("/race.bin", "wb")
fa.write(b"A" * 100000)
fb.write(b"B" * 100000)
fa.close()
fb.close()  # paramiko swallows CLOSE errors; the disk and audit tell
if read("drop/race.bin") != b"A" * 100000:
    fail("the second create replaced (or mixed into) the first")
ok("of two racing creates, the first CLOSE published and the second did not replace it")
EOF

[[ $(count_log '"operation":"publish","result":"ok","path":"/race.bin"') == 1 ]] \
    || fail "expected exactly one publish of /race.bin"
log_contains '"operation":"close","result":"denied","path":"/race.bin"' \
    || fail "the losing create was not audited as a denied close"
ok "exactly one publish; the loser is audited as denied"
