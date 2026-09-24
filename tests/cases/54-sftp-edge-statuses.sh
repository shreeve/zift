#!/usr/bin/env bash
# Test: status codes and audit lines at the edges of the SFTP handlers
# A partner who may not stat learns nothing about existence from errors;
# a FIFO cannot block a session; refusals and odd endings are audited;
# READ and READDIR replies are large.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
for d in drop box; do
    mkdir -p "$TEST_TMP/jail/$d/existing"
    echo x > "$TEST_TMP/jail/$d/file.txt"
    mkfifo "$TEST_TMP/jail/$d/fifo"
done
# One level deeper than the rename scan follows.
deep="$TEST_TMP/jail/box/deep"
for _ in $(seq 257); do deep="$deep/d"; done
mkdir -p "$deep" "$TEST_TMP/jail/box/many"
for i in $(seq 200); do : > "$TEST_TMP/jail/box/many/entry-$i"; done
head -c 300000 /dev/zero > "$TEST_TMP/jail/box/big.bin"

write_config <<EOF
$(config_head "idle-timeout 30s")

user runner
  auth $(make_password_hash secret)
  root $TEST_TMP/jail
  allow /drop write mkdir delete rename
  allow /box full
EOF
start_zift

"$PY" - <<'EOF'
import struct
from client import *
sftp = connect("runner")
for root, gone, there in (("/drop", "denied", "denied"), ("/box", "missing", "failure")):
    expect(f"mkdir under a missing parent in {root}", gone, sftp.mkdir, f"{root}/nope/sub")
    expect(f"mkdir of an existing dir in {root}", there, sftp.mkdir, f"{root}/existing")
    expect(f"remove of a missing file in {root}", gone, sftp.remove, f"{root}/nope.txt")
    expect(f"remove under a missing parent in {root}", gone, sftp.remove, f"{root}/nope/x.txt")
    expect(f"rmdir of a missing dir in {root}", gone, sftp.rmdir, f"{root}/nope")
    expect(f"rename of a missing source in {root}", gone, sftp.rename, f"{root}/nope.txt", f"{root}/new.txt")
    expect(f"rename into a missing parent in {root}", gone, sftp.rename, f"{root}/file.txt", f"{root}/nope/new.txt")

# A FIFO would block open(2) until a writer (or reader) appeared.
sftp.get_channel().settimeout(5)
expect("open of a FIFO for reading in /box", "failure", sftp.open, "/box/fifo", "r")
expect("open of a FIFO for writing in /box", "failure", sftp.open, "/box/fifo", "r+")
expect("open of a FIFO for writing in /drop", "denied", sftp.open, "/drop/fifo", "w")
expect("session still answers after the FIFO opens", "ok", sftp.listdir, "/box")

expect("rename past the scan depth limit", "failure", sftp.rename, "/box/deep", "/box/deep2")

# A write-only handle refuses every READ; only the first is audited.
f = sftp.open("/box/file.txt", "a")
for _ in range(20):
    if status(sftp, CMD_READ, f.handle, int64(0), 10) != FX_PERMISSION_DENIED:
        fail("READ on a write-only handle was not denied")
f.close()
ok("20 READs on a write-only handle denied")

with sftp.open("/box/big.bin", "r") as f:
    kind, reply = raw(sftp, CMD_READ, f.handle, int64(0), 1 << 20)
    got = len(reply.get_binary()) if kind == CMD_DATA else -1
if got <= 200 * 1024:
    fail(f"one READ returned {got} bytes")
ok(f"one READ returned {got} bytes")
kind, reply = raw(sftp, CMD_OPENDIR, "/box/many")
kind, reply = raw(sftp, CMD_READDIR, reply.get_binary())
count = reply.get_int() if kind == CMD_NAME else -1
if count != 200:
    fail(f"one READDIR reply carried {count} entries")
ok("one READDIR reply carried all 200 entries")
close(sftp)

# A packet too short to carry a request id ends the session.
chan = transport("runner").open_session()
chan.invoke_subsystem("sftp")
chan.sendall(struct.pack(">IBI", 5, 1, 3))
chan.recv(64)
chan.sendall(struct.pack(">IBH", 3, 5, 0))
chan.settimeout(10)
while chan.recv(64):
    pass
EOF
stop_zift TERM

[[ $(count_log '"operation":"read","result":"denied","path":"/box/file.txt"') == 1 ]] \
    || fail "refused READs audited $(count_log '"operation":"read","result":"denied"') times, want once"
ok "refused READs on one handle are audited once, with the path"
log_contains '"operation":"rename","result":"failed","path":"/box/deep","detail":"rename scan limit"' \
    || fail "no rename scan limit audit line"
ok "the rename scan limit is audited as a failure that names it"
log_contains '"operation":"session.ended","result":"failed","detail":"ShortPacket' \
    || fail "no session.ended line for a session that ended on an error"
ok "a session that ends on an error still gets session.ended"
