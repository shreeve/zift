#!/usr/bin/env bash
# Test: status codes and audit lines at the edges of the SFTP handlers
# Oracle: a partner who may not stat never learns whether a path or its
#         parent exists from MKDIR/REMOVE/RMDIR/RENAME; one who may stat
#         gets NO_SUCH_FILE for a missing entry; OPEN of a FIFO fails at
#         once instead of blocking the session; a handle's refused READs
#         are audited once; a malformed packet and the rename scan limit
#         leave audit lines that say so; one READ returns far more than
#         32 KiB and one READDIR reply far more than 16 entries

source "$(dirname "$0")/../lib/common.sh"

PY="$(dirname "$0")/../.venv/bin/python3"
if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)
for d in drop box; do
    mkdir -p "$TEST_TMP/jail/$d/existing"
    echo x > "$TEST_TMP/jail/$d/file.txt"
    mkfifo "$TEST_TMP/jail/$d/fifo"
done
# One level deeper than the rename scan follows.
deep="$TEST_TMP/jail/box/deep"
for _ in $(seq 257); do deep="$deep/d"; done
mkdir -p "$deep"
mkdir -p "$TEST_TMP/jail/box/many"
for i in $(seq 200); do : > "$TEST_TMP/jail/box/many/entry-$i"; done
head -c 300000 /dev/zero > "$TEST_TMP/jail/box/big.bin"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  idle-timeout 30s
  log stderr

user runner
  auth $hash
  root $TEST_TMP/jail
  allow /drop write mkdir delete rename
  allow /box full
EOF

start_zift

"$PY" - "$TEST_PORT" <<'EOF'
import socket, sys
import paramiko

port = int(sys.argv[1])
sock = socket.create_connection(("127.0.0.1", port), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="runner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)
failed = False

def expect(label, want, fn, *args):
    global failed
    try:
        fn(*args)
        got = "ok"
    except socket.timeout:
        got = "timeout"
    except PermissionError:
        got = "denied"
    except FileNotFoundError:
        got = "missing"
    except IOError:
        got = "failure"
    if got == want:
        print(f"  ok: {label}: {got}")
    else:
        print(f"  fail: {label}: want {want}, got {got}")
        failed = True

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
from paramiko.sftp import CMD_READ, int64
f = sftp.open("/box/file.txt", "a")
for _ in range(20):
    expect("READ on a write-only handle", "denied", sftp._request, CMD_READ, f.handle, int64(0), 10)
f.close()

from paramiko.sftp import CMD_OPENDIR, CMD_READDIR, CMD_DATA, CMD_NAME
with sftp.open("/box/big.bin", "r") as f:
    kind, msg = sftp._request(CMD_READ, f.handle, int64(0), 1 << 20)
    got = len(msg.get_binary()) if kind == CMD_DATA else -1
if got > 200 * 1024:
    print(f"  ok: one READ returned {got} bytes")
else:
    print(f"  fail: one READ returned {got} bytes")
    failed = True
kind, msg = sftp._request(CMD_OPENDIR, "/box/many")
handle = msg.get_binary()
kind, msg = sftp._request(CMD_READDIR, handle)
count = msg.get_int() if kind == CMD_NAME else -1
if count == 200:
    print(f"  ok: one READDIR reply carried all {count} entries")
else:
    print(f"  fail: one READDIR reply carried {count} entries")
    failed = True

sftp.close()
t.close()

# A packet too short to carry a request id ends the session.
import struct
sock = socket.create_connection(("127.0.0.1", port), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="runner", password="secret")
chan = t.open_session()
chan.invoke_subsystem("sftp")
chan.sendall(struct.pack(">IBI", 5, 1, 3))
chan.recv(64)
chan.sendall(struct.pack(">IBH", 3, 5, 0))
chan.settimeout(10)
while chan.recv(64):
    pass
t.close()
sys.exit(1 if failed else 0)
EOF

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true

reads=$(grep -c '"operation":"read","result":"denied","path":"/box/file.txt"' "$ZIFT_LOG" || true)
[[ "$reads" == 1 ]] || fail "refused READs audited $reads times, want once"
ok "refused READs on one handle are audited once, with the path"
grep -q '"operation":"rename","result":"failed","path":"/box/deep","detail":"rename scan limit"' "$ZIFT_LOG" \
    || fail "no rename scan limit audit line"
ok "the rename scan limit is audited as a failure that names it"
grep -q '"operation":"session.ended","result":"failed","detail":"ShortPacket' "$ZIFT_LOG" \
    || fail "no session.ended line for a session that ended on an error"
ok "a session that ends on an error still gets session.ended"
