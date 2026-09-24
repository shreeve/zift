#!/usr/bin/env bash
# Test: status codes and audit lines at the edges of the SFTP handlers
# Oracle: a partner who may not stat never learns whether a path or its
#         parent exists from MKDIR/REMOVE/RMDIR/RENAME; one who may stat
#         gets NO_SUCH_FILE for a missing entry

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
done

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

sftp.close()
t.close()
sys.exit(1 if failed else 0)
EOF

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
