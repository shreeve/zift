#!/usr/bin/env bash
# Test: one partner's slow directory rename does not stall another
#       partner's namespace changes (locks are per partner root)
# Oracle: while alice renames a large tree, bob's MKDIR/REMOVE finish
#         before alice's RENAME does

source "$(dirname "$0")/../lib/common.sh"

PY="$(dirname "$0")/../.venv/bin/python3"
if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)
mkdir -p "$TEST_TMP/alice/big" "$TEST_TMP/bob"
"$PY" - "$TEST_TMP/alice/big" <<'EOF'
import os, sys
base = sys.argv[1]
for d in range(10):
    sub = os.path.join(base, f"d{d}")
    os.mkdir(sub)
    for f in range(1000):
        open(os.path.join(sub, f"f{f}"), "w").close()
EOF

# Unrelated rules make every policy check, and so the rename scan, slow
# enough to observe on any machine.
padding=$(for i in $(seq 300); do echo "  allow /unrelated-$i/**/*.dat read"; done)

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  idle-timeout 120s
  log stderr

user alice
  auth $hash
  root $TEST_TMP/alice
  allow / full
$padding

user bob
  auth $hash
  root $TEST_TMP/bob
  allow / full
EOF

start_zift

"$PY" - "$TEST_PORT" <<'EOF'
import socket, sys, threading, time
import paramiko

port = int(sys.argv[1])

def connect(user):
    sock = socket.create_connection(("127.0.0.1", port), timeout=120)
    t = paramiko.Transport(sock)
    t.connect(username=user, password="secret")
    s = paramiko.SFTPClient.from_transport(t)
    s.get_channel().settimeout(120)
    return s

alice = connect("alice")
bob = connect("bob")
bob.mkdir("/warm")
bob.rmdir("/warm")
done = threading.Event()

def rename():
    alice.rename("/big", "/big2")
    done.set()

th = threading.Thread(target=rename)
start = time.monotonic()
th.start()
time.sleep(0.2)
ops = 0
while not done.is_set():
    bob.mkdir("/d")
    bob.rmdir("/d")
    if not done.is_set():
        ops += 1
th.join()
print(f"  alice's rename took {time.monotonic() - start:.2f}s")

print(f"  bob finished {ops} mkdir+rmdir pairs during alice's rename")
if ops < 3:
    print("  fail: bob's namespace changes waited for alice's rename")
    sys.exit(1)
print("  ok: bob's namespace changes did not wait for alice's rename")
EOF

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
