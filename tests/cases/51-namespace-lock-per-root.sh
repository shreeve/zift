#!/usr/bin/env bash
# Test: one partner's slow directory rename does not stall another
#       partner's namespace changes (locks are per partner root)
# While alice renames a large tree, bob's MKDIR/RMDIR keep finishing,
# and a second session of alice's, which shares her root and so her
# lock, waits. That control shows the check fails for two roots that
# share a lock.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
mkdir -p "$TEST_TMP/alice/big" "$TEST_TMP/bob"
"$PY" - "$TEST_TMP/alice/big" <<'EOF'
import os, sys
for d in range(10):
    sub = os.path.join(sys.argv[1], f"d{d}")
    os.mkdir(sub)
    for f in range(1000):
        open(os.path.join(sub, f"f{f}"), "w").close()
EOF

# Unrelated rules make every policy check, and so the rename scan, slow
# enough to observe on any machine.
padding=$(for i in $(seq 300); do echo "  allow /unrelated-$i/**/*.dat read"; done)
key=$(user_key)
write_config <<EOF
$(config_head "idle-timeout 120s")

user alice
  auth $key
  root $TEST_TMP/alice
  allow / full
$padding

user bob
  auth $key
  root $TEST_TMP/bob
  allow / full
EOF
start_zift

"$PY" - <<'EOF'
import threading, time
from client import *
alice, alice2, bob = (connect(u, timeout=120) for u in ("alice", "alice", "bob"))
for sftp in (alice2, bob):
    sftp.mkdir("/warm")
    sftp.rmdir("/warm")
done = threading.Event()
ops = {}

def rename():
    alice.rename("/big", "/big2")
    done.set()

def churn(name, sftp):
    # Pairs finished while alice's rename was still running.
    n = 0
    while not done.is_set():
        sftp.mkdir("/d")
        sftp.rmdir("/d")
        if not done.is_set():
            n += 1
    ops[name] = n

start = time.monotonic()
th = threading.Thread(target=rename)
th.start()
time.sleep(0.2)  # let alice's rename take the lock first
churners = [threading.Thread(target=churn, args=a) for a in (("alice2", alice2), ("bob", bob))]
for t in churners:
    t.start()
for t in [th] + churners:
    t.join()
print(f"  alice's rename took {time.monotonic() - start:.2f}s; mkdir+rmdir pairs meanwhile: {ops}")
if ops["alice2"] >= 3:
    fail("alice's second session did not wait for her rename, so this check cannot see a shared lock")
ok("alice's second session, on the same root, waited for her rename")
if ops["bob"] < 3:
    fail("bob's namespace changes waited for alice's rename")
ok("bob's namespace changes did not wait for alice's rename")
EOF
