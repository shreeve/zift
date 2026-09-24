#!/usr/bin/env bash
# Test: one partner's slow directory rename does not stall another
#       partner's namespace changes (locks are per partner root)
# While alice renames a large tree, bob's MKDIR/RMDIR keep finishing.

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
hash=$(make_password_hash secret)
write_config <<EOF
$(config_head "idle-timeout 120s")

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

"$PY" - <<'EOF'
import threading, time
from client import *
alice, bob = connect("alice", timeout=120), connect("bob", timeout=120)
bob.mkdir("/warm")
bob.rmdir("/warm")
done = threading.Event()

def rename():
    alice.rename("/big", "/big2")
    done.set()

th = threading.Thread(target=rename)
start = time.monotonic()
th.start()
time.sleep(0.2)  # let alice's rename take the lock first
ops = 0
while not done.is_set():
    bob.mkdir("/d")
    bob.rmdir("/d")
    if not done.is_set():
        ops += 1
th.join()
print(f"  alice's rename took {time.monotonic() - start:.2f}s; bob finished {ops} mkdir+rmdir pairs")
if ops < 3:
    fail("bob's namespace changes waited for alice's rename")
ok("bob's namespace changes did not wait for alice's rename")
EOF
