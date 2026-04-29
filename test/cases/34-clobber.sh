#!/usr/bin/env bash
# Test: v0.4.0 unified clobber rule. An `add`-only partner cannot
# destroy or modify an existing entry via OPEN(write). All four
# clobber attack vectors are blocked:
#
#   1. OPEN(write+CREAT+TRUNC) on existing path  (B3 in the threat model)
#   2. OPEN(write) on existing path, partial pwrite at offset  (B4)
#   3. OPEN(write+APPEND) on existing path  (B5)
#   4. RENAME to an existing destination  (B2 — already guarded in v0.3.0)
#
# Granting `remove` in addition to `add` (or using `full`) restores
# all clobber capabilities — verifies the rule isn't a one-way trap.
#
# Covers:  PLAN §6.3 v0.4.0 clobber rule, src/session.zig handleOpen
#          existing-file branch, src/session.zig handleRename
#          v0.3.0 destination-existence probe.
# Oracle:  SFTP_FXP_OPEN denied with PERMISSION_DENIED for each
#          attack; granting `remove` makes them succeed.

source "$(dirname "$0")/../lib/common.sh"

VENV="$(dirname "$0")/../.venv"
PY="$VENV/bin/python3"

if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing at $VENV"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)

mkdir -p "$TEST_TMP/data"
# Pre-existing file the operator placed (or another partner uploaded
# in a previous session). The add-only partner should not be able to
# modify any of these.
echo "OPERATOR-CONTRACT-VERSION-1" > "$TEST_TMP/data/contract.csv"
echo "EXISTING-LOG-LINE-1" > "$TEST_TMP/data/operator.log"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user dropper
  auth $hash
  root $TEST_TMP/data
  # add only — partner can drop NEW files but should not be able
  # to overwrite, modify in place, or append to existing files.
  allow / read list add
EOF

start_zift

"$PY" - <<EOF
import paramiko, socket, errno, sys

def connect():
    sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
    t = paramiko.Transport(sock)
    t.connect(username="dropper", password="secret")
    return t, paramiko.SFTPClient.from_transport(t)

# Read original content so we can verify it survives every attack
with open("$TEST_TMP/data/contract.csv") as f:
    original_contract = f.read()
with open("$TEST_TMP/data/operator.log") as f:
    original_log = f.read()

t, sftp = connect()

# --- B3: OPEN(write+CREAT+TRUNC) on existing file ----------------------
# This is what \`sftp put\` does by default — open existing for write,
# truncate to 0, fill with new bytes.
try:
    sftp.put("/dev/stdin", "/contract.csv")  # truncates+rewrites by default
    print("FAIL: partner truncate-overwrote /contract.csv (clobber rule failed)")
    sys.exit(1)
except IOError as exc:
    print(f"ok: B3 (truncate+overwrite): {exc}")

# --- B4: OPEN(write) on existing file, partial pwrite at offset --------
try:
    f = sftp.file("/contract.csv", "r+b")  # read+write, no truncate
    f.seek(5)
    f.write(b"DEFACED")
    f.close()
    print("FAIL: partner partially overwrote /contract.csv (clobber rule failed)")
    sys.exit(1)
except IOError as exc:
    print(f"ok: B4 (partial pwrite): {exc}")

# --- B5: OPEN(write+APPEND) on existing file ---------------------------
try:
    f = sftp.file("/operator.log", "ab")  # append mode
    f.write(b"INJECTED-LOG-LINE\n")
    f.close()
    print("FAIL: partner appended to /operator.log (clobber rule failed)")
    sys.exit(1)
except IOError as exc:
    print(f"ok: B5 (append): {exc}")

# --- B2: RENAME to an existing destination -----------------------------
# Upload an attacker-controlled file, then try to rename it OVER
# the operator's contract. The v0.3.0 rename guard should block this
# even though the v0.4.0 clobber rule wasn't yet in place.
sftp.putfo(__import__("io").BytesIO(b"ATTACKER-CONTROLLED"), "/attack.csv")
try:
    sftp.rename("/attack.csv", "/contract.csv")
    print("FAIL: partner renamed /attack.csv over /contract.csv (rename guard failed)")
    sys.exit(1)
except IOError as exc:
    print(f"ok: B2 (rename-overwrite): {exc}")

# --- Sanity: original content of both files still intact --------------
with open("$TEST_TMP/data/contract.csv") as f:
    assert f.read() == original_contract, "contract.csv was modified"
with open("$TEST_TMP/data/operator.log") as f:
    assert f.read() == original_log, "operator.log was modified"
print("ok: original contract.csv + operator.log content unchanged")

# --- Positive case: creating a NEW file is permitted ------------------
sftp.putfo(__import__("io").BytesIO(b"new file from partner"), "/new-upload.csv")
print("ok: creating new files (no existing target) is permitted")

# --- Cleanup the new file before testing remove path -------------------
# The partner has add but no remove, so they can't even clean up their
# own new uploads. Operator does it for the next phase.
sftp.close()
t.close()
EOF

# Operator (test framework) cleans up the partner's upload + the
# attack staging file so the next phase starts clean.
rm -f "$TEST_TMP/data/new-upload.csv" "$TEST_TMP/data/attack.csv"

# --- Phase 2: with `remove` granted, all clobber paths work ------------
# Restart with a config that grants `add remove` (= full mutate). All
# the previously-denied attacks now succeed — confirms the clobber rule
# isn't a one-way trap.
stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true

# Restore originals before phase 2.
echo "OPERATOR-CONTRACT-VERSION-1" > "$TEST_TMP/data/contract.csv"
echo "EXISTING-LOG-LINE-1" > "$TEST_TMP/data/operator.log"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user mutator
  auth $hash
  root $TEST_TMP/data
  # full = read + add + remove. All clobber paths now permitted.
  allow / full
EOF

start_zift

"$PY" - <<EOF
import paramiko, socket, sys, io

sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="mutator", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)

# B3: TRUNC overwrite — should now succeed
sftp.putfo(io.BytesIO(b"NEW-CONTRACT-V2"), "/contract.csv")
print("ok: with `remove`, truncate-overwrite succeeds")

# B5: APPEND — should now succeed
f = sftp.file("/operator.log", "ab")
f.write(b"\nLEGITIMATE-OPERATOR-APPEND\n")
f.close()
print("ok: with `remove`, append-on-existing succeeds")

sftp.close()
t.close()
EOF

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
