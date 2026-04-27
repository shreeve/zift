#!/usr/bin/env bash
# Test: directory listing edge cases — empty dir, deeply nested, hidden
#       files, names with spaces, denied directory.
# Covers: PLAN §7.6 READDIR, policy readdir/list permission
# Oracle: listings match filesystem; denied directory returns IOError

source "$(dirname "$0")/../lib/common.sh"

VENV="$(dirname "$0")/../.venv"
PY="$VENV/bin/python3"

if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing at $VENV"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)

mkdir -p "$TEST_TMP/data/empty"
mkdir -p "$TEST_TMP/data/deep/a/b/c"
mkdir -p "$TEST_TMP/data/denied"
touch "$TEST_TMP/data/deep/a/b/c/file.txt"
touch "$TEST_TMP/data/deep/file with spaces.txt"
touch "$TEST_TMP/data/deep/.hidden"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  idle-timeout 10s
  shutdown-grace 2s
  log stderr

user runner
  password $hash
  root $TEST_TMP/data
  allow / read list
  allow /deep read list
  deny /denied
EOF

start_zift

"$PY" - <<EOF
import paramiko, socket, sys

sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="runner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)

# Empty directory.
entries = sftp.listdir("/empty")
assert entries == [], f"expected empty listing, got {entries}"
print("ok: empty directory lists correctly")

# Deep nested directory.
entries = sftp.listdir("/deep/a/b/c")
assert "file.txt" in entries, f"missing file.txt in {entries}"
print("ok: deep nested directory lists correctly")

# Hidden files included.
entries = sftp.listdir("/deep")
assert ".hidden" in entries, f"hidden file missing from {entries}"
print("ok: hidden files included in listing")

# Names with spaces preserved.
assert any("spaces" in e for e in entries), f"file with spaces missing: {entries}"
print("ok: files with spaces listed correctly")

# Denied directory rejected.
try:
    sftp.listdir("/denied")
    print("fail: denied directory listing should have been rejected")
    sys.exit(1)
except IOError:
    print("ok: denied directory listing rejected")

sftp.close()
t.close()
EOF

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
