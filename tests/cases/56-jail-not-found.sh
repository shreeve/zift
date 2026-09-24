#!/usr/bin/env bash
# Test: a path through a regular file is "no such file", not a denial,
# while a path through a symlink stays denied; and REALPATH never
# returns a path longer than the server accepts.
#
# Covers:  src/vfs.zig openVirtualDir NotDir mapping and
#          normalizeVirtualInto's output bound.
# Oracle:  STAT/OPEN/OPENDIR through `file.txt` fail with ENOENT and
#          audit as failed; through a symlink they fail with EACCES;
#          REALPATH of a 4096-byte relative path is refused, and of a
#          4095-byte one returns exactly 4096 bytes.

source "$(dirname "$0")/../lib/common.sh"

VENV="$(dirname "$0")/../.venv"
PY="$VENV/bin/python3"

if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing at $VENV"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)

mkdir -p "$TEST_TMP/data/dir"
echo hi > "$TEST_TMP/data/file.txt"
ln -s dir "$TEST_TMP/data/link"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user runner
  auth $hash
  root $TEST_TMP/data
  allow / full
EOF

start_zift

"$PY" - <<EOF
import errno, paramiko, socket

sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="runner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)

def expect_errno(label, want, call):
    try:
        call()
    except IOError as e:
        assert e.errno == want, f"{label}: expected errno {want}, got {e!r}"
        print(f"ok: {label} -> {errno.errorcode[want]}")
        return
    raise AssertionError(f"{label} unexpectedly succeeded")

expect_errno("stat /file.txt/x", errno.ENOENT, lambda: sftp.stat("/file.txt/x"))
expect_errno("open /file.txt/x for write", errno.ENOENT, lambda: sftp.open("/file.txt/x", "wb"))
expect_errno("listdir /file.txt", errno.ENOENT, lambda: sftp.listdir("/file.txt"))
expect_errno("stat /link/x", errno.EACCES, lambda: sftp.stat("/link/x"))
expect_errno("listdir /link", errno.EACCES, lambda: sftp.listdir("/link"))

name = "a" * 4095
got = sftp.normalize(name)
assert got == "/" + name, f"realpath of 4095 bytes: got {len(got)} bytes"
print("ok: realpath of a 4095-byte relative path is 4096 bytes")
try:
    got = sftp.normalize(name + "a")
    raise AssertionError(f"realpath returned {len(got)} bytes, over the 4096 limit")
except IOError:
    print("ok: realpath refuses a result over 4096 bytes")

sftp.close()
t.close()
EOF

grep '"path":"/file.txt/x"' "$ZIFT_LOG" | grep '"operation":"open_write"' | grep -q '"result":"failed"' \
    || fail "open through a file should audit as failed, not denied"
ok "open through a file audits as failed"

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
