#!/usr/bin/env bash
# Test: policy globs match in linear time with `?` as one UTF-8
# character, and virtual-mode file bits promise only what OPEN allows.
#
# Covers:  src/policy.zig globMatch, effective, derivedMode.
# Oracle:  1. A 4 KiB STAT path against five `**` deny rules is judged
#             on the rules (not found), never denied for being slow.
#          2. `/utf/?.txt` grants `/utf/é.txt` but not `/utf/ab.txt`.
#          3. A listed file shows `w` only with `write` and `update`;
#             a symlink shows no permission bits.

source "$(dirname "$0")/../lib/common.sh"

VENV="$(dirname "$0")/../.venv"
PY="$VENV/bin/python3"

if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing at $VENV"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)

mkdir -p "$TEST_TMP/data/drop" "$TEST_TMP/data/rw" "$TEST_TMP/data/utf"
echo old > "$TEST_TMP/data/drop/old.csv"
echo data > "$TEST_TMP/data/rw/file.csv"
ln -s file.csv "$TEST_TMP/data/rw/link"
echo accent > "$TEST_TMP/data/utf/é.txt"
echo two > "$TEST_TMP/data/utf/ab.txt"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user runner
  auth $hash
  root $TEST_TMP/data
  allow / list
  allow /drop list write
  allow /rw read list write update
  allow /utf/?.txt read
  deny **/**/**/**/**/b
  deny **a**a**a**a**a**a**a**b
EOF

start_zift

"$PY" - <<EOF
import errno, paramiko, socket, time

sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="runner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)

# --- 1. pathological rules cost microseconds and decide on merit -------
path = "".join("/" + "a" * 63 for _ in range(64))[:4095] + "c"
assert len(path) == 4096
start = time.monotonic()
for _ in range(50):
    try:
        sftp.stat(path)
        raise AssertionError("stat of a missing path succeeded")
    except IOError as e:
        assert e.errno == errno.ENOENT, f"expected not found, got {e!r}"
elapsed = time.monotonic() - start
assert elapsed < 5, f"50 STATs took {elapsed:.2f}s"
print(f"ok: 4 KiB path vs five-** rules is not found, 50 STATs in {elapsed:.2f}s")

# The same deny rules still deny what they match.
try:
    sftp.stat(path[:-1] + "b")
    raise AssertionError("path matching a deny rule was allowed")
except IOError as e:
    assert e.errno == errno.EACCES, f"expected denied, got {e!r}"
print("ok: deny **/**/**/**/**/b still denies a match")

# --- 2. ? is one character, not one byte --------------------------------
with sftp.open("/utf/é.txt", "rb") as f:
    assert f.read() == b"accent\n"
print("ok: /utf/?.txt grants /utf/é.txt")
try:
    sftp.open("/utf/ab.txt", "rb")
    raise AssertionError("/utf/?.txt granted a two-character name")
except IOError as e:
    assert e.errno == errno.EACCES, f"expected denied, got {e!r}"
print("ok: /utf/?.txt does not grant /utf/ab.txt")

# --- 3. virtual-mode bits ----------------------------------------------
def modes(d):
    return {a.filename: a.longname.split()[0] for a in sftp.listdir_attr(d)}

drop = modes("/drop")
assert drop["old.csv"] == "----------", f"drop-box file should be ----------, got {drop['old.csv']!r}"
print("ok: write without update shows no w on an existing file")

rw = modes("/rw")
assert rw["file.csv"] == "-rw-rw----", f"write+update file should be -rw-rw----, got {rw['file.csv']!r}"
assert rw["link"] == "l---------", f"symlink should show no bits, got {rw['link']!r}"
print("ok: write+update shows rw-; a symlink shows ---")

root = modes("/")
assert root["drop"] == "drwxrwx---", f"drop dir should stay drwxrwx---, got {root['drop']!r}"
print("ok: directory bits unchanged")

sftp.close()
t.close()
EOF

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
