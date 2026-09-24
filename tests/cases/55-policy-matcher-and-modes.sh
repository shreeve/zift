#!/usr/bin/env bash
# Test: policy globs match in linear time with `?` as one UTF-8
#       character; a rule with a trailing comment still applies; and
#       virtual-mode file bits promise only what OPEN allows
# Pathological `**` rules must decide on merit, never deny for slowness;
# a listing's `w` must mean a write would succeed.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
mkdir -p "$TEST_TMP/data/drop" "$TEST_TMP/data/rw" "$TEST_TMP/data/utf" "$TEST_TMP/data/up/inbox"
echo old > "$TEST_TMP/data/drop/old.csv"
echo data > "$TEST_TMP/data/rw/file.csv"
ln -s file.csv "$TEST_TMP/data/rw/link"
echo accent > "$TEST_TMP/data/utf/é.txt"
echo two > "$TEST_TMP/data/utf/ab.txt"
write_config <<EOF
$(config_head)

user runner
  auth $(make_password_hash secret)
  root $TEST_TMP/data
  allow / list
  allow /drop list write
  allow /rw read list write update
  allow /utf/?.txt read
  allow /up full       # everything...
  deny /up/*.exe       # ...but top-level binaries
  deny **/**/**/**/**/b
  deny **a**a**a**a**a**a**a**b
EOF
start_zift

"$PY" - <<'EOF'
import errno, io, time
from client import *
sftp = connect("runner")

path = "".join("/" + "a" * 63 for _ in range(64))[:4095] + "c"
assert len(path) == 4096
start = time.monotonic()
for _ in range(50):
    expect_quiet = outcome(sftp.stat, path)
    if expect_quiet != "missing":
        fail(f"STAT of a 4 KiB path against ** rules: {expect_quiet}, want missing")
elapsed = time.monotonic() - start
if elapsed >= 5:
    fail(f"50 STATs took {elapsed:.2f}s")
ok(f"a 4 KiB path vs five-** rules is judged not found, 50 STATs in {elapsed:.2f}s")
expect("the same rules still deny a match", "denied", sftp.stat, path[:-1] + "b")

with sftp.open("/utf/é.txt", "rb") as f:
    if f.read() != b"accent\n":
        fail("/utf/é.txt content")
ok("/utf/?.txt grants /utf/é.txt")
expect("/utf/?.txt for a two-character name", "denied", sftp.open, "/utf/ab.txt", "rb")

put = lambda p: sftp.putfo(io.BytesIO(b"MZ"), p)
expect("upload /up/notes.txt", "ok", put, "/up/notes.txt")
expect("upload /up/tool.exe under a commented deny", "denied", put, "/up/tool.exe")
expect("upload /up/inbox/tool.exe (only the top level is denied)", "ok", put, "/up/inbox/tool.exe")

modes = lambda d: {a.filename: a.longname.split()[0] for a in sftp.listdir_attr(d)}
if modes("/drop")["old.csv"] != "----------":
    fail(f"drop-box file shows {modes('/drop')['old.csv']!r}")
ok("write without update shows no w on an existing file")
rw = modes("/rw")
if (rw["file.csv"], rw["link"]) != ("-rw-rw----", "l---------"):
    fail(f"/rw shows {rw}")
ok("write+update shows rw-; a symlink shows ---")
if modes("/")["drop"] != "drwxrwx---":
    fail(f"drop dir shows {modes('/')['drop']!r}")
ok("directory bits unchanged")
EOF
[[ ! -e "$TEST_TMP/data/up/tool.exe" ]] || fail "/up/tool.exe landed on disk"
