#!/usr/bin/env bash
# Test: `ls -la` in the default virtual listing mode shows the virtual
#       user, group "sftp", policy-derived rwx bits and `---` for world
# The on-disk owner, group and mode never leak into the partner's view.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
mkdir -p "$TEST_TMP/data/pending" "$TEST_TMP/data/archive"
echo "hello world" > "$TEST_TMP/data/notes.txt"
dd if=/dev/zero of="$TEST_TMP/data/large.bin" bs=1024 count=42 2>/dev/null
write_config <<EOF
$(config_head)

user runner
  auth $(user_key)
  root $TEST_TMP/data
  allow / read list
  allow /pending read list write delete update
  allow /archive read list
EOF
start_zift

"$PY" - <<'EOF'
from client import *
sftp = connect("runner")
attrs = {a.filename: a for a in sftp.listdir_attr("/")}
if not {"notes.txt", "large.bin", "pending", "archive"} <= set(attrs):
    fail(f"missing entries: {sorted(attrs)}")
notes, pending, archive, large = (attrs[n] for n in ("notes.txt", "pending", "archive", "large.bin"))
if notes.st_size != 12 or not notes.st_mtime:
    fail(f"notes.txt size/mtime wrong: {notes.st_size} {notes.st_mtime}")
ok("all entries listed with size and mtime")

if (notes.st_uid, notes.st_gid) != (0, 0):
    fail(f"wire uid/gid should be 0/0, got {notes.st_uid}/{notes.st_gid}")
ok("wire uid/gid zeroed")
fields = notes.longname.split()
if (fields[2], fields[3]) != ("runner", "sftp"):
    fail(f"longname owner/group should be runner/sftp: {notes.longname!r}")
ok("longname owner is the virtual user, group is 'sftp'")

mode = {n: a.longname.split()[0] for n, a in attrs.items()}
for n, m in mode.items():
    if m[7:10] != "---":
        fail(f"{n}: world bits {m!r}")
    if m[1:4] != m[4:7]:
        fail(f"{n}: group bits do not mirror owner bits: {m!r}")
ok("world bits are --- and group bits mirror owner bits everywhere")

for name, want in (("pending", "drwx"), ("archive", "dr-x"), ("notes.txt", "-r--")):
    if mode[name][:4] != want:
        fail(f"{name}: {mode[name]!r}, want {want}...")
ok("policy-derived bits: /pending rwx, /archive r-x, /notes.txt r--; d and - types kept")

if pending.longname.split()[4] != "-" or "42K" not in large.longname:
    fail(f"sizes: {pending.longname!r} / {large.longname!r}")
ok("dir size is '-', file size uses a K/M suffix")
EOF
