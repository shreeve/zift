#!/usr/bin/env bash
# Test: `listing-mode reality` shows the on-disk owner, group and mode
# The opt-in escape hatch for operators who want partners to see the
# real inode, not the virtual user and policy-derived bits.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
mkdir -p "$TEST_TMP/data"
echo "hello" > "$TEST_TMP/data/notes.txt"
chmod 0644 "$TEST_TMP/data/notes.txt"
write_config <<EOF
$(config_head "listing-mode reality")

user runner
  auth $(make_password_hash secret)
  root $TEST_TMP/data
  allow / read list
EOF
start_zift

"$PY" - <<'EOF'
import os, pwd
from client import *
sftp = connect("runner")
uid = os.geteuid()
a = sftp.lstat("/notes.txt")
if a.st_uid != uid:
    fail(f"wire uid {a.st_uid}, want the real {uid}")
if a.st_gid == 0 and uid != 0:
    fail("wire gid is zeroed as in virtual mode")
ok(f"wire uid/gid are the real ones ({a.st_uid}/{a.st_gid})")

notes = next(x for x in sftp.listdir_attr("/") if x.filename == "notes.txt")
owner, mode = notes.longname.split()[2], notes.longname.split()[0]
real_owner = pwd.getpwuid(uid).pw_name
if owner != real_owner:
    fail(f"longname owner {owner!r}, want the OS user {real_owner!r}")
ok(f"longname owner is the OS user {owner!r}")
# Virtual mode would show r-- here (read-only policy); the inode is 0644.
if mode[1:4] != "rw-" or a.st_mode & 0o777 != 0o644:
    fail(f"mode {mode!r} / {a.st_mode & 0o777:o} is not the inode's 0644")
ok("mode bits come from the inode, not the policy")
EOF
