#!/usr/bin/env bash
# Test: directory listing edge cases — empty dir, deeply nested, hidden
#       files, names with spaces, denied directory
# Listings match the filesystem, and a denied directory refuses to open.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
mkdir -p "$TEST_TMP/data/empty" "$TEST_TMP/data/deep/a/b/c" "$TEST_TMP/data/denied"
touch "$TEST_TMP/data/deep/a/b/c/file.txt" "$TEST_TMP/data/deep/file with spaces.txt" \
    "$TEST_TMP/data/deep/.hidden"
write_config <<EOF
$(config_head)

user runner
  auth $(make_password_hash secret)
  root $TEST_TMP/data
  allow / read list
  allow /deep read list
  deny /denied
EOF
start_zift

"$PY" - <<'EOF'
from client import *
sftp = connect("runner")
if sftp.listdir("/empty") != []:
    fail("empty directory is not empty")
ok("empty directory lists as empty")
if sftp.listdir("/deep/a/b/c") != ["file.txt"]:
    fail("deep nested directory listing is wrong")
ok("deep nested directory lists correctly")
if sorted(sftp.listdir("/deep")) != [".hidden", "a", "file with spaces.txt"]:
    fail(f"/deep lists {sftp.listdir('/deep')}")
ok("hidden files and names with spaces are listed")
expect("listing the denied directory", "denied", sftp.listdir, "/denied")
EOF
