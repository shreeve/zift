#!/usr/bin/env bash
# Test: a path through a regular file is "no such file", not a denial,
#       while a path through a symlink stays denied; and REALPATH never
#       returns a path or name longer than the server accepts
# Only symlinks are jail questions; a file used as a directory is just
# missing, and audited as a failure.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
mkdir -p "$TEST_TMP/data/dir"
echo hi > "$TEST_TMP/data/file.txt"
ln -s dir "$TEST_TMP/data/link"
write_config <<EOF
$(config_head)

user runner
  auth $(user_key)
  root $TEST_TMP/data
  allow / full
EOF
start_zift

"$PY" - <<'EOF'
from client import *
sftp = connect("runner")
expect("stat /file.txt/x", "missing", sftp.stat, "/file.txt/x")
expect("open /file.txt/x for write", "missing", sftp.open, "/file.txt/x", "wb")
expect("listdir /file.txt", "missing", sftp.listdir, "/file.txt")
expect("stat /link/x", "denied", sftp.stat, "/link/x")
expect("listdir /link", "denied", sftp.listdir, "/link")

# Sixteen 255-byte names: every name within the limit.
name = "/".join(["a" * 255] * 16)
if sftp.normalize(name) != "/" + name:
    fail("realpath of a 4095-byte relative path is not the 4096-byte absolute one")
ok("realpath of a 4095-byte relative path is 4096 bytes")
# 4096 bytes in seventeen 240-byte names; the leading "/" makes 4097.
expect("realpath of a result over 4096 bytes", "failure", sftp.normalize, "/".join(["a" * 240] * 17))
expect("realpath of a name over 255 bytes", "failure", sftp.normalize, "a" * 256)
EOF

grep '"path":"/file.txt/x"' "$ZIFT_LOG" | grep '"operation":"open_write"' | grep -q '"result":"failed"' \
    || fail "open through a file should audit as failed, not denied"
ok "open through a file audits as failed"
