#!/usr/bin/env bash
# Test: publish-mode and mkdir-mode set the modes of uploads and new
#       directories, and wire errors carry no Zift-internal words
# A clobber denial reads "permission denied", not an explanation of the
# server's internals.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
mkdir -p "$TEST_TMP/data/inbox"
echo "EXISTING-CONTENT" > "$TEST_TMP/data/inbox/existing.txt"
write_config <<EOF
$(config_head "publish-mode 0o640" "mkdir-mode 0o2750")

user partner
  auth $(make_password_hash secret)
  root $TEST_TMP/data
  allow / read write mkdir
EOF
start_zift

"$PY" - <<'EOF'
import os, stat
from client import *
mode = lambda p: stat.S_IMODE(os.stat(host(p)).st_mode)
sftp = connect("partner")

with sftp.file("/inbox/upload.txt", "wb") as f:
    f.write(b"hello, world")
if mode("data/inbox/upload.txt") != 0o640:
    fail(f"upload landed at 0{mode('data/inbox/upload.txt'):o}, want 0640")
ok("publish-mode 0o640 honored")

sftp.mkdir("/inbox/subdir")
if mode("data/inbox/subdir") != 0o2750:
    fail(f"mkdir landed at 0{mode('data/inbox/subdir'):o}, want 02750")
ok("mkdir-mode 0o2750 honored (setgid kept)")

try:
    with sftp.file("/inbox/existing.txt", "wb") as f:
        f.write(b"OVERWRITE-ATTEMPT")
    fail("clobber attempt succeeded against a write-only partner")
except PermissionError as exc:
    msg = str(exc).lower()
    leaked = [w for w in ("clobber", "publish", "partner", "staged", "staging", "zift",
                          "target appeared", "lacks update") if w in msg]
    if leaked or not ("denied" in msg or "permission" in msg):
        fail(f"wire error {exc!r} leaks {leaked} or says nothing of permission")
    ok(f"clobber error is plain: {exc}")
if read("data/inbox/existing.txt") != b"EXISTING-CONTENT\n":
    fail("existing file content corrupted")
ok("existing file survived the refused clobber")
EOF
