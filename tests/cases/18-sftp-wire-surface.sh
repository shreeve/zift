#!/usr/bin/env bash
# Test: unsupported requests get OP_UNSUPPORTED and malformed paths
#       BAD_MESSAGE, while FSTAT works
# SETSTAT of a size, READLINK, SYMLINK, EXTENDED and unknown opcodes are
# refused explicitly; NUL, control bytes, invalid UTF-8 and paths over
# 4096 bytes never reach policy or the filesystem.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
mkdir -p "$TEST_TMP/jail/inbox"
echo "test-content" > "$TEST_TMP/jail/inbox/file.txt"
write_config <<EOF
$(config_head)

user user1
  auth $(user_key)
  root $TEST_TMP/jail
  allow / read list
  allow /inbox full
EOF
start_zift

"$PY" - <<'EOF'
from client import *
sftp = connect("user1")
f = "/inbox/file.txt"
size = SFTPAttributes()
size.st_size = 0
for label, op, args in (("SETSTAT of a size", CMD_SETSTAT, (f, size)),
                        ("READLINK", CMD_READLINK, (f,)),
                        ("SYMLINK", CMD_SYMLINK, (f + ".link", f)),
                        ("EXTENDED", CMD_EXTENDED, ("posix-rename@openssh.com",)),
                        ("unknown opcode 250", 250, ())):
    code = status(sftp, op, *args)
    if code != FX_OP_UNSUPPORTED:
        fail(f"{label}: status {code}, want OP_UNSUPPORTED")
    ok(f"{label}: OP_UNSUPPORTED")

with sftp.open(f, "r") as h:
    if h.stat().st_size != 13:
        fail("FSTAT returned the wrong size")
ok("FSTAT returns attrs")

for label, path in (("NUL", b"/inbox/foo\x00bar"), ("SOH", b"/inbox/foo\x01bar"),
                    ("TAB", b"/inbox/foo\x09bar"), ("LF", b"/inbox/foo\x0abar"),
                    ("CR", b"/inbox/foo\x0dbar"), ("DEL", b"/inbox/foo\x7fbar"),
                    ("invalid UTF-8", b"/inbox/foo\xc3bar"),
                    ("path over 4096 bytes", b"/inbox/" + b"a" * 4090 + b"/x")):
    code = status(sftp, CMD_STAT, path)
    if code != FX_BAD_MESSAGE:
        fail(f"{label} in a path: status {code}, want BAD_MESSAGE")
    ok(f"{label} in a path: BAD_MESSAGE")
# The gate is not a catch-all: a well-formed missing path is NO_SUCH_FILE.
code = status(sftp, CMD_STAT, b"/inbox/well-formed-but-missing.txt")
if code != FX_NO_SUCH_FILE:
    fail(f"a well-formed missing path: status {code}, want NO_SUCH_FILE")
ok("a well-formed missing path: NO_SUCH_FILE")
EOF
