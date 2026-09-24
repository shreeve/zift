#!/usr/bin/env bash
# Test: SSH_FXP_STAT/LSTAT do not follow symlinks at the basename
# A symlink in the jail that points outside must never reveal the outside
# file's metadata: STAT and LSTAT describe the link itself or refuse.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
secret="this string is exactly the outside content with a particular length"
printf '%s' "$secret" > "$TEST_TMP/outside_secret.txt"
mkdir -p "$TEST_TMP/jail/inbox"
ln -s "$TEST_TMP/outside_secret.txt" "$TEST_TMP/jail/inbox/link-to-secret"
printf 'inside' > "$TEST_TMP/jail/inbox/regular.txt"

write_config <<EOF
$(config_head)

user user1
  auth $(make_password_hash secret)
  root $TEST_TMP/jail
  allow / read list
  allow /inbox read list
EOF
start_zift

"$PY" - "${#secret}" <<'EOF'
import stat, sys
from client import *
secret_size = int(sys.argv[1])
sftp = connect("user1")
# Liveness first, so a broken login or empty reply cannot pass vacuously.
for call in (sftp.stat, sftp.lstat):
    a = call("/inbox/regular.txt")
    if not stat.S_ISREG(a.st_mode) or a.st_size != 6:
        fail(f"{call.__name__} of a regular file: mode {a.st_mode:o} size {a.st_size}")
ok("STAT and LSTAT of a regular file inside the jail are correct")

for call in (sftp.stat, sftp.lstat):
    try:
        a = call("/inbox/link-to-secret")
    except PermissionError:
        ok(f"{call.__name__.upper()} of the escaping link refused")
        continue
    if stat.S_ISREG(a.st_mode) or a.st_size == secret_size:
        fail(f"{call.__name__.upper()} followed the link out of the jail (size {a.st_size})")
    if not stat.S_ISLNK(a.st_mode):
        fail(f"{call.__name__.upper()} of the link: mode {a.st_mode:o}, want a symlink")
    ok(f"{call.__name__.upper()} describes the link itself (size {a.st_size}, secret is {secret_size})")
EOF
