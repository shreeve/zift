#!/usr/bin/env bash
# Test: the clobber rule: `write` creates new files only; replacing,
#       modifying or appending to an existing file, by OPEN or by RENAME,
#       also needs `update`
# A drop-box partner must not destroy what the operator or another
# partner already placed. Granting `update` restores every path.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
hash=$(make_password_hash secret)
for who in dropper renamer updater; do
    mkdir -p "$TEST_TMP/$who"
    echo "OPERATOR-CONTRACT-VERSION-1" > "$TEST_TMP/$who/contract.csv"
    echo "EXISTING-LOG-LINE-1" > "$TEST_TMP/$who/operator.log"
done
write_config <<EOF
$(config_head)

user dropper
  auth $hash
  root $TEST_TMP/dropper
  allow / read list write

user renamer
  auth $hash
  root $TEST_TMP/renamer
  allow / read list write rename

user updater
  auth $hash
  root $TEST_TMP/updater
  allow / read list write rename update
EOF
start_zift

"$PY" - <<'EOF'
import io
from client import *

def put(sftp, path, data=b"ATTACKER-CONTROLLED"):
    sftp.putfo(io.BytesIO(data), path)

def pwrite(sftp, path, mode):
    with sftp.file(path, mode) as f:
        if mode == "r+b":
            f.seek(5)
        f.write(b"DEFACED")

def untouched(root):
    if read(f"{root}/contract.csv") != b"OPERATOR-CONTRACT-VERSION-1\n":
        fail(f"{root}/contract.csv was modified")
    if read(f"{root}/operator.log") != b"EXISTING-LOG-LINE-1\n":
        fail(f"{root}/operator.log was modified")

# write only: every clobber path is refused.
sftp = connect("dropper")
expect("write-only: truncate-overwrite (OPEN write|creat|trunc)", "denied", put, sftp, "/contract.csv")
expect("write-only: partial overwrite (OPEN write)", "denied", pwrite, sftp, "/contract.csv", "r+b")
expect("write-only: append (OPEN write|append)", "denied", pwrite, sftp, "/operator.log", "ab")
put(sftp, "/attack.csv")
expect("write-only: rename over an existing file (no rename verb)", "denied",
       sftp.rename, "/attack.csv", "/contract.csv")
untouched("dropper")
expect("write-only: creating a new file", "ok", put, sftp, "/new-upload.csv", b"new")

# write + rename, no update: rename may move, never replace.
sftp = connect("renamer")
put(sftp, "/attack.csv")
expect("write+rename: rename over an existing file", "denied", sftp.rename, "/attack.csv", "/contract.csv")
untouched("renamer")
expect("write+rename: rename to a free name", "ok", sftp.rename, "/attack.csv", "/moved.csv")

# write + rename + update: every path works.
sftp = connect("updater")
expect("with update: truncate-overwrite", "ok", put, sftp, "/contract.csv", b"NEW-CONTRACT-V2")
expect("with update: append", "ok", pwrite, sftp, "/operator.log", "ab")
put(sftp, "/replacement.csv", b"REPLACEMENT")
expect("with update: rename over an existing file", "ok", sftp.rename, "/replacement.csv", "/contract.csv")
if read("updater/contract.csv") != b"REPLACEMENT" or read("updater/operator.log") != b"EXISTING-LOG-LINE-1\nDEFACED":
    fail("the update paths did not write what they said")
ok("update restores overwrite, append and rename-over")
EOF
