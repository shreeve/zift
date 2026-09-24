#!/usr/bin/env bash
# Test: SETSTAT/FSETSTAT set atime/mtime under `update` (or on the
#       partner's own write handle), ignore modes and owners, and refuse
#       size changes
# `put -p` must keep mtimes, even into a write-only drop, without
# letting SETSTAT truncate, chmod, or reach through a symlink.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
mkdir -p "$TEST_TMP/jail/inbox" "$TEST_TMP/jail/drop" "$TEST_TMP/jail/ro" "$TEST_TMP/local"
echo readonly > "$TEST_TMP/jail/ro/file.txt"
echo target > "$TEST_TMP/jail/inbox/target.txt"
ln -s target.txt "$TEST_TMP/jail/inbox/link"
echo local > "$TEST_TMP/local/p.txt"
touch -t 200102030405.06 "$TEST_TMP/local/p.txt"
mtime_of() { "$PY" -c "import os,sys; print(int(os.stat(sys.argv[1]).st_mtime))" "$1"; }
want_mtime=$(mtime_of "$TEST_TMP/local/p.txt")

write_config <<EOF
$(config_head)

user runner
  auth $(make_password_hash secret)
  auth $(user_key)
  root $TEST_TMP/jail
  allow / list
  allow /inbox read write list update
  allow /drop write
  allow /ro read list
EOF
start_zift

sftp_password runner secret "put -p $TEST_TMP/local/p.txt /inbox/p.txt" \
    "put -p $TEST_TMP/local/p.txt /drop/p.txt" >"$TEST_TMP/put.log" 2>&1 || fail "put -p session failed"
for dir in inbox drop; do
    [[ -f "$TEST_TMP/jail/$dir/p.txt" ]] || fail "put -p to /$dir did not land: $(cat "$TEST_TMP/put.log")"
    [[ "$(mtime_of "$TEST_TMP/jail/$dir/p.txt")" == "$want_mtime" ]] || fail "put -p did not keep the mtime in /$dir"
done
ok "put -p keeps the local mtime, also into a write-only drop (FSETSTAT on the upload handle)"

"$PY" - <<'EOF'
import os, stat
from client import *
sftp = connect("runner")
st = lambda p: os.lstat(host("jail" + p))

sftp.utime("/inbox/p.txt", (1000000000, 1100000000))
if int(st("/inbox/p.txt").st_mtime) != 1100000000:
    fail("utime under update did not set mtime")
ok("SETSTAT sets mtime where the partner holds update")
expect("SETSTAT without update", "denied", sftp.utime, "/ro/file.txt", (1, 2))
if int(st("/ro/file.txt").st_mtime) == 2:
    fail("the denied utime still changed the file")

before = stat.S_IMODE(st("/inbox/p.txt").st_mode)
sftp.chmod("/inbox/p.txt", 0o777)
if stat.S_IMODE(st("/inbox/p.txt").st_mode) != before:
    fail("chmod changed the host mode")
ok("SETSTAT of permissions is a no-op that succeeds")
expect("SETSTAT of size", "failure", sftp.truncate, "/inbox/p.txt", 0)
if st("/inbox/p.txt").st_size == 0:
    fail("truncate changed the size")

target_mtime = int(st("/inbox/target.txt").st_mtime)
sftp.utime("/inbox/link", (5, 6))
if int(st("/inbox/target.txt").st_mtime) != target_mtime:
    fail("SETSTAT followed the symlink")
ok("SETSTAT does not follow a final symlink")

expect("SETSTAT of a missing file where the partner may stat", "missing", sftp.utime, "/inbox/missing.txt", (1, 2))
expect("SETSTAT of a missing file in a write-only drop", "denied", sftp.utime, "/drop/missing.txt", (1, 2))

with sftp.open("/inbox/p.txt", "r") as f:
    f.utime((1200000000, 1200000000))
if int(st("/inbox/p.txt").st_mtime) != 1200000000:
    fail("FSETSTAT on a read handle under update did not set mtime")
with sftp.open("/ro/file.txt", "r") as f:
    expect("FSETSTAT on a read handle without update", "denied", f.utime, (3, 4))
    expect("FSETSTAT of size", "failure", f.truncate, 0)
ok("FSETSTAT follows the same rules on read handles")
EOF

log_contains '"operation":"fsetstat","result":"ok","path":"/drop/p.txt"' || fail "no fsetstat audit line for the drop upload"
log_contains '"operation":"setstat","result":"denied","path":"/ro/file.txt"' || fail "no denied setstat audit line"
ok "SETSTAT and FSETSTAT are audited"
