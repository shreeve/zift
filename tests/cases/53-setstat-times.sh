#!/usr/bin/env bash
# Test: SETSTAT/FSETSTAT set atime/mtime under `update` (or on the
#       partner's own write handle), ignore modes and owners, and refuse
#       size changes
# Oracle: `put -p` keeps the local mtime, including a new upload into a
#         write-only drop; paramiko utime works under update and is denied
#         without it; chmod is a no-op; truncate is OP_UNSUPPORTED; a
#         symlink's target is never touched

source "$(dirname "$0")/../lib/common.sh"

PY="$(dirname "$0")/../.venv/bin/python3"
if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)

mkdir -p "$TEST_TMP/jail/inbox" "$TEST_TMP/jail/drop" "$TEST_TMP/jail/ro" "$TEST_TMP/local"
echo readonly > "$TEST_TMP/jail/ro/file.txt"
echo target > "$TEST_TMP/jail/inbox/target.txt"
ln -s target.txt "$TEST_TMP/jail/inbox/link"
echo local > "$TEST_TMP/local/p.txt"
# 2001-02-03 04:05:06 UTC
touch -t 200102030405.06 "$TEST_TMP/local/p.txt"
want_mtime=$("$PY" -c "import os,sys; print(int(os.stat(sys.argv[1]).st_mtime))" "$TEST_TMP/local/p.txt")

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user runner
  auth $hash
  root $TEST_TMP/jail
  allow / list
  allow /inbox read write list update
  allow /drop write
  allow /ro read list
EOF

start_zift

sftp_password runner secret \
    "put -p $TEST_TMP/local/p.txt /inbox/p.txt" \
    "put -p $TEST_TMP/local/p.txt /drop/p.txt" \
    >"$TEST_TMP/put.log" 2>&1 || true

mtime_of() { "$PY" -c "import os,sys; print(int(os.stat(sys.argv[1]).st_mtime))" "$1"; }
[[ -f "$TEST_TMP/jail/inbox/p.txt" ]] || { cat "$TEST_TMP/put.log"; fail "put -p to /inbox did not land"; }
[[ "$(mtime_of "$TEST_TMP/jail/inbox/p.txt")" == "$want_mtime" ]] \
    || fail "put -p did not keep the mtime in /inbox ($(mtime_of "$TEST_TMP/jail/inbox/p.txt") != $want_mtime)"
ok "put -p keeps the local mtime"
[[ -f "$TEST_TMP/jail/drop/p.txt" ]] || { cat "$TEST_TMP/put.log"; fail "put -p to /drop did not land"; }
[[ "$(mtime_of "$TEST_TMP/jail/drop/p.txt")" == "$want_mtime" ]] \
    || fail "put -p into a write-only drop did not keep the mtime"
ok "put -p into a write-only drop keeps the mtime (FSETSTAT on the upload handle)"

"$PY" - "$TEST_PORT" "$TEST_TMP/jail" <<'EOF'
import errno, os, socket, stat, sys
import paramiko

port, jail = int(sys.argv[1]), sys.argv[2]
sock = socket.create_connection(("127.0.0.1", port), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="runner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)

def fail(msg):
    print(f"  fail: {msg}")
    sys.exit(1)

def host(p):
    return os.lstat(os.path.join(jail, p.lstrip("/")))

sftp.utime("/inbox/p.txt", (1000000000, 1100000000))
if int(host("/inbox/p.txt").st_mtime) != 1100000000:
    fail("utime under update did not set mtime")
print("  ok: SETSTAT sets mtime where the partner holds update")

try:
    sftp.utime("/ro/file.txt", (1, 2))
    fail("utime without update succeeded")
except PermissionError:
    pass
if int(host("/ro/file.txt").st_mtime) == 2:
    fail("denied utime still changed the file")
print("  ok: SETSTAT without update is denied")

before = stat.S_IMODE(host("/inbox/p.txt").st_mode)
sftp.chmod("/inbox/p.txt", 0o777)
if stat.S_IMODE(host("/inbox/p.txt").st_mode) != before:
    fail("chmod changed the host mode")
print("  ok: SETSTAT of permissions is a no-op that succeeds")

try:
    sftp.truncate("/inbox/p.txt", 0)
    fail("truncate via SETSTAT succeeded")
except IOError as e:
    if isinstance(e, (PermissionError, FileNotFoundError)):
        fail(f"truncate got the wrong error: {e!r}")
if host("/inbox/p.txt").st_size == 0:
    fail("truncate changed the size")
print("  ok: SETSTAT of size is refused")

target_mtime = int(host("/inbox/target.txt").st_mtime)
sftp.utime("/inbox/link", (5, 6))
if int(host("/inbox/target.txt").st_mtime) != target_mtime:
    fail("SETSTAT followed the symlink")
print("  ok: SETSTAT does not follow a final symlink")

try:
    sftp.utime("/inbox/missing.txt", (1, 2))
    fail("utime of a missing file succeeded")
except FileNotFoundError:
    pass
try:
    sftp.utime("/drop/missing.txt", (1, 2))
    fail("utime in a write-only drop succeeded")
except PermissionError:
    pass
print("  ok: missing paths are NO_SUCH_FILE only where the partner may stat")

with sftp.open("/inbox/p.txt", "r") as f:
    f.utime((1200000000, 1200000000))
if int(host("/inbox/p.txt").st_mtime) != 1200000000:
    fail("FSETSTAT on a read handle under update did not set mtime")
with sftp.open("/ro/file.txt", "r") as f:
    try:
        f.utime((3, 4))
        fail("FSETSTAT on a read handle without update succeeded")
    except PermissionError:
        pass
    try:
        f.truncate(0)
        fail("FSETSTAT of size succeeded")
    except IOError as e:
        if isinstance(e, PermissionError):
            fail(f"truncate got the wrong error: {e!r}")
print("  ok: FSETSTAT follows the same rules on read handles")

sftp.close()
t.close()
EOF

grep -q '"operation":"fsetstat","result":"ok","path":"/drop/p.txt"' "$ZIFT_LOG" \
    || fail "no fsetstat audit line for the drop upload"
grep -q '"operation":"setstat","result":"denied","path":"/ro/file.txt"' "$ZIFT_LOG" \
    || fail "no denied setstat audit line"
ok "SETSTAT and FSETSTAT are audited"

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
