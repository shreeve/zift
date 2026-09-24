#!/usr/bin/env bash
# Test: READDIR lists only what STAT would allow and what a request could
#       name, and long names and user names are never truncated
# Oracle: `deny **/.ssh/**` hides key names; a denied file is missing from
#         its parent's listing; a control-byte name is hidden; a 255-byte
#         name shows in full in both name and longname

source "$(dirname "$0")/../lib/common.sh"

need_paramiko

make_host_key
hash=$(make_password_hash secret)
user=$(printf 'p%.0s' $(seq 64))

mkdir -p "$TEST_TMP/jail/.ssh" "$TEST_TMP/jail/inbox"
echo key > "$TEST_TMP/jail/.ssh/id_ed25519"
echo keys > "$TEST_TMP/jail/.ssh/authorized_keys"
echo secret > "$TEST_TMP/jail/inbox/secret.pdf"
echo public > "$TEST_TMP/jail/inbox/public.txt"
"$PY" - "$TEST_TMP/jail/inbox" <<'EOF'
import os, sys
open(os.path.join(sys.argv[1], "bad\x01name"), "w").close()
open(os.path.join(sys.argv[1], "L" * 255), "w").close()
EOF

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user $user
  auth $hash
  root $TEST_TMP/jail
  allow / read list
  deny **/.ssh/**
  deny /inbox/secret.pdf
EOF

start_zift

"$PY" - "$TEST_PORT" "$user" <<'EOF'
import socket, sys
import paramiko

port, user = int(sys.argv[1]), sys.argv[2]
sock = socket.create_connection(("127.0.0.1", port), timeout=15)
t = paramiko.Transport(sock)
t.connect(username=user, password="secret")
sftp = paramiko.SFTPClient.from_transport(t)

def fail(msg):
    print(f"  fail: {msg}")
    sys.exit(1)

keys = sftp.listdir("/.ssh")
if keys:
    fail(f"denied key names listed: {keys}")
print("  ok: deny **/.ssh/** hides key names from the .ssh listing")

names = sftp.listdir("/inbox")
if "secret.pdf" in names:
    fail(f"denied file listed: {names}")
if "public.txt" not in names:
    fail(f"allowed file missing: {names}")
print("  ok: a denied file is missing from its parent listing")

try:
    sftp.stat("/inbox/secret.pdf")
    fail("STAT of the denied file succeeded")
except PermissionError:
    pass

if any("\x01" in n for n in names):
    fail(f"control-byte name listed: {names!r}")
print("  ok: a name no request could carry is hidden")

long = "L" * 255
attrs = {a.filename: a for a in sftp.listdir_attr("/inbox")}
if long not in attrs:
    fail(f"255-byte name missing or truncated: {sorted(len(n) for n in attrs)}")
line = attrs[long].longname
if not line.endswith(" " + long) or user not in line:
    fail(f"longname truncated ({len(line)} bytes): {line!r}")
print("  ok: 255-byte name and 64-byte user appear in full in the longname")

sftp.close()
t.close()
EOF

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
