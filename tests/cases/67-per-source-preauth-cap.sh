#!/usr/bin/env bash
# Test: one source holds at most 8 pre-auth connections; authenticated
#       sessions do not count; refusals are audited once per minute
# One host must not fill max-connections with silent sockets, nor grow
# the audit log at reconnect speed.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
mkdir -p "$TEST_TMP/root"
write_config <<EOF
$(config_head "max-connections 64" "max-unauth-connections 64")

user ally
  auth $(user_key)
  root $TEST_TMP/root
  allow / read list
EOF
start_zift

"$PY" - <<'EOF'
import socket
from client import *
def banner(sock):
    sock.settimeout(3)
    try:
        return sock.recv(64).startswith(b"SSH-")
    except OSError:
        return False
connect_raw = lambda: socket.create_connection(("127.0.0.1", PORT), timeout=5)

# A round trip on each session proves its pre-auth slot was released
# (the release follows the auth success on the same thread).
held = [connect("ally") for _ in range(2)]
for sftp in held:
    sftp.listdir("/")
silent = [connect_raw() for _ in range(8)]
if not all(banner(s) for s in silent):
    fail("one of 8 pre-auth connections was refused")
ok("2 authenticated + 8 pre-auth connections admitted")

for _ in range(11):
    if banner(connect_raw()):
        fail("a 9th pre-auth connection was admitted")
ok("further pre-auth connections refused")

for s in silent:
    s.close()
# Refusals from here on are within the minute, so they add no audit line.
if not wait_for(lambda: banner(connect_raw()), 5):
    fail("slots not released after the silent sockets closed")
ok("slots released")
EOF

n=$(count_log '"operation":"accept.rejected","result":"denied","detail":"too many pre-auth connections from source"')
[[ "$n" == 1 ]] || fail "expected exactly 1 rate-limited rejection line, got $n"
ok "the refusals produced one audit line"
