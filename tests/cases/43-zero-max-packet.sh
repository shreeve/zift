#!/usr/bin/env bash
# Test: a channel open advertising max packet size 0 is refused promptly
# Regression for libssh CVE-2026-59843: it sent the server into an
# unbounded packetization loop. The server must stay responsive.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
mkdir -p "$TEST_TMP/data"
write_config <<EOF
$(config_head "idle-timeout 2s")

user partner
  auth $(make_password_hash secret)
  root $TEST_TMP/data
  allow / read list
EOF
start_zift

"$PY" - <<'EOF'
import time, paramiko
from client import *
t = transport("partner")
# Paramiko clamps this field; override the client-side guard only to put
# the malicious value on the wire.
sanitize = t._sanitize_packet_size
t._sanitize_packet_size = lambda value: 0 if value is None else sanitize(value)
started = time.monotonic()
try:
    t.open_session(timeout=3).invoke_subsystem("sftp")
    fail("server accepted a channel advertising max-packet-size=0")
except (EOFError, OSError, paramiko.SSHException):
    pass
elapsed = time.monotonic() - started
t.close()
if elapsed >= 3.0:
    fail(f"the malformed channel took {elapsed:.2f}s to refuse")
ok(f"zero max-packet channel refused in {elapsed:.2f}s")

if connect("partner").listdir("/") != []:
    fail("a clean session after the malformed one misbehaved")
ok("server remains responsive")
EOF
