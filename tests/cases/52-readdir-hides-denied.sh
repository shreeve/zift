#!/usr/bin/env bash
# Test: READDIR lists only what STAT would allow and what a request could
#       name, and long names and user names are never truncated
# A listing must not leak denied names (`deny **/.ssh/**`), nor show a
# name no request could carry, nor clip a 255-byte name or 64-byte user.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
user=$(printf 'p%.0s' $(seq 64))
mkdir -p "$TEST_TMP/jail/.ssh" "$TEST_TMP/jail/inbox"
echo key > "$TEST_TMP/jail/.ssh/id_ed25519"
echo keys > "$TEST_TMP/jail/.ssh/authorized_keys"
echo secret > "$TEST_TMP/jail/inbox/secret.pdf"
echo public > "$TEST_TMP/jail/inbox/public.txt"
: > "$TEST_TMP/jail/inbox/bad"$'\x01'"name"
: > "$TEST_TMP/jail/inbox/$(printf 'L%.0s' $(seq 255))"
write_config <<EOF
$(config_head)

user $user
  auth $(make_password_hash secret)
  root $TEST_TMP/jail
  allow / read list
  deny **/.ssh/**
  deny /inbox/secret.pdf
EOF
start_zift

"$PY" - "$user" <<'EOF'
import sys
from client import *
user = sys.argv[1]
sftp = connect(user)
if sftp.listdir("/.ssh"):
    fail(f"denied key names listed: {sftp.listdir('/.ssh')}")
ok("deny **/.ssh/** hides key names from the .ssh listing")

names = sftp.listdir("/inbox")
if "secret.pdf" in names or "public.txt" not in names:
    fail(f"/inbox lists {names}")
ok("a denied file is missing from its parent listing")
expect("STAT of the denied file", "denied", sftp.stat, "/inbox/secret.pdf")

if any("\x01" in n for n in names):
    fail(f"control-byte name listed: {names!r}")
ok("a name no request could carry is hidden")

long = "L" * 255
attrs = {a.filename: a for a in sftp.listdir_attr("/inbox")}
if long not in attrs:
    fail(f"255-byte name missing or truncated: {sorted(len(n) for n in attrs)}")
line = attrs[long].longname
if not line.endswith(" " + long) or user not in line:
    fail(f"longname truncated ({len(line)} bytes): {line!r}")
ok("255-byte name and 64-byte user appear in full in the longname")
EOF
