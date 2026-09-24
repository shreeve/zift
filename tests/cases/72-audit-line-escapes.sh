#!/usr/bin/env bash
# Test: partner filenames cannot split or reorder audit lines
# NEL, LINE SEPARATOR and RIGHT-TO-LEFT OVERRIDE in a name are escaped,
# so every line is one JSON object and the path round-trips.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
mkdir -p "$TEST_TMP/data"
AUDIT="$TEST_TMP/audit.jsonl"
write_config <<EOF
$(config_head "log $AUDIT")

user ally
  auth $(make_password_hash secret)
  root $TEST_TMP/data
  allow / read write list
EOF
start_zift

"$PY" - <<'EOF'
from client import *
sftp = connect("ally")
for name in ["/a\u0085b.txt", "/c d.txt", "/e‮f.txt"]:
    with sftp.open(name, "w") as f:
        f.write(b"x")
EOF
stop_zift TERM

"$PY" - "$AUDIT" <<'EOF' || fail "audit log is not one JSON object per line"
import json, sys
raw = open(sys.argv[1], "rb").read()
for ch in ("\u0085", " ", "‮"):
    assert ch.encode() not in raw, f"raw {ch!r} in audit log"
text = raw.decode()
lines = text.split("\n")[:-1]
assert text.splitlines() == lines, "splitlines disagrees with \\n framing"
paths = {json.loads(l).get("path") for l in lines}
for want in ("/a\u0085b.txt", "/c d.txt", "/e‮f.txt"):
    assert want in paths, f"{want!r} not audited; saw {paths}"
EOF
ok "C1, line-separator and bidi characters are escaped and round-trip"
