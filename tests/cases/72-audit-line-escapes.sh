#!/usr/bin/env bash
# Test: partner filenames cannot split or reorder audit lines
# Covers: audit.zig encodeChar escaping of C1 controls, U+2028/U+2029
#         and bidi overrides.
# Oracle: after uploading files whose names carry NEL, LINE SEPARATOR and
#         RIGHT-TO-LEFT OVERRIDE, every audit line is one JSON object
#         (Python's splitlines, which honors those characters, agrees
#         with a split on \n), the raw characters never appear, and the
#         decoded path round-trips.

source "$(dirname "$0")/../lib/common.sh"

VENV="$(dirname "$0")/../.venv"
PY="$VENV/bin/python3"
if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing at $VENV"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)
mkdir -p "$TEST_TMP/data"
AUDIT="$TEST_TMP/audit.jsonl"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log $AUDIT

user ally
  auth $hash
  root $TEST_TMP/data
  allow / read write list
EOF

start_zift

"$PY" - <<PY || fail "upload of oddly named files failed"
import paramiko, socket
sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="ally", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)
for name in ["/a\u0085b.txt", "/c d.txt", "/e‮f.txt"]:
    with sftp.open(name, "w") as f:
        f.write(b"x")
sftp.close(); t.close()
PY

stop_zift TERM
sleep 1

"$PY" - "$AUDIT" <<'PY' || fail "audit log is not one JSON object per line"
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
PY
ok "C1, line-separator and bidi characters are escaped and round-trip"
