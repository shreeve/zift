#!/usr/bin/env bash
# Test: SSH_FXP_OPEN must not write through a symlink that escapes the jail
# A stray symlink in an upload area must not let a partner overwrite a
# file outside the root.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
echo "OUTSIDE-SECRET-CONTENT" > "$TEST_TMP/outside_secret.txt"
mkdir -p "$TEST_TMP/jail/inbox"
ln -s "$TEST_TMP/outside_secret.txt" "$TEST_TMP/jail/inbox/innocent.txt"

write_config <<EOF
$(config_head)

user partner
  auth $(make_password_hash secret)
  root $TEST_TMP/jail
  allow /inbox write list mkdir
EOF
start_zift

"$PY" - <<'EOF'
import io
from client import *
sftp = connect("partner")
if outcome(sftp.putfo, io.BytesIO(b"ATTACKER-OVERWRITE\n"), "/inbox/innocent.txt") == "ok":
    fail("put over the symlink succeeded")
ok("put over a symlink to an outside file refused")
EOF

[[ "$(cat "$TEST_TMP/outside_secret.txt")" == "OUTSIDE-SECRET-CONTENT" ]] \
    || fail "symlink escape succeeded: outside-jail file was overwritten"
ok "outside-jail secret file is untouched"
log_contains '"operation":"open_write","result":"ok"' && fail "server allowed open_write through the symlink"
log_contains '"operation":"open_write","result":"denied"' || log_contains '"operation":"open_write","result":"failed"' \
    || fail "no open_write audit line"
ok "server logged the open_write refusal"
