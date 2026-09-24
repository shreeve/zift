#!/usr/bin/env bash
# Test: SSH_FXP_OPEN must not write through a symlink that escapes the jail
# A stray symlink in an upload area, as the final component or as a
# parent directory, must not let a partner write outside the root. The
# partner holds `update`, so the clobber rule cannot be what refuses it.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
echo "OUTSIDE-SECRET-CONTENT" > "$TEST_TMP/outside_secret.txt"
mkdir -p "$TEST_TMP/jail/inbox" "$TEST_TMP/outside_dir"
ln -s "$TEST_TMP/outside_secret.txt" "$TEST_TMP/jail/inbox/innocent.txt"
ln -s "$TEST_TMP/outside_dir" "$TEST_TMP/jail/inbox/escape"

write_config <<EOF
$(config_head)

user partner
  auth $(user_key)
  root $TEST_TMP/jail
  allow /inbox write update list mkdir
EOF
start_zift

"$PY" - <<'EOF'
import io
from client import *
sftp = connect("partner")
put = lambda path: sftp.putfo(io.BytesIO(b"ATTACKER-OVERWRITE\n"), path)
expect("put over a symlink to an outside file", "denied", put, "/inbox/innocent.txt")
expect("put through a symlinked parent dir", "denied", put, "/inbox/escape/x")
expect("put into a fresh file (control)", "ok", put, "/inbox/fresh.txt")
EOF

[[ "$(cat "$TEST_TMP/outside_secret.txt")" == "OUTSIDE-SECRET-CONTENT" ]] \
    || fail "symlink escape succeeded: outside-jail file was overwritten"
[[ -z "$(ls -A "$TEST_TMP/outside_dir")" ]] || fail "a file was created outside the jail"
ok "nothing outside the jail changed"

for path in /inbox/innocent.txt /inbox/escape/x; do
    log_contains "\"operation\":\"open_write\",\"result\":\"denied\",\"path\":\"$path\"" \
        || fail "no open_write denial audited for $path"
done
[[ $(count_log '"operation":"open_write","result":"ok"') == 1 ]] \
    || fail "expected only the control upload to be allowed"
ok "both escapes audited as denied"
