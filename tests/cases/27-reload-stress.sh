#!/usr/bin/env bash
# Test: SIGHUP-driven reloads under traffic do not disrupt sessions, and
#       the new config is observable to sessions opened afterwards
# A burst of reloads must not corrupt the config snapshot.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
runner_hash=$(make_password_hash secret)
later_hash=$(make_password_hash later-secret)
mkdir -p "$TEST_TMP/data/uploads" "$TEST_TMP/data2"
runner="user runner
  auth $runner_hash
  root $TEST_TMP/data
  allow / read write list mkdir delete update rename"
write_config <<EOF
$(config_head "reload-interval 0")

$runner
EOF
start_zift

"$PY" - <<'EOF'
import io
from client import *
connect("runner").putfo(io.BytesIO(b"BEFORE_RELOAD"), "/uploads/before.txt")
EOF
ok "a pre-reload session wrote /uploads/before.txt"

write_config <<EOF
$(config_head "reload-interval 0")

$runner

user late
  auth $later_hash
  root $TEST_TMP/data2
  allow / read write list mkdir
EOF
for _ in 1 2 3 4 5; do
    kill -HUP "$ZIFT_PID"
    sleep 0.2
done
wait_for_log 'config reloaded' || fail "no reload after the SIGHUPs"

"$PY" - <<'EOF'
import io
from client import *
connect("late", "later-secret").putfo(io.BytesIO(b"AFTER_RELOAD"), "/added.txt")
EOF
ok "user late, added by the reload, logged in and wrote"

[[ "$(cat "$TEST_TMP/data/uploads/before.txt")" == BEFORE_RELOAD ]] || fail "before payload corrupted"
[[ "$(cat "$TEST_TMP/data2/added.txt")" == AFTER_RELOAD ]] || fail "after payload corrupted"
ok "both payloads landed in their partner roots"
