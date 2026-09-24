#!/usr/bin/env bash
# Test: a session open across five SIGHUP reloads keeps its config
#       snapshot, while new sessions see the new config
# A reload that narrows a partner's rights applies to their next login,
# not mid-session; and rapid reloads must not corrupt the snapshot.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
runner_hash=$(make_password_hash secret)
later_hash=$(make_password_hash later-secret)
mkdir -p "$TEST_TMP/data/uploads" "$TEST_TMP/data2"

v1="user runner
  auth $runner_hash
  root $TEST_TMP/data
  allow / read list
  allow /uploads read write list"
write_config <<EOF
$(config_head "reload-interval 0")

$v1
EOF
start_zift

# v2 drops runner's write on /uploads and adds a user `late`.
write_config "$TEST_TMP/v2.conf" <<EOF
$(config_head "reload-interval 0")

user runner
  auth $runner_hash
  root $TEST_TMP/data
  allow / read list

user late
  auth $later_hash
  root $TEST_TMP/data2
  allow / read write list
EOF

"$PY" - "$ZIFT_PID" "$ZIFT_LOG" <<'EOF'
import io, os, shutil, signal, sys
from client import *
pid, log = int(sys.argv[1]), sys.argv[2]
put = lambda sftp, path, data: sftp.putfo(io.BytesIO(data), path)
reloads = lambda: open(log).read().count("config reloaded")

old = connect("runner")
put(old, "/uploads/before.txt", b"BEFORE_RELOAD")
ok("session opened under v1 wrote /uploads/before.txt")

shutil.copy(os.path.join(TMP, "v2.conf"), os.path.join(TMP, "zift.conf"))
for i in range(1, 6):
    os.kill(pid, signal.SIGHUP)
    if not wait_for(lambda: reloads() >= i):
        fail(f"reload {i} never happened")
    put(old, f"/uploads/during-{i}.txt", b"DURING")
ok("five reloads; the v1 session wrote after each one")

put(old, "/uploads/after.txt", b"AFTER_RELOAD")
if read("data/uploads/after.txt") != b"AFTER_RELOAD":
    fail("the v1 session's post-reload write is wrong on disk")
ok("the v1 session keeps its snapshot: its removed write rule still applies")

new = connect("runner")
expect("a new runner session under v2 writing to /uploads", "denied",
       put, new, "/uploads/new.txt", b"x")

late = connect("late", "later-secret")
put(late, "/added.txt", b"AFTER_RELOAD")
ok("user `late`, added by the reload, logged in and wrote")
for sftp in (old, new, late):
    close(sftp)
EOF

[[ "$(cat "$TEST_TMP/data/uploads/before.txt")" == BEFORE_RELOAD ]] || fail "before payload corrupted"
[[ "$(cat "$TEST_TMP/data2/added.txt")" == AFTER_RELOAD ]] || fail "late's payload corrupted"
[[ ! -e "$TEST_TMP/data/uploads/new.txt" ]] || fail "the v2 session's denied upload landed"
ok "every payload is in its own partner root"
