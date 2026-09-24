#!/usr/bin/env bash
# Test: a session holds at most 256 open handles
# Pipelined OPENs that are never closed must not grow a session's memory
# without bound; closing one frees a slot and the session stays usable.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
mkdir -p "$TEST_TMP/data"
for i in $(seq -f '%03g' 1 300); do : > "$TEST_TMP/data/file_$i"; done
write_config <<EOF
$(config_head)

user runner
  auth $(user_key)
  root $TEST_TMP/data
  allow / read list
EOF
start_zift

"$PY" - <<'EOF'
from client import *
sftp = connect("runner")
opened = [sftp.file("/file_%03d" % i, "r") for i in range(1, 257)]
ok(f"opened {len(opened)} handles")
expect("open #257", "failure", sftp.file, "/file_257", "r")
opened.pop(0).close()
opened.append(sftp.file("/file_258", "r"))
ok("closing one handle frees a slot for the next open")
for f in opened:
    f.close()
if len(sftp.listdir("/")) != 300:
    fail("listing broken after the cap")
ok("session usable after the cap")
EOF
