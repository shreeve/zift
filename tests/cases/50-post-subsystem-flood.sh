#!/usr/bin/env bash
# Test: SSH requests after the sftp subsystem starts are refused and
#       freed, not queued: memory stays bounded and SFTP keeps working
# libssh queues every unconsumed message, so an env/exec/pty-req/
# channel-open/tcpip-forward flood would otherwise grow without bound.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
mkdir -p "$TEST_TMP/jail"
write_config <<EOF
$(config_head "idle-timeout 60s")

user flood
  auth $(make_password_hash secret)
  root $TEST_TMP/jail
  allow / full
EOF
start_zift

rc=0
"$PY" "$LIB_DIR/probe_channel_flood.py" --user flood --pid "$ZIFT_PID" || rc=$?
kill -0 "$ZIFT_PID" 2>/dev/null || fail "zift exited during the flood"
case "$rc" in
    0) ok "flood refused with bounded memory" ;;
    2) fail "a flood check failed; see above" ;;
    *) fail "probe environment error (rc=$rc)" ;;
esac
