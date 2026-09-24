#!/usr/bin/env bash
# Test: an RSA host key below 2048 bits still serves
# libssh's RSA_MIN_SIZE also governs signing with the host key; raising
# it made a 1024-bit RSA host key start cleanly and then fail every
# handshake with "Could not sign the session id".

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

mkdir -p "$TEST_TMP/root"
for bits in 1024 3072; do
    rm -f "$HOST_KEY" "$HOST_KEY.pub"
    ssh-keygen -q -t rsa -b "$bits" -N "" -f "$HOST_KEY"
    write_config <<EOF2
$(config_head)

user ally
  auth $(user_key)
  root $TEST_TMP/root
  allow / read list
EOF2
    validate_ok "$TEST_TMP/zift.conf"
    start_zift
    "$PY" - <<'PY' || fail "login with a ${bits}-bit RSA host key failed"
from client import *
sftp = connect("ally")
sftp.listdir("/")
close(sftp)
PY
    ok "${bits}-bit RSA host key: handshake and login"
    stop_zift TERM
done
