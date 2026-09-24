#!/usr/bin/env bash
# Test: idle-timeout reaps pre-auth clients, freeing max-connections slots
# Sockets that never speak SSH (one reads the banner, one reads nothing)
# must not pin every slot: once reaped, a real partner gets in.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
# Pre-auth cap off: this case is about max-connections alone.
basic_config "idle-timeout 1s" "max-connections 2" "max-unauth-connections 0"
start_zift

# `stuck reader` reads until the server closes; `stuck silent` never
# reads and holds its socket until the case ends.
stuck() {
    python3 - "$TEST_PORT" "$1" "$TEST_TMP/release" <<'EOF'
import os, socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
s.settimeout(15)
if sys.argv[2] == "reader":
    while s.recv(4096):
        pass
else:
    while not os.path.exists(sys.argv[3]):
        time.sleep(0.05)
EOF
}
bg stuck reader
bg stuck silent
wait_for_count '"operation":"handshake.failed"' 2 || fail "stuck clients were not reaped"
ok "both stuck pre-auth clients reaped"

# The audit line comes just before the slot is released; allow a retry.
legit() { sftp_password ally secret "ls" >"$TEST_TMP/legit.log" 2>&1; }
wait_until 5 legit || fail "legit client refused after the reaping: $(cat "$TEST_TMP/legit.log")"
[[ $(count_log '"operation":"auth.password","result":"ok"') == 1 ]] \
    || fail "expected exactly one auth.password ok"
ok "legit client connected: the pre-auth slots were freed"
touch "$TEST_TMP/release"
wait_bg || fail "a stuck client errored"
