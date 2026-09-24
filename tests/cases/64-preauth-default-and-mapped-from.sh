#!/usr/bin/env bash
# Test: an unset max-unauth-connections defaults to max-connections / 4,
#       and `from ::ffff:a.b.c.d` admits the same peer seen as IPv4
# Covers: S-03 default pre-auth cap (silent sockets cannot hold every
#         slot); explicit 0 still turns the cap off; C26 IPv4-mapped
#         `from` matching a plain IPv4 peer.

source "$(dirname "$0")/../lib/common.sh"

need_paramiko

make_host_key
mkdir -p "$TEST_TMP/root"
hash=$(make_password_hash secret)

# serve_with <extra server lines> <from line>
serve_with() {
    : > "$TEST_TMP/audit.jsonl"
    write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  idle-timeout 5s
  shutdown-grace 1s
  log $TEST_TMP/audit.jsonl
$1
user runner
  auth $hash
  root $TEST_TMP/root
$2
  allow / read list
EOF
    start_zift
}

# Hold two silent TCP connections (never speaking SSH), then probe a third.
probe_silent() {
    "$PY" - <<EOF
import socket, time
held = [socket.create_connection(("127.0.0.1", $TEST_PORT)) for _ in range(2)]
time.sleep(0.6)
s = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=2)
try: s.recv(64)
except Exception: pass
s.close()
time.sleep(0.3)
for h in held: h.close()
EOF
}

cap_hits() {
    grep -Fc '"detail":"max-unauth-connections reached"' "$TEST_TMP/audit.jsonl" || true
}

# ---------- default: max-connections 8 → pre-auth cap 2 ----------
serve_with "  max-connections 8" ""
probe_silent
sleep 0.5
[[ $(cap_hits) -ge 1 ]] || fail "default cap: third silent connection was not refused; audit: $(cat "$TEST_TMP/audit.jsonl")"
ok "unset max-unauth-connections caps pre-auth sessions at max-connections / 4"
stop_zift TERM
sleep 1.5

# ---------- explicit 0 keeps the cap off ----------
serve_with "  max-connections 8
  max-unauth-connections 0" ""
probe_silent
sleep 0.5
[[ $(cap_hits) == 0 ]] || fail "explicit 0: pre-auth cap fired: $(cat "$TEST_TMP/audit.jsonl")"
ok "explicit max-unauth-connections 0 still means no separate cap"
stop_zift TERM
sleep 1.5

# ---------- from ::ffff:127.0.0.1 admits the IPv4 peer 127.0.0.1 ----------
login() {
    "$PY" - <<EOF
import socket, sys, paramiko
sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
try:
    t.connect(username="runner", password="secret")
    paramiko.SFTPClient.from_transport(t).listdir("/")
    print("ok")
except paramiko.AuthenticationException:
    print("denied")
finally:
    t.close()
EOF
}

serve_with "" "  from ::ffff:127.0.0.1"
[[ $(login) == ok ]] || fail "from ::ffff:127.0.0.1 did not admit 127.0.0.1: $(tail -5 "$TEST_TMP/audit.jsonl")"
ok "from ::ffff:127.0.0.1 admits the peer 127.0.0.1"
stop_zift TERM
sleep 1.5

serve_with "" "  from ::ffff:10.9.8.7"
[[ $(login) == denied ]] || fail "from ::ffff:10.9.8.7 admitted 127.0.0.1"
ok "from ::ffff:10.9.8.7 still refuses 127.0.0.1"
stop_zift TERM
