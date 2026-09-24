#!/usr/bin/env bash
# Test: `listen [::]:port` binds, serves IPv6 clients, and on a dual-stack
#       socket audits an IPv4 client by its plain IPv4 address
# Oracle: logins over ::1 and 127.0.0.1 both succeed, audited with ip
#         "0:0:0:0:0:0:0:1" and "127.0.0.1".

source "$(dirname "$0")/../lib/common.sh"
need_paramiko
"$PY" -c "import socket; socket.socket(socket.AF_INET6).bind(('::1', 0))" 2>/dev/null \
    || skip "no IPv6 loopback"

make_host_key
basic_config
sed -i.bak "s|listen 127.0.0.1:|listen [::]:|" "$TEST_TMP/zift.conf"
start_zift

"$PY" - <<'EOF'
from client import *
for host in ("::1", "127.0.0.1"):
    if not can_login("ally", "secret", host=host):
        fail(f"login over {host} failed")
ok("logins over ::1 and 127.0.0.1 succeeded")
EOF
log_contains '"operation":"auth.password","result":"ok","ip":"0:0:0:0:0:0:0:1"' || fail "IPv6 login not audited with its address"
log_contains '"operation":"auth.password","result":"ok","ip":"127.0.0.1"' \
    || fail "IPv4 login on the dual-stack socket not audited as 127.0.0.1"
ok "audit ip fields are 0:0:0:0:0:0:0:1 and 127.0.0.1"
