#!/usr/bin/env bash
# Test: an RSA user key logs in with rsa-sha2-256/512 signatures and is
#       refused with a SHA-1 `ssh-rsa` signature.
# Oracle: paramiko logs in with the default (SHA-2) signature; forcing
#         `ssh-rsa` fails and no second auth.publickey ok line appears.
# Skips while the config rejects `ssh-rsa` key lines.

source "$(dirname "$0")/../lib/common.sh"

need_paramiko

make_host_key
ssh-keygen -t rsa -b 3072 -f "$TEST_TMP/rsa_user" -N "" -q
cp "$TEST_TMP/rsa_user.pub" "$TEST_TMP/keys.pub"
chmod 600 "$TEST_TMP/keys.pub"
mkdir -p "$TEST_TMP/data"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user rsa
  auth $TEST_TMP/keys.pub
  root $TEST_TMP/data
  allow / read list
EOF

if ! "$ZIFT_BIN" validate "$TEST_TMP/zift.conf" >/dev/null 2>&1; then
    skip "this build does not accept ssh-rsa key lines"
fi

start_zift

"$PY" - "$TEST_TMP/rsa_user" <<EOF || fail "RSA signature algorithms not enforced (see above)"
import paramiko, socket, sys
from cryptography.hazmat.primitives import hashes

key = paramiko.RSAKey.from_private_key_file(sys.argv[1])

def login(force_sha1):
    t = paramiko.Transport(socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=10))
    t.auth_timeout = 5
    if force_sha1:
        # Paramiko no longer signs with SHA-1 on its own; make it.
        paramiko.RSAKey.HASHES["ssh-rsa"] = hashes.SHA1
        paramiko.auth_handler.AuthHandler._finalize_pubkey_algorithm = lambda self, kt: "ssh-rsa"
    t.start_client(timeout=10)
    try:
        t.auth_publickey("rsa", key)
        return True
    except Exception:
        return False
    finally:
        t.close()

if not login(False):
    print("fail: RSA-3072 key with a SHA-2 signature was refused"); sys.exit(1)
print("ok: RSA-3072 key logs in with a SHA-2 signature")
if login(True):
    print("fail: a SHA-1 ssh-rsa signature was accepted"); sys.exit(1)
print("ok: SHA-1 ssh-rsa signature refused")
EOF

n=$(grep -c '"operation":"auth.publickey","result":"ok"' "$ZIFT_LOG" || true)
[[ "$n" == "1" ]] || fail "expected exactly one successful publickey login, got $n"
ok "only the SHA-2 login succeeded"

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
