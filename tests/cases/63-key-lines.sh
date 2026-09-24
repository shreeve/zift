#!/usr/bin/env bash
# Test: key lines must match their algorithm; RSA keys of 2048+ bits log
#       in with rsa-sha2 signatures and never with SHA-1 `ssh-rsa`
# A mislabelled or truncated key used to validate and then silently
# never match; a SHA-1 signature must not be accepted for any RSA key.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
mkdir -p "$TEST_TMP/root" "$TEST_TMP/keys"
ssh-keygen -q -t rsa -b 2048 -N '' -f "$TEST_TMP/rsa_id"
ssh-keygen -q -t rsa -b 3072 -N '' -f "$TEST_TMP/rsa_3072"
ssh-keygen -q -t rsa -b 1024 -N '' -f "$TEST_TMP/rsa_small" 2>/dev/null
ssh-keygen -q -t ecdsa -b 256 -N '' -f "$TEST_TMP/ecdsa_id"

# keyfile <name> <line...>: a config whose only user key file holds the lines.
keyfile() {
    local name="$1"; shift
    printf '%s\n' "$@" > "$TEST_TMP/keys/$name.pub"
    chmod 0644 "$TEST_TMP/keys/$name.pub"
    write_config "$TEST_TMP/$name.conf" <<EOF
$(config_head)

user ally
  auth $TEST_TMP/keys/$name.pub
  root $TEST_TMP/root
  allow / read list
EOF
}

keyfile mislabelled "ssh-ed25519 $(cut -d' ' -f2 "$TEST_TMP/ecdsa_id.pub")"
validate_err "$TEST_TMP/mislabelled.conf" "the key does not match its algorithm name"
keyfile truncated "ssh-ed25519 AAAA"
validate_err "$TEST_TMP/truncated.conf" "line 1: malformed public-key line"
keyfile small-rsa "$(cat "$TEST_TMP/rsa_small.pub")"
validate_err "$TEST_TMP/small-rsa.conf" "RSA keys must be 2048 to 8192 bits"
keyfile dsa "ssh-dss AAAAB3NzaC1kc3MAAAA legacy"
validate_err "$TEST_TMP/dsa.conf" "unsupported algorithm"
ok "mislabelled, truncated, 1024-bit RSA and DSA key lines are rejected"

keyfile rsa "$(cat "$TEST_TMP/rsa_id.pub")" "$(cat "$TEST_TMP/rsa_3072.pub")"
validate_ok "$TEST_TMP/rsa.conf"
ok "ssh-rsa 2048- and 3072-bit key lines validate"

start_zift "$TEST_TMP/rsa.conf"
sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes \
    -o PubkeyAcceptedAlgorithms=rsa-sha2-512,rsa-sha2-256 \
    -i "$TEST_TMP/rsa_id" -P "$TEST_PORT" ally@127.0.0.1 <<<'ls' >"$TEST_TMP/sftp.out" 2>&1 \
    || fail "OpenSSH RSA-2048 key login failed: $(cat "$TEST_TMP/sftp.out")"
ok "OpenSSH logs in with an RSA-2048 key and rsa-sha2"

"$PY" - "$TEST_TMP/rsa_3072" <<'EOF'
import socket, sys, paramiko
from cryptography.hazmat.primitives import hashes
from client import *
key = paramiko.RSAKey.from_private_key_file(sys.argv[1])
if not can_login("ally", key=key):
    fail("RSA-3072 key with a SHA-2 signature was refused")
ok("paramiko logs in with an RSA-3072 key and a SHA-2 signature")
# Paramiko no longer signs with SHA-1 on its own; make it.
paramiko.RSAKey.HASHES["ssh-rsa"] = hashes.SHA1
paramiko.auth_handler.AuthHandler._finalize_pubkey_algorithm = lambda self, kt: "ssh-rsa"
t = paramiko.Transport(socket.create_connection(("127.0.0.1", PORT), timeout=10))
t.auth_timeout = 3  # the server sends no reply at all to this request
t.start_client(timeout=10)
try:
    t.auth_publickey("ally", key)
    fail("a SHA-1 ssh-rsa signature was accepted")
except (paramiko.SSHException, EOFError):
    pass  # refused, timed out or disconnected: not logged in
t.close()
ok("a SHA-1 ssh-rsa signature is refused")
EOF

[[ $(count_log '"operation":"auth.publickey","result":"ok","detail":"ssh-rsa"') == 2 ]] \
    || fail "expected exactly the two SHA-2 logins to succeed: $(grep auth.publickey "$ZIFT_LOG")"
ok "only the two SHA-2 logins succeeded"
