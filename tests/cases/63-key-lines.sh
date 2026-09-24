#!/usr/bin/env bash
# Test: key lines must match their algorithm; RSA keys of 2048+ bits log in
# Covers: a mislabelled or truncated key blob is rejected by validate (it
#         used to validate and then silently never match); ssh-rsa key
#         lines are accepted at >= 2048 bits and rejected below; an RSA
#         key login succeeds (rsa-sha2 signatures).

source "$(dirname "$0")/../lib/common.sh"

make_host_key
mkdir -p "$TEST_TMP/root" "$TEST_TMP/keys"
ssh-keygen -q -t rsa -b 2048 -N '' -f "$TEST_TMP/rsa_id"
ssh-keygen -q -t rsa -b 1024 -N '' -f "$TEST_TMP/rsa_small" 2>/dev/null
ssh-keygen -q -t ecdsa -b 256 -N '' -f "$TEST_TMP/ecdsa_id"

keyfile() {
    printf '%s\n' "$2" > "$TEST_TMP/keys/$1.pub"
    chmod 0644 "$TEST_TMP/keys/$1.pub"
    cat > "$TEST_TMP/$1.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user ally
  auth $TEST_TMP/keys/$1.pub
  root $TEST_TMP/root
  allow / read list
EOF
    set +e
    "$ZIFT_BIN" validate "$TEST_TMP/$1.conf" >"$TEST_TMP/v.out" 2>"$TEST_TMP/v.err"
    local rc=$?
    set -e
    return $rc
}

expect_reject() {
    local name="$1" line="$2" want="$3"
    keyfile "$name" "$line" && fail "$name: validate accepted it"
    grep -Fq "$want" "$TEST_TMP/v.err" || fail "$name: expected '$want', got: $(cat "$TEST_TMP/v.err")"
    ok "$name rejected: $want"
}

ecdsa_blob=$(cut -d' ' -f2 "$TEST_TMP/ecdsa_id.pub")
expect_reject mislabelled "ssh-ed25519 $ecdsa_blob" "the key does not match its algorithm name"
expect_reject truncated "ssh-ed25519 AAAA" "line 1: malformed public-key line"
expect_reject small-rsa "$(cat "$TEST_TMP/rsa_small.pub")" "RSA keys must be 2048 to 8192 bits"
expect_reject dsa "ssh-dss AAAAB3NzaC1kc3MAAAA legacy" "unsupported algorithm"

keyfile rsa "$(cat "$TEST_TMP/rsa_id.pub")" || fail "rsa 2048: $(cat "$TEST_TMP/v.err")"
ok "ssh-rsa 2048-bit key line validates"

cp "$TEST_TMP/rsa.conf" "$TEST_TMP/zift.conf"
start_zift
set +e
sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes \
    -o PubkeyAcceptedAlgorithms=rsa-sha2-512,rsa-sha2-256 \
    -i "$TEST_TMP/rsa_id" -P "$TEST_PORT" ally@127.0.0.1 <<<'ls' >"$TEST_TMP/sftp.out" 2>&1
rc=$?
set -e
[[ "$rc" == "0" ]] || fail "RSA key login failed (rc=$rc): $(cat "$TEST_TMP/sftp.out")"
grep -q '"operation":"auth.publickey","result":"ok","detail":"ssh-rsa"' "$ZIFT_LOG" \
    || fail "expected an auth.publickey ok (ssh-rsa) audit line: $(grep auth "$ZIFT_LOG")"
ok "RSA key login succeeds with rsa-sha2 signatures"
stop_zift TERM
