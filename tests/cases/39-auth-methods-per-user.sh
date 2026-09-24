#!/usr/bin/env bash
# Test: a password-only user is offered only `password`, so a client
#       holding a key never tries it; an unknown user is offered both
# Keeps "no keys configured" noise out of the audit log, while unknown
# users still look like users with keys (no username probing by methods).

source "$(dirname "$0")/../lib/common.sh"

make_host_key
basic_config
start_zift

# A client that would offer this (unconfigured) key before a password.
ssh-keygen -q -t ed25519 -N '' -f "$TEST_TMP/test_id"
export SFTP_OPTS="-o PreferredAuthentications=publickey,password -o IdentityAgent=none -o IdentitiesOnly=yes -i $TEST_TMP/test_id"

sftp_password ally secret >"$TEST_TMP/client.log" 2>&1 || fail "password login failed: $(cat "$TEST_TMP/client.log")"
log_contains '"user":"ally","operation":"auth.password","result":"ok"' || fail "no auth.password ok line"
ok "password auth succeeded"
[[ $(count_log '"user":"ally","operation":"auth.publickey"') == 0 ]] \
    || fail "the client tried its key: publickey was advertised to a password-only user"
ok "no publickey attempt for a password-only user"

sftp_password nobody anything >"$TEST_TMP/unknown.log" 2>&1 && fail "an unknown user logged in"
(($(count_log '"user":"nobody","operation":"auth.publickey"') >= 1)) \
    || fail "no publickey attempt for an unknown user: publickey is no longer advertised to them"
ok "an unknown user is still offered publickey"
