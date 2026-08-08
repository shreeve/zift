#!/usr/bin/env bash
# Test: v0.7.1 per-user auth-methods advertisement.
# A password-only user (no `auth /path/...` lines) should cause the
# server to advertise `methods = PASSWORD` only in the
# userauth_failure response, and well-behaved SSH clients should
# therefore skip the publickey-offering phase entirely. The test
# exercises an SSH client that WOULD otherwise offer a key and
# asserts the audit log contains zero `auth.publickey result=denied
# detail="no keys configured"` lines for the resulting session.
#
# v0.7.0 baseline: at least one such line per session — the
# (unwanted) noise this patch removes.
#
# Covers: src/ssh.zig `methodsForUser` + per-user
# `ssh_message_auth_set_methods` call in `authenticate`.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
hash=$(make_password_hash secret)

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user ally
  auth $hash
  root $TEST_TMP
  allow / read list
EOF

start_zift

# Generate a throwaway ed25519 keypair the client will offer. The key
# is NOT in the config, so EVERY publickey attempt against this user
# would be audited as `denied "no keys configured"` on a v0.7.0
# server. v0.7.1 narrows the advertised methods so the client never
# sends a publickey attempt in the first place.
ssh-keygen -t ed25519 -N '' -C 'v071-test' -f "$TEST_TMP/test_id" >/dev/null 2>&1

# Connect with default `PreferredAuthentications` (publickey before
# password) and an explicit identity file. `IdentityAgent=none` and
# `IdentitiesOnly=yes` lock the client to exactly the one key we
# generated, so the test isn't flaky based on the operator's agent
# state. Without v0.7.1's narrowing, the client would try the key
# first, get denied, then fall back to password — producing the
# unwanted audit line. With the narrowing, the client sees
# `methods=password` only and goes straight to the password prompt.
expect <<EOF >"$TEST_TMP/client.log" 2>&1
set timeout 15
spawn sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\
    -o IdentityAgent=none -o IdentitiesOnly=yes -i $TEST_TMP/test_id \\
    -o NumberOfPasswordPrompts=1 \\
    -P $TEST_PORT ally@127.0.0.1
expect "password:"
send "secret\r"
expect "sftp>"
send "bye\r"
expect eof
EOF

stop_zift TERM
sleep 1

# ---------- (1) auth succeeded via password ----------
grep -q '"operation":"auth.password","result":"ok"' "$ZIFT_LOG" \
    || fail "expected one auth.password ok line; tail:\n$(tail -10 "$ZIFT_LOG")"
ok "password auth succeeded"

# ---------- (2) zero pubkey attempts in the audit log ----------
# This is the v0.7.1 invariant. A single "no keys configured" line
# means the server advertised PUBLICKEY in its methods bitmask and
# the client (correctly) tried a key — exactly the behavior the
# patch removes.
pubkey_denied=$(grep -c '"auth.publickey","result":"denied","detail":"no keys configured"' "$ZIFT_LOG" || true)
[[ "$pubkey_denied" -eq "0" ]] \
    || fail "expected 0 'no keys configured' audit lines, got $pubkey_denied; sample:\n$(grep '"auth.publickey"' "$ZIFT_LOG" | head -5)"
ok "v0.7.1 narrowing: no publickey attempts for password-only user (was: ≥1 in v0.7.0)"

# ---------- (3) unknown-user response shape unchanged from v0.7.0 ----------
# Restart with a clean log and try an unknown user. The client should
# STILL see PUBLICKEY in the advertised methods (so it offers the
# key), and that audit line — operation=auth.publickey,
# detail="unknown user" — proves the unknown-user response is the
# v0.7.0 default (PASSWORD|PUBLICKEY). This is the upper bound on
# the anti-enumeration leak the v0.7.1 narrowing introduces:
# password-only known users ARE intentionally distinguishable from
# unknown users (see methodsForUser doc comment in ssh.zig),
# but the unknown-user shape itself stays at the historical
# default. If a future refactor accidentally narrowed the
# unknown-user response, an attacker could probe valid usernames
# trivially by inspecting the methods list — this assertion catches
# that regression.
: > "$ZIFT_LOG"
start_zift

expect <<EOF >"$TEST_TMP/unknown.log" 2>&1
set timeout 15
spawn sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\
    -o IdentityAgent=none -o IdentitiesOnly=yes -i $TEST_TMP/test_id \\
    -o NumberOfPasswordPrompts=1 \\
    -P $TEST_PORT nobody@127.0.0.1
expect "password:"
send "anything\r"
expect eof
EOF

stop_zift TERM
sleep 1

unknown_pubkey_audits=$(grep -c '"user":"nobody","operation":"auth.publickey"' "$ZIFT_LOG" || true)
[[ "$unknown_pubkey_audits" -ge "1" ]] \
    || fail "unknown-user shape: expected at least one auth.publickey line (proves PUBLICKEY still advertised for unknown users), got 0; tail:\n$(tail -10 "$ZIFT_LOG")"
ok "unknown-user response unchanged from v0.7.0 (still advertises PUBLICKEY)"
