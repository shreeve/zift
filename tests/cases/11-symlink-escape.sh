#!/usr/bin/env bash
# Test: SSH_FXP_OPEN must not write through a symlink that escapes the jail
# Covers: PLAN §8.3 strict path-jail enforcement (post-open FD verification)
# TODOS: P0 SSH_FXP_OPEN write path is symlink-escape-prone before verifyFile

source "$(dirname "$0")/../lib/common.sh"

make_host_key
hash=$(make_password_hash secret)

# Pre-place a "secret" file OUTSIDE the jail. The symlink-escape attack
# targets this file: a malicious symlink inside the jail aimed at this
# path would let a client truncate/overwrite it through SFTP if the
# server follows the symlink before verifying the resulting fd.
SECRET_FILE="$TEST_TMP/outside_secret.txt"
SECRET_BEFORE="OUTSIDE-SECRET-CONTENT"
echo "$SECRET_BEFORE" > "$SECRET_FILE"

# Build the jail. inbox/innocent.txt is a symlink that points OUTSIDE
# the jail, at the secret file. Operationally this is what happens if
# an admin (or a previous partner with shell access) leaves a stray
# symlink in the upload area.
mkdir -p "$TEST_TMP/jail/inbox"
ln -s "$SECRET_FILE" "$TEST_TMP/jail/inbox/innocent.txt"
ls -la "$TEST_TMP/jail/inbox/innocent.txt"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user partner
  auth $hash
  root $TEST_TMP/jail
  allow /inbox write list mkdir
EOF

start_zift

# Local payload the client will try to upload OVER the symlink path.
# If the server follows the symlink during open/truncate, the secret
# file outside the jail gets replaced with this content. That's the bug.
echo "ATTACKER-OVERWRITE" > "$TEST_TMP/payload.txt"

# Drive a standard `sftp put`. A successful put against /inbox/innocent.txt
# in the buggy code path would truncate+rewrite the secret file outside
# the jail. After the fix the put must fail (Permission denied) and the
# secret file's content must be unchanged.
expect <<EOF >"$TEST_TMP/client.log" 2>&1
set timeout 15
spawn sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\
    -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 \\
    -P $TEST_PORT partner@127.0.0.1
expect "password:"
send "secret\r"
expect "sftp>"
send "put $TEST_TMP/payload.txt /inbox/innocent.txt\r"
expect "sftp>"
send "bye\r"
expect eof
EOF

stop_zift TERM
sleep 1

# The oracle: did the OUT-OF-JAIL secret file get clobbered?
secret_after=$(cat "$SECRET_FILE")
echo "  secret before: $SECRET_BEFORE"
echo "  secret after : $secret_after"

if [[ "$secret_after" == "$SECRET_BEFORE" ]]; then
    ok "outside-jail secret file is untouched"
else
    fail "symlink escape succeeded: outside-jail file was overwritten"
fi

# Belt-and-suspenders: the audit log should show the open as denied,
# not as a successful write.
if grep -q '"operation":"open_write","result":"denied"' "$ZIFT_LOG"; then
    ok "server logged open_write denial"
elif grep -q '"operation":"open_write","result":"failed"' "$ZIFT_LOG"; then
    ok "server logged open_write failure (acceptable rejection)"
elif grep -q '"operation":"open_write","result":"ok"' "$ZIFT_LOG"; then
    fail "server allowed open_write through the symlink"
else
    fail "no open_write audit line found; see $ZIFT_LOG"
fi
