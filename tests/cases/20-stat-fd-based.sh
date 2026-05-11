#!/usr/bin/env bash
# Test: SSH_FXP_STAT/LSTAT do not follow symlinks at the basename
# Covers: PLAN §8.3 (no string-layer authorization for stat),
#         PLAN §7.6 (STAT/LSTAT behave identically; no dangling-symlink
#                    semantics distinct from stat)
# TODOS: P1 STAT path-based → FD-based (SFTP follow-up)
#
# A symlink inside the jail that points at a file OUTSIDE the jail
# must not let a client read the target's metadata via STAT. The
# fixed handler resolves the parent directory via openVerifiedParent
# (FD-relative, jail-verified) and then stats the basename with
# follow_symlinks=false, so the reply describes the symlink itself,
# never crosses the jail boundary, and never leaks size/mtime/etc of
# any file outside the jail.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
hash=$(make_password_hash secret)

# Pre-place an OUTSIDE-jail file with a distinctive size we'd notice
# if the server returned its metadata.
SECRET_OUTSIDE="$TEST_TMP/outside_secret.txt"
SECRET_BODY="this string is exactly the outside content with a particular length"
printf '%s' "$SECRET_BODY" > "$SECRET_OUTSIDE"
SECRET_SIZE=${#SECRET_BODY}

# Build the jail. The symlink lives inside the jail but points outside.
mkdir -p "$TEST_TMP/jail/inbox"
ln -s "$SECRET_OUTSIDE" "$TEST_TMP/jail/inbox/link-to-secret"

# Also put a regular file inside the jail with a different size so we
# can tell metadata apart.
INSIDE_BODY="inside"
printf '%s' "$INSIDE_BODY" > "$TEST_TMP/jail/inbox/regular.txt"
INSIDE_SIZE=${#INSIDE_BODY}

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user user1
  auth $hash
  root $TEST_TMP/jail
  allow / read list
  allow /inbox read list
EOF

start_zift

# Use sftp's `ls -l` against /inbox/link-to-secret. What the server
# returns is what we'd see if anyone STATs the symlink path.
expect <<EOF >"$TEST_TMP/client.log" 2>&1
set timeout 15
spawn sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\
    -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 \\
    -P $TEST_PORT user1@127.0.0.1
expect "password:"
send "secret\r"
expect "sftp>"
send "ls -l /inbox/link-to-secret\r"
expect "sftp>"
send "ls -l /inbox/regular.txt\r"
expect "sftp>"
send "bye\r"
expect eof
EOF

stop_zift TERM

echo "  outside-secret size: $SECRET_SIZE bytes"
echo "  inside-regular size: $INSIDE_SIZE bytes"
echo "  --- client output (stripped of expect framing) ---"
sed 's/^/    /' "$TEST_TMP/client.log"

# Oracle: in the ls -l output, the size column for /inbox/link-to-secret
# must NOT be the outside-secret's size. The acceptable answers are:
#   - the symlink's own size (length of the target path string), OR
#   - an error / unknown / 0 (server refused to follow)
# What we MUST NOT see is the secret's $SECRET_SIZE bytes, because that
# would mean the server followed the symlink across the jail boundary.

# Extract the size column for link-to-secret from the ls -l output.
# `sftp` formats sizes as the 5th whitespace-separated column.
LINK_LINE=$(grep 'link-to-secret' "$TEST_TMP/client.log" | grep -v '^sftp>' | head -1 || true)
echo "  link-to-secret stat line: $LINK_LINE"

if [[ -n "$LINK_LINE" ]]; then
    REPORTED_SIZE=$(echo "$LINK_LINE" | awk '{print $5}')
    if [[ "$REPORTED_SIZE" == "$SECRET_SIZE" ]]; then
        fail "STAT followed the symlink and returned the OUTSIDE secret's size ($REPORTED_SIZE bytes) — jail breach"
    fi
    ok "STAT did not return outside-secret size (got $REPORTED_SIZE, secret is $SECRET_SIZE)"
fi

# Sanity: a regular file inside the jail still stats correctly.
REG_LINE=$(grep 'regular.txt' "$TEST_TMP/client.log" | grep -v '^sftp>' | head -1 || true)
if [[ -n "$REG_LINE" ]]; then
    REG_SIZE=$(echo "$REG_LINE" | awk '{print $5}')
    [[ "$REG_SIZE" == "$INSIDE_SIZE" ]] \
        || fail "regular file inside jail: expected size $INSIDE_SIZE, got $REG_SIZE"
    ok "regular file inside jail still stats correctly ($REG_SIZE bytes)"
fi
