#!/usr/bin/env bash
# Test: SSH_FXP_STAT/LSTAT do not follow symlinks at the basename
# A symlink in the jail that points outside must never reveal the outside
# file's metadata.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
secret="this string is exactly the outside content with a particular length"
printf '%s' "$secret" > "$TEST_TMP/outside_secret.txt"
mkdir -p "$TEST_TMP/jail/inbox"
ln -s "$TEST_TMP/outside_secret.txt" "$TEST_TMP/jail/inbox/link-to-secret"
printf 'inside' > "$TEST_TMP/jail/inbox/regular.txt"

write_config <<EOF
$(config_head)

user user1
  auth $(make_password_hash secret)
  root $TEST_TMP/jail
  allow / read list
  allow /inbox read list
EOF
start_zift

sftp_password user1 secret "ls -l /inbox/link-to-secret" "ls -l /inbox/regular.txt" \
    >"$TEST_TMP/client.log" 2>&1 || true
sed 's/^/    /' "$TEST_TMP/client.log"

link_line=$(grep 'link-to-secret' "$TEST_TMP/client.log" | grep -v '^sftp>' | head -1 || true)
if [[ -n "$link_line" ]]; then
    [[ $(awk '{print $5}' <<<"$link_line") != "${#secret}" ]] \
        || fail "STAT followed the symlink and returned the outside secret's size"
    ok "STAT did not return the outside secret's size"
fi
reg_line=$(grep 'regular.txt' "$TEST_TMP/client.log" | grep -v '^sftp>' | head -1 || true)
if [[ -n "$reg_line" ]]; then
    [[ $(awk '{print $5}' <<<"$reg_line") == 6 ]] || fail "regular file inside the jail has the wrong size"
    ok "regular file inside the jail still stats correctly"
fi
