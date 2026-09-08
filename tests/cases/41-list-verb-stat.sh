#!/usr/bin/env bash
# Test: the `list` verb satisfies STAT/LSTAT, so "browse without
#       download" is expressible against real SFTP clients.
# Covers: policy.permissionsFor (STAT/LSTAT accept read OR list),
#         policy.policyDerivedMode (a browsable dir renders r-x)
#
# Mainstream clients stat a remote directory before opening it —
# FileZilla and WinSCP both do, and OpenSSH's `cd` does the same via
# do_stat(). A `list` that did not satisfy STAT would refuse that
# request with SSH_FX_PERMISSION_DENIED, and the client could never
# render a listing at all, so the verb could not do the one thing it
# names.
#
# The policy below is the browsable-root shape from configure.md: `/`
# carries `list` only, download is granted per-subtree. The oracle is
# two-sided, so the browse half and the refuse half are checked in
# SEPARATE sessions — one log must contain no denial at all, the other
# must contain exactly one.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
hash=$(make_password_hash secret)

mkdir -p "$TEST_TMP/jail/results"
# A file at the list-only root: visible by name, never downloadable.
printf 'root-secret-body' > "$TEST_TMP/jail/root-only.txt"
# A file in the read subtree: downloadable.
printf 'fetchable' > "$TEST_TMP/jail/results/report.txt"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user user1
  auth $hash
  root $TEST_TMP/jail
  allow /        list
  allow /results read
EOF

start_zift

cd "$TEST_TMP"

# --- Session 1: browse. Nothing here may be refused. ------------------
sftp_password user1 secret \
    "cd /" \
    "ls -la /" \
    >"$TEST_TMP/browse.raw" 2>&1 || true
# expect drives a PTY, so every line arrives CRLF-terminated. Strip the
# CR once here; otherwise an anchored `...$` match never fires.
tr -d '\r' < "$TEST_TMP/browse.raw" > "$TEST_TMP/browse.log"

echo "  --- browse session ---"
sed 's/^/    /' "$TEST_TMP/browse.log"

# `cd /` issues STAT — the exact request a read-gated STAT refused, and
# the one that left the partner's client unable to list anything.
if grep -qi 'permission denied\|couldn.t stat' "$TEST_TMP/browse.log"; then
    fail "a list-only root refused the stat-then-list path"
fi
ok "stat-then-list at a list-only root succeeded"

grep -q 'root-only.txt' "$TEST_TMP/browse.log" \
    || fail "listing did not include root-only.txt — READDIR produced nothing"
ok "listing rendered entries at the list-only root"

# A browsable directory must render `r-x`: a dir that serves STAT but
# shows no `r` contradicts the request it just answered.
DIR_LINE=$(grep -E '^d[rwx-]{9} .* results$' "$TEST_TMP/browse.log" | head -1 || true)
[[ -n "$DIR_LINE" ]] || fail "no directory line for 'results' in the listing"
DIR_MODE=$(echo "$DIR_LINE" | awk '{print $1}')
[[ "$DIR_MODE" == "dr-xr-x---" ]] \
    || fail "browsable dir rendered $DIR_MODE, expected dr-xr-x---"
ok "browsable dir renders $DIR_MODE"

# A file under a list-only rule shows its name and size but no `r`:
# the listing is honest that the content is out of reach.
FILE_LINE=$(grep -E '^-[rwx-]{9} .* root-only.txt$' "$TEST_TMP/browse.log" | head -1 || true)
[[ -n "$FILE_LINE" ]] || fail "no file line for 'root-only.txt' in the listing"
FILE_MODE=$(echo "$FILE_LINE" | awk '{print $1}')
[[ "$FILE_MODE" == "----------" ]] \
    || fail "list-only file rendered $FILE_MODE, expected ----------"
ok "list-only file renders $FILE_MODE (name visible, content not)"

# --- Session 2: fetch. The bytes at the root must stay refused. -------
sftp_password user1 secret \
    "get /root-only.txt" \
    "get /results/report.txt" \
    >"$TEST_TMP/fetch.raw" 2>&1 || true
tr -d '\r' < "$TEST_TMP/fetch.raw" > "$TEST_TMP/fetch.log"

echo "  --- fetch session ---"
sed 's/^/    /' "$TEST_TMP/fetch.log"

grep -qi 'remote open "/root-only.txt": permission denied' "$TEST_TMP/fetch.log" \
    || fail "download at the list-only root was not refused"
[[ -f "$TEST_TMP/root-only.txt" ]] \
    && fail "downloaded a file under a list-only rule — the verb leaked content"
ok "download refused at the list-only root"

[[ -f "$TEST_TMP/report.txt" ]] \
    || fail "read-granted subtree did not download"
[[ "$(cat "$TEST_TMP/report.txt")" == "fetchable" ]] \
    || fail "read-granted subtree downloaded the wrong bytes"
ok "read-granted subtree downloads normally"

stop_zift TERM

# The audit trail must show the same story the client saw.
log_contains '"operation":"opendir","result":"ok"' \
    || fail "audit log has no successful opendir at the list-only root"
ok "audit records the successful browse"
