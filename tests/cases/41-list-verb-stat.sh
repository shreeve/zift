#!/usr/bin/env bash
# Test: the `list` verb satisfies STAT/LSTAT, so "browse without
#       download" works with real SFTP clients
# Clients stat a directory before opening it (OpenSSH `cd`, FileZilla,
# WinSCP). The browse session must see no denial at all, and the fetch
# session exactly one: the download under the list-only root.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
mkdir -p "$TEST_TMP/jail/results"
printf 'root-secret-body' > "$TEST_TMP/jail/root-only.txt"
printf 'fetchable' > "$TEST_TMP/jail/results/report.txt"
write_config <<EOF
$(config_head)

user user1
  auth $(make_password_hash secret)
  root $TEST_TMP/jail
  allow /        list
  allow /results read
EOF
start_zift
cd "$TEST_TMP"
denials() { count_log '"result":"denied"'; }

# expect drives a PTY; strip the CRs so anchored matches work.
sftp_password user1 secret "cd /" "ls -la /" 2>&1 | tr -d '\r' > browse.log || fail "browse session failed"
sed 's/^/    /' browse.log
grep -qi 'permission denied\|couldn.t stat' browse.log && fail "a list-only root refused stat-then-list"
[[ $(denials) == 0 ]] || fail "the browse session was audited with a denial"
ok "stat-then-list at a list-only root: no denial on the client or in the audit"
grep -q 'root-only.txt' browse.log || fail "the listing lacks root-only.txt"
ok "the listing shows entries at the list-only root"
grep -qE '^dr-xr-x--- .* results$' browse.log || fail "browsable dir 'results' is not dr-xr-x---"
ok "a browsable dir renders dr-xr-x---"
grep -qE '^---------- .* root-only.txt$' browse.log || fail "list-only file 'root-only.txt' is not ----------"
ok "a list-only file renders ---------- (name visible, content not)"

sftp_password user1 secret "get /root-only.txt" "get /results/report.txt" 2>&1 | tr -d '\r' > fetch.log \
    || fail "fetch session failed"
sed 's/^/    /' fetch.log
[[ $(grep -ci 'permission denied' fetch.log) == 1 ]] || fail "expected exactly one refusal on the client"
grep -qi 'remote open "/root-only.txt": permission denied' fetch.log || fail "the root download was not the refusal"
[[ ! -e root-only.txt ]] || fail "downloaded a file under a list-only rule"
[[ $(denials) == 1 ]] && log_contains '"operation":"open_read","result":"denied","path":"/root-only.txt"' \
    || fail "expected exactly one denial in the audit, for /root-only.txt"
ok "download refused at the list-only root, once"
[[ "$(cat report.txt)" == fetchable ]] || fail "the read-granted subtree did not download correctly"
ok "the read-granted subtree downloads normally"
log_contains '"operation":"opendir","result":"ok"' || fail "no successful opendir audited"
ok "audit records the browse"
