#!/usr/bin/env bash
# Test: validate rejects rules that never match and ambiguous settings,
#       and accepts the lifted restrictions; a commented deny still denies
# Covers: dead rule patterns (a deny that would fail open), repeated
#         single-valued directives, max-connections 0, sub-second
#         idle-timeout, '_' in numbers; trailing comments, '#' inside a
#         pattern, any safe publish-mode/mkdir-mode, bracketed IPv6 listen.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
mkdir -p "$TEST_TMP/root/inbox"
hash=$(make_password_hash secret)

# Validate a config made of the server section plus "$1" (user lines).
# $2 = extra server lines. Leaves stderr in $TEST_TMP/v.err.
validate_with() {
    cat > "$TEST_TMP/v.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
$2
user runner
  auth $hash
  root $TEST_TMP/root
$1
EOF
    set +e
    "$ZIFT_BIN" validate "$TEST_TMP/v.conf" >"$TEST_TMP/v.out" 2>"$TEST_TMP/v.err"
    local rc=$?
    set -e
    return $rc
}

expect_reject() {
    local label="$1" want="$2" users="$3" server="${4:-}"
    validate_with "$users" "$server" && fail "$label: validate accepted it"
    grep -Fq "$want" "$TEST_TMP/v.err" || fail "$label: expected '$want', got: $(cat "$TEST_TMP/v.err")"
    ok "$label → $want"
}

expect_accept() {
    local label="$1" users="$2" server="${3:-}"
    validate_with "$users" "$server" || fail "$label: expected ok, got: $(cat "$TEST_TMP/v.err")"
    ok "$label accepted"
}

# ---------- rules that can never match (a dead deny fails open) ----------
expect_reject "unanchored glob" "'deny': InvalidPattern: '*.exe' never matches" "  allow / full
  deny *.exe"
expect_reject "bare name" "'secret' never matches" "  allow / full
  deny secret"
expect_reject "trailing slash" "drop the trailing '/'" "  allow /pending/ read"
expect_reject "empty component" "empty component" "  allow / full
  deny /a//b"
expect_reject "dot-dot component" "'.' or '..'" "  allow / full
  deny /inbox/../etc"

# ---------- ambiguous or unusable settings ----------
expect_reject "second root" "line 8: [user runner] 'root': DuplicateDirective: already set on line 7" "  root /elsewhere
  allow / read"
expect_reject "second listen" "'listen': DuplicateDirective: already set on line 2" "  allow / read" "  listen 127.0.0.1:1"
expect_reject "max-connections 0" "'max-connections': InvalidNumber: must be at least 1" "  allow / read" "  max-connections 0"
expect_reject "sub-second idle-timeout" "must be 0 (off) or at least 1s" "  allow / read" "  idle-timeout 10ms"
expect_reject "digit separator" "InvalidNumber" "  allow / read" "  max-connections 1_000"
expect_reject "world-writable publish-mode" "no world-write" "  allow / read" "  publish-mode 0o666"

# ---------- lifted restrictions ----------
expect_accept "trailing comments and '#' in a pattern" "  allow / full   # everything...
  deny /*.exe    # ...but top-level binaries
  deny /inbox/#private"
expect_accept "publish-mode 0o644 and mkdir-mode 0o755" "  allow / read" "  publish-mode 0o644
  mkdir-mode 0o755"
validate_with "  allow / read" "" || fail "base config: $(cat "$TEST_TMP/v.err")"
sed -i.bak "s|listen 127.0.0.1:$TEST_PORT|listen [::1]:$TEST_PORT|" "$TEST_TMP/v.conf"
"$ZIFT_BIN" validate "$TEST_TMP/v.conf" >/dev/null 2>"$TEST_TMP/v.err" \
    || fail "listen [::1]:port: $(cat "$TEST_TMP/v.err")"
ok "listen [::1]:$TEST_PORT validates"

# ---------- the commented deny still denies at runtime ----------
need_paramiko
write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user runner
  auth $hash
  root $TEST_TMP/root
  allow / full   # everything...
  deny /*.exe    # ...but top-level binaries
EOF
start_zift
"$PY" - <<EOF
import io, socket, sys, paramiko
sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="runner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)
sftp.putfo(io.BytesIO(b"ok"), "/notes.txt")
try:
    sftp.putfo(io.BytesIO(b"MZ"), "/tool.exe")
    print("FAIL: /tool.exe upload was allowed"); sys.exit(1)
except IOError:
    pass
sftp.putfo(io.BytesIO(b"MZ"), "/inbox/tool.exe")  # only the top level is denied
t.close()
EOF
[[ -f "$TEST_TMP/root/notes.txt" && ! -e "$TEST_TMP/root/tool.exe" && -f "$TEST_TMP/root/inbox/tool.exe" ]] \
    || fail "unexpected files: $(ls -R "$TEST_TMP/root")"
ok "deny /*.exe with a trailing comment denies /tool.exe and nothing else"
stop_zift TERM
