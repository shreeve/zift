#!/usr/bin/env bash
# Test: CLI exit codes and messages, and hash-password reading one line
# Covers: serve with the wrong argument count exits 1; an unreadable
#         config names the path; a parse error is printed once; validate
#         survives a long listen host and config path; hash-password
#         hashes only the first stdin line (as Janus does), so a trailing
#         second line cannot lock the partner out.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
mkdir -p "$TEST_TMP/root"

expect_rc() {
    local want="$1" label="$2"; shift 2
    set +e
    "$@" >"$TEST_TMP/out" 2>"$TEST_TMP/err"
    local rc=$?
    set -e
    [[ "$rc" == "$want" ]] || fail "$label: expected exit $want, got $rc; stderr: $(cat "$TEST_TMP/err")"
}

# ---------- usage errors exit 1 ----------
expect_rc 1 "serve with no config" "$ZIFT_BIN" serve
grep -q 'usage:' "$TEST_TMP/err" || fail "serve with no config: expected usage"
expect_rc 1 "serve with two configs" "$ZIFT_BIN" serve a b
expect_rc 1 "validate with no config" "$ZIFT_BIN" validate
expect_rc 1 "unknown command" "$ZIFT_BIN" frobnicate
ok "serve/validate with the wrong argument count exit 1"

# ---------- unreadable config: one line naming the path ----------
expect_rc 1 "serve missing config" "$ZIFT_BIN" serve "$TEST_TMP/nope.conf"
grep -q "cannot read $TEST_TMP/nope.conf: FileNotFound" "$TEST_TMP/err" \
    || fail "serve missing config: expected 'cannot read <path>: FileNotFound', got: $(cat "$TEST_TMP/err")"
grep -q 'error: ' "$TEST_TMP/err" && fail "serve missing config: raw error/trace leaked: $(cat "$TEST_TMP/err")"
ok "serve on a missing config names the path and exits 1"

# ---------- parse error printed once, no raw error ----------
printf 'server\n  listen :1\n  bogus x\n' > "$TEST_TMP/bad.conf"
expect_rc 1 "serve bad config" "$ZIFT_BIN" serve "$TEST_TMP/bad.conf"
[[ $(grep -c 'UnknownKey' "$TEST_TMP/err") == 1 ]] \
    || fail "serve bad config: expected one UnknownKey line, got: $(cat "$TEST_TMP/err")"
grep -q 'error: ' "$TEST_TMP/err" && fail "serve bad config: raw error leaked: $(cat "$TEST_TMP/err")"
ok "serve prints a parse error once and exits 1"

# ---------- validate with a long host and a long config path ----------
hash=$(printf 'secret\nsecond line\n' | "$ZIFT_BIN" hash-password)
long_dir="$TEST_TMP/$(printf 'd%.0s' {1..200})/$(printf 'e%.0s' {1..200})/$(printf 'f%.0s' {1..200})"
mkdir -p "$long_dir"
long_host=$(printf 'h%.0s' {1..250})
cat > "$long_dir/zift.conf" <<EOF
server
  listen $long_host:$TEST_PORT
  host-key $TEST_TMP/host_ed25519

user runner
  auth $hash
  root $TEST_TMP/root
  allow / read list
EOF
expect_rc 0 "validate long names" "$ZIFT_BIN" validate "$long_dir/zift.conf"
grep -q "^ok: $long_dir/zift.conf (1 user, listen $long_host:$TEST_PORT)$" "$TEST_TMP/out" \
    || fail "validate long names: unexpected ok line: $(cat "$TEST_TMP/out")"
ok "validate prints a long ok line instead of panicking"

# ---------- hash-password: first line only ----------
write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user runner
  auth $hash
  root $TEST_TMP/root
  allow / read list
EOF
start_zift
out=$(sftp_password runner secret "ls" 2>&1) || true
echo "$out" | grep -q "sftp>" || fail "password 'secret' (first stdin line) did not log in: $out"
ok "hash-password hashed only the first line ('secret')"
stop_zift TERM

expect_rc 1 "empty password" sh -c "printf '\r\n' | '$ZIFT_BIN' hash-password"
grep -q 'password must not be empty' "$TEST_TMP/err" || fail "empty password: $(cat "$TEST_TMP/err")"
ok "an empty first line is refused"
