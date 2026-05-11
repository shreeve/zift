#!/usr/bin/env bash
# Test: parser emits line-numbered diagnostics, rejects inline comments
#       and bare-number durations
# Covers: PLAN §6.2 (line-level diagnostics, suffix-required durations,
#                    whole-line-only comments)
# TODOS: P1 config grammar (line numbers + structured errors)

source "$(dirname "$0")/../lib/common.sh"

make_host_key
hash=$(make_password_hash secret)

# Helper: write config to $TEST_TMP/<name>.conf, run validate, capture
# stdout/stderr/exit code. Returns the exit code via $rc.
run_validate() {
    local name="$1"
    "$ZIFT_BIN" validate "$TEST_TMP/$name.conf" \
        > "$TEST_TMP/$name.stdout" 2> "$TEST_TMP/$name.stderr"
}

# ---------- (a) line-numbered error on a malformed user property ----------
# An unknown key on line 8 should produce a "line 8" diagnostic that
# also names the user.
cat > "$TEST_TMP/badkey.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519

user alice
  auth $hash
  root $TEST_TMP
  bogus-key something
  allow / read list
EOF

set +e
run_validate badkey
rc=$?
set -e

[[ "$rc" == "1" ]] || fail "badkey: expected exit 1, got $rc"
echo "  diag: $(cat "$TEST_TMP/badkey.stderr")"
grep -q 'line 8' "$TEST_TMP/badkey.stderr" \
    || fail "badkey: expected 'line 8' in diagnostic, got: $(cat "$TEST_TMP/badkey.stderr")"
grep -q '\[user alice\]' "$TEST_TMP/badkey.stderr" \
    || fail "badkey: expected '[user alice]' in diagnostic, got: $(cat "$TEST_TMP/badkey.stderr")"
grep -q 'UnknownKey' "$TEST_TMP/badkey.stderr" \
    || fail "badkey: expected 'UnknownKey' error name, got: $(cat "$TEST_TMP/badkey.stderr")"
ok "unknown user property → 'line 8: [user alice] UnknownKey'"

# ---------- (b) inline `#` comment is rejected ----------
cat > "$TEST_TMP/inlinecomment.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT  # inline comment after a value
  host-key $TEST_TMP/host_ed25519

user bob
  auth $hash
  root $TEST_TMP
  allow / read list
EOF

set +e
run_validate inlinecomment
rc=$?
set -e

[[ "$rc" == "1" ]] || fail "inlinecomment: expected exit 1, got $rc"
echo "  diag: $(cat "$TEST_TMP/inlinecomment.stderr")"
grep -q 'line 2' "$TEST_TMP/inlinecomment.stderr" \
    || fail "inlinecomment: expected 'line 2', got: $(cat "$TEST_TMP/inlinecomment.stderr")"
grep -q 'InlineComment' "$TEST_TMP/inlinecomment.stderr" \
    || fail "inlinecomment: expected 'InlineComment', got: $(cat "$TEST_TMP/inlinecomment.stderr")"
ok "inline '#' comment → 'line 2: ... InlineComment'"

# ---------- (c) whole-line `#` comment is still accepted ----------
cat > "$TEST_TMP/wholelinecomment.conf" <<EOF
# This is a top-level comment
server
  # And this one is indented
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519

# Comment between sections
user carol
  auth $hash
  root $TEST_TMP
  allow / read list
EOF

set +e
run_validate wholelinecomment
rc=$?
set -e

[[ "$rc" == "0" ]] || fail "wholelinecomment: expected exit 0, got $rc; stderr: $(cat "$TEST_TMP/wholelinecomment.stderr")"
ok "whole-line '#' comments still parse"

# ---------- (d) bare-number duration is rejected ----------
cat > "$TEST_TMP/baredur.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  reload-interval 5

user dan
  auth $hash
  root $TEST_TMP
  allow / read list
EOF

set +e
run_validate baredur
rc=$?
set -e

[[ "$rc" == "1" ]] || fail "baredur: expected exit 1, got $rc"
echo "  diag: $(cat "$TEST_TMP/baredur.stderr")"
grep -q 'line 4' "$TEST_TMP/baredur.stderr" \
    || fail "baredur: expected 'line 4', got: $(cat "$TEST_TMP/baredur.stderr")"
grep -q "reload-interval" "$TEST_TMP/baredur.stderr" \
    || fail "baredur: expected 'reload-interval' key, got: $(cat "$TEST_TMP/baredur.stderr")"
grep -q 'InvalidDuration' "$TEST_TMP/baredur.stderr" \
    || fail "baredur: expected 'InvalidDuration', got: $(cat "$TEST_TMP/baredur.stderr")"
ok "bare-number duration → 'line 4: [server] reload-interval: InvalidDuration'"

# ---------- (e) suffixed durations all parse ----------
cat > "$TEST_TMP/durations.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  reload-interval 2s
  idle-timeout 5m
  shutdown-grace 1h

user erin
  auth $hash
  root $TEST_TMP
  allow / read list
EOF

set +e
run_validate durations
rc=$?
set -e

[[ "$rc" == "0" ]] || fail "durations: expected exit 0, got $rc; stderr: $(cat "$TEST_TMP/durations.stderr")"
ok "suffixed durations (s/m/h) all parse"

# ---------- (f) bare `0` is allowed (the documented "disabled" sentinel) ----------
cat > "$TEST_TMP/zero.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  idle-timeout 0
  reload-interval 0

user fred
  auth $hash
  root $TEST_TMP
  allow / read list
EOF

set +e
run_validate zero
rc=$?
set -e

[[ "$rc" == "0" ]] || fail "zero: expected exit 0, got $rc; stderr: $(cat "$TEST_TMP/zero.stderr")"
ok "bare '0' accepted as the documented disabled sentinel"
