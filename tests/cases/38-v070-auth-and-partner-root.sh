#!/usr/bin/env bash
# Test: v0.7.0 ergonomic config — `auth` directive (PHC + key-file)
#       and server-level `partner-root` default for user roots.
# Covers: config.zig parser changes (auth dispatch, partner-root,
#         password→auth migration) + validateSemantic key-file
#         resolution + audit-line `time` field.
# TODOS: v0.7.0 ergonomic improvements.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
hash=$(make_password_hash secret)

# ---------- (1) partner-root: default user root ----------
# `partner-root /home/<x>` + a user block with NO `root` directive
# should resolve to `<partner-root>/<user-name>`. The directory
# must exist for validateSemantic to accept the config, so we
# pre-create it with the test's per-case scratch parent as the
# partner-root anchor.
mkdir -p "$TEST_TMP/partners/runner/in"

cat > "$TEST_TMP/partner_root.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr
  partner-root $TEST_TMP/partners

user runner
  auth $hash
  allow / read list
EOF

set +e
"$ZIFT_BIN" validate "$TEST_TMP/partner_root.conf" \
    > "$TEST_TMP/p.out" 2> "$TEST_TMP/p.err"
rc=$?
set -e

[[ "$rc" == "0" ]] \
    || fail "partner-root: expected exit 0, got $rc; stderr=$(cat "$TEST_TMP/p.err")"
ok "partner-root makes \`root\` optional in user blocks (defaulted to <partner-root>/<user>)"

# ---------- (2) explicit user root overrides partner-root ----------
mkdir -p "$TEST_TMP/custom"
cat > "$TEST_TMP/override.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr
  partner-root $TEST_TMP/partners

user override
  auth $hash
  root $TEST_TMP/custom
  allow / read list
EOF

set +e
"$ZIFT_BIN" validate "$TEST_TMP/override.conf" \
    > "$TEST_TMP/o.out" 2> "$TEST_TMP/o.err"
rc=$?
set -e

[[ "$rc" == "0" ]] \
    || fail "explicit root override: expected exit 0, got $rc; stderr=$(cat "$TEST_TMP/o.err")"
ok "explicit \`root\` overrides the partner-root default"

# ---------- (3) auth /path key-file resolution at validate time ----------
# Generate a real ed25519 keypair and reference the public-key file
# from the config via `auth /path`. The daemon must read+parse the
# file at validate time; an unreadable or malformed file should
# fail validation cleanly.
ssh-keygen -t ed25519 -N '' -C 'zift-070-test' -f "$TEST_TMP/runner_key" \
    > /dev/null 2>&1

cat > "$TEST_TMP/keyfile.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr
  partner-root $TEST_TMP/partners

user runner
  auth $hash
  auth $TEST_TMP/runner_key.pub
  allow / read list
EOF

set +e
"$ZIFT_BIN" validate "$TEST_TMP/keyfile.conf" \
    > "$TEST_TMP/k.out" 2> "$TEST_TMP/k.err"
rc=$?
set -e

[[ "$rc" == "0" ]] \
    || fail "auth /path: expected exit 0, got $rc; stderr=$(cat "$TEST_TMP/k.err")"
ok "auth /path public-key file accepted at validate time"

# ---------- (4) auth /path with a malformed file is rejected ----------
echo 'this is not a public key line' > "$TEST_TMP/junk.pub"
cat > "$TEST_TMP/badkey.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user runner
  auth $TEST_TMP/junk.pub
  root $TEST_TMP/partners/runner
  allow / read list
EOF

set +e
"$ZIFT_BIN" validate "$TEST_TMP/badkey.conf" \
    > "$TEST_TMP/b.out" 2> "$TEST_TMP/b.err"
rc=$?
set -e

[[ "$rc" == "1" ]] \
    || fail "malformed key file: expected exit 1, got $rc; stderr=$(cat "$TEST_TMP/b.err")"
grep -q 'malformed public-key line' "$TEST_TMP/b.err" \
    || fail "expected 'malformed public-key line' in stderr, got: $(cat "$TEST_TMP/b.err")"
grep -q "user 'runner'" "$TEST_TMP/b.err" \
    || fail "expected user name in diagnostic, got: $(cat "$TEST_TMP/b.err")"
ok "malformed \`auth /path\` key file rejected with operator-facing diagnostic"

# ---------- (5) auth /path with a missing file is rejected ----------
cat > "$TEST_TMP/missing.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user runner
  auth $TEST_TMP/does-not-exist.pub
  root $TEST_TMP/partners/runner
  allow / read list
EOF

set +e
"$ZIFT_BIN" validate "$TEST_TMP/missing.conf" \
    > "$TEST_TMP/m.out" 2> "$TEST_TMP/m.err"
rc=$?
set -e

[[ "$rc" == "1" ]] \
    || fail "missing key file: expected exit 1, got $rc"
grep -q 'unreadable' "$TEST_TMP/m.err" \
    || fail "expected 'unreadable' in stderr, got: $(cat "$TEST_TMP/m.err")"
grep -q "user 'runner'" "$TEST_TMP/m.err" \
    || fail "expected user name in diagnostic, got: $(cat "$TEST_TMP/m.err")"
ok "missing \`auth /path\` key file rejected with operator-facing diagnostic"

# ---------- (5b) symlink-to-real-file rejected ----------
# Defense in depth: an attacker with parent-dir write access could
# replace alice.pub with a symlink to their own properly-permissioned
# key file. We reject symlinks regardless of target.
ln -s "$TEST_TMP/runner_key.pub" "$TEST_TMP/runner_link.pub"

cat > "$TEST_TMP/sym.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user runner
  auth $TEST_TMP/runner_link.pub
  root $TEST_TMP/partners/runner
  allow / read list
EOF

set +e
"$ZIFT_BIN" validate "$TEST_TMP/sym.conf" \
    > "$TEST_TMP/s.out" 2> "$TEST_TMP/s.err"
rc=$?
set -e

[[ "$rc" == "1" ]] \
    || fail "symlink key file: expected exit 1, got $rc"
grep -q 'symlinks not allowed' "$TEST_TMP/s.err" \
    || fail "expected 'symlinks not allowed' in stderr, got: $(cat "$TEST_TMP/s.err")"
ok "\`auth /path\` symlink rejected (defense vs symlink-swap attack)"

# ---------- (6) duplicate password auth lines rejected ----------
cat > "$TEST_TMP/dupe.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user runner
  auth $hash
  auth $hash
  root $TEST_TMP/partners/runner
  allow / read list
EOF

set +e
"$ZIFT_BIN" validate "$TEST_TMP/dupe.conf" \
    > "$TEST_TMP/d.out" 2> "$TEST_TMP/d.err"
rc=$?
set -e

[[ "$rc" == "1" ]] \
    || fail "duplicate password auth: expected exit 1, got $rc"
grep -q 'DuplicatePassword' "$TEST_TMP/d.err" \
    || fail "expected DuplicatePassword in stderr, got: $(cat "$TEST_TMP/d.err")"
ok "two PHC \`auth\` lines for one user rejected with DuplicatePassword"

# Sanity: a stray non-`$`/non-`/` auth value is rejected with InvalidAuth.
cat > "$TEST_TMP/badval.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user runner
  auth not-a-valid-value
  root $TEST_TMP/partners/runner
  allow / read list
EOF

set +e
"$ZIFT_BIN" validate "$TEST_TMP/badval.conf" \
    > "$TEST_TMP/v.out" 2> "$TEST_TMP/v.err"
rc=$?
set -e

[[ "$rc" == "1" ]] \
    || fail "auth bad value: expected exit 1, got $rc"
grep -q 'InvalidAuth' "$TEST_TMP/v.err" \
    || fail "expected InvalidAuth in stderr, got: $(cat "$TEST_TMP/v.err")"
ok "auth value with neither \$ nor / leading byte rejected with InvalidAuth"

# ---------- (9) world-writable key file rejected ----------
# Operators who chmod 0666 a key file (or leave it world-writable
# by accident) must NOT have it silently honored — a writable
# auth file is equivalent to a writable password hash.
cp "$TEST_TMP/runner_key.pub" "$TEST_TMP/loose.pub"
chmod 0666 "$TEST_TMP/loose.pub"

cat > "$TEST_TMP/loose.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user runner
  auth $TEST_TMP/loose.pub
  root $TEST_TMP/partners/runner
  allow / read list
EOF

set +e
"$ZIFT_BIN" validate "$TEST_TMP/loose.conf" \
    > "$TEST_TMP/l.out" 2> "$TEST_TMP/l.err"
rc=$?
set -e

[[ "$rc" == "1" ]] \
    || fail "world-writable key file: expected exit 1, got $rc"
grep -q 'writable by group/world' "$TEST_TMP/l.err" \
    || fail "expected 'writable by group/world' diagnostic, got: $(cat "$TEST_TMP/l.err")"
ok "world-writable \`auth /path\` key file rejected"

# ---------- (10) legacy v0.6 directives rejected with migration hint ----------
cat > "$TEST_TMP/legacy_pw.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519

user runner
  password $hash
  root $TEST_TMP/partners/runner
EOF

set +e
"$ZIFT_BIN" validate "$TEST_TMP/legacy_pw.conf" \
    > "$TEST_TMP/lp.out" 2> "$TEST_TMP/lp.err"
rc=$?
set -e

[[ "$rc" == "1" ]] \
    || fail "legacy password directive: expected exit 1, got $rc"
grep -q 'PasswordDirectiveRemoved' "$TEST_TMP/lp.err" \
    || fail "expected PasswordDirectiveRemoved in stderr, got: $(cat "$TEST_TMP/lp.err")"
ok "legacy v0.6 \`password\` directive rejected with PasswordDirectiveRemoved"

cat > "$TEST_TMP/legacy_key.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519

user runner
  key ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPHj7SuD0g1xj0ZqLELSQ7Ux8RSjGlYBhVMxbfBhPXMd legacy
  root $TEST_TMP/partners/runner
EOF

set +e
"$ZIFT_BIN" validate "$TEST_TMP/legacy_key.conf" \
    > "$TEST_TMP/lk.out" 2> "$TEST_TMP/lk.err"
rc=$?
set -e

[[ "$rc" == "1" ]] \
    || fail "legacy key directive: expected exit 1, got $rc"
grep -q 'KeyDirectiveRemoved' "$TEST_TMP/lk.err" \
    || fail "expected KeyDirectiveRemoved in stderr, got: $(cat "$TEST_TMP/lk.err")"
ok "legacy v0.6 \`key\` directive rejected with KeyDirectiveRemoved"

# ---------- (11) username `..` blocked at parse time ----------
cat > "$TEST_TMP/dotdot.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  partner-root $TEST_TMP/partners

user ..
  auth $hash
EOF

set +e
"$ZIFT_BIN" validate "$TEST_TMP/dotdot.conf" \
    > "$TEST_TMP/dd.out" 2> "$TEST_TMP/dd.err"
rc=$?
set -e

[[ "$rc" == "1" ]] \
    || fail "username '..': expected exit 1, got $rc"
grep -q 'InvalidUserName' "$TEST_TMP/dd.err" \
    || fail "expected InvalidUserName in stderr, got: $(cat "$TEST_TMP/dd.err")"
ok "username '..' rejected at parse time (path-traversal defense)"

# ---------- (12) partner-root /home/zift/ trailing slash normalized ----------
mkdir -p "$TEST_TMP/partners-trailing/runner"
cat > "$TEST_TMP/trailing.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  partner-root $TEST_TMP/partners-trailing/

user runner
  auth $hash
  allow / read list
EOF

set +e
"$ZIFT_BIN" validate "$TEST_TMP/trailing.conf" \
    > "$TEST_TMP/t.out" 2> "$TEST_TMP/t.err"
rc=$?
set -e

[[ "$rc" == "0" ]] \
    || fail "partner-root with trailing slash: expected exit 0, got $rc; stderr=$(cat "$TEST_TMP/t.err")"
ok "partner-root trailing slash normalized (no double-slash in derived root)"

# ---------- (7) auth-by-pubkey end-to-end smoke ----------
# Boot a full server with key-only auth and complete a real SFTP
# session using the matching private key. Catches any breakage in
# the auth pipeline that the parse-only checks above wouldn't see.
cat > "$TEST_TMP/zift.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr
  partner-root $TEST_TMP/partners

user runner
  auth $TEST_TMP/runner_key.pub
  allow / read list
EOF

start_zift
log_contains "listening on 127.0.0.1:$TEST_PORT" || fail "server did not start"

# pubkey-only login via OpenSSH; expect the SFTP banner and a clean exit.
sftp_log="$TEST_TMP/sftp.log"
sftp -o StrictHostKeyChecking=no \
     -o UserKnownHostsFile=/dev/null \
     -o PreferredAuthentications=publickey \
     -o IdentityFile="$TEST_TMP/runner_key" \
     -o BatchMode=yes \
     -P "$TEST_PORT" \
     runner@127.0.0.1 <<EOF >"$sftp_log" 2>&1
ls
bye
EOF

stop_zift TERM
sleep 1

log_contains '"operation":"auth.publickey","result":"ok"' \
    || fail "expected auth.publickey ok in audit log; tail:\n$(tail -20 "$ZIFT_LOG")"
ok "auth /path public-key end-to-end auth succeeds"

# ---------- (8) leading-`time` audit field present and well-formed ----------
ts_count=$(grep -cE '"time":"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z"' "$ZIFT_LOG" || true)
[[ "$ts_count" -gt "0" ]] \
    || fail "expected at least one RFC3339 ms timestamp in audit log"
ok "audit lines lead with RFC 3339 UTC ms \`time\` ($ts_count occurrences)"
