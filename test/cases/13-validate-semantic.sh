#!/usr/bin/env bash
# Test: zift validate rejects semantic problems against the live filesystem
# Covers: PLAN §6.2 ("validate/runtime loader rejects missing roots,
#         unreadable host key, out-of-policy Argon2id params, and
#         overlapping roots")
# TODOS: P0 zift validate is parse-only (collapses three PLAN promises:
#         root existence, host-key readability, overlapping-roots rejection)
#
# `zift validate` previously only ran `config.parse`, so a config that
# pointed at a missing root or paired two users with overlapping roots
# would print "ok" — and then break at the first SFTP session. The fix
# moves these cross-cutting checks into a single `validateSemantic` pass
# that runs from `validate`, `serve` startup, and reload.

source "$(dirname "$0")/../lib/common.sh"

ZIFT="$ZIFT_BIN"
HOST_KEY="$TEST_TMP/host_ed25519"
make_host_key
hash=$(make_password_hash secret)

# Helper: write a config to $TEST_TMP/<name>.conf and run `zift validate`
# against it. Captures exit code and stderr; returns the exit code.
run_validate() {
    local name="$1"
    "$ZIFT" validate "$TEST_TMP/$name.conf" \
        > "$TEST_TMP/$name.stdout" 2> "$TEST_TMP/$name.stderr"
}

# Common roots used across the configs.
mkdir -p "$TEST_TMP/root_a"
mkdir -p "$TEST_TMP/root_b"

# ---------- happy path ----------
cat > "$TEST_TMP/happy.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $HOST_KEY

user alice
  password $hash
  root $TEST_TMP/root_a
  allow / read list

user bob
  password $hash
  root $TEST_TMP/root_b
  allow / read list
EOF

set +e
run_validate happy
rc=$?
set -e
[[ "$rc" == "0" ]] || fail "happy path: validate returned $rc instead of 0"
grep -q '^ok:' "$TEST_TMP/happy.stdout" || fail "happy path: stdout missing ok line"
ok "valid config validates and prints ok"

# ---------- missing user root ----------
cat > "$TEST_TMP/missing_root.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $HOST_KEY

user alice
  password $hash
  root $TEST_TMP/does-not-exist
  allow / read list
EOF

set +e
run_validate missing_root
rc=$?
set -e
[[ "$rc" == "1" ]] || fail "missing-root: validate returned $rc instead of 1"
grep -q "user 'alice' root does not exist" "$TEST_TMP/missing_root.stderr" \
    || fail "missing-root: expected stderr to identify alice's missing root, got: $(cat "$TEST_TMP/missing_root.stderr")"
ok "missing user root rejected with named diagnostic"

# ---------- root that exists but is a regular file, not a directory ----------
echo regular > "$TEST_TMP/file_not_dir"
cat > "$TEST_TMP/not_dir.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $HOST_KEY

user alice
  password $hash
  root $TEST_TMP/file_not_dir
  allow / read list
EOF

set +e
run_validate not_dir
rc=$?
set -e
[[ "$rc" == "1" ]] || fail "not-dir: validate returned $rc instead of 1"
grep -q "is not a directory" "$TEST_TMP/not_dir.stderr" \
    || fail "not-dir: expected 'is not a directory' diagnostic, got: $(cat "$TEST_TMP/not_dir.stderr")"
ok "non-directory root rejected"

# ---------- unreadable host-key ----------
cat > "$TEST_TMP/bad_hostkey.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/no_such_host_key

user alice
  password $hash
  root $TEST_TMP/root_a
  allow / read list
EOF

set +e
run_validate bad_hostkey
rc=$?
set -e
[[ "$rc" == "1" ]] || fail "bad-hostkey: validate returned $rc instead of 1"
grep -q "host-key unreadable" "$TEST_TMP/bad_hostkey.stderr" \
    || fail "bad-hostkey: expected 'host-key unreadable' diagnostic, got: $(cat "$TEST_TMP/bad_hostkey.stderr")"
ok "unreadable host-key rejected"

# ---------- overlapping roots (one is a path-component prefix of the other) ----------
mkdir -p "$TEST_TMP/shared/sub"
cat > "$TEST_TMP/overlap.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $HOST_KEY

user outer
  password $hash
  root $TEST_TMP/shared
  allow / read list

user inner
  password $hash
  root $TEST_TMP/shared/sub
  allow / read list
EOF

set +e
run_validate overlap
rc=$?
set -e
[[ "$rc" == "1" ]] || fail "overlap: validate returned $rc instead of 1"
grep -q "overlapping roots" "$TEST_TMP/overlap.stderr" \
    || fail "overlap: expected 'overlapping roots' diagnostic, got: $(cat "$TEST_TMP/overlap.stderr")"
ok "overlapping roots rejected"

# ---------- equal roots (same path for two users) ----------
cat > "$TEST_TMP/equal_roots.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $HOST_KEY

user alice
  password $hash
  root $TEST_TMP/shared
  allow / read list

user bob
  password $hash
  root $TEST_TMP/shared
  allow / read list
EOF

set +e
run_validate equal_roots
rc=$?
set -e
[[ "$rc" == "1" ]] || fail "equal-roots: validate returned $rc instead of 1"
grep -q "overlapping roots" "$TEST_TMP/equal_roots.stderr" \
    || fail "equal-roots: expected 'overlapping roots' diagnostic, got: $(cat "$TEST_TMP/equal_roots.stderr")"
ok "equal user roots rejected as overlapping"

# ---------- max-unauth-connections > max-connections ----------
cat > "$TEST_TMP/bad_cap.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $HOST_KEY
  max-connections 8
  max-unauth-connections 16

user alice
  password $hash
  root $TEST_TMP/root_a
  allow / read list
EOF

set +e
run_validate bad_cap
rc=$?
set -e
[[ "$rc" == "1" ]] || fail "bad-cap: validate returned $rc instead of 1"
grep -q "max-unauth-connections (16) exceeds max-connections (8)" "$TEST_TMP/bad_cap.stderr" \
    || fail "bad-cap: expected 'exceeds max-connections' diagnostic, got: $(cat "$TEST_TMP/bad_cap.stderr")"
ok "max-unauth-connections > max-connections rejected with named diagnostic"

# ---------- ordering: numeric cap fails before host-key stat ----------
# Both max-unauth (16) > max-connections (8) AND host-key path is
# missing. The pure-numeric check must fire FIRST so the operator
# fixes the typo before discovering the host-key issue.
cat > "$TEST_TMP/bad_cap_and_hostkey.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/no_such_host_key
  max-connections 8
  max-unauth-connections 16

user alice
  password $hash
  root $TEST_TMP/root_a
  allow / read list
EOF

set +e
run_validate bad_cap_and_hostkey
rc=$?
set -e
[[ "$rc" == "1" ]] || fail "bad-cap-and-hostkey: validate returned $rc instead of 1"
grep -q "max-unauth-connections" "$TEST_TMP/bad_cap_and_hostkey.stderr" \
    || fail "bad-cap-and-hostkey: cap diagnostic missing, got: $(cat "$TEST_TMP/bad_cap_and_hostkey.stderr")"
grep -q "host-key unreadable" "$TEST_TMP/bad_cap_and_hostkey.stderr" \
    && fail "bad-cap-and-hostkey: host-key diagnostic appeared first; cap check should fire before any I/O"
ok "numeric cap check fires before host-key stat (ordering preserved)"

# ---------- serve also rejects malformed configs at startup ----------
# Re-use the missing_root config: zift serve must refuse to listen.
set +e
"$ZIFT" serve "$TEST_TMP/missing_root.conf" \
    > "$TEST_TMP/serve_reject.stdout" 2> "$TEST_TMP/serve_reject.stderr" &
serve_pid=$!
# Wait briefly; if startup refuses, the process should exit on its own.
for _ in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$serve_pid" 2>/dev/null || break
    sleep 0.2
done
kill -KILL "$serve_pid" 2>/dev/null || true
wait "$serve_pid" 2>/dev/null || true
set -e

grep -q "user 'alice' root does not exist" "$TEST_TMP/serve_reject.stderr" \
    || fail "serve-reject: expected startup diagnostic, got: $(cat "$TEST_TMP/serve_reject.stderr")"
grep -q "listening on" "$TEST_TMP/serve_reject.stderr" \
    && fail "serve-reject: server reached 'listening on' despite invalid config"
ok "serve refuses to start on a semantically-invalid config"
