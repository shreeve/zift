#!/usr/bin/env bash
# Test: validate keeps daemon-private files out of partner roots, checks
#       what serve will open, and follows key symlinks to their targets
# Covers: host key / key file / log / config file inside a root; a
#         partner named like the key directory under partner-root; a
#         garbage host key and a missing log directory (both used to fail
#         only at serve); symlinked host key and key file accepted, and a
#         key login through a symlinked key file.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
mkdir -p "$TEST_TMP/etc" "$TEST_TMP/partners/ally" "$TEST_TMP/partners/keys" "$TEST_TMP/log"
mv "$TEST_TMP/host_ed25519" "$TEST_TMP/etc/host"
ssh-keygen -q -t ed25519 -N '' -f "$TEST_TMP/ally_id"
cp "$TEST_TMP/ally_id.pub" "$TEST_TMP/etc/ally.pub"
cp "$TEST_TMP/ally_id.pub" "$TEST_TMP/partners/keys/ally.pub"
chmod 0644 "$TEST_TMP/etc/ally.pub" "$TEST_TMP/partners/keys/ally.pub"

# conf <name> <host-key> <key file> <log> [extra server lines]
conf() {
    cat > "$TEST_TMP/$1.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $2
  log $4
  partner-root $TEST_TMP/partners
${5:-}
user ally
  auth $3
  allow / read list
EOF
}

run_validate() {
    set +e
    "$ZIFT_BIN" validate "$1" >"$TEST_TMP/v.out" 2>"$TEST_TMP/v.err"
    local rc=$?
    set -e
    return $rc
}

expect_reject() {
    local label="$1" conf_path="$2" want="$3"
    run_validate "$conf_path" && fail "$label: validate accepted it"
    grep -Fq "$want" "$TEST_TMP/v.err" || fail "$label: expected '$want', got: $(cat "$TEST_TMP/v.err")"
    ok "$label rejected"
}

good_key="$TEST_TMP/etc/ally.pub"
good_log="$TEST_TMP/log/audit.log"

conf good "$TEST_TMP/etc/host" "$good_key" "$good_log"
run_validate "$TEST_TMP/good.conf" || fail "good config: $(cat "$TEST_TMP/v.err")"
ok "private files outside every root validate"

# ---------- inside a root ----------
cp "$TEST_TMP/etc/host" "$TEST_TMP/partners/ally/host"
conf hostin "$TEST_TMP/partners/ally/host" "$good_key" "$good_log"
expect_reject "host key inside ally's root" "$TEST_TMP/hostin.conf" "host-key $TEST_TMP/partners/ally/host is inside user 'ally'"

conf logins "$TEST_TMP/etc/host" "$good_key" "$TEST_TMP/partners/ally/audit.log"
expect_reject "log inside ally's root" "$TEST_TMP/logins.conf" "log $TEST_TMP/partners/ally/audit.log is inside user 'ally'"

cp "$TEST_TMP/good.conf" "$TEST_TMP/partners/ally/zift.conf"
expect_reject "config file inside ally's root" "$TEST_TMP/partners/ally/zift.conf" "config file $TEST_TMP/partners/ally/zift.conf is inside user 'ally'"

# The documented layout trap: keys under partner-root, and a partner
# whose name matches the key directory gets it as a root.
cat > "$TEST_TMP/keys.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/etc/host
  partner-root $TEST_TMP/partners

user ally
  auth $TEST_TMP/partners/keys/ally.pub
  allow / read list

user keys
  auth $good_key
  allow / full
EOF
expect_reject "key file inside partner 'keys' root" "$TEST_TMP/keys.conf" "auth key file $TEST_TMP/partners/keys/ally.pub is inside user 'keys'"

# ---------- what serve opens, checked by validate ----------
printf 'garbage\n' > "$TEST_TMP/etc/junk"
chmod 0600 "$TEST_TMP/etc/junk"
conf junk "$TEST_TMP/etc/junk" "$good_key" "$good_log"
expect_reject "unloadable host key" "$TEST_TMP/junk.conf" "host-key is not a private key libssh can load"

conf nolog "$TEST_TMP/etc/host" "$good_key" "$TEST_TMP/nodir/audit.log"
expect_reject "log in a missing directory" "$TEST_TMP/nolog.conf" "log directory does not exist"

# ---------- symlinks are followed; the target is checked ----------
mkdir -p "$TEST_TMP/secrets"
ln -s "$TEST_TMP/etc/host" "$TEST_TMP/secrets/host"
ln -s "$TEST_TMP/etc/ally.pub" "$TEST_TMP/secrets/ally.pub"
conf linked "$TEST_TMP/secrets/host" "$TEST_TMP/secrets/ally.pub" "$good_log"
run_validate "$TEST_TMP/linked.conf" || fail "symlinked host key and key file: $(cat "$TEST_TMP/v.err")"
ok "symlinked host key and key file validate"

cp "$good_key" "$TEST_TMP/partners/ally/ally.pub"
ln -s "$TEST_TMP/partners/ally/ally.pub" "$TEST_TMP/secrets/in.pub"
conf linkin "$TEST_TMP/etc/host" "$TEST_TMP/secrets/in.pub" "$good_log"
expect_reject "symlink pointing into a root" "$TEST_TMP/linkin.conf" "is inside user 'ally'"

# ---------- a key login through the symlinked key file ----------
cp "$TEST_TMP/linked.conf" "$TEST_TMP/zift.conf"
start_zift
set +e
sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes \
    -i "$TEST_TMP/ally_id" -P "$TEST_PORT" ally@127.0.0.1 <<<'ls' >"$TEST_TMP/sftp.out" 2>&1
rc=$?
set -e
[[ "$rc" == "0" ]] || fail "key login via symlinked key file failed (rc=$rc): $(cat "$TEST_TMP/sftp.out")"
grep -q '"operation":"auth.publickey","result":"ok"' "$good_log" \
    || fail "expected an auth.publickey ok audit line: $(cat "$good_log")"
ok "key login works through a symlinked host key and key file"
stop_zift TERM
