#!/usr/bin/env bash
# Test: validate keeps daemon-private files out of partner roots, checks
#       what serve will open, and follows key symlinks to their targets
# A host key, key file, log or config inside a root would be partner-
# writable; a bad host key or log dir must fail validate, not only serve.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
T="$TEST_TMP"
mkdir -p "$T/etc" "$T/partners/ally" "$T/partners/keys" "$T/log" "$T/secrets"
mv "$HOST_KEY" "$T/etc/host"
ssh-keygen -q -t ed25519 -N '' -f "$T/ally_id"
cp "$T/ally_id.pub" "$T/etc/ally.pub"
cp "$T/ally_id.pub" "$T/partners/keys/ally.pub"
chmod 0644 "$T/etc/ally.pub" "$T/partners/keys/ally.pub"
good_key="$T/etc/ally.pub"
good_log="$T/log/audit.log"

# conf <name> <host-key> <key file> <log>: user ally, root from partner-root.
conf() {
    write_config "$T/$1.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $2
  log $4
  partner-root $T/partners

user ally
  auth $3
  allow / read list
EOF
}

conf good "$T/etc/host" "$good_key" "$good_log"
validate_ok "$T/good.conf"
ok "private files outside every root validate"

cp "$T/etc/host" "$T/partners/ally/host"
conf hostin "$T/partners/ally/host" "$good_key" "$good_log"
validate_err "$T/hostin.conf" "host-key $T/partners/ally/host is inside user 'ally'"
conf logins "$T/etc/host" "$good_key" "$T/partners/ally/audit.log"
validate_err "$T/logins.conf" "log $T/partners/ally/audit.log is inside user 'ally'"
cp "$T/good.conf" "$T/partners/ally/zift.conf"
validate_err "$T/partners/ally/zift.conf" "config file $T/partners/ally/zift.conf is inside user 'ally'"
ok "a host key, log or config file inside a partner root is rejected"

# The documented layout trap: keys under partner-root, and a partner
# whose name matches the key directory gets it as a root.
write_config "$T/keys.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $T/etc/host
  partner-root $T/partners

user ally
  auth $T/partners/keys/ally.pub
  allow / read list

user keys
  auth $good_key
  allow / full
EOF
validate_err "$T/keys.conf" "auth key file $T/partners/keys/ally.pub is inside user 'keys'"
ok "a key file inside partner 'keys' root is rejected"

printf 'garbage\n' > "$T/etc/junk"
chmod 0600 "$T/etc/junk"
conf junk "$T/etc/junk" "$good_key" "$good_log"
validate_err "$T/junk.conf" "host-key is not a private key libssh can load"
conf nolog "$T/etc/host" "$good_key" "$T/nodir/audit.log"
validate_err "$T/nolog.conf" "log directory does not exist"
ok "an unloadable host key and a log in a missing directory fail validate, not only serve"

ln -s "$T/etc/host" "$T/secrets/host"
ln -s "$T/etc/ally.pub" "$T/secrets/ally.pub"
conf linked "$T/secrets/host" "$T/secrets/ally.pub" "$good_log"
validate_ok "$T/linked.conf"
ok "a symlinked host key and key file validate"
cp "$good_key" "$T/partners/ally/ally.pub"
ln -s "$T/partners/ally/ally.pub" "$T/secrets/in.pub"
conf linkin "$T/etc/host" "$T/secrets/in.pub" "$good_log"
validate_err "$T/linkin.conf" "is inside user 'ally'"
ok "a symlink pointing into a root is rejected"

start_zift "$T/linked.conf"
sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes \
    -i "$T/ally_id" -P "$TEST_PORT" ally@127.0.0.1 <<<'ls' >"$T/sftp.out" 2>&1 \
    || fail "key login via the symlinked key file failed: $(cat "$T/sftp.out")"
log_contains '"operation":"auth.publickey","result":"ok"' "$good_log" \
    || fail "no auth.publickey ok audit line: $(cat "$good_log")"
ok "a key-only login works through a symlinked host key and key file"
