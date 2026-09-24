#!/usr/bin/env bash
# Test: `zift validate` accepts good configs and names each problem
# The operator-facing contract, before `serve` ever runs: exit code and
# diagnostic text for grammar, semantic and filesystem errors.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
hash=$(make_password_hash secret)
T="$TEST_TMP"
mkdir -p "$T/root_a" "$T/root_b" "$T/shared/sub" "$T/custom" \
    "$T/partners/runner/in" "$T/partners-trailing/runner"
echo regular > "$T/file_not_dir"
ssh-keygen -q -t ed25519 -N '' -f "$T/runner_key"
echo 'this is not a public key line' > "$T/junk.pub"
cp "$T/runner_key.pub" "$T/writable_key.pub"; chmod 0664 "$T/writable_key.pub"
cp "$T/runner_key.pub" "$T/loose.pub"; chmod 0666 "$T/loose.pub"
ln -s "$T/runner_key.pub" "$T/good_link.pub"
ln -s "$T/writable_key.pub" "$T/writable_link.pub"

# conf <name> <user lines> [server line...]: write $T/<name>.conf.
conf() {
    local name="$1" users="$2"; shift 2
    write_config "$T/$name.conf" <<EOF
$(config_head "$@")

$users
EOF
}
# user <name> [line...]: a user block with the shared password hash.
user() {
    printf 'user %s\n  auth %s\n' "$1" "$hash"
    shift
    printf '  %s\n' "$@"
}
alice=$(user alice "root $T/root_a" "allow / read list")
bob=$(user bob "root $T/root_b" "allow / read list")

# ---------- accepted ----------
conf happy "$alice
$bob"
validate_ok "$T/happy.conf"
grep -q '^ok:' "$T/v.out" || fail "happy: stdout has no ok line"
ok "a valid config prints ok"

write_config "$T/comments.conf" <<EOF
# a top-level comment
server
  # an indented one
  listen 127.0.0.1:$TEST_PORT  # a trailing one
  host-key $HOST_KEY

# one between sections
$alice
EOF
validate_ok "$T/comments.conf"
grep -q "listen 127.0.0.1:$TEST_PORT)" "$T/v.out" || fail "the comment leaked into the value: $(cat "$T/v.out")"
ok "trailing and whole-line '#' comments are ignored"

conf durations "$alice" "reload-interval 2s" "idle-timeout 5m" "shutdown-grace 1h"
validate_ok "$T/durations.conf"
conf zero "$alice" "idle-timeout 0" "reload-interval 0"
validate_ok "$T/zero.conf"
ok "s/m/h durations and the bare 0 (off) parse"

conf user64 "$(user "$(printf 'a%.0s' {1..64})" "root $T/root_a" "allow / read list")"
validate_ok "$T/user64.conf"
ok "a 64-byte username is accepted"

conf partner_root "$(user runner "allow / read list")" "partner-root $T/partners"
validate_ok "$T/partner_root.conf"
conf override "$(user override "root $T/custom" "allow / read list")" "partner-root $T/partners"
validate_ok "$T/override.conf"
conf trailing "$(user runner "allow / read list")" "partner-root $T/partners-trailing/"
validate_ok "$T/trailing.conf"
ok "partner-root supplies <partner-root>/<user>; an explicit root wins; a trailing / is fine"

conf keyfile "$(user runner "auth $T/runner_key.pub" "allow / read list")" "partner-root $T/partners"
validate_ok "$T/keyfile.conf"
conf keylink "$(user runner "auth $T/good_link.pub" "root $T/partners/runner" "allow / read list")"
validate_ok "$T/keylink.conf"
ok "auth /path key files, and symlinks to them, are accepted"

conf lifted "$(user runner "root $T/root_a" "allow / full   # everything..." \
    "deny /*.exe    # ...but top-level binaries" "deny /inbox/#private")" \
    "publish-mode 0o644" "mkdir-mode 0o755"
validate_ok "$T/lifted.conf"
ok "trailing comments on rules, '#' in a pattern, publish-mode 0o644, mkdir-mode 0o755"

conf ipv6 "$alice"
sed -i.bak "s|listen 127.0.0.1:$TEST_PORT|listen [::1]:$TEST_PORT|" "$T/ipv6.conf"
validate_ok "$T/ipv6.conf"
ok "listen [::1]:port validates"

# ---------- grammar ----------
conf badkey "$(user alice "root $T/root_a" "bogus-key something" "allow / read list")"
validate_err "$T/badkey.conf" "line 8" "[user alice]" "UnknownKey"
conf baredur "$alice" "reload-interval 5"
validate_err "$T/baredur.conf" "line 4" "reload-interval" "InvalidDuration"
conf second_root "$(user runner "root $T/root_a" "root /elsewhere" "allow / read")"
validate_err "$T/second_root.conf" "line 8: [user runner] 'root': DuplicateDirective: already set on line 7"
conf second_listen "$alice" "listen 127.0.0.1:1"
validate_err "$T/second_listen.conf" "'listen': DuplicateDirective: already set on line 2"
conf maxconn0 "$alice" "max-connections 0"
validate_err "$T/maxconn0.conf" "'max-connections': InvalidNumber: must be at least 1"
conf subsecond "$alice" "idle-timeout 10ms"
validate_err "$T/subsecond.conf" "must be 0 (off) or at least 1s"
conf digitsep "$alice" "max-connections 1_000"
validate_err "$T/digitsep.conf" "InvalidNumber"
conf worldpublish "$alice" "publish-mode 0o666"
validate_err "$T/worldpublish.conf" "no world-write"
conf user65 "$(user "$(printf 'a%.0s' {1..65})" "root $T/root_a" "allow / read list")"
validate_err "$T/user65.conf" "UsernameTooLong"
conf dotdot "$(user ..)" "partner-root $T/partners"
validate_err "$T/dotdot.conf" "InvalidUserName"
ok "unknown keys, bare durations, repeats, bad numbers and names are named with their line"

# Rules that can never match: a dead deny fails open.
for rule in "deny *.exe|'deny': InvalidPattern: '*.exe' never matches" \
            "deny secret|'secret' never matches" \
            "allow /pending/ read|drop the trailing '/'" \
            "deny /a//b|empty component" \
            "deny /inbox/../etc|'.' or '..'"; do
    conf rule "$(user runner "root $T/root_a" "allow / full" "${rule%%|*}")"
    validate_err "$T/rule.conf" "${rule#*|}"
done
ok "rules that never match are rejected"

# ---------- auth ----------
conf dupe_pw "$(user runner "auth $hash" "root $T/partners/runner" "allow / read list")"
validate_err "$T/dupe_pw.conf" "DuplicatePassword"
conf badval "user runner
  auth not-a-valid-value
  root $T/partners/runner
  allow / read list"
validate_err "$T/badval.conf" "InvalidPasshash"
conf huge_path "$(user keyguy "auth /$(printf 'A%.0s' {1..8200})" "root $T/root_a" "allow / read list")"
validate_err "$T/huge_path.conf" "InvalidAuth: key file path too long"
for bad in "junk.pub|malformed public-key line" "does-not-exist.pub|unreadable" \
           "loose.pub|writable by group/world" "writable_link.pub|writable by group/world"; do
    conf keybad "user runner
  auth $T/${bad%%|*}
  root $T/partners/runner
  allow / read list"
    validate_err "$T/keybad.conf" "${bad#*|}" "user 'runner'"
done
conf legacy_pw "user runner
  password $hash
  root $T/partners/runner"
validate_err "$T/legacy_pw.conf" "PasswordDirectiveRemoved"
conf legacy_key "user runner
  key ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPHj7SuD0g1xj0ZqLELSQ7Ux8RSjGlYBhVMxbfBhPXMd legacy
  root $T/partners/runner"
validate_err "$T/legacy_key.conf" "KeyDirectiveRemoved"
ok "bad auth values and key files are rejected with the user named"

# ---------- against the filesystem ----------
conf missing_root "$(user alice "root $T/does-not-exist" "allow / read list")"
validate_err "$T/missing_root.conf" "user 'alice' root does not exist"
conf not_dir "$(user alice "root $T/file_not_dir" "allow / read list")"
validate_err "$T/not_dir.conf" "is not a directory"
conf no_host_key "$alice"
sed -i.bak "s|host-key .*|host-key $T/no_such_host_key|" "$T/no_host_key.conf"
validate_err "$T/no_host_key.conf" "host-key unreadable"
conf overlap "$(user outer "root $T/shared" "allow / read list")
$(user inner "root $T/shared/sub" "allow / read list")"
validate_err "$T/overlap.conf" "overlapping roots"
conf equal "$(user alice "root $T/shared" "allow / read list")
$(user bob "root $T/shared" "allow / read list")"
validate_err "$T/equal.conf" "overlapping roots"
conf bad_cap "$alice" "max-connections 8" "max-unauth-connections 16"
validate_err "$T/bad_cap.conf" "max-unauth-connections (16) exceeds max-connections (8)"
ok "missing or non-directory roots, an unreadable host key, overlaps and caps are named"

# The numeric check runs before any stat(): no host-key diagnostic.
sed "s|host-key .*|host-key $T/no_such_host_key|" "$T/bad_cap.conf" > "$T/bad_cap_and_key.conf"
validate_err "$T/bad_cap_and_key.conf" "max-unauth-connections"
grep -q "host-key unreadable" "$T/v.err" && fail "host-key was stat'ed before the numeric check failed"
ok "the numeric cap check short-circuits before the host-key stat"

# ---------- serve refuses what validate refuses ----------
"$ZIFT_BIN" serve "$T/missing_root.conf" >"$T/serve.log" 2>&1 &
pid=$!
PIDS+=("$pid")
wait_exit "$pid" 5 || fail "serve kept running on an invalid config"
grep -q "user 'alice' root does not exist" "$T/serve.log" || fail "serve: no diagnostic: $(cat "$T/serve.log")"
grep -q "listening on" "$T/serve.log" && fail "serve listened despite an invalid config"
ok "serve refuses to start on a semantically invalid config"
