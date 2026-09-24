#!/usr/bin/env bash
# Test: `from` admits a user only from a listed address or CIDR, for
#       password and key logins alike, including IPv4-mapped IPv6 forms;
#       an IPv6 prefix that would cover all of IPv4 is refused
# A partner's credentials are only good from the partner's network; a
# correct password or key from elsewhere is refused and audited as such.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
hash=$(make_password_hash secret)
key=$(user_key)
for u in inside outside mapped mapped_other anywhere; do mkdir -p "$TEST_TMP/$u"; done
write_config <<EOF
$(config_head)

user inside
  auth $hash
  auth $key
  root $TEST_TMP/inside
  from 10.0.0.0/8
  from 127.0.0.1/32
  allow / read list

user outside
  auth $hash
  auth $key
  root $TEST_TMP/outside
  from 10.0.0.0/8
  from 2001:db8::/32
  allow / read list

user mapped
  auth $hash
  root $TEST_TMP/mapped
  from ::ffff:127.0.0.1
  allow / read list

user mapped_other
  auth $hash
  root $TEST_TMP/mapped_other
  from ::ffff:10.9.8.7
  allow / read list

user anywhere
  auth $hash
  root $TEST_TMP/anywhere
  from ::/0
  allow / read list
EOF

# IPv4 peers are matched as ::ffff:a.b.c.d, so an IPv6 prefix under /96
# over that space would admit 8.8.8.8 as readily as the partner.
for wide in "::ffff:10.0.0.0/8|write 10.0.0.0/8" "::/80|use a prefix of /96 or longer, or ::/0"; do
    sed "s|from ::ffff:10.9.8.7|from ${wide%%|*}|" "$TEST_TMP/zift.conf" > "$TEST_TMP/wide.conf"
    validate_err "$TEST_TMP/wide.conf" "[user mapped_other] 'from': InvalidFrom" "${wide#*|}"
done
ok "an IPv6 'from' prefix that covers every IPv4 peer is rejected with a hint"
start_zift

"$PY" - <<'EOF'
from client import *
for user, password, want in (("inside", "secret", True), ("inside", None, True),
                             ("outside", "secret", False), ("outside", None, False),
                             ("mapped", "secret", True), ("mapped_other", "secret", False),
                             ("anywhere", "secret", True)):
    how = "password" if password else "key"
    if can_login(user, password) != want:
        fail(f"{user} by {how} from 127.0.0.1: want {'admitted' if want else 'refused'}")
    ok(f"{user} by {how} from 127.0.0.1: {'admitted' if want else 'refused'}")
EOF

for line in '"user":"outside","operation":"auth.password","result":"denied","detail":"source not allowed"' \
            '"user":"outside","operation":"auth.publickey","result":"denied","detail":"source not allowed"' \
            '"user":"mapped_other","operation":"auth.password","result":"denied","detail":"source not allowed"'; do
    log_contains "$line" || fail "not audited: $line"
done
[[ $(count_log '"operation":"auth.password","result":"ok"') == 3 &&
   $(count_log '"operation":"auth.publickey","result":"ok"') == 1 ]] \
    || fail "expected exactly the four admitted logins: $(grep '"auth\.' "$ZIFT_LOG")"
ok "refusals are audited as 'source not allowed'; only the admitted logins succeeded"
