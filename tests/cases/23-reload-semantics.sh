#!/usr/bin/env bash
# Test: config reload: any stamp change reloads, stat failures warn once,
#       SIGHUP always reloads, and a bad host key is rejected on reload
# Deploys that restore old mtimes (rsync -t) must not need SIGHUP, and
# `reload-interval 0` must leave SIGHUP as the only trigger.

source "$(dirname "$0")/../lib/common.sh"

make_host_key
CONF="$TEST_TMP/zift.conf"
reloads() { count_log 'config reloaded'; }

# ---------- polling: forward and rewound stamps both reload ----------
basic_config "reload-interval 1s"
start_zift
touch -t 203001010000 "$CONF"
wait_for_count 'config reloaded' 1 5 || fail "a forward mtime change did not reload"
ok "a forward mtime change reloaded within the interval"

touch -t 200001010000 "$CONF"
wait_for_count 'config reloaded' 2 5 || fail "a rewound mtime did not reload"
ok "a rewound mtime reloaded"
sleep 1.5  # at least one more poll of an unchanged file
[[ $(reloads) == 2 ]] || fail "an unchanged config reloaded again"
ok "an unchanged config is not reloaded"

# ---------- stat failure warns once; recovery is announced ----------
mv "$CONF" "$CONF.hidden"
wait_for_log 'cannot stat config file' 5 || fail "no stat-failure warning"
sleep 1.5  # at least one more failed poll
[[ $(count_log 'cannot stat config file') == 1 ]] || fail "the stat-failure warning repeated"
ok "exactly one stat-failure warning"
mv "$CONF.hidden" "$CONF"
touch -t 203101010000 "$CONF"
wait_for_log 'config file readable again' 5 || fail "no recovery message"
ok "recovery announced when the file became readable again"
stop_zift TERM

# ---------- reload-interval 0: SIGHUP is the only trigger ----------
basic_config "reload-interval 0"
start_zift
kill -HUP "$ZIFT_PID"
wait_for_count 'config reloaded' 1 5 || fail "SIGHUP did not reload an unchanged config"
ok "SIGHUP forces a reload of an unchanged config"
touch -t 203001010000 "$CONF"
sleep 2.5  # longer than the default 2 s interval
[[ $(reloads) == 1 ]] || fail "reload-interval 0 still polled the mtime"
ok "reload-interval 0 suppresses mtime-driven reload"
kill -HUP "$ZIFT_PID"
wait_for_count 'config reloaded' 2 5 || fail "SIGHUP did not reload with reload-interval 0"
ok "SIGHUP still reloads with reload-interval 0"
stop_zift TERM

# ---------- a reload with an unreadable host key is rejected ----------
basic_config "reload-interval 1s"
start_zift
sed -i.bak "s|host-key .*|host-key $TEST_TMP/missing-host-key|" "$CONF"
touch -t 203001010000 "$CONF"
wait_for_log 'host-key unreadable' 5 || fail "no 'host-key unreadable' diagnostic on reload"
log_contains 'config reload rejected' || fail "no 'config reload rejected' line"
ok "reload rejected a config with an unreadable host key"
sftp_password ally secret >"$TEST_TMP/auth.log" 2>&1 \
    || fail "server stopped serving after a rejected reload"
ok "the previous config still serves"
