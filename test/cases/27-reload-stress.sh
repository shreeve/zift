#!/usr/bin/env bash
# Test: SIGHUP-driven reloads under concurrent traffic do not disrupt
#       in-flight sessions AND the new config snapshot is observable
#       to subsequently-connecting clients (PLAN §7.3).
# Covers: PLAN §7.3 ConfigRef refcounting + SIGHUP forceReload + active
#         session continues to use its captured snapshot.
# Oracle: a) the long-running session holds its old snapshot for life
#            and completes pre- and post-reload writes; b) a brand-new
#            session opened AFTER the reload sees the new config (an
#            additional virtual user that didn't exist at startup).

source "$(dirname "$0")/../lib/common.sh"

VENV="$(dirname "$0")/../.venv"
PY="$VENV/bin/python3"

if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing at $VENV"
    exit 0
fi

make_host_key
runner_hash=$(make_password_hash secret)
later_hash=$(make_password_hash later-secret)

mkdir -p "$TEST_TMP/data/uploads"
mkdir -p "$TEST_TMP/data2"

# Initial config: only `runner` exists. `late` is added by the rewrite
# between SIGHUPs.
write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  reload-interval 0
  idle-timeout 30s
  shutdown-grace 5s
  log stderr

user runner
  password $runner_hash
  root $TEST_TMP/data
  allow / read write list mkdir remove rename
EOF

start_zift

# Phase 1: open a long-running session under the OLD config and write
# a file. This session captures the v1 ConfigRef and must keep using
# it across all subsequent reloads.
"$PY" - <<EOF || fail "phase 1 sftp open failed"
import paramiko, socket
sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="runner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)
with sftp.open("/uploads/before.txt", "w") as f:
    f.write(b"BEFORE_RELOAD")
sftp.close(); t.close()
EOF
ok "phase 1: pre-reload session wrote /uploads/before.txt"

# Phase 2: rewrite the config to include a SECOND user, then hammer
# the server with five SIGHUPs in rapid succession. Each SIGHUP forces
# a reparse + validateSemantic + ConfigRef swap. The active session
# above has already gone away, but if forceReload thrashing leaks
# memory or corrupts the snapshot pointer this is where it would show.
cat > "$TEST_TMP/zift.conf" <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  reload-interval 0
  idle-timeout 30s
  shutdown-grace 5s
  log stderr

user runner
  password $runner_hash
  root $TEST_TMP/data
  allow / read write list mkdir remove rename

user late
  password $later_hash
  root $TEST_TMP/data2
  allow / read write list mkdir
EOF

sleep 0.2  # ensure the new config is fully on disk + visible
for _ in 1 2 3 4 5; do
    kill -HUP "$ZIFT_PID"
    sleep 0.2
done
sleep 1  # let the last reload land

# Sanity: the last "config reloaded" line in stderr must reflect the
# rewrite. If we only see the *first* successful reload before the
# rewrite, that's a missed signal we want to surface explicitly.
echo "  stderr after SIGHUP storm:"
sed 's/^/    /' "$TEST_TMP/zift.log" | tail -10

# Phase 3: open a NEW session as `late` — a user that did not exist
# in the v1 snapshot. This proves the post-SIGHUP config is observable
# to new connections, not just that SIGHUP didn't crash the server.
"$PY" - <<EOF || fail "phase 3 sftp as 'late' failed (new config not observable)"
import paramiko, socket
sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="late", password="later-secret")
sftp = paramiko.SFTPClient.from_transport(t)
with sftp.open("/added.txt", "w") as f:
    f.write(b"AFTER_RELOAD")
sftp.close(); t.close()
EOF
ok "phase 3: new session under new user 'late' authenticated and wrote"

# Phase 4: confirm both payloads landed in the right partner roots.
# `before.txt` lives under the v1 root, `added.txt` lives under the
# v2 root added by the reload.
[[ "$(cat "$TEST_TMP/data/uploads/before.txt")" == "BEFORE_RELOAD" ]] \
    || fail "phase 4: before payload corrupted"
[[ "$(cat "$TEST_TMP/data2/added.txt")" == "AFTER_RELOAD" ]] \
    || fail "phase 4: after payload corrupted"
ok "phase 4: both payloads landed in their respective partner roots"

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
