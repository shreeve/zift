#!/usr/bin/env bash
# Shared helpers for Zift integration cases. run.sh exports ZIFT_BIN,
# TEST_TMP (scratch dir), TEST_PORT and TEST_NAME, then runs the case,
# which sources this file. Every server and background job the case
# starts is killed when it exits, pass or fail.
#
# Exit 0 passes, 77 (via `skip`) skips, anything else fails.

set -euo pipefail

: "${ZIFT_BIN:?must be set by run.sh}"
: "${TEST_TMP:?must be set by run.sh}"
: "${TEST_PORT:?must be set by run.sh}"
: "${TEST_NAME:?must be set by run.sh}"

LIB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PY="$LIB_DIR/../.venv/bin/python3"
CACHE="${ZIFT_TEST_CACHE:-$TEST_TMP}"  # shared by the run's cases
HOST_KEY="$TEST_TMP/host_ed25519"
ZIFT_LOG="$TEST_TMP/zift.log"
ZIFT_PID=""
ZIFT_RC=""
PIDS=()     # every server and bg job this case started
BG_PIDS=()  # bg jobs not yet waited for

ok() { echo "  ok: $*"; }
fail() { echo "  fail: $*" >&2; exit 1; }

# `skip <reason>`: the case cannot run here. A reason starting with
# "slow" marks a slow-gated case, which ZIFT_REQUIRE_ALL=1 tolerates.
skip() {
    echo "skip: $*"
    printf '%s\n' "$*" > "$TEST_TMP/.skip"
    exit 77
}

need_paramiko() {
    [[ -x "$PY" ]] || skip "paramiko venv missing: python3 -m venv tests/.venv && tests/.venv/bin/pip install paramiko"
    export PYTHONPATH="$LIB_DIR"
}
need_slow() { [[ "${ZIFT_TEST_SLOW:-0}" == 1 ]] || skip "slow: set ZIFT_TEST_SLOW=1 to run"; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || skip "$1 not installed"; }

cleanup() {
    local pid
    for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill -TERM "$pid" 2>/dev/null || true; done
    for pid in ${PIDS[@]+"${PIDS[@]}"}; do
        wait_exit "$pid" 5 || kill -KILL "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

# `wait_until <seconds> <command...>`: poll until the command succeeds.
wait_until() {
    local limit="$1"; shift
    local end=$((SECONDS + limit))
    until "$@"; do
        (( SECONDS <= end )) || return 1
        sleep 0.05
    done
}

log_contains() { grep -Fq -- "$1" "${2:-$ZIFT_LOG}" 2>/dev/null; }

# `count_log <string> [file]`: lines holding the fixed string, as one integer.
count_log() {
    local n
    n=$(grep -Fc -- "$1" "${2:-$ZIFT_LOG}" 2>/dev/null) || true
    echo "${n:-0}"
}

wait_for_log() { wait_until "${2:-10}" log_contains "$1" "${3:-$ZIFT_LOG}"; }
count_at_least() { (( $(count_log "$1" "$3") >= $2 )); }
wait_for_count() { wait_until "${3:-10}" count_at_least "$1" "$2" "${4:-$ZIFT_LOG}"; }
wait_for_file() { wait_until "${2:-10}" test -e "$1"; }
not_running() { ! kill -0 "$1" 2>/dev/null; }
wait_exit() { wait_until "${2:-10}" not_running "$1"; }

# `bg <command...>`: run in the background, tracked; `wait_bg` fails if
# any job failed.
bg() {
    ( trap - EXIT; "$@" ) &
    BG_PIDS+=("$!")
    PIDS+=("$!")
}
wait_bg() {
    local pid failed=0
    for pid in ${BG_PIDS[@]+"${BG_PIDS[@]}"}; do wait "$pid" || failed=$((failed + 1)); done
    BG_PIDS=()
    return "$failed"
}

make_host_key() { ssh-keygen -q -t ed25519 -N "" -f "$HOST_KEY"; }

# `make_password_hash <plain>`: one Argon2id hash per password per run
# (0.7 s each in Debug), shared through run.sh's cache directory.
make_password_hash() {
    local cache="$CACHE/hash-$(printf '%s' "$1" | od -An -tx1 | tr -d ' \n')"
    [[ -s "$cache" ]] || printf '%s\n' "$1" | "$ZIFT_BIN" hash-password > "$cache"
    cat "$cache"
}

write_config() { cat > "${1:-$TEST_TMP/zift.conf}"; }

# `config_head [server line...]`: the server section with this case's
# listen and host key, for the top of a config heredoc.
config_head() {
    printf 'server\n  listen 127.0.0.1:%s\n  host-key %s\n' "$TEST_PORT" "$HOST_KEY"
    local line
    for line in "$@"; do printf '  %s\n' "$line"; done
}

# `basic_config [server line...]`: user `ally`, password `secret`, root
# $TEST_TMP/root with `allow / read list`.
basic_config() {
    mkdir -p "$TEST_TMP/root"
    write_config <<EOF
$(config_head "$@")

user ally
  auth $(make_password_hash secret)
  root $TEST_TMP/root
  allow / read list
EOF
}

# `start_zift [config]`: serve in the background, logging to $ZIFT_LOG,
# and wait for "listening on".
start_zift() {
    "$ZIFT_BIN" serve "${1:-$TEST_TMP/zift.conf}" >"$ZIFT_LOG" 2>&1 &
    ZIFT_PID=$!
    PIDS+=("$ZIFT_PID")
    wait_until 10 zift_up || { cat "$ZIFT_LOG" >&2; fail "zift never logged 'listening on'"; }
}
zift_up() {
    log_contains "listening on" && return 0
    kill -0 "$ZIFT_PID" 2>/dev/null || { cat "$ZIFT_LOG" >&2; fail "zift exited during startup"; }
    return 1
}

# `stop_zift [signal]`: signal the server and `wait_zift`.
# `wait_zift [seconds]`: wait for the server to exit; sets $ZIFT_RC.
stop_zift() {
    kill -"${1:-TERM}" "$ZIFT_PID" 2>/dev/null || true
    wait_zift
}
wait_zift() {
    wait_exit "$ZIFT_PID" "${1:-15}" || fail "zift did not exit"
    ZIFT_RC=0
    wait "$ZIFT_PID" 2>/dev/null || ZIFT_RC=$?
}

# `sftp_password <user> <password> [command...]`: an OpenSSH sftp
# session driven by expect. Exits with sftp's status; a missing prompt
# fails within 10 s. Extra ssh options go in $SFTP_OPTS. Commands:
#   @eof           wait for the server to close the session (then exit 0)
#   @until <path>  hold the session until <path> exists
sftp_password() {
    need_cmd expect
    ZIFT_TEST_PASSWORD="$2" expect -f "$LIB_DIR/sftp.exp" -- "$TEST_PORT" "$1" "${@:3}"
}

# `validate <config>`: run `zift validate`, output in $TEST_TMP/v.out
# and v.err. `validate_ok` requires exit 0; `validate_err <config>
# <string...>` requires exit 1 and each fixed string in stderr.
validate() { "$ZIFT_BIN" validate "$1" >"$TEST_TMP/v.out" 2>"$TEST_TMP/v.err"; }
validate_ok() {
    validate "$1" || fail "${2:-$1}: validate failed: $(cat "$TEST_TMP/v.err")"
}
validate_err() {
    local conf="$1" rc=0 want; shift
    validate "$conf" || rc=$?
    [[ "$rc" == 1 ]] || fail "$conf: validate exited $rc, want 1: $(cat "$TEST_TMP/v.err")"
    for want in "$@"; do
        grep -Fq -- "$want" "$TEST_TMP/v.err" || fail "$conf: want '$want', got: $(cat "$TEST_TMP/v.err")"
    done
}
