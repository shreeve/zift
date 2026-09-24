#!/usr/bin/env bash
# Shared helpers for Zift integration tests.
#
# A test case is a bash script under tests/cases/. The runner exports
# these env vars before sourcing this file:
#
#   ZIFT_BIN     absolute path to the built zift binary
#   TEST_TMP     per-test scratch directory (auto-cleaned)
#   TEST_PORT    unique TCP port for this test
#   TEST_NAME    case name (filename without .sh)
#
# The case script then sources this file and uses:
#
#   make_host_key
#   make_password_hash <plaintext>     -> a… credential on stdout
#   write_config <heredoc-body>        -> writes $TEST_TMP/zift.conf
#   start_zift [extra-config-args]     -> launches server, exports $ZIFT_PID
#   stop_zift [SIGNAL]                 -> sends signal, waits for exit
#   wait_listening                     -> blocks until server log says "listening"
#   log_contains <pattern>             -> checks server stderr log
#   sftp_password <user> <pass> <cmds>  -> runs sftp via expect with password
#   ok <message>                       -> prints "ok: ...", returns 0
#   fail <message>                     -> prints "fail: ...", exits 1
#   skip <reason>                      -> the case cannot run here: exit 77
#   need_paramiko / need_slow / need_cmd <tool>  -> skip unless available

set -euo pipefail

: "${ZIFT_BIN:?must be set by runner}"
: "${TEST_TMP:?must be set by runner}"
: "${TEST_PORT:?must be set by runner}"
: "${TEST_NAME:?must be set by runner}"

LIB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PY="$LIB_DIR/../.venv/bin/python3"
ZIFT_PID=""
ZIFT_LOG="$TEST_TMP/zift.log"
PIDS=()  # every server and background job this case started

# `skip <reason>`: the case cannot run here. A reason starting with
# "slow" marks a slow-gated case, which ZIFT_REQUIRE_ALL=1 tolerates.
skip() {
    echo "skip: $*"
    printf '%s\n' "$*" > "$TEST_TMP/.skip"
    exit 77
}
need_paramiko() {
    [[ -x "$PY" ]] || skip "paramiko venv missing: python3 -m venv tests/.venv && tests/.venv/bin/pip install paramiko"
}
need_slow() { [[ "${ZIFT_TEST_SLOW:-0}" == 1 ]] || skip "slow: set ZIFT_TEST_SLOW=1 to run"; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || skip "$1 not installed"; }

# Stop what this case started, and nothing else on the host.
cleanup() {
    local pid
    for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill -TERM "$pid" 2>/dev/null || true; done
    for pid in ${PIDS[@]+"${PIDS[@]}"}; do
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.5
        done
        kill -KILL "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

# Track backgrounded test jobs so we can wait for them without also
# waiting for the zift server (which start_zift also backgrounds).
BG_PIDS=()

# Run a command in a backgrounded subshell that does NOT inherit the
# EXIT cleanup trap, and that we can wait for via `wait_bg` later.
bg() {
    ( trap - EXIT; "$@" ) &
    BG_PIDS+=("$!")
    PIDS+=("$!")
}

# Wait for every job started via `bg`. Each child's exit code is ignored
# (test cases assert via the audit log, not exit codes).
wait_bg() {
    local pid
    for pid in "${BG_PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    BG_PIDS=()
}

make_host_key() {
    ssh-keygen -t ed25519 -f "$TEST_TMP/host_ed25519" -N "" -q
}

# One Argon2id hash (0.7 s in Debug) per password per run, cached in the
# directory run.sh shares between cases.
make_password_hash() {
    local cache="${ZIFT_TEST_CACHE:-$TEST_TMP}/hash-$(printf '%s' "$1" | od -An -tx1 | tr -d ' \n')"
    [[ -s "$cache" ]] || printf '%s\n' "$1" | "$ZIFT_BIN" hash-password > "$cache"
    cat "$cache"
}

write_config() {
    cat > "$TEST_TMP/zift.conf"
}

start_zift() {
    "$ZIFT_BIN" serve "$TEST_TMP/zift.conf" >"$ZIFT_LOG" 2>&1 &
    ZIFT_PID=$!
    PIDS+=("$ZIFT_PID")
    wait_listening
}

stop_zift() {
    local signal="${1:-TERM}"
    if [[ -n "$ZIFT_PID" ]]; then
        kill -"$signal" "$ZIFT_PID" 2>/dev/null || true
    fi
}

wait_listening() {
    local n=0
    while ! grep -q "listening on" "$ZIFT_LOG" 2>/dev/null; do
        n=$((n + 1))
        if [[ $n -gt 50 ]]; then
            echo "fail: zift never logged 'listening on' (see $ZIFT_LOG)" >&2
            cat "$ZIFT_LOG" >&2 || true
            return 1
        fi
        sleep 0.1
    done
}

log_contains() {
    local pattern="$1"
    grep -q "$pattern" "$ZIFT_LOG"
}

# Run an interactive sftp session with a password using expect. The
# remaining arguments are sftp commands fed one per line. Returns sftp's
# exit status; stdout is the captured session.
sftp_password() {
    local user="$1"; shift
    local pass="$1"; shift
    local commands=("$@")

    local cmd_file
    cmd_file="$TEST_TMP/sftp-cmds-$$.exp"
    {
        echo 'set timeout 30'
        # The password is read from the environment so a value containing
        # Tcl-special characters (`"`, `$`, `[`, `]`, `\`) is data, not
        # script. Interpolating directly into a `send "..."` string is
        # unsafe — see the test/lib note in PLAN §11.5.
        echo 'set password $env(ZIFT_TEST_PASSWORD)'
        printf 'spawn sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 -P %s %s@127.0.0.1\n' \
            "$TEST_PORT" "$user"
        echo 'expect "password:"'
        echo 'send -- "$password\r"'
        echo 'expect "sftp>"'
        for cmd in "${commands[@]}"; do
            # Commands are still interpolated; tests pass known-safe
            # values. If we ever need to script hostile commands, route
            # them through env vars too.
            printf 'send -- %s\nexpect "sftp>"\n' "\"$cmd\r\""
        done
        echo 'send -- "bye\r"'
        echo 'expect eof'
    } > "$cmd_file"
    ZIFT_TEST_PASSWORD="$pass" expect -f "$cmd_file"
}

ok() {
    echo "  ok: $*"
}

fail() {
    echo "  fail: $*" >&2
    # Hard-exit the test case. Without this, an `if … else fail "…" fi`
    # block produced a fail message but let the script keep running, so
    # the test runner's "exit-code-only" pass/fail check could mark a
    # test "PASS" even after internal assertions failed. Always exit
    # with a non-zero code instead.
    exit 1
}
