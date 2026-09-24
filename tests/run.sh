#!/usr/bin/env bash
# Zift integration test runner.
#
# Usage: tests/run.sh [--list] [--keep] [case...]
#   --list   print every case and its description
#   --keep   keep each case's scratch dir (tests/tmp/<case>.*) after it passes
#
# Environment:
#   ZIFT_BIN=<path>       test this binary and skip the build; otherwise
#                         run `zig build` (Debug) and stop if it fails
#   ZIFT_TEST_PORT_BASE   the Nth case run listens on base+N (default 22200)
#   ZIFT_TEST_TIMEOUT     seconds before a case and its servers are
#                         killed and it fails (default 180)
#   ZIFT_TEST_SLOW=1      also run slow cases
#   ZIFT_REQUIRE_ALL=1    any skipped case fails the run, except slow ones
#
# A case sources tests/lib/common.sh and exits 0 to pass, 77 to skip
# (`skip "<reason>"`), anything else to fail.

set -uo pipefail

if [[ -n "${ZIFT_BIN:-}" ]]; then
    [[ -x "$ZIFT_BIN" && -f "$ZIFT_BIN" ]] || { echo "ZIFT_BIN=$ZIFT_BIN is not an executable file" >&2; exit 2; }
    ZIFT_BIN=$(cd "$(dirname "$ZIFT_BIN")" && pwd)/$(basename "$ZIFT_BIN")
fi
cd "$(dirname "$0")"
ROOT=$(cd .. && pwd)
CASES_DIR="$(pwd)/cases"

KEEP=0
SELECT=()
while (($#)); do
    case "$1" in
        --list)
            for path in "$CASES_DIR"/*.sh; do
                printf '%-36s %s\n' "$(basename "$path" .sh)" "$(sed -n 's/^# Test: *//p' "$path" | head -1)"
            done
            exit 0 ;;
        --keep) KEEP=1 ;;
        -h|--help) sed -n '2,18p' "$(basename "$0")" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) SELECT+=("$1") ;;
    esac
    shift
done

CASES=()
if ((${#SELECT[@]} == 0)); then
    CASES=("$CASES_DIR"/*.sh)
else
    for name in "${SELECT[@]}"; do
        path="$CASES_DIR/${name%.sh}.sh"
        [[ -f "$path" ]] || { echo "no such case: $name" >&2; exit 2; }
        CASES+=("$path")
    done
fi

if [[ -z "${ZIFT_BIN:-}" ]]; then
    echo "==> zig build"
    if ! build_log=$(cd "$ROOT" && zig build 2>&1); then
        echo "$build_log" >&2
        echo "build failed; not testing a stale binary" >&2
        exit 2
    fi
    ZIFT_BIN="$ROOT/bin/zift"
fi

mkdir -p tmp
ZIFT_TEST_CACHE=$(mktemp -d "$(pwd)/tmp/cache.XXXXXX")
CURRENT=""
trap 'rm -rf "$ZIFT_TEST_CACHE"' EXIT
trap '[[ -n "$CURRENT" ]] && pkill -KILL -g "$CURRENT"; exit 130' INT TERM
export ZIFT_BIN ZIFT_TEST_CACHE
TIMEOUT=${ZIFT_TEST_TIMEOUT:-180}

if [[ -t 1 ]]; then
    GREEN=$'\e[32m' RED=$'\e[31m' YELLOW=$'\e[33m' DIM=$'\e[2m' RESET=$'\e[0m'
else
    GREEN="" RED="" YELLOW="" DIM="" RESET=""
fi

# Run one case in its own process group, so a timeout or a leaked
# server can be killed without touching anything else on the host.
run_case() {
    local path="$1" tmp="$2" port="$3" pid watchdog rc
    TEST_TMP="$tmp" TEST_PORT="$port" TEST_NAME=$(basename "$path" .sh) \
        perl -e 'setpgrp(0, 0); exec @ARGV or die "exec: $!"' bash "$path" \
        </dev/null >"$tmp/run.log" 2>&1 &
    pid=$!
    CURRENT=$pid
    perl -e '($pid, $limit, $mark) = @ARGV; sleep $limit; kill(0, $pid) or exit;
        open(my $f, ">", $mark); kill("TERM", -$pid); sleep 3; kill("KILL", -$pid)' \
        "$pid" "$TIMEOUT" "$tmp/.timeout" &
    watchdog=$!
    wait "$pid"; rc=$?
    kill "$watchdog" 2>/dev/null; wait "$watchdog" 2>/dev/null
    # Anything the case left behind in its group, e.g. a server it lost track of.
    pkill -KILL -g "$pid" 2>/dev/null
    return "$rc"
}

echo "==> running ${#CASES[@]} case(s) with $ZIFT_BIN"
PASS=0 FAIL=0 SKIP=0 INDEX=0
FAILED=() SKIPPED_HARD=()
for path in "${CASES[@]}"; do
    name=$(basename "$path" .sh)
    INDEX=$((INDEX + 1))
    tmp=$(mktemp -d "$(pwd)/tmp/$name.XXXXXX")
    printf '  %-36s %s%s%s ... ' "$name" "$DIM" "$(sed -n 's/^# Test: *//p' "$path" | head -1 | cut -c1-60)" "$RESET"
    start=$SECONDS
    run_case "$path" "$tmp" $((${ZIFT_TEST_PORT_BASE:-22200} + INDEX)); rc=$?
    took="$DIM($((SECONDS - start))s)$RESET"
    if [[ -e "$tmp/.timeout" ]]; then
        echo "${RED}FAIL${RESET} (timed out after ${TIMEOUT}s)"
        FAIL=$((FAIL + 1)); FAILED+=("$name|$tmp")
    elif ((rc == 0)); then
        echo "${GREEN}PASS${RESET} $took"
        PASS=$((PASS + 1))
        ((KEEP)) || rm -rf "$tmp"
    elif ((rc == 77)); then
        reason=$(cat "$tmp/.skip" 2>/dev/null || echo "no reason given")
        echo "${YELLOW}SKIP${RESET} ($reason)"
        SKIP=$((SKIP + 1))
        [[ "$reason" == slow* ]] || SKIPPED_HARD+=("$name")
        ((KEEP)) || rm -rf "$tmp"
    else
        echo "${RED}FAIL${RESET} $took"
        FAIL=$((FAIL + 1)); FAILED+=("$name|$tmp")
    fi
done

echo
echo "==> summary: ${GREEN}${PASS} passed${RESET}, ${YELLOW}${SKIP} skipped${RESET}, ${RED}${FAIL} failed${RESET}"
for entry in ${FAILED[@]+"${FAILED[@]}"}; do
    echo "  ${RED}${entry%%|*}${RESET}  ${entry#*|}/run.log"
done
if [[ "${ZIFT_REQUIRE_ALL:-0}" == 1 ]] && ((${#SKIPPED_HARD[@]} > 0)); then
    echo "${RED}ZIFT_REQUIRE_ALL=1: skipped ${SKIPPED_HARD[*]}${RESET}"
    exit 1
fi
((FAIL == 0))
