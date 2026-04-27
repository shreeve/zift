#!/usr/bin/env bash
# Zift integration test runner.
#
# Usage:
#   test/run.sh                    run every case under test/cases/
#   test/run.sh <name>...          run named cases (e.g. 02-max-connections)
#   test/run.sh --list             print every case + its first-line description
#   test/run.sh --keep             do not delete TEST_TMP after a passing run
#
# Each case script gets its own:
#   TEST_TMP    scratch dir (deleted after pass unless --keep)
#   TEST_PORT   unique TCP port (22200 + index)
#   TEST_NAME   filename without .sh
#   ZIFT_BIN    absolute path to the built zift
#
# Cases must source test/lib/common.sh and exit 0 on success.

set -uo pipefail

cd "$(dirname "$0")"
ROOT=$(cd .. && pwd)

KEEP=0
LIST=0
SELECT=()

while (($#)); do
    case "$1" in
        --list) LIST=1; shift ;;
        --keep) KEEP=1; shift ;;
        --help|-h)
            sed -n '1,16p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) SELECT+=("$1"); shift ;;
    esac
done

CASES_DIR="$(pwd)/cases"

list_descriptions() {
    for case_path in "$CASES_DIR"/*.sh; do
        local name desc
        name=$(basename "$case_path" .sh)
        desc=$(awk '/^# Test:/{sub(/^# Test: */,""); print; exit}' "$case_path")
        printf '%-32s %s\n' "$name" "$desc"
    done
}

if (( LIST )); then
    list_descriptions
    exit 0
fi

# --- build once up front ---------------------------------------------------
echo "==> building zift"
( cd "$ROOT" && zig build ) >/dev/null

ZIFT_BIN="$ROOT/bin/zift"
[[ -x "$ZIFT_BIN" ]] || { echo "missing $ZIFT_BIN"; exit 2; }

# --- pick the case set -----------------------------------------------------
CASES=()
if [[ ${#SELECT[@]} -eq 0 ]]; then
    while IFS= read -r path; do CASES+=("$path"); done < <(find "$CASES_DIR" -maxdepth 1 -name '*.sh' | sort)
else
    for name in "${SELECT[@]}"; do
        path="$CASES_DIR/$name"
        [[ "$path" != *.sh ]] && path="$path.sh"
        if [[ ! -f "$path" ]]; then
            echo "no such case: $name" >&2
            exit 2
        fi
        CASES+=("$path")
    done
fi

# --- run -------------------------------------------------------------------
mkdir -p tmp
PASS=0
FAIL=0
FAILED=()
INDEX=0

if [[ -t 1 ]]; then
    GREEN=$'\e[32m'; RED=$'\e[31m'; YELLOW=$'\e[33m'; DIM=$'\e[2m'; RESET=$'\e[0m'
else
    GREEN=""; RED=""; YELLOW=""; DIM=""; RESET=""
fi

echo "==> running ${#CASES[@]} case(s)"
for case_path in "${CASES[@]}"; do
    name=$(basename "$case_path" .sh)
    desc=$(awk '/^# Test:/{sub(/^# Test: */,""); print; exit}' "$case_path")
    INDEX=$((INDEX + 1))
    port=$((22200 + INDEX))
    tmp="$(pwd)/tmp/${name}.XXXXXX"
    tmp=$(mktemp -d "$tmp")

    printf '  %-32s %s%s%s ... ' "$name" "$DIM" "$desc" "$RESET"

    if (
        export ZIFT_BIN
        export TEST_TMP="$tmp"
        export TEST_PORT="$port"
        export TEST_NAME="$name"
        bash "$case_path"
    ) >"$tmp/run.log" 2>&1; then
        echo "${GREEN}PASS${RESET}"
        PASS=$((PASS + 1))
        if (( ! KEEP )); then rm -rf "$tmp"; fi
    else
        echo "${RED}FAIL${RESET}"
        FAIL=$((FAIL + 1))
        FAILED+=("$name|$tmp")
    fi
done

echo
echo "==> summary: ${GREEN}${PASS} passed${RESET}, ${RED}${FAIL} failed${RESET}"
if (( FAIL > 0 )); then
    echo "failed cases (with logs):"
    for entry in "${FAILED[@]}"; do
        IFS='|' read -r name tmp <<<"$entry"
        echo "  ${RED}${name}${RESET}  $tmp/run.log"
    done
    exit 1
fi
