#!/usr/bin/env bash
# verify-release.sh — assert a release artifact's runtime dependency
# surface matches what we promised.
#
# Run as: build/verify-release.sh <artifact>
#
# Wired into `zig build release` (build.zig) so a regression in the
# release dependency surface fails the build, not the deploy.
#
# This script's role evolves as the release pipeline grows:
#
#   Phase 1 (today, dynamic libssh):  asserts the small allowlist of
#       known dynamic deps (libssh, libc, optional pthread/dl/rt/m/
#       gcc_s) on Linux, plus libssh + libSystem on macOS. Any new
#       dep slipping in is a real regression — either the build picked
#       up an unwanted system library or upstream libssh added a new
#       transitive that we should evaluate.
#
#   Phase 2 (after static linking):  flip `LINUX_ALLOWED` to `^$`
#       (empty) so the zero-NEEDED contract PLAN §13 promises holds
#       literally on the published Linux binary. macOS shrinks to
#       libSystem + system frameworks only.
#
# Both phases use the same script and the same wiring; only the
# allowlist regex changes. The "zero-NEEDED" terminology in TODOS.md
# is the Linux phase-2 case.

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <artifact-path>" >&2
    exit 2
fi

artifact="$1"
[[ -f "$artifact" ]] || { echo "verify-release: not a file: $artifact" >&2; exit 2; }

# ----- detect binary kind without relying on any host-specific tool ----------
# ELF magic is `7f 45 4c 46`; Mach-O magic is one of `feedface`/`feedfacf`/
# `cafebabe` (fat) / their byte-swapped variants. We dispatch on the first
# four bytes so a macOS host inspecting an ELF (cross-compiled from a
# vendored libssh in phase 2) and vice-versa both work.
magic=$(od -An -tx1 -N4 "$artifact" | tr -d ' \n')
case "$magic" in
    7f454c46)
        kind="elf"
        ;;
    cffaedfe|cefaedfe|feedface|feedfacf|cafebabe|bebafeca)
        kind="macho"
        ;;
    *)
        echo "verify-release: unknown binary magic '$magic' in $artifact" >&2
        exit 2
        ;;
esac

# ----- per-kind allowlist + extraction --------------------------------------
# `LINUX_ALLOWED`: regex matched against each DT_NEEDED basename.
# v0.2.0+ ships fully-static Linux binaries (libssh + mbedTLS + zlib
# all linked statically), so the allowlist is empty — any NEEDED
# entry at all fails the build. The empty alternation `^()$` matches
# the empty line, so when `deps` is empty (truly zero NEEDED) the
# `grep -Ev` filter yields no unexpected output and we pass with
# "(zero entries — fully static)". Any non-empty NEEDED entry falls
# through and fails.
LINUX_ALLOWED=''

# `MACOS_ALLOWED`: regex matched against each LC_LOAD_DYLIB path.
# v0.2.0+ links statically against vendored libssh + mbedTLS, leaving
# only `libSystem` (the macOS C runtime — there is no static libc on
# Darwin) and optionally `libc++` (only present if Zig pulls in C++
# parts of stdlib, which it doesn't here, but kept in case it does
# in a future build) and system frameworks. NO Homebrew paths
# permitted: an `/opt/homebrew/.../libssh.4.dylib` entry would mean
# the static-link broke and we accidentally went back to dynamic.
MACOS_ALLOWED='^(/usr/lib/libSystem\.B\.dylib|/usr/lib/libc\+\+\..*\.dylib|/System/Library/Frameworks/.*\.framework/.*)$'

case "$kind" in
    elf)
        # `objdump -p` is the most portable tool for DT_NEEDED parsing
        # on a Linux toolchain. macOS LLVM ships an `objdump` that
        # speaks ELF too, so this command also works on a macOS host
        # inspecting a cross-compiled Linux binary.
        deps=$(objdump -p "$artifact" 2>/dev/null | awk '/NEEDED/ {print $2}' | sort -u)
        allowed_re="$LINUX_ALLOWED"
        kind_label="DT_NEEDED (ELF)"
        ;;
    macho)
        # `otool -L` is the right tool for Mach-O LC_LOAD_DYLIB inspection.
        # macOS ships it; on Linux LLVM ships `llvm-otool` (sometimes
        # `otool`). We call `otool` directly and let the build fail with
        # a clear "command not found" if the host lacks it.
        deps=$(otool -L "$artifact" 2>/dev/null | tail -n +2 | awk '{print $1}' | sort -u)
        allowed_re="$MACOS_ALLOWED"
        kind_label="LC_LOAD_DYLIB (Mach-O)"
        ;;
esac

# ----- compare --------------------------------------------------------------
unexpected=$(echo "$deps" | grep -Ev "$allowed_re" || true)
if [[ -n "$unexpected" ]]; then
    echo "verify-release: FAIL — unexpected runtime deps in $artifact"
    echo "  binary kind: $kind_label"
    echo "  allowlist  : $allowed_re"
    echo "  unexpected :"
    echo "$unexpected" | sed 's/^/    /'
    echo
    echo "  Either the build picked up a new system library (regression)"
    echo "  or the allowlist needs updating to match a deliberate change"
    echo "  in our dependency surface. Update build/verify-release.sh"
    echo "  if the new dep is intentional."
    exit 1
fi

# Success path: report the surface so the build log captures what shipped.
echo "verify-release: OK — $kind_label in $(basename "$artifact"):"
if [[ -z "$deps" ]]; then
    echo "  (zero entries — fully static)"
else
    echo "$deps" | sed 's/^/  /'
fi
