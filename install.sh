#!/usr/bin/env bash
#
# install.sh — install zift with one command (macOS and Linux):
#
#   curl -fsSL https://raw.githubusercontent.com/shreeve/zift/main/install.sh | bash
#
# Pin a version by passing a tag (with or without the leading v), and
# uninstall with --uninstall:
#
#   curl -fsSL .../install.sh | bash -s v1.2.3
#   curl -fsSL .../install.sh | bash -s -- --uninstall
#
# janus and harbor publish the same archives and install in the same two
# steps, but their copies of this script still carry project-specific
# code, so it is not yet a drop-in for them. It downloads the release archive for this platform, checks its sha256
# against the release's checksums, and runs the archive's own install.sh
# (with --uninstall to uninstall), which knows where the project goes.
# Every release publishes:
#
#   NAME-vX.Y.Z-<plat>.tar.gz     unpacks to NAME-vX.Y.Z-<plat>/install.sh ...
#   NAME-vX.Y.Z-checksums.txt     sha256sum output over the archives
#
# with <plat> one of osx-arm64, osx-amd64, linux-amd64, linux-arm64.

set -euo pipefail

REPO=shreeve/zift
NAME=zift

Red='' Dim='' Color_Off=''
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then Red='\033[0;31m' Dim='\033[0;2m' Color_Off='\033[0m'; fi
info() { printf "${Dim}%s${Color_Off}\n" "$*"; }
fail() { printf "${Red}error${Color_Off}: %s\n" "$*" >&2; exit 1; }

# Everything lives in main() so a truncated `curl | bash` download can
# never execute a half-delivered script.
main() {
  mode=
  if [ "${1:-}" = --uninstall ]; then mode=--uninstall; shift; fi

  command -v curl >/dev/null || fail "curl is required"
  command -v tar  >/dev/null || fail "tar is required"

  os=$(uname -s) arch=$(uname -m)
  # A shell running under Rosetta reports x86_64 on Apple Silicon.
  if [ "$os" = Darwin ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
    arch=arm64
  fi
  case "$os-$arch" in
    Darwin-arm64)              plat=osx-arm64   ;;
    Darwin-x86_64)             plat=osx-amd64   ;;
    Linux-x86_64)              plat=linux-amd64 ;;
    Linux-aarch64|Linux-arm64) plat=linux-arm64 ;;
    MINGW*|MSYS*|CYGWIN*)
      ps1="https://raw.githubusercontent.com/$REPO/main/install.ps1"
      curl -fsSIL -o /dev/null "$ps1" 2>/dev/null && fail "on Windows use install.ps1: irm $ps1 | iex"
      fail "$NAME has no Windows installer" ;;
    *) fail "unsupported platform: $os $arch" ;;
  esac

  # The tag: the argument, or the one `releases/latest` redirects to.
  tag=${1:-}
  if [ -n "$tag" ]; then
    case "$tag" in v*) ;; *) tag="v$tag" ;; esac
  else
    tag=$(curl -fsSLI --retry 3 --retry-delay 1 -o /dev/null -w '%{url_effective}' \
      "https://github.com/$REPO/releases/latest") || fail "cannot reach github.com"
    tag=${tag##*/}
  fi
  # A typo, a stray flag, or .../latest redirecting to .../releases when
  # there are none: only a real tag shape goes further.
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || fail "not a release tag: ${tag:-none} (expected vX.Y.Z)"

  base="https://github.com/$REPO/releases/download/$tag"
  asset="$NAME-$tag-$plat.tar.gz"
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT

  curl -fsSL --retry 3 --retry-delay 1 -o "$tmp/checksums.txt" "$base/$NAME-$tag-checksums.txt" \
    || fail "no $NAME release $tag with a checksums file (see https://github.com/$REPO/releases)"
  want=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' "$tmp/checksums.txt")
  [ -n "$want" ] || fail "no $plat build is published for $NAME $tag"

  info "$NAME $tag ($plat)"
  curl -fSL --retry 3 --retry-delay 1 --progress-bar -o "$tmp/$asset" "$base/$asset" \
    || fail "download failed: $base/$asset"
  if command -v sha256sum >/dev/null; then
    sum=$(sha256sum "$tmp/$asset" | cut -d' ' -f1)
  else
    sum=$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1)
  fi
  [ "$sum" = "$want" ] || fail "checksum mismatch for $asset"

  tar -xzf "$tmp/$asset" -C "$tmp"
  inner="$tmp/$NAME-$tag-$plat/install.sh"
  [ -f "$inner" ] || fail "$asset has no install.sh"
  # An archive whose installer predates --uninstall would install instead.
  if [ -n "$mode" ] && ! grep -q -- --uninstall "$inner"; then
    fail "the $tag installer cannot uninstall; remove $NAME by hand"
  fi
  bash "$inner" $mode
}

main "$@"
