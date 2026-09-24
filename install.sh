#!/usr/bin/env bash
#
# install.sh — install the zift binary with one command (Linux and macOS):
#
#   curl -fsSL https://raw.githubusercontent.com/shreeve/zift/main/install.sh | bash
#
# Pin a version by passing a tag (with or without the leading v):
#
#   curl -fsSL .../install.sh | bash -s v0.12.0
#
# Downloads the release binary for this platform, verifies its sha256
# against the release's SHA256SUMS, and installs it. To also check the
# cosign signature on SHA256SUMS, install by hand (docs/operate.md).
#
# As root, zift lands in /usr/local/bin; as a user, in ~/.local/bin. On a
# host that runs zift as a service it goes to /usr/local/bin, the path the
# unit runs, using sudo for that one write and saying so first. BIN=...
# overrides all of this and never elevates.
#
# This installs the binary only. The service user, host key, config and
# unit are docs/operate.md: a script piped from the internet must never
# touch a config that carries partner credentials.
#
# Uninstall the same way; the config, host key, partner trees and unit
# stay:
#
#   curl -fsSL .../install.sh | bash -s -- --uninstall

set -euo pipefail

REPO=shreeve/zift
NAME=zift

# Color only when stdout is a terminal, and never against NO_COLOR.
Color_Off='' Red='' Green='' Dim='' Bold_Green='' Bold_White=''
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  Color_Off='\033[0m'
  Red='\033[0;31m' Green='\033[0;32m' Dim='\033[0;2m'
  Bold_Green='\033[1;32m' Bold_White='\033[1m'
fi

info() { printf "${Dim}%s${Color_Off}\n" "$*"; }
warn() { printf "${Dim}%s${Color_Off}\n" "$*" >&2; }
fail() { printf "${Red}error${Color_Off}: %s\n" "$*" >&2; exit 1; }
tildify() { case "$1" in "$HOME"/*) printf '~%s' "${1#"$HOME"}" ;; *) printf '%s' "$1" ;; esac; }

host_runs_service() {
  command -v systemctl >/dev/null \
    && systemctl list-unit-files "$NAME.service" >/dev/null 2>&1
}

# SUDO is the prefix for the one privileged write, empty when none is
# needed. `sudo -n` first, so a passwordless setup is seamless; a prompt
# only when a terminal can answer it, since stdin is the curl pipe.
SUDO=""
try_sudo() {
  if sudo -n true 2>/dev/null; then
    SUDO="sudo -n"
  elif command -v sudo >/dev/null && (exec </dev/tty) 2>/dev/null; then
    SUDO="sudo"
  else
    return 1
  fi
}

resolve_dest() {
  [ -n "${BIN:-}" ] && return 0
  if [ "$(id -u)" = 0 ]; then BIN=/usr/local/bin
  elif host_runs_service && try_sudo; then BIN=/usr/local/bin
  else BIN="$HOME/.local/bin"; fi
}

# The shape the release workflow accepts.
valid_tag() {
  [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]
}

# Remove only what install put down: the binary. Removing a host key would
# break every partner's known_hosts on the next connect.
uninstall() {
  local explicit=${BIN:-}
  resolve_dest
  # A root install and a user install land in different places; without
  # BIN=, look in both.
  if [ ! -e "$BIN/$NAME" ] && [ -z "$explicit" ]; then
    for dir in /usr/local/bin "$HOME/.local/bin"; do
      if [ -e "$dir/$NAME" ]; then BIN=$dir; SUDO=""; break; fi
    done
  fi
  [ -e "$BIN/$NAME" ] || fail "$NAME is not installed at $(tildify "$BIN/$NAME") (BIN= if it lives elsewhere)"
  # Never delete, least of all with sudo, a file that is not zift.
  "$BIN/$NAME" version 2>/dev/null | head -1 | grep -q "^$NAME " \
    || fail "$(tildify "$BIN/$NAME") is not a $NAME binary; not removing it"
  if [ -z "$SUDO" ] && [ -z "$explicit" ] && [ ! -w "$BIN" ] && try_sudo; then
    info "using sudo to remove $BIN/$NAME"
  fi
  $SUDO rm -f "$BIN/$NAME" || fail "cannot remove $(tildify "$BIN/$NAME"); re-run under sudo if it was installed system-wide"
  printf "${Green}$NAME was removed from ${Bold_Green}%s${Color_Off}\n" "$(tildify "$BIN")"
  info "your config, host key, partner trees and service unit are untouched"
}

# Everything lives in main() so a truncated `curl | bash` download can
# never execute a half-delivered script.
main() {
  case "${1:-}" in
    --uninstall) uninstall; return ;;
  esac

  command -v curl >/dev/null || fail "curl is required"

  # --- platform -> release asset suffix ------------------------------------
  os=$(uname -s) arch=$(uname -m)
  # A shell running under Rosetta reports x86_64 on Apple Silicon.
  if [ "$os" = Darwin ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
    arch=arm64
  fi
  case "$os-$arch" in
    Linux-x86_64)              plat=x86_64-linux   ;;
    Linux-aarch64|Linux-arm64) plat=aarch64-linux  ;;
    Darwin-arm64)              plat=aarch64-macos  ;;
    Darwin-x86_64)             plat=x86_64-macos   ;;
    MINGW*|MSYS*|CYGWIN*)      fail "Windows is not supported; zift is a Unix daemon" ;;
    *)                         fail "unsupported platform: $os $arch" ;;
  esac

  # --- version: argument, or the tag `releases/latest` redirects to --------
  tag=${1:-}
  if [ -n "$tag" ]; then
    case "$tag" in v*) ;; *) tag="v$tag" ;; esac
    valid_tag "$tag" || fail "not a release tag: ${1} (expected vX.Y.Z or vX.Y.Z-pre, e.g. v0.12.0)"
  else
    tag=$(curl -fsSLI --retry 3 --retry-delay 1 -o /dev/null -w '%{url_effective}' \
      "https://github.com/$REPO/releases/latest") || fail "cannot reach github.com"
    tag=${tag##*/}
    # With no releases, .../latest redirects to .../releases.
    valid_tag "$tag" || fail "no releases found for $REPO"
  fi

  asset="$NAME-${tag#v}-$plat"
  base="https://github.com/$REPO/releases/download/$tag"

  # The staged copy beside the destination is removed on any failure or
  # interrupt, so the old binary is never left half-replaced.
  tmp=$(mktemp -d) staged=""
  cleanup() {
    rm -rf "$tmp"
    if [ -n "$staged" ]; then $SUDO rm -f "$staged" 2>/dev/null || true; fi
  }
  trap cleanup EXIT
  trap 'exit 1' HUP INT TERM

  info "$NAME $tag ($plat)"
  curl -fSL --retry 3 --retry-delay 1 --progress-bar -o "$tmp/$asset" "$base/$asset" \
    || fail "download failed: $base/$asset"

  # --- verify against the release's published checksums --------------------
  curl -fsSL --retry 3 --retry-delay 1 -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" \
    || fail "download failed: SHA256SUMS"
  if command -v sha256sum >/dev/null; then
    sum=$(sha256sum "$tmp/$asset" | cut -d' ' -f1)
  else
    sum=$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1)
  fi
  want=$(awk -v f="$asset" '$2 == f { print $1 }' "$tmp/SHA256SUMS")
  [ -n "$want" ]        || fail "no checksum published for $asset"
  [ "$sum" = "$want" ]  || fail "checksum mismatch for $asset"

  # --- install -------------------------------------------------------------
  resolve_dest
  dest="$BIN/$NAME"
  [ -n "$SUDO" ] && info "using sudo to install to $dest (this host runs $NAME as a service)"

  # Plain first: a missing ~/.local reads as unwritable, and sudo must
  # never create a user's own directories as root.
  [ -d "$BIN" ] || install -d -m 0755 "$BIN" 2>/dev/null || $SUDO install -d -m 0755 "$BIN" 2>/dev/null || true
  [ -d "$BIN" ] || fail "cannot create $(tildify "$BIN"); set BIN= to a writable directory"
  if [ -z "$SUDO" ] && [ ! -w "$BIN" ]; then
    fail "$(tildify "$BIN") is not writable; re-run under sudo, or set BIN="
  fi

  # A user install on a service host is almost always a missing sudo: the
  # daemon never sees it. Warn rather than refuse, since a user copy still
  # serves hash-password and validate.
  if [ -z "$SUDO" ] && [ "$(id -u)" != 0 ] && host_runs_service; then
    printf '\n'
    warn "This host runs $NAME as a service, but this is a user install to $(tildify "$dest")"
    warn "and sudo was not available, so the daemon will not pick it up. To install that one:"
    warn ""
    warn "  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sudo BIN=/usr/local/bin bash -s $tag"
    printf '\n'
  fi

  # Is the running daemon executing the file about to be replaced? The new
  # binary is a new inode renamed over the old one, so the daemon keeps
  # running the old code until it restarts.
  replacing_running=false
  if command -v systemctl >/dev/null && systemctl is-active --quiet "$NAME" 2>/dev/null; then
    pid=$(systemctl show "$NAME" -p MainPID --value 2>/dev/null || true)
    if [ -n "${pid:-}" ] && [ "$pid" != 0 ]; then
      case "$($SUDO readlink "/proc/$pid/exe" 2>/dev/null || true)" in
        "$dest"|"$dest "*) replacing_running=true ;;
      esac
    fi
  fi

  # Stage beside the destination, then rename: atomic, never writes into
  # the running file ("Text file busy"), and a unit restarting on failure
  # never finds the path missing.
  staged=$($SUDO mktemp "$BIN/.$NAME.install.XXXXXX") || fail "cannot write to $(tildify "$BIN")"
  $SUDO install -m 0755 "$tmp/$asset" "$staged" || fail "cannot write to $(tildify "$BIN")"
  $SUDO mv -f "$staged" "$dest" || fail "cannot install to $(tildify "$dest")"
  staged=""
  printf "${Green}$NAME was installed to ${Bold_Green}%s${Color_Off}\n" "$(tildify "$dest")"

  case ":$PATH:" in
    *":$BIN:"*) info "Run '$NAME version' to get started" ;;
    *)
      printf '\n'
      info "$(tildify "$BIN") is not on your PATH. Add it:"
      printf "  ${Bold_White}echo 'export PATH=\"%s:\$PATH\"' >> ~/.zshrc${Color_Off}${Dim}   # or ~/.bashrc${Color_Off}\n" "$BIN"
      ;;
  esac

  if $replacing_running; then
    printf '\n'
    info "The running daemon still executes the old binary. To switch (drops live sessions):"
    printf "  ${Bold_White}sudo systemctl restart %s${Color_Off}\n" "$NAME"
  else
    info "Setting up the service: https://github.com/$REPO/blob/main/docs/operate.md"
  fi
}

main "$@"
