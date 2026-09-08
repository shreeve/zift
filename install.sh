#!/usr/bin/env bash
#
# install.sh — install the zift binary with one command (Linux and macOS):
#
#   curl -fsSL https://raw.githubusercontent.com/shreeve/zift/main/install.sh | bash
#
# Pin a version by passing a tag (with or without the leading v):
#
#   curl -fsSL .../install.sh | bash -s v0.10.2
#
# Downloads the release binary for this platform, verifies it against the
# release's signed SHA256SUMS, and installs it. As root it lands in
# /usr/local/bin, so the systemd unit's ExecStart path keeps working; as a
# user it lands in ~/.local/bin, which is enough for `zift hash-password`
# and `zift validate` on a laptop. Override either with BIN=...
#
# This installs the BINARY ONLY. Standing up the daemon — service user,
# host key, config, jail tree, hardened systemd unit — is deliberately out
# of scope: those steps must be idempotent and must never clobber a config
# that carries partner credentials, which is a job for the host-zift
# runbook or docs/operate.md, not for a script piped from the internet.
#
# Uninstall the same way — the binary goes; your config, host key, partner
# trees, and service unit stay:
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

# The destination: system-wide for root, user-owned for everyone else.
# A systemd unit invokes zift by absolute path, so a root install has to
# land where that path points.
destdir() {
  if [ "$(id -u)" = 0 ]; then printf '%s' "${BIN:-/usr/local/bin}"
  else printf '%s' "${BIN:-$HOME/.local/bin}"; fi
}

# Remove only what install put down — the binary. The config, host key,
# partner trees, audit log, and systemd unit belong to the operator, and
# an uninstaller that reaches for those is malware with a manual. Removing
# a host key would break every partner's known_hosts on the next connect.
# No network: the filesystem answers what's installed.
uninstall() {
  BIN=$(destdir)
  [ -e "$BIN/$NAME" ] || fail "$NAME is not installed at $(tildify "$BIN/$NAME") (BIN= if it lives elsewhere; sudo for a system install)"
  rm -f "$BIN/$NAME" || fail "cannot remove $(tildify "$BIN/$NAME") — re-run under sudo if it was installed system-wide"
  printf "${Green}$NAME was removed from ${Bold_Green}%s${Color_Off}\n" "$(tildify "$BIN")"
  info "your config, host key, partner trees, and service unit are untouched"
  info "to retire the service too: systemctl disable --now zift"
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
    MINGW*|MSYS*|CYGWIN*)      fail "Windows is not supported — zift is a Unix daemon" ;;
    *)                         fail "unsupported platform: $os $arch" ;;
  esac

  # --- version: argument, or the tag `releases/latest` redirects to --------
  tag=${1:-}
  if [ -n "$tag" ]; then
    case "$tag" in v*) ;; *) tag="v$tag" ;; esac
  else
    tag=$(curl -fsSLI --retry 3 --retry-delay 1 -o /dev/null -w '%{url_effective}' \
      "https://github.com/$REPO/releases/latest") || fail "cannot reach github.com"
    tag=${tag##*/}
  fi
  # With no releases, GitHub redirects .../latest to .../releases — so the
  # resolved "tag" is only real if it looks like one.
  case "$tag" in v*) ;; *) fail "no releases found for $REPO" ;; esac

  # Release assets carry the bare version; the tag carries the leading v.
  version=${tag#v}
  asset="$NAME-$version-$plat"
  base="https://github.com/$REPO/releases/download/$tag"

  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT

  info "$NAME $tag ($plat)"
  curl -fSL --retry 3 --retry-delay 1 --progress-bar -o "$tmp/$asset" "$base/$asset" \
    || fail "download failed: $base/$asset"

  # --- verify against the release's signed checksum manifest ---------------
  # Two independent bindings: cosign ties SHA256SUMS to the workflow that
  # built it, and the hash ties these bytes to that manifest. The hash
  # check is mandatory. The signature check needs cosign, which is not on
  # a stock host, so it runs when available and says so when it does not.
  curl -fsSL --retry 3 --retry-delay 1 -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" \
    || fail "download failed: SHA256SUMS"

  if command -v cosign >/dev/null; then
    curl -fsSL --retry 3 --retry-delay 1 -o "$tmp/SHA256SUMS.bundle" "$base/SHA256SUMS.bundle" \
      || fail "download failed: SHA256SUMS.bundle"
    cosign verify-blob \
      --bundle "$tmp/SHA256SUMS.bundle" \
      --certificate-identity-regexp "https://github.com/$REPO/.+" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      "$tmp/SHA256SUMS" >/dev/null 2>&1 \
      || fail "cosign could not verify SHA256SUMS against $REPO — do not install this binary"
    info "signature verified (cosign keyless, $REPO workflow)"
  else
    warn "cosign not found — SHA256SUMS will not be checked for a valid signature"
    warn "the binary is still verified against it; for a production install see"
    warn "the provenance steps in docs/operate.md"
  fi

  if command -v sha256sum >/dev/null; then
    sum=$(sha256sum "$tmp/$asset" | cut -d' ' -f1)
  else
    sum=$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1)
  fi
  want=$(awk -v f="$asset" '$2 == f { print $1 }' "$tmp/SHA256SUMS")
  [ -n "$want" ]        || fail "no checksum published for $asset"
  [ "$sum" = "$want" ]  || fail "checksum mismatch for $asset"

  # --- install -------------------------------------------------------------
  BIN=$(destdir)
  dest="$BIN/$NAME"

  # Create the destination as ourselves when we can, so a missing ~/.local
  # is not mistaken for an unwritable one.
  [ -d "$BIN" ] || install -d -m 0755 "$BIN" 2>/dev/null || true
  [ -d "$BIN" ] || fail "cannot create $(tildify "$BIN") — set BIN= to a writable directory"
  [ -w "$BIN" ] || fail "$(tildify "$BIN") is not writable — re-run under sudo, or set BIN="

  # A user install on a host that runs zift as a service is almost always a
  # missing `sudo`: the binary lands somewhere the unit never looks, the
  # daemon keeps running whatever it already had, and the install appears
  # to have done nothing. Legitimate on a server for `hash-password` and
  # `validate`, so this warns rather than refuses — but it warns loudly,
  # because the quiet version of this message is easy to scroll past.
  if [ "$(id -u)" != 0 ] && command -v systemctl >/dev/null \
     && systemctl list-unit-files "$NAME.service" >/dev/null 2>&1; then
    unit_exec=$(systemctl show "$NAME" -p ExecStart --value 2>/dev/null | sed -n 's/.*path=\([^ ;]*\).*/\1/p')
    printf '\n'
    warn "This host runs $NAME as a service, but this is a USER install."
    warn "It is going to $(tildify "$dest")${unit_exec:+, while the service runs $unit_exec}."
    warn "The daemon will NOT pick this up. To install the one it runs:"
    warn ""
    warn "  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sudo bash"
    warn ""
    warn "Continuing — a user install is still fine for hash-password and validate."
    printf '\n'
  fi

  # Is a running daemon executing the very file we are about to replace?
  #
  # `install` unlinks the destination and creates a new inode, so this
  # write succeeds while the daemon runs. `cp` does NOT: it opens the
  # existing inode for writing, which the kernel refuses for a file being
  # executed — `cp: cannot create regular file: Text file busy`. That is
  # the whole reason this uses `install` and why no shutdown is needed.
  #
  # The cost of the new inode is that the running process keeps executing
  # the old, now-unlinked one (its /proc/<pid>/exe reads "... (deleted)")
  # until it restarts. Match on the actual running executable rather than
  # on "a unit named zift is active", so a user-level install never claims
  # to have replaced a system daemon's binary.
  replacing_running=false
  if command -v systemctl >/dev/null && systemctl is-active --quiet "$NAME" 2>/dev/null; then
    pid=$(systemctl show "$NAME" -p MainPID --value 2>/dev/null || true)
    if [ -n "${pid:-}" ] && [ "$pid" != 0 ]; then
      case "$(readlink "/proc/$pid/exe" 2>/dev/null || true)" in
        "$dest"|"$dest "*) replacing_running=true ;;
      esac
    fi
  fi

  install -m 0755 "$tmp/$asset" "$dest" || fail "cannot install to $(tildify "$dest")"
  printf "${Green}$NAME was installed to ${Bold_Green}%s${Color_Off}\n" "$(tildify "$dest")"

  # PATH hint: an install nobody can invoke is not an install.
  case ":$PATH:" in
    *":$BIN:"*) ;;
    *) info "note: $(tildify "$BIN") is not on your PATH" ;;
  esac

  printf '\n'
  if $replacing_running; then
    info "The daemon was running and is STILL EXECUTING THE OLD BINARY — the new"
    info "file is a new inode, so nothing picked it up yet. To cut over:"
    printf "\n  ${Bold_White}sudo systemctl restart %s${Color_Off}\n\n" "$NAME"
    info "  restart  loads the new binary, and drops live SFTP sessions"
    info "  reload   re-reads the config only, and keeps sessions"
    info "Confirm with: systemctl show $NAME -p MainPID --value, then"
    info "readlink /proc/<pid>/exe — a trailing \"(deleted)\" means still-old."
  else
    info "This installed the binary only. To stand up the daemon:"
    printf "\n  ${Bold_White}%s version${Color_Off}                 confirm the install\n" "$NAME"
    printf "  ${Bold_White}%s hash-password${Color_Off}           mint a partner credential\n" "$NAME"
    printf "  ${Bold_White}%s validate <conf>${Color_Off}         check a config before serving\n\n" "$NAME"
    info "The service user, host key, config, jail tree, and systemd unit are"
    info "docs/operate.md — deliberately not automated here, because those steps"
    info "must never clobber a config that carries partner credentials."
  fi
}

main "$@"
