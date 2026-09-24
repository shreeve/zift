#!/usr/bin/env bash
#
# install.sh — install zift from this extracted release archive:
#
#   bash install.sh               zift -> ~/.local/bin, or /usr/local/bin
#   bash install.sh --uninstall   remove it again
#
# As root, zift goes to /usr/local/bin. On a host that runs zift as a
# service it goes there too, the path the unit runs, using sudo for that
# one write and saying so first. BIN=... overrides both and never
# elevates. Before replacing the binary the service runs, it checks the
# service's config with the new version, as the service's user, and keeps
# the old binary if the config is rejected.
#
# This installs the binary only. zift.service here is the unit that
# docs/operate.md installs; the service user, host key and config are set
# up by hand, because an installer must never touch a config that carries
# partner credentials. Uninstall likewise removes only the binary.

set -euo pipefail
cd "$(dirname "$0")"

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
# only when a terminal can answer it, since under `curl | bash` stdin is
# the pipe.
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

explicit=${BIN:-}
if [ -z "$explicit" ]; then
  if [ "$(id -u)" = 0 ]; then BIN=/usr/local/bin
  elif host_runs_service && try_sudo; then BIN=/usr/local/bin
  else BIN="$HOME/.local/bin"; fi
fi

# Remove only the binary. Removing a host key would break every partner's
# known_hosts on the next connect.
uninstall() {
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

if [ "${1:-}" = --uninstall ]; then uninstall; exit 0; fi

[ -f "$NAME" ] && [ -x "$NAME" ] || fail "$NAME is missing from $(pwd)"
dest="$BIN/$NAME"
[ -n "$SUDO" ] && info "using sudo to install to $dest (this host runs $NAME as a service)"

# Plain first: a missing ~/.local reads as unwritable, and sudo must never
# create a user's own directories as root.
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
  warn "and sudo was not available, so the daemon will not pick it up. To install that one,"
  warn "re-run the same command with sudo BIN=/usr/local/bin in front of bash."
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

# Stage beside the destination, then rename: atomic, never writes into the
# running file ("Text file busy"), and a unit restarting on failure never
# finds the path missing. The staged copy goes on any failure or Ctrl-C,
# so the old binary is never left half-replaced.
staged=""
cleanup() { if [ -n "$staged" ]; then $SUDO rm -f "$staged" 2>/dev/null || true; fi; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
staged=$($SUDO mktemp "$BIN/.$NAME.install.XXXXXX") || fail "cannot write to $(tildify "$BIN")"
$SUDO install -m 0755 "$NAME" "$staged" || fail "cannot write to $(tildify "$BIN")"

# Replacing the binary a service runs: check the service's config with the
# new version, as the service's user, before it can land. A config the new
# version rejects keeps the old binary. The staged copy is what runs, since
# the service user cannot read this user's temp directory.
if host_runs_service; then
  exec_start=$(systemctl show "$NAME" -p ExecStart --value 2>/dev/null || true)
  case "$exec_start" in
    *"path=$dest ;"*)
      argv=$(printf '%s' "$exec_start" | sed -n 's/.*argv\[\]=\([^;]*\);.*/\1/p')
      conf=$(printf '%s' "$argv" | sed -n 's/.* serve \([^ ]*\).*/\1/p')
      user=$(systemctl show "$NAME" -p User --value 2>/dev/null || true)
      if [ -n "$conf" ]; then
        as_user=()
        if [ -n "$user" ] && [ "$user" != root ]; then
          if [ "$(id -u)" = 0 ]; then as_user=(runuser -u "$user" --); else as_user=(${SUDO:-sudo} -u "$user"); fi
        fi
        info "checking $conf with the new version${user:+ as $user}"
        ${as_user[@]+"${as_user[@]}"} "$staged" validate "$conf" \
          || fail "the new $NAME rejects $conf (above); nothing was installed"
      fi
      ;;
  esac
fi

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
  info "Setting up the service: https://github.com/shreeve/zift/blob/main/docs/operate.md"
fi
