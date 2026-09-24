#!/usr/bin/env bash
# package-release.sh — assemble one platform's release archive.
#
#   TAG=v1.2.3 PLAT=linux-amd64 scripts/package-release.sh
#
# Packs the binary that `zig build release -Dversion=1.2.3` wrote to
# release/ with its installer, the systemd unit, README and licenses, as
# OUT/zift-TAG-PLAT.tar.gz (OUT defaults to dist). The layout and names
# are the ones install.sh expects, shared with janus and harbor.

set -euo pipefail
cd "$(dirname "$0")/.."

TAG=${TAG:?package-release: set TAG (for example, v1.2.3)}
PLAT=${PLAT:?package-release: set PLAT}
OUT=${OUT:-dist}

[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || {
  echo "package-release: TAG must look like v1.2.3" >&2
  exit 2
}
case "$PLAT" in
  linux-amd64) target=x86_64-linux ;;
  linux-arm64) target=aarch64-linux ;;
  osx-arm64)   target=aarch64-macos ;;
  osx-amd64)   target=x86_64-macos ;;
  *) echo "package-release: unsupported PLAT $PLAT" >&2; exit 2 ;;
esac

binary="release/zift-${TAG#v}-$target"
[[ -f "$binary" ]] || { echo "package-release: $binary not found (zig build release first)" >&2; exit 2; }

name="zift-$TAG-$PLAT"
root="$OUT/$name"
rm -rf "$root"
mkdir -p "$root"
install -m 0755 "$binary" "$root/zift"
install -m 0755 scripts/release-install.sh "$root/install.sh"
install -m 0644 packaging/systemd/zift.service README.md LICENSE THIRD_PARTY_LICENSES.md "$root/"
tar -C "$OUT" -czf "$OUT/$name.tar.gz" "$name"
rm -rf "$root"
printf '  -> %s (%s)\n' "$OUT/$name.tar.gz" "$(du -h "$OUT/$name.tar.gz" | cut -f1)"
