#!/usr/bin/env python3
"""Point Formula/zift.rb at a new release.

    scripts/bump-homebrew-formula.py FORMULA VERSION CHECKSUMS

FORMULA is shreeve/homebrew-tap's Formula/zift.rb, VERSION is X.Y.Z, and
CHECKSUMS is the release's zift-vX.Y.Z-checksums.txt. Each archive URL
moves to VERSION and the sha256 on the line after it takes that
archive's checksum. Fails unless all four platforms are updated.
"""

import re
import sys

formula_path, version, checksums_path = sys.argv[1:]
if not re.fullmatch(r"\d+\.\d+\.\d+", version):
    sys.exit(f"not a release version: {version}")

sums = {}
for line in open(checksums_path):
    digest, name = line.split()
    sums[name.lstrip("*")] = digest

lines = open(formula_path).read().splitlines(keepends=True)
updated = set()
for i, line in enumerate(lines):
    m = re.search(r"/v[^/]+/zift-v[^-]+-([a-z0-9-]+)\.tar\.gz", line)
    if not m:
        continue
    plat = m.group(1)
    asset = f"zift-v{version}-{plat}.tar.gz"
    if asset not in sums:
        sys.exit(f"{checksums_path} has no {asset}")
    lines[i] = line[: m.start()] + f"/v{version}/{asset}" + line[m.end():]
    if "sha256" not in lines[i + 1]:
        sys.exit(f"line {i + 2}: expected the sha256 after the {plat} url")
    lines[i + 1] = re.sub(r'"[0-9a-f]{64}"', f'"{sums[asset]}"', lines[i + 1])
    updated.add(plat)

expected = {"osx-arm64", "osx-amd64", "linux-arm64", "linux-amd64"}
if updated != expected:
    sys.exit(f"updated {sorted(updated)}, expected {sorted(expected)}")
open(formula_path, "w").write("".join(lines))
