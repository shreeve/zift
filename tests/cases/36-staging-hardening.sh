#!/usr/bin/env bash
# Test: a planted or loose <root>/.zift or .zift/staging is refused, and
#       every SFTP operation on /.zift/* and /.zift-staging/* is denied
# A symlink there could redirect staging outside the jail; loose modes
# let local users watch or swap uploads mid-rename. The partner holds
# `full`, so every refusal is the namespace's, never the policy's.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
mkdir -p "$TEST_TMP/data/pending" "$TEST_TMP/elsewhere"
write_config <<EOF
$(config_head)

user partner
  auth $(make_password_hash secret)
  root $TEST_TMP/data
  allow / full
EOF
start_zift

# `upload_refused <label>`: a new session's upload must fail and leave
# nothing outside the jail. The staging dir is checked per session.
upload_refused() {
    "$PY" - "$1" <<'EOF'
import os, sys
from client import *
def upload():
    with connect("partner").file("/pending/should-fail.bin", "wb") as f:
        f.write(b"this should never be staged")
expect(f"upload with {sys.argv[1]}", "failure", upload)
if os.listdir(host("elsewhere")):
    fail("bytes leaked outside the jail")
EOF
}
ns="$TEST_TMP/data/.zift"

ln -s "$TEST_TMP/elsewhere" "$ns"
upload_refused ".zift as a symlink"
rm -f "$ns"

mkdir -m 0750 "$ns"
ln -s "$TEST_TMP/elsewhere" "$ns/staging"
upload_refused ".zift/staging as a symlink"
rm -rf "$ns"

mkdir -m 0770 "$ns"
upload_refused ".zift at 0770 (group-writable)"
rm -rf "$ns"

mkdir -m 0750 "$ns"
mkdir -m 0755 "$ns/staging"
upload_refused ".zift/staging at 0755"
rm -rf "$ns"
ok "planted symlinks and loose modes are refused, nothing leaks"

# A clean upload creates the namespace; then plant real files in it so
# REMOVE and RENAME cannot pass by NotFound.
"$PY" - <<'EOF'
from client import *
with connect("partner").file("/pending/seed.bin", "wb") as f:
    f.write(b"seed")
EOF
echo "operator-only" > "$ns/notes.md"
echo "harness-planted" > "$ns/staging/known-victim.txt"

"$PY" - <<'EOF'
import os
from client import *
sftp = connect("partner")
cases = [
    ("OPENDIR /.zift", sftp.listdir, "/.zift"),
    ("STAT /.zift", sftp.stat, "/.zift"),
    ("MKDIR /.zift", sftp.mkdir, "/.zift"),
    ("RMDIR /.zift", sftp.rmdir, "/.zift"),
    ("OPENDIR /.zift/staging", sftp.listdir, "/.zift/staging"),
    ("OPEN /.zift/notes.md", sftp.file, "/.zift/notes.md", "rb"),
    ("REMOVE /.zift/notes.md", sftp.remove, "/.zift/notes.md"),
    ("RENAME from /.zift/notes.md", sftp.rename, "/.zift/notes.md", "/pending/stolen.md"),
    ("OPEN-write /.zift/x", sftp.file, "/.zift/x", "wb"),
    ("MKDIR /.zift/sub", sftp.mkdir, "/.zift/sub"),
    ("RENAME to /.zift/x", sftp.rename, "/pending/seed.bin", "/.zift/x"),
    ("REMOVE /.zift/staging/known-victim.txt", sftp.remove, "/.zift/staging/known-victim.txt"),
    ("RENAME from /.zift/staging/known-victim.txt", sftp.rename,
     "/.zift/staging/known-victim.txt", "/pending/stolen.txt"),
    ("OPENDIR /.zift-staging", sftp.listdir, "/.zift-staging"),
    ("STAT /.zift-staging", sftp.stat, "/.zift-staging"),
    ("MKDIR /.zift-staging", sftp.mkdir, "/.zift-staging"),
    ("OPEN-write /.zift-staging/x", sftp.file, "/.zift-staging/x", "wb"),
    ("RENAME to /.zift-staging/x", sftp.rename, "/pending/seed.bin", "/.zift-staging/x"),
    ("OPENDIR /pending/../.zift", sftp.listdir, "/pending/../.zift"),
    ("OPENDIR /pending/../.zift-staging", sftp.listdir, "/pending/../.zift-staging"),
]
for label, fn, *args in cases:
    expect(label, "denied", fn, *args)
for path in ("data/.zift/notes.md", "data/.zift/staging/known-victim.txt", "data/pending/seed.bin"):
    if not os.path.exists(host(path)):
        fail(f"{path} was moved or removed despite the denials")
ok(f"all {len(cases)} reserved-path operations denied; the planted files survived")
EOF
