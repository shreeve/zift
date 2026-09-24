#!/usr/bin/env bash
# Test: an allowed symlink spelling cannot reach a denied path, and a
#       rename cannot carry denied or unreadable content anywhere
# Policy is judged on the real path: no alias into a denied tree or the
# .zift namespace, and RENAME checks every entry it would move.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
d="$TEST_TMP/data"
mkdir -p "$d/secret" "$d/tree/locked" "$d/safe/sub" "$d/rename-only" "$d/readable" "$d/.zift"
printf 'DENIED-DATA' > "$d/secret/data.txt"
printf 'LOCKED-DATA' > "$d/tree/locked/data.txt"
printf 'SAFE-DATA' > "$d/safe/sub/data.txt"
printf 'HIDDEN-DATA' > "$d/rename-only/hidden.txt"
printf 'PRIVATE-NOTES' > "$d/.zift/notes.txt"
chmod 0750 "$d/.zift"
ln -s secret "$d/alias"
ln -s .zift "$d/namespace-alias"
ln -s /etc "$d/safe/external-link"
write_config <<EOF
$(config_head)

user partner
  auth $(make_password_hash secret)
  root $d
  allow /alias read write list
  allow /namespace-alias read write list
  allow /tree full
  allow /moved full
  allow /safe full
  allow /safe-moved full
  allow /rename-only rename
  allow /readable full
  deny /secret
  deny /tree/locked
EOF
start_zift

"$PY" - <<'EOF'
import os
from client import *
sftp = connect("partner")
exists = lambda p: os.path.lexists(host("data/" + p))

for label, fn, *args in (
        ("read through an alias of a denied dir", sftp.open, "/alias/data.txt", "rb"),
        ("write through an alias of a denied dir", sftp.open, "/alias/data.txt", "wb"),
        ("list through an alias of a denied dir", sftp.listdir, "/alias"),
        ("read through an alias of .zift", sftp.open, "/namespace-alias/notes.txt", "rb"),
        ("write through an alias of .zift", sftp.open, "/namespace-alias/notes.txt", "wb"),
        ("list through an alias of .zift", sftp.listdir, "/namespace-alias")):
    if outcome(fn, *args) == "ok":
        fail(f"{label} succeeded")
    ok(f"{label} refused")
if read("data/secret/data.txt") != b"DENIED-DATA" or read("data/.zift/notes.txt") != b"PRIVATE-NOTES":
    fail("an aliased target was modified")

if outcome(sftp.rename, "/tree", "/moved") == "ok":
    fail("a directory rename carried a denied descendant")
if not exists("tree/locked/data.txt") or exists("moved"):
    fail("the refused directory rename moved something")
if outcome(sftp.open, "/tree/locked/data.txt", "rb") == "ok":
    fail("the denied descendant became readable")
ok("a directory rename carrying a denied descendant is refused")

if outcome(sftp.rename, "/rename-only/hidden.txt", "/readable/hidden.txt") == "ok":
    fail("rename alone moved an unreadable file into a readable dir")
if not exists("rename-only/hidden.txt") or exists("readable/hidden.txt"):
    fail("the refused file rename moved something")
ok("a file rename that would grant read access is refused")

sftp.rename("/safe", "/safe-moved")
with sftp.open("/safe-moved/sub/data.txt", "rb") as f:
    if f.read() != b"SAFE-DATA":
        fail("the renamed tree lost data")
if not os.path.islink(host("data/safe-moved/external-link")):
    fail("the child symlink was not moved as a link")
if outcome(sftp.listdir, "/safe-moved/external-link") == "ok":
    fail("the moved symlink is traversable")
ok("a fully authorized directory rename works and never follows a child symlink")
EOF
