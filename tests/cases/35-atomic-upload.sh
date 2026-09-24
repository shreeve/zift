#!/usr/bin/env bash
# Test: uploads are staged in <root>/.zift/staging and appear atomically
#       at CLOSE; the namespace is hidden, orphans are cleaned up, and a
#       target that appears mid-upload is not clobbered
# An operator watching the partner directory never sees a partial file.

source "$(dirname "$0")/../lib/common.sh"
need_paramiko

make_host_key
mkdir -p "$TEST_TMP/data/pending"
write_config <<EOF
$(config_head)

user partner
  auth $(user_key)
  root $TEST_TMP/data
  allow / read
  allow /pending read write
EOF
start_zift

"$PY" - <<'EOF'
import os, stat
from client import *
mode = lambda p: stat.S_IMODE(os.stat(host(p)).st_mode)
staged = lambda: os.listdir(host("data/.zift/staging"))
sftp = connect("partner")

# --- the target appears only at CLOSE, at publish-mode --------------
f = sftp.file("/pending/large.bin", "wb")
f.write(b"X" * 4096)
f.flush()
if os.path.exists(host("data/pending/large.bin")):
    fail("the target exists mid-upload")
ok("target absent from the operator's view during upload")
if (mode("data/.zift"), mode("data/.zift/staging")) != (0o750, 0o700) or len(staged()) != 1:
    fail(f"namespace {mode('data/.zift'):o}, staging {mode('data/.zift/staging'):o}, files {staged()}")
if mode("data/.zift/staging/" + staged()[0]) != 0o660:
    fail("the staging file is not at the default publish-mode 0660")
ok("namespace 0750, staging 0700, one staging file at 0660 mid-upload")
f.write(b"Y" * 4096)
f.close()
if os.path.getsize(host("data/pending/large.bin")) != 8192 or mode("data/pending/large.bin") != 0o660:
    fail("the published file is wrong")
ok("target appears at CLOSE with all 8192 bytes, mode 0660")

# --- the namespace is hidden and unreachable -----------------------
listing = sftp.listdir("/")
if ".zift" in listing or ".zift-staging" in listing:
    fail(f"namespace leaked into the listing: {listing}")
ok("/.zift and /.zift-staging are hidden from the listing")
for path in ("/.zift", "/.zift/staging", "/.zift/notes.md", "/.zift-staging"):
    expect(f"OPENDIR {path}", "denied", sftp.listdir, path)
    expect(f"STAT {path}", "denied", sftp.stat, path)
expect("OPEN under /.zift", "denied", sftp.file, "/.zift/anything", "rb")

# --- a dropped connection leaves no orphan -------------------------
other = connect("partner")
f2 = other.file("/pending/orphaned.bin", "wb")
f2.write(b"PARTIAL")
close(other)
if not wait_for(lambda: staged() == []):
    fail(f"orphaned staging files leaked: {staged()}")
if os.path.exists(host("data/pending/orphaned.bin")):
    fail("the orphaned upload was published")
ok("disconnect mid-upload removed the staging file and published nothing")

# --- a target that appears mid-upload is not clobbered at CLOSE -----
f4 = sftp.file("/pending/race-test.bin", "wb")
f4.write(b"FROM-PARTNER")
with open(host("data/pending/race-test.bin"), "wb") as racer:
    racer.write(b"FROM-RACER")
f4.close()  # paramiko swallows the CLOSE error; the bytes on disk tell
if read("data/pending/race-test.bin") != b"FROM-RACER":
    fail("the CLOSE-time clobber check let the partner overwrite the racer")
if not wait_for(lambda: staged() == []):
    fail("the refused upload left its staging file")
ok("a target that appeared during the upload survived CLOSE")
EOF
log_contains '"operation":"close","result":"denied","path":"/pending/race-test.bin"' \
    || fail "the refused publish was not audited as a denied close"
ok "the refused publish is audited"
