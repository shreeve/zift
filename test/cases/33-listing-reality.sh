#!/usr/bin/env bash
# Test: `listing-mode reality` is the v0.2.x-compatible escape hatch.
# Operators who genuinely want partners to see the on-disk owner /
# group / mode (rare; mostly debugging) can opt back in by adding
# `listing-mode reality` to the server block.
#
# Covers:  src/config.zig listing-mode parser, src/session.zig
#          applyListingMode `.reality => return real` branch,
#          src/listing.zig NameResolver still honored when reality
#          mode dispatches through it.
# Oracle:  paramiko reports the real OS uid/gid (non-zero) and the
#          longname's owner column matches the OS user that ran zift
#          — proof that we did NOT remap to the virtual user.

source "$(dirname "$0")/../lib/common.sh"

VENV="$(dirname "$0")/../.venv"
PY="$VENV/bin/python3"

if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing at $VENV"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)

mkdir -p "$TEST_TMP/data"
echo "hello" > "$TEST_TMP/data/notes.txt"
# Pin the file's on-disk mode so the test's "reality should expose
# the real owner-w bit" assertion isn't hostage to whatever umask the
# test runner happens to have set.
chmod 0644 "$TEST_TMP/data/notes.txt"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr
  listing-mode reality

user runner
  password $hash
  root $TEST_TMP/data
  allow / read list
EOF

start_zift

"$PY" - <<EOF
import paramiko, socket, os, pwd

sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="runner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)

# Files are owned on disk by whoever ran zift (the real OS user).
real_uid = os.geteuid()
real_owner = pwd.getpwuid(real_uid).pw_name

attrs = sftp.lstat("/notes.txt")

# --- 1. wire uid/gid are the REAL inode values (not the virtual-mode 0)
assert attrs.st_uid == real_uid, \
    f"reality mode should expose real uid {real_uid}, got {attrs.st_uid}"
print(f"ok: wire uid={attrs.st_uid} (real OS uid)")
# Note: st_gid may match real_uid's primary group OR something else
# depending on setgid bits on the parent dir; we only assert it's
# non-zero (proof that we didn't zero it out the way virtual mode does).
assert attrs.st_gid != 0 or real_uid == 0, \
    f"reality-mode wire gid should be real, got {attrs.st_gid} (real_uid={real_uid})"
print(f"ok: wire gid={attrs.st_gid} (real OS gid, not zeroed)")

# --- 2. longname carries the REAL OS user's name -----------------------
# In reality mode, the resolver (getpwuid_r) maps the on-disk uid to
# its system name. The virtual user's name should NOT appear in the
# owner column unless it happens to match the OS user's name.
listing = sftp.listdir_attr("/")
notes = next(a for a in listing if a.filename == "notes.txt")
fields = notes.longname.split()
owner_col = fields[2]

if real_owner != "runner":
    # The clean case: virtual user "runner" differs from OS user.
    assert owner_col == real_owner, \
        f"reality longname owner should be {real_owner!r} (the OS user), got {owner_col!r}"
    assert owner_col != "runner", \
        f"reality longname must NOT show the virtual user name 'runner', got {owner_col!r}"
    print(f"ok: longname owner = {owner_col!r} (real OS user, virtual mapping correctly bypassed)")
else:
    # Less informative case (CI runs zift as a user named "runner").
    # We can still verify the wire uid is real (we did, above).
    assert owner_col == "runner"
    print(f"(real OS user is 'runner' — virtual/reality both render same string here; wire uid={attrs.st_uid} confirms reality mode)")

# --- 3. mode bits are the REAL inode mode (not policy-derived) ----------
# notes.txt is a regular file owned by the OS user with whatever umask
# created it (typically 0o644). In virtual mode this would render as
# r-- (alice has only read+list at /, no write). In reality mode
# the inode's actual permissions show through, including the w bit
# for the OWNER class — because alice IS the inode's owner here, since
# that's how the test data was written.
import stat
mode_bits = attrs.st_mode & 0o777
print(f"ok: notes.txt real mode = 0o{mode_bits:o} (passed through from inode)")
# In virtual mode this owner triplet would be "r--" (alice has no
# write at /). In reality mode the inode's actual owner-rwx is
# reflected. Default umask 0o022 → 0o644 → owner "rw-".
mode_str = notes.longname.split()[0]
owner_bits = mode_str[1:4]
# The test asserts the owner triplet is NOT the virtual-mode "r--",
# unless the on-disk mode happens to match (rare, would require a
# 0o400 umask or similar). For the default umask-derived 0o644,
# owner_bits should be "rw-".
assert "w" in owner_bits, \
    f"reality-mode owner bits should include 'w' (real inode is writable), got {owner_bits!r} from {mode_str!r}"
print(f"ok: reality-mode owner bits = {owner_bits!r} (from real inode, NOT policy-derived)")

sftp.close()
t.close()
EOF

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
