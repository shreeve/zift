#!/usr/bin/env bash
# Test: SFTP `ls -la`-style listing renders real attrs + a formatted
# longname. Locks in the partner-facing user experience: the OpenSSH
# sftp client's `?`-laden fallback for missing fields is replaced
# with real mode bits, real nlink, real uid/gid (resolved to names),
# real size (`-` for dirs, human-readable suffix for files), and a
# `Mon DD HH:MM` mtime.
#
# Covers:  PLAN §7.6 READDIR + STAT attrs encoding, listing.zig
#          longname formatter.
# Oracle:  paramiko's SFTPAttributes.longname matches our format
#          (mode 10ch + nlink + owner + group + size + mtime + name).

source "$(dirname "$0")/../lib/common.sh"

VENV="$(dirname "$0")/../.venv"
PY="$VENV/bin/python3"

if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing at $VENV"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)

mkdir -p "$TEST_TMP/data/pending"
echo "hello world" > "$TEST_TMP/data/notes.txt"
dd if=/dev/zero of="$TEST_TMP/data/large.bin" bs=1024 count=42 2>/dev/null

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user runner
  password $hash
  root $TEST_TMP/data
  allow / read list
  allow /pending read write list
EOF

start_zift

"$PY" - <<EOF
import paramiko, socket, sys, re

sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="runner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)

# --- 1. listdir_attr exposes both attrs and longname --------------------
attrs_by_name = {a.filename: a for a in sftp.listdir_attr("/")}
expected = {"notes.txt", "large.bin", "pending"}
got = set(attrs_by_name.keys())
assert expected <= got, f"missing entries: expected {expected}, got {got}"
print("ok: listdir_attr returned all expected entries")

# --- 2. attrs are populated (not the v0.1 hardcoded zeros) ---------------
notes = attrs_by_name["notes.txt"]
assert notes.st_mode is not None and notes.st_mode != 0, \
    f"notes.txt mode missing: {notes.st_mode!r}"
assert notes.st_uid is not None, f"notes.txt uid missing"
assert notes.st_gid is not None, f"notes.txt gid missing"
assert notes.st_size == 12, f"notes.txt size wrong: {notes.st_size}"  # "hello world\n"
assert notes.st_mtime is not None and notes.st_mtime > 0, \
    f"notes.txt mtime missing: {notes.st_mtime!r}"
print(f"ok: notes.txt attrs populated (mode=0o{notes.st_mode & 0o7777:o}, "
      f"size={notes.st_size}, uid={notes.st_uid}, gid={notes.st_gid})")

pending = attrs_by_name["pending"]
import stat
assert stat.S_ISDIR(pending.st_mode), \
    f"pending should be a dir, mode=0o{pending.st_mode:o}"
print(f"ok: pending dir mode bits encode S_IFDIR")

# --- 3. longname is the GNU ls -la style line we constructed -----------
# Format we promise:
#   mode(10ch) nlink owner group size month day time-or-year name
# A regex anchors only the parts we control: the mode prefix (d for
# dir, - for regular file), the file/dir name at the end, and the
# absence of a literal "?" (the openssh fallback indicator that v0.1
# left in the gap when we sent no longname).
notes_long = notes.longname
assert notes_long is not None, "notes.txt has no longname"
assert "?" not in notes_long, \
    f"notes.txt longname contains '?' (server should provide all fields): {notes_long!r}"
assert notes_long.startswith("-rw"), \
    f"notes.txt longname should start with file-type '-rw...', got: {notes_long!r}"
assert "notes.txt" in notes_long, \
    f"notes.txt longname should end with filename, got: {notes_long!r}"
print(f"ok: notes.txt longname: {notes_long!r}")

pending_long = pending.longname
assert "?" not in pending_long, \
    f"pending longname contains '?': {pending_long!r}"
assert pending_long.startswith("d"), \
    f"pending longname should start with 'd' for directory, got: {pending_long!r}"
# Directory size should render as "-", not the inode size (4096 etc.)
# — explicit user request, see formatSize() in src/listing.zig.
fields = pending_long.split()
# fields layout: [mode, nlink, owner, group, size, month, day, time, name]
assert fields[4] == "-", \
    f"pending size column should be '-', got: {fields[4]!r} (full: {pending_long!r})"
print(f"ok: pending longname: {pending_long!r} (size column = '-')")

# --- 4. Large file size renders with K/M suffix --------------------------
large = attrs_by_name["large.bin"]
large_long = large.longname
# 42 KiB → "42K" with our threshold rule
assert "42K" in large_long, \
    f"large.bin longname should contain '42K', got: {large_long!r}"
print(f"ok: large.bin longname uses K suffix: {large_long!r}")

# --- 5. Owner/group fields are NAMES (not numeric) for known accounts ---
# Whoever ran zift owns the test dir. getpwuid_r should resolve their
# uid to a name on any sane system. Numeric fallback is only OK if libc
# cannot find the entry; we check the field is non-empty and matches
# the running user's name.
import os, pwd
my_uid = os.geteuid()
my_name = pwd.getpwuid(my_uid).pw_name
fields = notes_long.split()
owner_field = fields[2]
assert owner_field == my_name, \
    f"owner column should be {my_name!r} (resolved), got {owner_field!r}"
print(f"ok: owner column resolved to name: {owner_field!r}")

sftp.close()
t.close()
EOF

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
