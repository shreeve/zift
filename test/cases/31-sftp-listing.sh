#!/usr/bin/env bash
# Test: SFTP `ls -la` rendering in the v0.3.0+ DEFAULT virtual mode —
# partner sees their own virtual-user name, a fixed group of "sftp",
# policy-derived rwx bits, and `---` in the world triplet. The on-disk
# owner/group/mode never leak into the partner's view.
#
# Covers:  PLAN §7.6 READDIR/STAT attrs encoding, src/listing.zig
#          longname formatter, src/policy.zig policyDerivedMode,
#          src/session.zig handleReaddir virtual-mode dispatch.
# Oracle:  paramiko's SFTPAttributes.longname matches the
#          virtual-mode promise (alice/sftp/policy-rwx/world=---).

source "$(dirname "$0")/../lib/common.sh"

VENV="$(dirname "$0")/../.venv"
PY="$VENV/bin/python3"

if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing at $VENV"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)

mkdir -p "$TEST_TMP/data/pending" "$TEST_TMP/data/archive"
echo "hello world" > "$TEST_TMP/data/notes.txt"
dd if=/dev/zero of="$TEST_TMP/data/large.bin" bs=1024 count=42 2>/dev/null

# Use the new `add` verb on /pending (full r/w/list/add/remove).
# /archive stays read-only. Top-level files are visible via `allow /
# read list`.
write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user runner
  auth $hash
  root $TEST_TMP/data
  allow / read list
  allow /pending read list add remove
  allow /archive read list
EOF

start_zift

"$PY" - <<EOF
import paramiko, socket, stat, sys

sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
t = paramiko.Transport(sock)
t.connect(username="runner", password="secret")
sftp = paramiko.SFTPClient.from_transport(t)

attrs_by_name = {a.filename: a for a in sftp.listdir_attr("/")}
print(f"entries seen: {sorted(attrs_by_name)}")

# --- 1. attrs basics ----------------------------------------------------
expected = {"notes.txt", "large.bin", "pending", "archive"}
assert expected <= set(attrs_by_name), f"missing: {expected - set(attrs_by_name)}"
print("ok: all expected entries listed")

notes = attrs_by_name["notes.txt"]
assert notes.st_size == 12, f"notes.txt size wrong: {notes.st_size}"
assert notes.st_mtime and notes.st_mtime > 0, "mtime missing"
print(f"ok: notes.txt size+mtime populated")

# --- 2. virtual-mode: uid/gid are zeroed in the wire attrs --------------
# Server emits uid=0, gid=0 in virtual mode. The CLIENT may render
# them differently depending on its passwd db, but the fields ARE
# zero on the wire — confirming we never leaked the on-disk uid.
assert notes.st_uid == 0, f"virtual-mode wire uid should be 0, got {notes.st_uid}"
assert notes.st_gid == 0, f"virtual-mode wire gid should be 0, got {notes.st_gid}"
print("ok: wire uid/gid zeroed (virtual mode)")

# --- 3. longname owner column is the VIRTUAL user name, not the OS user
notes_long = notes.longname
assert notes_long, "notes.txt longname missing"
fields = notes_long.split()
# Layout: mode(10) nlink owner group size mon day time-or-year name
owner = fields[2]
group = fields[3]
assert owner == "runner", f"longname owner should be 'runner' (the virtual user), got {owner!r}"
assert group == "sftp", f"longname group should be the fixed 'sftp', got {group!r}"
print(f"ok: longname owner='runner' group='sftp'")
# Note: a "real owner not in longname" check used to live here, but
# it's redundant with the direct invariants above AND brittle when the
# OS user happens to share the virtual user's name. Direct assertions
# are sufficient.

# --- 4. world triplet is always `---` -----------------------------------
# Every entry, regardless of on-disk perms or what the partner can
# actually do — there's no "third class" of viewer in the jail.
for name, a in attrs_by_name.items():
    long = a.longname
    if not long:
        continue
    mode_str = long.split()[0]
    # mode_str layout: <type><owner3><group3><other3>
    # other3 is mode_str[7:10]
    other_bits = mode_str[7:10]
    assert other_bits == "---", \
        f"{name}: world bits should be '---', got {other_bits!r} (full: {mode_str!r})"
print("ok: every entry shows world bits as '---'")

# --- 5. policy-derived owner bits ---------------------------------------
# /pending has add+remove → directory mode bits should be rwx for owner.
# /archive has only read+list → r-x.
pending = attrs_by_name["pending"]
pending_owner = pending.longname.split()[0][1:4]
assert pending_owner == "rwx", f"/pending should show rwx (read+list+add+remove), got {pending_owner!r}"
print(f"ok: /pending owner bits = rwx (allow read list add remove)")

archive = attrs_by_name["archive"]
archive_owner = archive.longname.split()[0][1:4]
assert archive_owner == "r-x", f"/archive should show r-x (read+list, no mutation), got {archive_owner!r}"
print(f"ok: /archive owner bits = r-x (allow read list, no add/remove)")

# Top-level file: alice has `allow / read list` only. So a file at /
# should show r-- (read but no write/remove).
notes_owner = notes.longname.split()[0][1:4]
assert notes_owner == "r--", f"/notes.txt should show r-- (read only at root), got {notes_owner!r}"
print(f"ok: /notes.txt owner bits = r-- (read only at root)")

# --- 6. group bits mirror owner bits ------------------------------------
for name, a in attrs_by_name.items():
    long = a.longname
    if not long:
        continue
    mode_str = long.split()[0]
    owner_bits = mode_str[1:4]
    group_bits = mode_str[4:7]
    assert owner_bits == group_bits, \
        f"{name}: group bits {group_bits!r} should mirror owner bits {owner_bits!r} (full: {mode_str!r})"
print("ok: group bits mirror owner bits everywhere")

# --- 7. file-type bit preserved -----------------------------------------
assert pending.longname.startswith("d"), f"pending should start with 'd': {pending.longname!r}"
assert notes.longname.startswith("-"), f"notes.txt should start with '-': {notes.longname!r}"
print("ok: file-type bits preserved (d for dirs, - for files)")

# --- 8. dir size is `-`, file size is human-readable --------------------
assert pending.longname.split()[4] == "-", \
    f"directory size column should be '-', got: {pending.longname!r}"
large = attrs_by_name["large.bin"]
assert "42K" in large.longname, f"large.bin should show '42K': {large.longname!r}"
print("ok: dir size = '-', file size uses K/M suffix")

sftp.close()
t.close()
EOF

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
