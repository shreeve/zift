#!/usr/bin/env bash
# Regression coverage for policy aliases and conditional directory rename.

source "$(dirname "$0")/../lib/common.sh"

VENV="$(dirname "$0")/../.venv"
PY="$VENV/bin/python3"

if [[ ! -x "$PY" ]]; then
    echo "skip: paramiko venv missing at $VENV"
    exit 0
fi

make_host_key
hash=$(make_password_hash secret)

mkdir -p "$TEST_TMP/data/secret" \
         "$TEST_TMP/data/tree/locked" \
         "$TEST_TMP/data/safe/sub" \
         "$TEST_TMP/data/rename-only" \
         "$TEST_TMP/data/readable" \
         "$TEST_TMP/data/.zift"
printf 'DENIED-DATA' > "$TEST_TMP/data/secret/data.txt"
printf 'LOCKED-DATA' > "$TEST_TMP/data/tree/locked/data.txt"
printf 'SAFE-DATA' > "$TEST_TMP/data/safe/sub/data.txt"
printf 'HIDDEN-DATA' > "$TEST_TMP/data/rename-only/hidden.txt"
printf 'PRIVATE-NOTES' > "$TEST_TMP/data/.zift/notes.txt"
chmod 0750 "$TEST_TMP/data/.zift"
ln -s secret "$TEST_TMP/data/alias"
ln -s .zift "$TEST_TMP/data/namespace-alias"
ln -s /etc "$TEST_TMP/data/safe/external-link"

write_config <<EOF
server
  listen 127.0.0.1:$TEST_PORT
  host-key $TEST_TMP/host_ed25519
  log stderr

user partner
  auth $hash
  root $TEST_TMP/data
  allow /alias read write list
  allow /namespace-alias read write list
  allow /tree read write list mkdir delete rename update
  allow /moved read write list mkdir delete rename update
  allow /safe read write list mkdir delete rename update
  allow /safe-moved read write list mkdir delete rename update
  allow /rename-only rename
  allow /readable read write list mkdir delete rename update
  deny /secret
  deny /tree/locked
EOF

start_zift

"$PY" - <<EOF
import os
import socket
import paramiko

sock = socket.create_connection(("127.0.0.1", $TEST_PORT), timeout=15)
transport = paramiko.Transport(sock)
transport.connect(username="partner", password="secret")
sftp = paramiko.SFTPClient.from_transport(transport)

def denied(call, label):
    try:
        call()
    except IOError:
        print(f"ok: {label} denied")
        return
    raise AssertionError(f"{label} unexpectedly succeeded")

# An allowed spelling must not follow a directory symlink to a denied
# path or into Zift's reserved operator namespace.
denied(lambda: sftp.open("/alias/data.txt", "rb"), "inside-root policy alias read")
denied(lambda: sftp.open("/alias/data.txt", "wb"), "inside-root policy alias write")
denied(lambda: sftp.listdir("/alias"), "inside-root policy alias listing")
denied(lambda: sftp.open("/namespace-alias/notes.txt", "rb"), "reserved namespace alias read")
denied(lambda: sftp.open("/namespace-alias/notes.txt", "wb"), "reserved namespace alias write")
denied(lambda: sftp.listdir("/namespace-alias"), "reserved namespace alias listing")
assert open("$TEST_TMP/data/secret/data.txt", "rb").read() == b"DENIED-DATA"
assert open("$TEST_TMP/data/.zift/notes.txt", "rb").read() == b"PRIVATE-NOTES"

# The parent endpoints are allowed, but the source contains a denied
# descendant. Recursive rename authorization must reject the move and
# leave the tree under its original name.
denied(lambda: sftp.rename("/tree", "/moved"), "directory rename carrying denied descendant")
assert os.path.exists("$TEST_TMP/data/tree/locked/data.txt")
assert not os.path.exists("$TEST_TMP/data/moved")
denied(lambda: sftp.open("/tree/locked/data.txt", "rb"), "denied descendant after rejected rename")

# The same capability rule applies to a single file. Rename permission
# alone must not be usable to carry unreadable content into a readable
# destination.
denied(lambda: sftp.rename("/rename-only/hidden.txt", "/readable/hidden.txt"),
       "regular-file rename granting read access")
assert os.path.exists("$TEST_TMP/data/rename-only/hidden.txt")
assert not os.path.exists("$TEST_TMP/data/readable/hidden.txt")

# A directory whose complete existing subtree is authorized at both
# spellings remains renameable. A symlink entry inside it is examined
# but never traversed.
sftp.rename("/safe", "/safe-moved")
with sftp.open("/safe-moved/sub/data.txt", "rb") as f:
    assert f.read() == b"SAFE-DATA"
assert os.path.islink("$TEST_TMP/data/safe-moved/external-link")
denied(lambda: sftp.listdir("/safe-moved/external-link"), "renamed symlink traversal")
print("ok: fully-authorized directory rename succeeded without following child symlink")

sftp.close()
transport.close()
EOF

stop_zift TERM
wait "$ZIFT_PID" 2>/dev/null || true
