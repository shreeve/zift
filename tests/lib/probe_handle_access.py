#!/usr/bin/env python3
"""
SFTP probe for the per-handle access-mode test (TODOS.md P0).

Exercises the spec invariant from PLAN.md §6.3:

    `read` controls SSH_FXP_READ
    `write` controls SSH_FXP_WRITE

A user with `write` permission but NOT `read` opens a file with the
WRITE flag (allowed by `.open_write` policy), then issues a raw
SSH_FXP_READ against the same handle. Spec says READ must be denied.

Exit codes:
    0  fix is in place: server replied SSH_FX_PERMISSION_DENIED on READ
    2  bug present: server returned data on a READ from a write-only
       authorized handle (the bypass)
    3  unexpected error (test environment failure)

stdout is a single line beginning with `result:` for the test runner.

Usage:
    probe_handle_access.py --host HOST --port PORT --user USER --pass PASS --path /abs/virt/path
"""

import argparse
import errno
import socket
import sys

import paramiko
import paramiko.sftp as sftp_proto
from paramiko.message import Message
from paramiko.sftp_attr import SFTPAttributes


SSH_FXF_READ = 0x01
SSH_FXF_WRITE = 0x02
SSH_FX_OK = 0
SSH_FX_PERMISSION_DENIED = 3




def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", required=True, type=int)
    ap.add_argument("--user", required=True)
    ap.add_argument("--pass", dest="password", required=True)
    ap.add_argument("--path", required=True, help="absolute virtual path inside the user's jail")
    args = ap.parse_args()

    sock = socket.create_connection((args.host, args.port), timeout=15)
    transport = paramiko.Transport(sock)
    try:
        transport.connect(username=args.user, password=args.password)
    except Exception as exc:
        print(f"result:setup-error auth-failed:{exc}")
        return 3

    chan = transport.open_session()
    chan.invoke_subsystem("sftp")
    sftp = paramiko.SFTPClient(chan)

    # OPEN the path with WRITE flag only (no READ, no TRUNC, no CREAT).
    # `.open_write` policy must allow this for the user under test.
    attrs = SFTPAttributes()
    try:
        t, msg = sftp._request(sftp_proto.CMD_OPEN, args.path, SSH_FXF_WRITE, attrs)
    except paramiko.SFTPError as exc:
        print(f"result:open-denied write-open rejected: {exc}")
        return 3

    if t != sftp_proto.CMD_HANDLE:
        print(f"result:setup-error open returned non-handle reply (type={t})")
        return 3
    handle = msg.get_binary()

    # Now attempt the bypass: SSH_FXP_READ against the write-opened handle.
    # `paramiko.sftp.int64(...)` tells _request to serialize as uint64 for
    # the offset field; otherwise it gets packed as 32-bit and the server
    # parses garbage off the end. paramiko maps SSH_FX_PERMISSION_DENIED
    # to `OSError(errno.EACCES, …)` (a Python `PermissionError`).
    try:
        t2, msg2 = sftp._request(
            sftp_proto.CMD_READ,
            handle,
            sftp_proto.int64(0),
            4096,
        )
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.EACCES:
            print(f"result:denied SSH_FX_PERMISSION_DENIED ({exc})")
            return 0
        print(f"result:other-error {type(exc).__name__}: {exc}")
        return 3

    if t2 == sftp_proto.CMD_DATA:
        data = msg2.get_binary()
        print(f"result:bypass got {len(data)} bytes from a write-only handle: {data!r}")
        return 2

    print(f"result:setup-error read returned unexpected reply type {t2}")
    return 3


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"result:setup-error {type(exc).__name__}: {exc}")
        sys.exit(3)
