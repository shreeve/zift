#!/usr/bin/env python3
"""
SFTP protocol-surface probe for tests/cases/18-sftp-wire-surface.sh.

PLAN §7.6 specifies which SFTP v3 request types Zift implements vs.
rejects, and what status code each rejection emits.

Each rejection must come back as `SSH_FX_OP_UNSUPPORTED` (=8). paramiko
4.0's high-level _convert_status does NOT distinguish OP_UNSUPPORTED
from FAILURE at the Python layer (both raise IOError(text) with no
errno), so we drop to raw protocol and inspect the status integer in
the reply.

Probe runs each scenario, reports `result:<scenario>:<outcome>` per
line on stdout. Exit codes:
  0  every scenario behaved as PLAN §7.6 specifies
  2  at least one scenario diverged from spec
  3  test environment failure
"""

import argparse
import socket
import sys

import paramiko
import paramiko.sftp as sftp_proto
from paramiko.message import Message
from paramiko.sftp_attr import SFTPAttributes


SSH_FX_OK = 0
SSH_FX_FAILURE = 4
SSH_FX_OP_UNSUPPORTED = 8


def raw_request(sftp, opcode: int, *items) -> tuple[int, int, str]:
    """
    Send a raw SFTP packet and read back the reply, returning
    (reply_type, status_code, status_text). For non-status replies the
    status_code/text fields are -1/"".
    """
    m = Message()
    for item in items:
        if isinstance(item, bytes):
            m.add_string(item)
        elif isinstance(item, str):
            m.add_string(item.encode("utf-8"))
        elif isinstance(item, SFTPAttributes):
            item._pack(m)
        else:
            raise TypeError(f"unsupported raw_request item {type(item)}")
    return _raw_dispatch(sftp, opcode, m)


def _raw_dispatch(sftp, opcode: int, body: Message) -> tuple[int, int, str]:
    sftp._lock.acquire()
    try:
        full = Message()
        full.add_int(sftp.request_number)
        full.asbytes()  # no-op; paramiko quirk
        # Concatenate the request_id with our body bytes.
        payload = full.asbytes() + body.asbytes()
        request_id = sftp.request_number
        sftp.request_number += 1
        sftp._expecting[request_id] = type(None)
    finally:
        sftp._lock.release()

    # Wrap in an outer Message that _send_packet will frame as one packet.
    outer = Message(payload)
    sftp._send_packet(opcode, outer)

    t, data = sftp._read_packet()
    msg = Message(data)
    _ = msg.get_int()  # echoed request_id
    if t == sftp_proto.CMD_STATUS:
        code = msg.get_int()
        text = msg.get_string()
        return t, code, text.decode("utf-8", errors="replace") if isinstance(text, bytes) else text
    return t, -1, ""


def expect_op_unsupported(name: str, sftp, opcode: int, *items) -> int:
    """Return 0 on success, 1 on divergence."""
    try:
        t, code, text = raw_request(sftp, opcode, *items)
    except Exception as exc:
        print(f"result:{name}:probe-error {type(exc).__name__}: {exc}")
        return 1
    if t != sftp_proto.CMD_STATUS:
        print(f"result:{name}:non-status reply type={t}")
        return 1
    if code == SSH_FX_OP_UNSUPPORTED:
        print(f"result:{name}:op_unsupported as expected ({text!r})")
        return 0
    if code == SSH_FX_FAILURE:
        print(f"result:{name}:wrong-code FAILURE ({text!r})")
        return 1
    print(f"result:{name}:other-code code={code} text={text!r}")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", required=True, type=int)
    ap.add_argument("--user", required=True)
    ap.add_argument("--pass", dest="password", required=True)
    ap.add_argument("--testfile", required=True, help="absolute virtual path to a file the user may open r/w")
    args = ap.parse_args()

    sock = socket.create_connection((args.host, args.port), timeout=15)
    transport = paramiko.Transport(sock)
    try:
        transport.connect(username=args.user, password=args.password)
    except Exception as exc:
        print(f"result:setup-error auth-failed: {exc}")
        return 3

    chan = transport.open_session()
    chan.invoke_subsystem("sftp")
    sftp = paramiko.SFTPClient(chan)

    failures = 0

    # Scenario 1: SETSTAT (opcode 9) — path + ATTRS struct.
    failures += expect_op_unsupported(
        "setstat", sftp,
        sftp_proto.CMD_SETSTAT,
        args.testfile,
        SFTPAttributes(),
    )

    # Scenario 2: READLINK (opcode 19) — just a path.
    failures += expect_op_unsupported(
        "readlink", sftp,
        sftp_proto.CMD_READLINK,
        args.testfile,
    )

    # Scenario 3: SYMLINK (opcode 20) — link path + target path.
    failures += expect_op_unsupported(
        "symlink", sftp,
        sftp_proto.CMD_SYMLINK,
        args.testfile + ".link",
        args.testfile,
    )

    # Scenario 4: EXTENDED (opcode 200) — extension name only is enough
    # to exercise dispatch.
    failures += expect_op_unsupported(
        "extended", sftp,
        sftp_proto.CMD_EXTENDED,
        "posix-rename@openssh.com",
    )

    # Scenario 5: FSTAT on an open handle must return attrs (paramiko
    # high-level still works because FSTAT is implemented).
    try:
        f = sftp.open(args.testfile, "r")
        try:
            attrs = f.stat()
            if isinstance(attrs, SFTPAttributes) and attrs.st_size is not None:
                print(f"result:fstat:ok size={attrs.st_size}")
            else:
                print(f"result:fstat:wrong-attrs got {attrs!r}")
                failures += 1
        finally:
            f.close()
    except Exception as exc:
        print(f"result:fstat:failed {type(exc).__name__}: {exc}")
        failures += 1

    # Scenario 6: an unknown SFTP opcode (250 — unassigned in v3) must
    # come back as OP_UNSUPPORTED, not as FAILURE or a disconnect.
    failures += expect_op_unsupported("unknown", sftp, 250)

    return 0 if failures == 0 else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"result:setup-error {type(exc).__name__}: {exc}")
        sys.exit(3)
