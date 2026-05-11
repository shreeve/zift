#!/usr/bin/env python3
"""
SFTP path-limit probe for tests/cases/19-config-limits.sh.

PLAN §7.6: maximum virtual path length is 4096 bytes.
PLAN §8.3 step 2: reject NUL byte, all other ASCII control characters
(0x01–0x1F or 0x7F), and invalid UTF-8.

Each scenario sends a SFTP request with a malformed path and checks
that the server replies SSH_FX_BAD_MESSAGE (5) rather than going
through the policy/filesystem path. Uses raw protocol because
paramiko's high-level methods reject some malformed paths client-side
before we'd ever observe the server response.

Exit codes:
  0  every scenario rejected at the server with BAD_MESSAGE
  2  at least one scenario diverged
  3  test environment failure
"""

import argparse
import socket
import sys

import paramiko
import paramiko.sftp as sftp_proto
from paramiko.message import Message


SSH_FX_BAD_MESSAGE = 5


def raw_stat(sftp, path_bytes: bytes) -> tuple[int, int, str]:
    """Send SSH_FXP_STAT with `path_bytes` literally, return (type, code, text)."""
    body = Message()
    body.add_int(sftp.request_number)
    body.add_string(path_bytes)
    sftp.request_number += 1
    sftp._send_packet(sftp_proto.CMD_STAT, body)
    t, data = sftp._read_packet()
    msg = Message(data)
    _ = msg.get_int()
    if t == sftp_proto.CMD_STATUS:
        code = msg.get_int()
        text = msg.get_string()
        if isinstance(text, bytes):
            text = text.decode("utf-8", errors="replace")
        return t, code, text
    return t, -1, ""


def expect_bad_message(name: str, sftp, path_bytes: bytes) -> int:
    try:
        t, code, text = raw_stat(sftp, path_bytes)
    except Exception as exc:
        print(f"result:{name}:probe-error {type(exc).__name__}: {exc}")
        return 1
    if t != sftp_proto.CMD_STATUS:
        print(f"result:{name}:non-status reply type={t}")
        return 1
    if code == SSH_FX_BAD_MESSAGE:
        print(f"result:{name}:bad_message as expected ({text!r})")
        return 0
    print(f"result:{name}:wrong-code code={code} text={text!r}")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", required=True, type=int)
    ap.add_argument("--user", required=True)
    ap.add_argument("--pass", dest="password", required=True)
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

    # NUL byte.
    failures += expect_bad_message("nul-byte", sftp, b"/inbox/foo\x00bar")

    # ASCII control bytes 0x01–0x1F (PLAN §8.3 explicit).
    failures += expect_bad_message("c0-control-soh", sftp, b"/inbox/foo\x01bar")
    failures += expect_bad_message("c0-control-tab", sftp, b"/inbox/foo\x09bar")
    failures += expect_bad_message("c0-control-lf",  sftp, b"/inbox/foo\x0abar")
    failures += expect_bad_message("c0-control-cr",  sftp, b"/inbox/foo\x0dbar")

    # DEL (0x7F).
    failures += expect_bad_message("del", sftp, b"/inbox/foo\x7fbar")

    # Invalid UTF-8 sequence (lone 0xC3 with no continuation).
    failures += expect_bad_message("invalid-utf8", sftp, b"/inbox/foo\xc3bar")

    # Path > 4096 bytes (PLAN §7.6 limit).
    huge = b"/inbox/" + (b"a" * 4090) + b"/x"
    assert len(huge) > 4096
    failures += expect_bad_message("path-too-long", sftp, huge)

    # Sanity: a well-formed path that simply doesn't exist must NOT
    # come back as BAD_MESSAGE — it's NO_SUCH_FILE. Discriminates the
    # gate from a generic catch-all that flags every failure.
    try:
        t, code, text = raw_stat(sftp, b"/inbox/well-formed-but-missing.txt")
    except Exception as exc:
        print(f"result:sanity:probe-error {type(exc).__name__}: {exc}")
        failures += 1
    else:
        if code == SSH_FX_BAD_MESSAGE:
            print(f"result:sanity:false-positive a valid path got BAD_MESSAGE ({text!r})")
            failures += 1
        else:
            print(f"result:sanity:non-bad-message as expected (code={code})")

    return 0 if failures == 0 else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"result:setup-error {type(exc).__name__}: {exc}")
        sys.exit(3)
