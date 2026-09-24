"""Paramiko helpers for Zift cases (`need_paramiko` puts this on PYTHONPATH).

    from client import *
    sftp = connect("ally")          # password "secret", this case's port
    code = status(sftp, CMD_READLINK, "/x")
"""

import logging
import os
import socket
import sys
import time

import paramiko
from paramiko.message import Message
from paramiko.sftp import (CMD_CLOSE, CMD_DATA, CMD_EXTENDED, CMD_HANDLE, CMD_NAME, CMD_OPEN,
                           CMD_OPENDIR, CMD_READ, CMD_READDIR, CMD_READLINK, CMD_SETSTAT,
                           CMD_STAT, CMD_STATUS, CMD_SYMLINK, CMD_WRITE, int64)
from paramiko.sftp_attr import SFTPAttributes

logging.getLogger("paramiko").addHandler(logging.NullHandler())  # no transport-thread noise

PORT = int(os.environ["TEST_PORT"])
TMP = os.environ["TEST_TMP"]

FX_OK, FX_NO_SUCH_FILE, FX_PERMISSION_DENIED, FX_FAILURE = 0, 2, 3, 4
FX_BAD_MESSAGE, FX_OP_UNSUPPORTED = 5, 8
FXF_READ, FXF_WRITE, FXF_APPEND = 0x01, 0x02, 0x04


def ok(msg):
    print(f"  ok: {msg}")


def fail(msg):
    print(f"  fail: {msg}")
    sys.exit(1)


def transport(user, password="secret", key=None, host="127.0.0.1", timeout=15):
    """A logged-in transport, by key if given, else by password; raises
    paramiko.AuthenticationException."""
    t = paramiko.Transport(socket.create_connection((host, PORT), timeout=timeout))
    try:
        t.connect(username=user, password=None if key else password, pkey=key)
    except BaseException:
        t.close()
        raise
    return t


def connect(user, password="secret", timeout=15, **kw):
    """An SFTP client; `sftp.sock.get_transport()` is its transport."""
    sftp = paramiko.SFTPClient.from_transport(transport(user, password, timeout=timeout, **kw))
    sftp.get_channel().settimeout(timeout)
    return sftp


def close(sftp):
    sftp.sock.get_transport().close()


def can_login(user, password="secret", **kw):
    try:
        transport(user, password, **kw).close()
        return True
    except paramiko.AuthenticationException:
        return False


def raw(sftp, opcode, *items):
    """Send one request as given; return (reply type, Message after the id)."""
    body = Message()
    for item in items:
        if isinstance(item, SFTPAttributes):
            item._pack(body)
        elif isinstance(item, int64):
            body.add_int64(item)
        elif isinstance(item, int):
            body.add_int(item)
        else:
            body.add_string(item)
    with sftp._lock:
        req = sftp.request_number
        sftp.request_number += 1
    msg = Message()
    msg.add_int(req)
    sftp._send_packet(opcode, Message(msg.asbytes() + body.asbytes()))
    kind, data = sftp._read_packet()
    reply = Message(data)
    reply.get_int()
    return kind, reply


def status(sftp, opcode, *items):
    """The status code a raw request gets, or -1 for a non-status reply."""
    kind, reply = raw(sftp, opcode, *items)
    return reply.get_int() if kind == CMD_STATUS else -1


def outcome(fn, *args):
    """Run an SFTP call: 'ok', 'denied', 'missing', 'failure' or 'timeout'."""
    try:
        fn(*args)
        return "ok"
    except socket.timeout:
        return "timeout"
    except PermissionError:
        return "denied"
    except FileNotFoundError:
        return "missing"
    except IOError:
        return "failure"


def expect(label, want, fn, *args):
    got = outcome(fn, *args)
    if got != want:
        fail(f"{label}: want {want}, got {got}")
    ok(f"{label}: {got}")


def wait_for(pred, limit=10):
    end = time.monotonic() + limit
    while not pred():
        if time.monotonic() > end:
            return False
        time.sleep(0.05)
    return True


def host(path):
    """The on-disk path for a file the case keeps under $TEST_TMP."""
    return os.path.join(TMP, path)


def read(path):
    with open(host(path), "rb") as f:
        return f.read()
