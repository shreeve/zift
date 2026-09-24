#!/usr/bin/env python3
"""
Floods an established SFTP session with SSH messages Zift never serves:
`env`, `exec` and `pty-req` requests on the SFTP channel, extra session
channel opens, and tcpip-forward global requests.

libssh queues every such message unless something consumes it, so a
server that stops reading messages once the subsystem starts grows
without bound and never answers requests that want a reply. The probe
compares the server's RSS (via `ps`) before and after, checks that
want-reply requests are refused promptly, and checks SFTP still works.

Exit 0 on success, 2 on a failed check, 3 on an environment error.
"""

import argparse
import logging
import socket
import subprocess
import sys
import threading
import time

import paramiko
from paramiko.common import cMSG_CHANNEL_REQUEST
from paramiko.message import Message


def rss_kib(pid):
    out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True)
    return int(out.stdout.strip())


def channel_request(transport, chan, kind, *fields):
    # Raw and without want_reply: paramiko closes a channel whose
    # request fails, and the SFTP channel must stay up.
    m = Message()
    m.add_byte(cMSG_CHANNEL_REQUEST)
    m.add_int(chan.remote_chanid)
    m.add_string(kind)
    m.add_boolean(False)
    for f in fields:
        if isinstance(f, int):
            m.add_int(f)
        else:
            m.add_string(f)
    transport._send_user_message(m)


def global_request_with_timeout(transport, timeout):
    # paramiko waits forever for a global reply; a server that queues
    # the request never sends one.
    result = {}

    def run():
        result["reply"] = transport.global_request("tcpip-forward", ("127.0.0.1", 0), wait=True)

    th = threading.Thread(target=run, daemon=True)
    th.start()
    th.join(timeout)
    if th.is_alive():
        return "timeout"
    return result["reply"]


def main():
    # Each refused open would otherwise log a warning.
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--flood", type=int, default=4000)
    ap.add_argument("--max-growth-kib", type=int, default=24 * 1024)
    args = ap.parse_args()

    try:
        sock = socket.create_connection(("127.0.0.1", args.port), timeout=30)
        t = paramiko.Transport(sock)
        t.connect(username=args.user, password=args.password)
        sftp = paramiko.SFTPClient.from_transport(t)
        sftp.listdir("/")
    except Exception as e:
        print(f"env: cannot start SFTP: {e}")
        return 3

    failed = False
    before = rss_kib(args.pid)
    chan = sftp.get_channel()

    value = "x" * (16 * 1024)
    for i in range(args.flood):
        channel_request(t, chan, "env", f"FLOOD_{i}", value)
    for i in range(args.flood // 4):
        channel_request(t, chan, "exec", value)
        channel_request(t, chan, "pty-req", "xterm", 80, 24, 0, 0, value)
    # Replies are ordered after the flood, so once this returns the
    # server has taken in every request above.
    sftp.listdir("/")
    print(f"ok: SFTP answers after {args.flood} env and {args.flood // 2} exec/pty-req requests")

    refused = 0
    start = time.monotonic()
    for _ in range(100):
        try:
            extra = t.open_session(timeout=5)
            extra.close()
        except paramiko.ChannelException:
            refused += 1
        except paramiko.SSHException as e:
            print(f"fail: channel open was not refused promptly: {e}")
            failed = True
            break
    if refused == 100:
        print(f"ok: 100 extra channel opens refused in {time.monotonic() - start:.2f}s")
    else:
        print(f"fail: only {refused}/100 extra channel opens refused")
        failed = True

    for _ in range(200):
        t.global_request("tcpip-forward", ("127.0.0.1", 0), wait=False)
    reply = global_request_with_timeout(t, 5)
    if reply is None:
        print("ok: tcpip-forward refused")
    else:
        print(f"fail: tcpip-forward got {reply!r}")
        failed = True

    data = b"flood-survivor\n" * 1000
    with sftp.open("/flood.txt", "wb") as f:
        f.write(data)
    with sftp.open("/flood.txt", "rb") as f:
        got = f.read()
    if got == data:
        print("ok: SFTP upload and download still work")
    else:
        print("fail: SFTP round trip corrupted")
        failed = True

    after = rss_kib(args.pid)
    growth = after - before
    print(f"rss before={before} KiB after={after} KiB growth={growth} KiB")
    if growth > args.max_growth_kib:
        print(f"fail: RSS grew {growth} KiB (> {args.max_growth_kib})")
        failed = True
    else:
        print("ok: RSS stayed bounded")

    sftp.close()
    t.close()
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
