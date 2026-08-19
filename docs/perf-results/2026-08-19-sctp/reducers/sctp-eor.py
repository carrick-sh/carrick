#!/usr/bin/env python3
"""When exactly does Linux set MSG_EOR on an SCTP SOCK_STREAM recvmsg?

CPython's SCTP mixins assert MSG_EOR even for SHORT reads and peeks, which is not
obvious. Measure the rule on the oracle instead of inferring it.
"""
import socket, sys

MSG_EOR = 128
def run(label, bufsize, flags=0, sendsize=64):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
    srv.bind(("127.0.0.1", 0)); srv.listen(1)
    cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
    cli.connect(srv.getsockname())
    conn, _ = srv.accept()
    cli.send(b"x" * sendsize)
    data, anc, mf, addr = conn.recvmsg(bufsize, 0, flags)
    print("%-26s sent=%-4d buf=%-4d flags=%-4d -> got=%-4d msg_flags=0x%x eor=%s"
          % (label, sendsize, bufsize, flags, len(data), mf, bool(mf & MSG_EOR)), flush=True)
    for s in (conn, cli, srv): s.close()

run("full read", 1024)
run("short read", 16)
run("exact read", 64)
run("peek", 1024, socket.MSG_PEEK)
run("read after peek", 16, socket.MSG_PEEK)
sys.stdout.flush()
