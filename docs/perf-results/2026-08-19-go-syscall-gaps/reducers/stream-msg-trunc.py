#!/usr/bin/env python3
"""RED-FIRST: does a SHORT read on a unix STREAM socket set MSG_TRUNC?

Linux sets MSG_TRUNC for truncated ATOMIC records (datagram/seqpacket). A stream
has no record boundaries, so a short read just leaves the rest queued. macOS sets
it anyway, which Go's TestSCMCredentials catches: it reads with a nil data buffer
and requires msg_flags to be exactly MSG_CMSG_CLOEXEC.
"""
import socket, sys

MSG_TRUNC = 0x20
for name, styp in (("SOCK_STREAM", socket.SOCK_STREAM), ("SOCK_DGRAM", socket.SOCK_DGRAM)):
    a, b = socket.socketpair(socket.AF_UNIX, styp)
    a.send(b"hello")
    data, anc, flags, addr = b.recvmsg(0)          # zero-length data buffer
    print("%-12s recvmsg(0)  got=%d msg_flags=0x%x trunc=%s"
          % (name, len(data), flags, bool(flags & MSG_TRUNC)), flush=True)
    a2, b2 = socket.socketpair(socket.AF_UNIX, styp)
    a2.send(b"hello")
    data, anc, flags, addr = b2.recvmsg(2)         # short but non-zero
    print("%-12s recvmsg(2)  got=%d msg_flags=0x%x trunc=%s"
          % (name, len(data), flags, bool(flags & MSG_TRUNC)), flush=True)
sys.stdout.flush()
