#!/usr/bin/env python3
"""Go's TestSCMCredentials second case: SOCK_DGRAM, zero-length datagram.

Go writes `WriteMsgUnix(nil, oob, nil)` on a DGRAM pair — a zero-length datagram
carrying only SCM_CREDENTIALS — and reads it back with a nil data buffer,
requiring msg_flags to be EXACTLY MSG_CMSG_CLOEXEC. Nothing is truncated, so
Linux sets no MSG_TRUNC.
"""
import os, socket, struct, sys

SCM_CREDENTIALS, SO_PASSCRED, MSG_CMSG_CLOEXEC, MSG_TRUNC = 0x02, 16, 0x40000000, 0x20
for label, payload, readsize in (("0-byte dgram, 0 buf", b"", 0),
                                 ("0-byte dgram, 8 buf", b"", 8),
                                 ("1-byte dgram, 0 buf", b"\x00", 0)):
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    b.setsockopt(socket.SOL_SOCKET, SO_PASSCRED, 1)
    oob = struct.pack("iII", os.getpid(), os.getuid(), os.getgid())
    sent = a.sendmsg([payload], [(socket.SOL_SOCKET, SCM_CREDENTIALS, oob)])
    data, anc, flags, addr = b.recvmsg(readsize, socket.CMSG_SPACE(len(oob)) * 10,
                                       MSG_CMSG_CLOEXEC)
    print("%-22s sent=%d got=%d anc=%d msg_flags=0x%08x trunc=%s"
          % (label, sent, len(data), len(anc), flags, bool(flags & MSG_TRUNC)), flush=True)
    a.close(); b.close()
sys.stdout.flush()
