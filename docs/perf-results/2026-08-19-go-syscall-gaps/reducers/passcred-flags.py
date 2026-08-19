#!/usr/bin/env python3
"""Go's TestSCMCredentials read shape: SO_PASSCRED, a dummy byte, nil data buf.

Go writes a dummy byte on SOCK_STREAM (its own comment says so) and then reads
with a nil data buffer, requiring msg_flags to be EXACTLY MSG_CMSG_CLOEXEC.
carrick reported 0x40000020 — an extra 0x20, Linux MSG_TRUNC.
"""
import os, socket, struct, sys

SCM_CREDENTIALS, SO_PASSCRED, MSG_CMSG_CLOEXEC = 0x02, 16, 0x40000000
for label, readsize in (("nil data buf", 0), ("1-byte data buf", 1)):
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    b.setsockopt(socket.SOL_SOCKET, SO_PASSCRED, 1)
    oob = struct.pack("iII", os.getpid(), os.getuid(), os.getgid())
    a.sendmsg([b"\x00"], [(socket.SOL_SOCKET, SCM_CREDENTIALS, oob)])
    data, anc, flags, addr = b.recvmsg(readsize, socket.CMSG_SPACE(len(oob)) * 10,
                                       MSG_CMSG_CLOEXEC)
    print("%-16s got=%d anc=%d msg_flags=0x%08x extra=0x%x"
          % (label, len(data), len(anc), flags, flags & ~MSG_CMSG_CLOEXEC), flush=True)
    a.close(); b.close()
sys.stdout.flush()
