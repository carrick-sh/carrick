#!/usr/bin/env python3
"""RED-FIRST: does recvmsg echo MSG_CMSG_CLOEXEC back in msg_flags?

Go's TestSCMCredentials asserts `ReadMsgUnix flags = 0x40000000`; carrick
returns 0x0. Ask recvmsg directly on both sides.
"""
import array, os, socket, sys

MSG_CMSG_CLOEXEC = 0x40000000
a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
fd = os.open("/dev/null", os.O_RDONLY)
a.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])
data, anc, flags, addr = b.recvmsg(10, socket.CMSG_SPACE(4), MSG_CMSG_CLOEXEC)
print("with MSG_CMSG_CLOEXEC:    data=%r anc=%d msg_flags=0x%x" % (data, len(anc), flags), flush=True)
for level, typ, cd in anc:
    got = array.array("i"); got.frombytes(cd[:4])
    print("   received fd=%d cloexec=%s" % (got[0], bool(os.get_inheritable(got[0]) is False)), flush=True)
    os.close(got[0])

a.sendmsg([b"y"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])
data, anc, flags, addr = b.recvmsg(10, socket.CMSG_SPACE(4), 0)
print("without MSG_CMSG_CLOEXEC: data=%r anc=%d msg_flags=0x%x" % (data, len(anc), flags), flush=True)
for level, typ, cd in anc:
    got = array.array("i"); got.frombytes(cd[:4]); os.close(got[0])
sys.stdout.flush()
