#!/usr/bin/env python3
"""RED-FIRST: what ucred does a receiver get in SCM_CREDENTIALS?

Go's TestSCMCredentials sends an explicit SCM_CREDENTIALS record and compares the
oob bytes it reads back. carrick may REGENERATE the record from the host peer
instead of delivering what the sender supplied, and under HVPatch a host pid is
the carrier's for every peer rather than the sending guest's.
"""
import array, os, socket, struct, sys

SCM_CREDENTIALS = 0x02
SO_PASSCRED = 16

a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
b.setsockopt(socket.SOL_SOCKET, SO_PASSCRED, 1)
mypid, myuid, mygid = os.getpid(), os.getuid(), os.getgid()
print("sender identity: pid=%d uid=%d gid=%d" % (mypid, myuid, mygid), flush=True)

ucred = struct.pack("iII", mypid, myuid, mygid)
a.sendmsg([b"x"], [(socket.SOL_SOCKET, SCM_CREDENTIALS, ucred)])
data, anc, flags, addr = b.recvmsg(10, socket.CMSG_SPACE(len(ucred)))
print("received %d ancillary record(s)" % len(anc), flush=True)
for level, typ, cd in anc:
    if typ == SCM_CREDENTIALS and len(cd) >= 12:
        pid, uid, gid = struct.unpack("iII", cd[:12])
        print("  SCM_CREDENTIALS pid=%d uid=%d gid=%d  pid_matches_sender=%s"
              % (pid, uid, gid, pid == mypid), flush=True)
    else:
        print("  level=%d type=%d len=%d" % (level, typ, len(cd)), flush=True)
sys.stdout.flush()
