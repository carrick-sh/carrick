#!/usr/bin/env python3
"""Does msg_iovlen==0 (no iovec at all) change the returned msg_flags?

Python's socket.recvmsg always passes ONE iovec, so it cannot express what Go's
ReadMsgUnix(nil, oob) may do. Build the msghdr by hand and compare shapes.
aarch64 msghdr: name*, namelen, pad, iov*, iovlen(size_t), control*, controllen,
flags(int).
"""
import ctypes, os, socket, struct, sys

libc = ctypes.CDLL(None, use_errno=True)
SCM_CREDENTIALS, SO_PASSCRED, MSG_CMSG_CLOEXEC = 0x02, 16, 0x40000000

class IOVec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]

class MsgHdr(ctypes.Structure):
    _fields_ = [("name", ctypes.c_void_p), ("namelen", ctypes.c_uint32),
                ("pad", ctypes.c_uint32), ("iov", ctypes.POINTER(IOVec)),
                ("iovlen", ctypes.c_size_t), ("control", ctypes.c_void_p),
                ("controllen", ctypes.c_size_t), ("flags", ctypes.c_int)]

def probe(label, iovlen, buflen):
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    b.setsockopt(socket.SOL_SOCKET, SO_PASSCRED, 1)
    oob = struct.pack("iII", os.getpid(), os.getuid(), os.getgid())
    a.sendmsg([b"\x00"], [(socket.SOL_SOCKET, SCM_CREDENTIALS, oob)])

    buf = ctypes.create_string_buffer(max(buflen, 1))
    iov = IOVec(ctypes.cast(buf, ctypes.c_void_p), buflen)
    ctl = ctypes.create_string_buffer(320)
    m = MsgHdr()
    m.name = None; m.namelen = 0
    m.iov = ctypes.pointer(iov) if iovlen else None
    m.iovlen = iovlen
    m.control = ctypes.cast(ctl, ctypes.c_void_p); m.controllen = 320
    m.flags = 0
    ctypes.set_errno(0)
    n = libc.recvmsg(b.fileno(), ctypes.byref(m), MSG_CMSG_CLOEXEC)
    print("%-22s n=%-3d msg_flags=0x%08x extra=0x%x controllen=%d"
          % (label, n, m.flags & 0xffffffff, (m.flags & 0xffffffff) & ~MSG_CMSG_CLOEXEC,
             m.controllen), flush=True)
    a.close(); b.close()

probe("iovlen=0 (no iovec)", 0, 0)
probe("iovlen=1 len=0", 1, 0)
probe("iovlen=1 len=1", 1, 1)
sys.stdout.flush()
