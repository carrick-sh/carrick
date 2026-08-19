#!/usr/bin/env python3
"""Why does CPython skip the 42 SCTP socket tests under carrick?

CPython's test_socket gates them on being able to create an SCTP socket. If
carrick answers the socket(2) with an errno, they skip; Docker's LinuxKit kernel
has SCTP, so they run and pass. Print the exact errno so the gap is attributed to
a syscall answer rather than guessed at.
"""
import ctypes, errno, socket, sys

print("has IPPROTO_SCTP attr:", hasattr(socket, "IPPROTO_SCTP"),
      getattr(socket, "IPPROTO_SCTP", None), flush=True)
for name, proto in (("IPPROTO_SCTP", getattr(socket, "IPPROTO_SCTP", 132)),):
    for styp, sname in ((socket.SOCK_STREAM, "SOCK_STREAM"), (socket.SOCK_SEQPACKET, "SOCK_SEQPACKET")):
        try:
            s = socket.socket(socket.AF_INET, styp, proto)
            print(f"AF_INET/{sname}/{name}: OK fd={s.fileno()}", flush=True)
            s.close()
        except OSError as e:
            print(f"AF_INET/{sname}/{name}: errno={e.errno} ({errno.errorcode.get(e.errno)}) {e.strerror}", flush=True)
sys.stdout.flush()
