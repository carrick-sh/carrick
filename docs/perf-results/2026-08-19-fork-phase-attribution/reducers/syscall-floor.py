"""The per-syscall floor: what every guest operation pays before it does work.

Fork decomposes into the syscall (30x) plus the syscalls AROUND it, and the
latter cost more. So the floor matters more than any single primitive: it is
multiplied by every workload.

`getpid` is the cheapest real syscall — no arguments, no fd, no memory — so it
measures trap entry + dispatch + return and nothing else. `clock_gettime` is
included because it is the one carrick may answer without a full round trip,
which would show up as a much lower number and tell us the floor is avoidable.

Run under carrick and the native-arm64 Docker oracle, one at a time.
"""

import ctypes
import ctypes.util
import os
import time

libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
SYS_getpid, SYS_gettid, SYS_clock_gettime = 172, 178, 113
N = int(os.environ.get("SYS_N", "20000"))


class Ts(ctypes.Structure):
    _fields_ = [("s", ctypes.c_long), ("ns", ctypes.c_long)]


def bench(label, call):
    call()  # warm
    t0 = time.monotonic()
    for _ in range(N):
        call()
    d = time.monotonic() - t0
    print(f"{label:16s} {N} calls in {d*1000:8.1f} ms = {d*1e9/N:8.0f} ns/call", flush=True)


ts = Ts()
bench("getpid", lambda: libc.syscall(SYS_getpid))
bench("gettid", lambda: libc.syscall(SYS_gettid))
bench("clock_gettime", lambda: libc.syscall(SYS_clock_gettime, 1, ctypes.byref(ts)))
