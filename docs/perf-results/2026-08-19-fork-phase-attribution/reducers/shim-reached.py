"""Is the EL1 gettid handler REACHED, or does the cmp chain never match it?

The handler increments `IDENTITY_OFF_SHIM_SYSCALLS` BEFORE it reads
CONTEXTIDR_EL1, and its own comment notes the degrade path "still traps to the
host AFTER counting". So the counter cannot tell a hit from a degrade — but it
can tell REACHED from NOT REACHED, which is the open question.

carrick converts that counter into system time at `EL1_SHIM_SYSCALL_NOMINAL_NS`
(75 ns) per count, and surfaces it through getrusage(RUSAGE_SELF).ru_stime. So:

  getpid   EL1-served          -> counted, ~0 real dispatch
  gettid   reached + degrades  -> counted AND real dispatch
  getppid  never in the chain  -> NOT counted, real dispatch only

If gettid's stime is ~N*75ns ABOVE getppid's, the handler is reached and the
CONTEXTIDR read is returning 0 at EL1 despite the host seeing it set. If the two
match, the cmp/beq for 178 never fires and the bug is in the dispatch chain.

Docker has no such counter, so this is a carrick-internal measurement; the
comparison that matters is BETWEEN the three syscalls, not against Linux.
"""

import ctypes
import ctypes.util
import os

libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
N = int(os.environ.get("SHIM_N", "200000"))
SYS = {"getpid": 172, "gettid": 178, "getppid": 173}


class Timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class Rusage(ctypes.Structure):
    _fields_ = [("ru_utime", Timeval), ("ru_stime", Timeval)] + [
        (f"pad{i}", ctypes.c_long) for i in range(14)
    ]


def stime_us():
    r = Rusage()
    libc.getrusage(0, ctypes.byref(r))
    return r.ru_stime.tv_sec * 1_000_000 + r.ru_stime.tv_usec


for name, nr in SYS.items():
    before = stime_us()
    for _ in range(N):
        libc.syscall(nr)
    delta = stime_us() - before
    print(f"{name:8s} {N} calls -> ru_stime +{delta:8d} us "
          f"({delta*1000/N:6.1f} ns/call charged)", flush=True)
