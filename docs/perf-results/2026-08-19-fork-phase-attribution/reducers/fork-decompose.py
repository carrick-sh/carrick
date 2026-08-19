"""Split guest fork wall into the syscall itself and everything around it.

The fork-phase probes show the named phases cover 98% of carrick's fork
HANDLER, yet the handler is only ~26% of guest-observed fork wall. So three
quarters of the cost is outside it. This asks the next question: is that the
guest's own fork bookkeeping, or carrick's trap/dispatch path?

  os.fork()   - CPython's fork: PyOS_BeforeFork/AfterFork run the import lock,
                threading reinit and atfork handlers, each of which is more
                guest syscalls.
  libc.fork() - the raw libc call, no interpreter bookkeeping. The child is left
                in an inconsistent CPython state, which is fine because it only
                calls _exit.

If libc.fork() is far cheaper, the gap is per-syscall cost amplified by
CPython's bookkeeping, and fork itself is not the primitive to attack.
If both are equally slow, the cost is in carrick's own trap/dispatch path.

Run under carrick and under the native-arm64 Docker oracle, one at a time.
"""

import ctypes
import ctypes.util
import os
import time

libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
N = int(os.environ.get("FORK_N", "200"))


def reap(pid):
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


def timed(label, forker):
    kids = []
    t0 = time.monotonic()
    for _ in range(N):
        pid = forker()
        if pid == 0:
            os._exit(0)
        kids.append(pid)
    wall = time.monotonic() - t0
    for pid in kids:
        reap(pid)
    print(f"{label:12s} {N} forks in {wall*1000:8.1f} ms = {wall*1000/N:7.3f} ms/fork",
          flush=True)
    return wall / N


a = timed("os.fork", os.fork)
b = timed("libc.fork", libc.fork)
print(f"ratio os.fork / libc.fork = {a/b:.2f}x", flush=True)
