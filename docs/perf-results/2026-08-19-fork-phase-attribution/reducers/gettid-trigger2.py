#!/usr/bin/env python3
"""Which operation loses the EL1 gettid fast path? (fork alone does not.)"""
import ctypes, os, sys, threading, time

libc = ctypes.CDLL(None, use_errno=True)
N = 20000


def bench(nr):
    libc.syscall(nr)
    t0 = time.perf_counter_ns()
    for _ in range(N):
        libc.syscall(nr)
    return (time.perf_counter_ns() - t0) / N


def report(tag):
    p, t = bench(172), bench(178)
    print("%-24s getpid=%5.0fns gettid=%5.0fns value=%d %s"
          % (tag, p, t, libc.syscall(178), "OK" if t < p * 2 else "DEGRADED"), flush=True)


report("baseline")

pid = os.fork()
if pid == 0:
    os.execv("/bin/true", ["true"])
    os._exit(127)
os.waitpid(pid, 0)
report("after fork+exec child")

th = threading.Thread(target=lambda: time.sleep(0.05))
th.start()
th.join()
report("after thread create/join")

import subprocess
subprocess.run(["/bin/true"], check=False)
report("after subprocess.run")
sys.stdout.flush()
