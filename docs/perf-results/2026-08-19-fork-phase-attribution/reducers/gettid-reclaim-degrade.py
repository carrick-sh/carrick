#!/usr/bin/env python3
"""RED-FIRST: the EL1 gettid fast path must survive a vCPU lease reclaim.

A blocking wait long enough to trip `should_reclaim_vcpu_for_timed_wait`
releases this thread's vCPU. On resume the runtime rebinds saved register
state to a NEW slot but never re-stamps the guest tid into CONTEXTIDR_EL1,
so the EL1 `gettid` handler reads 0 and takes its degrade branch to the
host from then on -- permanently, and silently, since the host still
returns the correct tid.

PASS = gettid stays within 2x of getpid after every wait.
"""
import ctypes, os, sys, time

libc = ctypes.CDLL(None, use_errno=True)
N = 20000
FAIL = 0


def bench(nr):
    libc.syscall(nr)
    t0 = time.perf_counter_ns()
    for _ in range(N):
        libc.syscall(nr)
    return (time.perf_counter_ns() - t0) / N


def report(tag):
    global FAIL
    pid_ns, tid_ns = bench(172), bench(178)
    ok = tid_ns < pid_ns * 2
    if not ok:
        FAIL += 1
    print("%-22s getpid=%5.0fns gettid=%5.0fns value=%d %s"
          % (tag, pid_ns, tid_ns, libc.syscall(178), "OK" if ok else "DEGRADED"),
          flush=True)


report("baseline")
for ms in (5, 50, 400):
    pid = os.fork()
    if pid == 0:
        time.sleep(ms / 1000.0)
        os._exit(0)
    os.waitpid(pid, 0)
    report("after wait %dms" % ms)

print("RESULT: %s (%d degraded)" % ("FAIL" if FAIL else "PASS", FAIL), flush=True)
sys.stdout.flush()
sys.exit(1 if FAIL else 0)
