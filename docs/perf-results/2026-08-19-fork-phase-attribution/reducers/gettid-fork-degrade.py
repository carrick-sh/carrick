#!/usr/bin/env python3
"""RED-FIRST: does the EL1 gettid fast path SURVIVE a fork?

`getpid` reads the per-process identity PAGE (memory). `gettid` reads
CONTEXTIDR_EL1, a per-vCPU REGISTER stamped only at exec/clone. If a vCPU
lease reclaim/re-acquire hands the thread a fresh hv_vcpu, that register
reads 0 and every later gettid takes the handler's degrade branch to the
host -- permanently, and invisibly, since the host still returns the right
tid.

Expected on a correct runtime: gettid stays at getpid's cost across a fork.
"""
import ctypes, os, sys, time

libc = ctypes.CDLL(None, use_errno=True)
N = 20000


def bench(nr):
    libc.syscall(nr)
    t0 = time.perf_counter_ns()
    for _ in range(N):
        libc.syscall(nr)
    return (time.perf_counter_ns() - t0) / N


def report(tag):
    print("%-14s getpid=%4.0fns gettid=%4.0fns  gettid_value=%d"
          % (tag, bench(172), bench(178), libc.syscall(178)), flush=True)


report("before-fork")
pid = os.fork()
if pid == 0:
    report("child")
    sys.stdout.flush()
    os._exit(0)
os.waitpid(pid, 0)
report("after-fork")
sys.stdout.flush()
