#!/usr/bin/env python3
"""A/B the EL1 gettid fast path against getpid, direct loops, no lambda.

Both are ~14-instruction EL1 shim handlers differing in one instruction, so
any gap between them is that instruction. Run the SAME script on both arms.
"""
import ctypes, sys, time

libc = ctypes.CDLL(None, use_errno=True)
N = 20000
print("first values: gettid=%d getpid=%d" % (libc.syscall(178), libc.syscall(172)), flush=True)
for rep in range(3):
    out = []
    for name, nr in (("getpid", 172), ("gettid", 178)):
        t0 = time.perf_counter_ns()
        for _ in range(N):
            libc.syscall(nr)
        t1 = time.perf_counter_ns()
        out.append("%s=%.0fns" % (name, (t1 - t0) / N))
    print("rep%d %s" % (rep, "  ".join(out)), flush=True)
sys.stdout.flush()
