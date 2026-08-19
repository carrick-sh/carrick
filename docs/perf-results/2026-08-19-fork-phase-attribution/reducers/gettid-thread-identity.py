#!/usr/bin/env python3
"""A spawned thread must get its OWN tid from the EL1 fast path, fast.

Guards the sibling-vCPU restore path: carrying the parent's CONTEXTIDR_EL1
into a new thread's vCPU would make gettid return the PARENT's tid.
"""
import ctypes, os, sys, threading, time

libc = ctypes.CDLL(None, use_errno=True)
N = 20000


def probe(tag):
    libc.syscall(178)
    t0 = time.perf_counter_ns()
    for _ in range(N):
        libc.syscall(178)
    ns = (time.perf_counter_ns() - t0) / N
    shim = libc.syscall(178)
    native = threading.get_native_id()
    ok = (shim == native) and ns < 400
    print("%-10s shim_gettid=%-4d get_native_id=%-4d %6.0fns %s"
          % (tag, shim, native, ns, "OK" if ok else "BAD"), flush=True)
    return ok


results = [probe("main")]
for i in range(3):
    out = []
    t = threading.Thread(target=lambda: out.append(probe("thread%d" % i)))
    t.start()
    t.join()
    results.extend(out)
results.append(probe("main-after"))
print("RESULT:", "PASS" if all(results) else "FAIL", flush=True)
sys.stdout.flush()
