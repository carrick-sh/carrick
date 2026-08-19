#!/usr/bin/env python3
"""Bisect what makes the EL1 gettid fast path degrade.

syscall-floor.py sees gettid at ~1560ns; an otherwise identical direct loop
sees 147ns on the SAME binary. Walk syscall-floor's preamble one step at a
time, re-measuring after each, to find the exact step that flips it.
"""
import ctypes, ctypes.util, os, sys, time

libc = ctypes.CDLL(None, use_errno=True)
N = 20000


def bench(lc, nr):
    lc.syscall(nr)
    t0 = time.perf_counter_ns()
    for _ in range(N):
        lc.syscall(nr)
    return (time.perf_counter_ns() - t0) / N


def report(tag, lc=None):
    lc = lc or libc
    print("%-26s getpid=%5.0fns gettid=%5.0fns value=%d"
          % (tag, bench(lc, 172), bench(lc, 178), lc.syscall(178)), flush=True)


report("0 baseline CDLL(None)")
name = ctypes.util.find_library("c")
report("1 after find_library(%s)" % name)
libc2 = ctypes.CDLL(name or "libc.so.6", use_errno=True)
report("2 via CDLL(found)", libc2)
report("3 CDLL(None) again")
t = time.monotonic()
report("4 after time.monotonic")
sys.stdout.flush()
