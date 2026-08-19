#!/usr/bin/env python3
"""Does the EL1 gettid fast path keep returning the right tid over time?

Run against a build whose unstamped-tid degrade `cbz` is NOP'd out, so the
handler always erets with whatever CONTEXTIDR_EL1 holds. A transition
1 -> 0 proves CONTEXTIDR_EL1 is being LOST (not stamped on the vCPU the
thread later runs on), which sends every subsequent gettid down the degrade
branch to the host on an unmodified build.
"""
import ctypes, sys, time

libc = ctypes.CDLL(None, use_errno=True)
SYS_gettid = 178

seen = []
last = None
for i in range(200000):
    v = libc.syscall(SYS_gettid)
    if v != last:
        seen.append((i, v))
        last = v
        if len(seen) > 20:
            break
print("gettid value transitions (call_index, value):", seen, flush=True)
sys.stdout.flush()
