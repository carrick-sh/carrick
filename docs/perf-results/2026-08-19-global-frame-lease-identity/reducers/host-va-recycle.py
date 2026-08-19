"""Does Darwin hand the same host VA back after munmap?

`global_frame_host_owner_matches` (carrick-vmm-hvf/src/trap.rs) authenticates a
stale per-thread mapping row by comparing the OWNER'S HOST POINTER for a given
`(ipa, length)`. Its doc comment says macOS "may immediately recycle that host
VA for an unrelated frame" and calls the `(IPA, length, host pointer)` triple
"the only safe HVPatch predicate" — but the triple has no generation, so the
predicate is only as strong as the assumption that the pointer does not recur.

Host-only: no carrick, no guest, no build, ~1 s. Uses the same flags as
`map_shared_anon`.

Measured 2026-08-19 on the canonical host: 499/499 at both sizes, ONE distinct
address. Reuse is deterministic, not occasional.
"""

import ctypes
import ctypes.util

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                      ctypes.c_int, ctypes.c_int, ctypes.c_long]
libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]

PROT_RW = 3
FLAGS = 0x1 | 0x1000 | 0x40   # MAP_SHARED | MAP_ANON | MAP_NORESERVE (macOS)

for length in (16 * 1024, 64 * 1024):
    rounds, same, seen, prev = 500, 0, {}, None
    for _ in range(rounds):
        p = libc.mmap(None, length, PROT_RW, FLAGS, -1, 0)
        seen[p] = seen.get(p, 0) + 1
        if prev is not None and p == prev:
            same += 1
        libc.munmap(ctypes.c_void_p(p), length)
        prev = p
    print(f"len={length:6d}: immediate same-VA reuse {same}/{rounds - 1}, "
          f"distinct VAs={len(seen)}, max reuse of one VA={max(seen.values())}")
