"""Does carrick's mmap arena hand out one anonymous VA twice?

`next_mmap_address_inner` (`crates/carrick-runtime/src/dispatch/mem.rs`) has two
independent hand-out paths -- a free-list FIRST FIT (`mem.rs:2307`) and the bump
cursor `mmap_next` (`mem.rs:2316`) -- reconciled only by the invariant stated at
`mem.rs:485`, "everything at/above `mmap_next` is unallocated". Nothing enforces
its second half: no path clamps a `free_regions` entry to lie below the cursor.

Two ordinary-on-Linux sequences put a free region strictly ABOVE the cursor:

  CASE B  `MAP_FIXED` returns early at `mem.rs:2276` WITHOUT advancing the
          cursor, so munmapping that mapping inserts a region above it.
  CASE A  munmap's absorb loop (`mem.rs:4295`) reclaims only regions CONTIGUOUS
          BELOW the lowered cursor, so an interior hole that the lowering jumps
          past survives above it.

After either, the free list hands that VA out and the bump cursor later climbs
over it and hands out the SAME VA again -- flagged `stale` (below
`mmap_writable_high`), so carrick memsets it to zero THROUGH the first grant's
live mapping.

RED: `alias=True`, and/or the first grant's bytes read back as zero.
GREEN (and Linux): `alias=False` with bytes intact -- `mmap(NULL, ...)` never
returns a live VA.

Run under carrick and under the native-arm64 Docker oracle, one at a time.
"""

import ctypes, ctypes.util, os, sys

libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                      ctypes.c_int, ctypes.c_int, ctypes.c_long]
libc.munmap.restype = ctypes.c_int
libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]

PROT_READ, PROT_WRITE = 1, 2
MAP_SHARED, MAP_PRIVATE, MAP_FIXED, MAP_ANON = 0x01, 0x02, 0x10, 0x20
MAP_FAILED = ctypes.c_void_p(-1).value

PAGE = os.sysconf("SC_PAGESIZE")
NPAGES = 32                      # big enough that no incidental hole first-fits
SPAN = NPAGES * PAGE


def anon(n, at=0, fixed=False):
    flags = MAP_PRIVATE | MAP_ANON | (MAP_FIXED if fixed else 0)
    p = libc.mmap(ctypes.c_void_p(at), n, PROT_READ | PROT_WRITE, flags, -1, 0)
    return None if p == MAP_FAILED else p


def fill(addr, n, byte):
    ctypes.memset(ctypes.c_void_p(addr), byte, n)


def zeros(addr, n):
    return (ctypes.c_ubyte * n).from_address(addr)[:].count(0)


def walk_for_alias(first, limit=96):
    """Bump upward and see whether the cursor re-issues `first`."""
    for _ in range(limit):
        g = anon(SPAN)
        if g is None:
            return False
        if g == first:
            return True
    return False


def case_fixed():
    """MAP_FIXED above the cursor, then munmap it.

    The fixed address is derived, never guessed: reserve a span with
    mmap(NULL), free the WHOLE span (which on carrick also lowers the cursor
    back to its base), and only then MAP_FIXED inside it. That address is
    therefore free on Linux and above the cursor on carrick, so the case cannot
    clobber an unrelated live mapping on either side.
    """
    res = anon(64 * SPAN)
    if res is None:
        return "B reserve=failed", True
    libc.munmap(ctypes.c_void_p(res), 64 * SPAN)   # whole span free on both
    print("  B.1 reserved+freed", flush=True)

    fixed_at = res + 32 * SPAN                     # inside the freed span
    f = anon(SPAN, at=fixed_at, fixed=True)
    if f is None or f != fixed_at:
        return f"B MAP_FIXED={f} wanted={fixed_at:#x}", True
    fill(f, SPAN, 0x5A)                            # raise the dirty watermark
    libc.munmap(ctypes.c_void_p(f), SPAN)          # free region ABOVE the cursor
    print("  B.2 fixed mapped+filled+freed", flush=True)

    first = anon(SPAN)                             # expect the free-list fit
    if first is None:
        return "B first=failed", True
    fill(first, SPAN, 0x5A)
    print(f"  B.3 first={first:#x} filled", flush=True)

    alias = walk_for_alias(first)
    print(f"  B.4 walked alias={alias}", flush=True)
    z = zeros(first, SPAN)
    return (f"B fixed_at={fixed_at:#x} first={first:#x} alias={alias} "
            f"zeroed_of_first={z}"), (alias or z > 0)


def case_superset():
    a = anon(4 * SPAN)
    if a is None:
        return "A map=failed", True
    fill(a, 4 * SPAN, 0xAA)
    print("  A.1 reserved+filled", flush=True)
    libc.munmap(ctypes.c_void_p(a + SPAN), SPAN)  # interior hole
    libc.munmap(ctypes.c_void_p(a), 4 * SPAN)     # superset: ends at cursor
    print("  A.2 hole + superset munmap", flush=True)

    first = anon(SPAN)                            # expect the surviving hole
    if first is None:
        return "A first=failed", True
    fill(first, SPAN, 0x5A)
    print(f"  A.3 first={first:#x} filled", flush=True)
    alias = walk_for_alias(first)
    print(f"  A.4 walked alias={alias}", flush=True)
    z = zeros(first, SPAN)
    return (f"A base={a:#x} first={first:#x} alias={alias} "
            f"zeroed_of_first={z}"), (alias or z > 0)


red = False
print(f"page={PAGE} span={SPAN}", flush=True)
for case in (case_fixed, case_superset):
    line, bad = case()
    red = red or bad
    print(line, flush=True)
print("verdict=" + ("DOUBLE-GRANT-OBSERVED" if red else "clean"), flush=True)
sys.exit(1 if red else 0)
