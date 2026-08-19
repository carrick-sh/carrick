# RED receipt — arena double-grant reproduces in ~1 s

**Date:** 2026-08-18
**Artifact under test:** source `575c9288d`, binary
`c6e35353d915389714cdc5c5a60827eab822bdbfea444b79a67b83b205b9fb01`,
CDHash `5ba76e5055d1b86fbd5bff82af230a22c3f0b4a6`, hypervisor entitlement and
`__TEXT,__dof_carrick` present.
**Serialization:** the Docker leg and the carrick leg were run one after the
other, never concurrently. carrick reaped with `scripts/sudo/kill.sh adg-2`
(remaining procs = 0).

Reducer: `reducers/arena-double-grant.py` — no threads, no fork, ~40 lines of
`ctypes` over `mmap`/`munmap`. The `MAP_FIXED` address is **derived, never
guessed**: a span is reserved with `mmap(NULL)` and freed in full before the
fixed mapping is placed inside it, so the case is free on Linux and above the
cursor on carrick and cannot clobber an unrelated mapping on either side.

## Docker oracle — `localhost:5050/cpython-test:3.12.13`, `linux/arm64`

```
page=4096 span=131072
  B.1 reserved+freed
  B.2 fixed mapped+filled+freed
  B.3 first=0xffff8e630000 filled
  B.4 walked alias=False
B fixed_at=0xffff8e200000 first=0xffff8e630000 alias=False zeroed_of_first=0
  A.1 reserved+filled
  A.2 hole + superset munmap
  A.3 first=0xffff8da10000 filled
  A.4 walked alias=False
A base=0xffff8d9b0000 first=0xffff8da10000 alias=False zeroed_of_first=0
verdict=clean
DOCKER_EXIT=0
```

## carrick — same image, `--raw --fs host`

```
page=4096 span=131072
  B.1 reserved+freed
  B.2 fixed mapped+filled+freed
  B.3 first=0x60014b1000 filled
  B.4 walked alias=True
B fixed_at=0x60014b1000 first=0x60014b1000 alias=True zeroed_of_first=131072
  A.1 reserved+filled
  A.2 hole + superset munmap
  A.3 first=0x60014f1000 filled
  A.4 walked alias=True
A base=0x60014d1000 first=0x60014f1000 alias=True zeroed_of_first=131072
verdict=DOUBLE-GRANT-OBSERVED
```

## What this proves

Both cases: `mmap(NULL, len)` returned a VA that was **already live**, and every
one of the 131,072 bytes the first grant had filled with `0x5A` reads back as
zero. The guest was handed the same address twice and the second hand-out's
`stale` scrub memset the first grant's live mapping.

In case B `fixed_at == first` exactly, which pins the sequence: the free-list
first fit (`mem.rs:2307`) returned the region left above the cursor by the
`MAP_FIXED` that never advanced it (`mem.rs:2276`), and the bump cursor
(`mem.rs:2316`) then climbed over the same address.

An earlier, unsafe version of this reducer guessed the fixed address as
`probe + 512 pages` and produced an immediate guest `Segmentation fault` under
carrick while Docker passed. That run is **not** cited as evidence: a guessed
`MAP_FIXED` can legitimately replace a live mapping, so it could not distinguish
a double grant from self-inflicted damage. The derived-address version above
does, and it reports the corruption without crashing.

## Scope

This is a candidate root cause for the NULL-dereference crash family — an object
pointer read out of zeroed memory is exactly the `_PyEval_EvalFrameDefault`
`fault_address: 0` signature recorded for `cpython-importlib` — and it is
independently a silent data-loss bug reachable from ordinary `mmap`/`munmap`
use with no concurrency at all.
