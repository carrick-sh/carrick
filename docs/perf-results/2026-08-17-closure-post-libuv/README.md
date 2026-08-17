# Closure checkpoint — post-libuv

**Date:** 2026-08-17
**Lane:** canonical macOS / Apple Silicon / HVF / HVPatch, Linux arm64 guest

The first authoritative full-surface closure run since the `node-libuv` oracle
repair. Every count in `docs/conformance-closure-ledger.md` and in the handoff
predated that repair and is superseded by this.

## Artifact

Re-frozen onto a binary built from a clean HEAD with no source newer than it.
An earlier freeze named a binary built before a `just fmt` pass that rewrote a
runtime source; a closure run had already started against it and was **stopped
24 suites in** rather than allowed to produce a receipt that could not be
attributed to an exact artifact.

| | |
|---|---|
| binary sha256 | `5ab52d7b893f56fa8caf8abf784b39d7d33fdca4a624802a1420f5489107eb34` |
| CDHash | `704f4da6a750857b66272ed8f91b19a203bbdd1c` |
| hypervisor entitlement | present |
| `__TEXT,__dof_carrick` | present |
| scope | 2,127 suites, four frozen image digests unchanged |

The run emitted no staleness warning, ran all 2,127 Carrick suites before any
Docker container (84 uncached oracles, 2,043 cached), and left no processes
behind.

## Result

| metric | pre-repair checkpoint | this run | delta |
|---|---:|---:|---:|
| suites MATCH | 1,199 | **1,201** | +2 |
| suites INCOMPLETE | 928 | **926** | −2 |
| semantic gap rows | 4,761 | **2,947** | **−1,814** |
| unexercised rows | 7,775 | **5,598** | **−2,177** |

Total assertion rows compared: 107,277.

The suite headline barely moves because a suite is INCOMPLETE if even one
assertion diverges; the assertion counts are where the work shows.

## What this run found

### 1. `go-os` and `go-net` had the libuv oracle defect (~900 rows) — FIXED

Both contain a test needing a controlling TERMINAL —
`TestSpliceFile/{TCP,Unix}-To-TTY` and `TestCopyFromTTY`. Without one they do
not fail or skip, they **hang**, and the suite is killed at its 180 s budget
mid-transcript. The oracle recorded 104 of `go-os`'s ~730 assertions and 259 of
`go-net`'s 449.

Verified directly: `docker run` of `TestSpliceFile` alone is still hanging at
300 s; with `-t` it completes and PASSes. Same for `TestCopyFromTTY`.

After adding `-t` and refilling both closure oracles:

| suite | oracle before | oracle after | divergent before | divergent after |
|---|---:|---:|---:|---:|
| `go-net` | 259 | 449 | 280 | **0 real** (90 mutual skips) |
| `go-os` | 104 | 730 | 643 | **14 real** (13 fails + 1 skip mismatch), 17 mutual skips |

So ~900 uncompared rows became compared, and they expose 14 honest Carrick gaps
that were previously invisible.

**Another invalid performance number retired.** `go-os` was reported at 67.02x
(carrick 40,947 ms vs oracle 611 ms). The oracle was hanging; with `-t` it
finishes in 2.7 s. Like libuv's 145.02x, a ratio against a truncated oracle is
not performance evidence.

### 2. `ltp-mremap01` — 1,314 rows from ONE bug, root-caused

Carrick: 1,313 `TBROK` + 1 `TFAIL`, ending in a segfault. Docker: **1 TPASS**.

The chain starts at a single divergence — `mremap01.c:117: mremap failed:
errno=ENOMEM` — and everything after it (`munmap failed: EINVAL`, then a
repeating `unexpected signal SIGIOT/SIGABRT`) is cascade from that one failure.

Reduced to a five-line reproducer, deterministic, no LTP required:

```python
# MAP_SHARED|MAP_ANONYMOUS, 1 page, then grow to 2 with MREMAP_MAYMOVE
carrick: FAIL errno=22 (Invalid argument)
docker : ok
# the same with MAP_PRIVATE|MAP_ANONYMOUS
carrick: ok        docker: ok
```

**Carrick cannot grow a mapping that is not in the mmap arena, even with
`MREMAP_MAYMOVE`.** `dispatch/mem.rs` handles the non-arena case (a `MAP_SHARED`
file alias or a `MAP_SHARED` anonymous shared-aperture region) by supporting
resize-DOWN and then falling through to an unconditional `ENOMEM` for any grow.
Linux with `MREMAP_MAYMOVE` is free to MOVE the mapping, which is what it does.

Not attempted here: the fix lands in the shared-aperture/arena code, where
AGENTS.md's non-identity stage-1/stage-2 rules apply, and it deserves its own
red-first cycle rather than being tacked onto a measurement session.

### 3. `ltp-setpriority01` — the ORACLE fails 120 of its own assertions

carrick 118 fails / docker **120 fails**, 40 of them shared. This is the
documented under-privileged-oracle trap, not a Carrick gap: `setpriority` cases
that lower a nice value need `CAP_SYS_NICE`, which Docker's default capability
set drops. Confirm by running the case under Docker with and without the
capability before changing anything, then grant it via `docker_flags` exactly as
the fanotify and add_key rows already do.

Note this suite was NOT closed by the `nice`/`ioprio` scope fix, contrary to
what a reading of the stale ledger would suggest.

### 4. The remaining large clusters

| cluster | divergent rows | shape |
|---|---:|---|
| CPython multiprocessing `fork`/`forkserver`/`spawn` | ~946 | `fork`/`forkserver` emit ZERO assertions at 5–6x Docker wall (hang → kill → block-buffered stdout discarded); `spawn` emits 88 at 0.72x (a fast crash). **Two different bugs.** |
| `cpython-importlib` | 351 | 849 of 1,199 emitted, then stops |
| `cpython-concurrent_futures` | 239 | 61 emitted at 0.62x — fast crash |
| `go-go_types` | 574 | not yet triaged |
| `ltp-splice07` / `ltp-ioctl_ficlone04` | 410 | LTP `tst_fd.c` fd-type inventory differs, shifting every ordinal |

## Method notes worth keeping

- A suite whose Carrick side runs FASTER than Docker and stops early is a
  **fast crash**, not a timeout; one that runs 5–6x slower and emits nothing is
  a hang whose block-buffered transcript was discarded. The ratio distinguishes
  them before any debugging starts.
- Two of the three biggest "Carrick gaps" found this session were **oracle**
  defects (`node-libuv`, `go-os`/`go-net`). Both presented as huge
  `docker = absent` row counts with an implausible performance ratio. That pair
  of symptoms should now be the first thing checked on any suite with a large
  absent count.
