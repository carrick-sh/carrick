# Native-lane performance: state of play

**Date:** 2026-08-03 · **Branch:** `main` @ `fd547039` · **Scope:** Darwin/aarch64
native backend (`--exec-backend native`, the shipped default). VMM is explicitly
NOT the target: one process per VM against a ~127-VM macOS ceiling makes it a
dead end for build-shaped workloads.

## The goal

**Cold `go build` within 2-3x of native-arm64 Docker.** Carrick's premise is
running unmodified Linux binaries at host-native cost, so this number is the
product, not a metric about it.

The plan is [`docs/superpowers/specs/2026-08-02-performance-roadmap.md`](docs/superpowers/specs/2026-08-02-performance-roadmap.md).
Read it first; it carries the phase structure, the invalidation conditions, and
an appendix of rejected alternatives so nobody re-litigates them.

## Where we are

Measured 2026-08-03, quiet box, serial carrick-then-docker phases, in-guest wall,
shipped defaults ([`docs/perf-results/2026-08-03-wave3-scoreboard.md`](docs/perf-results/2026-08-03-wave3-scoreboard.md)):

| workload shape | carrick | docker | ratio | 08-02 start |
|---|---|---|---|---|
| cold `go build` | 9613 ms | 805 ms | **11.9x** | 13.3x |
| compute (awk 8M) | 365 ms | 111 ms | **3.3x** | 3.8x |
| fs-walk | 252 ms | 13 ms | 19.4x | ~18-20x |
| startup (2 execs) | 37 ms | ~0 | — | 42 ms |

**That table predates the last two merges** (store v5 wire, tier-D signals).
Re-measuring is step 1 below.

**Overhead is a function of workload SHAPE** — quote the shape with the number,
always. The build is not slow because it is serialized: it runs at Docker-equal
core width (~2.5) and burns **25.6 s CPU against Docker's 2.1 s**, i.e. ~12x
amplification ([`2026-08-03-build-serialization-attribution.md`](docs/perf-results/2026-08-03-build-serialization-attribution.md)).
That CPU decomposes: **translate 14.6 s** (1.74 M blocks — every process
retranslates its image), **gateway 7.1 s** (3.65 M entries, roughly half
cold-cache branch resolves), **translated_run 7.9 s** (only ~2.1 s of it useful
work), dispatch 2.6 s. `HostAliasTransactions`, fs amplification, and futex
lowering are all REFUTED for this shape — do not go back to them for the build.

## What landed (2026-08-02/03, six waves, all merged with `just ci` green)

**Exec pipeline.** Payload SHA-256 removed from the default artifact digest
(`CARRICK_EXEC_FAST=0` hatch); eligible PT_LOADs map `MAP_PRIVATE` from the
executable's own host file (`CARRICK_EXEC_FILE_BACKED=0`); execve probes read 1
and 256 bytes instead of walking the whole image twice. The per-exec chain is
~20 ms, of which ~5.3 ms is Darwin's own execve+dyld floor. The roadmap's "fixed
~18 ms" item was mis-measured and is corrected in place
([`2026-08-03-native-exec-fixed-cost-decomposition.md`](docs/perf-results/2026-08-03-native-exec-fixed-cost-decomposition.md)):
the zygote shape cannot exist under the libdispatch and PID-preservation
constraints, and the real win there was a per-MB term misfiled as fixed.

**Tier D (direct execution).** From "a guest could only leave by calling exit"
to: exit path plus a written guest-leave contract, dynamic linking (real glibc
`ld.so`), guest-created executable pages (`mmap(PROT_EXEC, fd)` scan+patch, two
lowerings), per-thread TLS via a **runtime-proven** Darwin TSD chain, wiring
into the shipped driver with fork/vfork/execve and real fd passthrough, and
async signal delivery + `rt_sigreturn`. Live-verified: `/bin/dash -c 'echo hi'`,
real CPython `print(1)`, real CPython `threading.Thread`, `timeout 1 sleep 5` →
rc=124 all-tier-D. Everything unproven fails closed with a named reason.
Reachable behind `CARRICK_NATIVE_DIRECT=1`; **default OFF** (blockers below).

**Persistent translation store.** Per-host, keyed by image identity, single
publisher elected via non-blocking host locks, LRU-pruned, crash-safe, corrupt
store fails closed to local translation. Template emission reached **parity with
native emission** (proven by disassembly plus a word-identity test) once the
regression was root-caused to block-ENTRY shape — an 11-12 instruction
`BindingIndex` guard versus a 3-instruction trusted entry, NOT the recorded
fusion-loss suspect. The v5 wire splits each block into a hot blob (decoded at
first lookup) and a cold blob (pc-map/recovery, ~98% of records, left undecoded
in the mmap until a fault needs it). Reachable behind
`CARRICK_DSR_PERSISTENT_STORE=1`; **default OFF pending confirmation** (below).
Roughly 22k lines of superseded machinery (the Mach-O emitter, the
codesign+dlopen transport, `BindingIndex`, cell sidecars, edge trampolines, V3
metadata) were DELETED, not parked behind flags.

**Memory.** Protection bookkeeping went from one BTreeMap entry per 16 KiB page
(~295k entries per Go process, re-consulted on every dispatch write) to
coalesced intervals — anon reservations are O(1), and the fixture that pinned it
went 1.66 s → <10 ms. Identical host syscall sequence, identical guest ABI.

## What's next

### 1. Re-measure, then land the two default flips (local work, no fan-out)
`just ci` on `fd547039`, `just build`, then the quiet-box round: awk-8M compute
ABBA, 20-exec `compile -V` micro, cold build, and `workload-spread.sh 3`. Arms
must be defined by the **host-env** knobs, counterbalanced, n≥8.

- **`CARRICK_DSR_PERSISTENT_STORE`** — the re-flip condition ("install cheaper
  than the retranslation it avoids, and no build regression") is *measured as
  met* under sibling load: micro −26%, build −9%, translate phase 50→18 ms per
  exec ([`2026-08-03-store-v5-lazy-hotcold-wire.md`](docs/perf-results/2026-08-03-store-v5-lazy-hotcold-wire.md)).
  One quiet-box confirmation and it flips ON. This is the 14.6 s retranslation
  lever — the single largest term in the build.
- **`CARRICK_NATIVE_DIRECT`** — stays OFF until the blockers below clear.

### 2. Tier D flip blockers, ranked (tasks #14, #15)
1. **The ubuntu:24.04 tier-D SIGSEGV.** Deterministic, image-content-specific,
   and reproduces on three commits including ones predating the signal lane — it
   was masked by the signal gap, not caused by it. Repro:
   `CARRICK_NATIVE_DIRECT=1 carrick run --exec-backend native --native-page-profile native16k ubuntu:24.04 /bin/sh -c 'echo hi'`
   → exit 139, pc `interp+0x70ae4`, fault addr `0x13`, x18=0. `debian:stable`
   works; DSR works. Suspect: an x18-consuming shape slipping the scan in that
   image's ld.so/libc. **This is the LTP-class blocker.**
2. **MT-fork sibling quiesce** — cpython-subprocess/threading, go.
3. **The Go MT+SIGURG crash tail.** Go PIE tests now run real bodies
   (go-context 24/24 subtests) and then die in unnamed host crashes under
   multi-threaded load (wild branch pc=0x81, 6-7 live threads). Newly-reached
   ground; needs a core + lldb pass. Note this is a *diagnosability* regression
   (named leave → crash) that the flip decision must weigh.
4. **Undecodable word `0x38764d52`** — a bad64 decode gap blocking node itself
   and two CPython extension `.so` windows.
5. `BlockingRecordLock` arm (cpython-fcntl).

Smoke status: control lane clean, no regressions. Tier-D-forced: **17 gating**
(down from 19 — node-app and node-v8 flipped to MATCH once signals landed), with
zero `WaitOnSignals`/`SignalThread` leaves remaining. cpython-glob/json/math run
on tier D at full workload scale, and directionally cpython-math fell from 15.3x
to below the 10x outlier bar — the Phase 2 estimate showing up in real data.

### 3. After the flips
Re-run the shape table; the build should move materially on the store flip
alone. Then the remaining sized levers: gateway round-trips (~2.3 s, largely
subsumed by a warm store), emitted-code overhead via tier D on the serial
compile-runtime path (~1.7-2.5 s), a guest-memory copy fast path (tier D
currently pays a mach trap per copy), CPU exposure (0.3-0.4 s measured), and
driver setup fs + clonefile seed (~0.6 s). fs-walk at 19.4x is untouched and is
the other big shape.

## Discipline that earned its keep (do not relearn these)

- **The perf knobs are HOST env vars.** Passing them through `carrick run -e`
  makes both ABBA arms identical — an entire measurement round was invalidated
  this way and read as "no effect".
- **Rebuild and prove the binary.** `just build` after runtime changes, then
  `strings -a target/release/carrick | grep <knob>`. A second round was
  invalidated by measuring a pre-merge binary, and it was caught only because
  the numbers contradicted mechanism-level counters.
- **Verify every merge with the FULL serial suite, twice.** Two defects reached
  the merge gate that the lanes' own green runs missed: a cross-lane SIGTRAP
  (which turned out to be a fork-poisoned libdispatch semaphore masking a real
  panic) and a suite-order failure from tier D hint cursors colliding with
  `BIAS_CANDIDATES` to the digit.
- **Attribute before fixing.** Three investigations each redirected the campaign
  off a wrong target: the build is amplified, not serialized; the template
  regression is entry shape, not fusion; lazy install alone could not win
  because `compile` touches ~99% of its unit's blocks.
- Counter and mechanism evidence beat wall clock under load. Wall numbers taken
  with siblings running are "suggests", never "confirmed".

## Constraint at handoff

The monthly API spend limit is reached, so **no subagent fan-out can run** until
it resets or is raised. Everything in step 1 is local work and can proceed
without it. Open tasks: #7 tier D Phase 2, #8 Phase 4 levers, #9 the
`NativeMemoryHandle` RwLock wedge soak, #14 the ubuntu crash, #15 the remaining
tier D flip blockers.
