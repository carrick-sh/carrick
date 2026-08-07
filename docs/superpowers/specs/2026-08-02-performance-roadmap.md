# Getting carrick correct and fast: the plan

**Status:** superseded 2026-08-05 for ranking and phase ordering by
[`2026-08-05-category-collapse-strategy-design.md`](2026-08-05-category-collapse-strategy-design.md).
The §5 appendix (rejected alternatives, DSR fallback playbook) and the tier-D
phase status records below remain authoritative; the workload-shape framing in
§0 stands.

> **2026-08-06:** the live-translation-arena line (the category-collapse
> spec's Move 1, the container-lifetime shared-translation successor to the
> §0 store history) is **closed negative**: policy-ON lost the cold go build
> ~36x and the 20-exec micro ~16%, the cause is structural (immutable shared
> code cannot be direct-linked; publication-window binding refuted), and the
> runtime was deleted in `1cb06de6`. The persistent unit store remains the
> shipped translation-sharing mechanism. Add the arena to the §5 rejected
> list in spirit: any successor must price the gateway round-trip tax first.

## 0. Where we actually are

Measured 2026-08-02, all in-guest wall with container lifecycle excluded,
carrick and Docker phases run serially:

| workload shape | carrick | docker | ratio |
|---|---|---|---|
| 20 execs of `compile -V` (no real work) | 2570 ms | 21 ms | **123x** |
| cold `go build` (~61 execs + work) | 19.4 s | 1.46 s | 13.3x |
| warm `go build` (~1-2 execs) | 785 ms | 39 ms | 19.4x |
| one exec + ~1 s real compute | 1163 ms | 163 ms | 7.3x |
| one exec + ~4x that work | 3669 ms | 735 ms | **5.0x** |

The spread is the whole story: **overhead is a function of workload SHAPE.**
Long-running processes are ~5x and falling as startup amortizes; process-churn
workloads are 13-123x. Quoting one number for "carrick's overhead" is
misleading, and the 2x bar has to be read per shape.

Two independent cost centres, each with its own fix:

**Per-exec cost** — 76% of a cold build, decomposed into three separable terms:
fork 4.25 ms, a fixed ~18 ms that exec adds regardless of guest size (carrick
self-re-execing its own ~30 MB signed binary and rebuilding dispatcher state),
and ~2.6 ms/MB of image materialization (52 ms of `compile`'s 125 ms).

**Steady-state execution** — emitted code is ~45% of build CPU, and 52.4% of
executed emitted instructions are the translator's own glue.

And one important negative result: **translation is not the bottleneck.**
Turning on shared translation removes 87% of translations (170,727 -> 22,895)
and buys 3.3% of wall, because its own load costs 14.8 ms per process. The
codegen campaign was ranking against the wrong term.

## 1. The two tracks, and why both are needed

**Track D — direct execution (tier D).** Same-ISA guests do not need
translating: only `svc`, x18 and `tpidr_el0` cannot execute on Darwin, and they
are 0.048% of a real binary's instructions. Tier D patches those and runs
everything else unmodified. Its measured cost model:

| | cost |
|---|---|
| unpatched guest instruction | native, by construction |
| `tpidr_el0` veneer | +0.28 ns per use |
| x18 veneer | +1.25 ns per use |
| syscall island | 7 ns |

This attacks the steady-state term, i.e. long-running workloads.

**Track E — exec cost.** Zygote, file-backed image mapping, cheap shared-unit
loading. This attacks the per-exec term, i.e. build and CI workloads.

They are not alternatives. A server execs once and runs for hours; a build
execs 61 times and computes little. Neither track helps the other's shape.

## 2. Phases

### Phase 1 — tier D generalization (correctness; unlocks everything)

Nothing real runs on tier D yet. In order:

1. **Exit path — DONE.** `GuestContext::pc` was informational because the
   island's return leg is a CONSTANT branch — which is exactly what makes it
   register-free. The landed shape is the gateway, not the scratch-slot
   indirect branch: the resume leg stays a constant branch (an indirect
   resume would need a register and every register is the guest's), and each
   island grew a LEAVE leg that restores the host stack discipline `enter`
   now captures and `ret`s to `enter`'s caller with the guest parked in its
   context. The bridge leaves on `Exit`/`Execve`/every unimplemented outcome.
   Design doc M1b has the red-first test names.
2. **Guest-leave contract — DONE.** The fixture bug that blocked the bridge
   for a full session (a guest returning to Rust with SP unbalanced) was a
   symptom of there being no stated contract. Now written down where the
   mechanism lives (`carrick_native_darwin::direct` module doc, the
   `direct_runner` bridge header, and the design doc §6): a tier-D guest
   leaves through the handler, never by returning.
3. **Dynamic linking — DONE at the loader/runner level.** `ld.so` maps as a
   second member image of a `DirectLoadGroup` (same scan/patch pipeline,
   slots per-load-group so TLS is coherent across images), the runner builds
   the exec stack (argv/envp/auxv with `AT_BASE`/`AT_ENTRY`/`AT_PHDR`,
   `AT_PAGESZ` = 16 KiB host page) reusing carrick-mem's serializer, and an
   identity memory model lowers anon mmap/munmap/mprotect/brk to host
   primitives. LIVE-VERIFIED: real glibc `ld-2.28.so` runs a dynamic
   `-nostdlib` PIE end to end on tier D — self-relocation, TLS init through
   the veneers into the group slot, handoff via `AT_ENTRY`, exit through the
   handler. The `/bin/dash` frontier is pinned by a test: ld.so finds the
   real `libc.so.6` through the dispatcher's VFS and stops, NAMED, at
   `mmap(PROT_EXEC, fd)` — which is item 5's scan+patch boundary (plus
   guest-fd → host-fd translation for the file-backed data mappings).
4. **Threads — DONE.** Slots are per-THREAD: every veneer and island
   resolves the executing thread's `DirectThreadSlots` through a proven
   Darwin TSD slot (`(TPIDRRO_EL0 & !7) + key*8`, a `pthread_key_create`
   key — the layout is PROVEN at first use on the creating thread and a
   fresh one, and a host that fails the proof refuses every image, named).
   The chain is 3 instructions where the old per-group veneers
   materialized a 4-instruction constant, but it trades an independent
   mov chain for a dependent load pair — per-use cost is UNMEASURED
   (this lane ran no paired benchmarks); treat the +0.28 ns tpidr figure
   as needing re-measurement, not as preserved. A thread-creating clone spawns a host thread whose
   guest enters through a runtime-emitted parked-entry stub (the island
   resume leg's exact register-transparent shape) with the full parent
   register file, x0 = 0, `CLONE_SETTLS` in its own TLS slot; `exit(2)`
   retires one thread (CLEARTID write + futex wake), and `FUTEX_WAIT`
   parks on the runner's shared table. LIVE-VERIFIED: real CPython 3.12
   WITHOUT `-I -S` runs `threading.Thread` end to end on tier D (clone3 →
   GIL futex traffic → join → ThreadExit), printing a value computed in
   the spawned thread; the raw-clone pthread_join-shaped fixture pins the
   mechanism. The identity memory model also grew a PROVEN `mremap`
   (tracked plain-anon-RW ranges only; everything else leaves named) —
   glibc realloc's mmapped-chunk path hits it on the threading run.
5. **Guest-created executable pages — DONE; fork/exec/signal orchestration
   remains.** `mmap(PROT_EXEC, fd)` routes through the same scan+patch
   pipeline with two lowerings (whole-span MAP_JIT windows, and MAP_FIXED
   plain-anon text with a separate `IslandArena` for modern glibc's
   map-over-reservation), `mprotect(PROT_EXEC)` is approved only inside
   still-patched mappings, and everything unproven fails closed to tier T.
   Live: real ld-2.28 maps real libc-2.28 through the window pipeline. The
   x18 veneers became sound for pc-relative and operand-attribute shapes on
   the way (two silent-GNU-hash-corruption bugs found by lldb on the live
   guest).

**Gate:** `/bin/dash -c 'echo hi'` — **MET** (real debian dash + ld.so +
libc on tier D, exit 0, `hi`). `python3 -I -S -c 'print(1)'` — **MET**
(real CPython 3.12, ~436 syscalls). `python3 -c 'threading.Thread(...)'`
— **MET multi-threaded** (item 4 landed: per-thread slots via the proven
TSD chain, full unrestricted CPython startup).
**Worth:** zero directly. Everything in Phase 2 depends on it.

### Phase 2 — tier D default-on (the compute win)

Flip eligible images to tier D with an exact `=0` hatch, per the
opt-out-not-opt-in rule.

**Status 2026-08-03 (lane K): WIRED, opt-in; default flip blocked on the
named gaps below.** Landed (`a59ad4a5`): the exec-time tier decision in the
shipped driver (launch AND `resume_guest_from_capsule`, so every exec'd
image is re-decided), fork (CoW host fork — identity memory makes the
kernel's copy the child's guest state), vfork (CoW + true parent
suspension; the CLONE_VM sharing half is a DOCUMENTED divergence —
posix_spawn's failed-exec errno write-back is lost), execve through the
existing capsule self-re-exec, blocking fd/proc/sleep waits on the
per-thread waiter, MAP_SHARED file mmaps as real host MAP_SHARED maps, and
kernel-verified guest-memory copies (`mach_vm_read_overwrite` — the
identity tier's copy_from_user). Live-verified through the shipped binary:
`sh -c 'echo hi'`, a three-generation vfork+exec chain, and the Go
toolchain refusing (ET_EXEC) onto tier T, all census-tagged
(`CARRICK_TIER_CENSUS`).

**Smoke evidence (2026-08-03, one sample each, sibling lane concurrent):**
control (tier D off, same binary) = **23/23 MATCH, no regressions**;
tier D forced on (`CARRICK_NATIVE_DIRECT=1`) = **19 gating failures**, all
attributable to named tier-D gaps, none to the DSR lane:

- **Async signal delivery + sigreturn (the big one).** `timeout(1)` parks
  in `sigsuspend` (leaves at `WaitOnSignals`) → every LTP case is Empty;
  Go test binaries are PIE and DO run tier D, then leave at
  `SignalThread` (SIGURG — Go's own async preemption) or MT fork.
  cpython-subprocess/-threading Empty for the same class.
- **Multithreaded fork** (`go-runtime`, cpython): needs the sibling
  quiesce the DSR lane has.
- **`BlockingRecordLock`** (cpython-fcntl): a small runner arm.
- **Undecodable word `0x38764d52`** (a `bad64` decode gap whose bits can
  name x18): refuses node's main binary at scan and CPython extension
  `.so`s at the `mmap(PROT_EXEC)` window → mid-run leaves. Decoding that
  one shape (or proving it x18-free) recovers node + cpython extensions.
- Node's failures under tier-D-on are its tier-D CHILDREN (node itself
  ran tier T); with children fixed node stays tier T until the word above
  is handled.

The four MATCHes under tier-D-on include cpython-glob/json/math running
ON tier D at full workload scale. Directional only (concurrent load, one
sample): cpython-math fell below the 10x outlier bar under tier D (15.31x
in the control) and glob read 13.30x vs 16.65x — consistent with the
estimate below, not yet a controlled measurement.

**Async signal delivery + sigreturn LANDED (2026-08-03, lane L,
`5b6a09d1`) — the #1 class above is closed.** Delivery reuses the one
signal semantics (`vcpu_loop::deliver_pending_signal` +
`carrick_hal::sigframe` through a tier-D trap adapter) at (a) every
syscall boundary and (b) interrupted blocking waits (EINTR/SA_RESTART),
with a `WaitOnSignals` arm, a per-group vDSO-shaped sigreturn trampoline,
and frame-exact restore through a leave-leg FP park + an extras-restoring
parked re-entry. Truly-async interruption of RUNNING guest code stays
fail-closed. Live through the shipped binary: `timeout 1 sleep 5` →
`rc=124`, the dash→timeout→sleep chain all-tier-D, cross-process SIGTERM
death included.

**Smoke re-run (2026-08-03, lane L, one sample, sibling lane
concurrent): control (tier D off) = 20/20 MATCH, no regressions; tier D
forced = 17 gating (was 19), node-app + node-v8 now MATCH.** The census
shows ZERO `WaitOnSignals`/`SignalThread` leaves; the four remaining
named leaves are exactly the other classes (`BlockingRecordLock`,
undecodable `0x38764d52` ×2, MT fork). The residue re-attributes:

- **LTP (10× Empty, unchanged verdicts, NEW cause):** with signals fixed
  the LTP chains run past `sigsuspend` and die at a PRE-EXISTING,
  image-content-specific tier-D crash — deterministic SIGSEGV at
  interp+0x70ae4, fault addr 0x13, x18=0 — reproduced on `ubuntu:24.04`
  `sh -c 'echo hi'` at 1a348627, f4713e5c AND with lane L's change
  (`debian:stable` works). Signal work unmasked it; it smells like a
  missed x18-consuming shape in that image's ld.so/libc slipping the
  scan. It is the LTP class's new blocker.
- **Go PIE tests (4× CRASH):** previously left NAMED at `SignalThread`
  with zero tests; now run REAL test bodies (go-context 24/24, go-time
  10/10 partials) into MT+SIGURG territory and die UNNAMED (host crashes,
  e.g. pc=0x81 wild branch, 6-7 threads live). Newly-reached ground, not
  attributed; needs a core/lldb pass before the flip.
- **cpython-subprocess/-threading (Empty):** MT fork (no sibling
  quiesce) — the already-named class.

**Flip verdict: still blocked**, now on (1) the image-specific
scan/veneer crash, (2) MT-fork quiesce, (3) the unattributed Go
MT+SIGURG crash tail, (4) `BlockingRecordLock` + the `0x38764d52`
decode gap — signals are no longer on the list.

**Gate:** conformance smoke, plus the outlier ratios the smoke already prints —
node 22-23x and cpython 14-17x today, both PIE and both dominated by emitted
code.
**Worth, ESTIMATED not measured:** the ~45% emitted-code CPU share collapses
toward guest-native. On the long-running shape that should move 5.0x to roughly
**3.3x**. This is the number to verify first, because the whole architecture
argument rests on it.

### Phase 3 — exec cost (the build win)

Three sized items, largest first:

| item | worth |
|---|---|
| file-backed image mapping (kill ~2.6 ms/MB materialization) | ~1.5-2 s |
| zygote / no self-re-exec (kill the fixed ~18 ms) | ~1.1 s |
| cheap shared-unit load (MAP_JIT copy instead of signed dylib + `dlopen`; publishing currently shells out to `codesign` twice) | ~0.8 s |

> **Correction (2026-08-03, exec lane) — the "fixed ~18 ms" item is measured
> at 8.5-9.0 ms and is mostly Darwin's exec floor.** Untraced decomposition
> ([2026-08-03 perf-results](../../perf-results/2026-08-03-native-exec-fixed-cost-decomposition.md)):
> 5.3 ms is kernel execve + dyld (of which ~1.8 ms is the floor for ANY
> binary, ~1.6 ms teardown of the dying guest's resident pages, ~0.9 ms
> CF/HVF/dtrace initializers, ~0.8 ms carrick-binary premium) and only
> ~3.2 ms is carrick's own code, already spread thin. The zygote shape
> cannot exist under the standing constraints: the libdispatch finding
> (2026-07-13 self-reexec design) forces a real exec before the new image may
> create threads, and PID preservation forbids handing off to a pooled
> process. What WAS in this item and landed: the prepared-artifact payload
> digest was ~1.5-2 ms/MB per exec (hashing image bytes twice), i.e. a
> per-MB term misfiled as fixed — now metadata-only by default
> (`CARRICK_EXEC_FAST=0` hatch), which A/B suggests is worth more than this
> item's original ~1.1 s estimate on the cold build. The residual fixed chain
> (~8.5 ms × 61 execs ≈ 0.5 s) is near its floor; chained fixups, DOF
> stripping, and symbol stripping were each measured at ~0.1 ms or less and
> rejected.

**Gate:** paired A/B on the cold `go build` with arms alternating, plus the
20-exec microbenchmark. Both, because they have disagreed before.
**Worth:** ~3.5 s of a 10.4 s build, i.e. build ~6.9 s ≈ **3.4x** Docker.

### Phase 4 — the kernel and memory residual

After Phases 2-3 the remaining excess is kernel time (32.4% of build CPU) and
carrick's host userspace. Known levers, already scoped elsewhere:

- fs endgame Lever B (serve reads from the shared cache tree, copy up on write):
  fs-walk total wall 3.8x -> ~1.8x;
- per-guest-page cost on Darwin — translate the guest's INTENT, using Go's
  dual-port allocator as the oracle (`MADV_FREE_REUSABLE`/`REUSE` rather than
  re-issuing Linux's `mprotect` idiom);
- the `HostAliasTransactions` exclusive gate: `zero_backing` runs while holding
  a process-global lock taken by every memory syscall (`dispatch/mod.rs:2434`),
  so 10 guest threads in one process pay 9.74 µs/fault where the same
  parallelism across 10 processes pays 6.42 µs, with 15x the involuntary
  context switches (controlled topology sweep,
  [2026-08-01 audit §4](../../perf-results/2026-08-01-native-wall-audit-and-fault-cost.md)).
  The lever is per-region locking, or not holding the gate across
  `zero_backing` at all;
- the syscall floor (0.29 µs measured) against Docker's.

**Gate:** re-measure the workload-shape table in section 0. That table is the
scoreboard.

## 3. What would invalidate this plan

- **Phase 2 comes in well under its estimate.** If removing the emitted-code
  penalty does not move the long-running shape close to 3.3x, then steady-state
  cost is dominated by something else (most likely kernel/memory), and Phase 4
  should be promoted ahead of Phase 3.
- **Tier D cannot hold a real workload.** RWX self-modifying guests and
  thread-heavy TLS are the two shapes most likely to force tier T; if cpython
  or node ends up on tier T, Phase 2's value evaporates and Track E becomes the
  whole plan.
- **The undecodable tail bites.** 81 words in 5.2M are undecodable today, but a
  different binary corpus (musl, Rust static binaries, JITs) may have more, and
  the scan fails closed.

## 4. The honest ceiling

Even with every phase landed, the 2x bar is per-shape, not global. Long-running
PIE workloads are the ones that can plausibly reach it: compute goes to roughly
native and the residual is syscalls plus memory management. Build- and
CI-shaped workloads carry an irreducible per-process cost that Docker pays once
at container start and carrick pays per exec — Phase 3 shrinks it, and a zygote
shrinks it further, but 61 process creations will not be free.

State the shape with the number, always.

## 5. Appendix — rejected alternatives, and the DSR fallback playbook

Folded from a superseded draft plan so nobody re-litigates or re-loses these.

### Rejected — measured worse or structurally impossible on Darwin

- **Single-instruction ORR-encodable bias** (compact biased addressing): tried
  as H008 Spike 1, measured **3.76% slower** (lost 5 of 6 paired runs) and
  carries an unfixed host-address leak. `APERTURE_DISJOINT_ORR_BIAS` survives
  for tests only (`crates/carrick-dsr/src/address.rs:25-35`).
- **General `GuestVA == HostVA` identity mapping**: Darwin's `__PAGEZERO`
  occupies 0–4 GiB (`NATIVE_DARWIN_HARD_PAGEZERO_END`), and static Linux
  binaries load at `0x400000`. Direct mode already exists for PIE guests whose
  regions all sit above 4 GiB (`address.rs:507`); the general case is
  structurally excluded.
- **`DsrContext` in `TPIDR_EL0` to free x28**: macOS owns `TPIDR_EL0`
  (pthread_self, errno, host TLS) and the guest needs it for Linux TLS;
  `TPIDRRO_EL0` is read-only from EL0. There is no spare AArch64 system
  register, and the signal handler finds `DsrContext` via x28 in `ucontext`.
- **`mprotect`-based W^X invalidation of the JIT cache**: incompatible with
  `MAP_JIT` / per-thread `pthread_jit_write_protect_np`. The generation guard
  also covers guest `mmap`/`munmap` replacing code pages and shared-unit
  invalidation across fork/exec — not just self-modifying code — so page
  protection cannot replace it.

### DSR fallback playbook — only if tier D cannot hold a workload

If the §3 invalidation fires and cpython/node land on tier T, the emitted-code
levers below are the plan for the residue. All ESTIMATED, none measured:

- **Aperture bounds check → guard pages**: drop the per-access `lsr`/`cbz`
  pair by extending the existing PROT_NONE guard windows to the whole
  out-of-aperture range; the SIGSEGV path already lowers to
  `NativeDsrExit::Fault`.
- **Bias preloaded in a reserved register** instead of per-access
  `movz`/`movk` materialization — consistent with the 2026-08-02 finding that
  ctx traffic is borrow save/restore (x17 ~21%), not guest-register spilling.
- **Scratch spill folding** across consecutive memory ops in a block.
- **Monomorphic inline cache + shadow return stack** for indirect exits: the
  ~35-40-instruction inline resolver becomes a ~3-instruction hit path.

### Open research question

Can Hypervisor.framework provide **stage-2 address translation without a
vCPU**? Hardware guest-PA→host-PA mapping would eliminate the bias entirely
and make every guest `ldr`/`str` a single host instruction. Unclear whether
HVF exposes stage-2 tables independently of a virtual CPU; nobody has checked.
