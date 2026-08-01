# Native/aarch64: the current wall number, and what the sys term is made of (2026-08-01)

Two things this records. First, a **current wall measurement at HEAD** — the
tree's newest wall figure was 187 commits stale, because the CPU campaign
switched its primary metric to CPU-seconds on 2026-07-30 and stopped measuring
wall. Second, a **decomposition of the 28%-of-CPU sys term**, which settles the
Workstream C question the campaign parked.

Host: macOS 27 / t8132 / Apple Silicon, 10 logical CPUs. Binary built and signed
at `86a8959e` (clean tree). Workload is the reference cold-`GOCACHE` `go build`
of a hello-world against
`localhost:5005/carrick-go-conformance:1.24`, `--exec-backend native`.

---

## 1 — Current wall, and the decomposition of the gap

`scripts/perf/native_go_build.py --engine both --samples 5`, strictly serial
phases:

| metric | carrick | docker (native arm64) | ratio |
|---|---|---|---|
| workload wall (median) | **11,728 ms** | 810 ms | **14.48x** |
| total wall (median) | 13,598 ms | 969 ms | 14.03x |
| guest user CPU | 20.4 s | 1.95 s | 10.5x |
| guest sys CPU | 7.9 s | 0.15 s | **53x** |
| guest total CPU | 28.3 s | 2.10 s | 13.5x |
| parallelism (CPU/wall) | 2.42 | 2.63 | 0.92 |
| host page reclaims | 2.29 M | — | — |

Carrick samples were tight: workload 11,474/11,498/11,728/11,767/11,815 ms.

CPU is in-guest POSIX `times` (children user/sys), appended to the same guest
script on both engines so the two are measured identically. Validated against
host-side `/usr/bin/time -l` on the carrick arm: guest-reported user 20.4 s
against host 20.4 s. Host sys reads ~1.6 s higher than guest sys, which is
carrick's own container setup outside the guest window — expected.

**The gap is ~100% CPU amplification. Parallelism is not a factor:** 13.5x CPU
against 0.92x parallelism reproduces the 14.6x wall almost exactly. There is no
scheduling or blocking story to chase; Docker is not using the other 8 cores
either.

### Three hypotheses refuted

- **Parallelism deficit** — refuted. Both engines run at ~2.5x on a 10-CPU host.
- **4K-guest-on-16K-host page granule** — refuted. `Auto` already resolves to
  16k geometry; explicit `CARRICK_NATIVE_PAGE_PROFILE=native16k` produces
  fault counts identical to the default (2,293,530 / 2,296,328 against
  2,296,632 / 2,298,099) and the same CPU split.
- **Shared translation helping now that the edge trampoline landed** — refuted.
  `SHARED_TRANSLATION=1 DIRECT_BINDINGS=1` at HEAD measures 12,023 / 12,290 ms
  workload against 11,606-11,781 ms default: still a loss, same sign as the
  campaign's +6.76% CPU result.

### The retained codegen switches are worth more than the campaign credited

Same-binary A/B, 3 samples per arm, non-overlapping populations:

| arm | workload wall | guest user | guest sys |
|---|---|---|---|
| default | 11,606-11,775 ms | 20.4 s | 7.9 s |
| `LEAN_GUARD=0 RESERVED_SCRATCH=0 SUPERBLOCK=off` | 15,579-15,764 ms | 29.8 s | 9.1 s |

Together the three switches buy **25% of wall and 31% of user CPU**. The
campaign's "codegen moves nothing" conclusion is about *marginal further
emission* tuning (`62f37f2d`: -9.3% emitted bytes moved CPU by zero), and that
narrower claim stands. The codegen term as a whole is not exhausted.

### Caveat on the -36% against W0

Frozen `W0` was 18,321 ms workload / 21.76x at `5aecc7fb`; HEAD reads
11,728 ms / 14.48x. That is **not a contemporaneous comparison** — different
day, different load, and this project's own rule is that isolated baseline drift
is not a result. Treat the -36% as provisional until a paired rebuild of
`5aecc7fb` measures it against HEAD in one session.

---

## 2 — The sys term: instrumentation reality first

Three probe points that plausible plans are built on **do not work on this
host**, each verified live:

- **`fbt::vm_fault:entry` is listed by `dtrace -l` but never fires.** Zero hits
  against 2,253,394 `as_fault`s in the same run. The actual stack at `as_fault`,
  captured with `stack()`, is
  `fleh_synchronous -> sleh_synchronous -> handle_user_abort`.
  **Corrected explanation:** the faults DO reach the fault handler — FBT is
  simply blind to it. The exported `_vm_fault` is an alias of
  `_vm_fault_external` (`0xfffffe000742b0b8`), while the trap path calls the
  **local** `_vm_fault_internal` (`0xfffffe00074210f8`, nm type `s`), and FBT
  exposes zero local symbols on this build. Verified against the KDK dSYM;
  `dtrace -l -P fbt` offers only `vm_fault` and `vm_fault_external`. For a
  translation fault — which every zfod first-touch is — `arm_fast_fault` is
  skipped and the fault goes straight into `vm_fault_internal`.
- **Kernel frames can be symbolizer aliases.** `IORWLockUnlock` and
  `lck_rw_done` are the SAME address (`0xfffffe0007377f88`); likewise
  `IORWLockRead`/`lck_rw_lock_shared` and `IOLockLock`/`lck_mtx_lock`. The
  "IOKit" frame reported in section 4 is rw-lock release traffic, not IOKit.
- **`handle_user_abort`, `arm_fast_fault` and `vm_fault_internal` are not
  FBT-instrumentable** — trap-context functions are blacklisted. There is no
  entry/return pair to time, so fault cost must be **sampled, not bracketed**.
- **`sched:::preempt` does not exist on macOS.** The provider offers only
  `on-cpu`, `off-cpu`, `sleep`, `wakeup`, `iwakeup`.

Also worth correcting the record: the campaign's stated blocker — "`vminfo`
carries no fault address, which is why every probe so far has been indirect" —
was already false. `vminfo:::as_fault` arg2 is the exact 16 KiB host-page base,
and `scripts/dtrace/native-fault-attribution.d` says so in its own header. That
instrument existed; it had simply never been run.

SIP on this box reports `DTrace Restrictions: disabled`, so fbt is available in
general — the blockers above are about these specific functions, not policy.

## 3 — Fault composition

From `scripts/dtrace/native-fault-cost.d` at GOMAXPROCS=1:

| kind | count | share |
|---|---|---|
| `as_fault` | 2,129,690 | — |
| `zfod` (first touch of anon memory) | 1,780,734 | **83.6%** |
| `cow_fault` | 96,905 | 4.6% |

Nearly **half of all faults are raised from three user PCs**. Resolved against
`vmmap` text ranges for this boot's dyld shared cache:

| PC | faults | library |
|---|---|---|
| `0x199f4bdb8` | 481,330 | `libsystem_platform` (`_platform_memmove`/`memset`) |
| `0x199f4be14` | 319,067 | `libsystem_platform` |
| `0x199d5e0c4` | 316,174 | `libsystem_malloc` |

So the mass is carrick **populating guest address space with host memcpy/memset
onto freshly-mapped anonymous pages**, re-paid per forked guest process (~50 per
build). This is the hypothesis already written into
`native-fault-attribution.d`'s header — now measured rather than asserted.

## 4 — Fault cost scales with guest concurrency (mechanism NOT established)

> **Correction, same day.** This section originally read as evidence of
> fault-path serialization. That reading is **confounded and should not be
> relied on.** `go build` takes `-p` from `GOMAXPROCS`, so sweeping 1 → 10
> changed three things at once: threads per guest process, the number of
> concurrent guest processes, AND the core class the work lands on — this host
> is **4 Performance + 6 Efficiency cores** (`hw.perflevel0.logicalcpu=4`,
> `hw.perflevel1.logicalcpu=6`), not 10 homogeneous CPUs. A run that fits on
> P-cores at `-p 1` and spills onto six E-cores at `-p 10` plausibly explains a
> ~2x per-fault cost with **zero contention**. The numbers below are real; the
> serialization *interpretation* of them is not supported.
>
> **Second correction, same day: the serialization is REAL — the lock is
> CARRICK'S OWN.** A controlled topology sweep (which the confounded GOMAXPROCS
> sweep below could not do) separates the variables: arm B = 10 threads in 1
> process costs **9.74 us/fault**; arm C = 10 processes x 1 thread costs
> **6.42 us/fault**, with 15x the involuntary context switches in arm B
> (1,599,519 vs 107,569). The dominant lock is a single zalloc'd instance at
> 180.4 M ticks (7.5 s) growing **146x** from GMP 1->10, identified by three
> independent instruments as the **pthread condvar ksyn workqueue lock**.
> `vm_page_locks` grows only 2.5-4.9x and is 51x smaller.
>
> Root cause in carrick code: `zero_backing` runs while holding
> **`HostAliasTransactions`, a process-global EXCLUSIVE gate** taken by every
> memory syscall (`dispatch/mod.rs:2434`, entered from mmap/munmap/mprotect/brk/
> madvise/mremap/msync/mlock/mincore), so siblings block on a parking_lot
> Condvar -> `psynch_cvwait`. Cross-process is cheap precisely because each
> process has its own gate. So the P/E-core confound below is real but is NOT
> the explanation; the topology sweep controls for it.
>
> XNU source refutes only the specific "one per-task KERNEL lock" mechanism: large
> anonymous mappings are split into `ANON_CHUNK_SIZE` = 128 MiB pieces, each
> with its own `vm_object` and its own `lck_rw_t`, and that lock is an rw-lock
> so concurrent readers do not serialize. The one genuinely shared structure,
> `vm_page_bucket_locks[]` reached from `vm_page_lookup`, is **machine-global**
> and hashed by (object, offset) — shared with every process on the box, so no
> intra-task restructuring touches it. A static caller census of
> `hw_lock_lock_contended` is dominated by scheduler / IPC-importance /
> turnstile / kqueue / `_ull_get` (ulock) call sites, not VM-fault functions,
> which reads as park/wake churn rather than fault-path contention.
>
> Settling it needs a three-arm experiment that separates the variables:
> one process × 10 threads, vs 10 processes × 1 thread, vs core-class pinned.

Sweeping guest threads at fixed total work:

| | GOMAXPROCS=1 | GOMAXPROCS=10 | ratio |
|---|---|---|---|
| `as_fault` | 2,129,690 | 2,431,217 | 1.14x |
| kernel samples | 9,654 | 16,758 | 1.74x |
| `sched:::off-cpu` | 99,070 | 764,423 | 7.7x |
| `sched:::sleep` | 96,385 | 465,289 | 4.8x |
| **off-cpu minus sleep** | **2,685** | **299,134** | **111x** |
| per-fault sys cost (untraced) | 1.81 us | 3.84 us | 2.1x |

Kernel time grows 1.74x while fault count grows only 1.14x, and the excess is
threads going off-CPU **without sleeping** — preempted, or spinning on a lock.

The kernel frame names agree. Present in the top-25 at GOMAXPROCS=10 and absent
at GOMAXPROCS=1: `hw_lock_lock_contended`, `thread_block_reason`,
`assert_wait_deadline_with_leeway`, `vm_page_lookup`, `IORWLockUnlock`
(lock/block frames go 1 -> 6). At GOMAXPROCS=1 the top frames are ambient noise
— apfs, EndpointSecurity, sandbox.

The thread model is confirmed from code — guest threads really are host pthreads
in one Darwin task (`native_darwin.rs:4448 spawn_clone_thread`), while every
non-thread clone is a real `libc::fork()` and therefore a new task
(`native_darwin.rs:6531`). But per the correction above, that model does NOT
imply the observed cost, and the per-task-lock mechanism is refuted.

### Both levers are real, and they converge on one carrick function

> **Superseded 2026-08-01 by the serialized-measurement workflow.** An earlier
> revision of this section claimed (a) guest `execve` maps images as fresh
> anonymous memory because `map_prepared_for_plan` is `dead_code`, and (b) fault
> COST is not independently actionable. **Both were wrong**, and the corrections
> matter more than the original claims:
>
> - `map_prepared_for_plan` (`mapped_memory.rs:1018`) is a **test-only helper**.
>   The live path is `map_prepared_region_extent` (`:4364`), and guest image
>   pages are **already file-backed and already shared**: 709
>   `MAP_PRIVATE|MAP_FIXED` file mmaps (~6 per exec, one per `PT_LOAD`) against a
>   guest-image zfod count of **11**. COW/file-backed image mapping is DONE, not
>   a lever. Do not re-implement it.
> - Fault COST is real, but the contended lock is **carrick's own userspace
>   gate**, not any Darwin VM lock. See §4.

**The fault mass is carrick's own Rust heap, not `zero_backing`.** Decoding the
capA bucket histogram against the measured 0x80_0000_0000 bias, and probing
where Darwin actually places allocations on this host, closes the accounting to
~99.5%:

| source | zfod | share |
|---|---|---|
| carrick's own Rust heap >= ~128 KiB (libmalloc large zone, `0x7x_xxxx_xxxx`) | 1,254,000 | **66.7%** (~20.5 GB) |
| guest mmap arena (`zero_backing`) | 561,394 | 29.9% (~9.2 GB) |
| remainder | ~62,000 | 3.4% |

The large zone allocates via `mach_vm_allocate`, **not** `mmap` — which is why
one traced build shows only 2,172 `mmap` calls against 1.88 M zfod, and why
every syscall-level instrument aimed at this missed two thirds of it.

Ruled out with measurements (do not re-litigate): `MADV_WILLNEED` as a populate
primitive (identical fault count to memset, 262,315 vs 262,315, slightly slower);
`mlock`/`vm_map_wire` (slower than memset at both thread counts); `MAP_POPULATE`
and superpages (absent from the SDK / documented unused); file-backed
`MAP_PRIVATE` as a general fault-count lever (at procs=50 mapping the same bytes
it takes MORE minor faults than anon).

---

## Method caveats — read before citing any number here

- **The fault instrument perturbs.** The `as_fault` probe fires ~2.1 M times,
  pushing sys from 3.92 s to 7.78 s at GOMAXPROCS=1. Absolute traced sys
  numbers are unusable. Only ratios between two arms carrying the same
  instrument are valid, which is how section 4 is constructed.
- **`native-fault-cost.d` scopes by `execname == "carrick"`.** Per the
  2026-07-29 evidence doc, `execname` is the binary basename and silently tracks
  nothing the moment two arms are built under different names. That is safe for
  the same-binary A/B here, and a trap for any future cross-binary screen —
  such a screen must switch to the `carrick*:::dsr-cache-*` lifecycle probes
  under `dtrace -Z`.
- Section 1 ran at 1-minute load ~6 on a 10-CPU host; section 4's arms ran
  serially, never concurrently with each other or with Docker.
- Nothing here is a promotion artifact. Section 1 is a fresh measurement with no
  paired control against a rebuilt historical binary; sections 3 and 4 are
  directional evidence from a perturbing instrument.
