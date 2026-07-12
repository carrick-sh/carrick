# DSR profile-driven performance design

**Date:** 2026-07-12  
**Status:** approved for direct planning and execution  
**Scope:** Darwin-native AArch64 DSR only

## Purpose

Turn the durable DSR profiles into an ordered optimization program. Every
change must remove a measured cost, preserve Linux-visible behavior, and carry
before/after evidence. This is not a general native-backend cleanup and it does
not preserve or modify the legacy `brk` executor.

The program optimizes one attributable bottleneck at a time. After every
accepted change, the relevant profile becomes the new baseline before the next
area begins. A plausible implementation without a measured workload win is not
an accepted performance change.

## Fixed decisions

- Performance is the priority; structural DSR changes are allowed.
- The per-thread indirect target cache may grow from 32 KiB to at most 256 KiB.
- Carrick's Linux oracle remains the semantic authority. No Linux kernel or
  other GPL implementation source is consulted.
- Fork correctness and Go and Rust static/PIE workloads remain required end
  states, even when the first performance proof uses V8 or a focused probe.
- Existing Rust ecosystem components are preferred for statistics, collections,
  synchronization, and signal handling. Carrick-specific code is reserved for
  the gateway ABI, typed guest/cache addresses, generation safety, and emitted
  AArch64 lookup sequences.
- Correctness gates do not move to make a performance result pass. Performance
  thresholds may be declared inconclusive, but not retroactively weakened.

## Measured starting point

These are diagnostic measurements on the current branch, not projections and
not universal claims about every workload.

### Normal translated loop

The broad profile reconciled 45,427 gateway slices:

| Phase | Count | Total | Mean | Observation |
|---|---:|---:|---:|---|
| prepare | 45,427 | 66.79 ms | 1.47 us | largest DSR-side aggregate |
| run | 45,427 | 57.95 ms | 1.28 us | translated gateway entry/exit |
| dispatcher | 44,047 | 40.57 ms | 0.92 us | shared syscall layer, not initially a DSR target |
| resolve | 1,352 | 14.46 ms | 10.70 us | miss path; includes translation work |
| translate | 1,372 | 10.52 ms | 7.67 us | nested in prepare/resolve paths |

Prepare is dominated by 45,140 `BlockIndexHit` outcomes consuming 66.08 ms.
Only 264 preparations use `ResumeEntryHit`. This makes repeated process-wide
block lookup the first normal-loop target.

The absolute DTrace durations include enabled-probe cost. Counts, phase
relationships, and before/after runs under the same profile are authoritative;
the absolute nanoseconds are not treated as untraced runtime latency.

### Indirect-heavy V8

The indirect profile captured 416,997 successful resolver exits, 10,159 source
sites, 44,826 source-target pairs, and 41,152 distinct missed targets. The
current cache is 1,024 direct-mapped 32-byte entries indexed only by guest-PC
bits 2 through 11.

All 1,024 buckets saw at least ten distinct missed targets. The two hottest
targets both map to bucket 154 and each generated about 10.4k resolver exits.
The top 100 source sites account for 161,932 exits (38.8%); the top 1,000 account
for 353,986 (84.9%). This is a broad collision problem with several especially
hot aliases, not a single-site anomaly.

The profile sees resolver exits, which are cache misses. It does not count
fast-path indirect hits, so it cannot state a miss rate without an additional
denominator. The repeated hot-target aliases plus the cache's exact index are
enough to justify a cache experiment, but the experiment must prove wall-time
improvement.

### Fork and exec

Across 220 samples per lifecycle class:

| Interval | p50 | p95 |
|---|---:|---:|
| child repair | 22.5 us | 26.4 us |
| first prepare after fork | 4.21 us | 5.75 us |
| exec replacement/reset | 1.581 ms | 1.685 ms |
| first prepare after exec | 12.46 us | 15.88 us |

The current `exec-reset` interval begins before native image replacement and
ends after the translator is installed. It includes more than cache clearing,
so it must be subdivided before choosing an optimization.

### Instrumentation guardrail

With DTrace disabled, the signed pre-instrumentation and instrumented binaries
pass the declared non-inferiority bounds:

- syscall floor ratio 0.9908, 95% interval 0.9803 through 1.0050, limit 1.02;
- direct V8 ratio 1.0015, interval 0.9952 through 1.0059, limit 1.01.

Enabled profiling is intentionally expensive and remains diagnostic-only:
broad syscall-floor profiling was about 15.1x wall time, indirect V8 about
1.20x, and fork profiling about 2.34x in the recorded report-only run.

## Program architecture

### Area 1: indirect target cache

The first implementation keeps the one-load/one-compare direct-mapped shape but
removes the pathological index and uses the approved memory budget:

- 8,192 entries at 32 bytes each, exactly 256 KiB per guest thread;
- a shared typed index definition used by Rust publication and emitted AArch64;
- a page-mixing hash equivalent to `mixed = guest ^ (guest >> 12)`, followed by
  extraction of the aligned 13-bit entry index;
- unchanged release publication: cache address and generation first, guest key
  last with release ordering;
- unchanged target block generation guard as the stale-code authority;
- full clear on fork/exec until a later measured lifecycle change replaces it.

The extra hash instruction cost is paid on every indirect lookup. The larger
table is accepted only if fewer resolver exits translate into faster untraced
V8. A deterministic probe with two targets that collide under the old index is
the red-first proof.

If 8,192 mixed direct-mapped entries do not produce a statistically supported
wall-time win, the next experiment is two-way and then four-way set
associativity within the same 256 KiB ceiling. Associativity is not implemented
preemptively because each extra way adds generated loads and comparisons to the
hit path.

**Acceptance:** signed V8 ABBA comparison has a median ratio below 1.0 and a 95%
upper bound below 1.0; resolver exits fall materially; the monomorphic indirect
microbenchmark does not regress beyond its declared 2% upper bound; all
generation, signal-recovery, fork, and indirect-flow tests pass.

### Area 2: syscall preparation lookup

The first experiment turns the existing typed thread-local resume entry into a
persistent last-prepared-entry cache. A successful process-index lookup
publishes `(guest PC, generation, cache entry)` into the thread-local slot; a
subsequent matching preparation validates the generation and reuses the slot
without consuming it. This keeps the smallest possible hot cache and avoids
introducing a second indexing policy before it is needed.

On a key or generation mismatch, the entry is discarded and the existing
process-wide translation/index path runs. Fork, exec, and invalidation continue
to clear or invalidate thread-local state. If one persistent entry does not
cover the measured loop, a four-entry typed PC-to-`PreparedEntry` cache is the
bounded fallback.

**Acceptance:** the syscall-floor broad profile moves at least 90% of the
current repeated block-index outcomes to validated resume hits, the untraced
syscall-floor median improves with a 95% ratio upper bound below 1.0, V8 does not
regress beyond 1%, and code-generation mutation tests prove no stale entry can
execute.

### Area 3: exec replacement lifecycle

Before optimization, extend `dsr-fork` with non-overlapping samples for:

1. old native-image unmap;
2. new image map and protection setup;
3. DSR translation-cache reset or allocation;
4. relocations plus vvar/vDSO publication;
5. translator handoff and thread-local clear.

The samples must reconcile with the existing outer exec interval. The largest
reproducible subphase determines the implementation:

- mapping churn may justify retaining/reusing mappings or reducing redundant
  protection transitions;
- cache reset may justify generation/epoch invalidation or `madvise`-backed
  reuse instead of eagerly clearing large storage;
- metadata clearing may justify swapping compact empty indices rather than
  walking capacity;
- relocation/vvar cost is optimized only if it is actually dominant.

**Acceptance:** the chosen subphase and the outer exec p50 both improve by at
least 10% across the 220-sample workload; fork-child repair remains correct;
vfork/exec, non-leader exec, static/PIE exec probes, and process-status behavior
remain green.

### Area 4: gateway transition cost

The broad profile makes `run` the second large DSR-side aggregate, but enabled
DTrace perturbs this boundary. Establish an untraced gateway microbenchmark
that separately measures scalar-only and SIMD-using translated blocks before
changing assembly.

Possible implementation directions are evaluated in this order:

1. remove redundant context loads/stores proven dead by disassembly and gateway
   oracle tests;
2. specialize entry/exit stubs only when block metadata proves the omitted
   state cannot be guest-observable;
3. consider lazy SIMD state only with an explicit state machine that preserves
   Linux register semantics across syscalls, host calls, signals, kicks, fork,
   and exec.

There is no design permission to approximate vector-register preservation.

**Acceptance:** at least 5% syscall-floor improvement with a 95% ratio upper
bound below 1.0, no V8 regression beyond 1%, and the complete register, signal,
kick, and fault-recovery oracle remains green.

### Area 5: translation and publication

Reprofile after Areas 1 and 2 because many current resolver/translation calls
are downstream of cache misses. If translation remains material, split it into
decode, plan, emit, publication/index update, and duplicate-publication wait.

Use existing ecosystem collections and synchronization where they fit. A
collection replacement such as `HashMap`/`hashbrown` is justified only by a
typed lookup benchmark and real workload improvement; a lock-free index or
epoch reclamation scheme is justified only by a measured concurrent
publication bottleneck.

**Acceptance:** the targeted subphase improves by at least 10%, cold-start and
code-churn wall time improve, duplicate publication remains single-winner, and
generation/invalidation/fork concurrency tests remain green.

### Area 6: dispatcher boundary

Dispatcher time is recorded because it is part of end-to-end latency, but it is
shared runtime code and not automatically a DSR optimization. Revisit it only
after DSR prepare and run costs fall, and only when the same syscall remains a
long pole under an untraced or low-perturbation measurement. Any dispatcher
change becomes its own scoped design and Linux-oracle task.

## Evidence and decision protocol

Every area follows the same protocol:

1. freeze the signed before binary, commit, SHA-256, host, workload, and command;
2. add a deterministic red reproducer for the mechanism being changed;
3. implement the smallest structural experiment;
4. run focused correctness tests and a signed end-to-end demo;
5. collect fixed-order ABBA samples with deterministic bootstrap intervals;
6. rerun the applicable DSR profile and reconcile counts/incomplete pairs;
7. accept, revise, or revert the experiment according to its predeclared gate;
8. promote the accepted binary and evidence as the next area's baseline.

Carrick and Docker never run concurrently. Docker is used only for Linux
semantic comparisons, not as a performance baseline for Darwin DSR.

## Required correctness matrix

An accepted optimization must preserve:

- DSR block, direct-flow, indirect-flow, register, signal-fault, kick,
  generation, publication, fork, and exec unit/oracle tests;
- signed static and PIE AArch64 probes;
- V8 direct execution;
- Go and Rust static and PIE executable coverage as those workload artifacts
  enter the campaign;
- fork, vfork/exec, non-leader exec, and child-status behavior;
- exact Linux behavior for any semantic change, verified separately against the
  native arm64 Docker oracle.

The final gate for a completed area is `just ci`, signed live execution, DOF
section presence, valid JSONL evidence, and a clean intentional diff.

## Deliverables

- one implementation commit per attributable optimization experiment;
- checked-in before/after performance JSONL for accepted changes;
- durable DSR profile summaries with zero drops and incomplete pairs;
- updates to `docs/dynamic-syscall-rewriter.md` that distinguish measured facts
  from future work;
- a running optimization ledger in the implementation plan, including rejected
  experiments and their evidence;
- a final ranked account of remaining DSR costs after the accepted sequence.

## Stop conditions

An area stops when one of the following is true:

- its acceptance gate passes and the new baseline is recorded;
- two bounded structural variants fail to improve wall time, in which case the
  area is recorded as inconclusive and the program moves to the next measured
  pole;
- correctness requires an architectural expansion outside this design, in
  which case a new design is written rather than embedding a workaround;
- the cost falls below the next measured pole and no longer justifies further
  work in the current ordering.

The program is complete when all five DSR areas have either an accepted
improvement or an evidence-backed stop record, the full correctness matrix is
green, and the remaining-cost ranking is current.
