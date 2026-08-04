# Native allocation-owner census: lifecycle-complete attribution without timing claims

**Date:** 2026-08-03 · **Status:** approved design, implementation not started ·
**Lane:** Darwin/aarch64 native DSR (`--exec-backend native`, the shipped
default) · **Decision:** add a diagnostic-only, feature-gated tagged system
allocator and a strict Rust aggregator. The ordinary binary remains unchanged.

---

## 0. Decision and gate

The next performance question is not “which allocation stack is largest in a
partial DHAT capture?” It is:

> Across every process image and every translating thread in the reference cold
> `go build`, which semantic owner requests enough allocation to plausibly own
> at least 10% of the separately measured normal-binary fault/CPU opportunity?

We will answer that with a diagnostic-only `alloc-owner-census` feature:

- a global allocator that delegates allocation behavior unchanged to
  `std::alloc::System`;
- a no-drop thread-local semantic owner tag;
- process-global relaxed atomic byte/call counters;
- explicit fork, exec, and process-exit epoch boundaries; and
- a typed `carrick debug alloc-owner-census` parser and aggregator.

The census is **attribution evidence only**. Its timing is unusable. Owner
counts are cross-bound to fault and CPU denominators captured from a separate,
ordinary signed binary built from identical source.

The output is a ranked portfolio, not a search for one mythical 3x change. Every
non-overlapping semantic owner that clears a 10% opportunity threshold in
**both** of two valid normal-binary bindings may be carried as a predicted
candidate. Candidates are implemented one at a time, each needs its own
single-variable end-to-end ABBA, and the remaining portfolio is remeasured and
rebased after every retained change. If no remaining owner clears the threshold,
this workstream stops and the campaign moves to the next bucket.

---

## 1. Why a new census is necessary

The current fault-ownership experiment stopped the production hypothesis. Two
source-identical bindings put even the favorable guest-fault opportunity at
7.411% and 7.425%, below the campaign's 10% pursuit threshold. The remaining
fault majority is host-side anonymous first touch, but the current evidence does
not identify its semantic allocator owner.

DHAT remains useful for discovering stacks and distinguishing cumulative from
retained shape. It is not lifecycle authority for this workload. Two fresh DHAT
scouts against the same persistent translation store produced this corrected
coverage:

| fact | scout A | scout B |
|---|---:|---:|
| natural exit / workload marker | rc 0 / `BUILD_OK` | rc 0 / `BUILD_OK` |
| main process-image epochs | 140 | 140 |
| process identities | 71 | 71 |
| all-thread translations | 772,292 | 772,322 |
| translations in DHAT-emitting PIDs | 284,494 | 321,729 |
| **all-thread DHAT coverage** | **36.8376%** | **41.6574%** |
| DHAT cumulative requested bytes | 10.841 GB | 12.045 GB |
| DHAT global `t-gmax` | 4.719 GB | 5.209 GB |
| cumulative / peak | 2.297x | 2.312x |

An earlier same-session calculation considered only `tid == pid` translation
records and incorrectly suggested roughly 99% coverage. That interpretation is
superseded by the all-thread reconciliation above. Absolute DHAT totals are not
accepted as workload totals.

The source shape is nevertheless stable enough to design the semantic tags:

| source class | A cumulative / peak share | B cumulative / peak share |
|---|---:|---:|
| publication map and recovery | 67.71% / 79.53% | 69.05% / 81.70% |
| translation transient / other | 19.98% / 1.71% | 19.86% / 1.39% |
| translation retained / support | 10.85% / 17.60% | 9.78% / 15.89% |
| other Carrick + external | 1.46% / 1.16% | 1.31% / 1.02% |

The leading stacks were `recovery.push`, publication-map capacity, the indirect
target cache, assembler emission, block planning, decode/read buffers, shared
translation buffers, and publication indexes. This is stack-discovery evidence,
not a production opportunity claim.

Authoritative current campaign evidence remains in
`docs/perf-results/2026-08-03-current-native-fault-ownership.md`; this design
does not change its stop verdict or the official shipped-default ratio.

---

## 2. Goals and non-goals

### Goals

1. Attribute successful allocation requests to typed semantic owners across
   all translating threads and all process-image epochs in the cold build.
2. Preserve allocator behavior: every allocation operation delegates to
   `System` with the original layout and pointer.
3. Produce lifecycle-complete, machine-validated export files at fork, exec,
   process exit, and normal host exit boundaries.
4. Reconcile the census to `NATIVEPERF v5` process-image epochs and all-thread
   translation totals before interpreting it.
5. Keep the ordinary product binary free of census code and overhead.
6. Bind attribution to separate normal-binary fault and CPU evidence, then emit
   a non-overlapping ranked portfolio with an explicit 10% carry/stop verdict
   for every owner.

### Non-goals

- Per-owner live bytes, retained bytes, or peak heap. Those require pointer
  ownership and deallocation tracking, which would materially change the
  allocator wrapper and its perturbation risk.
- Timing or fault counts from the feature-built census process.
- Stack collection inside the allocator.
- Core-file decoding. Export-only is the accepted first implementation.
- Eager whole-image translation. That remains a future improvement; JIT-on-JIT
  still needs this owner attribution independently.
- FreeBSD/NetBSD native, VMM, HVF, KVM, or bhyve behavior.
- A production allocator change or any guest-visible semantic change.

---

## 3. Alternatives considered

### A. Make DHAT lifecycle-complete

This would preserve exact stack attribution and peak/lifetime reporting, but
DHAT is highly perturbing and its profiler state is unsafe to treat casually
across fork-inherited process state. The two scouts already show incomplete
process coverage. It remains a discovery instrument, not the authority.

### B. Add explicit counters at known sites

This is cheap, but it counts only what was anticipated. It would miss
allocations made inside dynasm, collections, and adjacent helpers, and could
make a large unknown remainder look like absence of opportunity.

### C. Feature-gated tagged system allocator — selected

Thread-local owner scopes let allocations inside callees inherit semantic
ownership, including library internals, while the allocator still delegates
unchanged to `System`. A mandatory `other` bucket exposes attribution gaps. The
cost is diagnostic-only perturbation and the deliberate absence of live/peak
claims.

---

## 4. Feature and module architecture

The implementation adds one feature chain:

```text
carrick-cli/alloc-owner-census
  -> carrick-runtime/alloc-owner-census
     -> carrick-dsr-aarch64/alloc-owner-census
```

`alloc-owner-census` and the existing DHAT `alloc-census` feature are mutually
exclusive. Enabling both is a compile-time error. Neither belongs to a default
feature set. The allocator feature is supported only for the measured
macOS/aarch64 native lane and fails at compile time on another target; the text
parser remains portable.

The planned ownership is:

- `carrick-dsr-aarch64::alloc_owner_census`: owner enum, scope guard, atomic
  counters, allocator wrapper, lifecycle state, record renderer, and unit tests;
- `carrick-runtime`: re-export the diagnostic API for the native Darwin driver
  and expose the allocator type upward without adding a direct CLI-to-DSR
  dependency;
- `carrick-cli`: select the diagnostic global allocator, arm it at main entry,
  register the terminal host flush, add the debug subcommand, and host the typed
  parser/aggregator next to the existing census tooling;
- `carrick-runtime/src/native_darwin.rs`: call the lifecycle operations at the
  existing fork/exec/exit authority points and install semantic scopes around
  production work;
- `carrick-runtime/src/native_exec_capsule.rs`: drain at the final pre-`execve`
  seam, after capsule serialization and fd preparation have been counted, and
  rearm the same epoch if `execve` returns;
- `carrick-dsr-aarch64`: place narrower scopes around translation operations
  whose semantic boundaries live below the runtime driver, and align the
  in-process owner-epoch transition with the existing NATIVEPERF translator
  commit.

The normal configuration must compile these modules and calls out completely.
There is no runtime environment-variable branch in the shipping allocator.

---

## 5. Counter and allocator contract

### 5.1 Owners

The current v3 wire-stable owner enum is:

```rust
enum AllocationOwner {
    Other,
    PublicationMap,
    PublicationRecovery,
    BlockAssemblerTransient,
    DecodeReadBuffers,
    IndirectTargetCache,
    SharedTranslationSupport,
    PublicationIndexes,
    TranslationSourcePreparation,
    TranslationOrchestration,
}
```

Wire names are lowercase kebab-case:

```text
other
publication-map
publication-recovery
block-assembler-transient
decode-read-buffers
indirect-target-cache
shared-translation-support
publication-indexes
translation-source-preparation
translation-orchestration
```

The enum and parser are closed: an unknown owner is an error, not a bucket to
silently merge. Tags may be refined in a later implementation commit if the
mandatory `other` coverage gate fails, but the schema version must change if a
wire owner is added or renamed.

### 5.2 Scoped ownership

The current owner is a `thread_local!` cell with const initialization and no
destructor. `AllocationOwner::scope(owner)` returns a stack-safe guard that
restores the prior owner on drop. Nested scopes therefore attribute to the
innermost semantic operation without leaking a tag into unrelated work.

Scopes describe the semantic operation that induced an allocation, not merely
the concrete collection type. Examples:

- building the retained guest-PC map is `publication-map`;
- producing retained recovery metadata is `publication-recovery`;
- dynasm code/label/relocation growth during block assembly is
  `block-assembler-transient`;
- buffers used to read or decode guest bytes are `decode-read-buffers`;
- construction and growth of the target cache is `indirect-target-cache`;
- shared-store staging and mapped-unit support are
  `shared-translation-support`; and
- interval maps, route tables, or equivalent lookup structures installed when
  publishing are `publication-indexes`; and
- executable-span copies, source-word vectors, and segment construction before
  shared/artifact translation configuration are `translation-source-preparation`;
  and
- the residual allocation work induced by one process translation, outside its
  narrower nested decode, assembly, publication, cache, and shared-store
  scopes, is `translation-orchestration`.

Everything outside an active scope is `other`. Scopes must wrap the smallest
complete semantic operation, including relevant callees, rather than individual
`Vec::push` calls. The implementation plan will identify the exact call sites
with red-first tests.

### 5.3 Counted operations

The global allocator wrapper must obey this contract:

| operation | delegation | counter update after success |
|---|---|---|
| `alloc(layout)` | `System.alloc(layout)` | requested bytes += `layout.size()`; alloc calls += 1 |
| `alloc_zeroed(layout)` | `System.alloc_zeroed(layout)` | requested bytes += `layout.size()`; zeroed calls += 1 |
| `realloc(ptr, old, new_size)` | `System.realloc(ptr, old, new_size)` | requested bytes += full `new_size`; realloc calls += 1 |
| `dealloc(ptr, layout)` | `System.dealloc(ptr, layout)` | no owner counter |

Only a non-null result is successful. Reallocation charges the full requested
new size, not the delta, matching the cumulative-request semantics used to
compare source shape with DHAT. This is not a live-byte model.

Each owner has `u64` relaxed atomics for requested bytes, allocation calls,
zeroed calls, and reallocation calls. Relaxed ordering is sufficient because
these are commutative observations, not synchronization. Any checked-add
overflow sets a process-global overflow flag. Once overflowed, export still
writes the record but the parser rejects it for interpretation; wrapping into a
plausible count is forbidden.

Allocator callbacks may not format, allocate, read environment variables,
lock, write output, initialize a dropping TLS value, or call census lifecycle
code. They read the already-initialized TLS tag and armed state, delegate, and
update atomics only.

### 5.4 Arming boundary

The CLI resolves `CARRICK_ALLOC_OWNER_CENSUS_DIR` and arms the census as an
explicit first main-entry diagnostic action after the existing earliest process
stamp. Pre-main allocations are deliberately not counted and are reported as
`armed_at=main-entry`; they are not silently assigned to `other`. This is
acceptable because pre-main belongs to the separately measured fixed host-exec
segment, which is below 5% of cold-build CPU and is not the residual allocation
bucket under study.

Resolving the census directory/epoch and registering the atexit backstop happen
while unarmed; they are observer initialization, not product allocation. No
ordinary CLI dispatch or runtime setup may occur before arming.

The join authority is NATIVEPERF v5's existing main-thread `(pid, exec_epoch)`
key. A top-level process starts at epoch 0; a fork child resets to epoch 0; an
in-process exec increments at the existing translator commit; and a host
self-reexec successor receives the already-computed next epoch in a
feature-only internal environment entry. That entry is inserted directly into
the host exec environment before `execve`, is read at the successor's main
entry, and never enters the guest environment. Its construction is
observer-paused so it cannot inflate an owner. This avoids inventing a parallel
identity or arming the post-exec process under a temporary epoch 0.

---

## 6. Lifecycle state machine

The process-local states are:

```text
Unarmed -> Armed(exec_epoch, fragment_sequence) -> Draining -> Unarmed
                                       | terminal boundary: remain Unarmed
                                       | failed host exec: reset, rearm same epoch/next fragment
                                       | in-process exec: reset, rearm next epoch/fragment 0
Armed -> ObserverPaused -> Armed       | same counters and epoch, no drain
fork child: inherited bits -> reset-first -> Armed(epoch 0, fragment 0)
```

Transitions are fail-closed. Double arm, double drain, rearm before exporter
completion, or a terminal exit while still `Draining` is a lifecycle error in
the record or parser, never an implicit merge.

`ObserverPaused` exists because current exec seams render NATIVEPERF and
translation-census output before later production capsule/image work. A
quiescent boundary may pause owner counting around those existing diagnostic
serializers and then resume the same counters without snapshotting or advancing
the fragment. It may not enclose production work.

### 6.1 Fork child: reset before all repair

The child inherits a copy-on-write snapshot of the parent's atomics and TLS.
Therefore its **first child action after the fork branch is selected** must:

1. disarm inherited counting;
2. reset every owner counter, overflow bit, lifecycle sequence, and current TLS
   tag without allocating or locking; and
3. arm a fresh child epoch.

This occurs in `native_darwin.rs` before process stamping, fork barriers,
dispatcher repair, `ThreadRuntime::reset_after_fork_child`, or
`ThreadTranslator::after_fork_child`. Resetting in the translator hook is too
late: early child allocation would otherwise be charged to the parent epoch or
lost.

The parent continues its existing epoch without a flush.

### 6.2 Host self-reexec

The outer syscall path keeps counting through production publication, capsule
construction, serialization, nonce/environment/argv construction, prepared-fd
transactions, and all fallible validation. Draining earlier would omit real
host allocation and would turn a failed attempt into a false terminal epoch.

The outer path temporarily enters `ObserverPaused` around the existing
NATIVEPERF finalization and `xlat_census::flush`, then resumes the unchanged
owner counters before `begin_guest_exec`. Their allocations are observer cost,
while the capsule work that follows is production cost.

The allocation boundary is inside `native_exec_capsule::exec_capsule_with`,
after capsule and fd preparation and the existing pre-exec stamp, immediately
before the callback that invokes `libc::execve`:

1. disarm counting;
2. snapshot counters into a fixed, allocation-free intermediate;
3. render and atomically export `reason=host-self-reexec-attempt` while
   disarmed;
4. run any remaining diagnostic exporter while disarmed; and
5. invoke `execve`.

On success, control never returns; the new host process reads the feature-only
next-epoch entry and arms at main entry under `(same pid, exec_epoch + 1,
fragment 0)`. If `execve` returns an error, the old image resets the drained
counters and rearms the **same** `(pid, exec_epoch)` with the next fragment
sequence before returning the error to the syscall path. A later fragment in
that epoch therefore contains all post-failure work without double counting.

The aggregator infers which attempt succeeded from lineage: only the final
attempt may be followed by a same-pid `exec_epoch + 1` successor. Earlier
attempt fragments in the same epoch necessarily returned. An attempt with
neither a later same-epoch fragment nor a successor is incomplete and invalid.

### 6.3 In-process exec

The existing translation census drains early because no further guest
translation can occur during replacement. Allocation ownership cannot reuse
that location: image replacement, dispatcher reset, and translator preparation
still allocate and must remain in the outgoing epoch.

The allocation census temporarily enters `ObserverPaused` around that early
translation-census flush and resumes the same outgoing counters immediately
afterward.

The owner boundary aligns instead with
`PreparedThreadExecHandoff::commit_with_sink`, where NATIVEPERF already changes
the authoritative exec epoch. After all fallible replacement preparation but
before NATIVEPERF frame rendering and the process swap:

1. disarm and snapshot the outgoing epoch;
2. export `reason=in-process-exec` while disarmed;
3. render the outgoing NATIVEPERF frames while disarmed;
4. commit the process swap and advance NATIVEPERF to `exec_epoch + 1`;
5. reset allocation counters and TLS ownership; and
6. rearm the successor at `(same pid, exec_epoch + 1, fragment 0)` before guest
   execution can resume.

Any fallible preparation that returns before this commit leaves the outgoing
epoch armed. Rearming before diagnostic output or reset would pollute the
successor with observer allocations and is forbidden.

### 6.4 Process exit and host atexit

`finalize_native_process_exit` first publishes current production state, then
disarms and exports `reason=process-exit` **before** code-snapshot, NATIVEPERF,
or translation-census serialization. The terminal image does not rearm.

The CLI atexit handler is a last-resort `reason=atexit-backstop` path for a
normally terminating armed process that did not traverse native finalization.
It must be idempotent: if a terminal runtime drain already occurred, it writes
nothing. Crashes are not guaranteed to export; core decoding is deferred.

Only a quiescent exec/exit authority drains process-global counters. Thread exit
does not drain. All translating threads contribute to the same epoch atomics.

### 6.5 Export identity and durability

Each record filename is unique by process identity, monotonic timestamp, exec
epoch, and fragment sequence, for example:

```text
alloc-owner-<pid>-<monotonic-ns>-<exec-epoch>-<fragment>.txt
```

It is written to a caller-supplied census directory through a temporary file,
flushed, and renamed. A collision or partial write is an error; an existing
record is never overwritten. The directory is resolved and stored before
arming, outside allocator callbacks.

---

## 7. Wire schema and typed aggregator

The current schema is a line-oriented, deterministic `ALLOCOWNER3` record. V1
was superseded after the first full capture left `other = 13.3776%`, above the
10% coverage gate. The DHAT discovery table independently identified
`configure_shared_translation` as the largest remaining semantic boundary
(491,358,336 / 499,394,240 cumulative requested bytes in the partial A/B
scouts), so v2 added exactly `translation-source-preparation`. V2 arm A then
failed closed at `other = 10.036888623108418%`. The same DHAT stack table names
`ProcessState::translate` as the largest remaining outer semantic boundary
(9,109,059,802 / 10,319,258,502 gross cumulative requested bytes in partial
A/B scouts). V3 therefore adds `translation-orchestration` at that boundary;
narrower nested owners continue to win, so the new owner receives only the
previously residual allocation work. Its logical fields are:

```text
schema=3
pid=<host pid>
exec_epoch=<NATIVEPERF v5 u64>
fragment_sequence=<u64>
reason=<host-self-reexec-attempt|in-process-exec|process-exit|atexit-backstop>
armed_at=main-entry
overflow=<0|1>
owner=<wire name>,bytes=<u64>,alloc=<u64>,zeroed=<u64>,realloc=<u64>
...
total_bytes=<checked sum>
total_calls=<checked sum>
```

The implementation may choose a single header plus one owner row per enum
variant, but the following are contractual:

- every enum owner appears exactly once, including zero-valued owners;
- key order and owner order are deterministic;
- totals are present and equal checked recomputation;
- `(pid, exec_epoch)` exactly matches the existing `NATIVEPERF v5` main-thread
  process-image key, while `fragment_sequence` is contiguous within that key;
  and
- the complete record ends with a terminator/checksum so truncation is
  detectable.

`carrick debug alloc-owner-census <census-dir> --native-perf <path>` parses
records into typed Rust values and emits JSON. It rejects:

- unknown schema, field, owner, reason, or duplicate key;
- missing owner rows or required fields;
- malformed, truncated, overflowed, or total-inconsistent records;
- duplicate `(pid, exec_epoch, fragment_sequence)` records;
- contradictory terminal reasons or non-contiguous fragment sequences;
- records that cannot join to a process-image epoch; and
- lifecycle balance that cannot be reconciled with the reference run.

The JSON report includes per-owner bytes and calls, percentages of accepted
cumulative requests, `other` share, record/epoch/PID counts, all-thread
translation coverage, flush-reason counts, and every validation verdict. Raw
records remain the authority; JSON is a reproducible aggregation.

---

## 8. Coverage and opportunity validation

A census run is interpretable only when all of these pass:

1. the exact reference cold `go build` exits naturally with rc 0 and
   `BUILD_OK`;
2. zero workload survivors remain;
3. the persistent translation-store normalized-content receipt is unchanged;
4. the aggregator finds all 140 expected main process-image epochs and 71
   process identities, or explicitly demonstrates a newly measured equivalent
   workload topology rather than assuming those counts are timeless;
5. every `NATIVEPERF v5` `(pid, exec_epoch)` process-image epoch joins to one or
   more contiguous owner-census fragments whose aggregate has exactly one valid
   terminal disposition or successful exec successor;
6. all translating threads are included when reconciling translation counts;
7. schema, lifecycle, totals, overflow, and duplicate checks pass; and
8. `other` is too small to hide a qualifying owner.

The final rule is numeric. Let `T` be total accepted requested bytes and let
`Q` be the minimum byte share that the cross-binding model says could correspond
to 10% of the normal-binary opportunity. Validation fails if `other / T >= Q`.
The tool must print `Q`, its derivation, and the verdict. If the denominator
cannot support a defensible byte-to-opportunity mapping, the stricter default is
`Q = 10%`: an `other` bucket at or above 10% requires more tagging before any
stop conclusion.

Coverage does not make requested bytes equal faults. It only makes owner shares
complete enough to bind against separately measured normal-binary fault and CPU
evidence.

---

## 9. Measurement protocol and carry/stop rule

### Phase A — feature census, twice

For each of two natural captures:

- build the source-identical signed diagnostic binary with only
  `alloc-owner-census` enabled;
- use the locked reference workload and persistent store;
- enable `NATIVEPERF v5` and allocation-owner export together;
- run to natural completion; do not abort the observer;
- reap only the stamped run ID and prove zero survivors;
- aggregate with the typed command; and
- discard all feature-binary wall and CPU timing.

The two runs must agree on workload topology and translation opportunity. Owner
shares must be reported separately before any pooled summary.

### Phase B — normal-binary binding, twice

Use an ordinary signed binary from identical source and no diagnostic allocator
feature. Bind each accepted census share to a separately captured normal-binary
`NFAULT`/CPU denominator with source SHA, binary SHA, UUID, semantics, workload,
store receipt, and run receipt recorded. Do not reuse feature timing.

For every owner, report:

- measured cumulative requested bytes and calls in census A/B;
- share of accepted requests in A/B;
- the explicit mapping from that share to the normal-binary fault/CPU
  opportunity in binding A/B; and
- favorable and proportional ceilings, labeled as projections rather than
  measured improvements.

The default portfolio authority is the **proportional, non-overlapping** model:
an owner's accepted requested-byte share multiplies the separately measured
host-allocation fault/CPU pot, so carried owner projections sum to no more than
that pot. An owner-specific model may replace it only when DTrace/LLDB or
source-authoritative page accounting binds a disjoint set of normal-binary
faults to that owner. A favorable ceiling that reuses the whole host-allocation
pot for several owners cannot qualify a portfolio item.

### Decision

- **CARRY:** every non-overlapping semantic owner may enter the ranked
  production portfolio when it clears 10% opportunity in both valid bindings
  and its mechanism admits a non-regrettable change.
- **SEQUENCE:** implement only the highest-ranked carried candidate, retain it
  only after correctness gates and ordinary-binary ABBA, then rerun or refresh
  the attribution needed to rebase every remaining candidate against the new
  normal baseline. Initial percentages are not compounded into a promise.
- **STOP:** if no remaining owner clears 10% in both current bindings, commit
  the evidence and move to the next campaign bucket.
- **INVALID:** if coverage, lifecycle, `other`, or binding checks fail, improve
  the instrument or rerun; do not infer absence of opportunity.

A change is non-regrettable here when it preserves every guest ABI guarantee,
removes or compacts work instead of adding a permanent parallel path, remains
useful for dynamic/JIT-on-JIT execution even if eager translation arrives later,
and does not tax unrelated ordinary execution. A carried implementation is not
a win until a separate ordinary-binary, single-variable end-to-end ABBA retains
it. DTrace or LLDB attribution should bind the mechanism where practical, but
an instrumented timing run is never the official baseline comparison.

---

## 10. Testing and verification

Implementation is test-driven and must cover:

1. allocator success/failure accounting for alloc, zeroed alloc, realloc, and
   dealloc delegation;
2. full-new-size realloc semantics;
3. nested owner scopes and restoration after panic/unwind;
4. concurrent threads updating process-global counters under distinct TLS tags;
5. checked overflow producing an invalid record rather than wrapping;
6. compile-time rejection of simultaneous `alloc-census` and
   `alloc-owner-census`;
7. child reset occurring before every existing Darwin fork-child repair hook;
8. parent counters remaining intact across a fork;
9. host self-reexec success and returned-`execve` continuation, in-process
   exec, process exit, and atexit state transitions;
10. capsule construction/fd preparation remaining counted until the final
    pre-`execve` seam;
11. observer-pause scopes excluding existing diagnostic serializers without
    resetting, draining, or hiding later production allocations;
12. exporter allocation remaining uncounted and in-process rearm occurring only
    after all exporters/reset work and the NATIVEPERF epoch advance;
13. unique atomic export and truncated/collision handling;
14. strict parser rejection for every malformed/lifecycle/coverage case;
15. deterministic JSON aggregation from golden multi-process fixtures; and
16. a normal-feature build proving no allocator-census symbols/calls are linked
    into the ordinary binary.

Verification uses the repository recipes. At minimum: targeted red/green tests,
`just fmt-check`, `just clippy`, the relevant host integration tests under their
required serialization, a signed diagnostic smoke, and `RUST_TEST_THREADS=1
just ci` before campaign evidence is committed. The implementation plan may add
more focused gates but may not weaken these.

---

## 11. Failure modes and safeguards

| risk | safeguard |
|---|---|
| parent counters copied into fork child | reset/disarm is the first child action |
| early child allocations lost or misowned | rearm immediately after allocation-free reset, before stamp/repair |
| exporter counts itself | disarm before snapshot/render/write; rearm successor last |
| existing diagnostics inflate `other` | quiescent observer-pause scopes preserve counters around serializers |
| capsule preparation disappears from census | drain only at final pre-`execve` seam |
| failed host exec creates a false handoff | same-epoch fragment rearm plus successor/terminal lineage validation |
| owner epoch drifts from CPU epoch | use the existing NATIVEPERF `(pid, exec_epoch)` authority |
| allocator recursion or deadlock | no allocation, formatting, env reads, locks, or dropping TLS in callbacks |
| requested bytes mistaken for live/peak | schema and report name only cumulative requested bytes/calls |
| feature timing mistaken for product timing | aggregator omits timing authority; protocol discards it |
| partial process coverage looks complete | mandatory NATIVEPERF epoch and all-thread reconciliation |
| unknown allocation hides the prize | mandatory `other` and fail-closed opportunity threshold |
| counter wrap creates plausible totals | checked overflow bit invalidates interpretation |
| crash loses last epoch | accepted for export-only v1; core decoder deferred |
| two diagnostic allocators alter each other | compile-time mutual exclusion |
| feature leaks into shipping build | non-default feature chain plus binary/linkage gate |

---

## 12. Deferred improvements

1. **Core-file decoding:** expose allocation-owner counters through the LLDB
   debug surface so a crashed process can be recovered without a terminal
   export. This is useful but not required for the first authoritative natural
   run.
2. **Eager whole-image translation:** amortize a full translation at image load
   when workload economics support it. This does not replace the census because
   dynamic code and JIT-on-JIT workloads still translate after startup.
3. **Per-owner live/peak census:** only if cumulative attribution identifies a
   qualifying owner but retention remains the deciding uncertainty. It requires
   a separate design because pointer ownership changes the wrapper substantially.

---

## 13. Deliverables

The implementation plan must produce narrow, reviewable commits for:

1. feature wiring, counter core, allocator wrapper, and unit tests;
2. lifecycle integration and ordering tests;
3. semantic owner scopes with source-level tests;
4. strict export parser and `carrick debug alloc-owner-census` aggregation;
5. signed diagnostic smoke and complete two-run census evidence; and
6. normal-binary cross-binding evidence plus the ranked non-overlapping
   carry/stop portfolio.

No production optimization is part of those deliverables. Each carry verdict
creates a separately gated single-variable hypothesis; a stop verdict closes
this bucket only when no qualifying portfolio item remains.
