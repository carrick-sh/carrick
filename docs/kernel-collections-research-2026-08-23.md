# Kernel collection data structures — research and adoption policy (2026-08-23)

## Status and decision

This report follows a read-only source audit prompted by measured O(n)/O(n²)
work in global structures under one mutex. The trigger was
`retire_task_state_process_mappings` at approximately **540 ms per process
exit** in a 1000-process fork storm. The same campaign measured approximately
**35 ms/fork at 1000 live processes**, **45 s of retirement work inside a 10 s
window**, and 179 futex signal broadcasts across approximately 1000 waiters
(about **179,000 unparks**) in one probe.

The decision is deliberately not “standard library versus crates.io versus
hand-written.” Carrick should choose at two levels:

1. Carrick owns the **semantic composite**: identity, generation, ordering,
   ownership, rollback, and multi-index atomicity.
2. `std` or an ecosystem crate may supply a **leaf algorithm** when its exact
   semantics match that composite.

That yields the following policy:

| Need | Default decision |
|---|---|
| One exact-key index, ordered set, or bounded queue | Use `std`. |
| A standard range, arena, or intrusive algorithm whose semantics match exactly | Use an ecosystem crate behind a Carrick-owned typed wrapper. |
| Multiple coordinated indexes, generation/lifetime authentication, insertion-order precedence, or rollback | Build a Carrick-owned composite, using `std`/ecosystem leaves internally. |
| A specialized structure justified only by expected speed | Keep the current structure until a controlled measurement identifies the remaining cost. |

Do **not** add a generic `carrick-collections` crate or re-export third-party
collection types yet. Keep each semantic composite beside its owning domain.
Extract a shared leaf type only when at least two crates require the same
semantics, not merely a similarly named container.

## Evidence discipline

Every current-structure claim below is anchored to the `c49c4334` lineage used
for the audit. Complexity follows from code shape. Only the four measurements
above are measured performance results; all other performance effects are
hypotheses until a controlled experiment confirms them.

Crate health, release recency, popularity, and license compatibility are
screening inputs, not adoption evidence. A dependency is not approved merely
because it is maintained or widely downloaded. Before adoption it must pass:

- semantic API review against the Carrick invariant;
- license and feature-closure gates;
- a differential/reference-model test, plus red-first evidence when the change
  corrects an existing semantic defect;
- a controlled benchmark on the affected population;
- deletion of the structure or path it replaces.

---

## 1. Taxonomy of the kernel's collection needs

### T1 — Linux-visible identity with never-reused serials

`TaskKey { id: TaskId, serial: TaskSerial }` and `ThreadKey { tid,
serial }` live at `crates/carrick-runtime/src/kernel/objects.rs:72-81`.
`ObjectIdRegistry` allocates the serial from an `AtomicU64` and refuses
exhaustion (`kernel/ids.rs:170-203`). The serial is a kernel-lifetime identity,
not merely a recycled arena-slot generation.

**Current defects:**

- `RegistryState.tasks: BTreeMap<TaskId, TaskRecord>` is numeric-keyed
  (`kernel/core.rs:1502`), while exact-generation checks are repeated by callers
  such as `KernelTaskBinding::capture` (`core.rs:208-214`).
- `Task::threads: Mutex<BTreeMap<LinuxTid, (ThreadKey, ThreadRef)>>`
  (`objects.rs:2582`) has the same split between numeric lookup and exact
  authentication.
- `MmResourceState.retired: BTreeSet<TaskKey>` is permanent for the carrier
  (`hvpatch/mm_resources.rs:82-86`) and grows with retired generations.

**Important distinction:** `retired` is not only an anti-alias tombstone. It
makes repeated cleanup of one exact retired generation idempotent while an
unknown generation remains an error (`mm_resources.rs:244-275`). A generational
arena miss cannot distinguish those outcomes by itself.

### T2 — Missing or unused reverse indexes

The registry lacks a live `LinuxTid → (TaskKey, ThreadKey)` index. Exact-thread
resolution scans every task in `operations.rs:1855-2035`, including scheduler
wake and authority paths.

Other observed shapes:

- `set_oom_score_adj`, `task_nice`, and `set_task_nice`
  (`core.rs:1341/1361/1372`) linearly search a `BTreeMap` already keyed by the
  requested PID. These are direct shape bugs.
- `wait_child_matching` scans all zombies and then all tasks
  (`operations.rs:3730-3805`), although `Task::children` already owns a
  `BTreeSet<TaskKey>` (`objects.rs:2569,3277-3289`).
- `process_group_prio_targets` scans all tasks (`core.rs:1391`), although
  `ProcessGroupRecord.members` already exists (`core.rs:1549`).
- `user_prio_targets` scans all tasks (`core.rs:1419`); an euid index would need
  to participate in every credential transition.
- `update_fs_umask` scans tasks × threads (`operations.rs:2735-2748`). An
  `FsContextId → TaskKey` index would be too coarse because resource sharing is
  per exact thread/resource generation.

The rule is **reuse existing authoritative membership before adding another
index**. A new index belongs in the same critical section as the authoritative
mutation and must never become an independently locked source of truth.

### T3 — Range and interval queries

Carrick currently has several different range shapes:

| Site | Required semantics | Current structure |
|---|---|---|
| `carrick-guest-mem/src/protections.rs:45` | Non-overlapping merged set; point/overlap/coverage queries; range-local rollback | Sorted `Vec<(u64,u64)>` with `partition_point` |
| `trap.rs:2181` global-frame owners | Non-overlapping containing extent plus generation-pinned owner | `BTreeMap<(ipa,len), Owner>` with linear containment scan |
| `trap.rs:4580` COW armed ranges | Overlapping keep-all; most-specific containing range wins | `Vec<ForkCowRange>` with linear filter/max |
| `trap.rs:5765` global-frame allocator | Non-overlapping free extents; aligned smallest-fit allocation; exact live authority | `Vec` free list plus `BTreeMap` live set |
| `trap.rs:1912` alias registry | Overlapping candidates with several different ranking predicates | One global `Vec<AliasBacking>` |

These are not one interchangeable “interval map” problem. In particular,
overwrite-and-split semantics are valid only when obscured ranges are meant to
be destroyed. An overlapping candidate registry must retain every candidate
and apply the domain's selection rule at query time.

### T4 — Alias rows with cross-index ordering and liveness

The alias registry is the most load-bearing collection in this report. The same
row population supports multiple selection rules:

- Registration replaces the **first** row matching `(ipa, ownership_scope)` in
  place (`trap.rs:2295-2324`). Replacement does not make the row newest.
- `lookup_shared_alias` performs first-match IPA containment and skips dead
  host backings (`trap.rs:2404-2415`).
- VA lookup uses reverse insertion order and requires one row to contain the
  whole query (`trap.rs:2424-2573`).
- `physical_cow_source` uses reverse order, then authenticates process scope,
  semantic VA→IPA correspondence, physical extent, liveness, and reusable-frame
  owner generation (`trap.rs:11449-11483`).
- `shared_futex_location` uses reverse-order IPA containment plus sharing and
  liveness (`trap.rs:14084-14115`).
- `AliasOwnershipScope::Global` participates in the same global insertion order
  as process-scoped rows. Splitting global and process rows and always checking
  one first would change precedence.

`alias_backing_is_live` issues `mach_vm_region` and currently appears inside
linear predicates (`trap.rs:2359-2402,2565,2585,14108,11558`). That cost must be
removed without changing the skip-dead-and-continue behavior. Checking only one
preselected row and returning `None` when it is dead is not equivalent.

### T5 — Version chains and epochs

`AliasVersionRegistry` contains four association-list `Vec`s
(`trap.rs:7567-7573`). Epoch and chain lookup are linear in
`bump_version_epoch`, `scoped_alias_epoch_update`, and receipt processing
(`trap.rs:7583-7738`). These are ordinary exact-key indexes embedded in a
domain-specific receipt/rollback protocol.

### T6 — Snapshot, diff, and rollback

- `mutate_external_alias_state` clones the whole replay set and alias registry,
  mutates them, and diffs both sides (`trap.rs:7649-7745`).
- Several fork/spec paths clone the whole alias registry
  (`trap.rs:11145,14779,15429,15651,16033,16458`).
- `CowArmedRanges::snapshot` clones the complete range vector per fork
  transaction (`trap.rs:4580,11194`).
- `FileTableRwWriteGuard` clones the complete fd map to publish a diff
  (`objects.rs:1449-1458`).
- `KernelSnapshotV1` is a debug/observability projection with revision retries,
  not a rollback transaction (`snapshot.rs:26,873-920`).

Carrick already uses the correct rollback shape in several places: stage work is
recorded, committed, or discarded by RAII (`MmTransaction`,
`InventoryOverlay`, reservation tokens). The improvement target is keyed undo
information, not persistent collections throughout the kernel graph.

### T7 — Queues, futex enrollment, and targeted wakeups

- The scheduler run queue is `Mutex<VecDeque<QueueRow>> + Condvar` with a
  membership set (`scheduler.rs:369-400`). Targeted removal is linear
  (`scheduler.rs:865`), but the population is bounded by runnable threads.
- The executor directory clones tokens to find one thread
  (`scheduler.rs:304-342`).
- The futex table is already 64-way sharded (`carrick-thread/src/thread.rs:899,
  1006-1009`). Signal delivery clones every bucket ever created
  (`thread.rs:1022-1030,1351-1390`).

Futex buckets cannot simply be garbage-collected when their waiter counters
reach zero. `FutexWait` stores only `(addr, generation)` (`thread.rs:620-627`),
and `prepare_wait` intentionally releases the bucket before the later prepared
wait (`thread.rs:1038-1075`). Removing and recreating that bucket in the gap can
forget an intervening generation advance and lose the wake. Bucket lifetime is
currently part of the wake protocol.

A process-directed wake also needs more than `task → buckets`: multiple tasks
may wait on one shared futex bucket. The parking token/filter must identify the
target task as well as the thread.

### T8 — Free lists and Linux ID allocation

- `IdRegistry::reserve_next` linearly probes claimed PIDs
  (`registry.rs:91-119`).
- `GlobalFrameIpaAllocator::release` sorts and rebuilds the complete free list;
  allocation linearly finds the smallest aligned fitting extent
  (`trap.rs:5781-5878`).
- `AsidAllocator` already has the correct bounded shape: a reuse queue plus
  generation-stamped live/retired sets drained after TLB acknowledgement
  (`hvpatch/asid.rs:244-250`).

The global-frame allocator's alignment is load-bearing. A free extent whose raw
length fits may no longer fit after its base is aligned, including the 2 MiB
alignment used by large frames. A size index alone therefore cannot promise an
O(log F) smallest-fit lookup.

---

## 2. Structure decisions by need

### D1 — Task and thread identity: Carrick-owned wrappers over `std`

Introduce a domain API, initially backed by the existing standard maps:

```text
TaskTable
  get_numeric(TaskId) -> Option<&TaskRecord>
  get_exact(TaskKey) -> Result<&TaskRecord, UnknownTask | StaleTaskBinding>
  insert_exact(TaskKey, TaskRecord)
  remove_exact(TaskKey)

ThreadIndex
  get_numeric(LinuxTid) -> Option<(TaskKey, ThreadKey)>
  get_exact(ThreadKey) -> Result<(TaskKey, ThreadRef), UnknownThread | StaleThread>
```

This centralizes stale-generation failure without weakening `TaskSerial`'s
never-reused `u64` guarantee. `slotmap` is **not** the TaskKey/ThreadKey
authority: its slot generation is an internal weak-reference mechanism, not
Carrick's Linux-visible identity contract.

Do not delete `MmResourceState.retired` until the idempotent-retirement protocol
has a bounded replacement. A lifecycle-owned retirement receipt or an explicit
at-most-once cleanup authority may remove it later; treating every missing key
as “already retired” would hide unknown-task bugs.

A paged PID table and free bitmap remain valid custom candidates if PID lookup
or dense allocation becomes measured overhead. They are not prerequisites for
generation correctness.

### D2 — Reverse indexes: `std`, exact membership, one lock

Approved shapes:

- `tid_index: HashMap<LinuxTid, (TaskKey, ThreadKey)>`, maintained under the
  registry write lock that admits/retires thread claims;
- existing `Task::children` for `wait4`, followed by exact task/zombie lookups;
- existing `ProcessGroupRecord.members` for process-group operations;
- executor `by_thread: HashMap<ThreadKey, ExecutorId>` under the executor
  directory's existing lock.

Start with `std::collections::HashMap`'s default randomized hasher. A fast
non-cryptographic hasher is a per-index optimization only after the key domain
is proven Carrick-generated/non-adversarial and a controlled benchmark shows a
material gain. Guest futex addresses and other guest-derived keys do not meet a
blanket “internal” exemption.

For FS-context membership, either index exact `ThreadKey`s or make membership a
property of the `FsContext` authority itself. `FsContextId → TaskKey` is not
sufficient.

### D3 — Standard non-overlapping ranges: `rangemap` is an eligible leaf

`rangemap::RangeMap`/`RangeSet` is a good candidate where the required
semantics are exactly:

- ranges do not remain multiply represented;
- a new value overwrites overlapping old values;
- removal permanently clears the removed interval;
- equal-valued neighbours may coalesce.

Potential consumers are non-overlapping owner extents and canonical free or
protection ranges. Every consumer must still be wrapped in typed
`GuestVa`/`Gpa` APIs with checked range construction and domain-specific error
behavior.

Do not automatically replace `protections.rs`'s existing sorted `Vec`. It has
range-local snapshot/restore semantics and may have a very small population.
First compare its measured mutation/query population with the candidate.

### D4 — Overlapping intervals: ecosystem algorithm, Carrick selection policy

`iset` is an eligible candidate for the keep-all overlap algorithm because it
can return all intervals containing a point. Its 0.x API and smaller adoption
make a wrapper and reference-model testing mandatory. Carrick must store a
stable row key/ordinal and choose the winner itself.

If `iset` fails semantic, performance, or maintenance review, the fallback is a
Carrick-owned augmented interval tree. Do not write that tree merely because the
kernel is specialized; first prove the ecosystem leaf cannot satisfy the
required candidate enumeration.

### D5 — Alias registry: custom `AliasRegistry`, not one off-the-shelf map

The target is one authoritative composite:

```text
AliasRegistry {
    next_ordinal: u64,
    global: AliasSpace,
    root: AliasSpace,
    by_mm: HashMap<MmRootSlot, AliasSpace>,
}

AliasSpace {
    rows: StableRowStore<AliasRowKey, AliasRow { backing, ordinal }>,
    by_identity: HashMap<AliasIpa, AliasRowKey>,
    by_va: KeepAllIntervalIndex<GuestVa, AliasRowKey>,
    by_ipa: KeepAllIntervalIndex<Gpa, AliasRowKey>,
    by_physical: HashMap<PhysicalIpa, Vec<AliasRowKey>>,
    epochs: HashMap<AliasIpa, u64>,
}
```

The stable row store may use `slotmap`: its keys are private row handles, so
slot-generation wrap does not replace Carrick task identity. The interval
indexes may use `iset` after qualification.

Required behavior:

1. New rows receive a global monotonic ordinal. Replacing the first identity row
   retains its ordinal unless current code would append a new row.
2. A process lookup combines its local space and the global space, then ranks
   candidates by the same ordinal direction as the old single `Vec`.
3. Each query owns its full predicate: containment, whole-range coverage,
   scope, VA→IPA correspondence, sharing class, liveness, and owner generation.
4. A dead newest candidate is skipped and the next eligible live candidate is
   considered. Liveness may be cached or proactively cleaned only with an
   explicit invalidation/lifecycle authority.
5. Retiring an mm removes only its `AliasSpace` and performs O(its own rows)
   destruction. `Global` and `Root` remain distinct; neither is a wildcard.
6. Rebinding an inherited alias moves one row between spaces atomically while
   retaining the precedence required by current insertion order.
7. Replay, alias, and version mutation retains the existing
   `replay → alias → version` lock order until those states become one lock.

M1 sharding and M2 indexing from the previous report must be designed and
landed as one replacement. Sharding alone changes global/local precedence;
indexing alone leaves global retirement coupling.

### D6 — Versions and rollback: exact maps plus keyed journals

Replace the four `AliasVersionRegistry` association lists with ordinary exact
maps, inside the alias/receipt domain. Preserve:

- first epoch is 1;
- checked monotonic increment and abort on exhaustion;
- exact chain reset (`base = after`, then clear versions);
- receipt publication/retirement order.

Once every external alias mutator names its touched alias identities and replay
IPAs, delete `mutate_external_alias_state`'s general clone-and-diff path.

Use small domain-specific undo records for `MmTransaction`, frame inventory,
alias publication, and file-table writes. Do not introduce `rpds` or `imbl` yet.
After alias state is scope-local and keyed, remeasure the remaining snapshot
cost. Persistent collections are justified only if a large, genuine
snapshot-and-restore population remains.

`KernelSnapshotV1` stays an owned diagnostic projection. Do not tax every
syscall lookup with persistent nodes to optimize an observability path.

### D7 — Scheduler and futexes: keep locks, add exact directories

Keep `Mutex<VecDeque> + Condvar` for the scheduler queue. Add the executor
`by_thread` index first. Consider `slotmap` rows with `prev`/`next` keys or
`intrusive-collections` only if targeted removal remains measured after the
larger global costs are removed.

For futex signals:

- add a thread-directed enrollment directory that points to the exact live
  bucket `Arc`s, maintained with enrollment, requeue, and unenrollment;
- make process-directed notification accept an exact task identity;
- include task identity in the parking token/filter so a shared bucket wakes
  only the target process's waiters;
- preserve the enrolled/parked/pending-redirect/credit protocol through every
  transition.

Do **not** garbage-collect address buckets until prepared wait tokens retain or
enroll an exact bucket generation. The safe GC proof must cover the interval
between guest-word validation and actual parking, not only current waiter
counters.

The existing event ring remains its custom fixed-size, allocation-free,
overwriting atomic array. `boxcar` is append-only and growing, so it does not
match that contract.

### D8 — Global-frame allocator: custom two-index allocator over `std`

Use one Carrick-owned allocator with:

- `free_by_base: BTreeMap<Gpa, Length>` for predecessor/successor coalescing;
- `free_by_size: BTreeSet<(Length, Gpa)>` for candidate ordering;
- `live: BTreeMap<Gpa, Length>` as the exact fail-closed release authority.

Every split, allocation, release, and coalesce updates both free indexes inside
the allocator's existing mutex. Release becomes O(log F) neighbour lookup plus
bounded index updates instead of sort-and-rebuild.

Allocation must align each candidate base and verify the aligned remainder.
With arbitrary alignment, scanning size-ordered candidates is not guaranteed
O(log F). If measurements show that scan remains significant, exploit the
small finite alignment classes used by HVPatch with alignment-specific indexes;
do not claim the stronger bound before implementing that design.

PID allocation may use a custom free bitmap later. Keep it separate from the
task-record store: allocation availability, Linux-visible identity, and record
storage are related invariants but not the same collection.

---

## 3. Dependency disposition

| Crate | Disposition | Allowed use |
|---|---|---|
| `rangemap` | Eligible after qualification | Canonical non-overlapping overwrite/coalesce range maps and sets |
| `iset` | Evaluate behind a wrapper | Keep-all overlapping interval candidate enumeration |
| `slotmap` | Eligible for private handles | Alias/run-queue/internal arena rows; never TaskKey/ThreadKey authority |
| `rustc-hash` | Deferred | Per-index optimization for proven non-adversarial keys after measurement |
| `intrusive-collections` | Deferred | Scheduler targeted removal only after it is measured |
| `rpds` / `imbl` | Deferred | Narrow genuine snapshot/restore path after scope/index migrations and remeasurement |
| `smallvec` | Deferred | Only where cardinality histograms justify inline storage |
| `boxcar` | Rejected for current named uses | Does not match the fixed bounded event ring |
| `dashmap`, `papaya`, `scc`, `flurry` | Rejected for graph/alias authority | Cross-key atomicity and consistent snapshots matter more than sharded access |
| `left-right`, `evmap` | Rejected for alias state | Frequently written COW state would pay duplicate application/publish costs |
| `slab` | Rejected for external identities | No generation; stale keys can silently name reused slots |
| `indexmap` | Rejected for alias ranges | Insertion order does not solve interval candidate selection |

Do not use a transitive dependency as though it were a workspace API. Any
adopted crate becomes a direct dependency of its consumer, with its features and
license checked explicitly.

---

## 4. Revised migration sequence

Ranked first by measured coupling, then by semantic risk and implementation
cost. Each phase must delete the path it replaces.

### M0 — Apply the zero-dependency shape fixes

- Replace the three PID `.iter().find(...)` calls with exact map lookup.
- Route process-group priority through `ProcessGroupRecord.members`.
- Route `wait4` candidate enumeration through the parent's existing child set.
- Add executor `by_thread` under its existing lock.

These changes need focused correctness tests but no new collection dependency.
Measure them independently; do not attribute the 540 ms alias result to them.

### M1 — Specify and reference-test alias selection

Before changing storage, encode a simple test-only reference model of the
current `Vec` semantics. Required equivalence fixtures:

- overlapping `PROT_NONE` reservation and later `MAP_FIXED` commit;
- replacement of the first `(ipa, scope)` row without moving its precedence;
- dead newest row with an older live fallback;
- overlapping global and process-scoped rows in both insertion orders;
- whole-range-in-one-entry versus straddling two rows;
- stale owner generation against a recycled host VA/IPA extent;
- rebind across fork and atomic process-scope retirement.

The new registry must match the reference model before performance evidence is
considered.

### M2 — Replace the alias registry as one composite

Land scope-local storage, stable rows, global ordinal, VA/IPA candidate indexes,
and keyed identity indexes together. Preserve the reference semantics and lock
order. Then remeasure:

- 1000-process exit retirement;
- fork cost as live process count grows;
- COW-fault alias lookup;
- `mach_vm_region` calls per successful lookup.

This is the migration most directly tied to the measured 540 ms/process exit
and 35 ms/fork pathologies.

### M3 — Delete alias clone-and-diff and map the version chains

Convert every mutator to touched-key publication, replace version association
lists with exact maps, and delete `mutate_external_alias_state`. Preserve epoch
and receipt semantics byte-for-byte. Re-run the M2 measurements so the result is
separable from sharding/indexing.

### M4 — Range-index and pin global-frame owners

Replace linear owner containment lookup with a non-overlapping typed range
index. The lookup may release the global index lock before copying only after it
pins an `Arc`-owned mapping and exact generation so retirement cannot `munmap`
the host extent under the copy. Preserve the `(None, 0) => true` compatibility
case documented at `trap.rs:2139-2163`.

### M5 — Add exact futex signal enrollment indexes

Implement thread- and task-qualified wake targeting without bucket GC. Prove
the mid-requeue, unpark/repark, wake-credit, and prepared-wait gaps. Re-run the
recorded requeue durability workload and machine-count unparks.

### M6 — Add registry thread identity indexes

Add `tid_index` and the exact `TaskTable`/`ThreadIndex` APIs. Update them in the
same registry write-lock sections as task/thread claims. Preserve the distinction
between `Unknown*` and `Stale*` errors.

Only after those indexes land should user/euid or FS-context membership be
considered, and only against measured callers.

### M7 — Replace global-frame allocator sort/rebuild

Introduce the custom base/size/live composite. Prove aligned smallest-fit,
lowest-base tie-breaking, exact release rejection, split/coalesce, arena bounds,
and rollback. Report the actual candidate count under 16 KiB and 2 MiB
alignment before claiming O(log F) allocation.

### M8 — Bound exact-generation retirement history

Redesign `MmResourceState.retired` only with an explicit proof of repeated
cleanup semantics. A successful result must remain idempotent for the exact
retired generation, reject live duplicates, reject unknown tasks, and never let
a recycled numeric PID target its predecessor's lease.

### M9 — Journal touched fd/range state

Replace full file-table clones with touched-slot undo/publication. Reassess
`CowArmedRanges` after alias sharding: if its snapshot population remains large,
evaluate a keep-all interval structure or narrow copy-on-write representation
against the current vector reference model.

### M10 — Reassess deferred dependencies and lock granularity

Only after M0-M9:

- benchmark default `HashMap` versus a fast hasher on exact hot indexes;
- measure scheduler targeted-removal population before intrusive storage;
- measure remaining snapshot size/frequency before persistent collections;
- measure contention after algorithmic work before splitting global locks.

The measured defect is currently excessive work under locks, not evidence that
the locks themselves are the limiting algorithm.

---

## 5. Cross-cutting invariants and anti-recommendations

Every migration preserves:

- `replay → alias → version` lock order (`trap.rs:7646`, `trap.rs:2291`);
- `registry → observations` lock order (`snapshot.rs:967-969`);
- exact source/binary/receipt provenance for any performance or conformance
  claim;
- typed `GuestVa`, `Gpa`, physical IPA, owner generation, task, and futex-key
  domains;
- one authoritative implementation: no permanent old/new dual path.

Avoid these approaches:

- **Sharded concurrent maps for kernel graph authority.** They do not provide
  the required cross-key transaction or consistent snapshot.
- **A global fast-hasher alias.** Key threat models differ; select per index.
- **One universal interval type.** Non-overlapping overwrite, overlapping
  keep-all, aligned allocation, and range-local rollback are different
  semantics.
- **Generational arenas as Linux identity.** Internal slot validity is not the
  never-reused TaskSerial/ThreadSerial contract.
- **Futex bucket GC based only on current counters.** It ignores prepared wait
  tokens and can forget wake generations.
- **Persistent collections for the whole graph.** They optimize diagnostic
  cloning by taxing the syscall path.
- **A `carrick-collections` dependency façade.** Re-exporting crates hides the
  semantic decision instead of centralizing it.
- **Adding an index beside an independently mutable legacy path.** A composite
  may own multiple indexes, but every mutation must go through its single API
  and the replaced path must be deleted.

## 6. Typed-domain opportunity

Collection migrations must close, not reproduce, the existing bare-integer bug
shape:

- `FutexTable.shards: HashMap<u64, ...>` combines private guest addresses and
  shared waiter identities (`carrick-thread/src/thread.rs:899`).
- `ReplayMappingKey = (u64, usize, usize, u64)` combines several physical and
  permission domains (`trap.rs:2236`).
- `global_frame_host_owners` uses `(u64, u64)` for an IPA extent
  (`trap.rs:1974`).

New structures should use `FutexKey`, `GuestVa`, `Gpa`, `PhysicalIpa`, typed
lengths, and exact generation-bearing owner keys. The type boundary is part of
the collection design, not a cosmetic follow-up.

## 7. Bottom line

Carrick should build its own **kernel semantic data structures** where the
structure means more than its container: `AliasRegistry`, task/thread identity
tables, the global-frame allocator, futex enrollment, and undo journals.

Carrick should generally not build its own hash table, balanced tree, slot arena,
or interval-tree algorithm when a maintained crate exactly supplies that leaf.
Use `std` first; qualify `rangemap`, `iset`, or `slotmap` for narrow roles; wrap
them in typed Carrick APIs; and let controlled measurements decide whether the
remaining speculative dependencies are warranted.
