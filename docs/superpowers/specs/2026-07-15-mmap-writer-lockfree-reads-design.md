# mmap-Writer-Blocks-Readers — Lock-Free Reads Design

**Goal:** Remove the residual "writer blocks reader" contention on the memory
`RwLock`: mapping-mutating syscalls (mmap/munmap/mprotect/madvise/brk) + fork
take the exclusive write guard, and parking_lot's writer-fair `RwLock` blocks
all readers (the read-heavy translation/syscall path) behind a queued writer.

## Measured basis (pinned, rate-truthful)
Post memory-lock + translation-cache retirement, the residual `psynch_cvwait`
top frame is `parking_lot::RawRwLock::unlock_exclusive_slow` (a writer releasing
the lock and waking parked readers) with reader callers (`translate_read_mostly`,
`run_native_dsr_thread_loop_profiled`, `handle_native_fork`). So the residual
IS writer-blocks-reader on the RwLocks. Exact writer attribution was fuzzy
(per-sample slide math breaks for non-worker threads) but the SHAPE is clear.
The big wins are already banked (~22% wall / ~29% sys); this is a smaller,
tail-of-the-distribution residual.

## What readers need vs what writers mutate
Readers (lock-free-desired): translate guest VA → host VA (`regions`,
`address_mode`), accessibility check (`native_range_allows` → `native_page_
protections`; `protections.range_no_access`). Writers mutate `regions` (Vec),
`native_page_protections`/`native_write_exec_writable_pages`/`linux4k_page_
protections` (BTreeMaps), `owned_host_ranges`, and `protections`
(MemoryProtections — already has its own interior `RwLock`).

## Approaches considered
- **A — RCU / `ArcSwap<MappingSnapshot>` (recommended if we build).** Move the
  read-hot mapping state into an immutable snapshot behind `arc_swap::ArcSwap`.
  Readers `load()` (lock-free, never blocked by a writer) and look up on the
  immutable snapshot; writers clone-mutate-`store()` a new snapshot. To keep the
  per-write clone cheap, back the collections with structural-sharing persistent
  types (`im::Vector` for regions, `im::OrdMap` for the page maps) so a
  clone+mutate is O(log n), not O(n). Pros: readers never block on writers;
  durable. Cons: new deps (`arc-swap` + `im`, neither in the workspace);
  reworks ~250 read sites + the write sites to go through the snapshot;
  writers still serialize among themselves (fine — mmap-vs-mmap is rare); must
  integrate/replace the `protections` inner RwLock; a genuinely large refactor
  comparable in size to the memory-lock retirement.
- **B — seqlock.** Readers read optimistically + retry on a writer's sequence
  bump. Rejected: readers can't hold references into the region Vec (must copy
  out each lookup), awkward for a multi-field structure, retry storms under
  write-heavy phases.
- **C — reader-preferring RwLock.** Readers don't queue behind writers.
  Rejected: writer starvation (an mmap could wait indefinitely under constant
  reads — unacceptable, mmap must make progress); parking_lot has no such mode,
  needs a custom/third-party lock.
- **D — reduce writer frequency/scope.** e.g. special-case Go's frequent
  PROT_NONE arena reservation. Targeted, not general; doesn't help fork or
  other mutators.

## Recommendation
Approach A (RCU lock-free reads) is the correct, durable fix. But it is a
LARGE refactor (new dependencies, an immutable snapshot representation, routing
all mapping reads/writes through it, integrating the existing `protections`
lock) for a residual that is now a fraction of the already-captured contention.
Per the campaign's non-regression discipline, it must be built, measured
untraced, and kept ONLY if the numbers show a real gain — and its size warrants
a focused effort with fresh context, not a tail-end addition to an already very
long session.

## If built — phasing (each landable, red-first, measured)
1. Introduce `MappingSnapshot` (immutable) holding regions + the page maps;
   put it behind `ArcSwap`; readers `load()`. Writers still take the outer
   write guard AND rebuild+store the snapshot (correctness first; no perf yet —
   readers now read the snapshot lock-free but writers still exclude via the
   outer lock until step 2 removes the reader dependency on it).
2. Remove readers' dependency on the outer write guard for mapping lookups
   (they use only the ArcSwap snapshot); writers no longer block those readers.
3. Structural-sharing collections (`im`) so the per-write snapshot rebuild is
   cheap; measure the mmap/write throughput.
4. Measure untraced wall/CPU vs the current binary; keep only if it improves.

## Non-goals
Cold-translation misses on the translation `RwLock` (a separate residual, and
inherent — first-touch translation must serialize). fork/exec writers are heavy
but rare; the snapshot helps them too but they are not the frequency driver.

---

## Design revision (from the access-site exploration, .superpowers/sdd/mapping-rcu-sites.md)

1. **`owned_host_ranges` → NativeMemoryConfig, NOT the snapshot.** Zero incremental
   mutations; set-once + wholesale-replaced by `replace_image` (execve), exactly
   like address_mode/page-sizes. Fold into the existing lock-free
   `NativeMemoryConfig`. Snapshot is thus only 4 fields: `regions`,
   `native_page_protections`, `native_write_exec_writable_pages`,
   `linux4k_page_protections`.
2. **Fork is a READER.** `handle_native_fork` takes only `.read()` (OS COW does
   the memory duplication; no table rebuild). Remove fork from the writer list —
   it does not block readers. The real frequent writer is the anon-mmap metadata
   update (regions + protections), which the ArcSwap handles.
3. **NEW HAZARD (load-bearing): physical-backing replacement vs zero-copy readers.**
   `map_host_alias`/`remap_private` (MAP_SHARED/file mmap, private repoint) do raw
   `libc::mmap(MAP_FIXED)` replacing the physical backing at a host VA. Zero-copy
   readers (`host_ptr_for_read`/`host_ptr_for_write_shared`, used in
   dispatch/{fs,net,mem}.rs) hand the kernel a raw pointer into that backing.
   Today the outer write lock excludes them transitively. An ArcSwap over the 4
   metadata fields does NOT — so a lock-free zero-copy reader could have the kernel
   touch a host VA while `map_host_alias` remaps it → corruption/fault.
   **Architecture consequence:** the snapshot needs a COMPANION lock. Zero-copy
   dispatches take a SHARED "physical-backing-stable" guard; `map_host_alias`/
   `remap_private` take its EXCLUSIVE side. This lock is LOW-contention (only
   zero-copy syscalls read it; only MAP_FIXED-physical-remap writers write it —
   both far rarer than the metadata reads/writes the ArcSwap makes lock-free), so
   it does not reintroduce the mmap-writer bottleneck (Go's frequent anon-PROT_NONE
   arena mmap does NO physical remap — it only updates metadata → ArcSwap → no
   reader blocking). This is the key insight: separate METADATA (ArcSwap, hot) from
   PHYSICAL-BACKING STABILITY (small RwLock, cold).
4. **Ordering invariant, now explicit.** `map_host_alias` updates `protections`
   BEFORE pushing `regions` (safe direction: never "region visible without its
   protection"). Post-refactor each multi-field snapshot swap must preserve this
   as an audited invariant (build the full new snapshot, then one atomic store).
5. **Density / `im` decision.** `native_page_protections`/`linux4k_page_protections`
   can hold ~tens of thousands of entries (dense during arena reservation) → plain
   clone-per-write is O(n) and would negate the win → structural sharing needed.
   Options: (a) add `im` (im::OrdMap, O(log n) clone) — a new heavier dep vs the
   project's minimal-dep philosophy; (b) representation change to a RANGE map
   (contiguous same-prot ranges → the arena is ~1 entry, cheap plain clone, no new
   dep) — a larger internal change but dependency-free and arguably a better
   representation. `regions`/`native_write_exec_writable_pages` are small-N (plain
   clone fine). DECIDE after measuring actual map density empirically.

## Revised phasing
0. Fold `owned_host_ranges` into `NativeMemoryConfig` (small, dep-free, standalone).
1. Companion "physical-backing" RwLock: zero-copy dispatches take read; map_host_alias/
   remap_private take write. (Correctness for hazard #3, independent of ArcSwap.)
2. `MappingSnapshot` (4 fields) behind `ArcSwap`; readers `load()`; writers build+store
   one atomic snapshot (ordering invariant #4). Representation per #5.
3. Remove readers' outer-write-guard dependency for metadata lookups.
4. Measure untraced; keep only if it gains.
