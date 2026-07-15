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
