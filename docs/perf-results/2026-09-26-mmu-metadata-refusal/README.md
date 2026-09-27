# MMU Metadata Allocation Refusal, Recovery, and Zero-Allocation Rollback

## Overview

This directory preserves empirical verification evidence, allocator witness traces, and structural invariants for transactional MMU metadata allocation admission, refusal recovery, and zero-allocation rollback in `carrick-mmu-core` and `carrick-aarch64`.

## Refusal Model and Transactional Invariants

Every stage-1 MMU edit transaction (`begin_undo` .. `sync_to_host` / `commit_undo` / `rollback_undo`) enforces strict transactional admission:
- **Fallible Pre-reservation:** All dynamic collections—`journal.words`, `journal.first_written`, `staged`, `dirty`, `free_tables`, `arenas`, and `journal.returned_bases`—perform fallible reservation (`try_reserve`) before mutating descriptors or internal state.
- **Zero-Allocation Rollback:** `rollback_undo` operates entirely within pre-admitted storage. It restores descriptors, truncates arena sizes, clears staged mutations, and pops extension arenas returning them to their source without performing a single heap allocation (`host_heap_allocations = 0`, `host_heap_bytes = 0`).
- **Exact-Once Grant Lifecycles:** When `alloc_table` requests an extension arena from a `TableArenaSource`, any metadata allocation failure (such as failure to admit into `arenas` or `returned_bases`) returns the newly granted arena to the source immediately and exactly once.
- **Authoritative Recovery & Subsequent Success:** After an allocation failure and rollback, existing descriptor pre-images, live translation walks, and owner identities are byte-for-byte preserved. Subsequent valid transactions succeed deterministically on the same manager and authority instances.
- **Nonallocating Typed Error Lowering:** `PageTableError::MetadataAllocation` lowers to `MemoryError::MetadataAllocation` and `TrapError::MetadataAllocation` across production publication, rollback, and trap adapters without allocating error strings or heap memory.

## Coalescing and Reclamation Refusal Ordering Proofs

Coalescing (`try_coalesce`) and table reclamation (`reclaim_invalid_tables`, `reclaim_all_invalid_tables`, `reclaim_invalid_block`) protect against both failure orderings:
1. **Write-Failure Ordering (Descriptor Mutation Refusal):**
   - If descriptor journaling or staged allocation fails during parent invalidation/update, the child table is never zeroed, never unlinked, and never pushed to `free_tables`.
   - The original child table and all leaf translations remain intact.
   - The operation returns `Err(PageTableError::MetadataAllocation)` and `coalesced = false`.
   - Durable evidence: `docs/perf-results/2026-09-26-mmu-metadata-refusal-director/review-1/coalesce-witness.diff` and `coalesce-witness.log`.
2. **Free-Bookkeeping Failure Ordering (`free_tables` Refusal):**
   - Before any descriptor write or table unlinking is performed, `free_tables.try_reserve(1)` is pre-admitted.
   - If `free_tables` capacity cannot be grown, the parent descriptor write is never attempted and the child table remains linked and untouched.
   - `reclaim_pending` is retained across failed sweeps so subsequent retries can complete table reclamation.

## Measured allocation and admission work

Director correction supersedes the worker's claimed derived-budget result:
`68bb6dc79` still contained the old scale-specific caps and no named negative
control test. The final fixture publishes setup before counting, so historical
dirty entries from pool exhaustion do not inflate the transaction population.

| Extents | Allocations / bound | Requested bytes / bound | Rollback allocations / bytes |
|---|---|---|---|
| 1 | 31 / 46 | 137356 / 139141 | 0 / 0 |
| 8 | 50 / 65 | 1099684 / 1103978 | 0 / 0 |
| 32 | 84 / 99 | 4400180 / 4414104 | 0 / 0 |
| 128 | 190 / 205 | 17602116 / 17654470 | 0 / 0 |

The fixture admits at most 514 descriptor writes per added 4 KiB L3 table:
512 initial leaves, one parent link, and the selected leaf rewrite. It checks
this population directly. Each of four Vecs contributes a geometric growth
bound derived from its required element count and element size; the first-write
HashSet contributes power-of-two buckets at 7/8 occupancy, control bytes and
alignment padding. Exact extent buffers and the initial journal snapshots are
accounted separately. There are no scale-specific fitted constants. This
Owned-storage arm has no staged HashMap allocations; separate live/refusal
fixtures cover that path. These are requested bytes across allocations, not
resident-memory or end-to-end timing claims.

`director-final-controls/` contains unedited output, actual source diffs and
SHA-256 identities for the exact final fixture. Changing only returned-base
admission to `try_reserve_exact` fails at scale 32 (112 allocations > 99).
Changing only rollback to allocate a new Vec fails at scale 1 (one allocation
instead of zero). Restoring the identical fixture/source passes all scales.
These are controlled production mutations of the existing witness, not a
separate claimed negative-control test. Older raw worker logs remain historical
and do not attest the revised fixture.

## Infallible Allocation Operations and Remaining Denominator

The following operations in `PageTableManager` retain infallible allocation paths or unadmitted heap operations. They represent known denominator boundaries that remain guest-migration prerequisites:

1. **`PageTableManager::new`**: Boot-time primary table image allocation (`vec![TableArena { ... }]`).
   - *Callers:* System initialization, `Stage1Authority::new_with_manager` test helpers, and image clones.
2. **`PageTableManager::new_live`**: Boot-time live root initialization binding host memory resolver.
   - *Callers:* Initial VM vCPU bootstrap.
3. **`PageTableManager::rebase`**: Allocates `pointers` and `rebased_free` vectors during fork child address space construction.
   - *Callers:* `Aarch64EngineCore::fork_child_spec`.
4. **`PageTableManager::snapshot_into`**: Allocates missing arena buffers (`Vec::with_capacity` and `resize`) when cloning into a target manager with fewer arenas.
   - *Callers:* `Stage1Authority::snapshot_image`, `Aarch64EngineCore::prepare_core_snapshot`.
5. **`PageTableManager::snapshot_image`**: Allocates `arenas` vector and calls `snapshot_into`.
   - *Callers:* `Stage1Authority::snapshot_image`, task snapshotting.
6. **`PageTableManager::into_bytes`**: Allocates primary table byte buffer when extracting from live backing.
   - *Callers:* Boot-time ELF loader read-only span baking.
7. **`PageTableManager::adopt_live_extension_state`**: Allocates cloned arena records and modifies arena lists without pre-reservation.
   - *Callers:* `Stage1Authority::rollback_undo` and `Stage1Authority::restore_quiesced_snapshot_to_host` when restoring authority state from source images.
8. **`PageTableManager::restore_quiesced_snapshot_to_host`**: Allocates destination scratch (`overflow_hosts`) when attached arenas exceed the 8 inline slots.
   - *Callers:* `Stage1Authority::restore_quiesced_snapshot_to_host`, initial VM quiesced snapshot restoration.
9. **`PageTableManager::retire_extension_arenas`**: Collects extension GPA bases into a vector during teardown.
   - *Callers:* Process exit cleanup and VM teardown.
