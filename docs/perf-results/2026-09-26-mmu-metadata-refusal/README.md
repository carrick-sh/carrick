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

## Measured Allocation and Admission Work

Empirical measurements from `test_metadata_refusal_witness_rollback_allocations` across scale points [1, 8, 32, 128]:

| Extension Scale | Admission Allocations | Admission Bytes | Derived Max Allocs / Bytes | Rollback Allocations | Rollback Bytes | Popped Arenas |
|---|---|---|---|---|---|---|
| **1** | 22 | 88,300 (~86 KiB) | 31 / 268 KiB | **0** | **0** | 1 |
| **8** | 38 | 706,564 (~690 KiB) | 83 / 1.7 MiB | **0** | **0** | 8 |
| **32** | 70 | 2,827,412 (~2.7 MiB) | 137 / 6.6 MiB | **0** | **0** | 32 |
| **128** | 175 | 23,893,668 (~22.8 MiB) | 263 / 26.2 MiB | **0** | **0** | 128 |

### Derived Admission Budget Rationale
- **Per-Arena Backing:** Each attached extension arena allocates its `PT_PAGE = 4096` byte backing buffer (where `extension_arena_capacity = PT_PAGE = 4096`).
- **Amortized Geometric Growth:** Seven dynamic collections (`arenas`, `free_tables`, `staged`, `dirty`, `journal.words`, `journal.first_written`, `journal.returned_bases`) expand via geometric capacity doubling. Over a run attaching $K$ arenas, each container experiences at most $\lceil \log_2(K) \rceil + 2$ reallocations.
- **Common Derived Allocation Bound:**
  $$\text{max\_allocations}(K) = 15 + K + 15 \times (\lfloor \log_2(K) \rfloor + 1)$$
  (Scale 1: 31, Scale 8: 83, Scale 32: 137, Scale 128: 263).
- **Common Derived Byte Bound:**
  $$\text{max\_bytes}(K) = 64\text{ KiB} + K \times (\text{PT\_PAGE} + 200\text{ KiB})$$
  (Scale 1: 268 KiB, Scale 8: 1.7 MiB, Scale 32: 6.6 MiB, Scale 128: 26.2 MiB).
- **Negative Control Verification:** `test_metadata_refusal_negative_control_detects_exact_reallocation_regression` demonstrates that linear exact reallocation (e.g. `try_reserve_exact(needed_capacity)` while `len == 0`) incurs 128 reallocations for a single container at $K=128$, violating the derived $O(\log K)$ logarithmic growth budget.
- **Rollback Invariant:** Rollback performs strictly **0** allocations and **0** heap bytes across all scale points.

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
