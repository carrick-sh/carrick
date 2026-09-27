# EL1 Elastic Metadata Allocator, Dynamic Extent Grants, and Bounded Reclamation

## Overview

This directory documents the design, verification evidence, structural operation bounds, and host-guest grant lifecycle for the EL1 kernel metadata allocator in `carrick-el1` and `carrick-vmm-hvf`.

The dormant non-reclaiming bump allocator has been replaced by a bounded segregated-fit metadata allocator supporting:
1. **$O(1)$ Allocation and Deallocation:** 28 segregated size classes with bitmap indexing and intrusive doubly-linked lists.
2. **$O(1)$ Bidirectional Coalescing:** Single packed 32-byte `BlockHeader` structures with physical neighbor offsets (`prev_phys_offset` and forward address `(header as usize) + size`) merge contiguous free blocks immediately upon deallocation without requiring a separate footer.
3. **Arbitrary Alignment and Checked Arithmetic:** Prefix and suffix splitting with alignment compensation (`0 < prefix < MIN_BLOCK_SIZE` guard advancing `p += align`) ensures returned pointers satisfy arbitrary alignment (`align >= 16`).
4. **Grant Sizing with Full Overhead Accounting:** `needed_grant_size(size, align)` explicitly accounts for payload size, header overhead, alignment padding, and prefix splitting overhead before requesting host extent expansion.
5. **Authenticated Dynamic Extent Growth:** When capacity is exhausted, the allocator requests 512 KiB extent grants from the host hypervisor via `HVC #6` (`METADATA_GRANT_OP_ALLOC`).
6. **Kernel Stage-1 Dynamic Mapping:** The dynamic metadata aperture (`0x2D_0800_0000..0x2D_0C00_0000`, 64 MiB, 128 slots) is mapped in Stage 1 with kernel-only RW non-executable non-global block flags.
7. **Exact-Once Extent Return & Safe Unmap:** When an extent's live allocation count reaches zero and its free block coalesces to full extent size, it is unlinked in $O(1)$ and returned to the host via `HVC #6` (`METADATA_GRANT_OP_FREE`). Host aperture deallocates backing memory only upon successful Stage-2 unmap.
8. **Safe Lock/IRQ Behavior:** `disable_irq_save` captures current `DAIF` register flags and masks IRQs; `restore_irq` faithfully restores caller's prior `DAIF` state. Allocator spinlocks are explicitly dropped before issuing host hypercalls.
9. **Refusal Recovery:** Host grant denial preserves prior allocations and metadata without corruption or resource leaks, enabling subsequent valid transactions to succeed.
10. **`GlobalAlloc` Installation:** `MetadataStorage` implements `core::alloc::GlobalAlloc` and is installed as the EL1 `#[global_allocator]` with test control routed through `SYS_CARRICK_EL1_CONTROL` (`0xCA88_0001`).

---

## Allocator Data Structure and Operations

### Size Classes and Bin Indexing
- 28 segregated size bins covering block sizes from 32 B to 4 MiB.
- A `u32` bitmap tracks non-empty bins. Selecting the smallest fitting non-empty bin is an $O(1)$ operation using `trailing_zeros` over the masked bitmap.
- Each bin maintains an intrusive doubly-linked list of `BlockHeader` structures. Unlinking and pushing to a bin are $O(1)$ pointer updates.
- Allocation inspects at most 2 candidate blocks (head of target bin + head of next active bin) to guarantee strictly bounded search operations.

### Block Layout and Physical Coalescing
- Every block begins with a packed 32-byte `BlockHeader` (16-byte aligned):
  - `magic`: `0xCA77` for corruption detection.
  - `extent_idx`: `u8` indexing the containing extent in the extent table.
  - `prev_phys_offset`: `u32` relative byte offset to the preceding adjacent block in physical memory (or `0xFFFF_FFFF` if first block).
  - `size`: `usize` total block byte length (including header).
  - `is_allocated`: `bool` indicating whether the block is live.
  - `prev_free`: `*mut BlockHeader` intrusive free list pointer.
  - `next_free`: `*mut BlockHeader` intrusive free list pointer.
- Neighbor lookup:
  - Preceding block: `(header as usize) - prev_phys_offset`.
  - Following block: `(header as usize) + size`.
- Coalescing executes in $O(1)$ time with at most 2 merges per deallocation.

### Extent Table and Exact-Once Return
- A fixed table of 128 `ExtentDescriptor` entries tracks admitted memory regions.
- The bootstrap metadata region is registered at index 0 (`0x0070_0000..0x0100_0000`, 9 MiB).
- Dynamic extents are admitted in the aperture `0x2D_0800_0000..0x2D_0C00_0000` (512 KiB per extent, up to 64 MiB total).
- Each `BlockHeader` stores the 8-bit `extent_idx` of its containing extent. On `deallocate`, the extent is retrieved in $O(1)$ without searching.
- When an extent's `live_allocations` drops to 0 and its full capacity is free, the block is unlinked from the free bins and returned to the host.

### Operation Bounds & Memory at Scale

| Scale (Extents) | Descriptor Table Memory | Free Bins Memory | Extent Capacity | Max Free-List Inspections | Max Splits | Max Merges | Extent Lookup Operations |
|---|---|---|---|---|---|---|---|
| 1 | 32 B | 448 B | 9 MiB (bootstrap) | $\le 2$ | $\le 2$ | $\le 2$ | $O(1)$ (direct index) |
| 8 | 256 B | 448 B | 12.5 MiB | $\le 2$ | $\le 2$ | $\le 2$ | $O(1)$ (direct index) |
| 32 | 1,024 B | 448 B | 24.5 MiB | $\le 2$ | $\le 2$ | $\le 2$ | $O(1)$ (direct index) |
| 128 | 4,096 B | 448 B | 72.5 MiB | $\le 2$ | $\le 2$ | $\le 2$ | $O(1)$ (direct index) |

Total fixed descriptor state size is 4,548 bytes across all scales. Work metrics are derived and asserted at runtime in unit tests.

---

## Lock and IRQ Safety Protocol

- Allocator state is wrapped in `MetadataStorage` protected by a spinlock.
- **IRQ Masking with State Preservation:** `disable_irq_save` reads current `DAIF` flags, disables IRQs, and returns `IrqGuard { saved_daif }`; `restore_irq` faithfully restores the exact flags.
- **Hypercalls Outside Critical Section:** If an allocation requires host extent expansion, or a deallocation produces a returned extent:
  1. The allocator determines the needed action under lock.
  2. The spinlock is dropped and IRQ state is restored.
  3. The `HVC #6` hypercall is executed.
  4. On grant success, the lock is reacquired with IRQ save to admit the new extent and complete allocation.
- This prevents host waits while holding spinlocks and eliminates IRQ reentrancy deadlocks.

---

## Host Hypervisor Extent Grant Protocol

### Transport: `HVC #6`
- Immediate: `AARCH64_HVC_METADATA_GRANT_IMM = 6`
- Excluded from `is_aarch64_syscall_exception` in `carrick-hal` to ensure grant traps never route to Linux syscall dispatch.

### Register ABI
- **Request Grant (`METADATA_GRANT_OP_ALLOC = 1`):**
  - Input: `x0 = 1`, `x1 = requested_size` (e.g. 512 KiB)
  - Output: `x0 = status` (0 = SUCCESS, 1 = DENIED, 2 = INVALID_PARAM), `x1 = extent_base_ipa`, `x2 = granted_size`, `x3 = token`
- **Return Extent (`METADATA_GRANT_OP_FREE = 2`):**
  - Input: `x0 = 2`, `x1 = extent_base_ipa`, `x2 = extent_size`, `x3 = token`
  - Output: `x0 = status` (0 = SUCCESS, 1 = DENIED, 2 = INVALID_PARAM, 4 = NOT_FOUND)

### Host Processing (`carrick-vmm-hvf::metadata_grant`)
- 128-slot bitmap allocator managing the 64 MiB dynamic window `0x2D_0800_0000..0x2D_0C00_0000`.
- Supports arbitrary multi-slot extent grants ($N = \lceil \text{requested\_size} / 512\text{ KiB} \rceil$) with atomic multi-bit reservation (`find_and_reserve_slots`) under lock to prevent concurrent overlapping allocations.
- Validates that `extent_base_ipa` and `size` align to 512 KiB extent boundaries and fall strictly within the dynamic range.
- Enforces strict token authentication (`token != 0 && record.token == token && record.size == size`) without wildcards.
- Dynamic stage-2 mapping is established via `inventory_hv_vm_map` (with non-executable RW permissions `0b011`) and torn down via `inventory_hv_vm_unmap`.
- **Atomic Rollback & Host Quarantine:** If Stage-2 mapping fails, slot reservations are immediately rolled back and memory is freed. If Stage-2 unmapping fails during return, the slot record is retained and host backing memory is quarantined (not freed) to prevent host use-after-free while guest IPA mappings persist.
- Tracks 6 atomic host counters: `grants_requested`, `grants_succeeded`, `grants_denied`, `returns_completed`, `bytes_granted`, and `bytes_returned`.
- Supports test failpoint injection via `arm_deny_next_metadata_grant()`.

---

## Verification Evidence

### VM-Free Unit Tests (`crates/carrick-el1/src/alloc.rs` and `crates/carrick-vmm-hvf/src/metadata_grant.rs`)
1. `test_arbitrary_alignments_and_memory_writes`: Validates alignment from 16 to 4096 bytes, non-overlapping spans, payload write verification, and work bounds ($\le 2$ inspections, $\le 2$ splits, $\le 2$ merges).
2. `test_fragmentation_coalescing_and_reuse`: Validates that freeing non-adjacent blocks coalesces upon neighbor deallocation and allows a large contiguous block to be reallocated in-place.
3. `test_extent_admission_validation_and_overlap_rejection`: Validates that unaligned, out-of-range, and overlapping extents are rejected at admission.
4. `test_dynamic_growth_and_exact_once_return`: Validates that exhaustion triggers dynamic extent admission and full deallocation returns the extent exactly once.
5. `test_grant_refusal_preserves_state_and_allows_subsequent_retry`: Validates that when a grant fails, existing allocations remain valid and intact, and subsequent retries succeed.
6. `test_extent_return_cancellation_preserves_reusable_memory`: Validates that if host extent return fails, the guest cancels the return, retains active extent ownership, and safely reuses the memory without leaks or corruption.
7. `test_bounded_operations_and_bytes_at_scales_1_8_32_128`: Validates operation bounds ($\le 2$ inspections, $\le 2$ splits, $\le 2$ merges) and descriptor state sizes across 1, 8, 32, and 128 extent scales.
8. `test_host_aperture_multi_slot_reservation_and_overlap_rejection`: Validates multi-slot contiguous span reservation (e.g. 1.5 MiB across 3 contiguous 512 KiB slots), consecutive non-overlapping allocations, unreservation, and slot reuse.

### Embed Integration Test (`crates/carrick-embed/tests/el1_sched.rs`)
- `el1_metadata_allocator_grows_and_returns_extents`: Signed guest execution fixture divided into three distinct execution phases:
  - **Phase 1 (Basic):** Exercises arbitrary alignments (16..4096 bytes) and memory pattern writing in guest EL1.
  - **Phase 2 (Growth):** Allocates 10 MiB, forcing dynamic growth crossing the 9 MiB bootstrap boundary, verifies Stage-2 host mapping, deallocates all memory, and asserts exact match between `bytes_granted` and `bytes_returned`.
  - **Phase 3 (Denial & Recovery):** Arms the host grant denial failpoint, attempts allocation exceeding capacity, verifies error handling and data preservation, retries successfully upon failpoint reset, and returns all dynamic extents cleanly.
