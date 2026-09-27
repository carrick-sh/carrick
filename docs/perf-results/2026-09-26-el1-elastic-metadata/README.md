# EL1 Elastic Metadata Allocator, Dynamic Extent Grants, and Bounded Reclamation

## Overview

This directory documents the design, verification evidence, structural operation bounds, and host-guest grant lifecycle for the EL1 kernel metadata allocator in `carrick-el1` and `carrick-vmm-hvf`.

The dormant non-reclaiming bump allocator has been replaced by a bounded segregated-fit metadata allocator supporting:
1. **$O(1)$ Allocation and Deallocation:** 28 segregated size classes with bitmap indexing and intrusive doubly-linked lists.
2. **$O(1)$ Bidirectional Coalescing:** Boundary tag headers and footers merge contiguous free blocks immediately upon deallocation.
3. **Authenticated Dynamic Extent Growth:** When capacity is exhausted, the allocator requests 512 KiB extent grants from the host hypervisor via `HVC #6` (`METADATA_GRANT_OP_ALLOC`).
4. **Exact-Once Extent Return:** When an extent's live allocation count reaches zero and its free block coalesces to full extent size, it is unlinked in $O(1)$ and returned to the host via `HVC #6` (`METADATA_GRANT_OP_FREE`). No linear scans over historically freed extents exist.
5. **Safe Lock/IRQ Behavior:** IRQ state is preserved (`disable_irq_save`/`restore_irq`) during lock critical sections, and the allocator spinlock is explicitly released before issuing host hypercalls.
6. **Refusal Recovery:** Host grant denial preserves prior allocations and metadata without corruption or resource leaks, enabling subsequent valid transactions to succeed.

---

## Allocator Data Structure and Operations

### Size Classes and Bin Indexing
- 28 segregated size bins covering block sizes from 32 B to 4 MiB.
- A `u32` bitmap tracks non-empty bins. Selecting the smallest fitting non-empty bin is an $O(1)$ operation using `trailing_zeros` over the masked bitmap.
- Each bin maintains an intrusive doubly-linked list of `BlockHeader` structures. Unlinking and pushing to a bin are $O(1)$ pointer updates.

### Boundary Tags and Coalescing
- Every block is preceded by a 32-byte `BlockHeader` and followed by an 8-byte `BlockFooter`.
- The header records `size`, `is_free`, `prev_free`, `next_free`, `extent_idx`, and `magic`.
- The footer records `size` and `is_free`.
- Coalescing checks adjacent left and right blocks using physical addresses and footer/header tags in $O(1)$ time.

### Extent Table and Exact-Once Return
- A fixed table of 128 `ExtentDescriptor` entries tracks admitted memory regions.
- The bootstrap metadata region is registered at index 0 (`0x0070_0000..0x0100_0000`, 9 MiB).
- Dynamic extents are admitted in the aperture `0x2D_0800_0000..0x2D_0C00_0000` (up to 64 MiB).
- Each `BlockHeader` stores the 8-bit `extent_idx` of its containing extent. On `deallocate`, the extent is retrieved in $O(1)$ without searching.
- When an extent's `live_allocations` drops to 0 and its full capacity is free, the block is unlinked from the free bins and returned to the host.

### Operation Bounds & Memory at Scale

| Scale (Extents) | Descriptor Table Memory | Free Bins Memory | Extent Capacity | Max Search Operations | Extent Lookup Operations |
|---|---|---|---|---|---|
| 1 | 32 B | 448 B | 9 MiB (bootstrap) | $O(1)$ (1 bitwise op) | $O(1)$ (direct index) |
| 8 | 256 B | 448 B | 12.5 MiB | $O(1)$ (1 bitwise op) | $O(1)$ (direct index) |
| 32 | 1,024 B | 448 B | 24.5 MiB | $O(1)$ (1 bitwise op) | $O(1)$ (direct index) |
| 128 | 4,096 B | 448 B | 72.5 MiB | $O(1)$ (1 bitwise op) | $O(1)$ (direct index) |

Total fixed descriptor state size is 4,548 bytes across all scales.

---

## Lock and IRQ Safety Protocol

- Allocator state is wrapped in `MetadataStorage` protected by a spinlock.
- **IRQ Masking with State Preservation:** `disable_irq_save` reads current `DAIF` flags, disables IRQs, and returns the previous state; `restore_irq` restores the exact flags.
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
  - Output: `x0 = status` (0 = SUCCESS, 1 = DENIED, 2 = INVALID_PARAM), `x1 = extent_base_ipa`, `x2 = granted_size`
- **Return Extent (`METADATA_GRANT_OP_FREE = 2`):**
  - Input: `x0 = 2`, `x1 = extent_base_ipa`, `x2 = extent_size`
  - Output: `x0 = status` (0 = SUCCESS, 1 = DENIED, 2 = INVALID_PARAM)

### Host Processing (`carrick-vmm-hvf::metadata_grant`)
- Validates that `extent_base_ipa` and `size` align to 4 KiB page boundaries and fall strictly within the guest dynamic metadata range `0x2D_0800_0000..0x2D_0C00_0000`.
- Verifies that new grants do not overlap existing active extents and that returned extents match an active grant.
- Dynamic stage-2 mapping is established via `inventory_hv_vm_map` and torn down via `inventory_hv_vm_unmap`.
- Tracks host counters: `grants_requested`, `grants_succeeded`, `grants_denied`, `returns_completed`, `bytes_granted`, and `bytes_returned`.
- Supports test failpoint injection via `arm_deny_next_metadata_grant()`.

---

## Verification Evidence

### VM-Free Unit Tests (`crates/carrick-el1/src/alloc.rs`)
1. `test_basic_allocation_and_free`: Validates 8-byte alignment, non-overlapping spans, and payload pattern integrity.
2. `test_fragmentation_coalescing_and_reuse`: Validates that freeing non-adjacent blocks coalesces upon neighbor deallocation and allows a large contiguous block to be reallocated.
3. `test_extent_admission_validation_and_overlap_rejection`: Validates that unaligned, out-of-range, and overlapping extents are rejected at admission.
4. `test_dynamic_growth_and_exact_once_return`: Validates that exhaustion triggers dynamic extent callbacks and full deallocation returns the extent exactly once.
5. `test_grant_refusal_preserves_state_and_allows_subsequent_retry`: Validates that when a grant fails, existing allocations remain valid and intact, and subsequent retries succeed.
6. `test_bounded_operations_and_bytes_at_scales_1_8_32_128`: Validates operation bounds and descriptor state sizes across 1, 8, 32, and 128 extent scales.

### Embed Integration Test (`crates/carrick-embed/tests/el1_sched.rs`)
- `el1_metadata_allocator_grows_and_returns_extents`: Signed guest execution fixture exercising real guest allocation beyond the 9 MiB bootstrap region, verifying host grant/return counters and failpoint recovery.
