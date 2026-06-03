# Stage-1 Page-Table Manager + EL1 TLBI Trampoline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make guest `mprotect`, `PROT_NONE`, and `munmap` change *guest-visible* memory semantics by editing the EL1 stage-1 page tables at runtime and flushing the stage-1 TLB via a Carrick-owned EL1 maintenance trampoline — so a guest access to a `PROT_NONE`/unmapped range faults during EL0 execution (not only on host-side `read_bytes` checks).

**Architecture:** Carrick owns the EL1 stage-1 page tables (`stage1_identity_page_tables`, block-mapped identity at boot) and the guest EL1 vector/trampoline pages in the kernel hole. This plan adds: (1) a `PageTableManager` that parses/splits/coalesces descriptors and flips AP/UXN/PXN/validity over a sub-range, operating on the page-table region's host backing; (2) a stage-2-writable page-table region at boot; (3) a tiny EL1 maintenance trampoline (`dsb ish; tlbi vmalle1is; dsb ish; isb; hvc #1`) that Carrick runs on its own vCPU — after quiescing siblings — to make descriptor edits guest-observable (arm64 public HVF has no stage-2 TLBI, but Carrick owns stage-1); (4) syscall wiring so `mprotect`/`PROT_NONE` mmap/`munmap` edit descriptors + flush. Fault→signal delivery already exists (`deliver_fault_signal`, runtime.rs), so a newly-invalid descriptor produces a real guest SIGSEGV for free.

**Tech Stack:** Rust, Apple Hypervisor.framework (`applevisor`/`applevisor_sys`), aarch64 stage-1 long-descriptor format, `parking_lot`. Crate: `crates/carrick-runtime`.

**Spec:** `docs/superpowers/specs/2026-05-26-durable-memory-architecture-design.md` (decomposition items 2 + 3, combined per user direction).

---

## Already-done precondition (verify, do not re-implement)

Fault→signal delivery exists end to end:
- `run_until_syscall` surfaces non-SVC EL0 synchronous exceptions as `TrapError::EL0Fault { syndrome, elr, far, .. }` (trap.rs:1286).
- The vCPU loop routes `EL0Fault` to `deliver_fault_signal` (runtime.rs:1516) → `el0_fault_signal(esr)` → SIGSEGV/SIGBUS with handler/altstack/restorer, else terminate(128+signum) (runtime.rs:1937+).

Verification step (run before Phase D): confirm an unmapped-access fault already yields SIGSEGV. A guest that stores to an unmapped IPA (e.g. `0x70_0000_0000`, between the mmap arena top and the shared aperture) should terminate with signal 11, NOT panic the runtime. This proves the fault path; this plan only adds the *cause* (invalid stage-1 descriptors for `PROT_NONE`/`munmap`).

---

## File Structure

- **Create:** `crates/carrick-runtime/src/page_table.rs` — `PageTableManager`: parse the boot table image, walk to a leaf, split blocks to finer granularity, set/clear validity + AP/UXN/PXN for a `[va, va+len)` sub-range, coalesce. Pure logic over a `&mut [u8]` view of the table region + a bump page allocator for new tables within the region's spare pages. Unit-tested without HVF.
- **Modify:** `crates/carrick-runtime/src/memory.rs` — grow `LINUX_PAGE_TABLES_SIZE` to reserve spare pages for runtime-allocated sub-tables; make the page-table region writable (`perms.write = true`); add `LINUX_EL1_MAINT_BASE` trampoline page + `el1_maintenance_bytes()` in the kernel hole; add the maintenance page to the kernel regions; widen the kernel hole's stage-1 kernel block if needed to cover it.
- **Modify:** `crates/carrick-runtime/src/trap.rs` — boot: keep a host pointer to the page-table region for runtime edits; add `run_el1_maintenance()` (set PC=maint base + EL1h PSTATE, run, expect `hvc #1`, restore EL0 state); extend `run_until_syscall` HVC handling to recognize `hvc #1` as maintenance-complete; add `GuestMemory` methods `protect_range`/`unmap_range` that edit descriptors via `PageTableManager` then flush.
- **Modify:** `crates/carrick-runtime/src/runtime.rs` — quiesce siblings around a page-table mutation (reuse `fork_quiesce` machinery), then call the engine flush.
- **Modify:** `crates/carrick-runtime/src/dispatch/mem.rs` — `mprotect`, `PROT_NONE` mmap, and `munmap` (private arena) call the new descriptor-edit path.
- **Modify:** `crates/carrick-runtime/src/lib.rs` — `mod page_table;`.
- **Create:** `fixtures/linux-aarch64-hello/src/mprotect_fault.rs` + wire into `scripts/build-linux-fixtures.sh` — guest probe: `mprotect(PROT_NONE)` a page then read it, expecting SIGSEGV.

---

## Phase B — PageTableManager (pure logic, no HVF)

The aarch64 stage-1 long descriptor (4 KiB granule, 40-bit IPA) used by `stage1_identity_page_tables`:
- Levels L0→L1→L2→L3; L0/L1/L2 entries are either *table* descriptors (`bits[1:0]=0b11`, next-level table PA in bits[47:12]) or *block* descriptors (`bits[1:0]=0b01`, leaf). L3 entries are *page* descriptors (`bits[1:0]=0b11`, leaf).
- Index math: `l0 = (va>>39)&0x1ff`, `l1=(va>>30)&0x1ff`, `l2=(va>>21)&0x1ff`, `l3=(va>>12)&0x1ff`.
- Leaf attribute bits (from memory.rs constants): valid=bit0, AF=bit10, SH=bits[9:8], AttrIndex=bits[4:2], AP=bits[7:6] (AP[2:1]), PXN=bit53, UXN=bit54.
- `USER_BLOCK_FLAGS = 0x2001_0441`, `USER_PAGE_FLAGS = USER_BLOCK_FLAGS | 0b10`. PROT_NONE ⇒ clear valid bit (cleanest: an invalid descriptor faults on any access, giving SEGV_MAPERR). Read-only ⇒ AP=0b11 (read-only EL0+EL1... actually AP[2:1]: 0b01=RW both, 0b11=RO both); no-exec ⇒ UXN=1.

### Task B1: descriptor + index helpers

**Files:**
- Create: `crates/carrick-runtime/src/page_table.rs`
- Modify: `crates/carrick-runtime/src/lib.rs`

- [ ] **Step 1: register module** — add `pub(crate) mod page_table;` in `lib.rs` (alphabetical, near `pub(crate) mod shared_aperture;`).

- [ ] **Step 2: write failing tests** for index extraction + leaf-bit edits. Create `page_table.rs` with:

```rust
//! Runtime editor for the EL1 stage-1 identity page tables. Splits coarse
//! block descriptors to finer granularity and flips validity / AP / UXN for a
//! guest VA sub-range, operating on the host-backed bytes of the page-table
//! region (`LINUX_PAGE_TABLES_BASE`). HVF never sees these edits until the
//! caller runs the EL1 TLBI maintenance trampoline (see `trap.rs`).

/// Per-level table index for `va` (4 KiB granule, 40-bit IPA).
pub(crate) fn indices(va: u64) -> [usize; 4] {
    [
        ((va >> 39) & 0x1ff) as usize,
        ((va >> 30) & 0x1ff) as usize,
        ((va >> 21) & 0x1ff) as usize,
        ((va >> 12) & 0x1ff) as usize,
    ]
}

const VALID: u64 = 1 << 0;
const TABLE: u64 = 0b11; // valid + table/page bit
const AP_RO: u64 = 0b11 << 6; // AP[2:1]=0b11 read-only EL0+EL1
const AP_MASK: u64 = 0b11 << 6;
const UXN: u64 = 1 << 54;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn indices_decompose_va() {
        // VA in the mmap arena: 0x60_0000_0000 = 384 GiB.
        let i = indices(0x60_0000_0000);
        assert_eq!(i[0], 0); // < 512 GiB
        assert_eq!(i[1], 0x60_0000_0000 >> 30 & 0x1ff);
    }
    #[test]
    fn clearing_valid_makes_descriptor_fault() {
        let desc: u64 = 0x2001_0441 | VALID;
        let invalid = desc & !VALID;
        assert_eq!(invalid & VALID, 0);
    }
    #[test]
    fn setting_ap_ro_marks_read_only() {
        let desc: u64 = 0x2001_0441; // AP=0b01 (RW)
        let ro = (desc & !AP_MASK) | AP_RO;
        assert_eq!(ro & AP_MASK, AP_RO);
    }
}
```

- [ ] **Step 3:** `cargo test -p carrick-runtime --lib page_table::` → PASS (helpers compile, asserts hold). Suppress dead-code on constants used in later tasks with module-level test usage or `#[allow(dead_code)]` where needed.

- [ ] **Step 4: Commit** `feat(mem): page-table descriptor + index helpers`.

### Task B2: `PageTableManager` over a byte view + spare-page allocator

- [ ] **Step 1: failing test** — construct a manager over a copy of `stage1_identity_page_tables()` bytes, call `set_prot_none(va, len)` for a 4 KiB range inside the mmap arena (currently a 1 GiB block), and assert: (a) the L1 block was split into an L2 (and L2→L3 as needed) so only the targeted 4 KiB page's descriptor has `valid=0`, (b) neighbouring pages remain valid RW, (c) a spare page was consumed from the reserved tail.

```rust
#[test]
fn set_prot_none_splits_block_and_invalidates_only_target() {
    let bytes = crate::memory::stage1_identity_page_tables();
    let mut mgr = PageTableManager::new(bytes, crate::memory::LINUX_PAGE_TABLES_BASE);
    let va = crate::memory::LINUX_MMAP_BASE + 0x10_0000; // arbitrary arena page
    mgr.set_prot_none(va, 0x1000).expect("split+invalidate");
    assert!(!mgr.is_valid(va), "target page must be invalid");
    assert!(mgr.is_valid(va + 0x1000), "next page stays mapped");
    assert!(mgr.is_valid(va - 0x1000), "prev page stays mapped");
}
```

- [ ] **Step 2:** run → FAIL (no `PageTableManager`).

- [ ] **Step 3: implement** `PageTableManager`:
  - Holds `bytes: Vec<u8>` (the region image), `base: u64` (LINUX_PAGE_TABLES_BASE → PA of byte offset 0), and `next_free_page` cursor into the reserved spare pages (region size minus the 5 boot pages).
  - `read_desc(offset)` / `write_desc(offset, u64)` — little-endian 8-byte access; `offset = (table_pa - base)` + `index*8`.
  - `walk_to_pte(va, allocate: bool)` — descend L0→L3; when a level holds a *block* descriptor and we need finer granularity, allocate a new table page, fill it with `512` block/page descriptors that reproduce the parent block's mapping+attrs at the finer stride, then overwrite the parent with a table descriptor pointing at the new page. Return the byte offset of the final leaf descriptor.
  - `set_prot_none(va, len)` / `set_readonly(va, len)` / `set_rw(va, len)` / `invalidate(va, len)` — for each 4 KiB page in range, `walk_to_pte(va, allocate=true)` then edit bits (clear VALID for prot_none/invalidate; AP for ro; restore USER_PAGE_FLAGS for rw).
  - `is_valid(va)` — `walk_to_pte(va, allocate=false)` then test VALID (test helper).
  - `into_bytes()` — return the edited image for copying back to the host region.
  - On spare-page exhaustion return `Err(PageTableError::OutOfTables)` (maps to ENOMEM).

  (Reuse the exact `*_FLAGS` constants and PA masks from `memory.rs`; expose them `pub(crate)` from `memory.rs` if not already, or re-declare with a unit test asserting they equal the `memory.rs` values to prevent drift.)

- [ ] **Step 4:** run the B2 test + a coalesce/round-trip test → PASS.

- [ ] **Step 5: Commit** `feat(mem): PageTableManager split/invalidate/protect over table image`.

### Task B3: split/coalesce + restore edge cases

- [ ] Tests + impl: splitting a 2 MiB block; `set_rw` after `set_prot_none` returns the page to USER_PAGE_FLAGS; invalidating then restoring a full 2 MiB block coalesces back to a block descriptor (free the sub-table); `OutOfTables` when spare pages exhausted. Commit.

---

## Phase C — Boot: writable PT region + EL1 maintenance trampoline page

### Task C1: reserve spare table pages + make PT region writable

**Files:** `crates/carrick-runtime/src/memory.rs`

- [ ] Grow `LINUX_PAGE_TABLES_SIZE` from `0x8000` (5 pages used of 8) to a size that reserves a runtime sub-table pool (e.g. `0x40000` = 64 pages: 5 boot + 59 spare; 59×2 MiB-or-finer splits is ample for arena churn). Update the `with_stage1_page_tables` region and the `stage1_identity_page_tables` emitter to zero-fill the spare tail (invalid descriptors). Set the region `perms.write = true` so the stage-2 mapping is RW and host descriptor edits are visible to the MMU table-walker. Add a unit test asserting the region size and that boot pages are unchanged.
- [ ] Confirm the kernel hole's stage-1 kernel block (2 MiB at `LINUX_KERNEL_REGION_BASE`) still covers `LINUX_PAGE_TABLES_BASE + LINUX_PAGE_TABLES_SIZE`; if the larger size crosses 2 MiB, extend the kernel-only mapping (it already maps the first 2 MiB block of the hole; `0x20000 + 0x40000 = 0x60000` < `0x200000`, so it still fits — assert this in a test). Commit.

### Task C2: EL1 maintenance trampoline page

**Files:** `crates/carrick-runtime/src/memory.rs`

- [ ] Add `LINUX_EL1_MAINT_BASE = LINUX_KERNEL_REGION_BASE + 0x30000` (one HVF page, inside the kernel hole, PXN=0 so EL1 can fetch). Add `el1_maintenance_bytes()` emitting:
  ```
  dsb ish        ; 0xd5033b9f
  tlbi vmalle1is ; 0xd508831f  (IS variant; confirm encoding)
  dsb ish        ; 0xd5033b9f
  isb            ; 0xd5033fdf
  hvc #1         ; 0xd4000022  (imm16=1 → maintenance-complete marker, distinct from the #0 syscall-forward path)
  ```
  followed by `nop` padding. Add the page to the kernel regions builder (it lives in the kernel hole, so the existing kernel block already maps it; just emit the bytes into a `MemoryRegion` at `LINUX_EL1_MAINT_BASE`). Unit-test the opcodes (mirror the `stage1_tests`/vector-byte tests). Commit.

---

## Phase C2 — EL1 maintenance run mechanism (HVF)

### Task C3: `run_el1_maintenance()` + run-loop `hvc #1` handling

**Files:** `crates/carrick-runtime/src/trap.rs`

- [ ] Store the page-table region host pointer + a `PageTableManager`-shaped editing surface on `HvfInner` at boot (find the page-table region in `self.mappings` by `start == LINUX_PAGE_TABLES_BASE`; keep its `host_addr`).
- [ ] Add `fn run_el1_maintenance(&mut self) -> Result<(), TrapError>`:
  1. Snapshot current `PC`, `CPSR`, and `ELR_EL1`/`SPSR_EL1` and the GPRs the trampoline never touches (the trampoline uses none, but save PC/PSTATE).
  2. Set `Reg::PC = LINUX_EL1_MAINT_BASE`; set `Reg::CPSR` to EL1h with DAIF masked (`0x3c5`: M[3:0]=0b0101 EL1h, DAIF set). TTBR0/SCTLR/MAIR/TCR are already programmed from boot and persist.
  3. Loop `self.vcpu.run()`; on `ExitReason::EXCEPTION` with HVC syndrome whose `imm16 == 1` (add `is_aarch64_hvc_maintenance(syndrome)`), break — maintenance done. Any other exit during maintenance is a hard error (per spec: stop the process rather than resume with ambiguous memory).
  4. Restore the snapshot (`PC`, `CPSR`); the guest resumes exactly where it was.
- [ ] Extend `run_until_syscall`'s HVC branch (trap.rs:1268) so a stray `hvc #1` outside maintenance is treated as an error, not a syscall. Add the `imm16` decode helper next to `is_aarch64_hvc_exception`.
- [ ] No standalone unit test (needs HVF); covered by the Phase D integration fixture. Commit.

---

## Phase D — Wire syscalls + quiesce + integration

### Task D1: `GuestMemory::protect_range` / `unmap_range`

**Files:** `crates/carrick-runtime/src/trap.rs`, `crates/carrick-runtime/src/dispatch/mod.rs`

- [ ] Add trait methods (default no-op for the in-memory test backend, matching the `set_no_access` pattern):
  ```rust
  fn protect_range(&mut self, address: u64, len: usize, prot: u64) -> Result<(), MemoryError>;
  fn unmap_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError>;
  ```
- [ ] Implement on `HvfInner`/`HvfTrapEngine`: edit the page-table image via `PageTableManager` (prot=0 ⇒ `set_prot_none`; RO ⇒ `set_readonly`; RW(X) ⇒ `set_rw`; unmap ⇒ `invalidate`), copy the changed pages back to the host page-table backing, then `run_el1_maintenance()`. Keep the existing `set_no_access` host-side bookkeeping in sync (so syscall-buffer EFAULT still works for the same ranges). Commit.

### Task D2: quiesce around mutation

**Files:** `crates/carrick-runtime/src/runtime.rs`

- [ ] When a `mprotect`/`munmap`/`PROT_NONE` mmap reaches the engine edit under the multi-threaded runtime, quiesce siblings first using the existing `fork_quiesce` barrier (`set_quiescing` + `kick_all_except` + `wait_quiesced`), perform the edit+flush on the calling vCPU, then release. Single-threaded path skips the barrier. (Mirror `handle_fork`'s quiesce; factor a small `with_siblings_quiesced(|| …)` helper if clean.) Commit.

### Task D3: dispatcher wiring

**Files:** `crates/carrick-runtime/src/dispatch/mem.rs`

- [ ] `mprotect`: after validating prot, call `cx.memory.protect_range(addr, len, prot)` (in addition to the existing `set_no_access` for PROT_NONE). `mmap` PROT_NONE anon: call `protect_range(addr,len,0)` after allocation. `munmap` (private arena branch): call `cx.memory.unmap_range(addr, len)` so the freed range faults until reused (reuse path restores RW + zeroes). Return ENOMEM on `OutOfTables`, EINVAL on bad input. Commit.

### Task D4: integration fixture + HVF verification

**Files:** `fixtures/linux-aarch64-hello/src/mprotect_fault.rs`, `scripts/build-linux-fixtures.sh`

- [ ] Add a raw-syscall Rust fixture (mirror `madvise.rs`/`shared_mmap_fork.rs`): `mmap(MAP_PRIVATE|MAP_ANON, RW)` a page, write to it (succeeds), `mprotect(PROT_NONE)`, install a SIGSEGV handler via `rt_sigaction` that `_exit(0)`s (or use SA_SIGINFO to check si_addr), then read the page — expect the handler to fire. exit 0 iff SIGSEGV was delivered at the faulting page. Wire into `build-linux-fixtures.sh`.
- [ ] Build signed (`./scripts/build-signed.sh -p carrick-cli`), build fixtures, run under `carrick run-elf --raw`. Expected: handler fires, exit 0.
- [ ] Regression: rerun `shared_mmap_fork` (exit 0), `debian:stable /bin/ls` (works), and `cargo test -p carrick-runtime --lib` (green). Measure peak RSS — must not regress (sub-table pool is demand-zero). Commit.

---

## Self-Review

**Spec coverage (items 2 + 3):**
- "descriptor split/coalesce" → Phase B (B2/B3).
- "guest-visible PROT_NONE/unmapped faults" → Phase D (D1/D3 edit descriptors invalid) + already-done `deliver_fault_signal` (precondition).
- "tests for mmap/munmap/mprotect" → B unit tests + D4 fixture.
- "quiesce integration" → D2 (reuse fork_quiesce).
- "whole-ASID flush first" → C2 (`tlbi vmalle1is`), C3 run mechanism. Range TLBI deferred (spec allows).
- Spec §"Carrick-owned stage-1 TLBI interface" steps 1-4 → D2 quiesce, D1 write+flush, C3 trampoline, restore+resume.
- Spec failure handling: "maintenance trampoline fails to complete → stop the process" → C3 treats non-`hvc #1` exits during maintenance as hard error. "ENOMEM on split/alloc failure, EINVAL on bad input" → B2 `OutOfTables` + D3.

**Placeholder scan:** opcode encodings flagged "confirm encoding" must be verified against an assembler during C2 (assemble `tlbi vmalle1is`/`hvc #1` and compare) — do not ship guessed encodings.

**Type consistency:** `PageTableManager::{new,set_prot_none,set_readonly,set_rw,invalidate,is_valid,into_bytes}`; `protect_range(addr,len,prot)` / `unmap_range(addr,len)` used identically in trait, impl, and dispatcher.

**Risk notes:** This mutates live page tables and runs guest EL1 code on demand — both novel. The EL1 maintenance run (C3) is the linchpin; if `run_el1_maintenance` mis-restores PSTATE/PC it wedges the vCPU. Verify C3 in isolation (a no-op edit + flush on a single-threaded guest that then continues to exit 0) before D2's multi-threaded path. Keep `git` checkpoints per task for easy revert.
