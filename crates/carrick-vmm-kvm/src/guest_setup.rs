//! Guest bring-up for the KVM MVP: load the freestanding ELF into a host mmap,
//! reuse carrick-mem's architectural stage-1 / trampoline builders, install a
//! tiny EL1 vector whose lower-EL-sync slot STORES TO A SENTINEL gpa (the MMIO
//! trap vehicle) instead of HVF's `hvc #2`, and program the system registers
//! WITHOUT the Apple-Silicon FEAT_PAN3 / PSTATE.PAN=1 workaround.
// On x86_64, the aarch64-specific items (EL1 vector builders, bring_up,
// program_sysregs, BroughtUp) are cfg-gated.  Suppress dead_code/unused-import
// warnings on x86_64 to keep `cargo clippy -- -D warnings` clean.
#![cfg_attr(not(target_arch = "aarch64"), allow(dead_code, unused_imports))]
use std::sync::{Arc, RwLock};

use carrick_hal::{HvVcpu, HvVm, MemPerms, OsError, Reg, SysReg};
use carrick_mem::memory::{
    AddressSpace, LINUX_EL0_TRAMPOLINE_BASE, LINUX_EL1_MAINT_BASE, LINUX_EL1_VECTORS_BASE,
    LINUX_EL1_VECTORS_SIZE, LINUX_NULL_GUARD_END, LINUX_PAGE_TABLES_BASE,
    stage1_identity_page_tables, va_in_shared_aperture,
};
use carrick_mem::protections::MemoryProtections;

use crate::kvm::{KvmVcpu, KvmVm};

/// Guest-physical address the EL1 vector stores to on an EL0 `svc`.
///
/// Requirements: it must be (a) **stage-1 identity-mapped** (so the EL1 store
/// translates), yet (b) left UNMAPPED in every KVM memory region (so the access
/// faults out as `KVM_EXIT_MMIO { gpa: SENTINEL_GPA, .. }` — the trap vehicle).
///
/// 320 GiB satisfies both: the stage-1 identity map covers 0..512 GiB with
/// 1 GiB user blocks (`stage1_identity_page_tables`), and 320 GiB sits in the
/// gap between the heap (`LINUX_HEAP_BASE` = 256 GiB, +128 MiB) and the mmap
/// arena (`LINUX_MMAP_BASE` = 384 GiB), so it is never a real carrick region.
/// It is also far above the backed RAM window (which ends at the kernel hole,
/// ~180 GiB), so the store always faults to stage-2 / MMIO.
///
/// NOTE: it must NOT be `LINUX_HEAP_BASE` (256 GiB) — that collides with the
/// guest heap region.
pub const SENTINEL_GPA: u64 = 0x50_0000_0000; // 320 GiB

/// Guest-physical address the EL1 vector stores to on an EL0 *fault* (a data /
/// instruction abort or alignment fault, as opposed to an `svc`). Distinct from
/// [`SENTINEL_GPA`] so the host distinguishes a syscall trap from a fault trap
/// by the MMIO `gpa` alone. Same dual constraints as SENTINEL_GPA: stage-1
/// identity-mapped yet UNMAPPED in every KVM slot. 324 GiB sits in the same
/// heap/mmap gap (between 320 GiB SENTINEL and 384 GiB `LINUX_MMAP_BASE`), so
/// the store always faults to stage-2 / MMIO.
pub const FAULT_SENTINEL_GPA: u64 = 0x51_0000_0000; // 324 GiB

/// Guest-physical address the EL1 stage-1 MAINTENANCE trampoline stores to once
/// it has flushed the stage-1 TLB. Same dual constraints as [`SENTINEL_GPA`]:
/// stage-1 identity-mapped (so the EL1 store translates) yet UNMAPPED in every
/// KVM slot (so it faults out as `KVM_EXIT_MMIO { gpa: MAINT_SENTINEL_GPA, .. }`
/// — the completion vehicle). 328 GiB sits in the same heap/mmap gap as the
/// other two sentinels (between 324 GiB FAULT_SENTINEL and 384 GiB
/// `LINUX_MMAP_BASE`), so the store always faults to stage-2 / MMIO.
///
/// This is the KVM analogue of HVF's `hvc #1` maintenance-complete marker: KVM
/// runs the guest with PSCI 0.2 enabled, so a guest `hvc` traps to EL2 and is
/// consumed by KVM's PSCI/SMCCC handler (an unknown function-id is reflected
/// back to the guest, NOT surfaced as a userspace exit) — it would never reach
/// us. The MMIO sentinel store is the SAME proven mechanism the syscall/fault
/// vectors use, so the maintenance run uses it too instead of `hvc #1`.
pub const MAINT_SENTINEL_GPA: u64 = 0x52_0000_0000; // 328 GiB

/// Base of the KVM alias-GPA arena: a free identity hole between the private
/// overlay (608+2 GiB) and the stack (~1 TiB), within the 40-bit nested-KVM IPA
/// limit (lima reports `IPA Size Limit: 40 bits`). A guest `mmap(MAP_SHARED, fd)`
/// (or other [`carrick_mem::memory::is_high_va`] alias) gets a dispatcher-chosen
/// VA >= `LINUX_HIGH_VA_THRESHOLD` (1 TiB), which exceeds the IPA limit and so
/// cannot itself be a KVM GPA. KVM instead backs it with a slot at
/// `KVM_ALIAS_GPA_BASE + (va - LINUX_HIGH_VA_THRESHOLD)` — a deterministic,
/// collision-free low GPA (the dispatcher's alias VAs are already unique and span
/// exactly `LINUX_ALIAS_IPA_SIZE`), and maps VA -> that GPA in stage-1. HVF, with
/// its own per-region `hv_vm_map`, uses the dispatcher's low IPA directly; this is
/// the KVM-specific stage-2 glue.
pub(crate) const KVM_ALIAS_GPA_BASE: u64 = 0xA0_0000_0000; // 640 GiB
/// Size of the KVM alias-GPA arena. Matches `LINUX_ALIAS_IPA_SIZE` (64 GiB) so the
/// VA->GPA delta always lands in-arena; ends at 704 GiB, well below the stack.
pub(crate) const KVM_ALIAS_GPA_SIZE: u64 = 0x10_0000_0000; // 64 GiB

/// KVM memory-slot alignment. `KVM_SET_USER_MEMORY_REGION` requires the
/// guest-physical base and size to be a multiple of the HOST page size; 64 KiB
/// covers every aarch64 host granule (4K/16K/64K). The high guest regions are
/// already ≥ 64 KiB-aligned, so this only rounds the (16 KiB) sigreturn window
/// up — harmless extra lazy backing.
const KVM_SLOT_ALIGN: u64 = 0x10000;

fn align_down_slot(addr: u64) -> u64 {
    addr & !(KVM_SLOT_ALIGN - 1)
}

fn align_up_slot(addr: u64) -> Result<u64, OsError> {
    addr.checked_add(KVM_SLOT_ALIGN - 1)
        .map(|a| a & !(KVM_SLOT_ALIGN - 1))
        .ok_or_else(|| OsError::new(format!("kvm: region end 0x{addr:x} overflows on align")))
}

/// Copy ONLY the RESIDENT pages of `[src, src+scan)` into `dst` (which must back
/// `total` >= `scan` bytes). Used by the `vfork(2)` shadow seed + copy-back so a
/// multi-GB window doesn't fault in every untouched page (the OOM-`SIGKILL` a
/// naive `memcpy` causes). `mincore` reports which of `src`'s pages are resident
/// WITHOUT committing them; non-resident pages are left untouched in `dst` (lazily
/// zero under `MAP_NORESERVE` — correct, since the parent never touched them
/// either). On `mincore` failure, fall back to copying the bounded `scan` prefix
/// in full (correct, just less sparse). Mirrors HVF's `clone_region_for_child`.
fn copy_resident_pages(src: *const u8, dst: *mut u8, scan: usize, total: usize) {
    if scan == 0 {
        return;
    }
    let page = {
        let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if p <= 0 { 4096usize } else { p as usize }
    };
    let n_pages = scan.div_ceil(page);
    let mut resident = vec![0u8; n_pages];
    // Linux `mincore` vec arg is `*mut c_uchar` (u8); resident[] is u8.
    let rc = unsafe {
        libc::mincore(
            src as *mut libc::c_void,
            scan,
            resident.as_mut_ptr() as *mut libc::c_uchar,
        )
    };
    if rc != 0 {
        // mincore failed — copy the bounded prefix in full (still bounded by
        // `scan`, so the arena's used-prefix bound keeps this from OOMing).
        // SAFETY: `src`/`dst` each back at least `total` >= `scan` bytes.
        unsafe { std::ptr::copy_nonoverlapping(src, dst, scan.min(total)) };
        return;
    }
    for (i, &flag) in resident.iter().enumerate() {
        if flag & 1 != 0 {
            let off = i * page;
            let len = page.min(total - off);
            // SAFETY: `off + len <= total`; both pointers back `total` bytes and
            // the mappings are distinct (non-overlapping).
            unsafe { std::ptr::copy_nonoverlapping(src.add(off), dst.add(off), len) };
        }
    }
}

// The aarch64 vector table layout (matches carrick-mem's el1_vectors_bytes):
// 16 slots * 0x80 bytes; the lower-EL synchronous slot is at offset 0x400.
const AARCH64_VECTOR_SLOT_SIZE: u64 = 0x80;
const AARCH64_VECTOR_LOWER_EL_SYNC_OFFSET: u64 = 0x400;
const AARCH64_ERET_OPCODE: u32 = 0xd69f_03e0;
const AARCH64_NOP_OPCODE: u32 = 0xd503_201f;

// Encoders for the sentinel store sequence. The sentinel store needs a scratch
// register holding the sentinel GPA (`str x8, [x9]`), and we use x9. But the
// Linux aarch64 syscall ABI PRESERVES x1..x30 across an `svc` (the kernel
// saves/restores the full register frame), and real code relies on it — e.g.
// musl's `__expand_heap` keeps its malloc-context pointer in x9 across the
// `brk(2)` svc, then does `str x10, [x9, #920]` AFTER. So the vector first SAVES
// x9 to `TPIDR_EL1` (a per-vCPU EL1 sysreg carrick does NOT otherwise use on KVM:
// the guest runs at EL0 and uses TPIDR_EL0 for TLS), and `complete_syscall`
// restores x9 from it on the way out. (glibc happened never to hold a live x9
// across an svc, which masked this for a long time; musl/alpine exposed it.)
fn enc_movz_x9(imm16: u16, hw: u32) -> u32 {
    0xD280_0009 | (hw << 21) | (u32::from(imm16) << 5)
}
fn enc_movk_x9(imm16: u16, hw: u32) -> u32 {
    0xF280_0009 | (hw << 21) | (u32::from(imm16) << 5)
}
// `str x8, [x9]` — store the syscall number to the sentinel (any store works).
const ENC_STR_X8_X9: u32 = 0xf900_0128;
// `msr tpidr_el1, x9` — save the guest's live x9 before the vector clobbers it as
// the sentinel-store scratch (see the comment above). Assembled via GNU `as`.
const ENC_MSR_TPIDR_EL1_X9: u32 = 0xd518_d089;

// EL0-fault discriminator opcodes. The lower-EL-sync slot is entered by BOTH an
// EL0 `svc` AND an EL0 synchronous fault (data/instruction abort, alignment),
// because KVM/arm64 vectors a guest EL0 abort to the guest's own VBAR_EL1 — it
// is NOT a KVM_RUN exit. So the slot must read ESR_EL1, extract the exception
// class, and branch to a SECOND (fault) sentinel store when it is not an svc;
// otherwise a fault would be mishandled as a syscall and re-fault forever.
// These four opcodes were verified against the GNU assembler (`as`) and are
// re-asserted by the `lower_el_sync_slot_*` test below.
const ENC_MRS_X9_ESR_EL1: u32 = 0xd538_5209; // mrs  x9, esr_el1
const ENC_UBFX_X9_X9_EC: u32 = 0xd35a_7d29; // ubfx x9, x9, #26, #6  (EC = ESR[31:26])
const ENC_CMP_X9_SVC: u32 = 0xf100_553f; // cmp  x9, #0x15  (subs xzr, x9, #EC_SVC64)
const ENC_BNE_FAULT: u32 = 0x5400_00e1; // b.ne +7 instructions -> the fault block

/// Build the EL1 vector page: every slot is `eret`, except the lower-EL sync
/// slot which materialises SENTINEL_GPA in x9 and stores there (-> MMIO exit),
/// then `eret`. Mirrors carrick-mem's `el1_vectors_bytes` shape but with the
/// sentinel store in place of `hvc #2`.
pub fn el1_vectors_sentinel_bytes() -> Vec<u8> {
    let size = LINUX_EL1_VECTORS_SIZE as usize;
    let mut bytes = vec![0u8; size];
    let put = |b: &mut [u8], off: usize, op: u32| {
        b[off..off + 4].copy_from_slice(&op.to_le_bytes());
    };
    // Fill all 16 slots with eret + nop padding.
    let mut slot = 0u64;
    while slot < 16 * AARCH64_VECTOR_SLOT_SIZE && (slot as usize) < size {
        let base = slot as usize;
        put(&mut bytes, base, AARCH64_ERET_OPCODE);
        let mut c = base + 4;
        while c + 4 <= base + AARCH64_VECTOR_SLOT_SIZE as usize {
            put(&mut bytes, c, AARCH64_NOP_OPCODE);
            c += 4;
        }
        slot += AARCH64_VECTOR_SLOT_SIZE;
    }
    // Overwrite the lower-EL sync slot. It is entered by an EL0 `svc` AND by an
    // EL0 synchronous fault, so it discriminates on ESR.EC: EC == 0x15 (SVC64)
    // takes the syscall path (store to SENTINEL_GPA); anything else is a fault
    // and takes the fault path (store to FAULT_SENTINEL_GPA). 17 instructions,
    // well within the 0x80 (32-instruction) slot.
    //
    // s+0 SAVES the guest's x9 to TPIDR_EL1 BEFORE clobbering it (the ABI
    // preserves x9; see the encoder comment). `complete_syscall` restores it.
    // The `mrs x9, esr_el1` then MUST run before any sentinel store: that store
    // is itself a stage-2 MMIO abort, but because it does NOT take an EL1
    // exception it leaves ESR_EL1/FAR_EL1 holding the ORIGINAL EL0-fault values
    // for the host to read. The b.ne jumps +7 instructions to the fault block, so
    // the fault block MUST stay exactly 7 instructions after it (the test asserts
    // this) — the +1 leading `msr` shifts BOTH paths uniformly, so +7 is intact.
    let s = AARCH64_VECTOR_LOWER_EL_SYNC_OFFSET as usize;
    // movz x9, gpa[0]; movk x9, gpa[1..4] — materialize a 64-bit gpa into x9.
    let materialize = |b: &mut [u8], off: usize, g: u64| {
        put(b, off, enc_movz_x9((g & 0xFFFF) as u16, 0));
        put(b, off + 4, enc_movk_x9(((g >> 16) & 0xFFFF) as u16, 1));
        put(b, off + 8, enc_movk_x9(((g >> 32) & 0xFFFF) as u16, 2));
        put(b, off + 12, enc_movk_x9(((g >> 48) & 0xFFFF) as u16, 3));
    };
    // Save x9 (s+0), then the ESR.EC discriminator (s+4 .. s+16).
    put(&mut bytes, s, ENC_MSR_TPIDR_EL1_X9); //   msr  tpidr_el1, x9  (save live x9)
    put(&mut bytes, s + 4, ENC_MRS_X9_ESR_EL1); // mrs  x9, esr_el1
    put(&mut bytes, s + 8, ENC_UBFX_X9_X9_EC); //  ubfx x9, x9, #26, #6  (x9 = EC)
    put(&mut bytes, s + 12, ENC_CMP_X9_SVC); //    cmp  x9, #0x15
    put(&mut bytes, s + 16, ENC_BNE_FAULT); //     b.ne fault_block (+7)
    // SVC path (EC == 0x15), s+20 .. s+40: re-materialize x9 (clobbered by the
    // mrs) with SENTINEL_GPA, store, eret.
    materialize(&mut bytes, s + 20, SENTINEL_GPA);
    put(&mut bytes, s + 36, ENC_STR_X8_X9); //     str x8, [x9]  (host: gpa == SENTINEL_GPA)
    put(&mut bytes, s + 40, AARCH64_ERET_OPCODE); // eret
    // FAULT path (EC != 0x15), s+44 .. s+64: store to FAULT_SENTINEL_GPA so the
    // host captures ESR/FAR/ELR and delivers a guest signal, then eret.
    materialize(&mut bytes, s + 44, FAULT_SENTINEL_GPA);
    put(&mut bytes, s + 60, ENC_STR_X8_X9); //     str x8, [x9]  (host: gpa == FAULT_SENTINEL_GPA)
    put(&mut bytes, s + 64, AARCH64_ERET_OPCODE); // eret
    bytes
}

// Stage-1 maintenance barrier/TLBI opcodes (verified against GNU `as`, and
// re-asserted by `maint_sentinel_bytes_*` below). These match carrick-mem's
// private `el1_maintenance_bytes` opcodes; redefined locally because the KVM
// variant ends in an MMIO sentinel store, not `hvc #1` (see MAINT_SENTINEL_GPA).
const ENC_DSB_SY: u32 = 0xd503_3f9f; // dsb sy
const ENC_TLBI_VMALLE1IS: u32 = 0xd508_831f; // tlbi vmalle1is (inner-shareable)
const ENC_ISB: u32 = 0xd503_3fdf; // isb

/// Build the EL1 stage-1 MAINTENANCE trampoline page for KVM. Carrick runs this
/// on its own vCPU (PC = [`carrick_mem::memory::LINUX_EL1_MAINT_BASE`], PSTATE =
/// EL1h-DAIF-masked) AFTER editing stage-1 page descriptors, to flush the stale
/// stage-1 TLB so the guest observes the new mapping. It is the KVM analogue of
/// carrick-mem's `el1_maintenance_bytes` (the HVF variant), differing ONLY in
/// the completion marker: HVF ends in `hvc #1` (traps EL1→EL2 → HVF exit), but
/// on KVM `hvc` is consumed by PSCI and never surfaces, so the KVM variant
/// materialises [`MAINT_SENTINEL_GPA`] into x9 and STORES there — the same
/// MMIO-exit completion vehicle the syscall/fault vectors use.
///
/// Register discipline: the trampoline clobbers x8 and x9 (the store value and
/// the sentinel-address scratch). The caller
/// (`Aarch64EngineCore::run_el1_maintenance`) SAVES and RESTORES x8 and x9 around the
/// run, exactly as it saves/restores PC/PSTATE/ELR_EL1/SPSR_EL1 — so the
/// in-flight (parked) syscall frame resumes unperturbed. The store value (x8) is
/// irrelevant to the host (only the gpa matters), so it is left as the
/// materialised gpa to avoid touching any other register.
///
/// `dsb sy; tlbi vmalle1is; dsb sy; isb` is the architectural sequence: make the
/// prior descriptor stores observable, drop all stage-1 TLB entries in the
/// inner-shareable domain (broadcasting to any PMR-paused sibling vCPUs), make
/// the invalidation observable, then resynchronise translation before the store.
pub fn el1_maintenance_sentinel_bytes() -> Vec<u8> {
    use carrick_mem::memory::LINUX_EL1_MAINT_SIZE;
    let size = LINUX_EL1_MAINT_SIZE as usize;
    let mut bytes = vec![0u8; size];
    let put = |b: &mut [u8], off: usize, op: u32| {
        b[off..off + 4].copy_from_slice(&op.to_le_bytes());
    };
    // dsb sy; tlbi vmalle1is; dsb sy; isb — flush the stage-1 TLB (inner-shareable).
    put(&mut bytes, 0, ENC_DSB_SY);
    put(&mut bytes, 4, ENC_TLBI_VMALLE1IS);
    put(&mut bytes, 8, ENC_DSB_SY);
    put(&mut bytes, 12, ENC_ISB);
    // movz/movk x9, MAINT_SENTINEL_GPA; str x8,[x9] — the completion MMIO store.
    put(
        &mut bytes,
        16,
        enc_movz_x9((MAINT_SENTINEL_GPA & 0xFFFF) as u16, 0),
    );
    put(
        &mut bytes,
        20,
        enc_movk_x9(((MAINT_SENTINEL_GPA >> 16) & 0xFFFF) as u16, 1),
    );
    put(
        &mut bytes,
        24,
        enc_movk_x9(((MAINT_SENTINEL_GPA >> 32) & 0xFFFF) as u16, 2),
    );
    put(
        &mut bytes,
        28,
        enc_movk_x9(((MAINT_SENTINEL_GPA >> 48) & 0xFFFF) as u16, 3),
    );
    put(&mut bytes, 32, ENC_STR_X8_X9); // str x8,[x9] -> KVM_EXIT_MMIO { gpa == MAINT_SENTINEL_GPA }
    // The MMIO store IS the exit: run_el1_maintenance stops the loop on the
    // MAINT_SENTINEL exit and never re-enters, so anything after it is dead. Pad
    // the rest with `nop` so an accidental over-run is harmless.
    let mut c = 36;
    while c + 4 <= size {
        put(&mut bytes, c, AARCH64_NOP_OPCODE);
        c += 4;
    }
    bytes
}

/// Whether the host `mmap` backing a guest-physical window is shared across
/// `fork(2)` (`MAP_SHARED`) or copy-on-write snapshotted (`MAP_PRIVATE`).
///
/// The KVM slot `flags` field is always `0` in both cases — KVM does not
/// distinguish; only the HOST mmap flags change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowKind {
    /// `MAP_PRIVATE`: copy-on-write on fork (image, heap, stack, page-tables,
    /// vectors, trampoline, private overlay).
    Private,
    /// `MAP_SHARED`: writes are visible across `fork(2)` — used for the
    /// boot-mapped shared aperture `[LINUX_SHARED_FILE_BASE,
    /// LINUX_SHARED_FILE_BASE + LINUX_SHARED_FILE_SIZE)` so that guest
    /// `MAP_SHARED` futex words survive the fork used by `clone(2)`.
    Shared,
}

/// Multi-window host-backed guest RAM. The MVP used a single low window; a real
/// binary additionally needs the high runtime regions (stack near 1 TiB,
/// heap @ 256 GiB, mmap arena @ 384 GiB, sigreturn @ 192 GiB), which sit far
/// above the low window and at sparse, huge GPAs. Each is its own `MAP_NORESERVE`
/// window (lazily committed) and its own KVM slot — discrete windows, NOT one
/// giant slot, so the SENTINEL gpa stays UNMAPPED (the MMIO trap vehicle relies
/// on it faulting to stage-2). All windows are MAP_PRIVATE for now (no fork; the
/// host-MAP_SHARED fork-coherence model is the full-backend Phase D work).
pub struct GuestRam {
    windows: Arc<RwLock<Vec<WindowDesc>>>,
    /// Guest-physical ranges the guest has made PROT_NONE (mmap(PROT_NONE)/
    /// mprotect/munmap). carrick backs the whole arena with accessible host
    /// memory, so a PROT_NONE buffer is otherwise readable on the syscall path —
    /// a guest passing such a buffer to a syscall must instead see EFAULT. This
    /// is the HOST-SIDE syscall-read check (cheap, no page tables). Making the
    /// GUEST itself fault mid-EL0 is the COMPLEMENTARY stage-1 path:
    /// `protect_range`/`unmap_range`/`unmap_alias_range` edit the live stage-1
    /// descriptors (via `Aarch64EngineCore::pt_edit_and_flush`,
    /// which also runs the EL1-maintenance TLBI so a RE-protect of an already-
    /// walked page takes effect) and the Phase-4 EL0-fault→SIGSEGV path delivers
    /// the resulting abort — so these are LIVE overrides, not no-ops.
    ///
    /// SHARED (`Arc`) with every sibling vCPU thread's `GuestRam`, exactly like
    /// HVF: a `clone(CLONE_VM)` thread group runs on one VM, so a `mprotect`
    /// made by any thread MUST be observed by every other thread's syscall-path
    /// checks. A per-thread copy diverges — one thread reserves a region
    /// PROT_NONE, another commits it, and the first then wrongly EFAULTs a valid
    /// buffer there (the Go-on-KVM `futexwakeup … EFAULT` crash). A `fork(2)`
    /// child gets an INDEPENDENT copy (the COW of the whole process duplicates
    /// the `Arc`'s target); `execve` starts fresh. The neutral-core type is
    /// shared with HVF: [`carrick_mem::protections::MemoryProtections`].
    protections: Arc<MemoryProtections>,
    /// Whether this `GuestRam` OWNS its window mmaps (and must `munmap` them on
    /// drop). `true` for the initial / fork-child / execve RAM. `false` for a
    /// `clone(CLONE_THREAD)` sibling's view (see [`Self::from_shared_windows`]):
    /// a sibling shares the SAME host mmaps as the parent thread (threads share
    /// the address space, no fork), so it must NEVER `munmap` them — the parent
    /// engine owns them and frees them at process exit. Double-`munmap` (or a
    /// sibling freeing pages a live parent vCPU still uses) would be UB.
    owns_windows: bool,
}

/// `munmap` the host backing of every window when the `GuestRam` is dropped.
///
/// For the long-lived initial / forked-child RAM this never fires in practice
/// (the engine lives for the process). It matters for
/// `Aarch64EngineCore::execve_into`, which REPLACES `self.ram`
/// with a fresh `GuestRam` for the new image: the OLD `GuestRam` drops here and
/// must release its host mmaps, or repeated execve would leak the prior image's
/// windows (heap/mmap-arena/stack near 1 TiB are huge VA reservations).
///
/// The caller MUST have unregistered the KVM slots backed by these windows
/// before the drop (execve does: `unmap_memory_slot` for each old slot first),
/// so no live vCPU references the pages being unmapped.
impl Drop for GuestRam {
    fn drop(&mut self) {
        // A non-owning sibling VIEW (`clone(CLONE_THREAD)`) must NOT free the
        // shared host mmaps — the owning parent does, at process exit.
        if !self.owns_windows {
            return;
        }
        let mut windows = self.windows.write().unwrap_or_else(|e| e.into_inner());
        for w in windows.iter() {
            // SAFETY: `host`..`host+len` is the mmap this window owns (created in
            // `add_window`); it is unmapped exactly once, on drop. KVM slots over
            // it were already deleted by the execve caller.
            unsafe {
                libc::munmap((w.host as *mut u8).cast::<libc::c_void>(), w.len);
            }
        }
        windows.clear();
    }
}

impl GuestRam {
    pub(crate) fn new() -> Self {
        Self {
            windows: Arc::new(RwLock::new(Vec::new())),
            protections: Arc::new(MemoryProtections::default()),
            owns_windows: true,
        }
    }

    /// The shared PROT_NONE bookkeeping handle, cloned into a `clone(CLONE_VM)`
    /// sibling so it observes this thread's `mprotect`s (and vice versa).
    pub(crate) fn shared_protections(&self) -> Arc<MemoryProtections> {
        Arc::clone(&self.protections)
    }

    /// Borrow the PROT_NONE set for the shared `GuestMemory::protections()` gate.
    pub(crate) fn protections_ref(&self) -> &MemoryProtections {
        &self.protections
    }

    /// Whether [gpa, gpa+len) overlaps any PROT_NONE range (so a syscall buffer
    /// there must fault with EFAULT). Delegates to the SHARED, process-wide
    /// [`MemoryProtections`] so a sibling thread's `mprotect` is visible here.
    pub(crate) fn range_no_access(&self, gpa: u64, len: usize) -> bool {
        self.protections.range_no_access(gpa, len)
    }

    /// Record (`no_access=true`) or clear (`false`) a PROT_NONE range on the
    /// SHARED bookkeeping (interior-mutable, so `&self`): the change is observed
    /// by every sibling vCPU thread's syscall-path access checks.
    pub(crate) fn set_no_access(&self, gpa: u64, len: usize, no_access: bool) {
        self.protections.set_no_access(gpa, len, no_access);
    }

    /// mmap `len` bytes (lazy, `MAP_NORESERVE`) to back guest-physical
    /// [base, base+len) and record the window. Refuses any window that would
    /// cover [`SENTINEL_GPA`] — that page MUST stay unmapped so the EL1 vector's
    /// sentinel store faults out as `KVM_EXIT_MMIO` (the syscall trap vehicle).
    ///
    /// `kind` selects the host mmap flags:
    /// - [`WindowKind::Private`] → `MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE`
    ///   (copy-on-write on fork; used for image/heap/stack/page-tables/vectors).
    /// - [`WindowKind::Shared`] → `MAP_SHARED|MAP_ANONYMOUS|MAP_NORESERVE`
    ///   (writes survive fork; used for the shared aperture so guest `MAP_SHARED`
    ///   futex words remain coherent across the `fork` used by `clone(2)`).
    ///
    /// The KVM slot `flags` field is always `0` regardless of `kind`.
    pub(crate) fn add_window(
        &mut self,
        base: u64,
        len: usize,
        kind: WindowKind,
    ) -> Result<(), OsError> {
        if len == 0 {
            return Ok(());
        }
        let end = base
            .checked_add(len as u64)
            .ok_or_else(|| OsError::new(format!("kvm: window 0x{base:x}+{len} overflows")))?;
        if (base <= SENTINEL_GPA && SENTINEL_GPA < end)
            || (base <= FAULT_SENTINEL_GPA && FAULT_SENTINEL_GPA < end)
            || (base <= MAINT_SENTINEL_GPA && MAINT_SENTINEL_GPA < end)
        {
            return Err(OsError::new(format!(
                "kvm: window 0x{base:x}..0x{end:x} would back a sentinel gpa \
                 (syscall 0x{SENTINEL_GPA:x} / fault 0x{FAULT_SENTINEL_GPA:x} / \
                 maint 0x{MAINT_SENTINEL_GPA:x}); all must stay unmapped"
            )));
        }
        let mmap_flags = match kind {
            WindowKind::Private => libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
            WindowKind::Shared => libc::MAP_SHARED | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
        };
        // SAFETY: anonymous mapping (no fd); we own it for the VM's life.
        // MAP_SHARED|MAP_ANONYMOUS is used for the shared aperture so that guest
        // MAP_SHARED futex words remain coherent across fork(2)/clone(2); KVM
        // slot flags stay 0 in both cases — only the host mmap flags change.
        let host = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                mmap_flags,
                -1,
                0,
            )
        };
        if host == libc::MAP_FAILED {
            return Err(OsError::new(format!(
                "kvm: guest RAM mmap failed for 0x{base:x}+{len}"
            )));
        }
        self.windows
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .push(WindowDesc {
                base,
                host: host.cast::<u8>() as usize,
                len,
                kind,
                slot_gpa: None,
            });
        Ok(())
    }

    /// Back a dynamic ALIAS mapping on the LIVE VM: host-mmap the backing (a
    /// `MAP_SHARED` dup'd fd for a guest `mmap(MAP_SHARED, fd)`, coherent across
    /// fork + other openers; or `MAP_PRIVATE|MAP_ANON` seeded with `payload`),
    /// register a NEW KVM memory slot at `gpa` (a low identity hole), and track
    /// the window keyed by the guest `va` (which differs from `gpa`). The caller
    /// then builds the VA->`gpa` stage-1 path via `map_aliased`. The host backing
    /// is owned by this `GuestRam` and `munmap`'d on drop. Mirrors HVF's
    /// `map_host_alias`, with a KVM slot in place of `hv_vm_map`.
    pub(crate) fn add_alias(
        &mut self,
        vm: &mut KvmVm,
        va: u64,
        gpa: u64,
        len: u64,
        backing: AliasBacking,
    ) -> Result<(), OsError> {
        let size = usize::try_from(align_up_slot(len)?)
            .map_err(|_| OsError::new(format!("kvm: alias len {len} too large")))?;
        // The slot GPA must never back a sentinel (the KVM alias arena sits at
        // 640..704 GiB, above both 320/324 GiB sentinels, but assert the contract).
        let gpa_end = gpa
            .checked_add(size as u64)
            .ok_or_else(|| OsError::new(format!("kvm: alias slot 0x{gpa:x}+{size} overflows")))?;
        if (gpa <= SENTINEL_GPA && SENTINEL_GPA < gpa_end)
            || (gpa <= FAULT_SENTINEL_GPA && FAULT_SENTINEL_GPA < gpa_end)
            || (gpa <= MAINT_SENTINEL_GPA && MAINT_SENTINEL_GPA < gpa_end)
        {
            return Err(OsError::new(format!(
                "kvm: alias slot 0x{gpa:x}..0x{gpa_end:x} would back a sentinel gpa"
            )));
        }
        let (host, kind) = match backing {
            AliasBacking::File { fd, offset, prot } => {
                // MAP_SHARED of the dup'd fd: writes hit the page cache (coherent
                // with other openers + across fork). We own the dup; mmap takes its
                // own reference, so close it once mapped.
                let h = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        size,
                        prot,
                        libc::MAP_SHARED,
                        fd,
                        offset,
                    )
                };
                unsafe { libc::close(fd) };
                if h == libc::MAP_FAILED {
                    return Err(OsError::new(format!(
                        "kvm: alias MAP_SHARED file (fd={fd} off={offset} size={size} prot={prot}) failed"
                    )));
                }
                (h.cast::<u8>(), WindowKind::Shared)
            }
            AliasBacking::Anon { payload } => {
                let h = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        size,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                        -1,
                        0,
                    )
                };
                if h == libc::MAP_FAILED {
                    return Err(OsError::new(format!(
                        "kvm: alias anon mmap size={size} failed"
                    )));
                }
                if !payload.is_empty() {
                    let n = payload.len().min(size);
                    unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), h.cast::<u8>(), n) };
                }
                (h.cast::<u8>(), WindowKind::Private)
            }
        };
        // Register the LIVE KVM slot at the alias GPA. On failure, unmap before
        // returning so we never leak the host backing.
        if let Err(e) = vm.map_memory(gpa, host, size, MemPerms::ReadWriteExec) {
            unsafe { libc::munmap(host.cast::<libc::c_void>(), size) };
            return Err(e);
        }
        self.windows
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .push(WindowDesc {
                base: va,
                host: host as usize,
                len: size,
                kind,
                slot_gpa: Some(gpa),
            });
        Ok(())
    }

    /// The window whose [base, base+len) wholly contains [gpa, gpa+len), with
    /// the host offset of `gpa` within it.
    fn locate(&self, gpa: u64, len: usize) -> Option<(WindowDesc, usize)> {
        self.windows
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find_map(|w| {
                let off = gpa.checked_sub(w.base)?;
                ((off as usize).checked_add(len)? <= w.len).then_some((*w, off as usize))
            })
    }

    /// Project each window into the neutral [`carrick_guest_mem::region::GuestMemoryRegion`]
    /// keyed on `WindowDesc::base` (the SAME value `locate` keys on — the guest-VA
    /// the host syscall path uses, NOT `slot_gpa`). Yielded BY VALUE so the gate
    /// can iterate without allocating; the `slot_gpa` <1 TiB-alias handling stays
    /// glue (it never enters the projection — `base` is always the lookup key).
    fn safe_access_projected(
        &self,
        va: u64,
        ipa: u64,
        len: usize,
    ) -> Result<*mut u8, carrick_guest_mem::region::GuestAccessError> {
        let windows = self.windows.read().unwrap_or_else(|e| e.into_inner());
        carrick_guest_mem::region::safe_guest_access_translated_in(
            |g, l| self.protections.range_no_access(g, l),
            windows
                .iter()
                .map(|w| carrick_guest_mem::region::GuestMemoryRegion {
                    base: w.base,
                    len: w.len,
                    host_addr: w.host as *mut u8,
                }),
            va,
            ipa,
            len,
        )
    }

    /// The COMBINED syscall-buffer gate: the PROT_NONE check THEN the single-
    /// region whole-range lookup, via the neutral
    /// [`carrick_guest_mem::region::safe_guest_access_translated_in`] (the
    /// recurrence guard shared with HVF/bhyve). Returns the host pointer to the
    /// buffer, or a [`carrick_guest_mem::region::GuestAccessError`] the caller
    /// maps to its `MemoryError`. Zero-alloc: windows are projected on the fly.
    /// The PROT_NONE predicate delegates to the shared, process-wide
    /// [`MemoryProtections`] so a sibling thread's `mprotect` is observed here.
    ///
    /// The PROT_NONE check and the window lookup use SEPARATE addresses: `va`
    /// (the guest's syscall pointer) for the PROT_NONE gate, and `ipa` (its
    /// stage-1 translation) for the backing lookup. For an identity VA the caller
    /// passes `ipa == va` and this is byte-identical to the pre-translation gate.
    /// For a `repoint_private` overlay (or a high-VA alias) `ipa != va`, so the
    /// copy lands in the PRIVATE overlay backing the guest's OWN loads/stores hit
    /// — while `mprotect(PROT_NONE)`, which records the guest VA, still faults
    /// EFAULT (it's keyed on `va`, NOT the translated `ipa`).
    pub(crate) fn safe_access_translated(
        &self,
        va: u64,
        ipa: u64,
        len: usize,
    ) -> Result<*mut u8, carrick_guest_mem::region::GuestAccessError> {
        // The stage-1 tables leave VA 0..LINUX_NULL_GUARD_END UNMAPPED (the
        // null guard = Linux's default vm.mmap_min_addr): the guest's OWN NULL
        // deref faults. The host syscall path must agree — KVM's flat low
        // identity window DOES back GPA 0, so without this gate a NULL syscall
        // buffer silently reads/writes that backing instead of EFAULTing (LTP
        // pipe05: pipe(NULL) must fail EFAULT). HVF gets this structurally
        // from its discrete per-region windows (no region covers VA 0).
        // Zero-length accesses stay exempt, matching HVF's `read_bytes`
        // zero-length short-circuit (`read(fd, NULL, 0)` returns 0 on Linux).
        if len > 0 && va < LINUX_NULL_GUARD_END {
            return Err(carrick_guest_mem::region::GuestAccessError::OutOfBounds);
        }
        self.safe_access_projected(va, ipa, len)
    }

    /// Like [`safe_access_translated`](Self::safe_access_translated) but WITHOUT the PROT_NONE gate — the shared
    /// default `GuestMemory::read_bytes`/`write_bytes` already ran it on the guest
    /// VA. Keeps the NULL-guard (a backing fact) + the IPA-translated single-region
    /// lookup. This is the backing-only path the `*_raw` trait methods call.
    pub(crate) fn safe_access_translated_raw(
        &self,
        va: u64,
        ipa: u64,
        len: usize,
    ) -> Result<*mut u8, carrick_guest_mem::region::GuestAccessError> {
        if len > 0 && va < LINUX_NULL_GUARD_END {
            return Err(carrick_guest_mem::region::GuestAccessError::OutOfBounds);
        }
        let windows = self.windows.read().unwrap_or_else(|e| e.into_inner());
        carrick_guest_mem::region::safe_guest_access_translated_in(
            // PROT_NONE gated in the default GuestMemory::read_bytes/write_bytes.
            |_g, _l| false,
            windows
                .iter()
                .map(|w| carrick_guest_mem::region::GuestMemoryRegion {
                    base: w.base,
                    len: w.len,
                    host_addr: w.host as *mut u8,
                }),
            va,
            ipa,
            len,
        )
    }

    /// Copy `data` to guest-physical `gpa` (must lie wholly within one window).
    /// `pub(crate)` so the `GuestMemory` impl on `crate::trap_engine::KvmTrapEngine`
    /// can service guest `write_bytes` through the same bounds-checked path
    /// bring-up uses; the guest VA is identity-mapped to this GPA.
    pub(crate) fn write_gpa(&mut self, gpa: u64, data: &[u8]) -> Result<(), OsError> {
        let (host, off) = {
            let (w, off) = self.locate(gpa, data.len()).ok_or_else(|| {
                OsError::new(format!("kvm: write gpa 0x{gpa:x} out of guest RAM"))
            })?;
            (w.host, off)
        };
        // SAFETY: bounds checked by `locate`; host points at `len` writable bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), (host as *mut u8).add(off), data.len());
        }
        Ok(())
    }

    /// Rebuild a fresh `KvmVm` + `KvmVcpu` over THIS `GuestRam`'s existing host
    /// mmaps — the child side of `Aarch64EngineCore::fork`.
    ///
    /// After `libc::fork`, the child's inherited KVM fds point at the PARENT's
    /// kernel VM and are useless, so the child opens `/dev/kvm` afresh
    /// (`KVM_CREATE_VM`), re-registers EVERY window in the SAME order / GPA /
    /// slot id over the COW-inherited host VAs (the `SENTINEL_GPA` hole stays
    /// unmapped), and creates a vCPU (`KVM_CREATE_VCPU` + preferred-target init,
    /// via [`KvmVm::add_vcpu`]). PRIVATE windows are the Linux-COW copies; the
    /// `MAP_SHARED` aperture re-registers the SAME (inherited) host pages, so its
    /// writes stay coherent across the fork. The vCPU is returned UNPROGRAMMED;
    /// the caller restores the parent's `Aarch64VcpuSnapshot` onto it.
    pub(crate) fn rebuild_vm_for_child(&self) -> Result<(KvmVm, KvmVcpu), OsError> {
        let mut vm = KvmVm::create_empty()?;
        let windows = self.windows.read().unwrap_or_else(|e| e.into_inner());
        for w in windows.iter() {
            // An ALIAS window's KVM slot lives at `slot_gpa` (a <1 TiB hole), NOT
            // at `w.base` (the guest VA, e.g. 1 TiB — at/above the 40-bit nested
            // IPA cap, which KVM rejects with EFAULT). Mirror the boot/sibling
            // registration path (`window_slots` -> `slot_gpa.unwrap_or(base)`); a
            // plain identity window has slot_gpa=None so this is `w.base`. Without
            // this, a fork AFTER a map_host_alias (e.g. `go build` exec'ing
            // `go tool compile`) crashed the child rebuild with
            // KVM_SET_USER_MEMORY_REGION(gpa=1 TiB): Bad address.
            vm.map_memory(
                w.slot_gpa.unwrap_or(w.base),
                w.host as *mut u8,
                w.len,
                MemPerms::ReadWriteExec,
            )?;
        }
        let vcpu = vm.add_vcpu()?;
        Ok((vm, vcpu))
    }

    /// `vfork(2)` (`CLONE_VM|CLONE_VFORK`) PARENT, PRE-`libc::fork` half.
    ///
    /// A `Private` (COW) window is NOT shared across `fork(2)` — the child's guest
    /// writes land in its own copy, invisible to the suspended parent, so the
    /// CLONE_VM "writes visible to the parent" contract breaks (the `vforkvmshare`
    /// gap). HVF gets sharing for free because its guest RAM is host-`MAP_SHARED`;
    /// KVM's is host-`MAP_PRIVATE` (deliberate, so an ordinary fork COWs for free).
    ///
    /// Bridge the two WITHOUT making the parent's long-lived RAM shared (which
    /// would break the parent's NEXT ordinary fork): for every `Private` window
    /// allocate a `MAP_SHARED|MAP_ANONYMOUS` SHADOW of the same length, seed it
    /// with the window's current contents, and return the shadow list. The CHILD
    /// re-registers its KVM slots over the shadows ([`Self::rebuild_vm_for_child_vfork`]),
    /// so the child's guest writes hit the shared shadow; the parent — SUSPENDED
    /// for the whole vfork window — copies the shadow back into its private window
    /// on resume ([`Self::finish_vfork_parent`]), making the child's writes visible.
    ///
    /// `Shared` windows (the futex aperture, file aliases) already survive fork
    /// coherently, so they carry NO shadow (the child maps the inherited host page
    /// as-is, exactly like an ordinary fork).
    ///
    /// NOTE on page tables: HVF keeps the stage-1 page-table BACKING private even
    /// for a vfork child (defense-in-depth against a pre-execve child PT edit
    /// corrupting the suspended parent). On the x86 KVM layout the PML4/CR3 backing
    /// is FUSED into the low identity window (trampoline + GDT + PML4 + low image),
    /// so it cannot be excluded without splitting that window. This is sound for a
    /// LEGAL vfork-for-exec child — the only thing it may do is `execve`/`_exit`,
    /// neither of which edits page tables (execve rebuilds a fresh VM + tables),
    /// and the parent is SUSPENDED for the whole window — exactly the Go `os/exec`
    /// / glibc `posix_spawn` shape this targets.
    ///
    /// `arena_high_water` is the guest's mmap-arena high-water (the runtime
    /// publishes it pre-fork). The seed copy is **mincore-gated**: only RESIDENT
    /// pages are copied into the shadow (the rest stay lazily zero under
    /// `MAP_NORESERVE`), and the residency scan over the 32 GiB arena window is
    /// bounded to `[LINUX_MMAP_BASE, arena_high_water)`. A naive full-window memcpy
    /// would FAULT IN every byte of every window — committing the whole multi-GB
    /// arena → OOM-`SIGKILL` (the exact failure this gates against). This mirrors
    /// the HVF child-snapshot `clone_region_for_child`.
    pub(crate) fn prepare_vfork_shadows(
        &self,
        arena_high_water: u64,
    ) -> Result<VforkShadows, OsError> {
        let windows = self.windows.read().unwrap_or_else(|e| e.into_inner());
        let mut shadows = Vec::new();
        for w in windows.iter() {
            if w.kind != WindowKind::Private {
                continue;
            }
            // SAFETY: anonymous MAP_SHARED mapping we own for the vfork window; the
            // child maps over it and the parent munmaps it in finish_vfork_parent.
            let shadow = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    w.len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                    -1,
                    0,
                )
            };
            if shadow == libc::MAP_FAILED {
                // Roll back the shadows already mapped, then signal failure so the
                // caller degrades to a plain (non-suspending) fork rather than
                // sharing nothing.
                for s in &shadows {
                    let s: &VforkShadow = s;
                    unsafe { libc::munmap(s.shadow as *mut libc::c_void, s.len) };
                }
                return Err(OsError::new(format!(
                    "kvm: vfork shadow mmap failed for window 0x{:x}+{}",
                    w.base, w.len
                )));
            }
            // Seed the shadow with the window's RESIDENT contents (only) so the
            // child sees the parent's pre-fork state without committing untouched
            // arena/heap/stack pages. The arena window's scan is bounded to the
            // used prefix; other windows scan in full (they are small).
            let scan = if w.base == carrick_mem::memory::LINUX_MMAP_BASE {
                arena_high_water
                    .saturating_sub(w.base)
                    .min(w.len as u64)
                    .try_into()
                    .unwrap_or(w.len)
            } else {
                w.len
            };
            copy_resident_pages(w.host as *const u8, shadow as *mut u8, scan, w.len);
            shadows.push(VforkShadow {
                base: w.base,
                slot_gpa: w.slot_gpa,
                private_host: w.host,
                shadow: shadow as usize,
                len: w.len,
            });
        }
        Ok(VforkShadows { shadows })
    }

    /// `vfork(2)` CHILD, POST-`libc::fork` half: rebuild a fresh `KvmVm` + `KvmVcpu`
    /// like [`Self::rebuild_vm_for_child`], but register every `Private` window's
    /// KVM slot over its SHARED SHADOW (so the child's guest writes are visible to
    /// the parent), and re-point the window's `host` at the shadow so the child's
    /// syscall-buffer `read`/`write`/`host_ptr` see the same shared bytes. `Shared`
    /// windows keep their inherited host page (already fork-coherent). The shadows
    /// are owned by the parent's `VforkShadows`; the child must NOT munmap them —
    /// it detaches on execve (a fresh VM) or `_exit` (process death).
    pub(crate) fn rebuild_vm_for_child_vfork(
        &self,
        shadows: &VforkShadows,
    ) -> Result<(KvmVm, KvmVcpu), OsError> {
        let mut vm = KvmVm::create_empty()?;
        let mut windows = self.windows.write().unwrap_or_else(|e| e.into_inner());
        for w in windows.iter_mut() {
            // A Private window registers over its shadow (shared with the parent);
            // a Shared window keeps the inherited host page (already coherent).
            let host = shadows
                .shadow_for(w.base, w.slot_gpa)
                .inspect(|&s| w.host = s)
                .unwrap_or(w.host);
            vm.map_memory(
                w.slot_gpa.unwrap_or(w.base),
                host as *mut u8,
                w.len,
                MemPerms::ReadWriteExec,
            )?;
        }
        drop(windows);
        let vcpu = vm.add_vcpu()?;
        Ok((vm, vcpu))
    }

    /// `vfork(2)` PARENT, on RESUME (the child has execve'd or `_exit`ed, so the
    /// shared window is quiescent — the parent was suspended for the whole window).
    /// Copy each shadow's RESIDENT pages back into the parent's private window, so
    /// the child's shared writes become visible to the parent (CLONE_VM), then
    /// release the shadows. The copy-back is mincore-gated for the same reason the
    /// seed is: only pages the child actually touched (made resident in the shared
    /// shadow) are copied — a full copy-back would fault in every untouched arena
    /// page in the PARENT, re-introducing the OOM. Idempotent against an empty
    /// `VforkShadows` (pipe-failure degrade path).
    pub(crate) fn finish_vfork_parent(&self, shadows: VforkShadows) {
        for s in &shadows.shadows {
            // Copy back only the shadow's resident pages (what the child wrote).
            copy_resident_pages(
                s.shadow as *const u8,
                s.private_host as *mut u8,
                s.len,
                s.len,
            );
            // SAFETY: `shadow` is the mapping we created in prepare_vfork_shadows;
            // it is unmapped exactly once here (the child never owned/freed it).
            unsafe { libc::munmap(s.shadow as *mut libc::c_void, s.len) };
        }
    }

    /// Read `len` bytes of LIVE guest memory at guest-physical `gpa` (so guest
    /// writes are visible). `gpa` must lie wholly within one backed window — e.g.
    /// a `write(2)` buffer the guest passed in `x1`.
    pub fn read(&self, gpa: u64, len: usize) -> Result<Vec<u8>, OsError> {
        let (w, off) = self.locate(gpa, len).ok_or_else(|| {
            OsError::new(format!("kvm: read gpa 0x{gpa:x}+{len} out of guest RAM"))
        })?;
        let mut out = vec![0u8; len];
        // SAFETY: bounds checked by `locate`; host points at `len` readable bytes.
        unsafe {
            std::ptr::copy_nonoverlapping((w.host as *mut u8).add(off), out.as_mut_ptr(), len);
        }
        Ok(out)
    }

    /// Diagnostic: describe why an access at `[gpa, gpa+len)` would (not) resolve
    /// — the located window or the nearest windows, plus no_access state. Gated
    /// callers only (CARRICK_MEM_DEBUG); allocates, so never on the hot path.
    pub(crate) fn debug_access(&self, gpa: u64, len: usize) -> String {
        let located = self.locate(gpa, len).is_some();
        let no_access = self.range_no_access(gpa, len);
        // The PROT_NONE intervals straddling (or within ~16 MiB of) the access,
        // so a stale-reserve vs genuine-uncommitted range is distinguishable.
        let near: Vec<String> = self
            .protections
            .snapshot()
            .into_iter()
            .filter(|&(s, e)| {
                e > gpa.saturating_sub(0x100_0000) && s < gpa.saturating_add(0x100_0000)
            })
            .map(|(s, e)| format!("[0x{s:x}..0x{e:x})"))
            .collect();
        let windows = self.windows.read().unwrap_or_else(|e| e.into_inner());
        let mut wins: Vec<String> = windows
            .iter()
            .map(|w| {
                format!(
                    "[0x{:x}..0x{:x} {:?}{}]",
                    w.base,
                    w.base + w.len as u64,
                    w.kind,
                    w.slot_gpa
                        .map(|g| format!(" slot_gpa=0x{g:x}"))
                        .unwrap_or_default()
                )
            })
            .collect();
        wins.sort();
        format!(
            "gpa=0x{gpa:x} len={len} located={located} no_access={no_access} \
             no_access_ranges_near={} windows({})={}",
            if near.is_empty() {
                "(none)".to_string()
            } else {
                near.join(" ")
            },
            windows.len(),
            wins.join(" ")
        )
    }

    /// Host virtual address of the `len`-byte span at guest-physical `gpa`,
    /// regardless of window kind, or `None` if it does not lie wholly within one
    /// backed window. Used by the live stage-1 page-table editor to `sync_to_host`
    /// changed descriptors straight into the guest's page-table backing (at
    /// `LINUX_PAGE_TABLES_BASE`, in the low window). Unlike
    /// [`Self::shared_futex_host_addr`], this does NOT require a `Shared` window.
    pub(crate) fn host_ptr(&self, gpa: u64, len: usize) -> Option<*mut u8> {
        let (w, off) = self.locate(gpa, len)?;
        // SAFETY: `locate` proved [gpa, gpa+len) ⊆ this window, so `host + off`
        // points at `len` valid bytes of that window's backing.
        Some(unsafe { (w.host as *mut u8).add(off) })
    }

    /// Host virtual address of the `len`-byte word at guest-physical `gpa`, but
    /// ONLY when it lies wholly within a `WindowKind::Shared` window (the
    /// boot-mapped `MAP_SHARED|MAP_ANONYMOUS` aperture). That backing is the SAME
    /// physical page in parent and child across `fork(2)`, so it is a valid
    /// target for a bare host `SYS_futex` cross-process rendezvous (see
    /// `crate::kvm_futex::KvmFutex::shared_wait`). Returns `None` for a word in
    /// a `Private` (COW) window — those futexes stay in-process via the parking-
    /// lot [`carrick_thread::thread::FutexTable`]. The guest is identity-mapped
    /// (VA == GPA), so the dispatcher passes the guest futex VA straight in.
    pub fn shared_futex_host_addr(&self, gpa: u64, len: usize) -> Option<usize> {
        let (w, off) = self.locate(gpa, len)?;
        if w.kind != WindowKind::Shared {
            return None;
        }
        // SAFETY: `locate` proved [gpa, gpa+len) ⊆ this window, so `host + off`
        // points at `len` valid bytes of the shared aperture backing.
        Some(unsafe { (w.host as *mut u8).add(off) } as usize)
    }
}

/// Result of bring-up: a VM + a vCPU initialised to the EL1 trampoline, ready
/// for the trap engine to drive. `ram` is kept alive (its mmap backs KVM).
/// Result of the aarch64 KVM bring-up. The x86_64 analogue is `BroughtUpX86`
/// in `guest_setup_x86.rs` (Task 2).
#[cfg(target_arch = "aarch64")]
pub struct BroughtUp {
    pub vm: KvmVm,
    pub vcpu: KvmVcpu,
    pub ram: GuestRam,
    pub entry: u64,
}

/// The low window covers the user image's low segments AND the kernel region
/// (EL0 trampoline / EL1 vectors / stage-1 page tables) at 180 GiB.
const KERNEL_HOLE_END: u64 = 0x2D_0020_0000; // LINUX_KERNEL_REGION_BASE + 2 MiB

impl GuestRam {
    /// Build a fresh `GuestRam` over a freshly-`mmap`'d set of host windows for
    /// `image`, and write the image segments + the architectural bring-up pages
    /// (EL0 trampoline / stage-1 identity tables / EL1 sentinel vectors) into
    /// them. This is the shared "lay out the guest physical RAM for an image"
    /// step used by BOTH the initial [`bring_up`] and
    /// `Aarch64EngineCore::execve_into` — execve replaces the
    /// guest image in place by building a new `GuestRam` here and re-registering
    /// its windows on the LIVE VM (the slots having first been unmapped).
    ///
    /// It does NOT touch any KVM object (no slot registration, no vCPU
    /// programming) — those steps differ between bring-up (fresh VM) and execve
    /// (live VM remap), so the caller drives them via [`Self::windows_for_kvm`]
    /// and [`program_sysregs`].
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn build_for_image(image: &AddressSpace) -> Result<Self, OsError> {
        let mut ram = GuestRam::new();
        // Low window covers image segments + kernel-region pages; always private
        // (image text/data/bss are per-process, not shared across fork).
        ram.add_window(0, KERNEL_HOLE_END as usize, WindowKind::Private)?;

        // 1. ELF + runtime regions (identity GPA == region.start). `load_elf`
        //    also appends the guest's high runtime reservations (sigreturn @
        //    192 GiB, heap @ 256 GiB, mmap arena @ 384 GiB, shared aperture @
        //    576 GiB, private overlay @ 608 GiB), and `with_linux_initial_stack`
        //    appends the stack near 1 TiB. Low regions land in the low window;
        //    each HIGH region (>= KERNEL_HOLE_END) gets its own MAP_NORESERVE
        //    window + KVM slot, page-aligned and lazily committed. (`add_window`
        //    refuses any window that would back the unmapped SENTINEL gpa.)
        //
        //    WindowKind is derived from the MemoryRegion's `shared` flag:
        //    - `shared: true`  → MAP_SHARED (the boot-mapped shared aperture)
        //    - `shared: false` → MAP_PRIVATE (all other regions)
        //    The KVM slot `flags` field stays 0 in both cases.
        for region in image.regions() {
            if region.start < KERNEL_HOLE_END {
                let bytes = region.bytes();
                if !bytes.is_empty() {
                    ram.write_gpa(region.start, bytes)?;
                }
                continue;
            }
            let base = align_down_slot(region.start);
            let end = align_up_slot(region.end)?;
            // Derive kind from carrick-mem's `shared` flag, cross-checked against
            // the shared-aperture address range. Both must agree: if a region is
            // marked shared it must lie in the shared aperture, and vice versa.
            debug_assert_eq!(
                region.shared,
                va_in_shared_aperture(base, end - base),
                "region.shared / shared-aperture address mismatch at 0x{base:x}"
            );
            let kind = if region.shared {
                WindowKind::Shared
            } else {
                WindowKind::Private
            };
            ram.add_window(base, (end - base) as usize, kind)?;
            let bytes = region.bytes();
            if !bytes.is_empty() {
                ram.write_gpa(region.start, bytes)?;
            }
        }
        // 2. Architectural bring-up pages (low window). The per-ISA trampoline
        //    bytes come from the engine's GuestArch (the x86_64 seam); free
        //    function, so name the engine explicitly (as `program_sysregs`).
        use carrick_hal::GuestArch as _;
        ram.write_gpa(
            LINUX_EL0_TRAMPOLINE_BASE,
            &<crate::trap_engine::KvmTrapEngine as carrick_hal::ThreadedEngine>::Arch::entry_trampoline_bytes(),
        )?;
        // Seed pristine boot tables ONLY when the image did not carry its own
        // stage-1 region: `with_stage1_page_tables` now bakes the ELF images'
        // read-only spans (.text/.rodata write protection) into the region
        // bytes the loop above already wrote — overwriting them here with the
        // pristine identity image would silently strip that enforcement.
        let image_carries_stage1 = image
            .regions()
            .iter()
            .any(|region| region.start == LINUX_PAGE_TABLES_BASE && !region.bytes().is_empty());
        if !image_carries_stage1 {
            ram.write_gpa(LINUX_PAGE_TABLES_BASE, &stage1_identity_page_tables())?;
        }
        // 3. Our sentinel vector (NOT carrick-mem's hvc #2 variant).
        ram.write_gpa(LINUX_EL1_VECTORS_BASE, &el1_vectors_sentinel_bytes())?;
        // 4. Our stage-1 MAINTENANCE trampoline (NOT carrick-mem's hvc #1
        //    variant). The canonical AddressSpace already placed `el1_maintenance_
        //    bytes()` (the HVF `hvc #1` version) at LINUX_EL1_MAINT_BASE via the
        //    region loop above; OVERWRITE it with the KVM MMIO-sentinel variant so
        //    run_el1_maintenance's flush completes via a KVM_EXIT_MMIO instead of an
        //    `hvc` that PSCI would swallow. The page is inside the kernel hole's
        //    first 2 MiB block, so stage-1 maps it EL1-executable (AP=00/UXN=1/
        //    PXN=0) — runnable at EL1 by construction.
        ram.write_gpa(LINUX_EL1_MAINT_BASE, &el1_maintenance_sentinel_bytes())?;
        Ok(ram)
    }

    /// Iterate every window as `(base, host, len)` for `KVM_SET_USER_MEMORY_REGION`
    /// registration, in slot order. Used by both bring-up and execve to publish
    /// the windows onto a (fresh or live) VM via [`KvmVm::map_memory`].
    pub(crate) fn windows_for_kvm(&self) -> Vec<(u64, *mut u8, usize)> {
        // An alias window registers its KVM slot at `slot_gpa` (a low identity
        // hole), NOT `base` (its high guest VA); an ordinary window has base==gpa.
        self.windows
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|w| (w.slot_gpa.unwrap_or(w.base), w.host as *mut u8, w.len))
            .collect()
    }

    /// Shared, `Send`-safe descriptors of this RAM's host-backed windows.
    /// `clone(CLONE_THREAD)` siblings receive the SAME handle, so high-VA alias
    /// windows added by any thread are immediately visible to every sibling's
    /// syscall-buffer path.
    pub(crate) fn window_descriptors(&self) -> Arc<RwLock<Vec<WindowDesc>>> {
        Arc::clone(&self.windows)
    }

    /// Build a NON-OWNING `GuestRam` view over windows another thread owns (a
    /// `clone(CLONE_THREAD)` sibling). The windows alias the SAME host mmaps the
    /// parent engine owns; this view records them so the sibling's `read`/`write`
    /// syscall-buffer path works, but its `Drop` is a NO-OP (`owns_windows =
    /// false`) — only the owning parent `munmap`s, at process exit. `no_access`
    /// starts empty: the sibling shares the parent's address space, but the
    /// HOST-SIDE PROT_NONE bookkeeping is per-engine (a future Phase-4 concern);
    /// the MVP threads fixture touches no PROT_NONE buffers.
    /// Build a NON-OWNING sibling view over the parent's window descriptors,
    /// SHARING the parent's PROT_NONE bookkeeping (`protections`) so the sibling
    /// observes the parent's (and every other sibling's) `mprotect`s — and they
    /// observe its. A fresh per-thread set would diverge (the Go-on-KVM EFAULT
    /// crash); see [`MemoryProtections`]'s sharing contract.
    pub(crate) fn from_shared_windows(
        windows: Arc<RwLock<Vec<WindowDesc>>>,
        protections: Arc<MemoryProtections>,
    ) -> Self {
        Self {
            windows,
            protections,
            owns_windows: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_window_views_observe_late_insertions() {
        let mut parent = GuestRam::new();
        parent
            .add_window(0x1000, 0x1000, WindowKind::Private)
            .expect("initial window");
        let sibling =
            GuestRam::from_shared_windows(parent.window_descriptors(), parent.shared_protections());

        assert!(sibling.host_ptr(0x1000, 1).is_some());

        parent
            .add_window(0x9000, 0x1000, WindowKind::Private)
            .expect("late window");
        assert!(
            sibling.host_ptr(0x9000, 1).is_some(),
            "sibling views must observe high-VA aliases added after clone"
        );
    }
}

/// A `Send` descriptor of one host-backed guest window, used to hand a
/// `clone(CLONE_THREAD)` sibling a view of the SAME backing across host threads.
/// `host` is a `usize` (not `*mut u8`) so the enclosing sibling-spec is `Send`;
/// it is the same host VA in every thread of the process (no fork involved).
#[derive(Debug, Clone, Copy)]
pub(crate) struct WindowDesc {
    pub base: u64,
    pub host: usize,
    pub len: usize,
    pub kind: WindowKind,
    /// Alias windows: the KVM-slot GPA (differs from `base`). `None` for ordinary
    /// identity windows.
    pub slot_gpa: Option<u64>,
}

/// One `Private` window's `vfork(2)` SHARED SHADOW (see
/// [`GuestRam::prepare_vfork_shadows`]). `private_host` is the parent's
/// (COW-private) window backing; `shadow` is the `MAP_SHARED` mapping the child
/// registers its KVM slot over. The window is identified by `(base, slot_gpa)`
/// (the same key the rebuild registration uses).
pub(crate) struct VforkShadow {
    base: u64,
    slot_gpa: Option<u64>,
    private_host: usize,
    shadow: usize,
    len: usize,
}

/// The set of `vfork(2)` shadows a vfork parent prepared pre-`libc::fork`. Carried
/// across the fork (the child consults it in `rebuild_vm_for_child_vfork`; the
/// parent reconciles + releases it in `finish_vfork_parent`).
pub(crate) struct VforkShadows {
    shadows: Vec<VforkShadow>,
}

impl VforkShadows {
    /// Whether any window has a shadow (false on the pipe-failure degrade path).
    pub(crate) fn is_empty(&self) -> bool {
        self.shadows.is_empty()
    }

    /// The shadow host pointer for the window keyed by `(base, slot_gpa)`, if any.
    fn shadow_for(&self, base: u64, slot_gpa: Option<u64>) -> Option<usize> {
        self.shadows
            .iter()
            .find(|s| s.base == base && s.slot_gpa == slot_gpa)
            .map(|s| s.shadow)
    }
}

/// How [`GuestRam::add_alias`] backs a dynamic alias mapping's host memory.
pub(crate) enum AliasBacking<'a> {
    /// A guest `mmap(MAP_SHARED, fd)`: `MAP_SHARED` of a dup'd host fd at `offset`
    /// with host `prot`, so guest writes hit the file's page cache (coherent with
    /// other openers and inherited across `fork(2)`). `GuestRam::add_alias` owns
    /// the dup and closes it after the mmap takes its own reference.
    File {
        fd: libc::c_int,
        offset: libc::off_t,
        prot: libc::c_int,
    },
    /// A high-VA anonymous alias: `MAP_PRIVATE|MAP_ANON` seeded with `payload`
    /// (empty for a zero-filled region).
    Anon { payload: &'a [u8] },
}

/// Load `image` (a freestanding aarch64 ELF), build the stage-1 identity map +
/// trampoline + sentinel vector, program the vCPU, and return it parked at the
/// EL1 trampoline. Reuses carrick-mem's architectural builders; does NOT use
/// the FEAT_PAN3 workaround (see `program_sysregs`).
#[cfg(target_arch = "aarch64")]
pub fn bring_up(image: &AddressSpace) -> Result<BroughtUp, OsError> {
    // 1-3. Lay out guest physical RAM: windows + image segments + the
    //       architectural bring-up pages (shared with execve_into).
    let mut ram = GuestRam::build_for_image(image)?;

    // 4. Create VM + publish every window as its own KVM memory slot.
    let mut vm = KvmVm::create(image)?;
    for (base, host, len) in ram.windows_for_kvm() {
        vm.map_memory(base, host, len, MemPerms::ReadWriteExec)?;
    }
    let mut vcpu = vm.add_vcpu()?;

    // 5. Program registers (sys regs + entry/SP/PC), NO FEAT_PAN3 workaround.
    program_sysregs(&mut vcpu, image)?;

    // 6. Calibrate the vDSO clock so its `cntvct_el0` fast path returns correct
    //    wall-clock time (EL0 counter access is enabled per-vCPU in the vCPU
    //    create path). Best-effort: a calibration failure leaves the vvar zeroed
    //    (realtime reads as boot-relative) rather than aborting bring-up.
    // vDSO vvar calibration is aarch64-only (CNTVCT/CNTFRQ timer; vDSO not
    // present in the x86 KVM backend Phase 2 — spec N3).
    #[cfg(target_arch = "aarch64")]
    let _ = populate_vdso_vvar(&vcpu, &mut ram);

    Ok(BroughtUp {
        vm,
        vcpu,
        ram,
        entry: image.entry(),
    })
}

/// Calibrate the vDSO clock data page (vvar). The vDSO computes
/// `realtime_ns = CNTVCT_EL0/CNTFRQ_EL0*1e9 + realtime_off`, reading CNTVCT/CNTFRQ
/// directly at EL0 (enabled per-vCPU via CNTKCTL_EL1 in the vCPU create path) and
/// `realtime_off` from the vvar. So write `realtime_off = unix_ns - cnt/freq*1e9`
/// measured here against the GUEST's counter (KVM_REG_ARM_TIMER_CNT — the value
/// the guest's `mrs cntvct_el0` returns) and the CNTFRQ_EL0 the vDSO reads. The
/// offset is constant; as the guest counter advances, the vDSO tracks real time.
/// (The vDSO reads the freq from the sysreg, not the vvar, so only offset 16 is
/// filled.) Mirrors HVF's `populate_vdso_data_page`, calibrated to the guest's own
/// counter rather than macOS CLOCK_UPTIME_RAW. Re-run on execve (new image RAM)
/// and on the fork child (new VM = new counter basis).
/// Read the host's `CNTFRQ_EL0` (timer frequency, Hz). Unconditionally
/// EL0-readable on aarch64, and equal to the KVM guest's CNTFRQ_EL0 (the same
/// physical counter) — which KVM does not surface through `KVM_GET_ONE_REG`.
/// Also used by `kvm.rs::align_counter_to_host_monotonic` (the guest-counter
/// epoch alignment) for the same reason.
// compile error recorded when building for x86_64 before this gate was added:
//   error: instruction requires: aarch64
//   --> crates/carrick-vmm-kvm/src/guest_setup.rs:1050:9
//   note: `mrs {}, cntfrq_el0` is an AArch64-only system-register read
// and in kvm.rs:
//   error[E0432]: unresolved import `kvm_bindings::KVM_ARM_VCPU_PSCI_0_2`
//   error[E0599]: no method named `get_one_reg`/`set_one_reg` found ...
#[cfg(target_arch = "aarch64")]
pub(crate) fn host_cntfrq_el0() -> u64 {
    let freq: u64;
    // SAFETY: `cntfrq_el0` is an unprivileged read on aarch64 Linux.
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nomem, nostack));
    }
    freq
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn populate_vdso_vvar(vcpu: &KvmVcpu, ram: &mut GuestRam) -> Result<(), OsError> {
    use carrick_mem::vdso::{LINUX_VVAR_BASE, VVAR_OFF_REALTIME_OFF_NS};
    // KVM does NOT expose CNTFRQ_EL0 via KVM_GET_ONE_REG (ENOENT), but the guest's
    // CNTFRQ_EL0 (what the vDSO reads) is the SAME physical timer frequency the
    // host sees — and CNTFRQ_EL0 is unconditionally EL0-readable on aarch64 Linux,
    // so read it directly from the host. The COUNTER, however, must come from the
    // guest (KVM_REG_ARM_TIMER_CNT) — it has the guest's CNTVOFF baked in.
    let freq = host_cntfrq_el0();
    let cnt = vcpu.get_timer_cnt()?;
    if std::env::var_os("CARRICK_VDSO_DEBUG").is_some() {
        eprintln!("[VDSODBG] host_cntfrq={freq} guest_timer_cnt={cnt}");
    }
    if freq == 0 {
        return Ok(()); // no counter — the vDSO clock falls back to syscalls
    }
    let mono_ns = ((cnt as u128) * 1_000_000_000u128 / (freq as u128)) as u64;
    let unix_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let realtime_off = unix_ns.wrapping_sub(mono_ns);
    ram.write_gpa(
        LINUX_VVAR_BASE + VVAR_OFF_REALTIME_OFF_NS as u64,
        &realtime_off.to_le_bytes(),
    )
}

/// Program the vCPU's system + core registers for `image`: MAIR/TCR/TTBR0/1/
/// SCTLR/CPACR/VBAR + PSTATE/SPSR/ELR/PC/SP, with NO FEAT_PAN3 workaround (KVM
/// controls PSTATE, so PAN stays clear so the EL1 sentinel store reaches MMIO).
///
/// Shared by both [`bring_up`] (initial image) and
/// `Aarch64EngineCore::execve_into` (in-place image
/// replacement). `execve_into` additionally zeroes x0..x30 before calling this
/// (Linux execve clears the GPRs); this routine sets only SP/PC/PSTATE among the
/// core registers, leaving x0..x30 to the caller's zeroing — and resets
/// TPIDR_EL0 = 0 so the new image's libc re-initialises its thread pointer.
#[cfg(target_arch = "aarch64")]
pub(crate) fn program_sysregs(vcpu: &mut KvmVcpu, image: &AddressSpace) -> Result<(), OsError> {
    // MAIR_EL1 slot 0 = Normal Inner/Outer WB cacheable (0xFF), as HVF. The
    // bootstrap MAIR/TCR/SCTLR/CPACR values are SHARED with HVF via GuestArch
    // (canonical rationale in carrick_mem::arch_sysregs; byte-identical, one
    // edit point). Free function, so name the engine explicitly.
    use carrick_hal::GuestArch as _;
    let boot =
        <crate::trap_engine::KvmTrapEngine as carrick_hal::ThreadedEngine>::Arch::bootstrap_sysregs(
        );
    vcpu.set_sys_reg(SysReg::Mair, boot.mair_el1)?;
    // TCR_EL1: identical bootstrap value to the HVF path. T0SZ=
    // T1SZ=16, Inner-WB/Inner-Shareable both halves, TG1=4K, IPS=40-bit, TBI0/1.
    vcpu.set_sys_reg(SysReg::Tcr, boot.tcr_el1)?;
    vcpu.set_sys_reg(SysReg::Ttbr0, LINUX_PAGE_TABLES_BASE)?;
    vcpu.set_sys_reg(SysReg::Ttbr1, LINUX_PAGE_TABLES_BASE)?;

    // SCTLR_EL1: the shared base (C/I/DZE/UCT/UCI + M=1) from carrick-mem, plus
    // SPAN (bit 23) which is KVM-SPECIFIC PAN GLUE — NOT part of the shared
    // const.
    //
    // SPAN(bit 23)=1 is LOAD-BEARING for the MMIO sentinel: it means
    // "PSTATE.PAN is left UNCHANGED on taking an exception to EL1". With SPAN=0
    // (the architectural default) the hardware sets PSTATE.PAN=1 on every
    // EL0-`svc` entry to EL1 (FEAT_PAN is mandatory ARMv8.1 and KVM-exposed);
    // the EL1 sentinel vector's `str x8,[x9]` to the EL0-accessible (AP=01)
    // sentinel page would then fault as a stage-1 PAN permission abort and
    // never reach stage-2 / KVM_EXIT_MMIO — wedging the first guest syscall.
    // The guest enters EL0 with PSTATE.PAN=0 (SPSR_EL1 below), so SPAN=1 keeps
    // PAN=0 through the svc trap and the sentinel store reaches the host. (HVF
    // takes the opposite tack — SPAN=0 + forced PSTATE.PAN=1 — so this bit lives
    // here, not in the shared bootstrap SCTLR value.)
    const SCTLR_EL1_SPAN: u64 = 1 << 23;
    let sctlr: u64 = boot.sctlr_el1 | SCTLR_EL1_SPAN;
    vcpu.set_sys_reg(SysReg::Sctlr, sctlr)?;

    // FP/SIMD on (CPACR_EL1.FPEN = 0b11) so guest NEON memset doesn't trap.
    vcpu.set_sys_reg(SysReg::Cpacr, boot.cpacr_el1)?;

    // VBAR_EL1 -> our sentinel vector page.
    vcpu.set_sys_reg(SysReg::Vbar, LINUX_EL1_VECTORS_BASE)?;

    // TPIDR_EL0 = 0: the EL0 thread pointer starts cleared. On a fresh vCPU
    // (bring-up) this is already 0; on an execve-into-a-live-vCPU it RESETS a
    // value the prior image's libc may have installed (Linux execve clears the
    // thread pointer; the new image's libc re-initialises it via
    // set_thread_area). Mirrors the HVF execve path (trap.rs:3899-3903).
    vcpu.set_sys_reg(SysReg::TpidrEl0, 0)?;

    // THE PAN DIVERGENCE FROM HVF. Apple HVF forces PSTATE.PAN=1 and the
    // identity tables work around FEAT_PAN3 with AP=01+PXN=1 on user pages.
    // On KVM the host controls PSTATE. The sentinel store is issued from EL1
    // against an EL0-accessible (user) identity page, so PAN MUST be clear or
    // it would fault as a permission abort instead of reaching stage-2 / MMIO.
    const DAIF_MASKED: u64 = 0b1111 << 6;
    const PSTATE_M_EL1H: u64 = 0b0101; // M[3:0] = EL1h
    const PSTATE_M_EL0T: u64 = 0b0000; // M[3:0] = EL0t
    // Current PSTATE: run the EL0 trampoline at EL1h, DAIF masked, PAN(bit22)=0.
    vcpu.set_reg(Reg::Pstate, PSTATE_M_EL1H | DAIF_MASKED)?;

    // The trampoline ends in `eret`, which loads PC <- ELR_EL1 and
    // PSTATE <- SPSR_EL1. Program both so the eret drops to EL0 at the image
    // entry. (Mirrors the HVF path at carrick-vmm-hvf/src/trap.rs:1462-1476.)
    vcpu.set_reg(Reg::SpsrEl1, PSTATE_M_EL0T | DAIF_MASKED)?;
    vcpu.set_reg(Reg::ElrEl1, image.entry())?;

    // Start the vCPU executing the EL0 trampoline (in EL1h).
    vcpu.set_reg(Reg::Pc, LINUX_EL0_TRAMPOLINE_BASE)?;

    // The EL0 user stack lives in SP_EL0 (== Reg::Sp), NOT SP_EL1. The
    // freestanding MVP binary has no initial stack (load_elf_bytes leaves it
    // None) and never touches SP; a real image sets it via
    // `AddressSpace::with_linux_initial_stack` before bring-up.
    if let Some(sp) = image.initial_stack_pointer() {
        vcpu.set_reg(Reg::Sp, sp)?;
    }
    Ok(())
}

#[cfg(test)]
mod vector_tests {
    use super::*;

    /// Byte-assert the lower-EL-sync slot: the ESR.EC discriminator, the svc
    /// path (SENTINEL_GPA), and the fault path (FAULT_SENTINEL_GPA), plus that the
    /// `b.ne` jumps exactly +7 instructions to the fault block. Hand-assembled
    /// vector asm is high-risk; this locks every opcode + the branch offset.
    #[test]
    fn lower_el_sync_slot_discriminates_svc_vs_fault() {
        let bytes = el1_vectors_sentinel_bytes();
        let s = AARCH64_VECTOR_LOWER_EL_SYNC_OFFSET as usize;
        let op = |off: usize| -> u32 {
            u32::from_le_bytes(bytes[s + off..s + off + 4].try_into().unwrap())
        };
        // s+0 saves the guest's live x9 (the ABI preserves x9; the vector clobbers
        // it as the sentinel-store scratch, and complete_syscall restores it).
        assert_eq!(
            op(0),
            ENC_MSR_TPIDR_EL1_X9,
            "s+0 msr tpidr_el1, x9 (save x9)"
        );
        // Discriminator (shifted +4 by the leading save).
        assert_eq!(op(4), ENC_MRS_X9_ESR_EL1, "s+4 mrs x9, esr_el1");
        assert_eq!(op(8), ENC_UBFX_X9_X9_EC, "s+8 ubfx x9,x9,#26,#6");
        assert_eq!(op(12), ENC_CMP_X9_SVC, "s+12 cmp x9,#0x15");
        assert_eq!(op(16), ENC_BNE_FAULT, "s+16 b.ne fault");
        // A B.cond imm19 (bits[23:5]) is the branch distance in INSTRUCTIONS; the
        // fault block (s+44) is 7 instructions after the b.ne (s+16) — both paths
        // shifted uniformly by the leading save, so the distance is unchanged.
        assert_eq!(
            (op(16) >> 5) & 0x7_ffff,
            7,
            "b.ne must jump +7 instructions"
        );
        assert_eq!((44 - 16) / 4, 7, "fault block is +7 instructions from b.ne");
        // SVC path: SENTINEL_GPA materialize + str + eret.
        assert_eq!(
            op(20),
            enc_movz_x9((SENTINEL_GPA & 0xFFFF) as u16, 0),
            "s+20 movz SENTINEL"
        );
        assert_eq!(op(36), ENC_STR_X8_X9, "s+36 svc str x8,[x9]");
        assert_eq!(op(40), AARCH64_ERET_OPCODE, "s+40 svc eret");
        // FAULT path: FAULT_SENTINEL_GPA materialize + str + eret.
        assert_eq!(
            op(44),
            enc_movz_x9((FAULT_SENTINEL_GPA & 0xFFFF) as u16, 0),
            "s+44 movz FAULT"
        );
        assert_eq!(
            op(48),
            enc_movk_x9(((FAULT_SENTINEL_GPA >> 16) & 0xFFFF) as u16, 1),
            "s+48 movk FAULT"
        );
        assert_eq!(op(60), ENC_STR_X8_X9, "s+60 fault str x8,[x9]");
        assert_eq!(op(64), AARCH64_ERET_OPCODE, "s+64 fault eret");
    }

    /// Byte-assert the KVM stage-1 maintenance trampoline: the
    /// `dsb sy; tlbi vmalle1is; dsb sy; isb` barrier sequence, then a
    /// MAINT_SENTINEL_GPA materialize + `str x8,[x9]` completion store (the KVM
    /// MMIO analogue of HVF's closing `hvc #1`). Hand-assembled EL1 asm is
    /// high-risk; this locks every opcode + the gpa materialization.
    #[test]
    fn maint_sentinel_bytes_flush_then_mmio_store() {
        let bytes = el1_maintenance_sentinel_bytes();
        assert_eq!(
            bytes.len() as u64,
            carrick_mem::memory::LINUX_EL1_MAINT_SIZE,
            "maint trampoline fills the whole region"
        );
        let op =
            |off: usize| -> u32 { u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) };
        assert_eq!(op(0), ENC_DSB_SY, "0 dsb sy");
        assert_eq!(op(4), ENC_TLBI_VMALLE1IS, "4 tlbi vmalle1is");
        assert_eq!(op(8), ENC_DSB_SY, "8 dsb sy");
        assert_eq!(op(12), ENC_ISB, "12 isb");
        assert_eq!(
            op(16),
            enc_movz_x9((MAINT_SENTINEL_GPA & 0xFFFF) as u16, 0),
            "16 movz x9, MAINT_SENTINEL[0]"
        );
        assert_eq!(
            op(20),
            enc_movk_x9(((MAINT_SENTINEL_GPA >> 16) & 0xFFFF) as u16, 1),
            "20 movk x9, MAINT_SENTINEL[1]"
        );
        assert_eq!(
            op(24),
            enc_movk_x9(((MAINT_SENTINEL_GPA >> 32) & 0xFFFF) as u16, 2),
            "24 movk x9, MAINT_SENTINEL[2]"
        );
        assert_eq!(
            op(28),
            enc_movk_x9(((MAINT_SENTINEL_GPA >> 48) & 0xFFFF) as u16, 3),
            "28 movk x9, MAINT_SENTINEL[3]"
        );
        assert_eq!(op(32), ENC_STR_X8_X9, "32 str x8,[x9] (MMIO completion)");
        // The tail is `nop` padding (any over-run past the exit is harmless).
        assert_eq!(op(36), AARCH64_NOP_OPCODE, "36 nop pad");
        // The three sentinels must be DISTINCT gpas so the host disambiguates a
        // syscall trap, a fault trap, and a maintenance completion by gpa alone.
        assert_ne!(MAINT_SENTINEL_GPA, SENTINEL_GPA);
        assert_ne!(MAINT_SENTINEL_GPA, FAULT_SENTINEL_GPA);
    }
}

#[cfg(test)]
mod window_kind_tests {
    use super::*;
    use carrick_mem::memory::{LINUX_SHARED_FILE_BASE, LINUX_SHARED_FILE_SIZE};

    /// Verify that `add_window` stores the correct `WindowKind` on each window:
    /// the shared-aperture range gets `Shared`, all others get `Private`.
    #[test]
    fn shared_aperture_window_tagged_shared() {
        let mut ram = GuestRam::new();
        // Low window (private).
        ram.add_window(0, 0x10000, WindowKind::Private)
            .expect("low window");
        // Shared aperture window — uses real constants from carrick-mem.
        ram.add_window(
            LINUX_SHARED_FILE_BASE,
            LINUX_SHARED_FILE_SIZE as usize,
            WindowKind::Shared,
        )
        .expect("shared aperture window");
        // Another private high window (e.g. stack).
        ram.add_window(0xC0_0000_0000, 0x10000, WindowKind::Private)
            .expect("high private window");

        let kinds: Vec<WindowKind> = ram
            .windows
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|w| w.kind)
            .collect();
        assert_eq!(kinds[0], WindowKind::Private, "low window must be Private");
        assert_eq!(
            kinds[1],
            WindowKind::Shared,
            "shared-aperture window must be Shared"
        );
        assert_eq!(
            kinds[2],
            WindowKind::Private,
            "high private window must be Private"
        );
    }

    /// COW probe: validates the OS-level mmap semantics that the `Shared` window
    /// path relies on, independent of carrick.
    ///
    /// Strategy: parent writes sentinel bytes into both a MAP_SHARED and a
    /// MAP_PRIVATE page BEFORE `fork`.  After `fork`, the parent overwrites only
    /// the MAP_SHARED page.  The child, signalled to read after the parent write,
    /// must observe the new value through the shared page (MAP_SHARED writes are
    /// immediately visible across the fork) and the old value through the private
    /// page (MAP_PRIVATE COW-snapshotted the page at fork time).
    #[test]
    fn cow_probe_shared_vs_private() {
        use std::os::unix::io::RawFd;

        const PAGE: usize = 4096;
        const BEFORE: u8 = 0xAB;
        const AFTER: u8 = 0xCD;

        // Allocate one shared and one private page, write BEFORE into both.
        let shared_pg = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(shared_pg, libc::MAP_FAILED, "shared mmap failed");

        let private_pg = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(private_pg, libc::MAP_FAILED, "private mmap failed");

        unsafe { *(shared_pg as *mut u8) = BEFORE };
        unsafe { *(private_pg as *mut u8) = BEFORE };

        // Two pipes for coordination:
        //   p2c: parent sends one "go" byte to child after writing AFTER.
        //   c2p: child sends two result bytes back to parent.
        let mut p2c: [RawFd; 2] = [-1; 2];
        let mut c2p: [RawFd; 2] = [-1; 2];
        assert_eq!(unsafe { libc::pipe(p2c.as_mut_ptr()) }, 0, "pipe p2c");
        assert_eq!(unsafe { libc::pipe(c2p.as_mut_ptr()) }, 0, "pipe c2p");

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            // ── child ──────────────────────────────────────────────────────────
            unsafe {
                libc::close(p2c[1]); // close parent-write end
                libc::close(c2p[0]); // close child-read end
            }
            // Block until parent signals "go" (after writing AFTER to shared_pg).
            let mut go = [0u8; 1];
            unsafe { libc::read(p2c[0], go.as_mut_ptr() as *mut _, 1) };
            unsafe { libc::close(p2c[0]) };

            let sv = unsafe { *(shared_pg as *const u8) };
            let pv = unsafe { *(private_pg as *const u8) };
            let results = [sv, pv];
            unsafe { libc::write(c2p[1], results.as_ptr() as *const libc::c_void, 2) };
            unsafe { libc::close(c2p[1]) };
            unsafe { libc::_exit(0) };
        }

        // ── parent ─────────────────────────────────────────────────────────────
        unsafe {
            libc::close(p2c[0]); // close child-read end
            libc::close(c2p[1]); // close child-write end
        }

        // Overwrite only the MAP_SHARED page AFTER fork.
        unsafe { *(shared_pg as *mut u8) = AFTER };
        // MAP_PRIVATE page intentionally unchanged (stays BEFORE in child's snapshot).

        // Signal child to proceed.
        let go = [1u8];
        unsafe { libc::write(p2c[1], go.as_ptr() as *const libc::c_void, 1) };
        unsafe { libc::close(p2c[1]) };

        // Read child's observations.
        let mut results = [0u8; 2];
        let n = unsafe { libc::read(c2p[0], results.as_mut_ptr() as *mut libc::c_void, 2) };
        assert_eq!(n, 2, "expected 2 result bytes from child");
        unsafe { libc::close(c2p[0]) };

        let mut status: libc::c_int = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };

        unsafe {
            libc::munmap(shared_pg, PAGE);
            libc::munmap(private_pg, PAGE);
        }

        assert_eq!(
            results[0], AFTER,
            "child must observe parent's post-fork write through MAP_SHARED \
             (expected 0x{AFTER:02x}, got 0x{:02x})",
            results[0]
        );
        assert_eq!(
            results[1], BEFORE,
            "child must NOT observe parent's post-fork write through MAP_PRIVATE \
             (expected 0x{BEFORE:02x}, got 0x{:02x})",
            results[1]
        );
    }
}
