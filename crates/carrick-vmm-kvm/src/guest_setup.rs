//! Guest bring-up for the KVM MVP: load the freestanding ELF into a host mmap,
//! reuse carrick-mem's architectural stage-1 / trampoline builders, install a
//! tiny EL1 vector whose lower-EL-sync slot STORES TO A SENTINEL gpa (the MMIO
//! trap vehicle) instead of HVF's `hvc #2`, and program the system registers
//! WITHOUT the Apple-Silicon FEAT_PAN3 / PSTATE.PAN=1 workaround.
//!
//! The aarch64 bring-up (EL1 vector builders, `bring_up`, `program_sysregs`,
//! `BroughtUp`, the trap engine's alias/protection/exec-reset helpers) and the
//! x86_64 fork/vfork VM rebuild are each `cfg`-gated to the architecture that
//! calls them; the window/slot model in between is shared.

use carrick_hal::{HostAliasBacking, HostAliasSharing, HvVm, MemPerms, OsError};
#[cfg(target_arch = "aarch64")]
use carrick_hal::{HvVcpu, Reg, SysReg};
use carrick_mem::memory::LINUX_EL1_VECTORS_SIZE;
#[cfg(target_arch = "aarch64")]
use carrick_mem::memory::{
    AddressSpace, LINUX_EL0_TRAMPOLINE_BASE, LINUX_EL1_MAINT_BASE, LINUX_EL1_VECTORS_BASE,
    LINUX_NULL_GUARD_END, LINUX_PAGE_TABLES_BASE, stage1_identity_page_tables,
    va_in_shared_aperture,
};

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
pub use carrick_x86_cpl0_host::guest_ram::{FAULT_SENTINEL_GPA, MAINT_SENTINEL_GPA, SENTINEL_GPA};

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
#[cfg(target_arch = "aarch64")]
pub(crate) const KVM_ALIAS_GPA_BASE: u64 = 0xA0_0000_0000; // 640 GiB
/// Size of the KVM alias-GPA arena. Matches `LINUX_ALIAS_IPA_SIZE` (64 GiB) so the
/// VA->GPA delta always lands in-arena; ends at 704 GiB, well below the stack.
#[cfg(target_arch = "aarch64")]
pub(crate) const KVM_ALIAS_GPA_SIZE: u64 = 0x10_0000_0000; // 64 GiB

/// KVM memory-slot alignment. `KVM_SET_USER_MEMORY_REGION` requires the
/// guest-physical base and size to be a multiple of the HOST page size; 64 KiB
/// covers every aarch64 host granule (4K/16K/64K). The high guest regions are
/// already ≥ 64 KiB-aligned, so this only rounds the (16 KiB) sigreturn window
/// up — harmless extra lazy backing.
const KVM_SLOT_ALIGN: u64 = 0x10000;

#[cfg(target_arch = "aarch64")]
fn align_down_slot(addr: u64) -> u64 {
    addr & !(KVM_SLOT_ALIGN - 1)
}

fn align_up_slot(addr: u64) -> Result<u64, OsError> {
    addr.checked_add(KVM_SLOT_ALIGN - 1)
        .map(|a| a & !(KVM_SLOT_ALIGN - 1))
        .ok_or_else(|| OsError::new(format!("kvm: region end 0x{addr:x} overflows on align")))
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

#[cfg(target_arch = "x86_64")]
pub use carrick_x86_cpl0_host::guest_ram::VforkShadows;
pub use carrick_x86_cpl0_host::guest_ram::{GuestRam, WindowDesc, WindowKind};

pub(crate) trait GuestRamKvmExt {
    fn add_alias(
        &mut self,
        vm: &mut KvmVm,
        va: u64,
        gpa: u64,
        len: u64,
        payload: &[u8],
        backing: HostAliasBacking,
    ) -> Result<(), OsError>;

    #[cfg(target_arch = "x86_64")]
    fn rebuild_vm_for_child(&self) -> Result<(KvmVm, KvmVcpu), OsError>;

    #[cfg(target_arch = "x86_64")]
    fn rebuild_vm_for_child_vfork(
        &self,
        shadows: &VforkShadows,
    ) -> Result<(KvmVm, KvmVcpu), OsError>;

    #[cfg(target_arch = "aarch64")]
    fn build_for_image(image: &AddressSpace) -> Result<GuestRam, OsError>;
}

impl GuestRamKvmExt for GuestRam {
    fn add_alias(
        &mut self,
        vm: &mut KvmVm,
        va: u64,
        gpa: u64,
        len: u64,
        payload: &[u8],
        backing: HostAliasBacking,
    ) -> Result<(), OsError> {
        let size = usize::try_from(align_up_slot(len)?)
            .map_err(|_| OsError::new(format!("kvm: alias len {len} too large")))?;
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
            HostAliasBacking::File {
                fd,
                offset,
                host_prot,
                sharing,
            } => {
                let raw_fd = fd.as_raw_fd();
                let (flags, prot, kind) = match sharing {
                    HostAliasSharing::Shared => (libc::MAP_SHARED, host_prot, WindowKind::Shared),
                    HostAliasSharing::Private => (
                        libc::MAP_PRIVATE,
                        libc::PROT_READ | libc::PROT_WRITE,
                        WindowKind::Private,
                    ),
                };
                let h =
                    unsafe { libc::mmap(std::ptr::null_mut(), size, prot, flags, raw_fd, offset) };
                if h == libc::MAP_FAILED {
                    return Err(OsError::new(format!(
                        "kvm: alias {sharing:?} file (fd={raw_fd} off={offset} size={size} prot={prot}) failed"
                    )));
                }
                (h.cast::<u8>(), kind)
            }
            HostAliasBacking::Anonymous { sharing } => {
                let (flags, kind) = match sharing {
                    HostAliasSharing::Shared => (
                        libc::MAP_SHARED | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                        WindowKind::Shared,
                    ),
                    HostAliasSharing::Private => (
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                        WindowKind::Private,
                    ),
                };
                let h = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        size,
                        libc::PROT_READ | libc::PROT_WRITE,
                        flags,
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
                (h.cast::<u8>(), kind)
            }
        };
        if let Err(e) = vm.map_memory(gpa, host, size, MemPerms::ReadWriteExec) {
            unsafe { libc::munmap(host.cast::<libc::c_void>(), size) };
            return Err(e);
        }
        // SAFETY: this path created `host`, mapped the complete range into the
        // VM, and transfers its mapping ownership into `GuestRam`.
        unsafe { self.push_window(va, host, size, kind, Some(gpa)) };
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn rebuild_vm_for_child(&self) -> Result<(KvmVm, KvmVcpu), OsError> {
        let mut vm = KvmVm::create_empty()?;
        for (gpa, host, len) in self.slot_windows() {
            vm.map_memory(gpa, host, len, MemPerms::ReadWriteExec)?;
        }
        let vcpu = vm.add_vcpu()?;
        Ok((vm, vcpu))
    }

    #[cfg(target_arch = "x86_64")]
    fn rebuild_vm_for_child_vfork(
        &self,
        shadows: &VforkShadows,
    ) -> Result<(KvmVm, KvmVcpu), OsError> {
        let mut vm = KvmVm::create_empty()?;
        self.replace_private_windows_with_vfork_shadows(shadows);
        for (gpa, host, len) in self.slot_windows() {
            vm.map_memory(gpa, host, len, MemPerms::ReadWriteExec)?;
        }
        let vcpu = vm.add_vcpu()?;
        Ok((vm, vcpu))
    }

    #[cfg(target_arch = "aarch64")]
    fn build_for_image(image: &AddressSpace) -> Result<GuestRam, OsError> {
        let mut ram = GuestRam::new();
        ram.add_window(0, KERNEL_HOLE_END as usize, WindowKind::Private)?;

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
        use carrick_hal::GuestArch as _;
        ram.write_gpa(
            LINUX_EL0_TRAMPOLINE_BASE,
            &<crate::trap_engine::KvmTrapEngine as carrick_hal::ThreadedEngine>::Arch::entry_trampoline_bytes(),
        )?;
        let image_carries_stage1 = image
            .regions()
            .iter()
            .any(|region| region.start == LINUX_PAGE_TABLES_BASE && !region.bytes().is_empty());
        if !image_carries_stage1 {
            ram.write_gpa(LINUX_PAGE_TABLES_BASE, &stage1_identity_page_tables())?;
        }
        ram.write_gpa(LINUX_EL1_VECTORS_BASE, &el1_vectors_sentinel_bytes())?;
        ram.write_gpa(LINUX_EL1_MAINT_BASE, &el1_maintenance_sentinel_bytes())?;
        Ok(ram)
    }
}
/// Whether the stage-1 leaf for an alias may be writable. A shared file is
/// mapped on the host at the guest's prot, so a read-only host view must not
/// be reachable through a writable leaf (the host would SIGBUS); private
/// files and anonymous backings are always RW on the host and the guest prot
/// is applied by the backend `protect_range` afterwards.
pub(crate) fn alias_leaf_writable(backing: &HostAliasBacking) -> bool {
    match backing {
        HostAliasBacking::File {
            host_prot,
            sharing: HostAliasSharing::Shared,
            ..
        } => *host_prot & libc::PROT_WRITE != 0,
        HostAliasBacking::File {
            sharing: HostAliasSharing::Private,
            ..
        }
        | HostAliasBacking::Anonymous { .. } => true,
    }
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
    for (base, host, len) in ram.slot_windows() {
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

        let kinds = ram.window_kinds();
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

#[cfg(all(test, target_arch = "x86_64"))]
mod vfork_tests {
    use super::*;

    #[test]
    fn vfork_rebuild_host_reads_shadow_bytes() {
        let mut ram = GuestRam::new();
        ram.add_window(0x1000, 0x1000, WindowKind::Private).unwrap();
        ram.add_window(0x3000, 0x1000, WindowKind::Shared).unwrap();
        ram.write_gpa(0x1000, b"parent").unwrap();
        ram.write_gpa(0x3000, b"shared").unwrap();
        let original = ram.read(0x1000, 6).unwrap();
        let shadows = ram.prepare_vfork_shadows(0).unwrap();
        let shadow = shadows.shadow_for(0x1000, None).unwrap();
        // SAFETY: this fixture owns the stopped, six-byte shadow mapping.
        unsafe { std::ptr::copy_nonoverlapping(b"child!".as_ptr(), shadow as *mut u8, 6) };
        let rebuilt = ram.rebuild_vm_for_child_vfork(&shadows).unwrap();
        let private = ram.read(0x1000, 6).unwrap();
        let shared = ram.read(0x3000, 6).unwrap();
        drop(rebuilt);
        ram.finish_vfork_parent(shadows);
        ram.write_gpa(0x1000, &original).unwrap();
        assert_eq!(&private, b"child!", "host must read the child's shadow");
        assert_eq!(&shared, b"shared");
    }
}
