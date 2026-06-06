//! Guest bring-up for the KVM MVP: load the freestanding ELF into a host mmap,
//! reuse carrick-mem's architectural stage-1 / trampoline builders, install a
//! tiny EL1 vector whose lower-EL-sync slot STORES TO A SENTINEL gpa (the MMIO
//! trap vehicle) instead of HVF's `hvc #2`, and program the system registers
//! WITHOUT the Apple-Silicon FEAT_PAN3 / PSTATE.PAN=1 workaround.
use carrick_hal::{HvVcpu, HvVm, MemPerms, OsError, Reg, SysReg};
use carrick_mem::memory::{
    AddressSpace, LINUX_EL0_TRAMPOLINE_BASE, LINUX_EL1_VECTORS_BASE, LINUX_EL1_VECTORS_SIZE,
    LINUX_PAGE_TABLES_BASE, el0_trampoline_bytes, stage1_identity_page_tables,
};

use crate::kvm::{KvmVcpu, KvmVm};

/// Guest-physical address the EL1 vector stores to on an EL0 `svc`. It is left
/// UNMAPPED in every KVM memory region, so the store faults out as
/// `KVM_EXIT_MMIO { gpa: SENTINEL_GPA, .. }` — the trap vehicle. Chosen high,
/// outside any region carrick maps, and distinct from the kernel hole.
pub const SENTINEL_GPA: u64 = 0x40_0000_0000;

// The aarch64 vector table layout (matches carrick-mem's el1_vectors_bytes):
// 16 slots * 0x80 bytes; the lower-EL synchronous slot is at offset 0x400.
const AARCH64_VECTOR_SLOT_SIZE: u64 = 0x80;
const AARCH64_VECTOR_LOWER_EL_SYNC_OFFSET: u64 = 0x400;
const AARCH64_ERET_OPCODE: u32 = 0xd69f_03e0;
const AARCH64_NOP_OPCODE: u32 = 0xd503_201f;

// Encoders for the sentinel store sequence. We use x9 as scratch (the guest's
// svc convention leaves x0..x8 as the syscall frame; x9 is caller-saved and
// unobserved across the trap because the host reads the frame, completes the
// syscall, and resumes via ELR_EL1).
fn enc_movz_x9(imm16: u16, hw: u32) -> u32 {
    0xD280_0009 | (hw << 21) | (u32::from(imm16) << 5)
}
fn enc_movk_x9(imm16: u16, hw: u32) -> u32 {
    0xF280_0009 | (hw << 21) | (u32::from(imm16) << 5)
}
// `str x8, [x9]` — store the syscall number to the sentinel (any store works).
const ENC_STR_X8_X9: u32 = 0xf900_0128;

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
    // Overwrite the lower-EL sync slot with the sentinel store sequence.
    let s = AARCH64_VECTOR_LOWER_EL_SYNC_OFFSET as usize;
    let g = SENTINEL_GPA;
    put(&mut bytes, s, enc_movz_x9((g & 0xFFFF) as u16, 0));
    put(
        &mut bytes,
        s + 4,
        enc_movk_x9(((g >> 16) & 0xFFFF) as u16, 1),
    );
    put(
        &mut bytes,
        s + 8,
        enc_movk_x9(((g >> 32) & 0xFFFF) as u16, 2),
    );
    put(
        &mut bytes,
        s + 12,
        enc_movk_x9(((g >> 48) & 0xFFFF) as u16, 3),
    );
    put(&mut bytes, s + 16, ENC_STR_X8_X9);
    put(&mut bytes, s + 20, AARCH64_ERET_OPCODE);
    bytes
}

/// One contiguous host-backed guest RAM window. MVP: MAP_PRIVATE (no fork, so
/// the host-MAP_SHARED + host-VA-futex fork-coherence model is deferred — see
/// the MVP non-goals). Spans [base, base+len) of guest-physical space.
pub struct GuestRam {
    base: u64,
    host: *mut u8,
    len: usize,
}

impl GuestRam {
    /// mmap `len` bytes of host RAM to back guest-physical [base, base+len).
    fn new(base: u64, len: usize) -> Result<Self, OsError> {
        // SAFETY: standard anonymous private mapping; we own it for the VM's life.
        let host = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if host == libc::MAP_FAILED {
            return Err(OsError::new("kvm: guest RAM mmap failed".to_string()));
        }
        Ok(Self {
            base,
            host: host.cast::<u8>(),
            len,
        })
    }

    /// Copy `data` to guest-physical `gpa` (must lie within this window).
    fn write_gpa(&mut self, gpa: u64, data: &[u8]) -> Result<(), OsError> {
        let off = gpa
            .checked_sub(self.base)
            .filter(|o| (*o as usize).saturating_add(data.len()) <= self.len)
            .ok_or_else(|| OsError::new(format!("kvm: gpa 0x{gpa:x} out of guest RAM")))?;
        // SAFETY: bounds checked above; host points at `len` writable bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), self.host.add(off as usize), data.len());
        }
        Ok(())
    }
}

/// Result of bring-up: a VM + a vCPU initialised to the EL1 trampoline, ready
/// for the trap engine to drive. `ram` is kept alive (its mmap backs KVM).
pub struct BroughtUp {
    pub vm: KvmVm,
    pub vcpu: KvmVcpu,
    pub ram: GuestRam,
    pub entry: u64,
}

/// Load `image` (a freestanding aarch64 ELF), build the stage-1 identity map +
/// trampoline + sentinel vector, program the vCPU, and return it parked at the
/// EL1 trampoline. Reuses carrick-mem's architectural builders; does NOT use
/// the FEAT_PAN3 workaround (see `program_sysregs`).
pub fn bring_up(image: &AddressSpace) -> Result<BroughtUp, OsError> {
    // One window covering both the user image and the kernel hole. The kernel
    // hole sits at 0x2D_0000_0000 (2 MiB); the freestanding test ELF loads low
    // (<= a few MiB). Size the window to span [0, kernel_hole_end).
    const KERNEL_HOLE_END: u64 = 0x2D_0020_0000; // LINUX_KERNEL_REGION_BASE + 2 MiB
    let len = KERNEL_HOLE_END as usize;
    let mut ram = GuestRam::new(0, len)?;

    // 1. ELF segments (identity GPA == region.start).
    for region in image.regions() {
        ram.write_gpa(region.start, region.bytes())?;
    }
    // 2. Architectural bring-up pages, reused verbatim from carrick-mem.
    ram.write_gpa(LINUX_EL0_TRAMPOLINE_BASE, &el0_trampoline_bytes())?;
    ram.write_gpa(LINUX_PAGE_TABLES_BASE, &stage1_identity_page_tables())?;
    // 3. Our sentinel vector (NOT carrick-mem's hvc #2 variant).
    ram.write_gpa(LINUX_EL1_VECTORS_BASE, &el1_vectors_sentinel_bytes())?;

    // 4. Create VM + map the whole window as one region.
    let mut vm = KvmVm::create(image)?;
    vm.map_memory(0, ram.host, ram.len, MemPerms::ReadWriteExec)?;
    let mut vcpu = vm.add_vcpu()?;

    // 5. Program registers (sys regs + entry/SP/PC), NO FEAT_PAN3 workaround.
    program_sysregs(&mut vcpu, image)?;

    Ok(BroughtUp {
        vm,
        vcpu,
        ram,
        entry: image.entry(),
    })
}

fn program_sysregs(vcpu: &mut KvmVcpu, image: &AddressSpace) -> Result<(), OsError> {
    // MAIR_EL1 slot 0 = Normal Inner/Outer WB cacheable (0xFF), as HVF.
    vcpu.set_sys_reg(SysReg::Mair, 0xFF)?;
    // TCR_EL1: identical bootstrap value to the HVF path. T0SZ=
    // T1SZ=16, Inner-WB/Inner-Shareable both halves, TG1=4K, IPS=40-bit, TBI0/1.
    const T0SZ: u64 = 16;
    const T1SZ: u64 = 16;
    const TCR_EL1_BOOTSTRAP: u64 = T0SZ
        | (0b11 << 8)
        | (0b11 << 10)
        | (0b11 << 12)
        | (T1SZ << 16)
        | (0b11 << 24)
        | (0b11 << 26)
        | (0b11 << 28)
        | (0b10 << 30)
        | (0b010 << 32)
        | (1 << 37)
        | (1 << 38);
    vcpu.set_sys_reg(SysReg::Tcr, TCR_EL1_BOOTSTRAP)?;
    vcpu.set_sys_reg(SysReg::Ttbr0, LINUX_PAGE_TABLES_BASE)?;
    vcpu.set_sys_reg(SysReg::Ttbr1, LINUX_PAGE_TABLES_BASE)?;

    // SCTLR_EL1: C,I,UCI,UCT,DZE + M=1 (stage-1 on). Same bits as HVF plus the MMU-enable bit.
    let sctlr: u64 = (1 << 2) | (1 << 12) | (1 << 26) | (1 << 15) | (1 << 14) | 1;
    vcpu.set_sys_reg(SysReg::Sctlr, sctlr)?;

    // FP/SIMD on (CPACR_EL1.FPEN = 0b11) so guest NEON memset doesn't trap.
    vcpu.set_sys_reg(SysReg::Cpacr, 0x3 << 20)?;

    // VBAR_EL1 -> our sentinel vector page.
    vcpu.set_sys_reg(SysReg::Vbar, LINUX_EL1_VECTORS_BASE)?;

    // THE PAN DIVERGENCE FROM HVF. Apple HVF forces PSTATE.PAN=1 and the
    // identity tables work around FEAT_PAN3 with AP=01+PXN=1 on user pages.
    // On KVM the host controls PSTATE: start the vCPU at the EL1 trampoline in
    // EL1h with PAN EXPLICITLY CLEARED (bit 22), DAIF masked. Bit layout of
    // SPSR/PSTATE: M[3:0]=0b0101 (EL1h), DAIF=0b1111<<6, PAN(bit 22)=0.
    const PSTATE_EL1H_DAIF_MASKED_PAN_CLEAR: u64 = 0b0101 | (0b1111 << 6);
    vcpu.set_reg(Reg::Pstate, PSTATE_EL1H_DAIF_MASKED_PAN_CLEAR)?;

    // Start at the EL0 trampoline (EL1h); it does TLBI/IC/ISB then `eret` to
    // EL0 at the image entry. Seed SP and the EL0 entry.
    vcpu.set_reg(Reg::Pc, LINUX_EL0_TRAMPOLINE_BASE)?;
    if let Some(sp) = image.initial_stack_pointer() {
        vcpu.set_sys_reg(SysReg::SpEl1, sp)?;
    }
    Ok(())
}
