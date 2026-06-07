//! KvmVm / KvmVcpu: the `carrick-hal` raw-hypervisor layer (HvVm/HvVcpu) on
//! Linux/KVM, aarch64. /dev/kvm -> KVM_CREATE_VM -> KVM_CREATE_VCPU ->
//! KVM_ARM_PREFERRED_TARGET + KVM_ARM_VCPU_INIT; guest RAM via
//! KVM_SET_USER_MEMORY_REGION over a host mmap; registers via
//! KVM_GET/SET_ONE_REG; run via KVM_RUN. kick() is a signal-based vCPU exit.
use carrick_hal::{HvVcpu, HvVm, MemPerms, OsError, Reg, SysReg, VcpuExit};
use carrick_mem::memory::AddressSpace;
use kvm_bindings::{KVM_ARM_VCPU_PSCI_0_2, KVM_MEM_LOG_DIRTY_PAGES, kvm_userspace_memory_region};
use kvm_ioctls::{Kvm, VcpuExit as KvmExit, VcpuFd, VmFd};

use crate::fork::VcpuSnapshot;

fn os_err(context: &str, e: impl std::fmt::Display) -> OsError {
    OsError::new(format!("kvm: {context}: {e}"))
}

// KVM aarch64 register-id field layout (Linux arch/arm64/include/uapi/asm/kvm.h):
//   KVM_REG_ARM64           = 0x6000... (bits 60-61: arch tag)
//   KVM_REG_SIZE_U64        = 0x0030... (bits 52-55: size, shift 52)
//   KVM_REG_ARM_COPROC_SHIFT = 16  -> the coprocessor field is bits 16-27
//   KVM_REG_ARM_CORE        = 0x0010 << 16  (the core register file)
//   KVM_REG_ARM64_SYSREG    = 0x0013 << 16  (the sysreg demux)
const KVM_REG_ARM64: u64 = 0x6000_0000_0000_0000;
const KVM_REG_SIZE_U64: u64 = 0x0030_0000_0000_0000;
const KVM_REG_ARM_COPROC_SHIFT: u64 = 16;
const KVM_REG_ARM_CORE: u64 = 0x0010 << KVM_REG_ARM_COPROC_SHIFT;
const KVM_REG_ARM64_SYSREG: u64 = 0x0013 << KVM_REG_ARM_COPROC_SHIFT;

/// Core-reg id for a `struct kvm_regs` field at `byte_offset`. The low bits of
/// a KVM_REG_ARM_CORE id are `offsetof(kvm_regs, field) / sizeof(__u32)`.
fn core_reg_id(byte_offset: u64) -> u64 {
    KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | (byte_offset / 4)
}

// Byte offsets into `struct kvm_regs`:
//   struct user_pt_regs regs;   // 0:  regs[31] (0..248), sp@248, pc@256, pstate@264 -> 272 bytes
//   __u64 sp_el1;               // 272
//   __u64 elr_el1;              // 280
//   __u64 spsr[KVM_NR_SPSR];    // 288 (spsr[0] == SPSR_EL1)
// `user_pt_regs.sp` is SP_EL0 (the EL0/user stack).
const USER_PT_REGS_SP_EL0: u64 = 31 * 8; // 248
const USER_PT_REGS_PC: u64 = USER_PT_REGS_SP_EL0 + 8; // 256
const USER_PT_REGS_PSTATE: u64 = USER_PT_REGS_PC + 8; // 264
const KVM_REGS_SP_EL1: u64 = 272;
const KVM_REGS_ELR_EL1: u64 = 280;
const KVM_REGS_SPSR_EL1: u64 = 288;

// KVM_REG_ARM64_SYSREG: id = base | (op0<<14)|(op1<<11)|(crn<<7)|(crm<<3)|op2
fn sysreg_id(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
    KVM_REG_ARM64
        | KVM_REG_SIZE_U64
        | KVM_REG_ARM64_SYSREG
        | (op0 << 14)
        | (op1 << 11)
        | (crn << 7)
        | (crm << 3)
        | op2
}

fn reg_to_id(r: Reg) -> u64 {
    // All of these live in the CORE register file (`struct kvm_regs`), NOT the
    // sysreg demux — including ELR_EL1 / SPSR_EL1 / SP_EL1 (see SysReg vs Reg).
    match r {
        Reg::X(n) => core_reg_id(u64::from(n) * 8), // offsetof(kvm_regs, regs.regs[n]) == n*8
        Reg::Sp => core_reg_id(USER_PT_REGS_SP_EL0), // == SP_EL0
        Reg::Pc => core_reg_id(USER_PT_REGS_PC),
        Reg::Pstate => core_reg_id(USER_PT_REGS_PSTATE),
        Reg::SpEl1 => core_reg_id(KVM_REGS_SP_EL1),
        Reg::ElrEl1 => core_reg_id(KVM_REGS_ELR_EL1),
        Reg::SpsrEl1 => core_reg_id(KVM_REGS_SPSR_EL1),
    }
}
fn sysreg_to_id(r: SysReg) -> u64 {
    // Architectural (op0,op1,CRn,CRm,op2) encodings (ARM ARM, AArch64-sysreg).
    match r {
        SysReg::Sctlr => sysreg_id(3, 0, 1, 0, 0),     // SCTLR_EL1
        SysReg::Ttbr0 => sysreg_id(3, 0, 2, 0, 0),     // TTBR0_EL1
        SysReg::Ttbr1 => sysreg_id(3, 0, 2, 0, 1),     // TTBR1_EL1
        SysReg::Tcr => sysreg_id(3, 0, 2, 0, 2),       // TCR_EL1
        SysReg::Mair => sysreg_id(3, 0, 10, 2, 0),     // MAIR_EL1
        SysReg::Vbar => sysreg_id(3, 0, 12, 0, 0),     // VBAR_EL1
        SysReg::Cpacr => sysreg_id(3, 0, 1, 0, 2),     // CPACR_EL1
        SysReg::TpidrEl0 => sysreg_id(3, 3, 13, 0, 2), // TPIDR_EL0 (EL0 thread pointer)
    }
}

pub struct KvmVm {
    _kvm: Kvm,
    vm: VmFd,
    next_slot: u32,
}
pub struct KvmVcpu {
    fd: VcpuFd,
}

impl KvmVm {
    /// Open `/dev/kvm` and `KVM_CREATE_VM` with no address space — the child
    /// side of `fork(2)` rebuilds its VM over the parent's already-built
    /// `GuestRam` windows, so there is no `AddressSpace` to thread through.
    /// (`HvVm::create` ignores its `&AddressSpace` argument; this is the same
    /// bring-up without the unused parameter.)
    pub(crate) fn create_empty() -> Result<Self, OsError> {
        let kvm = Kvm::new().map_err(|e| os_err("open /dev/kvm", e))?;
        let vm = kvm.create_vm().map_err(|e| os_err("KVM_CREATE_VM", e))?;
        Ok(Self {
            _kvm: kvm,
            vm,
            next_slot: 0,
        })
    }
}

impl HvVm for KvmVm {
    type Vcpu = KvmVcpu;

    fn create(_mem: &AddressSpace) -> Result<Self, OsError> {
        Self::create_empty()
    }

    fn map_memory(
        &mut self,
        gpa: u64,
        host: *mut u8,
        len: usize,
        _perms: MemPerms,
    ) -> Result<(), OsError> {
        let region = kvm_userspace_memory_region {
            slot: self.next_slot,
            guest_phys_addr: gpa,
            memory_size: len as u64,
            userspace_addr: host as u64,
            flags: 0, // not KVM_MEM_LOG_DIRTY_PAGES; W^X enforced in stage-1
        };
        // SAFETY: `host`..`host+len` is a live mmap owned by guest_setup for the
        // lifetime of the VM; KVM only accesses it while the vCPU runs.
        unsafe {
            self.vm
                .set_user_memory_region(region)
                .map_err(|e| os_err("KVM_SET_USER_MEMORY_REGION", e))?;
        }
        self.next_slot += 1;
        let _ = KVM_MEM_LOG_DIRTY_PAGES; // keep import meaningful; unused in MVP
        Ok(())
    }

    fn add_vcpu(&mut self) -> Result<Self::Vcpu, OsError> {
        let fd = self
            .vm
            .create_vcpu(0)
            .map_err(|e| os_err("KVM_CREATE_VCPU", e))?;
        // aarch64: ask the kernel for its preferred CPU target, then init.
        let mut kvi = kvm_bindings::kvm_vcpu_init::default();
        self.vm
            .get_preferred_target(&mut kvi)
            .map_err(|e| os_err("KVM_ARM_PREFERRED_TARGET", e))?;
        // PSCI 0.2 so a future PSCI SYSTEM_OFF / smoke path is available; the
        // MVP exits via exit_group, but the bit is harmless and standard.
        kvi.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
        fd.vcpu_init(&kvi)
            .map_err(|e| os_err("KVM_ARM_VCPU_INIT", e))?;
        Ok(KvmVcpu { fd })
    }

    fn destroy(self) -> Result<(), OsError> {
        // VmFd/Kvm own their fds; dropping closes them (KVM tears down the VM).
        Ok(())
    }
}

impl HvVcpu for KvmVcpu {
    fn run(&mut self) -> Result<VcpuExit, OsError> {
        match self.fd.run().map_err(|e| os_err("KVM_RUN", e))? {
            KvmExit::MmioWrite(gpa, data) => {
                // KVM hands us the bytes written and the length via the slice.
                let len = data.len() as u8;
                let mut buf = [0u8; 8];
                buf[..data.len()].copy_from_slice(data);
                Ok(VcpuExit::MmioWrite {
                    gpa,
                    data: u64::from_le_bytes(buf),
                    len,
                })
            }
            KvmExit::SystemEvent(_, _) => Ok(VcpuExit::Halt),
            KvmExit::Shutdown | KvmExit::Hlt => Ok(VcpuExit::Halt),
            KvmExit::Intr => Ok(VcpuExit::Kicked),
            other => Err(os_err("unexpected KVM_RUN exit", format!("{other:?}"))),
        }
    }

    fn reg(&self, r: Reg) -> Result<u64, OsError> {
        let mut bytes = [0u8; 8];
        self.fd
            .get_one_reg(reg_to_id(r), &mut bytes)
            .map_err(|e| os_err("KVM_GET_ONE_REG", e))?;
        Ok(u64::from_le_bytes(bytes))
    }
    fn set_reg(&mut self, r: Reg, v: u64) -> Result<(), OsError> {
        let bytes = v.to_le_bytes();
        self.fd
            .set_one_reg(reg_to_id(r), &bytes)
            .map_err(|e| os_err("KVM_SET_ONE_REG", e))?;
        Ok(())
    }
    fn set_sys_reg(&mut self, r: SysReg, v: u64) -> Result<(), OsError> {
        let bytes = v.to_le_bytes();
        self.fd
            .set_one_reg(sysreg_to_id(r), &bytes)
            .map_err(|e| os_err("KVM_SET_ONE_REG(sysreg)", e))?;
        Ok(())
    }

    fn kick(&self) -> Result<(), OsError> {
        // A signal delivered to the vCPU thread makes KVM_RUN return EINTR
        // (-> VcpuExit::Intr -> VcpuExit::Kicked). The MVP is single-threaded
        // (write+exit, no cross-thread wakeups), so this is exercised only by
        // the full backend; provide the mechanism, not a thread registry.
        Ok(())
    }
}

impl KvmVcpu {
    /// Read a system register through `KVM_GET_ONE_REG` + the sysreg demux
    /// (`sysreg_to_id`). Symmetric to [`HvVcpu::set_sys_reg`]; used by
    /// [`Self::snapshot`] to capture the stage-1 MMU + thread-pointer registers
    /// across `fork(2)`.
    pub fn get_sys_reg(&self, r: SysReg) -> Result<u64, OsError> {
        let mut bytes = [0u8; 8];
        self.fd
            .get_one_reg(sysreg_to_id(r), &mut bytes)
            .map_err(|e| os_err("KVM_GET_ONE_REG(sysreg)", e))?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Capture the parent vCPU's architectural register file before `fork(2)`
    /// so the rebuilt child vCPU can resume exactly where the parent left off
    /// (inside the trapped `clone`/`fork` syscall).
    ///
    /// FP/SIMD state (`vregs`/`fpsr`/`fpcr`) is STUBBED to zero in Phase 2 — full
    /// FP capture is Phase 4. The fields are kept on [`VcpuSnapshot`] so Task 5
    /// (threads) can reuse the struct without an ABI change.
    pub fn snapshot(&self) -> Result<VcpuSnapshot, OsError> {
        let mut gprs = [0u64; 31];
        for (n, g) in gprs.iter_mut().enumerate() {
            *g = self.reg(Reg::X(n as u32))?;
        }
        Ok(VcpuSnapshot {
            gprs,
            pc: self.reg(Reg::Pc)?,
            pstate: self.reg(Reg::Pstate)?,
            sp_el0: self.reg(Reg::Sp)?, // user_pt_regs.sp == SP_EL0
            sp_el1: self.reg(Reg::SpEl1)?,
            elr_el1: self.reg(Reg::ElrEl1)?,
            spsr_el1: self.reg(Reg::SpsrEl1)?,
            ttbr0: self.get_sys_reg(SysReg::Ttbr0)?,
            ttbr1: self.get_sys_reg(SysReg::Ttbr1)?,
            tcr: self.get_sys_reg(SysReg::Tcr)?,
            sctlr: self.get_sys_reg(SysReg::Sctlr)?,
            mair: self.get_sys_reg(SysReg::Mair)?,
            vbar: self.get_sys_reg(SysReg::Vbar)?,
            cpacr: self.get_sys_reg(SysReg::Cpacr)?,
            tpidr_el0: self.get_sys_reg(SysReg::TpidrEl0)?,
            // Phase 4: real FP/SIMD capture. Zero-stubbed for now.
            vregs: [0; 32],
            fpsr: 0,
            fpcr: 0,
        })
    }

    /// Restore a [`VcpuSnapshot`] onto this (freshly created) vCPU. The mirror of
    /// [`Self::snapshot`]; FP/SIMD fields are skipped in Phase 2 (zero-stubbed).
    pub fn restore(&mut self, snap: &VcpuSnapshot) -> Result<(), OsError> {
        for (n, g) in snap.gprs.iter().enumerate() {
            self.set_reg(Reg::X(n as u32), *g)?;
        }
        self.set_reg(Reg::Pc, snap.pc)?;
        self.set_reg(Reg::Pstate, snap.pstate)?;
        self.set_reg(Reg::Sp, snap.sp_el0)?; // SP_EL0
        self.set_reg(Reg::SpEl1, snap.sp_el1)?;
        self.set_reg(Reg::ElrEl1, snap.elr_el1)?;
        self.set_reg(Reg::SpsrEl1, snap.spsr_el1)?;
        self.set_sys_reg(SysReg::Ttbr0, snap.ttbr0)?;
        self.set_sys_reg(SysReg::Ttbr1, snap.ttbr1)?;
        self.set_sys_reg(SysReg::Tcr, snap.tcr)?;
        self.set_sys_reg(SysReg::Sctlr, snap.sctlr)?;
        self.set_sys_reg(SysReg::Mair, snap.mair)?;
        self.set_sys_reg(SysReg::Vbar, snap.vbar)?;
        self.set_sys_reg(SysReg::Cpacr, snap.cpacr)?;
        self.set_sys_reg(SysReg::TpidrEl0, snap.tpidr_el0)?;
        // Phase 4: restore vregs/fpsr/fpcr. Skipped while zero-stubbed.
        Ok(())
    }
}
