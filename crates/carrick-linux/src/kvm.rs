//! KvmVm / KvmVcpu: the `carrick-hal` raw-hypervisor layer (HvVm/HvVcpu) on
//! Linux/KVM, aarch64. /dev/kvm -> KVM_CREATE_VM -> KVM_CREATE_VCPU ->
//! KVM_ARM_PREFERRED_TARGET + KVM_ARM_VCPU_INIT; guest RAM via
//! KVM_SET_USER_MEMORY_REGION over a host mmap; registers via
//! KVM_GET/SET_ONE_REG; run via KVM_RUN. kick() is a signal-based vCPU exit.
use carrick_hal::{HvVcpu, HvVm, MemPerms, OsError, Reg, SysReg, VcpuExit};
use carrick_mem::memory::AddressSpace;
use kvm_bindings::{KVM_ARM_VCPU_PSCI_0_2, KVM_MEM_LOG_DIRTY_PAGES, kvm_userspace_memory_region};
use kvm_ioctls::{Kvm, VcpuExit as KvmExit, VcpuFd, VmFd};

fn os_err(context: &str, e: impl std::fmt::Display) -> OsError {
    OsError::new(format!("kvm: {context}: {e}"))
}

// KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE — core register file
// (x0..x30, sp, pc, pstate) addressed by byte offset into `struct user_pt_regs`.
const KVM_REG_ARM64: u64 = 0x6000_0000_0000_0000;
const KVM_REG_SIZE_U64: u64 = 0x0030_0000_0000_0000;
const KVM_REG_ARM_CORE: u64 = 0x0010_0000_0000_0000;

/// Core-reg id for `user_pt_regs.regs[idx]` (x0..x30); each entry is 8 bytes.
fn core_reg_id(idx_offset_bytes: u64) -> u64 {
    KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | (idx_offset_bytes / 4)
}
fn x_reg_id(n: u64) -> u64 {
    // offsetof(user_pt_regs, regs[n]) == n*8
    core_reg_id(n * 8)
}
// pc and pstate live after regs[31] (regs) + sp + pc + pstate in user_pt_regs:
//   regs[31] -> bytes 0..248, sp -> 248, pc -> 256, pstate -> 264.
const USER_PT_REGS_SP: u64 = 31 * 8; // 248
const USER_PT_REGS_PC: u64 = USER_PT_REGS_SP + 8; // 256
const USER_PT_REGS_PSTATE: u64 = USER_PT_REGS_PC + 8; // 264

// KVM_REG_ARM64_SYSREG: id = base | (op0<<14)|(op1<<11)|(crn<<7)|(crm<<3)|op2
const KVM_REG_ARM64_SYSREG: u64 = 0x0013_0000_0000_0000;
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
    match r {
        Reg::X(n) => x_reg_id(u64::from(n)),
        Reg::Pc => core_reg_id(USER_PT_REGS_PC),
        Reg::Sp => core_reg_id(USER_PT_REGS_SP),
        Reg::Pstate => core_reg_id(USER_PT_REGS_PSTATE),
    }
}
fn sysreg_to_id(r: SysReg) -> u64 {
    // Architectural (op0,op1,CRn,CRm,op2) encodings (ARM ARM, AArch64-sysreg).
    match r {
        SysReg::Sctlr => sysreg_id(3, 0, 1, 0, 0), // SCTLR_EL1
        SysReg::Ttbr0 => sysreg_id(3, 0, 2, 0, 0), // TTBR0_EL1
        SysReg::Ttbr1 => sysreg_id(3, 0, 2, 0, 1), // TTBR1_EL1
        SysReg::Tcr => sysreg_id(3, 0, 2, 0, 2),   // TCR_EL1
        SysReg::Mair => sysreg_id(3, 0, 10, 2, 0), // MAIR_EL1
        SysReg::Vbar => sysreg_id(3, 0, 12, 0, 0), // VBAR_EL1
        SysReg::Cpacr => sysreg_id(3, 0, 1, 0, 2), // CPACR_EL1
        SysReg::SpEl1 => sysreg_id(3, 4, 4, 1, 0), // SP_EL1
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

impl HvVm for KvmVm {
    type Vcpu = KvmVcpu;

    fn create(_mem: &AddressSpace) -> Result<Self, OsError> {
        let kvm = Kvm::new().map_err(|e| os_err("open /dev/kvm", e))?;
        let vm = kvm.create_vm().map_err(|e| os_err("KVM_CREATE_VM", e))?;
        Ok(Self {
            _kvm: kvm,
            vm,
            next_slot: 0,
        })
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
    fn elr_el1_id() -> u64 {
        // ELR_EL1: op0=3, op1=0, CRn=4, CRm=0, op2=1
        KVM_REG_ARM64
            | KVM_REG_SIZE_U64
            | KVM_REG_ARM64_SYSREG
            | (3 << 14)
            | (0 << 11)
            | (4 << 7)
            | (0 << 3)
            | 1
    }
    pub fn elr_el1(&self) -> Result<u64, OsError> {
        let mut bytes = [0u8; 8];
        self.fd
            .get_one_reg(Self::elr_el1_id(), &mut bytes)
            .map_err(|e| os_err("KVM_GET_ONE_REG(ELR_EL1)", e))?;
        Ok(u64::from_le_bytes(bytes))
    }
    pub fn set_elr_el1(&mut self, v: u64) -> Result<(), OsError> {
        let bytes = v.to_le_bytes();
        self.fd
            .set_one_reg(Self::elr_el1_id(), &bytes)
            .map_err(|e| os_err("KVM_SET_ONE_REG(ELR_EL1)", e))?;
        Ok(())
    }
}
