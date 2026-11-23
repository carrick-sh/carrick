//! HVF vCPU setup, mailbox binding, and trapped register reads.

use super::*;

#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::cmp::Eq, ::core::cmp::PartialEq)]
pub(crate) enum SetupVcpuCleanup {
    /// The pending VM-creation transaction destroys the recorded vCPU with its
    /// VM on rollback.
    PendingRaw,
    /// The vCPU's own setup failed before it ran: destroy it through
    /// `destroy_raw_vcpu` (`VcpuDestroySite::CreationError`).
    DestroyOnError,
}

pub(crate) struct SetupVcpuGuard {
    vcpu: std::mem::ManuallyDrop<applevisor::vcpu::Vcpu>,
    cleanup: SetupVcpuCleanup,
    armed: bool,
}

impl SetupVcpuGuard {
    pub(crate) fn new(vcpu: applevisor::vcpu::Vcpu, cleanup: SetupVcpuCleanup) -> Self {
        Self {
            vcpu: std::mem::ManuallyDrop::new(vcpu),
            cleanup,
            armed: true,
        }
    }

    pub(crate) fn into_inner(mut self) -> applevisor::vcpu::Vcpu {
        self.armed = false;
        // SAFETY: `armed` prevents Drop from touching the value after this
        // single ownership transfer.
        unsafe { std::mem::ManuallyDrop::take(&mut self.vcpu) }
    }
}

impl std::ops::Deref for SetupVcpuGuard {
    type Target = applevisor::vcpu::Vcpu;

    fn deref(&self) -> &Self::Target {
        &self.vcpu
    }
}

impl Drop for SetupVcpuGuard {
    fn drop(&mut self) {
        if !self.armed || self.cleanup == SetupVcpuCleanup::PendingRaw {
            return;
        }
        // The wrapper stays in `ManuallyDrop`: applevisor's destructor never
        // runs, and the one raw destroy funnel reports the destroy.
        let _ = destroy_raw_vcpu(self.vcpu.id(), VcpuDestroySite::CreationError);
        self.armed = false;
    }
}

impl HvfVmState {
    /// Create a fresh vCPU bound to this VM. Admitted only while the VM's
    /// topology assembles (`vcpu_topology`).
    pub(crate) fn add_vcpu(
        &mut self,
    ) -> Result<(applevisor::vcpu::Vcpu, MailboxBinding), TrapError> {
        let vcpu = create_vcpu(&self._vm)?;
        enable_el0_counter_access(vcpu.id());
        let mailbox = self.allocate_mailbox_for_vcpu(&vcpu)?;
        self.executor_vcpu = Some(ExecutorVcpuIdentity::of(&vcpu));
        self.publish_live_vcpu();
        Ok((vcpu.into_inner(), mailbox))
    }

    pub(crate) fn allocate_mailbox_for_vcpu(
        &self,
        vcpu: &applevisor::vcpu::Vcpu,
    ) -> Result<MailboxBinding, TrapError> {
        use applevisor::prelude::SysReg;

        let lease = self
            .mailbox_slots
            .allocate()
            .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
        let address = lease.id().guest_address();
        let pointer = self.mailbox_host_pointer(lease.id())?;
        // SAFETY: `mailbox_host_pointer` resolved the complete fixed slot from
        // this VM's process-lifetime mapping, and the lease uniquely owns it.
        let binding = unsafe { MailboxBinding::new(lease, pointer, self.syscall_transport) };
        vcpu.set_sys_reg(SysReg::SP_EL1, address)
            .map_err(hvf_error)?;
        Ok(binding)
    }

    pub(crate) fn emulate_el0_sys64_read_inner(
        vcpu: &mut applevisor::vcpu::Vcpu,
        esr: u64,
    ) -> Result<bool, TrapError> {
        use applevisor::prelude::*;

        // EL0 read of a feature-ID register (the CRn==0, Op0==3, Op1==0 space).
        // The Linux kernel emulates these for userspace; Apple Rosetta reads
        // ID_AA64MMFR1_EL1 (and friends) at startup, and without this the MRS
        // takes a fatal undef. Return the real vCPU value. (The Op1==3 timer /
        // CTR_EL0 / DCZID_EL0 reads handled below are a separate space.)
        let op0 = (esr >> 20) & 0x3;
        let op1 = (esr >> 14) & 0x7;
        let crn = (esr >> 10) & 0xf;
        let crm = (esr >> 1) & 0xf;
        let op2 = (esr >> 17) & 0x7;
        let direction_read = esr & 1 == 1;
        if direction_read && op0 == 3 && op1 == 0 && crn == 0 {
            let rt_id = ((esr >> 5) & 0x1f) as usize;
            let enc = (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2;
            let id_reg = match enc {
                0xc000 => Some(SysReg::MIDR_EL1),
                0xc020 => Some(SysReg::ID_AA64PFR0_EL1),
                0xc021 => Some(SysReg::ID_AA64PFR1_EL1),
                0xc028 => Some(SysReg::ID_AA64DFR0_EL1),
                0xc029 => Some(SysReg::ID_AA64DFR1_EL1),
                0xc030 => Some(SysReg::ID_AA64ISAR0_EL1),
                0xc031 => Some(SysReg::ID_AA64ISAR1_EL1),
                0xc038 => Some(SysReg::ID_AA64MMFR0_EL1),
                0xc039 => Some(SysReg::ID_AA64MMFR1_EL1),
                0xc03a => Some(SysReg::ID_AA64MMFR2_EL1),
                // Any other CRn==0/Op0==3/Op1==0 slot reads-as-zero (RES0),
                // matching the architectural default for unallocated ID regs.
                _ => None,
            };
            let value = match id_reg {
                // The in-kernel GIC makes the vCPU report the GIC
                // system-register interface; Linux hides that field from EL0.
                Some(SysReg::ID_AA64PFR0_EL1) => crate::gic::el0_id_aa64pfr0_view(
                    vcpu.get_sys_reg(SysReg::ID_AA64PFR0_EL1)
                        .map_err(hvf_error)?,
                ),
                Some(reg) => vcpu.get_sys_reg(reg).map_err(hvf_error)?,
                None => 0,
            };
            if let Some(target) = GPR_TABLE.get(rt_id) {
                vcpu.set_reg(*target, value).map_err(hvf_error)?;
            }
            let elr = vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_error)?;
            vcpu.set_sys_reg(SysReg::ELR_EL1, elr.wrapping_add(4))
                .map_err(hvf_error)?;
            return Ok(true);
        }

        let Some((rt, reg)) = decode_el0_sys64_read(esr) else {
            return Ok(false);
        };
        let value = match reg {
            El0SysRegRead::CntfrqEl0 => AARCH64_GUEST_COUNTER_HZ,
            El0SysRegRead::CntvctEl0 => guest_counter_ticks(),
            // Fallback if a guest's CTR_EL0/DCZID_EL0 read still traps despite
            // SCTLR_EL1.UCT/DZE (e.g. a forked child before its sysregs are
            // re-applied). Return the real host cache geometry.
            El0SysRegRead::CtrEl0 => host_ctr_dczid().0,
            El0SysRegRead::DczidEl0 => host_ctr_dczid().1,
        };
        if let Some(target) = GPR_TABLE.get(rt as usize) {
            vcpu.set_reg(*target, value).map_err(hvf_error)?;
        }
        let elr = vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::ELR_EL1, elr.wrapping_add(4))
            .map_err(hvf_error)?;
        Ok(true)
    }
}
