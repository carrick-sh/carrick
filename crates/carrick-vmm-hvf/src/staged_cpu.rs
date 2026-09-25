//! A root task's CPU state held as data before any vCPU runs it.
//!
//! EL1 plan 1a D2: every vCPU lives for its VM's whole life. A container root
//! therefore boots without a vCPU of its own, the way a clone child already
//! does: [`StagedCpu`] is the register file the root's bring-up programs, and
//! the root's first executor load restores it onto a live persistent-executor
//! vCPU. A staged CPU has never run, so stage-1 TLB maintenance requested
//! during bring-up is recorded and owed to that first live executor.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use carrick_aarch64::{Aarch64VcpuSnapshot, OwedStage1Maintenance, Stage1Maintenance};
use carrick_hal::{Reg, SysReg, TrapError};

use crate::trap::GuestMappingPlan;

/// `PSTATE` of a root before its first instruction: EL1h with `DAIF` masked, the
/// state the EL0-entry trampoline's `eret` leaves from.
pub(crate) const ROOT_BOOT_PSTATE: u64 = 0x3c5;
/// `SPSR_EL1` the trampoline's `eret` loads: EL0t with `DAIF` masked.
pub(crate) const ROOT_EL0_ENTRY_SPSR: u64 = 0x3c0;
/// `CNTKCTL_EL1.EL0VCTEN | EL0PCTEN`: EL0 reads the counters without trapping.
pub(crate) const EL0_COUNTER_ACCESS: u64 = (1 << 1) | (1 << 0);

/// The registers of a task that owns no vCPU yet.
// Transition: only the boot vCPU's shadow uses this until the root boots on it.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct StagedCpu {
    snapshot: Aarch64VcpuSnapshot,
    owed: OwedStage1Maintenance,
}

fn unsupported(what: &str) -> TrapError {
    TrapError::Hypervisor(format!("staged root CPU has no {what}"))
}

#[allow(dead_code)]
impl StagedCpu {
    /// The root's first-instruction register file, programmed from `plan`
    /// exactly as a freshly created vCPU would be before its first run.
    pub(crate) fn initial_root(plan: &GuestMappingPlan) -> Self {
        use carrick_hal::GuestArch as _;
        let boot = carrick_hal::Aarch64GuestArch::bootstrap_sysregs();
        let (elr_el1, spsr_el1) = match plan.el0_trampoline_entry {
            Some(_) => (plan.entry, ROOT_EL0_ENTRY_SPSR),
            None => (0, 0),
        };
        let (mair, tcr, ttbr, stage1) = match plan.stage1_page_tables_base {
            Some(base) => (boot.mair_el1, boot.tcr_el1, base, 1),
            None => (0, 0, 0, 0),
        };
        Self {
            snapshot: Aarch64VcpuSnapshot {
                gprs: [0; 31],
                pc: plan.el0_trampoline_entry.unwrap_or(plan.entry),
                pstate: ROOT_BOOT_PSTATE,
                sp_el0: plan.initial_stack_pointer.unwrap_or(0),
                sp_el1: 0,
                elr_el1,
                spsr_el1,
                ttbr0: ttbr,
                ttbr1: ttbr,
                tcr,
                sctlr: (boot.sctlr_el1 & !1) | stage1,
                mair,
                vbar: plan.el1_vectors_base.unwrap_or(0),
                cpacr: boot.cpacr_el1,
                cntkctl_el1: EL0_COUNTER_ACCESS,
                tpidr_el0: 0,
                tpidrro_el0: 0,
                tpidr_el1: 0,
                contextidr_el1: 0,
                actlr_el1: 0,
                vregs: [0; 32],
                fpsr: 0,
                fpcr: 0,
            },
            owed: OwedStage1Maintenance::default(),
        }
    }

    pub(crate) fn snapshot(&self) -> Aarch64VcpuSnapshot {
        self.snapshot.clone()
    }

    pub(crate) fn restore(&mut self, snapshot: &Aarch64VcpuSnapshot) {
        self.snapshot = snapshot.clone();
    }

    pub(crate) fn get_reg(&self, reg: Reg) -> Result<u64, TrapError> {
        let s = &self.snapshot;
        Ok(match reg {
            Reg::X(n) => *s
                .gprs
                .get(n as usize)
                .ok_or_else(|| unsupported("such general register"))?,
            Reg::Sp => s.sp_el0,
            Reg::Pc => s.pc,
            Reg::Pstate => s.pstate,
            Reg::SpEl1 => s.sp_el1,
            Reg::ElrEl1 => s.elr_el1,
            Reg::SpsrEl1 => s.spsr_el1,
            _ => return Err(unsupported("x86 register")),
        })
    }

    pub(crate) fn set_reg(&mut self, reg: Reg, value: u64) -> Result<(), TrapError> {
        let s = &mut self.snapshot;
        let slot = match reg {
            Reg::X(n) => s
                .gprs
                .get_mut(n as usize)
                .ok_or_else(|| unsupported("such general register"))?,
            Reg::Sp => &mut s.sp_el0,
            Reg::Pc => &mut s.pc,
            Reg::Pstate => &mut s.pstate,
            Reg::SpEl1 => &mut s.sp_el1,
            Reg::ElrEl1 => &mut s.elr_el1,
            Reg::SpsrEl1 => &mut s.spsr_el1,
            _ => return Err(unsupported("x86 register")),
        };
        *slot = value;
        Ok(())
    }

    /// The registers of the set `hvf_set_sys_reg` exposes, SCTLR_EL1 aside.
    fn sys_reg_slot(&mut self, reg: SysReg) -> Result<&mut u64, TrapError> {
        let s = &mut self.snapshot;
        Ok(match reg {
            SysReg::Ttbr0 => &mut s.ttbr0,
            SysReg::Ttbr1 => &mut s.ttbr1,
            SysReg::Tcr => &mut s.tcr,
            SysReg::Mair => &mut s.mair,
            SysReg::Vbar => &mut s.vbar,
            SysReg::Cpacr => &mut s.cpacr,
            SysReg::TpidrEl0 => &mut s.tpidr_el0,
            SysReg::Sctlr | SysReg::CntkctlEl1 | SysReg::FsBase | SysReg::GsBase => {
                return Err(unsupported("mapping for this system register"));
            }
        })
    }

    pub(crate) fn get_sys_reg(&self, reg: SysReg) -> Result<u64, TrapError> {
        let s = &self.snapshot;
        Ok(match reg {
            SysReg::Sctlr => s.sctlr,
            SysReg::Ttbr0 => s.ttbr0,
            SysReg::Ttbr1 => s.ttbr1,
            SysReg::Tcr => s.tcr,
            SysReg::Mair => s.mair,
            SysReg::Vbar => s.vbar,
            SysReg::Cpacr => s.cpacr,
            SysReg::TpidrEl0 => s.tpidr_el0,
            SysReg::CntkctlEl1 | SysReg::FsBase | SysReg::GsBase => {
                return Err(unsupported("mapping for this system register"));
            }
        })
    }

    pub(crate) fn set_sys_reg(&mut self, reg: SysReg, value: u64) -> Result<(), TrapError> {
        if reg == SysReg::Sctlr {
            self.snapshot.sctlr = value;
            return Ok(());
        }
        *self.sys_reg_slot(reg)? = value;
        Ok(())
    }

    pub(crate) fn get_vreg(&self, n: u32) -> Result<u128, TrapError> {
        self.snapshot
            .vregs
            .get(n as usize)
            .copied()
            .ok_or_else(|| TrapError::Hypervisor(format!("vreg index {n} out of range")))
    }

    pub(crate) fn set_vreg(&mut self, n: u32, value: u128) -> Result<(), TrapError> {
        let slot = self
            .snapshot
            .vregs
            .get_mut(n as usize)
            .ok_or_else(|| TrapError::Hypervisor(format!("vreg index {n} out of range")))?;
        *slot = value;
        Ok(())
    }

    pub(crate) fn fpcr(&self) -> u64 {
        u64::from(self.snapshot.fpcr)
    }

    pub(crate) fn set_fpcr(&mut self, value: u64) {
        self.snapshot.fpcr = value as u32;
    }

    pub(crate) fn fpsr(&self) -> u64 {
        u64::from(self.snapshot.fpsr)
    }

    pub(crate) fn set_fpsr(&mut self, value: u64) {
        self.snapshot.fpsr = value as u32;
    }

    pub(crate) fn actlr_el1(&self) -> u64 {
        self.snapshot.actlr_el1
    }

    pub(crate) fn set_actlr_el1(&mut self, value: u64) {
        self.snapshot.actlr_el1 = value;
    }

    /// The EL1 `gettid` word and the EL0 read-only thread pointer.
    pub(crate) fn stamp_guest_thread_id(&mut self, packed: u64) {
        self.snapshot.contextidr_el1 = packed & 0xffff_ffff;
        self.snapshot.tpidrro_el0 = packed;
    }

    /// Record maintenance this CPU cannot run: nothing has executed with its
    /// translations, so the first live executor that loads it discharges it.
    pub(crate) fn owe(&mut self, maintenance: Stage1Maintenance) {
        self.owed.record(maintenance);
    }

    pub(crate) fn take_owed(&mut self) -> OwedStage1Maintenance {
        std::mem::take(&mut self.owed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> GuestMappingPlan {
        GuestMappingPlan {
            entry: 0x40_1000,
            initial_stack_pointer: Some(0xff_ffff_e000),
            el0_trampoline_entry: Some(0x2d_0000_0000),
            el1_vectors_base: Some(carrick_mem::memory::LINUX_EL1_VECTORS_BASE),
            stage1_page_tables_base: Some(0x9a_0000_0000),
            ro_spans: Vec::new(),
            mappings: Vec::new(),
        }
    }

    #[test]
    fn a_staged_root_starts_at_the_el0_entry_trampoline() {
        let cpu = StagedCpu::initial_root(&plan());
        let s = cpu.snapshot();
        assert_eq!(s.pc, 0x2d_0000_0000);
        assert_eq!(s.pstate, ROOT_BOOT_PSTATE);
        assert_eq!(s.elr_el1, 0x40_1000);
        assert_eq!(s.spsr_el1, ROOT_EL0_ENTRY_SPSR);
        assert_eq!(s.sp_el0, 0xff_ffff_e000);
        assert_eq!((s.ttbr0, s.ttbr1), (0x9a_0000_0000, 0x9a_0000_0000));
        assert_eq!(s.sctlr & 1, 1, "stage-1 on when tables exist");
        assert!(carrick_mem::arch_sysregs::is_bootstrap_sctlr_el1(s.sctlr));

        assert_eq!(s.vbar, carrick_mem::memory::LINUX_EL1_VECTORS_BASE);
        assert_eq!(s.cntkctl_el1, EL0_COUNTER_ACCESS);
        assert_eq!(s.gprs, [0; 31]);
    }

    #[test]
    fn staged_registers_round_trip_through_the_hal_names() {
        let mut cpu = StagedCpu::initial_root(&plan());
        cpu.set_reg(Reg::X(8), 221).unwrap();
        cpu.set_sys_reg(SysReg::Tcr, 7).unwrap();
        cpu.set_vreg(31, 5).unwrap();
        cpu.stamp_guest_thread_id((9 << 32) | 4);
        assert_eq!(cpu.get_reg(Reg::X(8)).unwrap(), 221);
        assert_eq!(cpu.get_sys_reg(SysReg::Tcr).unwrap(), 7);
        assert_eq!(cpu.get_vreg(31).unwrap(), 5);
        assert_eq!(cpu.snapshot().contextidr_el1, 4);
        assert_eq!(cpu.snapshot().tpidrro_el0, (9 << 32) | 4);
        assert!(cpu.get_reg(Reg::X(31)).is_err());
        assert!(cpu.get_sys_reg(SysReg::CntkctlEl1).is_err());
        assert!(cpu.get_reg(Reg::Rax).is_err());
    }

    #[test]
    fn maintenance_a_staged_root_cannot_run_is_owed_once() {
        let mut cpu = StagedCpu::initial_root(&plan());
        assert!(cpu.take_owed().is_none());
        cpu.owe(Stage1Maintenance::AllAsids);
        cpu.owe(Stage1Maintenance::Asid(3));
        let owed = cpu.take_owed();
        assert!(owed.all_asids());
        assert!(cpu.take_owed().is_none(), "taking the debt clears it");
    }
}
