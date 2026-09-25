//! A cross-thread kick the run loop could not surface where it landed.
//!
//! A kick (`hv_vcpus_exit`, KVM `KVM_RUN` EINTR) that stops the vCPU inside
//! Carrick's own EL1 code — the syscall vector, the EL1 kernel image, or the
//! EL0 clock stub mid-completion — cannot be reported there: treating that PC
//! as interrupted guest code corrupts the in-flight syscall. The engine
//! therefore re-enters the guest and owes the kick to the next EL0 instruction
//! boundary, delivering it as a pending virtual IRQ whose vector (`hvc` kick,
//! lower-EL IRQ slot) surfaces a normal EL0 kick.
//!
//! Two host facts make the naive "arm a pending IRQ and continue" lose that
//! kick, and this type exists to close both:
//!
//! - Carrick runs guest EL0 with DAIF masked (`SPSR_EL1 = EL0t | 0x3c0`). The
//!   armed IRQ is never taken at EL0, so the vCPU keeps executing guest code
//!   until some unrelated exit. A Go thread computing between clock reads
//!   (which the backend emulates without surfacing) can run for seconds; the
//!   page-table drain that kicked it then waited out its budget and the guest
//!   died with `fault page-table pause failed before mutation: TimedOut`.
//!   Owing the kick therefore unmasks `I` in the EL0 return state, and the
//!   surfacing exit restores the original bit, so the guest never observes the
//!   change.
//! - Hypervisor.framework clears pending interrupts on EVERY `hv_vcpu_run`
//!   return (qualified with a standalone HVF probe on macOS 27.2 / M4), so any
//!   exit the loop handles internally before the IRQ is taken must re-arm it.
//!
//! The obligation ends at the first exit that surfaces to the runtime: the host
//! then has control, which is all a kick asks for.

use carrick_hal::{Reg, TrapError};

use crate::vmm::Aarch64Vcpu;

/// PSTATE/SPSR `I` (IRQ mask) bit.
const PSTATE_I: u64 = 1 << 7;

/// Where the absorbed kick stopped the vCPU (for the `kick-rearm-irq` probe).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbsorbedKickSite {
    El1Vector = 1,
    El1Image = 2,
    El0ClockStub = 3,
}

/// The kick currently owed to the EL0 boundary, if any, for one `next_syscall`.
#[derive(Debug, Default)]
pub struct OwedKick {
    /// `Some(original_i)` while owed: whether the EL0 return state had `I` set
    /// before the owed kick cleared it.
    original_i: Option<bool>,
}

impl OwedKick {
    pub fn is_owed(&self) -> bool {
        self.original_i.is_some()
    }

    /// A kick stopped the vCPU inside Carrick's EL1 code: owe it to EL0. The
    /// caller re-enters the guest afterwards.
    pub fn absorb<C: Aarch64Vcpu + ?Sized>(
        &mut self,
        vcpu: &mut C,
        pc: u64,
        site: AbsorbedKickSite,
    ) -> Result<(), TrapError> {
        let el0_state = el0_return_state(vcpu)?;
        let el0_pstate = vcpu.get_reg(el0_state)?;
        carrick_observability::probes::kick_rearm_irq(
            pc,
            site as u32,
            el0_pstate,
            vcpu.get_reg(Reg::ElrEl1).unwrap_or(u64::MAX),
        );
        if !vcpu.injects_kick_irq()
            || !carrick_hal::aarch64::ExecLevel::from_pstate(el0_pstate).is_guest()
        {
            // No IRQ vehicle on this backend, or no EL0 return state to unmask
            // (Carrick's current-EL IRQ slots are bare `eret`, so an IRQ must
            // never be deliverable at EL1): leave the state untouched. The
            // kick is served at the next surfaced exit.
            return vcpu.set_pending_irq(true);
        }
        let original_i = *self.original_i.get_or_insert(el0_pstate & PSTATE_I != 0);
        if original_i {
            vcpu.set_reg(el0_state, el0_pstate & !PSTATE_I)?;
        }
        vcpu.set_pending_irq(true)
    }

    /// The loop handled an exit internally and is about to re-enter: the
    /// backend dropped the pending IRQ on that return, so arm it again.
    pub fn rearm<C: Aarch64Vcpu + ?Sized>(&self, vcpu: &mut C) -> Result<(), TrapError> {
        if self.is_owed() {
            vcpu.set_pending_irq(true)?;
        }
        Ok(())
    }

    /// An exit is surfacing to the runtime, so the kick is served. Restore the
    /// original `I` bit wherever the interrupted EL0 PSTATE lives now.
    pub fn settle<C: Aarch64Vcpu + ?Sized>(&mut self, vcpu: &mut C) -> Result<(), TrapError> {
        let Some(original_i) = self.original_i.take() else {
            return Ok(());
        };
        let pstate = vcpu.get_reg(Reg::Pstate)?;
        let el0_state = el0_return_state(vcpu)?;
        carrick_observability::probes::owed_kick_settle(
            vcpu.get_reg(Reg::Pc).unwrap_or(0),
            pstate,
            vcpu.get_reg(el0_state).unwrap_or(u64::MAX),
        );
        vcpu.set_pending_irq(false)?;
        if !original_i {
            return Ok(());
        }
        let el0_state = el0_return_state(vcpu)?;
        let el0_pstate = vcpu.get_reg(el0_state)?;
        vcpu.set_reg(el0_state, el0_pstate | PSTATE_I)
    }
}

/// Where the interrupted EL0 PSTATE lives right now: the live PSTATE when the
/// vCPU is stopped at EL0 (a normalized clock restart, or the IRQ-kick exit
/// that restored PSTATE from SPSR), else `SPSR_EL1`, which Carrick's EL1 code
/// will `eret` into.
fn el0_return_state<C: Aarch64Vcpu + ?Sized>(vcpu: &C) -> Result<Reg, TrapError> {
    let pstate = vcpu.get_reg(Reg::Pstate)?;
    Ok(
        if carrick_hal::aarch64::ExecLevel::from_pstate(pstate).is_guest() {
            Reg::Pstate
        } else {
            Reg::SpsrEl1
        },
    )
}

#[cfg(test)]
mod tests {
    //! Contract `kernel.vcpu.kick-el0-boundary` (VM-free binding).
    //!
    //! `ModelVcpu` models exactly the Hypervisor.framework facts the owed kick
    //! depends on, each qualified live with a standalone HVF probe on this
    //! host: a pending IRQ is taken at EL0 only when PSTATE.I is clear, `eret`
    //! loads PSTATE from SPSR_EL1, and every `run` return clears the pending
    //! IRQ. Carrick's EL0 state is `EL0t | DAIF masked` (0x3c0).
    use super::*;
    use crate::vmm::{Aarch64Exit, Aarch64VcpuSnapshot};
    use carrick_guest_mem::Aarch64SyscallFrame;
    use carrick_hal::SysReg;

    const EL0_DAIF_MASKED: u64 = 0x3c0;
    const EL1H_DAIF_MASKED: u64 = 0x3c5;
    const GUEST_PC: u64 = 0x4000_1000;

    fn vector_resume_pc() -> u64 {
        carrick_mem::memory::LINUX_EL1_VECTORS_BASE + 0xb30
    }

    struct ModelVcpu {
        pc: u64,
        pstate: u64,
        spsr_el1: u64,
        elr_el1: u64,
        pending_irq: bool,
        /// A `hv_vcpus_exit` latched before the next run.
        latched_kick: bool,
        /// Engine-visible internal exits the EL1 path takes before its `eret`.
        el1_exits_before_eret: u32,
        /// Guest EL0 instructions retired so far. A kick owed to the EL0
        /// boundary must surface with this still zero.
        el0_steps: u64,
        /// Trapped clock reads (emulated inside the backend's run, so invisible
        /// to the engine) before the guest's next surfaced syscall.
        clock_reads_before_syscall: u32,
    }

    impl ModelVcpu {
        /// Stopped in Carrick's syscall vector just after the host returned
        /// from the `hvc`, about to `eret` to EL0 — where a kick latched while
        /// the executor was entering lands (trace: `pc=0x...b30 el=1`).
        fn at_vector_resume(clock_reads_before_syscall: u32) -> Self {
            Self {
                pc: vector_resume_pc(),
                pstate: EL1H_DAIF_MASKED,
                spsr_el1: EL0_DAIF_MASKED,
                elr_el1: GUEST_PC,
                pending_irq: false,
                latched_kick: true,
                el1_exits_before_eret: 0,
                el0_steps: 0,
                clock_reads_before_syscall,
            }
        }

        fn at_el0(&self) -> bool {
            carrick_hal::aarch64::ExecLevel::from_pstate(self.pstate).is_guest()
        }
    }

    impl Aarch64Vcpu for ModelVcpu {
        fn get_reg(&self, r: Reg) -> Result<u64, TrapError> {
            Ok(match r {
                Reg::Pc => self.pc,
                Reg::Pstate => self.pstate,
                Reg::SpsrEl1 => self.spsr_el1,
                Reg::ElrEl1 => self.elr_el1,
                _ => 0,
            })
        }

        fn set_reg(&mut self, r: Reg, v: u64) -> Result<(), TrapError> {
            match r {
                Reg::Pc => self.pc = v,
                Reg::Pstate => self.pstate = v,
                Reg::SpsrEl1 => self.spsr_el1 = v,
                Reg::ElrEl1 => self.elr_el1 = v,
                _ => {}
            }
            Ok(())
        }

        fn get_sys_reg(&self, _r: SysReg) -> Result<u64, TrapError> {
            Ok(0)
        }

        fn set_sys_reg(&mut self, _r: SysReg, _v: u64) -> Result<(), TrapError> {
            Ok(())
        }

        fn get_vreg(&self, _n: u32) -> Result<u128, TrapError> {
            Ok(0)
        }

        fn set_vreg(&mut self, _n: u32, _v: u128) -> Result<(), TrapError> {
            Ok(())
        }

        fn get_fpcr(&self) -> Result<u64, TrapError> {
            Ok(0)
        }

        fn set_fpcr(&mut self, _v: u64) -> Result<(), TrapError> {
            Ok(())
        }

        fn get_fpsr(&self) -> Result<u64, TrapError> {
            Ok(0)
        }

        fn set_fpsr(&mut self, _v: u64) -> Result<(), TrapError> {
            Ok(())
        }

        fn get_esr_el1(&self) -> Result<u64, TrapError> {
            Ok(0)
        }

        fn get_far_el1(&self) -> Result<u64, TrapError> {
            Ok(0)
        }

        fn snapshot(&self) -> Result<Aarch64VcpuSnapshot, TrapError> {
            Err(TrapError::Hypervisor("unused model snapshot".into()))
        }

        fn restore(&mut self, _snap: &Aarch64VcpuSnapshot) -> Result<(), TrapError> {
            Ok(())
        }

        fn set_pending_irq(&mut self, pending: bool) -> Result<(), TrapError> {
            self.pending_irq = pending;
            Ok(())
        }

        fn injects_kick_irq(&self) -> bool {
            true
        }

        fn run(&mut self) -> Result<Aarch64Exit, TrapError> {
            let exit = self.run_until_exit();
            // Hypervisor.framework: every run return clears pending IRQs.
            self.pending_irq = false;
            Ok(exit)
        }

        fn kick(&self) -> Result<(), TrapError> {
            Ok(())
        }
    }

    impl ModelVcpu {
        fn run_until_exit(&mut self) -> Aarch64Exit {
            if std::mem::take(&mut self.latched_kick) {
                return Aarch64Exit::Kicked;
            }
            if !self.at_el0() {
                if self.el1_exits_before_eret > 0 {
                    self.el1_exits_before_eret -= 1;
                    return Aarch64Exit::MaintenanceDone;
                }
                // eret
                self.pstate = self.spsr_el1;
                self.pc = self.elr_el1;
            }
            loop {
                if self.pending_irq && self.pstate & PSTATE_I == 0 {
                    // Lower-EL IRQ vector `hvc` kick; the backend decode puts
                    // the interrupted EL0 PC/PSTATE back before surfacing.
                    self.spsr_el1 = self.pstate;
                    self.elr_el1 = self.pc;
                    return Aarch64Exit::Kicked;
                }
                if self.clock_reads_before_syscall == 0 {
                    return Aarch64Exit::Syscall {
                        frame: Aarch64SyscallFrame {
                            x0: 0,
                            x1: 0,
                            x2: 0,
                            x3: 0,
                            x4: 0,
                            x5: 0,
                            x8: 172,
                        },
                        resume_pc: self.pc + 4,
                        current_guest_sp: None,
                    };
                }
                // A trapped CNTVCT_EL0 read, emulated inside the backend run
                // loop: the engine never sees it, but HVF's return clears the
                // pending IRQ exactly as a surfaced exit would.
                self.clock_reads_before_syscall -= 1;
                self.el0_steps += 1;
                self.pending_irq = false;
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Surfaced {
        Kick { pc: u64, pstate: u64 },
        Syscall,
    }

    /// The engine's `next_syscall` dispositions for the exits this model
    /// produces, in the same order.
    fn next_surfaced(vcpu: &mut ModelVcpu) -> Surfaced {
        let mut owed = OwedKick::default();
        loop {
            match vcpu.run().expect("model run") {
                Aarch64Exit::Kicked => {
                    let pc = vcpu.get_reg(Reg::Pc).expect("pc");
                    if carrick_mem::memory::is_carrick_el1_vector_va(pc) {
                        owed.absorb(vcpu, pc, AbsorbedKickSite::El1Vector)
                            .expect("absorb");
                        continue;
                    }
                    owed.settle(vcpu).expect("settle");
                    return Surfaced::Kick {
                        pc,
                        pstate: vcpu.get_reg(Reg::Pstate).expect("pstate"),
                    };
                }
                Aarch64Exit::MaintenanceDone | Aarch64Exit::Sys64Read { .. } => {
                    owed.rearm(vcpu).expect("rearm");
                }
                Aarch64Exit::Syscall { .. } => {
                    owed.settle(vcpu).expect("settle");
                    return Surfaced::Syscall;
                }
                other => panic!("unexpected model exit {other:?}"),
            }
        }
    }

    /// A kick latched while the executor was entering lands in the syscall
    /// vector. It must surface at the first EL0 instruction boundary — before
    /// the guest retires any EL0 work — however long the guest would otherwise
    /// compute between surfaced exits, and the guest's PSTATE must come back
    /// exactly as it was.
    #[test]
    fn kick_absorbed_in_el1_vector_surfaces_at_the_el0_boundary() {
        for clock_reads in [1_u32, 8, 32, 128] {
            let mut vcpu = ModelVcpu::at_vector_resume(clock_reads);
            let surfaced = next_surfaced(&mut vcpu);
            assert_eq!(
                surfaced,
                Surfaced::Kick {
                    pc: GUEST_PC,
                    pstate: EL0_DAIF_MASKED,
                },
                "{clock_reads} clock reads: the owed kick must surface at EL0 with the \
                 original masked PSTATE, not after the guest's next syscall"
            );
            assert_eq!(
                vcpu.el0_steps, 0,
                "the guest retired EL0 work while a kick was owed"
            );
            assert!(!vcpu.pending_irq);
        }
    }

    /// An EL1 exit the loop handles internally before the vector's `eret`
    /// clears the pending IRQ; the owed kick must be re-armed each time.
    #[test]
    fn owed_kick_survives_internal_el1_exits_before_eret() {
        for internal_exits in [1_u32, 8, 32] {
            let mut vcpu = ModelVcpu::at_vector_resume(128);
            vcpu.el1_exits_before_eret = internal_exits;
            assert_eq!(
                next_surfaced(&mut vcpu),
                Surfaced::Kick {
                    pc: GUEST_PC,
                    pstate: EL0_DAIF_MASKED,
                }
            );
            assert_eq!(vcpu.el0_steps, 0);
        }
    }

    /// When an unrelated exit surfaces first (a syscall taken from Carrick's
    /// EL1 code), the kick is served by that exit and the EL0 return state is
    /// restored in SPSR_EL1.
    #[test]
    fn surfaced_el1_exit_settles_the_owed_kick_in_spsr() {
        let mut vcpu = ModelVcpu::at_vector_resume(0);
        let mut owed = OwedKick::default();
        owed.absorb(&mut vcpu, vector_resume_pc(), AbsorbedKickSite::El1Vector)
            .expect("absorb");
        assert!(owed.is_owed());
        assert_eq!(vcpu.spsr_el1 & PSTATE_I, 0, "owed kick unmasks EL0 IRQ");
        owed.settle(&mut vcpu).expect("settle");
        assert!(!owed.is_owed());
        assert_eq!(vcpu.spsr_el1, EL0_DAIF_MASKED);
        assert!(!vcpu.pending_irq);
    }
}
