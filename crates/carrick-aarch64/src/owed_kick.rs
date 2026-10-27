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
//! - Without an interrupt controller, Hypervisor.framework clears pending
//!   interrupts on EVERY `hv_vcpu_run` return (qualified with a standalone HVF
//!   probe on macOS 27.2 / M4), so any exit the loop handles internally before
//!   the IRQ is taken must re-arm it. With the in-kernel GICv3 (the HVF
//!   default since EL1 plan 1a) the owed kick is a redistributor-pending SGI
//!   that survives run returns until it is taken or withdrawn: the re-arm is
//!   then an idempotent write (kept for the `CARRICK_HVF_GIC=0` hatch), and
//!   `settle` must withdraw it, because nothing else will.
//!
//! - Carrick's EL1 syscall hook saves SPSR_EL1 on entry and reloads it before
//!   its served `eret`, which would overwrite the unmask. `absorb` therefore
//!   also publishes the kick to the vCPU's EL1 slot (`publish_owed_kick`),
//!   and the hook consults it after its last SPSR_EL1 write: before that point
//!   the syscall leaves through the host, after it the unmask survives.
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
    /// EL0 of a native thread EL1 runs on an idle-entry vCPU, owed to the
    /// EL1 scheduler's IRQ boundary (`run_idle_entry`).
    IdleEntryEl0 = 4,
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
        // Every owed kick is visible to the EL1 hook's pending-host-work
        // check, whoever issued it: the served path forwards on it, or finds
        // its SPSR_EL1 already final and keeps the unmask below.
        vcpu.publish_owed_kick()?;
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

/// Run an idle-entry vCPU (no host task loaded, see
/// `Aarch64EngineCore::run_idle_entry_on_vcpu`) until an exit its executor
/// must take.
pub fn run_idle_entry<C: Aarch64Vcpu + ?Sized>(
    vcpu: &mut C,
) -> Result<crate::vmm::Aarch64Exit, TrapError> {
    use crate::vmm::Aarch64Exit;
    loop {
        match vcpu.run()? {
            // A kick at an EL1 instruction outside the image (the vector
            // page) surfaces here. The hook may already hold a thread EL1
            // switched in, so it is never abandoned: re-enter, and the hook
            // leaves through the host on the kick's pending host work.
            Aarch64Exit::Kicked if vcpu_at_el1(vcpu) => continue,
            // At EL0: EL1 switched a native-owned record in and runs it here.
            // No host task is loaded to take the kick (#890), so it is owed
            // to the EL1 scheduler's EL0 IRQ boundary instead.
            Aarch64Exit::Kicked if owe_idle_el0_kick(vcpu)? => continue,
            exit => return Ok(exit),
        }
    }
}

/// A kick cancelled an idle-entry vCPU while EL1 ran a native thread at EL0.
/// Re-enter with the kick owed to the scheduler's EL0 IRQ boundary: the
/// native owner settles the record there (`Sched::finish_interrupt` ->
/// `host_work_boundary` for host work, the preemption decision for a
/// reschedule) and the vCPU resumes the thread or leaves through the idle
/// exit with the record handed back. False when the kick was EL1's own
/// requested boundary or this backend cannot owe kicks to the guest
/// scheduler; the exit then surfaces as before.
///
/// What the kicker published decides what is owed:
/// - host work (`el1_zone::kick_slot`): the kick SGI is made pending; EL1
///   takes it as host work;
/// - only an owed reschedule (`el1_zone::resched_slot`): the backend's run
///   loop raises the reschedule SGI before the vCPU runs on, and it is not
///   turned into host work;
/// - neither (a bare hardware kick, such as one that predates its kicker's
///   host-work publication, or any future raw kicker): the kick is published
///   as owed host work and the kick SGI made pending, exactly as an
///   absorbed EL1 kick is ([`OwedKick::absorb`]). A raw kick therefore always
///   reaches the host; it is never swallowed.
///
/// Either SGI is taken at the first EL0 instruction once `I` is clear. The
/// guest never observes `I` (`carrick_hal::el0_visible_pstate`) and EL1's
/// served returns to EL0 clear it anyway, so it is not restored.
fn owe_idle_el0_kick<C: Aarch64Vcpu + ?Sized>(vcpu: &mut C) -> Result<bool, TrapError> {
    // EL1's own `hvc` kick at an EL0 boundary decodes to `Kicked` too. That
    // is a boundary EL1 asked for: re-entering it would loop, so only a raw
    // cross-thread cancellation is owed.
    if !vcpu.kicked_by_cancellation() || !vcpu.owes_el0_kicks_to_guest_scheduler() {
        return Ok(false);
    }
    let pstate = vcpu.get_reg(Reg::Pstate)?;
    if !carrick_hal::aarch64::ExecLevel::from_pstate(pstate).is_guest() {
        return Ok(false);
    }
    carrick_observability::probes::kick_rearm_irq(
        vcpu.get_reg(Reg::Pc).unwrap_or(0),
        AbsorbedKickSite::IdleEntryEl0 as u32,
        pstate,
        vcpu.get_reg(Reg::ElrEl1).unwrap_or(u64::MAX),
    );
    let host_work = vcpu.host_work_pending()?;
    if host_work || !vcpu.resched_pending()? {
        if !host_work {
            vcpu.publish_owed_kick()?;
        }
        vcpu.set_pending_irq(true)?;
    }
    if pstate & PSTATE_I != 0 {
        vcpu.set_reg(Reg::Pstate, pstate & !PSTATE_I)?;
    }
    Ok(true)
}

fn vcpu_at_el1<C: Aarch64Vcpu + ?Sized>(vcpu: &C) -> bool {
    vcpu.get_reg(Reg::Pstate)
        .is_ok_and(|pstate| !carrick_hal::aarch64::ExecLevel::from_pstate(pstate).is_guest())
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
        /// Owed kicks published to Carrick's EL1 code (the slot's
        /// pending-host-work flag the EL1 syscall hook consults).
        published_owed_kicks: u32,
        /// The in-kernel GIC: the pending kick is an SGI that survives run
        /// returns (qualified live) instead of a line HVF clears on each one.
        gic_semantics: bool,
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
                published_owed_kicks: 0,
                gic_semantics: false,
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

        fn publish_owed_kick(&mut self) -> Result<(), TrapError> {
            self.published_owed_kicks += 1;
            Ok(())
        }

        fn run(&mut self) -> Result<Aarch64Exit, TrapError> {
            let exit = self.run_until_exit();
            // Hypervisor.framework without a GIC: every run return clears
            // pending IRQs. The GIC's redistributor keeps them.
            if !self.gic_semantics {
                self.pending_irq = false;
            }
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
                    // The backend's `hvc #4` decode withdraws the kick in
                    // both models.
                    self.pending_irq = false;
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
                if !self.gic_semantics {
                    self.pending_irq = false;
                }
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

    /// Carrick's EL1 syscall hook reloads SPSR_EL1 from its entry snapshot
    /// before a served `eret`, so the unmask alone cannot carry a kick absorbed
    /// in the hook. Every absorbed kick must also be published to the vCPU's
    /// EL1 slot, which the hook consults after that reload (the hook's own
    /// VM-free binding, `carrick_mem`'s `el1_hook_kick`, proves the other
    /// half against the emitted bytes).
    #[test]
    fn absorbed_kick_is_published_to_the_el1_hook() {
        let mut vcpu = ModelVcpu::at_vector_resume(0);
        let mut owed = OwedKick::default();
        for absorbed in 1..=3 {
            owed.absorb(&mut vcpu, vector_resume_pc(), AbsorbedKickSite::El1Vector)
                .expect("absorb");
            assert_eq!(vcpu.published_owed_kicks, absorbed);
        }
    }

    /// With the in-kernel GIC the kick is a redistributor-pending SGI that
    /// survives every run return, so `rearm` is an idempotent write. The owed
    /// kick must still surface at the EL0 boundary with the original PSTATE,
    /// and nothing may stay pending once any exit has surfaced: a stale SGI
    /// would later be taken as a kick nobody issued.
    #[test]
    fn gic_pending_kick_survives_run_returns_and_is_withdrawn_when_served() {
        for internal_exits in [0_u32, 8] {
            let mut vcpu = ModelVcpu::at_vector_resume(32);
            vcpu.gic_semantics = true;
            vcpu.el1_exits_before_eret = internal_exits;
            assert_eq!(
                next_surfaced(&mut vcpu),
                Surfaced::Kick {
                    pc: GUEST_PC,
                    pstate: EL0_DAIF_MASKED,
                }
            );
            assert_eq!(vcpu.el0_steps, 0);
            assert!(!vcpu.pending_irq, "a surfaced kick left the SGI pending");
        }
        // An unrelated exit surfaces first: `settle` withdraws the SGI.
        let mut vcpu = ModelVcpu::at_vector_resume(0);
        vcpu.gic_semantics = true;
        let mut owed = OwedKick::default();
        owed.absorb(&mut vcpu, vector_resume_pc(), AbsorbedKickSite::El1Vector)
            .expect("absorb");
        assert!(vcpu.pending_irq);
        owed.settle(&mut vcpu).expect("settle");
        assert!(!vcpu.pending_irq, "settle left the SGI pending");
        assert_eq!(vcpu.spsr_el1, EL0_DAIF_MASKED);
    }

    /// Contract `kernel.vcpu.kick-el0-boundary`, idle-entry half (#890).
    ///
    /// An executor with no host task waits in the EL1 scheduler (the idle
    /// entry). EL1 may switch a native-owned record in and run it at EL0 on
    /// that vCPU. A kick that cancels the vCPU there is not an exit the
    /// executor can take: no host task is loaded to receive it. It must reach
    /// the EL1 scheduler's EL0 IRQ boundary, where the native owner settles
    /// the record (`Sched::finish_interrupt` -> `host_work_boundary` for host
    /// work, the preemption decision for a reschedule), and the vCPU then
    /// leaves through the idle exit with the record handed back.
    ///
    /// `IdleModel` models the Hypervisor.framework + in-kernel GIC facts this
    /// depends on: a pending SGI is taken at EL0 only with PSTATE.I clear and
    /// survives run returns; the HVF run loop arms the reschedule SGI owed by
    /// a host placement (`ZoneTables::take_resched`) and unmasks EL0 IRQs
    /// before it runs the vCPU. The EL1 side of the boundary is the
    /// scheduler's own VM-free suite (`carrick-el1-linux` `sched::tests`).
    mod idle_entry {
        use super::*;

        /// The idle entry's EL1h, DAIF-masked start state.
        const EL1H: u64 = 0x3c5;
        /// A native thread EL1 switched in: EL0t with IRQs unmasked, as every
        /// EL1-served return to EL0 leaves it under the GIC.
        const EL0_UNMASKED: u64 = 0x340;
        const NATIVE_PC: u64 = 0x0029_e564;

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum Settled {
            /// The native owner settled the record at the IRQ boundary for
            /// host work and the vCPU left through the idle exit.
            HostWorkBoundary,
            /// The reschedule preempted the record into its run queue and the
            /// vCPU left for the executor.
            Preempted,
        }

        struct IdleModel {
            pc: u64,
            pstate: u64,
            /// The EL0 PSTATE the switched-in native thread runs with.
            native_pstate: u64,
            /// EL1 switched the native record in on the first run.
            switched_in: bool,
            /// The slot's pending-host-work doorbell (`kick_slot`).
            host_work: bool,
            /// A host placement owes the slot a reschedule SGI.
            resched_owed: bool,
            kick_sgi: bool,
            resched_sgi: bool,
            kick_sgis_armed: u32,
            settled: Option<Settled>,
            /// EL0 ran on with nothing pending: the kick was lost.
            lost_kick: bool,
            /// The first `Kicked` is EL1's own `hvc` boundary request rather
            /// than a cross-thread cancellation.
            el1_requested: bool,
            /// The last exit was a cross-thread cancellation.
            cancelled: bool,
            /// The backend delivers owed kicks as interrupts taken at EL0
            /// (HVF with its in-kernel GIC); `false` models the hatch.
            guest_scheduler_irqs: bool,
            /// Owed kicks published to the slot's host-work doorbell.
            published_owed_kicks: u32,
        }

        impl IdleModel {
            fn new(native_pstate: u64, host_work: bool, resched_owed: bool) -> Self {
                Self {
                    pc: 0,
                    pstate: EL1H,
                    native_pstate,
                    switched_in: false,
                    host_work,
                    resched_owed,
                    kick_sgi: false,
                    resched_sgi: false,
                    kick_sgis_armed: 0,
                    settled: None,
                    lost_kick: false,
                    el1_requested: false,
                    cancelled: false,
                    guest_scheduler_irqs: true,
                    published_owed_kicks: 0,
                }
            }
        }

        impl Aarch64Vcpu for IdleModel {
            fn host_work_pending(&self) -> Result<bool, TrapError> {
                Ok(self.host_work)
            }
            fn kicked_by_cancellation(&self) -> bool {
                self.cancelled
            }
            fn resched_pending(&self) -> Result<bool, TrapError> {
                Ok(self.resched_owed)
            }
            fn owes_el0_kicks_to_guest_scheduler(&self) -> bool {
                self.guest_scheduler_irqs
            }
            fn publish_owed_kick(&mut self) -> Result<(), TrapError> {
                self.published_owed_kicks += 1;
                self.host_work = true;
                Ok(())
            }
            fn get_reg(&self, r: Reg) -> Result<u64, TrapError> {
                Ok(match r {
                    Reg::Pc => self.pc,
                    Reg::Pstate => self.pstate,
                    _ => 0,
                })
            }
            fn set_reg(&mut self, r: Reg, v: u64) -> Result<(), TrapError> {
                match r {
                    Reg::Pc => self.pc = v,
                    Reg::Pstate => self.pstate = v,
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
                if pending {
                    self.kick_sgis_armed += 1;
                }
                self.kick_sgi = pending;
                Ok(())
            }
            fn injects_kick_irq(&self) -> bool {
                true
            }
            fn kick(&self) -> Result<(), TrapError> {
                Ok(())
            }
            fn run(&mut self) -> Result<Aarch64Exit, TrapError> {
                self.cancelled = false;
                if !self.switched_in {
                    // EL1's idle loop switches the native record in and
                    // erets to it; the cross-thread kick cancels the vCPU at
                    // its first EL0 instruction.
                    self.switched_in = true;
                    self.pstate = self.native_pstate;
                    self.pc = NATIVE_PC;
                    self.cancelled = !self.el1_requested;
                    return Ok(Aarch64Exit::Kicked);
                }
                // The HVF run loop's pre-run reschedule check.
                if std::mem::take(&mut self.resched_owed) {
                    self.resched_sgi = true;
                    self.pstate &= !PSTATE_I;
                }
                let at_el0 = carrick_hal::aarch64::ExecLevel::from_pstate(self.pstate).is_guest();
                if at_el0 && self.pstate & PSTATE_I == 0 && (self.kick_sgi || self.resched_sgi) {
                    // Taken at EL0: the EL0 IRQ hook enters the scheduler.
                    // A kick SGI is host work (`Sched::take_irqs`).
                    if std::mem::take(&mut self.kick_sgi) {
                        self.host_work = true;
                    }
                    let resched = std::mem::take(&mut self.resched_sgi);
                    self.settled = Some(if self.host_work {
                        Settled::HostWorkBoundary
                    } else {
                        assert!(resched);
                        Settled::Preempted
                    });
                    // `hvc #5`: the idle exit, no thread loaded.
                    self.pstate = EL1H;
                    return Ok(Aarch64Exit::Halt);
                }
                self.lost_kick = true;
                Ok(Aarch64Exit::Halt)
            }
        }

        /// A host kick (`kick_slot`: host work published, then
        /// `hv_vcpus_exit`) landing on the native thread at EL0 is settled
        /// at the native owner's IRQ boundary, never surfaced as an exit the
        /// threadless executor would have to fail on. Both EL0 IRQ states.
        #[test]
        fn host_kick_at_el0_settles_at_the_native_irq_boundary() {
            for native_pstate in [EL0_UNMASKED, EL0_DAIF_MASKED] {
                let mut vcpu = IdleModel::new(native_pstate, true, false);
                let exit = run_idle_entry(&mut vcpu).expect("idle entry");
                assert!(
                    matches!(exit, Aarch64Exit::Halt),
                    "pstate {native_pstate:#x}: an EL0 kick under the idle entry surfaced \
                     as {exit:?} to an executor with no host task loaded"
                );
                assert_eq!(vcpu.settled, Some(Settled::HostWorkBoundary));
                assert!(!vcpu.lost_kick);
                assert!(
                    !vcpu.kick_sgi,
                    "the kick SGI stayed pending after it was taken"
                );
            }
        }

        /// A reschedule kick (`resched_slot`: a host placement, no host
        /// work) reaches the scheduler's preemption decision through the
        /// reschedule SGI. It must not be turned into host work.
        #[test]
        fn resched_kick_at_el0_reaches_the_preemption_decision() {
            for native_pstate in [EL0_UNMASKED, EL0_DAIF_MASKED] {
                let mut vcpu = IdleModel::new(native_pstate, false, true);
                let exit = run_idle_entry(&mut vcpu).expect("idle entry");
                assert!(
                    matches!(exit, Aarch64Exit::Halt),
                    "pstate {native_pstate:#x}: a reschedule kick at EL0 surfaced as {exit:?}"
                );
                assert_eq!(vcpu.settled, Some(Settled::Preempted));
                assert_eq!(vcpu.kick_sgis_armed, 0, "a reschedule invented host work");
                assert_eq!(vcpu.published_owed_kicks, 0);
                assert!(!vcpu.host_work);
                assert!(!vcpu.lost_kick);
            }
        }

        /// A bare cancellation that published neither host work nor a
        /// reschedule (the pool's shutdown kick, or any future raw kicker)
        /// must not be swallowed: re-entering with nothing pending leaves the
        /// native thread computing, or EL1 in WFI, and the kicker waits
        /// forever. It is owed as host work and reaches the host.
        #[test]
        fn bare_kick_at_el0_is_owed_as_host_work_not_swallowed() {
            for native_pstate in [EL0_UNMASKED, EL0_DAIF_MASKED] {
                let mut vcpu = IdleModel::new(native_pstate, false, false);
                let exit = run_idle_entry(&mut vcpu).expect("idle entry");
                assert!(
                    !vcpu.lost_kick,
                    "pstate {native_pstate:#x}: a bare kick was swallowed and EL0 ran on"
                );
                assert!(matches!(exit, Aarch64Exit::Halt), "{exit:?}");
                assert_eq!(vcpu.settled, Some(Settled::HostWorkBoundary));
                assert_eq!(vcpu.published_owed_kicks, 1);
            }
        }

        /// A backend that cannot owe kicks to the guest scheduler (HVF's
        /// `CARRICK_HVF_GIC=0` hatch) keeps surfacing the kick.
        #[test]
        fn kick_without_guest_scheduler_irqs_still_surfaces() {
            let mut vcpu = IdleModel::new(EL0_UNMASKED, true, false);
            vcpu.guest_scheduler_irqs = false;
            let exit = run_idle_entry(&mut vcpu).expect("idle entry");
            assert!(matches!(exit, Aarch64Exit::Kicked));
            assert_eq!(vcpu.kick_sgis_armed, 0);
        }

        /// EL1's own `hvc` kick at an EL0 boundary also decodes to `Kicked`.
        /// It is a boundary EL1 asked for, not a cancellation: it surfaces
        /// (re-entering it would loop on the same pending host work).
        #[test]
        fn el1_requested_el0_boundary_still_surfaces() {
            let mut vcpu = IdleModel::new(EL0_UNMASKED, true, false);
            vcpu.el1_requested = true;
            let exit = run_idle_entry(&mut vcpu).expect("idle entry");
            assert!(matches!(exit, Aarch64Exit::Kicked));
            assert_eq!(vcpu.kick_sgis_armed, 0);
            assert_eq!(vcpu.settled, None);
        }
    }
}
