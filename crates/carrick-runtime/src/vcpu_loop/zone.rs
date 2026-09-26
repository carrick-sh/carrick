//! The runtime's side of the in-guest scheduler zone (EL1 plan 1b).
//!
//! Guest EL1 hands a vCPU from one thread of a process to another through a
//! private futex without a host exit (`carrick-el1` `sched.rs`), on queues the
//! host shares (`carrick_sched_core`, host venue `carrick_kernel::el1_zone`).
//! The executor that holds a vCPU slot is the only host party that touches
//! what EL1 did on that slot, and it does so only while the vCPU is stopped:
//!
//! - [`ProductionHvpatchLoopJob::reconcile_zone_exit`], at every exit before
//!   the exit is used: threads EL1 woke onto the slot and the thread EL1
//!   switched in go back to the host (their zone waits become ready), and if
//!   the thread this executor loaded is parked in the zone, it settles into a
//!   zone wait. The exit itself then belonged to another thread: it is
//!   abandoned (a forwarded syscall is rewound to its `svc`).
//! - [`ProductionHvpatchLoopJob::zone_park`]: a wait EL1 forwarded (or one it
//!   never serves: timed, `futex_waitv`) parks in the same queues, with the
//!   context in a record, so an in-guest waker can run it.
//! - [`ProductionHvpatchLoopJob::resume_zone`]: a zone-parked thread loaded
//!   from its record applies how its wait ended ([`Handback`]).

use super::binding::{HvpatchProductionPhase, ProductionHvpatchLoopJob};
use super::exec::ProductionHvpatchPollError;
use super::outcome::HvpatchLoopSuspension;
use super::*;
use carrick_el1_abi::{
    CurrentHandback, Handback, RecordRef, SlotId, ThreadCtx, ThreadIdentity, ZoneTables,
};
use carrick_hal::threaded::GuestCpuState;
use carrick_kernel::el1_zone::HostLockWait;

thread_local! {
    /// The zone thread this executor thread took off its vCPU at the last
    /// exit (EL1 plan 1d): it claims that thread itself next, rather than
    /// publish it to a run queue for any executor.
    static PENDING_ADOPTION: std::cell::Cell<Option<RecordRef>> =
        const { std::cell::Cell::new(None) };
}

/// The zone thread this executor thread owes a claim, if any.
pub(crate) fn take_pending_adoption() -> Option<RecordRef> {
    PENDING_ADOPTION.with(std::cell::Cell::take)
}

fn owe_adoption(record: RecordRef) {
    if let Some(previous) = PENDING_ADOPTION.with(|cell| cell.replace(Some(record))) {
        // One exit takes at most one thread off the vCPU, and the executor
        // claims it before its next run: a second is a protocol violation.
        carrick_fatal::carrick_fatal!(
            "vcpu_loop::el1_zone",
            "executor owed two zone adoptions: {previous:?} then {record:?}"
        );
    }
}

/// How the vCPU left the guest, for capturing a thread's EL0 state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ZoneExit {
    /// A syscall forwarded through the mailbox. `completed`: the syscall is
    /// done (served in-guest with pending host work, or a host park), so the
    /// thread resumes after the `svc`; otherwise it is rewound to re-issue it.
    Syscall { completed: bool },
    /// Stopped at an EL0 instruction (a kick, a direct EL0 abort, a halt) or
    /// at an EL0 fault the EL1 vector forwarded (resume at the faulting
    /// instruction).
    El0,
}

/// The EL0 context a thread resumes with, from a live-vCPU capture.
pub(super) fn zone_ctx_from_state(
    state: &GuestCpuState,
    exit: ZoneExit,
) -> Result<ThreadCtx, RuntimeError> {
    let GuestCpuState::Aarch64V1(s) = state else {
        return Err(RuntimeError::Configuration(
            "EL1 zone capture on a non-AArch64 task".to_owned(),
        ));
    };
    let mut ctx = ThreadCtx::ZERO;
    ctx.x = s.gprs;
    ctx.sp_el0 = s.sp_el0;
    ctx.tpidr_el0 = s.tpidr_el0;
    ctx.tpidrro_el0 = s.tpidrro_el0;
    ctx.contextidr_el1 = s.contextidr_el1;
    ctx.v = s.vregs;
    ctx.fpsr = u64::from(s.fpsr);
    ctx.fpcr = u64::from(s.fpcr);
    apply_zone_exit(
        &mut ctx,
        s.syscall_continuation.as_ref(),
        (s.trap_pc, s.trap_pstate),
        (s.elr_el1, s.spsr_el1),
        exit,
    )?;
    Ok(ctx)
}

/// The resume point of a thread taken off a vCPU at `exit`: after (or at,
/// to re-issue it) a forwarded syscall, from the mailbox continuation; at
/// the EL0 instruction the vCPU stopped at (`trap`), or the EL0 state the
/// EL1 vector trapped from (`vector`).
fn apply_zone_exit(
    ctx: &mut ThreadCtx,
    continuation: Option<&carrick_hal::threaded::Aarch64SyscallContinuationV1>,
    trap: (u64, u64),
    vector: (u64, u64),
    exit: ZoneExit,
) -> Result<(), RuntimeError> {
    match exit {
        ZoneExit::Syscall { completed } => {
            // The mailbox capture used x16/x17 as scratch after saving them,
            // and holds the EL0 return state.
            let continuation = continuation.ok_or_else(|| {
                RuntimeError::Configuration(
                    "EL1 zone capture at a syscall exit without its mailbox request".to_owned(),
                )
            })?;
            ctx.x[16] = continuation.resume_x16;
            ctx.x[17] = continuation.resume_x17;
            ctx.x[29] = continuation.fp;
            ctx.x[30] = continuation.lr;
            ctx.sp_el0 = continuation.sp;
            ctx.pstate = continuation.spsr;
            ctx.pc = if completed {
                continuation.resume_pc
            } else {
                continuation.resume_pc.wrapping_sub(4)
            };
        }
        ZoneExit::El0 => {
            // EL0t: the vCPU stopped in guest code. Otherwise it is in the EL1
            // vector, whose ELR/SPSR hold the EL0 state it trapped from.
            if trap.1 & 0xf == 0 {
                (ctx.pc, ctx.pstate) = trap;
            } else {
                (ctx.pc, ctx.pstate) = vector;
            }
        }
    }
    Ok(())
}

/// Hand each host-owned zone thread (a host wake no vCPU could take) back
/// to its host continuation.
pub(super) fn publish_zone_handbacks(_kernel: &Kernel, records: &[RecordRef]) {
    carrick_kernel::el1_zone::hand_back(records);
}

/// The zone and this process's key, when the carrier serves its private
/// futexes in the zone.
pub(super) fn zone_for(zone_mm: Option<u64>) -> Option<(&'static ZoneTables, u64)> {
    Some((carrick_kernel::el1_zone::zone()?, zone_mm?))
}

/// The zone and the vCPU slot `engine` runs on, when the carrier schedules
/// threads in the guest.
pub(super) fn zone_slot<E: ThreadedEngine>(engine: &E) -> Option<(&'static ZoneTables, SlotId)> {
    Some((
        carrick_kernel::el1_zone::zone()?,
        engine.mailbox_slot().and_then(SlotId::from_index)?,
    ))
}

/// How long until the guest virtual counter reaches `deadline` (guest
/// `CNTVCT_EL0` is the host's `mach_absolute_time` tick count).
fn until_deadline(deadline: u64) -> std::time::Duration {
    let ticks = deadline.saturating_sub(carrick_host::clock::monotonic_ticks());
    let scale = carrick_host::clock::tick_scale()
        .unwrap_or(carrick_host::clock::TickScale { numer: 1, denom: 1 });
    let ns = u128::from(ticks) * u128::from(scale.numer) / u128::from(scale.denom.max(1));
    std::time::Duration::from_nanos(u64::try_from(ns).unwrap_or(u64::MAX))
}

impl<E: ThreadedEngine + 'static> ProductionHvpatchLoopJob<E>
where
    E::SiblingSpec: 'static,
{
    /// The zone key of the task this job runs (its address-space id).
    pub(super) fn refresh_zone_key(&mut self, control: &executor::HvpatchQuantumControl<'_, '_>) {
        self.state.zone_mm = carrick_kernel::el1_zone::zone()
            .and(control.binding)
            .map(|binding| binding.identity().mm.raw());
    }

    /// Settle what EL1 did on this vCPU slot since the host last ran it,
    /// before anything uses the exit (the slot is already closed to other
    /// vCPUs). `None`: the thread this job runs is the one that exited;
    /// handle the exit. `Some`: that thread is parked in the zone (it waited
    /// in EL1 while the vCPU switched to another thread, or was preempted
    /// there) and has settled; the exit is abandoned.
    ///
    /// Threads still queued on the slot stay queued (EL1 plan 1d): EL1 runs
    /// them when this vCPU returns to the guest, or an idle vCPU steals them.
    /// A thread EL1 ran here that exited to the host is this executor's to
    /// claim next ([`take_pending_adoption`]), not a run queue's.
    pub(super) fn reconcile_zone_exit(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
        exit: ZoneExit,
    ) -> Result<Option<executor::ExecutorExit>, ProductionHvpatchPollError> {
        let Some((zone, slot)) = zone_slot(engine) else {
            return Ok(None);
        };
        zone.sweep_cancelled(slot);
        carrick_kernel::el1_zone::hand_back_wanted(slot);
        let s = zone.slot(slot);
        let (current, own) = (s.current(), s.host_record());
        let state = match (current, own) {
            (None, None) => return self.own_space_installed(zone, slot).map(|()| None),
            (Some(current), Some(own)) if current == own => {
                // EL1 switched this job's own thread back in: it is simply
                // running again, and its record is done.
                zone.release_current(slot, current);
                return self.own_space_installed(zone, slot).map(|()| None);
            }
            (Some(current), _) => {
                // Another thread is on the vCPU. Take it off with its live
                // state; this executor claims it next. This job's thread,
                // which EL1 parked, settles below.
                let served_with_work =
                    carrick_kernel::el1_delegation::take_served_with_work(slot.raw().into());
                carrick_kernel::el1_delegation::clear_pending_host_work(slot.raw().into());
                let state = engine.snapshot_guest_state_for_publication()?;
                let ctx = zone_ctx_from_state(
                    &state,
                    match exit {
                        ZoneExit::Syscall { .. } => ZoneExit::Syscall {
                            completed: served_with_work,
                        },
                        ZoneExit::El0 => ZoneExit::El0,
                    },
                )?;
                engine.discard_terminal_syscall_continuation()?;
                if served_with_work {
                    carrick_kernel::el1_inotify::deliver_owed_wakes();
                }
                // SAFETY: `current` is OnCpu on this slot and the vCPU is
                // stopped: this executor is its only owner until the
                // handback below.
                unsafe { *zone.record(current).ctx_mut() = ctx };
                let current_ref = zone.record_ref(current);
                match zone.handback_current(slot, current) {
                    CurrentHandback::HandedBack => {
                        zone.counters
                            .exit_adoptions
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        owe_adoption(current_ref);
                    }
                    CurrentHandback::Discard => zone.free_record(current),
                    CurrentHandback::Lost => {
                        return Err(RuntimeError::Configuration(format!(
                            "EL1 zone slot {slot:?} switched-in record {current:?} was not on the slot"
                        ))
                        .into());
                    }
                }
                state
            }
            (None, Some(_)) => {
                // The vCPU left EL1 with no thread on it (the idle exit)
                // with this job's thread parked or preempted: host work, or
                // a queued thread that needs this executor.
                carrick_kernel::el1_delegation::clear_pending_host_work(slot.raw().into());
                engine.snapshot_guest_state_for_publication()?
            }
        };
        let own = own.ok_or_else(|| {
            RuntimeError::Configuration(format!(
                "EL1 zone slot {slot:?} ran another thread but never parked the loaded one"
            ))
        })?;
        // EL1 may have switched the vCPU to another process's address space
        // (EL1 increment 2): the settled thread keeps its own roots. EL1
        // switches away only from a published space, whose two roots are
        // the lease's `TTBR0` value.
        let state = self.with_own_roots(zone, slot, control, state)?;
        // The thread settles into a host zone wait: its record stops being
        // this slot's home, and a deadline this slot's timer kept is the
        // host's to keep now.
        let affinity = self
            .state
            .kernel_thread
            .as_ref()
            .map_or(0, |thread| thread.affinity().words()[0]);
        let (seq, timeout) = match zone.unhome(slot, own, affinity) {
            Some((seq, deadline)) => (seq, Some(until_deadline(deadline))),
            None => (0, None),
        };
        let own = zone.record_ref(own);
        let request = SyscallRequest::new(98, carrick_observability::compat::SyscallArgs([0; 6]));
        let exit = self.settle_into_zone(control, state, own, seq, timeout, request)?;
        Ok(Some(exit))
    }

    /// The vCPU state `state` with this job's own translation roots, when the
    /// address space installed on the vCPU is not the job's.
    fn with_own_roots(
        &self,
        zone: &ZoneTables,
        slot: SlotId,
        control: &executor::HvpatchQuantumControl<'_, '_>,
        state: GuestCpuState,
    ) -> Result<GuestCpuState, ProductionHvpatchPollError> {
        let installed = zone.installed_space(slot);
        if self.state.zone_mm.is_none_or(|mm| mm == installed) {
            return Ok(state);
        }
        let GuestCpuState::Aarch64V1(cpu) = &state else {
            return Ok(state);
        };
        let ttbr0 = control
            .binding
            .and_then(|binding| binding.stage1_ttbr0())
            .ok_or_else(|| {
                RuntimeError::Configuration(format!(
                    "EL1 zone slot {slot:?} switched address spaces under a task with no stage-1 lease"
                ))
            })?;
        let mut cpu = (**cpu).clone();
        cpu.ttbr0 = ttbr0;
        cpu.ttbr1 = ttbr0;
        Ok(GuestCpuState::from_aarch64_v1(cpu))
    }

    /// This job's own thread is on the vCPU again: EL1 installed its address
    /// space before it ran it (EL1 increment 2), so the exit is this
    /// thread's to handle. Anything else would let the host resolve a fault
    /// or run a syscall against the wrong address space: fail loud.
    fn own_space_installed(
        &self,
        zone: &ZoneTables,
        slot: SlotId,
    ) -> Result<(), ProductionHvpatchPollError> {
        let installed = zone.installed_space(slot);
        match self.state.zone_mm {
            Some(mm) if mm != installed => Err(RuntimeError::Configuration(format!(
                "EL1 zone slot {slot:?} returned the loaded thread of address space {mm} \
                 with address space {installed} installed"
            ))
            .into()),
            _ => Ok(()),
        }
    }

    /// Whether the address space installed on this job's vCPU is its own:
    /// EL1 stopped mid-operation on the vCPU (a stage-1 COW fault) while it
    /// ran a thread it switched in from another process would have the
    /// fault resolved in this job's address space.
    pub(super) fn check_own_space_at_el1_fault(
        &self,
        engine: &E,
    ) -> Result<(), ProductionHvpatchPollError> {
        match zone_slot(engine) {
            Some((zone, slot)) => self.own_space_installed(zone, slot),
            None => Ok(()),
        }
    }

    /// This job's thread is parked in the zone on `record` (park `seq`,
    /// bounded by `timeout`): settle it into a zone wait whose save keeps its
    /// registers in the record.
    fn settle_into_zone(
        &mut self,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
        base: GuestCpuState,
        record: RecordRef,
        seq: u32,
        timeout: Option<std::time::Duration>,
        request: SyscallRequest,
    ) -> Result<executor::ExecutorExit, ProductionHvpatchPollError> {
        let context = self
            .kernel
            .dispatcher
            .capture_kernel_context(self.state.linux_tid)
            .map_err(|error| {
                RuntimeError::Configuration(format!("EL1 zone settle lost Kernel context: {error}"))
            })?;
        let lease = control.execution_lease_mut().map_err(RuntimeError::Trap)?;
        let capture = carrick_kernel::kernel::continuation::ContinuationCapture::from_lease(
            &context,
            lease,
            request,
            carrick_kernel::kernel::continuation::RestartClass::Never,
        )
        .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
        let continuation =
            carrick_kernel::kernel::continuation::BlockedContinuation::from_zone_park(
                capture,
                carrick_kernel::kernel::continuation::ZoneWait::new(record, seq),
                timeout,
            );
        let binding = control.binding.ok_or_else(|| {
            RuntimeError::Configuration("EL1 zone settle without a task binding".to_owned())
        })?;
        binding.set_zone_save(continuation::quantum::ZoneSave { base, record });
        self.state.service_kernel_context = Some(context);
        self.phase = HvpatchProductionPhase::ResumeZone;
        Ok(self.suspend(
            HvpatchLoopSuspension::BlockedContinuation,
            executor::ExecutorExit::BlockedContinuation {
                continuation: Box::new(continuation),
                vfork_activation: None,
            },
        ))
    }

    /// Park this job's thread in the zone for a futex wait the host serves
    /// (EL1 forwarded it, or never serves it), in the same queues EL1 uses.
    /// The word is re-checked under the bucket lock, which every waker takes.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn zone_park(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
        frame: carrick_hal::RawSyscall,
        uaddr: u64,
        value: u32,
        bitset: u32,
        timeout: Option<std::time::Duration>,
        index: u32,
    ) -> Result<executor::ExecutorExit, ProductionHvpatchPollError> {
        let Some((zone, mm)) = zone_for(self.state.zone_mm) else {
            return self.service_outcome(
                engine,
                control,
                frame,
                DispatchOutcome::Errno {
                    errno: crate::linux_abi::LINUX_EAGAIN,
                },
            );
        };
        let state = engine.snapshot_guest_state_for_publication()?;
        let ctx = zone_ctx_from_state(&state, ZoneExit::Syscall { completed: true })?;
        let request = self
            .state
            .syscall_completion
            .guest("zone park lost its prepared completion token")?
            .syscall()
            .request;
        let context = self.state.service_kernel_context.as_ref().ok_or_else(|| {
            RuntimeError::Configuration("zone park lost its Kernel context".to_owned())
        })?;
        let identity = ThreadIdentity {
            tid: carrick_el1_abi::El1TaskId::from_linux_tid(self.state.linux_tid.raw()).raw(),
            serial: context.thread().key().serial.raw(),
            mm,
            file_table: context.resources().files().id().raw(),
            generation: control
                .current_submission_key()
                .map(|(_, generation)| generation.raw())
                .unwrap_or(0),
            affinity: context.thread().affinity().words()[0],
        };
        let parked = {
            let Some(guard) = zone.lock(ZoneTables::bucket_of(mm, uaddr), &HostLockWait) else {
                return Err(RuntimeError::Configuration(
                    "zone park: host bucket lock gave up".to_owned(),
                )
                .into());
            };
            let word = engine
                .read_bytes(uaddr, 4)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .map(u32::from_ne_bytes);
            match word {
                None => Err(crate::linux_abi::LINUX_EFAULT),
                Some(word) if word != value => Err(crate::linux_abi::LINUX_EAGAIN),
                Some(_) => match zone.alloc_record(identity) {
                    Err(_) => Err(crate::linux_abi::LINUX_EAGAIN),
                    Ok(record) => {
                        // SAFETY: freshly allocated and not yet published.
                        unsafe { *zone.record(record).ctx_mut() = ctx };
                        let seq = zone.next_seq(record);
                        if zone
                            .enqueue(&guard, record, seq, mm, uaddr, bitset, index)
                            .is_err()
                        {
                            zone.free_record(record);
                            Err(crate::linux_abi::LINUX_EAGAIN)
                        } else {
                            zone.publish_park(record, seq);
                            Ok((record, seq))
                        }
                    }
                },
            }
        };
        let (record, seq) = match parked {
            Ok(parked) => parked,
            Err(errno) => {
                return self.service_outcome(
                    engine,
                    control,
                    frame,
                    DispatchOutcome::Errno { errno },
                );
            }
        };
        zone.counters
            .host_parks
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        engine.discard_terminal_syscall_continuation()?;
        self.state.retire_syscall()?;
        let record = zone.record_ref(record);
        self.settle_into_zone(control, state, record, seq, timeout, request)
    }

    /// A zone-parked thread was loaded from its record: apply how its wait
    /// ended, free the record, and deliver any signal at this EL0 boundary.
    pub(super) fn resume_zone(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> Result<executor::ExecutorExit, ProductionHvpatchPollError> {
        let context = self
            .kernel
            .dispatcher
            .capture_kernel_context(self.state.linux_tid)
            .map_err(|error| {
                RuntimeError::Configuration(format!("EL1 zone resume lost Kernel context: {error}"))
            })?;
        let lease = control.execution_lease_mut().map_err(RuntimeError::Trap)?;
        let continuation = lease.blocked_continuation().ok_or_else(|| {
            RuntimeError::Configuration("EL1 zone resume lost its zone wait".to_owned())
        })?;
        let record = continuation
            .zone_wait()
            .map(|wait| wait.record)
            .ok_or_else(|| {
                RuntimeError::Configuration("EL1 zone resume on a non-zone wait".to_owned())
            })?;
        let event = continuation
            .ready_event()
            .map_err(|error| RuntimeError::Configuration(format!("zone wait event: {error:?}")))?;
        let fresh = context
            .task_binding()
            .capture(self.state.linux_tid)
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
        let mut result =
            carrick_kernel::kernel::continuation::resume_continuation(lease, event, &fresh)
                .map_err(|error| {
                    RuntimeError::Configuration(format!("resume zone wait: {error:?}"))
                })?;
        let reserved = result.take_reserved_signal();
        let zone = carrick_kernel::el1_zone::zone().ok_or_else(|| {
            RuntimeError::Configuration("EL1 zone resume without zone tables".to_owned())
        })?;
        let rec = zone.live(record).ok_or_else(|| {
            RuntimeError::Configuration(format!("EL1 zone resume: record {record:?} is gone"))
        })?;
        let x0: Option<i64> = match rec.handback() {
            Some(Handback::Woken) => Some(rec.result() as i64),
            Some(Handback::Resumed) => None,
            Some(Handback::Timeout) => Some(crate::linux_abi::LINUX_ETIMEDOUT.guest_retval()),
            Some(Handback::Signal) => Some(crate::linux_abi::LINUX_EINTR.guest_retval()),
            // The host needed it runnable (an exit or exec drain, or a
            // control action): its wait ends as a spurious wakeup.
            Some(Handback::Control) => Some(0),
            // A service record names a thread the host made runnable; it is
            // loaded from its own residency, never resumed from a zone wait.
            Some(Handback::Cancelled | Handback::Service) | None => {
                return Err(RuntimeError::Configuration(format!(
                    "EL1 zone resume of record {record:?} with handback {:?}",
                    rec.handback()
                ))
                .into());
            }
        };
        if let Some(value) = x0 {
            engine
                .set_reg(carrick_hal::Reg::X(0), value as u64)
                .map_err(|error| {
                    RuntimeError::Configuration(format!("EL1 zone resume x0: {error}"))
                })?;
        }
        zone.free_record(record.id);
        self.state.service_kernel_context = Some(context.retain_exact());
        let pc = engine.current_pc()?;
        if let Some(outcome) = service_signals_threaded(
            &self.kernel,
            &context,
            engine,
            self.state.this_tid,
            self.state.fatal_image_generation,
            None,
            Some(pc),
            None,
            reserved,
            self.traps,
        )? {
            return Ok(self.enter_terminal_with_outcome(engine, outcome));
        }
        Ok(executor::ExecutorExit::Syscall)
    }
}
