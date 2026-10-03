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
    CurrentHandback, CurrentRelease, Handback, RecordRef, SlotId, ThreadCtx, ThreadIdentity,
    ZoneTables,
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

/// `state` with argument 0 restored to `x0`, so re-issuing its syscall runs
/// the ORIGINAL call (EL1 overwrote x0 with the result it served).
pub(super) fn with_original_arg0(state: GuestCpuState, x0: u64) -> GuestCpuState {
    let GuestCpuState::Aarch64V1(cpu) = &state else {
        return state;
    };
    let mut cpu = (**cpu).clone();
    cpu.gprs[0] = x0;
    GuestCpuState::from_aarch64_v1(cpu)
}

/// How a thread taken off its vCPU resumes after EL1 served its syscall:
/// `(state, completed)`. A call whose host commit is owed re-issues with its
/// original arguments; any other served call is complete; an unserved call
/// re-issues as it is.
pub(super) fn settle_served_state(
    state: GuestCpuState,
    boundary: Option<carrick_el1_abi::ServedBoundary>,
) -> (GuestCpuState, bool) {
    match boundary {
        None => (state, false),
        Some(carrick_el1_abi::ServedBoundary::Completed) => (state, true),
        Some(carrick_el1_abi::ServedBoundary::ReplayOriginal { x0 }) => {
            (with_original_arg0(state, x0), false)
        }
    }
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
        // Every exit: nothing serves this slot's timer until the vCPU
        // returns, so another thread's timed park on it goes to the host.
        carrick_kernel::el1_zone::hand_back_foreign_timer(slot);
        let s = zone.slot(slot);
        let (mut current, own) = (s.current(), s.host_record());
        let mut requeued = false;
        if let (Some(switched), Some(own)) = (current, own)
            && switched == own
        {
            // EL1 switched this job's own thread back in. Nothing stays
            // switched in on the slot past this boundary.
            match zone.release_current(slot, own, &HostLockWait) {
                // It is simply running again: its record is retired.
                CurrentRelease::Released => {
                    return self.own_space_installed(zone, slot).map(|()| None);
                }
                // It was switched in at the SVC of its pending object
                // operation, which never re-executed (EL1 left with host
                // work after the switch, or a kick stopped it at EL0): its
                // record is back at the head of the run queue, and the
                // thread settles into its zone wait on it below, exactly as
                // a thread EL1 parked or preempted. Its next load resumes
                // the operation; this exit (no call of the thread's) is
                // abandoned.
                CurrentRelease::Requeued => {
                    crate::probes::el1_zone_requeue_operation(
                        u32::from(slot.raw()),
                        u32::from(matches!(exit, ZoneExit::Syscall { .. })),
                        own.raw().into(),
                    );
                    current = None;
                    requeued = true;
                }
            }
        }
        let state = match (current, own) {
            (None, None) => return self.own_space_installed(zone, slot).map(|()| None),
            (Some(current), _) => {
                // Another thread is on the vCPU. Take it off with its live
                // state; this executor claims it next. This job's thread,
                // which EL1 parked, settles below.
                // Delivers what the served call owed (inotify, IPC).
                let boundary = carrick_kernel::el1_delegation::settle_el1_boundary_for(
                    slot.raw().into(),
                    &self.kernel.dispatcher,
                );
                let state = engine.snapshot_guest_state_for_publication()?;
                let (ctx_state, completed) = settle_served_state(state.clone(), boundary);
                let ctx = zone_ctx_from_state(
                    &ctx_state,
                    match exit {
                        ZoneExit::Syscall { .. } => ZoneExit::Syscall { completed },
                        ZoneExit::El0 => ZoneExit::El0,
                    },
                )?;
                engine.discard_terminal_syscall_continuation()?;
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
                    CurrentHandback::Retired => {}
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
                let boundary = carrick_kernel::el1_delegation::settle_el1_boundary_for(
                    slot.raw().into(),
                    &self.kernel.dispatcher,
                );
                let state = engine.snapshot_guest_state_for_publication()?;
                if requeued && matches!(exit, ZoneExit::Syscall { .. }) {
                    // EL1 left through the syscall mailbox with the requeued
                    // record's unexecuted SVC as its frame: no call of this
                    // thread's to complete. The record keeps its context.
                    engine.discard_terminal_syscall_continuation()?;
                }
                // The thread re-issues its syscall when it resumes. A call EL1
                // served whose host commit is owed must re-issue with its
                // ORIGINAL x0, not the result EL1 wrote there (a re-issued
                // `mprotect(0, len)` answered ENOMEM).
                match settle_served_state(state.clone(), boundary) {
                    (replayed, false) => replayed,
                    (_, true) => state,
                }
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
            lifecycle_page: 0,
            control_slot: 0,
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
        if rec.has_object_operation() {
            // An IPC operation parked with this thread: the thread is at its
            // SVC with the original registers; the operation (not a wake
            // value) decides the result.
            let handback = rec.handback();
            // SAFETY: the host owns this handed-back record, all of its
            // registrations are unlinked, and this executor loaded its exact
            // task and address space.
            let taken = unsafe { rec.take_object_operation() };
            zone.free_record(record.id);
            self.state.service_kernel_context = Some(context.retain_exact());
            if taken
                .as_ref()
                .is_some_and(|token| token.metadata_generation().is_some())
            {
                // Metadata readiness resumes the saved control SVC with every
                // original register intact. A wake is not its return value.
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
                return Ok(executor::ExecutorExit::Syscall);
            }
            let token = taken.and_then(host_ipc::from_sched_token).ok_or_else(|| {
                RuntimeError::Configuration(
                    "EL1 zone resume: IPC operation token is not ours".to_owned(),
                )
            })?;
            if let Some(exit) =
                self.resume_ipc_operation(engine, control, handback, token, reserved.as_ref())?
            {
                return Ok(exit);
            }
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
            return Ok(executor::ExecutorExit::Syscall);
        }
        let x0: Option<i64> = match rec.handback() {
            Some(Handback::Woken) => Some(rec.result() as i64),
            Some(Handback::Resumed) => None,
            Some(Handback::Timeout) => Some(crate::linux_abi::LINUX_ETIMEDOUT.guest_retval()),
            Some(Handback::Signal) => Some(crate::linux_abi::LINUX_EINTR.guest_retval()),
            // The host needed it runnable (an exit or exec drain, or a
            // control action): its wait ends as a spurious wakeup.
            Some(Handback::Control | Handback::GroupStop) => Some(0),
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

// ------------------------------------------------------------------ IPC

use carrick_el1_abi::ipc::pipe::WaitFor;
use carrick_el1_abi::ipc::{IpcMmKey, IpcObjectHandle, IpcOpToken};
use carrick_kernel::kernel::continuation::ipc as host_ipc;
use host_ipc::ObjectWaitSnapshot;

/// What the host does with an EL1 handback frame, decided at the syscall
/// boundary (the frame's `x0`/`x8` already restored to the original call).
pub(super) enum IpcHandbackRoute {
    /// The call is complete with this outcome (SIGPIPE already marked).
    Complete(DispatchOutcome),
    /// The call took no effect: dispatch the original call on the host path.
    /// A timed epoll wait's timeout argument (`x3`) was already rewritten
    /// to what is left of its deadline ([`restart_with_remaining`]).
    Restart,
    /// The call must keep waiting: park the thread with its owned operation.
    Park(IpcPark),
}

/// An owned operation the host parks on an object wait queue.
#[derive(Debug)]
pub(crate) struct IpcPark {
    token: IpcOpToken,
    object: IpcObjectHandle,
    lane: WaitFor,
    snapshot: ObjectWaitSnapshot,
}

fn lane_index(lane: WaitFor) -> usize {
    match lane {
        WaitFor::Readable => 0,
        WaitFor::Writable => 1,
    }
}

fn ipc_error(what: &str, error: impl std::fmt::Debug) -> RuntimeError {
    RuntimeError::Configuration(format!("IPC {what}: {error:?}"))
}

/// Map a completed host IPC outcome onto the syscall result, marking
/// SIGPIPE for the calling thread when owed (unless ignored).
fn ipc_complete(
    dispatcher: &carrick_kernel::dispatch::SyscallDispatcher,
    context: &carrick_kernel::kernel::KernelContext,
    tid: ThreadId,
    result: i64,
    sigpipe: bool,
) -> DispatchOutcome {
    if sigpipe && !dispatcher.signal_is_ignored(context, carrick_abi::LINUX_SIGPIPE) {
        dispatcher.mark_signal_pending(context, tid, carrick_abi::LINUX_SIGPIPE);
    }
    match LinuxErrno::from_guest_retval(result) {
        Some(errno) => DispatchOutcome::Errno { errno },
        None => DispatchOutcome::Returned { value: result },
    }
}

/// Decode an [`carrick_el1_abi::ipc::IPC_HANDBACK_NR`] frame: restore the
/// original call in `request` and in the vCPU's `x0`/`x8`, then complete,
/// restart or park the owned operation. Wait-queue snapshots are taken
/// before the operation's readiness is checked, so a park cannot miss a
/// notification in between.
pub(super) fn ipc_handback_route<E: ThreadedEngine>(
    kernel: &Kernel,
    context: &carrick_kernel::kernel::KernelContext,
    tid: ThreadId,
    engine: &mut E,
    zone_mm: Option<u64>,
    request: &mut SyscallRequest,
) -> Result<IpcHandbackRoute, RuntimeError> {
    let region = host_ipc::host_region().ok_or_else(|| {
        RuntimeError::Configuration("IPC handback without a published IPC window".to_owned())
    })?;
    let (token, op) = host_ipc::take_handback(&region, request.arg(0))
        .map_err(|error| ipc_error("handback names no live operation", error))?;
    request.number = carrick_abi::CanonicalNr(u64::from(op.nr));
    request.native_number = carrick_abi::NativeNr(u64::from(op.nr));
    request.args.0[0] = op.orig_x0;
    engine
        .set_reg(carrick_hal::Reg::X(8), u64::from(op.nr))
        .map_err(|error| ipc_error("restore x8", error))?;
    engine
        .set_reg(carrick_hal::Reg::X(0), op.orig_x0)
        .map_err(|error| ipc_error("restore x0", error))?;
    let object = IpcObjectHandle::from_raw(op.object);
    let snapshots =
        carrick_kernel::el1_zone::zone().map(|zone| host_ipc::lane_snapshots(zone, object));
    let outcome = host_ipc::complete_handback(
        &region,
        token,
        IpcMmKey(zone_mm.unwrap_or(0)),
        engine,
        None,
        &host_ipc::ZoneHostServices::new(context.kernel())
            .map_err(|error| ipc_error("IPC owner", error))?,
    )
    .map_err(|error| ipc_error("handback completion", error))?;
    restart_with_remaining(engine, Some(request), &outcome)?;
    ipc_route(&kernel.dispatcher, context, tid, outcome, snapshots)
}

/// A timed epoll wait re-runs with what is left of its deadline: rewrite
/// its timeout argument (`x3`) in the vCPU and, for a call the host is about
/// to dispatch, in `request`, so the re-run never waits the full original
/// timeout again.
fn restart_with_remaining<E: ThreadedEngine>(
    engine: &mut E,
    request: Option<&mut SyscallRequest>,
    outcome: &host_ipc::IpcHostOutcome,
) -> Result<(), RuntimeError> {
    let host_ipc::IpcHostOutcome::Restart {
        timeout_ms: Some(timeout_ms),
        ..
    } = *outcome
    else {
        return Ok(());
    };
    let x3 = timeout_ms as u32 as u64;
    engine
        .set_reg(carrick_hal::Reg::X(3), x3)
        .map_err(|error| ipc_error("restore x3", error))?;
    if let Some(request) = request {
        request.args.0[3] = x3;
    }
    Ok(())
}

fn ipc_route(
    dispatcher: &carrick_kernel::dispatch::SyscallDispatcher,
    context: &carrick_kernel::kernel::KernelContext,
    tid: ThreadId,
    outcome: host_ipc::IpcHostOutcome,
    snapshots: Option<[Option<ObjectWaitSnapshot>; 2]>,
) -> Result<IpcHandbackRoute, RuntimeError> {
    Ok(match outcome {
        host_ipc::IpcHostOutcome::Complete { result, sigpipe } => {
            IpcHandbackRoute::Complete(ipc_complete(dispatcher, context, tid, result, sigpipe))
        }
        host_ipc::IpcHostOutcome::Restart { .. } => IpcHandbackRoute::Restart,
        host_ipc::IpcHostOutcome::Blocked {
            token,
            object,
            lane,
            ..
        } => {
            let snapshot = snapshots.and_then(|s| s[lane_index(lane)]).ok_or_else(|| {
                RuntimeError::Configuration(
                    "IPC operation must wait but its wait queue is unavailable".to_owned(),
                )
            })?;
            IpcHandbackRoute::Park(IpcPark {
                token,
                object,
                lane,
                snapshot,
            })
        }
    })
}

/// How an attempt to park an IPC operation ended.
enum IpcParkAttempt {
    Parked(executor::ExecutorExit),
    /// Readiness changed between the check and the park: the operation
    /// (token returned) runs again.
    Changed(IpcOpToken),
}

impl<E: ThreadedEngine + 'static> ProductionHvpatchLoopJob<E>
where
    E::SiblingSpec: 'static,
{
    /// Park this job's thread on the object wait queue of an IPC operation
    /// the host could not finish: the record holds the thread at its SVC with
    /// the original registers (`request`) and owns the operation token, so an
    /// in-guest wake resumes it in EL1 (the adapter takes the token before
    /// any fd lookup) and a host claim resumes it in [`Self::resume_zone`].
    fn ipc_park_attempt(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
        exit: ZoneExit,
        request: SyscallRequest,
        park: IpcPark,
    ) -> Result<IpcParkAttempt, ProductionHvpatchPollError> {
        let Some((zone, mm)) = zone_for(self.state.zone_mm) else {
            return Err(RuntimeError::Configuration(
                "IPC park without in-guest zone tables".to_owned(),
            )
            .into());
        };
        let context = self
            .kernel
            .dispatcher
            .capture_kernel_context(self.state.linux_tid)
            .map_err(|error| ipc_error("park context", error))?;
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
            lifecycle_page: 0,
            control_slot: 0,
        };
        let state = engine.snapshot_guest_state_for_publication()?;
        // Resume at the SVC with the original call's registers.
        let mut ctx = zone_ctx_from_state(&state, exit)?;
        ctx.x[0] = request.args.0[0];
        ctx.x[8] = request.number.raw();
        let key = host_ipc::wait_key(park.object, park.lane)
            .ok_or_else(|| ipc_error("wait key", park.object))?;
        let parked = {
            let guard = zone
                .object_wait(key, &HostLockWait)
                .map_err(|error| ipc_error("wait queue", error))?;
            let record = zone
                .alloc_record(identity)
                .map_err(|error| ipc_error("park record", error))?;
            // SAFETY: freshly allocated and not yet published.
            unsafe { *zone.record(record).ctx_mut() = ctx };
            let token = host_ipc::to_sched_token(park.token)
                .map_err(|_| RuntimeError::Configuration("IPC token conversion".to_owned()))?;
            // The park's sequence (the same one `park` publishes).
            let seq = zone.next_seq(record);
            match guard.park(park.snapshot, record, token) {
                Ok(()) => Ok((record, seq)),
                Err((error, token)) => {
                    zone.free_record(record);
                    Err((error, token))
                }
            }
        };
        match parked {
            Ok((record, seq)) => {
                zone.counters
                    .host_parks
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if matches!(exit, ZoneExit::Syscall { .. }) {
                    engine.discard_terminal_syscall_continuation()?;
                    self.state.retire_syscall()?;
                }
                let record = zone.record_ref(record);
                self.settle_into_zone(control, state, record, seq, None, request)
                    .map(IpcParkAttempt::Parked)
            }
            Err((host_ipc::ObjectWaitError::Changed, token)) => {
                let token = host_ipc::from_sched_token(token).ok_or_else(|| {
                    RuntimeError::Configuration("IPC token conversion".to_owned())
                })?;
                Ok(IpcParkAttempt::Changed(token))
            }
            Err((error, _token)) => Err(ipc_error("park refused", error).into()),
        }
    }

    /// Run the owned operation again on the host (no signal is pending at
    /// this boundary), with fresh wait snapshots taken before the check.
    fn ipc_continue(
        &mut self,
        engine: &mut E,
        token: IpcOpToken,
    ) -> Result<IpcHandbackRoute, ProductionHvpatchPollError> {
        let region = host_ipc::host_region().ok_or_else(|| {
            RuntimeError::Configuration("IPC continuation without a published window".to_owned())
        })?;
        let op = region
            .operation(&token)
            .map_err(|error| ipc_error("continuation", error))?;
        let object = IpcObjectHandle::from_raw(op.object);
        let snapshots =
            carrick_kernel::el1_zone::zone().map(|zone| host_ipc::lane_snapshots(zone, object));
        let outcome = host_ipc::complete_handback(
            &region,
            token,
            IpcMmKey(self.state.zone_mm.unwrap_or(0)),
            engine,
            None,
            &host_ipc::ZoneHostServices::for_dispatcher(&self.kernel.dispatcher)
                .map_err(|error| ipc_error("IPC owner", error))?,
        )
        .map_err(|error| ipc_error("continuation", error))?;
        // Re-entered at the SVC, the re-run reads its timeout from x3.
        restart_with_remaining(engine, None, &outcome)?;
        let context = self
            .kernel
            .dispatcher
            .capture_kernel_context(self.state.linux_tid)
            .map_err(|error| ipc_error("continuation context", error))?;
        Ok(ipc_route(
            &self.kernel.dispatcher,
            &context,
            self.state.this_tid,
            outcome,
            snapshots,
        )?)
    }

    /// The handback's operation must wait: park it; a readiness change
    /// before the park runs it again (completing the syscall if it can).
    pub(super) fn ipc_park(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
        frame: carrick_hal::RawSyscall,
        mut park: IpcPark,
    ) -> Result<executor::ExecutorExit, ProductionHvpatchPollError> {
        let request = self
            .state
            .syscall_completion
            .guest("IPC park lost its prepared completion token")?
            .syscall()
            .request;
        loop {
            match self.ipc_park_attempt(
                engine,
                control,
                ZoneExit::Syscall { completed: false },
                request,
                park,
            )? {
                IpcParkAttempt::Parked(exit) => return Ok(exit),
                IpcParkAttempt::Changed(token) => match self.ipc_continue(engine, token)? {
                    IpcHandbackRoute::Park(next) => park = next,
                    IpcHandbackRoute::Complete(outcome) => {
                        return self.service_outcome(engine, control, frame, outcome);
                    }
                    IpcHandbackRoute::Restart => {
                        return Err(RuntimeError::Configuration(
                            "IPC continuation restarted after taking effect".to_owned(),
                        )
                        .into());
                    }
                },
            }
        }
    }

    /// Whether this job's task is stopped by job control (a default-action
    /// stop signal took effect and no SIGCONT followed yet).
    fn job_control_stopped(&self) -> bool {
        self.kernel
            .dispatcher
            .capture_kernel_context(self.state.linux_tid)
            .is_ok_and(|context| {
                context
                    .kernel()
                    .task_is_job_control_stopped(context.task().key().id)
            })
    }

    /// A zone record holding an IPC operation was loaded from its record
    /// (the thread is at its SVC with the original registers): decide the
    /// operation by how the wait ended. `Some(exit)`: it parked again.
    fn resume_ipc_operation(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
        handback: Option<Handback>,
        token: IpcOpToken,
        reserved: Option<&carrick_kernel::kernel::continuation::ReservedSignal>,
    ) -> Result<Option<executor::ExecutorExit>, ProductionHvpatchPollError> {
        let region = host_ipc::host_region().ok_or_else(|| {
            RuntimeError::Configuration("IPC resume without a published window".to_owned())
        })?;
        // The resumed operation copies into the guest buffer without
        // passing syscall entry again; EL1 work this MM published while it
        // was parked is settled first, as at syscall entry.
        let mm_executor = self.state.guest_execution.as_mut().ok_or_else(|| {
            RuntimeError::Configuration("IPC resume without MM executor participation".to_owned())
        })?;
        signal::settle_guest_work_before_host_copy(&self.kernel.dispatcher, engine, mm_executor)?;
        let mut op = region
            .operation(&token)
            .map_err(|error| ipc_error("resume", error))?;
        let request = SyscallRequest::new(
            u64::from(op.nr),
            carrick_observability::compat::SyscallArgs([
                op.orig_x0,
                engine.get_reg(carrick_hal::Reg::X(1)).unwrap_or(0),
                engine.get_reg(carrick_hal::Reg::X(2)).unwrap_or(0),
                engine.get_reg(carrick_hal::Reg::X(3)).unwrap_or(0),
                engine.get_reg(carrick_hal::Reg::X(4)).unwrap_or(0),
                engine.get_reg(carrick_hal::Reg::X(5)).unwrap_or(0),
            ]),
        );
        let cause = match handback {
            Some(kind @ (Handback::Signal | Handback::GroupStop)) => Some(match reserved {
                // What the signal will do decides the interruption: a handler
                // (its SA_RESTART), a default stop (man 7 signal: some calls
                // fail with EINTR after SIGCONT, others continue), or nothing.
                Some(signal) => {
                    let action = signal.action();
                    ipc_signal_cause(
                        kind,
                        carrick_kernel::kernel::evaluate_signal_delivery_action(
                            signal.signum(),
                            action,
                        ),
                        action.sa_flags & carrick_abi::LINUX_SA_RESTART != 0,
                    )
                }
                None if handback == Some(Handback::GroupStop) => host_ipc::IpcCause::Stop,
                None => host_ipc::IpcCause::Signal { restart: false },
            }),
            // The deadline of a timed park (an epoll wait) the host kept
            // after it settled the slot.
            Some(Handback::Timeout) => Some(host_ipc::IpcCause::Timeout),
            // A control quantum for a job-control stop is a stop; the rest
            // (exec/exit drain, quiesce) never interrupt a call.
            Some(Handback::Control) if self.job_control_stopped() => Some(host_ipc::IpcCause::Stop),
            Some(Handback::Control | Handback::Cancelled) => Some(host_ipc::IpcCause::Control),
            Some(Handback::Woken | Handback::Resumed) => None,
            Some(Handback::Service) | None => {
                return Err(RuntimeError::Configuration(format!(
                    "IPC resume with handback {handback:?}"
                ))
                .into());
            }
        };
        let mut route = match cause {
            Some(cause) => {
                let outcome = host_ipc::interrupt(
                    &region,
                    token,
                    cause,
                    &host_ipc::ZoneHostServices::for_dispatcher(&self.kernel.dispatcher)
                        .map_err(|error| ipc_error("IPC owner", error))?,
                )
                .map_err(|error| ipc_error("interrupt", error))?;
                restart_with_remaining(engine, None, &outcome)?;
                let context = self
                    .kernel
                    .dispatcher
                    .capture_kernel_context(self.state.linux_tid)
                    .map_err(|error| ipc_error("interrupt context", error))?;
                ipc_route(
                    &self.kernel.dispatcher,
                    &context,
                    self.state.this_tid,
                    outcome,
                    None,
                )?
            }
            None => {
                // Readiness changed: continue the owned operation here.
                op.handback = carrick_el1_abi::ipc::IpcHandback::Continue;
                region
                    .update_operation(&token, op)
                    .map_err(|error| ipc_error("resume", error))?;
                self.ipc_continue(engine, token)?
            }
        };
        loop {
            match route {
                IpcHandbackRoute::Complete(outcome) => {
                    let value = match outcome {
                        DispatchOutcome::Errno { errno } => errno.guest_retval(),
                        DispatchOutcome::Returned { value } => value,
                        _ => 0,
                    };
                    let pc = engine.current_pc()?;
                    engine
                        .set_reg(carrick_hal::Reg::X(0), value as u64)
                        .map_err(|error| ipc_error("resume x0", error))?;
                    engine
                        .set_reg(carrick_hal::Reg::Pc, pc.wrapping_add(4))
                        .map_err(|error| ipc_error("resume pc", error))?;
                    return Ok(None);
                }
                // At the SVC with the original registers: the call runs
                // again after any handler (it took no effect).
                IpcHandbackRoute::Restart => return Ok(None),
                IpcHandbackRoute::Park(park) => {
                    match self.ipc_park_attempt(engine, control, ZoneExit::El0, request, park)? {
                        IpcParkAttempt::Parked(exit) => return Ok(Some(exit)),
                        IpcParkAttempt::Changed(token) => {
                            route = self.ipc_continue(engine, token)?
                        }
                    }
                }
            }
        }
    }
}

/// Preserve a caught handler's policy without losing the owned stop reason.
fn ipc_signal_cause(
    handback: Handback,
    action: carrick_kernel::kernel::SignalDeliveryAction,
    restart: bool,
) -> host_ipc::IpcCause {
    use carrick_kernel::kernel::SignalDeliveryAction;
    match action {
        SignalDeliveryAction::Handler { .. } => host_ipc::IpcCause::Signal { restart },
        SignalDeliveryAction::Stop => host_ipc::IpcCause::Stop,
        SignalDeliveryAction::Ignore if handback == Handback::GroupStop => host_ipc::IpcCause::Stop,
        SignalDeliveryAction::Ignore => host_ipc::IpcCause::Control,
        SignalDeliveryAction::Terminate => host_ipc::IpcCause::Signal { restart: false },
    }
}

#[cfg(test)]
mod ipc_tests {
    //! Host-level bindings for kernel.el1.ipc-continuation at the runtime
    //! boundary: syscall results, SIGPIPE, and the park decision.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use carrick_el1_abi::ipc::{EventMode, IpcOperation, IpcRegion};
    use carrick_kernel::dispatch::SyscallDispatcher;
    use std::alloc::Layout;

    #[test]
    fn ignored_signal_preserves_zone_group_stop_interruption() {
        use carrick_kernel::kernel::SignalDeliveryAction;
        assert_eq!(
            ipc_signal_cause(Handback::GroupStop, SignalDeliveryAction::Ignore, false),
            host_ipc::IpcCause::Stop,
        );
        assert_eq!(
            ipc_signal_cause(Handback::Signal, SignalDeliveryAction::Ignore, false),
            host_ipc::IpcCause::Control,
        );
        for restart in [false, true] {
            assert_eq!(
                ipc_signal_cause(
                    Handback::GroupStop,
                    SignalDeliveryAction::Handler { address: 0x1000 },
                    restart,
                ),
                host_ipc::IpcCause::Signal { restart },
            );
        }
    }

    fn dispatcher_and_context() -> (
        SyscallDispatcher,
        carrick_kernel::kernel::KernelContext,
        ThreadId,
    ) {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().expect("context");
        let tid = ThreadId::synthetic_for_tests(context.thread().key().tid.raw());
        (dispatcher, context, tid)
    }

    fn sigpipe_pending(context: &carrick_kernel::kernel::KernelContext) -> bool {
        context
            .thread()
            .signal_state()
            .pending()
            .contains(carrick_abi::LINUX_SIGPIPE)
    }

    fn region() -> &'static IpcRegion<'static> {
        let dir = unsafe {
            std::alloc::alloc_zeroed(
                Layout::from_size_align(carrick_el1_abi::ipc::IPC_DIRECTORY_BYTES, 4096).unwrap(),
            )
            .cast()
        };
        let pool_len = 1 << 20;
        let pool =
            unsafe { std::alloc::alloc_zeroed(Layout::from_size_align(pool_len, 4096).unwrap()) };
        Box::leak(Box::new(
            unsafe {
                IpcRegion::initialize(
                    dir,
                    carrick_el1_abi::ipc::IPC_DIRECTORY_BYTES,
                    pool,
                    pool_len,
                    3,
                )
            }
            .unwrap(),
        ))
    }

    fn zone() -> Box<ZoneTables> {
        // SAFETY: all-zero is the valid empty zone.
        unsafe { Box::from_raw(std::alloc::alloc_zeroed(Layout::new::<ZoneTables>()).cast()) }
    }

    #[test]
    fn el1_ipc_completion_maps_results_and_marks_sigpipe_unless_ignored() {
        let (dispatcher, context, tid) = dispatcher_and_context();
        assert_eq!(
            ipc_complete(&dispatcher, &context, tid, 65536, true),
            DispatchOutcome::Returned { value: 65536 }
        );
        assert!(sigpipe_pending(&context), "SIGPIPE after a partial write");
        context
            .thread()
            .update_signal_state(|s| s.replace_pending_entries(&[]));
        let epipe = carrick_abi::LINUX_EPIPE.guest_retval();
        assert_eq!(
            ipc_complete(&dispatcher, &context, tid, epipe, false),
            DispatchOutcome::Errno {
                errno: carrick_abi::LINUX_EPIPE
            }
        );
        assert!(!sigpipe_pending(&context), "no SIGPIPE unless requested");
        let mut ign = carrick_abi::LinuxSigaction::empty();
        ign.sa_handler = carrick_abi::LINUX_SIG_IGN;
        let signal =
            carrick_kernel::kernel::LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGPIPE)
                .unwrap();
        context.shared().sighand().install_action(signal, ign);
        ipc_complete(&dispatcher, &context, tid, epipe, true);
        assert!(!sigpipe_pending(&context), "SIG_IGN suppresses SIGPIPE");
    }

    #[test]
    fn el1_ipc_blocked_operation_parks_with_its_lane_snapshot_or_fails_closed() {
        let (dispatcher, context, tid) = dispatcher_and_context();
        let region = region();
        let zone = zone();
        let object = region
            .create_eventfd(0, EventMode::Counter, &HostLockWait)
            .unwrap();
        let blocked = |token| host_ipc::IpcHostOutcome::Blocked {
            token,
            object,
            lane: WaitFor::Writable,
            x0: 3,
            nr: 64,
        };
        // Snapshots taken before the readiness check, both lanes.
        let snapshots = host_ipc::lane_snapshots(&zone, object);
        assert!(snapshots.iter().all(Option::is_some));
        let token = region.begin_operation(IpcOperation::EMPTY).unwrap();
        let route = ipc_route(&dispatcher, &context, tid, blocked(token), Some(snapshots)).unwrap();
        let IpcHandbackRoute::Park(park) = route else {
            panic!("a blocked operation parks");
        };
        assert_eq!(park.lane, WaitFor::Writable);
        assert_eq!(
            Some(park.snapshot),
            snapshots[1],
            "the writer lane's snapshot"
        );
        assert_eq!(park.object, object);
        // A notification between the check and the park is never missed:
        // the park is refused as Changed and the operation runs again.
        let key = host_ipc::wait_key(object, WaitFor::Writable).unwrap();
        {
            let guard = zone.object_wait(key, &HostLockWait).unwrap();
            guard.notify_object_host(&mut |_| {}, &mut |_| {}).unwrap();
        }
        let record = zone
            .alloc_record(ThreadIdentity {
                tid: 1,
                serial: 1,
                mm: 7,
                file_table: 5,
                generation: 1,
                affinity: 0,
                lifecycle_page: 0,
                control_slot: 0,
            })
            .unwrap();
        let guard = zone.object_wait(key, &HostLockWait).unwrap();
        let token = host_ipc::to_sched_token(park.token).unwrap();
        let refused = guard.park(park.snapshot, record, token);
        assert!(matches!(
            refused,
            Err((host_ipc::ObjectWaitError::Changed, _))
        ));
        drop(guard);
        // Without a wait queue, a blocked operation fails closed.
        let token = region.begin_operation(IpcOperation::EMPTY).unwrap();
        assert!(ipc_route(&dispatcher, &context, tid, blocked(token), None).is_err());
    }

    fn syscall_state(nr: u64, x0: u64) -> GuestCpuState {
        let GuestCpuState::Aarch64V1(cpu) =
            crate::vcpu_loop::executor::tests::test_guest_cpu_state(0x100)
        else {
            unreachable!()
        };
        let mut cpu = (*cpu).clone();
        cpu.gprs[8] = nr;
        cpu.gprs[0] = x0;
        cpu.gprs[1] = 0x20000;
        GuestCpuState::from_aarch64_v1(cpu)
    }

    fn x0_x1(state: &GuestCpuState) -> (u64, u64) {
        match state {
            GuestCpuState::Aarch64V1(cpu) => (cpu.gprs[0], cpu.gprs[1]),
            _ => unreachable!(),
        }
    }

    /// A full VMA journal leaves `mprotect` with its commit owed, and EL1 has
    /// already written the result 0 into x0. The re-issued call must carry
    /// the original address, not 0.
    #[test]
    fn a_commit_owed_call_replays_with_its_original_address() {
        let boundary = Some(carrick_el1_abi::ServedBoundary::ReplayOriginal { x0: 0x60_0000_5000 });
        let (state, completed) = settle_served_state(syscall_state(226, 0), boundary);
        assert!(!completed, "the host commit is still owed");
        assert_eq!(x0_x1(&state), (0x60_0000_5000, 0x20000));
    }

    /// A call that merely left served (a drain that could not finish, an
    /// owed wake) is complete: its x0 is the result and it is never re-run,
    /// whatever its number (a journaled `mprotect` that blocked in a drain
    /// was re-run as `mprotect(0, len)` and answered ENOMEM).
    #[test]
    fn a_completed_served_call_is_not_replayed_even_for_mprotect() {
        let (state, completed) = settle_served_state(
            syscall_state(226, 0),
            Some(carrick_el1_abi::ServedBoundary::Completed),
        );
        assert!(completed);
        assert_eq!(x0_x1(&state).0, 0, "the result stays");
        let (state, completed) = settle_served_state(syscall_state(226, 0x5000), None);
        assert!(!completed);
        assert_eq!(x0_x1(&state).0, 0x5000, "a forwarded call keeps its frame");
    }
}
