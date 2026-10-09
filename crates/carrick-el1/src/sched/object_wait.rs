//! Guest venue for neutral object waits. The personality supplies the saved
//! resumption entry (for AArch64 Linux SVC, the SVC instruction address). On
//! readiness EL1 restores that entry and all original arguments in the exact
//! waiter's MM; the adapter takes the operation token before any fd lookup.
//! Re-entering resumes that owned operation, including its byte progress. It
//! must never replay the operation from its original numeric descriptor.

use crate::substrate::sched::{
    EL1_ZONE_LOCK_SPINS, Sched, Served, ThreadCpu, UserWord, identity_of,
};
use carrick_el1_abi::{Aarch64ParkedContext, SlotId, TrapFrame};
use carrick_sched_core::object_wait::{
    ObjectWaitError, ObjectWaitKey, ObjectWaitSnapshot, ObjectWakeReport, OperationToken,
};
use carrick_sched_core::{RecordId, WakeEffects};
use core::sync::atomic::Ordering;

/// Required completion venue for EL1-held queues. Detached handbacks use
/// the carrier boundary; SGIs and pending work are delivered after unlock.
pub(crate) fn deliver_completion<C: carrick_el1_abi::EntryContext>(
    zone: &carrick_sched_core::ZoneTables<C>,
    venue: SlotId,
    owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_, C>,
) {
    let (waker, effects, deferred) = owned.defer_handbacks();
    #[cfg(target_os = "none")]
    {
        let mut cpu = crate::substrate::sched::hw::HardwareCpu;
        let own = match waker {
            carrick_sched_core::Waker::El1 { slot } => Some(slot),
            carrick_sched_core::Waker::Host => None,
        };
        assert!(own.is_some() || (!effects.queued_own && !effects.misplaced));
        for slot in effects
            .sgi_slots()
            .chain(own.filter(|slot| effects.queued_own && *slot != venue))
        {
            let target = zone.slot(slot).sgi_target();
            if target != 0 {
                cpu.send_resched(slot, target);
            }
        }
        if effects.misplaced
            && let Some(slot) = own
            && let Some(task) = carrick_el1_abi::current_task_guest(usize::from(slot.raw()))
        {
            task.linux.mark_pending_host_work();
        }
        if (deferred || (effects.queued_own && own == Some(venue)))
            && let Some(task) = carrick_el1_abi::current_task_guest(usize::from(venue.raw()))
        {
            task.linux.mark_pending_host_work();
        }
    }
    #[cfg(not(target_os = "none"))]
    let _ = (waker, effects, deferred, venue, zone);
}

pub use carrick_core::wait::{ObjectParked, OperationResumePc};

impl<'a, C: ThreadCpu, U: UserWord> Sched<'a, C, U> {
    /// Snapshot before checking the object predicate. The object authority
    /// retains its endpoint pin throughout check, enrollment and resumption.
    pub fn observe_object(
        &self,
        key: ObjectWaitKey,
    ) -> Result<ObjectWaitSnapshot, ObjectWaitError> {
        let completion = |effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            Aarch64ParkedContext,
        >| { deliver_completion(self.zone, self.slot, effects) };
        carrick_core::wait::observe_object(self.zone, self.slot, key, &completion)
    }

    /// Whether a park of the running thread may carry a deadline: the
    /// slot's timer has no other live owner. The home record's deadline goes
    /// to the host when its executor settles it (`unhome`); any other
    /// record's is taken off the timer at every exit of the slot's executor
    /// (`take_foreign_timer`) and its thread re-runs the call on the host
    /// with the time left.
    pub fn may_time_park(&self) -> bool {
        carrick_core::wait::may_time_park(self.zone, self.slot)
    }

    /// Whether the switched-in record's last object park ended at its
    /// deadline (read after taking its operation token).
    pub fn object_wait_expired(&self) -> bool {
        carrick_core::wait::object_wait_expired(self.zone, self.slot)
    }

    /// Save and park a pending operation without switching while any caller
    /// lock might still be live. On Changed the caller rechecks the object;
    /// no bytes may be replayed, and the returned token remains its property.
    /// `deadline` (`CNTVCT`) bounds the park on this slot's timer; only a
    /// park [`Self::may_time_park`] allows may carry one (else `Occupied`).
    pub fn park_object(
        &mut self,
        frame: &TrapFrame,
        key: ObjectWaitKey,
        snapshot: ObjectWaitSnapshot,
        resume: OperationResumePc,
        operation: OperationToken,
        deadline: Option<u64>,
    ) -> Result<ObjectParked<'a, Aarch64ParkedContext>, (ObjectWaitError, OperationToken)> {
        let zone = self.zone;
        let slot = self.slot;
        let completion = |effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            Aarch64ParkedContext,
        >| { deliver_completion(zone, slot, effects) };
        let request =
            carrick_core::wait::ObjectParkRequest::new(key, snapshot, operation, deadline);
        carrick_core::wait::park_object_record(
            zone,
            slot,
            request,
            EL1_ZONE_LOCK_SPINS,
            &completion,
            || {
                let fresh = zone.slot(slot).current().is_none();
                let record = match self.current_record() {
                    Ok(record) => record,
                    Err(_) => return Err(ObjectWaitError::Exhausted),
                };
                // SAFETY: this is the slot's current record or its newly allocated
                // home record. Only this CPU owns its context until publish below.
                let ctx = unsafe { zone.record(record).ctx_mut() };
                self.cpu.save(frame, ctx);
                ctx.native.pc = resume.raw();
                Ok((record, fresh))
            },
        )
    }

    /// Consume the park ticket by leaving for the host at once, running
    /// nothing else on this vCPU: host work is pending here, and the host
    /// settles the parked thread at this boundary (its enrollment samples
    /// pending signals). All caller locks must be released.
    pub fn leave_after_object_park(
        &mut self,
        mut parked: ObjectParked<'_, Aarch64ParkedContext>,
    ) -> Option<Served> {
        if !parked.matches(self.zone, self.slot) {
            return None;
        }
        self.record_handoff(parked.take_receipt());
        self.counters.exit_reasons[carrick_el1_abi::El1ExitReason::IdleHostWork as usize]
            .fetch_add(1, Ordering::Relaxed);
        Some(Served::Idle)
    }

    /// All caller locks must be released before consuming the park ticket.
    /// `timeout_result` belongs to any unrelated timed futex served by idle.
    pub fn resume_after_object_park(
        &mut self,
        frame: &mut TrapFrame,
        mut parked: ObjectParked<'_, Aarch64ParkedContext>,
        timeout_result: u64,
    ) -> Option<Served> {
        if !parked.matches(self.zone, self.slot) {
            return None;
        }
        self.record_handoff(parked.take_receipt());
        Some(self.run_next(frame, timeout_result))
    }

    /// Called at the adapter's re-entry before looking up its numeric fd.
    /// The exact identity and MM were installed by `load`, then authenticated
    /// here before ownership is transferred out of the record.
    pub fn take_object_operation(&self) -> Result<Option<OperationToken>, ObjectWaitError> {
        let Some(record): Option<RecordId> = self.zone.slot(self.slot).current() else {
            return Ok(None);
        };
        let affinity = self.zone.record(record).identity().affinity;
        carrick_core::wait::take_object_operation(
            self.zone,
            self.slot,
            identity_of(self.task, affinity),
        )
    }

    /// Notify under the caller's object lock, then drop ALL locks before
    /// `finish_object_wake`. `deferred != 0` requires boundary settlement.
    pub fn notify_object(
        &self,
        key: ObjectWaitKey,
    ) -> Result<(ObjectWakeReport, WakeEffects), ObjectWaitError> {
        carrick_core::wait::notify_object(self.zone, self.slot, key, EL1_ZONE_LOCK_SPINS)
    }

    /// Send the same targeted SGIs and program the same queue timer as futex
    /// wakes. No object lock is held and no successful I/O result is forged.
    pub fn finish_object_wake(&mut self, effects: WakeEffects) {
        self.send_sgis(&effects);
        if effects.queued_own {
            self.zone.note_queued_since(self.slot, self.cpu.now());
            self.program_timer(true);
        }
        if effects.misplaced {
            self.task.linux.mark_pending_host_work();
        }
    }
}

/// Bind release authority at the actual zone-bearing guest entrypoint.
pub fn space_access<C: carrick_el1_abi::EntryContext>(
    zone: &carrick_sched_core::ZoneTables<C>,
    slot: carrick_sched_core::SlotId,
) -> carrick_sched_core::spaces::notification::SpaceAccess<'_, C> {
    fn deliver<C: carrick_el1_abi::EntryContext>(
        zone: &carrick_sched_core::ZoneTables<C>,
        waker: carrick_sched_core::Waker,
        effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_, C>,
    ) {
        assert!(matches!(waker, carrick_sched_core::Waker::El1 { .. }));
        if let carrick_sched_core::Waker::El1 { slot } = waker {
            deliver_completion(zone, slot, effects);
        }
    }
    carrick_core::wait::space_access(zone, slot, deliver)
}
