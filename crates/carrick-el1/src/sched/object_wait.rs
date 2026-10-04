//! Guest venue for neutral object waits. The personality supplies the saved
//! resumption entry (for AArch64 Linux SVC, the SVC instruction address). On
//! readiness EL1 restores that entry and all original arguments in the exact
//! waiter's MM; the adapter takes the operation token before any fd lookup.
//! Re-entering resumes that owned operation, including its byte progress. It
//! must never replay the operation from its original numeric descriptor.

use crate::substrate::sched::{
    EL1_ZONE_LOCK_SPINS, Sched, Served, ThreadCpu, UserWord, identity_of,
};
use carrick_el1_abi::{SlotId, TrapFrame};
use carrick_sched_core::object_wait::{
    ObjectWaitError, ObjectWaitKey, ObjectWaitSnapshot, ObjectWakeReport, OperationToken,
};
use carrick_sched_core::{BoundedSpin, Claim, RecordId, WakeEffects, ZoneTables};
use core::sync::atomic::Ordering;

/// Required completion venue for EL1-held queues. Detached handbacks use
/// the carrier boundary; SGIs and pending work are delivered after unlock.
pub(crate) fn deliver_completion(
    zone: &ZoneTables,
    venue: SlotId,
    owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects,
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
                cpu.send_sgi(target | (u64::from(carrick_el1_abi::GIC_RESCHED_INTID) << 24));
            }
        }
        if effects.misplaced
            && let Some(slot) = own
            && let Some(task) = carrick_el1_abi::current_task_guest(usize::from(slot.raw()))
        {
            task.mark_pending_host_work();
        }
        if (deferred || (effects.queued_own && own == Some(venue)))
            && let Some(task) = carrick_el1_abi::current_task_guest(usize::from(venue.raw()))
        {
            task.mark_pending_host_work();
        }
    }
    #[cfg(not(target_os = "none"))]
    let _ = (waker, effects, deferred, venue, zone);
}

/// Adapter-selected guest re-entry PC, distinct from a syscall return value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationResumePc(u64);

impl OperationResumePc {
    pub const fn new(pc: u64) -> Option<Self> {
        if pc == 0 || !pc.is_multiple_of(4) {
            None
        } else {
            Some(Self(pc))
        }
    }
}

/// A published park. Consuming this ticket switches only after all object
/// and queue guards have been released by the caller.
#[must_use = "a published park must be followed by scheduling another thread"]
pub struct ObjectParked<'a> {
    zone: &'a ZoneTables,
    slot: SlotId,
}

impl<'a, C: ThreadCpu, U: UserWord> Sched<'a, C, U> {
    /// Snapshot before checking the object predicate. The object authority
    /// retains its endpoint pin throughout check, enrollment and resumption.
    pub fn observe_object(
        &self,
        key: ObjectWaitKey,
    ) -> Result<ObjectWaitSnapshot, ObjectWaitError> {
        let completion = |effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>| {
            deliver_completion(self.zone, self.slot, effects)
        };
        let guard = if self.zone.completion_enabled(key) {
            self.zone.object_wait_with_completion(
                key,
                &BoundedSpin(EL1_ZONE_LOCK_SPINS),
                &completion,
            )?
        } else {
            self.zone
                .object_wait(key, &BoundedSpin(EL1_ZONE_LOCK_SPINS))?
        };
        Ok(guard.snapshot())
    }

    /// Whether a park of the running thread may carry a deadline: the
    /// slot's timer has no other live owner. The home record's deadline goes
    /// to the host when its executor settles it (`unhome`); any other
    /// record's is taken off the timer at every exit of the slot's executor
    /// (`take_foreign_timer`) and its thread re-runs the call on the host
    /// with the time left.
    pub fn may_time_park(&self) -> bool {
        self.zone.timer_free(self.slot)
    }

    /// Whether the switched-in record's last object park ended at its
    /// deadline (read after taking its operation token).
    pub fn object_wait_expired(&self) -> bool {
        self.zone
            .slot(self.slot)
            .current()
            .is_some_and(|record| self.zone.record(record).object_wait_expired())
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
    ) -> Result<ObjectParked<'a>, (ObjectWaitError, OperationToken)> {
        let zone = self.zone;
        if deadline.is_some() && !self.may_time_park() {
            return Err((ObjectWaitError::Occupied, operation));
        }
        let completion = |effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>| {
            deliver_completion(zone, self.slot, effects)
        };
        let result = if zone.completion_enabled(key) {
            zone.object_wait_with_completion(key, &BoundedSpin(EL1_ZONE_LOCK_SPINS), &completion)
        } else {
            zone.object_wait(key, &BoundedSpin(EL1_ZONE_LOCK_SPINS))
        };
        let guard = match result {
            Ok(guard) => guard,
            Err(error) => return Err((error, operation)),
        };
        let fresh = zone.slot(self.slot).current().is_none();
        let record = match self.current_record() {
            Ok(record) => record,
            Err(_) => return Err((ObjectWaitError::Exhausted, operation)),
        };
        // SAFETY: this is the slot's current record or its newly allocated
        // home record. Only this CPU owns its context until publish below.
        let ctx = unsafe { zone.record(record).ctx_mut() };
        self.cpu.save(frame, ctx);
        ctx.pc = resume.0;
        // The park's sequence (the one `park_until` publishes). The timer is
        // armed first: until the park is published its owner is not live
        // (a refused park leaves a stale owner `timer_owner` drops).
        let seq = zone.next_seq(record);
        if deadline.is_some() && zone.arm_timer(self.slot, record, seq).is_err() {
            drop(guard);
            if fresh {
                zone.discard_unpublished(self.slot, record);
            }
            return Err((ObjectWaitError::Occupied, operation));
        }
        if let Err(error) = guard.park_until(snapshot, record, operation, deadline.unwrap_or(0)) {
            drop(guard);
            if fresh {
                zone.discard_unpublished(self.slot, record);
            }
            return Err(error);
        }
        drop(guard);
        zone.clear_current(self.slot);
        zone.counters.el1_parks.fetch_add(1, Ordering::Relaxed);
        Ok(ObjectParked {
            zone,
            slot: self.slot,
        })
    }

    /// Consume the park ticket by leaving for the host at once, running
    /// nothing else on this vCPU: host work is pending here, and the host
    /// settles the parked thread at this boundary (its enrollment samples
    /// pending signals). All caller locks must be released.
    pub fn leave_after_object_park(&mut self, parked: ObjectParked<'_>) -> Option<Served> {
        if parked.slot != self.slot || !core::ptr::eq(parked.zone, self.zone) {
            return None;
        }
        self.counters.exit_reasons[carrick_el1_abi::El1ExitReason::IdleHostWork as usize]
            .fetch_add(1, Ordering::Relaxed);
        Some(Served::Idle)
    }

    /// All caller locks must be released before consuming the park ticket.
    /// `timeout_result` belongs to any unrelated timed futex served by idle.
    pub fn resume_after_object_park(
        &mut self,
        frame: &mut TrapFrame,
        parked: ObjectParked<'_>,
        timeout_result: u64,
    ) -> Option<Served> {
        if parked.slot != self.slot || !core::ptr::eq(parked.zone, self.zone) {
            return None;
        }
        Some(self.run_next(frame, timeout_result))
    }

    /// Called at the adapter's re-entry before looking up its numeric fd.
    /// The exact identity and MM were installed by `load`, then authenticated
    /// here before ownership is transferred out of the record.
    pub fn take_object_operation(&self) -> Result<Option<OperationToken>, ObjectWaitError> {
        let Some(record): Option<RecordId> = self.zone.slot(self.slot).current() else {
            return Ok(None);
        };
        let rec = self.zone.record(record);
        let id = rec.identity();
        if !matches!(rec.claim(), Claim::OnCpu { slot, .. } if slot == self.slot)
            || id != identity_of(self.task, id.affinity)
            || self.zone.installed_space(self.slot) != id.mm
        {
            return Err(ObjectWaitError::Stale);
        }
        // SAFETY: this slot owns the OnCpu record, load restored its exact
        // MM/task, and the waker detached its registration before queueing.
        Ok(unsafe { rec.take_object_operation() })
    }

    /// Notify under the caller's object lock, then drop ALL locks before
    /// `finish_object_wake`. `deferred != 0` requires boundary settlement.
    pub fn notify_object(
        &self,
        key: ObjectWaitKey,
    ) -> Result<(ObjectWakeReport, WakeEffects), ObjectWaitError> {
        let guard = self
            .zone
            .object_wait(key, &BoundedSpin(EL1_ZONE_LOCK_SPINS))?;
        let mut effects = WakeEffects::default();
        let report = guard.notify_object(self.slot, &mut effects)?;
        Ok((report, effects))
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
            self.task.mark_pending_host_work();
        }
    }
}

/// Bind release authority at the actual zone-bearing guest entrypoint.
pub fn space_access(
    zone: &carrick_sched_core::ZoneTables,
    slot: carrick_sched_core::SlotId,
) -> carrick_sched_core::spaces::notification::SpaceAccess<'_> {
    fn deliver(
        zone: &carrick_sched_core::ZoneTables,
        waker: carrick_sched_core::Waker,
        effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>,
    ) {
        assert!(matches!(waker, carrick_sched_core::Waker::El1 { .. }));
        if let carrick_sched_core::Waker::El1 { slot } = waker {
            deliver_completion(zone, slot, effects);
        }
    }
    carrick_sched_core::spaces::notification::SpaceAccess::notified(
        carrick_sched_core::spaces::notification::SpaceReleaseVenue {
            zone,
            waker: carrick_sched_core::Waker::El1 { slot },
            deliver,
        },
    )
}
