//! Guest venue for neutral object waits. The personality supplies the saved
//! resumption entry (for AArch64 Linux SVC, the SVC instruction address). On
//! readiness EL1 restores that entry and all original arguments in the exact
//! waiter's MM; the adapter takes the operation token before any fd lookup.
//! Re-entering resumes that owned operation, including its byte progress. It
//! must never replay the operation from its original numeric descriptor.

use super::*;
use carrick_sched_core::object_wait::{
    ObjectWaitError, ObjectWaitKey, ObjectWaitSnapshot, ObjectWakeReport, OperationToken,
};
use carrick_sched_core::{Claim, RecordId};

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
#[derive(Debug)]
#[must_use = "a published park must be followed by scheduling another thread"]
pub struct ObjectParked {
    slot: SlotId,
}

impl<C: ThreadCpu, U: UserWord> Sched<'_, C, U> {
    /// Snapshot before checking the object predicate. The object authority
    /// retains its endpoint pin throughout check, enrollment and resumption.
    pub fn observe_object(
        &self,
        key: ObjectWaitKey,
    ) -> Result<ObjectWaitSnapshot, ObjectWaitError> {
        Ok(self
            .zone
            .object_wait(key, &BoundedSpin(EL1_ZONE_LOCK_SPINS))?
            .snapshot())
    }

    /// Save and park a pending operation without switching while any caller
    /// lock might still be live. On Changed the caller rechecks the object;
    /// no bytes may be replayed, and the returned token remains its property.
    pub fn park_object(
        &mut self,
        frame: &TrapFrame,
        key: ObjectWaitKey,
        snapshot: ObjectWaitSnapshot,
        resume: OperationResumePc,
        operation: OperationToken,
    ) -> Result<ObjectParked, (ObjectWaitError, OperationToken)> {
        let zone = self.zone;
        let guard = match zone.object_wait(key, &BoundedSpin(EL1_ZONE_LOCK_SPINS)) {
            Ok(guard) => guard,
            Err(error) => return Err((error, operation)),
        };
        let fresh = zone.slot(self.slot).current().is_none();
        let affinity = zone.slot(self.slot).affinity();
        let record = match zone.current_or_new(self.slot, identity_of(self.task, affinity)) {
            Ok(record) => record,
            Err(_) => return Err((ObjectWaitError::Exhausted, operation)),
        };
        // SAFETY: this is the slot's current record or its newly allocated
        // home record. Only this CPU owns its context until publish below.
        let ctx = unsafe { zone.record(record).ctx_mut() };
        self.cpu.save(frame, ctx);
        ctx.pc = resume.0;
        if let Err(error) = guard.park(snapshot, record, operation) {
            drop(guard);
            if fresh {
                zone.discard_unpublished(self.slot, record);
            }
            return Err(error);
        }
        drop(guard);
        zone.clear_current(self.slot);
        zone.counters.el1_parks.fetch_add(1, Ordering::Relaxed);
        Ok(ObjectParked { slot: self.slot })
    }

    /// All caller locks must be released before consuming the park ticket.
    /// `timeout_result` belongs to any unrelated timed futex served by idle.
    pub fn resume_after_object_park(
        &mut self,
        frame: &mut TrapFrame,
        parked: ObjectParked,
        timeout_result: u64,
    ) -> Option<Served> {
        if parked.slot != self.slot {
            return None;
        }
        Some(self.run_next(frame, timeout_result))
    }

    /// Called at the adapter's re-entry before looking up its numeric fd.
    /// The exact identity and MM were installed by `load`, then authenticated
    /// here before ownership is transferred out of the record.
    pub fn take_object_operation(&self) -> Option<OperationToken> {
        let record: RecordId = self.zone.slot(self.slot).current()?;
        let rec = self.zone.record(record);
        let id = rec.identity();
        if !matches!(rec.claim(), Claim::OnCpu { slot, .. } if slot == self.slot)
            || id != identity_of(self.task, id.affinity)
            || self.zone.installed_space(self.slot) != id.mm
        {
            return None;
        }
        // SAFETY: this slot owns the OnCpu record, load restored its exact
        // MM/task, and the waker detached its registration before queueing.
        unsafe { rec.take_object_operation() }
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
