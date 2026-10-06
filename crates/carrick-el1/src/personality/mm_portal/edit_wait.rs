//! Conflicting edits retain their original syscall arguments in the existing
//! EL1 scheduler context. They have performed no effect before this park.

use crate::memory::reservations::SharedReservations;
use crate::substrate::sched::{Sched, Served, ThreadCpu, UserWord};
use carrick_core::wait::{
    EditWaitOutcome, EditWaitTarget, OperationResumePc, coordinate_prepared_edit_wait,
};
use carrick_el1_abi::{ReservationMm, ReservationRange, TrapFrame};
use core::sync::atomic::Ordering;

/// No result means the existing syscall venue continues. A result means its
/// original context is parked/queued, with execution capacity released.
pub fn park_prepared_edit<C: ThreadCpu, U: UserWord>(
    sched: &mut Sched<'_, C, U>,
    frame: &mut TrapFrame,
    table: &SharedReservations,
) -> Option<Served> {
    let nr = frame.x[8];
    if !matches!(nr, 214 | 215 | 216 | 222 | 226) {
        return None;
    }
    let mm = ReservationMm::new(sched.task.zone_mm.load(Ordering::Acquire))?;
    let index = sched.zone.spaces.find(mm.raw())?;
    if !table.admitted(index.index(), mm) {
        return None;
    }
    let resumed = sched.take_object_operation().ok().flatten();
    let resume = OperationResumePc::new(frame.elr.checked_sub(4)?)?;
    let rounded = |start: u64, len: u64| {
        let end = start.checked_add(len)?.checked_add(4095)? & !4095;
        ReservationRange::new(start & !4095, end)
    };
    let slot = sched.slot;
    let space_acc = crate::substrate::sched::object_wait::space_access(sched.zone, slot);

    let check_conflict = |root: &mut crate::memory::reservations::Reservations<'_>| {
        let first = match nr {
            215 | 216 | 226 => rounded(frame.x[0], frame.x[1]),
            222 if frame.x[3] & (0x10 | 0x100000) != 0 => rounded(frame.x[0], frame.x[1]),
            214 => {
                let old = root.brk_current().checked_add(4095)? & !4095;
                let new = frame.x[0].checked_add(4095)? & !4095;
                ReservationRange::new(old.min(new), old.max(new))
            }
            _ => None,
        };
        let second = (nr == 216 && frame.x[3] & 2 != 0)
            .then(|| rounded(frame.x[4], frame.x[2]))
            .flatten();
        Some(
            first.is_some_and(|range| root.prepared_overlaps(range))
                || second.is_some_and(|range| root.prepared_overlaps(range)),
        )
    };

    let zone = sched.zone;
    let observe = |key| {
        let completion = |effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>| {
            crate::substrate::sched::object_wait::deliver_completion(zone, slot, effects);
        };
        carrick_core::wait::observe_object(zone, slot, key, &completion)
    };

    let target = EditWaitTarget::new(space_acc, index.index(), mm, slot);
    let outcome = coordinate_prepared_edit_wait(
        table,
        target,
        resumed,
        observe,
        check_conflict,
        |key, snapshot, token| sched.park_object(frame, key, snapshot, resume, token, None),
    );

    match outcome {
        EditWaitOutcome::StaleToken => {
            sched.task.orig_arg0.store(frame.x[0], Ordering::Relaxed);
            frame.x[0] = (-3i64) as u64;
            Some(Served::Returned { switched: false })
        }
        EditWaitOutcome::Parked(parked) => {
            if sched.task.has_pending_host_work() {
                sched.leave_after_object_park(parked)
            } else {
                sched.resume_after_object_park(frame, parked, 0)
            }
        }
        EditWaitOutcome::NoConflict | EditWaitOutcome::Refused => None,
    }
}
