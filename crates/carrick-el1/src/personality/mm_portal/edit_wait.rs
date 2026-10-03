//! Conflicting edits retain their original syscall arguments in the existing
//! EL1 scheduler context. They have performed no effect before this park.
use crate::memory::reservations::SharedReservations;
use crate::substrate::sched::object_wait::OperationResumePc;
use crate::substrate::sched::{Sched, Served, ThreadCpu, UserWord};
use carrick_el1_abi::{ReservationMm, ReservationRange, TrapFrame};
use carrick_sched_core::BoundedSpin;
use carrick_sched_core::object_wait::{ObjectWaitError, OperationToken};
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
    // A resumed edit owns only its unchanged saved SVC context. Unlike a
    // consuming IPC operation, redispatch has no source effect to replay.
    let resumed = sched.take_object_operation().ok().flatten();
    loop {
        let mut root = table.lock_el1(index.index(), mm, frame.slot as u32).ok()?;
        let key = root.prepared_wait_key()?;
        if resumed.as_ref().is_some_and(|token| {
            token.index() != u64::from(key.index()) || token.generation() != key.generation()
        }) {
            sched.task.orig_arg0.store(frame.x[0], Ordering::Relaxed);
            frame.x[0] = (-3i64) as u64;
            return Some(Served::Returned { switched: false });
        }

        let snapshot = match sched.observe_object(key) {
            Ok(snapshot) => snapshot,
            Err(ObjectWaitError::Stale) => {
                let completion =
                    |effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>| {
                        crate::substrate::sched::object_wait::deliver_completion(
                            sched.zone, sched.slot, effects,
                        )
                    };
                sched
                    .zone
                    .bind_object_wait_with_completion(key, &BoundedSpin(256), &completion)
                    .ok()?;
                sched.observe_object(key).ok()?
            }
            Err(_) => return None,
        };
        let rounded = |start: u64, len: u64| {
            let end = start.checked_add(len)?.checked_add(4095)? & !4095;
            ReservationRange::new(start & !4095, end)
        };
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
        let conflict = first.is_some_and(|range| root.prepared_overlaps(range))
            || second.is_some_and(|range| root.prepared_overlaps(range));
        drop(root);
        if !conflict {
            return None;
        }
        let resume = OperationResumePc::new(frame.elr.checked_sub(4)?)?;
        let token = OperationToken::new(u64::from(key.index()), key.generation())?;
        match sched.park_object(frame, key, snapshot, resume, token, None) {
            Ok(parked) => {
                return if sched.task.has_pending_host_work() {
                    sched.leave_after_object_park(parked)
                } else {
                    sched.resume_after_object_park(frame, parked, 0)
                };
            }
            // This is a completed owner publication, not a poll. Recheck the
            // predicate against its new epoch before making any proposal.
            Err((ObjectWaitError::Changed, _)) => continue,
            Err(_) => return None,
        }
    }
}
