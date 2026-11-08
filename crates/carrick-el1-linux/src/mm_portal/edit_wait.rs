//! Conflicting edits retain their original syscall arguments in the existing
//! EL1 scheduler context. They have performed no effect before this park.

use carrick_core::wait::{
    EditWaitOutcome, EditWaitTarget, OperationResumePc, coordinate_anonymous_edit_wait,
    coordinate_prepared_edit_wait,
};
use carrick_el1::memory::reservations::SharedReservations;
use carrick_el1::substrate::sched::{Sched, Served, ThreadCpu, UserWord};
use carrick_el1_abi::{ReservationMm, ReservationRange, TrapFrame};
use carrick_personality_linux::dispatch::AnonymousCall;
use carrick_sched_core::object_wait::ObjectWaitError;
use carrick_sched_core::spaces::notification::SpaceWaitCause;
use carrick_syscall_abi::CanonicalNr;
use core::num::NonZeroU64;
use core::sync::atomic::Ordering;

/// Consume the scheduler-owned token after a resumed anonymous edit commits.
///
/// A caught signal unlinks the wait but deliberately leaves its operation on
/// the record while the handler borrows execution.  A successful replay is
/// the terminal owner of that token.  Match it against this MM's typed space
/// notification keys before taking it so an unrelated adapter operation can
/// never be consumed by the anonymous path.
pub fn complete_anonymous_edit_replay(
    zone: &carrick_sched_core::ZoneTables<carrick_sched_core::Aarch64ParkedContext>,
    slot: carrick_el1_abi::SlotId,
    task: &carrick_el1_abi::CurrentTask,
) -> Result<bool, ObjectWaitError> {
    let Some(record) = zone
        .slot(slot)
        .current()
        .or_else(|| zone.slot(slot).host_record())
    else {
        return Ok(false);
    };
    let retained = zone.record(record);
    let Some(census) = retained.object_wait_census() else {
        return Ok(false);
    };
    let mm = NonZeroU64::new(task.mm.key.load(Ordering::Acquire))
        .and_then(|mm| zone.space_entry(mm))
        .and_then(|entry| entry.live_notifications().ok());
    let Some(notifications) = mm else {
        return Ok(false);
    };
    let anonymous = SpaceWaitCause::ALL.into_iter().any(|cause| {
        let key = notifications.key(cause);
        census.operation == key.index() as u64 && census.operation_generation == key.generation()
    });
    if !anonymous {
        return Ok(false);
    }
    carrick_core::wait::take_object_operation(zone, slot, retained.identity())?
        .map(|_| true)
        .ok_or(ObjectWaitError::Stale)
}

/// No result means the existing syscall venue continues. A result means its
/// original context is parked/queued, with execution capacity released.
pub fn park_prepared_edit<C: ThreadCpu, U: UserWord>(
    sched: &mut Sched<'_, C, U>,
    frame: &mut TrapFrame,
    table: &SharedReservations,
) -> Option<Served> {
    let nr = frame.x[8];
    let call = AnonymousCall::from_canonical(CanonicalNr::new(nr))?;
    let mm = ReservationMm::new(sched.task.mm.key.load(Ordering::Acquire))?;
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
    let space_acc = carrick_el1::substrate::sched::object_wait::space_access(sched.zone, slot);

    let check_conflict = |root: &mut carrick_el1::memory::reservations::Reservations<'_>| {
        let first = match call {
            AnonymousCall::Munmap | AnonymousCall::Mremap | AnonymousCall::Mprotect => {
                rounded(frame.x[0], frame.x[1])
            }
            AnonymousCall::Mmap if frame.x[3] & (0x10 | 0x100000) != 0 => {
                rounded(frame.x[0], frame.x[1])
            }
            AnonymousCall::Brk => {
                let old = root.brk_current().checked_add(4095)? & !4095;
                let new = frame.x[0].checked_add(4095)? & !4095;
                ReservationRange::new(old.min(new), old.max(new))
            }
            _ => None,
        };
        let second = (call == AnonymousCall::Mremap && frame.x[3] & 2 != 0)
            .then(|| rounded(frame.x[4], frame.x[2]))
            .flatten();
        Some(
            first.is_some_and(|range| root.prepared_overlaps(range))
                || second.is_some_and(|range| root.prepared_overlaps(range)),
        )
    };

    let zone = sched.zone;
    let observe = |key| {
        let completion = |effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_el1_abi::Aarch64ParkedContext,
        >| {
            carrick_el1::substrate::sched::object_wait::deliver_completion(zone, slot, effects);
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
            sched
                .task
                .linux
                .orig_arg0
                .store(frame.x[0], Ordering::Relaxed);
            frame.elr = resume.raw();
            Some(Served::Returned { switched: false })
        }
        EditWaitOutcome::Parked(parked) => {
            if sched.task.linux.has_pending_host_work() {
                sched.leave_after_object_park(parked)
            } else {
                sched.resume_after_object_park(frame, parked, 0)
            }
        }
        EditWaitOutcome::NoConflict | EditWaitOutcome::Refused => None,
    }
}

/// A native anonymous refusal has made no effects. Recheck the exact MM
/// resource after observing every release source, then park or replay the
/// original SVC. The pre-dispatch prepared check above remains a fast probe.
pub fn park_anonymous_edit<C: ThreadCpu, U: UserWord>(
    sched: &mut Sched<'_, C, U>,
    frame: &mut TrapFrame,
    table: &SharedReservations,
    initial_cause: SpaceWaitCause,
) -> Option<Served> {
    park_anonymous_edit_with_allocator(
        sched,
        frame,
        table,
        initial_cause,
        &carrick_el1::alloc::GLOBAL_ALLOCATOR,
    )
}

pub(super) fn park_anonymous_edit_with_allocator<C: ThreadCpu, U: UserWord>(
    sched: &mut Sched<'_, C, U>,
    frame: &mut TrapFrame,
    table: &SharedReservations,
    _initial_cause: SpaceWaitCause,
    metadata: &impl carrick_core::mm::reservation::ReservationMetadataAllocator,
) -> Option<Served> {
    let mm = ReservationMm::new(sched.task.mm.key.load(Ordering::Acquire))?;
    let index = sched.zone.spaces.find(mm.raw())?;
    if !table.admitted(index.index(), mm) {
        return None;
    }
    let source = sched
        .zone
        .space_entry(NonZeroU64::new(mm.raw())?)?
        .live_notifications()
        .ok()?;
    let resume = OperationResumePc::new(frame.elr.checked_sub(4)?)?;
    let resumed = sched.take_object_operation().ok().flatten();
    let slot = sched.slot;
    let access = carrick_el1::substrate::sched::object_wait::space_access(sched.zone, slot);
    let owner = NonZeroU64::new(slot.index() as u64 + 1)?;
    let task = sched.task;
    AnonymousCall::from_canonical(CanonicalNr::new(frame.x[8]))?;
    let zone = sched.zone;
    let outcome = coordinate_anonymous_edit_wait(
        &source,
        resumed,
        || {
            let mut root = match table.lock_in(access, index.index(), mm, slot.index() as u32) {
                Ok(root) => root,
                Err(carrick_el1::memory::reservations::Refusal::Busy) => {
                    return Some(Some(SpaceWaitCause::Reservations));
                }
                Err(_) => return None,
            };
            use carrick_el1::memory::{ReservationDisposition, decide_reservation_syscall};
            let decision = decide_reservation_syscall(frame, task, &mut root, None);
            match decision {
                ReservationDisposition::Unavailable(
                    carrick_el1::memory::reservations::Refusal::PreparedConflict,
                ) => return Some(Some(SpaceWaitCause::PreparedOverlap)),
                ReservationDisposition::Unavailable(
                    carrick_el1::memory::reservations::Refusal::Busy,
                ) => return Some(Some(SpaceWaitCause::PendingEdit)),
                ReservationDisposition::Unavailable(
                    carrick_el1::memory::reservations::Refusal::MetadataRequired,
                ) => {
                    if root.provision_metadata(metadata).is_err() {
                        return None;
                    }
                    return Some(None);
                }
                ReservationDisposition::Unavailable(_) => return None,
                ReservationDisposition::Work(pending) => {
                    if pending.cancel(&mut root).is_err() {
                        return None;
                    }
                }
                ReservationDisposition::Return(_) | ReservationDisposition::Forward => {}
            }
            drop(root);
            match zone
                .spaces
                .try_begin_edit_cause(index, mm.raw(), owner, access.venue())
            {
                Ok(editor) => {
                    drop(editor);
                    Some(None)
                }
                Err(carrick_sched_core::spaces::EditAdmissionRefusal::Editor) => {
                    Some(Some(SpaceWaitCause::Editor))
                }
                Err(carrick_sched_core::spaces::EditAdmissionRefusal::Gate) => {
                    Some(Some(SpaceWaitCause::Gate))
                }
                Err(carrick_sched_core::spaces::EditAdmissionRefusal::Stale) => None,
            }
        },
        |key, snapshot, token| {
            sched.park_object_rechecked(frame, key, snapshot, resume, token, || {
                SpaceWaitCause::ALL.into_iter().any(|cause| {
                    source.key(cause) == key && source.observe(cause) == snapshot.observed()
                })
            })
        },
    );
    match outcome {
        EditWaitOutcome::Parked(parked) => {
            if sched.task.linux.has_pending_host_work() {
                sched.leave_after_object_park(parked)
            } else {
                sched.resume_after_object_park(frame, parked, 0)
            }
        }
        EditWaitOutcome::NoConflict | EditWaitOutcome::StaleToken => {
            frame.elr = resume.raw();
            Some(Served::Returned { switched: false })
        }
        EditWaitOutcome::Refused => None,
    }
}
