//! Linux epoll_pwait(2) on a zone epoll, served in EL1 (contract
//! `kernel.el1.epoll-zone`).
//!
//! The set's zone half lives in the shared record
//! (`carrick_el1_abi::ipc::epoll`); EL1 runs the same harvest routine the
//! host does. EL1 serves a wait only when the set has no host-half items;
//! the rest is forwarded unchanged, before any effect:
//!
//! - a non-NULL sigmask that EL1 cannot honour: unreadable, or the caller has
//!   no native signal owner (the host swaps the mask around its wait). A
//!   native caller's mask is swapped in by EL1 as the wait parks: the
//!   persistent mask is saved in the thread's control slot and restored by
//!   the signal checkpoint that ends the call (so a handler runs under the
//!   temporary mask, as for `rt_sigsuspend`), or by the re-entered call
//!   before it harvests again. A call that returns without parking never
//!   changes the mask;
//! - host-half items (only the host harvests both halves);
//! - a finite timeout with nothing ready while another thread's timed
//!   park holds the slot's timer (a slot's timer has one owner);
//! - a buffer the reports cannot be copied to, when no native owner retains
//!   the caller's memory (the harvested items are put back first, so the
//!   host's harvest reports them again).
//!
//! With a native owner, a refused copy-out never leaves the ring: the items
//! are put back, the owner prepares the buffer (a first touch is supplied,
//! or waited for) and the call harvests again; a buffer the owner faults is
//! EFAULT, its reports still queued, as on Linux. A pwait mask is armed
//! before the preparation, so a suspended preparation keeps it like a parked
//! wait does. A full operation arena is "not now": the call parks on the
//! arena's slot release and reruns, keeping what it accepted at entry (its
//! armed mask, and its timeout's absolute expiry, retained by the native
//! owner); a signal the mask does not block ends that wait with EINTR.
//!
//! A blocking wait parks on the epoll's `Readable` lane with an
//! [`IpcOpKind::EpollWait`] operation that pins the epoll's description, so
//! the record and its wait key keep their incarnation while parked. A
//! finite timeout becomes an absolute deadline on the virtual counter, kept
//! in the operation and armed on the slot's timer; the park ends on a
//! notification or the deadline, whichever claims it first. The operation
//! owns no progress: on an in-guest wake the thread re-enters the SVC, the
//! adapter retires the operation and harvests afresh, re-parking with the
//! remaining time if nothing is ready; after the deadline it harvests once
//! more (a wake racing the deadline is reported) and otherwise returns 0. A
//! host continuation re-runs the original call; a host-kept deadline
//! returns 0; a signal ends it with EINTR whatever the handler's
//! `SA_RESTART` (`interrupted` on the host).
//!
//! The wait snapshot is taken before the harvest: a member's publication
//! queues its item on the epoll before it notifies the lane, so an item
//! queued after an empty harvest always moves the snapshot and the park
//! reports `Changed`.

use super::{
    EL1_WAIT, Finish, IpcExecution, IpcRegion, IpcServed, IpcVenue, Parked, UserCopy,
    argument_word, finish, from_sched_token, leave, linux, mm_key, notify_operation_release, park,
    park_result, release_pin, retain_native_operation, set_result, snapshot, task_key,
    to_sched_token,
};
use crate::dispatch::GuestDispatchFrame;
use carrick_core::mm::transaction::{CopyoutPreparation, CopyoutRequest, OwnedOperationYield};
use carrick_core_abi::wait::AcceptedWait;
use carrick_el1_abi::IpcLeave;
use carrick_el1_abi::ipc::epoll::{EpollItemRef, EpollReport};
use carrick_el1_abi::ipc::fd::{Error as FdError, Fd, TableId};
use carrick_el1_abi::ipc::pipe::WaitFor;
use carrick_el1_abi::ipc::{
    BackingToken, IpcBacking, IpcCounterDeadline, IpcHandback, IpcObjectHandle, IpcOpKind,
    IpcOpToken, IpcOperation, IpcUserVa, OfdPin, RawIpcObject, RawOfdPin,
};
use carrick_guest_arch::CounterTick;

/// `epoll_pwait` on AArch64 (`epoll_wait` is not in its table).
pub const SYS_EPOLL_PWAIT: usize = 22;

/// Reports one EL1 harvest takes (a stack buffer): fewer than `maxevents`
/// is a valid epoll_wait(2) result.
const BATCH: usize = 32;
/// `struct epoll_event` on AArch64: u32 events, 4 bytes padding, u64 data.
const EVENT_BYTES: usize = 16;
/// Largest `maxevents` Linux accepts (`EP_MAX_EVENTS`).
const EP_MAX_EVENTS: i64 = i32::MAX as i64 / EVENT_BYTES as i64;
/// The kernel `sigset_t` `epoll_pwait` takes (`sigsetsize` must equal it).
const SIGSET_BYTES: usize = 8;

fn epoll_of(backing: BackingToken) -> Option<IpcObjectHandle> {
    match IpcBacking::decode(backing)? {
        IpcBacking::Epoll { object } => Some(object),
        _ => None,
    }
}

/// How long a wait may block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Wait {
    /// Harvest once (a zero timeout, or a deadline already reached).
    Poll,
    /// A negative timeout.
    Forever,
    /// Until this `CNTVCT` value.
    Until(u64),
}

/// A woken, expired or re-entered wait: retire the operation (dropping its
/// pin), then serve the call from its original registers with what is left
/// of its wait.
pub(super) fn resume<E: IpcExecution, M: UserCopy>(
    sched: &mut E,
    frame: &mut E::Frame,
    venue: &IpcVenue<'_>,
    user: &mut M,
    token: IpcOpToken,
    op: IpcOperation,
    interrupt: &mut dyn FnMut() -> bool,
) -> IpcServed {
    let wait = if sched.object_wait_expired() {
        Wait::Poll
    } else {
        op.deadline.get().map_or(Wait::Forever, Wait::Until)
    };
    let record = sched.zone().slot(sched.slot()).current();
    finish(sched, token, &venue.region);
    // A continuation keeps the accepted mask in the control slot, whether it
    // parked on readiness or on the owner's events-buffer preparation. In
    // particular, lost readiness must re-park under that same snapshot.
    let served = serve_with(sched, frame, venue, user, Some(wait), &mut false, interrupt);
    let parked = record.is_some_and(|id| sched.zone().record(id).has_object_operation());
    if !parked || matches!(served, IpcServed::Forward | IpcServed::Handback) {
        user.disarm_wait_sigmask();
    }
    served
}

/// Serve a fresh `epoll_pwait` (see the module docs for what forwards), or
/// the rerun of one that accepted its mask and timeout and then waited for
/// an operation slot (`admit_output`).
pub(super) fn serve<E: IpcExecution, M: UserCopy>(
    sched: &mut E,
    frame: &mut E::Frame,
    venue: &IpcVenue<'_>,
    user: &mut M,
    interrupt: &mut dyn FnMut() -> bool,
) -> IpcServed {
    let (wait, mut armed) = match user.take_accepted_epoll_wait() {
        None => (None, false),
        // The rerun keeps what the call accepted: its mask is still armed,
        // and its timeout ends at the expiry it accepted at entry.
        Some(accepted) => {
            if user.interrupt_pending_wait() || interrupt() {
                // A signal ended the slot wait: EINTR whatever SA_RESTART.
                // The signal checkpoint selects the handler under the
                // accepted mask, then restores the persistent one.
                return returned(frame, carrick_syscall_abi::LINUX_EINTR.guest_retval());
            }
            let wait = accepted
                .deadline
                .map_or(Wait::Forever, |deadline| Wait::Until(deadline.raw()));
            (Some(wait), true)
        }
    };
    let served = serve_with(sched, frame, venue, user, wait, &mut armed, interrupt);
    // A call that ends here restores the mask it armed. One that parked, or
    // whose preparation suspended, handed it to its continuation, which
    // resumes through `resume` (or reruns, after an operation-slot wait) and
    // never reads the mask argument again.
    if armed {
        user.disarm_wait_sigmask();
    }
    served
}

/// `wait`: what is left of a resumed or rerun call's wait (`None`: a fresh
/// call, whose timeout argument starts now). `armed`: set while this call
/// owns restoring the accepted temporary mask; cleared when a continuation
/// takes it over (a resumed call's mask is its continuation's).
fn serve_with<E: IpcExecution, M: UserCopy>(
    sched: &mut E,
    frame: &mut E::Frame,
    venue: &IpcVenue<'_>,
    user: &mut M,
    wait: Option<Wait>,
    armed: &mut bool,
    interrupt: &mut dyn FnMut() -> bool,
) -> IpcServed {
    // epoll_pwait(2) checks the mask argument before the set.
    let sigmask = if wait.is_some() || argument_word(frame, 4) == 0 {
        // Resumption uses the already-armed slot, never user memory again.
        None
    } else if argument_word(frame, 5) != SIGSET_BYTES as u64 {
        return returned(frame, linux::EINVAL);
    } else {
        let mut bytes = [0u8; SIGSET_BYTES];
        if !user.copy_in(&mut bytes, argument_word(frame, 4)) {
            // The host resolves a first touch, or reports EFAULT.
            return leave(sched, IpcLeave::EpollSigmask, IpcServed::Forward);
        }
        Some(u64::from_le_bytes(bytes))
    };
    let maxevents = i64::from(argument_word(frame, 2) as i32);
    if maxevents <= 0 || maxevents > EP_MAX_EVENTS {
        return returned(frame, linux::EINVAL);
    }
    let wait = wait.unwrap_or_else(|| match argument_word(frame, 3) as i32 {
        0 => Wait::Poll,
        ms if ms < 0 => Wait::Forever,
        // Round up by one tick: the wait lasts at least `ms` (epoll_wait(2)).
        ms => Wait::Until(
            sched
                .now()
                .saturating_add(sched.ticks(ms as u64 * 1_000_000))
                .saturating_add(1),
        ),
    });
    let region = &venue.region;
    let (mut op, mut object) = match pin_epoll(sched, frame, venue, wait) {
        Ok(pinned) => pinned,
        Err(served) => return served,
    };
    let buf = argument_word(frame, 1);
    let limit = usize::try_from(maxevents).map_or(BATCH, |n| n.min(BATCH));
    // The owner prepared the events buffer for the last refused copy-out.
    let mut prepared = false;
    loop {
        // Before the harvest: an item queued after it moves this snapshot.
        let wait = match wait {
            Wait::Until(deadline) if sched.now() >= deadline => Wait::Poll,
            wait => wait,
        };
        let snap = if wait == Wait::Poll {
            None
        } else {
            snapshot(sched, object, WaitFor::Readable)
        };
        let mut reports = [EpollReport::default(); BATCH];
        let mut taken = [EpollItemRef::default(); BATCH];
        let harvest = match region.epoll_harvest(
            object,
            &mut reports[..limit],
            &mut taken[..limit],
            &EL1_WAIT,
        ) {
            Ok(harvest) => harvest,
            Err(_) => {
                release_pin(sched, OfdPin::from_raw(op.pin), region);
                return leave(sched, IpcLeave::ObjectBusy, IpcServed::Forward);
            }
        };
        let taken = &taken[..harvest.reported];
        if harvest.host_items != 0 {
            // Only the host harvests a mixed set: put the zone reports back.
            let _ = region.epoll_restore(object, taken, &Finish);
            release_pin(sched, OfdPin::from_raw(op.pin), region);
            return leave(sched, IpcLeave::EpollHostItems, IpcServed::Forward);
        }
        if harvest.reported > 0 {
            let mut bytes = [0u8; BATCH * EVENT_BYTES];
            for (event, report) in bytes
                .chunks_exact_mut(EVENT_BYTES)
                .zip(&reports[..harvest.reported])
            {
                event[..4].copy_from_slice(&report.events.to_ne_bytes());
                event[8..].copy_from_slice(&report.data.to_ne_bytes());
            }
            if !user.copy_out(buf, &bytes[..harvest.reported * EVENT_BYTES]) {
                // Not delivered: queue the items again, so a later harvest
                // reports them exactly once (Linux re-queues on a failed copy).
                let _ = region.epoll_restore(object, taken, &Finish);
                let Some(request) = user.take_copyout_refusal() else {
                    // No native owner retains this caller's memory: the
                    // host-owned lane resolves the fault and reports them.
                    release_pin(sched, OfdPin::from_raw(op.pin), region);
                    return leave(sched, IpcLeave::EpollCopyOut, IpcServed::Forward);
                };
                if wait == Wait::Poll {
                    // A resumed operation keeps a reached deadline: it harvests once.
                    op.deadline = IpcCounterDeadline::at(sched.now());
                }
                // The accepted mask covers the preparation and any wait for
                // its operation slot: a suspended preparation resumes through
                // `resume`, and a slot wait reruns, and neither reads the
                // mask argument again.
                if let Some(mask) = sigmask
                    && !*armed
                {
                    if !user.arm_wait_sigmask(mask) {
                        release_pin(sched, OfdPin::from_raw(op.pin), region);
                        return leave(sched, IpcLeave::EpollSigmask, IpcServed::Forward);
                    }
                    *armed = true;
                }
                let token = match admit_output(sched, frame, venue, user, op, armed, interrupt) {
                    Admitted::Operation(token) => token,
                    Admitted::Parked(served) => return served,
                    Admitted::Rerun => {
                        (op, object) = match pin_epoll(sched, frame, venue, wait) {
                            Ok(pinned) => pinned,
                            Err(served) => return served,
                        };
                        prepared = false;
                        continue;
                    }
                };
                match prepare_output(sched, frame, region, user, token, request, prepared) {
                    Output::Rerun(back, ready) => {
                        op = back;
                        prepared = ready;
                        continue;
                    }
                    Output::Done(served) => return served,
                    Output::Retained(served) => {
                        *armed = false;
                        return served;
                    }
                }
            }
            release_pin(sched, OfdPin::from_raw(op.pin), region);
            return returned(frame, harvest.reported as i64);
        }
        let deadline = match wait {
            Wait::Poll => {
                release_pin(sched, OfdPin::from_raw(op.pin), region);
                return returned(frame, 0);
            }
            Wait::Forever => None,
            Wait::Until(_) if !sched.may_time_park() => {
                // Another timed park owns the slot's timer: the host waits
                // with the deadline (nothing was taken).
                release_pin(sched, OfdPin::from_raw(op.pin), region);
                return leave(sched, IpcLeave::EpollTimedWait, IpcServed::Forward);
            }
            Wait::Until(deadline) => Some(deadline),
        };
        let Some(snap) = snap else {
            release_pin(sched, OfdPin::from_raw(op.pin), region);
            return leave(sched, IpcLeave::ParkRefused, IpcServed::Forward);
        };
        // Armed before the park, whose post-enrollment probe must already see
        // the temporary mask.
        if let Some(mask) = sigmask
            && !*armed
        {
            if !user.arm_wait_sigmask(mask) {
                release_pin(sched, OfdPin::from_raw(op.pin), region);
                return leave(sched, IpcLeave::EpollSigmask, IpcServed::Forward);
            }
            *armed = true;
        }
        let token = match region.begin_operation(op) {
            Ok(token) => token,
            Err(_) => {
                disarm(user, armed);
                release_pin(sched, OfdPin::from_raw(op.pin), region);
                return leave(sched, IpcLeave::NoOperationRecord, IpcServed::Forward);
            }
        };
        match park(
            sched,
            frame,
            region,
            token,
            op,
            object,
            WaitFor::Readable,
            snap,
            deadline,
            &mut || user.interrupt_pending_wait() || interrupt(),
        ) {
            Parked::Done(served) => {
                *armed = false;
                return served;
            }
            // Readiness moved before the park: retire the record (the pin
            // stays with `op`) and harvest again, still under the mask.
            Parked::Retry(token) => {
                match region.finish_operation(token, || {
                    notify_operation_release(region, sched.zone(), sched.slot())
                }) {
                    Ok(back) => op = back,
                    Err(_) => return leave(sched, IpcLeave::StaleOperation, IpcServed::Forward),
                }
            }
            Parked::Refused(token) => {
                disarm(user, armed);
                finish(sched, token, region);
                return leave(sched, IpcLeave::ParkRefused, IpcServed::Forward);
            }
        }
    }
}

/// Pin the call's epoll description for one pass (`Err`: how the call was
/// served instead). The operation carries the pin and a finite deadline.
fn pin_epoll<E: IpcExecution>(
    sched: &mut E,
    frame: &mut E::Frame,
    venue: &IpcVenue<'_>,
    wait: Wait,
) -> Result<(IpcOperation, IpcObjectHandle), IpcServed> {
    let task = sched.task();
    let region = &venue.region;
    let Some(table) = venue.tables.table_of(task) else {
        return Err(leave(sched, IpcLeave::NoTable, IpcServed::Forward));
    };
    let table = TableId::from_raw(table);
    let fd = Fd(argument_word(frame, 0) as i32);
    let fda = region.fd(EL1_WAIT);
    match fda.get(table, fd) {
        Ok(snapshot) if epoll_of(snapshot.backing).is_some() => {}
        // Not a zone epoll (EINVAL, or a host-backed epoll): the host.
        Ok(_) => return Err(leave(sched, IpcLeave::EpollNotZone, IpcServed::Forward)),
        Err(FdError::BadFd) => return Err(returned(frame, linux::EBADF)),
        Err(FdError::Contended) => {
            return Err(leave(sched, IpcLeave::TableContended, IpcServed::Forward));
        }
        Err(_) => return Err(leave(sched, IpcLeave::TableRefused, IpcServed::Forward)),
    }
    let operation = |pin: RawOfdPin, object: RawIpcObject| IpcOperation {
        kind: IpcOpKind::EpollWait,
        pin,
        object,
        task: task_key(task),
        mm: mm_key(task),
        buf: IpcUserVa(argument_word(frame, 1)),
        orig_x0: argument_word(frame, 0),
        nr: SYS_EPOLL_PWAIT as u32,
        ..IpcOperation::EMPTY
    };
    let (pin, desc) = match fda.pin(table, fd) {
        Ok(found) => found,
        Err(FdError::BadFd) => return Err(returned(frame, linux::EBADF)),
        Err(FdError::Contended) => {
            return Err(leave(sched, IpcLeave::PinContended, IpcServed::Forward));
        }
        // A pin on a reused record the fd did not name: the host drops it
        // (possibly a final release EL1 cannot perform) and runs the call.
        Err(FdError::PinRaced(raw)) => {
            return Err(restart(
                sched,
                frame,
                venue,
                operation(raw, RawIpcObject::default()),
            ));
        }
        Err(_) => return Err(leave(sched, IpcLeave::PinRefused, IpcServed::Forward)),
    };
    let Some(object) = epoll_of(desc.backing) else {
        // Replaced since the snapshot by a description EL1 does not serve.
        return Err(restart(
            sched,
            frame,
            venue,
            operation(pin.into_raw(), RawIpcObject::default()),
        ));
    };
    let mut op = operation(pin.into_raw(), object.to_raw());
    if let Wait::Until(deadline) = wait {
        op.deadline = IpcCounterDeadline::at(deadline);
    }
    Ok((op, object))
}

/// A temporary mask this call armed is restored when it leaves without a
/// continuation.
fn disarm<M: UserCopy>(user: &mut M, armed: &mut bool) {
    if core::mem::take(armed) {
        user.disarm_wait_sigmask();
    }
}

/// How a refused copy-out's preparation was admitted to the operation arena.
enum Admitted {
    /// The `EpollWait` record the preparation retains (with the pin).
    Operation(IpcOpToken),
    /// Parked on the arena's slot release with the pin dropped: the thread
    /// replays the call when a slot returns.
    Parked(IpcServed),
    /// A slot returned before the park: pin and harvest again now.
    Rerun,
}

/// Admit a refused copy-out's preparation as its `EpollWait` record. A full
/// arena is contention, "not now": never a forward or an errno. No record
/// holds the call yet (the items are queued again), so the pin is dropped
/// and the thread parks on the arena's slot release (`admit_operation_wait`,
/// the source every retirement publishes to) with a replay receipt that
/// owns nothing; the scheduler re-runs the call once a slot returns.
///
/// The call stays accepted across that wait (epoll_pwait(2) reads its mask
/// once, and its timeout runs from the call's start). Its mask, armed by the
/// caller, stays armed, so a signal it blocks cannot end the wait; the
/// operation's absolute expiry is retained by the native owner for the
/// rerun ([`serve`]), which reads neither argument again. A signal the mask
/// does not block ends the wait, and the rerun returns EINTR.
fn admit_output<E: IpcExecution, M: UserCopy>(
    sched: &mut E,
    frame: &mut E::Frame,
    venue: &IpcVenue<'_>,
    user: &mut M,
    op: IpcOperation,
    armed: &mut bool,
    interrupt: &mut dyn FnMut() -> bool,
) -> Admitted {
    use carrick_sched_core::object_wait::{ObjectStateSnapshot, ObjectWaitError, OperationToken};
    use carrick_sched_core::refusal::Refusal;
    let region = &venue.region;
    let replay = OperationToken::metadata_request(region.operation_slot_generation().get())
        .unwrap_or_else(invalid);
    let (replay, key, observed) = {
        let zone = sched.zone();
        let slot = sched.slot();
        let completion =
            |owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_, E::Context>| {
                crate::sched::object_wait::deliver_completion(zone, slot, owned)
            };
        match super::admit_operation_wait(region, zone, op, &completion).result {
            Ok(token) => return Admitted::Operation(token),
            // SAFETY: the enrollment's key and its observation (sampled
            // before the failed arena probe) go straight to this lane's
            // scheduler park below, which revalidates that exact epoch and
            // either retains the receipt on the slot queue or returns it for
            // an immediate rerun. No guard crosses the park.
            Err(Refusal::Contended(ticket)) => unsafe {
                ticket.park_and_rerun(replay, |replay, enrollment| {
                    (replay, enrollment.key(), enrollment.observed())
                })
            },
            Err(Refusal::Invariant(_) | Refusal::Guest(_)) => invalid(),
        }
    };
    release_pin(sched, OfdPin::from_raw(op.pin), region);
    // Retained before the park: once parked, the rerun may begin on another
    // vCPU. A refused copy-out was recorded only for a native owner.
    let accepted = AcceptedWait {
        deadline: op.deadline.get().map(CounterTick::new),
    };
    if !user.retain_accepted_epoll_wait(accepted) {
        invalid::<()>();
    }
    // SAFETY: observed before the arena probe that found no free slot.
    let snapshot = unsafe { ObjectStateSnapshot::before_object_probe(observed) };
    match sched.park(
        frame,
        key,
        snapshot,
        replay,
        None,
        Some(&mut || user.interrupt_pending_wait() || interrupt()),
    ) {
        // The rerun owns the armed mask now.
        Ok(served) => {
            *armed = false;
            Admitted::Parked(served)
        }
        // This pass keeps both: the call harvests again at once.
        Err((ObjectWaitError::Changed, _)) => {
            let _ = user.take_accepted_epoll_wait();
            Admitted::Rerun
        }
        Err(_) => invalid(),
    }
}

/// How an events buffer the ring's copy refused was settled.
enum Output {
    /// Harvest again with this operation (its pin kept); `true` when the
    /// owner prepared the buffer, so the next copy must succeed.
    Rerun(IpcOperation, bool),
    /// The call ended.
    Done(IpcServed),
    /// The call's operation is retained (parked on the owner, or suspended
    /// in the owner's service) and resumes through [`resume`].
    Retained(IpcServed),
}

/// Settle a refused events copy-out through the native owner's exact-MM
/// output preparation, the one the ring pipe read uses (`run`): a first
/// touch is supplied (or waited for) and the call harvests again; only a
/// buffer the owner faults is EFAULT. The harvested items are already
/// queued again, and the call is retained as its `EpollWait` operation
/// while the owner prepares, so a suspended call resumes through
/// [`resume`] and harvests afresh.
fn prepare_output<E: IpcExecution, M: UserCopy>(
    sched: &mut E,
    frame: &mut E::Frame,
    region: &IpcRegion<'_>,
    user: &mut M,
    token: IpcOpToken,
    request: CopyoutRequest,
    prepared: bool,
) -> Output {
    let operation = to_sched_token(token).unwrap_or_else(|_| invalid());
    // One preparation may retry the hardware copy once. A refusal right
    // after the owner reported the buffer ready has no errno authority.
    let preparation = if prepared {
        CopyoutPreparation::Unrouted(operation)
    } else {
        user.prepare_copyout(request, operation)
    };
    let ipc_token = |operation| from_sched_token(operation).unwrap_or_else(invalid);
    let rerun = |sched: &mut E, token, ready| match region.finish_operation(token, || {
        notify_operation_release(region, sched.zone(), sched.slot())
    }) {
        Ok(op) => Output::Rerun(op, ready),
        Err(_) => invalid(),
    };
    match preparation {
        CopyoutPreparation::Ready(operation) => rerun(sched, ipc_token(operation), true),
        CopyoutPreparation::Fault(operation) => {
            finish(sched, ipc_token(operation), region);
            Output::Done(returned(
                frame,
                carrick_syscall_abi::LINUX_EFAULT.guest_retval(),
            ))
        }
        CopyoutPreparation::Wait { operation, wait } => {
            if wait.handle().mm().raw() != mm_key(sched.task()).0 {
                invalid::<()>();
            }
            match park_result(sched.park_owner(frame, wait, operation)) {
                Parked::Done(served) => Output::Retained(served),
                Parked::Retry(token) => rerun(sched, token, false),
                Parked::Refused(_) => invalid(),
            }
        }
        // Contention is not now: yield the same operation through its
        // carrier-work owner; it resumes and harvests again.
        CopyoutPreparation::Busy(operation) => match user.yield_owned_operation(operation) {
            OwnedOperationYield::Ready(operation) => rerun(sched, ipc_token(operation), false),
            OwnedOperationYield::Suspended => Output::Retained(IpcServed::Idle),
            OwnedOperationYield::Complete(result) => Output::Done(returned(frame, result)),
            OwnedOperationYield::Unrouted(_) => invalid(),
        },
        CopyoutPreparation::Unrouted(operation) => {
            // Stale or quarantined execution keeps terminal custody.
            retain_native_operation(sched, ipc_token(operation));
            invalid()
        }
        CopyoutPreparation::Complete(result) => Output::Done(returned(frame, result)),
        CopyoutPreparation::Suspended => Output::Retained(IpcServed::Idle),
    }
}

/// A broken custody invariant: fail the run.
fn invalid<T>() -> T {
    crate::dispatch::invalid_completion(crate::dispatch::NativeInvariant::EntryBinding)
}

fn returned(frame: &mut impl GuestDispatchFrame, result: i64) -> IpcServed {
    set_result(frame, result as u64);
    IpcServed::Returned { switched: false }
}

/// No effect was taken but the pin is not one EL1 may drop: the host drops
/// it and runs the original call.
fn restart<E: IpcExecution>(
    sched: &mut E,
    frame: &mut E::Frame,
    venue: &IpcVenue<'_>,
    op: IpcOperation,
) -> IpcServed {
    match venue.region.begin_operation(op) {
        Ok(token) => {
            let served = super::handback(sched, frame, token, op, IpcHandback::Restart, 0, venue);
            leave(sched, IpcLeave::Restart, served)
        }
        Err(_) => {
            release_pin(sched, OfdPin::from_raw(op.pin), &venue.region);
            leave(sched, IpcLeave::NoOperationRecord, IpcServed::Forward)
        }
    }
}
