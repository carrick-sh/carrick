//! Linux epoll_pwait(2) on a zone epoll, served in EL1 (contract
//! `kernel.el1.epoll-zone`).
//!
//! The set's zone half lives in the shared record
//! (`carrick_el1_abi::ipc::epoll`); EL1 runs the same harvest routine the
//! host does. EL1 serves a wait only when the set has no host-half items and
//! no signal mask is passed; everything else is forwarded unchanged, before
//! any effect:
//!
//! - a non-NULL sigmask (the host swaps the mask around its wait);
//! - host-half items (only the host harvests both halves);
//! - a finite timeout with nothing ready while another thread's timed
//!   park holds the slot's timer (a slot's timer has one owner);
//! - a buffer the reports cannot be copied to (the harvested items are put
//!   back first, so the host's harvest reports them again).
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
    EL1_WAIT, Finish, IpcServed, IpcVenue, Parked, Sched, ThreadCpu, UserCopy, UserWord, finish,
    leave, linux, mm_key, park, release_pin, snapshot, task_key,
};
use carrick_el1_abi::IpcLeave;
use carrick_el1_abi::TrapFrame;
use carrick_el1_abi::ipc::epoll::{EpollItemRef, EpollReport};
use carrick_el1_abi::ipc::fd::{Error as FdError, Fd, TableId};
use carrick_el1_abi::ipc::pipe::WaitFor;
use carrick_el1_abi::ipc::{
    BackingToken, IpcBacking, IpcCounterDeadline, IpcHandback, IpcObjectHandle, IpcOpKind,
    IpcOpToken, IpcOperation, IpcUserVa, OfdPin, RawIpcObject, RawOfdPin,
};

/// `epoll_pwait` on AArch64 (`epoll_wait` is not in its table).
pub const SYS_EPOLL_PWAIT: usize = 22;

/// Reports one EL1 harvest takes (a stack buffer): fewer than `maxevents`
/// is a valid epoll_wait(2) result.
const BATCH: usize = 32;
/// `struct epoll_event` on AArch64: u32 events, 4 bytes padding, u64 data.
const EVENT_BYTES: usize = 16;
/// Largest `maxevents` Linux accepts (`EP_MAX_EVENTS`).
const EP_MAX_EVENTS: i64 = i32::MAX as i64 / EVENT_BYTES as i64;

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
pub(super) fn resume<C: ThreadCpu, U: UserWord, M: UserCopy>(
    sched: &mut Sched<'_, C, U>,
    frame: &mut TrapFrame,
    venue: &IpcVenue<'_>,
    user: &mut M,
    token: IpcOpToken,
    op: IpcOperation,
) -> IpcServed {
    let wait = if sched.object_wait_expired() {
        Wait::Poll
    } else {
        op.deadline.get().map_or(Wait::Forever, Wait::Until)
    };
    finish(sched, token, &venue.region);
    serve_with(sched, frame, venue, user, Some(wait))
}

/// Serve a fresh `epoll_pwait` (see the module docs for what forwards).
pub(super) fn serve<C: ThreadCpu, U: UserWord, M: UserCopy>(
    sched: &mut Sched<'_, C, U>,
    frame: &mut TrapFrame,
    venue: &IpcVenue<'_>,
    user: &mut M,
) -> IpcServed {
    serve_with(sched, frame, venue, user, None)
}

/// `wait`: what is left of a resumed call's wait (`None`: a fresh call,
/// whose timeout argument starts now).
fn serve_with<C: ThreadCpu, U: UserWord, M: UserCopy>(
    sched: &mut Sched<'_, C, U>,
    frame: &mut TrapFrame,
    venue: &IpcVenue<'_>,
    user: &mut M,
    wait: Option<Wait>,
) -> IpcServed {
    if frame.x[4] != 0 {
        return leave(sched, IpcLeave::EpollSigmask, IpcServed::Forward);
    }
    let maxevents = i64::from(frame.x[2] as i32);
    if maxevents <= 0 || maxevents > EP_MAX_EVENTS {
        // EINVAL, from the host's full validation.
        return IpcServed::Forward;
    }
    let wait = wait.unwrap_or_else(|| match frame.x[3] as i32 {
        0 => Wait::Poll,
        ms if ms < 0 => Wait::Forever,
        // Round up by one tick: the wait lasts at least `ms` (epoll_wait(2)).
        ms => Wait::Until(
            sched
                .cpu
                .now()
                .saturating_add(sched.ticks(ms as u64 * 1_000_000))
                .saturating_add(1),
        ),
    });
    let task = sched.task;
    let region = &venue.region;
    let Some(table) = venue.tables.table_of(task) else {
        return leave(sched, IpcLeave::NoTable, IpcServed::Forward);
    };
    let table = TableId::from_raw(table);
    let fd = Fd(frame.x[0] as i32);
    let fda = region.fd(EL1_WAIT);
    match fda.get(table, fd) {
        Ok(snapshot) if epoll_of(snapshot.backing).is_some() => {}
        // Not a zone epoll (EINVAL, or a host-backed epoll): the host.
        Ok(_) => return IpcServed::Forward,
        Err(FdError::BadFd) => return returned(frame, linux::EBADF),
        Err(FdError::Contended) => {
            return leave(sched, IpcLeave::TableContended, IpcServed::Forward);
        }
        Err(_) => return leave(sched, IpcLeave::TableRefused, IpcServed::Forward),
    }
    let operation = |pin: RawOfdPin, object: RawIpcObject| IpcOperation {
        kind: IpcOpKind::EpollWait,
        pin,
        object,
        task: task_key(task),
        mm: mm_key(task),
        buf: IpcUserVa(frame.x[1]),
        orig_x0: frame.x[0],
        nr: SYS_EPOLL_PWAIT as u32,
        ..IpcOperation::EMPTY
    };
    let (pin, desc) = match fda.pin(table, fd) {
        Ok(found) => found,
        Err(FdError::BadFd) => return returned(frame, linux::EBADF),
        Err(FdError::Contended) => {
            return leave(sched, IpcLeave::PinContended, IpcServed::Forward);
        }
        // A pin on a reused record the fd did not name: the host drops it
        // (possibly a final release EL1 cannot perform) and runs the call.
        Err(FdError::PinRaced(raw)) => {
            return restart(sched, frame, venue, operation(raw, RawIpcObject::default()));
        }
        Err(_) => return leave(sched, IpcLeave::PinRefused, IpcServed::Forward),
    };
    let Some(object) = epoll_of(desc.backing) else {
        // Replaced since the snapshot by a description EL1 does not serve.
        return restart(
            sched,
            frame,
            venue,
            operation(pin.into_raw(), RawIpcObject::default()),
        );
    };
    let mut op = operation(pin.into_raw(), object.to_raw());
    if let Wait::Until(deadline) = wait {
        op.deadline = IpcCounterDeadline::at(deadline);
    }
    let buf = frame.x[1];
    let limit = usize::try_from(maxevents).map_or(BATCH, |n| n.min(BATCH));
    loop {
        // Before the harvest: an item queued after it moves this snapshot.
        let wait = match wait {
            Wait::Until(deadline) if sched.cpu.now() >= deadline => Wait::Poll,
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
                // Not delivered: queue the items again; the host resolves the
                // fault (first touch, or EFAULT) and reports them.
                let _ = region.epoll_restore(object, taken, &Finish);
                release_pin(sched, OfdPin::from_raw(op.pin), region);
                return leave(sched, IpcLeave::EpollCopyOut, IpcServed::Forward);
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
        let token = match region.begin_operation(op) {
            Ok(token) => token,
            Err(_) => {
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
        ) {
            Parked::Done(served) => return served,
            // Readiness moved before the park: retire the record (the pin
            // stays with `op`) and harvest again.
            Parked::Retry(token) => match region.finish_operation(token) {
                Ok(back) => op = back,
                Err(_) => return leave(sched, IpcLeave::StaleOperation, IpcServed::Forward),
            },
            Parked::Refused(token) => {
                finish(sched, token, region);
                return leave(sched, IpcLeave::ParkRefused, IpcServed::Forward);
            }
        }
    }
}

fn returned(frame: &mut TrapFrame, result: i64) -> IpcServed {
    frame.x[0] = result as u64;
    IpcServed::Returned { switched: false }
}

/// No effect was taken but the pin is not one EL1 may drop: the host drops
/// it and runs the original call.
fn restart<C: ThreadCpu, U: UserWord>(
    sched: &mut Sched<'_, C, U>,
    frame: &mut TrapFrame,
    venue: &IpcVenue<'_>,
    op: IpcOperation,
) -> IpcServed {
    match venue.region.begin_operation(op) {
        Ok(token) => {
            let served = super::handback(frame, token, op, IpcHandback::Restart, 0, venue);
            leave(sched, IpcLeave::Restart, served)
        }
        Err(_) => {
            release_pin(sched, OfdPin::from_raw(op.pin), &venue.region);
            leave(sched, IpcLeave::NoOperationRecord, IpcServed::Forward)
        }
    }
}
