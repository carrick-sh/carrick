//! A one-description `poll(2)` wait on a native IPC object.
//!
//! Native-fork children have no host descriptor table to wait on. Their
//! inherited pipe/eventfd descriptions therefore enroll on the object's EL1
//! wait queue, retaining the exact open description until readiness or the
//! deadline wins. Multi-description polling remains with the carrier until a
//! multi-object continuation owns all of its enrollments.

use super::{
    EL1_WAIT, IpcServed, IpcVenue, Parked, Sched, ThreadCpu, UserCopy, UserWord, finish, handback,
    leave, mm_key, park, release_pin, snapshot, task_key,
};
use crate::file_table::PollFd;
use carrick_el1_abi::IpcLeave;
use carrick_el1_abi::TrapFrame;
use carrick_el1_abi::ipc::fd::{Error as FdError, Fd, TableId};
use carrick_el1_abi::ipc::pipe::WaitFor;
use carrick_el1_abi::ipc::{
    End, IpcBacking, IpcCounterDeadline, IpcHandback, IpcObjectHandle, IpcOpKind, IpcOperation,
    IpcUserVa, OfdPin, RawIpcObject, RawOfdPin,
};

const POLLIN: i16 = 0x0001;
const POLLOUT: i16 = 0x0004;
const POLLERR: i16 = 0x0008;
const POLLHUP: i16 = 0x0010;
const POLLNVAL: i16 = 0x0020;

#[derive(Clone, Copy)]
enum NativeObject {
    Pipe(IpcObjectHandle, End),
    EventFd(IpcObjectHandle),
}

impl NativeObject {
    fn decode(backing: carrick_el1_abi::ipc::BackingToken) -> Option<Self> {
        match IpcBacking::decode(backing)? {
            IpcBacking::Pipe { object, end } => Some(Self::Pipe(object, end)),
            IpcBacking::EventFd { object } => Some(Self::EventFd(object)),
            IpcBacking::Host(_) | IpcBacking::Epoll { .. } => None,
        }
    }

    fn object(self) -> IpcObjectHandle {
        match self {
            Self::Pipe(object, _) | Self::EventFd(object) => object,
        }
    }

    fn lane(self, events: i16) -> WaitFor {
        match self {
            Self::Pipe(_, End::Reader) => WaitFor::Readable,
            Self::Pipe(_, End::Writer) => WaitFor::Writable,
            Self::EventFd(_) if events & POLLIN != 0 => WaitFor::Readable,
            Self::EventFd(_) => WaitFor::Writable,
        }
    }
}

#[derive(Clone, Copy)]
enum Wait {
    Poll,
    Forever,
    Until(u64),
}

/// Serve a single native pipe/eventfd entry. `None` means this call did not
/// have the shape this adapter owns and is unchanged for another venue.
pub fn serve_one<C: ThreadCpu, U: UserWord, M: UserCopy>(
    sched: &mut Sched<'_, C, U>,
    frame: &mut TrapFrame,
    venue: &IpcVenue<'_>,
    user: &mut M,
    pollfd: &mut PollFd,
    user_va: u64,
    timeout_ms: i32,
) -> Option<IpcServed> {
    let task = sched.task;
    let table = TableId::from_raw(venue.tables.owned_table_of(task)?);
    let region = &venue.region;
    let resumed = match sched.take_object_operation() {
        Ok(Some(token)) => {
            let Some(token) = carrick_el1::substrate::ipc::from_sched_token(token) else {
                return Some(leave(sched, IpcLeave::StaleOperation, IpcServed::Forward));
            };
            let Ok(op) = region.operation(&token) else {
                return Some(leave(sched, IpcLeave::StaleOperation, IpcServed::Forward));
            };
            if op.kind != IpcOpKind::PollWait
                || op.task != task_key(task)
                || op.mm != mm_key(task)
                || op.buf.0 != user_va
                || op.progress.len != pollfd.fd as u64
            {
                finish(sched, token, region);
                return Some(leave(sched, IpcLeave::StaleOperation, IpcServed::Forward));
            }
            let wait = if sched.object_wait_expired() {
                Wait::Poll
            } else {
                op.deadline.get().map_or(Wait::Forever, Wait::Until)
            };
            finish(sched, token, region);
            Some(wait)
        }
        Ok(None) => None,
        Err(_) => return None,
    };

    let wait = resumed.unwrap_or_else(|| match timeout_ms {
        0 => Wait::Poll,
        ms if ms < 0 => Wait::Forever,
        ms => Wait::Until(
            sched
                .cpu
                .now()
                .saturating_add(sched.ticks(ms as u64 * 1_000_000))
                .saturating_add(1),
        ),
    });
    let fda = region.fd(EL1_WAIT);
    let operation = |pin: RawOfdPin, object: RawIpcObject| IpcOperation {
        kind: IpcOpKind::PollWait,
        pin,
        object,
        task: task_key(task),
        mm: mm_key(task),
        buf: IpcUserVa(user_va),
        progress: carrick_el1_abi::ipc::WriteProgress {
            len: pollfd.fd as u64,
            written: 0,
        },
        orig_x0: frame.x[0],
        nr: frame.x[8] as u32,
        ..IpcOperation::EMPTY
    };
    let (pin, desc) = match fda.pin(table, Fd(pollfd.fd)) {
        Ok(found) => found,
        Err(FdError::BadFd) => {
            pollfd.revents = POLLNVAL;
            return Some(complete(frame, user, pollfd, user_va, 1));
        }
        Err(FdError::Contended) => {
            return Some(leave(sched, IpcLeave::PinContended, IpcServed::Forward));
        }
        Err(FdError::PinRaced(raw)) => {
            let op = operation(raw, RawIpcObject::default());
            return Some(restart(sched, frame, venue, op));
        }
        Err(_) => return Some(leave(sched, IpcLeave::PinRefused, IpcServed::Forward)),
    };
    let Some(native) = NativeObject::decode(desc.backing) else {
        let op = operation(pin.into_raw(), RawIpcObject::default());
        return Some(restart(sched, frame, venue, op));
    };
    let object = native.object();
    let lane = native.lane(pollfd.events);
    let mut op = operation(pin.into_raw(), object.to_raw());
    if let Wait::Until(deadline) = wait {
        op.deadline = IpcCounterDeadline::at(deadline);
    }

    loop {
        let wait = match wait {
            Wait::Until(deadline) if sched.cpu.now() >= deadline => Wait::Poll,
            other => other,
        };
        let snap = if matches!(wait, Wait::Poll) {
            None
        } else {
            snapshot(sched, object, lane)
        };
        let revents = match readiness(region, native, pollfd.events) {
            Ok(bits) => bits,
            Err(()) => {
                release_pin(sched, OfdPin::from_raw(op.pin), region);
                return Some(leave(sched, IpcLeave::ObjectBusy, IpcServed::Forward));
            }
        };
        if revents != 0 {
            release_pin(sched, OfdPin::from_raw(op.pin), region);
            pollfd.revents = revents;
            return Some(complete(frame, user, pollfd, user_va, 1));
        }
        let deadline = match wait {
            Wait::Poll => {
                release_pin(sched, OfdPin::from_raw(op.pin), region);
                pollfd.revents = 0;
                return Some(complete(frame, user, pollfd, user_va, 0));
            }
            Wait::Forever => None,
            Wait::Until(_) if !sched.may_time_park() => {
                release_pin(sched, OfdPin::from_raw(op.pin), region);
                return Some(leave(sched, IpcLeave::EpollTimedWait, IpcServed::Forward));
            }
            Wait::Until(deadline) => Some(deadline),
        };
        let Some(snap) = snap else {
            release_pin(sched, OfdPin::from_raw(op.pin), region);
            return Some(leave(sched, IpcLeave::ParkRefused, IpcServed::Forward));
        };
        let token = match region.begin_operation(op) {
            Ok(token) => token,
            Err(_) => {
                release_pin(sched, OfdPin::from_raw(op.pin), region);
                return Some(leave(
                    sched,
                    IpcLeave::NoOperationRecord,
                    IpcServed::Forward,
                ));
            }
        };
        match park(
            sched, frame, region, token, op, object, lane, snap, deadline,
        ) {
            Parked::Done(served) => return Some(served),
            Parked::Retry(token) => match region.finish_operation(token) {
                Ok(back) => op = back,
                Err(_) => {
                    return Some(leave(sched, IpcLeave::StaleOperation, IpcServed::Forward));
                }
            },
            Parked::Refused(token) => {
                finish(sched, token, region);
                return Some(leave(sched, IpcLeave::ParkRefused, IpcServed::Forward));
            }
        }
    }
}

fn restart<C: ThreadCpu, U: UserWord>(
    sched: &mut Sched<'_, C, U>,
    frame: &mut TrapFrame,
    venue: &IpcVenue<'_>,
    op: IpcOperation,
) -> IpcServed {
    match venue.region.begin_operation(op) {
        Ok(token) => leave(
            sched,
            IpcLeave::Restart,
            handback(frame, token, op, IpcHandback::Restart, 0, venue),
        ),
        Err(_) => {
            release_pin(sched, OfdPin::from_raw(op.pin), &venue.region);
            leave(sched, IpcLeave::NoOperationRecord, IpcServed::Forward)
        }
    }
}

fn readiness(
    region: &carrick_el1_abi::ipc::IpcRegion<'_>,
    native: NativeObject,
    events: i16,
) -> Result<i16, ()> {
    let mut guard = region.lock(native.object(), &EL1_WAIT).map_err(|_| ())?;
    let ready = match native {
        NativeObject::Pipe(_, end) => guard.pipe().map_err(|_| ())?.readiness(end),
        NativeObject::EventFd(_) => guard.eventfd().map_err(|_| ())?.readiness(),
    };
    let mut revents = 0;
    if ready.readable && events & POLLIN != 0 {
        revents |= POLLIN;
    }
    if ready.writable && events & POLLOUT != 0 {
        revents |= POLLOUT;
    }
    if ready.err {
        revents |= POLLERR;
    }
    if ready.hup {
        revents |= POLLHUP;
    }
    Ok(revents)
}

fn complete<M: UserCopy>(
    frame: &mut TrapFrame,
    user: &mut M,
    pollfd: &PollFd,
    user_va: u64,
    result: i64,
) -> IpcServed {
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (pollfd as *const PollFd).cast::<u8>(),
            core::mem::size_of::<PollFd>(),
        )
    };
    frame.x[0] = if user.copy_out(user_va, bytes) {
        result as u64
    } else {
        carrick_syscall_abi::LINUX_EFAULT.guest_retval() as u64
    };
    IpcServed::Returned { switched: false }
}
