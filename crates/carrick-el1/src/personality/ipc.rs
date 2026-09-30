//! Linux read(2)/write(2) on pipes and eventfds served in EL1, on the shared
//! IPC objects (`carrick_el1_abi::ipc`) the host creates and manages.
//!
//! Decoding (descriptor access, O_NONBLOCK, buffer sizes) and Linux results
//! (EOF, EAGAIN, EBADF, EINVAL, EPIPE + SIGPIPE) live here; the staged copy
//! and object mechanics are neutral (`substrate::ipc`), and blocking uses the
//! scheduler's object waits.
//!
//! # One operation, one owner
//!
//! A served call pins its exact open description (a brief table lock), then
//! records itself as an [`IpcOperation`] behind an owned [`IpcOpToken`]
//! before any effect. Each attempt locks one object, runs one staged step
//! (only delivered bytes are consumed or published), publishes readiness and
//! notifies the lane's waiters under the object lock, then unlocks and sends
//! SGIs. A blocking call parks with the token and the SVC instruction as its
//! resumption entry; on wake the thread re-enters the SVC with its original
//! registers and this adapter takes the token BEFORE any fd lookup, so a
//! closed or reused descriptor number never redirects it and no byte is
//! replayed. A final description release found on completion is performed
//! here (the object lock is only ever held for short sections, so EL1 waits
//! for it), waking the peer lane.
//!
//! # Leaving EL1
//!
//! - An unchanged `Forward` happens only before any effect of a call that
//!   never parked (host-backed descriptions, unpublished tables, contended
//!   locks, a first copy that faults, EPIPE with no progress).
//! - A call that would block parks in the zone even with host work pending
//!   on the vCPU; the vCPU then leaves at once (`Idle`) so the host settles
//!   the parked thread, delivering a pending signal to it there.
//! - After progress, or for any resumed operation, EL1 never forwards the
//!   original call. It completes it, or hands the owned operation to the host
//!   with an [`IPC_HANDBACK_NR`] frame: `x0` holds the packed raw token, every
//!   other argument register is untouched, and the record says what to do
//!   ([`IpcHandback`]) and carries the original `x0` and syscall number.

use super::sched::{Sched, Served, ThreadCpu, UserWord};
use crate::substrate::file::UserCopy;
use crate::substrate::ipc::{
    PrefixCopy, StepStatus, from_sched_token, to_sched_token, transfer, wait_key,
};
use crate::substrate::sched::object_wait::OperationResumePc;
pub use carrick_el1_abi::ipc::IPC_HANDBACK_NR;
use carrick_el1_abi::ipc::fd::{AccessMode, Error as FdError, Fd, TableId};
use carrick_el1_abi::ipc::pipe::{WaitFor, WakeSet};
use carrick_el1_abi::ipc::{
    IpcBacking, IpcEventValue, IpcHandback, IpcLockHolder, IpcMmKey, IpcObjectHandle, IpcOpKind,
    IpcOpToken, IpcOperation, IpcRegion, IpcReleased, IpcTaskKey, IpcUserVa, OfdPin, RawOfdPin,
    RawTableId, WriteProgress,
};
use carrick_el1_abi::ipc_tables::IpcTableMap;
use carrick_el1_abi::{CurrentTask, EL1_GUEST_LOCK_SPINS, IpcLeave, TrapFrame};
use carrick_sched_core::object_wait::{ObjectWaitError, ObjectWaitSnapshot};
use carrick_sched_core::{BoundedSpin, LockWait, WakeEffects};
use core::sync::atomic::Ordering;

/// Linux AArch64 values this adapter decodes and returns.
mod linux {
    pub const SYS_READ: usize = 63;
    pub const SYS_WRITE: usize = 64;
    pub const EBADF: i64 = -9;
    pub const EAGAIN: i64 = -11;
    pub const EINVAL: i64 = -22;
    pub const EPIPE: i64 = -32;
    /// Largest byte count one read/write transfers (`MAX_RW_COUNT`).
    pub const MAX_RW_COUNT: u64 = 0x7fff_f000;
    /// eventfd reads and writes move one native-endian u64.
    pub const EVENTFD_WORD: u64 = 8;
    /// Length of the AArch64 SVC instruction ELR points past.
    pub const SVC_LEN: u64 = 4;
}
pub use linux::{SYS_READ, SYS_WRITE};

/// Where the venue finds a task's descriptor table in the shared authority.
/// Returns a table only when it is the task's complete descriptor namespace
/// (a missing descriptor is then EBADF, not a host descriptor).
pub trait IpcTables {
    fn table_of(&self, task: &CurrentTask) -> Option<RawTableId>;
}

/// The shared IPC authority as this venue maps it.
pub struct IpcVenue<'a> {
    pub region: IpcRegion<'a>,
    pub tables: &'a dyn IpcTables,
}

/// How a read/write reached the IPC adapter ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcServed {
    /// Not an IPC call, or refused before any effect: continue dispatch
    /// (the frame is unchanged).
    Forward,
    /// Completed in EL1. Without `switched`, `x0` holds the result; with it
    /// the caller parked and the frame is another thread's.
    Returned { switched: bool },
    /// The caller parked, nothing was runnable and host work arrived.
    Idle,
    /// The frame now carries an [`IPC_HANDBACK_NR`] call for the host.
    Handback,
}

/// Tables resolved through the host-published [`IpcTableMap`], keyed by the
/// running task's host file table (which an EL1 switch-in updates): a table
/// with no entry is not served.
pub struct MapTables<'a>(pub &'a IpcTableMap);

impl IpcTables for MapTables<'_> {
    fn table_of(&self, task: &CurrentTask) -> Option<RawTableId> {
        self.0.lookup(task.file_table.load(Ordering::Acquire))
    }
}

/// The shared IPC authority EL1 serves from: the window the runtime maps at
/// `EL1_IPC_BASE`, once the host authority has published its directory.
/// Unmapped or unpublished, the attach fails and every call forwards.
#[cfg(target_os = "none")]
pub fn guest_venue(slot: u32) -> Option<IpcVenue<'static>> {
    static TABLES: GuestTables = GuestTables;
    // Unmapped at stage-2 until the carrier installs it: never touch the
    // window before the host says so.
    if !carrick_el1_abi::ipc_table_map_guest().window_published() {
        return None;
    }
    let region = carrick_el1_abi::ipc_window_guest()?
        .attach()
        .ok()?
        .for_el1_slot(slot);
    Some(IpcVenue {
        region,
        tables: &TABLES,
    })
}

/// Host builds serve no guest: there is no EL1 window to attach.
#[cfg(not(target_os = "none"))]
pub fn guest_venue(_slot: u32) -> Option<IpcVenue<'static>> {
    None
}

#[cfg(target_os = "none")]
struct GuestTables;

#[cfg(target_os = "none")]
impl IpcTables for GuestTables {
    fn table_of(&self, task: &CurrentTask) -> Option<RawTableId> {
        MapTables(carrick_el1_abi::ipc_table_map_guest()).table_of(task)
    }
}

const EL1_WAIT: BoundedSpin = BoundedSpin(EL1_GUEST_LOCK_SPINS);

/// Wait for a lock held only by another party's short section (an object
/// or queue lock: never held across I/O, a switch or a host wait).
struct Finish;
impl LockWait for Finish {
    fn wait(&self, _attempt: u32) -> bool {
        core::hint::spin_loop();
        true
    }
}

/// Serve read(2)/write(2) on a pipe or eventfd in EL1.
pub fn serve_ipc<C: ThreadCpu, U: UserWord, M: UserCopy>(
    sched: &mut Sched<'_, C, U>,
    frame: &mut TrapFrame,
    venue: &IpcVenue<'_>,
    user: &mut M,
) -> IpcServed {
    let nr = frame.x[8] as usize;
    if nr != SYS_READ && nr != SYS_WRITE {
        return IpcServed::Forward;
    }
    let (token, op, resumed) = match sched.take_object_operation() {
        // The slot's record is not this task's: the host settles it.
        Err(_) => return leave(sched, IpcLeave::StaleOperation, IpcServed::Forward),
        Ok(Some(t)) => {
            let Some(token) = from_sched_token(t) else {
                return leave(sched, IpcLeave::StaleOperation, IpcServed::Forward);
            };
            let Ok(op) = venue.region.operation(&token) else {
                return leave(sched, IpcLeave::StaleOperation, IpcServed::Forward);
            };
            if op.task != task_key(sched.task) || op.mm != mm_key(sched.task) {
                let served = handback(frame, token, op, IpcHandback::Continue, 0, venue);
                return leave(sched, IpcLeave::ForeignOperation, served);
            }
            (token, op, true)
        }
        Ok(None) => match admit(sched, frame, venue, user) {
            Admission::Admitted(token, op) => (token, op, false),
            Admission::Immediate(result) => {
                frame.x[0] = result as u64;
                return IpcServed::Returned { switched: false };
            }
            Admission::Forward => return IpcServed::Forward,
            Admission::Restart(token, op) => {
                let served = handback(frame, token, op, IpcHandback::Restart, 0, venue);
                return leave(sched, IpcLeave::Restart, served);
            }
        },
    };
    run(sched, frame, venue, user, token, op, resumed)
}

fn task_key(task: &CurrentTask) -> IpcTaskKey {
    IpcTaskKey(task.task_id.load(Ordering::Relaxed))
}

fn mm_key(task: &CurrentTask) -> IpcMmKey {
    IpcMmKey(task.zone_mm.load(Ordering::Relaxed))
}

enum Admission {
    Admitted(IpcOpToken, IpcOperation),
    Immediate(i64),
    Forward,
    /// The pinned description is not one EL1 serves (the fd changed between
    /// the snapshot and the pin): the host drops the pin and runs the call.
    Restart(IpcOpToken, IpcOperation),
}

fn op_kind(
    backing: carrick_el1_abi::ipc::BackingToken,
    reading: bool,
) -> Option<(IpcOpKind, IpcObjectHandle)> {
    match IpcBacking::decode(backing)? {
        IpcBacking::Pipe { object, .. } if reading => Some((IpcOpKind::PipeRead, object)),
        IpcBacking::Pipe { object, .. } => Some((IpcOpKind::PipeWrite, object)),
        IpcBacking::EventFd { object } if reading => Some((IpcOpKind::EventFdRead, object)),
        IpcBacking::EventFd { object } => Some((IpcOpKind::EventFdWrite, object)),
        IpcBacking::Host(_) => None,
    }
}

/// Decode a fresh call and take ownership of it, before any effect.
fn admit<C: ThreadCpu, U: UserWord, M: UserCopy>(
    sched: &mut Sched<'_, C, U>,
    frame: &TrapFrame,
    venue: &IpcVenue<'_>,
    user: &mut M,
) -> Admission {
    let task = sched.task;
    let region = &venue.region;
    let Some(table) = venue.tables.table_of(task) else {
        return refuse(sched, IpcLeave::NoTable);
    };
    let table = TableId::from_raw(table);
    let fd = Fd(frame.x[0] as i32);
    let reading = frame.x[8] as usize == SYS_READ;
    let fda = region.fd(EL1_WAIT);
    // A snapshot first (no retention): host-backed descriptions are never
    // pinned in EL1, so EL1 never holds a hold it could not release.
    match fda.get(table, fd) {
        Ok(snapshot) if op_kind(snapshot.backing, reading).is_some() => {}
        Ok(_) => return Admission::Forward,
        Err(FdError::BadFd) => return Admission::Immediate(linux::EBADF),
        Err(FdError::Contended) => return refuse(sched, IpcLeave::TableContended),
        Err(_) => return refuse(sched, IpcLeave::TableRefused),
    }
    let operation = |pin: RawOfdPin| IpcOperation {
        pin,
        task: task_key(task),
        mm: mm_key(task),
        buf: IpcUserVa(frame.x[1]),
        orig_x0: frame.x[0],
        nr: frame.x[8] as u32,
        ..IpcOperation::EMPTY
    };
    let (pin, desc) = match fda.pin(table, fd) {
        Ok(found) => found,
        // Closed since the snapshot: the call ran after the close.
        Err(FdError::BadFd) => return Admission::Immediate(linux::EBADF),
        Err(FdError::Contended) => return refuse(sched, IpcLeave::PinContended),
        // The lock-free pin landed on a reused record the fd did not name:
        // the host drops that pin (possibly a final release of a host
        // resource EL1 cannot release) and runs the call afresh.
        Err(FdError::PinRaced(raw)) => {
            let op = operation(raw);
            return match region.begin_operation(op) {
                Ok(token) => Admission::Restart(token, op),
                Err(_) => {
                    release_pin(sched, OfdPin::from_raw(raw), region);
                    refuse(sched, IpcLeave::NoOperationRecord)
                }
            };
        }
        Err(_) => return refuse(sched, IpcLeave::PinRefused),
    };
    let mut op = operation(pin.into_raw());
    let Some((kind, object)) = op_kind(desc.backing, reading) else {
        // Replaced by a host-backed description since the snapshot: the
        // host owns its release.
        return match region.begin_operation(op) {
            Ok(token) => Admission::Restart(token, op),
            Err(_) => {
                release_pin(sched, OfdPin::from_raw(op.pin), region);
                refuse(sched, IpcLeave::NoOperationRecord)
            }
        };
    };
    let permitted = match desc.access {
        AccessMode::ReadWrite => true,
        AccessMode::ReadOnly => reading,
        AccessMode::WriteOnly => !reading,
        AccessMode::Path => false,
    };
    let count = frame.x[2].min(linux::MAX_RW_COUNT);
    let eventfd = matches!(kind, IpcOpKind::EventFdRead | IpcOpKind::EventFdWrite);
    let immediate = if !permitted {
        Some(linux::EBADF)
    } else if !eventfd && count == 0 {
        Some(0)
    } else if eventfd && count < linux::EVENTFD_WORD {
        Some(linux::EINVAL)
    } else {
        None
    };
    if let Some(result) = immediate {
        release_pin(sched, OfdPin::from_raw(op.pin), region);
        return Admission::Immediate(result);
    }
    // eventfd(2): a write copies its value once, before it can block.
    let mut value = [0u8; linux::EVENTFD_WORD as usize];
    if kind == IpcOpKind::EventFdWrite
        && PrefixCopy::new(user).copy_in(&mut value, frame.x[1]) != value.len()
    {
        // No effect yet: the host resolves the fault (first touch or EFAULT).
        release_pin(sched, OfdPin::from_raw(op.pin), region);
        return refuse(sched, IpcLeave::CopyInFault);
    }
    op.kind = kind;
    op.object = object.to_raw();
    op.progress = WriteProgress::new(if eventfd { linux::EVENTFD_WORD } else { count });
    op.value = IpcEventValue(u64::from_ne_bytes(value));
    match region.begin_operation(op) {
        Ok(token) => Admission::Admitted(token, op),
        Err(_) => {
            release_pin(sched, OfdPin::from_raw(op.pin), region);
            refuse(sched, IpcLeave::NoOperationRecord)
        }
    }
}

/// Drop a description pin. A final release is performed here, waiting out
/// another party's short object-lock section, and wakes the peer lane (EOF
/// for readers, EPIPE for writers). Only IPC-backed descriptions are ever
/// pinned in EL1.
fn release_pin<C: ThreadCpu, U: UserWord>(
    sched: &mut Sched<'_, C, U>,
    pin: OfdPin,
    region: &IpcRegion<'_>,
) {
    let Ok(Some(description)) = region.fd(EL1_WAIT).unpin(pin) else {
        return;
    };
    let Ok(IpcReleased::Object { wake, freed }) =
        region.release_backing(description.backing, &Finish)
    else {
        return;
    };
    if wake.host_owed {
        sched.task.mark_pending_host_work();
    }
    // A freed object has no waiters: each holds a pin on it.
    if !freed {
        let lanes = WakeSet {
            readers: wake.readers,
            writers: wake.writers,
        };
        for e in notify(sched, wake.object, lanes).into_iter().flatten() {
            sched.finish_object_wake(e);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run<C: ThreadCpu, U: UserWord, M: UserCopy>(
    sched: &mut Sched<'_, C, U>,
    frame: &mut TrapFrame,
    venue: &IpcVenue<'_>,
    user: &mut M,
    mut token: IpcOpToken,
    mut op: IpcOperation,
    resumed: bool,
) -> IpcServed {
    let region = &venue.region;
    let object = IpcObjectHandle::from_raw(op.object);
    let mut copy = PrefixCopy::new(user);
    loop {
        let nonblock = {
            let pin = OfdPin::from_raw(op.pin);
            let flags = region.fd(EL1_WAIT).pinned(&pin).map(|d| d.flags.nonblock);
            op.pin = pin.into_raw();
            match flags {
                Ok(nonblock) => nonblock,
                Err(_) => {
                    return bail(
                        sched,
                        frame,
                        token,
                        op,
                        resumed,
                        venue,
                        IpcLeave::FlagsRefused,
                    );
                }
            }
        };
        // Wait for the object lock's holder (`Finish`), never forward: a
        // holder's section is short and never waits on this vCPU. A host
        // thread's takes no guest-progress lock; an EL1 holder that a host
        // kick stopped mid-section is resumed to completion on its vCPU
        // (`should_resume_mid_el1`). Giving up turned a transfer that could
        // complete into a host round trip.
        let mut guard = match region.lock(object, &Finish) {
            Ok(guard) => guard,
            Err(_) => {
                let why = match region.lock_holder(object) {
                    Some(IpcLockHolder::Host) => IpcLeave::ObjectBusyHost,
                    Some(IpcLockHolder::El1 { .. }) => IpcLeave::ObjectBusyEl1,
                    None => IpcLeave::ObjectBusy,
                };
                return bail(sched, frame, token, op, resumed, venue, why);
            }
        };
        let (status, wake) = match transfer(&mut guard, &mut op, &mut copy) {
            Ok(step) => step,
            Err(_) => {
                drop(guard);
                return bail(
                    sched,
                    frame,
                    token,
                    op,
                    resumed,
                    venue,
                    IpcLeave::TransferRefused,
                );
            }
        };
        let published = guard.publish(wake);
        if published.host_owed {
            sched.task.mark_pending_host_work();
        }
        let effects = notify(sched, object, wake);
        // A call that would block parks in the zone even with host work
        // pending (a kick, an owed host wake, possibly a signal for this
        // thread): `park` then leaves for the host at once, which settles the
        // parked thread there and interrupts it for a pending signal (Linux
        // checks for one before it sleeps). Moving the wait to the host
        // instead gives the object a host subscriber, whose owed wakes mark
        // pending host work on every later writer's vCPU.
        let parking = match status {
            StepStatus::Blocked(lane) if !nonblock => Some((lane, snapshot(sched, object, lane))),
            _ => None,
        };
        drop(guard);
        for e in effects.into_iter().flatten() {
            sched.finish_object_wake(e);
        }
        let written = op.progress.written;
        let result = match status {
            StepStatus::Complete => written as i64,
            StepStatus::EndOfFile => 0,
            StepStatus::Invalid => linux::EINVAL,
            StepStatus::Blocked(_) if nonblock => {
                if written > 0 {
                    written as i64
                } else {
                    linux::EAGAIN
                }
            }
            StepStatus::Blocked(lane) => {
                let Some((_, Some(snap))) = parking else {
                    return bail(
                        sched,
                        frame,
                        token,
                        op,
                        resumed,
                        venue,
                        IpcLeave::ParkRefused,
                    );
                };
                match park(sched, frame, region, token, op, object, lane, snap) {
                    Parked::Done(served) => return served,
                    Parked::Retry(t) => {
                        token = t;
                        continue;
                    }
                    Parked::Refused(t) => {
                        return bail(sched, frame, t, op, resumed, venue, IpcLeave::ParkRefused);
                    }
                }
            }
            StepStatus::Broken if written == 0 && !resumed => {
                // No effect yet: the host re-runs the call (EPIPE + SIGPIPE).
                finish(sched, token, region);
                return leave(sched, IpcLeave::BrokenFirst, IpcServed::Forward);
            }
            StepStatus::Broken => {
                let result = if written > 0 {
                    written as i64
                } else {
                    linux::EPIPE
                };
                let served = handback(frame, token, op, IpcHandback::Sigpipe, result, venue);
                return leave(sched, IpcLeave::SigpipeHandback, served);
            }
            StepStatus::Fault if written == 0 && !resumed => {
                // The host resolves the fault (first touch or EFAULT).
                finish(sched, token, region);
                return leave(sched, IpcLeave::FaultFirst, IpcServed::Forward);
            }
            StepStatus::Fault if op.kind == IpcOpKind::PipeRead => written as i64,
            StepStatus::Fault => {
                return bail(
                    sched,
                    frame,
                    token,
                    op,
                    resumed,
                    venue,
                    IpcLeave::FaultFirst,
                );
            }
        };
        finish(sched, token, region);
        frame.x[0] = result as u64;
        return IpcServed::Returned { switched: false };
    }
}

/// Notify both lanes' waiters the step owes, under the object lock.
fn notify<C: ThreadCpu, U: UserWord>(
    sched: &Sched<'_, C, U>,
    object: IpcObjectHandle,
    wake: WakeSet,
) -> [Option<WakeEffects>; 2] {
    let mut out = [None, None];
    for (i, (lane, due)) in [
        (WaitFor::Readable, wake.readers),
        (WaitFor::Writable, wake.writers),
    ]
    .into_iter()
    .enumerate()
    {
        let Some(key) = due.then(|| wait_key(object, lane)).flatten() else {
            continue;
        };
        // The queue lock is held only for enqueue/unlink by a running
        // party: finish the notification rather than lose a wake.
        loop {
            match sched.notify_object(key) {
                Ok((report, effects)) => {
                    if report.deferred != 0 {
                        sched.task.mark_pending_host_work();
                    }
                    out[i] = Some(effects);
                    break;
                }
                Err(ObjectWaitError::Busy) => core::hint::spin_loop(),
                // Never bound: nobody ever waited on this incarnation.
                Err(ObjectWaitError::Stale) => break,
                Err(_) => {
                    sched.task.mark_pending_host_work();
                    break;
                }
            }
        }
    }
    out
}

/// Sample the lane's wait epoch under the object lock (binding the queue to
/// this incarnation on first use).
fn snapshot<C: ThreadCpu, U: UserWord>(
    sched: &Sched<'_, C, U>,
    object: IpcObjectHandle,
    lane: WaitFor,
) -> Option<ObjectWaitSnapshot> {
    let key = wait_key(object, lane)?;
    match sched.observe_object(key) {
        Ok(snap) => Some(snap),
        Err(ObjectWaitError::Stale) => {
            let _ = sched.zone.bind_object_wait(key, &EL1_WAIT);
            sched.observe_object(key).ok()
        }
        Err(_) => None,
    }
}

enum Parked {
    Done(IpcServed),
    Retry(IpcOpToken),
    Refused(IpcOpToken),
}

#[allow(clippy::too_many_arguments)]
fn park<C: ThreadCpu, U: UserWord>(
    sched: &mut Sched<'_, C, U>,
    frame: &mut TrapFrame,
    region: &IpcRegion<'_>,
    token: IpcOpToken,
    op: IpcOperation,
    object: IpcObjectHandle,
    lane: WaitFor,
    snap: ObjectWaitSnapshot,
) -> Parked {
    let (Some(key), Some(resume)) = (
        wait_key(object, lane),
        OperationResumePc::new(frame.elr.wrapping_sub(linux::SVC_LEN)),
    ) else {
        return Parked::Refused(token);
    };
    if region.update_operation(&token, op).is_err() {
        return Parked::Refused(token);
    }
    let sched_token = match to_sched_token(token) {
        Ok(t) => t,
        Err(token) => return Parked::Refused(token),
    };
    match sched.park_object(frame, key, snap, resume, sched_token) {
        Ok(parked) => {
            let served = if sched.task.has_pending_host_work() {
                sched.leave_after_object_park(parked)
            } else {
                sched.resume_after_object_park(frame, parked, 0)
            };
            Parked::Done(match served {
                Some(Served::Returned { switched }) => IpcServed::Returned { switched },
                Some(Served::Idle) | None => IpcServed::Idle,
            })
        }
        Err((error, t)) => {
            let Some(token) = from_sched_token(t) else {
                // Unreachable for a token this adapter converted.
                return Parked::Done(IpcServed::Idle);
            };
            if error == ObjectWaitError::Changed {
                Parked::Retry(token)
            } else {
                Parked::Refused(token)
            }
        }
    }
}

/// Retire the operation record and drop its pin.
fn finish<C: ThreadCpu, U: UserWord>(
    sched: &mut Sched<'_, C, U>,
    token: IpcOpToken,
    region: &IpcRegion<'_>,
) {
    if let Ok(op) = region.finish_operation(token) {
        release_pin(sched, OfdPin::from_raw(op.pin), region);
    }
}

/// Count why a call leaves for the host (`Counters::ipc_leaves`).
fn note<C: ThreadCpu, U: UserWord>(sched: &Sched<'_, C, U>, why: IpcLeave) {
    sched.counters.ipc_leaves[why as usize].fetch_add(1, Ordering::Relaxed);
}

fn leave<C: ThreadCpu, U: UserWord>(
    sched: &Sched<'_, C, U>,
    why: IpcLeave,
    served: IpcServed,
) -> IpcServed {
    note(sched, why);
    served
}

fn refuse<C: ThreadCpu, U: UserWord>(sched: &Sched<'_, C, U>, why: IpcLeave) -> Admission {
    note(sched, why);
    Admission::Forward
}

/// The call cannot continue in EL1: before any effect of a never-parked
/// call, forward it unchanged; otherwise hand the owned operation back.
#[allow(clippy::too_many_arguments)]
fn bail<C: ThreadCpu, U: UserWord>(
    sched: &mut Sched<'_, C, U>,
    frame: &mut TrapFrame,
    token: IpcOpToken,
    op: IpcOperation,
    resumed: bool,
    venue: &IpcVenue<'_>,
    why: IpcLeave,
) -> IpcServed {
    note(sched, why);
    if op.progress.written == 0 && !resumed {
        finish(sched, token, &venue.region);
        return IpcServed::Forward;
    }
    handback(frame, token, op, IpcHandback::Continue, 0, venue)
}

/// Hand the owned operation to the host: the record says what to do; the
/// frame carries only the token (`x0`) and [`IPC_HANDBACK_NR`] (`x8`).
fn handback(
    frame: &mut TrapFrame,
    token: IpcOpToken,
    mut op: IpcOperation,
    what: IpcHandback,
    result: i64,
    venue: &IpcVenue<'_>,
) -> IpcServed {
    op.handback = what;
    op.result = result;
    if op.nr == 0 {
        // A resumed operation: the re-executed SVC carries its registers.
        op.orig_x0 = frame.x[0];
        op.nr = frame.x[8] as u32;
    }
    let _ = venue.region.update_operation(&token, op);
    frame.x[8] = IPC_HANDBACK_NR;
    frame.x[0] = token.into_raw().pack();
    IpcServed::Handback
}

#[cfg(test)]
mod tests {
    //! VM-free bindings for kernel.el1.ipc-read-write: the Linux adapter over
    //! real shared IPC records, the real scheduler tables and a fake CPU.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    extern crate std;

    use super::*;
    use crate::substrate::sched::{FakeCpu, HardwareUserWord};
    use carrick_el1_abi::ipc::fd::{Description, StatusFlags};
    use carrick_el1_abi::ipc::{
        End, EventMode, Extent, IPC_POOL_ALIGN, IpcDirectory, IpcPipeStorage, LockWait,
        descriptor_extent_bytes,
    };
    use carrick_el1_abi::{Counters, El1TaskId, SlotId, ThreadCtx, ThreadIdentity, ZoneTables};
    use core::cell::{Cell, RefCell};
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::boxed::Box;
    use std::collections::HashMap;
    use std::vec::Vec;

    // ---- allocation counter (this thread's heap allocations) ----
    struct Counting;
    std::thread_local! {
        static ALLOCS: Cell<usize> = const { Cell::new(0) };
    }
    // SAFETY: forwards to the system allocator; only counts.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let _ = ALLOCS.try_with(|n| n.set(n.get() + 1));
            // SAFETY: the caller's contract.
            unsafe { System.alloc(layout) }
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            let _ = ALLOCS.try_with(|n| n.set(n.get() + 1));
            // SAFETY: the caller's contract. Keeps the directory mapping's
            // large reservation lazily committed.
            unsafe { System.alloc_zeroed(layout) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: the caller's contract.
            unsafe { System.dealloc(ptr, layout) }
        }
    }
    #[global_allocator]
    static COUNTING: Counting = Counting;
    fn allocations() -> usize {
        ALLOCS.with(|n| n.get())
    }

    struct HostWait;
    impl LockWait for HostWait {
        fn wait(&self, _attempt: u32) -> bool {
            core::hint::spin_loop();
            true
        }
    }

    const MM: u64 = 7;
    const OTHER_MM: u64 = 9;
    const SLOT: SlotId = SlotId::new(3);
    const IDLE_TTBR: u64 = 0x4000_0000;
    const TTBR_MM: u64 = (7 << 48) | 0x7000_0000;
    const TTBR_OTHER: u64 = (9 << 48) | 0x9000_0000;
    const PAGE: u64 = 4096;
    const A_SVC: u64 = 0xA000;
    const B_SVC: u64 = 0xB000;

    // ---- user memory: pages per (address space, page) ----
    type Pages = HashMap<(u64, u64), Box<[u8; 4096]>>;
    #[derive(Default)]
    struct Memory {
        pages: RefCell<Pages>,
    }
    impl Memory {
        fn map(&self, mm: u64, va: u64, len: u64) {
            let mut pages = self.pages.borrow_mut();
            let mut page = va & !(PAGE - 1);
            while page < va + len {
                pages
                    .entry((mm, page))
                    .or_insert_with(|| Box::new([0; 4096]));
                page += PAGE;
            }
        }
        fn write(&self, mm: u64, va: u64, bytes: &[u8]) {
            self.map(mm, va, bytes.len() as u64);
            let mut pages = self.pages.borrow_mut();
            for (i, b) in bytes.iter().enumerate() {
                let at = va + i as u64;
                pages.get_mut(&(mm, at & !(PAGE - 1))).unwrap()[(at % PAGE) as usize] = *b;
            }
        }
        fn read(&self, mm: u64, va: u64, len: usize) -> Vec<u8> {
            let pages = self.pages.borrow();
            (0..len as u64)
                .map(|i| {
                    let at = va + i;
                    pages[&(mm, at & !(PAGE - 1))][(at % PAGE) as usize]
                })
                .collect()
        }
    }
    /// The venue's user copy for the task running on the slot: refuses any
    /// range touching an unmapped page (EL1 forwards those to the host).
    struct User<'a> {
        task: &'a CurrentTask,
        mem: &'a Memory,
    }
    impl User<'_> {
        fn present(&self, va: u64, len: usize) -> bool {
            let mm = self.task.zone_mm.load(Ordering::Relaxed);
            let pages = self.mem.pages.borrow();
            let mut page = va & !(PAGE - 1);
            while page < va + len as u64 {
                if !pages.contains_key(&(mm, page)) {
                    return false;
                }
                page += PAGE;
            }
            true
        }
    }
    impl UserCopy for User<'_> {
        fn copy_out(&mut self, dst_va: u64, src: &[u8]) -> bool {
            if !self.present(dst_va, src.len()) {
                return false;
            }
            self.mem
                .write(self.task.zone_mm.load(Ordering::Relaxed), dst_va, src);
            true
        }
        fn copy_in(&mut self, dst: &mut [u8], src_va: u64) -> bool {
            if !self.present(src_va, dst.len()) {
                return false;
            }
            let mm = self.task.zone_mm.load(Ordering::Relaxed);
            let pages = self.mem.pages.borrow();
            for (i, b) in dst.iter_mut().enumerate() {
                let at = src_va + i as u64;
                *b = pages[&(mm, at & !(PAGE - 1))][(at % PAGE) as usize];
            }
            true
        }
    }

    /// The file table a test thread runs with: A's is 5, every other
    /// thread's is its tid (one process each).
    fn file_table_of(tid: u64, a_tid: u64) -> u64 {
        if tid == a_tid { 5 } else { tid }
    }

    // ---- the world: region (host-initialized), zone, one slot, task A ----
    struct World {
        region: &'static IpcRegion<'static>,
        /// Next free byte of the pool's ring area and descriptor area.
        next: Cell<u64>,
        next_descriptor: Cell<u64>,
        zone: Box<ZoneTables>,
        task: CurrentTask,
        cpu: FakeCpu,
        counters: &'static Counters,
        mem: Memory,
        map: &'static IpcTableMap,
        tables: MapTables<'static>,
        a_tid: u64,
    }

    fn identity(tid: u64, mm: u64) -> ThreadIdentity {
        ThreadIdentity {
            tid,
            serial: tid + 1000,
            mm,
            file_table: tid,
            generation: 1,
            affinity: 0,
        }
    }

    fn world() -> World {
        let dir = unsafe {
            std::alloc::alloc_zeroed(
                Layout::from_size_align(carrick_el1_abi::ipc::IPC_DIRECTORY_BYTES, 4096).unwrap(),
            )
            .cast::<IpcDirectory>()
        };
        let pool_len = 32 << 20;
        let pool =
            unsafe { std::alloc::alloc_zeroed(Layout::from_size_align(pool_len, 4096).unwrap()) };
        let region = unsafe {
            IpcRegion::initialize(
                dir,
                carrick_el1_abi::ipc::IPC_DIRECTORY_BYTES,
                pool,
                pool_len,
                42,
            )
        }
        .unwrap();
        let zone: Box<ZoneTables> =
            unsafe { Box::from_raw(std::alloc::alloc_zeroed(Layout::new::<ZoneTables>()).cast()) };
        zone.spaces.set_idle_ttbr(IDLE_TTBR);
        for (mm, ttbr) in [(MM, TTBR_MM), (OTHER_MM, TTBR_OTHER)] {
            let index = zone.spaces.publish_closed(mm, ttbr, ttbr).unwrap();
            zone.spaces.open(index);
        }
        zone.drive(SLOT, u64::from(SLOT.raw()) + 1);
        zone.publish_slot(SLOT, MM, None, 0);
        let here = carrick_sched_core::ExecutionSlot::zone(SLOT);
        zone.occupancy.vacate_any(here);
        assert!(zone.occupancy.replace(here, 0, MM));
        zone.enter_guest(SLOT);
        let task = CurrentTask::new();
        task.set(El1TaskId::from_linux_tid(101), 1, 5);
        task.zone_mm.store(MM, Ordering::Relaxed);
        task.thread_serial.store(1101, Ordering::Relaxed);
        let a_tid = task.task_id.load(Ordering::Relaxed);
        // SAFETY: all-zero is the empty table map.
        let map: &'static IpcTableMap = unsafe {
            &*std::alloc::alloc_zeroed(Layout::new::<IpcTableMap>()).cast::<IpcTableMap>()
        };
        // The fake CPU records switches and SGIs in vectors: reserve them so
        // allocation accounting sees only the code under test.
        let mut cpu = FakeCpu::default();
        cpu.translations.reserve(4096);
        cpu.sgis.reserve(4096);
        cpu.asid_invalidations.reserve(4096);
        World {
            next_descriptor: Cell::new(
                carrick_el1_abi::ipc::ipc_descriptor_area(pool_len as u64).start,
            ),
            region: Box::leak(Box::new(region)),
            next: Cell::new(0),
            zone,
            task,
            cpu,
            counters: Box::leak(Box::new(Counters::default())),
            mem: Memory::default(),
            map,
            tables: MapTables(map),
            a_tid,
        }
    }

    impl World {
        /// Ring-area bytes.
        fn bump(&self, bytes: u64) -> u64 {
            let at = self.next.get();
            self.next.set((at + bytes).next_multiple_of(IPC_POOL_ALIGN));
            at
        }
        /// A descriptor extent of `capacity` slots, in the descriptor area.
        fn descriptor_extent(&self, capacity: usize) -> Extent {
            let at = self.next_descriptor.get();
            self.next_descriptor
                .set((at + descriptor_extent_bytes(capacity)).next_multiple_of(IPC_POOL_ALIGN));
            Extent {
                token: at,
                capacity: capacity as u64,
            }
        }
        fn host(&self) -> carrick_el1_abi::ipc::IpcFdAuthority<'static, HostWait> {
            self.region.fd(HostWait)
        }
        /// The host venue's table for thread `tid` (a new process).
        fn table(&self, tid: u64) -> TableId {
            let extent = self.descriptor_extent(64);
            let t = self.host().create_table(1024, &mut { extent }).unwrap();
            self.map
                .publish(file_table_of(tid, self.a_tid), t.to_raw())
                .unwrap();
            t
        }
        fn fork_table(&self, parent: TableId, tid: u64) -> TableId {
            let mut extent = self.descriptor_extent(64);
            let t = self.host().fork(parent, &mut extent).unwrap();
            self.map
                .publish(file_table_of(tid, self.a_tid), t.to_raw())
                .unwrap();
            t
        }
        /// A new pipe object before any write: no ring yet.
        fn unbacked_pipe_object(&self) -> IpcObjectHandle {
            let mut retired = None;
            let object = self
                .region
                .create_pipe(65536, &mut retired, &HostWait)
                .unwrap();
            assert_eq!(retired, None);
            object
        }
        /// pipe(2) as the host venue performs it, after its first write.
        fn pipe(&self, t: TableId, flags: StatusFlags) -> (i32, i32, IpcObjectHandle) {
            let object = self.unbacked_pipe_object();
            // The ring the host's first write would provide.
            let mut storage = IpcPipeStorage {
                offset: self.bump(65536 + 16 * 8),
                ring_bytes: 65536,
                pages: 16,
            };
            let mut guard = self.region.lock(object, &HostWait).unwrap();
            assert_eq!(guard.provide_pipe_storage(&mut storage), Ok(true));
            drop(guard);
            let open = |end, access| {
                self.host()
                    .open(
                        t,
                        Fd(0),
                        Description::new(IpcBacking::Pipe { object, end }.encode(), access, flags),
                        false,
                    )
                    .unwrap()
                    .0
            };
            (
                open(End::Reader, AccessMode::ReadOnly),
                open(End::Writer, AccessMode::WriteOnly),
                object,
            )
        }
        fn eventfd(&self, t: TableId, initial: u32, mode: EventMode, flags: StatusFlags) -> i32 {
            let object = self
                .region
                .create_eventfd(initial, mode, &HostWait)
                .unwrap();
            self.host()
                .open(
                    t,
                    Fd(0),
                    Description::new(
                        IpcBacking::EventFd { object }.encode(),
                        AccessMode::ReadWrite,
                        flags,
                    ),
                    false,
                )
                .unwrap()
                .0
        }
        /// close(2) as the host venue performs it, including notifying the
        /// peer lane of a released endpoint through the scheduler.
        fn host_close(&mut self, t: TableId, fd: i32) {
            if let Some(d) = self.host().close(t, Fd(fd)).unwrap()
                && let Ok(IpcReleased::Object { wake, freed: false }) =
                    self.region.release_backing(d.backing, &HostWait)
            {
                let zone: &ZoneTables = &self.zone;
                let sched = Sched {
                    zone,
                    slot: SLOT,
                    task: &self.task,
                    cpu: &mut self.cpu,
                    user: &HardwareUserWord,
                    counters: self.counters,
                };
                for lane in [WaitFor::Readable, WaitFor::Writable] {
                    if let Some(key) = wait_key(wake.object, lane)
                        && let Ok((_, e)) = sched.notify_object(key)
                    {
                        assert!(e.sgi.iter().all(|w| *w == 0));
                    }
                }
            }
        }
        fn venue(&self) -> IpcVenue<'_> {
            IpcVenue {
                region: *self.region,
                tables: &self.tables,
            }
        }
        /// One trap into the adapter on the slot.
        fn call(&mut self, frame: &mut TrapFrame) -> IpcServed {
            let zone: &ZoneTables = &self.zone;
            let mut sched = Sched {
                zone,
                slot: SLOT,
                task: &self.task,
                cpu: &mut self.cpu,
                user: &HardwareUserWord,
                counters: self.counters,
            };
            let venue = IpcVenue {
                region: *self.region,
                tables: &self.tables,
            };
            let mut user = User {
                task: &self.task,
                mem: &self.mem,
            };
            serve_ipc(&mut sched, frame, &venue, &mut user)
        }
        /// Queue thread `tid` of `mm`, runnable on the slot, about to issue
        /// the syscall in `frame` (its SVC at `svc`).
        fn queue(&self, tid: u64, mm: u64, frame: &TrapFrame, svc: u64) {
            let uaddr = 0x5000 + tid;
            let guard = self
                .zone
                .lock(ZoneTables::bucket_of(mm, uaddr), &HostWait)
                .unwrap();
            let record = self.zone.alloc_record(identity(tid, mm)).unwrap();
            let mut ctx = ThreadCtx::ZERO;
            ctx.x = frame.x;
            ctx.pc = svc;
            // SAFETY: freshly allocated and unpublished.
            unsafe { *self.zone.record(record).ctx_mut() = ctx };
            let seq = self.zone.next_seq(record);
            self.zone
                .enqueue(&guard, record, seq, mm, uaddr, u32::MAX, 0)
                .unwrap();
            self.zone.publish_park(record, seq);
            let mut placed = 0;
            let woken = self.zone.wake_host(
                &guard,
                mm,
                uaddr,
                u32::MAX,
                1,
                true,
                &mut |_| panic!("the slot runs it"),
                &mut |_| placed += 1,
            );
            assert_eq!((woken, placed), (1, 1));
        }
    }

    /// The operation a handback frame names (its token is in `x0`).
    fn handed_back(w: &World, frame: &TrapFrame) -> IpcOperation {
        let raw = carrick_el1_abi::ipc::RawIpcOpToken::unpack(frame.x[0]);
        w.region.operation(&IpcOpToken::from_raw(raw)).unwrap()
    }

    fn syscall(nr: usize, fd: i32, buf: u64, len: u64, svc: u64) -> TrapFrame {
        let mut frame = TrapFrame {
            elr: svc + 4,
            spsr: 0,
            slot: u64::from(SLOT.raw()),
            ..TrapFrame::default()
        };
        frame.x[0] = fd as u64;
        frame.x[1] = buf;
        frame.x[2] = len;
        frame.x[8] = nr as u64;
        frame
    }
    /// A switched-in thread re-executes its SVC: the trap's ELR is past it.
    fn reenter(frame: &mut TrapFrame, svc: u64) {
        assert_eq!(frame.elr, svc, "resumes at its SVC");
        frame.elr = svc + 4;
    }
    const NONBLOCK: StatusFlags = StatusFlags {
        append: false,
        nonblock: true,
        asynchronous: false,
        direct: false,
        noatime: false,
        dsync: false,
        sync: false,
        immutable: 0,
    };
    const BLOCK: StatusFlags = StatusFlags {
        nonblock: false,
        ..NONBLOCK
    };
    const RETURNED: IpcServed = IpcServed::Returned { switched: false };
    const SWITCHED: IpcServed = IpcServed::Returned { switched: true };

    fn host_calls(w: &World) -> u64 {
        w.counters
            .forwarded
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum::<u64>()
            + w.zone
                .counters
                .host_service_placements
                .load(Ordering::Relaxed)
            + w.zone.counters.el1_service_exits.load(Ordering::Relaxed)
    }

    #[test]
    fn el1_ipc_io_access_and_size_errors_are_decoded_in_guest() {
        let mut w = world();
        let t = w.table(w.a_tid);
        let (r, wfd, _) = w.pipe(t, BLOCK);
        let e = w.eventfd(t, 0, EventMode::Counter, NONBLOCK);
        w.mem.map(MM, 0x10000, PAGE);
        for (nr, fd, len, expected) in [
            (SYS_READ, wfd, 4, linux::EBADF),
            (SYS_WRITE, r, 4, linux::EBADF),
            (SYS_READ, 99, 4, linux::EBADF),
            (SYS_READ, r, 0, 0),
            (SYS_WRITE, wfd, 0, 0),
            (SYS_READ, e, 7, linux::EINVAL),
            (SYS_WRITE, e, 4, linux::EINVAL),
        ] {
            let mut f = syscall(nr, fd, 0x10000, len, A_SVC);
            assert_eq!(w.call(&mut f), RETURNED, "{nr} {fd} {len}");
            assert_eq!(f.x[0] as i64, expected, "{nr} {fd} {len}");
        }
        w.mem.write(MM, 0x10000, &u64::MAX.to_ne_bytes());
        let mut f = syscall(SYS_WRITE, e, 0x10000, 8, A_SVC);
        assert_eq!(w.call(&mut f), RETURNED);
        assert_eq!(f.x[0] as i64, linux::EINVAL, "all-ones counter write");
        assert_eq!(host_calls(&w), 0);
    }

    #[test]
    fn el1_ipc_io_roundtrip_eof_and_nonblocking_eagain() {
        let mut w = world();
        let t = w.table(w.a_tid);
        let (r, wfd, _) = w.pipe(t, NONBLOCK);
        w.mem.write(MM, 0x10000, b"hello");
        w.mem.map(MM, 0x20000, PAGE);
        let mut f = syscall(SYS_WRITE, wfd, 0x10000, 5, A_SVC);
        assert_eq!((w.call(&mut f), f.x[0]), (RETURNED, 5));
        let mut f = syscall(SYS_READ, r, 0x20000, 64, A_SVC);
        assert_eq!((w.call(&mut f), f.x[0]), (RETURNED, 5));
        assert_eq!(w.mem.read(MM, 0x20000, 5), b"hello");
        let mut f = syscall(SYS_READ, r, 0x20000, 64, A_SVC);
        assert_eq!(w.call(&mut f), RETURNED);
        assert_eq!(f.x[0] as i64, linux::EAGAIN);
        w.host_close(t, wfd);
        let mut f = syscall(SYS_READ, r, 0x20000, 64, A_SVC);
        assert_eq!((w.call(&mut f), f.x[0]), (RETURNED, 0), "EOF");
        assert_eq!(host_calls(&w), 0);
    }

    #[test]
    fn el1_ipc_io_nonblocking_saturation_and_atomic_small_writes() {
        let mut w = world();
        let t = w.table(w.a_tid);
        let (r, wfd, _) = w.pipe(t, NONBLOCK);
        w.mem.write(MM, 0x100000, &[7; 65536 + 16384]);
        let mut f = syscall(SYS_WRITE, wfd, 0x100000, 65535, A_SVC);
        assert_eq!((w.call(&mut f), f.x[0]), (RETURNED, 65535));
        for len in [2, 4096, 5000] {
            let mut f = syscall(SYS_WRITE, wfd, 0x100000, len, A_SVC);
            assert_eq!(w.call(&mut f), RETURNED);
            assert_eq!(f.x[0] as i64, linux::EAGAIN, "no prefix of {len} bytes");
        }
        w.mem.map(MM, 0x200000, PAGE);
        let mut f = syscall(SYS_READ, r, 0x200000, 4096, A_SVC);
        assert_eq!((w.call(&mut f), f.x[0]), (RETURNED, 4096));
        // Above PIPE_BUF a nonblocking write may be partial.
        let mut f = syscall(SYS_WRITE, wfd, 0x100000, 10000, A_SVC);
        assert_eq!((w.call(&mut f), f.x[0]), (RETURNED, 4096));
        assert_eq!(host_calls(&w), 0);
    }

    #[test]
    fn el1_ipc_io_eventfd_counter_semaphore_and_saturation() {
        let mut w = world();
        let t = w.table(w.a_tid);
        let c = w.eventfd(t, 0, EventMode::Counter, NONBLOCK);
        let s = w.eventfd(t, 2, EventMode::Semaphore, NONBLOCK);
        w.mem.map(MM, 0x10000, PAGE);
        let rw = |w: &mut World, nr, fd, value: Option<u64>| {
            if let Some(v) = value {
                w.mem.write(MM, 0x10000, &v.to_ne_bytes());
            }
            let mut f = syscall(nr, fd, 0x10000, 16, A_SVC);
            assert_eq!(w.call(&mut f), RETURNED);
            f.x[0] as i64
        };
        assert_eq!(rw(&mut w, SYS_READ, c, None), linux::EAGAIN);
        assert_eq!(rw(&mut w, SYS_WRITE, c, Some(3)), 8);
        assert_eq!(rw(&mut w, SYS_WRITE, c, Some(4)), 8);
        assert_eq!(rw(&mut w, SYS_READ, c, None), 8);
        assert_eq!(w.mem.read(MM, 0x10000, 8), 7u64.to_ne_bytes());
        assert_eq!(rw(&mut w, SYS_READ, s, None), 8);
        assert_eq!(w.mem.read(MM, 0x10000, 8), 1u64.to_ne_bytes());
        assert_eq!(rw(&mut w, SYS_WRITE, c, Some(u64::MAX - 1)), 8);
        assert_eq!(rw(&mut w, SYS_WRITE, c, Some(1)), linux::EAGAIN);
        assert_eq!(host_calls(&w), 0);
    }

    /// A pipe gets its ring at its first write (Linux allocates pipe pages
    /// on demand). EL1 never provisions: a write to an unbacked pipe
    /// forwards unchanged before any effect, so the host provides the ring
    /// and performs the write; reads and EOF need no ring.
    #[test]
    fn el1_ipc_io_first_write_to_an_unbacked_pipe_forwards_before_effects() {
        let mut w = world();
        let t = w.table(w.a_tid);
        let object = w.unbacked_pipe_object();
        let open = |w: &World, end, access| {
            w.host()
                .open(
                    t,
                    Fd(0),
                    Description::new(IpcBacking::Pipe { object, end }.encode(), access, NONBLOCK),
                    false,
                )
                .unwrap()
                .0
        };
        let r = open(&w, End::Reader, AccessMode::ReadOnly);
        let wfd = open(&w, End::Writer, AccessMode::WriteOnly);
        w.mem.map(MM, 0x10000, PAGE);
        w.mem.write(MM, 0x10000, b"ping");
        let seqs = w.region.observe(object).unwrap();
        let mut f = syscall(SYS_WRITE, wfd, 0x10000, 4, A_SVC);
        let before = f;
        assert_eq!(w.call(&mut f), IpcServed::Forward);
        assert_eq!((f.x, f.elr), (before.x, before.elr), "frame unchanged");
        assert_eq!(
            w.region.observe(object).unwrap(),
            seqs,
            "no effect, no wake"
        );
        let mut g = w.region.lock(object, &HostWait).unwrap();
        assert!(!g.pipe().unwrap().is_backed());
        assert_eq!(g.pipe().unwrap().unread_bytes(), 0);
        drop(g);
        // An empty unbacked pipe reads as EAGAIN in EL1, with no ring.
        let mut f = syscall(SYS_READ, r, 0x10000, 4, A_SVC);
        assert_eq!((w.call(&mut f), f.x[0] as i64), (RETURNED, linux::EAGAIN));
        // Once the host provided the ring, EL1 serves the write itself.
        let mut ring = IpcPipeStorage {
            offset: w.bump(65536 + 16 * 8),
            ring_bytes: 65536,
            pages: 16,
        };
        let mut g = w.region.lock(object, &HostWait).unwrap();
        assert_eq!(g.provide_pipe_storage(&mut ring), Ok(true));
        drop(g);
        let mut f = syscall(SYS_WRITE, wfd, 0x10000, 4, A_SVC);
        assert_eq!((w.call(&mut f), f.x[0]), (RETURNED, 4));
        let mut f = syscall(SYS_READ, r, 0x10000, 4, A_SVC);
        assert_eq!((w.call(&mut f), f.x[0]), (RETURNED, 4));
    }

    /// With stocked rings (the host keeps them provisioned), the first write
    /// of a fresh pipe is served in EL1: it takes a ring from the stock under
    /// the object lock, with no host exit. The stock only shrinks by that.
    #[test]
    fn el1_ipc_io_first_write_takes_a_stocked_ring_without_forwarding() {
        let mut w = world();
        let t = w.table(w.a_tid);
        for _ in 0..2 {
            let ring = IpcPipeStorage {
                offset: w.bump(65536 + 16 * 8),
                ring_bytes: 65536,
                pages: 16,
            };
            assert_eq!(w.region.stock_ring(ring), Ok(()));
        }
        let object = w.unbacked_pipe_object();
        let open = |w: &World, end, access| {
            w.host()
                .open(
                    t,
                    Fd(0),
                    Description::new(IpcBacking::Pipe { object, end }.encode(), access, NONBLOCK),
                    false,
                )
                .unwrap()
                .0
        };
        let r = open(&w, End::Reader, AccessMode::ReadOnly);
        let wfd = open(&w, End::Writer, AccessMode::WriteOnly);
        w.mem.map(MM, 0x10000, PAGE);
        w.mem.write(MM, 0x10000, b"ping");
        let mut f = syscall(SYS_WRITE, wfd, 0x10000, 4, A_SVC);
        assert_eq!((w.call(&mut f), f.x[0]), (RETURNED, 4), "served in EL1");
        let mut f = syscall(SYS_READ, r, 0x10000, 4, A_SVC);
        assert_eq!((w.call(&mut f), f.x[0]), (RETURNED, 4));
        assert_eq!(host_calls(&w), 0);
        let mut g = w.region.lock(object, &HostWait).unwrap();
        assert!(g.pipe().unwrap().is_backed());
        drop(g);
        // One stocked ring is left; a third pipe takes it, a fourth forwards.
        let mut backed = 0;
        for _ in 0..2 {
            let other = w.unbacked_pipe_object();
            let mut g = w.region.lock(other, &HostWait).unwrap();
            backed += usize::from(g.provide_ring_from_stock().unwrap());
        }
        assert_eq!(backed, 1);
    }

    /// An object lock is held only for short sections that never wait on
    /// the waiter: a host thread's, or an EL1 holder's that the host resumes
    /// to completion when a kick lands mid-section. So EL1 waits for the
    /// holder instead of turning a transfer that can complete into a host
    /// round trip (`object_busy_el1` in el1_ipc_pairs_blocking, n=8).
    #[test]
    fn el1_ipc_io_contended_object_lock_waits_for_its_holder_instead_of_forwarding() {
        let mut w = world();
        let t = w.table(w.a_tid);
        let (_r, wfd, object) = w.pipe(t, NONBLOCK);
        w.mem.map(MM, 0x10000, PAGE);
        w.mem.write(MM, 0x10000, b"ping");
        let region = w.region;
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let calling = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|s| {
            let calling = &calling;
            s.spawn(move || {
                // A holder stopped far longer than any bounded spin: it
                // releases only well after the call started waiting (the
                // green result waits for it whatever the timing).
                let guard = region.lock(object, &HostWait).unwrap();
                held_tx.send(()).unwrap();
                while !calling.load(Ordering::Acquire) {
                    core::hint::spin_loop();
                }
                for _ in 0..50_000_000u64 {
                    core::hint::spin_loop();
                }
                drop(guard);
            });
            held_rx.recv().unwrap();
            calling.store(true, Ordering::Release);
            assert_eq!(
                region.lock_holder(object),
                Some(carrick_el1_abi::ipc::IpcLockHolder::Host)
            );
            let mut f = syscall(SYS_WRITE, wfd, 0x10000, 4, A_SVC);
            assert_eq!(
                (w.call(&mut f), f.x[0]),
                (RETURNED, 4),
                "served once the holder releases"
            );
        });
        assert_eq!(host_calls(&w), 0);
        assert!(
            w.counters
                .ipc_leaves
                .iter()
                .all(|n| n.load(Ordering::Relaxed) == 0)
        );
    }

    #[test]
    fn el1_ipc_io_copy_faults_forward_before_effects_and_keep_prefixes() {
        let mut w = world();
        let t = w.table(w.a_tid);
        let (r, wfd, object) = w.pipe(t, BLOCK);
        let e = w.eventfd(t, 5, EventMode::Counter, NONBLOCK);
        let unread = |w: &World| {
            let mut g = w.region.lock(object, &HostWait).unwrap();
            g.pipe().unwrap().unread_bytes()
        };
        // Write from an unmapped buffer: forwarded unchanged, nothing staged.
        let mut f = syscall(SYS_WRITE, wfd, 0x300000, 100, A_SVC);
        let before = f;
        assert_eq!(w.call(&mut f), IpcServed::Forward);
        assert_eq!((f.x, f.elr), (before.x, before.elr));
        assert_eq!(unread(&w), 0);
        w.mem.write(MM, 0x100000, &[1; 8192]);
        let mut f = syscall(SYS_WRITE, wfd, 0x100000, 8192, A_SVC);
        assert_eq!((w.call(&mut f), f.x[0]), (RETURNED, 8192));
        // Read into an unmapped buffer: forwarded, the pipe keeps its bytes.
        let mut f = syscall(SYS_READ, r, 0x300000, 8192, A_SVC);
        assert_eq!(w.call(&mut f), IpcServed::Forward);
        assert_eq!(unread(&w), 8192);
        // Read whose second page is unmapped: the delivered prefix only.
        w.mem.map(MM, 0x400000, PAGE);
        let mut f = syscall(SYS_READ, r, 0x400000, 8192, A_SVC);
        assert_eq!((w.call(&mut f), f.x[0]), (RETURNED, 4096));
        assert_eq!(unread(&w), 4096);
        // An eventfd read whose copyout faults drains nothing.
        let mut f = syscall(SYS_READ, e, 0x300000, 8, A_SVC);
        assert_eq!(w.call(&mut f), IpcServed::Forward);
        let mut f = syscall(SYS_READ, e, 0x400000, 8, A_SVC);
        assert_eq!((w.call(&mut f), f.x[0]), (RETURNED, 8));
        assert_eq!(w.mem.read(MM, 0x400000, 8), 5u64.to_ne_bytes());
        // A blocking write faulting after progress hands its continuation
        // to the host: the published prefix stays, nothing is replayed.
        let mut f = syscall(SYS_READ, r, 0x400000, 4096, A_SVC);
        assert_eq!((w.call(&mut f), f.x[0]), (RETURNED, 4096));
        w.mem.write(MM, 0x500000, &[9; 4096]);
        let mut f = syscall(SYS_WRITE, wfd, 0x500000, 8192, A_SVC);
        let before = f;
        assert_eq!(w.call(&mut f), IpcServed::Handback);
        assert_eq!(f.x[8], IPC_HANDBACK_NR);
        assert_eq!(
            f.x[1..8],
            before.x[1..8],
            "only x0 and x8 carry the handback"
        );
        let op = handed_back(&w, &f);
        assert_eq!(
            (op.kind, op.progress.written, op.progress.len, op.handback),
            (IpcOpKind::PipeWrite, 4096, 8192, IpcHandback::Continue)
        );
        assert_eq!((op.orig_x0, op.nr), (before.x[0], SYS_WRITE as u32));
        assert_eq!(unread(&w), 4096);
        assert_eq!(
            w.counters
                .forwarded
                .iter()
                .map(|c| c.load(Ordering::Relaxed))
                .sum::<u64>(),
            0
        );
    }

    #[test]
    fn el1_ipc_io_host_backed_descriptions_forward_unchanged() {
        let mut w = world();
        let t = w.table(w.a_tid);
        let token = carrick_el1_abi::ipc::HostResourceToken::new(77).unwrap();
        let fd = w
            .host()
            .open(
                t,
                Fd(0),
                Description::new(
                    IpcBacking::Host(token).encode(),
                    AccessMode::ReadWrite,
                    BLOCK,
                ),
                false,
            )
            .unwrap();
        let mut f = syscall(SYS_READ, fd.0, 0x10000, 4, A_SVC);
        let before = f;
        assert_eq!(w.call(&mut f), IpcServed::Forward);
        assert_eq!(f.x, before.x);
        // A task with no published table is not served at all.
        w.map.withdraw(5);
        assert_eq!(w.call(&mut f), IpcServed::Forward);
    }

    /// A blocks reading, B (another process, same user VA) runs in the
    /// guest, the host closes A's fd and reuses its number, B writes and
    /// blocks; A resumes through its operation token, not its fd number.
    #[test]
    fn el1_ipc_io_blocked_read_resumes_by_token_after_fd_reuse() {
        let mut w = world();
        let a = w.table(w.a_tid);
        let (r, wfd, _) = w.pipe(a, BLOCK);
        let (r2, _w2, _) = w.pipe(a, BLOCK);
        w.fork_table(a, 202);
        let va = 0x7000;
        w.mem.map(MM, va, PAGE);
        w.mem.write(OTHER_MM, va, b"data");
        let b_write = syscall(SYS_WRITE, wfd, va, 4, B_SVC);
        w.queue(202, OTHER_MM, &b_write, B_SVC);
        let allocs = allocations();
        let mut f = syscall(SYS_READ, r, va, 16, A_SVC);
        let a_regs = f.x;
        assert_eq!(w.call(&mut f), SWITCHED, "A parks, B runs");
        assert_eq!(w.task.zone_mm.load(Ordering::Relaxed), OTHER_MM);
        // The host closes A's fd and the number is reused.
        assert_eq!(w.host().close(a, Fd(r)), Ok(None), "A's pin keeps it");
        let reused = w.eventfd(a, 42, EventMode::Counter, BLOCK);
        assert_eq!(reused, r);
        // B returns from the futex wait it was queued from, then writes.
        assert_eq!(f.elr, B_SVC);
        f = b_write;
        assert_eq!((w.call(&mut f), f.x[0]), (RETURNED, 4), "B writes");
        // B blocks on another empty pipe: the vCPU goes back to A.
        let mut g = syscall(SYS_READ, r2, va, 16, B_SVC);
        assert_eq!(w.call(&mut g), SWITCHED);
        assert_eq!(g.x, a_regs, "A's original arguments");
        reenter(&mut g, A_SVC);
        let served = w.call(&mut g);
        let allocated = allocations() - allocs;
        assert_eq!((served, g.x[0]), (RETURNED, 4));
        assert_eq!(w.mem.read(MM, va, 4), b"data");
        assert_eq!(w.task.zone_mm.load(Ordering::Relaxed), MM);
        assert_eq!(allocated, 0, "no allocation for admitted I/O");
        assert_eq!(host_calls(&w), 0, "no host exit or adapter call");
        assert_eq!(w.zone.counters.el1_parks.load(Ordering::Relaxed), 2);
        assert_eq!(g.elr, A_SVC + 4, "completed read returns past its SVC");
        let current = w.zone.slot(SLOT).current().unwrap();
        assert!(!w.zone.record(current).has_object_operation());
        // The next call at the same libc SVC must resolve the reused number,
        // not replay the finished pipe operation or return its old count.
        let mut next = syscall(SYS_READ, reused, va, 8, A_SVC);
        assert_eq!((w.call(&mut next), next.x[0]), (RETURNED, 8));
        assert_eq!(w.mem.read(MM, va, 8), 42u64.to_ne_bytes());
        assert_eq!(next.elr, A_SVC + 4);
        assert!(!w.zone.record(current).has_object_operation());
    }

    /// A blocking write larger than the pipe suspends with its progress and
    /// resumes from it: B reads every byte exactly once, all in the guest.
    #[test]
    fn el1_ipc_io_large_write_suspends_without_replay() {
        let mut w = world();
        let a = w.table(w.a_tid);
        let (r, wfd, _) = w.pipe(a, BLOCK);
        let (r2, _, _) = w.pipe(a, BLOCK);
        w.fork_table(a, 202);
        let total = 2 * 65536 + 7;
        let source: Vec<u8> = (0..total).map(|n| (n % 251) as u8).collect();
        w.mem.write(MM, 0x100000, &source);
        w.mem.map(OTHER_MM, 0x100000, 65536);
        let b_read = syscall(SYS_READ, r, 0x100000, 65536, B_SVC);
        w.queue(202, OTHER_MM, &b_read, B_SVC);
        let mut received = Vec::with_capacity(total);
        let mut chunk = [0u8; 65536];
        let allocs = allocations();
        let mut f = syscall(SYS_WRITE, wfd, 0x100000, total as u64, A_SVC);
        assert_eq!(w.call(&mut f), SWITCHED, "A writes 64 KiB and parks");
        assert_eq!(f.elr, B_SVC);
        f = b_read;
        let mut a_result = None;
        let mut b_turns = 0;
        loop {
            // B: read until the pipe is empty, then park.
            if w.task.zone_mm.load(Ordering::Relaxed) == OTHER_MM {
                match w.call(&mut f) {
                    RETURNED => {
                        let n = f.x[0] as usize;
                        {
                            let pages = w.mem.pages.borrow();
                            for (i, b) in chunk[..n].iter_mut().enumerate() {
                                let at = 0x100000 + i as u64;
                                *b = pages[&(OTHER_MM, at & !(PAGE - 1))][(at % PAGE) as usize];
                            }
                        }
                        received.extend_from_slice(&chunk[..n]);
                        b_turns += 1;
                        if received.len() == total {
                            break;
                        }
                        f = syscall(SYS_READ, r, 0x100000, 65536, B_SVC);
                    }
                    SWITCHED => reenter(&mut f, A_SVC),
                    other => panic!("B: {other:?}"),
                }
            } else {
                // A: its one write, re-entered; once done it blocks.
                match w.call(&mut f) {
                    RETURNED => {
                        a_result = Some(f.x[0]);
                        f = syscall(SYS_READ, r2, 0x100000, 1, A_SVC);
                    }
                    SWITCHED => reenter(&mut f, B_SVC),
                    other => panic!("A: {other:?}"),
                }
            }
        }
        assert_eq!(received, source, "no byte replayed or lost");
        assert_eq!(a_result, Some(total as u64), "write returns its full count");
        assert!(b_turns >= 3);
        assert_eq!(allocations() - allocs, 0);
        assert_eq!(host_calls(&w), 0);
    }

    /// The reader goes away while a large blocking write is suspended with
    /// progress: the write returns its count and asks for SIGPIPE.
    #[test]
    fn el1_ipc_io_epipe_after_progress_returns_count_and_requests_sigpipe() {
        let mut w = world();
        let a = w.table(w.a_tid);
        let (r, wfd, _) = w.pipe(a, BLOCK);
        let (r2, _, _) = w.pipe(a, BLOCK);
        w.fork_table(a, 202);
        w.mem.write(MM, 0x100000, &[3; 65536 + 100]);
        w.mem.map(OTHER_MM, 0x100000, PAGE);
        let b_block = syscall(SYS_READ, r2, 0x100000, 1, B_SVC);
        w.queue(202, OTHER_MM, &b_block, B_SVC);
        let mut f = syscall(SYS_WRITE, wfd, 0x100000, 65536 + 100, A_SVC);
        assert_eq!(w.call(&mut f), SWITCHED);
        // Every read end closes (A's table and B's forked copy).
        w.host_close(a, r);
        let b = TableId::from_raw(w.map.lookup(202).unwrap());
        w.host_close(b, r);
        assert_eq!(f.elr, B_SVC);
        f = b_block;
        assert_eq!(w.call(&mut f), SWITCHED, "B blocks; A was woken");
        reenter(&mut f, A_SVC);
        assert_eq!(w.call(&mut f), IpcServed::Handback);
        assert_eq!(f.x[8], IPC_HANDBACK_NR);
        let op = handed_back(&w, &f);
        assert_eq!((op.handback, op.result), (IpcHandback::Sigpipe, 65536));
        assert_eq!(op.nr, SYS_WRITE as u32);
        // Without progress, EPIPE is the host's to raise: forward unchanged.
        let mut f = syscall(SYS_WRITE, wfd, 0x100000, 10, A_SVC);
        assert_eq!(w.call(&mut f), IpcServed::Forward);
    }

    /// A blocked eventfd write uses the value it copied before blocking,
    /// even if the user buffer changes while it waits (eventfd(2)).
    #[test]
    fn el1_ipc_io_blocked_eventfd_write_keeps_its_value() {
        let mut w = world();
        let a = w.table(w.a_tid);
        let e = w.eventfd(a, 0, EventMode::Counter, BLOCK);
        let (r2, _, _) = w.pipe(a, BLOCK);
        w.fork_table(a, 202);
        let object = {
            let d = w.host().get(a, Fd(e)).unwrap();
            match IpcBacking::decode(d.backing) {
                Some(IpcBacking::EventFd { object }) => object,
                other => panic!("{other:?}"),
            }
        };
        w.region
            .lock(object, &HostWait)
            .unwrap()
            .eventfd()
            .unwrap()
            .try_write(u64::MAX - 1)
            .result
            .unwrap();
        w.mem.write(MM, 0x10000, &5u64.to_ne_bytes());
        w.mem.map(OTHER_MM, 0x10000, PAGE);
        let b_read = syscall(SYS_READ, e, 0x10000, 8, B_SVC);
        w.queue(202, OTHER_MM, &b_read, B_SVC);
        let mut f = syscall(SYS_WRITE, e, 0x10000, 8, A_SVC);
        assert_eq!(w.call(&mut f), SWITCHED, "A's write would overflow: parks");
        // The writer's buffer changes while it is blocked.
        w.mem.write(MM, 0x10000, &9u64.to_ne_bytes());
        f = b_read;
        assert_eq!((w.call(&mut f), f.x[0]), (RETURNED, 8), "B drains");
        let mut g = syscall(SYS_READ, r2, 0x10000, 1, B_SVC);
        assert_eq!(w.call(&mut g), SWITCHED);
        reenter(&mut g, A_SVC);
        assert_eq!((w.call(&mut g), g.x[0]), (RETURNED, 8));
        let value = w
            .region
            .lock(object, &HostWait)
            .unwrap()
            .eventfd()
            .unwrap()
            .value();
        assert_eq!(value, 5, "the value copied before blocking");
    }

    /// Dispatch maps the adapter onto actions and counters: a served write
    /// counts as served, never forwarded.
    #[test]
    fn el1_ipc_io_dispatch_serves_ipc_without_the_host() {
        let w = world();
        let t = w.table(w.a_tid);
        let (_r, wfd, _) = w.pipe(t, BLOCK);
        let tasks: Vec<CurrentTask> = (0..=SLOT.raw() as usize)
            .map(|_| CurrentTask::new())
            .collect();
        let task = &tasks[SLOT.raw() as usize];
        task.set(El1TaskId::from_linux_tid(101), 1, 5);
        task.zone_mm.store(MM, Ordering::Relaxed);
        let venue = w.venue();
        // SAFETY: all-zero is a valid empty name cache.
        let names: &carrick_el1_abi::InotifyNameCache = unsafe {
            &*std::alloc::alloc_zeroed(Layout::new::<carrick_el1_abi::InotifyNameCache>()).cast()
        };
        let mut cpu = FakeCpu::default();
        // The dispatcher copies through EL1's validated user copy, which in a
        // host test reads process memory directly.
        let mut byte = [b'x'];
        let mut frame = syscall(SYS_WRITE, wfd, byte.as_mut_ptr() as u64, 1, A_SVC);
        let action = crate::personality::dispatch::dispatch_syscall_with_ipc(
            &mut frame,
            w.counters,
            &tasks,
            &[],
            &[],
            &[],
            &[],
            names,
            Some(crate::personality::dispatch::Zone {
                tables: &w.zone,
                cpu: &mut cpu,
                user: &HardwareUserWord,
            }),
            Some(&venue),
            |_| core::ptr::null_mut(),
        );
        assert_eq!(action, carrick_el1_abi::Action::Served);
        assert_eq!(frame.x[0], 1);
        assert_eq!(w.counters.served[SYS_WRITE].load(Ordering::Relaxed), 1);
        assert_eq!(host_calls(&w), 0);
    }

    /// The slot's task table as EL1 publishes it for the thread `w.task`
    /// names, with host work pending (a kick, an owed wake or a signal).
    fn slot_tasks_with_host_work(w: &World) -> Vec<CurrentTask> {
        let tasks: Vec<CurrentTask> = (0..=SLOT.raw() as usize)
            .map(|_| CurrentTask::new())
            .collect();
        let task = &tasks[SLOT.raw() as usize];
        for (to, from) in [
            (&task.task_id, &w.task.task_id),
            (&task.thread_serial, &w.task.thread_serial),
            (&task.file_table, &w.task.file_table),
            (&task.zone_mm, &w.task.zone_mm),
            (&task.generation, &w.task.generation),
        ] {
            to.store(from.load(Ordering::Relaxed), Ordering::Relaxed);
        }
        task.mark_pending_host_work();
        tasks
    }

    /// One trap through the EL1 syscall dispatcher on the slot.
    fn dispatch(
        w: &World,
        frame: &mut TrapFrame,
        tasks: &[CurrentTask],
    ) -> carrick_el1_abi::Action {
        let venue = w.venue();
        // SAFETY: all-zero is a valid empty name cache.
        let names: &carrick_el1_abi::InotifyNameCache = unsafe {
            &*std::alloc::alloc_zeroed(Layout::new::<carrick_el1_abi::InotifyNameCache>()).cast()
        };
        let mut cpu = FakeCpu::default();
        crate::personality::dispatch::dispatch_syscall_with_ipc(
            frame,
            w.counters,
            tasks,
            &[],
            &[],
            &[],
            &[],
            names,
            Some(crate::personality::dispatch::Zone {
                tables: &w.zone,
                cpu: &mut cpu,
                user: &HardwareUserWord,
            }),
            Some(&venue),
            |_| core::ptr::null_mut(),
        )
    }

    /// A woken thread re-issues its SVC to resume the operation its record
    /// owns. Pending host work on the slot must not forward that SVC before
    /// the operation is taken: the host would run the call afresh (consuming
    /// the value) while the record kept the operation, and the thread's next
    /// read or write would resume the stale one instead (a write turned into
    /// a second read: both sides of a ping-pong parked reading, every write
    /// consumed; el1_ipc_two_processes_blocking under guest admission).
    #[test]
    fn el1_ipc_io_pending_host_work_cannot_orphan_a_resumed_operation() {
        let mut w = world();
        let a = w.table(w.a_tid);
        let e = w.eventfd(a, 0, EventMode::Counter, BLOCK);
        let (r2, _, _) = w.pipe(a, BLOCK);
        w.fork_table(a, 202);
        // A's buffer is real memory: the dispatcher's validated copy writes it.
        let mut value = [0u8; 8];
        let buf = value.as_mut_ptr() as u64;
        w.mem.map(MM, buf, 8);
        w.mem.write(OTHER_MM, 0x10000, &7u64.to_ne_bytes());
        let b_write = syscall(SYS_WRITE, e, 0x10000, 8, B_SVC);
        w.queue(202, OTHER_MM, &b_write, B_SVC);
        let mut f = syscall(SYS_READ, e, buf, 8, A_SVC);
        assert_eq!(w.call(&mut f), SWITCHED, "A reads nothing and parks");
        f = b_write;
        assert_eq!((w.call(&mut f), f.x[0]), (RETURNED, 8), "B writes, A woken");
        let mut g = syscall(SYS_READ, r2, 0x10000, 1, B_SVC);
        assert_eq!(w.call(&mut g), SWITCHED, "B parks: the vCPU runs A");
        reenter(&mut g, A_SVC);
        let current = w.zone.slot(SLOT).current().unwrap();
        assert!(w.zone.record(current).has_object_operation());
        // The slot's task as EL1 published it for A, with host work pending.
        let tasks = slot_tasks_with_host_work(&w);
        let task = &tasks[SLOT.raw() as usize];
        let action = dispatch(&w, &mut g, &tasks);
        assert_eq!(
            (action, g.x[0]),
            (carrick_el1_abi::Action::ServedWithWork, 8),
            "the owned read completes and leaves with its result"
        );
        assert_eq!(u64::from_ne_bytes(value), 7);
        assert!(!w.zone.record(current).has_object_operation());
        assert_eq!(task.served_with_work.load(Ordering::Acquire), 1);
    }

    /// Host work pending at entry (the host kicked the vCPU, or a write
    /// owed a host-parked peer a wake) must not send a pipe read that
    /// completes right now to the host: EL1 serves it and leaves with the
    /// work (el1_ipc_two_processes_blocking lost one served read per fork,
    /// 511 of 512). Linux runs a signal pending at entry after the call
    /// returns, which is what the host does with the work on the way out.
    #[test]
    fn el1_ipc_io_pending_host_work_serves_a_completing_transfer() {
        let w = world();
        let t = w.table(w.a_tid);
        let (r, wfd, _) = w.pipe(t, BLOCK);
        let tasks = slot_tasks_with_host_work(&w);
        let task = &tasks[SLOT.raw() as usize];
        let mut out = *b"ab";
        let mut f = syscall(SYS_WRITE, wfd, out.as_mut_ptr() as u64, 2, A_SVC);
        assert_eq!(
            (dispatch(&w, &mut f, &tasks), f.x[0]),
            (carrick_el1_abi::Action::ServedWithWork, 2),
            "a write with room completes in EL1"
        );
        let mut buf = [0u8; 2];
        let mut f = syscall(SYS_READ, r, buf.as_mut_ptr() as u64, 2, A_SVC);
        assert_eq!(
            (dispatch(&w, &mut f, &tasks), f.x[0]),
            (carrick_el1_abi::Action::ServedWithWork, 2),
            "a read with data completes in EL1"
        );
        assert_eq!(&buf, b"ab");
        assert_eq!(task.orig_arg0.load(Ordering::Relaxed), r as u64);
        assert!(task.has_pending_host_work(), "the host still sees its work");
        assert_eq!(task.served_with_work.load(Ordering::Acquire), 1);
        assert_eq!(w.counters.served[SYS_READ].load(Ordering::Relaxed), 1);
        assert_eq!(w.counters.served[SYS_WRITE].load(Ordering::Relaxed), 1);
        assert_eq!(host_calls(&w), 0);
    }

    /// A read that would block while host work is pending (a kick of this
    /// vCPU, an owed host wake, possibly a signal) parks in the zone and the
    /// vCPU leaves for the host at once, running nothing else here: the host
    /// settles the parked thread at this boundary, and its enrollment samples
    /// pending signals, so a signal still interrupts the wait (Linux checks
    /// for one before it sleeps). Forwarding the read instead moved the wait
    /// to the host, and its host subscription owed every later peer write a
    /// host wake, marking more slots: under 64 concurrent pairs whole-run
    /// witnesses lost served reads (el1_ipc_pairs_blocking, 18687/18688).
    #[test]
    fn el1_ipc_io_pending_host_work_parks_a_fresh_read_that_would_block() {
        let w = world();
        let t = w.table(w.a_tid);
        let (r, _wfd, _) = w.pipe(t, BLOCK);
        // Another thread is runnable here: a park would switch to it.
        w.mem.write(OTHER_MM, 0x10000, &[0; 8]);
        w.fork_table(t, 202);
        let b = syscall(SYS_READ, r, 0x10000, 1, B_SVC);
        w.queue(202, OTHER_MM, &b, B_SVC);
        let tasks = slot_tasks_with_host_work(&w);
        let task = &tasks[SLOT.raw() as usize];
        let mut buf = [0u8; 1];
        let mut f = syscall(SYS_READ, r, buf.as_mut_ptr() as u64, 1, A_SVC);
        assert_eq!(
            dispatch(&w, &mut f, &tasks),
            carrick_el1_abi::Action::Idle,
            "parked in the zone; the vCPU leaves for the host"
        );
        assert_eq!(w.zone.counters.el1_parks.load(Ordering::Relaxed), 1);
        assert_eq!(
            w.zone.slot(SLOT).current(),
            None,
            "nothing else was switched in"
        );
        assert!(task.has_pending_host_work(), "the host still sees its work");
        assert_eq!(task.served_with_work.load(Ordering::Acquire), 0);
        assert_eq!(w.counters.forwarded[SYS_READ].load(Ordering::Relaxed), 0);
        assert_eq!(host_calls(&w), 0);
    }

    /// A woken read re-enters to resume its owned operation and finds the
    /// pipe empty again while host work is pending: it parks again in the
    /// zone with its operation and leaves for the host, which settles it (a
    /// pending signal interrupts it there). No handback moves the wait to
    /// the host.
    #[test]
    fn el1_ipc_io_pending_host_work_reparks_a_resumed_read_that_would_block() {
        let mut w = world();
        let a = w.table(w.a_tid);
        let (r, wfd, _) = w.pipe(a, BLOCK);
        w.fork_table(a, 202);
        let mut buf = [0u8; 1];
        let a_buf = buf.as_mut_ptr() as u64;
        w.mem.map(MM, a_buf, 1);
        w.mem.write(OTHER_MM, 0x10000, b"z");
        let b_write = syscall(SYS_WRITE, wfd, 0x10000, 1, B_SVC);
        w.queue(202, OTHER_MM, &b_write, B_SVC);
        let mut f = syscall(SYS_READ, r, a_buf, 1, A_SVC);
        assert_eq!(w.call(&mut f), SWITCHED, "A reads nothing and parks");
        f = b_write;
        assert_eq!((w.call(&mut f), f.x[0]), (RETURNED, 1), "B writes, A woken");
        let mut g = syscall(SYS_READ, r, 0x10000, 1, B_SVC);
        assert_eq!((w.call(&mut g), g.x[0]), (RETURNED, 1), "B takes the byte");
        let mut g = syscall(SYS_READ, r, 0x10000, 1, B_SVC);
        assert_eq!(w.call(&mut g), SWITCHED, "B parks: the vCPU runs A");
        reenter(&mut g, A_SVC);
        let current = w.zone.slot(SLOT).current().unwrap();
        assert!(w.zone.record(current).has_object_operation());
        let parks = w.zone.counters.el1_parks.load(Ordering::Relaxed);
        let tasks = slot_tasks_with_host_work(&w);
        let task = &tasks[SLOT.raw() as usize];
        assert_eq!(
            dispatch(&w, &mut g, &tasks),
            carrick_el1_abi::Action::Idle,
            "parked again with its operation; the vCPU leaves"
        );
        assert_ne!(g.x[8], IPC_HANDBACK_NR, "nothing is handed back");
        assert!(
            w.zone.record(current).has_object_operation(),
            "the parked record still owns the read"
        );
        assert_eq!(w.zone.counters.el1_parks.load(Ordering::Relaxed), parks + 1);
        assert!(task.has_pending_host_work(), "the host still sees its work");
        assert_eq!(task.served_with_work.load(Ordering::Acquire), 0);
    }

    /// N communicating pairs of processes, pipes both ways plus an eventfd,
    /// after setup: exact payloads, zero allocations, zero host calls, and
    /// exactly twice the copy work for twice the rounds.
    fn pairs(n: usize, rounds: usize) -> (usize, usize, u64) {
        let mut w = world();
        struct Pair {
            a: u64,
            b: u64,
            ab: (i32, i32),
            ba: (i32, i32),
            ev: i32,
        }
        let mut all = Vec::new();
        for p in 0..n as u64 {
            let (a, b) = (1000 + 2 * p, 1001 + 2 * p);
            let ta = w.table(a);
            let ab = w.pipe(ta, BLOCK);
            let ba = w.pipe(ta, BLOCK);
            let ev = w.eventfd(ta, 0, EventMode::Semaphore, BLOCK);
            w.fork_table(ta, b);
            all.push(Pair {
                a,
                b,
                ab: (ab.0, ab.1),
                ba: (ba.0, ba.1),
                ev,
            });
        }
        // Both processes use the same user VAs in their own spaces; here
        // one space per role stands for them.
        w.mem.write(MM, 0x10000, &[0x5a; 64]);
        w.mem.map(MM, 0x20000, PAGE);
        w.mem.write(MM, 0x30000, &1u64.to_ne_bytes());
        let copied = Cell::new(0usize);
        let allocs = allocations();
        for _ in 0..rounds {
            for p in &all {
                let mut io = |tid: u64, nr, fd, buf, len| {
                    w.task.task_id.store(tid, Ordering::Relaxed);
                    w.task.file_table.store(tid, Ordering::Relaxed);
                    let mut f = syscall(nr, fd, buf, len, A_SVC);
                    assert_eq!(w.call(&mut f), RETURNED);
                    copied.set(copied.get() + f.x[0] as usize);
                    f.x[0]
                };
                assert_eq!(io(p.a, SYS_WRITE, p.ab.1, 0x10000, 64), 64);
                assert_eq!(io(p.b, SYS_READ, p.ab.0, 0x20000, 64), 64);
                assert_eq!(io(p.b, SYS_WRITE, p.ba.1, 0x20000, 64), 64);
                assert_eq!(io(p.a, SYS_READ, p.ba.0, 0x20000, 64), 64);
                assert_eq!(io(p.b, SYS_WRITE, p.ev, 0x30000, 8), 8);
                assert_eq!(io(p.a, SYS_READ, p.ev, 0x20000, 8), 8);
            }
        }
        let allocated = allocations() - allocs;
        assert_eq!(w.mem.read(MM, 0x20000, 8), 1u64.to_ne_bytes());
        (copied.get(), allocated, host_calls(&w))
    }

    #[test]
    fn el1_ipc_io_steady_state_scales_without_host_calls_or_allocation() {
        // Positive control: the counter sees this thread's allocations.
        let before = allocations();
        let probe = std::hint::black_box(Vec::<u8>::with_capacity(8));
        assert!(allocations() > before);
        drop(probe);
        for n in [1, 8, 64] {
            let (bytes, allocs, host) = pairs(n, 8);
            assert_eq!(bytes, n * 8 * (4 * 64 + 2 * 8), "N={n}");
            assert_eq!((allocs, host), (0, 0), "N={n}");
            let (bytes2, allocs2, host2) = pairs(n, 16);
            assert_eq!(bytes2, 2 * bytes, "round-count scaling at N={n}");
            assert_eq!((allocs2, host2), (0, 0));
        }
    }
}
