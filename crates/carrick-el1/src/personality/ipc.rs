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
//! replayed.
//!
//! # Leaving EL1
//!
//! - An unchanged `Forward` happens only before any effect of a call that
//!   never parked (host-backed descriptions, unpublished tables, contended
//!   locks, a first copy that faults, EPIPE with no progress).
//! - After progress, or for any resumed operation, EL1 never forwards the
//!   original call. It completes it, or hands the owned continuation to the
//!   host with an [`IPC_HANDBACK_NR`] frame (`x0` result, `x1`
//!   [`HandbackFlags`], `x2` raw operation token, `x3` a backing token whose
//!   release is owed). The host venue (runtime integration) finishes it.

use super::sched::{Sched, Served, ThreadCpu, UserWord};
use crate::substrate::file::UserCopy;
use crate::substrate::ipc::{
    PrefixCopy, StepStatus, from_sched_token, to_sched_token, transfer, wait_key,
};
use crate::substrate::sched::object_wait::OperationResumePc;
use carrick_el1_abi::ipc::fd::{AccessMode, Error as FdError, Fd, TableId};
use carrick_el1_abi::ipc::pipe::{WaitFor, WakeSet};
use carrick_el1_abi::ipc::{
    BackingToken, IpcBacking, IpcEventValue, IpcMmKey, IpcObjectHandle, IpcOpKind, IpcOpToken,
    IpcOperation, IpcRegion, IpcReleased, IpcTaskKey, IpcUserVa, OfdPin, RawTableId, WriteProgress,
};
use carrick_el1_abi::{CurrentTask, EL1_GUEST_LOCK_SPINS, TrapFrame};
use carrick_sched_core::object_wait::{ObjectWaitError, ObjectWaitSnapshot};
use carrick_sched_core::{BoundedSpin, WakeEffects};
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

/// Private host call carrying an owned IPC continuation or owed completion
/// work out of EL1 (next to `SYS_CARRICK_EL1_CONTROL`).
pub const IPC_HANDBACK_NR: u64 = 0xCA88_0002;

/// What an [`IPC_HANDBACK_NR`] frame asks the host to do.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HandbackFlags(pub u64);
impl HandbackFlags {
    /// `x2` is a raw [`IpcOpToken`]: finish that operation (its record holds
    /// the pinned description, buffer, length and progress); `x0` is unused.
    pub const CONTINUE: u64 = 1;
    /// Deliver SIGPIPE to the calling thread along with the result in `x0`.
    pub const SIGPIPE: u64 = 2;
    /// Release the backing named by `x3` (a description's final hold went
    /// away in EL1 and EL1 could not release it itself).
    pub const RELEASE: u64 = 4;
}

/// Where the venue finds a task's descriptor table in the shared authority.
/// Returns a table only when it is the task's complete descriptor namespace
/// (a missing descriptor is then EBADF, not a host descriptor).
pub trait IpcTables {
    fn table_of(&self, task: &CurrentTask) -> Option<RawTableId>;
}

/// The shared IPC authority as this venue maps it.
pub struct IpcVenue<'a> {
    pub region: &'a IpcRegion<'a>,
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

/// The shared IPC authority EL1 serves from. None until the runtime
/// integration places the region in the EL1 address space and publishes
/// each task's table ([`IpcTables`]); until then every call forwards.
pub fn guest_venue() -> Option<IpcVenue<'static>> {
    None
}

const EL1_WAIT: BoundedSpin = BoundedSpin(EL1_GUEST_LOCK_SPINS);

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
    let mut owed = Owed::default();
    let (token, op, resumed) = match sched.take_object_operation() {
        // The slot's record is not this task's: the host settles it.
        Err(_) => return IpcServed::Forward,
        Ok(Some(t)) => {
            let Some(token) = from_sched_token(t) else {
                return IpcServed::Forward;
            };
            let Ok(op) = venue.region.operation(&token) else {
                return IpcServed::Forward;
            };
            if op.task != task_key(sched.task) || op.mm != mm_key(sched.task) {
                return handback_continue(frame, token, op, venue, &mut owed);
            }
            (token, op, true)
        }
        Ok(None) => match admit(sched, frame, venue, user, &mut owed) {
            Admission::Admitted(token, op) => (token, op, false),
            Admission::Immediate(result) => return complete(frame, result, false, &owed),
            Admission::Forward => return owed.forward(frame),
        },
    };
    run(sched, frame, venue, user, token, op, resumed, owed)
}

/// Work a call owes the host beyond its result.
#[derive(Default)]
struct Owed {
    release: Option<BackingToken>,
}

impl Owed {
    /// Forward unchanged, unless this call dropped its description's final
    /// hold: every descriptor naming it was closed concurrently, so the call
    /// completes as if it ran after the close (EBADF) and the release is
    /// handed to the host with it, never lost.
    fn forward(&self, frame: &mut TrapFrame) -> IpcServed {
        match self.release {
            None => IpcServed::Forward,
            Some(_) => handback_result(frame, linux::EBADF, 0, self),
        }
    }
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
}

/// Decode a fresh call and take ownership of it, before any effect.
fn admit<C: ThreadCpu, U: UserWord, M: UserCopy>(
    sched: &mut Sched<'_, C, U>,
    frame: &TrapFrame,
    venue: &IpcVenue<'_>,
    user: &mut M,
    owed: &mut Owed,
) -> Admission {
    let task = sched.task;
    let region = venue.region;
    let Some(table) = venue.tables.table_of(task) else {
        return Admission::Forward;
    };
    let fda = region.fd(EL1_WAIT);
    let (pin, desc) = match fda.pin(TableId::from_raw(table), Fd(frame.x[0] as i32)) {
        Ok(found) => found,
        Err(FdError::BadFd) => return Admission::Immediate(linux::EBADF),
        Err(_) => return Admission::Forward,
    };
    let reading = frame.x[8] as usize == SYS_READ;
    let (kind, object) = match IpcBacking::decode(desc.backing) {
        Some(IpcBacking::Pipe { object, .. }) if reading => (IpcOpKind::PipeRead, object),
        Some(IpcBacking::Pipe { object, .. }) => (IpcOpKind::PipeWrite, object),
        Some(IpcBacking::EventFd { object }) if reading => (IpcOpKind::EventFdRead, object),
        Some(IpcBacking::EventFd { object }) => (IpcOpKind::EventFdWrite, object),
        // Host-backed (or unknown) descriptions stay host-served.
        _ => {
            release_pin(sched, pin, region, owed);
            return Admission::Forward;
        }
    };
    let permitted = match desc.access {
        AccessMode::ReadWrite => true,
        AccessMode::ReadOnly => reading,
        AccessMode::WriteOnly => !reading,
        AccessMode::Path => false,
    };
    let count = frame.x[2].min(linux::MAX_RW_COUNT);
    let immediate = if !permitted {
        Some(linux::EBADF)
    } else if matches!(kind, IpcOpKind::PipeRead | IpcOpKind::PipeWrite) && count == 0 {
        Some(0)
    } else if matches!(kind, IpcOpKind::EventFdRead | IpcOpKind::EventFdWrite)
        && count < linux::EVENTFD_WORD
    {
        Some(linux::EINVAL)
    } else {
        None
    };
    if let Some(result) = immediate {
        release_pin(sched, pin, region, owed);
        return Admission::Immediate(result);
    }
    let len = match kind {
        IpcOpKind::EventFdRead | IpcOpKind::EventFdWrite => linux::EVENTFD_WORD,
        _ => count,
    };
    // eventfd(2): a write copies its value once, before it can block.
    let mut value = [0u8; linux::EVENTFD_WORD as usize];
    if kind == IpcOpKind::EventFdWrite
        && PrefixCopy::new(user).copy_in(&mut value, frame.x[1]) != value.len()
    {
        // No effect yet: the host resolves the fault (first touch or EFAULT).
        release_pin(sched, pin, region, owed);
        return Admission::Forward;
    }
    let op = IpcOperation {
        kind,
        nonblock: 0,
        pin: pin.into_raw(),
        object: object.to_raw(),
        task: task_key(task),
        mm: mm_key(task),
        buf: IpcUserVa(frame.x[1]),
        progress: WriteProgress::new(len),
        park_seq: 0,
        value: IpcEventValue(u64::from_ne_bytes(value)),
    };
    match region.begin_operation(op) {
        Ok(token) => Admission::Admitted(token, op),
        Err(_) => {
            release_pin(sched, OfdPin::from_raw(op.pin), region, owed);
            Admission::Forward
        }
    }
}

/// Drop a description pin. A final release is performed here (waking the
/// peer lane: EOF for readers, EPIPE for writers) or owed to the host.
fn release_pin<C: ThreadCpu, U: UserWord>(
    sched: &mut Sched<'_, C, U>,
    pin: OfdPin,
    region: &IpcRegion<'_>,
    owed: &mut Owed,
) {
    let Ok(Some(description)) = region.fd(EL1_WAIT).unpin(pin) else {
        return;
    };
    match region.release_backing(description.backing, &EL1_WAIT) {
        Ok(IpcReleased::Object { wake, freed }) => {
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
        Ok(IpcReleased::Host(_)) | Err(_) => owed.release = Some(description.backing),
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
    mut owed: Owed,
) -> IpcServed {
    let region = venue.region;
    let object = IpcObjectHandle::from_raw(op.object);
    let mut copy = PrefixCopy::new(user);
    loop {
        let nonblock = {
            let pin = OfdPin::from_raw(op.pin);
            let flags = region.fd(EL1_WAIT).pinned(&pin).map(|d| d.flags.nonblock);
            op.pin = pin.into_raw();
            match flags {
                Ok(nonblock) => nonblock,
                Err(_) => return bail(sched, frame, token, op, resumed, venue, owed),
            }
        };
        let mut guard = match region.lock(object, &EL1_WAIT) {
            Ok(guard) => guard,
            Err(_) => return bail(sched, frame, token, op, resumed, venue, owed),
        };
        let (status, wake) = match transfer(&mut guard, &mut op, &mut copy) {
            Ok(step) => step,
            Err(_) => {
                drop(guard);
                return bail(sched, frame, token, op, resumed, venue, owed);
            }
        };
        let published = guard.publish(wake);
        if published.host_owed {
            sched.task.mark_pending_host_work();
        }
        let effects = notify(sched, object, wake);
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
                    return bail(sched, frame, token, op, resumed, venue, owed);
                };
                match park(sched, frame, region, token, op, object, lane, snap) {
                    Parked::Done(served) => return served,
                    Parked::Retry(t) => {
                        token = t;
                        continue;
                    }
                    Parked::Refused(t) => return bail(sched, frame, t, op, resumed, venue, owed),
                }
            }
            StepStatus::Broken if written == 0 && !resumed => {
                // No effect yet: the host re-runs the call (EPIPE + SIGPIPE).
                finish(sched, token, region, &mut owed);
                return owed.forward(frame);
            }
            StepStatus::Broken => {
                finish(sched, token, region, &mut owed);
                let result = if written > 0 {
                    written as i64
                } else {
                    linux::EPIPE
                };
                return handback_result(frame, result, HandbackFlags::SIGPIPE, &owed);
            }
            StepStatus::Fault if written == 0 && !resumed => {
                // The host resolves the fault (first touch or EFAULT).
                finish(sched, token, region, &mut owed);
                return owed.forward(frame);
            }
            StepStatus::Fault if op.kind == IpcOpKind::PipeRead => written as i64,
            StepStatus::Fault => return bail(sched, frame, token, op, resumed, venue, owed),
        };
        finish(sched, token, region, &mut owed);
        return complete(frame, result, false, &owed);
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
        Ok(parked) => Parked::Done(match sched.resume_after_object_park(frame, parked, 0) {
            Some(Served::Returned { switched }) => IpcServed::Returned { switched },
            Some(Served::Idle) | None => IpcServed::Idle,
        }),
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
    owed: &mut Owed,
) {
    if let Ok(op) = region.finish_operation(token) {
        release_pin(sched, OfdPin::from_raw(op.pin), region, owed);
    }
}

/// The call cannot continue in EL1: before any effect of a never-parked
/// call, forward it unchanged; otherwise hand the owned continuation back.
fn bail<C: ThreadCpu, U: UserWord>(
    sched: &mut Sched<'_, C, U>,
    frame: &mut TrapFrame,
    token: IpcOpToken,
    op: IpcOperation,
    resumed: bool,
    venue: &IpcVenue<'_>,
    mut owed: Owed,
) -> IpcServed {
    if op.progress.written == 0 && !resumed {
        finish(sched, token, venue.region, &mut owed);
        return owed.forward(frame);
    }
    handback_continue(frame, token, op, venue, &mut owed)
}

fn handback_continue(
    frame: &mut TrapFrame,
    token: IpcOpToken,
    op: IpcOperation,
    venue: &IpcVenue<'_>,
    owed: &mut Owed,
) -> IpcServed {
    let _ = venue.region.update_operation(&token, op);
    let raw = token.into_raw();
    frame.x[8] = IPC_HANDBACK_NR;
    frame.x[0] = 0;
    frame.x[1] = HandbackFlags::CONTINUE
        | if owed.release.is_some() {
            HandbackFlags::RELEASE
        } else {
            0
        };
    frame.x[2] = u64::from(raw.index) | (u64::from(raw.generation) << 32);
    frame.x[3] = owed.release.map_or(0, |b| b.0);
    IpcServed::Handback
}

fn handback_result(frame: &mut TrapFrame, result: i64, flags: u64, owed: &Owed) -> IpcServed {
    frame.x[8] = IPC_HANDBACK_NR;
    frame.x[0] = result as u64;
    frame.x[1] = flags
        | if owed.release.is_some() {
            HandbackFlags::RELEASE
        } else {
            0
        };
    frame.x[2] = 0;
    frame.x[3] = owed.release.map_or(0, |b| b.0);
    IpcServed::Handback
}

fn complete(frame: &mut TrapFrame, result: i64, switched: bool, owed: &Owed) -> IpcServed {
    if owed.release.is_some() {
        return handback_result(frame, result, 0, owed);
    }
    frame.x[0] = result as u64;
    IpcServed::Returned { switched }
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

    #[derive(Default)]
    struct Tables(RefCell<HashMap<u64, RawTableId>>);
    impl IpcTables for Tables {
        fn table_of(&self, task: &CurrentTask) -> Option<RawTableId> {
            self.0
                .borrow()
                .get(&task.task_id.load(Ordering::Relaxed))
                .copied()
        }
    }

    // ---- the world: region (host-initialized), zone, one slot, task A ----
    struct World {
        region: &'static IpcRegion<'static>,
        next: Cell<u64>,
        zone: Box<ZoneTables>,
        task: CurrentTask,
        cpu: FakeCpu,
        counters: &'static Counters,
        mem: Memory,
        tables: Tables,
        a_tid: u64,
    }

    fn identity(tid: u64, mm: u64) -> ThreadIdentity {
        ThreadIdentity {
            tid,
            serial: tid + 1000,
            mm,
            file_table: 5,
            generation: 1,
            affinity: 0,
        }
    }

    fn world() -> World {
        let dir = unsafe {
            std::alloc::alloc_zeroed(Layout::new::<IpcDirectory>()).cast::<IpcDirectory>()
        };
        let pool_len = 16 << 20;
        let pool =
            unsafe { std::alloc::alloc_zeroed(Layout::from_size_align(pool_len, 4096).unwrap()) };
        let region = unsafe { IpcRegion::initialize(dir, pool, pool_len, 42) }.unwrap();
        let zone: Box<ZoneTables> =
            unsafe { Box::from_raw(std::alloc::alloc_zeroed(Layout::new::<ZoneTables>()).cast()) };
        zone.spaces.set_idle_ttbr(IDLE_TTBR);
        for (mm, ttbr) in [(MM, TTBR_MM), (OTHER_MM, TTBR_OTHER)] {
            let index = zone.spaces.publish_closed(mm, ttbr, ttbr).unwrap();
            zone.spaces.open(index);
        }
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
        // The fake CPU records switches and SGIs in vectors: reserve them so
        // allocation accounting sees only the code under test.
        let mut cpu = FakeCpu::default();
        cpu.translations.reserve(4096);
        cpu.sgis.reserve(4096);
        cpu.asid_invalidations.reserve(4096);
        World {
            region: Box::leak(Box::new(region)),
            next: Cell::new(0),
            zone,
            task,
            cpu,
            counters: Box::leak(Box::new(Counters::default())),
            mem: Memory::default(),
            tables: Tables::default(),
            a_tid,
        }
    }

    impl World {
        fn bump(&self, bytes: u64) -> u64 {
            let at = self.next.get();
            self.next.set((at + bytes).next_multiple_of(IPC_POOL_ALIGN));
            at
        }
        fn host(&self) -> carrick_el1_abi::ipc::IpcFdAuthority<'static, HostWait> {
            self.region.fd(HostWait)
        }
        /// The host venue's table for thread `tid` (a new process).
        fn table(&self, tid: u64) -> TableId {
            let extent = Extent {
                token: self.bump(descriptor_extent_bytes(64)),
                capacity: 64,
            };
            let t = self.host().create_table(1024, &mut { extent }).unwrap();
            self.tables.0.borrow_mut().insert(tid, t.to_raw());
            t
        }
        fn fork_table(&self, parent: TableId, tid: u64) -> TableId {
            let mut extent = Extent {
                token: self.bump(descriptor_extent_bytes(64)),
                capacity: 64,
            };
            let t = self.host().fork(parent, &mut extent).unwrap();
            self.tables.0.borrow_mut().insert(tid, t.to_raw());
            t
        }
        /// pipe(2) as the host venue performs it.
        fn pipe(&self, t: TableId, flags: StatusFlags) -> (i32, i32, IpcObjectHandle) {
            let storage = IpcPipeStorage {
                offset: self.bump(65536 + 16 * 8),
                ring_bytes: 65536,
                pages: 16,
            };
            let object = self
                .region
                .create_pipe(65536, &mut Some(storage), &HostWait)
                .unwrap();
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
                region: self.region,
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
                region: self.region,
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
        assert_eq!(w.call(&mut f), IpcServed::Handback);
        assert_eq!(f.x[8], IPC_HANDBACK_NR);
        assert_eq!(f.x[1], HandbackFlags::CONTINUE);
        let token = IpcOpToken::from_raw(carrick_el1_abi::ipc::RawIpcOpToken {
            index: f.x[2] as u32,
            generation: (f.x[2] >> 32) as u32,
        });
        let op = w.region.operation(&token).unwrap();
        assert_eq!(
            (op.kind, op.progress.written, op.progress.len),
            (IpcOpKind::PipeWrite, 4096, 8192)
        );
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
        w.tables.0.borrow_mut().clear();
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
        let reused = w.eventfd(a, 0, EventMode::Counter, BLOCK);
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
        let b = TableId::from_raw(w.tables.0.borrow()[&202]);
        w.host_close(b, r);
        assert_eq!(f.elr, B_SVC);
        f = b_block;
        assert_eq!(w.call(&mut f), SWITCHED, "B blocks; A was woken");
        reenter(&mut f, A_SVC);
        assert_eq!(w.call(&mut f), IpcServed::Handback);
        assert_eq!(f.x[8], IPC_HANDBACK_NR);
        assert_eq!(f.x[0], 65536);
        assert_eq!(f.x[1], HandbackFlags::SIGPIPE);
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
