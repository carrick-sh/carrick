//! select(2)/pselect6(2) over several zone descriptors, served in ring as a
//! client of the zone epoll owner (contract `kernel.el1.poll-select-owner`).
//!
//! The single-description owner (`serve_zone_readiness`) parks on one
//! object's lane. A set whose answer is not known at once must park on
//! every member, which is what an epoll already does: members publish
//! readiness onto an epoll's lock-free ready list and wake its `Readable`
//! lane. So a multi-descriptor select builds a TRANSIENT epoll: an epoll
//! object whose only reference is a description pinned by the call's
//! operation (no descriptor number, so no guest `epoll_ctl` reaches it).
//! Each selected descriptor becomes one edge-triggered item (its member
//! object and kind, the description's key, and a [`SetWord`] holding the fd
//! and its select interest). The wait is the epoll wait's: snapshot the
//! epoll's lane, harvest, translate the reports back into the three
//! `fd_set`s, and park on that lane if nothing is select-ready. Edge
//! triggering keeps an item that reported without a select class (a hangup
//! on a write-only interest) from staying queued and swallowing a later
//! publication.
//!
//! The operation is an ordinary [`IpcOpKind::SelectWait`] whose `pin` names
//! the transient description, so every existing retirement (completion,
//! EINTR, the host's settlement, a dying task) drops that pin, and the
//! description's final release destroys the epoll and unlinks its items.
//! The deadline, the output layout and the armed mask follow the
//! single-description protocol exactly; so does a full operation arena
//! (`super::begin_readiness_operation`).
//!
//! Scope: every selected descriptor must be a zone object an epoll can
//! hold (pipe ends, eventfds, stream ends). A host-backed descriptor, a
//! nested epoll, or a member already watched by
//! [`carrick_el1_abi::ipc::epoll::MAX_MEMBER_ITEMS`] epolls leaves the call
//! unrouted before any effect, as before; mixed host and zone sets are
//! #1886's composition.

extern crate alloc;

use super::{
    Begun, EL1_WAIT, IpcExecution, IpcServed, IpcVenue, Parked, PollOutput, SELECT_INTERESTS,
    SelectReady, UserCopy, begin_readiness_operation, finish, mm_key, native_select_output, park,
    poll_result, release_pin, select_ready, snapshot, task_key,
};
use crate::dispatch::GuestDispatchFrame;
use alloc::vec::Vec;
use carrick_el1_abi::ipc::epoll::{EpollItemRef, EpollMember, EpollReport, events};
use carrick_el1_abi::ipc::fd::{
    AccessMode, Description, Error as FdError, Fd, StatusFlags, TableId,
};
use carrick_el1_abi::ipc::pipe::WaitFor;
use carrick_el1_abi::ipc::{
    IpcBacking, IpcCounterDeadline, IpcError, IpcObjectHandle, IpcOpKind, IpcOpToken, IpcOperation,
    IpcRegion, IpcSelectOutput, IpcUserVa, OfdPin,
};
use carrick_sched_core::LockWait;
use carrick_syscall_abi::LinuxErrno;

/// One transient item's `data` word: the descriptor, the select classes it
/// asked for and, once the host decided the answer, those it reports.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SetWord {
    pub fd: i32,
    pub interest: i16,
    pub ready: i16,
}

impl SetWord {
    pub const fn to_raw(self) -> u64 {
        (self.fd as u32 as u64)
            | ((self.interest as u16 as u64) << 32)
            | ((self.ready as u16 as u64) << 48)
    }

    pub const fn from_raw(raw: u64) -> Self {
        Self {
            fd: raw as u32 as i32,
            interest: (raw >> 32) as u16 as i16,
            ready: (raw >> 48) as u16 as i16,
        }
    }
}

/// The epoll events an item requests for a select interest. ERR and HUP
/// are always reported; [`select_ready`] maps them to their classes.
const fn select_events(interest: i16) -> u32 {
    let mut requested = events::ET;
    if interest & SELECT_INTERESTS[0] != 0 {
        requested |= events::IN | events::RDNORM | events::RDBAND;
    }
    if interest & SELECT_INTERESTS[1] != 0 {
        requested |= events::OUT | events::WRNORM | events::WRBAND;
    }
    if interest & SELECT_INTERESTS[2] != 0 {
        requested |= events::PRI;
    }
    requested
}

/// The transient epoll a set operation's pinned description names.
pub fn transient_epoll<W: LockWait>(
    region: &IpcRegion<'_>,
    op: &IpcOperation,
    wait: W,
) -> Option<IpcObjectHandle> {
    if !matches!(op.kind, IpcOpKind::SelectWait | IpcOpKind::PollWait) {
        return None;
    }
    let pin = OfdPin::from_raw(op.pin);
    let description = region.fd(wait).pinned(&pin);
    let _ = pin.into_raw();
    match IpcBacking::decode(description.ok()?.backing)? {
        IpcBacking::Epoll { object } if object.to_raw() == op.object => Some(object),
        _ => None,
    }
}

/// Whether a retained select operation is a set (its pin names a transient
/// epoll) rather than a single description.
pub(super) fn names_set(region: &IpcRegion<'_>, op: &IpcOperation) -> bool {
    transient_epoll(region, op, EL1_WAIT).is_some()
}

/// Harvest the set once and translate the reports into select classes.
/// The one probe both venues use; an empty answer means nothing is
/// select-ready (reports without a class are dropped).
pub fn harvest_ready(
    region: &IpcRegion<'_>,
    epoll: IpcObjectHandle,
    wait: &impl LockWait,
) -> Result<Vec<SelectReady>, IpcError> {
    let items = region.epoll_zone_items(epoll, wait)? as usize;
    let mut reports = Vec::new();
    let mut taken = Vec::new();
    let mut ready = Vec::new();
    if reports.try_reserve_exact(items).is_err()
        || taken.try_reserve_exact(items).is_err()
        || ready.try_reserve_exact(items).is_err()
    {
        return Err(IpcError::NoObjects);
    }
    reports.resize(items, EpollReport::default());
    taken.resize(items, EpollItemRef::default());
    let harvest = region.epoll_harvest(epoll, &mut reports, &mut taken, wait)?;
    for report in &reports[..harvest.reported] {
        let word = SetWord::from_raw(report.data);
        let classes = select_ready(word.interest, report.events);
        if classes != 0 {
            ready.push(SelectReady {
                fd: word.fd,
                ready: classes,
            });
        }
    }
    Ok(ready)
}

/// Keep a decided answer in the set's own items (the host's copy-out may
/// be refused and resumed; it must render the same bytes each time).
pub fn record_answer(
    region: &IpcRegion<'_>,
    epoll: IpcObjectHandle,
    ready: &[SelectReady],
    wait: &impl LockWait,
) -> Result<(), IpcError> {
    region.epoll_update_data(epoll, wait, |raw| {
        let word = SetWord::from_raw(raw);
        let classes = ready
            .iter()
            .find(|entry| entry.fd == word.fd)
            .map_or(0, |entry| entry.ready);
        SetWord {
            ready: classes,
            ..word
        }
        .to_raw()
    })
}

/// The answer [`record_answer`] kept.
pub fn recorded_answer(
    region: &IpcRegion<'_>,
    epoll: IpcObjectHandle,
    wait: &impl LockWait,
) -> Result<Vec<SelectReady>, IpcError> {
    let mut ready = Vec::new();
    let mut refused = false;
    region.epoll_update_data(epoll, wait, |raw| {
        let word = SetWord::from_raw(raw);
        if word.ready != 0 {
            refused |= ready.try_reserve(1).is_err();
            if !refused {
                ready.push(SelectReady {
                    fd: word.fd,
                    ready: word.ready,
                });
            }
        }
        raw
    })?;
    if refused {
        return Err(IpcError::NoObjects);
    }
    Ok(ready)
}

/// What a fresh set call accepted at entry.
pub(super) struct SetCall {
    pub kind: IpcOpKind,
    pub layout: IpcSelectOutput,
    /// Read, write and except bitmaps, `layout.words` each (empty when no
    /// descriptor is named).
    pub sets: Vec<u64>,
    pub timeout: IpcUserVa,
    pub deadline: IpcCounterDeadline,
    /// A pselect6/ppoll mask not yet armed (a slot-wait replay armed it already).
    pub sigmask: Option<u64>,
    pub arg0: u64,
}

enum Build {
    Errno(LinuxErrno),
    /// Not a set this owner serves; nothing was changed.
    Unrouted,
}

/// Serve a select over several descriptors from its entry.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub(super) fn serve<E: IpcExecution, M: UserCopy>(
    sched: &mut E,
    frame: &mut E::Frame,
    venue: &IpcVenue<'_>,
    user: &mut M,
    output: &mut Option<PollOutput>,
    keep_sigmask: &mut bool,
    table: TableId,
    mut call: SetCall,
) -> IpcServed {
    let region = &venue.region;
    loop {
        let (pin, epoll) = match build(sched, region, table, &call) {
            Ok(built) => built,
            Err(Build::Errno(errno)) => return poll_result(frame, errno.guest_retval()),
            Err(Build::Unrouted) => return IpcServed::Forward,
        };
        let op = IpcOperation {
            kind: call.kind,
            pin: pin.into_raw(),
            object: epoll.to_raw(),
            task: task_key(sched.task()),
            mm: mm_key(sched.task()),
            buf: call.timeout,
            orig_x0: call.arg0,
            select: call.layout,
            nr: frame.native_number().raw() as u32,
            deadline: call.deadline,
            ..IpcOperation::EMPTY
        };
        match wait(
            sched,
            frame,
            region,
            user,
            output,
            keep_sigmask,
            op,
            None,
            &mut call.sigmask,
        ) {
            Some(served) => return served,
            // A slot was released before the arena park: build again.
            None => continue,
        }
    }
}

/// Resume a parked set operation (its mask is armed; nothing is reread).
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub(super) fn resume<E: IpcExecution, M: UserCopy>(
    sched: &mut E,
    frame: &mut E::Frame,
    venue: &IpcVenue<'_>,
    user: &mut M,
    output: &mut Option<PollOutput>,
    keep_sigmask: &mut bool,
    token: IpcOpToken,
    op: IpcOperation,
) -> IpcServed {
    let region = &venue.region;
    // A retained operation only completes or parks again: it never builds.
    wait(
        sched,
        frame,
        region,
        user,
        output,
        keep_sigmask,
        op,
        Some(token),
        &mut None,
    )
    .unwrap_or_else(|| {
        crate::dispatch::invalid_completion(crate::dispatch::NativeInvariant::EntryBinding)
    })
}

/// Make the transient epoll and enrol every selected descriptor on it.
fn build<E: IpcExecution>(
    sched: &mut E,
    region: &IpcRegion<'_>,
    table: TableId,
    call: &SetCall,
) -> Result<(OfdPin, IpcObjectHandle), Build> {
    let epoll = loop {
        let seen = region.object_count();
        match region.create_epoll(&EL1_WAIT) {
            Ok(object) => break object,
            Err(IpcError::NoObjects) => {
                if region.grow_objects(seen).is_err() {
                    return Err(Build::Errno(carrick_abi::LINUX_ENOMEM));
                }
            }
            Err(_) => return Err(Build::Unrouted),
        }
    };
    let backing = IpcBacking::Epoll { object: epoll }.encode();
    let authority = region.fd(EL1_WAIT);
    let pin = match authority.create_pinned(Description::new(
        backing,
        AccessMode::ReadWrite,
        StatusFlags::default(),
    )) {
        Ok(pin) => pin,
        Err(_) => {
            let _ = region.release_backing(backing, &super::Finish);
            return Err(Build::Unrouted);
        }
    };
    match enrol(sched, region, table, call, epoll) {
        Ok(()) => Ok((pin, epoll)),
        Err(refused) => {
            // The description's final release destroys the epoll and
            // unlinks every item enrolled so far.
            release_pin(sched, pin, region);
            Err(refused)
        }
    }
}

fn enrol<E: IpcExecution>(
    sched: &mut E,
    region: &IpcRegion<'_>,
    table: TableId,
    call: &SetCall,
    epoll: IpcObjectHandle,
) -> Result<(), Build> {
    if call.sets.is_empty() {
        return Ok(());
    }
    let authority = region.fd(EL1_WAIT);
    let words = call.layout.words as usize;
    for index in 0..words {
        let mut any = call.sets[index] | call.sets[words + index] | call.sets[2 * words + index];
        while any != 0 {
            let bit = any.trailing_zeros() as usize;
            any &= any - 1;
            let interest = SELECT_INTERESTS
                .iter()
                .enumerate()
                .filter(|&(set, _)| call.sets[set * words + index] & (1 << bit) != 0)
                .fold(0, |interest, (_, &class)| interest | class);
            let fd = (index * 64 + bit) as i32;
            let (pin, description) = loop {
                match authority.pin(table, Fd(fd)) {
                    Ok(pinned) => break pinned,
                    Err(FdError::BadFd) => {
                        return Err(Build::Errno(carrick_syscall_abi::LINUX_EBADF));
                    }
                    // Freed and reused under the pin: drop it and resolve again.
                    Err(FdError::PinRaced(raw)) => {
                        release_pin(sched, OfdPin::from_raw(raw), region);
                    }
                    Err(_) => return Err(Build::Unrouted),
                }
            };
            let key = pin.key();
            let file_key = (u64::from(key.index) << 32) | (key.generation & u64::from(u32::MAX));
            let added = IpcBacking::decode(description.backing)
                .and_then(EpollMember::of_backing)
                .map(|(member, kind)| {
                    region.epoll_add(
                        epoll,
                        member,
                        kind,
                        fd,
                        file_key,
                        select_events(interest),
                        SetWord {
                            fd,
                            interest,
                            ready: 0,
                        }
                        .to_raw(),
                        &EL1_WAIT,
                    )
                });
            // The item holds the member by generation; its last close
            // detaches the item, as for any epoll.
            release_pin(sched, pin, region);
            // An already-ready member queued its item on an epoll nobody
            // waits on yet: the harvest below reports it.
            if !matches!(added, Some(Ok(_))) {
                return Err(Build::Unrouted);
            }
        }
    }
    Ok(())
}

/// Probe and park until the set answers, its deadline passes or a signal
/// ends it. `None`: the arena admitted no operation and a slot was released
/// meanwhile, so a fresh call builds its set again.
#[allow(clippy::too_many_arguments)]
fn wait<E: IpcExecution, M: UserCopy>(
    sched: &mut E,
    frame: &mut E::Frame,
    region: &IpcRegion<'_>,
    user: &mut M,
    output: &mut Option<PollOutput>,
    keep_sigmask: &mut bool,
    op: IpcOperation,
    mut token: Option<IpcOpToken>,
    sigmask: &mut Option<u64>,
) -> Option<IpcServed> {
    let epoll = IpcObjectHandle::from_raw(op.object);
    let retire = |sched: &mut E, token: Option<IpcOpToken>, op: &IpcOperation| match token {
        Some(token) => finish(sched, token, region),
        None => release_pin(sched, OfdPin::from_raw(op.pin), region),
    };
    loop {
        // Before the harvest: an item queued after it moves this snapshot.
        let snap = snapshot(sched, epoll, WaitFor::Readable);
        let ready = match harvest_ready(region, epoll, &EL1_WAIT) {
            Ok(ready) => ready,
            Err(_) => {
                retire(sched, token, &op);
                return Some(IpcServed::Forward);
            }
        };
        let deadline = op.deadline;
        if !ready.is_empty() || deadline.get().is_some_and(|end| sched.now() >= end) {
            retire(sched, token, &op);
            if op.kind == IpcOpKind::PollWait {
                return Some(poll_result(frame, 0));
            }
            let result = ready
                .iter()
                .map(|entry| i64::from(entry.ready.count_ones()))
                .sum();
            return Some(
                match native_select_output(op.select, op.buf, sched, &ready, deadline, result) {
                    Ok(answer) => {
                        *output = Some(answer);
                        poll_result(frame, result)
                    }
                    Err(errno) => poll_result(frame, errno.guest_retval()),
                },
            );
        }
        let Some(snap) = snap else {
            retire(sched, token, &op);
            return Some(IpcServed::Forward);
        };
        // Armed once before admission and park, so the post-enrollment
        // probe observes the temporary mask and a retry never re-arms.
        if let Some(mask) = sigmask.take()
            && !user.arm_wait_sigmask(mask)
        {
            retire(sched, token, &op);
            return Some(IpcServed::Forward);
        }
        let admitted = match token.take() {
            Some(admitted) => admitted,
            None => match begin_readiness_operation(sched, frame, region, user, op, keep_sigmask) {
                Begun::Operation(admitted) => admitted,
                Begun::Served(served) => return Some(served),
                Begun::Rerun => return None,
            },
        };
        match park(
            sched,
            frame,
            region,
            admitted,
            op,
            epoll,
            WaitFor::Readable,
            snap,
            deadline.get(),
            &mut || user.interrupt_pending_wait(),
        ) {
            Parked::Done(served) => {
                *keep_sigmask = true;
                return Some(served);
            }
            Parked::Retry(retained) => token = Some(retained),
            Parked::Refused(retained) => {
                finish(sched, retained, region);
                return Some(IpcServed::Forward);
            }
        }
    }
}
