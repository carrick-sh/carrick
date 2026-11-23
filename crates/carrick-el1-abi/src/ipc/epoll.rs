//! Zone epoll records: the one authority for an epoll instance's in-zone
//! items (members that are pipe ends or eventfds in this region), shared by
//! the host and EL1 in place (contract `kernel.el1.epoll-zone`).
//!
//! # One owner per item
//!
//! An epoll instance is an [`IpcObjectKind::Epoll`] object. Items watching
//! IPC objects, and native host sockets with carrier-published readiness,
//! live in [`IpcEpollItem`] and share the same ready list. The legacy host
//! epoll path keeps its own interest map; this record counts those items
//! ([`IpcRegion::epoll_host_items`]) and the host harvests both lists
//! when that legacy map is populated.
//!
//! Candid divergence from Linux: Linux keeps one ready list per epoll, in
//! the order items became ready. A set with both halves has two: the zone
//! half here, in its own arrival order, and the host half. A host harvest
//! of a mixed set reports zone items first, then host items, under one
//! `maxevents` budget. Within each half the order is Linux's.
//!
//! # Identity
//!
//! Linux keys an item on the (open file, fd number) pair it was added with
//! and removes it when the open file's last reference goes away
//! (`man 7 epoll`). An item records `fd` and `file_key`, the venue-defined
//! identity of the member's open file description (the host passes the
//! IPC OFD's index and generation); `EPOLL_CTL_ADD`/`MOD`/`DEL` match
//! both, and [`IpcRegion::epoll_detach_file`] removes every item of a file
//! whose last descriptor closed.
//!
//! # Readiness
//!
//! A member's state change ([`IpcObjectGuard::publish`]) runs under the
//! member's lock and walks the member's item list (at most
//! [`MAX_MEMBER_ITEMS`] items): an item interested in the published lane,
//! not disabled by `EPOLLONESHOT` and not already queued is pushed on its
//! epoll's lock-free ready stack. The publisher takes no epoll lock. The
//! returned [`IpcWake`] names each epoll it pushed to; the caller notifies
//! that epoll's waiters (its `Readable` wait key) after unlocking, and the
//! epoll is owed a host wake only if it has a host subscriber (a host-side
//! waiter), never because a member does.
//!
//! A harvest ([`IpcRegion::epoll_harvest`]) takes the epoll's lock, drains
//! the stack into the ordered ready list, pops one item, and releases the
//! lock before it locks the member to read its current level: the level,
//! not the publication, decides what is reported, so a stale or spurious
//! queueing reports nothing. Level-triggered items that reported are queued
//! again (after the scan, so one harvest reports an item at most once);
//! edge-triggered items are queued again only by a later publication;
//! one-shot items are disabled until `EPOLL_CTL_MOD`.
//!
//! # Lock order
//!
//! Member object, then epoll object (add, modify, delete, detach). A
//! publisher holds only the member (the ready stack is lock-free). A
//! harvest holds only one of the two at a time and never both. Every lock
//! is an object lock of this region; no lock is held across a park.

use super::*;

/// Zone epoll items in one region (all epolls together). Exhaustion is not
/// guest-visible: the host places the item in its own half instead.
pub const IPC_EPOLL_ITEMS: usize = 16384;
/// Items one member object may carry in zone epolls. A member watched by
/// more epolls has its further items in the host half, so a publisher's
/// wake list is bounded.
pub const MAX_MEMBER_ITEMS: usize = 4;

/// A bounded readiness snapshot whose shared epoll record had no host items.
/// This is not a membership lease; a later ADD may change the set.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct ZoneOnlyEpollReadyCount {
    records: usize,
}

impl ZoneOnlyEpollReadyCount {
    pub const fn records(self) -> usize {
        self.records
    }
}

/// Linux epoll event bits this record interprets (uapi `eventpoll.h`).
pub mod events {
    pub const IN: u32 = 0x001;
    pub const PRI: u32 = 0x002;
    pub const OUT: u32 = 0x004;
    pub const ERR: u32 = 0x008;
    pub const HUP: u32 = 0x010;
    pub const RDNORM: u32 = 0x040;
    pub const RDBAND: u32 = 0x080;
    pub const WRNORM: u32 = 0x100;
    pub const WRBAND: u32 = 0x200;
    pub const RDHUP: u32 = 0x2000;
    pub const EXCLUSIVE: u32 = 1 << 28;
    pub const WAKEUP: u32 = 1 << 29;
    pub const ONESHOT: u32 = 1 << 30;
    pub const ET: u32 = 1 << 31;
    /// Bits a member level can carry and an item can request.
    pub const LEVEL_MASK: u32 =
        IN | PRI | OUT | ERR | HUP | RDNORM | RDBAND | WRNORM | WRBAND | RDHUP;
    /// Reported whether requested or not.
    pub const ALWAYS: u32 = ERR | HUP;
    /// The lane a readers-side publication serves.
    pub const READ_SIDE: u32 = IN | PRI | RDNORM | RDBAND | RDHUP;
    /// The lane a writers-side publication serves.
    pub const WRITE_SIDE: u32 = OUT | WRNORM | WRBAND;
}

/// Which side of which object an item watches.
#[repr(u32)]
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum EpollMember {
    EventFd = 1,
    PipeReader = 2,
    PipeWriter = 3,
    /// A stream pair's [`StreamEnd::First`]: readable from the second
    /// end's lane, writable into its own.
    StreamFirst = 4,
    /// A stream pair's [`StreamEnd::Second`].
    StreamSecond = 5,
    /// A carrier-owned socket readiness source. Its sampled level is stored
    /// in the item itself under the epoll lock.
    HostSocket = 6,
}
impl EpollMember {
    const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::EventFd),
            2 => Some(Self::PipeReader),
            3 => Some(Self::PipeWriter),
            4 => Some(Self::StreamFirst),
            5 => Some(Self::StreamSecond),
            6 => Some(Self::HostSocket),
            _ => None,
        }
    }
    /// The stream end this member watches.
    pub const fn stream_end(self) -> Option<StreamEnd> {
        match self {
            Self::StreamFirst => Some(StreamEnd::First),
            Self::StreamSecond => Some(StreamEnd::Second),
            Self::EventFd | Self::PipeReader | Self::PipeWriter | Self::HostSocket => None,
        }
    }
    /// The member a description's backing names, if it is an IPC object.
    pub const fn of_backing(backing: IpcBacking) -> Option<(IpcObjectHandle, Self)> {
        match backing {
            IpcBacking::EventFd { object } => Some((object, Self::EventFd)),
            IpcBacking::Pipe {
                object,
                end: End::Reader,
            } => Some((object, Self::PipeReader)),
            IpcBacking::Pipe {
                object,
                end: End::Writer,
            } => Some((object, Self::PipeWriter)),
            IpcBacking::Stream {
                object,
                end: StreamEnd::First,
            } => Some((object, Self::StreamFirst)),
            IpcBacking::Stream {
                object,
                end: StreamEnd::Second,
            } => Some((object, Self::StreamSecond)),
            IpcBacking::Host(_) | IpcBacking::Epoll { .. } | IpcBacking::Directory { .. } => None,
        }
    }
}

/// An epoll object's state (under its lock).
#[repr(C)]
#[derive(
    ::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug, ::core::default::Default,
)]
pub struct EpollState {
    /// First item of the interest list (item number, 0 none).
    interest_head: u32,
    /// Zone items in the interest list.
    zone_items: u32,
    /// Ordered ready list (item numbers, 0 none), drained from the stack.
    ready_head: u32,
    ready_tail: u32,
    /// Items of this epoll that live in the host's half.
    host_items: u32,
    /// Set by [`IpcRegion::epoll_destroy`] when it takes the interest list:
    /// from then on the teardown owns every item.
    dead: u32,
    /// Advanced by each harvest; an item records the epoch it was reported
    /// in, so one harvest reports an item at most once even when a member
    /// publication queues it again mid-scan.
    harvest_epoch: u32,
    _reserved: u32,
}

const QUEUED: u32 = 1;
const DISABLED: u32 = 2;

/// One zone epoll item. Fields written under the epoll's lock: interest
/// links, `ready_next` while on the ordered list, `events`, `data` and
/// `DISABLED`. Under the member's lock: member links. `QUEUED` is the
/// lock-free membership token of the ready stack/list: set by the one
/// party that queues the item, cleared by the harvester that pops it.
#[repr(C, align(64))]
pub struct IpcEpollItem {
    generation: AtomicU32,
    live: AtomicU32,
    pub(super) next_free: AtomicU64,
    epoll: AtomicU64,
    /// Packed member object handle, or the sampled Linux level for a
    /// carrier socket. Socket publishers write it under the epoll lock.
    member: AtomicU64,
    file_key: AtomicU64,
    data: AtomicU64,
    events: AtomicU32,
    fd: AtomicU32,
    member_kind: AtomicU32,
    flags: AtomicU32,
    member_next: AtomicU32,
    member_prev: AtomicU32,
    interest_next: AtomicU32,
    interest_prev: AtomicU32,
    ready_next: AtomicU32,
    /// The harvest epoch that last reported this item (epoll lock).
    reported_epoch: AtomicU32,
}

const HOST_SOCKET_BATCH: usize = 32;

impl IpcEpollItem {
    fn report(&self, level: u32, epoch: u32) -> Option<EpollReport> {
        let requested = self.events.load(Ordering::Relaxed);
        let report = level & (requested | events::ALWAYS);
        if report == 0 || self.flags.load(Ordering::Relaxed) & DISABLED != 0 {
            return None;
        }
        self.reported_epoch.store(epoch, Ordering::Relaxed);
        if requested & events::ONESHOT != 0 {
            self.flags.fetch_or(DISABLED, Ordering::AcqRel);
        }
        Some(EpollReport {
            events: report,
            data: self.data.load(Ordering::Relaxed),
        })
    }

    fn is_level_triggered(&self) -> bool {
        self.events.load(Ordering::Relaxed) & (events::ET | events::ONESHOT) == 0
    }
}

const fn pack(object: IpcObjectHandle) -> u64 {
    ((object.index as u64) << 32) | object.generation as u64
}
const fn unpack(word: u64) -> IpcObjectHandle {
    IpcObjectHandle {
        index: (word >> 32) as u32,
        generation: word as u32,
    }
}

/// Exact identity of one item: its number and incarnation.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::default::Default,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct EpollItemRef {
    number: u32,
    generation: u32,
}

/// One reported event (Linux `struct epoll_event` without packing).
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::default::Default,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct EpollReport {
    pub events: u32,
    pub data: u64,
}

/// Why a zone `EPOLL_CTL_ADD` did not take the item. `Exists`/`NotFound`
/// are the guest's `EEXIST`/`ENOENT`; `HostHalf` means the item belongs in
/// the host's half (a placement refusal, never guest-visible).
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum EpollCtlError {
    Exists,
    NotFound,
    /// An argument Linux refuses (`EINVAL`), e.g. `EPOLLEXCLUSIVE` on MOD.
    Invalid,
    HostHalf(HostHalfReason),
    Ipc(IpcError),
}
/// Why an item that could be in the zone is placed in the host half.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum HostHalfReason {
    /// The zone item store is exhausted.
    ItemsExhausted,
    /// The member already carries [`MAX_MEMBER_ITEMS`] zone items.
    MemberFanOut,
    /// `EPOLLEXCLUSIVE` wake-one semantics stay with the host.
    Exclusive,
}
impl From<IpcError> for EpollCtlError {
    fn from(error: IpcError) -> Self {
        Self::Ipc(error)
    }
}

/// Epolls a member publication queued items on: the caller notifies each
/// one's `Readable` wait key after unlocking (bounded by
/// [`MAX_MEMBER_ITEMS`]).
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::default::Default,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct EpollWakes {
    len: u32,
    epolls: [RawIpcObject; MAX_MEMBER_ITEMS],
}
impl EpollWakes {
    pub const EMPTY: Self = Self {
        len: 0,
        epolls: [RawIpcObject {
            index: 0,
            generation: 0,
        }; MAX_MEMBER_ITEMS],
    };
    fn add(&mut self, epoll: IpcObjectHandle) {
        let raw = epoll.to_raw();
        let len = self.len as usize;
        if self.epolls[..len].contains(&raw) || len >= MAX_MEMBER_ITEMS {
            return;
        }
        self.epolls[len] = raw;
        self.len += 1;
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn iter(&self) -> impl Iterator<Item = IpcObjectHandle> + '_ {
        self.epolls[..self.len as usize]
            .iter()
            .map(|raw| IpcObjectHandle::from_raw(*raw))
    }
}

/// The zone half of an epoll as a harvest found it.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::default::Default,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct EpollHarvest {
    /// Reports written to the output.
    pub reported: usize,
    /// Items in the host's half when the harvest began (EL1 forwards a wait
    /// on a set with any).
    pub host_items: u32,
}

impl<'a> IpcRegion<'a> {
    /// Item slot `index` of the array at [`IPC_EPOLL_ITEMS_OFFSET`].
    pub(super) fn epoll_item_at(&self, index: usize) -> Option<&'a IpcEpollItem> {
        (index < IPC_EPOLL_ITEMS).then(|| {
            // SAFETY: in bounds of the item reservation of the mapping
            // (IPC_DIRECTORY_BYTES, checked at attach); all-zero is a valid
            // item of atomics.
            unsafe {
                &*self
                    .base
                    .add(IPC_EPOLL_ITEMS_OFFSET)
                    .cast::<IpcEpollItem>()
                    .add(index)
            }
        })
    }

    fn item(&self, number: u32) -> Option<&'a IpcEpollItem> {
        self.epoll_item_at(number.checked_sub(1)? as usize)
    }

    fn item_ref(&self, number: u32) -> Option<EpollItemRef> {
        let item = self.item(number)?;
        Some(EpollItemRef {
            number,
            generation: item.generation.load(Ordering::Acquire),
        })
    }

    fn live_item(&self, r: EpollItemRef) -> Option<&'a IpcEpollItem> {
        let item = self.item(r.number)?;
        (item.live.load(Ordering::Acquire) != 0
            && item.generation.load(Ordering::Acquire) == r.generation)
            .then_some(item)
    }

    fn alloc_item(&self) -> Option<(u32, &'a IpcEpollItem)> {
        let index = pop(&self.dir.free_epoll_items, |i| {
            self.epoll_item_at(i)
                .map(|item| item.next_free.load(Ordering::Relaxed))
        })?;
        Some((index as u32 + 1, self.epoll_item_at(index)?))
    }

    fn free_item(&self, number: u32) {
        let Some(item) = self.item(number) else {
            return;
        };
        item.live.store(0, Ordering::Relaxed);
        item.flags.store(0, Ordering::Relaxed);
        let next = item.generation.load(Ordering::Relaxed).wrapping_add(1);
        item.generation.store(next, Ordering::Release);
        if next != u32::MAX {
            push(
                &self.dir.free_epoll_items,
                number as usize - 1,
                &item.next_free,
            );
        }
    }

    /// Create an epoll object with an empty interest list. Host venue.
    pub fn create_epoll<W: LockWait>(&self, wait: &W) -> Result<IpcObjectHandle, IpcError> {
        let (index, record) = self.pop_object()?;
        let guard = self.lock_fresh(index, record, wait)?;
        record.epoll_link.store(0, Ordering::Relaxed);
        // SAFETY: the object lock is held and the record is unpublished.
        unsafe { (*record.state.get()).kind_state.counters.epoll = EpollState::default() };
        Ok(guard.publish_kind(KIND_EPOLL))
    }

    /// Lock `epoll` and drain its lock-free stack into the ordered list.
    /// Acquire an epoll's ready-list lock for a harvest owned by this caller.
    pub fn lock_epoll<W: LockWait>(
        &self,
        epoll: IpcObjectHandle,
        wait: &W,
    ) -> Result<IpcObjectGuard<'a>, IpcError> {
        let mut guard = self.lock(epoll, wait)?;
        if guard.epoll_state()?.dead != 0 {
            return Err(IpcError::Stale);
        }
        guard.drain_ready_stack();
        Ok(guard)
    }

    /// `EPOLL_CTL_ADD` of a zone member. Locks the member, then the epoll.
    /// Returns the epoll's wake when the member is already ready (the
    /// caller delivers it after this returns).
    #[allow(clippy::too_many_arguments)]
    pub fn epoll_add<W: LockWait>(
        &self,
        epoll: IpcObjectHandle,
        member: IpcObjectHandle,
        kind: EpollMember,
        fd: i32,
        file_key: u64,
        events: u32,
        data: u64,
        wait: &W,
    ) -> Result<Option<IpcWake>, EpollCtlError> {
        if kind == EpollMember::HostSocket {
            return Err(EpollCtlError::Invalid);
        }
        if events & events::EXCLUSIVE != 0 {
            return Err(EpollCtlError::HostHalf(HostHalfReason::Exclusive));
        }
        let mut member_guard = self.lock(member, wait)?;
        let level = member_guard.member_level(kind)?;
        let mut count = 0;
        let mut cursor = member_guard.record.epoll_link.load(Ordering::Relaxed) as u32;
        while let Some(item) = self.item(cursor) {
            count += 1;
            cursor = item.member_next.load(Ordering::Relaxed);
        }
        if count >= MAX_MEMBER_ITEMS {
            return Err(EpollCtlError::HostHalf(HostHalfReason::MemberFanOut));
        }
        let mut epoll_guard = self.lock_epoll(epoll, wait)?;
        if epoll_guard.find_item(fd, file_key).is_some() {
            return Err(EpollCtlError::Exists);
        }
        let (number, item) = epoll_guard.link_item(member, kind, fd, file_key, events, data)?;
        let member_head = member_guard.record.epoll_link.load(Ordering::Relaxed) as u32;
        item.member_prev.store(0, Ordering::Relaxed);
        item.member_next.store(member_head, Ordering::Relaxed);
        if let Some(next) = self.item(member_head) {
            next.member_prev.store(number, Ordering::Relaxed);
        }
        member_guard
            .record
            .epoll_link
            .store(u64::from(number), Ordering::Relaxed);
        let wake = (level & (events | events::ALWAYS) != 0).then(|| {
            item.flags.store(QUEUED, Ordering::Relaxed);
            epoll_guard.append_ready(number);
            epoll_guard.publish(WakeSet {
                readers: true,
                writers: false,
            })
        });
        drop(epoll_guard);
        drop(member_guard);
        Ok(wake)
    }

    /// An epoll that has hosted a socket retires its carrier registrations
    /// at the backing's final release, even if its last pin returns in ring.
    #[inline(never)]
    pub fn epoll_needs_host_release(&self, object: IpcObjectHandle) -> bool {
        self.record(object.index()).is_some_and(|record| {
            record.generation.load(Ordering::Acquire) != u64::from(object.generation())
                || record.host_flags.load(Ordering::Acquire) & EPOLL_NEEDS_HOST_RELEASE != 0
        })
    }

    /// Add a carrier socket's interest to the shared ready list. The carrier
    /// has enrolled its event source before calling this with its first sample.
    pub fn epoll_add_host_socket<W: LockWait>(
        &self,
        epoll: IpcObjectHandle,
        fd: fd::Fd,
        file_key: u64,
        report: EpollReport,
        level: u32,
        wait: &W,
    ) -> Result<(EpollItemRef, Option<IpcWake>), EpollCtlError> {
        let mut guard = self.lock_epoll(epoll, wait)?;
        if guard.find_item(fd.0, file_key).is_some() {
            return Err(EpollCtlError::Exists);
        }
        let (number, item) = guard.link_item(
            unpack(0),
            EpollMember::HostSocket,
            fd.0,
            file_key,
            report.events,
            report.data,
        )?;
        guard
            .record
            .host_flags
            .fetch_or(EPOLL_NEEDS_HOST_RELEASE, Ordering::Release);
        let wake = guard.publish_host_socket(number, item, level, true);
        Ok((self.item_ref(number).ok_or(IpcError::Corrupt)?, wake))
    }

    /// Rearm a carrier socket interest, invalidating publications and copy
    /// receipts that still name the prior registration.
    pub fn epoll_modify_host_socket<W: LockWait>(
        &self,
        epoll: IpcObjectHandle,
        target: EpollItemRef,
        report: EpollReport,
        level: u32,
        wait: &W,
    ) -> Result<(EpollItemRef, Option<IpcWake>), EpollCtlError> {
        let mut guard = self.lock_epoll(epoll, wait)?;
        let item = self
            .host_socket_item(epoll, target)
            .ok_or(EpollCtlError::NotFound)?;
        let generation = target
            .generation
            .checked_add(1)
            .ok_or(IpcError::ZoneLimit)?;
        item.generation.store(generation, Ordering::Release);
        item.events.store(report.events, Ordering::Relaxed);
        item.data.store(report.data, Ordering::Relaxed);
        item.flags.fetch_and(!DISABLED, Ordering::Relaxed);
        let wake = guard.publish_host_socket(target.number, item, level, true);
        Ok((
            EpollItemRef {
                generation,
                ..target
            },
            wake,
        ))
    }

    pub fn epoll_delete_host_socket<W: LockWait>(
        &self,
        epoll: IpcObjectHandle,
        target: EpollItemRef,
        wait: &W,
    ) -> Result<(), EpollCtlError> {
        let mut guard = self.lock_epoll(epoll, wait)?;
        self.host_socket_item(epoll, target)
            .ok_or(EpollCtlError::NotFound)?;
        guard.unlink_item(target.number);
        self.free_item(target.number);
        Ok(())
    }

    /// Refresh a host socket's level. Only a host event queues an ET item.
    /// A readiness sample after guest I/O can clear its level without
    /// reissuing an edge that a waiter already consumed.
    pub fn epoll_publish_host_socket<W: LockWait>(
        &self,
        epoll: IpcObjectHandle,
        target: EpollItemRef,
        level: u32,
        edge: bool,
        wait: &W,
    ) -> Result<Option<IpcWake>, IpcError> {
        let mut guard = self.lock_epoll(epoll, wait)?;
        let item = self
            .host_socket_item(epoll, target)
            .ok_or(IpcError::Stale)?;
        Ok(guard.publish_host_socket(target.number, item, level, edge))
    }

    fn host_socket_item(
        &self,
        epoll: IpcObjectHandle,
        target: EpollItemRef,
    ) -> Option<&'a IpcEpollItem> {
        self.live_item(target).filter(|item| {
            item.epoll.load(Ordering::Relaxed) == pack(epoll)
                && item.member_kind.load(Ordering::Relaxed) == EpollMember::HostSocket as u32
        })
    }

    /// `EPOLL_CTL_MOD` of the zone item `(fd, file_key)`: new events and
    /// data, `EPOLLONESHOT` re-armed, readiness re-evaluated (Linux queues a
    /// modified item that is ready now).
    pub fn epoll_modify<W: LockWait>(
        &self,
        epoll: IpcObjectHandle,
        fd: i32,
        file_key: u64,
        events: u32,
        data: u64,
        wait: &W,
    ) -> Result<Option<IpcWake>, EpollCtlError> {
        let (member, kind, target) = {
            let mut epoll_guard = self.lock_epoll(epoll, wait)?;
            let number = epoll_guard
                .find_item(fd, file_key)
                .ok_or(EpollCtlError::NotFound)?;
            let item = self.item(number).ok_or(IpcError::Corrupt)?;
            let kind = EpollMember::from_raw(item.member_kind.load(Ordering::Relaxed))
                .ok_or(IpcError::Corrupt)?;
            (
                unpack(item.member.load(Ordering::Relaxed)),
                kind,
                self.item_ref(number).ok_or(IpcError::Corrupt)?,
            )
        };
        if events & events::EXCLUSIVE != 0 {
            // Linux refuses EPOLLEXCLUSIVE on MOD.
            return Err(EpollCtlError::Invalid);
        }
        let mut member_guard = self.lock(member, wait)?;
        let level = member_guard.member_level(kind)?;
        let mut epoll_guard = self.lock_epoll(epoll, wait)?;
        let item = self.live_item(target).ok_or(EpollCtlError::NotFound)?;
        item.events.store(events, Ordering::Relaxed);
        item.data.store(data, Ordering::Relaxed);
        item.flags.fetch_and(!DISABLED, Ordering::AcqRel);
        let wake = (level & (events | events::ALWAYS) != 0
            && item.flags.fetch_or(QUEUED, Ordering::AcqRel) & QUEUED == 0)
            .then(|| {
                epoll_guard.append_ready(target.number);
                epoll_guard.publish(WakeSet {
                    readers: true,
                    writers: false,
                })
            });
        drop(epoll_guard);
        drop(member_guard);
        Ok(wake)
    }

    /// `EPOLL_CTL_DEL` of the zone item `(fd, file_key)`.
    pub fn epoll_delete<W: LockWait>(
        &self,
        epoll: IpcObjectHandle,
        fd: i32,
        file_key: u64,
        wait: &W,
    ) -> Result<(), EpollCtlError> {
        let (member, target) = {
            let mut epoll_guard = self.lock_epoll(epoll, wait)?;
            let number = epoll_guard
                .find_item(fd, file_key)
                .ok_or(EpollCtlError::NotFound)?;
            let item = self.item(number).ok_or(IpcError::Corrupt)?;
            (
                unpack(item.member.load(Ordering::Relaxed)),
                self.item_ref(number).ok_or(IpcError::Corrupt)?,
            )
        };
        match self.lock(member, wait) {
            Ok(member_guard) => {
                let mut epoll_guard = self.lock_epoll(epoll, wait)?;
                let item = self.live_item(target).ok_or(EpollCtlError::NotFound)?;
                let _ = item;
                epoll_guard.unlink_item(target.number);
                member_guard.unlink_member_item(target.number);
            }
            // The member was freed: its release already detached the item.
            Err(IpcError::Stale) => return Err(EpollCtlError::NotFound),
            Err(error) => return Err(error.into()),
        }
        self.free_item(target.number);
        Ok(())
    }

    /// Remove every zone item of the open file `file_key` on `member` (its
    /// last descriptor closed). Locks the member, then each item's epoll.
    pub fn epoll_detach_file<W: LockWait>(
        &self,
        member: IpcObjectHandle,
        file_key: u64,
        wait: &W,
    ) -> Result<usize, IpcError> {
        let member_guard = match self.lock(member, wait) {
            Ok(guard) => guard,
            Err(IpcError::Stale) => return Ok(0),
            Err(error) => return Err(error),
        };
        let removed = member_guard.detach_member_items(Some(file_key), wait)?;
        drop(member_guard);
        for number in removed.iter() {
            self.free_item(number);
        }
        Ok(removed.len())
    }

    /// Final release of an epoll description: retire every zone item, then
    /// free the object. Each step leaves the record consistent, so a step
    /// refused by the lock policy (`Contended`) can be resumed by calling
    /// this again (an EL1 release hands it to the host). Never holds the
    /// epoll and a member lock together.
    pub fn epoll_destroy<W: LockWait>(
        &self,
        epoll: IpcObjectHandle,
        wait: &W,
    ) -> Result<(), IpcError> {
        loop {
            // Take one item off the interest list under the epoll's lock.
            // `dead` makes every other path leave the items to this one.
            let number = {
                let mut guard = self.lock(epoll, wait)?;
                guard.epoll_state()?.dead = 1;
                guard.drain_ready_stack();
                let number = guard.epoll_state()?.interest_head;
                if number == 0 {
                    break;
                }
                guard.unlink_item(number);
                number
            };
            // A publisher reaches an item only through its member's list,
            // under the member's lock, so once unlinked there nothing pushes
            // it again.
            let item = self.item(number).ok_or(IpcError::Corrupt)?;
            if item.member_kind.load(Ordering::Relaxed) == EpollMember::HostSocket as u32 {
                self.free_item(number);
                continue;
            }
            let member = unpack(item.member.load(Ordering::Relaxed));
            match self.lock(member, wait) {
                Ok(guard) => guard.unlink_member_item(number),
                Err(IpcError::Stale) => {}
                Err(error) => {
                    // Keep the item reachable for the resumed teardown.
                    let mut guard = self.lock(epoll, wait)?;
                    let state = guard.epoll_state()?;
                    item.interest_prev.store(0, Ordering::Relaxed);
                    item.interest_next
                        .store(state.interest_head, Ordering::Relaxed);
                    if let Some(next) = self.item(state.interest_head) {
                        next.interest_prev.store(number, Ordering::Relaxed);
                    }
                    state.interest_head = number;
                    state.zone_items += 1;
                    return Err(error);
                }
            }
            self.free_item(number);
        }
        let guard = self.lock(epoll, wait)?;
        // Pushes onto a dead epoll's stack name only freed items.
        guard.record.epoll_link.store(0, Ordering::Relaxed);
        guard.free();
        Ok(())
    }

    /// Host bookkeeping: the number of items in the host's half of `epoll`
    /// (written by the host after each change of its interest map).
    pub fn epoll_set_host_items<W: LockWait>(
        &self,
        epoll: IpcObjectHandle,
        count: u32,
        wait: &W,
    ) -> Result<(), IpcError> {
        let mut guard = self.lock(epoll, wait)?;
        guard.epoll_state()?.host_items = count;
        Ok(())
    }

    /// Items in the zone half of `epoll` (a lock-held read).
    pub fn epoll_zone_items<W: LockWait>(
        &self,
        epoll: IpcObjectHandle,
        wait: &W,
    ) -> Result<u32, IpcError> {
        let mut guard = self.lock(epoll, wait)?;
        Ok(guard.epoll_state()?.zone_items)
    }

    /// Whether `epoll` holds a zone item for fd number `fd` (any open
    /// file), for diagnostics and tests.
    pub fn epoll_has_item_fd<W: LockWait>(
        &self,
        epoll: IpcObjectHandle,
        fd: i32,
        wait: &W,
    ) -> Result<bool, IpcError> {
        let mut guard = self.lock(epoll, wait)?;
        let mut cursor = guard.epoll_state()?.interest_head;
        while let Some(item) = self.item(cursor) {
            if item.fd.load(Ordering::Relaxed) == fd as u32 {
                return Ok(true);
            }
            cursor = item.interest_next.load(Ordering::Relaxed);
        }
        Ok(false)
    }

    /// Rewrite the `data` word of every zone item of `epoll` under its lock
    /// (`update` returns the new word; returning the old one only reads).
    /// A transient readiness set (poll-family over N descriptors) has no
    /// guest descriptor, so no `EPOLL_CTL_MOD` races this: it keeps its
    /// decided answer in the items it already owns.
    pub fn epoll_update_data<W: LockWait>(
        &self,
        epoll: IpcObjectHandle,
        wait: &W,
        mut update: impl FnMut(u64) -> u64,
    ) -> Result<(), IpcError> {
        let mut guard = self.lock(epoll, wait)?;
        let mut cursor = guard.epoll_state()?.interest_head;
        while let Some(item) = self.item(cursor) {
            if item.member_kind.load(Ordering::Relaxed) != EpollMember::HostSocket as u32 {
                let data = item.data.load(Ordering::Relaxed);
                item.data.store(update(data), Ordering::Relaxed);
            }
            cursor = item.interest_next.load(Ordering::Relaxed);
        }
        Ok(())
    }

    /// Items in the host's half of `epoll` (a lock-held read).
    pub fn epoll_host_items<W: LockWait>(
        &self,
        epoll: IpcObjectHandle,
        wait: &W,
    ) -> Result<u32, IpcError> {
        let mut guard = self.lock(epoll, wait)?;
        Ok(guard.epoll_state()?.host_items)
    }

    /// Harvest up to `out.len()` reports from the zone half of `epoll`
    /// (`taken` receives each reported item, for [`Self::epoll_restore`]).
    /// The one routine both venues use. Holds the epoll's lock or one
    /// member's lock at a time, never both.
    pub fn epoll_harvest<W: LockWait>(
        &self,
        epoll: IpcObjectHandle,
        out: &mut [EpollReport],
        taken: &mut [EpollItemRef],
        wait: &W,
    ) -> Result<EpollHarvest, IpcError> {
        let guard = self.lock_epoll(epoll, wait)?;
        self.epoll_harvest_locked(guard, out, taken, wait)
    }

    /// Continue a harvest after its caller probed the lock using a
    /// release-queue observation. No second acquisition for host items.
    pub fn epoll_harvest_locked<W: LockWait>(
        &self,
        mut epoll_guard: IpcObjectGuard<'a>,
        out: &mut [EpollReport],
        taken: &mut [EpollItemRef],
        wait: &W,
    ) -> Result<EpollHarvest, IpcError> {
        if !self.same_mapping(&epoll_guard.region) {
            return Err(IpcError::BadRegion);
        }
        let epoll = epoll_guard.handle();
        let limit = out.len().min(taken.len());
        let mut reported = 0;
        let state = epoll_guard.epoll_state()?;
        let host_items = state.host_items;
        state.harvest_epoch = state.harvest_epoch.wrapping_add(1).max(1);
        let epoch = state.harvest_epoch;
        let mut locked = Some(epoll_guard);
        while reported < limit {
            let mut guard = match locked.take() {
                Some(guard) => guard,
                None => match self.lock_epoll(epoll, wait) {
                    Ok(guard) => guard,
                    Err(error) if reported == 0 => return Err(error),
                    Err(_) => break,
                },
            };
            let Some(number) = guard.pop_ready() else {
                locked = Some(guard);
                break;
            };
            let item = self.item(number).ok_or(IpcError::Corrupt)?;
            let target = self.item_ref(number).ok_or(IpcError::Corrupt)?;
            let kind = EpollMember::from_raw(item.member_kind.load(Ordering::Relaxed))
                .ok_or(IpcError::Corrupt)?;
            if item.reported_epoch.load(Ordering::Relaxed) == epoch {
                // Already reported in this scan, then made ready again.
                guard.prepend_ready(number);
                locked = Some(guard);
                break;
            }
            if kind == EpollMember::HostSocket {
                // Keep the socket's level report on the ready list while
                // another waiter can see it. Neither the sampled level nor
                // the cookie requires a second object lock. Cap this batch
                // at the ring's report window so deduplication stays bounded
                // even for a mixed set with another harvester.
                if reported >= HOST_SOCKET_BATCH || taken[..reported].contains(&target) {
                    guard.prepend_ready(number);
                    locked = Some(guard);
                    break;
                }
                let level = item.member.load(Ordering::Relaxed) as u32;
                item.flags.fetch_and(!QUEUED, Ordering::Relaxed);
                if let Some(report) = item.report(level, epoch) {
                    out[reported] = report;
                    taken[reported] = target;
                    reported += 1;
                    if item.is_level_triggered() {
                        item.flags.fetch_or(QUEUED, Ordering::Relaxed);
                        guard.append_ready(number);
                    }
                }
                locked = Some(guard);
                continue;
            }
            item.flags.fetch_and(!QUEUED, Ordering::AcqRel);
            if item.flags.load(Ordering::Relaxed) & DISABLED != 0 {
                locked = Some(guard);
                continue;
            }
            let member = unpack(item.member.load(Ordering::Relaxed));
            drop(guard);
            // The member's level decides, read under its lock alone.
            let level = match self.lock(member, wait) {
                Ok(mut guard) => guard.member_level(kind)?,
                // A freed member's release detaches its items.
                Err(IpcError::Stale) => continue,
                // A refused lock puts the item back before ending the scan.
                Err(error) => {
                    self.requeue_unlocked(epoll, target);
                    if reported == 0 {
                        return Err(error);
                    }
                    break;
                }
            };
            let guard = match self.lock_epoll(epoll, wait) {
                Ok(guard) => guard,
                Err(error) => {
                    self.requeue_unlocked(epoll, target);
                    if reported == 0 {
                        return Err(error);
                    }
                    break;
                }
            };
            if let Some(item) = self.live_item(target)
                && let Some(report) = item.report(level, epoch)
            {
                out[reported] = report;
                taken[reported] = target;
                reported += 1;
            }
            locked = Some(guard);
        }
        // In-zone level items go back after the scan. Carrier sockets have
        // already been requeued under the guard used to report them.
        if reported > 0 {
            let acquired = match locked {
                Some(guard) => Ok(guard),
                None => self.lock_epoll(epoll, wait),
            };
            let mut guard = acquired.ok();
            for target in &taken[..reported] {
                let Some(item) = self.live_item(*target) else {
                    continue;
                };
                if !item.is_level_triggered()
                    || item.member_kind.load(Ordering::Relaxed) == EpollMember::HostSocket as u32
                {
                    continue;
                }
                if let Some(guard) = &mut guard {
                    if item.flags.fetch_or(QUEUED, Ordering::AcqRel) & QUEUED == 0 {
                        guard.append_ready(target.number);
                    }
                } else {
                    self.requeue_unlocked(epoll, *target);
                }
            }
        }
        Ok(EpollHarvest {
            reported,
            host_items,
        })
    }

    /// Put a popped item back on `epoll`'s lock-free ready stack without
    /// any lock (a harvest step the lock policy refused), so no readiness
    /// is lost; the next harvest re-reads its level.
    fn requeue_unlocked(&self, epoll: IpcObjectHandle, target: EpollItemRef) {
        let (Some(item), Some(record)) = (self.live_item(target), self.record(epoll.index)) else {
            return;
        };
        if item.flags.fetch_or(QUEUED, Ordering::AcqRel) & QUEUED != 0 {
            return;
        }
        let mut head = record.epoll_link.load(Ordering::Acquire);
        loop {
            item.ready_next.store(head as u32, Ordering::Relaxed);
            match record.epoll_link.compare_exchange_weak(
                head,
                u64::from(target.number),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => head = current,
            }
        }
    }

    /// Undo a harvest whose reports could not be delivered (an unwritable
    /// events buffer): queue every taken item again and re-arm one-shot
    /// items, so the next wait reports them (Linux re-queues on a failed
    /// copy).
    pub fn epoll_restore<W: LockWait>(
        &self,
        epoll: IpcObjectHandle,
        taken: &[EpollItemRef],
        wait: &W,
    ) -> Result<(), IpcError> {
        let mut guard = self.lock_epoll(epoll, wait)?;
        for target in taken {
            let Some(item) = self.live_item(*target) else {
                continue;
            };
            item.flags.fetch_and(!DISABLED, Ordering::AcqRel);
            if item.flags.fetch_or(QUEUED, Ordering::AcqRel) & QUEUED == 0 {
                guard.append_ready(target.number);
            }
        }
        Ok(())
    }

    /// Whether the zone half has a reportable item now, without consuming
    /// anything (poll/select on the epoll fd, a parent epoll's readiness).
    /// Items whose member is no longer ready stay queued; the next harvest
    /// drops them.
    pub fn epoll_ready_probe<W: LockWait>(
        &self,
        epoll: IpcObjectHandle,
        wait: &W,
    ) -> Result<bool, IpcError> {
        self.epoll_ready_count(epoll, 1, wait)
            .map(|count| count != 0)
    }

    /// Return a count only when the shared membership authority proves this
    /// is a zone-only set. Host-backed sets require their existing selector.
    pub fn epoll_zone_only_ready_count<W: LockWait>(
        &self,
        epoll: IpcObjectHandle,
        limit: usize,
        wait: &W,
    ) -> Result<Option<ZoneOnlyEpollReadyCount>, IpcError> {
        if self.epoll_host_items(epoll, wait)? != 0 {
            return Ok(None);
        }
        let records = self.epoll_ready_count(epoll, limit, wait)?;
        Ok((self.epoll_host_items(epoll, wait)? == 0)
            .then_some(ZoneOnlyEpollReadyCount { records }))
    }

    /// Count at most `limit` reportable items without consuming reports,
    /// clearing edge latches or disarming one-shots. Like the existing probe,
    /// the scan normalizes pending publications into the ordered ready list.
    /// This is a snapshot, not a reservation: concurrent member changes may
    /// invalidate it before harvest.
    /// A zero limit touches neither the object nor its members.
    pub fn epoll_ready_count<W: LockWait>(
        &self,
        epoll: IpcObjectHandle,
        limit: usize,
        wait: &W,
    ) -> Result<usize, IpcError> {
        if limit == 0 {
            return Ok(0);
        }
        const BATCH: usize = 32;
        let mut cursor = None;
        let mut count = 0;
        loop {
            let mut batch = [(EpollItemRef::default(), RawIpcObject::default(), 0u32, 0u32); BATCH];
            let mut len = 0;
            {
                let mut guard = self.lock_epoll(epoll, wait)?;
                let state = guard.epoll_state()?;
                let mut number = match cursor {
                    None => state.ready_head,
                    Some(previous) => {
                        let next = self.live_item(previous).and_then(|item| {
                            let next = item.ready_next.load(Ordering::Relaxed);
                            // Deletion frees storage outside the epoll lock. A
                            // reused slot must not supply another item's link.
                            (item.flags.load(Ordering::Relaxed) & QUEUED != 0
                                && item.epoll.load(Ordering::Relaxed) == pack(epoll)
                                && self.live_item(previous).is_some())
                            .then_some(next)
                        });
                        match next {
                            Some(next) => next,
                            None => {
                                // Recount from the current list, dropping the
                                // prefix count so a restart cannot double count.
                                count = 0;
                                state.ready_head
                            }
                        }
                    }
                };
                while len < BATCH {
                    let Some(item) = self.item(number) else {
                        break;
                    };
                    if item.flags.load(Ordering::Relaxed) & DISABLED == 0 {
                        batch[len] = (
                            self.item_ref(number).ok_or(IpcError::Corrupt)?,
                            unpack(item.member.load(Ordering::Relaxed)).to_raw(),
                            item.member_kind.load(Ordering::Relaxed),
                            item.events.load(Ordering::Relaxed),
                        );
                        len += 1;
                    }
                    cursor = Some(self.item_ref(number).ok_or(IpcError::Corrupt)?);
                    number = item.ready_next.load(Ordering::Relaxed);
                }
                if len == 0 {
                    return Ok(count);
                }
            }
            for &(target, member, kind, requested) in &batch[..len] {
                let Some(kind) = EpollMember::from_raw(kind) else {
                    return Err(IpcError::Corrupt);
                };
                let level = if kind == EpollMember::HostSocket {
                    let _guard = self.lock_epoll(epoll, wait)?;
                    let Some(item) = self.host_socket_item(epoll, target) else {
                        continue;
                    };
                    item.member.load(Ordering::Relaxed) as u32
                } else {
                    match self.lock(IpcObjectHandle::from_raw(member), wait) {
                        Ok(mut guard) => guard.member_level(kind)?,
                        Err(IpcError::Stale) => continue,
                        Err(error) => return Err(error),
                    }
                };
                if level & (requested | events::ALWAYS) != 0 {
                    count += 1;
                    if count == limit {
                        return Ok(count);
                    }
                }
            }
            if len < BATCH {
                return Ok(count);
            }
        }
    }
}

/// Removed item numbers (bounded by [`MAX_MEMBER_ITEMS`]).
struct Removed {
    len: usize,
    numbers: [u32; MAX_MEMBER_ITEMS],
}
impl Removed {
    fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.numbers[..self.len].iter().copied()
    }
    fn len(&self) -> usize {
        self.len
    }
}

impl IpcObjectGuard<'_> {
    /// Census line for an epoll object (under its lock).
    pub(super) fn epoll_census(&mut self) -> Option<(u32, u32, bool, u32)> {
        let state = self.epoll_state().ok()?;
        Some((
            state.zone_items,
            state.host_items,
            state.dead != 0,
            state.ready_head,
        ))
    }
}

impl<'a> IpcObjectGuard<'a> {
    /// The epoll state, in place.
    fn epoll_state(&mut self) -> Result<&mut EpollState, IpcError> {
        if self.kind() != Some(IpcObjectKind::Epoll) {
            return Err(IpcError::WrongKind);
        }
        // SAFETY: the object lock is held.
        Ok(unsafe { &mut (*self.record.state.get()).kind_state.counters.epoll })
    }

    /// Move the lock-free stack (newest first) to the ordered list's tail
    /// in arrival order. Under this epoll's lock.
    fn drain_ready_stack(&mut self) {
        let mut top = self.record.epoll_link.swap(0, Ordering::AcqRel) as u32;
        // Reverse the stack: the oldest push comes first.
        let mut reversed = 0u32;
        while let Some(item) = self.region.item(top) {
            let next = item.ready_next.load(Ordering::Relaxed);
            item.ready_next.store(reversed, Ordering::Relaxed);
            reversed = top;
            top = next;
        }
        while let Some(item) = self.region.item(reversed) {
            let next = item.ready_next.load(Ordering::Relaxed);
            self.append_ready(reversed);
            reversed = next;
        }
    }

    fn append_ready(&mut self, number: u32) {
        let Some(item) = self.region.item(number) else {
            return;
        };
        item.ready_next.store(0, Ordering::Relaxed);
        // SAFETY: the object lock is held; the kind was checked by the caller.
        let state = unsafe { &mut (*self.record.state.get()).kind_state.counters.epoll };
        match self.region.item(state.ready_tail) {
            Some(tail) => tail.ready_next.store(number, Ordering::Relaxed),
            None => state.ready_head = number,
        }
        state.ready_tail = number;
    }

    fn prepend_ready(&mut self, number: u32) {
        let Some(item) = self.region.item(number) else {
            return;
        };
        // SAFETY: the object lock is held; the kind was checked by the caller.
        let state = unsafe { &mut (*self.record.state.get()).kind_state.counters.epoll };
        item.ready_next.store(state.ready_head, Ordering::Relaxed);
        state.ready_head = number;
        if state.ready_tail == 0 {
            state.ready_tail = number;
        }
    }

    fn pop_ready(&mut self) -> Option<u32> {
        // SAFETY: the object lock is held; the kind was checked by the caller.
        let state = unsafe { &mut (*self.record.state.get()).kind_state.counters.epoll };
        let number = state.ready_head;
        let item = self.region.item(number)?;
        state.ready_head = item.ready_next.load(Ordering::Relaxed);
        if state.ready_head == 0 {
            state.ready_tail = 0;
        }
        item.ready_next.store(0, Ordering::Relaxed);
        Some(number)
    }

    fn find_item(&mut self, fd: i32, file_key: u64) -> Option<u32> {
        // SAFETY: the object lock is held; the kind was checked by the caller.
        let state = unsafe { &*self.record.state.get() };
        let mut cursor = unsafe { state.kind_state.counters.epoll.interest_head };
        while let Some(item) = self.region.item(cursor) {
            if item.fd.load(Ordering::Relaxed) == fd as u32
                && item.file_key.load(Ordering::Relaxed) == file_key
            {
                return Some(cursor);
            }
            cursor = item.interest_next.load(Ordering::Relaxed);
        }
        None
    }

    fn link_item(
        &mut self,
        member: IpcObjectHandle,
        kind: EpollMember,
        fd: i32,
        file_key: u64,
        events: u32,
        data: u64,
    ) -> Result<(u32, &'a IpcEpollItem), EpollCtlError> {
        let region = self.region;
        let epoll = self.handle();
        let state = self.epoll_state()?;
        let Some((number, item)) = region.alloc_item() else {
            return Err(EpollCtlError::HostHalf(HostHalfReason::ItemsExhausted));
        };
        item.epoll.store(pack(epoll), Ordering::Relaxed);
        item.member.store(pack(member), Ordering::Relaxed);
        item.member_kind.store(kind as u32, Ordering::Relaxed);
        item.file_key.store(file_key, Ordering::Relaxed);
        item.fd.store(fd as u32, Ordering::Relaxed);
        item.events.store(events, Ordering::Relaxed);
        item.data.store(data, Ordering::Relaxed);
        item.flags.store(0, Ordering::Relaxed);
        item.ready_next.store(0, Ordering::Relaxed);
        item.reported_epoch.store(0, Ordering::Relaxed);
        let head = state.interest_head;
        item.interest_prev.store(0, Ordering::Relaxed);
        item.interest_next.store(head, Ordering::Relaxed);
        if let Some(next) = region.item(head) {
            next.interest_prev.store(number, Ordering::Relaxed);
        }
        state.interest_head = number;
        state.zone_items += 1;
        item.live.store(1, Ordering::Release);
        Ok((number, item))
    }

    fn publish_host_socket(
        &mut self,
        number: u32,
        item: &IpcEpollItem,
        level: u32,
        edge: bool,
    ) -> Option<IpcWake> {
        item.member.store(u64::from(level), Ordering::Relaxed);
        let interest = item.events.load(Ordering::Relaxed);
        if level & (interest | events::ALWAYS) == 0
            || (!edge && interest & events::ET != 0)
            || item.flags.load(Ordering::Relaxed) & (DISABLED | QUEUED) != 0
        {
            return None;
        }
        item.flags.fetch_or(QUEUED, Ordering::Relaxed);
        self.append_ready(number);
        Some(self.publish(WakeSet {
            readers: true,
            writers: false,
        }))
    }

    /// Unlink an item from this epoll's interest and ready lists (the stack
    /// was drained by `lock_epoll`).
    fn unlink_item(&mut self, number: u32) {
        let Some(item) = self.region.item(number) else {
            return;
        };
        // SAFETY: the object lock is held; the kind was checked by the caller.
        let state = unsafe { &mut (*self.record.state.get()).kind_state.counters.epoll };
        let prev = item.interest_prev.load(Ordering::Relaxed);
        let next = item.interest_next.load(Ordering::Relaxed);
        match self.region.item(prev) {
            Some(p) => p.interest_next.store(next, Ordering::Relaxed),
            None => state.interest_head = next,
        }
        if let Some(n) = self.region.item(next) {
            n.interest_prev.store(prev, Ordering::Relaxed);
        }
        state.zone_items = state.zone_items.saturating_sub(1);
        if item.flags.load(Ordering::Relaxed) & QUEUED != 0 {
            let mut prev_ready = 0u32;
            let mut cursor = state.ready_head;
            while let Some(entry) = self.region.item(cursor) {
                let after = entry.ready_next.load(Ordering::Relaxed);
                if cursor == number {
                    match self.region.item(prev_ready) {
                        Some(p) => p.ready_next.store(after, Ordering::Relaxed),
                        None => state.ready_head = after,
                    }
                    if state.ready_tail == number {
                        state.ready_tail = prev_ready;
                    }
                    break;
                }
                prev_ready = cursor;
                cursor = after;
            }
        }
    }

    /// Unlink an item from this member's list.
    fn unlink_member_item(&self, number: u32) {
        let Some(item) = self.region.item(number) else {
            return;
        };
        let prev = item.member_prev.load(Ordering::Relaxed);
        let next = item.member_next.load(Ordering::Relaxed);
        match self.region.item(prev) {
            Some(p) => p.member_next.store(next, Ordering::Relaxed),
            None => self
                .record
                .epoll_link
                .store(u64::from(next), Ordering::Relaxed),
        }
        if let Some(n) = self.region.item(next) {
            n.member_prev.store(prev, Ordering::Relaxed);
        }
    }

    /// Under this member's lock: unlink every item of `file_key` (every item
    /// when `None`) from its epoll (taking that epoll's lock, member then
    /// epoll) and from this member. The caller frees the returned items
    /// after unlocking.
    fn detach_member_items<W: LockWait>(
        &self,
        file_key: Option<u64>,
        wait: &W,
    ) -> Result<Removed, IpcError> {
        let mut removed = Removed {
            len: 0,
            numbers: [0; MAX_MEMBER_ITEMS],
        };
        let mut cursor = self.record.epoll_link.load(Ordering::Relaxed) as u32;
        while let Some(item) = self.region.item(cursor) {
            let number = cursor;
            cursor = item.member_next.load(Ordering::Relaxed);
            if file_key.is_some_and(|key| item.file_key.load(Ordering::Relaxed) != key) {
                continue;
            }
            let epoll = unpack(item.epoll.load(Ordering::Relaxed));
            match self.region.lock_epoll(epoll, wait) {
                Ok(mut guard) => guard.unlink_item(number),
                // A destroyed epoll already took its interest list; its
                // teardown frees the item after it unlinks it here.
                Err(IpcError::Stale) => continue,
                Err(error) => return Err(error),
            }
            self.unlink_member_item(number);
            if removed.len < MAX_MEMBER_ITEMS {
                removed.numbers[removed.len] = number;
                removed.len += 1;
            }
        }
        Ok(removed)
    }

    /// This member's current level, as Linux epoll event bits.
    pub fn member_level(&mut self, kind: EpollMember) -> Result<u32, IpcError> {
        let readiness = match kind {
            EpollMember::EventFd => self.eventfd()?.readiness(),
            EpollMember::HostSocket => return Err(IpcError::WrongKind),
            EpollMember::PipeReader => self.pipe()?.readiness(End::Reader),
            EpollMember::PipeWriter => self.pipe()?.readiness(End::Writer),
            EpollMember::StreamFirst | EpollMember::StreamSecond => {
                let end = kind.stream_end().ok_or(IpcError::Corrupt)?;
                return self.stream_level(end);
            }
        };
        let mut level = 0;
        if readiness.readable {
            level |= events::IN
                | if kind == EpollMember::EventFd {
                    0
                } else {
                    events::RDNORM
                };
        }
        if readiness.writable {
            level |= events::OUT
                | if kind == EpollMember::EventFd {
                    0
                } else {
                    events::WRNORM
                };
        }
        if readiness.hup {
            level |= events::HUP;
        }
        if readiness.err {
            level |= events::ERR;
        }
        Ok(level)
    }

    /// A connected stream end's level, as `poll(2)` reports an `AF_UNIX`
    /// stream socket: readable with bytes from its peer; RDHUP and readable
    /// once it receives no more (the peer shut its writes or closed, or
    /// this end shut its reads); HUP once both directions are shut; and
    /// writable while its own lane has room or no reader drains it (a
    /// write then fails with EPIPE).
    pub fn stream_level(&mut self, end: StreamEnd) -> Result<u32, IpcError> {
        let (rx_unread, rx_shut) = {
            let rx = self.stream_lane(end.peer())?;
            (
                rx.unread_bytes() != 0,
                rx.references(End::Reader) == 0 || rx.references(End::Writer) == 0,
            )
        };
        let (tx_room, tx_shut) = {
            let tx = self.stream_lane(end)?;
            (
                tx.readiness(End::Writer).writable,
                (
                    tx.references(End::Writer) == 0,
                    tx.references(End::Reader) == 0,
                ),
            )
        };
        let (own_write_shut, peer_gone) = tx_shut;
        let mut level = 0;
        if rx_unread || rx_shut {
            level |= events::IN | events::RDNORM;
        }
        if rx_shut {
            level |= events::RDHUP;
        }
        if rx_shut && (own_write_shut || peer_gone) {
            level |= events::HUP;
        }
        if tx_room || peer_gone {
            level |= events::OUT | events::WRNORM | events::WRBAND;
        }
        Ok(level)
    }

    /// Under this member's lock, from [`IpcObjectGuard::publish`]: queue
    /// every item interested in the published side on its epoll's
    /// lock-free stack. Returns the epolls to notify and whether any of
    /// them owes its host subscribers a wake.
    pub(super) fn publish_to_epolls(&self, wake: WakeSet) -> (EpollWakes, bool) {
        let mut wakes = EpollWakes::EMPTY;
        let mut host_owed = false;
        let mut cursor = self.record.epoll_link.load(Ordering::Relaxed) as u32;
        while let Some(item) = self.region.item(cursor) {
            let number = cursor;
            cursor = item.member_next.load(Ordering::Relaxed);
            let requested = item.events.load(Ordering::Relaxed);
            let interested = match EpollMember::from_raw(item.member_kind.load(Ordering::Relaxed)) {
                Some(EpollMember::PipeReader) => wake.readers,
                Some(EpollMember::PipeWriter) => wake.writers,
                // Either lane of a pair moves both ends' levels.
                Some(EpollMember::StreamFirst | EpollMember::StreamSecond) => {
                    wake.readers || wake.writers
                }
                Some(EpollMember::EventFd) => {
                    (wake.readers && requested & events::READ_SIDE != 0)
                        || (wake.writers && requested & events::WRITE_SIDE != 0)
                }
                Some(EpollMember::HostSocket) | None => false,
            };
            if !interested
                || item.flags.load(Ordering::Acquire) & DISABLED != 0
                || item.flags.fetch_or(QUEUED, Ordering::AcqRel) & QUEUED != 0
            {
                continue;
            }
            let epoll = unpack(item.epoll.load(Ordering::Relaxed));
            let Some(record) = self.region.record(epoll.index) else {
                continue;
            };
            // Push-only stack: a harvester takes it whole, so the classic
            // pop ABA cannot arise.
            let mut head = record.epoll_link.load(Ordering::Acquire);
            loop {
                item.ready_next.store(head as u32, Ordering::Relaxed);
                match record.epoll_link.compare_exchange_weak(
                    head,
                    u64::from(number),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(current) => head = current,
                }
            }
            record.read_seq.fetch_add(1, Ordering::Release);
            if record.host_subscribers.load(Ordering::Acquire) != 0 {
                record.owe_host_wake();
                self.region.index_host_wake(epoll.index);
                host_owed = true;
            }
            wakes.add(epoll);
        }
        (wakes, host_owed)
    }

    /// Under this member's lock, when the member object is being freed:
    /// detach every remaining item (a description release the host did not
    /// see, e.g. a final unpin in EL1). Returns the items to free.
    pub(super) fn detach_all_member_items<W: LockWait>(&self, wait: &W) -> Result<(), IpcError> {
        let removed = self.detach_member_items(None, wait)?;
        for number in removed.iter() {
            self.region.free_item(number);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
