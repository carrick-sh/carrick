//! The host venue of a zone epoll record (contract `kernel.el1.epoll-zone`).
//!
//! An epoll description owns one [`ZoneEpoll`]: the shared record
//! ([`carrick_el1_abi::ipc::epoll`]) that is the single authority for its
//! in-zone items (eventfds and pipe ends). Every other item stays in the
//! description's host interest map. An item's home is chosen by member type
//! at `EPOLL_CTL_ADD` and never changes; the record counts the host half so
//! EL1 serves a wait only on a set with none.
//!
//! Host-side waiters (a host `epoll_pwait`, a parent epoll, poll/select on
//! the epoll fd) are the only reason a member's change reaches the host:
//! while one exists the record has a host subscriber, and a member's
//! publication owes the host a wake through this epoll, delivered by
//! [`ZoneEpoll`]'s publisher (the instance kqueue's user wake and the
//! description's wait queue). With no host-side waiter a member's change
//! costs no host exit.

use std::sync::{Arc, Weak};

use carrick_el1_abi::ipc::epoll::{
    EpollCtlError, EpollItemRef, EpollMember, EpollReport, HostHalfReason,
};
use carrick_el1_abi::ipc::{IpcBacking, IpcObjectHandle, IpcWake, fd};
use parking_lot::Mutex;

use crate::el1_ipc::{HostDescription, HostDescriptionFlags, HostIpc};
use crate::el1_zone::HostLockWait;
use crate::linux_abi::LinuxEpollEvent;

/// A zone epoll item's member: an IPC object side and the identity of the
/// open file (its shared OFD) it was added through.
#[derive(Debug)]
pub(crate) struct ZoneMember {
    pub(crate) owner: Arc<HostIpc>,
    pub(crate) object: IpcObjectHandle,
    pub(crate) kind: EpollMember,
    pub(crate) file_key: u64,
}

/// What a zone `epoll_ctl` decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ZoneCtl {
    /// Done in the zone record.
    Done,
    /// `EEXIST`, `ENOENT` or `EINVAL` for the guest.
    Exists,
    NotFound,
    Invalid,
    /// The item belongs in the host's half (a placement, never visible).
    HostHalf(HostHalfReason),
}

/// The zone record of one epoll description.
pub(crate) struct ZoneEpoll {
    owner: Arc<HostIpc>,
    object: IpcObjectHandle,
    /// The record's OFD (backing `IpcBacking::Epoll`) the host holds while
    /// any descriptor names the epoll; its final release destroys the record.
    lifetime: Mutex<Option<HostDescription>>,
    /// The host wake target for this epoll's owed wakes, held alive here.
    _publisher: Arc<dyn Fn() + Send + Sync>,
    _primer: Arc<dyn Fn() + Send + Sync>,
    /// Whose turn reports first on a mixed set (true: the host half).
    host_turn: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for ZoneEpoll {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZoneEpoll")
            .field("object", &self.object)
            .finish_non_exhaustive()
    }
}

/// Zone harvest result: reports in arrival order and the items taken, for a
/// restore when the reports cannot be delivered.
pub(crate) struct ZoneHarvest {
    pub(crate) events: Vec<LinuxEpollEvent>,
    pub(crate) taken: Vec<EpollItemRef>,
    pub(crate) host_items: u32,
}

impl ZoneEpoll {
    /// Create the record for a new epoll description. `kqueue` and
    /// `wait_queue` are the description's host wake channels (weak: the
    /// description owns them). `None`: no IPC authority, or its stores are
    /// exhausted; the epoll then keeps every item in the host half.
    pub(crate) fn create(
        owner: &Arc<HostIpc>,
        object: IpcObjectHandle,
        kqueue: Weak<crate::dispatch::EpollKqueue>,
        wait_queue: Weak<crate::kernel::WaitQueue>,
    ) -> Option<Arc<Self>> {
        let backing = IpcBacking::Epoll { object }.encode();
        let lifetime = match owner.admit_description(fd::Description::new(
            backing,
            fd::AccessMode::ReadWrite,
            fd::StatusFlags::default(),
        )) {
            Ok(lifetime) => lifetime,
            Err(_) => {
                let _ = owner.region().epoll_destroy(object, &HostLockWait);
                return None;
            }
        };
        let publisher: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            if let Some(kqueue) = kqueue.upgrade() {
                kqueue.wake_parked();
            }
            if let Some(queue) = wait_queue.upgrade() {
                queue.wake_all();
            }
        });
        let primer: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});
        owner.register_host_waker(object, &publisher, &primer);
        Some(Arc::new(Self {
            owner: Arc::clone(owner),
            object,
            lifetime: Mutex::new(Some(lifetime)),
            _publisher: publisher,
            _primer: primer,
            host_turn: std::sync::atomic::AtomicBool::new(false),
        }))
    }

    /// The epoll description's shared flags (its OFD), for file-table
    /// publication: EL1 resolves an epoll fd to this record through it.
    pub(crate) fn status_flags(&self) -> Option<Arc<HostDescriptionFlags>> {
        self.lifetime.lock().as_ref().map(HostDescription::flags)
    }

    /// The last descriptor closed: release the host's hold on the record.
    /// It is destroyed (every zone item retired) once no in-flight guest
    /// operation still pins it.
    pub(crate) fn close(&self) {
        let lifetime = self.lifetime.lock().take();
        drop(lifetime);
    }

    pub(crate) fn belongs_to(&self, owner: &Arc<HostIpc>) -> bool {
        Arc::ptr_eq(&self.owner, owner)
    }

    /// The subscription a description wait queue takes while a parent
    /// epoll or poll waiter is enrolled on it.
    pub(crate) fn queue_subscription(
        owner: Arc<HostIpc>,
        object: IpcObjectHandle,
    ) -> impl Fn() -> Option<Box<dyn std::fmt::Debug + Send + Sync>> + Send + Sync + 'static {
        move || {
            let subscription = owner.subscribe_host(object).ok()?;
            Some(Box::new(subscription) as Box<dyn std::fmt::Debug + Send + Sync>)
        }
    }

    fn deliver(&self, wake: Option<IpcWake>) {
        let Some(wake) = wake else {
            return;
        };
        let mut delivery = crate::el1_zone::ObjectWakeDelivery::new();
        delivery.collect(wake);
        delivery.deliver();
        self.owner.service_wake(&wake);
    }

    fn ctl(result: Result<Option<IpcWake>, EpollCtlError>, this: &Self) -> ZoneCtl {
        match result {
            Ok(wake) => {
                this.deliver(wake);
                ZoneCtl::Done
            }
            Err(EpollCtlError::Exists) => ZoneCtl::Exists,
            Err(EpollCtlError::NotFound) => ZoneCtl::NotFound,
            Err(EpollCtlError::Invalid) => ZoneCtl::Invalid,
            Err(EpollCtlError::HostHalf(reason)) => ZoneCtl::HostHalf(reason),
            // A member retired between lookup and lock: no such item.
            Err(EpollCtlError::Ipc(carrick_el1_abi::ipc::IpcError::Stale)) => ZoneCtl::NotFound,
            Err(EpollCtlError::Ipc(error)) => carrick_fatal::carrick_fatal!(
                "epoll::zone",
                "zone epoll_ctl refused by the shared record: {error:?}"
            ),
        }
    }

    /// `EPOLL_CTL_ADD` of a zone member.
    pub(crate) fn add(&self, member: &ZoneMember, fd: i32, events: u32, data: u64) -> ZoneCtl {
        if !Arc::ptr_eq(&member.owner, &self.owner) {
            return ZoneCtl::HostHalf(HostHalfReason::ItemsExhausted);
        }
        let result = self.owner.region().epoll_add(
            self.object,
            member.object,
            member.kind,
            fd,
            member.file_key,
            events,
            data,
            &HostLockWait,
        );
        Self::ctl(result, self)
    }

    /// `EPOLL_CTL_MOD` of the zone item `(fd, file_key)`.
    pub(crate) fn modify(&self, fd: i32, file_key: u64, events: u32, data: u64) -> ZoneCtl {
        let result = self.owner.region().epoll_modify(
            self.object,
            fd,
            file_key,
            events,
            data,
            &HostLockWait,
        );
        Self::ctl(result, self)
    }

    /// `EPOLL_CTL_DEL` of the zone item `(fd, file_key)`.
    pub(crate) fn delete(&self, fd: i32, file_key: u64) -> ZoneCtl {
        let result = self
            .owner
            .region()
            .epoll_delete(self.object, fd, file_key, &HostLockWait)
            .map(|()| None);
        Self::ctl(result, self)
    }

    /// The host half now has `count` items (EL1 serves only at zero).
    pub(crate) fn set_host_items(&self, count: usize) {
        let count = u32::try_from(count).unwrap_or(u32::MAX);
        let _ = self
            .owner
            .region()
            .epoll_set_host_items(self.object, count, &HostLockWait);
    }

    /// Harvest up to `max` zone reports (the shared routine EL1 uses).
    pub(crate) fn harvest(&self, max: usize) -> ZoneHarvest {
        let mut out = vec![EpollReport::default(); max];
        let mut taken = vec![EpollItemRef::default(); max];
        let harvest = self
            .owner
            .region()
            .epoll_harvest(self.object, &mut out, &mut taken, &HostLockWait)
            .unwrap_or_else(|error| {
                carrick_fatal::carrick_fatal!("epoll::zone", "zone harvest refused: {error:?}")
            });
        out.truncate(harvest.reported);
        taken.truncate(harvest.reported);
        ZoneHarvest {
            events: out
                .into_iter()
                .map(|report| LinuxEpollEvent {
                    events: report.events,
                    _pad: 0,
                    data: report.data,
                })
                .collect(),
            taken,
            host_items: harvest.host_items,
        }
    }

    /// Whether this mixed-set call is the host half's turn to report first;
    /// turns alternate call by call, the zone half first.
    pub(crate) fn take_host_turn(&self) -> bool {
        self.host_turn
            .fetch_xor(true, std::sync::atomic::Ordering::Relaxed)
    }

    /// Queue undelivered harvested items again (an unwritable buffer, or
    /// reports past the budget).
    pub(crate) fn restore(&self, taken: &[EpollItemRef]) {
        if taken.is_empty() {
            return;
        }
        let _ = self
            .owner
            .region()
            .epoll_restore(self.object, taken, &HostLockWait);
    }

    /// Items in the zone half.
    pub(crate) fn zone_items(&self) -> usize {
        self.owner
            .region()
            .epoll_zone_items(self.object, &HostLockWait)
            .map_or(0, |n| n as usize)
    }

    /// Whether the zone half holds an item for fd number `fd`.
    #[cfg(test)]
    pub(crate) fn has_item_fd(&self, fd: i32) -> bool {
        self.owner
            .region()
            .epoll_has_item_fd(self.object, fd, &HostLockWait)
            .unwrap_or(false)
    }

    /// Whether the zone half has a reportable item (non-consuming).
    pub(crate) fn ready(&self) -> bool {
        self.owner
            .region()
            .epoll_ready_probe(self.object, &HostLockWait)
            .unwrap_or(false)
    }
}

/// Remove every zone item of a member's open file whose last descriptor
/// closed (`man 7 epoll`).
pub(crate) fn detach_member_file(member: &ZoneMember) {
    let _ = member
        .owner
        .region()
        .epoll_detach_file(member.object, member.file_key, &HostLockWait);
}

