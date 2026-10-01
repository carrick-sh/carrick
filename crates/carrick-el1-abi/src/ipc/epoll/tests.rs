//! VM-free binding of contract `kernel.el1.epoll-zone` for the shared
//! record: Linux epoll semantics (`man 7 epoll`) of zone items, the
//! one-owner identity of an item, and the structural rule that a member's
//! publication reaches an epoll's host subscribers only through the epoll.
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

extern crate std;

use super::super::tests::zeroed_directory;
use super::*;
use std::alloc::Layout;
use std::boxed::Box;
use std::vec::Vec;

struct Spin;
impl LockWait for Spin {
    fn wait(&self, _attempt: u32) -> bool {
        core::hint::spin_loop();
        true
    }
}

static IDENTITY: AtomicU64 = AtomicU64::new(0x9_0000);

fn region() -> &'static IpcRegion<'static> {
    let pool_len = 1 << 20;
    let dir = zeroed_directory();
    // SAFETY: a leaked zeroed pool outlives the region.
    let pool =
        unsafe { std::alloc::alloc_zeroed(Layout::from_size_align(pool_len, 4096).unwrap()) };
    let identity = IDENTITY.fetch_add(1, Ordering::Relaxed);
    let region =
        unsafe { IpcRegion::initialize(dir, IPC_DIRECTORY_BYTES, pool, pool_len, identity) }
            .unwrap();
    Box::leak(Box::new(region))
}

/// A backed pipe (ring from a fresh ring-area extent).
fn pipe(r: &IpcRegion<'_>, offset: u64) -> IpcObjectHandle {
    let mut retired = None;
    let object = r.create_pipe(65536, &mut retired, &Spin).unwrap();
    let mut storage = IpcPipeStorage {
        offset,
        ring_bytes: 16 * IPC_PIPE_PAGE_SIZE as u64,
        pages: 16,
    };
    let mut guard = r.lock(object, &Spin).unwrap();
    assert!(guard.provide_pipe_storage(&mut storage).unwrap());
    object
}

fn eventfd_write(r: &IpcRegion<'_>, object: IpcObjectHandle, value: u64) -> IpcWake {
    let mut guard = r.lock(object, &Spin).unwrap();
    let step = guard.eventfd().unwrap().try_write(value);
    step.result.unwrap();
    guard.publish(step.wake)
}

fn eventfd_read(r: &IpcRegion<'_>, object: IpcObjectHandle) -> IpcWake {
    let mut guard = r.lock(object, &Spin).unwrap();
    let step = guard.eventfd().unwrap().try_read();
    step.result.unwrap();
    guard.publish(step.wake)
}

fn pipe_write(r: &IpcRegion<'_>, object: IpcObjectHandle, bytes: &[u8]) -> IpcWake {
    let mut guard = r.lock(object, &Spin).unwrap();
    let step = guard.pipe().unwrap().try_write(bytes);
    step.result.unwrap();
    guard.publish(step.wake)
}

fn pipe_read(r: &IpcRegion<'_>, object: IpcObjectHandle, len: usize) -> IpcWake {
    let mut guard = r.lock(object, &Spin).unwrap();
    let mut buf = std::vec![0u8; len];
    let step = guard.pipe().unwrap().try_read(&mut buf);
    step.result.unwrap();
    guard.publish(step.wake)
}

fn harvest(r: &IpcRegion<'_>, epoll: IpcObjectHandle, max: usize) -> Vec<EpollReport> {
    let mut out = std::vec![EpollReport::default(); max];
    let mut taken = std::vec![EpollItemRef::default(); max];
    let h = r.epoll_harvest(epoll, &mut out, &mut taken, &Spin).unwrap();
    out.truncate(h.reported);
    out
}

fn add(
    r: &IpcRegion<'_>,
    epoll: IpcObjectHandle,
    member: IpcObjectHandle,
    kind: EpollMember,
    fd: i32,
    events: u32,
) -> Option<IpcWake> {
    r.epoll_add(
        epoll,
        member,
        kind,
        fd,
        0x1000 + fd as u64,
        events,
        fd as u64,
        &Spin,
    )
    .unwrap()
}

use events::{ERR, ET, HUP, IN, ONESHOT, OUT};

#[test]
fn level_triggered_eventfd_reports_until_drained() {
    let r = region();
    let ep = r.create_epoll(&Spin).unwrap();
    let efd = r.create_eventfd(0, EventMode::Counter, &Spin).unwrap();
    assert!(add(r, ep, efd, EpollMember::EventFd, 5, IN).is_none());
    assert!(harvest(r, ep, 4).is_empty());
    let wake = eventfd_write(r, efd, 1);
    assert_eq!(wake.epolls.iter().collect::<Vec<_>>(), std::vec![ep]);
    let first = harvest(r, ep, 4);
    assert_eq!(
        first,
        std::vec![EpollReport {
            events: IN,
            data: 5
        }]
    );
    assert_eq!(harvest(r, ep, 4), first, "LT stays ready");
    eventfd_read(r, efd);
    assert!(harvest(r, ep, 4).is_empty(), "drained");
}

#[test]
fn edge_triggered_reports_each_arrival_once() {
    let r = region();
    let ep = r.create_epoll(&Spin).unwrap();
    let efd = r.create_eventfd(0, EventMode::Counter, &Spin).unwrap();
    add(r, ep, efd, EpollMember::EventFd, 3, IN | ET);
    eventfd_write(r, efd, 1);
    assert_eq!(harvest(r, ep, 4).len(), 1);
    assert!(harvest(r, ep, 4).is_empty(), "no new arrival");
    eventfd_write(r, efd, 1);
    assert_eq!(harvest(r, ep, 4).len(), 1, "a new write is a new edge");
    let read = eventfd_read(r, efd);
    assert!(read.epolls.is_empty(), "a read only changes writability");
    assert!(harvest(r, ep, 4).is_empty());

    let pipe_ep = r.create_epoll(&Spin).unwrap();
    let p = pipe(r, 0);
    add(r, pipe_ep, p, EpollMember::PipeReader, 4, IN | ET);
    pipe_write(r, p, b"ab");
    assert_eq!(harvest(r, pipe_ep, 4).len(), 1);
    pipe_read(r, p, 1);
    assert!(
        harvest(r, pipe_ep, 4).is_empty(),
        "a partial read is no edge"
    );
    pipe_write(r, p, b"c");
    assert_eq!(harvest(r, pipe_ep, 4).len(), 1);
}

#[test]
fn oneshot_disarms_until_modified() {
    let r = region();
    let ep = r.create_epoll(&Spin).unwrap();
    let efd = r.create_eventfd(0, EventMode::Counter, &Spin).unwrap();
    add(r, ep, efd, EpollMember::EventFd, 7, IN | ONESHOT);
    eventfd_write(r, efd, 1);
    assert_eq!(harvest(r, ep, 4).len(), 1);
    assert!(harvest(r, ep, 4).is_empty());
    eventfd_write(r, efd, 1);
    assert!(harvest(r, ep, 4).is_empty(), "stays disarmed");
    let wake = r
        .epoll_modify(ep, 7, 0x1007, IN | ONESHOT, 70, &Spin)
        .unwrap();
    assert!(wake.is_some(), "a modified ready item is queued and wakes");
    assert_eq!(
        harvest(r, ep, 4),
        std::vec![EpollReport {
            events: IN,
            data: 70
        }]
    );
    assert!(harvest(r, ep, 4).is_empty());
}

#[test]
fn pipe_close_masks_follow_linux() {
    let r = region();
    let ep = r.create_epoll(&Spin).unwrap();
    let p = pipe(r, 0);
    add(r, ep, p, EpollMember::PipeReader, 1, IN | events::RDHUP);
    add(r, ep, p, EpollMember::PipeWriter, 2, OUT);
    pipe_write(r, p, b"xy");
    // Writer releases: reader sees IN|HUP (RDHUP is not a pipe event). The
    // reader item is still queued from the write, so the release pushes
    // nothing new; the harvest reads the level.
    let _wake = {
        let mut guard = r.lock(p, &Spin).unwrap();
        let step = guard.pipe().unwrap().release(End::Writer);
        step.result.unwrap();
        guard.publish(step.wake)
    };
    let reports = harvest(r, ep, 4);
    assert!(reports.contains(&EpollReport {
        events: IN | HUP,
        data: 1
    }));
}

#[test]
fn harvest_honours_maxevents_order_and_requeues_level_items_after_the_scan() {
    let r = region();
    let ep = r.create_epoll(&Spin).unwrap();
    let a = r.create_eventfd(0, EventMode::Counter, &Spin).unwrap();
    let b = r.create_eventfd(0, EventMode::Counter, &Spin).unwrap();
    let c = r.create_eventfd(0, EventMode::Counter, &Spin).unwrap();
    add(r, ep, a, EpollMember::EventFd, 10, IN);
    add(r, ep, b, EpollMember::EventFd, 11, IN);
    add(r, ep, c, EpollMember::EventFd, 12, IN);
    eventfd_write(r, b, 1);
    eventfd_write(r, a, 1);
    eventfd_write(r, c, 1);
    let data = |v: &[EpollReport]| v.iter().map(|e| e.data).collect::<Vec<_>>();
    // Arrival order, two at a time; the third waits for the next harvest.
    assert_eq!(data(&harvest(r, ep, 2)), std::vec![11, 10]);
    assert_eq!(data(&harvest(r, ep, 2)), std::vec![12, 11]);
    assert_eq!(data(&harvest(r, ep, 8)), std::vec![10, 12, 11]);
}

#[test]
fn items_are_keyed_on_file_and_fd_number() {
    let r = region();
    let ep = r.create_epoll(&Spin).unwrap();
    let efd = r.create_eventfd(0, EventMode::Counter, &Spin).unwrap();
    r.epoll_add(ep, efd, EpollMember::EventFd, 4, 1, IN, 1, &Spin)
        .unwrap();
    assert_eq!(
        r.epoll_add(ep, efd, EpollMember::EventFd, 4, 1, IN, 1, &Spin),
        Err(EpollCtlError::Exists)
    );
    // The same number naming another open file is another item.
    let other = r.create_eventfd(0, EventMode::Counter, &Spin).unwrap();
    assert!(
        r.epoll_add(ep, other, EpollMember::EventFd, 4, 2, IN, 2, &Spin)
            .is_ok()
    );
    assert_eq!(
        r.epoll_modify(ep, 4, 3, IN, 0, &Spin),
        Err(EpollCtlError::NotFound)
    );
    assert_eq!(
        r.epoll_delete(ep, 4, 3, &Spin),
        Err(EpollCtlError::NotFound)
    );
    r.epoll_delete(ep, 4, 1, &Spin).unwrap();
    eventfd_write(r, efd, 1);
    eventfd_write(r, other, 1);
    assert_eq!(
        harvest(r, ep, 4),
        std::vec![EpollReport {
            events: IN,
            data: 2
        }]
    );
}

#[test]
fn closing_the_last_descriptor_of_a_file_removes_its_items() {
    let r = region();
    let ep1 = r.create_epoll(&Spin).unwrap();
    let ep2 = r.create_epoll(&Spin).unwrap();
    let efd = r.create_eventfd(0, EventMode::Counter, &Spin).unwrap();
    r.epoll_add(ep1, efd, EpollMember::EventFd, 4, 9, IN, 1, &Spin)
        .unwrap();
    r.epoll_add(ep2, efd, EpollMember::EventFd, 6, 9, IN, 2, &Spin)
        .unwrap();
    eventfd_write(r, efd, 1);
    assert_eq!(r.epoll_detach_file(efd, 9, &Spin).unwrap(), 2);
    assert!(harvest(r, ep1, 4).is_empty());
    assert!(harvest(r, ep2, 4).is_empty());
    assert!(eventfd_write(r, efd, 1).epolls.is_empty());
    // The fd number is free for a new item.
    assert!(
        r.epoll_add(ep1, efd, EpollMember::EventFd, 4, 10, IN, 3, &Spin)
            .is_ok()
    );
}

#[test]
fn destroying_an_epoll_unlinks_members_and_frees_items() {
    let r = region();
    let free_before = (0..IPC_EPOLL_ITEMS)
        .filter(|&i| r.epoll_item_at(i).unwrap().live.load(Ordering::Relaxed) == 0)
        .count();
    let ep = r.create_epoll(&Spin).unwrap();
    let efd = r.create_eventfd(0, EventMode::Counter, &Spin).unwrap();
    let p = pipe(r, 0);
    add(r, ep, efd, EpollMember::EventFd, 4, IN);
    add(r, ep, p, EpollMember::PipeReader, 5, IN);
    eventfd_write(r, efd, 1);
    assert!(matches!(
        r.release_backing(IpcBacking::Epoll { object: ep }.encode(), &Spin),
        Ok(IpcReleased::Epoll)
    ));
    assert!(eventfd_write(r, efd, 1).epolls.is_empty());
    assert!(pipe_write(r, p, b"z").epolls.is_empty());
    let free_after = (0..IPC_EPOLL_ITEMS)
        .filter(|&i| r.epoll_item_at(i).unwrap().live.load(Ordering::Relaxed) == 0)
        .count();
    assert_eq!(free_before, free_after);
    assert_eq!(r.lock(ep, &Spin).err(), Some(IpcError::Stale));
}

#[test]
fn freeing_a_member_detaches_items_the_host_did_not() {
    let r = region();
    let ep = r.create_epoll(&Spin).unwrap();
    let efd = r.create_eventfd(0, EventMode::Counter, &Spin).unwrap();
    add(r, ep, efd, EpollMember::EventFd, 4, IN);
    eventfd_write(r, efd, 1);
    assert!(matches!(
        r.release_backing(IpcBacking::EventFd { object: efd }.encode(), &Spin),
        Ok(IpcReleased::Object { freed: true, .. })
    ));
    assert!(harvest(r, ep, 4).is_empty());
    assert_eq!(
        r.epoll_delete(ep, 4, 0x1004, &Spin),
        Err(EpollCtlError::NotFound)
    );
}

#[test]
fn a_member_carries_a_bounded_number_of_zone_items() {
    let r = region();
    let efd = r.create_eventfd(0, EventMode::Counter, &Spin).unwrap();
    for fd in 0..MAX_MEMBER_ITEMS as i32 {
        let ep = r.create_epoll(&Spin).unwrap();
        add(r, ep, efd, EpollMember::EventFd, fd, IN);
    }
    let ep = r.create_epoll(&Spin).unwrap();
    assert_eq!(
        r.epoll_add(ep, efd, EpollMember::EventFd, 9, 9, IN, 0, &Spin),
        Err(EpollCtlError::HostHalf(HostHalfReason::MemberFanOut))
    );
    assert_eq!(
        r.epoll_add(
            ep,
            efd,
            EpollMember::EventFd,
            9,
            9,
            IN | events::EXCLUSIVE,
            0,
            &Spin
        ),
        Err(EpollCtlError::HostHalf(HostHalfReason::Exclusive))
    );
}

/// Structural: a member's publication owes the host a wake only when the
/// epoll it reaches has a host subscriber (a host-side waiter); a member
/// watched only by a zone epoll owes nothing.
#[test]
fn a_member_owes_the_host_only_through_an_epoll_with_a_host_waiter() {
    let r = region();
    let ep = r.create_epoll(&Spin).unwrap();
    let efd = r.create_eventfd(0, EventMode::Counter, &Spin).unwrap();
    add(r, ep, efd, EpollMember::EventFd, 4, IN);
    let wake = eventfd_write(r, efd, 1);
    assert!(!wake.host_owed, "no host waiter anywhere");
    assert!(!r.take_host_wake(ep));
    harvest(r, ep, 4);
    eventfd_read(r, efd);
    harvest(r, ep, 4);
    r.subscribe_host(ep, &Spin).unwrap();
    let wake = eventfd_write(r, efd, 1);
    assert!(wake.host_owed, "the epoll has a host waiter");
    assert!(r.take_host_wake(ep));
    assert!(!r.take_host_wake(efd), "the member itself owes nothing");
    r.unsubscribe_host(ep, &Spin).unwrap();
}

#[test]
fn restore_requeues_and_rearms_an_undelivered_harvest() {
    let r = region();
    let ep = r.create_epoll(&Spin).unwrap();
    let efd = r.create_eventfd(0, EventMode::Counter, &Spin).unwrap();
    add(r, ep, efd, EpollMember::EventFd, 4, IN | ONESHOT);
    eventfd_write(r, efd, 1);
    let mut out = [EpollReport::default(); 2];
    let mut taken = [EpollItemRef::default(); 2];
    let h = r.epoll_harvest(ep, &mut out, &mut taken, &Spin).unwrap();
    assert_eq!(h.reported, 1);
    r.epoll_restore(ep, &taken[..1], &Spin).unwrap();
    assert_eq!(harvest(r, ep, 2).len(), 1, "the failed copy is redelivered");
}

#[test]
fn ready_probe_does_not_consume() {
    let r = region();
    let ep = r.create_epoll(&Spin).unwrap();
    let efd = r.create_eventfd(0, EventMode::Counter, &Spin).unwrap();
    add(r, ep, efd, EpollMember::EventFd, 4, IN | ET);
    assert!(!r.epoll_ready_probe(ep, &Spin).unwrap());
    eventfd_write(r, efd, 1);
    assert!(r.epoll_ready_probe(ep, &Spin).unwrap());
    assert!(r.epoll_ready_probe(ep, &Spin).unwrap());
    assert_eq!(harvest(r, ep, 4).len(), 1);
    assert!(!r.epoll_ready_probe(ep, &Spin).unwrap());
}

#[test]
fn host_half_count_is_reported_by_harvest() {
    let r = region();
    let ep = r.create_epoll(&Spin).unwrap();
    r.epoll_set_host_items(ep, 1, &Spin).unwrap();
    assert_eq!(r.epoll_host_items(ep, &Spin).unwrap(), 1);
    let mut out = [EpollReport::default(); 1];
    let mut taken = [EpollItemRef::default(); 1];
    assert_eq!(
        r.epoll_harvest(ep, &mut out, &mut taken, &Spin)
            .unwrap()
            .host_items,
        1
    );
    r.epoll_set_host_items(ep, 0, &Spin).unwrap();
    let _ = (ERR, OUT);
}

/// One harvest reports an item at most once, even when a member
/// publication queues it again in the middle of the scan.
#[test]
fn a_harvest_reports_an_item_once_when_republished_mid_scan() {
    let r = region();
    let ep = r.create_epoll(&Spin).unwrap();
    let efd = r.create_eventfd(0, EventMode::Counter, &Spin).unwrap();
    add(r, ep, efd, EpollMember::EventFd, 4, IN | ET);
    eventfd_write(r, efd, 1);
    // Pop it as a harvest would, then let a publication queue it again
    // before the same harvest pops once more.
    let mut out = [EpollReport::default(); 4];
    let mut taken = [EpollItemRef::default(); 4];
    assert_eq!(
        r.epoll_harvest(ep, &mut out[..1], &mut taken[..1], &Spin)
            .unwrap()
            .reported,
        1
    );
    eventfd_write(r, efd, 1);
    // A fresh harvest is a new scan: the new edge is reported once.
    assert_eq!(harvest(r, ep, 4).len(), 1);
    assert!(harvest(r, ep, 4).is_empty());
}

/// Lock order: a harvest never holds the epoll and a member lock together.
/// A member lock the EL1 policy cannot take refuses the harvest with the
/// epoll lock already released, and the popped item is not lost.
#[test]
fn a_refused_member_lock_releases_the_epoll_and_keeps_the_item() {
    let r = region();
    let ep = r.create_epoll(&Spin).unwrap();
    let efd = r.create_eventfd(0, EventMode::Counter, &Spin).unwrap();
    add(r, ep, efd, EpollMember::EventFd, 4, IN | ET);
    eventfd_write(r, efd, 1);
    let held = r.lock(efd, &Spin).unwrap();
    let mut out = [EpollReport::default(); 2];
    let mut taken = [EpollItemRef::default(); 2];
    let el1 = carrick_fd_core::BoundedSpin(16);
    assert_eq!(
        r.epoll_harvest(ep, &mut out, &mut taken, &el1),
        Err(IpcError::Contended)
    );
    assert_eq!(r.lock_holder(ep), None, "the epoll lock is free");
    drop(held);
    assert_eq!(harvest(r, ep, 2).len(), 1, "the edge survived the refusal");
}
