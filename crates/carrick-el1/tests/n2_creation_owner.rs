//! N2 landing-A portable owner witnesses. These use the production personality
//! dispatcher with explicit regions, never the host-only dispatch stub.
//!
//! Linux authority: https://man7.org/linux/man-pages/man2/clone.2.html (child
//! return zero, inherited state, shared MM and files). Each admitted creation
//! must save exactly one child context, publish exactly one Born entry and
//! queue it once with no semantic forward. Two live MM identities use the same
//! child stack VA. Stocked identities are fixture resources, not host services.
//!
//! The 21-ID census is a baseline characterization, not a zero-work acceptance
//! pass: process clone and exec still forward. The zero-dispatch budget reds
//! live in a separate follow-on commit on work/n2a-witness for the N2 ownership
//! landing. Hardware MM/IPC execution, loader byte batches and runtime executor
//! exhaustion remain unsupported in this layer.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Duration;

use carrick_el1::personality::lifecycle::{LifecycleThread, LifecycleVenue};
use carrick_el1::{Zone, dispatch_syscall_with_lifecycle, dispatch_syscall_with_regions, sched};
use carrick_el1_abi::{
    Action, BlockedMask, Counters, CurrentTask, El1TaskId, EntryIdentity, EntryRef, EntryState,
    InotifyNameCache, SlotId, THREAD_POOL_ENTRIES, ThreadControlSlot, ThreadCtx,
    ThreadLifecyclePage, TrapFrame, ZoneTables,
};

// The plan's 18 numeric IDs, plus robust-list 99 and execve/execveat 221/281.
const CREATION_IDS: [usize; 21] = [
    220, 93, 94, 96, 178, 122, 103, 134, 214, 215, 222, 226, 57, 59, 64, 73, 98, 260, 99, 221, 281,
];
const SAME_VA: u64 = 0x4000_1000;
const GO_THREAD_FLAGS: u64 = 0x0005_0f00;

/// One creator process, with the ordinary eight-entry identity pool. Distinct
/// processes may share an MM (CLONE_VM without CLONE_THREAD); the two MM roots
/// and per-process file descriptions remain distinct in this fixture.
struct Venue {
    parent_tid: u64,
    page: ThreadLifecyclePage,
    leader: ThreadControlSlot,
    children: [ThreadControlSlot; THREAD_POOL_ENTRIES],
}

impl Venue {
    fn new(tid: u32) -> Self {
        let page = ThreadLifecyclePage::new();
        for index in 0..THREAD_POOL_ENTRIES {
            page.stock(
                index,
                EntryIdentity {
                    tid: 10_000 + tid * THREAD_POOL_ENTRIES as u32 + index as u32,
                    visible_tid: 10_000 + tid * THREAD_POOL_ENTRIES as u32 + index as u32,
                    thread_serial: u64::from(tid) * 100 + index as u64,
                    uid_credit: 1,
                },
            )
            .unwrap();
        }
        let leader = ThreadControlSlot::new();
        leader.init_blocked(BlockedMask(u64::from(tid)));
        Self {
            parent_tid: u64::from(tid),
            page,
            leader,
            children: core::array::from_fn(|_| ThreadControlSlot::new()),
        }
    }
}

impl LifecycleVenue for Venue {
    fn thread(&self, task: &CurrentTask) -> Option<LifecycleThread<'_>> {
        (task.task_id.load(Ordering::Acquire) == self.parent_tid).then_some(LifecycleThread {
            page: &self.page,
            slot: &self.leader,
        })
    }

    fn born_slot(&self, page: &ThreadLifecyclePage, entry: EntryRef) -> Option<&ThreadControlSlot> {
        core::ptr::eq(page, &self.page)
            .then(|| self.children.get(entry.index()))
            .flatten()
    }
}

/// Only context save is legal in this non-switching fixture. Unexpected CPU
/// operations fail immediately; no hardware instruction can execute on Linux.
#[derive(Default)]
struct SaveCpu {
    saves: usize,
}

impl sched::ThreadCpu for SaveCpu {
    fn save(&mut self, frame: &TrapFrame, ctx: &mut ThreadCtx) {
        self.saves += 1;
        ctx.x = frame.x;
        ctx.pc = frame.elr;
        ctx.pstate = frame.spsr;
    }
    fn load(&mut self, _: &mut TrapFrame, _: &ThreadCtx) {
        unreachable!("no switch")
    }
    fn set_translation(&mut self, _: u64, _: u64) {
        unreachable!("no root install")
    }
    fn invalidate_asid(&mut self, _: u64) {
        unreachable!("no invalidation")
    }
    fn now(&self) -> u64 {
        1
    }
    fn freq(&self) -> u64 {
        24_000_000
    }
    fn set_timer(&mut self, _: Option<u64>) {}
    fn send_sgi(&mut self, _: u64) {
        unreachable!("no remote wake")
    }
    fn ack_irq(&mut self) -> u32 {
        unreachable!("no IRQ")
    }
    fn end_irq(&mut self, _: u32) {
        unreachable!("no IRQ")
    }
    fn wait_for_interrupt(&mut self) {
        unreachable!("no idle")
    }
    fn spin(&mut self) {
        unreachable!("no idle")
    }
    fn own_sgi_target(&self) -> u64 {
        1
    }
}

fn zone() -> Box<ZoneTables> {
    // SAFETY: ZoneTables' empty ABI representation is all-zero, as used by
    // the existing owner tests. Allocate directly on the heap (large table).
    let zone = unsafe { Box::<ZoneTables>::new_zeroed().assume_init() };
    for mm in [71, 83] {
        let index = zone.spaces.publish_closed(mm, mm << 12, mm << 12).unwrap();
        zone.spaces.open(index);
    }
    zone
}

#[test]
fn admitted_thread_creation_owns_one_completion_at_1_8_32() {
    for n in [1, 8, 32] {
        let zone = zone();
        let counters = Counters::default();
        let tasks: Vec<_> = (0..n.max(2))
            .map(|i| {
                let task = CurrentTask::new();
                task.set(El1TaskId::from_linux_tid(40 + i as i32), 1, 500 + i as u64);
                task.zone_mm
                    .store(if i % 2 == 0 { 71 } else { 83 }, Ordering::Release);
                task.thread_serial.store(100 + i as u64, Ordering::Release);
                task
            })
            .collect();
        let venues: Vec<_> = (0..n).map(|i| Venue::new(40 + i as u32)).collect();
        for (i, task) in tasks.iter().take(n).enumerate() {
            let slot = SlotId::from_index(i).unwrap();
            let mm = task.zone_mm.load(Ordering::Acquire);
            zone.drive(slot, i as u64 + 1);
            zone.publish_slot(slot, mm, None, 0);
        }
        let (ready_tx, ready_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let mut releases = Vec::new();
            let mut handles = Vec::new();
            for (i, venue) in venues.iter().enumerate() {
                let (go_tx, go_rx) = mpsc::channel();
                releases.push(go_tx);
                let ready = ready_tx.clone();
                let zone = &zone;
                let tasks = &tasks;
                let counters = &counters;
                handles.push(scope.spawn(move || {
                    ready.send(()).unwrap();
                    go_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    let mut cpu = SaveCpu::default();
                    let mut frame = TrapFrame {
                        slot: i as u64,
                        elr: 0x4000,
                        ..TrapFrame::default()
                    };
                    frame.x[8] = 220;
                    frame.x[0] = GO_THREAD_FLAGS;
                    frame.x[1] = SAME_VA;
                    assert_eq!(
                        dispatch_syscall_with_lifecycle(
                            &mut frame,
                            counters,
                            tasks,
                            &[],
                            &[],
                            &[],
                            &[],
                            &InotifyNameCache::new(),
                            Some(Zone {
                                tables: zone,
                                cpu: &mut cpu,
                                user: &sched::HardwareUserWord
                            }),
                            None,
                            Some(venue),
                            |_| core::ptr::null_mut(),
                        ),
                        Action::Served
                    );
                    assert_eq!(cpu.saves, 1, "one child context per operation");
                    assert_eq!(venue.page.live(), 2);
                    assert_eq!(venue.page.claimed_count(), 0);
                    let slot = SlotId::from_index(i).unwrap();
                    assert_eq!(zone.slot(slot).queued(), 1);
                    let record = zone.runnable_head(slot).unwrap();
                    let identity = zone.record(record).identity();
                    assert_eq!(identity.mm, tasks[i].zone_mm.load(Ordering::Acquire));
                    assert_eq!(
                        identity.file_table,
                        tasks[i].file_table.load(Ordering::Acquire)
                    );
                    let entry = (0..THREAD_POOL_ENTRIES)
                        .find(|&index| venue.page.state(index).unwrap().1 == EntryState::Born)
                        .unwrap();
                    let entry = venue.children[entry].entry().unwrap();
                    assert_eq!(
                        venue.children[entry.index()].blocked(),
                        venue.leader.blocked()
                    );
                    assert_eq!(
                        frame.x[0],
                        u64::from(venue.page.identity(entry).unwrap().visible_tid)
                    );
                    // SAFETY: all dispatcher workers have separate records. This
                    // child remains queued and no scheduler runs in this fixture.
                    let ctx = unsafe { *zone.record(record).ctx_mut() };
                    assert_eq!(ctx.x[0], 0);
                    assert_eq!(ctx.pc, 0x4000);
                    assert_eq!(ctx.sp_el0, SAME_VA);
                }));
            }
            for _ in 0..n {
                ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            }
            for go in releases {
                go.send(()).unwrap();
            }
            for handle in handles {
                handle.join().unwrap();
            }
        });
        assert_eq!(counters.served[220].load(Ordering::Relaxed), n as u64);
        assert_eq!(counters.forwarded[220].load(Ordering::Relaxed), 0);
        assert_eq!(zone.counters.el1_parks.load(Ordering::Relaxed), 0);
        assert_eq!(zone.counters.host_parks.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn complete_creation_surface_census_counts_each_nonadmitted_forward_once() {
    for n in [1, 8, 32] {
        let counters = Counters::default();
        let tasks = [CurrentTask::new(), CurrentTask::new()];
        for (task, mm) in tasks.iter().zip([71, 83]) {
            task.zone_mm.store(mm, Ordering::Release);
        }
        for nr in CREATION_IDS {
            for i in 0..n {
                let mut frame = TrapFrame {
                    slot: (i % 2) as u64,
                    ..TrapFrame::default()
                };
                frame.x[..6].copy_from_slice(&[17, SAME_VA, 31, 41, 47, 53]);
                frame.x[8] = nr as u64;
                let original = frame.x;
                assert_eq!(
                    dispatch_syscall_with_regions(
                        &mut frame,
                        &counters,
                        &tasks,
                        &[],
                        &[],
                        &[],
                        &[],
                        &InotifyNameCache::new(),
                        None::<Zone<'_, SaveCpu, sched::HardwareUserWord>>,
                        |_| core::ptr::null_mut(),
                    ),
                    Action::Forward,
                    "numeric ID {nr}"
                );
                assert_eq!(frame.x, original);
            }
            assert_eq!(counters.forwarded[nr].load(Ordering::Relaxed), n as u64);
            assert_eq!(counters.served[nr].load(Ordering::Relaxed), 0);
        }
        assert_eq!(
            counters
                .forwarded
                .iter()
                .map(|c| c.load(Ordering::Relaxed))
                .sum::<u64>(),
            21 * n as u64
        );
    }
}
