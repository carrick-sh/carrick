#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
extern crate std;

use super::*;
use crate::personality::dispatch::{Zone, dispatch_syscall_with_lifecycle};
use crate::personality::sched::{FakeCpu, HardwareUserWord, SYS_FUTEX};
use carrick_el1_abi::{InotifyNameCache, LifecycleHatches, PendingSignals, SlotId, ZoneTables};
use carrick_sched_core::ExecutionSlot;
use std::boxed::Box;
use std::sync::Barrier;
use std::vec::Vec;

const MM: u64 = 7;
const SLOT_IDX: usize = 3;
const SLOT: SlotId = SlotId::new(SLOT_IDX as u8);
const PARENT_TID: u64 = 40;
const CHILD_TID: u32 = 50;
const CHILD_VISIBLE: u32 = 7;
const CHILD_SERIAL: u64 = 5050;
const CLONE_PC: u64 = 0x4000;
const CHILD_STACK: u64 = 0xdead_0000;
const CHILD_TLS: u64 = 0x7777_0000;

/// glibc `pthread_create`.
const GLIBC_FLAGS: u64 = 0x003d_0f00;
/// musl `pthread_create` (glibc's set plus `CLONE_DETACHED`).
const MUSL_FLAGS: u64 = 0x007d_0f00;
/// Go `newosproc`.
const GO_FLAGS: u64 = 0x0005_0f00;

fn zone() -> Box<ZoneTables> {
    let layout = std::alloc::Layout::new::<ZoneTables>();
    // SAFETY: all-zero is the valid empty zone.
    unsafe {
        let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables>();
        assert!(!ptr.is_null());
        Box::from_raw(ptr)
    }
}

/// A process's lifecycle state as the host would publish it: the page, the
/// leader's control slot (0) and one slot per pool entry (1..).
struct Venue {
    page: ThreadLifecyclePage,
    leader: u64,
    slots: [ThreadControlSlot; 9],
}

impl Venue {
    fn new(hatches: LifecycleHatches) -> Box<Self> {
        Box::new(Self {
            page: ThreadLifecyclePage::with_hatches(hatches),
            leader: PARENT_TID,
            slots: core::array::from_fn(|_| ThreadControlSlot::new()),
        })
    }

    fn stock(&self, index: usize, tid: u32, visible: u32) -> EntryRef {
        self.page
            .stock(
                index,
                carrick_el1_abi::EntryIdentity {
                    tid,
                    visible_tid: visible,
                    thread_serial: CHILD_SERIAL + index as u64,
                    uid_credit: 1,
                },
            )
            .unwrap()
    }

    fn leader_slot(&self) -> &ThreadControlSlot {
        &self.slots[0]
    }

    fn child_slot(&self, entry: usize) -> &ThreadControlSlot {
        &self.slots[entry + 1]
    }
}

impl LifecycleVenue for Venue {
    fn thread(&self, task: &CurrentTask) -> Option<LifecycleThread<'_>> {
        let tid = task.task_id.load(Ordering::Relaxed);
        let slot = if tid == self.leader {
            &self.slots[0]
        } else {
            self.slots[1..].iter().find(|slot| {
                slot.entry()
                    .and_then(|entry| self.page.identity(entry))
                    .is_some_and(|identity| u64::from(identity.tid) == tid)
            })?
        };
        Some(LifecycleThread {
            page: &self.page,
            slot,
        })
    }

    fn born_slot(&self, page: &ThreadLifecyclePage, entry: EntryRef) -> Option<&ThreadControlSlot> {
        core::ptr::eq(page, &self.page)
            .then(|| self.slots.get(entry.index() + 1))
            .flatten()
    }
}

/// One vCPU slot running the process's leader, loaded by its executor.
struct World {
    zone: Box<ZoneTables>,
    tasks: [CurrentTask; 4],
    cpu: FakeCpu,
    counters: Box<Counters>,
    venue: Box<Venue>,
}

impl World {
    fn new(hatches: LifecycleHatches) -> Self {
        let zone = zone();
        // The executor loads the leader and publishes the slot.
        zone.drive(SLOT, u64::from(SLOT.raw()) + 1);
        zone.publish_slot(SLOT, MM, None, 0);
        let here = ExecutionSlot::zone(SLOT);
        zone.occupancy.vacate_any(here);
        assert!(zone.occupancy.replace(here, 0, MM));
        let tasks: [CurrentTask; 4] = core::array::from_fn(|_| CurrentTask::new());
        let task = &tasks[SLOT_IDX];
        task.set(El1TaskId::from_linux_tid(PARENT_TID as i32), 1, 5);
        task.zone_mm.store(MM, Ordering::Relaxed);
        task.thread_serial
            .store(PARENT_TID + 1000, Ordering::Relaxed);
        let mut cpu = FakeCpu::default();
        cpu.regs.sp_el0 = 0x2222_0000;
        cpu.regs.tpidr_el0 = 0x1111_0000;
        // The host stamps the gettid word and TPIDRRO_EL0 (pid << 32 | tid).
        cpu.regs.contextidr_el1 = PARENT_TID;
        cpu.regs.tpidrro_el0 = (PARENT_TID << 32) | PARENT_TID;
        cpu.regs.v[3] = 0xfeed;
        Self {
            zone,
            tasks,
            cpu,
            counters: Box::new(Counters::default()),
            venue: Venue::new(hatches),
        }
    }

    fn task(&self) -> &CurrentTask {
        &self.tasks[SLOT_IDX]
    }

    fn page(&self) -> &ThreadLifecyclePage {
        &self.venue.page
    }

    /// Issue syscall `nr` from the running thread through the production
    /// dispatcher. `frame` carries the running thread across switches.
    fn call(&mut self, frame: &mut TrapFrame, nr: usize, args: &[u64]) -> Action {
        frame.x[..args.len()].copy_from_slice(args);
        frame.x[8] = nr as u64;
        frame.slot = SLOT_IDX as u64;
        frame.esr = 0x5600_0000;
        dispatch_syscall_with_lifecycle(
            frame,
            &self.counters,
            &self.tasks,
            &[],
            &[],
            &[],
            &[],
            &InotifyNameCache::new(),
            Some(Zone {
                tables: &self.zone,
                cpu: &mut self.cpu,
                user: &HardwareUserWord,
            }),
            None,
            Some(&*self.venue),
            |_| core::ptr::null_mut(),
        )
    }

    fn syscall(&mut self, nr: usize, args: &[u64]) -> (Action, TrapFrame) {
        let mut frame = TrapFrame {
            elr: CLONE_PC,
            ..TrapFrame::default()
        };
        let action = self.call(&mut frame, nr, args);
        (action, frame)
    }

    fn served(&self, nr: usize) -> u64 {
        self.counters.served[nr].load(Ordering::Relaxed)
    }

    fn forwarded(&self, nr: usize) -> u64 {
        self.counters.forwarded[nr].load(Ordering::Relaxed)
    }
}

fn addr<T>(value: &T) -> u64 {
    value as *const T as u64
}

#[test]
fn gettid_uses_each_live_process_immutable_projection() {
    let mut first = World::new(LifecycleHatches::ON);
    let mut second = World::new(LifecycleHatches::ON);
    assert!(first.venue.leader_slot().publish_visible_tid(41));
    assert!(second.venue.leader_slot().publish_visible_tid(73));
    for (world, expected) in [(&mut first, 41), (&mut second, 73)] {
        let (action, frame) = world.syscall(178, &[]);
        assert_eq!(action, Action::Served);
        assert_eq!(frame.x[0], expected);
        assert_eq!(world.forwarded(178), 0);
    }
}

#[test]
fn exit_decline_census_names_the_authority_without_changing_it() {
    let mut world = World::new(LifecycleHatches::ON);
    let (action, _) = world.syscall(SYS_EXIT, &[0]);
    assert_eq!(action, Action::Forward);
    assert_eq!(
        world.counters.lifecycle_declines[carrick_el1_abi::LifecycleDecline::ExitNoEntry as usize]
            .load(Ordering::Relaxed),
        1
    );
}

/// Host-memory user copies that fail on chosen addresses (a fault EL1 cannot
/// serve through).
#[derive(Default)]
struct FaultingUser {
    deny_in: Vec<u64>,
    deny_out: Vec<u64>,
}

impl UserCopy for FaultingUser {
    fn copy_out(&mut self, dst_va: u64, src: &[u8]) -> bool {
        if self.deny_out.contains(&dst_va) {
            return false;
        }
        // SAFETY: tests pass live host buffers.
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst_va as *mut u8, src.len()) };
        true
    }

    fn copy_in(&mut self, dst: &mut [u8], src_va: u64) -> bool {
        if self.deny_in.contains(&src_va) {
            return false;
        }
        // SAFETY: tests pass live host buffers.
        unsafe { core::ptr::copy_nonoverlapping(src_va as *const u8, dst.as_mut_ptr(), dst.len()) };
        true
    }
}

fn serve_directly(w: &mut World, frame: &mut TrapFrame, user: &mut FaultingUser) -> Option<Action> {
    let task = &w.tasks[SLOT_IDX];
    let sched = Sched {
        zone: &w.zone,
        slot: SLOT,
        task,
        cpu: &mut w.cpu,
        user: &HardwareUserWord,
        counters: &w.counters,
    };
    serve(frame, &w.counters, task, Some(sched), &*w.venue, user)
}

fn clone_args(flags: u64, parent_tid: u64, child_tid: u64) -> [u64; 5] {
    [flags, CHILD_STACK, parent_tid, CHILD_TLS, child_tid]
}

// ---- clone ----

#[test]
fn clone_serves_libc_and_go_thread_flag_sets_and_queues_the_child() {
    for flags in [GLIBC_FLAGS, MUSL_FLAGS, GO_FLAGS] {
        let mut w = World::new(LifecycleHatches::ON);
        let entry = w.venue.stock(2, CHILD_TID, CHILD_VISIBLE);
        w.venue.leader_slot().init_blocked(BlockedMask(0x1234));
        let parent_word = Box::new(0xaaaa_u32);
        let child_word = Box::new(0xbbbb_u32);
        let (action, frame) = w.syscall(
            SYS_CLONE,
            &clone_args(flags, addr(&*parent_word), addr(&*child_word)),
        );
        assert_eq!(action, Action::Served, "flags {flags:#x}");
        assert_eq!(frame.x[0], u64::from(CHILD_VISIBLE));
        assert_eq!(w.served(SYS_CLONE), 1);
        assert_eq!(w.forwarded(SYS_CLONE), 0);
        let libc = flags & CLONE_PARENT_SETTID != 0;
        assert_eq!(*parent_word, if libc { CHILD_VISIBLE } else { 0xaaaa });
        // No CLONE_CHILD_SETTID in any of these sets: the child word is
        // only the CLEARTID target.
        assert_eq!(*child_word, 0xbbbb);

        // Born, with the mask captured at the claim; one more live thread.
        let page = w.page();
        assert_eq!(
            page.state(2).unwrap(),
            (entry.generation(), EntryState::Born)
        );
        let clear = if libc { addr(&*child_word) } else { 0 };
        assert_eq!(
            page.born_record(entry),
            Some(BornRecord {
                caller_task: PARENT_TID,
                caller_serial: PARENT_TID + 1000,
                clone_flags: flags,
                clear_child_tid: clear,
                blocked: BlockedMask(0x1234),
            })
        );
        assert_eq!(page.live(), 2);
        let child_slot = w.venue.child_slot(2);
        assert_eq!(child_slot.entry(), Some(entry));
        assert_eq!(child_slot.blocked(), BlockedMask(0x1234));
        assert_eq!(child_slot.clear_child_tid(), clear);
        assert!(child_slot.read_altstack().is_disabled());
        assert_eq!(child_slot.robust_list(), (0, 0));

        // Queued on this vCPU with the parent's frame: clone returns 0 on
        // its own stack and TLS, and gettid names the child.
        assert_eq!(w.zone.slot(SLOT).queued(), 1);
        let record = w.zone.runnable_head(SLOT).expect("child queued");
        let rec = w.zone.record(record);
        assert_eq!(rec.identity().tid, u64::from(CHILD_TID));
        assert_eq!(rec.identity().serial, CHILD_SERIAL + 2);
        assert_eq!(rec.identity().mm, MM);
        assert_eq!(rec.identity().file_table, 5);
        assert_eq!(rec.home(), None);
        // SAFETY: queued, owned by this vCPU; the test only reads.
        let ctx = unsafe { *rec.ctx_mut() };
        assert_eq!(ctx.x[0], 0);
        assert_eq!(&ctx.x[1..5], &frame.x[1..5]);
        assert_eq!(ctx.pc, CLONE_PC);
        assert_eq!(ctx.sp_el0, CHILD_STACK);
        let settls = flags & CLONE_SETTLS != 0;
        assert_eq!(ctx.tpidr_el0, if settls { CHILD_TLS } else { 0x1111_0000 });
        assert_eq!(ctx.contextidr_el1, PARENT_TID);
        assert_eq!(w.venue.child_slot(2).visible_tid(), Some(CHILD_VISIBLE));
        assert_eq!(
            ctx.tpidrro_el0,
            (PARENT_TID << 32) | u64::from(CHILD_VISIBLE)
        );
        assert_eq!(ctx.v[3], 0xfeed);
    }
}

#[test]
fn clone_forwards_every_other_flag_set_without_effects() {
    let fork = 0x11; // SIGCHLD
    let cases = [
        fork,
        CLONE_VM | 0x4000 | fork,                  // vfork
        GLIBC_FLAGS | 0x8000,                      // CLONE_PARENT
        GLIBC_FLAGS | fork,                        // an exit signal
        GLIBC_FLAGS & !CLONE_SYSVSEM,              // not a libc set
        GLIBC_FLAGS | 0x1000,                      // CLONE_PIDFD
        GLIBC_FLAGS | 0x0200_0000,                 // CLONE_UNTRACED
        GLIBC_FLAGS | CLONE_CHILD_SETTID | 0x2000, // CLONE_PTRACE
    ];
    for flags in cases {
        let mut w = World::new(LifecycleHatches::ON);
        let entry = w.venue.stock(0, CHILD_TID, CHILD_VISIBLE);
        let word = Box::new(0xaaaa_u32);
        let args = clone_args(flags, addr(&*word), addr(&*word));
        let (action, frame) = w.syscall(SYS_CLONE, &args);
        assert_eq!(action, Action::Forward, "flags {flags:#x}");
        assert_eq!(&frame.x[..5], &args, "forwarding cannot consume arguments");
        assert_eq!(*word, 0xaaaa);
        assert_eq!(
            w.page().state(0).unwrap(),
            (entry.generation(), EntryState::Reserved)
        );
        assert_eq!(w.page().live(), 1);
        assert_eq!(w.zone.slot(SLOT).queued(), 0);
        assert_eq!(w.forwarded(SYS_CLONE), 1);
    }
    // A child on the parent's stack, and clone3, stay on the host.
    let mut w = World::new(LifecycleHatches::ON);
    w.venue.stock(0, CHILD_TID, CHILD_VISIBLE);
    let (action, _) = w.syscall(SYS_CLONE, &[GLIBC_FLAGS, 0, 0, 0, 0]);
    assert_eq!(action, Action::Forward);
    let (action, _) = w.syscall(435, &[0x1000, 88]);
    assert_eq!(action, Action::Forward);
    assert_eq!(w.page().state(0).unwrap().1, EntryState::Reserved);
}

#[test]
fn clone_forwards_behind_a_closed_gate_or_the_threads_hatch() {
    let run = |w: &mut World| {
        let entry = w.venue.stock(0, CHILD_TID, CHILD_VISIBLE);
        let word = Box::new(0xaaaa_u32);
        let (action, _) = w.syscall(
            SYS_CLONE,
            &clone_args(GLIBC_FLAGS, addr(&*word), addr(&*word)),
        );
        assert_eq!(action, Action::Forward);
        assert_eq!(*word, 0xaaaa);
        assert_eq!(
            w.page().state(0).unwrap(),
            (entry.generation(), EntryState::Reserved)
        );
        assert_eq!(w.page().claimed_count(), 0);
        assert_eq!(w.zone.slot(SLOT).queued(), 0);
    };
    let mut w = World::new(LifecycleHatches::ON);
    w.page().close_for_fork().unwrap();
    run(&mut w);
    let mut w = World::new(LifecycleHatches::ON);
    w.page().close();
    run(&mut w);
    // CARRICK_EL1_THREADS=0.
    let mut w = World::new(LifecycleHatches {
        threads: false,
        sigmask: true,
    });
    run(&mut w);
}

#[test]
fn clone_with_an_empty_pool_forwards() {
    let mut w = World::new(LifecycleHatches::ON);
    let (action, _) = w.syscall(SYS_CLONE, &clone_args(GO_FLAGS, 0, 0));
    assert_eq!(action, Action::Forward);
    assert_eq!(w.page().live(), 1);
}

#[test]
fn clone_on_exhausted_zone_records_returns_the_entry_and_forwards() {
    let mut w = World::new(LifecycleHatches::ON);
    let entry = w.venue.stock(0, CHILD_TID, CHILD_VISIBLE);
    let mut taken = Vec::new();
    while let Ok(record) = w.zone.alloc_record(ThreadIdentity::default()) {
        taken.push(record);
    }
    let word = Box::new(0xaaaa_u32);
    let args = clone_args(GLIBC_FLAGS, addr(&*word), addr(&*word));
    let (action, _) = w.syscall(SYS_CLONE, &args);
    assert_eq!(action, Action::Forward);
    assert_eq!(*word, 0xaaaa, "no tid output before the child exists");
    assert_eq!(
        w.page().state(0).unwrap(),
        (entry.generation(), EntryState::Reserved)
    );
    assert_eq!(w.page().live(), 1);
    // The same identity serves the next clone once a record is free.
    w.zone.free_record(taken.pop().unwrap());
    let (action, frame) = w.syscall(SYS_CLONE, &args);
    assert_eq!(action, Action::Served);
    assert_eq!(frame.x[0], u64::from(CHILD_VISIBLE));
    assert_eq!(
        w.page().state(0).unwrap(),
        (entry.generation(), EntryState::Born)
    );
}

#[test]
fn clone_tid_copy_faults_restore_the_preimages_and_forward() {
    let flags = GLIBC_FLAGS | CLONE_CHILD_SETTID;
    // An unreadable output word: nothing is claimed or written.
    let mut w = World::new(LifecycleHatches::ON);
    w.venue.stock(0, CHILD_TID, CHILD_VISIBLE);
    let parent_word = Box::new(0xaaaa_u32);
    let child_word = Box::new(0xbbbb_u32);
    let args = clone_args(flags, addr(&*parent_word), addr(&*child_word));
    let mut frame = TrapFrame::default();
    frame.x[..5].copy_from_slice(&args);
    frame.x[8] = SYS_CLONE as u64;
    let mut user = FaultingUser {
        deny_in: std::vec![addr(&*child_word)],
        ..FaultingUser::default()
    };
    assert_eq!(serve_directly(&mut w, &mut frame, &mut user), None);
    assert_eq!(w.page().state(0).unwrap().1, EntryState::Reserved);

    // The child copyout faults after the parent's landed: the parent word
    // gets its preimage back, the entry returns to the pool, the record is
    // freed, and the host lane answers the forwarded clone (EFAULT).
    let mut w = World::new(LifecycleHatches::ON);
    let entry = w.venue.stock(0, CHILD_TID, CHILD_VISIBLE);
    let mut frame = TrapFrame::default();
    frame.x[..5].copy_from_slice(&args);
    frame.x[8] = SYS_CLONE as u64;
    let mut user = FaultingUser {
        deny_out: std::vec![addr(&*child_word)],
        ..FaultingUser::default()
    };
    assert_eq!(serve_directly(&mut w, &mut frame, &mut user), None);
    assert_eq!(*parent_word, 0xaaaa);
    assert_eq!(*child_word, 0xbbbb);
    assert_eq!(&frame.x[..5], &args);
    assert_eq!(
        w.page().state(0).unwrap(),
        (entry.generation(), EntryState::Reserved)
    );
    assert_eq!(w.page().live(), 1);
    assert_eq!(w.zone.slot(SLOT).queued(), 0);
    assert_eq!(w.venue.child_slot(0).entry(), None);
    // Every zone record is free again.
    let mut free = 0;
    while w.zone.alloc_record(ThreadIdentity::default()).is_ok() {
        free += 1;
    }
    assert_eq!(free, carrick_sched_core::ZONE_RECORDS - 1);
}

// ---- rt_sigprocmask ----

const SIGUSR1_BIT: u64 = 1 << 9; // signal 10

#[test]
fn lifecycle_setup_completes_once_before_pending_host_work() {
    for nr in [SYS_RT_SIGPROCMASK, SYS_SIGALTSTACK, SYS_SET_ROBUST_LIST] {
        let mut w = World::new(LifecycleHatches::ON);
        w.task().mark_pending_host_work();
        let args: &[u64] = match nr {
            SYS_RT_SIGPROCMASK => &[0, 0, 0, 8],
            SYS_SIGALTSTACK => &[0, 0],
            _ => &[0x1234, 24],
        };
        let (action, _) = w.syscall(nr, args);
        assert_eq!(action, Action::ServedWithWork, "syscall {nr}");
        assert_eq!(w.served(nr), 1);
        assert_eq!(w.forwarded(nr), 0);
    }
}

#[test]
fn sigprocmask_unblocking_a_pending_signal_serves_with_work() {
    let mut w = World::new(LifecycleHatches::ON);
    let slot = w.venue.leader_slot();
    slot.init_blocked(BlockedMask(SIGUSR1_BIT | 1));
    // A sender posted SIGUSR1 and saw it blocked: it left it pending.
    let seen = w
        .venue
        .leader_slot()
        .pending()
        .post_then_read_blocked(PendingSignals(SIGUSR1_BIT), slot);
    assert_ne!(seen.0 & SIGUSR1_BIT, 0);
    let set = Box::new(SIGUSR1_BIT);
    let old = Box::new(0_u64);
    let (action, frame) = w.syscall(
        SYS_RT_SIGPROCMASK,
        &[SIG_UNBLOCK, addr(&*set), addr(&*old), 8],
    );
    assert_eq!(action, Action::ServedWithWork);
    assert_eq!(frame.x[0], 0);
    assert_eq!(*old, SIGUSR1_BIT | 1);
    assert_eq!(w.venue.leader_slot().blocked(), BlockedMask(1));
    assert_eq!(w.task().served_with_work.load(Ordering::Relaxed), 1);
    assert_eq!(w.served(SYS_RT_SIGPROCMASK), 1);
}

#[test]
fn sigprocmask_unblocking_a_process_pending_signal_serves_with_work() {
    let mut w = World::new(LifecycleHatches::ON);
    let slot = w.venue.leader_slot();
    slot.init_blocked(BlockedMask(SIGUSR1_BIT | 1));
    // A sender posted SIGUSR1 and saw it blocked: it left it pending.
    let seen = w
        .venue
        .page
        .pending()
        .post_then_read_blocked(PendingSignals(SIGUSR1_BIT), slot);
    assert_ne!(seen.0 & SIGUSR1_BIT, 0);
    let set = Box::new(SIGUSR1_BIT);
    let old = Box::new(0_u64);
    let (action, frame) = w.syscall(
        SYS_RT_SIGPROCMASK,
        &[SIG_UNBLOCK, addr(&*set), addr(&*old), 8],
    );
    assert_eq!(action, Action::ServedWithWork);
    assert_eq!(frame.x[0], 0);
    assert_eq!(*old, SIGUSR1_BIT | 1);
    assert_eq!(w.venue.leader_slot().blocked(), BlockedMask(1));
    assert_eq!(w.task().served_with_work.load(Ordering::Relaxed), 1);
    assert_eq!(w.served(SYS_RT_SIGPROCMASK), 1);
}

#[test]
fn sigprocmask_serves_block_setmask_and_query() {
    let mut w = World::new(LifecycleHatches::ON);
    let set = Box::new(SIGUSR1_BIT);
    let old = Box::new(u64::MAX);
    let (action, _) = w.syscall(
        SYS_RT_SIGPROCMASK,
        &[SIG_BLOCK, addr(&*set), addr(&*old), 8],
    );
    assert_eq!(action, Action::Served);
    assert_eq!(*old, 0);
    assert_eq!(w.venue.leader_slot().blocked(), BlockedMask(SIGUSR1_BIT));
    // SIGKILL and SIGSTOP never enter a mask.
    let all = Box::new(u64::MAX);
    let (action, _) = w.syscall(SYS_RT_SIGPROCMASK, &[SIG_SETMASK, addr(&*all), 0, 8]);
    assert_eq!(action, Action::Served);
    assert_eq!(w.venue.leader_slot().blocked(), BlockedMask(!UNBLOCKABLE));
    // A query ignores `how`, as the host lane does.
    let (action, frame) = w.syscall(SYS_RT_SIGPROCMASK, &[99, 0, addr(&*old), 8]);
    assert_eq!(action, Action::Served);
    assert_eq!(frame.x[0], 0);
    assert_eq!(*old, !UNBLOCKABLE);
    // Blocking a pending signal re-targets it: the host must look.
    let mut w = World::new(LifecycleHatches::ON);
    let _ = w
        .venue
        .leader_slot()
        .pending()
        .post_then_read_blocked(PendingSignals(SIGUSR1_BIT), w.venue.leader_slot());
    let (action, _) = w.syscall(SYS_RT_SIGPROCMASK, &[SIG_BLOCK, addr(&*set), 0, 8]);
    assert_eq!(action, Action::ServedWithWork);
}

#[test]
fn sigprocmask_forwards_errors_aliases_and_closed_services() {
    let set = Box::new(SIGUSR1_BIT);
    let old = Box::new(0x55_u64);
    let cases: [(LifecycleHatches, [u64; 4], bool); 5] = [
        (
            LifecycleHatches::ON,
            [SIG_BLOCK, addr(&*set), addr(&*old), 16],
            false,
        ),
        (
            LifecycleHatches::ON,
            [SIG_BLOCK, addr(&*set), addr(&*set), 8],
            false,
        ),
        (
            LifecycleHatches::ON,
            [7, addr(&*set), addr(&*old), 8],
            false,
        ),
        (
            LifecycleHatches {
                threads: true,
                sigmask: false,
            },
            [SIG_BLOCK, addr(&*set), addr(&*old), 8],
            false,
        ),
        (
            LifecycleHatches::ON,
            [SIG_BLOCK, addr(&*set), addr(&*old), 8],
            true,
        ),
    ];
    for (hatches, args, close) in cases {
        let mut w = World::new(hatches);
        if close {
            w.page().close();
        }
        let (action, frame) = w.syscall(SYS_RT_SIGPROCMASK, &args);
        assert_eq!(action, Action::Forward, "{args:x?}");
        assert_eq!(&frame.x[..4], &args);
        assert_eq!(w.venue.leader_slot().blocked(), BlockedMask(0));
        assert_eq!(*old, 0x55);
        assert_eq!(*set, SIGUSR1_BIT);
    }
    // A set EL1 cannot read: the host answers (EFAULT or the fault-in).
    let mut w = World::new(LifecycleHatches::ON);
    let mut frame = TrapFrame::default();
    frame.x[..4].copy_from_slice(&[SIG_BLOCK, addr(&*set), addr(&*old), 8]);
    frame.x[8] = SYS_RT_SIGPROCMASK as u64;
    let mut user = FaultingUser {
        deny_in: std::vec![addr(&*set)],
        ..FaultingUser::default()
    };
    assert_eq!(serve_directly(&mut w, &mut frame, &mut user), None);
    assert_eq!(*old, 0x55);
}

/// The Dekker pair through the served call: a sender posting a signal and a
/// thread unblocking it never both miss each other.
#[test]
fn sigprocmask_dekker_storm_loses_no_signal() {
    run_sigprocmask_dekker_storm(false);
}

#[test]
fn sigprocmask_process_dekker_storm_loses_no_signal() {
    run_sigprocmask_dekker_storm(true);
}

fn run_sigprocmask_dekker_storm(process: bool) {
    const ROUNDS: usize = 20_000;
    let venue = Venue::new(LifecycleHatches::ON);
    let summary = if process {
        venue.page.pending()
    } else {
        venue.leader_slot().pending()
    };
    let (start, end) = (Barrier::new(2), Barrier::new(2));
    let (saw_blocked, works) = std::thread::scope(|scope| {
        let sender = scope.spawn(|| {
            let mut saw_blocked = Vec::with_capacity(ROUNDS);
            for _ in 0..ROUNDS {
                venue.leader_slot().init_blocked(BlockedMask(SIGUSR1_BIT));
                start.wait();
                let blocked = if process {
                    summary.replace_from_locked_queue(PendingSignals(SIGUSR1_BIT));
                    venue.leader_slot().blocked_after_pending_publication()
                } else {
                    summary.post_then_read_blocked(PendingSignals(SIGUSR1_BIT), venue.leader_slot())
                };
                saw_blocked.push(blocked.0 & SIGUSR1_BIT != 0);
                end.wait();
                end.wait();
                summary.clear(PendingSignals(SIGUSR1_BIT));
            }
            saw_blocked
        });
        let set = SIGUSR1_BIT;
        let mut frame = TrapFrame::default();
        let mut works = Vec::with_capacity(ROUNDS);
        for _ in 0..ROUNDS {
            start.wait();
            frame.x[..4].copy_from_slice(&[SIG_UNBLOCK, addr(&set), 0, 8]);
            let thread = LifecycleThread {
                page: &venue.page,
                slot: venue.leader_slot(),
            };
            works.push(serve_sigprocmask(&frame, thread, &mut FaultingUser::default()).unwrap());
            end.wait();
            end.wait();
        }
        (sender.join().unwrap(), works)
    });
    let lost = saw_blocked
        .iter()
        .zip(&works)
        .filter(|(blocked, work)| **blocked && !**work)
        .count();
    assert_eq!(lost, 0, "a signal left pending with nobody to deliver it");
}

// ---- sigaltstack / set_robust_list ----

/// arm64 `stack_t`: `ss_sp`, `ss_flags` + 4 bytes of pad, `ss_size`.
fn stack_t(sp: u64, flags: u32, size: u64) -> [u8; 24] {
    let mut bytes = [0u8; 24];
    let (sp_bytes, rest) = bytes.split_at_mut(8);
    let (flag_bytes, size_bytes) = rest.split_at_mut(8);
    sp_bytes.copy_from_slice(&sp.to_le_bytes());
    flag_bytes[..4].copy_from_slice(&flags.to_le_bytes());
    size_bytes.copy_from_slice(&size.to_le_bytes());
    bytes
}

#[test]
fn sigaltstack_serves_off_the_alternate_stack() {
    let mut w = World::new(LifecycleHatches::ON);
    let old = Box::new([0xffu8; 24]);
    // Query: none installed.
    let (action, _) = w.syscall(SYS_SIGALTSTACK, &[0, addr(&*old)]);
    assert_eq!(action, Action::Served);
    assert_eq!(*old, stack_t(0, SS_DISABLE, 0));
    // Install.
    let new = Box::new(stack_t(0x10_0000, 0, 0x4000));
    let (action, _) = w.syscall(SYS_SIGALTSTACK, &[addr(&*new), 0]);
    assert_eq!(action, Action::Served);
    assert_eq!(
        w.venue.leader_slot().read_altstack(),
        AltStack {
            sp: 0x10_0000,
            size: 0x4000,
            flags: 0
        }
    );
    // Query from the thread's own stack.
    let (action, _) = w.syscall(SYS_SIGALTSTACK, &[0, addr(&*old)]);
    assert_eq!(action, Action::Served);
    assert_eq!(*old, stack_t(0x10_0000, 0, 0x4000));
    // Running on it (a handler): the host decides SS_ONSTACK and EPERM.
    w.cpu.regs.sp_el0 = 0x10_2000;
    let (action, _) = w.syscall(SYS_SIGALTSTACK, &[0, addr(&*old)]);
    assert_eq!(action, Action::Forward);
    w.cpu.regs.sp_el0 = 0x2222_0000;
    // Errors and aliases stay on the host.
    for bad in [stack_t(0x20_0000, 0, 1024), stack_t(0x20_0000, 1, 0x4000)] {
        let bad = Box::new(bad);
        let (action, _) = w.syscall(SYS_SIGALTSTACK, &[addr(&*bad), 0]);
        assert_eq!(action, Action::Forward);
    }
    let (action, _) = w.syscall(SYS_SIGALTSTACK, &[addr(&*new), addr(&*new)]);
    assert_eq!(action, Action::Forward);
    // Disable, returning the old one.
    let off = Box::new(stack_t(0, SS_DISABLE, 0));
    let (action, _) = w.syscall(SYS_SIGALTSTACK, &[addr(&*off), addr(&*old)]);
    assert_eq!(action, Action::Served);
    assert_eq!(*old, stack_t(0x10_0000, 0, 0x4000));
    assert!(w.venue.leader_slot().read_altstack().is_disabled());
    assert_eq!(w.served(SYS_SIGALTSTACK), 4);
}

#[test]
fn set_robust_list_stores_the_head_or_forwards() {
    let mut w = World::new(LifecycleHatches::ON);
    let (action, frame) = w.syscall(SYS_SET_ROBUST_LIST, &[0x9000, 24]);
    assert_eq!(action, Action::Served);
    assert_eq!(frame.x[0], 0);
    assert_eq!(w.venue.leader_slot().robust_list(), (0x9000, 24));
    let (action, _) = w.syscall(SYS_SET_ROBUST_LIST, &[0xa000, 23]);
    assert_eq!(action, Action::Forward);
    assert_eq!(w.venue.leader_slot().robust_list(), (0x9000, 24));
    let mut w = World::new(LifecycleHatches {
        threads: true,
        sigmask: false,
    });
    let (action, _) = w.syscall(SYS_SET_ROBUST_LIST, &[0x9000, 24]);
    assert_eq!(action, Action::Forward);
}

// ---- exit ----

/// The leader clones a glibc thread whose tid word is `word`, then joins
/// it (futex wait on the word): the child is switched in. Returns the
/// running (child's) frame.
fn clone_then_join(w: &mut World, word: &u32) -> TrapFrame {
    w.venue.stock(0, CHILD_TID, CHILD_VISIBLE);
    let (action, _) = w.syscall(SYS_CLONE, &clone_args(GLIBC_FLAGS, addr(word), addr(word)));
    assert_eq!(action, Action::Served);
    assert_eq!(*word, CHILD_VISIBLE);
    let mut frame = TrapFrame {
        elr: 0x5000,
        ..TrapFrame::default()
    };
    let action = w.call(
        &mut frame,
        SYS_FUTEX,
        &[addr(word), 128, u64::from(CHILD_VISIBLE), 0],
    );
    assert_eq!(action, Action::Served);
    assert_eq!(
        w.task().task_id.load(Ordering::Relaxed),
        u64::from(CHILD_TID)
    );
    assert_eq!(frame.elr, CLONE_PC);
    assert_eq!(frame.x[0], 0, "clone returns 0 in the child");
    assert_eq!(w.cpu.regs.sp_el0, CHILD_STACK);
    assert_eq!(w.cpu.regs.tpidr_el0, CHILD_TLS);
    frame
}

#[test]
fn exit_of_a_born_thread_clears_cleartid_wakes_the_joiner_and_runs_it() {
    let mut w = World::new(LifecycleHatches::ON);
    let word = Box::new(0_u32);
    let mut frame = clone_then_join(&mut w, &word);
    let action = w.call(&mut frame, SYS_EXIT, &[0]);
    assert_eq!(action, Action::Served);
    assert_eq!(*word, 0, "CLEARTID cleared");
    let page = w.page();
    assert_eq!(page.state(0).unwrap().1, EntryState::ExitedInZone);
    assert_eq!(page.live(), 1);
    assert_eq!(w.served(SYS_EXIT), 1);
    assert_eq!(w.forwarded(SYS_EXIT), 0);
    // The joiner resumes after its futex wait, which returned 0.
    assert_eq!(w.task().task_id.load(Ordering::Relaxed), PARENT_TID);
    assert_eq!(frame.elr, 0x5000);
    assert_eq!(frame.x[0], 0);
    let s = w.zone.slot(SLOT);
    assert_eq!(s.current(), s.host_record());
    assert_eq!(s.queued(), 0);
}

#[test]
fn exit_keeps_a_migrated_host_job_while_the_other_process_exits_in_zone() {
    let mut hosted = World::new(LifecycleHatches::ON);
    let mut peer = World::new(LifecycleHatches::ON);
    let hosted_word = Box::new(0_u32);
    let peer_word = Box::new(0_u32);
    let mut hosted_frame = clone_then_join(&mut hosted, &hosted_word);
    let mut peer_frame = clone_then_join(&mut peer, &peer_word);
    let entry = hosted.venue.child_slot(0).entry().unwrap();
    hosted.page().publish(entry).unwrap();
    let record = hosted.zone.slot(SLOT).current().unwrap();
    assert_ne!(Some(record), hosted.zone.slot(SLOT).host_record());
    let mut identity = hosted.zone.record(record).identity();
    identity.generation = 2;
    assert_eq!(
        hosted.zone.release_current(
            SLOT,
            record,
            &carrick_sched_core::BoundedSpin(carrick_el1_abi::EL1_GUEST_LOCK_SPINS),
        ),
        carrick_sched_core::CurrentRelease::Released,
    );
    let record = hosted.zone.alloc_record(identity).unwrap();
    hosted.zone.requeue_preempted(SLOT, record);
    assert_eq!(hosted.zone.switch_in(SLOT), Some(record));
    assert_eq!(hosted.page().live(), 2);
    assert_eq!(peer.page().live(), 2);

    assert_eq!(
        hosted.call(&mut hosted_frame, SYS_EXIT, &[0]),
        Action::Forward
    );
    assert_eq!(
        hosted.page().state(entry.index()).unwrap().1,
        EntryState::Published
    );
    assert_eq!(hosted.page().live(), 2);
    assert_eq!(
        *hosted_word, CHILD_VISIBLE,
        "host retirement still owns CLEARTID"
    );
    assert_eq!(hosted.zone.slot(SLOT).current(), Some(record));
    assert_eq!(
        hosted.counters.lifecycle_declines
            [carrick_el1_abi::LifecycleDecline::ExitHostAdopted as usize]
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(peer.call(&mut peer_frame, SYS_EXIT, &[0]), Action::Served);
    assert_eq!(peer.page().live(), 1);
    assert_eq!(*peer_word, 0);
}

#[test]
fn exit_forwards_unless_a_switched_in_non_last_thread_may_leave() {
    // (label, setup applied after the child is switched in)
    type Setup = fn(&World);
    let cases: [(&str, Setup); 5] = [
        ("last thread (n == 1)", |w| {
            w.page().try_exit().unwrap();
        }),
        ("robust list registered", |w| {
            w.venue.child_slot(0).set_robust_list(0x9000, 24);
        }),
        ("pending signal", |w| {
            let _ = w
                .page()
                .pending()
                .post_then_read_blocked(PendingSignals(SIGUSR1_BIT), w.venue.child_slot(0));
        }),
        ("gate closing for a fork", |w| {
            w.page().close_for_fork().unwrap();
        }),
        ("host work pending", |w| {
            w.task().mark_pending_host_work();
        }),
    ];
    for (label, setup) in cases {
        let mut w = World::new(LifecycleHatches::ON);
        let word = Box::new(0_u32);
        let mut frame = clone_then_join(&mut w, &word);
        setup(&w);
        let live = w.page().live();
        let action = w.call(&mut frame, SYS_EXIT, &[3]);
        assert_eq!(action, Action::Forward, "{label}");
        assert_eq!(
            w.counters
                .lifecycle_declines
                .iter()
                .map(|count| count.load(Ordering::Relaxed))
                .sum::<u64>(),
            1,
            "{label}: exactly one decline reason"
        );
        assert_eq!(frame.x[0], 3, "{label}: the host exits with the status");
        assert_eq!(*word, CHILD_VISIBLE, "{label}: CLEARTID untouched");
        assert_eq!(w.page().state(0).unwrap().1, EntryState::Born, "{label}");
        assert_eq!(w.page().live(), live, "{label}");
        assert_eq!(
            w.task().task_id.load(Ordering::Relaxed),
            u64::from(CHILD_TID)
        );
        assert!(w.zone.slot(SLOT).current().is_some(), "{label}");
    }

    // The leader, and a thread its executor loaded, exit on the host.
    let mut w = World::new(LifecycleHatches::ON);
    let (action, _) = w.syscall(SYS_EXIT, &[0]);
    assert_eq!(action, Action::Forward);
    let entry = w.venue.stock(0, CHILD_TID, CHILD_VISIBLE);
    let word = Box::new(9_u32);
    w.venue
        .child_slot(0)
        .reset_for_birth(BlockedMask(0), addr(&*word), entry);
    w.page().thread_born().unwrap();
    w.task()
        .set(El1TaskId::from_linux_tid(CHILD_TID as i32), 1, 5);
    let (action, _) = w.syscall(SYS_EXIT, &[0]);
    assert_eq!(action, Action::Forward);
    assert_eq!(*word, 9);
    assert_eq!(w.page().live(), 2);
}
