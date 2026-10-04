#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
extern crate std;

use super::*;
use crate::personality::thread_setup::LifecycleThread;
use carrick_el1_abi::{EntryRef, LifecycleHatches, ThreadControlSlot, ThreadLifecyclePage};
use carrick_guest_arch::{CanonicalOrdinal, GuestIsa, NativeOrdinal, UserVa};
use std::boxed::Box;

const TID_A: u64 = 41;
const TID_B: u64 = 42;

/// One process with two live threads, each with its own control slot.
struct Venue {
    page: ThreadLifecyclePage,
    slots: [ThreadControlSlot; 2],
}

impl LifecycleVenue for Venue {
    fn thread<'a>(&'a self, task: &'a CurrentTask) -> Option<LifecycleThread<'a>> {
        let slot = match task.task_id.load(Ordering::Relaxed) {
            TID_A => &self.slots[0],
            TID_B => &self.slots[1],
            _ => return None,
        };
        Some(LifecycleThread {
            page: &self.page,
            slot,
        })
    }
    fn born_slot(&self, _: &ThreadLifecyclePage, _: EntryRef) -> Option<&ThreadControlSlot> {
        None
    }
}

struct World {
    venue: Box<Venue>,
    tasks: [CurrentTask; 2],
    counters: Box<Counters>,
    publications: AtomicU64,
}

impl World {
    fn new(hatches: LifecycleHatches) -> Self {
        let tasks: [CurrentTask; 2] = core::array::from_fn(|_| CurrentTask::new());
        tasks[0].set(
            carrick_el1_abi::El1TaskId::from_linux_tid(TID_A as i32),
            1,
            5,
        );
        tasks[1].set(
            carrick_el1_abi::El1TaskId::from_linux_tid(TID_B as i32),
            2,
            5,
        );
        Self {
            venue: Box::new(Venue {
                page: ThreadLifecyclePage::with_hatches(hatches),
                slots: core::array::from_fn(|_| ThreadControlSlot::new()),
            }),
            tasks,
            counters: Box::new(Counters::new()),
            publications: AtomicU64::new(0),
        }
    }

    /// x86_64 `set_robust_list` (native 273) as the CPL0 entry decodes it.
    fn set_robust_list(&self, task: usize, head: u64, len: u64) -> EntryOutcome {
        let call = CanonicalCall {
            isa: GuestIsa::X86_64,
            canonical: CanonicalOrdinal::new(SYS_SET_ROBUST_LIST as u64),
            native: NativeOrdinal::new(273),
            args: [head, len, 0, 0, 0, 0],
            stack: UserVa::new(0x7fff_0000),
        };
        serve_canonical(
            &call,
            &self.counters,
            &self.tasks[task],
            &*self.venue,
            Some(&self.publications),
        )
    }

    fn heads(&self) -> [(u64, u32); 2] {
        [
            self.venue.slots[0].robust_list(),
            self.venue.slots[1].robust_list(),
        ]
    }

    fn served(&self) -> u64 {
        self.counters.served[SYS_SET_ROBUST_LIST].load(Ordering::Relaxed)
    }

    fn forwarded(&self) -> u64 {
        self.counters.forwarded[SYS_SET_ROBUST_LIST].load(Ordering::Relaxed)
    }
}

#[test]
fn two_tasks_publish_only_their_own_robust_heads() {
    let w = World::new(LifecycleHatches::ON);
    let mut previous_b = (0, 0);
    for round in 0..4_u64 {
        let (a, b) = (0xa000 + round * 0x40, 0xb000 + round * 0x40);
        assert_eq!(
            w.set_robust_list(0, a, 24),
            EntryOutcome::Served(SyscallResult::new(0))
        );
        assert_eq!(w.heads(), [(a, 24), previous_b]);
        assert_eq!(
            w.set_robust_list(1, b, 24),
            EntryOutcome::Served(SyscallResult::new(0))
        );
        assert_eq!(w.heads(), [(a, 24), (b, 24)]);
        previous_b = (b, 24);
    }
    assert_eq!(w.served(), 8);
    assert_eq!(w.publications.load(Ordering::Relaxed), 8);
    assert_eq!(w.forwarded(), 0);
}

#[test]
fn invalid_length_is_einval_and_changes_neither_head() {
    let w = World::new(LifecycleHatches::ON);
    w.set_robust_list(0, 0xa000, 24);
    w.set_robust_list(1, 0xb000, 24);
    for len in [0, 23, 25, u64::MAX] {
        for task in 0..2 {
            assert_eq!(
                w.set_robust_list(task, 0xdead_0000, len),
                EntryOutcome::Served(SyscallResult::new(-22)),
                "len {len}"
            );
            assert_eq!(w.heads(), [(0xa000, 24), (0xb000, 24)]);
        }
    }
    assert_eq!(w.served(), 2 + 8);
    assert_eq!(w.publications.load(Ordering::Relaxed), 2);
    assert_eq!(w.forwarded(), 0);
}

#[test]
fn pending_host_work_completes_once_and_leaves_with_work() {
    let w = World::new(LifecycleHatches::ON);
    w.tasks[1].mark_pending_host_work();
    assert_eq!(
        w.set_robust_list(1, 0xb000, 24),
        EntryOutcome::ServedWithWork(SyscallResult::new(0))
    );
    assert_ne!(w.tasks[1].served_with_work.load(Ordering::Relaxed), 0);
    assert_eq!(w.tasks[0].served_with_work.load(Ordering::Relaxed), 0);
    assert_eq!(w.heads(), [(0, 0), (0xb000, 24)]);
    assert_eq!(w.served(), 1);
    assert_eq!(w.publications.load(Ordering::Relaxed), 1);
}

#[test]
fn closed_gate_or_hatch_forwards_without_effect() {
    let w = World::new(LifecycleHatches::ON);
    w.venue.page.close();
    assert_eq!(w.set_robust_list(0, 0xa000, 24), EntryOutcome::Forward);
    assert_eq!(w.set_robust_list(0, 0xa000, 23), EntryOutcome::Forward);
    let w2 = World::new(LifecycleHatches {
        threads: true,
        sigmask: false,
    });
    assert_eq!(w2.set_robust_list(1, 0xb000, 24), EntryOutcome::Forward);
    for w in [&w, &w2] {
        assert_eq!(w.heads(), [(0, 0), (0, 0)]);
        assert_eq!(w.served(), 0);
    }
    assert_eq!(w.forwarded(), 2);
    assert_eq!(w2.forwarded(), 1);
}

#[test]
fn unissued_task_or_unadmitted_call_forwards() {
    let w = World::new(LifecycleHatches::ON);
    let stranger = CurrentTask::new();
    let call = CanonicalCall {
        isa: GuestIsa::X86_64,
        canonical: CanonicalOrdinal::new(SYS_SET_ROBUST_LIST as u64),
        native: NativeOrdinal::new(273),
        args: [0xc000, 24, 0, 0, 0, 0],
        stack: UserVa::new(0),
    };
    assert_eq!(
        serve_canonical(
            &call,
            &w.counters,
            &stranger,
            &*w.venue,
            Some(&w.publications)
        ),
        EntryOutcome::Forward
    );
    let getpid = CanonicalCall {
        canonical: CanonicalOrdinal::new(172),
        native: NativeOrdinal::new(39),
        ..call
    };
    assert_eq!(
        serve_canonical(
            &getpid,
            &w.counters,
            &w.tasks[0],
            &*w.venue,
            Some(&w.publications)
        ),
        EntryOutcome::Forward
    );
    assert_eq!(w.heads(), [(0, 0), (0, 0)]);
    assert_eq!(w.counters.forwarded[172].load(Ordering::Relaxed), 1);
}

#[test]
fn cleared_execution_generation_cannot_publish_to_a_retained_slot() {
    let w = World::new(LifecycleHatches::ON);
    w.tasks[0].generation.store(0, Ordering::Release);
    assert_eq!(w.set_robust_list(0, 0xa000, 24), EntryOutcome::Forward);
    assert_eq!(w.heads(), [(0, 0), (0, 0)]);
    assert_eq!(w.publications.load(Ordering::Relaxed), 0);
    assert_eq!(w.served(), 0);
    assert_eq!(w.forwarded(), 1);
}
