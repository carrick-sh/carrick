#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
extern crate std;

use carrick_core::lifecycle::Lifecycle;
use carrick_el1::personality::common_entry::{
    EntryOutcome, SYS_SET_ROBUST_LIST, execution_binding, serve_canonical,
    serve_canonical_with_anonymous,
};
use carrick_el1::personality::thread_setup::{LifecycleThread, LifecycleVenue};
use carrick_el1_abi::{Counters, CurrentTask};
use carrick_el1_abi::{EntryRef, LifecycleHatches, ThreadControlSlot, ThreadLifecyclePage};
use carrick_guest_arch::{GuestIsa, NativeOrdinal, UserVa};
use carrick_personality_linux::dispatch::FamilyCompletion;
use carrick_personality_linux::entry::CanonicalOrdinal;
use carrick_personality_linux::entry::SyscallResult;
use carrick_personality_linux::entry::decode_aarch64;
use carrick_personality_linux::entry::{CanonicalCall, decode_x86_snapshot};
use carrick_personality_linux::pending_anonymous::{
    DelegatedStep, PendingAnonymousVenue, PermissionStep, RetirementStep,
};
use carrick_x86::cpl0_entry::NativeFrame;
use core::sync::atomic::{AtomicU64, Ordering};
use std::boxed::Box;

const TID_A: u64 = 41;
const TID_B: u64 = 42;

/// Two live exact task/MM owners with separately retained control pages.
struct Venue {
    pages: [ThreadLifecyclePage; 2],
    bindings: [carrick_core_abi::ExecutionBinding; 2],
    slots: [ThreadControlSlot; 2],
}

impl LifecycleVenue for Venue {
    fn thread<'a>(&'a self, task: &'a CurrentTask) -> Option<LifecycleThread<'a>> {
        let binding = execution_binding(task);
        let index = self
            .bindings
            .iter()
            .position(|expected| *expected == binding)?;
        Some(LifecycleThread {
            page: &self.pages[index],
            slot: &self.slots[index],
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
        for (index, task) in tasks.iter().enumerate() {
            task.mm.key.store(5 + index as u64, Ordering::Release);
            task.mm
                .thread_generation
                .store(101 + index as u64, Ordering::Release);
        }
        Self {
            venue: Box::new(Venue {
                pages: core::array::from_fn(|_| ThreadLifecyclePage::with_hatches(hatches)),
                bindings: core::array::from_fn(|i| execution_binding(&tasks[i])),
                slots: core::array::from_fn(|_| ThreadControlSlot::new()),
            }),
            tasks,
            counters: Box::new(Counters::new()),
            publications: AtomicU64::new(0),
        }
    }

    /// x86_64 `set_robust_list` (native 273) as the CPL0 entry decodes it.
    fn set_robust_list(&self, task: usize, head: u64, len: u64) -> EntryOutcome {
        let native = NativeFrame {
            rax: 273,
            rdi: head,
            rsi: len,
            rsp: 0x7fff_0000,
            ..Default::default()
        };
        let call = decode_x86_snapshot(native.snapshot()).unwrap();
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

fn served_result(outcome: EntryOutcome) -> Option<i64> {
    match outcome {
        EntryOutcome::Served { result, .. } | EntryOutcome::ServedWithWork { result, .. } => {
            Some(result.raw())
        }
        EntryOutcome::Forward | EntryOutcome::InvalidCompletion => None,
    }
}

struct AnonymousBreak;
impl PendingAnonymousVenue for AnonymousBreak {
    fn original_argument0(&self) -> u64 {
        0
    }
    fn task_state(&self) -> Option<&carrick_personality_linux::abi::entry::LinuxTaskState> {
        None
    }
    fn delegated(&mut self) -> DelegatedStep {
        DelegatedStep::Served(SyscallResult::new(0x403000))
    }
    fn park_prepared(&mut self) -> Option<FamilyCompletion> {
        None
    }
    fn permission(&mut self) -> PermissionStep {
        PermissionStep::Forward
    }
    fn retirement(&mut self) -> RetirementStep {
        RetirementStep::Forward
    }
    fn install_result(&mut self, _: SyscallResult) {}
}

#[test]
fn x86_brk_enters_the_common_linux_anonymous_route() {
    let world = World::new(LifecycleHatches::ON);
    let call = decode_x86_snapshot(
        NativeFrame {
            rax: 12,
            rsp: 0x7fff_0000,
            ..Default::default()
        }
        .snapshot(),
    )
    .unwrap();
    let mut anonymous = AnonymousBreak;
    let result = serve_canonical_with_anonymous(
        &call,
        &world.counters,
        &world.tasks[0],
        &*world.venue,
        Some(&world.publications),
        &mut anonymous,
    );
    assert_eq!(
        served_result(result),
        Some(0x403000),
        "canonical: {:?}; served: {}; forwarded: {}",
        call.canonical,
        world.counters.served[214].load(Ordering::Relaxed),
        world.counters.forwarded[214].load(Ordering::Relaxed)
    );
    assert_eq!(world.counters.served[214].load(Ordering::Relaxed), 1);
    assert_eq!(world.counters.forwarded[214].load(Ordering::Relaxed), 0);
}

#[test]
fn arm_process_calls_still_forward_without_native_hooks() {
    let world = World::new(LifecycleHatches::ON);
    for number in [94, 260] {
        let call = decode_aarch64(number, [0; 6], 0x7000);
        assert_eq!(
            serve_canonical(
                &call,
                &world.counters,
                &world.tasks[0],
                &*world.venue,
                Some(&world.publications),
            ),
            EntryOutcome::Forward,
        );
    }
}

#[test]
fn two_tasks_publish_only_their_own_robust_heads() {
    let w = World::new(LifecycleHatches::ON);
    let mut previous_b = (0, 0);
    for round in 0..4_u64 {
        let (a, b) = (0xa000 + round * 0x40, 0xb000 + round * 0x40);
        assert_eq!(served_result(w.set_robust_list(0, a, 24)), Some(0));
        assert_eq!(w.heads(), [(a, 24), previous_b]);
        assert_eq!(served_result(w.set_robust_list(1, b, 24)), Some(0));
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
                served_result(w.set_robust_list(task, 0xdead_0000, len)),
                Some(-22),
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
    w.tasks[1].linux.mark_pending_host_work();
    assert!(
        matches!(w.set_robust_list(1, 0xb000, 24), EntryOutcome::ServedWithWork { result, .. } if result.raw() == 0)
    );
    assert_ne!(w.tasks[1].linux.served_with_work.load(Ordering::Relaxed), 0);
    assert_eq!(w.tasks[0].linux.served_with_work.load(Ordering::Relaxed), 0);
    assert_eq!(w.heads(), [(0, 0), (0xb000, 24)]);
    assert_eq!(w.served(), 1);
    assert_eq!(w.publications.load(Ordering::Relaxed), 1);
}

#[test]
fn closed_gate_or_hatch_forwards_without_effect() {
    let w = World::new(LifecycleHatches::ON);
    w.venue.pages[0].close();
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
    w.tasks[0].execution.generation.store(0, Ordering::Release);
    assert_eq!(w.set_robust_list(0, 0xa000, 24), EntryOutcome::Forward);
    assert_eq!(w.heads(), [(0, 0), (0, 0)]);
    assert_eq!(w.publications.load(Ordering::Relaxed), 0);
    assert_eq!(w.served(), 0);
    assert_eq!(w.forwarded(), 1);
}

/// X4 uses the moved production entry, real EL1 pending family/robust-list
/// body, and native codecs, never a fixture that implements Linux results.
pub(super) fn x4_linux_common_entry() {
    for scale in [1, 2, 8] {
        let mut w = World::new(LifecycleHatches::ON);
        // Reuse the Linux-visible ID while retaining distinct exact task/MM
        // generations and thread serials in both simultaneously live owners.
        w.tasks[1].execution.task.store(TID_A, Ordering::Release);
        w.venue.bindings[1] = execution_binding(&w.tasks[1]);
        for turn in 0..scale {
            for task in 0..2 {
                let head = 0xa000 + (task as u64 * 0x1000) + turn * 0x40;
                w.tasks[task].linux.mark_pending_host_work();
                let before = w.heads();
                let result = w.set_robust_list(task, head, 24);
                assert!(
                    matches!(result, EntryOutcome::ServedWithWork { result } if result.raw() == 0)
                );
                assert_eq!(
                    w.tasks[task].linux.take_served_boundary(),
                    Some(carrick_el1_abi::ServedBoundary::Completed)
                );
                assert_eq!(w.tasks[task].linux.take_served_boundary(), None);
                assert_eq!(w.heads()[task], (head, 24));
                assert_eq!(w.heads()[1 - task], before[1 - task]);
                // ARM crosses its real TrapFrame adapter and the real EL1
                // PendingFamilies implementation, preserving native registers.
                use carrick_el1::personality::{dispatch, sched};
                let mut frame = carrick_el1_abi::TrapFrame {
                    slot: task as u64,
                    esr: 0x5600_0000,
                    ..Default::default()
                };
                frame.x[0] = head;
                frame.x[1] = 23;
                frame.x[8] = 99;
                frame.x[19] = 0xfeed;
                assert_eq!(
                    dispatch::dispatch_syscall_with_lifecycle(
                        &mut frame,
                        &w.counters,
                        &w.tasks,
                        &[],
                        &[],
                        &[],
                        &[],
                        &carrick_el1_abi::InotifyNameCache::new(),
                        None::<dispatch::Zone<'_, super::NoCpu, sched::HardwareUserWord>>,
                        None,
                        Some(&*w.venue),
                        |_| core::ptr::null_mut()
                    ),
                    carrick_el1_abi::Action::ServedWithWork
                );
                assert_eq!(frame.x[0] as i64, -22);
                assert_eq!(frame.x[19], 0xfeed);
                assert_eq!(w.heads()[task], (head, 24));
                w.tasks[task].linux.take_served_boundary();
            }
        }
        assert_eq!(w.served(), 4 * scale);
        assert_eq!(w.publications.load(Ordering::Relaxed), 2 * scale);
        let before = w.heads();
        for native in [39, 99, u64::MAX - 1] {
            let frame = NativeFrame {
                rax: native,
                rdi: 0xdead,
                rsi: 24,
                ..Default::default()
            };
            let call = decode_x86_snapshot(frame.snapshot()).unwrap();
            assert_eq!(
                serve_canonical(
                    &call,
                    &w.counters,
                    &w.tasks[0],
                    &*w.venue,
                    Some(&w.publications)
                ),
                EntryOutcome::Forward
            );
            assert_eq!(w.heads(), before);
        }
        // A profile mismatch must be rejected by the codec before effects.
        let frame = NativeFrame::default();
        let mut snapshot = frame.snapshot();
        snapshot.isa = GuestIsa::Aarch64;
        assert!(decode_x86_snapshot(snapshot).is_none());
        snapshot.isa = GuestIsa::X86_64;
        snapshot.abi = carrick_guest_arch::NativeAbi::Aarch64El0;
        assert!(decode_x86_snapshot(snapshot).is_none());
        // Each identity dimension independently refuses the real family slot.
        for word in [
            &w.tasks[0].execution.generation,
            &w.tasks[0].mm.key,
            &w.tasks[0].mm.thread_generation,
        ] {
            let original = word.load(Ordering::Acquire);
            word.store(original + 1, Ordering::Release);
            assert_eq!(w.set_robust_list(0, 0xdead, 24), EntryOutcome::Forward);
            assert_eq!(w.heads(), before);
            word.store(original, Ordering::Release);
        }
    }
}
