#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
extern crate std;

use carrick_core::lifecycle::Lifecycle;
use carrick_el1::personality::thread_setup::{LifecycleThread, LifecycleVenue};
use carrick_el1::personality::{common_entry::execution_binding, dispatch, sched};
use carrick_el1_abi::{
    Action, BlockedMask, Counters, CurrentTask, EntryRef, InotifyNameCache, LifecycleHatches,
    PendingSignals, ThreadControlSlot, ThreadLifecyclePage, TrapFrame,
};
use carrick_guest_arch::{CanonicalNr, GuestIsa, NativeReturnWord, SyscallFrame, UserVa};
use carrick_personality_linux::entry::decode_x86_snapshot;
use carrick_x86::cpl0_entry::NativeFrame;
use core::sync::atomic::{AtomicU64, Ordering};
use std::boxed::Box;

const TID_A: u64 = 41;
const TID_B: u64 = 42;
const SET_ROBUST_LIST: usize = 99;

/// The x86 register adapter used by the shared dispatch witness. Argument 0
/// and the result occupy different native registers, as in production CPL0.
struct X86Frame<'a> {
    canonical: CanonicalNr,
    args: [u64; 6],
    rax: u64,
    slot: usize,
    stack: UserVa,
    publications: &'a AtomicU64,
}

impl SyscallFrame for X86Frame<'_> {
    fn canonical_ordinal(&self) -> CanonicalNr {
        self.canonical
    }
    fn argument(&self, index: usize) -> Option<u64> {
        self.args.get(index).copied()
    }
    fn result(&self) -> NativeReturnWord {
        NativeReturnWord(self.rax)
    }
    fn set_result(&mut self, result: NativeReturnWord) {
        self.rax = result.0;
    }
    fn slot(&self) -> Option<carrick_guest_arch::SlotId> {
        carrick_guest_arch::SlotId::from_index(self.slot)
    }
    fn user_sp(&self) -> Option<UserVa> {
        Some(self.stack)
    }
}
impl dispatch::GuestDispatchFrame for X86Frame<'_> {
    fn arm_frame(&mut self) -> Option<&mut TrapFrame> {
        None
    }
    fn arm_frame_ref(&self) -> Option<&TrapFrame> {
        None
    }
    fn arm_scheduler(&self) -> bool {
        false
    }
    fn robust_publications(&self) -> Option<&AtomicU64> {
        Some(self.publications)
    }
}

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
        let tasks = [CurrentTask::new(), CurrentTask::new()];
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
    fn call(&self, task: usize, native: NativeFrame) -> (Action, X86Frame<'_>) {
        let call = decode_x86_snapshot(native.snapshot()).expect("x86 snapshot");
        let mut frame = X86Frame {
            canonical: call.canonical,
            args: call.args,
            rax: native.rax,
            slot: task,
            stack: call.stack,
            publications: &self.publications,
        };
        let action = dispatch::dispatch_syscall_with_lifecycle(
            &mut frame,
            &self.counters,
            &self.tasks,
            &[],
            &[],
            &[],
            &[],
            &InotifyNameCache::new(),
            None::<dispatch::Zone<'_, super::NoCpu, sched::HardwareUserWord>>,
            None,
            Some(&*self.venue),
            |_| core::ptr::null_mut(),
        );
        (action, frame)
    }
    fn robust(&self, task: usize, head: u64, len: u64) -> (Action, i64) {
        let (action, frame) = self.call(
            task,
            NativeFrame {
                rax: 273,
                rdi: head,
                rsi: len,
                rsp: 0x7fff_0000,
                ..Default::default()
            },
        );
        (action, frame.rax as i64)
    }
    fn heads(&self) -> [(u64, u32); 2] {
        [
            self.venue.slots[0].robust_list(),
            self.venue.slots[1].robust_list(),
        ]
    }
    fn served(&self) -> u64 {
        self.counters.served[SET_ROBUST_LIST].load(Ordering::Relaxed)
    }
    fn forwarded(&self) -> u64 {
        self.counters.forwarded[SET_ROBUST_LIST].load(Ordering::Relaxed)
    }
}

#[test]
fn two_tasks_publish_only_their_own_robust_heads() {
    let w = World::new(LifecycleHatches::ON);
    let mut previous_b = (0, 0);
    for round in 0..4_u64 {
        let (a, b) = (0xa000 + round * 0x40, 0xb000 + round * 0x40);
        assert_eq!(w.robust(0, a, 24), (Action::Served, 0));
        assert_eq!(w.heads(), [(a, 24), previous_b]);
        assert_eq!(w.robust(1, b, 24), (Action::Served, 0));
        assert_eq!(w.heads(), [(a, 24), (b, 24)]);
        previous_b = (b, 24);
    }
    assert_eq!(w.served(), 8);
    assert_eq!(w.publications.load(Ordering::Relaxed), 8);
    assert_eq!(w.forwarded(), 0);
}

#[test]
fn x86_block_pending_unblock_owes_work_before_return() {
    const SIGUSR1_BIT: u64 = 1 << 9;
    let w = World::new(LifecycleHatches::ON);
    let set = Box::new(SIGUSR1_BIT);
    let sigprocmask = |how| NativeFrame {
        rax: 14,
        rdi: how,
        rsi: (&*set as *const u64) as u64,
        r10: 8,
        rsp: 0x7fff_0000,
        ..Default::default()
    };
    let (blocked, frame) = w.call(0, sigprocmask(0));
    assert_eq!((blocked, frame.rax), (Action::Served, 0));
    let slot = &w.venue.slots[0];
    assert_eq!(slot.blocked(), BlockedMask(SIGUSR1_BIT));

    // The forwarded kill(self) has posted a signal while it was blocked.
    let seen = slot
        .pending()
        .post_then_read_blocked(PendingSignals(SIGUSR1_BIT), slot);
    assert_ne!(seen.0 & SIGUSR1_BIT, 0);
    let (unblocked, frame) = w.call(0, sigprocmask(1));
    assert_eq!((unblocked, frame.rax), (Action::ServedWithWork, 0));
    assert_eq!(slot.blocked(), BlockedMask(0));
    assert_eq!(w.tasks[0].linux.served_with_work.load(Ordering::Acquire), 1);
}

#[test]
fn invalid_length_is_einval_and_changes_neither_head() {
    let w = World::new(LifecycleHatches::ON);
    w.robust(0, 0xa000, 24);
    w.robust(1, 0xb000, 24);
    for len in [0, 23, 25, u64::MAX] {
        for task in 0..2 {
            assert_eq!(w.robust(task, 0xdead_0000, len), (Action::Served, -22));
            assert_eq!(w.heads(), [(0xa000, 24), (0xb000, 24)]);
        }
    }
    assert_eq!(w.served(), 10);
    assert_eq!(w.publications.load(Ordering::Relaxed), 2);
    assert_eq!(w.forwarded(), 0);
}

#[test]
fn pending_host_work_completes_once_and_leaves_with_work() {
    let w = World::new(LifecycleHatches::ON);
    w.tasks[1].linux.mark_pending_host_work();
    assert_eq!(w.robust(1, 0xb000, 24), (Action::ServedWithWork, 0));
    assert_ne!(w.tasks[1].linux.served_with_work.load(Ordering::Relaxed), 0);
    assert_eq!(w.tasks[0].linux.served_with_work.load(Ordering::Relaxed), 0);
    assert_eq!(w.heads(), [(0, 0), (0xb000, 24)]);
    assert_eq!(w.served(), 1);
    assert_eq!(w.publications.load(Ordering::Relaxed), 1);
}

#[test]
fn tid_registration_uses_shared_completion_with_pending_work() {
    let w = World::new(LifecycleHatches::ON);
    assert!(w.venue.slots[1].publish_visible_tid(TID_B as u32));
    w.tasks[1].linux.mark_pending_host_work();
    let (action, frame) = w.call(
        1,
        NativeFrame {
            rax: 218,
            rdi: 0x1004,
            rsp: 0x9000,
            ..Default::default()
        },
    );
    assert_eq!(action, Action::ServedWithWork);
    assert_eq!(frame.rax, TID_B);
    assert_eq!(w.venue.slots[1].clear_child_tid(), 0x1004);
    assert_eq!(w.venue.slots[0].clear_child_tid(), 0);
    assert_eq!(w.counters.served[96].load(Ordering::Relaxed), 1);
    assert_eq!(w.tasks[1].linux.served_with_work.load(Ordering::Relaxed), 1);
    assert_eq!(w.tasks[1].linux.orig_arg0.load(Ordering::Relaxed), 0x1004);
}

#[test]
fn closed_gate_or_hatch_forwards_without_effect() {
    let w = World::new(LifecycleHatches::ON);
    w.venue.pages[0].close();
    assert_eq!(w.robust(0, 0xa000, 24).0, Action::Forward);
    assert_eq!(w.robust(0, 0xa000, 23).0, Action::Forward);
    let w2 = World::new(LifecycleHatches {
        threads: true,
        sigmask: false,
    });
    assert_eq!(w2.robust(1, 0xb000, 24).0, Action::Forward);
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
    assert_eq!(
        w.call(
            2,
            NativeFrame {
                rax: 273,
                rdi: 0xc000,
                rsi: 24,
                ..Default::default()
            }
        )
        .0,
        Action::Forward
    );
    assert_eq!(
        w.call(
            256,
            NativeFrame {
                rax: 273,
                rdi: 0xc000,
                rsi: 24,
                ..Default::default()
            }
        )
        .0,
        Action::Forward
    );
    assert_eq!(
        w.call(
            0,
            NativeFrame {
                rax: 39,
                ..Default::default()
            }
        )
        .0,
        Action::Forward
    );
    assert_eq!(w.heads(), [(0, 0), (0, 0)]);
    assert_eq!(w.counters.forwarded[172].load(Ordering::Relaxed), 1);
}

#[test]
fn cleared_execution_generation_cannot_publish_to_a_retained_slot() {
    let w = World::new(LifecycleHatches::ON);
    w.tasks[0].execution.generation.store(0, Ordering::Release);
    assert_eq!(w.robust(0, 0xa000, 24).0, Action::Forward);
    assert_eq!(w.heads(), [(0, 0), (0, 0)]);
    assert_eq!(w.publications.load(Ordering::Relaxed), 0);
}

#[test]
fn x86_result_register_is_distinct_from_argument_zero() {
    let w = World::new(LifecycleHatches::ON);
    let (action, frame) = w.call(
        0,
        NativeFrame {
            rax: 273,
            rdi: 0xa000,
            rsi: 24,
            ..Default::default()
        },
    );
    assert_eq!(action, Action::Served);
    assert_eq!(frame.args[0], 0xa000);
    assert_eq!(frame.result().0, 0);
}

#[test]
fn x86_exit_without_a_native_scheduler_forwards() {
    let w = World::new(LifecycleHatches::ON);
    let (action, frame) = w.call(
        0,
        NativeFrame {
            rax: 60,
            rdi: 17,
            ..Default::default()
        },
    );
    assert_eq!(action, Action::Forward);
    assert_eq!(frame.args[0], 17);
    assert_eq!(frame.result().0, 60);
}

pub(super) fn x4_linux_common_entry() {
    for scale in [1, 2, 8] {
        let mut w = World::new(LifecycleHatches::ON);
        w.tasks[1].execution.task.store(TID_A, Ordering::Release);
        w.venue.bindings[1] = execution_binding(&w.tasks[1]);
        for turn in 0..scale {
            for task in 0..2 {
                let head = 0xa000 + (task as u64 * 0x1000) + turn * 0x40;
                w.tasks[task].linux.mark_pending_host_work();
                let before = w.heads();
                assert_eq!(w.robust(task, head, 24), (Action::ServedWithWork, 0));
                assert_eq!(
                    w.tasks[task].linux.take_served_boundary(),
                    Some(carrick_el1_abi::ServedBoundary::Completed)
                );
                assert_eq!(w.tasks[task].linux.take_served_boundary(), None);
                assert_eq!(w.heads()[task], (head, 24));
                assert_eq!(w.heads()[1 - task], before[1 - task]);
                let mut frame = TrapFrame {
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
                        &InotifyNameCache::new(),
                        None::<dispatch::Zone<'_, super::NoCpu, sched::HardwareUserWord>>,
                        None,
                        Some(&*w.venue),
                        |_| core::ptr::null_mut()
                    ),
                    Action::ServedWithWork
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
            assert_eq!(
                w.call(
                    0,
                    NativeFrame {
                        rax: native,
                        rdi: 0xdead,
                        rsi: 24,
                        ..Default::default()
                    }
                )
                .0,
                Action::Forward
            );
            assert_eq!(w.heads(), before);
        }
        let frame = NativeFrame::default();
        let mut snapshot = frame.snapshot();
        snapshot.isa = GuestIsa::Aarch64;
        assert!(decode_x86_snapshot(snapshot).is_none());
        snapshot.isa = GuestIsa::X86_64;
        snapshot.abi = carrick_guest_arch::NativeAbi::Aarch64El0;
        assert!(decode_x86_snapshot(snapshot).is_none());
        for word in [
            &w.tasks[0].execution.generation,
            &w.tasks[0].mm.key,
            &w.tasks[0].mm.thread_generation,
        ] {
            let original = word.load(Ordering::Acquire);
            word.store(original + 1, Ordering::Release);
            assert_eq!(w.robust(0, 0xdead, 24).0, Action::Forward);
            assert_eq!(w.heads(), before);
            word.store(original, Ordering::Release);
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn arch_prctl_uses_shared_admission_and_completion_with_pending_work() {
    use carrick_personality_linux::abi::x86_64::ArchPrctlOperation;
    use carrick_personality_linux::dispatch::{CompletionRoute, EntryCounters, PendingFamilies};
    use carrick_personality_linux::entry::SyscallResult;
    struct NativePending<'a> {
        world: &'a World,
        calls: core::cell::Cell<u64>,
        args: [u64; 6],
    }
    impl<'a> PendingFamilies<'a> for NativePending<'a> {
        fn binding(&self) -> Option<carrick_core_abi::ExecutionBinding> {
            let generation = self.world.tasks[1]
                .execution
                .generation
                .load(Ordering::Acquire);
            if generation == 0 {
                None
            } else {
                Some(execution_binding(&self.world.tasks[1]))
            }
        }
        fn original_argument0(&self) -> u64 {
            self.args[0]
        }
        fn install_result(&mut self, _: SyscallResult) {}
        fn task_state(&self) -> Option<&carrick_personality_linux::abi::entry::LinuxTaskState> {
            Some(&self.world.tasks[1].linux)
        }
        fn host_work(&self) -> bool {
            self.world.tasks[1].linux.has_pending_host_work()
        }
        fn arch_prctl(&mut self) -> Option<SyscallResult> {
            let operation = ArchPrctlOperation::decode(self.args[0]);
            let address = UserVa::new(self.args[1]);
            assert_eq!(operation, Some(ArchPrctlOperation::SetFs));
            assert_eq!(address.raw(), 0x7000);
            self.calls.set(self.calls.get() + 1);
            Some(SyscallResult::new(0))
        }
        fn entry_counters(&self) -> Option<EntryCounters<'_>> {
            Some(EntryCounters {
                served: &self.world.counters.served,
                forwarded: &self.world.counters.forwarded,
            })
        }
        fn publish_work(&self, _: bool) {
            self.world.tasks[1].linux.record_completed_with_work();
        }
    }
    let w = World::new(LifecycleHatches::ON);
    let mut pending = NativePending {
        world: &w,
        calls: core::cell::Cell::new(0),
        args: [0x1002, 0x7000, 0, 0, 0, 0],
    };
    let private_slot = carrick_syscall_abi::private_x86_counter_slot(
        carrick_syscall_abi::CanonicalNr(carrick_syscall_abi::CARRICK_PRIVATE_X86_ARCH_PRCTL),
    )
    .unwrap();
    let getgroups = carrick_personality_linux::entry::decode_x86_64(115, [0; 6], 0x9000);
    assert_eq!(getgroups.canonical.raw(), 158);
    let mut getgroups_pending = NativePending {
        world: &w,
        calls: core::cell::Cell::new(0),
        args: [0; 6],
    };
    assert_eq!(
        carrick_personality_linux::dispatch::dispatch_x86(
            getgroups.canonical.raw(),
            u64::MAX,
            &mut getgroups_pending,
        ),
        CompletionRoute::Forward
    );
    assert_eq!(w.counters.forwarded[158].load(Ordering::Relaxed), 1);
    assert_eq!(
        w.counters.forwarded[private_slot].load(Ordering::Relaxed),
        0
    );
    w.tasks[1].linux.mark_pending_host_work();
    let call =
        carrick_personality_linux::entry::decode_x86_64(158, [0x1002, 0x7000, 0, 0, 0, 0], 0x9000);
    assert_eq!(
        call.canonical.raw(),
        carrick_syscall_abi::CARRICK_PRIVATE_X86_ARCH_PRCTL
    );
    let route = carrick_personality_linux::dispatch::dispatch_x86(
        call.canonical.raw(),
        u64::MAX,
        &mut pending,
    );
    assert_eq!(route, CompletionRoute::WithWork);
    assert_eq!(pending.calls.get(), 1);
    assert_eq!(w.counters.served[158].load(Ordering::Relaxed), 0);
    assert_eq!(w.counters.served[private_slot].load(Ordering::Relaxed), 1);
    assert_eq!(w.tasks[1].linux.served_with_work.load(Ordering::Relaxed), 1);
    assert_eq!(w.tasks[0].linux.served_with_work.load(Ordering::Relaxed), 0);
    assert_eq!(w.tasks[1].linux.orig_arg0.load(Ordering::Relaxed), 0x1002);
    w.tasks[1].execution.generation.store(0, Ordering::Release);
    let route = carrick_personality_linux::dispatch::dispatch_x86(
        call.canonical.raw(),
        u64::MAX,
        &mut pending,
    );
    assert_eq!(route, CompletionRoute::Forward);
    assert_eq!(
        pending.calls.get(),
        1,
        "unadmitted native effects are forbidden"
    );
    assert_eq!(w.counters.served[158].load(Ordering::Relaxed), 0);
    assert_eq!(w.counters.served[private_slot].load(Ordering::Relaxed), 1);
    assert_eq!(
        w.counters.forwarded[private_slot].load(Ordering::Relaxed),
        1
    );
    assert_eq!(w.counters.forwarded[158].load(Ordering::Relaxed), 1);
}
