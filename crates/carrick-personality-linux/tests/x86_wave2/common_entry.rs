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
use carrick_personality_linux::dispatch::FamilyCompletion;
use carrick_personality_linux::entry::{
    CanonicalCall, SyscallResult, decode_aarch64, decode_x86_snapshot,
};
use carrick_personality_linux::pending_anonymous::{
    DelegatedStep, PendingAnonymousVenue, PermissionStep, RetirementStep,
};
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
            None,
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

fn serve_full<'a, Context: dispatch::DispatchContext + 'a>(
    call: &CanonicalCall,
    world: &'a World,
    anonymous: &'a mut dyn PendingAnonymousVenue,
    mut process: Option<&'a mut dyn carrick_personality_linux::lifecycle::ProcessNative<Context>>,
    source: Option<carrick_core_abi::BornInZoneSource<'a, Context>>,
) -> (carrick_personality_linux::dispatch::CompletionRoute, i64) {
    let mut frame = X86Frame {
        canonical: call.canonical,
        args: call.args,
        rax: call.native.raw(),
        slot: source.map_or(0, |source| source.slot.index()),
        stack: call.stack,
        publications: &world.publications,
    };
    let route = dispatch::dispatch_syscall_with_native(
        &mut frame,
        &world.counters,
        &world.tasks,
        &[],
        &[],
        &[],
        &[],
        &InotifyNameCache::new(),
        None::<dispatch::Zone<'_, super::NoCpu, sched::HardwareUserWord>>,
        None,
        Some(&*world.venue),
        process.as_mut().map(|process| {
            &mut **process
                as &mut (dyn carrick_personality_linux::lifecycle::ProcessNative<Context> + '_)
        }),
        source,
        Some(anonymous),
        |_| core::ptr::null_mut(),
    );
    (route, frame.result().0 as i64)
}
fn served_result(
    (route, result): (carrick_personality_linux::dispatch::CompletionRoute, i64),
) -> Option<i64> {
    use carrick_personality_linux::dispatch::CompletionRoute;
    matches!(route, CompletionRoute::Served | CompletionRoute::WithWork).then_some(result)
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
    let result =
        serve_full::<carrick_sched_core::ThreadCtx>(&call, &world, &mut anonymous, None, None);
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
fn anonymous_result_is_not_installed_after_execution_changes() {
    struct InvalidatingAnonymous<'a>(&'a AtomicU64);
    impl PendingAnonymousVenue for InvalidatingAnonymous<'_> {
        fn original_argument0(&self) -> u64 {
            0x7000
        }
        fn task_state(&self) -> Option<&carrick_personality_linux::abi::entry::LinuxTaskState> {
            None
        }
        fn delegated(&mut self) -> DelegatedStep {
            self.0.fetch_add(1, Ordering::AcqRel);
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
        fn install_result(&mut self, _: SyscallResult) {
            panic!("native result must use authenticated common finish")
        }
    }
    let world = World::new(LifecycleHatches::ON);
    let call =
        carrick_personality_linux::entry::decode_x86_64(12, [0x7000, 0, 0, 0, 0, 0], 0x7fff0000);
    let mut anonymous = InvalidatingAnonymous(&world.tasks[0].execution.generation);
    let (route, result) =
        serve_full::<carrick_sched_core::ThreadCtx>(&call, &world, &mut anonymous, None, None);
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::InvalidCompletion
    );
    assert_eq!(
        result, 12,
        "the completed value must not enter an unauthenticated return frame"
    );
    assert_eq!(world.counters.served[214].load(Ordering::Relaxed), 0);
    assert_eq!(
        world.counters.forwarded[214].load(Ordering::Relaxed),
        0,
        "an effect must not be forwarded for replay"
    );
}

#[test]
fn arm_process_calls_still_forward_without_native_hooks() {
    let world = World::new(LifecycleHatches::ON);
    for number in [94, 260] {
        let call = decode_aarch64(number, [0; 6], 0x7000);
        assert_eq!(
            serve_full::<carrick_sched_core::ThreadCtx>(
                &call,
                &world,
                &mut AnonymousBreak,
                None,
                None
            )
            .0,
            carrick_personality_linux::dispatch::CompletionRoute::Forward,
        );
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
                        None,
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
fn common_linux_entry_calls_native_process_custody() {
    use carrick_personality_linux::lifecycle::{LifecycleOutcome, ProcessNative, ProcessWaitPid};
    struct Process {
        binding: carrick_core_abi::ExecutionBinding,
        visits: std::vec::Vec<u64>,
        idle: bool,
    }
    impl ProcessNative for Process {
        fn binding(&self) -> carrick_core_abi::ExecutionBinding {
            self.binding
        }
        fn fork(&mut self) -> LifecycleOutcome {
            self.visits.push(57);
            LifecycleOutcome::Returned {
                result: SyscallResult::new(42),
                work: false,
            }
        }
        fn wait4(
            &mut self,
            pid: ProcessWaitPid,
            status: UserVa,
            options: carrick_personality_linux::lifecycle::LinuxWaitOptions,
            rusage: UserVa,
        ) -> LifecycleOutcome {
            assert_eq!(pid.raw(), 42);
            assert_eq!(status.raw(), 0x7000);
            assert_eq!(options.bits(), 0);
            assert_eq!(rusage.raw(), 0x8000);
            self.visits.push(61);
            if self.idle {
                return LifecycleOutcome::Transferred {
                    progress: carrick_core_abi::Served::Idle,
                    result: SyscallResult::new(0),
                };
            }
            LifecycleOutcome::Returned {
                result: SyscallResult::new(42),
                work: false,
            }
        }
        fn exit_group(&mut self, status: u8) -> LifecycleOutcome {
            assert_eq!(status, 7);
            self.visits.push(231);
            LifecycleOutcome::Returned {
                result: SyscallResult::new(0),
                work: false,
            }
        }
    }
    let world = World::new(LifecycleHatches::ON);
    let mut process = Process {
        binding: execution_binding(&world.tasks[0]),
        visits: std::vec::Vec::new(),
        idle: false,
    };
    let mut anonymous = AnonymousBreak;
    for (native, args, result) in [
        (57, [0; 6], 42),
        (61, [42, 0x7000, 0, 0x8000, 0, 0], 42),
        (231, [7, 0, 0, 0, 0, 0], 0),
    ] {
        let call = carrick_personality_linux::entry::decode_x86_64(native, args, 0x7fff0000);
        assert_eq!(
            served_result(serve_full(
                &call,
                &world,
                &mut anonymous,
                Some(&mut process),
                None
            )),
            Some(result)
        );
        assert_eq!(
            world
                .counters
                .forwarded
                .iter()
                .map(|count| count.load(Ordering::Relaxed))
                .sum::<u64>(),
            0
        );
    }
    assert_eq!(process.visits, [57, 61, 231]);
    process.idle = true;
    let call = carrick_personality_linux::entry::decode_x86_64(
        61,
        [42, 0x7000, 0, 0x8000, 0, 0],
        0x7fff0000,
    );
    assert_eq!(
        serve_full(&call, &world, &mut anonymous, Some(&mut process), None).0,
        carrick_personality_linux::dispatch::CompletionRoute::InvalidCompletion
    );
    assert_eq!(process.visits, [57, 61, 231, 61]);
    assert_eq!(
        world
            .counters
            .forwarded
            .iter()
            .map(|count| count.load(Ordering::Relaxed))
            .sum::<u64>(),
        0
    );
    process.binding = execution_binding(&world.tasks[1]);
    let call = carrick_personality_linux::entry::decode_x86_64(57, [0; 6], 0x7fff0000);
    assert_eq!(
        serve_full(&call, &world, &mut anonymous, Some(&mut process), None).0,
        carrick_personality_linux::dispatch::CompletionRoute::Forward
    );
    assert_eq!(process.visits, [57, 61, 231, 61]);
    process.binding = execution_binding(&world.tasks[0]);
    for index in 1..6 {
        let mut args = [17, 0, 0, 0, 0, 0];
        args[index] = 0x1000;
        let call = carrick_personality_linux::entry::decode_x86_64(56, args, 0x7fff0000);
        assert_eq!(
            serve_full(&call, &world, &mut anonymous, Some(&mut process), None).0,
            carrick_personality_linux::dispatch::CompletionRoute::Forward
        );
        assert_eq!(
            process.visits,
            [57, 61, 231, 61],
            "unsupported clone shape must not call fork"
        );
    }
}

#[test]
fn compact_common_entry_suspends_only_after_authenticated_park() {
    use carrick_core_abi::{BornInZoneSource, EntryHandoffReceipt};
    use carrick_personality_linux::lifecycle::{LifecycleOutcome, ProcessNative, ProcessWaitPid};
    use carrick_sched_core::{
        ExecutionSlot, ParkedContextWords, SlotId, ThreadIdentity, ZoneTables,
    };
    struct Process<'a> {
        binding: carrick_core_abi::ExecutionBinding,
        source: BornInZoneSource<'a, ParkedContextWords>,
        record: carrick_sched_core::RecordId,
        receipt: Option<EntryHandoffReceipt<ParkedContextWords>>,
        visits: usize,
    }
    impl ProcessNative<ParkedContextWords> for Process<'_> {
        fn binding(&self) -> carrick_core_abi::ExecutionBinding {
            self.binding
        }
        fn take_handoff_receipt(&mut self) -> Option<EntryHandoffReceipt<ParkedContextWords>> {
            self.receipt.take()
        }
        fn fork(&mut self) -> LifecycleOutcome {
            panic!("wrong lifecycle family")
        }
        fn exit_group(&mut self, _: u8) -> LifecycleOutcome {
            panic!("wrong lifecycle family")
        }
        fn wait4(
            &mut self,
            pid: ProcessWaitPid,
            status: UserVa,
            options: carrick_personality_linux::lifecycle::LinuxWaitOptions,
            rusage: UserVa,
        ) -> LifecycleOutcome {
            assert_eq!(pid.raw(), 72);
            assert_eq!(status.raw(), 0x7000);
            assert_eq!(options.bits(), 0);
            assert_eq!(rusage.raw(), 0);
            self.visits += 1;
            let start =
                carrick_core::entry::prepare_handoff(self.binding, self.source, self.record)
                    .unwrap();
            let zone = self.source.zone;
            let guard = zone
                .lock(
                    ZoneTables::bucket_of(self.binding.mm.raw(), 0x1000),
                    &carrick_sched_core::BoundedSpin(1024),
                )
                .unwrap();
            let sequence = zone.next_seq(self.record);
            zone.enqueue(
                &guard,
                self.record,
                sequence,
                self.binding.mm.raw(),
                0x1000,
                u32::MAX,
                0,
            )
            .unwrap();
            self.receipt = Some(
                carrick_core::entry::publish_handoff_park(
                    start,
                    &guard,
                    carrick_core_abi::EntryRecordGeneration(sequence),
                )
                .unwrap(),
            );
            zone.clear_current(self.source.slot);
            LifecycleOutcome::Transferred {
                progress: carrick_core_abi::Served::Idle,
                result: SyscallResult::new(0),
            }
        }
    }
    for generation in [0, 11] {
        type CompactZone = ZoneTables<ParkedContextWords>;
        let layout = std::alloc::Layout::new::<CompactZone>();
        // SAFETY: exact zero-initialized scheduler allocation with its native
        // context alignment; Box retains it for this one entry turn.
        let zone = unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<CompactZone>();
            assert!(!ptr.is_null());
            Box::from_raw(ptr)
        };
        let slot = SlotId::new(1);
        let identity = ThreadIdentity {
            tid: 71,
            serial: 113,
            mm: 29,
            file_table: 9,
            generation,
            affinity: 2,
            lifecycle_page: 0x1000,
            control_slot: 0x2000,
        };
        zone.drive(slot, 3);
        zone.publish_slot(slot, identity.mm, None, 0);
        let here = ExecutionSlot::zone(slot);
        zone.occupancy.vacate_any(here);
        assert!(zone.occupancy.replace(here, 0, identity.mm));
        zone.enter_guest(slot);
        let space = zone
            .spaces
            .publish_closed(identity.mm, 0x9000, 0x9000)
            .unwrap();
        zone.spaces.open(space);
        assert!(zone.install_space(slot, identity.mm).is_some());
        let record = zone.alloc_record(identity).unwrap();
        zone.requeue_preempted(slot, record);
        assert_eq!(zone.switch_in(slot), Some(record));
        let binding = carrick_core_abi::ExecutionBinding {
            task: carrick_core_abi::EntryTaskKey::from_raw(identity.tid),
            generation: carrick_core_abi::EntryGeneration::from_raw(identity.generation),
            mm: carrick_core_abi::EntryMmKey::from_raw(identity.mm),
            thread_generation: carrick_core_abi::EntryThreadGeneration::from_raw(identity.serial),
        };
        let source = BornInZoneSource { zone: &zone, slot };
        let mut process = Process {
            binding,
            source,
            record,
            receipt: None,
            visits: 0,
        };
        let mut world = World::new(LifecycleHatches::ON);
        world.tasks[1].set(
            carrick_el1_abi::El1TaskId::from_linux_tid(identity.tid.try_into().unwrap()),
            identity.generation,
            identity.file_table,
        );
        world.tasks[1].mm.key.store(identity.mm, Ordering::Release);
        world.tasks[1]
            .mm
            .thread_generation
            .store(identity.serial, Ordering::Release);
        world.venue.bindings[1] = binding;
        let state = &world.tasks[1].linux;
        state.orig_arg0.store(123, Ordering::Relaxed);
        let counters = &world.counters;
        let call = carrick_personality_linux::entry::decode_x86_64(
            61,
            [72, 0x7000, 0, 0, 0, 0],
            0x7fff0000,
        );
        assert_eq!(
            serve_full(
                &call,
                &world,
                &mut AnonymousBreak,
                Some(&mut process),
                Some(source)
            )
            .0,
            carrick_personality_linux::dispatch::CompletionRoute::Suspended
        );
        assert_eq!(process.visits, 1);
        assert!(process.receipt.is_none());
        assert!(zone.slot(slot).current().is_none());
        assert_eq!(state.orig_arg0.load(Ordering::Relaxed), 123);
        assert_eq!(
            counters
                .forwarded
                .iter()
                .map(|v| v.load(Ordering::Relaxed))
                .sum::<u64>(),
            0
        );
        assert_eq!(
            counters
                .served
                .iter()
                .map(|v| v.load(Ordering::Relaxed))
                .sum::<u64>(),
            1
        );
    }
}
