#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use carrick_abi::LinuxCloneFlags;
use carrick_hal::NullHostSignalBridge;
use carrick_hal::threaded::{Aarch64TaskCpuStateV1, GuestCpuState};
use carrick_hal::{
    BudgetError, CpuAffinity, CpuQueueView, DispatchContext, GuestCpuId, GuestCpuPolicy, RunBudget,
    SchedProcessId, SchedThreadId, SchedulingPolicy, TaskPlacement, ThreadId,
};
use carrick_kernel::kernel::objects::MigratableTaskState;
use carrick_kernel::kernel::scheduler::PreemptionReasons;
use carrick_kernel::kernel::scheduler::preemption::{
    DeliveryOutcome, DemandTicket, ManualClock, MonotonicClock, PreemptionRequest, PreemptionWork,
};
use carrick_kernel::kernel::{
    ClonePlan, ExecutorBinding, ExecutorKick, ExecutorKickToken, Kernel, KernelContext, Scheduler,
};
use carrick_kernel_example::process::{AddressSpace, AsidAllocator, ExampleProcess};

#[derive(Debug, Default)]
struct TestKick {
    binding: parking_lot::Mutex<Option<ExecutorBinding>>,
    tokens: parking_lot::Mutex<Vec<ExecutorKickToken>>,
    changed: parking_lot::Condvar,
    kicked: AtomicBool,
}

impl ExecutorKick for TestKick {
    fn try_bind(&self, binding: ExecutorBinding) -> bool {
        let mut current = self.binding.lock();
        if current.is_some() {
            return false;
        }
        *current = Some(binding);
        true
    }

    fn unbind(&self, binding: ExecutorBinding) {
        let mut current = self.binding.lock();
        if *current == Some(binding) {
            *current = None;
        }
    }

    fn rebind_exact_with(
        &self,
        predecessor: ExecutorBinding,
        successor: ExecutorBinding,
        publish: &mut dyn FnMut() -> bool,
    ) -> bool {
        let mut current = self.binding.lock();
        if *current != Some(predecessor) {
            return false;
        }
        if !publish() {
            return false;
        }
        *current = Some(successor);
        true
    }

    fn deliver_exact(&self, token: ExecutorKickToken) -> bool {
        let current = self.binding.lock();
        if !current.is_some_and(|binding| {
            binding.executor() == token.executor()
                && binding.executor_epoch() == token.executor_epoch()
                && binding.thread() == token.thread()
                && binding.generation() == token.generation()
        }) {
            return false;
        }
        self.kicked.store(true, Ordering::Release);
        self.tokens.lock().push(token);
        self.changed.notify_all();
        true
    }

    fn current_binding(&self) -> Option<ExecutorBinding> {
        *self.binding.lock()
    }
}

fn bootstrap_kernel(pid: i32) -> (Arc<Kernel>, KernelContext, Arc<AsidAllocator>) {
    let asids = Arc::new(AsidAllocator::new());
    let space = AddressSpace::allocate(&asids).expect("allocate space");
    let (_process, root) = ExampleProcess::boot_root(
        pid,
        "scheduler preemption test",
        Arc::new(NullHostSignalBridge::default()),
        space,
    )
    .expect("boot root");
    let kernel = Arc::clone(root.kernel());
    (kernel, root, asids)
}

fn bootstrap_kernel_with_policy_and_clock(
    pid: i32,
    policy: Arc<dyn SchedulingPolicy>,
    clock: Arc<dyn MonotonicClock>,
) -> (
    Arc<Kernel>,
    KernelContext,
    Arc<Scheduler>,
    Arc<AsidAllocator>,
) {
    let asids = Arc::new(AsidAllocator::new());
    let space = AddressSpace::allocate(&asids).expect("allocate space");
    let (_process, root) = ExampleProcess::boot_root(
        pid,
        "scheduler preemption test",
        Arc::new(NullHostSignalBridge::default()),
        space,
    )
    .expect("boot root");
    let kernel = Arc::clone(root.kernel());
    let scheduler = Arc::new(Scheduler::new_with_policy_and_clock(
        Arc::clone(&kernel),
        policy,
        clock,
    ));
    (kernel, root, scheduler, asids)
}

fn bootstrap_kernel_with_clock(
    pid: i32,
    clock: Arc<dyn MonotonicClock>,
) -> (
    Arc<Kernel>,
    KernelContext,
    Arc<Scheduler>,
    Arc<AsidAllocator>,
) {
    bootstrap_kernel_with_policy_and_clock(
        pid,
        Arc::new(GuestCpuPolicy::new(carrick_hal::MAX_GUEST_CPUS)),
        clock,
    )
}

fn create_sibling_thread(
    kernel: &Arc<Kernel>,
    parent: &KernelContext,
    host_tid: i32,
) -> KernelContext {
    let plan = ClonePlan::from_flags(
        LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
    )
    .expect("thread plan");
    kernel
        .reserve_thread_clone(parent, plan, None)
        .expect("reserve thread clone")
        .prepare(ThreadId::synthetic_for_tests(host_tid))
        .expect("prepare thread clone")
        .commit()
        .expect("publish thread clone")
        .start_thread()
        .expect("start thread")
        .into_context()
}

fn create_forked_child(
    kernel: &Arc<Kernel>,
    parent: &KernelContext,
    asids: &Arc<AsidAllocator>,
    child_name: &str,
) -> (KernelContext, Arc<ExampleProcess>) {
    let plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
    let reservation = kernel
        .reserve_fork(parent, plan, child_name.to_owned(), None)
        .expect("reserve fork");
    let child_pid = reservation.visible_child_id();
    let child_tid = ThreadId::from_guest_supplied_tid(child_pid);
    let space = AddressSpace::allocate(asids).expect("allocate space");
    let prepared = reservation
        .prepare_with_mm_backend(space.mm_backend(), child_tid)
        .expect("prepare with mm backend");
    let published = prepared.commit().expect("commit fork");
    let (child_context, _vfork) = published.into_parts().expect("into parts");
    let child_process = Arc::new(ExampleProcess::new(&child_context, space));
    (child_context, child_process)
}

fn publish_task(context: &KernelContext, marker: u64) {
    let mm = context.shared().mm().id();
    let state = MigratableTaskState {
        cpu: GuestCpuState::from_aarch64_v1(Aarch64TaskCpuStateV1 {
            gprs: std::array::from_fn(|index| marker + index as u64),
            pc: marker + 0x1000,
            pstate: marker + 0x2000,
            trap_pc: marker + 0x2100,
            trap_pstate: marker + 0x2200,
            sp_el0: marker + 0x3000,
            elr_el1: marker + 0x3100,
            spsr_el1: marker + 0x3200,
            ttbr0: marker + 0x4000,
            ttbr1: marker + 0x5000,
            tcr: marker + 0x6000,
            sctlr_el1: marker + 0x6100,
            mair_el1: marker + 0x6200,
            vbar_el1: marker + 0x6300,
            cpacr_el1: marker + 0x6400,
            cntkctl_el1: marker + 0x6500,
            tpidr_el1: marker + 0x6600,
            actlr_el1: marker + 0x7000,
            tpidr_el0: marker + 0x8000,
            tpidrro_el0: marker + 0x9000,
            contextidr_el1: marker + 0xa000,
            vregs: std::array::from_fn(|index| marker as u128 + index as u128),
            fpsr: marker as u32,
            fpcr: marker as u32 + 1,
            pending_resume_pc: Some(marker + 0xb000),
            last_syscall_nr: Some(marker),
            last_syscall_orig_x0: marker + 2,
            last_fault_esr: marker + 3,
            last_exit_class: marker,
            is_forked_child: false,
            syscall_continuation: None,
            mm_generation: mm.raw(),
            asid_generation: mm.raw(),
        }),
        mm,
        asid_generation: mm.raw(),
    };
    context
        .thread()
        .publish_initial_task_state(state)
        .expect("publish task state");
}

/// Test 1: Sibling threads receive distinct SchedThreadId values but equal SchedProcessId values,
/// and a custom policy can select the second sibling by SchedThreadId.
#[test]
fn sibling_threads_have_distinct_thread_ids_and_equal_process_ids() {
    #[derive(Debug, Default)]
    struct SelectSecondPolicy {
        placements: parking_lot::Mutex<Vec<(SchedThreadId, SchedProcessId)>>,
        target_pick: parking_lot::Mutex<Option<SchedThreadId>>,
    }

    impl SchedulingPolicy for SelectSecondPolicy {
        fn cpu_count(&self) -> usize {
            1
        }

        fn select_cpu(&self, placement: &TaskPlacement<'_>) -> GuestCpuId {
            self.placements
                .lock()
                .push((placement.thread, placement.process));
            GuestCpuId::new(0)
        }

        fn inspects_queues(&self) -> bool {
            true
        }

        fn pick_next(&self, view: &CpuQueueView<'_>) -> Option<SchedThreadId> {
            let target = *self.target_pick.lock();
            if let Some(target) = target
                && view.queued.contains(&target)
            {
                return Some(target);
            }
            view.queued.first().copied()
        }
    }

    let policy = Arc::new(SelectSecondPolicy::default());
    let (kernel, ctx_a, _asids) = bootstrap_kernel(61_001);
    publish_task(&ctx_a, 100);
    let ctx_b = create_sibling_thread(&kernel, &ctx_a, 61_002);
    publish_task(&ctx_b, 200);

    let scheduler = Arc::new(Scheduler::new_with_policy(
        Arc::clone(&kernel),
        policy.clone(),
    ));
    let executor = scheduler
        .register_executor_bound(
            Arc::new(TestKick::default()),
            Some(GuestCpuId::new(0)),
            false,
        )
        .unwrap();

    let key_a = ctx_a.thread().key();
    let key_b = ctx_b.thread().key();

    scheduler.make_runnable(key_a).unwrap();
    scheduler.make_runnable(key_b).unwrap();

    let records = policy.placements.lock().clone();
    assert_eq!(records.len(), 2, "both threads placed");
    let (thread_a, proc_a) = records[0];
    let (thread_b, proc_b) = records[1];

    // Core Task 1 identity invariants:
    assert_ne!(
        thread_a, thread_b,
        "sibling threads must have distinct SchedThreadId"
    );
    assert_eq!(
        proc_a, proc_b,
        "sibling threads must share the same SchedProcessId"
    );

    // Direct policy to choose the second thread:
    *policy.target_pick.lock() = Some(thread_b);

    let running = scheduler.take(&executor).unwrap();
    assert_eq!(
        running.thread_key(),
        key_b,
        "scheduler must claim the exact sibling thread selected by SchedThreadId"
    );

    scheduler
        .settle_blocked(
            running,
            carrick_kernel::kernel::objects::BlockedReason::HostWait,
        )
        .unwrap();
}

/// Test 2: Two distinct processes pin both identity domains (distinct SchedProcessId and SchedThreadId).
#[test]
fn distinct_processes_have_distinct_process_ids() {
    #[derive(Debug, Default)]
    struct RecordPlacementsPolicy {
        placements: parking_lot::Mutex<Vec<(SchedThreadId, SchedProcessId)>>,
    }

    impl SchedulingPolicy for RecordPlacementsPolicy {
        fn cpu_count(&self) -> usize {
            1
        }

        fn select_cpu(&self, placement: &TaskPlacement<'_>) -> GuestCpuId {
            self.placements
                .lock()
                .push((placement.thread, placement.process));
            GuestCpuId::new(0)
        }
    }

    let policy = Arc::new(RecordPlacementsPolicy::default());
    let (kernel, proc_a, asids) = bootstrap_kernel(62_001);
    publish_task(&proc_a, 300);

    let (proc_b, _child_proc) = create_forked_child(&kernel, &proc_a, &asids, "forked-child");
    publish_task(&proc_b, 400);

    let scheduler = Arc::new(Scheduler::new_with_policy(
        Arc::clone(&kernel),
        policy.clone(),
    ));

    scheduler.make_runnable(proc_a.thread().key()).unwrap();
    scheduler.make_runnable(proc_b.thread().key()).unwrap();

    let records = policy.placements.lock().clone();
    assert_eq!(records.len(), 2);
    let (thread_a, process_a) = records[0];
    let (thread_b, process_b) = records[1];

    assert_ne!(
        process_a, process_b,
        "distinct processes must have distinct SchedProcessId"
    );
    assert_ne!(
        thread_a, thread_b,
        "threads across processes must have distinct SchedThreadId"
    );
}

/// Test 3: Callback reentrancy without deadlock: pick_next can safely query scheduler state
/// like snapshot_run_queue_rows() because GuestCpu lock is not held during the callback.
#[test]
fn pick_next_callback_reentrancy_without_deadlock() {
    #[derive(Debug)]
    struct ReentrantPolicy {
        scheduler_cell: parking_lot::Mutex<Option<Arc<Scheduler>>>,
        saw_rows: parking_lot::Mutex<Vec<usize>>,
    }

    impl SchedulingPolicy for ReentrantPolicy {
        fn cpu_count(&self) -> usize {
            1
        }

        fn select_cpu(&self, _placement: &TaskPlacement<'_>) -> GuestCpuId {
            GuestCpuId::new(0)
        }

        fn inspects_queues(&self) -> bool {
            true
        }

        fn pick_next(&self, view: &CpuQueueView<'_>) -> Option<SchedThreadId> {
            if let Some(sched) = self.scheduler_cell.lock().as_ref() {
                // This acquires cpu.state.lock() across all CPUs.
                // If pop_local held cpu.state.lock(), this would deadlock immediately.
                let rows = sched.snapshot_run_queue_rows();
                self.saw_rows.lock().push(rows.len());
            }
            view.queued.first().copied()
        }
    }

    let policy = Arc::new(ReentrantPolicy {
        scheduler_cell: parking_lot::Mutex::new(None),
        saw_rows: parking_lot::Mutex::new(Vec::new()),
    });

    let (kernel, ctx_a, _asids) = bootstrap_kernel(63_001);
    publish_task(&ctx_a, 500);

    let scheduler = Arc::new(Scheduler::new_with_policy(
        Arc::clone(&kernel),
        policy.clone(),
    ));
    *policy.scheduler_cell.lock() = Some(Arc::clone(&scheduler));

    let executor = scheduler
        .register_executor_bound(
            Arc::new(TestKick::default()),
            Some(GuestCpuId::new(0)),
            false,
        )
        .unwrap();

    scheduler.make_runnable(ctx_a.thread().key()).unwrap();

    let (done_tx, done_rx) = mpsc::channel();
    let sched_take = Arc::clone(&scheduler);
    thread::spawn(move || {
        let running = sched_take.take(&executor).unwrap();
        done_tx.send(running.thread_key()).unwrap();
    });

    let claimed_key = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("take must succeed without deadlock in pick_next");
    assert_eq!(claimed_key, ctx_a.thread().key());
    assert_eq!(*policy.saw_rows.lock(), vec![1]);
}

/// Test 4: Queue change during callback and stale selection fallback to FIFO head.
#[test]
fn queue_change_during_callback_and_stale_fallback_to_fifo() {
    #[derive(Debug)]
    struct StalePickPolicy {
        entered_pick: Arc<Barrier>,
        proceed_pick: Arc<Barrier>,
    }

    impl SchedulingPolicy for StalePickPolicy {
        fn cpu_count(&self) -> usize {
            1
        }

        fn select_cpu(&self, _placement: &TaskPlacement<'_>) -> GuestCpuId {
            GuestCpuId::new(0)
        }

        fn inspects_queues(&self) -> bool {
            true
        }

        fn pick_next(&self, _view: &CpuQueueView<'_>) -> Option<SchedThreadId> {
            self.entered_pick.wait();
            self.proceed_pick.wait();
            // Return a completely stale / nonexistent SchedThreadId:
            Some(SchedThreadId::new(999_999))
        }
    }

    let entered = Arc::new(Barrier::new(2));
    let proceed = Arc::new(Barrier::new(2));
    let policy = Arc::new(StalePickPolicy {
        entered_pick: Arc::clone(&entered),
        proceed_pick: Arc::clone(&proceed),
    });

    let (kernel, ctx_a, _asids) = bootstrap_kernel(64_001);
    publish_task(&ctx_a, 600);
    let ctx_b = create_sibling_thread(&kernel, &ctx_a, 64_002);
    publish_task(&ctx_b, 700);

    let scheduler = Arc::new(Scheduler::new_with_policy(Arc::clone(&kernel), policy));

    let executor = scheduler
        .register_executor_bound(
            Arc::new(TestKick::default()),
            Some(GuestCpuId::new(0)),
            false,
        )
        .unwrap();

    scheduler.make_runnable(ctx_a.thread().key()).unwrap();

    let sched_worker = Arc::clone(&scheduler);
    let (claimed_tx, claimed_rx) = mpsc::channel();
    thread::spawn(move || {
        let running = sched_worker.take(&executor).unwrap();
        claimed_tx.send(running.thread_key()).unwrap();
    });

    // Wait until pick_next is entered:
    entered.wait();

    // While pick_next is in flight, enqueue thread B:
    scheduler.make_runnable(ctx_b.thread().key()).unwrap();

    // Release pick_next to return the stale thread ID:
    proceed.wait();

    let claimed_key = claimed_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("take completed");

    // Stale selection falls back to FIFO head (ctx_a):
    assert_eq!(
        claimed_key,
        ctx_a.thread().key(),
        "stale policy selection must fall back to FIFO head"
    );

    // ctx_b remains queued:
    assert_eq!(scheduler.queued_len(), 1);
}

/// Test 5: Default FIFO policy (inspects_queues = false) never materializes queue snapshots.
#[test]
fn default_fifo_policy_never_materializes_snapshots() {
    #[derive(Debug, Default)]
    struct CountingFifoPolicy {
        inspects_called: AtomicUsize,
        pick_next_called: AtomicUsize,
        steal_called: AtomicUsize,
    }

    impl SchedulingPolicy for CountingFifoPolicy {
        fn cpu_count(&self) -> usize {
            2
        }

        fn select_cpu(&self, _placement: &TaskPlacement<'_>) -> GuestCpuId {
            GuestCpuId::new(0)
        }

        fn inspects_queues(&self) -> bool {
            self.inspects_called.fetch_add(1, Ordering::SeqCst);
            false
        }

        fn pick_next(&self, _view: &CpuQueueView<'_>) -> Option<SchedThreadId> {
            self.pick_next_called.fetch_add(1, Ordering::SeqCst);
            None
        }

        fn steal(
            &self,
            _cpu: GuestCpuId,
            _victims: &[CpuQueueView<'_>],
        ) -> Option<(GuestCpuId, SchedThreadId)> {
            self.steal_called.fetch_add(1, Ordering::SeqCst);
            None
        }
    }

    let policy = Arc::new(CountingFifoPolicy::default());
    let (kernel, ctx_a, _asids) = bootstrap_kernel(65_001);
    publish_task(&ctx_a, 800);

    let scheduler = Arc::new(Scheduler::new_with_policy(
        Arc::clone(&kernel),
        policy.clone(),
    ));

    let executor = scheduler
        .register_executor_bound(
            Arc::new(TestKick::default()),
            Some(GuestCpuId::new(0)),
            false,
        )
        .unwrap();

    scheduler.make_runnable(ctx_a.thread().key()).unwrap();
    let running = scheduler.take(&executor).unwrap();

    assert_eq!(running.thread_key(), ctx_a.thread().key());
    assert_eq!(
        policy.pick_next_called.load(Ordering::SeqCst),
        0,
        "default FIFO must never call pick_next"
    );
    assert_eq!(
        policy.steal_called.load(Ordering::SeqCst),
        0,
        "default FIFO must never call steal"
    );
}

/// Test 6: RunBudget constructor bounds and defaults.
#[test]
fn run_budget_constructor_bounds_and_defaults() {
    assert_eq!(
        RunBudget::default().quantum(),
        Duration::from_millis(4),
        "default budget is 4 ms"
    );

    assert!(RunBudget::new(Duration::from_millis(1)).is_ok());
    assert!(RunBudget::new(Duration::from_millis(100)).is_ok());

    assert!(matches!(
        RunBudget::new(Duration::from_millis(0)),
        Err(BudgetError::TooSmall { .. })
    ));
    assert!(matches!(
        RunBudget::new(Duration::from_micros(999)),
        Err(BudgetError::TooSmall { .. })
    ));
    assert!(matches!(
        RunBudget::new(Duration::from_millis(101)),
        Err(BudgetError::TooLarge { .. })
    ));
}

/// Test 7: Multiple executors bound to the same CPU running sibling threads get independent residencies and demand tickets.
#[test]
fn one_cpu_two_executors_independent_residencies() {
    let (kernel, ctx_a, _asids) = bootstrap_kernel(66_001);
    publish_task(&ctx_a, 900);
    let ctx_b = create_sibling_thread(&kernel, &ctx_a, 66_002);
    publish_task(&ctx_b, 901);

    let scheduler = Arc::new(Scheduler::new(kernel));
    let kick_a = Arc::new(TestKick::default());
    let kick_b = Arc::new(TestKick::default());

    let exec_a = scheduler
        .register_executor_bound(kick_a, Some(GuestCpuId::new(0)), false)
        .unwrap();
    let exec_b = scheduler
        .register_executor_bound(kick_b, Some(GuestCpuId::new(0)), false)
        .unwrap();

    scheduler.make_runnable(ctx_a.thread().key()).unwrap();
    scheduler.make_runnable(ctx_b.thread().key()).unwrap();

    let running_a = scheduler.take(&exec_a).unwrap();
    let running_b = scheduler.take(&exec_b).unwrap();

    let res_a = scheduler
        .binding_residency(exec_a.id())
        .expect("residency for exec_a must exist");
    let res_b = scheduler
        .binding_residency(exec_b.id())
        .expect("residency for exec_b must exist");

    assert_eq!(res_a.cpu, GuestCpuId::new(0));
    assert_eq!(res_b.cpu, GuestCpuId::new(0));
    assert_ne!(res_a.binding, res_b.binding);
    assert_ne!(
        res_a.ticket, res_b.ticket,
        "two executors on the same CPU must receive independent demand tickets"
    );

    scheduler.settle_runnable(running_a).unwrap();
    scheduler.settle_runnable(running_b).unwrap();
}

/// Test 8: Setting and clearing fairness preemption reason does not clear concurrent signal reason.
#[test]
fn pending_signal_plus_fairness_isolation() {
    let (kernel, ctx_a, _asids) = bootstrap_kernel(67_001);
    publish_task(&ctx_a, 950);

    let scheduler = Arc::new(Scheduler::new(kernel));
    let kick = Arc::new(TestKick::default());
    let exec = scheduler
        .register_executor_bound(kick, Some(GuestCpuId::new(0)), false)
        .unwrap();

    scheduler.make_runnable(ctx_a.thread().key()).unwrap();
    let running = scheduler.take(&exec).unwrap();

    // Initially no preemption reasons:
    assert!(!scheduler.should_preempt(&running));

    // Add both SIGNAL and FAIRNESS:
    assert!(scheduler.set_preemption_reason(
        exec.id(),
        PreemptionReasons::SIGNAL | PreemptionReasons::FAIRNESS,
    ));

    let snap = scheduler.binding_residency(exec.id()).unwrap();
    assert!(snap.reasons.contains(PreemptionReasons::SIGNAL));
    assert!(snap.reasons.contains(PreemptionReasons::FAIRNESS));
    assert!(scheduler.should_preempt(&running));

    // Clear FAIRNESS only:
    assert!(scheduler.clear_preemption_reason(exec.id(), PreemptionReasons::FAIRNESS));

    let snap = scheduler.binding_residency(exec.id()).unwrap();
    assert!(
        snap.reasons.contains(PreemptionReasons::SIGNAL),
        "SIGNAL reason must survive clearing of FAIRNESS"
    );
    assert!(
        !snap.reasons.contains(PreemptionReasons::FAIRNESS),
        "FAIRNESS reason must be cleared"
    );
    assert!(
        scheduler.should_preempt(&running),
        "should_preempt must still be true due to surviving SIGNAL reason"
    );

    scheduler.settle_runnable(running).unwrap();
}

/// Test 9: 10,000 uncontended syscall steps retain residency without kicks or preemption.
#[test]
fn uncontended_syscall_steps_retain_residency() {
    let (kernel, ctx_a, _asids) = bootstrap_kernel(68_001);
    publish_task(&ctx_a, 980);

    let scheduler = Arc::new(Scheduler::new(kernel));
    let kick = Arc::new(TestKick::default());
    let exec = scheduler
        .register_executor_bound(kick.clone(), Some(GuestCpuId::new(0)), false)
        .unwrap();

    scheduler.make_runnable(ctx_a.thread().key()).unwrap();
    let running = scheduler.take(&exec).unwrap();

    for _ in 0..10_000 {
        scheduler.note_syscall_boundary(&running);
        assert!(
            !scheduler.should_preempt(&running),
            "uncontended syscall must never trigger preemption"
        );
        assert!(!scheduler.need_resched());
    }

    assert_eq!(
        kick.tokens.lock().len(),
        0,
        "uncontended loop must receive zero kicks"
    );
    assert!(!kick.kicked.load(Ordering::Acquire));

    scheduler.settle_runnable(running).unwrap();
}

/// Test 10: Timeline: A starts at 0; B queues at 1 ms -> One request due at 4 ms.
#[test]
fn timeline_a_starts_0_b_queues_1ms_due_at_4ms() {
    let t0 = Instant::now();
    let clock = Arc::new(ManualClock::new(t0));
    let (kernel, ctx_a, scheduler, _asids) = bootstrap_kernel_with_clock(70_001, clock.clone());
    clock.attach_condvar(scheduler.preemption_condvar());
    publish_task(&ctx_a, 1001);
    let ctx_b = create_sibling_thread(&kernel, &ctx_a, 70_002);
    publish_task(&ctx_b, 1002);

    let kick_a = Arc::new(TestKick::default());
    let exec_a = scheduler
        .register_executor_bound(kick_a, Some(GuestCpuId::new(0)), false)
        .unwrap();

    scheduler.make_runnable(ctx_a.thread().key()).unwrap();
    let running_a = scheduler.take(&exec_a).unwrap();
    assert_eq!(
        scheduler.live_deadline_count(),
        0,
        "uncontended residency has no deadline"
    );

    clock.advance(Duration::from_millis(1));
    scheduler.make_runnable(ctx_b.thread().key()).unwrap();

    assert!(scheduler.has_deadline(exec_a.id()));
    assert_eq!(
        scheduler.deadline_for(exec_a.id()),
        Some(t0 + Duration::from_millis(4))
    );
    assert_eq!(scheduler.live_deadline_count(), 1);

    clock.advance(Duration::from_millis(2)); // t = 3 ms
    assert!(
        scheduler.poll_due_preemption_requests().is_empty(),
        "deadline at 4 ms must not be due at 3 ms"
    );

    clock.advance(Duration::from_millis(1)); // t = 4 ms
    let due = scheduler.poll_due_preemption_requests();
    assert_eq!(due.len(), 1, "exactly one request due at 4 ms");
    assert_eq!(due[0].binding.executor(), exec_a.id());
    assert!(due[0].reasons.contains(PreemptionReasons::FAIRNESS));

    scheduler.settle_runnable(running_a).unwrap();
}

/// Test 11: Timeline: A starts at 0; B queues at 20 ms -> A immediately eligible for one request.
#[test]
fn timeline_a_starts_0_b_queues_20ms_immediately_eligible() {
    let t0 = Instant::now();
    let clock = Arc::new(ManualClock::new(t0));
    let (kernel, ctx_a, scheduler, _asids) = bootstrap_kernel_with_clock(71_001, clock.clone());
    publish_task(&ctx_a, 1101);
    let ctx_b = create_sibling_thread(&kernel, &ctx_a, 71_002);
    publish_task(&ctx_b, 1102);

    let kick_a = Arc::new(TestKick::default());
    let exec_a = scheduler
        .register_executor_bound(kick_a, Some(GuestCpuId::new(0)), false)
        .unwrap();

    scheduler.make_runnable(ctx_a.thread().key()).unwrap();
    let running_a = scheduler.take(&exec_a).unwrap();

    clock.advance(Duration::from_millis(20));
    assert!(
        scheduler.poll_due_preemption_requests().is_empty(),
        "no requests before contention"
    );

    scheduler.make_runnable(ctx_b.thread().key()).unwrap();
    let due = scheduler.poll_due_preemption_requests();
    assert_eq!(
        due.len(),
        1,
        "A is immediately eligible for one preemption request"
    );
    assert_eq!(due[0].binding.executor(), exec_a.id());
    assert!(due[0].reasons.contains(PreemptionReasons::FAIRNESS));

    assert!(
        scheduler.poll_due_preemption_requests().is_empty(),
        "one due claim produces at most one delivery"
    );

    scheduler.settle_runnable(running_a).unwrap();
}

/// Test 12: Timeline: More wakes at 2 and 3 ms do not extend original 4 ms deadline.
#[test]
fn timeline_more_wakes_do_not_extend_deadline() {
    let t0 = Instant::now();
    let clock = Arc::new(ManualClock::new(t0));
    let (kernel, ctx_a, scheduler, _asids) = bootstrap_kernel_with_clock(72_001, clock.clone());
    publish_task(&ctx_a, 1201);
    let ctx_b = create_sibling_thread(&kernel, &ctx_a, 72_002);
    publish_task(&ctx_b, 1202);
    let ctx_c = create_sibling_thread(&kernel, &ctx_a, 72_003);
    publish_task(&ctx_c, 1203);
    let ctx_d = create_sibling_thread(&kernel, &ctx_a, 72_004);
    publish_task(&ctx_d, 1204);

    let kick_a = Arc::new(TestKick::default());
    let exec_a = scheduler
        .register_executor_bound(kick_a, Some(GuestCpuId::new(0)), false)
        .unwrap();

    scheduler.make_runnable(ctx_a.thread().key()).unwrap();
    let running_a = scheduler.take(&exec_a).unwrap();

    clock.advance(Duration::from_millis(1));
    scheduler.make_runnable(ctx_b.thread().key()).unwrap();
    assert_eq!(
        scheduler.deadline_for(exec_a.id()),
        Some(t0 + Duration::from_millis(4))
    );

    clock.advance(Duration::from_millis(1)); // t = 2 ms
    scheduler.make_runnable(ctx_c.thread().key()).unwrap();
    assert_eq!(
        scheduler.deadline_for(exec_a.id()),
        Some(t0 + Duration::from_millis(4)),
        "wake at 2 ms must not extend deadline"
    );

    clock.advance(Duration::from_millis(1)); // t = 3 ms
    scheduler.make_runnable(ctx_d.thread().key()).unwrap();
    assert_eq!(
        scheduler.deadline_for(exec_a.id()),
        Some(t0 + Duration::from_millis(4)),
        "wake at 3 ms must not extend deadline"
    );
    assert!(scheduler.poll_due_preemption_requests().is_empty());

    clock.advance(Duration::from_millis(1)); // t = 4 ms
    let due = scheduler.poll_due_preemption_requests();
    assert_eq!(
        due.len(),
        1,
        "exactly one request due at original 4 ms deadline"
    );

    scheduler.settle_runnable(running_a).unwrap();
}

/// Test 13: Timeline: B claimed by idle executor before expiry cancels unclaimed deadline.
#[test]
fn timeline_b_claimed_by_idle_executor_cancels_unclaimed_deadline() {
    let t0 = Instant::now();
    let clock = Arc::new(ManualClock::new(t0));
    let (kernel, ctx_a, scheduler, _asids) = bootstrap_kernel_with_clock(73_001, clock.clone());
    publish_task(&ctx_a, 1301);
    let ctx_b = create_sibling_thread(&kernel, &ctx_a, 73_002);
    publish_task(&ctx_b, 1302);

    let kick_a = Arc::new(TestKick::default());
    let kick_b = Arc::new(TestKick::default());
    let exec_a = scheduler
        .register_executor_bound(kick_a, Some(GuestCpuId::new(0)), false)
        .unwrap();
    let exec_b = scheduler
        .register_executor_bound(kick_b, Some(GuestCpuId::new(0)), false)
        .unwrap();

    scheduler.make_runnable(ctx_a.thread().key()).unwrap();
    let running_a = scheduler.take(&exec_a).unwrap();

    clock.advance(Duration::from_millis(1));
    scheduler.make_runnable(ctx_b.thread().key()).unwrap();
    assert!(scheduler.has_deadline(exec_a.id()));
    assert_eq!(scheduler.live_deadline_count(), 1);

    clock.advance(Duration::from_millis(1)); // t = 2 ms
    let running_b = scheduler.take(&exec_b).unwrap(); // B claimed by idle executor
    assert!(
        !scheduler.has_deadline(exec_a.id()),
        "claiming demand must eagerly cancel unclaimed deadline on A"
    );
    assert_eq!(scheduler.live_deadline_count(), 0);

    clock.advance(Duration::from_millis(2)); // t = 4 ms
    assert!(
        scheduler.poll_due_preemption_requests().is_empty(),
        "no request should fire after deadline was cancelled"
    );

    scheduler.settle_runnable(running_a).unwrap();
    scheduler.settle_runnable(running_b).unwrap();
}

/// Test 14: Timeline: B only allows CPU 0; CPU 1 is busy -> never kick CPU 1 for B.
#[test]
fn timeline_affinity_constrained_contender_never_kicks_ineligible_cpu() {
    let t0 = Instant::now();
    let clock = Arc::new(ManualClock::new(t0));
    let (kernel, ctx_a, scheduler, _asids) = bootstrap_kernel_with_clock(74_001, clock.clone());
    publish_task(&ctx_a, 1401);
    let ctx_b = create_sibling_thread(&kernel, &ctx_a, 74_002);
    publish_task(&ctx_b, 1402);

    let kick_1 = Arc::new(TestKick::default());
    let exec_1 = scheduler
        .register_executor_bound(kick_1.clone(), Some(GuestCpuId::new(1)), false)
        .unwrap();

    scheduler.make_runnable(ctx_a.thread().key()).unwrap();
    let running_a = scheduler.take(&exec_1).unwrap();

    // B only allows CPU 0
    ctx_b
        .thread()
        .set_affinity(CpuAffinity::single(GuestCpuId::new(0)));

    clock.advance(Duration::from_millis(1));
    scheduler.make_runnable(ctx_b.thread().key()).unwrap();

    assert!(
        !scheduler.has_deadline(exec_1.id()),
        "ineligible CPU 1 must not receive a deadline for CPU 0 demand"
    );

    clock.advance(Duration::from_millis(10));
    assert!(
        scheduler.poll_due_preemption_requests().is_empty(),
        "ineligible CPU 1 must never be queued for preemption"
    );
    assert!(!kick_1.kicked.load(Ordering::SeqCst));

    scheduler.settle_runnable(running_a).unwrap();
}

/// Test 15: Timeline: One contender, several busy executors on CPU 0 -> selects one oldest eligible residency.
#[test]
fn timeline_one_contender_several_busy_executors_selects_oldest() {
    let t0 = Instant::now();
    let clock = Arc::new(ManualClock::new(t0));
    let (kernel, ctx_a1, scheduler, _asids) = bootstrap_kernel_with_clock(75_001, clock.clone());
    publish_task(&ctx_a1, 1501);
    let ctx_a2 = create_sibling_thread(&kernel, &ctx_a1, 75_002);
    publish_task(&ctx_a2, 1502);
    let ctx_b = create_sibling_thread(&kernel, &ctx_a1, 75_003);
    publish_task(&ctx_b, 1503);

    let kick_1 = Arc::new(TestKick::default());
    let kick_2 = Arc::new(TestKick::default());
    let exec_1 = scheduler
        .register_executor_bound(kick_1, Some(GuestCpuId::new(0)), false)
        .unwrap();
    let exec_2 = scheduler
        .register_executor_bound(kick_2, Some(GuestCpuId::new(0)), false)
        .unwrap();

    scheduler.make_runnable(ctx_a1.thread().key()).unwrap();
    let running_1 = scheduler.take(&exec_1).unwrap(); // starts at t = 0 ms

    clock.advance(Duration::from_millis(1)); // t = 1 ms
    scheduler.make_runnable(ctx_a2.thread().key()).unwrap();
    let running_2 = scheduler.take(&exec_2).unwrap(); // starts at t = 1 ms

    clock.advance(Duration::from_millis(1)); // t = 2 ms
    scheduler.make_runnable(ctx_b.thread().key()).unwrap(); // 1 contender queues

    assert!(
        scheduler.has_deadline(exec_1.id()),
        "oldest residency must be selected for single contender"
    );
    assert!(
        !scheduler.has_deadline(exec_2.id()),
        "newer residency must NOT receive deadline when demand is 1"
    );
    assert_eq!(scheduler.live_deadline_count(), 1);

    scheduler.settle_runnable(running_1).unwrap();
    scheduler.settle_runnable(running_2).unwrap();
}

/// Test 16: Timeline: Demand disappears after delivery claim -> at most one extra exit of the same binding.
#[test]
fn timeline_demand_disappears_after_delivery_claim_at_most_one_extra_exit() {
    let t0 = Instant::now();
    let clock = Arc::new(ManualClock::new(t0));
    let (kernel, ctx_a, scheduler, _asids) = bootstrap_kernel_with_clock(76_001, clock.clone());
    publish_task(&ctx_a, 1601);
    let ctx_b = create_sibling_thread(&kernel, &ctx_a, 76_002);
    publish_task(&ctx_b, 1602);

    let kick_a = Arc::new(TestKick::default());
    let exec_a = scheduler
        .register_executor_bound(kick_a.clone(), Some(GuestCpuId::new(0)), false)
        .unwrap();

    scheduler.make_runnable(ctx_a.thread().key()).unwrap();
    let running_a = scheduler.take(&exec_a).unwrap();

    clock.advance(Duration::from_millis(1));
    scheduler.make_runnable(ctx_b.thread().key()).unwrap();

    clock.advance(Duration::from_millis(3)); // t = 4 ms
    let delivered = scheduler.request_preemption();
    assert_eq!(delivered, 1);
    assert_eq!(kick_a.tokens.lock().len(), 1);

    // Subsequent poll/request should be 0 because demand was claimed:
    assert!(scheduler.poll_due_preemption_requests().is_empty());
    assert_eq!(
        scheduler.request_preemption(),
        0,
        "demand claimed once must not deliver multiple times"
    );

    scheduler.settle_runnable(running_a).unwrap();
}

/// Test 17: Timeline: Deadline fires after exec/unbind -> no successor receives that request.
#[test]
fn timeline_deadline_fires_after_exec_unbind_no_successor() {
    let t0 = Instant::now();
    let clock = Arc::new(ManualClock::new(t0));
    let (kernel, ctx_a, scheduler, _asids) = bootstrap_kernel_with_clock(77_001, clock.clone());
    publish_task(&ctx_a, 1701);
    let ctx_b = create_sibling_thread(&kernel, &ctx_a, 77_002);
    publish_task(&ctx_b, 1702);

    let kick_a = Arc::new(TestKick::default());
    let exec_a = scheduler
        .register_executor_bound(kick_a.clone(), Some(GuestCpuId::new(0)), false)
        .unwrap();

    scheduler.make_runnable(ctx_a.thread().key()).unwrap();
    let running_a = scheduler.take(&exec_a).unwrap();
    let old_binding = running_a.binding();

    clock.advance(Duration::from_millis(1));
    scheduler.make_runnable(ctx_b.thread().key()).unwrap();
    assert!(scheduler.has_deadline(exec_a.id()));

    // At 2 ms, task unbinds / execs:
    clock.advance(Duration::from_millis(1)); // t = 2 ms
    scheduler.settle_exited(running_a).unwrap();
    kick_a.unbind(old_binding);

    // At 4 ms, deadline fires:
    clock.advance(Duration::from_millis(2)); // t = 4 ms
    let stale_req = PreemptionRequest {
        binding: old_binding,
        ticket: DemandTicket(0),
        reasons: PreemptionReasons::FAIRNESS,
        cpu: GuestCpuId::new(0),
    };
    let outcome = scheduler.deliver_preemption(stale_req);
    assert_eq!(outcome, DeliveryOutcome::Stale);
    assert!(
        kick_a.tokens.lock().is_empty(),
        "unbound/successor executor must not receive kick for stale binding"
    );
}

/// Test 18: Cost assertions: live deadline entries <= live execution slots; parked noncompetitors add zero fairness work; FIFO rotation.
#[test]
fn cost_assertions_and_fifo_rotation() {
    for slots in [1, 2, 4] {
        for n in [1, 8, 32, 128] {
            let clock = Arc::new(ManualClock::new(Instant::now()));
            let policy = Arc::new(GuestCpuPolicy::new(1));
            let (kernel, root, scheduler, _asids) = bootstrap_kernel_with_policy_and_clock(
                78_000 + (slots * 1000 + n) as i32,
                policy,
                clock.clone(),
            );
            clock.attach_condvar(scheduler.preemption_condvar());
            publish_task(&root, 18_000);

            let mut executors = Vec::new();
            for _ in 0..slots {
                let kick = Arc::new(TestKick::default());
                let exec = scheduler
                    .register_executor_bound(kick, Some(GuestCpuId::new(0)), false)
                    .unwrap();
                executors.push(exec);
            }

            let mut threads = vec![root.thread().key()];
            for i in 1..n {
                let sibling = create_sibling_thread(
                    &kernel,
                    &root,
                    78_000 + (slots * 1000 + n) as i32 + i as i32,
                );
                publish_task(&sibling, 18_000 + i as u64);
                threads.push(sibling.thread().key());
            }

            for key in &threads {
                scheduler.make_runnable(*key).unwrap();
            }

            // Invariant 1: live deadline entries <= live execution slots
            assert!(
                scheduler.live_deadline_count() <= slots,
                "deadlines {} must not exceed live execution slots {}",
                scheduler.live_deadline_count(),
                slots
            );

            // Run a rotation:
            let mut running_threads = Vec::new();
            for exec in &executors {
                if scheduler.queued_len() > 0
                    && let Ok(runnable) = scheduler.take(exec)
                {
                    running_threads.push(runnable);
                }
            }

            assert!(
                scheduler.live_deadline_count() <= slots,
                "deadlines {} must not exceed slots {} after take",
                scheduler.live_deadline_count(),
                slots
            );

            // Advance clock by quantum to trigger preemption eligibility:
            clock.advance(Duration::from_millis(4));

            let due = scheduler.poll_due_preemption_requests();
            assert!(
                due.len() <= slots,
                "due requests {} cannot exceed live execution slots {}",
                due.len(),
                slots
            );

            // Settle all running threads
            for r in running_threads {
                scheduler.settle_runnable(r).unwrap();
            }

            // Drain queue without blocking
            while scheduler.queued_len() > 0 {
                let r = scheduler.take(&executors[0]).unwrap();
                scheduler.settle_exited(r).unwrap();
            }

            // Invariant 2: when queue is drained, parked noncompetitors add zero fairness work
            assert_eq!(
                scheduler.live_deadline_count(),
                0,
                "drained queue must have 0 live deadlines"
            );
            assert!(
                scheduler.poll_due_preemption_requests().is_empty(),
                "drained queue must have 0 due requests"
            );
        }
    }
}

/// Test 19: Custom quantum policy: policy returning 10 ms quantum sets 10 ms deadline, not 4 ms.
#[test]
fn custom_quantum_policy_sets_10ms_deadline() {
    #[derive(Debug)]
    struct CustomQuantumPolicy {
        base: GuestCpuPolicy,
    }

    impl SchedulingPolicy for CustomQuantumPolicy {
        fn cpu_count(&self) -> usize {
            self.base.cpu_count()
        }

        fn select_cpu(&self, placement: &TaskPlacement<'_>) -> GuestCpuId {
            self.base.select_cpu(placement)
        }

        fn on_dispatch(&self, _ctx: &DispatchContext) -> RunBudget {
            RunBudget::new(Duration::from_millis(10)).unwrap()
        }
    }

    let t0 = Instant::now();
    let clock = Arc::new(ManualClock::new(t0));
    let policy = Arc::new(CustomQuantumPolicy {
        base: GuestCpuPolicy::new(carrick_hal::MAX_GUEST_CPUS),
    });
    let (kernel, ctx_a, scheduler, _asids) =
        bootstrap_kernel_with_policy_and_clock(79_001, policy, clock.clone());
    publish_task(&ctx_a, 1901);
    let ctx_b = create_sibling_thread(&kernel, &ctx_a, 79_002);
    publish_task(&ctx_b, 1902);

    let kick_a = Arc::new(TestKick::default());
    let exec_a = scheduler
        .register_executor_bound(kick_a, Some(GuestCpuId::new(0)), false)
        .unwrap();

    scheduler.make_runnable(ctx_a.thread().key()).unwrap();
    let running_a = scheduler.take(&exec_a).unwrap();

    clock.advance(Duration::from_millis(1));
    scheduler.make_runnable(ctx_b.thread().key()).unwrap();

    assert_eq!(
        scheduler.deadline_for(exec_a.id()),
        Some(t0 + Duration::from_millis(10)),
        "custom policy must schedule 10 ms deadline"
    );

    clock.advance(Duration::from_millis(8)); // t = 9 ms
    assert!(scheduler.poll_due_preemption_requests().is_empty());

    clock.advance(Duration::from_millis(1)); // t = 10 ms
    let due = scheduler.poll_due_preemption_requests();
    assert_eq!(due.len(), 1, "request due at 10 ms");

    scheduler.settle_runnable(running_a).unwrap();
}

/// Test 20: Threaded driver: wait_preemption_work wakes on manual clock advance without wall-clock sleep.
#[test]
fn threaded_driver_wait_preemption_work_wakes_on_manual_clock_advance() {
    let t0 = Instant::now();
    let clock = Arc::new(ManualClock::new(t0));
    let (kernel, ctx_a, scheduler, _asids) = bootstrap_kernel_with_clock(80_001, clock.clone());
    clock.attach_condvar(scheduler.preemption_condvar());
    publish_task(&ctx_a, 2001);
    let ctx_b = create_sibling_thread(&kernel, &ctx_a, 80_002);
    publish_task(&ctx_b, 2002);

    let kick_a = Arc::new(TestKick::default());
    let exec_a = scheduler
        .register_executor_bound(kick_a, Some(GuestCpuId::new(0)), false)
        .unwrap();

    scheduler.make_runnable(ctx_a.thread().key()).unwrap();
    let running_a = scheduler.take(&exec_a).unwrap();

    clock.advance(Duration::from_millis(1));
    scheduler.make_runnable(ctx_b.thread().key()).unwrap();

    // Spawn driver thread waiting on wait_preemption_work
    let sched_clone = Arc::clone(&scheduler);
    let (tx, rx) = mpsc::channel();
    let driver_handle = thread::spawn(move || {
        let work = sched_clone.wait_preemption_work();
        tx.send(work).unwrap();
    });

    // Advance clock to 4 ms. This notifies the condvar via attach_condvar and wakes the driver thread!
    clock.advance(Duration::from_millis(3));

    let work = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("driver thread must wake up on clock advance");
    match work {
        PreemptionWork::Due(requests) => {
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].binding.executor(), exec_a.id());
        }
        PreemptionWork::Shutdown => panic!("expected Due, got Shutdown"),
    }

    driver_handle.join().unwrap();
    scheduler.settle_runnable(running_a).unwrap();
}
