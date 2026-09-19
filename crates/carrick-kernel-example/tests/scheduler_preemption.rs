#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::Duration;

use carrick_abi::LinuxCloneFlags;
use carrick_hal::NullHostSignalBridge;
use carrick_hal::threaded::{Aarch64TaskCpuStateV1, GuestCpuState};
use carrick_hal::{
    BudgetError, CpuQueueView, GuestCpuId, RunBudget, SchedProcessId, SchedThreadId,
    SchedulingPolicy, TaskPlacement, ThreadId,
};
use carrick_kernel::kernel::objects::MigratableTaskState;
use carrick_kernel::kernel::scheduler::PreemptionReasons;
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
