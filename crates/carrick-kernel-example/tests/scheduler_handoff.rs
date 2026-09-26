#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::Duration;

use carrick_abi::LinuxCloneFlags;
use carrick_hal::NullHostSignalBridge;
use carrick_hal::threaded::{Aarch64TaskCpuStateV1, GuestCpuState};
use carrick_hal::{CpuAffinity, GuestCpuId, GuestCpuPolicy, ThreadId};
use carrick_kernel::kernel::objects::MigratableTaskState;
use carrick_kernel::kernel::{
    ClonePlan, ExecutorBinding, ExecutorKick, ExecutorKickToken, Kernel, KernelContext,
    RunQueueError, Scheduler, SchedulerError, WakeDisposition,
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

impl TestKick {
    fn wait_for_kick(&self) {
        let mut tokens = self.tokens.lock();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while tokens.is_empty() {
            if self.changed.wait_until(&mut tokens, deadline).timed_out() {
                assert!(
                    !tokens.is_empty(),
                    "returning owner must kick the active replacement"
                );
            }
        }
    }
}

fn bootstrap_kernel(pid: i32) -> (Arc<Kernel>, KernelContext, Arc<AsidAllocator>) {
    let asids = Arc::new(AsidAllocator::new());
    let space = AddressSpace::allocate(&asids).expect("allocate space");
    let (_process, root) = ExampleProcess::boot_root(
        pid,
        "scheduler handoff test",
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

/// Test 1: Sibling thread handoff.
/// One guest CPU (P0), M1 bound to P0 holding Task A, M2 registered as spare.
/// Task B is a runnable sibling thread.
/// While Task A waits in a host operation, Task B progresses on P0 via spare M2.
#[test]
fn host_wait_handoff_sibling_thread_progresses_on_spare() {
    let (kernel, root_context, _asids) = bootstrap_kernel(50_001);
    publish_task(&root_context, 100);

    let sibling_context = create_sibling_thread(&kernel, &root_context, 50_002);
    publish_task(&sibling_context, 200);

    let scheduler = Arc::new(Scheduler::new_with_policy(
        Arc::clone(&kernel),
        Arc::new(GuestCpuPolicy::new(1)),
    ));

    let m1_kick = Arc::new(TestKick::default());
    let m1_reg = scheduler
        .register_executor_bound(m1_kick, Some(GuestCpuId::new(0)), false)
        .expect("register m1");

    let m2_kick = Arc::new(TestKick::default());
    let m2_reg = scheduler
        .register_executor_bound(m2_kick, None, true)
        .expect("register m2");

    assert_eq!(
        scheduler
            .make_runnable(root_context.thread().key())
            .unwrap(),
        WakeDisposition::Queued
    );

    let running_a = scheduler.take(&m1_reg).expect("m1 takes task a");
    assert_eq!(running_a.thread_key(), root_context.thread().key());
    assert_eq!(running_a.guest_cpu(), GuestCpuId::new(0));

    assert_eq!(
        scheduler
            .make_runnable(sibling_context.thread().key())
            .unwrap(),
        WakeDisposition::Queued
    );

    let token = scheduler
        .begin_host_wait(&running_a, &m1_reg)
        .expect("begin host wait on m1");
    assert!(token.is_active());
    assert_eq!(token.cpu(), GuestCpuId::new(0));

    let (tx, rx) = mpsc::channel();
    let s_clone = Arc::clone(&scheduler);
    let m2_reg_clone = m2_reg.clone();
    let sibling_thread_key = sibling_context.thread().key();

    let m2_handle = thread::spawn(move || {
        let running_b = s_clone
            .take(&m2_reg_clone)
            .expect("spare m2 takes task b during handoff");
        assert_eq!(running_b.thread_key(), sibling_thread_key);
        assert_eq!(running_b.guest_cpu(), GuestCpuId::new(0));
        let census = s_clone
            .host_wait_census()
            .expect("uncontended live ownership");
        assert_eq!(census.slots.len(), 1);
        assert_eq!(census.slots[0].owner, Some(m2_reg_clone.id()));
        assert_eq!(census.slots[0].waiters.len(), 1);
        assert_eq!(census.entered, 1);
        assert_eq!(census.resumed, 0);
        s_clone.settle_exited(running_b).expect("settle task b");
        tx.send(()).expect("send completion");
    });

    rx.recv_timeout(Duration::from_secs(5))
        .expect("task B must progress and finish on spare M2 while M1 waits");
    m2_handle.join().expect("join m2");

    scheduler
        .end_host_wait(&running_a, &m1_reg, token)
        .expect("end host wait on m1");

    scheduler.settle_exited(running_a).expect("settle task a");
}

/// Test 2: Separate-process child handoff.
/// One guest CPU (P0), M1 bound to P0 holding Task A (parent process), M2 spare.
/// Task B is a separate-process child created via reserve_fork -> prepare_with_mm_backend -> commit.
/// While Task A is in host wait, child Task B progresses on P0 via spare M2.
#[test]
fn host_wait_handoff_separate_process_child_progresses_on_spare() {
    let (kernel, parent_context, asids) = bootstrap_kernel(51_001);
    publish_task(&parent_context, 1000);

    let (child_context, _child_process) =
        create_forked_child(&kernel, &parent_context, &asids, "child-proc-51002");
    publish_task(&child_context, 2000);

    let scheduler = Arc::new(Scheduler::new_with_policy(
        Arc::clone(&kernel),
        Arc::new(GuestCpuPolicy::new(1)),
    ));

    let m1_kick = Arc::new(TestKick::default());
    let m1_reg = scheduler
        .register_executor_bound(m1_kick, Some(GuestCpuId::new(0)), false)
        .expect("register m1");

    let m2_kick = Arc::new(TestKick::default());
    let m2_reg = scheduler
        .register_executor_bound(m2_kick, None, true)
        .expect("register m2");

    assert_eq!(
        scheduler
            .make_runnable(parent_context.thread().key())
            .unwrap(),
        WakeDisposition::Queued
    );

    let running_parent = scheduler.take(&m1_reg).expect("m1 takes parent task");
    assert_eq!(running_parent.thread_key(), parent_context.thread().key());

    assert_eq!(
        scheduler
            .make_runnable(child_context.thread().key())
            .unwrap(),
        WakeDisposition::Queued
    );

    let token = scheduler
        .begin_host_wait(&running_parent, &m1_reg)
        .expect("begin host wait on parent");

    let (tx, rx) = mpsc::channel();
    let s_clone = Arc::clone(&scheduler);
    let m2_reg_clone = m2_reg.clone();
    let child_thread_key = child_context.thread().key();

    let m2_handle = thread::spawn(move || {
        let running_child = s_clone
            .take(&m2_reg_clone)
            .expect("spare m2 takes child process task");
        assert_eq!(running_child.thread_key(), child_thread_key);
        assert_eq!(running_child.guest_cpu(), GuestCpuId::new(0));
        s_clone
            .settle_exited(running_child)
            .expect("settle child task");
        tx.send(()).expect("send completion");
    });

    rx.recv_timeout(Duration::from_secs(5))
        .expect("child task must progress and finish on spare M2 while parent waits");
    m2_handle.join().expect("join m2");

    scheduler
        .end_host_wait(&running_parent, &m1_reg, token)
        .expect("end host wait on parent");

    scheduler
        .settle_exited(running_parent)
        .expect("settle parent task");
}

/// Test 3: No spare registered; P remains vacant during host wait and resumes immediately.
#[test]
fn host_wait_handoff_no_spare_vacant_and_resumes() {
    let (kernel, root_context, _asids) = bootstrap_kernel(52_001);
    publish_task(&root_context, 300);

    let scheduler = Arc::new(Scheduler::new_with_policy(
        Arc::clone(&kernel),
        Arc::new(GuestCpuPolicy::new(1)),
    ));

    let m1_kick = Arc::new(TestKick::default());
    let m1_reg = scheduler
        .register_executor_bound(m1_kick, Some(GuestCpuId::new(0)), false)
        .expect("register m1");

    assert_eq!(
        scheduler
            .make_runnable(root_context.thread().key())
            .unwrap(),
        WakeDisposition::Queued
    );

    let running_a = scheduler.take(&m1_reg).expect("m1 takes task a");

    let token = scheduler
        .begin_host_wait(&running_a, &m1_reg)
        .expect("begin host wait");
    assert!(token.is_active());

    scheduler
        .end_host_wait(&running_a, &m1_reg, token)
        .expect("end host wait immediately");

    scheduler.settle_exited(running_a).expect("settle task a");
}

/// Test 4: Affinity pinned placement.
/// 2 CPUs (P0, P1). M1 on P0, M_p1 on P1, M_spare spare.
/// Task B is pinned specifically to P0.
/// While M1 waits on P0, spare M_spare runs Task B on P0.
#[test]
fn host_wait_handoff_affinity_pinned_placement() {
    let (kernel, root_context, _asids) = bootstrap_kernel(53_001);
    publish_task(&root_context, 400);

    let sibling_b = create_sibling_thread(&kernel, &root_context, 53_002);
    publish_task(&sibling_b, 401);
    sibling_b
        .thread()
        .set_affinity(CpuAffinity::single(GuestCpuId::new(0)));

    let scheduler = Arc::new(Scheduler::new_with_policy(
        Arc::clone(&kernel),
        Arc::new(GuestCpuPolicy::new(2)),
    ));

    let m1_kick = Arc::new(TestKick::default());
    let m1_reg = scheduler
        .register_executor_bound(m1_kick, Some(GuestCpuId::new(0)), false)
        .expect("register m1 on p0");

    let m_p1_kick = Arc::new(TestKick::default());
    let _m_p1_reg = scheduler
        .register_executor_bound(m_p1_kick, Some(GuestCpuId::new(1)), false)
        .expect("register m_p1 on p1");

    let m_spare_kick = Arc::new(TestKick::default());
    let m_spare_reg = scheduler
        .register_executor_bound(m_spare_kick, None, true)
        .expect("register spare");

    assert_eq!(
        scheduler
            .make_runnable(root_context.thread().key())
            .unwrap(),
        WakeDisposition::Queued
    );

    let running_a = scheduler.take(&m1_reg).expect("m1 takes task a");
    assert_eq!(running_a.guest_cpu(), GuestCpuId::new(0));

    assert_eq!(
        scheduler.make_runnable(sibling_b.thread().key()).unwrap(),
        WakeDisposition::Queued
    );

    let token = scheduler
        .begin_host_wait(&running_a, &m1_reg)
        .expect("begin host wait on m1");

    let (tx, rx) = mpsc::channel();
    let s_clone = Arc::clone(&scheduler);
    let m_spare_reg_clone = m_spare_reg.clone();
    let sibling_b_key = sibling_b.thread().key();

    let spare_handle = thread::spawn(move || {
        let running_b = s_clone
            .take(&m_spare_reg_clone)
            .expect("spare takes pinned task b");
        assert_eq!(running_b.thread_key(), sibling_b_key);
        assert_eq!(running_b.guest_cpu(), GuestCpuId::new(0));
        s_clone.settle_exited(running_b).expect("settle task b");
        tx.send(()).expect("send completion");
    });

    rx.recv_timeout(Duration::from_secs(5))
        .expect("pinned task B must progress on spare on P0");
    spare_handle.join().expect("join spare");

    scheduler
        .end_host_wait(&running_a, &m1_reg, token)
        .expect("end host wait on m1");

    scheduler.settle_exited(running_a).expect("settle task a");
}

/// Test 5: Nested handoffs and ancestor returning before descendant.
/// M1 on P0 enters host wait for Task A.
/// M2 (spare 1) claims P0 and starts Task B.
/// While running Task B, M2 enters host wait -> M3 (spare 2) claims P0 and starts Task C.
/// While M3 is running Task C, M1 calls end_host_wait on a separate thread.
/// M1 kicks M3 (leaf replacement) and waits.
/// M3 settles Task C. M2 ends host wait and settles Task B.
/// M1's end_host_wait unblocks and reclaims P0 only after all descendants yield!
#[test]
fn host_wait_handoff_nested_lineage_and_ancestor_return() {
    let (kernel, ctx_a, _asids) = bootstrap_kernel(54_001);
    publish_task(&ctx_a, 500);

    let ctx_b = create_sibling_thread(&kernel, &ctx_a, 54_002);
    publish_task(&ctx_b, 501);

    let ctx_c = create_sibling_thread(&kernel, &ctx_a, 54_003);
    publish_task(&ctx_c, 502);

    let scheduler = Arc::new(Scheduler::new_with_policy(
        Arc::clone(&kernel),
        Arc::new(GuestCpuPolicy::new(1)),
    ));

    let m1_kick = Arc::new(TestKick::default());
    let m1_reg = scheduler
        .register_executor_bound(
            Arc::clone(&m1_kick) as Arc<dyn ExecutorKick>,
            Some(GuestCpuId::new(0)),
            false,
        )
        .expect("register m1");
    let m2_kick = Arc::new(TestKick::default());
    let m2_reg = scheduler
        .register_executor_bound(Arc::clone(&m2_kick) as Arc<dyn ExecutorKick>, None, true)
        .expect("register m2");
    let m3_kick = Arc::new(TestKick::default());
    let m3_reg = scheduler
        .register_executor_bound(Arc::clone(&m3_kick) as Arc<dyn ExecutorKick>, None, true)
        .expect("register m3");

    assert_eq!(
        scheduler.make_runnable(ctx_a.thread().key()).unwrap(),
        WakeDisposition::Queued
    );
    let running_a = scheduler.take(&m1_reg).expect("m1 takes task a");

    assert_eq!(
        scheduler.make_runnable(ctx_b.thread().key()).unwrap(),
        WakeDisposition::Queued
    );
    assert_eq!(
        scheduler.make_runnable(ctx_c.thread().key()).unwrap(),
        WakeDisposition::Queued
    );

    let token_a = scheduler
        .begin_host_wait(&running_a, &m1_reg)
        .expect("m1 begins host wait");

    let barrier_m3_running = Arc::new(Barrier::new(2));

    let s_clone = Arc::clone(&scheduler);
    let m2_reg_clone = m2_reg.clone();
    let m3_reg_clone = m3_reg.clone();
    let m3_kick_clone = Arc::clone(&m3_kick);
    let b_m3_run = Arc::clone(&barrier_m3_running);

    let key_b = ctx_b.thread().key();
    let key_c = ctx_c.thread().key();

    let (done_tx, done_rx) = mpsc::channel();

    let worker_thread = thread::spawn(move || {
        let running_b = s_clone.take(&m2_reg_clone).expect("m2 takes task b");
        assert_eq!(running_b.thread_key(), key_b);

        let token_b = s_clone
            .begin_host_wait(&running_b, &m2_reg_clone)
            .expect("m2 begins host wait");

        let s_inner = Arc::clone(&s_clone);
        let m3_inner = m3_reg_clone.clone();
        let m3_handle = thread::spawn(move || {
            let running_c = s_inner.take(&m3_inner).expect("m3 takes task c");
            assert_eq!(running_c.thread_key(), key_c);

            // Signal that M3 is actively running Task C
            b_m3_run.wait();
            // Wait for M1 to initiate ancestor return
            m3_kick_clone.wait_for_kick();

            // Verify that leaf kick was delivered to M3
            assert!(m3_kick_clone.kicked.load(Ordering::Acquire));

            s_inner.settle_exited(running_c).expect("settle task c");
        });

        m3_handle.join().expect("join m3");

        s_clone
            .end_host_wait(&running_b, &m2_reg_clone, token_b)
            .expect("m2 ends host wait");
        s_clone.settle_exited(running_b).expect("settle task b");

        done_tx.send(()).expect("send completion");
    });

    // Wait until M3 is actively running Task C
    barrier_m3_running.wait();

    // The original can return before an intermediate host wait finishes,
    // but never while the leaf still owns the one transferred slot.
    scheduler
        .end_host_wait(&running_a, &m1_reg, token_a)
        .expect("ancestor returns");
    scheduler.settle_exited(running_a).expect("settle ancestor");

    done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("nested descendants must finish");
    worker_thread.join().expect("join worker");
}

/// Test 6: Concurrent returns across multiple CPUs.
/// Multiple executors concurrently transitioning through host waits, spare handoffs,
/// and returning simultaneously under load with zero deadlocks.
#[test]
fn host_wait_handoff_concurrent_returns() {
    let ncpu = 4;
    let (kernel, ctx_root, _asids) = bootstrap_kernel(55_001);
    publish_task(&ctx_root, 600);

    let scheduler = Arc::new(Scheduler::new_with_policy(
        Arc::clone(&kernel),
        Arc::new(GuestCpuPolicy::new(ncpu)),
    ));

    let mut m_regs = Vec::new();
    for i in 0..ncpu {
        let reg = scheduler
            .register_executor_bound(
                Arc::new(TestKick::default()),
                Some(GuestCpuId::new(i as u32)),
                false,
            )
            .expect("register bound executor");
        m_regs.push(reg);
    }
    let mut spares = Vec::new();
    for _ in 0..ncpu {
        let spare = scheduler
            .register_executor_bound(Arc::new(TestKick::default()), None, true)
            .expect("register spare");
        spares.push(spare);
    }

    let mut parent_contexts = Vec::new();
    let mut spare_contexts = Vec::new();
    for i in 0..ncpu {
        let task_ctx = create_sibling_thread(&kernel, &ctx_root, 55_100 + i as i32);
        publish_task(&task_ctx, 700 + i as u64);
        parent_contexts.push(task_ctx);

        let work_ctx = create_sibling_thread(&kernel, &ctx_root, 55_200 + i as i32);
        publish_task(&work_ctx, 800 + i as u64);
        spare_contexts.push(work_ctx);
    }

    let barrier = Arc::new(Barrier::new(ncpu * 2));
    let mut handles = Vec::new();

    for i in 0..ncpu {
        let (completed_tx, completed_rx) = mpsc::channel();
        let s_c = Arc::clone(&scheduler);
        let m_reg = m_regs[i].clone();
        let b = Arc::clone(&barrier);
        let task_ctx = parent_contexts.remove(0);

        let parent_thread = thread::spawn(move || {
            s_c.make_runnable(task_ctx.thread().key()).unwrap();

            let running = s_c.take(&m_reg).expect("take main task");
            b.wait();

            let token = s_c
                .begin_host_wait(&running, &m_reg)
                .expect("begin host wait");
            completed_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("replacement completes before return");
            s_c.end_host_wait(&running, &m_reg, token)
                .expect("end host wait");
            s_c.settle_exited(running).expect("settle main task");
        });
        handles.push(parent_thread);

        let s_spare = Arc::clone(&scheduler);
        let spare_reg = spares[i].clone();
        let b_spare = Arc::clone(&barrier);
        let work_ctx = spare_contexts.remove(0);

        let spare_thread = thread::spawn(move || {
            s_spare.make_runnable(work_ctx.thread().key()).unwrap();

            b_spare.wait();
            let running = s_spare.take(&spare_reg).expect("spare take");
            s_spare.settle_exited(running).expect("settle spare task");
            completed_tx.send(()).expect("publish spare completion");
        });
        handles.push(spare_thread);
    }

    for h in handles {
        h.join().expect("join thread");
    }
}

/// Test 7: Authentication and stale unregister.
/// Authenticates registrations, validates capability requirement, rejects cross-scheduler calls,
/// and ensures unregistering stale/unregistered executor fails closed with StaleExecutor.
#[test]
fn host_wait_authentication_and_stale_unregister() {
    let (kernel, ctx_a, _asids) = bootstrap_kernel(56_001);
    publish_task(&ctx_a, 900);

    let scheduler1 = Arc::new(Scheduler::new_with_policy(
        Arc::clone(&kernel),
        Arc::new(GuestCpuPolicy::new(1)),
    ));
    let scheduler2 = Arc::new(Scheduler::new_with_policy(
        Arc::clone(&kernel),
        Arc::new(GuestCpuPolicy::new(1)),
    ));

    let m1_reg = scheduler1
        .register_executor_bound(
            Arc::new(TestKick::default()),
            Some(GuestCpuId::new(0)),
            false,
        )
        .expect("register m1 on s1");
    let s2_reg = scheduler2
        .register_executor_bound(
            Arc::new(TestKick::default()),
            Some(GuestCpuId::new(0)),
            false,
        )
        .expect("register s2 on s2");

    assert_eq!(
        scheduler1.make_runnable(ctx_a.thread().key()).unwrap(),
        WakeDisposition::Queued
    );
    let running_a = scheduler1.take(&m1_reg).expect("take task a");

    // 1. Cross scheduler rejection
    let cross_err = scheduler2.begin_host_wait(&running_a, &s2_reg);
    assert!(matches!(
        cross_err,
        Err(SchedulerError::Queue(RunQueueError::AuthorityMismatch))
    ));
    drop(cross_err);

    // 2. Lent lease authentication
    let lease = running_a.lease();
    let token = scheduler1
        .begin_host_wait_with_lease(lease, &m1_reg)
        .expect("valid begin host wait with lent lease");

    // 3. Stale unregister rejection
    let unreg_err = scheduler2.unregister_executor(&m1_reg);
    assert!(matches!(unreg_err, Err(RunQueueError::StaleExecutor)));

    // 4. End host wait succeeds
    scheduler1
        .end_host_wait(&running_a, &m1_reg, token)
        .expect("end host wait");

    scheduler1.settle_exited(running_a).expect("settle task a");
}

/// Test 8: Dropped token unwinding while replacement is actively running.
/// When HostWaitToken is dropped without end_host_wait while replacement is running,
/// slot is marked abandoned, replacement finishes cleanly, and subsequent end_host_wait fails.
#[test]
fn host_wait_dropped_token_unwinding_with_active_replacement() {
    let (kernel, ctx_a, _asids) = bootstrap_kernel(57_001);
    publish_task(&ctx_a, 1000);
    let ctx_b = create_sibling_thread(&kernel, &ctx_a, 57_002);
    publish_task(&ctx_b, 1001);
    let scheduler = Arc::new(Scheduler::new_with_policy(
        Arc::clone(&kernel),
        Arc::new(GuestCpuPolicy::new(1)),
    ));
    let original = scheduler
        .register_executor_bound(
            Arc::new(TestKick::default()),
            Some(GuestCpuId::new(0)),
            false,
        )
        .unwrap();
    let kick = Arc::new(TestKick::default());
    let spare = scheduler
        .register_executor_bound(kick.clone(), None, true)
        .unwrap();
    scheduler.make_runnable(ctx_a.thread().key()).unwrap();
    let running = scheduler.take(&original).unwrap();
    scheduler.make_runnable(ctx_b.thread().key()).unwrap();
    let token = scheduler.begin_host_wait(&running, &original).unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let worker_scheduler = scheduler.clone();
    let worker = thread::spawn(move || {
        let child = worker_scheduler.take(&spare).unwrap();
        started_tx.send(()).unwrap();
        // A dropped guard must request this exact owner's boundary before
        // the original caller's unwind can continue.
        kick.wait_for_kick();
        worker_scheduler.settle_exited(child).unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _wait = token;
        panic!("injected external operation unwind");
    }));
    assert!(result.is_err());
    assert!(!original.in_host_wait());
    assert_eq!(original.bound_cpu(), Some(GuestCpuId::new(0)));
    assert_eq!(
        scheduler
            .binding_for_thread(running.thread_key())
            .map(|b| b.executor()),
        Some(original.id()),
    );
    worker.join().unwrap();
    scheduler.settle_exited(running).unwrap();
}

/// Test 9: Graceful close and drain.
/// When close() is initiated during host wait, queue enters Closing (not premature Closed)
/// until active claims settle, after which drain completes and spare take returns Closed.
#[test]
fn host_wait_graceful_close_and_drain() {
    let (kernel, ctx_a, _asids) = bootstrap_kernel(58_001);
    publish_task(&ctx_a, 1100);

    let scheduler = Arc::new(Scheduler::new_with_policy(
        Arc::clone(&kernel),
        Arc::new(GuestCpuPolicy::new(1)),
    ));

    let m1_reg = scheduler
        .register_executor_bound(
            Arc::new(TestKick::default()),
            Some(GuestCpuId::new(0)),
            false,
        )
        .expect("register m1");
    let m2_reg = scheduler
        .register_executor_bound(Arc::new(TestKick::default()), None, true)
        .expect("register m2");

    assert_eq!(
        scheduler.make_runnable(ctx_a.thread().key()).unwrap(),
        WakeDisposition::Queued
    );
    let running_a = scheduler.take(&m1_reg).expect("m1 take");

    let token = scheduler
        .begin_host_wait(&running_a, &m1_reg)
        .expect("begin host wait");

    let s_clone = Arc::clone(&scheduler);
    let m2_clone = m2_reg.clone();
    let spare_handle = thread::spawn(move || {
        let res = s_clone.take(&m2_clone);
        assert!(matches!(res, Err(RunQueueError::Closed)));
    });

    // Initiate close while M1 holds active claim in host wait
    scheduler.close();

    // M1 completes host wait and settles
    scheduler
        .end_host_wait(&running_a, &m1_reg, token)
        .expect("end host wait");
    scheduler.settle_exited(running_a).expect("settle task a");

    // Once active claim has settled, drain completes and spare unparks with Closed
    spare_handle.join().expect("join spare");
}

/// Control poking and residency flush requests remain observable.
#[test]
fn host_wait_control_pokes_and_residency_flush_requests() {
    let (kernel, ctx_a, _asids) = bootstrap_kernel(59_001);
    publish_task(&ctx_a, 1200);

    let scheduler = Arc::new(Scheduler::new_with_policy(
        Arc::clone(&kernel),
        Arc::new(GuestCpuPolicy::new(1)),
    ));

    let m1_reg = scheduler
        .register_executor_bound(
            Arc::new(TestKick::default()),
            Some(GuestCpuId::new(0)),
            false,
        )
        .expect("register m1");
    let m2_reg = scheduler
        .register_executor_bound(Arc::new(TestKick::default()), None, true)
        .expect("register m2");

    // Poke control: next take on m1 returns ControlPoked
    scheduler.poke_executor_control();

    // Request residency flush
    scheduler.request_residency_flush(m1_reg.id());
    assert!(m1_reg.flush_requested());
    m1_reg.clear_flush_request();
    assert!(!m1_reg.flush_requested());

    assert_eq!(
        scheduler.make_runnable(ctx_a.thread().key()).unwrap(),
        WakeDisposition::Queued
    );
    let poked = scheduler.take(&m1_reg);
    assert!(matches!(poked, Err(RunQueueError::ControlPoked)));

    let running_a = scheduler.take(&m1_reg).expect("take after control poked");
    let token = scheduler
        .begin_host_wait(&running_a, &m1_reg)
        .expect("begin host wait");

    scheduler
        .end_host_wait(&running_a, &m1_reg, token)
        .expect("end host wait");
    scheduler.settle_exited(running_a).expect("settle");
    scheduler.unregister_executor(&m2_reg).expect("unreg m2");
    scheduler.unregister_executor(&m1_reg).expect("unreg m1");
}

/// Compose the public dispatcher, actual host-operation injection, MM admission,
/// and scheduler. The replacement needs a sole-MM mutation while sync waits.
#[test]
fn injected_host_sync_allows_replacement_mm_mutation() {
    run_injected_host_operation(false, InjectedOperation::Sync);
}

#[test]
fn injected_host_sync_does_not_readmit_a_retired_thread() {
    run_injected_host_operation(true, InjectedOperation::Sync);
}

#[test]
fn injected_stdio_writer_allows_replacement_mm_mutation() {
    run_injected_host_operation(false, InjectedOperation::Stdio);
}

#[test]
fn injected_stdio_writer_does_not_readmit_a_retired_thread() {
    run_injected_host_operation(true, InjectedOperation::Stdio);
}

#[test]
fn redirected_stdio_writer_allows_replacement_mm_mutation() {
    run_injected_host_operation(false, InjectedOperation::RedirectedStdio);
}

#[test]
fn redirected_stdio_writer_does_not_readmit_a_retired_thread() {
    run_injected_host_operation(true, InjectedOperation::RedirectedStdio);
}

#[test]
fn injected_stdio_short_write_then_error_preserves_writer_contract() {
    run_injected_host_operation(false, InjectedOperation::ShortStdioError);
}

#[test]
fn injected_stdio_unwind_restores_cpu_ownership() {
    run_injected_host_operation(false, InjectedOperation::PanickingStdio);
}

#[test]
fn retired_stdio_unwind_does_not_readmit_the_old_task() {
    run_injected_host_operation(true, InjectedOperation::PanickingStdio);
}

#[derive(Clone, Copy)]
enum InjectedOperation {
    Sync,
    Stdio,
    RedirectedStdio,
    ShortStdioError,
    PanickingStdio,
}

// Shared integration-test fixture; an unexpected dispatch route is a test
// failure, never a production panic path.
#[allow(clippy::panic)]
fn run_injected_host_operation(retire_waiter: bool, operation: InjectedOperation) {
    let stdio = !matches!(operation, InjectedOperation::Sync);
    let error_after_prefix = matches!(operation, InjectedOperation::ShortStdioError);
    let panic_after_release = matches!(operation, InjectedOperation::PanickingStdio);
    use carrick_kernel::compat::{CompatReporter, SyscallArgs};
    use carrick_kernel::dispatch::routing::OrdinaryDispatchRoute;
    use carrick_kernel::dispatch::{
        DispatchOutcome, HostIo, LinearMemory, PreparedDispatch, SyscallDispatcher, SyscallRequest,
        ThreadCtx,
    };
    use carrick_kernel::thread::{FutexTable, ThreadRegistry};
    struct HeldSync {
        entered: mpsc::Sender<()>,
        release: parking_lot::Mutex<mpsc::Receiver<()>>,
        released: AtomicBool,
    }
    impl HostIo for HeldSync {
        fn sync(&self) {
            let _ = self.entered.send(());
            self.released.store(
                self.release
                    .lock()
                    .recv_timeout(Duration::from_secs(5))
                    .is_ok(),
                Ordering::Release,
            );
        }
        fn flush(&self, _fd: std::os::fd::BorrowedFd<'_>) -> Result<(), carrick_abi::LinuxErrno> {
            self.sync();
            Ok(())
        }
    }
    struct HeldWriter {
        held: Arc<HeldSync>,
        error_after_prefix: bool,
        wrote_prefix: bool,
        panic_after_release: bool,
    }
    impl std::io::Write for HeldWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.wrote_prefix {
                assert_eq!(
                    bytes, &[0; 2],
                    "write_all must retry only the uncommitted suffix"
                );
                return Err(std::io::Error::other("injected writer failure"));
            }
            assert_eq!(bytes, &[0; 4]);
            self.held.sync();
            assert!(!self.panic_after_release, "injected writer unwind");
            if self.error_after_prefix {
                self.wrote_prefix = true;
                Ok(2)
            } else {
                Ok(bytes.len())
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let host_io = Arc::new(HeldSync {
        entered: entered_tx,
        release: parking_lot::Mutex::new(release_rx),
        released: AtomicBool::new(false),
    });
    let mut dispatcher =
        SyscallDispatcher::with_bridges(carrick_kernel::dispatch::CarrierBridges {
            host_signal: Arc::new(NullHostSignalBridge::default()),
            timers: Arc::new(carrick_hal::NullGuestTimerBridge::default()),
        });
    dispatcher.set_host_io(host_io.clone());
    if stdio {
        dispatcher.set_stdio_sink(carrick_kernel::dispatch::StdioSink::Piped {
            stdout: Box::new(HeldWriter {
                held: host_io.clone(),
                error_after_prefix,
                wrote_prefix: false,
                panic_after_release,
            }),
            stderr: Box::new(std::io::sink()),
        });
    }
    let root = dispatcher.capture_one_task_context().unwrap();
    let write_fd = if matches!(operation, InjectedOperation::RedirectedStdio) {
        let mut memory = LinearMemory::new(0x10000, vec![0; 4096]);
        match dispatcher
            .dispatch(
                &root,
                SyscallRequest::new(23, SyscallArgs::from([1, 0, 0, 0, 0, 0])),
                &mut memory,
                &CompatReporter::default(),
            )
            .unwrap()
        {
            DispatchOutcome::Returned { value } if value >= 0 => value as u64,
            other => panic!("dup stdout: {other:?}"),
        }
    } else {
        1
    };
    let kernel = Arc::clone(root.kernel());
    let sibling = create_sibling_thread(&kernel, &root, 59_101);
    publish_task(&root, 1300);
    publish_task(&sibling, 1400);
    let dispatcher = Arc::new(dispatcher);
    let scheduler = Arc::new(Scheduler::new_with_policy(
        kernel,
        Arc::new(GuestCpuPolicy::new(1)),
    ));
    let owner = scheduler
        .register_executor_bound(
            Arc::new(TestKick::default()),
            Some(GuestCpuId::new(0)),
            false,
        )
        .unwrap();
    let spare = scheduler
        .register_executor_bound(Arc::new(TestKick::default()), None, true)
        .unwrap();
    scheduler.make_runnable(root.thread().key()).unwrap();
    let running = scheduler.take(&owner).unwrap();
    scheduler.make_runnable(sibling.thread().key()).unwrap();
    let worker_scheduler = Arc::clone(&scheduler);
    let worker_dispatcher = Arc::clone(&dispatcher);
    let worker_spare = spare.clone();
    let waiting_context = root.retain_exact();
    let worker = thread::spawn(move || -> Result<(), String> {
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        let replacement = worker_scheduler
            .take(&worker_spare)
            .map_err(|e| e.to_string())?;
        let tid = ThreadId::synthetic_for_tests(59_101);
        let registry = ThreadRegistry::new(tid);
        let futex = FutexTable::new();
        let mut memory = LinearMemory::new(0x10000, vec![0; 4096]);
        let mut participation = worker_dispatcher
            .enter_mm_executor()
            .map_err(|e| e.to_string())?;
        let outcome = if retire_waiter {
            waiting_context
                .kernel()
                .exit_thread(&waiting_context, None)
                .map(|_| DispatchOutcome::Returned { value: 0 })
                .map_err(|e| e.to_string())
        } else {
            worker_dispatcher
                .dispatch_threaded_with_mm_executor(
                    &mut participation,
                    &sibling,
                    SyscallRequest::new(214, SyscallArgs::from([0; 6])),
                    &mut memory,
                    &CompatReporter::default(),
                    ThreadCtx::new(tid, &registry, &futex),
                )
                .map_err(|e| e.to_string())
        };
        drop(participation);
        worker_scheduler
            .settle_exited(replacement)
            .map_err(|e| e.to_string())?;
        let _ = release_tx.send(());
        let outcome = outcome.map_err(|e| e.to_string())?;
        if !matches!(outcome, DispatchOutcome::Returned { .. }) {
            return Err(format!("brk: {outcome:?}"));
        }
        Ok(())
    });
    let tid = ThreadId::synthetic_for_tests(59_100);
    let registry = ThreadRegistry::new(tid);
    let futex = FutexTable::new();
    let reporter = CompatReporter::default();
    let mut memory = LinearMemory::new(0x10000, vec![0; 4096]);
    let mut participation = dispatcher.enter_mm_executor().unwrap();
    let PreparedDispatch::Invoke(prepared) = dispatcher
        .prepare_syscall(
            &root,
            if stdio {
                SyscallRequest::new(64, SyscallArgs::from([write_fd, 0x10000, 4, 0, 0, 0]))
            } else {
                SyscallRequest::new(81, SyscallArgs::from([0; 6]))
            },
            &reporter,
        )
        .unwrap()
    else {
        panic!("sync must dispatch");
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        dispatcher.dispatch_threaded_prepared_with_mm_executor_and_lease(
            &root,
            prepared,
            &mut memory,
            &reporter,
            ThreadCtx::new(tid, &registry, &futex),
            OrdinaryDispatchRoute {
                host_wait: Some(carrick_kernel::dispatch::HostWaitContext {
                    scheduler: &scheduler,
                    registration: &owner,
                }),
                lease: Some(running.lease()),
                mm_executor: Some(&mut participation),
            },
        )
    }));
    drop(participation);
    scheduler.settle_exited(running).unwrap();
    // A failing no-handoff path still drains its queued sibling before close.
    if !host_io.released.load(Ordering::Acquire) {
        let pending = scheduler.take(&owner).unwrap();
        scheduler.settle_exited(pending).unwrap();
    }
    scheduler.close();
    let progress = worker.join().unwrap();
    scheduler.unregister_executor(&spare).unwrap();
    scheduler.unregister_executor(&owner).unwrap();
    assert!(
        host_io.released.load(Ordering::Acquire),
        "replacement must finish while host operation is held"
    );
    progress.expect("replacement acquired sole-MM mutation authority");
    let census = scheduler.host_wait_census().unwrap();
    assert_eq!((census.entered, census.resumed), (1, 1));
    if panic_after_release {
        assert!(
            outcome.is_err(),
            "preserve the writer's panic after cleanup"
        );
        return;
    }
    let outcome = outcome.expect("ordinary writer must not panic");
    if retire_waiter {
        assert!(
            matches!(
                outcome,
                Err(carrick_kernel::dispatch::DispatchError::HostWaitRetired)
            ),
            "a retired task must settle terminally, not return to guest memory: {outcome:?}"
        );
    } else if error_after_prefix {
        assert_eq!(
            outcome.unwrap(),
            DispatchOutcome::errno(carrick_abi::LINUX_EIO)
        );
    } else {
        assert_eq!(
            outcome.unwrap(),
            DispatchOutcome::Returned {
                value: if stdio { 4 } else { 0 }
            }
        );
    }
}

/// kernel.scheduler.preemption-cost: completing an uncontended external
/// operation must not manufacture demand for a scheduler round trip.
#[test]
fn uncontended_host_wait_return_has_zero_spurious_preemptions() {
    for scale in [1, 8, 32, 128] {
        let (kernel, ctx, _asids) = bootstrap_kernel(59_100);
        publish_task(&ctx, 1300);
        let scheduler = Scheduler::new_with_policy(kernel, Arc::new(GuestCpuPolicy::new(1)));
        let executor = scheduler
            .register_executor_bound(
                Arc::new(TestKick::default()),
                Some(GuestCpuId::new(0)),
                false,
            )
            .unwrap();
        scheduler.make_runnable(ctx.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        let mut spurious = 0;
        for _ in 0..scale {
            let wait = scheduler.begin_host_wait(&running, &executor).unwrap();
            scheduler.end_host_wait(&running, &executor, wait).unwrap();
            spurious += usize::from(scheduler.should_preempt(&running));
        }
        let census = scheduler.host_wait_census().unwrap();
        assert_eq!(census.entered, scale);
        assert_eq!(census.resumed, scale);
        assert!(census.slots.is_empty());
        scheduler.settle_exited(running).unwrap();
        assert_eq!(spurious, 0, "scale={scale}: uncontended host returns");
    }
}

/// A return reason belongs to the surviving handoff, not to the executor's
/// next residency after that handoff has completely drained.
#[test]
fn nested_host_wait_final_return_clears_stale_handoff_reason() {
    use carrick_kernel::kernel::scheduler::PreemptionReasons;

    for mandatory in [false, true] {
        let (kernel, root, _asids) = bootstrap_kernel(59_200);
        let child = create_sibling_thread(&kernel, &root, 59_201);
        publish_task(&root, 1400);
        publish_task(&child, 1401);
        let scheduler = Scheduler::new_with_policy(kernel, Arc::new(GuestCpuPolicy::new(1)));
        let owner = scheduler
            .register_executor_bound(
                Arc::new(TestKick::default()),
                Some(GuestCpuId::new(0)),
                false,
            )
            .unwrap();
        let replacement = scheduler
            .register_executor_bound(Arc::new(TestKick::default()), None, true)
            .unwrap();
        scheduler.make_runnable(root.thread().key()).unwrap();
        let original = scheduler.take(&owner).unwrap();
        let first_wait = scheduler.begin_host_wait(&original, &owner).unwrap();
        scheduler.make_runnable(child.thread().key()).unwrap();
        let replacing = scheduler.take(&replacement).unwrap();
        let child_wait = scheduler.begin_host_wait(&replacing, &replacement).unwrap();

        scheduler
            .end_host_wait(&original, &owner, first_wait)
            .unwrap();
        assert!(
            scheduler
                .binding_residency(owner.id())
                .unwrap()
                .reasons
                .contains(PreemptionReasons::HOST_WAIT_RETURN)
        );
        if mandatory {
            assert!(scheduler.set_preemption_reason(
                owner.id(),
                PreemptionReasons::SIGNAL | PreemptionReasons::CONTROL,
            ));
        }
        // Another host operation starts before the returning root settles.
        // Its saved reasons therefore include the earlier handoff return bit.
        let final_wait = scheduler.begin_host_wait(&original, &owner).unwrap();
        scheduler
            .end_host_wait(&replacing, &replacement, child_wait)
            .unwrap();
        scheduler.settle_exited(replacing).unwrap();
        scheduler
            .end_host_wait(&original, &owner, final_wait)
            .unwrap();

        let reasons = scheduler.binding_residency(owner.id()).unwrap().reasons;
        assert!(!reasons.contains(PreemptionReasons::HOST_WAIT_RETURN));
        assert_eq!(reasons.contains(PreemptionReasons::SIGNAL), mandatory);
        assert_eq!(reasons.contains(PreemptionReasons::CONTROL), mandatory);
        assert_eq!(scheduler.should_preempt(&original), mandatory);
        let census = scheduler.host_wait_census().unwrap();
        assert_eq!(census.entered, 3);
        assert_eq!(census.resumed, 3);
        assert!(census.slots.is_empty());
        scheduler.settle_exited(original).unwrap();
    }
}
