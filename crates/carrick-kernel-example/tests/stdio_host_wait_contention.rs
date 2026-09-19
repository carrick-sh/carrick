#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use carrick_abi::LinuxCloneFlags;
use carrick_hal::NullHostSignalBridge;
use carrick_hal::threaded::{Aarch64TaskCpuStateV1, GuestCpuState};
use carrick_hal::{GuestCpuId, GuestCpuPolicy, ThreadId};
use carrick_kernel::compat::{CompatReporter, SyscallArgs};
use carrick_kernel::dispatch::routing::OrdinaryDispatchRoute;
use carrick_kernel::dispatch::{
    DispatchOutcome, HostWaitContext, LinearMemory, PreparedDispatch, StdioSink, SyscallDispatcher,
    SyscallRequest, ThreadCtx,
};
use carrick_kernel::kernel::objects::MigratableTaskState;
use carrick_kernel::kernel::{
    ClonePlan, ExecutorBinding, ExecutorKick, ExecutorKickToken, Kernel, KernelContext, Scheduler,
};
use carrick_kernel::thread::{FutexTable, ThreadRegistry};

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

struct ContendedWriter {
    task_a_entered: mpsc::Sender<()>,
    task_a_release: parking_lot::Mutex<mpsc::Receiver<()>>,
    write_count: AtomicUsize,
}

impl std::io::Write for ContendedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let index = self.write_count.fetch_add(1, Ordering::SeqCst);
        if index == 0 {
            // Task A holds the writer mutex inside with_host_wait; notify Thread B and wait for release.
            let _ = self.task_a_entered.send(());
            let release = self.task_a_release.lock();
            let _ = release.recv_timeout(Duration::from_secs(5));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Writer-mutex contention proof: one P, two spares.
///
/// Task A acquires P0 on the bound executor, enters `write_owned_stdio_sink`,
/// acquires the writer mutex inside `with_host_wait`, and blocks inside `Write`.
/// Task B (run on spare 1) writes to the same writer and blocks on its mutex
/// after entering `with_host_wait`, placing both tasks in simultaneous host wait.
/// Task C (run on spare 2) acquires P0 and performs an MM mutation (`brk`) before
/// releasing Task A.
#[test]
#[allow(clippy::panic)]
fn stdio_writer_mutex_contention_allows_spare_progression_and_mm_mutation() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();

    let writer = ContendedWriter {
        task_a_entered: entered_tx,
        task_a_release: parking_lot::Mutex::new(release_rx),
        write_count: AtomicUsize::new(0),
    };

    let dispatcher = SyscallDispatcher::with_bridges(carrick_kernel::dispatch::CarrierBridges {
        host_signal: Arc::new(NullHostSignalBridge::default()),
        timers: Arc::new(carrick_hal::NullGuestTimerBridge::default()),
    });
    dispatcher.set_stdio_sink(StdioSink::Piped {
        stdout: Box::new(writer),
        stderr: Box::new(std::io::sink()),
    });

    let root = dispatcher.capture_one_task_context().unwrap();
    let kernel = Arc::clone(root.kernel());
    let sibling_b = create_sibling_thread(&kernel, &root, 59_201);
    let sibling_c = create_sibling_thread(&kernel, &root, 59_202);
    publish_task(&root, 100);
    publish_task(&sibling_b, 200);
    publish_task(&sibling_c, 300);

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
    let spare1 = scheduler
        .register_executor_bound(Arc::new(TestKick::default()), None, true)
        .unwrap();
    let spare2 = scheduler
        .register_executor_bound(Arc::new(TestKick::default()), None, true)
        .unwrap();

    // Start Task A on bound owner executor
    scheduler.make_runnable(root.thread().key()).unwrap();
    let running_a = scheduler.take(&owner).unwrap();

    // Thread B: executes on spare1
    let s_b = Arc::clone(&scheduler);
    let d_b = Arc::clone(&dispatcher);
    let sp1 = spare1.clone();
    let sib_b = sibling_b.retain_exact();
    let handle_b = thread::spawn(move || -> Result<(), String> {
        // Wait until Task A enters write_all and holds writer mutex
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|e| format!("timed out waiting for task A to enter writer: {e}"))?;

        // Task B is now runnable and can take the lent P0 on spare1
        s_b.make_runnable(sib_b.thread().key())
            .map_err(|e| format!("make Task B runnable: {e:?}"))?;

        let running_b = s_b
            .take(&sp1)
            .map_err(|e| format!("spare1 take Task B: {e:?}"))?;

        let tid_b = ThreadId::synthetic_for_tests(59_201);
        let registry_b = ThreadRegistry::new(tid_b);
        let futex_b = FutexTable::new();
        let reporter_b = CompatReporter::default();
        let mut memory_b = LinearMemory::new(0x10000, vec![0; 4096]);
        let mut participation_b = d_b
            .enter_mm_executor()
            .map_err(|e| format!("enter mm for Task B: {e:?}"))?;

        let PreparedDispatch::Invoke(prepared_b) = d_b
            .prepare_syscall(
                &sib_b,
                SyscallRequest::new(64, SyscallArgs::from([1, 0x10000, 4, 0, 0, 0])),
                &reporter_b,
            )
            .map_err(|e| format!("prepare Task B write: {e:?}"))?
        else {
            return Err("write must dispatch for Task B".into());
        };

        // Task B enters write_owned_stdio_sink -> enters with_host_wait -> lends P0!
        // Inside closure, Task B calls writer.lock() and blocks on Task A's lock.
        let outcome_b = d_b.dispatch_threaded_prepared_with_mm_executor_and_lease(
            &sib_b,
            prepared_b,
            &mut memory_b,
            &reporter_b,
            ThreadCtx::new(tid_b, &registry_b, &futex_b),
            OrdinaryDispatchRoute {
                host_wait: Some(HostWaitContext {
                    scheduler: &s_b,
                    registration: &sp1,
                }),
                lease: Some(running_b.lease()),
                mm_executor: Some(&mut participation_b),
            },
        );
        drop(participation_b);
        s_b.settle_exited(running_b)
            .map_err(|e| format!("settle Task B: {e:?}"))?;

        let outcome_b = outcome_b.map_err(|e| format!("dispatch Task B error: {e:?}"))?;
        if outcome_b != (DispatchOutcome::Returned { value: 4 }) {
            return Err(format!("unexpected outcome for Task B: {outcome_b:?}"));
        }
        Ok(())
    });

    // Thread C: executes on spare2
    let s_c = Arc::clone(&scheduler);
    let d_c = Arc::clone(&dispatcher);
    let sp2 = spare2.clone();
    let sib_c = sibling_c.retain_exact();
    let handle_c = thread::spawn(move || -> Result<(), String> {
        // Wait until both Task A and Task B have entered host wait
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(census) = s_c.host_wait_census()
                && census.entered >= 2
                && !census.slots.is_empty()
                && census.slots[0].waiters.len() >= 2
            {
                break;
            }
            if Instant::now() > deadline {
                return Err("timed out waiting for 2 simultaneous host waits".into());
            }
            thread::sleep(Duration::from_millis(2));
        }

        // Make Task C runnable; it acquires P0 via spare2 because both A and B are in host wait
        s_c.make_runnable(sib_c.thread().key())
            .map_err(|e| format!("make Task C runnable: {e:?}"))?;

        let running_c = s_c
            .take(&sp2)
            .map_err(|e| format!("spare2 take Task C: {e:?}"))?;

        // Assert two simultaneous host waits visible in debug snapshot
        let census = s_c.host_wait_census().expect("live census during Task C");
        assert_eq!(census.slots.len(), 1, "must be exactly 1 handoff slot");
        assert_eq!(
            census.slots[0].waiters.len(),
            2,
            "both Task A and Task B must be waiting simultaneously in host wait"
        );
        assert_eq!(census.entered, 2, "must have entered host wait twice");
        assert_eq!(census.resumed, 0, "neither host wait must have resumed yet");
        assert_eq!(
            census.slots[0].owner,
            Some(sp2.id()),
            "spare2 running Task C must be the active CPU slot owner"
        );

        // Perform MM mutation while both Task A and Task B are in host wait.
        // Both A and B have temporarily left MM participation, so C acquires sole MM authority.
        let mut participation_c = d_c
            .enter_mm_executor()
            .map_err(|e| format!("enter mm for Task C: {e:?}"))?;
        let mut memory_c = LinearMemory::new(0x10000, vec![0; 4096]);
        let tid_c = ThreadId::synthetic_for_tests(59_202);
        let registry_c = ThreadRegistry::new(tid_c);
        let futex_c = FutexTable::new();
        let reporter_c = CompatReporter::default();
        let outcome_c = d_c
            .dispatch_threaded_with_mm_executor(
                &mut participation_c,
                &sib_c,
                SyscallRequest::new(214, SyscallArgs::from([0; 6])), // brk(0)
                &mut memory_c,
                &reporter_c,
                ThreadCtx::new(tid_c, &registry_c, &futex_c),
            )
            .map_err(|e| format!("brk for Task C: {e:?}"))?;
        drop(participation_c);

        if !matches!(outcome_c, DispatchOutcome::Returned { .. }) {
            return Err(format!("unexpected brk outcome for Task C: {outcome_c:?}"));
        }

        // Settle Task C
        s_c.settle_exited(running_c)
            .map_err(|e| format!("settle Task C: {e:?}"))?;

        // Release Task A now that Task C has finished MM mutation
        release_tx
            .send(())
            .map_err(|e| format!("release Task A: {e}"))?;

        Ok(())
    });

    // Run Task A on bound owner executor
    let tid_a = ThreadId::synthetic_for_tests(59_200);
    let registry_a = ThreadRegistry::new(tid_a);
    let futex_a = FutexTable::new();
    let reporter_a = CompatReporter::default();
    let mut memory_a = LinearMemory::new(0x10000, vec![0; 4096]);
    let mut participation_a = dispatcher.enter_mm_executor().unwrap();
    let PreparedDispatch::Invoke(prepared_a) = dispatcher
        .prepare_syscall(
            &root,
            SyscallRequest::new(64, SyscallArgs::from([1, 0x10000, 4, 0, 0, 0])),
            &reporter_a,
        )
        .unwrap()
    else {
        panic!("write must dispatch for Task A");
    };

    let outcome_a = dispatcher.dispatch_threaded_prepared_with_mm_executor_and_lease(
        &root,
        prepared_a,
        &mut memory_a,
        &reporter_a,
        ThreadCtx::new(tid_a, &registry_a, &futex_a),
        OrdinaryDispatchRoute {
            host_wait: Some(HostWaitContext {
                scheduler: &scheduler,
                registration: &owner,
            }),
            lease: Some(running_a.lease()),
            mm_executor: Some(&mut participation_a),
        },
    );
    drop(participation_a);
    scheduler.settle_exited(running_a).unwrap();

    let res_c = handle_c.join().expect("join Thread C");
    res_c.expect("Thread C succeeded");

    let res_b = handle_b.join().expect("join Thread B");
    res_b.expect("Thread B succeeded");

    assert_eq!(outcome_a.unwrap(), DispatchOutcome::Returned { value: 4 });

    scheduler.close();
    scheduler.unregister_executor(&spare2).unwrap();
    scheduler.unregister_executor(&spare1).unwrap();
    scheduler.unregister_executor(&owner).unwrap();

    let final_census = scheduler.host_wait_census().expect("final census");
    assert_eq!((final_census.entered, final_census.resumed), (2, 2));
    assert!(
        final_census.slots.is_empty() || final_census.slots[0].waiters.is_empty(),
        "all waiters must have resumed"
    );
}
