#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use carrick_abi::LinuxCloneFlags;
use carrick_hal::NullHostSignalBridge;
use carrick_hal::threaded::{Aarch64TaskCpuStateV1, GuestCpuState};
use carrick_hal::{GuestCpuId, GuestCpuPolicy, ThreadId};
use carrick_kernel::kernel::objects::MigratableTaskState;
use carrick_kernel::kernel::{
    ClonePlan, ExecutorBinding, ExecutorKick, ExecutorKickToken, Kernel, KernelContext, Scheduler,
};

#[derive(Debug, Default)]
struct TestKick {
    binding: parking_lot::Mutex<Option<ExecutorBinding>>,
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
        current.is_some_and(|binding| {
            binding.executor() == token.executor()
                && binding.executor_epoch() == token.executor_epoch()
                && binding.thread() == token.thread()
                && binding.generation() == token.generation()
        })
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

/// Public API binding for kernel.scheduler.host-wait-handoff: a peer exec
/// retires the exact thread held in sync; returning dispatch must not reenter
/// guest memory or restore the predecessor MM admission.
#[test]
#[allow(clippy::panic)]
fn peer_exec_retires_host_wait_without_guest_return() {
    use carrick_kernel::compat::{CompatReporter, SyscallArgs};
    use carrick_kernel::dispatch::routing::OrdinaryDispatchRoute;
    use carrick_kernel::dispatch::{
        HostIo, LinearMemory, PreparedDispatch, SyscallDispatcher, SyscallRequest, ThreadCtx,
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
    let root = dispatcher.capture_one_task_context().unwrap();
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
    let worker_spare = spare.clone();
    let worker = thread::spawn(move || -> Result<(), String> {
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        let replacement = worker_scheduler
            .take(&worker_spare)
            .map_err(|e| e.to_string())?;
        assert_eq!(replacement.thread_key(), sibling.thread().key());
        let census = worker_scheduler.host_wait_census().expect("live census");
        assert_eq!(census.slots.len(), 1);
        assert_eq!(census.slots[0].owner, Some(worker_spare.id()));
        assert_eq!(census.entered, 1);
        assert_eq!(census.resumed, 0);
        let prepared = sibling
            .kernel()
            .prepare_exec(&sibling, None)
            .map_err(|e| e.to_string())?;
        // The exec caller crosses its terminal boundary before publishing its
        // successor. The old waiting sibling still retains its exact claim.
        worker_scheduler
            .settle_exited(replacement)
            .map_err(|e| e.to_string())?;
        let successor = sibling
            .kernel()
            .commit_exec(prepared, None)
            .map_err(|e| e.to_string())?;
        assert_ne!(successor.shared().mm().id(), sibling.shared().mm().id());
        assert_ne!(successor.thread().key(), sibling.thread().key());
        let _ = release_tx.send(());
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
            SyscallRequest::new(81, SyscallArgs::from([0; 6])),
            &reporter,
        )
        .unwrap()
    else {
        panic!("sync must dispatch");
    };
    let outcome = dispatcher.dispatch_threaded_prepared_with_mm_executor_and_lease(
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
    );
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
    progress.expect("peer exec published while host sync was held");
    assert!(
        matches!(
            outcome,
            Err(carrick_kernel::dispatch::DispatchError::HostWaitRetired)
        ),
        "predecessor must not return to guest after peer exec: {outcome:?}"
    );
    let census = scheduler.host_wait_census().expect("final census");
    assert_eq!(census.entered, 1);
    assert_eq!(census.resumed, 1);
}
