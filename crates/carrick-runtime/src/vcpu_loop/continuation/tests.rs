//! Unit and integration test suite for vcpu_loop continuations.

use std::os::fd::RawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::{Duration, Instant};

use carrick_abi::{LinuxCloneFlags, SigBlockMask, SigSet, WaitSigMask};
use carrick_guest_mem::{GuestMemory, GuestVa, HostVa, SharedFutexLocation};
use carrick_hal::ThreadId;
use carrick_hal::threaded::{Aarch64TaskCpuStateV1, GuestCpuState};

use super::*;
use crate::dispatch::SharedFutexTarget;

#[cfg(test)]
fn spawn_contained_test_child(test_name: &str, marker: &str) -> std::process::Child {
    std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env(marker, "1")
        .stdin(std::process::Stdio::null())
        .spawn()
        .expect("spawn contained test child")
}

/// Drive one future to completion on the calling test thread.
///
/// This used to submit the future to the transitional runner pool, which is
/// retired. A test awaiting a single future needs no executor at all: park
/// the thread and let the waker unpark it. Parking here is a test-only host
/// wait and is outside the production source the host-blocking-authority
/// gate inspects.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    struct ThreadWaker(std::thread::Thread);
    impl Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }
    let mut future = std::pin::pin!(future);
    let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
        std::thread::park();
    }
}

fn block_on_timeout<F: std::future::Future>(future: F, timeout: Duration) -> Option<F::Output> {
    struct ThreadWaker(std::thread::Thread);
    impl Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }
    let start = Instant::now();
    let mut future = std::pin::pin!(future);
    let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return Some(value);
        }
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return None;
        }
        let remaining = timeout.saturating_sub(elapsed);
        std::thread::park_timeout(remaining);
    }
}

fn await_event(
    service: &CarrierWaitService,
    token: ContinuationWakeToken,
) -> Result<ContinuationEvent, WaitServiceError> {
    let service = service.clone();
    block_on(async move { service.event(token).await })
}

fn await_event_timeout(
    service: &CarrierWaitService,
    token: ContinuationWakeToken,
    timeout: Duration,
) -> Option<Result<ContinuationEvent, WaitServiceError>> {
    let service = service.clone();
    block_on_timeout(async move { service.event(token).await }, timeout)
}

#[test]
fn carrier_wait_service_try_new_succeeds() {
    let (kernel, _) = bootstrap(15_469);
    let scheduler = Arc::new(Scheduler::new(kernel));
    assert!(CarrierWaitService::try_new(scheduler).is_ok());
}

#[test]
fn enrollment_samples_signal_pending_before_continuation_capture() {
    let (kernel, context) = bootstrap(15_470);
    let generation = publish(&context, 0x915);
    let signal = crate::kernel::LinuxSignal::for_signal_number(crate::linux_abi::LINUX_SIGKILL)
        .expect("SIGKILL");

    // Reproduce the procladder last-child race: the parent posts SIGKILL
    // before this child reaches pause(2), so continuation capture observes
    // the already-advanced task-wake generation. Subscription alone cannot
    // report that older edge; enrollment must sample authoritative pending
    // signal state after installing every producer subscription.
    context
        .signal_authority()
        .enqueue_task_standard(signal, None);
    context.task().wake();

    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::empty(),
            timeout: None,
            sig_mask: WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd { on_timeout: 0 },
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("pause-shaped continuation");
    let scheduler = Arc::new(Scheduler::new(kernel));
    let service = CarrierWaitService::new(scheduler);
    let mut registration = service.prepare_registration(&continuation);
    let token = registration.wake_token();
    service
        .enroll(&mut registration)
        .expect("enroll continuation with preexisting SIGKILL");

    let state = service.inner.state.lock();
    let entry = state
        .entries
        .get(&token.continuation)
        .expect("live continuation registration");
    assert_eq!(entry.state, RegistrationState::Ready);
    assert_eq!(
        entry
            .event
            .as_ref()
            .and_then(ContinuationEvent::reserved_signal)
            .map(ReservedSignal::signum),
        Some(crate::linux_abi::LINUX_SIGKILL),
        "preexisting fatal signal must prevent the child from parking"
    );
}

#[test]
fn hvpatch_launch_callgraph_never_constructs_the_compatibility_loop_future() {
    let source = include_str!("../binding.rs");
    // INVERTED for the fork-closure deletion. This used to bound the launch
    // entry between `launch_vcpu_until_exit` and `PreparedInitialRunnerTask`
    // and assert the HVPatch arm came first. Both are deleted: there is no
    // compatibility launch entry left to come second, so the invariant is
    // now that none of that text exists at all. Asserting ABSENCE is the
    // only form that keeps gating once the text is gone — a `split_once` on
    // absent text would hand the whole file to the next assertion.
    for deleted in [
        "fn launch_vcpu_until_exit",
        "fn launch_compatibility_vcpu_future",
        "fn run_vcpu_until_exit",
        "fn run_vcpu_until_exit_inner",
    ] {
        assert!(
            !source.contains(deleted),
            "the welded-thread vCPU loop is retired; `{deleted}` must not exist"
        );
    }
    // `prepare_initial_runner_handoff` and its `PreparedInitialRunnerTask`
    // are NOT part of that chain: `launch_persistent_hvpatch_job` calls them
    // to publish the initial task state and claim its start gate. Deleting
    // them with the welded loop was caught by the compiler, not by a test.
    for shared in [
        "fn prepare_initial_runner_handoff",
        "struct PreparedInitialRunnerTask",
    ] {
        assert!(
            source.contains(shared),
            "the persistent launcher's initial handoff `{shared}` must survive"
        );
    }
    let logical_job = source
        .split_once("fn prepare_hvpatch_logical_job")
        .expect("reusable logical-job constructor")
        .1
        .split_once("fn launch_persistent_hvpatch_job")
        .expect("end of reusable logical-job constructor")
        .0;
    for required in [
        "HvpatchLoopJob::production",
        "HvpatchTaskBinding::new_with_stage1_mm",
    ] {
        assert!(
            logical_job.contains(required),
            "reusable HVPatch logical-job constructor omitted {required}"
        );
    }
    let persistent = source
        .split_once("fn launch_persistent_hvpatch_job")
        .expect("persistent HVPatch launcher")
        .1
        .split_once("fn trap_watchdog_decision")
        .expect("end of persistent launcher")
        .0;
    for prohibited in [
        "run_vcpu_until_exit_inner",
        "OwnerThreadEngine",
        "std::thread::Builder",
    ] {
        assert!(
            !persistent.contains(prohibited),
            "persistent HVPatch launch retained compatibility authority {prohibited}"
        );
    }
    for required in [
        "prepare_hvpatch_logical_job",
        "prepare_submission",
        "start_persistent_pool",
        "dormant.activate",
    ] {
        assert!(
            persistent.contains(required),
            "persistent HVPatch launch omitted production edge {required}"
        );
    }
    let proof = persistent
        .find("logical.activation_proof()")
        .expect("consumed Kernel start-gate proof");
    let start = persistent
        .find("start_persistent_pool(")
        .expect("pool start");
    let activate = persistent
        .find("dormant.activate")
        .expect("queue activation");
    let rollback = persistent
        .find("if started_pool")
        .expect("new-pool-only rollback guard");
    let shutdown = persistent
        .find("shutdown_persistent_pool()")
        .expect("new pool close/join rollback");
    assert!(proof < start && start < activate && activate < rollback && rollback < shutdown);

    let executor_source = include_str!("../executor/binding.rs");
    let worker_prepare = executor_source
        .split_once("fn prepare_hvpatch_submission")
        .expect("worker-held HVPatch preparation API")
        .1
        .split_once("pub trait TaskBindingResolver")
        .expect("end of worker-held preparation API")
        .0;
    assert!(worker_prepare.contains("self.current"));
    assert!(worker_prepare.contains("Some(current)"));
    assert!(!worker_prepare.contains("bindings.get(&grant)"));
}

#[test]
fn static_hvpatch_continuation_closure_forbids_host_blocking_authority() {
    let continuation_source = include_str!("../continuation.rs")
        .split("#[cfg(test)]\nmod tests")
        .next()
        .expect("production continuation source");
    for prohibited in [
        "libc::wait",
        "libc::waitpid",
        "libc::kill",
        "libc::nanosleep",
        "ThreadWaiter",
        "make_readiness_pipe",
        "wait_for_event",
        "Duration::from_millis(2)",
        "Duration::from_secs(24 * 60 * 60)",
    ] {
        assert!(
            !continuation_source.contains(prohibited),
            "HVPatch continuation path retains prohibited host-blocking authority: {prohibited}"
        );
    }
    assert_eq!(DISPATCH_FAMILIES.len() + 1, 16);
    // The transitional runner pool and its ambient thread-locals are gone.
    // Nothing on the persistent executor ever published them, so every read
    // already answered None/false; they are deleted rather than left as a
    // second, silently-inert executor identity.
    for deleted in [
        "TransitionalDedicatedRunner",
        "TransitionalRunnerPool",
        "TransitionalWorkerContext",
        "TransitionalWorkerKick",
        "run_task_quantum",
        "CURRENT_RUNNER_WORKER",
        "CURRENT_RUNNER_JOB",
        "LogicalTaskReceipt",
    ] {
        assert!(
            !continuation_source.contains(deleted),
            "the transitional runner pool is retired; `{deleted}` must not exist"
        );
    }
    assert!(!continuation_source.contains("TaskQuantumSource"));
    assert!(!continuation_source.contains("fallback_fd"));
    // REPOINTED for the fork-closure deletion. `scheduler.request_preemption()`
    // was the transitional pool's carrier-timer policy hook and its only
    // production caller; the persistent executor owns preemption itself
    // through its own `need_resched` flag, so the invariant is asserted
    // where it now lives.
    let executor_source = include_str!("../executor/pool.rs");
    assert!(
        executor_source.contains("self.need_resched.store(true, Ordering::Release);"),
        "the persistent executor must own its own preemption request"
    );

    let loop_source = include_str!("../mod.rs");
    let prepare_suspend = loop_source
        .split("fn prepare_hvpatch_continuation")
        .nth(1)
        .and_then(|tail| tail.split("fn persistent_block_exit").next())
        .expect("engine-free HVPatch continuation preparation");
    for required in [
        "ContinuationCapture::from_lease",
        "BlockedContinuation::from_dispatch_outcome",
        "BlockedContinuation::from_vfork_parent",
        "install_temporary_signal_mask",
    ] {
        assert!(
            prepare_suspend.contains(required),
            "engine-free continuation preparation misses {required}"
        );
    }
    // INVERTED for the fork-closure deletion. The engine-owning welded loop
    // and its `suspend_hvpatch_continuation` adapter used to be bounded and
    // inspected here for product boundaries and prohibited host-blocking
    // authority. `launch_vcpu_until_exit` returned unconditionally at its
    // first statement, so none of that ran; the persistent executor reaches
    // the same continuation through `persistent_block_exit`. The surviving
    // invariant is that the welded chain does not exist at all.
    for deleted in [
        "fn suspend_hvpatch_continuation",
        "async fn yield_hvpatch_quantum",
        "fn run_vcpu_until_exit",
        "fn launch_vcpu_until_exit",
        "struct OwnerThreadEngine",
        "enum CompatibilityThreadWaiter",
    ] {
        assert!(
            !loop_source.contains(deleted),
            "the welded-thread vCPU loop is retired; `{deleted}` must not exist"
        );
    }
    let dispatch = loop_source
        .split("fn redispatch_threaded_syscall_for_executor")
        .nth(1)
        .and_then(|tail| tail.split("\n    fn ").next())
        .expect("dispatch service body");
    assert!(
        dispatch.contains("continuation::is_blocking_dispatch_outcome(&outcome)"),
        "HVPatch must still escape a blocking outcome at the dispatch seam"
    );
    let quiesce = include_str!("../quiesce.rs");
    let hvpatch_fork = quiesce
        .split("fn prepare_in_process_fork")
        .nth(1)
        .and_then(|tail| tail.split("#[cfg(test)]").next())
        .expect("HVPatch fork body");
    assert!(hvpatch_fork.contains("PreparedInProcessFork::SuspendVfork"));
    assert!(!hvpatch_fork.contains(".await"));
    assert!(!hvpatch_fork.contains("wait.wait_for_release"));
    let binding = include_str!("../binding.rs");
    let fork_wrapper = binding
        .split("fn complete_persistent_process_fork")
        .nth(1)
        .and_then(|tail| tail.split("fn finalize_persistent_process_terminal").next())
        .expect("persistent fork suspension wrapper");
    assert!(fork_wrapper.contains("HvpatchBlockInput::Vfork"));

    let threads = include_str!("../threads.rs");
    // INVERTED for the fork-closure deletion. This clause used to bound the
    // exec drain by the retired pool's ambient job thread-local and inspect
    // the executor-lease drain inside it. Only that pool ever published the
    // thread-local — never the persistent executor — so the branch never
    // ran, and the bounded drain beside it is the one that has always
    // executed. The surviving invariant is that guest-thread teardown
    // reacquires no retired runner identity.
    for deleted in [
        "TransitionalDedicatedRunner",
        "TransitionalWorkerContext",
        "await_hvpatch_sibling_jobs",
    ] {
        assert!(
            !threads.contains(deleted),
            "guest-thread teardown retains retired runner authority {deleted}"
        );
    }

    // Anchored on the reactor itself rather than on the Nth textual
    // occurrence of `ReadinessProbe::RecordLock`: an occurrence index
    // silently reaims at unrelated code the moment another match arm on
    // that variant is added anywhere earlier in the file (the diagnostic
    // renderer did exactly that), and a test that reaims is worse than no
    // test. This region is exactly the reactor body.
    let wait_service_source = include_str!("wait_service.rs");
    let record_reactor = wait_service_source
        .split("fn run_reactor")
        .nth(1)
        .and_then(|tail| tail.split("impl Drop for CarrierWaitServiceInner").next())
        .expect("shared record-lock reactor path");
    assert!(record_reactor.contains("try_drive_blocking_record_lock"));
    for prohibited in [
        "crate::dispatch::drive_blocking_record_lock(",
        "F_SETLKW",
        "Condvar",
    ] {
        assert!(
            !record_reactor.contains(prohibited),
            "record-lock reactor retains blocking authority {prohibited}"
        );
    }

    let signal_source = include_str!("../signal.rs");
    assert!(signal_source.contains("deliver_pending_signal_with_restart"));
    assert!(loop_source.contains("continuation.install_temporary_signal_mask(context)"));
    // The resume path must stash the restart decision — but ONLY for a
    // completion the signal path itself produced. A Ready->Redispatch
    // resume stashing its default NoRestart vetoed SA_RESTART for the
    // redispatched syscall's own EINTR (waitrestart scenario A).
    assert!(loop_source.contains("self.continuation_restart = match result.completion"));
    assert!(loop_source.contains("=> Some(result.restart()),"));
    assert!(loop_source.contains("ContinuationResumeError::StaleFileSlot"));
    assert!(!loop_source.contains("TransitionalSchedulerKick"));
    assert!(!loop_source.contains("continuation_executor"));

    let net_source = include_str!("../../dispatch/net.rs");
    assert!(
        net_source.matches("with_guest_slots(&files").count() >= 2,
        "pselect/ppoll must capture every exact guest fd slot at dispatch"
    );
    let io_uring_source = include_str!("../../dispatch/ioring.rs");
    assert!(io_uring_source.contains("with_guest_slots(&files, [ring_fd, sqe.fd])"));
    let proc_source = include_str!("../../dispatch/proc.rs");
    assert!(proc_source.contains("with_guest_slots(&files, [id as i32])"));
    let fs_source = include_str!("../../dispatch/fs.rs");
    assert!(!fs_source.contains("WaitFdAuthority::Missing"));
    for required in [
        "captured_slot_authority(guest_fd)",
        "captured_slot_authority(fd)",
        "captured_slot_authority(fd.0)",
        "WaitFdAuthority::logical",
        "[in_fd.0, out_fd.0]",
        "complete_wait_fd_authority",
    ] {
        assert!(
            fs_source.contains(required),
            "fd producer misses {required}"
        );
    }
}

use crate::compat::SyscallArgs;
use crate::dispatch::{BlockingHostWrite, DispatchOutcome, SyscallRequest, WaitFds};
use crate::kernel::objects::{
    BlockedReason, ExecutionGeneration, MigratableTaskState, ThreadExecutionState,
};
use crate::kernel::{ClonePlan, Kernel, KernelContext, RootBootstrap, Scheduler};
use crate::thread::FutexTable;

pub(crate) fn bootstrap(pid: i32) -> (Arc<Kernel>, KernelContext) {
    let input = RootBootstrap::for_reference_model(
        pid,
        ThreadId::synthetic_for_tests(pid),
        "continuation test".to_owned(),
    )
    .expect("bootstrap input");
    Kernel::bootstrap_root(input).expect("kernel")
}

pub(crate) fn task_state(context: &KernelContext, marker: u64) -> MigratableTaskState {
    task_state_with_asid(context, marker, context.shared().mm().id().raw())
}

pub(crate) fn task_state_with_asid(
    context: &KernelContext,
    marker: u64,
    asid_generation: u64,
) -> MigratableTaskState {
    let mm = context.shared().mm().id();
    MigratableTaskState {
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
            asid_generation,
        }),
        mm,
        asid_generation,
    }
}

pub(crate) fn publish(context: &KernelContext, marker: u64) -> ExecutionGeneration {
    context
        .thread()
        .publish_initial_task_state(task_state(context, marker))
        .expect("publish task state")
}

pub(crate) fn request(number: u64) -> SyscallRequest {
    SyscallRequest::new(
        number,
        SyscallArgs([0x1100, 0x2200, 0x3300, 0x4400, 0x5500, 0x6600]),
    )
}

fn capture(
    context: &KernelContext,
    generation: ExecutionGeneration,
    backend: ContinuationBackend,
) -> ContinuationCapture {
    ContinuationCapture::new(
        context,
        generation,
        request(73),
        RestartClass::RestartSyscall,
        backend,
    )
    .expect("capture exact continuation authority")
}

fn pipe_pair() -> [RawFd; 2] {
    let mut fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    fds
}

fn close_pair(fds: [RawFd; 2]) {
    for fd in fds {
        unsafe { libc::close(fd) };
    }
}

fn install_test_fd_authority(
    context: &KernelContext,
    guest_fd: i32,
) -> crate::kernel::objects::FileSlotAuthority {
    let files = context.resources().files();
    let number = crate::kernel::FileSlotNumber::for_open_fd(guest_fd).expect("test guest fd");
    let ids = crate::kernel::ObjectIdRegistry::new();
    files.install(
        number,
        Arc::new(crate::kernel::FileDescription::regular(
            ids.file_description_id().expect("test description"),
        )),
        false,
    );
    files
        .capture_slot_authority(number)
        .expect("test slot authority")
}

fn outcome_for(family: ContinuationFamily, tid: ThreadId) -> DispatchOutcome {
    match family {
        ContinuationFamily::FutexWait => DispatchOutcome::FutexWait {
            wait: FutexTable::new().prepare_wait(0x1000),
            timeout: Some(Duration::from_secs(2)),
        },
        ContinuationFamily::FutexWaitv => DispatchOutcome::FutexWaitv {
            wait: FutexTable::new().prepare_wait(0x2000),
            timeout: Some(Duration::from_secs(3)),
            index: 4,
        },
        ContinuationFamily::SharedFutexWait => DispatchOutcome::SharedFutexWait {
            target: SharedFutexTarget {
                location: SharedFutexLocation::Direct {
                    word: HostVa(0x3000),
                    waiter_key: 31,
                },
                waiter_key: 31,
            },
            generation: carrick_thread::platform_futex::carrier_shared_futex_table()
                .prepare_wait(31),
            value: 7,
            timeout: Some(Duration::from_secs(4)),
        },
        ContinuationFamily::SharedFutexWaitv => DispatchOutcome::SharedFutexWaitv {
            target: SharedFutexTarget {
                location: SharedFutexLocation::Direct {
                    word: HostVa(0x4000),
                    waiter_key: 41,
                },
                waiter_key: 41,
            },
            generation: carrick_thread::platform_futex::carrier_shared_futex_table()
                .prepare_wait(41),
            value: 8,
            timeout: Some(Duration::from_secs(5)),
            index: 9,
        },
        ContinuationFamily::WaitOnSharedWord => DispatchOutcome::WaitOnSharedWord {
            location: SharedFutexLocation::Direct {
                word: HostVa(0x5000),
                waiter_key: 51,
            },
            waiter_key: 51,
            generation: carrick_thread::platform_futex::carrier_shared_futex_table()
                .prepare_wait(51),
            value: 10,
            sysv: None,
        },
        ContinuationFamily::WaitOnFds => DispatchOutcome::WaitOnFds {
            fds: WaitFds::empty(),
            timeout: Some(Duration::from_secs(6)),
            sig_mask: WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd { on_timeout: -11 },
        },
        ContinuationFamily::WaitOnFdsSelect => DispatchOutcome::WaitOnFds {
            fds: WaitFds::empty(),
            timeout: Some(Duration::from_secs(7)),
            sig_mask: WaitSigMask::NONE,
            completion: FdWaitCompletion::Select {
                clear_on_timeout: vec![(0x7000, 16), (0x7100, 8)],
            },
        },
        ContinuationFamily::WaitOnPollFds => DispatchOutcome::WaitOnFds {
            fds: WaitFds::empty(),
            timeout: Some(Duration::from_secs(8)),
            sig_mask: WaitSigMask::NONE,
            completion: FdWaitCompletion::Poll { on_timeout: 0 },
        },
        ContinuationFamily::BlockingHostWrite => {
            let fds = pipe_pair();
            let write = BlockingHostWrite::for_tests(fds[1], vec![1, 2, 3, 4], 2, tid, true)
                .expect("pinned partial write");
            close_pair(fds);
            DispatchOutcome::BlockingHostWrite(write)
        }
        ContinuationFamily::BlockingRecordLock => {
            let contention = crate::dispatch::RecordLockContentionFixture::new();
            DispatchOutcome::BlockingRecordLock(contention.waiter(tid, 1))
        }
        ContinuationFamily::WaitOnProcExit => DispatchOutcome::WaitOnProcExit {
            pid: 9001,
            sig_mask: WaitSigMask::NONE,
        },
        ContinuationFamily::WaitOnProcState => DispatchOutcome::WaitOnProcState {
            pid: 9002,
            sig_mask: WaitSigMask::NONE,
        },
        ContinuationFamily::WaitOnHvpatchChild => DispatchOutcome::WaitOnHvpatchChild {
            target: None,
            sig_mask: WaitSigMask::NONE,
            precheck: crate::kernel::ChildWaitPrecheck::unsampled(),
        },
        ContinuationFamily::WaitOnSignals => DispatchOutcome::WaitOnSignals {
            wait_set: SigSet::from_raw(0x55),
            block_mask: SigBlockMask::blocking_all_of(SigSet::from_raw(0xaa)),
            timeout: Some(Duration::from_secs(9)),
        },
        ContinuationFamily::WaitOnSleep => DispatchOutcome::WaitOnSleep {
            duration: Duration::from_secs(10),
            remaining: Some(crate::dispatch::GuestPtr(0x9000)),
        },
        ContinuationFamily::VforkParent => {
            panic!("vfork continuation is constructed from the published Kernel relationship")
        }
    }
}

const DISPATCH_FAMILIES: [ContinuationFamily; 15] = [
    ContinuationFamily::FutexWait,
    ContinuationFamily::FutexWaitv,
    ContinuationFamily::SharedFutexWait,
    ContinuationFamily::SharedFutexWaitv,
    ContinuationFamily::WaitOnSharedWord,
    ContinuationFamily::WaitOnFds,
    ContinuationFamily::WaitOnFdsSelect,
    ContinuationFamily::WaitOnPollFds,
    ContinuationFamily::BlockingHostWrite,
    ContinuationFamily::BlockingRecordLock,
    ContinuationFamily::WaitOnProcExit,
    ContinuationFamily::WaitOnProcState,
    ContinuationFamily::WaitOnHvpatchChild,
    ContinuationFamily::WaitOnSignals,
    ContinuationFamily::WaitOnSleep,
];

#[test]
fn continuation_family_event_codes_are_stable_unique_and_nonzero() {
    let mut families = DISPATCH_FAMILIES.to_vec();
    families.push(ContinuationFamily::VforkParent);
    let mut codes = families
        .into_iter()
        .map(ContinuationFamily::event_code)
        .collect::<Vec<_>>();
    assert!(codes.iter().all(|code| *code != 0));
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes, (1_u8..=16).collect::<Vec<_>>());
}

fn assert_send_static<T: Send + 'static>(_: &T) {}

#[test]
fn exhaustive_real_dispatch_shapes_become_owned_send_static_continuations() {
    let (kernel, context) = bootstrap(15_000);
    let generation = publish(&context, 0x100);
    let now = Instant::now();
    for family in DISPATCH_FAMILIES {
        let backend = if matches!(
            family,
            ContinuationFamily::WaitOnProcExit | ContinuationFamily::WaitOnProcState
        ) {
            ContinuationBackend::HostProcessCompatibility
        } else {
            ContinuationBackend::Hvpatch
        };
        let continuation = BlockedContinuation::from_dispatch_outcome(
            outcome_for(family, context.thread().registry_id()),
            capture(&context, generation, backend),
        )
        .expect("blocking outcome must convert");
        assert_eq!(continuation.family(), family);
        assert_send_static(&continuation);
        let authority = continuation.authority();
        assert_eq!(authority.thread(), context.thread().key());
        assert_eq!(authority.execution_generation(), generation);
        assert_eq!(authority.mm(), context.shared().mm().id());
        assert_eq!(
            authority.asid_generation(),
            context.shared().mm().id().raw()
        );
        assert_eq!(authority.syscall().request(), request(73));
        assert_eq!(authority.restart_class(), RestartClass::RestartSyscall);
        let masks = continuation.signal_masks();
        assert_eq!(masks.persistent(), SigSet::EMPTY);
        assert_eq!(masks.restore_after_signal(), None);
        assert_eq!(
            masks.temporary().is_some(),
            matches!(
                family,
                ContinuationFamily::WaitOnFds
                    | ContinuationFamily::WaitOnFdsSelect
                    | ContinuationFamily::WaitOnPollFds
                    | ContinuationFamily::BlockingHostWrite
                    | ContinuationFamily::BlockingRecordLock
                    | ContinuationFamily::WaitOnProcExit
                    | ContinuationFamily::WaitOnProcState
                    | ContinuationFamily::WaitOnHvpatchChild
                    | ContinuationFamily::WaitOnSignals
            )
        );
        if let Some(deadline) = continuation.deadline() {
            assert!(deadline >= now, "deadline must be absolute monotonic time");
        }
        for range in continuation.guest_outputs() {
            assert_eq!(range.mm(), context.shared().mm().id());
            assert_eq!(range.asid_generation(), context.shared().mm().id().raw());
            assert!(!range.is_empty());
        }
    }
    drop(kernel);
}

#[test]
fn vfork_parent_owns_exact_parent_child_relationship_and_release_token() {
    let (kernel, context) = bootstrap(15_010);
    let generation = publish(&context, 0x200);
    let plan =
        ClonePlan::from_flags(LinuxCloneFlags::VFORK | LinuxCloneFlags::VM).expect("vfork plan");
    let published = kernel
        .reserve_fork(&context, plan, "continuation vfork".to_owned(), None)
        .expect("reserve vfork")
        .prepare_reference(ThreadId::synthetic_for_tests(15_011))
        .expect("prepare vfork")
        .commit()
        .expect("publish vfork");
    let (child, wait) = published.into_parts().expect("start child");
    let wait = wait.expect("vfork parent wait");
    let current = context
        .task_binding()
        .capture(context.thread().key().tid)
        .expect("recapture parent after vfork publication");
    let continuation = BlockedContinuation::from_vfork_parent(
        capture(&current, generation, ContinuationBackend::Hvpatch),
        child.task().key(),
        wait.clone(),
    )
    .expect("owned vfork wait");
    assert_eq!(continuation.family(), ContinuationFamily::VforkParent);
    assert_eq!(continuation.vfork_child(), Some(child.task().key()));
    assert_send_static(&continuation);
    assert!(matches!(
        continuation.resume(ContinuationEvent::Ready, &current),
        Err(ContinuationResumeError::PrematureVforkRelease)
    ));

    let probe = Arc::new(AtomicUsize::new(0));
    let make = || {
        let mut continuation = BlockedContinuation::from_vfork_parent(
            capture(&current, generation, ContinuationBackend::Hvpatch),
            child.task().key(),
            wait.clone(),
        )
        .expect("repeat owned vfork wait");
        continuation.install_cleanup_probe(Arc::clone(&probe));
        continuation
    };
    let mut specimens = std::iter::repeat_with(make).take(6).collect::<Vec<_>>();

    kernel
        .exit_task(
            child.task().key().id,
            crate::kernel::LinuxWaitStatus::from_wait_encoding(0),
            None,
        )
        .expect("publish exact vfork child release");
    let fresh = context
        .task_binding()
        .capture(context.thread().key().tid)
        .expect("recapture parent after exact vfork release");
    let ready = specimens
        .remove(0)
        .resume(ContinuationEvent::Ready, &fresh)
        .expect("vfork release result");
    assert_eq!(
        ready.completion,
        ContinuationCompletion::Return(i64::from(child.task().key().id.raw()))
    );
    for cause in [
        CancellationCause::Exec,
        CancellationCause::ThreadExit,
        CancellationCause::ProcessExit,
        CancellationCause::Quiesce,
    ] {
        assert_eq!(specimens.remove(0).cancel(cause).cleanup_count(), 1);
    }
    drop(specimens.pop().expect("drop specimen"));
    assert_eq!(probe.load(Ordering::SeqCst), 6);
}

#[test]
fn hvpatch_rejects_host_proc_wait_and_resolves_child_selectors_in_kernel_domain() {
    let (_kernel, context) = bootstrap(15_020);
    let generation = publish(&context, 0x300);
    let error = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnProcExit {
            pid: 22,
            sig_mask: WaitSigMask::NONE,
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect_err("HvPatch may never infer a child from a Darwin pid");
    assert_eq!(error, ContinuationBuildError::HostProcessWaitOnHvpatch);

    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnHvpatchChild {
            target: None,
            sig_mask: WaitSigMask::NONE,
            precheck: crate::kernel::ChildWaitPrecheck::unsampled(),
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("kernel child selector");
    assert_eq!(
        continuation.child_selector(),
        Some(ChildSelector::AnyChildOf(context.task().key()))
    );
}

#[test]
fn hvpatch_child_enrollment_requires_a_real_task_event() {
    let (kernel, context) = bootstrap(15_021);
    let generation = publish(&context, 0x301);
    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnHvpatchChild {
            target: None,
            sig_mask: WaitSigMask::NONE,
            precheck: crate::kernel::ChildWaitPrecheck::unsampled(),
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("kernel child continuation");
    let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let service = CarrierWaitService::new(scheduler);
    let mut registration = service.prepare_registration(&continuation);
    let token = registration.wake_token();
    service
        .enroll(&mut registration)
        .expect("enroll quiet child wait");

    assert_eq!(
        service
            .inner
            .state
            .lock()
            .entries
            .get(&token.continuation)
            .expect("live child registration")
            .state,
        RegistrationState::Enrolled,
        "enrollment polling must not manufacture child readiness"
    );

    assert!(kernel.publish_task_event_and_wake(context.task().key(), || true));
    assert_eq!(
        service
            .inner
            .state
            .lock()
            .entries
            .get(&token.continuation)
            .expect("woken child registration")
            .state,
        RegistrationState::Ready,
        "a real task event must redispatch the child wait"
    );
}

#[test]
fn diagnostic_names_the_wait_and_whether_a_producer_can_still_reach_it() {
    let (kernel, context) = bootstrap(15_120);
    let generation = publish(&context, 0x360);
    let mut continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnHvpatchChild {
            target: None,
            sig_mask: WaitSigMask::NONE,
            precheck: crate::kernel::ChildWaitPrecheck::unsampled(),
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("kernel child continuation");
    let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let service = CarrierWaitService::new(scheduler);
    let mut registration = service.prepare_registration(&continuation);
    let token = registration.wake_token();
    service
        .enroll(&mut registration)
        .expect("enroll child wait");
    continuation
        .attach_registration(registration)
        .expect("bind registration");

    let enrolled = continuation.diagnostic();
    assert_eq!(enrolled.id, continuation.id().raw());
    assert_eq!(enrolled.family, "wait-on-hvpatch-child");
    assert!(
        enrolled.detail.starts_with("process any-child-of="),
        "detail must name the child selector, got {}",
        enrolled.detail
    );
    let bound = enrolled.registration.expect("registration diagnostic");
    assert_eq!(bound.state, "enrolled");
    assert!(bound.service_alive);
    assert_eq!(bound.event, None);
    assert_eq!(bound.continuation, token.continuation.raw());

    // A wake the thread has not consumed yet reads `ready`: the producer
    // fired and the scheduler owes the thread a redispatch. That is a
    // different bug from "nothing can wake it", so the two must not
    // render the same.
    assert!(kernel.publish_task_event_and_wake(context.task().key(), || true));
    assert_eq!(
        continuation
            .diagnostic()
            .registration
            .expect("registration diagnostic")
            .state,
        "ready"
    );
    assert_eq!(
        continuation
            .diagnostic()
            .registration
            .expect("registration diagnostic")
            .event,
        Some("ready")
    );

    // Once the service forgets the entry, nothing can publish into it.
    // This is the lost-wake signature a wedge snapshot has to be able to
    // state on its own.
    service
        .inner
        .state
        .lock()
        .entries
        .remove(&token.continuation);
    assert_eq!(
        continuation
            .diagnostic()
            .registration
            .expect("registration diagnostic")
            .state,
        "absent"
    );
}

/// A child that exits AFTER the wait scan found nothing but BEFORE the
/// continuation is captured must still wake the parent.
///
/// This is the `go build` wedge: the exit's producer edge is published
/// while the syscall is still returning `StillRunning`, the capture then
/// re-reads the parent's wake generation and sees the post-edge value,
/// and `subscribe_wake` enrols past the only edge that will ever fire.
/// The snapshot signature is a zombie child, an `enrolled` parent wait
/// with `event: None`, and `observed_wake == current_wake`
/// (`target/perf/wedges/ohw-r2c-32079`).
///
/// Red-first receipt: build the continuation from a precheck sampled
/// AFTER the edge (`ChildWaitPrecheck::unsampled()` is not enough —
/// use the post-edge generation) and this assertion fails, which is the
/// behaviour every capture-time reading had.
#[test]
fn child_wait_enrolled_after_the_exit_edge_still_sees_it() {
    let (kernel, context) = bootstrap(15_121);
    let generation = publish(&context, 0x361);

    // What the wait scan observed: no child reapable, parent at this
    // wake generation.
    let precheck = crate::kernel::ChildWaitPrecheck::for_test(context.task().wake_generation());

    // The child exits here — after the scan, before the capture — and its
    // terminal path publishes the parent's wake edge.
    // Returns false: no listener is enrolled yet — which is exactly the
    // problem. The generation still moves.
    let _ = context.task().publish_wake_subscriptions();
    assert_ne!(
        context.task().wake_generation(),
        precheck.wake_generation(),
        "the simulated exit must actually move the parent's generation"
    );

    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnHvpatchChild {
            target: None,
            sig_mask: WaitSigMask::NONE,
            precheck,
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("kernel child continuation");
    let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let service = CarrierWaitService::new(scheduler);
    let mut registration = service.prepare_registration(&continuation);
    let token = registration.wake_token();
    service
        .enroll(&mut registration)
        .expect("enroll child wait");

    assert_eq!(
        service
            .inner
            .state
            .lock()
            .entries
            .get(&token.continuation)
            .expect("child registration")
            .state,
        RegistrationState::Ready,
        "an exit edge published between the child scan and the capture must \
         still make the wait ready; enrolling past it parks the parent forever"
    );
}

#[test]
fn futex_wait_ignores_unrelated_task_event_until_generation_changes() {
    let (kernel, context) = bootstrap(15_022);
    let generation = publish(&context, 0x302);
    let futex = Arc::new(FutexTable::new());
    let address = 0xcafe;
    let mut continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::FutexWait {
            wait: futex.prepare_wait(address),
            timeout: None,
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("futex continuation");
    continuation.bind_product_futex(&futex);
    let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let service = CarrierWaitService::new(scheduler);
    let mut registration = service.prepare_registration(&continuation);
    let token = registration.wake_token();
    service
        .enroll(&mut registration)
        .expect("enroll futex wait");

    assert!(kernel.publish_task_event_and_wake(context.task().key(), || true));
    assert_eq!(
        service
            .inner
            .state
            .lock()
            .entries
            .get(&token.continuation())
            .expect("futex registration after unrelated task event")
            .state,
        RegistrationState::Enrolled,
        "an unrelated task event must not manufacture futex readiness",
    );

    assert_eq!(futex.wake(address, 1), 1);
    assert_eq!(
        await_event(&service, token).expect("exact futex generation wake"),
        ContinuationEvent::Ready,
    );
}

#[test]
fn logical_group_wait_dispatch_builds_an_any_child_continuation() {
    let _lane = crate::dispatch::HvpatchLaneScope::force(false);
    let (process, root) = crate::hvpatch::process_context_for_tests(15_025);
    let mut dispatcher = crate::dispatch::SyscallDispatcher::new();
    dispatcher.bind_hvpatch_process(process);
    let _child = root
        .kernel()
        .reserve_fork(
            &root,
            ClonePlan::from_flags(LinuxCloneFlags::empty()).unwrap(),
            "group-wait-child".to_owned(),
            None,
        )
        .unwrap()
        .prepare_reference(ThreadId::synthetic_for_tests(15_026))
        .unwrap()
        .commit()
        .unwrap()
        .into_parts()
        .unwrap()
        .0;
    let root = root
        .kernel()
        .context(root.task().key().id, root.thread().key().tid)
        .unwrap();
    let generation = publish(&root, 0x325);
    let mut memory = crate::dispatch::LinearMemory::new(0x4000, vec![0; 0x100]);
    let outcome = dispatcher
        .dispatch(
            &root,
            SyscallRequest::new(260, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &crate::compat::CompatReporter::default(),
        )
        .unwrap();
    assert!(matches!(
        &outcome,
        DispatchOutcome::WaitOnHvpatchChild { target: None, .. }
    ));
    let continuation = BlockedContinuation::from_dispatch_outcome(
        outcome,
        capture(&root, generation, ContinuationBackend::Hvpatch),
    )
    .expect("group wait must build without StaleChildSelector");
    assert_eq!(
        continuation.child_selector(),
        Some(ChildSelector::AnyChildOf(root.task().key()))
    );
}

struct RaceFixture {
    scheduler: Arc<Scheduler>,
    service: Arc<CarrierWaitService>,
    context: KernelContext,
    executor: crate::kernel::ExecutorRegistration,
    running: crate::kernel::RunnableThread,
    continuation: BlockedContinuation,
    registration: ContinuationRegistration,
}

fn race_fixture(pid: i32) -> RaceFixture {
    let (kernel, context) = bootstrap(pid);
    let generation = publish(&context, pid as u64);
    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnSleep {
            duration: Duration::from_secs(30),
            remaining: Some(crate::dispatch::GuestPtr(0xa000)),
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("continuation");
    let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let executor = scheduler
        .register_executor(Arc::new(TestKick::default()))
        .expect("executor");
    scheduler
        .make_runnable(context.thread().key())
        .expect("queue root");
    let running = scheduler.take(&executor).expect("claim root");
    let service = Arc::new(CarrierWaitService::new(Arc::clone(&scheduler)));
    let registration = service.prepare_registration(&continuation);
    RaceFixture {
        scheduler,
        service,
        context,
        executor,
        running,
        continuation,
        registration,
    }
}

fn control_quantum_fixture(
    pid: i32,
    family: ContinuationFamily,
) -> (RaceFixture, Option<Arc<FutexTable>>) {
    let (kernel, context) = bootstrap(pid);
    let generation = publish(&context, pid as u64);
    let mut futex = None;
    let outcome = match family {
        ContinuationFamily::WaitOnSleep => DispatchOutcome::WaitOnSleep {
            duration: Duration::from_secs(30),
            remaining: Some(crate::dispatch::GuestPtr(0xa000)),
        },
        ContinuationFamily::WaitOnPollFds => DispatchOutcome::WaitOnFds {
            fds: WaitFds::empty(),
            timeout: Some(Duration::from_secs(30)),
            sig_mask: WaitSigMask::NONE,
            completion: FdWaitCompletion::Poll { on_timeout: 0 },
        },
        ContinuationFamily::FutexWait => {
            let table = Arc::new(FutexTable::new());
            let outcome = DispatchOutcome::FutexWait {
                wait: table.prepare_wait(0xcafe),
                timeout: Some(Duration::from_secs(30)),
            };
            futex = Some(table);
            outcome
        }
        other => panic!("unsupported control-quantum fixture {other:?}"),
    };
    let mut continuation = BlockedContinuation::from_dispatch_outcome(
        outcome,
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("control-quantum continuation");
    if let Some(table) = futex.as_ref() {
        continuation.bind_product_futex(table);
    }
    let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let executor = scheduler
        .register_executor(Arc::new(TestKick::default()))
        .expect("executor");
    scheduler
        .make_runnable(context.thread().key())
        .expect("queue root");
    let running = scheduler.take(&executor).expect("claim root");
    let service = Arc::new(CarrierWaitService::new(Arc::clone(&scheduler)));
    let registration = service.prepare_registration(&continuation);
    (
        RaceFixture {
            scheduler,
            service,
            context,
            executor,
            running,
            continuation,
            registration,
        },
        futex,
    )
}

#[test]
fn control_quantum_preserves_sleep_poll_and_futex_until_real_readiness() {
    for (offset, family) in [
        ContinuationFamily::WaitOnSleep,
        ContinuationFamily::WaitOnPollFds,
        ContinuationFamily::FutexWait,
    ]
    .into_iter()
    .enumerate()
    {
        let (mut fixture, futex) = control_quantum_fixture(15_140 + offset as i32, family);
        fixture
            .scheduler
            .begin_switch_out(&fixture.running)
            .expect("switch out");
        fixture
            .service
            .enroll(&mut fixture.registration)
            .expect("enroll");
        let expected_id = fixture.continuation.id();
        let expected_deadline = fixture.continuation.deadline();
        fixture
            .scheduler
            .settle_blocked_continuation(
                fixture.running,
                fixture.continuation,
                fixture.registration,
            )
            .expect("park original continuation");

        assert_eq!(
            fixture
                .scheduler
                .wake_control(fixture.context.thread().key())
                .expect("control wake"),
            crate::kernel::WakeDisposition::Queued
        );
        let running = fixture
            .scheduler
            .take(&fixture.executor)
            .expect("claim control quantum");
        let preserved = running
            .lease()
            .blocked_continuation()
            .expect("preserved continuation");
        assert_eq!(preserved.family(), family);
        assert_eq!(preserved.id(), expected_id);
        assert_eq!(preserved.deadline(), expected_deadline);
        assert!(
            preserved.ready_event().is_err(),
            "control work fabricated {family:?} readiness"
        );
        let quantum = fixture
            .context
            .thread()
            .finish_scheduler_control_quantum(fixture.context.thread().key())
            .expect("finish control quantum");
        assert_eq!(quantum.blocked_reason, Some(BlockedReason::HostWait));
        fixture
            .scheduler
            .settle_blocked(running, quantum.blocked_reason.expect("blocked reason"))
            .expect("repark exact continuation");

        if let Some(table) = futex.as_ref() {
            // A futex wait resumes with `Return(0)`, which asserts a
            // counted `FUTEX_WAKE`; a generic scheduler wake is not one.
            assert_eq!(
                fixture
                    .scheduler
                    .wake(fixture.context.thread().key())
                    .expect("generic wake of parked futex waiter"),
                crate::kernel::WakeDisposition::Pending
            );
            assert_eq!(table.wake(0xcafe, 1), 1, "exact futex producer");
        } else {
            assert_eq!(
                fixture
                    .scheduler
                    .wake(fixture.context.thread().key())
                    .expect("real producer wake"),
                crate::kernel::WakeDisposition::Queued
            );
        }
        let ready = fixture
            .scheduler
            .take(&fixture.executor)
            .expect("claim real readiness");
        let resumed = ready
            .lease()
            .blocked_continuation()
            .expect("ready continuation");
        assert_eq!(resumed.id(), expected_id);
        assert_eq!(resumed.deadline(), expected_deadline);
        assert_eq!(
            resumed.ready_event().expect("real readiness event"),
            ContinuationEvent::Ready
        );
        fixture
            .scheduler
            .settle_exited(ready)
            .expect("retire fixture");
    }
}

#[test]
fn real_readiness_between_control_queue_and_claim_is_not_lost() {
    let (mut fixture, _futex) = control_quantum_fixture(15_143, ContinuationFamily::WaitOnSleep);
    fixture
        .scheduler
        .begin_switch_out(&fixture.running)
        .expect("switch out");
    fixture
        .service
        .enroll(&mut fixture.registration)
        .expect("enroll");
    let expected_id = fixture.continuation.id();
    fixture
        .scheduler
        .settle_blocked_continuation(fixture.running, fixture.continuation, fixture.registration)
        .expect("park");
    assert_eq!(
        fixture
            .scheduler
            .wake_control(fixture.context.thread().key())
            .expect("queue control"),
        crate::kernel::WakeDisposition::Queued
    );
    assert_eq!(
        fixture
            .scheduler
            .wake(fixture.context.thread().key())
            .expect("producer races before claim"),
        crate::kernel::WakeDisposition::Coalesced
    );
    let ready = fixture
        .scheduler
        .take(&fixture.executor)
        .expect("claim control plus real readiness");
    let continuation = ready
        .lease()
        .blocked_continuation()
        .expect("preserved continuation");
    assert_eq!(continuation.id(), expected_id);
    assert_eq!(
        continuation.ready_event().expect("real event survives"),
        ContinuationEvent::Ready
    );
    fixture
        .context
        .thread()
        .finish_scheduler_control_quantum(fixture.context.thread().key())
        .expect("finish control quantum");
    fixture
        .scheduler
        .settle_exited(ready)
        .expect("retire fixture");
}

#[derive(Debug, Default)]
struct TestKick {
    binding: parking_lot::Mutex<Option<crate::kernel::ExecutorBinding>>,
    kicks: AtomicUsize,
}

impl crate::kernel::ExecutorKick for TestKick {
    fn try_bind(&self, binding: crate::kernel::ExecutorBinding) -> bool {
        let mut current = self.binding.lock();
        if current.is_some() {
            return false;
        }
        *current = Some(binding);
        true
    }

    fn unbind(&self, binding: crate::kernel::ExecutorBinding) {
        let mut current = self.binding.lock();
        if *current == Some(binding) {
            *current = None;
        }
    }

    fn rebind_exact_with(
        &self,
        predecessor: crate::kernel::ExecutorBinding,
        successor: crate::kernel::ExecutorBinding,
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

    fn deliver_exact(&self, token: crate::kernel::ExecutorKickToken) -> bool {
        let current = self.binding.lock();
        if current.as_ref().is_none_or(|binding| {
            binding.executor() != token.executor()
                || binding.executor_epoch() != token.executor_epoch()
                || binding.thread() != token.thread()
                || binding.generation() != token.generation()
        }) {
            return false;
        }
        self.kicks.fetch_add(1, Ordering::SeqCst);
        true
    }

    fn current_binding(&self) -> Option<crate::kernel::ExecutorBinding> {
        *self.binding.lock()
    }
}

fn publish_with_real_barrier(
    service: Arc<CarrierWaitService>,
    token: ContinuationWakeToken,
) -> thread::JoinHandle<WakePublishReceipt> {
    let barrier = Arc::new(Barrier::new(2));
    let child_barrier = Arc::clone(&barrier);
    let join = thread::spawn(move || {
        child_barrier.wait();
        service.publish_ready(token)
    });
    barrier.wait();
    join
}

#[test]
fn event_before_enrollment_is_durable_and_settles_runnable_once() {
    let mut fixture = race_fixture(15_100);
    let receipt = publish_with_real_barrier(
        Arc::clone(&fixture.service),
        fixture.registration.wake_token(),
    )
    .join()
    .expect("publisher");
    assert!(receipt.first_publication());
    fixture
        .scheduler
        .begin_switch_out(&fixture.running)
        .expect("switch out");
    fixture
        .service
        .enroll(&mut fixture.registration)
        .expect("enroll after event");
    fixture
        .scheduler
        .settle_blocked_continuation(fixture.running, fixture.continuation, fixture.registration)
        .expect("settle");
    assert!(matches!(
        fixture.context.thread().execution_state(),
        ThreadExecutionState::Runnable { .. }
    ));
    assert_eq!(fixture.scheduler.queued_len(), 1);
}

#[test]
fn event_during_switching_out_save_is_durable_and_queues_once() {
    let mut fixture = race_fixture(15_110);
    fixture
        .scheduler
        .begin_switch_out(&fixture.running)
        .expect("switch out");
    fixture
        .service
        .enroll(&mut fixture.registration)
        .expect("enroll");
    let join = publish_with_real_barrier(
        Arc::clone(&fixture.service),
        fixture.registration.wake_token(),
    );
    join.join().expect("publisher");
    fixture
        .scheduler
        .settle_blocked_continuation(fixture.running, fixture.continuation, fixture.registration)
        .expect("settle");
    assert!(matches!(
        fixture.context.thread().execution_state(),
        ThreadExecutionState::Runnable { .. }
    ));
    assert_eq!(fixture.scheduler.queued_len(), 1);
}

#[test]
fn event_after_binding_clear_before_settlement_commit_queues_once() {
    let mut fixture = race_fixture(15_120);
    fixture
        .scheduler
        .begin_switch_out(&fixture.running)
        .expect("switch out");
    fixture
        .service
        .enroll(&mut fixture.registration)
        .expect("enroll");
    let at_clear = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    fixture
        .scheduler
        .install_continuation_settlement_barriers(Arc::clone(&at_clear), Arc::clone(&release));
    let scheduler = Arc::clone(&fixture.scheduler);
    let running = fixture.running;
    let continuation = fixture.continuation;
    let registration = fixture.registration;
    let settle = thread::spawn(move || {
        scheduler.settle_blocked_continuation(running, continuation, registration)
    });
    at_clear.wait();
    fixture
        .service
        .publish_ready(fixture.service.last_prepared_token())
        .assert_accepted();
    release.wait();
    settle.join().expect("settler").expect("settled");
    assert!(matches!(
        fixture.context.thread().execution_state(),
        ThreadExecutionState::Runnable { .. }
    ));
    assert_eq!(fixture.scheduler.queued_len(), 1);
}

#[test]
fn event_after_destination_load_before_resume_kicks_exact_generation_once() {
    let mut fixture = race_fixture(15_130);
    fixture
        .scheduler
        .begin_switch_out(&fixture.running)
        .expect("switch out");
    fixture
        .service
        .enroll(&mut fixture.registration)
        .expect("enroll");
    let token = fixture.registration.wake_token();
    fixture
        .scheduler
        .settle_blocked_continuation(fixture.running, fixture.continuation, fixture.registration)
        .expect("block");
    fixture.service.publish_ready(token).assert_accepted();
    let mut destination = fixture
        .scheduler
        .take(&fixture.executor)
        .expect("destination load");
    assert!(matches!(
        fixture.context.thread().execution_state(),
        ThreadExecutionState::Running {
            wake_pending: false,
            ..
        }
    ));
    let join = publish_with_real_barrier(Arc::clone(&fixture.service), token);
    let duplicate = join.join().expect("publisher");
    assert!(
        !duplicate.accepted(),
        "a consumed Ready registration must reject a stale duplicate without waking the successor"
    );
    assert!(matches!(
        fixture.context.thread().execution_state(),
        ThreadExecutionState::Running {
            wake_pending: false,
            ..
        }
    ));
    let continuation = destination
        .lease()
        .blocked_continuation()
        .expect("Kernel-owned continuation migrates in exact lease");
    assert_eq!(continuation.id(), token.continuation());
    let resumed = resume_continuation(
        destination.lease_mut(),
        ContinuationEvent::Timeout,
        &fixture.context,
    )
    .expect("consume exact continuation once");
    assert!(matches!(
        resumed.completion,
        ContinuationCompletion::ReturnWithGuestWrites(0, _)
    ));
    assert_eq!(
        resume_continuation(
            destination.lease_mut(),
            ContinuationEvent::Timeout,
            &fixture.context,
        ),
        Err(ContinuationResumeError::MissingContinuation)
    );
    fixture.scheduler.settle_exited(destination).expect("exit");
    assert_eq!(fixture.scheduler.queued_len(), 0);
}

/// `vforkexecthread` residual (2026-09-01, traced with
/// `hvpatch-executor-claim-sequence.d`): the exec thread parked a
/// continuation at generation g, was claimed at g+1 while the leader's
/// fork quiesce held executor registrations closed, and so re-parked
/// `Blocked(HostWait)` WITHOUT consuming it. The kernel carried the
/// continuation through that lease untouched, the release wake bumped
/// the generation once more, and the resuming lease at g+3 failed the
/// `+1/+2` succession check with `StaleThread` — exit 127 and a fatal
/// MM-authority drop for a thread that had done nothing wrong. Every
/// settlement that carries an unconsumed continuation must re-stamp its
/// authority to the lease that held it, so the succession check stays
/// exact instead of accumulating one generation per re-park.
#[test]
fn continuation_carried_through_unconsumed_lease_resumes_on_next_claim() {
    let mut fixture = race_fixture(15_140);
    fixture
        .scheduler
        .begin_switch_out(&fixture.running)
        .expect("switch out");
    fixture
        .service
        .enroll(&mut fixture.registration)
        .expect("enroll");
    let token = fixture.registration.wake_token();
    let parked_generation = fixture.running.generation();
    fixture
        .scheduler
        .settle_blocked_continuation(fixture.running, fixture.continuation, fixture.registration)
        .expect("block");
    fixture.service.publish_ready(token).assert_accepted();
    let refused = fixture
        .scheduler
        .take(&fixture.executor)
        .expect("claim after wake");
    assert_eq!(
        refused
            .lease()
            .blocked_continuation()
            .expect("continuation rides the claiming lease")
            .authority()
            .execution_generation(),
        parked_generation
    );
    // The executor could not be admitted (fork quiesce held registration
    // closed): it re-parks without touching the continuation.
    fixture
        .scheduler
        .settle_blocked(refused, crate::kernel::objects::BlockedReason::HostWait)
        .expect("re-park without consuming");
    assert!(matches!(
        fixture.context.thread().execution_state(),
        ThreadExecutionState::Blocked { .. }
    ));
    let thread = fixture.context.thread().key();
    fixture.scheduler.wake(thread).expect("release wake");
    let mut resumed = fixture
        .scheduler
        .take(&fixture.executor)
        .expect("claim after release");
    let carried = resumed
        .lease()
        .blocked_continuation()
        .expect("continuation still rides the lease");
    assert_eq!(carried.id(), token.continuation());
    let result = resume_continuation(
        resumed.lease_mut(),
        ContinuationEvent::Timeout,
        &fixture.context,
    )
    .expect("a continuation held across an unconsumed lease resumes on the next claim");
    assert!(matches!(
        result.completion,
        ContinuationCompletion::ReturnWithGuestWrites(0, _)
    ));
    fixture.scheduler.settle_exited(resumed).expect("exit");
}

#[test]
fn timeout_signal_exec_exit_and_drop_cleanup_are_literal_for_every_family() {
    let (_kernel, context) = bootstrap(15_200);
    let generation = publish(&context, 0x400);
    for family in DISPATCH_FAMILIES {
        let backend = if matches!(
            family,
            ContinuationFamily::WaitOnProcExit | ContinuationFamily::WaitOnProcState
        ) {
            ContinuationBackend::HostProcessCompatibility
        } else {
            ContinuationBackend::Hvpatch
        };
        let probe = Arc::new(AtomicUsize::new(0));
        let make = || {
            let mut continuation = BlockedContinuation::from_dispatch_outcome(
                outcome_for(family, context.thread().registry_id()),
                capture(&context, generation, backend),
            )
            .expect("continuation");
            continuation.install_cleanup_probe(Arc::clone(&probe));
            continuation
        };

        let timeout = make()
            .resume(ContinuationEvent::Timeout, &context)
            .expect("timeout result");
        match (family, timeout.completion) {
            (
                ContinuationFamily::FutexWait
                | ContinuationFamily::FutexWaitv
                | ContinuationFamily::SharedFutexWait
                | ContinuationFamily::SharedFutexWaitv,
                ContinuationCompletion::Errno(errno),
            ) => assert_eq!(errno, LINUX_ETIMEDOUT),
            (ContinuationFamily::WaitOnFds, ContinuationCompletion::Return(-11))
            | (ContinuationFamily::WaitOnPollFds, ContinuationCompletion::Return(0))
            | (ContinuationFamily::BlockingHostWrite, ContinuationCompletion::Return(2))
            | (
                ContinuationFamily::WaitOnSharedWord
                | ContinuationFamily::BlockingRecordLock
                | ContinuationFamily::WaitOnProcExit
                | ContinuationFamily::WaitOnProcState
                | ContinuationFamily::WaitOnHvpatchChild,
                ContinuationCompletion::Redispatch,
            ) => {}
            (ContinuationFamily::WaitOnSignals, ContinuationCompletion::Errno(errno)) => {
                assert_eq!(errno, LINUX_EAGAIN)
            }
            (
                ContinuationFamily::WaitOnFdsSelect,
                ContinuationCompletion::ReturnWithGuestWrites(0, writes),
            ) => assert_eq!(writes.len(), 2),
            (
                ContinuationFamily::WaitOnSleep,
                ContinuationCompletion::ReturnWithGuestWrites(0, writes),
            ) => assert_eq!(writes.len(), 1),
            other => panic!("unexpected timeout result: {other:?}"),
        }
        let interrupted = make()
            .resume(ContinuationEvent::Signal, &context)
            .expect("signal result");
        match (&family, &interrupted.completion) {
            (ContinuationFamily::BlockingHostWrite, ContinuationCompletion::Return(2)) => {}
            (
                ContinuationFamily::WaitOnSleep,
                ContinuationCompletion::InterruptedSleep { remaining },
            ) => {
                assert!(remaining.is_some());
            }
            (_, ContinuationCompletion::Errno(errno)) => assert_eq!(*errno, LINUX_EINTR),
            other => panic!("unexpected signal result: {other:?}"),
        }
        if matches!(family, ContinuationFamily::WaitOnSignals) {
            assert_eq!(interrupted.restart(), RestartDecision::NoRestart);
        }
        for cause in [
            CancellationCause::Exec,
            CancellationCause::ThreadExit,
            CancellationCause::ProcessExit,
        ] {
            let receipt = make().cancel(cause);
            assert_eq!(receipt.cause(), cause);
            assert_eq!(receipt.cleanup_count(), 1);
        }
        drop(make());
        assert_eq!(
            probe.load(Ordering::SeqCst),
            6,
            "{family:?} cleans once per terminal path"
        );
    }
}

#[test]
fn select_and_sleep_guest_writes_revalidate_exact_mm_before_any_access() {
    let (_kernel, context) = bootstrap(15_210);
    let generation = publish(&context, 0x500);
    for (family, expected) in [
        (
            ContinuationFamily::WaitOnFdsSelect,
            vec![
                GuestOutputRange::new(
                    GuestVa(0x7000),
                    16,
                    context.shared().mm().id(),
                    context.shared().mm().id().raw(),
                )
                .unwrap(),
                GuestOutputRange::new(
                    GuestVa(0x7100),
                    8,
                    context.shared().mm().id(),
                    context.shared().mm().id().raw(),
                )
                .unwrap(),
            ],
        ),
        (
            ContinuationFamily::WaitOnSleep,
            vec![
                GuestOutputRange::new(
                    GuestVa(0x9000),
                    std::mem::size_of::<libc::timespec>(),
                    context.shared().mm().id(),
                    context.shared().mm().id().raw(),
                )
                .unwrap(),
            ],
        ),
    ] {
        let continuation = BlockedContinuation::from_dispatch_outcome(
            outcome_for(family, context.thread().registry_id()),
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .unwrap();
        assert_eq!(continuation.guest_outputs(), expected);
        let wrong = ResumeContext::for_test(
            context.thread().key(),
            context.task().key(),
            generation,
            context.shared().mm().id(),
            context.shared().mm().id().raw() + 1,
        );
        assert_eq!(
            continuation.authorize_resume(wrong),
            Err(ContinuationResumeError::StaleAddressSpace)
        );
    }
}

#[test]
fn stale_task_mm_fd_and_registration_generations_never_wake_successors() {
    let fixture = race_fixture(15_220);
    let token = fixture.registration.wake_token();
    assert!(
        !fixture
            .service
            .publish_ready(token.with_thread_serial_offset_for_test(1))
            .accepted()
    );
    assert!(
        !fixture
            .service
            .publish_ready(token.with_execution_generation_offset_for_test(1))
            .accepted()
    );
    assert!(
        !fixture
            .service
            .publish_ready(token.with_resource_generation_offset_for_test(1))
            .accepted()
    );
    assert!(
        !fixture
            .service
            .publish_ready(token.with_mm_generation_offset_for_test(1))
            .accepted()
    );
    assert!(
        !fixture
            .service
            .publish_ready(token.with_asid_generation_offset_for_test(1))
            .accepted()
    );
    assert!(
        !fixture
            .service
            .publish_ready(token.with_registration_generation_offset_for_test(1))
            .accepted()
    );
    assert_eq!(fixture.scheduler.queued_len(), 0);
    assert!(matches!(
        fixture.context.thread().execution_state(),
        ThreadExecutionState::Running {
            wake_pending: false,
            ..
        }
    ));
}

#[test]
fn fd_wait_pins_exact_open_description_until_cleanup_and_rejects_reuse() {
    let (_kernel, context) = bootstrap(15_225);
    let generation = publish(&context, 0x551);
    let authority = install_test_fd_authority(&context, 0);
    let fds = pipe_pair();
    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::raw(vec![(fds[0], libc::POLLIN)]).with_slot_authorities(vec![authority]),
            timeout: None,
            sig_mask: WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd { on_timeout: 0 },
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("pin exact open description");
    let pinned = continuation.pinned_fds_for_test();
    assert_eq!(pinned.len(), 1);
    close_pair(fds);
    assert_ne!(unsafe { libc::fcntl(pinned[0], libc::F_GETFD) }, -1);
    drop(continuation);
    assert_eq!(unsafe { libc::fcntl(pinned[0], libc::F_GETFD) }, -1);
}

#[test]
fn fd_wait_subscription_rejects_close_reuse_before_redispatch() {
    let (kernel, context) = bootstrap(15_226);
    let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let service = CarrierWaitService::new(scheduler);
    let generation = publish(&context, 0x552);
    let files = context.resources().files();
    let number = crate::kernel::FileSlotNumber::for_open_fd(0).expect("stdin slot");
    let ids = crate::kernel::ObjectIdRegistry::new();
    files.install(
        number,
        Arc::new(crate::kernel::FileDescription::regular(
            ids.file_description_id().expect("original description"),
        )),
        false,
    );
    let authority = files
        .capture_slot_authority(number)
        .expect("exact stdin authority");
    let fds = pipe_pair();
    let mut continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::raw_one(fds[0], libc::POLLIN).with_slot_authorities(vec![authority]),
            timeout: None,
            sig_mask: WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd { on_timeout: 0 },
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("fd-authorized continuation");
    let mut registration = service.prepare_registration(&continuation);
    service.enroll(&mut registration).expect("enroll fd slot");
    let token = registration.wake_token();
    continuation
        .attach_registration(registration)
        .expect("attach exact registration");

    let successor = Arc::new(crate::kernel::FileDescription::regular(
        ids.file_description_id().expect("successor description"),
    ));
    files.install(number, successor, false);
    assert_eq!(
        await_event(&service, token).expect("slot replacement readiness"),
        ContinuationEvent::Ready
    );
    assert_eq!(
        continuation.resume(ContinuationEvent::Ready, &context),
        Err(ContinuationResumeError::StaleFileSlot)
    );
    close_pair(fds);
}

#[test]
fn epoll_strict_owner_and_watched_source_authority_have_distinct_resume_results() {
    let run_case = |pid: i32, replace_epfd: bool| {
        let (kernel, context) = bootstrap(pid);
        let generation = publish(&context, 0xa00);
        let files = context.resources().files();
        let epfd = install_test_fd_authority(&context, 40);
        let watched = install_test_fd_authority(&context, 41);
        let fds = WaitFds::empty()
            .with_redispatch_and_watched_slots(&files, [40], [41])
            .expect("split epoll authority");
        let continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnFds {
                fds,
                timeout: None,
                sig_mask: WaitSigMask::NONE,
                completion: FdWaitCompletion::Fd { on_timeout: 0 },
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("epoll continuation");
        let scheduler = Arc::new(Scheduler::new(kernel));
        let service = CarrierWaitService::new(scheduler);
        let mut registration = service.prepare_registration(&continuation);
        service
            .enroll(&mut registration)
            .expect("enroll epoll wait");
        let replacement = if replace_epfd { epfd } else { watched };
        let number = crate::kernel::FileSlotNumber::for_open_fd(if replace_epfd { 40 } else { 41 })
            .expect("replacement slot");
        let ids = crate::kernel::ObjectIdRegistry::new();
        files.install(
            number,
            Arc::new(crate::kernel::FileDescription::regular(
                ids.file_description_id().expect("successor description"),
            )),
            false,
        );
        let event =
            await_event(&service, registration.wake_token()).expect("slot generation publication");
        assert_eq!(event, ContinuationEvent::Ready);
        assert!(!files.validate_slot_authority(replacement));
        continuation.resume(event, &context)
    };

    let watched = run_case(15_461, false).expect("watched change recomputes epoll");
    assert_eq!(watched.completion, ContinuationCompletion::Redispatch);
    assert_eq!(
        run_case(15_462, true),
        Err(ContinuationResumeError::StaleFileSlot),
        "strict epfd reuse is EBADF authority failure"
    );
}

#[test]
fn hvpatch_fd_wait_without_explicit_slot_authority_fails_closed() {
    let (_kernel, context) = bootstrap(15_227);
    let generation = publish(&context, 0x554);
    let _fallback_would_have_matched = install_test_fd_authority(&context, 0);
    let fds = pipe_pair();
    let result = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::raw_one(fds[0], libc::POLLIN),
            timeout: None,
            sig_mask: WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd { on_timeout: 0 },
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    );
    assert!(matches!(result, Err(ContinuationBuildError::FdPinFailed)));
    close_pair(fds);
}

#[test]
fn hvpatch_fd_less_wait_authorizes_empty_slot_authority() {
    let (_kernel, context) = bootstrap(15_228);
    let generation = publish(&context, 0x555);
    for fds in [
        WaitFds::raw(Vec::new()),
        WaitFds::raw(Vec::new()).with_slot_authorities(Vec::new()),
        WaitFds::empty(),
    ] {
        let result = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnFds {
                fds,
                timeout: None,
                sig_mask: WaitSigMask::NONE,
                completion: FdWaitCompletion::Fd { on_timeout: 0 },
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        );
        assert!(result.is_ok(), "fd-less wait should accept empty authority");
    }
}

#[test]
fn hvpatch_synthetic_negative_fd_wait_accepts_slot_authority_and_task_event_wakes() {
    let (kernel, context) = bootstrap(15_229);
    let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let service = CarrierWaitService::new(scheduler);
    let authority = install_test_fd_authority(&context, 3);
    let generation = publish(&context, 0x556);
    let fds = WaitFds::raw_one(-1, 0).with_slot_authorities(vec![authority]);
    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds,
            timeout: None,
            sig_mask: WaitSigMask::NONE,
            completion: FdWaitCompletion::Poll { on_timeout: 0 },
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("synthetic fd continuation");
    let mut registration = service.prepare_registration(&continuation);
    service
        .enroll(&mut registration)
        .expect("enroll synthetic fd wait");
    assert_eq!(
        service
            .inner
            .state
            .lock()
            .entries
            .get(&registration.wake_token().continuation())
            .expect("entry")
            .state,
        RegistrationState::Enrolled
    );

    let target = context.task().key();
    kernel.publish_task_event_and_wake(target, || true);

    let event = await_event(&service, registration.wake_token()).expect("task event wake");
    assert!(matches!(event, ContinuationEvent::Ready));
}

#[test]
fn shared_wait_service_is_bounded_and_blocked_tasks_own_no_executor() {
    let mut fixture = race_fixture(15_230);
    let topology = fixture.service.topology();
    assert_eq!(topology.service_threads(), 1);
    assert_eq!(topology.shared_reactors(), 1);
    assert_eq!(topology.record_lock_workers(), 0);
    for _ in 0..256 {
        let continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnSleep {
                duration: Duration::from_secs(30),
                remaining: None,
            },
            ContinuationCapture::from_lease(
                &fixture.context,
                fixture.running.lease(),
                request(73),
                RestartClass::RestartSyscall,
                ContinuationBackend::Hvpatch,
            )
            .expect("running lease capture"),
        )
        .unwrap();
        let mut registration = fixture.service.prepare_registration(&continuation);
        fixture.service.enroll(&mut registration).unwrap();
        fixture.service.cancel_registration(registration).unwrap();
        drop(continuation);
    }
    assert_eq!(fixture.service.topology(), topology);
    fixture
        .scheduler
        .begin_switch_out(&fixture.running)
        .expect("switch out");
    fixture
        .service
        .enroll(&mut fixture.registration)
        .expect("enroll");
    fixture
        .scheduler
        .settle_blocked_continuation(fixture.running, fixture.continuation, fixture.registration)
        .expect("block");
    assert!(matches!(
        fixture.context.thread().execution_state(),
        ThreadExecutionState::Blocked { .. }
    ));
    assert!(
        fixture
            .scheduler
            .binding_for_thread(fixture.context.thread().key())
            .is_none()
    );
}

#[test]
fn cancelled_contended_record_locks_do_not_consume_shared_worker_capacity() {
    let (kernel, context) = bootstrap(15_231);
    let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let service = CarrierWaitService::new(scheduler);
    assert_eq!(service.topology().record_lock_workers(), 0);
    let generation = publish(&context, 0x553);
    let contention = crate::dispatch::RecordLockContentionFixture::new();

    for serial in [2, 3] {
        let mut continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::BlockingRecordLock(
                contention.waiter(ThreadId::synthetic_for_tests(15_231), serial),
            ),
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("contended record-lock continuation");
        let mut registration = service.prepare_registration(&continuation);
        service
            .enroll(&mut registration)
            .expect("enroll contention");
        continuation
            .attach_registration(registration)
            .expect("attach contention");
        let receipt = continuation.cancel(CancellationCause::ThreadExit);
        assert_eq!(receipt.cleanup_count(), 1);
    }

    let mut successful = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::BlockingRecordLock(
            contention.waiter(ThreadId::synthetic_for_tests(15_231), 4),
        ),
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("third record-lock continuation");
    let mut registration = service.prepare_registration(&successful);
    service
        .enroll(&mut registration)
        .expect("enroll third lock");
    let token = registration.wake_token();
    successful
        .attach_registration(registration)
        .expect("attach third lock");
    contention.release_blocker();
    service.nudge_reactor_for_test();
    assert_eq!(
        await_event(&service, token).expect("third lock completes"),
        ContinuationEvent::Ready
    );
    assert_eq!(
        successful
            .resume(ContinuationEvent::Ready, &context)
            .expect("third lock resume")
            .completion,
        ContinuationCompletion::Return(0)
    );
}

#[test]
fn shared_reactor_observes_real_fd_and_timer_readiness_without_private_waiters() {
    let (kernel, context) = bootstrap(15_231);
    let generation = publish(&context, 0x552);
    let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let service = CarrierWaitService::new(Arc::clone(&scheduler));
    let authority = install_test_fd_authority(&context, 0);
    let fds = pipe_pair();
    let fd_continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::raw(vec![(fds[0], libc::POLLIN)]).with_slot_authorities(vec![authority]),
            timeout: Some(Duration::from_secs(1)),
            sig_mask: WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd { on_timeout: 0 },
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("fd continuation");
    let mut fd_registration = service.prepare_registration(&fd_continuation);
    service.enroll(&mut fd_registration).expect("enroll fd");
    let fd_token = fd_registration.wake_token();
    assert_eq!(unsafe { libc::write(fds[1], b"x".as_ptr().cast(), 1) }, 1);
    assert_eq!(
        await_event(&service, fd_token).expect("fd event"),
        ContinuationEvent::Ready
    );
    assert!(service.cancel_registration(fd_registration).is_err());
    drop(fd_continuation);
    close_pair(fds);

    let timer = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnSleep {
            duration: Duration::from_millis(5),
            remaining: None,
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("timer continuation");
    let mut timer_registration = service.prepare_registration(&timer);
    service
        .enroll(&mut timer_registration)
        .expect("enroll timer");
    assert_eq!(
        await_event(&service, timer_registration.wake_token()).expect("timer event"),
        ContinuationEvent::Timeout
    );
    assert_eq!(service.topology().service_threads(), 1);
    assert_eq!(service.topology().shared_reactors(), 1);
    assert_eq!(service.topology().record_lock_workers(), 0);
}

#[test]
fn shared_reactor_rechecks_private_futex_and_shared_word_producer_state() {
    let (kernel, context) = bootstrap(15_232);
    let generation = publish(&context, 0x553);
    let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let service = CarrierWaitService::new(scheduler);

    let futex = Arc::new(FutexTable::new());
    let wait = futex.prepare_wait(0xfeed);
    futex.wake(0xfeed, 1);
    let mut private = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::FutexWait {
            wait,
            timeout: Some(Duration::from_secs(1)),
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("private futex continuation");
    private.bind_product_futex(&futex);
    let mut registration = service.prepare_registration(&private);
    service.enroll(&mut registration).expect("enroll futex");
    assert_eq!(
        await_event(&service, registration.wake_token())
            .expect("event-before-registration generation recheck"),
        ContinuationEvent::Ready
    );
    drop(private);

    let word = std::sync::atomic::AtomicU32::new(7);
    let location = SharedFutexLocation::Direct {
        word: HostVa((&word as *const std::sync::atomic::AtomicU32) as usize),
        waiter_key: 0xbeef,
    };
    let shared = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnSharedWord {
            location,
            waiter_key: 0xbeef,
            generation: carrick_thread::platform_futex::carrier_shared_futex_table()
                .prepare_wait(0xbeef),
            value: 7,
            sysv: None,
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("shared-word continuation");
    let mut registration = service.prepare_registration(&shared);
    service
        .enroll(&mut registration)
        .expect("enroll shared word");
    word.store(8, Ordering::Release);
    carrick_thread::platform_futex::carrier_shared_futex_table().wake(0xbeef, 1);
    assert_eq!(
        await_event(&service, registration.wake_token()).expect("shared word durable recheck"),
        ContinuationEvent::Ready
    );
}

#[test]
fn shared_reactor_drives_write_record_signal_and_vfork_sources() {
    let (kernel, context) = bootstrap(15_233);
    let generation = publish(&context, 0x554);
    let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let service = CarrierWaitService::new(scheduler);

    let pipe = pipe_pair();
    let write = BlockingHostWrite::for_tests(
        pipe[1],
        vec![1, 2, 3, 4],
        2,
        context.thread().registry_id(),
        false,
    )
    .expect("write state");
    let mut continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::BlockingHostWrite(write),
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("write continuation");
    let mut registration = service.prepare_registration(&continuation);
    service.enroll(&mut registration).expect("enroll write");
    assert_eq!(
        await_event(&service, registration.wake_token()).expect("write completion"),
        ContinuationEvent::Ready
    );
    continuation
        .attach_registration(registration)
        .expect("attach write registration");
    let completion = continuation
        .resume(ContinuationEvent::Ready, &context)
        .expect("resume write")
        .completion;
    assert!(matches!(
        completion,
        ContinuationCompletion::BlockingWrite {
            outcome: BlockingWriteOutcome::Return(4),
            ..
        }
    ));
    close_pair(pipe);

    // The record-lock source is carrick's own logical table (the host
    // `fcntl` transport is gone), so the reactor reaches its terminal
    // result when the conflicting holder releases — not when a host
    // descriptor errors out.
    let record_contention = crate::dispatch::RecordLockContentionFixture::new();
    let lock = record_contention.waiter(ThreadId::synthetic_for_tests(15_241), 7);
    let lock_continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::BlockingRecordLock(lock),
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("record continuation");
    let mut registration = service.prepare_registration(&lock_continuation);
    service.enroll(&mut registration).expect("enroll record");
    let record_token = registration.wake_token();
    record_contention.release_blocker();
    service.nudge_reactor_for_test();
    assert_eq!(
        await_event(&service, record_token).expect("record terminal result"),
        ContinuationEvent::Ready
    );
    drop(lock_continuation);

    let signal_continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnSignals {
            wait_set: SigSet::from_raw(1 << 9),
            block_mask: SigBlockMask::NONE,
            timeout: None,
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("signal continuation");
    let mut registration = service.prepare_registration(&signal_continuation);
    service.enroll(&mut registration).expect("enroll signal");
    context.signal_authority().enqueue_thread_standard(
        crate::kernel::LinuxSignal::for_signal_number(10).expect("SIGUSR1"),
        None,
    );
    context.task().wake();
    assert_eq!(
        await_event(&service, registration.wake_token()).expect("task signal source"),
        ContinuationEvent::Ready
    );
    drop(signal_continuation);

    let plan =
        ClonePlan::from_flags(LinuxCloneFlags::VFORK | LinuxCloneFlags::VM).expect("vfork plan");
    let published = kernel
        .reserve_fork(&context, plan, "reactor vfork".to_owned(), None)
        .expect("reserve")
        .prepare_reference(ThreadId::synthetic_for_tests(15_234))
        .expect("prepare")
        .commit()
        .expect("commit");
    let (child, wait) = published.into_parts().expect("child start");
    let wait = wait.expect("parent wait");
    let current = context
        .task_binding()
        .capture(context.thread().key().tid)
        .expect("current parent");
    let mut vfork = BlockedContinuation::from_vfork_parent(
        capture(&current, generation, ContinuationBackend::Hvpatch),
        child.task().key(),
        wait,
    )
    .expect("vfork continuation");
    let mut registration = service.prepare_registration(&vfork);
    service.enroll(&mut registration).expect("enroll vfork");
    let vfork_token = registration.wake_token();
    kernel.publish_task_event_and_wake(context.task().key(), || true);
    assert_eq!(
        service
            .inner
            .state
            .lock()
            .entries
            .get(&vfork_token.continuation())
            .expect("vfork registration after unrelated parent task event")
            .state,
        RegistrationState::Enrolled,
        "a parent task event must not release vfork before the exact child exec/exit gate",
    );
    context.signal_authority().enqueue_thread_standard(
        crate::kernel::LinuxSignal::for_signal_number(10).expect("SIGUSR1"),
        None,
    );
    context.task().wake();
    assert_eq!(
        service
            .inner
            .state
            .lock()
            .entries
            .get(&vfork_token.continuation())
            .expect("vfork registration after deliverable parent signal")
            .state,
        RegistrationState::Enrolled,
        "a deliverable parent signal must remain pending until the exact vfork child release",
    );
    kernel
        .exit_task(
            child.task().key().id,
            crate::kernel::LinuxWaitStatus::from_wait_encoding(0),
            None,
        )
        .expect("exit vfork child");
    assert_eq!(
        await_event(&service, registration.wake_token()).expect("vfork release source"),
        ContinuationEvent::Ready
    );
    let fresh = context
        .task_binding()
        .capture(context.thread().key().tid)
        .expect("parent context after child exit");
    assert_ne!(fresh.revision(), context.revision());
    vfork
        .attach_registration(registration)
        .expect("attach released vfork registration");
    assert_eq!(
        vfork
            .resume(ContinuationEvent::Ready, &fresh)
            .expect("revision advance from child exit is legitimate")
            .completion,
        ContinuationCompletion::Return(i64::from(child.task().key().id.raw()))
    );

    let published = kernel
        .reserve_fork(&fresh, plan, "reactor killable vfork".to_owned(), None)
        .expect("reserve killable vfork")
        .prepare_reference(ThreadId::synthetic_for_tests(15_235))
        .expect("prepare killable vfork")
        .commit()
        .expect("commit killable vfork");
    let (kill_child, kill_wait) = published.into_parts().expect("start killable vfork child");
    let kill_wait = kill_wait.expect("killable parent wait");
    let kill_context = fresh
        .task_binding()
        .capture(fresh.thread().key().tid)
        .expect("current killable vfork parent");
    let mut killable_vfork = BlockedContinuation::from_vfork_parent(
        capture(&kill_context, generation, ContinuationBackend::Hvpatch),
        kill_child.task().key(),
        kill_wait.clone(),
    )
    .expect("killable vfork continuation");
    let mut kill_registration = service.prepare_registration(&killable_vfork);
    service
        .enroll(&mut kill_registration)
        .expect("enroll killable vfork");
    kill_context.signal_authority().enqueue_thread_standard(
        crate::kernel::LinuxSignal::for_signal_number(crate::linux_abi::LINUX_SIGKILL)
            .expect("SIGKILL"),
        None,
    );
    kill_context.task().wake();
    let kill_event = await_event(&service, kill_registration.wake_token())
        .expect("SIGKILL interrupts TASK_KILLABLE vfork wait");
    assert!(matches!(
        &kill_event,
        ContinuationEvent::ReservedSignal(signal)
            if signal.signum() == crate::linux_abi::LINUX_SIGKILL
    ));
    assert_eq!(kill_wait.released_reason(), None);
    killable_vfork
        .attach_registration(kill_registration)
        .expect("attach SIGKILL vfork registration");
    let kill_result = killable_vfork
        .resume(kill_event, &kill_context)
        .expect("resume vfork for fatal signal delivery");
    assert_eq!(
        kill_result.completion,
        ContinuationCompletion::Errno(crate::linux_abi::LINUX_EINTR)
    );
    assert_eq!(
        kill_result
            .reserved_signal()
            .expect("reserved fatal signal")
            .signum(),
        crate::linux_abi::LINUX_SIGKILL
    );
    kernel
        .exit_task(
            kill_child.task().key().id,
            crate::kernel::LinuxWaitStatus::from_wait_encoding(0),
            None,
        )
        .expect("retire killable vfork child after parent cancellation");
}

#[test]
fn kernel_owned_continuation_does_not_form_a_thread_or_kernel_arc_cycle() {
    let mut fixture = race_fixture(15_235);
    let thread = Arc::downgrade(fixture.context.thread());
    fixture
        .scheduler
        .begin_switch_out(&fixture.running)
        .expect("switch out");
    fixture
        .service
        .enroll(&mut fixture.registration)
        .expect("enroll");
    fixture
        .scheduler
        .settle_blocked_continuation(fixture.running, fixture.continuation, fixture.registration)
        .expect("block");
    drop(fixture.context);
    drop(fixture.service);
    drop(fixture.scheduler);
    assert!(
        thread.upgrade().is_none(),
        "Kernel Thread -> continuation -> KernelContext would be an unreclaimable cycle"
    );
}

#[test]
fn readiness_cancellation_race_has_one_registration_winner_and_one_cleanup() {
    for pid in 15_300..15_364 {
        let fixture = race_fixture(pid);
        let token = fixture.registration.wake_token();
        let barrier = Arc::new(Barrier::new(4));
        let publish_service = Arc::clone(&fixture.service);
        let publish_barrier = Arc::clone(&barrier);
        let publish = thread::spawn(move || {
            publish_barrier.wait();
            publish_service.publish_ready(token)
        });
        let timeout_service = Arc::clone(&fixture.service);
        let timeout_barrier = Arc::clone(&barrier);
        let timeout = thread::spawn(move || {
            timeout_barrier.wait();
            timeout_service
                .inner
                .publish_event(token, ContinuationEvent::Timeout)
        });
        let cancel_service = Arc::clone(&fixture.service);
        let cancel_barrier = Arc::clone(&barrier);
        let registration = fixture.registration;
        let cancel = thread::spawn(move || {
            cancel_barrier.wait();
            cancel_service.cancel_registration(registration)
        });
        barrier.wait();
        let ready = publish.join().expect("ready publisher");
        let timed_out = timeout.join().expect("timeout publisher");
        let cancelled = cancel.join().expect("canceller");
        assert_eq!(
            usize::from(ready.accepted())
                + usize::from(timed_out.accepted())
                + usize::from(cancelled.is_ok()),
            1,
            "readiness, timeout, and cancellation must have exactly one terminal winner"
        );
        if ready.accepted() || timed_out.accepted() {
            assert!(matches!(
                fixture.context.thread().execution_state(),
                ThreadExecutionState::Running {
                    wake_pending: true,
                    ..
                }
            ));
        } else {
            assert!(matches!(
                fixture.context.thread().execution_state(),
                ThreadExecutionState::Running {
                    wake_pending: false,
                    ..
                }
            ));
        }
        drop(fixture.continuation);
    }
}

#[test]
fn duplicate_ready_and_cancel_after_ready_are_rejected_without_extra_wake() {
    let fixture = race_fixture(15_365);
    let token = fixture.registration.wake_token();
    let first = fixture.service.publish_ready(token);
    assert!(first.accepted());
    assert!(first.first_publication());
    let duplicate = fixture.service.publish_ready(token);
    assert!(!duplicate.accepted());
    assert!(!duplicate.first_publication());
    assert!(
        fixture
            .service
            .cancel_registration(fixture.registration)
            .is_err()
    );
    assert!(matches!(
        fixture.context.thread().execution_state(),
        ThreadExecutionState::Running {
            wake_pending: true,
            ..
        }
    ));
}

#[test]
fn capture_uses_live_lease_mm_and_independent_asid_authority() {
    let (_kernel, context) = bootstrap(15_366);
    let mm = context.shared().mm().id();
    let independent_asid = mm.raw().checked_add(0x4000).expect("test asid");
    context
        .thread()
        .publish_initial_task_state(task_state_with_asid(&context, 0x701, independent_asid))
        .expect("publish independent ASID snapshot");
    let executor =
        crate::kernel::objects::ExecutorId::for_transitional_thread(context.thread().registry_id())
            .expect("executor");
    let lease = context.thread().claim_runnable(executor).expect("lease");
    let capture = ContinuationCapture::from_lease(
        &context,
        &lease,
        request(73),
        RestartClass::RestartSyscall,
        ContinuationBackend::Hvpatch,
    )
    .expect("lease-derived capture");
    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnSleep {
            duration: Duration::from_secs(1),
            remaining: None,
        },
        capture,
    )
    .expect("continuation");
    assert_eq!(continuation.authority().mm(), mm);
    assert_eq!(continuation.authority().asid_generation(), independent_asid);
    assert_eq!(continuation.authority().task_revision(), context.revision());
    drop(lease);
}

#[test]
fn same_task_same_mm_revision_drift_reauthorizes_variant_resources() {
    let (kernel, context) = bootstrap(15_367);
    let generation = publish(&context, 0x702);
    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnSleep {
            duration: Duration::from_secs(1),
            remaining: None,
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("continuation");
    let plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
    let published = kernel
        .reserve_fork(&context, plan, "revision drift child".to_owned(), None)
        .expect("reserve fork")
        .prepare_reference(ThreadId::synthetic_for_tests(15_368))
        .expect("prepare fork")
        .commit()
        .expect("commit fork");
    let (_child, no_vfork_wait) = published.into_parts().expect("start child");
    assert!(no_vfork_wait.is_none());
    let fresh = context
        .task_binding()
        .capture(context.thread().key().tid)
        .expect("fresh same-task context");
    assert_eq!(fresh.task().key(), context.task().key());
    assert_eq!(fresh.shared().mm().id(), context.shared().mm().id());
    assert_ne!(fresh.revision(), context.revision());
    assert!(
        continuation
            .resume(ContinuationEvent::Ready, &fresh)
            .is_ok()
    );
}

#[test]
fn signal_restart_is_derived_from_captured_kernel_action_not_event_input() {
    let (_kernel, context) = bootstrap(15_369);
    let generation = publish(&context, 0x703);
    let signal = crate::kernel::LinuxSignal::for_signal_number(10).expect("SIGUSR1");
    let persistent = SigSet::EMPTY.with(10);
    context.signal_authority().set_blocked(persistent);
    let mut action = carrick_abi::LinuxSigaction::empty();
    action.sa_handler = 0x1234;
    action.sa_flags = carrick_abi::LINUX_SA_RESTART;
    let authority = context.signal_authority();
    authority.install_action(signal, action);
    authority.enqueue_thread_standard(signal, None);
    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::empty(),
            timeout: None,
            sig_mask: WaitSigMask::Replace(SigSet::EMPTY),
            completion: FdWaitCompletion::Fd { on_timeout: 0 },
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("restartable continuation");
    continuation.install_temporary_signal_mask(&context);
    let result = continuation
        .resume(ContinuationEvent::Signal, &context)
        .expect("signal completion");
    assert_eq!(result.restart(), RestartDecision::Restart);
    assert_eq!(
        result.completion,
        ContinuationCompletion::Errno(LINUX_EINTR)
    );
    assert_eq!(context.signal_authority().blocked(), SigSet::EMPTY);
    assert_eq!(
        context.signal_authority().armed_restore_mask(),
        Some(persistent)
    );
}

#[test]
fn reserved_signal_keeps_exact_action_when_opposite_restart_signal_arrives_before_resume() {
    let (_kernel, context) = bootstrap(153_692);
    let generation = publish(&context, 0x707);
    let first = crate::kernel::LinuxSignal::for_signal_number(10).expect("SIGUSR1");
    let second = crate::kernel::LinuxSignal::for_signal_number(12).expect("SIGUSR2");
    let mut restart = carrick_abi::LinuxSigaction::empty();
    restart.sa_handler = 0x1110;
    restart.sa_flags = carrick_abi::LINUX_SA_RESTART;
    let mut no_restart = carrick_abi::LinuxSigaction::empty();
    no_restart.sa_handler = 0x2220;
    context.signal_authority().install_action(first, restart);
    context
        .signal_authority()
        .install_action(second, no_restart);
    context
        .signal_authority()
        .enqueue_thread_standard(first, None);
    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::empty(),
            timeout: None,
            sig_mask: WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd { on_timeout: 0 },
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("continuation");
    let event = SignalReadinessProbe::from_continuation(&continuation)
        .event()
        .expect("first signal readiness");
    assert_eq!(
        event.reserved_signal().expect("exact reservation").signum(),
        10
    );

    context
        .signal_authority()
        .enqueue_thread_standard(second, None);
    let result = continuation.resume(event, &context).expect("resume");
    assert_eq!(result.restart(), RestartDecision::Restart);
    let reserved = result.reserved_signal().expect("reserved delivery");
    assert_eq!(reserved.signum(), 10);
    assert_eq!(reserved.action(), restart);
    assert_ne!(reserved.action(), no_restart);
}

#[test]
fn host_slot_signal_is_reserved_and_cancelled_into_exact_kernel_ownership() {
    let (_kernel, context) = bootstrap(153_693);
    let generation = publish(&context, 0x708);
    let signal = crate::kernel::LinuxSignal::for_signal_number(10).expect("SIGUSR1");
    let persistent = SigSet::EMPTY.with(10);
    context.signal_authority().set_blocked(persistent);
    let mut action = carrick_abi::LinuxSigaction::empty();
    action.sa_handler = 0x3330;
    context.signal_authority().install_action(signal, action);
    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::empty(),
            timeout: None,
            sig_mask: WaitSigMask::Replace(SigSet::EMPTY),
            completion: FdWaitCompletion::Fd { on_timeout: 0 },
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("continuation");
    let tid = context.thread().key().tid.raw();
    crate::host_signal::publish_pending_for(tid, 10);
    let event = SignalReadinessProbe::from_continuation(&continuation)
        .event()
        .expect("host-slot readiness reservation");
    assert_eq!(event.reserved_signal().expect("reservation").signum(), 10);
    drop(event);
    assert_eq!(
        crate::host_signal::take_pending_for(tid),
        0,
        "imported host ownership is not duplicated back into the lossy host bitmask"
    );
    let replay = context
        .signal_authority()
        .reserve_deliverable_for_wait(WaitSigMask::Replace(SigSet::EMPTY))
        .expect("abandoned reservation remains exact in Kernel pending state");
    assert_eq!(replay.signum(), 10);
    assert_eq!(replay.action(), action);
}

#[test]
fn realtime_host_slot_import_preserves_fifo_multiplicity_and_exact_cancellation_requeue() {
    let (kernel, context) = bootstrap(15_468);
    let generation = publish(&context, 0x913);
    drop(kernel);
    let rt_a = crate::kernel::LinuxSignal::for_signal_number(32).expect("SIGRTMIN");
    let rt_b = crate::kernel::LinuxSignal::for_signal_number(33).expect("SIGRTMIN+1");
    for signal in [rt_a, rt_b] {
        let mut action = carrick_abi::LinuxSigaction::empty();
        action.sa_handler = 0x9000 + signal.raw() as u64;
        context.signal_authority().install_action(signal, action);
    }
    let first =
        crate::linux_abi::LinuxSiginfo::kill(32, crate::linux_abi::LINUX_SI_TKILL, 101, 201);
    let second =
        crate::linux_abi::LinuxSiginfo::kill(32, crate::linux_abi::LINUX_SI_TKILL, 102, 202);
    let other =
        crate::linux_abi::LinuxSiginfo::kill(33, crate::linux_abi::LINUX_SI_TKILL, 103, 203);
    let action_a = context.signal_authority().action(rt_a);
    let action_b = context.signal_authority().action(rt_b);
    context.thread().update_signal_state(|state| {
        state.record_routed_siginfo(rt_a, first);
        state.record_routed_siginfo(rt_a, second);
        state.record_routed_siginfo(rt_b, other);
        state.record_pending_action(rt_a, action_a);
        state.record_pending_action(rt_a, action_a);
        state.record_pending_action(rt_b, action_b);
    });
    let tid = context.thread().key().tid.raw();
    crate::host_signal::publish_pending_for(tid, 32);
    crate::host_signal::publish_pending_for(tid, 32);
    crate::host_signal::publish_pending_for(tid, 33);

    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::empty(),
            timeout: None,
            sig_mask: WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd { on_timeout: 0 },
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("suspended RT continuation");
    let event = SignalReadinessProbe::from_continuation(&continuation)
        .event()
        .expect("first RT readiness");
    let reserved = event.reserved_signal().expect("first RT reservation");
    assert_eq!(reserved.signum(), 32);
    assert_eq!(reserved.siginfo(), Some(first));
    assert_eq!(reserved.host_slot_tid(), Some(tid));
    let result = continuation
        .resume(event, &context)
        .expect("resume first RT interruption");
    drop(result);

    let replay = context
        .signal_authority()
        .reserve_deliverable_for_wait(WaitSigMask::NONE)
        .expect("cancelled first RT requeues exactly");
    let replay = ReservedSignal::from_kernel_reservation(context.signal_authority(), replay);
    assert_eq!(replay.siginfo(), Some(first));
    assert!(replay.consume());
    let second_reserved = context
        .signal_authority()
        .reserve_deliverable_for_wait(WaitSigMask::NONE)
        .expect("second same-signum RT instance remains queued");
    let second_reserved =
        ReservedSignal::from_kernel_reservation(context.signal_authority(), second_reserved);
    assert_eq!(second_reserved.signum(), 32);
    assert_eq!(second_reserved.siginfo(), Some(second));
    assert!(second_reserved.consume());

    let next = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::empty(),
            timeout: None,
            sig_mask: WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd { on_timeout: 0 },
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("next suspended RT continuation");
    let next_event = SignalReadinessProbe::from_continuation(&next)
        .event()
        .expect("other RT signum readiness");
    let next_reserved = next_event.reserved_signal().expect("other RT reservation");
    assert_eq!(next_reserved.signum(), 33);
    assert_eq!(next_reserved.siginfo(), Some(other));
    assert!(
        context
            .thread()
            .update_signal_state(|state| state.pending_actions().is_empty())
    );
}

#[test]
fn kernel_native_guest_signal_continuation_cancels_and_delivers_without_host_sidecars() {
    let (kernel, context) = bootstrap(15_469);
    let generation = publish(&context, 0x914);
    let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let service = CarrierWaitService::new(scheduler);
    let mut continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::empty(),
            timeout: None,
            sig_mask: WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd { on_timeout: 0 },
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("guest-signal continuation");
    let mut registration = service.prepare_registration(&continuation);
    service
        .enroll(&mut registration)
        .expect("enroll guest-signal continuation");
    let wake_token = registration.wake_token();
    continuation
        .attach_registration(registration)
        .expect("attach guest-signal registration");
    let signal = crate::kernel::LinuxSignal::for_signal_number(32).expect("SIGRTMIN");
    let info = crate::linux_abi::LinuxSiginfo::kill(
        32,
        crate::linux_abi::LINUX_SI_TKILL,
        context.task().key().id.raw(),
        context.resources().credentials().ruid().raw(),
    );
    let ticket = match kernel.authorize_signal_target_exact(
        &context,
        context.task().key(),
        Some(context.thread().key()),
        Some(signal),
    ) {
        crate::kernel::ExactSignalTargetAuthorization::Allowed(ticket) => ticket,
        other => panic!("exact guest signal ticket: {other:?}"),
    };
    assert_eq!(
        kernel.post_guest_thread_signal_to_authorized_target(&ticket, signal, Some(info)),
        crate::kernel::ExactThreadSignalPost::Posted(Some(context.thread().key()))
    );
    assert_eq!(
        crate::host_signal::take_pending_for(context.thread().key().tid.raw()),
        0
    );
    let event = await_event(&service, wake_token).expect("Kernel-native guest signal readiness");
    let reserved = event.reserved_signal().expect("exact guest reservation");
    assert_eq!(reserved.siginfo(), Some(info));
    assert_eq!(reserved.host_slot_tid(), None);
    let mut result = continuation
        .resume(event, &context)
        .expect("guest signal resume");
    let cancelled = result
        .take_reserved_signal()
        .expect("continuation owns exact reservation");
    drop(result);
    drop(cancelled);
    assert!(context.signal_authority().thread_pending().contains(32));

    let replay = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::empty(),
            timeout: None,
            sig_mask: WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd { on_timeout: 0 },
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("replay continuation");
    let replay_event = SignalReadinessProbe::from_continuation(&replay)
        .event()
        .expect("cancelled exact instance replays");
    let replay_reserved = replay_event
        .reserved_signal()
        .expect("replayed reservation");
    assert_eq!(replay_reserved.siginfo(), Some(info));
    assert!(replay_reserved.consume());
    assert!(!replay_reserved.consume());
}

#[test]
fn ignored_lower_signal_does_not_hide_next_exact_deliverable_reservation() {
    let (_kernel, context) = bootstrap(153_694);
    let generation = publish(&context, 0x709);
    let ignored = crate::kernel::LinuxSignal::for_signal_number(17).expect("SIGCHLD");
    let caught = crate::kernel::LinuxSignal::for_signal_number(18).expect("signal 18");
    let mut ignore_action = carrick_abi::LinuxSigaction::empty();
    ignore_action.sa_handler = carrick_abi::LINUX_SIG_IGN;
    let mut caught_action = carrick_abi::LinuxSigaction::empty();
    caught_action.sa_handler = 0x4440;
    let authority = context.signal_authority();
    authority.install_action(ignored, ignore_action);
    authority.install_action(caught, caught_action);
    authority.enqueue_thread_standard(ignored, None);
    authority.enqueue_thread_standard(caught, None);
    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::empty(),
            timeout: None,
            sig_mask: WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd { on_timeout: 0 },
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("continuation");
    let event = SignalReadinessProbe::from_continuation(&continuation)
        .event()
        .expect("caught signal behind ignored SIGCHLD");
    assert_eq!(event.reserved_signal().expect("reservation").signum(), 18);
}

#[test]
fn kernel_signal_reservation_is_atomic_across_two_waiters_and_two_instances() {
    let (_kernel, context) = bootstrap(153_695);
    let authority = context.signal_authority();
    for signum in [10, 12] {
        let signal = crate::kernel::LinuxSignal::for_signal_number(signum).expect("signal");
        let mut action = carrick_abi::LinuxSigaction::empty();
        action.sa_handler = 0x5000 + signum as u64;
        authority.install_action(signal, action);
        authority.enqueue_thread_standard(signal, None);
    }
    let barrier = Arc::new(Barrier::new(3));
    let mut waiters = Vec::new();
    for _ in 0..2 {
        let authority = authority.clone();
        let barrier = Arc::clone(&barrier);
        waiters.push(thread::spawn(move || {
            barrier.wait();
            authority
                .reserve_deliverable_for_wait(WaitSigMask::NONE)
                .expect("one exact reservation")
        }));
    }
    barrier.wait();
    let mut reserved = waiters
        .into_iter()
        .map(|waiter| waiter.join().expect("reservation waiter"))
        .collect::<Vec<_>>();
    reserved.sort_unstable_by_key(|reservation| reservation.signum());
    assert_eq!(
        reserved
            .iter()
            .map(|reservation| reservation.signum())
            .collect::<Vec<_>>(),
        vec![10, 12]
    );
    for reservation in reserved {
        let delivery = ReservedSignal::from_kernel_reservation(authority.clone(), reservation);
        assert!(delivery.consume(), "exact signal delivers once");
        assert!(!delivery.consume(), "duplicate delivery is rejected");
    }
    assert!(authority.thread_pending().is_empty());
}

#[test]
fn kernel_signal_reservation_linearizes_disposition_and_mask_changes() {
    for (pid, initial_handler, replacement_handler) in [
        (153_696, 0x6000, carrick_abi::LINUX_SIG_IGN),
        (153_697, carrick_abi::LINUX_SIG_IGN, 0x7000),
    ] {
        let (_kernel, context) = bootstrap(pid);
        let authority = context.signal_authority();
        let signal = crate::kernel::LinuxSignal::for_signal_number(10).expect("SIGUSR1");
        let mut initial = carrick_abi::LinuxSigaction::empty();
        initial.sa_handler = initial_handler;
        authority.install_action(signal, initial);
        authority.enqueue_thread_standard(signal, None);
        let barrier = Arc::new(Barrier::new(3));
        let reserve_authority = authority.clone();
        let reserve_barrier = Arc::clone(&barrier);
        let reserver = thread::spawn(move || {
            reserve_barrier.wait();
            reserve_authority.reserve_deliverable_for_wait(WaitSigMask::NONE)
        });
        let action_authority = authority.clone();
        let action_barrier = Arc::clone(&barrier);
        let changer = thread::spawn(move || {
            action_barrier.wait();
            let mut replacement = carrick_abi::LinuxSigaction::empty();
            replacement.sa_handler = replacement_handler;
            action_authority.install_action(signal, replacement);
        });
        barrier.wait();
        changer.join().expect("action changer");
        if let Some(reservation) = reserver.join().expect("reserver") {
            let handler = reservation.action().sa_handler;
            assert_ne!(handler, carrick_abi::LINUX_SIG_IGN);
            assert!(handler == initial_handler || handler == replacement_handler);
        }
        assert!(
            authority.thread_pending().is_empty(),
            "the transaction either reserves the caught instance or discards the ignored instance"
        );
    }

    let (_kernel, context) = bootstrap(153_698);
    let authority = context.signal_authority();
    let signal = crate::kernel::LinuxSignal::for_signal_number(10).expect("SIGUSR1");
    let mut action = carrick_abi::LinuxSigaction::empty();
    action.sa_handler = 0x8000;
    authority.install_action(signal, action);
    authority.enqueue_thread_standard(signal, None);
    let barrier = Arc::new(Barrier::new(3));
    let reserve_authority = authority.clone();
    let reserve_barrier = Arc::clone(&barrier);
    let reserver = thread::spawn(move || {
        reserve_barrier.wait();
        reserve_authority.reserve_deliverable_for_wait(WaitSigMask::NONE)
    });
    let mask_authority = authority.clone();
    let mask_barrier = Arc::clone(&barrier);
    let masker = thread::spawn(move || {
        mask_barrier.wait();
        mask_authority.set_blocked(SigSet::EMPTY.with(10));
    });
    barrier.wait();
    masker.join().expect("mask changer");
    match reserver.join().expect("mask reserver") {
        Some(reservation) => {
            assert!(!reservation.effective_mask().contains(10));
            assert!(authority.thread_pending().is_empty());
        }
        None => {
            assert!(authority.thread_pending().contains(10));
            assert!(authority.blocked().contains(10));
        }
    }
}

#[test]
fn partial_blocking_write_never_restarts_after_caught_sa_restart_signal() {
    let (_kernel, context) = bootstrap(153_691);
    let generation = publish(&context, 0x706);
    let signal = crate::kernel::LinuxSignal::for_signal_number(10).expect("SIGUSR1");
    let mut action = carrick_abi::LinuxSigaction::empty();
    action.sa_handler = 0x1234;
    action.sa_flags = carrick_abi::LINUX_SA_RESTART;
    context.signal_authority().install_action(signal, action);
    context
        .signal_authority()
        .enqueue_thread_standard(signal, None);
    let fds = pipe_pair();
    let write = BlockingHostWrite::for_tests(
        fds[1],
        vec![1, 2, 3, 4],
        2,
        ThreadId::synthetic_for_tests(153_691),
        false,
    )
    .expect("partial blocking write");
    close_pair(fds);
    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::BlockingHostWrite(write),
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("partial write continuation");
    let result = continuation
        .resume(ContinuationEvent::Signal, &context)
        .expect("partial signal result");
    assert_eq!(result.restart(), RestartDecision::NoRestart);
    assert_eq!(result.completion, ContinuationCompletion::Return(2));
}

#[test]
fn signal_readiness_honors_replace_additive_ignore_and_live_restart_action() {
    let (kernel, context) = bootstrap(15_370);
    let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let service = CarrierWaitService::new(scheduler);
    let usr1 = crate::kernel::LinuxSignal::for_signal_number(10).expect("SIGUSR1");
    let usr1_set = SigSet::from_raw(1 << 9);
    context.signal_authority().set_blocked(usr1_set);
    let generation = publish(&context, 0x704);

    let replacement = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::empty(),
            timeout: None,
            sig_mask: WaitSigMask::Replace(SigSet::EMPTY),
            completion: FdWaitCompletion::Fd { on_timeout: 0 },
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("replacement-mask continuation");
    let mut replacement_registration = service.prepare_registration(&replacement);
    service
        .enroll(&mut replacement_registration)
        .expect("enroll replacement mask");
    context
        .signal_authority()
        .enqueue_thread_standard(usr1, None);
    context.task().wake();
    let event = await_event(&service, replacement_registration.wake_token())
        .expect("replacement mask unblocks SIGUSR1");
    assert_eq!(
        event.reserved_signal().expect("reserved SIGUSR1").signum(),
        10
    );
    let result = replacement
        .resume(event, &context)
        .expect("replacement resume");
    assert_eq!(result.restart(), RestartDecision::NoRestart);
    assert_eq!(context.signal_authority().blocked(), SigSet::EMPTY);
    assert_eq!(
        context.signal_authority().armed_restore_mask(),
        Some(usr1_set)
    );
    result
        .reserved_signal()
        .expect("reserved default delivery")
        .restore_persistent_after_default_action();
    assert_eq!(context.signal_authority().blocked(), usr1_set);

    let (kernel, context) = bootstrap(15_371);
    let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let service = CarrierWaitService::new(scheduler);
    let generation = publish(&context, 0x705);
    let additive = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::empty(),
            timeout: None,
            sig_mask: WaitSigMask::Additive(usr1_set),
            completion: FdWaitCompletion::Fd { on_timeout: 0 },
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("additive-mask continuation");
    let mut additive_registration = service.prepare_registration(&additive);
    service
        .enroll(&mut additive_registration)
        .expect("enroll additive mask");
    context
        .signal_authority()
        .enqueue_thread_standard(usr1, None);
    context.task().wake();
    assert_eq!(
        service
            .inner
            .state
            .lock()
            .entries
            .get(&additive_registration.wake_token().continuation())
            .expect("additive registration")
            .state,
        RegistrationState::Enrolled
    );

    let chld = crate::kernel::LinuxSignal::for_signal_number(17).expect("SIGCHLD");
    let mut ignored = carrick_abi::LinuxSigaction::empty();
    ignored.sa_handler = carrick_abi::LINUX_SIG_IGN;
    context.signal_authority().install_action(chld, ignored);
    context
        .signal_authority()
        .enqueue_thread_standard(chld, None);
    context.task().wake();
    assert_eq!(
        service
            .inner
            .state
            .lock()
            .entries
            .get(&additive_registration.wake_token().continuation())
            .expect("ignored-signal registration")
            .state,
        RegistrationState::Enrolled
    );
    service
        .cancel_registration(additive_registration)
        .expect("cancel masked wait");
}

#[test]
fn failed_initial_submission_retires_exact_runnable_without_queue_row() {
    let (kernel, context) = bootstrap(15_460);
    let scheduler = Scheduler::new(kernel);
    let generation = publish(&context, 0x900);
    assert_eq!(scheduler.queued_len(), 0);
    context
        .thread()
        .fail_runnable_generation(
            generation,
            crate::kernel::objects::ExecutionFailure::SnapshotSaveFailed,
        )
        .expect("exact bootstrap failure");
    assert!(matches!(
        context.thread().execution_state(),
        ThreadExecutionState::Failed {
            generation: failed,
            reason: crate::kernel::objects::ExecutionFailure::SnapshotSaveFailed,
        } if failed == generation
    ));
    assert_eq!(scheduler.queued_len(), 0);
}

#[test]
fn indefinite_registration_has_no_synthetic_timeout_or_periodic_probe_deadline() {
    let (kernel, context) = bootstrap(15_370);
    let generation = publish(&context, 0x704);
    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::empty(),
            timeout: None,
            sig_mask: WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd { on_timeout: 0 },
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("indefinite continuation");
    let scheduler = Arc::new(Scheduler::new(kernel));
    let service = CarrierWaitService::new(scheduler);
    let mut registration = service.prepare_registration(&continuation);
    service
        .enroll(&mut registration)
        .expect("enroll indefinite");
    assert_eq!(continuation.deadline(), None);
    let state = service
        .registration_timing(registration.wake_token())
        .expect("registration timing");
    assert_eq!(state.deadline(), None);
    assert!(!state.has_periodic_probe());
}

/// The reactor's per-cycle cost must not grow with the number of parked
/// tasks. Before `ReactorWorkSet`, one cycle scanned every registration
/// three times — poll set, expired deadlines, record locks — so a carrier
/// with 256 sleepers paid 256 row visits on the wake path of the ONE
/// registration that actually had a readiness fd. Ablate the index (walk
/// `state.entries` again in the cycle) and this fails with visits ~=257.
/// The index is only sound if it answers exactly what the full scan did.
/// Every question the reactor asks is checked against the scan it replaced,
/// across the state transitions that move a row in or out of the work set.
#[test]
fn the_reactor_work_set_answers_exactly_what_a_full_scan_would() {
    fn scan_nearest(state: &CarrierWaitState) -> Option<Instant> {
        state
            .entries
            .values()
            .filter(|entry| entry.state == RegistrationState::Enrolled)
            .filter_map(|entry| entry.deadline)
            .min()
    }
    fn scan_expired(state: &CarrierWaitState, now: Instant) -> Vec<ContinuationId> {
        let mut ids: Vec<_> = state
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry.state == RegistrationState::Enrolled
                    && entry.deadline.is_some_and(|deadline| now >= deadline)
            })
            .map(|(id, _)| *id)
            .collect();
        ids.sort_unstable();
        ids
    }
    fn scan_pollable(state: &CarrierWaitState) -> Vec<ContinuationId> {
        let mut ids: Vec<_> = state
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry.state == RegistrationState::Enrolled && entry.probe.contributes_pollfds()
            })
            .map(|(id, _)| *id)
            .collect();
        ids.sort_unstable();
        ids
    }
    fn agree(state: &CarrierWaitState, now: Instant, at: &str) {
        assert_eq!(
            state.reactor_work.nearest_deadline(),
            scan_nearest(state),
            "nearest deadline disagrees with a full scan at {at}"
        );
        assert_eq!(
            state.reactor_work.expired_at(now).collect::<Vec<_>>(),
            scan_expired(state, now),
            "expired set disagrees with a full scan at {at}"
        );
        assert_eq!(
            state
                .reactor_work
                .pollable
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            scan_pollable(state),
            "pollable set disagrees with a full scan at {at}"
        );
    }

    let (kernel, context) = bootstrap(15_373);
    let generation = publish(&context, 0x707);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let service = CarrierWaitService::new(scheduler);
    let now = Instant::now();
    let mut owned = Vec::new();
    for index in 0..8 {
        let continuation = if index % 2 == 0 {
            BlockedContinuation::from_dispatch_outcome(
                DispatchOutcome::WaitOnSleep {
                    duration: Duration::from_millis(10 * (index + 1)),
                    remaining: None,
                },
                capture(&context, generation, ContinuationBackend::Hvpatch),
            )
        } else {
            BlockedContinuation::from_dispatch_outcome(
                DispatchOutcome::WaitOnFds {
                    fds: WaitFds::empty(),
                    timeout: None,
                    sig_mask: WaitSigMask::NONE,
                    completion: FdWaitCompletion::Fd { on_timeout: 0 },
                },
                capture(&context, generation, ContinuationBackend::Hvpatch),
            )
        }
        .expect("continuation");
        let registration = service.prepare_registration(&continuation);
        owned.push((continuation, registration));
    }
    agree(&service.inner.state.lock(), now, "prepared");
    for (_, registration) in owned.iter_mut() {
        service.enroll(registration).expect("enroll");
    }
    agree(&service.inner.state.lock(), now, "enrolled");
    agree(
        &service.inner.state.lock(),
        now + Duration::from_secs(1),
        "enrolled, every deadline passed",
    );
    for (_, registration) in owned.iter().take(3) {
        service.inner.cancel_exact(
            registration.wake_token(),
            CancellationCause::ServiceShutdown,
        );
    }
    agree(&service.inner.state.lock(), now, "three cancelled");
    let tokens: Vec<_> = owned
        .iter()
        .skip(3)
        .map(|(_, registration)| registration.wake_token())
        .collect();
    for token in tokens {
        service.inner.publish_event(token, ContinuationEvent::Ready);
    }
    agree(&service.inner.state.lock(), now, "the rest made ready");
    {
        let mut state = service.inner.state.lock();
        let ids: Vec<_> = state.entries.keys().copied().collect();
        for id in ids {
            state.remove_registration(id);
        }
        assert!(state.reactor_work.pollable.is_empty());
        assert!(state.reactor_work.deadlines.is_empty());
        assert!(state.reactor_work.record_locks.is_empty());
        agree(&state, now, "all removed");
    }
    drop(owned);
}

/// The index is only maintained because every mutation goes through
/// `CarrierWaitState`. A bare `entries.get_mut`/`insert`/`remove` outside
/// those three mutators is how it would silently go stale, so the shape is
/// asserted rather than left to review.
#[test]
fn every_registration_mutation_goes_through_the_indexed_mutators() {
    let source = include_str!("wait_service.rs");
    let production = source
        .split("#[cfg(test)]\nmod tests {")
        .next()
        .expect("production half of the module");
    for (needle, allowed) in [
        ("entries.get_mut(", 1usize),
        ("entries.insert(", 1),
        ("entries.remove(", 1),
        ("entries.values_mut(", 0),
        ("entries.iter_mut(", 1),
    ] {
        assert_eq!(
            production.matches(needle).count(),
            allowed,
            "`{needle}` must appear only inside CarrierWaitState's indexed mutators"
        );
    }
}

#[test]
fn a_reactor_cycle_visits_only_its_pollable_registrations() {
    let (kernel, context) = bootstrap(15_372);
    let generation = publish(&context, 0x706);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let service = CarrierWaitService::new(scheduler);
    let mut owned = Vec::new();
    // 256 timer-only parks: no readiness fd, nothing for a poll set.
    for _ in 0..256 {
        let continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnSleep {
                duration: Duration::from_secs(3_600),
                remaining: None,
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("timer continuation");
        let mut registration = service.prepare_registration(&continuation);
        service.enroll(&mut registration).expect("enroll");
        owned.push((continuation, registration));
    }
    // One pollable park, so the cycle has real work to do.
    let pollable = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::empty(),
            timeout: None,
            sig_mask: WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd { on_timeout: 0 },
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("pollable continuation");
    let mut pollable_registration = service.prepare_registration(&pollable);
    service
        .enroll(&mut pollable_registration)
        .expect("enroll pollable");

    let before_visits = service.reactor_cycle_visits();
    let before_calls = service.reactor_poll_calls();
    let observed = service.observe_next_reactor_poll();
    service.nudge_reactor_for_test();
    observed.wait();
    assert!(
        service.reactor_poll_calls() > before_calls,
        "reactor did not complete a cycle"
    );
    let visits = service.reactor_cycle_visits() - before_visits;
    assert!(
        visits <= 8,
        "a reactor cycle visited {visits} registrations with 257 enrolled: \
         the poll set is being rebuilt by scanning the whole map"
    );
    drop(pollable);
    drop(pollable_registration);
    drop(owned);
}

#[test]
fn idle_256_indefinite_waits_use_one_blocking_poll_without_probe_storm() {
    let (kernel, context) = bootstrap(15_371);
    let generation = publish(&context, 0x705);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let service = CarrierWaitService::new(scheduler);
    let mut owned = Vec::new();
    for _ in 0..256 {
        let continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnFds {
                fds: WaitFds::empty(),
                timeout: None,
                sig_mask: WaitSigMask::NONE,
                completion: FdWaitCompletion::Fd { on_timeout: 0 },
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("indefinite continuation");
        let mut registration = service.prepare_registration(&continuation);
        service.enroll(&mut registration).expect("enroll");
        owned.push((continuation, registration));
    }
    let before = service.reactor_poll_calls();
    let observed = service.observe_next_reactor_poll();
    service.nudge_reactor_for_test();
    observed.wait();
    let after = service.reactor_poll_calls();
    assert!(
        after > before,
        "blocking reactor did not observe its control nudge"
    );
    for _ in 0..1024 {
        thread::yield_now();
    }
    assert!(service.reactor_poll_calls() <= after + 1);
    assert_eq!(service.topology().shared_reactors(), 1);
    assert_eq!(service.topology().task_waiter_threads(), 0);
    drop(owned);
}

fn fill_pipe(write_fd: i32) -> Vec<u8> {
    let mut total = Vec::new();
    let chunk = [0x5au8; 1024];
    unsafe {
        let flags = libc::fcntl(write_fd, libc::F_GETFL);
        libc::fcntl(write_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        loop {
            let n = libc::write(write_fd, chunk.as_ptr().cast(), chunk.len());
            if n <= 0 {
                break;
            }
            total.extend_from_slice(&chunk[..n as usize]);
        }
    }
    total
}

fn drain_pipe(read_fd: i32, count: usize) {
    let mut buf = vec![0u8; 1024];
    let mut drained = 0;
    unsafe {
        let flags = libc::fcntl(read_fd, libc::F_GETFL);
        libc::fcntl(read_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    while drained < count {
        let to_read = (count - drained).min(buf.len());
        let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), to_read) };
        if n <= 0 {
            break;
        }
        drained += n as usize;
    }
}

#[test]
fn deterministic_rendezvous_enrollment_vs_reactor_host_write_interleaving() {
    let (kernel, context) = bootstrap(15_380);
    let generation = publish(&context, 0x720);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let service = CarrierWaitService::new(scheduler);

    let pipe = pipe_pair();
    let dummy = fill_pipe(pipe[1]);

    let payload = vec![11, 22, 33, 44];
    let write = BlockingHostWrite::for_tests(
        pipe[1],
        payload.clone(),
        0,
        context.thread().registry_id(),
        false,
    )
    .expect("write state");
    let mut continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::BlockingHostWrite(write),
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("write continuation");
    let mut registration = service.prepare_registration(&continuation);
    let token = registration.wake_token();

    // Enroll while pipe is full: recheck gets EAGAIN and parks in pollable set
    service.enroll(&mut registration).expect("enroll write");
    continuation
        .attach_registration(registration)
        .expect("attach registration");

    let (reactor_reached_tx, reactor_reached_rx) = std::sync::mpsc::sync_channel(1);
    let (enroll_done_tx, enroll_done_rx) = std::sync::mpsc::sync_channel(1);
    let enroll_done_rx = Arc::new(std::sync::Mutex::new(enroll_done_rx));

    service.set_before_host_write_hook(move || {
        let _ = reactor_reached_tx.send(());
        let _ = enroll_done_rx
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5));
    });

    // Drain dummy bytes so pipe becomes writable, triggering reactor pollout
    drain_pipe(pipe[0], dummy.len());
    service.nudge_reactor_for_test();

    // Wait for reactor to reach hook before driving write
    reactor_reached_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("reactor reached hook");

    // Concurrent thread unblocks reactor hook
    enroll_done_tx.send(()).expect("unblock reactor");

    assert_eq!(
        await_event(&service, token).expect("write event"),
        ContinuationEvent::Ready
    );

    // Verify exact pipe bytes read
    let mut buf = vec![0u8; payload.len()];
    let read_bytes = unsafe { libc::read(pipe[0], buf.as_mut_ptr().cast(), buf.len()) };
    assert_eq!(read_bytes as usize, payload.len());
    assert_eq!(buf, payload);

    let resume_outcome = continuation
        .resume(ContinuationEvent::Ready, &context)
        .expect("resume write")
        .completion;
    assert!(matches!(
        resume_outcome,
        ContinuationCompletion::BlockingWrite {
            outcome: BlockingWriteOutcome::Return(4),
            ..
        }
    ));

    service.clear_test_hooks();
    close_pair(pipe);
}

#[test]
fn cancellation_during_inflight_host_write_competing_with_ready_event_drains_safely() {
    let (kernel, context) = bootstrap(15_381);
    let generation = publish(&context, 0x721);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let service = CarrierWaitService::new(scheduler);

    let pipe = pipe_pair();
    let dummy = fill_pipe(pipe[1]);

    let payload = vec![1, 2, 3, 4, 5];
    let write = BlockingHostWrite::for_tests(
        pipe[1],
        payload.clone(),
        0,
        context.thread().registry_id(),
        false,
    )
    .expect("write state");
    let mut continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::BlockingHostWrite(write),
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("write continuation");
    let mut registration = service.prepare_registration(&continuation);
    let token = registration.wake_token();
    service.enroll(&mut registration).expect("enroll write");
    continuation
        .attach_registration(registration)
        .expect("attach registration");

    let (drive_started_tx, drive_started_rx) = std::sync::mpsc::sync_channel(1);
    let (cancel_started_tx, cancel_started_rx) = std::sync::mpsc::sync_channel(1);
    let cancel_started_rx = Arc::new(std::sync::Mutex::new(cancel_started_rx));

    service.set_inside_host_write_hook(move || {
        let _ = drive_started_tx.send(());
        let _ = cancel_started_rx
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5));
    });

    // Drain dummy bytes to make pipe writable and wake reactor
    drain_pipe(pipe[0], dummy.len());
    service.nudge_reactor_for_test();

    // Wait until reactor is inside drive_blocking_host_write (holding OperationClaimGuard)
    drive_started_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("reactor started drive");

    // While HostWrite is in-flight, an independent producer publishes Ready
    let publish_receipt = service.inner.publish_event(token, ContinuationEvent::Ready);
    assert!(publish_receipt.accepted());
    assert_eq!(
        service
            .inner
            .state
            .lock()
            .entries
            .get(&token.continuation)
            .expect("entry")
            .state,
        RegistrationState::Ready
    );

    let (cancel_done_tx, cancel_done_rx) = std::sync::mpsc::sync_channel(1);

    let cancel_thread = thread::spawn(move || {
        let receipt = continuation.cancel(CancellationCause::ProcessExit);
        cancel_done_tx.send(receipt).expect("send receipt");
    });

    // Assert that cancel CANNOT complete/retire while operation claim is held (drain blocks)
    assert!(
        cancel_done_rx
            .recv_timeout(Duration::from_millis(50))
            .is_err(),
        "cancellation must block on operation gate drain and cannot retire early"
    );

    // Tell inside hook to complete and drop OperationClaimGuard
    cancel_started_tx.send(()).expect("unblock reactor drive");

    let receipt = cancel_done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("cancel completed after claim dropped");
    assert_eq!(receipt.cause(), CancellationCause::ProcessExit);
    assert_eq!(receipt.cleanup_count(), 1);

    cancel_thread.join().expect("cancel thread join");

    // Verify gate is permanently closed: no fresh drive can claim
    let entry_gate = {
        let state = service.inner.state.lock();
        let entry = state.entries.get(&token.continuation).expect("entry");
        assert_eq!(
            entry.state,
            RegistrationState::Cancelled(CancellationCause::ProcessExit)
        );
        Arc::clone(&entry.operation_gate)
    };
    assert!(entry_gate.try_claim(token).is_none());

    // Verify that publish_event after cancellation is rejected
    let publish_receipt = service.inner.publish_event(token, ContinuationEvent::Ready);
    assert!(
        !publish_receipt.accepted(),
        "publish after cancellation must be rejected"
    );

    // Verify exact pipe bytes were written by the in-flight drive before cancellation completed
    let mut buf = vec![0u8; payload.len()];
    let read_bytes = unsafe { libc::read(pipe[0], buf.as_mut_ptr().cast(), buf.len()) };
    assert_eq!(read_bytes as usize, payload.len());
    assert_eq!(buf, payload);

    service.clear_test_hooks();
    close_pair(pipe);
}

#[test]
fn incoming_drain_waker_clone_runs_outside_registration_locks() {
    struct CloneChecking {
        gate: Arc<RegistrationOperationGate>,
        service: Arc<CarrierWaitServiceInner>,
        locked_clone: AtomicBool,
    }
    unsafe fn clone_raw(data: *const ()) -> std::task::RawWaker {
        // SAFETY: every raw waker owns one Arc count of CloneChecking.
        let owner = unsafe { &*data.cast::<CloneChecking>() };
        if owner
            .gate
            .state
            .try_lock_for(Duration::from_millis(50))
            .is_none()
            || owner
                .service
                .state
                .try_lock_for(Duration::from_millis(50))
                .is_none()
        {
            owner.locked_clone.store(true, Ordering::Release);
        }
        // SAFETY: the source waker retains a live Arc throughout cloning.
        unsafe { Arc::increment_strong_count(data.cast::<CloneChecking>()) };
        std::task::RawWaker::new(data, &VTABLE)
    }
    unsafe fn drop_raw(data: *const ()) {
        // SAFETY: consume the single Arc count owned by this raw waker.
        drop(unsafe { Arc::from_raw(data.cast::<CloneChecking>()) });
    }
    unsafe fn wake_ref_raw(_: *const ()) {}
    static VTABLE: std::task::RawWakerVTable =
        std::task::RawWakerVTable::new(clone_raw, drop_raw, wake_ref_raw, drop_raw);
    let (kernel, context) = bootstrap(15_392);
    let generation = publish(&context, 0x732);
    let service = CarrierWaitService::new(Arc::new(Scheduler::new(kernel)));
    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnSleep {
            duration: Duration::from_secs(60),
            remaining: None,
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("sleep continuation");
    let registration = service.prepare_registration(&continuation);
    let token = registration.wake_token();
    let gate = Arc::clone(
        &service
            .inner
            .state
            .lock()
            .entries
            .get(&token.continuation)
            .expect("prepared registration")
            .operation_gate,
    );
    let claim = gate.try_claim(token).expect("admitted operation");
    let _ = service
        .inner
        .state
        .lock()
        .cancel_all_active(CancellationCause::ProcessExit);
    let owner = Arc::new(CloneChecking {
        gate,
        service: Arc::clone(&service.inner),
        locked_clone: AtomicBool::new(false),
    });
    let data = Arc::into_raw(Arc::clone(&owner)).cast::<()>();
    // SAFETY: VTABLE retains/releases one Arc count for each owned Waker.
    let waker = unsafe { Waker::from_raw(std::task::RawWaker::new(data, &VTABLE)) };
    let mut future = service.event(token);
    assert!(
        Pin::new(&mut future)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    drop(claim);
    assert!(
        !owner.locked_clone.load(Ordering::Acquire),
        "incoming drain waker clone callback must run outside both registration locks"
    );
}

#[test]
fn incoming_task_waker_clone_runs_outside_registration_locks() {
    struct CloneChecking {
        service: Arc<CarrierWaitServiceInner>,
        locked_clone: AtomicBool,
    }
    unsafe fn clone_raw(data: *const ()) -> std::task::RawWaker {
        // SAFETY: every raw waker owns one Arc count of CloneChecking.
        let owner = unsafe { &*data.cast::<CloneChecking>() };
        if owner
            .service
            .state
            .try_lock_for(Duration::from_millis(50))
            .is_none()
        {
            owner.locked_clone.store(true, Ordering::Release);
        }
        // SAFETY: the source waker retains a live Arc throughout cloning.
        unsafe { Arc::increment_strong_count(data.cast::<CloneChecking>()) };
        std::task::RawWaker::new(data, &VTABLE)
    }
    unsafe fn drop_raw(data: *const ()) {
        // SAFETY: consume the single Arc count owned by this raw waker.
        drop(unsafe { Arc::from_raw(data.cast::<CloneChecking>()) });
    }
    unsafe fn wake_ref_raw(_: *const ()) {}
    static VTABLE: std::task::RawWakerVTable =
        std::task::RawWakerVTable::new(clone_raw, drop_raw, wake_ref_raw, drop_raw);
    let (kernel, context) = bootstrap(15_393);
    let generation = publish(&context, 0x733);
    let service = CarrierWaitService::new(Arc::new(Scheduler::new(kernel)));
    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnSleep {
            duration: Duration::from_secs(60),
            remaining: None,
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("sleep continuation");
    let registration = service.prepare_registration(&continuation);
    let token = registration.wake_token();
    let owner = Arc::new(CloneChecking {
        service: Arc::clone(&service.inner),
        locked_clone: AtomicBool::new(false),
    });
    let data = Arc::into_raw(Arc::clone(&owner)).cast::<()>();
    // SAFETY: VTABLE retains/releases one Arc count for each owned Waker.
    let waker = unsafe { Waker::from_raw(std::task::RawWaker::new(data, &VTABLE)) };
    let mut future = service.event(token);
    assert!(
        Pin::new(&mut future)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert!(
        !owner.locked_clone.load(Ordering::Acquire),
        "incoming task waker clone callback must run outside registration lock"
    );
}

#[test]
fn drain_waker_runs_outside_operation_gate_lock() {
    struct GateCheckingWake {
        gate: Arc<RegistrationOperationGate>,
        observed: Arc<AtomicBool>,
        unlocked: Arc<AtomicBool>,
    }
    impl std::task::Wake for GateCheckingWake {
        fn wake(self: Arc<Self>) {
            self.unlocked
                .store(self.gate.state.try_lock().is_some(), Ordering::Release);
            self.observed.store(true, Ordering::Release);
        }
    }
    let (kernel, context) = bootstrap(15_389);
    let generation = publish(&context, 0x729);
    let service = CarrierWaitService::new(Arc::new(Scheduler::new(kernel)));
    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnSleep {
            duration: Duration::from_secs(60),
            remaining: None,
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("sleep continuation");
    let registration = service.prepare_registration(&continuation);
    let token = registration.wake_token();
    let gate = Arc::clone(
        &service
            .inner
            .state
            .lock()
            .entries
            .get(&token.continuation)
            .expect("prepared registration")
            .operation_gate,
    );
    let claim = gate.try_claim(token).expect("admitted operation");
    let _ = service
        .inner
        .state
        .lock()
        .cancel_all_active(CancellationCause::ProcessExit);
    let observed = Arc::new(AtomicBool::new(false));
    let unlocked = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(GateCheckingWake {
        gate,
        observed: Arc::clone(&observed),
        unlocked: Arc::clone(&unlocked),
    }));
    let mut future = service.event(token);
    assert!(
        Pin::new(&mut future)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    drop(claim);
    assert!(
        observed.load(Ordering::Acquire),
        "actual cancelled future must receive drain wake"
    );
    assert!(
        unlocked.load(Ordering::Acquire),
        "drain callback must run after releasing gate.state; callbacks may reenter service -> gate"
    );
}

#[test]
fn replaced_drain_waker_drops_outside_registration_locks() {
    struct DropCheckingWake {
        gate: Arc<RegistrationOperationGate>,
        service: Arc<CarrierWaitServiceInner>,
        observed: Arc<AtomicBool>,
        gate_unlocked: Arc<AtomicBool>,
        service_unlocked: Arc<AtomicBool>,
    }
    // Not `Waker::noop()`: the test observes WHEN this waker is dropped.
    #[allow(clippy::manual_noop_waker)]
    impl std::task::Wake for DropCheckingWake {
        fn wake(self: Arc<Self>) {}
    }
    impl Drop for DropCheckingWake {
        fn drop(&mut self) {
            self.gate_unlocked.store(
                self.gate
                    .state
                    .try_lock_for(Duration::from_millis(50))
                    .is_some(),
                Ordering::Release,
            );
            self.service_unlocked.store(
                self.service
                    .state
                    .try_lock_for(Duration::from_millis(50))
                    .is_some(),
                Ordering::Release,
            );
            self.observed.store(true, Ordering::Release);
        }
    }
    let (kernel, context) = bootstrap(15_390);
    let generation = publish(&context, 0x730);
    let service = CarrierWaitService::new(Arc::new(Scheduler::new(kernel)));
    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnSleep {
            duration: Duration::from_secs(60),
            remaining: None,
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("sleep continuation");
    let registration = service.prepare_registration(&continuation);
    let token = registration.wake_token();
    let gate = Arc::clone(
        &service
            .inner
            .state
            .lock()
            .entries
            .get(&token.continuation)
            .expect("prepared registration")
            .operation_gate,
    );
    let claim = gate.try_claim(token).expect("admitted operation");
    let _ = service
        .inner
        .state
        .lock()
        .cancel_all_active(CancellationCause::ProcessExit);
    let observed = Arc::new(AtomicBool::new(false));
    let gate_unlocked = Arc::new(AtomicBool::new(false));
    let service_unlocked = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(DropCheckingWake {
        gate,
        service: Arc::clone(&service.inner),
        observed: Arc::clone(&observed),
        gate_unlocked: Arc::clone(&gate_unlocked),
        service_unlocked: Arc::clone(&service_unlocked),
    }));
    let mut future = service.event(token);
    assert!(
        Pin::new(&mut future)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    // Only the registration owns this waker now. Repolling with a
    // replacement must release its final references outside both locks.
    drop(waker);
    assert!(
        Pin::new(&mut future)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(claim);
    assert!(
        observed.load(Ordering::Acquire),
        "replacing the registered waker must release its old owner"
    );
    assert!(
        gate_unlocked.load(Ordering::Acquire),
        "replaced waker destructor must run after releasing gate.state; destructors may reenter service -> gate"
    );
    assert!(
        service_unlocked.load(Ordering::Acquire),
        "replaced waker destructor must run after releasing service.state; destructors may reenter service -> gate"
    );
}

#[test]
fn replaced_task_waker_drops_outside_registration_locks() {
    struct DropCheckingWake {
        service: Arc<CarrierWaitServiceInner>,
        observed: Arc<AtomicBool>,
        service_unlocked: Arc<AtomicBool>,
    }
    // Not `Waker::noop()`: the test observes WHEN this waker is dropped.
    #[allow(clippy::manual_noop_waker)]
    impl std::task::Wake for DropCheckingWake {
        fn wake(self: Arc<Self>) {}
    }
    impl Drop for DropCheckingWake {
        fn drop(&mut self) {
            self.service_unlocked.store(
                self.service
                    .state
                    .try_lock_for(Duration::from_millis(50))
                    .is_some(),
                Ordering::Release,
            );
            self.observed.store(true, Ordering::Release);
        }
    }
    let (kernel, context) = bootstrap(15_391);
    let generation = publish(&context, 0x731);
    let service = CarrierWaitService::new(Arc::new(Scheduler::new(kernel)));
    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnSleep {
            duration: Duration::from_secs(60),
            remaining: None,
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("sleep continuation");
    let registration = service.prepare_registration(&continuation);
    let token = registration.wake_token();
    let observed = Arc::new(AtomicBool::new(false));
    let service_unlocked = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(DropCheckingWake {
        service: Arc::clone(&service.inner),
        observed: Arc::clone(&observed),
        service_unlocked: Arc::clone(&service_unlocked),
    }));
    let mut future = service.event(token);
    assert!(
        Pin::new(&mut future)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    drop(waker);
    assert!(
        Pin::new(&mut future)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert!(
        observed.load(Ordering::Acquire),
        "replacing the registered task waker must release its old owner"
    );
    assert!(
        service_unlocked.load(Ordering::Acquire),
        "replaced task waker destructor must run after releasing service.state"
    );
}

#[test]
fn event_future_cancelled_observation_drains_inflight_operation_safely() {
    // A broken production lock order can deadlock irrecoverably. Contain
    // that interleaving in an owned child so the regression itself fails
    // with an assertion and leaves no live blocked test threads.
    const CHILD_MARKER: &str = "CARRICK_WAIT_TERMINAL_TEST_CHILD";
    if std::env::var_os(CHILD_MARKER).as_deref() != Some(std::ffi::OsStr::new("1")) {
        let mut child = spawn_contained_test_child(
            "vcpu_loop::continuation::tests::event_future_cancelled_observation_drains_inflight_operation_safely",
            CHILD_MARKER,
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().expect("read child status") {
                break Some(status);
            }
            if Instant::now() >= deadline {
                child.kill().expect("reap deadlocked child");
                let status = child.wait().expect("wait for killed child");
                eprintln!(
                    "contained terminal-retirement child {} reaped with {status}",
                    child.id()
                );
                break None;
            }
            thread::sleep(Duration::from_millis(10));
        };
        assert!(
            status.is_some_and(|status| status.success()),
            "production terminal-retirement child must complete successfully within its bound; child was reaped"
        );
        return;
    }
    let (kernel, context) = bootstrap(15_382);
    let generation = publish(&context, 0x722);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let service = CarrierWaitService::new(scheduler);

    let pipe = pipe_pair();
    let dummy = fill_pipe(pipe[1]);

    let payload = vec![9, 8, 7, 6];
    let write = BlockingHostWrite::for_tests(
        pipe[1],
        payload.clone(),
        0,
        context.thread().registry_id(),
        false,
    )
    .expect("write state");
    let mut continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::BlockingHostWrite(write),
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("write continuation");
    let mut registration = service.prepare_registration(&continuation);
    let token = registration.wake_token();
    service.enroll(&mut registration).expect("enroll write");
    continuation
        .attach_registration(registration)
        .expect("attach registration");

    let (drive_started_tx, drive_started_rx) = std::sync::mpsc::sync_channel(1);
    let (cancel_started_tx, cancel_started_rx) = std::sync::mpsc::sync_channel(1);
    let cancel_started_rx = Arc::new(std::sync::Mutex::new(cancel_started_rx));

    service.set_inside_host_write_hook(move || {
        let _ = drive_started_tx.send(());
        let _ = cancel_started_rx
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5));
    });

    // Drain dummy bytes to wake reactor
    drain_pipe(pipe[0], dummy.len());
    service.nudge_reactor_for_test();

    drive_started_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("reactor started drive");

    // Cancel registration while reactor is inside hook
    let (cancel_done_tx, cancel_done_rx) = std::sync::mpsc::sync_channel(1);
    let cancel_thread = thread::spawn(move || {
        let receipt = continuation.cancel(CancellationCause::ProcessExit);
        cancel_done_tx.send(receipt).expect("send receipt");
    });

    // 1. Wait for bounded acknowledgment of the cancellation transition in service.state
    let deadline = Instant::now() + Duration::from_secs(5);
    let gate = loop {
        let state = service.inner.state.lock();
        if let Some(entry) = state.entries.get(&token.continuation) {
            if entry.state == RegistrationState::Cancelled(CancellationCause::ProcessExit) {
                break Arc::clone(&entry.operation_gate);
            }
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for cancellation to linearize in service.state");
        }
        std::thread::yield_now();
    };

    // 2. Cancellation has linearized, but cancel thread is STILL blocked on drain because reactor holds claim
    assert!(
        cancel_done_rx.try_recv().is_err(),
        "cancel must block on drain while in-flight operation is active"
    );

    // 3. Verify cancellation linearization point: admission is closed, no new claims admitted
    assert!(
        gate.try_claim(token).is_none(),
        "no fresh claim admitted after cancellation linearization point"
    );

    // 3. Verify event future poll is non-blocking and returns Pending while in-flight operation active
    let mut event_future = service.event(token);
    let noop_waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(noop_waker);
    let poll_result = Pin::new(&mut event_future).poll(&mut cx);
    assert!(
        poll_result.is_pending(),
        "poll must return Pending without blocking while in-flight operation is active"
    );

    // 4. Verify unrelated waiter progress during in-flight operation
    let unrelated_continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnSleep {
            duration: Duration::from_millis(1),
            remaining: None,
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("sleep continuation");
    let mut unrelated_reg = service.prepare_registration(&unrelated_continuation);
    let unrelated_token = unrelated_reg.wake_token();
    service
        .enroll(&mut unrelated_reg)
        .expect("enroll unrelated");
    assert_eq!(
        await_event(&service, unrelated_token).expect("unrelated event"),
        ContinuationEvent::Timeout
    );

    // 5. Release hook so claim drops
    cancel_started_tx.send(()).expect("unblock reactor drive");

    let cancel_receipt = cancel_done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("cancel completed");
    assert_eq!(cancel_receipt.cause(), CancellationCause::ProcessExit);
    cancel_thread.join().expect("cancel thread join");

    // 6. Polling event future now returns Cancelled and removes the registration
    let poll_result_2 = Pin::new(&mut event_future).poll(&mut cx);
    assert!(matches!(
        poll_result_2,
        Poll::Ready(Err(WaitServiceError::Cancelled(
            CancellationCause::ProcessExit
        )))
    ));
    assert!(
        !service
            .inner
            .state
            .lock()
            .entries
            .contains_key(&token.continuation),
        "registration removed only after quiescence"
    );

    // 7. Verify payload was written before cancel completed
    let mut buf = vec![0u8; payload.len()];
    let read_bytes = unsafe { libc::read(pipe[0], buf.as_mut_ptr().cast(), buf.len()) };
    assert_eq!(read_bytes as usize, payload.len());
    assert_eq!(buf, payload);

    service.clear_test_hooks();
    close_pair(pipe);
}

#[test]
fn cancellation_before_drive_prevents_fresh_host_work() {
    let (kernel, context) = bootstrap(15_383);
    let generation = publish(&context, 0x723);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let service = CarrierWaitService::new(scheduler);

    let pipe = pipe_pair();
    let dummy = fill_pipe(pipe[1]);

    let payload = vec![9, 8, 7, 6];
    let write = BlockingHostWrite::for_tests(
        pipe[1],
        payload.clone(),
        0,
        context.thread().registry_id(),
        false,
    )
    .expect("write state");
    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::BlockingHostWrite(write),
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("write continuation");
    let mut registration = service.prepare_registration(&continuation);
    service.enroll(&mut registration).expect("enroll write");

    // Cancel registration immediately before reactor drives it
    service
        .cancel_registration_with_cause(registration, CancellationCause::ProcessExit)
        .expect("cancel registration");

    // Drain dummy bytes and run a full reactor cycle
    drain_pipe(pipe[0], dummy.len());
    let observed = service.observe_next_reactor_poll();
    service.nudge_reactor_for_test();
    observed.wait();

    // Verify NO payload bytes were written to the pipe
    let mut buf = vec![0u8; payload.len()];
    let read_bytes = unsafe { libc::read(pipe[0], buf.as_mut_ptr().cast(), buf.len()) };
    assert!(
        read_bytes <= 0,
        "no fresh host write must happen after cancellation"
    );

    close_pair(pipe);
}

#[test]
fn shared_word_lifetime_and_safety_through_cancellation_retirement() {
    let (kernel, context) = bootstrap(15_384);
    let generation = publish(&context, 0x724);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let service = CarrierWaitService::new(scheduler);

    // Allocate atomic word on heap (simulating guest memory)
    let word_box = Box::new(std::sync::atomic::AtomicU32::new(42));
    let word_raw = Box::into_raw(word_box);
    let location = SharedFutexLocation::Direct {
        word: HostVa(word_raw as usize),
        waiter_key: 0xbeef,
    };

    let futex_wait =
        carrick_thread::platform_futex::carrier_shared_futex_table().prepare_wait(0xbeef);
    let mut continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnSharedWord {
            location,
            waiter_key: 0xbeef,
            generation: futex_wait,
            value: 42,
            sysv: None,
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("shared word continuation");
    let mut registration = service.prepare_registration(&continuation);
    let token = registration.wake_token();
    service.enroll(&mut registration).expect("enroll");
    continuation
        .attach_registration(registration)
        .expect("attach registration");

    let (claim_started_tx, claim_started_rx) = std::sync::mpsc::sync_channel(1);
    let (cancel_started_tx, cancel_started_rx) = std::sync::mpsc::sync_channel(1);
    let cancel_started_rx = Arc::new(std::sync::Mutex::new(cancel_started_rx));

    service.set_after_recheck_claim_hook(move || {
        let _ = claim_started_tx.send(());
        let _ = cancel_started_rx
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5));
    });

    let service_for_recheck = service.clone();
    let recheck_thread = thread::spawn(move || {
        // Background thread runs recheck_registration
        let reg = ContinuationRegistration {
            token,
            service: Arc::downgrade(&service_for_recheck.inner),
            enrolled: true,
            settled: true,
        };
        service_for_recheck.recheck_registration(&reg)
    });

    claim_started_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("recheck claimed gate");

    let (cancel_done_tx, cancel_done_rx) = std::sync::mpsc::sync_channel(1);
    let cancel_thread = thread::spawn(move || {
        let receipt = continuation.cancel(CancellationCause::ThreadExit);
        cancel_done_tx.send(receipt).expect("send receipt");
    });

    // Verify cancel cannot retire while recheck claim is held
    assert!(
        cancel_done_rx
            .recv_timeout(Duration::from_millis(50))
            .is_err(),
        "cancel must block on drain while claim is held"
    );

    cancel_started_tx.send(()).expect("unblock recheck");

    let receipt = cancel_done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("cancel completed");
    assert_eq!(receipt.cause(), CancellationCause::ThreadExit);

    let recheck_result = recheck_thread.join().expect("recheck thread join");
    assert!(recheck_result.is_ok());
    // Publication was rejected because cancellation won, so recheck returns Ok(None)
    assert_eq!(recheck_result.unwrap(), None);

    cancel_thread.join().expect("cancel thread join");

    // Now memory is safely dropped on heap without any risk of concurrent access
    unsafe {
        drop(Box::from_raw(word_raw));
    }

    service.clear_test_hooks();
}

#[test]
fn recheck_registration_race_rejects_late_publication_and_requeues_reserved_signal() {
    let (kernel, context) = bootstrap(15_385);
    let generation = publish(&context, 0x725);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let service = CarrierWaitService::new(scheduler);

    let signal = crate::kernel::LinuxSignal::for_signal_number(10).expect("SIGUSR1");

    let mut continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnSignals {
            wait_set: SigSet::EMPTY.with(signal.raw()),
            block_mask: SigBlockMask::NONE,
            timeout: None,
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("signals continuation");
    let mut registration = service.prepare_registration(&continuation);
    let token = registration.wake_token();
    service.enroll(&mut registration).expect("enroll");
    continuation
        .attach_registration(registration)
        .expect("attach registration");

    // Queue deliverable signal after enrollment so recheck_registration exercises the probe race
    context
        .signal_authority()
        .enqueue_thread_standard(signal, None);

    let (probe_started_tx, probe_started_rx) = std::sync::mpsc::sync_channel(1);
    let (cancel_done_tx, cancel_done_rx) = std::sync::mpsc::sync_channel(1);
    let cancel_done_rx = Arc::new(std::sync::Mutex::new(cancel_done_rx));

    service.set_after_recheck_claim_hook(move || {
        let _ = probe_started_tx.send(());
        let _ = cancel_done_rx
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5));
    });

    let service_for_recheck = service.clone();
    let recheck_thread = thread::spawn(move || {
        let reg = ContinuationRegistration {
            token,
            service: Arc::downgrade(&service_for_recheck.inner),
            enrolled: true,
            settled: true,
        };
        service_for_recheck.recheck_registration(&reg)
    });

    probe_started_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("recheck reached probe");

    // Cancel continuation while recheck is in flight
    let (cancel_receipt_tx, cancel_receipt_rx) = std::sync::mpsc::sync_channel(1);
    let cancel_thread = thread::spawn(move || {
        let receipt = continuation.cancel(CancellationCause::ProcessExit);
        cancel_receipt_tx.send(receipt).expect("send receipt");
    });

    // Verify cancel blocks until recheck drops claim
    assert!(
        cancel_receipt_rx
            .recv_timeout(Duration::from_millis(50))
            .is_err(),
        "cancel must block on drain"
    );

    cancel_done_tx.send(()).expect("unblock recheck");

    let recheck_result = recheck_thread.join().expect("recheck join");
    assert!(recheck_result.is_ok());
    // Since publication was rejected, recheck_registration returns Ok(None)
    assert_eq!(recheck_result.unwrap(), None);

    let cancel_receipt = cancel_receipt_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("cancel completed");
    assert_eq!(cancel_receipt.cause(), CancellationCause::ProcessExit);
    cancel_thread.join().expect("cancel thread join");

    // Verify that the signal was requeued to the signal authority and not lost
    assert!(
        context
            .signal_authority()
            .thread_pending()
            .contains(signal.raw())
    );

    service.clear_test_hooks();
}

#[test]
fn stale_and_reused_token_rejection_prevents_cross_wait_resurrection() {
    let (kernel, context) = bootstrap(15_386);
    let generation = publish(&context, 0x726);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let service = CarrierWaitService::new(scheduler);

    let continuation1 = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnSleep {
            duration: Duration::from_secs(60),
            remaining: None,
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("continuation1");
    let mut registration1 = service.prepare_registration(&continuation1);
    service.enroll(&mut registration1).expect("enroll 1");
    let stale_token = registration1.wake_token();

    // Cancel registration 1
    service
        .cancel_registration_with_cause(registration1, CancellationCause::ProcessExit)
        .expect("cancel 1");

    // Prepare registration 2
    let continuation2 = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnSleep {
            duration: Duration::from_secs(60),
            remaining: None,
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("continuation2");
    let mut registration2 = service.prepare_registration(&continuation2);
    service.enroll(&mut registration2).expect("enroll 2");
    let fresh_token = registration2.wake_token();

    // Publishing with stale token must be rejected
    let stale_receipt = service
        .inner
        .publish_event(stale_token, ContinuationEvent::Ready);
    assert!(
        !stale_receipt.accepted(),
        "stale token publication must be rejected"
    );

    // Fresh token is still Enrolled and not ready
    assert_eq!(
        service
            .inner
            .state
            .lock()
            .entries
            .get(&fresh_token.continuation)
            .expect("fresh entry")
            .state,
        RegistrationState::Enrolled
    );

    // Publishing with fresh token succeeds
    let fresh_receipt = service
        .inner
        .publish_event(fresh_token, ContinuationEvent::Ready);
    assert!(
        fresh_receipt.accepted(),
        "fresh token publication must succeed"
    );
    assert_eq!(
        service
            .inner
            .state
            .lock()
            .entries
            .get(&fresh_token.continuation)
            .expect("fresh entry")
            .state,
        RegistrationState::Ready
    );

    drop(continuation1);
    drop(continuation2);
}

#[test]
fn unrelated_waiter_progress_during_concurrent_host_write() {
    let (kernel, context) = bootstrap(15_387);
    let generation = publish(&context, 0x727);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let service = CarrierWaitService::new(scheduler);

    let pipe = pipe_pair();
    let write = BlockingHostWrite::for_tests(
        pipe[1],
        vec![1, 2, 3, 4],
        0,
        context.thread().registry_id(),
        false,
    )
    .expect("write state");
    let write_cont = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::BlockingHostWrite(write),
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("write continuation");
    let mut write_reg = service.prepare_registration(&write_cont);
    service.enroll(&mut write_reg).expect("enroll write");

    let write_arc = match &write_cont.state().detail {
        ContinuationDetail::HostWrite(w) => Arc::clone(w),
        _ => unreachable!(),
    };

    let barrier_locked = Arc::new(Barrier::new(2));
    let barrier_finish = Arc::new(Barrier::new(2));

    let b_locked = Arc::clone(&barrier_locked);
    let b_finish = Arc::clone(&barrier_finish);
    let w_held = Arc::clone(&write_arc);

    let locker_thread = thread::spawn(move || {
        let _guard = w_held.lock();
        b_locked.wait();
        b_finish.wait();
    });

    // Wait until locker_thread holds write.lock()
    barrier_locked.wait();

    // An unrelated waiter enrolls and rechecks while write.lock() is held
    let sleep_cont = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnSleep {
            duration: Duration::from_millis(1),
            remaining: None,
        },
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("sleep continuation");
    let mut sleep_reg = service.prepare_registration(&sleep_cont);
    service
        .enroll(&mut sleep_reg)
        .expect("enroll sleep must not block on write lock");

    let sleep_token = sleep_reg.wake_token();
    let sleep_receipt = service
        .inner
        .publish_event(sleep_token, ContinuationEvent::Ready);
    assert!(sleep_receipt.accepted());

    barrier_finish.wait();
    locker_thread.join().expect("locker thread join");
    close_pair(pipe);
}

#[test]
fn lock_ordering_opposing_locks_rendezvous_completes_without_deadlock() {
    // A broken production lock order can deadlock irrecoverably. Contain
    // that interleaving in an owned child so the regression itself fails
    // with an assertion and leaves no live blocked test threads.
    const CHILD_MARKER: &str = "CARRICK_WAIT_LOCK_ORDER_TEST_CHILD";
    if std::env::var_os(CHILD_MARKER).as_deref() != Some(std::ffi::OsStr::new("1")) {
        let mut child = spawn_contained_test_child(
            "vcpu_loop::continuation::tests::lock_ordering_opposing_locks_rendezvous_completes_without_deadlock",
            CHILD_MARKER,
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().expect("read child status") {
                break Some(status);
            }
            if Instant::now() >= deadline {
                child.kill().expect("reap deadlocked child");
                let status = child.wait().expect("wait for killed child");
                eprintln!(
                    "contained lock-order child {} reaped with {status}",
                    child.id()
                );
                break None;
            }
            thread::sleep(Duration::from_millis(10));
        };
        assert!(
            status.is_some_and(|status| status.success()),
            "production lock-order child must complete successfully within its bound; child was reaped"
        );
        return;
    }
    let (kernel, context) = bootstrap(15_388);
    let generation = publish(&context, 0x728);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let service = CarrierWaitService::new(scheduler);

    let pipe = pipe_pair();
    let dummy = fill_pipe(pipe[1]);

    let payload = vec![1, 2, 3, 4];
    let write = BlockingHostWrite::for_tests(
        pipe[1],
        payload.clone(),
        0,
        context.thread().registry_id(),
        false,
    )
    .expect("write state");
    let mut continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::BlockingHostWrite(write),
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("write continuation");
    let mut registration = service.prepare_registration(&continuation);
    let token = registration.wake_token();

    service.enroll(&mut registration).expect("enroll write");
    continuation
        .attach_registration(registration)
        .expect("attach registration");

    let (reactor_reached_tx, reactor_reached_rx) = std::sync::mpsc::sync_channel(1);
    let (reactor_unblock_tx, reactor_unblock_rx) = std::sync::mpsc::sync_channel(1);
    let reactor_unblock_rx = Arc::new(std::sync::Mutex::new(reactor_unblock_rx));

    let (recheck_reached_tx, recheck_reached_rx) = std::sync::mpsc::sync_channel(1);
    let (recheck_unblock_tx, recheck_unblock_rx) = std::sync::mpsc::sync_channel(1);
    let recheck_unblock_rx = Arc::new(std::sync::Mutex::new(recheck_unblock_rx));

    // 1. Real reactor hook inside drive_blocking_host_write while holding write lock & claim
    service.set_inside_host_write_hook(move || {
        let _ = reactor_reached_tx.send(());
        let _ = reactor_unblock_rx
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5));
    });

    // 2. Recheck hook after acquiring claim, before probing write lock
    service.set_after_recheck_claim_hook(move || {
        let _ = recheck_reached_tx.send(());
        let _ = recheck_unblock_rx
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5));
    });

    // Drain pipe so real reactor wakes and executes drive_blocking_host_write
    drain_pipe(pipe[0], dummy.len());
    service.nudge_reactor_for_test();

    // Wait until real reactor thread is inside write lock holding OperationClaimGuard
    reactor_reached_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("real reactor reached inside drive hook");

    // Concurrent thread runs recheck_registration while reactor is inside drive hook
    let service_for_recheck = service.clone();
    let recheck_thread = thread::spawn(move || {
        let reg = ContinuationRegistration {
            token,
            service: Arc::downgrade(&service_for_recheck.inner),
            enrolled: true,
            settled: true,
        };
        service_for_recheck.recheck_registration(&reg)
    });

    // Acknowledge that recheck reached its claim point without deadlocking on service.state
    recheck_reached_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("recheck reached claim hook concurrently");

    // Unblock both threads in defined order
    recheck_unblock_tx.send(()).expect("unblock recheck");
    reactor_unblock_tx.send(()).expect("unblock reactor");

    let recheck_result = recheck_thread.join().expect("recheck join");
    assert!(recheck_result.is_ok());

    assert_eq!(
        await_event(&service, token).expect("ready event"),
        ContinuationEvent::Ready
    );

    let mut buf = vec![0u8; payload.len()];
    let read_bytes = unsafe { libc::read(pipe[0], buf.as_mut_ptr().cast(), buf.len()) };
    assert_eq!(read_bytes as usize, payload.len());
    assert_eq!(buf, payload);

    service.clear_test_hooks();
    close_pair(pipe);
}

#[test]
fn syslog_read_continuation_real_fd_event_and_redispatch() {
    let (kernel, context) = bootstrap(15_390);
    context.task().with_caps(|caps| {
        caps.effective |= 1 << crate::namespace::process::CAP_SYSLOG;
        caps.permitted |= 1 << crate::namespace::process::CAP_SYSLOG;
    });

    // Drain any bootstrap records
    let _ = kernel.syslog().read_consuming(65536);
    assert_eq!(kernel.syslog().size_unread(), 0);

    let mut dispatcher = crate::dispatch::SyscallDispatcher::new();
    let mut memory = crate::dispatch::LinearMemory::new(0x4000, vec![0u8; 1024]);
    let reporter = crate::compat::CompatReporter::default();

    // 1. Dispatch action 2 (SYSLOG_ACTION_READ) on empty ring -> WaitOnFds
    let req = crate::dispatch::SyscallRequest::new(
        116,
        crate::compat::SyscallArgs([2, 0x4000, 512, 0, 0, 0]),
    );
    let outcome = dispatcher
        .dispatch(&context, req, &mut memory, &reporter)
        .unwrap();
    assert!(matches!(&outcome, DispatchOutcome::WaitOnFds { .. }));

    // 2. Convert to BlockedContinuation and enroll in CarrierWaitService
    let generation = publish(&context, 0x981);
    let mut continuation = BlockedContinuation::from_dispatch_outcome(
        outcome,
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("syslog blocked continuation");

    let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let service = CarrierWaitService::new(scheduler);
    let mut registration = service.prepare_registration(&continuation);
    service
        .enroll(&mut registration)
        .expect("enroll syslog continuation");
    let wake_token = registration.wake_token();
    continuation
        .attach_registration(registration)
        .expect("attach registration");

    // 3. Producer thread appends a log record after enrollment
    let kernel_clone = Arc::clone(&kernel);
    let barrier = Arc::new(Barrier::new(2));
    let barrier_clone = Arc::clone(&barrier);
    let producer = thread::spawn(move || {
        barrier_clone.wait();
        thread::sleep(Duration::from_millis(20));
        kernel_clone
            .syslog()
            .append(6, 0, 12345, b"continuation log record\n".to_vec());
    });

    barrier.wait();
    let event = match await_event_timeout(&service, wake_token, Duration::from_secs(5)) {
        Some(res) => res.expect("syslog wake event"),
        None => {
            let _ = continuation.cancel(CancellationCause::ServiceShutdown);
            let _ = producer.join();
            panic!("syslog continuation wait timed out: missing producer readiness notification");
        }
    };
    assert_eq!(event, ContinuationEvent::Ready);
    producer.join().expect("producer join");

    // 4. Resume continuation to consume registration from service
    let resume_res = continuation
        .resume(event, &context)
        .expect("continuation resume");
    assert_eq!(resume_res.completion, ContinuationCompletion::Redispatch);

    // 5. Syscall continuation redispatch consumes the record
    let outcome2 = dispatcher
        .dispatch(&context, req, &mut memory, &reporter)
        .unwrap();
    match outcome2 {
        DispatchOutcome::Returned { value } => {
            assert!(value > 0);
            let bytes = memory.read_bytes(0x4000, value as usize).unwrap();
            assert_eq!(bytes, b"<6>continuation log record\n");
        }
        other => panic!("expected Returned on redispatch, got {other:?}"),
    }
}

#[test]
fn syslog_read_continuation_cancellation_and_retirement() {
    let (kernel, context) = bootstrap(15_391);
    context.task().with_caps(|caps| {
        caps.effective |= 1 << crate::namespace::process::CAP_SYSLOG;
        caps.permitted |= 1 << crate::namespace::process::CAP_SYSLOG;
    });

    let _ = kernel.syslog().read_consuming(65536);
    assert_eq!(kernel.syslog().size_unread(), 0);

    let mut dispatcher = crate::dispatch::SyscallDispatcher::new();
    let mut memory = crate::dispatch::LinearMemory::new(0x4000, vec![0u8; 1024]);
    let reporter = crate::compat::CompatReporter::default();

    let req = crate::dispatch::SyscallRequest::new(
        116,
        crate::compat::SyscallArgs([2, 0x4000, 512, 0, 0, 0]),
    );
    let outcome = dispatcher
        .dispatch(&context, req, &mut memory, &reporter)
        .unwrap();
    assert!(matches!(&outcome, DispatchOutcome::WaitOnFds { .. }));

    let generation = publish(&context, 0x982);
    let mut continuation = BlockedContinuation::from_dispatch_outcome(
        outcome,
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("syslog blocked continuation");

    let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let service = CarrierWaitService::new(scheduler);
    let mut registration = service.prepare_registration(&continuation);
    service
        .enroll(&mut registration)
        .expect("enroll syslog continuation");
    let wake_token = registration.wake_token();
    continuation
        .attach_registration(registration)
        .expect("attach registration");

    // 1. Verify active enrollment state in CarrierWaitService
    {
        let state = service.inner.state.lock();
        let entry = state
            .entries
            .get(&wake_token.continuation)
            .expect("enrolled continuation entry");
        assert_eq!(entry.state, RegistrationState::Enrolled);
        assert!(
            state
                .reactor_work
                .pollable
                .contains(&wake_token.continuation),
            "enrolled syslog continuation must be in reactor pollable set"
        );
    }

    // 2. Cancel the continuation before data append
    let receipt = continuation.cancel(CancellationCause::ProcessExit);
    assert_eq!(receipt.cause(), CancellationCause::ProcessExit);
    assert_eq!(receipt.continuation, wake_token.continuation);

    // 3. Exact ownership-state assertions against CarrierWaitService API:
    // (a) Wake token retirement / subscription removal from reactor work set
    {
        let state = service.inner.state.lock();
        let entry = state
            .entries
            .get(&wake_token.continuation)
            .expect("cancelled continuation entry");
        assert_eq!(
            entry.state,
            RegistrationState::Cancelled(CancellationCause::ProcessExit)
        );
        assert!(
            !state
                .reactor_work
                .pollable
                .contains(&wake_token.continuation),
            "cancelled continuation must be removed from reactor pollable work set"
        );
    }

    // (b) Stale Ready rejection: publishing ready to cancelled token must be rejected
    let stale_publish_receipt = service.publish_ready(wake_token);
    assert!(
        !stale_publish_receipt.accepted(),
        "stale Ready publish on cancelled token must be rejected"
    );
    assert!(
        !stale_publish_receipt.first_publication(),
        "stale Ready publish must not be first"
    );

    // (c) Event future resolution: awaiting event on cancelled token returns Cancelled and purges entry
    let event_res = await_event(&service, wake_token);
    assert!(
        matches!(
            event_res,
            Err(WaitServiceError::Cancelled(CancellationCause::ProcessExit))
        ),
        "awaiting event on cancelled token must return Cancelled(ProcessExit)"
    );
    assert!(
        !service
            .inner
            .state
            .lock()
            .entries
            .contains_key(&wake_token.continuation),
        "cancelled entry must be fully purged after event future resolution"
    );
    assert!(
        matches!(
            service.registration_timing(wake_token),
            Err(WaitServiceError::StaleRegistration)
        ),
        "retired continuation timing must report StaleRegistration"
    );

    // 4. Producer writes record after old waiter cancellation and retirement
    kernel
        .syslog()
        .append(6, 0, 12346, b"post-cancel record\n".to_vec());

    // 5. Subsequent fresh dispatch consumes the record without issue
    let outcome2 = dispatcher
        .dispatch(&context, req, &mut memory, &reporter)
        .unwrap();
    match outcome2 {
        DispatchOutcome::Returned { value } => {
            assert!(value > 0);
            let bytes = memory.read_bytes(0x4000, value as usize).unwrap();
            assert_eq!(bytes, b"<6>post-cancel record\n");
        }
        other => panic!("expected Returned on fresh dispatch, got {other:?}"),
    }
}

#[test]
fn controller_mixed_ppoll_netlink_real_service_wake() {
    use carrick_guest_mem::GuestMemory;
    use std::future::Future;
    let mut dispatcher = crate::dispatch::SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().unwrap();
    let kernel = Arc::clone(context.kernel());
    let mut memory = crate::dispatch::LinearMemory::new(0x4000, vec![0u8; 4096]);
    let reporter = crate::compat::CompatReporter::default();
    fn returned(outcome: DispatchOutcome) -> i64 {
        match outcome {
            DispatchOutcome::Returned { value } => value,
            other => panic!("fixture syscall: {other:?}"),
        }
    }
    let efd = returned(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(19, SyscallArgs([0; 6])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
    );
    let nlfd = returned(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(198, SyscallArgs([16, 3, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
    );
    let mut pollfds = [0u8; 16];
    pollfds[0..4].copy_from_slice(&(efd as i32).to_le_bytes());
    pollfds[4..6].copy_from_slice(&1i16.to_le_bytes());
    pollfds[8..12].copy_from_slice(&(nlfd as i32).to_le_bytes());
    pollfds[12..14].copy_from_slice(&1i16.to_le_bytes());
    memory.write_bytes(0x4000, &pollfds).unwrap();
    let req = SyscallRequest::new(73, SyscallArgs([0x4000, 2, 0, 0, 0, 0]));
    let outcome = dispatcher
        .dispatch(&context, req, &mut memory, &reporter)
        .unwrap();
    assert!(
        matches!(
            &outcome,
            DispatchOutcome::WaitOnFds {
                completion: FdWaitCompletion::Poll { .. },
                ..
            }
        ),
        "mixed ppoll must yield: {outcome:?}"
    );
    let generation = publish(&context, 0x982);
    let mut continuation = BlockedContinuation::from_dispatch_outcome(
        outcome,
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("actual mixed ppoll continuation");
    let service = CarrierWaitService::new(Arc::new(Scheduler::new(kernel)));
    let mut registration = service.prepare_registration(&continuation);
    service
        .enroll(&mut registration)
        .expect("enroll real mixed ppoll");
    let token = registration.wake_token();
    continuation
        .attach_registration(registration)
        .expect("attach real registration");

    // Produce a real synthetic netlink reply after enrollment; eventfd stays empty.
    let mut header = [0u8; 16];
    header[0..4].copy_from_slice(&16u32.to_le_bytes());
    header[4..6].copy_from_slice(&18u16.to_le_bytes());
    header[6..8].copy_from_slice(&0x301u16.to_le_bytes());
    header[8..12].copy_from_slice(&1u32.to_le_bytes());
    memory.write_bytes(0x4100, &header).unwrap();
    assert_eq!(
        returned(
            dispatcher
                .dispatch(
                    &context,
                    SyscallRequest::new(206, SyscallArgs([nlfd as u64, 0x4100, 16, 0, 0, 0])),
                    &mut memory,
                    &reporter
                )
                .unwrap()
        ),
        16
    );

    struct ThreadWake(std::thread::Thread);
    impl std::task::Wake for ThreadWake {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(service.event(token));
    let deadline = Instant::now() + Duration::from_secs(5);
    let event = loop {
        if let Poll::Ready(event) = future.as_mut().poll(&mut cx) {
            break Some(event);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break None;
        }
        std::thread::park_timeout(remaining);
    };
    if event.is_none() {
        let _ = continuation.cancel(CancellationCause::ServiceShutdown);
        let observed = dispatcher
            .dispatch(&context, req, &mut memory, &reporter)
            .unwrap();
        panic!("real mixed ppoll lost synthetic producer wake; fresh logical recheck={observed:?}");
    }
    let event = event.unwrap().expect("real producer wake");
    assert_eq!(event, ContinuationEvent::Ready);
    assert_eq!(
        continuation.resume(event, &context).unwrap().completion,
        ContinuationCompletion::Redispatch
    );
    assert_eq!(
        dispatcher
            .dispatch(&context, req, &mut memory, &reporter)
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );
}

#[test]
fn controller_nested_epoll_real_service_wake() {
    use carrick_guest_mem::GuestMemory;
    use std::future::Future;
    let mut dispatcher = crate::dispatch::SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().unwrap();
    let kernel = Arc::clone(context.kernel());
    let mut memory = crate::dispatch::LinearMemory::new(0x4000, vec![0u8; 4096]);
    let reporter = crate::compat::CompatReporter::default();
    fn returned(outcome: DispatchOutcome) -> i64 {
        match outcome {
            DispatchOutcome::Returned { value } => value,
            other => panic!("fixture syscall: {other:?}"),
        }
    }
    let efd = returned(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(19, SyscallArgs([0; 6])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
    );
    let inner = returned(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(20, SyscallArgs([0; 6])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
    );
    let outer = returned(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(20, SyscallArgs([0; 6])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
    );
    // inner epoll watches efd (EPOLLIN, data=101)
    let mut ev = [0u8; 16];
    ev[0..4].copy_from_slice(&carrick_abi::LINUX_EPOLLIN.to_le_bytes());
    ev[8..16].copy_from_slice(&101u64.to_le_bytes());
    memory.write_bytes(0x4000, &ev).unwrap();
    assert_eq!(
        returned(
            dispatcher
                .dispatch(
                    &context,
                    SyscallRequest::new(
                        21,
                        SyscallArgs([
                            inner as u64,
                            carrick_abi::LINUX_EPOLL_CTL_ADD,
                            efd as u64,
                            0x4000,
                            0,
                            0
                        ])
                    ),
                    &mut memory,
                    &reporter
                )
                .unwrap()
        ),
        0
    );
    // outer epoll watches inner (EPOLLIN, data=202)
    ev[8..16].copy_from_slice(&202u64.to_le_bytes());
    memory.write_bytes(0x4020, &ev).unwrap();
    assert_eq!(
        returned(
            dispatcher
                .dispatch(
                    &context,
                    SyscallRequest::new(
                        21,
                        SyscallArgs([
                            outer as u64,
                            carrick_abi::LINUX_EPOLL_CTL_ADD,
                            inner as u64,
                            0x4020,
                            0,
                            0
                        ])
                    ),
                    &mut memory,
                    &reporter
                )
                .unwrap()
        ),
        0
    );

    // epoll_pwait on outer with no timeout (yields continuation)
    let req = SyscallRequest::new(22, SyscallArgs([outer as u64, 0x4040, 1, !0u64, 0, 0]));
    let outcome = dispatcher
        .dispatch(&context, req, &mut memory, &reporter)
        .unwrap();
    assert!(
        matches!(
            &outcome,
            DispatchOutcome::WaitOnFds {
                completion: FdWaitCompletion::Poll { .. },
                ..
            }
        ),
        "nested epoll wait must yield: {outcome:?}"
    );
    let generation = publish(&context, 0x983);
    let mut continuation = BlockedContinuation::from_dispatch_outcome(
        outcome,
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("actual nested epoll continuation");
    let service = CarrierWaitService::new(Arc::new(Scheduler::new(kernel)));
    let mut registration = service.prepare_registration(&continuation);
    service
        .enroll(&mut registration)
        .expect("enroll nested epoll");
    let token = registration.wake_token();
    continuation
        .attach_registration(registration)
        .expect("attach nested epoll registration");

    // Write 1 to efd
    memory.write_bytes(0x4100, &1u64.to_le_bytes()).unwrap();
    assert_eq!(
        returned(
            dispatcher
                .dispatch(
                    &context,
                    SyscallRequest::new(64, SyscallArgs([efd as u64, 0x4100, 8, 0, 0, 0])),
                    &mut memory,
                    &reporter
                )
                .unwrap()
        ),
        8
    );

    struct ThreadWake(std::thread::Thread);
    impl std::task::Wake for ThreadWake {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(service.event(token));
    let deadline = Instant::now() + Duration::from_secs(5);
    let event = loop {
        if let Poll::Ready(event) = future.as_mut().poll(&mut cx) {
            break Some(event);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break None;
        }
        std::thread::park_timeout(remaining);
    };
    if event.is_none() {
        let _ = continuation.cancel(CancellationCause::ServiceShutdown);
        let observed = dispatcher
            .dispatch(&context, req, &mut memory, &reporter)
            .unwrap();
        panic!("nested epoll lost synthetic producer wake; fresh logical recheck={observed:?}");
    }
    let event = event.unwrap().expect("nested epoll wake");
    assert_eq!(event, ContinuationEvent::Ready);
    assert_eq!(
        continuation.resume(event, &context).unwrap().completion,
        ContinuationCompletion::Redispatch
    );
    assert_eq!(
        dispatcher
            .dispatch(&context, req, &mut memory, &reporter)
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );
}

#[test]
fn controller_carrier_wait_service_cancellation_and_retirement() {
    use carrick_guest_mem::GuestMemory;
    let mut dispatcher = crate::dispatch::SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().unwrap();
    let kernel = Arc::clone(context.kernel());
    let mut memory = crate::dispatch::LinearMemory::new(0x4000, vec![0u8; 4096]);
    let reporter = crate::compat::CompatReporter::default();
    fn returned(outcome: DispatchOutcome) -> i64 {
        match outcome {
            DispatchOutcome::Returned { value } => value,
            other => panic!("fixture syscall: {other:?}"),
        }
    }
    let efd = returned(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(19, SyscallArgs([0; 6])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
    );
    let files = context.resources().files();
    let slot = crate::kernel::FileSlotNumber::for_open_fd(efd as i32).unwrap();
    let slot_authority = files.capture_slot_or_stdio_authority(slot).unwrap();
    let efd_desc = files.resolve_slot_authority(slot_authority).unwrap();
    let efd_wq = efd_desc.wait_queue().unwrap();
    assert_eq!(efd_wq.callback_count(), 0, "initial callback count is 0");

    let mut pollfds = [0u8; 8];
    pollfds[0..4].copy_from_slice(&(efd as i32).to_le_bytes());
    pollfds[4..6].copy_from_slice(&1i16.to_le_bytes());
    memory.write_bytes(0x4000, &pollfds).unwrap();
    let req = SyscallRequest::new(73, SyscallArgs([0x4000, 1, 0, 0, 0, 0]));
    let outcome = dispatcher
        .dispatch(&context, req, &mut memory, &reporter)
        .unwrap();
    assert!(matches!(&outcome, DispatchOutcome::WaitOnFds { .. }));

    let generation = publish(&context, 0x984);
    let mut continuation = BlockedContinuation::from_dispatch_outcome(
        outcome,
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("continuation");
    let service = CarrierWaitService::new(Arc::new(Scheduler::new(kernel)));
    let mut registration = service.prepare_registration(&continuation);
    service.enroll(&mut registration).expect("enroll");
    let token = registration.wake_token();
    continuation
        .attach_registration(registration)
        .expect("attach");

    // While enrolled, wait_queue has 1 callback
    assert_eq!(efd_wq.callback_count(), 1, "callback enrolled while active");

    // Cancel continuation
    let receipt = continuation.cancel(CancellationCause::ThreadExit);
    assert_eq!(receipt.cleanup_count(), 1);

    // After cancellation, callback is immediately removed
    assert_eq!(
        efd_wq.callback_count(),
        0,
        "callback removed upon cancellation"
    );

    // A producer write after cancellation must NOT publish to cancelled token
    let publish_receipt = service.publish_ready(token);
    assert!(
        !publish_receipt.accepted(),
        "publication to cancelled token must be rejected"
    );

    // Close efd and reinstall another descriptor at the same slot
    assert_eq!(
        returned(
            dispatcher
                .dispatch(
                    &context,
                    SyscallRequest::new(57, SyscallArgs([efd as u64, 0, 0, 0, 0, 0])),
                    &mut memory,
                    &reporter
                )
                .unwrap()
        ),
        0
    );
    let new_efd = returned(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(19, SyscallArgs([0; 6])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
    );
    assert_eq!(new_efd, efd, "reused fd slot");

    // Write to new descriptor
    memory.write_bytes(0x4100, &5u64.to_le_bytes()).unwrap();
    assert_eq!(
        returned(
            dispatcher
                .dispatch(
                    &context,
                    SyscallRequest::new(64, SyscallArgs([new_efd as u64, 0x4100, 8, 0, 0, 0])),
                    &mut memory,
                    &reporter
                )
                .unwrap()
        ),
        8
    );
    // Stale token still rejected
    assert!(
        !service.publish_ready(token).accepted(),
        "stale token publication rejected after slot reuse"
    );
}

#[test]
fn controller_in_flight_callback_rejected_on_retired_or_recycled_registration() {
    use carrick_guest_mem::GuestMemory;
    let mut dispatcher = crate::dispatch::SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().unwrap();
    let kernel = Arc::clone(context.kernel());
    let mut memory = crate::dispatch::LinearMemory::new(0x4000, vec![0u8; 4096]);
    let reporter = crate::compat::CompatReporter::default();
    fn returned(outcome: DispatchOutcome) -> i64 {
        match outcome {
            DispatchOutcome::Returned { value } => value,
            other => panic!("fixture syscall: {other:?}"),
        }
    }
    let efd = returned(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(19, SyscallArgs([0; 6])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
    );
    let mut pollfds = [0u8; 8];
    pollfds[0..4].copy_from_slice(&(efd as i32).to_le_bytes());
    pollfds[4..6].copy_from_slice(&1i16.to_le_bytes());
    memory.write_bytes(0x4000, &pollfds).unwrap();
    let req = SyscallRequest::new(73, SyscallArgs([0x4000, 1, 0, 0, 0, 0]));
    let outcome = dispatcher
        .dispatch(&context, req, &mut memory, &reporter)
        .unwrap();

    let generation = publish(&context, 0x985);
    let mut continuation1 = BlockedContinuation::from_dispatch_outcome(
        outcome,
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("continuation1");
    let service = CarrierWaitService::new(Arc::new(Scheduler::new(kernel)));
    let mut registration1 = service.prepare_registration(&continuation1);
    service.enroll(&mut registration1).expect("enroll1");
    let token1 = registration1.wake_token();
    continuation1
        .attach_registration(registration1)
        .expect("attach1");

    let files = context.resources().files();
    let slot = crate::kernel::FileSlotNumber::for_open_fd(efd as i32).unwrap();
    let authority = files.capture_slot_or_stdio_authority(slot).unwrap();
    let description = files.resolve_slot_authority(authority).unwrap();
    let callbacks = description
        .wait_queue()
        .unwrap()
        .controller_callback_snapshot();
    assert_eq!(
        callbacks.len(),
        1,
        "capture the actual installed service closure"
    );

    // Simulate wake event on continuation1 and resume (consuming it)
    let receipt1 = service.publish_ready(token1);
    assert!(receipt1.accepted(), "first publish accepted");
    let outcome1 = continuation1
        .resume(ContinuationEvent::Ready, &context)
        .unwrap();
    assert_eq!(outcome1.completion, ContinuationCompletion::Redispatch);

    // Now token1 is completely retired and consumed.
    // Any in-flight callback for token1 must be rejected:
    let in_flight_receipt = service.publish_ready(token1);
    assert!(
        !in_flight_receipt.accepted(),
        "in-flight callback on consumed registration must be rejected"
    );

    // Now create continuation2 on the same thread/slot with a fresh registration generation
    let outcome_fresh = dispatcher
        .dispatch(&context, req, &mut memory, &reporter)
        .unwrap();
    let mut continuation2 = BlockedContinuation::from_dispatch_outcome(
        outcome_fresh,
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("continuation2");
    let mut registration2 = service.prepare_registration(&continuation2);
    service.enroll(&mut registration2).expect("enroll2");
    let token2 = registration2.wake_token();
    assert_ne!(
        token1, token2,
        "new registration has distinct monotonic token"
    );
    continuation2
        .attach_registration(registration2)
        .expect("attach2");

    // Stale in-flight callback for token1 must NOT wake token2
    let stale_receipt = service.publish_ready(token1);
    assert!(
        !stale_receipt.accepted(),
        "stale token1 publication rejected even after new registration token2 exists"
    );

    assert!(
        service
            .inner
            .state
            .lock()
            .entries
            .get(&token2.continuation)
            .unwrap()
            .event
            .is_none(),
        "new registration starts without a queued event"
    );
    // Invoke the actual producer closure captured before retirement, not publish_ready directly.
    callbacks[0](0);
    assert!(
        service
            .inner
            .state
            .lock()
            .entries
            .get(&token2.continuation)
            .unwrap()
            .event
            .is_none(),
        "retired producer closure must not queue an event for the new registration"
    );

    // Proper token2 publication succeeds
    let valid_receipt = service.publish_ready(token2);
    assert!(
        valid_receipt.accepted(),
        "valid token2 publication accepted"
    );
    let outcome2 = continuation2
        .resume(ContinuationEvent::Ready, &context)
        .unwrap();
    assert_eq!(outcome2.completion, ContinuationCompletion::Redispatch);
}

#[test]
fn controller_nested_epoll_5_levels_deep_real_service_wake() {
    use carrick_guest_mem::GuestMemory;
    use std::future::Future;
    let mut dispatcher = crate::dispatch::SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().unwrap();
    let kernel = Arc::clone(context.kernel());
    let mut memory = crate::dispatch::LinearMemory::new(0x4000, vec![0u8; 8192]);
    let reporter = crate::compat::CompatReporter::default();
    fn returned(outcome: DispatchOutcome) -> i64 {
        match outcome {
            DispatchOutcome::Returned { value } => value,
            other => panic!("fixture syscall: {other:?}"),
        }
    }
    let efd = returned(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(19, SyscallArgs([0; 6])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
    );
    let ep1 = returned(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(20, SyscallArgs([0; 6])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
    );
    let ep2 = returned(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(20, SyscallArgs([0; 6])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
    );
    let ep3 = returned(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(20, SyscallArgs([0; 6])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
    );
    let ep4 = returned(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(20, SyscallArgs([0; 6])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
    );
    let ep5 = returned(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(20, SyscallArgs([0; 6])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
    );
    let ep6 = returned(
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(20, SyscallArgs([0; 6])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
    );

    let mut add = |dispatcher: &mut crate::dispatch::SyscallDispatcher,
                   ep: i64,
                   target: i64,
                   data: u64,
                   addr: u64| {
        let mut ev = [0u8; 16];
        ev[0..4].copy_from_slice(&carrick_abi::LINUX_EPOLLIN.to_le_bytes());
        ev[8..16].copy_from_slice(&data.to_le_bytes());
        memory.write_bytes(addr, &ev).unwrap();
        dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(
                    21,
                    SyscallArgs([
                        ep as u64,
                        carrick_abi::LINUX_EPOLL_CTL_ADD,
                        target as u64,
                        addr,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap()
    };

    // ep1 watches efd
    assert_eq!(returned(add(&mut dispatcher, ep1, efd, 101, 0x4000)), 0);
    // ep2 watches ep1
    assert_eq!(returned(add(&mut dispatcher, ep2, ep1, 202, 0x4020)), 0);
    // ep3 watches ep2
    assert_eq!(returned(add(&mut dispatcher, ep3, ep2, 303, 0x4040)), 0);
    // ep4 watches ep3
    assert_eq!(returned(add(&mut dispatcher, ep4, ep3, 404, 0x4060)), 0);
    // ep5 watches ep4 (depth 5)
    assert_eq!(returned(add(&mut dispatcher, ep5, ep4, 505, 0x4080)), 0);

    // 6th level ep6 watches ep5 -> must be rejected with ELOOP (exceeds max nesting depth of 5)
    let eloop_outcome = add(&mut dispatcher, ep6, ep5, 606, 0x40A0);
    assert!(
        matches!(eloop_outcome, DispatchOutcome::Errno { errno } if errno == carrick_abi::LINUX_ELOOP),
        "6th nesting level must be rejected with ELOOP: {eloop_outcome:?}"
    );

    // epoll_pwait on outermost admitted epoll (ep5) with no timeout
    let req = SyscallRequest::new(22, SyscallArgs([ep5 as u64, 0x4100, 1, !0u64, 0, 0]));
    let outcome = dispatcher
        .dispatch(&context, req, &mut memory, &reporter)
        .unwrap();
    assert!(
        matches!(
            &outcome,
            DispatchOutcome::WaitOnFds {
                completion: FdWaitCompletion::Poll { .. },
                ..
            }
        ),
        "nested 5-level epoll wait must yield: {outcome:?}"
    );
    let generation = publish(&context, 0x986);
    let mut continuation = BlockedContinuation::from_dispatch_outcome(
        outcome,
        capture(&context, generation, ContinuationBackend::Hvpatch),
    )
    .expect("actual 5-level nested epoll continuation");
    let service = CarrierWaitService::new(Arc::new(Scheduler::new(kernel)));
    let mut registration = service.prepare_registration(&continuation);
    service
        .enroll(&mut registration)
        .expect("enroll 5-level nested epoll");
    let token = registration.wake_token();
    continuation
        .attach_registration(registration)
        .expect("attach 5-level nested epoll registration");

    // Write 1 to leaf efd
    memory.write_bytes(0x4200, &1u64.to_le_bytes()).unwrap();
    assert_eq!(
        returned(
            dispatcher
                .dispatch(
                    &context,
                    SyscallRequest::new(64, SyscallArgs([efd as u64, 0x4200, 8, 0, 0, 0])),
                    &mut memory,
                    &reporter
                )
                .unwrap()
        ),
        8
    );

    struct ThreadWake(std::thread::Thread);
    impl std::task::Wake for ThreadWake {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(service.event(token));
    let deadline = Instant::now() + Duration::from_secs(5);
    let event = loop {
        if let Poll::Ready(event) = future.as_mut().poll(&mut cx) {
            break Some(event);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break None;
        }
        std::thread::park_timeout(remaining);
    };
    if event.is_none() {
        let _ = continuation.cancel(CancellationCause::ServiceShutdown);
        let observed = dispatcher
            .dispatch(&context, req, &mut memory, &reporter)
            .unwrap();
        panic!(
            "5-level nested epoll lost synthetic producer wake; fresh logical recheck={observed:?}"
        );
    }
    let event = event.unwrap().expect("5-level nested epoll wake");
    assert_eq!(event, ContinuationEvent::Ready);
    assert_eq!(
        continuation.resume(event, &context).unwrap().completion,
        ContinuationCompletion::Redispatch
    );
    assert_eq!(
        dispatcher
            .dispatch(&context, req, &mut memory, &reporter)
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );
    let out_bytes = memory.read_bytes(0x4100, 16).unwrap();
    let out_event =
        <carrick_abi::LinuxEpollEvent as zerocopy::FromBytes>::read_from_bytes(&out_bytes).unwrap();
    let events = out_event.events;
    let data = out_event.data;
    assert_eq!(
        events & carrick_abi::LINUX_EPOLLIN,
        carrick_abi::LINUX_EPOLLIN
    );
    assert_eq!(data, 505);
}
