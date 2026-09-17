//! Deterministic integration tests for ptrace non-child wait continuations.
//!
//! Authority:
//! - `man 2 ptrace`: a tracer may attach to and wait on any permitted tracee,
//!   including non-child siblings and ancestor/root processes (LTP `ptrace11`).
//! - `man 2 wait4`, `man 2 waitid`: wait on a traced process reports stop/continue
//!   events to its tracer even when the tracer is not the tracee's parent.

use std::sync::Arc;
use std::time::Duration;

use carrick_abi::syscall::nr;
use carrick_abi::{
    LINUX_ECHILD, LINUX_P_PID, LINUX_PTRACE_ATTACH, LINUX_SIGCHLD, LINUX_SIGSTOP, LINUX_WEXITED,
    LINUX_WSTOPPED, LinuxCloneFlags,
};
use carrick_hal::{NullGuestTimerBridge, NullHostSignalBridge, ThreadId};
use carrick_kernel::compat::{CompatReporter, SyscallArgs};
use carrick_kernel::dispatch::{
    CarrierBridges, DispatchError, DispatchOutcome, SyscallDispatcher, SyscallRequest, ThreadCtx,
};
use carrick_kernel::kernel::continuation::{
    BlockedContinuation, CarrierWaitService, ContinuationCapture, RestartClass,
    fold_continuation_completion,
};
use carrick_kernel::kernel::objects::ExecutionGeneration;
use carrick_kernel::kernel::{
    CarrierProcess, ChildExitSignal, CloneObjectMode, ClonePlan, KernelContext, LinuxWaitStatus,
    Scheduler,
};
use carrick_kernel::thread::{FutexTable, ThreadRegistry};
use carrick_kernel_example::{
    AddressSpace, AsidAllocator, ExampleProcess, TaskMemory, block_on_timeout,
    seed_initial_task_state,
};

const PTRACE_DETACH: u64 = 17;
const LINUX_CLD_STOPPED: i32 = 5;

struct TestProcess {
    process: Arc<ExampleProcess>,
    context: KernelContext,
    dispatcher: SyscallDispatcher,
    memory: TaskMemory,
    threads: Arc<ThreadRegistry>,
    futex: Arc<FutexTable>,
    execution_generation: ExecutionGeneration,
}

impl TestProcess {
    fn boot_root(asids: &AsidAllocator, diagnostic_name: &str) -> Self {
        let space = AddressSpace::allocate(asids).expect("allocate address space");
        let (process, context) = ExampleProcess::boot_root(
            1,
            diagnostic_name,
            Arc::new(NullHostSignalBridge::default()),
            space,
        )
        .expect("boot root process");
        let process = Arc::new(process);
        let dispatcher = SyscallDispatcher::with_bridges(CarrierBridges {
            host_signal: Arc::new(NullHostSignalBridge::default()),
            timers: Arc::new(NullGuestTimerBridge::default()),
        });
        dispatcher.bind_hvpatch_process(Arc::clone(&process) as Arc<dyn CarrierProcess>);
        if let Some(failure) = process.take_bind_failure() {
            panic!("bind failure: {failure:?}");
        }
        dispatcher
            .activate_file_authority(context.resources().files())
            .expect("activate file authority");
        let execution_generation = seed_initial_task_state(&context, process.asid_generation())
            .expect("seed initial task state");
        let threads = Arc::new(ThreadRegistry::new(ThreadId::from_guest_supplied_tid(1)));
        let futex = Arc::new(FutexTable::new());
        Self {
            process,
            context,
            dispatcher,
            memory: TaskMemory::new(),
            threads,
            futex,
            execution_generation,
        }
    }

    fn fork_child(&mut self, asids: &AsidAllocator, name: &str) -> Self {
        let parent = &self.context;
        let plan = ClonePlan::from_flags(LinuxCloneFlags::empty())
            .expect("clone plan")
            .with_exit_signal(ChildExitSignal::for_clone_request(LINUX_SIGCHLD as u32));
        let reservation = parent
            .kernel()
            .reserve_fork(parent, plan, name.to_owned(), None)
            .expect("reserve fork");
        let child_pid = reservation.visible_child_id();
        let child_tid = ThreadId::from_guest_supplied_tid(child_pid);
        let space = AddressSpace::allocate(asids).expect("allocate child address space");
        let prepared = reservation
            .prepare_with_mm_backend(space.mm_backend(), child_tid)
            .expect("prepare with mm backend");

        let parent_mm_id = parent.shared().mm().id();
        let child_mm_id = prepared.child_mm_id();
        let prepared_mm = self
            .dispatcher
            .prepare_fork_mm(parent_mm_id, child_mm_id, CloneObjectMode::Copy)
            .expect("prepare fork mm");

        let parent_guest_pid = u32::try_from(self.process.pid()).expect("parent pid positive");
        let child_guest_pid = u32::try_from(child_pid).expect("child pid positive");

        let child_dispatcher = self
            .dispatcher
            .with_mm_executor_mutation(|dispatcher, guard| {
                let permit = guard.host_alias_permit();
                dispatcher.fork_clone_with_prepared_mm_authorized(
                    parent_mm_id,
                    child_mm_id,
                    parent_guest_pid,
                    child_guest_pid,
                    prepared_mm,
                    &permit,
                )
            })
            .expect("with mm executor mutation")
            .expect("fork clone with prepared mm");

        let published = prepared.commit().expect("commit prepared fork");
        let (child_context, _vfork) = published.into_parts().expect("published into_parts");
        let child_process = Arc::new(ExampleProcess::new(&child_context, space));
        child_dispatcher
            .bind_hvpatch_process(Arc::clone(&child_process) as Arc<dyn CarrierProcess>);
        if let Some(failure) = child_process.take_bind_failure() {
            panic!("child bind failure: {failure:?}");
        }

        let child_generation =
            seed_initial_task_state(&child_context, child_process.asid_generation())
                .expect("child seed initial task state");
        let child_threads = Arc::new(ThreadRegistry::new(child_tid));
        let child_futex = Arc::new(FutexTable::new());

        Self {
            process: child_process,
            context: child_context,
            dispatcher: child_dispatcher,
            memory: TaskMemory::new(),
            threads: child_threads,
            futex: child_futex,
            execution_generation: child_generation,
        }
    }

    fn dispatch(&mut self, request: SyscallRequest) -> Result<DispatchOutcome, DispatchError> {
        let tid = self.context.thread().registry_id();
        let thread_ctx = ThreadCtx::new(tid, &self.threads, &self.futex);
        let reporter = CompatReporter::default();
        let mut executor = self
            .dispatcher
            .enter_mm_executor()
            .map_err(DispatchError::MmExecutorAdmission)?;
        self.dispatcher.dispatch_threaded_with_mm_executor(
            &mut executor,
            &self.context,
            request,
            &mut self.memory.linear,
            &reporter,
            thread_ctx,
        )
    }

    fn ptrace_attach(&mut self, target_pid: i32) -> Result<DispatchOutcome, DispatchError> {
        let request = SyscallRequest::new(
            nr::PTRACE.raw(),
            SyscallArgs::from([LINUX_PTRACE_ATTACH, target_pid as u64, 0, 0, 0, 0]),
        );
        self.dispatch(request)
    }

    fn ptrace_detach(&mut self, target_pid: i32) -> Result<DispatchOutcome, DispatchError> {
        let request = SyscallRequest::new(
            nr::PTRACE.raw(),
            SyscallArgs::from([PTRACE_DETACH, target_pid as u64, 0, 0, 0, 0]),
        );
        self.dispatch(request)
    }

    fn wait4(
        &mut self,
        pid: i32,
        wstatus_addr: u64,
        options: u64,
        rusage_addr: u64,
    ) -> (SyscallRequest, Result<DispatchOutcome, DispatchError>) {
        let request = SyscallRequest::new(
            nr::WAIT4.raw(),
            SyscallArgs::from([pid as u64, wstatus_addr, options, rusage_addr, 0, 0]),
        );
        let outcome = self.dispatch(request);
        (request, outcome)
    }

    fn waitid(
        &mut self,
        which: u64,
        pid: i32,
        infop_addr: u64,
        options: u64,
        rusage_addr: u64,
    ) -> (SyscallRequest, Result<DispatchOutcome, DispatchError>) {
        let request = SyscallRequest::new(
            nr::WAITID.raw(),
            SyscallArgs::from([which, pid as u64, infop_addr, options, rusage_addr, 0]),
        );
        let outcome = self.dispatch(request);
        (request, outcome)
    }

    fn exit(&mut self, code: i32) {
        let task_key = self.context.task().key();
        self.dispatcher.retire_hvpatch_process_fds(&self.context);
        let adopter = self.dispatcher.hvpatch_orphan_adopter();
        let status = LinuxWaitStatus::from_wait_encoding((code & 0xff) << 8);
        self.context
            .kernel()
            .exit_task_key_eventually_notifying(task_key, status, adopter, |_| {})
            .expect("exit_task_key_eventually_notifying");
    }
}

/// LTP ptrace11 shape: Tracer attaches to PID 1 (ancestor/root), waits before stop settlement,
/// and builds a wait continuation for the non-child tracee.
#[test]
fn ptrace_attach_and_wait_on_ancestor_root_continuation_wait4() {
    let asids = AsidAllocator::new();
    let mut root = TestProcess::boot_root(&asids, "root-pid1");
    let mut tracer = root.fork_child(&asids, "tracer-child");

    let scheduler = Arc::new(Scheduler::new(Arc::clone(root.context.kernel())));
    let wait_service = CarrierWaitService::try_new(scheduler).expect("carrier wait service");

    let wstatus_addr = tracer.memory.alloc_zeroed(4).expect("alloc wstatus");

    // 1. Tracer attaches to PID 1 (ancestor/root).
    let attach_outcome = tracer.ptrace_attach(1).expect("ptrace attach");
    assert_eq!(attach_outcome, DispatchOutcome::Returned { value: 0 });

    // 2. Deterministically hold tracee BEFORE stop settlement.
    // Tracer calls wait4(1, wstatus_addr, 0, 0).
    let (request, wait_outcome) = tracer.wait4(1, wstatus_addr, 0, 0);
    let outcome = wait_outcome.expect("wait4 dispatch");
    assert!(
        matches!(
            outcome,
            DispatchOutcome::WaitOnHvpatchChild {
                target: Some(1),
                ..
            }
        ),
        "expected WaitOnHvpatchChild with target 1, got: {outcome:?}"
    );

    // 3. Build BlockedContinuation from outcome and capture.
    let capture = ContinuationCapture::new(
        &tracer.context,
        tracer.execution_generation,
        request,
        RestartClass::Never,
    )
    .expect("continuation capture");

    let mut continuation = BlockedContinuation::from_dispatch_outcome(outcome, capture)
        .expect("continuation build for non-child tracee (ancestor/root) must succeed");

    continuation.install_temporary_signal_mask(&tracer.context);
    continuation.bind_product_futex(&tracer.futex);

    // 4. Enroll in wait service.
    let mut registration = wait_service.prepare_registration(&continuation);
    wait_service
        .enroll(&mut registration)
        .expect("enroll wait registration");
    let token = registration.wake_token();
    continuation
        .attach_registration(registration)
        .expect("attach registration");

    // 5. Root settles ptrace stop.
    let stopped = root.process.stop_for_ptrace_signal(LINUX_SIGSTOP as i32);
    assert!(stopped, "root stop_for_ptrace_signal must succeed");

    // 6. Wait service receives event.
    let event = block_on_timeout(wait_service.event(token), Duration::from_secs(5))
        .expect("wait service event must arrive before timeout")
        .expect("wait service event must succeed");

    // 7. Resume continuation and fold completion.
    let result = continuation
        .resume(event, &tracer.context)
        .expect("continuation resume");
    let fold_result = fold_continuation_completion(
        result.completion,
        &tracer.dispatcher,
        &tracer.context,
        &mut tracer.memory.linear,
    )
    .expect("fold continuation completion");
    assert_eq!(
        fold_result, None,
        "WaitOnHvpatchChild wake requires redispatch"
    );

    // 8. Re-dispatch wait4 and assert expected stop status.
    let (_, redispatch) = tracer.wait4(1, wstatus_addr, 0, 0);
    let redispatch_outcome = redispatch.expect("redispatch wait4");
    match redispatch_outcome {
        DispatchOutcome::Returned { value } => {
            assert_eq!(value, 1, "wait4 must return tracee pid 1");
            let status_bytes = tracer.memory.read(wstatus_addr, 4).expect("read wstatus");
            let status = i32::from_ne_bytes(status_bytes.try_into().unwrap());
            assert_eq!(status, ((LINUX_SIGSTOP as i32) << 8) | 0x7f);
        }
        other => panic!("expected Returned outcome on redispatch wait4, got: {other:?}"),
    }

    // 9. Detach.
    let detach_outcome = tracer.ptrace_detach(1).expect("ptrace detach");
    assert_eq!(detach_outcome, DispatchOutcome::Returned { value: 0 });
}

/// LTP ptrace11 shape with waitid: Tracer attaches to PID 1 (ancestor/root), waits before
/// stop settlement, and builds a wait continuation for the non-child tracee.
#[test]
fn ptrace_attach_and_wait_on_ancestor_root_continuation_waitid() {
    let asids = AsidAllocator::new();
    let mut root = TestProcess::boot_root(&asids, "root-pid1");
    let mut tracer = root.fork_child(&asids, "tracer-child");

    let scheduler = Arc::new(Scheduler::new(Arc::clone(root.context.kernel())));
    let wait_service = CarrierWaitService::try_new(scheduler).expect("carrier wait service");

    let siginfo_addr = tracer.memory.alloc_zeroed(128).expect("alloc siginfo");

    // 1. Tracer attaches to PID 1 (ancestor/root).
    let attach_outcome = tracer.ptrace_attach(1).expect("ptrace attach");
    assert_eq!(attach_outcome, DispatchOutcome::Returned { value: 0 });

    // 2. Deterministically hold tracee BEFORE stop settlement.
    // Tracer calls waitid(P_PID, 1, siginfo_addr, WSTOPPED | WEXITED, 0).
    let (request, wait_outcome) = tracer.waitid(
        LINUX_P_PID,
        1,
        siginfo_addr,
        LINUX_WSTOPPED | LINUX_WEXITED,
        0,
    );
    let outcome = wait_outcome.expect("waitid dispatch");
    assert!(
        matches!(
            outcome,
            DispatchOutcome::WaitOnHvpatchChild {
                target: Some(1),
                ..
            }
        ),
        "expected WaitOnHvpatchChild with target 1, got: {outcome:?}"
    );

    // 3. Build BlockedContinuation from outcome and capture.
    let capture = ContinuationCapture::new(
        &tracer.context,
        tracer.execution_generation,
        request,
        RestartClass::Never,
    )
    .expect("continuation capture");

    let mut continuation = BlockedContinuation::from_dispatch_outcome(outcome, capture)
        .expect("continuation build for non-child tracee (ancestor/root) must succeed");

    continuation.install_temporary_signal_mask(&tracer.context);
    continuation.bind_product_futex(&tracer.futex);

    // 4. Enroll in wait service.
    let mut registration = wait_service.prepare_registration(&continuation);
    wait_service
        .enroll(&mut registration)
        .expect("enroll wait registration");
    let token = registration.wake_token();
    continuation
        .attach_registration(registration)
        .expect("attach registration");

    // 5. Root settles ptrace stop.
    let stopped = root.process.stop_for_ptrace_signal(LINUX_SIGSTOP as i32);
    assert!(stopped, "root stop_for_ptrace_signal must succeed");

    // 6. Wait service receives event.
    let event = block_on_timeout(wait_service.event(token), Duration::from_secs(5))
        .expect("wait service event must arrive before timeout")
        .expect("wait service event must succeed");

    // 7. Resume continuation and fold completion.
    let result = continuation
        .resume(event, &tracer.context)
        .expect("continuation resume");
    let fold_result = fold_continuation_completion(
        result.completion,
        &tracer.dispatcher,
        &tracer.context,
        &mut tracer.memory.linear,
    )
    .expect("fold continuation completion");
    assert_eq!(
        fold_result, None,
        "WaitOnHvpatchChild wake requires redispatch"
    );

    // 8. Re-dispatch waitid and assert expected stop status in siginfo.
    let (_, redispatch) = tracer.waitid(
        LINUX_P_PID,
        1,
        siginfo_addr,
        LINUX_WSTOPPED | LINUX_WEXITED,
        0,
    );
    let redispatch_outcome = redispatch.expect("redispatch waitid");
    assert_eq!(redispatch_outcome, DispatchOutcome::Returned { value: 0 });

    let siginfo_bytes = tracer.memory.read(siginfo_addr, 128).expect("read siginfo");
    let si_signo = i32::from_ne_bytes(siginfo_bytes[0..4].try_into().unwrap());
    let si_code = i32::from_ne_bytes(siginfo_bytes[8..12].try_into().unwrap());
    let si_pid = i32::from_ne_bytes(siginfo_bytes[16..20].try_into().unwrap());
    let si_status = i32::from_ne_bytes(siginfo_bytes[24..28].try_into().unwrap());

    assert_eq!(si_signo, LINUX_SIGCHLD as i32);
    assert_eq!(si_code, LINUX_CLD_STOPPED);
    assert_eq!(si_pid, 1);
    assert_eq!(si_status, LINUX_SIGSTOP as i32);

    // 9. Detach.
    let detach_outcome = tracer.ptrace_detach(1).expect("ptrace detach");
    assert_eq!(detach_outcome, DispatchOutcome::Returned { value: 0 });
}

/// Non-child sibling tracee: Sibling A (PID 2) attaches to Sibling B (PID 3), waits via wait4
/// before stop settlement, and builds a wait continuation for the non-child tracee.
#[test]
fn ptrace_attach_and_wait_on_non_child_sibling_continuation_wait4() {
    let asids = AsidAllocator::new();
    let mut root = TestProcess::boot_root(&asids, "root-pid1");
    let mut tracer = root.fork_child(&asids, "sibling-tracer");
    let tracee = root.fork_child(&asids, "sibling-tracee");

    let scheduler = Arc::new(Scheduler::new(Arc::clone(root.context.kernel())));
    let wait_service = CarrierWaitService::try_new(scheduler).expect("carrier wait service");

    let wstatus_addr = tracer.memory.alloc_zeroed(4).expect("alloc wstatus");
    let tracee_pid = tracee.process.pid();

    // 1. Tracer attaches to non-child sibling (PID 3).
    let attach_outcome = tracer.ptrace_attach(tracee_pid).expect("ptrace attach");
    assert_eq!(attach_outcome, DispatchOutcome::Returned { value: 0 });

    // 2. Deterministically hold tracee BEFORE stop settlement.
    // Tracer calls wait4(tracee_pid, wstatus_addr, 0, 0).
    let (request, wait_outcome) = tracer.wait4(tracee_pid, wstatus_addr, 0, 0);
    let outcome = wait_outcome.expect("wait4 dispatch");
    assert!(
        matches!(
            outcome,
            DispatchOutcome::WaitOnHvpatchChild {
                target: Some(target),
                ..
            } if target == tracee_pid
        ),
        "expected WaitOnHvpatchChild with target {tracee_pid}, got: {outcome:?}"
    );

    // 3. Build BlockedContinuation from outcome and capture.
    let capture = ContinuationCapture::new(
        &tracer.context,
        tracer.execution_generation,
        request,
        RestartClass::Never,
    )
    .expect("continuation capture");

    let mut continuation = BlockedContinuation::from_dispatch_outcome(outcome, capture)
        .expect("continuation build for non-child sibling tracee must succeed");

    continuation.install_temporary_signal_mask(&tracer.context);
    continuation.bind_product_futex(&tracer.futex);

    // 4. Enroll in wait service.
    let mut registration = wait_service.prepare_registration(&continuation);
    wait_service
        .enroll(&mut registration)
        .expect("enroll wait registration");
    let token = registration.wake_token();
    continuation
        .attach_registration(registration)
        .expect("attach registration");

    // 5. Tracee settles ptrace stop.
    let stopped = tracee.process.stop_for_ptrace_signal(LINUX_SIGSTOP as i32);
    assert!(stopped, "tracee stop_for_ptrace_signal must succeed");

    // 6. Wait service receives event.
    let event = block_on_timeout(wait_service.event(token), Duration::from_secs(5))
        .expect("wait service event must arrive before timeout")
        .expect("wait service event must succeed");

    // 7. Resume continuation and fold completion.
    let result = continuation
        .resume(event, &tracer.context)
        .expect("continuation resume");
    let fold_result = fold_continuation_completion(
        result.completion,
        &tracer.dispatcher,
        &tracer.context,
        &mut tracer.memory.linear,
    )
    .expect("fold continuation completion");
    assert_eq!(
        fold_result, None,
        "WaitOnHvpatchChild wake requires redispatch"
    );

    // 8. Re-dispatch wait4 and assert expected stop status.
    let (_, redispatch) = tracer.wait4(tracee_pid, wstatus_addr, 0, 0);
    let redispatch_outcome = redispatch.expect("redispatch wait4");
    match redispatch_outcome {
        DispatchOutcome::Returned { value } => {
            assert_eq!(
                value, tracee_pid as i64,
                "wait4 must return tracee pid {tracee_pid}"
            );
            let status_bytes = tracer.memory.read(wstatus_addr, 4).expect("read wstatus");
            let status = i32::from_ne_bytes(status_bytes.try_into().unwrap());
            assert_eq!(status, ((LINUX_SIGSTOP as i32) << 8) | 0x7f);
        }
        other => panic!("expected Returned outcome on redispatch wait4, got: {other:?}"),
    }

    // 9. Detach.
    let detach_outcome = tracer.ptrace_detach(tracee_pid).expect("ptrace detach");
    assert_eq!(detach_outcome, DispatchOutcome::Returned { value: 0 });
}

/// Non-child sibling tracee with waitid: Sibling A (PID 2) attaches to Sibling B (PID 3),
/// waits via waitid before stop settlement, and builds a wait continuation for the non-child tracee.
#[test]
fn ptrace_attach_and_wait_on_non_child_sibling_continuation_waitid() {
    let asids = AsidAllocator::new();
    let mut root = TestProcess::boot_root(&asids, "root-pid1");
    let mut tracer = root.fork_child(&asids, "sibling-tracer");
    let tracee = root.fork_child(&asids, "sibling-tracee");

    let scheduler = Arc::new(Scheduler::new(Arc::clone(root.context.kernel())));
    let wait_service = CarrierWaitService::try_new(scheduler).expect("carrier wait service");

    let siginfo_addr = tracer.memory.alloc_zeroed(128).expect("alloc siginfo");
    let tracee_pid = tracee.process.pid();

    // 1. Tracer attaches to non-child sibling (PID 3).
    let attach_outcome = tracer.ptrace_attach(tracee_pid).expect("ptrace attach");
    assert_eq!(attach_outcome, DispatchOutcome::Returned { value: 0 });

    // 2. Deterministically hold tracee BEFORE stop settlement.
    // Tracer calls waitid(P_PID, tracee_pid, siginfo_addr, WSTOPPED | WEXITED, 0).
    let (request, wait_outcome) = tracer.waitid(
        LINUX_P_PID,
        tracee_pid,
        siginfo_addr,
        LINUX_WSTOPPED | LINUX_WEXITED,
        0,
    );
    let outcome = wait_outcome.expect("waitid dispatch");
    assert!(
        matches!(
            outcome,
            DispatchOutcome::WaitOnHvpatchChild {
                target: Some(target),
                ..
            } if target == tracee_pid
        ),
        "expected WaitOnHvpatchChild with target {tracee_pid}, got: {outcome:?}"
    );

    // 3. Build BlockedContinuation from outcome and capture.
    let capture = ContinuationCapture::new(
        &tracer.context,
        tracer.execution_generation,
        request,
        RestartClass::Never,
    )
    .expect("continuation capture");

    let mut continuation = BlockedContinuation::from_dispatch_outcome(outcome, capture)
        .expect("continuation build for non-child sibling tracee must succeed");

    continuation.install_temporary_signal_mask(&tracer.context);
    continuation.bind_product_futex(&tracer.futex);

    // 4. Enroll in wait service.
    let mut registration = wait_service.prepare_registration(&continuation);
    wait_service
        .enroll(&mut registration)
        .expect("enroll wait registration");
    let token = registration.wake_token();
    continuation
        .attach_registration(registration)
        .expect("attach registration");

    // 5. Tracee settles ptrace stop.
    let stopped = tracee.process.stop_for_ptrace_signal(LINUX_SIGSTOP as i32);
    assert!(stopped, "tracee stop_for_ptrace_signal must succeed");

    // 6. Wait service receives event.
    let event = block_on_timeout(wait_service.event(token), Duration::from_secs(5))
        .expect("wait service event must arrive before timeout")
        .expect("wait service event must succeed");

    // 7. Resume continuation and fold completion.
    let result = continuation
        .resume(event, &tracer.context)
        .expect("continuation resume");
    let fold_result = fold_continuation_completion(
        result.completion,
        &tracer.dispatcher,
        &tracer.context,
        &mut tracer.memory.linear,
    )
    .expect("fold continuation completion");
    assert_eq!(
        fold_result, None,
        "WaitOnHvpatchChild wake requires redispatch"
    );

    // 8. Re-dispatch waitid and assert expected stop status in siginfo.
    let (_, redispatch) = tracer.waitid(
        LINUX_P_PID,
        tracee_pid,
        siginfo_addr,
        LINUX_WSTOPPED | LINUX_WEXITED,
        0,
    );
    let redispatch_outcome = redispatch.expect("redispatch waitid");
    assert_eq!(redispatch_outcome, DispatchOutcome::Returned { value: 0 });

    let siginfo_bytes = tracer.memory.read(siginfo_addr, 128).expect("read siginfo");
    let si_signo = i32::from_ne_bytes(siginfo_bytes[0..4].try_into().unwrap());
    let si_code = i32::from_ne_bytes(siginfo_bytes[8..12].try_into().unwrap());
    let si_pid = i32::from_ne_bytes(siginfo_bytes[16..20].try_into().unwrap());
    let si_status = i32::from_ne_bytes(siginfo_bytes[24..28].try_into().unwrap());

    assert_eq!(si_signo, LINUX_SIGCHLD as i32);
    assert_eq!(si_code, LINUX_CLD_STOPPED);
    assert_eq!(si_pid, tracee_pid);
    assert_eq!(si_status, LINUX_SIGSTOP as i32);

    // 9. Detach.
    let detach_outcome = tracer.ptrace_detach(tracee_pid).expect("ptrace detach");
    assert_eq!(detach_outcome, DispatchOutcome::Returned { value: 0 });
}

/// Control test: An unrelated non-tracer process attempting to wait on a non-child
/// receives ECHILD immediately without entering a blocking wait continuation.
#[test]
fn control_unrelated_non_tracer_sees_echild() {
    let asids = AsidAllocator::new();
    let mut root = TestProcess::boot_root(&asids, "root-pid1");
    let mut sibling_a = root.fork_child(&asids, "sibling-a");
    let sibling_b = root.fork_child(&asids, "sibling-b");

    let wstatus_addr = sibling_a.memory.alloc_zeroed(4).expect("alloc wstatus");
    let siginfo_addr = sibling_a.memory.alloc_zeroed(128).expect("alloc siginfo");
    let sibling_b_pid = sibling_b.process.pid();

    // Sibling A waiting on Sibling B without attaching -> ECHILD
    let (_, wait4_outcome) = sibling_a.wait4(sibling_b_pid, wstatus_addr, 0, 0);
    assert_eq!(
        wait4_outcome.expect("wait4 dispatch"),
        DispatchOutcome::Errno {
            errno: LINUX_ECHILD
        }
    );

    let (_, waitid_outcome) = sibling_a.waitid(
        LINUX_P_PID,
        sibling_b_pid,
        siginfo_addr,
        LINUX_WEXITED | LINUX_WSTOPPED,
        0,
    );
    assert_eq!(
        waitid_outcome.expect("waitid dispatch"),
        DispatchOutcome::Errno {
            errno: LINUX_ECHILD
        }
    );

    // Sibling A waiting on Root (PID 1) without attaching -> ECHILD
    let (_, wait4_root_outcome) = sibling_a.wait4(1, wstatus_addr, 0, 0);
    assert_eq!(
        wait4_root_outcome.expect("wait4 dispatch"),
        DispatchOutcome::Errno {
            errno: LINUX_ECHILD
        }
    );

    let (_, waitid_root_outcome) = sibling_a.waitid(
        LINUX_P_PID,
        1,
        siginfo_addr,
        LINUX_WEXITED | LINUX_WSTOPPED,
        0,
    );
    assert_eq!(
        waitid_root_outcome.expect("waitid dispatch"),
        DispatchOutcome::Errno {
            errno: LINUX_ECHILD
        }
    );
}

/// Control test: Parent waiting on its actual child builds a continuation successfully
/// (green control) and reaps the child when it exits.
#[test]
fn control_normal_child_wait_continuation_succeeds() {
    let asids = AsidAllocator::new();
    let mut root = TestProcess::boot_root(&asids, "root-pid1");
    let mut child = root.fork_child(&asids, "normal-child");

    let scheduler = Arc::new(Scheduler::new(Arc::clone(root.context.kernel())));
    let wait_service = CarrierWaitService::try_new(scheduler).expect("carrier wait service");

    let wstatus_addr = root.memory.alloc_zeroed(4).expect("alloc wstatus");
    let child_pid = child.process.pid();

    // 1. Root calls wait4(child_pid, wstatus_addr, 0, 0) before child exits.
    let (request, wait_outcome) = root.wait4(child_pid, wstatus_addr, 0, 0);
    let outcome = wait_outcome.expect("wait4 dispatch");
    assert!(
        matches!(
            outcome,
            DispatchOutcome::WaitOnHvpatchChild {
                target: Some(target),
                ..
            } if target == child_pid
        ),
        "expected WaitOnHvpatchChild with target {child_pid}, got: {outcome:?}"
    );

    // 2. Build BlockedContinuation: this must succeed because child is Root's own child.
    let capture = ContinuationCapture::new(
        &root.context,
        root.execution_generation,
        request,
        RestartClass::Never,
    )
    .expect("continuation capture");

    let mut continuation = BlockedContinuation::from_dispatch_outcome(outcome, capture)
        .expect("continuation build for normal child must succeed");

    continuation.install_temporary_signal_mask(&root.context);
    continuation.bind_product_futex(&root.futex);

    // 3. Enroll in wait service.
    let mut registration = wait_service.prepare_registration(&continuation);
    wait_service
        .enroll(&mut registration)
        .expect("enroll wait registration");
    let token = registration.wake_token();
    continuation
        .attach_registration(registration)
        .expect("attach registration");

    // 4. Child exits with status 42.
    child.exit(42);

    // 5. Wait service receives event.
    let event = block_on_timeout(wait_service.event(token), Duration::from_secs(5))
        .expect("wait service event must arrive before timeout")
        .expect("wait service event must succeed");

    // 6. Resume continuation and fold completion.
    let result = continuation
        .resume(event, &root.context)
        .expect("continuation resume");
    let fold_result = fold_continuation_completion(
        result.completion,
        &root.dispatcher,
        &root.context,
        &mut root.memory.linear,
    )
    .expect("fold continuation completion");
    assert_eq!(
        fold_result, None,
        "WaitOnHvpatchChild wake requires redispatch"
    );

    // 7. Re-dispatch wait4 and assert child reaped with status 42.
    let (_, redispatch) = root.wait4(child_pid, wstatus_addr, 0, 0);
    let redispatch_outcome = redispatch.expect("redispatch wait4");
    match redispatch_outcome {
        DispatchOutcome::Returned { value } => {
            assert_eq!(
                value, child_pid as i64,
                "wait4 must return child pid {child_pid}"
            );
            let status_bytes = root.memory.read(wstatus_addr, 4).expect("read wstatus");
            let status = i32::from_ne_bytes(status_bytes.try_into().unwrap());
            assert_eq!(status, 42 << 8);
        }
        other => panic!("expected Returned outcome on redispatch wait4, got: {other:?}"),
    }
}
