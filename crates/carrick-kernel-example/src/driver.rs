//! # Continuation outcome driver
//!
//! Replaces the polling re-dispatch wait loop with kernel-owned continuations
//! parked on [`CarrierWaitService`](carrick_kernel::kernel::continuation::CarrierWaitService).
//!
//! | DispatchOutcome Variant | Kernel Continuation Mapping | Wait Service Probe | Restart Policy |
//! |---|---|---|---|
//! | `WaitOnFds` | `BlockedContinuation::from_dispatch_outcome` | `ReadinessProbe::Fds` (polled host fds + wait queues) | `RestartClass::RestartSyscall` (for restartable nr) / `Never` |
//! | `WaitOnHvpatchChild` | `BlockedContinuation::from_dispatch_outcome` | `ReadinessProbe::TaskWake` (child exit edge) | `RestartClass::Never` |
//! | `WaitOnSignals` | `BlockedContinuation::from_dispatch_outcome` | `SignalReadinessProbe` (pending signal deliverable) | `RestartClass::Never` |
//! | `WaitOnSleep` | `BlockedContinuation::from_dispatch_outcome` | `ReadinessProbe::Timer` (reactor deadline) | `RestartClass::Never` |
//! | `FutexWait` / `FutexWaitv` | `BlockedContinuation::from_dispatch_outcome` | `ReadinessProbe::Futex` (futex table subscription) | `RestartClass::Never` |
//! | `SharedFutexWait` / `SharedFutexWaitv` | `BlockedContinuation::from_dispatch_outcome` | `ReadinessProbe::SharedFutex` | `RestartClass::Never` |
//! | `WaitOnSharedWord` | `BlockedContinuation::from_dispatch_outcome` | `ReadinessProbe::SharedWord` | `RestartClass::Never` |
//! | `BlockingWrite` | `BlockedContinuation::from_dispatch_outcome` | `ReadinessProbe::BlockingWrite` (polled host fd write readiness) | `RestartClass::RestartSyscall` with partial progress |
//! | `BlockingTimerFdRead` | `BlockedContinuation::from_dispatch_outcome` | `ReadinessProbe::TimerFdRead` | `RestartClass::Never` |
//! | `BlockingSemop` | `BlockedContinuation::from_dispatch_outcome` | `ReadinessProbe::Semop` | `RestartClass::Never` |
//! | `BlockingMqueue` | `BlockedContinuation::from_dispatch_outcome` | `ReadinessProbe::Mqueue` | `RestartClass::Never` |
//! | `BlockingFdWait` | `BlockedContinuation::from_dispatch_outcome` | `ReadinessProbe::FdWait` | `RestartClass::Never` |
//! | `BlockingRecordLock` | `BlockedContinuation::from_dispatch_outcome` | `ReadinessProbe::RecordLock` (retry tick) | `RestartClass::Never` |
//!
//! ## Adapter Lifetime & Continuation Ownership
//!
//! In this VM-less backend, continuations are built from the kernel's `BlockedContinuation`
//! and parked on the shared [`CarrierWaitService`]. The continuation remains owned by
//! the backend host thread driving this task.
//!
//! When a sibling thread issues `exit_group` or process terminal exit occurs:
//! - Terminal exit publication is serialized under the per-process `dispatcher` lock.
//! - After releasing the dispatcher lock, [`Shared::wake_active_tokens_for_task`] calls
//!   `wait_service.publish_ready(token)` as a **transport-level wakeup notification**
//!   to prompt the waiting host thread loop to wake.
//! - Upon waking (or immediately if terminal exit occurs before parking), the thread
//!   observes that its exact thread/process is no longer live, cancels its own backend-owned
//!   continuation with [`CancellationCause::ProcessExit`], and unwinds cleanly.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use carrick_hal::threaded::{Aarch64TaskCpuStateV1, GuestCpuState};
use carrick_kernel::compat::SyscallArgs;
use carrick_kernel::dispatch::{DispatchOutcome, SyscallRequest, ThreadCtx};
use carrick_kernel::kernel::continuation::{
    BlockedContinuation, CancellationCause, ContinuationCapture, ContinuationResult, RestartClass,
    WaitServiceError, fold_continuation_completion, is_blocking_dispatch_outcome,
    is_restartable_syscall,
};
use carrick_kernel::kernel::objects::{ExecutionGeneration, MigratableTaskState};
use carrick_kernel::kernel::{CarrierProcess, KernelContext};

use crate::operand::Syscall;
use crate::scripted::{ExampleError, InternalCompletion, Shared, Task, WAIT_BOUND};

/// Seed the initial `MigratableTaskState` onto a new task's leader thread so continuation captures can authenticate authority.
pub(crate) fn seed_initial_task_state(
    context: &KernelContext,
    asid_generation: u64,
) -> Result<ExecutionGeneration, ExampleError> {
    let mm = context.shared().mm().id();
    let state = MigratableTaskState {
        cpu: GuestCpuState::from_aarch64_v1(Aarch64TaskCpuStateV1 {
            gprs: [0; 31],
            pc: 0x1000,
            pstate: 0,
            trap_pc: 0,
            trap_pstate: 0,
            sp_el0: 0,
            elr_el1: 0,
            spsr_el1: 0,
            ttbr0: 0,
            ttbr1: 0,
            tcr: 0,
            sctlr_el1: 0,
            mair_el1: 0,
            vbar_el1: 0,
            cpacr_el1: 0,
            cntkctl_el1: 0,
            tpidr_el1: 0,
            actlr_el1: 0,
            tpidr_el0: 0,
            tpidrro_el0: 0,
            contextidr_el1: 0,
            vregs: [0; 32],
            fpsr: 0,
            fpcr: 0,
            pending_resume_pc: None,
            last_syscall_nr: None,
            last_syscall_orig_x0: 0,
            last_fault_esr: 0,
            last_exit_class: 0,
            is_forked_child: false,
            syscall_continuation: None,
            mm_generation: mm.raw(),
            asid_generation,
        }),
        mm,
        asid_generation,
    };
    context
        .thread()
        .publish_initial_task_state(state)
        .map_err(|e| ExampleError::Unsupported(format!("publish initial task state failed: {e}")))
}

struct ThreadWaker(std::thread::Thread);

impl std::task::Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

/// Drive a future synchronously on the current host thread with a timeout bound.
pub(crate) fn block_on_timeout<F: std::future::Future>(
    future: F,
    timeout: Duration,
) -> Option<F::Output> {
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

fn check_deliverable_signals(
    dispatcher: &carrick_kernel::dispatch::SyscallDispatcher,
    context: &KernelContext,
    tid: carrick_kernel::thread::ThreadId,
) -> Result<Option<InternalCompletion>, ExampleError> {
    while let Some(pending) = dispatcher.take_deliverable_pending_from(context, tid) {
        let action = dispatcher.signal_action(context, pending.signum);
        match carrick_kernel::kernel::evaluate_signal_delivery_action(pending.signum, action) {
            carrick_kernel::kernel::SignalDeliveryAction::Ignore => {}
            carrick_kernel::kernel::SignalDeliveryAction::Terminate => {
                return Ok(Some(InternalCompletion::Death(pending.signum)));
            }
            carrick_kernel::kernel::SignalDeliveryAction::Stop => {
                return Err(ExampleError::Unsupported(format!(
                    "job control stop signal {} not supported in scripted backend",
                    pending.signum
                )));
            }
            carrick_kernel::kernel::SignalDeliveryAction::Handler { address } => {
                return Err(ExampleError::Unsupported(format!(
                    "guest signal handler at {address:#x} not supported in scripted backend"
                )));
            }
        }
    }
    Ok(None)
}

/// Drive a syscall to completion by dispatching and parking blocked outcomes on the shared wait service.
pub(crate) fn drive(
    task: &mut Task,
    syscall: &Syscall,
    args: [u64; 6],
    shared: &Arc<Shared>,
) -> Result<InternalCompletion, ExampleError> {
    let deadline = Instant::now() + WAIT_BOUND;
    loop {
        let is_live = task.context.exact_thread_is_live()
            && task
                .process
                .kernel_graph()
                .task_is_live(task.process.task_id());
        if !is_live {
            return Ok(InternalCompletion::Cancelled(
                CancellationCause::ProcessExit,
            ));
        }
        let tid = task.context.thread().registry_id();

        let (mut outcome, request) = {
            let disp = task.dispatcher.lock();
            if !task.context.exact_thread_is_live()
                || !task
                    .process
                    .kernel_graph()
                    .task_is_live(task.process.task_id())
            {
                return Ok(InternalCompletion::Cancelled(
                    CancellationCause::ProcessExit,
                ));
            }

            // Deliverable signals check at syscall entry.
            if let Some(death) = check_deliverable_signals(&disp, &task.context, tid)? {
                return Ok(death);
            }

            shared.dispatches.fetch_add(1, Ordering::SeqCst);
            shared.ledger.lock().dispatch_events.push((
                task.process.pid(),
                task.tid,
                syscall.label,
            ));

            let request = SyscallRequest::new(syscall.nr.raw(), SyscallArgs::from(args));
            let thread_ctx = ThreadCtx::new(tid, &task.thread_registry, &task.futex_table);

            let mut mem = task.memory.lock();
            let mut executor = disp
                .enter_mm_executor()
                .map_err(carrick_kernel::dispatch::DispatchError::MmExecutorAdmission)?;
            let outcome = disp.dispatch_threaded_with_mm_executor(
                &mut executor,
                &task.context,
                request,
                &mut mem.linear,
                &task.reporter,
                thread_ctx,
            )?;
            (outcome, request)
        };

        loop {
            match outcome {
                DispatchOutcome::Returned { value } => {
                    let is_live = task.context.exact_thread_is_live()
                        && task
                            .process
                            .kernel_graph()
                            .task_is_live(task.process.task_id());
                    if !is_live {
                        return Ok(InternalCompletion::Cancelled(
                            CancellationCause::ProcessExit,
                        ));
                    }
                    let disp = task.dispatcher.lock();
                    if let Some(death) = check_deliverable_signals(&disp, &task.context, tid)? {
                        return Ok(death);
                    }
                    return Ok(InternalCompletion::Returned(value));
                }
                DispatchOutcome::Errno { errno } => {
                    let is_live = task.context.exact_thread_is_live()
                        && task
                            .process
                            .kernel_graph()
                            .task_is_live(task.process.task_id());
                    if !is_live {
                        return Ok(InternalCompletion::Cancelled(
                            CancellationCause::ProcessExit,
                        ));
                    }
                    let disp = task.dispatcher.lock();
                    if let Some(death) = check_deliverable_signals(&disp, &task.context, tid)? {
                        return Ok(death);
                    }
                    return Ok(InternalCompletion::Errno(errno));
                }
                DispatchOutcome::Exit { code } => return Ok(InternalCompletion::Exit(code)),
                DispatchOutcome::ThreadExit { code } => {
                    return Ok(InternalCompletion::ThreadExit(code));
                }
                DispatchOutcome::SignalDeath { signum } => {
                    return Ok(InternalCompletion::Death(signum));
                }
                DispatchOutcome::Fork {
                    flags,
                    pidfd_out,
                    clone_parent,
                    parent_tid_addr,
                    child_tid_addr,
                    exit_signal,
                    child_stack,
                    vfork,
                } => {
                    let plain = pidfd_out.is_none()
                        && !clone_parent
                        && parent_tid_addr.is_none()
                        && child_tid_addr.is_none()
                        && child_stack == 0
                        && vfork.is_none();
                    if !plain {
                        return Err(ExampleError::Unsupported(format!(
                            "clone flags {flags:#x}: only a plain fork (no CLONE_PIDFD, \
                             CLONE_PARENT, tid stores, child stack or vfork) runs here"
                        )));
                    }
                    return Ok(InternalCompletion::Fork { flags, exit_signal });
                }
                DispatchOutcome::CloneThread {
                    flags,
                    clear_child_tid_addr,
                    parent_tid_addr,
                    child_tid_addr,
                    tls,
                    ..
                } => {
                    if parent_tid_addr != 0 || child_tid_addr != 0 || tls.is_some() {
                        return Err(ExampleError::Unsupported(
                            "clone_thread does not support parent_tid_addr, child_tid_addr, or tls in scripted backend".to_owned(),
                        ));
                    }
                    return Ok(InternalCompletion::CloneThread {
                        flags,
                        clear_child_tid_addr,
                    });
                }
                DispatchOutcome::SignalThread {
                    tid: target,
                    kernel_target,
                    ..
                } => {
                    let exact = kernel_target.ok_or_else(|| {
                        ExampleError::Unsupported(
                            "legacy host thread signal routing is not a scripted kernel operation"
                                .to_owned(),
                        )
                    })?;
                    if exact.tid.raw() != target.raw() {
                        return Err(ExampleError::Script(
                            "thread signal target identity mismatch".to_owned(),
                        ));
                    }
                    // Dispatch already authorized and posted this exact-thread signal.
                    shared.wait_service.publish_signal_for_thread(exact);
                    outcome = DispatchOutcome::Returned { value: 0 };
                }
                DispatchOutcome::SchedulerYield => {
                    std::thread::yield_now();
                    return Ok(InternalCompletion::Returned(0));
                }
                blocking_outcome if is_blocking_dispatch_outcome(&blocking_outcome) => {
                    let restart = if is_restartable_syscall(syscall.nr.raw()) {
                        RestartClass::RestartSyscall
                    } else {
                        RestartClass::Never
                    };
                    let capture = ContinuationCapture::new(
                        &task.context,
                        task.execution_generation,
                        request,
                        restart,
                    )
                    .map_err(|e| {
                        ExampleError::Unsupported(format!("continuation capture failed: {e}"))
                    })?;

                    let mut continuation =
                        BlockedContinuation::from_dispatch_outcome(blocking_outcome, capture)
                            .map_err(|e| {
                                ExampleError::Unsupported(format!("continuation build failed: {e}"))
                            })?;
                    continuation.install_temporary_signal_mask(&task.context);
                    continuation.bind_product_futex(&task.futex_table);

                    let mut registration = shared.wait_service.prepare_registration(&continuation);
                    shared.wait_service.enroll(&mut registration).map_err(|e| {
                        ExampleError::Unsupported(format!("wait service enroll failed: {e}"))
                    })?;
                    let token = registration.wake_token();
                    continuation
                        .attach_registration(registration)
                        .map_err(|e| {
                            ExampleError::Unsupported(format!("attach registration failed: {e}"))
                        })?;

                    // Serialize active token registration and exact liveness re-check under
                    // the per-process dispatcher mutex. If process terminal exit retired the
                    // task before registration, we detect it immediately, cancel the
                    // continuation, and return without parking for WAIT_BOUND.
                    {
                        let disp = task.dispatcher.lock();
                        let is_live = task.context.exact_thread_is_live()
                            && task
                                .process
                                .kernel_graph()
                                .task_is_live(task.process.task_id());
                        if !is_live {
                            drop(disp);
                            let _ = continuation.cancel(CancellationCause::ProcessExit);
                            return Ok(InternalCompletion::Cancelled(
                                CancellationCause::ProcessExit,
                            ));
                        }
                        shared.register_active_token(task.context.task().key(), token);
                    }
                    // Notify listeners that this task thread is now parked/enrolled.
                    shared.notify_parked(task.tid, syscall.label);

                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        shared.unregister_active_token(token);
                        let _ = continuation.cancel(CancellationCause::ServiceShutdown);
                        return Err(ExampleError::WaitTimedOut(syscall.label));
                    }

                    // Drive wait service event on host thread. Note: `shared.wake_active_tokens_for_task`
                    // calling `publish_ready` for a retired task is transport notification only:
                    // it prompts this host thread loop to wake and observe exact liveness/retirement.
                    let event_result =
                        block_on_timeout(shared.wait_service.event(token), remaining);
                    shared.unregister_active_token(token);
                    let Some(event_result) = event_result else {
                        let _ = continuation.cancel(CancellationCause::ServiceShutdown);
                        return Err(ExampleError::WaitTimedOut(syscall.label));
                    };

                    let event = match event_result {
                        Ok(event) => event,
                        Err(WaitServiceError::Cancelled(cause)) => {
                            return Ok(InternalCompletion::Cancelled(cause));
                        }
                        Err(e) => {
                            return Err(ExampleError::Unsupported(format!(
                                "wait service event error: {e}"
                            )));
                        }
                    };

                    let is_live = task.context.exact_thread_is_live()
                        && task
                            .process
                            .kernel_graph()
                            .task_is_live(task.process.task_id());
                    if !is_live {
                        let _ = continuation.cancel(CancellationCause::ProcessExit);
                        return Ok(InternalCompletion::Cancelled(
                            CancellationCause::ProcessExit,
                        ));
                    }

                    let mut result: ContinuationResult = match continuation
                        .resume(event, &task.context)
                    {
                        Ok(result) => result,
                        Err(
                            carrick_kernel::kernel::continuation::ContinuationResumeError::StaleThread(
                                _,
                            ),
                        ) => {
                            return Ok(InternalCompletion::Cancelled(
                                CancellationCause::ProcessExit,
                            ));
                        }
                        Err(e) => {
                            return Err(ExampleError::Unsupported(format!(
                                "continuation resume failed: {e:?}"
                            )));
                        }
                    };

                    if let Some(reserved) = result.take_reserved_signal() {
                        if !reserved.consume() {
                            return Err(ExampleError::Unsupported(
                                "reserved signal was already consumed".to_owned(),
                            ));
                        }
                        let action = reserved.action();
                        match carrick_kernel::kernel::evaluate_signal_delivery_action(
                            reserved.signum(),
                            action,
                        ) {
                            carrick_kernel::kernel::SignalDeliveryAction::Ignore => {
                                reserved.restore_persistent_after_default_action();
                            }
                            carrick_kernel::kernel::SignalDeliveryAction::Terminate => {
                                reserved.restore_persistent_after_default_action();
                                return Ok(InternalCompletion::Death(reserved.signum()));
                            }
                            carrick_kernel::kernel::SignalDeliveryAction::Stop => {
                                reserved.restore_persistent_after_default_action();
                                return Err(ExampleError::Unsupported(format!(
                                    "job control stop signal {} not supported in scripted backend",
                                    reserved.signum()
                                )));
                            }
                            carrick_kernel::kernel::SignalDeliveryAction::Handler { address } => {
                                return Err(ExampleError::Unsupported(format!(
                                    "guest signal handler at {address:#x} not supported in scripted backend"
                                )));
                            }
                        }
                    }

                    let fold_result = {
                        let disp = task.dispatcher.lock();
                        let mut mem = task.memory.lock();
                        fold_continuation_completion(
                            result.completion,
                            &disp,
                            &task.context,
                            &mut mem.linear,
                        )
                    };

                    match fold_result {
                        Ok(Some(next_outcome)) => {
                            outcome = next_outcome;
                            continue;
                        }
                        Ok(None) => break, // redispatch original syscall request
                        Err(err) => {
                            return Err(ExampleError::Unsupported(format!(
                                "memory error folding continuation: {err:?}"
                            )));
                        }
                    }
                }
                other => return Err(ExampleError::Unsupported(format!("{other:?}"))),
            }
        }
    }
}
