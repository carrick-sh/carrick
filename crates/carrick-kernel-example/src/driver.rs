//! # Continuation outcome driver
//!
//! Replaces the polling re-dispatch wait loop with kernel-owned continuations
//! parked on [`CarrierWaitService`].
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

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use carrick_hal::threaded::{Aarch64TaskCpuStateV1, GuestCpuState};
use carrick_kernel::compat::SyscallArgs;
use carrick_kernel::dispatch::{DispatchOutcome, SyscallRequest};
use carrick_kernel::kernel::continuation::{
    BlockedContinuation, CancellationCause, ContinuationCapture, ContinuationCompletion,
    ContinuationResult, RestartClass, is_blocking_dispatch_outcome,
};
use carrick_kernel::kernel::objects::{ExecutionGeneration, MigratableTaskState};
use carrick_kernel::kernel::{CarrierProcess, KernelContext};

use crate::operand::Syscall;
use crate::scripted::{ExampleError, InternalCompletion, Shared, Task, WAIT_BOUND};

/// Check whether a Linux syscall is restartable upon signal interruption or readiness wake.
pub(crate) fn is_restartable_syscall(nr: u64) -> bool {
    matches!(
        nr,
        63  // read
        | 64  // write
        | 65  // readv
        | 66  // writev
        | 67  // pread64
        | 68  // pwrite64
        | 69  // preadv
        | 70  // pwritev
        | 286 // preadv2
        | 287 // pwritev2
        | 29  // ioctl
        | 56  // openat
        | 32  // flock
        | 25  // fcntl
        | 182 // mq_timedsend
        | 183 // mq_timedreceive
    )
}

/// Seed the initial `MigratableTaskState` onto a new task's leader thread so continuation captures can authenticate authority.
pub(crate) fn seed_initial_task_state(
    context: &KernelContext,
) -> Result<ExecutionGeneration, ExampleError> {
    let mm = context.shared().mm().id();
    let asid_generation = mm.raw();
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

/// Drive a syscall to completion by dispatching and parking blocked outcomes on the shared wait service.
pub(crate) fn drive(
    task: &mut Task,
    syscall: &Syscall,
    args: [u64; 6],
    shared: &Arc<Shared>,
) -> Result<InternalCompletion, ExampleError> {
    loop {
        let context = task.dispatcher.capture_one_task_context()?;
        shared.dispatches.fetch_add(1, Ordering::SeqCst);
        shared
            .ledger
            .lock()
            .dispatch_events
            .push((task.process.pid(), syscall.label));

        let request = SyscallRequest::new(syscall.nr.raw(), SyscallArgs::from(args));
        let outcome =
            task.dispatcher
                .dispatch(&context, request, &mut task.memory.linear, &task.reporter)?;

        match outcome {
            DispatchOutcome::Returned { value } => return Ok(InternalCompletion::Returned(value)),
            DispatchOutcome::Errno { errno } => return Ok(InternalCompletion::Errno(errno)),
            DispatchOutcome::Exit { code } => return Ok(InternalCompletion::Exit(code)),
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
            DispatchOutcome::SchedulerYield => {
                std::thread::yield_now();
                return Ok(InternalCompletion::Returned(0));
            }
            outcome if is_blocking_dispatch_outcome(&outcome) => {
                let restart = if is_restartable_syscall(syscall.nr.raw()) {
                    RestartClass::RestartSyscall
                } else {
                    RestartClass::Never
                };
                let capture =
                    ContinuationCapture::new(&context, task.execution_generation, request, restart)
                        .map_err(|e| {
                            ExampleError::Unsupported(format!("continuation capture failed: {e}"))
                        })?;

                let mut continuation = BlockedContinuation::from_dispatch_outcome(outcome, capture)
                    .map_err(|e| {
                        ExampleError::Unsupported(format!("continuation build failed: {e}"))
                    })?;
                continuation.install_temporary_signal_mask(&context);

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

                // Notify listeners that this task is now parked/enrolled.
                shared.notify_parked(task.process.pid(), syscall.label);

                let event_result = block_on_timeout(shared.wait_service.event(token), WAIT_BOUND);
                let Some(event_result) = event_result else {
                    let _ = continuation.cancel(CancellationCause::ServiceShutdown);
                    return Err(ExampleError::WaitTimedOut(syscall.label));
                };

                let event = event_result.map_err(|e| {
                    ExampleError::Unsupported(format!("wait service event error: {e}"))
                })?;

                let fresh_context = task.dispatcher.capture_one_task_context()?;
                let result: ContinuationResult =
                    continuation.resume(event, &fresh_context).map_err(|e| {
                        ExampleError::Unsupported(format!("continuation resume failed: {e:?}"))
                    })?;

                match result.completion {
                    ContinuationCompletion::Return(val) => {
                        return Ok(InternalCompletion::Returned(val));
                    }
                    ContinuationCompletion::Errno(errno) => {
                        return Ok(InternalCompletion::Errno(errno));
                    }
                    ContinuationCompletion::ReturnWithGuestWrites(val, _writes) => {
                        return Ok(InternalCompletion::Returned(val));
                    }
                    ContinuationCompletion::ErrnoWithGuestWrites(errno, _writes) => {
                        return Ok(InternalCompletion::Errno(errno));
                    }
                    ContinuationCompletion::Redispatch => continue,
                    ContinuationCompletion::RedispatchWithPartial(_offset) => continue,
                    ContinuationCompletion::BlockingWrite { outcome, .. } => match outcome {
                        carrick_kernel::kernel::continuation::BlockingWriteOutcome::Return(val) => {
                            return Ok(InternalCompletion::Returned(val));
                        }
                        carrick_kernel::kernel::continuation::BlockingWriteOutcome::Errno(
                            errno,
                        ) => {
                            return Ok(InternalCompletion::Errno(errno));
                        }
                    },
                    ContinuationCompletion::TimerFdRead(_)
                    | ContinuationCompletion::Semop(_)
                    | ContinuationCompletion::Mqueue(_)
                    | ContinuationCompletion::FdWait { .. } => continue,
                    ContinuationCompletion::InterruptedSleep { .. } => {
                        return Ok(InternalCompletion::Errno(carrick_abi::LINUX_EINTR));
                    }
                }
            }
            other => return Err(ExampleError::Unsupported(format!("{other:?}"))),
        }
    }
}
