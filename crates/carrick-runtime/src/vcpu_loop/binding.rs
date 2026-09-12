//! HVPatch kernel execution and task binding.

use std::sync::Arc;
use std::time::{Duration, Instant};

use carrick_fatal::carrick_fatal;
use parking_lot::Mutex;

use carrick_hal::{PlatformFutex, ThreadedEngine, VcpuRegistry};

use crate::dispatch::DispatchOutcome;
use crate::run_result::RuntimeError;
use crate::thread::{FutexTable, ThreadId, ThreadRegistry};
use crate::trap::TrapError;

use super::exec::*;
use super::lifecycle::*;
use super::outcome::*;
use super::terminal::*;
use super::threads::*;
use super::wait_wake::*;
use super::*;

/// Exact execution authority is task-local in the compatibility loop and is
/// lent by the Task 4 worker in the persistent loop. Both modes expose the
/// same narrow slot API so exec/continuation helpers cannot accidentally grow
/// a second scheduler-specific implementation.
pub(crate) enum ExecutionLeaseCell {
    Owned(Mutex<Option<crate::kernel::objects::ThreadExecutionLease>>),
    Injected(Arc<InjectedExecutionLeaseSlot>),
}

pub(crate) struct InjectedExecutionLeaseSlot {
    slot: std::sync::atomic::AtomicPtr<Option<crate::kernel::objects::ThreadExecutionLease>>,
}

impl InjectedExecutionLeaseSlot {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            slot: std::sync::atomic::AtomicPtr::new(std::ptr::null_mut()),
        })
    }

    pub(crate) fn install(
        self: &Arc<Self>,
        slot: *mut Option<crate::kernel::objects::ThreadExecutionLease>,
    ) -> InjectedExecutionLeasePublication<'_> {
        if self
            .slot
            .compare_exchange(
                std::ptr::null_mut(),
                slot,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_err()
        {
            carrick_fatal!(
                "vcpu_loop::runtime_context",
                "Duplicate installation of thread-local VcpuRuntimeContext"
            );
        }
        InjectedExecutionLeasePublication { owner: self }
    }
}

pub(crate) struct InjectedExecutionLeasePublication<'a> {
    owner: &'a Arc<InjectedExecutionLeaseSlot>,
}

impl Drop for InjectedExecutionLeasePublication<'_> {
    fn drop(&mut self) {
        let previous = self
            .owner
            .slot
            .swap(std::ptr::null_mut(), std::sync::atomic::Ordering::AcqRel);
        if previous.is_null() {
            carrick_fatal!(
                "vcpu_loop::runtime_context",
                "Thread-local VcpuRuntimeContext missing on teardown"
            );
        }
    }
}

pub(crate) enum ExecutionLeaseGuard<'a> {
    Owned(parking_lot::MutexGuard<'a, Option<crate::kernel::objects::ThreadExecutionLease>>),
    Injected(&'a mut Option<crate::kernel::objects::ThreadExecutionLease>),
}

impl std::ops::Deref for ExecutionLeaseGuard<'_> {
    type Target = Option<crate::kernel::objects::ThreadExecutionLease>;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(slot) => slot,
            Self::Injected(slot) => slot,
        }
    }
}

impl std::ops::DerefMut for ExecutionLeaseGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Owned(slot) => slot,
            Self::Injected(slot) => slot,
        }
    }
}

impl ExecutionLeaseCell {
    pub(crate) fn owned() -> Self {
        Self::Owned(Mutex::new(None))
    }

    pub(crate) fn injected() -> (Self, Arc<InjectedExecutionLeaseSlot>) {
        let slot = InjectedExecutionLeaseSlot::new();
        (Self::Injected(Arc::clone(&slot)), slot)
    }

    pub(crate) fn lock(&self) -> ExecutionLeaseGuard<'_> {
        match self {
            Self::Owned(slot) => ExecutionLeaseGuard::Owned(slot.lock()),
            Self::Injected(slot) => {
                let pointer = slot.slot.load(std::sync::atomic::Ordering::Acquire);
                if pointer.is_null() {
                    carrick_fatal!(
                        "vcpu_loop::runtime_context",
                        "Thread-local VcpuRuntimeContext missing when entering direct dispatch lock"
                    );
                }
                // SAFETY: the persistent worker installs the unique mutable
                // lease slot for the duration of this poll and clears it before
                // returning the physical engine. A logical job is polled by at
                // most one worker at a time under HvpatchTaskQuantum's mutex.
                ExecutionLeaseGuard::Injected(unsafe { &mut *pointer })
            }
        }
    }
}

pub(crate) enum HvpatchBlockInput {
    Dispatch(DispatchOutcome),
    Vfork {
        child: crate::kernel::TaskKey,
        wait: crate::kernel::VforkParentWait,
        activation: executor::PreparedVforkChildActivation,
    },
}

pub(crate) enum HvpatchContinuationInput {
    Dispatch(DispatchOutcome),
    Vfork {
        child: crate::kernel::TaskKey,
        wait: crate::kernel::VforkParentWait,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeferredResumeBlocked {
    frame: carrick_hal::RawSyscall,
    vfork_child_pid: Option<i32>,
    original_blocked_reason: Option<crate::kernel::objects::BlockedReason>,
}

impl DeferredResumeBlocked {
    pub(super) fn capture(
        phase: &HvpatchProductionPhase,
        original_blocked_reason: Option<crate::kernel::objects::BlockedReason>,
    ) -> Option<Self> {
        match phase {
            HvpatchProductionPhase::ResumeBlocked {
                frame,
                vfork_child_pid,
            } => Some(Self {
                frame: *frame,
                vfork_child_pid: *vfork_child_pid,
                original_blocked_reason,
            }),
            _ => None,
        }
    }

    pub(super) fn restore(self, phase: &mut HvpatchProductionPhase) {
        *phase = HvpatchProductionPhase::ResumeBlocked {
            frame: self.frame,
            vfork_child_pid: self.vfork_child_pid,
        };
    }
}

pub(super) enum HvpatchProductionPhase {
    Resident,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    BootstrapProcessChild(ProcessChildBootstrap),
    BootstrapThreadChild,
    ResumeForkQuiesce {
        _subscription: carrick_thread::fork_quiesce::QuiesceSubscription,
    },
    ResumeJobControlStop {
        _subscription: crate::kernel::objects::TaskWakeSubscription,
    },
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    RetryProcessFork {
        frame: Option<carrick_hal::RawSyscall>,
        request: quiesce::ForkRequest,
        coordinator: Option<quiesce::ProcessForkCoordinator>,
        external_exec: Option<crate::kernel::control::ExecWork>,
        deferred_resume_blocked: Option<DeferredResumeBlocked>,
        _subscription: quiesce::ProcessForkRetrySubscription,
    },
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    RetryCloneThread {
        frame: carrick_hal::RawSyscall,
        request: HvpatchCloneThreadRequest,
        prepared: Option<crate::kernel::PreparedThreadClone>,
        _subscription: CloneRetrySubscription,
    },
    /// A guest thread exit found the kernel task reservation held
    /// (`ProcessThreadExit::Busy`). The job parked with a
    /// reservation-change subscription (stored on the runtime state) and
    /// re-runs the exit with this code on resume. The executor stays free
    /// to service peer commands in between — blocking it in the exit wait
    /// deadlocked against an exec survivor's ASID-ack collection.
    RetryThreadExit {
        code: i32,
    },
    ResumeBlocked {
        frame: carrick_hal::RawSyscall,
        vfork_child_pid: Option<i32>,
    },
    ExecSiblingDrain {
        context: crate::kernel::KernelContext,
        owner: exec::PreparedExecveDrain,
    },
    TerminalProcessDrain {
        terminal: PersistentTerminal,
        context: crate::kernel::KernelContext,
        drain: continuation::ProcessDrain,
    },
    TerminalClaimRetry {
        terminal: PersistentTerminal,
        context: crate::kernel::KernelContext,
        _subscription: Option<CloneAdmissionChangeSubscription>,
    },
    TerminalRetireRetry {
        terminal: PersistentTerminal,
        context: crate::kernel::KernelContext,
        _subscription: TerminalRetireSubscription,
    },
    Complete,
}

/// What a parked process terminal waits on before retrying its retirement.
pub(crate) enum TerminalRetireSubscription {
    /// The carrier-wide topology lock (another fork/exec/exit mid-edit).
    Topology {
        _subscription: carrick_thread::fork_quiesce::TopologyReleaseSubscription,
    },
    /// A sibling's exec reservation owns this process's MM generation; the
    /// exit's owner-set edit is admitted once it settles.
    ExecSettlement {
        _subscription: crate::hvpatch::ExecSettlementSubscription,
    },
}

#[cfg(test)]
pub(crate) fn enter_guest_executor_then_register<F>(
    census: &Arc<crate::kernel::GuestExecutorCensus>,
    thread: Option<crate::kernel::ThreadRef>,
    register: F,
) -> Result<
    (
        crate::kernel::GuestExecutorParticipation,
        carrick_hal::VcpuRegistrationEnrollment,
    ),
    crate::kernel::GuestExecutorCensusError,
>
where
    F: FnOnce() -> carrick_hal::VcpuRegistrationEnrollment,
{
    let participation = census.enter(thread)?;
    let enrollment = register();
    Ok((participation, enrollment))
}

pub(crate) fn enter_mm_executor_then_register<F>(
    dispatcher: &crate::dispatch::SyscallDispatcher,
    thread: Option<crate::kernel::ThreadRef>,
    registry: Arc<dyn carrick_hal::VcpuRegistry>,
    tid: ThreadId,
    register: F,
) -> Result<
    (
        crate::dispatch::MmExecutorParticipation,
        carrick_hal::VcpuRegistrationEnrollment,
    ),
    crate::kernel::GuestExecutorCensusError,
>
where
    F: FnOnce() -> carrick_hal::VcpuRegistrationEnrollment,
{
    let participation = dispatcher.enter_mm_executor_for_thread(thread, registry, tid)?;
    let enrollment = register();
    Ok((participation, enrollment))
}

pub(super) fn registration_wake_uses_control(
    phase: &HvpatchProductionPhase,
    pending_control_quantum: bool,
) -> bool {
    if pending_control_quantum {
        return true;
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        matches!(
            phase,
            HvpatchProductionPhase::RetryProcessFork {
                external_exec: Some(_),
                ..
            }
        )
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        let _ = phase;
        false
    }
}

pub(crate) fn registration_wake_callback(
    scheduler: Arc<crate::kernel::Scheduler>,
    thread: crate::kernel::ThreadKey,
    use_control: bool,
) -> Arc<dyn Fn() + Send + Sync + 'static> {
    Arc::new(move || {
        let _ = if use_control {
            scheduler.wake_control(thread)
        } else {
            scheduler.wake(thread)
        };
    })
}

impl HvpatchProductionPhase {
    fn is_terminal_transition(&self) -> bool {
        matches!(
            self,
            Self::ExecSiblingDrain { .. }
                | Self::TerminalProcessDrain { .. }
                | Self::TerminalClaimRetry { .. }
                | Self::TerminalRetireRetry { .. }
        )
    }

    /// Stable ordinal for the `hvpatch-thread-terminal` probe's `detail`
    /// (reason `ExternallySettledWithoutResult`): which phase a job was
    /// parked in when the executor settled its terminal for it.
    const fn probe_ordinal(&self) -> i32 {
        match self {
            Self::Resident => 0,
            Self::BootstrapProcessChild { .. } => 1,
            Self::ResumeForkQuiesce { .. } => 2,
            Self::ResumeJobControlStop { .. } => 3,
            Self::RetryProcessFork { .. } => 4,
            Self::RetryCloneThread { .. } => 5,
            Self::RetryThreadExit { .. } => 6,
            Self::ResumeBlocked { .. } => 7,
            Self::ExecSiblingDrain { .. } => 8,
            Self::TerminalProcessDrain { .. } => 9,
            Self::TerminalClaimRetry { .. } => 10,
            Self::TerminalRetireRetry { .. } => 11,
            Self::Complete => 12,
            Self::BootstrapThreadChild => 13,
        }
    }
}

#[cfg(test)]
#[test]
pub(crate) fn bootstrap_thread_child_probe_ordinal_is_append_only() {
    assert_eq!(
        HvpatchProductionPhase::BootstrapThreadChild.probe_ordinal(),
        13
    );
}

pub(crate) enum PersistentTerminal {
    Outcome {
        outcome: VcpuLoopOutcome,
        prepared_core: Option<Box<PreparedCorePublication>>,
    },
    Error(RuntimeError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PersistentTerminalRuntimeState {
    Resident,
    Withdrawn,
}

impl PersistentTerminal {
    pub(crate) fn from_outcome(outcome: VcpuLoopOutcome) -> Self {
        Self::Outcome {
            outcome,
            prepared_core: None,
        }
    }

    fn into_result(self) -> Result<VcpuLoopOutcome, RuntimeError> {
        match self {
            Self::Outcome { outcome, .. } => Ok(outcome),
            Self::Error(error) => Err(error),
        }
    }
}

pub(crate) struct ProductionHvpatchLoopJob<E: ThreadedEngine> {
    pub(super) kernel: Kernel,
    pub(super) state: ThreadRuntimeState<E>,
    pub(super) phase: HvpatchProductionPhase,
    pub(super) registration_wait: Option<carrick_hal::VcpuLeaseChangeSubscription>,
    pub(super) terminal_settlement: HvpatchExternalTerminalSettlement,
    pub(super) terminal_result: Option<Result<VcpuLoopOutcome, RuntimeError>>,
    pub(super) completion: continuation::LogicalJobCompletion,
    pub(super) traps: usize,
    pub(super) budget_floor: usize,
    pub(super) seen_signal_progress: u64,
    pub(super) last_signal_progress: Instant,
    pub(super) terminal_runtime: PersistentTerminalRuntimeState,
    pub(super) pending_terminal_retirement: Option<crate::hvpatch::PendingAddressSpaceRetirement>,
    pub(super) pending_terminal_inventory:
        Option<(Arc<crate::kernel::Kernel>, crate::kernel::MmId)>,
    pub(super) external_exec: Option<crate::kernel::control::ExecWork>,
}

pub(crate) trait ProductionHvpatchLoopPoll: Send {
    fn pt_quiesce(&self) -> Arc<crate::fork_quiesce::PtQuiesce>;

    fn poll(
        &mut self,
        engine: &mut dyn std::any::Any,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> executor::ExecutorExit;

    fn after_terminal_settlement(&mut self);

    /// The scheduler settled this thread against a target the kernel graph
    /// says is TERMINAL: no successor exists, so nothing will run this job
    /// again and no other publisher is left for it.
    fn after_reaped_settlement(&mut self);

    fn after_executor_failure_settlement(&mut self) -> continuation::ExecutorFailureSettlement;

    fn take_address_space_retirement(
        &mut self,
    ) -> Option<crate::hvpatch::PendingAddressSpaceRetirement>;

    fn apply_detached_address_space_retirement(
        &mut self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), TrapError>;

    /// The same publication, returning the authenticated receipt a published
    /// `HvpatchTaskMmAuthority` needs to leave its `Active` phase.
    fn apply_detached_address_space_retirement_with_receipt(
        &mut self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<carrick_hal::FrameInventoryRetirementReceipt, TrapError>;
}

impl<E: ThreadedEngine + 'static> ProductionHvpatchLoopJob<E>
where
    E::SiblingSpec: 'static,
{
    fn external_exec_failure(&mut self, engine: &mut E, code: i32) -> executor::ExecutorExit {
        let context = self
            .state
            .service_kernel_context
            .as_ref()
            .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during external exec failure transition"))
            .retain_exact();
        let outcome = VcpuLoopOutcome::ProcessExit(Box::new(assemble_run_result(
            &self.kernel,
            code,
            None,
            self.traps,
            false,
        )));
        self.begin_persistent_process_terminal(
            engine,
            PersistentTerminal::from_outcome(outcome),
            context,
        )
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) fn start_external_exec(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> Result<executor::ExecutorExit, ProductionHvpatchPollError> {
        let request = self
            .external_exec
            .as_mut()
            .ok_or_else(|| {
                RuntimeError::Configuration("external exec work disappeared".to_owned())
            })?
            .take_request()
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
        let context = self
            .state
            .service_kernel_context
            .as_ref()
            .ok_or_else(|| {
                RuntimeError::Configuration(
                    "external exec lost exact child Kernel context".to_owned(),
                )
            })?
            .retain_exact();
        let user = request.user.map(|user| {
            let supplementary = user
                .supplementary_gids
                .into_iter()
                .map(carrick_abi::NsGid::new)
                .collect();
            (
                carrick_abi::NsUid::new(user.uid),
                carrick_abi::NsGid::new(user.gid),
                supplementary,
            )
        });
        let context = match self.kernel.dispatcher.configure_logical_exec_context(
            &context,
            request.workdir.as_deref(),
            user,
        ) {
            Ok(context) => context,
            Err(_) => {
                self.state.finish_internal_control_exec()?;
                return Ok(self.external_exec_failure(engine, 126));
            }
        };
        let kernel = Arc::clone(&self.kernel);
        let setup = kernel.dispatcher.with_kernel_resources(&context, || {
            let requested_path = request.argv[0].clone();
            let argv = request.argv.into_iter().map(String::into_bytes).collect();
            let mut env = self.kernel.dispatcher.current_exec_env();
            for variable in request.env {
                let prefix = format!("{}=", variable.key).into_bytes();
                env.retain(|entry| !entry.starts_with(&prefix));
                let mut entry = prefix;
                entry.extend_from_slice(variable.value.as_bytes());
                env.push(entry);
            }
            let path = if requested_path.contains('/') {
                Ok(requested_path)
            } else {
                let search = env
                    .iter()
                    .rev()
                    .find_map(|entry| entry.strip_prefix(b"PATH="))
                    .and_then(|value| std::str::from_utf8(value).ok())
                    .unwrap_or("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
                self.kernel
                    .dispatcher
                    .resolve_execvp_path(&requested_path, search)
            };
            path.map(|path| (path, argv, env))
        });
        let (path, argv, env) = match setup {
            Ok(setup) => setup,
            Err(errno) => {
                let exit_code = if errno == crate::linux_abi::LINUX_ENOENT {
                    127
                } else {
                    126
                };
                self.state.finish_internal_control_exec()?;
                return Ok(self.external_exec_failure(engine, exit_code));
            }
        };
        match self.state.prepare_execve(
            &self.kernel,
            &context,
            engine,
            path,
            argv,
            env,
            ExecCompletionOrigin::InternalControl,
        )? {
            exec::ExecvePreparation::Complete(Some(outcome)) => {
                self.state.finish_internal_control_exec()?;
                Ok(self.enter_terminal_with_outcome(engine, outcome))
            }
            exec::ExecvePreparation::Complete(None) => Ok(self.external_exec_failure(engine, 126)),
            exec::ExecvePreparation::TerminalFailure(failure) => {
                Err(ProductionHvpatchPollError::from_exec_failure(failure))
            }
            exec::ExecvePreparation::Prepared(prepared) => {
                let prepared = *prepared;
                let owner = match self.state.begin_prepared_execve_drain(
                    &self.kernel,
                    self.completion.id(),
                    prepared,
                ) {
                    Ok(owner) => owner,
                    Err(failure) => {
                        return Err(ProductionHvpatchPollError::from_exec_failure(failure));
                    }
                };
                if owner.is_ready() {
                    let finished = match self.state.finish_prepared_execve_drain(
                        &self.kernel,
                        engine,
                        &self.completion,
                        owner,
                    ) {
                        Ok(finished) => finished,
                        Err(failure) => {
                            return Err(ProductionHvpatchPollError::from_exec_failure(failure));
                        }
                    };
                    self.finish_exec_suffix(engine, control, finished)
                } else {
                    self.phase = HvpatchProductionPhase::ExecSiblingDrain { context, owner };
                    Ok(self.suspend(
                        HvpatchLoopSuspension::ExecSiblingDrain,
                        executor::ExecutorExit::Blocked(
                            crate::kernel::objects::BlockedReason::ChildState,
                        ),
                    ))
                }
            }
        }
    }

    fn take_terminal_inventory_authority(
        &mut self,
    ) -> Result<(Arc<crate::kernel::Kernel>, crate::kernel::MmId), TrapError> {
        self.pending_terminal_inventory.take().ok_or_else(|| {
            TrapError::Hypervisor(
                "detached terminal cleanup lost its exact Kernel/MM authority".to_owned(),
            )
        })
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn control_quantum(
        &self,
    ) -> Result<Option<crate::kernel::objects::SchedulerControlQuantum>, RuntimeError> {
        let context = self.state.service_kernel_context.as_ref().ok_or_else(|| {
            RuntimeError::Configuration(
                "carrier logical exec lost exact root Kernel context".to_owned(),
            )
        })?;
        let thread = context.thread();
        thread
            .scheduler_control_quantum(thread.key())
            .map_err(|error| {
                RuntimeError::Configuration(format!(
                    "inspect carrier logical exec control quantum: {error}"
                ))
            })
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn finish_control_quantum(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
        deferred_resume_blocked: Option<DeferredResumeBlocked>,
    ) -> Result<executor::ExecutorExit, RuntimeError> {
        let context = self.state.service_kernel_context.as_ref().ok_or_else(|| {
            RuntimeError::Configuration(
                "carrier logical exec lost exact root Kernel context".to_owned(),
            )
        })?;
        let thread = context.thread();
        let quantum = thread
            .finish_scheduler_control_quantum(thread.key())
            .map_err(|error| {
                RuntimeError::Configuration(format!(
                    "finish carrier logical exec control quantum: {error}"
                ))
            })?;
        // Clear-then-recheck closes coalesced admission races. Every request
        // queued before the clear remains visible here. A request queued after
        // this check observes no marker, so its waker creates a fresh control
        // edge. If the next request is already visible, restore the displaced
        // continuation token and service it in this same owner quantum.
        if let Some(work) = self.kernel.try_take_control_exec() {
            thread
                .restore_scheduler_control_quantum(thread.key(), quantum)
                .map_err(|error| {
                    RuntimeError::Configuration(format!(
                        "continue carrier logical exec control quantum: {error}"
                    ))
                })?;
            return self.begin_control_exec_fork(engine, control, work, deferred_resume_blocked);
        }
        let Some(deferred) = deferred_resume_blocked else {
            if quantum.blocked_reason.is_some() {
                return Err(RuntimeError::Configuration(
                    "carrier logical exec lost its deferred blocked continuation".to_owned(),
                ));
            }
            return Ok(executor::ExecutorExit::Syscall);
        };
        if quantum.blocked_reason != deferred.original_blocked_reason {
            return Err(RuntimeError::Configuration(
                "carrier logical exec changed the deferred blocked reason".to_owned(),
            ));
        }
        let continuation_ready = control
            .execution_lease_mut()
            .map_err(RuntimeError::Trap)?
            .blocked_continuation()
            .is_some_and(|continuation| continuation.ready_event().is_ok());
        let original_blocked_reason = deferred.original_blocked_reason;
        deferred.restore(&mut self.phase);
        match (original_blocked_reason, continuation_ready) {
            // A real producer won while the control quantum was runnable. Let
            // ResumeBlocked consume that exact event in this same lease.
            (_, true) | (None, _) => Ok(executor::ExecutorExit::Syscall),
            (Some(reason), false) => Ok(self.suspend(
                HvpatchLoopSuspension::BlockedContinuation,
                executor::ExecutorExit::Blocked(reason),
            )),
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn begin_control_exec_fork(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
        work: crate::kernel::control::ExecWork,
        deferred_resume_blocked: Option<DeferredResumeBlocked>,
    ) -> Result<executor::ExecutorExit, RuntimeError> {
        let context = self
            .state
            .service_kernel_context
            .as_ref()
            .ok_or_else(|| {
                RuntimeError::Configuration(
                    "carrier logical exec lost exact root Kernel context".to_owned(),
                )
            })?
            .retain_exact();
        let prepared = self.state.prepare_in_process_fork(
            &self.kernel,
            &context,
            engine,
            control,
            &mut ProductionHvpatchProcessBackendOps,
            quiesce::ProcessForkAttempt {
                request: quiesce::ForkRequest {
                    flags: 0,
                    pidfd_out: None,
                    clone_parent: false,
                    parent_tid_addr: None,
                    child_tid_addr: None,
                    exit_signal: 0,
                    child_stack: 0,
                    vfork: None,
                },
                coordinator: None,
                external_exec: Some(work),
            },
        )?;
        self.complete_persistent_process_fork(
            engine,
            control,
            None,
            deferred_resume_blocked,
            prepared,
        )
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) fn complete_persistent_process_fork(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
        frame: Option<carrick_hal::RawSyscall>,
        deferred_resume_blocked: Option<DeferredResumeBlocked>,
        prepared: quiesce::PreparedInProcessFork,
    ) -> Result<executor::ExecutorExit, RuntimeError> {
        match prepared {
            quiesce::PreparedInProcessFork::Complete(Some(value)) => {
                if frame.is_some() {
                    self.state
                        .complete_returned(engine, &self.kernel.reporter, value)?;
                }
                if frame.is_none() {
                    return self.finish_control_quantum(engine, control, deferred_resume_blocked);
                }
                Ok(executor::ExecutorExit::Syscall)
            }
            quiesce::PreparedInProcessFork::Complete(None) => {
                if deferred_resume_blocked.is_some() {
                    return Err(RuntimeError::Configuration(
                        "external logical exec retired the blocked init process".to_owned(),
                    ));
                }
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during persistent fork completion"))
                    .retain_exact();
                let outcome = VcpuLoopOutcome::ProcessExit(Box::new(assemble_run_result(
                    &self.kernel,
                    0,
                    None,
                    self.traps,
                    false,
                )));
                Ok(self.begin_persistent_process_terminal(
                    engine,
                    PersistentTerminal::from_outcome(outcome),
                    context,
                ))
            }
            quiesce::PreparedInProcessFork::SuspendVfork(suspension) => {
                let frame = frame.ok_or_else(|| {
                    RuntimeError::Configuration(
                        "external logical exec unexpectedly requested vfork suspension".to_owned(),
                    )
                })?;
                let request = suspension.request;
                let child_pid = suspension.child_pid;
                let exit = self.state.persistent_block_exit(
                    &self.kernel,
                    control.execution_lease_mut().map_err(RuntimeError::Trap)?,
                    request,
                    HvpatchBlockInput::Vfork {
                        child: suspension.child,
                        wait: suspension.wait,
                        activation: suspension.activation,
                    },
                )?;
                self.phase = HvpatchProductionPhase::ResumeBlocked {
                    frame,
                    vfork_child_pid: Some(child_pid),
                };
                Ok(self.suspend(HvpatchLoopSuspension::VforkParent, exit))
            }
            quiesce::PreparedInProcessFork::Retry {
                request,
                coordinator,
                external_exec,
                _subscription,
            } => {
                self.phase = HvpatchProductionPhase::RetryProcessFork {
                    frame,
                    request,
                    coordinator,
                    external_exec,
                    deferred_resume_blocked,
                    _subscription,
                };
                Ok(self.suspend(
                    HvpatchLoopSuspension::BlockedContinuation,
                    executor::ExecutorExit::Blocked(
                        crate::kernel::objects::BlockedReason::HostWait,
                    ),
                ))
            }
        }
    }

    fn finalize_persistent_process_terminal(
        &mut self,
        engine: &mut E,
        terminal_context: crate::kernel::KernelContext,
        terminal: PersistentTerminal,
    ) -> executor::ExecutorExit {
        let process = self.kernel.hvpatch_process.as_ref().unwrap_or_else(|| {
            carrick_fatal!(
                "kernel::terminal_settlement",
                "Terminal process missing execution context during terminal finalization"
            )
        });
        let wake_scheduler = || {
            self.kernel
                .hvpatch_runtime
                .as_ref()
                .unwrap_or_else(|| carrick_fatal!("hvpatch::task_backend_lifecycle", "Missing HVPatch runtime reference when constructing the terminal-retire wake callback"))
                .continuation_services(terminal_context.kernel())
                .0
        };
        // Close the process's fds FIRST — before the owner-set hold and the
        // retirement topology lock — matching Linux `exit_files` preceding
        // `exit_notify`, and the fork path's lock order (subsystem
        // authorities, then topology). Closing takes per-description locks;
        // a sibling mid-`read(2)` holds one of those while its copy-in
        // faults a copy-on-write page, which needs the topology lock. Taking
        // the topology lock first and closing fds under it was an ABBA that
        // wedged `ltp-fork07` at its ninth child (`forkreadexitcow`).
        // Idempotent on a `TerminalRetireRetry` re-entry: the table
        // generation is already drained and its close events consumed.
        self.kernel
            .dispatcher
            .retire_hvpatch_process_fds(&terminal_context);
        // Retiring this process's MM edge is an owner-set edit on its
        // generation. A vfork sibling mid-exec has that generation reserved
        // and its owner set frozen; admit the edit against the reservation
        // here, where a refusal is a parkable wait, rather than at
        // `begin_address_space_retirement` after the kernel exit
        // publication, where it is only an abort. The hold itself is taken
        // before the topology lock and never held across a park.
        let owner_set_edit = loop {
            let settlement = process.mm_resources().exec_settlement_epoch();
            match process
                .mm_resources()
                .hold_owner_set_edit(terminal_context.task().key())
            {
                Ok(hold) => break Some(hold),
                Err(crate::hvpatch::MmResourcesError::UnknownTask(_)) => break None,
                Err(crate::hvpatch::MmResourcesError::ExecReservationConflict(conflict)) => {
                    let scheduler = wake_scheduler();
                    let thread = terminal_context.thread().key();
                    match process.mm_resources().subscribe_exec_settlement(
                        settlement,
                        Arc::new(move |_| {
                            let _ = scheduler.wake(thread);
                        }),
                    ) {
                        crate::hvpatch::ExecSettlementEnrollment::Ready => continue,
                        crate::hvpatch::ExecSettlementEnrollment::Subscribed(subscription) => {
                            tracing::debug!(
                                ?conflict,
                                "process exit deferred behind a sibling's exec reservation"
                            );
                            self.phase = HvpatchProductionPhase::TerminalRetireRetry {
                                terminal,
                                context: terminal_context,
                                _subscription: TerminalRetireSubscription::ExecSettlement {
                                    _subscription: subscription,
                                },
                            };
                            return self.suspend(
                                HvpatchLoopSuspension::TerminalSiblingDrain,
                                executor::ExecutorExit::Blocked(
                                    crate::kernel::objects::BlockedReason::HostWait,
                                ),
                            );
                        }
                    }
                }
                Err(failure) => {
                    tracing::error!(%failure, "admit persistent terminal MM retirement");
                    carrick_fatal!(
                        "hvpatch::mm_reservation",
                        "admit persistent terminal MM retirement failed: {failure}"
                    );
                }
            }
        };
        let topology = loop {
            let observed = crate::fork_quiesce::topology_release_generation();
            if let Some(topology) = crate::fork_quiesce::try_acquire_topology_lock(
                carrick_observability::probes::HvpatchTopologyOperation::ProcessRetire,
                process.pid(),
                self.state.this_tid.raw(),
            ) {
                break topology;
            }
            let scheduler = wake_scheduler();
            let thread = terminal_context.thread().key();
            match crate::fork_quiesce::subscribe_topology_release(
                observed,
                Arc::new(move |_| {
                    let _ = scheduler.wake(thread);
                }),
            ) {
                carrick_thread::fork_quiesce::TopologyReleaseEnrollment::Ready(_) => continue,
                carrick_thread::fork_quiesce::TopologyReleaseEnrollment::Subscribed(
                    subscription,
                ) => {
                    // Release the admission while parked: the topology
                    // holder may be the exec'er this hold is excluding.
                    drop(owner_set_edit);
                    self.phase = HvpatchProductionPhase::TerminalRetireRetry {
                        terminal,
                        context: terminal_context,
                        _subscription: TerminalRetireSubscription::Topology {
                            _subscription: subscription,
                        },
                    };
                    return self.suspend(
                        HvpatchLoopSuspension::TerminalSiblingDrain,
                        executor::ExecutorExit::Blocked(
                            crate::kernel::objects::BlockedReason::HostWait,
                        ),
                    );
                }
            }
        };
        let terminal_mm = terminal_context.shared().mm().id();
        let owns_final_mm = process
            .owns_final_mm_edge(terminal_context.task().key())
            .unwrap_or_else(|failure| {
                tracing::error!(%failure, "classify persistent terminal MM ownership");
                carrick_fatal!(
                    "kernel::terminal_settlement",
                    "classify persistent terminal MM ownership failed: {failure}"
                );
            });
        if owns_final_mm {
            let capacity = carrick_hal::FrameEventCapacity::for_event_count(
                carrick_hal::MAX_FRAME_INVENTORY_EVENTS_PER_BATCH,
            )
            .unwrap_or_else(|_| {
                carrick_fatal!(
                    "kernel::terminal_settlement",
                    "Missing sibling execution context during terminal settlement"
                )
            });
            let reservation = terminal_context
                .kernel()
                .reserve_frame_inventory(0, 0, capacity)
                .unwrap_or_else(|failure| {
                    tracing::error!(%failure, "reserve persistent failure inventory");
                    carrick_fatal!(
                        "kernel::terminal_settlement",
                        "reserve persistent failure inventory failed: {failure}"
                    );
                });
            let transaction = reservation.transaction();
            engine
                .begin_retirement_inventory(reservation)
                .unwrap_or_else(|failure| {
                    terminal_context
                        .kernel()
                        .frame_inventory()
                        .abandon(transaction);
                    tracing::error!(%failure, "arm persistent failure inventory");
                    carrick_fatal!(
                        "kernel::container_scope",
                        "arm persistent failure inventory failed: {failure}"
                    );
                });
        }
        let prepared_core = match &terminal {
            PersistentTerminal::Outcome { prepared_core, .. } => prepared_core.as_deref(),
            _ => None,
        };
        let core_publication = match prepared_core {
            Some(prepared) => {
                match self.kernel.dispatcher.publish_core_atomic(
                    &prepared.snapshot,
                    prepared.generation,
                    prepared.payload.clone(),
                ) {
                    Ok(publ) => {
                        crate::probes::hvpatch_core_lifecycle(
                            4,
                            process.pid(),
                            prepared.fatal_tid,
                            publ.generation,
                            0,
                        );
                        tracing::debug!(
                            path = %publ.path,
                            bytes = publ.bytes,
                            "published guest core file"
                        );
                        Some(publ)
                    }
                    Err(error) => {
                        tracing::warn!(%error, "publish core atomic");
                        crate::probes::hvpatch_core_lifecycle(
                            6,
                            process.pid(),
                            prepared.fatal_tid,
                            prepared.generation,
                            1,
                        );
                        None
                    }
                }
            }
            None => None,
        };
        let core_dumped = core_publication.is_some();
        let (exit_code, wait_encoding, terminal_publication) = match &terminal {
            PersistentTerminal::Outcome {
                outcome: VcpuLoopOutcome::ProcessExit(run) | VcpuLoopOutcome::TrapLimit(run),
                ..
            } => (
                run.exit_code,
                run.wait_status_encoding(core_dumped),
                Ok((**run).clone()),
            ),
            PersistentTerminal::Error(error) => {
                // The owner's failure would otherwise vanish: its sibling job
                // result is not the launch result, so this arm's Err(()) was
                // the only externally visible trace ("sibling-owned process
                // termination failed" with no cause). Name the cause here.
                //
                // The guest pid belongs in the line for the same reason: a
                // `cpython-importlib` wedge left one zombie at `127 << 8` and
                // an unattributable error on stderr, so which Linux process
                // carrick killed had to be inferred from the wait status.
                tracing::error!(
                    guest_pid = process.pid(),
                    %error,
                    "HVPatch terminal owner publishes failure"
                );
                (127, 127 << 8, Err(()))
            }
            PersistentTerminal::Outcome {
                outcome: VcpuLoopOutcome::ThreadDone,
                ..
            } => carrick_fatal!(
                "kernel::terminal_settlement",
                "Unexpected terminal settlement disposition encountered during process teardown"
            ),
        };
        let process_exit_event = process.record_process_exit_begin(exit_code, self.state.this_tid);
        let child = process.is_child();
        if let Some(work) = self.external_exec.take() {
            let out = self.kernel.dispatcher.stdout();
            let err = self.kernel.dispatcher.stderr();
            let terminating_signal = match &terminal {
                PersistentTerminal::Outcome {
                    outcome: VcpuLoopOutcome::ProcessExit(run) | VcpuLoopOutcome::TrapLimit(run),
                    ..
                } => run.terminating_signal,
                PersistentTerminal::Error(_) => None,
                PersistentTerminal::Outcome {
                    outcome: VcpuLoopOutcome::ThreadDone,
                    ..
                } => None,
            };
            if let Err(error) = work.complete(crate::kernel::control::ExecResult {
                exit_code,
                terminating_signal,
                stdout: out,
                stderr: err,
                output_truncated: false,
            }) {
                tracing::error!(%error, "publish logical exec terminal result failed");
                carrick_fatal!(
                    "kernel::terminal_settlement",
                    "publish logical exec terminal result failed: {error}"
                );
            }
        }
        let status = crate::kernel::LinuxWaitStatus::from_wait_encoding(wait_encoding);
        let orphan_adopter = self.kernel.dispatcher.hvpatch_orphan_adopter();
        let publish_result = process.publish_exit_status(status, orphan_adopter, |parent| {
            if child {
                self.kernel.notify_hvpatch_parent_exit(parent);
            } else if let Some(parent) = parent {
                tracing::error!(
                    parent = ?parent,
                    "child exit notification dropped: is_child() said no parent but the exit transaction named one"
                );
            }
        });
        if publish_result.is_ok() {
            if let Some(chain) = self.kernel.dispatcher.observers() {
                let p = crate::observe::ProcessInfo::new(&terminal_context);
                chain.on_process_exit(&p, crate::observe::ExitStatus::from_wait_status(status));
            }
        }
        if let Err(failure) = publish_result {
            if let Some(publ) = &core_publication {
                let _ = self.kernel.dispatcher.rollback_core_publication(publ);
            }
            if let Some(prepared) = prepared_core {
                crate::probes::hvpatch_core_lifecycle(
                    6,
                    process.pid(),
                    prepared.fatal_tid,
                    prepared.generation,
                    1,
                );
            }
            tracing::error!(%failure, "publish persistent failure Kernel exit");
            carrick_fatal!(
                "kernel::terminal_settlement",
                "publish persistent failure Kernel exit failed: {failure}"
            );
        }
        // The logical process is no longer runnable. Drop its carrier-wide
        // run-state publication now; run-state-only records are reclaimed here,
        // while namespace-owned records retain their zombie metadata until a
        // consuming wait reaps them.
        crate::run_state::clear_guest_process(process.pid());
        if let Some(prepared) = prepared_core {
            if core_dumped {
                crate::probes::hvpatch_core_lifecycle(
                    5,
                    process.pid(),
                    prepared.fatal_tid,
                    prepared.generation,
                    0,
                );
            }
        }
        self.kernel.unregister_hvpatch_runtime_endpoint();
        if owns_final_mm {
            if self
                .pending_terminal_inventory
                .replace((Arc::clone(terminal_context.kernel()), terminal_mm))
                .is_some()
            {
                carrick_fatal!(
                    "kernel::terminal_settlement",
                    "Failed to claim persistent process terminal owner role"
                );
            }
        }
        self.pending_terminal_retirement = Some(
            process
                .begin_address_space_retirement(exit_code, self.state.this_tid, process_exit_event)
                .unwrap_or_else(|failure| {
                    tracing::error!(%failure, "retire persistent failure MM/ASID");
                    carrick_fatal!(
                        "kernel::terminal_settlement",
                        "retire persistent failure MM/ASID failed: {failure}"
                    );
                }),
        );
        drop(owner_set_edit);
        drop(topology);
        self.kernel.publish_process_terminal(terminal_publication);
        self.finish(terminal.into_result())
    }

    /// Complete or park a guest thread's logical exit. `Busy` parks the
    /// job with a reservation-change subscription and schedules a retry
    /// through `HvpatchProductionPhase::RetryThreadExit` — the executor
    /// must NOT block in the exit wait, because the reservation holder (an
    /// exec survivor's terminal path) may be waiting for this exact
    /// executor's ASID acknowledgement (the execfromthread ABBA wedge).
    fn settle_persistent_thread_exit(
        &mut self,
        engine: &mut E,
        code: i32,
        context: crate::kernel::KernelContext,
        disposition: threads::PersistentThreadExitDisposition,
    ) -> executor::ExecutorExit {
        match disposition {
            threads::PersistentThreadExitDisposition::Done(VcpuLoopOutcome::ThreadDone) => {
                self.finish(Ok(VcpuLoopOutcome::ThreadDone))
            }
            threads::PersistentThreadExitDisposition::Done(
                outcome @ VcpuLoopOutcome::ProcessExit(_),
            ) => {
                self.terminal_runtime = PersistentTerminalRuntimeState::Withdrawn;
                self.begin_persistent_process_terminal(
                    engine,
                    PersistentTerminal::from_outcome(outcome),
                    context,
                )
            }
            threads::PersistentThreadExitDisposition::Done(VcpuLoopOutcome::TrapLimit(_)) => {
                carrick_fatal!(
                    "kernel::thread_settlement",
                    "Unhandled thread exit disposition during persistent thread settlement"
                )
            }
            threads::PersistentThreadExitDisposition::Busy { observed_epoch } => {
                if self.kernel.process_exiting()
                    || thread_should_finish_for_exec_replacement(
                        &self.state.registry,
                        self.state.this_tid,
                    )
                {
                    // Ownership passed (see the drain gate): the process
                    // terminal or an exec replacement retires this thread's
                    // row; parking would strand past retirement.
                    self.state.trace_hvpatch_thread_terminal(
                        carrick_observability::probes::HvpatchThreadTerminalReason::ProcessTerminalLoser,
                        1,
                    );
                    if !self.state.thread_exit_withdrawn {
                        let _ = self
                            .state
                            .withdraw_persistent_terminal_owner_runtime(&self.kernel, engine);
                        self.state.thread_exit_withdrawn = true;
                    }
                    return self.finish(Ok(VcpuLoopOutcome::ThreadDone));
                }
                self.park_thread_exit_retry(
                    &context,
                    observed_epoch,
                    HvpatchProductionPhase::RetryThreadExit { code },
                )
            }
        }
    }

    /// Park a Busy thread exit as a Blocked job subscribed to the kernel
    /// reservation-change epoch, retrying through `retry_phase`. The wake
    /// is the plain key-addressed `Scheduler::wake`: while the task is
    /// LIVE it rolls the submission authority correctly, and the drain
    /// invariant (the terminal owner's sibling drain waits for member jobs
    /// and wakes removed members BEFORE the task exit commits) guarantees
    /// the task is live whenever this park still needs a wake. A wake that
    /// races retirement anyway fails with UnknownThread and is discarded —
    /// never an abort (only a generation-observer bypass can abort, which
    /// this path does not do).
    fn park_thread_exit_retry(
        &mut self,
        context: &crate::kernel::KernelContext,
        observed_epoch: u64,
        retry_phase: HvpatchProductionPhase,
    ) -> executor::ExecutorExit {
        let scheduler = self
            .kernel
            .hvpatch_runtime
            .as_ref()
            .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during thread exit retry park"))
            .continuation_services(context.kernel())
            .0;
        let thread = context.thread().key();
        let callback: Arc<dyn Fn() + Send + Sync + 'static> = Arc::new(move || {
            let woke = scheduler.wake(thread);
            tracing::info!(?thread, ?woke, "thread-exit retry wake");
        });
        // A `None` subscription means the epoch already moved and the
        // callback (wake) already fired — parking is still correct: the
        // pending wake resumes the retry immediately.
        self.state.thread_exit_retry_subscription = context
            .kernel()
            .subscribe_reservation_change(observed_epoch, callback);
        tracing::info!(
            thread = ?context.thread().key(),
            observed_epoch,
            "thread-exit retry parks"
        );
        self.phase = retry_phase;
        self.suspend(
            HvpatchLoopSuspension::TerminalSiblingDrain,
            executor::ExecutorExit::Blocked(crate::kernel::objects::BlockedReason::ChildState),
        )
    }

    fn begin_persistent_process_terminal(
        &mut self,
        engine: &mut E,
        terminal: PersistentTerminal,
        context: crate::kernel::KernelContext,
    ) -> executor::ExecutorExit {
        let receipt = self
            .kernel
            .try_claim_persistent_process_exit(self.state.this_tid)
            .unwrap_or_else(|failure| {
                tracing::error!(%failure, "claim persistent process terminal owner");
                carrick_fatal!(
                    "kernel::terminal_settlement",
                    "claim persistent process terminal owner failed: {failure}"
                );
            });
        self.begin_persistent_process_terminal_with_claim(engine, terminal, context, receipt)
    }

    fn begin_persistent_process_terminal_from_exec(
        &mut self,
        engine: &mut E,
        terminal: PersistentTerminal,
        pending: PendingExecTerminal,
    ) -> executor::ExecutorExit {
        let PendingExecTerminal { context, handoff } = pending;
        let receipt = handoff.claim_process_exit().unwrap_or_else(|failure| {
            match &terminal {
                PersistentTerminal::Error(original) => {
                    tracing::error!(%original, %failure, "claim exec terminal handoff owner");
                }
                PersistentTerminal::Outcome { .. } => {
                    tracing::error!(%failure, "claim exec terminal handoff owner");
                }
            }
            carrick_fatal!(
                "hvpatch::exec_terminal",
                "claim exec terminal handoff owner failed: {failure}"
            );
        });
        self.state.service_kernel_context = Some(context.retain_exact());
        self.state.kernel_thread = Some(Arc::clone(context.thread()));
        if receipt.claim == ProcessExitClaim::Owner {
            self.kernel.begin_process_exit();
        }
        self.begin_persistent_process_terminal_with_claim(engine, terminal, context, receipt)
    }

    fn begin_persistent_process_terminal_with_claim(
        &mut self,
        engine: &mut E,
        terminal: PersistentTerminal,
        context: crate::kernel::KernelContext,
        receipt: ProcessExitClaimReceipt,
    ) -> executor::ExecutorExit {
        match receipt.claim {
            ProcessExitClaim::LostToExec | ProcessExitClaim::AlreadyOwned => {
                self.state.trace_hvpatch_thread_terminal(
                    carrick_observability::probes::HvpatchThreadTerminalReason::ProcessTerminalLoser,
                    2,
                );
                if self.terminal_runtime == PersistentTerminalRuntimeState::Resident {
                    let _ = self.state.handle_persistent_thread_exit(
                        &self.kernel,
                        engine,
                        127,
                        self.traps,
                    );
                    if !self.state.thread_exit_withdrawn {
                        let _ = self
                            .state
                            .withdraw_persistent_terminal_owner_runtime(&self.kernel, engine);
                        self.state.thread_exit_withdrawn = true;
                    }
                    self.terminal_runtime = PersistentTerminalRuntimeState::Withdrawn;
                }
                return self.finish(Ok(VcpuLoopOutcome::ThreadDone));
            }
            ProcessExitClaim::Pending => {
                tracing::info!(tid = ?self.state.this_tid, "process-terminal claim PENDING parks");
                let scheduler = self
                    .kernel
                    .hvpatch_runtime
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("kernel::runtime_binding", "A pending terminal claim cannot subscribe its exact thread without the Kernel HVPatch runtime"))
                    .continuation_services(context.kernel())
                    .0;
                let thread = context.thread().key();
                let subscription = self.kernel.clone_admission.subscribe_change(
                    receipt.change_epoch,
                    Arc::new(move || {
                        let _ = scheduler.wake(thread);
                    }),
                );
                self.phase = HvpatchProductionPhase::TerminalClaimRetry {
                    terminal,
                    context,
                    _subscription: subscription,
                };
                return self.suspend(
                    HvpatchLoopSuspension::TerminalSiblingDrain,
                    executor::ExecutorExit::Blocked(
                        crate::kernel::objects::BlockedReason::ChildState,
                    ),
                );
            }
            ProcessExitClaim::Owner => {
                self.terminal_settlement
                    .arm_process_owner()
                    .unwrap_or_else(|failure| {
                        tracing::error!(%failure, "arm persistent terminal result owner");
                        carrick_fatal!(
                            "kernel::terminal_settlement",
                            "arm persistent terminal result owner failed: {failure}"
                        );
                    });
            }
        }
        let mut terminal = terminal;
        if let PersistentTerminal::Outcome {
            ref outcome,
            ref mut prepared_core,
        } = terminal
        {
            let terminating_signal = match outcome {
                VcpuLoopOutcome::ProcessExit(run) | VcpuLoopOutcome::TrapLimit(run) => {
                    run.terminating_signal
                }
                VcpuLoopOutcome::ThreadDone => None,
            };
            if let Some(fatal) = fatal_for_terminal_owner(
                self.kernel
                    .fatal_signal
                    .recorded_for(self.state.fatal_image_generation),
                self.state.fatal_image_generation,
                self.state.linux_tid,
                terminating_signal,
            ) {
                *prepared_core =
                    match self
                        .state
                        .capture_core_for_publication(&self.kernel, engine, fatal)
                    {
                        Ok(p) => p.map(Box::new),
                        Err(error) => {
                            tracing::warn!(%error, "capture core for publication");
                            None
                        }
                    };
            }
        }
        // Withdraw runtime execution immediately, but retain the exact Kernel
        // thread/generation through drain and topology retries. Their callbacks
        // wake this owner by that key; retiring it here loses the only wake.
        if self.terminal_runtime == PersistentTerminalRuntimeState::Resident {
            self.state
                .withdraw_persistent_terminal_owner_runtime(&self.kernel, engine);
            self.terminal_runtime = PersistentTerminalRuntimeState::Withdrawn;
        }
        drop(self.state.guest_execution.take());
        let drain = self
            .state
            .begin_persistent_exit_sibling_drain(&self.kernel, self.completion.id())
            .unwrap_or_else(|failure| {
                tracing::error!(%failure, "begin persistent failure sibling drain");
                carrick_fatal!(
                    "kernel::terminal_settlement",
                    "begin persistent failure sibling drain failed: {failure}"
                );
            });
        if drain.is_ready() {
            let completions = self
                .state
                .finish_persistent_sibling_drain(&self.completion)
                .unwrap_or_else(|failure| {
                    tracing::error!(%failure, "finish persistent failure sibling drain");
                    carrick_fatal!(
                        "kernel::terminal_settlement",
                        "finish persistent failure sibling drain failed: {failure}"
                    );
                });
            self.kernel
                .process_physical_retirement
                .publish(completions)
                .unwrap_or_else(|failure| {
                    tracing::error!(%failure, "publish persistent process physical retirement");
                    carrick_fatal!(
                        "kernel::terminal_settlement",
                        "publish persistent process physical retirement failed: {failure}"
                    );
                });
            return self.finalize_persistent_process_terminal(engine, context, terminal);
        }
        self.phase = HvpatchProductionPhase::TerminalProcessDrain {
            terminal,
            context,
            drain,
        };
        self.suspend(
            HvpatchLoopSuspension::TerminalSiblingDrain,
            executor::ExecutorExit::Blocked(crate::kernel::objects::BlockedReason::ChildState),
        )
    }

    fn suspend_for_process_quiesce(
        &mut self,
        engine: &E,
        _control: &executor::HvpatchQuantumControl<'_, '_>,
    ) -> Result<Option<executor::ExecutorExit>, RuntimeError> {
        let Some(barrier) = self.state.process_fork_barrier.as_ref().map(Arc::clone) else {
            return Ok(None);
        };
        if !barrier.is_quiescing() {
            return Ok(None);
        }
        let _ = self.state.stash_parked_registers(engine);
        if self
            .state
            .publish_crash_registers_if_requested(engine)
            .is_err()
        {
            self.state.withdraw_from_crash_capture();
        }
        let context = match self.state.service_kernel_context.as_ref() {
            Some(context) => context.retain_exact(),
            None => self
                .kernel
                .dispatcher
                .capture_kernel_context(self.state.linux_tid)
                .map_err(|error| {
                    RuntimeError::Configuration(format!(
                        "quiescing HVPatch task lost Kernel context: {error}"
                    ))
                })?,
        };
        self.state.service_kernel_context = Some(context.retain_exact());
        let scheduler = self
            .kernel
            .hvpatch_runtime
            .as_ref()
            .unwrap_or_else(|| {
                carrick_fatal!(
                    "vcpu_loop::quiesce_barrier",
                    "Missing quiesce barrier reference when suspending for process quiesce"
                )
            })
            .continuation_services(context.kernel())
            .0;
        let thread = context.thread().key();
        loop {
            let observed = barrier.publication_generation();
            let wake_scheduler = Arc::clone(&scheduler);
            let enrollment = barrier.subscribe_quiesce(
                observed,
                Arc::new(move |event| {
                    if event.kind == carrick_thread::fork_quiesce::QuiesceEventKind::Released {
                        let _ = wake_scheduler.wake(thread);
                    }
                }),
            );
            match enrollment {
                carrick_thread::fork_quiesce::QuiesceEnrollment::Ready(event)
                    if event.kind == carrick_thread::fork_quiesce::QuiesceEventKind::Released =>
                {
                    return Ok(None);
                }
                carrick_thread::fork_quiesce::QuiesceEnrollment::Ready(_) => continue,
                carrick_thread::fork_quiesce::QuiesceEnrollment::Subscribed(subscription) => {
                    self.phase = HvpatchProductionPhase::ResumeForkQuiesce {
                        _subscription: subscription,
                    };
                    let exit = self.suspend(
                        HvpatchLoopSuspension::InitialAdmission,
                        executor::ExecutorExit::Quiesced,
                    );
                    barrier.notify_quiesced_progress();
                    return Ok(Some(exit));
                }
            }
        }
    }

    fn suspend_for_job_control(
        &mut self,
        engine: &mut E,
        _control: &executor::HvpatchQuantumControl<'_, '_>,
    ) -> Result<Option<executor::ExecutorExit>, RuntimeError> {
        let context = match self.state.service_kernel_context.as_ref() {
            Some(context) => context.retain_exact(),
            None => {
                let context = self
                    .kernel
                    .dispatcher
                    .capture_kernel_context(self.state.linux_tid)
                    .map_err(|error| {
                        RuntimeError::Configuration(format!(
                            "capture kernel context for job control: {error}"
                        ))
                    })?;
                self.state.service_kernel_context = Some(context.retain_exact());
                context
            }
        };
        let task = context.task();
        let ptrace_stop_settled = match context.kernel().settle_task_ptrace_stop(task.key().id) {
            crate::kernel::objects::PtraceStopSettlement::NotPtraceStopped => false,
            crate::kernel::objects::PtraceStopSettlement::Stopped
            | crate::kernel::objects::PtraceStopSettlement::Resumed { .. } => true,
        };
        if !task.is_job_control_stopped() && !ptrace_stop_settled {
            return Ok(None);
        }
        self.state.withdraw_from_crash_capture();
        self.state
            .publish_thread_run_state(crate::run_state::RunState::Blocked, 'T');

        let scheduler = self
            .kernel
            .hvpatch_runtime
            .as_ref()
            .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during job control suspension"))
            .continuation_services(context.kernel())
            .0;
        let thread = context.thread().key();

        while task.is_job_control_stopped() {
            let observed = task.wake_generation();
            let wake_scheduler = Arc::clone(&scheduler);
            let enrollment = task.subscribe_wake(
                observed,
                Arc::new(move |_| {
                    let _ = wake_scheduler.wake(thread);
                }),
            );
            match enrollment {
                crate::kernel::objects::TaskWakeEnrollment::Ready(_) => {
                    if !task.is_job_control_stopped() {
                        break;
                    }
                    continue;
                }
                crate::kernel::objects::TaskWakeEnrollment::Subscribed(subscription) => {
                    if !task.is_job_control_stopped() {
                        break;
                    }
                    self.phase = HvpatchProductionPhase::ResumeJobControlStop {
                        _subscription: subscription,
                    };
                    let exit = self.suspend(
                        HvpatchLoopSuspension::BlockedContinuation,
                        executor::ExecutorExit::Blocked(
                            crate::kernel::objects::BlockedReason::HostWait,
                        ),
                    );
                    return Ok(Some(exit));
                }
            }
        }
        if let Some(fault) = context.kernel().take_ptrace_resume_fault(task.key().id) {
            if let Some(outcome) = deliver_fault_signal(
                &self.kernel,
                &context,
                engine,
                self.state.this_tid,
                self.state.fatal_image_generation,
                fault.signal.raw(),
                fault.si_code,
                fault.si_addr,
                fault.interrupted_pc,
                self.traps,
            )? {
                return Ok(Some(self.enter_terminal_with_outcome(engine, outcome)));
            }
            return Ok(None);
        }
        if ptrace_stop_settled
            && let Some(outcome) = service_signals_threaded(
                &self.kernel,
                &context,
                engine,
                self.state.this_tid,
                self.state.fatal_image_generation,
                None,
                None,
                None,
                None,
                self.traps,
            )?
        {
            return Ok(Some(self.enter_terminal_with_outcome(engine, outcome)));
        }
        Ok(None)
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[allow(clippy::too_many_arguments)]
    fn rollback_published_hvpatch_clone<M: threads::CloneTidMemory>(
        &self,
        memory: &mut M,
        context: &crate::kernel::KernelContext,
        generation: crate::kernel::objects::ExecutionGeneration,
        tid: ThreadId,
        tid_outputs: &threads::CloneTidOutputTransaction,
        logical: Option<PreparedHvpatchLogicalJob>,
        registry_installed: bool,
    ) {
        let completion = logical.as_ref().map(|logical| logical.completion.clone());
        // Dropping the logical job first retires its exact task backend/carrier
        // registration. No scheduler or Kernel row can be retired while a live
        // backend still has authority to mutate the child MM.
        drop(logical);
        let runtime = self.kernel.hvpatch_runtime.as_ref().unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::clone_rollback",
                "Missing parent execution context during clone publication rollback"
            )
        });
        let process = self.kernel.hvpatch_process.as_ref().unwrap_or_else(|| {
            carrick_fatal!(
                "kernel::runtime_binding",
                "Missing HVPatch runtime binding on KernelState during clone rollback"
            )
        });
        let scheduler = runtime.continuation_services(context.kernel()).0;
        executor::retire_failed_hvpatch_clone_authority(
            &scheduler,
            process.kernel_graph(),
            context,
            generation,
            |thread, generation| runtime.persistent_bindings().retire(thread, generation),
        )
        .map(|retirement| {
            // A child that settled terminally before the rollback reached it
            // is not a rollback failure. This used to abort the carrier: an
            // executor claimed the child's pre-activation generation, could
            // not resolve its binding, settled it
            // `Failed { SnapshotRestoreFailed }`, and this rollback then
            // found that Failed generation and killed every Linux process in
            // the carrier. The claim itself is now unrepresentable (the
            // thread's pre-publication reservation outlives the authority
            // this rollback drops), and the outcome of reaching this state by
            // any other route is a guest-visible clone failure, not a dead
            // carrier.
            if let executor::FailedCloneRetirement::AlreadySettled(state) = retirement {
                tracing::error!(
                    thread = ?context.thread().key(),
                    ?generation,
                    ?state,
                    "HVPatch clone rollback found its child already settled; failing the clone"
                );
            }
        })
        .unwrap_or_else(|error| {
            eprintln!("carrick: FATAL: authoritative HVPatch clone rollback: {error}");
            carrick_fatal!(
                "hvpatch::clone_rollback",
                "authoritative HVPatch clone rollback failed: {error}"
            );
        });
        if registry_installed {
            self.state.registry.exit(tid);
        }
        tid_outputs.rollback(memory).unwrap_or_else(|error| {
            eprintln!("carrick: FATAL: restore published HVPatch clone TID outputs: {error}");
            carrick_fatal!(
                "hvpatch::clone_rollback",
                "restore published HVPatch clone TID outputs failed: {error}"
            );
        });
        if let Some(completion) = completion {
            let id = completion.id();
            let _ = self.state.threads.take_by_id(id);
            // Completion is the final irrevocable publication. Every backend,
            // binding, scheduler, Kernel, registry, handle, and copyout owner
            // above is gone before a waiter can observe it.
            completion.publish();
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) fn spawn_persistent_hvpatch_clone_thread<M, O>(
        &mut self,
        memory: &mut M,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
        parent_context: &crate::kernel::KernelContext,
        request: HvpatchCloneThreadRequest,
        retry_prepared: Option<crate::kernel::PreparedThreadClone>,
        ops: &mut O,
    ) -> Result<PersistentHvpatchCloneAttempt, RuntimeError>
    where
        M: threads::CloneTidMemory + 'static,
        O: HvpatchCloneBackendOps<M>,
    {
        let HvpatchCloneThreadRequest {
            stack,
            tls,
            flags,
            parent_tid_addr,
            child_tid_addr,
            clear_child_tid_addr,
        } = request;

        let clone_permit = match self.kernel.enroll_thread_clone() {
            CloneEnrollment::Admitted(permit) => permit,
            CloneEnrollment::Deferred { observed_epoch } => {
                // A sibling's process fork has admission closed while it
                // publishes its child. Linux serializes the two; park until
                // that close lifts and enroll again, keeping any prepared
                // clone state for the retry.
                let scheduler = self
                    .kernel
                    .hvpatch_runtime
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("kernel::runtime_binding", "Missing HVPatch runtime reference when constructing the clone-admission deferral wake callback"))
                    .continuation_services(parent_context.kernel())
                    .0;
                let thread = parent_context.thread().key();
                let subscription = self.kernel.clone_admission.subscribe_change(
                    observed_epoch,
                    Arc::new(move || {
                        let _ = scheduler.wake(thread);
                    }),
                );
                tracing::debug!("thread clone deferred behind a sibling fork's admission close");
                return Ok(PersistentHvpatchCloneAttempt::Wait {
                    prepared: retry_prepared,
                    subscription: CloneRetrySubscription::Admission {
                        _subscription: subscription,
                    },
                });
            }
            CloneEnrollment::Refused => {
                // A guest-visible resource failure must never be silent: EAGAIN
                // from thread admission under NO real pressure has meant a leaked
                // permit/lease before, and the guest's own report ("failed to
                // spawn thread") cannot say which side refused.
                tracing::warn!("thread clone admission refused; clone(2) = EAGAIN");
                return Ok(PersistentHvpatchCloneAttempt::Complete(
                    threads::CloneThreadSpawn::Errno(crate::linux_abi::LINUX_EAGAIN),
                ));
            }
        };
        if self.kernel.process_exiting() || clone_permit.is_cancelled() {
            tracing::warn!(
                exiting = self.kernel.process_exiting(),
                "thread clone raced exec/exit cancellation; clone(2) = EAGAIN"
            );
            return Ok(PersistentHvpatchCloneAttempt::Complete(
                threads::CloneThreadSpawn::Errno(crate::linux_abi::LINUX_EAGAIN),
            ));
        }
        let plan = match crate::kernel::ClonePlan::from_flags(
            carrick_abi::LinuxCloneFlags::from_bits_retain(flags),
        ) {
            Ok(plan) => plan,
            Err(_) => {
                return Ok(PersistentHvpatchCloneAttempt::Complete(
                    threads::CloneThreadSpawn::Errno(crate::linux_abi::LINUX_EINVAL),
                ));
            }
        };
        let process = self.kernel.hvpatch_process.as_ref().ok_or_else(|| {
            RuntimeError::Configuration("persistent thread clone has no HVPatch process".to_owned())
        })?;
        let wait_for_change = |observed, prepared| {
            let runtime = self
                .kernel
                .hvpatch_runtime
                .as_ref()
                .unwrap_or_else(|| carrick_fatal!("hvpatch::task_backend_lifecycle", "Missing HVPatch runtime reference when constructing the reservation-change wake callback for a deferred thread clone"));
            let scheduler = runtime.continuation_services(parent_context.kernel()).0;
            let thread = parent_context.thread().key();
            let callback: Arc<dyn Fn() + Send + Sync + 'static> = Arc::new(move || {
                let _ = scheduler.wake(thread);
            });
            let subscription = process
                .kernel_graph()
                .subscribe_reservation_change(observed, callback);
            PersistentHvpatchCloneAttempt::Wait {
                prepared,
                subscription: CloneRetrySubscription::Reservation {
                    _subscription: subscription,
                },
            }
        };
        let prepared = if let Some(prepared) = retry_prepared {
            prepared
        } else {
            let observed = process.kernel_graph().reservation_epoch();
            let reservation =
                match process
                    .kernel_graph()
                    .reserve_thread_clone(parent_context, plan, None)
                {
                    Ok(reservation) => reservation,
                    Err(crate::kernel::KernelOperationError::TaskBusy(_)) => {
                        return Ok(wait_for_change(observed, None));
                    }
                    Err(error) => {
                        return Err(RuntimeError::Configuration(format!(
                            "reserve persistent HVPatch thread clone: {error}"
                        )));
                    }
                };
            let linux_tid = reservation.tid();
            let tid = ThreadId::from_guest_supplied_tid(linux_tid.raw());
            reservation.prepare(tid).map_err(|error| {
                RuntimeError::Configuration(format!(
                    "prepare persistent HVPatch thread clone: {error}"
                ))
            })?
        };
        let observed = process.kernel_graph().reservation_epoch();
        let prepared = match prepared.try_reserve_publication().map_err(|error| {
            RuntimeError::Configuration(format!(
                "reserve persistent HVPatch thread publication: {error}"
            ))
        })? {
            crate::kernel::ThreadPublicationReservationAttempt::Reserved(prepared) => prepared,
            crate::kernel::ThreadPublicationReservationAttempt::Busy(prepared) => {
                return Ok(wait_for_change(observed, Some(prepared)));
            }
        };
        let linux_tid = prepared.tid();
        let visible_tid = prepared.visible_tid();
        let tid = ThreadId::from_guest_supplied_tid(linux_tid.raw());
        let tid_outputs = match threads::CloneTidOutputTransaction::capture(
            memory,
            parent_tid_addr,
            child_tid_addr,
        ) {
            Ok(outputs) => outputs,
            Err(errno) => {
                return Ok(PersistentHvpatchCloneAttempt::Complete(
                    threads::CloneThreadSpawn::Errno(errno),
                ));
            }
        };
        let (task_key, thread_key, mm, expected_generation) =
            prepared.prepared_execution_identity();
        let mm_binding = process.mm_binding().ok_or_else(|| {
            RuntimeError::Configuration(
                "persistent HVPatch clone has no MM/ASID binding".to_owned(),
            )
        })?;
        let asid_generation = process.asid_generation();
        let carrier_identity = carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskIdentity {
            task_serial: task_key.serial.raw(),
            thread_serial: thread_key.serial.raw(),
            execution_generation: expected_generation.raw(),
            linux_pid: process.pid(),
            linux_tid: linux_tid.raw(),
            asid: mm_binding.asid.raw(),
        };
        let (prepared_backend, cpu) = ops.prepare(
            memory,
            carrier_identity,
            carrick_hal::GuestEntryRegs {
                return_value: 0,
                stack: Some(stack),
                tls,
            },
            mm.raw(),
            asid_generation,
        )?;
        if !tid_outputs.publish(memory, visible_tid, tid) {
            tid_outputs.rollback(memory).map_err(|error| {
                RuntimeError::Configuration(format!(
                    "restore failed HVPatch clone TID copyout: {error}"
                ))
            })?;
            ops.abort(prepared_backend)?;
            return Ok(PersistentHvpatchCloneAttempt::Complete(
                threads::CloneThreadSpawn::Errno(crate::linux_abi::LINUX_EFAULT),
            ));
        }
        if let Err(error) = check_hvpatch_clone_failpoint(HvpatchCloneFailpoint::TidCopyout) {
            tid_outputs.rollback(memory).map_err(|rollback| {
                RuntimeError::Configuration(format!(
                    "restore failpoint HVPatch clone TID outputs: {rollback}"
                ))
            })?;
            ops.abort(prepared_backend)?;
            return Err(error);
        }
        let published = match prepared.commit() {
            Ok(published) => published,
            Err(error) => {
                tid_outputs.rollback(memory).map_err(|rollback| {
                    RuntimeError::Configuration(format!(
                        "restore unpublished HVPatch clone TID outputs: {rollback}"
                    ))
                })?;
                ops.abort(prepared_backend)?;
                return Err(RuntimeError::Configuration(format!(
                    "publish persistent HVPatch thread: {error}"
                )));
            }
        };
        let child_context = published
            .context()
            .ok_or_else(|| {
                RuntimeError::Configuration(
                    "published HVPatch thread has no closed-gate context".to_owned(),
                )
            })?
            .retain_exact();
        let task_state = crate::kernel::objects::MigratableTaskState {
            cpu,
            mm,
            asid_generation,
        };
        // The gate must stand BEFORE the child is Kernel-runnable: from here
        // a producer can wake it, and its submission is not admitted for
        // another few hundred lines. See
        // `Scheduler::publish_initial_task_state_gated`.
        let publishing_scheduler = self
            .kernel
            .hvpatch_runtime
            .as_ref()
            .ok_or_else(|| {
                RuntimeError::Configuration(
                    "persistent HVPatch clone has no runtime directory".to_owned(),
                )
            })?
            .continuation_services(child_context.kernel())
            .0;
        let generation = match publishing_scheduler
            .publish_initial_task_state_gated(child_context.thread(), task_state.clone())
        {
            Ok(generation) if generation == expected_generation => generation,
            Ok(generation) => {
                ops.abort(prepared_backend).unwrap_or_else(|error| {
                    eprintln!("carrick: FATAL: abort generation-drifted clone backend: {error}");
                    carrick_fatal!(
                        "hvpatch::clone_lifecycle",
                        "abort generation-drifted clone backend failed: {error}"
                    );
                });
                let runtime = self.kernel.hvpatch_runtime.as_ref().unwrap_or_else(|| {
                    carrick_fatal!(
                        "kernel::runtime_binding",
                        "Missing HVPatch runtime binding during generation drift clone retirement"
                    )
                });
                let scheduler = runtime.continuation_services(child_context.kernel()).0;
                executor::retire_failed_hvpatch_clone_authority(
                    &scheduler,
                    process.kernel_graph(),
                    &child_context,
                    generation,
                    |_, _| {},
                )
                .map(|_| ())
                .unwrap_or_else(|error| {
                    eprintln!("carrick: FATAL: retire generation-drifted clone: {error}");
                    carrick_fatal!(
                        "hvpatch::clone_lifecycle",
                        "retire generation-drifted clone failed: {error}"
                    );
                });
                tid_outputs.rollback(memory).unwrap_or_else(|error| {
                    eprintln!("carrick: FATAL: restore generation-drifted clone TIDs: {error}");
                    carrick_fatal!(
                        "hvpatch::clone_lifecycle",
                        "restore generation-drifted clone TIDs failed: {error}"
                    );
                });
                return Err(RuntimeError::Configuration(
                    "persistent HVPatch child execution generation drifted".to_owned(),
                ));
            }
            Err(error) => {
                ops.abort(prepared_backend).unwrap_or_else(|abort| {
                    eprintln!("carrick: FATAL: abort unpublished clone backend: {abort}");
                    carrick_fatal!(
                        "hvpatch::clone_lifecycle",
                        "abort unpublished clone backend failed: {abort}"
                    );
                });
                process
                    .kernel_graph()
                    .exit_thread(&child_context, None)
                    .unwrap_or_else(|retire| {
                        eprintln!("carrick: FATAL: retire unpublished clone: {retire}");
                        carrick_fatal!(
                            "hvpatch::clone_lifecycle",
                            "retire unpublished clone failed: {retire}"
                        );
                    });
                tid_outputs.rollback(memory).unwrap_or_else(|rollback| {
                    eprintln!("carrick: FATAL: restore published clone TIDs: {rollback}");
                    carrick_fatal!(
                        "hvpatch::clone_lifecycle",
                        "restore published clone TIDs failed: {rollback}"
                    );
                });
                return Err(RuntimeError::Configuration(format!(
                    "publish persistent HVPatch child execution state: {error}"
                )));
            }
        };
        let runtime = self.kernel.hvpatch_runtime.as_ref().unwrap_or_else(|| {
            carrick_fatal!(
                "kernel::runtime_binding",
                "Missing HVPatch runtime binding when committing clone task backend"
            )
        });
        let mut task_backend = match ops.commit(
            prepared_backend,
            runtime.carrier_tasks(child_context.kernel()),
        ) {
            Ok(state) => state,
            Err(error) => {
                let scheduler = runtime.continuation_services(child_context.kernel()).0;
                executor::retire_failed_hvpatch_clone_authority(
                    &scheduler,
                    process.kernel_graph(),
                    &child_context,
                    generation,
                    |_, _| {},
                )
                .map(|_| ())
                .unwrap_or_else(|retire| {
                    eprintln!("carrick: FATAL: retire carrier-commit clone: {retire}");
                    carrick_fatal!(
                        "hvpatch::clone_lifecycle",
                        "retire carrier-commit clone failed: {retire}"
                    );
                });
                tid_outputs.rollback(memory).unwrap_or_else(|rollback| {
                    eprintln!("carrick: FATAL: restore carrier-commit clone TIDs: {rollback}");
                    carrick_fatal!(
                        "hvpatch::clone_lifecycle",
                        "restore carrier-commit clone TIDs failed: {rollback}"
                    );
                });
                return Err(error);
            }
        };
        if let Err(error) = check_hvpatch_clone_failpoint(HvpatchCloneFailpoint::BackendCommit) {
            drop(task_backend);
            self.rollback_published_hvpatch_clone(
                memory,
                &child_context,
                generation,
                tid,
                &tid_outputs,
                None,
                false,
            );
            return Err(error);
        }
        let cow_identity = carrick_hal::FrameCowIdentity {
            linux_pid: process.pid(),
            linux_tid: linux_tid.raw(),
            mm: mm.raw(),
            asid: mm_binding.asid.raw(),
        };
        let cow_authority = Arc::new(KernelFrameCowAuthority {
            deferred_anonymous: self.kernel.dispatcher.deferred_anonymous_state(mm),
            kernel: Arc::clone(child_context.kernel()),
            mm,
            owner_inventory: ops.frame_cow_owner_inventory(&task_backend),
            guest_executors: self.kernel.dispatcher.mm_executor_census(),
            tid,
            identity: cow_identity,
            pt_quiesce: self.kernel.dispatcher.pt_quiesce(),
        });
        let child_token = match Arc::clone(&cow_authority).issue_hvpatch_child_token(&child_context)
        {
            Ok(token) => token,
            Err(error) => {
                drop(task_backend);
                self.rollback_published_hvpatch_clone(
                    memory,
                    &child_context,
                    generation,
                    tid,
                    &tid_outputs,
                    None,
                    false,
                );
                return Err(RuntimeError::Configuration(error));
            }
        };
        if let Err(error) = ops.bind_child_kernel(&mut task_backend, child_token) {
            drop(task_backend);
            self.rollback_published_hvpatch_clone(
                memory,
                &child_context,
                generation,
                tid,
                &tid_outputs,
                None,
                false,
            );
            return Err(error);
        }
        if let Err(error) = check_hvpatch_clone_failpoint(HvpatchCloneFailpoint::TokenBind) {
            drop(task_backend);
            self.rollback_published_hvpatch_clone(
                memory,
                &child_context,
                generation,
                tid,
                &tid_outputs,
                None,
                false,
            );
            return Err(error);
        }
        if let Err(error) = ops.activate_child(&mut task_backend) {
            drop(task_backend);
            self.rollback_published_hvpatch_clone(
                memory,
                &child_context,
                generation,
                tid,
                &tid_outputs,
                None,
                false,
            );
            return Err(error);
        }

        let (execution_lease, injected_lease) = ExecutionLeaseCell::injected();
        let mut child_state = ThreadRuntimeState::<E>::new(
            Arc::clone(&self.state.registry),
            Arc::clone(&self.state.futex),
            Arc::clone(&self.state.platform_futex),
            Arc::clone(&self.state.platform_futex_factory),
            self.kernel.process_fork_barrier.clone(),
            self.kernel.crash_capture.clone(),
            Some(Arc::clone(child_context.thread())),
            Some(process.pid()),
            linux_tid,
            self.kernel.fatal_signal.current_generation(),
            tid,
            self.state.threads.clone(),
            Arc::clone(&self.state.kicker),
            carrick_hal::InGuestFlag::for_guest_thread(),
            self.state.max_traps,
        );
        child_state.execution_lease = execution_lease;
        child_state.service_kernel_context = Some(child_context.retain_exact());
        let child_syscall = self
            .state
            .syscall_completion
            .guest("clone child publication lost parent completion token")?
            .syscall();
        child_state.syscall_completion =
            SyscallCompletionOwnership::Guest(SyscallCompletionToken::new(
                child_syscall,
                child_context.retain_exact(),
                self.kernel.dispatcher.observers().cloned(),
            ));
        let mut logical = match prepare_hvpatch_logical_job(HvpatchLogicalJobInput {
            kernel: Arc::clone(&self.kernel),
            state: child_state,
            task_backend: ops.make_binding_state(task_backend),
            context: child_context.retain_exact(),
            cpu: task_state,
            generation,
            injected_lease,
            bootstrap_process_child: None,
            bootstrap_thread_child: true,
        }) {
            Ok(logical) => logical,
            Err(error) => {
                self.rollback_published_hvpatch_clone(
                    memory,
                    &child_context,
                    generation,
                    tid,
                    &tid_outputs,
                    None,
                    false,
                );
                return Err(RuntimeError::Trap(error));
            }
        };
        let (grant_thread, grant_generation) = match control.current_submission_key() {
            Ok(key) => key,
            Err(error) => {
                self.rollback_published_hvpatch_clone(
                    memory,
                    &child_context,
                    generation,
                    tid,
                    &tid_outputs,
                    Some(logical),
                    false,
                );
                return Err(RuntimeError::Trap(error));
            }
        };
        let dormant = match control.prepare_hvpatch_submission(
            runtime.persistent_bindings(),
            executor::HvpatchSubmissionShape::SameTaskSibling {
                grant: (grant_thread, grant_generation),
            },
            Arc::clone(child_context.thread()),
            generation,
            Arc::clone(&logical.binding),
        ) {
            Ok(dormant) => dormant,
            Err(error) => {
                self.rollback_published_hvpatch_clone(
                    memory,
                    &child_context,
                    generation,
                    tid,
                    &tid_outputs,
                    Some(logical),
                    false,
                );
                return Err(RuntimeError::Trap(error));
            }
        };
        self.state
            .registry
            .register_child_with_tid(tid, clear_child_tid_addr);
        enroll_persistent_process_member(&self.state.threads, &logical.terminal_settlement);
        if let Err(error) = check_hvpatch_clone_failpoint(HvpatchCloneFailpoint::RegistryHandle) {
            drop(dormant);
            self.rollback_published_hvpatch_clone(
                memory,
                &child_context,
                generation,
                tid,
                &tid_outputs,
                Some(logical),
                true,
            );
            return Err(error);
        }
        let started = match published.start_thread() {
            Ok(started) => started,
            Err(error) => {
                drop(dormant);
                self.rollback_published_hvpatch_clone(
                    memory,
                    &child_context,
                    generation,
                    tid,
                    &tid_outputs,
                    Some(logical),
                    true,
                );
                return Err(RuntimeError::Configuration(format!(
                    "open persistent HVPatch child start gate: {error}"
                )));
            }
        };
        let start_gate = match started
            .context()
            .thread()
            .take_opened_start_gate(generation)
        {
            Some(gate) => gate,
            None => {
                drop(dormant);
                self.rollback_published_hvpatch_clone(
                    memory,
                    &child_context,
                    generation,
                    tid,
                    &tid_outputs,
                    Some(logical),
                    true,
                );
                return Err(RuntimeError::Configuration(
                    "persistent HVPatch child lost opened start proof".to_owned(),
                ));
            }
        };
        if let Err(error) = logical.install_start_gate(start_gate) {
            drop(dormant);
            self.rollback_published_hvpatch_clone(
                memory,
                &child_context,
                generation,
                tid,
                &tid_outputs,
                Some(logical),
                true,
            );
            return Err(RuntimeError::Trap(error));
        }
        let proof = match logical.activation_proof() {
            Ok(proof) => proof,
            Err(error) => {
                drop(dormant);
                self.rollback_published_hvpatch_clone(
                    memory,
                    &child_context,
                    generation,
                    tid,
                    &tid_outputs,
                    Some(logical),
                    true,
                );
                return Err(RuntimeError::Trap(error));
            }
        };
        if let Err(error) = check_hvpatch_clone_failpoint(HvpatchCloneFailpoint::StartProof) {
            drop(dormant);
            self.rollback_published_hvpatch_clone(
                memory,
                &child_context,
                generation,
                tid,
                &tid_outputs,
                Some(logical),
                true,
            );
            return Err(error);
        }
        if let Err(error) = dormant.activate(
            &runtime.continuation_services(child_context.kernel()).0,
            Arc::clone(child_context.thread()),
            proof,
        ) {
            self.rollback_published_hvpatch_clone(
                memory,
                &child_context,
                generation,
                tid,
                &tid_outputs,
                Some(logical),
                true,
            );
            return Err(RuntimeError::Trap(error));
        }
        if let Err(error) = check_hvpatch_clone_failpoint(HvpatchCloneFailpoint::Activation) {
            self.rollback_published_hvpatch_clone(
                memory,
                &child_context,
                generation,
                tid,
                &tid_outputs,
                Some(logical),
                true,
            );
            return Err(error);
        }
        drop(clone_permit);
        Ok(PersistentHvpatchCloneAttempt::Complete(
            threads::CloneThreadSpawn::Started {
                internal: linux_tid,
                visible: visible_tid,
            },
        ))
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) fn complete_persistent_hvpatch_clone(
        &mut self,
        engine: &mut E,
        spawned: threads::CloneThreadSpawn,
    ) -> Result<executor::ExecutorExit, RuntimeError> {
        let (completed_internal_tid, completed_visible_tid, completed_errno) = match spawned {
            threads::CloneThreadSpawn::Started { internal, visible } => {
                self.state
                    .complete_returned(engine, &self.kernel.reporter, i64::from(visible))?;
                (internal.raw(), visible, 0)
            }
            threads::CloneThreadSpawn::Errno(errno) => {
                self.state.complete_returned(
                    engine,
                    &self.kernel.reporter,
                    errno.guest_retval(),
                )?;
                (
                    self.state.this_tid.raw(),
                    self.state.this_tid.raw(),
                    errno.get(),
                )
            }
        };
        crate::event_ring::rec(
            crate::event_ring::CLONESPAWN,
            self.state.this_tid.raw(),
            completed_internal_tid,
            completed_errno,
        );
        crate::probes::mn_clone_outcome(
            completed_visible_tid,
            carrick_observability::probes::HvpatchCloneThreadPhase::Completed,
            completed_errno,
        );
        Ok(executor::ExecutorExit::Syscall)
    }

    fn leave_executor(&mut self) {
        self.state.kicker.unregister(self.state.this_tid);
        drop(self.state.guest_execution.take());
    }

    fn finish(&mut self, outcome: Result<VcpuLoopOutcome, RuntimeError>) -> executor::ExecutorExit {
        self.leave_executor();
        if self.terminal_result.replace(outcome).is_some() {
            carrick_fatal!(
                "vcpu_loop::lifecycle",
                "Duplicate terminal outcome recorded on completed thread run loop"
            );
        }
        self.phase = HvpatchProductionPhase::Complete;
        executor::ExecutorExit::Exited
    }

    fn publish_terminal_result(&mut self) {
        if self.terminal_result.is_none() && !self.terminal_settlement.is_published() {
            self.state.trace_hvpatch_thread_terminal(
                carrick_observability::probes::HvpatchThreadTerminalReason::ExternallySettledWithoutResult,
                self.phase.probe_ordinal(),
            );
        }
        self.terminal_settlement
            .publish_terminal(self.terminal_result.take());
    }

    /// Publish the terminal result of a job that lost the process-exit claim.
    ///
    /// Such a job carries no outcome of its own: another thread of the same
    /// process owns the exit, so Linux terminated this thread. That is the same
    /// `ThreadDone` the owner's member drain publishes through
    /// `publish_member`, and publishing it here keeps the job's own settlement
    /// the sole owner of its publication instead of a member list this job may
    /// already have left.
    fn publish_lost_claim_terminal_result(&mut self) {
        if self.terminal_result.is_none() {
            self.terminal_result = Some(Ok(VcpuLoopOutcome::ThreadDone));
        }
        self.publish_terminal_result();
    }

    fn suspend(
        &mut self,
        suspension: HvpatchLoopSuspension,
        exit: executor::ExecutorExit,
    ) -> executor::ExecutorExit {
        self.leave_executor();
        match suspension {
            HvpatchLoopSuspension::BlockedContinuation | HvpatchLoopSuspension::VforkParent => {
                let is_stopped = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .is_some_and(|cx| cx.task().is_job_control_stopped());
                if is_stopped {
                    self.state
                        .publish_thread_run_state(crate::run_state::RunState::Blocked, 'T');
                } else {
                    self.state
                        .publish_thread_run_state(crate::run_state::RunState::Blocked, 'S');
                }
            }
            _ => {}
        }
        exit
    }

    fn publish_exec_replacement(
        &mut self,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> Result<bool, RuntimeError> {
        if let Some(replacement) = self.state.pending_exec_replacement.take() {
            control
                .publish_exec_replacement(replacement)
                .map_err(RuntimeError::Trap)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn finish_exec_suffix(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
        finished: exec::FinishedPreparedExecve,
    ) -> Result<executor::ExecutorExit, ProductionHvpatchPollError> {
        let (outcome, context, handoff) = finished.into_parts();
        let replaced = match self.publish_exec_replacement(control) {
            Ok(replaced) => replaced,
            Err(error) => {
                return Err(ProductionHvpatchPollError::from_exec_error(
                    error, context, handoff,
                ));
            }
        };
        let pending = PendingExecTerminal { context, handoff };
        if let Some(outcome) = outcome {
            return Ok(self.begin_persistent_process_terminal_from_exec(
                engine,
                PersistentTerminal::from_outcome(outcome),
                pending,
            ));
        }

        // Successful replacement is the only non-terminal path that may
        // reopen clone admission. Every fallible operation after the close,
        // including executor replacement publication, has completed first.
        drop(pending);
        Ok(if replaced {
            self.suspend(
                HvpatchLoopSuspension::Preemption,
                executor::ExecutorExit::Preempted,
            )
        } else {
            executor::ExecutorExit::Syscall
        })
    }

    pub(super) fn service_outcome(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
        frame: carrick_hal::RawSyscall,
        outcome: DispatchOutcome,
    ) -> Result<executor::ExecutorExit, ProductionHvpatchPollError> {
        if continuation::is_blocking_dispatch_outcome(&outcome) {
            let _ = self.state.stash_parked_registers(engine);
            let request = self
                .state
                .syscall_completion
                .guest("blocking syscall lost its prepared completion token")?
                .syscall()
                .request;
            let exit = self.state.persistent_block_exit(
                &self.kernel,
                control.execution_lease_mut().map_err(RuntimeError::Trap)?,
                request,
                HvpatchBlockInput::Dispatch(outcome),
            )?;
            self.phase = HvpatchProductionPhase::ResumeBlocked {
                frame,
                vfork_child_pid: None,
            };
            return Ok(self.suspend(HvpatchLoopSuspension::BlockedContinuation, exit));
        }

        Ok(match outcome {
            DispatchOutcome::Returned { value } => {
                self.state
                    .complete_returned(engine, &self.kernel.reporter, value)?;
                self.state.trace_syscall_return(self.traps, Some(value));
                // Self-directed signals (e.g. raise(SIGABRT)) posted during syscall handling must be serviced before returning to guest EL0, otherwise the thread resumes execution and runs subsequent instructions (like _exit(99)) before any asynchronous kick can arrive.
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during run-loop outcome servicing"))
                    .retain_exact();
                if let Some(outcome) = service_signals_threaded(
                    &self.kernel,
                    &context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    Some(value),
                    None,
                    self.state.continuation_restart.take(),
                    self.state.reserved_signal.take(),
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
                if let Some(exit) = self.suspend_for_job_control(engine, control)? {
                    return Ok(exit);
                }
                executor::ExecutorExit::Syscall
            }
            DispatchOutcome::Errno { errno } => {
                let value = self
                    .state
                    .complete_errno(engine, &self.kernel.reporter, errno)?;
                self.state.trace_syscall_return(self.traps, Some(value));
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during run-loop outcome servicing"))
                    .retain_exact();
                if let Some(outcome) = service_signals_threaded(
                    &self.kernel,
                    &context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    Some(value),
                    None,
                    self.state.continuation_restart.take(),
                    self.state.reserved_signal.take(),
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
                if let Some(exit) = self.suspend_for_job_control(engine, control)? {
                    return Ok(exit);
                }
                executor::ExecutorExit::Syscall
            }
            DispatchOutcome::SchedulerYield => {
                self.state
                    .complete_returned(engine, &self.kernel.reporter, 0)?;
                // Linux delivers pending signals on the return-to-user edge of
                // EVERY syscall — sched_yield included. This arm skipped the
                // service, so a thread looping on sched_yield NEVER took a
                // pending unblocked signal: musl's __synccall broadcast
                // (SIGSYNCCALL, rt signal 34) sat pending on a yield-storming
                // sibling forever and set*id hung for its full 45 s budget
                // (setidthreadchurn — kernel snapshot showed the pending
                // signal on a Running thread across ~200k yield quanta).
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during run-loop outcome servicing"))
                    .retain_exact();
                if let Some(outcome) = service_signals_threaded(
                    &self.kernel,
                    &context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    Some(0),
                    None,
                    self.state.continuation_restart.take(),
                    self.state.reserved_signal.take(),
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
                if let Some(exit) = self.suspend_for_job_control(engine, control)? {
                    return Ok(exit);
                }
                self.suspend(
                    HvpatchLoopSuspension::SchedulerYield,
                    executor::ExecutorExit::Yielded,
                )
            }
            DispatchOutcome::ThreadExit { code } => {
                self.state.retire_syscall()?;
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during run-loop outcome servicing"))
                    .retain_exact();
                let disposition = self.state.handle_persistent_thread_exit(
                    &self.kernel,
                    engine,
                    code,
                    self.traps,
                );
                self.settle_persistent_thread_exit(engine, code, context, disposition)
            }
            DispatchOutcome::Exit { code } => {
                self.state.retire_syscall()?;
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during run-loop outcome servicing"))
                    .retain_exact();
                let outcome = VcpuLoopOutcome::ProcessExit(Box::new(assemble_run_result(
                    &self.kernel,
                    code,
                    None,
                    self.traps,
                    false,
                )));
                self.begin_persistent_process_terminal(
                    engine,
                    PersistentTerminal::from_outcome(outcome),
                    context,
                )
            }
            DispatchOutcome::Execve { path, argv, env } => {
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .ok_or_else(|| {
                        RuntimeError::Configuration(
                            "persistent exec lost exact Kernel context".to_owned(),
                        )
                    })?
                    .retain_exact();
                let preparation = self.state.prepare_execve(
                    &self.kernel,
                    &context,
                    engine,
                    path,
                    argv,
                    env,
                    ExecCompletionOrigin::GuestSyscall,
                )?;
                match preparation {
                    exec::ExecvePreparation::Complete(Some(outcome)) => {
                        self.state.retire_syscall()?;
                        self.finish(Ok(outcome))
                    }
                    exec::ExecvePreparation::Complete(None) => executor::ExecutorExit::Syscall,
                    exec::ExecvePreparation::TerminalFailure(failure) => {
                        return Err(ProductionHvpatchPollError::from_exec_failure(failure));
                    }
                    exec::ExecvePreparation::Prepared(prepared) => {
                        let prepared = *prepared;
                        let owner = match self.state.begin_prepared_execve_drain(
                            &self.kernel,
                            self.completion.id(),
                            prepared,
                        ) {
                            Ok(owner) => owner,
                            Err(failure) => {
                                return Err(ProductionHvpatchPollError::from_exec_failure(failure));
                            }
                        };
                        if owner.is_ready() {
                            let finished = match self.state.finish_prepared_execve_drain(
                                &self.kernel,
                                engine,
                                &self.completion,
                                owner,
                            ) {
                                Ok(finished) => finished,
                                Err(failure) => {
                                    return Err(ProductionHvpatchPollError::from_exec_failure(
                                        failure,
                                    ));
                                }
                            };
                            return self.finish_exec_suffix(engine, control, finished);
                        }
                        self.phase = HvpatchProductionPhase::ExecSiblingDrain { context, owner };
                        self.suspend(
                            HvpatchLoopSuspension::ExecSiblingDrain,
                            executor::ExecutorExit::Blocked(
                                crate::kernel::objects::BlockedReason::ChildState,
                            ),
                        )
                    }
                }
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
            } if engine.supports_in_process_fork() => {
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .ok_or_else(|| {
                        RuntimeError::Configuration(
                            "persistent fork lost exact Kernel context".to_owned(),
                        )
                    })?
                    .retain_exact();
                let prepared = self.state.prepare_in_process_fork(
                    &self.kernel,
                    &context,
                    engine,
                    control,
                    &mut ProductionHvpatchProcessBackendOps,
                    quiesce::ProcessForkAttempt {
                        request: quiesce::ForkRequest {
                            flags,
                            pidfd_out,
                            clone_parent,
                            parent_tid_addr,
                            child_tid_addr,
                            exit_signal,
                            child_stack,
                            vfork,
                        },
                        coordinator: None,
                        external_exec: None,
                    },
                )?;
                return Ok(self.complete_persistent_process_fork(
                    engine,
                    control,
                    Some(frame),
                    None,
                    prepared,
                )?);
            }
            DispatchOutcome::CloneThread {
                stack,
                tls,
                flags,
                parent_tid_addr,
                child_tid_addr,
                clear_child_tid_addr,
            } => {
                #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                let spawned = {
                    let context = self
                        .state
                        .service_kernel_context
                        .as_ref()
                        .ok_or_else(|| {
                            RuntimeError::Configuration(
                                "persistent clone-thread lost exact Kernel context".to_owned(),
                            )
                        })?
                        .retain_exact();
                    let request = HvpatchCloneThreadRequest {
                        stack,
                        tls,
                        flags,
                        parent_tid_addr,
                        child_tid_addr,
                        clear_child_tid_addr,
                    };
                    match self.spawn_persistent_hvpatch_clone_thread(
                        engine,
                        control,
                        &context,
                        request,
                        None,
                        &mut ProductionHvpatchCloneBackendOps,
                    )? {
                        PersistentHvpatchCloneAttempt::Complete(spawned) => spawned,
                        PersistentHvpatchCloneAttempt::Wait {
                            prepared,
                            subscription,
                        } => {
                            self.phase = HvpatchProductionPhase::RetryCloneThread {
                                frame,
                                request,
                                prepared,
                                _subscription: subscription,
                            };
                            return Ok(self.suspend(
                                HvpatchLoopSuspension::BlockedContinuation,
                                executor::ExecutorExit::Blocked(
                                    crate::kernel::objects::BlockedReason::HostWait,
                                ),
                            ));
                        }
                    }
                };
                #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
                let spawned = threads::CloneThreadSpawn::Errno(crate::linux_abi::LINUX_EAGAIN);
                let (completed_internal_tid, completed_visible_tid, completed_errno) = match spawned
                {
                    threads::CloneThreadSpawn::Started { internal, visible } => {
                        self.state.complete_returned(
                            engine,
                            &self.kernel.reporter,
                            i64::from(visible),
                        )?;
                        (internal.raw(), visible, 0)
                    }
                    threads::CloneThreadSpawn::Errno(errno) => {
                        self.state.complete_returned(
                            engine,
                            &self.kernel.reporter,
                            errno.guest_retval(),
                        )?;
                        (
                            self.state.this_tid.raw(),
                            self.state.this_tid.raw(),
                            errno.get(),
                        )
                    }
                };
                crate::event_ring::rec(
                    crate::event_ring::CLONESPAWN,
                    self.state.this_tid.raw(),
                    completed_internal_tid,
                    completed_errno,
                );
                crate::probes::mn_clone_outcome(
                    completed_visible_tid,
                    carrick_observability::probes::HvpatchCloneThreadPhase::Completed,
                    completed_errno,
                );
                executor::ExecutorExit::Syscall
            }
            DispatchOutcome::SignalThread {
                tid,
                signum,
                kernel_target,
            } => {
                // `tkill`/`tgkill`/`pthread_kill` at a sibling thread. This
                // existed only in the welded loop; without it the outcome fell
                // through to the catch-all below, which returns `InvalidState`
                // and hangs the guest — `xthreadsig` timed out at
                // `SignalThread { signum: 10 }`.
                let value = self.state.complete_signal_thread(
                    &self.kernel,
                    engine,
                    tid,
                    signum,
                    kernel_target,
                )?;
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during run-loop outcome servicing"))
                    .retain_exact();
                if let Some(outcome) = service_signals_threaded(
                    &self.kernel,
                    &context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    Some(value),
                    None,
                    None,
                    None,
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
                executor::ExecutorExit::Syscall
            }
            DispatchOutcome::SetMemoryModel { tso } => {
                engine
                    .set_memory_model(hardware_tso_for_debug(tso))
                    .map_err(RuntimeError::Trap)?;
                let value = self
                    .state
                    .complete_returned(engine, &self.kernel.reporter, 0)?;
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during run-loop outcome servicing"))
                    .retain_exact();
                if let Some(outcome) = service_signals_threaded(
                    &self.kernel,
                    &context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    Some(value),
                    None,
                    None,
                    None,
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
                executor::ExecutorExit::Syscall
            }
            DispatchOutcome::SigReturn => {
                // `rt_sigreturn`. This existed only in the welded loop, so on the
                // persistent path it fell through to the unlowered-outcome arm —
                // invisible until forced-exit signal service started actually
                // delivering signals, at which point every guest that RETURNED
                // from a handler produced one of these.
                let restored_sigmask = match engine.restore_from_sigframe() {
                    Ok(mask) => mask,
                    // A guest-reachable bad `rt_sigreturn` frame (bad SP, or a
                    // corrupt/forged frame) is `force_sigsegv` on Linux: kill
                    // THIS process by SIGSEGV, never abort the carrier. Mirrors
                    // the unclassified-EL0-fault path.
                    Err(TrapError::SignalDeliveryFault) => {
                        self.state.retire_syscall()?;
                        let result = assemble_run_result(
                            &self.kernel,
                            128 + 11,
                            Some(crate::linux_abi::LINUX_SIGSEGV),
                            self.traps,
                            false,
                        );
                        return Ok(self.enter_terminal_with_outcome(
                            engine,
                            VcpuLoopOutcome::ProcessExit(Box::new(result)),
                        ));
                    }
                    Err(error) => return Err(RuntimeError::Trap(error).into()),
                };
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .ok_or_else(|| {
                        RuntimeError::Configuration(
                            "sigreturn lost its exact Kernel context".to_owned(),
                        )
                    })?
                    .retain_exact();
                self.kernel.dispatcher.restore_signal_mask(
                    &context,
                    self.state.this_tid,
                    carrick_abi::SigSet::from_raw(restored_sigmask),
                );
                self.state.retire_syscall()?;
                if let Some(outcome) = service_signals_threaded(
                    &self.kernel,
                    &context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    None,
                    None,
                    None,
                    None,
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
                // The guest resumes at the just-restored user PC. Do NOT complete
                // a syscall return here: `rt_sigreturn` has no return value, and
                // on x86 the frame restores RCX as an ordinary caller-clobbered
                // register that a syscall-boundary completion would mistake for
                // the resume address.
                executor::ExecutorExit::Syscall
            }
            DispatchOutcome::SharedFutexWake { target, count } => {
                let value =
                    shared_futex_wake(target.location.wait_addr().raw(), target.waiter_key, count);
                self.state
                    .complete_returned(engine, &self.kernel.reporter, value)?;
                self.state.trace_syscall_return(self.traps, Some(value));
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during run-loop outcome servicing"))
                    .retain_exact();
                if let Some(outcome) = service_signals_threaded(
                    &self.kernel,
                    &context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    Some(value),
                    None,
                    self.state.continuation_restart.take(),
                    self.state.reserved_signal.take(),
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
                if let Some(exit) = self.suspend_for_job_control(engine, control)? {
                    return Ok(exit);
                }
                executor::ExecutorExit::Syscall
            }
            DispatchOutcome::SharedFutexRequeue {
                from,
                to,
                wake,
                requeue,
            } => {
                trace_shared_futex_requeue(0, from.waiter_key, to.waiter_key, wake, requeue, 0, 0);
                let (carrier_woken, carrier_requeued) =
                    carrick_thread::platform_futex::carrier_shared_futex_table().requeue(
                        from.waiter_key as u64,
                        to.waiter_key as u64,
                        wake,
                        requeue,
                    );
                let (ulock_woken, ulock_requeued) = crate::ulock::requeue_counted(
                    from.location.wait_addr().raw(),
                    from.waiter_key,
                    to.location.wait_addr().raw(),
                    to.waiter_key,
                    wake,
                    requeue,
                );
                let woken = carrier_woken.max(ulock_woken);
                let requeued = carrier_requeued.max(ulock_requeued);
                trace_shared_futex_requeue(
                    1,
                    from.waiter_key,
                    to.waiter_key,
                    wake,
                    requeue,
                    woken,
                    requeued,
                );
                let value = i64::from(woken + requeued);
                self.state
                    .complete_returned(engine, &self.kernel.reporter, value)?;
                self.state.trace_syscall_return(self.traps, Some(value));
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during run-loop outcome servicing"))
                    .retain_exact();
                if let Some(outcome) = service_signals_threaded(
                    &self.kernel,
                    &context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    Some(value),
                    None,
                    self.state.continuation_restart.take(),
                    self.state.reserved_signal.take(),
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
                if let Some(exit) = self.suspend_for_job_control(engine, control)? {
                    return Ok(exit);
                }
                executor::ExecutorExit::Syscall
            }
            DispatchOutcome::SignalDeath { signum } => {
                self.state.retire_syscall()?;
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during run-loop outcome servicing"))
                    .retain_exact();
                self.kernel.record_fatal_signal(FatalSignalRecord {
                    image_generation: self.state.fatal_image_generation,
                    tid: context.thread().key().tid,
                    signo: signum,
                    code: 0,
                    addr: 0,
                });
                let outcome = VcpuLoopOutcome::ProcessExit(Box::new(assemble_run_result(
                    &self.kernel,
                    128 + signum,
                    Some(signum),
                    self.traps,
                    false,
                )));
                self.begin_persistent_process_terminal(
                    engine,
                    PersistentTerminal::from_outcome(outcome),
                    context,
                )
            }
            other => {
                tracing::error!(
                    ?other,
                    "persistent HVPatch loop reached an unlowered outcome"
                );
                executor::ExecutorExit::InvalidState
            }
        })
    }

    /// Route a terminal outcome produced outside `service_outcome` — a fault
    /// signal that killed the process, or a forced-exit signal service — into
    /// the persistent terminal, the same way the trap watchdog does.
    fn enter_terminal_with_outcome(
        &mut self,
        engine: &mut E,
        outcome: VcpuLoopOutcome,
    ) -> executor::ExecutorExit {
        let context = self
            .state
            .service_kernel_context
            .as_ref()
            .unwrap_or_else(|| {
                carrick_fatal!(
                    "vcpu_loop::service_context",
                    "ThreadRuntimeState missing service_kernel_context when entering terminal state"
                )
            })
            .retain_exact();
        self.begin_persistent_process_terminal(
            engine,
            PersistentTerminal::from_outcome(outcome),
            context,
        )
    }

    fn step_trap_watchdog<C, W>(&mut self, clock: C, max_wall: W) -> TrapWatchdog
    where
        C: FnOnce(&Instant) -> Duration,
        W: FnOnce() -> Duration,
    {
        let signal_progress = signal_progress_count();
        if signal_progress != self.seen_signal_progress {
            self.seen_signal_progress = signal_progress;
            self.budget_floor = self.traps;
            self.last_signal_progress = Instant::now();
        }
        let decision = trap_watchdog_decision(
            self.traps.saturating_sub(self.budget_floor),
            self.state.max_traps,
            || clock(&self.last_signal_progress),
            max_wall,
        );
        if decision == TrapWatchdog::ResetBudget {
            self.budget_floor = self.traps;
            self.last_signal_progress = Instant::now();
        }
        decision
    }

    pub(super) fn poll_with_engine(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> Result<executor::ExecutorExit, ProductionHvpatchPollError> {
        if self.terminal_settlement.is_published()
            || matches!(self.phase, HvpatchProductionPhase::Complete)
        {
            self.phase = HvpatchProductionPhase::Complete;
            return Ok(executor::ExecutorExit::Exited);
        }
        if self.state.guest_execution.is_none() {
            drop(self.registration_wait.take());
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            let pending_control_quantum = self.control_quantum()?.is_some();
            #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
            let pending_control_quantum = false;
            let registration_wake_mode =
                registration_wake_uses_control(&self.phase, pending_control_quantum);
            let context = self.state.service_kernel_context.as_ref().ok_or_else(|| {
                RuntimeError::Configuration(
                    "persistent registration admission lost exact Kernel context".to_owned(),
                )
            })?;
            let runtime = self.kernel.hvpatch_runtime.as_ref().ok_or_else(|| {
                RuntimeError::Configuration(
                    "persistent registration admission lost shared scheduler".to_owned(),
                )
            })?;
            let scheduler = runtime.continuation_services(context.kernel()).0;
            let wake_registration = registration_wake_callback(
                scheduler,
                context.thread().key(),
                registration_wake_mode,
            );
            let (participation, enrollment) = enter_mm_executor_then_register(
                &self.kernel.dispatcher,
                self.state.kernel_thread.as_ref().map(Arc::clone),
                Arc::clone(&self.state.kicker),
                self.state.this_tid,
                || {
                    self.state
                        .subscribe_register_vcpu(engine, wake_registration)
                },
            )
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
            self.state.guest_execution = Some(participation);
            match enrollment {
                carrick_hal::VcpuRegistrationEnrollment::Registered => {}
                carrick_hal::VcpuRegistrationEnrollment::Waiting { subscription, .. } => {
                    self.registration_wait = Some(subscription);
                    return Ok(self.suspend(
                        HvpatchLoopSuspension::InitialAdmission,
                        executor::ExecutorExit::Blocked(
                            crate::kernel::objects::BlockedReason::HostWait,
                        ),
                    ));
                }
            }
        }

        // Exec/exit can force a blocked vfork parent runnable solely so it can
        // retire its exact logical result. Do not resume the old continuation
        // or touch guest state after that terminal ownership transition.
        let exec_finish =
            thread_should_finish_for_exec_replacement(&self.state.registry, self.state.this_tid);
        if !self.phase.is_terminal_transition() && (self.kernel.process_exiting() || exec_finish) {
            self.state.trace_hvpatch_thread_terminal(
                carrick_observability::probes::HvpatchThreadTerminalReason::ExecRegistryGoneAtLoopTop,
                i32::from(self.kernel.process_exiting()),
            );
            match self
                .state
                .handle_persistent_thread_exit(&self.kernel, engine, 0, self.traps)
            {
                // The drain path always finishes ThreadDone: the terminal
                // owner or exec survivor owns the task's end, so a
                // registry-derived process-exit claim is discarded here
                // exactly as it always was.
                threads::PersistentThreadExitDisposition::Done(_) => {
                    return Ok(self.finish(Ok(VcpuLoopOutcome::ThreadDone)));
                }
                threads::PersistentThreadExitDisposition::Busy { observed_epoch } => {
                    // Ownership passed: on this drain path the thread is
                    // here BECAUSE an exec replacement or the process
                    // terminal is retiring it — the Busy holder is (or is
                    // superseded by) the very transaction that retires this
                    // thread's kernel row. Its own exit_thread is redundant,
                    // and parking for the holder STRANDS: the retirement
                    // makes every registry-addressed wake UnknownThread
                    // (measured live — parks at observed_epoch with three
                    // later publishes, final wake Err(UnknownThread), 10/12
                    // teardown hangs). Finish; the owner retires the row.
                    let _ = observed_epoch;
                    if !self.state.thread_exit_withdrawn {
                        let _ = self
                            .state
                            .withdraw_persistent_terminal_owner_runtime(&self.kernel, engine);
                        self.state.thread_exit_withdrawn = true;
                    }
                    return Ok(self.finish(Ok(VcpuLoopOutcome::ThreadDone)));
                }
            }
        }

        self.state
            .publish_thread_run_state(crate::run_state::RunState::Running, 'R');

        // A control exec is a peer-root operation, not completion of the
        // init's blocked syscall. Service it at this scheduler safe point
        // before ResumeBlocked consumes and re-parks the continuation. The
        // typed token survives a fork retry and restores the exact frame and
        // vfork identity after publication.
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        if let Some(quantum) = self.control_quantum()?
            && let Some(deferred_resume_blocked) =
                DeferredResumeBlocked::capture(&self.phase, quantum.blocked_reason)
        {
            if let Some(work) = self.kernel.try_take_control_exec() {
                return Ok(self.begin_control_exec_fork(
                    engine,
                    control,
                    work,
                    Some(deferred_resume_blocked),
                )?);
            }
            // Admission may have been cancelled before the owner claimed it.
            // Consume only the control edge and put the untouched continuation
            // back; never turn this into guest readiness.
            return Ok(self.finish_control_quantum(
                engine,
                control,
                Some(deferred_resume_blocked),
            )?);
        }

        let phase = std::mem::replace(&mut self.phase, HvpatchProductionPhase::Resident);
        match phase {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            HvpatchProductionPhase::BootstrapProcessChild(bootstrap) => {
                bootstrap_hvpatch_process_child(&self.kernel, &mut self.state, engine, bootstrap)?;
                if let Some(work) = self.kernel.take_external_exec_work() {
                    self.external_exec = Some(work);
                    return self.start_external_exec(engine, control);
                }
            }
            HvpatchProductionPhase::BootstrapThreadChild => {
                self.state
                    .complete_precompleted_child(&self.kernel.reporter, 0)?;
            }
            HvpatchProductionPhase::ResumeForkQuiesce { _subscription } => {
                drop(_subscription);
            }
            HvpatchProductionPhase::ResumeJobControlStop { _subscription } => {
                drop(_subscription);
                let context = match self.state.service_kernel_context.as_ref() {
                    Some(context) => context.retain_exact(),
                    None => self
                        .kernel
                        .dispatcher
                        .capture_kernel_context(self.state.linux_tid)
                        .map_err(|error| {
                            RuntimeError::Configuration(format!(
                                "resume from job control stop lost Kernel context: {error}"
                            ))
                        })?,
                };
                self.state.service_kernel_context = Some(context.retain_exact());
                if let Some(outcome) = service_signals_threaded(
                    &self.kernel,
                    &context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    None,
                    None,
                    None,
                    None,
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
            }
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            HvpatchProductionPhase::RetryProcessFork {
                frame,
                request,
                coordinator,
                external_exec,
                deferred_resume_blocked,
                _subscription,
            } => {
                drop(_subscription);
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .ok_or_else(|| {
                        RuntimeError::Configuration(
                            "persistent fork retry lost exact Kernel context".to_owned(),
                        )
                    })?
                    .retain_exact();
                let prepared = self.state.prepare_in_process_fork(
                    &self.kernel,
                    &context,
                    engine,
                    control,
                    &mut ProductionHvpatchProcessBackendOps,
                    quiesce::ProcessForkAttempt {
                        request,
                        coordinator,
                        external_exec,
                    },
                )?;
                return Ok(self.complete_persistent_process_fork(
                    engine,
                    control,
                    frame,
                    deferred_resume_blocked,
                    prepared,
                )?);
            }
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            HvpatchProductionPhase::RetryCloneThread {
                frame,
                request,
                prepared,
                _subscription,
            } => {
                drop(_subscription);
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .ok_or_else(|| {
                        RuntimeError::Configuration(
                            "persistent clone retry lost exact Kernel context".to_owned(),
                        )
                    })?
                    .retain_exact();
                return match self.spawn_persistent_hvpatch_clone_thread(
                    engine,
                    control,
                    &context,
                    request,
                    prepared,
                    &mut ProductionHvpatchCloneBackendOps,
                )? {
                    PersistentHvpatchCloneAttempt::Complete(spawned) => {
                        Ok(self.complete_persistent_hvpatch_clone(engine, spawned)?)
                    }
                    PersistentHvpatchCloneAttempt::Wait {
                        prepared,
                        subscription,
                    } => {
                        self.phase = HvpatchProductionPhase::RetryCloneThread {
                            frame,
                            request,
                            prepared,
                            _subscription: subscription,
                        };
                        Ok(self.suspend(
                            HvpatchLoopSuspension::BlockedContinuation,
                            executor::ExecutorExit::Blocked(
                                crate::kernel::objects::BlockedReason::HostWait,
                            ),
                        ))
                    }
                };
            }
            HvpatchProductionPhase::RetryThreadExit { code } => {
                // Drop the reservation subscription for this attempt; a
                // fresh one is installed if the retry parks again.
                self.state.thread_exit_retry_subscription = None;
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .ok_or_else(|| {
                        RuntimeError::Configuration(
                            "persistent thread-exit retry lost exact Kernel context".to_owned(),
                        )
                    })?
                    .retain_exact();
                let disposition = self.state.handle_persistent_thread_exit(
                    &self.kernel,
                    engine,
                    code,
                    self.traps,
                );
                return Ok(self.settle_persistent_thread_exit(engine, code, context, disposition));
            }
            HvpatchProductionPhase::ResumeBlocked {
                frame,
                vfork_child_pid,
            } => {
                let resumed = self.state.resume_persistent_continuation(
                    &self.kernel,
                    engine,
                    control.execution_lease_mut().map_err(RuntimeError::Trap)?,
                )?;
                if vfork_child_pid.is_some()
                    && matches!(&resumed, Some(DispatchOutcome::Returned { .. }))
                {
                    let parent_context =
                        self.state.service_kernel_context.as_ref().ok_or_else(|| {
                            RuntimeError::Configuration(
                                "vfork parent identity restore lost Kernel context".to_owned(),
                            )
                        })?;
                    stamp_identity_page(engine, &self.kernel.dispatcher, parent_context).map_err(
                        |error| {
                            RuntimeError::Trap(TrapError::Hypervisor(format!(
                                "restore vfork parent identity page: {error}"
                            )))
                        },
                    )?;
                }
                let outcome = match (vfork_child_pid, resumed) {
                    (Some(child_pid), Some(DispatchOutcome::Returned { .. })) => {
                        DispatchOutcome::Returned {
                            value: i64::from(child_pid),
                        }
                    }
                    (Some(_), Some(DispatchOutcome::ThreadExit { code })) => {
                        DispatchOutcome::ThreadExit { code }
                    }
                    (Some(_), _) => {
                        return Err(RuntimeError::Configuration(
                            "vfork parent resumed without release completion".to_owned(),
                        )
                        .into());
                    }
                    (None, Some(outcome)) => outcome,
                    (None, None) => self
                        .state
                        .redispatch_threaded_syscall(&self.kernel, engine)?,
                };
                if self.kernel.dispatcher.take_signal_pump_request() {
                    self.kernel
                        .signal_pump
                        .start_signal_pump(&self.state.kicker, &self.state.platform_futex);
                }
                return self.service_outcome(engine, control, frame, outcome);
            }
            HvpatchProductionPhase::ExecSiblingDrain { context, owner } => {
                if !owner.is_ready() {
                    self.phase = HvpatchProductionPhase::ExecSiblingDrain { context, owner };
                    return Ok(self.suspend(
                        HvpatchLoopSuspension::ExecSiblingDrain,
                        executor::ExecutorExit::Blocked(
                            crate::kernel::objects::BlockedReason::ChildState,
                        ),
                    ));
                }
                let finished = match self.state.finish_prepared_execve_drain(
                    &self.kernel,
                    engine,
                    &self.completion,
                    owner,
                ) {
                    Ok(finished) => finished,
                    Err(failure) => {
                        return Err(ProductionHvpatchPollError::from_exec_failure(failure));
                    }
                };
                return self.finish_exec_suffix(engine, control, finished);
            }
            HvpatchProductionPhase::TerminalProcessDrain {
                terminal,
                context,
                drain,
            } => {
                if !drain.is_ready() {
                    self.phase = HvpatchProductionPhase::TerminalProcessDrain {
                        terminal,
                        context,
                        drain,
                    };
                    return Ok(self.suspend(
                        HvpatchLoopSuspension::TerminalSiblingDrain,
                        executor::ExecutorExit::Blocked(
                            crate::kernel::objects::BlockedReason::ChildState,
                        ),
                    ));
                }
                let completions = self
                    .state
                    .finish_persistent_sibling_drain(&self.completion)?;
                self.kernel
                    .process_physical_retirement
                    .publish(completions)?;
                return Ok(self.finalize_persistent_process_terminal(engine, context, terminal));
            }
            HvpatchProductionPhase::TerminalClaimRetry {
                terminal,
                context,
                _subscription,
            } => {
                drop(_subscription);
                return Ok(self.begin_persistent_process_terminal(engine, terminal, context));
            }
            HvpatchProductionPhase::TerminalRetireRetry {
                terminal,
                context,
                _subscription,
            } => {
                drop(_subscription);
                return Ok(self.finalize_persistent_process_terminal(engine, context, terminal));
            }
            HvpatchProductionPhase::Resident => {}
            HvpatchProductionPhase::Complete => return Ok(executor::ExecutorExit::Exited),
        }

        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        if self.control_quantum()?.is_some() {
            if let Some(work) = self.kernel.try_take_control_exec() {
                return Ok(self.begin_control_exec_fork(engine, control, work, None)?);
            }
            return Ok(self.finish_control_quantum(engine, control, None)?);
        }

        if let Some(exit) = self.suspend_for_process_quiesce(engine, control)? {
            return Ok(exit);
        }

        if let Some(exit) = self.suspend_for_job_control(engine, control)? {
            return Ok(exit);
        }

        if control.need_resched() {
            return Ok(self.suspend(
                HvpatchLoopSuspension::Preemption,
                executor::ExecutorExit::Preempted,
            ));
        }
        match self.step_trap_watchdog(Instant::elapsed, trap_watchdog_wall_window) {
            TrapWatchdog::KeepRunning | TrapWatchdog::ResetBudget => {}
            TrapWatchdog::Trip => {
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context on trap limit outcome assembly"))
                    .retain_exact();
                let outcome = VcpuLoopOutcome::TrapLimit(Box::new(assemble_run_result(
                    &self.kernel,
                    -1,
                    None,
                    self.state.max_traps,
                    true,
                )));
                return Ok(self.begin_persistent_process_terminal(
                    engine,
                    PersistentTerminal::from_outcome(outcome),
                    context,
                ));
            }
        }
        self.traps = self.traps.saturating_add(1);
        let pt_quiesce = self.kernel.pt_quiesce();
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let entered_guest = quiesce::enter_hvpatch_guest_or_service_invalidation(
            &self.state.in_guest,
            &pt_quiesce,
            self.state.this_tid,
            engine,
            control,
        )?;
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        let entered_guest = quiesce::enter_guest_or_park(&self.state.in_guest, &pt_quiesce);
        if !entered_guest {
            return Ok(executor::ExecutorExit::Syscall);
        }
        self.state
            .publish_thread_run_state(crate::run_state::RunState::Running, 'R');
        if let Some(thread) = self.state.kernel_thread.as_ref() {
            thread.begin_guest_run();
        }
        let next = engine.next_syscall();
        if let Some(thread) = self.state.kernel_thread.as_ref() {
            thread.charge_user_ns(engine.take_guest_run_receipt_ns());
        }
        self.state.in_guest.leave_guest();
        // Every guest boundary that is NOT a syscall arrives here: a forced exit
        // with no pending syscall, a stage-1 COW fault, and — the one that
        // matters most — a synchronous EL0 fault. This handling used to live
        // ONLY in the welded `run_vcpu_until_exit_inner`, which
        // `launch_vcpu_until_exit` made unreachable at its first statement, so
        // the persistent executor turned every guest fault into a runtime error
        // and killed the process instead of delivering SIGSEGV/SIGBUS/SIGTRAP.
        // `ExecutorExit::Syscall` is this loop's "poll me again", i.e. the
        // welded loop's `continue`.
        let frame = match next {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                // The vCPU was forced out of the guest by a cross-thread kick
                // (hv_vcpus_exit) with no syscall pending — deliver a signal at
                // the interrupted PC, then resume.
                let pc = engine.current_pc()?;
                let signal_context = self
                    .kernel
                    .dispatcher
                    .capture_kernel_context(self.state.linux_tid)
                    .map_err(|error| {
                        RuntimeError::Configuration(format!(
                            "capture forced-exit signal context: {error}"
                        ))
                    })?;
                if let Some(outcome) = service_signals_threaded(
                    &self.kernel,
                    &signal_context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    None,
                    Some(pc),
                    None,
                    None,
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
                if let Some(exit) = self.suspend_for_process_quiesce(engine, control)? {
                    return Ok(exit);
                }
                if let Some(exit) = self.suspend_for_job_control(engine, control)? {
                    return Ok(exit);
                }
                return Ok(executor::ExecutorExit::Syscall);
            }
            Err(TrapError::Stage1CowFault {
                syndrome,
                far,
                elr,
                spsr,
            }) => {
                // The engine's single COW resolver emits the exact TTBR +
                // descriptor pair immediately before its typed trigger. Do not
                // duplicate that pair here: the structural consumer joins and
                // consumes one sequence per attempted fault.
                if let carrick_hal::CowFaultResolution::Resolved { translation } =
                    engine.resolve_frame_cow_fault(syndrome, far)?
                {
                    self.state.note_cow_resolution(far, syndrome, translation)?;
                    return Ok(executor::ExecutorExit::Syscall);
                }
                return Err(RuntimeError::Trap(TrapError::GuestAtEl1 {
                    esr_el1: syndrome,
                    elr_el1: elr,
                    far_el1: far,
                    spsr_el1: spsr,
                })
                .into());
            }
            Err(TrapError::EL0Fault {
                syndrome,
                elr,
                far,
                from_el0_direct,
                ..
            }) => {
                if let carrick_hal::CowFaultResolution::Resolved { translation } =
                    engine.resolve_frame_cow_fault(syndrome, far)?
                {
                    self.state.note_cow_resolution(far, syndrome, translation)?;
                    return Ok(executor::ExecutorExit::Syscall);
                }
                // The fault probes are load-bearing instruments, not debug
                // spam: `carrick trace` profiles and `scripts/dtrace/*.d` join
                // on them, and a probe that never fires reads as "the fault did
                // not happen". They were part of this handling before it was
                // ported off the welded loop and stay part of it.
                // Both probes take their arguments LAZILY: the instruction
                // fetch (a guest read, two heap allocations) and the register
                // reads run only when a D script is attached. This branch is
                // taken on every data abort, so eager decoding here was a
                // per-fault allocation on the happy path.
                crate::probes::vcpu_fault_regs_with(|| {
                    let instruction = engine
                        .read_bytes(elr, 4)
                        .ok()
                        .and_then(|bytes| bytes.try_into().ok())
                        .map(u32::from_le_bytes);
                    let (base_register, base_value) = instruction.map_or((u32::MAX, 0), |word| {
                        let index = (word >> 5) & 0x1f;
                        let value = (index < 31)
                            .then(|| engine.get_reg(carrick_hal::Reg::X(index)).ok())
                            .flatten()
                            .unwrap_or(0);
                        (index, value)
                    });
                    (
                        syndrome,
                        elr,
                        far,
                        instruction.map_or(u64::MAX, u64::from),
                        base_register,
                        base_value,
                    )
                });
                crate::probes::vcpu_fault_gprs_with(|| {
                    let x = |n: u32| engine.get_reg(carrick_hal::Reg::X(n)).unwrap_or(0);
                    (x(0), x(1), x(2), x(3), x(4), x(5))
                });
                // Same lazy-argument contract as the two probes above, and for
                // the same reason: the stage-1 walk is a `TTBR0_EL1` sysreg
                // read, a backend lookup for the table root and four
                // descriptor reads, and it was running on EVERY data abort to
                // feed two probes that are a no-op with no D script attached.
                crate::probes::pt_fault_with(far, || engine.diagnostic_fault_page_tables(far));
                if let Some(process) = self.kernel.hvpatch_process.as_ref() {
                    process.trace_fault(syndrome, elr, far, self.state.this_tid);
                }
                // A synchronous guest EL0 fault (nil deref, bad access, BRK,
                // single-step). Lower the raw aarch64 ESR to the ISA-neutral
                // (signum, si_code, fault_addr) triple — covering BOTH the abort
                // classes (SIGSEGV/SIGBUS) AND the debug classes (BRK /
                // single-step → SIGTRAP) — then deliver via the shared
                // GuestFault path. `from_el0_direct` selects whether the sigframe
                // records the faulting PC as the resume target.
                let Some((signum, si_code, si_addr)) = lower_el0_fault(syndrome, elr, far) else {
                    // Unclassified EL0 fault: Linux forces the default action
                    // (terminate by SIGSEGV).
                    self.kernel.record_fatal_signal(FatalSignalRecord {
                        image_generation: self.state.fatal_image_generation,
                        tid: self.state.linux_tid,
                        signo: crate::linux_abi::LINUX_SIGSEGV,
                        code: 0,
                        addr: far,
                    });
                    let result = assemble_run_result(
                        &self.kernel,
                        128 + 11,
                        Some(crate::linux_abi::LINUX_SIGSEGV),
                        self.traps,
                        false,
                    );
                    return Ok(self.enter_terminal_with_outcome(
                        engine,
                        VcpuLoopOutcome::ProcessExit(Box::new(result)),
                    ));
                };
                // Raw hardware/host faults can decode as MAPERR even when
                // Carrick tracks a live VMA denying the access. Upgrade from the
                // shared protection metadata (LTP mmap05 / roprotect probe).
                let si_code =
                    signal::upgrade_protection_si_code(&*engine, signum, si_code, si_addr);
                let interrupted_pc = from_el0_direct.then_some(elr);
                let faulting_tid = self.state.linux_tid;
                if self.kernel.dispatcher.fault_requires_mm_mutation(si_addr)
                    && self
                        .state
                        .with_mm_mutation_authority(&self.kernel, |mutation| {
                            signal::resolve_mutating_fault(
                                &self.kernel.dispatcher,
                                engine,
                                si_addr,
                                signal::el0_fault_access(syndrome),
                                faulting_tid,
                                mutation,
                            )
                        })?
                        .map_err(RuntimeError::Trap)?
                {
                    return Ok(executor::ExecutorExit::Syscall);
                }
                // Captured only now: a first touch resolved above never
                // delivers a signal, and this capture is an `RwLock` read plus
                // a kernel-graph snapshot that only `deliver_fault_signal`
                // consumes. Hoisting it out of the resolved path takes it off
                // the hot arm of every anonymous first-touch fault.
                let fault_context = self
                    .kernel
                    .dispatcher
                    .capture_kernel_context(self.state.linux_tid)
                    .map_err(|error| {
                        RuntimeError::Configuration(format!(
                            "capture synchronous-fault signal context: {error}"
                        ))
                    })?;
                if let Some(outcome) = deliver_fault_signal(
                    &self.kernel,
                    &fault_context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    signum,
                    si_code,
                    si_addr,
                    interrupted_pc,
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
                return Ok(executor::ExecutorExit::Syscall);
            }
            Err(TrapError::GuestFault {
                signum,
                si_code,
                fault_addr,
            }) => {
                // The ISA-neutral structured fault path: an x86 backend emits
                // this directly (fault_addr = CR2). The backend restores the
                // interrupted user context before surfacing the fault, so the
                // live PC is the faulting instruction.
                let si_code =
                    signal::upgrade_protection_si_code(&*engine, signum, si_code, fault_addr);
                let interrupted_pc = Some(engine.current_pc()?);
                let faulting_tid = self.state.linux_tid;
                if self
                    .kernel
                    .dispatcher
                    .fault_requires_mm_mutation(fault_addr)
                    && self
                        .state
                        .with_mm_mutation_authority(&self.kernel, |mutation| {
                            // The ISA-neutral triple carries no syndrome, so
                            // the access class is unknown here: a stale fault
                            // on this arm is delivered rather than retried.
                            signal::resolve_mutating_fault(
                                &self.kernel.dispatcher,
                                engine,
                                fault_addr,
                                None,
                                faulting_tid,
                                mutation,
                            )
                        })?
                        .map_err(RuntimeError::Trap)?
                {
                    return Ok(executor::ExecutorExit::Syscall);
                }
                // Same hoist as the aarch64 arm above: only the delivered
                // path needs the captured kernel context.
                let fault_context = self
                    .kernel
                    .dispatcher
                    .capture_kernel_context(self.state.linux_tid)
                    .map_err(|error| {
                        RuntimeError::Configuration(format!(
                            "capture guest-fault signal context: {error}"
                        ))
                    })?;
                if let Some(outcome) = deliver_fault_signal(
                    &self.kernel,
                    &fault_context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    signum,
                    si_code,
                    fault_addr,
                    interrupted_pc,
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
                return Ok(executor::ExecutorExit::Syscall);
            }
            Err(error) => return Err(RuntimeError::Trap(error).into()),
        };
        self.state.trace_syscall(self.traps, frame);
        let outcome = self
            .state
            .service_threaded_syscall(&self.kernel, engine, frame)?;
        if self.kernel.dispatcher.take_signal_pump_request() {
            self.kernel
                .signal_pump
                .start_signal_pump(&self.state.kicker, &self.state.platform_futex);
        }
        self.service_outcome(engine, control, frame, outcome)
    }

    fn poll_with_engine_typed(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> Result<executor::ExecutorExit, ProductionHvpatchPollError> {
        let _current_mm =
            carrick_thread::fork_quiesce::bind_current_mm_quiesce(self.kernel.pt_quiesce());
        match self.poll_with_engine(engine, control) {
            Err(ProductionHvpatchPollError::Runtime(error)) => {
                match self.take_pending_exec_terminal() {
                    Some(pending) => Err(ProductionHvpatchPollError::Exec(Box::new(
                        PendingExecTerminalError { error, pending },
                    ))),
                    None => Err(ProductionHvpatchPollError::Runtime(error)),
                }
            }
            result => result,
        }
    }

    /// Extract a suspended exec's exact context and terminal authority without
    /// reopening clone admission. This is the sole error-boundary extraction
    /// for failures before the main phase dispatch (control lookup,
    /// exact-context recovery, or vCPU/MM re-admission).
    fn take_pending_exec_terminal(&mut self) -> Option<PendingExecTerminal> {
        let phase = std::mem::replace(&mut self.phase, HvpatchProductionPhase::Resident);
        match phase {
            HvpatchProductionPhase::ExecSiblingDrain { context, owner } => {
                let (terminal_context, handoff) = owner.into_terminal_authority();
                drop(context);
                Some(PendingExecTerminal {
                    context: terminal_context,
                    handoff,
                })
            }
            other => {
                self.phase = other;
                None
            }
        }
    }
}

impl<E: ThreadedEngine + 'static> ProductionHvpatchLoopPoll for ProductionHvpatchLoopJob<E>
where
    E::SiblingSpec: 'static,
{
    fn pt_quiesce(&self) -> Arc<crate::fork_quiesce::PtQuiesce> {
        self.kernel.pt_quiesce()
    }

    fn poll(
        &mut self,
        engine: &mut dyn std::any::Any,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> executor::ExecutorExit {
        let Some(engine) = engine.downcast_mut::<E>() else {
            return executor::ExecutorExit::InvalidState;
        };
        match self.poll_with_engine_typed(engine, control) {
            Ok(exit) => exit,
            Err(ProductionHvpatchPollError::Exec(pending)) => {
                let PendingExecTerminalError { error, pending } = *pending;
                self.begin_persistent_process_terminal_from_exec(
                    engine,
                    PersistentTerminal::Error(error),
                    pending,
                )
            }
            Err(ProductionHvpatchPollError::Runtime(error)) => {
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context on engine error terminal transition"))
                    .retain_exact();
                self.begin_persistent_process_terminal(
                    engine,
                    PersistentTerminal::Error(error),
                    context,
                )
            }
        }
    }

    fn after_terminal_settlement(&mut self) {
        self.publish_terminal_result();
    }

    fn after_reaped_settlement(&mut self) {
        // Same publication the lost-process-exit-claim path makes, for the
        // same reason: this thread is terminated and carries no outcome of its
        // own, so the `ThreadDone` its owner's member drain would have
        // published is published from the settlement that owns it. Without
        // this the job's `HvpatchLoopResult` was never filled and its
        // container process job waited on it forever (`go_types`).
        self.publish_lost_claim_terminal_result();
    }

    fn after_executor_failure_settlement(&mut self) -> continuation::ExecutorFailureSettlement {
        if self.terminal_settlement.is_published() {
            return continuation::ExecutorFailureSettlement::AlreadyPublished;
        }
        if self.terminal_result.is_some() {
            self.publish_terminal_result();
            return continuation::ExecutorFailureSettlement::PublishCurrent;
        }

        let receipt = match self.take_pending_exec_terminal() {
            Some(PendingExecTerminal { context, handoff }) => {
                let receipt = handoff.claim_process_exit().unwrap_or_else(|failure| {
                    tracing::error!(%failure, "claim unexpected executor-failure exec handoff");
                    carrick_fatal!(
                        "hvpatch::exec_terminal",
                        "claim unexpected executor-failure exec handoff failed: {failure}"
                    );
                });
                self.state.service_kernel_context = Some(context.retain_exact());
                self.state.kernel_thread = Some(Arc::clone(context.thread()));
                if receipt.claim == ProcessExitClaim::Owner {
                    self.kernel.begin_process_exit();
                }
                receipt
            }
            None => self
                .kernel
                .try_claim_persistent_process_exit(self.state.this_tid)
                .unwrap_or_else(|failure| {
                    tracing::error!(%failure, "claim unexpected executor-failure process exit");
                    carrick_fatal!(
                        "kernel::terminal_settlement",
                        "claim unexpected executor-failure process exit failed: {failure}"
                    );
                }),
        };
        match receipt.claim {
            ProcessExitClaim::LostToExec | ProcessExitClaim::AlreadyOwned => {
                // Losing the claim used to defer publication to the process
                // terminal owner. That owner only ever publishes the members
                // its drain snapshot holds, and an `execve` survivor is removed
                // from the member list by `finish_persistent_process_handles`
                // and never re-enrolled -- so a lost-claim survivor's result was
                // published by nobody. Its container process job then waited on
                // an `HvpatchLoopResult` forever, with every Kernel task retired
                // and every executor idle (the `go build` / `go_types` exit
                // wedge). The outcome is not in doubt here: another thread owns
                // the process exit, so Linux has terminated this one, which is
                // exactly the `ThreadDone` the owner's member drain would have
                // published. Publish it from the settlement that owns it.
                self.publish_lost_claim_terminal_result();
                return continuation::ExecutorFailureSettlement::PublishCurrent;
            }
            ProcessExitClaim::Owner | ProcessExitClaim::Pending => {}
        }

        if receipt.claim == ProcessExitClaim::Pending {
            // The failed worker cannot block on a clone permit held by another
            // executor. Arm the fail-closed root wait first, stop every known
            // sibling, then let a failure-only coordinator publish the exact
            // member snapshot after clone admission reaches zero.
            self.kernel.begin_process_exit();
        }
        let sibling_stop = self
            .state
            .persistent_sibling_stop_authority()
            .unwrap_or_else(|failure| {
                tracing::error!(%failure, "retain unexpected executor-failure sibling stop");
                carrick_fatal!(
                    "kernel::terminal_settlement",
                    "retain unexpected executor-failure sibling stop failed: {failure}"
                );
            });
        sibling_stop
            .publish(&self.kernel)
            .unwrap_or_else(|failure| {
                tracing::error!(%failure, "stop siblings after unexpected executor failure");
                carrick_fatal!(
                    "kernel::terminal_settlement",
                    "stop siblings after unexpected executor failure failed: {failure}"
                );
            });

        if receipt.claim == ProcessExitClaim::Owner {
            publish_unexpected_executor_failure_retirement(
                &self.kernel,
                &self.state.threads,
                &self.completion,
            )
            .unwrap_or_else(|failure| {
                tracing::error!(%failure, "publish unexpected executor-failure retirement");
                carrick_fatal!(
                    "kernel::terminal_settlement",
                    "publish unexpected executor-failure retirement failed: {failure}"
                );
            });
        } else {
            let kernel = Arc::clone(&self.kernel);
            let threads = self.state.threads.clone();
            let current = self.completion.clone();
            let owner = self.state.this_tid;
            if let Err(failure) = std::thread::Builder::new()
                .name("carrick-exit-failure-drain".to_owned())
                .spawn(move || {
                    if let Err(failure) = kernel
                        .clone_admission
                        .wait_for_claimed_process_exit_clone_drain(
                            owner,
                            PHYSICAL_JOB_RETIREMENT_TIMEOUT,
                        )
                        .and_then(|()| sibling_stop.publish(&kernel))
                        .and_then(|()| {
                            publish_unexpected_executor_failure_retirement(
                                &kernel, &threads, &current,
                            )
                        })
                    {
                        // `begin_process_exit` already armed the root's bounded
                        // publication wait. Leaving the receipt absent is the
                        // fail-closed outcome; never synthesize an incomplete
                        // member list after a clone-drain failure.
                        tracing::error!(%failure, "unexpected executor-failure retirement coordinator failed");
                    }
                })
            {
                tracing::error!(%failure, "spawn unexpected executor-failure retirement coordinator");
            }
        }

        self.publish_terminal_result();
        continuation::ExecutorFailureSettlement::PublishCurrent
    }

    fn take_address_space_retirement(
        &mut self,
    ) -> Option<crate::hvpatch::PendingAddressSpaceRetirement> {
        self.pending_terminal_retirement.take()
    }

    fn apply_detached_address_space_retirement(
        &mut self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), TrapError> {
        let (kernel, mm) = self.take_terminal_inventory_authority()?;
        kernel
            .frame_inventory()
            .apply(mm, commit)
            .map(|_| ())
            .map_err(|error| {
                TrapError::Hypervisor(format!(
                    "publish detached terminal inventory retirement: {error}"
                ))
            })
    }

    /// The same publication, but returning the authenticated receipt a published
    /// `HvpatchTaskMmAuthority` needs to leave its `Active` phase.
    fn apply_detached_address_space_retirement_with_receipt(
        &mut self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<carrick_hal::FrameInventoryRetirementReceipt, TrapError> {
        let (kernel, mm) = self.take_terminal_inventory_authority()?;
        kernel
            .frame_inventory()
            .apply_retirement_with_receipt(mm, commit)
            .map(|(_, receipt)| receipt)
            .map_err(|error| {
                TrapError::Hypervisor(format!(
                    "publish detached terminal inventory retirement receipt: {error}"
                ))
            })
    }
}

/// Engine-free logical state for the HVPatch vCPU loop.  The backend engine is
/// lent to `poll_quantum_with_engine` by its persistent owner pthread and is
/// never stored here.  Production logical/runtime fields are moved into this
/// object as the seven async suspension arms are lowered to the typed states
/// above.
pub(crate) struct HvpatchLoopJob<E> {
    suspended: Option<HvpatchLoopSuspension>,
    injected_lease: Option<Arc<InjectedExecutionLeaseSlot>>,
    production: Option<Box<dyn ProductionHvpatchLoopPoll>>,
    poller: fn(
        &mut HvpatchLoopJob<E>,
        &mut E,
        &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> executor::ExecutorExit,
    #[cfg(test)]
    scripted: std::collections::VecDeque<HvpatchLoopSuspension>,
    #[cfg(test)]
    resumed: Vec<HvpatchLoopSuspension>,
    _marker: std::marker::PhantomData<fn(&mut E)>,
}

#[cfg(test)]
pub(crate) trait ScriptedHvpatchLoopEngine {
    fn record_injected_resume(&mut self, resumed: &[HvpatchLoopSuspension]);
}

#[cfg(test)]
impl<E: ScriptedHvpatchLoopEngine> HvpatchLoopJob<E> {
    pub(super) fn scripted_for_test(
        boundaries: impl IntoIterator<Item = HvpatchLoopSuspension>,
    ) -> Self {
        Self {
            suspended: None,
            injected_lease: None,
            production: None,
            poller: Self::poll_scripted_for_test,
            scripted: boundaries.into_iter().collect(),
            resumed: Vec::new(),
            _marker: std::marker::PhantomData,
        }
    }

    fn poll_scripted_for_test(
        job: &mut Self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> executor::ExecutorExit {
        let need_resched = control.need_resched();
        match job.poll_quantum_with_engine(engine, need_resched) {
            HvpatchLoopPoll::Suspended(HvpatchLoopSuspension::BlockedContinuation) => {
                executor::ExecutorExit::Blocked(crate::kernel::objects::BlockedReason::HostWait)
            }
            HvpatchLoopPoll::Suspended(HvpatchLoopSuspension::SchedulerYield) => {
                executor::ExecutorExit::Yielded
            }
            HvpatchLoopPoll::Suspended(HvpatchLoopSuspension::Preemption) => {
                executor::ExecutorExit::Preempted
            }
            HvpatchLoopPoll::Suspended(
                HvpatchLoopSuspension::ExecSiblingDrain
                | HvpatchLoopSuspension::VforkParent
                | HvpatchLoopSuspension::TerminalSiblingDrain,
            ) => executor::ExecutorExit::Blocked(crate::kernel::objects::BlockedReason::ChildState),
            HvpatchLoopPoll::Suspended(HvpatchLoopSuspension::InitialAdmission) => {
                executor::ExecutorExit::Quiesced
            }
            HvpatchLoopPoll::Exited => executor::ExecutorExit::Exited,
        }
    }

    pub(super) fn poll_quantum_with_engine(
        &mut self,
        engine: &mut E,
        _need_resched: bool,
    ) -> HvpatchLoopPoll {
        let Some(boundary) = self.scripted.pop_front() else {
            self.suspended = None;
            engine.record_injected_resume(&self.resumed);
            return HvpatchLoopPoll::Exited;
        };
        self.resumed.push(boundary);
        engine.record_injected_resume(&self.resumed);
        self.suspended = Some(boundary);
        HvpatchLoopPoll::Suspended(boundary)
    }

    pub(super) const fn suspended_at(&self) -> Option<HvpatchLoopSuspension> {
        self.suspended
    }
}

impl<E: 'static> HvpatchLoopJob<E> {
    pub(crate) fn production(
        job: ProductionHvpatchLoopJob<E>,
        injected_lease: Arc<InjectedExecutionLeaseSlot>,
    ) -> Self
    where
        E: ThreadedEngine,
        E::SiblingSpec: 'static,
    {
        Self {
            suspended: Some(HvpatchLoopSuspension::InitialAdmission),
            injected_lease: Some(injected_lease),
            production: Some(Box::new(job)),
            poller: Self::poll_production,
            #[cfg(test)]
            scripted: std::collections::VecDeque::new(),
            #[cfg(test)]
            resumed: Vec::new(),
            _marker: std::marker::PhantomData,
        }
    }

    fn poll_production(
        job: &mut Self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> executor::ExecutorExit {
        let Some(production) = job.production.as_mut() else {
            return executor::ExecutorExit::InvalidState;
        };
        let _current_mm =
            carrick_thread::fork_quiesce::bind_current_mm_quiesce(production.pt_quiesce());
        let exit = production.poll(engine, control);
        job.suspended = match exit {
            executor::ExecutorExit::BlockedContinuation { .. }
            | executor::ExecutorExit::Blocked(crate::kernel::objects::BlockedReason::HostWait) => {
                Some(HvpatchLoopSuspension::BlockedContinuation)
            }
            executor::ExecutorExit::Blocked(crate::kernel::objects::BlockedReason::ChildState) => {
                match job.suspended {
                    Some(HvpatchLoopSuspension::ExecSiblingDrain) => {
                        Some(HvpatchLoopSuspension::ExecSiblingDrain)
                    }
                    Some(HvpatchLoopSuspension::VforkParent) => {
                        Some(HvpatchLoopSuspension::VforkParent)
                    }
                    _ => Some(HvpatchLoopSuspension::TerminalSiblingDrain),
                }
            }
            executor::ExecutorExit::Yielded => Some(HvpatchLoopSuspension::SchedulerYield),
            executor::ExecutorExit::Preempted => Some(HvpatchLoopSuspension::Preemption),
            executor::ExecutorExit::Exited | executor::ExecutorExit::InvalidState => None,
            _ => None,
        };
        exit
    }
}

impl<E: 'static> continuation::PersistentQuantumJob for HvpatchLoopJob<E> {
    fn poll_quantum_with_engine(
        &mut self,
        engine: &mut dyn std::any::Any,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> executor::ExecutorExit {
        let Some(engine) = engine.downcast_mut::<E>() else {
            return executor::ExecutorExit::InvalidState;
        };
        let lease_slot = control.execution_lease_slot_mut() as *mut _;
        let injected_lease = self.injected_lease.clone();
        let _lease_publication = injected_lease.as_ref().map(|slot| slot.install(lease_slot));
        (self.poller)(self, engine, control)
    }

    fn after_terminal_settlement(&mut self) {
        if let Some(production) = self.production.as_mut() {
            production.after_terminal_settlement();
        }
    }

    fn after_reaped_settlement(&mut self) {
        if let Some(production) = self.production.as_mut() {
            production.after_reaped_settlement();
        }
    }

    fn after_executor_failure_settlement(&mut self) -> continuation::ExecutorFailureSettlement {
        match self.production.as_mut() {
            Some(production) => production.after_executor_failure_settlement(),
            None => continuation::ExecutorFailureSettlement::PublishCurrent,
        }
    }

    fn take_address_space_retirement(
        &mut self,
    ) -> Option<crate::hvpatch::PendingAddressSpaceRetirement> {
        self.production
            .as_mut()
            .and_then(|production| production.take_address_space_retirement())
    }

    fn apply_detached_address_space_retirement(
        &mut self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), TrapError> {
        self.production
            .as_mut()
            .ok_or_else(|| {
                TrapError::Hypervisor(
                    "scripted HVPatch job has no detached address-space authority".to_owned(),
                )
            })?
            .apply_detached_address_space_retirement(commit)
    }

    fn apply_detached_address_space_retirement_with_receipt(
        &mut self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<carrick_hal::FrameInventoryRetirementReceipt, TrapError> {
        self.production
            .as_mut()
            .ok_or_else(|| {
                TrapError::Hypervisor(
                    "scripted HVPatch job has no detached address-space authority".to_owned(),
                )
            })?
            .apply_detached_address_space_retirement_with_receipt(commit)
    }
}

/// RAII-timed completion record for Linux syscalls multiplexed inside the
/// one-VM hvpatch host process. Keeping publication in `Drop` covers every
/// returned, blocking, fork/exec, exit, and error path that unwinds normally,
/// without changing control flow. A terminal `_exit` cannot run destructors and
/// is intentionally absent from the completed population.
pub(crate) struct HvpatchSyscallServiceGuard {
    pid: i32,
    tid: i32,
    asid: u32,
    number: u64,
    started: std::time::Instant,
}

impl HvpatchSyscallServiceGuard {
    pub(crate) fn begin(
        pid: i32,
        tid: i32,
        asid: u32,
        number: u64,
        args: [u64; 6],
    ) -> Option<Self> {
        // The wrapper materializes the clock only inside the USDT enabled
        // closure. With no consumer this returns `None`, preserving the probe
        // surface's predicted-not-taken-branch cost contract.
        let event =
            carrick_observability::probes::HvpatchSyscallService::new(pid, tid, asid, number, 0)
                .ok()?;
        let started = crate::probes::hvpatch_syscall_service_begin(event, args)?;
        Some(Self {
            pid,
            tid,
            asid,
            number,
            started,
        })
    }
}

impl Drop for HvpatchSyscallServiceGuard {
    fn drop(&mut self) {
        use carrick_observability::probes::HvpatchSyscallService;

        let duration_ns = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        if let Ok(event) =
            HvpatchSyscallService::new(self.pid, self.tid, self.asid, self.number, duration_ns)
        {
            crate::probes::hvpatch_syscall_service(event);
            crate::probes::hvpatch_syscall_service_clear(event);
        }
    }
}

/// Wall-clock budget for the trap watchdog: a guest that keeps trapping but makes
/// NO signal-handler progress for this long is treated as genuinely wedged. The
/// default (30s) is comfortably above any legitimate syscall-bound burst (e.g. a
/// 10s SIGALRM-bounded `gettimeofday` loop) yet below the conformance harness's
/// outer per-run timeout (~40s), so a real wedge aborts cleanly here rather than
/// via the harness SIGKILL. Override with `CARRICK_MAX_WALL_MS`.
pub(crate) fn trap_watchdog_wall_window() -> std::time::Duration {
    // Read once: this sits on the watchdog checkpoint that every trap
    // quantum passes through, and a `getenv` per checkpoint was measurable
    // (0.6% of the arena-churn profile) for a value that never changes.
    static WINDOW: std::sync::OnceLock<std::time::Duration> = std::sync::OnceLock::new();
    *WINDOW.get_or_init(|| {
        let ms = std::env::var("CARRICK_MAX_WALL_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(30_000);
        std::time::Duration::from_millis(ms)
    })
}

/// One progress-aware trap-watchdog checkpoint decision.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TrapWatchdog {
    /// Under the count pre-filter — keep running (the cheap hot-path case).
    KeepRunning,
    /// Over the count pre-filter, but the guest made wall-clock progress within
    /// `max_wall` (a syscall-bound-but-progressing loop) — reset the count budget
    /// and keep running, do NOT abort.
    ResetBudget,
    /// Over the count pre-filter AND no signal-handler progress for `max_wall`
    /// (a genuine wedge) — abort the vCPU loop.
    Trip,
}

pub(crate) enum VcpuLoopLaunch {
    Direct(Result<VcpuLoopOutcome, RuntimeError>),
    Persistent {
        result: HvpatchLoopResult,
        completion: continuation::LogicalJobCompletion,
        process_retirement: ProcessPhysicalRetirement,
        /// The always-on runner invariant, carried so the CONTAINER ROOT's own
        /// wait is supervised too. The exit wedge parked here as readily as in
        /// `ContainerJobGroup::join`: this is the main thread's wait for the
        /// root process job, and an unsupervised wait here would leave the
        /// wedge in place for exactly the run every other lane goes through.
        liveness: ProcessGraphLiveness,
    },
}

impl VcpuLoopLaunch {
    pub(crate) fn is_persistent(&self) -> bool {
        matches!(self, Self::Persistent { .. })
    }

    /// Wait for this container root's main-thread job. Carrier-global pool
    /// shutdown belongs exclusively to the carrier terminal finalizer.
    pub(crate) fn wait(self) -> Result<VcpuLoopOutcome, RuntimeError> {
        match self {
            Self::Direct(result) => result,
            Self::Persistent {
                result,
                completion,
                process_retirement,
                liveness,
            } => {
                let outcome = result.wait_supervised(&liveness);
                // An aborted kernel's executor bindings are not going to
                // retire: the abort exists precisely because the graph will
                // not progress, and its guest threads are still loaded. Waiting
                // for retirement here reported "logical HVPatch job N published
                // before its executor binding retired" and MASKED the abort,
                // turning the one answer the caller needs into a generic
                // carrier failure.
                if matches!(outcome, Err(RuntimeError::KernelAborted { .. })) {
                    return outcome;
                }
                wait_for_physical_job_retirement(&completion)?;
                match &outcome {
                    Ok(_) => process_retirement.wait()?,
                    Err(_) => process_retirement.wait_if_exit_started_or_published()?,
                }
                tracing::info!(
                    outcome = match &outcome {
                        Ok(VcpuLoopOutcome::ProcessExit(_)) => "process-exit",
                        Ok(VcpuLoopOutcome::ThreadDone) => "thread-done",
                        Ok(_) => "other-ok",
                        Err(_) => "error",
                    },
                    "HVPatch root launch wait returned"
                );
                outcome
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct PreparedHvpatchLogicalJob {
    pub(crate) binding: Arc<continuation::HvpatchTaskBinding>,
    pub(crate) result: HvpatchLoopResult,
    pub(crate) completion: continuation::LogicalJobCompletion,
    pub(crate) process_retirement: ProcessPhysicalRetirement,
    pub(crate) terminal_settlement: HvpatchExternalTerminalSettlement,
    pub(crate) context: crate::kernel::KernelContext,
    pub(crate) cpu: crate::kernel::objects::MigratableTaskState,
    pub(crate) generation: crate::kernel::objects::ExecutionGeneration,
    pub(crate) start_gate: Option<crate::kernel::objects::OpenedStartGate>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PreparedHvpatchLogicalJob {
    pub(crate) fn install_start_gate(
        &mut self,
        start_gate: crate::kernel::objects::OpenedStartGate,
    ) -> Result<(), TrapError> {
        if self.start_gate.replace(start_gate).is_some() {
            return Err(TrapError::Hypervisor(
                "HVPatch logical job received duplicate start-gate proof".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn activation_proof(
        &mut self,
    ) -> Result<executor::HvpatchActivationProof, TrapError> {
        let start_gate = self.start_gate.take().ok_or_else(|| {
            TrapError::Hypervisor("HVPatch start-gate proof was already consumed".to_owned())
        })?;
        executor::HvpatchActivationProof::validate(
            &self.context,
            &self.cpu,
            self.generation,
            self.binding.identity(),
            start_gate,
        )
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct HvpatchLogicalJobInput<E: ThreadedEngine> {
    pub(crate) kernel: Kernel,
    pub(crate) state: ThreadRuntimeState<E>,
    pub(crate) task_backend: executor::HvpatchTaskEngineBindingState,
    pub(crate) context: crate::kernel::KernelContext,
    pub(crate) cpu: crate::kernel::objects::MigratableTaskState,
    pub(crate) generation: crate::kernel::objects::ExecutionGeneration,
    pub(crate) injected_lease: Arc<InjectedExecutionLeaseSlot>,
    pub(crate) bootstrap_process_child: Option<ProcessChildBootstrap>,
    pub(crate) bootstrap_thread_child: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn prepare_hvpatch_logical_job<E: ThreadedEngine + 'static>(
    input: HvpatchLogicalJobInput<E>,
) -> Result<PreparedHvpatchLogicalJob, TrapError>
where
    E::SiblingSpec: 'static,
{
    let HvpatchLogicalJobInput {
        kernel,
        state,
        task_backend,
        context,
        cpu,
        generation,
        injected_lease,
        bootstrap_process_child,
        bootstrap_thread_child,
    } = input;
    if context.thread().key()
        != state
            .kernel_thread
            .as_ref()
            .ok_or_else(|| {
                TrapError::Hypervisor("prepared HVPatch job has no exact Kernel thread".to_owned())
            })?
            .key()
        || context.shared().mm().id() != cpu.mm
    {
        return Err(TrapError::Hypervisor(
            "prepared HVPatch logical job rejected Kernel/CPU/MM identity".to_owned(),
        ));
    }
    let result = HvpatchLoopResult::pending();
    let completion = continuation::LogicalJobCompletion::pending();
    let terminal_settlement =
        HvpatchExternalTerminalSettlement::new(result.clone(), completion.clone());
    let process_retirement = kernel.process_physical_retirement.clone();
    let identity = executor::TaskLoadIdentity {
        abi: cpu.cpu.guest_abi(),
        version: cpu.cpu.version(),
        mm: cpu.mm,
        asid_generation: cpu.asid_generation,
    };
    let process = kernel
        .hvpatch_process
        .as_ref()
        .ok_or_else(|| TrapError::Hypervisor("HVPatch logical job has no process MM".to_owned()))?;
    let stage1_mm = process
        .stage1_mm_lease()
        .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
    let production = ProductionHvpatchLoopJob {
        kernel,
        state,
        phase: if bootstrap_thread_child {
            HvpatchProductionPhase::BootstrapThreadChild
        } else {
            bootstrap_process_child.map_or(
                HvpatchProductionPhase::Resident,
                HvpatchProductionPhase::BootstrapProcessChild,
            )
        },
        registration_wait: None,
        terminal_settlement: terminal_settlement.clone(),
        terminal_result: None,
        completion: completion.clone(),
        traps: 0,
        budget_floor: 0,
        seen_signal_progress: signal_progress_count(),
        last_signal_progress: Instant::now(),
        terminal_runtime: PersistentTerminalRuntimeState::Resident,
        pending_terminal_retirement: None,
        pending_terminal_inventory: None,
        external_exec: None,
    };
    let job = HvpatchLoopJob::production(production, injected_lease);
    let quantum = Arc::new(continuation::HvpatchTaskQuantum::new(
        Box::new(job),
        completion.clone(),
    ));
    let binding = Arc::new(continuation::HvpatchTaskBinding::new_with_stage1_mm(
        identity,
        quantum,
        Box::new(task_backend),
        stage1_mm,
    )?);
    Ok(PreparedHvpatchLogicalJob {
        binding,
        result,
        completion,
        process_retirement,
        terminal_settlement,
        context: context.retain_exact(),
        cpu,
        generation,
        start_gate: None,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn launch_persistent_hvpatch_job<E: ThreadedEngine + 'static>(
    kernel: Kernel,
    mut engine: E,
    registry: Arc<ThreadRegistry>,
    futex: Arc<FutexTable>,
    platform_futex: Arc<dyn PlatformFutex>,
    platform_futex_factory: PlatformFutexFactory,
    linux_tid: crate::kernel::LinuxTid,
    this_tid: ThreadId,
    threads: impl Into<VcpuThreadRegistry>,
    kicker: Arc<dyn VcpuRegistry>,
    in_guest: carrick_hal::InGuestFlag,
    max_traps: usize,
) -> VcpuLoopLaunch
where
    E::SiblingSpec: 'static,
{
    let threads = threads.into();
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        let _ = (
            kernel,
            engine,
            registry,
            futex,
            platform_futex,
            platform_futex_factory,
            linux_tid,
            this_tid,
            threads,
            kicker,
            in_guest,
            max_traps,
        );
        return VcpuLoopLaunch::Direct(Err(RuntimeError::Configuration(
            "HVPatch persistent executors require macOS/aarch64 HVF".to_owned(),
        )));
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        type HvfEngine = carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Engine;

        let mut prepared = match prepare_initial_runner_handoff(
            &kernel,
            &mut engine,
            &kicker,
            linux_tid,
            this_tid,
        ) {
            Ok(prepared) => prepared,
            Err(error) => return VcpuLoopLaunch::Direct(Err(error)),
        };
        let prepared_task = prepared.task.take().unwrap_or_else(|| {
            carrick_fatal!(
                "vcpu_loop::job_launch",
                "Prepared persistent job missing task context during job launch"
            )
        });
        let context = prepared_task.context;
        let exact_cpu = prepared_task.cpu;
        let start_gate = prepared_task.start_gate;
        let thread = Arc::clone(context.thread());

        // Initial-runner park has stopped/destroyed its vCPU. Only now may the
        // factory take the four owning carrier mappings: every failure below
        // can drop them without unmapping stage-2 under a live bootstrap vCPU.
        let authority = match (&mut engine as &mut dyn std::any::Any).downcast_mut::<HvfEngine>() {
            Some(engine) => {
                match carrick_vmm_hvf::hvf_aarch64_engine::persistent_executor_factory_authority(
                    engine,
                ) {
                    Ok(authority) => authority,
                    Err(error) => {
                        prepared.fail_exact();
                        return VcpuLoopLaunch::Direct(Err(RuntimeError::Trap(error)));
                    }
                }
            }
            None => {
                prepared.fail_exact();
                return VcpuLoopLaunch::Direct(Err(RuntimeError::Configuration(
                    "HVPatch launch rejected a non-HVF engine".to_owned(),
                )));
            }
        };

        let boxed: Box<dyn std::any::Any> = Box::new(engine);
        let hvf_engine = match boxed.downcast::<HvfEngine>() {
            Ok(engine) => *engine,
            Err(_) => {
                prepared.fail_exact();
                return VcpuLoopLaunch::Direct(Err(RuntimeError::Configuration(
                    "HVPatch engine changed type during persistent handoff".to_owned(),
                )));
            }
        };
        let (task_backend, parked_vcpu) =
            carrick_vmm_hvf::hvf_aarch64_engine::split_initial_task_engine(hvf_engine);
        drop(parked_vcpu);

        let (execution_lease, injected_lease) = ExecutionLeaseCell::injected();
        let process_members = threads.clone();
        let mut state = ThreadRuntimeState::<HvfEngine>::new(
            registry,
            futex,
            platform_futex,
            platform_futex_factory,
            kernel.process_fork_barrier.clone(),
            kernel.crash_capture.clone(),
            Some(Arc::clone(&thread)),
            kernel.hvpatch_process.as_ref().map(|process| process.pid()),
            linux_tid,
            kernel.fatal_signal.current_generation(),
            this_tid,
            threads,
            kicker,
            in_guest,
            max_traps,
        );
        state.execution_lease = execution_lease;
        state.service_kernel_context = Some(context.retain_exact());

        let mut logical = match prepare_hvpatch_logical_job(HvpatchLogicalJobInput {
            kernel: Arc::clone(&kernel),
            state,
            task_backend: executor::HvpatchTaskEngineBindingState::initial(task_backend),
            context,
            cpu: exact_cpu,
            generation: prepared.generation,
            injected_lease,
            bootstrap_process_child: None,
            bootstrap_thread_child: false,
        }) {
            Ok(logical) => logical,
            Err(error) => {
                prepared.fail_exact();
                return VcpuLoopLaunch::Direct(Err(RuntimeError::Trap(error)));
            }
        };
        if let Err(error) = logical.install_start_gate(start_gate) {
            prepared.fail_exact();
            return VcpuLoopLaunch::Direct(Err(RuntimeError::Trap(error)));
        }
        let directory = kernel.hvpatch_runtime.as_ref().unwrap_or_else(|| {
            carrick_fatal!(
                "kernel::runtime_binding",
                "KernelState missing HVPatch runtime reference during persistent job launch"
            )
        });
        let dormant = match directory.persistent_bindings().prepare_submission(
            &prepared.scheduler,
            executor::HvpatchSubmissionShape::Root,
            None,
            Arc::clone(&thread),
            prepared.generation,
            Arc::clone(&logical.binding),
        ) {
            Ok(dormant) => dormant,
            Err(error) => {
                prepared.fail_exact();
                return VcpuLoopLaunch::Direct(Err(RuntimeError::Trap(error)));
            }
        };
        let proof = match logical.activation_proof() {
            Ok(proof) => proof,
            Err(error) => {
                drop(dormant);
                prepared.fail_exact();
                return VcpuLoopLaunch::Direct(Err(RuntimeError::Trap(error)));
            }
        };
        let member_publication =
            PersistentProcessMemberPublication::new(process_members, &logical.terminal_settlement);
        let started_pool = match directory.start_persistent_pool(
            authority,
            <HvfEngine as ThreadedEngine>::vcpu_budget(),
            &PreparedPersistentServices {
                scheduler: Arc::clone(&prepared.scheduler),
                wait_service: Arc::clone(&prepared.wait_service),
            },
        ) {
            Ok(started) => started,
            Err(error) => {
                drop(dormant);
                prepared.fail_exact();
                return VcpuLoopLaunch::Direct(Err(error));
            }
        };
        if let Err(error) = dormant.activate(&prepared.scheduler, Arc::clone(&thread), proof) {
            // The job was never exposed. Remove its process-local drain handle
            // before closing a newly-created pool, or shutdown would wait on a
            // completion no scheduler row can ever publish.
            drop(member_publication);
            prepared.fail_exact();
            if started_pool && let Err(shutdown) = directory.shutdown_persistent_pool() {
                return VcpuLoopLaunch::Direct(Err(RuntimeError::Configuration(format!(
                    "HVPatch root activation failed: {error}; newly started pool rollback failed: {shutdown}"
                ))));
            }
            return VcpuLoopLaunch::Direct(Err(RuntimeError::Trap(error)));
        }
        member_publication.commit();
        prepared.disarm();
        VcpuLoopLaunch::Persistent {
            result: logical.result,
            completion: logical.completion,
            process_retirement: logical.process_retirement,
            liveness: directory.process_graph_liveness(),
        }
    }
}

pub(crate) struct PreparedInitialRunnerTask {
    context: crate::kernel::KernelContext,
    cpu: crate::kernel::objects::MigratableTaskState,
    start_gate: crate::kernel::objects::OpenedStartGate,
}

pub(crate) struct PreparedInitialHandoff {
    task: Option<PreparedInitialRunnerTask>,
    scheduler: Arc<crate::kernel::Scheduler>,
    wait_service: Arc<continuation::CarrierWaitService>,
    thread: crate::kernel::ThreadRef,
    generation: crate::kernel::objects::ExecutionGeneration,
    armed: bool,
}

impl PreparedInitialHandoff {
    fn fail_exact(&mut self) {
        if !self.armed {
            return;
        }
        let _ = self.scheduler.fail_runnable_exact(
            self.thread.key(),
            self.generation,
            crate::kernel::objects::ExecutionFailure::SnapshotSaveFailed,
        );
        self.armed = false;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PreparedInitialHandoff {
    fn drop(&mut self) {
        self.fail_exact();
    }
}

pub(crate) fn prepare_initial_runner_handoff<E: ThreadedEngine + 'static>(
    kernel: &Kernel,
    engine: &mut E,
    kicker: &Arc<dyn VcpuRegistry>,
    linux_tid: crate::kernel::LinuxTid,
    this_tid: ThreadId,
) -> Result<PreparedInitialHandoff, RuntimeError> {
    let context = kernel
        .dispatcher
        .capture_kernel_context(linux_tid)
        .map_err(|error| {
            RuntimeError::Configuration(format!("capture initial runner task authority: {error}"))
        })?;
    let mm = context.shared().mm().id();
    let asid_generation = kernel
        .hvpatch_process
        .as_ref()
        .map_or(mm.raw(), crate::hvpatch::ProcessContext::asid_generation);
    engine.bind_task_snapshot_identity(mm.raw(), asid_generation);
    if let Some(process) = kernel.hvpatch_process.as_ref() {
        let owner_inventory = engine.frame_cow_owner_inventory().ok_or_else(|| {
            RuntimeError::Configuration(
                "HVPatch initial runner has no carrier host-owner inventory".to_owned(),
            )
        })?;
        let binding = process.mm_binding().ok_or_else(|| {
            RuntimeError::Configuration("HVPatch initial runner task has no ASID".to_owned())
        })?;
        engine.bind_frame_cow(
            Arc::new(KernelFrameCowAuthority {
                deferred_anonymous: kernel.dispatcher.deferred_anonymous_state(mm),
                kernel: Arc::clone(context.kernel()),
                mm,
                owner_inventory,
                guest_executors: kernel.dispatcher.mm_executor_census(),
                tid: this_tid,
                identity: carrick_hal::FrameCowIdentity {
                    linux_pid: process.pid(),
                    linux_tid: this_tid.raw(),
                    mm: mm.raw(),
                    asid: binding.asid.raw(),
                },
                pt_quiesce: kernel.dispatcher.pt_quiesce(),
            }),
            carrick_hal::FrameCowIdentity {
                linux_pid: process.pid(),
                linux_tid: this_tid.raw(),
                mm: mm.raw(),
                asid: binding.asid.raw(),
            },
        );
    }
    if !kernel.dispatcher.bind_deferred_anonymous_state(engine, mm) {
        return Err(RuntimeError::Configuration(
            "initial runner anonymous authority MM mismatch".to_owned(),
        ));
    }
    let directory = kernel.hvpatch_runtime.as_ref().ok_or_else(|| {
        RuntimeError::Configuration("initial runner task has no runtime directory".to_owned())
    })?;
    let services = directory.prepare_persistent_services(context.kernel());
    let scheduler = Arc::clone(&services.scheduler);
    let cpu = engine
        .save_initial_runner_state()
        .map_err(RuntimeError::Trap)?;
    let state = crate::kernel::objects::MigratableTaskState {
        cpu,
        mm,
        asid_generation,
    };
    let retained_cpu = state.clone();
    // Gated for the same reason the clone child is: the initial runner is
    // Kernel-runnable here, and its submission is admitted later.
    let generation = scheduler
        .publish_initial_task_state_gated(context.thread(), state)
        .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
    let start_gate = context
        .thread()
        .take_opened_start_gate(generation)
        .ok_or_else(|| {
            RuntimeError::Configuration(
                "initial HVPatch runner has no exact opened Kernel start gate".to_owned(),
            )
        })?;
    let thread = Arc::clone(context.thread());
    let prepared = PreparedInitialHandoff {
        task: Some(PreparedInitialRunnerTask {
            context,
            cpu: retained_cpu,
            start_gate,
        }),
        scheduler,
        wait_service: services.wait_service,
        thread,
        generation,
        armed: true,
    };
    kicker.unregister(this_tid);
    if let Some(lease) = carrick_hal::vcpu_sched::take_current_lease() {
        carrick_hal::vcpu_sched::global().release(lease, carrick_hal::Yield::Blocked);
    }
    engine
        .audit_executor_boundary()
        .map_err(RuntimeError::Trap)?;
    Ok(prepared)
}

/// Decide what the progress-aware trap watchdog should do at one checkpoint.
///
/// The watchdog trips on a WALL-TIME stall, not on raw syscall count:
/// `traps_since_signal` exceeding `max_traps` is only a cheap pre-filter (it
/// gates the comparatively expensive wall-clock read at the call site). Once the
/// pre-filter fires, the guest is aborted only if there has ALSO been no
/// delivered-signal progress for `elapsed >= max_wall`; otherwise the count
/// budget is reset and the guest keeps running. Pure so the trip / no-trip
/// boundaries are unit-testable without a live vCPU.
fn trap_watchdog_decision<E, W>(
    traps_since_signal: usize,
    max_traps: usize,
    elapsed: E,
    max_wall: W,
) -> TrapWatchdog
where
    E: FnOnce() -> std::time::Duration,
    W: FnOnce() -> std::time::Duration,
{
    if traps_since_signal <= max_traps {
        TrapWatchdog::KeepRunning
    } else if elapsed() >= max_wall() {
        TrapWatchdog::Trip
    } else {
        TrapWatchdog::ResetBudget
    }
}

#[cfg(test)]
pub(crate) fn write_hvpatch_child_output(fd: i32, mut bytes: &[u8]) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written > 0 {
            bytes = &bytes[written as usize..];
            continue;
        }
        if written == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "host output descriptor made no progress",
            ));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;
    use super::*;
    use carrick_guest_mem::GuestMemory;
    use std::num::NonZeroU64;
    use std::time::{Duration, Instant};

    #[test]
    fn guest_run_accounting_uses_non_aliasing_engine_receipts() {
        let source = include_str!("binding.rs");
        assert!(!source.contains(concat!("this_thread_", "slot")));
        assert!(!source.contains(concat!("slot_", "us(")));
        assert!(source.contains(concat!("take_guest_run_", "receipt_ns")));
    }

    #[test]
    fn initial_execution_authority_precedes_registration_and_guest_run() {
        let source = include_str!("binding.rs");
        // The welded loop published the initial execution authority inline and
        // then registered the vCPU and ran the guest in the same function. The
        // persistent path publishes it in `prepare_initial_runner_handoff`,
        // whose start gate the executor must have claimed before any guest run,
        // so the ordering is asserted where it now lives.
        let handoff = source
            .split("fn prepare_initial_runner_handoff")
            .nth(1)
            .and_then(|tail| tail.split("fn trap_watchdog_decision").next())
            .expect("initial runner handoff body");
        let publish = handoff
            .find(concat!(
                "publish_initial_",
                "task_state_gated(context.thread(), state)"
            ))
            .expect("initial task state must be published through its claimability gate");
        let gate = handoff
            .find("take_opened_start_gate(generation)")
            .expect("claimed start gate");
        assert!(
            publish < gate,
            "the start gate is claimed only after the initial task state is published"
        );
    }

    fn alias_context(pid: i32) -> crate::kernel::KernelContext {
        let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
            pid,
            ThreadId::synthetic_for_tests(pid),
            "alias-inventory".to_owned(),
        )
        .expect("root bootstrap");
        crate::kernel::Kernel::bootstrap_root(bootstrap)
            .expect("root kernel")
            .1
    }

    fn mock_alias_commit(
        context: &crate::kernel::KernelContext,
    ) -> carrick_hal::FrameInventoryCommit<()> {
        let capacity = carrick_hal::FrameEventCapacity::for_event_count(2).expect("capacity");
        let mut reservation = context
            .kernel()
            .reserve_frame_inventory(1, 1, capacity)
            .expect("reservation");
        let transaction = reservation.transaction();
        let frame = reservation.claim_frame().expect("frame candidate");
        let mapping = reservation.claim_mapping().expect("mapping candidate");
        let generation = carrick_hal::MappingGeneration::from_backend_counter(
            NonZeroU64::new(1).expect("generation"),
        );
        reservation
            .push(carrick_hal::FrameInventoryEvent::PrepareMapping {
                transaction,
                frame,
                mapping,
                generation,
                gpa: carrick_guest_mem::Gpa(0x8000),
                length: carrick_hal::FrameLength::from_mapping_extent(
                    NonZeroU64::new(0x4000).expect("length"),
                ),
                permissions: carrick_hal::MemPerms {
                    read: true,
                    write: true,
                    exec: false,
                },
            })
            .expect("prepare event");
        reservation
            .push(carrick_hal::FrameInventoryEvent::PublishMapping {
                transaction,
                mapping,
                generation,
            })
            .expect("publish event");
        reservation.commit(())
    }

    /// The backend's shared-frame registry makes a freshly staged shared-file
    /// frame reusable by the next installer of the same file from staging
    /// time, and a reuser's batch does not reserve that frame; the authority
    /// accepts the reuse only if the frame is already published. So the
    /// install arm must publish while it still holds the AliasMap topology
    /// lock. Publishing after the release produced the 2026-09-08 silent
    /// `UnreservedFrame` carrier abort under concurrent MAP_SHARED installs.
    #[test]
    fn alias_install_publishes_inventory_before_releasing_the_topology_lock() {
        let source = include_str!("mod.rs");
        let arm = source
            .split("DispatchOutcome::MapHostAlias {")
            .nth(1)
            .expect("the alias-install arm exists");
        let arm = arm
            .split("break 'service installed;")
            .next()
            .expect("the alias-install arm ends by breaking with its result");
        // Anchor after the backend commit is taken: the failed-install
        // rollback above it drops the lock too, and must not satisfy this.
        let tail = arm
            .split("engine.take_alias_inventory()")
            .nth(1)
            .expect("the arm takes the backend alias commit");
        let publish = tail
            .find("apply_alias_frame_inventory(&kernel_context, commit)")
            .expect("the arm publishes the alias inventory");
        let release = tail
            .find("drop(registry);")
            .expect("the arm releases the registry guard after the commit is taken");
        assert!(
            publish < release,
            "alias inventory publication must complete under the leaf registry guard"
        );
    }

    #[test]
    fn alias_inventory_applies_to_the_syscall_context_mm() {
        let context = alias_context(67_103);
        let exact_mm = context.shared().mm().id();
        let commit = mock_alias_commit(&context);

        apply_alias_frame_inventory(&context, commit).expect("alias publication");

        let snapshot = context.kernel().frame_inventory().snapshot_for_mm(exact_mm);
        assert_eq!(snapshot.mappings.len(), 1);
        assert_eq!(snapshot.mappings[0].mm, exact_mm);
    }

    #[test]
    fn hvpatch_migration_endpoint_routes_task_wake_to_exact_scheduler_generation() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().expect("task context");
        let mm = context.shared().mm().id();
        context
            .thread()
            .publish_initial_task_state(crate::kernel::objects::MigratableTaskState {
                cpu: carrick_hal::threaded::GuestCpuState::from_aarch64_v1(
                    carrick_hal::threaded::Aarch64TaskCpuStateV1 {
                        gprs: [0; 31],
                        pc: 0x1000,
                        pstate: 0,
                        trap_pc: 0,
                        trap_pstate: 0,
                        sp_el0: 0x2000,
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
                        asid_generation: mm.raw(),
                    },
                ),
                mm,
                asid_generation: mm.raw(),
            })
            .expect("initial scheduler state");
        let scheduler = Arc::new(crate::kernel::scheduler::Scheduler::new(Arc::clone(
            context.kernel(),
        )));
        let directory = HvpatchRuntimeDirectory::default();
        directory
            .install_scheduler(Arc::clone(&scheduler))
            .expect("install packaged scheduler route");
        let kernel = Arc::new(KernelState::new(
            dispatcher,
            Arc::new(EndpointTestSignalPump),
            Arc::new(EndpointTestSignalArrival),
            None,
            None,
            None,
        ));
        directory.register_endpoint(
            context.task().key(),
            Arc::downgrade(&kernel),
            context.task_binding(),
        );
        let compatibility_wake = Arc::new(EndpointRecordingWaker::default());
        context.task().set_waker(compatibility_wake.clone());

        directory.notify_child_exit(context.task().key(), None);
        assert_eq!(scheduler.queued_len(), 1);
        assert_eq!(
            compatibility_wake
                .0
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "exact scheduler publication must not also invoke the broad compatibility waker"
        );
        assert!(matches!(
            context.thread().execution_state(),
            crate::kernel::objects::ThreadExecutionState::Runnable { .. }
        ));
    }

    #[test]
    fn installed_scheduler_rejection_never_falls_back_to_broad_task_wake_authority() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().expect("task context");
        let scheduler = Arc::new(crate::kernel::scheduler::Scheduler::new(Arc::clone(
            context.kernel(),
        )));
        let directory = HvpatchRuntimeDirectory::default();
        directory
            .install_scheduler(scheduler)
            .expect("install packaged scheduler route");
        let kernel = Arc::new(KernelState::new(
            dispatcher,
            Arc::new(EndpointTestSignalPump),
            Arc::new(EndpointTestSignalArrival),
            None,
            None,
            None,
        ));
        directory.register_endpoint(
            context.task().key(),
            Arc::downgrade(&kernel),
            context.task_binding(),
        );
        let compatibility_wake = Arc::new(EndpointRecordingWaker::default());
        context.task().set_waker(compatibility_wake.clone());

        directory.notify_child_exit(context.task().key(), None);

        assert_eq!(
            compatibility_wake
                .0
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a broad compatibility nudge cannot replace rejected scheduler authority"
        );
    }

    #[test]
    fn persistent_root_waits_for_physical_retirement_after_error_result() {
        struct NeverPolled;
        impl continuation::PersistentQuantumJob for NeverPolled {
            fn poll_quantum_with_engine(
                &mut self,
                _engine: &mut dyn std::any::Any,
                _control: &mut executor::HvpatchQuantumControl<'_, '_>,
            ) -> executor::ExecutorExit {
                unreachable!("retirement-only test job must not run")
            }
        }

        let result = HvpatchLoopResult::pending();
        let completion = continuation::LogicalJobCompletion::pending();
        let quantum = Arc::new(continuation::HvpatchTaskQuantum::new(
            Box::new(NeverPolled),
            completion.clone(),
        ));
        let launch = VcpuLoopLaunch::Persistent {
            liveness: ProcessGraphLiveness::unbound(),
            result: result.clone(),
            completion: completion.clone(),
            process_retirement: ProcessPhysicalRetirement::default(),
        };
        let (wait_tx, wait_rx) = std::sync::mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            wait_tx.send(launch.wait()).expect("report root wait");
        });
        result.publish(Err(RuntimeError::Unsupported(
            "injected root failure".to_owned(),
        )));
        completion.publish();
        assert!(
            wait_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "root error must not outrun physical binding retirement"
        );
        drop(quantum);
        match wait_rx.recv().expect("root wait result") {
            Err(error) => assert!(error.to_string().contains("injected root failure")),
            Ok(_) => panic!("injected root failure unexpectedly succeeded"),
        }
        waiter.join().expect("root waiter");
    }

    #[test]
    fn persistent_error_after_exit_starts_waits_for_process_physical_retirement() {
        struct NeverPolled;
        impl continuation::PersistentQuantumJob for NeverPolled {
            fn poll_quantum_with_engine(
                &mut self,
                _engine: &mut dyn std::any::Any,
                _control: &mut executor::HvpatchQuantumControl<'_, '_>,
            ) -> executor::ExecutorExit {
                unreachable!("retirement-only test job must not run")
            }
        }

        let result = HvpatchLoopResult::pending();
        let root_completion = continuation::LogicalJobCompletion::pending();
        let sibling_completion = continuation::LogicalJobCompletion::pending();
        let root_quantum = Arc::new(continuation::HvpatchTaskQuantum::new(
            Box::new(NeverPolled),
            root_completion.clone(),
        ));
        let sibling_quantum = Arc::new(continuation::HvpatchTaskQuantum::new(
            Box::new(NeverPolled),
            sibling_completion.clone(),
        ));
        let process_retirement = ProcessPhysicalRetirement::default();
        process_retirement.begin_process_exit();
        process_retirement
            .publish(vec![root_completion.clone(), sibling_completion.clone()])
            .unwrap();
        let launch = VcpuLoopLaunch::Persistent {
            liveness: ProcessGraphLiveness::unbound(),
            result: result.clone(),
            completion: root_completion.clone(),
            process_retirement,
        };

        let (wait_tx, wait_rx) = std::sync::mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            wait_tx.send(launch.wait()).expect("report root wait");
        });
        result.publish(Err(RuntimeError::Unsupported(
            "injected terminal failure".to_owned(),
        )));
        root_completion.publish();
        sibling_completion.publish();
        drop(root_quantum);

        assert!(
            wait_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "terminal error must not outrun sibling physical retirement"
        );
        drop(sibling_quantum);
        match wait_rx.recv().expect("root wait result") {
            Err(error) => assert!(error.to_string().contains("injected terminal failure")),
            Ok(_) => panic!("injected terminal failure unexpectedly succeeded"),
        }
        waiter.join().expect("root waiter");
    }

    #[test]
    fn pre_exit_executor_failure_reaps_late_clone_before_physical_retirement() {
        struct NeverPolled {
            _mount_owner: Option<Box<dyn Send>>,
        }

        impl continuation::PersistentQuantumJob for NeverPolled {
            fn poll_quantum_with_engine(
                &mut self,
                _engine: &mut dyn std::any::Any,
                _control: &mut executor::HvpatchQuantumControl<'_, '_>,
            ) -> executor::ExecutorExit {
                unreachable!("retirement-only sibling job must not run")
            }
        }

        let dispatcher = SyscallDispatcher::new();
        let mut mounts = dispatcher.prepare_mount_retirement();
        let sibling_mount_owner: Box<dyn Send> = Box::new(dispatcher.archive_authority());
        drop(dispatcher);

        let (runtime, scheduler, kernel, root, process, generation) =
            test_carrier_graph_with_dispatcher!(72_430, SyscallDispatcher::new());
        let pending_clone = kernel
            .enroll_thread_clone()
            .admitted()
            .expect("hold one in-flight clone admission");
        let executor = scheduler
            .register_executor(Arc::new(RuntimeTestExecutorKick::default()))
            .expect("register failing executor");
        let running = scheduler.take(&executor).expect("take failing root job");
        runtime
            .persistent_bindings()
            .retire(root.thread().key(), generation);

        let threads = VcpuThreadRegistry::default();
        let root_result = HvpatchLoopResult::pending();
        let root_completion = continuation::LogicalJobCompletion::pending();
        let root_settlement =
            HvpatchExternalTerminalSettlement::new(root_result.clone(), root_completion.clone());
        let sibling_result = HvpatchLoopResult::pending();
        let sibling_completion = continuation::LogicalJobCompletion::pending();
        let sibling_settlement =
            HvpatchExternalTerminalSettlement::new(sibling_result, sibling_completion.clone());
        enroll_persistent_process_member(&threads, &root_settlement);
        enroll_persistent_process_member(&threads, &sibling_settlement);

        let this_tid = ThreadId::synthetic_for_tests(72_430);
        let registry = Arc::new(ThreadRegistry::new(this_tid));
        let futex = Arc::new(FutexTable::new());
        let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
        let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
        let kicker: Arc<dyn VcpuRegistry> = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let mut state = ThreadRuntimeState::<CrashCaptureTestEngine>::new(
            Arc::clone(&registry),
            futex,
            platform,
            platform_factory,
            kernel.process_fork_barrier.clone(),
            kernel.crash_capture.clone(),
            Some(Arc::clone(root.thread())),
            Some(process.pid()),
            root.thread().key().tid,
            kernel.fatal_signal.current_generation(),
            this_tid,
            threads.clone(),
            kicker,
            carrick_hal::InGuestFlag::for_guest_thread(),
            1_000,
        );
        state.service_kernel_context = Some(root.retain_exact());
        let production = ProductionHvpatchLoopJob {
            kernel: Arc::clone(&kernel),
            state,
            phase: HvpatchProductionPhase::Resident,
            registration_wait: None,
            terminal_settlement: root_settlement,
            terminal_result: None,
            completion: root_completion.clone(),
            traps: 0,
            budget_floor: 0,
            seen_signal_progress: signal_progress_count(),
            last_signal_progress: Instant::now(),
            terminal_runtime: PersistentTerminalRuntimeState::Resident,
            pending_terminal_retirement: None,
            pending_terminal_inventory: None,
            external_exec: None,
        };
        let root_quantum = Arc::new(continuation::HvpatchTaskQuantum::new(
            Box::new(HvpatchLoopJob::production(
                production,
                InjectedExecutionLeaseSlot::new(),
            )),
            root_completion.clone(),
        ));
        let root_binding = Arc::new(continuation::HvpatchTaskBinding::new(
            executor::TaskLoadIdentity {
                abi: carrick_abi::LinuxGuestAbi::Aarch64,
                version: 1,
                mm: root.shared().mm().id(),
                asid_generation: process.asid_generation(),
            },
            Arc::clone(&root_quantum),
            Box::new(72_430_u64),
        ));
        runtime
            .persistent_bindings()
            .publish(root.thread().key(), generation, Arc::clone(&root_binding))
            .expect("publish production failure binding");
        let sibling_quantum = Arc::new(continuation::HvpatchTaskQuantum::new(
            Box::new(NeverPolled {
                _mount_owner: Some(sibling_mount_owner),
            }),
            sibling_completion,
        ));
        let launch = VcpuLoopLaunch::Persistent {
            liveness: ProcessGraphLiveness::unbound(),
            result: root_result,
            completion: root_completion,
            process_retirement: kernel.process_physical_retirement.clone(),
        };

        assert!(
            executor::fail_running_and_retire_for_test::<continuation::HvpatchTaskBinding, _>(
                runtime.persistent_bindings().as_ref(),
                &scheduler,
                running,
                crate::kernel::objects::ExecutionFailure::SnapshotRestoreFailed,
            )
            .is_none(),
            "exact failure settlement itself must succeed",
        );
        drop(root_binding);
        drop(root_quantum);

        let (wait_tx, wait_rx) = std::sync::mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            wait_tx.send(launch.wait()).expect("report root wait");
        });
        assert!(
            wait_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "pre-exit executor failure must not outrun sibling physical retirement"
        );
        assert!(
            mounts.prepare().is_err(),
            "the live sibling quantum still owns the exact mount table"
        );

        let late_tid = registry.register_child(0);
        let late_result = HvpatchLoopResult::pending();
        let late_completion = continuation::LogicalJobCompletion::pending();
        let late_settlement =
            HvpatchExternalTerminalSettlement::new(late_result, late_completion.clone());
        enroll_persistent_process_member(&threads, &late_settlement);
        let late_quantum = Arc::new(continuation::HvpatchTaskQuantum::new(
            Box::new(NeverPolled { _mount_owner: None }),
            late_completion.clone(),
        ));

        drop(pending_clone);
        let late_settlement_deadline = Instant::now() + Duration::from_secs(1);
        while !late_completion.is_finished() && Instant::now() < late_settlement_deadline {
            std::thread::yield_now();
        }
        assert!(
            late_completion.is_finished(),
            "post-stop admitted clone must be included in the exact member snapshot"
        );
        assert!(
            !registry.is_live(late_tid),
            "post-stop admitted clone must be removed by a repeated sibling stop"
        );
        assert!(
            wait_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "clone-drain completion must publish a receipt that still waits for the sibling"
        );
        drop(sibling_quantum);
        assert!(
            wait_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "the exact receipt must retain the late child's physical quantum"
        );
        drop(late_quantum);
        assert!(matches!(
            wait_rx.recv().expect("root wait result"),
            Err(RuntimeError::CarrierFailed(_))
        ));
        waiter.join().expect("root waiter");
        mounts.prepare().expect("all physical mount owners retired");
        scheduler
            .unregister_executor(&executor)
            .expect("unregister failing executor");
        scheduler.close();
        scheduler.wait_closed();
    }

    #[test]
    fn persistent_root_wait_does_not_outrun_sibling_terminal_mount_owner() {
        struct NeverPolled {
            _mount_owner: Option<Box<dyn Send>>,
        }
        impl continuation::PersistentQuantumJob for NeverPolled {
            fn poll_quantum_with_engine(
                &mut self,
                _engine: &mut dyn std::any::Any,
                _control: &mut executor::HvpatchQuantumControl<'_, '_>,
            ) -> executor::ExecutorExit {
                unreachable!("retirement-only test job must not run")
            }
        }

        let dispatcher = SyscallDispatcher::new();
        let mut mounts = dispatcher.prepare_mount_retirement();
        let sibling_mount_owner: Box<dyn Send> = Box::new(dispatcher.archive_authority());
        drop(dispatcher);

        let root_result = HvpatchLoopResult::pending();
        let root_completion = continuation::LogicalJobCompletion::pending();
        let root_quantum = Arc::new(continuation::HvpatchTaskQuantum::new(
            Box::new(NeverPolled { _mount_owner: None }),
            root_completion.clone(),
        ));
        let sibling_completion = continuation::LogicalJobCompletion::pending();
        let sibling_quantum = Arc::new(continuation::HvpatchTaskQuantum::new(
            Box::new(NeverPolled {
                _mount_owner: Some(sibling_mount_owner),
            }),
            sibling_completion.clone(),
        ));
        let launch = VcpuLoopLaunch::Persistent {
            liveness: ProcessGraphLiveness::unbound(),
            result: root_result.clone(),
            completion: root_completion.clone(),
            process_retirement: {
                let retirement = ProcessPhysicalRetirement::default();
                retirement
                    .publish(vec![root_completion.clone(), sibling_completion.clone()])
                    .unwrap();
                retirement
            },
        };

        let (wait_tx, wait_rx) = std::sync::mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            wait_tx.send(launch.wait()).expect("report root wait");
        });
        root_result.publish(Ok(VcpuLoopOutcome::ThreadDone));
        root_completion.publish();
        sibling_completion.publish();
        drop(root_quantum);

        assert!(
            wait_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "root process wait must retain the sibling owner's physical completion"
        );
        assert!(
            mounts.prepare().is_err(),
            "the live sibling quantum still owns the exact mount table"
        );

        drop(sibling_quantum);
        assert!(matches!(
            wait_rx.recv().expect("root wait result"),
            Ok(VcpuLoopOutcome::ThreadDone)
        ));
        waiter.join().expect("root waiter");
        mounts.prepare().expect("all physical mount owners retired");
    }

    #[test]
    fn exec_replacement_treats_removed_sibling_as_done_after_flag_clears() {
        let owner = ThreadId::synthetic_for_tests(1000);
        let registry = ThreadRegistry::new(owner);
        let sibling = registry.register_child(0);

        let removed = registry.remove_all_except(owner);
        assert!(removed.contains(&sibling));
        crate::fork_quiesce::end_exec_replacement();

        assert!(thread_should_finish_for_exec_replacement(
            &registry, sibling
        ));
    }

    #[test]
    fn trap_watchdog_keeps_running_below_count_prefilter() {
        // Below the count pre-filter, the wall clock is irrelevant — never trip,
        // even after a long elapsed window.
        assert_eq!(
            trap_watchdog_decision(
                100,
                1000,
                || Duration::from_secs(60),
                || Duration::from_secs(30)
            ),
            TrapWatchdog::KeepRunning
        );
        // Exactly AT the count threshold is still under (the guard uses `>`).
        assert_eq!(
            trap_watchdog_decision(
                1000,
                1000,
                || Duration::from_secs(60),
                || Duration::from_secs(30)
            ),
            TrapWatchdog::KeepRunning
        );
    }

    #[test]
    fn trap_watchdog_resets_budget_when_count_exceeded_but_wall_intact() {
        // Over the count pre-filter but the guest made wall-clock progress
        // recently (a syscall-bound-but-progressing loop) → reset, do not abort.
        assert_eq!(
            trap_watchdog_decision(
                1001,
                1000,
                || Duration::from_millis(100),
                || Duration::from_secs(30)
            ),
            TrapWatchdog::ResetBudget
        );
        // Just under the wall window is still a reset (the trip uses `>=`).
        assert_eq!(
            trap_watchdog_decision(
                2_000_000,
                1000,
                || Duration::from_millis(29_999),
                || Duration::from_millis(30_000)
            ),
            TrapWatchdog::ResetBudget
        );
    }

    #[test]
    fn trap_watchdog_trips_on_count_and_wall_stall() {
        // Over the count pre-filter AND no progress for >= max_wall → abort.
        // The boundary is inclusive (`>=`): exactly max_wall trips.
        assert_eq!(
            trap_watchdog_decision(
                1001,
                1000,
                || Duration::from_secs(30),
                || Duration::from_secs(30)
            ),
            TrapWatchdog::Trip
        );
        assert_eq!(
            trap_watchdog_decision(
                1_000_000,
                1000,
                || Duration::from_secs(45),
                || Duration::from_secs(30)
            ),
            TrapWatchdog::Trip
        );
    }

    #[test]
    fn trap_watchdog_decision_gates_clock_and_window_reads() {
        use std::cell::Cell;

        let clock_reads = Cell::new(0_usize);
        let window_reads = Cell::new(0_usize);
        let clock = || {
            clock_reads.set(clock_reads.get() + 1);
            Duration::from_secs(10)
        };
        let window = || {
            window_reads.set(window_reads.get() + 1);
            Duration::from_secs(30)
        };

        // 1. Below threshold: zero clock/window reads.
        let decision = trap_watchdog_decision(500, 1000, clock, window);
        assert_eq!(decision, TrapWatchdog::KeepRunning);
        assert_eq!(
            clock_reads.get(),
            0,
            "below count prefilter must perform 0 clock reads"
        );
        assert_eq!(
            window_reads.get(),
            0,
            "below count prefilter must perform 0 window reads"
        );

        // 2. Exactly at threshold: zero clock/window reads.
        let decision = trap_watchdog_decision(1000, 1000, clock, window);
        assert_eq!(decision, TrapWatchdog::KeepRunning);
        assert_eq!(
            clock_reads.get(),
            0,
            "exact count threshold must perform 0 clock reads"
        );
        assert_eq!(
            window_reads.get(),
            0,
            "exact count threshold must perform 0 window reads"
        );

        // 3. usize::MAX threshold (ecosystem invocation): zero clock/window reads.
        let decision = trap_watchdog_decision(10_000_000, usize::MAX, clock, window);
        assert_eq!(decision, TrapWatchdog::KeepRunning);
        assert_eq!(
            clock_reads.get(),
            0,
            "usize::MAX threshold must perform 0 clock reads"
        );
        assert_eq!(
            window_reads.get(),
            0,
            "usize::MAX threshold must perform 0 window reads"
        );

        // 4. Above threshold: exactly 1 clock read and 1 window read.
        let decision = trap_watchdog_decision(1001, 1000, clock, window);
        assert_eq!(decision, TrapWatchdog::ResetBudget);
        assert_eq!(
            clock_reads.get(),
            1,
            "above count threshold must perform 1 clock read"
        );
        assert_eq!(
            window_reads.get(),
            1,
            "above count threshold must perform 1 window read"
        );
    }

    #[test]
    fn trap_watchdog_step_seam_proves_call_path_zero_reads_and_signal_reset() {
        use std::cell::Cell;

        let (process, root) = crate::hvpatch::process_context_for_tests(70_222);
        let dispatcher = SyscallDispatcher::new();
        dispatcher.bind_hvpatch_process(process.clone());
        let kernel = Arc::new(KernelState::new(
            dispatcher,
            Arc::new(EndpointTestSignalPump),
            Arc::new(EndpointTestSignalArrival),
            Some(process.clone()),
            None,
            None,
        ));
        let this_tid = ThreadId::synthetic_for_tests(70_222);
        let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
        let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
        let mut state = ThreadRuntimeState::<CrashCaptureTestEngine>::new(
            Arc::new(ThreadRegistry::new(this_tid)),
            Arc::new(FutexTable::new()),
            platform,
            platform_factory,
            kernel.process_fork_barrier.clone(),
            kernel.crash_capture.clone(),
            Some(Arc::clone(root.thread())),
            Some(process.pid()),
            root.thread().key().tid,
            kernel.fatal_signal.current_generation(),
            this_tid,
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(carrick_hal::GenericVcpuRegistry::new()),
            carrick_hal::InGuestFlag::for_guest_thread(),
            1_000,
        );
        state.service_kernel_context = Some(root.retain_exact());
        let mut job =
            suffix_failure_test_job(&kernel, state, HvpatchProductionPhase::Resident, None);

        let clock_reads = Cell::new(0_usize);
        let window_reads = Cell::new(0_usize);
        let clock = |_last: &Instant| {
            clock_reads.set(clock_reads.get() + 1);
            Duration::from_millis(100)
        };
        let window = || {
            window_reads.set(window_reads.get() + 1);
            Duration::from_secs(30)
        };

        // Below threshold (traps = 500, max_traps = 1000): 0 clock reads, 0 window reads.
        job.traps = 500;
        let decision = job.step_trap_watchdog(clock, window);
        assert_eq!(decision, TrapWatchdog::KeepRunning);
        assert_eq!(
            clock_reads.get(),
            0,
            "call path below count threshold must perform 0 clock reads"
        );
        assert_eq!(
            window_reads.get(),
            0,
            "call path below count threshold must perform 0 window reads"
        );

        // Exactly at threshold (traps = 1000, max_traps = 1000): 0 clock reads, 0 window reads.
        job.traps = 1000;
        let decision = job.step_trap_watchdog(clock, window);
        assert_eq!(decision, TrapWatchdog::KeepRunning);
        assert_eq!(
            clock_reads.get(),
            0,
            "call path at exact count threshold must perform 0 clock reads"
        );
        assert_eq!(
            window_reads.get(),
            0,
            "call path at exact count threshold must perform 0 window reads"
        );

        // Above threshold (traps = 1001, max_traps = 1000): 1 clock read, 1 window read -> ResetBudget.
        job.traps = 1001;
        let decision = job.step_trap_watchdog(clock, window);
        assert_eq!(decision, TrapWatchdog::ResetBudget);
        assert_eq!(
            clock_reads.get(),
            1,
            "call path above count threshold must read clock"
        );
        assert_eq!(
            window_reads.get(),
            1,
            "call path above count threshold must read window"
        );
        assert_eq!(
            job.budget_floor, 1001,
            "budget floor must reset to current traps on ResetBudget"
        );

        // Next step after budget reset (traps = 1002, budget_floor = 1001, delta = 1 <= 1000): 0 reads.
        job.traps = 1002;
        let decision = job.step_trap_watchdog(clock, window);
        assert_eq!(decision, TrapWatchdog::KeepRunning);
        assert_eq!(
            clock_reads.get(),
            1,
            "call path after budget reset must perform 0 new clock reads"
        );
        assert_eq!(
            window_reads.get(),
            1,
            "call path after budget reset must perform 0 new window reads"
        );

        // Now test max_traps = usize::MAX (ecosystem workload pattern)
        job.state.max_traps = usize::MAX;
        job.traps = 50_000_000;
        let decision = job.step_trap_watchdog(clock, window);
        assert_eq!(decision, TrapWatchdog::KeepRunning);
        assert_eq!(
            clock_reads.get(),
            1,
            "usize::MAX max_traps must perform 0 new clock reads"
        );
        assert_eq!(
            window_reads.get(),
            1,
            "usize::MAX max_traps must perform 0 new window reads"
        );

        // Now test signal progress independently resets budget floor without reading clock
        job.state.max_traps = 1000;
        job.traps = 2000; // traps_since_signal would be 2000 - 1001 = 999 <= 1000
        // Simulate a new signal progress event by modifying seen_signal_progress
        job.seen_signal_progress = signal_progress_count().wrapping_sub(1);
        let decision = job.step_trap_watchdog(clock, window);
        assert_eq!(decision, TrapWatchdog::KeepRunning);
        assert_eq!(
            job.budget_floor, 2000,
            "signal progress must update budget floor to traps"
        );
        assert_eq!(job.seen_signal_progress, signal_progress_count());
        assert_eq!(
            clock_reads.get(),
            1,
            "signal progress reset must not require clock read if delta <= max_traps"
        );

        // Now test Trip condition: traps above threshold and elapsed >= max_wall
        job.traps = 3500; // delta = 3500 - 2000 = 1500 > 1000
        let trip_clock = |_last: &Instant| {
            clock_reads.set(clock_reads.get() + 1);
            Duration::from_secs(35)
        };
        let decision = job.step_trap_watchdog(trip_clock, window);
        assert_eq!(decision, TrapWatchdog::Trip);
        assert_eq!(clock_reads.get(), 2);
        assert_eq!(window_reads.get(), 2);
    }

    #[test]
    fn hvpatch_child_output_writer_drains_payload_larger_than_a_pipe() {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let payload: Vec<u8> = (0..(256 * 1024)).map(|index| (index % 251) as u8).collect();
        let reader = std::thread::spawn(move || {
            let mut output = Vec::new();
            let mut buffer = [0_u8; 8192];
            loop {
                let read = unsafe { libc::read(fds[0], buffer.as_mut_ptr().cast(), buffer.len()) };
                if read > 0 {
                    output.extend_from_slice(&buffer[..read as usize]);
                } else {
                    break;
                }
            }
            unsafe { libc::close(fds[0]) };
            output
        });
        write_hvpatch_child_output(fds[1], &payload).expect("complete pipe write");
        unsafe { libc::close(fds[1]) };
        assert_eq!(reader.join().expect("pipe reader"), payload);
    }

    #[test]
    fn post_close_exec_failures_reach_production_poll_as_typed_authority() {
        let source = include_str!("binding.rs");
        let exec_source = include_str!("exec.rs");

        assert!(
            exec_source.contains("enum ProductionHvpatchPollError"),
            "production polling must distinguish ordinary errors from exact post-close exec errors"
        );
        assert!(
            (source.contains("ProductionHvpatchPollError::Exec")
                || exec_source.contains("ProductionHvpatchPollError::Exec")),
            "the production wrapper must consume the typed exec-terminal error arm"
        );
        assert!(
            exec_source.contains("struct ExecTerminalFailure"),
            "fallible prepared-drain and suffix operations must return the retained handoff"
        );
        assert!(
            exec_source.contains("struct FinishedPreparedExecve"),
            "the handoff must remain live through fallible post-suffix publication"
        );
    }

    #[test]
    fn persistent_terminal_owner_withdrawal_clears_child_tid_and_wakes_joiner() {
        let owner = ThreadId::synthetic_for_tests(70_302);
        let clear_address = 0x2_000;
        let registry = ThreadRegistry::new(owner);
        registry.set_clear_child_tid(owner, clear_address);
        let futex = FutexTable::new();
        let wait = futex.prepare_wait(clear_address);
        let wakes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let wake_count = Arc::clone(&wakes);
        let enrollment = futex.subscribe_generation(
            wait,
            Arc::new(move |_| {
                wake_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }),
        );
        let mut memory =
            crate::dispatch::LinearMemory::new(clear_address, owner.raw().to_le_bytes().to_vec());

        threads::clear_persistent_child_tid_and_wake(&mut memory, &registry, &futex, owner);

        assert_eq!(
            memory.read_bytes(clear_address, std::mem::size_of::<i32>()),
            Ok(0_i32.to_le_bytes().to_vec())
        );
        assert_eq!(wakes.load(std::sync::atomic::Ordering::SeqCst), 1);
        drop(enrollment);
    }

    /// The production thread-clone path must park a `Deferred` enrollment
    /// on the gate's change epoch rather than lower it to `EAGAIN`.
    /// A process exit retires its MM edge; that is an owner-set edit and
    /// must be admitted against a sibling's exec reservation exactly as a
    /// shared fork is — before the topology lock, and long before the
    /// kernel exit publication after which a refusal is only an abort.
    #[track_caller]
    fn expect_test<T>(opt: Option<T>, msg: &str) -> T {
        assert!(opt.is_some(), "{msg}");
        match opt {
            Some(val) => val,
            None => unreachable!(),
        }
    }

    #[test]
    fn process_exit_admits_its_retirement_against_exec_reservations() {
        let source = include_str!("binding.rs");
        let finalize = expect_test(
            expect_test(
                source
                    .split("fn finalize_persistent_process_terminal(")
                    .nth(1),
                "finalize_persistent_process_terminal missing from binding.rs",
            )
            .split("\n    fn ")
            .next(),
            "finalize_persistent_process_terminal body missing from binding.rs",
        );
        let hold_at = finalize
            .find(".hold_owner_set_edit(terminal_context.task().key())")
            .expect("exit admits its owner-set edit");
        let topology_at = finalize
            .find("try_acquire_topology_lock(")
            .expect("exit takes the topology lock");
        let publish_at = finalize
            .find(".publish_exit_status(")
            .expect("exit publishes into the kernel graph");
        let retire_at = finalize
            .find(".begin_address_space_retirement(")
            .expect("exit retires its MM edge");
        assert!(
            hold_at < topology_at,
            "admission precedes the topology lock"
        );
        assert!(
            hold_at < publish_at,
            "admission precedes kernel publication"
        );
        assert!(finalize.contains("TerminalRetireSubscription::ExecSettlement"));
        assert!(finalize.contains(".subscribe_exec_settlement("));
        // The hold is also dropped when parking on the topology lock; the
        // final release follows the retirement.
        let release_at = finalize
            .rfind("drop(owner_set_edit);")
            .expect("the hold is released explicitly after retirement");
        assert!(retire_at < release_at);
        let park_release_at = finalize
            .find("drop(owner_set_edit);")
            .expect("the hold is dropped before parking on topology");
        assert!(
            park_release_at
                < topology_at
                    + finalize[topology_at..]
                        .find("return self.suspend(")
                        .unwrap()
        );
    }

    #[test]
    fn deferred_thread_clone_parks_on_the_admission_epoch() {
        let source = include_str!("binding.rs");
        let spawn = expect_test(
            expect_test(
                source
                    .split("fn spawn_persistent_hvpatch_clone_thread")
                    .nth(1),
                "spawn_persistent_hvpatch_clone_thread missing from binding.rs",
            )
            .split("\n#[cfg(test)]")
            .next(),
            "spawn_persistent_hvpatch_clone_thread body missing from binding.rs",
        );
        let deferred_at = spawn
            .find("CloneEnrollment::Deferred { observed_epoch }")
            .expect("thread clone handles a deferred enrollment");
        let refused_at = spawn
            .find("CloneEnrollment::Refused")
            .expect("thread clone handles a refused enrollment");
        let eagain_at = spawn
            .find("thread clone admission refused; clone(2) = EAGAIN")
            .expect("refusal is the only EAGAIN");
        assert!(deferred_at < refused_at && refused_at < eagain_at);
        assert!(spawn[deferred_at..refused_at].contains("CloneRetrySubscription::Admission"));
        assert!(spawn[deferred_at..refused_at].contains("clone_admission.subscribe_change("));
        assert!(!spawn[deferred_at..refused_at].contains("LINUX_EAGAIN"));
    }

    #[test]
    fn fork_barrier_raise_uses_durable_threads_when_sibling_owns_no_executor() {
        let (process, root) = crate::hvpatch::process_context_for_tests(70_100);
        let plan = crate::kernel::ClonePlan::from_flags(
            carrick_abi::LinuxCloneFlags::THREAD
                | carrick_abi::LinuxCloneFlags::SIGHAND
                | carrick_abi::LinuxCloneFlags::VM,
        )
        .unwrap();
        let sibling = process
            .kernel_graph()
            .reserve_thread_clone(&root, plan, None)
            .unwrap()
            .prepare(ThreadId::synthetic_for_tests(70_101))
            .unwrap()
            .commit()
            .unwrap()
            .start_thread()
            .unwrap()
            .into_context();
        let dispatcher = SyscallDispatcher::new();
        dispatcher.bind_hvpatch_process(process);
        let runtime = KernelState::new(
            dispatcher,
            Arc::new(EndpointTestSignalPump),
            Arc::new(EndpointTestSignalArrival),
            None,
            None,
            None,
        );
        assert_eq!(
            runtime
                .dispatcher
                .mm_executor_census()
                .participant_count_for_probe(),
            0
        );
        assert_eq!(root.task().threads().len(), 2);
        assert_eq!(sibling.task().key(), root.task().key());
        assert!(
            include_str!("quiesce.rs")
                .contains("fork_barrier_participants(parent_context.thread().key())")
        );
    }

    #[test]
    fn persistent_exec_drain_retains_leader_result_until_exact_completion() {
        let (_process, context) = crate::hvpatch::process_context_for_tests(70_102);
        let directory = HvpatchRuntimeDirectory::default();
        let (scheduler, _) = directory.continuation_services(context.kernel());
        let handles = VcpuThreadRegistry::default();
        let leader_result = HvpatchLoopResult::pending();
        let leader_completion = continuation::LogicalJobCompletion::pending();
        let exec_result = HvpatchLoopResult::pending();
        let exec_completion = continuation::LogicalJobCompletion::pending();
        let leader_settlement = HvpatchExternalTerminalSettlement::new(
            leader_result.clone(),
            leader_completion.clone(),
        );
        let exec_settlement =
            HvpatchExternalTerminalSettlement::new(exec_result, exec_completion.clone());

        enroll_persistent_process_member(&handles, &leader_settlement);
        enroll_persistent_process_member(&handles, &exec_settlement);
        let drain = continuation::ProcessDrain::for_scheduler(
            context.thread().key(),
            &scheduler,
            exec_completion.id(),
            handles.completions(),
        );
        assert!(!drain.is_ready(), "exec must wait for the suspended leader");

        leader_settlement
            .publish_member(Ok(VcpuLoopOutcome::ThreadDone))
            .unwrap();
        assert!(drain.is_ready());
        let (published, _) = finish_persistent_process_handles(&handles, &exec_completion)
            .expect("drain exact leader result without synthesizing one");
        assert_eq!(published, 0, "the leader settled its own job");
    }

    #[test]
    fn persistent_worker_drain_never_waits_for_a_removed_logical_job() {
        let source = include_str!("binding.rs");
        let threads_source = include_str!("threads.rs");
        let finish = threads_source
            .split("fn finish_completed(")
            .nth(1)
            .and_then(|tail| tail.split("fn enroll_persistent_process_member").next())
            .expect("persistent handle settlement body");
        assert!(
            !finish.contains("result.wait()"),
            "an executor worker must externally settle a removed persistent job, never wait"
        );
        let poll = source
            .split("fn poll_with_engine(")
            .nth(1)
            .and_then(|tail| {
                tail.split("impl<E: ThreadedEngine + 'static> ProductionHvpatchLoopPoll")
                    .next()
            })
            .expect("production job poll");
        assert!(
            poll.find("terminal_settlement.is_published()").unwrap()
                < poll.find("guest_execution.is_none()").unwrap(),
            "a late queued poll must observe external terminal settlement before re-entry"
        );
        let publication = source
            .split("fn publish_terminal_result(&mut self)")
            .nth(1)
            .and_then(|tail| tail.split("fn suspend(").next())
            .expect("production terminal result publication");
        assert!(
            publication.contains("publish_terminal(self.terminal_result.take())"),
            "scheduler terminal settlement must consume the typed role/result pair"
        );
        assert!(
            source.contains("ProcessExitClaim::Owner => {")
                && source.contains("arm_process_owner()"),
            "the exact terminal CAS winner must arm owner-result authority"
        );
    }

    #[test]
    fn production_registration_keeps_census_before_registry_publication() {
        let source = include_str!("binding.rs");
        let poll = source.split("fn poll_with_engine(").nth(1).unwrap();
        assert!(
            poll.find("enter_mm_executor_then_register").unwrap()
                < poll.find("subscribe_register_vcpu").unwrap()
        );
    }

    #[test]
    fn registration_wait_is_sidecar_not_hvpatch_phase() {
        let source = include_str!("binding.rs");
        let job = source
            .split("struct ProductionHvpatchLoopJob")
            .nth(1)
            .unwrap();
        assert!(
            job.contains("registration_wait: Option<carrick_hal::VcpuLeaseChangeSubscription>")
        );
        let phases = source
            .split("enum HvpatchProductionPhase")
            .nth(1)
            .unwrap()
            .split("impl HvpatchProductionPhase")
            .next()
            .unwrap();
        assert!(!phases.contains("RegistrationWait"));
    }

    #[test]
    fn production_registration_has_no_barrier_precheck_or_phase_replacement() {
        let source = include_str!("binding.rs");
        let poll = source
            .split("fn poll_with_engine(")
            .nth(1)
            .expect("production poll body");
        let registration = poll
            .split("if self.state.guest_execution.is_none()")
            .nth(1)
            .expect("registration admission block")
            .split("// Exec/exit can force")
            .next()
            .expect("bounded registration admission block");
        assert!(registration.contains("enter_mm_executor_then_register"));
        assert!(!registration.contains("is_quiescing"));
        assert!(!registration.contains("try_begin_fork"));
        assert!(!registration.contains("self.phase ="));
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn registration_test_exec_work() -> crate::kernel::control::ExecWork {
        use crate::kernel::control::{
            CarrierExecAdmission, ControlNonce, ControlTaskKey, ExecAttach, ExecCapability,
            ExecRequest, ExecRuntime, ExecStatus,
        };

        let runtime = ExecRuntime::new(1);
        let capability = ExecCapability::from(ControlNonce::fresh().expect("control nonce"));
        let submit = runtime.clone();
        let request = ExecRequest {
            argv: vec!["/bin/true".to_owned()],
            env: Vec::new(),
            workdir: None,
            user: None,
            tty: false,
            attach: ExecAttach::Capture,
        };
        let submitter = std::thread::spawn(move || submit.admit(capability, request));
        while runtime.query(capability) != ExecStatus::Pending {
            std::thread::yield_now();
        }
        let mut work = loop {
            if let Some(work) = runtime.try_take() {
                break work;
            }
            std::thread::yield_now();
        };
        assert!(work.begin_publication());
        assert!(work.admit(ControlTaskKey {
            pid: 70_204,
            serial: 1,
        }));
        assert_eq!(submitter.join().expect("exec submitter"), Ok(capability));
        work
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn registration_test_retry_phase(
        external_exec: Option<crate::kernel::control::ExecWork>,
    ) -> HvpatchProductionPhase {
        HvpatchProductionPhase::RetryProcessFork {
            frame: None,
            request: quiesce::ForkRequest {
                flags: 0,
                pidfd_out: None,
                clone_parent: false,
                parent_tid_addr: None,
                child_tid_addr: None,
                exit_signal: 0,
                child_stack: 0,
                vfork: None,
            },
            coordinator: None,
            external_exec,
            deferred_resume_blocked: None,
            _subscription: quiesce::ProcessForkRetrySubscription::Reservation {
                _subscription: None,
            },
        }
    }

    #[test]
    fn census_admission_precedes_registry_publication() {
        let registry = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let census = Arc::new(crate::kernel::GuestExecutorCensus::default());
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().expect("task context");
        let thread = context.thread().clone();
        let first = ThreadId::synthetic_for_tests(70_201);
        let second = ThreadId::synthetic_for_tests(70_202);
        let _first_participation = census.enter(None).expect("first participation");
        let freeze = match registry.subscribe_lease_drain(first, Arc::new(|| {})) {
            carrick_hal::VcpuLeaseDrainEnrollment::Frozen(guard) => guard,
            _ => panic!("first thread must freeze an empty sibling lease set"),
        };
        let second_in_guest = carrick_hal::InGuestFlag::for_guest_thread();

        let (second_participation, attempt) =
            enter_guest_executor_then_register(&census, Some(thread.clone()), || {
                assert!(
                    census.has_peer_executor(),
                    "census admission must precede registry publication"
                );
                assert!(
                    thread.is_crash_safe_point_participant(),
                    "crash participation must precede registry publication"
                );
                registry.subscribe_register(
                    second,
                    registration_test_handle(),
                    &second_in_guest,
                    Arc::new(|| {}),
                )
            })
            .expect("second participation");

        assert!(census.has_peer_executor());
        assert!(matches!(
            &attempt,
            carrick_hal::VcpuRegistrationEnrollment::Waiting { .. }
        ));
        assert_eq!(
            registry.poll_lease_drain(first),
            carrick_hal::VcpuLeaseDrainPoll::Complete
        );
        drop(second_participation);
        assert_eq!(census.participant_count_for_probe(), 1);
        drop(attempt);
        drop(freeze);
    }

    #[test]
    fn failed_crash_admission_suppresses_registry_publication() {
        let census = Arc::new(crate::kernel::GuestExecutorCensus::default());
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().expect("task context");
        let thread = context.thread().clone();
        let _outside = thread
            .enter_crash_safe_point_participation()
            .expect("outside crash participation");
        let register_called = std::sync::atomic::AtomicBool::new(false);

        assert!(matches!(
            enter_guest_executor_then_register(&census, Some(thread.clone()), || {
                register_called.store(true, std::sync::atomic::Ordering::Release);
                panic!("failed admission must not invoke registry publication")
            }),
            Err(crate::kernel::GuestExecutorCensusError::CrashParticipationAlreadyActive {
                thread: rejected
            }) if rejected == thread.key()
        ));
        assert!(!register_called.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(census.participant_count_for_probe(), 0);
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn fork_owner_registration_ignores_raised_barrier_and_preserves_phase() {
        let registry = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let census = Arc::new(crate::kernel::GuestExecutorCensus::default());
        let owner = ThreadId::synthetic_for_tests(70_203);
        let barrier = Arc::new(crate::fork_quiesce::QuiesceBarrier::new());
        assert!(barrier.try_begin_fork());
        barrier.set_quiescing();
        let phase = registration_test_retry_phase(None);
        let freeze = match registry.subscribe_lease_drain(owner, Arc::new(|| {})) {
            carrick_hal::VcpuLeaseDrainEnrollment::Frozen(guard) => guard,
            _ => panic!("owner must freeze an empty sibling lease set"),
        };
        let owner_in_guest = carrick_hal::InGuestFlag::for_guest_thread();

        let (participation, enrollment) = enter_guest_executor_then_register(&census, None, || {
            registry.subscribe_register(
                owner,
                registration_test_handle(),
                &owner_in_guest,
                Arc::new(|| {}),
            )
        })
        .expect("owner participation");

        assert!(matches!(
            enrollment,
            carrick_hal::VcpuRegistrationEnrollment::Registered
        ));
        assert!(matches!(
            phase,
            HvpatchProductionPhase::RetryProcessFork { .. }
        ));
        assert!(barrier.is_quiescing());
        registry.unregister(owner);
        drop(participation);
        barrier.end_quiesce();
        barrier.end_fork();
        drop(freeze);
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn registration_thaw_wakes_external_exec_control_quantum() {
        let (_process, context) = crate::hvpatch::process_context_for_tests(70_204);
        context
            .thread()
            .publish_initial_task_state(executor::tests::task_state(&context, 204))
            .expect("publish test task state");
        let scheduler = Arc::new(crate::kernel::Scheduler::new(Arc::clone(context.kernel())));
        scheduler
            .make_runnable(context.thread().key())
            .expect("queue test thread");
        let registry = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let owner = ThreadId::synthetic_for_tests(70_205);
        let waiter = ThreadId::synthetic_for_tests(70_204);
        let freeze = match registry.subscribe_lease_drain(owner, Arc::new(|| {})) {
            carrick_hal::VcpuLeaseDrainEnrollment::Frozen(guard) => guard,
            _ => panic!("owner must freeze an empty sibling lease set"),
        };
        let mut phase = registration_test_retry_phase(Some(registration_test_exec_work()));
        let wake_mode = registration_wake_uses_control(&phase, false);
        let wake_registration =
            registration_wake_callback(Arc::clone(&scheduler), context.thread().key(), wake_mode);
        let waiter_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let attempt = registry.subscribe_register(
            waiter,
            registration_test_handle(),
            &waiter_in_guest,
            wake_registration,
        );
        assert!(matches!(
            &attempt,
            carrick_hal::VcpuRegistrationEnrollment::Waiting { .. }
        ));
        assert!(
            context
                .thread()
                .scheduler_control_quantum(context.thread().key())
                .expect("inspect control quantum")
                .is_none()
        );

        phase = HvpatchProductionPhase::Resident;
        assert!(matches!(phase, HvpatchProductionPhase::Resident));
        drop(freeze);

        assert!(
            context
                .thread()
                .scheduler_control_quantum(context.thread().key())
                .expect("registration thaw control quantum")
                .is_some()
        );
        assert_eq!(scheduler.queued_len(), 1);
        drop(attempt);
    }

    #[test]
    fn registration_thaw_wakes_pending_control_quantum_before_phase_transition() {
        let (_process, context) = crate::hvpatch::process_context_for_tests(70_206);
        context
            .thread()
            .publish_initial_task_state(executor::tests::task_state(&context, 206))
            .expect("publish test task state");
        let scheduler = Arc::new(crate::kernel::Scheduler::new(Arc::clone(context.kernel())));
        scheduler
            .make_runnable(context.thread().key())
            .expect("queue test thread");
        scheduler
            .wake_control(context.thread().key())
            .expect("publish pending scheduler control quantum");
        let pending_control_quantum = context
            .thread()
            .scheduler_control_quantum(context.thread().key())
            .expect("inspect pending control quantum")
            .is_some();
        let phase = HvpatchProductionPhase::Resident;
        let wake_mode = registration_wake_uses_control(&phase, pending_control_quantum);
        let wake_registration =
            registration_wake_callback(Arc::clone(&scheduler), context.thread().key(), wake_mode);
        let registry = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let owner = ThreadId::synthetic_for_tests(70_207);
        let waiter = ThreadId::synthetic_for_tests(70_206);
        let freeze = match registry.subscribe_lease_drain(owner, Arc::new(|| {})) {
            carrick_hal::VcpuLeaseDrainEnrollment::Frozen(guard) => guard,
            _ => panic!("owner must freeze an empty sibling lease set"),
        };
        let waiter_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let attempt = registry.subscribe_register(
            waiter,
            registration_test_handle(),
            &waiter_in_guest,
            wake_registration,
        );
        assert!(matches!(
            &attempt,
            carrick_hal::VcpuRegistrationEnrollment::Waiting { .. }
        ));
        context
            .thread()
            .finish_scheduler_control_quantum(context.thread().key())
            .expect("simulate phase transition after captured wake mode");
        assert!(
            context
                .thread()
                .scheduler_control_quantum(context.thread().key())
                .expect("control quantum consumed for transition")
                .is_none()
        );

        drop(freeze);

        assert!(matches!(phase, HvpatchProductionPhase::Resident));
        assert!(
            context
                .thread()
                .scheduler_control_quantum(context.thread().key())
                .expect("registration thaw restores control quantum")
                .is_some()
        );
        assert_eq!(scheduler.queued_len(), 1);
        drop(attempt);
    }

    #[test]
    fn removed_persistent_job_is_settled_once_without_repoll_or_binding_cycle() {
        let (_process, context) = crate::hvpatch::process_context_for_tests(70_104);
        let task_state = executor::tests::task_state(&context, 104);
        let binding = executor::tests::hvpatch_test_binding(&context, &task_state, 104);
        let quantum_strong_before = Arc::strong_count(binding.quantum());
        let handles = VcpuThreadRegistry::default();
        let removed_result = HvpatchLoopResult::pending();
        let removed_completion = continuation::LogicalJobCompletion::pending();
        let removed = HvpatchExternalTerminalSettlement::new(
            removed_result.clone(),
            removed_completion.clone(),
        );
        let owner = HvpatchExternalTerminalSettlement::new(
            HvpatchLoopResult::pending(),
            continuation::LogicalJobCompletion::pending(),
        );
        enroll_persistent_process_member(&handles, &removed);
        enroll_persistent_process_member(&handles, &owner);
        assert_eq!(
            Arc::strong_count(binding.quantum()),
            quantum_strong_before,
            "process-member retention must not point back to binding/quantum/job"
        );

        let (published, _) = finish_persistent_process_handles(&handles, &owner.completion())
            .expect("removed Kernel thread settles without a job repoll");
        assert_eq!(published, 1);
        assert!(handles.is_empty());
        assert!(removed.result_is_ready());
        assert!(removed_completion.is_finished());
        assert!(matches!(
            removed_result.wait(),
            Ok(VcpuLoopOutcome::ThreadDone)
        ));
        assert!(
            !removed
                .publish_member(Ok(VcpuLoopOutcome::ThreadDone))
                .unwrap(),
            "external result authority is one-shot"
        );
        assert!(
            !owner.is_published(),
            "the exact current owner retains its separate outcome authority"
        );

        let consumed_result = HvpatchLoopResult::pending();
        let consumed = HvpatchExternalTerminalSettlement::new(
            consumed_result.clone(),
            continuation::LogicalJobCompletion::pending(),
        );
        consumed
            .publish_member(Ok(VcpuLoopOutcome::ThreadDone))
            .unwrap();
        assert!(matches!(
            consumed_result.wait(),
            Ok(VcpuLoopOutcome::ThreadDone)
        ));
        let consumed_handles = VcpuThreadRegistry::default();
        enroll_persistent_process_member(&consumed_handles, &consumed);
        enroll_persistent_process_member(&consumed_handles, &owner);
        let (published, _) =
            finish_persistent_process_handles(&consumed_handles, &owner.completion())
                .expect("already-consumed result retains durable settlement proof");
        assert_eq!(
            published, 0,
            "an already-consumed member is not republished"
        );
    }

    #[test]
    fn terminal_physical_retirement_includes_a_sole_current_member() {
        let handles = VcpuThreadRegistry::default();
        let current = continuation::LogicalJobCompletion::pending();

        let (published, completions) =
            finish_persistent_process_handles(&handles, &current).unwrap();

        assert_eq!(published, 0);
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0].id(), current.id());

        let current_settlement =
            HvpatchExternalTerminalSettlement::new(HvpatchLoopResult::pending(), current.clone());
        let sibling_completion = continuation::LogicalJobCompletion::pending();
        let sibling_settlement = HvpatchExternalTerminalSettlement::new(
            HvpatchLoopResult::pending(),
            sibling_completion.clone(),
        );
        enroll_persistent_process_member(&handles, &current_settlement);
        enroll_persistent_process_member(&handles, &sibling_settlement);

        let (published, completions) =
            finish_persistent_process_handles(&handles, &current).unwrap();
        assert_eq!(published, 1);
        assert_eq!(
            completions
                .iter()
                .filter(|completion| completion.id() == current.id())
                .count(),
            1,
            "the terminal owner must occur exactly once even when still enrolled"
        );
        assert!(
            completions
                .iter()
                .any(|completion| completion.id() == sibling_completion.id()),
            "every sibling physical completion must remain in the receipt"
        );
    }

    #[test]
    fn missing_terminal_publication_fails_but_an_externally_settled_sibling_stays_thread_done() {
        assert!(matches!(
            terminal_result_for_publication(None, HvpatchTerminalSettlementRole::Member),
            Err(RuntimeError::CarrierFailed(_))
        ));
        assert!(matches!(
            terminal_result_for_publication(None, HvpatchTerminalSettlementRole::ProcessOwner),
            Err(RuntimeError::Configuration(_))
        ));
        assert!(matches!(
            terminal_result_for_publication(
                Some(Ok(VcpuLoopOutcome::ThreadDone)),
                HvpatchTerminalSettlementRole::ProcessOwner
            ),
            Ok(VcpuLoopOutcome::ThreadDone)
        ));

        let member_result = HvpatchLoopResult::pending();
        let member_completion = continuation::LogicalJobCompletion::pending();
        let member = HvpatchExternalTerminalSettlement::new(
            member_result.clone(),
            member_completion.clone(),
        );
        assert!(
            member
                .publish_member(Ok(VcpuLoopOutcome::ThreadDone))
                .unwrap()
        );
        assert!(
            !member.publish_terminal(None),
            "the executor callback must not replace an exact external sibling settlement"
        );
        assert!(member_completion.is_finished());
        assert!(matches!(
            member_result.wait(),
            Ok(VcpuLoopOutcome::ThreadDone)
        ));

        let owner_result = HvpatchLoopResult::pending();
        let owner_completion = continuation::LogicalJobCompletion::pending();
        let owner =
            HvpatchExternalTerminalSettlement::new(owner_result.clone(), owner_completion.clone());
        owner.arm_process_owner().unwrap();
        assert!(owner.publish_terminal(None));
        assert!(owner_completion.is_finished());
        assert!(matches!(
            owner_result.wait(),
            Err(RuntimeError::Configuration(_))
        ));
    }

    #[test]
    fn persistent_exec_terminal_check_precedes_blocked_vfork_resume() {
        let source = include_str!("binding.rs");
        let poll = source
            .split("fn poll_with_engine(")
            .nth(1)
            .and_then(|tail| {
                tail.split("impl<E: ThreadedEngine + 'static> ProductionHvpatchLoopPoll")
                    .next()
            })
            .expect("production poll body");
        let terminal = poll
            .find("thread_should_finish_for_exec_replacement")
            .expect("top-of-quantum exec terminal check");
        let phase = poll
            .find("let phase = std::mem::replace")
            .expect("phase dispatch");
        assert!(
            terminal < phase,
            "a forced vfork wake must exit before ResumeBlocked"
        );
    }

    #[test]
    fn persistent_terminal_transition_phases_are_not_aborted_by_process_exiting() {
        let context = alias_context(70_105);
        assert!(
            HvpatchProductionPhase::TerminalClaimRetry {
                terminal: PersistentTerminal::from_outcome(VcpuLoopOutcome::ThreadDone),
                context: context.retain_exact(),
                _subscription: None,
            }
            .is_terminal_transition()
        );
        assert!(
            HvpatchProductionPhase::TerminalProcessDrain {
                terminal: PersistentTerminal::from_outcome(VcpuLoopOutcome::ThreadDone),
                context: context.retain_exact(),
                drain: continuation::ProcessDrain::excluding(
                    continuation::LogicalJobCompletion::pending(),
                    Vec::new(),
                ),
            }
            .is_terminal_transition()
        );
        assert!(!HvpatchProductionPhase::Resident.is_terminal_transition());
        assert!(
            !HvpatchProductionPhase::ResumeBlocked {
                frame: carrick_hal::RawSyscall {
                    number: carrick_abi::CanonicalNr(0),
                    args: [0; 6],
                    guest_abi: carrick_abi::LinuxGuestAbi::Aarch64,
                    native_number: carrick_abi::NativeNr(0),
                },
                vfork_child_pid: None,
            }
            .is_terminal_transition()
        );
    }

    fn deferred_frame() -> carrick_hal::RawSyscall {
        carrick_hal::RawSyscall {
            number: carrick_abi::CanonicalNr(101),
            args: [1, 2, 3, 4, 5, 6],
            guest_abi: carrick_abi::LinuxGuestAbi::Aarch64,
            native_number: carrick_abi::NativeNr(202),
        }
    }

    fn assert_deferred_resume_exact(
        phase: &HvpatchProductionPhase,
        expected_frame: carrick_hal::RawSyscall,
        expected_vfork_child: Option<i32>,
    ) {
        let HvpatchProductionPhase::ResumeBlocked {
            frame,
            vfork_child_pid,
        } = phase
        else {
            panic!("deferred phase was not restored to ResumeBlocked");
        };
        assert_eq!(*frame, expected_frame);
        assert_eq!(*vfork_child_pid, expected_vfork_child);
    }

    #[test]
    fn control_exec_complete_restores_exact_blocked_frame_and_vfork_identity() {
        let frame = deferred_frame();
        let original = HvpatchProductionPhase::ResumeBlocked {
            frame,
            vfork_child_pid: Some(70_106),
        };
        let deferred = DeferredResumeBlocked::capture(
            &original,
            Some(crate::kernel::objects::BlockedReason::HostWait),
        )
        .expect("capture ResumeBlocked");
        let mut after_peer_publication = HvpatchProductionPhase::Resident;
        deferred.restore(&mut after_peer_publication);
        assert_deferred_resume_exact(&after_peer_publication, frame, Some(70_106));
    }

    #[test]
    fn control_exec_retry_carries_exact_blocked_frame_and_vfork_identity() {
        fn carry_retry_token(token: DeferredResumeBlocked) -> Option<DeferredResumeBlocked> {
            Some(token)
        }

        let frame = deferred_frame();
        let original = HvpatchProductionPhase::ResumeBlocked {
            frame,
            vfork_child_pid: Some(70_107),
        };
        let retry_token = carry_retry_token(
            DeferredResumeBlocked::capture(
                &original,
                Some(crate::kernel::objects::BlockedReason::HostWait),
            )
            .expect("capture ResumeBlocked"),
        );
        let mut after_retry = HvpatchProductionPhase::Resident;
        retry_token
            .expect("RetryProcessFork carries deferred token")
            .restore(&mut after_retry);
        assert_deferred_resume_exact(&after_retry, frame, Some(70_107));
    }

    #[test]
    fn control_exec_completion_clear_then_rechecks_coalesced_queue() {
        let source = include_str!("binding.rs");
        let finish = source
            .split_once("fn finish_control_quantum(")
            .expect("control completion helper")
            .1
            .split_once("fn begin_control_exec_fork(")
            .expect("end control completion helper")
            .0;
        let clear = finish
            .find("finish_scheduler_control_quantum")
            .expect("atomically clear current marker");
        let recheck = finish
            .find("try_take_control_exec")
            .expect("recheck queued work");
        let restore = finish
            .find("restore_scheduler_control_quantum")
            .expect("restore displaced continuation for next work");
        let continue_work = finish
            .find("begin_control_exec_fork")
            .expect("service next work in same root quantum");
        assert!(clear < recheck && recheck < restore && restore < continue_work);
    }

    #[test]
    fn persistent_exec_stop_control_wakes_unreleased_vfork_parent_without_guest_readiness() {
        let (process, root) = crate::hvpatch::process_context_for_tests(70_103);
        let plan = crate::kernel::ClonePlan::from_flags(
            carrick_abi::LinuxCloneFlags::THREAD
                | carrick_abi::LinuxCloneFlags::SIGHAND
                | carrick_abi::LinuxCloneFlags::VM,
        )
        .expect("thread clone plan");
        let sibling_tid = ThreadId::synthetic_for_tests(70_104);
        let sibling = process
            .kernel_graph()
            .reserve_thread_clone(&root, plan, None)
            .expect("reserve sibling")
            .prepare(sibling_tid)
            .expect("prepare sibling")
            .commit()
            .expect("publish sibling")
            .start_thread()
            .expect("start sibling")
            .into_context();
        let root_state = executor::tests::task_state(&root, 710);
        let sibling_state = executor::tests::task_state(&sibling, 711);
        root.thread()
            .publish_initial_task_state(root_state)
            .expect("publish root state");
        sibling
            .thread()
            .publish_initial_task_state(sibling_state)
            .expect("publish sibling state");
        let executor = crate::kernel::objects::ExecutorId::for_transitional_thread(
            ThreadId::synthetic_for_tests(71),
        )
        .expect("test executor");
        let lease = root
            .thread()
            .claim_runnable(executor)
            .expect("claim leader");
        let published = process
            .kernel_graph()
            .reserve_fork(
                &root,
                crate::kernel::ClonePlan::from_flags(
                    carrick_abi::LinuxCloneFlags::VFORK | carrick_abi::LinuxCloneFlags::VM,
                )
                .expect("vfork plan"),
                "persistent exec-stop vfork parent".to_owned(),
                None,
            )
            .expect("reserve vfork")
            .prepare_reference(ThreadId::synthetic_for_tests(70_105))
            .expect("prepare vfork child")
            .commit()
            .expect("publish vfork child");
        let (vfork_child, vfork_wait) = published.into_parts().expect("start vfork child");
        let current = root
            .task_binding()
            .capture(root.thread().key().tid)
            .expect("recapture vfork parent");
        let continuation = continuation::BlockedContinuation::from_vfork_parent(
            continuation::ContinuationCapture::from_lease(
                &current,
                &lease,
                SyscallRequest::new(220, crate::compat::SyscallArgs([0; 6])),
                continuation::RestartClass::RestartSyscall,
                continuation::ContinuationBackend::Hvpatch,
            )
            .expect("capture vfork parent"),
            vfork_child.task().key(),
            vfork_wait.expect("vfork parent wait"),
        )
        .expect("construct vfork parent continuation");
        root.thread()
            .scheduler_park_continuation_from_executor(
                lease,
                crate::kernel::objects::BlockedReason::ChildState,
                continuation,
            )
            .map_err(|(error, _)| error)
            .expect("block vfork leader");
        let directory = HvpatchRuntimeDirectory::default();
        let (scheduler, _) = directory.continuation_services(root.kernel());

        threads::wake_removed_persistent_sibling_threads(
            &sibling,
            &scheduler,
            &[ThreadId::synthetic_for_tests(root.thread().key().tid.raw())],
        )
        .expect("wake exact removed leader");

        assert!(matches!(
            root.thread().execution_state(),
            crate::kernel::objects::ThreadExecutionState::Runnable { .. }
        ));
        assert_eq!(scheduler.queued_len(), 1);
        let claimed = root
            .thread()
            .claim_runnable(executor)
            .expect("claim control-woken vfork parent");
        assert!(
            claimed
                .blocked_continuation()
                .expect("preserved vfork continuation")
                .ready_event()
                .is_err(),
            "terminal control wake must not manufacture guest vfork readiness",
        );
        root.thread()
            .exit_from_executor(claimed)
            .expect("retire control-woken vfork parent");
    }
}
