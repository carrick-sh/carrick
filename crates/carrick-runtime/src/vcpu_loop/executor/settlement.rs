//! Execution exit, state save, boundary auditing, and task settlement for the HVPatch executor.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::mpsc;

use crate::dispatch::SyscallDispatcher;
use crate::kernel::objects::{
    BlockedReason, ExecutionFailure, ExecutionGeneration, ExecutorId, MigratableTaskState,
    ThreadExecutionLease, ThreadExecutionState, ThreadKey,
};
use crate::kernel::{ExecutorKick as _, ExecutorRegistration, RunnableThread, Scheduler};
use crate::trap::TrapError;

use super::binding::{PersistentTaskBinding, PreparedVforkChildActivation, TaskBindingResolver};
use super::probe_executor_lifecycle;
use super::{ExecutorPoolEvent, PersistentExecutor, ReceiptLog, WorkerCommand, WorkerKick};

pub struct RunnableTask<'a, B> {
    pub(crate) thread: ThreadKey,
    pub(crate) generation: ExecutionGeneration,
    pub(crate) lease: &'a ThreadExecutionLease,
    pub(crate) binding: Arc<B>,
}

impl<B> RunnableTask<'_, B> {
    pub const fn thread_key(&self) -> ThreadKey {
        self.thread
    }

    pub const fn generation(&self) -> ExecutionGeneration {
        self.generation
    }

    pub const fn lease(&self) -> &ThreadExecutionLease {
        self.lease
    }

    pub const fn binding(&self) -> &Arc<B> {
        &self.binding
    }
}

impl<B: PersistentTaskBinding> RunnableTask<'_, B> {
    pub fn validate_for_load(&self) -> Result<&MigratableTaskState, TrapError> {
        let identity = self.binding.load_identity();
        let state = self
            .lease
            .task_state_for_restore(
                identity.abi,
                identity.version,
                identity.mm,
                identity.asid_generation,
            )
            .map_err(|error| {
                TrapError::Hypervisor(format!(
                    "persistent executor rejected task migration authority: {error}"
                ))
            })?;
        self.binding.validate_task_state(state)?;
        Ok(state)
    }
}

#[derive(Debug)]
pub(crate) enum ExecutorExit {
    Syscall,
    Blocked(BlockedReason),
    BlockedContinuation {
        continuation: Box<crate::vcpu_loop::continuation::BlockedContinuation>,
        vfork_activation: Option<PreparedVforkChildActivation>,
    },
    Yielded,
    Preempted,
    Quiesced,
    Exited,
    InvalidState,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExecutorCpuReceipt {
    pub user_ns: u64,
    pub system_ns: u64,
}

pub struct SavedRunnable {
    pub(crate) lease: ThreadExecutionLease,
}

impl SavedRunnable {
    pub fn new(lease: ThreadExecutionLease) -> Self {
        Self { lease }
    }

    pub(crate) fn into_lease(self) -> ThreadExecutionLease {
        self.lease
    }
}

pub struct ExecutorSaveError {
    pub(crate) error: Box<TrapError>,
    pub(crate) lease: Box<ThreadExecutionLease>,
}

impl ExecutorSaveError {
    pub fn new(error: TrapError, lease: ThreadExecutionLease) -> Self {
        Self {
            error: Box::new(error),
            lease: Box::new(lease),
        }
    }

    pub(crate) fn into_parts(self) -> (TrapError, ThreadExecutionLease) {
        (*self.error, *self.lease)
    }
}

impl std::fmt::Debug for ExecutorSaveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutorSaveError")
            .field("error", &self.error)
            .field("lease", &self.lease)
            .finish()
    }
}

impl std::fmt::Display for ExecutorSaveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for ExecutorSaveError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutorStateDisposition {
    ExecutorLocal,
    TaskMigrated,
    BoundaryReset,
    Prohibited,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutorBoundaryInventoryEntry {
    pub name: &'static str,
    pub disposition: ExecutorStateDisposition,
}

const BOUNDARY_INVENTORY: &[ExecutorBoundaryInventoryEntry] = &[
    ExecutorBoundaryInventoryEntry {
        name: "vcpu-owner",
        disposition: ExecutorStateDisposition::ExecutorLocal,
    },
    ExecutorBoundaryInventoryEntry {
        name: "owner-pthread-mach-port",
        disposition: ExecutorStateDisposition::ExecutorLocal,
    },
    ExecutorBoundaryInventoryEntry {
        name: "topology-depth",
        disposition: ExecutorStateDisposition::BoundaryReset,
    },
    ExecutorBoundaryInventoryEntry {
        name: "stage1-depth",
        disposition: ExecutorStateDisposition::BoundaryReset,
    },
    ExecutorBoundaryInventoryEntry {
        name: "need-resched",
        disposition: ExecutorStateDisposition::ExecutorLocal,
    },
    ExecutorBoundaryInventoryEntry {
        name: "exact-kick-binding",
        disposition: ExecutorStateDisposition::ExecutorLocal,
    },
    ExecutorBoundaryInventoryEntry {
        name: "signal-progress",
        disposition: ExecutorStateDisposition::BoundaryReset,
    },
    ExecutorBoundaryInventoryEntry {
        name: "task-signal-restart",
        disposition: ExecutorStateDisposition::TaskMigrated,
    },
    ExecutorBoundaryInventoryEntry {
        name: "task-mailbox-continuation",
        disposition: ExecutorStateDisposition::TaskMigrated,
    },
    ExecutorBoundaryInventoryEntry {
        name: "task-mapping-mm-asid",
        disposition: ExecutorStateDisposition::TaskMigrated,
    },
    ExecutorBoundaryInventoryEntry {
        name: "task-cpu-accounting",
        disposition: ExecutorStateDisposition::TaskMigrated,
    },
    ExecutorBoundaryInventoryEntry {
        name: "logical-mq-wait-state",
        disposition: ExecutorStateDisposition::TaskMigrated,
    },
    ExecutorBoundaryInventoryEntry {
        name: "active-kernel-context",
        disposition: ExecutorStateDisposition::BoundaryReset,
    },
    ExecutorBoundaryInventoryEntry {
        name: "hvf-fork-snapshot",
        disposition: ExecutorStateDisposition::BoundaryReset,
    },
    ExecutorBoundaryInventoryEntry {
        name: "sysv-mq-fd-cache",
        disposition: ExecutorStateDisposition::BoundaryReset,
    },
    ExecutorBoundaryInventoryEntry {
        name: "fanotify-internal-open-depth",
        disposition: ExecutorStateDisposition::BoundaryReset,
    },
    ExecutorBoundaryInventoryEntry {
        name: "path-resolution-depth",
        disposition: ExecutorStateDisposition::BoundaryReset,
    },
    ExecutorBoundaryInventoryEntry {
        name: "host-signal-mask",
        disposition: ExecutorStateDisposition::BoundaryReset,
    },
    ExecutorBoundaryInventoryEntry {
        name: "raw-task-pointer-or-fd",
        disposition: ExecutorStateDisposition::Prohibited,
    },
    ExecutorBoundaryInventoryEntry {
        name: "mailbox-slot-pointer-generation",
        disposition: ExecutorStateDisposition::Prohibited,
    },
    ExecutorBoundaryInventoryEntry {
        name: "host-waiter-task-identity",
        disposition: ExecutorStateDisposition::Prohibited,
    },
];

#[derive(Clone, Copy, Debug, Default)]
pub struct ExecutorBoundaryAudit;

impl ExecutorBoundaryAudit {
    pub const fn production() -> Self {
        Self
    }

    pub const fn inventory(self) -> &'static [ExecutorBoundaryInventoryEntry] {
        BOUNDARY_INVENTORY
    }
}

#[derive(Debug)]
pub(crate) struct WorkerBoundaryAudit {
    baseline_signal_mask: Vec<bool>,
}

impl WorkerBoundaryAudit {
    pub(crate) fn capture() -> Result<Self, TrapError> {
        Ok(Self {
            baseline_signal_mask: current_signal_mask()?,
        })
    }

    pub(crate) fn audit_runtime_owned(&self) -> Result<(), TrapError> {
        // A boundary ends this host thread's authority over whatever logical
        // thread it was running, and the system-CPU charge window is exactly
        // that authority: commit and close it here, BEFORE the audit, so no
        // path out of a residency — including the error paths that skip the
        // ordinary close — can leave the window open for a different logical
        // thread to inherit. Idempotent: a closed window costs nothing.
        crate::kernel::close_system_charge_window();
        if !crate::kernel::system_charge_window_is_closed() {
            return Err(boundary_error("system-charge-window"));
        }
        if !carrick_thread::fork_quiesce::topology_depth_is_zero_for_executor_boundary() {
            return Err(boundary_error("topology-depth"));
        }
        if !SyscallDispatcher::executor_boundary_path_resolution_is_clear() {
            return Err(boundary_error("path-resolution-depth"));
        }
        if !crate::dispatch::resources::executor_boundary_is_clear() {
            return Err(boundary_error("active-kernel-context"));
        }
        if crate::fanotify::internal_open_in_progress() {
            return Err(boundary_error("fanotify-internal-open-depth"));
        }
        let _ = SyscallDispatcher::reset_sysv_executor_boundary_state();
        let _previous_signal_progress =
            crate::vcpu_loop::reset_signal_progress_for_executor_boundary();
        if !crate::vcpu_loop::signal_progress_is_zero_for_executor_boundary() {
            return Err(boundary_error("signal-progress"));
        }
        let current_signal_mask = current_signal_mask()?;
        if current_signal_mask != self.baseline_signal_mask {
            let added: Vec<_> = current_signal_mask
                .iter()
                .zip(&self.baseline_signal_mask)
                .enumerate()
                .filter_map(|(index, (current, baseline))| {
                    (*current && !*baseline).then_some(index + 1)
                })
                .collect();
            let removed: Vec<_> = current_signal_mask
                .iter()
                .zip(&self.baseline_signal_mask)
                .enumerate()
                .filter_map(|(index, (current, baseline))| {
                    (!*current && *baseline).then_some(index + 1)
                })
                .collect();
            return Err(TrapError::Hypervisor(format!(
                "persistent executor boundary audit failed: host-signal-mask: added={added:?}, removed={removed:?}"
            )));
        }
        Ok(())
    }

    pub(crate) fn audit_runtime<E: PersistentExecutor>(
        &self,
        backend: &mut E,
    ) -> Result<(), TrapError> {
        self.audit_runtime_owned()?;
        backend.audit_boundary()
    }

    pub(crate) fn audit_clean<E: PersistentExecutor>(
        &self,
        backend: &mut E,
        kick: &WorkerKick,
    ) -> Result<(), TrapError> {
        self.audit_runtime(backend)?;
        if kick.current_binding().is_some() {
            return Err(boundary_error("exact-kick-binding"));
        }
        Ok(())
    }
}

pub(crate) fn boundary_error(name: &str) -> TrapError {
    TrapError::Hypervisor(format!("persistent executor boundary audit failed: {name}"))
}

pub(crate) fn audit_backend_hardware<E: PersistentExecutor>(
    backend: &E,
    kick: &WorkerKick,
) -> Result<(), TrapError> {
    let observed = backend.hardware_kick()?;
    kick.audit_hardware(&observed)
}

pub(crate) fn current_signal_mask() -> Result<Vec<bool>, TrapError> {
    let mut mask = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    let result = unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask) };
    if result != 0 {
        return Err(TrapError::Hypervisor(format!(
            "pthread_sigmask boundary observation failed: {result}"
        )));
    }
    #[cfg(target_os = "macos")]
    const MAX_SIGNAL: libc::c_int = 31;
    #[cfg(not(target_os = "macos"))]
    const MAX_SIGNAL: libc::c_int = 64;
    let mut members = Vec::with_capacity(usize::try_from(MAX_SIGNAL).unwrap_or(0));
    for signal in 1..=MAX_SIGNAL {
        let member = unsafe { libc::sigismember(&mask, signal) };
        if member < 0 {
            return Err(TrapError::Hypervisor(format!(
                "sigismember boundary observation failed for signal {signal}"
            )));
        }
        members.push(member == 1);
    }
    Ok(members)
}

pub(crate) fn terminal_drain<B, R>(
    scheduler: &Scheduler,
    resolver: &R,
    registration: &ExecutorRegistration,
    receipts: &ReceiptLog,
) -> Result<(), String>
where
    B: PersistentTaskBinding + Send + Sync + 'static,
    R: TaskBindingResolver<B>,
{
    scheduler.close();
    resolver
        .cancel_dormant(scheduler, ExecutionFailure::SnapshotRestoreFailed)
        .map_err(|error| error.to_string())?;
    scheduler
        .clear_executor_binding(registration)
        .map_err(|error| error.to_string())?;
    loop {
        let running = match scheduler.take(registration) {
            Ok(running) => running,
            Err(crate::kernel::RunQueueError::Closed) => return Ok(()),
            Err(error) => return Err(error.to_string()),
        };
        let executor = running.executor();
        let thread = running.thread_key();
        let generation = running.generation();
        receipts.record(executor, ExecutorPoolEvent::Claimed { thread, generation });
        if let Some(error) = fail_running_and_retire::<B, _>(
            resolver,
            scheduler,
            running,
            ExecutionFailure::SnapshotRestoreFailed,
            receipts,
        ) {
            return Err(error);
        }
    }
}

pub(crate) fn executor_boundary_event_code(exit: &ExecutorExit) -> i32 {
    match exit {
        ExecutorExit::Blocked(BlockedReason::ChildState) => 1,
        ExecutorExit::Blocked(BlockedReason::HostWait) => 2,
        ExecutorExit::BlockedContinuation { .. } => 3,
        ExecutorExit::Yielded => 4,
        ExecutorExit::Preempted => 5,
        ExecutorExit::Quiesced => 6,
        ExecutorExit::Exited => 7,
        ExecutorExit::InvalidState => 8,
        ExecutorExit::Syscall => 0,
    }
}

pub(crate) fn thread_settlement_event_code(state: ThreadExecutionState) -> i32 {
    match state {
        ThreadExecutionState::Runnable { .. } => 1,
        ThreadExecutionState::Blocked {
            reason: BlockedReason::ChildState,
            ..
        } => 2,
        ThreadExecutionState::Blocked {
            reason: BlockedReason::HostWait,
            ..
        } => 3,
        ThreadExecutionState::Exited { .. } => 4,
        ThreadExecutionState::Failed { .. } => 5,
        ThreadExecutionState::Running { .. } => 6,
        ThreadExecutionState::SwitchingOut { .. } => 7,
        ThreadExecutionState::Uninitialized => 8,
    }
}

pub(crate) fn service_owner_thread_commands<E: PersistentExecutor>(
    backend: &mut E,
    executor: ExecutorId,
    commands: &mpsc::Receiver<WorkerCommand>,
    boundary: &WorkerBoundaryAudit,
    receipts: &ReceiptLog,
) -> Result<bool, String> {
    loop {
        match commands.try_recv() {
            Ok(WorkerCommand::InvalidateAsid {
                generation,
                response,
            }) => {
                if let Err(error) = boundary.audit_runtime(backend) {
                    let message = format!(
                        "executor {executor:?} failed boundary audit before ASID invalidation: {error}"
                    );
                    let _ = response.send(Err(message.clone()));
                    return Err(message);
                }
                if let Err(error) = backend.invalidate_asid(generation) {
                    let message = format!(
                        "executor {executor:?} failed ASID generation {} invalidation: {error}",
                        generation.generation()
                    );
                    let _ = response.send(Err(message.clone()));
                    return Err(message);
                }
                receipts.record(
                    executor,
                    ExecutorPoolEvent::InvalidatedAsid {
                        generation: generation.generation(),
                    },
                );
                probe_executor_lifecycle(
                    executor,
                    crate::probes::HvpatchExecutorLifecyclePhase::InvalidateAsid,
                    None,
                    None,
                    generation.generation(),
                );
                let _ = response.send(Ok(crate::hvpatch::InvalidationAck::new(
                    executor, generation,
                )));
            }
            Ok(WorkerCommand::Stop) | Err(mpsc::TryRecvError::Disconnected) => return Ok(true),
            Err(mpsc::TryRecvError::Empty) => return Ok(false),
            Ok(WorkerCommand::Initialize | WorkerCommand::Run) => {
                return Err("executor received an invalid owner-thread command".to_owned());
            }
        }
    }
}

pub(crate) fn acquire_process_retire_topology_lock_servicing<E: PersistentExecutor>(
    pid: i32,
    tid: i32,
    backend: &mut E,
    executor: ExecutorId,
    commands: &mpsc::Receiver<WorkerCommand>,
    boundary: &WorkerBoundaryAudit,
    receipts: &ReceiptLog,
) -> Result<(carrick_thread::fork_quiesce::TopologyLockGuard, bool), String> {
    let mut deferred_stop = false;
    let mut recorded_retry = false;
    let mut backoff = std::time::Duration::from_micros(50);
    let max_backoff = std::time::Duration::from_millis(5);
    loop {
        if let Some(guard) = carrick_thread::fork_quiesce::try_acquire_topology_lock(
            carrick_observability::probes::HvpatchTopologyOperation::ProcessRetire,
            pid,
            tid,
        ) {
            return Ok((guard, deferred_stop));
        }
        if !recorded_retry {
            receipts.record(
                executor,
                ExecutorPoolEvent::TopologyRetrying {
                    operation:
                        carrick_observability::probes::HvpatchTopologyOperation::ProcessRetire,
                },
            );
            recorded_retry = true;
        }
        let stop_seen =
            service_owner_thread_commands(backend, executor, commands, boundary, receipts)?;
        deferred_stop |= stop_seen;
        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(max_backoff);
    }
}

pub(crate) fn fail_running(
    scheduler: &Scheduler,
    running: RunnableThread,
    reason: ExecutionFailure,
    receipts: &ReceiptLog,
) -> Option<String> {
    let executor = running.executor();
    let thread = running.thread_key();
    let generation = running.generation();
    let settlement_error = scheduler.settle_failed(running, reason).err();
    receipts.record(executor, ExecutorPoolEvent::Failed { thread, generation });
    settlement_error.map(|error| error.to_string())
}

#[track_caller]
pub(crate) fn fail_running_and_retire<B, R>(
    resolver: &R,
    scheduler: &Scheduler,
    running: RunnableThread,
    reason: ExecutionFailure,
    receipts: &ReceiptLog,
) -> Option<String>
where
    B: PersistentTaskBinding + Send + Sync + 'static,
    R: TaskBindingResolver<B>,
{
    let thread = running.thread_key();
    let generation = running.generation();
    let resolved = resolver.resolve(thread, generation);
    // Naming the settle site is the difference between "a claimed task was
    // failed" and a diagnosis: `run_executor_loop` has more than a dozen arms
    // that all settle `SnapshotRestoreFailed`, and reading the wrong one costs
    // an investigation. `#[track_caller]` gives the exact arm for free.
    tracing::error!(
        ?thread,
        ?generation,
        ?reason,
        resolved = resolved.is_ok(),
        resolve_error = resolved.as_ref().err().map(ToString::to_string),
        site = %std::panic::Location::caller(),
        "executor failed a claimed task"
    );
    let binding = resolved.ok();
    let result = fail_running(scheduler, running, reason, receipts);
    resolver.retire(thread, generation);
    if let Some(binding) = binding {
        binding.after_executor_failure_settlement();
    }
    result
}

#[cfg(test)]
pub(crate) fn fail_running_and_retire_for_test<B, R>(
    resolver: &R,
    scheduler: &Scheduler,
    running: RunnableThread,
    reason: ExecutionFailure,
) -> Option<String>
where
    B: PersistentTaskBinding + Send + Sync + 'static,
    R: TaskBindingResolver<B>,
{
    fail_running_and_retire::<B, R>(resolver, scheduler, running, reason, &ReceiptLog::default())
}

pub(crate) fn with_settlement_error(mut source: String, settlement: Option<String>) -> String {
    if let Some(settlement) = settlement {
        source.push_str("; exact failure settlement failed: ");
        source.push_str(&settlement);
    }
    source
}

pub(crate) fn destroy_and_unregister<E: PersistentExecutor>(
    backend: E,
    scheduler: &Scheduler,
    registration: &ExecutorRegistration,
    kick: &WorkerKick,
    receipts: &ReceiptLog,
) -> Option<String> {
    let executor = registration.id();
    let observed_hardware = catch_unwind(AssertUnwindSafe(|| backend.hardware_kick()));
    let hardware_error = match &observed_hardware {
        Ok(Ok(observed)) => kick
            .audit_hardware(observed)
            .err()
            .map(|error| format!("executor shutdown hardware audit failed: {error}")),
        Ok(Err(error)) => Some(format!(
            "executor shutdown hardware observation failed: {error}"
        )),
        Err(_) => Some("executor shutdown hardware observation panicked".to_owned()),
    };
    let destroy = catch_unwind(AssertUnwindSafe(|| backend.destroy()));
    let destroy_error = match destroy {
        Ok(Ok(())) => {
            receipts.record(executor, ExecutorPoolEvent::Destroyed);
            probe_executor_lifecycle(
                executor,
                crate::probes::HvpatchExecutorLifecyclePhase::Destroy,
                None,
                None,
                0,
            );
            None
        }
        Ok(Err(error)) => Some(format!("executor destroy failed: {error}")),
        Err(_) => Some("executor destroy panicked".to_owned()),
    };
    let retired_hardware = kick.hardware.lock().take();
    let retirement_error = match (&observed_hardware, retired_hardware.as_ref()) {
        (Ok(Ok(observed)), Some(published))
            if observed.raw_vcpu_id == published.raw_vcpu_id
                && observed.owner_thread_port == published.owner_thread_port =>
        {
            None
        }
        (_, Some(_)) => Some("executor shutdown cleared mismatched hardware identity".to_owned()),
        (_, None) => Some("executor shutdown found no published hardware identity".to_owned()),
    };
    let unregister_error = scheduler
        .unregister_executor(registration)
        .err()
        .map(|error| format!("executor unregister failed: {error}"));
    let mut failures = Vec::new();
    failures.extend(hardware_error);
    failures.extend(destroy_error);
    failures.extend(retirement_error);
    failures.extend(unregister_error);
    (!failures.is_empty()).then(|| failures.join("; "))
}
