//! Persistent owner-thread executor pool used to prove the HVPatch M:N
//! lifecycle before a real HVF backend is wired to it.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;

use parking_lot::Mutex;

use crate::dispatch::SyscallDispatcher;
use crate::kernel::objects::{
    BlockedReason, ExecutionFailure, ExecutionGeneration, ExecutorId, ThreadExecutionLease,
    ThreadKey,
};
use crate::kernel::{
    ExecutorBinding, ExecutorKick, ExecutorKickToken, ExecutorRegistration, RunnableThread,
    Scheduler,
};
use crate::trap::TrapError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutorPoolConfig {
    pub physical_cores: usize,
    pub vcpu_ceiling: usize,
    pub reserve: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ExecutorPoolConfigError {
    #[error("the backend reports zero available vCPUs")]
    ZeroVcpuCeiling,
}

impl ExecutorPoolConfig {
    pub fn executor_count(self) -> Result<usize, ExecutorPoolConfigError> {
        if self.vcpu_ceiling == 0 {
            return Err(ExecutorPoolConfigError::ZeroVcpuCeiling);
        }
        let available = self.vcpu_ceiling.saturating_sub(self.reserve);
        Ok(self.physical_cores.min(available).max(1))
    }
}

pub trait PersistentExecutorFactory: Send + Sync + 'static {
    type Executor: PersistentExecutor;

    fn create(&self, executor: ExecutorId) -> Result<Self::Executor, TrapError>;
}

pub trait PersistentExecutor: 'static {
    type TaskBinding: Send + Sync + 'static;

    fn load(&mut self, task: &RunnableTask<'_, Self::TaskBinding>) -> Result<(), TrapError>;

    fn run_until_boundary(&mut self, need_resched: &AtomicBool) -> Result<ExecutorExit, TrapError>;

    fn take_cpu_receipt(&mut self) -> ExecutorCpuReceipt;

    fn save(&mut self, lease: ThreadExecutionLease) -> Result<SavedRunnable, ExecutorSaveError>;

    fn invalidate_asid(&mut self, generation: u64) -> Result<(), TrapError>;

    /// Backend-owned state that the runtime crate cannot inspect (HVF fork
    /// snapshot, vCPU/mailbox owner identity, invariant EL1 state) is audited
    /// here on the executor's owner pthread.
    fn audit_boundary(&mut self) -> Result<(), TrapError>;

    fn destroy(self) -> Result<(), TrapError>;
}

pub trait TaskBindingResolver<B>: Send + Sync + 'static {
    fn resolve(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
    ) -> Result<Arc<B>, TrapError>;
}

pub struct RunnableTask<'a, B> {
    thread: ThreadKey,
    generation: ExecutionGeneration,
    lease: &'a ThreadExecutionLease,
    binding: Arc<B>,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutorExit {
    Syscall,
    Blocked(BlockedReason),
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
    lease: ThreadExecutionLease,
}

impl SavedRunnable {
    pub fn new(lease: ThreadExecutionLease) -> Self {
        Self { lease }
    }

    fn into_lease(self) -> ThreadExecutionLease {
        self.lease
    }
}

pub struct ExecutorSaveError {
    error: Box<TrapError>,
    lease: Box<ThreadExecutionLease>,
}

impl ExecutorSaveError {
    pub fn new(error: TrapError, lease: ThreadExecutionLease) -> Self {
        Self {
            error: Box::new(error),
            lease: Box::new(lease),
        }
    }

    fn into_parts(self) -> (TrapError, ThreadExecutionLease) {
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
        name: "sysv-mq-wait-cache",
        disposition: ExecutorStateDisposition::BoundaryReset,
    },
    ExecutorBoundaryInventoryEntry {
        name: "sysv-mq-blocked-ids",
        disposition: ExecutorStateDisposition::BoundaryReset,
    },
    ExecutorBoundaryInventoryEntry {
        name: "fanotify-internal-open-depth",
        disposition: ExecutorStateDisposition::BoundaryReset,
    },
    ExecutorBoundaryInventoryEntry {
        name: "dispatch-lock-order-depth",
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
struct WorkerBoundaryAudit {
    baseline_signal_mask: Vec<bool>,
}

impl WorkerBoundaryAudit {
    fn capture() -> Result<Self, TrapError> {
        Ok(Self {
            baseline_signal_mask: current_signal_mask()?,
        })
    }

    fn audit_runtime<E: PersistentExecutor>(&self, backend: &mut E) -> Result<(), TrapError> {
        if !carrick_thread::fork_quiesce::topology_depth_is_zero_for_executor_boundary() {
            return Err(boundary_error("topology-depth"));
        }
        if !crate::dispatch::lock_order::executor_boundary_is_clear() {
            return Err(boundary_error("dispatch-lock-order-depth"));
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
        if !SyscallDispatcher::reset_sysv_executor_boundary_state() {
            return Err(boundary_error("sysv-mq-blocked-ids"));
        }
        let _previous_signal_progress = super::reset_signal_progress_for_executor_boundary();
        if !super::signal_progress_is_zero_for_executor_boundary() {
            return Err(boundary_error("signal-progress"));
        }
        if current_signal_mask()? != self.baseline_signal_mask {
            return Err(boundary_error("host-signal-mask"));
        }
        backend.audit_boundary()
    }

    fn audit_clean<E: PersistentExecutor>(
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

fn boundary_error(name: &str) -> TrapError {
    TrapError::Hypervisor(format!("persistent executor boundary audit failed: {name}"))
}

fn current_signal_mask() -> Result<Vec<bool>, TrapError> {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutorPoolEvent {
    Created,
    AuditPassed,
    Claimed {
        thread: ThreadKey,
        generation: ExecutionGeneration,
    },
    Loaded {
        thread: ThreadKey,
        generation: ExecutionGeneration,
    },
    OrdinarySyscall {
        thread: ThreadKey,
        generation: ExecutionGeneration,
    },
    KickDelivered {
        thread: ThreadKey,
        generation: ExecutionGeneration,
    },
    Saved {
        thread: ThreadKey,
        generation: ExecutionGeneration,
    },
    SettledBlocked {
        thread: ThreadKey,
        generation: ExecutionGeneration,
    },
    SettledRunnable {
        thread: ThreadKey,
        generation: ExecutionGeneration,
    },
    SettledExited {
        thread: ThreadKey,
        generation: ExecutionGeneration,
    },
    Failed {
        thread: ThreadKey,
        generation: ExecutionGeneration,
    },
    Destroyed,
    Joined,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutorPoolReceipt {
    pub sequence: u64,
    pub executor: ExecutorId,
    pub event: ExecutorPoolEvent,
}

#[derive(Debug, Default)]
struct ReceiptState {
    next_sequence: u64,
    events: Vec<ExecutorPoolReceipt>,
}

#[derive(Debug, Default)]
struct ReceiptLog(Mutex<ReceiptState>);

impl ReceiptLog {
    fn record(&self, executor: ExecutorId, event: ExecutorPoolEvent) {
        let mut state = self.0.lock();
        state.next_sequence = state
            .next_sequence
            .checked_add(1)
            .unwrap_or_else(|| std::process::abort());
        let sequence = state.next_sequence;
        state.events.push(ExecutorPoolReceipt {
            sequence,
            executor,
            event,
        });
    }

    fn snapshot(&self) -> Vec<ExecutorPoolReceipt> {
        self.0.lock().events.clone()
    }
}

#[derive(Debug)]
struct WorkerKick {
    binding: Mutex<Option<ExecutorBinding>>,
    need_resched: AtomicBool,
    receipts: Arc<ReceiptLog>,
}

impl WorkerKick {
    fn new(receipts: Arc<ReceiptLog>) -> Self {
        Self {
            binding: Mutex::new(None),
            need_resched: AtomicBool::new(false),
            receipts,
        }
    }
}

impl ExecutorKick for WorkerKick {
    fn try_bind(&self, binding: ExecutorBinding) -> bool {
        let mut current = self.binding.lock();
        if current.is_some() {
            return false;
        }
        self.need_resched.store(false, Ordering::Release);
        *current = Some(binding);
        true
    }

    fn unbind(&self, binding: ExecutorBinding) {
        let mut current = self.binding.lock();
        if *current == Some(binding) {
            *current = None;
            self.need_resched.store(false, Ordering::Release);
        }
    }

    fn deliver_exact(&self, token: ExecutorKickToken) -> bool {
        let current = *self.binding.lock();
        if current != Some(token.binding()) {
            return false;
        }
        self.need_resched.store(true, Ordering::Release);
        self.receipts.record(
            token.executor(),
            ExecutorPoolEvent::KickDelivered {
                thread: token.thread(),
                generation: token.generation(),
            },
        );
        true
    }

    fn current_binding(&self) -> Option<ExecutorBinding> {
        *self.binding.lock()
    }
}

#[derive(Debug)]
enum WorkerCommand {
    Initialize,
    Run,
    Stop,
}

#[derive(Debug)]
struct StartupStatus {
    index: usize,
    error: Option<String>,
}

#[derive(Debug)]
struct WorkerOutcome {
    executor: Option<ExecutorId>,
    failure: Option<String>,
    retired: bool,
}

#[derive(Debug)]
struct WorkerHandle {
    command: mpsc::Sender<WorkerCommand>,
    join: JoinHandle<WorkerOutcome>,
}

pub struct ExecutorPool<F, R>
where
    F: PersistentExecutorFactory,
    R: TaskBindingResolver<
        <<F as PersistentExecutorFactory>::Executor as PersistentExecutor>::TaskBinding,
    >,
{
    scheduler: Arc<Scheduler>,
    handles: Vec<WorkerHandle>,
    receipts: Arc<ReceiptLog>,
    _factory: std::marker::PhantomData<F>,
    _resolver: std::marker::PhantomData<R>,
}

impl<F, R> std::fmt::Debug for ExecutorPool<F, R>
where
    F: PersistentExecutorFactory,
    R: TaskBindingResolver<
        <<F as PersistentExecutorFactory>::Executor as PersistentExecutor>::TaskBinding,
    >,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutorPool")
            .field("workers", &self.handles.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("persistent executor pool startup failed: {message}")]
pub struct ExecutorPoolStartError {
    configured_workers: usize,
    message: String,
}

impl ExecutorPoolStartError {
    pub const fn configured_workers(&self) -> usize {
        self.configured_workers
    }
}

#[derive(Debug)]
pub struct ExecutorPoolReport {
    events: Vec<ExecutorPoolReceipt>,
    created: usize,
    destroyed: usize,
    joined: usize,
}

impl ExecutorPoolReport {
    pub const fn created(&self) -> usize {
        self.created
    }

    pub const fn destroyed(&self) -> usize {
        self.destroyed
    }

    pub const fn joined(&self) -> usize {
        self.joined
    }

    pub fn events(&self) -> &[ExecutorPoolReceipt] {
        &self.events
    }
}

#[derive(Debug, thiserror::Error)]
#[error("persistent executor pool shutdown failed: {message}")]
pub struct ExecutorPoolShutdownError {
    report: ExecutorPoolReport,
    retired_workers: usize,
    message: String,
}

impl ExecutorPoolShutdownError {
    pub const fn retired_workers(&self) -> usize {
        self.retired_workers
    }

    pub const fn report(&self) -> &ExecutorPoolReport {
        &self.report
    }
}

impl<F, R> ExecutorPool<F, R>
where
    F: PersistentExecutorFactory,
    R: TaskBindingResolver<
        <<F as PersistentExecutorFactory>::Executor as PersistentExecutor>::TaskBinding,
    >,
{
    pub fn start(
        config: ExecutorPoolConfig,
        scheduler: Arc<Scheduler>,
        factory: Arc<F>,
        resolver: Arc<R>,
        _audit: ExecutorBoundaryAudit,
    ) -> Result<Self, ExecutorPoolStartError> {
        let configured_workers =
            config
                .executor_count()
                .map_err(|error| ExecutorPoolStartError {
                    configured_workers: 0,
                    message: error.to_string(),
                })?;
        let receipts = Arc::new(ReceiptLog::default());
        let (startup_tx, startup_rx) = mpsc::channel();
        let mut handles: Vec<WorkerHandle> = Vec::with_capacity(configured_workers);
        for index in 0..configured_workers {
            let (command_tx, command_rx) = mpsc::channel();
            let scheduler = Arc::clone(&scheduler);
            let factory = Arc::clone(&factory);
            let resolver = Arc::clone(&resolver);
            let receipts_for_worker = Arc::clone(&receipts);
            let startup_tx = startup_tx.clone();
            let join = match std::thread::Builder::new()
                .name(format!("carrick-executor-{index}"))
                .spawn(move || {
                    executor_worker(
                        index,
                        scheduler,
                        factory,
                        resolver,
                        receipts_for_worker,
                        command_rx,
                        startup_tx,
                    )
                }) {
                Ok(join) => join,
                Err(error) => {
                    let cleanup_failures = stop_and_join_startup(handles);
                    let mut message = format!("worker {index} spawn failed: {error}");
                    append_failures(&mut message, cleanup_failures);
                    return Err(ExecutorPoolStartError {
                        configured_workers,
                        message,
                    });
                }
            };
            handles.push(WorkerHandle {
                command: command_tx,
                join,
            });
        }
        drop(startup_tx);

        let mut startup_failure = None;
        for (index, handle) in handles.iter().enumerate() {
            if startup_failure.is_some() {
                break;
            }
            if handle.command.send(WorkerCommand::Initialize).is_err() {
                startup_failure = Some(format!("worker {index} stopped before initialization"));
                break;
            }
            match startup_rx.recv() {
                Ok(status) if status.index == index && status.error.is_none() => {}
                Ok(status) => {
                    startup_failure = Some(status.error.unwrap_or_else(|| {
                        format!(
                            "worker startup status mismatch: expected {index}, got {}",
                            status.index
                        )
                    }));
                }
                Err(error) => startup_failure = Some(format!("startup channel failed: {error}")),
            }
        }

        if let Some(mut message) = startup_failure {
            append_failures(&mut message, stop_and_join_startup(handles));
            return Err(ExecutorPoolStartError {
                configured_workers,
                message,
            });
        }

        for handle in &handles {
            if handle.command.send(WorkerCommand::Run).is_err() {
                let mut message = "worker stopped before pool publication".to_owned();
                append_failures(&mut message, stop_and_join_startup(handles));
                return Err(ExecutorPoolStartError {
                    configured_workers,
                    message,
                });
            }
        }

        Ok(Self {
            scheduler,
            handles,
            receipts,
            _factory: std::marker::PhantomData,
            _resolver: std::marker::PhantomData,
        })
    }

    pub fn shutdown(self) -> Result<ExecutorPoolReport, ExecutorPoolShutdownError> {
        self.scheduler.close();
        let mut failures = Vec::new();
        let mut retired_workers = 0;
        let mut joined = 0;
        for handle in self.handles {
            match handle.join.join() {
                Ok(outcome) => {
                    joined += 1;
                    if outcome.retired {
                        retired_workers += 1;
                    }
                    if let Some(error) = outcome.failure {
                        failures.push(error);
                    }
                    if let Some(executor) = outcome.executor {
                        self.receipts.record(executor, ExecutorPoolEvent::Joined);
                    }
                }
                Err(_) => {
                    retired_workers += 1;
                    failures.push("executor worker panicked outside containment".to_owned());
                }
            }
        }
        self.scheduler.wait_closed();
        let events = self.receipts.snapshot();
        let created = events
            .iter()
            .filter(|event| event.event == ExecutorPoolEvent::Created)
            .count();
        let destroyed = events
            .iter()
            .filter(|event| event.event == ExecutorPoolEvent::Destroyed)
            .count();
        let report = ExecutorPoolReport {
            events,
            created,
            destroyed,
            joined,
        };
        if failures.is_empty() {
            Ok(report)
        } else {
            Err(ExecutorPoolShutdownError {
                report,
                retired_workers,
                message: failures.join("; "),
            })
        }
    }
}

fn stop_and_join_startup(handles: Vec<WorkerHandle>) -> Vec<String> {
    for handle in &handles {
        let _ = handle.command.send(WorkerCommand::Stop);
    }
    let mut failures = Vec::new();
    for handle in handles {
        match handle.join.join() {
            Ok(outcome) => {
                if let Some(failure) = outcome.failure {
                    failures.push(failure);
                }
            }
            Err(_) => failures.push("executor worker panicked during startup rollback".to_owned()),
        }
    }
    failures
}

fn append_failures(message: &mut String, failures: Vec<String>) {
    for failure in failures {
        message.push_str("; ");
        message.push_str(&failure);
    }
}

fn executor_worker<F, R>(
    index: usize,
    scheduler: Arc<Scheduler>,
    factory: Arc<F>,
    resolver: Arc<R>,
    receipts: Arc<ReceiptLog>,
    commands: mpsc::Receiver<WorkerCommand>,
    startup: mpsc::Sender<StartupStatus>,
) -> WorkerOutcome
where
    F: PersistentExecutorFactory,
    R: TaskBindingResolver<
        <<F as PersistentExecutorFactory>::Executor as PersistentExecutor>::TaskBinding,
    >,
{
    if !matches!(commands.recv(), Ok(WorkerCommand::Initialize)) {
        return WorkerOutcome {
            executor: None,
            failure: None,
            retired: false,
        };
    }
    let kick = Arc::new(WorkerKick::new(Arc::clone(&receipts)));
    let registration = match scheduler.register_executor(Arc::clone(&kick) as Arc<dyn ExecutorKick>)
    {
        Ok(registration) => registration,
        Err(error) => {
            let _ = startup.send(StartupStatus {
                index,
                error: Some(error.to_string()),
            });
            return WorkerOutcome {
                executor: None,
                failure: Some(error.to_string()),
                retired: true,
            };
        }
    };
    let executor_id = registration.id();
    let mut backend = match catch_unwind(AssertUnwindSafe(|| factory.create(executor_id))) {
        Ok(Ok(backend)) => backend,
        Ok(Err(error)) => {
            let _ = scheduler.unregister_executor(&registration);
            let _ = startup.send(StartupStatus {
                index,
                error: Some(error.to_string()),
            });
            return WorkerOutcome {
                executor: Some(executor_id),
                failure: Some(error.to_string()),
                retired: true,
            };
        }
        Err(_) => {
            let _ = scheduler.unregister_executor(&registration);
            let message = "executor factory panicked".to_owned();
            let _ = startup.send(StartupStatus {
                index,
                error: Some(message.clone()),
            });
            return WorkerOutcome {
                executor: Some(executor_id),
                failure: Some(message),
                retired: true,
            };
        }
    };
    receipts.record(executor_id, ExecutorPoolEvent::Created);
    let boundary = match WorkerBoundaryAudit::capture().and_then(|boundary| {
        boundary.audit_clean(&mut backend, &kick)?;
        Ok(boundary)
    }) {
        Ok(boundary) => boundary,
        Err(error) => {
            let mut message = error.to_string();
            if let Some(destroy_error) =
                destroy_and_unregister(backend, &scheduler, &registration, &receipts)
            {
                append_failures(&mut message, vec![destroy_error]);
            }
            let _ = startup.send(StartupStatus {
                index,
                error: Some(message.clone()),
            });
            return WorkerOutcome {
                executor: Some(executor_id),
                failure: Some(message),
                retired: true,
            };
        }
    };
    receipts.record(executor_id, ExecutorPoolEvent::AuditPassed);
    let _ = startup.send(StartupStatus { index, error: None });
    match commands.recv() {
        Ok(WorkerCommand::Run) => {}
        Ok(WorkerCommand::Stop) | Err(_) => {
            let failure = destroy_and_unregister(backend, &scheduler, &registration, &receipts);
            return WorkerOutcome {
                executor: Some(executor_id),
                retired: failure.is_some(),
                failure,
            };
        }
        Ok(WorkerCommand::Initialize) => {
            let failure = Some("executor received duplicate initialize".to_owned());
            let _ = destroy_and_unregister(backend, &scheduler, &registration, &receipts);
            return WorkerOutcome {
                executor: Some(executor_id),
                failure,
                retired: true,
            };
        }
    }

    let run_result = catch_unwind(AssertUnwindSafe(|| {
        run_executor_loop(
            &scheduler,
            &resolver,
            &mut backend,
            &registration,
            &kick,
            &boundary,
            &receipts,
        )
    }));
    let mut retired = false;
    let mut failure = match run_result {
        Ok(Ok(())) => None,
        Ok(Err(error)) => {
            retired = true;
            Some(error)
        }
        Err(_) => {
            retired = true;
            Some("executor worker/backend panicked; exact lease failed closed".to_owned())
        }
    };
    if let Some(destroy_error) =
        destroy_and_unregister(backend, &scheduler, &registration, &receipts)
    {
        retired = true;
        if let Some(existing) = &mut failure {
            existing.push_str("; ");
            existing.push_str(&destroy_error);
        } else {
            failure = Some(destroy_error);
        }
    }
    WorkerOutcome {
        executor: Some(executor_id),
        failure,
        retired,
    }
}

fn run_executor_loop<F, R>(
    scheduler: &Arc<Scheduler>,
    resolver: &Arc<R>,
    backend: &mut F,
    registration: &ExecutorRegistration,
    kick: &Arc<WorkerKick>,
    boundary: &WorkerBoundaryAudit,
    receipts: &Arc<ReceiptLog>,
) -> Result<(), String>
where
    F: PersistentExecutor,
    R: TaskBindingResolver<F::TaskBinding>,
{
    loop {
        let mut running = match scheduler.take(registration) {
            Ok(running) => running,
            Err(crate::kernel::RunQueueError::Closed) => return Ok(()),
            Err(error) => return Err(error.to_string()),
        };
        let executor_id = running.executor();
        let thread = running.thread_key();
        let generation = running.generation();
        receipts.record(
            executor_id,
            ExecutorPoolEvent::Claimed { thread, generation },
        );
        if let Err(error) = boundary.audit_runtime(backend) {
            let settlement = fail_running(
                scheduler,
                running,
                ExecutionFailure::SnapshotRestoreFailed,
                receipts,
            );
            return Err(with_settlement_error(error.to_string(), settlement));
        }
        let binding = match resolver.resolve(thread, generation) {
            Ok(binding) => binding,
            Err(error) => {
                let settlement = fail_running(
                    scheduler,
                    running,
                    ExecutionFailure::SnapshotRestoreFailed,
                    receipts,
                );
                return Err(with_settlement_error(error.to_string(), settlement));
            }
        };
        let task = RunnableTask {
            thread,
            generation,
            lease: running.lease(),
            binding,
        };
        if let Err(error) = backend.load(&task) {
            let settlement = fail_running(
                scheduler,
                running,
                ExecutionFailure::SnapshotRestoreFailed,
                receipts,
            );
            return Err(with_settlement_error(error.to_string(), settlement));
        }
        receipts.record(
            executor_id,
            ExecutorPoolEvent::Loaded { thread, generation },
        );

        let exit = loop {
            let exit = match backend.run_until_boundary(&kick.need_resched) {
                Ok(exit) => exit,
                Err(error) => {
                    let settlement = fail_running(
                        scheduler,
                        running,
                        ExecutionFailure::SnapshotRestoreFailed,
                        receipts,
                    );
                    return Err(with_settlement_error(error.to_string(), settlement));
                }
            };
            let cpu = backend.take_cpu_receipt();
            running.thread().charge_user_ns(cpu.user_ns);
            running.thread().charge_system_ns(cpu.system_ns);
            if exit == ExecutorExit::Syscall {
                scheduler.note_syscall_boundary(&running);
                receipts.record(
                    executor_id,
                    ExecutorPoolEvent::OrdinarySyscall { thread, generation },
                );
                continue;
            }
            break exit;
        };
        if exit == ExecutorExit::InvalidState {
            let settlement = fail_running(
                scheduler,
                running,
                ExecutionFailure::SnapshotRestoreFailed,
                receipts,
            );
            return Err(with_settlement_error(
                "backend returned invalid executor state".to_owned(),
                settlement,
            ));
        }
        if let Err(error) = scheduler.begin_switch_out(&running) {
            let settlement = fail_running(
                scheduler,
                running,
                ExecutionFailure::SnapshotSaveFailed,
                receipts,
            );
            return Err(with_settlement_error(error.to_string(), settlement));
        }
        let lease = running.take_lease();
        let saved = match backend.save(lease) {
            Ok(saved) => saved,
            Err(error) => {
                let (source, lease) = error.into_parts();
                if let Err((restore_error, lease)) =
                    scheduler.restore_saved_lease(&mut running, lease)
                {
                    drop(lease);
                    return Err(format!("{source}; lease restore failed: {restore_error}"));
                }
                let settlement = fail_running(
                    scheduler,
                    running,
                    ExecutionFailure::SnapshotSaveFailed,
                    receipts,
                );
                return Err(with_settlement_error(source.to_string(), settlement));
            }
        };
        receipts.record(executor_id, ExecutorPoolEvent::Saved { thread, generation });
        if let Err((error, lease)) = scheduler.restore_saved_lease(&mut running, saved.into_lease())
        {
            drop(lease);
            return Err(error.to_string());
        }
        if let Err(error) = boundary.audit_runtime(backend) {
            let settlement = fail_running(
                scheduler,
                running,
                ExecutionFailure::SnapshotRestoreFailed,
                receipts,
            );
            return Err(with_settlement_error(error.to_string(), settlement));
        }
        let settlement = match exit {
            ExecutorExit::Blocked(reason) => scheduler
                .settle_blocked(running, reason)
                .map(|()| ExecutorPoolEvent::SettledBlocked { thread, generation }),
            ExecutorExit::Yielded | ExecutorExit::Preempted | ExecutorExit::Quiesced => scheduler
                .settle_runnable(running)
                .map(|()| ExecutorPoolEvent::SettledRunnable { thread, generation }),
            ExecutorExit::Exited => scheduler
                .settle_exited(running)
                .map(|()| ExecutorPoolEvent::SettledExited { thread, generation }),
            ExecutorExit::Syscall | ExecutorExit::InvalidState => unreachable!(),
        };
        match settlement {
            Ok(event) => receipts.record(executor_id, event),
            Err(error) => return Err(error.to_string()),
        }
        if let Err(error) = boundary.audit_clean(backend, kick) {
            return Err(error.to_string());
        }
        receipts.record(executor_id, ExecutorPoolEvent::AuditPassed);
        std::thread::yield_now();
    }
}

fn fail_running(
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

fn with_settlement_error(mut source: String, settlement: Option<String>) -> String {
    if let Some(settlement) = settlement {
        source.push_str("; exact failure settlement failed: ");
        source.push_str(&settlement);
    }
    source
}

fn destroy_and_unregister<E: PersistentExecutor>(
    backend: E,
    scheduler: &Scheduler,
    registration: &ExecutorRegistration,
    receipts: &ReceiptLog,
) -> Option<String> {
    let executor = registration.id();
    let destroy = catch_unwind(AssertUnwindSafe(|| backend.destroy()));
    let destroy_error = match destroy {
        Ok(Ok(())) => {
            receipts.record(executor, ExecutorPoolEvent::Destroyed);
            None
        }
        Ok(Err(error)) => Some(format!("executor destroy failed: {error}")),
        Err(_) => Some("executor destroy panicked".to_owned()),
    };
    let unregister_error = scheduler
        .unregister_executor(registration)
        .err()
        .map(|error| format!("executor unregister failed: {error}"));
    match (destroy_error, unregister_error) {
        (None, None) => None,
        (Some(error), None) | (None, Some(error)) => Some(error),
        (Some(mut first), Some(second)) => {
            first.push_str("; ");
            first.push_str(&second);
            Some(first)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread::{self, ThreadId as HostThreadId};
    use std::time::{Duration, Instant};

    use carrick_abi::LinuxCloneFlags;
    use carrick_hal::ThreadId;
    use carrick_hal::threaded::{Aarch64TaskCpuStateV1, GuestCpuState};

    use super::{
        ExecutorBoundaryAudit, ExecutorCpuReceipt, ExecutorExit, ExecutorPool, ExecutorPoolConfig,
        ExecutorPoolEvent, ExecutorSaveError, PersistentExecutor, PersistentExecutorFactory,
        RunnableTask, SavedRunnable, TaskBindingResolver,
    };
    use crate::kernel::objects::{
        BlockedReason, ExecutionFailure, ExecutionGeneration, ExecutorId, MigratableTaskState,
        ThreadExecutionLease, ThreadExecutionState,
    };
    use crate::kernel::{
        ClonePlan, Kernel, KernelContext, RootBootstrap, Scheduler, SubmissionAuthority, ThreadKey,
    };
    use crate::trap::TrapError;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Step {
        Syscalls(usize),
        ComputeUntilKick,
        Block,
        Yield,
        Exit,
        FailRun,
        PanicRun,
        Invalid,
    }

    #[derive(Debug)]
    struct DescendantPublication {
        scheduler: Arc<Scheduler>,
        child_thread: Arc<crate::kernel::Thread>,
        child_generation: ExecutionGeneration,
        child_binding: Arc<FakeBinding>,
    }

    #[derive(Debug)]
    struct FakeBinding {
        marker: u64,
        steps: parking_lot::Mutex<VecDeque<Step>>,
        load_fails: AtomicBool,
        save_fails: AtomicBool,
        audit_fails: AtomicBool,
        entered: parking_lot::Mutex<Option<Arc<Barrier>>>,
        progress: AtomicUsize,
        lineage_authority: parking_lot::Mutex<Option<SubmissionAuthority>>,
        descendant: parking_lot::Mutex<Option<DescendantPublication>>,
    }

    impl FakeBinding {
        fn new(marker: u64, steps: impl IntoIterator<Item = Step>) -> Arc<Self> {
            Arc::new(Self {
                marker,
                steps: parking_lot::Mutex::new(steps.into_iter().collect()),
                load_fails: AtomicBool::new(false),
                save_fails: AtomicBool::new(false),
                audit_fails: AtomicBool::new(false),
                entered: parking_lot::Mutex::new(None),
                progress: AtomicUsize::new(0),
                lineage_authority: parking_lot::Mutex::new(None),
                descendant: parking_lot::Mutex::new(None),
            })
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum BackendEventKind {
        Create,
        Destroy,
        Load,
        Save,
        Run,
        Audit,
    }

    #[derive(Clone, Debug)]
    struct BackendEvent {
        kind: BackendEventKind,
        executor: ExecutorId,
        host_thread: HostThreadId,
        task: Option<(ThreadKey, ExecutionGeneration)>,
    }

    #[derive(Clone, Debug, Default)]
    struct FakeFactory {
        bindings: Arc<parking_lot::Mutex<BTreeMap<ThreadKey, Arc<FakeBinding>>>>,
        events: Arc<parking_lot::Mutex<Vec<BackendEvent>>>,
        create_calls: Arc<AtomicUsize>,
        fail_create_call: Arc<AtomicUsize>,
        destroy_mode: Arc<AtomicUsize>,
        snapshot_count: Arc<AtomicUsize>,
        concurrent_loads: Arc<parking_lot::Mutex<BTreeSet<(ThreadKey, ExecutionGeneration)>>>,
        inherited_state: Arc<parking_lot::Mutex<Vec<(u64, u64, u64, u64, u64)>>>,
    }

    impl FakeFactory {
        fn install(&self, context: &KernelContext, binding: Arc<FakeBinding>) {
            self.bindings.lock().insert(context.thread().key(), binding);
        }

        fn record(
            &self,
            kind: BackendEventKind,
            executor: ExecutorId,
            task: Option<(ThreadKey, ExecutionGeneration)>,
        ) {
            self.events.lock().push(BackendEvent {
                kind,
                executor,
                host_thread: thread::current().id(),
                task,
            });
        }
    }

    impl TaskBindingResolver<FakeBinding> for FakeFactory {
        fn resolve(
            &self,
            thread: ThreadKey,
            _generation: ExecutionGeneration,
        ) -> Result<Arc<FakeBinding>, TrapError> {
            self.bindings.lock().get(&thread).cloned().ok_or_else(|| {
                TrapError::Hypervisor(format!("missing fake binding for {thread:?}"))
            })
        }
    }

    struct FakeExecutor {
        id: ExecutorId,
        factory: FakeFactory,
        owner: HostThreadId,
        current: Option<(ThreadKey, ExecutionGeneration, Arc<FakeBinding>)>,
        credentials: u64,
        restart_state: u64,
        mailbox: u64,
        tls: u64,
        user_ns: u64,
        system_ns: u64,
    }

    impl PersistentExecutorFactory for FakeFactory {
        type Executor = FakeExecutor;

        fn create(&self, executor: ExecutorId) -> Result<Self::Executor, TrapError> {
            let call = self.create_calls.fetch_add(1, Ordering::SeqCst) + 1;
            self.record(BackendEventKind::Create, executor, None);
            if self.fail_create_call.load(Ordering::SeqCst) == call {
                return Err(TrapError::Hypervisor("injected create failure".to_owned()));
            }
            Ok(FakeExecutor {
                id: executor,
                factory: self.clone(),
                owner: thread::current().id(),
                current: None,
                credentials: 0,
                restart_state: 0,
                mailbox: 0,
                tls: 0,
                user_ns: 0,
                system_ns: 0,
            })
        }
    }

    impl PersistentExecutor for FakeExecutor {
        type TaskBinding = FakeBinding;

        fn load(&mut self, task: &RunnableTask<'_, Self::TaskBinding>) -> Result<(), TrapError> {
            assert_eq!(thread::current().id(), self.owner);
            let key = (task.thread_key(), task.generation());
            assert_eq!(task.lease().generation(), task.generation());
            assert_eq!(task.lease().executor(), self.id);
            if !self.factory.concurrent_loads.lock().insert(key) {
                return Err(TrapError::Hypervisor("concurrent double-load".to_owned()));
            }
            let binding = Arc::clone(task.binding());
            if binding.load_fails.load(Ordering::SeqCst) {
                self.factory.concurrent_loads.lock().remove(&key);
                return Err(TrapError::Hypervisor("injected load failure".to_owned()));
            }
            self.factory.inherited_state.lock().push((
                binding.marker,
                self.credentials,
                self.restart_state,
                self.mailbox,
                self.tls,
            ));
            self.credentials = binding.marker + 1;
            self.restart_state = binding.marker + 2;
            self.mailbox = binding.marker + 3;
            self.tls = binding.marker + 4;
            self.current = Some((key.0, key.1, Arc::clone(&binding)));
            self.factory
                .record(BackendEventKind::Load, self.id, Some(key));
            Ok(())
        }

        fn run_until_boundary(
            &mut self,
            need_resched: &AtomicBool,
        ) -> Result<ExecutorExit, TrapError> {
            assert_eq!(thread::current().id(), self.owner);
            let (thread, generation, binding) = self.current.as_ref().expect("loaded task");
            self.factory
                .record(BackendEventKind::Run, self.id, Some((*thread, *generation)));
            binding.progress.fetch_add(1, Ordering::SeqCst);
            if let Some(gate) = binding.entered.lock().take() {
                gate.wait();
            }
            if let Some(publication) = binding.descendant.lock().take() {
                let authority = binding
                    .lineage_authority
                    .lock()
                    .take()
                    .expect("live authority");
                let descendant = authority
                    .admit_descendant(publication.child_thread.key(), publication.child_generation)
                    .expect("admit descendant during closing");
                descendant
                    .publish(
                        &publication.scheduler,
                        Arc::clone(&publication.child_thread),
                    )
                    .expect("publish descendant during closing");
                *publication.child_binding.lineage_authority.lock() = Some(descendant);
                drop(authority);
            } else {
                drop(binding.lineage_authority.lock().take());
            }
            let step = {
                let mut steps = binding.steps.lock();
                let step = steps.pop_front().unwrap_or(Step::Exit);
                match step {
                    Step::Syscalls(remaining) if remaining > 1 => {
                        steps.push_front(Step::Syscalls(remaining - 1));
                        Step::Syscalls(remaining)
                    }
                    other => other,
                }
            };
            self.user_ns = self.user_ns.saturating_add(7_000);
            self.system_ns = self.system_ns.saturating_add(3_000);
            match step {
                Step::Syscalls(_) => Ok(ExecutorExit::Syscall),
                Step::ComputeUntilKick => {
                    let deadline = Instant::now() + Duration::from_secs(2);
                    while !need_resched.load(Ordering::Acquire) && Instant::now() < deadline {
                        binding.progress.fetch_add(1, Ordering::Relaxed);
                        thread::yield_now();
                    }
                    if need_resched.load(Ordering::Acquire) {
                        Ok(ExecutorExit::Preempted)
                    } else {
                        Err(TrapError::Hypervisor(
                            "fake compute task was never kicked".to_owned(),
                        ))
                    }
                }
                Step::Block => Ok(ExecutorExit::Blocked(BlockedReason::HostWait)),
                Step::Yield => Ok(ExecutorExit::Yielded),
                Step::Exit => Ok(ExecutorExit::Exited),
                Step::FailRun => Err(TrapError::Hypervisor("injected run failure".to_owned())),
                Step::PanicRun => panic!("injected executor panic"),
                Step::Invalid => Ok(ExecutorExit::InvalidState),
            }
        }

        fn take_cpu_receipt(&mut self) -> ExecutorCpuReceipt {
            let receipt = ExecutorCpuReceipt {
                user_ns: self.user_ns,
                system_ns: self.system_ns,
            };
            self.user_ns = 0;
            self.system_ns = 0;
            receipt
        }

        fn save(
            &mut self,
            lease: ThreadExecutionLease,
        ) -> Result<SavedRunnable, ExecutorSaveError> {
            assert_eq!(thread::current().id(), self.owner);
            let Some((thread, generation, binding)) = self.current.take() else {
                return Err(ExecutorSaveError::new(
                    TrapError::Hypervisor("save without loaded task".to_owned()),
                    lease,
                ));
            };
            self.factory
                .record(BackendEventKind::Save, self.id, Some((thread, generation)));
            self.factory
                .concurrent_loads
                .lock()
                .remove(&(thread, generation));
            self.factory.snapshot_count.fetch_add(1, Ordering::SeqCst);
            if binding.save_fails.load(Ordering::SeqCst) {
                return Err(ExecutorSaveError::new(
                    TrapError::Hypervisor("injected save failure".to_owned()),
                    lease,
                ));
            }
            if !binding.audit_fails.load(Ordering::SeqCst) {
                self.credentials = 0;
                self.restart_state = 0;
                self.mailbox = 0;
                self.tls = 0;
            }
            Ok(SavedRunnable::new(lease))
        }

        fn invalidate_asid(&mut self, _generation: u64) -> Result<(), TrapError> {
            assert_eq!(thread::current().id(), self.owner);
            Ok(())
        }

        fn audit_boundary(&mut self) -> Result<(), TrapError> {
            assert_eq!(thread::current().id(), self.owner);
            self.factory.record(BackendEventKind::Audit, self.id, None);
            if self
                .current
                .as_ref()
                .is_some_and(|(_, _, binding)| binding.audit_fails.load(Ordering::SeqCst))
                || self.credentials != 0
                || self.restart_state != 0
                || self.mailbox != 0
                || self.tls != 0
            {
                return Err(TrapError::Hypervisor(
                    "injected or observed dirty executor boundary".to_owned(),
                ));
            }
            Ok(())
        }

        fn destroy(self) -> Result<(), TrapError> {
            assert_eq!(thread::current().id(), self.owner);
            self.factory
                .record(BackendEventKind::Destroy, self.id, None);
            match self.factory.destroy_mode.load(Ordering::SeqCst) {
                1 => Err(TrapError::Hypervisor(
                    "injected executor destroy failure".to_owned(),
                )),
                2 => panic!("injected executor destroy panic"),
                _ => Ok(()),
            }
        }
    }

    fn bootstrap(pid: i32) -> (Arc<Kernel>, KernelContext) {
        let input = RootBootstrap::for_reference_model(
            pid,
            ThreadId::synthetic_for_tests(pid),
            "executor test".to_owned(),
        )
        .expect("bootstrap input");
        Kernel::bootstrap_root(input).expect("kernel")
    }

    fn sibling(kernel: &Arc<Kernel>, parent: &KernelContext, host_tid: i32) -> KernelContext {
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread clone plan");
        kernel
            .reserve_thread_clone(parent, plan, None)
            .expect("reserve sibling")
            .prepare(ThreadId::synthetic_for_tests(host_tid))
            .expect("prepare sibling")
            .commit()
            .expect("publish sibling")
            .start_thread()
            .expect("start sibling")
            .into_context()
    }

    fn process_child(
        kernel: &Arc<Kernel>,
        parent: &KernelContext,
        host_tid: i32,
        name: &str,
    ) -> KernelContext {
        kernel
            .reserve_fork(
                parent,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("process fork plan"),
                name.to_owned(),
                None,
            )
            .expect("reserve process child")
            .prepare_reference(ThreadId::synthetic_for_tests(host_tid))
            .expect("prepare process child")
            .commit()
            .expect("publish process child")
            .start_child()
            .expect("start process child")
            .into_parts()
            .0
    }

    fn task_state(context: &KernelContext, marker: u64) -> MigratableTaskState {
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
        }
    }

    fn publish(context: &KernelContext, marker: u64) -> ExecutionGeneration {
        context
            .thread()
            .publish_initial_task_state(task_state(context, marker))
            .expect("publish task state")
    }

    fn enqueue_root(
        scheduler: &Arc<Scheduler>,
        context: &KernelContext,
        generation: ExecutionGeneration,
    ) -> SubmissionAuthority {
        let authority = scheduler
            .admit_root(context.thread().key(), generation)
            .expect("admit root");
        authority
            .publish(scheduler, Arc::clone(context.thread()))
            .expect("publish root");
        authority
    }

    fn config(workers: usize) -> ExecutorPoolConfig {
        ExecutorPoolConfig {
            physical_cores: workers,
            vcpu_ceiling: workers + 1,
            reserve: 1,
        }
    }

    fn start_pool(
        scheduler: Arc<Scheduler>,
        factory: Arc<FakeFactory>,
        workers: usize,
    ) -> ExecutorPool<FakeFactory, FakeFactory> {
        ExecutorPool::start(
            config(workers),
            scheduler,
            Arc::clone(&factory),
            factory,
            ExecutorBoundaryAudit::production(),
        )
        .expect("start executor pool")
    }

    #[test]
    fn pool_size_is_bounded_and_zero_host_capacity_fails_before_creation() {
        assert_eq!(
            ExecutorPoolConfig {
                physical_cores: 12,
                vcpu_ceiling: 8,
                reserve: 2,
            }
            .executor_count()
            .unwrap(),
            6
        );
        assert_eq!(
            ExecutorPoolConfig {
                physical_cores: 0,
                vcpu_ceiling: 8,
                reserve: 99,
            }
            .executor_count()
            .unwrap(),
            1
        );
        assert!(
            ExecutorPoolConfig {
                physical_cores: 8,
                vcpu_ceiling: 0,
                reserve: 0,
            }
            .executor_count()
            .is_err()
        );
    }

    #[test]
    fn creation_is_transactional_and_every_created_vcpu_dies_on_its_owner_worker() {
        let caller = thread::current().id();
        let (kernel, _) = bootstrap(14_001);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        factory.fail_create_call.store(3, Ordering::SeqCst);
        let error = ExecutorPool::start(
            config(4),
            scheduler,
            Arc::clone(&factory),
            Arc::clone(&factory),
            ExecutorBoundaryAudit::production(),
        )
        .expect_err("third create must abort startup");
        assert_eq!(error.configured_workers(), 4);
        let events = factory.events.lock().clone();
        let creates: Vec<_> = events
            .iter()
            .filter(|event| event.kind == BackendEventKind::Create)
            .collect();
        let destroys: Vec<_> = events
            .iter()
            .filter(|event| event.kind == BackendEventKind::Destroy)
            .collect();
        assert_eq!(creates.len(), 3);
        assert_eq!(destroys.len(), 2);
        assert!(creates.iter().all(|event| event.host_thread != caller));
        for destroy in destroys {
            let create = creates
                .iter()
                .find(|event| event.executor == destroy.executor)
                .expect("matching create");
            assert_eq!(create.host_thread, destroy.host_thread);
        }
    }

    #[test]
    fn sequential_generations_reuse_one_executor_and_migration_follows_save() {
        let (kernel, first) = bootstrap(14_010);
        let second = sibling(&kernel, &first, 24_010);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        let first_binding = FakeBinding::new(10, [Step::Yield, Step::Exit]);
        let second_binding = FakeBinding::new(20, [Step::Exit]);
        factory.install(&first, first_binding);
        factory.install(&second, second_binding);
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        let first_authority = enqueue_root(&scheduler, &first, publish(&first, 10));
        let second_authority = enqueue_root(&scheduler, &second, publish(&second, 20));
        drop((first_authority, second_authority));
        let report = pool.shutdown().expect("clean shutdown");
        assert_eq!(report.created(), 1);
        assert_eq!(report.destroyed(), 1);
        let events = factory.events.lock();
        let loaded: Vec<_> = events
            .iter()
            .filter(|event| event.kind == BackendEventKind::Load)
            .collect();
        assert_eq!(loaded.len(), 3);
        assert_eq!(
            loaded
                .iter()
                .map(|event| event.executor)
                .collect::<BTreeSet<_>>()
                .len(),
            1
        );
        assert!(factory.concurrent_loads.lock().is_empty());
        let first_loads: Vec<_> = loaded
            .iter()
            .filter(|event| {
                event
                    .task
                    .is_some_and(|(key, _)| key == first.thread().key())
            })
            .collect();
        assert_eq!(first_loads.len(), 2);
        let save_position = events
            .iter()
            .position(|event| {
                event.kind == BackendEventKind::Save
                    && event
                        .task
                        .is_some_and(|(key, _)| key == first.thread().key())
            })
            .unwrap();
        let reload_position = events
            .iter()
            .rposition(|event| {
                event.kind == BackendEventKind::Load
                    && event
                        .task
                        .is_some_and(|(key, _)| key == first.thread().key())
            })
            .unwrap();
        assert!(save_position < reload_position);
    }

    #[test]
    fn task_migrates_between_workers_only_after_complete_save_and_unbind() {
        let (kernel, context) = bootstrap(14_015);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        let mut steps = vec![Step::Yield; 20];
        steps.push(Step::Exit);
        factory.install(&context, FakeBinding::new(15, steps));
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 2);
        let authority = enqueue_root(&scheduler, &context, publish(&context, 15));
        drop(authority);
        pool.shutdown().expect("clean migration shutdown");
        let events = factory.events.lock();
        let task_events: Vec<_> = events
            .iter()
            .filter(|event| {
                event
                    .task
                    .is_some_and(|(key, _)| key == context.thread().key())
            })
            .collect();
        let loads: Vec<_> = task_events
            .iter()
            .enumerate()
            .filter(|(_, event)| event.kind == BackendEventKind::Load)
            .collect();
        assert!(
            loads
                .iter()
                .map(|(_, event)| event.executor)
                .collect::<BTreeSet<_>>()
                .len()
                > 1,
            "the real two-worker run must exercise migration"
        );
        for window in loads.windows(2) {
            if window[0].1.executor == window[1].1.executor {
                continue;
            }
            assert!(
                task_events[window[0].0 + 1..window[1].0]
                    .iter()
                    .any(|event| event.kind == BackendEventKind::Save)
            );
        }
        assert!(factory.concurrent_loads.lock().is_empty());
    }

    #[test]
    fn resident_task_crosses_ten_thousand_syscalls_without_snapshot_or_tick() {
        let (kernel, context) = bootstrap(14_020);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        let binding = FakeBinding::new(30, [Step::Syscalls(10_000), Step::Exit]);
        factory.install(&context, Arc::clone(&binding));
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        let authority = enqueue_root(&scheduler, &context, publish(&context, 30));
        drop(authority);
        pool.shutdown().expect("clean shutdown");
        assert_eq!(binding.progress.load(Ordering::SeqCst), 10_001);
        assert_eq!(
            factory.snapshot_count.load(Ordering::SeqCst),
            1,
            "only terminal save"
        );
        assert!(!scheduler.need_resched());
        assert_eq!(
            scheduler.snapshot_count(),
            0,
            "ordinary syscalls never settle"
        );
    }

    #[test]
    fn demand_preemption_and_exact_signal_kick_advance_two_compute_tasks_without_stale_leak() {
        let (kernel, first) = bootstrap(14_030);
        let second = sibling(&kernel, &first, 24_030);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        let first_gate = Arc::new(Barrier::new(2));
        let second_gate = Arc::new(Barrier::new(2));
        let first_binding = FakeBinding::new(40, [Step::ComputeUntilKick, Step::Exit]);
        *first_binding.entered.lock() = Some(Arc::clone(&first_gate));
        let second_binding = FakeBinding::new(50, [Step::ComputeUntilKick, Step::Exit]);
        *second_binding.entered.lock() = Some(Arc::clone(&second_gate));
        factory.install(&first, Arc::clone(&first_binding));
        factory.install(&second, Arc::clone(&second_binding));
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        let first_authority = enqueue_root(&scheduler, &first, publish(&first, 40));
        first_gate.wait();
        let second_authority = enqueue_root(&scheduler, &second, publish(&second, 50));
        assert!(scheduler.need_resched());
        assert_eq!(scheduler.request_preemption(), 1);
        second_gate.wait();
        assert!(matches!(
            scheduler.wake(second.thread().key()),
            Ok(crate::kernel::WakeDisposition::Kicked)
        ));
        drop((first_authority, second_authority));
        let report = pool.shutdown().expect("clean shutdown");
        assert!(first_binding.progress.load(Ordering::SeqCst) > 0);
        assert!(second_binding.progress.load(Ordering::SeqCst) > 0);
        for context in [&first, &second] {
            let saves = factory
                .events
                .lock()
                .iter()
                .filter(|event| {
                    event.kind == BackendEventKind::Save
                        && event
                            .task
                            .is_some_and(|(key, _)| key == context.thread().key())
                })
                .count();
            assert_eq!(saves, 2, "one preemption plus terminal save");
        }
        let kick_threads: BTreeSet<_> = report
            .events()
            .iter()
            .filter_map(|event| match event.event {
                ExecutorPoolEvent::KickDelivered { thread, .. } => Some(thread),
                _ => None,
            })
            .collect();
        assert_eq!(
            kick_threads,
            BTreeSet::from([first.thread().key(), second.thread().key()])
        );
    }

    #[test]
    fn blocked_task_releases_the_only_worker_immediately() {
        let (kernel, blocked) = bootstrap(14_040);
        let runnable = sibling(&kernel, &blocked, 24_040);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        factory.install(&blocked, FakeBinding::new(60, [Step::Block]));
        factory.install(&runnable, FakeBinding::new(70, [Step::Exit]));
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        let blocked_authority = enqueue_root(&scheduler, &blocked, publish(&blocked, 60));
        let runnable_authority = enqueue_root(&scheduler, &runnable, publish(&runnable, 70));
        drop((blocked_authority, runnable_authority));
        pool.shutdown().expect("clean shutdown");
        assert!(matches!(
            blocked.thread().execution_state(),
            ThreadExecutionState::Blocked { .. }
        ));
        assert!(matches!(
            runnable.thread().execution_state(),
            ThreadExecutionState::Exited { .. }
        ));
    }

    #[test]
    fn load_save_run_panic_audit_and_invalid_state_fail_exact_task_and_retire_worker() {
        for (case, step) in [
            ("run", Step::FailRun),
            ("panic", Step::PanicRun),
            ("invalid", Step::Invalid),
        ] {
            let (kernel, context) = bootstrap(14_100 + i32::try_from(case.len()).unwrap());
            let scheduler = Arc::new(Scheduler::new(kernel));
            let factory = Arc::new(FakeFactory::default());
            let binding = FakeBinding::new(80, [step]);
            factory.install(&context, binding);
            let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
            let authority = enqueue_root(&scheduler, &context, publish(&context, 80));
            drop(authority);
            let report = pool.shutdown().expect_err("worker failure must surface");
            assert_eq!(report.retired_workers(), 1, "{case}");
            assert!(matches!(
                context.thread().execution_state(),
                ThreadExecutionState::Failed { .. }
            ));
        }

        for (case, inject) in [("load", 0_u8), ("save", 1_u8), ("audit", 2_u8)] {
            let (kernel, context) = bootstrap(14_200 + i32::from(inject));
            let scheduler = Arc::new(Scheduler::new(kernel));
            let factory = Arc::new(FakeFactory::default());
            let binding = FakeBinding::new(90, [Step::Yield]);
            binding.load_fails.store(inject == 0, Ordering::SeqCst);
            binding.save_fails.store(inject == 1, Ordering::SeqCst);
            binding.audit_fails.store(inject == 2, Ordering::SeqCst);
            factory.install(&context, binding);
            let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
            let authority = enqueue_root(&scheduler, &context, publish(&context, 90));
            drop(authority);
            let report = pool.shutdown().expect_err("worker failure must surface");
            assert_eq!(report.retired_workers(), 1, "{case}");
            assert!(matches!(
                context.thread().execution_state(),
                ThreadExecutionState::Failed { .. }
            ));
        }
    }

    #[test]
    fn destroy_error_and_panic_are_terminal_and_reported_after_join() {
        for destroy_mode in [1, 2] {
            let (kernel, context) = bootstrap(14_250 + destroy_mode as i32);
            let scheduler = Arc::new(Scheduler::new(kernel));
            let factory = Arc::new(FakeFactory::default());
            factory.destroy_mode.store(destroy_mode, Ordering::SeqCst);
            factory.install(&context, FakeBinding::new(95, [Step::Exit]));
            let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
            let authority = enqueue_root(&scheduler, &context, publish(&context, 95));
            drop(authority);
            let error = pool
                .shutdown()
                .expect_err("destroy failure must be reported");
            assert_eq!(error.retired_workers(), 1);
            assert_eq!(error.report().created(), 1);
            assert_eq!(error.report().destroyed(), 0);
            assert_eq!(error.report().joined(), 1);
        }
    }

    #[test]
    fn shutdown_drains_recursive_child_and_grandchild_before_destroy_and_join() {
        let (kernel, root) = bootstrap(14_300);
        let child = process_child(&kernel, &root, 24_300, "child");
        let grandchild = process_child(&kernel, &child, 34_300, "grandchild");
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        let root_binding = FakeBinding::new(100, [Step::Exit]);
        let child_binding = FakeBinding::new(110, [Step::Exit]);
        let grandchild_binding = FakeBinding::new(120, [Step::Exit]);
        factory.install(&root, Arc::clone(&root_binding));
        factory.install(&child, Arc::clone(&child_binding));
        factory.install(&grandchild, Arc::clone(&grandchild_binding));
        let root_generation = publish(&root, 100);
        let child_generation = publish(&child, 110);
        let grandchild_generation = publish(&grandchild, 120);
        let root_authority = enqueue_root(&scheduler, &root, root_generation);
        *root_binding.lineage_authority.lock() = Some(root_authority);
        *root_binding.descendant.lock() = Some(DescendantPublication {
            scheduler: Arc::clone(&scheduler),
            child_thread: Arc::clone(child.thread()),
            child_generation,
            child_binding: Arc::clone(&child_binding),
        });
        // Child picks up its retained authority from the fake worker and uses it
        // to publish the real process-lineage grandchild while Closing.
        *child_binding.descendant.lock() = Some(DescendantPublication {
            scheduler: Arc::clone(&scheduler),
            child_thread: Arc::clone(grandchild.thread()),
            child_generation: grandchild_generation,
            child_binding: Arc::clone(&grandchild_binding),
        });
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        let report = pool.shutdown().expect("recursive drain");
        assert!(matches!(
            root.thread().execution_state(),
            ThreadExecutionState::Exited { .. }
        ));
        assert!(matches!(
            child.thread().execution_state(),
            ThreadExecutionState::Exited { .. }
        ));
        assert!(matches!(
            grandchild.thread().execution_state(),
            ThreadExecutionState::Exited { .. }
        ));
        assert_eq!(report.created(), report.destroyed());
        assert_eq!(report.destroyed(), report.joined());
        let events = report.events();
        let last_exit = events
            .iter()
            .rposition(|event| matches!(event.event, ExecutorPoolEvent::SettledExited { .. }))
            .unwrap();
        let destroy = events
            .iter()
            .position(|event| matches!(event.event, ExecutorPoolEvent::Destroyed))
            .unwrap();
        assert!(last_exit < destroy);
    }

    #[test]
    fn alternating_tasks_never_inherit_cpu_mailbox_restart_or_tls_state() {
        let (kernel, first) = bootstrap(14_400);
        let second = sibling(&kernel, &first, 24_400);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        factory.install(&first, FakeBinding::new(130, [Step::Yield, Step::Exit]));
        factory.install(&second, FakeBinding::new(140, [Step::Yield, Step::Exit]));
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        let first_authority = enqueue_root(&scheduler, &first, publish(&first, 130));
        let second_authority = enqueue_root(&scheduler, &second, publish(&second, 140));
        drop((first_authority, second_authority));
        pool.shutdown().expect("clean alternating shutdown");
        assert!(factory.inherited_state.lock().iter().all(
            |(_, credentials, restart, mailbox, tls)| {
                (*credentials, *restart, *mailbox, *tls) == (0, 0, 0, 0)
            }
        ));
        assert_eq!(first.thread().cpu_us(), 14);
        assert_eq!(first.thread().system_cpu_us(), 6);
        assert_eq!(second.thread().cpu_us(), 14);
        assert_eq!(second.thread().system_cpu_us(), 6);
    }

    #[test]
    fn boundary_inventory_is_typed_exhaustive_and_receipts_are_totally_ordered() {
        let inventory = ExecutorBoundaryAudit::production().inventory();
        for required in [
            "vcpu-owner",
            "topology-depth",
            "hvf-fork-snapshot",
            "signal-progress",
            "active-kernel-context",
            "sysv-mq-fd-cache",
            "sysv-mq-wait-cache",
            "fanotify-internal-open-depth",
            "dispatch-lock-order-depth",
            "path-resolution-depth",
            "host-signal-mask",
            "exact-kick-binding",
            "task-cpu-accounting",
            "task-mailbox-continuation",
        ] {
            assert!(
                inventory.iter().any(|entry| entry.name == required),
                "{required}"
            );
        }

        let (kernel, context) = bootstrap(14_500);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        factory.install(&context, FakeBinding::new(150, [Step::Exit]));
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        let generation = publish(&context, 150);
        let authority = enqueue_root(&scheduler, &context, generation);
        drop(authority);
        let report = pool.shutdown().expect("clean receipt shutdown");
        let sequences: Vec<_> = report.events().iter().map(|event| event.sequence).collect();
        assert!(sequences.windows(2).all(|window| window[0] < window[1]));
        for expected in [
            ExecutorPoolEvent::Created,
            ExecutorPoolEvent::AuditPassed,
            ExecutorPoolEvent::Claimed {
                thread: context.thread().key(),
                generation,
            },
            ExecutorPoolEvent::Loaded {
                thread: context.thread().key(),
                generation,
            },
            ExecutorPoolEvent::Saved {
                thread: context.thread().key(),
                generation,
            },
            ExecutorPoolEvent::Destroyed,
            ExecutorPoolEvent::Joined,
        ] {
            assert!(report.events().iter().any(|event| event.event == expected));
        }
    }

    #[test]
    fn save_error_retains_exact_lease_authority_until_failure_settlement() {
        let (kernel, context) = bootstrap(14_600);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        let binding = FakeBinding::new(160, [Step::Yield]);
        binding.save_fails.store(true, Ordering::SeqCst);
        factory.install(&context, binding);
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        let authority = enqueue_root(&scheduler, &context, publish(&context, 160));
        drop(authority);
        pool.shutdown().expect_err("save failure retires worker");
        assert!(matches!(
            context.thread().execution_state(),
            ThreadExecutionState::Failed {
                reason: ExecutionFailure::SnapshotSaveFailed,
                ..
            }
        ));
    }
}
