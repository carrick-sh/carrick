use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Weak};

use parking_lot::{Condvar, Mutex};

use carrick_fatal::carrick_fatal;
use carrick_hal::{SignalArrival, VcpuRegistry};
use carrick_thread::thread::FutexTable;

use crate::run_result::RuntimeError;
use crate::vcpu_loop::continuation;
use crate::vcpu_loop::executor;
use crate::vcpu_loop::{
    HvpatchLoopResult, KernelAbortRecord, KernelState, LIVENESS_CONFIRM, LIVENESS_POLL,
    ProcessGraphLiveness,
};

/// Runtime-only delivery endpoint for one live HVPatch task generation.
/// Linux parentage remains authoritative in `Kernel`; this table only turns
/// the parent key selected there into the host wake objects needed to deliver
/// the configured child-exit signal.
#[derive(Clone)]
pub(crate) struct HvpatchRuntimeEndpoint {
    pub(crate) kernel: Weak<KernelState>,
    /// Exact parent task generation retained at endpoint publication. Each
    /// notification recaptures one CURRENT live thread through this binding so
    /// exec's replacement Sighand is observed without accepting PID reuse.
    pub(crate) task_binding: crate::kernel::KernelTaskBinding,
    /// Migration-only exact scheduler endpoint. While absent, the welded
    /// runner below remains the explicitly transitional fallback. When
    /// present, exact-generation scheduler wake is authoritative and the
    /// legacy wake vehicles are compatibility nudges only.
    pub(crate) scheduler: Option<Arc<crate::kernel::scheduler::Scheduler>>,
}

impl HvpatchRuntimeEndpoint {
    pub(crate) fn wake_scheduler_exact(
        &self,
        snapshot: &crate::kernel::core::KernelTaskSignalSnapshot,
    ) -> Result<bool, crate::kernel::scheduler::SchedulerError> {
        let Some(scheduler) = self.scheduler.as_ref() else {
            return Ok(false);
        };
        let mut delivered = false;
        for thread in snapshot.threads() {
            match scheduler.wake(thread.key()) {
                Ok(_) => delivered = true,
                Err(
                    crate::kernel::scheduler::SchedulerError::Thread(
                        crate::kernel::objects::ThreadExecutionError::InvalidTransition { .. },
                    )
                    | crate::kernel::scheduler::SchedulerError::UnknownThread,
                ) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(delivered)
    }
}

/// The kernel lane's [`TaskWaker`](crate::kernel::TaskWaker): the three vehicles a guest task on this
/// lane can be parked on, kicked together.
///
/// A parked guest is waiting on one of them and the kernel cannot tell which,
/// so all three fire. Each is a hint — the woken thread re-reads the
/// authoritative pending queue — which is what makes kicking all three safe
/// rather than merely wasteful.
///
/// These are the SAME objects child-exit notification has always used; routing
/// both through one waker is what keeps a single answer to "how is a task on
/// this lane woken".
pub(crate) struct HvpatchTaskWaker {
    /// Unparks a `FUTEX_WAIT`, and the futex-backed waits layered on it.
    pub(crate) futex: Arc<FutexTable>,
    /// Forces the vCPU out of `hv_vcpu_run` so a RUNNING guest reaches a
    /// boundary where it polls. Process-scoped, which is correct here: the
    /// waker is registered per Linux process with that process's own kicker.
    pub(crate) kicker: Arc<dyn VcpuRegistry>,
    /// Writes the wake pipes every parked `ThreadWaiter` kqueue watches.
    pub(crate) signal_arrival: Arc<dyn SignalArrival>,
}

impl std::fmt::Debug for HvpatchTaskWaker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HvpatchTaskWaker")
    }
}

impl crate::kernel::TaskWaker for HvpatchTaskWaker {
    fn wake_task(&self) {
        self.futex.notify_signal_pending();
        // Shared (`MAP_SHARED`) futex waiters park in the CARRIER-wide table,
        // not this process's — a wake that only pokes `self.futex` leaves a
        // shared waiter asleep until its timeout. Concretely: `tgkill` posts
        // the signal and comes through here; before this line, a target parked
        // in `tst_checkpoint_wait` never noticed the pending signal and the
        // sender's delivery handshake stalled its full 10 s (`tgkill01`).
        carrick_thread::platform_futex::carrier_shared_futex_table().notify_signal_pending();
        self.signal_arrival.wake_all_waiters();
        self.kicker.kick_all();
    }
}

pub(crate) struct HvpatchRuntimeDirectory {
    pub(crate) endpoints: Mutex<BTreeMap<crate::kernel::TaskKey, HvpatchRuntimeEndpoint>>,
    continuation_wait_service: Mutex<Option<Arc<continuation::CarrierWaitService>>>,
    pub(crate) scheduler: Mutex<Option<Arc<crate::kernel::scheduler::Scheduler>>>,
    /// The kernel this carrier's jobs live in, for the always-on
    /// `ProcessGraphLiveness` invariant and its post-mortem capture. `Weak`
    /// because the directory outlives no kernel: the runner OBSERVES the graph,
    /// it never keeps it alive.
    liveness_kernel: Mutex<Option<Weak<crate::kernel::Kernel>>>,
    /// The one abort this carrier has suffered, if any.
    ///
    /// An abort is CARRIER-terminal, not job-terminal. The kernel graph it
    /// describes is the carrier's only graph, so once it is captured every
    /// later job wait in this carrier is answered by that same record rather
    /// than starting a fresh wait. Without this, the container's own
    /// `ContainerJobGroup::join` unwedged and the implicit carrier's
    /// `shutdown_wait` immediately parked again on the jobs of guest tasks that
    /// are still running -- moving the hang instead of removing it.
    kernel_abort: Arc<Mutex<Option<KernelAbortRecord>>>,
    /// The policy this carrier's scheduler runs, if an embedder installed one.
    /// CARRIER-scoped, not container-scoped: HVPatch multiplexes every Linux
    /// task of every container in one carrier with ONE run queue, so the `P`
    /// set and the placement policy over it belong to the carrier.
    scheduling_policy: Mutex<Option<Arc<dyn carrick_hal::SchedulingPolicy>>>,
    persistent_bindings: Arc<executor::HvpatchTaskBindingDirectory>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    carrier_tasks:
        Mutex<Option<Arc<carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskStateDirectory>>>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    persistent_pool: Mutex<
        Option<
            executor::ExecutorPool<
                executor::HvpatchPersistentExecutorFactory,
                executor::HvpatchTaskBindingDirectory,
            >,
        >,
    >,
    /// Carrier-owned logical process jobs. No process child owns a host thread;
    /// the root waits these exact completions before shutting the shared pool.
    pub(crate) process_jobs: Mutex<ProcessJobDirectoryState>,
    pub(crate) process_jobs_changed: Condvar,
    shutdown: Mutex<RuntimeDirectoryShutdown>,
    shutdown_changed: Condvar,
}

#[derive(Default)]
pub(crate) struct ProcessJobDirectoryState {
    pub(crate) closing: bool,
    pub(crate) active_drains: usize,
    pub(crate) groups: BTreeMap<crate::kernel::ContainerId, ContainerJobState>,
    pub(crate) closed_groups: BTreeSet<crate::kernel::ContainerId>,
}

#[derive(Default)]
pub(crate) struct ContainerJobState {
    pub(crate) closing: bool,
    pub(crate) draining: bool,
    pub(crate) reservations: usize,
    pub(crate) jobs: Vec<HvpatchProcessJobHandle>,
}

#[derive(Clone, Default)]
pub(crate) struct ProcessPhysicalRetirement {
    state: Arc<ProcessPhysicalRetirementState>,
}

#[derive(Default)]
struct ProcessPhysicalRetirementState {
    publication: Mutex<ProcessPhysicalRetirementPublication>,
    changed: Condvar,
}

#[derive(Default)]
struct ProcessPhysicalRetirementPublication {
    exit_started: bool,
    completions: Option<Vec<continuation::LogicalJobCompletion>>,
}

impl ProcessPhysicalRetirement {
    pub(crate) fn begin_process_exit(&self) {
        let mut publication = self.state.publication.lock();
        publication.exit_started = true;
        self.state.changed.notify_all();
    }

    pub(crate) fn publish(
        &self,
        completions: Vec<continuation::LogicalJobCompletion>,
    ) -> Result<(), RuntimeError> {
        if completions.is_empty() {
            return Err(RuntimeError::Configuration(
                "HVPatch terminal physical-retirement receipt omitted every process member"
                    .to_owned(),
            ));
        }
        let mut publication = self.state.publication.lock();
        if publication.completions.is_some() {
            return Err(RuntimeError::Configuration(
                "HVPatch process physical-retirement receipt was published twice".to_owned(),
            ));
        }
        publication.completions = Some(completions);
        self.state.changed.notify_all();
        Ok(())
    }

    pub(crate) fn wait(&self) -> Result<(), RuntimeError> {
        self.wait_with_publication_timeout(PHYSICAL_JOB_RETIREMENT_TIMEOUT)
    }

    pub(crate) fn wait_if_exit_started_or_published(&self) -> Result<(), RuntimeError> {
        let must_wait = {
            let publication = self.state.publication.lock();
            publication.exit_started || publication.completions.is_some()
        };
        if must_wait { self.wait() } else { Ok(()) }
    }

    pub(crate) fn wait_with_publication_timeout(
        &self,
        publication_timeout: std::time::Duration,
    ) -> Result<(), RuntimeError> {
        let completions = {
            let mut publication = self.state.publication.lock();
            let mut deadline = None;
            while publication.completions.is_none() {
                if !publication.exit_started {
                    self.state.changed.wait(&mut publication);
                    continue;
                }
                let deadline = *deadline
                    .get_or_insert_with(|| std::time::Instant::now() + publication_timeout);
                let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now())
                else {
                    return Err(RuntimeError::CarrierFailed(
                        "HVPatch terminal physical-retirement receipt was not published".to_owned(),
                    ));
                };
                if self
                    .state
                    .changed
                    .wait_for(&mut publication, remaining)
                    .timed_out()
                    && publication.completions.is_none()
                {
                    return Err(RuntimeError::CarrierFailed(
                        "HVPatch terminal physical-retirement receipt was not published".to_owned(),
                    ));
                }
            }
            publication
                .completions
                .as_ref()
                .unwrap_or_else(|| carrick_fatal!("kernel::terminal_settlement", "A notified physical-retirement wait without its completion receipt is a torn terminal publication"))
                .clone()
        };
        for completion in completions {
            wait_for_physical_job_retirement(&completion)?;
        }
        Ok(())
    }
}

#[derive(Default)]
enum RuntimeDirectoryShutdown {
    #[default]
    Open,
    Closing,
    Closed(Result<(), String>),
}

pub(crate) struct PreparedPersistentServices {
    pub(crate) scheduler: Arc<crate::kernel::Scheduler>,
    pub(crate) wait_service: Arc<continuation::CarrierWaitService>,
}

pub(crate) enum HvpatchProcessJobHandle {
    Persistent {
        result: HvpatchLoopResult,
        completion: continuation::LogicalJobCompletion,
        process_retirement: ProcessPhysicalRetirement,
    },
}

#[derive(Clone)]
pub(crate) struct ContainerJobGroup {
    directory: Arc<HvpatchRuntimeDirectory>,
    container_id: crate::kernel::ContainerId,
}

pub(crate) struct ContainerJobReservation {
    directory: Arc<HvpatchRuntimeDirectory>,
    container_id: crate::kernel::ContainerId,
    armed: bool,
}

impl ContainerJobGroup {
    pub(crate) fn reserve(&self) -> Result<ContainerJobReservation, RuntimeError> {
        let mut state = self.directory.process_jobs.lock();
        if state.closing || state.closed_groups.contains(&self.container_id) {
            return Err(RuntimeError::CarrierClosing);
        }
        let group = state.groups.entry(self.container_id).or_default();
        if group.closing {
            return Err(RuntimeError::CarrierClosing);
        }
        group.reservations = group.reservations.checked_add(1).ok_or_else(|| {
            RuntimeError::CarrierFailed("HVPatch process job reservation overflow".to_owned())
        })?;
        Ok(ContainerJobReservation {
            directory: Arc::clone(&self.directory),
            container_id: self.container_id,
            armed: true,
        })
    }

    pub(crate) fn join(&self) -> Result<usize, RuntimeError> {
        let jobs = loop {
            let mut state = self.directory.process_jobs.lock();
            if state.closed_groups.contains(&self.container_id) {
                return Ok(0);
            }
            let group = state.groups.entry(self.container_id).or_default();
            group.closing = true;
            while state
                .groups
                .get(&self.container_id)
                .is_some_and(|group| group.reservations != 0)
            {
                self.directory.process_jobs_changed.wait(&mut state);
            }
            if state
                .groups
                .get(&self.container_id)
                .is_some_and(|group| group.draining)
            {
                self.directory.process_jobs_changed.wait(&mut state);
                continue;
            }
            let group = state
                .groups
                .get_mut(&self.container_id)
                .unwrap_or_else(|| carrick_fatal!("vcpu_loop::container_job_group", "A container job group disappeared after the closer claimed it and drained all reservations"));
            group.draining = true;
            let jobs = std::mem::take(&mut group.jobs);
            state.active_drains = state
                .active_drains
                .checked_add(1)
                .unwrap_or_else(|| carrick_fatal!("vcpu_loop::container_job_group", "The carrier active-drain counter overflowed while establishing exclusive container job-group drainage"));
            self.directory.process_jobs_changed.notify_all();
            break jobs;
        };
        let result = wait_process_jobs(jobs, &self.directory.process_graph_liveness());
        let mut state = self.directory.process_jobs.lock();
        let exact = state.groups.get(&self.container_id).is_some_and(|group| {
            group.closing && group.draining && group.reservations == 0 && group.jobs.is_empty()
        });
        if !exact || state.active_drains == 0 {
            carrick_fatal!(
                "vcpu_loop::container_job_group",
                "A drained container job group no longer has the exact closing, draining, reservation-free state, or the carrier lost its active-drain claim"
            );
        }
        state.groups.remove(&self.container_id);
        state.closed_groups.insert(self.container_id);
        state.active_drains -= 1;
        self.directory.process_jobs_changed.notify_all();
        result
    }
}

impl ContainerJobReservation {
    pub(crate) fn activate_with_process_retirement(
        mut self,
        result: HvpatchLoopResult,
        completion: continuation::LogicalJobCompletion,
        process_retirement: ProcessPhysicalRetirement,
    ) -> Result<(), RuntimeError> {
        let mut state = self.directory.process_jobs.lock();
        let Some(group) = state.groups.get_mut(&self.container_id) else {
            return Err(RuntimeError::CarrierFailed(
                "HVPatch process job reservation lost its exact group".to_owned(),
            ));
        };
        if group.reservations == 0 {
            return Err(RuntimeError::CarrierFailed(
                "HVPatch process job reservation was already consumed".to_owned(),
            ));
        }
        group.reservations -= 1;
        group.jobs.push(HvpatchProcessJobHandle::Persistent {
            result,
            completion,
            process_retirement,
        });
        self.armed = false;
        self.directory.process_jobs_changed.notify_all();
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn activate(
        self,
        result: HvpatchLoopResult,
        completion: continuation::LogicalJobCompletion,
    ) -> Result<(), RuntimeError> {
        let process_retirement = ProcessPhysicalRetirement::default();
        process_retirement.publish(vec![completion.clone()])?;
        self.activate_with_process_retirement(result, completion, process_retirement)
    }
}

impl Drop for ContainerJobReservation {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut state = self.directory.process_jobs.lock();
        let remove = if let Some(group) = state.groups.get_mut(&self.container_id) {
            if group.reservations == 0 {
                carrick_fatal!(
                    "vcpu_loop::container_job_group",
                    "Dropping an armed container-job reservation with a zero reservation count proves the exact admission token was already consumed"
                );
            }
            group.reservations -= 1;
            !group.closing && group.reservations == 0 && group.jobs.is_empty()
        } else {
            false
        };
        if remove {
            state.groups.remove(&self.container_id);
        }
        self.directory.process_jobs_changed.notify_all();
    }
}

pub(crate) fn wait_process_jobs(
    jobs: Vec<HvpatchProcessJobHandle>,
    liveness: &ProcessGraphLiveness,
) -> Result<usize, RuntimeError> {
    let joined = jobs.len();
    if let Some(recorded) = liveness.recorded() {
        return Err(recorded);
    }
    // Every job's result cell, kept so an abort can COMPLETE the ones this
    // loop has not reached. A judge that proved nobody will publish job N has
    // proved it for the whole group, and leaving the others pending would just
    // move the wedge to the next waiter.
    let pending: Vec<HvpatchLoopResult> = jobs
        .iter()
        .map(|job| match job {
            HvpatchProcessJobHandle::Persistent { result, .. } => result.clone(),
        })
        .collect();
    let mut child_errors = Vec::new();
    for (index, job) in jobs.into_iter().enumerate() {
        let result = match job {
            HvpatchProcessJobHandle::Persistent {
                result,
                completion,
                process_retirement,
            } => {
                let _completion_identity = completion.id();
                let result = result.wait_supervised(liveness);
                if let Err(RuntimeError::KernelAborted {
                    reason,
                    post_mortem,
                }) = &result
                {
                    for other in pending.iter().skip(index + 1) {
                        other.publish_if_pending(Err(RuntimeError::KernelAborted {
                            reason: reason.clone(),
                            post_mortem: Arc::clone(post_mortem),
                        }));
                    }
                    // The kernel is frozen and captured; waiting the remaining
                    // physical-retirement bounds would only add 5 s per job to
                    // an outcome that is already decided.
                    return Err(RuntimeError::KernelAborted {
                        reason: reason.clone(),
                        post_mortem: Arc::clone(post_mortem),
                    });
                }
                // Result publication happens from terminal settlement while
                // the worker still owns its loaded binding. Wait for the
                // quantum's drop receipt before container-scoped VFS and
                // mount-table retirement examines the ownership graph.
                match wait_for_physical_job_retirement(&completion).and_then(|()| match &result {
                    Ok(_) => process_retirement.wait(),
                    Err(_) => process_retirement.wait_if_exit_started_or_published(),
                }) {
                    Ok(()) => result,
                    Err(retirement_error) => match result {
                        Ok(_) => Err(retirement_error),
                        Err(result_error) => Err(RuntimeError::CarrierFailed(format!(
                            "{result_error}; {retirement_error}"
                        ))),
                    },
                }
            }
        };
        if let Err(error) = result {
            tracing::error!(%error, "HVPatch process job failed");
            child_errors.push(error.to_string());
        }
    }
    match child_errors.first() {
        Some(first) => Err(RuntimeError::Unsupported(format!(
            "HVPatch process child panicked ({} failed): first: {first}",
            child_errors.len()
        ))),
        None => Ok(joined),
    }
}

pub(crate) const PHYSICAL_JOB_RETIREMENT_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(5);

pub(crate) fn wait_for_physical_job_retirement(
    completion: &continuation::LogicalJobCompletion,
) -> Result<(), RuntimeError> {
    completion
        .wait_for_physical_retirement(PHYSICAL_JOB_RETIREMENT_TIMEOUT)
        .then_some(())
        .ok_or_else(|| {
            RuntimeError::CarrierFailed(format!(
                "logical HVPatch job {} published before its executor binding retired",
                completion.id().raw()
            ))
        })
}

impl HvpatchRuntimeDirectory {
    /// The carrier's directory, running `policy` (or the default per-CPU
    /// policy when the embedder installed none).
    pub(crate) fn with_scheduling_policy(
        policy: Option<Arc<dyn carrick_hal::SchedulingPolicy>>,
    ) -> Self {
        Self {
            scheduling_policy: Mutex::new(policy),
            ..Self::default()
        }
    }
}

impl Default for HvpatchRuntimeDirectory {
    fn default() -> Self {
        Self {
            endpoints: Mutex::new(BTreeMap::new()),
            continuation_wait_service: Mutex::new(None),
            scheduler: Mutex::new(None),
            liveness_kernel: Mutex::new(None),
            kernel_abort: Arc::default(),
            scheduling_policy: Mutex::new(None),
            persistent_bindings: Arc::default(),
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            carrier_tasks: Mutex::new(None),
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            persistent_pool: Mutex::new(None),
            process_jobs: Mutex::new(ProcessJobDirectoryState::default()),
            process_jobs_changed: Condvar::new(),
            shutdown: Mutex::new(RuntimeDirectoryShutdown::Open),
            shutdown_changed: Condvar::new(),
        }
    }
}

impl HvpatchRuntimeDirectory {
    pub(crate) fn container_job_group(
        self: &Arc<Self>,
        container_id: crate::kernel::ContainerId,
    ) -> ContainerJobGroup {
        ContainerJobGroup {
            directory: Arc::clone(self),
            container_id,
        }
    }

    /// The runner invariant's view of this carrier.
    pub(crate) fn process_graph_liveness(&self) -> ProcessGraphLiveness {
        ProcessGraphLiveness {
            kernel: self.liveness_kernel.lock().clone(),
            scheduler: self.scheduler.lock().clone(),
            recorded: Arc::clone(&self.kernel_abort),
            #[cfg(test)]
            fixed_census: None,
            poll: LIVENESS_POLL,
            confirm: LIVENESS_CONFIRM,
        }
    }

    pub(crate) fn live_job_group_count(&self) -> usize {
        self.process_jobs.lock().groups.len()
    }

    #[cfg(test)]
    pub(crate) fn live_process_job_count(&self) -> usize {
        self.process_jobs
            .lock()
            .groups
            .values()
            .map(|group| group.jobs.len())
            .sum()
    }

    pub(crate) fn persistent_bindings(&self) -> &Arc<executor::HvpatchTaskBindingDirectory> {
        &self.persistent_bindings
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn carrier_tasks(
        &self,
        kernel: &Arc<crate::kernel::Kernel>,
    ) -> Arc<carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskStateDirectory> {
        let mut installed = self.carrier_tasks.lock();
        Arc::clone(installed.get_or_insert_with(|| {
            static NEXT_DIRECTORY: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(1);
            let raw = NEXT_DIRECTORY
                .fetch_update(
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                    |current| current.checked_add(1),
                )
                .unwrap_or_else(|_| {
                    carrick_fatal!(
                        "hvpatch::process_identity",
                        "Parsing hexadecimal HVPatch process instance ID string failed"
                    )
                });
            let instance = std::num::NonZeroU64::new(raw).unwrap_or_else(|| {
                carrick_fatal!(
                    "hvpatch::process_identity",
                    "Parsed HVPatch process instance ID evaluated to zero"
                )
            });
            Arc::new(
                carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskStateDirectory::new(
                    instance,
                    kernel.hvpatch_child_token_verifier(),
                ),
            )
        }))
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn start_persistent_pool(
        &self,
        authority: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchPersistentExecutorFactoryAuthority,
        vcpu_ceiling: usize,
        services: &PreparedPersistentServices,
    ) -> Result<bool, RuntimeError> {
        let mut pool = self.persistent_pool.lock();
        if pool.is_some() {
            return Ok(false);
        }
        // The scheduler's `P` count is the guest CPU count; the `M` count is
        // still host parallelism, and the executors bind to the `P`s
        // round-robin. Cutting `M` to `P` is the design's steady state and it
        // no longer wedges — see `ExecutorPoolConfig` for the 2026-09-08
        // measurement that retired that claim, and for why the timing
        // comparison that replaced it is not yet conclusive.
        // `CARRICK_BOUND_EXECUTORS` is the exact hatch that settles it without
        // a rebuild.
        let bound_workers = executor::configured_bound_executors(services.scheduler.cpu_count());
        let spare_executors = executor::configured_spare_executors(services.scheduler.cpu_count());
        let factory = Arc::new(executor::HvpatchPersistentExecutorFactory::new(authority));
        let started = self.start_services_transaction(services, || {
            executor::ExecutorPool::start(
                executor::ExecutorPoolConfig {
                    bound_workers,
                    spare_executors,
                    vcpu_ceiling,
                    reserve: 0,
                },
                Arc::clone(&services.scheduler),
                factory,
                Arc::clone(&self.persistent_bindings),
                executor::ExecutorBoundaryAudit,
            )
            .map_err(|error| RuntimeError::Configuration(error.to_string()))
        })?;
        *pool = Some(started);
        Ok(true)
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn shutdown_persistent_pool(&self) -> Result<(), RuntimeError> {
        let Some(pool) = self.persistent_pool.lock().take() else {
            return Ok(());
        };
        tracing::info!("HVPatch persistent pool shutdown begins (run queue will close)");
        let result = pool
            .shutdown()
            .map(|_| ())
            .map_err(|error| RuntimeError::Configuration(error.to_string()));
        *self.continuation_wait_service.lock() = None;
        *self.scheduler.lock() = None;
        for endpoint in self.endpoints.lock().values_mut() {
            endpoint.scheduler = None;
        }
        result
    }

    /// Bind the kernel the runner's liveness invariant observes. Idempotent
    /// for one kernel; a DIFFERENT kernel replaces it, because the carrier has
    /// exactly one live kernel graph and the invariant must judge that one.
    fn bind_liveness_kernel(&self, kernel: &Arc<crate::kernel::Kernel>) {
        let mut slot = self.liveness_kernel.lock();
        if slot
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some_and(|installed| Arc::ptr_eq(&installed, kernel))
        {
            return;
        }
        *slot = Some(Arc::downgrade(kernel));
    }

    pub(crate) fn prepare_persistent_services(
        &self,
        kernel: &Arc<crate::kernel::Kernel>,
    ) -> PreparedPersistentServices {
        self.bind_liveness_kernel(kernel);
        if let Some(scheduler) = self.scheduler.lock().clone() {
            let wait_service = self
                .continuation_wait_service
                .lock()
                .as_ref()
                .map(Arc::clone)
                .unwrap_or_else(|| carrick_fatal!("vcpu_loop::persistent_services", "A published carrier scheduler without its paired continuation wait service is a torn persistent-service transaction"));
            return PreparedPersistentServices {
                scheduler,
                wait_service,
            };
        }
        let scheduler = self.carrier_scheduler(kernel);
        let wait_service = Arc::new(continuation::CarrierWaitService::new(Arc::clone(
            &scheduler,
        )));
        PreparedPersistentServices {
            scheduler,
            wait_service,
        }
    }

    /// Build THE carrier's scheduler and publish the CPU count its policy
    /// fixes, which is from here on the guest's `nproc`. This is the only
    /// place that publishes: `RunQueue::new` is also driven by every in-crate
    /// reference-model kernel with its own CPU count, and none of those is the
    /// guest's answer.
    fn carrier_scheduler(
        &self,
        kernel: &Arc<crate::kernel::Kernel>,
    ) -> Arc<crate::kernel::scheduler::Scheduler> {
        let policy = self.scheduling_policy();
        crate::kernel::scheduler::publish_guest_cpu_count(policy.cpu_count());
        Arc::new(crate::kernel::Scheduler::new_with_policy(
            Arc::clone(kernel),
            policy,
        ))
    }

    /// The policy to build the carrier's scheduler with: the installed one, or
    /// the default per-CPU policy sized by the host's guest CPU count.
    fn scheduling_policy(&self) -> Arc<dyn carrick_hal::SchedulingPolicy> {
        self.scheduling_policy.lock().clone().unwrap_or_else(|| {
            Arc::new(carrick_hal::GuestCpuPolicy::new(
                crate::kernel::scheduler::default_guest_cpu_count(),
            ))
        })
    }

    fn publish_persistent_services(&self, services: &PreparedPersistentServices) {
        let mut scheduler = self.scheduler.lock();
        let mut wait_service = self.continuation_wait_service.lock();
        match (scheduler.as_ref(), wait_service.as_ref()) {
            (None, None) => {
                *scheduler = Some(Arc::clone(&services.scheduler));
                *wait_service = Some(Arc::clone(&services.wait_service));
            }
            (Some(installed_scheduler), Some(installed_wait_service))
                if Arc::ptr_eq(installed_scheduler, &services.scheduler)
                    && Arc::ptr_eq(installed_wait_service, &services.wait_service) => {}
            _ => carrick_fatal!(
                "vcpu_loop::persistent_services",
                "Publishing prepared persistent services over a partial or identity-mismatched scheduler/wait-service pair would split carrier service authority"
            ),
        }
        for endpoint in self.endpoints.lock().values_mut() {
            endpoint.scheduler = Some(Arc::clone(&services.scheduler));
        }
    }

    pub(crate) fn start_services_transaction<T>(
        &self,
        services: &PreparedPersistentServices,
        start: impl FnOnce() -> Result<T, RuntimeError>,
    ) -> Result<T, RuntimeError> {
        let started = start()?;
        self.publish_persistent_services(services);
        Ok(started)
    }

    pub(crate) fn continuation_services(
        &self,
        kernel: &Arc<crate::kernel::Kernel>,
    ) -> (
        Arc<crate::kernel::Scheduler>,
        Arc<continuation::CarrierWaitService>,
    ) {
        self.bind_liveness_kernel(kernel);
        let scheduler = {
            let mut slot = self.scheduler.lock();
            Arc::clone(slot.get_or_insert_with(|| {
                Arc::new(crate::kernel::Scheduler::new_with_policy(
                    Arc::clone(kernel),
                    self.scheduling_policy(),
                ))
            }))
        };
        for endpoint in self.endpoints.lock().values_mut() {
            if endpoint.scheduler.is_none() {
                endpoint.scheduler = Some(Arc::clone(&scheduler));
            }
        }
        let service = {
            let mut slot = self.continuation_wait_service.lock();
            Arc::clone(slot.get_or_insert_with(|| {
                Arc::new(continuation::CarrierWaitService::new(Arc::clone(
                    &scheduler,
                )))
            }))
        };
        (scheduler, service)
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Task 4 installs the persistent executor scheduler through this packaged seam"
        )
    )]
    pub(crate) fn install_scheduler(
        &self,
        scheduler: Arc<crate::kernel::scheduler::Scheduler>,
    ) -> Result<(), RuntimeError> {
        let mut installed = self.scheduler.lock();
        if installed.is_some() || !self.endpoints.lock().is_empty() {
            return Err(RuntimeError::Unsupported(
                "HVPatch scheduler must be installed exactly once before endpoint publication"
                    .to_owned(),
            ));
        }
        *installed = Some(scheduler);
        Ok(())
    }

    pub(crate) fn register_endpoint(
        &self,
        task: crate::kernel::TaskKey,
        kernel: Weak<KernelState>,
        task_binding: crate::kernel::KernelTaskBinding,
    ) {
        let scheduler = self.scheduler.lock().clone();
        self.register(
            task,
            HvpatchRuntimeEndpoint {
                kernel,
                task_binding,
                scheduler,
            },
        );
    }

    pub(crate) fn register(&self, task: crate::kernel::TaskKey, endpoint: HvpatchRuntimeEndpoint) {
        self.endpoints.lock().insert(task, endpoint);
    }

    /// Wake every registered task's parked vehicles so they re-check pending
    /// signal state. The process-directed signal lane's host publication
    /// (`PROC_PENDING`) carries no task identity, so arrival is a carrier
    /// broadcast; `task.wake()` is a hint and spurious wakes are harmless.
    /// Without this, a thread parked in a non-futex continuation (wait4's
    /// `WaitOnHvpatchChild`) never observed a process-directed SIGALRM: the
    /// pump's `kick_all` reaches only live vCPU leases and its futex notify
    /// only enrolled futex waiters (the `waitrestart` hang).
    pub(crate) fn wake_all_tasks_for_process_signal(&self) {
        let endpoints: Vec<HvpatchRuntimeEndpoint> =
            self.endpoints.lock().values().cloned().collect();
        for endpoint in endpoints {
            if endpoint.kernel.upgrade().is_none() {
                continue;
            }
            let Ok(snapshot) = endpoint.task_binding.capture_signal_snapshot() else {
                continue;
            };
            snapshot.context().task().wake();
        }
    }

    pub(crate) fn remove(&self, task: crate::kernel::TaskKey) {
        self.endpoints.lock().remove(&task);
    }

    fn join_all_process_threads(&self) -> Result<(), RuntimeError> {
        // Carry the joined children's actual failure payloads into the
        // terminal clause: the bare "HVPatch process child panicked" summary
        // hid the root cause behind a generic string (14 gate-14 rows were
        // indistinguishable until their stderr tails were exhumed one by
        // one), and a 2-line stderr tail can cut the tracing line that held
        // the detail.
        let jobs = {
            let mut state = self.process_jobs.lock();
            state.closing = true;
            for group in state.groups.values_mut() {
                group.closing = true;
            }
            while state.active_drains != 0
                || state.groups.values().any(|group| group.reservations != 0)
            {
                self.process_jobs_changed.wait(&mut state);
            }
            let groups = std::mem::take(&mut state.groups);
            state.closed_groups.extend(groups.keys().copied());
            groups.into_values().flat_map(|group| group.jobs).collect()
        };
        wait_process_jobs(jobs, &self.process_graph_liveness()).map(|_| ())
    }

    pub(crate) fn shutdown_carrier_runtime(&self) -> Result<(), RuntimeError> {
        {
            let mut shutdown = self.shutdown.lock();
            loop {
                match &*shutdown {
                    RuntimeDirectoryShutdown::Open => {
                        *shutdown = RuntimeDirectoryShutdown::Closing;
                        break;
                    }
                    RuntimeDirectoryShutdown::Closing => {
                        self.shutdown_changed.wait(&mut shutdown);
                    }
                    RuntimeDirectoryShutdown::Closed(result) => {
                        return result.clone().map_err(RuntimeError::CarrierFailed);
                    }
                }
            }
        }
        let process_result = self.join_all_process_threads();
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let pool_result = self.shutdown_persistent_pool();
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        let pool_result = Ok(());
        let result = process_result
            .and(pool_result)
            .map_err(|error| format!("carrier runtime shutdown failed: {error}"));
        let mut shutdown = self.shutdown.lock();
        *shutdown = RuntimeDirectoryShutdown::Closed(result.clone());
        self.shutdown_changed.notify_all();
        result.map_err(RuntimeError::CarrierFailed)
    }

    pub(crate) fn notify_child_exit(&self, parent: crate::kernel::TaskKey, signal: Option<i32>) {
        let Some(endpoint) = self.endpoints.lock().get(&parent).cloned() else {
            tracing::error!(
                parent = ?parent,
                "child exit notification dropped: no runtime endpoint for the parent"
            );
            return;
        };
        let Some(parent_kernel) = endpoint.kernel.upgrade() else {
            tracing::error!(
                parent = ?parent,
                "child exit notification dropped: parent KernelState already dropped"
            );
            return;
        };
        let signal_snapshot = match endpoint.task_binding.capture_signal_snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                tracing::error!(
                    parent = ?parent,
                    %error,
                    "child exit notification dropped: parent signal snapshot unavailable"
                );
                return;
            }
        };
        let signal_context = signal_snapshot.context();
        if let Some(signal) = signal
            && parent_kernel
                .dispatcher
                .child_exit_signal_snapshot_needs_pump(&signal_snapshot, signal as u32)
        {
            parent_kernel
                .dispatcher
                .mark_in_process_signal_pending(signal_context, signal);
        }
        // Child waitability is independent of SIGCHLD disposition. The Kernel
        // zombie is durable, but a parent can be between its initial wait query
        // and host-wait enrollment when publication occurs; always nudge every
        // wait vehicle so it rechecks the authoritative graph even when SIGCHLD
        // is ignored or blocked.
        let _ = signal_context.task().publish_wake_subscriptions();
        if let Err(error) = endpoint.wake_scheduler_exact(&signal_snapshot) {
            tracing::error!(parent = ?parent, %error, "authoritative scheduler wake rejected");
        }
    }
}

pub(crate) fn shared_futex_wake(host_addr: usize, waiter_key: usize, count: u32) -> i64 {
    let carrier_woken =
        carrick_thread::platform_futex::carrier_shared_futex_table().wake(waiter_key as u64, count);
    let ulock_woken = crate::ulock::wake_counted(host_addr, waiter_key, count);
    crate::probes::ulock_wake(host_addr as u64, 0, ulock_woken);
    i64::from(carrier_woken).max(ulock_woken.max(0))
}

pub(crate) fn trace_shared_futex_requeue(
    phase: u32,
    from_key: usize,
    to_key: usize,
    wake_req: u32,
    requeue_req: u32,
    wake_ret: u32,
    requeue_ret: u32,
) {
    let from = crate::ulock::waiter_debug_counts(from_key);
    let to = crate::ulock::waiter_debug_counts(to_key);
    crate::probes::ulock_requeue(crate::probes::UlockRequeueProbe {
        phase,
        from_key: from_key as u64,
        to_key: to_key as u64,
        wake_req,
        requeue_req,
        wake_ret,
        requeue_ret,
        from_count: from.count,
        from_requeue_wake: from.requeue_wake,
        from_requeue_count: from.requeue_count,
        from_logical_requeued: from.logical_requeued,
        from_logical_wake: from.logical_wake,
        to_count: to.count,
        to_requeue_wake: to.requeue_wake,
        to_requeue_count: to.requeue_count,
        to_logical_requeued: to.logical_requeued,
        to_logical_wake: to.logical_wake,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::SyscallDispatcher;
    use crate::thread::ThreadId;
    use crate::vcpu_loop::VcpuLoopOutcome;

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

    struct EndpointTestSignalPump;

    impl carrick_hal::SignalPumpControl for EndpointTestSignalPump {
        fn start_signal_pump(
            &self,
            _registry: &Arc<dyn VcpuRegistry>,
            _futex: &Arc<dyn carrick_hal::PlatformFutex>,
        ) {
        }
    }

    struct EndpointTestSignalArrival;

    impl carrick_hal::SignalArrival for EndpointTestSignalArrival {
        fn wake_all_waiters(&self) {}
    }

    #[test]
    fn carrier_retains_and_retires_exact_persistent_process_completion() {
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

        let directory = Arc::new(HvpatchRuntimeDirectory::default());
        let group = directory.container_job_group(crate::kernel::ContainerId::allocate());
        let reservation = group.reserve().expect("reserve process job");
        let result = HvpatchLoopResult::pending();
        let completion = continuation::LogicalJobCompletion::pending();
        let quantum = Arc::new(continuation::HvpatchTaskQuantum::new(
            Box::new(NeverPolled),
            completion.clone(),
        ));
        reservation
            .activate(result.clone(), completion.clone())
            .expect("enroll process job");
        assert_eq!(directory.process_jobs.lock().groups.len(), 1);
        result.publish(Ok(VcpuLoopOutcome::ThreadDone));
        completion.publish();
        let (joined_tx, joined_rx) = std::sync::mpsc::sync_channel(1);
        let closer = group.clone();
        let join = std::thread::spawn(move || {
            joined_tx.send(closer.join()).expect("report join");
        });
        assert!(
            joined_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "logical completion must not outrun physical binding retirement"
        );
        drop(quantum);
        assert_eq!(joined_rx.recv().expect("join result").unwrap(), 1);
        join.join().expect("closer");
        assert!(directory.process_jobs.lock().groups.is_empty());
    }

    #[test]
    fn process_child_join_does_not_outrun_sibling_terminal_mount_owner() {
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

        let directory = Arc::new(HvpatchRuntimeDirectory::default());
        let group = directory.container_job_group(crate::kernel::ContainerId::allocate());
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
        let process_retirement = ProcessPhysicalRetirement::default();
        process_retirement
            .publish(vec![root_completion.clone(), sibling_completion.clone()])
            .unwrap();
        group
            .reserve()
            .expect("reserve child root")
            .activate_with_process_retirement(
                root_result.clone(),
                root_completion.clone(),
                process_retirement,
            )
            .expect("activate child root");

        let (joined_tx, joined_rx) = std::sync::mpsc::sync_channel(1);
        let closer = group.clone();
        let join = std::thread::spawn(move || {
            joined_tx.send(closer.join()).expect("report child join");
        });
        root_result.publish(Ok(VcpuLoopOutcome::ThreadDone));
        root_completion.publish();
        sibling_completion.publish();
        drop(root_quantum);

        assert!(
            joined_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "process-child join must retain the sibling owner's physical completion"
        );
        assert!(mounts.prepare().is_err());

        drop(sibling_quantum);
        assert_eq!(joined_rx.recv().expect("join result").unwrap(), 1);
        join.join().expect("closer");
        mounts.prepare().expect("all physical mount owners retired");
    }

    #[test]
    fn process_retirement_receipt_fails_closed_after_exit_starts() {
        let retirement = ProcessPhysicalRetirement::default();
        retirement.begin_process_exit();

        let error = retirement
            .wait_with_publication_timeout(std::time::Duration::from_millis(20))
            .expect_err("started process exit must not wait forever for a missing receipt");
        assert!(
            error
                .to_string()
                .contains("terminal physical-retirement receipt was not published"),
            "unexpected invariant: {error}"
        );
    }

    #[test]
    fn container_job_groups_are_scoped() {
        let directory = Arc::new(HvpatchRuntimeDirectory::default());
        let alpha_id = crate::kernel::ContainerId::allocate();
        let beta_id = crate::kernel::ContainerId::allocate();
        let alpha = directory.container_job_group(alpha_id);
        let beta = directory.container_job_group(beta_id);
        let alpha_result = HvpatchLoopResult::pending();
        let alpha_completion = continuation::LogicalJobCompletion::pending();
        let beta_result = HvpatchLoopResult::pending();
        let beta_completion = continuation::LogicalJobCompletion::pending();
        alpha
            .reserve()
            .expect("reserve alpha")
            .activate(alpha_result.clone(), alpha_completion.clone())
            .expect("enroll alpha");
        beta.reserve()
            .expect("reserve beta")
            .activate(beta_result.clone(), beta_completion.clone())
            .expect("enroll beta");

        alpha_result.publish(Ok(VcpuLoopOutcome::ThreadDone));
        alpha_completion.publish();
        alpha_completion.publish_physical_retirement_for_test();
        let (joined_tx, joined_rx) = std::sync::mpsc::sync_channel(1);
        let alpha_join = alpha.clone();
        std::thread::spawn(move || {
            joined_tx
                .send(alpha_join.join())
                .expect("report alpha join");
        });
        assert_eq!(
            joined_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("alpha join must not wait for beta")
                .expect("alpha join"),
            1
        );
        assert!(
            alpha
                .reserve()
                .and_then(|reservation| reservation.activate(
                    HvpatchLoopResult::pending(),
                    continuation::LogicalJobCompletion::pending(),
                ))
                .is_err()
        );
        assert_eq!(directory.live_job_group_count(), 1);

        beta_result.publish(Ok(VcpuLoopOutcome::ThreadDone));
        beta_completion.publish();
        beta_completion.publish_physical_retirement_for_test();
        assert_eq!(beta.join().expect("beta join"), 1);
        assert_eq!(directory.live_job_group_count(), 0);
    }

    #[test]
    fn container_job_close_waits_for_preclose_reservation_and_reclaims_row() {
        let directory = Arc::new(HvpatchRuntimeDirectory::default());
        let group = directory.container_job_group(crate::kernel::ContainerId::allocate());
        let reservation = group.reserve().expect("reserve before close");
        let (joined_tx, joined_rx) = std::sync::mpsc::sync_channel(1);
        let closer = group.clone();
        let close = std::thread::spawn(move || {
            joined_tx.send(closer.join()).expect("report join");
        });
        assert!(
            joined_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err()
        );
        assert!(matches!(group.reserve(), Err(RuntimeError::CarrierClosing)));

        let result = HvpatchLoopResult::pending();
        let completion = continuation::LogicalJobCompletion::pending();
        reservation
            .activate(result.clone(), completion.clone())
            .expect("pre-close reservation may activate during drain");
        result.publish(Ok(VcpuLoopOutcome::ThreadDone));
        completion.publish();
        completion.publish_physical_retirement_for_test();
        assert_eq!(joined_rx.recv().expect("join result").expect("join"), 1);
        close.join().expect("closer");
        assert_eq!(directory.live_job_group_count(), 0);
        assert!(directory.process_jobs.lock().groups.is_empty());
        assert!(matches!(group.reserve(), Err(RuntimeError::CarrierClosing)));
    }

    #[test]
    fn dropped_job_reservation_rolls_back_without_leaking_group_row() {
        let directory = Arc::new(HvpatchRuntimeDirectory::default());
        let group = directory.container_job_group(crate::kernel::ContainerId::allocate());
        drop(group.reserve().expect("reserve"));
        assert_eq!(directory.live_job_group_count(), 0);
        assert!(directory.process_jobs.lock().groups.is_empty());
    }

    #[test]
    fn carrier_shutdown_closes_admission_and_replays_one_failure() {
        let directory = Arc::new(HvpatchRuntimeDirectory::default());
        let group = directory.container_job_group(crate::kernel::ContainerId::allocate());
        let result = HvpatchLoopResult::pending();
        let completion = continuation::LogicalJobCompletion::pending();
        group
            .reserve()
            .expect("reserve")
            .activate(result.clone(), completion.clone())
            .expect("activate");
        result.publish(Err(RuntimeError::Unsupported(
            "injected child failure".to_owned(),
        )));
        completion.publish();
        completion.publish_physical_retirement_for_test();

        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut callers = Vec::new();
        for _ in 0..2 {
            let directory = Arc::clone(&directory);
            let barrier = Arc::clone(&barrier);
            callers.push(std::thread::spawn(move || {
                barrier.wait();
                directory
                    .shutdown_carrier_runtime()
                    .map_err(|error| error.to_string())
            }));
        }
        barrier.wait();
        let first = callers.remove(0).join().expect("first caller");
        let second = callers.remove(0).join().expect("second caller");
        assert_eq!(first, second);
        assert!(
            first
                .expect_err("stable failure")
                .contains("injected child failure")
        );
        assert!(matches!(group.reserve(), Err(RuntimeError::CarrierClosing)));
        assert!(directory.process_jobs.lock().groups.is_empty());
    }

    #[test]
    fn carrier_shutdown_waits_for_container_specific_active_drain() {
        let directory = Arc::new(HvpatchRuntimeDirectory::default());
        let group = directory.container_job_group(crate::kernel::ContainerId::allocate());
        let result = HvpatchLoopResult::pending();
        let completion = continuation::LogicalJobCompletion::pending();
        group
            .reserve()
            .expect("reserve")
            .activate(result.clone(), completion.clone())
            .expect("activate");

        let (group_tx, group_rx) = std::sync::mpsc::sync_channel(1);
        let group_closer = group.clone();
        let group_thread = std::thread::spawn(move || {
            group_tx.send(group_closer.join()).expect("report group");
        });
        {
            let mut state = directory.process_jobs.lock();
            while state.active_drains == 0 {
                directory.process_jobs_changed.wait(&mut state);
            }
        }

        let (carrier_tx, carrier_rx) = std::sync::mpsc::sync_channel(1);
        let shutdown_directory = Arc::clone(&directory);
        let carrier_thread = std::thread::spawn(move || {
            carrier_tx
                .send(shutdown_directory.shutdown_carrier_runtime())
                .expect("report carrier");
        });
        assert!(
            carrier_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err()
        );
        result.publish(Ok(VcpuLoopOutcome::ThreadDone));
        completion.publish();
        completion.publish_physical_retirement_for_test();
        assert_eq!(group_rx.recv().expect("group result").expect("group"), 1);
        carrier_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("carrier released after group")
            .expect("carrier shutdown");
        group_thread.join().expect("group closer");
        carrier_thread.join().expect("carrier closer");
    }

    #[test]
    fn prepared_persistent_services_publish_only_after_commit_and_are_retryable() {
        let context = alias_context(67_099);
        let directory = HvpatchRuntimeDirectory::default();
        let first = directory.prepare_persistent_services(context.kernel());
        let error = directory
            .start_services_transaction(&first, || {
                Err::<(), _>(RuntimeError::Configuration(
                    "injected executor start failure".to_owned(),
                ))
            })
            .expect_err("start failure");
        assert!(
            error
                .to_string()
                .contains("injected executor start failure")
        );
        assert!(directory.scheduler.lock().is_none());
        assert!(directory.continuation_wait_service.lock().is_none());
        drop(first);

        let retry = directory.prepare_persistent_services(context.kernel());
        assert!(directory.scheduler.lock().is_none());
        assert!(directory.continuation_wait_service.lock().is_none());
        directory
            .start_services_transaction(&retry, || Ok(()))
            .expect("retry start");
        assert!(Arc::ptr_eq(
            directory.scheduler.lock().as_ref().expect("scheduler"),
            &retry.scheduler,
        ));
        assert!(Arc::ptr_eq(
            directory
                .continuation_wait_service
                .lock()
                .as_ref()
                .expect("wait service"),
            &retry.wait_service,
        ));
    }

    #[test]
    fn prepared_persistent_services_accept_exact_boot_published_authority() {
        let context = alias_context(67_100);
        let directory = HvpatchRuntimeDirectory::default();
        let (installed_scheduler, installed_wait_service) =
            directory.continuation_services(context.kernel());
        let prepared = directory.prepare_persistent_services(context.kernel());
        assert!(Arc::ptr_eq(&installed_scheduler, &prepared.scheduler));
        assert!(Arc::ptr_eq(&installed_wait_service, &prepared.wait_service));

        directory
            .start_services_transaction(&prepared, || Ok(()))
            .expect("exact pre-published services remain a valid startup transaction");
        assert!(Arc::ptr_eq(
            directory.scheduler.lock().as_ref().expect("scheduler"),
            &prepared.scheduler,
        ));
        assert!(Arc::ptr_eq(
            directory
                .continuation_wait_service
                .lock()
                .as_ref()
                .expect("wait service"),
            &prepared.wait_service,
        ));
    }

    #[test]
    fn hvpatch_child_exit_reads_the_post_exec_sighand_generation() {
        let dispatcher = SyscallDispatcher::new();
        let pre_exec = dispatcher
            .capture_one_task_context()
            .expect("pre-exec context");
        let task = pre_exec.task().key();
        let directory = HvpatchRuntimeDirectory::default();
        let kernel = Arc::new(KernelState::new(
            dispatcher,
            Arc::new(EndpointTestSignalPump),
            Arc::new(EndpointTestSignalArrival),
            None,
            None,
            None,
        ));
        directory.register(
            task,
            HvpatchRuntimeEndpoint {
                kernel: Arc::downgrade(&kernel),
                task_binding: pre_exec.task_binding(),
                scheduler: None,
            },
        );

        let prepared = kernel
            .dispatcher
            .prepare_one_task_kernel_exec(&pre_exec)
            .expect("prepare exec");
        let post_exec = kernel
            .dispatcher
            .commit_one_task_kernel_exec(prepared)
            .expect("commit exec");
        let chld = crate::linux_abi::LINUX_SIGCHLD;
        let signal = crate::kernel::LinuxSignal::for_signal_number(chld).expect("SIGCHLD");
        let mut caught = carrick_abi::LinuxSigaction::empty();
        caught.sa_handler = 0x4000;
        post_exec.shared().sighand().install_action(signal, caught);

        assert_eq!(pre_exec.task().key(), post_exec.task().key());
        assert_ne!(pre_exec.revision(), post_exec.revision());
        assert_ne!(pre_exec.thread().key(), post_exec.thread().key());
        assert_ne!(
            pre_exec.shared().sighand().id(),
            post_exec.shared().sighand().id()
        );
        let post_exec_snapshot = pre_exec
            .task_binding()
            .capture_signal_snapshot()
            .expect("post-exec signal snapshot");
        assert_eq!(
            post_exec_snapshot.context().revision(),
            post_exec.revision()
        );
        assert_eq!(
            post_exec_snapshot.context().thread().key(),
            post_exec.thread().key()
        );
        assert_eq!(post_exec_snapshot.threads().len(), 1);
        assert_eq!(
            post_exec_snapshot.threads()[0].key(),
            post_exec.thread().key()
        );
        assert_eq!(
            post_exec.shared().sighand().disposition(signal),
            crate::kernel::SignalDisposition::Caught
        );
        directory.notify_child_exit(task, Some(chld));
        assert!(
            post_exec
                .shared()
                .pending_signals()
                .present()
                .contains(chld)
        );
    }
}
