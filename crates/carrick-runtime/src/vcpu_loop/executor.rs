//! Persistent owner-thread executor pool used to prove the HVPatch M:N
//! lifecycle before a real HVF backend is wired to it.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;

use parking_lot::Mutex;

use carrick_abi::LinuxGuestAbi;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use carrick_hal::ThreadedEngine as _;

use crate::dispatch::SyscallDispatcher;
#[cfg(test)]
use crate::kernel::SchedulerError;
use crate::kernel::objects::{
    BlockedReason, ExecutionFailure, ExecutionGeneration, ExecutorId, MigratableTaskState,
    ThreadExecutionLease, ThreadKey,
};
use crate::kernel::{
    ExecutorBinding, ExecutorKick, ExecutorKickToken, ExecutorRegistration, MmId, RunnableThread,
    Scheduler, SubmissionAuthority,
};
use crate::trap::TrapError;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct HvpatchPersistentExecutorFactory {
    authority: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchPersistentExecutorFactoryAuthority,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvpatchPersistentExecutorFactory {
    pub(crate) fn new(
        authority: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchPersistentExecutorFactoryAuthority,
    ) -> Self {
        Self { authority }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct HvpatchPersistentExecutor {
    executor_id: ExecutorId,
    lifecycle: Option<carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Vmm>,
    vcpu: Option<carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Vcpu>,
    current: Option<carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Engine>,
    binding: Option<Arc<crate::vcpu_loop::continuation::HvpatchTaskBinding>>,
    loaded_task_only: Option<carrick_vmm_hvf::hvf_aarch64_engine::HvpatchTaskOnlyEngineState>,
    receipt: ExecutorCpuReceipt,
    raw_vcpu_id: u64,
    owner_thread_port: u32,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct HvpatchTaskEngineBindingState {
    payload: HvpatchTaskEngineBindingPayload,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
enum HvpatchTaskEngineBindingPayload {
    Resident(Box<carrick_vmm_hvf::hvf_aarch64_engine::HvpatchTaskEngineState>),
    TaskOnly(Box<carrick_vmm_hvf::hvf_aarch64_engine::HvpatchTaskOnlyEngineState>),
    #[cfg(test)]
    Test,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvpatchTaskEngineBindingState {
    pub(crate) fn initial(
        state: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchTaskEngineState,
    ) -> Self {
        Self {
            payload: HvpatchTaskEngineBindingPayload::Resident(Box::new(state)),
        }
    }

    pub(crate) fn task_only(
        state: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchTaskOnlyEngineState,
    ) -> Self {
        Self {
            payload: HvpatchTaskEngineBindingPayload::TaskOnly(Box::new(state)),
        }
    }

    #[cfg(test)]
    pub(crate) fn test_only() -> Self {
        Self {
            payload: HvpatchTaskEngineBindingPayload::Test,
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PersistentExecutorFactory for HvpatchPersistentExecutorFactory {
    type Executor = HvpatchPersistentExecutor;
    fn create(&self, executor: ExecutorId) -> Result<Self::Executor, TrapError> {
        let (lifecycle, vcpu) = self.authority.create_executor_parts()?;
        let raw_vcpu_id = carrick_vmm_hvf::hvf_aarch64_engine::persistent_vcpu_identity(&vcpu);
        let owner_thread_port = current_owner_thread_port();
        Ok(HvpatchPersistentExecutor {
            executor_id: executor,
            lifecycle: Some(lifecycle),
            vcpu: Some(vcpu),
            current: None,
            binding: None,
            loaded_task_only: None,
            receipt: ExecutorCpuReceipt::default(),
            raw_vcpu_id,
            owner_thread_port,
        })
    }
}

fn probe_executor_lifecycle(
    executor: ExecutorId,
    phase: crate::probes::HvpatchExecutorLifecyclePhase,
    thread: Option<ThreadKey>,
    generation: Option<ExecutionGeneration>,
    asid_generation: u64,
) {
    crate::probes::hvpatch_executor_lifecycle(
        executor.raw_for_probe(),
        phase,
        thread.map_or(0, |key| key.serial.raw()),
        generation.map_or(0, ExecutionGeneration::raw),
        asid_generation,
    );
}

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

pub(crate) trait PersistentExecutorFactory: Send + Sync + 'static {
    type Executor: PersistentExecutor;

    fn create(&self, executor: ExecutorId) -> Result<Self::Executor, TrapError>;
}

pub(crate) trait PersistentExecutor: 'static {
    type TaskBinding: PersistentTaskBinding + Send + Sync + 'static;

    fn load(&mut self, task: &RunnableTask<'_, Self::TaskBinding>) -> Result<(), TrapError>;

    fn run_until_boundary(
        &mut self,
        need_resched: &AtomicBool,
        submission: &mut ExecutorSubmissionContext<'_>,
    ) -> Result<ExecutorExit, TrapError>;

    fn take_cpu_receipt(&mut self) -> ExecutorCpuReceipt;

    fn hardware_kick(&self) -> Result<ExactHardwareKick, TrapError>;

    fn validate_loaded_hardware_identity(&self) -> Result<(), TrapError> {
        Ok(())
    }

    fn retarget_loaded_task(&mut self, _binding: Arc<Self::TaskBinding>) -> Result<(), TrapError> {
        Err(TrapError::Hypervisor(
            "persistent executor does not support loaded exec replacement".to_owned(),
        ))
    }

    fn save(&mut self, lease: ThreadExecutionLease) -> Result<SavedRunnable, ExecutorSaveError>;

    fn invalidate_asid(
        &mut self,
        generation: crate::hvpatch::AsidGeneration,
    ) -> Result<(), TrapError>;

    /// Backend-owned state that the runtime crate cannot inspect (HVF fork
    /// snapshot, vCPU/mailbox owner identity, invariant EL1 state) is audited
    /// here on the executor's owner pthread.
    fn audit_boundary(&mut self) -> Result<(), TrapError>;

    fn destroy(self) -> Result<(), TrapError>;
}

pub struct ExactHardwareKick {
    handle: Box<dyn carrick_hal::VcpuKickDyn>,
    raw_vcpu_id: u64,
    owner_thread_port: u32,
}

impl ExactHardwareKick {
    fn new(
        handle: Box<dyn carrick_hal::VcpuKickDyn>,
        raw_vcpu_id: u64,
        owner_thread_port: u32,
    ) -> Result<Self, TrapError> {
        if raw_vcpu_id == 0 || owner_thread_port == 0 {
            return Err(TrapError::Hypervisor(
                "hardware kick lacks exact vCPU/Mach owner identity".to_owned(),
            ));
        }
        Ok(Self {
            handle,
            raw_vcpu_id,
            owner_thread_port,
        })
    }
}

fn current_owner_thread_port() -> u32 {
    #[cfg(target_os = "macos")]
    {
        unsafe { libc::pthread_mach_thread_np(libc::pthread_self()) }
    }
    #[cfg(not(target_os = "macos"))]
    {
        1
    }
}

fn restore_worker_vcpu_before_binding_publication<V, B>(
    worker_vcpu: &mut Option<V>,
    vcpu: V,
    backend: B,
    publish: impl FnOnce(B, &Option<V>) -> Result<(), TrapError>,
) -> Result<(), TrapError> {
    if worker_vcpu.replace(vcpu).is_some() {
        std::process::abort();
    }
    publish(backend, worker_vcpu)
}

pub(crate) fn retire_failed_hvpatch_clone_authority(
    scheduler: &Scheduler,
    kernel: &Arc<crate::kernel::Kernel>,
    context: &crate::kernel::KernelContext,
    generation: ExecutionGeneration,
    retire_binding: impl FnOnce(ThreadKey, ExecutionGeneration),
) -> Result<(), String> {
    scheduler
        .fail_runnable_exact(
            context.thread().key(),
            generation,
            ExecutionFailure::SnapshotSaveFailed,
        )
        .map_err(|error| format!("fail exact HVPatch clone runnable: {error}"))?;
    retire_binding(context.thread().key(), generation);
    kernel
        .exit_thread(context, None)
        .map(|_| ())
        .map_err(|error| format!("retire exact HVPatch clone Kernel thread: {error}"))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PersistentExecutor for HvpatchPersistentExecutor {
    type TaskBinding = crate::vcpu_loop::continuation::HvpatchTaskBinding;

    fn load(&mut self, task: &RunnableTask<'_, Self::TaskBinding>) -> Result<(), TrapError> {
        if self.current.is_some() || self.binding.is_some() {
            return Err(TrapError::Hypervisor(
                "HVPatch executor already has task authority".into(),
            ));
        }
        let mut asid_load = task.binding().begin_asid_load(self.executor_id)?;
        asid_load.arm_hardware_dirty().map_err(|error| {
            TrapError::Hypervisor(format!("HVPatch ASID hardware arm failed: {error}"))
        })?;
        let state = task
            .binding()
            .take_backend::<HvpatchTaskEngineBindingState>()?;
        let vcpu = self
            .vcpu
            .take()
            .ok_or_else(|| TrapError::Hypervisor("HVPatch executor lost worker vCPU".into()))?;
        let engine = match state.payload {
            HvpatchTaskEngineBindingPayload::Resident(state) => {
                let lifecycle = self.lifecycle.as_mut().ok_or_else(|| {
                    TrapError::Hypervisor("HVPatch executor lost idle lifecycle".into())
                })?;
                carrick_vmm_hvf::hvf_aarch64_engine::attach_task_engine(*state, lifecycle, vcpu)
            }
            HvpatchTaskEngineBindingPayload::TaskOnly(state) => {
                let lifecycle = self.lifecycle.take().ok_or_else(|| {
                    TrapError::Hypervisor("HVPatch task-only load lost worker lifecycle".into())
                })?;
                let identity = task.binding().identity();
                let engine = carrick_vmm_hvf::hvf_aarch64_engine::attach_task_only_engine(
                    &state,
                    lifecycle,
                    vcpu,
                    identity.mm.raw(),
                    identity.asid_generation,
                );
                self.loaded_task_only = Some(*state);
                engine
            }
            #[cfg(test)]
            HvpatchTaskEngineBindingPayload::Test => {
                self.vcpu = Some(vcpu);
                let _ = task
                    .binding()
                    .put_backend(HvpatchTaskEngineBindingState::test_only());
                return Err(TrapError::Hypervisor(
                    "test-only HVPatch backend cannot load on hardware".into(),
                ));
            }
        };
        self.current = Some(engine);
        self.binding = Some(Arc::clone(task.binding()));
        let cpu = &task.validate_for_load()?.cpu;
        self.current
            .as_mut()
            .ok_or_else(|| TrapError::Hypervisor("HVPatch load lost attached engine".into()))?
            .overlay_task_state_on_live_executor(cpu)?;
        self.current
            .as_mut()
            .ok_or_else(|| TrapError::Hypervisor("HVPatch load lost barrier engine".into()))?
            .complete_task_load_barrier()?;
        asid_load.mark_resident().map_err(|error| {
            TrapError::Hypervisor(format!("HVPatch ASID residence commit failed: {error}"))
        })
    }

    fn run_until_boundary(
        &mut self,
        need_resched: &AtomicBool,
        submission: &mut ExecutorSubmissionContext<'_>,
    ) -> Result<ExecutorExit, TrapError> {
        let quantum = Arc::clone(
            self.binding
                .as_ref()
                .ok_or_else(|| {
                    TrapError::Hypervisor("HVPatch executor has no task binding".into())
                })?
                .quantum(),
        );
        let mut control = HvpatchQuantumControl {
            need_resched,
            submission,
        };
        let engine = self
            .current
            .as_mut()
            .ok_or_else(|| TrapError::Hypervisor("HVPatch executor lost loaded engine".into()))?;
        Ok(quantum.poll_quantum_with_engine(engine, &mut control))
    }

    fn take_cpu_receipt(&mut self) -> ExecutorCpuReceipt {
        std::mem::take(&mut self.receipt)
    }

    fn hardware_kick(&self) -> Result<ExactHardwareKick, TrapError> {
        let engine = self.current.as_ref().ok_or_else(|| {
            TrapError::Hypervisor("HVPatch hardware kick requested without live vCPU".into())
        })?;
        let (handle, raw_vcpu_id, owner_thread_port) =
            carrick_vmm_hvf::hvf_aarch64_engine::persistent_hardware_kick(engine);
        if raw_vcpu_id != self.raw_vcpu_id || owner_thread_port != self.owner_thread_port {
            return Err(TrapError::Hypervisor(
                "HVPatch hardware kick identity drifted from worker owner".into(),
            ));
        }
        ExactHardwareKick::new(Box::new(handle), raw_vcpu_id, owner_thread_port)
    }

    fn retarget_loaded_task(&mut self, binding: Arc<Self::TaskBinding>) -> Result<(), TrapError> {
        if self.current.is_none() || self.binding.is_none() {
            return Err(TrapError::Hypervisor(
                "HVPatch exec replacement has no loaded worker task".into(),
            ));
        }
        self.validate_loaded_hardware_identity()?;
        self.binding = Some(binding);
        Ok(())
    }

    fn validate_loaded_hardware_identity(&self) -> Result<(), TrapError> {
        let engine = self.current.as_ref().ok_or_else(|| {
            TrapError::Hypervisor("HVPatch loaded identity audit has no live vCPU".into())
        })?;
        let (_, raw_vcpu_id, owner_thread_port) =
            carrick_vmm_hvf::hvf_aarch64_engine::persistent_hardware_kick(engine);
        if raw_vcpu_id != self.raw_vcpu_id || owner_thread_port != self.owner_thread_port {
            return Err(TrapError::Hypervisor(
                "HVPatch loaded vCPU/Mach identity drifted before exec retarget".into(),
            ));
        }
        Ok(())
    }

    fn save(
        &mut self,
        mut lease: ThreadExecutionLease,
    ) -> Result<SavedRunnable, ExecutorSaveError> {
        let Some(engine) = self.current.as_mut() else {
            return Err(ExecutorSaveError::new(
                TrapError::Hypervisor("HVPatch save without loaded engine".into()),
                lease,
            ));
        };
        let cpu = match engine.snapshot_task_state_from_live_executor() {
            Ok(cpu) => cpu,
            Err(error) => return Err(ExecutorSaveError::new(error, lease)),
        };
        let (mm, asid_generation) = match lease.task_state_authority() {
            Ok(authority) => authority,
            Err(error) => {
                return Err(ExecutorSaveError::new(
                    TrapError::Hypervisor(error.to_string()),
                    lease,
                ));
            }
        };
        if let Err(error) = lease.replace_task_state(MigratableTaskState {
            cpu,
            mm,
            asid_generation,
        }) {
            return Err(ExecutorSaveError::new(
                TrapError::Hypervisor(error.to_string()),
                lease,
            ));
        }
        let engine = self.current.take().unwrap_or_else(|| std::process::abort());
        let Some(binding) = self.binding.take() else {
            return Err(ExecutorSaveError::new(
                TrapError::Hypervisor("HVPatch save lost task binding".into()),
                lease,
            ));
        };
        let (backend, vcpu) = if let Some(task_only) = self.loaded_task_only.take() {
            let (lifecycle, vcpu) =
                carrick_vmm_hvf::hvf_aarch64_engine::detach_task_only_engine(&task_only, engine);
            if self.lifecycle.replace(lifecycle).is_some() {
                std::process::abort();
            }
            (HvpatchTaskEngineBindingState::task_only(task_only), vcpu)
        } else {
            let lifecycle = self
                .lifecycle
                .as_mut()
                .unwrap_or_else(|| std::process::abort());
            let (state, vcpu) =
                carrick_vmm_hvf::hvf_aarch64_engine::detach_task_engine(engine, lifecycle);
            (HvpatchTaskEngineBindingState::initial(state), vcpu)
        };
        if let Err(error) = restore_worker_vcpu_before_binding_publication(
            &mut self.vcpu,
            vcpu,
            backend,
            |backend, _| binding.put_backend(backend),
        ) {
            return Err(ExecutorSaveError::new(error, lease));
        }
        Ok(SavedRunnable::new(lease))
    }

    fn invalidate_asid(
        &mut self,
        generation: crate::hvpatch::AsidGeneration,
    ) -> Result<(), TrapError> {
        let lifecycle = self.lifecycle.as_mut().ok_or_else(|| {
            TrapError::Hypervisor("ASID invalidation lost idle worker lifecycle".into())
        })?;
        let vcpu = self.vcpu.as_mut().ok_or_else(|| {
            TrapError::Hypervisor("ASID invalidation lost idle worker vCPU".into())
        })?;
        carrick_vmm_hvf::hvf_aarch64_engine::invalidate_worker_asid(
            lifecycle,
            vcpu,
            generation.raw(),
        )
    }
    fn audit_boundary(&mut self) -> Result<(), TrapError> {
        if self.current.is_some()
            || self.binding.is_some()
            || self.loaded_task_only.is_some()
            || self.lifecycle.is_none()
            || self.vcpu.is_none()
        {
            return Err(TrapError::Hypervisor(
                "dirty HVPatch executor boundary".into(),
            ));
        }
        let vcpu = self.vcpu.as_ref().unwrap_or_else(|| std::process::abort());
        if carrick_vmm_hvf::hvf_aarch64_engine::persistent_vcpu_identity(vcpu) != self.raw_vcpu_id
            || current_owner_thread_port() != self.owner_thread_port
        {
            return Err(TrapError::Hypervisor(
                "HVPatch executor vCPU/Mach owner identity drifted".into(),
            ));
        }
        self.lifecycle
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
            .audit_persistent_executor_idle()?;
        Ok(())
    }
    fn destroy(mut self) -> Result<(), TrapError> {
        if let Some(mut engine) = self.current.take() {
            let _ = catch_unwind(AssertUnwindSafe(|| {
                engine.snapshot_task_state_from_live_executor()
            }));
            let (backend, vcpu) = if let Some(task_only) = self.loaded_task_only.take() {
                let (lifecycle, vcpu) =
                    carrick_vmm_hvf::hvf_aarch64_engine::detach_task_only_engine(
                        &task_only, engine,
                    );
                if self.lifecycle.replace(lifecycle).is_some() {
                    std::process::abort();
                }
                (HvpatchTaskEngineBindingState::task_only(task_only), vcpu)
            } else {
                let lifecycle = self
                    .lifecycle
                    .as_mut()
                    .unwrap_or_else(|| std::process::abort());
                let (state, vcpu) =
                    carrick_vmm_hvf::hvf_aarch64_engine::detach_task_engine(engine, lifecycle);
                (HvpatchTaskEngineBindingState::initial(state), vcpu)
            };
            if let Some(binding) = self.binding.take() {
                let _ = binding.put_backend(backend);
            }
            self.vcpu = Some(vcpu);
        }
        let mut vcpu = self
            .vcpu
            .take()
            .ok_or_else(|| TrapError::Hypervisor("destroy missing worker vCPU".into()))?;
        let lifecycle = self
            .lifecycle
            .as_mut()
            .ok_or_else(|| TrapError::Hypervisor("destroy missing worker lifecycle".into()))?;
        carrick_vmm_hvf::hvf_aarch64_engine::destroy_worker_vcpu(lifecycle, &mut vcpu);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskLoadIdentity {
    pub abi: LinuxGuestAbi,
    pub version: u16,
    pub mm: MmId,
    pub asid_generation: u64,
}

pub trait PersistentTaskBinding {
    fn load_identity(&self) -> TaskLoadIdentity;

    fn validate_task_state(&self, state: &MigratableTaskState) -> Result<(), TrapError>;

    fn after_terminal_settlement(&self) {}

    fn take_address_space_retirement(
        &self,
    ) -> Option<crate::hvpatch::PendingAddressSpaceRetirement> {
        None
    }
}

impl PersistentTaskBinding for crate::vcpu_loop::continuation::HvpatchTaskBinding {
    fn load_identity(&self) -> TaskLoadIdentity {
        self.identity()
    }

    fn validate_task_state(&self, state: &MigratableTaskState) -> Result<(), TrapError> {
        self.validate_state(state)
    }

    fn after_terminal_settlement(&self) {
        crate::vcpu_loop::continuation::HvpatchTaskBinding::after_terminal_settlement(self);
    }

    fn take_address_space_retirement(
        &self,
    ) -> Option<crate::hvpatch::PendingAddressSpaceRetirement> {
        crate::vcpu_loop::continuation::HvpatchTaskBinding::take_address_space_retirement(self)
    }
}

pub struct ExecutorSubmissionContext<'a> {
    pub(super) scheduler: &'a Scheduler,
    #[cfg(test)]
    pub(super) publish_test_descendant:
        &'a dyn Fn(Arc<crate::kernel::Thread>, ExecutionGeneration) -> Result<(), TrapError>,
    pub(super) current: Option<&'a SubmissionAuthority>,
    // The worker lends ownership, not an alias, for exactly one resident poll.
    // This lets the HVPatch logical state machine consume and replace exec
    // authority while making it impossible to retain a borrow across a
    // Pending boundary. The worker takes the exact lease back before it saves
    // or settles the task.
    pub(super) lease: Option<ThreadExecutionLease>,
    pub(super) exec_replacement: Option<PendingExecReplacement>,
}

pub(crate) struct PendingExecReplacement {
    pub(crate) transition: crate::kernel::exec::CommittedExecTransition,
    pub(crate) replacement_mm: Arc<crate::hvpatch::Stage1MmLease>,
    pub(crate) retired_mm: crate::hvpatch::Stage1MmRetirement,
}

/// Borrowed worker authority passed into one engine-resident logical quantum.
/// It is deliberately non-owning: neither the job nor a continuation may
/// retain an executor kick/preemption or descendant-publication capability
/// after `run_until_boundary` returns.
pub(crate) struct HvpatchQuantumControl<'a, 'lease> {
    pub(super) need_resched: &'a AtomicBool,
    pub(super) submission: &'a mut ExecutorSubmissionContext<'lease>,
}

impl HvpatchQuantumControl<'_, '_> {
    pub(crate) fn need_resched(&self) -> bool {
        self.need_resched.load(Ordering::Acquire)
    }

    pub(crate) fn current_submission_key(
        &self,
    ) -> Result<(ThreadKey, ExecutionGeneration), TrapError> {
        let current = self.submission.current.ok_or_else(|| {
            TrapError::Hypervisor("resident task has no worker-held authority".to_owned())
        })?;
        Ok((current.thread_key(), current.generation()))
    }

    #[cfg(test)]
    pub(crate) const fn submission(&self) -> &ExecutorSubmissionContext<'_> {
        self.submission
    }

    pub(crate) fn execution_lease_mut(&mut self) -> Result<&mut ThreadExecutionLease, TrapError> {
        self.submission.execution_lease_mut()
    }

    pub(crate) const fn execution_lease_slot_mut(&mut self) -> &mut Option<ThreadExecutionLease> {
        self.submission.execution_lease_slot_mut()
    }

    pub(crate) fn publish_exec_replacement(
        &mut self,
        replacement: PendingExecReplacement,
    ) -> Result<(), TrapError> {
        if self
            .submission
            .exec_replacement
            .replace(replacement)
            .is_some()
        {
            return Err(TrapError::Hypervisor(
                "quantum published more than one exec replacement".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn prepare_hvpatch_submission(
        &self,
        directory: &Arc<HvpatchTaskBindingDirectory>,
        shape: HvpatchSubmissionShape,
        thread: Arc<crate::kernel::Thread>,
        generation: ExecutionGeneration,
        binding: Arc<crate::vcpu_loop::continuation::HvpatchTaskBinding>,
    ) -> Result<PreparedHvpatchSubmission, TrapError> {
        self.submission
            .prepare_hvpatch_submission(directory, shape, thread, generation, binding)
    }
}

impl ExecutorSubmissionContext<'_> {
    pub(crate) fn execution_lease_mut(&mut self) -> Result<&mut ThreadExecutionLease, TrapError> {
        self.lease.as_mut().ok_or_else(|| {
            TrapError::Hypervisor("quantum has no mutable execution lease authority".to_owned())
        })
    }

    pub(crate) const fn execution_lease_slot_mut(&mut self) -> &mut Option<ThreadExecutionLease> {
        &mut self.lease
    }

    fn take_execution_lease(&mut self) -> Result<ThreadExecutionLease, TrapError> {
        self.lease.take().ok_or_else(|| {
            TrapError::Hypervisor("quantum returned without execution lease authority".to_owned())
        })
    }

    #[allow(dead_code)]
    pub(crate) fn prepare_hvpatch_submission(
        &self,
        directory: &Arc<HvpatchTaskBindingDirectory>,
        shape: HvpatchSubmissionShape,
        thread: Arc<crate::kernel::Thread>,
        generation: ExecutionGeneration,
        binding: Arc<crate::vcpu_loop::continuation::HvpatchTaskBinding>,
    ) -> Result<PreparedHvpatchSubmission, TrapError> {
        let current = self.current.ok_or_else(|| {
            TrapError::Hypervisor(
                "resident HVPatch task has no worker-held submission authority".to_owned(),
            )
        })?;
        directory.prepare_submission(
            self.scheduler,
            shape,
            Some(current),
            thread,
            generation,
            binding,
        )
    }

    #[cfg(test)]
    pub fn publish_test_descendant(
        &self,
        thread: Arc<crate::kernel::Thread>,
        generation: ExecutionGeneration,
    ) -> Result<(), TrapError> {
        (self.publish_test_descendant)(thread, generation)
    }
}

pub(crate) struct ExecBindingTransition {
    predecessor_thread: ThreadKey,
    predecessor_generation: ExecutionGeneration,
    successor_thread: ThreadKey,
    successor_generation: ExecutionGeneration,
    identity: TaskLoadIdentity,
    replacement_mm: Option<Arc<crate::hvpatch::Stage1MmLease>>,
    authority: Option<SubmissionAuthority>,
}

pub trait TaskBindingResolver<B>: Send + Sync + 'static {
    fn install_scheduler(self: &Arc<Self>, _scheduler: &Arc<Scheduler>) -> Result<(), TrapError> {
        Ok(())
    }

    fn resolve(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
    ) -> Result<Arc<B>, TrapError>;

    #[allow(private_interfaces)]
    fn take_submission_authority(
        &self,
        _thread: ThreadKey,
        _generation: ExecutionGeneration,
    ) -> Option<SubmissionAuthority> {
        None
    }

    #[allow(private_interfaces)]
    fn restore_submission_authority(
        &self,
        authority: SubmissionAuthority,
    ) -> Result<(), SubmissionAuthority> {
        Err(authority)
    }

    #[cfg(test)]
    #[allow(private_interfaces)]
    fn publish_test_root(
        &self,
        _scheduler: &Scheduler,
        _thread: Arc<crate::kernel::Thread>,
        _authority: SubmissionAuthority,
    ) -> Result<(), SchedulerError> {
        Err(crate::kernel::RunQueueError::SubmissionRejected.into())
    }

    #[cfg(test)]
    #[allow(private_interfaces)]
    fn publish_test_descendant(
        &self,
        _scheduler: &Scheduler,
        _parent: &SubmissionAuthority,
        _thread: Arc<crate::kernel::Thread>,
        _generation: ExecutionGeneration,
    ) -> Result<(), TrapError> {
        Err(TrapError::Hypervisor(
            "resolver does not support test descendant publication".to_owned(),
        ))
    }

    fn retire(&self, _thread: ThreadKey, _generation: ExecutionGeneration) {}

    fn cancel_dormant(
        &self,
        _scheduler: &Scheduler,
        _reason: ExecutionFailure,
    ) -> Result<usize, TrapError> {
        Ok(0)
    }

    #[allow(private_interfaces)]
    fn replace_exec(
        &self,
        _scheduler: &Scheduler,
        _transition: ExecBindingTransition,
    ) -> Result<ExecBindingReplacement<B>, TrapError> {
        Err(TrapError::Hypervisor(
            "task binding resolver does not support exec replacement".to_owned(),
        ))
    }
}

pub(crate) struct ExecBindingReplacement<B> {
    binding: Arc<B>,
    authority: Option<SubmissionAuthority>,
}

#[derive(Default)]
pub(crate) struct HvpatchTaskBindingDirectory {
    bindings:
        Mutex<std::collections::BTreeMap<(ThreadKey, ExecutionGeneration), HvpatchTaskRecord>>,
    scheduler: Mutex<std::sync::Weak<Scheduler>>,
}

struct HvpatchTaskRecord {
    binding: Arc<crate::vcpu_loop::continuation::HvpatchTaskBinding>,
    authority: Option<SubmissionAuthority>,
    active: bool,
}

impl HvpatchTaskBindingDirectory {
    pub(super) fn install_scheduler(
        self: &Arc<Self>,
        scheduler: &Arc<Scheduler>,
    ) -> Result<(), TrapError> {
        let mut installed = self.scheduler.lock();
        if installed.strong_count() != 0 {
            return Ok(());
        }
        *installed = Arc::downgrade(scheduler);
        drop(installed);
        scheduler
            .install_generation_observer(
                Arc::clone(self) as Arc<dyn crate::kernel::scheduler::SchedulerGenerationObserver>
            )
            .map_err(|error| TrapError::Hypervisor(error.to_string()))
    }

    #[cfg(test)]
    pub(crate) fn publish(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
        binding: Arc<crate::vcpu_loop::continuation::HvpatchTaskBinding>,
    ) -> Result<(), TrapError> {
        if self
            .bindings
            .lock()
            .insert(
                (thread, generation),
                HvpatchTaskRecord {
                    binding,
                    authority: None,
                    active: true,
                },
            )
            .is_some()
        {
            return Err(TrapError::Hypervisor(
                "duplicate exact HVPatch task binding publication".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn retire(&self, thread: ThreadKey, generation: ExecutionGeneration) {
        self.bindings.lock().remove(&(thread, generation));
    }

    pub(crate) fn prepare_submission(
        self: &Arc<Self>,
        scheduler: &Scheduler,
        shape: HvpatchSubmissionShape,
        grant_authority: Option<&SubmissionAuthority>,
        thread: Arc<crate::kernel::Thread>,
        generation: ExecutionGeneration,
        binding: Arc<crate::vcpu_loop::continuation::HvpatchTaskBinding>,
    ) -> Result<PreparedHvpatchSubmission, TrapError> {
        let key = (thread.key(), generation);
        let mut bindings = self.bindings.lock();
        if bindings.contains_key(&key) {
            return Err(TrapError::Hypervisor(
                "duplicate exact dormant HVPatch submission".to_owned(),
            ));
        }
        let authority = match (shape, grant_authority) {
            (HvpatchSubmissionShape::Root, None) => scheduler
                .admit_process_root(key.0, key.1)
                .map_err(|error| TrapError::Hypervisor(error.to_string()))?,
            (HvpatchSubmissionShape::Descendant { grant }, Some(authority))
                if (authority.thread_key(), authority.generation()) == grant =>
            {
                authority
                    .admit_descendant(key.0, key.1)
                    .map_err(|error| TrapError::Hypervisor(error.to_string()))?
            }
            (HvpatchSubmissionShape::SameTaskSibling { grant }, Some(authority))
                if (authority.thread_key(), authority.generation()) == grant =>
            {
                authority
                    .admit_same_task_sibling(key.0, key.1)
                    .map_err(|error| TrapError::Hypervisor(error.to_string()))?
            }
            (HvpatchSubmissionShape::PeerRoot { grant }, Some(authority))
                if (authority.thread_key(), authority.generation()) == grant =>
            {
                authority
                    .admit_peer_root(key.0, key.1)
                    .map_err(|error| TrapError::Hypervisor(error.to_string()))?
            }
            _ => {
                return Err(TrapError::Hypervisor(
                    "HVPatch submission shape does not match worker-held authority".to_owned(),
                ));
            }
        };
        bindings.insert(
            key,
            HvpatchTaskRecord {
                binding,
                authority: Some(authority),
                active: false,
            },
        );
        Ok(PreparedHvpatchSubmission {
            directory: Arc::clone(self),
            key,
            armed: true,
        })
    }

    #[cfg(test)]
    pub(super) fn install_root_authority(
        &self,
        scheduler: &Scheduler,
        thread: Arc<crate::kernel::Thread>,
        authority: SubmissionAuthority,
    ) -> Result<(), SchedulerError> {
        let key = (authority.thread_key(), authority.generation());
        let mut bindings = self.bindings.lock();
        let record = bindings
            .get_mut(&key)
            .ok_or(crate::kernel::RunQueueError::AuthorityMismatch)?;
        if record.authority.is_some() {
            return Err(crate::kernel::RunQueueError::SubmissionRejected.into());
        }
        record.authority = Some(authority);
        match record
            .authority
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
            .publish(scheduler, thread)
        {
            Ok(()) => Ok(()),
            Err(error) => {
                record.authority.take();
                Err(error)
            }
        }
    }

    #[cfg(test)]
    fn rollover_exact(
        &self,
        thread: ThreadKey,
        predecessor: ExecutionGeneration,
        successor: ExecutionGeneration,
    ) -> Result<(), TrapError> {
        if predecessor.raw().checked_add(1) != Some(successor.raw()) {
            return Err(TrapError::Hypervisor(
                "HVPatch binding rollover rejected non-successor generation".to_owned(),
            ));
        }
        let mut bindings = self.bindings.lock();
        if bindings.contains_key(&(thread, successor)) {
            if !bindings.contains_key(&(thread, predecessor)) {
                return Ok(());
            }
            return Err(TrapError::Hypervisor(
                "HVPatch binding rollover found overlapping generations".to_owned(),
            ));
        }
        let record = bindings.get(&(thread, predecessor)).ok_or_else(|| {
            TrapError::Hypervisor("missing predecessor HVPatch binding".to_owned())
        })?;
        if record.authority.is_some() {
            return Err(TrapError::Hypervisor(
                "HVPatch binding rollover requires scheduler-owned authority transaction"
                    .to_owned(),
            ));
        }
        let record = bindings
            .remove(&(thread, predecessor))
            .unwrap_or_else(|| std::process::abort());
        bindings.insert((thread, successor), record);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// Root is production-wired in this slice. The other shapes are intentionally
// prepared now so the subsequent fork/clone conversion cannot fall back to a
// generic descendant edge while it replaces the compatibility materializers.
#[allow(dead_code)]
pub(crate) enum HvpatchSubmissionShape {
    Root,
    Descendant {
        grant: (ThreadKey, ExecutionGeneration),
    },
    SameTaskSibling {
        grant: (ThreadKey, ExecutionGeneration),
    },
    PeerRoot {
        grant: (ThreadKey, ExecutionGeneration),
    },
}

pub(crate) struct HvpatchActivationProof {
    thread: ThreadKey,
    generation: ExecutionGeneration,
    identity: TaskLoadIdentity,
}

impl HvpatchActivationProof {
    pub(crate) fn validate(
        context: &crate::kernel::KernelContext,
        state: &MigratableTaskState,
        generation: ExecutionGeneration,
        identity: TaskLoadIdentity,
        start_gate: crate::kernel::objects::OpenedStartGate,
    ) -> Result<Self, TrapError> {
        if start_gate.thread() != context.thread().key()
            || start_gate.generation() != generation
            || context.thread().execution_state().generation() != Some(generation)
            || context.shared().mm().id() != state.mm
            || identity.mm != state.mm
            || identity.asid_generation != state.asid_generation
            || state.cpu.task_identity() != (state.mm.raw(), state.asid_generation)
            || state.cpu.guest_abi() != identity.abi
            || state.cpu.version() != identity.version
        {
            return Err(TrapError::Hypervisor(
                "HVPatch activation proof rejected Kernel/CPU/MM/ASID/start state".to_owned(),
            ));
        }
        Ok(Self {
            thread: context.thread().key(),
            generation,
            identity,
        })
    }
}

pub(crate) struct PreparedHvpatchSubmission {
    directory: Arc<HvpatchTaskBindingDirectory>,
    key: (ThreadKey, ExecutionGeneration),
    armed: bool,
}

impl PreparedHvpatchSubmission {
    pub(crate) fn activate(
        mut self,
        scheduler: &Scheduler,
        thread: Arc<crate::kernel::Thread>,
        proof: HvpatchActivationProof,
    ) -> Result<(), TrapError> {
        if self.key != (proof.thread, proof.generation) || thread.key() != proof.thread {
            return Err(TrapError::Hypervisor(
                "HVPatch activation proof names a different submission".to_owned(),
            ));
        }
        let mut bindings = self.directory.bindings.lock();
        let record = bindings.get_mut(&self.key).ok_or_else(|| {
            TrapError::Hypervisor("missing dormant HVPatch submission".to_owned())
        })?;
        if record.active || record.binding.identity() != proof.identity {
            return Err(TrapError::Hypervisor(
                "HVPatch dormant binding identity changed before activation".to_owned(),
            ));
        }
        record
            .authority
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("dormant authority missing".to_owned()))?
            .publish_unique(scheduler, thread)
            .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
        record.active = true;
        self.armed = false;
        Ok(())
    }
}

impl Drop for PreparedHvpatchSubmission {
    fn drop(&mut self) {
        if self.armed {
            let mut bindings = self.directory.bindings.lock();
            if bindings.get(&self.key).is_some_and(|record| !record.active) {
                bindings.remove(&self.key);
            }
        }
    }
}

impl crate::kernel::scheduler::SchedulerGenerationObserver for HvpatchTaskBindingDirectory {
    fn transition(
        &self,
        thread: ThreadKey,
        predecessor: ExecutionGeneration,
        successor: ExecutionGeneration,
        kind: crate::kernel::scheduler::SchedulerGenerationTransition,
    ) -> Result<(), crate::kernel::RunQueueError> {
        let scheduler = self
            .scheduler
            .lock()
            .upgrade()
            .ok_or(crate::kernel::RunQueueError::AuthorityMismatch)?;
        let mut bindings = self.bindings.lock();
        let mut record = bindings
            .remove(&(thread, predecessor))
            .ok_or(crate::kernel::RunQueueError::AuthorityMismatch)?;
        if kind == crate::kernel::scheduler::SchedulerGenerationTransition::Terminal {
            return Ok(());
        }
        if bindings.contains_key(&(thread, successor)) {
            bindings.insert((thread, predecessor), record);
            return Err(crate::kernel::RunQueueError::SubmissionRejected);
        }
        if let Some(authority) = record.authority.take() {
            let transition = match kind {
                crate::kernel::scheduler::SchedulerGenerationTransition::Runnable => {
                    if authority.is_active() {
                        authority.rollover_exact(&scheduler, thread, predecessor, thread, successor)
                    } else {
                        authority.reactivate_exact(&scheduler, predecessor, successor)
                    }
                }
                crate::kernel::scheduler::SchedulerGenerationTransition::Blocked => {
                    authority.park_exact(&scheduler, predecessor, successor)
                }
                crate::kernel::scheduler::SchedulerGenerationTransition::Terminal => {
                    unreachable!()
                }
            };
            match transition {
                Ok(authority) => record.authority = Some(authority),
                Err((error, authority)) => {
                    record.authority = Some(authority);
                    bindings.insert((thread, predecessor), record);
                    return Err(error);
                }
            }
        }
        bindings.insert((thread, successor), record);
        Ok(())
    }
}

impl TaskBindingResolver<crate::vcpu_loop::continuation::HvpatchTaskBinding>
    for HvpatchTaskBindingDirectory
{
    fn install_scheduler(self: &Arc<Self>, scheduler: &Arc<Scheduler>) -> Result<(), TrapError> {
        HvpatchTaskBindingDirectory::install_scheduler(self, scheduler)
    }

    fn resolve(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
    ) -> Result<Arc<crate::vcpu_loop::continuation::HvpatchTaskBinding>, TrapError> {
        let bindings = self.bindings.lock();
        bindings
            .get(&(thread, generation))
            .filter(|record| record.active)
            .map(|record| Arc::clone(&record.binding))
            .ok_or_else(|| TrapError::Hypervisor("missing exact HVPatch task binding".to_owned()))
    }
    fn take_submission_authority(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
    ) -> Option<SubmissionAuthority> {
        let mut bindings = self.bindings.lock();
        let record = bindings.get_mut(&(thread, generation))?;
        record.active.then(|| record.authority.take()).flatten()
    }

    fn restore_submission_authority(
        &self,
        authority: SubmissionAuthority,
    ) -> Result<(), SubmissionAuthority> {
        let key = (authority.thread_key(), authority.generation());
        let mut bindings = self.bindings.lock();
        let Some(record) = bindings.get_mut(&key) else {
            return Err(authority);
        };
        if !record.active || record.authority.is_some() {
            return Err(authority);
        }
        record.authority = Some(authority);
        Ok(())
    }

    fn retire(&self, thread: ThreadKey, generation: ExecutionGeneration) {
        HvpatchTaskBindingDirectory::retire(self, thread, generation);
    }

    fn cancel_dormant(
        &self,
        scheduler: &Scheduler,
        reason: ExecutionFailure,
    ) -> Result<usize, TrapError> {
        let candidates = self
            .bindings
            .lock()
            .iter()
            .map(|(&(thread, generation), record)| {
                (thread, generation, Arc::clone(&record.binding))
            })
            .collect::<Vec<_>>();
        let mut cancelled = 0usize;
        for (thread, generation, binding) in candidates {
            if scheduler
                .fail_blocked_exact(thread, generation, reason)
                .map_err(|error| TrapError::Hypervisor(error.to_string()))?
            {
                binding.after_terminal_settlement();
                cancelled = cancelled
                    .checked_add(1)
                    .ok_or_else(|| TrapError::Hypervisor("dormant cancellation overflow".into()))?;
            }
        }
        Ok(cancelled)
    }

    fn replace_exec(
        &self,
        scheduler: &Scheduler,
        transition: ExecBindingTransition,
    ) -> Result<ExecBindingReplacement<crate::vcpu_loop::continuation::HvpatchTaskBinding>, TrapError>
    {
        let ExecBindingTransition {
            predecessor_thread,
            predecessor_generation,
            successor_thread,
            successor_generation,
            identity,
            replacement_mm,
            authority,
        } = transition;
        let mut bindings = self.bindings.lock();
        if bindings.contains_key(&(successor_thread, successor_generation)) {
            return Err(TrapError::Hypervisor(
                "exec replacement binding already exists".to_owned(),
            ));
        }
        let mut record = bindings
            .remove(&(predecessor_thread, predecessor_generation))
            .ok_or_else(|| TrapError::Hypervisor("missing predecessor exec binding".to_owned()))?;
        if record.authority.is_some() {
            bindings.insert((predecessor_thread, predecessor_generation), record);
            return Err(TrapError::Hypervisor(
                "exec replacement found authority outside running quantum".to_owned(),
            ));
        }
        let replacement_result = match replacement_mm {
            Some(replacement_mm) => record
                .binding
                .replacement_with_stage1_mm(identity, replacement_mm),
            None => {
                #[cfg(test)]
                {
                    Ok(record.binding.replacement(identity))
                }
                #[cfg(not(test))]
                {
                    Err(TrapError::Hypervisor(
                        "production exec replacement omitted fresh stage-1/ASID lease".to_owned(),
                    ))
                }
            }
        };
        let replacement = match replacement_result {
            Ok(replacement) => Arc::new(replacement),
            Err(error) => {
                bindings.insert((predecessor_thread, predecessor_generation), record);
                return Err(error);
            }
        };
        let authority = match authority {
            Some(authority) => match authority.replace_exec_exact(
                scheduler,
                predecessor_thread,
                predecessor_generation,
                successor_thread,
                successor_generation,
            ) {
                Ok(authority) => Some(authority),
                Err((error, authority)) => {
                    record.authority = Some(authority);
                    bindings.insert((predecessor_thread, predecessor_generation), record);
                    return Err(TrapError::Hypervisor(error.to_string()));
                }
            },
            None => None,
        };
        bindings.insert(
            (successor_thread, successor_generation),
            HvpatchTaskRecord {
                binding: Arc::clone(&replacement),
                authority: None,
                active: true,
            },
        );
        Ok(ExecBindingReplacement {
            binding: replacement,
            authority,
        })
    }
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
pub enum ExecutorExit {
    Syscall,
    Blocked(BlockedReason),
    BlockedContinuation(Box<crate::vcpu_loop::continuation::BlockedContinuation>),
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
        let _ = SyscallDispatcher::reset_sysv_executor_boundary_state();
        let _previous_signal_progress = super::reset_signal_progress_for_executor_boundary();
        if !super::signal_progress_is_zero_for_executor_boundary() {
            return Err(boundary_error("signal-progress"));
        }
        if current_signal_mask()? != self.baseline_signal_mask {
            return Err(boundary_error("host-signal-mask"));
        }
        Ok(())
    }

    fn audit_runtime<E: PersistentExecutor>(&self, backend: &mut E) -> Result<(), TrapError> {
        self.audit_runtime_owned()?;
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
    InvalidatedAsid {
        generation: u64,
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

struct WorkerKick {
    binding: Mutex<Option<ExecutorBinding>>,
    hardware: Mutex<Option<ExactHardwareKick>>,
    need_resched: AtomicBool,
    receipts: Arc<ReceiptLog>,
    #[cfg(test)]
    delivery_validation_gate: Mutex<Option<Arc<std::sync::Barrier>>>,
    #[cfg(test)]
    delivery_receipt_gate: Mutex<Option<Arc<std::sync::Barrier>>>,
}

impl std::fmt::Debug for WorkerKick {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerKick")
            .field("binding", &*self.binding.lock())
            .field("hardware_published", &self.hardware.lock().is_some())
            .field(
                "hardware_vcpu_id",
                &self.hardware.lock().as_ref().map(|kick| kick.raw_vcpu_id),
            )
            .field("need_resched", &self.need_resched.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl WorkerKick {
    fn new(receipts: Arc<ReceiptLog>) -> Self {
        Self {
            binding: Mutex::new(None),
            hardware: Mutex::new(None),
            need_resched: AtomicBool::new(false),
            receipts,
            #[cfg(test)]
            delivery_validation_gate: Mutex::new(None),
            #[cfg(test)]
            delivery_receipt_gate: Mutex::new(None),
        }
    }

    fn publish_hardware(&self, hardware: ExactHardwareKick) -> bool {
        let binding = self.binding.lock();
        if binding.is_none()
            || hardware.owner_thread_port != current_owner_thread_port()
            || self.hardware.lock().is_some()
        {
            return false;
        }
        *self.hardware.lock() = Some(hardware);
        if self.need_resched.load(Ordering::Acquire)
            && let Some(hardware) = self.hardware.lock().as_ref()
        {
            hardware.handle.kick();
        }
        true
    }

    fn poke_control(&self) {
        self.need_resched.store(true, Ordering::Release);
        if let Some(hardware) = self.hardware.lock().as_ref() {
            hardware.handle.kick();
        }
    }

    #[cfg(test)]
    fn install_delivery_validation_gate(&self, gate: Arc<std::sync::Barrier>) {
        *self.delivery_validation_gate.lock() = Some(gate);
    }

    #[cfg(test)]
    fn install_delivery_receipt_gate(&self, gate: Arc<std::sync::Barrier>) {
        *self.delivery_receipt_gate.lock() = Some(gate);
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
            self.hardware.lock().take();
        }
    }

    fn rebind_exact_with(
        &self,
        predecessor: ExecutorBinding,
        successor: ExecutorBinding,
        publish: &mut dyn FnMut() -> bool,
    ) -> bool {
        let mut current = self.binding.lock();
        if *current != Some(predecessor) || predecessor.executor() != successor.executor() {
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
        if *current != Some(token.binding()) {
            return false;
        }
        #[cfg(test)]
        if let Some(gate) = self.delivery_validation_gate.lock().clone() {
            gate.wait();
            gate.wait();
        }
        self.need_resched.store(true, Ordering::Release);
        if let Some(hardware) = self.hardware.lock().as_ref() {
            hardware.handle.kick();
        }
        #[cfg(test)]
        if let Some(gate) = self.delivery_receipt_gate.lock().clone() {
            gate.wait();
            gate.wait();
        }
        self.receipts.record(
            token.executor(),
            ExecutorPoolEvent::KickDelivered {
                thread: token.thread(),
                generation: token.generation(),
            },
        );
        drop(current);
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
    InvalidateAsid {
        generation: crate::hvpatch::AsidGeneration,
        response: mpsc::SyncSender<Result<crate::hvpatch::InvalidationAck, String>>,
    },
    Stop,
}

#[derive(Debug)]
struct StartupStatus {
    index: usize,
    error: Option<String>,
    executor: Option<ExecutorId>,
    kick: Option<Arc<WorkerKick>>,
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
    executor: Option<ExecutorId>,
    kick: Option<Arc<WorkerKick>>,
}

#[derive(Debug)]
struct WorkerChannels {
    commands: mpsc::Receiver<WorkerCommand>,
    startup: mpsc::Sender<StartupStatus>,
}

struct WorkerRuntime<'a> {
    registration: &'a ExecutorRegistration,
    kick: &'a Arc<WorkerKick>,
    boundary: &'a WorkerBoundaryAudit,
    receipts: &'a Arc<ReceiptLog>,
    control: &'a PoolControl,
}

#[derive(Debug)]
struct PoolControl {
    usable_workers: std::sync::atomic::AtomicUsize,
    wait_service: crate::vcpu_loop::continuation::CarrierWaitService,
    scheduler: Arc<Scheduler>,
    workers: Mutex<std::collections::BTreeMap<ExecutorId, WorkerControlHandle>>,
}

#[derive(Clone, Debug)]
struct WorkerControlHandle {
    command: mpsc::Sender<WorkerCommand>,
    kick: Arc<WorkerKick>,
}

type PendingAsidInvalidation = (
    ExecutorId,
    mpsc::Receiver<Result<crate::hvpatch::InvalidationAck, String>>,
);
type PendingAsidInvalidations = Vec<PendingAsidInvalidation>;

impl PoolControl {
    fn new(workers: usize, scheduler: Arc<Scheduler>) -> Self {
        Self {
            usable_workers: std::sync::atomic::AtomicUsize::new(workers),
            wait_service: crate::vcpu_loop::continuation::CarrierWaitService::new(Arc::clone(
                &scheduler,
            )),
            scheduler,
            workers: Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    fn register_worker(
        &self,
        executor: ExecutorId,
        command: mpsc::Sender<WorkerCommand>,
        kick: Arc<WorkerKick>,
    ) {
        if self
            .workers
            .lock()
            .insert(executor, WorkerControlHandle { command, kick })
            .is_some()
        {
            std::process::abort();
        }
    }

    fn retire_failed_worker(&self) -> bool {
        self.usable_workers.fetch_sub(1, Ordering::AcqRel) == 1
    }

    fn dispatch_invalidation_commands(
        &self,
        generation: crate::hvpatch::AsidGeneration,
        targets: impl IntoIterator<Item = ExecutorId>,
    ) -> Result<PendingAsidInvalidations, String> {
        let workers = self.workers.lock();
        let mut pending = Vec::new();
        for target in targets {
            let worker = workers
                .get(&target)
                .ok_or_else(|| format!("ASID retirement resident executor {target:?} is absent"))?;
            let (response_tx, response_rx) = mpsc::sync_channel(1);
            worker
                .command
                .send(WorkerCommand::InvalidateAsid {
                    generation,
                    response: response_tx,
                })
                .map_err(|_| {
                    format!("ASID retirement executor {target:?} command channel closed")
                })?;
            worker.kick.poke_control();
            pending.push((target, response_rx));
        }
        drop(workers);
        if !pending.is_empty() {
            self.scheduler.poke_executor_control();
        }
        Ok(pending)
    }

    fn consume_invalidation_acks(
        retirement: &crate::hvpatch::Stage1MmRetirement,
        pending: Vec<(
            ExecutorId,
            mpsc::Receiver<Result<crate::hvpatch::InvalidationAck, String>>,
        )>,
    ) -> Result<(), String> {
        for (target, response) in pending {
            let ack = response.recv().map_err(|_| {
                format!("ASID retirement executor {target:?} lost acknowledgement")
            })??;
            retirement
                .acknowledge(ack)
                .map_err(|error| format!("ASID retirement acknowledgement rejected: {error}"))?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn invalidate_external(
        &self,
        retirement: &crate::hvpatch::Stage1MmRetirement,
    ) -> Result<(), String> {
        let pending = self
            .dispatch_invalidation_commands(retirement.asid_generation(), retirement.pending())?;
        Self::consume_invalidation_acks(retirement, pending)
    }

    fn invalidate_after_exec<E: PersistentExecutor>(
        &self,
        retirement: &crate::hvpatch::Stage1MmRetirement,
        current: ExecutorId,
        backend: &mut E,
        boundary: &WorkerBoundaryAudit,
        receipts: &ReceiptLog,
    ) -> Result<(), String> {
        let generation = retirement.asid_generation();
        let targets = retirement.pending();
        let pending = self.dispatch_invalidation_commands(
            generation,
            targets.iter().copied().filter(|target| *target != current),
        )?;
        if targets.contains(&current) {
            boundary
                .audit_runtime(backend)
                .map_err(|error| error.to_string())?;
            backend
                .invalidate_asid(generation)
                .map_err(|error| error.to_string())?;
            receipts.record(
                current,
                ExecutorPoolEvent::InvalidatedAsid {
                    generation: generation.generation(),
                },
            );
            retirement
                .acknowledge(crate::hvpatch::InvalidationAck::new(current, generation))
                .map_err(|error| error.to_string())?;
        }
        Self::consume_invalidation_acks(retirement, pending)
    }
}

pub(crate) struct ExecutorPool<F, R>
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
    resolver: Arc<R>,
    #[cfg(test)]
    control: Arc<PoolControl>,
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
        resolver
            .install_scheduler(&scheduler)
            .map_err(|error| ExecutorPoolStartError {
                configured_workers,
                message: format!("install combined task resolver: {error}"),
            })?;
        let receipts = Arc::new(ReceiptLog::default());
        let control = Arc::new(PoolControl::new(configured_workers, Arc::clone(&scheduler)));
        let (startup_tx, startup_rx) = mpsc::channel();
        let mut handles: Vec<WorkerHandle> = Vec::with_capacity(configured_workers);
        for index in 0..configured_workers {
            let (command_tx, command_rx) = mpsc::channel();
            let scheduler = Arc::clone(&scheduler);
            let factory = Arc::clone(&factory);
            let resolver = Arc::clone(&resolver);
            let receipts_for_worker = Arc::clone(&receipts);
            let control_for_worker = Arc::clone(&control);
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
                        control_for_worker,
                        WorkerChannels {
                            commands: command_rx,
                            startup: startup_tx,
                        },
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
                executor: None,
                kick: None,
            });
        }
        drop(startup_tx);

        let mut startup_failure = None;
        for (index, handle) in handles.iter_mut().enumerate() {
            if startup_failure.is_some() {
                break;
            }
            if handle.command.send(WorkerCommand::Initialize).is_err() {
                startup_failure = Some(format!("worker {index} stopped before initialization"));
                break;
            }
            match startup_rx.recv() {
                Ok(status) if status.index == index && status.error.is_none() => {
                    handle.executor = status.executor;
                    handle.kick = status.kick;
                    if handle.executor.is_none() || handle.kick.is_none() {
                        startup_failure = Some(format!(
                            "worker {index} omitted exact executor/kick startup identity"
                        ));
                    } else {
                        control.register_worker(
                            handle.executor.unwrap_or_else(|| std::process::abort()),
                            handle.command.clone(),
                            Arc::clone(
                                handle
                                    .kick
                                    .as_ref()
                                    .unwrap_or_else(|| std::process::abort()),
                            ),
                        );
                    }
                }
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
            resolver,
            #[cfg(test)]
            control,
        })
    }

    #[cfg(test)]
    pub(crate) fn executor_ids(&self) -> Vec<ExecutorId> {
        self.handles
            .iter()
            .map(|handle| handle.executor.unwrap_or_else(|| std::process::abort()))
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn invalidate_asid_retirement(
        &self,
        retirement: &crate::hvpatch::Stage1MmRetirement,
    ) -> Result<(), String> {
        self.control.invalidate_external(retirement)
    }

    pub fn shutdown(self) -> Result<ExecutorPoolReport, ExecutorPoolShutdownError> {
        self.scheduler.close();
        let mut failures = Vec::new();
        if let Err(error) = self
            .resolver
            .cancel_dormant(&self.scheduler, ExecutionFailure::SnapshotRestoreFailed)
        {
            failures.push(format!("dormant task cancellation failed: {error}"));
        }
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
        // A task can cross Running -> Blocked after the pre-join cancellation
        // snapshot while its worker is completing save/settlement. Joined
        // workers make the generation set stable; cancel that exact successor
        // before waiting for queue closure or logical completion.
        if let Err(error) = self
            .resolver
            .cancel_dormant(&self.scheduler, ExecutionFailure::SnapshotRestoreFailed)
        {
            tracing::error!(%error, "post-join exact dormant cancellation failed");
            std::process::abort();
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

    #[cfg(test)]
    pub fn submit_root(
        &self,
        thread: Arc<crate::kernel::Thread>,
        generation: ExecutionGeneration,
    ) -> Result<(), SchedulerError> {
        let authority = self.scheduler.admit_root(thread.key(), generation)?;
        self.resolver
            .publish_test_root(&self.scheduler, thread, authority)
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
    control: Arc<PoolControl>,
    channels: WorkerChannels,
) -> WorkerOutcome
where
    F: PersistentExecutorFactory,
    R: TaskBindingResolver<
        <<F as PersistentExecutorFactory>::Executor as PersistentExecutor>::TaskBinding,
    >,
{
    let WorkerChannels { commands, startup } = channels;
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
                executor: None,
                kick: None,
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
                executor: Some(executor_id),
                kick: None,
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
                executor: Some(executor_id),
                kick: None,
            });
            return WorkerOutcome {
                executor: Some(executor_id),
                failure: Some(message),
                retired: true,
            };
        }
    };
    let mut startup_sent = false;
    let lifecycle = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
        receipts.record(executor_id, ExecutorPoolEvent::Created);
        probe_executor_lifecycle(
            executor_id,
            crate::probes::HvpatchExecutorLifecyclePhase::Create,
            None,
            None,
            0,
        );
        let boundary = WorkerBoundaryAudit::capture()
            .and_then(|boundary| {
                boundary.audit_clean(&mut backend, &kick)?;
                Ok(boundary)
            })
            .map_err(|error| error.to_string())?;
        receipts.record(executor_id, ExecutorPoolEvent::AuditPassed);
        startup
            .send(StartupStatus {
                index,
                error: None,
                executor: Some(executor_id),
                kick: Some(Arc::clone(&kick)),
            })
            .map_err(|error| format!("startup status publication failed: {error}"))?;
        startup_sent = true;
        match commands.recv() {
            Ok(WorkerCommand::Run) => run_executor_loop(
                &scheduler,
                &resolver,
                &mut backend,
                WorkerRuntime {
                    registration: &registration,
                    kick: &kick,
                    boundary: &boundary,
                    receipts: &receipts,
                    control: &control,
                },
                &commands,
            ),
            Ok(WorkerCommand::Stop) | Err(_) => Ok(()),
            Ok(WorkerCommand::Initialize | WorkerCommand::InvalidateAsid { .. }) => {
                Err("executor received duplicate initialize".to_owned())
            }
        }
    }));
    let mut retired = false;
    let mut failure = match lifecycle {
        Ok(Ok(())) => None,
        Ok(Err(error)) => {
            retired = true;
            Some(error)
        }
        Err(_) => {
            retired = true;
            Some("executor post-create lifecycle panicked; exact lease failed closed".to_owned())
        }
    };
    if !startup_sent {
        let message = failure
            .clone()
            .unwrap_or_else(|| "executor stopped before startup publication".to_owned());
        let _ = startup.send(StartupStatus {
            index,
            error: Some(message),
            executor: Some(executor_id),
            kick: None,
        });
    }
    if startup_sent
        && failure.is_some()
        && control.retire_failed_worker()
        && let Err(drain_error) =
            terminal_drain(&scheduler, resolver.as_ref(), &registration, &receipts)
    {
        if let Some(existing) = &mut failure {
            existing.push_str("; ");
            existing.push_str(&drain_error);
        } else {
            failure = Some(drain_error);
        }
    }
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

fn terminal_drain<B, R>(
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

fn run_executor_loop<F, R>(
    scheduler: &Arc<Scheduler>,
    resolver: &Arc<R>,
    backend: &mut F,
    runtime: WorkerRuntime<'_>,
    commands: &mpsc::Receiver<WorkerCommand>,
) -> Result<(), String>
where
    F: PersistentExecutor,
    R: TaskBindingResolver<F::TaskBinding>,
{
    let WorkerRuntime {
        registration,
        kick,
        boundary,
        receipts,
        control,
    } = runtime;
    loop {
        if service_owner_thread_commands(backend, registration.id(), commands, boundary, receipts)?
        {
            return Ok(());
        }
        let mut running = match scheduler.take(registration) {
            Ok(running) => running,
            Err(crate::kernel::RunQueueError::ControlPoked) => continue,
            Err(crate::kernel::RunQueueError::Closed) => return Ok(()),
            Err(error) => return Err(error.to_string()),
        };
        let executor_id = running.executor();
        let mut thread = running.thread_key();
        let mut generation = running.generation();
        receipts.record(
            executor_id,
            ExecutorPoolEvent::Claimed { thread, generation },
        );
        if let Err(error) = boundary.audit_runtime(backend) {
            let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                resolver.as_ref(),
                scheduler,
                running,
                ExecutionFailure::SnapshotRestoreFailed,
                receipts,
            );
            return Err(with_settlement_error(error.to_string(), settlement));
        }
        let mut binding = match resolver.resolve(thread, generation) {
            Ok(binding) => binding,
            Err(error) => {
                let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                    resolver.as_ref(),
                    scheduler,
                    running,
                    ExecutionFailure::SnapshotRestoreFailed,
                    receipts,
                );
                return Err(with_settlement_error(error.to_string(), settlement));
            }
        };
        let mut submission_authority = resolver.take_submission_authority(thread, generation);
        let task = RunnableTask {
            thread,
            generation,
            lease: running.lease(),
            binding: Arc::clone(&binding),
        };
        let mut asid_generation = match task.validate_for_load() {
            Ok(state) => state.asid_generation,
            Err(error) => {
                let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                    resolver.as_ref(),
                    scheduler,
                    running,
                    ExecutionFailure::SnapshotRestoreFailed,
                    receipts,
                );
                return Err(with_settlement_error(error.to_string(), settlement));
            }
        };
        if let Err(error) = backend.load(&task) {
            let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                resolver.as_ref(),
                scheduler,
                running,
                ExecutionFailure::SnapshotRestoreFailed,
                receipts,
            );
            return Err(with_settlement_error(error.to_string(), settlement));
        }
        let hardware = match backend.hardware_kick() {
            Ok(hardware) => hardware,
            Err(error) => {
                let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                    resolver.as_ref(),
                    scheduler,
                    running,
                    ExecutionFailure::SnapshotRestoreFailed,
                    receipts,
                );
                return Err(with_settlement_error(error.to_string(), settlement));
            }
        };
        if !kick.publish_hardware(hardware) {
            let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                resolver.as_ref(),
                scheduler,
                running,
                ExecutionFailure::SnapshotRestoreFailed,
                receipts,
            );
            return Err(with_settlement_error(
                "backend failed to publish exact live hardware kick".to_owned(),
                settlement,
            ));
        }
        receipts.record(
            executor_id,
            ExecutorPoolEvent::Loaded { thread, generation },
        );
        probe_executor_lifecycle(
            executor_id,
            crate::probes::HvpatchExecutorLifecyclePhase::Load,
            Some(thread),
            Some(generation),
            asid_generation,
        );

        let mut pending_exec_retirement = None;
        let exit = loop {
            let lease = running.take_lease();
            #[cfg(test)]
            let publish_test_descendant = |child, child_generation| {
                let parent = submission_authority.as_ref().ok_or_else(|| {
                    TrapError::Hypervisor(
                        "test descendant publication has no resolver authority".to_owned(),
                    )
                })?;
                resolver.publish_test_descendant(scheduler, parent, child, child_generation)
            };
            let mut submission = ExecutorSubmissionContext {
                scheduler,
                #[cfg(test)]
                publish_test_descendant: &publish_test_descendant,
                current: submission_authority.as_ref(),
                lease: Some(lease),
                exec_replacement: None,
            };
            let attempted = catch_unwind(AssertUnwindSafe(|| {
                backend.run_until_boundary(&kick.need_resched, &mut submission)
            }));
            let exec_replacement = submission.exec_replacement.take();
            let lease = match submission.take_execution_lease() {
                Ok(lease) => lease,
                Err(error) => {
                    let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                        resolver.as_ref(),
                        scheduler,
                        running,
                        ExecutionFailure::SnapshotRestoreFailed,
                        receipts,
                    );
                    return Err(with_settlement_error(error.to_string(), settlement));
                }
            };
            if let Some(replacement) = exec_replacement {
                let PendingExecReplacement {
                    transition,
                    replacement_mm,
                    retired_mm,
                } = replacement;
                let predecessor_thread = thread;
                let predecessor_generation = generation;
                let successor_generation = lease.generation();
                let authority = submission_authority.take();
                let replacement_record =
                    scheduler.retarget_running_exec(&mut running, transition, lease, |committed| {
                        backend
                            .validate_loaded_hardware_identity()
                            .map_err(|error| error.to_string())?;
                        let identity = TaskLoadIdentity {
                            abi: binding.load_identity().abi,
                            version: binding.load_identity().version,
                            mm: committed.successor_mm,
                            asid_generation: committed.successor_asid_generation,
                        };
                        let replacement_record = resolver
                            .replace_exec(
                                scheduler,
                                ExecBindingTransition {
                                    predecessor_thread,
                                    predecessor_generation,
                                    successor_thread: committed.successor_thread,
                                    successor_generation,
                                    identity,
                                    replacement_mm: Some(Arc::clone(&replacement_mm)),
                                    authority,
                                },
                            )
                            .map_err(|error| error.to_string())?;
                        if backend
                            .retarget_loaded_task(Arc::clone(&replacement_record.binding))
                            .is_err()
                        {
                            // The combined record now names the replacement;
                            // allowing the old Arc to receive saved state would
                            // split immutable MM/ASID identity.
                            std::process::abort();
                        }
                        Ok(replacement_record)
                    });
                let replacement_record = match replacement_record {
                    Ok(replacement) => replacement,
                    Err(error) => {
                        // Kernel exec has already published the replacement
                        // image/thread. Returning through predecessor failure
                        // cleanup would orphan the active successor and its
                        // authority. This is a split-authority invariant loss,
                        // so fail-stop the carrier rather than resume either
                        // image.
                        tracing::error!(%error, "worker-owned exec retarget failed after publication");
                        std::process::abort();
                    }
                };
                binding = replacement_record.binding;
                pending_exec_retirement = Some(retired_mm);
                submission_authority = replacement_record.authority;
                thread = running.thread_key();
                generation = successor_generation;
                asid_generation = binding.load_identity().asid_generation;
            } else if let Err((error, lease)) = running.restore_lease(lease) {
                let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                    resolver.as_ref(),
                    scheduler,
                    running,
                    ExecutionFailure::SnapshotRestoreFailed,
                    receipts,
                );
                drop(lease);
                return Err(with_settlement_error(error.to_string(), settlement));
            }
            let cpu = backend.take_cpu_receipt();
            running.thread().charge_user_ns(cpu.user_ns);
            running.thread().charge_system_ns(cpu.system_ns);
            let exit = match attempted {
                Ok(Ok(exit)) => exit,
                Ok(Err(error)) => {
                    let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                        resolver.as_ref(),
                        scheduler,
                        running,
                        ExecutionFailure::SnapshotRestoreFailed,
                        receipts,
                    );
                    return Err(with_settlement_error(error.to_string(), settlement));
                }
                Err(_) => {
                    let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                        resolver.as_ref(),
                        scheduler,
                        running,
                        ExecutionFailure::SnapshotRestoreFailed,
                        receipts,
                    );
                    return Err(with_settlement_error(
                        "backend run panicked after publishing its exact CPU receipt".to_owned(),
                        settlement,
                    ));
                }
            };
            if matches!(exit, ExecutorExit::Syscall) {
                scheduler.note_syscall_boundary(&running);
                receipts.record(
                    executor_id,
                    ExecutorPoolEvent::OrdinarySyscall { thread, generation },
                );
                continue;
            }
            break exit;
        };
        if matches!(exit, ExecutorExit::InvalidState) {
            let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                resolver.as_ref(),
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
            let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                resolver.as_ref(),
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
                    let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                        resolver.as_ref(),
                        scheduler,
                        running,
                        ExecutionFailure::SnapshotSaveFailed,
                        receipts,
                    );
                    drop(lease);
                    return Err(with_settlement_error(
                        format!("{source}; lease restore failed: {restore_error}"),
                        settlement,
                    ));
                }
                let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                    resolver.as_ref(),
                    scheduler,
                    running,
                    ExecutionFailure::SnapshotSaveFailed,
                    receipts,
                );
                return Err(with_settlement_error(source.to_string(), settlement));
            }
        };
        receipts.record(executor_id, ExecutorPoolEvent::Saved { thread, generation });
        probe_executor_lifecycle(
            executor_id,
            crate::probes::HvpatchExecutorLifecyclePhase::Save,
            Some(thread),
            Some(generation),
            asid_generation,
        );
        if let Err((error, lease)) = scheduler.restore_saved_lease(&mut running, saved.into_lease())
        {
            let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                resolver.as_ref(),
                scheduler,
                running,
                ExecutionFailure::SnapshotRestoreFailed,
                receipts,
            );
            drop(lease);
            return Err(with_settlement_error(error.to_string(), settlement));
        }
        if let Err(error) = boundary.audit_runtime(backend) {
            let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                resolver.as_ref(),
                scheduler,
                running,
                ExecutionFailure::SnapshotRestoreFailed,
                receipts,
            );
            return Err(with_settlement_error(error.to_string(), settlement));
        }
        let terminal_retirement = binding.take_address_space_retirement();
        if terminal_retirement.is_some() && pending_exec_retirement.is_some() {
            std::process::abort();
        }
        if let Some(retirement) = pending_exec_retirement.take() {
            if let Err(error) =
                control.invalidate_after_exec(&retirement, executor_id, backend, boundary, receipts)
            {
                let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                    resolver.as_ref(),
                    scheduler,
                    running,
                    ExecutionFailure::SnapshotRestoreFailed,
                    receipts,
                );
                return Err(with_settlement_error(
                    format!("exec predecessor ASID retirement failed: {error}"),
                    settlement,
                ));
            }
            if let Err(error) = retirement.complete() {
                let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                    resolver.as_ref(),
                    scheduler,
                    running,
                    ExecutionFailure::SnapshotRestoreFailed,
                    receipts,
                );
                return Err(with_settlement_error(
                    format!("exec predecessor ASID/root release failed: {error}"),
                    settlement,
                ));
            }
        }
        if let Some(retirement) = terminal_retirement {
            if let Some(stage1) = retirement.retirement()
                && let Err(error) =
                    control.invalidate_after_exec(stage1, executor_id, backend, boundary, receipts)
            {
                let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                    resolver.as_ref(),
                    scheduler,
                    running,
                    ExecutionFailure::SnapshotRestoreFailed,
                    receipts,
                );
                return Err(with_settlement_error(
                    format!("terminal ASID retirement failed: {error}"),
                    settlement,
                ));
            }
            if let Err(error) = retirement.complete() {
                let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                    resolver.as_ref(),
                    scheduler,
                    running,
                    ExecutionFailure::SnapshotRestoreFailed,
                    receipts,
                );
                return Err(with_settlement_error(
                    format!("terminal ASID/root release failed: {error}"),
                    settlement,
                ));
            }
        }
        if let Some(authority) = submission_authority.take() {
            if let Err(authority) = resolver.restore_submission_authority(authority) {
                drop(authority);
                return Err(
                    "combined task resolver rejected worker-held authority restoration".to_owned(),
                );
            }
        }
        let settlement = match exit {
            ExecutorExit::Blocked(reason) => {
                drop(submission_authority);
                scheduler
                    .settle_blocked(running, reason)
                    .map(|()| ExecutorPoolEvent::SettledBlocked { thread, generation })
            }
            ExecutorExit::BlockedContinuation(continuation) => {
                let mut registration = control.wait_service.prepare_registration(&continuation);
                if let Err(error) = control.wait_service.enroll(&mut registration) {
                    let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                        resolver.as_ref(),
                        scheduler,
                        running,
                        ExecutionFailure::SnapshotRestoreFailed,
                        receipts,
                    );
                    return Err(with_settlement_error(error.to_string(), settlement));
                }
                drop(submission_authority);
                scheduler
                    .settle_blocked_continuation(running, *continuation, registration)
                    .map(|()| ExecutorPoolEvent::SettledBlocked { thread, generation })
            }
            ExecutorExit::Yielded | ExecutorExit::Preempted => {
                let successor = scheduler
                    .settle_runnable_successor(running)
                    .map_err(|error| error.to_string())?;
                let _ = successor;
                Ok(ExecutorPoolEvent::SettledRunnable { thread, generation })
            }
            ExecutorExit::Quiesced => {
                drop(submission_authority);
                scheduler
                    .settle_blocked(running, BlockedReason::HostWait)
                    .map(|()| ExecutorPoolEvent::SettledBlocked { thread, generation })
            }
            ExecutorExit::Exited => {
                drop(submission_authority);
                let settled = scheduler
                    .settle_exited(running)
                    .map(|()| ExecutorPoolEvent::SettledExited { thread, generation });
                if settled.is_ok() {
                    resolver.retire(thread, generation);
                }
                settled
            }
            ExecutorExit::Syscall | ExecutorExit::InvalidState => unreachable!(),
        };
        match settlement {
            Ok(event) => {
                if matches!(event, ExecutorPoolEvent::SettledExited { .. }) {
                    binding.after_terminal_settlement();
                }
                receipts.record(executor_id, event);
                probe_executor_lifecycle(
                    executor_id,
                    crate::probes::HvpatchExecutorLifecyclePhase::Switch,
                    Some(thread),
                    Some(generation),
                    asid_generation,
                );
            }
            Err(error) => return Err(error.to_string()),
        }
        // All fallible owner/backend checks ran while `running` still carried
        // the predecessor claim. Settlement then unbound the exact kick in the
        // same scheduler transaction. A bound kick here is an internal
        // invariant violation after successor publication; fail-stop instead
        // of retrospectively failing a predecessor that no longer exists.
        if kick.current_binding().is_some() {
            std::process::abort();
        }
        receipts.record(executor_id, ExecutorPoolEvent::AuditPassed);
        std::thread::yield_now();
    }
}

fn service_owner_thread_commands<E: PersistentExecutor>(
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

fn fail_running_and_retire<B, R>(
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
    let binding = resolver.resolve(thread, generation).ok();
    let result = fail_running(scheduler, running, reason, receipts);
    resolver.retire(thread, generation);
    if let Some(binding) = binding {
        binding.after_terminal_settlement();
    }
    result
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
pub(crate) mod tests {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread::{self, ThreadId as HostThreadId};
    use std::time::{Duration, Instant};

    use carrick_abi::LinuxCloneFlags;
    use carrick_hal::ThreadId;
    use carrick_hal::threaded::{
        Aarch64SyscallContinuationV1, Aarch64TaskCpuStateV1, GuestCpuState,
    };

    use super::{
        ExecBindingTransition, ExecutorBoundaryAudit, ExecutorCpuReceipt, ExecutorExit,
        ExecutorPool, ExecutorPoolConfig, ExecutorPoolEvent, ExecutorSaveError,
        ExecutorSubmissionContext, HvpatchActivationProof, HvpatchQuantumControl,
        HvpatchSubmissionShape, HvpatchTaskBindingDirectory, PersistentExecutor,
        PersistentExecutorFactory, PersistentTaskBinding, ReceiptLog, RunnableTask, SavedRunnable,
        TaskBindingResolver, TaskLoadIdentity, WorkerBoundaryAudit, WorkerKick,
        restore_worker_vcpu_before_binding_publication, retire_failed_hvpatch_clone_authority,
    };
    use crate::compat::SyscallArgs;
    use crate::dispatch::{DispatchOutcome, SyscallDispatcher, SyscallRequest};
    use crate::kernel::objects::{
        BlockedReason, ExecutionFailure, ExecutionGeneration, ExecutorId, MigratableTaskState,
        ThreadExecutionLease, ThreadExecutionState,
    };
    use crate::kernel::{
        ClonePlan, Kernel, KernelContext, RootBootstrap, Scheduler, SchedulerError,
        SubmissionAuthority, ThreadKey,
    };
    use crate::trap::TrapError;

    #[derive(Clone)]
    struct TestVcpuKick;

    impl carrick_hal::VcpuKick for TestVcpuKick {
        fn kick(&self) {}
    }

    fn test_hardware_kick(raw_vcpu_id: u64) -> super::ExactHardwareKick {
        super::ExactHardwareKick::new(
            Box::new(TestVcpuKick),
            raw_vcpu_id.max(1),
            super::current_owner_thread_port(),
        )
        .unwrap()
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Step {
        Syscalls(usize),
        ComputeUntilKick,
        Block,
        Yield,
        Preempt,
        Exit,
        FailRun,
        PanicRun,
        LoseLease,
        Invalid,
    }

    #[derive(Debug)]
    struct DescendantPublication {
        child_thread: Arc<crate::kernel::Thread>,
        child_generation: ExecutionGeneration,
        after_progress: usize,
        published: Option<std::sync::mpsc::Sender<()>>,
    }

    #[derive(Debug)]
    struct FakeBinding {
        marker: u64,
        steps: parking_lot::Mutex<VecDeque<Step>>,
        load_fails: AtomicBool,
        save_fails: AtomicBool,
        audit_fails: AtomicBool,
        entered: parking_lot::Mutex<Option<Arc<Barrier>>>,
        resume: parking_lot::Mutex<Option<Arc<Barrier>>>,
        progress: AtomicUsize,
        load_identity: parking_lot::Mutex<Option<TaskLoadIdentity>>,
        required_continuation_sequence: parking_lot::Mutex<Option<u64>>,
        blocked_continuation:
            parking_lot::Mutex<Option<crate::vcpu_loop::continuation::BlockedContinuation>>,
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
                resume: parking_lot::Mutex::new(None),
                progress: AtomicUsize::new(0),
                load_identity: parking_lot::Mutex::new(None),
                required_continuation_sequence: parking_lot::Mutex::new(None),
                blocked_continuation: parking_lot::Mutex::new(None),
                descendant: parking_lot::Mutex::new(None),
            })
        }

        fn override_expected_abi(&self, abi: carrick_abi::LinuxGuestAbi) {
            self.load_identity
                .lock()
                .as_mut()
                .expect("installed load identity")
                .abi = abi;
        }

        fn override_expected_version(&self, version: u16) {
            self.load_identity
                .lock()
                .as_mut()
                .expect("installed load identity")
                .version = version;
        }

        fn override_expected_mm(&self, mm: crate::kernel::MmId) {
            self.load_identity
                .lock()
                .as_mut()
                .expect("installed load identity")
                .mm = mm;
        }

        fn override_expected_asid_generation(&self, asid_generation: u64) {
            self.load_identity
                .lock()
                .as_mut()
                .expect("installed load identity")
                .asid_generation = asid_generation;
        }

        fn require_continuation_sequence(&self, sequence: u64) {
            *self.required_continuation_sequence.lock() = Some(sequence);
        }

        fn block_with_continuation(
            &self,
            continuation: crate::vcpu_loop::continuation::BlockedContinuation,
        ) {
            *self.blocked_continuation.lock() = Some(continuation);
        }
    }

    impl PersistentTaskBinding for FakeBinding {
        fn load_identity(&self) -> TaskLoadIdentity {
            self.load_identity
                .lock()
                .expect("fake binding installed before publication")
        }

        fn validate_task_state(&self, state: &MigratableTaskState) -> Result<(), TrapError> {
            let Some(expected) = *self.required_continuation_sequence.lock() else {
                return Ok(());
            };
            let actual = match &state.cpu {
                GuestCpuState::Aarch64V1(state) => state
                    .syscall_continuation
                    .map(|continuation| continuation.sequence),
                GuestCpuState::X86_64V1(_) => None,
            };
            if actual != Some(expected) || expected == 0 {
                return Err(TrapError::Hypervisor(format!(
                    "fake task continuation mismatch: expected {expected}, got {actual:?}"
                )));
            }
            Ok(())
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
        Invalidate,
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
        authorities: Arc<
            parking_lot::Mutex<BTreeMap<(ThreadKey, ExecutionGeneration), SubmissionAuthority>>,
        >,
        scheduler: Arc<parking_lot::Mutex<std::sync::Weak<Scheduler>>>,
        events: Arc<parking_lot::Mutex<Vec<BackendEvent>>>,
        create_calls: Arc<AtomicUsize>,
        fail_create_call: Arc<AtomicUsize>,
        panic_initial_audit_call: Arc<AtomicUsize>,
        initial_audit_gate: Arc<parking_lot::Mutex<Option<Arc<Barrier>>>>,
        fail_invalidation_generation: Arc<AtomicU64>,
        fail_hardware_kick: Arc<AtomicBool>,
        owner_dirty_mode: Arc<AtomicUsize>,
        owner_dirty_fds: Arc<parking_lot::Mutex<Vec<(i32, i32)>>>,
        destroy_mode: Arc<AtomicUsize>,
        snapshot_count: Arc<AtomicUsize>,
        concurrent_loads: Arc<parking_lot::Mutex<BTreeSet<(ThreadKey, ExecutionGeneration)>>>,
        inherited_state: Arc<parking_lot::Mutex<Vec<(u64, u64, u64, u64, u64)>>>,
        retired_bindings: Arc<parking_lot::Mutex<Vec<(ThreadKey, ExecutionGeneration)>>>,
    }

    impl FakeFactory {
        fn install(&self, context: &KernelContext, binding: Arc<FakeBinding>) {
            let mm = context.shared().mm().id();
            *binding.load_identity.lock() = Some(TaskLoadIdentity {
                abi: carrick_abi::LinuxGuestAbi::Aarch64,
                version: 1,
                mm,
                asid_generation: mm.raw(),
            });
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
        fn install_scheduler(
            self: &Arc<Self>,
            scheduler: &Arc<Scheduler>,
        ) -> Result<(), TrapError> {
            *self.scheduler.lock() = Arc::downgrade(scheduler);
            scheduler
                .install_generation_observer(Arc::clone(self)
                    as Arc<dyn crate::kernel::scheduler::SchedulerGenerationObserver>)
                .map_err(|error| TrapError::Hypervisor(error.to_string()))
        }

        fn resolve(
            &self,
            thread: ThreadKey,
            _generation: ExecutionGeneration,
        ) -> Result<Arc<FakeBinding>, TrapError> {
            self.bindings.lock().get(&thread).cloned().ok_or_else(|| {
                TrapError::Hypervisor(format!("missing fake binding for {thread:?}"))
            })
        }

        fn retire(&self, thread: ThreadKey, generation: ExecutionGeneration) {
            self.authorities.lock().remove(&(thread, generation));
            self.retired_bindings.lock().push((thread, generation));
        }

        fn take_submission_authority(
            &self,
            thread: ThreadKey,
            generation: ExecutionGeneration,
        ) -> Option<SubmissionAuthority> {
            self.authorities.lock().remove(&(thread, generation))
        }

        fn restore_submission_authority(
            &self,
            authority: SubmissionAuthority,
        ) -> Result<(), SubmissionAuthority> {
            let key = (authority.thread_key(), authority.generation());
            let mut authorities = self.authorities.lock();
            if authorities.contains_key(&key) {
                return Err(authority);
            }
            authorities.insert(key, authority);
            Ok(())
        }

        fn publish_test_root(
            &self,
            scheduler: &Scheduler,
            thread: Arc<crate::kernel::Thread>,
            authority: SubmissionAuthority,
        ) -> Result<(), SchedulerError> {
            let key = (authority.thread_key(), authority.generation());
            let mut authorities = self.authorities.lock();
            if authorities.contains_key(&key) {
                return Err(crate::kernel::RunQueueError::SubmissionRejected.into());
            }
            authority.publish(scheduler, thread)?;
            authorities.insert(key, authority);
            Ok(())
        }

        fn publish_test_descendant(
            &self,
            scheduler: &Scheduler,
            parent: &SubmissionAuthority,
            thread: Arc<crate::kernel::Thread>,
            generation: ExecutionGeneration,
        ) -> Result<(), TrapError> {
            let authority = parent
                .admit_descendant(thread.key(), generation)
                .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
            self.publish_test_root(scheduler, thread, authority)
                .map_err(|error| TrapError::Hypervisor(error.to_string()))
        }
    }

    impl crate::kernel::scheduler::SchedulerGenerationObserver for FakeFactory {
        fn transition(
            &self,
            thread: ThreadKey,
            predecessor: ExecutionGeneration,
            successor: ExecutionGeneration,
            kind: crate::kernel::scheduler::SchedulerGenerationTransition,
        ) -> Result<(), crate::kernel::RunQueueError> {
            let Some(scheduler) = self.scheduler.lock().upgrade() else {
                return Err(crate::kernel::RunQueueError::Closed);
            };
            let mut authorities = self.authorities.lock();
            let Some(authority) = authorities.remove(&(thread, predecessor)) else {
                return Ok(());
            };
            if kind == crate::kernel::scheduler::SchedulerGenerationTransition::Terminal {
                return Ok(());
            }
            if authorities.contains_key(&(thread, successor)) {
                return Err(crate::kernel::RunQueueError::SubmissionRejected);
            }
            let authority =
                if kind == crate::kernel::scheduler::SchedulerGenerationTransition::Blocked {
                    authority
                        .park_exact(&scheduler, predecessor, successor)
                        .map_err(|(error, _authority)| error)?
                } else if authority.is_active() {
                    authority
                        .rollover_exact(&scheduler, thread, predecessor, thread, successor)
                        .map_err(|(error, _authority)| error)?
                } else {
                    authority
                        .reactivate_exact(&scheduler, predecessor, successor)
                        .map_err(|(error, _authority)| error)?
                };
            authorities.insert((thread, successor), authority);
            Ok(())
        }
    }

    struct FakeExecutor {
        id: ExecutorId,
        factory: FakeFactory,
        owner: HostThreadId,
        create_call: usize,
        current: Option<(ThreadKey, ExecutionGeneration, Arc<FakeBinding>)>,
        owner_dirty_cleanup: Option<Box<dyn FnOnce()>>,
        credentials: u64,
        restart_state: u64,
        mailbox: u64,
        tls: u64,
        user_ns: u64,
        system_ns: u64,
    }

    struct BoundaryAuditProbe;

    #[derive(Debug)]
    struct MaliciousBinding {
        identity: TaskLoadIdentity,
        entered: Arc<Barrier>,
        resume: Arc<Barrier>,
    }

    impl PersistentTaskBinding for MaliciousBinding {
        fn load_identity(&self) -> TaskLoadIdentity {
            self.identity
        }

        fn validate_task_state(&self, _state: &MigratableTaskState) -> Result<(), TrapError> {
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct MaliciousFactory {
        bindings: parking_lot::Mutex<BTreeMap<ThreadKey, Arc<MaliciousBinding>>>,
        authorities:
            parking_lot::Mutex<BTreeMap<(ThreadKey, ExecutionGeneration), SubmissionAuthority>>,
    }

    impl MaliciousFactory {
        fn install(&self, context: &KernelContext, entered: Arc<Barrier>, resume: Arc<Barrier>) {
            let mm = context.shared().mm().id();
            self.bindings.lock().insert(
                context.thread().key(),
                Arc::new(MaliciousBinding {
                    identity: TaskLoadIdentity {
                        abi: carrick_abi::LinuxGuestAbi::Aarch64,
                        version: 1,
                        mm,
                        asid_generation: mm.raw(),
                    },
                    entered,
                    resume,
                }),
            );
        }
    }

    impl TaskBindingResolver<MaliciousBinding> for MaliciousFactory {
        fn resolve(
            &self,
            thread: ThreadKey,
            _generation: ExecutionGeneration,
        ) -> Result<Arc<MaliciousBinding>, TrapError> {
            self.bindings
                .lock()
                .get(&thread)
                .cloned()
                .ok_or_else(|| TrapError::Hypervisor("missing malicious binding".to_owned()))
        }

        fn take_submission_authority(
            &self,
            thread: ThreadKey,
            generation: ExecutionGeneration,
        ) -> Option<SubmissionAuthority> {
            self.authorities.lock().remove(&(thread, generation))
        }

        fn restore_submission_authority(
            &self,
            authority: SubmissionAuthority,
        ) -> Result<(), SubmissionAuthority> {
            let key = (authority.thread_key(), authority.generation());
            let mut authorities = self.authorities.lock();
            if authorities.contains_key(&key) {
                return Err(authority);
            }
            authorities.insert(key, authority);
            Ok(())
        }

        fn publish_test_root(
            &self,
            scheduler: &Scheduler,
            thread: Arc<crate::kernel::Thread>,
            authority: SubmissionAuthority,
        ) -> Result<(), SchedulerError> {
            let key = (authority.thread_key(), authority.generation());
            let mut authorities = self.authorities.lock();
            if authorities.contains_key(&key) {
                return Err(crate::kernel::RunQueueError::SubmissionRejected.into());
            }
            authority.publish(scheduler, thread)?;
            authorities.insert(key, authority);
            Ok(())
        }

        fn retire(&self, thread: ThreadKey, generation: ExecutionGeneration) {
            self.authorities.lock().remove(&(thread, generation));
        }
    }

    struct MaliciousExecutor {
        id: ExecutorId,
        current: Option<Arc<MaliciousBinding>>,
    }

    impl PersistentExecutorFactory for MaliciousFactory {
        type Executor = MaliciousExecutor;

        fn create(&self, executor: ExecutorId) -> Result<Self::Executor, TrapError> {
            Ok(MaliciousExecutor {
                id: executor,
                current: None,
            })
        }
    }

    impl PersistentExecutor for MaliciousExecutor {
        type TaskBinding = MaliciousBinding;

        fn load(&mut self, task: &RunnableTask<'_, Self::TaskBinding>) -> Result<(), TrapError> {
            task.validate_for_load()?;
            self.current = Some(Arc::clone(task.binding()));
            Ok(())
        }

        fn run_until_boundary(
            &mut self,
            _need_resched: &AtomicBool,
            _submission: &mut super::ExecutorSubmissionContext<'_>,
        ) -> Result<ExecutorExit, TrapError> {
            let binding = self.current.as_ref().expect("malicious binding loaded");
            binding.entered.wait();
            binding.resume.wait();
            Err(TrapError::Hypervisor(
                "malicious backend retains binding through failure".to_owned(),
            ))
        }

        fn take_cpu_receipt(&mut self) -> ExecutorCpuReceipt {
            ExecutorCpuReceipt::default()
        }

        fn hardware_kick(&self) -> Result<super::ExactHardwareKick, TrapError> {
            Ok(test_hardware_kick(u64::from(self.id.raw_for_probe())))
        }

        fn save(
            &mut self,
            lease: ThreadExecutionLease,
        ) -> Result<SavedRunnable, ExecutorSaveError> {
            Err(ExecutorSaveError::new(
                TrapError::Hypervisor("malicious executor cannot save".to_owned()),
                lease,
            ))
        }

        fn invalidate_asid(
            &mut self,
            _generation: crate::hvpatch::AsidGeneration,
        ) -> Result<(), TrapError> {
            Ok(())
        }

        fn audit_boundary(&mut self) -> Result<(), TrapError> {
            Ok(())
        }

        fn destroy(self) -> Result<(), TrapError> {
            drop(self.current);
            Ok(())
        }
    }

    impl PersistentExecutor for BoundaryAuditProbe {
        type TaskBinding = FakeBinding;

        fn load(&mut self, _task: &RunnableTask<'_, Self::TaskBinding>) -> Result<(), TrapError> {
            panic!("audit-only backend cannot load a task")
        }

        fn run_until_boundary(
            &mut self,
            _need_resched: &AtomicBool,
            _submission: &mut super::ExecutorSubmissionContext<'_>,
        ) -> Result<ExecutorExit, TrapError> {
            panic!("audit-only backend cannot run a task")
        }

        fn take_cpu_receipt(&mut self) -> ExecutorCpuReceipt {
            panic!("audit-only backend has no CPU receipt")
        }

        fn hardware_kick(&self) -> Result<super::ExactHardwareKick, TrapError> {
            panic!("audit-only backend has no hardware kick")
        }

        fn save(
            &mut self,
            _lease: ThreadExecutionLease,
        ) -> Result<SavedRunnable, ExecutorSaveError> {
            panic!("audit-only backend cannot save a task")
        }

        fn invalidate_asid(
            &mut self,
            _generation: crate::hvpatch::AsidGeneration,
        ) -> Result<(), TrapError> {
            panic!("audit-only backend cannot invalidate an ASID")
        }

        fn audit_boundary(&mut self) -> Result<(), TrapError> {
            Ok(())
        }

        fn destroy(self) -> Result<(), TrapError> {
            Ok(())
        }
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
                create_call: call,
                current: None,
                owner_dirty_cleanup: None,
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
            task.validate_for_load()?;
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
            submission: &mut super::ExecutorSubmissionContext<'_>,
        ) -> Result<ExecutorExit, TrapError> {
            assert_eq!(thread::current().id(), self.owner);
            let (thread, generation, binding) = self.current.as_ref().expect("loaded task");
            self.factory
                .record(BackendEventKind::Run, self.id, Some((*thread, *generation)));
            binding.progress.fetch_add(1, Ordering::SeqCst);
            if let Some(gate) = binding.entered.lock().take() {
                gate.wait();
            }
            if let Some(gate) = binding.resume.lock().take() {
                gate.wait();
            }
            let should_publish = binding
                .descendant
                .lock()
                .as_ref()
                .is_some_and(|publication| {
                    binding.progress.load(Ordering::SeqCst) >= publication.after_progress
                });
            if should_publish {
                let publication = binding
                    .descendant
                    .lock()
                    .take()
                    .expect("ready descendant publication");
                submission
                    .publish_test_descendant(
                        Arc::clone(&publication.child_thread),
                        publication.child_generation,
                    )
                    .expect("publish descendant during closing");
                if let Some(published) = publication.published {
                    published.send(()).expect("publish descendant receipt");
                }
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
                Step::Block => match binding.blocked_continuation.lock().take() {
                    Some(continuation) => {
                        Ok(ExecutorExit::BlockedContinuation(Box::new(continuation)))
                    }
                    None => Ok(ExecutorExit::Blocked(BlockedReason::HostWait)),
                },
                Step::Yield => Ok(ExecutorExit::Yielded),
                Step::Preempt => Ok(ExecutorExit::Preempted),
                Step::Exit => Ok(ExecutorExit::Exited),
                Step::FailRun => Err(TrapError::Hypervisor("injected run failure".to_owned())),
                Step::PanicRun => panic!("injected executor panic"),
                Step::LoseLease => {
                    let lease = submission
                        .execution_lease_slot_mut()
                        .take()
                        .expect("worker injected exact lease");
                    std::mem::forget(lease);
                    Ok(ExecutorExit::InvalidState)
                }
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

        fn hardware_kick(&self) -> Result<super::ExactHardwareKick, TrapError> {
            if self.factory.fail_hardware_kick.load(Ordering::SeqCst) {
                return Err(TrapError::Hypervisor(
                    "injected missing exact hardware identity".to_owned(),
                ));
            }
            Ok(test_hardware_kick(u64::from(self.id.raw_for_probe())))
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
            match self.factory.owner_dirty_mode.load(Ordering::SeqCst) {
                1 => {
                    let guard = carrick_thread::fork_quiesce::acquire_topology_lock(
                        carrick_observability::probes::HvpatchTopologyOperation::AliasMap,
                        1,
                        1,
                    );
                    self.owner_dirty_cleanup = Some(Box::new(move || drop(guard)));
                }
                2 => {
                    let guard = crate::dispatch::lock_order::LockOrderGuard::acquire(
                        crate::dispatch::lock_order::LockLevel::Proc,
                    );
                    self.owner_dirty_cleanup = Some(Box::new(move || drop(guard)));
                }
                3 => {
                    let guard = SyscallDispatcher::dirty_executor_boundary_path_guard_for_test();
                    self.owner_dirty_cleanup = Some(Box::new(move || drop(guard)));
                }
                4 => {
                    let guard =
                        crate::dispatch::resources::dirty_executor_boundary_resources_guard_for_test();
                    self.owner_dirty_cleanup = Some(Box::new(move || drop(guard)));
                }
                5 => {
                    let guard = crate::fanotify::InternalOpenGuard::enter();
                    self.owner_dirty_cleanup = Some(Box::new(move || drop(guard)));
                }
                6 => {
                    let mut blocked = unsafe { std::mem::zeroed::<libc::sigset_t>() };
                    let mut previous = unsafe { std::mem::zeroed::<libc::sigset_t>() };
                    assert_eq!(unsafe { libc::sigemptyset(&mut blocked) }, 0);
                    assert_eq!(unsafe { libc::sigaddset(&mut blocked, libc::SIGUSR1) }, 0);
                    assert_eq!(
                        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous) },
                        0
                    );
                    self.owner_dirty_cleanup = Some(Box::new(move || {
                        assert_eq!(
                            unsafe {
                                libc::pthread_sigmask(
                                    libc::SIG_SETMASK,
                                    &previous,
                                    std::ptr::null_mut(),
                                )
                            },
                            0
                        );
                    }));
                }
                7 => {
                    let fds = SyscallDispatcher::dirty_sysv_executor_boundary_state_for_test();
                    self.factory.owner_dirty_fds.lock().push(fds);
                }
                _ => {}
            }
            Ok(SavedRunnable::new(lease))
        }

        fn invalidate_asid(
            &mut self,
            generation: crate::hvpatch::AsidGeneration,
        ) -> Result<(), TrapError> {
            assert_eq!(thread::current().id(), self.owner);
            if self
                .factory
                .fail_invalidation_generation
                .load(Ordering::SeqCst)
                == generation.generation()
            {
                return Err(TrapError::Hypervisor(
                    "injected ASID invalidation failure".to_owned(),
                ));
            }
            self.factory
                .record(BackendEventKind::Invalidate, self.id, None);
            Ok(())
        }

        fn audit_boundary(&mut self) -> Result<(), TrapError> {
            assert_eq!(thread::current().id(), self.owner);
            self.factory.record(BackendEventKind::Audit, self.id, None);
            if self.current.is_none()
                && self.factory.panic_initial_audit_call.load(Ordering::SeqCst) == self.create_call
            {
                if let Some(gate) = self.factory.initial_audit_gate.lock().take() {
                    gate.wait();
                }
                panic!("injected initial boundary audit panic");
            }
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

        fn destroy(mut self) -> Result<(), TrapError> {
            assert_eq!(thread::current().id(), self.owner);
            if let Some(cleanup) = self.owner_dirty_cleanup.take() {
                cleanup();
            }
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

    #[test]
    fn pre_fork_exec_hardware_and_shutdown_guards_are_fail_closed() {
        let source = include_str!("executor.rs");
        let concrete_load = source
            .split("impl PersistentExecutor for HvpatchPersistentExecutor")
            .nth(1)
            .and_then(|tail| tail.split("fn run_until_boundary").next())
            .expect("concrete HVPatch task load");
        let begin_asid = concrete_load
            .find("begin_asid_load")
            .expect("strong ASID load admission");
        let overlay = concrete_load
            .find("overlay_task_state_on_live_executor")
            .expect("live executor task overlay");
        let resident = concrete_load
            .find("mark_resident")
            .expect("post-install ASID residence");
        let dirty = concrete_load
            .find("arm_hardware_dirty")
            .expect("pre-mutation ASID load arm");
        let barrier = concrete_load
            .find("complete_task_load_barrier")
            .expect("post-TTBR DSB/ISB load barrier");
        assert!(begin_asid < dirty && dirty < overlay && overlay < barrier && barrier < resident);

        let worker_loop = source
            .split("fn run_executor_loop")
            .nth(1)
            .and_then(|tail| tail.split("fn service_owner_thread_commands").next())
            .expect("persistent worker loop");
        let save = worker_loop.find("backend.save(lease)").expect("task save");
        let invalidate = worker_loop
            .find("invalidate_after_exec")
            .expect("post-save ASID invalidation");
        let release = worker_loop
            .find("retirement.complete()")
            .expect("post-ack ASID/root release");
        assert!(save < invalidate && invalidate < release);
        let pre_load = worker_loop
            .split("if let Err(error) = backend.load(&task)")
            .next()
            .expect("worker pre-load path");
        assert!(
            !pre_load.contains("invalidate_asid"),
            "ordinary task load must never invalidate an ASID"
        );

        let concrete_retarget = source
            .split(concat!("fn retarget_loaded_", "task(&mut self, binding:"))
            .nth(1)
            .and_then(|tail| tail.split("fn save(").next())
            .expect("concrete HVPatch loaded retarget");
        assert!(concrete_retarget.contains("validate_loaded_hardware_identity()?"));

        let exec_cutover = source
            .split("if let Some(replacement) = exec_replacement")
            .nth(1)
            .and_then(|tail| tail.split("} else if let Err").next())
            .expect("worker-owned exec cutover");
        let validate = exec_cutover
            .find("validate_loaded_hardware_identity()")
            .expect("live vCPU/Mach preflight");
        let publish = exec_cutover
            .find(".replace_exec(")
            .expect("combined successor publication");
        assert!(validate < publish);

        let marker = source
            .find(concat!("post-join exact dormant ", "cancellation failed"))
            .expect("post-join cancellation boundary");
        let cancel = source[..marker]
            .rfind("cancel_dormant")
            .expect("stable exact cancellation");
        let fail_stop = source[marker..]
            .find("std::process::abort()")
            .map(|offset| marker + offset)
            .expect("cancellation failure fail-stop");
        let wait = source[fail_stop..]
            .find("self.scheduler.wait_closed()")
            .map(|offset| fail_stop + offset)
            .expect("queue closure wait");
        assert!(cancel < fail_stop && fail_stop < wait);
    }

    #[test]
    fn hvpatch_quantum_borrows_a_fresh_injected_engine_at_every_boundary() {
        #[derive(Default)]
        struct InjectedEngine {
            polls: usize,
        }

        struct SevenBoundaryJob {
            exits: VecDeque<ExecutorExit>,
            observed: Arc<parking_lot::Mutex<Vec<usize>>>,
        }

        impl crate::vcpu_loop::continuation::PersistentQuantumJob for SevenBoundaryJob {
            fn poll_quantum_with_engine(
                &mut self,
                engine: &mut dyn std::any::Any,
                control: &mut HvpatchQuantumControl<'_, '_>,
            ) -> ExecutorExit {
                let engine = engine
                    .downcast_mut::<InjectedEngine>()
                    .expect("exact injected engine type");
                engine.polls += 1;
                self.observed.lock().push(engine.polls);
                assert!(!control.need_resched());
                let _ = control.submission();
                self.exits.pop_front().expect("scripted boundary")
            }
        }

        let boundaries = [
            ExecutorExit::Blocked(BlockedReason::HostWait),
            ExecutorExit::Blocked(BlockedReason::ChildState),
            ExecutorExit::Yielded,
            ExecutorExit::Quiesced,
            ExecutorExit::Preempted,
            ExecutorExit::Yielded,
            ExecutorExit::Exited,
        ];
        let expected_discriminants = boundaries
            .iter()
            .map(std::mem::discriminant)
            .collect::<Vec<_>>();
        let observed = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let completion = crate::vcpu_loop::continuation::LogicalJobCompletion::pending();
        let quantum = crate::vcpu_loop::continuation::HvpatchTaskQuantum::new(
            Box::new(SevenBoundaryJob {
                exits: boundaries.into_iter().collect(),
                observed: Arc::clone(&observed),
            }),
            completion.clone(),
        );
        let (kernel, _) = bootstrap(13_991);
        let scheduler = Scheduler::new(Arc::clone(&kernel));
        let reject_descendant = |_, _| {
            Err(TrapError::Hypervisor(
                "seven-boundary test publishes no descendants".to_owned(),
            ))
        };
        let mut submission = ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &reject_descendant,
            current: None,
            lease: None,
            exec_replacement: None,
        };
        let need_resched = AtomicBool::new(false);
        let mut control = HvpatchQuantumControl {
            need_resched: &need_resched,
            submission: &mut submission,
        };

        for (index, expected) in expected_discriminants.into_iter().enumerate() {
            // This value represents the executor-owned engine after load. It is
            // dropped after every returned boundary, exactly where the real
            // backend's save path detaches its task state from the worker vCPU.
            let mut engine = InjectedEngine::default();
            let actual = quantum.poll_quantum_with_engine(&mut engine, &mut control);
            assert_eq!(std::mem::discriminant(&actual), expected);
            assert_eq!(engine.polls, 1, "boundary {index} reused a retained engine");
        }
        assert_eq!(*observed.lock(), vec![1; 7]);
        quantum.after_terminal_settlement();
        assert!(completion.is_finished());
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

    pub(crate) fn task_state(context: &KernelContext, marker: u64) -> MigratableTaskState {
        task_state_with_continuation(context, marker, None)
    }

    fn task_state_with_continuation(
        context: &KernelContext,
        marker: u64,
        syscall_continuation: Option<Aarch64SyscallContinuationV1>,
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
                syscall_continuation,
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

    pub(crate) fn hvpatch_test_binding(
        context: &KernelContext,
        state: &MigratableTaskState,
        marker: u64,
    ) -> Arc<crate::vcpu_loop::continuation::HvpatchTaskBinding> {
        struct ExitJob;

        impl crate::vcpu_loop::continuation::PersistentQuantumJob for ExitJob {
            fn poll_quantum_with_engine(
                &mut self,
                _engine: &mut dyn std::any::Any,
                _control: &mut HvpatchQuantumControl<'_, '_>,
            ) -> ExecutorExit {
                ExecutorExit::Exited
            }
        }

        assert_eq!(context.shared().mm().id(), state.mm);
        Arc::new(crate::vcpu_loop::continuation::HvpatchTaskBinding::new(
            TaskLoadIdentity {
                abi: state.cpu.guest_abi(),
                version: state.cpu.version(),
                mm: state.mm,
                asid_generation: state.asid_generation,
            },
            Arc::new(crate::vcpu_loop::continuation::HvpatchTaskQuantum::new(
                Box::new(ExitJob),
                crate::vcpu_loop::continuation::LogicalJobCompletion::pending(),
            )),
            Box::new(marker),
        ))
    }

    pub(crate) fn activate_hvpatch_test_submission(
        dormant: super::PreparedHvpatchSubmission,
        scheduler: &Scheduler,
        context: &KernelContext,
        state: &MigratableTaskState,
        generation: ExecutionGeneration,
        binding: &crate::vcpu_loop::continuation::HvpatchTaskBinding,
    ) {
        let start_gate = context
            .thread()
            .take_opened_start_gate(generation)
            .expect("exact opened start gate");
        let proof = HvpatchActivationProof::validate(
            context,
            state,
            generation,
            binding.identity(),
            start_gate,
        )
        .expect("exact activation proof");
        dormant
            .activate(scheduler, Arc::clone(context.thread()), proof)
            .expect("activate exact dormant submission");
    }

    #[test]
    fn dormant_submission_is_invisible_until_exact_activation() {
        let (kernel, context) = bootstrap(13_993);
        let state = task_state(&context, 93);
        let generation = context
            .thread()
            .publish_initial_task_state(state.clone())
            .expect("publish root state");
        let scheduler = Arc::new(Scheduler::new(kernel));
        let directory = Arc::new(HvpatchTaskBindingDirectory::default());
        directory.install_scheduler(&scheduler).unwrap();
        let binding = hvpatch_test_binding(&context, &state, 93);
        let dormant = directory
            .prepare_submission(
                &scheduler,
                HvpatchSubmissionShape::Root,
                None,
                Arc::clone(context.thread()),
                generation,
                Arc::clone(&binding),
            )
            .expect("prepare dormant root");

        assert_eq!(scheduler.queued_len(), 0);
        assert!(
            <HvpatchTaskBindingDirectory as TaskBindingResolver<_>>::resolve(
                directory.as_ref(),
                context.thread().key(),
                generation,
            )
            .is_err()
        );
        activate_hvpatch_test_submission(
            dormant,
            &scheduler,
            &context,
            &state,
            generation,
            binding.as_ref(),
        );
        assert_eq!(scheduler.queued_len(), 1);
        let resolved = <HvpatchTaskBindingDirectory as TaskBindingResolver<_>>::resolve(
            directory.as_ref(),
            context.thread().key(),
            generation,
        )
        .expect("binding visible only after activation");
        assert!(Arc::ptr_eq(&resolved, &binding));
    }

    #[test]
    fn opened_start_gate_is_kernel_minted_only_after_start_and_consumed_once() {
        let (kernel, root) = bootstrap(13_989);
        let published = kernel
            .reserve_fork(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).unwrap(),
                "start-gated".to_owned(),
                None,
            )
            .unwrap()
            .prepare_reference(ThreadId::synthetic_for_tests(23_989))
            .unwrap()
            .commit()
            .unwrap();
        let before_start = published.context().expect("published child context");
        let state = task_state(before_start, 89);
        let generation = before_start
            .thread()
            .publish_initial_task_state(state)
            .unwrap();
        assert!(
            before_start
                .thread()
                .take_opened_start_gate(generation)
                .is_none()
        );

        let started = published.start_child().unwrap();
        assert!(
            started
                .context()
                .thread()
                .take_opened_start_gate(generation)
                .is_some()
        );
        assert!(
            started
                .context()
                .thread()
                .take_opened_start_gate(generation)
                .is_none()
        );
    }

    #[test]
    fn same_task_clone_binding_stays_dormant_until_kernel_gate_opens() {
        let (kernel, root) = bootstrap(13_988);
        let root_state = task_state(&root, 88);
        let root_generation = root
            .thread()
            .publish_initial_task_state(root_state.clone())
            .unwrap();
        let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
        let directory = Arc::new(HvpatchTaskBindingDirectory::default());
        directory.install_scheduler(&scheduler).unwrap();
        let root_binding = hvpatch_test_binding(&root, &root_state, 88);
        let root_submission = directory
            .prepare_submission(
                &scheduler,
                HvpatchSubmissionShape::Root,
                None,
                Arc::clone(root.thread()),
                root_generation,
                Arc::clone(&root_binding),
            )
            .unwrap();
        activate_hvpatch_test_submission(
            root_submission,
            &scheduler,
            &root,
            &root_state,
            root_generation,
            root_binding.as_ref(),
        );
        let root_authority = directory
            .take_submission_authority(root.thread().key(), root_generation)
            .unwrap();

        let published = kernel
            .reserve_thread_clone(
                &root,
                ClonePlan::from_flags(
                    LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
                )
                .unwrap(),
                None,
            )
            .unwrap()
            .prepare(ThreadId::synthetic_for_tests(23_988))
            .unwrap()
            .reserve_publication_eventually()
            .unwrap()
            .commit()
            .unwrap();
        let child = published.context().unwrap().retain_exact();
        let child_state = task_state(&child, 89);
        let child_generation = child
            .thread()
            .publish_initial_task_state(child_state.clone())
            .unwrap();
        let child_binding = hvpatch_test_binding(&child, &child_state, 89);
        let dormant = directory
            .prepare_submission(
                &scheduler,
                HvpatchSubmissionShape::SameTaskSibling {
                    grant: (root.thread().key(), root_generation),
                },
                Some(&root_authority),
                Arc::clone(child.thread()),
                child_generation,
                Arc::clone(&child_binding),
            )
            .unwrap();
        assert_eq!(scheduler.queued_len(), 1);
        assert!(
            directory
                .resolve(child.thread().key(), child_generation)
                .is_err()
        );
        assert!(
            child
                .thread()
                .take_opened_start_gate(child_generation)
                .is_none()
        );

        let started = published.start_thread().unwrap();
        let gate = started
            .context()
            .thread()
            .take_opened_start_gate(child_generation)
            .unwrap();
        let proof = HvpatchActivationProof::validate(
            &child,
            &child_state,
            child_generation,
            child_binding.identity(),
            gate,
        )
        .unwrap();
        dormant
            .activate(&scheduler, Arc::clone(child.thread()), proof)
            .unwrap();
        assert_eq!(scheduler.queued_len(), 2);
        assert!(
            directory
                .resolve(child.thread().key(), child_generation)
                .is_ok()
        );
        directory
            .restore_submission_authority(root_authority)
            .unwrap();
    }

    #[test]
    fn dormant_and_active_clone_directory_retirement_is_exact() {
        #[derive(Clone, Copy, Eq, PartialEq)]
        enum Phase {
            TidCopyout,
            BackendCommit,
            TokenBind,
            RegistryHandle,
            StartProof,
            Activation,
        }
        for (case, phase) in [
            Phase::TidCopyout,
            Phase::BackendCommit,
            Phase::TokenBind,
            Phase::RegistryHandle,
            Phase::StartProof,
            Phase::Activation,
        ]
        .into_iter()
        .enumerate()
        {
            let (kernel, root) = bootstrap(13_980 + case as i32);
            let root_state = task_state(&root, 80 + case as u64);
            let root_generation = root
                .thread()
                .publish_initial_task_state(root_state.clone())
                .unwrap();
            let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
            let directory = Arc::new(HvpatchTaskBindingDirectory::default());
            directory.install_scheduler(&scheduler).unwrap();
            let root_binding = hvpatch_test_binding(&root, &root_state, 80 + case as u64);
            let root_submission = directory
                .prepare_submission(
                    &scheduler,
                    HvpatchSubmissionShape::Root,
                    None,
                    Arc::clone(root.thread()),
                    root_generation,
                    Arc::clone(&root_binding),
                )
                .unwrap();
            activate_hvpatch_test_submission(
                root_submission,
                &scheduler,
                &root,
                &root_state,
                root_generation,
                root_binding.as_ref(),
            );
            let root_authority = directory
                .take_submission_authority(root.thread().key(), root_generation)
                .unwrap();
            let published = kernel
                .reserve_thread_clone(
                    &root,
                    ClonePlan::from_flags(
                        LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
                    )
                    .unwrap(),
                    None,
                )
                .unwrap()
                .prepare(ThreadId::synthetic_for_tests(23_980 + case as i32))
                .unwrap()
                .commit()
                .unwrap();
            let child = published.context().unwrap().retain_exact();
            let child_state = task_state(&child, 90 + case as u64);
            let child_generation = child
                .thread()
                .publish_initial_task_state(child_state.clone())
                .unwrap();
            let has_logical_handle = matches!(
                phase,
                Phase::RegistryHandle | Phase::StartProof | Phase::Activation
            );
            let completion = has_logical_handle
                .then(crate::vcpu_loop::continuation::LogicalJobCompletion::pending);
            let child_binding = hvpatch_test_binding(&child, &child_state, 90 + case as u64);
            let mut dormant = has_logical_handle.then(|| {
                directory
                    .prepare_submission(
                        &scheduler,
                        HvpatchSubmissionShape::SameTaskSibling {
                            grant: (root.thread().key(), root_generation),
                        },
                        Some(&root_authority),
                        Arc::clone(child.thread()),
                        child_generation,
                        Arc::clone(&child_binding),
                    )
                    .unwrap()
            });
            if matches!(phase, Phase::StartProof | Phase::Activation) {
                let started = published.start_thread().unwrap();
                let gate = started
                    .context()
                    .thread()
                    .take_opened_start_gate(child_generation)
                    .unwrap();
                let proof = HvpatchActivationProof::validate(
                    &child,
                    &child_state,
                    child_generation,
                    child_binding.identity(),
                    gate,
                )
                .unwrap();
                if phase == Phase::Activation {
                    dormant
                        .take()
                        .unwrap()
                        .activate(&scheduler, Arc::clone(child.thread()), proof)
                        .unwrap();
                    assert!(
                        directory
                            .resolve(child.thread().key(), child_generation)
                            .is_ok()
                    );
                }
            }
            drop(dormant);
            retire_failed_hvpatch_clone_authority(
                &scheduler,
                &kernel,
                &child,
                child_generation,
                |thread, generation| directory.retire(thread, generation),
            )
            .unwrap();
            if let Some(completion) = &completion {
                assert!(!completion.is_finished());
                completion.publish();
            }
            assert!(completion.as_ref().is_none_or(|value| value.is_finished()));
            assert!(
                directory
                    .resolve(child.thread().key(), child_generation)
                    .is_err()
            );
            assert!(
                kernel
                    .context(root.task().key().id, child.thread().key().tid)
                    .is_err()
            );
            assert_eq!(scheduler.queued_len(), 1);
            directory
                .restore_submission_authority(root_authority)
                .unwrap();
        }
    }

    #[test]
    fn task_only_save_restores_worker_vcpu_before_binding_publication_can_fail() {
        let mut worker_vcpu = None;
        let result = restore_worker_vcpu_before_binding_publication(
            &mut worker_vcpu,
            0xfeed_u64,
            (),
            |(), worker_vcpu| {
                assert_eq!(*worker_vcpu, Some(0xfeed));
                Err(TrapError::Hypervisor(
                    "injected binding publication failure".to_owned(),
                ))
            },
        );
        assert!(result.is_err());
        assert_eq!(worker_vcpu, Some(0xfeed));
    }

    #[test]
    fn clone_failure_retirement_is_scheduler_then_kernel_and_never_silent() {
        let (kernel, root) = bootstrap(13_979);
        let published = kernel
            .reserve_thread_clone(
                &root,
                ClonePlan::from_flags(
                    LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
                )
                .unwrap(),
                None,
            )
            .unwrap()
            .prepare(ThreadId::synthetic_for_tests(23_979))
            .unwrap()
            .commit()
            .unwrap();
        let child = published.context().unwrap().retain_exact();
        let state = task_state(&child, 79);
        let generation = child
            .thread()
            .publish_initial_task_state(state)
            .expect("publish child runnable");
        let scheduler = Scheduler::new(Arc::clone(&kernel));

        retire_failed_hvpatch_clone_authority(&scheduler, &kernel, &child, generation, |_, _| {})
            .expect("exact child retirement");
        assert!(matches!(
            child.thread().execution_state(),
            ThreadExecutionState::Failed { .. }
        ));
        assert!(
            kernel
                .context(child.task().key().id, child.thread().key().tid)
                .is_err()
        );
        assert!(
            retire_failed_hvpatch_clone_authority(
                &scheduler,
                &kernel,
                &child,
                generation,
                |_, _| {},
            )
            .is_err(),
            "a duplicate or stale retirement must remain observable"
        );
    }

    #[test]
    fn dormant_submission_drop_rolls_back_binding_and_queue_authority() {
        let (kernel, context) = bootstrap(13_994);
        let state = task_state(&context, 94);
        let generation = context
            .thread()
            .publish_initial_task_state(state.clone())
            .expect("publish root state");
        let scheduler = Scheduler::new(kernel);
        let directory = Arc::new(HvpatchTaskBindingDirectory::default());
        let binding = hvpatch_test_binding(&context, &state, 94);
        let dormant = directory
            .prepare_submission(
                &scheduler,
                HvpatchSubmissionShape::Root,
                None,
                Arc::clone(context.thread()),
                generation,
                Arc::clone(&binding),
            )
            .expect("prepare dormant root");
        drop(dormant);

        assert_eq!(scheduler.queued_len(), 0);
        assert!(
            <HvpatchTaskBindingDirectory as TaskBindingResolver<_>>::resolve(
                directory.as_ref(),
                context.thread().key(),
                generation,
            )
            .is_err()
        );
        let retry = directory
            .prepare_submission(
                &scheduler,
                HvpatchSubmissionShape::Root,
                None,
                Arc::clone(context.thread()),
                generation,
                binding,
            )
            .expect("rollback releases exact key and authority");
        drop(retry);
        scheduler.close();
        scheduler.wait_closed();
    }

    #[test]
    fn dormant_submission_rejects_duplicate_exact_key() {
        let (kernel, context) = bootstrap(13_995);
        let state = task_state(&context, 95);
        let generation = context
            .thread()
            .publish_initial_task_state(state.clone())
            .expect("publish root state");
        let scheduler = Scheduler::new(kernel);
        let directory = Arc::new(HvpatchTaskBindingDirectory::default());
        let binding = hvpatch_test_binding(&context, &state, 95);
        let first = directory
            .prepare_submission(
                &scheduler,
                HvpatchSubmissionShape::Root,
                None,
                Arc::clone(context.thread()),
                generation,
                Arc::clone(&binding),
            )
            .expect("prepare first exact row");
        assert!(
            directory
                .prepare_submission(
                    &scheduler,
                    HvpatchSubmissionShape::Root,
                    None,
                    Arc::clone(context.thread()),
                    generation,
                    binding,
                )
                .is_err()
        );
        drop(first);
    }

    #[test]
    fn dormant_activation_rejects_a_preexisting_exact_queue_row() {
        let (kernel, context) = bootstrap(13_998);
        let state = task_state(&context, 108);
        let generation = context
            .thread()
            .publish_initial_task_state(state.clone())
            .expect("publish root state");
        let scheduler = Scheduler::new(kernel);
        let directory = Arc::new(HvpatchTaskBindingDirectory::default());
        let binding = hvpatch_test_binding(&context, &state, 108);
        let dormant = directory
            .prepare_submission(
                &scheduler,
                HvpatchSubmissionShape::Root,
                None,
                Arc::clone(context.thread()),
                generation,
                Arc::clone(&binding),
            )
            .expect("prepare dormant root");
        let foreign = scheduler
            .admit_root(context.thread().key(), generation)
            .expect("inject competing exact authority");
        foreign
            .publish(&scheduler, Arc::clone(context.thread()))
            .expect("inject competing queue row");
        let start_gate = context
            .thread()
            .take_opened_start_gate(generation)
            .expect("opened root start gate");
        let proof = HvpatchActivationProof::validate(
            &context,
            &state,
            generation,
            binding.identity(),
            start_gate,
        )
        .unwrap();

        assert!(
            dormant
                .activate(&scheduler, Arc::clone(context.thread()), proof)
                .is_err()
        );
        assert!(
            <HvpatchTaskBindingDirectory as TaskBindingResolver<_>>::resolve(
                directory.as_ref(),
                context.thread().key(),
                generation,
            )
            .is_err()
        );
        assert_eq!(scheduler.queued_len(), 1);
    }

    #[test]
    fn dormant_submission_activates_all_four_exact_authority_shapes() {
        let (kernel, root) = bootstrap(13_996);
        let sibling = sibling(&kernel, &root, 23_996);
        let first_child = process_child(&kernel, &root, 33_996, "first-child");
        let peer_child = process_child(&kernel, &root, 43_996, "peer-child");
        let scheduler = Arc::new(Scheduler::new(kernel));
        let directory = Arc::new(HvpatchTaskBindingDirectory::default());
        directory.install_scheduler(&scheduler).unwrap();

        let root_state = task_state(&root, 96);
        let sibling_state = task_state(&sibling, 97);
        let first_child_state = task_state(&first_child, 98);
        let peer_child_state = task_state(&peer_child, 99);
        let root_generation = root
            .thread()
            .publish_initial_task_state(root_state.clone())
            .unwrap();
        let sibling_generation = sibling
            .thread()
            .publish_initial_task_state(sibling_state.clone())
            .unwrap();
        let first_child_generation = first_child
            .thread()
            .publish_initial_task_state(first_child_state.clone())
            .unwrap();
        let peer_child_generation = peer_child
            .thread()
            .publish_initial_task_state(peer_child_state.clone())
            .unwrap();
        let root_binding = hvpatch_test_binding(&root, &root_state, 96);
        let sibling_binding = hvpatch_test_binding(&sibling, &sibling_state, 97);
        let first_child_binding = hvpatch_test_binding(&first_child, &first_child_state, 98);
        let peer_child_binding = hvpatch_test_binding(&peer_child, &peer_child_state, 99);

        let root_submission = directory
            .prepare_submission(
                &scheduler,
                HvpatchSubmissionShape::Root,
                None,
                Arc::clone(root.thread()),
                root_generation,
                Arc::clone(&root_binding),
            )
            .unwrap();
        activate_hvpatch_test_submission(
            root_submission,
            &scheduler,
            &root,
            &root_state,
            root_generation,
            root_binding.as_ref(),
        );
        let root_grant = (root.thread().key(), root_generation);
        let root_authority = directory
            .take_submission_authority(root_grant.0, root_grant.1)
            .expect("worker holds exact root authority during resident quantum");
        assert!(
            directory
                .prepare_submission(
                    &scheduler,
                    HvpatchSubmissionShape::SameTaskSibling { grant: root_grant },
                    None,
                    Arc::clone(sibling.thread()),
                    sibling_generation,
                    Arc::clone(&sibling_binding),
                )
                .is_err()
        );
        let reject_descendant = |_, _| {
            Err(TrapError::Hypervisor(
                "worker-held grant test publishes no nested descendant".to_owned(),
            ))
        };
        let worker_submission = ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &reject_descendant,
            current: Some(&root_authority),
            lease: None,
            exec_replacement: None,
        };

        let sibling_submission = worker_submission
            .prepare_hvpatch_submission(
                &directory,
                HvpatchSubmissionShape::SameTaskSibling { grant: root_grant },
                Arc::clone(sibling.thread()),
                sibling_generation,
                Arc::clone(&sibling_binding),
            )
            .unwrap();
        activate_hvpatch_test_submission(
            sibling_submission,
            &scheduler,
            &sibling,
            &sibling_state,
            sibling_generation,
            sibling_binding.as_ref(),
        );

        let child_submission = directory
            .prepare_submission(
                &scheduler,
                HvpatchSubmissionShape::Descendant { grant: root_grant },
                Some(&root_authority),
                Arc::clone(first_child.thread()),
                first_child_generation,
                Arc::clone(&first_child_binding),
            )
            .unwrap();
        activate_hvpatch_test_submission(
            child_submission,
            &scheduler,
            &first_child,
            &first_child_state,
            first_child_generation,
            first_child_binding.as_ref(),
        );
        let first_child_authority = directory
            .take_submission_authority(first_child.thread().key(), first_child_generation)
            .expect("worker holds exact child authority during resident quantum");

        let peer_submission = directory
            .prepare_submission(
                &scheduler,
                HvpatchSubmissionShape::PeerRoot {
                    grant: (first_child.thread().key(), first_child_generation),
                },
                Some(&first_child_authority),
                Arc::clone(peer_child.thread()),
                peer_child_generation,
                Arc::clone(&peer_child_binding),
            )
            .unwrap();
        activate_hvpatch_test_submission(
            peer_submission,
            &scheduler,
            &peer_child,
            &peer_child_state,
            peer_child_generation,
            peer_child_binding.as_ref(),
        );

        assert_eq!(scheduler.queued_len(), 4);
        directory
            .restore_submission_authority(root_authority)
            .expect("restore root authority after resident quantum");
        directory
            .restore_submission_authority(first_child_authority)
            .expect("restore child authority after resident quantum");
    }

    #[test]
    fn dormant_submission_rejects_each_wrong_non_root_authority_shape() {
        let (kernel, root) = bootstrap(13_997);
        let root_sibling = sibling(&kernel, &root, 23_997);
        let first_child = process_child(&kernel, &root, 33_997, "first-child");
        let peer_child = process_child(&kernel, &root, 43_997, "peer-child");
        let scheduler = Scheduler::new(Arc::clone(&kernel));
        let directory = Arc::new(HvpatchTaskBindingDirectory::default());
        let root_state = task_state(&root, 100);
        let root_generation = root
            .thread()
            .publish_initial_task_state(root_state.clone())
            .unwrap();
        let root_binding = hvpatch_test_binding(&root, &root_state, 100);
        let root_submission = directory
            .prepare_submission(
                &scheduler,
                HvpatchSubmissionShape::Root,
                None,
                Arc::clone(root.thread()),
                root_generation,
                Arc::clone(&root_binding),
            )
            .unwrap();
        activate_hvpatch_test_submission(
            root_submission,
            &scheduler,
            &root,
            &root_state,
            root_generation,
            root_binding.as_ref(),
        );
        let root_grant = (root.thread().key(), root_generation);
        let root_authority = directory
            .take_submission_authority(root_grant.0, root_grant.1)
            .expect("worker-held root grant");

        let first_child_state = task_state(&first_child, 101);
        let first_child_generation = first_child
            .thread()
            .publish_initial_task_state(first_child_state.clone())
            .unwrap();
        let sibling_state = task_state(&root_sibling, 102);
        let sibling_generation = root_sibling
            .thread()
            .publish_initial_task_state(sibling_state.clone())
            .unwrap();
        assert!(
            directory
                .prepare_submission(
                    &scheduler,
                    HvpatchSubmissionShape::SameTaskSibling { grant: root_grant },
                    Some(&root_authority),
                    Arc::clone(first_child.thread()),
                    first_child_generation,
                    hvpatch_test_binding(&first_child, &first_child_state, 101),
                )
                .is_err()
        );
        for shape in [
            HvpatchSubmissionShape::Descendant { grant: root_grant },
            HvpatchSubmissionShape::PeerRoot { grant: root_grant },
        ] {
            assert!(
                directory
                    .prepare_submission(
                        &scheduler,
                        shape,
                        Some(&root_authority),
                        Arc::clone(root_sibling.thread()),
                        sibling_generation,
                        hvpatch_test_binding(&root_sibling, &sibling_state, 102),
                    )
                    .is_err()
            );
        }

        let first_child_binding = hvpatch_test_binding(&first_child, &first_child_state, 101);
        let first_child_submission = directory
            .prepare_submission(
                &scheduler,
                HvpatchSubmissionShape::Descendant { grant: root_grant },
                Some(&root_authority),
                Arc::clone(first_child.thread()),
                first_child_generation,
                Arc::clone(&first_child_binding),
            )
            .expect("correct descendant shape remains usable after rejection");
        activate_hvpatch_test_submission(
            first_child_submission,
            &scheduler,
            &first_child,
            &first_child_state,
            first_child_generation,
            first_child_binding.as_ref(),
        );
        let first_child_authority = directory
            .take_submission_authority(first_child.thread().key(), first_child_generation)
            .expect("worker-held child grant");

        let child_sibling = sibling(&kernel, &first_child, 53_997);
        let child_sibling_state = task_state(&child_sibling, 106);
        let child_sibling_generation = child_sibling
            .thread()
            .publish_initial_task_state(child_sibling_state.clone())
            .unwrap();
        assert!(
            directory
                .prepare_submission(
                    &scheduler,
                    HvpatchSubmissionShape::Descendant { grant: root_grant },
                    Some(&root_authority),
                    Arc::clone(child_sibling.thread()),
                    child_sibling_generation,
                    hvpatch_test_binding(&child_sibling, &child_sibling_state, 106),
                )
                .is_err()
        );

        let peer_state = task_state(&peer_child, 105);
        let peer_generation = peer_child
            .thread()
            .publish_initial_task_state(peer_state.clone())
            .unwrap();
        assert!(
            directory
                .prepare_submission(
                    &scheduler,
                    HvpatchSubmissionShape::Descendant {
                        grant: (first_child.thread().key(), first_child_generation),
                    },
                    Some(&first_child_authority),
                    Arc::clone(peer_child.thread()),
                    peer_generation,
                    hvpatch_test_binding(&peer_child, &peer_state, 105),
                )
                .is_err()
        );
        let peer_sibling = sibling(&kernel, &peer_child, 63_997);
        let peer_sibling_state = task_state(&peer_sibling, 107);
        let peer_sibling_generation = peer_sibling
            .thread()
            .publish_initial_task_state(peer_sibling_state.clone())
            .unwrap();
        assert!(
            directory
                .prepare_submission(
                    &scheduler,
                    HvpatchSubmissionShape::PeerRoot {
                        grant: (first_child.thread().key(), first_child_generation),
                    },
                    Some(&first_child_authority),
                    Arc::clone(peer_sibling.thread()),
                    peer_sibling_generation,
                    hvpatch_test_binding(&peer_sibling, &peer_sibling_state, 107),
                )
                .is_err()
        );
        directory
            .restore_submission_authority(root_authority)
            .expect("restore root authority");
        directory
            .restore_submission_authority(first_child_authority)
            .expect("restore child authority");
    }

    #[test]
    fn dormant_root_submission_rejects_a_process_child_authority_shape() {
        let (kernel, root) = bootstrap(13_992);
        let child = process_child(&kernel, &root, 23_992, "not-root");
        let state = task_state(&child, 92);
        let generation = child
            .thread()
            .publish_initial_task_state(state.clone())
            .expect("publish child state");
        let scheduler = Scheduler::new(kernel);
        let directory = Arc::new(HvpatchTaskBindingDirectory::default());
        let binding = hvpatch_test_binding(&child, &state, 92);

        assert!(
            directory
                .prepare_submission(
                    &scheduler,
                    HvpatchSubmissionShape::Root,
                    None,
                    Arc::clone(child.thread()),
                    generation,
                    binding,
                )
                .is_err()
        );
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
    fn multi_worker_initial_audit_panic_returns_transactionally_and_destroys_every_created_backend()
    {
        let caller = thread::current().id();
        let (kernel, _) = bootstrap(14_005);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        factory.panic_initial_audit_call.store(2, Ordering::SeqCst);
        let gate = Arc::new(Barrier::new(2));
        *factory.initial_audit_gate.lock() = Some(Arc::clone(&gate));
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let start_factory = Arc::clone(&factory);
        let starter = thread::spawn(move || {
            let result = ExecutorPool::start(
                config(3),
                scheduler,
                Arc::clone(&start_factory),
                start_factory,
                ExecutorBoundaryAudit::production(),
            );
            result_tx
                .send(result.is_err())
                .expect("publish startup result");
        });
        gate.wait();
        assert_eq!(
            result_rx.recv_timeout(Duration::from_secs(1)),
            Ok(true),
            "initial audit panic must not strand startup behind other worker senders"
        );
        starter.join().expect("join pool starter");

        let events = factory.events.lock().clone();
        let creates: Vec<_> = events
            .iter()
            .filter(|event| event.kind == BackendEventKind::Create)
            .collect();
        let destroys: Vec<_> = events
            .iter()
            .filter(|event| event.kind == BackendEventKind::Destroy)
            .collect();
        assert_eq!(creates.len(), 2);
        assert_eq!(destroys.len(), 2);
        assert!(creates.iter().all(|event| event.host_thread != caller));
        for create in creates {
            let destroy = destroys
                .iter()
                .find(|event| event.executor == create.executor)
                .expect("created backend must be destroyed during rollback");
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
    fn hvpatch_binding_rollover_publishes_exact_successor_before_retiring_predecessor() {
        struct ExitJob;
        impl crate::vcpu_loop::continuation::PersistentQuantumJob for ExitJob {
            fn poll_quantum_with_engine(
                &mut self,
                _engine: &mut dyn std::any::Any,
                _control: &mut HvpatchQuantumControl<'_, '_>,
            ) -> ExecutorExit {
                ExecutorExit::Exited
            }
        }

        let (kernel, context) = bootstrap(14_011);
        let first = publish(&context, 11);
        let scheduler = Scheduler::new(kernel);
        let executor = scheduler
            .register_executor(Arc::new(WorkerKick::new(Arc::new(ReceiptLog::default()))))
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        scheduler.settle_runnable(running).unwrap();
        let successor = context.thread().execution_state().generation().unwrap();
        assert_eq!(successor.raw(), first.raw() + 1);

        let completion = crate::vcpu_loop::continuation::LogicalJobCompletion::pending();
        let binding = Arc::new(crate::vcpu_loop::continuation::HvpatchTaskBinding::new(
            TaskLoadIdentity {
                abi: carrick_abi::LinuxGuestAbi::Aarch64,
                version: 1,
                mm: context.shared().mm().id(),
                asid_generation: context.shared().mm().id().raw(),
            },
            Arc::new(crate::vcpu_loop::continuation::HvpatchTaskQuantum::new(
                Box::new(ExitJob),
                completion,
            )),
            Box::new(17_u64),
        ));
        let directory = HvpatchTaskBindingDirectory::default();
        directory
            .publish(context.thread().key(), first, Arc::clone(&binding))
            .unwrap();
        directory
            .rollover_exact(context.thread().key(), first, successor)
            .unwrap();
        assert!(
            <HvpatchTaskBindingDirectory as TaskBindingResolver<_>>::resolve(
                &directory,
                context.thread().key(),
                first,
            )
            .is_err()
        );
        let resolved = <HvpatchTaskBindingDirectory as TaskBindingResolver<_>>::resolve(
            &directory,
            context.thread().key(),
            successor,
        )
        .unwrap();
        assert!(Arc::ptr_eq(&resolved, &binding));
        let successor_running = scheduler.take(&executor).unwrap();
        scheduler.settle_exited(successor_running).unwrap();
        scheduler.unregister_executor(&executor).unwrap();
        scheduler.close();
        scheduler.wait_closed();
    }

    #[test]
    fn shutdown_cancels_dormant_exact_binding_and_completes_once() {
        struct BlockedJob;
        impl crate::vcpu_loop::continuation::PersistentQuantumJob for BlockedJob {
            fn poll_quantum_with_engine(
                &mut self,
                _engine: &mut dyn std::any::Any,
                _control: &mut HvpatchQuantumControl<'_, '_>,
            ) -> ExecutorExit {
                ExecutorExit::Blocked(BlockedReason::HostWait)
            }
        }

        let (kernel, context) = bootstrap(14_014);
        let generation = publish(&context, 14);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let directory = Arc::new(HvpatchTaskBindingDirectory::default());
        directory.install_scheduler(&scheduler).unwrap();
        let completion = crate::vcpu_loop::continuation::LogicalJobCompletion::pending();
        let binding = Arc::new(crate::vcpu_loop::continuation::HvpatchTaskBinding::new(
            TaskLoadIdentity {
                abi: carrick_abi::LinuxGuestAbi::Aarch64,
                version: 1,
                mm: context.shared().mm().id(),
                asid_generation: context.shared().mm().id().raw(),
            },
            Arc::new(crate::vcpu_loop::continuation::HvpatchTaskQuantum::new(
                Box::new(BlockedJob),
                completion.clone(),
            )),
            Box::new(14_u64),
        ));
        directory
            .publish(context.thread().key(), generation, binding)
            .unwrap();
        let authority = scheduler
            .admit_root(context.thread().key(), generation)
            .unwrap();
        directory
            .install_root_authority(&scheduler, Arc::clone(context.thread()), authority)
            .unwrap();

        let executor = scheduler
            .register_executor(Arc::new(WorkerKick::new(Arc::new(ReceiptLog::default()))))
            .unwrap();
        let running = scheduler.take(&executor).unwrap();
        scheduler.close();
        assert_eq!(
            directory
                .cancel_dormant(&scheduler, ExecutionFailure::SnapshotRestoreFailed)
                .unwrap(),
            0,
            "pre-join cancellation may observe the still-running predecessor"
        );
        scheduler
            .settle_blocked(running, BlockedReason::HostWait)
            .unwrap();
        let blocked_generation = context.thread().execution_state().generation().unwrap();
        assert!(!completion.is_finished());
        scheduler.unregister_executor(&executor).unwrap();

        assert_eq!(
            directory
                .cancel_dormant(&scheduler, ExecutionFailure::SnapshotRestoreFailed)
                .unwrap(),
            1
        );
        assert_eq!(
            directory
                .cancel_dormant(&scheduler, ExecutionFailure::SnapshotRestoreFailed)
                .unwrap(),
            0,
            "terminal completion and retirement are exact-once"
        );
        scheduler.wait_closed();
        assert!(completion.is_finished());
        assert!(matches!(
            context.thread().execution_state(),
            ThreadExecutionState::Failed { .. }
        ));
        assert!(
            <HvpatchTaskBindingDirectory as TaskBindingResolver<_>>::resolve(
                directory.as_ref(),
                context.thread().key(),
                blocked_generation,
            )
            .is_err()
        );
    }

    #[test]
    fn exec_replacement_keeps_worker_identity_and_swaps_thread_mm_asid_binding() {
        struct ExitJob;
        impl crate::vcpu_loop::continuation::PersistentQuantumJob for ExitJob {
            fn poll_quantum_with_engine(
                &mut self,
                _engine: &mut dyn std::any::Any,
                _control: &mut HvpatchQuantumControl<'_, '_>,
            ) -> ExecutorExit {
                ExecutorExit::Exited
            }
        }

        let (kernel, context) = bootstrap(14_016);
        let old_mm = context.shared().mm().id();
        let old_generation = publish(&context, 16);
        let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
        let directory = Arc::new(HvpatchTaskBindingDirectory::default());
        directory.install_scheduler(&scheduler).unwrap();
        let completion = crate::vcpu_loop::continuation::LogicalJobCompletion::pending();
        let old_binding = Arc::new(crate::vcpu_loop::continuation::HvpatchTaskBinding::new(
            TaskLoadIdentity {
                abi: carrick_abi::LinuxGuestAbi::Aarch64,
                version: 1,
                mm: old_mm,
                asid_generation: old_mm.raw(),
            },
            Arc::new(crate::vcpu_loop::continuation::HvpatchTaskQuantum::new(
                Box::new(ExitJob),
                completion,
            )),
            Box::new(16_u64),
        ));
        directory
            .publish(
                context.thread().key(),
                old_generation,
                Arc::clone(&old_binding),
            )
            .unwrap();
        let authority = scheduler
            .admit_root(context.thread().key(), old_generation)
            .unwrap();
        directory
            .install_root_authority(&scheduler, Arc::clone(context.thread()), authority)
            .unwrap();
        let worker = Arc::new(WorkerKick::new(Arc::new(ReceiptLog::default())));
        let registration = scheduler.register_executor(worker).unwrap();
        let mut running = scheduler.take(&registration).unwrap();
        let worker_id = running.executor();
        let predecessor_authority = directory
            .take_submission_authority(context.thread().key(), old_generation)
            .expect("running generation authority");

        let prepared = kernel
            .prepare_exec_with_registry_id(&context, ThreadId::synthetic_for_tests(114_016), None)
            .unwrap();
        let old_lease = running.take_lease();
        context.thread().exit_from_executor(old_lease).unwrap();
        let committed = kernel.commit_exec_transition(prepared, None).unwrap();
        let committed_context = committed.context().retain_exact();
        let new_mm = committed_context.shared().mm().id();
        let committed = committed
            .attach_successor_asid_generation(new_mm, new_mm.raw())
            .unwrap();
        assert_ne!(new_mm, old_mm);
        let new_generation = committed_context
            .thread()
            .publish_initial_task_state(task_state(&committed_context, 17))
            .unwrap();
        let new_lease = committed_context
            .thread()
            .claim_runnable(worker_id)
            .unwrap();
        let identity = TaskLoadIdentity {
            abi: carrick_abi::LinuxGuestAbi::Aarch64,
            version: 1,
            mm: new_mm,
            asid_generation: new_mm.raw(),
        };
        let replacement_record = scheduler
            .retarget_running_exec(&mut running, committed, new_lease, |transition| {
                directory
                    .replace_exec(
                        &scheduler,
                        ExecBindingTransition {
                            predecessor_thread: context.thread().key(),
                            predecessor_generation: old_generation,
                            successor_thread: transition.successor_thread,
                            successor_generation: new_generation,
                            identity,
                            replacement_mm: None,
                            authority: Some(predecessor_authority),
                        },
                    )
                    .map_err(|error| error.to_string())
            })
            .unwrap();
        let super::ExecBindingReplacement {
            binding: replacement_binding,
            authority: replacement_authority,
        } = replacement_record;
        directory
            .restore_submission_authority(
                replacement_authority.expect("exec retains exact successor authority"),
            )
            .unwrap();

        assert_eq!(running.executor(), worker_id);
        assert_eq!(running.thread_key(), committed_context.thread().key());
        assert_eq!(running.generation(), new_generation);
        assert_eq!(replacement_binding.identity(), identity);
        assert!(!Arc::ptr_eq(&replacement_binding, &old_binding));
        assert!(
            directory
                .resolve(context.thread().key(), old_generation)
                .is_err()
        );
        assert!(Arc::ptr_eq(
            &directory
                .resolve(committed_context.thread().key(), new_generation)
                .unwrap(),
            &replacement_binding
        ));
        scheduler.settle_exited(running).unwrap();
        scheduler.unregister_executor(&registration).unwrap();
        scheduler.close();
        scheduler.wait_closed();
    }

    #[test]
    fn compute_bound_preemption_reaches_the_exact_live_hardware_kick() {
        #[derive(Clone)]
        struct CountingKick(Arc<AtomicUsize>);
        impl carrick_hal::VcpuKick for CountingKick {
            fn kick(&self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let (kernel, first) = bootstrap(14_012);
        let second = sibling(&kernel, &first, 24_012);
        publish(&first, 12);
        publish(&second, 13);
        let scheduler = Scheduler::new(kernel);
        let worker = Arc::new(WorkerKick::new(Arc::new(ReceiptLog::default())));
        let executor = scheduler.register_executor(worker.clone()).unwrap();
        scheduler.make_runnable(first.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        let kicks = Arc::new(AtomicUsize::new(0));
        let owner = super::current_owner_thread_port();
        let wrong_owner = owner.wrapping_add(1).max(1);
        assert!(
            !worker.publish_hardware(
                super::ExactHardwareKick::new(
                    Box::new(CountingKick(Arc::clone(&kicks))),
                    12,
                    wrong_owner,
                )
                .unwrap()
            )
        );
        assert!(
            worker.publish_hardware(
                super::ExactHardwareKick::new(
                    Box::new(CountingKick(Arc::clone(&kicks))),
                    12,
                    owner,
                )
                .unwrap()
            )
        );
        assert!(
            !worker.publish_hardware(
                super::ExactHardwareKick::new(
                    Box::new(CountingKick(Arc::clone(&kicks))),
                    12,
                    owner,
                )
                .unwrap()
            ),
            "exact hardware identity is publish-once for one loaded binding"
        );
        scheduler.make_runnable(second.thread().key()).unwrap();
        assert_eq!(scheduler.request_preemption(), 1);
        assert_eq!(kicks.load(Ordering::SeqCst), 1);
        scheduler.settle_exited(running).unwrap();
        scheduler.unregister_executor(&executor).unwrap();
    }

    #[test]
    fn terminal_settlement_retires_the_exact_binding_before_worker_destroy() {
        let (kernel, context) = bootstrap(14_013);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        factory.install(&context, FakeBinding::new(13, [Step::Exit]));
        let generation = publish(&context, 13);
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        let authority = enqueue_root(&scheduler, &context, generation);
        drop(authority);
        let report = pool.shutdown().expect("terminal settlement");
        assert_eq!(
            factory.retired_bindings.lock().as_slice(),
            &[(context.thread().key(), generation)]
        );
        let events = factory.events.lock();
        let destroy = events
            .iter()
            .position(|event| event.kind == BackendEventKind::Destroy)
            .expect("worker destroy");
        assert!(
            events[..destroy]
                .iter()
                .any(|event| event.kind == BackendEventKind::Save),
            "terminal binding retirement follows detach/save and precedes worker destroy"
        );
        assert_eq!(report.created(), report.destroyed());
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
    fn rebind_in_delivery_validation_to_mutation_window_cannot_flag_or_receipt_successor() {
        let (kernel, context) = bootstrap(14_035);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let receipts = Arc::new(ReceiptLog::default());
        let kick = Arc::new(WorkerKick::new(Arc::clone(&receipts)));
        let registration = scheduler
            .register_executor(Arc::clone(&kick) as Arc<dyn crate::kernel::ExecutorKick>)
            .expect("register exact worker kick");
        let authority = enqueue_root(&scheduler, &context, publish(&context, 55));
        drop(authority);
        let running = scheduler
            .take(&registration)
            .expect("claim first generation");
        let stale_generation = running.generation();
        let gate = Arc::new(Barrier::new(2));
        kick.install_delivery_validation_gate(Arc::clone(&gate));
        let receipt_gate = Arc::new(Barrier::new(2));
        kick.install_delivery_receipt_gate(Arc::clone(&receipt_gate));

        let wake_scheduler = Arc::clone(&scheduler);
        let thread_key = context.thread().key();
        let delivery = thread::spawn(move || wake_scheduler.wake(thread_key));
        gate.wait();

        let (successor_tx, successor_rx) = std::sync::mpsc::channel();
        let (settlement_probe_tx, settlement_probe_rx) = std::sync::mpsc::channel();
        let successor_attempt = Arc::new(Barrier::new(2));
        let successor_attempt_thread = Arc::clone(&successor_attempt);
        let settle_scheduler = Arc::clone(&scheduler);
        let settle_registration = registration.clone();
        let settle_receipts = Arc::clone(&receipts);
        let settle_kick = Arc::clone(&kick);
        let settlement = thread::spawn(move || {
            settlement_probe_tx
                .send(settle_kick.binding.try_lock().is_none())
                .expect("publish settlement-thread lock probe");
            successor_attempt_thread.wait();
            settle_scheduler
                .settle_runnable(running)
                .expect("unbind and publish successor");
            let successor = settle_scheduler
                .take(&settle_registration)
                .expect("bind exact successor generation");
            settle_receipts.record(
                successor.executor(),
                ExecutorPoolEvent::Loaded {
                    thread: successor.thread_key(),
                    generation: successor.generation(),
                },
            );
            let successor_generation = successor.generation();
            let successor_executor = successor.executor();
            let successor_thread = successor.thread_key();
            settle_scheduler
                .settle_exited(successor)
                .expect("settle exact successor generation");
            settle_receipts.record(
                successor_executor,
                ExecutorPoolEvent::SettledExited {
                    thread: successor_thread,
                    generation: successor_generation,
                },
            );
            successor_tx
                .send(successor_generation)
                .expect("publish exact successor generation");
        });
        assert!(
            settlement_probe_rx
                .recv()
                .expect("receive settlement-thread lock probe"),
            "the actual settlement thread must observe WouldBlock on the held validation lock"
        );
        gate.wait();
        receipt_gate.wait();
        let receipt_lock_held = kick.binding.try_lock().is_none();
        successor_attempt.wait();
        let early_successor = if receipt_lock_held {
            receipt_gate.wait();
            None
        } else {
            let successor = successor_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("old implementation permits successor before stale kick receipt");
            receipt_gate.wait();
            Some(successor)
        };
        let disposition = delivery.join().expect("join delayed delivery").unwrap();
        let successor_generation = early_successor.unwrap_or_else(|| {
            successor_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("successor claim after exact delivery mutation")
        });
        settlement.join().expect("join successor settlement");

        assert!(
            receipt_lock_held,
            "causal kick receipt must publish while the exact binding lock is retained"
        );
        assert_eq!(disposition, crate::kernel::WakeDisposition::Kicked);
        assert_ne!(successor_generation, stale_generation);
        assert!(!kick.need_resched.load(Ordering::Acquire));
        let events = receipts.snapshot();
        let old_kick = events
            .iter()
            .position(|receipt| {
                matches!(
                    receipt.event,
                    ExecutorPoolEvent::KickDelivered { generation, .. }
                        if generation == stale_generation
                )
            })
            .expect("old exact kick receipt");
        let successor_loaded = events
            .iter()
            .position(|receipt| {
                matches!(
                    receipt.event,
                    ExecutorPoolEvent::Loaded { generation, .. }
                        if generation == successor_generation
                )
            })
            .expect("successor load receipt");
        let successor_settled = events
            .iter()
            .position(|receipt| {
                matches!(
                    receipt.event,
                    ExecutorPoolEvent::SettledExited { generation, .. }
                        if generation == successor_generation
                )
            })
            .expect("successor settlement receipt");
        assert!(old_kick < successor_loaded);
        assert!(old_kick < successor_settled);
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
    fn pool_drives_owned_blocked_continuation_into_kernel_state() {
        use crate::vcpu_loop::continuation::{
            BlockedContinuation, ContinuationBackend, ContinuationCapture, RestartClass,
        };

        let (kernel, blocked) = bootstrap(14_045);
        let runnable = sibling(&kernel, &blocked, 24_045);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        let blocked_generation = publish(&blocked, 61);
        let continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnSleep {
                duration: Duration::from_secs(30),
                remaining: None,
            },
            ContinuationCapture::new(
                &blocked,
                blocked_generation,
                SyscallRequest::new(101, SyscallArgs([0; 6])),
                RestartClass::Never,
                ContinuationBackend::Hvpatch,
            )
            .expect("capture continuation"),
        )
        .expect("owned continuation");
        let continuation_id = continuation.id();
        let blocked_binding = FakeBinding::new(61, [Step::Block]);
        blocked_binding.block_with_continuation(continuation);
        factory.install(&blocked, blocked_binding);
        factory.install(&runnable, FakeBinding::new(71, [Step::Exit]));
        let runnable_generation = publish(&runnable, 71);
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        let blocked_authority = enqueue_root(&scheduler, &blocked, blocked_generation);
        let runnable_authority = enqueue_root(&scheduler, &runnable, runnable_generation);
        drop((blocked_authority, runnable_authority));
        pool.shutdown().expect("clean shutdown");

        assert!(matches!(
            blocked.thread().execution_state(),
            ThreadExecutionState::Blocked {
                continuation: Some(actual),
                ..
            } if actual == continuation_id
        ));
        assert!(
            scheduler
                .binding_for_thread(blocked.thread().key())
                .is_none()
        );
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
            assert_eq!(report.report().created(), 1, "{case}");
            assert_eq!(report.report().destroyed(), 1, "{case}");
            let events = factory.events.lock();
            let create = events
                .iter()
                .find(|event| event.kind == BackendEventKind::Create)
                .expect("failed phase still creates one owner backend");
            let destroy = events
                .iter()
                .find(|event| event.kind == BackendEventKind::Destroy)
                .expect("failed phase destroys the owner backend");
            assert_eq!(create.host_thread, destroy.host_thread, "{case}");
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
            assert_eq!(report.report().created(), 1, "{case}");
            assert_eq!(report.report().destroyed(), 1, "{case}");
            let events = factory.events.lock();
            let create = events
                .iter()
                .find(|event| event.kind == BackendEventKind::Create)
                .expect("failed phase still creates one owner backend");
            let destroy = events
                .iter()
                .find(|event| event.kind == BackendEventKind::Destroy)
                .expect("failed phase destroys the owner backend");
            assert_eq!(create.host_thread, destroy.host_thread, "{case}");
            assert!(matches!(
                context.thread().execution_state(),
                ThreadExecutionState::Failed { .. }
            ));
        }
    }

    #[test]
    fn last_worker_failure_fails_queued_exact_generation_and_shutdown_returns() {
        let (kernel, first) = bootstrap(14_240);
        let second = sibling(&kernel, &first, 24_240);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        let run_gate = Arc::new(Barrier::new(2));
        let first_binding = FakeBinding::new(91, [Step::FailRun]);
        *first_binding.entered.lock() = Some(Arc::clone(&run_gate));
        factory.install(&first, first_binding);
        factory.install(&second, FakeBinding::new(92, [Step::Exit]));
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        let first_generation = publish(&first, 91);
        let second_generation = publish(&second, 92);
        let first_authority = enqueue_root(&scheduler, &first, first_generation);
        let second_authority = enqueue_root(&scheduler, &second, second_generation);
        run_gate.wait();
        drop((first_authority, second_authority));

        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
        let shutdown = thread::spawn(move || {
            shutdown_tx
                .send(pool.shutdown())
                .expect("publish shutdown result");
        });
        let result = shutdown_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("last-worker failure must not strand queued generations");
        let error = result.expect_err("backend failure remains reported");
        shutdown.join().expect("join shutdown observer");

        assert!(matches!(
            first.thread().execution_state(),
            ThreadExecutionState::Failed { .. }
        ));
        assert!(matches!(
            second.thread().execution_state(),
            ThreadExecutionState::Failed { .. }
        ));
        assert_eq!(error.report().created(), 1);
        assert_eq!(error.report().destroyed(), 1);
        assert_eq!(error.report().joined(), 1);
        let mut retired = factory.retired_bindings.lock().clone();
        retired.sort();
        let mut expected = vec![
            (first.thread().key(), first_generation),
            (second.thread().key(), second_generation),
        ];
        expected.sort();
        assert_eq!(
            retired, expected,
            "queued terminal drain retires both exact rows"
        );
    }

    #[test]
    fn malicious_backend_retained_binding_cannot_receive_authority_or_hold_terminal_drain_open() {
        let (kernel, first) = bootstrap(14_242);
        let second = sibling(&kernel, &first, 24_242);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(MaliciousFactory::default());
        let entered = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        factory.install(&first, Arc::clone(&entered), Arc::clone(&resume));
        factory.install(
            &second,
            Arc::new(Barrier::new(1)),
            Arc::new(Barrier::new(1)),
        );
        let first_generation = publish(&first, 92);
        let second_generation = publish(&second, 93);
        let pool = ExecutorPool::start(
            config(1),
            Arc::clone(&scheduler),
            Arc::clone(&factory),
            factory,
            ExecutorBoundaryAudit::production(),
        )
        .expect("start malicious-binding pool");
        pool.submit_root(Arc::clone(first.thread()), first_generation)
            .expect("pool owns first root authority");
        entered.wait();
        pool.submit_root(Arc::clone(second.thread()), second_generation)
            .expect("pool owns queued second-root authority before failure");
        resume.wait();

        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
        let shutdown = thread::spawn(move || {
            shutdown_tx
                .send(pool.shutdown())
                .expect("publish retained-authority shutdown result");
        });
        let result = shutdown_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("failure cleanup must revoke its exact authority before terminal drain");
        let error = result.expect_err("backend failure remains reported");
        shutdown.join().expect("join retained-authority shutdown");

        assert!(matches!(
            first.thread().execution_state(),
            ThreadExecutionState::Failed { .. }
        ));
        assert!(matches!(
            second.thread().execution_state(),
            ThreadExecutionState::Failed { .. }
        ));
        assert_eq!(error.report().created(), 1);
        assert_eq!(error.report().destroyed(), 1);
        assert_eq!(error.report().joined(), 1);
    }

    #[test]
    fn run_error_and_panic_charge_exact_cpu_receipt_once_before_failure() {
        for (offset, step) in [Step::FailRun, Step::PanicRun].into_iter().enumerate() {
            let (kernel, context) = bootstrap(14_245 + i32::try_from(offset).unwrap());
            let scheduler = Arc::new(Scheduler::new(kernel));
            let factory = Arc::new(FakeFactory::default());
            factory.install(&context, FakeBinding::new(93, [step]));
            let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
            let authority = enqueue_root(&scheduler, &context, publish(&context, 93));
            drop(authority);
            pool.shutdown()
                .expect_err("failed run must retire and report worker");

            assert_eq!(context.thread().cpu_us(), 7);
            assert_eq!(context.thread().system_cpu_us(), 3);
            assert!(matches!(
                context.thread().execution_state(),
                ThreadExecutionState::Failed { .. }
            ));
        }
    }

    #[test]
    fn missing_scoped_lease_return_fails_and_retires_exact_claim() {
        let (kernel, context) = bootstrap(14_247);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        factory.install(&context, FakeBinding::new(95, [Step::LoseLease]));
        let generation = publish(&context, 95);
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        let authority = enqueue_root(&scheduler, &context, generation);
        drop(authority);

        pool.shutdown()
            .expect_err("missing scoped lease return must retire worker");
        assert!(matches!(
            context.thread().execution_state(),
            ThreadExecutionState::Failed { .. }
        ));
        assert_eq!(
            factory.retired_bindings.lock().as_slice(),
            &[(context.thread().key(), generation)]
        );
    }

    #[test]
    fn missing_exact_hardware_identity_fails_and_retires_loaded_claim() {
        let (kernel, context) = bootstrap(14_248);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        factory.fail_hardware_kick.store(true, Ordering::SeqCst);
        factory.install(&context, FakeBinding::new(96, [Step::Exit]));
        let generation = publish(&context, 96);
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        let authority = enqueue_root(&scheduler, &context, generation);
        drop(authority);

        pool.shutdown()
            .expect_err("missing exact hardware identity must retire worker");
        assert!(matches!(
            context.thread().execution_state(),
            ThreadExecutionState::Failed { .. }
        ));
        assert_eq!(
            factory.retired_bindings.lock().as_slice(),
            &[(context.thread().key(), generation)]
        );
    }

    #[test]
    fn invalid_migration_authority_and_invalidation_failure_never_load_or_run_backend() {
        fn reject_case(
            pid: i32,
            continuation: Option<Aarch64SyscallContinuationV1>,
            configure: impl FnOnce(&Arc<Kernel>, &KernelContext, &Arc<FakeBinding>, &Arc<FakeFactory>),
        ) {
            let (kernel, context) = bootstrap(pid);
            let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
            let factory = Arc::new(FakeFactory::default());
            let binding = FakeBinding::new(94, [Step::Exit]);
            factory.install(&context, Arc::clone(&binding));
            configure(&kernel, &context, &binding, &factory);
            let generation = context
                .thread()
                .publish_initial_task_state(task_state_with_continuation(
                    &context,
                    94,
                    continuation,
                ))
                .expect("publish migration test state");
            let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
            let authority = enqueue_root(&scheduler, &context, generation);
            drop(authority);
            let error = pool
                .shutdown()
                .expect_err("invalid migration authority must retire worker");

            assert_eq!(error.retired_workers(), 1);
            assert!(matches!(
                context.thread().execution_state(),
                ThreadExecutionState::Failed { .. }
            ));
            assert!(!factory.events.lock().iter().any(|event| {
                matches!(
                    event.kind,
                    BackendEventKind::Invalidate | BackendEventKind::Load | BackendEventKind::Run
                )
            }));
            assert!(factory.inherited_state.lock().is_empty());
            assert!(factory.concurrent_loads.lock().is_empty());
        }

        reject_case(14_247, None, |_kernel, _context, binding, _factory| {
            binding.override_expected_abi(carrick_abi::LinuxGuestAbi::X86_64);
        });
        reject_case(14_248, None, |_kernel, _context, binding, _factory| {
            binding.override_expected_version(2);
        });
        reject_case(14_249, None, |kernel, context, binding, _factory| {
            let other = process_child(kernel, context, 24_249, "stale-mm");
            binding.override_expected_mm(other.shared().mm().id());
        });
        reject_case(14_250, None, |_kernel, _context, binding, _factory| {
            binding.override_expected_asid_generation(u64::MAX - 1);
        });
        reject_case(14_251, None, |_kernel, _context, binding, _factory| {
            binding.require_continuation_sequence(7);
        });
        reject_case(
            14_252,
            Some(Aarch64SyscallContinuationV1 {
                sequence: 0,
                state: 0,
                trap_kind: 0,
                response_action: 0,
                flags: 0,
                native_nr: 0,
                args: [0; 6],
                x8: 0,
                resume_pc: 0,
                spsr: 0,
                fp: 0,
                lr: 0,
                sp: 0,
                esr: 0,
                return_value: 0,
                resume_x16: 0,
                resume_x17: 0,
            }),
            |_kernel, _context, binding, _factory| {
                binding.require_continuation_sequence(7);
            },
        );
    }

    #[test]
    fn retirement_command_invalidates_on_exact_resident_owner_worker_only() {
        let (process, context) = crate::hvpatch::process_context_for_tests(14_254);
        let scheduler = Arc::new(Scheduler::new(Arc::clone(context.kernel())));
        let factory = Arc::new(FakeFactory::default());
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        let executor = pool.executor_ids()[0];
        let lease = process.stage1_mm_lease().expect("exact MM lease");
        lease
            .begin_asid_load(executor)
            .expect("load admission")
            .mark_resident()
            .expect("resident executor");
        let retired = process
            .mm_resources()
            .retire(process.task_key())
            .expect("retire process MM");
        let retirement = retired
            .retirement()
            .expect("last MM owner retirement authority");

        pool.invalidate_asid_retirement(retirement)
            .expect("owner-thread invalidation and exact ack");

        assert!(retirement.pending().is_empty());
        let invalidations = factory
            .events
            .lock()
            .iter()
            .filter(|event| event.kind == BackendEventKind::Invalidate)
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(invalidations.len(), 1);
        assert_eq!(invalidations[0].executor, executor);
        assert_ne!(invalidations[0].host_thread, thread::current().id());
        process
            .mm_resources()
            .acknowledge_tlb_flush(retired)
            .expect("release exact ASID/root only after all acks");
        pool.shutdown().expect("pool shutdown");
    }

    #[test]
    fn failed_owner_thread_invalidation_retires_worker_and_quarantines_generation() {
        let (process, context) = crate::hvpatch::process_context_for_tests(14_256);
        let scheduler = Arc::new(Scheduler::new(Arc::clone(context.kernel())));
        let factory = Arc::new(FakeFactory::default());
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        let executor = pool.executor_ids()[0];
        let lease = process.stage1_mm_lease().expect("exact MM lease");
        lease
            .begin_asid_load(executor)
            .expect("load admission")
            .mark_resident()
            .expect("resident executor");
        factory
            .fail_invalidation_generation
            .store(lease.asid_generation().generation(), Ordering::SeqCst);
        let retired = process
            .mm_resources()
            .retire(process.task_key())
            .expect("retire process MM");
        let retirement = retired
            .retirement()
            .expect("last MM owner retirement authority");

        assert!(pool.invalidate_asid_retirement(retirement).is_err());
        assert_eq!(retirement.pending(), vec![executor]);
        assert!(
            process
                .mm_resources()
                .acknowledge_tlb_flush(retired)
                .unwrap_err()
                .to_string()
                .contains("awaits executor invalidation")
        );
        assert!(pool.shutdown().is_err());
    }

    #[test]
    fn ordinary_task_load_never_performs_an_asid_invalidation() {
        let (kernel, context) = bootstrap(14_255);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        factory.install(&context, FakeBinding::new(97, [Step::Exit]));
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        let authority = enqueue_root(&scheduler, &context, publish(&context, 97));
        drop(authority);

        pool.shutdown().expect("pool shutdown");

        assert!(
            !factory
                .events
                .lock()
                .iter()
                .any(|event| event.kind == BackendEventKind::Invalidate)
        );
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
    fn authority_rolls_across_yield_and_preempt_before_normal_descendant_publication() {
        let (kernel, root) = bootstrap(14_290);
        let child = process_child(&kernel, &root, 24_290, "child");
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        let root_binding =
            FakeBinding::new(98, [Step::Yield, Step::Preempt, Step::Yield, Step::Exit]);
        let child_binding = FakeBinding::new(99, [Step::Exit]);
        factory.install(&root, Arc::clone(&root_binding));
        factory.install(&child, child_binding);
        let root_generation = publish(&root, 98);
        let child_generation = publish(&child, 99);
        let (published_tx, published_rx) = std::sync::mpsc::channel();
        *root_binding.descendant.lock() = Some(DescendantPublication {
            child_thread: Arc::clone(child.thread()),
            child_generation,
            after_progress: 4,
            published: Some(published_tx),
        });
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        pool.submit_root(Arc::clone(root.thread()), root_generation)
            .expect("pool-owned root publication");
        published_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("descendant publication after three authority rollovers");
        let report = pool.shutdown().expect("normal descendant drain");

        assert!(matches!(
            root.thread().execution_state(),
            ThreadExecutionState::Exited { .. }
        ));
        assert!(matches!(
            child.thread().execution_state(),
            ThreadExecutionState::Exited { .. }
        ));
        assert_eq!(report.created(), 1);
        assert_eq!(report.destroyed(), 1);
        assert_eq!(report.joined(), 1);
    }

    #[test]
    fn shutdown_drains_recursive_child_and_grandchild_before_destroy_and_join() {
        let (kernel, root) = bootstrap(14_300);
        let child = process_child(&kernel, &root, 24_300, "child");
        let grandchild = process_child(&kernel, &child, 34_300, "grandchild");
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        let root_binding =
            FakeBinding::new(100, [Step::Yield, Step::Preempt, Step::Yield, Step::Exit]);
        let root_entered = Arc::new(Barrier::new(2));
        let root_resume = Arc::new(Barrier::new(2));
        *root_binding.entered.lock() = Some(Arc::clone(&root_entered));
        *root_binding.resume.lock() = Some(Arc::clone(&root_resume));
        let child_binding = FakeBinding::new(110, [Step::Yield, Step::Preempt, Step::Exit]);
        let grandchild_binding = FakeBinding::new(120, [Step::Exit]);
        factory.install(&root, Arc::clone(&root_binding));
        factory.install(&child, Arc::clone(&child_binding));
        factory.install(&grandchild, Arc::clone(&grandchild_binding));
        let root_generation = publish(&root, 100);
        let child_generation = publish(&child, 110);
        let grandchild_generation = publish(&grandchild, 120);
        *root_binding.descendant.lock() = Some(DescendantPublication {
            child_thread: Arc::clone(child.thread()),
            child_generation,
            after_progress: 4,
            published: None,
        });
        *child_binding.descendant.lock() = Some(DescendantPublication {
            child_thread: Arc::clone(grandchild.thread()),
            child_generation: grandchild_generation,
            after_progress: 3,
            published: None,
        });
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        pool.submit_root(Arc::clone(root.thread()), root_generation)
            .expect("pool retains root authority before publication");
        root_entered.wait();
        let close_started = Arc::new(Barrier::new(2));
        scheduler.install_close_started_gate(Arc::clone(&close_started));
        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
        let shutdown = thread::spawn(move || {
            shutdown_tx
                .send(pool.shutdown())
                .expect("publish recursive shutdown result");
        });
        close_started.wait();
        root_resume.wait();
        let report = shutdown_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("recursive Closing drain result")
            .expect("recursive drain");
        shutdown.join().expect("join recursive shutdown");
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
            "logical-mq-wait-state",
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
        assert!(
            inventory
                .iter()
                .all(|entry| entry.name != "sysv-mq-wait-cache"
                    && entry.name != "sysv-mq-blocked-ids"),
            "SysV wait-word and blocked-id state belongs to the continuation, not executor TLS"
        );

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
    fn real_owner_boundary_state_fails_or_resets_and_successor_observes_clean_state() {
        let (kernel, context) = bootstrap(14_550);
        let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
        let receipts = Arc::new(ReceiptLog::default());
        let kick = Arc::new(WorkerKick::new(Arc::clone(&receipts)));
        let registration = scheduler
            .register_executor(Arc::clone(&kick) as Arc<dyn crate::kernel::ExecutorKick>)
            .expect("register audit executor");
        let mut backend = BoundaryAuditProbe;
        let boundary = WorkerBoundaryAudit::capture().expect("capture host signal mask baseline");

        let topology = carrick_thread::fork_quiesce::acquire_topology_lock(
            carrick_observability::probes::HvpatchTopologyOperation::AliasMap,
            1,
            1,
        );
        assert!(boundary.audit_runtime(&mut backend).is_err());
        drop(topology);
        boundary
            .audit_runtime(&mut backend)
            .expect("topology unwound");

        let lock = crate::dispatch::lock_order::LockOrderGuard::acquire(
            crate::dispatch::lock_order::LockLevel::Proc,
        );
        assert!(boundary.audit_runtime(&mut backend).is_err());
        drop(lock);
        boundary
            .audit_runtime(&mut backend)
            .expect("lock order unwound");

        SyscallDispatcher::with_dirty_executor_boundary_path_resolution_for_test(|| {
            assert!(boundary.audit_runtime(&mut backend).is_err());
        });
        boundary
            .audit_runtime(&mut backend)
            .expect("path depth unwound");

        crate::dispatch::resources::with_dirty_captured_resources_for_executor_test(
            &context,
            || assert!(boundary.audit_runtime(&mut backend).is_err()),
        );
        boundary
            .audit_runtime(&mut backend)
            .expect("active/captured resources unwound");
        crate::dispatch::resources::with_dirty_retiring_resources_for_executor_test(
            context.resources().files(),
            || assert!(boundary.audit_runtime(&mut backend).is_err()),
        );
        boundary
            .audit_runtime(&mut backend)
            .expect("retiring resources unwound");

        let fanotify = crate::fanotify::InternalOpenGuard::enter();
        assert!(boundary.audit_runtime(&mut backend).is_err());
        drop(fanotify);
        boundary
            .audit_runtime(&mut backend)
            .expect("fanotify unwound");

        crate::vcpu_loop::signal::note_signal_progress();
        assert_ne!(crate::vcpu_loop::signal::signal_progress_count(), 0);
        boundary
            .audit_runtime(&mut backend)
            .expect("signal progress is resettable executor state");
        assert_eq!(crate::vcpu_loop::signal::signal_progress_count(), 0);

        struct RestoreSignalMask(libc::sigset_t);
        impl Drop for RestoreSignalMask {
            fn drop(&mut self) {
                let result = unsafe {
                    libc::pthread_sigmask(libc::SIG_SETMASK, &self.0, std::ptr::null_mut())
                };
                assert_eq!(result, 0);
            }
        }
        let mut blocked = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        let mut previous = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        assert_eq!(unsafe { libc::sigemptyset(&mut blocked) }, 0);
        assert_eq!(unsafe { libc::sigaddset(&mut blocked, libc::SIGUSR1) }, 0);
        assert_eq!(
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous) },
            0
        );
        let restore = RestoreSignalMask(previous);
        assert!(boundary.audit_runtime(&mut backend).is_err());
        drop(restore);
        boundary
            .audit_runtime(&mut backend)
            .expect("host signal mask restored");

        let (cached_fd, wait_word_fd) =
            SyscallDispatcher::dirty_sysv_executor_boundary_state_for_test();
        boundary
            .audit_runtime(&mut backend)
            .expect("SysV host-fd cache is resettable executor state");
        assert_eq!(unsafe { libc::fcntl(cached_fd, libc::F_GETFD) }, -1);
        assert_eq!(unsafe { libc::fcntl(wait_word_fd, libc::F_GETFD) }, -1);
        assert!(SyscallDispatcher::sysv_executor_boundary_state_is_clear_for_test());
        boundary
            .audit_runtime(&mut backend)
            .expect("SysV reset leaves successor clean");

        let generation = publish(&context, 155);
        let authority = enqueue_root(&scheduler, &context, generation);
        drop(authority);
        let running = scheduler
            .take(&registration)
            .expect("bind exact kick state");
        assert!(boundary.audit_clean(&mut backend, &kick).is_err());
        scheduler
            .settle_exited(running)
            .expect("clear exact kick binding");
        boundary
            .audit_clean(&mut backend, &kick)
            .expect("successor observes no kick identity");

        drop(backend);
        scheduler
            .unregister_executor(&registration)
            .expect("unregister audit executor");
    }

    #[test]
    fn prohibited_real_owner_state_retires_worker_and_cleanup_leaves_no_inherited_state() {
        for mode in 1..=6 {
            let (kernel, context) = bootstrap(14_560 + mode as i32);
            let scheduler = Arc::new(Scheduler::new(kernel));
            let factory = Arc::new(FakeFactory::default());
            factory.owner_dirty_mode.store(mode, Ordering::SeqCst);
            factory.install(&context, FakeBinding::new(156, [Step::Yield]));
            let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
            let authority = enqueue_root(&scheduler, &context, publish(&context, 156));
            drop(authority);
            let error = pool
                .shutdown()
                .expect_err("dirty real owner state must retire worker");

            assert_eq!(error.retired_workers(), 1, "dirty owner mode {mode}");
            assert!(matches!(
                context.thread().execution_state(),
                ThreadExecutionState::Failed { .. }
            ));
            assert_eq!(error.report().created(), 1);
            assert_eq!(error.report().destroyed(), 1);
            assert_eq!(error.report().joined(), 1);
            for (cached_fd, wait_word_fd) in factory.owner_dirty_fds.lock().iter().copied() {
                assert_eq!(unsafe { libc::fcntl(cached_fd, libc::F_GETFD) }, -1);
                assert_eq!(unsafe { libc::fcntl(wait_word_fd, libc::F_GETFD) }, -1);
            }
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
