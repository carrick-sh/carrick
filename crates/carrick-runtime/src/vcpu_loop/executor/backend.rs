//! Persistent executor backend abstractions and HVPatch hardware executor implementation.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use carrick_fatal::carrick_fatal;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use carrick_hal::ThreadedEngine as _;

use crate::kernel::objects::{
    ExecutionFailure, ExecutionGeneration, ExecutorId, MigratableTaskState, ThreadExecutionLease,
    ThreadKey,
};
use crate::kernel::{Scheduler, SchedulerError};
use crate::trap::TrapError;
use crate::vcpu_loop::executor::binding::{
    ExecutorSubmissionContext, HvpatchQuantumControl, PersistentTaskBinding,
};
use crate::vcpu_loop::executor::settlement::{
    ExecutorCpuReceipt, ExecutorExit, ExecutorSaveError, RunnableTask, SavedRunnable,
};

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
    cow_invalidation_observer: Option<crate::hvpatch::CowInvalidationObserver>,
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
    pub(crate) fn preflight_runtime_projection(
        &self,
        cpu: &carrick_hal::threaded::GuestCpuState,
    ) -> Result<(), TrapError> {
        match &self.payload {
            HvpatchTaskEngineBindingPayload::TaskOnly(state) => {
                state.preflight_runtime_projection(cpu)
            }
            HvpatchTaskEngineBindingPayload::Resident(_) => Ok(()),
            #[cfg(test)]
            HvpatchTaskEngineBindingPayload::Test => Ok(()),
        }
    }

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

    /// Retire the detached address space AND publish its inventory retirement.
    ///
    /// The two payloads differ in what owns the retirement, not in policy. A
    /// task-only backend was published through the carrier directory and owns a
    /// `HvpatchTaskMmAuthority` whose phase must advance `Active -> Retired`
    /// through its authenticated receipt; dropping that authority while it is
    /// still `Active` aborts the carrier, which is what every forked process
    /// used to do. The initial resident engine has no such published authority,
    /// so its commit is applied directly.
    pub(crate) fn retire_detached_address_space_with(
        &mut self,
        root_ticket: Option<crate::hvpatch::Stage1RootRetirementTicket>,
        apply_with_receipt: impl FnOnce(
            carrick_hal::FrameInventoryCommit<()>,
        ) -> Result<
            carrick_hal::FrameInventoryRetirementReceipt,
            TrapError,
        >,
        apply_commit: impl FnOnce(carrick_hal::FrameInventoryCommit<()>) -> Result<(), TrapError>,
    ) -> Result<Option<crate::hvpatch::Stage1RootRetirementReceipt>, TrapError> {
        match &mut self.payload {
            HvpatchTaskEngineBindingPayload::Resident(state) => {
                let (commit, root_receipt) = match root_ticket {
                    Some(ticket) => {
                        let (commit, proof) = carrick_vmm_hvf::hvf_aarch64_engine::retire_detached_task_engine_with_root_proof(
                            state,
                            ticket.base(),
                            ticket.size(),
                        )?;
                        let receipt = ticket.redeem_vmm(proof).map_err(|error| {
                            TrapError::Hypervisor(format!(
                                "authenticate detached resident root retirement: {error}"
                            ))
                        })?;
                        (commit, Some(receipt))
                    }
                    None => (
                        carrick_vmm_hvf::hvf_aarch64_engine::retire_detached_task_engine(state)?,
                        None,
                    ),
                };
                apply_commit(commit)?;
                Ok(root_receipt)
            }
            HvpatchTaskEngineBindingPayload::TaskOnly(state) => {
                // A vfork/`CLONE_VM` task shares another process's kernel mm, so
                // the frame-inventory ledger is not its to retire — the owner
                // retires it. The caller picks this path from STAGE-1
                // ownership, which is a different domain: a task can own a
                // stage-1 root and still share the ledger, and then staging a
                // retirement from that ledger would unmap the owner's live
                // mappings. Ask the authority that actually knows.
                //
                // Reached by `/bin/sh -c`, which vforks: teardown failed with
                // "HVPatch inventory retirement is duplicate or not active
                // (phase=shared_process)" after the guest had already run
                // correctly.
                if state.shares_another_process_inventory() {
                    // Skipping is correct ONLY while the ledger really belongs
                    // to someone else. If a task reaches here still marked
                    // shared after an exec gave it a ledger of its own, this
                    // silently abandons that ledger's rows and the kernel graph
                    // ends up with mappings naming a dead mm.
                    tracing::debug!(
                        target: "carrick::exec",
                        "detached retirement skipped: task shares another process's inventory",
                    );
                    return match root_ticket {
                        Some(ticket) => {
                            let proof = carrick_vmm_hvf::hvf_aarch64_engine::retire_detached_task_only_shared_root_with_proof(
                                state,
                                ticket.base(),
                                ticket.size(),
                            )?;
                            ticket.redeem_vmm(proof).map(Some).map_err(|error| {
                                TrapError::Hypervisor(format!(
                                    "authenticate detached shared-inventory root retirement: {error}"
                                ))
                            })
                        }
                        None => Ok(None),
                    };
                }
                let (commit, root_receipt) = match root_ticket {
                    Some(ticket) => {
                        let (commit, proof) = carrick_vmm_hvf::hvf_aarch64_engine::retire_detached_task_only_engine_with_root_proof(
                            state,
                            ticket.base(),
                            ticket.size(),
                        )?;
                        let receipt = ticket.redeem_vmm(proof).map_err(|error| {
                            TrapError::Hypervisor(format!(
                                "authenticate detached task-only root retirement: {error}"
                            ))
                        })?;
                        (commit, Some(receipt))
                    }
                    None => (
                        carrick_vmm_hvf::hvf_aarch64_engine::retire_detached_task_only_engine(
                            state,
                        )?,
                        None,
                    ),
                };
                state.prepare_inventory_retirement(commit)?;
                state.apply_inventory_retirement(apply_with_receipt)?;
                Ok(root_receipt)
            }
            #[cfg(test)]
            HvpatchTaskEngineBindingPayload::Test => Err(TrapError::Hypervisor(
                "test-only backend has no detached address space".to_owned(),
            )),
        }
    }

    pub(crate) fn retire_detached_exec_predecessor(
        &mut self,
        root_ticket: Option<crate::hvpatch::Stage1RootRetirementTicket>,
    ) -> Result<Option<crate::hvpatch::Stage1RootRetirementReceipt>, TrapError> {
        match &mut self.payload {
            HvpatchTaskEngineBindingPayload::Resident(state) => match root_ticket {
                Some(ticket) => {
                    let proof = carrick_vmm_hvf::hvf_aarch64_engine::retire_detached_exec_predecessor_with_root_proof(
                            state,
                            ticket.base(),
                            ticket.size(),
                        )?;
                    ticket.redeem_vmm(proof).map(Some).map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "authenticate resident exec predecessor root retirement: {error}"
                        ))
                    })
                }
                None => {
                    carrick_vmm_hvf::hvf_aarch64_engine::retire_detached_exec_predecessor(state)?;
                    Ok(None)
                }
            },
            HvpatchTaskEngineBindingPayload::TaskOnly(state) => match root_ticket {
                Some(ticket) => {
                    let proof = carrick_vmm_hvf::hvf_aarch64_engine::retire_detached_task_only_exec_predecessor_with_root_proof(
                            state,
                            ticket.base(),
                            ticket.size(),
                        )?;
                    ticket.redeem_vmm(proof).map(Some).map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "authenticate task-only exec predecessor root retirement: {error}"
                        ))
                    })
                }
                None => {
                    carrick_vmm_hvf::hvf_aarch64_engine::retire_detached_task_only_exec_predecessor(state)?;
                    Ok(None)
                }
            },
            #[cfg(test)]
            HvpatchTaskEngineBindingPayload::Test => Err(TrapError::Hypervisor(
                "test-only backend has no exec predecessor cleanup".to_owned(),
            )),
        }
    }

    pub(crate) fn cancel_dormant(&mut self) -> Result<(), TrapError> {
        match &mut self.payload {
            HvpatchTaskEngineBindingPayload::Resident(state) => {
                carrick_vmm_hvf::hvf_aarch64_engine::cancel_dormant_task_engine(state)
            }
            HvpatchTaskEngineBindingPayload::TaskOnly(state) => {
                carrick_vmm_hvf::hvf_aarch64_engine::cancel_dormant_task_only_engine(state)
            }
            #[cfg(test)]
            HvpatchTaskEngineBindingPayload::Test => Ok(()),
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
            cow_invalidation_observer: None,
            loaded_task_only: None,
            receipt: ExecutorCpuReceipt::default(),
            raw_vcpu_id,
            owner_thread_port,
        })
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
    pub(crate) handle: Box<dyn carrick_hal::VcpuKickDyn>,
    pub(crate) raw_vcpu_id: u64,
    pub(crate) owner_thread_port: u32,
}

impl ExactHardwareKick {
    pub(crate) fn new(
        handle: Box<dyn carrick_hal::VcpuKickDyn>,
        raw_vcpu_id: u64,
        owner_thread_port: u32,
    ) -> Result<Self, TrapError> {
        if owner_thread_port == 0 {
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

pub(crate) fn current_owner_thread_port() -> u32 {
    #[cfg(target_os = "macos")]
    {
        unsafe { libc::pthread_mach_thread_np(libc::pthread_self()) }
    }
    #[cfg(not(target_os = "macos"))]
    {
        1
    }
}

pub(crate) fn restore_worker_vcpu_before_binding_publication<V, B>(
    worker_vcpu: &mut Option<V>,
    vcpu: V,
    backend: B,
    publish: impl FnOnce(B, &Option<V>) -> Result<(), TrapError>,
) -> Result<(), TrapError> {
    if worker_vcpu.replace(vcpu).is_some() {
        carrick_fatal!(
            "vcpu_loop::executor_lease",
            "worker vCPU slot unexpectedly occupied prior to binding publication"
        );
    }
    publish(backend, worker_vcpu)
}

/// What a clone rollback found when it went to retire the child's exact
/// published generation.
#[derive(Debug, Clone, Copy)]
pub(crate) enum FailedCloneRetirement {
    /// The rollback failed the runnable generation itself: the child never
    /// ran, which is the ordinary case.
    Retired,
    /// The generation had already settled TERMINALLY before the rollback
    /// reached it. That is not a rollback failure and never justified killing
    /// the carrier: the generation this rollback exists to retire is already
    /// retired, the child is torn down exactly as before, and the clone still
    /// fails to the guest.
    AlreadySettled(crate::kernel::objects::ThreadExecutionState),
}

pub(crate) fn retire_failed_hvpatch_clone_authority(
    scheduler: &Scheduler,
    kernel: &Arc<crate::kernel::Kernel>,
    context: &crate::kernel::KernelContext,
    generation: ExecutionGeneration,
    retire_binding: impl FnOnce(ThreadKey, ExecutionGeneration),
) -> Result<FailedCloneRetirement, String> {
    let retirement = match scheduler.fail_runnable_exact(
        context.thread().key(),
        generation,
        ExecutionFailure::SnapshotSaveFailed,
    ) {
        Ok(()) => FailedCloneRetirement::Retired,
        // Classified on the TYPED transition error, never on a formatted
        // string: the only refusal that is not a carrier fault is "this exact
        // generation is already terminal".
        Err(SchedulerError::Thread(
            crate::kernel::objects::ThreadExecutionError::InvalidTransition {
                operation: "fail_runnable_generation",
                state,
            },
        )) if matches!(
            state,
            crate::kernel::objects::ThreadExecutionState::Failed { .. }
                | crate::kernel::objects::ThreadExecutionState::Exited { .. }
        ) =>
        {
            FailedCloneRetirement::AlreadySettled(state)
        }
        Err(error) => return Err(format!("fail exact HVPatch clone runnable: {error}")),
    };
    retire_binding(context.thread().key(), generation);
    kernel
        .exit_thread(context, None)
        .map(|_| retirement)
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
        // Validate the exact Kernel CPU/MM/ASID image before taking backend,
        // vCPU, ASID-residency, or task-projection authority. A malformed
        // same-generation snapshot must leave the runnable task untouched.
        let cpu = &task.validate_for_load()?.cpu;
        task.binding()
            .inspect_backend::<HvpatchTaskEngineBindingState, _>(|state| {
                state.preflight_runtime_projection(cpu)
            })?;
        let mut asid_load = task.binding().begin_asid_load(self.executor_id)?;
        let cow_invalidation_observer = task.binding().cow_invalidation_observer(self.executor_id);
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
                    cpu,
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
        self.current
            .as_mut()
            .ok_or_else(|| TrapError::Hypervisor("HVPatch load lost attached engine".into()))?
            .overlay_task_state_on_live_executor(cpu)?;
        task.binding().service_pending_cow_invalidation(
            &cow_invalidation_observer,
            |generation| {
                carrick_vmm_hvf::hvf_aarch64_engine::invalidate_loaded_asid(
                    self.current.as_mut().ok_or_else(|| {
                        TrapError::Hypervisor(
                            "HVPatch pre-entry invalidation lost loaded engine".into(),
                        )
                    })?,
                    generation.raw(),
                )
            },
        )?;
        self.cow_invalidation_observer = Some(cow_invalidation_observer);
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
            executor_id: Some(self.executor_id),
            binding: Some(
                self.binding
                    .as_ref()
                    .unwrap_or_else(|| {
                        carrick_fatal!(
                            "vcpu_loop::executor_lease",
                            "HvpatchPersistentExecutor task binding disappeared between quantum setup and control construction: executor_id={:?}",
                            self.executor_id
                        );
                    }),
            ),
            cow_invalidation_observer: self.cow_invalidation_observer.as_ref(),
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
        let (handle, raw_vcpu_id, owner_thread_port) = if let Some(engine) = self.current.as_ref() {
            carrick_vmm_hvf::hvf_aarch64_engine::persistent_hardware_kick(engine)
        } else if let Some(vcpu) = self.vcpu.as_ref() {
            carrick_vmm_hvf::hvf_aarch64_engine::persistent_vcpu_hardware_kick(vcpu)
        } else {
            return Err(TrapError::Hypervisor(
                "HVPatch hardware kick requested without worker vCPU".into(),
            ));
        };
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
        if let Err(error) = engine.restore_persistent_executor_invariants() {
            return Err(ExecutorSaveError::new(error, lease));
        }
        let engine = self.current.take().unwrap_or_else(|| {
            carrick_fatal!(
                "vcpu_loop::executor_lease",
                "HvpatchPersistentExecutor missing active engine during save transition: executor_id={:?}",
                self.executor_id
            );
        });
        let Some(binding) = self.binding.take() else {
            return Err(ExecutorSaveError::new(
                TrapError::Hypervisor("HVPatch save lost task binding".into()),
                lease,
            ));
        };
        self.cow_invalidation_observer = None;
        let (backend, vcpu) = if let Some(task_only) = self.loaded_task_only.take() {
            let (lifecycle, vcpu) =
                carrick_vmm_hvf::hvf_aarch64_engine::detach_task_only_engine(&task_only, engine);
            if self.lifecycle.replace(lifecycle).is_some() {
                carrick_fatal!(
                    "vcpu_loop::executor_lease",
                    "HvpatchPersistentExecutor lifecycle slot unexpectedly occupied during engine detachment in save: executor_id={:?}",
                    self.executor_id
                );
            }
            (HvpatchTaskEngineBindingState::task_only(task_only), vcpu)
        } else {
            let lifecycle = self
                .lifecycle
                .as_mut()
                .unwrap_or_else(|| {
                    carrick_fatal!(
                        "vcpu_loop::executor_lease",
                        "HvpatchPersistentExecutor missing lifecycle state during engine detachment in save: executor_id={:?}",
                        self.executor_id
                    );
                });
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
        let vcpu = self.vcpu.as_ref().unwrap_or_else(|| {
            carrick_fatal!(
                "vcpu_loop::executor_lease",
                "HvpatchPersistentExecutor missing vCPU handle during boundary audit: executor_id={:?}",
                self.executor_id
            );
        });
        if carrick_vmm_hvf::hvf_aarch64_engine::persistent_vcpu_identity(vcpu) != self.raw_vcpu_id
            || current_owner_thread_port() != self.owner_thread_port
        {
            return Err(TrapError::Hypervisor(
                "HVPatch executor vCPU/Mach owner identity drifted".into(),
            ));
        }
        self.lifecycle
            .as_ref()
            .unwrap_or_else(|| {
                carrick_fatal!(
                    "vcpu_loop::executor_lease",
                    "HvpatchPersistentExecutor missing active engine during boundary audit: executor_id={:?}",
                    self.executor_id
                );
            })
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
                    carrick_fatal!(
                        "vcpu_loop::executor_lease",
                        "HvpatchPersistentExecutor lifecycle slot unexpectedly occupied during engine detachment in destroy: executor_id={:?}",
                        self.executor_id
                    );
                }
                (HvpatchTaskEngineBindingState::task_only(task_only), vcpu)
            } else {
                let lifecycle = self
                    .lifecycle
                    .as_mut()
                    .unwrap_or_else(|| {
                        carrick_fatal!(
                            "vcpu_loop::executor_lease",
                            "HvpatchPersistentExecutor missing lifecycle state during engine detachment in destroy: executor_id={:?}",
                            self.executor_id
                        );
                    });
                let (state, vcpu) =
                    carrick_vmm_hvf::hvf_aarch64_engine::detach_task_engine(engine, lifecycle);
                (HvpatchTaskEngineBindingState::initial(state), vcpu)
            };
            if let Some(binding) = self.binding.take() {
                self.cow_invalidation_observer = None;
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
