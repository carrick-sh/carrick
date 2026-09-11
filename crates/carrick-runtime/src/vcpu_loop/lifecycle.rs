//! Fork and clone lifecycle for the HVPatch vCPU loop.
//!
//! Owns process fork preparation and commit/rollback boundaries, clone thread
//! request and retry lifecycle, failpoints, and child identity bootstrap.

use std::sync::Arc;

use carrick_fatal::carrick_fatal;
use carrick_guest_mem::CurrentMmMemory;
use carrick_hal::TrapError;
use carrick_hal::threaded::ThreadedEngine;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use carrick_hal::VcpuRegistry;

use super::terminal::CloneAdmissionChangeSubscription;
use super::threads;
use super::{
    Kernel, RuntimeError, SyscallDispatcher, ThreadRuntimeState, executor, stamp_identity_values,
    stamp_ns_visible_guest_tid,
};

pub(crate) enum ProcessChildBootstrap {
    GuestFork {
        shares_mm: bool,
        child_settid: Option<(u64, i32)>,
    },
    ExternalControlExec {
        shares_mm: bool,
    },
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy)]
pub(crate) struct HvpatchCloneThreadRequest {
    pub(crate) stack: u64,
    pub(crate) tls: Option<u64>,
    pub(crate) flags: u64,
    pub(crate) parent_tid_addr: u64,
    pub(crate) child_tid_addr: u64,
    pub(crate) clear_child_tid_addr: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
// `Complete` is the clone hot path. Boxing it would add an allocation to every
// successful guest thread clone solely to shrink the uncommon parked variant.
#[allow(clippy::large_enum_variant)]
pub(super) enum PersistentHvpatchCloneAttempt {
    Complete(threads::CloneThreadSpawn),
    Wait {
        prepared: Option<crate::kernel::PreparedThreadClone>,
        subscription: CloneRetrySubscription,
    },
}

/// What a parked thread clone waits on before it is retried.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) enum CloneRetrySubscription {
    /// The kernel task reservation (parent busy in another transaction).
    Reservation {
        _subscription: Option<crate::kernel::ReservationChangeSubscription>,
    },
    /// A sibling process fork's transient clone-admission close.
    Admission {
        _subscription: Option<CloneAdmissionChangeSubscription>,
    },
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) trait HvpatchCloneBackendOps<M: threads::CloneTidMemory> {
    type Prepared;
    type Backend;

    fn prepare(
        &mut self,
        memory: &M,
        identity: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskIdentity,
        entry: carrick_hal::GuestEntryRegs,
        mm_generation: u64,
        asid_generation: u64,
    ) -> Result<(Self::Prepared, carrick_hal::threaded::GuestCpuState), RuntimeError>;
    fn abort(&mut self, prepared: Self::Prepared) -> Result<(), RuntimeError>;
    fn commit(
        &mut self,
        prepared: Self::Prepared,
        directory: Arc<carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskStateDirectory>,
    ) -> Result<Self::Backend, RuntimeError>;
    fn bind_child_kernel(
        &mut self,
        backend: &mut Self::Backend,
        token: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchChildKernelBinding,
    ) -> Result<(), RuntimeError>;
    fn frame_cow_owner_inventory(
        &self,
        backend: &Self::Backend,
    ) -> Arc<dyn carrick_hal::FrameCowOwnerInventory>;
    fn activate_child(&mut self, backend: &mut Self::Backend) -> Result<(), RuntimeError>;
    fn make_binding_state(
        &mut self,
        backend: Self::Backend,
    ) -> executor::HvpatchTaskEngineBindingState;
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) type HvpatchProcessPreparation<P> = (
    P,
    carrick_hal::threaded::GuestCpuState,
    Arc<dyn VcpuRegistry>,
);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) enum HvpatchProcessInventoryPreparation<'a> {
    /// A plain fork owns a new MM and must publish its staged frame inventory.
    Copied(
        &'a mut dyn FnMut(
            usize,
            usize,
            carrick_hal::FrameEventCapacity,
        ) -> Result<carrick_hal::FrameInventoryReservation, RuntimeError>,
    ),
    /// `CLONE_VM`/vfork retains the parent's exact MM/inventory authority.  No
    /// process inventory transaction exists for the child edge.
    SharedMm { kernel_mm: u64 },
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn validate_hvpatch_process_prepare_boundary(
    inventory: &HvpatchProcessInventoryPreparation<'_>,
    request: &carrick_hal::ProcessForkRequest,
    mm_generation: u64,
) -> Result<(), RuntimeError> {
    carrick_hal::validate_fork_projection(request.plan.ranges()).map_err(|error| {
        RuntimeError::Configuration(format!("invalid HVPatch fork projection: {error}"))
    })?;
    match (inventory, &request.plan) {
        (
            HvpatchProcessInventoryPreparation::Copied(_),
            carrick_hal::ForkProjectionPlan::Copied {
                parent_mm,
                child_mm,
                ..
            },
        ) if *child_mm == mm_generation && parent_mm != child_mm => Ok(()),
        (
            HvpatchProcessInventoryPreparation::SharedMm { kernel_mm },
            carrick_hal::ForkProjectionPlan::Shared { parent_mm, .. },
        ) if *parent_mm == *kernel_mm
            && request.plan.child_mm() == *kernel_mm
            && mm_generation == *kernel_mm =>
        {
            Ok(())
        }
        (HvpatchProcessInventoryPreparation::Copied(_), _) => Err(RuntimeError::Configuration(
            "copied HVPatch inventory requires a distinct-parent Copied projection bound to the child MM generation"
                .to_owned(),
        )),
        (HvpatchProcessInventoryPreparation::SharedMm { .. }, _) => {
            Err(RuntimeError::Configuration(
                "shared HVPatch inventory requires a Shared projection bound to the kernel MM"
                    .to_owned(),
            ))
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn cleanup_failed_hvpatch_initial_cpu<T>(
    abort: impl FnOnce() -> Result<(), RuntimeError>,
    context: &mut T,
    cancel_inventory: impl FnOnce(&mut T) -> Result<(), RuntimeError>,
    rollback_parent: impl FnOnce(&mut T) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    let abort_error = abort().err();
    let _cancel_error = cancel_inventory(context).err();
    let rollback_error = rollback_parent(context).err();
    match (abort_error, rollback_error) {
        (None, None) => Ok(()),
        (Some(abort), None) => Err(RuntimeError::Configuration(format!(
            "HVPatch initial CPU cleanup failed to abort child: {abort}"
        ))),
        (None, Some(rollback)) => Err(RuntimeError::Configuration(format!(
            "HVPatch initial CPU cleanup failed to rollback parent: {rollback}"
        ))),
        (Some(abort), Some(rollback)) => Err(RuntimeError::Configuration(format!(
            "HVPatch initial CPU cleanup failed to abort child ({abort}) and rollback parent ({rollback})"
        ))),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) trait HvpatchProcessBackendOps<E: ThreadedEngine, M: CurrentMmMemory> {
    type Prepared;
    type Backend;

    fn prepare(
        &mut self,
        memory: &mut M,
        inventory: HvpatchProcessInventoryPreparation<'_>,
        request: carrick_hal::ProcessForkRequest,
        identity: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskIdentity,
        mm_generation: u64,
        asid_generation: u64,
    ) -> Result<HvpatchProcessPreparation<Self::Prepared>, RuntimeError>;
    fn abort(&mut self, prepared: Self::Prepared) -> Result<(), RuntimeError>;
    fn commit_parent(&mut self, memory: &mut M) -> Result<(), RuntimeError>;
    fn rollback_parent(&mut self, memory: &mut M) -> Result<(), RuntimeError>;
    fn abort_and_rollback_prepared(
        &mut self,
        prepared: Self::Prepared,
        memory: &mut M,
        rollback_parent: bool,
    ) -> Result<(), RuntimeError> {
        let abort_error = self.abort(prepared).err();
        let rollback_error = rollback_parent
            .then(|| self.rollback_parent(memory).err())
            .flatten();
        match (abort_error, rollback_error) {
            (None, None) => Ok(()),
            (Some(abort), None) => Err(RuntimeError::Configuration(format!(
                "HVPatch prepared unwind failed to abort child: {abort}"
            ))),
            (None, Some(rollback)) => Err(RuntimeError::Configuration(format!(
                "HVPatch prepared unwind failed to rollback parent: {rollback}"
            ))),
            (Some(abort), Some(rollback)) => Err(RuntimeError::Configuration(format!(
                "HVPatch prepared unwind failed to abort child ({abort}) and rollback parent ({rollback})"
            ))),
        }
    }
    fn commit(
        &mut self,
        prepared: Self::Prepared,
        directory: Arc<carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskStateDirectory>,
    ) -> Result<Self::Backend, RuntimeError>;
    fn apply_inventory(
        &mut self,
        backend: &Self::Backend,
        kernel: &Arc<crate::kernel::Kernel>,
        mm: crate::kernel::MmId,
    ) -> Result<(), RuntimeError>;
    fn bind_child_kernel(
        &mut self,
        backend: &mut Self::Backend,
        token: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchChildKernelBinding,
    ) -> Result<(), RuntimeError>;
    fn frame_cow_owner_inventory(
        &self,
        backend: &Self::Backend,
    ) -> Arc<dyn carrick_hal::FrameCowOwnerInventory>;
    fn activate_child(&mut self, backend: &mut Self::Backend) -> Result<(), RuntimeError>;
    fn make_binding_state(
        &mut self,
        backend: Self::Backend,
    ) -> executor::HvpatchTaskEngineBindingState;
    fn guest_sp(&self, memory: &M) -> Option<u64>;
    fn fail_stop(&mut self, error: RuntimeError) -> RuntimeError;
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct ProductionHvpatchProcessBackendOps;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl<E: ThreadedEngine + 'static> HvpatchProcessBackendOps<E, E>
    for ProductionHvpatchProcessBackendOps
where
    E::ProcessSpec: 'static,
{
    type Prepared = carrick_vmm_hvf::hvf_aarch64_engine::HvpatchPreparedTaskOnlyEngineState;
    type Backend = carrick_vmm_hvf::hvf_aarch64_engine::HvpatchTaskOnlyEngineState;

    fn prepare(
        &mut self,
        memory: &mut E,
        inventory: HvpatchProcessInventoryPreparation<'_>,
        request: carrick_hal::ProcessForkRequest,
        identity: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskIdentity,
        mm_generation: u64,
        asid_generation: u64,
    ) -> Result<HvpatchProcessPreparation<Self::Prepared>, RuntimeError> {
        type HvfEngine = carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Engine;
        validate_hvpatch_process_prepare_boundary(&inventory, &request, mm_generation)?;
        let prepared = match inventory {
            HvpatchProcessInventoryPreparation::Copied(reserve) => {
                let spec = match memory.build_process_spec(request) {
                    Ok(spec) => spec,
                    Err(error) => {
                        let _ = memory.cancel_process_inventory();
                        memory.rollback_process_fork().map_err(RuntimeError::Trap)?;
                        return Err(RuntimeError::Trap(error));
                    }
                };
                let spec = match (Box::new(spec) as Box<dyn std::any::Any>)
                    .downcast::<<HvfEngine as ThreadedEngine>::ProcessSpec>()
                {
                    Ok(spec) => spec,
                    Err(_) => {
                        let _ = memory.cancel_process_inventory();
                        memory.rollback_process_fork().map_err(RuntimeError::Trap)?;
                        return Err(RuntimeError::Configuration(
                            "persistent HVPatch fork rejected non-HVF process spec".to_owned(),
                        ));
                    }
                };
                match carrick_vmm_hvf::hvf_aarch64_engine::materialize_hvpatch_process_without_vcpu_with_reservation(
                    identity,
                    *spec,
                    |frames, mappings, capacity| {
                        reserve(frames, mappings, capacity)
                            .map_err(|error| carrick_hal::TrapError::Hypervisor(error.to_string()))
                    },
                ) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        let _ = memory.cancel_process_inventory();
                        memory.rollback_process_fork().map_err(RuntimeError::Trap)?;
                        return Err(RuntimeError::Trap(error));
                    }
                }
            }
            HvpatchProcessInventoryPreparation::SharedMm { kernel_mm } => {
                if !request.shares_mm() {
                    return Err(RuntimeError::Configuration(
                        "shared HVPatch process preparation requires CLONE_VM".to_owned(),
                    ));
                }
                let engine = (memory as &dyn std::any::Any)
                    .downcast_ref::<HvfEngine>()
                    .ok_or_else(|| {
                        RuntimeError::Configuration(
                            "persistent HVPatch shared process rejected non-HVF engine".to_owned(),
                        )
                    })?;
                let spec = <HvfEngine as ThreadedEngine>::build_sibling_spec(engine, request.entry)
                    .map_err(RuntimeError::Trap)?;
                carrick_vmm_hvf::hvf_aarch64_engine::materialize_hvpatch_shared_process_without_vcpu(
                    identity,
                    kernel_mm,
                    spec,
                )
                .map_err(RuntimeError::Trap)?
            }
        };
        let cpu = match prepared.initial_cpu_state(mm_generation, asid_generation) {
            Ok(cpu) => cpu,
            Err(error) => {
                if let Err(cleanup_error) = cleanup_failed_hvpatch_initial_cpu(
                    || prepared.abort().map_err(RuntimeError::Trap),
                    memory,
                    |memory| {
                        let _cancelled = memory.cancel_process_inventory();
                        Ok(())
                    },
                    |memory| memory.rollback_process_fork().map_err(RuntimeError::Trap),
                ) {
                    return Err(<Self as HvpatchProcessBackendOps<E, E>>::fail_stop(
                        self,
                        cleanup_error,
                    ));
                }
                return Err(RuntimeError::Trap(error));
            }
        };
        Ok((prepared, cpu, memory.fresh_fork_kicker()))
    }

    fn abort(&mut self, prepared: Self::Prepared) -> Result<(), RuntimeError> {
        prepared.abort().map_err(RuntimeError::Trap)
    }

    fn commit_parent(&mut self, memory: &mut E) -> Result<(), RuntimeError> {
        memory.commit_process_fork().map_err(RuntimeError::Trap)
    }

    fn rollback_parent(&mut self, memory: &mut E) -> Result<(), RuntimeError> {
        let _ = memory.cancel_process_inventory();
        memory.rollback_process_fork().map_err(RuntimeError::Trap)
    }

    fn commit(
        &mut self,
        prepared: Self::Prepared,
        directory: Arc<carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskStateDirectory>,
    ) -> Result<Self::Backend, RuntimeError> {
        prepared.commit(directory).map_err(RuntimeError::Trap)
    }

    fn apply_inventory(
        &mut self,
        backend: &Self::Backend,
        kernel: &Arc<crate::kernel::Kernel>,
        mm: crate::kernel::MmId,
    ) -> Result<(), RuntimeError> {
        backend
            .apply_inventory(|commit| {
                kernel
                    .frame_inventory()
                    .apply_with_receipt(mm, commit)
                    .map(|(_, receipt)| receipt)
                    .map_err(|error| TrapError::Hypervisor(error.to_string()))
            })
            .map_err(RuntimeError::Trap)
    }

    fn bind_child_kernel(
        &mut self,
        backend: &mut Self::Backend,
        token: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchChildKernelBinding,
    ) -> Result<(), RuntimeError> {
        backend.bind_child_kernel(token).map_err(RuntimeError::Trap)
    }

    fn frame_cow_owner_inventory(
        &self,
        backend: &Self::Backend,
    ) -> Arc<dyn carrick_hal::FrameCowOwnerInventory> {
        backend.frame_cow_owner_inventory()
    }

    fn activate_child(&mut self, backend: &mut Self::Backend) -> Result<(), RuntimeError> {
        backend.activate_child().map_err(RuntimeError::Trap)
    }

    fn make_binding_state(
        &mut self,
        backend: Self::Backend,
    ) -> executor::HvpatchTaskEngineBindingState {
        executor::HvpatchTaskEngineBindingState::task_only(backend)
    }

    fn guest_sp(&self, memory: &E) -> Option<u64> {
        memory.get_reg(carrick_hal::Reg::Sp).ok()
    }

    fn fail_stop(&mut self, error: RuntimeError) -> RuntimeError {
        eprintln!("carrick: FATAL: HVPatch process publication failure: {error}");
        carrick_fatal!(
            "vcpu_loop::fail_stop",
            "HVPatch process publication failure: {error}"
        );
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct ProductionHvpatchCloneBackendOps;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl<M: threads::CloneTidMemory + 'static> HvpatchCloneBackendOps<M>
    for ProductionHvpatchCloneBackendOps
{
    type Prepared = carrick_vmm_hvf::hvf_aarch64_engine::HvpatchPreparedTaskOnlyEngineState;
    type Backend = carrick_vmm_hvf::hvf_aarch64_engine::HvpatchTaskOnlyEngineState;

    fn prepare(
        &mut self,
        memory: &M,
        identity: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskIdentity,
        entry: carrick_hal::GuestEntryRegs,
        mm_generation: u64,
        asid_generation: u64,
    ) -> Result<(Self::Prepared, carrick_hal::threaded::GuestCpuState), RuntimeError> {
        type HvfEngine = carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Engine;
        let engine = (memory as &dyn std::any::Any)
            .downcast_ref::<HvfEngine>()
            .ok_or_else(|| {
                RuntimeError::Configuration(
                    "persistent HVPatch clone rejected non-HVF engine".to_owned(),
                )
            })?;
        let spec = <HvfEngine as ThreadedEngine>::build_sibling_spec(engine, entry)
            .map_err(RuntimeError::Trap)?;
        let prepared =
            carrick_vmm_hvf::hvf_aarch64_engine::materialize_hvpatch_sibling_without_vcpu(
                identity, spec,
            )
            .map_err(RuntimeError::Trap)?;
        let cpu = prepared
            .initial_cpu_state(mm_generation, asid_generation)
            .map_err(RuntimeError::Trap)?;
        Ok((prepared, cpu))
    }

    fn abort(&mut self, prepared: Self::Prepared) -> Result<(), RuntimeError> {
        prepared.abort().map_err(RuntimeError::Trap)
    }

    fn commit(
        &mut self,
        prepared: Self::Prepared,
        directory: Arc<carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskStateDirectory>,
    ) -> Result<Self::Backend, RuntimeError> {
        prepared.commit(directory).map_err(RuntimeError::Trap)
    }

    fn bind_child_kernel(
        &mut self,
        backend: &mut Self::Backend,
        token: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchChildKernelBinding,
    ) -> Result<(), RuntimeError> {
        backend.bind_child_kernel(token).map_err(RuntimeError::Trap)
    }

    fn frame_cow_owner_inventory(
        &self,
        backend: &Self::Backend,
    ) -> Arc<dyn carrick_hal::FrameCowOwnerInventory> {
        backend.frame_cow_owner_inventory()
    }

    fn activate_child(&mut self, backend: &mut Self::Backend) -> Result<(), RuntimeError> {
        backend.activate_child().map_err(RuntimeError::Trap)
    }

    fn make_binding_state(
        &mut self,
        backend: Self::Backend,
    ) -> executor::HvpatchTaskEngineBindingState {
        executor::HvpatchTaskEngineBindingState::task_only(backend)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum HvpatchCloneFailpoint {
    TidCopyout = 1,
    BackendCommit = 2,
    TokenBind = 3,
    RegistryHandle = 4,
    StartProof = 5,
    Activation = 6,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum HvpatchProcessFailpoint {
    ParentCopyout = 1,
    BackendCommit = 2,
    KernelCommit = 3,
    TokenBind = 4,
    DormantHandle = 5,
    StartProof = 6,
    Activation = 7,
    ChildSettidBootstrap = 8,
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
static HVPATCH_CLONE_FAILPOINT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
static HVPATCH_PROCESS_FAILPOINT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn install_hvpatch_clone_failpoint(phase: HvpatchCloneFailpoint) {
    HVPATCH_CLONE_FAILPOINT.store(phase as u8, std::sync::atomic::Ordering::Release);
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn install_hvpatch_process_failpoint(phase: HvpatchProcessFailpoint) {
    HVPATCH_PROCESS_FAILPOINT.store(phase as u8, std::sync::atomic::Ordering::Release);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn check_hvpatch_clone_failpoint(
    phase: HvpatchCloneFailpoint,
) -> Result<(), RuntimeError> {
    #[cfg(test)]
    if HVPATCH_CLONE_FAILPOINT
        .compare_exchange(
            phase as u8,
            0,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .is_ok()
    {
        return Err(RuntimeError::Configuration(format!(
            "injected production HVPatch clone failpoint: {phase:?}"
        )));
    }
    #[cfg(not(test))]
    let _ = phase;
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn check_hvpatch_process_failpoint(
    phase: HvpatchProcessFailpoint,
) -> Result<(), RuntimeError> {
    #[cfg(test)]
    if HVPATCH_PROCESS_FAILPOINT
        .compare_exchange(
            phase as u8,
            0,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .is_ok()
    {
        return Err(RuntimeError::Configuration(format!(
            "injected production HVPatch process failpoint: {phase:?}"
        )));
    }
    #[cfg(not(test))]
    let _ = phase;
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn bootstrap_hvpatch_process_child<E: ThreadedEngine + 'static>(
    kernel: &Kernel,
    state: &mut ThreadRuntimeState<E>,
    engine: &mut E,
    bootstrap: ProcessChildBootstrap,
) -> Result<(), RuntimeError>
where
    E::SiblingSpec: 'static,
{
    let shares_mm = match bootstrap {
        ProcessChildBootstrap::GuestFork { shares_mm, .. }
        | ProcessChildBootstrap::ExternalControlExec { shares_mm } => shares_mm,
    };
    if !shares_mm {
        engine
            .refresh_fork_process_state()
            .map_err(RuntimeError::Trap)?;
    }
    let context = state.service_kernel_context.as_ref().ok_or_else(|| {
        RuntimeError::Configuration("process child bootstrap lost Kernel context".to_owned())
    })?;
    bootstrap_hvpatch_process_child_identity(engine, &kernel.dispatcher, context, shares_mm)?;
    stamp_ns_visible_guest_tid(engine, &kernel.dispatcher, context).map_err(RuntimeError::Trap)?;
    if let ProcessChildBootstrap::GuestFork { child_settid, .. } = bootstrap {
        if let Some((address, tid)) = child_settid {
            bootstrap_hvpatch_process_child_tid(engine, address, tid)?;
        }
        state.complete_precompleted_child(&kernel.reporter, 0)?;
    }
    Ok(())
}

pub(crate) fn bootstrap_hvpatch_process_child_identity(
    memory: &mut impl CurrentMmMemory,
    dispatcher: &SyscallDispatcher,
    kernel_context: &crate::kernel::KernelContext,
    shares_mm: bool,
) -> Result<(), RuntimeError> {
    bootstrap_hvpatch_process_child_identity_with(
        memory,
        dispatcher,
        kernel_context,
        shares_mm,
        crate::syscall_shim_enabled(),
    )
}

pub(crate) fn bootstrap_hvpatch_process_child_identity_with(
    memory: &mut impl CurrentMmMemory,
    dispatcher: &SyscallDispatcher,
    kernel_context: &crate::kernel::KernelContext,
    shares_mm: bool,
    shim_enabled: bool,
) -> Result<(), RuntimeError> {
    if !shim_enabled {
        return Ok(());
    }
    let base = crate::memory::LINUX_IDENTITY_PAGE_BASE;
    let res = if shares_mm {
        memory.write_bytes(
            base + crate::memory::IDENTITY_OFF_SHIM_ENABLED,
            &0_u32.to_le_bytes(),
        )
    } else {
        let id = dispatcher.identity_snapshot(kernel_context);
        stamp_identity_values(
            memory,
            base,
            id.pid,
            u32::from(dispatcher.identity_fast_path_enabled()),
        )
    };
    res.map_err(|error| {
        RuntimeError::Trap(TrapError::Hypervisor(format!(
            "process child identity bootstrap: {error}"
        )))
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn bootstrap_hvpatch_process_child_tid(
    memory: &mut impl CurrentMmMemory,
    address: u64,
    tid: i32,
) -> Result<(), RuntimeError> {
    check_hvpatch_process_failpoint(HvpatchProcessFailpoint::ChildSettidBootstrap)?;
    memory
        .write_bytes(address, &tid.to_le_bytes())
        .map_err(|error| {
            RuntimeError::Trap(TrapError::Hypervisor(format!(
                "process child TID bootstrap copyout: {error}"
            )))
        })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::binding::*;
    use super::super::tests::*;
    use super::super::*;
    use super::*;
    use crate::thread::{FutexTable, ThreadId, ThreadRegistry};
    use crate::vcpu_loop::executor::TaskBindingResolver;
    use crate::vcpu_loop::memory::fixed_frame_cow_owner_inventory_for_test;
    use carrick_guest_mem::GuestMemory;
    use parking_lot::Mutex;
    use std::cell::RefCell;
    use std::sync::Arc;

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn fork_request(plan: carrick_hal::ForkProjectionPlan) -> carrick_hal::ProcessForkRequest {
        carrick_hal::ProcessForkRequest {
            entry: carrick_hal::GuestEntryRegs::default(),
            child_ttbr0: 0,
            root_slot_base: 0,
            root_slot_size: 0,
            plan,
            child_tid: carrick_hal::ThreadId::NONE,
            forking_tid: carrick_hal::ThreadId::NONE,
            table_arena_source: None,
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn projection_ranges() -> Arc<[carrick_hal::ForkProjectionRange]> {
        Arc::from([carrick_hal::ForkProjectionRange {
            va: 0x1000,
            len: 0x1000,
            disposition: carrick_hal::ForkLeafDisposition::Preserve,
        }])
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn backend_fork_boundary_rejects_wrong_inventory_mode_and_mm_identity() {
        let mut reserve = |_, _, _| {
            Err(RuntimeError::Configuration(
                "validation test must not reserve inventory".to_owned(),
            ))
        };
        let copied_inventory = HvpatchProcessInventoryPreparation::Copied(&mut reserve);
        let shared = fork_request(carrick_hal::ForkProjectionPlan::Shared {
            parent_mm: 7,
            ranges: projection_ranges(),
        });
        assert!(validate_hvpatch_process_prepare_boundary(&copied_inventory, &shared, 8).is_err());

        let wrong_child = fork_request(carrick_hal::ForkProjectionPlan::Copied {
            parent_mm: 7,
            child_mm: 9,
            ranges: projection_ranges(),
        });
        assert!(
            validate_hvpatch_process_prepare_boundary(&copied_inventory, &wrong_child, 8).is_err()
        );

        let shared_inventory = HvpatchProcessInventoryPreparation::SharedMm { kernel_mm: 7 };
        let copied = fork_request(carrick_hal::ForkProjectionPlan::Copied {
            parent_mm: 7,
            child_mm: 8,
            ranges: projection_ranges(),
        });
        assert!(validate_hvpatch_process_prepare_boundary(&shared_inventory, &copied, 8).is_err());
        let wrong_shared_mm = fork_request(carrick_hal::ForkProjectionPlan::Shared {
            parent_mm: 8,
            ranges: projection_ranges(),
        });
        assert!(
            validate_hvpatch_process_prepare_boundary(&shared_inventory, &wrong_shared_mm, 8)
                .is_err()
        );
        let right_shared_mm_wrong_generation =
            fork_request(carrick_hal::ForkProjectionPlan::Shared {
                parent_mm: 7,
                ranges: projection_ranges(),
            });
        assert!(
            validate_hvpatch_process_prepare_boundary(
                &shared_inventory,
                &right_shared_mm_wrong_generation,
                8,
            )
            .is_err()
        );
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn backend_fork_boundary_rejects_invalid_projection_before_prepare() {
        let inventory = HvpatchProcessInventoryPreparation::SharedMm { kernel_mm: 7 };
        let request = fork_request(carrick_hal::ForkProjectionPlan::Shared {
            parent_mm: 7,
            ranges: Arc::from([carrick_hal::ForkProjectionRange {
                va: 0x1001,
                len: 0x1000,
                disposition: carrick_hal::ForkLeafDisposition::Preserve,
            }]),
        });
        assert!(validate_hvpatch_process_prepare_boundary(&inventory, &request, 7).is_err());
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn initial_cpu_cleanup_attempts_cancel_and_rollback_after_abort_failure() {
        let calls = RefCell::new(Vec::new());
        let result = cleanup_failed_hvpatch_initial_cpu(
            || {
                calls.borrow_mut().push("abort");
                Err(RuntimeError::Configuration("abort failed".to_owned()))
            },
            &mut (),
            |_| {
                calls.borrow_mut().push("cancel");
                Err(RuntimeError::Configuration("cancel failed".to_owned()))
            },
            |_| {
                calls.borrow_mut().push("rollback");
                Ok(())
            },
        );

        assert!(result.is_err());
        assert_eq!(*calls.borrow(), ["abort", "cancel", "rollback"]);
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn prepared_unwind_attempts_parent_rollback_after_abort_failure() {
        let mut ops = FakeBackendOps {
            abort_fails: true,
            ..Default::default()
        };
        let mut memory = Memory::default();
        let result = <FakeBackendOps as HvpatchProcessBackendOps<
            carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Engine,
            Memory,
        >>::abort_and_rollback_prepared(&mut ops, (), &mut memory, true);
        assert!(result.is_err());
        assert_eq!(ops.aborts, 1);
        assert_eq!(ops.parent_rollbacks, 1);
    }

    #[test]
    fn hvpatch_process_child_identity_bootstrap_handles_shared_and_copied_mm() {
        let base = crate::memory::LINUX_IDENTITY_PAGE_BASE;
        let read_state = |m: &crate::dispatch::LinearMemory| {
            let pid = u32::from_le_bytes(
                m.read_bytes_raw(base + crate::memory::IDENTITY_OFF_PID, 4)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            );
            let enabled = u32::from_le_bytes(
                m.read_bytes_raw(base + crate::memory::IDENTITY_OFF_SHIM_ENABLED, 4)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            );
            let syscalls = u64::from_le_bytes(
                m.read_bytes_raw(base + crate::memory::IDENTITY_OFF_SHIM_SYSCALLS, 8)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            );
            (pid, enabled, syscalls)
        };

        let mut memory = crate::dispatch::LinearMemory::new(base, vec![0; 4096]);
        let (parent_pid, parent_counter): (u32, u64) = (70_301, 127);
        stamp_identity_values(&mut memory, base, parent_pid, 1).unwrap();
        memory
            .write_bytes(
                base + crate::memory::IDENTITY_OFF_SHIM_SYSCALLS,
                &parent_counter.to_le_bytes(),
            )
            .unwrap();

        let (_child_process, child_context) = crate::hvpatch::process_context_for_tests(70_302);
        let dispatcher = SyscallDispatcher::new();
        let child_pid = dispatcher.identity_snapshot(&child_context).pid;
        assert_ne!(child_pid, parent_pid);

        // 1. Shared-MM: preserves parent PID and counter, clears enabled word.
        bootstrap_hvpatch_process_child_identity_with(
            &mut memory,
            &dispatcher,
            &child_context,
            true,
            true,
        )
        .unwrap();
        assert_eq!(read_state(&memory), (parent_pid, 0, parent_counter));

        // 2. Copied-MM: stamps child PID and enabled state, resets counter.
        let mut child_memory = crate::dispatch::LinearMemory::new(base, vec![0; 4096]);
        stamp_identity_values(&mut child_memory, base, parent_pid, 1).unwrap();
        child_memory
            .write_bytes(
                base + crate::memory::IDENTITY_OFF_SHIM_SYSCALLS,
                &parent_counter.to_le_bytes(),
            )
            .unwrap();

        bootstrap_hvpatch_process_child_identity_with(
            &mut child_memory,
            &dispatcher,
            &child_context,
            false,
            true,
        )
        .unwrap();
        assert_eq!(read_state(&child_memory), (child_pid, 1, 0));
    }

    #[test]
    fn production_clone_failpoints_are_exact_and_consumed_once() {
        #[derive(Default)]
        pub(crate) struct Memory(pub(crate) std::collections::BTreeMap<u64, Vec<u8>>);
        impl threads::CloneTidMemory for Memory {
            fn read_clone_tid_bytes(
                &self,
                address: u64,
                _len: usize,
            ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
                self.0
                    .get(&address)
                    .cloned()
                    .ok_or(carrick_guest_mem::MemoryError::OutOfBounds { address, length: 4 })
            }

            fn write_clone_tid_bytes(
                &mut self,
                address: u64,
                bytes: &[u8],
            ) -> Result<(), carrick_guest_mem::MemoryError> {
                self.0.insert(address, bytes.to_vec());
                Ok(())
            }
        }

        struct FakeBackendOps;
        impl HvpatchCloneBackendOps<Memory> for FakeBackendOps {
            type Prepared = ();
            type Backend = ();

            fn prepare(
                &mut self,
                _memory: &Memory,
                _identity: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskIdentity,
                _entry: carrick_hal::GuestEntryRegs,
                mm_generation: u64,
                asid_generation: u64,
            ) -> Result<(Self::Prepared, carrick_hal::threaded::GuestCpuState), RuntimeError>
            {
                Ok((
                    (),
                    carrick_hal::threaded::GuestCpuState::from_aarch64_v1(
                        carrick_hal::threaded::Aarch64TaskCpuStateV1 {
                            gprs: [0; 31],
                            pc: 0x1000,
                            pstate: 0,
                            trap_pc: 0,
                            trap_pstate: 0,
                            sp_el0: 0x8000,
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
                            mm_generation,
                            asid_generation,
                        },
                    ),
                ))
            }

            fn abort(&mut self, _prepared: Self::Prepared) -> Result<(), RuntimeError> {
                Ok(())
            }

            fn commit(
                &mut self,
                _prepared: Self::Prepared,
                _directory: Arc<
                    carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskStateDirectory,
                >,
            ) -> Result<Self::Backend, RuntimeError> {
                Ok(())
            }

            fn bind_child_kernel(
                &mut self,
                _backend: &mut Self::Backend,
                _token: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchChildKernelBinding,
            ) -> Result<(), RuntimeError> {
                Ok(())
            }

            fn frame_cow_owner_inventory(
                &self,
                _backend: &Self::Backend,
            ) -> Arc<dyn carrick_hal::FrameCowOwnerInventory> {
                fixed_frame_cow_owner_inventory_for_test(
                    carrick_hal::ForeignOwnerGeneration::from_backend_counter(
                        std::num::NonZeroU64::new(1).unwrap(),
                    ),
                )
            }

            fn activate_child(&mut self, _backend: &mut Self::Backend) -> Result<(), RuntimeError> {
                Ok(())
            }

            fn make_binding_state(
                &mut self,
                _backend: Self::Backend,
            ) -> executor::HvpatchTaskEngineBindingState {
                executor::HvpatchTaskEngineBindingState::test_only()
            }
        }

        struct NoopPlatformFutex;
        impl PlatformFutex for NoopPlatformFutex {
            fn private_wait(
                &self,
                _addr: u64,
                _val: u32,
                _tid: ThreadId,
                _timeout: Option<Duration>,
                _interrupted: &dyn Fn() -> bool,
            ) -> carrick_hal::FutexOutcome {
                carrick_hal::FutexOutcome::Interrupted
            }
            fn private_wake(&self, _addr: u64, _n: u32) -> u32 {
                0
            }
            fn shared_wait(
                &self,
                _location: carrick_guest_mem::SharedFutexLocation,
                _val: u32,
                _tid: ThreadId,
                _timeout: Option<Duration>,
                _interrupted: &dyn Fn() -> bool,
                _wait_enrolled: &dyn Fn(),
            ) -> i64 {
                -1
            }
            fn shared_wake(
                &self,
                _location: carrick_guest_mem::SharedFutexLocation,
                _waiter_key: usize,
                _n: u32,
            ) -> i64 {
                0
            }
            fn requeue(&self, _from: u64, _to: u64, _wake: u32, _requeue: u32) -> (u32, u32) {
                (0, 0)
            }
            fn notify_signal_pending(&self) {}
            fn notify_signal_pending_for(&self, _tid: ThreadId) {}
        }

        let request = HvpatchCloneThreadRequest {
            stack: 0x9000,
            tls: None,
            flags: (carrick_abi::LinuxCloneFlags::THREAD
                | carrick_abi::LinuxCloneFlags::SIGHAND
                | carrick_abi::LinuxCloneFlags::VM)
                .bits(),
            parent_tid_addr: 0x1000,
            child_tid_addr: 0x2000,
            clear_child_tid_addr: 0,
        };
        for (case, phase) in [
            HvpatchCloneFailpoint::TidCopyout,
            HvpatchCloneFailpoint::BackendCommit,
            HvpatchCloneFailpoint::TokenBind,
            HvpatchCloneFailpoint::RegistryHandle,
            HvpatchCloneFailpoint::StartProof,
            HvpatchCloneFailpoint::Activation,
        ]
        .into_iter()
        .enumerate()
        {
            let pid = 68_000 + case as i32;
            let (process, root) = crate::hvpatch::process_context_for_tests(pid);
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
            let runtime = kernel.hvpatch_runtime.as_ref().unwrap();
            let (scheduler, _) = runtime.continuation_services(root.kernel());
            runtime
                .persistent_bindings()
                .install_scheduler(&scheduler)
                .unwrap();
            let mut root_state = executor::tests::task_state(&root, 100 + case as u64);
            root_state.asid_generation = process.asid_generation();
            let carrick_hal::threaded::GuestCpuState::Aarch64V1(cpu) = &mut root_state.cpu else {
                unreachable!()
            };
            Arc::make_mut(cpu).asid_generation = process.asid_generation();
            let root_generation = root
                .thread()
                .publish_initial_task_state(root_state.clone())
                .unwrap();
            let root_binding =
                executor::tests::hvpatch_test_binding(&root, &root_state, 200 + case as u64);
            let dormant = runtime
                .persistent_bindings()
                .prepare_submission(
                    &scheduler,
                    executor::HvpatchSubmissionShape::Root,
                    None,
                    Arc::clone(root.thread()),
                    root_generation,
                    Arc::clone(&root_binding),
                )
                .unwrap();
            executor::tests::activate_hvpatch_test_submission(
                dormant,
                &scheduler,
                &root,
                &root_state,
                root_generation,
                root_binding.as_ref(),
            );
            let root_authority = runtime
                .persistent_bindings()
                .take_submission_authority(root.thread().key(), root_generation)
                .unwrap();
            let this_tid = ThreadId::synthetic_for_tests(pid);
            let registry = Arc::new(ThreadRegistry::new(this_tid));
            let futex = Arc::new(FutexTable::new());
            let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
            let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
            let kicker: Arc<dyn VcpuRegistry> = Arc::new(carrick_hal::GenericVcpuRegistry::new());
            let threads = VcpuThreadRegistry::default();
            let mut state =
                ThreadRuntimeState::<carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Engine>::new(
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
            let syscall_request = SyscallRequest::new(
                220,
                crate::compat::SyscallArgs([
                    request.flags,
                    request.stack,
                    request.parent_tid_addr,
                    request.tls.unwrap_or(0),
                    request.child_tid_addr,
                    0,
                ]),
            );
            state.syscall_completion =
                SyscallCompletionOwnership::Guest(SyscallCompletionToken::new(
                    PreparedSyscall {
                        original_args: syscall_request.args,
                        request: syscall_request,
                    },
                    root.retain_exact(),
                    kernel.dispatcher.observers().cloned(),
                ));
            let job_result = HvpatchLoopResult::pending();
            let job_completion = continuation::LogicalJobCompletion::pending();
            let mut job = ProductionHvpatchLoopJob {
                kernel: Arc::clone(&kernel),
                state,
                phase: HvpatchProductionPhase::Resident,
                registration_wait: None,
                terminal_settlement: HvpatchExternalTerminalSettlement::new(
                    job_result,
                    job_completion.clone(),
                ),
                terminal_result: None,
                completion: job_completion,
                traps: 0,
                budget_floor: 0,
                seen_signal_progress: signal_progress_count(),
                last_signal_progress: Instant::now(),
                terminal_runtime: PersistentTerminalRuntimeState::Resident,
                pending_terminal_retirement: None,
                pending_terminal_inventory: None,
                external_exec: None,
            };
            let mut memory = Memory::default();
            memory.0.insert(0x1000, 11_i32.to_le_bytes().to_vec());
            memory.0.insert(0x2000, 22_i32.to_le_bytes().to_vec());
            let need_resched = std::sync::atomic::AtomicBool::new(false);
            let mut submission = executor::ExecutorSubmissionContext {
                scheduler: &scheduler,
                publish_test_descendant: &|_, _| unreachable!(),
                current: Some(&root_authority),
                lease: None,
                exec_replacement: None,
            };
            let mut control =
                executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
            install_hvpatch_clone_failpoint(phase);
            assert!(
                job.spawn_persistent_hvpatch_clone_thread(
                    &mut memory,
                    &mut control,
                    &root,
                    request,
                    None,
                    &mut FakeBackendOps,
                )
                .is_err()
            );
            assert!(check_hvpatch_clone_failpoint(phase).is_ok());
            assert_eq!(memory.0[&0x1000], 11_i32.to_le_bytes());
            assert_eq!(memory.0[&0x2000], 22_i32.to_le_bytes());
            assert_eq!(root.task().threads().len(), 1);
            assert_eq!(registry.live_count(), 1);
            assert!(threads.is_empty());
            assert_eq!(scheduler.queued_len(), 1);
            runtime
                .persistent_bindings()
                .restore_submission_authority(root_authority)
                .unwrap();
        }
    }

    #[derive(Default)]
    pub(crate) struct Memory(pub(crate) std::collections::BTreeMap<u64, Vec<u8>>);
    impl carrick_guest_mem::GuestMemory for Memory {
        fn read_bytes_raw(
            &self,
            address: u64,
            length: usize,
        ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
            self.0
                .get(&address)
                .filter(|bytes| bytes.len() == length)
                .cloned()
                .ok_or(carrick_guest_mem::MemoryError::OutOfBounds { address, length })
        }

        fn write_bytes_raw(
            &mut self,
            address: u64,
            bytes: &[u8],
        ) -> Result<(), carrick_guest_mem::MemoryError> {
            self.0.insert(address, bytes.to_vec());
            Ok(())
        }
    }

    impl CurrentMmMemory for Memory {}

    impl threads::CloneTidMemory for Memory {
        fn read_clone_tid_bytes(
            &self,
            address: u64,
            len: usize,
        ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
            self.read_bytes_raw(address, len)
        }

        fn write_clone_tid_bytes(
            &mut self,
            address: u64,
            bytes: &[u8],
        ) -> Result<(), carrick_guest_mem::MemoryError> {
            self.write_bytes_raw(address, bytes)
        }
    }

    #[derive(Default)]
    pub(crate) struct FakeBackendOps {
        pub(crate) parent_commits: usize,
        pub(crate) parent_rollbacks: usize,
        pub(crate) backend_prepare_rollbacks: usize,
        pub(crate) aborts: usize,
        pub(crate) fail_stops: usize,
        pub(crate) child_kernel_bound: bool,
        pub(crate) copied_preparations: usize,
        pub(crate) shared_preparations: usize,
        pub(crate) inventory_applies: usize,
        pub(crate) prepare_fails: bool,
        pub(crate) abort_fails: bool,
        pub(crate) on_prepare: Option<Arc<dyn Fn() + Send + Sync>>,
        pub(crate) request_parent_mm: Option<u64>,
        pub(crate) request_child_mm: Option<u64>,
    }

    impl<E: ThreadedEngine> HvpatchProcessBackendOps<E, Memory> for FakeBackendOps {
        type Prepared = ();
        type Backend = ();

        fn prepare(
            &mut self,
            _memory: &mut Memory,
            inventory: HvpatchProcessInventoryPreparation<'_>,
            request: carrick_hal::ProcessForkRequest,
            _identity: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskIdentity,
            mm_generation: u64,
            asid_generation: u64,
        ) -> Result<
            (
                Self::Prepared,
                carrick_hal::threaded::GuestCpuState,
                Arc<dyn VcpuRegistry>,
            ),
            RuntimeError,
        > {
            self.request_parent_mm = Some(request.plan.parent_mm());
            self.request_child_mm = Some(request.plan.child_mm());
            if self.prepare_fails {
                self.backend_prepare_rollbacks += 1;
                return Err(RuntimeError::Trap(
                    carrick_vmm_hvf::trap::TrapError::Hypervisor(
                        "simulated backend prepare error".to_owned(),
                    ),
                ));
            }
            if let Some(hook) = &self.on_prepare {
                hook();
            }
            match inventory {
                HvpatchProcessInventoryPreparation::Copied(_) => {
                    self.copied_preparations += 1;
                }
                HvpatchProcessInventoryPreparation::SharedMm { .. } => {
                    self.shared_preparations += 1;
                }
            }
            Ok((
                (),
                carrick_hal::threaded::GuestCpuState::from_aarch64_v1(
                    carrick_hal::threaded::Aarch64TaskCpuStateV1 {
                        gprs: [0; 31],
                        pc: 0x1000,
                        pstate: 0,
                        trap_pc: 0,
                        trap_pstate: 0,
                        sp_el0: 0x8000,
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
                        is_forked_child: true,
                        syscall_continuation: None,
                        mm_generation,
                        asid_generation,
                    },
                ),
                Arc::new(carrick_hal::GenericVcpuRegistry::new()),
            ))
        }

        fn abort(&mut self, _prepared: Self::Prepared) -> Result<(), RuntimeError> {
            self.aborts += 1;
            if self.abort_fails {
                return Err(RuntimeError::Configuration(
                    "simulated backend abort failure".to_owned(),
                ));
            }
            Ok(())
        }

        fn commit_parent(&mut self, _memory: &mut Memory) -> Result<(), RuntimeError> {
            self.parent_commits += 1;
            Ok(())
        }

        fn rollback_parent(&mut self, _memory: &mut Memory) -> Result<(), RuntimeError> {
            self.parent_rollbacks += 1;
            Ok(())
        }

        fn commit(
            &mut self,
            _prepared: Self::Prepared,
            _directory: Arc<carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskStateDirectory>,
        ) -> Result<Self::Backend, RuntimeError> {
            Ok(())
        }

        fn apply_inventory(
            &mut self,
            _backend: &Self::Backend,
            _kernel: &Arc<crate::kernel::Kernel>,
            _mm: crate::kernel::MmId,
        ) -> Result<(), RuntimeError> {
            assert!(
                self.child_kernel_bound,
                "inventory must follow exact child Kernel/MM binding"
            );
            self.inventory_applies += 1;
            Ok(())
        }

        fn bind_child_kernel(
            &mut self,
            _backend: &mut Self::Backend,
            _token: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchChildKernelBinding,
        ) -> Result<(), RuntimeError> {
            self.child_kernel_bound = true;
            Ok(())
        }

        fn frame_cow_owner_inventory(
            &self,
            _backend: &Self::Backend,
        ) -> Arc<dyn carrick_hal::FrameCowOwnerInventory> {
            fixed_frame_cow_owner_inventory_for_test(
                carrick_hal::ForeignOwnerGeneration::from_backend_counter(
                    std::num::NonZeroU64::new(1).unwrap(),
                ),
            )
        }

        fn activate_child(&mut self, _backend: &mut Self::Backend) -> Result<(), RuntimeError> {
            Ok(())
        }

        fn make_binding_state(
            &mut self,
            _backend: Self::Backend,
        ) -> executor::HvpatchTaskEngineBindingState {
            executor::HvpatchTaskEngineBindingState::test_only()
        }

        fn guest_sp(&self, _memory: &Memory) -> Option<u64> {
            Some(0x8000)
        }

        fn fail_stop(&mut self, error: RuntimeError) -> RuntimeError {
            self.fail_stops += 1;
            error
        }
    }

    pub(super) struct NoopPlatformFutex;
    impl PlatformFutex for NoopPlatformFutex {
        fn private_wait(
            &self,
            _addr: u64,
            _val: u32,
            _tid: ThreadId,
            _timeout: Option<Duration>,
            _interrupted: &dyn Fn() -> bool,
        ) -> carrick_hal::FutexOutcome {
            carrick_hal::FutexOutcome::Interrupted
        }
        fn private_wake(&self, _addr: u64, _n: u32) -> u32 {
            0
        }
        fn shared_wait(
            &self,
            _location: carrick_guest_mem::SharedFutexLocation,
            _val: u32,
            _tid: ThreadId,
            _timeout: Option<Duration>,
            _interrupted: &dyn Fn() -> bool,
            _wait_enrolled: &dyn Fn(),
        ) -> i64 {
            -1
        }
        fn shared_wake(
            &self,
            _location: carrick_guest_mem::SharedFutexLocation,
            _waiter_key: usize,
            _n: u32,
        ) -> i64 {
            0
        }
        fn requeue(&self, _from: u64, _to: u64, _wake: u32, _requeue: u32) -> (u32, u32) {
            (0, 0)
        }
        fn notify_signal_pending(&self) {}
        fn notify_signal_pending_for(&self, _tid: ThreadId) {}
    }

    macro_rules! test_carrier_graph_with_dispatcher {
        ($pid:expr, $dispatcher:expr) => {{
            let (process, root) = crate::hvpatch::process_context_for_tests($pid);
            $dispatcher.bind_hvpatch_process(process.clone());
            let kernel = Arc::new(KernelState::new(
                $dispatcher,
                Arc::new(EndpointTestSignalPump),
                Arc::new(EndpointTestSignalArrival),
                Some(process.clone()),
                None,
                None,
            ));
            let runtime = Arc::clone(kernel.hvpatch_runtime.as_ref().unwrap());
            let (scheduler, _) = runtime.continuation_services(root.kernel());
            runtime
                .persistent_bindings()
                .install_scheduler(&scheduler)
                .unwrap();
            let mut root_state = executor::tests::task_state(&root, 500);
            root_state.asid_generation = process.asid_generation();
            let carrick_hal::threaded::GuestCpuState::Aarch64V1(cpu) = &mut root_state.cpu else {
                unreachable!()
            };
            Arc::make_mut(cpu).asid_generation = process.asid_generation();
            let root_generation = root
                .thread()
                .publish_initial_task_state(root_state.clone())
                .unwrap();
            let root_binding = executor::tests::hvpatch_test_binding(&root, &root_state, 600);
            let dormant = runtime
                .persistent_bindings()
                .prepare_submission(
                    &scheduler,
                    executor::HvpatchSubmissionShape::Root,
                    None,
                    Arc::clone(root.thread()),
                    root_generation,
                    Arc::clone(&root_binding),
                )
                .unwrap();
            executor::tests::activate_hvpatch_test_submission(
                dormant,
                &scheduler,
                &root,
                &root_state,
                root_generation,
                root_binding.as_ref(),
            );
            (runtime, scheduler, kernel, root, process, root_generation)
        }};
    }

    #[test]
    fn production_process_failpoints_run_the_real_kernel_copyout_and_publication_body() {
        for (case, phase) in [
            Some(HvpatchProcessFailpoint::ParentCopyout),
            Some(HvpatchProcessFailpoint::BackendCommit),
            Some(HvpatchProcessFailpoint::KernelCommit),
            Some(HvpatchProcessFailpoint::TokenBind),
            Some(HvpatchProcessFailpoint::DormantHandle),
            Some(HvpatchProcessFailpoint::StartProof),
            Some(HvpatchProcessFailpoint::Activation),
            None,
        ]
        .into_iter()
        .enumerate()
        {
            let pid = 69_000 + case as i32;
            let (process, root) = crate::hvpatch::process_context_for_tests(pid);
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
            let runtime = kernel.hvpatch_runtime.as_ref().unwrap();
            let (scheduler, _) = runtime.continuation_services(root.kernel());
            runtime
                .persistent_bindings()
                .install_scheduler(&scheduler)
                .unwrap();
            let mut root_state = executor::tests::task_state(&root, 500 + case as u64);
            root_state.asid_generation = process.asid_generation();
            let carrick_hal::threaded::GuestCpuState::Aarch64V1(cpu) = &mut root_state.cpu else {
                unreachable!()
            };
            Arc::make_mut(cpu).asid_generation = process.asid_generation();
            let root_generation = root
                .thread()
                .publish_initial_task_state(root_state.clone())
                .unwrap();
            let root_binding =
                executor::tests::hvpatch_test_binding(&root, &root_state, 600 + case as u64);
            let dormant = runtime
                .persistent_bindings()
                .prepare_submission(
                    &scheduler,
                    executor::HvpatchSubmissionShape::Root,
                    None,
                    Arc::clone(root.thread()),
                    root_generation,
                    Arc::clone(&root_binding),
                )
                .unwrap();
            executor::tests::activate_hvpatch_test_submission(
                dormant,
                &scheduler,
                &root,
                &root_state,
                root_generation,
                root_binding.as_ref(),
            );
            let root_authority = runtime
                .persistent_bindings()
                .take_submission_authority(root.thread().key(), root_generation)
                .unwrap();
            let this_tid = ThreadId::synthetic_for_tests(pid);
            let registry = Arc::new(ThreadRegistry::new(this_tid));
            let futex = Arc::new(FutexTable::new());
            let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
            let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
            let kicker: Arc<dyn VcpuRegistry> = Arc::new(carrick_hal::GenericVcpuRegistry::new());
            let mut state =
                ThreadRuntimeState::<carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Engine>::new(
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
                    Arc::new(Mutex::new(Vec::new())),
                    kicker,
                    carrick_hal::InGuestFlag::for_guest_thread(),
                    1_000,
                );
            state.service_kernel_context = Some(root.retain_exact());
            let clone_flags = if phase.is_none() {
                carrick_abi::LinuxCloneFlags::VM.bits()
            } else {
                0
            };
            let syscall_request = SyscallRequest::new(
                220,
                crate::compat::SyscallArgs([clone_flags, 0, 0x1000, 0, 0x2000, 0]),
            );
            state.syscall_completion =
                SyscallCompletionOwnership::Guest(SyscallCompletionToken::new(
                    PreparedSyscall {
                        original_args: syscall_request.args,
                        request: syscall_request,
                    },
                    root.retain_exact(),
                    kernel.dispatcher.observers().cloned(),
                ));
            let mut memory = Memory::default();
            memory.0.insert(0x1000, 11_i32.to_le_bytes().to_vec());
            memory.0.insert(0x2000, 22_i32.to_le_bytes().to_vec());
            let need_resched = std::sync::atomic::AtomicBool::new(false);
            let mut submission = executor::ExecutorSubmissionContext {
                scheduler: &scheduler,
                publish_test_descendant: &|_, _| unreachable!(),
                current: Some(&root_authority),
                lease: None,
                exec_replacement: None,
            };
            let mut control =
                executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
            let mut ops = FakeBackendOps::default();
            if let Some(phase) = phase {
                install_hvpatch_process_failpoint(phase);
            }
            let result = state.prepare_in_process_fork(
                &kernel,
                &root,
                &mut memory,
                &mut control,
                &mut ops,
                quiesce::ProcessForkAttempt {
                    request: quiesce::ForkRequest {
                        flags: clone_flags,
                        pidfd_out: None,
                        clone_parent: false,
                        parent_tid_addr: Some(0x1000),
                        child_tid_addr: Some(0x2000),
                        exit_signal: crate::linux_abi::LINUX_SIGCHLD as u32,
                        child_stack: 0,
                        vfork: None,
                    },
                    coordinator: None,
                    external_exec: None,
                },
            );
            let Some(phase) = phase else {
                assert!(matches!(
                    result,
                    Ok(quiesce::PreparedInProcessFork::Complete(Some(_)))
                ));
                assert_eq!(ops.shared_preparations, 1);
                assert_eq!(ops.copied_preparations, 0);
                assert_eq!(ops.parent_commits, 0);
                assert_eq!(ops.parent_rollbacks, 0);
                assert_eq!(ops.inventory_applies, 0);
                assert_eq!(root.kernel().registry().task_count(), 2);
                continue;
            };
            assert!(result.is_err());
            assert!(check_hvpatch_process_failpoint(phase).is_ok());
            assert_eq!(ops.copied_preparations, 1);
            assert_eq!(ops.shared_preparations, 0);
            if matches!(
                phase,
                HvpatchProcessFailpoint::ParentCopyout
                    | HvpatchProcessFailpoint::BackendCommit
                    | HvpatchProcessFailpoint::KernelCommit
            ) {
                assert_eq!(memory.0[&0x1000], 11_i32.to_le_bytes());
                assert_eq!(ops.parent_rollbacks, 1);
                assert_eq!(ops.fail_stops, 0);
                assert_eq!(root.kernel().registry().task_count(), 1);
            } else {
                assert_eq!(ops.parent_commits, 1);
                assert_eq!(ops.fail_stops, 1);
                assert_eq!(root.kernel().registry().task_count(), 2);
            }
        }

        let mut bootstrap = Memory::default();
        bootstrap.0.insert(0x3000, 33_i32.to_le_bytes().to_vec());
        install_hvpatch_process_failpoint(HvpatchProcessFailpoint::ChildSettidBootstrap);
        assert!(bootstrap_hvpatch_process_child_tid(&mut bootstrap, 0x3000, 44).is_err());
        assert_eq!(bootstrap.0[&0x3000], 33_i32.to_le_bytes());
        bootstrap_hvpatch_process_child_tid(&mut bootstrap, 0x3000, 44).unwrap();
        assert_eq!(bootstrap.0[&0x3000], 44_i32.to_le_bytes());
    }

    #[test]
    fn backend_prepare_error_does_not_double_rollback() {
        let pid = 42;
        let dispatcher = SyscallDispatcher::new();
        let (runtime, scheduler, kernel, root, process, root_generation) =
            test_carrier_graph_with_dispatcher!(pid, dispatcher);
        let root_authority = runtime
            .persistent_bindings()
            .take_submission_authority(root.thread().key(), root_generation)
            .unwrap();
        let this_tid = ThreadId::synthetic_for_tests(pid);
        let registry = Arc::new(ThreadRegistry::new(this_tid));
        let futex = Arc::new(FutexTable::new());
        let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
        let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
        let kicker: Arc<dyn VcpuRegistry> = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let mut state =
            ThreadRuntimeState::<carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Engine>::new(
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
                Arc::new(Mutex::new(Vec::new())),
                kicker,
                carrick_hal::InGuestFlag::for_guest_thread(),
                1_000,
            );
        state.service_kernel_context = Some(root.retain_exact());
        let mut memory = Memory::default();
        let need_resched = std::sync::atomic::AtomicBool::new(false);
        let mut submission = executor::ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &|_, _| unreachable!(),
            current: Some(&root_authority),
            lease: None,
            exec_replacement: None,
        };
        let mut control = executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
        let mut ops = FakeBackendOps {
            prepare_fails: true,
            ..Default::default()
        };
        let result = state.prepare_in_process_fork(
            &kernel,
            &root,
            &mut memory,
            &mut control,
            &mut ops,
            quiesce::ProcessForkAttempt {
                request: quiesce::ForkRequest {
                    flags: 0,
                    pidfd_out: None,
                    clone_parent: false,
                    parent_tid_addr: None,
                    child_tid_addr: None,
                    exit_signal: crate::linux_abi::LINUX_SIGCHLD as u32,
                    child_stack: 0,
                    vfork: None,
                },
                coordinator: None,
                external_exec: None,
            },
        );
        assert!(result.is_err());
        // Backend prepare handles its own rollback on error; caller must not roll back again.
        assert_eq!(ops.backend_prepare_rollbacks, 1);
        assert_eq!(ops.parent_rollbacks, 0);
        assert_eq!(ops.aborts, 0);
    }

    #[test]
    fn backend_staleness_after_successful_prepare_aborts_and_rolls_copied_parent_back_exactly_once()
    {
        let pid = 43;
        let dispatcher = SyscallDispatcher::new();
        let parent_context = dispatcher.capture_one_task_context().unwrap();
        let (runtime, scheduler, kernel, root, process, root_generation) =
            test_carrier_graph_with_dispatcher!(pid, dispatcher);
        let root_authority = runtime
            .persistent_bindings()
            .take_submission_authority(root.thread().key(), root_generation)
            .unwrap();
        let this_tid = ThreadId::synthetic_for_tests(pid);
        let registry = Arc::new(ThreadRegistry::new(this_tid));
        let futex = Arc::new(FutexTable::new());
        let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
        let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
        let kicker: Arc<dyn VcpuRegistry> = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let mut state =
            ThreadRuntimeState::<carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Engine>::new(
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
                Arc::new(Mutex::new(Vec::new())),
                kicker,
                carrick_hal::InGuestFlag::for_guest_thread(),
                1_000,
            );
        state.service_kernel_context = Some(root.retain_exact());
        let mut memory = Memory::default();
        let need_resched = std::sync::atomic::AtomicBool::new(false);
        let mut submission = executor::ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &|_, _| unreachable!(),
            current: Some(&root_authority),
            lease: None,
            exec_replacement: None,
        };
        let mut control = executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);

        let kernel_clone = Arc::clone(&kernel);
        let mut ops = FakeBackendOps {
            on_prepare: Some(Arc::new(move || {
                // Simulate an authority swap / revision change during prepare
                let replacement = Arc::new(
                    crate::dispatch::DispatchMmAuthority::new_for_test_with_revision(
                        crate::kernel::VmaRevision::from_authority_raw(999),
                    ),
                );
                kernel_clone
                    .dispatcher
                    .replace_current_mm_for_test(replacement);
            })),
            ..Default::default()
        };

        let result = state.prepare_in_process_fork(
            &kernel,
            &root,
            &mut memory,
            &mut control,
            &mut ops,
            quiesce::ProcessForkAttempt {
                request: quiesce::ForkRequest {
                    flags: 0,
                    pidfd_out: None,
                    clone_parent: false,
                    parent_tid_addr: None,
                    child_tid_addr: None,
                    exit_signal: crate::linux_abi::LINUX_SIGCHLD as u32,
                    child_stack: 0,
                    vfork: None,
                },
                coordinator: None,
                external_exec: None,
            },
        );
        assert!(matches!(
            result,
            Ok(quiesce::PreparedInProcessFork::Complete(Some(_)))
        ));
        // Fork lowered to EAGAIN and rolled back copied parent exactly once.
        assert_eq!(ops.aborts, 1);
        assert_eq!(ops.parent_rollbacks, 1);
        assert_eq!(ops.parent_commits, 0);
        assert_eq!(
            ops.request_parent_mm,
            Some(parent_context.shared().mm().id().raw())
        );
        assert!(ops.request_child_mm.is_some());
        assert_ne!(ops.request_parent_mm, ops.request_child_mm);
    }
}
