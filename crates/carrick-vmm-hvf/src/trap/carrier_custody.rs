//! # Carrier VM Custody and Stage-2 Authority
//!
//! Monotonic lifecycle authority over the carrier's hardware VM and its stage-2
//! address translations. Hypervisor.framework binds guest physical addresses
//! into a live VM instance; this module tracks monotonically incrementing VM
//! generations, stage-2 mapping records, active pins, and structured cleanup/
//! rollback during VM creation and destruction.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use super::*;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct PendingCarrierVmCreation {
    pub(crate) custody: std::sync::Arc<CarrierVmCustody>,
    pub(crate) generation: CarrierVmGeneration,
    pub(crate) probe_code: i32,
    pub(crate) vcpu_id: Option<applevisor_sys::hv_vcpu_t>,
    pub(crate) armed: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PendingCarrierVmCreation {
    pub(crate) fn record_vcpu(&mut self, vcpu_id: applevisor_sys::hv_vcpu_t) {
        self.vcpu_id = Some(vcpu_id);
    }

    pub(crate) fn commit(mut self) -> Result<(), TrapError> {
        if let Err(error) = self.custody.commit_create(self.generation) {
            let mut vcpu_id = self.vcpu_id.take();
            let mut raw_vm_destroyed = false;
            let cleanup_error = drive_pending_carrier_vm_cleanup(
                &self.custody,
                self.generation,
                &mut vcpu_id,
                &mut raw_vm_destroyed,
                "VM setup commit failure cleanup",
            )
            .err();
            self.armed = false;
            if cleanup_error.is_some() {
                *persistent_carrier_cell().lock() =
                    Some(PersistentCarrierCellEntry::CreateCleanup {
                        custody: std::sync::Arc::clone(&self.custody),
                        generation: self.generation,
                        vcpu_id,
                        raw_vm_destroyed,
                    });
            }
            let commit_error = custody_transition_error("VM setup", "commit_create", error);
            return Err(match cleanup_error {
                Some(cleanup_error) => TrapError::Hypervisor(format!(
                    "{commit_error}; {cleanup_error}; exact Creating cleanup retained"
                )),
                None => commit_error,
            });
        }
        record_vm_resident();
        let _ = self.custody.frame_pool();
        // `CARRIER_VM_LIVE` is published by `create_vm_with_admission` now, at
        // the moment the VM actually exists; publishing it here left a window
        // in which a VM was live but `carrier_vm_live()` still said no.
        crate::probes::vm_lifecycle(1, self.probe_code);
        self.armed = false;
        Ok(())
    }

    pub(crate) fn rollback(mut self, setup_error: TrapError) -> Result<(), TrapError> {
        let mut vcpu_id = self.vcpu_id.take();
        let mut raw_vm_destroyed = false;
        if let Err(rollback_error) = drive_pending_carrier_vm_cleanup(
            &self.custody,
            self.generation,
            &mut vcpu_id,
            &mut raw_vm_destroyed,
            "VM setup rollback",
        ) {
            self.armed = false;
            *persistent_carrier_cell().lock() = Some(PersistentCarrierCellEntry::CreateCleanup {
                custody: std::sync::Arc::clone(&self.custody),
                generation: self.generation,
                vcpu_id,
                raw_vm_destroyed,
            });
            return Err(TrapError::Hypervisor(format!(
                "VM setup failed ({setup_error}); {rollback_error}; exact Creating custody published for cleanup retry"
            )));
        }
        self.armed = false;
        Err(setup_error)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn drive_pending_carrier_vm_cleanup(
    custody: &std::sync::Arc<CarrierVmCustody>,
    generation: CarrierVmGeneration,
    vcpu_id: &mut Option<applevisor_sys::hv_vcpu_t>,
    raw_vm_destroyed: &mut bool,
    context: &str,
) -> Result<(), TrapError> {
    drive_pending_carrier_vm_cleanup_using(
        custody,
        generation,
        PendingCarrierVmCleanupState {
            vcpu_id,
            raw_vm_destroyed,
            context,
        },
        |id| unsafe { applevisor_sys::hv_vcpu_destroy(id) },
        |custody, generation, context| {
            destroy_vm_with_custody_target(
                custody,
                context,
                CarrierVmDestroyTarget::Creating(generation),
            )
        },
        finalize_carrier_exit_global_frame_owners_in,
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct PendingCarrierVmCleanupState<'a> {
    pub vcpu_id: &'a mut Option<applevisor_sys::hv_vcpu_t>,
    pub raw_vm_destroyed: &'a mut bool,
    pub context: &'a str,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn drive_pending_carrier_vm_cleanup_using(
    custody: &std::sync::Arc<CarrierVmCustody>,
    generation: CarrierVmGeneration,
    state: PendingCarrierVmCleanupState<'_>,
    mut destroy_vcpu: impl FnMut(applevisor_sys::hv_vcpu_t) -> applevisor_sys::hv_return_t,
    mut destroy_vm: impl FnMut(
        &std::sync::Arc<CarrierVmCustody>,
        CarrierVmGeneration,
        &str,
    ) -> Result<(), TrapError>,
    mut finalize_records: impl FnMut(&std::sync::Arc<CarrierVmCustody>) -> Result<(), TrapError>,
) -> Result<(), TrapError> {
    let PendingCarrierVmCleanupState {
        vcpu_id,
        raw_vm_destroyed,
        context,
    } = state;
    if let Some(id) = *vcpu_id {
        let rc = destroy_vcpu(id);
        if rc != 0 {
            return Err(TrapError::Hypervisor(format!(
                "{context}: hv_vcpu_destroy rc={rc:#x}; exact vCPU cleanup retained"
            )));
        }
        vcpu_destroyed(id);
        *vcpu_id = None;
    }
    if !*raw_vm_destroyed {
        destroy_vm(custody, generation, context)?;
        *raw_vm_destroyed = true;
    }
    finalize_records(custody).map_err(|error| {
        TrapError::Hypervisor(format!(
            "{context}: terminal setup-record cleanup failed after raw VM destroy: {error}"
        ))
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for PendingCarrierVmCreation {
    fn drop(&mut self) {
        debug_assert!(
            !self.armed,
            "pending carrier VM creation escaped without explicit commit/rollback"
        );
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn finish_pending_vm_creation<T>(
    pending: Option<PendingCarrierVmCreation>,
    result: Result<T, TrapError>,
) -> Result<T, TrapError> {
    let Some(pending) = pending else {
        return result;
    };
    match result {
        Ok(value) => {
            pending.commit()?;
            Ok(value)
        }
        Err(error) => pending.rollback(error).and_then(|()| unreachable!()),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn commit_pending_creation_before_vcpu_handoff(
    pending: &mut Option<PendingCarrierVmCreation>,
) -> Result<(), TrapError> {
    let creation = pending.take().ok_or_else(|| {
        TrapError::Hypervisor("VM creation transaction disappeared before vCPU handoff".to_owned())
    })?;
    creation.commit()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn prepare_initial_carrier_before_admission<T, U>(
    prepare_fallible_inputs: impl FnOnce() -> Result<T, TrapError>,
    acquire_vm_and_permit: impl FnOnce() -> Result<U, TrapError>,
) -> Result<(T, U), TrapError> {
    let inputs = prepare_fallible_inputs()?;
    let acquired = acquire_vm_and_permit()?;
    Ok((inputs, acquired))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum SetupVcpuCleanup {
    PendingRaw,
    LocalRaii,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct SetupVmGuard {
    vm: std::mem::ManuallyDrop<SharedVm>,
    pending_raw_cleanup: bool,
    armed: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl SetupVmGuard {
    pub(crate) fn new(vm: SharedVm, pending_raw_cleanup: bool) -> Self {
        Self {
            vm: std::mem::ManuallyDrop::new(vm),
            pending_raw_cleanup,
            armed: true,
        }
    }

    pub(crate) fn into_inner(mut self) -> SharedVm {
        self.armed = false;
        // SAFETY: `armed` prevents Drop from touching the value after this
        // single ownership transfer.
        unsafe { std::mem::ManuallyDrop::take(&mut self.vm) }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl std::ops::Deref for SetupVmGuard {
    type Target = SharedVm;

    fn deref(&self) -> &Self::Target {
        &self.vm
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for SetupVmGuard {
    fn drop(&mut self) {
        if !self.armed || self.pending_raw_cleanup {
            return;
        }
        // SAFETY: a reused carrier VM has no Pending raw cleanup owner. Drop
        // only this clone through its ordinary applevisor RAII path.
        unsafe { std::mem::ManuallyDrop::drop(&mut self.vm) };
        self.armed = false;
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct SetupVcpuGuard {
    vcpu: std::mem::ManuallyDrop<applevisor::vcpu::Vcpu>,
    cleanup: SetupVcpuCleanup,
    armed: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl SetupVcpuGuard {
    pub(crate) fn new(vcpu: applevisor::vcpu::Vcpu, cleanup: SetupVcpuCleanup) -> Self {
        Self {
            vcpu: std::mem::ManuallyDrop::new(vcpu),
            cleanup,
            armed: true,
        }
    }

    pub(crate) fn into_inner(mut self) -> applevisor::vcpu::Vcpu {
        self.armed = false;
        // SAFETY: `armed` prevents Drop from touching the value after this
        // single ownership transfer.
        unsafe { std::mem::ManuallyDrop::take(&mut self.vcpu) }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl std::ops::Deref for SetupVcpuGuard {
    type Target = applevisor::vcpu::Vcpu;

    fn deref(&self) -> &Self::Target {
        &self.vcpu
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn complete_local_vcpu_raii_cleanup(
    id: applevisor_sys::hv_vcpu_t,
    drop_wrapper: impl FnOnce(),
    record_destroyed: impl FnOnce(applevisor_sys::hv_vcpu_t),
) {
    drop_wrapper();
    record_destroyed(id);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for SetupVcpuGuard {
    fn drop(&mut self) {
        if !self.armed || self.cleanup == SetupVcpuCleanup::PendingRaw {
            return;
        }
        let id = self.vcpu.id();
        complete_local_vcpu_raii_cleanup(
            id,
            || {
                // SAFETY: the local-reuse lane has no Pending transaction. Its
                // ordinary applevisor RAII destruction remains the sole HV owner.
                unsafe { std::mem::ManuallyDrop::drop(&mut self.vcpu) };
            },
            vcpu_destroyed,
        );
        self.armed = false;
    }
}

/// Carrier-local identity for one installed Hypervisor.framework VM.
///
/// Generations are monotonically allocated by [`CarrierVmCustody`] and never
/// reused inside that carrier, so a teardown retry cannot accidentally operate
/// on a successor VM that happens to reuse the same stage-2 coordinates.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CarrierVmGeneration(pub(crate) u64);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct CarrierStage2RecordId(pub(crate) u64);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CarrierLogicalOwner {
    pub(crate) id: u64,
    pub(crate) generation: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CarrierStage2RecordSpec {
    pub(crate) vm_generation: CarrierVmGeneration,
    pub(crate) ipa: u64,
    pub(crate) len: usize,
    pub(crate) host_addr: usize,
    pub(crate) mapped: bool,
    pub(crate) backend_map_installed: bool,
    pub(crate) release_ipa: bool,
    pub(crate) perms: u64,
    pub(crate) logical_owner: Option<CarrierLogicalOwner>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CarrierStage2RecordIdentity {
    pub(crate) record_id: CarrierStage2RecordId,
    pub(crate) vm_generation: CarrierVmGeneration,
    pub(crate) logical_owner: Option<CarrierLogicalOwner>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // the real HV return adapter is wired in the next migration slice
pub(crate) enum CarrierStage2BackendError {
    HvReturn(u32),
    ConcurrentRetirement,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CarrierStage2RetireOutcome {
    RetiredUnmapped,
    DeferredActivePins,
    RetryPending(CarrierStage2BackendError),
    TerminalizedByVmDestroy,
    NotFound,
    OwnerIdentityMismatch,
    OwnerGenerationMismatch,
    VmGenerationMismatch,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CarrierStage2RecordError {
    InvalidExtent,
    NoLiveVm,
    VmGenerationMismatch,
    RecordIdExhausted,
    RecordNotFound,
    RecordNotTerminal,
    RecordIdentityMismatch,
    ReleaseInFlight,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CarrierStage2PinError {
    NotFound,
    VmNotLive,
    OwnerIdentityMismatch,
    OwnerGenerationMismatch,
    VmGenerationMismatch,
    TerminalizedByVmDestroy,
    NotMapped,
    RetirementRequested,
    PinCountExhausted,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CarrierStage2RecordSnapshot {
    pub(crate) record_id: CarrierStage2RecordId,
    pub(crate) vm_generation: CarrierVmGeneration,
    pub(crate) ipa: u64,
    pub(crate) len: usize,
    pub(crate) host_addr: usize,
    pub(crate) mapped: bool,
    pub(crate) backend_map_installed: bool,
    pub(crate) release_ipa: bool,
    pub(crate) perms: u64,
    pub(crate) logical_owner: Option<CarrierLogicalOwner>,
    pub(crate) pin_count: u64,
    pub(crate) retirement_requested: bool,
    pub(crate) retry_eligible: bool,
    pub(crate) retry_pending: Option<CarrierStage2BackendError>,
    pub(crate) terminalized_by_vm_destroy: bool,
    pub(crate) superseded_by_rebind: bool,
    pub(crate) release_in_flight: bool,
    pub(crate) release_retry_pending: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CarrierStage2Record {
    pub(crate) snapshot: CarrierStage2RecordSnapshot,
    pub(crate) unmap_in_flight: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // exercised by the lifecycle tests; wired into VM calls in the next slice
pub(crate) enum CarrierVmCustodyError {
    LifecycleConflict,
    StaleGeneration,
    GenerationExhausted,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // exercised by the lifecycle tests; wired into VM calls in the next slice
pub(crate) enum CarrierVmLifecycle {
    Vacant,
    Creating(CarrierVmGeneration),
    Live(CarrierVmGeneration),
    Destroying(CarrierVmGeneration),
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
#[allow(dead_code)] // exercised by the lifecycle tests; wired into VM calls in the next slice
pub(crate) struct CarrierVmCustodyState {
    pub(crate) next_generation: u64,
    pub(crate) lifecycle: CarrierVmLifecycle,
    pub(crate) next_stage2_record_id: u64,
    pub(crate) next_logical_owner_id: u64,
    pub(crate) next_logical_owner_generation: u64,
    pub(crate) stage2_records:
        std::collections::BTreeMap<CarrierStage2RecordId, CarrierStage2Record>,
}

/// Carrier-owned VM lifecycle authority.
///
/// The state is intentionally neither static nor process-global. A failed
/// backend destroy is represented by `abort_destroy`, which restores custody of
/// the exact generation; a successful destroy must be committed before a later
/// generation can begin creation.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
#[allow(dead_code)] // exercised by the lifecycle tests; wired into VM calls in the next slice
pub(crate) struct CarrierVmCustody {
    pub(crate) state: parking_lot::Mutex<CarrierVmCustodyState>,
    pub(crate) structural_backings: parking_lot::Mutex<
        std::collections::BTreeMap<
            CarrierStage2RecordId,
            std::sync::Arc<StructuralBackingCustodyEntry>,
        >,
    >,
    pub(crate) carrier_stage2_records:
        parking_lot::Mutex<std::collections::BTreeMap<(u64, u64), CarrierStage2RecordIdentity>>,
    pub(crate) global_frame_host_owners: GlobalFrameHostOwnerDirectory,
    pub(crate) pending_global_frame_owners: parking_lot::Mutex<
        std::collections::BTreeMap<CarrierStage2RecordId, std::sync::Arc<GlobalFrameHostOwner>>,
    >,
    pub(crate) pending_global_frame_retirement_retry: std::sync::atomic::AtomicBool,
    pub(crate) pending_global_frame_retirement_turn_in_flight: std::sync::atomic::AtomicBool,
    pub(crate) pending_global_frame_directory_retries:
        parking_lot::Mutex<PendingGlobalFrameRetirementQueue<((u64, u64), u64)>>,
    pub(crate) pending_global_frame_detached_retries:
        parking_lot::Mutex<PendingGlobalFrameRetirementQueue<CarrierStage2RecordId>>,
    pub(crate) frame_pool: parking_lot::Mutex<CarrierFramePoolState>,
    pub(crate) root_slot_pool: parking_lot::Mutex<CarrierRootSlotPoolState>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug, Default)]
pub(crate) enum CarrierFramePoolState {
    #[default]
    Uninitialized,
    Active(std::sync::Arc<crate::frame_pool::PreMappedFramePool>),
    Failed,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug, Default)]
pub(crate) enum CarrierRootSlotPoolState {
    #[default]
    Uninitialized,
    Active(std::sync::Arc<crate::frame_pool::PreMappedRootSlotPool>),
    Failed,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Default for CarrierVmCustody {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(dead_code)] // exercised by the lifecycle tests; wired into VM calls in the next slice
impl CarrierVmCustody {
    pub(crate) fn new() -> Self {
        Self {
            state: parking_lot::Mutex::new(CarrierVmCustodyState {
                next_generation: 1,
                lifecycle: CarrierVmLifecycle::Vacant,
                next_stage2_record_id: 1,
                next_logical_owner_id: 1,
                next_logical_owner_generation: 1,
                stage2_records: std::collections::BTreeMap::new(),
            }),
            structural_backings: parking_lot::Mutex::new(std::collections::BTreeMap::new()),
            carrier_stage2_records: parking_lot::Mutex::new(std::collections::BTreeMap::new()),
            global_frame_host_owners: parking_lot::Mutex::new(std::collections::BTreeMap::new()),
            pending_global_frame_owners: parking_lot::Mutex::new(std::collections::BTreeMap::new()),
            pending_global_frame_retirement_retry: std::sync::atomic::AtomicBool::new(false),
            pending_global_frame_retirement_turn_in_flight: std::sync::atomic::AtomicBool::new(
                false,
            ),
            pending_global_frame_directory_retries: parking_lot::Mutex::new(
                PendingGlobalFrameRetirementQueue::default(),
            ),
            pending_global_frame_detached_retries: parking_lot::Mutex::new(
                PendingGlobalFrameRetirementQueue::default(),
            ),
            frame_pool: parking_lot::Mutex::new(CarrierFramePoolState::Uninitialized),
            root_slot_pool: parking_lot::Mutex::new(CarrierRootSlotPoolState::Uninitialized),
        }
    }

    pub(crate) fn request_global_frame_retirement_retry(&self) {
        self.pending_global_frame_retirement_retry
            .store(true, std::sync::atomic::Ordering::Release);
    }

    pub(crate) fn enqueue_directory_global_frame_retirement(
        &self,
        key: (u64, u64),
        generation: u64,
    ) {
        self.pending_global_frame_directory_retries
            .lock()
            .enqueue((key, generation));
        self.request_global_frame_retirement_retry();
    }

    pub(crate) fn enqueue_detached_global_frame_retirement(
        &self,
        record_id: CarrierStage2RecordId,
    ) {
        self.pending_global_frame_detached_retries
            .lock()
            .enqueue(record_id);
        self.request_global_frame_retirement_retry();
    }

    pub(crate) fn take_global_frame_retirement_retry_request(&self) -> bool {
        self.pending_global_frame_retirement_retry
            .swap(false, std::sync::atomic::Ordering::AcqRel)
    }

    #[cfg(any(test, feature = "foreign-cow-test-support"))]
    pub(crate) fn new_live_fixture() -> Self {
        let custody = Self::new();
        {
            let mut state = custody.state.lock();
            state.next_generation = 2;
            state.lifecycle = CarrierVmLifecycle::Live(CarrierVmGeneration(1));
        }
        custody
    }

    pub(crate) fn begin_create(&self) -> Result<CarrierVmGeneration, CarrierVmCustodyError> {
        let mut state = self.state.lock();
        if state.lifecycle != CarrierVmLifecycle::Vacant {
            return Err(CarrierVmCustodyError::LifecycleConflict);
        }
        let next_generation = state
            .next_generation
            .checked_add(1)
            .ok_or(CarrierVmCustodyError::GenerationExhausted)?;
        let generation = CarrierVmGeneration(state.next_generation);
        state.next_generation = next_generation;
        state.lifecycle = CarrierVmLifecycle::Creating(generation);
        Ok(generation)
    }

    pub(crate) fn commit_create(
        &self,
        generation: CarrierVmGeneration,
    ) -> Result<(), CarrierVmCustodyError> {
        let mut state = self.state.lock();
        match state.lifecycle {
            CarrierVmLifecycle::Creating(current) if current == generation => {
                state.lifecycle = CarrierVmLifecycle::Live(generation);
                Ok(())
            }
            CarrierVmLifecycle::Creating(_) | CarrierVmLifecycle::Live(_) => {
                Err(CarrierVmCustodyError::StaleGeneration)
            }
            CarrierVmLifecycle::Vacant | CarrierVmLifecycle::Destroying(_) => {
                Err(CarrierVmCustodyError::LifecycleConflict)
            }
        }
    }

    pub(crate) fn abort_create(
        &self,
        generation: CarrierVmGeneration,
    ) -> Result<(), CarrierVmCustodyError> {
        let mut state = self.state.lock();
        match state.lifecycle {
            CarrierVmLifecycle::Creating(current) if current == generation => {
                state.lifecycle = CarrierVmLifecycle::Vacant;
                Ok(())
            }
            CarrierVmLifecycle::Creating(_) | CarrierVmLifecycle::Live(_) => {
                Err(CarrierVmCustodyError::StaleGeneration)
            }
            CarrierVmLifecycle::Vacant | CarrierVmLifecycle::Destroying(_) => {
                Err(CarrierVmCustodyError::LifecycleConflict)
            }
        }
    }

    pub(crate) fn abort_created_vm_after_raw_destroy(
        &self,
        generation: CarrierVmGeneration,
    ) -> Result<(), CarrierVmCustodyError> {
        let mut state = self.state.lock();
        match state.lifecycle {
            CarrierVmLifecycle::Creating(current) if current == generation => {
                for record in state
                    .stage2_records
                    .values_mut()
                    .filter(|record| record.snapshot.vm_generation == generation)
                {
                    record.snapshot.mapped = false;
                    record.snapshot.backend_map_installed = false;
                    record.snapshot.retirement_requested = true;
                    record.snapshot.retry_eligible = false;
                    record.snapshot.retry_pending = None;
                    record.snapshot.terminalized_by_vm_destroy = true;
                    record.unmap_in_flight = false;
                }
                state.lifecycle = CarrierVmLifecycle::Vacant;
                Ok(())
            }
            CarrierVmLifecycle::Creating(_) | CarrierVmLifecycle::Live(_) => {
                Err(CarrierVmCustodyError::StaleGeneration)
            }
            CarrierVmLifecycle::Vacant | CarrierVmLifecycle::Destroying(_) => {
                Err(CarrierVmCustodyError::LifecycleConflict)
            }
        }
    }

    pub(crate) fn begin_destroy(
        &self,
        generation: CarrierVmGeneration,
    ) -> Result<(), CarrierVmCustodyError> {
        let mut state = self.state.lock();
        match state.lifecycle {
            CarrierVmLifecycle::Live(current) if current == generation => {
                state.lifecycle = CarrierVmLifecycle::Destroying(generation);
                Ok(())
            }
            CarrierVmLifecycle::Live(_) => Err(CarrierVmCustodyError::StaleGeneration),
            CarrierVmLifecycle::Vacant
            | CarrierVmLifecycle::Creating(_)
            | CarrierVmLifecycle::Destroying(_) => Err(CarrierVmCustodyError::LifecycleConflict),
        }
    }

    pub(crate) fn abort_destroy(
        &self,
        generation: CarrierVmGeneration,
    ) -> Result<(), CarrierVmCustodyError> {
        let mut state = self.state.lock();
        match state.lifecycle {
            CarrierVmLifecycle::Destroying(current) if current == generation => {
                state.lifecycle = CarrierVmLifecycle::Live(generation);
                Ok(())
            }
            CarrierVmLifecycle::Destroying(_) | CarrierVmLifecycle::Live(_) => {
                Err(CarrierVmCustodyError::StaleGeneration)
            }
            CarrierVmLifecycle::Vacant | CarrierVmLifecycle::Creating(_) => {
                Err(CarrierVmCustodyError::LifecycleConflict)
            }
        }
    }

    pub(crate) fn commit_destroy(
        &self,
        generation: CarrierVmGeneration,
    ) -> Result<(), CarrierVmCustodyError> {
        let mut state = self.state.lock();
        match state.lifecycle {
            CarrierVmLifecycle::Destroying(current) if current == generation => {
                for record in state
                    .stage2_records
                    .values_mut()
                    .filter(|record| record.snapshot.vm_generation == generation)
                {
                    record.snapshot.mapped = false;
                    record.snapshot.backend_map_installed = false;
                    record.snapshot.retirement_requested = true;
                    record.snapshot.retry_eligible = false;
                    record.snapshot.retry_pending = None;
                    record.snapshot.terminalized_by_vm_destroy = true;
                    record.unmap_in_flight = false;
                }
                if let CarrierFramePoolState::Active(pool) = std::mem::replace(
                    &mut *self.frame_pool.lock(),
                    CarrierFramePoolState::Uninitialized,
                ) {
                    pool.forget_backend_mapping();
                }
                if let CarrierRootSlotPoolState::Active(pool) = std::mem::replace(
                    &mut *self.root_slot_pool.lock(),
                    CarrierRootSlotPoolState::Uninitialized,
                ) {
                    pool.forget_backend_mapping();
                }
                state.lifecycle = CarrierVmLifecycle::Vacant;
                Ok(())
            }
            CarrierVmLifecycle::Destroying(_) | CarrierVmLifecycle::Live(_) => {
                Err(CarrierVmCustodyError::StaleGeneration)
            }
            CarrierVmLifecycle::Vacant | CarrierVmLifecycle::Creating(_) => {
                Err(CarrierVmCustodyError::LifecycleConflict)
            }
        }
    }

    pub(crate) fn frame_pool(
        &self,
    ) -> Option<std::sync::Arc<crate::frame_pool::PreMappedFramePool>> {
        if !crate::frame_pool::is_frame_pool_enabled() {
            return None;
        }
        // Lock hierarchy: always read state lifecycle first without holding frame_pool,
        // so commit_destroy (which takes state then frame_pool) never deadlocks with us.
        let state = self.state.lock();
        match state.lifecycle {
            CarrierVmLifecycle::Creating(_) | CarrierVmLifecycle::Live(_) => drop(state),
            _ => return None,
        }
        let mut guard = self.frame_pool.lock();
        match &*guard {
            CarrierFramePoolState::Active(pool) => Some(std::sync::Arc::clone(pool)),
            CarrierFramePoolState::Failed => None,
            CarrierFramePoolState::Uninitialized => {
                match crate::frame_pool::PreMappedFramePool::try_new() {
                    Ok(pool) => {
                        let pool = std::sync::Arc::new(pool);
                        *guard = CarrierFramePoolState::Active(std::sync::Arc::clone(&pool));
                        Some(pool)
                    }
                    Err(error) => {
                        *guard = CarrierFramePoolState::Failed;
                        eprintln!(
                            "carrick: frame pool unavailable: {error}; COW/sparse faults use per-fault mappings"
                        );
                        None
                    }
                }
            }
        }
    }

    pub(crate) fn root_slot_pool(
        &self,
    ) -> Option<std::sync::Arc<crate::frame_pool::PreMappedRootSlotPool>> {
        if !crate::frame_pool::is_root_slot_pool_enabled() {
            return None;
        }
        // Lock hierarchy: always read state lifecycle first without holding root_slot_pool,
        // so commit_destroy (which takes state then root_slot_pool) never deadlocks with us.
        let state = self.state.lock();
        match state.lifecycle {
            CarrierVmLifecycle::Creating(_) | CarrierVmLifecycle::Live(_) => drop(state),
            _ => return None,
        }
        let mut guard = self.root_slot_pool.lock();
        match &*guard {
            CarrierRootSlotPoolState::Active(pool) => Some(std::sync::Arc::clone(pool)),
            CarrierRootSlotPoolState::Failed => None,
            CarrierRootSlotPoolState::Uninitialized => {
                match crate::frame_pool::PreMappedRootSlotPool::try_new() {
                    Ok(pool) => {
                        let pool = std::sync::Arc::new(pool);
                        *guard = CarrierRootSlotPoolState::Active(std::sync::Arc::clone(&pool));
                        Some(pool)
                    }
                    Err(error) => {
                        *guard = CarrierRootSlotPoolState::Failed;
                        eprintln!(
                            "carrick: root slot pool unavailable: {error}; stage-1 root slots use per-fork mappings"
                        );
                        None
                    }
                }
            }
        }
    }

    pub(crate) fn is_pooled_ipa(&self, ipa: u64) -> bool {
        let in_frame_pool = match &*self.frame_pool.lock() {
            CarrierFramePoolState::Active(pool) => pool.contains_ipa(ipa),
            CarrierFramePoolState::Uninitialized | CarrierFramePoolState::Failed => false,
        };
        if in_frame_pool {
            return true;
        }
        match &*self.root_slot_pool.lock() {
            CarrierRootSlotPoolState::Active(pool) => pool.contains_ipa(ipa),
            CarrierRootSlotPoolState::Uninitialized | CarrierRootSlotPoolState::Failed => false,
        }
    }

    #[cfg(test)]
    pub(crate) fn install_frame_pool(
        &self,
        pool: std::sync::Arc<crate::frame_pool::PreMappedFramePool>,
    ) {
        *self.frame_pool.lock() = CarrierFramePoolState::Active(pool);
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn install_root_slot_pool(
        &self,
        pool: std::sync::Arc<crate::frame_pool::PreMappedRootSlotPool>,
    ) {
        *self.root_slot_pool.lock() = CarrierRootSlotPoolState::Active(pool);
    }

    pub(crate) fn live_generation(&self) -> Option<CarrierVmGeneration> {
        match self.state.lock().lifecycle {
            CarrierVmLifecycle::Live(generation) => Some(generation),
            CarrierVmLifecycle::Vacant
            | CarrierVmLifecycle::Creating(_)
            | CarrierVmLifecycle::Destroying(_) => None,
        }
    }

    pub(crate) fn setup_generation(&self) -> Option<CarrierVmGeneration> {
        match self.state.lock().lifecycle {
            CarrierVmLifecycle::Creating(generation) | CarrierVmLifecycle::Live(generation) => {
                Some(generation)
            }
            CarrierVmLifecycle::Vacant | CarrierVmLifecycle::Destroying(_) => None,
        }
    }

    pub(crate) fn creating_generation(&self) -> Option<CarrierVmGeneration> {
        match self.state.lock().lifecycle {
            CarrierVmLifecycle::Creating(generation) => Some(generation),
            CarrierVmLifecycle::Vacant
            | CarrierVmLifecycle::Live(_)
            | CarrierVmLifecycle::Destroying(_) => None,
        }
    }

    pub(crate) fn stage2_record_identities(&self) -> Vec<CarrierStage2RecordIdentity> {
        self.state
            .lock()
            .stage2_records
            .iter()
            .map(|(&record_id, record)| CarrierStage2RecordIdentity {
                record_id,
                vm_generation: record.snapshot.vm_generation,
                logical_owner: record.snapshot.logical_owner,
            })
            .collect()
    }

    pub(crate) fn allocate_logical_owner(
        &self,
    ) -> Result<CarrierLogicalOwner, CarrierStage2RecordError> {
        let mut state = self.state.lock();
        let next_id = state
            .next_logical_owner_id
            .checked_add(1)
            .ok_or(CarrierStage2RecordError::RecordIdExhausted)?;
        let next_generation = state
            .next_logical_owner_generation
            .checked_add(1)
            .ok_or(CarrierStage2RecordError::RecordIdExhausted)?;
        let owner = CarrierLogicalOwner {
            id: state.next_logical_owner_id,
            generation: state.next_logical_owner_generation,
        };
        state.next_logical_owner_id = next_id;
        state.next_logical_owner_generation = next_generation;
        Ok(owner)
    }

    pub(crate) fn remove_terminal_stage2_record(
        &self,
        identity: CarrierStage2RecordIdentity,
    ) -> Option<CarrierStage2RecordSnapshot> {
        let mut state = self.state.lock();
        let record = state.stage2_records.get(&identity.record_id)?;
        if Self::stage2_identity_mismatch(record, identity).is_some()
            || record.snapshot.pin_count != 0
            || (record.snapshot.mapped && !record.snapshot.terminalized_by_vm_destroy)
        {
            return None;
        }
        state
            .stage2_records
            .remove(&identity.record_id)
            .map(|record| record.snapshot)
    }

    pub(crate) fn claim_terminal_stage2_release(
        &self,
        identity: CarrierStage2RecordIdentity,
    ) -> Result<Option<(u64, u64)>, CarrierStage2RecordError> {
        let mut state = self.state.lock();
        let record = state
            .stage2_records
            .get_mut(&identity.record_id)
            .ok_or(CarrierStage2RecordError::RecordNotFound)?;
        if Self::stage2_identity_mismatch(record, identity).is_some() {
            return Err(CarrierStage2RecordError::RecordIdentityMismatch);
        }
        if record.snapshot.pin_count != 0
            || (record.snapshot.mapped && !record.snapshot.terminalized_by_vm_destroy)
        {
            return Err(CarrierStage2RecordError::RecordNotTerminal);
        }
        if record.snapshot.release_in_flight {
            return Err(CarrierStage2RecordError::ReleaseInFlight);
        }
        if !record.snapshot.release_ipa {
            state.stage2_records.remove(&identity.record_id);
            return Ok(None);
        }
        record.snapshot.release_in_flight = true;
        record.snapshot.release_retry_pending = false;
        Ok(Some((record.snapshot.ipa, record.snapshot.len as u64)))
    }

    pub(crate) fn commit_terminal_stage2_release(&self, identity: CarrierStage2RecordIdentity) {
        let mut state = self.state.lock();
        let removable = state
            .stage2_records
            .get(&identity.record_id)
            .is_some_and(|record| {
                Self::stage2_identity_mismatch(record, identity).is_none()
                    && record.snapshot.release_in_flight
                    && record.snapshot.release_ipa
            });
        debug_assert!(
            removable,
            "claimed terminal release identity must remain stable"
        );
        if removable {
            state.stage2_records.remove(&identity.record_id);
        }
    }

    pub(crate) fn abort_terminal_stage2_release(&self, identity: CarrierStage2RecordIdentity) {
        let mut state = self.state.lock();
        let Some(record) = state.stage2_records.get_mut(&identity.record_id) else {
            debug_assert!(false, "claimed terminal release record disappeared");
            return;
        };
        debug_assert!(Self::stage2_identity_mismatch(record, identity).is_none());
        record.snapshot.release_in_flight = false;
        record.snapshot.release_retry_pending = true;
    }

    #[cfg(test)]
    pub(crate) fn pending_global_frame_owner_count(&self) -> usize {
        self.pending_global_frame_owners.lock().len()
    }

    #[cfg(test)]
    pub(crate) fn disarm_stage2_backend_map_for_test(&self, identity: CarrierStage2RecordIdentity) {
        let mut state = self.state.lock();
        let record = state
            .stage2_records
            .get_mut(&identity.record_id)
            .unwrap_or_else(|| panic!("missing test stage-2 record"));
        assert!(
            Self::stage2_identity_mismatch(record, identity).is_none(),
            "test stage-2 record identity drifted"
        );
        record.snapshot.backend_map_installed = false;
    }

    pub(crate) fn register_stage2_record(
        &self,
        spec: CarrierStage2RecordSpec,
    ) -> Result<CarrierStage2RecordIdentity, CarrierStage2RecordError> {
        if spec.len == 0 || (spec.mapped && spec.host_addr == 0) {
            return Err(CarrierStage2RecordError::InvalidExtent);
        }
        let mut state = self.state.lock();
        match state.lifecycle {
            CarrierVmLifecycle::Creating(generation) | CarrierVmLifecycle::Live(generation)
                if generation == spec.vm_generation => {}
            CarrierVmLifecycle::Creating(_) | CarrierVmLifecycle::Live(_) => {
                return Err(CarrierStage2RecordError::VmGenerationMismatch);
            }
            CarrierVmLifecycle::Vacant | CarrierVmLifecycle::Destroying(_) => {
                return Err(CarrierStage2RecordError::NoLiveVm);
            }
        }
        let next_id = state
            .next_stage2_record_id
            .checked_add(1)
            .ok_or(CarrierStage2RecordError::RecordIdExhausted)?;
        let record_id = CarrierStage2RecordId(state.next_stage2_record_id);
        state.next_stage2_record_id = next_id;
        let identity = CarrierStage2RecordIdentity {
            record_id,
            vm_generation: spec.vm_generation,
            logical_owner: spec.logical_owner,
        };
        state.stage2_records.insert(
            record_id,
            CarrierStage2Record {
                snapshot: CarrierStage2RecordSnapshot {
                    record_id,
                    vm_generation: spec.vm_generation,
                    ipa: spec.ipa,
                    len: spec.len,
                    host_addr: spec.host_addr,
                    mapped: spec.mapped,
                    backend_map_installed: spec.backend_map_installed,
                    release_ipa: spec.release_ipa,
                    perms: spec.perms,
                    logical_owner: spec.logical_owner,
                    pin_count: 0,
                    retirement_requested: false,
                    retry_eligible: false,
                    retry_pending: None,
                    terminalized_by_vm_destroy: false,
                    superseded_by_rebind: false,
                    release_in_flight: false,
                    release_retry_pending: false,
                },
                unmap_in_flight: false,
            },
        );
        Ok(identity)
    }

    pub(crate) fn rebind_terminal_stage2_record(
        &self,
        old_identity: CarrierStage2RecordIdentity,
        host_addr: usize,
        perms: u64,
    ) -> Result<CarrierStage2RecordIdentity, CarrierStage2RecordError> {
        let mut state = self.state.lock();
        let live_generation = match state.lifecycle {
            CarrierVmLifecycle::Creating(generation) | CarrierVmLifecycle::Live(generation) => {
                generation
            }
            CarrierVmLifecycle::Vacant | CarrierVmLifecycle::Destroying(_) => {
                return Err(CarrierStage2RecordError::NoLiveVm);
            }
        };
        let old = state
            .stage2_records
            .get(&old_identity.record_id)
            .copied()
            .ok_or(CarrierStage2RecordError::RecordNotFound)?;
        if Self::stage2_identity_mismatch(&old, old_identity).is_some() {
            return Err(CarrierStage2RecordError::RecordIdentityMismatch);
        }
        if !old.snapshot.terminalized_by_vm_destroy || old.snapshot.mapped {
            return Err(CarrierStage2RecordError::RecordNotTerminal);
        }
        if old.snapshot.release_in_flight {
            return Err(CarrierStage2RecordError::ReleaseInFlight);
        }
        if old.snapshot.vm_generation == live_generation {
            return Err(CarrierStage2RecordError::VmGenerationMismatch);
        }
        if host_addr == 0 || host_addr != old.snapshot.host_addr {
            return Err(CarrierStage2RecordError::InvalidExtent);
        }
        let next_id = state
            .next_stage2_record_id
            .checked_add(1)
            .ok_or(CarrierStage2RecordError::RecordIdExhausted)?;
        let record_id = CarrierStage2RecordId(state.next_stage2_record_id);
        state.next_stage2_record_id = next_id;
        let identity = CarrierStage2RecordIdentity {
            record_id,
            vm_generation: live_generation,
            logical_owner: old_identity.logical_owner,
        };
        state.stage2_records.insert(
            record_id,
            CarrierStage2Record {
                snapshot: CarrierStage2RecordSnapshot {
                    record_id,
                    vm_generation: live_generation,
                    ipa: old.snapshot.ipa,
                    len: old.snapshot.len,
                    host_addr,
                    mapped: true,
                    backend_map_installed: true,
                    release_ipa: old.snapshot.release_ipa,
                    perms,
                    logical_owner: old.snapshot.logical_owner,
                    pin_count: 0,
                    retirement_requested: false,
                    retry_eligible: false,
                    retry_pending: None,
                    terminalized_by_vm_destroy: false,
                    superseded_by_rebind: false,
                    release_in_flight: false,
                    release_retry_pending: false,
                },
                unmap_in_flight: false,
            },
        );
        let old = state
            .stage2_records
            .get_mut(&old_identity.record_id)
            .ok_or(CarrierStage2RecordError::RecordNotFound)?;
        old.snapshot.release_ipa = false;
        old.snapshot.superseded_by_rebind = true;
        Ok(identity)
    }

    pub(crate) fn stage2_record_snapshot(
        &self,
        record_id: CarrierStage2RecordId,
    ) -> Option<CarrierStage2RecordSnapshot> {
        self.state
            .lock()
            .stage2_records
            .get(&record_id)
            .map(|record| record.snapshot)
    }

    pub(crate) fn stage2_identity_mismatch(
        record: &CarrierStage2Record,
        identity: CarrierStage2RecordIdentity,
    ) -> Option<CarrierStage2RetireOutcome> {
        if record.snapshot.vm_generation != identity.vm_generation {
            return Some(CarrierStage2RetireOutcome::VmGenerationMismatch);
        }
        match (record.snapshot.logical_owner, identity.logical_owner) {
            (Some(expected), Some(actual)) if expected.id != actual.id => {
                Some(CarrierStage2RetireOutcome::OwnerIdentityMismatch)
            }
            (Some(expected), Some(actual)) if expected.generation != actual.generation => {
                Some(CarrierStage2RetireOutcome::OwnerGenerationMismatch)
            }
            (None, None) | (Some(_), Some(_)) => None,
            (None, Some(_)) | (Some(_), None) => {
                Some(CarrierStage2RetireOutcome::OwnerIdentityMismatch)
            }
        }
    }

    pub(crate) fn pin_stage2_record(
        self: &std::sync::Arc<Self>,
        identity: CarrierStage2RecordIdentity,
    ) -> Result<CarrierStage2Pin, CarrierStage2PinError> {
        let mut state = self.state.lock();
        match state.lifecycle {
            CarrierVmLifecycle::Live(generation) if generation == identity.vm_generation => {}
            CarrierVmLifecycle::Live(_) => {
                return Err(CarrierStage2PinError::VmGenerationMismatch);
            }
            CarrierVmLifecycle::Vacant
            | CarrierVmLifecycle::Creating(_)
            | CarrierVmLifecycle::Destroying(_) => {
                return Err(CarrierStage2PinError::VmNotLive);
            }
        }
        let record = state
            .stage2_records
            .get_mut(&identity.record_id)
            .ok_or(CarrierStage2PinError::NotFound)?;
        if let Some(mismatch) = Self::stage2_identity_mismatch(record, identity) {
            return Err(match mismatch {
                CarrierStage2RetireOutcome::VmGenerationMismatch => {
                    CarrierStage2PinError::VmGenerationMismatch
                }
                CarrierStage2RetireOutcome::OwnerIdentityMismatch => {
                    CarrierStage2PinError::OwnerIdentityMismatch
                }
                CarrierStage2RetireOutcome::OwnerGenerationMismatch => {
                    CarrierStage2PinError::OwnerGenerationMismatch
                }
                _ => CarrierStage2PinError::NotFound,
            });
        }
        if record.snapshot.terminalized_by_vm_destroy {
            return Err(CarrierStage2PinError::TerminalizedByVmDestroy);
        }
        if record.snapshot.retirement_requested || record.unmap_in_flight {
            return Err(CarrierStage2PinError::RetirementRequested);
        }
        if !record.snapshot.mapped {
            return Err(CarrierStage2PinError::NotMapped);
        }
        record.snapshot.pin_count = record
            .snapshot
            .pin_count
            .checked_add(1)
            .ok_or(CarrierStage2PinError::PinCountExhausted)?;
        Ok(CarrierStage2Pin {
            custody: std::sync::Arc::clone(self),
            identity,
            active: true,
        })
    }

    pub(crate) fn request_stage2_record_retirement(
        &self,
        identity: CarrierStage2RecordIdentity,
    ) -> CarrierStage2RetireOutcome {
        let mut state = self.state.lock();
        let Some(record) = state.stage2_records.get_mut(&identity.record_id) else {
            return CarrierStage2RetireOutcome::NotFound;
        };
        if let Some(mismatch) = Self::stage2_identity_mismatch(record, identity) {
            return mismatch;
        }
        if record.snapshot.terminalized_by_vm_destroy {
            return CarrierStage2RetireOutcome::TerminalizedByVmDestroy;
        }
        record.snapshot.retirement_requested = true;
        record.snapshot.retry_eligible = record.snapshot.pin_count == 0;
        CarrierStage2RetireOutcome::DeferredActivePins
    }

    pub(crate) fn retire_stage2_record_using(
        &self,
        identity: CarrierStage2RecordIdentity,
        unmap: impl FnOnce(u64, usize) -> Result<(), CarrierStage2BackendError>,
    ) -> CarrierStage2RetireOutcome {
        let (ipa, len) = {
            let mut state = self.state.lock();
            let Some(record) = state.stage2_records.get_mut(&identity.record_id) else {
                return CarrierStage2RetireOutcome::NotFound;
            };
            if let Some(mismatch) = Self::stage2_identity_mismatch(record, identity) {
                return mismatch;
            }
            if record.snapshot.terminalized_by_vm_destroy {
                return CarrierStage2RetireOutcome::TerminalizedByVmDestroy;
            }
            record.snapshot.retirement_requested = true;
            if record.snapshot.pin_count != 0 {
                record.snapshot.retry_eligible = false;
                return CarrierStage2RetireOutcome::DeferredActivePins;
            }
            if !record.snapshot.mapped {
                record.snapshot.retry_eligible = false;
                record.snapshot.retry_pending = None;
                return CarrierStage2RetireOutcome::RetiredUnmapped;
            }
            if record.unmap_in_flight {
                return CarrierStage2RetireOutcome::RetryPending(
                    CarrierStage2BackendError::ConcurrentRetirement,
                );
            }
            if !record.snapshot.backend_map_installed {
                record.snapshot.mapped = false;
                record.snapshot.retry_eligible = false;
                record.snapshot.retry_pending = None;
                return CarrierStage2RetireOutcome::RetiredUnmapped;
            }
            record.unmap_in_flight = true;
            record.snapshot.retry_eligible = false;
            (record.snapshot.ipa, record.snapshot.len)
        };

        let backend_result = unmap(ipa, len);
        let mut state = self.state.lock();
        let Some(record) = state.stage2_records.get_mut(&identity.record_id) else {
            return CarrierStage2RetireOutcome::NotFound;
        };
        if let Some(mismatch) = Self::stage2_identity_mismatch(record, identity) {
            return mismatch;
        }
        record.unmap_in_flight = false;
        if record.snapshot.terminalized_by_vm_destroy {
            return CarrierStage2RetireOutcome::TerminalizedByVmDestroy;
        }
        match backend_result {
            Ok(()) => {
                record.snapshot.mapped = false;
                record.snapshot.backend_map_installed = false;
                record.snapshot.retry_eligible = false;
                record.snapshot.retry_pending = None;
                CarrierStage2RetireOutcome::RetiredUnmapped
            }
            Err(error) => {
                record.snapshot.retry_eligible = true;
                record.snapshot.retry_pending = Some(error);
                CarrierStage2RetireOutcome::RetryPending(error)
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct CarrierStage2Pin {
    custody: std::sync::Arc<CarrierVmCustody>,
    identity: CarrierStage2RecordIdentity,
    active: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for CarrierStage2Pin {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.custody.state.lock();
        let Some(record) = state.stage2_records.get_mut(&self.identity.record_id) else {
            return;
        };
        if CarrierVmCustody::stage2_identity_mismatch(record, self.identity).is_some() {
            return;
        }
        record.snapshot.pin_count = record.snapshot.pin_count.saturating_sub(1);
        if record.snapshot.pin_count == 0
            && record.snapshot.retirement_requested
            && record.snapshot.mapped
            && !record.snapshot.terminalized_by_vm_destroy
        {
            record.snapshot.retry_eligible = true;
        }
        let remove_terminal_predecessor = record.snapshot.pin_count == 0
            && record.snapshot.terminalized_by_vm_destroy
            && record.snapshot.superseded_by_rebind;
        if remove_terminal_predecessor {
            state.stage2_records.remove(&self.identity.record_id);
        }
        self.active = false;
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn custody_transition_error(
    context: &str,
    transition: &str,
    error: CarrierVmCustodyError,
) -> TrapError {
    TrapError::Hypervisor(format!(
        "{context}: carrier VM custody {transition} failed: {error:?}"
    ))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg(test)]
pub(crate) fn create_vm_with_custody_using<T>(
    custody: &CarrierVmCustody,
    context: &str,
    create: impl FnOnce() -> Result<T, TrapError>,
    record_created: impl FnOnce(),
) -> Result<T, TrapError> {
    let generation = custody
        .begin_create()
        .map_err(|error| custody_transition_error(context, "begin_create", error))?;
    match create() {
        Ok(vm) => {
            custody
                .commit_create(generation)
                .map_err(|error| custody_transition_error(context, "commit_create", error))?;
            record_created();
            Ok(vm)
        }
        Err(error) => {
            custody
                .abort_create(generation)
                .map_err(|error| custody_transition_error(context, "abort_create", error))?;
            Err(error)
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg(test)]
pub(crate) fn destroy_vm_with_custody_using(
    custody: &CarrierVmCustody,
    context: &str,
    destroy: impl FnOnce() -> applevisor_sys::hv_return_t,
    record_released: impl FnOnce(),
) -> Result<(), TrapError> {
    let generation = custody.live_generation().ok_or_else(|| {
        TrapError::Hypervisor(format!(
            "{context}: carrier VM custody has no live generation"
        ))
    })?;
    custody
        .begin_destroy(generation)
        .map_err(|error| custody_transition_error(context, "begin_destroy", error))?;
    let rc = destroy();
    if rc != 0 {
        custody
            .abort_destroy(generation)
            .map_err(|error| custody_transition_error(context, "abort_destroy", error))?;
        return Err(TrapError::Hypervisor(format!(
            "{context}: hv_vm_destroy rc={rc:#x}"
        )));
    }
    custody
        .commit_destroy(generation)
        .map_err(|error| custody_transition_error(context, "commit_destroy", error))?;
    record_released();
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn destroy_vm_with_custody(
    custody: &CarrierVmCustody,
    context: &str,
) -> Result<(), TrapError> {
    destroy_vm_with_custody_target(custody, context, CarrierVmDestroyTarget::Live)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy)]
pub(crate) enum CarrierVmDestroyTarget {
    Live,
    Creating(CarrierVmGeneration),
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn destroy_vm_with_custody_target(
    custody: &CarrierVmCustody,
    context: &str,
    target: CarrierVmDestroyTarget,
) -> Result<(), TrapError> {
    let generation = match target {
        CarrierVmDestroyTarget::Live => {
            let generation = custody.live_generation().ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "{context}: carrier VM custody has no live generation"
                ))
            })?;
            custody
                .begin_destroy(generation)
                .map_err(|error| custody_transition_error(context, "begin_destroy", error))?;
            crate::probes::vm_lifecycle(2, -1);
            generation
        }
        CarrierVmDestroyTarget::Creating(generation) => {
            if custody.creating_generation() != Some(generation) {
                return Err(TrapError::Hypervisor(format!(
                    "{context}: carrier VM custody has no exact Creating generation {generation:?}"
                )));
            }
            generation
        }
    };

    let rc = unsafe { inventory_hv_vm_destroy() };
    if rc != 0 {
        if matches!(target, CarrierVmDestroyTarget::Live) {
            custody
                .abort_destroy(generation)
                .map_err(|error| custody_transition_error(context, "abort_destroy", error))?;
        }
        let retained = match target {
            CarrierVmDestroyTarget::Live => "exact Live custody restored",
            CarrierVmDestroyTarget::Creating(_) => "exact Creating custody retained",
        };
        return Err(TrapError::Hypervisor(format!(
            "{context}: hv_vm_destroy rc={rc:#x}; {retained}"
        )));
    }

    match target {
        CarrierVmDestroyTarget::Live => {
            custody
                .commit_destroy(generation)
                .map_err(|error| custody_transition_error(context, "commit_destroy", error))?;
            record_vm_released();
            Ok(())
        }
        CarrierVmDestroyTarget::Creating(_) => custody
            .abort_created_vm_after_raw_destroy(generation)
            .map_err(|error| custody_transition_error(context, "abort_created_vm", error)),
    }
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod carrier_vm_custody_tests {
    use super::{
        CarrierLogicalOwner, CarrierStage2BackendError, CarrierStage2PinError,
        CarrierStage2RecordIdentity, CarrierStage2RecordSpec, CarrierStage2RetireOutcome,
        CarrierVmCustody, CarrierVmCustodyError, CarrierVmGeneration, create_vm_with_custody_using,
        destroy_vm_with_custody_using,
    };

    #[allow(clippy::expect_used)]
    fn live_custody() -> (std::sync::Arc<CarrierVmCustody>, CarrierVmGeneration) {
        let custody = std::sync::Arc::new(CarrierVmCustody::new());
        let generation = custody.begin_create().expect("begin VM create");
        custody
            .commit_create(generation)
            .expect("publish VM generation");
        (custody, generation)
    }

    fn stage2_spec(
        vm_generation: CarrierVmGeneration,
        owner_generation: u64,
    ) -> CarrierStage2RecordSpec {
        CarrierStage2RecordSpec {
            vm_generation,
            ipa: 0x4000,
            len: 0x4000,
            host_addr: 0x1234_0000,
            mapped: true,
            backend_map_installed: true,
            release_ipa: true,
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            logical_owner: Some(CarrierLogicalOwner {
                id: 7,
                generation: owner_generation,
            }),
        }
    }

    #[test]
    fn global_frame_owner_directory_is_isolated_per_carrier_custody() {
        let (first, _) = live_custody();
        let (second, _) = live_custody();
        let key = (0xa081_0000_0000, 0x4000);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate carrier-local owner backing");
        let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        lease.mark_test_mapped_without_backend();
        super::register_global_frame_host_owner_in(
            &first,
            lease,
            mapping,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .expect("register carrier-local owner");

        assert!(first.global_frame_host_owners.lock().contains_key(&key));
        assert!(second.global_frame_host_owners.lock().is_empty());
    }

    #[test]
    fn production_global_frame_owner_operations_require_carrier_custody_static_audit() {
        let source = concat!(include_str!("../trap.rs"), include_str!("global_frame.rs"));
        let legacy_directory = concat!(
            "#[cfg(all(test, target_os = \"macos\", target_arch = \"aarch64\"))]\n",
            "fn global_frame_host_owners() -> &'static GlobalFrameHostOwnerDirectory"
        );
        assert!(
            source.contains(legacy_directory),
            "the legacy process-global-shaped owner directory must remain cfg(test)-only"
        );

        for operation in [
            "global_frame_host_owner_generation_in",
            "global_frame_host_owner_identity_in",
            "register_global_frame_host_owner_in",
            "publish_exec_region_host_owner_in",
            "retire_global_frame_host_owner_in",
            "retire_global_frame_host_owner_if_generation_in",
            "reconcile_global_frame_owners_after_replay_in",
            "global_frame_host_owner_matches_in",
            "copy_from_global_frame_owner_in",
            "global_frame_region_owner_matches_in",
            "carrier_frame_cow_owner_inventory_in",
        ] {
            let marker = format!("fn {operation}(");
            let signature = source
                .split(&marker)
                .nth(1)
                .and_then(|tail| tail.split('{').next())
                .unwrap_or_else(|| panic!("missing production owner operation `{operation}`"));
            assert!(
                signature.contains("custody:"),
                "production owner operation `{operation}` must receive carrier custody explicitly"
            );
        }
    }

    #[test]
    fn executor_cleanup_funnels_guarantee_a_post_drop_idle_maintenance_turn_static_audit() {
        let source = include_str!("../../../carrick-runtime/src/vcpu_loop/executor.rs");
        let exec_cleanup = source
            .split("let exec_cleanup_ran =")
            .nth(1)
            .and_then(|tail| {
                tail.split("if let Some(retirement) = terminal_retirement")
                    .next()
            })
            .expect("exec cleanup lifecycle slice");
        assert!(
            exec_cleanup.contains("boundary.audit_runtime(backend)"),
            "exec predecessor cleanup must run the idle maintenance boundary after Drop",
        );
        assert!(
            exec_cleanup.contains("fail_running_and_retire::<F::TaskBinding"),
            "a failed post-exec audit must settle the still-running task",
        );

        let terminal_cleanup = source.split("drop(_topology);").find(|tail| {
            tail.contains("terminal registration")
                && tail.contains("boundary.audit_runtime(backend)")
        });
        assert!(
            terminal_cleanup.is_some(),
            "terminal cleanup must release topology before its idle maintenance boundary",
        );
        assert!(
            terminal_cleanup
                .is_some_and(|tail| { tail.contains("fail_running_and_retire::<F::TaskBinding") }),
            "a failed post-terminal audit must settle the still-running task",
        );
    }

    #[test]
    fn vm_rebuild_funnels_reconcile_owner_generation_before_guest_entry_static_audit() {
        let source = concat!(
            include_str!("../trap.rs"),
            include_str!("mapping_plan.rs"),
            include_str!("persistent_executor.rs")
        );
        let shared_wait = source
            .split(concat!("pub(crate) fn shared_wait_", "resume("))
            .nth(1)
            .and_then(|tail| {
                tail.split(concat!("pub(crate) fn destroy_vcpu_", "on_thread_exit"))
                    .next()
            })
            .expect("shared-wait resume body");
        let shared_rebind = shared_wait
            .rfind("reconcile_global_frame_owners_after_replay_in(")
            .expect("shared-wait owner rebind");
        let shared_entry = shared_wait
            .find("self.reacquire_mailbox_after_vcpu_create")
            .expect("shared-wait guest-entry preparation");
        assert!(shared_rebind < shared_entry);

        let initial = source
            .split(concat!("fn new_with_", "plan_inner("))
            .nth(1)
            .and_then(|tail| {
                tail.split("/// Volatile copy out of guest-shared memory")
                    .next()
            })
            .expect("initial carrier creation body");
        let initial_rebind = initial
            .find("reconcile_global_frame_owners_after_replay_in(")
            .expect("initial carrier owner reconciliation");
        let initial_entry = initial
            .find("// Start PC:")
            .expect("initial guest entry setup");
        assert!(initial_rebind < initial_entry);

        let exec = include_str!("execve_rebuild.rs")
            .split(concat!("pub(crate) fn execve_", "rebuild("))
            .nth(1)
            .expect("exec rebuild body");
        assert!(
            exec.matches("reconcile_global_frame_owners_after_replay_in(")
                .count()
                >= 2,
            "exec must retire terminal predecessor owners and audit replayed successors"
        );

        let carrier_exit = source
            .split(concat!("pub fn destroy_persistent_vm_", "at_carrier_exit("))
            .nth(1)
            .and_then(|tail| {
                tail.split(concat!("pub fn atomic_permit_", "enabled("))
                    .next()
            })
            .expect("carrier-exit destroy body");
        assert!(!carrier_exit.contains("drain_and_retry_pending_global_frame_retirements_in"));
        let raw_destroy = carrier_exit
            .find("destroy_vm_with_custody")
            .expect("carrier-exit raw destroy");
        let terminal_cleanup = carrier_exit
            .rfind("finalize_carrier_exit_global_frame_owners_in(&custody)")
            .expect("carrier-exit terminal owner cleanup");
        assert!(raw_destroy < terminal_cleanup);
        assert!(
            !carrier_exit.contains("let _ = finalize_carrier_exit_global_frame_owners_in"),
            "carrier exit must propagate terminal cleanup failure"
        );
    }

    #[test]
    fn global_owner_late_final_pin_defers_persistent_failure_without_abort_then_retries() {
        let (custody, _) = live_custody();
        let key = (0xa081_1000_0000, 0x4000);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate pinned global owner backing");
        let host_addr = mapping.as_ptr() as usize;
        let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        lease.mark_mapped();
        let generation = super::register_global_frame_host_owner_in(
            &custody,
            lease,
            mapping,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .expect("register pinned global owner");
        let exact_owner =
            std::sync::Arc::clone(custody.global_frame_host_owners.lock()[&key].owner());
        let pin = custody.global_frame_host_owners.lock()[&key]
            .owner()
            .pin()
            .expect("pin exact global owner record");
        let retained_lease = super::CarrierFrameCowOwnerLease {
            key,
            pin,
            generation: carrick_hal::ForeignOwnerGeneration::from_backend_counter(
                std::num::NonZeroU64::new(generation).expect("nonzero owner generation"),
            ),
        };
        let mut unmap_calls = 0_u32;

        assert!(matches!(
            super::retire_global_frame_host_owner_if_generation_in_using(
                &custody,
                key.0,
                key.1,
                generation,
                &mut |_, _| {
                    unmap_calls += 1;
                    Ok(())
                },
            ),
            super::GlobalFrameRetirementOutcome::DeferredActivePins { .. }
        ));
        assert_eq!(unmap_calls, 0);
        assert!(super::alias_backing_is_live(host_addr));
        assert!(
            !carrick_hal::FrameCowOwnerLease::is_current(&retained_lease),
            "a lease retained before retirement must stop authenticating once pending is published"
        );

        drop(retained_lease);
        let injected = super::CarrierStage2BackendError::HvReturn(0xfae9_4001);
        assert!(matches!(
            super::retire_global_frame_host_owner_if_generation_in_using(
                &custody,
                key.0,
                key.1,
                generation,
                &mut |_, _| {
                    unmap_calls += 1;
                    Err(injected)
                },
            ),
            super::GlobalFrameRetirementOutcome::RetryPending { .. }
        ));
        assert_eq!(unmap_calls, 1);
        assert!(super::alias_backing_is_live(host_addr));
        {
            let owners = custody.global_frame_host_owners.lock();
            match owners.get(&key) {
                Some(super::GlobalFrameOwnerEntry::RetirementPending {
                    owner,
                    error: Some(error),
                    ..
                }) if std::sync::Arc::ptr_eq(owner, &exact_owner) => {
                    assert!(error.contains("HvReturn"));
                }
                other => panic!(
                    "failed backend retirement must preserve the exact pending owner and error, got {other:?}"
                ),
            }
        }

        let replacement_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate refused pending-owner replacement");
        let mut replacement_lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        replacement_lease.mark_test_mapped_without_backend();
        assert!(
            super::register_global_frame_host_owner_in_using(
                &custody,
                replacement_lease,
                replacement_mapping,
                u64::from(applevisor::memory::MemPerms::ReadWrite),
                &mut |_, _| Ok(()),
            )
            .is_err(),
            "a successor must not replace an exact owner with pending backend retirement"
        );
        assert!(matches!(
            custody.global_frame_host_owners.lock().get(&key),
            Some(super::GlobalFrameOwnerEntry::RetirementPending { owner, .. })
                if std::sync::Arc::ptr_eq(owner, &exact_owner)
        ));
        drop(exact_owner);

        assert!(matches!(
            super::retire_global_frame_host_owner_if_generation_in_using(
                &custody,
                key.0,
                key.1,
                generation,
                &mut |_, _| {
                    unmap_calls += 1;
                    Ok(())
                },
            ),
            super::GlobalFrameRetirementOutcome::RetiredUnmapped { .. }
        ));
        assert_eq!(unmap_calls, 2);
        assert!(!super::alias_backing_is_live(host_addr));
    }

    #[test]
    fn global_owner_retirement_publishes_pending_before_backend_unmap_without_holding_directory() {
        let (custody, _) = live_custody();
        let key = (0xa081_1800_0000, 0x4000);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate global owner retirement lock-order fixture");
        let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        lease.mark_mapped();
        let generation = super::register_global_frame_host_owner_in(
            &custody,
            lease,
            mapping,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .expect("register global owner retirement lock-order fixture");
        let exact_owner =
            std::sync::Arc::clone(custody.global_frame_host_owners.lock()[&key].owner());

        let outcome = super::retire_global_frame_host_owner_if_generation_in_using(
            &custody,
            key.0,
            key.1,
            generation,
            &mut |ipa, len| {
                assert_eq!((ipa, len as u64), key);
                let owners = custody
                    .global_frame_host_owners
                    .try_lock()
                    .expect("backend unmap must run without holding the owner directory");
                match owners.get(&key) {
                    Some(super::GlobalFrameOwnerEntry::RetirementPending {
                        owner,
                        error: None,
                        in_flight: true,
                    }) if std::sync::Arc::ptr_eq(owner, &exact_owner) => {}
                    other => panic!(
                        "backend unmap must observe the exact owner published pending, got {other:?}"
                    ),
                }
                assert!(
                    !owners
                        .get(&key)
                        .is_some_and(|entry| entry.is_live_exact(&exact_owner)),
                    "the shared live-owner predicate must reject pending"
                );
                drop(owners);
                assert!(
                    matches!(
                        exact_owner.pin(),
                        Err(super::CarrierStage2PinError::RetirementRequested)
                    ),
                    "a pre-cloned owner Arc must not admit a pin after pending publication"
                );
                let mut nested_unmap_calls = 0_u32;
                assert!(matches!(
                    super::retire_global_frame_host_owner_if_generation_in_using(
                        &custody,
                        key.0,
                        key.1,
                        generation,
                        &mut |_, _| {
                            nested_unmap_calls += 1;
                            Ok(())
                        },
                    ),
                    super::GlobalFrameRetirementOutcome::RetryPending { .. }
                ));
                assert_eq!(
                    nested_unmap_calls, 0,
                    "a second ordinary retirement cannot enter backend unmap while the claimant is active"
                );
                assert_eq!(
                    super::global_frame_host_owner_identity_in(&custody, key.0, key.1),
                    None,
                    "pending retirement must not publish a live owner identity"
                );
                assert!(
                    !super::global_frame_host_owner_matches_in(
                        &custody,
                        key.0,
                        key.1,
                        exact_owner.host_addr(),
                        exact_owner.generation(),
                    ),
                    "pending retirement must not authenticate a mapping row"
                );
                let mut copied = [0_u8; 1];
                assert_eq!(
                    super::copy_from_global_frame_owner_in(&custody, key.0, &mut copied),
                    None,
                    "pending retirement must not remain copyable"
                );
                let inventory = super::CarrierFrameCowOwnerInventory {
                    custody: std::sync::Arc::clone(&custody),
                };
                let length = carrick_hal::FrameLength::from_mapping_extent(
                    std::num::NonZeroU64::new(key.1).unwrap(),
                );
                assert!(
                    carrick_hal::FrameCowOwnerInventory::retain_current(
                        &inventory,
                        carrick_guest_mem::Gpa(key.0),
                        length,
                    )
                    .is_err(),
                    "pending retirement must not admit a new COW owner pin"
                );
                Ok(())
            },
        );
        assert!(matches!(
            outcome,
            super::GlobalFrameRetirementOutcome::RetiredUnmapped { .. }
        ));
        assert!(
            !custody.global_frame_host_owners.lock().contains_key(&key),
            "successful retirement must remove the exact pending slot"
        );
    }

    #[test]
    fn later_exact_retirement_retries_a_transient_backend_failure_once() {
        let (custody, _) = live_custody();
        let key = (0xa081_1a00_0000, 0x4000);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate exclusive retirement fixture");
        let host_addr = mapping.as_ptr() as usize;
        let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        lease.mark_mapped();
        let generation = super::register_global_frame_host_owner_in(
            &custody,
            lease,
            mapping,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .expect("register exclusive retirement fixture");
        let injected = super::CarrierStage2BackendError::HvReturn(0xfae9_4001);
        let mut first_calls = 0_u32;
        assert!(matches!(
            super::retire_global_frame_host_owner_if_generation_in_using(
                &custody,
                key.0,
                key.1,
                generation,
                &mut |_, _| {
                    first_calls += 1;
                    Err(injected)
                },
            ),
            super::GlobalFrameRetirementOutcome::RetryPending { .. }
        ));
        assert_eq!(first_calls, 1);

        let mut retry_calls = 0_u32;
        assert!(matches!(
            super::retire_global_frame_host_owner_if_generation_in_using(
                &custody,
                key.0,
                key.1,
                generation,
                &mut |_, _| {
                    retry_calls += 1;
                    Ok(())
                },
            ),
            super::GlobalFrameRetirementOutcome::RetiredUnmapped { .. }
        ));
        assert_eq!(retry_calls, 1);
        assert!(!super::alias_backing_is_live(host_addr));
    }

    #[test]
    fn foreign_mm_drop_release_only_enqueues_until_the_executor_idle_safe_point() {
        let (custody, _) = live_custody();
        let key = (0xa081_1b00_0000, 0x4000);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate foreign-MM release safe-point fixture");
        let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        lease.mark_mapped();
        let generation = super::register_global_frame_host_owner_in(
            &custody,
            lease,
            mapping,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .expect("register foreign-MM release safe-point fixture");
        let pin = custody.global_frame_host_owners.lock()[&key]
            .owner()
            .pin()
            .expect("retain the final foreign-MM owner pin");
        let mut backing = super::RetainedForeignMmBacking {
            extents: vec![super::RetainedForeignExtent {
                key,
                owner: super::RetainedPhysicalOwner::Global(pin),
            }],
        };
        let mut unmap_calls = 0_u32;
        assert!(matches!(
            super::retire_global_frame_host_owner_if_generation_in_using(
                &custody,
                key.0,
                key.1,
                generation,
                &mut |_, _| {
                    unmap_calls += 1;
                    Ok(())
                },
            ),
            super::GlobalFrameRetirementOutcome::DeferredActivePins { .. }
        ));
        assert_eq!(unmap_calls, 0);

        backing.extents.clear();
        custody.request_global_frame_retirement_retry();
        assert!(backing.extents.is_empty());
        assert_eq!(unmap_calls, 0, "pin release/Drop must not call the backend");
        assert!(custody.global_frame_host_owners.lock()[&key].is_pending());

        assert_eq!(
            super::retry_pending_global_frame_retirements_at_idle_in_using(
                &custody,
                &mut |_, _| {
                    unmap_calls += 1;
                    Ok(())
                },
            ),
            0,
            "the executor-idle turn must fully drain this exact pending owner",
        );
        assert_eq!(unmap_calls, 1);
        assert!(!custody.global_frame_host_owners.lock().contains_key(&key));
    }

    #[test]
    fn executor_idle_safe_point_requeues_one_transient_backend_failure() {
        let (custody, _) = live_custody();
        let key = (0xa081_1b80_0000, 0x4000);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate foreign-MM transient retry fixture");
        let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        lease.mark_mapped();
        let generation = super::register_global_frame_host_owner_in(
            &custody,
            lease,
            mapping,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .expect("register foreign-MM transient retry fixture");
        let injected = super::CarrierStage2BackendError::HvReturn(0xfae9_4001);
        assert!(matches!(
            super::retire_global_frame_host_owner_if_generation_in_using(
                &custody,
                key.0,
                key.1,
                generation,
                &mut |_, _| Err(injected),
            ),
            super::GlobalFrameRetirementOutcome::RetryPending { .. }
        ));
        let mut retry_calls = 0_u32;
        assert_eq!(
            super::retry_pending_global_frame_retirements_at_idle_in_using(
                &custody,
                &mut |_, _| {
                    retry_calls += 1;
                    Err(injected)
                },
            ),
            1,
            "the first idle-turn failure must remain queued",
        );
        assert_eq!(retry_calls, 1);
        assert!(custody.global_frame_host_owners.lock()[&key].is_pending());

        assert_eq!(
            super::retry_pending_global_frame_retirements_at_idle_in_using(
                &custody,
                &mut |_, _| {
                    retry_calls += 1;
                    Ok(())
                },
            ),
            0,
            "the next idle turn must drain the requeued exact owner",
        );
        assert_eq!(retry_calls, 2);
        assert!(!custody.global_frame_host_owners.lock().contains_key(&key));
    }

    #[test]
    fn synchronous_retirement_removes_queued_storage_before_key_reuse() {
        let (custody, _) = live_custody();
        let make_pending = |key: (u64, u64)| {
            let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                key.1 as usize,
                crate::host_mapping::HostMappingKind::PerMmKernelState,
            )
            .expect("allocate removable FIFO fixture");
            let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
            lease.mark_mapped();
            let generation = super::register_global_frame_host_owner_in(
                &custody,
                lease,
                mapping,
                u64::from(applevisor::memory::MemPerms::ReadWrite),
            )
            .expect("register removable FIFO fixture");
            assert!(matches!(
                super::retire_global_frame_host_owner_if_generation_in_using(
                    &custody,
                    key.0,
                    key.1,
                    generation,
                    &mut |_, _| Err(super::CarrierStage2BackendError::ConcurrentRetirement),
                ),
                super::GlobalFrameRetirementOutcome::RetryPending { .. }
            ));
            generation
        };

        let old_key = (0xa081_1be0_0000, 0x4000);
        let old_generation = make_pending(old_key);
        assert_eq!(
            custody
                .pending_global_frame_directory_retries
                .lock()
                .storage_len(),
            1,
        );
        assert!(matches!(
            super::retire_global_frame_host_owner_if_generation_in_using(
                &custody,
                old_key.0,
                old_key.1,
                old_generation,
                &mut |_, _| Ok(()),
            ),
            super::GlobalFrameRetirementOutcome::RetiredUnmapped { .. }
        ));
        assert_eq!(
            custody
                .pending_global_frame_directory_retries
                .lock()
                .storage_len(),
            0,
            "ordinary exact completion must remove queued storage immediately",
        );

        let real_key = (old_key.0 + 0x4000, old_key.1);
        make_pending(real_key);
        let mut calls = 0_u32;
        let turn = super::retry_pending_global_frame_retirements_at_idle_in_using(
            &custody,
            &mut |ipa, _| {
                assert_eq!(ipa, real_key.0, "idle turn must not inspect a ghost item");
                calls += 1;
                Ok(())
            },
        );
        assert_eq!(turn.inspected_directory, 1);
        assert_eq!(calls, 1);
        assert_eq!(
            custody
                .pending_global_frame_directory_retries
                .lock()
                .storage_len(),
            0,
        );
    }

    #[test]
    fn executor_idle_safe_point_never_duplicates_an_in_flight_turn() {
        let (custody, _) = live_custody();
        let key = (0xa081_1bc0_0000, 0x4000);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate concurrent idle-turn fixture");
        let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        lease.mark_mapped();
        let generation = super::register_global_frame_host_owner_in(
            &custody,
            lease,
            mapping,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .expect("register concurrent idle-turn fixture");
        assert!(matches!(
            super::retire_global_frame_host_owner_if_generation_in_using(
                &custody,
                key.0,
                key.1,
                generation,
                &mut |_, _| Err(super::CarrierStage2BackendError::ConcurrentRetirement),
            ),
            super::GlobalFrameRetirementOutcome::RetryPending { .. }
        ));

        custody
            .pending_global_frame_retirement_turn_in_flight
            .store(true, std::sync::atomic::Ordering::Release);
        let mut calls = 0_u32;
        assert_eq!(
            super::retry_pending_global_frame_retirements_at_idle_in_using(
                &custody,
                &mut |_, _| {
                    calls += 1;
                    Ok(())
                },
            ),
            1,
        );
        assert_eq!(
            calls, 0,
            "a second idle turn must not duplicate backend work"
        );
        assert!(custody.global_frame_host_owners.lock()[&key].is_pending());

        custody
            .pending_global_frame_retirement_turn_in_flight
            .store(false, std::sync::atomic::Ordering::Release);
        assert_eq!(
            super::retry_pending_global_frame_retirements_at_idle_in_using(
                &custody,
                &mut |_, _| {
                    calls += 1;
                    Ok(())
                },
            ),
            0,
        );
        assert_eq!(calls, 1);
        assert!(!custody.global_frame_host_owners.lock().contains_key(&key));
    }

    #[test]
    fn retirement_retains_backing_if_the_claimed_directory_slot_disappears() {
        let (custody, _) = live_custody();
        let key = (0xa081_1c00_0000, 0x4000);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate disappearing retirement slot fixture");
        let host_addr = mapping.as_ptr() as usize;
        let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        lease.mark_mapped();
        let generation = super::register_global_frame_host_owner_in(
            &custody,
            lease,
            mapping,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .expect("register disappearing retirement slot fixture");
        let record_id = custody.global_frame_host_owners.lock()[&key]
            .owner()
            .record_identity
            .record_id;
        let injected = super::CarrierStage2BackendError::HvReturn(0xfae9_4001);

        assert!(matches!(
            super::retire_global_frame_host_owner_if_generation_in_using(
                &custody,
                key.0,
                key.1,
                generation,
                &mut |_, _| {
                    custody.global_frame_host_owners.lock().remove(&key);
                    Err(injected)
                },
            ),
            super::GlobalFrameRetirementOutcome::RetryPending { .. }
        ));
        assert_eq!(
            custody.pending_global_frame_owner_count(),
            1,
            "a lost directory claim must retain the backing in detached custody"
        );
        assert!(
            custody
                .stage2_record_snapshot(record_id)
                .is_some_and(|snapshot| snapshot.mapped && snapshot.backend_map_installed),
            "the failed backend retirement remains mapped"
        );
        assert!(super::alias_backing_is_live(host_addr));

        super::retry_pending_global_frame_retirements_in_using(&custody, &mut |_, _| Ok(()))
            .expect("detached custody retries the lost directory claim");
        assert_eq!(custody.pending_global_frame_owner_count(), 0);
        assert!(!super::alias_backing_is_live(host_addr));
    }

    #[test]
    fn global_owner_collision_retains_failed_rollback_candidate_until_safe_point() {
        let (custody, _) = live_custody();
        let key = (0xa081_2000_0000, 0x4000);
        let incumbent_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate incumbent global owner backing");
        let mut incumbent_lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        incumbent_lease.mark_test_mapped_without_backend();
        let incumbent_generation = super::register_global_frame_host_owner_in(
            &custody,
            incumbent_lease,
            incumbent_mapping,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .expect("register incumbent global owner");

        let candidate_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate colliding global owner backing");
        let candidate_host = candidate_mapping.as_ptr() as usize;
        let mut candidate_lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        candidate_lease.mark_mapped();
        let injected = super::CarrierStage2BackendError::HvReturn(0xfae9_4001);
        let mut rollback_calls = 0_u32;

        assert!(
            super::register_global_frame_host_owner_in_using(
                &custody,
                candidate_lease,
                candidate_mapping,
                u64::from(applevisor::memory::MemPerms::ReadWrite),
                &mut |_, _| {
                    rollback_calls += 1;
                    Err(injected)
                },
            )
            .is_err()
        );
        assert_eq!(
            super::global_frame_host_owner_generation_in(&custody, key.0, key.1),
            incumbent_generation,
            "collision must not replace the incumbent"
        );
        assert_eq!(custody.pending_global_frame_owner_count(), 1);
        assert!(super::alias_backing_is_live(candidate_host));
        assert_eq!(
            rollback_calls, 1,
            "collision rollback and owner Drop must not invoke a second backend callback",
        );

        assert_eq!(
            super::retry_pending_global_frame_retirements_at_idle_in_using(
                &custody,
                &mut |_, _| {
                    rollback_calls += 1;
                    Ok(())
                },
            ),
            0,
            "production idle turn retires the enqueued colliding candidate",
        );
        assert_eq!(rollback_calls, 2);
        assert_eq!(custody.pending_global_frame_owner_count(), 0);
        assert!(!super::alias_backing_is_live(candidate_host));
        assert_eq!(
            super::global_frame_host_owner_generation_in(&custody, key.0, key.1),
            incumbent_generation
        );
    }

    #[test]
    fn bounded_idle_retry_rotates_past_persistent_prefix_and_services_detached_work() {
        let (custody, _) = live_custody();
        let mut live = Vec::new();
        for index in 0..128_u64 {
            let key = (0xa081_8000_0000 + index * 0x4000, 0x4000);
            let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                key.1 as usize,
                crate::host_mapping::HostMappingKind::PerMmKernelState,
            )
            .expect("allocate large live-directory backing");
            let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
            lease.mark_test_mapped_without_backend();
            let generation = super::register_global_frame_host_owner_in(
                &custody,
                lease,
                mapping,
                u64::from(applevisor::memory::MemPerms::ReadWrite),
            )
            .expect("register large live-directory owner");
            live.push((key, generation));
        }
        let mut directory = Vec::new();
        for index in 0..33_u64 {
            let key = (0xa082_0000_0000 + index * 0x4000, 0x4000);
            let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                key.1 as usize,
                crate::host_mapping::HostMappingKind::PerMmKernelState,
            )
            .expect("allocate fair-retry directory backing");
            let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
            lease.mark_mapped();
            let generation = super::register_global_frame_host_owner_in(
                &custody,
                lease,
                mapping,
                u64::from(applevisor::memory::MemPerms::ReadWrite),
            )
            .expect("register fair-retry directory owner");
            assert!(matches!(
                super::retire_global_frame_host_owner_if_generation_in_using(
                    &custody,
                    key.0,
                    key.1,
                    generation,
                    &mut |_, _| Err(super::CarrierStage2BackendError::ConcurrentRetirement),
                ),
                super::GlobalFrameRetirementOutcome::RetryPending { .. }
            ));
            directory.push((key, generation));
        }

        let collision_key = (0xa083_0000_0000, 0x4000);
        let incumbent_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            collision_key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate fair-retry incumbent");
        let mut incumbent_lease =
            super::GlobalFrameStage2Lease::fixed(collision_key.0, collision_key.1);
        incumbent_lease.mark_test_mapped_without_backend();
        let incumbent_generation = super::register_global_frame_host_owner_in(
            &custody,
            incumbent_lease,
            incumbent_mapping,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .expect("register fair-retry incumbent");
        let candidate_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            collision_key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate fair-retry detached candidate");
        let mut candidate_lease =
            super::GlobalFrameStage2Lease::fixed(collision_key.0, collision_key.1);
        candidate_lease.mark_mapped();
        assert!(
            super::register_global_frame_host_owner_in_using(
                &custody,
                candidate_lease,
                candidate_mapping,
                u64::from(applevisor::memory::MemPerms::ReadWrite),
                &mut |_, _| Err(super::CarrierStage2BackendError::ConcurrentRetirement),
            )
            .is_err()
        );

        let ready_key = directory[32].0;
        for _ in 0..3 {
            let turn = super::retry_pending_global_frame_retirements_at_idle_in_using(
                &custody,
                &mut |ipa, _| {
                    if ipa == ready_key.0 || ipa == collision_key.0 {
                        Ok(())
                    } else {
                        Err(super::CarrierStage2BackendError::ConcurrentRetirement)
                    }
                },
            );
            assert!(turn.inspected_directory <= 16);
            assert!(turn.inspected_detached <= 16);
        }
        assert!(
            !custody
                .global_frame_host_owners
                .lock()
                .contains_key(&ready_key),
            "the 33rd directory owner must not starve behind a failing prefix",
        );
        assert_eq!(
            custody.pending_global_frame_owner_count(),
            0,
            "detached ready work must receive bounded service despite directory failures",
        );

        let replacement_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            ready_key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate reused ready-key backing");
        let mut replacement_lease = super::GlobalFrameStage2Lease::fixed(ready_key.0, ready_key.1);
        replacement_lease.mark_test_mapped_without_backend();
        let replacement_generation = super::register_global_frame_host_owner_in(
            &custody,
            replacement_lease,
            replacement_mapping,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .expect("reuse retired ready key");

        while super::retry_pending_global_frame_retirements_at_idle_in_using(
            &custody,
            &mut |_, _| Ok(()),
        ) != 0
        {}
        assert_eq!(
            super::global_frame_host_owner_generation_in(&custody, ready_key.0, ready_key.1),
            replacement_generation,
            "a deleted queue identity must not retire a successor at the reused key",
        );
        assert!(matches!(
            super::retire_global_frame_host_owner_if_generation_in_using(
                &custody,
                ready_key.0,
                ready_key.1,
                replacement_generation,
                &mut |_, _| Ok(()),
            ),
            super::GlobalFrameRetirementOutcome::RetiredUnmapped { .. }
        ));
        for (key, generation) in live {
            assert!(matches!(
                super::retire_global_frame_host_owner_if_generation_in_using(
                    &custody,
                    key.0,
                    key.1,
                    generation,
                    &mut |_, _| Ok(()),
                ),
                super::GlobalFrameRetirementOutcome::RetiredUnmapped { .. }
            ));
        }
        assert!(matches!(
            super::retire_global_frame_host_owner_if_generation_in_using(
                &custody,
                collision_key.0,
                collision_key.1,
                incumbent_generation,
                &mut |_, _| Ok(()),
            ),
            super::GlobalFrameRetirementOutcome::RetiredUnmapped { .. }
        ));
    }

    #[test]
    fn reconcile_deferred_owner_enqueues_for_idle_retry_after_pin_drop() {
        let (custody, _) = live_custody();
        let key = (0xa084_0000_0000, 0x4000);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate reconcile-deferred backing");
        let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        lease.mark_test_mapped_without_backend();
        super::register_global_frame_host_owner_in(
            &custody,
            lease,
            mapping,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .expect("register reconcile-deferred owner");
        let pin = custody.global_frame_host_owners.lock()[&key]
            .owner()
            .pin()
            .expect("pin reconcile-deferred owner");

        destroy_vm_with_custody_using(&custody, "deferred G1 destroy", || 0, || {})
            .expect("destroy deferred G1");
        let g2 = custody.begin_create().expect("begin deferred G2");
        custody.commit_create(g2).expect("publish deferred G2");
        let report = super::reconcile_global_frame_owners_after_replay_in_using(
            &custody,
            &[],
            true,
            &mut |_, _| Ok(()),
        )
        .expect("defer pinned terminal owner");
        assert_eq!(report.deferred, 1);
        assert!(custody.global_frame_host_owners.lock()[&key].is_pending());

        drop(pin);
        let mut backend_calls = 0_u32;
        assert_eq!(
            super::retry_pending_global_frame_retirements_at_idle_in_using(
                &custody,
                &mut |_, _| {
                    backend_calls += 1;
                    Ok(())
                },
            ),
            0,
            "reconcile must enqueue the deferred owner without a manual retry bit",
        );
        assert_eq!(
            backend_calls, 0,
            "terminalized retirement needs no backend unmap"
        );
        assert!(!custody.global_frame_host_owners.lock().contains_key(&key));
    }

    #[test]
    fn global_owner_stale_same_key_generation_never_retires_successor() {
        let (custody, _) = live_custody();
        let key = (0xa081_3000_0000, 0x4000);
        let install = || {
            let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                key.1 as usize,
                crate::host_mapping::HostMappingKind::PerMmKernelState,
            )
            .expect("allocate same-key global owner backing");
            let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
            lease.mark_test_mapped_without_backend();
            super::register_global_frame_host_owner_in(
                &custody,
                lease,
                mapping,
                u64::from(applevisor::memory::MemPerms::ReadWrite),
            )
            .expect("register same-key global owner")
        };
        let predecessor = install();
        assert!(matches!(
            super::retire_global_frame_host_owner_if_generation_in_using(
                &custody,
                key.0,
                key.1,
                predecessor,
                &mut |_, _| Ok(()),
            ),
            super::GlobalFrameRetirementOutcome::RetiredUnmapped { .. }
        ));
        let successor = install();
        assert_ne!(predecessor, successor);
        let mut unmap_calls = 0_u32;
        let stale = super::retire_global_frame_host_owner_if_generation_in_using(
            &custody,
            key.0,
            key.1,
            predecessor,
            &mut |_, _| {
                unmap_calls += 1;
                Ok(())
            },
        );
        assert!(matches!(
            stale,
            super::GlobalFrameRetirementOutcome::MismatchedGeneration {
                current_generation,
                expected_generation,
                ..
            } if current_generation == successor && expected_generation == predecessor
        ));
        assert_eq!(unmap_calls, 0);
        assert_eq!(
            super::global_frame_host_owner_generation_in(&custody, key.0, key.1),
            successor
        );
    }

    #[test]
    fn vm_rebuild_rebinds_live_owner_to_g2_and_transfers_release_authority_once() {
        let (custody, g1) = live_custody();
        let key = (0xa081_4000_0000_u64, 0x4000_u64);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate rebuild owner backing");
        let host_addr = mapping.as_ptr() as usize;
        let mut lease = super::GlobalFrameStage2Lease::reserve(key.1, key.1)
            .expect("reserve rebuild owner IPA");
        let reserved_key = lease.key();
        lease.mark_test_mapped_without_backend();
        let generation = super::register_global_frame_host_owner_in(
            &custody,
            lease,
            mapping,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .expect("register rebuild owner");
        let old_owner = custody.global_frame_host_owners.lock()[&reserved_key]
            .owner()
            .clone();
        let old_identity = old_owner.record_identity;
        let old_pin = old_owner.pin().expect("pin G1 owner");
        let fixed_key = (0xa081_4000_0000_u64, 0x4000_u64);
        let fixed_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            fixed_key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate fixed rebuild owner backing");
        let fixed_host = fixed_mapping.as_ptr() as usize;
        let mut fixed_lease = super::GlobalFrameStage2Lease::fixed(fixed_key.0, fixed_key.1);
        fixed_lease.mark_test_mapped_without_backend();
        super::register_global_frame_host_owner_in(
            &custody,
            fixed_lease,
            fixed_mapping,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .expect("register fixed rebuild owner");
        let fixed_old_identity = custody.global_frame_host_owners.lock()[&fixed_key]
            .owner()
            .record_identity;

        destroy_vm_with_custody_using(&custody, "G1 destroy", || 0, || {}).expect("destroy G1");
        let terminal = custody
            .stage2_record_snapshot(old_identity.record_id)
            .expect("terminal G1 record");
        assert_eq!(terminal.vm_generation, g1);
        assert!(terminal.terminalized_by_vm_destroy);
        assert!(terminal.release_ipa);
        assert!(super::alias_backing_is_live(host_addr));
        let reservation_probe =
            super::GlobalFrameStage2Lease::reserve(reserved_key.1, reserved_key.1)
                .expect("probe reservation while G1 owner awaits replay");
        assert_ne!(
            reservation_probe.base, reserved_key.0,
            "successful destroy must preserve the live logical owner's IPA reservation"
        );
        drop(reservation_probe);

        let g2 = custody.begin_create().expect("begin G2 create");
        custody.commit_create(g2).expect("publish G2");
        let mut release_calls = 0_u32;
        let report = super::reconcile_global_frame_owners_after_replay_in_using(
            &custody,
            &[
                super::GlobalFrameReplayExtent {
                    ipa: reserved_key.0,
                    length: reserved_key.1,
                    host_addr,
                    perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
                },
                super::GlobalFrameReplayExtent {
                    ipa: fixed_key.0,
                    length: fixed_key.1,
                    host_addr: fixed_host,
                    perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
                },
            ],
            false,
            &mut |_, _| {
                release_calls += 1;
                Ok(())
            },
        )
        .expect("rebind live G1 owner into G2");
        assert_eq!(report.rebound, 2);
        assert_eq!(report.retired, 0);

        let current = custody.global_frame_host_owners.lock()[&reserved_key]
            .owner()
            .clone();
        assert_eq!(current.record_identity.vm_generation, g2);
        assert_eq!(current.generation(), generation);
        assert!(!std::sync::Arc::ptr_eq(&old_owner, &current));
        assert!(
            !custody
                .stage2_record_snapshot(old_identity.record_id)
                .expect("pinned G1 record remains")
                .release_ipa
        );
        assert!(
            custody
                .stage2_record_snapshot(current.record_identity.record_id)
                .expect("current G2 record")
                .release_ipa
        );
        let fixed_current = custody.global_frame_host_owners.lock()[&fixed_key]
            .owner()
            .clone();
        assert_eq!(fixed_current.record_identity.vm_generation, g2);
        assert!(
            !custody
                .stage2_record_snapshot(fixed_current.record_identity.record_id)
                .expect("current fixed G2 record")
                .release_ipa
        );
        assert!(
            custody
                .stage2_record_snapshot(fixed_old_identity.record_id)
                .is_none()
        );
        let current_record_id = current.record_identity.record_id;
        let second = super::reconcile_global_frame_owners_after_replay_in_using(
            &custody,
            &[
                super::GlobalFrameReplayExtent {
                    ipa: reserved_key.0,
                    length: reserved_key.1,
                    host_addr,
                    perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
                },
                super::GlobalFrameReplayExtent {
                    ipa: fixed_key.0,
                    length: fixed_key.1,
                    host_addr: fixed_host,
                    perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
                },
            ],
            false,
            &mut |_, _| {
                release_calls += 1;
                Ok(())
            },
        )
        .expect("same replay reconciliation is idempotent");
        assert_eq!(second, super::GlobalFrameReplayReconcileReport::default());
        assert_eq!(
            custody.global_frame_host_owners.lock()[&reserved_key]
                .owner()
                .record_identity
                .record_id,
            current_record_id
        );
        let g2_pin = current.pin().expect("owner auth pins current G2 record");
        assert_eq!(old_pin._stage2_pin.identity.vm_generation, g1);
        assert_eq!(g2_pin._stage2_pin.identity.vm_generation, g2);
        assert_eq!(unsafe { *old_pin.owner().ptr() }, unsafe {
            *g2_pin.owner().ptr()
        });

        drop(old_pin);
        assert!(
            custody
                .stage2_record_snapshot(old_identity.record_id)
                .is_none()
        );
        assert_eq!(release_calls, 0, "G1 final pin must not release G2 IPA");
        assert!(
            custody
                .stage2_record_snapshot(current.record_identity.record_id)
                .is_some_and(|snapshot| snapshot.release_ipa && snapshot.mapped)
        );
        drop(g2_pin);
        assert!(super::alias_backing_is_live(host_addr));
        assert_eq!(reserved_key.1, key.1);
    }

    #[test]
    fn vm_destroy_success_terminalizes_pending_owner_but_failure_preserves_exact_g1() {
        let (custody, g1) = live_custody();
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            0x4000,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate pending rebuild owner");
        let host_addr = mapping.as_ptr() as usize;
        let mut lease = super::GlobalFrameStage2Lease::reserve(0x4000, 0x4000)
            .expect("reserve pending rebuild owner IPA");
        let key = lease.key();
        lease.mark_mapped();
        let generation = super::register_global_frame_host_owner_in(
            &custody,
            lease,
            mapping,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .expect("register pending rebuild owner");
        let identity = custody.global_frame_host_owners.lock()[&key]
            .owner()
            .record_identity;
        let injected = CarrierStage2BackendError::HvReturn(0xfae9_4001);
        assert!(matches!(
            super::retire_global_frame_host_owner_if_generation_in_using(
                &custody,
                key.0,
                key.1,
                generation,
                &mut |_, _| Err(injected),
            ),
            super::GlobalFrameRetirementOutcome::RetryPending { .. }
        ));
        let before_failed_destroy = custody
            .stage2_record_snapshot(identity.record_id)
            .expect("pending G1 record");

        assert!(
            destroy_vm_with_custody_using(
                &custody,
                "failed G1 destroy",
                || 0xfae9_4002_u32 as i32,
                || {},
            )
            .is_err()
        );
        assert_eq!(custody.live_generation(), Some(g1));
        assert_eq!(
            custody.stage2_record_snapshot(identity.record_id),
            Some(before_failed_destroy),
            "failed raw destroy must preserve exact G1 record"
        );

        destroy_vm_with_custody_using(&custody, "successful G1 destroy", || 0, || {})
            .expect("persistent pre-destroy unmap failure must not block raw destroy");
        assert!(
            custody
                .stage2_record_snapshot(identity.record_id)
                .is_some_and(|snapshot| snapshot.terminalized_by_vm_destroy)
        );
        assert!(super::alias_backing_is_live(host_addr));

        let g2 = custody.begin_create().expect("begin successor VM");
        custody.commit_create(g2).expect("publish successor VM");
        let mut releases = 0_u32;
        let report = super::reconcile_global_frame_owners_after_replay_in_using(
            &custody,
            &[],
            true,
            &mut |ipa, length| {
                assert_eq!((ipa, length), key);
                releases += 1;
                Ok(())
            },
        )
        .expect("retired G1 owner is finalized, not rebound");
        assert_eq!(report.rebound, 0);
        assert_eq!(report.retired, 1);
        assert_eq!(releases, 1);
        assert!(!custody.global_frame_host_owners.lock().contains_key(&key));
        assert!(!super::alias_backing_is_live(host_addr));
    }

    #[test]
    fn carrier_exit_propagates_terminal_owner_cleanup_failure_after_destroy_success() {
        let (custody, g1) = live_custody();
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            0x4000,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate carrier-exit owner backing");
        let host_addr = mapping.as_ptr() as usize;
        let mut lease = super::GlobalFrameStage2Lease::reserve(0x4000, 0x4000)
            .expect("reserve carrier-exit owner IPA");
        let key = lease.key();
        lease.mark_test_mapped_without_backend();
        super::register_global_frame_host_owner_in(
            &custody,
            lease,
            mapping,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .expect("register carrier-exit owner");
        let identity = custody.global_frame_host_owners.lock()[&key]
            .owner()
            .record_identity;

        destroy_vm_with_custody_using(&custody, "carrier-exit test", || 0, || {})
            .expect("raw carrier-exit destroy succeeds");
        let injected = "injected terminal owner release failure";
        let error =
            super::finalize_carrier_exit_global_frame_owners_in_using(&custody, &mut |_, _| {
                Err(super::TrapError::Hypervisor(injected.to_owned()))
            })
            .expect_err("carrier exit must propagate terminal cleanup failure");

        assert!(matches!(
            error,
            super::TrapError::Hypervisor(message)
                if message.contains("carrier-exit terminal global frame cleanup")
                    && message.contains(injected)
        ));
        assert_eq!(custody.live_generation(), None);
        assert!(
            custody
                .stage2_record_snapshot(identity.record_id)
                .is_some_and(|snapshot| {
                    snapshot.vm_generation == g1 && snapshot.terminalized_by_vm_destroy
                }),
            "cleanup failure must retain already-terminalized exact custody"
        );
        assert!(custody.global_frame_host_owners.lock().contains_key(&key));
        assert!(super::alias_backing_is_live(host_addr));
    }

    #[test]
    fn terminal_release_claim_aborts_for_retry_and_commits_removal_exactly_once() {
        let (custody, _) = live_custody();
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            0x4000,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate terminal release backing");
        let mut lease = super::GlobalFrameStage2Lease::reserve(0x4000, 0x4000)
            .expect("reserve terminal release IPA");
        lease.mark_test_mapped_without_backend();
        super::register_global_frame_host_owner_in(
            &custody,
            lease,
            mapping,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .expect("register terminal release owner");
        let owner = custody
            .global_frame_host_owners
            .lock()
            .values()
            .next()
            .expect("terminal release owner")
            .owner()
            .clone();
        let identity = owner.record_identity;
        assert_eq!(
            custody.retire_stage2_record_using(identity, |_, _| Ok(())),
            super::CarrierStage2RetireOutcome::RetiredUnmapped
        );

        let mut releases = 0_u32;
        assert!(
            super::finalize_terminal_stage2_record_using(&custody, identity, &mut |_, _| {
                releases += 1;
                Err(super::TrapError::Hypervisor(
                    "injected release failure".to_owned(),
                ))
            },)
            .is_err()
        );
        assert_eq!(releases, 1);
        assert!(
            custody
                .stage2_record_snapshot(identity.record_id)
                .is_some_and(|snapshot| {
                    snapshot.release_ipa
                        && !snapshot.release_in_flight
                        && snapshot.release_retry_pending
                })
        );

        super::finalize_terminal_stage2_record_using(&custody, identity, &mut |_, _| {
            releases += 1;
            Ok(())
        })
        .expect("retry commits claimed release and removal");
        assert_eq!(releases, 2);
        assert!(custody.stage2_record_snapshot(identity.record_id).is_none());
        assert!(
            super::finalize_terminal_stage2_record_using(&custody, identity, &mut |_, _| {
                releases += 1;
                Ok(())
            },)
            .is_err()
        );
        assert_eq!(releases, 2, "removed identity cannot release twice");
    }

    #[test]
    fn post_raw_create_failures_never_publish_live_and_terminalize_exact_setup_generation() {
        for stage in ["initial-vcpu", "shared-wait-map", "exec-reconcile"] {
            let custody = CarrierVmCustody::new();
            let generation = custody.begin_create().expect("begin injected create");
            let identity = custody
                .register_stage2_record(stage2_spec(generation, 70))
                .expect("setup may register exact Creating-generation records");
            assert_eq!(
                custody.live_generation(),
                None,
                "{stage} published too early"
            );

            custody
                .abort_created_vm_after_raw_destroy(generation)
                .expect("injected post-create failure rolls back exact raw VM");
            assert_eq!(custody.live_generation(), None);
            assert!(
                custody
                    .stage2_record_snapshot(identity.record_id)
                    .is_some_and(|snapshot| {
                        snapshot.vm_generation == generation && snapshot.terminalized_by_vm_destroy
                    })
            );
            assert!(
                custody.begin_create().is_ok(),
                "{stage} did not restore Vacant"
            );
        }
    }

    #[test]
    fn frame_pool_and_commit_destroy_concurrent_lock_order() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::thread;

        for _ in 0..50 {
            let (custody, generation) = live_custody();
            let fixture_pool = Arc::new(crate::frame_pool::PreMappedFramePool::new_test_fixture(4));
            custody.install_frame_pool(fixture_pool);

            let stop = Arc::new(AtomicBool::new(false));
            let stop_worker = Arc::clone(&stop);
            let custody_worker = Arc::clone(&custody);

            let worker = thread::spawn(move || {
                while !stop_worker.load(Ordering::Acquire) {
                    let _ = custody_worker.frame_pool();
                }
            });

            custody.begin_destroy(generation).expect("begin destroy");
            custody.commit_destroy(generation).expect("commit destroy");

            stop.store(true, Ordering::Release);
            worker.join().expect("worker thread join without deadlock");
        }
    }

    #[test]
    fn late_g1_carrier_mm_retirement_request_cannot_mutate_same_key_g2_record() {
        let (custody, g1) = live_custody();
        let key = (0xa081_9000_0000, 0x4000);
        let mut g1_lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        g1_lease.mark_test_mapped_without_backend();
        let owners = std::collections::BTreeMap::from([(key, 0x1000)]);
        let old_identity =
            super::register_carrier_stage2_leases(&custody, &mut vec![g1_lease], &owners)
                .expect("register G1 carrier-MM record")[0];
        assert_eq!(old_identity.vm_generation, g1);
        destroy_vm_with_custody_using(&custody, "carrier G1 destroy", || 0, || {})
            .expect("destroy G1");
        let g2 = custody.begin_create().expect("begin G2");
        let report = super::reconcile_global_frame_owners_after_replay_in_using(
            &custody,
            &[super::GlobalFrameReplayExtent {
                ipa: key.0,
                length: key.1,
                host_addr: owners[&key],
                perms: 0,
            }],
            false,
            &mut |_, _| panic!("rebind must transfer rather than release IPA authority"),
        )
        .expect("production replay reconciliation rebinds carrier-MM record");
        assert_eq!(report.rebound, 1);
        let new_identity = custody.carrier_stage2_records.lock()[&key];
        custody.commit_create(g2).expect("publish G2");

        assert_eq!(
            custody.request_stage2_record_retirement(old_identity),
            super::CarrierStage2RetireOutcome::NotFound
        );
        assert!(
            custody
                .stage2_record_snapshot(new_identity.record_id)
                .is_some_and(|snapshot| {
                    snapshot.vm_generation == g2
                        && snapshot.mapped
                        && !snapshot.retirement_requested
                })
        );
    }

    #[test]
    fn terminal_release_claim_blocks_generation_rebind_until_abort() {
        let (custody, _) = live_custody();
        let identity = custody
            .register_stage2_record(stage2_spec(custody.live_generation().expect("G1 live"), 91))
            .expect("register G1 record");
        destroy_vm_with_custody_using(&custody, "G1 destroy", || 0, || {}).expect("destroy G1");
        let _g2 = custody.begin_create().expect("begin G2 replay");
        assert!(
            custody
                .claim_terminal_stage2_release(identity)
                .expect("claim exact terminal release")
                .is_some()
        );
        assert_eq!(
            custody.rebind_terminal_stage2_record(
                identity,
                0x1234_0000,
                stage2_spec(identity.vm_generation, 91).perms
            ),
            Err(super::CarrierStage2RecordError::ReleaseInFlight)
        );
        custody.abort_terminal_stage2_release(identity);
        assert!(
            custody
                .rebind_terminal_stage2_record(
                    identity,
                    0x1234_0000,
                    stage2_spec(identity.vm_generation, 91).perms,
                )
                .is_ok()
        );
    }

    #[test]
    fn create_cleanup_retains_failed_vcpu_then_retries_terminal_finalization_only() {
        let custody = std::sync::Arc::new(CarrierVmCustody::new());
        let generation = custody.begin_create().expect("begin Creating VM");
        let identity = custody
            .register_stage2_record(stage2_spec(generation, 92))
            .expect("register setup record");
        let mut vcpu_id = Some(41);
        let mut raw_vm_destroyed = false;
        let vm_destroy_calls = std::cell::Cell::new(0_u32);
        let finalize_calls = std::cell::Cell::new(0_u32);

        let first = super::drive_pending_carrier_vm_cleanup_using(
            &custody,
            generation,
            super::PendingCarrierVmCleanupState {
                vcpu_id: &mut vcpu_id,
                raw_vm_destroyed: &mut raw_vm_destroyed,
                context: "injected cleanup",
            },
            |_| 0xfae9_4001_u32 as applevisor_sys::hv_return_t,
            |_, _, _| {
                vm_destroy_calls.set(vm_destroy_calls.get() + 1);
                Ok(())
            },
            |_| {
                finalize_calls.set(finalize_calls.get() + 1);
                Ok(())
            },
        );
        assert!(first.is_err());
        assert_eq!(vcpu_id, Some(41));
        assert!(!raw_vm_destroyed);
        assert_eq!(vm_destroy_calls.get(), 0);

        let second = super::drive_pending_carrier_vm_cleanup_using(
            &custody,
            generation,
            super::PendingCarrierVmCleanupState {
                vcpu_id: &mut vcpu_id,
                raw_vm_destroyed: &mut raw_vm_destroyed,
                context: "injected cleanup retry",
            },
            |_| 0,
            |custody, generation, _| {
                vm_destroy_calls.set(vm_destroy_calls.get() + 1);
                custody
                    .abort_created_vm_after_raw_destroy(generation)
                    .map_err(|error| super::TrapError::Hypervisor(format!("{error:?}")))
            },
            |custody| {
                finalize_calls.set(finalize_calls.get() + 1);
                super::finalize_carrier_exit_global_frame_owners_in_using(custody, &mut |_, _| {
                    Err(super::TrapError::Hypervisor("release retry".to_owned()))
                })
            },
        );
        assert!(second.is_err());
        assert_eq!(vcpu_id, None);
        assert!(raw_vm_destroyed);
        assert_eq!(vm_destroy_calls.get(), 1);
        assert!(
            custody
                .stage2_record_snapshot(identity.record_id)
                .is_some_and(|snapshot| snapshot.release_retry_pending)
        );

        super::drive_pending_carrier_vm_cleanup_using(
            &custody,
            generation,
            super::PendingCarrierVmCleanupState {
                vcpu_id: &mut vcpu_id,
                raw_vm_destroyed: &mut raw_vm_destroyed,
                context: "terminal cleanup retry",
            },
            |_| panic!("vCPU already destroyed"),
            |_, _, _| panic!("raw VM destroy must not repeat"),
            |custody| {
                finalize_calls.set(finalize_calls.get() + 1);
                super::finalize_carrier_exit_global_frame_owners_in_using(custody, &mut |_, _| {
                    Ok(())
                })
            },
        )
        .expect("terminal record cleanup retries without repeating raw destroy");
        assert_eq!(vm_destroy_calls.get(), 1);
        assert_eq!(finalize_calls.get(), 2);
        assert!(custody.stage2_record_snapshot(identity.record_id).is_none());
    }

    #[test]
    fn initial_fallible_input_failure_precedes_vm_and_admission_permit_acquisition() {
        let admission_attempted = std::cell::Cell::new(false);
        let result = super::prepare_initial_carrier_before_admission(
            || {
                Err::<(), _>(super::TrapError::Hypervisor(
                    "injected syscall transport setup failure".to_owned(),
                ))
            },
            || {
                admission_attempted.set(true);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(
            !admission_attempted.get(),
            "no VM or admission permit may be acquired before fallible transport setup succeeds"
        );
    }

    #[test]
    fn pending_vcpu_wrapper_never_runs_raii_destroy_before_exact_cleanup() {
        struct DropProbe(std::sync::Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        {
            let _held = std::mem::ManuallyDrop::new(DropProbe(std::sync::Arc::clone(&drops)));
        }
        assert_eq!(
            drops.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the wrapper must stay disarmed while PendingCarrierVmCreation owns raw cleanup"
        );
    }

    #[test]
    fn carrier_reuse_vcpu_failure_drops_wrapper_then_releases_accounting_once() {
        let order = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        struct DropProbe(std::sync::Arc<parking_lot::Mutex<Vec<&'static str>>>);
        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.lock().push("wrapper-drop");
            }
        }
        let wrapper = DropProbe(std::sync::Arc::clone(&order));
        super::complete_local_vcpu_raii_cleanup(
            71,
            || drop(wrapper),
            |id| {
                assert_eq!(id, 71);
                order.lock().push("accounting-release");
            },
        );
        assert_eq!(&*order.lock(), &["wrapper-drop", "accounting-release"]);
    }

    #[test]
    fn fresh_vm_vcpu_and_permit_wrappers_remain_guarded_until_commit_static_audit() {
        let source = concat!(
            include_str!("../trap.rs"),
            include_str!("persistent_executor.rs")
        );
        let create = source
            .split("fn create_vm_with_admission(")
            .nth(1)
            .and_then(|tail| {
                tail.split("fn virtual_machine_with_private_signals_blocked(")
                    .next()
            })
            .expect("create-with-admission body");
        assert!(
            create.find("HeldPermitGuard::new").expect("permit guard")
                < create
                    .find(".begin_create()")
                    .expect("custody begin_create"),
            "permit ownership must be armed before any fallible custody transition"
        );

        let shared = source
            .split(concat!("fn shared_wait_resume_", "inner("))
            .nth(1)
            .and_then(|tail| {
                tail.split("pub(crate) fn destroy_vcpu_on_thread_exit")
                    .next()
            })
            .expect("shared-wait rebuild body");
        assert!(shared.contains("SetupVmGuard::new(new_vm, true)"));
        assert!(shared.contains("SetupVcpuCleanup::PendingRaw"));
        assert!(
            shared
                .find("commit_pending_creation_before_vcpu_handoff")
                .expect("shared commit")
                < shared
                    .find("new_vcpu.into_inner()")
                    .expect("shared handoff")
        );

        let exec = include_str!("execve_rebuild.rs")
            .split(concat!("fn execve_rebuild_", "inner("))
            .nth(1)
            .expect("exec rebuild body");
        assert!(exec.contains("SetupVmGuard::new(new_vm, true)"));
        assert!(exec.contains("SetupVcpuCleanup::PendingRaw"));
        let commit = exec
            .rfind("commit_pending_creation_before_vcpu_handoff")
            .expect("exec commit");
        assert!(
            commit
                < exec
                    .rfind("new_vcpu.into_inner()")
                    .expect("exec vCPU handoff")
        );
        assert!(commit < exec.rfind("new_vm.into_inner()").expect("exec VM handoff"));
    }

    #[test]
    fn carrier_mm_logical_authority_follows_g1_record_rebind_and_retires_g2_once() {
        let (custody, g1) = live_custody();
        let key = (0xa081_a000_0000, 0x4000);
        let old_identity = custody
            .register_stage2_record(CarrierStage2RecordSpec {
                ipa: key.0,
                ..stage2_spec(g1, 93)
            })
            .expect("register G1 carrier-MM record");
        custody
            .carrier_stage2_records
            .lock()
            .insert(key, old_identity);
        let mut authority = super::carrier_stage2_logical_leases(&custody, &[old_identity]);

        destroy_vm_with_custody_using(&custody, "G1 destroy", || 0, || {}).expect("destroy G1");
        let g2 = custody.begin_create().expect("begin G2");
        super::reconcile_global_frame_owners_after_replay_in_using(
            &custody,
            &[super::GlobalFrameReplayExtent {
                ipa: key.0,
                length: key.1,
                host_addr: 0x1234_0000,
                perms: stage2_spec(g1, 93).perms,
            }],
            false,
            &mut |_, _| panic!("rebind must not release G1 authority"),
        )
        .expect("rebind live carrier-MM authority");
        custody.commit_create(g2).expect("publish G2");
        let new_identity = custody.carrier_stage2_records.lock()[&key];
        assert_ne!(old_identity.record_id, new_identity.record_id);

        let frames = std::sync::Arc::new(parking_lot::Mutex::new(
            super::InventoryFrameRegistry::default(),
        ));
        super::request_carrier_stage2_record_retirements(
            &mut authority,
            &std::sync::Arc::downgrade(&custody),
            &frames,
        );
        assert!(
            custody
                .stage2_record_snapshot(new_identity.record_id)
                .is_some_and(|snapshot| snapshot.retirement_requested)
        );
        let mut releases = 0_u32;
        super::retire_carrier_stage2_record_at_safe_point_using(
            &custody,
            new_identity,
            |_, _| Ok(()),
            |_, _| {
                releases += 1;
                Ok(())
            },
        )
        .expect("current G2 logical authority retires at explicit safe point");
        assert_eq!(releases, 1);
        assert!(
            custody
                .stage2_record_snapshot(new_identity.record_id)
                .is_none()
        );
    }

    #[test]
    fn concurrent_exact_owner_finalization_cannot_republish_removed_owner() {
        let (custody, _) = live_custody();
        let key = (0xa081_b000_0000, 0x4000);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate concurrent-retirement owner");
        let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        lease.mark_mapped();
        super::register_global_frame_host_owner_in(
            &custody,
            lease,
            mapping,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .expect("register concurrent-retirement owner");
        let generation = custody
            .global_frame_host_owners
            .lock()
            .get(&key)
            .expect("owner")
            .owner()
            .generation();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();

        let first_custody = std::sync::Arc::clone(&custody);
        let first = std::thread::spawn(move || {
            super::retire_global_frame_host_owner_if_generation_in_using(
                &first_custody,
                key.0,
                key.1,
                generation,
                &mut |_, _| {
                    entered_tx.send(()).expect("announce terminal interleave");
                    resume_rx.recv().expect("resume terminal interleave");
                    Ok(())
                },
            )
        });
        entered_rx.recv().expect("first retirement reached unmap");
        let second_custody = std::sync::Arc::clone(&custody);
        let second = std::thread::spawn(move || {
            super::retire_global_frame_host_owner_if_generation_in_using(
                &second_custody,
                key.0,
                key.1,
                generation,
                &mut |_, _| panic!("serialized second retirement must not unmap"),
            )
        });
        assert!(matches!(
            second.join().expect("second retirement thread"),
            super::GlobalFrameRetirementOutcome::RetryPending { .. }
        ));
        resume_tx.send(()).expect("finish first retirement");
        assert!(matches!(
            first.join().expect("first retirement thread"),
            super::GlobalFrameRetirementOutcome::RetiredUnmapped { .. }
        ));
        assert!(custody.global_frame_host_owners.lock().get(&key).is_none());
    }

    #[test]
    fn structural_owner_drop_requests_then_safe_point_retires_with_backing_intact() {
        let (custody, _) = live_custody();
        let key = (0x7d00_1000_0000, 0x4000);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate structural backing");
        let host_addr = mapping.as_ptr() as usize;
        let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        lease.mark_test_mapped_without_backend();
        let owner = super::StructuralBackingOwner::new_in(
            &custody,
            mapping,
            lease,
            u64::from(applevisor::memory::MemPerms::ReadWriteExec),
            super::next_structural_epoch().expect("structural epoch"),
            key.0,
            key.1 as usize,
        )
        .expect("publish structural custody");
        let identity = *owner.retained.record_identity.lock();

        drop(owner);
        assert!(super::alias_backing_is_live(host_addr));
        assert!(
            custody
                .stage2_record_snapshot(identity.record_id)
                .is_some_and(|record| record.retirement_requested && record.mapped)
        );
        super::retry_structural_backing_retirements_in_using(
            &custody,
            &mut |_, _| Ok(()),
            &mut |_, _| Ok(()),
        )
        .expect("explicit safe point retires structural backing");
        assert!(custody.stage2_record_snapshot(identity.record_id).is_none());
        assert!(!super::alias_backing_is_live(host_addr));
    }

    #[test]
    fn explicit_offset_structural_retirement_unmaps_with_physical_sized_projection() {
        let _stage2_stub = super::ScopedStage2MapTestStub::enable();
        let (custody, _) = live_custody();
        let ipa = 0x7d00_1800_0000;
        let len = 0x4000_u64;
        let mapping = super::GuestMapping {
            guest_start: ipa,
            ipa_start: ipa,
            mapped_size: len,
            offset_in_mapping: 0,
            payload_size: len,
            perms: carrick_mem::elf::SegmentPerms {
                read: true,
                write: true,
                execute: false,
            },
            shared: false,
            image: std::sync::Arc::new(vec![0; len as usize]),
            private_file_backing: None,
        };
        let region = super::map_region_raw_in(&custody, &mapping, false, true)
            .expect("map structural root-slot fixture");
        let owner = region
            .structural_owner
            .as_ref()
            .cloned()
            .expect("structural root-slot owner");
        let identity = *owner.retained.record_identity.lock();
        let mm_access = super::MmAccessState::new(
            carrick_aarch64::Stage1Authority::new(),
            std::sync::Arc::new(super::MemoryProtections::default()),
            std::sync::Arc::new(parking_lot::Mutex::new(
                super::HvpatchFrameInventory::default(),
            )),
            std::sync::Arc::new(parking_lot::Mutex::new(super::CowArmedRanges::default())),
            std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
        );
        mm_access.install_structural_owner(std::sync::Arc::clone(&owner));
        drop(owner);
        let projection_offset = 0x1000_u64;
        let mut region = region;
        region.start += projection_offset;
        region.ipa += projection_offset;
        region.host_addr = region.host_addr.wrapping_add(projection_offset as usize);
        let mut mappings = super::TaskMappingIndex::from_region(region);
        // `unowned_runtime_region` intentionally retains the physical owner
        // size even when this row is only an offset semantic projection.
        assert_eq!(
            mappings.first().unwrap().size,
            mappings.first().unwrap().physical_size
        );
        assert_eq!(
            mappings.first().unwrap().end - mappings.first().unwrap().start,
            len - projection_offset,
        );

        let exact_generation = mappings.first().unwrap().owner_generation;
        mappings.first_mut().unwrap().owner_generation = exact_generation.saturating_add(1);
        let drift_error = super::HvfVmState::retire_stage2_extent_from_mappings_in(
            &custody,
            &mut mappings,
            ipa,
            len,
        )
        .expect_err("a drifted region generation must not authenticate structural retirement");
        assert!(
            drift_error
                .to_string()
                .contains("is not the exact current custody owner"),
            "unexpected structural generation-drift rejection: {drift_error}",
        );
        assert!(
            !mappings
                .first()
                .unwrap()
                .structural_owner
                .as_ref()
                .expect("drift rejection preserves structural owner")
                .retained
                .owner_retired
                .load(std::sync::atomic::Ordering::Acquire),
            "authentication failure must precede the retirement request",
        );
        assert!(
            super::ScopedStage2MapTestStub::is_mapped(ipa, len as usize),
            "generation-drift rejection must preserve the structural map",
        );
        mappings.first_mut().unwrap().owner_generation = exact_generation;

        let subextent_error = super::HvfVmState::retire_stage2_extent_from_mappings_in(
            &custody,
            &mut mappings,
            ipa + 0x1000,
            0x1000,
        )
        .expect_err("a structural subextent must not retire or bypass its whole owner");
        assert!(
            subextent_error
                .to_string()
                .contains("is not the exact current custody owner"),
            "unexpected structural subextent rejection: {subextent_error}",
        );
        assert!(
            super::ScopedStage2MapTestStub::is_mapped(ipa, len as usize),
            "failed-closed subextent retirement must preserve the whole structural map",
        );

        super::HvfVmState::retire_stage2_extent_from_mappings_in(&custody, &mut mappings, ipa, len)
            .expect("explicitly retire structural root slot");

        assert!(
            custody.stage2_record_snapshot(identity.record_id).is_none(),
            "explicit MM retirement must remove stage-2 custody even while stale MM-access metadata retains an Arc",
        );
        assert!(
            !super::ScopedStage2MapTestStub::is_mapped(ipa, len as usize),
            "the returned root slot must be available for the next child hv_vm_map",
        );
        let replacement = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            len as usize,
            crate::host_mapping::HostMappingKind::PrivateAnon,
        )
        .expect("allocate replacement root-slot backing");
        assert_eq!(
            unsafe {
                super::inventory_hv_vm_map(
                    replacement.as_ptr().cast(),
                    ipa,
                    len as usize,
                    u64::from(applevisor::memory::MemPerms::ReadWrite),
                )
            },
            0,
            "a second child must map the returned root slot while stale MM-access metadata still exists",
        );
        assert_eq!(
            unsafe { super::inventory_hv_vm_unmap(ipa, len as usize) },
            0
        );
        drop(replacement);
        drop(mm_access);
    }

    #[test]
    fn pinned_structural_retirement_refuses_root_slot_reuse_until_terminal() {
        let _stage2_stub = super::ScopedStage2MapTestStub::enable();
        let (custody, _) = live_custody();
        let ipa = 0x7d00_1c00_0000;
        let len = 0x4000_u64;
        let mapping = super::GuestMapping {
            guest_start: ipa,
            ipa_start: ipa,
            mapped_size: len,
            offset_in_mapping: 0,
            payload_size: len,
            perms: carrick_mem::elf::SegmentPerms {
                read: true,
                write: true,
                execute: false,
            },
            shared: false,
            image: std::sync::Arc::new(vec![0; len as usize]),
            private_file_backing: None,
        };
        let region = super::map_region_raw_in(&custody, &mapping, false, true)
            .expect("map pinned structural root-slot fixture");
        let owner = region
            .structural_owner
            .as_ref()
            .cloned()
            .expect("pinned structural root-slot owner");
        let identity = *owner.retained.record_identity.lock();
        let mm_access = super::MmAccessState::new(
            carrick_aarch64::Stage1Authority::new(),
            std::sync::Arc::new(super::MemoryProtections::default()),
            std::sync::Arc::new(parking_lot::Mutex::new(
                super::HvpatchFrameInventory::default(),
            )),
            std::sync::Arc::new(parking_lot::Mutex::new(super::CowArmedRanges::default())),
            std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
        );
        mm_access.install_structural_owner(std::sync::Arc::clone(&owner));
        drop(owner);
        let pin = custody
            .pin_stage2_record(identity)
            .expect("pin structural root slot");
        let mut mappings = super::TaskMappingIndex::from_region(region);

        let retirement_error = super::HvfVmState::retire_stage2_extent_from_mappings_in(
            &custody,
            &mut mappings,
            ipa,
            len,
        )
        .expect_err("active pin must prevent successful structural retirement");
        assert!(
            retirement_error
                .to_string()
                .contains("did not reach terminal retirement"),
            "unexpected active-pin retirement error: {retirement_error}",
        );
        assert!(
            custody
                .stage2_record_snapshot(identity.record_id)
                .is_some_and(|snapshot| snapshot.mapped),
            "deferred retirement must keep the old stage-2 record mapped",
        );
        let replacement = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            len as usize,
            crate::host_mapping::HostMappingKind::PrivateAnon,
        )
        .expect("allocate refused replacement root-slot backing");
        assert_ne!(
            unsafe {
                super::inventory_hv_vm_map(
                    replacement.as_ptr().cast(),
                    ipa,
                    len as usize,
                    u64::from(applevisor::memory::MemPerms::ReadWrite),
                )
            },
            0,
            "same-IPA reuse must remain refused until structural retirement is terminal",
        );
        drop(replacement);

        drop(pin);
        drop(mappings);
        drop(mm_access);
        super::retry_structural_backing_identities_in_using(
            &custody,
            &[identity],
            &mut super::unmap_global_frame_stage2_record,
            &mut super::release_retired_stage2_ipa,
        )
        .expect("clean up deferred pinned structural fixture");
    }

    #[test]
    fn live_structural_owner_rebinds_exactly_to_g2_before_late_drop() {
        let (custody, g1) = live_custody();
        let key = (0x7d00_2000_0000, 0x4000);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate rebuild structural backing");
        let host_addr = mapping.as_ptr() as usize;
        let perms = u64::from(applevisor::memory::MemPerms::ReadWriteExec);
        let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        lease.mark_test_mapped_without_backend();
        let owner = super::StructuralBackingOwner::new_in(
            &custody,
            mapping,
            lease,
            perms,
            super::next_structural_epoch().expect("structural epoch"),
            key.0,
            key.1 as usize,
        )
        .expect("publish rebuild structural custody");
        let old_identity = *owner.retained.record_identity.lock();
        assert_eq!(old_identity.vm_generation, g1);

        destroy_vm_with_custody_using(&custody, "structural G1 destroy", || 0, || {})
            .expect("destroy structural G1");
        let g2 = custody.begin_create().expect("begin structural G2");
        custody.commit_create(g2).expect("publish structural G2");
        let report = super::reconcile_global_frame_owners_after_replay_in_using(
            &custody,
            &[super::GlobalFrameReplayExtent {
                ipa: key.0,
                length: key.1,
                host_addr,
                perms,
            }],
            false,
            &mut |_, _| Ok(()),
        )
        .expect("rebind structural backing into G2");
        assert_eq!(report.rebound, 1);
        let new_identity = *owner.retained.record_identity.lock();
        assert_eq!(new_identity.vm_generation, g2);
        assert_ne!(new_identity.record_id, old_identity.record_id);
        assert!(
            custody
                .stage2_record_snapshot(old_identity.record_id)
                .is_none()
        );
        assert!(super::alias_backing_is_live(host_addr));

        drop(owner);
        assert!(
            custody
                .stage2_record_snapshot(new_identity.record_id)
                .is_some_and(|record| record.retirement_requested)
        );
    }

    #[test]
    fn creation_funnels_hold_transaction_through_setup_and_prepared_writes_hold_pin_static_audit() {
        let source = concat!(
            include_str!("../trap.rs"),
            include_str!("mapping_plan.rs"),
            include_str!("foreign_mm.rs"),
            include_str!("global_frame.rs"),
            include_str!("execve_rebuild.rs"),
            include_str!("persistent_executor.rs")
        );
        for (outer, inner) in [
            (
                concat!("pub(crate) fn new_with_", "plan("),
                "Self::new_with_plan_inner",
            ),
            (
                concat!("pub(crate) fn shared_wait_", "resume("),
                "self.shared_wait_resume_inner",
            ),
            (
                concat!("pub(crate) fn execve_", "rebuild("),
                "self.execve_rebuild_inner",
            ),
        ] {
            let body = source
                .split(outer)
                .nth(1)
                .and_then(|tail| tail.split("\n    fn ").next())
                .expect("creation funnel wrapper");
            assert!(body.contains(inner));
            assert!(body.contains("finish_pending_vm_creation"));
        }
        let prepared = source
            .split(concat!("struct CarrierForeign", "PreparedWrite<'a> {"))
            .nth(1)
            .and_then(|tail| tail.split('}').next())
            .expect("prepared foreign write fields");
        assert!(prepared.contains("_owner_pin: GlobalFrameOwnerPin"));

        let lease_drop = source
            .split(concat!("impl Drop for GlobalFrameStage2", "Lease {"))
            .nth(1)
            .and_then(|tail| tail.split("\n}\n").next())
            .expect("global-frame lease Drop body");
        assert!(!lease_drop.contains("try_retire"));
        assert!(!lease_drop.contains("inventory_hv_vm_unmap"));
        assert!(!lease_drop.contains("process::abort"));
        let structural_drop = source
            .split(concat!("impl Drop for StructuralBacking", "Owner {"))
            .nth(1)
            .and_then(|tail| tail.split("\n}\n").next())
            .expect("structural owner Drop body");
        assert!(structural_drop.contains("request_stage2_record_retirement"));
        assert!(!structural_drop.contains("inventory_hv_vm_unmap"));
        assert!(!prepared.contains("Arc<GlobalFrameHostOwner>"));
    }

    #[test]
    fn abort_destroy_preserves_the_exact_live_generation_for_retry() {
        let custody = CarrierVmCustody::new();
        let generation = custody.begin_create().expect("begin first VM create");
        custody
            .commit_create(generation)
            .expect("publish first VM generation");

        custody
            .begin_destroy(generation)
            .expect("begin first VM destroy");
        custody
            .abort_destroy(generation)
            .expect("failed backend destroy restores custody");

        assert_eq!(custody.live_generation(), Some(generation));
        custody
            .begin_destroy(generation)
            .expect("same generation remains retryable");
    }

    #[test]
    fn committed_destroy_prevents_a_stale_generation_from_mutating_its_successor() {
        let custody = CarrierVmCustody::new();
        let first = custody.begin_create().expect("begin first VM create");
        custody
            .commit_create(first)
            .expect("publish first VM generation");
        custody.begin_destroy(first).expect("begin first destroy");

        assert_eq!(
            custody.begin_create(),
            Err(CarrierVmCustodyError::LifecycleConflict)
        );

        custody
            .commit_destroy(first)
            .expect("terminalize first VM generation");
        let second = custody.begin_create().expect("begin successor VM create");
        assert_ne!(first, second);
        custody
            .commit_create(second)
            .expect("publish successor VM generation");

        assert_eq!(
            custody.begin_destroy(first),
            Err(CarrierVmCustodyError::StaleGeneration)
        );
        assert_eq!(custody.live_generation(), Some(second));
    }

    #[test]
    fn aborted_create_returns_custody_to_vacant_without_reusing_the_generation() {
        let custody = CarrierVmCustody::new();
        let failed = custody.begin_create().expect("begin failed VM create");
        custody
            .abort_create(failed)
            .expect("failed backend create returns custody");

        let successor = custody.begin_create().expect("retry VM create");
        assert_ne!(failed, successor);
        custody
            .commit_create(successor)
            .expect("publish retry generation");
        assert_eq!(custody.live_generation(), Some(successor));
    }

    #[test]
    fn backend_destroy_failure_preserves_live_custody_and_skips_release_publication() {
        let custody = CarrierVmCustody::new();
        let generation = custody.begin_create().expect("begin VM create");
        custody
            .commit_create(generation)
            .expect("publish VM generation");
        let released = std::sync::atomic::AtomicBool::new(false);

        let result = destroy_vm_with_custody_using(
            &custody,
            "test destroy",
            || 0xfae9_4001_u32 as applevisor_sys::hv_return_t,
            || released.store(true, std::sync::atomic::Ordering::SeqCst),
        );

        assert!(matches!(result, Err(super::TrapError::Hypervisor(_))));
        assert_eq!(custody.live_generation(), Some(generation));
        assert!(!released.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            custody.begin_create(),
            Err(CarrierVmCustodyError::LifecycleConflict),
            "failed destroy must not admit a successor VM"
        );
    }

    #[test]
    fn backend_destroy_success_terminalizes_before_release_publication() {
        let custody = CarrierVmCustody::new();
        let generation = custody.begin_create().expect("begin VM create");
        custody
            .commit_create(generation)
            .expect("publish VM generation");
        let released_after_terminal = std::cell::Cell::new(false);

        destroy_vm_with_custody_using(
            &custody,
            "test destroy",
            || 0,
            || released_after_terminal.set(custody.live_generation().is_none()),
        )
        .expect("destroy transaction succeeds");

        assert!(released_after_terminal.get());
        assert!(custody.begin_create().is_ok());
    }

    #[test]
    fn backend_create_failure_returns_custody_to_vacant_and_skips_publication() {
        let custody = CarrierVmCustody::new();
        let published = std::cell::Cell::new(false);

        let result = create_vm_with_custody_using(
            &custody,
            "test create",
            || {
                Err::<(), _>(super::TrapError::Hypervisor(
                    "injected create failure".into(),
                ))
            },
            || published.set(true),
        );

        assert!(matches!(result, Err(super::TrapError::Hypervisor(_))));
        assert!(!published.get());
        assert!(
            custody.begin_create().is_ok(),
            "failed create must return carrier custody to Vacant"
        );
    }

    #[test]
    fn backend_create_success_commits_generation_before_publication() {
        let custody = CarrierVmCustody::new();
        let published_generation = std::cell::Cell::new(None);

        let value = create_vm_with_custody_using(
            &custody,
            "test create",
            || Ok(17_u8),
            || published_generation.set(custody.live_generation()),
        )
        .expect("create transaction succeeds");

        assert_eq!(value, 17);
        assert_eq!(published_generation.get(), custody.live_generation());
        assert!(published_generation.get().is_some());
    }

    #[test]
    fn persistent_unmap_failure_retains_the_exact_record_for_retry() {
        let (custody, generation) = live_custody();
        let identity = custody
            .register_stage2_record(stage2_spec(generation, 11))
            .expect("register exact stage-2 record");
        let second = custody
            .register_stage2_record(CarrierStage2RecordSpec {
                ipa: 0x8000,
                host_addr: 0x5678_0000,
                ..stage2_spec(generation, 12)
            })
            .expect("register second exact stage-2 record");
        assert_ne!(identity.record_id, second.record_id);
        let injected = CarrierStage2BackendError::HvReturn(0xfae9_4001);

        assert_eq!(
            custody.retire_stage2_record_using(identity, |_, _| Err(injected)),
            CarrierStage2RetireOutcome::RetryPending(injected)
        );
        let retained = custody
            .stage2_record_snapshot(identity.record_id)
            .expect("failed unmap record remains in carrier custody");
        assert_eq!(retained.vm_generation, generation);
        assert_eq!(retained.ipa, 0x4000);
        assert_eq!(retained.len, 0x4000);
        assert_eq!(retained.host_addr, 0x1234_0000);
        assert!(retained.mapped);
        assert!(retained.release_ipa);
        assert_eq!(retained.logical_owner, identity.logical_owner);
        assert_eq!(retained.retry_pending, Some(injected));

        assert_eq!(
            custody.retire_stage2_record_using(identity, |_, _| Ok(())),
            CarrierStage2RetireOutcome::RetiredUnmapped
        );
        assert!(
            !custody
                .stage2_record_snapshot(identity.record_id)
                .expect("retired tombstone remains exact")
                .mapped
        );
    }

    #[test]
    fn carrier_safe_point_failure_retains_directory_identity_until_exact_retry_finishes() {
        let (custody, generation) = live_custody();
        let identity = custody
            .register_stage2_record(stage2_spec(generation, 13))
            .expect("register carrier stage-2 record");
        let key = (0x4000, 0x4000);
        custody.carrier_stage2_records.lock().insert(key, identity);
        let injected = CarrierStage2BackendError::HvReturn(0xfae9_4001);

        let error = super::retire_carrier_stage2_record_at_safe_point_using(
            &custody,
            identity,
            |_, _| Err(injected),
            |_, _| panic!("release must not run while unmap is retry-pending"),
        )
        .expect_err("persistent unmap failure must remain visible to its safe point");
        assert!(matches!(
            error,
            super::TrapError::Hypervisor(message) if message.contains("RetryPending")
        ));
        assert_eq!(
            custody.carrier_stage2_records.lock().get(&key),
            Some(&identity)
        );
        assert!(
            custody
                .stage2_record_snapshot(identity.record_id)
                .is_some_and(|record| record.retry_pending == Some(injected))
        );

        let mut releases = 0_u32;
        super::retire_carrier_stage2_record_at_safe_point_using(
            &custody,
            identity,
            |_, _| Ok(()),
            |_, _| {
                releases += 1;
                Ok(())
            },
        )
        .expect("exact safe-point retry retires and releases the record");
        assert_eq!(releases, 1);
        assert!(!custody.carrier_stage2_records.lock().contains_key(&key));
        assert!(custody.stage2_record_snapshot(identity.record_id).is_none());
    }

    #[test]
    fn last_pin_drop_is_non_panicking_and_only_marks_retry_eligibility() {
        let (custody, generation) = live_custody();
        let identity = custody
            .register_stage2_record(stage2_spec(generation, 21))
            .expect("register pinned record");
        let pin = custody
            .pin_stage2_record(identity)
            .expect("pin exact record");
        let unmap_calls = std::cell::Cell::new(0_u32);

        assert_eq!(
            custody.retire_stage2_record_using(identity, |_, _| {
                unmap_calls.set(unmap_calls.get() + 1);
                Ok(())
            }),
            CarrierStage2RetireOutcome::DeferredActivePins
        );
        assert_eq!(unmap_calls.get(), 0);
        assert!(matches!(
            custody.pin_stage2_record(identity),
            Err(CarrierStage2PinError::RetirementRequested)
        ));
        drop(pin);
        let eligible = custody
            .stage2_record_snapshot(identity.record_id)
            .expect("last-pin drop retains record");
        assert_eq!(eligible.pin_count, 0);
        assert!(eligible.retry_eligible);
        assert!(eligible.mapped);

        assert_eq!(
            custody.retire_stage2_record_using(identity, |_, _| {
                unmap_calls.set(unmap_calls.get() + 1);
                Ok(())
            }),
            CarrierStage2RetireOutcome::RetiredUnmapped
        );
        assert_eq!(unmap_calls.get(), 1);
    }

    #[test]
    fn successful_vm_destroy_terminalizes_generation_without_post_destroy_unmap() {
        let (custody, generation) = live_custody();
        let first = custody
            .register_stage2_record(stage2_spec(generation, 31))
            .expect("register first record");
        let second = custody
            .register_stage2_record(CarrierStage2RecordSpec {
                ipa: 0xc000,
                host_addr: 0x9abc_0000,
                ..stage2_spec(generation, 32)
            })
            .expect("register second record");

        destroy_vm_with_custody_using(&custody, "test destroy", || 0, || {})
            .expect("destroy exact generation");
        let post_destroy_unmaps = std::cell::Cell::new(0_u32);
        for identity in [first, second] {
            assert_eq!(
                custody.retire_stage2_record_using(identity, |_, _| {
                    post_destroy_unmaps.set(post_destroy_unmaps.get() + 1);
                    Ok(())
                }),
                CarrierStage2RetireOutcome::TerminalizedByVmDestroy
            );
        }
        assert_eq!(post_destroy_unmaps.get(), 0);
    }

    #[test]
    fn failed_vm_destroy_preserves_records_and_live_generation() {
        let (custody, generation) = live_custody();
        let identity = custody
            .register_stage2_record(stage2_spec(generation, 41))
            .expect("register record");
        let before = custody
            .stage2_record_snapshot(identity.record_id)
            .expect("record before destroy");

        assert!(
            destroy_vm_with_custody_using(
                &custody,
                "test destroy",
                || 0xfae9_4001_u32 as applevisor_sys::hv_return_t,
                || {},
            )
            .is_err()
        );

        assert_eq!(custody.live_generation(), Some(generation));
        assert_eq!(
            custody.stage2_record_snapshot(identity.record_id),
            Some(before)
        );
        assert_eq!(
            custody.retire_stage2_record_using(identity, |_, _| Ok(())),
            CarrierStage2RetireOutcome::RetiredUnmapped
        );
    }

    #[test]
    fn cross_generation_same_key_rejects_old_vm_and_owner_identities() {
        let (custody, first_generation) = live_custody();
        let first = custody
            .register_stage2_record(stage2_spec(first_generation, 51))
            .expect("register predecessor record");
        destroy_vm_with_custody_using(&custody, "test destroy", || 0, || {})
            .expect("destroy predecessor VM");
        let second_generation = custody.begin_create().expect("begin successor create");
        custody
            .commit_create(second_generation)
            .expect("publish successor generation");
        let second = custody
            .register_stage2_record(stage2_spec(second_generation, 52))
            .expect("register same-key successor");
        assert_ne!(first.record_id, second.record_id);
        let unmap_calls = std::cell::Cell::new(0_u32);

        assert_eq!(
            custody.retire_stage2_record_using(
                CarrierStage2RecordIdentity {
                    vm_generation: first_generation,
                    ..second
                },
                |_, _| {
                    unmap_calls.set(unmap_calls.get() + 1);
                    Ok(())
                },
            ),
            CarrierStage2RetireOutcome::VmGenerationMismatch
        );
        assert_eq!(
            custody.retire_stage2_record_using(
                CarrierStage2RecordIdentity {
                    logical_owner: first.logical_owner,
                    ..second
                },
                |_, _| {
                    unmap_calls.set(unmap_calls.get() + 1);
                    Ok(())
                },
            ),
            CarrierStage2RetireOutcome::OwnerGenerationMismatch
        );
        assert_eq!(unmap_calls.get(), 0);
        assert!(
            custody
                .stage2_record_snapshot(second.record_id)
                .expect("successor remains mapped")
                .mapped
        );
    }
}
