//! # Carrier VM Custody and Stage-2 Authority
//!
//! Monotonic lifecycle authority over the carrier's hardware VM and its stage-2
//! address translations. Hypervisor.framework binds guest physical addresses
//! into a live VM instance; this module tracks monotonically incrementing VM
//! generations, stage-2 mapping records, active pins, and structured cleanup/
//! rollback during VM creation and destruction.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use super::*;
use carrick_aarch64::stage2::custody::{
    Stage2Custody, Stage2CustodyError, Stage2CustodyState, Stage2Gone, Stage2Inner, Stage2Lifecycle,
};
use carrick_aarch64::vmm::VcpuDestroyError;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct PendingCarrierVmCreation {
    pub(crate) custody: std::sync::Arc<CarrierVmCustody>,
    pub(crate) generation: CarrierVmGeneration,
    pub(crate) probe_code: i32,
    pub(crate) vcpu_id: Option<CarrierVcpuId>,
    pub(crate) armed: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PendingCarrierVmCreation {
    pub(crate) fn record_vcpu(&mut self, vcpu_id: CarrierVcpuId) {
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
    vcpu_id: &mut Option<CarrierVcpuId>,
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
        |id| {
            let rc = destroy_raw_vcpu(id.raw(), VcpuDestroySite::CreationRollback);
            if rc == 0 {
                Ok(())
            } else {
                Err(VcpuDestroyError::from_raw(rc as u32))
            }
        },
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
    pub vcpu_id: &'a mut Option<CarrierVcpuId>,
    pub raw_vm_destroyed: &'a mut bool,
    pub context: &'a str,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn drive_pending_carrier_vm_cleanup_using(
    custody: &std::sync::Arc<CarrierVmCustody>,
    generation: CarrierVmGeneration,
    state: PendingCarrierVmCleanupState<'_>,
    mut destroy_vcpu: impl FnMut(CarrierVcpuId) -> Result<(), VcpuDestroyError>,
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
        // `destroy_vcpu` reports a successful destroy itself (`destroy_raw_vcpu`).
        if let Err(rc) = destroy_vcpu(id) {
            return Err(TrapError::Hypervisor(format!(
                "{context}: hv_vcpu_destroy rc={rc:#x}; exact vCPU cleanup retained"
            )));
        }
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
pub(crate) use carrick_core::mm::retirement::{
    CarrierLogicalOwner, CarrierStage2BackendError, CarrierStage2PinError, CarrierStage2Record,
    CarrierStage2RecordError, CarrierStage2RecordId, CarrierStage2RecordIdentity,
    CarrierStage2RecordSnapshot, CarrierStage2RecordSpec, CarrierStage2RetireOutcome,
    CarrierVmGeneration,
};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(::core::fmt::Debug)]
pub(crate) struct UntrackedStage2Mapping {
    pub(crate) mapping: carrick_aarch64::stage2::custody::Stage2Mapping,
    pub(crate) host_addr: usize,
    pub(crate) perms: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(::core::fmt::Debug)]
/// The carrier's stage-2 records, held under its [`Stage2Custody`]'s
/// lifecycle lock (the custody owns the lifecycle and the generation).
pub(crate) struct CarrierStage2Records {
    pub(crate) next_stage2_record_id: u64,
    pub(crate) next_logical_owner_id: u64,
    pub(crate) next_logical_owner_generation: u64,
    pub(crate) stage2_records:
        std::collections::BTreeMap<CarrierStage2RecordId, CarrierStage2Record>,
    pub(crate) installed: std::collections::BTreeMap<
        CarrierStage2RecordId,
        carrick_aarch64::stage2::custody::Stage2Mapping,
    >,
    pub(crate) untracked_mappings: std::collections::BTreeMap<(u64, usize), UntrackedStage2Mapping>,
    /// One physical index over every record, independent of the authority
    /// that owns its lifetime. Rebind may briefly retain predecessor IDs.
    stage2_extent_index:
        std::collections::BTreeMap<(u64, u64), std::collections::BTreeSet<CarrierStage2RecordId>>,
    pub(crate) pinned_structural_predecessors: std::collections::BTreeMap<
        CarrierStage2RecordId,
        std::collections::BTreeSet<CarrierStage2RecordId>,
    >,
    pub(crate) pinned_structural_successor:
        std::collections::BTreeMap<CarrierStage2RecordId, CarrierStage2RecordIdentity>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl CarrierStage2Records {
    fn index_record(&mut self, id: CarrierStage2RecordId, ipa: u64, len: usize) {
        self.stage2_extent_index
            .entry((ipa, len as u64))
            .or_default()
            .insert(id);
    }

    pub(crate) fn remove_record(
        &mut self,
        id: CarrierStage2RecordId,
    ) -> Option<CarrierStage2Record> {
        let _ = self.installed.remove(&id);
        let removed = self.stage2_records.remove(&id);
        if let Some(record) = &removed {
            let key = (record.snapshot.ipa, record.snapshot.len as u64);
            if let Some(ids) = self.stage2_extent_index.get_mut(&key) {
                ids.remove(&id);
                if ids.is_empty() {
                    self.stage2_extent_index.remove(&key);
                }
            }
        }
        removed
    }

    pub(crate) fn record_covering(
        &self,
        ipa: u64,
        len: usize,
    ) -> Option<CarrierStage2RecordIdentity> {
        let (&(base, length), ids) = self
            .stage2_extent_index
            .range(..=(ipa, u64::MAX))
            .next_back()?;
        let end = ipa.checked_add(len as u64)?;
        if end > base.checked_add(length)? {
            return None;
        }
        ids.iter().rev().find_map(|id| {
            let record = self.stage2_records.get(id)?;
            let snapshot = record.snapshot;
            (snapshot.mapped && !snapshot.terminalized_by_vm_destroy).then_some(
                CarrierStage2RecordIdentity {
                    record_id: *id,
                    vm_generation: snapshot.vm_generation,
                    logical_owner: snapshot.logical_owner,
                },
            )
        })
    }
}

/// The carrier's exec owner (#2305): the neutral owner the x86 carrier
/// shares, over HVF's prepared successors. HVF never parks a request.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) type NativeExecOwner =
    carrick_hal::exec_owner::ExecPreparations<crate::trap::PreparedNativeExecSuccessor>;

/// Carrier-owned VM lifecycle authority.
///
/// The state is intentionally neither static nor process-global. A failed
/// backend destroy is represented by `abort_destroy`, which restores custody of
/// the exact generation; a successful destroy must be committed before a later
/// generation can begin creation.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(::core::fmt::Debug)]
pub(crate) enum CarrierLeaseKeeperState {
    Replayable(super::global_frame::LeaseBackingKeeper),
    Abandoned {
        vm_generation: CarrierVmGeneration,
        release_ipa: Option<(u64, u64)>,
        keeper: super::global_frame::LeaseBackingKeeper,
    },
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl CarrierLeaseKeeperState {
    pub(crate) fn into_keeper(self) -> super::global_frame::LeaseBackingKeeper {
        match self {
            Self::Replayable(keeper) | Self::Abandoned { keeper, .. } => keeper,
        }
    }

    pub(crate) fn clone_keeper(&self) -> super::global_frame::LeaseBackingKeeper {
        match self {
            Self::Replayable(keeper) | Self::Abandoned { keeper, .. } => keeper.clone(),
        }
    }

    pub(crate) fn is_abandoned(&self) -> bool {
        matches!(self, Self::Abandoned { .. })
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(::core::fmt::Debug, ::core::default::Default)]
pub(crate) struct CarrierLeaseKeeperDirectory {
    pub(crate) entries: std::collections::BTreeMap<CarrierStage2RecordId, CarrierLeaseKeeperState>,
    pub(crate) drained_through: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(::core::fmt::Debug)]
pub(crate) struct DeferredStructuralLogicalRelease {
    pub(crate) state: std::sync::Weak<super::MmAccessState>,
    pub(crate) owner: std::sync::Arc<super::global_frame::StructuralBackingOwner>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl DeferredStructuralLogicalRelease {
    pub(crate) fn drain(self) {
        if let Some(mm) = self.state.upgrade() {
            mm.release_exact_structural_owner(&self.owner);
        } else {
            self.owner.release_pooled_root_slot();
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) enum TerminalReleaseClaim {
    AlreadyTerminal(Option<super::global_frame::LeaseBackingKeeper>),
    NeedsRelease { ipa: u64, length: u64 },
}

pub(crate) struct RetainedIpcWindowBacking(
    #[allow(dead_code)] std::sync::Arc<dyn super::stage2_backend::IpcWindowBacking>,
);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ::core::fmt::Debug for RetainedIpcWindowBacking {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        f.write_str("RetainedIpcWindowBacking(..)")
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(::core::fmt::Debug, ::core::default::Default)]
pub(crate) struct RetainedIpcBackings {
    drained_through: u64,
    entries: Vec<(CarrierVmGeneration, RetainedIpcWindowBacking)>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(::core::fmt::Debug)]
#[allow(dead_code)] // exercised by the lifecycle tests; wired into VM calls in the next slice
pub struct CarrierVmCustody {
    pub(crate) transfer_carrier: core::num::NonZeroU64,
    pub(crate) el1_frame_grants: std::sync::Arc<El1FrameGrantLedger>,
    /// Host COW accounting for every MM admitted to this carrier.
    pub(crate) host_cow_ledger: crate::hvf_aarch64_engine::HostCowLedger,
    pub(crate) metadata_completion:
        parking_lot::Mutex<Option<std::sync::Arc<dyn carrick_el1_abi::MetadataCompletionWake>>>,
    pub(crate) native_wait_channel_wake: parking_lot::Mutex<
        Option<std::sync::Arc<dyn crate::metadata_grant::NativeWaitChannelWake>>,
    >,
    pub(crate) metadata_aperture: parking_lot::Mutex<crate::metadata_grant::HostApertureState>,
    pub fork_stock:
        carrick_aarch64::stage2::custody::Stage2Inner<crate::fork_stock::ForkStockHostCustody>,
    pub(crate) fork_stock_install: parking_lot::Mutex<()>,
    pub(crate) retained_ipc_backings: parking_lot::Mutex<RetainedIpcBackings>,
    /// Serializes every settlement of a native child's owed returns
    /// (#1369 slice 3).
    pub(crate) return_settlement: carrick_hal::return_settlement::SettlementLock,
    pub(crate) native_frame_backings: parking_lot::Mutex<
        std::collections::BTreeMap<
            (u64, u64),
            std::sync::Weak<crate::fork_stock::NativeFrameBacking>,
        >,
    >,
    pub asids: carrick_hal::asid::AsidAllocator,
    /// The VM lifecycle, its stage-2 backend and records: the only way to
    /// map, unmap or destroy (lock order: `metadata_aperture`, then this,
    /// then every pool, stock and registry lock).
    pub(crate) stage2: Stage2Custody<CarrierStage2Records>,
    pub(crate) structural_backings: parking_lot::Mutex<
        std::collections::BTreeMap<
            CarrierStage2RecordId,
            std::sync::Arc<StructuralBackingCustodyEntry>,
        >,
    >,
    pub(crate) deferred_structural_owner_releases: parking_lot::Mutex<
        std::collections::BTreeMap<CarrierStage2RecordId, DeferredStructuralLogicalRelease>,
    >,
    /// IPA lookup for mapped structural and carrier-owned stage-2 records.
    /// The record-ID table owns their lifetime; this index only finds exact
    /// physical custody for a selected IPA.
    pub(crate) carrier_stage2_records:
        parking_lot::Mutex<std::collections::BTreeMap<(u64, u64), CarrierStage2RecordIdentity>>,
    pub(crate) carrier_lease_keepers: parking_lot::Mutex<CarrierLeaseKeeperDirectory>,
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
    pub(crate) pending_structural_retries:
        parking_lot::Mutex<PendingGlobalFrameRetirementQueue<CarrierStage2RecordId>>,
    pub(crate) frame_pool: Stage2Inner<CarrierFramePoolState>,
    pub(crate) root_slot_pool: Stage2Inner<CarrierRootSlotPoolState>,
    /// The exact backend state of every MM whose COW runtime this carrier
    /// bound, by MM id: guest COW settlement must fold an MM's completions
    /// into the state its executors use, never a stale copy found by scan.
    pub(crate) guest_cow_states:
        parking_lot::Mutex<std::collections::HashMap<u64, std::sync::Weak<MmAccessState>>>,
    pub(crate) native_exec_services:
        std::sync::Arc<crate::metadata_grant::NativeExecServiceDirectory>,
    pub(crate) native_root_replies:
        parking_lot::Mutex<crate::metadata_grant::NativeRootReplyLedger>,
    pub(crate) native_root_waits: crate::metadata_grant::NativeRootWaitLedger,
    /// Exec receipts reserved at claim, the prepared successors keyed by
    /// them, and the adopted execs awaiting settlement.
    pub(crate) native_exec_preparations: parking_lot::Mutex<NativeExecOwner>,
    pub(crate) native_exec_predecessors: parking_lot::Mutex<
        Vec<carrick_hal::fork_stock::ExecPredecessorReceipt<carrick_hal::asid::AsidGeneration>>,
    >,
    pub(crate) guest_capture: std::sync::Arc<crate::guest_capture::GuestCapture>,
    #[cfg(test)]
    pub(crate) metadata_residency_resolutions: std::sync::atomic::AtomicUsize,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl CarrierVmCustody {
    pub(crate) fn install_native_exec_service(
        &self,
        capability: carrick_core_abi::service::ExecCapabilityId,
        service: std::sync::Arc<
            dyn carrick_hal::native_exec::NativeExecHostService<crate::trap::GuestMappingPlan>,
        >,
    ) -> Result<
        crate::metadata_grant::NativeExecServiceRegistration,
        crate::metadata_grant::NativeExecRegistrationError,
    > {
        self.native_exec_services.install(capability, service)
    }

    /// Reserve the receipt for the ring's exec request `identity` asked for
    /// `successor`, before any preparation runs.
    pub(crate) fn claim_native_exec(
        &self,
        identity: carrick_core_abi::service::ServiceIdentity,
        successor: carrick_el1_abi::ReservationMm,
        root_generation: core::num::NonZeroU64,
    ) -> Result<
        carrick_core_abi::service::ExecAdoptionReceipt,
        carrick_hal::exec_owner::ExecOwnerError,
    > {
        self.native_exec_preparations
            .lock()
            .claim(identity, successor, root_generation)
            .map(|claim| claim.receipt())
    }

    /// Stage the claimed row's prepared successor and seal it: the manifest
    /// carries the receipt reserved at claim. A refusal retires the row.
    pub(crate) fn seal_native_exec_preparation(
        &self,
        receipt: carrick_core_abi::service::ExecAdoptionReceipt,
        prepared: crate::trap::PreparedNativeExecSuccessor,
    ) -> Result<(), ()> {
        let mut owner = self.native_exec_preparations.lock();
        let sealed = match owner.stage(receipt, prepared) {
            Ok(()) => owner.seal(receipt).is_ok(),
            Err((_, prepared)) => {
                drop(owner);
                drop(prepared);
                return Err(());
            }
        };
        if sealed {
            return Ok(());
        }
        let retired = owner.retire(receipt, carrick_hal::exec_owner::ExecRetireReason::Refused);
        drop(owner);
        drop(retired);
        Err(())
    }

    /// Retire the unadopted row `receipt` for `reason`, dropping what it
    /// held outside the owner's lock.
    pub(crate) fn retire_native_exec(
        &self,
        receipt: carrick_core_abi::service::ExecAdoptionReceipt,
        reason: carrick_hal::exec_owner::ExecRetireReason,
    ) -> bool {
        let retired = self.native_exec_preparations.lock().retire(receipt, reason);
        retired.is_ok()
    }

    pub(crate) fn take_native_exec_preparation(
        &self,
        receipt: carrick_core_abi::service::ExecAdoptionReceipt,
        manifest: &carrick_core_abi::service::ExecSuccessorManifest,
        execution: carrick_hal::fork_stock::GrantExecution,
    ) -> Option<(
        crate::trap::PreparedNativeExecSuccessor,
        carrick_core_abi::service::ExecSuccessorManifestView,
    )> {
        let mut owner = self.native_exec_preparations.lock();
        let (claim, _) = owner.sealed(receipt)?;
        let view = manifest.open(claim.identity(), receipt)?;
        if !claim.names_execution(self.transfer_carrier, execution) {
            return None;
        }
        let predecessor = carrick_el1_abi::ReservationMm::new(execution.binding.mm.raw())?;
        let adoption = owner.adopt(receipt, predecessor).ok()?;
        Some((adoption.data, view))
    }

    pub(crate) fn validate_native_exec_preparation(
        &self,
        receipt: carrick_core_abi::service::ExecAdoptionReceipt,
        manifest: &carrick_core_abi::service::ExecSuccessorManifest,
        execution: carrick_hal::fork_stock::GrantExecution,
    ) -> Option<carrick_core_abi::service::ExecSuccessorManifestView> {
        let owner = self.native_exec_preparations.lock();
        let (claim, prepared) = owner.sealed(receipt)?;
        let view = manifest.open(claim.identity(), receipt)?;
        if !claim.names_execution(self.transfer_carrier, execution)
            || prepared.root() != view.root
            || prepared.entry() != view.entry.raw()
            || prepared.stack_pointer() != view.stack_pointer.raw()
        {
            return None;
        }
        Some(view)
    }

    pub(crate) fn cancel_native_exec_preparation(
        &self,
        receipt: carrick_core_abi::service::ExecAdoptionReceipt,
        execution: carrick_hal::fork_stock::GrantExecution,
    ) -> bool {
        let mut owner = self.native_exec_preparations.lock();
        if !owner
            .sealed(receipt)
            .is_some_and(|(claim, _)| claim.predecessor_is(self.transfer_carrier, execution))
        {
            return false;
        }
        let Ok((prepared, _, _)) = owner.cancel(receipt) else {
            return false;
        };
        drop(owner);
        drop(prepared);
        true
    }

    /// Route the ring's settlement through the exec owner. Every HVF lane
    /// holds the root's custody, so a root settlement is never handed back.
    pub(crate) fn route_native_exec_settlement(
        &self,
        predecessor: carrick_el1_abi::ReservationMm,
        successor: carrick_el1_abi::ReservationMm,
        effects: carrick_el1_abi::ExecCommitEffects,
    ) -> Option<carrick_hal::exec_owner::SettledExec> {
        use carrick_hal::exec_owner::{ExecSettleLane, ExecSettlement};
        match self.native_exec_preparations.lock().settle(
            predecessor,
            successor,
            effects,
            ExecSettleLane::RootCustody,
        ) {
            Ok(ExecSettlement::Child(settled)) => Some(settled),
            Ok(ExecSettlement::Root(root)) => Some(root.consume()),
            Ok(ExecSettlement::NotHere) | Err(_) => None,
        }
    }

    /// Apply the exec owner's carrier-exit verdict (#2799): retire every row
    /// the run left unadopted and drop what it held outside the owner's
    /// lock, as a ring cancellation does. A sealed successor's physical
    /// frames are released here, while the VM is still live, so they are not
    /// pinned at the terminal global-frame cleanup. Returns the rows retired.
    pub(crate) fn retire_native_exec_preparations_at_carrier_exit(&self) -> usize {
        let retired = self
            .native_exec_preparations
            .lock()
            .retire_at_carrier_exit();
        retired.len()
    }

    /// What this carrier's exec owner reserved, sealed and retired.
    pub fn exec_owner_census(&self) -> carrick_hal::exec_owner::ExecOwnerCensus {
        self.native_exec_preparations.lock().census()
    }
}

/// Who owns an executable output's bytes, for the instruction-cache
/// authority.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
enum ExecutableBacking {
    /// A backing incarnation with per-page cleanliness: `(mapping, base, len)`.
    Tracked(
        std::sync::Arc<super::global_frame::GlobalFrameSharedMapping>,
        u64,
        u64,
    ),
    /// A stage-2 extent without it: `(host base, base, len)`.
    Untracked(*mut u8, u64, u64),
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl CarrierVmCustody {
    /// The backing that owns physical `ipa`: a global frame or a structural
    /// backing (tracked: its `CodeContent` carries per-page instruction-cache
    /// state), else any other carrier stage-2 extent (untracked).
    fn backing_for_ipa(&self, ipa: u64) -> Option<ExecutableBacking> {
        {
            let owners = self.global_frame_host_owners.lock();
            if let Some((&(base, len), entry)) = owners.range(..=(ipa, u64::MAX)).next_back()
                && ipa < base.saturating_add(len)
            {
                return Some(ExecutableBacking::Tracked(
                    std::sync::Arc::clone(&entry.owner().mapping),
                    base,
                    len,
                ));
            }
        }
        let (base, len, record) = {
            let records = self.carrier_stage2_records.lock();
            let (&(base, len), identity) = records.range(..=(ipa, u64::MAX)).next_back()?;
            (ipa < base.saturating_add(len)).then_some((base, len, identity.record_id))?
        };
        if let Some(entry) = self.structural_backings.lock().get(&record) {
            return Some(ExecutableBacking::Tracked(
                std::sync::Arc::clone(&entry.mapping),
                base,
                len,
            ));
        }
        // A stage-2 extent with no content owner (boot identity, fixed
        // apertures): its host address is known, its cleanliness is not.
        let host = self.stage2_record_snapshot(record)?.host_addr;
        Some(ExecutableBacking::Untracked(host as *mut u8, base, len))
    }

    /// The instruction-cache authority behind every EL0-executable
    /// publication (`HostArenaResolver::publish_user_executable`): for each
    /// backing page of `[output, output + len)`, the first publication after
    /// its incarnation or a host write invalidates it by host address; a
    /// clean page costs nothing. A carrier stage-2 extent with no content
    /// owner is invalidated every time; an output with no stage-2 record is
    /// resolved through `structural` then `rows` (the caller's MM-local
    /// lookups) and invalidated every time, and one nothing resolves has no
    /// backing to fetch from, so it needs none. Returns the number of
    /// invalidations issued (the work budget tests read it).
    pub(crate) fn publish_user_executable(
        &self,
        output: u64,
        len: u64,
        structural: impl Fn(u64, usize) -> Option<*mut u8>,
        rows: impl Fn(u64, usize) -> Option<*mut u8>,
    ) -> Result<usize, carrick_mmu_core::aarch64::PageTableError> {
        use carrick_mmu_core::aarch64::PageTableError;
        let end = output.checked_add(len).ok_or(PageTableError::BadAddress)?;
        let mut cursor = output;
        let mut invalidations = 0;
        while cursor < end {
            let (host, chunk, dirty) = match self.backing_for_ipa(cursor) {
                Some(ExecutableBacking::Untracked(host, base, extent)) => {
                    let chunk = end.min(base.saturating_add(extent)) - cursor;
                    let offset =
                        usize::try_from(cursor - base).map_err(|_| PageTableError::BadAddress)?;
                    (unsafe { host.add(offset) }, chunk, true)
                }
                Some(ExecutableBacking::Tracked(mapping, base, extent)) => {
                    // The backing owner expands dirty claims to full pages
                    // and bounds each claim/invalidation lock hold to 16 KiB.
                    let chunk = end.min(base.saturating_add(extent)) - cursor;
                    let offset =
                        usize::try_from(cursor - base).map_err(|_| PageTableError::BadAddress)?;
                    let size = usize::try_from(chunk).map_err(|_| PageTableError::BadAddress)?;
                    invalidations += mapping
                        .code_content
                        .publish_icache(offset, size, |offset, size| {
                            super::cow_engine::invalidate_instruction_cache(
                                unsafe { mapping.host_base().add(offset) },
                                size as u64,
                            );
                        })
                        .map_err(|_| PageTableError::BadAddress)?;
                    cursor += chunk;
                    continue;
                }
                None => {
                    let chunk = (end - cursor).min(4096 - (cursor & 0xfff));
                    let size = usize::try_from(chunk).map_err(|_| PageTableError::BadAddress)?;
                    match structural(cursor, size).or_else(|| rows(cursor, size)) {
                        Some(host) => (host, chunk, true),
                        // No stage-2 record and no mapping row: no memory
                        // backs this output, so no fetch can hit it and no
                        // line of it can be cached.
                        None => {
                            cursor += chunk;
                            continue;
                        }
                    }
                }
            };
            if dirty {
                super::cow_engine::invalidate_instruction_cache(host, chunk);
                invalidations += 1;
            }
            cursor += chunk;
        }
        carrick_observability::probes::hvpatch_exec_publication(
            output,
            len,
            u32::try_from(invalidations).unwrap_or(u32::MAX),
        );
        Ok(invalidations)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(::core::clone::Clone, ::core::fmt::Debug, ::core::default::Default)]
pub(crate) enum CarrierFramePoolState {
    #[default]
    Uninitialized,
    Active(std::sync::Arc<crate::frame_pool::PreMappedFramePool>),
    Failed,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(::core::clone::Clone, ::core::fmt::Debug, ::core::default::Default)]
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
    pub fn new() -> Self {
        static NEXT_CARRIER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let id = NEXT_CARRIER
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |id| id.checked_add(1),
            )
            .unwrap_or_else(|_| {
                carrick_fatal::carrick_fatal!("hvf::transfer", "carrier identity exhausted")
            });
        let transfer_carrier = core::num::NonZeroU64::new(id).unwrap_or_else(|| {
            carrick_fatal::carrick_fatal!("hvf::transfer", "zero carrier identity")
        });
        let asids = carrick_hal::asid::AsidAllocator::new();
        Self {
            transfer_carrier,
            el1_frame_grants: std::sync::Arc::new(El1FrameGrantLedger::default()),
            host_cow_ledger: crate::hvf_aarch64_engine::HostCowLedger::default(),
            metadata_completion: parking_lot::Mutex::new(None),
            native_wait_channel_wake: parking_lot::Mutex::new(None),
            metadata_aperture: parking_lot::Mutex::new(
                crate::metadata_grant::HostApertureState::new(),
            ),
            native_frame_backings: Default::default(),
            return_settlement: carrick_hal::return_settlement::SettlementLock::new(),
            fork_stock: carrick_aarch64::stage2::custody::Stage2Inner::new(
                crate::fork_stock::ForkStockHostCustody::with_asids(
                    transfer_carrier,
                    asids.clone(),
                ),
            ),
            fork_stock_install: parking_lot::Mutex::new(()),
            retained_ipc_backings: parking_lot::Mutex::new(RetainedIpcBackings::default()),
            asids,
            stage2: Stage2Custody::new(
                super::stage2_backend::HvfCarrierStage2::custody_backend(),
                CarrierStage2Records {
                    next_stage2_record_id: 1,
                    next_logical_owner_id: 1,
                    next_logical_owner_generation: 1,
                    stage2_records: std::collections::BTreeMap::new(),
                    installed: std::collections::BTreeMap::new(),
                    untracked_mappings: std::collections::BTreeMap::new(),
                    stage2_extent_index: std::collections::BTreeMap::new(),
                    pinned_structural_predecessors: std::collections::BTreeMap::new(),
                    pinned_structural_successor: std::collections::BTreeMap::new(),
                },
            ),
            structural_backings: parking_lot::Mutex::new(std::collections::BTreeMap::new()),
            deferred_structural_owner_releases: parking_lot::Mutex::new(
                std::collections::BTreeMap::new(),
            ),
            carrier_stage2_records: parking_lot::Mutex::new(std::collections::BTreeMap::new()),
            carrier_lease_keepers: parking_lot::Mutex::new(CarrierLeaseKeeperDirectory::default()),
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
            pending_structural_retries: parking_lot::Mutex::new(
                PendingGlobalFrameRetirementQueue::default(),
            ),
            frame_pool: Stage2Inner::new(CarrierFramePoolState::Uninitialized),
            root_slot_pool: Stage2Inner::new(CarrierRootSlotPoolState::Uninitialized),
            guest_cow_states: parking_lot::Mutex::new(std::collections::HashMap::new()),
            native_exec_services: std::sync::Arc::new(
                crate::metadata_grant::NativeExecServiceDirectory::default(),
            ),
            native_root_replies: parking_lot::Mutex::new(Default::default()),
            native_root_waits: Default::default(),
            native_exec_preparations: parking_lot::Mutex::new(NativeExecOwner::default()),
            native_exec_predecessors: parking_lot::Mutex::new(Vec::new()),
            guest_capture: std::sync::Arc::new(crate::guest_capture::GuestCapture::new()),
            #[cfg(test)]
            metadata_residency_resolutions: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn asid_allocator(&self) -> &carrick_hal::asid::AsidAllocator {
        &self.asids
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

    pub(crate) fn enqueue_structural_retirement_retry(&self, record_id: CarrierStage2RecordId) {
        self.pending_structural_retries.lock().enqueue(record_id);
        self.request_global_frame_retirement_retry();
    }

    pub(crate) fn take_global_frame_retirement_retry_request(&self) -> bool {
        self.pending_global_frame_retirement_retry
            .swap(false, std::sync::atomic::Ordering::AcqRel)
    }

    #[cfg(any(test, feature = "foreign-cow-test-support"))]
    pub(crate) fn new_live_fixture() -> Self {
        let custody = Self::new();
        // A fresh custody is Vacant, so both transitions hold; a failure would
        // leave no live generation, which every fixture user then reports.
        let live = custody
            .begin_create()
            .and_then(|generation| custody.commit_create(generation));
        debug_assert!(live.is_ok(), "live fixture: {live:?}");
        custody
    }

    pub(crate) fn begin_create(&self) -> Result<CarrierVmGeneration, Stage2CustodyError> {
        self.stage2.begin_create()
    }

    pub(crate) fn commit_create(
        &self,
        generation: CarrierVmGeneration,
    ) -> Result<(), Stage2CustodyError> {
        self.stage2
            .commit_create_with(generation, |_| self.native_root_waits.reset_for_new_vm())
    }

    pub(crate) fn abort_create(
        &self,
        generation: CarrierVmGeneration,
    ) -> Result<(), Stage2CustodyError> {
        self.stage2.abort_create(generation)
    }

    fn drain_ipc_backings_through(
        &self,
        generation: CarrierVmGeneration,
    ) -> Vec<RetainedIpcWindowBacking> {
        let mut retained = self.retained_ipc_backings.lock();
        retained.drained_through = retained.drained_through.max(generation.0);
        let mut retired = Vec::new();
        let mut idx = 0;
        while idx < retained.entries.len() {
            if retained.entries[idx].0.0 <= generation.0 {
                retired.push(retained.entries.swap_remove(idx).1);
            } else {
                idx += 1;
            }
        }
        retired
    }

    /// A failed setup's raw destroy left the generation `Gone`, its records
    /// already terminal; a successor may now be created.
    fn drain_abandoned_carrier_lease_keepers_locked(
        &self,
        state: &mut Stage2CustodyState<CarrierStage2Records>,
        generation: CarrierVmGeneration,
    ) -> (
        Vec<super::global_frame::LeaseBackingKeeper>,
        Vec<(u64, u64)>,
    ) {
        let mut keepers = self.carrier_lease_keepers.lock();
        keepers.drained_through = keepers.drained_through.max(generation.0);
        let doomed: Vec<_> = keepers
            .entries
            .iter()
            .filter_map(|(&record_id, entry)| match entry {
                CarrierLeaseKeeperState::Abandoned {
                    vm_generation,
                    release_ipa,
                    ..
                } if vm_generation.0 <= generation.0 => {
                    let record = state.stage2_records.get(&record_id);
                    let busy = record.is_some_and(|r| {
                        !carrick_core::mm::retirement::record_is_unpinned(r)
                            || r.snapshot.release_in_flight
                    });
                    if busy {
                        None
                    } else {
                        let extent = record
                            .and_then(|r| {
                                r.snapshot
                                    .release_ipa
                                    .then_some((r.snapshot.ipa, r.snapshot.len as u64))
                            })
                            .or(*release_ipa);
                        Some((record_id, extent))
                    }
                }
                _ => None,
            })
            .collect();
        let mut drained_keepers = Vec::with_capacity(doomed.len());
        let mut drained_ipas = Vec::new();
        for (record_id, extent) in doomed {
            let _ = state.remove_record(record_id);
            if let Some(entry) = keepers.entries.remove(&record_id) {
                drained_keepers.push(entry.into_keeper());
            }
            if let Some(extent) = extent {
                drained_ipas.push(extent);
            }
        }
        (drained_keepers, drained_ipas)
    }

    pub(crate) fn detach_and_abandon_carrier_batch_prefix_locked(
        &self,
        records: &mut std::collections::BTreeMap<(u64, u64), CarrierStage2RecordIdentity>,
        identities: &[CarrierStage2RecordIdentity],
    ) {
        let mut state = self.stage2.lock();
        let mut keepers = self.carrier_lease_keepers.lock();
        for &identity in identities {
            let Some(record) = state.stage2_records.get_mut(&identity.record_id) else {
                continue;
            };
            if Self::stage2_identity_mismatch(record, identity).is_some() {
                continue;
            }
            let key = (record.snapshot.ipa, record.snapshot.len as u64);
            if records.get(&key) == Some(&identity) {
                records.remove(&key);
            }
            let _ = carrick_core::mm::retirement::request_record_retirement(record, identity);
            if !record.snapshot.release_in_flight {
                let release_ipa = record
                    .snapshot
                    .release_ipa
                    .then_some((record.snapshot.ipa, record.snapshot.len as u64));
                if let Some(existing) = keepers.entries.remove(&identity.record_id) {
                    let keeper = existing.into_keeper();
                    keepers.entries.insert(
                        identity.record_id,
                        CarrierLeaseKeeperState::Abandoned {
                            vm_generation: identity.vm_generation,
                            release_ipa,
                            keeper,
                        },
                    );
                }
            }
        }
    }

    pub(crate) fn is_abandoned_record_settled_by_destroy(
        &self,
        identity: CarrierStage2RecordIdentity,
    ) -> bool {
        let state = self.stage2.lock();
        let keepers = self.carrier_lease_keepers.lock();
        keepers.drained_through >= identity.vm_generation.0
            && !keepers.entries.contains_key(&identity.record_id)
            && Self::stage2_record_snapshot_locked(&state, identity.record_id).is_none()
    }

    pub(crate) fn abandon_carrier_stage2_record(&self, identity: CarrierStage2RecordIdentity) {
        let mut records = self.carrier_stage2_records.lock();
        let mut state = self.stage2.lock();
        let mut settled_keeper = None;
        let mut settled_ipa = None;
        {
            let mut keepers = self.carrier_lease_keepers.lock();
            if let Some(record) = state.stage2_records.get_mut(&identity.record_id) {
                if Self::stage2_identity_mismatch(record, identity).is_none() {
                    let key = (record.snapshot.ipa, record.snapshot.len as u64);
                    if records.get(&key) == Some(&identity) {
                        records.remove(&key);
                    }
                    let _ =
                        carrick_core::mm::retirement::request_record_retirement(record, identity);
                    if !record.snapshot.release_in_flight {
                        let release_ipa = record
                            .snapshot
                            .release_ipa
                            .then_some((record.snapshot.ipa, record.snapshot.len as u64));
                        if identity.vm_generation.0 <= keepers.drained_through
                            && record.snapshot.terminalized_by_vm_destroy
                            && carrick_core::mm::retirement::record_is_unpinned(record)
                        {
                            let _ = state.remove_record(identity.record_id);
                            settled_keeper = keepers
                                .entries
                                .remove(&identity.record_id)
                                .map(CarrierLeaseKeeperState::into_keeper);
                            settled_ipa = release_ipa;
                        } else if let Some(existing) = keepers.entries.remove(&identity.record_id) {
                            let keeper = existing.into_keeper();
                            keepers.entries.insert(
                                identity.record_id,
                                CarrierLeaseKeeperState::Abandoned {
                                    vm_generation: identity.vm_generation,
                                    release_ipa,
                                    keeper,
                                },
                            );
                        }
                    }
                }
            }
        }
        drop(state);
        drop(records);
        drop(settled_keeper);
        if let Some((ipa, len)) = settled_ipa {
            let _ = super::global_frame::release_retired_stage2_ipa(ipa, len);
        }
    }

    pub(crate) fn abort_created_vm_after_raw_destroy(
        &self,
        generation: CarrierVmGeneration,
    ) -> Result<(), Stage2CustodyError> {
        let (frame_pool, root_slot_pool, drained_keepers, drained_ipas) = {
            let mut state = self.stage2.lock();
            match state.lifecycle() {
                Stage2Lifecycle::Gone(current) if current == generation => {}
                Stage2Lifecycle::Gone(_)
                | Stage2Lifecycle::Live(_)
                | Stage2Lifecycle::Destroying(_) => {
                    return Err(Stage2CustodyError::StaleGeneration);
                }
                Stage2Lifecycle::Vacant | Stage2Lifecycle::Creating(_) => {
                    return Err(Stage2CustodyError::LifecycleConflict);
                }
            }
            let frame_pool = std::mem::replace(
                &mut *self.frame_pool.lock(),
                CarrierFramePoolState::Uninitialized,
            );
            let root_slot_pool = std::mem::replace(
                &mut *self.root_slot_pool.lock(),
                CarrierRootSlotPoolState::Uninitialized,
            );
            if let CarrierFramePoolState::Active(pool) = &frame_pool {
                pool.forget_backend_mapping();
            }
            if let CarrierRootSlotPoolState::Active(pool) = &root_slot_pool {
                pool.forget_backend_mapping();
            }
            let (keepers, ipas) =
                self.drain_abandoned_carrier_lease_keepers_locked(&mut state, generation);
            (frame_pool, root_slot_pool, keepers, ipas)
        };
        let retired_ipc_backings = self.drain_ipc_backings_through(generation);
        drop(retired_ipc_backings);
        drop(frame_pool);
        drop(root_slot_pool);
        drop(drained_keepers);
        for (ipa, len) in drained_ipas {
            let _ = super::global_frame::release_retired_stage2_ipa(ipa, len);
        }
        self.stage2.finish_destroy(generation)
    }

    pub(crate) fn begin_destroy(
        &self,
        generation: CarrierVmGeneration,
    ) -> Result<(), Stage2CustodyError> {
        self.stage2.begin_destroy(generation)
    }

    pub(crate) fn abort_destroy(
        &self,
        generation: CarrierVmGeneration,
    ) -> Result<(), Stage2CustodyError> {
        self.stage2.abort_destroy(generation)
    }

    /// What the raw destroy settles under the custody lock: every record of
    /// the destroyed generation is terminal before any thread can see `Gone`.
    pub(crate) fn terminalize_generation(
        records: &mut CarrierStage2Records,
        generation: CarrierVmGeneration,
    ) {
        records
            .installed
            .retain(|_, mapping| mapping.generation() != generation);
        records
            .untracked_mappings
            .retain(|_, entry| entry.mapping.generation() != generation);
        for record in records
            .stage2_records
            .values_mut()
            .filter(|record| record.snapshot.vm_generation == generation)
        {
            carrick_core::mm::retirement::terminalize_record(record);
        }
    }

    /// The raw destroy of `generation`'s stage 2 through the custody (the
    /// only path to the backend's destroy), from `Destroying` or a failed
    /// setup's `Creating`.
    ///
    /// # Safety
    ///
    /// No vCPU of the generation may still run.
    pub(crate) unsafe fn destroy_stage2(
        &self,
        generation: CarrierVmGeneration,
    ) -> Result<carrick_aarch64::stage2::custody::Stage2Destroyed, Stage2CustodyError> {
        // SAFETY: forwarded from this function's contract.
        unsafe {
            self.stage2
                .destroy_stage2(generation, Self::terminalize_generation)
        }
    }

    /// A test's raw destroy of `generation` through the custody, with the
    /// backend scripted to succeed (no hypervisor VM in a lifecycle test).
    #[cfg(test)]
    pub(crate) fn destroy_stage2_for_test(&self, generation: CarrierVmGeneration) {
        super::stage2_backend::script_next_stage2_destroy(
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
        );
        // SAFETY: no vCPU runs in a lifecycle test.
        let destroyed = unsafe { self.destroy_stage2(generation) };
        super::stage2_backend::script_next_stage2_destroy_clear();
        drop(destroyed.unwrap_or_else(|error| panic!("test raw destroy: {error:?}")));
    }

    /// Settle a `Gone` generation: release its pools, grants and stock, then
    /// let a successor in. Failed physical proof keeps `Gone`, so it admits
    /// no successor and frees no unknown backing.
    pub(crate) fn commit_destroy(
        &self,
        generation: CarrierVmGeneration,
    ) -> Result<(), Stage2CustodyError> {
        match self.stage2.lifecycle() {
            Stage2Lifecycle::Gone(current) if current == generation => {}
            Stage2Lifecycle::Gone(_)
            | Stage2Lifecycle::Live(_)
            | Stage2Lifecycle::Destroying(_) => {
                return Err(Stage2CustodyError::StaleGeneration);
            }
            Stage2Lifecycle::Vacant | Stage2Lifecycle::Creating(_) => {
                return Err(Stage2CustodyError::LifecycleConflict);
            }
        }
        // Join physical callbacks before publishing Vacant: a successor VM
        // must never race an old callback through the process-global ABI view.
        self.native_root_waits.clear_all_before_mapping_release();
        let (destroyed_stock, drained_keepers, drained_ipas) = {
            // Match grant publication/return: aperture precedes lifecycle state.
            let mut metadata = self.metadata_aperture.lock();
            let mut state = self.stage2.lock();
            if state.lifecycle() != Stage2Lifecycle::Gone(generation) {
                return Err(Stage2CustodyError::StaleGeneration);
            }
            #[cfg(test)]
            self.stage2.at_client_point(COMMIT_DESTROY_HOLDING_STAGE2);
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
            metadata.release_destroyed_vm(generation.0, |identity| {
                let _ = state.remove_record(identity.record_id);
            });
            let (drained_keepers, drained_ipas) =
                self.drain_abandoned_carrier_lease_keepers_locked(&mut state, generation);
            let stock = std::mem::replace(
                &mut *self.fork_stock.lock(),
                crate::fork_stock::ForkStockHostCustody::with_asids(
                    self.transfer_carrier,
                    self.asids.clone(),
                ),
            );
            (stock, drained_keepers, drained_ipas)
        };
        let retired_ipc_backings = self.drain_ipc_backings_through(generation);
        drop(retired_ipc_backings);
        drop(destroyed_stock);
        drop(drained_keepers);
        for (ipa, len) in drained_ipas {
            let _ = super::global_frame::release_retired_stage2_ipa(ipa, len);
        }
        self.native_root_replies
            .lock()
            .release_destroyed_vm()
            .map_err(|_| Stage2CustodyError::UnsettledAfterDestroy)?;
        self.stage2.finish_destroy(generation)
    }

    pub(crate) fn retain_unretired_ipc_backing(
        &self,
        generation: CarrierVmGeneration,
        backing: std::sync::Arc<dyn super::stage2_backend::IpcWindowBacking>,
    ) {
        let wrapped = RetainedIpcWindowBacking(backing);
        let mut retained = self.retained_ipc_backings.lock();
        if generation.0 <= retained.drained_through {
            drop(retained);
            drop(wrapped);
            return;
        }
        retained.entries.push((generation, wrapped));
    }

    pub(crate) fn frame_pool(
        &self,
    ) -> Option<std::sync::Arc<crate::frame_pool::PreMappedFramePool>> {
        if !crate::frame_pool::is_frame_pool_enabled() {
            return None;
        }
        // Hold the admitting generation's guard across construction and pool
        // publication so no destroy_stage2 can race the backend map.
        let mut stage2 = self.stage2.stage2()?;
        if !stage2.admits_mappings() {
            return None;
        }
        self.stage2.at_client_point(FRAME_POOL_ADMITTED);
        let mut guard = self.frame_pool.lock();
        match &*guard {
            CarrierFramePoolState::Active(pool) => Some(std::sync::Arc::clone(pool)),
            CarrierFramePoolState::Failed => None,
            CarrierFramePoolState::Uninitialized => {
                match crate::frame_pool::PreMappedFramePool::try_new(&mut stage2) {
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
        // Hold the admitting generation's guard across construction and pool
        // publication so no destroy_stage2 can race the backend map.
        let mut stage2 = self.stage2.stage2()?;
        if !stage2.admits_mappings() {
            return None;
        }
        self.stage2.at_client_point(ROOT_SLOT_POOL_ADMITTED);
        let mut guard = self.root_slot_pool.lock();
        match &*guard {
            CarrierRootSlotPoolState::Active(pool) => Some(std::sync::Arc::clone(pool)),
            CarrierRootSlotPoolState::Failed => None,
            CarrierRootSlotPoolState::Uninitialized => {
                match crate::frame_pool::PreMappedRootSlotPool::try_new(&mut stage2) {
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
        match self.stage2.lifecycle() {
            Stage2Lifecycle::Live(generation) => Some(generation),
            Stage2Lifecycle::Vacant
            | Stage2Lifecycle::Gone(_)
            | Stage2Lifecycle::Creating(_)
            | Stage2Lifecycle::Destroying(_) => None,
        }
    }

    pub(crate) fn setup_generation(&self) -> Option<CarrierVmGeneration> {
        match self.stage2.lifecycle() {
            Stage2Lifecycle::Creating(generation) | Stage2Lifecycle::Live(generation) => {
                Some(generation)
            }
            Stage2Lifecycle::Vacant | Stage2Lifecycle::Gone(_) | Stage2Lifecycle::Destroying(_) => {
                None
            }
        }
    }

    pub(crate) fn creating_generation(&self) -> Option<CarrierVmGeneration> {
        match self.stage2.lifecycle() {
            Stage2Lifecycle::Creating(generation) => Some(generation),
            Stage2Lifecycle::Vacant
            | Stage2Lifecycle::Gone(_)
            | Stage2Lifecycle::Live(_)
            | Stage2Lifecycle::Destroying(_) => None,
        }
    }

    pub(crate) fn stage2_record_identities(&self) -> Vec<CarrierStage2RecordIdentity> {
        self.stage2
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

    /// The guard of the generation that admits mappings now (`Creating` or
    /// `Live`): what every stage-2 map holds across the map and its record.
    pub(crate) fn admitting_stage2(
        &self,
        context: &str,
    ) -> Result<super::stage2_backend::CarrierStage2<'_>, TrapError> {
        let stage2 = self.stage2.stage2();
        if let Some(stage2) = stage2 {
            if stage2.admits_mappings() {
                return Ok(stage2);
            }
            let lifecycle = stage2.lifecycle();
            drop(stage2);
            return Err(TrapError::Hypervisor(format!(
                "{context}: carrier VM admits no stage-2 mapping (lifecycle {lifecycle:?})"
            )));
        }
        Err(TrapError::Hypervisor(format!(
            "{context}: carrier VM has no stage 2"
        )))
    }

    /// The admitting guard of exact generation `generation`, failing if its
    /// stage 2 is already gone or no longer admits mappings.
    pub(crate) fn admitting_stage2_in(
        &self,
        generation: CarrierVmGeneration,
        context: &str,
    ) -> Result<super::stage2_backend::CarrierStage2<'_>, TrapError> {
        let stage2 = self.stage2.stage2_in(generation).map_err(|_| {
            TrapError::Hypervisor(format!(
                "{context}: carrier VM generation {generation:?} is gone"
            ))
        })?;
        if stage2.admits_mappings() {
            return Ok(stage2);
        }
        let lifecycle = stage2.lifecycle();
        drop(stage2);
        Err(TrapError::Hypervisor(format!(
            "{context}: carrier VM admits no stage-2 mapping (lifecycle {lifecycle:?})"
        )))
    }

    #[cfg(test)]
    pub(crate) fn allocate_logical_owner(
        &self,
    ) -> Result<CarrierLogicalOwner, CarrierStage2RecordError> {
        Self::allocate_logical_owner_locked(&mut self.stage2.lock())
    }

    pub(crate) fn allocate_logical_owner_in(
        stage2: &mut super::stage2_backend::CarrierStage2<'_>,
    ) -> Result<CarrierLogicalOwner, CarrierStage2RecordError> {
        Self::allocate_logical_owner_locked(stage2)
    }

    fn allocate_logical_owner_locked(
        state: &mut Stage2CustodyState<CarrierStage2Records>,
    ) -> Result<CarrierLogicalOwner, CarrierStage2RecordError> {
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
        let mut state = self.stage2.lock();
        let record = state.stage2_records.get(&identity.record_id)?;
        if Self::stage2_identity_mismatch(record, identity).is_some()
            || !carrick_core::mm::retirement::record_is_unpinned(record)
            || (record.snapshot.mapped && !record.snapshot.terminalized_by_vm_destroy)
        {
            return None;
        }
        state
            .remove_record(identity.record_id)
            .map(|record| record.snapshot)
    }

    pub(crate) fn claim_terminal_stage2_release_with_keeper(
        &self,
        identity: CarrierStage2RecordIdentity,
    ) -> Result<TerminalReleaseClaim, CarrierStage2RecordError> {
        let mut state = self.stage2.lock();
        let record = state
            .stage2_records
            .get_mut(&identity.record_id)
            .ok_or(CarrierStage2RecordError::RecordNotFound)?;
        if Self::stage2_identity_mismatch(record, identity).is_some()
            || record.snapshot.superseded_by_rebind
        {
            return Err(CarrierStage2RecordError::RecordIdentityMismatch);
        }
        let has_pinned_predecessor = state
            .pinned_structural_predecessors
            .contains_key(&identity.record_id);
        let record = state
            .stage2_records
            .get_mut(&identity.record_id)
            .ok_or(CarrierStage2RecordError::RecordNotFound)?;
        if has_pinned_predecessor
            || !carrick_core::mm::retirement::record_is_unpinned(record)
            || (record.snapshot.mapped && !record.snapshot.terminalized_by_vm_destroy)
        {
            return Err(CarrierStage2RecordError::RecordNotTerminal);
        }
        if record.snapshot.release_in_flight {
            return Err(CarrierStage2RecordError::ReleaseInFlight);
        }
        if !record.snapshot.release_ipa {
            let _ = state.remove_record(identity.record_id);
            let keeper = self
                .carrier_lease_keepers
                .lock()
                .entries
                .remove(&identity.record_id)
                .map(CarrierLeaseKeeperState::into_keeper);
            return Ok(TerminalReleaseClaim::AlreadyTerminal(keeper));
        }
        record.snapshot.release_in_flight = true;
        record.snapshot.release_retry_pending = false;
        Ok(TerminalReleaseClaim::NeedsRelease {
            ipa: record.snapshot.ipa,
            length: record.snapshot.len as u64,
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn claim_terminal_stage2_release(
        &self,
        identity: CarrierStage2RecordIdentity,
    ) -> Result<Option<(u64, u64)>, CarrierStage2RecordError> {
        match self.claim_terminal_stage2_release_with_keeper(identity)? {
            TerminalReleaseClaim::AlreadyTerminal(keeper) => {
                drop(keeper);
                Ok(None)
            }
            TerminalReleaseClaim::NeedsRelease { ipa, length } => Ok(Some((ipa, length))),
        }
    }

    pub(crate) fn commit_terminal_stage2_release_with_keeper(
        &self,
        identity: CarrierStage2RecordIdentity,
    ) -> Option<super::global_frame::LeaseBackingKeeper> {
        let mut state = self.stage2.lock();
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
            let _ = state.remove_record(identity.record_id);
            self.carrier_lease_keepers
                .lock()
                .entries
                .remove(&identity.record_id)
                .map(CarrierLeaseKeeperState::into_keeper)
        } else {
            None
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn commit_terminal_stage2_release(&self, identity: CarrierStage2RecordIdentity) {
        let keeper = self.commit_terminal_stage2_release_with_keeper(identity);
        drop(keeper);
    }

    pub(crate) fn abort_terminal_stage2_release(&self, identity: CarrierStage2RecordIdentity) {
        let mut state = self.stage2.lock();
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
        let mut state = self.stage2.lock();
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
        stage2: &mut super::stage2_backend::CarrierStage2<'_>,
        spec: CarrierStage2RecordSpec,
    ) -> Result<CarrierStage2RecordIdentity, CarrierStage2RecordError> {
        Self::register_stage2_record_locked(stage2, spec)
    }

    pub(crate) fn register_stage2_record_with_mapping(
        stage2: &mut super::stage2_backend::CarrierStage2<'_>,
        spec: CarrierStage2RecordSpec,
        mapping: Option<carrick_aarch64::stage2::custody::Stage2Mapping>,
    ) -> Result<
        CarrierStage2RecordIdentity,
        (
            CarrierStage2RecordError,
            Option<carrick_aarch64::stage2::custody::Stage2Mapping>,
        ),
    > {
        if spec.backend_map_installed != mapping.is_some() {
            return Err((CarrierStage2RecordError::InvalidExtent, mapping));
        }
        if let Some(ref installed) = mapping {
            if installed.generation() != spec.vm_generation {
                return Err((CarrierStage2RecordError::VmGenerationMismatch, mapping));
            }
            if installed.ipa() != spec.ipa || installed.size() != spec.len {
                return Err((CarrierStage2RecordError::InvalidExtent, mapping));
            }
        }
        let identity = match Self::register_stage2_record_locked(stage2, spec) {
            Ok(identity) => identity,
            Err(error) => return Err((error, mapping)),
        };
        if let Some(installed) = mapping {
            stage2.installed.insert(identity.record_id, installed);
        }
        Ok(identity)
    }

    /// Commit backend mapping and its exact record under a held generation guard.
    /// The backend callback must not re-enter custody. All fallible record
    /// admission happens before map; a failed map removes the unpublished record.
    pub(crate) fn publish_stage2_record_in(
        stage2: &mut super::stage2_backend::CarrierStage2<'_>,
        spec: CarrierStage2RecordSpec,
        map: impl FnOnce(
            &mut super::stage2_backend::CarrierStage2<'_>,
            CarrierStage2RecordIdentity,
        ) -> Result<
            Option<carrick_aarch64::stage2::custody::Stage2Mapping>,
            carrick_aarch64::stage2::Stage2Status,
        >,
    ) -> Result<CarrierStage2RecordIdentity, TrapError> {
        let identity = Self::register_stage2_record_locked(stage2, spec).map_err(|error| {
            TrapError::Hypervisor(format!("stage-2 record admission: {error:?}"))
        })?;
        match map(stage2, identity) {
            Ok(maybe_mapping) => {
                if spec.backend_map_installed != maybe_mapping.is_some() {
                    let _ = stage2.remove_record(identity.record_id);
                    if let Some(mapping) = maybe_mapping {
                        let _ = unsafe { stage2.unmap(mapping) };
                    }
                    return Err(TrapError::Hypervisor(format!(
                        "stage-2 record backend mapping mismatch at IPA {:#x}/{}",
                        spec.ipa, spec.len
                    )));
                }
                if let Some(mapping) = maybe_mapping {
                    if mapping.generation() != spec.vm_generation
                        || mapping.ipa() != spec.ipa
                        || mapping.size() != spec.len
                    {
                        let _ = stage2.remove_record(identity.record_id);
                        let _ = unsafe { stage2.unmap(mapping) };
                        return Err(TrapError::Hypervisor(format!(
                            "stage-2 record mapping extent mismatch at IPA {:#x}/{}",
                            spec.ipa, spec.len
                        )));
                    }
                    stage2.installed.insert(identity.record_id, mapping);
                }
                Ok(identity)
            }
            Err(rc) => {
                let _ = stage2.remove_record(identity.record_id);
                Err(TrapError::Hypervisor(format!(
                    "stage-2 map failed: {rc:#x}"
                )))
            }
        }
    }

    /// Commit backend mapping and its exact record under one generation guard.
    /// The backend callback receives `&mut CarrierStage2<'_>` so it can map
    /// without re-entering custody. All fallible record admission happens
    /// before map; a failed map removes the unpublished record.
    pub(crate) fn publish_stage2_record_using(
        &self,
        spec: CarrierStage2RecordSpec,
        map: impl FnOnce(
            &mut super::stage2_backend::CarrierStage2<'_>,
            CarrierStage2RecordIdentity,
        ) -> Result<
            Option<carrick_aarch64::stage2::custody::Stage2Mapping>,
            carrick_aarch64::stage2::Stage2Status,
        >,
    ) -> Result<CarrierStage2RecordIdentity, TrapError> {
        let mut stage2 = self
            .admitting_stage2_in(spec.vm_generation, "stage-2 record admission")
            .map_err(|_| TrapError::Hypervisor("stage-2 record admission: NoLiveVm".to_owned()))?;
        Self::publish_stage2_record_in(&mut stage2, spec, map)
    }

    #[cfg(test)]
    pub(crate) fn publish_test_stage2_record_using(
        &self,
        spec: CarrierStage2RecordSpec,
        map: impl FnOnce(
            &mut super::stage2_backend::CarrierStage2<'_>,
            CarrierStage2RecordIdentity,
        ) -> carrick_aarch64::stage2::Stage2Status,
    ) -> Result<CarrierStage2RecordIdentity, TrapError> {
        let mut stage2 = self
            .admitting_stage2_in(spec.vm_generation, "stage-2 record admission")
            .map_err(|_| TrapError::Hypervisor("stage-2 record admission: NoLiveVm".to_owned()))?;
        let identity = Self::register_stage2_record_locked(&mut stage2, spec).map_err(|error| {
            TrapError::Hypervisor(format!("stage-2 record admission: {error:?}"))
        })?;
        let rc = map(&mut stage2, identity);
        if rc != 0 {
            let _ = stage2.remove_record(identity.record_id);
            return Err(TrapError::Hypervisor(format!(
                "stage-2 map failed: {rc:#x}"
            )));
        }
        Ok(identity)
    }

    fn register_stage2_record_locked(
        state: &mut Stage2CustodyState<CarrierStage2Records>,
        spec: CarrierStage2RecordSpec,
    ) -> Result<CarrierStage2RecordIdentity, CarrierStage2RecordError> {
        if spec.len == 0 || (spec.mapped && spec.host_addr == 0) {
            return Err(CarrierStage2RecordError::InvalidExtent);
        }
        match state.lifecycle() {
            Stage2Lifecycle::Creating(generation) | Stage2Lifecycle::Live(generation)
                if generation == spec.vm_generation => {}
            Stage2Lifecycle::Creating(_) | Stage2Lifecycle::Live(_) => {
                return Err(CarrierStage2RecordError::VmGenerationMismatch);
            }
            Stage2Lifecycle::Vacant | Stage2Lifecycle::Gone(_) | Stage2Lifecycle::Destroying(_) => {
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
        state.index_record(record_id, spec.ipa, spec.len);
        Ok(identity)
    }

    pub(crate) fn rebind_terminal_stage2_record(
        stage2: &mut super::stage2_backend::CarrierStage2<'_>,
        old_identity: CarrierStage2RecordIdentity,
        host_addr: usize,
        perms: u64,
    ) -> Result<CarrierStage2RecordIdentity, CarrierStage2RecordError> {
        let state = &mut **stage2;
        let live_generation = match state.lifecycle() {
            Stage2Lifecycle::Creating(generation) | Stage2Lifecycle::Live(generation) => generation,
            Stage2Lifecycle::Vacant | Stage2Lifecycle::Gone(_) | Stage2Lifecycle::Destroying(_) => {
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
        let untracked_key = (old.snapshot.ipa, old.snapshot.len);
        let entry = state
            .untracked_mappings
            .get(&untracked_key)
            .ok_or(CarrierStage2RecordError::InvalidExtent)?;
        if entry.mapping.generation() != live_generation {
            return Err(CarrierStage2RecordError::VmGenerationMismatch);
        }
        if entry.host_addr != host_addr || entry.perms != perms {
            return Err(CarrierStage2RecordError::RecordIdentityMismatch);
        }
        let stage2_mapping = state
            .untracked_mappings
            .remove(&untracked_key)
            .ok_or(CarrierStage2RecordError::InvalidExtent)?
            .mapping;
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
        state.installed.insert(record_id, stage2_mapping);
        state.index_record(record_id, old.snapshot.ipa, old.snapshot.len);
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
        Self::stage2_record_snapshot_locked(&self.stage2.lock(), record_id)
    }

    pub(crate) fn stage2_record_snapshot_in(
        stage2: &super::stage2_backend::CarrierStage2<'_>,
        record_id: CarrierStage2RecordId,
    ) -> Option<CarrierStage2RecordSnapshot> {
        Self::stage2_record_snapshot_locked(stage2, record_id)
    }

    fn stage2_record_snapshot_locked(
        state: &Stage2CustodyState<CarrierStage2Records>,
        record_id: CarrierStage2RecordId,
    ) -> Option<CarrierStage2RecordSnapshot> {
        state
            .stage2_records
            .get(&record_id)
            .map(|record| record.snapshot)
    }

    pub(crate) fn stage2_record_covering(
        &self,
        ipa: u64,
        len: usize,
    ) -> Option<CarrierStage2RecordIdentity> {
        self.stage2.lock().record_covering(ipa, len)
    }

    pub(crate) fn stage2_record_covering_in(
        state: &Stage2CustodyState<CarrierStage2Records>,
        ipa: u64,
        len: usize,
    ) -> Option<CarrierStage2RecordIdentity> {
        state.record_covering(ipa, len)
    }

    pub(crate) fn stage2_identity_mismatch(
        record: &CarrierStage2Record,
        identity: CarrierStage2RecordIdentity,
    ) -> Option<CarrierStage2RetireOutcome> {
        carrick_core::mm::retirement::record_identity_mismatch(record, identity)
    }

    pub(crate) fn pin_stage2_record(
        self: &std::sync::Arc<Self>,
        identity: CarrierStage2RecordIdentity,
    ) -> Result<CarrierStage2Pin, CarrierStage2PinError> {
        let mut state = self.stage2.lock();
        match state.lifecycle() {
            Stage2Lifecycle::Live(generation) if generation == identity.vm_generation => {}
            Stage2Lifecycle::Live(_) => {
                return Err(CarrierStage2PinError::VmGenerationMismatch);
            }
            Stage2Lifecycle::Vacant
            | Stage2Lifecycle::Gone(_)
            | Stage2Lifecycle::Creating(_)
            | Stage2Lifecycle::Destroying(_) => {
                return Err(CarrierStage2PinError::VmNotLive);
            }
        }
        let record = state
            .stage2_records
            .get_mut(&identity.record_id)
            .ok_or(CarrierStage2PinError::NotFound)?;
        carrick_core::mm::retirement::pin_record(
            record,
            identity,
            CarrierPinVenue(std::sync::Arc::downgrade(self)),
        )
    }

    pub(crate) fn request_stage2_record_retirement(
        &self,
        identity: CarrierStage2RecordIdentity,
    ) -> CarrierStage2RetireOutcome {
        let mut state = self.stage2.lock();
        let Some(record) = state.stage2_records.get_mut(&identity.record_id) else {
            return CarrierStage2RetireOutcome::NotFound;
        };
        carrick_core::mm::retirement::request_record_retirement(record, identity)
    }

    pub(crate) fn retire_stage2_record(
        &self,
        identity: CarrierStage2RecordIdentity,
    ) -> CarrierStage2RetireOutcome {
        self.retire_stage2_record_with(identity, None)
    }

    #[cfg(test)]
    pub(crate) fn retire_stage2_record_using(
        &self,
        identity: CarrierStage2RecordIdentity,
        unmap: impl FnOnce(u64, usize) -> Result<(), CarrierStage2BackendError>,
    ) -> CarrierStage2RetireOutcome {
        let mut unmap = Some(unmap);
        let mut unmap_fn = |ipa, len| {
            unmap
                .take()
                .expect("test retire unmap callback called at most once")(ipa, len)
        };
        self.retire_stage2_record_with(identity, Some(&mut unmap_fn))
    }

    fn retire_stage2_record_with(
        &self,
        identity: CarrierStage2RecordIdentity,
        test_unmap: Option<&mut dyn FnMut(u64, usize) -> Result<(), CarrierStage2BackendError>>,
    ) -> CarrierStage2RetireOutcome {
        use carrick_core::mm::retirement::{
            RecordRetirement, prepare_record_retirement_with_external_pins,
            settle_record_retirement,
        };
        // The decision to unmap, the backend unmap and its settlement run
        // under one guard of the record's own generation: no raw destroy, and
        // so no successor VM, can run between them.
        let mut stage2 = match self.stage2.stage2_in(identity.vm_generation) {
            Ok(stage2) => stage2,
            Err(Stage2Gone) => {
                // No stage 2 is left to unmap: the generation's raw destroy
                // terminalized its records under the same lock.
                let mut state = self.stage2.lock();
                let has_pinned_predecessor = state
                    .pinned_structural_predecessors
                    .contains_key(&identity.record_id);
                let Some(record) = state.stage2_records.get_mut(&identity.record_id) else {
                    return CarrierStage2RetireOutcome::NotFound;
                };
                return match prepare_record_retirement_with_external_pins(
                    record,
                    identity,
                    has_pinned_predecessor,
                ) {
                    RecordRetirement::Complete(outcome) => outcome,
                    RecordRetirement::Unmap { .. } => {
                        // Every record created under a generation is terminalized by
                        // commit_destroy before its stage 2 leaves stage2_in; fail closed
                        // without dropping host backing if an invariant violation arrives here.
                        settle_record_retirement(
                            record,
                            identity,
                            Err(CarrierStage2BackendError::HvReturn(0xfae9_4001)),
                        )
                    }
                };
            }
        };
        let has_pinned_predecessor = stage2
            .pinned_structural_predecessors
            .contains_key(&identity.record_id);
        let Some(record) = stage2.stage2_records.get_mut(&identity.record_id) else {
            return CarrierStage2RetireOutcome::NotFound;
        };
        let (ipa, len) = match prepare_record_retirement_with_external_pins(
            record,
            identity,
            has_pinned_predecessor,
        ) {
            RecordRetirement::Complete(outcome) => return outcome,
            RecordRetirement::Unmap { ipa, len } => (ipa, len),
        };
        let mapping = stage2.installed.remove(&identity.record_id);
        self.stage2.at_client_point(RECORD_UNMAP_PREPARED);
        let backend_result = if let Some(unmap) = test_unmap {
            let result = unmap(ipa, len);
            if result.is_err()
                && let Some(mapping) = mapping
            {
                stage2.installed.insert(identity.record_id, mapping);
            }
            result
        } else if let Some(mapping) = mapping {
            // SAFETY: the record retirement is prepared under its generation
            // guard and has zero active pins.
            match unsafe { stage2.unmap(mapping) } {
                Ok(()) => Ok(()),
                Err((mapping, status)) => {
                    stage2.installed.insert(identity.record_id, mapping);
                    Err(CarrierStage2BackendError::HvReturn(status.raw()))
                }
            }
        } else {
            Err(CarrierStage2BackendError::HvReturn(0xfae9_4001))
        };
        let Some(record) = stage2.stage2_records.get_mut(&identity.record_id) else {
            return CarrierStage2RetireOutcome::NotFound;
        };
        settle_record_retirement(record, identity, backend_result)
    }
}

/// The custody hook point where a record's retirement has decided to unmap
/// and is about to call the backend.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) const RECORD_UNMAP_PREPARED: &str = "record unmap prepared";

/// The custody hook points where a pre-mapped pool's construction has been
/// admitted for the current generation and is about to map the pool.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) const FRAME_POOL_ADMITTED: &str = "frame pool admitted";
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) const ROOT_SLOT_POOL_ADMITTED: &str = "root slot pool admitted";
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) const REPLAY_REBIND_ADMITTED: &str = "replay rebind admitted";
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) const IPC_WINDOW_ADMITTED: &str = "ipc window admitted";
#[cfg(test)]
pub(crate) const FORK_STOCK_INSTALL_BEFORE_ARENAS: &str = "fork stock install before arenas";
#[cfg(test)]
pub(crate) const STRUCTURAL_DIRECTORY_CONTENDED: &str = "structural directory contended";
#[cfg(test)]
pub(crate) const FORK_CONTROL_CAPACITY_BEFORE_INSTALL: &str =
    "fork control capacity before install";
#[cfg(test)]
pub(crate) const COMMIT_DESTROY_HOLDING_STAGE2: &str = "commit destroy holding stage2";
#[cfg(test)]
pub(crate) const REPLAY_REMAP_DURING_PHASE1_LOOKUP: &str = "replay remap during phase1 lookup";
#[cfg(test)]
pub(crate) const REPLAY_SLICE_BETWEEN_LOCKS: &str = "replay slice between locks";
#[cfg(test)]
pub(crate) const REPLAY_PHASE1_BEFORE_LIVENESS_PROBE: &str = "replay phase1 before liveness probe";
#[cfg(test)]
pub(crate) const REPLAY_REMAP_BEFORE_GUARD: &str = "replay remap before guard";
#[cfg(test)]
pub(crate) const REPLAY_REMAP_LOOKED_UP: &str = "replay remap looked up";

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(::core::fmt::Debug)]
pub(crate) struct CarrierPinVenue(std::sync::Weak<CarrierVmCustody>);
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl carrick_core::mm::retirement::RecordPinVenue for CarrierPinVenue {
    fn release_pin(&self, identity: CarrierStage2RecordIdentity) {
        if let Some(custody) = self.0.upgrade() {
            custody.release_stage2_pin(identity);
        }
    }
}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) type CarrierStage2Pin = carrick_core::mm::retirement::RecordPin<CarrierPinVenue>;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl CarrierVmCustody {
    /// Release one pin on the exact record `identity` (the drop half of
    /// [`Self::pin_stage2_record`]).
    pub(crate) fn has_pinned_structural_predecessor(
        &self,
        record_id: CarrierStage2RecordId,
    ) -> bool {
        self.stage2
            .lock()
            .pinned_structural_predecessors
            .contains_key(&record_id)
    }

    pub(crate) fn is_structural_owner_retired(&self, record_id: CarrierStage2RecordId) -> bool {
        self.structural_backings
            .lock()
            .get(&record_id)
            .is_some_and(|retained| {
                retained
                    .owner_retired
                    .load(std::sync::atomic::Ordering::Acquire)
            })
    }

    pub(crate) fn has_deferred_structural_logical_release(
        &self,
        record_id: CarrierStage2RecordId,
    ) -> bool {
        self.deferred_structural_owner_releases
            .lock()
            .contains_key(&record_id)
    }

    pub(crate) fn take_deferred_structural_logical_release(
        &self,
        record_id: CarrierStage2RecordId,
    ) -> Option<DeferredStructuralLogicalRelease> {
        self.deferred_structural_owner_releases
            .lock()
            .remove(&record_id)
    }

    pub(crate) fn rebind_deferred_structural_logical_release(
        &self,
        old_id: CarrierStage2RecordId,
        new_id: CarrierStage2RecordId,
    ) {
        let mut deferred = self.deferred_structural_owner_releases.lock();
        if let Some(entry) = deferred.remove(&old_id) {
            deferred.insert(new_id, entry);
        }
        self.pending_structural_retries.lock().complete(old_id);
    }

    pub(crate) fn release_stage2_pin(&self, identity: CarrierStage2RecordIdentity) {
        use carrick_core::mm::retirement::{
            RecordPinRelease, record_is_unpinned, release_record_pin_outcome,
        };
        let (
            outcome,
            settles_last_pin,
            predecessor_keeper,
            successor_to_retire,
            abandoned_settlement,
        ) = {
            let mut state = self.stage2.lock();
            let Some(record) = state.stage2_records.get_mut(&identity.record_id) else {
                return;
            };
            let outcome = release_record_pin_outcome(record, identity);
            let settles_last_pin = matches!(
                outcome,
                RecordPinRelease::ReadyToRetry | RecordPinRelease::ReadyToRetire { .. }
            );
            let mut predecessor_keeper = None;
            let mut successor_to_retire = None;
            let mut abandoned_settlement = None;
            if outcome == RecordPinRelease::RemovePredecessor {
                let _ = state.remove_record(identity.record_id);
                if let Some(successor) = state
                    .pinned_structural_successor
                    .remove(&identity.record_id)
                {
                    let became_unpinned = match state
                        .pinned_structural_predecessors
                        .get_mut(&successor.record_id)
                    {
                        Some(preds) => {
                            preds.remove(&identity.record_id);
                            preds.is_empty()
                        }
                        None => false,
                    };
                    if became_unpinned {
                        state
                            .pinned_structural_predecessors
                            .remove(&successor.record_id);
                        successor_to_retire = Some(successor);
                    }
                }
                predecessor_keeper = self
                    .carrier_lease_keepers
                    .lock()
                    .entries
                    .remove(&identity.record_id)
                    .map(CarrierLeaseKeeperState::into_keeper);
            } else if settles_last_pin
                && record.snapshot.terminalized_by_vm_destroy
                && record_is_unpinned(record)
                && !record.snapshot.release_in_flight
            {
                let mut keepers = self.carrier_lease_keepers.lock();
                if let Some(CarrierLeaseKeeperState::Abandoned { vm_generation, .. }) =
                    keepers.entries.get(&identity.record_id)
                    && vm_generation.0 <= keepers.drained_through
                {
                    let release_ipa = record
                        .snapshot
                        .release_ipa
                        .then_some((record.snapshot.ipa, record.snapshot.len as u64));
                    let _ = state.remove_record(identity.record_id);
                    let keeper = keepers
                        .entries
                        .remove(&identity.record_id)
                        .map(CarrierLeaseKeeperState::into_keeper);
                    abandoned_settlement = Some((keeper, release_ipa));
                }
            }
            (
                outcome,
                settles_last_pin,
                predecessor_keeper,
                successor_to_retire,
                abandoned_settlement,
            )
        };
        drop(predecessor_keeper);
        if let Some(successor) = successor_to_retire {
            if (self.has_deferred_structural_logical_release(successor.record_id)
                || self.is_structural_owner_retired(successor.record_id))
                && super::retire_structural_stage2_record_at_safe_point(self, successor).is_err()
            {
                self.enqueue_structural_retirement_retry(successor.record_id);
            }
            return;
        }
        if let Some((keeper, release_ipa)) = abandoned_settlement {
            drop(keeper);
            if let Some(deferred) =
                self.take_deferred_structural_logical_release(identity.record_id)
            {
                deferred.drain();
            }
            if let Some((ipa, len)) = release_ipa {
                let _ = super::global_frame::release_retired_stage2_ipa(ipa, len);
            }
            return;
        }
        if settles_last_pin && self.has_deferred_structural_logical_release(identity.record_id) {
            if super::retire_structural_stage2_record_at_safe_point(self, identity).is_err() {
                self.enqueue_structural_retirement_retry(identity.record_id);
            }
        } else if outcome == RecordPinRelease::ReadyToRetry {
            if self.is_structural_owner_retired(identity.record_id) {
                self.enqueue_structural_retirement_retry(identity.record_id);
            } else {
                self.request_global_frame_retirement_retry();
            }
        } else if let RecordPinRelease::ReadyToRetire { .. } = outcome {
            if self.is_structural_owner_retired(identity.record_id) {
                if super::retire_structural_stage2_record_at_safe_point(self, identity).is_err() {
                    self.enqueue_structural_retirement_retry(identity.record_id);
                }
            } else {
                // A global owner already retained its exact pending retirement.
                // Last-unpin requests that existing idle turn; it neither unmaps
                // here nor runs a supply continuation under the pin venue.
                self.request_global_frame_retirement_retry();
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn custody_transition_error(
    context: &str,
    transition: &str,
    error: Stage2CustodyError,
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
    raw_destroy: carrick_aarch64::stage2::Stage2Status,
    record_released: impl FnOnce(),
) -> Result<(), TrapError> {
    // The scripted status is consumed only if the production sequence
    // reaches the backend's raw destroy (`raw_stage2_destroy_count` counts
    // that); a refused transition leaves it unconsumed and clears it here.
    super::stage2_backend::script_next_stage2_destroy(raw_destroy);
    let result = destroy_vm_with_custody(custody, context);
    super::stage2_backend::script_next_stage2_destroy_clear();
    result.map(|()| record_released())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn destroy_vm_with_custody(
    custody: &CarrierVmCustody,
    context: &str,
) -> Result<(), TrapError> {
    destroy_vm_with_custody_target(custody, context, CarrierVmDestroyTarget::Live)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(::core::clone::Clone, ::core::marker::Copy)]
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

    // SAFETY: the callers destroyed every vCPU of the generation first.
    let destroyed = match unsafe { custody.destroy_stage2(generation) } {
        Ok(destroyed) => destroyed,
        Err(Stage2CustodyError::Backend(rc)) => {
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
        Err(error) => return Err(custody_transition_error(context, "destroy_stage2", error)),
    };

    let settled = match target {
        CarrierVmDestroyTarget::Live => custody
            .commit_destroy(generation)
            .map_err(|error| custody_transition_error(context, "commit_destroy", error))
            .map(|()| record_vm_released()),
        CarrierVmDestroyTarget::Creating(_) => custody
            .abort_created_vm_after_raw_destroy(generation)
            .map_err(|error| custody_transition_error(context, "abort_created_vm", error)),
    };
    // The generation's unretired backings outlive its stage 2 only until here.
    drop(destroyed);
    settled
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod carrier_vm_custody_tests {
    use super::{
        CarrierLogicalOwner, CarrierStage2BackendError, CarrierStage2PinError,
        CarrierStage2RecordIdentity, CarrierStage2RecordSpec, CarrierStage2RetireOutcome,
        CarrierVmCustody, CarrierVmGeneration, Stage2CustodyError, create_vm_with_custody_using,
        destroy_vm_with_custody_using,
    };

    /// Work budget of the instruction-cache authority: an executable
    /// publication over a fresh frame invalidates once, re-publication of the
    /// clean frame costs nothing, a host write makes it cost one again, an
    /// output no backing owns is invalidated every time through the caller's
    /// fallback, and an output nothing backs needs no maintenance.
    #[test]
    #[allow(clippy::expect_used)]
    fn executable_publication_invalidates_a_frame_once_per_incarnation() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let custody = CarrierVmCustody::new();
        let ipa = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x51_0000;
        let len = 0x8000_u64;
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            len as usize,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("test frame backing");
        let generation = super::super::global_frame::next_global_frame_owner_generation();
        let owner = std::sync::Arc::new(super::super::global_frame::GlobalFrameHostOwner::new(
            super::super::global_frame::GlobalFrameStage2Lease::fixed(ipa, len),
            mapping,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
            generation,
            ipa,
            len,
        ));
        custody.global_frame_host_owners.lock().insert(
            (ipa, len),
            super::super::global_frame::GlobalFrameOwnerEntry::Live(std::sync::Arc::clone(&owner)),
        );
        let none = |_: u64, _: usize| -> Option<*mut u8> { None };
        let publish = |output, size| custody.publish_user_executable(output, size, none, none);

        assert_eq!(publish(ipa + 0x1000, 0x1000), Ok(1), "fresh frame");
        assert_eq!(
            publish(ipa + 0x1000, 0x1000),
            Ok(0),
            "clean frame re-published"
        );
        assert_eq!(
            publish(ipa + 0x2000, 0x1000),
            Ok(1),
            "its neighbour is its own page"
        );
        drop(
            owner
                .mapping
                .begin_content_write(0x1000, 16)
                .expect("host write"),
        );
        assert_eq!(publish(ipa + 0x1000, 0x1000), Ok(1), "host-written page");
        assert_eq!(publish(ipa + 0x1000, 0x1000), Ok(0));

        let mut unowned_backing = vec![0u8; 0x1000];
        let host = unowned_backing.as_mut_ptr();
        let rows = |_: u64, _: usize| Some(host);
        let unowned = ipa + 0x10_0000;
        for _ in 0..2 {
            assert_eq!(
                custody.publish_user_executable(unowned, 0x1000, none, rows),
                Ok(1),
                "an unowned output is invalidated every time"
            );
        }
        assert_eq!(
            custody.publish_user_executable(unowned, 0x1000, none, none),
            Ok(0),
            "no stage-2 record and no row: nothing backs it, nothing to fetch"
        );
    }

    #[allow(clippy::expect_used)]
    fn live_custody() -> (std::sync::Arc<CarrierVmCustody>, CarrierVmGeneration) {
        let custody = std::sync::Arc::new(CarrierVmCustody::new());
        let generation = custody.begin_create().expect("begin VM create");
        custody
            .commit_create(generation)
            .expect("publish VM generation");
        (custody, generation)
    }

    /// A record's retirement decided to unmap in G1 while a rival destroys G1
    /// and creates G2. The unmap must reach G1's stage 2 before its raw
    /// destroy, never G2's after it: the retirement holds G1's guard from its
    /// decision to its backend call. The hook parks the retirement at that
    /// point until the rival either finished (nothing excluded it: the bug)
    /// or reported that it waits for the custody lock (the fix), so the
    /// order is set by real events, with no sleep.
    #[test]
    #[allow(clippy::expect_used)]
    fn a_record_unmap_never_runs_after_its_generation_is_destroyed_and_recreated() {
        use carrick_aarch64::stage2::custody::Stage2HookPoint;
        use std::sync::atomic::{AtomicBool, Ordering};
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let (custody, g1) = live_custody();
        let identity =
            register_test_stage2_record(&custody, stage2_spec(g1, 1)).expect("G1 record");
        let rival_done = std::sync::Arc::new(AtomicBool::new(false));
        let (start_tx, start_rx) = std::sync::mpsc::channel::<()>();
        let (event_tx, event_rx) = std::sync::mpsc::channel::<&'static str>();
        let hook_event_tx = event_tx.clone();
        let event_rx = std::sync::Mutex::new(event_rx);
        custody
            .stage2
            .set_hook(Some(std::sync::Arc::new(move |point| match point {
                carrick_aarch64::stage2::custody::Stage2HookPoint::Client(
                    super::RECORD_UNMAP_PREPARED,
                ) => {
                    start_tx.send(()).expect("rival alive");
                    let event = event_rx
                        .lock()
                        .expect("event receiver")
                        .recv()
                        .expect("rival reports");
                    assert!(matches!(event, "contended" | "done"));
                }
                Stage2HookPoint::LockContended(_) => {
                    let _ = hook_event_tx.send("contended");
                }
                _ => {}
            })));

        let rival = {
            let custody = std::sync::Arc::clone(&custody);
            let rival_done = std::sync::Arc::clone(&rival_done);
            std::thread::spawn(move || {
                start_rx.recv().expect("retirement parked");
                destroy_vm_with_custody_using(
                    &custody,
                    "rival G1 destroy",
                    carrick_aarch64::stage2::Stage2Status::SUCCESS,
                    || {},
                )
                .expect("rival destroys G1");
                let g2 = custody.begin_create().expect("begin G2");
                custody.commit_create(g2).expect("publish G2");
                rival_done.store(true, Ordering::SeqCst);
                let _ = event_tx.send("done");
                g2
            })
        };

        let unmapped_after_rival = AtomicBool::new(false);
        let outcome = custody.retire_stage2_record_using(identity, |_, _| {
            unmapped_after_rival.store(rival_done.load(Ordering::SeqCst), Ordering::SeqCst);
            Ok(())
        });
        let g2 = rival.join().expect("rival");
        custody.stage2.set_hook(None);

        assert_ne!(g2, g1);
        assert!(
            !unmapped_after_rival.load(Ordering::SeqCst),
            "the G1 record's unmap reached the backend after G1 was destroyed and G2 created: \
             it hit G2's stage 2"
        );
        assert_eq!(outcome, CarrierStage2RetireOutcome::RetiredUnmapped);
    }

    /// A pre-mapped pool's construction was admitted in G1 while a rival
    /// destroys G1. The pool must be mapped in G1's stage 2 before its raw
    /// destroy (so G1's settlement forgets it), never after it into a
    /// custody with no VM, which would then serve the pool to G2 although
    /// G2's stage 2 never mapped it. The hook parks the construction at its
    /// admission until the rival either finished (nothing excluded it: the
    /// bug) or reported that it waits for the custody lock (the fix).
    #[allow(clippy::expect_used)]
    fn a_pool_built_for_a_destroyed_generation_is_never_kept(
        point: &'static str,
        build: impl FnOnce(&CarrierVmCustody) -> bool,
        take_active: impl FnOnce(&CarrierVmCustody) -> Option<Box<dyn FnOnce()>>,
    ) {
        use carrick_aarch64::stage2::custody::{Stage2HookPoint, Stage2Lifecycle};
        use std::sync::atomic::{AtomicBool, Ordering};
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let (custody, g1) = live_custody();
        let mapped_after_rival = std::sync::Arc::new(AtomicBool::new(false));
        let (start_tx, start_rx) = std::sync::mpsc::channel::<()>();
        let (event_tx, event_rx) = std::sync::mpsc::channel::<&'static str>();
        let hook_event_tx = event_tx.clone();
        let event_rx = std::sync::Mutex::new(event_rx);
        {
            let mapped_after_rival = std::sync::Arc::clone(&mapped_after_rival);
            custody.stage2.set_hook(Some(std::sync::Arc::new(
                move |hook_point| match hook_point {
                    carrick_aarch64::stage2::custody::Stage2HookPoint::Client(name)
                        if name == point =>
                    {
                        start_tx.send(()).expect("rival alive");
                        let event = event_rx
                            .lock()
                            .expect("event receiver")
                            .recv()
                            .expect("rival reports");
                        assert!(matches!(event, "contended" | "done"));
                        // The pool's map follows this point in the same
                        // thread: a finished rival means it maps after G1's
                        // raw destroy.
                        mapped_after_rival.store(event == "done", Ordering::SeqCst);
                    }
                    Stage2HookPoint::LockContended(_) => {
                        let _ = hook_event_tx.send("contended");
                    }
                    _ => {}
                },
            )));
        }

        let rival = {
            let custody = std::sync::Arc::clone(&custody);
            std::thread::spawn(move || {
                start_rx.recv().expect("construction parked");
                destroy_vm_with_custody_using(
                    &custody,
                    "rival G1 destroy",
                    carrick_aarch64::stage2::Stage2Status::SUCCESS,
                    || {},
                )
                .expect("rival destroys G1");
                let _ = event_tx.send("done");
            })
        };

        let built = build(&custody);
        rival.join().expect("rival");
        custody.stage2.set_hook(None);

        assert_eq!(custody.stage2.lifecycle(), Stage2Lifecycle::Vacant);
        // Settle a pool the bug left behind before asserting, so the failure
        // reports the race instead of a mapped lease's drop check.
        let kept = take_active(&custody).map(|forget| forget()).is_some();
        assert!(built, "G1 admitted the construction, so it builds a pool");
        assert!(
            !mapped_after_rival.load(Ordering::SeqCst) && !kept,
            "a pool admitted in G1 was mapped after G1's raw destroy and kept by a custody \
             with no VM (mapped after destroy: {}, kept: {kept}); G2 would be served a pool \
             its stage 2 never mapped (g1 {g1:?})",
            mapped_after_rival.load(Ordering::SeqCst)
        );
    }

    #[test]
    fn a_frame_pool_built_for_a_destroyed_generation_is_never_kept() {
        use super::CarrierFramePoolState;
        a_pool_built_for_a_destroyed_generation_is_never_kept(
            super::FRAME_POOL_ADMITTED,
            |custody| custody.frame_pool().is_some(),
            |custody| match std::mem::take(&mut *custody.frame_pool.lock()) {
                CarrierFramePoolState::Active(pool) => {
                    Some(Box::new(move || pool.forget_backend_mapping()) as Box<dyn FnOnce()>)
                }
                CarrierFramePoolState::Uninitialized | CarrierFramePoolState::Failed => None,
            },
        );
    }

    #[test]
    fn a_root_slot_pool_built_for_a_destroyed_generation_is_never_kept() {
        use super::CarrierRootSlotPoolState;
        a_pool_built_for_a_destroyed_generation_is_never_kept(
            super::ROOT_SLOT_POOL_ADMITTED,
            |custody| custody.root_slot_pool().is_some(),
            |custody| match std::mem::take(&mut *custody.root_slot_pool.lock()) {
                CarrierRootSlotPoolState::Active(pool) => {
                    Some(Box::new(move || pool.forget_backend_mapping()) as Box<dyn FnOnce()>)
                }
                CarrierRootSlotPoolState::Uninitialized | CarrierRootSlotPoolState::Failed => None,
            },
        );
    }

    /// Replay reconciliation checked the live generation (`G2`), then rebound
    /// a terminal `G1` carrier-MM record without holding `G2`'s guard while a
    /// rival destroyed `G2` and began `G3` (with no replay into `G3`). Holding
    /// the generation guard from the check through the rebind ensures `G2` is
    /// either rebound and terminalized before `G3` begins, or refused; a live
    /// mapped record can never appear in `G3` without an actual replay in `G3`.
    #[test]
    #[allow(clippy::expect_used)]
    fn a_replay_rebind_never_binds_to_a_generation_created_after_it_checked() {
        use carrick_aarch64::stage2::custody::Stage2HookPoint;
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let (custody, g1) = live_custody();
        let key = (0xa081_b000_0000_u64, 0x4000_u64);
        let spec = CarrierStage2RecordSpec {
            ipa: key.0,
            len: key.1 as usize,
            release_ipa: false,
            ..stage2_spec(g1, 101)
        };
        let old_identity =
            register_test_stage2_record(&custody, spec).expect("register G1 carrier-MM record");
        custody
            .carrier_stage2_records
            .lock()
            .insert(key, old_identity);
        destroy_vm_with_custody_using(
            &custody,
            "destroy G1",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy G1");

        let g2 = custody.begin_create().expect("begin G2");
        custody.commit_create(g2).expect("commit G2");
        super::super::stage2_backend::test_stage2_map_untracked(
            &custody,
            spec.host_addr as *mut std::ffi::c_void,
            key.0,
            key.1 as usize,
            spec.perms,
        );

        let (start_tx, start_rx) = std::sync::mpsc::channel::<()>();
        let (event_tx, event_rx) = std::sync::mpsc::channel::<&'static str>();
        let hook_event_tx = event_tx.clone();
        let event_rx = std::sync::Mutex::new(event_rx);
        custody
            .stage2
            .set_hook(Some(std::sync::Arc::new(move |point| match point {
                carrick_aarch64::stage2::custody::Stage2HookPoint::Client(
                    super::REPLAY_REBIND_ADMITTED,
                ) => {
                    start_tx.send(()).expect("rival alive");
                    let event = event_rx
                        .lock()
                        .expect("event receiver")
                        .recv()
                        .expect("rival reports");
                    assert!(matches!(event, "contended" | "done"));
                }
                Stage2HookPoint::LockContended(_) => {
                    let _ = hook_event_tx.send("contended");
                }
                _ => {}
            })));

        let rival = {
            let custody = std::sync::Arc::clone(&custody);
            std::thread::spawn(move || {
                start_rx.recv().expect("reconcile parked");
                destroy_vm_with_custody_using(
                    &custody,
                    "rival G2 destroy",
                    carrick_aarch64::stage2::Stage2Status::SUCCESS,
                    || {},
                )
                .expect("rival destroys G2");
                let g3 = custody.begin_create().expect("begin G3");
                let _ = event_tx.send("done");
                g3
            })
        };

        let result = super::reconcile_global_frame_owners_after_replay_in(
            &custody,
            &[super::GlobalFrameReplayExtent {
                ipa: key.0,
                length: key.1,
                host_addr: spec.host_addr,
                perms: spec.perms,
                vm_generation: g2,
            }],
            false,
        );
        let g3 = rival.join().expect("rival");
        custody.stage2.set_hook(None);

        assert_ne!(g3, g2);
        result.expect("G2 admitted replay rebind before G2 was destroyed");
        let current = custody.carrier_stage2_records.lock()[&key];
        let snapshot = custody
            .stage2_record_snapshot(current.record_id)
            .expect("rebound record snapshot");
        assert_ne!(
            snapshot.vm_generation, g3,
            "a replay checked in G2 fabricated a live mapped record in G3 after G2 destroyed"
        );
        assert_eq!(snapshot.vm_generation, g2);
        assert!(snapshot.terminalized_by_vm_destroy && !snapshot.mapped);
    }

    /// A `GlobalFrameStage2Lease` mapped in `G1` carries no generation on the
    /// lease before `Stage2Mapping` replaces its `backend_map_installed` bool.
    /// If `G1` destroys and `G2` starts before custody transfer runs, transfer
    /// must refuse `G1`'s stale mapping instead of fabricating a live `G2`
    /// record, and rollback must never unmap `G2`'s stage 2.
    #[test]
    #[allow(clippy::expect_used)]
    fn g1_mapped_lease_never_transfers_into_g2_and_never_unmaps_g2() {
        use super::super::stage2_backend::ScopedStage2MapTestStub;
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = ScopedStage2MapTestStub::enable();
        let (custody, _g1) = live_custody();
        let ipa = 0xa081_c000_0000_u64;
        let len = 0x4000_usize;
        let perms = carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite);
        let mut lease = super::GlobalFrameStage2Lease::fixed(ipa, len as u64);
        let mut backing = vec![0_u8; len];
        let mapping = super::super::stage2_backend::test_stage2_map(
            &custody,
            backing.as_mut_ptr().cast(),
            ipa,
            len,
            perms,
        );
        lease.mark_mapped(mapping);

        destroy_vm_with_custody_using(
            &custody,
            "destroy G1",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy G1");
        let g2 = custody.begin_create().expect("begin G2");
        custody.commit_create(g2).expect("commit G2");
        ScopedStage2MapTestStub::clear_events();

        let transferred = super::transfer_global_frame_stage2_lease_to_custody(
            &custody,
            lease,
            backing.as_ptr() as usize,
            perms,
            None,
        );
        assert!(
            transferred.is_err(),
            "a lease mapped in destroyed G1 transferred into live G2: {transferred:?}"
        );
        assert!(custody.stage2_record_identities().is_empty());
        assert!(
            ScopedStage2MapTestStub::events().is_empty(),
            "retiring destroyed G1 lease emitted backend unmap on G2: {:?}",
            ScopedStage2MapTestStub::events()
        );
    }

    /// Rolling back an un-transferred `G1` mapped lease after `G1` destroyed
    /// and `G2` mapped the same IPA must drop the gone `G1` mapping without
    /// unmapping `G2`'s backend extent.
    #[test]
    #[allow(clippy::expect_used)]
    fn g1_mapped_lease_rollback_after_vm_destroy_never_unmaps_g2() {
        use super::super::stage2_backend::ScopedStage2MapTestStub;
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = ScopedStage2MapTestStub::enable();
        let (custody, _g1) = live_custody();
        let ipa = 0xa081_d000_0000_u64;
        let len = 0x4000_usize;
        let perms = carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite);
        let mut g1_lease = super::GlobalFrameStage2Lease::fixed(ipa, len as u64);
        let mut g1_backing = vec![0_u8; len];
        let g1_mapping = super::super::stage2_backend::test_stage2_map(
            &custody,
            g1_backing.as_mut_ptr().cast(),
            ipa,
            len,
            perms,
        );
        g1_lease.mark_mapped(g1_mapping);

        destroy_vm_with_custody_using(
            &custody,
            "destroy G1",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy G1");
        let g2 = custody.begin_create().expect("begin G2");
        custody.commit_create(g2).expect("commit G2");
        let mut g2_backing = vec![0_u8; len];
        let _g2_mapping = super::super::stage2_backend::test_stage2_map(
            &custody,
            g2_backing.as_mut_ptr().cast(),
            ipa,
            len,
            perms,
        );
        assert!(ScopedStage2MapTestStub::is_mapped(ipa, len));
        ScopedStage2MapTestStub::clear_events();

        super::rollback_partial_process_stage2_authorities(
            &custody,
            None,
            &mut [g1_lease],
            &[],
            &[],
            std::collections::BTreeMap::new(),
        )
        .expect("rollback of gone G1 lease settles cleanly");
        assert!(
            ScopedStage2MapTestStub::events().is_empty()
                && ScopedStage2MapTestStub::is_mapped(ipa, len),
            "rolling back a destroyed G1 lease unmapped live G2: events={:?}",
            ScopedStage2MapTestStub::events()
        );
    }

    fn register_test_stage2_record(
        custody: &CarrierVmCustody,
        spec: CarrierStage2RecordSpec,
    ) -> Result<CarrierStage2RecordIdentity, super::CarrierStage2RecordError> {
        let mut stage2 = custody
            .stage2
            .stage2_in(spec.vm_generation)
            .map_err(|_| super::CarrierStage2RecordError::NoLiveVm)?;
        CarrierVmCustody::register_stage2_record(&mut stage2, spec)
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
            perms: carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
            logical_owner: Some(CarrierLogicalOwner {
                id: 7,
                generation: owner_generation,
            }),
        }
    }

    #[test]
    fn global_frame_owner_directory_is_isolated_per_carrier_custody() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
        )
        .expect("register carrier-local owner");

        assert!(first.global_frame_host_owners.lock().contains_key(&key));
        assert!(second.global_frame_host_owners.lock().is_empty());
    }

    #[test]
    fn production_global_frame_owner_operations_require_carrier_custody_static_audit() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let source = concat!(
            include_str!("../trap.rs"),
            include_str!("mapping_plan.rs"),
            include_str!("persistent_executor.rs")
        );
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
            .find("StagedCpu::initial_root(plan)")
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
    fn serial_host_global_owner_late_final_pin_defers_persistent_failure_without_abort_then_retries()
     {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let (custody, _) = live_custody();
        let key = (0xa081_1000_0000, 0x4000);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate pinned global owner backing");
        let host_addr = mapping.as_ptr() as usize;
        let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        let stage2_mapping = crate::trap::stage2_backend::test_stage2_map(
            &custody,
            mapping.as_ptr().cast(),
            key.0,
            key.1 as usize,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
        );
        lease.mark_mapped(stage2_mapping);
        let generation = super::register_global_frame_host_owner_in(
            &custody,
            lease,
            mapping,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
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
                carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let (custody, _) = live_custody();
        let key = (0xa081_1800_0000, 0x4000);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate global owner retirement lock-order fixture");
        let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        let stage2_mapping = crate::trap::stage2_backend::test_stage2_map(
            &custody,
            mapping.as_ptr().cast(),
            key.0,
            key.1 as usize,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
        );
        lease.mark_mapped(stage2_mapping);
        let generation = super::register_global_frame_host_owner_in(
            &custody,
            lease,
            mapping,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
        )
        .expect("register global owner retirement lock-order fixture");
        let exact_owner =
            std::sync::Arc::clone(custody.global_frame_host_owners.lock()[&key].owner());

        let mut rival_pin = None;
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
                // The backend unmap runs under the guard of the record's
                // generation, so a pin through a pre-cloned owner Arc can't
                // run beside it (here, on this thread, it would re-enter the
                // custody). A rival thread's pin must wait for the guard;
                // the hook reports when it does, with no sleep, and after
                // the settlement it is refused.
                let (contended_tx, contended_rx) = std::sync::mpsc::channel::<()>();
                custody
                    .stage2
                    .set_hook(Some(std::sync::Arc::new(move |point| {
                        if let carrick_aarch64::stage2::custody::Stage2HookPoint::LockContended(_) =
                            point
                        {
                            let _ = contended_tx.send(());
                        }
                    })));
                let owner = std::sync::Arc::clone(&exact_owner);
                rival_pin = Some(std::thread::spawn(move || owner.pin().map(drop)));
                contended_rx
                    .recv()
                    .expect("a rival pin waits for the retirement's guard");
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
                        carrick_guest_mem::Gpa::new(key.0),
                        length,
                    )
                    .is_err(),
                    "pending retirement must not admit a new COW owner pin"
                );
                Ok(())
            },
        );
        let rival_pin = rival_pin
            .take()
            .expect("the backend unmap ran")
            .join()
            .expect("rival pin thread");
        custody.stage2.set_hook(None);
        assert!(matches!(
            outcome,
            super::GlobalFrameRetirementOutcome::RetiredUnmapped { .. }
        ));
        assert!(
            matches!(
                rival_pin,
                Err(super::CarrierStage2PinError::RetirementRequested
                    | super::CarrierStage2PinError::NotFound)
            ),
            "a pre-cloned owner Arc must not admit a pin once its retirement began: {rival_pin:?}"
        );
        assert!(
            !custody.global_frame_host_owners.lock().contains_key(&key),
            "successful retirement must remove the exact pending slot"
        );
    }

    #[test]
    fn serial_host_later_exact_retirement_retries_a_transient_backend_failure_once() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let (custody, _) = live_custody();
        let key = (0xa081_1a00_0000, 0x4000);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate exclusive retirement fixture");
        let host_addr = mapping.as_ptr() as usize;
        let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        let stage2_mapping = crate::trap::stage2_backend::test_stage2_map(
            &custody,
            mapping.as_ptr().cast(),
            key.0,
            key.1 as usize,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
        );
        lease.mark_mapped(stage2_mapping);
        let generation = super::register_global_frame_host_owner_in(
            &custody,
            lease,
            mapping,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let (custody, _) = live_custody();
        let key = (0xa081_1b00_0000, 0x4000);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate foreign-MM release safe-point fixture");
        let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        let stage2_mapping = crate::trap::stage2_backend::test_stage2_map(
            &custody,
            mapping.as_ptr().cast(),
            key.0,
            key.1 as usize,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
        );
        lease.mark_mapped(stage2_mapping);
        let generation = super::register_global_frame_host_owner_in(
            &custody,
            lease,
            mapping,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
        )
        .expect("register foreign-MM release safe-point fixture");
        let pin = custody.global_frame_host_owners.lock()[&key]
            .owner()
            .pin()
            .expect("retain the final foreign-MM owner pin");
        let mut backing = super::RetainedForeignMmBacking {
            extents: vec![super::RetainedForeignExtent {
                key,
                owner: super::RetainedPhysicalOwner::Global {
                    pin,
                    len: key.1 as usize,
                },
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let (custody, _) = live_custody();
        let key = (0xa081_1b80_0000, 0x4000);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate foreign-MM transient retry fixture");
        let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        let stage2_mapping = crate::trap::stage2_backend::test_stage2_map(
            &custody,
            mapping.as_ptr().cast(),
            key.0,
            key.1 as usize,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
        );
        lease.mark_mapped(stage2_mapping);
        let generation = super::register_global_frame_host_owner_in(
            &custody,
            lease,
            mapping,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let (custody, _) = live_custody();
        let make_pending = |key: (u64, u64)| {
            let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                key.1 as usize,
                crate::host_mapping::HostMappingKind::PerMmKernelState,
            )
            .expect("allocate removable FIFO fixture");
            let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
            let stage2_mapping = crate::trap::stage2_backend::test_stage2_map(
                &custody,
                mapping.as_ptr().cast(),
                key.0,
                key.1 as usize,
                carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
            );
            lease.mark_mapped(stage2_mapping);
            let generation = super::register_global_frame_host_owner_in(
                &custody,
                lease,
                mapping,
                carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let (custody, _) = live_custody();
        let key = (0xa081_1bc0_0000, 0x4000);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate concurrent idle-turn fixture");
        let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        let stage2_mapping = crate::trap::stage2_backend::test_stage2_map(
            &custody,
            mapping.as_ptr().cast(),
            key.0,
            key.1 as usize,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
        );
        lease.mark_mapped(stage2_mapping);
        let generation = super::register_global_frame_host_owner_in(
            &custody,
            lease,
            mapping,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
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
    fn serial_host_retirement_retains_backing_if_the_claimed_directory_slot_disappears() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let (custody, _) = live_custody();
        let key = (0xa081_1c00_0000, 0x4000);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate disappearing retirement slot fixture");
        let host_addr = mapping.as_ptr() as usize;
        let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        let stage2_mapping = crate::trap::stage2_backend::test_stage2_map(
            &custody,
            mapping.as_ptr().cast(),
            key.0,
            key.1 as usize,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
        );
        lease.mark_mapped(stage2_mapping);
        let generation = super::register_global_frame_host_owner_in(
            &custody,
            lease,
            mapping,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
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
    fn serial_host_global_owner_collision_retains_failed_rollback_candidate_until_safe_point() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
        )
        .expect("register incumbent global owner");

        let candidate_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate colliding global owner backing");
        let candidate_host = candidate_mapping.as_ptr() as usize;
        let mut candidate_lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        let stage2_mapping = crate::trap::stage2_backend::test_stage2_map(
            &custody,
            candidate_mapping.as_ptr().cast(),
            key.0,
            key.1 as usize,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
        );
        candidate_lease.mark_mapped(stage2_mapping);
        let injected = super::CarrierStage2BackendError::HvReturn(0xfae9_4001);
        let mut rollback_calls = 0_u32;

        assert!(
            super::register_global_frame_host_owner_in_using(
                &custody,
                candidate_lease,
                candidate_mapping,
                carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
                carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
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
            let stage2_mapping = crate::trap::stage2_backend::test_stage2_map(
                &custody,
                mapping.as_ptr().cast(),
                key.0,
                key.1 as usize,
                carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
            );
            lease.mark_mapped(stage2_mapping);
            let generation = super::register_global_frame_host_owner_in(
                &custody,
                lease,
                mapping,
                carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
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
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
        )
        .expect("register fair-retry incumbent");
        let candidate_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            collision_key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate fair-retry detached candidate");
        let mut candidate_lease =
            super::GlobalFrameStage2Lease::fixed(collision_key.0, collision_key.1);
        let stage2_mapping = crate::trap::stage2_backend::test_stage2_map(
            &custody,
            candidate_mapping.as_ptr().cast(),
            collision_key.0,
            collision_key.1 as usize,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
        );
        candidate_lease.mark_mapped(stage2_mapping);
        assert!(
            super::register_global_frame_host_owner_in_using(
                &custody,
                candidate_lease,
                candidate_mapping,
                carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
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
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
        )
        .expect("register reconcile-deferred owner");
        let pin = custody.global_frame_host_owners.lock()[&key]
            .owner()
            .pin()
            .expect("pin reconcile-deferred owner");

        destroy_vm_with_custody_using(
            &custody,
            "deferred G1 destroy",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
                carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
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
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
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
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
        )
        .expect("register fixed rebuild owner");
        let fixed_old_identity = custody.global_frame_host_owners.lock()[&fixed_key]
            .owner()
            .record_identity;

        destroy_vm_with_custody_using(
            &custody,
            "G1 destroy",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy G1");
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
        let rw_perms = carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite);
        super::super::stage2_backend::test_stage2_map_untracked(
            &custody,
            host_addr as *mut std::ffi::c_void,
            reserved_key.0,
            reserved_key.1 as usize,
            rw_perms,
        );
        super::super::stage2_backend::test_stage2_map_untracked(
            &custody,
            fixed_host as *mut std::ffi::c_void,
            fixed_key.0,
            fixed_key.1 as usize,
            rw_perms,
        );
        let mut release_calls = 0_u32;
        let report = super::reconcile_global_frame_owners_after_replay_in_using(
            &custody,
            &[
                super::GlobalFrameReplayExtent {
                    ipa: reserved_key.0,
                    length: reserved_key.1,
                    host_addr,
                    perms: rw_perms,
                    vm_generation: g2,
                },
                super::GlobalFrameReplayExtent {
                    ipa: fixed_key.0,
                    length: fixed_key.1,
                    host_addr: fixed_host,
                    perms: rw_perms,
                    vm_generation: g2,
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
                    perms: rw_perms,
                    vm_generation: g2,
                },
                super::GlobalFrameReplayExtent {
                    ipa: fixed_key.0,
                    length: fixed_key.1,
                    host_addr: fixed_host,
                    perms: rw_perms,
                    vm_generation: g2,
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
        assert_eq!(old_pin._stage2_pin.identity().vm_generation, g1);
        assert_eq!(g2_pin._stage2_pin.identity().vm_generation, g2);
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
    fn serial_host_vm_destroy_success_terminalizes_pending_owner_but_failure_preserves_exact_g1() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
        let stage2_mapping = crate::trap::stage2_backend::test_stage2_map(
            &custody,
            mapping.as_ptr().cast(),
            key.0,
            key.1 as usize,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
        );
        lease.mark_mapped(stage2_mapping);
        let generation = super::register_global_frame_host_owner_in(
            &custody,
            lease,
            mapping,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
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
                carrick_aarch64::stage2::Stage2Status::from_raw(0xfae9_4002),
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

        destroy_vm_with_custody_using(
            &custody,
            "successful G1 destroy",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
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

    /// #2826: the carrier-exit arm that finds the VM already gone (a retry
    /// after a failed terminal cleanup) runs only the terminal cleanup. A
    /// sealed exec preparation still alive there must be drained by it, and
    /// dropping it after the destroy must release its frame backing, IPA
    /// lease and executable without a backend call.
    #[test]
    fn carrier_exit_after_vm_destroy_drains_a_sealed_exec_preparation() {
        use carrick_core_abi::service::{ServiceBirth, ServiceIdentity};
        use carrick_sched_core::{
            RecordId, RecordRef,
            process::{TaskId, TaskKey, TaskSerial},
        };
        use core::num::{NonZeroI32, NonZeroU64};

        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let custody = std::sync::Arc::new(CarrierVmCustody::new_live_fixture());
        let ipa_baseline = crate::trap::exec_ipa_lease_count_for_tests();
        let frame_baseline = custody.native_frame_backings.lock().len();
        #[derive(Debug)]
        struct Executable;
        impl carrick_hal::fork_stock::ExecutableIdentity for Executable {
            fn display_path(&self) -> String {
                "/sealed-at-carrier-exit".into()
            }
        }
        let executable: std::sync::Arc<dyn carrick_hal::fork_stock::ExecutableIdentity> =
            std::sync::Arc::new(Executable);
        let live_executable = std::sync::Arc::downgrade(&executable);
        let prepared = crate::trap::PreparedNativeExecSuccessor::installed_cancel_fixture(
            &custody, executable,
        )
        .expect("sealed successor fixture");
        let identity = ServiceIdentity {
            birth: ServiceBirth {
                origin: carrick_core_abi::service::ServiceOrigin::Initial,
                process: TaskKey {
                    id: TaskId::from_registry_allocation(NonZeroI32::new(41).unwrap()),
                    serial: TaskSerial::from_registry_allocation(NonZeroU64::MIN),
                },
                thread: carrick_core_abi::EntryThreadGeneration::from_raw(101),
                record: RecordRef {
                    id: RecordId::from_raw(1).unwrap(),
                    incarnation: 1,
                },
                // SAFETY: the fixture names this exact carrier/MM incarnation.
                mm: unsafe {
                    carrick_el1_abi::El1MmHandle::from_admitted_owner(
                        custody.transfer_carrier,
                        carrick_el1_abi::ReservationMm::new(5).unwrap(),
                        NonZeroU64::new(77).unwrap(),
                    )
                },
            },
            execution: carrick_core_abi::SnapshotGeneration::from_raw(11),
            sequence: NonZeroU64::MIN,
        };
        let receipt = custody
            .claim_native_exec(
                identity,
                carrick_el1_abi::ReservationMm::new(6).unwrap(),
                NonZeroU64::new(78).unwrap(),
            )
            .expect("claim exec receipt");
        custody
            .seal_native_exec_preparation(receipt, prepared)
            .expect("seal the prepared successor");
        assert_eq!(custody.native_exec_preparations.lock().len(), 1);
        assert_eq!(
            custody.native_frame_backings.lock().len(),
            frame_baseline + 1
        );

        // The VM is destroyed first; the exit then finds it gone.
        destroy_vm_with_custody_using(
            &custody,
            "carrier-exit test",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("raw carrier-exit destroy succeeds");
        assert_eq!(custody.live_generation(), None);
        super::finalize_carrier_exit_global_frame_owners_in_using(&custody, &mut |_, _| Ok(()))
            .expect("terminal cleanup after the VM is gone");

        assert_eq!(custody.native_exec_preparations.lock().len(), 0);
        let census = custody.exec_owner_census();
        assert_eq!(
            (census.reserved, census.sealed, census.carrier_exit),
            (1, 1, 1),
            "{census}"
        );
        assert_eq!(custody.native_frame_backings.lock().len(), frame_baseline);
        assert_eq!(live_executable.strong_count(), 0);
        assert_eq!(crate::trap::exec_ipa_lease_count_for_tests(), ipa_baseline);

        // A retry of the cleanup finds nothing left to drain.
        super::finalize_carrier_exit_global_frame_owners_in_using(&custody, &mut |_, _| Ok(()))
            .expect("terminal cleanup retry");
        assert_eq!(custody.exec_owner_census().carrier_exit, 1);
    }

    #[test]
    fn carrier_exit_propagates_terminal_owner_cleanup_failure_after_destroy_success() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
        )
        .expect("register carrier-exit owner");
        let identity = custody.global_frame_host_owners.lock()[&key]
            .owner()
            .record_identity;

        destroy_vm_with_custody_using(
            &custody,
            "carrier-exit test",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        for stage in ["initial-vcpu", "shared-wait-map", "exec-reconcile"] {
            let custody = CarrierVmCustody::new();
            let generation = custody.begin_create().expect("begin injected create");
            let identity = register_test_stage2_record(&custody, stage2_spec(generation, 70))
                .expect("setup may register exact Creating-generation records");
            assert_eq!(
                custody.live_generation(),
                None,
                "{stage} published too early"
            );

            custody.destroy_stage2_for_test(generation);
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
    fn failed_creating_vm_rebuilds_both_pools_for_successor() {
        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let custody = CarrierVmCustody::new();
        let g1 = custody.begin_create().expect("begin G1");
        let frames1 = custody.frame_pool().expect("G1 frame pool");
        let roots1 = custody.root_slot_pool().expect("G1 root pool");
        assert_eq!(frames1.vm_generation(), Some(g1));
        assert_eq!(roots1.vm_generation(), Some(g1));
        super::super::stage2_backend::script_next_stage2_destroy(
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
        );
        let result = super::destroy_vm_with_custody_target(
            &custody,
            "failed G1 creation",
            super::CarrierVmDestroyTarget::Creating(g1),
        );
        super::super::stage2_backend::script_next_stage2_destroy_clear();
        result.expect("production failed-creation cleanup");
        let g2 = custody.begin_create().expect("begin G2");
        let frames2 = custody.frame_pool().expect("G2 frame pool");
        let roots2 = custody.root_slot_pool().expect("G2 root pool");
        let observed = (
            frames2.vm_generation(),
            roots2.vm_generation(),
            std::sync::Arc::ptr_eq(&frames1, &frames2),
            std::sync::Arc::ptr_eq(&roots1, &roots2),
        );
        custody.commit_create(g2).expect("commit G2");
        destroy_vm_with_custody_using(
            &custody,
            "G2 cleanup",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy G2");
        drop((frames1, roots1, frames2, roots2));
        assert_eq!(
            observed,
            (Some(g2), Some(g2), false, false),
            "G2 must own freshly mapped pools"
        );
    }

    #[test]
    fn stale_failed_creation_cleanup_cannot_drain_or_reset_gone_generation() {
        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let custody = CarrierVmCustody::new();
        let g1 = custody.begin_create().expect("begin G1");
        let frames = custody.frame_pool().expect("G1 frame pool");
        let roots = custody.root_slot_pool().expect("G1 root pool");
        custody.destroy_stage2_for_test(g1);
        let before_keepers = custody.carrier_lease_keepers.lock().drained_through;
        let before_ipc = custody.retained_ipc_backings.lock().drained_through;
        let wrong = CarrierVmGeneration(g1.0 + 1);
        let result = custody.abort_created_vm_after_raw_destroy(wrong);
        let observed_keepers = custody.carrier_lease_keepers.lock().drained_through;
        let observed_ipc = custody.retained_ipc_backings.lock().drained_through;
        let observed_frames = matches!(&*custody.frame_pool.lock(), super::CarrierFramePoolState::Active(pool) if std::sync::Arc::ptr_eq(pool, &frames));
        let observed_roots = matches!(&*custody.root_slot_pool.lock(), super::CarrierRootSlotPoolState::Active(pool) if std::sync::Arc::ptr_eq(pool, &roots));
        custody
            .abort_created_vm_after_raw_destroy(g1)
            .expect("cleanup exact G1");
        // Keep pre-fix fixture teardown from dropping mapped leases after
        // raw destroy; the assertions below still observe the stale call.
        frames.forget_backend_mapping();
        roots.forget_backend_mapping();
        drop((frames, roots));
        assert!(result.is_err(), "wrong generation must be refused");
        assert_eq!(
            observed_keepers, before_keepers,
            "stale cleanup must not advance keeper drain"
        );
        assert_eq!(
            observed_ipc, before_ipc,
            "stale cleanup must not advance IPC drain"
        );
        assert!(
            observed_frames && observed_roots,
            "stale cleanup must not change pools"
        );
    }

    #[test]
    fn frame_pool_and_commit_destroy_concurrent_lock_order() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
            custody.destroy_stage2_for_test(generation);
            custody.commit_destroy(generation).expect("commit destroy");

            stop.store(true, Ordering::Release);
            worker.join().expect("worker thread join without deadlock");
        }
    }

    #[test]
    fn late_g1_carrier_mm_retirement_request_cannot_mutate_same_key_g2_record() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let (custody, g1) = live_custody();
        let key = (0xa081_9000_0000, 0x4000);
        let mut g1_lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        g1_lease.mark_test_mapped_without_backend();
        let owners = std::collections::BTreeMap::from([(key, 0x1000)]);
        let old_identity =
            super::register_carrier_stage2_leases(&custody, &mut vec![g1_lease], &owners)
                .expect("register G1 carrier-MM record")[0];
        assert_eq!(old_identity.vm_generation, g1);
        destroy_vm_with_custody_using(
            &custody,
            "carrier G1 destroy",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy G1");
        let g2 = custody.begin_create().expect("begin G2");
        super::super::stage2_backend::test_stage2_map_untracked(
            &custody,
            owners[&key] as *mut std::ffi::c_void,
            key.0,
            key.1 as usize,
            0,
        );
        let report = super::reconcile_global_frame_owners_after_replay_in_using(
            &custody,
            &[super::GlobalFrameReplayExtent {
                ipa: key.0,
                length: key.1,
                host_addr: owners[&key],
                perms: 0,
                vm_generation: g2,
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let (custody, _) = live_custody();
        let identity = register_test_stage2_record(
            &custody,
            stage2_spec(custody.live_generation().expect("G1 live"), 91),
        )
        .expect("register G1 record");
        destroy_vm_with_custody_using(
            &custody,
            "G1 destroy",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy G1");
        let _g2 = custody.begin_create().expect("begin G2 replay");
        assert!(
            custody
                .claim_terminal_stage2_release(identity)
                .expect("claim exact terminal release")
                .is_some()
        );
        {
            let mut stage2 = custody.admitting_stage2("test rebind").expect("admitting");
            assert_eq!(
                CarrierVmCustody::rebind_terminal_stage2_record(
                    &mut stage2,
                    identity,
                    0x1234_0000,
                    stage2_spec(identity.vm_generation, 91).perms
                ),
                Err(super::CarrierStage2RecordError::ReleaseInFlight)
            );
        }
        custody.abort_terminal_stage2_release(identity);
        {
            let mut stage2 = custody.admitting_stage2("test rebind").expect("admitting");
            assert!(
                CarrierVmCustody::rebind_terminal_stage2_record(
                    &mut stage2,
                    identity,
                    0x1234_0000,
                    stage2_spec(identity.vm_generation, 91).perms,
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn create_cleanup_retains_failed_vcpu_then_retries_terminal_finalization_only() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let custody = std::sync::Arc::new(CarrierVmCustody::new());
        let generation = custody.begin_create().expect("begin Creating VM");
        let identity = register_test_stage2_record(&custody, stage2_spec(generation, 92))
            .expect("register setup record");
        let id = super::CarrierVcpuId::from_raw(41);
        let mut vcpu_id = Some(id);
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
            |_| Err(super::VcpuDestroyError::from_raw(0xfae9_4001)),
            |_, _, _| {
                vm_destroy_calls.set(vm_destroy_calls.get() + 1);
                Ok(())
            },
            |_| {
                finalize_calls.set(finalize_calls.get() + 1);
                Ok(())
            },
        );
        assert!(matches!(
            first,
            Err(super::TrapError::Hypervisor(message))
                if message == "injected cleanup: hv_vcpu_destroy rc=0xfae94001; exact vCPU cleanup retained"
        ));
        assert_eq!(vcpu_id, Some(id));
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
            |_| Ok(()),
            |custody, generation, _| {
                vm_destroy_calls.set(vm_destroy_calls.get() + 1);
                custody.destroy_stage2_for_test(generation);
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
    fn fresh_vm_vcpu_and_permit_wrappers_remain_guarded_until_commit_static_audit() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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

        let exec = include_str!("execve_rebuild.rs")
            .split(concat!("fn execve_rebuild_", "inner("))
            .nth(1)
            .expect("exec rebuild body");
        assert!(exec.contains("SetupVmGuard::new(new_vm, true)"));
        // `create_vcpu_with_permit` hands back a `PendingRaw` guard.
        assert!(exec.contains("create_vcpu_with_permit(&new_vm, permit)"));
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let (custody, g1) = live_custody();
        let key = (0xa081_a000_0000, 0x4000);
        let old_identity = register_test_stage2_record(
            &custody,
            CarrierStage2RecordSpec {
                ipa: key.0,
                ..stage2_spec(g1, 93)
            },
        )
        .expect("register G1 carrier-MM record");
        custody
            .carrier_stage2_records
            .lock()
            .insert(key, old_identity);
        let mut authority = super::carrier_stage2_logical_leases(&custody, &[old_identity]);

        destroy_vm_with_custody_using(
            &custody,
            "G1 destroy",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy G1");
        let g2 = custody.begin_create().expect("begin G2");
        super::super::stage2_backend::test_stage2_map_untracked(
            &custody,
            0x1234_0000 as *mut std::ffi::c_void,
            key.0,
            key.1 as usize,
            stage2_spec(g1, 93).perms,
        );
        super::reconcile_global_frame_owners_after_replay_in_using(
            &custody,
            &[super::GlobalFrameReplayExtent {
                ipa: key.0,
                length: key.1,
                host_addr: 0x1234_0000,
                perms: stage2_spec(g1, 93).perms,
                vm_generation: g2,
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let (custody, _) = live_custody();
        let key = (0xa081_b000_0000, 0x4000);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate concurrent-retirement owner");
        let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        let stage2_mapping = crate::trap::stage2_backend::test_stage2_map(
            &custody,
            mapping.as_ptr().cast(),
            key.0,
            key.1 as usize,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
        );
        lease.mark_mapped(stage2_mapping);
        super::register_global_frame_host_owner_in(
            &custody,
            lease,
            mapping,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
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
    fn serial_host_structural_owner_drop_requests_then_safe_point_retires_with_backing_intact() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWriteExec),
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
        let mm_access = super::MmAccessState::new_unbound(
            carrick_aarch64::Stage1Authority::new(),
            carrick_guest_mem::UserMemoryAuthority::from_legacy(std::sync::Arc::new(
                super::MemoryProtections::default(),
            )),
            std::sync::Arc::new(parking_lot::Mutex::new(
                super::HvpatchFrameInventory::default(),
            )),
            std::sync::Arc::new(parking_lot::Mutex::new(super::CowArmedRanges::default())),
            std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
            crate::hvf_aarch64_engine::HostCowStats::default(),
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
            None,
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
            None,
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

        super::HvfVmState::retire_stage2_extent_from_mappings_in(
            &custody,
            &mut mappings,
            ipa,
            len,
            None,
        )
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
        let replacement_mapping = super::test_stage2_map(
            &custody,
            replacement.as_ptr().cast(),
            ipa,
            len as usize,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
        );
        let mut stage2 = custody.stage2.stage2().expect("live custody");
        assert!(unsafe { stage2.unmap(replacement_mapping) }.is_ok());
        drop(stage2);
        drop(replacement);
        drop(mm_access);
    }

    #[test]
    fn pinned_structural_retirement_refuses_root_slot_reuse_until_terminal() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
        let mm_access = super::MmAccessState::new_unbound(
            carrick_aarch64::Stage1Authority::new(),
            carrick_guest_mem::UserMemoryAuthority::from_legacy(std::sync::Arc::new(
                super::MemoryProtections::default(),
            )),
            std::sync::Arc::new(parking_lot::Mutex::new(
                super::HvpatchFrameInventory::default(),
            )),
            std::sync::Arc::new(parking_lot::Mutex::new(super::CowArmedRanges::default())),
            std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
            crate::hvf_aarch64_engine::HostCowStats::default(),
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
            None,
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
        let mut stage2 = custody
            .admitting_stage2("refused reuse check")
            .expect("admitting");
        assert!(
            unsafe {
                super::stage2_map(
                    &mut stage2,
                    replacement.as_ptr().cast(),
                    ipa,
                    len as usize,
                    carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
                )
            }
            .is_err(),
            "same-IPA reuse must remain refused until structural retirement is terminal",
        );
        drop(stage2);
        drop(replacement);

        drop(pin);
        drop(mappings);
        drop(mm_access);
        super::retry_structural_backing_identities_in(
            &custody,
            &[identity],
            &mut super::release_retired_stage2_ipa,
        )
        .expect("clean up deferred pinned structural fixture");
    }

    #[test]
    fn live_structural_owner_rebinds_exactly_to_g2_before_late_drop() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let (custody, g1) = live_custody();
        let key = (0x7d00_2000_0000, 0x4000);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("allocate rebuild structural backing");
        let host_addr = mapping.as_ptr() as usize;
        let perms =
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWriteExec);
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

        destroy_vm_with_custody_using(
            &custody,
            "structural G1 destroy",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy structural G1");
        let g2 = custody.begin_create().expect("begin structural G2");
        custody.commit_create(g2).expect("publish structural G2");
        super::super::stage2_backend::test_stage2_map_untracked(
            &custody,
            host_addr as *mut std::ffi::c_void,
            key.0,
            key.1 as usize,
            perms,
        );
        let report = super::reconcile_global_frame_owners_after_replay_in_using(
            &custody,
            &[super::GlobalFrameReplayExtent {
                ipa: key.0,
                length: key.1,
                host_addr,
                perms,
                vm_generation: g2,
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
    fn last_predecessor_pin_preserves_live_owner_after_successor_destroy() {
        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let (custody, g1) = live_custody();
        let (ipa, len) = (0x7d00_3000_0000, 0x4000);
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            len,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .expect("structural backing");
        let host = mapping.as_ptr() as usize;
        let perms =
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWriteExec);
        let mut lease = super::GlobalFrameStage2Lease::fixed(ipa, len as u64);
        lease.mark_test_mapped_without_backend();
        let owner = super::StructuralBackingOwner::new_in(
            &custody,
            mapping,
            lease,
            perms,
            super::next_structural_epoch().unwrap(),
            ipa,
            len,
        )
        .expect("structural owner");
        let old = owner.record_identity();
        assert_eq!(old.vm_generation, g1);
        let pin = custody.pin_stage2_record(old).expect("predecessor pin");
        destroy_vm_with_custody_using(
            &custody,
            "G1",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy G1");
        let g2 = custody.begin_create().expect("begin G2");
        custody.commit_create(g2).expect("commit G2");
        super::super::stage2_backend::test_stage2_map_untracked(
            &custody,
            host as *mut std::ffi::c_void,
            ipa,
            len,
            perms,
        );
        super::reconcile_global_frame_owners_after_replay_in_using(
            &custody,
            &[super::GlobalFrameReplayExtent {
                ipa,
                length: len as u64,
                host_addr: host,
                perms,
                vm_generation: g2,
            }],
            false,
            &mut |_, _| Ok(()),
        )
        .expect("rebind live owner");
        let successor = owner.record_identity();
        assert_ne!(successor.record_id, old.record_id);
        assert!(custody.has_pinned_structural_predecessor(successor.record_id));
        destroy_vm_with_custody_using(
            &custody,
            "G2",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy G2");
        assert!(!custody.is_structural_owner_retired(successor.record_id));
        assert!(!custody.has_deferred_structural_logical_release(successor.record_id));
        drop(pin);
        assert!(custody.stage2_record_snapshot(old.record_id).is_none());
        assert!(
            custody
                .stage2_record_snapshot(successor.record_id)
                .is_some(),
            "live successor record must survive G2 destroy and predecessor unpin"
        );
        assert_eq!(owner.record_identity(), successor);
        assert!(
            custody
                .structural_backings
                .lock()
                .contains_key(&successor.record_id)
        );
        assert!(super::alias_backing_is_live(host));
        drop(owner);
    }

    #[test]
    fn last_pin_preserves_live_pooled_root_across_destroy_and_new_pool() {
        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let (custody, g1) = live_custody();
        let pool = custody.root_slot_pool().expect("G1 pool");
        let handle = pool.allocate_slot().expect("G1 slot");
        let ipa = handle.ipa();
        let len = handle.len();
        let perms = carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite);
        let mut lease = super::GlobalFrameStage2Lease::fixed(ipa, len as u64);
        lease.mark_pre_mapped_in(Some(g1));
        let owner = super::StructuralBackingOwner::new_pooled_root_in(
            &custody,
            handle,
            lease,
            perms,
            super::next_structural_epoch().unwrap(),
            ipa,
            len,
        )
        .expect("pooled structural owner");
        let identity = owner.record_identity();
        let pin = custody.pin_stage2_record(identity).expect("G1 pin");
        destroy_vm_with_custody_using(
            &custody,
            "G1",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy G1");
        let g2 = custody.begin_create().expect("begin G2");
        custody.commit_create(g2).expect("commit G2");
        let pool2 = custody.root_slot_pool().expect("G2 pool");
        assert!(
            pool2.contains_ipa(ipa),
            "G2 pool must cover the old fixed IPA"
        );
        assert!(!custody.is_structural_owner_retired(identity.record_id));
        drop(pin);
        assert!(
            custody.stage2_record_snapshot(identity.record_id).is_some(),
            "live pooled record must survive last unpin"
        );
        assert_eq!(owner.record_identity(), identity);
        assert!(
            custody
                .structural_backings
                .lock()
                .contains_key(&identity.record_id)
        );
        drop(owner);
    }

    #[test]
    fn last_pin_retires_dead_pooled_owner_without_active_pool() {
        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let (custody, g1) = live_custody();
        let pool = custody.root_slot_pool().expect("G1 pool");
        let handle = pool.allocate_slot().expect("G1 slot");
        let ipa = handle.ipa();
        let len = handle.len();
        let perms = carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite);
        let mut lease = super::GlobalFrameStage2Lease::fixed(ipa, len as u64);
        lease.mark_pre_mapped_in(Some(g1));
        let owner = super::StructuralBackingOwner::new_pooled_root_in(
            &custody,
            handle,
            lease,
            perms,
            super::next_structural_epoch().unwrap(),
            ipa,
            len,
        )
        .expect("pooled structural owner");
        let identity = owner.record_identity();
        let pin = custody.pin_stage2_record(identity).expect("G1 pin");
        drop(owner);
        assert!(custody.is_structural_owner_retired(identity.record_id));
        destroy_vm_with_custody_using(
            &custody,
            "G1",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy G1");
        assert!(!custody.is_pooled_ipa(ipa), "destroy removes active pool");
        drop(pin);
        assert!(
            custody.stage2_record_snapshot(identity.record_id).is_none(),
            "retired pooled record must drain without active pool"
        );
        assert!(
            !custody
                .structural_backings
                .lock()
                .contains_key(&identity.record_id)
        );
    }

    #[test]
    fn creation_funnels_hold_transaction_through_setup_and_prepared_writes_hold_pin_static_audit() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
        assert!(!lease_drop.contains("inventory_stage2_unmap"));
        assert!(!lease_drop.contains("process::abort"));
        let structural_drop = source
            .split(concat!("impl Drop for StructuralBacking", "Owner {"))
            .nth(1)
            .and_then(|tail| tail.split("\n}\n").next())
            .expect("structural owner Drop body");
        assert!(structural_drop.contains("request_stage2_record_retirement"));
        assert!(!structural_drop.contains("inventory_stage2_unmap"));
        assert!(!prepared.contains("Arc<GlobalFrameHostOwner>"));
    }

    #[test]
    fn abort_destroy_preserves_the_exact_live_generation_for_retry() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let custody = CarrierVmCustody::new();
        let first = custody.begin_create().expect("begin first VM create");
        custody
            .commit_create(first)
            .expect("publish first VM generation");
        custody.begin_destroy(first).expect("begin first destroy");

        assert_eq!(
            custody.begin_create(),
            Err(Stage2CustodyError::LifecycleConflict)
        );

        custody.destroy_stage2_for_test(first);
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
            Err(Stage2CustodyError::StaleGeneration)
        );
        assert_eq!(custody.live_generation(), Some(second));
    }

    #[test]
    fn aborted_create_returns_custody_to_vacant_without_reusing_the_generation() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let custody = CarrierVmCustody::new();
        let generation = custody.begin_create().expect("begin VM create");
        custody
            .commit_create(generation)
            .expect("publish VM generation");
        let released = std::sync::atomic::AtomicBool::new(false);

        let result = destroy_vm_with_custody_using(
            &custody,
            "test destroy",
            carrick_aarch64::stage2::Stage2Status::from_raw(0xfae9_4001),
            || released.store(true, std::sync::atomic::Ordering::SeqCst),
        );

        assert!(matches!(result, Err(super::TrapError::Hypervisor(_))));
        assert_eq!(custody.live_generation(), Some(generation));
        assert!(!released.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            custody.begin_create(),
            Err(Stage2CustodyError::LifecycleConflict),
            "failed destroy must not admit a successor VM"
        );
    }

    #[test]
    fn backend_destroy_success_terminalizes_before_release_publication() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let custody = CarrierVmCustody::new();
        let generation = custody.begin_create().expect("begin VM create");
        custody
            .commit_create(generation)
            .expect("publish VM generation");
        let released_after_terminal = std::cell::Cell::new(false);

        destroy_vm_with_custody_using(
            &custody,
            "test destroy",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || released_after_terminal.set(custody.live_generation().is_none()),
        )
        .expect("destroy transaction succeeds");

        assert!(released_after_terminal.get());
        assert!(custody.begin_create().is_ok());
    }

    #[test]
    fn backend_create_failure_returns_custody_to_vacant_and_skips_publication() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let (custody, generation) = live_custody();
        let identity = register_test_stage2_record(&custody, stage2_spec(generation, 11))
            .expect("register exact stage-2 record");
        let second = register_test_stage2_record(
            &custody,
            CarrierStage2RecordSpec {
                ipa: 0x8000,
                host_addr: 0x5678_0000,
                ..stage2_spec(generation, 12)
            },
        )
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let (custody, generation) = live_custody();
        let identity = register_test_stage2_record(&custody, stage2_spec(generation, 13))
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let (custody, generation) = live_custody();
        let identity = register_test_stage2_record(&custody, stage2_spec(generation, 21))
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
    fn retained_stage2_pin_does_not_keep_its_carrier_alive() {
        let (custody, generation) = live_custody();
        let identity = register_test_stage2_record(&custody, stage2_spec(generation, 71))
            .expect("register stage-2 record");
        let pin = custody.pin_stage2_record(identity).expect("pin record");
        let weak = std::sync::Arc::downgrade(&custody);
        drop(custody);
        assert!(
            weak.upgrade().is_none(),
            "a pin retained by fork stock must not cycle the carrier"
        );
        drop(pin);
    }

    #[test]
    fn committed_child_in_fork_stock_drops_with_carrier_and_releases_stage2_pins_on_destroy() {
        use carrick_aarch64::fork::ForkCustody;
        use carrick_el1_abi::{
            EntryMmKey, EntryTaskKey, EntryThreadGeneration, ExecutionBinding, ForkLifecycleLoan,
            ForkStockExchange, ForkStockRequest, ForkStockSettlement, PortalForkCompletion,
            PortalForkCustody, PortalOperation, ReservationGeneration, ReservationMm,
            SnapshotGeneration,
        };
        use carrick_guest_arch::{
            AddressContext, ContextGeneration, CpuId, FrameGpa, KernelVa, MmGeneration, RootGpa,
        };
        use core::num::NonZeroU64;

        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let settle_child_with_retained_frame =
            |custody: &std::sync::Arc<CarrierVmCustody>, ipa: u64| {
                let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                    0x4000,
                    crate::host_mapping::HostMappingKind::PerMmKernelState,
                )
                .expect("allocate global owner mapping");
                let mut lease = super::GlobalFrameStage2Lease::fixed(ipa, 0x4000);
                lease.mark_test_mapped_without_backend();
                super::register_global_frame_host_owner_in(
                    custody,
                    lease,
                    mapping,
                    carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
                )
                .expect("register global frame owner");
                let identity = custody
                    .stage2_record_covering(ipa, 1)
                    .expect("registered stage-2 record");
                let stock_base = carrick_el1_abi::AARCH64_STAGE1_TABLE_POOL_BASE + 0x20_0000;
                {
                    let mut stock = custody.fork_stock.lock();
                    stock.owner.set_carrier(custody.transfer_carrier);
                    stock
                        .owner
                        .install(
                            (0..4)
                                .map(|i| {
                                    RootGpa::page_aligned(FrameGpa::new(stock_base + i * 4096))
                                        .expect("page aligned")
                                })
                                .collect(),
                            carrick_hal::fork_stock::TableReserve::EMPTY,
                            vec![ForkLifecycleLoan::ARM_DEFAULT],
                        )
                        .expect("install fork stock");
                    stock
                        .owner
                        .provide_arm_control_capacity(0x5000_0000)
                        .expect("provide control window");
                }
                let exec = carrick_hal::fork_stock::GrantExecution::new(
                    CpuId::new(0),
                    ExecutionBinding {
                        task: EntryTaskKey::from_raw(41),
                        generation: SnapshotGeneration::from_raw(11),
                        mm: EntryMmKey::from_raw(301),
                        thread_generation: EntryThreadGeneration::from_raw(101),
                    },
                    AddressContext {
                        mm: MmGeneration::new(NonZeroU64::new(301).expect("nonzero")),
                        root: RootGpa::page_aligned(FrameGpa::new(
                            carrick_el1_abi::AARCH64_STAGE1_TABLE_POOL_BASE,
                        ))
                        .expect("page aligned"),
                        generation: ContextGeneration::new(NonZeroU64::MIN),
                    },
                );
                let req = ForkStockRequest {
                    binding: exec.binding,
                    context: exec.context,
                    operation: PortalOperation {
                        carrier: custody.transfer_carrier,
                        mm: ReservationMm::new(301).expect("mm"),
                        incarnation: NonZeroU64::MIN,
                        sequence: NonZeroU64::new(2).expect("seq"),
                    },
                    parent_generation: ReservationGeneration::INITIAL,
                    child_mm: ReservationMm::new(302).expect("child mm"),
                    child_bytes: 4096,
                    parent_bytes: 4096,
                };
                let mut exchange = ForkStockExchange::new(req).expect("exchange");
                let loan = {
                    let mut stock = custody.fork_stock.lock();
                    let mut ledger = crate::fork_stock::fork_table_accounting(custody);
                    stock
                        .owner
                        .loan(&mut ledger, exec, &mut exchange, |_| true)
                        .expect("grant loan")
                };
                let selected = PortalForkCustody::Frame {
                    va: 0x7000,
                    ipa,
                    len: 4096,
                    shared: false,
                };
                let physical_owner = super::ForkPhysicalCustody::new(
                    std::sync::Arc::clone(custody),
                    std::sync::Arc::new(|_, _| None),
                );
                let retained = physical_owner
                    .retain(loan.request, selected)
                    .expect("retain frame")
                    .expect("frame pin");
                assert_eq!(
                    custody
                        .stage2_record_snapshot(identity.record_id)
                        .expect("record snapshot")
                        .pin_count,
                    1
                );
                let completion = PortalForkCompletion {
                    request: loan.request,
                    child: unsafe {
                        carrick_el1_abi::El1MmHandle::from_admitted_owner(
                            custody.transfer_carrier,
                            loan.request.child_mm,
                            NonZeroU64::MIN,
                        )
                    },
                    parent_generation: ReservationGeneration::new(2).expect("gen"),
                    child_tables_used: 4096,
                    parent_tables_used: 4096,
                };
                let mut reserve =
                    ForkStockSettlement::reserve(loan, completion, KernelVa::new(0x1000), 1)
                        .expect("reserve settlement");
                {
                    let mut stock = custody.fork_stock.lock();
                    stock
                        .owner
                        .reserve_custody(
                            exec,
                            &mut reserve,
                            |_| true,
                            |_| true,
                            |_, _, _| {
                                Ok(crate::fork_stock::NativeChildPhysical {
                                    inherited: vec![retained],
                                    ..Default::default()
                                })
                            },
                            |_| {},
                        )
                        .expect("reserve custody");
                    let mut commit =
                        ForkStockSettlement::commit_reserved(loan, completion).expect("commit");
                    let mut ledger = crate::fork_stock::fork_table_accounting(custody);
                    stock
                        .owner
                        .commit_admitted(&mut ledger, exec, &mut commit)
                        .expect("commit admitted child");
                    assert_eq!(stock.owner.live_children(), 1);
                }
                identity
            };

        let (custody, _) = live_custody();
        let _ = settle_child_with_retained_frame(&custody, 0xa091_0000_0000);
        let weak = std::sync::Arc::downgrade(&custody);
        drop(custody);
        assert!(
            weak.upgrade().is_none(),
            "committed child in fork_stock must not cycle CarrierVmCustody"
        );

        let (custody, _) = live_custody();
        let identity = settle_child_with_retained_frame(&custody, 0xa091_1000_0000);
        assert_eq!(custody.fork_stock.lock().owner.live_children(), 1);
        destroy_vm_with_custody_using(
            &custody,
            "test destroy",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy VM with live committed child");
        assert_eq!(
            custody.fork_stock.lock().owner.live_children(),
            0,
            "VM destroy must drain committed fork_stock children"
        );
        assert_eq!(
            custody
                .stage2_record_snapshot(identity.record_id)
                .expect("terminalized record snapshot")
                .pin_count,
            0,
            "draining fork_stock on VM destroy must release retained stage-2 pins"
        );
        assert_eq!(
            custody.claim_terminal_stage2_release(identity),
            Ok(None),
            "fixed test lease owns no IPA allocation to release"
        );
    }

    #[test]
    fn successful_vm_destroy_terminalizes_generation_without_post_destroy_unmap() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let (custody, generation) = live_custody();
        let first = register_test_stage2_record(&custody, stage2_spec(generation, 31))
            .expect("register first record");
        let second = register_test_stage2_record(
            &custody,
            CarrierStage2RecordSpec {
                ipa: 0xc000,
                host_addr: 0x9abc_0000,
                ..stage2_spec(generation, 32)
            },
        )
        .expect("register second record");

        destroy_vm_with_custody_using(
            &custody,
            "test destroy",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let (custody, generation) = live_custody();
        let identity = register_test_stage2_record(&custody, stage2_spec(generation, 41))
            .expect("register record");
        let before = custody
            .stage2_record_snapshot(identity.record_id)
            .expect("record before destroy");

        assert!(
            destroy_vm_with_custody_using(
                &custody,
                "test destroy",
                carrick_aarch64::stage2::Stage2Status::from_raw(0xfae9_4001),
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
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let (custody, first_generation) = live_custody();
        let first = register_test_stage2_record(&custody, stage2_spec(first_generation, 51))
            .expect("register predecessor record");
        destroy_vm_with_custody_using(
            &custody,
            "test destroy",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy predecessor VM");
        let second_generation = custody.begin_create().expect("begin successor create");
        custody
            .commit_create(second_generation)
            .expect("publish successor generation");
        let second = register_test_stage2_record(&custody, stage2_spec(second_generation, 52))
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

    /// `HvfVmState::try_lazy_alias_remap` resolves an `AliasBacking` from the
    /// process-global alias registry and previously called raw
    /// `inventory_stage2_map_replay` with no `Stage2Generation` guard. If a
    /// rival destroys `G1` and creates `G2` after lookup, the stale `G1`
    /// replay maps into `G2`. Holding `admitting_stage2` across the replay map
    /// serializes destruction on `LockContended` instead.
    #[test]
    fn try_lazy_alias_remap_holds_generation_guard_across_replay() {
        use carrick_aarch64::stage2::custody::Stage2HookPoint;
        use std::sync::atomic::{AtomicBool, Ordering};
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stage2_stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let (custody, g1) = live_custody();
        let ipa = 0x7d00_2400_0000_u64;
        let va = 0x6000_2400_0000_u64;
        let len = 0x4000_usize;
        let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            len,
            crate::host_mapping::HostMappingKind::PrivateAnon,
        )
        .expect("allocate shared alias replay backing");
        let host_addr = host_mapping.as_ptr() as usize;
        let backing = super::AliasBacking {
            start: va,
            ipa,
            host_addr,
            size: len,
            physical_ipa: ipa,
            physical_host_addr: host_addr,
            physical_size: len,
            perms: 7,
            guest_writable: true,
            sharing: super::GuestMappingSharing::GlobalShared,
            ownership_scope: super::AliasOwnershipScope::Global,
            inventory_backing: super::InventoryBackingIdentity::Private(9991),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        super::register_shared_alias(backing);
        super::forget_replay_extent(ipa, len);

        let mut vm = super::HvfVmState {
            _vm: std::mem::ManuallyDrop::new(unsafe { std::mem::zeroed() }),
            vm_generation: Some(g1),
            task: super::hvpatch_neutral_task_state_for_test(),
            carrier_foreign_mm_transport: std::sync::Arc::new(super::CarrierForeignMmTransport {
                custody: std::sync::Arc::clone(&custody),
                ..Default::default()
            }),
            carrier_mappings: None,
            mailbox_slots: std::sync::Arc::new(super::MailboxSlotAllocator::new()),
            syscall_transport: super::HvfSyscallTransport::Mailbox,
            executor_vcpu: None,
            cached_fork_alias_snapshot: parking_lot::Mutex::new(None),
            last_fork_host_mapping_allocations: std::sync::atomic::AtomicU64::new(0),
            last_fork_projection_rows_visited: std::sync::atomic::AtomicU64::new(0),
        };

        let mapped_after_rival = std::sync::Arc::new(AtomicBool::new(false));
        let (start_tx, start_rx) = std::sync::mpsc::channel::<()>();
        let (event_tx, event_rx) = std::sync::mpsc::channel::<&'static str>();
        let hook_event_tx = event_tx.clone();
        let event_rx = std::sync::Mutex::new(event_rx);
        {
            let mapped_after_rival = std::sync::Arc::clone(&mapped_after_rival);
            custody.stage2.set_hook(Some(std::sync::Arc::new(
                move |hook_point| match hook_point {
                    carrick_aarch64::stage2::custody::Stage2HookPoint::Client(name)
                        if name == super::REPLAY_REMAP_LOOKED_UP =>
                    {
                        start_tx.send(()).expect("rival alive");
                        let event = event_rx
                            .lock()
                            .expect("event receiver")
                            .recv()
                            .expect("rival reports");
                        assert!(matches!(event, "contended" | "done"));
                        mapped_after_rival.store(event == "done", Ordering::SeqCst);
                    }
                    Stage2HookPoint::LockContended(_) => {
                        let _ = hook_event_tx.send("contended");
                    }
                    _ => {}
                },
            )));
        }

        let rival = {
            let custody = std::sync::Arc::clone(&custody);
            std::thread::spawn(move || {
                start_rx.recv().expect("replay parked");
                destroy_vm_with_custody_using(
                    &custody,
                    "rival G1 destroy",
                    carrick_aarch64::stage2::Stage2Status::SUCCESS,
                    || {},
                )
                .expect("rival destroys G1");
                let g2 = custody.begin_create().expect("begin G2");
                custody.commit_create(g2).expect("commit G2");
                let _ = event_tx.send("done");
                g2
            })
        };

        let remapped = vm.try_lazy_alias_remap(ipa, va);
        let g2 = rival.join().expect("rival");
        custody.stage2.set_hook(None);
        super::mutate_external_alias_state(|registry| {
            registry.retain(|alias| alias.physical_ipa != ipa);
        });
        super::forget_replay_extent(ipa, len);
        drop(host_mapping);

        assert_ne!(g2, g1);
        assert!(remapped, "G1 replay map must succeed before G1 destroy");
        assert!(
            !mapped_after_rival.load(Ordering::SeqCst),
            "stale G1 replay reached backend after G1 destroyed and G2 created"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn g1_untracked_unmap_after_vm_destroy_never_unmaps_g2() {
        use super::super::stage2_backend::{
            ScopedStage2MapTestStub, stage2_unmap_untracked_in, test_stage2_map_untracked,
        };
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = ScopedStage2MapTestStub::enable();
        let (custody, g1) = live_custody();
        let ipa = 0xa081_e000_0000_u64;
        let len = 0x4000_usize;
        let perms = carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite);
        let mut g1_backing = vec![0_u8; len];
        test_stage2_map_untracked(&custody, g1_backing.as_mut_ptr().cast(), ipa, len, perms);

        destroy_vm_with_custody_using(
            &custody,
            "destroy G1",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy G1");
        let g2 = custody.begin_create().expect("begin G2");
        custody.commit_create(g2).expect("commit G2");
        let mut g2_backing = vec![0_u8; len];
        test_stage2_map_untracked(&custody, g2_backing.as_mut_ptr().cast(), ipa, len, perms);
        assert!(ScopedStage2MapTestStub::is_mapped(ipa, len));

        stage2_unmap_untracked_in(&custody, g1, Some(g1_backing.as_ptr() as usize), ipa, len)
            .expect("stale G1 untracked unmap returns no-op without touching G2");
        assert!(
            ScopedStage2MapTestStub::is_mapped(ipa, len),
            "stale G1 untracked unmap damaged G2 mapping"
        );
        stage2_unmap_untracked_in(&custody, g2, Some(g2_backing.as_ptr() as usize), ipa, len)
            .expect("owning G2 untracked unmap retires G2 mapping");
        assert!(!ScopedStage2MapTestStub::is_mapped(ipa, len));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn stage2_map_replay_refuses_unregistered_alias_even_in_live_vm() {
        use super::super::stage2_backend::{
            ReplayAliasLookup, ScopedStage2MapTestStub, stage2_map_replay,
        };
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = ScopedStage2MapTestStub::enable();
        let (custody, g1) = live_custody();
        let len = 0x4000_usize;
        let ipa = crate::memory::LINUX_ALIAS_IPA_BASE + 0x7e00_0000;
        let result = unsafe {
            stage2_map_replay(
                &custody,
                g1,
                ReplayAliasLookup::Ipa { gpa: ipa },
                &mut |_| true,
            )
        };
        assert_eq!(result, Ok(None));
        assert!(!ScopedStage2MapTestStub::is_mapped(ipa, len));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn stale_g1_pooled_handles_are_refused_in_g2() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let (custody, g1) = live_custody();
        let frame_pool = std::sync::Arc::new(
            crate::frame_pool::PreMappedFramePool::new_test_fixture_in(&custody, 1),
        );
        let root_pool = std::sync::Arc::new(
            crate::frame_pool::PreMappedRootSlotPool::new_test_fixture_in(&custody, 1),
        );
        let frame_handle = frame_pool.allocate_compound().expect("G1 pooled frame");
        let root_handle = root_pool.allocate_slot().expect("G1 pooled root slot");
        assert_eq!(frame_handle.vm_generation(), Some(g1));
        assert_eq!(root_handle.vm_generation(), Some(g1));

        destroy_vm_with_custody_using(
            &custody,
            "destroy G1",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy G1");
        let g2 = custody.begin_create().expect("begin G2");
        custody.commit_create(g2).expect("commit G2");

        let perms = carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite);
        assert!(
            super::super::register_pooled_global_frame_host_owner_in(
                &custody,
                frame_handle,
                perms,
            )
            .is_err(),
            "G1 pooled frame handle must not register into G2"
        );
        assert!(custody.global_frame_host_owners.lock().is_empty());

        let root_ipa = root_handle.ipa();
        let root_len = root_handle.len();
        let mut root_lease = super::super::GlobalFrameStage2Lease::fixed(root_ipa, root_len as u64);
        root_lease.mark_pre_mapped_in(root_handle.vm_generation());
        assert!(
            super::super::StructuralBackingOwner::new_pooled_root_in(
                &custody,
                root_handle,
                root_lease,
                perms,
                super::super::next_structural_epoch().expect("epoch"),
                root_ipa,
                root_len,
            )
            .is_err(),
            "G1 pooled root handle must not register into G2"
        );
        assert!(custody.structural_backings.lock().is_empty());
    }

    #[test]
    fn try_lazy_alias_remap_refuses_g1_after_pre_guard_destroy_and_g2_create() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stage2_stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let (custody, g1) = live_custody();
        let ipa = 0x7d00_2500_0000_u64;
        let va = 0x6000_2500_0000_u64;
        let len = 0x4000_usize;
        let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            len,
            crate::host_mapping::HostMappingKind::PrivateAnon,
        )
        .expect("allocate shared alias replay backing");
        let host_addr = host_mapping.as_ptr() as usize;
        let backing = super::AliasBacking {
            start: va,
            ipa,
            host_addr,
            size: len,
            physical_ipa: ipa,
            physical_host_addr: host_addr,
            physical_size: len,
            perms: 7,
            guest_writable: true,
            sharing: super::GuestMappingSharing::GlobalShared,
            ownership_scope: super::AliasOwnershipScope::Global,
            inventory_backing: super::InventoryBackingIdentity::Private(9992),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        super::register_shared_alias(backing);
        super::forget_replay_extent(ipa, len);

        let mut vm = super::HvfVmState {
            _vm: std::mem::ManuallyDrop::new(unsafe { std::mem::zeroed() }),
            vm_generation: Some(g1),
            task: super::hvpatch_neutral_task_state_for_test(),
            carrier_foreign_mm_transport: std::sync::Arc::new(super::CarrierForeignMmTransport {
                custody: std::sync::Arc::clone(&custody),
                ..Default::default()
            }),
            carrier_mappings: None,
            mailbox_slots: std::sync::Arc::new(super::MailboxSlotAllocator::new()),
            syscall_transport: super::HvfSyscallTransport::Mailbox,
            executor_vcpu: None,
            cached_fork_alias_snapshot: parking_lot::Mutex::new(None),
            last_fork_host_mapping_allocations: std::sync::atomic::AtomicU64::new(0),
            last_fork_projection_rows_visited: std::sync::atomic::AtomicU64::new(0),
        };

        let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let go_rx = std::sync::Mutex::new(go_rx);
        custody.stage2.set_hook(Some(std::sync::Arc::new(
            move |hook_point| match hook_point {
                carrick_aarch64::stage2::custody::Stage2HookPoint::Client(name)
                    if name == super::REPLAY_REMAP_BEFORE_GUARD =>
                {
                    entered_tx.send(()).expect("rival alive");
                    let _ = go_rx.lock().expect("go receiver").recv();
                }
                _ => {}
            },
        )));

        let rival = {
            let custody = std::sync::Arc::clone(&custody);
            std::thread::spawn(move || {
                entered_rx.recv().expect("replay parked before guard");
                destroy_vm_with_custody_using(
                    &custody,
                    "rival G1 destroy",
                    carrick_aarch64::stage2::Stage2Status::SUCCESS,
                    || {},
                )
                .expect("rival destroys G1");
                let g2 = custody.begin_create().expect("begin G2");
                custody.commit_create(g2).expect("commit G2");
                let _ = go_tx.send(());
                g2
            })
        };

        let remapped = vm.try_lazy_alias_remap(ipa, va);
        let g2 = rival.join().expect("rival");
        custody.stage2.set_hook(None);
        super::mutate_external_alias_state(|registry| {
            registry.retain(|alias| alias.physical_ipa != ipa);
        });
        super::forget_replay_extent(ipa, len);
        drop(host_mapping);

        assert_ne!(g2, g1);
        assert!(
            !remapped,
            "stale G1 replay must fail closed after G1 destroy"
        );
        assert!(
            !super::super::stage2_backend::ScopedStage2MapTestStub::is_mapped(ipa, len),
            "stale G1 replay mapped into G2"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn stage2_map_replay_does_not_hold_stage2_across_alias_lookup_and_revalidates_removal() {
        use super::super::stage2_backend::{
            ReplayAliasLookup, ScopedStage2MapTestStub, stage2_map_replay,
        };
        use carrick_aarch64::stage2::custody::Stage2HookPoint;
        use std::sync::{Arc, mpsc};
        use std::time::Duration;

        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = ScopedStage2MapTestStub::enable();
        let (custody, g1) = live_custody();
        let len = 0x4000_usize;
        let ipa = crate::memory::LINUX_ALIAS_IPA_BASE + 0x7a00_0000;
        let va = 0x6200_0000_u64;
        let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            len,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("allocate alias backing");
        let host_addr = host_mapping.as_ptr() as usize;
        super::register_shared_alias(super::AliasBacking {
            start: va,
            ipa,
            host_addr,
            size: len,
            physical_ipa: ipa,
            physical_host_addr: host_addr,
            physical_size: len,
            perms: 7,
            guest_writable: true,
            sharing: super::GuestMappingSharing::GlobalShared,
            ownership_scope: super::AliasOwnershipScope::Global,
            inventory_backing: super::InventoryBackingIdentity::Private(9993),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        });
        super::forget_replay_extent(ipa, len);

        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let (event_tx, event_rx) = mpsc::channel::<&'static str>();
        let hook_event_tx = event_tx.clone();
        let go_rx = std::sync::Mutex::new(go_rx);
        custody
            .stage2
            .set_hook(Some(Arc::new(move |point| match point {
                Stage2HookPoint::Client(name)
                    if name == super::REPLAY_REMAP_DURING_PHASE1_LOOKUP =>
                {
                    let _ = entered_tx.send(());
                    let _ = go_rx.lock().expect("go receiver").recv();
                }
                Stage2HookPoint::LockContended(_) => {
                    let _ = hook_event_tx.send("contended");
                }
                _ => {}
            })));

        let replay_custody = Arc::clone(&custody);
        let replay_thread = std::thread::spawn(move || {
            let _stub = ScopedStage2MapTestStub::enable();
            unsafe {
                stage2_map_replay(
                    &replay_custody,
                    g1,
                    ReplayAliasLookup::Ipa { gpa: ipa },
                    &mut |_| true,
                )
            }
        });
        entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("replay paused in phase 1");

        // `custody.stage2` must NOT be held during Phase 1 lookup: a concurrent
        // acquirer succeeds immediately with zero `LockContended`.
        let probe_custody = Arc::clone(&custody);
        let probe_event_tx = event_tx.clone();
        let probe_thread = std::thread::spawn(move || {
            let guard = probe_custody.stage2.lock();
            drop(guard);
            let _ = probe_event_tx.send("acquired");
        });
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(2)),
            Ok("acquired"),
            "stage2 lock was held during lazy replay Phase 1 lookup"
        );
        probe_thread.join().expect("probe joined");

        // Remove the alias while paused before Phase 2; Phase 2's point revalidation
        // must fail closed cleanly rather than mapping the retired backing.
        super::mutate_external_alias_state(|registry| {
            registry.retain(|alias| alias.physical_ipa != ipa);
        });
        go_tx.send(()).expect("resume replay");
        let result = replay_thread.join().expect("replay joined");
        custody.stage2.set_hook(None);
        super::forget_replay_extent(ipa, len);
        drop(host_mapping);

        assert_eq!(result, Ok(None));
        assert!(!ScopedStage2MapTestStub::is_mapped(ipa, len));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn failed_lease_rollback_unmap_retains_host_backing_until_vm_destroy() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let (custody, g1) = live_custody();
        let key = (0xa081_f800_0000_u64, 0x4000_u64);
        let backing = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            key.1 as usize,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("allocate lease backing");
        let host_addr = backing.as_ptr() as usize;
        let perms = carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite);
        let stage2_mapping = super::super::stage2_backend::test_stage2_map(
            &custody,
            backing.as_ptr().cast(),
            key.0,
            key.1 as usize,
            perms,
        );
        let mut lease = super::GlobalFrameStage2Lease::fixed(key.0, key.1);
        lease.mark_mapped(stage2_mapping);

        // Force custody rejection (`begin_destroy` puts VM into Destroying) AND unmap failure.
        custody.begin_destroy(g1).expect("begin destroy");
        stub.set_fail_next_unmap(true);
        let err = super::register_global_frame_host_owner_in(&custody, lease, backing, perms)
            .expect_err(
                "destroying VM must reject registration and retain backing on unmap failure",
            );
        let _ = err;
        stub.set_fail_next_unmap(false);

        assert!(
            super::alias_backing_is_live(host_addr),
            "host backing must stay alive while unretired G1 mapping exists"
        );
        assert!(
            super::super::stage2_backend::ScopedStage2MapTestStub::is_mapped(key.0, key.1 as usize,)
        );
        custody.destroy_stage2_for_test(g1);
        custody.commit_destroy(g1).expect("commit destroy G1");
        assert!(
            !super::alias_backing_is_live(host_addr),
            "destroyed G1 must drop retained backing outside custody locks"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn retire_stage2_extent_refuses_reused_ipa_with_mismatched_host_owner() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let (custody, g1) = live_custody();
        let perms = carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite);
        let stale_host_a = 0x1111_0000_usize;

        // 1. Reusable global owner B reuses (ipa, len) with host B != stale_host_a.
        let global_lease =
            super::GlobalFrameStage2Lease::reserve(0x4000, 0x4000).expect("reserve global ipa");
        let global_ipa = global_lease.base();
        let global_backing_b = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            0x4000,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("map global backing B");
        let global_host_b = global_backing_b.as_ptr() as usize;
        let global_stage2 = super::super::stage2_backend::test_stage2_map(
            &custody,
            global_backing_b.as_ptr().cast(),
            global_ipa,
            0x4000,
            perms,
        );
        let mut mapped_global_lease = global_lease;
        mapped_global_lease.mark_mapped(global_stage2);
        let global_gen_b = super::register_global_frame_host_owner_in(
            &custody,
            mapped_global_lease,
            global_backing_b,
            perms,
        )
        .expect("register global owner B");
        let mut mappings = super::TaskMappingIndex::new();
        let global_err = super::HvfVmState::retire_stage2_extent_from_mappings_in(
            &custody,
            &mut mappings,
            global_ipa,
            0x4000,
            Some(stale_host_a),
        )
        .expect_err("stale host A must not retire global owner B");
        let _ = global_err;
        assert_eq!(
            super::global_frame_host_owner_generation_in(&custody, global_ipa, 0x4000),
            global_gen_b,
            "global owner B must stay live"
        );
        assert!(
            super::super::stage2_backend::ScopedStage2MapTestStub::is_mapped(global_ipa, 0x4000)
        );
        assert!(
            super::retire_global_frame_host_owner_if_generation_in(
                &custody,
                global_ipa,
                0x4000,
                global_gen_b
            )
            .is_retired()
        );

        // 2. Structural owner B in TaskMappingIndex with host B != stale_host_a.
        let struct_ipa = 0x2000_0000_u64;
        let struct_len = 0x4000_usize;
        let struct_backing_b = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            struct_len,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("map structural backing B");
        let struct_ptr_b = struct_backing_b.as_ptr();
        let struct_stage2 = super::super::stage2_backend::test_stage2_map(
            &custody,
            struct_ptr_b.cast(),
            struct_ipa,
            struct_len,
            perms,
        );
        let mut struct_lease = super::GlobalFrameStage2Lease::fixed(struct_ipa, struct_len as u64);
        struct_lease.mark_mapped(struct_stage2);
        let epoch_b = super::next_structural_epoch().expect("epoch");
        let owner_b = super::StructuralBackingOwner::new_in(
            &custody,
            struct_backing_b,
            struct_lease,
            perms,
            epoch_b,
            struct_ipa,
            struct_len,
        )
        .expect("structural owner B");
        let struct_id_b = owner_b.record_identity();
        let mut struct_mappings = super::TaskMappingIndex::from_region(super::HvfMappedRegion {
            start: 0x3000_0000,
            end: 0x3000_0000 + struct_len as u64,
            ipa: struct_ipa,
            physical_ipa: struct_ipa,
            physical_size: struct_len,
            owner_generation: epoch_b.raw(),
            host_addr: struct_ptr_b,
            size: struct_len,
            perms: carrick_hal::MemPerms::ReadWrite,
            memory: None,
            host_mapping: None,
            structural_owner: Some(owner_b),
            stage2_lease: None,
            stage2_generation: Some(g1),
            is_dynamic_alias: false,
            sharing: super::GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: None,
            shared_key_offset: 0,
        });
        let struct_err = super::HvfVmState::retire_stage2_extent_from_mappings_in(
            &custody,
            &mut struct_mappings,
            struct_ipa,
            struct_len as u64,
            Some(stale_host_a),
        )
        .expect_err("stale host A must not retire structural owner B");
        let _ = struct_err;
        assert!(
            custody
                .stage2_record_snapshot(struct_id_b.record_id)
                .is_some()
        );
        assert!(
            super::super::stage2_backend::ScopedStage2MapTestStub::is_mapped(
                struct_ipa, struct_len
            )
        );
        super::HvfVmState::retire_stage2_extent_from_mappings_in(
            &custody,
            &mut struct_mappings,
            struct_ipa,
            struct_len as u64,
            Some(struct_ptr_b as usize),
        )
        .expect("exact host B retires structural owner B");

        // 3. Row-local stage2_lease B in TaskMappingIndex with host B != stale_host_a.
        let local_ipa = 0x2100_0000_u64;
        let local_len = 0x4000_usize;
        let local_backing_b = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            local_len,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("map local backing B");
        let local_ptr_b = local_backing_b.as_ptr();
        let local_stage2 = super::super::stage2_backend::test_stage2_map(
            &custody,
            local_ptr_b.cast(),
            local_ipa,
            local_len,
            perms,
        );
        let mut local_lease = super::GlobalFrameStage2Lease::fixed(local_ipa, local_len as u64);
        local_lease.mark_mapped(local_stage2);
        let mut local_mappings = super::TaskMappingIndex::from_region(super::HvfMappedRegion {
            start: 0x3100_0000,
            end: 0x3100_0000 + local_len as u64,
            ipa: local_ipa,
            physical_ipa: local_ipa,
            physical_size: local_len,
            owner_generation: 0,
            host_addr: local_ptr_b,
            size: local_len,
            perms: carrick_hal::MemPerms::ReadWrite,
            memory: None,
            host_mapping: Some(local_backing_b.into()),
            structural_owner: None,
            stage2_lease: Some(local_lease),
            stage2_generation: Some(g1),
            is_dynamic_alias: false,
            sharing: super::GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: None,
            shared_key_offset: 0,
        });
        let local_err = super::HvfVmState::retire_stage2_extent_from_mappings_in(
            &custody,
            &mut local_mappings,
            local_ipa,
            local_len as u64,
            Some(stale_host_a),
        )
        .expect_err("stale host A must not retire local lease B");
        let _ = local_err;
        assert!(local_mappings.first().unwrap().stage2_lease.is_some());
        assert!(
            super::super::stage2_backend::ScopedStage2MapTestStub::is_mapped(local_ipa, local_len)
        );
        super::HvfVmState::retire_stage2_extent_from_mappings_in(
            &custody,
            &mut local_mappings,
            local_ipa,
            local_len as u64,
            Some(local_ptr_b as usize),
        )
        .expect("exact host B retires local lease B");
        assert!(
            !super::super::stage2_backend::ScopedStage2MapTestStub::is_mapped(local_ipa, local_len),
            "exact local retirement must unmap stage-2 mapping"
        );
        assert!(
            !super::alias_backing_is_live(local_ptr_b as usize),
            "exact local retirement must release row host backing once unmapped"
        );

        // 3b. Local unmap refusal on exact owner keeps RegionHostOwner backing alive until VM destroy.
        let refused_ipa = 0x2150_0000_u64;
        let refused_backing = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            local_len,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("map refused backing");
        let refused_ptr = refused_backing.as_ptr();
        let refused_stage2 = super::super::stage2_backend::test_stage2_map(
            &custody,
            refused_ptr.cast(),
            refused_ipa,
            local_len,
            perms,
        );
        let mut refused_lease = super::GlobalFrameStage2Lease::fixed(refused_ipa, local_len as u64);
        refused_lease.mark_mapped(refused_stage2);
        let mut refused_mappings = super::TaskMappingIndex::from_region(super::HvfMappedRegion {
            start: 0x3150_0000,
            end: 0x3150_0000 + local_len as u64,
            ipa: refused_ipa,
            physical_ipa: refused_ipa,
            physical_size: local_len,
            owner_generation: 0,
            host_addr: refused_ptr,
            size: local_len,
            perms: carrick_hal::MemPerms::ReadWrite,
            memory: None,
            host_mapping: Some(refused_backing.into()),
            structural_owner: None,
            stage2_lease: Some(refused_lease),
            stage2_generation: Some(g1),
            is_dynamic_alias: false,
            sharing: super::GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: None,
            shared_key_offset: 0,
        });
        stub.set_fail_next_unmap(true);
        let refuse_err = super::HvfVmState::retire_stage2_extent_from_mappings_in(
            &custody,
            &mut refused_mappings,
            refused_ipa,
            local_len as u64,
            Some(refused_ptr as usize),
        )
        .expect_err("refused unmap must propagate error");
        let _ = refuse_err;
        stub.set_fail_next_unmap(false);
        assert!(
            super::alias_backing_is_live(refused_ptr as usize),
            "unmap refusal on exact local lease must retain RegionHostOwner backing until custody destroy"
        );
        assert!(
            super::super::stage2_backend::ScopedStage2MapTestStub::is_mapped(
                refused_ipa,
                local_len
            )
        );

        // 4. Unowned row-local stage2_lease C: stale host A preserves lease and
        // stage-2 mapping; exact host C unmaps stage-2 mapping and drops backing.
        let unowned_ipa = 0x2200_0000_u64;
        let unowned_backing = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            local_len,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("map unowned backing C");
        let unowned_ptr = unowned_backing.as_ptr();
        let unowned_stage2 = super::super::stage2_backend::test_stage2_map(
            &custody,
            unowned_ptr.cast(),
            unowned_ipa,
            local_len,
            perms,
        );
        let mut unowned_lease = super::GlobalFrameStage2Lease::fixed(unowned_ipa, local_len as u64);
        unowned_lease.mark_mapped(unowned_stage2);
        let mut unowned_mappings = super::TaskMappingIndex::from_region(super::HvfMappedRegion {
            start: 0x3200_0000,
            end: 0x3200_0000 + local_len as u64,
            ipa: unowned_ipa,
            physical_ipa: unowned_ipa,
            physical_size: local_len,
            owner_generation: 0,
            host_addr: unowned_ptr,
            size: local_len,
            perms: carrick_hal::MemPerms::ReadWrite,
            memory: None,
            host_mapping: Some(unowned_backing.into()),
            structural_owner: None,
            stage2_lease: Some(unowned_lease),
            stage2_generation: Some(g1),
            is_dynamic_alias: false,
            sharing: super::GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: None,
            shared_key_offset: 0,
        });
        let unowned_err = super::HvfVmState::retire_unowned_stage2_extent_from_mappings_in(
            &custody,
            &mut unowned_mappings,
            unowned_ipa,
            local_len as u64,
            stale_host_a,
        )
        .expect_err("stale host A must not retire unowned lease C");
        let _ = unowned_err;
        assert!(unowned_mappings.first().unwrap().stage2_lease.is_some());
        assert!(
            super::super::stage2_backend::ScopedStage2MapTestStub::is_mapped(
                unowned_ipa,
                local_len
            )
        );
        super::HvfVmState::retire_unowned_stage2_extent_from_mappings_in(
            &custody,
            &mut unowned_mappings,
            unowned_ipa,
            local_len as u64,
            unowned_ptr as usize,
        )
        .expect("exact host C retires unowned lease C");
        assert!(
            !super::super::stage2_backend::ScopedStage2MapTestStub::is_mapped(
                unowned_ipa,
                local_len
            ),
            "exact unowned local retirement must unmap stage-2 mapping"
        );
        assert!(
            !super::alias_backing_is_live(unowned_ptr as usize),
            "exact unowned local retirement must release host backing after unmap"
        );
        assert!(
            super::alias_backing_is_live(refused_ptr as usize),
            "retained refused-unmap backing stays live until VM destroy"
        );
        destroy_vm_with_custody_using(
            &custody,
            "destroy VM to release retained local unmap-refused backing",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy VM");
        assert!(
            !super::alias_backing_is_live(refused_ptr as usize),
            "VM destroy must release retained refused-unmap backing"
        );
        let _ = (global_host_b, stale_host_a);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn failed_carrier_batch_rollback_retains_all_host_backings_until_vm_destroy() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let (custody, g0) = live_custody();
        // Destroy g0 and start g1 on the SAME custody so g0 is a genuine destroyed
        // predecessor generation when testing mid-batch stale-generation failure below.
        destroy_vm_with_custody_using(
            &custody,
            "destroy G0 for predecessor generation",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy G0");
        let g1 = custody.begin_create().expect("begin G1");
        custody.commit_create(g1).expect("commit G1");
        let perms = carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite);
        let len = 0x4000_usize;

        let make_mapped_lease_in = |target_custody: &std::sync::Arc<CarrierVmCustody>| {
            let backing = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                len,
                crate::host_mapping::HostMappingKind::FrameCow,
            )
            .expect("allocate lease backing");
            let host_addr = backing.as_ptr() as usize;
            let mut lease = super::GlobalFrameStage2Lease::reserve(len as u64, len as u64)
                .expect("reserve IPA");
            let ipa = lease.base();
            let stage2_mapping = super::super::stage2_backend::test_stage2_map(
                target_custody,
                backing.as_ptr().cast(),
                ipa,
                len,
                perms,
            );
            lease.mark_mapped(stage2_mapping);
            lease.set_backing_keeper(super::LeaseBackingKeeper::Host(std::sync::Arc::new(
                super::GlobalFrameSharedMapping::new(backing),
            )));
            (lease, ipa, host_addr)
        };

        // 1. Multi-lease Process/LeaseTest::abort where lease 0 fails unmap:
        // leases 1 & 2 still settle immediately, while lease 0 retains host0 + ipa0 until VM destroy.
        let (lease0, ipa0, host0) = make_mapped_lease_in(&custody);
        let (lease1, ipa1, host1) = make_mapped_lease_in(&custody);
        let (lease2, ipa2, host2) = make_mapped_lease_in(&custody);
        let mut leases = vec![lease0, lease1, lease2];
        stub.set_fail_next_unmap(true);
        let abort_err = super::HvpatchCarrierTaskState::LeaseTest {
            stage2_leases: std::mem::take(&mut leases),
        }
        .abort(Some(&custody))
        .expect_err("lease 0 unmap refusal must report rollback error");
        let _ = abort_err;
        stub.set_fail_next_unmap(false);

        assert!(super::alias_backing_is_live(host0));
        assert!(super::super::stage2_backend::ScopedStage2MapTestStub::is_mapped(ipa0, len));
        assert!(!super::alias_backing_is_live(host1) && !super::alias_backing_is_live(host2));
        assert!(
            !super::super::stage2_backend::ScopedStage2MapTestStub::is_mapped(ipa1, len)
                && !super::super::stage2_backend::ScopedStage2MapTestStub::is_mapped(ipa2, len)
        );
        assert!(
            !super::global_frame_ipa_allocator()
                .lock()
                .is_live(ipa1, len as u64)
                && !super::global_frame_ipa_allocator()
                    .lock()
                    .is_live(ipa2, len as u64)
        );
        assert!(
            super::global_frame_ipa_allocator()
                .lock()
                .is_live(ipa0, len as u64)
        );

        // 2. Production mid-batch `register_carrier_stage2_leases` transfer failure:
        // `mid0` succeeds custody transfer in G1 first, then `mid_stale` (mapped on destroyed G0)
        // passes batch validation and fails transfer -> rollback must unmap/retire BOTH `mid0`
        // (with unmap refusal retaining keeper as Abandoned!) AND remaining `mid2` in pending_iter,
        // preserve the rollback error, and `commit_destroy(g1)` MUST drain the Abandoned keeper!
        let (mid_stale, mid_stale_ipa, mid_stale_host) = {
            let backing = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                len,
                crate::host_mapping::HostMappingKind::FrameCow,
            )
            .expect("allocate stale lease backing");
            let host_addr = backing.as_ptr() as usize;
            let mut lease = super::GlobalFrameStage2Lease::reserve(len as u64, len as u64)
                .expect("reserve stale IPA");
            lease.mark_pre_mapped_in(Some(g0));
            lease.set_backing_keeper(super::LeaseBackingKeeper::Host(std::sync::Arc::new(
                super::GlobalFrameSharedMapping::new(backing),
            )));
            let ipa = lease.base();
            (lease, ipa, host_addr)
        };
        let (mid0, mid_ipa0, mid_host0) = make_mapped_lease_in(&custody);
        let (mid2, mid_ipa2, mid_host2) = make_mapped_lease_in(&custody);
        let mid_owners = std::collections::BTreeMap::from([
            ((mid_ipa0, len as u64), mid_host0),
            ((mid_stale_ipa, len as u64), mid_stale_host),
            ((mid_ipa2, len as u64), mid_host2),
        ]);
        let mut mid_batch = vec![mid0, mid_stale, mid2];
        stub.set_fail_next_unmap(true);
        let mid_err = super::register_carrier_stage2_leases(&custody, &mut mid_batch, &mid_owners)
            .expect_err("mid-batch transfer failure must fail and roll back batch");
        stub.set_fail_next_unmap(false);
        assert!(
            mid_err
                .to_string()
                .contains("carrier stage-2 batch rollback failed"),
            "mid-batch rollback error must be preserved: {mid_err}"
        );
        assert!(
            super::alias_backing_is_live(mid_host0),
            "unmap-refused transferred mid0 backing must stay live as Abandoned until VM destroy"
        );
        assert!(
            custody.carrier_stage2_records.lock().is_empty(),
            "abandoned mid0 record must not linger in replayable carrier_stage2_records"
        );
        assert!(
            !super::alias_backing_is_live(mid_stale_host)
                && !super::alias_backing_is_live(mid_host2),
            "failing and remaining leases in pending_iter must settle cleanly"
        );
        assert!(
            !super::global_frame_ipa_allocator()
                .lock()
                .is_live(mid_ipa2, len as u64)
                && !super::global_frame_ipa_allocator()
                    .lock()
                    .is_live(mid_stale_ipa, len as u64)
        );

        // 3. Also keep a live Replayable carrier record in the same VM G1 so we prove
        // `commit_destroy(g1)` drains Abandoned mid0 + lease0 WITHOUT dropping Replayable
        // `keep_host`, and Loop 3 rebind atomically moves `keep_host` to G2 without letting
        // concurrent cleanup of old_identity drop the rebound keeper!
        let (keep_lease, keep_ipa, keep_host) = make_mapped_lease_in(&custody);
        let keep_owners = std::collections::BTreeMap::from([((keep_ipa, len as u64), keep_host)]);
        let mut keep_batch = vec![keep_lease];
        let keep_ids =
            super::register_carrier_stage2_leases(&custody, &mut keep_batch, &keep_owners)
                .expect("register replayable carrier lease");
        let old_id = keep_ids[0];

        custody.begin_destroy(g1).expect("begin destroy");
        custody.destroy_stage2_for_test(g1);
        custody.commit_destroy(g1).expect("commit destroy");
        assert!(
            !super::alias_backing_is_live(host0) && !super::alias_backing_is_live(mid_host0),
            "VM destroy must drain all retained/abandoned backings"
        );
        assert!(
            !super::global_frame_ipa_allocator()
                .lock()
                .is_live(ipa0, len as u64)
                && !super::global_frame_ipa_allocator()
                    .lock()
                    .is_live(mid_ipa0, len as u64)
        );
        assert!(
            super::alias_backing_is_live(keep_host),
            "Replayable carrier lease keeper must survive G1 destroy for Loop 3 replay"
        );

        // Begin/commit G2, stage untracked G2 mapping, and race Loop 3 rebind against
        // stale terminal finalization of `old_id`.
        let g2 = custody.begin_create().expect("begin G2");
        custody.commit_create(g2).expect("commit G2");
        super::super::stage2_backend::test_stage2_map_untracked(
            &custody,
            keep_host as *mut std::ffi::c_void,
            keep_ipa,
            len,
            perms,
        );
        let (rebind_tx, rebind_rx) = std::sync::mpsc::channel::<()>();
        let (contended_tx, contended_rx) = std::sync::mpsc::channel::<()>();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let go_rx = std::sync::Mutex::new(go_rx);
        custody
            .stage2
            .set_hook(Some(std::sync::Arc::new(move |point| match point {
                carrick_aarch64::stage2::custody::Stage2HookPoint::Client(
                    super::REPLAY_REBIND_ADMITTED,
                ) => {
                    rebind_tx.send(()).expect("notify Loop 3 rebind point");
                    go_rx
                        .lock()
                        .expect("go lock")
                        .recv()
                        .expect("resume Loop 3");
                }
                carrick_aarch64::stage2::custody::Stage2HookPoint::LockContended("lock") => {
                    let _ = contended_tx.send(());
                }
                _ => {}
            })));
        let reconcile_custody = std::sync::Arc::clone(&custody);
        let reconcile_thread = std::thread::spawn(move || {
            super::reconcile_global_frame_owners_after_replay_in_using(
                &reconcile_custody,
                &[super::GlobalFrameReplayExtent {
                    ipa: keep_ipa,
                    length: len as u64,
                    host_addr: keep_host,
                    perms,
                    vm_generation: g2,
                }],
                false,
                &mut super::release_retired_stage2_ipa,
            )
        });
        rebind_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("Loop 3 reached REPLAY_REBIND_ADMITTED");
        let stale_finalize_custody = std::sync::Arc::clone(&custody);
        let stale_finalize_thread = std::thread::spawn(move || {
            super::finalize_terminal_stage2_record_using(
                &stale_finalize_custody,
                old_id,
                &mut super::release_retired_stage2_ipa,
            )
        });
        contended_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("stale cleanup must reach Loop 3 custody lock boundary");
        go_tx.send(()).expect("resume Loop 3");
        reconcile_thread
            .join()
            .expect("reconcile thread")
            .expect("Loop 3 rebind must succeed");
        let _ = stale_finalize_thread.join().expect("stale finalize thread");
        custody.stage2.set_hook(None);

        assert!(
            super::alias_backing_is_live(keep_host),
            "rebound G2 record must still own live host backing after concurrent old_id cleanup"
        );
        let new_id = custody.carrier_stage2_records.lock()[&(keep_ipa, len as u64)];
        assert_ne!(new_id, old_id);
        assert!(
            custody
                .carrier_lease_keepers
                .lock()
                .entries
                .contains_key(&new_id.record_id)
        );
        assert!(
            !custody
                .carrier_lease_keepers
                .lock()
                .entries
                .contains_key(&old_id.record_id)
        );

        super::retire_carrier_stage2_record_at_safe_point(&custody, new_id)
            .expect("retire rebound G2 carrier record");
        assert!(!super::alias_backing_is_live(keep_host));
        assert!(custody.carrier_lease_keepers.lock().entries.is_empty());
        assert!(
            !super::global_frame_ipa_allocator()
                .lock()
                .is_live(keep_ipa, len as u64)
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn structural_retry_and_replay_serialize_terminal_finalization_under_directory_lock() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let (custody, g1) = live_custody();
        let len = 0x4000_usize;
        let perms = carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite);
        let backing = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            len,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("structural backing");
        let host_addr = backing.as_ptr() as usize;
        let mut lease =
            super::GlobalFrameStage2Lease::reserve(len as u64, len as u64).expect("reserve IPA");
        let ipa = lease.base();
        let stage2_mapping = super::super::stage2_backend::test_stage2_map(
            &custody,
            backing.as_ptr().cast(),
            ipa,
            len,
            perms,
        );
        lease.mark_mapped(stage2_mapping);
        let epoch = super::next_structural_epoch().expect("epoch");
        let owner =
            super::StructuralBackingOwner::new_in(&custody, backing, lease, perms, epoch, ipa, len)
                .expect("structural owner");
        let identity = owner.record_identity();
        let owner_entry = std::sync::Arc::clone(&owner.retained);

        // Owner retires before G1 destroys; record remains terminal until finalization.
        drop(owner);
        destroy_vm_with_custody_using(
            &custody,
            "destroy G1",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy G1");

        // Park retry inside `release_ipa` (which holds `structural_backings` and has claimed
        // terminal release) while concurrent `reconcile_global_frame_owners_after_replay_in_using`
        // enters Loop 4 and signals `STRUCTURAL_DIRECTORY_CONTENDED`.
        let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let (contended_tx, contended_rx) = std::sync::mpsc::channel::<()>();
        let retry_custody = std::sync::Arc::clone(&custody);
        let retry_releases = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let retry_releases_worker = std::sync::Arc::clone(&retry_releases);
        let retry_thread = std::thread::spawn(move || {
            super::retry_structural_backing_identities_in_using(
                &retry_custody,
                &[identity],
                &mut |_, _| Ok(()),
                &mut |released_ipa, released_len| {
                    retry_releases_worker.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    entered_tx.send(()).expect("notify main");
                    go_rx.recv().expect("resume retry");
                    super::release_retired_stage2_ipa(released_ipa, released_len)
                },
            )
        });

        entered_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("retry inside release_ipa");
        custody
            .stage2
            .set_hook(Some(std::sync::Arc::new(move |point| {
                if matches!(
                    point,
                    carrick_aarch64::stage2::custody::Stage2HookPoint::Client(
                        super::STRUCTURAL_DIRECTORY_CONTENDED
                    )
                ) {
                    let _ = contended_tx.send(());
                }
            })));
        let reconcile_custody = std::sync::Arc::clone(&custody);
        let reconcile_releases = std::sync::Arc::clone(&retry_releases);
        let reconcile_thread = std::thread::spawn(move || {
            super::reconcile_global_frame_owners_after_replay_in_using(
                &reconcile_custody,
                &[],
                true,
                &mut |_, _| {
                    reconcile_releases.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                },
            )
        });

        contended_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("Loop 4 reached contended structural_backings lock");
        go_tx.send(()).expect("unblock retry");

        retry_thread
            .join()
            .expect("retry thread panicked")
            .expect("retry finalization failed");
        let report = reconcile_thread
            .join()
            .expect("reconcile thread panicked")
            .expect("reconcile must not race retry terminal finalization");
        custody.stage2.set_hook(None);
        let _ = (g1, report);
        assert_eq!(
            retry_releases.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "terminal IPA release must run at most once"
        );
        assert!(custody.structural_backings.lock().is_empty());
        assert!(custody.stage2_record_snapshot(identity.record_id).is_none());
        assert_eq!(
            *owner_entry.record_identity.lock(),
            super::cleared_stage2_record_identity()
        );
        drop(owner_entry);
        assert!(
            !super::global_frame_ipa_allocator()
                .lock()
                .is_live(ipa, len as u64)
        );
        assert!(!super::alias_backing_is_live(host_addr));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn loop3_rebind_retains_pinned_predecessor_backing_until_last_unpin() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let (custody, g1) = live_custody();
        let perms = carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite);
        let len = 0x4000_usize;

        let backing = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            len,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("allocate lease backing");
        let host_addr = backing.as_ptr() as usize;
        let mut lease =
            super::GlobalFrameStage2Lease::reserve(len as u64, len as u64).expect("reserve IPA");
        let ipa = lease.base();
        let stage2_mapping = super::super::stage2_backend::test_stage2_map(
            &custody,
            backing.as_ptr().cast(),
            ipa,
            len,
            perms,
        );
        lease.mark_mapped(stage2_mapping);
        lease.set_backing_keeper(super::LeaseBackingKeeper::Host(std::sync::Arc::new(
            super::GlobalFrameSharedMapping::new(backing),
        )));
        let owners = std::collections::BTreeMap::from([((ipa, len as u64), host_addr)]);
        let old_id = super::register_carrier_stage2_leases(&custody, &mut vec![lease], &owners)
            .expect("register carrier lease")[0];
        let old_pin = custody
            .pin_stage2_record(old_id)
            .expect("pin G1 carrier record");

        destroy_vm_with_custody_using(
            &custody,
            "destroy G1 while old_id is pinned",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy G1");
        let g2 = custody.begin_create().expect("begin G2");
        custody.commit_create(g2).expect("commit G2");
        super::super::stage2_backend::test_stage2_map_untracked(
            &custody,
            host_addr as *mut std::ffi::c_void,
            ipa,
            len,
            perms,
        );
        let report = super::reconcile_global_frame_owners_after_replay_in_using(
            &custody,
            &[super::GlobalFrameReplayExtent {
                ipa,
                length: len as u64,
                host_addr,
                perms,
                vm_generation: g2,
            }],
            false,
            &mut super::release_retired_stage2_ipa,
        )
        .expect("Loop 3 rebind with pinned predecessor");
        assert_eq!(report.rebound, 1);

        let new_id = custody.carrier_stage2_records.lock()[&(ipa, len as u64)];
        assert_ne!(new_id, old_id);
        let old_snapshot = custody
            .stage2_record_snapshot(old_id.record_id)
            .expect("pinned predecessor record must stay retained");
        assert!(old_snapshot.superseded_by_rebind);
        assert_eq!(old_snapshot.pin_count, 1);
        assert!(
            custody
                .carrier_lease_keepers
                .lock()
                .entries
                .contains_key(&old_id.record_id)
        );
        assert!(
            custody
                .carrier_lease_keepers
                .lock()
                .entries
                .contains_key(&new_id.record_id)
        );

        // Retiring successor frees G2 mapping/IPA while old_pin keeps host backing live.
        super::retire_carrier_stage2_record_at_safe_point(&custody, new_id)
            .expect("retire rebound successor");
        assert!(
            super::alias_backing_is_live(host_addr),
            "pinned predecessor must keep host backing alive after successor retires"
        );
        assert!(
            !super::global_frame_ipa_allocator()
                .lock()
                .is_live(ipa, len as u64)
        );

        drop(old_pin);
        assert!(custody.stage2_record_snapshot(old_id.record_id).is_none());
        assert!(custody.carrier_lease_keepers.lock().entries.is_empty());
        assert!(
            !super::alias_backing_is_live(host_addr),
            "dropping last predecessor pin must release backing"
        );
        let _ = g1;
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn pinned_abandoned_fixed_and_reserved_batch_records_drain_on_last_unpin_after_destroy() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let (custody, g0) = live_custody();
        destroy_vm_with_custody_using(
            &custody,
            "destroy G0 before G1",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy G0");
        let g1 = custody.begin_create().expect("begin G1");
        custody.commit_create(g1).expect("commit G1");
        let perms = carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite);
        let len = 0x4000_usize;

        // 1. Fixed-IPA (`release_ipa == false`) prefix lease pinned across mid-batch failure.
        let fixed_ipa = 0x2400_0000_u64;
        let fixed_backing = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            len,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("allocate fixed backing");
        let fixed_host = fixed_backing.as_ptr() as usize;
        let fixed_stage2 = super::super::stage2_backend::test_stage2_map(
            &custody,
            fixed_backing.as_ptr().cast(),
            fixed_ipa,
            len,
            perms,
        );
        let mut fixed_lease = super::GlobalFrameStage2Lease::fixed(fixed_ipa, len as u64);
        fixed_lease.mark_mapped(fixed_stage2);
        fixed_lease.set_backing_keeper(super::LeaseBackingKeeper::Host(std::sync::Arc::new(
            super::GlobalFrameSharedMapping::new(fixed_backing),
        )));

        // 2. Allocator-reserved (`release_ipa == true`) prefix lease also pinned across mid-batch failure.
        let res_backing = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            len,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("allocate reserved backing");
        let res_host = res_backing.as_ptr() as usize;
        let mut res_lease =
            super::GlobalFrameStage2Lease::reserve(len as u64, len as u64).expect("reserve IPA");
        let res_ipa = res_lease.base();
        let res_stage2 = super::super::stage2_backend::test_stage2_map(
            &custody,
            res_backing.as_ptr().cast(),
            res_ipa,
            len,
            perms,
        );
        res_lease.mark_mapped(res_stage2);
        res_lease.set_backing_keeper(super::LeaseBackingKeeper::Host(std::sync::Arc::new(
            super::GlobalFrameSharedMapping::new(res_backing),
        )));

        // 3. Stale G0 lease in the same batch triggers mid-batch failure; pin both prefixes
        // deterministically when rollback reaches CARRIER_BATCH_ROLLBACK_BEFORE_RETIRE.
        let stale_backing = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            len,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("allocate stale backing");
        let stale_host = stale_backing.as_ptr() as usize;
        let mut stale_lease =
            super::GlobalFrameStage2Lease::reserve(len as u64, len as u64).expect("reserve stale");
        let stale_ipa = stale_lease.base();
        stale_lease.mark_pre_mapped_in(Some(g0));
        stale_lease.set_backing_keeper(super::LeaseBackingKeeper::Host(std::sync::Arc::new(
            super::GlobalFrameSharedMapping::new(stale_backing),
        )));

        let (pin_ready_tx, pin_ready_rx) = std::sync::mpsc::channel::<()>();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel::<()>();
        let resume_rx = std::sync::Mutex::new(resume_rx);
        let captured_pins = std::sync::Arc::new(parking_lot::Mutex::new(None));
        let hook_custody = std::sync::Arc::clone(&custody);
        let hook_pins = std::sync::Arc::clone(&captured_pins);
        custody
            .stage2
            .set_hook(Some(std::sync::Arc::new(move |point| match point {
                carrick_aarch64::stage2::custody::Stage2HookPoint::Client(
                    super::CARRIER_BATCH_PREFIX_BEFORE_DETACH,
                ) => {
                    let fixed_id = hook_custody
                        .stage2_record_covering(fixed_ipa, len)
                        .expect("fixed prefix mapped before detach");
                    let res_id = hook_custody
                        .stage2_record_covering(res_ipa, len)
                        .expect("reserved prefix mapped before detach");
                    *hook_pins.lock() = Some((
                        fixed_id,
                        res_id,
                        hook_custody
                            .pin_stage2_record(fixed_id)
                            .expect("pin fixed prefix before retirement request"),
                        hook_custody
                            .pin_stage2_record(res_id)
                            .expect("pin reserved prefix before retirement request"),
                    ));
                }
                carrick_aarch64::stage2::custody::Stage2HookPoint::Client(
                    super::CARRIER_BATCH_ROLLBACK_BEFORE_RETIRE,
                ) => {
                    pin_ready_tx.send(()).expect("notify rollback hook");
                    resume_rx
                        .lock()
                        .expect("resume lock")
                        .recv()
                        .expect("resume rollback");
                }
                _ => {}
            })));
        let owners = std::collections::BTreeMap::from([
            ((fixed_ipa, len as u64), fixed_host),
            ((res_ipa, len as u64), res_host),
            ((stale_ipa, len as u64), stale_host),
        ]);
        let batch_custody = std::sync::Arc::clone(&custody);
        let batch_thread = std::thread::spawn(move || {
            let mut batch = vec![fixed_lease, res_lease, stale_lease];
            super::register_carrier_stage2_leases(&batch_custody, &mut batch, &owners)
        });
        pin_ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("batch rollback must hit CARRIER_BATCH_ROLLBACK_BEFORE_RETIRE");
        let (fixed_id, res_id, fixed_pin, res_pin) = captured_pins
            .lock()
            .take()
            .expect("pins captured before detach");
        assert!(
            custody.carrier_stage2_records.lock().is_empty(),
            "batch rollback must detach prefix entries before releasing carrier_stage2_records"
        );
        assert!(custody.carrier_lease_keepers.lock().entries[&fixed_id.record_id].is_abandoned());
        assert!(custody.carrier_lease_keepers.lock().entries[&res_id.record_id].is_abandoned());
        resume_tx.send(()).expect("resume batch rollback");
        let batch_err = batch_thread
            .join()
            .expect("batch thread")
            .expect_err("mid-batch stale lease must roll back");
        let _ = batch_err;
        custody.stage2.set_hook(None);

        // Pinned prefixes MUST be detached from `carrier_stage2_records`, marked Abandoned,
        // and retained across `destroy_stage2` + `commit_destroy(g1)`.
        assert!(
            custody.carrier_stage2_records.lock().is_empty(),
            "deferred batch rollback must detach pinned prefixes from replay directory"
        );
        assert!(custody.carrier_lease_keepers.lock().entries[&fixed_id.record_id].is_abandoned());
        assert!(custody.carrier_lease_keepers.lock().entries[&res_id.record_id].is_abandoned());
        assert!(!super::alias_backing_is_live(stale_host));

        custody.begin_destroy(g1).expect("begin destroy G1");
        custody.destroy_stage2_for_test(g1);
        custody.commit_destroy(g1).expect("commit destroy G1");
        assert_eq!(custody.carrier_lease_keepers.lock().drained_through, g1.0);
        assert!(super::alias_backing_is_live(fixed_host));
        assert!(super::alias_backing_is_live(res_host));
        assert!(custody.stage2_record_snapshot(fixed_id.record_id).is_some());
        assert!(custody.stage2_record_snapshot(res_id.record_id).is_some());

        // Dropping each pin AFTER destroy must settle both fixed (`ReadyToRetire`) and
        // reserved (`ReadyToRetry`) abandoned records immediately!
        drop(fixed_pin);
        assert!(
            custody.stage2_record_snapshot(fixed_id.record_id).is_none(),
            "fixed-IPA abandoned record must settle on last unpin after destroy"
        );
        assert!(!super::alias_backing_is_live(fixed_host));

        drop(res_pin);
        assert!(
            custody.stage2_record_snapshot(res_id.record_id).is_none(),
            "reserved-IPA abandoned record must settle on last unpin after destroy"
        );
        assert!(!super::alias_backing_is_live(res_host));
        assert!(
            !super::global_frame_ipa_allocator()
                .lock()
                .is_live(res_ipa, len as u64)
        );
        assert!(custody.carrier_lease_keepers.lock().entries.is_empty());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn fork_builder_rollback_with_pinned_owner_retains_slot_until_last_unpin_and_settles_sibling() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let custody = std::sync::Arc::new(CarrierVmCustody::new());
        let g1 = custody.begin_create().expect("begin G1");
        custody.commit_create(g1).expect("commit G1");

        let pool = custody
            .root_slot_pool()
            .expect("create root slot pool in G1");
        let handle0 = pool.allocate_slot().expect("checkout pooled root slot");
        let ipa0 = handle0.ipa();
        let len0 = handle0.len();
        let perms =
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWriteExec);
        let mut lease0 = super::GlobalFrameStage2Lease::fixed(ipa0, len0 as u64);
        lease0.mark_pre_mapped_in(Some(g1));
        let epoch0 = super::next_structural_epoch().expect("epoch0");
        let owner0 = super::StructuralBackingOwner::new_pooled_root_in(
            &custody, handle0, lease0, perms, epoch0, ipa0, len0,
        )
        .expect("structural owner0");
        let id0 = owner0.record_identity();

        let ipa1 = 0x2500_0000_u64;
        let len1 = 0x4000_usize;
        let backing1 = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            len1,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("backing1");
        let ptr1 = backing1.as_ptr() as usize;
        let stage2_1 = super::super::stage2_backend::test_stage2_map(
            &custody,
            backing1.as_ptr().cast(),
            ipa1,
            len1,
            perms,
        );
        let mut lease1 = super::GlobalFrameStage2Lease::fixed(ipa1, len1 as u64);
        lease1.mark_mapped(stage2_1);
        let epoch1 = super::next_structural_epoch().expect("epoch1");
        let owner1 = super::StructuralBackingOwner::new_in(
            &custody, backing1, lease1, perms, epoch1, ipa1, len1,
        )
        .expect("structural owner1");
        let id1 = owner1.record_identity();

        let mm_access = super::MmAccessState::new_unbound(
            carrick_aarch64::Stage1Authority::new(),
            carrick_guest_mem::UserMemoryAuthority::from_legacy(std::sync::Arc::new(
                super::MemoryProtections::default(),
            )),
            std::sync::Arc::new(parking_lot::Mutex::new(
                super::HvpatchFrameInventory::default(),
            )),
            std::sync::Arc::new(parking_lot::Mutex::new(super::CowArmedRanges::default())),
            std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
            crate::hvf_aarch64_engine::HostCowStats::default(),
        );
        mm_access.install_structural_owner(std::sync::Arc::clone(&owner0));
        mm_access.install_structural_owner(std::sync::Arc::clone(&owner1));

        // Pin owner0 across fork rollback while owner1 has zero pins.
        let pin0 = custody.pin_stage2_record(id0).expect("pin owner0");
        let outcome = super::owner_fork::retire_or_defer_published_fork_owners(
            &custody,
            &mm_access,
            &[
                std::sync::Arc::clone(&owner0),
                std::sync::Arc::clone(&owner1),
            ],
        )
        .expect("defer outcome cleanly");
        assert_eq!(
            outcome,
            super::owner_fork::ForkOwnerRollbackOutcome::DeferredActivePins
        );

        // Sibling owner1 MUST be settled and removed from BOTH structural_backings and MM structural_owners.
        assert!(custody.stage2_record_snapshot(id1.record_id).is_none());
        assert!(
            !custody
                .structural_backings
                .lock()
                .contains_key(&id1.record_id)
        );
        assert!(mm_access.structural_owner_host_ptr(ipa1, len1).is_none());
        assert_eq!(
            owner1.record_identity(),
            super::cleared_stage2_record_identity()
        );
        drop(owner1);
        assert!(!super::alias_backing_is_live(ptr1));

        // Pinned owner0 MUST stay in structural_owners and pooled root slot stays allocated!
        assert!(custody.stage2_record_snapshot(id0.record_id).is_some());
        assert!(
            custody
                .structural_backings
                .lock()
                .contains_key(&id0.record_id)
        );
        assert!(mm_access.structural_owner_host_ptr(ipa0, len0).is_some());
        assert!(custody.has_deferred_structural_logical_release(id0.record_id));
        drop(owner0);

        // Once last pin drops, BOTH physical record AND parent MM structural_owners + pooled slot release!
        drop(pin0);
        assert!(custody.stage2_record_snapshot(id0.record_id).is_none());
        assert!(custody.structural_backings.lock().is_empty());
        assert!(mm_access.structural_owner_host_ptr(ipa0, len0).is_none());
        assert!(!custody.has_deferred_structural_logical_release(id0.record_id));
        // Pooled root slot was returned to pool -> can allocate the exact slot again.
        let reallocated = pool
            .allocate_slot_at(ipa0)
            .expect("exact pooled root slot released on last unpin");
        reallocated.release_slot();
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn pinned_abandoned_batch_rollback_blocks_competing_replay_and_settles_on_last_unpin() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let (custody, g0) = live_custody();
        destroy_vm_with_custody_using(
            &custody,
            "destroy G0 before G1",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy G0");
        let g1 = custody.begin_create().expect("begin G1");
        custody.commit_create(g1).expect("commit G1");

        let perms = carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite);
        let len = 0x4000_usize;

        let fixed_ipa = 0x2410_0000_u64;
        let fixed_backing = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            len,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("allocate fixed backing");
        let fixed_host = fixed_backing.as_ptr() as usize;
        let fixed_stage2 = super::super::stage2_backend::test_stage2_map(
            &custody,
            fixed_backing.as_ptr().cast(),
            fixed_ipa,
            len,
            perms,
        );
        let mut fixed_lease = super::GlobalFrameStage2Lease::fixed(fixed_ipa, len as u64);
        fixed_lease.mark_mapped(fixed_stage2);
        fixed_lease.set_backing_keeper(super::LeaseBackingKeeper::Host(std::sync::Arc::new(
            super::GlobalFrameSharedMapping::new(fixed_backing),
        )));

        let res_backing = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            len,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("allocate reserved backing");
        let res_host = res_backing.as_ptr() as usize;
        let mut res_lease =
            super::GlobalFrameStage2Lease::reserve(len as u64, len as u64).expect("reserve IPA");
        let res_ipa = res_lease.base();
        let res_stage2 = super::super::stage2_backend::test_stage2_map(
            &custody,
            res_backing.as_ptr().cast(),
            res_ipa,
            len,
            perms,
        );
        res_lease.mark_mapped(res_stage2);
        res_lease.set_backing_keeper(super::LeaseBackingKeeper::Host(std::sync::Arc::new(
            super::GlobalFrameSharedMapping::new(res_backing),
        )));

        let stale_backing = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            len,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("allocate stale backing");
        let stale_host = stale_backing.as_ptr() as usize;
        let mut stale_lease =
            super::GlobalFrameStage2Lease::reserve(len as u64, len as u64).expect("reserve stale");
        let stale_ipa = stale_lease.base();
        stale_lease.mark_pre_mapped_in(Some(g0));
        stale_lease.set_backing_keeper(super::LeaseBackingKeeper::Host(std::sync::Arc::new(
            super::GlobalFrameSharedMapping::new(stale_backing),
        )));

        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel::<()>();
        let resume_rx = std::sync::Mutex::new(resume_rx);
        let captured_pins = std::sync::Arc::new(parking_lot::Mutex::new(None));
        let hook_custody = std::sync::Arc::clone(&custody);
        let hook_pins = std::sync::Arc::clone(&captured_pins);
        custody
            .stage2
            .set_hook(Some(std::sync::Arc::new(move |point| match point {
                carrick_aarch64::stage2::custody::Stage2HookPoint::Client(
                    super::CARRIER_BATCH_PREFIX_BEFORE_DETACH,
                ) => {
                    let fixed_id = hook_custody
                        .stage2_record_covering(fixed_ipa, len)
                        .expect("fixed prefix mapped before detach");
                    let res_id = hook_custody
                        .stage2_record_covering(res_ipa, len)
                        .expect("reserved prefix mapped before detach");
                    *hook_pins.lock() = Some((
                        fixed_id,
                        res_id,
                        hook_custody
                            .pin_stage2_record(fixed_id)
                            .expect("pin fixed before detach"),
                        hook_custody
                            .pin_stage2_record(res_id)
                            .expect("pin reserved before detach"),
                    ));
                }
                carrick_aarch64::stage2::custody::Stage2HookPoint::Client(
                    super::CARRIER_BATCH_ROLLBACK_BEFORE_RETIRE,
                ) => {
                    ready_tx.send(()).expect("notify rollback hook");
                    resume_rx
                        .lock()
                        .expect("resume lock")
                        .recv()
                        .expect("resume rollback");
                }
                _ => {}
            })));
        let owners = std::collections::BTreeMap::from([
            ((fixed_ipa, len as u64), fixed_host),
            ((res_ipa, len as u64), res_host),
            ((stale_ipa, len as u64), stale_host),
        ]);
        let batch_custody = std::sync::Arc::clone(&custody);
        let batch_thread = std::thread::spawn(move || {
            let mut batch = vec![fixed_lease, res_lease, stale_lease];
            super::register_carrier_stage2_leases(&batch_custody, &mut batch, &owners)
        });
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("batch rollback must hit CARRIER_BATCH_ROLLBACK_BEFORE_RETIRE");

        let (fixed_id, res_id, fixed_pin, res_pin) = captured_pins
            .lock()
            .take()
            .expect("pins captured before detach");
        assert!(custody.carrier_stage2_records.lock().is_empty());

        // Competing VM destroy + G2 replay attempts to rebind both prefix entries before rollback resumes.
        destroy_vm_with_custody_using(
            &custody,
            "competing destroy G1",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy G1");
        let g2 = custody.begin_create().expect("begin G2");
        custody.commit_create(g2).expect("commit G2");
        super::super::stage2_backend::test_stage2_map_untracked(
            &custody,
            fixed_host as *mut std::ffi::c_void,
            fixed_ipa,
            len,
            perms,
        );
        super::super::stage2_backend::test_stage2_map_untracked(
            &custody,
            res_host as *mut std::ffi::c_void,
            res_ipa,
            len,
            perms,
        );
        let report = super::reconcile_global_frame_owners_after_replay_in_using(
            &custody,
            &[
                super::GlobalFrameReplayExtent {
                    ipa: fixed_ipa,
                    length: len as u64,
                    host_addr: fixed_host,
                    perms,
                    vm_generation: g2,
                },
                super::GlobalFrameReplayExtent {
                    ipa: res_ipa,
                    length: len as u64,
                    host_addr: res_host,
                    perms,
                    vm_generation: g2,
                },
            ],
            false,
            &mut super::release_retired_stage2_ipa,
        )
        .expect("reconcile ignores detached abandoned prefixes");
        assert_eq!(report.rebound, 0);
        assert!(custody.carrier_stage2_records.lock().is_empty());

        resume_tx.send(()).expect("resume batch rollback");
        let _batch_err = batch_thread
            .join()
            .expect("batch thread")
            .expect_err("mid-batch failure rolls back");
        custody.stage2.set_hook(None);

        assert!(custody.carrier_stage2_records.lock().is_empty());
        assert!(super::alias_backing_is_live(fixed_host));
        assert!(super::alias_backing_is_live(res_host));
        assert!(!super::alias_backing_is_live(stale_host));

        drop(fixed_pin);
        assert!(custody.stage2_record_snapshot(fixed_id.record_id).is_none());
        assert!(!super::alias_backing_is_live(fixed_host));

        drop(res_pin);
        assert!(custody.stage2_record_snapshot(res_id.record_id).is_none());
        assert!(!super::alias_backing_is_live(res_host));
        assert!(
            !super::global_frame_ipa_allocator()
                .lock()
                .is_live(res_ipa, len as u64)
        );
        assert!(custody.carrier_lease_keepers.lock().entries.is_empty());
    }

    #[derive(Debug)]
    struct RecordingTableArenaSource {
        arenas: std::collections::VecDeque<carrick_mmu_core::aarch64::SubstrateGpa>,
        returned: std::sync::Arc<parking_lot::Mutex<Vec<carrick_mmu_core::aarch64::SubstrateGpa>>>,
    }

    impl carrick_mmu_core::aarch64::TableArenaSource for RecordingTableArenaSource {
        fn id(&self) -> carrick_mmu_core::aarch64::TableArenaSourceId {
            carrick_mmu_core::aarch64::TableArenaSourceId(carrick_mmu_core::aarch64::SubstrateGpa(
                0x2000_0000,
            ))
        }

        fn take_arena(&mut self) -> Option<carrick_mmu_core::aarch64::SubstrateGpa> {
            self.arenas.pop_front()
        }

        fn return_arena(&mut self, gpa: carrick_mmu_core::aarch64::SubstrateGpa) {
            self.returned.lock().push(gpa);
        }
    }

    fn make_fork_test_vm(
        custody: &std::sync::Arc<CarrierVmCustody>,
        g: CarrierVmGeneration,
    ) -> super::HvfVmState {
        let vm = super::HvfVmState {
            _vm: std::mem::ManuallyDrop::new(unsafe { std::mem::zeroed() }),
            vm_generation: Some(g),
            task: super::hvpatch_neutral_task_state_for_test(),
            carrier_foreign_mm_transport: std::sync::Arc::new(super::CarrierForeignMmTransport {
                custody: std::sync::Arc::clone(custody),
                ..Default::default()
            }),
            carrier_mappings: None,
            mailbox_slots: std::sync::Arc::new(super::MailboxSlotAllocator::new()),
            syscall_transport: super::HvfSyscallTransport::Mailbox,
            executor_vcpu: None,
            cached_fork_alias_snapshot: parking_lot::Mutex::new(None),
            last_fork_host_mapping_allocations: std::sync::atomic::AtomicU64::new(0),
            last_fork_projection_rows_visited: std::sync::atomic::AtomicU64::new(0),
        };
        let state = vm.task.mm_access_authority();
        state.bind_cow_runtime(super::MmCowRuntimeBinding {
            authority: std::sync::Arc::new(
                super::task_only_carrier_directory_tests::TestCowAuthority,
            ),
            identity: carrick_hal::FrameCowIdentity {
                linux_pid: 41,
                linux_tid: 41,
                mm: 41,
                asid: 41,
            },
            mm_root_slot: None,
            container_root: super::ContainerRootToken::ROOT,
            persistent_vm_lifecycle: true,
        });
        vm
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn prepare_owner_fork_builder_rollback_defers_pinned_owner_until_last_unpin() {
        const ARENA: usize = 2 * 1024 * 1024;
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let (custody, g1) = live_custody();
        let pool = custody.root_slot_pool().expect("root slot pool");
        let h0 = pool.allocate_slot().expect("slot0");
        let h1 = pool.allocate_slot().expect("slot1");
        let slot0_ipa = h0.ipa();
        let slot1_ipa = h1.ipa();
        h0.release_slot();
        h1.release_slot();
        assert_ne!(slot0_ipa, slot1_ipa);

        // Path 1: control arena fails publish_raw_stage1_arenas_into after root_slot_base publishes.
        let vm = make_fork_test_vm(&custody, g1);
        let state = vm.task.mm_access_authority();
        let returned_path1 = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut req1 = carrick_hal::ProcessForkRequest {
            entry: carrick_hal::GuestEntryRegs::default(),
            child_ttbr0: slot0_ipa + 0x1000,
            root_slot_base: slot0_ipa,
            root_slot_size: ARENA as u64,
            plan: carrick_hal::ForkProjectionPlan::Copied {
                parent_mm: 41,
                child_mm: 42,
                ranges: std::sync::Arc::from([]),
            },
            child_tid: carrick_hal::ThreadId::synthetic_for_tests(42),
            forking_tid: carrick_hal::ThreadId::synthetic_for_tests(41),
            table_arena_source: Some(Box::new(RecordingTableArenaSource {
                arenas: std::collections::VecDeque::from([
                    carrick_mmu_core::aarch64::SubstrateGpa(0x1000),
                ]),
                returned: std::sync::Arc::clone(&returned_path1),
            })),
        };
        let pin_slot = std::sync::Arc::new(parking_lot::Mutex::new(None));
        let hook_custody = std::sync::Arc::clone(&custody);
        let hook_pin = std::sync::Arc::clone(&pin_slot);
        custody
            .stage2
            .set_hook(Some(std::sync::Arc::new(move |point| {
                if matches!(
                    point,
                    carrick_aarch64::stage2::custody::Stage2HookPoint::Client(
                        super::owner_fork::FORK_PREPARE_BEFORE_ROLLBACK
                    )
                ) {
                    let id = hook_custody
                        .stage2_record_covering(slot0_ipa, ARENA)
                        .expect("slot0 published before rollback");
                    *hook_pin.lock() = Some(
                        hook_custody
                            .pin_stage2_record(id)
                            .expect("pin published slot0"),
                    );
                }
            })));
        let err1 = vm
            .prepare_owner_fork_builder(&mut req1)
            .err()
            .expect("invalid control arena must trigger rollback");
        let _ = err1;
        custody.stage2.set_hook(None);
        let pin0 = pin_slot
            .lock()
            .take()
            .expect("pin0 captured at rollback hook");
        let id0 = custody
            .stage2_record_covering(slot0_ipa, ARENA)
            .expect("slot0 record still live while pinned");
        assert_eq!(
            returned_path1.lock().as_slice(),
            &[carrick_mmu_core::aarch64::SubstrateGpa(0x1000)],
            "unpublished control arena must be returned to source"
        );
        assert!(
            pool.allocate_slot_at(slot0_ipa).is_none(),
            "exact slot0 must remain unavailable while pinned"
        );
        assert!(state.structural_owner_host_ptr(slot0_ipa, ARENA).is_some());
        assert!(custody.has_deferred_structural_logical_release(id0.record_id));
        drop(pin0);
        assert!(custody.stage2_record_snapshot(id0.record_id).is_none());
        assert!(custody.structural_backings.lock().is_empty());
        assert!(state.structural_owner_host_ptr(slot0_ipa, ARENA).is_none());
        assert!(!custody.has_deferred_structural_logical_release(id0.record_id));
        let freed0 = pool
            .allocate_slot_at(slot0_ipa)
            .expect("exact slot0 freed after last unpin");
        freed0.release_slot();

        // Path 2: root_slot_base already owned -> published.len() != 2 with pinned control slot.
        let pre_handle = pool
            .allocate_slot_at(slot0_ipa)
            .expect("slot0 for pre-owner");
        let perms =
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWriteExec);
        let mut pre_lease = super::GlobalFrameStage2Lease::fixed(slot0_ipa, ARENA as u64);
        pre_lease.mark_pre_mapped_in(Some(g1));
        let pre_epoch = super::next_structural_epoch().expect("pre epoch");
        let pre_owner = super::StructuralBackingOwner::new_pooled_root_in(
            &custody, pre_handle, pre_lease, perms, pre_epoch, slot0_ipa, ARENA,
        )
        .expect("pre owner");
        state.install_structural_owner(std::sync::Arc::clone(&pre_owner));

        let returned_path2 = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut req2 = carrick_hal::ProcessForkRequest {
            entry: carrick_hal::GuestEntryRegs::default(),
            child_ttbr0: slot0_ipa + 0x1000,
            root_slot_base: slot0_ipa,
            root_slot_size: ARENA as u64,
            plan: carrick_hal::ForkProjectionPlan::Copied {
                parent_mm: 41,
                child_mm: 43,
                ranges: std::sync::Arc::from([]),
            },
            child_tid: carrick_hal::ThreadId::synthetic_for_tests(43),
            forking_tid: carrick_hal::ThreadId::synthetic_for_tests(41),
            table_arena_source: Some(Box::new(RecordingTableArenaSource {
                arenas: std::collections::VecDeque::from([
                    carrick_mmu_core::aarch64::SubstrateGpa(slot1_ipa),
                ]),
                returned: std::sync::Arc::clone(&returned_path2),
            })),
        };
        let pin_slot2 = std::sync::Arc::new(parking_lot::Mutex::new(None));
        let hook_custody2 = std::sync::Arc::clone(&custody);
        let hook_pin2 = std::sync::Arc::clone(&pin_slot2);
        custody
            .stage2
            .set_hook(Some(std::sync::Arc::new(move |point| {
                if matches!(
                    point,
                    carrick_aarch64::stage2::custody::Stage2HookPoint::Client(
                        super::owner_fork::FORK_PREPARE_BEFORE_ROLLBACK
                    )
                ) {
                    let id = hook_custody2
                        .stage2_record_covering(slot1_ipa, ARENA)
                        .expect("control slot1 published before rollback");
                    *hook_pin2.lock() = Some(
                        hook_custody2
                            .pin_stage2_record(id)
                            .expect("pin published slot1"),
                    );
                }
            })));
        let err2 = vm
            .prepare_owner_fork_builder(&mut req2)
            .err()
            .expect("published.len() != 2 must fail and defer");
        assert!(err2.to_string().contains("deferred while pinned"));
        custody.stage2.set_hook(None);
        let pin1 = pin_slot2.lock().take().expect("pin1 captured");
        let id1 = custody
            .stage2_record_covering(slot1_ipa, ARENA)
            .expect("slot1 record still live");
        assert!(
            returned_path2.lock().is_empty(),
            "pinned published control arena must NOT be returned while pinned"
        );
        assert!(pool.allocate_slot_at(slot1_ipa).is_none());
        assert!(state.structural_owner_host_ptr(slot1_ipa, ARENA).is_some());
        drop(pin1);
        assert!(custody.stage2_record_snapshot(id1.record_id).is_none());
        assert!(state.structural_owner_host_ptr(slot1_ipa, ARENA).is_none());
        let freed1 = pool
            .allocate_slot_at(slot1_ipa)
            .expect("exact slot1 freed after last unpin");
        freed1.release_slot();
        state.release_exact_structural_owner(&pre_owner);
        drop(pre_owner);
        let _ = super::retry_structural_backing_retirements_in(&custody);
        std::mem::forget(vm);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn deferred_structural_fork_rollback_survives_unreplayed_and_replayed_vm_destroy_until_last_unpin()
     {
        const ARENA: usize = 2 * 1024 * 1024;
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();

        // Subcase A: pinned fork rollback across VM destroy when extent is UNREPLAYED.
        {
            let (custody, g1) = live_custody();
            let pool = custody.root_slot_pool().expect("root slot pool");
            let h0 = pool.allocate_slot().expect("slot0");
            let slot0_ipa = h0.ipa();
            h0.release_slot();
            let vm = make_fork_test_vm(&custody, g1);
            let state = vm.task.mm_access_authority();
            let returned = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
            let mut req = carrick_hal::ProcessForkRequest {
                entry: carrick_hal::GuestEntryRegs::default(),
                child_ttbr0: slot0_ipa + 0x1000,
                root_slot_base: slot0_ipa,
                root_slot_size: ARENA as u64,
                plan: carrick_hal::ForkProjectionPlan::Copied {
                    parent_mm: 41,
                    child_mm: 44,
                    ranges: std::sync::Arc::from([]),
                },
                child_tid: carrick_hal::ThreadId::synthetic_for_tests(44),
                forking_tid: carrick_hal::ThreadId::synthetic_for_tests(41),
                table_arena_source: Some(Box::new(RecordingTableArenaSource {
                    arenas: std::collections::VecDeque::from([
                        carrick_mmu_core::aarch64::SubstrateGpa(0x1000),
                    ]),
                    returned,
                })),
            };
            let pin_slot = std::sync::Arc::new(parking_lot::Mutex::new(None));
            let hc = std::sync::Arc::clone(&custody);
            let hp = std::sync::Arc::clone(&pin_slot);
            custody
                .stage2
                .set_hook(Some(std::sync::Arc::new(move |point| {
                    if matches!(
                        point,
                        carrick_aarch64::stage2::custody::Stage2HookPoint::Client(
                            super::owner_fork::FORK_PREPARE_BEFORE_ROLLBACK
                        )
                    ) {
                        let id = hc.stage2_record_covering(slot0_ipa, ARENA).expect("slot0");
                        *hp.lock() = Some(hc.pin_stage2_record(id).expect("pin0"));
                    }
                })));
            let _ = vm
                .prepare_owner_fork_builder(&mut req)
                .err()
                .expect("rollback");
            custody.stage2.set_hook(None);
            let pin0 = pin_slot.lock().take().expect("pin0");
            let id0 = custody
                .stage2_record_covering(slot0_ipa, ARENA)
                .expect("id0");

            destroy_vm_with_custody_using(
                &custody,
                "destroy G1 with pinned deferred structural owner",
                carrick_aarch64::stage2::Stage2Status::SUCCESS,
                || {},
            )
            .expect("destroy G1");
            let g2 = custody.begin_create().expect("begin G2");
            custody.commit_create(g2).expect("commit G2");
            let report = super::reconcile_global_frame_owners_after_replay_in_using(
                &custody,
                &[],
                false,
                &mut super::release_retired_stage2_ipa,
            )
            .expect("unreplayed pinned deferred rollback must defer rather than RecordNotTerminal");
            assert_eq!(report.deferred, 1);
            assert!(
                pool.allocate_slot_at(slot0_ipa).is_none(),
                "retained G1 pool must keep exact slot0 checked out while pinned across G2"
            );
            assert!(state.structural_owner_host_ptr(slot0_ipa, ARENA).is_some());
            drop(pin0);
            assert!(custody.stage2_record_snapshot(id0.record_id).is_none());
            assert!(custody.structural_backings.lock().is_empty());
            assert!(state.structural_owner_host_ptr(slot0_ipa, ARENA).is_none());
            assert!(!custody.has_deferred_structural_logical_release(id0.record_id));
            let freed = pool
                .allocate_slot_at(slot0_ipa)
                .expect("exact slot0 freed after last unpin post-destroy");
            freed.release_slot();
            std::mem::forget(vm);
        }

        // Subcase B: pinned fork rollback across VM destroy when extent IS REPLAYED into G2.
        {
            let (custody, g1) = live_custody();
            let pool = custody.root_slot_pool().expect("root slot pool");
            let h0 = pool.allocate_slot().expect("slot0");
            let slot0_ipa = h0.ipa();
            let slot0_host = h0.as_mut_ptr() as usize;
            h0.release_slot();
            let perms =
                carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWriteExec);
            let vm = make_fork_test_vm(&custody, g1);
            let state = vm.task.mm_access_authority();
            let returned = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
            let mut req = carrick_hal::ProcessForkRequest {
                entry: carrick_hal::GuestEntryRegs::default(),
                child_ttbr0: slot0_ipa + 0x1000,
                root_slot_base: slot0_ipa,
                root_slot_size: ARENA as u64,
                plan: carrick_hal::ForkProjectionPlan::Copied {
                    parent_mm: 41,
                    child_mm: 45,
                    ranges: std::sync::Arc::from([]),
                },
                child_tid: carrick_hal::ThreadId::synthetic_for_tests(45),
                forking_tid: carrick_hal::ThreadId::synthetic_for_tests(41),
                table_arena_source: Some(Box::new(RecordingTableArenaSource {
                    arenas: std::collections::VecDeque::from([
                        carrick_mmu_core::aarch64::SubstrateGpa(0x1000),
                    ]),
                    returned,
                })),
            };
            let pin_slot = std::sync::Arc::new(parking_lot::Mutex::new(None));
            let hc = std::sync::Arc::clone(&custody);
            let hp = std::sync::Arc::clone(&pin_slot);
            custody
                .stage2
                .set_hook(Some(std::sync::Arc::new(move |point| {
                    if matches!(
                        point,
                        carrick_aarch64::stage2::custody::Stage2HookPoint::Client(
                            super::owner_fork::FORK_PREPARE_BEFORE_ROLLBACK
                        )
                    ) {
                        let id = hc.stage2_record_covering(slot0_ipa, ARENA).expect("slot0");
                        *hp.lock() = Some(hc.pin_stage2_record(id).expect("pin0"));
                    }
                })));
            let _ = vm
                .prepare_owner_fork_builder(&mut req)
                .err()
                .expect("rollback");
            custody.stage2.set_hook(None);
            let pin0 = pin_slot.lock().take().expect("pin0");
            let old_id = custody
                .stage2_record_covering(slot0_ipa, ARENA)
                .expect("id0");

            destroy_vm_with_custody_using(
                &custody,
                "destroy G1 before replayed structural rollback",
                carrick_aarch64::stage2::Stage2Status::SUCCESS,
                || {},
            )
            .expect("destroy G1");
            let g2 = custody.begin_create().expect("begin G2");
            custody.commit_create(g2).expect("commit G2");
            super::super::stage2_backend::test_stage2_map_untracked(
                &custody,
                slot0_host as *mut std::ffi::c_void,
                slot0_ipa,
                ARENA,
                perms,
            );
            let report = super::reconcile_global_frame_owners_after_replay_in_using(
                &custody,
                &[super::GlobalFrameReplayExtent {
                    ipa: slot0_ipa,
                    length: ARENA as u64,
                    host_addr: slot0_host,
                    perms,
                    vm_generation: g2,
                }],
                false,
                &mut super::release_retired_stage2_ipa,
            )
            .expect("replayed deferred rollback must rebind and stay deferred while pinned");
            assert_eq!(report.deferred, 1);
            let new_id = {
                let sb = custody.structural_backings.lock();
                assert_eq!(sb.len(), 1);
                let (&id, retained) = sb.iter().next().expect("entry");
                let nid = *retained.record_identity.lock();
                assert_eq!(nid.record_id, id);
                nid
            };
            assert_ne!(new_id.record_id, old_id.record_id);
            assert!(custody.has_deferred_structural_logical_release(new_id.record_id));
            assert!(custody.has_pinned_structural_predecessor(new_id.record_id));
            // Retry pass before predecessor unpin drops MUST defer and keep slot0 out of pool.
            super::retry_structural_backing_retirements_in(&custody)
                .expect("retry defers while predecessor pinned");
            assert!(pool.allocate_slot_at(slot0_ipa).is_none());
            assert!(state.structural_owner_host_ptr(slot0_ipa, ARENA).is_some());

            // Now destroy G2 and inject a failed G2->G3 rebind (missing untracked G3 map):
            // the predecessor pin fence on `new_id` MUST survive the failed rebind!
            destroy_vm_with_custody_using(
                &custody,
                "destroy G2 before refused G3 rebind",
                carrick_aarch64::stage2::Stage2Status::SUCCESS,
                || {},
            )
            .expect("destroy G2");
            let g3 = custody.begin_create().expect("begin G3");
            custody.commit_create(g3).expect("commit G3");
            let rebind_err = super::reconcile_global_frame_owners_after_replay_in_using(
                &custody,
                &[super::GlobalFrameReplayExtent {
                    ipa: slot0_ipa,
                    length: ARENA as u64,
                    host_addr: slot0_host,
                    perms,
                    vm_generation: g3,
                }],
                false,
                &mut super::release_retired_stage2_ipa,
            )
            .expect_err("missing G3 untracked map must fail rebind");
            assert!(
                rebind_err
                    .to_string()
                    .contains("rebind structural backing after VM replay"),
                "unexpected refused G3 rebind error: {rebind_err}"
            );
            assert!(custody.has_pinned_structural_predecessor(new_id.record_id));
            assert!(custody.has_deferred_structural_logical_release(new_id.record_id));
            assert_eq!(
                super::retire_structural_stage2_record_at_safe_point(&custody, new_id)
                    .expect("terminal safe-point retirement must stay deferred while G1 pin holds"),
                super::StructuralSafePointRetirement::DeferredActivePins
            );
            super::retry_structural_backing_retirements_in(&custody)
                .expect("retry after refused G3 rebind must still keep G1 pin fence");
            assert!(pool.allocate_slot_at(slot0_ipa).is_none());
            assert!(state.structural_owner_host_ptr(slot0_ipa, ARENA).is_some());

            // Dropping predecessor pin settles successor and frees exact pooled root slot!
            drop(pin0);
            assert!(custody.stage2_record_snapshot(old_id.record_id).is_none());
            assert!(custody.stage2_record_snapshot(new_id.record_id).is_none());
            assert!(custody.structural_backings.lock().is_empty());
            assert!(state.structural_owner_host_ptr(slot0_ipa, ARENA).is_none());
            assert!(!custody.has_deferred_structural_logical_release(new_id.record_id));
            let freed = pool
                .allocate_slot_at(slot0_ipa)
                .expect("exact slot0 freed after predecessor unpin");
            freed.release_slot();
            std::mem::forget(vm);
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn deferred_structural_last_unpin_unmap_refusal_routes_to_retry_and_releases_slot() {
        const ARENA: usize = 2 * 1024 * 1024;
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let (custody, g1) = live_custody();
        // Use a non-pooled IPA so backend_map_installed == true and last unpin executes stage2.unmap.
        let non_pooled_ipa = 0x2800_0000_u64;
        let vm = make_fork_test_vm(&custody, g1);
        let state = vm.task.mm_access_authority();
        let returned = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut req = carrick_hal::ProcessForkRequest {
            entry: carrick_hal::GuestEntryRegs::default(),
            child_ttbr0: non_pooled_ipa + 0x1000,
            root_slot_base: non_pooled_ipa,
            root_slot_size: ARENA as u64,
            plan: carrick_hal::ForkProjectionPlan::Copied {
                parent_mm: 41,
                child_mm: 46,
                ranges: std::sync::Arc::from([]),
            },
            child_tid: carrick_hal::ThreadId::synthetic_for_tests(46),
            forking_tid: carrick_hal::ThreadId::synthetic_for_tests(41),
            table_arena_source: Some(Box::new(RecordingTableArenaSource {
                arenas: std::collections::VecDeque::from([
                    carrick_mmu_core::aarch64::SubstrateGpa(0x1000),
                ]),
                returned,
            })),
        };
        let pin_slot = std::sync::Arc::new(parking_lot::Mutex::new(None));
        let hc = std::sync::Arc::clone(&custody);
        let hp = std::sync::Arc::clone(&pin_slot);
        custody
            .stage2
            .set_hook(Some(std::sync::Arc::new(move |point| {
                if matches!(
                    point,
                    carrick_aarch64::stage2::custody::Stage2HookPoint::Client(
                        super::owner_fork::FORK_PREPARE_BEFORE_ROLLBACK
                    )
                ) {
                    let id = hc
                        .stage2_record_covering(non_pooled_ipa, ARENA)
                        .expect("non_pooled_ipa published");
                    *hp.lock() = Some(hc.pin_stage2_record(id).expect("pin non_pooled"));
                }
            })));
        let _ = vm
            .prepare_owner_fork_builder(&mut req)
            .err()
            .expect("rollback");
        custody.stage2.set_hook(None);
        let pin = pin_slot.lock().take().expect("pin captured");
        let id = custody
            .stage2_record_covering(non_pooled_ipa, ARENA)
            .expect("id");
        let host_ptr = state
            .structural_owner_host_ptr(non_pooled_ipa, ARENA)
            .expect("host ptr") as usize;
        assert!(custody.is_structural_owner_retired(id.record_id));
        assert!(custody.has_deferred_structural_logical_release(id.record_id));

        // Inject backend unmap failure on last unpin -> must route to retry boundary!
        stub.set_fail_next_unmap(true);
        drop(pin);
        assert!(
            custody
                .pending_global_frame_retirement_retry
                .load(std::sync::atomic::Ordering::Acquire),
            "failed last-unpin structural retirement must schedule retry"
        );
        assert!(
            custody
                .stage2_record_snapshot(id.record_id)
                .is_some_and(|s| s.retry_eligible && s.mapped)
        );
        assert!(custody.has_deferred_structural_logical_release(id.record_id));
        assert!(
            state
                .structural_owner_host_ptr(non_pooled_ipa, ARENA)
                .is_some()
        );
        assert!(super::alias_backing_is_live(host_ptr));

        // Idle retry boundary completes unmap and drains deferred logical release!
        let turn = super::retry_pending_global_frame_retirements_at_idle_in(&custody);
        assert_eq!(turn.remaining, 0);
        assert!(custody.stage2_record_snapshot(id.record_id).is_none());
        assert!(custody.structural_backings.lock().is_empty());
        assert!(!custody.has_deferred_structural_logical_release(id.record_id));
        assert!(
            state
                .structural_owner_host_ptr(non_pooled_ipa, ARENA)
                .is_none()
        );
        assert!(!super::alias_backing_is_live(host_ptr));
        std::mem::forget(vm);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn deferred_structural_idle_retry_does_not_starve_later_owner_when_earlier_refuses() {
        const ARENA: usize = 2 * 1024 * 1024;
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let (custody, g1) = live_custody();
        let vm = make_fork_test_vm(&custody, g1);
        let state = vm.task.mm_access_authority();
        let ipa_low = 0x2800_0000_u64;
        let ipa_high = 0x2840_0000_u64;
        let mut raw = Vec::new();
        state
            .publish_raw_stage1_arenas_into(
                &custody,
                &[ipa_low, ipa_high],
                carrick_hal::MemPerms::ReadWriteExec,
                &mut raw,
            )
            .expect("publish two non-pooled structural arenas");
        let owners = raw
            .iter()
            .filter_map(|r| r.structural_owner.clone())
            .collect::<Vec<_>>();
        assert_eq!(owners.len(), 2);
        let id_low = owners[0].record_identity();
        let id_high = owners[1].record_identity();
        assert!(id_low.record_id < id_high.record_id);
        let ptr_low = owners[0].ptr() as usize;
        let ptr_high = owners[1].ptr() as usize;

        let pin_low = custody.pin_stage2_record(id_low).expect("pin low");
        let pin_high = custody.pin_stage2_record(id_high).expect("pin high");
        assert_eq!(
            super::owner_fork::retire_or_defer_published_fork_owners(&custody, &state, &owners)
                .expect("defer both pinned owners"),
            super::owner_fork::ForkOwnerRollbackOutcome::DeferredActivePins
        );
        drop(owners);
        drop(raw);

        stub.set_fail_next_unmap(true);
        drop(pin_low);
        stub.set_fail_next_unmap(true);
        drop(pin_high);
        assert!(
            custody
                .pending_global_frame_retirement_retry
                .load(std::sync::atomic::Ordering::Acquire)
        );

        // Also retain 20 unrelated live structural owners so idle turn proves O(queued) work.
        let mut unrelated_owners = Vec::new();
        for idx in 0..20_usize {
            let extra_ipa = 0x3000_0000_u64 + (idx as u64) * 0x40_0000;
            let mut extra_raw = Vec::new();
            state
                .publish_raw_stage1_arenas_into(
                    &custody,
                    &[extra_ipa],
                    carrick_hal::MemPerms::ReadWriteExec,
                    &mut extra_raw,
                )
                .expect("publish unrelated live owner");
            unrelated_owners.extend(extra_raw.iter().filter_map(|r| r.structural_owner.clone()));
        }

        // Idle retry where lower-ID owner keeps refusing unmap MUST NOT starve later owner
        // and MUST NOT scan unrelated live structural owners!
        let turn1 = super::retry_pending_global_frame_retirements_at_idle_in_using(
            &custody,
            &mut |ipa, _| {
                if ipa == ipa_low {
                    Err(super::CarrierStage2BackendError::HvReturn(1))
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(turn1.inspected_structural, 2);
        assert_eq!(turn1.remaining, 1);
        assert!(
            custody
                .pending_global_frame_retirement_retry
                .load(std::sync::atomic::Ordering::Acquire)
        );
        assert!(custody.stage2_record_snapshot(id_high.record_id).is_none());
        assert!(!custody.has_deferred_structural_logical_release(id_high.record_id));
        assert!(state.structural_owner_host_ptr(ipa_high, ARENA).is_none());
        assert!(!super::alias_backing_is_live(ptr_high));

        assert!(custody.stage2_record_snapshot(id_low.record_id).is_some());
        assert!(custody.has_deferred_structural_logical_release(id_low.record_id));
        assert!(state.structural_owner_host_ptr(ipa_low, ARENA).is_some());

        let turn2 = super::retry_pending_global_frame_retirements_at_idle_in(&custody);
        assert_eq!(turn2.inspected_structural, 1);
        assert_eq!(turn2.remaining, 0);
        assert!(custody.stage2_record_snapshot(id_low.record_id).is_none());
        assert_eq!(custody.structural_backings.lock().len(), 20);
        assert!(!custody.has_deferred_structural_logical_release(id_low.record_id));
        assert!(state.structural_owner_host_ptr(ipa_low, ARENA).is_none());
        assert!(!super::alias_backing_is_live(ptr_low));
        for owner in unrelated_owners {
            state.release_exact_structural_owner(&owner);
            drop(owner);
        }
        super::retry_structural_backing_retirements_in(&custody)
            .expect("retire unrelated structural test owners");
        assert!(custody.structural_backings.lock().is_empty());
        std::mem::forget(vm);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn idle_structural_pinned_disposition_never_erases_concurrent_last_unpin_retry() {
        use carrick_aarch64::stage2::custody::Stage2HookPoint;
        use std::sync::{Arc, atomic::Ordering, mpsc};
        use std::time::Duration;

        const ARENA: usize = 2 * 1024 * 1024;
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let (custody, g1) = live_custody();
        let non_pooled_ipa = 0x2800_0000_u64;
        let perms =
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWriteExec);
        let vm = make_fork_test_vm(&custody, g1);
        let state = vm.task.mm_access_authority();
        let returned = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let mut req = carrick_hal::ProcessForkRequest {
            entry: carrick_hal::GuestEntryRegs::default(),
            child_ttbr0: non_pooled_ipa + 0x1000,
            root_slot_base: non_pooled_ipa,
            root_slot_size: ARENA as u64,
            plan: carrick_hal::ForkProjectionPlan::Copied {
                parent_mm: 41,
                child_mm: 47,
                ranges: Arc::from([]),
            },
            child_tid: carrick_hal::ThreadId::synthetic_for_tests(47),
            forking_tid: carrick_hal::ThreadId::synthetic_for_tests(41),
            table_arena_source: Some(Box::new(RecordingTableArenaSource {
                arenas: std::collections::VecDeque::from([
                    carrick_mmu_core::aarch64::SubstrateGpa(0x1000),
                ]),
                returned,
            })),
        };
        let pin_slot = Arc::new(parking_lot::Mutex::new(None));
        let hc = Arc::clone(&custody);
        let hp = Arc::clone(&pin_slot);
        custody.stage2.set_hook(Some(Arc::new(move |point| {
            if matches!(
                point,
                Stage2HookPoint::Client(super::owner_fork::FORK_PREPARE_BEFORE_ROLLBACK)
            ) {
                let id = hc
                    .stage2_record_covering(non_pooled_ipa, ARENA)
                    .expect("non_pooled_ipa published");
                *hp.lock() = Some(hc.pin_stage2_record(id).expect("pin non_pooled"));
            }
        })));
        let _ = vm
            .prepare_owner_fork_builder(&mut req)
            .err()
            .expect("rollback");
        custody.stage2.set_hook(None);
        let pin0 = pin_slot.lock().take().expect("pin captured");
        let host_ptr = state
            .structural_owner_host_ptr(non_pooled_ipa, ARENA)
            .expect("host ptr") as usize;

        destroy_vm_with_custody_using(
            &custody,
            "destroy G1 before replayed structural idle-vs-unpin race",
            carrick_aarch64::stage2::Stage2Status::SUCCESS,
            || {},
        )
        .expect("destroy G1");
        let g2 = custody.begin_create().expect("begin G2");
        custody.commit_create(g2).expect("commit G2");
        super::super::stage2_backend::test_stage2_map_untracked(
            &custody,
            host_ptr as *mut std::ffi::c_void,
            non_pooled_ipa,
            ARENA,
            perms,
        );
        let report = super::reconcile_global_frame_owners_after_replay_in_using(
            &custody,
            &[super::GlobalFrameReplayExtent {
                ipa: non_pooled_ipa,
                length: ARENA as u64,
                host_addr: host_ptr,
                perms,
                vm_generation: g2,
            }],
            false,
            &mut super::release_retired_stage2_ipa,
        )
        .expect("rebind deferred structural owner across G2");
        assert_eq!(report.deferred, 1);
        let new_id = {
            let sb = custody.structural_backings.lock();
            assert_eq!(sb.len(), 1);
            let (&id, retained) = sb.iter().next().expect("entry");
            let nid = *retained.record_identity.lock();
            assert_eq!(nid.record_id, id);
            nid
        };
        assert!(custody.has_pinned_structural_predecessor(new_id.record_id));
        assert!(custody.has_deferred_structural_logical_release(new_id.record_id));
        assert!(super::alias_backing_is_live(host_ptr));

        custody.enqueue_structural_retirement_retry(new_id.record_id);
        assert_eq!(custody.pending_structural_retries.lock().storage_len(), 1);

        let (idle_entered_tx, idle_entered_rx) = mpsc::channel::<()>();
        let (idle_go_tx, idle_go_rx) = mpsc::channel::<()>();
        let (contended_tx, contended_rx) = mpsc::channel::<()>();
        let idle_go_rx = parking_lot::Mutex::new(idle_go_rx);
        custody
            .stage2
            .set_hook(Some(Arc::new(move |point| match point {
                Stage2HookPoint::Client(name)
                    if name == super::IDLE_STRUCTURAL_PINNED_BEFORE_COMPLETE =>
                {
                    let _ = idle_entered_tx.send(());
                    let _ = idle_go_rx.lock().recv();
                }
                Stage2HookPoint::LockContended(_) => {
                    let _ = contended_tx.send(());
                }
                _ => {}
            })));

        let idle_custody = Arc::clone(&custody);
        let idle_thread = std::thread::spawn(move || {
            let _stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
            super::retry_pending_global_frame_retirements_at_idle_in(&idle_custody)
        });
        idle_entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("idle turn paused holding stage2 across pinned disposition");

        let unpin_thread = std::thread::spawn(move || {
            let stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
            stub.set_fail_next_unmap(true);
            drop(pin0);
        });
        contended_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("last-unpin contended on stage2 while idle checked pinned disposition");

        idle_go_tx.send(()).expect("resume idle turn");
        let turn1 = idle_thread.join().expect("idle thread panicked");
        unpin_thread.join().expect("unpin thread panicked");
        custody.stage2.set_hook(None);

        assert_eq!(turn1.inspected_structural, 1);
        assert_eq!(
            custody.pending_structural_retries.lock().storage_len(),
            1,
            "idle pinned complete() must finish before last-unpin re-enqueues failed retirement"
        );
        assert!(
            custody
                .pending_global_frame_retirement_retry
                .load(Ordering::Acquire)
        );
        assert!(
            custody
                .stage2_record_snapshot(new_id.record_id)
                .is_some_and(|s| s.mapped && s.retry_eligible)
        );
        assert!(custody.has_deferred_structural_logical_release(new_id.record_id));
        assert!(super::alias_backing_is_live(host_ptr));

        let turn2 = super::retry_pending_global_frame_retirements_at_idle_in(&custody);
        assert_eq!(turn2.inspected_structural, 1);
        assert_eq!(turn2.remaining, 0);
        assert_eq!(custody.pending_structural_retries.lock().storage_len(), 0);
        assert!(custody.stage2_record_snapshot(new_id.record_id).is_none());
        assert!(custody.structural_backings.lock().is_empty());
        assert!(!custody.has_deferred_structural_logical_release(new_id.record_id));
        assert!(
            state
                .structural_owner_host_ptr(non_pooled_ipa, ARENA)
                .is_none()
        );
        assert!(!super::alias_backing_is_live(host_ptr));
        std::mem::forget(vm);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn pooled_root_last_unpin_removes_structural_directory_entry_for_replay() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let _stub = super::super::stage2_backend::ScopedStage2MapTestStub::enable();
        let custody = std::sync::Arc::new(CarrierVmCustody::new());
        let g1 = custody.begin_create().expect("begin G1");
        custody.commit_create(g1).expect("commit G1");

        let pool = custody
            .root_slot_pool()
            .expect("create root slot pool in G1");
        let handle = pool.allocate_slot().expect("checkout pooled root slot");
        let ipa = handle.ipa();
        let len = handle.len();
        let perms = carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite);
        let mut lease = super::GlobalFrameStage2Lease::fixed(ipa, len as u64);
        lease.mark_pre_mapped_in(Some(g1));
        let epoch = super::next_structural_epoch().expect("epoch");
        let owner = super::StructuralBackingOwner::new_pooled_root_in(
            &custody, handle, lease, perms, epoch, ipa, len,
        )
        .expect("pooled root structural owner");
        let identity = owner.record_identity();
        let owner_entry = std::sync::Arc::clone(&owner.retained);

        let pin = custody
            .pin_stage2_record(identity)
            .expect("pin pooled root");
        drop(owner);
        assert!(
            custody
                .structural_backings
                .lock()
                .contains_key(&identity.record_id),
            "pinned pooled root remains in structural_backings until last unpin"
        );
        drop(pin);

        assert!(
            custody.stage2_record_snapshot(identity.record_id).is_none(),
            "last unpin must terminalize pooled root stage-2 record"
        );
        assert!(
            custody.structural_backings.lock().is_empty(),
            "last unpin must remove pooled root from structural_backings too"
        );
        assert_eq!(
            *owner_entry.record_identity.lock(),
            super::cleared_stage2_record_identity()
        );
        super::reconcile_global_frame_owners_after_replay_in_using(
            &custody,
            &[],
            false,
            &mut super::release_retired_stage2_ipa,
        )
        .expect("Loop 4 must succeed after pooled-root last unpin");
    }
}
