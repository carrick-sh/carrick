//! The neutral half of a carrier's stage-2 custody: the VM lifecycle, the
//! stage-2 record table with its extent index, and the backend that maps
//! the records (#1236 slice D).
//!
//! Every aarch64 carrier holds one [`Stage2Custody`] over its own
//! [`Stage2Backend`]: HVF over `hv_vm_map` (its `CarrierVmCustody` embeds
//! one), the soft CPU over its `SoftStage2` windows. The record types and
//! their transitions are `carrick_core::mm::retirement`'s; this table drives
//! them. Carrier-specific steps (HVF's frame pools, metadata aperture and
//! native root waits) stay with the carrier and run around the neutral
//! transitions here.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The record vocabulary this custody's API speaks.
pub use carrick_core::mm::retirement::{
    CarrierLogicalOwner, CarrierStage2BackendError, CarrierStage2PinError, CarrierStage2Record,
    CarrierStage2RecordError, CarrierStage2RecordId, CarrierStage2RecordIdentity,
    CarrierStage2RecordSnapshot, CarrierStage2RecordSpec, CarrierStage2RetireOutcome,
    CarrierVmGeneration, RecordPin, RecordPinRelease, RecordPinVenue,
};
use carrick_hal::TrapError;

use super::{Stage2Backend, Stage2Status};

/// A lifecycle transition the custody refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage2CustodyError {
    /// The VM is not in the state the transition starts from.
    LifecycleConflict,
    /// The transition names a generation other than the current one.
    StaleGeneration,
    /// No generation is left to create.
    GenerationExhausted,
    /// The carrier could not prove its physical grants settled at destroy.
    UnsettledPhysicalGrants,
}

/// The carrier VM's lifecycle. Generations only grow: a destroyed
/// generation never comes back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmLifecycle {
    Vacant,
    Creating(CarrierVmGeneration),
    Live(CarrierVmGeneration),
    Destroying(CarrierVmGeneration),
}

/// The lifecycle and record table, under the custody's one lock.
#[derive(Debug)]
pub struct Stage2CustodyState {
    pub next_generation: u64,
    pub lifecycle: VmLifecycle,
    pub next_stage2_record_id: u64,
    pub next_logical_owner_id: u64,
    pub next_logical_owner_generation: u64,
    pub stage2_records: BTreeMap<CarrierStage2RecordId, CarrierStage2Record>,
    /// One physical index over every record, independent of the authority
    /// that owns its lifetime. Rebind may briefly retain predecessor IDs.
    stage2_extent_index: BTreeMap<(u64, u64), BTreeSet<CarrierStage2RecordId>>,
}

impl Stage2CustodyState {
    fn vacant() -> Self {
        Self {
            next_generation: 1,
            lifecycle: VmLifecycle::Vacant,
            next_stage2_record_id: 1,
            next_logical_owner_id: 1,
            next_logical_owner_generation: 1,
            stage2_records: BTreeMap::new(),
            stage2_extent_index: BTreeMap::new(),
        }
    }

    fn index_record(&mut self, id: CarrierStage2RecordId, ipa: u64, len: usize) {
        self.stage2_extent_index
            .entry((ipa, len as u64))
            .or_default()
            .insert(id);
    }

    /// Remove one record and its extent-index entry.
    pub fn remove_record(&mut self, id: CarrierStage2RecordId) -> Option<CarrierStage2Record> {
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

    /// The VM of `generation` is gone, and its stage 2 with it: every record
    /// of that generation is terminal without an unmap.
    pub fn terminalize_generation(&mut self, generation: CarrierVmGeneration) {
        for record in self
            .stage2_records
            .values_mut()
            .filter(|record| record.snapshot.vm_generation == generation)
        {
            carrick_core::mm::retirement::terminalize_record(record);
        }
    }

    /// Admit a record for `spec` in this state, before any backend map.
    pub fn register_record(
        &mut self,
        spec: CarrierStage2RecordSpec,
    ) -> Result<CarrierStage2RecordIdentity, CarrierStage2RecordError> {
        if spec.len == 0 || (spec.mapped && spec.host_addr == 0) {
            return Err(CarrierStage2RecordError::InvalidExtent);
        }
        match self.lifecycle {
            VmLifecycle::Creating(generation) | VmLifecycle::Live(generation)
                if generation == spec.vm_generation => {}
            VmLifecycle::Creating(_) | VmLifecycle::Live(_) => {
                return Err(CarrierStage2RecordError::VmGenerationMismatch);
            }
            VmLifecycle::Vacant | VmLifecycle::Destroying(_) => {
                return Err(CarrierStage2RecordError::NoLiveVm);
            }
        }
        let next_id = self
            .next_stage2_record_id
            .checked_add(1)
            .ok_or(CarrierStage2RecordError::RecordIdExhausted)?;
        let record_id = CarrierStage2RecordId(self.next_stage2_record_id);
        self.next_stage2_record_id = next_id;
        let identity = CarrierStage2RecordIdentity {
            record_id,
            vm_generation: spec.vm_generation,
            logical_owner: spec.logical_owner,
        };
        self.stage2_records.insert(
            record_id,
            fresh_record(
                record_id,
                spec.vm_generation,
                spec.ipa,
                spec.len,
                spec.host_addr,
                spec.mapped,
                spec.backend_map_installed,
                spec.release_ipa,
                spec.perms,
                spec.logical_owner,
            ),
        );
        self.index_record(record_id, spec.ipa, spec.len);
        Ok(identity)
    }
}

fn fresh_record(
    record_id: CarrierStage2RecordId,
    vm_generation: CarrierVmGeneration,
    ipa: u64,
    len: usize,
    host_addr: usize,
    mapped: bool,
    backend_map_installed: bool,
    release_ipa: bool,
    perms: u64,
    logical_owner: Option<CarrierLogicalOwner>,
) -> CarrierStage2Record {
    CarrierStage2Record {
        snapshot: CarrierStage2RecordSnapshot {
            record_id,
            vm_generation,
            ipa,
            len,
            host_addr,
            mapped,
            backend_map_installed,
            release_ipa,
            perms,
            logical_owner,
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
    }
}

/// One carrier VM's stage-2 custody: its lifecycle, its record table, and
/// the backend that maps the records.
///
/// The state is neither static nor process-global. A failed backend destroy
/// is represented by [`Stage2Custody::abort_destroy`], which restores the
/// exact generation; a successful destroy must be committed before a later
/// generation can begin creation.
pub struct Stage2Custody {
    backend: Arc<dyn Stage2Backend + Send>,
    pub state: parking_lot::Mutex<Stage2CustodyState>,
}

impl core::fmt::Debug for Stage2Custody {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Stage2Custody")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Stage2Custody {
    /// A vacant custody whose records `backend` maps.
    pub fn new(backend: Arc<dyn Stage2Backend + Send>) -> Self {
        Self {
            backend,
            state: parking_lot::Mutex::new(Stage2CustodyState::vacant()),
        }
    }

    /// The backend this custody's records are mapped through.
    pub fn backend(&self) -> &dyn Stage2Backend {
        self.backend.as_ref()
    }

    /// The exact backend handle: two carriers' backends never compare equal,
    /// even of the same kind.
    pub fn backend_handle(&self) -> &Arc<dyn Stage2Backend + Send> {
        &self.backend
    }

    pub fn begin_create(&self) -> Result<CarrierVmGeneration, Stage2CustodyError> {
        let mut state = self.state.lock();
        if state.lifecycle != VmLifecycle::Vacant {
            return Err(Stage2CustodyError::LifecycleConflict);
        }
        let next_generation = state
            .next_generation
            .checked_add(1)
            .ok_or(Stage2CustodyError::GenerationExhausted)?;
        let generation = CarrierVmGeneration(state.next_generation);
        state.next_generation = next_generation;
        state.lifecycle = VmLifecycle::Creating(generation);
        Ok(generation)
    }

    /// Publish `generation` live. `on_live` runs under the custody lock,
    /// just before the generation is published, for the carrier's own
    /// per-VM reset.
    pub fn commit_create_with(
        &self,
        generation: CarrierVmGeneration,
        on_live: impl FnOnce(),
    ) -> Result<(), Stage2CustodyError> {
        let mut state = self.state.lock();
        match state.lifecycle {
            VmLifecycle::Creating(current) if current == generation => {
                on_live();
                state.lifecycle = VmLifecycle::Live(generation);
                Ok(())
            }
            VmLifecycle::Creating(_) | VmLifecycle::Live(_) => {
                Err(Stage2CustodyError::StaleGeneration)
            }
            VmLifecycle::Vacant | VmLifecycle::Destroying(_) => {
                Err(Stage2CustodyError::LifecycleConflict)
            }
        }
    }

    pub fn abort_create(&self, generation: CarrierVmGeneration) -> Result<(), Stage2CustodyError> {
        let mut state = self.state.lock();
        match state.lifecycle {
            VmLifecycle::Creating(current) if current == generation => {
                state.lifecycle = VmLifecycle::Vacant;
                Ok(())
            }
            VmLifecycle::Creating(_) | VmLifecycle::Live(_) => {
                Err(Stage2CustodyError::StaleGeneration)
            }
            VmLifecycle::Vacant | VmLifecycle::Destroying(_) => {
                Err(Stage2CustodyError::LifecycleConflict)
            }
        }
    }

    /// A VM that failed creation was destroyed raw: its records are terminal
    /// and the custody is vacant again.
    pub fn abort_created_vm_after_raw_destroy(
        &self,
        generation: CarrierVmGeneration,
    ) -> Result<(), Stage2CustodyError> {
        let mut state = self.state.lock();
        match state.lifecycle {
            VmLifecycle::Creating(current) if current == generation => {
                state.terminalize_generation(generation);
                state.lifecycle = VmLifecycle::Vacant;
                Ok(())
            }
            VmLifecycle::Creating(_) | VmLifecycle::Live(_) => {
                Err(Stage2CustodyError::StaleGeneration)
            }
            VmLifecycle::Vacant | VmLifecycle::Destroying(_) => {
                Err(Stage2CustodyError::LifecycleConflict)
            }
        }
    }

    pub fn begin_destroy(&self, generation: CarrierVmGeneration) -> Result<(), Stage2CustodyError> {
        let mut state = self.state.lock();
        match state.lifecycle {
            VmLifecycle::Live(current) if current == generation => {
                state.lifecycle = VmLifecycle::Destroying(generation);
                Ok(())
            }
            VmLifecycle::Live(_) => Err(Stage2CustodyError::StaleGeneration),
            VmLifecycle::Vacant | VmLifecycle::Creating(_) | VmLifecycle::Destroying(_) => {
                Err(Stage2CustodyError::LifecycleConflict)
            }
        }
    }

    pub fn abort_destroy(&self, generation: CarrierVmGeneration) -> Result<(), Stage2CustodyError> {
        let mut state = self.state.lock();
        match state.lifecycle {
            VmLifecycle::Destroying(current) if current == generation => {
                state.lifecycle = VmLifecycle::Live(generation);
                Ok(())
            }
            VmLifecycle::Destroying(_) | VmLifecycle::Live(_) => {
                Err(Stage2CustodyError::StaleGeneration)
            }
            VmLifecycle::Vacant | VmLifecycle::Creating(_) => {
                Err(Stage2CustodyError::LifecycleConflict)
            }
        }
    }

    pub fn live_generation(&self) -> Option<CarrierVmGeneration> {
        match self.state.lock().lifecycle {
            VmLifecycle::Live(generation) => Some(generation),
            VmLifecycle::Vacant | VmLifecycle::Creating(_) | VmLifecycle::Destroying(_) => None,
        }
    }

    pub fn setup_generation(&self) -> Option<CarrierVmGeneration> {
        match self.state.lock().lifecycle {
            VmLifecycle::Creating(generation) | VmLifecycle::Live(generation) => Some(generation),
            VmLifecycle::Vacant | VmLifecycle::Destroying(_) => None,
        }
    }

    pub fn creating_generation(&self) -> Option<CarrierVmGeneration> {
        match self.state.lock().lifecycle {
            VmLifecycle::Creating(generation) => Some(generation),
            VmLifecycle::Vacant | VmLifecycle::Live(_) | VmLifecycle::Destroying(_) => None,
        }
    }

    pub fn stage2_record_identities(&self) -> Vec<CarrierStage2RecordIdentity> {
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

    pub fn allocate_logical_owner(&self) -> Result<CarrierLogicalOwner, CarrierStage2RecordError> {
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

    pub fn remove_terminal_stage2_record(
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
            .remove_record(identity.record_id)
            .map(|record| record.snapshot)
    }

    pub fn claim_terminal_stage2_release(
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
            let _ = state.remove_record(identity.record_id);
            return Ok(None);
        }
        record.snapshot.release_in_flight = true;
        record.snapshot.release_retry_pending = false;
        Ok(Some((record.snapshot.ipa, record.snapshot.len as u64)))
    }

    pub fn commit_terminal_stage2_release(&self, identity: CarrierStage2RecordIdentity) {
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
            let _ = state.remove_record(identity.record_id);
        }
    }

    pub fn abort_terminal_stage2_release(&self, identity: CarrierStage2RecordIdentity) {
        let mut state = self.state.lock();
        let Some(record) = state.stage2_records.get_mut(&identity.record_id) else {
            debug_assert!(false, "claimed terminal release record disappeared");
            return;
        };
        debug_assert!(Self::stage2_identity_mismatch(record, identity).is_none());
        record.snapshot.release_in_flight = false;
        record.snapshot.release_retry_pending = true;
    }

    pub fn register_stage2_record(
        &self,
        spec: CarrierStage2RecordSpec,
    ) -> Result<CarrierStage2RecordIdentity, CarrierStage2RecordError> {
        self.state.lock().register_record(spec)
    }

    /// Commit backend mapping and its exact record under one lifecycle lock.
    /// The backend callback must not re-enter custody. All fallible record
    /// admission happens before map; a failed map removes the unpublished record.
    pub fn publish_stage2_record_using(
        &self,
        spec: CarrierStage2RecordSpec,
        map: impl FnOnce(CarrierStage2RecordIdentity) -> Stage2Status,
    ) -> Result<CarrierStage2RecordIdentity, TrapError> {
        let mut state = self.state.lock();
        let identity = state.register_record(spec).map_err(|error| {
            TrapError::Hypervisor(format!("stage-2 record admission: {error:?}"))
        })?;
        let rc = map(identity);
        if rc != 0 {
            let _ = state.remove_record(identity.record_id);
            return Err(TrapError::Hypervisor(format!(
                "stage-2 map failed: {rc:#x}"
            )));
        }
        Ok(identity)
    }

    /// Publish `spec` and map it through this custody's own backend.
    ///
    /// # Safety
    ///
    /// As [`Stage2Backend::map`]: `[spec.host_addr, + spec.len)` must stay
    /// mapped and unused for anything else until the record retires or the
    /// VM is destroyed.
    pub unsafe fn publish_stage2_record(
        &self,
        spec: CarrierStage2RecordSpec,
    ) -> Result<CarrierStage2RecordIdentity, TrapError> {
        let perms = super::stage2_perms_from_bits(spec.perms).ok_or_else(|| {
            TrapError::Hypervisor(format!("stage-2 permission word {:#x}", spec.perms))
        })?;
        // A busy backend is "not now": the failed attempt removed its
        // unpublished record and released the custody lock, so the rerun
        // waits on the holder's release with no custody state held.
        let mut published = None;
        let _ = super::run_past_busy(self.backend(), || {
            let mut status = Stage2Status::SUCCESS;
            published = Some(self.publish_stage2_record_using(spec, |_| {
                // SAFETY: the caller's contract above.
                status = unsafe {
                    self.backend.map(
                        spec.host_addr as *mut core::ffi::c_void,
                        spec.ipa,
                        spec.len,
                        perms,
                    )
                };
                status
            }));
            status
        });
        published.unwrap_or_else(|| {
            Err(TrapError::Hypervisor(
                "stage-2 publish made no attempt".to_owned(),
            ))
        })
    }

    pub fn rebind_terminal_stage2_record(
        &self,
        old_identity: CarrierStage2RecordIdentity,
        host_addr: usize,
        perms: u64,
    ) -> Result<CarrierStage2RecordIdentity, CarrierStage2RecordError> {
        let mut state = self.state.lock();
        let live_generation = match state.lifecycle {
            VmLifecycle::Creating(generation) | VmLifecycle::Live(generation) => generation,
            VmLifecycle::Vacant | VmLifecycle::Destroying(_) => {
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
            fresh_record(
                record_id,
                live_generation,
                old.snapshot.ipa,
                old.snapshot.len,
                host_addr,
                true,
                true,
                old.snapshot.release_ipa,
                perms,
                old.snapshot.logical_owner,
            ),
        );
        state.index_record(record_id, old.snapshot.ipa, old.snapshot.len);
        let old = state
            .stage2_records
            .get_mut(&old_identity.record_id)
            .ok_or(CarrierStage2RecordError::RecordNotFound)?;
        old.snapshot.release_ipa = false;
        old.snapshot.superseded_by_rebind = true;
        Ok(identity)
    }

    pub fn stage2_record_snapshot(
        &self,
        record_id: CarrierStage2RecordId,
    ) -> Option<CarrierStage2RecordSnapshot> {
        self.state
            .lock()
            .stage2_records
            .get(&record_id)
            .map(|record| record.snapshot)
    }

    pub fn stage2_record_covering(
        &self,
        ipa: u64,
        len: usize,
    ) -> Option<CarrierStage2RecordIdentity> {
        let state = self.state.lock();
        let (&(base, length), ids) = state
            .stage2_extent_index
            .range(..=(ipa, u64::MAX))
            .next_back()?;
        let end = ipa.checked_add(len as u64)?;
        if end > base.checked_add(length)? {
            return None;
        }
        ids.iter().rev().find_map(|id| {
            let record = state.stage2_records.get(id)?;
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

    pub fn stage2_identity_mismatch(
        record: &CarrierStage2Record,
        identity: CarrierStage2RecordIdentity,
    ) -> Option<CarrierStage2RetireOutcome> {
        carrick_core::mm::retirement::record_identity_mismatch(record, identity)
    }

    /// Pin the exact live record `identity`; `venue` receives the pin's
    /// release.
    pub fn pin_stage2_record_in<V: RecordPinVenue>(
        &self,
        identity: CarrierStage2RecordIdentity,
        venue: V,
    ) -> Result<RecordPin<V>, CarrierStage2PinError> {
        let mut state = self.state.lock();
        match state.lifecycle {
            VmLifecycle::Live(generation) if generation == identity.vm_generation => {}
            VmLifecycle::Live(_) => {
                return Err(CarrierStage2PinError::VmGenerationMismatch);
            }
            VmLifecycle::Vacant | VmLifecycle::Creating(_) | VmLifecycle::Destroying(_) => {
                return Err(CarrierStage2PinError::VmNotLive);
            }
        }
        let record = state
            .stage2_records
            .get_mut(&identity.record_id)
            .ok_or(CarrierStage2PinError::NotFound)?;
        carrick_core::mm::retirement::pin_record(record, identity, venue)
    }

    /// Release one pin on `identity`. `None` if the record is gone; a
    /// predecessor whose last pin this was is removed here.
    pub fn release_stage2_pin_outcome(
        &self,
        identity: CarrierStage2RecordIdentity,
    ) -> Option<RecordPinRelease> {
        let mut state = self.state.lock();
        let record = state.stage2_records.get_mut(&identity.record_id)?;
        let outcome = carrick_core::mm::retirement::release_record_pin_outcome(record, identity);
        if outcome == RecordPinRelease::RemovePredecessor {
            let _ = state.remove_record(identity.record_id);
        }
        Some(outcome)
    }

    pub fn request_stage2_record_retirement(
        &self,
        identity: CarrierStage2RecordIdentity,
    ) -> CarrierStage2RetireOutcome {
        let mut state = self.state.lock();
        let Some(record) = state.stage2_records.get_mut(&identity.record_id) else {
            return CarrierStage2RetireOutcome::NotFound;
        };
        carrick_core::mm::retirement::request_record_retirement(record, identity)
    }

    pub fn retire_stage2_record_using(
        &self,
        identity: CarrierStage2RecordIdentity,
        unmap: impl FnOnce(u64, usize) -> Result<(), CarrierStage2BackendError>,
    ) -> CarrierStage2RetireOutcome {
        let (ipa, len) = {
            let mut state = self.state.lock();
            let Some(record) = state.stage2_records.get_mut(&identity.record_id) else {
                return CarrierStage2RetireOutcome::NotFound;
            };
            match carrick_core::mm::retirement::prepare_record_retirement(record, identity) {
                carrick_core::mm::retirement::RecordRetirement::Complete(outcome) => {
                    return outcome;
                }
                carrick_core::mm::retirement::RecordRetirement::Unmap { ipa, len } => (ipa, len),
            }
        };

        let backend_result = unmap(ipa, len);
        let mut state = self.state.lock();
        let Some(record) = state.stage2_records.get_mut(&identity.record_id) else {
            return CarrierStage2RetireOutcome::NotFound;
        };
        carrick_core::mm::retirement::settle_record_retirement(record, identity, backend_result)
    }

    /// Retire `identity`, unmapping it through this custody's own backend.
    pub fn retire_stage2_record(
        &self,
        identity: CarrierStage2RecordIdentity,
    ) -> CarrierStage2RetireOutcome {
        self.retire_stage2_record_using(identity, |ipa, len| {
            // No custody lock is held here, so a busy backend is waited out
            // in place: enrol on its release, probe once, rerun.
            let status = super::run_past_busy(self.backend(), || {
                // SAFETY: the custody owns the record and prepared its
                // retirement.
                unsafe { self.backend.unmap(ipa, len) }
            });
            if status.is_success() {
                Ok(())
            } else {
                Err(CarrierStage2BackendError::HvReturn(status.raw()))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_hal::MemPerms;

    #[derive(Default)]
    struct NullStage2;

    impl Stage2Backend for NullStage2 {
        unsafe fn map(
            &self,
            _host: *mut core::ffi::c_void,
            _ipa: u64,
            _size: usize,
            _perms: MemPerms,
        ) -> Stage2Status {
            Stage2Status::SUCCESS
        }

        unsafe fn unmap(&self, _ipa: u64, _size: usize) -> Stage2Status {
            Stage2Status::SUCCESS
        }

        unsafe fn destroy(&self) -> Stage2Status {
            Stage2Status::SUCCESS
        }
    }

    fn live() -> (Stage2Custody, CarrierVmGeneration) {
        let custody = Stage2Custody::new(Arc::new(NullStage2));
        let generation = custody.begin_create().expect("begin create");
        custody
            .commit_create_with(generation, || {})
            .expect("commit create");
        (custody, generation)
    }

    fn spec(generation: CarrierVmGeneration, ipa: u64) -> CarrierStage2RecordSpec {
        CarrierStage2RecordSpec {
            vm_generation: generation,
            ipa,
            len: 0x4000,
            host_addr: 0x1000,
            mapped: true,
            backend_map_installed: true,
            release_ipa: false,
            perms: super::super::STAGE2_PERM_READ,
            logical_owner: None,
        }
    }

    #[test]
    fn generations_only_grow_through_create_and_destroy() {
        let (custody, g1) = live();
        assert_eq!(custody.live_generation(), Some(g1));
        assert_eq!(
            custody.begin_create(),
            Err(Stage2CustodyError::LifecycleConflict)
        );
        custody.begin_destroy(g1).expect("begin destroy");
        custody
            .abort_destroy(g1)
            .expect("a failed destroy restores g1");
        assert_eq!(custody.live_generation(), Some(g1));
        custody.begin_destroy(g1).expect("begin destroy again");
        custody.state.lock().terminalize_generation(g1);
        custody.state.lock().lifecycle = VmLifecycle::Vacant;
        let g2 = custody.begin_create().expect("a successor generation");
        assert!(g2.0 > g1.0);
        assert_eq!(
            custody.commit_create_with(g1, || {}),
            Err(Stage2CustodyError::StaleGeneration)
        );
    }

    #[test]
    fn a_record_is_found_by_extent_until_it_retires() {
        let (custody, generation) = live();
        let identity = custody
            .register_stage2_record(spec(generation, 0x10_0000))
            .expect("admit a record");
        assert_eq!(
            custody.stage2_record_covering(0x10_1000, 0x1000),
            Some(identity)
        );
        assert_eq!(
            custody.retire_stage2_record(identity),
            CarrierStage2RetireOutcome::RetiredUnmapped
        );
        assert_eq!(custody.stage2_record_covering(0x10_1000, 0x1000), None);
    }

    #[test]
    fn a_record_of_a_destroyed_generation_is_refused() {
        let (custody, g1) = live();
        custody.begin_destroy(g1).expect("begin destroy");
        assert_eq!(
            custody.register_stage2_record(spec(g1, 0x20_0000)),
            Err(CarrierStage2RecordError::NoLiveVm)
        );
    }
}
