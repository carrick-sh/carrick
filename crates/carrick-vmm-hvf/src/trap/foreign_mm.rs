//! # Foreign MM Operations and Stage-2 Authority
//!
//! Hypervisor.framework memory transport for cross-process address space access,
//! stage-1 translations for foreign memory inspection, and zero-downtime
//! copy-on-write page-table manipulation during process_vm_readv / process_vm_writev.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use super::*;

/// Carrier-owned index of live HVPatch address spaces available to foreign-MM
/// operations. Entries retain only weak references: the kernel token keeps the
/// MM alive, while backend teardown remains the owner of its access state.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct CarrierForeignMmBinding {
    pub(crate) asid: carrick_hal::ForeignAsid,
    pub(crate) stage1_root: carrick_guest_mem::Gpa,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CarrierForeignMmSnapshot {
    pub(crate) mm: carrick_hal::ForeignMmId,
    pub(crate) binding: CarrierForeignMmBinding,
    pub(crate) backend_revision: carrick_hal::ForeignBackendRevision,
    pub(crate) vma_revision: carrick_hal::ForeignVmaRevision,
    pub(crate) frame_inventory_revision: carrick_hal::ForeignFrameInventoryRevision,
    pub(crate) mapping_ids: Vec<carrick_hal::MappingId>,
    pub(crate) executable_ranges: Vec<carrick_hal::ForeignExecutableRange>,
    pub(crate) readable_ranges: Vec<carrick_hal::ForeignReadableRange>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl CarrierForeignMmSnapshot {
    pub(crate) fn capture(snapshot: &dyn carrick_hal::ForeignMmSnapshot) -> Self {
        Self {
            mm: snapshot.mm(),
            binding: CarrierForeignMmBinding {
                asid: snapshot.binding().asid(),
                stage1_root: snapshot.binding().stage1_root(),
            },
            backend_revision: snapshot.backend_revision(),
            vma_revision: snapshot.vma_revision(),
            frame_inventory_revision: snapshot.frame_inventory_revision(),
            mapping_ids: snapshot.mapping_ids().to_vec(),
            executable_ranges: snapshot.executable_ranges().to_vec(),
            readable_ranges: snapshot.readable_ranges().to_vec(),
        }
    }

    pub(crate) fn matches(&self, snapshot: &dyn carrick_hal::ForeignMmSnapshot) -> bool {
        *self == Self::capture(snapshot)
    }

    pub(crate) fn readable_range(
        &self,
        va: carrick_guest_mem::GuestVa,
    ) -> Option<carrick_hal::ForeignReadableRange> {
        self.readable_ranges
            .iter()
            .copied()
            .find(|range| range.contains(va))
    }

    pub(crate) fn is_readable(&self, va: carrick_guest_mem::GuestVa) -> bool {
        self.readable_range(va).is_some()
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl carrick_hal::ForeignMmSnapshot for CarrierForeignMmSnapshot {
    fn mm(&self) -> carrick_hal::ForeignMmId {
        self.mm
    }
    fn binding(&self) -> carrick_hal::ForeignMmBinding {
        carrick_hal::ForeignMmBinding::for_aarch64(self.binding.asid, self.binding.stage1_root)
    }
    fn backend_revision(&self) -> carrick_hal::ForeignBackendRevision {
        self.backend_revision
    }
    fn vma_revision(&self) -> carrick_hal::ForeignVmaRevision {
        self.vma_revision
    }
    fn frame_inventory_revision(&self) -> carrick_hal::ForeignFrameInventoryRevision {
        self.frame_inventory_revision
    }
    fn mapping_ids(&self) -> &[carrick_hal::MappingId] {
        &self.mapping_ids
    }
    fn executable_ranges(&self) -> &[carrick_hal::ForeignExecutableRange] {
        &self.executable_ranges
    }
    fn readable_ranges(&self) -> &[carrick_hal::ForeignReadableRange] {
        &self.readable_ranges
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Default, Debug)]
pub(crate) struct CarrierForeignMmTransport {
    pub(crate) states: std::sync::Arc<
        parking_lot::RwLock<
            std::collections::HashMap<CarrierForeignMmBinding, std::sync::Weak<MmAccessState>>,
        >,
    >,
    #[allow(dead_code)] // migrated into the VM create/destroy paths in the next custody slice
    pub(crate) custody: std::sync::Arc<CarrierVmCustody>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl CarrierForeignMmTransport {
    pub(crate) fn new() -> Self {
        #[cfg(not(test))]
        {
            Self::default()
        }
        #[cfg(test)]
        {
            Self {
                custody: std::sync::Arc::clone(legacy_test_carrier_vm_custody_arc()),
                ..Self::default()
            }
        }
    }

    #[cfg(any(test, feature = "foreign-cow-test-support"))]
    pub(crate) fn register(
        &self,
        snapshot: &dyn carrick_hal::ForeignMmSnapshot,
        state: &std::sync::Arc<MmAccessState>,
    ) {
        let snapshot = CarrierForeignMmSnapshot::capture(snapshot);
        state.install_identity(snapshot.mm, snapshot.binding);
        self.states
            .write()
            .insert(snapshot.binding, std::sync::Arc::downgrade(state));
    }

    pub(crate) fn register_identity(
        &self,
        mm: carrick_hal::ForeignMmId,
        binding: CarrierForeignMmBinding,
        state: &std::sync::Arc<MmAccessState>,
    ) {
        state.install_identity(mm, binding);
        self.states
            .write()
            .insert(binding, std::sync::Arc::downgrade(state));
    }

    pub(crate) fn register_owned_identity(
        self: &std::sync::Arc<Self>,
        mm: carrick_hal::ForeignMmId,
        binding: CarrierForeignMmBinding,
        state: &std::sync::Arc<MmAccessState>,
    ) -> CarrierForeignMmRegistration {
        self.register_identity(mm, binding, state);
        CarrierForeignMmRegistration {
            transport: std::sync::Arc::clone(self),
            mm,
            binding,
            state: std::sync::Arc::downgrade(state),
        }
    }

    pub(crate) fn unregister_exact(&self, registration: &CarrierForeignMmRegistration) {
        let mut states = self.states.write();
        let exact = states
            .get(&registration.binding)
            .and_then(std::sync::Weak::upgrade)
            .zip(registration.state.upgrade())
            .is_some_and(|(published, owned)| {
                std::sync::Arc::ptr_eq(&published, &owned)
                    && *owned.identity.read() == Some((registration.mm, registration.binding))
            });
        if exact {
            states.remove(&registration.binding);
        }
    }

    pub(crate) fn state_for(
        &self,
        snapshot: &CarrierForeignMmSnapshot,
        deadline: std::time::Instant,
    ) -> Result<std::sync::Arc<MmAccessState>, carrick_hal::ForeignMmTransportError> {
        let states = self
            .states
            .try_read_until(deadline)
            .ok_or(carrick_hal::ForeignMmTransportError::TimedOut)?;
        let state = states
            .get(&snapshot.binding)
            .and_then(std::sync::Weak::upgrade)
            .ok_or(carrick_hal::ForeignMmTransportError::MissingBinding)?;
        drop(states);
        let identity = state
            .identity
            .try_read_until(deadline)
            .ok_or(carrick_hal::ForeignMmTransportError::TimedOut)?;
        if identity.as_ref() != Some(&(snapshot.mm, snapshot.binding)) {
            return Err(carrick_hal::ForeignMmTransportError::MissingBinding);
        }
        drop(identity);
        Ok(state)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct CarrierForeignMmRegistration {
    pub(crate) transport: std::sync::Arc<CarrierForeignMmTransport>,
    pub(crate) mm: carrick_hal::ForeignMmId,
    pub(crate) binding: CarrierForeignMmBinding,
    pub(crate) state: std::sync::Weak<MmAccessState>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for CarrierForeignMmRegistration {
    fn drop(&mut self) {
        self.transport.unregister_exact(self);
        self.transport
            .custody
            .request_global_frame_retirement_retry();
    }
}

/// Shared backend state whose lifetime and identity belong to one Linux MM,
/// never to whichever persistent worker currently executes one of its tasks.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct MmRootStage2Authority {
    pub(crate) root_slot: (u64, u64),
    pub(crate) physical_extent: (u64, usize),
    pub(crate) owner: std::sync::Arc<StructuralBackingOwner>,
    pub(crate) record_identity: CarrierStage2RecordIdentity,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl MmRootStage2Authority {
    pub(crate) fn new(
        root_slot: (u64, u64),
        owner: std::sync::Arc<StructuralBackingOwner>,
    ) -> Result<Self, TrapError> {
        let slot_end = root_slot
            .0
            .checked_add(root_slot.1)
            .ok_or_else(|| TrapError::Hypervisor("stage-1 root slot extent overflow".to_owned()))?;
        let physical_end = owner
            .physical_ipa
            .checked_add(owner.physical_size as u64)
            .ok_or_else(|| {
                TrapError::Hypervisor("stage-1 root physical extent overflow".to_owned())
            })?;
        if root_slot.1 == 0
            || owner.physical_ipa != root_slot.0
            || physical_end > slot_end
            || is_reusable_global_frame_extent(owner.physical_ipa, owner.physical_size as u64)
        {
            return Err(TrapError::Hypervisor(format!(
                "structural page-table authority ({:#x}, {:#x}) does not exactly cover root slot ({:#x}, {:#x})",
                owner.physical_ipa, owner.physical_size, root_slot.0, root_slot.1
            )));
        }
        Ok(Self {
            root_slot,
            physical_extent: (owner.physical_ipa, owner.physical_size),
            record_identity: owner.record_identity(),
            owner,
        })
    }
}

/// Sealed VMM proof that the exact structural stage-2 record covering one
/// reusable stage-1 root slot is terminal. The runtime may authenticate these
/// coordinates against its one-shot allocator ticket; it cannot construct or
/// clone this proof itself.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub struct HvpatchMmRootRetirementProof {
    root_slot: (u64, u64),
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvpatchMmRootRetirementProof {
    pub fn root_slot_base(&self) -> u64 {
        self.root_slot.0
    }

    pub fn root_slot_size(&self) -> u64 {
        self.root_slot.1
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct RetiredMmRootStage2 {
    pub(crate) proof: HvpatchMmRootRetirementProof,
    pub(crate) physical_extent: (u64, usize),
    pub(crate) owner: InventoryStage2OwnerIdentity,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct MmAccessState {
    pub(crate) deferred_anonymous: parking_lot::RwLock<
        Option<(
            carrick_hal::ForeignMmId,
            std::sync::Arc<carrick_guest_mem::DeferredAnonymousState>,
        )>,
    >,
    pub(crate) identity:
        parking_lot::RwLock<Option<(carrick_hal::ForeignMmId, CarrierForeignMmBinding)>>,
    pub(crate) page_tables: parking_lot::RwLock<carrick_aarch64::Stage1Authority>,
    pub(crate) protections: std::sync::Arc<MemoryProtections>,
    pub(crate) frame_inventory: HvpatchFrameInventoryState,
    pub(crate) cow_armed: std::sync::Arc<parking_lot::Mutex<CowArmedRanges>>,
    pub(crate) cow_deferred_publications:
        std::sync::Arc<parking_lot::Mutex<Vec<PendingFrameCowPublication>>>,
    pub(crate) structural_owners: parking_lot::RwLock<
        std::collections::BTreeMap<(u64, usize), std::sync::Arc<StructuralBackingOwner>>,
    >,
    pub(crate) mm_root_stage2: parking_lot::Mutex<Option<MmRootStage2Authority>>,
    pub(crate) mutation_coordinator: parking_lot::Mutex<()>,
    pub(crate) cow_runtime: parking_lot::RwLock<Option<MmCowRuntimeBinding>>,
    pub(crate) cow_rollback_scratch:
        parking_lot::Mutex<Option<crate::page_table::PageTableManager>>,
    #[cfg(test)]
    pub(crate) foreign_cow_failpoint: std::sync::atomic::AtomicU8,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone)]
pub(crate) struct MmCowRuntimeBinding {
    pub(crate) authority: std::sync::Arc<dyn carrick_hal::FrameCowAuthority>,
    pub(crate) identity: carrick_hal::FrameCowIdentity,
    pub(crate) mm_root_slot: Option<(u64, u64)>,
    pub(crate) container_root: ContainerRootToken,
    pub(crate) persistent_vm_lifecycle: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl MmAccessState {
    pub(crate) fn new(
        page_tables: carrick_aarch64::Stage1Authority,
        protections: std::sync::Arc<MemoryProtections>,
        frame_inventory: std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>>,
        cow_armed: std::sync::Arc<parking_lot::Mutex<CowArmedRanges>>,
        cow_deferred_publications: std::sync::Arc<
            parking_lot::Mutex<Vec<PendingFrameCowPublication>>,
        >,
    ) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            identity: parking_lot::RwLock::new(None),
            page_tables: parking_lot::RwLock::new(page_tables),
            protections,
            frame_inventory: HvpatchFrameInventoryState::new(frame_inventory),
            cow_armed,
            cow_deferred_publications,
            structural_owners: parking_lot::RwLock::new(std::collections::BTreeMap::new()),
            mm_root_stage2: parking_lot::Mutex::new(None),
            mutation_coordinator: parking_lot::Mutex::new(()),
            cow_runtime: parking_lot::RwLock::new(None),
            deferred_anonymous: parking_lot::RwLock::new(None),
            cow_rollback_scratch: parking_lot::Mutex::new(None),
            #[cfg(test)]
            foreign_cow_failpoint: std::sync::atomic::AtomicU8::new(0),
        })
    }

    #[cfg(test)]
    pub(crate) fn set_foreign_cow_failpoint(&self, phase: u8) {
        self.foreign_cow_failpoint
            .store(phase, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn for_foreign_read_test(
        binding: CarrierForeignMmBinding,
        page_tables: carrick_aarch64::Stage1Authority,
        protections: std::sync::Arc<MemoryProtections>,
        frame_inventory: std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>>,
        snapshot: &dyn carrick_hal::ForeignMmSnapshot,
    ) -> std::sync::Arc<Self> {
        assert_eq!(
            binding.asid.raw_for_probe(),
            snapshot.binding().asid().raw_for_probe()
        );
        assert_eq!(binding.stage1_root, snapshot.binding().stage1_root());
        let state = Self::new(
            page_tables,
            protections,
            frame_inventory,
            std::sync::Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
            std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
        );
        let snapshot = CarrierForeignMmSnapshot::capture(snapshot);
        state.install_identity(snapshot.mm, snapshot.binding);
        state
    }

    pub(crate) fn install_identity(
        &self,
        mm: carrick_hal::ForeignMmId,
        binding: CarrierForeignMmBinding,
    ) {
        *self.identity.write() = Some((mm, binding));
    }

    pub(crate) fn page_tables_authority(&self) -> carrick_aarch64::Stage1Authority {
        self.page_tables.read().clone()
    }

    pub(crate) fn bind_page_tables_authority(&self, page_tables: carrick_aarch64::Stage1Authority) {
        let previous = {
            let mut slot = self.page_tables.write();
            std::mem::replace(&mut *slot, page_tables.clone())
        };
        page_tables.adopt_unshared_predecessor(&previous);
        if cow_refusal_diagnostics_enabled() && !previous.shares_exact_authority(&page_tables) {
            let old_root = previous.root_base();
            let new_root = page_tables.root_base();
            record_cow_diagnostic_event(CowDiagnosticEvent::PageTableBind {
                mm_access: self as *const Self as usize,
                old_authority: previous.authority_id() as usize,
                new_authority: page_tables.authority_id() as usize,
                old_root,
                new_root,
            });
        }
    }

    pub(crate) fn bind_cow_runtime(&self, binding: MmCowRuntimeBinding) {
        if let Some(state) = binding.authority.deferred_anonymous_state() {
            let mm = carrick_hal::ForeignMmId::from_kernel_allocation(
                std::num::NonZeroU64::new(binding.identity.mm).unwrap_or_else(|| {
                    carrick_fatal!(
                        "hvpatch::deferred_materialization_binding",
                        "COW runtime binding supplied zero MM identity: asid={} tid={}",
                        binding.identity.asid,
                        binding.identity.linux_tid
                    );
                }),
            );
            let mut slot = self.deferred_anonymous.write();
            if slot.as_ref().is_some_and(|(old_mm, old_state)| {
                *old_mm != mm || !std::sync::Arc::ptr_eq(old_state, &state)
            }) {
                carrick_fatal!(
                    "hvpatch::deferred_materialization_binding",
                    "MM access state rebound to different MM or authority while prior binding live: mm={:?} asid={}",
                    mm,
                    binding.identity.asid
                );
            }
            *slot = Some((mm, state));
        }
        crate::probes::hvpatch_cow_runtime_bind(
            binding.identity.mm,
            u32::from(binding.identity.asid),
            std::sync::Arc::as_ptr(&binding.authority) as *const () as u64,
            binding.identity.linux_tid,
            true,
        );
        *self.cow_runtime.write() = Some(binding);
    }

    pub(crate) fn install_structural_owner(&self, owner: std::sync::Arc<StructuralBackingOwner>) {
        let key = (owner.physical_ipa, owner.physical_size);
        self.structural_owners.write().insert(key, owner);
    }

    /// Host pointer of the structural owner published for exactly
    /// `(physical_ipa, physical_size)` — the O(1) lookup for a stage-1
    /// extension arena's backing.
    pub(crate) fn structural_owner_host_ptr(
        &self,
        physical_ipa: u64,
        physical_size: usize,
    ) -> Option<*mut u8> {
        self.structural_owners
            .read()
            .get(&(physical_ipa, physical_size))
            .map(|owner| owner.ptr())
    }

    pub(crate) fn install_mm_root_stage2_authority(
        &self,
        root_slot: (u64, u64),
        owner: std::sync::Arc<StructuralBackingOwner>,
    ) -> Result<(), TrapError> {
        self.install_prepared_mm_root_stage2_authority(MmRootStage2Authority::new(
            root_slot, owner,
        )?)
    }

    pub(crate) fn install_prepared_mm_root_stage2_authority(
        &self,
        candidate: MmRootStage2Authority,
    ) -> Result<(), TrapError> {
        let mut slot = self.mm_root_stage2.lock();
        match slot.as_ref() {
            None => *slot = Some(candidate),
            Some(current)
                if current.root_slot == candidate.root_slot
                    && current.physical_extent == candidate.physical_extent
                    && current.record_identity == candidate.record_identity => {}
            Some(current) => {
                return Err(TrapError::Hypervisor(format!(
                    "stage-1 root structural authority was rebound: current={current:?} candidate={candidate:?}"
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn install_structural_mapping_authority(
        &self,
        root_slot: Option<(u64, u64)>,
        owner: std::sync::Arc<StructuralBackingOwner>,
    ) -> Result<(), TrapError> {
        self.install_structural_owner(std::sync::Arc::clone(&owner));
        if let Some(root_slot) = root_slot
            && owner.physical_ipa == root_slot.0
        {
            self.install_mm_root_stage2_authority(root_slot, owner)?;
        }
        Ok(())
    }

    pub(crate) fn retire_mm_root_stage2_in(
        &self,
        custody: &CarrierVmCustody,
        expected_root_slot: (u64, u64),
    ) -> Result<RetiredMmRootStage2, TrapError> {
        let mut slot = self.mm_root_stage2.lock();
        let authority = slot.as_ref().ok_or_else(|| {
            TrapError::Hypervisor(format!(
                "stage-1 root slot ({:#x}, {:#x}) has no exact structural stage-2 authority",
                expected_root_slot.0, expected_root_slot.1
            ))
        })?;
        if authority.root_slot != expected_root_slot {
            return Err(TrapError::Hypervisor(format!(
                "stage-1 root retirement coordinates mismatch: expected=({:#x}, {:#x}) authority=({:#x}, {:#x})",
                expected_root_slot.0,
                expected_root_slot.1,
                authority.root_slot.0,
                authority.root_slot.1
            )));
        }
        if authority.owner.record_identity() != authority.record_identity
            || (authority.owner.physical_ipa, authority.owner.physical_size)
                != authority.physical_extent
        {
            return Err(TrapError::Hypervisor(
                "stage-1 root structural owner identity drifted before retirement".to_owned(),
            ));
        }

        let copied_bytes = self
            .page_tables
            .read()
            .with_manager(|m| m.copied_bytes())
            .unwrap_or(0);
        authority
            .owner
            .record_populated_prefix(copied_bytes as usize);

        authority
            .owner
            .retained
            .owner_retired
            .store(true, std::sync::atomic::Ordering::Release);
        retry_structural_backing_identities_in_using(
            custody,
            &[authority.record_identity],
            &mut unmap_global_frame_stage2_record,
            &mut release_retired_stage2_ipa,
        )?;
        if let Some(snapshot) = custody.stage2_record_snapshot(authority.record_identity.record_id)
        {
            return Err(TrapError::Hypervisor(format!(
                "stage-1 root structural record remained nonterminal: {snapshot:?}"
            )));
        }

        let authority = slot.take().unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::mm_authority",
                "stage-1 root authority disappeared before retirement completion: root_slot=(0x{:x}, 0x{:x})",
                expected_root_slot.0,
                expected_root_slot.1
            );
        });
        let key = authority.physical_extent;
        let owner = InventoryStage2OwnerIdentity {
            host_addr: authority.owner.ptr() as usize,
            generation: authority.owner.epoch().raw(),
        };
        let mut structural_owners = self.structural_owners.write();
        if structural_owners
            .get(&key)
            .is_some_and(|owner| std::sync::Arc::ptr_eq(owner, &authority.owner))
        {
            structural_owners.remove(&key);
        }
        Ok(RetiredMmRootStage2 {
            proof: HvpatchMmRootRetirementProof {
                root_slot: expected_root_slot,
            },
            physical_extent: key,
            owner,
        })
    }

    pub(crate) fn retain_physical_backing_in(
        &self,
        custody: &std::sync::Arc<CarrierVmCustody>,
        snapshot: &CarrierForeignMmSnapshot,
        deadline: std::time::Instant,
    ) -> Result<RetainedForeignMmBacking, carrick_hal::ForeignMmTransportError> {
        let inventory = self
            .frame_inventory
            .ledger
            .try_lock_until(deadline)
            .ok_or(carrick_hal::ForeignMmTransportError::TimedOut)?;
        let retained_extents: Vec<_> = inventory
            .extents
            .iter()
            .filter(|(_, extent)| snapshot.mapping_ids.contains(&extent.mapping))
            .map(|(&key, extent)| {
                (
                    key,
                    extent.mapping,
                    (extent.stage2_base, extent.stage2_length),
                    extent.stage2_owner,
                )
            })
            .collect();
        drop(inventory);
        let retained_mapping_ids: std::collections::BTreeSet<_> = retained_extents
            .iter()
            .map(|(_, mapping, _, _)| *mapping)
            .collect();
        if snapshot
            .mapping_ids
            .iter()
            .any(|mapping| !retained_mapping_ids.contains(mapping))
        {
            return Err(carrick_hal::ForeignMmTransportError::OwnerStale);
        }
        let global_owners = custody
            .global_frame_host_owners
            .try_lock_until(deadline)
            .ok_or(carrick_hal::ForeignMmTransportError::TimedOut)?;
        let structural_owners = self.structural_owners.read();
        let mut extents = Vec::with_capacity(retained_extents.len());
        for (logical_key, _, owner_key, expected) in retained_extents {
            let logical_end = logical_key
                .0
                .checked_add(logical_key.1)
                .ok_or(carrick_hal::ForeignMmTransportError::OwnerStale)?;
            let owner_end = owner_key
                .0
                .checked_add(owner_key.1)
                .ok_or(carrick_hal::ForeignMmTransportError::OwnerStale)?;
            if logical_key.0 < owner_key.0 || logical_end > owner_end {
                return Err(carrick_hal::ForeignMmTransportError::OwnerStale);
            }
            let owner = if let Some(global) = global_owners
                .get(&owner_key)
                .and_then(GlobalFrameOwnerEntry::live_owner)
                .filter(|owner| {
                    owner.generation() != 0
                        && owner.generation() == expected.generation
                        && owner.host_addr() == expected.host_addr
                        && owner.length() == owner_key.1
                })
                .cloned()
            {
                let pin = global
                    .pin()
                    .map_err(|_| carrick_hal::ForeignMmTransportError::OwnerStale)?;
                RetainedPhysicalOwner::Global(pin)
            } else if let Ok(size) = usize::try_from(owner_key.1)
                && let Some(structural) = structural_owners
                    .get(&(owner_key.0, size))
                    .filter(|owner| {
                        owner.epoch.raw() != 0
                            && owner.epoch.raw() == expected.generation
                            && owner.ptr() as usize == expected.host_addr
                            && owner.len() == size
                    })
                    .cloned()
            {
                RetainedPhysicalOwner::Structural(structural)
            } else {
                return Err(carrick_hal::ForeignMmTransportError::OwnerStale);
            };
            extents.push(RetainedForeignExtent {
                key: owner_key,
                owner,
            });
        }
        Ok(RetainedForeignMmBacking { extents })
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) enum RetainedPhysicalOwner {
    Global(GlobalFrameOwnerPin),
    Structural(std::sync::Arc<StructuralBackingOwner>),
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl RetainedPhysicalOwner {
    pub(crate) fn ptr(&self) -> *mut u8 {
        match self {
            Self::Global(pin) => pin.owner().ptr(),
            Self::Structural(owner) => owner.ptr(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Global(pin) => pin.owner().len(),
            Self::Structural(owner) => owner.len(),
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        match self {
            Self::Global(pin) => pin.owner().generation(),
            Self::Structural(owner) => owner.epoch.raw(),
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct RetainedForeignExtent {
    pub(crate) key: (u64, u64),
    pub(crate) owner: RetainedPhysicalOwner,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct RetainedForeignMmBacking {
    pub(crate) extents: Vec<RetainedForeignExtent>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl RetainedForeignMmBacking {
    pub(crate) fn extent_for(
        &self,
        ipa: u64,
        len: usize,
    ) -> Result<&RetainedForeignExtent, carrick_hal::ForeignMmTransportError> {
        let end = ipa
            .checked_add(len as u64)
            .ok_or(carrick_hal::ForeignMmTransportError::OwnerStale)?;
        self.extents
            .iter()
            .find(|extent| extent.key.0 <= ipa && end <= extent.key.0.saturating_add(extent.key.1))
            .ok_or(carrick_hal::ForeignMmTransportError::OwnerStale)
    }

    #[allow(dead_code)]
    pub(crate) fn read_bytes(
        &self,
        physical_ipa: u64,
        offset: usize,
        buf: &mut [u8],
    ) -> Result<usize, TrapError> {
        let extent = self
            .extent_for(physical_ipa, buf.len())
            .map_err(|_| TrapError::Hypervisor("extent not retained".to_owned()))?;
        if offset
            .checked_add(buf.len())
            .is_some_and(|end| end <= extent.owner.len())
        {
            unsafe {
                let src = extent.owner.ptr().add(offset);
                std::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), buf.len());
            }
            Ok(buf.len())
        } else {
            Err(TrapError::Hypervisor("read_bytes out of bounds".to_owned()))
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn copy_from_pinned_owner(
    backing: &RetainedForeignMmBacking,
    ipa: u64,
    dst: &mut [u8],
) -> Result<carrick_hal::ForeignOwnerGeneration, carrick_hal::ForeignMmTransportError> {
    let extent = backing.extent_for(ipa, dst.len())?;
    let key = extent.key;
    let offset = ipa
        .checked_sub(key.0)
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or(carrick_hal::ForeignMmTransportError::OwnerStale)?;
    let owner = &extent.owner;
    let generation = owner.generation();
    if generation == 0
        || offset
            .checked_add(dst.len())
            .is_none_or(|end| end > owner.len())
    {
        return Err(carrick_hal::ForeignMmTransportError::OwnerStale);
    }
    unsafe {
        std::ptr::copy_nonoverlapping(owner.ptr().add(offset), dst.as_mut_ptr(), dst.len());
    }
    std::num::NonZeroU64::new(generation)
        .map(carrick_hal::ForeignOwnerGeneration::from_backend_counter)
        .ok_or(carrick_hal::ForeignMmTransportError::OwnerStale)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn foreign_stage1_translate(
    backing: &RetainedForeignMmBacking,
    stage1_root: carrick_guest_mem::Gpa,
    va: carrick_guest_mem::GuestVa,
    owner_generations: &mut Vec<carrick_hal::ForeignOwnerGeneration>,
) -> Result<u64, carrick_hal::ForeignMmTransportError> {
    const VALID: u64 = 1;
    const TABLE_OR_PAGE: u64 = 2;
    const ADDRESS_MASK: u64 = 0x0000_ffff_ffff_f000;
    const SHIFTS: [u32; 4] = [39, 30, 21, 12];

    let mut table = stage1_root.raw();
    for (level, shift) in SHIFTS.into_iter().enumerate() {
        let index = (va.raw() >> shift) & 0x1ff;
        let descriptor_ipa = table
            .checked_add(index * 8)
            .ok_or(carrick_hal::ForeignMmTransportError::Translation(va))?;
        let mut bytes = [0_u8; 8];
        owner_generations.push(copy_from_pinned_owner(backing, descriptor_ipa, &mut bytes)?);
        let descriptor = u64::from_le_bytes(bytes);
        if descriptor & VALID == 0 {
            return Err(carrick_hal::ForeignMmTransportError::Translation(va));
        }
        if level == 3 {
            if descriptor & TABLE_OR_PAGE == 0 {
                return Err(carrick_hal::ForeignMmTransportError::Translation(va));
            }
            return Ok((descriptor & ADDRESS_MASK) | (va.raw() & 0xfff));
        }
        if descriptor & TABLE_OR_PAGE != 0 {
            table = descriptor & ADDRESS_MASK;
            continue;
        }
        let block_size = 1_u64 << shift;
        let output = descriptor & ADDRESS_MASK & !(block_size - 1);
        return Ok(output | (va.raw() & (block_size - 1)));
    }
    Err(carrick_hal::ForeignMmTransportError::Translation(va))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct CarrierForeignMmReceipt {
    pub(crate) snapshot: CarrierForeignMmSnapshot,
    pub(crate) bytes_read: usize,
    pub(crate) owner_generations: Vec<carrick_hal::ForeignOwnerGeneration>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct CarrierForeignCowReceipt {
    pub(crate) snapshot: CarrierForeignMmSnapshot,
    pub(crate) start: carrick_guest_mem::GuestVa,
    pub(crate) len: usize,
    pub(crate) mapping: carrick_hal::MappingId,
    pub(crate) frame: carrick_hal::FrameId,
    pub(crate) physical_base: carrick_guest_mem::Gpa,
    pub(crate) physical_len: u64,
    pub(crate) owner_generation: carrick_hal::ForeignOwnerGeneration,
    pub(crate) kernel_proof: carrick_hal::ForeignCowKernelProof,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl carrick_hal::ForeignCowReceipt for CarrierForeignCowReceipt {
    fn mm(&self) -> carrick_hal::ForeignMmId {
        self.snapshot.mm
    }
    fn range_start(&self) -> carrick_guest_mem::GuestVa {
        self.start
    }
    fn range_len(&self) -> usize {
        self.len
    }
    fn backend_revision(&self) -> carrick_hal::ForeignBackendRevision {
        self.snapshot.backend_revision
    }
    fn vma_revision(&self) -> carrick_hal::ForeignVmaRevision {
        self.snapshot.vma_revision
    }
    fn frame_inventory_revision(&self) -> carrick_hal::ForeignFrameInventoryRevision {
        self.snapshot.frame_inventory_revision
    }
    fn mapping(&self) -> carrick_hal::MappingId {
        self.mapping
    }
    fn frame(&self) -> carrick_hal::FrameId {
        self.frame
    }
    fn physical_base(&self) -> carrick_guest_mem::Gpa {
        self.physical_base
    }
    fn physical_len(&self) -> u64 {
        self.physical_len
    }
    fn owner_generation(&self) -> carrick_hal::ForeignOwnerGeneration {
        self.owner_generation
    }
    fn kernel_proof(&self) -> &carrick_hal::ForeignCowKernelProof {
        &self.kernel_proof
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct CarrierForeignWriteReceipt {
    pub(crate) snapshot: CarrierForeignMmSnapshot,
    pub(crate) start: carrick_guest_mem::GuestVa,
    pub(crate) len: usize,
    pub(crate) mapping: carrick_hal::MappingId,
    pub(crate) frame: carrick_hal::FrameId,
    pub(crate) owner_generation: carrick_hal::ForeignOwnerGeneration,
    pub(crate) bytes_written: usize,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl carrick_hal::ForeignMmWriteReceipt for CarrierForeignWriteReceipt {
    fn mm(&self) -> carrick_hal::ForeignMmId {
        self.snapshot.mm
    }
    fn range_start(&self) -> carrick_guest_mem::GuestVa {
        self.start
    }
    fn range_len(&self) -> usize {
        self.len
    }
    fn bytes_written(&self) -> usize {
        self.bytes_written
    }
    fn backend_revision(&self) -> carrick_hal::ForeignBackendRevision {
        self.snapshot.backend_revision
    }
    fn vma_revision(&self) -> carrick_hal::ForeignVmaRevision {
        self.snapshot.vma_revision
    }
    fn frame_inventory_revision(&self) -> carrick_hal::ForeignFrameInventoryRevision {
        self.snapshot.frame_inventory_revision
    }
    fn mapping(&self) -> carrick_hal::MappingId {
        self.mapping
    }
    fn frame(&self) -> carrick_hal::FrameId {
        self.frame
    }
    fn owner_generation(&self) -> carrick_hal::ForeignOwnerGeneration {
        self.owner_generation
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct CarrierForeignPreparedWrite<'a> {
    pub(crate) _owner_pin: GlobalFrameOwnerPin,
    pub(crate) dst_ptr: *mut u8,
    pub(crate) src: &'a [u8],
    pub(crate) receipt: Box<CarrierForeignWriteReceipt>,
    pub(crate) publish_instruction: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl std::fmt::Debug for CarrierForeignPreparedWrite<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CarrierForeignPreparedWrite")
            .field("receipt", &self.receipt)
            .finish_non_exhaustive()
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl carrick_hal::ForeignMmPreparedWrite for CarrierForeignPreparedWrite<'_> {
    fn commit(self: Box<Self>) {
        unsafe {
            std::ptr::copy(self.src.as_ptr(), self.dst_ptr, self.src.len());
            if self.publish_instruction {
                unsafe extern "C" {
                    fn sys_icache_invalidate(start: *mut core::ffi::c_void, len: usize);
                }
                sys_icache_invalidate(self.dst_ptr.cast(), self.src.len());
            }
        }
    }

    fn receipt(&self) -> &dyn carrick_hal::ForeignMmWriteReceipt {
        self.receipt.as_ref()
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl carrick_hal::ForeignMmReadReceipt for CarrierForeignMmReceipt {
    fn bytes_read(&self) -> usize {
        self.bytes_read
    }

    fn owner_generations(&self) -> &[carrick_hal::ForeignOwnerGeneration] {
        &self.owner_generations
    }

    fn authenticates(&self, snapshot: &dyn carrick_hal::ForeignMmSnapshot) -> bool {
        self.snapshot.matches(snapshot)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct CarrierLeaseState {
    pub(crate) retained: CarrierForeignMmSnapshot,
    pub(crate) backing: RetainedForeignMmBacking,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct CarrierForeignMmReadLease {
    pub(crate) custody: std::sync::Arc<CarrierVmCustody>,
    pub(crate) state: std::sync::Arc<MmAccessState>,
    pub(crate) inner: parking_lot::Mutex<CarrierLeaseState>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl std::fmt::Debug for CarrierForeignMmReadLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CarrierForeignMmReadLease")
            .field("retained", &self.inner.lock().retained)
            .finish_non_exhaustive()
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for CarrierForeignMmReadLease {
    fn drop(&mut self) {
        let inner = self.inner.get_mut();
        inner.backing.extents.clear();
        self.custody.request_global_frame_retirement_retry();
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn live_snapshot_matches(
    authority: &dyn carrick_hal::ForeignMmLiveAuthority,
    expected: &CarrierForeignMmSnapshot,
    deadline: std::time::Instant,
) -> Result<bool, carrick_hal::ForeignMmTransportError> {
    if std::time::Instant::now() >= deadline {
        return Err(carrick_hal::ForeignMmTransportError::TimedOut);
    }
    let observed = authority.snapshot(deadline)?;
    Ok(expected.matches(observed.as_ref()))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn foreign_cow_failpoint(
    state: &MmAccessState,
    phase: u8,
) -> Result<(), carrick_hal::ForeignMmTransportError> {
    #[cfg(test)]
    if state
        .foreign_cow_failpoint
        .load(std::sync::atomic::Ordering::SeqCst)
        == phase
    {
        return Err(carrick_hal::ForeignMmTransportError::MutationFailed);
    }
    let _ = (state, phase);
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct ForeignCowTransactionRequest<'a> {
    pub(crate) invocation: &'a carrick_hal::ForeignMmInvocation,
    pub(crate) requested: &'a CarrierForeignMmSnapshot,
    pub(crate) va: carrick_guest_mem::GuestVa,
    pub(crate) len: usize,
    pub(crate) executable: Option<&'a carrick_hal::ForeignPtraceTextCowPlan<'a>>,
    pub(crate) deadline: std::time::Instant,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
/// The IDENTITY foreign-write lane: mint a `CarrierForeignCowReceipt` for a
/// page that is already private to the target mm, without copying, remapping,
/// or touching the frame inventory.
///
/// Safety comes from three live authorities, checked in order: the page's own
/// stage-1 leaf must grant the GUEST user write access (a still-COW-shared
/// page is read-only there, so a `cow_armed` bookkeeping miss can never leak a
/// write into a shared compound), the protection tracker must not deny the
/// range, and the kernel authority must attest that the exact (mapping, frame,
/// physical extent) tuple is live at the caller's snapshot revision with the
/// current host-owner generation. The receipt then flows through the same
/// prepared-write validation as a copied compound.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn attest_foreign_identity_write_receipt(
    lease: &CarrierForeignMmReadLease,
    lease_guard: &mut CarrierLeaseState,
    requested: &CarrierForeignMmSnapshot,
    runtime: &MmCowRuntimeBinding,
    va: carrick_guest_mem::GuestVa,
    len: usize,
    deadline: std::time::Instant,
) -> Result<CarrierForeignCowReceipt, carrick_hal::ForeignMmTransportError> {
    const PAGE: u64 = 0x1000;
    let page_va = va.raw() & !(PAGE - 1);
    let range_end = va
        .raw()
        .checked_add(len as u64)
        .ok_or(carrick_hal::ForeignMmTransportError::MutationFailed)?;
    // Callers chunk writes at 4 KiB page boundaries; a range crossing the page
    // has no single leaf to attest.
    let page_end = page_va
        .checked_add(PAGE)
        .ok_or(carrick_hal::ForeignMmTransportError::MutationFailed)?;
    if range_end > page_end {
        return Err(carrick_hal::ForeignMmTransportError::MutationFailed);
    }
    let page_tables_authority = lease.state.page_tables_authority();
    let (ipa, guest_writable) = page_tables_authority.try_with_manager_until(
        deadline,
        carrick_hal::ForeignMmTransportError::TimedOut,
        carrick_hal::ForeignMmTransportError::AuthorityUnavailable,
        |tables| {
            let ipa = tables
                .translate_retained_output(page_va)
                .ok_or(carrick_hal::ForeignMmTransportError::Translation(va))?;
            // The live leaf's access permissions ARE the guest's own write
            // authority; only user-RW qualifies for the identity lane.
            const AP_MASK: u64 = 0b11 << 6;
            const AP_USER_RW: u64 = 0b01 << 6;
            let leaf = tables.debug_walk(page_va)[3];
            Ok((ipa, leaf & AP_MASK == AP_USER_RW))
        },
    )?;
    if !guest_writable
        || lease
            .state
            .protections
            .range_write_denied(page_va, PAGE as usize)
    {
        return Err(carrick_hal::ForeignMmTransportError::MutationFailed);
    }
    // The receipt references the inventory extent that already CONTAINS the
    // page — ordinary private memory lives in extents of arbitrary size, not
    // the compound-sized splits foreign COW manufactures. The lease must
    // already retain it (it retains every extent the snapshot published).
    let _ = lease_guard.backing.extent_for(ipa, len.max(1))?;
    let (extent_key, mapping, frame, extent_generation) = {
        let inventory = lease
            .state
            .frame_inventory
            .ledger
            .try_lock_until(deadline)
            .ok_or(carrick_hal::ForeignMmTransportError::TimedOut)?;
        let (key, extent) = inventory
            .extents
            .iter()
            .find(|((base, extent_len), _)| {
                ipa >= *base && ipa.checked_sub(*base).is_some_and(|off| off < *extent_len)
            })
            .map(|(key, extent)| (*key, *extent))
            .ok_or(carrick_hal::ForeignMmTransportError::OwnerStale)?;
        (
            key,
            extent.mapping,
            extent.frame,
            extent.stage2_owner.generation,
        )
    };
    lease
        .custody
        .global_frame_host_owners
        .try_lock_until(deadline)
        .ok_or(carrick_hal::ForeignMmTransportError::TimedOut)?
        .get(&extent_key)
        .and_then(GlobalFrameOwnerEntry::live_owner)
        .filter(|owner| owner.generation() == extent_generation && owner.length() == extent_key.1)
        .ok_or(carrick_hal::ForeignMmTransportError::OwnerStale)?;
    let cow_length = carrick_hal::FrameLength::from_mapping_extent(
        std::num::NonZeroU64::new(extent_key.1)
            .ok_or(carrick_hal::ForeignMmTransportError::OwnerStale)?,
    );
    // Statically nonzero: const-evaluated so no runtime failure arm exists.
    const SEMANTIC_LEN: std::num::NonZeroUsize = match std::num::NonZeroUsize::new(PAGE as usize) {
        Some(len) => len,
        None => unreachable!(),
    };
    let semantic_len = SEMANTIC_LEN;
    let (kernel_proof, owner_generation) = runtime
        .authority
        .attest_foreign_identity_write(
            carrick_guest_mem::GuestVa(page_va),
            semantic_len,
            requested.frame_inventory_revision.raw_for_probe(),
            mapping,
            frame,
            carrick_guest_mem::Gpa(extent_key.0),
            cow_length,
        )
        .map_err(|_| carrick_hal::ForeignMmTransportError::MutationFailed)?;
    if owner_generation.raw_for_probe() != extent_generation {
        return Err(carrick_hal::ForeignMmTransportError::OwnerStale);
    }
    Ok(CarrierForeignCowReceipt {
        snapshot: requested.clone(),
        start: carrick_guest_mem::GuestVa(page_va),
        len: PAGE as usize,
        mapping,
        frame,
        physical_base: carrick_guest_mem::Gpa(extent_key.0),
        physical_len: extent_key.1,
        owner_generation,
        kernel_proof,
    })
}

pub(crate) struct ForeignWriteRequest {
    pub va: carrick_guest_mem::GuestVa,
    pub len: usize,
    pub deadline: std::time::Instant,
    pub deferred: std::sync::Arc<carrick_guest_mem::DeferredAnonymousState>,
}

pub(crate) fn materialize_foreign_pristine_write(
    lease: &CarrierForeignMmReadLease,
    lease_guard: &mut CarrierLeaseState,
    invalidator: &mut dyn carrick_hal::ForeignMmInvalidator,
    invocation: &carrick_hal::ForeignMmInvocation,
    requested: &CarrierForeignMmSnapshot,
    request: ForeignWriteRequest,
) -> Result<CarrierForeignCowReceipt, carrick_hal::ForeignMmTransportError> {
    let ForeignWriteRequest {
        va,
        len,
        deadline,
        deferred,
    } = request;
    const PAGE: usize = 4096;
    let start = va.raw() & !(PAGE as u64 - 1);
    let end = start
        .checked_add(PAGE as u64)
        .ok_or(carrick_hal::ForeignMmTransportError::MutationFailed)?;
    if len == 0
        || va
            .raw()
            .checked_add(len as u64)
            .is_none_or(|limit| limit > end)
        || lease.state.protections.range_no_access(start, PAGE)
        || lease.state.protections.range_write_denied(start, PAGE)
        || !deferred.covers_pristine(carrick_guest_mem::GuestVa(start), PAGE)
    {
        return Err(carrick_hal::ForeignMmTransportError::MutationFailed);
    }
    let context = sparse_materialization::PublicationContext::for_foreign(
        lease.state.clone(),
        lease.custody.clone(),
        invocation,
        requested,
        deadline,
    )?;
    let transition = deferred
        .begin_materialization(carrick_guest_mem::GuestVa(start), PAGE)
        .map_err(|_| carrick_hal::ForeignMmTransportError::MutationFailed)?;
    let mut flush = || {
        invalidator
            .invalidate_exact_asid(carrick_hal::ForeignMmSnapshot::binding(requested), deadline)
            .map_err(|error| TrapError::Hypervisor(format!("foreign sparse TLBI: {error:?}")))
    };
    let published = sparse_materialization::publish(
        &context,
        start,
        end,
        SparseExtentBacking::Anon,
        &mut flush,
    )
    .map_err(|_| carrick_hal::ForeignMmTransportError::MutationFailed)?;
    let receipt = published.foreign_receipt.unwrap_or_else(|| {
        carrick_fatal!(
            "hvpatch::foreign_sparse_materialization",
            "foreign sparse publication completed without foreign-MM receipt: va=0x{start:x}"
        );
    });
    let key = (receipt.physical_base.raw(), receipt.physical_len);
    let owner = lease
        .custody
        .global_frame_host_owners
        .lock()
        .get(&key)
        .and_then(GlobalFrameOwnerEntry::live_owner)
        .cloned()
        .unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::foreign_sparse_materialization",
                "anonymous sparse frame disappeared from global owner registry: gpa=0x{:x} len={}",
                key.0,
                key.1
            );
        });
    if owner.generation() != receipt.owner_generation.raw_for_probe() {
        carrick_fatal!(
            "hvpatch::foreign_sparse_materialization",
            "global owner generation mismatch before foreign lease retention: owner_gen={} receipt_gen={} gpa=0x{:x}",
            owner.generation(),
            receipt.owner_generation.raw_for_probe(),
            key.0
        );
    }
    let pin = owner.pin().unwrap_or_else(|error| {
        carrick_fatal!(
            "hvpatch::foreign_sparse_materialization",
            "pinning anonymous sparse owner failed before foreign retention: gpa=0x{:x} error={error:?}",
            key.0
        );
    });
    lease_guard.backing.extents.push(RetainedForeignExtent {
        key,
        owner: RetainedPhysicalOwner::Global(pin),
    });
    for region in published.extension_regions {
        let owner = region.structural_owner.unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::foreign_sparse_materialization",
                "stage-1 extension region lacks structural owner: va=0x{:x} physical_ipa=0x{:x}",
                region.start,
                region.physical_ipa
            );
        });
        lease_guard.backing.extents.push(RetainedForeignExtent {
            key: (owner.physical_ipa, owner.physical_size as u64),
            owner: RetainedPhysicalOwner::Structural(owner),
        });
    }
    lease_guard.retained = receipt.snapshot.clone();
    transition.commit();
    Ok(receipt)
}

pub(crate) fn materialize_foreign_private_file_write(
    lease: &CarrierForeignMmReadLease,
    lease_guard: &mut CarrierLeaseState,
    invalidator: &mut dyn carrick_hal::ForeignMmInvalidator,
    invocation: &carrick_hal::ForeignMmInvocation,
    requested: &CarrierForeignMmSnapshot,
    request: ForeignWriteRequest,
) -> Result<CarrierForeignCowReceipt, carrick_hal::ForeignMmTransportError> {
    let ForeignWriteRequest {
        va,
        len,
        deadline,
        deferred,
    } = request;
    const PAGE: usize = 4096;
    let start = va.raw() & !(PAGE as u64 - 1);
    let end = start
        .checked_add(PAGE as u64)
        .ok_or(carrick_hal::ForeignMmTransportError::MutationFailed)?;
    if len == 0
        || va
            .raw()
            .checked_add(
                u64::try_from(len)
                    .map_err(|_| carrick_hal::ForeignMmTransportError::MutationFailed)?,
            )
            .is_none_or(|limit| limit > end)
        || lease.state.protections.range_no_access(start, PAGE)
        || lease.state.protections.range_write_denied(start, PAGE)
    {
        return Err(carrick_hal::ForeignMmTransportError::MutationFailed);
    }
    let transition = deferred
        .begin_private_file_materialization(va)
        .ok_or(carrick_hal::ForeignMmTransportError::MutationFailed)?;
    let mut page = [0_u8; PAGE];
    transition
        .copy_pristine(carrick_guest_mem::GuestVa(start), &mut page)
        .map_err(|_| carrick_hal::ForeignMmTransportError::MutationFailed)?;
    let context = sparse_materialization::PublicationContext::for_foreign(
        lease.state.clone(),
        lease.custody.clone(),
        invocation,
        requested,
        deadline,
    )?;
    let mut flush = || {
        invalidator
            .invalidate_exact_asid(carrick_hal::ForeignMmSnapshot::binding(requested), deadline)
            .map_err(|error| TrapError::Hypervisor(format!("foreign sparse TLBI: {error:?}")))
    };
    let published = sparse_materialization::publish(
        &context,
        start,
        end,
        SparseExtentBacking::SeededAnon { bytes: &page },
        &mut flush,
    )
    .map_err(|_| carrick_hal::ForeignMmTransportError::MutationFailed)?;
    let receipt = published.foreign_receipt.unwrap_or_else(|| {
        carrick_fatal!(
            "hvpatch::foreign_file_materialization",
            "foreign private-file publication completed without required foreign-MM receipt"
        )
    });
    let key = (receipt.physical_base.raw(), receipt.physical_len);
    let owner = lease
        .custody
        .global_frame_host_owners
        .lock()
        .get(&key)
        .and_then(GlobalFrameOwnerEntry::live_owner)
        .cloned()
        .unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::foreign_file_materialization",
                "newly committed private-file sparse frame disappeared from global owner registry before lease retention"
            )
        });
    if owner.generation() != receipt.owner_generation.raw_for_probe() {
        carrick_fatal!(
            "hvpatch::foreign_file_materialization",
            "global owner generation mismatch for committed private-file sparse receipt"
        );
    }
    let pin = owner.pin().unwrap_or_else(|_| {
        carrick_fatal!(
            "hvpatch::foreign_file_materialization",
            "failed to pin newly committed private-file sparse owner before foreign lease retention"
        )
    });
    lease_guard.backing.extents.push(RetainedForeignExtent {
        key,
        owner: RetainedPhysicalOwner::Global(pin),
    });
    for region in published.extension_regions {
        let owner = region.structural_owner.unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::foreign_file_materialization",
                "stage-1 extension for private-file materialization missing structural owner"
            )
        });
        lease_guard.backing.extents.push(RetainedForeignExtent {
            key: (owner.physical_ipa, owner.physical_size as u64),
            owner: RetainedPhysicalOwner::Structural(owner),
        });
    }
    lease_guard.retained = receipt.snapshot.clone();
    transition
        .commit_range(carrick_guest_mem::GuestVa(start), PAGE)
        .map_err(|_| carrick_hal::ForeignMmTransportError::MutationFailed)?;
    Ok(receipt)
}

pub(crate) fn perform_foreign_cow_transaction(
    lease: &CarrierForeignMmReadLease,
    lease_guard: &mut CarrierLeaseState,
    invalidator: &mut dyn carrick_hal::ForeignMmInvalidator,
    request: ForeignCowTransactionRequest<'_>,
) -> Result<CarrierForeignCowReceipt, carrick_hal::ForeignMmTransportError> {
    let ForeignCowTransactionRequest {
        invocation,
        requested,
        va,
        len,
        executable,
        deadline,
    } = request;
    let executable_span = match executable {
        Some(plan) => Some(
            plan.authenticated_cow_span(requested, va, len)
                .ok_or(carrick_hal::ForeignMmTransportError::MutationFailed)?,
        ),
        None => None,
    };
    let executable_authorized = executable_span.is_some();
    let runtime = lease
        .state
        .cow_runtime
        .try_read_until(deadline)
        .ok_or(carrick_hal::ForeignMmTransportError::TimedOut)?
        .clone()
        .ok_or(carrick_hal::ForeignMmTransportError::AuthorityUnavailable)?;
    if runtime.identity.mm != requested.mm.raw_for_probe()
        || runtime.identity.asid != requested.binding.asid.raw_for_probe()
    {
        return Err(carrick_hal::ForeignMmTransportError::MissingBinding);
    }
    if !runtime.persistent_vm_lifecycle {
        return Err(carrick_hal::ForeignMmTransportError::AuthorityUnavailable);
    }
    // The runtime already holds exact-MM page-table exclusion. Foreign COW
    // must never reacquire the frame-COW quiesce or wait HostAlias -> PtPause.
    let range_end = va
        .raw()
        .checked_add(len as u64)
        .ok_or(carrick_hal::ForeignMmTransportError::MutationFailed)?;
    let span = match executable_span {
        Some((start, len)) => CowArmedSpan {
            va: start.raw(),
            len,
            executable: true,
            kernel_only: false,
        },
        None => match lease.state.cow_armed.lock().span_for(va.raw()) {
            Some(span) => span,
            None => {
                let deferred = lease
                    .state
                    .deferred_anonymous
                    .read()
                    .as_ref()
                    .filter(|(mm, _)| *mm == requested.mm)
                    .map(|(_, state)| std::sync::Arc::clone(state));
                if let Some(deferred) = deferred.as_ref()
                    && deferred.covers_pristine(va, len)
                {
                    return materialize_foreign_pristine_write(
                        lease,
                        lease_guard,
                        invalidator,
                        invocation,
                        requested,
                        ForeignWriteRequest {
                            va,
                            len,
                            deadline,
                            deferred: std::sync::Arc::clone(deferred),
                        },
                    );
                }
                if let Some(deferred) = deferred.as_ref()
                    && deferred.covers_private_file(va, len)
                {
                    return materialize_foreign_private_file_write(
                        lease,
                        lease_guard,
                        invalidator,
                        invocation,
                        requested,
                        ForeignWriteRequest {
                            va,
                            len,
                            deadline,
                            deferred: std::sync::Arc::clone(deferred),
                        },
                    );
                }
                // Not COW-armed: the page is already PRIVATE to this mm — one
                // the target wrote or mapped after fork, so there is nothing
                // to copy. `process_vm_writev` into a forked child's own
                // buffer lands exactly here. Write authority is attested
                // against the live stage-1 translation instead: the identity
                // lane below mints a receipt referencing the EXISTING
                // compound, and the prepared write commits into the live
                // owner pages the guest itself already writes.
                return attest_foreign_identity_write_receipt(
                    lease,
                    lease_guard,
                    requested,
                    &runtime,
                    va,
                    len,
                    deadline,
                );
            }
        },
    };
    let span_end = span
        .va
        .checked_add(span.len as u64)
        .ok_or(carrick_hal::ForeignMmTransportError::MutationFailed)?;
    if range_end > span_end {
        return Err(carrick_hal::ForeignMmTransportError::MutationFailed);
    }
    let page_tables_authority = lease.state.page_tables_authority();
    let old_ipa = page_tables_authority.try_with_manager_until(
        deadline,
        carrick_hal::ForeignMmTransportError::TimedOut,
        carrick_hal::ForeignMmTransportError::AuthorityUnavailable,
        |tables| {
            let old_ipa = tables
                .translate_retained_output(span.va)
                .ok_or(carrick_hal::ForeignMmTransportError::Translation(va))?;
            let old_physical_ipa = align_down(old_ipa, CowArmedRanges::COMPOUND_SIZE);
            let mut source_va = span.va;
            loop {
                let expected_ipa = old_ipa
                    .checked_add(source_va.saturating_sub(span.va))
                    .ok_or(carrick_hal::ForeignMmTransportError::OwnerStale)?;
                let observed_ipa = tables
                    .translate_retained_output(source_va)
                    .ok_or(carrick_hal::ForeignMmTransportError::OwnerStale)?;
                if observed_ipa != expected_ipa
                    || align_down(observed_ipa, CowArmedRanges::COMPOUND_SIZE) != old_physical_ipa
                {
                    return Err(carrick_hal::ForeignMmTransportError::OwnerStale);
                }
                let next_leaf = (source_va & !0xfff_u64)
                    .checked_add(0x1000)
                    .ok_or(carrick_hal::ForeignMmTransportError::OwnerStale)?;
                if next_leaf >= span_end {
                    break;
                }
                source_va = next_leaf;
            }
            Ok(old_ipa)
        },
    )?;
    let old_physical_ipa = align_down(old_ipa, CowArmedRanges::COMPOUND_SIZE);
    let old_extent = lease_guard
        .backing
        .extent_for(old_physical_ipa, CowArmedRanges::COMPOUND_SIZE as usize)?;
    let source_compound_offset = old_physical_ipa
        .checked_sub(old_extent.key.0)
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or(carrick_hal::ForeignMmTransportError::OwnerStale)?;
    let old_host = unsafe { old_extent.owner.ptr().add(source_compound_offset) };
    let old_offset = old_ipa
        .checked_sub(old_physical_ipa)
        .ok_or(carrick_hal::ForeignMmTransportError::MutationFailed)?;
    let source_alias_guest_writable = alias_registry()
        .lock()
        .newest_matching_for_process(runtime.mm_root_slot, runtime.container_root, |alias| {
            let semantic_offset = span.va.checked_sub(alias.start);
            let alias_end = alias.start.checked_add(alias.size as u64);
            alias_matches_process_scope(
                alias.ownership_scope,
                runtime.mm_root_slot,
                runtime.container_root,
            ) && semantic_offset.is_some_and(|offset| {
                offset < alias.size as u64
                    && alias_end.is_some_and(|alias_end| span_end <= alias_end)
                    && alias.ipa.checked_add(offset) == Some(old_ipa)
                    && usize::try_from(offset)
                        .ok()
                        .and_then(|offset| alias.host_addr.checked_add(offset))
                        == usize::try_from(old_offset)
                            .ok()
                            .and_then(|old_offset| (old_host as usize).checked_add(old_offset))
            }) && alias.physical_ipa == old_extent.key.0
                && alias.physical_size as u64 == old_extent.key.1
                && alias.physical_host_addr == old_extent.owner.ptr() as usize
                && alias.owner_generation == old_extent.owner.generation()
        })
        .map(|alias| alias.guest_writable)
        .ok_or(carrick_hal::ForeignMmTransportError::OwnerStale)?;
    let source_guest_writable = source_alias_guest_writable;
    if (!source_guest_writable || lease.state.protections.range_write_denied(va.raw(), len))
        && !executable_authorized
    {
        return Err(carrick_hal::ForeignMmTransportError::MutationFailed);
    }
    let retention_aliases = authenticated_cow_retention_aliases_in(
        &lease.custody,
        runtime.mm_root_slot,
        runtime.container_root,
        old_physical_ipa,
    );
    let retain_old_compound = page_tables_authority.try_with_manager_until(
        deadline,
        carrick_hal::ForeignMmTransportError::TimedOut,
        carrick_hal::ForeignMmTransportError::AuthorityUnavailable,
        |tables| {
            Ok(cow_source_has_retained_projection(
                span,
                old_ipa,
                old_physical_ipa,
                &retention_aliases,
                |candidate| tables.translate_retained_output(candidate),
            ))
        },
    )?;
    let split_shape = {
        let inventory = lease
            .state
            .frame_inventory
            .ledger
            .try_lock_until(deadline)
            .ok_or(carrick_hal::ForeignMmTransportError::TimedOut)?;
        HvfVmState::cow_inventory_split_shape(
            &inventory,
            old_physical_ipa,
            retain_old_compound,
            |frame| {
                runtime.authority.frame_mapping_count(frame).map_err(|_| {
                    TrapError::Hypervisor("query foreign COW mapping count".to_owned())
                })
            },
        )
        .map_err(|_| carrick_hal::ForeignMmTransportError::MutationFailed)?
    };
    let CowInventorySplitShape {
        old_key,
        old,
        fragments,
        retirement,
    } = split_shape;
    let mapping_candidates = fragments.len().saturating_add(1);
    let event_count = 1usize
        .saturating_add(mapping_candidates.saturating_mul(2))
        .saturating_add(usize::from(retirement.retire_old_frame));
    let mut reservation = runtime
        .authority
        .reserve(1, mapping_candidates, event_count)
        .map_err(|_| carrick_hal::ForeignMmTransportError::MutationFailed)?;
    lease_guard.backing.extents.reserve(1);
    foreign_cow_failpoint(&lease.state, 1)?;
    let new_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        CowArmedRanges::COMPOUND_SIZE as usize,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .map_err(|_| carrick_hal::ForeignMmTransportError::MutationFailed)?;
    let new_host_ptr = new_host.as_ptr();
    unsafe {
        std::ptr::copy_nonoverlapping(
            old_host,
            new_host_ptr,
            CowArmedRanges::COMPOUND_SIZE as usize,
        );
    }
    let mut new_lease = GlobalFrameStage2Lease::reserve(
        CowArmedRanges::COMPOUND_SIZE,
        CowArmedRanges::COMPOUND_SIZE,
    )
    .map_err(|_| carrick_hal::ForeignMmTransportError::MutationFailed)?;
    let new_physical_ipa = new_lease.base;
    let new_ipa = new_physical_ipa
        .checked_add(old_offset)
        .ok_or(carrick_hal::ForeignMmTransportError::MutationFailed)?;
    let stage2_perms = applevisor::memory::MemPerms::ReadWriteExec;
    #[cfg(not(any(test, feature = "foreign-cow-test-support")))]
    {
        let map_result = unsafe {
            inventory_hv_vm_map(
                new_host_ptr.cast(),
                new_physical_ipa,
                CowArmedRanges::COMPOUND_SIZE as usize,
                u64::from(stage2_perms),
            )
        };
        if map_result != 0 {
            return Err(carrick_hal::ForeignMmTransportError::MutationFailed);
        }
        new_lease.mark_mapped();
    }
    #[cfg(test)]
    new_lease.mark_test_mapped_without_backend();
    #[cfg(all(not(test), feature = "foreign-cow-test-support"))]
    new_lease.mark_test_mapped_without_backend();
    let owner_generation = register_global_frame_host_owner_in(
        &lease.custody,
        new_lease,
        new_host,
        u64::from(stage2_perms),
    )
    .map_err(|_| carrick_hal::ForeignMmTransportError::MutationFailed)?;
    let mut owner_rollback = GlobalFrameOwnerRollback::new(std::sync::Arc::clone(&lease.custody));
    owner_rollback.record((new_physical_ipa, CowArmedRanges::COMPOUND_SIZE));
    foreign_cow_failpoint(&lease.state, 2)?;
    let backing = HvfVmState::private_backing_identity();
    let split = match HvfVmState::stage_cow_inventory_split(
        &mut reservation,
        old_key,
        old,
        &fragments,
        retirement,
        CowInventoryReplacementStage {
            existing: None,
            gpa: new_physical_ipa,
            backing,
            stage2_owner: InventoryStage2OwnerIdentity {
                host_addr: new_host_ptr as usize,
                generation: owner_generation,
            },
        },
    ) {
        Ok(split) => split,
        Err(_) => return Err(carrick_hal::ForeignMmTransportError::MutationFailed),
    };
    foreign_cow_failpoint(&lease.state, 5)?;
    let page_table_host_ptr = {
        let page_table_extent = lease_guard
            .backing
            .extent_for(requested.binding.stage1_root.raw(), 1)?;
        let offset = usize::try_from(
            requested
                .binding
                .stage1_root
                .raw()
                .saturating_sub(page_table_extent.key.0),
        )
        .map_err(|_| carrick_hal::ForeignMmTransportError::OwnerStale)?;
        unsafe { page_table_extent.owner.ptr().add(offset) }
    };
    let resolve_page_table_host = |base: u64| -> Option<*mut u8> {
        lease_guard
            .backing
            .extent_for(base, carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize)
            .ok()
            .and_then(|extent| {
                let offset = usize::try_from(base.saturating_sub(extent.key.0)).ok()?;
                Some(unsafe { extent.owner.ptr().add(offset) })
            })
            .or_else(|| {
                (base == requested.binding.stage1_root.raw()).then_some(page_table_host_ptr)
            })
    };
    let mut recycled = lease.state.cow_rollback_scratch.lock().take();
    let mut rollback = None;
    let page_table_result = page_tables_authority.try_edit_until(
        deadline,
        carrick_hal::ForeignMmTransportError::TimedOut,
        carrick_hal::ForeignMmTransportError::AuthorityUnavailable,
        || Err(carrick_hal::ForeignMmTransportError::AuthorityUnavailable),
        |tables| {
            rollback = Some(HvfVmState::rollback_pre_image(
                &mut recycled,
                tables.manager,
            ));
            HvfVmState::refresh_stage1_exclusivity(tables.manager);
            tables
                .repoint_preserving_attributes(span.va, new_ipa, span.len as u64)
                .map_err(|_| carrick_hal::ForeignMmTransportError::MutationFailed)?;
            let span_end = span.va.saturating_add(span.len as u64);
            let mut page_va = span.va & !0xfff;
            while page_va < span_end {
                if source_guest_writable && !lease.state.protections.range_write_denied(page_va, 1)
                {
                    tables
                        .set_writable_preserving_attributes(page_va, 0x1000)
                        .map_err(|_| carrick_hal::ForeignMmTransportError::MutationFailed)?;
                } else if executable_authorized {
                    // The repointed leaf keeps the source VMA's execute bit; the
                    // fork arm only withdraws write.
                    tables
                        .set_fork_readonly(page_va, 0x1000)
                        .map_err(|_| carrick_hal::ForeignMmTransportError::MutationFailed)?;
                }
                page_va = page_va.saturating_add(0x1000);
            }
            unsafe { tables.sync_to_host(resolve_page_table_host) }
                .map_err(|_| carrick_hal::ForeignMmTransportError::MutationFailed)?;
            // Authenticate the exact live leaves before the TLBI publishes this
            // foreign COW.  Ptrace text authority permits the host copy; it must
            // never grant the guest write access that the source VMA did not have.
            const PA_MASK_4KIB: u64 = 0x0000_FFFF_FFFF_F000;
            const AP_MASK: u64 = 0b11 << 6;
            const AP_USER_RW: u64 = 0b01 << 6;
            const AP_USER_RO: u64 = 0b11 << 6;
            let pre_image = rollback
                .as_ref()
                .ok_or(carrick_hal::ForeignMmTransportError::MutationFailed)?;
            let mut page_va = span.va & !0xfff;
            while page_va < span_end {
                let shadow = tables.debug_walk(page_va);
                let live = unsafe { tables.debug_walk_host(resolve_page_table_host, page_va) }
                    .map_err(|_| carrick_hal::ForeignMmTransportError::MutationFailed)?;
                let expected_ipa = new_ipa
                    .checked_add(page_va.saturating_sub(span.va))
                    .ok_or(carrick_hal::ForeignMmTransportError::MutationFailed)?;
                let expected_ap = if source_guest_writable
                    && !lease.state.protections.range_write_denied(page_va, 1)
                {
                    AP_USER_RW
                } else if executable_authorized {
                    AP_USER_RO
                } else {
                    pre_image.debug_walk(page_va)[3] & AP_MASK
                };
                if shadow != live
                    || live[3] & PA_MASK_4KIB != expected_ipa & PA_MASK_4KIB
                    || live[3] & AP_MASK != expected_ap
                {
                    return Err(carrick_hal::ForeignMmTransportError::MutationFailed);
                }
                page_va = page_va.saturating_add(0x1000);
            }
            foreign_cow_failpoint(&lease.state, 3)?;
            Ok::<(), carrick_hal::ForeignMmTransportError>(())
        },
    );
    let binding = carrick_hal::ForeignMmBinding::for_aarch64(
        requested.binding.asid,
        requested.binding.stage1_root,
    );
    if let Err(error) = page_table_result {
        if let Some(snapshot) = rollback.take() {
            let recycled_manager = unsafe {
                page_tables_authority.restore_image_and_host(snapshot, 8, resolve_page_table_host)
            };
            *lease.state.cow_rollback_scratch.lock() = recycled_manager.or(recycled);
            if invalidator
                .invalidate_exact_asid(binding, deadline)
                .is_err()
            {
                carrick_fatal!(
                    "hvpatch::mm_authority",
                    "stage-1 TLB invalidation failed during foreign COW page-table error rollback"
                );
            }
        } else {
            *lease.state.cow_rollback_scratch.lock() = recycled;
        }
        return Err(error);
    }
    let rollback = rollback.unwrap_or_else(|| {
        carrick_fatal!(
            "hvpatch::mm_authority",
            "missing page-table rollback pre-image after successful page-table modification"
        )
    });
    if let Err(error) = invalidator.invalidate_exact_asid(binding, deadline) {
        let recycled_manager = unsafe {
            page_tables_authority.restore_image_and_host(rollback, 9, resolve_page_table_host)
        };
        *lease.state.cow_rollback_scratch.lock() = recycled_manager.or(recycled);
        if invalidator
            .invalidate_exact_asid(binding, deadline)
            .is_err()
        {
            carrick_fatal!(
                "hvpatch::mm_authority",
                "stage-1 TLB invalidation failed during foreign COW invalidation-error rollback"
            );
        }
        return Err(error);
    }
    if let Err(error) = foreign_cow_failpoint(&lease.state, 4) {
        let recycled_manager = unsafe {
            page_tables_authority.restore_image_and_host(rollback, 10, resolve_page_table_host)
        };
        *lease.state.cow_rollback_scratch.lock() = recycled_manager.or(recycled);
        if invalidator
            .invalidate_exact_asid(binding, deadline)
            .is_err()
        {
            carrick_fatal!(
                "hvpatch::mm_authority",
                "stage-1 TLB invalidation failed during foreign COW failpoint rollback"
            );
        }
        return Err(error);
    }
    *lease.state.cow_rollback_scratch.lock() = Some(rollback);
    let commit = reservation.commit(());
    let mut committed_mapping_ids = requested.mapping_ids.clone();
    for event in commit.batch().events() {
        match *event {
            carrick_hal::FrameInventoryEvent::UnmapMapping { mapping, .. } => {
                committed_mapping_ids.retain(|candidate| *candidate != mapping);
            }
            carrick_hal::FrameInventoryEvent::PrepareMapping { mapping, .. } => {
                committed_mapping_ids.push(mapping);
            }
            _ => {}
        }
    }
    committed_mapping_ids.sort_unstable();
    committed_mapping_ids.dedup();
    let challenge = commit.receipt_challenge();
    let cow_length = carrick_hal::FrameLength::from_mapping_extent(
        std::num::NonZeroU64::new(CowArmedRanges::COMPOUND_SIZE).unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::frame_inventory",
                "zero compound size constant when constructing foreign COW frame length"
            )
        }),
    );
    let owner_generation_token = std::num::NonZeroU64::new(owner_generation)
        .map(carrick_hal::ForeignOwnerGeneration::from_backend_counter)
        .unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::host_alias",
                "zero owner generation token returned when registering global frame host owner"
            )
        });
    let owner_is_live = lease
        .custody
        .global_frame_host_owners
        .lock()
        .get(&(new_physical_ipa, CowArmedRanges::COMPOUND_SIZE))
        .and_then(GlobalFrameOwnerEntry::live_owner)
        .is_some_and(|owner| {
            owner.generation() == owner_generation && std::ptr::eq(owner.as_ptr(), new_host_ptr)
        });
    if !owner_is_live {
        carrick_fatal!(
            "hvpatch::host_alias",
            "global frame host owner was not found in registry with matching generation and host mapping pointer prior to foreign COW publication"
        );
    }
    let registry = crate::fork_quiesce::FrameRegistryGuard::new(
        crate::fork_quiesce::frame_registry_lock().lock(),
    );
    let (apply_receipt, kernel_proof, authenticated_owner_generation) = match runtime
        .authority
        .apply_foreign_cow(
            commit,
            carrick_guest_mem::GuestVa(span.va),
            std::num::NonZeroUsize::new(span.len).unwrap_or_else(|| {
                carrick_fatal!(
                    "hvpatch::cow_token",
                    "zero length in armed foreign COW span violates non-zero span length invariants"
                )
            }),
            split.new_extent.mapping,
            split.new_extent.frame,
            carrick_guest_mem::Gpa(new_physical_ipa),
            cow_length,
        ) {
        Ok(publication) => publication,
        Err(_error) => {
            let rollback = lease
                .state
                .cow_rollback_scratch
                .lock()
                .take()
                .unwrap_or_else(|| {
                    carrick_fatal!(
                        "hvpatch::mm_authority",
                        "missing rollback pre-image in scratch storage during foreign COW kernel publication failure"
                    )
                });
            let recycled_manager = unsafe {
                page_tables_authority.restore_image_and_host(rollback, 11, resolve_page_table_host)
            };
            *lease.state.cow_rollback_scratch.lock() = recycled_manager;
            if invalidator
                .invalidate_exact_asid(binding, deadline)
                .is_err()
            {
                carrick_fatal!(
                    "hvpatch::mm_authority",
                    "stage-1 TLB invalidation failed during foreign COW publication-error rollback"
                );
            }
            return Err(carrick_hal::ForeignMmTransportError::MutationFailed);
        }
    };
    if authenticated_owner_generation != owner_generation_token {
        carrick_fatal!(
            "hvpatch::host_alias",
            "authenticated owner generation returned from kernel foreign COW publication does not match registered host owner generation token"
        );
    }
    let expected_mm =
        std::num::NonZeroU64::new(requested.mm.raw_for_probe()).unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::mm_authority",
                "zero MM identity in foreign MM request during challenge authentication"
            )
        });
    if !challenge.authenticate_apply(&apply_receipt, expected_mm)
        || !apply_receipt.authorizes(split.new_extent.mapping, split.new_extent.frame)
    {
        carrick_fatal!(
            "hvpatch::frame_inventory",
            "foreign COW apply receipt failed cryptographic challenge authentication or failed to authorize replacement mapping and frame"
        );
    }
    let retired_old_stage2 = {
        let mut inventory = lease.state.frame_inventory.ledger.lock();
        HvfVmState::commit_cow_inventory_split(&mut inventory, &split, || {
            HvfVmState::retire_stage2_extent_from_mappings_in(
                &lease.custody,
                &mut TaskMappingIndex::new(),
                split.old.stage2_base,
                split.old.stage2_length,
            )
        })
        .unwrap_or_else(|_| {
            carrick_fatal!(
                "hvpatch::frame_inventory",
                "committing frame inventory split into carrier ledger failed after kernel publication"
            )
        })
    };
    drop(registry);
    record_cow_inventory_lifecycle(
        CowDiagnosticLifecycleKind::InventoryRemoved,
        CowDiagnosticLifecycleSite::ForeignCowCommit,
        &lease.custody,
        Some(runtime.identity),
        runtime.mm_root_slot,
        span.va,
        span.len as u64,
        split.old_key,
        split.old,
    );
    for fragment in &split.fragments {
        record_cow_inventory_lifecycle(
            CowDiagnosticLifecycleKind::InventoryPublished,
            CowDiagnosticLifecycleSite::ForeignCowCommit,
            &lease.custody,
            Some(runtime.identity),
            runtime.mm_root_slot,
            span.va,
            span.len as u64,
            (fragment.gpa, fragment.length),
            InventoryExtent {
                frame: split.old.frame,
                mapping: fragment.mapping,
                backing: split.old.backing,
                stage2_base: split.old.stage2_base,
                stage2_length: split.old.stage2_length,
                stage2_owner: split.old.stage2_owner,
            },
        );
    }
    record_cow_inventory_lifecycle(
        CowDiagnosticLifecycleKind::InventoryPublished,
        CowDiagnosticLifecycleSite::ForeignCowCommit,
        &lease.custody,
        Some(runtime.identity),
        runtime.mm_root_slot,
        span.va,
        span.len as u64,
        split.new_key,
        split.new_extent,
    );
    if retired_old_stage2 {
        let retired = [RetiredStage2Projection::from(split.old)];
        let cleanup = mutate_known_external_alias_state(
            |_, aliases| retired_projection_mutation_keys(aliases, &retired, &[]),
            |replay, aliases| remove_rows_for_retired_stage2_projections(replay, aliases, &retired),
        );
        for alias in cleanup.removed_aliases {
            record_cow_alias_lifecycle(
                CowDiagnosticLifecycleKind::AliasRemoved,
                CowDiagnosticLifecycleSite::ForeignCowCommit,
                Some(&lease.custody),
                Some(runtime.identity),
                runtime.mm_root_slot,
                alias,
            );
        }
        for alias in cleanup.preserved_reused_aliases {
            record_cow_alias_lifecycle(
                CowDiagnosticLifecycleKind::AliasPreservedReused,
                CowDiagnosticLifecycleSite::ForeignCowCommit,
                Some(&lease.custody),
                Some(runtime.identity),
                runtime.mm_root_slot,
                alias,
            );
        }
    }
    let semantic_host = unsafe { new_host_ptr.add(old_offset as usize) };
    let alias = AliasBacking {
        start: span.va,
        ipa: new_ipa,
        host_addr: semantic_host as usize,
        size: span.len,
        physical_ipa: new_physical_ipa,
        physical_host_addr: new_host_ptr as usize,
        physical_size: CowArmedRanges::COMPOUND_SIZE as usize,
        perms: u64::from(stage2_perms),
        guest_writable: source_guest_writable,
        sharing: GuestMappingSharing::Private,
        ownership_scope: alias_ownership_scope(
            GuestMappingSharing::Private,
            runtime.mm_root_slot,
            runtime.container_root,
        ),
        inventory_backing: backing,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation,
    };
    register_shared_alias(alias);
    record_cow_alias_lifecycle(
        CowDiagnosticLifecycleKind::AliasPublished,
        CowDiagnosticLifecycleSite::ForeignCowCommit,
        Some(&lease.custody),
        Some(runtime.identity),
        runtime.mm_root_slot,
        alias,
    );
    record_alias_revision(
        CowDiagnosticAliasRevisionSite::ForeignCowPublication,
        &lease.custody,
        Some(runtime.identity),
        new_physical_ipa,
        alias_registry().lock().revision(),
    );
    match runtime.authority.mapping_is_live(
        split.new_extent.mapping,
        split.new_extent.frame,
        carrick_guest_mem::Gpa(new_physical_ipa),
        cow_length,
    ) {
        Ok(true) => {}
        Ok(false) | Err(_) => {
            carrick_fatal!(
                "hvpatch::frame_inventory",
                "post-publication verification that replacement mapping is live in kernel authority failed or returned false"
            );
        }
    }
    let owner_is_live = lease
        .custody
        .global_frame_host_owners
        .lock()
        .get(&(new_physical_ipa, CowArmedRanges::COMPOUND_SIZE))
        .and_then(GlobalFrameOwnerEntry::live_owner)
        .is_some_and(|owner| {
            owner.generation() == owner_generation && std::ptr::eq(owner.as_ptr(), new_host_ptr)
        });
    if !owner_is_live {
        carrick_fatal!(
            "hvpatch::host_alias",
            "global frame host owner entry was missing or modified in registry following post-publication verification"
        );
    }
    if !committed_mapping_ids.contains(&split.new_extent.mapping) {
        carrick_fatal!(
            "hvpatch::frame_inventory",
            "committed mapping ID list does not contain replacement mapping after processing reservation commit events"
        );
    }
    owner_rollback.commit();
    lease.state.cow_armed.lock().disarm(span);
    let committed = CarrierForeignMmSnapshot {
        mm: requested.mm,
        binding: requested.binding,
        backend_revision: requested.backend_revision,
        vma_revision: requested.vma_revision,
        frame_inventory_revision: carrick_hal::ForeignFrameInventoryRevision::from_authority_raw(
            apply_receipt.revision(),
        ),
        mapping_ids: committed_mapping_ids,
        executable_ranges: requested.executable_ranges.clone(),
        readable_ranges: requested.readable_ranges.clone(),
    };
    let new_owner_arc = lease
        .custody
        .global_frame_host_owners
        .lock()
        .get(&(new_physical_ipa, CowArmedRanges::COMPOUND_SIZE))
        .and_then(GlobalFrameOwnerEntry::live_owner)
        .cloned()
        .unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::host_alias",
                "failed to retrieve registered global frame host owner when retaining foreign extent for lease guard"
            )
        });
    let new_owner_pin = new_owner_arc.pin().unwrap_or_else(|_| {
        carrick_fatal!(
            "hvpatch::host_alias",
            "pinning newly published global owner failed after inventory and kernel publication committed"
        )
    });
    lease_guard.backing.extents.push(RetainedForeignExtent {
        key: (new_physical_ipa, CowArmedRanges::COMPOUND_SIZE),
        owner: RetainedPhysicalOwner::Global(new_owner_pin),
    });
    lease_guard.retained = committed.clone();
    Ok(CarrierForeignCowReceipt {
        snapshot: committed,
        start: carrick_guest_mem::GuestVa(span.va),
        len: span.len,
        mapping: split.new_extent.mapping,
        frame: split.new_extent.frame,
        physical_base: carrick_guest_mem::Gpa(new_physical_ipa),
        physical_len: CowArmedRanges::COMPOUND_SIZE,
        owner_generation: authenticated_owner_generation,
        kernel_proof,
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl carrick_hal::ForeignMmReadLease for CarrierForeignMmReadLease {
    fn read(
        &self,
        _invocation: &carrick_hal::ForeignMmInvocation,
        authority: &dyn carrick_hal::ForeignMmLiveAuthority,
        snapshot: &dyn carrick_hal::ForeignMmSnapshot,
        va: carrick_guest_mem::GuestVa,
        dst: &mut [u8],
        deadline: std::time::Instant,
    ) -> Result<Box<dyn carrick_hal::ForeignMmReadReceipt>, carrick_hal::ForeignMmTransportError>
    {
        let requested = CarrierForeignMmSnapshot::capture(snapshot);
        let inner = self
            .inner
            .try_lock_until(deadline)
            .ok_or(carrick_hal::ForeignMmTransportError::TimedOut)?;
        if requested != inner.retained {
            let retained = &inner.retained;
            tracing::debug!(
                target: "carrick::foreign_mm",
                mm = requested.mm != retained.mm,
                binding = requested.binding != retained.binding,
                backend_revision = requested.backend_revision != retained.backend_revision,
                vma_revision = requested.vma_revision != retained.vma_revision,
                frame_inventory_revision =
                    requested.frame_inventory_revision != retained.frame_inventory_revision,
                mapping_ids = requested.mapping_ids != retained.mapping_ids,
                executable_ranges = requested.executable_ranges != retained.executable_ranges,
                readable_ranges = requested.readable_ranges != retained.readable_ranges,
                "foreign read lease snapshot drifted from the retained one (fields that differ)"
            );
            return Err(carrick_hal::ForeignMmTransportError::LeaseStale);
        }
        let _read_coordinator = self
            .state
            .mutation_coordinator
            .try_lock_until(deadline)
            .ok_or(carrick_hal::ForeignMmTransportError::TimedOut)?;
        if !live_snapshot_matches(authority, &requested, deadline)? {
            return Err(carrick_hal::ForeignMmTransportError::Retry);
        }
        let mut cursor = va.raw();
        let mut completed = 0_usize;
        let mut owner_generations = Vec::new();
        while completed < dst.len() {
            if !live_snapshot_matches(authority, &requested, deadline)? {
                return Err(carrick_hal::ForeignMmTransportError::Retry);
            }
            let current_va = carrick_guest_mem::GuestVa(cursor);
            let ipa = match foreign_stage1_translate(
                &inner.backing,
                requested.binding.stage1_root,
                current_va,
                &mut owner_generations,
            ) {
                Ok(ipa) => Some(ipa),
                Err(carrick_hal::ForeignMmTransportError::Translation(failed_va)) => {
                    if requested.is_readable(current_va) {
                        None
                    } else {
                        return Err(carrick_hal::ForeignMmTransportError::Translation(failed_va));
                    }
                }
                Err(err) => return Err(err),
            };
            let page_remaining = 0x1000_usize - (current_va.raw() as usize & 0xfff);
            let chunk = match ipa {
                Some(ipa) => {
                    let chunk = page_remaining.min(dst.len() - completed);
                    owner_generations.push(copy_from_pinned_owner(
                        &inner.backing,
                        ipa,
                        &mut dst[completed..completed + chunk],
                    )?);
                    chunk
                }
                None => {
                    let readable_remaining = requested
                        .readable_range(current_va)
                        .map(|range| (range.end().raw() - current_va.raw()) as usize)
                        .unwrap_or(page_remaining);
                    let chunk = page_remaining
                        .min(readable_remaining)
                        .min(dst.len() - completed);
                    let deferred = self
                        .state
                        .deferred_anonymous
                        .read()
                        .as_ref()
                        .filter(|(mm, _)| *mm == requested.mm)
                        .map(|(_, state)| std::sync::Arc::clone(state));
                    let copied_from_deferred = deferred.as_ref().is_some_and(|state| {
                        state
                            .copy_pristine_zero(current_va, &mut dst[completed..completed + chunk])
                            .unwrap_or(false)
                            || state
                                .copy_pristine_file(
                                    current_va,
                                    &mut dst[completed..completed + chunk],
                                )
                                .unwrap_or(false)
                    });
                    if !copied_from_deferred {
                        // Reaching here means: inside a readable VMA, no
                        // stage-1 translation, and no pristine recipe. That
                        // combination is NOT a hole. The anonymous fault
                        // window materializes zeroed backing up to 64 KiB
                        // wide while installing stage-1 only for the page
                        // that faulted, so the rest of the window leaves
                        // `pristine` (it is backed) without gaining a
                        // stage-1 entry (the target has not touched it). A
                        // page in that state has never been written -- a
                        // write would have faulted and installed the entry --
                        // so its bytes are zeros, which is exactly what Linux
                        // reads from an untouched anonymous page. Refusing
                        // instead ended the transfer early and made
                        // `process_vm_readv` return short.
                        //
                        // A retained PRIVATE FILE recipe we could not read is
                        // the one case where zeros would be a lie: that page
                        // has real file bytes behind it, so it still fails.
                        if deferred
                            .as_ref()
                            .is_some_and(|state| state.covers_private_file(current_va, chunk))
                        {
                            return Err(carrick_hal::ForeignMmTransportError::Translation(
                                current_va,
                            ));
                        }
                        dst[completed..completed + chunk].fill(0);
                    }
                    chunk
                }
            };
            if !live_snapshot_matches(authority, &requested, deadline)? {
                return Err(carrick_hal::ForeignMmTransportError::Retry);
            }
            completed += chunk;
            cursor = cursor.checked_add(chunk as u64).ok_or(
                carrick_hal::ForeignMmTransportError::Translation(current_va),
            )?;
        }
        owner_generations.sort_unstable();
        owner_generations.dedup();
        Ok(Box::new(CarrierForeignMmReceipt {
            snapshot: requested,
            bytes_read: completed,
            owner_generations,
        }))
    }

    fn break_cow(
        &self,
        invocation: &carrick_hal::ForeignMmInvocation,
        invalidator: &mut dyn carrick_hal::ForeignMmInvalidator,
        snapshot: &dyn carrick_hal::ForeignMmSnapshot,
        va: carrick_guest_mem::GuestVa,
        len: usize,
        executable: Option<&carrick_hal::ForeignPtraceTextCowPlan>,
        deadline: std::time::Instant,
    ) -> Result<Box<dyn carrick_hal::ForeignCowReceipt>, carrick_hal::ForeignMmTransportError> {
        let requested = CarrierForeignMmSnapshot::capture(snapshot);
        let mut lease_guard = self
            .inner
            .try_lock_until(deadline)
            .ok_or(carrick_hal::ForeignMmTransportError::TimedOut)?;
        if requested != lease_guard.retained {
            return Err(carrick_hal::ForeignMmTransportError::MissingBinding);
        }
        perform_foreign_cow_transaction(
            self,
            &mut lease_guard,
            invalidator,
            ForeignCowTransactionRequest {
                invocation,
                requested: &requested,
                va,
                len,
                executable,
                deadline,
            },
        )
        .map(|receipt| Box::new(receipt) as Box<dyn carrick_hal::ForeignCowReceipt>)
    }

    fn prepare_write<'a>(
        &self,
        _invocation: &carrick_hal::ForeignMmInvocation,
        authority: &dyn carrick_hal::ForeignMmLiveAuthority,
        snapshot: &dyn carrick_hal::ForeignMmSnapshot,
        cow: &dyn carrick_hal::ForeignCowReceipt,
        va: carrick_guest_mem::GuestVa,
        src: &'a [u8],
        publication: &carrick_hal::ForeignInstructionPublicationPlan,
        deadline: std::time::Instant,
    ) -> Result<
        Box<dyn carrick_hal::ForeignMmPreparedWrite + 'a>,
        carrick_hal::ForeignMmTransportError,
    > {
        let requested = CarrierForeignMmSnapshot::capture(snapshot);
        if !publication.authenticates(&requested, va, src.len()) {
            return Err(carrick_hal::ForeignMmTransportError::MutationFailed);
        }
        let publish_instruction = publication.is_required();
        let inner = self
            .inner
            .try_lock_until(deadline)
            .ok_or(carrick_hal::ForeignMmTransportError::TimedOut)?;
        if requested != inner.retained {
            return Err(carrick_hal::ForeignMmTransportError::LeaseStale);
        }
        if !live_snapshot_matches(authority, &requested, deadline)?
            || cow.mm() != requested.mm
            || cow.backend_revision() != requested.backend_revision
            || cow.vma_revision() != requested.vma_revision
            || cow.frame_inventory_revision() != requested.frame_inventory_revision
            || !requested.mapping_ids.contains(&cow.mapping())
            // A COPIED compound is always compound-sized; an IDENTITY receipt
            // names the extent that already contains the page, whatever its
            // size. Both shapes are pinned exactly by the ledger and owner
            // lookups below, so the only degenerate shape to reject here is
            // an empty extent.
            || cow.physical_len() == 0
        {
            return Err(carrick_hal::ForeignMmTransportError::Retry);
        }
        if src.is_empty() {
            return Err(carrick_hal::ForeignMmTransportError::MutationFailed);
        }
        let va_end = va
            .raw()
            .checked_add(src.len() as u64)
            .ok_or(carrick_hal::ForeignMmTransportError::MutationFailed)?;
        let span_end = cow
            .range_start()
            .raw()
            .checked_add(cow.range_len() as u64)
            .ok_or(carrick_hal::ForeignMmTransportError::MutationFailed)?;
        if va.raw() < cow.range_start().raw() || va_end > span_end {
            return Err(carrick_hal::ForeignMmTransportError::MutationFailed);
        }
        let extent_key = (cow.physical_base().raw(), cow.physical_len());
        let expected_generation = cow.owner_generation().raw_for_probe();
        let inventory_extent = {
            let inventory = self
                .state
                .frame_inventory
                .ledger
                .try_lock_until(deadline)
                .ok_or(carrick_hal::ForeignMmTransportError::TimedOut)?;
            inventory
                .extents
                .get(&extent_key)
                .copied()
                .filter(|extent| {
                    extent.mapping == cow.mapping()
                        && extent.frame == cow.frame()
                        && extent.stage2_base == extent_key.0
                        && extent.stage2_length == extent_key.1
                        && extent.stage2_owner.generation == expected_generation
                })
                .ok_or(carrick_hal::ForeignMmTransportError::OwnerStale)?
        };
        let owner = self
            .custody
            .global_frame_host_owners
            .try_lock_until(deadline)
            .ok_or(carrick_hal::ForeignMmTransportError::TimedOut)?
            .get(&extent_key)
            .and_then(GlobalFrameOwnerEntry::live_owner)
            .filter(|owner| {
                owner.generation() == expected_generation
                    && owner.host_addr() == inventory_extent.stage2_owner.host_addr
                    && owner.length() == extent_key.1
            })
            .cloned()
            .ok_or(carrick_hal::ForeignMmTransportError::OwnerStale)?;

        let mut owner_generations = Vec::new();
        let initial_physical = foreign_stage1_translate(
            &inner.backing,
            requested.binding.stage1_root,
            va,
            &mut owner_generations,
        )?;
        let mut cursor = va.raw();
        let mut expected_physical = initial_physical;
        while cursor < va_end {
            let current_va = carrick_guest_mem::GuestVa(cursor);
            let leaf_physical = foreign_stage1_translate(
                &inner.backing,
                requested.binding.stage1_root,
                current_va,
                &mut owner_generations,
            )?;
            if leaf_physical != expected_physical {
                return Err(carrick_hal::ForeignMmTransportError::OwnerStale);
            }
            let bytes_in_page = 0x1000_u64 - (cursor & 0xfff);
            let step = bytes_in_page.min(va_end - cursor);
            cursor = cursor
                .checked_add(step)
                .ok_or(carrick_hal::ForeignMmTransportError::MutationFailed)?;
            expected_physical = expected_physical
                .checked_add(step)
                .ok_or(carrick_hal::ForeignMmTransportError::MutationFailed)?;
        }

        let offset = initial_physical
            .checked_sub(extent_key.0)
            .and_then(|offset| usize::try_from(offset).ok())
            .filter(|offset| {
                offset
                    .checked_add(src.len())
                    .is_some_and(|end| end <= owner.len())
            })
            .ok_or(carrick_hal::ForeignMmTransportError::OwnerStale)?;
        if !live_snapshot_matches(authority, &requested, deadline)?
            || !global_frame_host_owner_matches_in(
                &self.custody,
                extent_key.0,
                extent_key.1,
                owner.host_addr(),
                expected_generation,
            )
        {
            return Err(carrick_hal::ForeignMmTransportError::Retry);
        }
        let owner_pin = owner
            .pin()
            .map_err(|_| carrick_hal::ForeignMmTransportError::Retry)?;
        let dst_ptr = unsafe { owner_pin.owner().as_ptr().add(offset) };
        let receipt = Box::new(CarrierForeignWriteReceipt {
            snapshot: requested,
            start: va,
            len: src.len(),
            mapping: cow.mapping(),
            frame: cow.frame(),
            owner_generation: cow.owner_generation(),
            bytes_written: src.len(),
        });
        Ok(Box::new(CarrierForeignPreparedWrite {
            _owner_pin: owner_pin,
            dst_ptr,
            src,
            receipt,
            publish_instruction,
        }))
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl carrick_hal::ForeignMmTransport for CarrierForeignMmTransport {
    fn retain(
        &self,
        _invocation: &carrick_hal::ForeignMmInvocation,
        snapshot: &dyn carrick_hal::ForeignMmSnapshot,
        deadline: std::time::Instant,
    ) -> Result<
        std::sync::Arc<dyn carrick_hal::ForeignMmReadLease>,
        carrick_hal::ForeignMmTransportError,
    > {
        if std::time::Instant::now() >= deadline {
            return Err(carrick_hal::ForeignMmTransportError::TimedOut);
        }
        let retained = CarrierForeignMmSnapshot::capture(snapshot);
        let state = self.state_for(&retained, deadline)?;
        let backing = state.retain_physical_backing_in(&self.custody, &retained, deadline)?;
        Ok(std::sync::Arc::new(CarrierForeignMmReadLease {
            custody: std::sync::Arc::clone(&self.custody),
            state,
            inner: parking_lot::Mutex::new(CarrierLeaseState { retained, backing }),
        }))
    }
}

/// Test-only composition seam for exercising the production carrier foreign-MM
/// transport from the runtime crate. The harness owns real carrier page tables,
/// physical owners, inventory, alias metadata, and the private transport; the
/// caller must supply kernel-minted mapping/frame identities and the real
/// [`carrick_hal::FrameCowAuthority`].
#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    feature = "foreign-cow-test-support"
))]
pub mod foreign_cow_test_support {
    use super::*;

    pub const TEST_VA: u64 = 0x6000_2000_0000;
    pub const OWNER_LEN: u64 = CowArmedRanges::COMPOUND_SIZE;

    pub struct ProductionCarrierForeignCowCustody {
        custody: std::sync::Arc<CarrierVmCustody>,
    }

    impl ProductionCarrierForeignCowCustody {
        pub fn new() -> Self {
            let custody = std::sync::Arc::new(CarrierVmCustody::new_live_fixture());
            Self { custody }
        }

        pub fn owner_inventory(&self) -> std::sync::Arc<dyn carrick_hal::FrameCowOwnerInventory> {
            carrier_frame_cow_owner_inventory_in(std::sync::Arc::clone(&self.custody))
        }
    }

    impl Default for ProductionCarrierForeignCowCustody {
        fn default() -> Self {
            Self::new()
        }
    }

    #[derive(Clone, Copy, Debug)]
    pub struct InitialInventoryIdentity {
        pub root_mapping: carrick_hal::MappingId,
        pub root_frame: carrick_hal::FrameId,
        pub data_mapping: carrick_hal::MappingId,
        pub data_frame: carrick_hal::FrameId,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct FixtureShape {
        pub stage1_root: carrick_guest_mem::Gpa,
        pub page_table_len: u64,
        pub data_ipa: carrick_guest_mem::Gpa,
        pub data_len: u64,
    }

    impl FixtureShape {
        pub fn new(
            stage1_root: carrick_guest_mem::Gpa,
            data_ipa: carrick_guest_mem::Gpa,
        ) -> Result<Self, String> {
            let tables = make_page_tables(stage1_root, data_ipa)?;
            Ok(Self {
                stage1_root,
                page_table_len: tables.as_bytes().len() as u64,
                data_ipa,
                data_len: OWNER_LEN,
            })
        }
    }

    pub struct ProductionCarrierForeignCowInstallArgs {
        pub shape: FixtureShape,
        pub inventory: InitialInventoryIdentity,
        pub authority: std::sync::Arc<dyn carrick_hal::FrameCowAuthority>,
        pub identity: carrick_hal::FrameCowIdentity,
        pub ordinal: u64,
        pub initial_bytes: [u8; 4],
    }

    pub struct ProductionCarrierForeignCowHarness {
        transport: CarrierForeignMmTransport,
        state: std::sync::Arc<MmAccessState>,
        original_extents: Vec<(u64, u64)>,
    }

    impl ProductionCarrierForeignCowHarness {
        pub fn install(
            custody: ProductionCarrierForeignCowCustody,
            snapshot: &dyn carrick_hal::ForeignMmSnapshot,
            args: ProductionCarrierForeignCowInstallArgs,
        ) -> Result<Self, String> {
            let ProductionCarrierForeignCowInstallArgs {
                shape,
                inventory,
                authority,
                identity,
                ordinal,
                initial_bytes,
            } = args;
            if snapshot.binding().stage1_root() != shape.stage1_root
                || snapshot.mapping_ids().len() != 2
                || !snapshot.mapping_ids().contains(&inventory.root_mapping)
                || !snapshot.mapping_ids().contains(&inventory.data_mapping)
                || identity.mm != snapshot.mm().raw_for_probe()
                || identity.asid != snapshot.binding().asid().raw_for_probe()
            {
                return Err("carrier fixture rejected mismatched kernel snapshot identity".into());
            }
            let tables = make_page_tables(shape.stage1_root, shape.data_ipa)?;
            if tables.as_bytes().len() as u64 != shape.page_table_len {
                return Err("carrier fixture page-table shape changed".into());
            }
            let table_bytes = tables.as_bytes().to_vec();
            let (table_generation, table_host) =
                install_owner(&custody.custody, shape.stage1_root.0, &table_bytes)?;
            let mut data_bytes = vec![0_u8; shape.data_len as usize];
            data_bytes[..initial_bytes.len()].copy_from_slice(&initial_bytes);
            let (data_generation, data_host) =
                install_owner(&custody.custody, shape.data_ipa.0, &data_bytes)?;

            let root_key = (shape.stage1_root.0, shape.page_table_len);
            let data_key = (shape.data_ipa.0, shape.data_len);
            let root_backing = InventoryBackingIdentity::Private(
                ordinal
                    .checked_mul(2)
                    .ok_or_else(|| "carrier fixture backing identity exhausted".to_owned())?,
            );
            let data_backing = InventoryBackingIdentity::Private(
                ordinal
                    .checked_mul(2)
                    .and_then(|value| value.checked_add(1))
                    .ok_or_else(|| "carrier fixture backing identity exhausted".to_owned())?,
            );
            let mut ledger = HvpatchFrameInventory {
                initialized: true,
                ..HvpatchFrameInventory::default()
            };
            ledger.extents.insert(
                root_key,
                InventoryExtent {
                    frame: inventory.root_frame,
                    mapping: inventory.root_mapping,
                    backing: root_backing,
                    stage2_base: root_key.0,
                    stage2_length: root_key.1,
                    stage2_owner: InventoryStage2OwnerIdentity {
                        host_addr: table_host,
                        generation: table_generation,
                    },
                },
            );
            ledger.extents.insert(
                data_key,
                InventoryExtent {
                    frame: inventory.data_frame,
                    mapping: inventory.data_mapping,
                    backing: data_backing,
                    stage2_base: data_key.0,
                    stage2_length: data_key.1,
                    stage2_owner: InventoryStage2OwnerIdentity {
                        host_addr: data_host,
                        generation: data_generation,
                    },
                },
            );
            {
                let mut frames = ledger.frames.lock();
                for (frame, key) in [
                    (inventory.root_frame, root_key),
                    (inventory.data_frame, data_key),
                ] {
                    frames.references.insert(frame, 1);
                    frames.extent_references.insert((frame, key.0, key.1), 1);
                    frames.stage2_references.insert(key, 1);
                }
            }
            let state = MmAccessState::new(
                carrick_aarch64::Stage1Authority::new_with_manager(Some(tables)),
                std::sync::Arc::new(MemoryProtections::default()),
                std::sync::Arc::new(parking_lot::Mutex::new(ledger)),
                std::sync::Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
                std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
            );
            let transport = CarrierForeignMmTransport {
                custody: custody.custody,
                ..CarrierForeignMmTransport::new()
            };
            transport.register(snapshot, &state);
            register_shared_alias(AliasBacking {
                start: TEST_VA,
                ipa: data_key.0,
                host_addr: data_host,
                size: shape.data_len as usize,
                physical_ipa: data_key.0,
                physical_host_addr: data_host,
                physical_size: shape.data_len as usize,
                perms: u64::from(applevisor::memory::MemPerms::ReadWriteExec),
                guest_writable: true,
                sharing: GuestMappingSharing::Private,
                ownership_scope: alias_ownership_scope(
                    GuestMappingSharing::Private,
                    Some(root_key),
                    ContainerRootToken::ROOT,
                ),
                inventory_backing: data_backing,
                shared_key_base: 0,
                shared_key_offset: 0,
                owner_generation: data_generation,
            });
            state
                .cow_armed
                .lock()
                .arm(&[carrick_aarch64::vmm::ForkCowRange {
                    va: TEST_VA,
                    len: shape.data_len as usize,
                    executable: false,
                    kernel_only: false,
                    granule: carrick_aarch64::vmm::CowGranule::Compound,
                }]);
            state.bind_cow_runtime(MmCowRuntimeBinding {
                authority,
                identity,
                mm_root_slot: Some(root_key),
                container_root: ContainerRootToken::ROOT,
                persistent_vm_lifecycle: true,
            });
            Ok(Self {
                transport,
                state,
                original_extents: vec![root_key, data_key],
            })
        }

        pub fn endpoint(&self) -> carrick_hal::ForeignMmEndpoint {
            carrick_hal::ForeignMmEndpoint::for_carrier(std::sync::Arc::new(self.transport.clone()))
        }

        pub fn set_source_guest_writable_for_test(&self, writable: bool) -> Result<(), String> {
            let data_key = self.original_extents[1];
            let mut aliases = alias_registry().lock();
            let updated = aliases.update_newest_matching(
                |alias| {
                    alias.start == TEST_VA
                        && (alias.physical_ipa, alias.physical_size as u64) == data_key
                },
                |alias| {
                    alias.guest_writable = writable;
                    alias.perms = u64::from(if writable {
                        applevisor::memory::MemPerms::ReadWriteExec
                    } else {
                        applevisor::memory::MemPerms::ReadExec
                    });
                },
            );
            if !updated {
                return Err("production carrier source alias is absent".to_owned());
            }
            Ok(())
        }

        pub fn set_source_stage1_writable_for_test(&self) -> Result<(), String> {
            self.state.page_tables_authority().edit(
                || Err("production carrier page tables are absent".to_owned()),
                |editor| {
                    editor
                        .set_writable_preserving_attributes(TEST_VA, 0x1000)
                        .map_err(|error| {
                            format!("make production carrier source leaf writable: {error:?}")
                        })
                        .map(|_| ())
                },
            )
        }

        pub fn source_direct_store_would_fault_for_test(&self) -> Result<bool, String> {
            const AP_MASK: u64 = 0b11 << 6;
            const AP_USER_RW: u64 = 0b01 << 6;
            let leaf = self
                .state
                .page_tables_authority()
                .with_manager(|tables| {
                    carrick_mem::page_table::terminal_descriptor(tables.debug_walk(TEST_VA))
                })
                .ok_or_else(|| "production carrier page tables are absent".to_owned())?;
            Ok(leaf & AP_MASK != AP_USER_RW)
        }

        pub fn source_guest_writable_for_test(&self) -> Result<bool, String> {
            let aliases = alias_registry().lock();
            aliases
                .newest_containing_va(TEST_VA, |alias| alias.start == TEST_VA)
                .map(|alias| alias.guest_writable)
                .ok_or_else(|| "production carrier source alias is absent".to_owned())
        }
    }

    impl Drop for ProductionCarrierForeignCowHarness {
        fn drop(&mut self) {
            let mut extents = self.original_extents.clone();
            extents.extend(
                self.state
                    .frame_inventory
                    .ledger
                    .lock()
                    .extents
                    .keys()
                    .copied(),
            );
            extents.sort_unstable();
            extents.dedup();
            alias_registry().lock().retain(|alias| {
                !extents.contains(&(alias.physical_ipa, alias.physical_size as u64))
            });
            let mut owners = self.transport.custody.global_frame_host_owners.lock();
            for extent in extents {
                owners.remove(&extent);
            }
        }
    }

    fn make_page_tables(
        stage1_root: carrick_guest_mem::Gpa,
        data_ipa: carrick_guest_mem::Gpa,
    ) -> Result<crate::page_table::PageTableManager, String> {
        let mut tables = carrick_mem::page_table::PageTableManager::new(
            carrick_mem::memory::stage1_hvpatch_page_tables(),
            carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
        );
        tables
            .rebase(stage1_root.0, None)
            .map_err(|error| format!("rebase carrier fixture page tables: {error:?}"))?;
        tables
            .map_aliased(TEST_VA, data_ipa.0, OWNER_LEN, false, None)
            .map_err(|error| format!("map carrier fixture COW leaf: {error:?}"))?;
        Ok(tables)
    }

    fn install_owner(
        custody: &std::sync::Arc<CarrierVmCustody>,
        ipa: u64,
        bytes: &[u8],
    ) -> Result<(u64, usize), String> {
        let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            bytes.len(),
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .map_err(|error| format!("map carrier fixture physical owner: {error}"))?;
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), mapping.as_ptr(), bytes.len());
        }
        let host_addr = mapping.as_ptr() as usize;
        let mut lease = GlobalFrameStage2Lease::fixed(ipa, bytes.len() as u64);
        lease.mark_test_mapped_without_backend();
        let generation = register_global_frame_host_owner_in(
            custody,
            lease,
            mapping,
            u64::from(applevisor::memory::MemPerms::ReadWriteExec),
        )
        .map_err(|error| format!("register carrier fixture physical owner: {error}"))?;
        Ok((generation, host_addr))
    }
}

#[cfg(test)]
pub(crate) mod tests;
