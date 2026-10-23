//! Owner-selected fork backing custody. This module accepts physical extents
//! selected by EL1 and never consults guest VMA/protection projections.
use super::*;
use carrick_aarch64::fork::ForkCustody;
use carrick_el1_abi::{PortalForkCustody, PortalForkRequest};
use core::num::NonZeroU64;
use std::sync::Arc;

pub type RetainHostBacking = Arc<
    dyn Fn(NonZeroU64, NonZeroU64) -> Option<Arc<dyn carrick_hal::fork_stock::HostBackingRetention>>
        + Send
        + Sync,
>;

pub struct ForkPhysicalCustody {
    custody: Arc<CarrierVmCustody>,
    source: RetainHostBacking,
}
impl ForkPhysicalCustody {
    pub(crate) fn new(custody: Arc<CarrierVmCustody>, source: RetainHostBacking) -> Self {
        Self { custody, source }
    }
}
/// A pin owns the exact physical record and allocation selected by the owner.
/// No host pointer can outlive its source allocation through this receipt.
pub struct ForkPhysicalRetention {
    selected: PortalForkCustody,
    _frames: Vec<(CarrierStage2Pin, Arc<GlobalFrameSharedMapping>)>,
    _native_owners: Vec<Arc<crate::fork_stock::NativeFrameBacking>>,
    source: Option<Arc<dyn carrick_hal::fork_stock::HostBackingRetention>>,
}
impl core::fmt::Debug for ForkPhysicalRetention {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ForkPhysicalRetention")
            .field("selected", &self.selected)
            .finish_non_exhaustive()
    }
}
impl ForkPhysicalRetention {
    pub fn retained_host_backing(
        &self,
    ) -> Option<Arc<dyn carrick_hal::fork_stock::HostBackingRetention>> {
        self.source.clone()
    }
    pub fn selected(&self) -> PortalForkCustody {
        self.selected
    }
}
type RetainedPhysicalExtent = (
    CarrierStage2Pin,
    Arc<GlobalFrameSharedMapping>,
    CarrierStage2RecordSnapshot,
);

impl ForkPhysicalCustody {
    fn retain_extent(
        &self,
        ipa: u64,
        len: u64,
    ) -> Result<Option<RetainedPhysicalExtent>, TrapError> {
        let Some(end) = ipa.checked_add(len).filter(|_| len != 0) else {
            return Ok(None);
        };
        // EL1 selected a physical IPA, not a guest VA or a carrier-MM alias.
        // The extent authority includes structural roots and arenas; pin its
        // exact VM and logical-owner generation before accessing any bytes.
        let Some(identity) = self.custody.stage2_record_covering(ipa, 1) else {
            return Ok(None);
        };
        let global = self
            .custody
            .global_frame_host_owners
            .lock()
            .range(..=(ipa, u64::MAX))
            .next_back()
            .filter(|((base, length), _)| {
                base.checked_add(*length)
                    .is_some_and(|owner_end| end <= owner_end)
            })
            .and_then(|(_, entry)| entry.live_owner().cloned())
            .filter(|owner| owner.record_identity == identity);
        let mapping = if let Some(owner) = global {
            Some(Arc::clone(&owner.mapping))
        } else {
            self.custody
                .structural_backings
                .lock()
                .get(&identity.record_id)
                .map(|entry| Arc::clone(&entry.mapping))
        };
        let Some(mapping) = mapping else {
            return Ok(None);
        };
        let pin = self.custody.pin_stage2_record(identity).map_err(|_| {
            TrapError::Hypervisor("owner Fork selected retired physical custody".into())
        })?;
        let record = self
            .custody
            .stage2_record_snapshot(identity.record_id)
            .ok_or_else(|| {
                TrapError::Hypervisor(
                    "owner Fork physical record disappeared after retention".into(),
                )
            })?;
        if record.host_addr != mapping.host_base() as usize
            || ipa < record.ipa
            || record
                .ipa
                .checked_add(record.len as u64)
                .is_none_or(|record_end| end > record_end)
        {
            return Ok(None);
        }
        Ok(Some((pin, mapping, record)))
    }
}
impl ForkCustody for ForkPhysicalCustody {
    type Retention = ForkPhysicalRetention;
    fn retain(
        &self,
        request: PortalForkRequest,
        selected: PortalForkCustody,
    ) -> Result<Option<Self::Retention>, TrapError> {
        if request.operation.carrier != self.custody.transfer_carrier {
            return Ok(None);
        }
        match selected {
            PortalForkCustody::HostBacking { handle, generation } => Ok((self.source)(
                handle, generation,
            )
            .map(|source| ForkPhysicalRetention {
                selected,
                _frames: Vec::new(),
                _native_owners: Vec::new(),
                source: Some(source),
            })),
            PortalForkCustody::Frame { ipa, len, .. } => {
                let Some(end) = ipa.checked_add(len).filter(|_| len != 0) else {
                    return Ok(None);
                };
                let mut cursor = ipa;
                let mut frames = Vec::new();
                let mut native_owners = Vec::new();
                while cursor < end {
                    let Some((pin, mapping, record)) = self.retain_extent(cursor, 1)? else {
                        return Ok(None);
                    };
                    let Some(bound) = record.ipa.checked_add(record.len as u64) else {
                        return Ok(None);
                    };
                    if let Some(logical) = record.logical_owner
                        && let Some(owner) = self
                            .custody
                            .native_frame_backings
                            .lock()
                            .get(&(record.ipa, logical.generation))
                            .and_then(std::sync::Weak::upgrade)
                    {
                        native_owners.push(owner);
                    }
                    cursor = bound.min(end);
                    frames.push((pin, mapping));
                }
                Ok(Some(ForkPhysicalRetention {
                    selected,
                    _frames: frames,
                    _native_owners: native_owners,
                    source: None,
                }))
            }
            PortalForkCustody::StructuralCopy {
                source_ipa,
                destination_ipa,
                len,
                executable,
            } => {
                let Some(destination_end) = destination_ipa.checked_add(len) else {
                    return Ok(None);
                };
                let Some(window_end) = request
                    .kernel_control_ipa
                    .checked_add(carrick_mem::memory::LINUX_KERNEL_REGION_SIZE)
                else {
                    return Ok(None);
                };
                if len == 0
                    || len > carrick_mem::memory::LINUX_KERNEL_REGION_SIZE
                    || destination_ipa < request.kernel_control_ipa
                    || destination_end > window_end
                {
                    return Ok(None);
                }
                let Some((source_pin, source_mapping, source_record)) =
                    self.retain_extent(source_ipa, len)?
                else {
                    return Ok(None);
                };
                let Some((destination_pin, destination_mapping, destination_record)) =
                    self.retain_extent(destination_ipa, len)?
                else {
                    return Ok(None);
                };
                if source_record.record_id == destination_record.record_id {
                    return Ok(None);
                }
                let source_offset = usize::try_from(source_ipa - source_record.ipa)
                    .map_err(|_| TrapError::MappingTooLarge(len))?;
                let destination_offset = usize::try_from(destination_ipa - destination_record.ipa)
                    .map_err(|_| TrapError::MappingTooLarge(len))?;
                let len = usize::try_from(len).map_err(|_| TrapError::MappingTooLarge(len))?;
                // SAFETY: two distinct exact physical records and their owned
                // allocations are pinned; both ranges were checked before any
                // pointer arithmetic. The owner selected a bounded control
                // copy into the supplied unpublished destination.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        source_mapping.host_base().add(source_offset),
                        destination_mapping.host_base().add(destination_offset),
                        len,
                    );
                }
                destination_mapping
                    .code_content
                    .mark_icache_dirty(destination_offset, len);
                if executable {
                    self.custody
                        .publish_user_executable(
                            destination_ipa,
                            len as u64,
                            |_, _| None,
                            |_, _| None,
                        )
                        .map_err(|error| {
                            TrapError::Hypervisor(format!(
                                "owner structural executable publication failed: {error:?}"
                            ))
                        })?;
                }
                Ok(Some(ForkPhysicalRetention {
                    selected,
                    source: None,
                    _native_owners: Vec::new(),
                    _frames: vec![
                        (source_pin, source_mapping),
                        (destination_pin, destination_mapping),
                    ],
                }))
            }
        }
    }
}

struct ForkTableResolver {
    owners: Vec<Arc<StructuralBackingOwner>>,
}
// SAFETY: strong structural owners retain each checked physical table extent.
unsafe impl carrick_mmu_core::aarch64::HostArenaResolver for ForkTableResolver {
    fn host_ptr_for_range(&self, base: u64, len: usize) -> Option<*mut u8> {
        self.owners.iter().find_map(|owner| {
            let offset = base.checked_sub(owner.physical_ipa)?;
            let offset = usize::try_from(offset).ok()?;
            (offset.checked_add(len)? <= owner.physical_size)
                .then(|| owner.ptr().wrapping_add(offset))
        })
    }
    fn publish_user_executable(
        &self,
        _output: u64,
        _len: u64,
    ) -> Result<(), carrick_mmu_core::aarch64::PageTableError> {
        Err(carrick_mmu_core::aarch64::PageTableError::GuestOwnsLiveDescriptors)
    }
    fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
        self.host_ptr_for_range(base, 0)
    }
    fn host_const_ptr_for_range(&self, base: u64, len: usize) -> Option<*const u8> {
        self.host_ptr_for_range(base, len)
            .map(|pointer| pointer.cast_const())
    }
    fn host_const_ptr_for_base(&self, base: u64) -> Option<*const u8> {
        self.host_const_ptr_for_range(base, 0)
    }
}

fn inherited_futex_identity(
    backing: InventoryBackingIdentity,
    physical_offset: u64,
) -> Result<(Option<carrick_guest_mem::SharedFutexFileIdentity>, u64), TrapError> {
    match backing {
        InventoryBackingIdentity::SharedFile {
            device,
            inode,
            offset,
            ..
        } => {
            let offset = offset.checked_add(physical_offset).ok_or_else(|| {
                TrapError::Hypervisor("owner fork shared-file offset overflow".into())
            })?;
            Ok((
                Some(carrick_guest_mem::SharedFutexFileIdentity { device, inode }),
                offset,
            ))
        }
        _ => Ok((None, 0)),
    }
}

/// Project owner-selected semantic leaves and their physical inventory custody.
/// Kept separate from carrier publication so the production plan is VM-free.
pub(super) fn project_owner_fork_frames(
    physical: &ForkPhysicalCustody,
    inventory: &parking_lot::Mutex<HvpatchFrameInventory>,
    source_owners: &std::collections::BTreeMap<(u64, usize), Arc<StructuralBackingOwner>>,
    published: &[Arc<StructuralBackingOwner>],
    selected: &[PortalForkCustody],
) -> Result<(Vec<ProcessMappingDesc>, Vec<ProcessInventoryDesc>), TrapError> {
    let mut mappings = Vec::new();
    let mut inventory_mappings = Vec::new();
    let mut inherited = std::collections::BTreeSet::new();
    for custody in selected {
        let PortalForkCustody::Frame {
            va,
            ipa,
            len,
            shared,
        } = *custody
        else {
            continue;
        };
        let end = ipa.checked_add(len).ok_or(TrapError::MappingOverflow {
            guest_start: va,
            mapped_size: len,
        })?;
        let mut cursor = ipa;
        while cursor < end {
            let Some((_, allocation, record)) = physical.retain_extent(cursor, 1)? else {
                return Err(TrapError::Hypervisor(
                    "owner-selected child frame lost exact physical custody".into(),
                ));
            };
            let mut take = (record.ipa + record.len as u64).min(end) - cursor;
            let start = va + (cursor - ipa);
            let perms = applevisor::memory::MemPerms::from(record.perms);
            let source = inventory
                .lock()
                .extents
                .range(..=(cursor, u64::MAX))
                .next_back()
                .filter(|((base, length), _)| {
                    *base <= cursor
                        && base
                            .checked_add(*length)
                            .is_some_and(|bound| cursor < bound)
                })
                .map(|((base, length), extent)| {
                    take = take.min(base + length - cursor);
                    ((*base, *length), *extent)
                });
            // The selection bounds guest access, not physical custody. A 4 KiB
            // leaf can name part of a 16 KiB frame; the child's later COW and
            // exec retirement require the parent's exact inventory extent.
            let (inventory_key, source) = match source {
                Some((key, extent)) => {
                    if key.0 < record.ipa
                        || key
                            .0
                            .checked_add(key.1)
                            .is_none_or(|end| end > record.ipa + record.len as u64)
                        || (extent.stage2_base, extent.stage2_length)
                            != (record.ipa, record.len as u64)
                        || extent.stage2_owner.host_addr != record.host_addr
                        || record
                            .logical_owner
                            .is_none_or(|owner| owner.generation != extent.stage2_owner.generation)
                    {
                        return Err(TrapError::Hypervisor(
                            "owner-selected inventory differs from live physical custody".into(),
                        ));
                    }
                    (key, Some(extent))
                }
                None => ((record.ipa, record.len as u64), None),
            };
            let structural = source_owners
                .get(&(record.ipa, record.len))
                .cloned()
                .or_else(|| {
                    published
                        .iter()
                        .find(|owner| {
                            owner.physical_ipa == record.ipa && owner.physical_size == record.len
                        })
                        .cloned()
                });
            if source.is_none() && structural.is_none() {
                return Err(TrapError::Hypervisor(
                    "owner-selected physical frame has no exact inventory or structural lifetime"
                        .into(),
                ));
            }
            let backing = source
                .map(|entry| entry.backing)
                .unwrap_or_else(HvfVmState::private_backing_identity);
            let owner_generation = structural.as_ref().map_or(
                source.map_or(0, |entry| entry.stage2_owner.generation),
                |owner| owner.epoch().raw(),
            );
            let physical_offset = cursor
                .checked_sub(source.map_or(record.ipa, |entry| entry.stage2_base))
                .ok_or_else(|| {
                    TrapError::Hypervisor("owner fork physical offset underflow".into())
                })?;
            let (shared_key_base, shared_key_offset) =
                inherited_futex_identity(backing, physical_offset)?;
            mappings.push(ProcessMappingDesc {
                start,
                ipa: cursor,
                end: start + take,
                host: ProcessMappingHost::Borrowed {
                    pointer: allocation.host_base(),
                    structural_owner: structural,
                },
                size: take as usize,
                physical_ipa: record.ipa,
                physical_host_addr: allocation.host_base(),
                physical_size: record.len,
                inventory_backing: backing,
                perms,
                is_dynamic_alias: source.is_some(),
                sharing: if shared {
                    GuestMappingSharing::GlobalShared
                } else {
                    GuestMappingSharing::Private
                },
                guest_writable: false,
                inherited_frame: source.map(|entry| entry.frame),
                stage2_lease: None,
                shared_key_base,
                shared_key_offset,
                owner_generation,
            });
            if inherited.insert(inventory_key) {
                inventory_mappings.push(ProcessInventoryDesc {
                    gpa: inventory_key.0,
                    length: inventory_key.1,
                    permissions: carrick_hal::MemPerms {
                        read: record.perms & 1 != 0,
                        write: record.perms & 2 != 0,
                        exec: record.perms & 4 != 0,
                    },
                    inherited_frame: source.map(|entry| entry.frame),
                    inherited_mapping: source.map(|entry| entry.mapping),
                    backing,
                    stage2_lease: (record.ipa, record.len as u64),
                    stage2_owner: InventoryStage2OwnerIdentity {
                        host_addr: record.host_addr,
                        generation: owner_generation,
                    },
                    fork_frame_receipt_kind: None,
                });
            }
            cursor += take;
        }
    }
    Ok((mappings, inventory_mappings))
}

pub(crate) struct OwnerPhysicalForkBuilder {
    physical: ForkPhysicalCustody,
    state: Arc<MmAccessState>,
    tables: carrick_el1_abi::PortalForkTableArena,
    control: u64,
    published: Vec<Arc<StructuralBackingOwner>>,
    source_owners: std::collections::BTreeMap<(u64, usize), Arc<StructuralBackingOwner>>,
    inventory: Arc<parking_lot::Mutex<HvpatchFrameInventory>>,
    mailbox_slots: Arc<MailboxSlotAllocator>,
    syscall_transport: HvfSyscallTransport,
    transport: Arc<CarrierForeignMmTransport>,
    vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
    container_root: ContainerRootToken,
    persistent: bool,
    settled: bool,
}
// SAFETY: like ProcessSpec, this owns physical allocations and carrier VM
// lifetime; its pointers are resolved through retained structural owners.
unsafe impl Send for OwnerPhysicalForkBuilder {}
impl ForkCustody for OwnerPhysicalForkBuilder {
    type Retention = Box<dyn Send>;
    fn retain(
        &self,
        request: PortalForkRequest,
        selected: PortalForkCustody,
    ) -> Result<Option<Self::Retention>, TrapError> {
        self.physical
            .retain(request, selected)
            .map(|pin| pin.map(|pin| Box::new(pin) as Box<dyn Send>))
    }
}
impl carrick_aarch64::fork::PhysicalForkBuilder<ProcessSpec> for OwnerPhysicalForkBuilder {
    fn child_tables(&self) -> carrick_el1_abi::PortalForkTableArena {
        self.tables
    }
    fn kernel_control_ipa(&self) -> u64 {
        self.control
    }
    fn carrier(&self) -> NonZeroU64 {
        self.physical.custody.transfer_carrier
    }
    fn child_resolver(
        &self,
    ) -> Arc<dyn carrick_mmu_core::aarch64::HostArenaResolver + Send + Sync> {
        Arc::new(ForkTableResolver {
            owners: self.published.clone(),
        })
    }
    fn consume_owner_fork_completion(
        &mut self,
        request: &carrick_hal::ProcessForkRequest,
        completion: carrick_el1_abi::PortalForkCompletion,
        selected: &[PortalForkCustody],
    ) -> Result<ProcessSpec, TrapError> {
        if completion.request.child_tables != self.tables
            || completion.request.kernel_control_ipa != self.control
            || completion.request.child_mm.raw() != request.plan.child_mm()
            || completion.request.operation.mm.raw() != request.plan.parent_mm()
        {
            return Err(TrapError::Hypervisor(
                "physical Fork completion identity differs from prepared capacity".into(),
            ));
        }
        let (mut mappings, mut inventory_mappings) = project_owner_fork_frames(
            &self.physical,
            &self.inventory,
            &self.source_owners,
            &self.published,
            selected,
        )?;
        // Table and control capacities have no host semantic projection. Their
        // fixed carrier aliases were substituted by the owner itself.
        for owner in &self.published {
            if mappings
                .iter()
                .any(|row| row.physical_ipa == owner.physical_ipa)
            {
                continue;
            }
            let pointer = owner.ptr();
            let backing = HvfVmState::private_backing_identity();
            let generation = owner.epoch().raw();
            mappings.push(ProcessMappingDesc {
                start: owner.physical_ipa,
                ipa: owner.physical_ipa,
                end: owner.physical_ipa + owner.physical_size as u64,
                host: ProcessMappingHost::Borrowed {
                    pointer,
                    structural_owner: Some(owner.clone()),
                },
                size: owner.physical_size,
                physical_ipa: owner.physical_ipa,
                physical_host_addr: pointer,
                physical_size: owner.physical_size,
                inventory_backing: backing,
                perms: applevisor::memory::MemPerms::ReadWriteExec,
                is_dynamic_alias: false,
                sharing: GuestMappingSharing::Private,
                guest_writable: false,
                inherited_frame: None,
                stage2_lease: None,
                shared_key_base: None,
                shared_key_offset: 0,
                owner_generation: generation,
            });
            inventory_mappings.push(ProcessInventoryDesc {
                gpa: owner.physical_ipa,
                length: owner.physical_size as u64,
                permissions: carrick_hal::MemPerms {
                    read: true,
                    write: true,
                    exec: true,
                },
                inherited_frame: None,
                inherited_mapping: None,
                backing,
                stage2_lease: (owner.physical_ipa, owner.physical_size as u64),
                stage2_owner: InventoryStage2OwnerIdentity {
                    host_addr: pointer as usize,
                    generation,
                },
                fork_frame_receipt_kind: None,
            });
        }
        let frame_inventory = {
            let mut parent = self.inventory.lock();
            let mut child = HvpatchFrameInventory::with_frames(Arc::clone(&parent.frames));
            child.process_reservation = parent.process_reservation.take();
            Arc::new(parking_lot::Mutex::new(child))
        };
        let plan = ProcessSpecPlan::new(
            mappings,
            inventory_mappings,
            ProcessSpecPlanContext {
                protections: carrick_guest_mem::UserMemoryAuthority::from_owner(completion.child),
                mailbox_slots: self.mailbox_slots.clone(),
                syscall_transport: self.syscall_transport,
                persistent_vm_lifecycle: self.persistent,
                mm_root_slot: (request.root_slot_base, request.root_slot_size),
                container_root: self.container_root,
                frame_inventory,
                cow_armed: Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
                carrier_foreign_mm_transport: self.transport.clone(),
            },
        );
        Ok(ProcessSpec::new(self.vm.clone(), plan))
    }
    fn settle(mut self: Box<Self>, committed: bool) -> Result<(), TrapError> {
        for owner in &self.published {
            if !committed {
                // Physical retirement is exact and precedes logical slot return.
                let identity = *owner.retained.record_identity.lock();
                retire_carrier_stage2_record_at_safe_point(&self.physical.custody, identity)?;
            }
            self.state
                .structural_owners
                .write()
                .remove(&(owner.physical_ipa, owner.physical_size));
        }
        self.settled = true;
        Ok(())
    }
}
impl Drop for OwnerPhysicalForkBuilder {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        for owner in &self.published {
            retire_carrier_stage2_record_at_safe_point(
                &self.physical.custody,
                owner.record_identity(),
            )
            .unwrap_or_else(|error| {
                carrick_fatal::carrick_fatal!(
                    "hvpatch::stage2_lifecycle",
                    "unpublished owner Fork capacity retirement failed: {error}"
                );
            });
            self.state
                .release_structural_owner_at(owner.physical_ipa, owner.physical_size);
        }
    }
}

impl HvfVmState {
    pub(crate) fn prepare_owner_fork_builder(
        &self,
        request: &mut carrick_hal::ProcessForkRequest,
    ) -> Result<Box<dyn carrick_aarch64::fork::PhysicalForkBuilder<ProcessSpec>>, TrapError> {
        const ARENA: u64 = 2 * 1024 * 1024;
        let root = request.child_ttbr0 & 0x0000_ffff_ffff_f000;
        let slot_end = request
            .root_slot_base
            .checked_add(request.root_slot_size)
            .ok_or(TrapError::MappingOverflow {
                guest_start: request.root_slot_base,
                mapped_size: request.root_slot_size,
            })?;
        if request.shares_mm()
            || request.root_slot_size != ARENA
            || !request.root_slot_base.is_multiple_of(ARENA)
            || root < request.root_slot_base
            || root >= slot_end
        {
            return Err(TrapError::Hypervisor(
                "owner child physical root capacity is invalid".into(),
            ));
        }
        let source = request.table_arena_source.as_mut().ok_or_else(|| {
            TrapError::Hypervisor("owner child has no physical arena source".into())
        })?;
        let control = source
            .take_arena()
            .ok_or_else(|| {
                TrapError::Hypervisor("owner child control physical capacity exhausted".into())
            })?
            .0;
        let state = self.task.mm_access_authority();
        let runtime = state.cow_runtime.read().clone().ok_or_else(|| {
            TrapError::Hypervisor("owner parent source custody is unbound".into())
        })?;
        let custody = self.carrier_vm_custody();
        let mut raw = Vec::new();
        if let Err(error) = state.publish_raw_stage1_arenas_into(
            &custody,
            &[request.root_slot_base, control],
            applevisor::memory::MemPerms::ReadWriteExec,
            &mut raw,
        ) {
            for region in &raw {
                if let Some(owner) = &region.structural_owner {
                    retire_carrier_stage2_record_at_safe_point(&custody, owner.record_identity())?;
                }
                state.release_structural_owner_at(region.physical_ipa, region.physical_size);
            }
            source.return_arena(carrick_mmu_core::aarch64::SubstrateGpa(control));
            return Err(error);
        }
        let published = raw
            .iter()
            .filter_map(|region| region.structural_owner.clone())
            .collect::<Vec<_>>();
        if published.len() != 2 {
            for region in &raw {
                if let Some(owner) = &region.structural_owner {
                    retire_carrier_stage2_record_at_safe_point(&custody, owner.record_identity())?;
                }
                state.release_structural_owner_at(region.physical_ipa, region.physical_size);
            }
            source.return_arena(carrick_mmu_core::aarch64::SubstrateGpa(control));
            return Err(TrapError::Hypervisor(
                "owner child physical capacity was already published".into(),
            ));
        }
        let authority = runtime.authority;
        let physical = ForkPhysicalCustody::new(
            custody,
            Arc::new(move |handle, generation| authority.retain_host_backing(handle, generation)),
        );
        let source_owners = state.structural_owners.read().clone();
        Ok(Box::new(OwnerPhysicalForkBuilder {
            physical,
            state,
            tables: carrick_el1_abi::PortalForkTableArena::new(root, slot_end - root).ok_or_else(
                || TrapError::Hypervisor("owner child table capacity is malformed".into()),
            )?,
            control,
            published,
            source_owners,
            inventory: self.task.frame_inventory.shared_ledger(),
            mailbox_slots: Arc::clone(&self.mailbox_slots),
            syscall_transport: self.syscall_transport,
            transport: Arc::clone(&self.carrier_foreign_mm_transport),
            vm: (*self._vm).clone(),
            container_root: self.task.container_root,
            persistent: self.task.persistent_vm_lifecycle,
            settled: false,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owner_fork_retains_file_futex_identity_across_physical_slices() {
        let backing = InventoryBackingIdentity::SharedFile {
            device: 71,
            inode: 72,
            offset: 0x8000,
            length: 0x4000,
        };
        let (identity, offset) = inherited_futex_identity(backing, 0x104).unwrap();
        let expected = carrick_guest_mem::SharedFutexFileIdentity {
            device: 71,
            inode: 72,
        };
        assert_eq!(identity, Some(expected));
        assert_eq!(offset, 0x8104);
        let shifted = InventoryBackingIdentity::SharedFile {
            device: 71,
            inode: 72,
            offset: 0x8100,
            length: 0x100,
        };
        assert_eq!(
            inherited_futex_identity(shifted, 4).unwrap(),
            (identity, offset)
        );
        assert_eq!(
            inherited_futex_identity(InventoryBackingIdentity::SharedAnon(71), 0x104).unwrap(),
            (None, 0)
        );
        let overflow = InventoryBackingIdentity::SharedFile {
            device: 71,
            inode: 72,
            offset: u64::MAX,
            length: 4,
        };
        assert!(inherited_futex_identity(overflow, 1).is_err());
    }

    #[test]
    fn owner_fork_shared_leaves_inherit_one_exact_extent_and_keep_file_offsets() {
        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let custody = Arc::new(CarrierVmCustody::new_live_fixture());
        let ipa = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x200_0000;
        let len = CowArmedRanges::COMPOUND_SIZE;
        let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            len as usize,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .unwrap();
        let pointer = host.as_ptr() as usize;
        let mut lease = GlobalFrameStage2Lease::fixed(ipa, len);
        lease.mark_test_mapped_without_backend();
        let generation = register_global_frame_host_owner_in(
            &custody,
            lease,
            host,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .unwrap();
        let frame = carrick_hal::FrameId::from_kernel_allocation(NonZeroU64::new(1).unwrap());
        let mapping = carrick_hal::MappingId::from_kernel_allocation(NonZeroU64::new(2).unwrap());
        let extent = InventoryExtent {
            frame,
            mapping,
            backing: InventoryBackingIdentity::SharedFile {
                device: 71,
                inode: 72,
                offset: 0x8000,
                length: len,
            },
            stage2_base: ipa,
            stage2_length: len,
            stage2_owner: InventoryStage2OwnerIdentity {
                host_addr: pointer,
                generation,
            },
        };
        let mut inventory = HvpatchFrameInventory::default();
        inventory.extents.insert((ipa, len), extent);
        let inventory = parking_lot::Mutex::new(inventory);
        let physical = ForkPhysicalCustody::new(custody.clone(), Arc::new(|_, _| None));
        let selected = [
            PortalForkCustody::Frame {
                va: 0x7000,
                ipa,
                len: 4096,
                shared: true,
            },
            PortalForkCustody::Frame {
                va: 0xa000,
                ipa: ipa + 0x2000,
                len: 4096,
                shared: true,
            },
        ];
        let (semantic, inherited) =
            project_owner_fork_frames(&physical, &inventory, &Default::default(), &[], &selected)
                .unwrap();
        assert_eq!(semantic.len(), 2);
        assert_eq!(semantic.iter().map(|row| row.size).sum::<usize>(), 8192);
        assert!(
            semantic
                .iter()
                .all(|row| row.sharing == GuestMappingSharing::GlobalShared)
        );
        assert_eq!(semantic[0].shared_key_offset, 0x8000);
        assert_eq!(semantic[1].shared_key_offset, 0xa000);
        assert_eq!(semantic[0].shared_key_base, semantic[1].shared_key_base);
        assert_eq!(
            inherited.len(),
            1,
            "inventory work is per extent, not per leaf"
        );
        assert_eq!((inherited[0].gpa, inherited[0].length), (ipa, len));
        assert_eq!(inherited[0].inherited_mapping, Some(mapping));
        assert_eq!(inherited[0].inherited_frame, Some(frame));
        assert_eq!(inherited[0].stage2_owner, extent.stage2_owner);

        // A cached inventory row is not permission to enlarge custody beyond
        // the live physical record or to inherit a recycled owner incarnation.
        for corrupt in [0, 1, 2] {
            let mut ledger = inventory.lock();
            ledger.extents.clear();
            let mut stale = extent;
            let key = match corrupt {
                0 => {
                    stale.stage2_owner.generation += 1;
                    (ipa, len)
                }
                1 => {
                    stale.stage2_owner.host_addr += 4096;
                    (ipa, len)
                }
                _ => (ipa, len + 4096),
            };
            ledger.extents.insert(key, stale);
            drop(ledger);
            assert!(
                project_owner_fork_frames(
                    &physical,
                    &inventory,
                    &Default::default(),
                    &[],
                    &selected,
                )
                .is_err()
            );
            assert_eq!(
                inventory.lock().extents.len(),
                1,
                "refusal publishes nothing"
            );
        }
        assert!(
            retire_global_frame_host_owner_if_generation_in(&custody, ipa, len, generation,)
                .is_retired()
        );
    }

    fn request(custody: &CarrierVmCustody, mm: u64) -> PortalForkRequest {
        PortalForkRequest {
            operation: carrick_el1_abi::PortalOperation {
                carrier: custody.transfer_carrier,
                mm: carrick_el1_abi::ReservationMm::new(mm).unwrap(),
                incarnation: NonZeroU64::new(2).unwrap(),
                sequence: NonZeroU64::new(3).unwrap(),
            },
            parent_generation: carrick_el1_abi::ReservationGeneration::new(1).unwrap(),
            child_mm: carrick_el1_abi::ReservationMm::new(mm + 10).unwrap(),
            child_tables: carrick_el1_abi::PortalForkTableArena::new(0x200000, 0x200000).unwrap(),
            parent_tables: carrick_el1_abi::PortalForkTableArena::new(0x400000, 0x200000).unwrap(),
            kernel_control_ipa: 0x600000,
        }
    }
    #[test]
    fn owner_fork_retains_live_structural_capacity_without_carrier_mm_alias_index() {
        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let custody = Arc::new(CarrierVmCustody::new_live_fixture());
        let request = request(&custody, 1);
        let source = 0xa090_2000_0000;
        let mut owners = Vec::new();
        for ipa in [source, request.kernel_control_ipa] {
            let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                0x4000,
                crate::host_mapping::HostMappingKind::PerMmKernelState,
            )
            .unwrap();
            let mut lease = GlobalFrameStage2Lease::fixed(ipa, 0x4000);
            lease.mark_test_mapped_without_backend();
            let owner = StructuralBackingOwner::new_in(
                &custody,
                mapping,
                lease,
                u64::from(applevisor::memory::MemPerms::ReadWriteExec),
                next_structural_epoch().unwrap(),
                ipa,
                0x4000,
            )
            .unwrap();
            assert_eq!(
                custody.stage2_record_covering(ipa, 4096),
                Some(owner.record_identity())
            );
            owners.push(owner);
        }
        assert!(custody.carrier_stage2_records.lock().is_empty());
        let physical = ForkPhysicalCustody::new(custody.clone(), Arc::new(|_, _| None));
        let selected = PortalForkCustody::StructuralCopy {
            source_ipa: source,
            destination_ipa: request.kernel_control_ipa,
            len: 4096,
            executable: false,
        };
        assert!(
            physical.retain(request, selected).unwrap().is_some(),
            "exact live structural custody must not be declined by the legacy carrier-MM alias index"
        );
        drop(owners);
    }
    #[test]
    fn owner_structural_copy_publishes_selected_executable_bytes() {
        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let custody = Arc::new(CarrierVmCustody::new_live_fixture());
        let source = 0xa090_2000_0000;
        let request = request(&custody, 1);
        for (ipa, byte) in [(source, 0x53), (request.kernel_control_ipa, 0)] {
            let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                0x4000,
                crate::host_mapping::HostMappingKind::PerMmKernelState,
            )
            .unwrap();
            // SAFETY: freshly allocated exact host extent.
            unsafe { core::ptr::write_bytes(mapping.as_ptr(), byte, 0x4000) };
            let mut lease = GlobalFrameStage2Lease::fixed(ipa, 0x4000);
            lease.mark_test_mapped_without_backend();
            register_global_frame_host_owner_in(
                &custody,
                lease,
                mapping,
                u64::from(applevisor::memory::MemPerms::ReadWriteExec),
            )
            .unwrap();
        }
        let physical = ForkPhysicalCustody::new(custody.clone(), Arc::new(|_, _| None));
        let retained = physical
            .retain(
                request,
                PortalForkCustody::StructuralCopy {
                    source_ipa: source,
                    destination_ipa: request.kernel_control_ipa,
                    len: 4096,
                    executable: true,
                },
            )
            .unwrap()
            .unwrap();
        let destination = &retained._frames[1].1;
        // SAFETY: the receipt pins the copied destination extent.
        assert_eq!(unsafe { *destination.host_base() }, 0x53);
        assert_eq!(custody.publish_user_executable(
            request.kernel_control_ipa, 4096, |_, _| None, |_, _| None,
        ).unwrap(), 0, "selected executable bytes were already published before custody ack");
    }
    #[test]
    fn owner_selected_same_va_in_two_mms_retains_exact_physical_frames() {
        let _guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let custody = Arc::new(CarrierVmCustody::new_live_fixture());
        let ipa_a = 0xa090_1000_0000;
        let ipa_b = ipa_a + 0x4000;
        for (ipa, byte) in [(ipa_a, 0x41), (ipa_b, 0x42)] {
            let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                0x4000,
                crate::host_mapping::HostMappingKind::PerMmKernelState,
            )
            .unwrap();
            // SAFETY: newly owned host allocation has exactly this extent.
            unsafe {
                core::ptr::write_bytes(mapping.as_ptr(), byte, 0x4000);
            }
            let mut lease = GlobalFrameStage2Lease::fixed(ipa, 0x4000);
            lease.mark_test_mapped_without_backend();
            register_global_frame_host_owner_in(
                &custody,
                lease,
                mapping,
                u64::from(applevisor::memory::MemPerms::ReadWrite),
            )
            .unwrap();
        }
        let physical = ForkPhysicalCustody::new(custody.clone(), Arc::new(|_, _| None));
        let a = physical
            .retain(
                request(&custody, 1),
                PortalForkCustody::Frame {
                    va: 0x7000,
                    ipa: ipa_a,
                    len: 4096,
                    shared: false,
                },
            )
            .unwrap()
            .unwrap();
        let b = physical
            .retain(
                request(&custody, 2),
                PortalForkCustody::Frame {
                    va: 0x7000,
                    ipa: ipa_b,
                    len: 4096,
                    shared: false,
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(a._frames.len(), 1);
        assert_eq!(b._frames.len(), 1);
        // SAFETY: each exact record pin keeps its allocation alive.
        unsafe {
            assert_eq!(*a._frames[0].1.host_base(), 0x41);
            assert_eq!(*b._frames[0].1.host_base(), 0x42);
        }
        // A block receipt spans physical records; custody follows records,
        // rather than assuming one allocation for one owner-selected leaf.
        let both = physical
            .retain(
                request(&custody, 1),
                PortalForkCustody::Frame {
                    va: 0x10000,
                    ipa: ipa_a,
                    len: 0x8000,
                    shared: false,
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(both._frames.len(), 2);
        drop((a, b, both));
        for ipa in [ipa_a, ipa_b] {
            assert!(matches!(
                retire_global_frame_host_owner_inner_in_using(
                    &custody,
                    ipa,
                    0x4000,
                    None,
                    &mut |_, _| Ok(())
                ),
                GlobalFrameRetirementOutcome::RetiredUnmapped { .. }
            ));
        }
    }
}
