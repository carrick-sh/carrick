//! HVPatch execve stage-2 and authority rebuild logic.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use super::*;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct PendingExecStage2Cleanup {
    #[cfg(not(test))]
    pub(crate) custody: std::sync::Arc<CarrierVmCustody>,
    pub(crate) mappings: TaskMappingIndex,
    /// Physical candidates selected at exec publication, bound to the exact
    /// global-owner incarnation observed at that boundary.
    pub(crate) extents: std::collections::BTreeMap<(u64, usize), InventoryStage2OwnerIdentity>,
    /// Exact alias values visible from the predecessor MM when exec published
    /// its replacement. The root container scope can be reused by the
    /// successor, so a delayed cleanup may remove these values only—not every
    /// row that happens to carry the same broad scope later.
    pub(crate) predecessor_aliases: Vec<AliasBacking>,
    /// Shared backend reference authority rechecked immediately before recycle.
    pub(crate) frames: std::sync::Arc<parking_lot::Mutex<InventoryFrameRegistry>>,
    /// Semantic alias ownership of the address space replaced by exec.
    pub(crate) mm_root_slot: Option<(u64, u64)>,
    /// Exact predecessor MM authority retained independently of its frame
    /// inventory candidates. Present only when this exec owns retirement of
    /// the old MM; a shared projection leaves the authority with its sharer.
    pub(crate) mm_access: Option<std::sync::Arc<MmAccessState>>,
    /// Immutable exact Kernel identity captured before exec replaces the task.
    pub(crate) predecessor_identity: carrick_hal::ExecPredecessorIdentity,
    /// Never-reused predecessor MM identity from the matching COW binding.
    pub(crate) predecessor_mm: u64,
    pub(crate) shared_projection: bool,
    pub(crate) armed: bool,
}

// SAFETY: cleanup moves with the stopped logical task and is consumed only on
// a Task4 owner worker after save/detach. Its raw mapping pointers remain owned
// by the contained HvfMappedRegion backings until cleanup runs.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Send for PendingExecStage2Cleanup {}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PendingExecStage2Cleanup {
    pub(crate) fn retire(&mut self) -> Result<(), TrapError> {
        self.retire_with(&mut |event| {
            crate::probes::hvpatch_exec_predecessor_classification(event);
        })
    }

    pub(crate) fn retire_with(
        &mut self,
        publish: &mut dyn FnMut(
            carrick_observability::probes::HvpatchExecPredecessorClassification,
        ),
    ) -> Result<(), TrapError> {
        self.retire_with_cleanup_boundary(publish, &mut |_| {})
            .map(|_| ())
    }

    pub(crate) fn retire_with_root_proof(
        &mut self,
        expected_root_slot: (u64, u64),
    ) -> Result<HvpatchMmRootRetirementProof, TrapError> {
        if self.mm_root_slot != Some(expected_root_slot) {
            return Err(TrapError::Hypervisor(format!(
                "exec predecessor root retirement coordinates mismatch: expected=({:#x}, {:#x}) captured={:?}",
                expected_root_slot.0, expected_root_slot.1, self.mm_root_slot
            )));
        }
        self.retire_with_cleanup_boundary(
            &mut |event| crate::probes::hvpatch_exec_predecessor_classification(event),
            &mut |_| {},
        )?
        .ok_or_else(|| {
            TrapError::Hypervisor(
                "exec predecessor retirement produced no stage-1 root proof".to_owned(),
            )
        })
    }

    pub(crate) fn retire_with_cleanup_boundary(
        &mut self,
        publish: &mut dyn FnMut(
            carrick_observability::probes::HvpatchExecPredecessorClassification,
        ),
        after_exact_owner_retirement: &mut dyn FnMut(RetiredStage2Projection),
    ) -> Result<Option<HvpatchMmRootRetirementProof>, TrapError> {
        #[cfg(not(test))]
        let custody = std::sync::Arc::clone(&self.custody);
        #[cfg(not(test))]
        let custody = custody.as_ref();
        #[cfg(test)]
        let custody = legacy_test_carrier_vm_custody();
        let identity = self.predecessor_identity;
        let classification =
            carrick_observability::probes::HvpatchExecPredecessorClassification::new(
                carrick_observability::probes::HvpatchExecPredecessorClassificationPhase::CleanupConsumed,
                carrick_observability::probes::HvpatchExecPredecessorIdentity::new(
                    identity.task_serial,
                    identity.thread_serial,
                    identity.linux_pid,
                    identity.linux_tid,
                    self.predecessor_mm,
                    u32::from(identity.asid),
                )
                .map_err(|error| {
                    TrapError::Hypervisor(format!(
                        "construct deferred HVPatch exec predecessor identity: {error}"
                    ))
                })?,
                self.shared_projection,
            )
            .map_err(|error| {
                TrapError::Hypervisor(format!(
                    "construct deferred HVPatch exec predecessor classification: {error}"
                ))
            })?;
        if self.shared_projection {
            // A CLONE_VM process edge owns only unowned descriptors into the
            // parent's still-live MM. Exec drops that projection; it must not
            // unmap stage-2, retire aliases, or release parent backing.
            self.mappings.clear();
            self.armed = false;
            publish(classification);
            return Ok(None);
        }
        let mut retired_extents = Vec::new();
        for (&(ipa, size), &owner_identity) in &self.extents {
            let owner_generation = owner_identity.generation;
            let lease = (ipa, size as u64);
            if owner_generation == 0 && is_reusable_global_frame_extent(ipa, size as u64) {
                // A reusable extent is born with a registered owner generation.
                // Absence at selection is incomplete authority, never permission
                // for delayed cleanup to remove a later incarnation by bare key.
                continue;
            }
            if global_frame_host_owner_generation_in(custody, ipa, size as u64) != owner_generation
            {
                continue;
            }
            let mut exact_owner_retired = false;
            if HvfVmState::retire_stage2_candidate_if_unreferenced(&self.frames, lease, || {
                if owner_generation == 0 {
                    HvfVmState::retire_stage2_extent_from_mappings_in(
                        custody,
                        &mut self.mappings,
                        ipa,
                        size as u64,
                    )
                } else {
                    let outcome = retire_global_frame_host_owner_if_generation_in(
                        custody,
                        ipa,
                        size as u64,
                        owner_generation,
                    );
                    match outcome {
                        GlobalFrameRetirementOutcome::RetiredUnmapped { .. }
                        | GlobalFrameRetirementOutcome::TerminalizedByVmDestroy { .. } => {
                            exact_owner_retired = true;
                            Ok(())
                        }
                        GlobalFrameRetirementOutcome::DeferredActivePins { .. }
                        | GlobalFrameRetirementOutcome::RetryPending { .. } => Ok(()),
                        outcome => Err(TrapError::Hypervisor(format!(
                            "HVPatch exec predecessor owner generation drifted at IPA 0x{ipa:x} size {size}: {outcome:?}"
                        ))),
                    }
                }
            })? {
                let retired = RetiredStage2Projection {
                    physical_ipa: ipa,
                    physical_length: size as u64,
                    owner: owner_identity,
                };
                retired_extents.push(retired);
                if exact_owner_retired {
                    after_exact_owner_retirement(retired);
                }
            }
        }
        let mut root_proof = None;
        if let (Some(mm_access), Some(root_slot)) = (&self.mm_access, self.mm_root_slot) {
            let retired_root = mm_access.retire_mm_root_stage2_in(custody, root_slot)?;
            let (ipa, size) = retired_root.physical_extent;
            if !retired_extents.iter().any(|retired| {
                (retired.physical_ipa, retired.physical_length) == (ipa, size as u64)
            }) {
                retired_extents.push(RetiredStage2Projection {
                    physical_ipa: ipa,
                    physical_length: size as u64,
                    owner: retired_root.owner,
                });
            }
            root_proof = Some(retired_root.proof);
        }
        let (removed_aliases, preserved_aliases) = mutate_known_external_alias_state(
            |_, registry| {
                retired_projection_mutation_keys(
                    registry,
                    &retired_extents,
                    &self.predecessor_aliases,
                )
            },
            |replay, registry| {
                let cleanup =
                    remove_rows_for_retired_stage2_projections(replay, registry, &retired_extents);
                let mut removed = cleanup.removed_aliases;
                let mut preserved = cleanup.preserved_reused_aliases;
                for expected in &self.predecessor_aliases {
                    if let Some(current) =
                        registry.find_by_key(expected.start, expected.ipa, expected.ownership_scope)
                        && current != *expected
                    {
                        preserved.push(current);
                    }
                }
                removed.extend(registry.remove_exact_values_in_batch(&self.predecessor_aliases));
                (removed, preserved)
            },
        );
        for alias in removed_aliases {
            record_cow_alias_lifecycle(
                CowDiagnosticLifecycleKind::AliasRemoved,
                CowDiagnosticLifecycleSite::ExecRetirement,
                Some(custody),
                None,
                self.mm_root_slot,
                alias,
            );
        }
        for alias in preserved_aliases {
            record_cow_alias_lifecycle(
                CowDiagnosticLifecycleKind::AliasPreservedReused,
                CowDiagnosticLifecycleSite::ExecRetirement,
                Some(custody),
                None,
                self.mm_root_slot,
                alias,
            );
        }
        record_alias_revision(
            CowDiagnosticAliasRevisionSite::ExecPredecessorMutation,
            custody,
            None,
            0,
            alias_registry().lock().revision(),
        );
        let structural_retirements = self
            .mappings
            .iter()
            .filter_map(|mapping| {
                mapping
                    .structural_owner
                    .as_ref()
                    .map(|owner| *owner.retained.record_identity.lock())
            })
            .collect::<Vec<_>>();
        let mut retained_backings = Vec::new();
        for mapping in std::mem::take(&mut self.mappings).into_values() {
            if retired_extents
                .iter()
                .any(|retired| mapped_region_matches_retired_inventory_extent(&mapping, *retired))
            {
                drop(mapping);
            } else {
                retained_backings.push(mapping);
            }
        }
        std::mem::forget(retained_backings);
        retry_structural_backing_identities_in_using(
            custody,
            &structural_retirements,
            &mut unmap_global_frame_stage2_record,
            &mut release_retired_stage2_ipa,
        )?;
        self.armed = false;
        publish(classification);
        Ok(root_proof)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for PendingExecStage2Cleanup {
    fn drop(&mut self) {
        if self.armed {
            if let Err(error) = self.retire() {
                carrick_fatal!(
                    "hvpatch::exec_commit",
                    "drop pending exec predecessor cleanup failed: {error}"
                );
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct GlobalExecPlan {
    pub(crate) plan: GuestMappingPlan,
    pub(crate) stage2_leases: std::collections::BTreeMap<(u64, u64), GlobalFrameStage2Lease>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExecStage2Install {
    pub(crate) ipa: u64,
    pub(crate) size: usize,
    pub(crate) host: *mut u8,
    pub(crate) perms: u64,
    pub(crate) replay_registered: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExecLeaseFingerprint {
    pub(crate) base: u64,
    pub(crate) length: u64,
    pub(crate) mapped: bool,
    pub(crate) active: bool,
    pub(crate) release_ipa: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl From<&GlobalFrameStage2Lease> for ExecLeaseFingerprint {
    fn from(lease: &GlobalFrameStage2Lease) -> Self {
        Self {
            base: lease.base,
            length: lease.length,
            mapped: lease.mapped,
            active: lease.active,
            release_ipa: lease.release_ipa,
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecOwnerFingerprint {
    pub(crate) key: (u64, u64),
    pub(crate) host: usize,
    pub(crate) host_len: usize,
    pub(crate) perms: u64,
    pub(crate) lease: ExecLeaseFingerprint,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExecBackendExtentFingerprint {
    pub(crate) key: (u64, u64),
    pub(crate) frame: carrick_hal::FrameId,
    pub(crate) mapping: carrick_hal::MappingId,
    pub(crate) backing: InventoryBackingIdentity,
    pub(crate) stage2_base: u64,
    pub(crate) stage2_length: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecMappingFingerprint {
    pub(crate) start: u64,
    pub(crate) ipa: u64,
    pub(crate) physical_ipa: u64,
    pub(crate) end: u64,
    pub(crate) host: usize,
    pub(crate) size: usize,
    pub(crate) physical_size: usize,
    pub(crate) perms: u64,
    pub(crate) has_memory: bool,
    pub(crate) host_owner: Option<(usize, usize)>,
    pub(crate) stage2_lease: Option<ExecLeaseFingerprint>,
    pub(crate) is_dynamic_alias: bool,
    pub(crate) sharing: GuestMappingSharing,
    pub(crate) guest_writable: bool,
    pub(crate) shared_key_base: u64,
    pub(crate) shared_key_offset: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecAllocatorFingerprint {
    pub(crate) next: u64,
    pub(crate) free: Vec<(u64, u64)>,
    pub(crate) live: Vec<(u64, u64)>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecAuthorityFingerprint {
    pub(crate) owners: Vec<ExecOwnerFingerprint>,
    pub(crate) inventory_initialized: bool,
    pub(crate) backend_extents: Vec<ExecBackendExtentFingerprint>,
    pub(crate) frame_references: Vec<(carrick_hal::FrameId, usize)>,
    pub(crate) extent_references: Vec<((carrick_hal::FrameId, u64, u64), usize)>,
    pub(crate) stage2_references: Vec<((u64, u64), usize)>,
    pub(crate) authority_retained_stage2: Vec<(u64, u64)>,
    pub(crate) mappings: Vec<ExecMappingFingerprint>,
    pub(crate) allocator: ExecAllocatorFingerprint,
    pub(crate) replay_mappings: Vec<ReplayMappingKey>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn verify_exec_authority_rollback(
    before: &ExecAuthorityFingerprint,
    after: &ExecAuthorityFingerprint,
) -> Result<(), TrapError> {
    if before == after {
        Ok(())
    } else {
        Err(TrapError::Hypervisor(
            "HVPatch exec stage-2 rollback changed published authority".to_owned(),
        ))
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ExecStage2Install {
    pub(crate) fn replay_key(&self) -> Option<ReplayMappingKey> {
        self.replay_registered
            .then_some((self.ipa, self.size, self.host as usize, self.perms, 0))
    }

    #[cfg(test)]
    pub(crate) fn key(&self) -> (u64, u64) {
        (self.ipa, self.size as u64)
    }

    #[cfg(test)]
    pub(crate) fn for_test(ipa: u64, size: usize) -> Self {
        Self {
            ipa,
            size,
            host: std::ptr::null_mut(),
            perms: 0,
            replay_registered: false,
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn switch_exec_stage2_transaction(
    old: &[ExecStage2Install],
    new: &[ExecStage2Install],
    fail_after_maps: Option<usize>,
    mut unmap: impl FnMut(&ExecStage2Install) -> Result<(), TrapError>,
    mut map: impl FnMut(&ExecStage2Install) -> Result<(), TrapError>,
) -> Result<(), TrapError> {
    for (old_unmapped, extent) in old.iter().enumerate() {
        if let Err(error) = unmap(extent) {
            for restore in &old[..old_unmapped] {
                map(restore).unwrap_or_else(|rollback| {
                    carrick_fatal!(
                        "hvpatch::exec_commit",
                        "restore HVPatch exec predecessor after unmap failure: {rollback}"
                    );
                });
            }
            return Err(error);
        }
    }

    let rollback =
        |mapped: usize,
         unmap: &mut dyn FnMut(&ExecStage2Install) -> Result<(), TrapError>,
         map: &mut dyn FnMut(&ExecStage2Install) -> Result<(), TrapError>| {
            for replacement in new[..mapped].iter().rev() {
                unmap(replacement).unwrap_or_else(|error| {
                    carrick_fatal!(
                        "hvpatch::exec_commit",
                        "rollback HVPatch exec replacement stage-2 mapping: {error}"
                    );
                });
            }
            for predecessor in old {
                map(predecessor).unwrap_or_else(|error| {
                    carrick_fatal!(
                        "hvpatch::exec_commit",
                        "restore HVPatch exec predecessor stage-2 mapping: {error}"
                    );
                });
            }
        };

    for (new_mapped, extent) in new.iter().enumerate() {
        if fail_after_maps == Some(new_mapped) {
            rollback(new_mapped, &mut unmap, &mut map);
            return Err(TrapError::Hypervisor(format!(
                "injected HVPatch exec stage-2 map failure after {new_mapped} maps"
            )));
        }
        if let Err(error) = map(extent) {
            rollback(new_mapped, &mut unmap, &mut map);
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn exec_stage2_fail_after_maps() -> Option<usize> {
    std::env::var("CARRICK_HVPATCH_EXEC_FAIL_AFTER_MAPS")
        .ok()
        .and_then(|value| value.parse().ok())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn global_frame_exec_lease_order(
    mappings: &[GuestMapping],
    table_index: usize,
) -> Vec<usize> {
    let mut order: Vec<usize> = (0..mappings.len())
        .filter(|&index| {
            !is_sparse_hvpatch_mmap_mapping(&mappings[index])
                && !is_persistent_executor_carrier_guest_mapping(&mappings[index])
        })
        .collect();
    order.sort_by_key(|&index| {
        (
            u8::from(index != table_index),
            std::cmp::Reverse(mappings[index].mapped_size),
            mappings[index].guest_start,
            index,
        )
    });
    order
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn prepare_global_exec_plan(
    plan: &GuestMappingPlan,
    mm_root_slot: Option<(u64, u64)>,
) -> Result<GlobalExecPlan, TrapError> {
    let old_root = plan.stage1_page_tables_base.ok_or_else(|| {
        TrapError::Hypervisor("hvpatch exec image has no stage-1 tables".to_owned())
    })?;
    let table_index = plan
        .mappings
        .iter()
        .position(|mapping| mapping.guest_start == old_root)
        .ok_or_else(|| {
            TrapError::Hypervisor("hvpatch exec page-table mapping absent".to_owned())
        })?;
    let mut global = plan.clone();
    let mut stage2_leases = std::collections::BTreeMap::new();
    let mut page_tables = crate::page_table::PageTableManager::new(
        global.mappings[table_index].image.as_ref().clone(),
        old_root,
    );
    const TWO_MIB: u64 = 2 * 1024 * 1024;
    let mut order = global_frame_exec_lease_order(&global.mappings, table_index);
    if mm_root_slot.is_none() {
        // The root's table is allocator-owned after its first exec, unlike a
        // child's fixed root-slot table. Preserve scarce large holes by giving
        // the largest root mappings first choice before reserving the table.
        order.sort_by_key(|&index| {
            (
                std::cmp::Reverse(global.mappings[index].mapped_size),
                global.mappings[index].guest_start,
                index,
            )
        });
    }
    for index in order {
        let mapping = &mut global.mappings[index];
        let lease = if let Some((root_slot_base, root_slot_size)) = mm_root_slot
            && index == table_index
        {
            if mapping.mapped_size > root_slot_size {
                return Err(TrapError::Hypervisor(format!(
                    "hvpatch stage-1 root needs {} bytes, slot has {root_slot_size}",
                    mapping.mapped_size
                )));
            }
            let lease = GlobalFrameStage2Lease::fixed(root_slot_base, mapping.mapped_size);
            if lease
                .base
                .checked_add(mapping.mapped_size)
                .is_none_or(|end| end > root_slot_base.saturating_add(root_slot_size))
            {
                return Err(TrapError::Hypervisor(format!(
                    "hvpatch stage-1 root mapping escapes slot 0x{root_slot_base:x}..0x{:x}",
                    root_slot_base.saturating_add(root_slot_size)
                )));
            }
            lease
        } else {
            let alignment =
                if mapping.guest_start.is_multiple_of(TWO_MIB) && mapping.mapped_size >= TWO_MIB {
                    TWO_MIB
                } else {
                    HVF_PAGE_SIZE
                };
            GlobalFrameStage2Lease::reserve(mapping.mapped_size, alignment)?
        };
        let ipa = lease.base;
        mapping.ipa_start = ipa;
        if stage2_leases
            .insert((ipa, mapping.mapped_size), lease)
            .is_some()
        {
            return Err(TrapError::Hypervisor(format!(
                "duplicate HVPatch exec stage-2 lease IPA 0x{ipa:x} size {}",
                mapping.mapped_size
            )));
        }
    }
    let root = global.mappings[table_index].ipa_start;
    page_tables.rebase(root, None).map_err(|error| {
        TrapError::Hypervisor(format!("rebase HVPatch exec page tables: {error:?}"))
    })?;
    for mapping in global
        .mappings
        .iter()
        .filter(|mapping| !is_sparse_hvpatch_mmap_mapping(mapping))
    {
        let remap = if (crate::memory::LINUX_KERNEL_REGION_BASE
            ..crate::memory::LINUX_KERNEL_REGION_BASE + TWO_MIB)
            .contains(&mapping.guest_start)
        {
            page_tables.map_kernel_aliased(
                mapping.guest_start,
                mapping.ipa_start,
                mapping.mapped_size,
                None,
            )
        } else {
            page_tables.map_aliased(
                mapping.guest_start,
                mapping.ipa_start,
                mapping.mapped_size,
                mapping.perms.write,
                None,
            )
        };
        remap.map_err(|error| {
            TrapError::Hypervisor(format!(
                "plan global-frame HVPatch exec VA 0x{:x}: {error:?}",
                mapping.guest_start
            ))
        })?;
    }
    page_tables
        .set_prot_none(
            crate::memory::LINUX_MMAP_BASE,
            crate::memory::mmap_arena_size() as usize,
            None,
        )
        .map_err(|error| {
            TrapError::Hypervisor(format!("reserve sparse HVPatch mmap arena: {error:?}"))
        })?;
    reapply_global_exec_readonly_spans(&mut page_tables, &global.ro_spans)?;
    for mapping in &global.mappings {
        let expected = (!is_sparse_hvpatch_mmap_mapping(mapping)).then_some(mapping.ipa_start);
        if page_tables.translate(mapping.guest_start) != expected {
            return Err(TrapError::Hypervisor(format!(
                "hvpatch exec translation mismatch for VA 0x{:x}: expected={expected:x?}",
                mapping.guest_start,
            )));
        }
    }
    carrick_aarch64::engine::reserve_hvpatch_process_apertures(&mut page_tables).map_err(
        |error| {
            TrapError::Hypervisor(format!(
                "reserve hvpatch exec root-slot/global-frame apertures: {error:?}"
            ))
        },
    )?;
    let table_bytes = page_tables.into_bytes();
    {
        let table = &mut global.mappings[table_index];
        if table.ipa_start != root || table_bytes.len() > table.mapped_size as usize {
            return Err(TrapError::Hypervisor(
                "hvpatch exec page-table root-slot layout mismatch".to_owned(),
            ));
        }
        table.image = table_bytes.into();
        table.payload_size = table.image.len() as u64;
    }
    global.stage1_page_tables_base = Some(root);
    Ok(GlobalExecPlan {
        plan: global,
        stage2_leases,
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn is_sparse_hvpatch_mmap_mapping(mapping: &GuestMapping) -> bool {
    mapping.guest_start == crate::memory::LINUX_MMAP_BASE
        && mapping.mapped_size == crate::memory::mmap_arena_size()
        && !mapping.shared
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn reapply_global_exec_readonly_spans(
    page_tables: &mut crate::page_table::PageTableManager,
    ro_spans: &[carrick_mem::elf::RoSpan],
) -> Result<(), TrapError> {
    for span in ro_spans {
        let len = usize::try_from(span.len).map_err(|_| {
            TrapError::Hypervisor(format!(
                "HVPatch exec read-only span at 0x{:x} is too large: {}",
                span.start, span.len
            ))
        })?;
        page_tables
            .set_readonly(span.start, len, span.exec, None)
            .map_err(|error| {
                TrapError::Hypervisor(format!(
                    "restore HVPatch exec read-only span at 0x{:x}: {error:?}",
                    span.start
                ))
            })?;
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct GlobalFrameOwnerRollback {
    pub(crate) custody: std::sync::Arc<CarrierVmCustody>,
    pub(crate) keys: Vec<(u64, u64)>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl GlobalFrameOwnerRollback {
    pub(crate) fn new(custody: std::sync::Arc<CarrierVmCustody>) -> Self {
        Self {
            custody,
            keys: Vec::new(),
        }
    }

    pub(crate) fn record(&mut self, key: (u64, u64)) {
        self.keys.push(key);
    }

    pub(crate) fn commit(mut self) {
        self.keys.clear();
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for GlobalFrameOwnerRollback {
    fn drop(&mut self) {
        for &(ipa, length) in self.keys.iter().rev() {
            let outcome = retire_global_frame_host_owner_in(&self.custody, ipa, length);
            if matches!(outcome, GlobalFrameRetirementOutcome::NotFound { .. }) {
                carrick_fatal!(
                    "hvpatch::frame_inventory",
                    "rollback lost global frame owner IPA 0x{ipa:x} size {length}"
                );
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfVmState {
    pub(crate) fn exec_authority_fingerprint(&self) -> ExecAuthorityFingerprint {
        let inventory = self.frame_inventory.lock();
        let backend_extents = inventory
            .extents
            .iter()
            .map(|(&key, extent)| ExecBackendExtentFingerprint {
                key,
                frame: extent.frame,
                mapping: extent.mapping,
                backing: extent.backing,
                stage2_base: extent.stage2_base,
                stage2_length: extent.stage2_length,
            })
            .collect();
        let inventory_initialized = inventory.initialized;
        let frames = inventory.frames.lock();
        let frame_references = frames
            .references
            .iter()
            .map(|(&key, &value)| (key, value))
            .collect();
        let extent_references = frames
            .extent_references
            .iter()
            .map(|(&key, &value)| (key, value))
            .collect();
        let stage2_references = frames
            .stage2_references
            .iter()
            .map(|(&key, &value)| (key, value))
            .collect();
        let authority_retained_stage2 = frames.authority_retained_stage2.iter().copied().collect();
        drop(frames);
        drop(inventory);
        let owners = self
            .custody()
            .global_frame_host_owners
            .lock()
            .iter()
            .map(|(&key, entry)| {
                let owner = entry.owner();
                ExecOwnerFingerprint {
                    key,
                    host: owner.host_addr(),
                    host_len: owner.len(),
                    perms: owner.perms(),
                    lease: owner.lease_fingerprint().unwrap_or(ExecLeaseFingerprint {
                        base: key.0,
                        length: key.1,
                        mapped: false,
                        active: false,
                        release_ipa: false,
                    }),
                }
            })
            .collect();
        let mappings = self
            .mappings
            .iter()
            .map(|mapping| ExecMappingFingerprint {
                start: mapping.start,
                ipa: mapping.ipa,
                physical_ipa: mapping.physical_ipa,
                end: mapping.end,
                host: mapping.host_addr as usize,
                size: mapping.size,
                physical_size: mapping.physical_size,
                perms: u64::from(mapping.perms),
                has_memory: mapping.memory.is_some(),
                host_owner: mapping
                    .host_mapping
                    .as_ref()
                    .map(|owner| (owner.as_ptr() as usize, owner.len())),
                stage2_lease: mapping.stage2_lease.as_ref().map(Into::into),
                is_dynamic_alias: mapping.is_dynamic_alias,
                sharing: mapping.sharing,
                guest_writable: mapping.guest_writable,
                shared_key_base: mapping.shared_key_base,
                shared_key_offset: mapping.shared_key_offset,
            })
            .collect();
        let allocator = global_frame_ipa_allocator().lock();
        let allocator = ExecAllocatorFingerprint {
            next: allocator.next,
            free: allocator.free.clone(),
            live: allocator
                .live
                .iter()
                .map(|(&key, &value)| (key, value))
                .collect(),
        };
        let replay_mappings = replay_mappings().lock().iter().copied().collect();
        ExecAuthorityFingerprint {
            owners,
            inventory_initialized,
            backend_extents,
            frame_references,
            extent_references,
            stage2_references,
            authority_retained_stage2,
            mappings,
            allocator,
            replay_mappings,
        }
    }

    /// `execve(2)` image replacement. Ordinary VMM tears down and rebuilds the
    /// VM; hvpatch retains its one process-wide VM and replaces only stage-2
    /// mappings plus vCPU architectural state. Clears the alias registry and
    /// preserves `is_forked_child`.
    pub(crate) fn execve_rebuild(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
        plan: &GuestMappingPlan,
    ) -> Result<(), TrapError> {
        let mut pending_creation = None;
        let result = self.execve_rebuild_inner(vcpu, mailbox, plan, &mut pending_creation);
        finish_pending_vm_creation(pending_creation, result)
    }

    fn execve_rebuild_inner(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
        plan: &GuestMappingPlan,
        pending_creation: &mut Option<PendingCarrierVmCreation>,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::*;
        let custody = self.carrier_vm_custody();
        let predecessor_mm_root_slot = self.mm_root_slot;
        let replacement_mm_root_slot = if self.persistent_vm_lifecycle {
            self.pending_exec_mm_root_slot.ok_or_else(|| {
                TrapError::Hypervisor(
                    "HVPatch exec began without a fresh root-slot lease".to_owned(),
                )
            })?
        } else {
            self.mm_root_slot.unwrap_or((0, 0))
        };
        let replacement_asid = if self.persistent_vm_lifecycle {
            self.pending_exec_asid.ok_or_else(|| {
                TrapError::Hypervisor("HVPatch exec began without a fresh ASID lease".to_owned())
            })?
        } else {
            0
        };
        let mut inventory_reservations = if self.persistent_vm_lifecycle {
            let mut inventory = self.frame_inventory.lock();
            // The replacement transaction is mandatory. The retirement one is
            // absent exactly when the old mm stays owned by a live sharer, so
            // its absence here is the armed contract, not a missing reservation.
            let replacement = inventory.replacement_reservation.take().ok_or_else(|| {
                TrapError::Hypervisor(
                    "HVPatch exec began without replacement-mm inventory reservation".to_owned(),
                )
            })?;
            Some((inventory.retired_reservation.take(), replacement))
        } else {
            None
        };
        let frame_plan_started = std::time::Instant::now();
        let GlobalExecPlan {
            plan: mut global_plan,
            mut stage2_leases,
        } = self.global_frame_exec_plan(plan)?;
        self.pending_exec_mm_root_slot = None;
        self.pending_exec_asid = None;
        let frame_plan_elapsed_ns = frame_plan_started
            .elapsed()
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        let replacement_mapping_count = global_plan
            .mappings
            .iter()
            .filter(|mapping| {
                !is_sparse_hvpatch_mmap_mapping(mapping)
                    && !is_persistent_executor_carrier_guest_mapping(mapping)
            })
            .count() as u64;
        let replacement_mapped_bytes = global_plan
            .mappings
            .iter()
            .filter(|mapping| {
                !is_sparse_hvpatch_mmap_mapping(mapping)
                    && !is_persistent_executor_carrier_guest_mapping(mapping)
            })
            .map(|mapping| mapping.mapped_size)
            .sum::<u64>();
        crate::probes::hvpatch_exec_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStage::new(
                carrick_observability::probes::HvpatchExecReplaceStagePhase::FramePlan,
                frame_plan_elapsed_ns,
                replacement_mapping_count,
                replacement_mapped_bytes,
            ),
        );
        let private_file_artifacts_started = std::time::Instant::now();
        if self.persistent_vm_lifecycle {
            attach_exec_private_file_backings(&mut global_plan)?;
        }
        let private_file_artifacts_elapsed_ns = private_file_artifacts_started
            .elapsed()
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        let plan = &global_plan;
        let map_backings_started = std::time::Instant::now();
        let mut prepared_exec_regions = Vec::new();
        if self.persistent_vm_lifecycle {
            for mapping in plan.mappings.iter().filter(|mapping| {
                !is_sparse_hvpatch_mmap_mapping(mapping)
                    && !is_persistent_executor_carrier_guest_mapping(mapping)
            }) {
                let key = (mapping.ipa_start, mapping.mapped_size);
                let lease = stage2_leases.remove(&key).ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "HVPatch exec mapping IPA 0x{:x} size {} has no owning lease",
                        key.0, key.1
                    ))
                })?;
                let region = prepare_exec_region_raw_in(&custody, mapping)?;
                prepared_exec_regions.push((region, lease));
            }
            if !stage2_leases.is_empty() {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch exec left {} reserved stage-2 leases unmaterialized",
                    stage2_leases.len()
                )));
            }
        }
        let emit_replace_stage =
            |phase: carrick_observability::probes::HvpatchExecReplaceStagePhase,
             started: std::time::Instant| {
                let elapsed_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
                crate::probes::hvpatch_exec_replace_stage(
                    carrick_observability::probes::HvpatchExecReplaceStage::new(
                        phase,
                        elapsed_ns,
                        replacement_mapping_count,
                        replacement_mapped_bytes,
                    ),
                );
            };
        crate::probes::hvpatch_exec_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStage::new(
                carrick_observability::probes::HvpatchExecReplaceStagePhase::PrivateFileArtifacts,
                private_file_artifacts_elapsed_ns,
                replacement_mapping_count,
                replacement_mapped_bytes,
            ),
        );
        // Preserve `is_forked_child` across execve. A process that descended from
        // the original `carrick run` invocation should keep using the
        // `_exit`-without-JSON shutdown path even after it execve's into a
        // different image; otherwise every forked + execve'd descendant prints its
        // own JSON report to stdout (interleaved with the parent's), making the
        // user-visible output unreadable.
        let was_forked_child = self.is_forked_child;
        let shared_projection = self.shared_process_mm;
        let address_space_teardown_started = std::time::Instant::now();
        let mut pending_exec_vcpu = None;
        let mut pending_exec_vm = None;
        let retired_physical_extents = if self.persistent_vm_lifecycle {
            // The vCPU is stopped at the execve syscall exit and every sibling
            // has already retired. Build the complete predecessor/replacement
            // edge sets before touching stage-2. The switch helper restores the
            // exact predecessor on every ordinary failure, so backend inventory,
            // owners and mapping rows remain unchanged until this succeeds.
            let authority = self.cow_authority.as_ref().cloned().ok_or_else(|| {
                TrapError::Hypervisor(
                    "HVPatch exec retirement has no frame inventory authority".to_owned(),
                )
            })?;
            let extents =
                final_exec_physical_extents(&self.frame_inventory.lock(), authority.as_ref())?;
            let replacement = plan
                .mappings
                .iter()
                .filter(|mapping| {
                    !is_sparse_hvpatch_mmap_mapping(mapping)
                        && !is_persistent_executor_carrier_guest_mapping(mapping)
                })
                .zip(prepared_exec_regions.iter())
                .map(|(mapping, (region, _))| exec_stage2_install(mapping, region))
                .collect::<Vec<_>>();
            let authority_before = self.exec_authority_fingerprint();
            let switch_result = switch_exec_stage2_transaction(
                &[],
                &replacement,
                exec_stage2_fail_after_maps(),
                |extent| {
                    crate::probes::hvpatch_exec_stage2(
                        carrick_observability::probes::HvpatchExecStage2::new(
                            carrick_observability::probes::HvpatchExecStage2Phase::UnmapBegin,
                            extent.ipa,
                            extent.size as u64,
                            u64::MAX,
                            0,
                        ),
                    );
                    let rc = unsafe { inventory_hv_vm_unmap(extent.ipa, extent.size) };
                    crate::probes::hvpatch_exec_stage2(
                        carrick_observability::probes::HvpatchExecStage2::new(
                            carrick_observability::probes::HvpatchExecStage2Phase::UnmapEnd,
                            extent.ipa,
                            extent.size as u64,
                            u64::MAX,
                            if rc == 0 { 0 } else { -1 },
                        ),
                    );
                    if rc == 0 {
                        Ok(())
                    } else {
                        Err(TrapError::Hypervisor(format!(
                            "unmap HVPatch exec predecessor IPA 0x{:x} size {} failed: 0x{rc:x}",
                            extent.ipa, extent.size
                        )))
                    }
                },
                |extent| {
                    crate::probes::hvpatch_exec_stage2(
                        carrick_observability::probes::HvpatchExecStage2::new(
                            carrick_observability::probes::HvpatchExecStage2Phase::MapBegin,
                            extent.ipa,
                            extent.size as u64,
                            u64::MAX,
                            0,
                        ),
                    );
                    let rc = unsafe {
                        inventory_hv_vm_map(
                            extent.host.cast(),
                            extent.ipa,
                            extent.size,
                            extent.perms,
                        )
                    };
                    if rc == 0
                        && let Some(replay_key) = extent.replay_key()
                    {
                        mutate_external_alias_state(|replay, _| {
                            replay.insert(replay_key);
                        });
                    }
                    crate::probes::hvpatch_exec_stage2(
                        carrick_observability::probes::HvpatchExecStage2::new(
                            carrick_observability::probes::HvpatchExecStage2Phase::MapEnd,
                            extent.ipa,
                            extent.size as u64,
                            u64::MAX,
                            rc as i32,
                        ),
                    );
                    if rc == 0 {
                        Ok(())
                    } else {
                        Err(TrapError::Hypervisor(format!(
                            "map HVPatch exec replacement IPA 0x{:x} size {} failed: 0x{rc:x}",
                            extent.ipa, extent.size
                        )))
                    }
                },
            );
            if let Err(error) = switch_result {
                let authority_after = self.exec_authority_fingerprint();
                if let Err(rollback_error) =
                    verify_exec_authority_rollback(&authority_before, &authority_after)
                {
                    carrick_fatal!("hvpatch::exec_commit", "{rollback_error}");
                }
                return Err(error);
            }
            for (_, lease) in &mut prepared_exec_regions {
                lease.mark_mapped();
            }
            if let Some((Some(retired), _)) = inventory_reservations.as_mut() {
                let authority = self.cow_authority.as_ref().cloned().ok_or_else(|| {
                    TrapError::Hypervisor(
                        "HVPatch exec retirement has no frame inventory authority".to_owned(),
                    )
                })?;
                let mut inventory = self.frame_inventory.lock();
                let diagnostic_extents = if cow_refusal_diagnostics_enabled() {
                    inventory
                        .extents
                        .iter()
                        .map(|(&key, &extent)| (key, extent))
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                if let Err(error) =
                    Self::stage_retirement(&mut inventory, retired, authority.as_ref())
                {
                    carrick_fatal!(
                        "hvpatch::frame_inventory",
                        "stage inventory after HVPatch exec unmap: {error}"
                    );
                }
                for (key, extent) in diagnostic_extents {
                    record_cow_inventory_lifecycle(
                        CowDiagnosticLifecycleKind::InventoryRemoved,
                        CowDiagnosticLifecycleSite::ExecRetirement,
                        &self.carrier_foreign_mm_transport.custody,
                        self.cow_identity,
                        self.mm_root_slot,
                        0,
                        0,
                        key,
                        extent,
                    );
                }
            }
            extents
        } else {
            // Mature VMM behavior: tear down the current HVF VM and rebuild it.
            let inherited_vcpu_id = vcpu.id();
            let vcpu_destroy_rc = unsafe { applevisor_sys::hv_vcpu_destroy(inherited_vcpu_id) };
            if vcpu_destroy_rc == 0 {
                self._vcpu_guard = None;
                vcpu_destroyed(inherited_vcpu_id);
            }
            destroy_vm_with_custody(&self.carrier_foreign_mm_transport.custody, "execve_rebuild")?;

            let (new_vm, permit, creation) = create_vm_with_admission(
                VmCreateAdmission::ExecveRebuild,
                &self.carrier_foreign_mm_transport.custody,
            )?;
            let new_vm = SetupVmGuard::new(new_vm, true);
            *pending_creation = Some(creation);
            reconcile_global_frame_owners_after_replay_in(
                &self.carrier_foreign_mm_transport.custody,
                &[],
                true,
            )?;
            let new_vcpu = SetupVcpuGuard::new(
                create_vcpu_with_permit(&new_vm, permit)?,
                SetupVcpuCleanup::PendingRaw,
            );
            let creation = pending_creation.as_mut().ok_or_else(|| {
                TrapError::Hypervisor("exec creation transaction disappeared".to_owned())
            })?;
            creation.record_vcpu(new_vcpu.id());
            enable_el0_counter_access(new_vcpu.id());
            pending_exec_vcpu = Some(new_vcpu);
            pending_exec_vm = Some(new_vm);
            std::collections::BTreeSet::new()
        };
        emit_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStagePhase::AddressSpaceTeardown,
            address_space_teardown_started,
        );
        // Retain aliases still backed by another live mm. Mature VMM destroyed
        // the whole VM; persistent HVPatch removes only physical extents whose
        // final logical references retired above.
        let alias_cleanup_started = std::time::Instant::now();
        if !self.persistent_vm_lifecycle {
            clear_alias_registry();
        }
        emit_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStagePhase::AliasCleanup,
            alias_cleanup_started,
        );
        let drop_backings_started = std::time::Instant::now();
        if self.persistent_vm_lifecycle {
            let predecessor_cow_identity = self.cow_identity.ok_or_else(|| {
                TrapError::Hypervisor(
                    "HVPatch exec predecessor cleanup lacks exact COW identity".to_owned(),
                )
            })?;
            let predecessor_identity =
                self.take_exec_predecessor_identity(predecessor_cow_identity)?;
            let predecessor_classification =
                carrick_observability::probes::HvpatchExecPredecessorClassification::new(
                    carrick_observability::probes::HvpatchExecPredecessorClassificationPhase::BackendCaptured,
                    carrick_observability::probes::HvpatchExecPredecessorIdentity::new(
                        predecessor_identity.task_serial,
                        predecessor_identity.thread_serial,
                        predecessor_identity.linux_pid,
                        predecessor_identity.linux_tid,
                        predecessor_cow_identity.mm,
                        u32::from(predecessor_identity.asid),
                    )
                    .map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "construct backend HVPatch exec predecessor identity: {error}"
                        ))
                    })?,
                    shared_projection,
                )
                .map_err(|error| {
                    TrapError::Hypervisor(format!(
                        "construct backend HVPatch exec predecessor classification: {error}"
                    ))
                })?;
            let predecessor_aliases = alias_registry()
                .lock()
                .process_visible_ordered(predecessor_mm_root_slot, self.container_root)
                .into_iter()
                .filter(|alias| {
                    alias_is_owned_by_process(
                        alias.ownership_scope,
                        predecessor_mm_root_slot,
                        self.container_root,
                    )
                })
                .collect::<Vec<_>>();
            let predecessor_mappings = std::mem::take(&mut self.mappings);
            let predecessor_mm_access = if shared_projection {
                None
            } else {
                Some(std::sync::Arc::clone(&self.mm_access))
            };
            let predecessor_frames = std::sync::Arc::clone(&self.frame_inventory.lock().frames);
            let predecessor_extents = retired_physical_extents
                .iter()
                .map(|&(ipa, size)| {
                    let owner = global_frame_host_owner_identity_in(&custody, ipa, size as u64)
                        .map(|(host_addr, generation)| InventoryStage2OwnerIdentity {
                            host_addr,
                            generation,
                        })
                        .or_else(|| {
                            predecessor_mappings
                                .iter()
                                .find(|mapping| {
                                    (mapping.physical_ipa, mapping.physical_size) == (ipa, size)
                                })
                                .and_then(mapped_region_stage2_owner_identity)
                        })
                        .ok_or_else(|| {
                            TrapError::Hypervisor(format!(
                                "HVPatch exec predecessor extent IPA 0x{ipa:x} size {size} has no exact owner identity"
                            ))
                        })?;
                    Ok(((ipa, size), owner))
                })
                .collect::<std::result::Result<
                    std::collections::BTreeMap<_, _>,
                    TrapError,
                >>()?;
            if self
                .pending_exec_stage2_cleanup
                .replace(PendingExecStage2Cleanup {
                    #[cfg(not(test))]
                    custody: std::sync::Arc::clone(&custody),
                    mappings: predecessor_mappings,
                    extents: predecessor_extents,
                    predecessor_aliases,
                    frames: predecessor_frames,
                    mm_root_slot: predecessor_mm_root_slot,
                    mm_access: predecessor_mm_access,
                    predecessor_identity,
                    predecessor_mm: predecessor_cow_identity.mm,
                    shared_projection,
                    armed: true,
                })
                .is_some()
            {
                carrick_fatal!(
                    "hvpatch::exec_commit",
                    "overlapping detached exec predecessor cleanup"
                );
            }
            crate::probes::hvpatch_exec_predecessor_classification(predecessor_classification);
        } else {
            // Preserve mature VMM's historical leak-until-process-exit discipline:
            // the old VM was raw-destroyed and sibling/alias projections may still
            // carry non-owning pointers into these backings.
            std::mem::forget(std::mem::take(&mut self.mappings));
        }
        emit_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStagePhase::DropBackings,
            drop_backings_started,
        );
        let page_tables_started = std::time::Instant::now();
        self.reclaim_authority = ReclaimParkAuthority::Live;
        self.last_exit_class = 0;
        self.last_fault_esr = 0;
        self.is_forked_child = was_forked_child;
        self.forked_no_exec = false; // execve gives a fresh VM: no longer a live forked-no-exec child
        self.shared_process_mm = false;
        self.pending_fork_frame_receipts.clear();
        self.pending_process_aliases.clear();
        // The shared AArch64 engine already builds this editor lazily from the
        // live page-table backing on its first real edit. Keeping an eager
        // manager here cloned the complete 1.8 MiB root-slot table on every exec,
        // even for short-lived compiler children that never mmap/mprotect.
        // Mailbox publication resolves its static boot mapping directly; an
        // in-process fork below explicitly materializes the manager on demand.
        // The =0 hatch restores the eager clone for schedule-identical ABBA.
        if self.persistent_vm_lifecycle {
            self.mm_root_slot = Some(replacement_mm_root_slot);
        }
        let exec_page_tables = if lazy_exec_page_tables_enabled() {
            None
        } else {
            self.mm_root_slot.and_then(|_| {
                let root = plan.stage1_page_tables_base?;
                let table = plan
                    .mappings
                    .iter()
                    .find(|mapping| mapping.guest_start == crate::memory::LINUX_PAGE_TABLES_BASE)?;
                Some(crate::page_table::PageTableManager::new(
                    table.image.as_ref().clone(),
                    root,
                ))
            })
        };
        // Exec replaces the exact MM authority as one unit. Old protections,
        // stage-1 state, and COW metadata cannot survive independently.
        let protections = std::sync::Arc::new(MemoryProtections::default());
        let cow_armed = std::sync::Arc::new(parking_lot::Mutex::new(CowArmedRanges::default()));
        let cow_deferred_publications = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        self.mm_access = MmAccessState::new(
            carrick_aarch64::Stage1Authority::new_with_manager(exec_page_tables),
            protections,
            self.frame_inventory.shared_ledger(),
            cow_armed,
            cow_deferred_publications,
        );
        self.seed_readonly_spans_from_plan(plan);
        // Mature one-process VMM exec gets a fresh VM-local allocator. A
        // persistent HVPatch worker must retain its executor-local allocator
        // on the owner pthread; `allocate_mailbox_for_vcpu` below gives the
        // replacement task a fresh slot from that same bounded arena.
        if !self.persistent_vm_lifecycle {
            self.mailbox_slots = std::sync::Arc::new(MailboxSlotAllocator::new());
        }
        self.last_syscall_nr = None;
        self.last_syscall_orig_x0 = 0;
        emit_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStagePhase::PageTables,
            page_tables_started,
        );

        // Stage-2 is already switched transactionally on HVPatch. Publish its
        // host owners only after predecessor retirement can no longer roll
        // back. Mature VMM still maps through the historical helper here.
        if self.persistent_vm_lifecycle {
            for (mut region, lease) in prepared_exec_regions.drain(..) {
                publish_exec_region_host_owner_in(
                    &custody,
                    &mut region,
                    lease,
                    Some(replacement_mm_root_slot),
                )
                .unwrap_or_else(|error| {
                    carrick_fatal!(
                        "hvpatch::frame_inventory",
                        "publish HVPatch exec global-frame owner: {error}"
                    )
                });
                if let Some(owner) = region.structural_owner.as_ref() {
                    self.mm_access
                        .install_structural_mapping_authority(
                            Some(replacement_mm_root_slot),
                            std::sync::Arc::clone(owner),
                        )
                        .unwrap_or_else(|error| {
                            carrick_fatal!(
                                "hvpatch::mm_authority",
                                "install exec structural MM authority: {error}"
                            )
                        });
                }
                self.mappings.insert(region);
            }
        } else {
            for mapping in &plan.mappings {
                self.mappings
                    .insert(map_region_raw_in(&custody, mapping, false, false)?);
            }
            let replayed =
                replayed_global_frame_owners_for_regions_in(&custody, self.mappings.iter());
            reconcile_global_frame_owners_after_replay_in(&custody, &replayed, false)?;
        }
        if let Some((retired, mut replacement)) = inventory_reservations.take() {
            let staged_inventory_mappings = {
                let mut inventory = self.frame_inventory.lock();
                let mut staged_mappings = Vec::with_capacity(self.mappings.len());
                for region in &self.mappings {
                    let stage2_owner = mapped_region_stage2_owner_identity(region)
                        .unwrap_or_else(|| {
                            carrick_fatal!(
                                "hvpatch::frame_inventory",
                                "HVPatch exec inventory region IPA 0x{:x} has invalid physical owner offset",
                                region.physical_ipa
                            )
                        });
                    let staged = match Self::stage_mapping_in(
                        &custody,
                        &mut inventory,
                        &mut replacement,
                        InventoryMappingStage {
                            gpa: region.physical_ipa,
                            length: region.physical_size as u64,
                            permissions: Self::region_permissions(region),
                            backing: Self::private_backing_identity(),
                            inherited_frame: None,
                            stage2_lease: None,
                            stage2_owner,
                        },
                    ) {
                        Ok(staged) => staged,
                        Err(error) => {
                            carrick_fatal!(
                                "hvpatch::frame_inventory",
                                "stage inventory after HVPatch exec map: {error}"
                            );
                        }
                    };
                    staged_mappings
                        .push(((region.physical_ipa, region.physical_size as u64), staged));
                }
                staged_mappings
            };
            let replacement_commit = replacement.commit(());
            let retired_commit = retired.map(|retired| retired.commit(()));
            let fallback_replacement_commit = if self.registration.is_some() {
                let replacement_challenge = replacement_commit.receipt_challenge();
                let owner_hosts =
                    collect_carrier_stage2_owner_hosts(self.mappings.iter().map(|mapping| {
                        let owner =
                            mapped_region_stage2_owner_identity(mapping).unwrap_or_else(|| {
                                carrick_fatal!(
                                    "hvpatch::frame_inventory",
                                    "exec carrier lease has invalid physical host offset"
                                )
                            });
                        (
                            (mapping.physical_ipa, mapping.physical_size as u64),
                            owner.host_addr,
                        )
                    }))
                    .unwrap_or_else(|error| {
                        carrick_fatal!(
                            "hvpatch::frame_inventory",
                            "collect exec carrier lease owners: {error}"
                        )
                    });
                let mut stage2_leases = Vec::new();
                for region in &mut self.mappings {
                    if let Some(stage2_lease) = region.stage2_lease.take() {
                        stage2_leases.push(stage2_lease);
                    }
                }
                let stage2_lease_keys =
                    register_carrier_stage2_leases(&custody, &mut stage2_leases, &owner_hosts)
                        .unwrap_or_else(|error| {
                            // Replacement inventory already names every candidate.
                            // Fail-stop before unwinding can drop their leases or host
                            // backings out from under that published authority.
                            carrick_fatal!(
                                "hvpatch::frame_inventory",
                                "register carrier stage2 lease for exec: {error}"
                            )
                        });
                let mapped_task_mappings: Vec<HvpatchTaskMappingState> = self
                    .mappings
                    .iter()
                    .map(|mapping| HvpatchTaskMappingState {
                        start: mapping.start,
                        ipa: mapping.ipa,
                        physical_ipa: mapping.physical_ipa,
                        end: mapping.end,
                        host_addr: mapping.host_addr,
                        physical_host_addr: mapping.host_addr,
                        size: mapping.size,
                        physical_size: mapping.physical_size,
                        perms: mapping.perms,
                        guest_writable: mapping.guest_writable,
                        host_mapping: None,
                        structural_owner: mapping.structural_owner.clone(),
                        is_dynamic_alias: mapping.is_dynamic_alias,
                        sharing: mapping.sharing,
                        shared_key_base: mapping.shared_key_base,
                        shared_key_offset: mapping.shared_key_offset,
                        owner_generation: mapping.owner_generation,
                        // Exec re-describes rows this process's live authority
                        // already owns; the replacement never registers them.
                        global_frame_owner_role: GlobalFrameOwnerRole::Borrowed,
                    })
                    .collect();

                let new_authority = HvpatchTaskInventoryAuthority::ProcessPrepared {
                    ledger: std::sync::Arc::clone(&self.frame_inventory.ledger),
                    staged: staged_inventory_mappings,
                    commit: Some(replacement_commit),
                    challenge: Some(replacement_challenge),
                };

                let new_task_mm = std::sync::Arc::new(HvpatchTaskMmAuthority {
                    mappings: mapped_task_mappings,
                    foreign_mm_transport: Some(std::sync::Arc::clone(
                        &self.carrier_foreign_mm_transport,
                    )),
                    mm_root_slot: Some(replacement_mm_root_slot),
                    mm_root_stage2: parking_lot::Mutex::new(None),
                    container_root: self.container_root,
                    inventory: parking_lot::Mutex::new(new_authority),
                    kernel_mm: parking_lot::Mutex::new(None),
                    cow_armed: Some(std::sync::Arc::clone(&self.cow_armed)),
                    cow_deferred_publications: Some(std::sync::Arc::clone(
                        &self.cow_deferred_publications,
                    )),
                    mm_access: parking_lot::Mutex::new(Some(std::sync::Arc::clone(
                        &self.mm_access,
                    ))),
                    pending_publication_receipts: parking_lot::Mutex::new(Vec::new()),
                    pending_receipts: parking_lot::Mutex::new(Vec::new()),
                    alias_receipts: parking_lot::Mutex::new(Vec::new()),
                    last_holder: parking_lot::Mutex::new(HvpatchTaskMmHolder::ExecRebind),
                    #[cfg(test)]
                    drop_order: None,
                });

                let Some(ref mut reg) = self.registration else {
                    carrick_fatal!(
                        "hvpatch::task_backend_lifecycle",
                        "missing registration for HVPatch exec rebind"
                    );
                };
                if let Err(error) = reg.rebind_exec_authority(
                    new_task_mm,
                    replacement_mm_root_slot,
                    stage2_lease_keys,
                    &custody,
                    shared_projection,
                ) {
                    carrick_fatal!(
                        "hvpatch::task_backend_lifecycle",
                        "rebind HVPatch exec MM authority: {error}"
                    );
                }
                None
            } else {
                Some(replacement_commit)
            };
            self.frame_inventory.lock().exec_commits =
                Some((retired_commit, fallback_replacement_commit));
        }
        emit_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStagePhase::MapBackings,
            map_backings_started,
        );

        // Initial vCPU state — same sequence as `new_with_plan`. Zero the GPRs
        // first: Linux's execve contract says the new program starts with all
        // registers clear except for SP and PC. Without this, musl's _start in the
        // new image inherits the previous process's x8 which can decode as a bogus
        // syscall number on the first svc.
        let active_vcpu = pending_exec_vcpu.as_deref().unwrap_or(vcpu);
        let post_publication = (|| -> std::result::Result<MailboxBinding, TrapError> {
            let registers_started = std::time::Instant::now();
            for reg in GPR_TABLE {
                active_vcpu.set_reg(reg, 0).map_err(hvf_error)?;
            }

            let initial_pc = plan.el0_trampoline_entry.unwrap_or(plan.entry);
            active_vcpu
                .set_reg(Reg::PC, initial_pc)
                .map_err(hvf_error)?;
            const AARCH64_PSTATE_EL1H_DAIF_MASKED: u64 = 0x3c5;
            active_vcpu
                .set_reg(Reg::CPSR, AARCH64_PSTATE_EL1H_DAIF_MASKED)
                .map_err(hvf_error)?;
            if let Some(_trampoline) = plan.el0_trampoline_entry {
                const AARCH64_PSTATE_EL0T_DAIF_MASKED: u64 = 0x3c0;
                active_vcpu
                    .set_sys_reg(SysReg::SPSR_EL1, AARCH64_PSTATE_EL0T_DAIF_MASKED)
                    .map_err(hvf_error)?;
                active_vcpu
                    .set_sys_reg(SysReg::ELR_EL1, plan.entry)
                    .map_err(hvf_error)?;
            }
            // C=1, I=1, UCI=1 (bit 26), UCT=1 (bit 15), DZE=1 (bit 14) — EL0 cache-
            // maintenance ops + CTR_EL0/DCZID_EL0 reads + DC ZVA, matching Linux.
            // See the matching comment at the initial-bringup site; glibc 2.41 reads
            // CTR_EL0 at startup, which traps to EL1 (fatal) without UCT.
            // Shared bootstrap SCTLR (via GuestArch; canonical rationale in
            // carrick_mem::arch_sysregs) carries M=1 (stage-1 on); HVF enables M
            // only when stage-1 tables exist (below), so start from the value with
            // M cleared and OR M back in there. HVF leaves SPAN(23) CLEAR and
            // forces PSTATE.PAN=1 (FEAT_PAN3) — SPAN is KVM glue, NOT part of the
            // shared value.
            use carrick_hal::GuestArch as _;
            let boot = <HvfTrapEngine as carrick_hal::ThreadedEngine>::Arch::bootstrap_sysregs();
            let mut sctlr_el1: u64 = boot.sctlr_el1 & !1;
            if let Some(pt_base) = plan.stage1_page_tables_base {
                active_vcpu
                    .set_sys_reg(SysReg::MAIR_EL1, boot.mair_el1)
                    .map_err(hvf_error)?;
                // 48-bit VA, TTBR0 + TTBR1 both active sharing one root. MUST stay
                // identical to the canonical TCR comment/value in new_with_plan.
                // boot.tcr_el1 is the shared bootstrap value via GuestArch
                // (canonical rationale in carrick_mem::arch_sysregs).
                active_vcpu
                    .set_sys_reg(SysReg::TCR_EL1, boot.tcr_el1)
                    .map_err(hvf_error)?;
                let ttbr = pt_base | (u64::from(replacement_asid) << 48);
                active_vcpu
                    .set_sys_reg(SysReg::TTBR0_EL1, ttbr)
                    .map_err(hvf_error)?;
                // TTBR1 shares the same root (see the TCR comment above).
                active_vcpu
                    .set_sys_reg(SysReg::TTBR1_EL1, ttbr)
                    .map_err(hvf_error)?;
                sctlr_el1 |= 1;
            }
            active_vcpu
                .set_sys_reg(SysReg::SCTLR_EL1, sctlr_el1)
                .map_err(hvf_error)?;
            // boot.cpacr_el1 (FPEN=0b11, no FP/SIMD trap at EL0) is shared.
            active_vcpu
                .set_sys_reg(SysReg::CPACR_EL1, boot.cpacr_el1)
                .map_err(hvf_error)?;
            if let Some(vectors_base) = plan.el1_vectors_base {
                active_vcpu
                    .set_sys_reg(SysReg::VBAR_EL1, vectors_base)
                    .map_err(hvf_error)?;
            }
            if let Some(stack_pointer) = plan.initial_stack_pointer {
                active_vcpu
                    .set_sys_reg(SysReg::SP_EL0, stack_pointer)
                    .map_err(hvf_error)?;
            }
            // execve resets TPIDR_EL0 — the new image's musl init will call
            // set_thread_area to initialise it.
            active_vcpu
                .set_sys_reg(SysReg::TPIDR_EL0, 0)
                .map_err(hvf_error)?;

            // Verify post-execve sysreg state through dtrace. If stage-1 isn't on or
            // TTBR0 doesn't point at the new tables, the new process will fault on the
            // first LDAXR.
            let actual_sctlr = active_vcpu.get_sys_reg(SysReg::SCTLR_EL1).unwrap_or(0);
            let actual_ttbr0 = active_vcpu.get_sys_reg(SysReg::TTBR0_EL1).unwrap_or(0);
            let actual_mair = active_vcpu.get_sys_reg(SysReg::MAIR_EL1).unwrap_or(0);
            emit_replace_stage(
                carrick_observability::probes::HvpatchExecReplaceStagePhase::Registers,
                registers_started,
            );
            crate::probes::execve_sysregs(actual_sctlr, actual_ttbr0, actual_mair);
            self.populate_vdso_data_page();
            self.allocate_mailbox_for_vcpu(active_vcpu)
        })();
        let mailbox_started = std::time::Instant::now();
        *mailbox = post_publication.unwrap_or_else(|error| {
            // Backend inventory and non-owning mapping rows already name these
            // frames. Returning would let `owner_rollback` retire their leases
            // while leaving those authorities published, so the only sound
            // outcome after this indeterminate boundary is process fail-stop.
            carrick_fatal!(
                "hvpatch::exec_commit",
                "HVPatch exec post-publication register/mailbox failure: {error}"
            );
        });
        emit_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStagePhase::Mailbox,
            mailbox_started,
        );
        if let Some(new_vcpu) = pending_exec_vcpu {
            let new_vm = pending_exec_vm.take().ok_or_else(|| {
                TrapError::Hypervisor(
                    "exec VM disappeared before committed vCPU handoff".to_owned(),
                )
            })?;
            commit_pending_creation_before_vcpu_handoff(pending_creation)?;
            self._vcpu_guard = Some(vcpu_census().created());
            self.vcpu_id = new_vcpu.id();
            self.vcpu_handle = new_vcpu.get_handle();
            self.publish_live_vcpu();
            std::mem::forget(std::mem::replace(vcpu, new_vcpu.into_inner()));
            replace_destroyed_vm(self, new_vm.into_inner());
        }
        Ok(())
    }
}
