//! Executor-independent preparation of sparse backing. The returned rollback
//! owner keeps stage-2 custody provisional until the caller publishes inventory
//! and stage-1 successfully. No guest permission is granted by preparation.
use super::*;

use carrick_fatal::carrick_fatal;

pub(super) struct PreparedSparseBacking {
    pub(super) physical_host: *mut u8,
    pub(super) semantic_host: *mut u8,
    pub(super) physical_ipa: u64,
    pub(super) semantic_ipa: u64,
    pub(super) physical_len: u64,
    pub(super) physical_size: usize,
    pub(super) stage2_perms: applevisor::memory::MemPerms,
    pub(super) inventory_backing: InventoryBackingIdentity,
    pub(super) page_granular_arm: bool,
    pub(super) owner_generation: u64,
    pub(super) owner_rollback: GlobalFrameOwnerRollback,
}

pub(super) struct PublishedFrameGrant {
    pub(super) region: HvfMappedRegion,
    pub(super) alias: AliasBacking,
    pub(super) ready: carrick_hal::El1FrameGrantReady,
    pub(super) receipt: carrick_hal::FrameInventoryApplyReceipt,
    pub(super) inventory_entry: ((u64, u64), InventoryExtent),
}

pub(super) fn frame_grant_local_lease_is_current(
    lease: (u64, u64, u64),
    mut aliases: impl Iterator<Item = (u64, u64, u64)>,
) -> bool {
    aliases.any(|alias| alias == lease)
}

pub(super) fn frame_grant_predecessors_are_accounted_for(
    replaced: &std::collections::BTreeSet<(u64, u64)>,
    retired: &std::collections::BTreeSet<(u64, u64)>,
    retained: &std::collections::BTreeSet<(u64, u64)>,
    has_inventory: bool,
) -> bool {
    (retired.is_empty() || has_inventory)
        && replaced
            .iter()
            .all(|lease| retired.contains(lease) || retained.contains(lease))
}

pub(super) fn frame_grant_request_is_valid(
    identity: carrick_hal::FrameCowIdentity,
    request: carrick_hal::El1FrameGrantRequest,
) -> bool {
    let Some(end) = request.semantic_base.checked_add(request.len) else {
        return false;
    };
    let access_allowed = match request.access {
        1 => request.permissions != 0,
        2 => request.permissions & 2 != 0,
        4 => request.permissions & 4 != 0,
        _ => false,
    };
    identity.mm != 0
        && identity.asid != 0
        && request.mm_key == identity.mm
        && request.semantic_base.is_multiple_of(4096)
        && request.len != 0
        && request.len <= carrick_el1_abi::EL1_FRAME_GRANT_TARGET_SIZE
        && request.len.is_multiple_of(4096)
        && request.semantic_base <= request.fault_va
        && request.fault_va < end
        && request.permissions != 0
        && request.permissions & !7 == 0
        && access_allowed
}

pub(super) fn prepare(
    custody: std::sync::Arc<CarrierVmCustody>,
    start: u64,
    end: u64,
    backing: SparseExtentBacking<'_>,
) -> Result<PreparedSparseBacking, TrapError> {
    if start >= end || !start.is_multiple_of(4096) || !end.is_multiple_of(4096) {
        return Err(TrapError::Hypervisor(
            "invalid sparse backing extent".to_owned(),
        ));
    }
    const TWO_MIB: u64 = 2 * 1024 * 1024;
    let layout = match backing {
        SparseExtentBacking::FileView { offset, .. } => {
            file_view_allocation_layout(start, end, offset)?
        }
        _ => allocation_layout(start, end, end - start >= TWO_MIB)?,
    };
    let physical_offset = layout.offset;
    let physical_len = layout.length;
    let physical_size =
        usize::try_from(physical_len).map_err(|_| TrapError::MappingTooLarge(physical_len))?;
    let can_pool = physical_len == CowArmedRanges::COMPOUND_SIZE
        && physical_offset == 0
        && matches!(backing, SparseExtentBacking::Anon);
    let pooled_handle = if can_pool {
        custody.frame_pool().and_then(|p| p.allocate_compound())
    } else {
        None
    };

    let (
        physical_host,
        semantic_host,
        physical_ipa,
        semantic_ipa,
        stage2_perms,
        inventory_backing,
        page_granular_arm,
        owner_generation,
    ) = if let Some(handle) = pooled_handle {
        let host_ptr = handle.as_mut_ptr();
        let ipa = handle.ipa();
        unsafe {
            std::ptr::write_bytes(host_ptr, 0, CowArmedRanges::COMPOUND_SIZE as usize);
        }
        carrick_observability::probes::hvpatch_frame_pool_hit(1, ipa);
        let stage2_perms = applevisor::memory::MemPerms::ReadWriteExec;
        let inventory_backing = HvfVmState::private_backing_identity();
        let page_granular_arm = false;
        let owner_generation =
            register_pooled_global_frame_host_owner_in(&custody, handle, u64::from(stage2_perms))?;
        (
            host_ptr,
            host_ptr,
            ipa,
            ipa,
            stage2_perms,
            inventory_backing,
            page_granular_arm,
            owner_generation,
        )
    } else {
        if can_pool {
            carrick_observability::probes::hvpatch_frame_pool_miss(1, 0);
        }
        let host_mapping = match backing {
            SparseExtentBacking::FileView {
                fd, offset, source, ..
            } => {
                let delta = layout.offset;
                let file_offset = libc::off_t::try_from(offset - delta).map_err(|_| {
                    TrapError::Hypervisor(format!("private file view offset 0x{offset:x} overflow"))
                })?;
                match source {
                    carrick_guest_mem::PrivateFileSource::ImmutableLower => {
                        crate::host_mapping::OwnedHostMapping::map_private_file(
                            fd.as_raw_fd(),
                            file_offset,
                            physical_size,
                        )
                        .map_err(|error| {
                            TrapError::Hypervisor(format!(
                                "map immutable private-file view at VA 0x{start:x}: {error}"
                            ))
                        })?
                    }
                    carrick_guest_mem::PrivateFileSource::Mutable => {
                        crate::host_mapping::OwnedHostMapping::map_shared_file(
                            fd.as_raw_fd(),
                            file_offset,
                            physical_size,
                            libc::PROT_READ | libc::PROT_WRITE,
                        )
                        .map_err(|error| {
                            TrapError::Hypervisor(format!(
                                "map writable shared private-file view at VA 0x{start:x}: {error}"
                            ))
                        })?
                    }
                }
            }
            SparseExtentBacking::Anon | SparseExtentBacking::SeededAnon { .. } => {
                crate::host_mapping::OwnedHostMapping::map_shared_anon(
                    physical_size,
                    crate::host_mapping::HostMappingKind::PrivateAnon,
                )
                .map_err(|error| {
                    TrapError::Hypervisor(format!("allocate sparse HVPatch mmap backing: {error}"))
                })?
            }
        };
        let physical_host = host_mapping.as_ptr();
        let semantic_host = unsafe { physical_host.add(physical_offset as usize) };
        let (stage2_perms, inventory_backing, page_granular_arm) = match backing {
            SparseExtentBacking::Anon
            | SparseExtentBacking::SeededAnon { .. }
            | SparseExtentBacking::FileView {
                source: carrick_guest_mem::PrivateFileSource::ImmutableLower,
                ..
            } => (
                applevisor::memory::MemPerms::ReadWriteExec,
                HvfVmState::private_backing_identity(),
                false,
            ),
            SparseExtentBacking::FileView { .. } => {
                // Mutable files use a writable host MAP_SHARED view so HVF can
                // access the VM object and clean pages follow file writes.
                // Stage-1 remains page-granular COW armed so guest and foreign
                // writes first create Carrick-owned private pages. Immutable
                // lower views above already have private host backing; ordinary
                // fork COW still protects those owners when another MM shares them.
                (
                    applevisor::memory::MemPerms::ReadWriteExec,
                    HvfVmState::private_file_view_backing_identity(),
                    true,
                )
            }
        };
        if let SparseExtentBacking::SeededAnon { bytes } = backing {
            let semantic_len = usize::try_from(end - start)
                .map_err(|_| TrapError::MappingTooLarge(end - start))?;
            if bytes.len() > semantic_len {
                return Err(TrapError::Hypervisor(
                    "seeded sparse backing exceeds its semantic extent".to_owned(),
                ));
            }
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), semantic_host, bytes.len());
            }
        }
        let mut lease = GlobalFrameStage2Lease::reserve(physical_len, layout.alignment)?;
        let physical_ipa = lease.base;
        let semantic_ipa = physical_ipa
            .checked_add(physical_offset)
            .ok_or_else(|| TrapError::Hypervisor("sparse mmap IPA overflow".to_owned()))?;
        let map_result = unsafe {
            inventory_hv_vm_map(
                physical_host.cast(),
                physical_ipa,
                physical_size,
                u64::from(stage2_perms),
            )
        };
        if map_result != 0 {
            return Err(TrapError::Hypervisor(format!(
                "map sparse HVPatch mmap IPA 0x{physical_ipa:x}: 0x{map_result:x}"
            )));
        }
        lease.mark_mapped();
        let owner_generation = register_global_frame_host_owner_in(
            &custody,
            lease,
            host_mapping,
            u64::from(stage2_perms),
        )?;
        (
            physical_host,
            semantic_host,
            physical_ipa,
            semantic_ipa,
            stage2_perms,
            inventory_backing,
            page_granular_arm,
            owner_generation,
        )
    };
    let mut owner_rollback = GlobalFrameOwnerRollback::new(custody);
    owner_rollback.record((physical_ipa, physical_len));
    Ok(PreparedSparseBacking {
        physical_host,
        semantic_host,
        physical_ipa,
        semantic_ipa,
        physical_len,
        physical_size,
        stage2_perms,
        inventory_backing,
        page_granular_arm,
        owner_generation,
        owner_rollback,
    })
}

/// Prepare and authenticate one EL1-owned stage-1 grant without editing a
/// host stage-1 descriptor. Every fallible operation precedes alias
/// publication; failed inventory application rolls back the backend ledger,
/// while the prepared owner's RAII guard retires stage-2 custody.
pub(super) fn publish_frame_grant(
    context: &PublicationContext<'_>,
    request: carrick_hal::El1FrameGrantRequest,
    retirement: Option<&InventoryLeaseRetirement>,
    _registry: &crate::fork_quiesce::FrameRegistryGuard<'_>,
) -> Result<PublishedFrameGrant, TrapError> {
    publish_frame_grant_backing(
        context,
        request,
        retirement,
        SparseExtentBacking::Anon,
        _registry,
    )
}

fn publish_frame_grant_backing(
    context: &PublicationContext<'_>,
    request: carrick_hal::El1FrameGrantRequest,
    retirement: Option<&InventoryLeaseRetirement>,
    backing: SparseExtentBacking<'_>,
    _registry: &crate::fork_quiesce::FrameRegistryGuard<'_>,
) -> Result<PublishedFrameGrant, TrapError> {
    let end = request
        .semantic_base
        .checked_add(request.len)
        .ok_or_else(|| TrapError::Hypervisor("EL1 frame-grant range overflow".to_owned()))?;
    let semantic_len =
        usize::try_from(request.len).map_err(|_| TrapError::MappingTooLarge(request.len))?;
    let retirement_events = retirement.map_or(0, InventoryLeaseRetirement::event_count);
    let mut reservation = context
        .authority
        .reserve(1, 1, 2usize.saturating_add(retirement_events))
        .map_err(|error| {
            TrapError::Hypervisor(format!("reserve EL1 frame-grant inventory: {error}"))
        })?;
    if let Some(retirement) = retirement {
        HvfVmState::stage_inventory_lease_retirement(&mut reservation, retirement)?;
    }
    let PreparedSparseBacking {
        physical_host,
        semantic_host,
        physical_ipa,
        semantic_ipa,
        physical_len,
        physical_size,
        stage2_perms,
        inventory_backing,
        page_granular_arm,
        owner_generation,
        owner_rollback,
    } = prepare(
        std::sync::Arc::clone(&context.custody),
        request.semantic_base,
        end,
        backing,
    )?;
    if page_granular_arm {
        carrick_fatal!(
            "hvpatch::el1_frame_grant",
            "anonymous EL1 frame grant unexpectedly requires page-granular COW arming"
        );
    }
    let inventory_mapping = {
        let mut inventory = context.state.frame_inventory.ledger.lock();
        HvfVmState::stage_mapping_in(
            &context.custody,
            &mut inventory,
            &mut reservation,
            InventoryMappingStage {
                gpa: physical_ipa,
                length: physical_len,
                permissions: carrick_hal::MemPerms {
                    read: true,
                    write: true,
                    exec: true,
                },
                backing: inventory_backing,
                inherited_frame: None,
                stage2_lease: Some((physical_ipa, physical_len)),
                stage2_owner: InventoryStage2OwnerIdentity {
                    host_addr: physical_host as usize,
                    generation: owner_generation,
                },
            },
        )?
    };
    let inventory_entry = ((physical_ipa, physical_len), inventory_mapping);
    let physical_length = carrick_hal::FrameLength::from_mapping_extent(
        std::num::NonZeroU64::new(physical_len).unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::el1_frame_grant",
                "prepared EL1 frame grant has zero physical length"
            );
        }),
    );
    let apply_grant = |commit: carrick_hal::FrameInventoryCommit<()>| {
        let challenge = commit.receipt_challenge();
        context
            .authority
            .apply_frame_grant(
                commit,
                inventory_mapping.mapping,
                inventory_mapping.frame,
                carrick_guest_mem::Gpa(physical_ipa),
                physical_length,
            )
            .map(|applied| (challenge, applied))
            .map_err(|error| TrapError::Hypervisor(error.to_string()))
    };
    // A folded predecessor retirement publishes and drops its backend
    // references as one step with the grant (`apply_inventory_lease_retirement`).
    let applied = match retirement {
        None => apply_grant(reservation.commit(())),
        Some(retirement) => HvfVmState::apply_inventory_lease_retirement(
            &context.state.frame_inventory.ledger,
            retirement,
            reservation,
            apply_grant,
        ),
    };
    let (challenge, (receipt, authenticated_owner_generation)) = match applied {
        Ok(applied) => applied,
        Err(error) => {
            if let Err(rollback) = HvfVmState::rollback_unpublished_mappings(
                &mut context.state.frame_inventory.ledger.lock(),
                &[inventory_entry],
            ) {
                carrick_fatal!(
                    "hvpatch::el1_frame_grant",
                    "backend frame-grant rollback failed after kernel refusal: {rollback}"
                );
            }
            return Err(TrapError::Hypervisor(format!(
                "apply EL1 frame-grant inventory: {error}"
            )));
        }
    };
    let expected_mm = std::num::NonZeroU64::new(request.mm_key).unwrap_or_else(|| {
        carrick_fatal!(
            "hvpatch::el1_frame_grant",
            "EL1 frame-grant request reached inventory with zero MM identity"
        );
    });
    if !challenge.authenticate_apply(&receipt, expected_mm)
        || !receipt.authorizes(inventory_mapping.mapping, inventory_mapping.frame)
        || authenticated_owner_generation.raw_for_probe() != owner_generation
    {
        if retirement.is_some() {
            carrick_fatal!(
                "hvpatch::el1_frame_grant",
                "combined replacement grant failed post-commit authentication: mm={} semantic_base=0x{:x} len=0x{:x}",
                request.mm_key,
                request.semantic_base,
                request.len,
            );
        }
        if let Err(error) = context.authority.rollback_frame_grant(&receipt) {
            carrick_fatal!(
                "hvpatch::el1_frame_grant",
                "kernel frame-grant rollback failed after receipt mismatch: {error}"
            );
        }
        if let Err(error) = HvfVmState::rollback_unpublished_mappings(
            &mut context.state.frame_inventory.ledger.lock(),
            &[inventory_entry],
        ) {
            carrick_fatal!(
                "hvpatch::el1_frame_grant",
                "backend frame-grant rollback failed after receipt mismatch: {error}"
            );
        }
        return Err(TrapError::Hypervisor(
            "EL1 frame-grant receipt or owner generation failed authentication".to_owned(),
        ));
    }

    let sharing = GuestMappingSharing::Private;
    let alias = AliasBacking {
        start: request.semantic_base,
        ipa: semantic_ipa,
        host_addr: semantic_host as usize,
        size: semantic_len,
        physical_ipa,
        physical_host_addr: physical_host as usize,
        physical_size,
        perms: u64::from(stage2_perms),
        guest_writable: true,
        sharing,
        ownership_scope: alias_ownership_scope(
            sharing,
            context.mm_root_slot,
            context.container_root,
        ),
        inventory_backing,
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation,
    };
    let region = HvfMappedRegion {
        start: request.semantic_base,
        ipa: semantic_ipa,
        physical_ipa,
        end,
        host_addr: semantic_host,
        size: semantic_len,
        physical_size,
        perms: stage2_perms,
        memory: None,
        host_mapping: None,
        structural_owner: None,
        stage2_lease: None,
        is_dynamic_alias: true,
        sharing,
        guest_writable: true,
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation,
    };
    let ready = carrick_hal::El1FrameGrantReady {
        physical_ipa: semantic_ipa,
        frame_id: inventory_mapping.frame.raw(),
        mapping_id: inventory_mapping.mapping.raw(),
        owner_generation,
        inventory_revision: receipt.revision(),
    };
    owner_rollback.commit();
    Ok(PublishedFrameGrant {
        region,
        alias,
        ready,
        receipt,
        inventory_entry,
    })
}

#[derive(Debug)]
struct AllocationLayout {
    offset: u64,
    length: u64,
    alignment: u64,
}

fn allocation_layout(
    start: u64,
    end: u64,
    block_congruence: bool,
) -> Result<AllocationLayout, TrapError> {
    if start >= end || !start.is_multiple_of(4096) || !end.is_multiple_of(4096) {
        return Err(TrapError::Hypervisor(
            "invalid sparse allocation range".to_owned(),
        ));
    }
    // Single-page demand allocation needs only host-page congruence. Using
    // the VA's 2 MiB offset here allocates up to 2 MiB for each 4 KiB fault.
    // Bulk anonymous mappings retain their existing block congruence.
    let alignment = if block_congruence {
        2 * 1024 * 1024
    } else {
        HVF_PAGE_SIZE
    };
    let offset = start & (alignment - 1);
    let length = align_up(
        offset
            .checked_add(end - start)
            .ok_or_else(|| TrapError::Hypervisor("sparse allocation overflow".to_owned()))?,
        HVF_PAGE_SIZE,
    )?;
    Ok(AllocationLayout {
        offset,
        length,
        alignment,
    })
}

fn file_view_allocation_layout(
    start: u64,
    end: u64,
    offset: u64,
) -> Result<AllocationLayout, TrapError> {
    if start >= end
        || !start.is_multiple_of(4096)
        || !end.is_multiple_of(4096)
        || !offset.is_multiple_of(4096)
    {
        return Err(TrapError::Hypervisor(
            "invalid sparse private-file view range".to_owned(),
        ));
    }
    // The host view is aligned around the file offset, not the semantic VA.
    // Stage-1 maps the guest's 4 KiB VA to this independently aligned IPA.
    let delta = offset & (HVF_PAGE_SIZE - 1);
    let length = align_up(
        delta
            .checked_add(end - start)
            .ok_or_else(|| TrapError::Hypervisor("private file view overflow".to_owned()))?,
        HVF_PAGE_SIZE,
    )?;
    Ok(AllocationLayout {
        offset: delta,
        length,
        alignment: HVF_PAGE_SIZE,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_live_physical_owner_without_an_mm_alias_is_not_a_grant_predecessor() {
        let lease = (0x8000, 16384, 7);
        assert!(!frame_grant_local_lease_is_current(
            lease,
            std::iter::empty()
        ));
        assert!(!frame_grant_local_lease_is_current(
            lease,
            [(0x8000, 16384, 8)].into_iter()
        ));
        assert!(frame_grant_local_lease_is_current(
            lease,
            [lease].into_iter()
        ));
    }

    #[test]
    fn partial_frame_grant_keeps_authenticated_predecessor_fragments() {
        use std::collections::BTreeSet;
        let replaced = BTreeSet::from([(0x8000, 16384)]);
        let none = BTreeSet::new();
        assert!(frame_grant_predecessors_are_accounted_for(
            &replaced, &none, &replaced, false,
        ));
        assert!(!frame_grant_predecessors_are_accounted_for(
            &replaced, &none, &none, false,
        ));
        assert!(frame_grant_predecessors_are_accounted_for(
            &replaced, &replaced, &none, true,
        ));
        assert!(!frame_grant_predecessors_are_accounted_for(
            &replaced, &replaced, &none, false,
        ));
    }

    #[test]
    fn frame_grant_backend_accepts_copyout_without_a_mailbox_claim() {
        let identity = carrick_hal::FrameCowIdentity {
            linux_pid: 7,
            linux_tid: 8,
            mm: 9,
            asid: 10,
        };
        let request = carrick_hal::El1FrameGrantRequest {
            mm_key: 9,
            fault_va: 0x4000,
            access: 2,
            semantic_base: 0x4000,
            len: 4096,
            permissions: 3,
        };
        assert!(frame_grant_request_is_valid(identity, request));
    }

    #[test]
    fn frame_grant_backend_accepts_only_one_exact_coherent_mm_span() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let identity = carrick_hal::FrameCowIdentity {
            linux_pid: 7,
            linux_tid: 8,
            mm: 9,
            asid: 10,
        };
        let request = carrick_hal::El1FrameGrantRequest {
            mm_key: identity.mm,
            fault_va: 0x4000_4123,
            access: 2,
            semantic_base: 0x4000_0000,
            len: 0x20_0000,
            permissions: 3,
        };
        assert!(frame_grant_request_is_valid(identity, request));
        for invalid in [
            carrick_hal::El1FrameGrantRequest {
                mm_key: 12,
                ..request
            },
            carrick_hal::El1FrameGrantRequest {
                fault_va: request.semantic_base + request.len,
                ..request
            },
            carrick_hal::El1FrameGrantRequest {
                semantic_base: request.semantic_base + 1,
                ..request
            },
            carrick_hal::El1FrameGrantRequest { len: 0, ..request },
            carrick_hal::El1FrameGrantRequest {
                len: carrick_el1_abi::EL1_FRAME_GRANT_TARGET_SIZE + 4096,
                ..request
            },
            carrick_hal::El1FrameGrantRequest {
                access: 4,
                ..request
            },
        ] {
            assert!(!frame_grant_request_is_valid(identity, invalid));
        }
    }

    #[test]
    fn anonymous_first_touch_never_allocates_a_block_of_padding() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        for page in (0..512_u32).rev() {
            let start = u64::from(page) * 4096;
            let layout = allocation_layout(start, start + 4096, false).unwrap();
            assert_eq!(layout.length, HVF_PAGE_SIZE, "4 KiB fault at {start:#x}");
            assert_eq!(layout.alignment, HVF_PAGE_SIZE);
            assert_eq!(layout.offset, start % HVF_PAGE_SIZE);
        }
    }

    #[test]
    fn bulk_anonymous_views_preserve_block_congruence() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        for start in [0, 4096, TWO_MIB - 4096, TWO_MIB] {
            let layout = allocation_layout(start, start + 3 * TWO_MIB, true).unwrap();
            assert_eq!(layout.alignment, TWO_MIB);
            assert_eq!(layout.offset, start % TWO_MIB);
            assert!(layout.length >= layout.offset + 3 * TWO_MIB);
            assert!(layout.length < layout.offset + 3 * TWO_MIB + HVF_PAGE_SIZE);
        }
    }

    #[test]
    fn file_view_layout_is_one_host_mapping_with_semantic_delta() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        for (start, offset, semantic_len, expected_len) in [
            (0, 0, 4096, HVF_PAGE_SIZE),
            (4096, 4096, 4096, HVF_PAGE_SIZE),
            (3 * 4096, 3 * 4096, 8192, 2 * HVF_PAGE_SIZE),
            (HVF_PAGE_SIZE, 0, 5 * 4096, 2 * HVF_PAGE_SIZE),
            (0, 4096, 4096, HVF_PAGE_SIZE),
            (4096, 0, 4096, HVF_PAGE_SIZE),
            (8192, 12288, 8192, 2 * HVF_PAGE_SIZE),
        ] {
            let layout = file_view_allocation_layout(start, start + semantic_len, offset).unwrap();
            assert_eq!(layout.offset, offset & (HVF_PAGE_SIZE - 1));
            assert_eq!(layout.length, expected_len);
            assert_eq!(layout.alignment, HVF_PAGE_SIZE);
        }
        assert!(file_view_allocation_layout(0, 4096, 1).is_err());
    }

    #[test]
    fn sparse_allocation_rejects_invalid_semantic_ranges() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        for (start, end) in [(0, 0), (4096, 0), (1, 4096), (0, 4097)] {
            assert!(allocation_layout(start, end, false).is_err());
        }
    }
}

impl MmAccessState {
    /// Publish missing structural arenas into this MM's custody. Callers hold
    /// exact-MM mutation exclusion and topology; executor rows are only caches.
    pub(super) fn publish_stage1_extension_arenas(
        &self,
        custody: &std::sync::Arc<CarrierVmCustody>,
        manager: &carrick_mmu_core::aarch64::PageTableManager,
        root_perms: applevisor::memory::MemPerms,
    ) -> Result<Vec<HvfMappedRegion>, TrapError> {
        let mut published = Vec::new();
        self.publish_stage1_extension_arenas_into(custody, manager, root_perms, &mut published)?;
        Ok(published)
    }

    fn publish_stage1_extension_arenas_into(
        &self,
        custody: &std::sync::Arc<CarrierVmCustody>,
        manager: &carrick_mmu_core::aarch64::PageTableManager,
        root_perms: applevisor::memory::MemPerms,
        published: &mut Vec<HvfMappedRegion>,
    ) -> Result<(), TrapError> {
        const TWO_MIB: usize = 2 * 1024 * 1024;
        for base in manager.extension_arena_bases() {
            if self.structural_owners.read().contains_key(&(base, TWO_MIB)) {
                continue;
            }

            // A stage-1 extension arena is a 2 MiB slot out of the same
            // root-slot arena the carrier pre-maps, so it must come from that
            // pool: mapping private backing at a pre-mapped IPA fails
            // (`HV_ERROR`), and this path lowers that failure to a guest
            // SIGSEGV (CPython's `test_compiler_recursion_limit` grew the mmap
            // arena until its tables needed a new extension).
            let pooled = custody
                .root_slot_pool()
                .and_then(|pool| pool.allocate_slot_at(base));
            let (host_addr, host_mapping, mut lease, pooled) = match pooled {
                Some(handle) => {
                    let host_addr = handle.as_mut_ptr();
                    let mut lease = GlobalFrameStage2Lease::fixed(base, TWO_MIB as u64);
                    lease.mark_pre_mapped();
                    (host_addr, None, lease, Some(handle))
                }
                None => {
                    if custody
                        .root_slot_pool()
                        .is_some_and(|pool| pool.contains_ipa(base))
                    {
                        return Err(TrapError::Hypervisor(format!(
                            "stage-1 extension arena IPA 0x{base:x} is still held by the root-slot pool"
                        )));
                    }
                    let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                        TWO_MIB,
                        crate::host_mapping::HostMappingKind::PerMmKernelState,
                    )
                    .map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "allocate stage-1 extension arena host backing: {error}"
                        ))
                    })?;

                    let rc = unsafe {
                        inventory_hv_vm_map(
                            host_mapping.as_ptr().cast(),
                            base,
                            TWO_MIB,
                            u64::from(root_perms),
                        )
                    };
                    if rc != 0 {
                        return Err(TrapError::ChildMapFailed {
                            host_addr: host_mapping.as_ptr() as u64,
                            guest_start: base,
                            size: TWO_MIB,
                            code: rc as u32,
                        });
                    }

                    let mut lease = GlobalFrameStage2Lease::fixed(base, TWO_MIB as u64);
                    lease.mark_mapped();
                    let host_addr = host_mapping.as_ptr();
                    (host_addr, Some(host_mapping), lease, None)
                }
            };
            let _ = &mut lease;

            let mut region = HvfMappedRegion {
                start: base,
                end: base + TWO_MIB as u64,
                ipa: base,
                physical_ipa: base,
                physical_size: TWO_MIB,
                owner_generation: 0,
                host_addr,
                size: TWO_MIB,
                perms: root_perms,
                memory: None,
                host_mapping,
                structural_owner: None,
                stage2_lease: None,
                is_dynamic_alias: false,
                sharing: GuestMappingSharing::Private,
                guest_writable: true,
                shared_key_base: None,
                shared_key_offset: 0,
            };

            let _ = match pooled {
                Some(handle) => {
                    publish_pooled_exec_root_owner_in(custody, &mut region, lease, handle)?
                }
                None => publish_exec_region_host_owner_in(custody, &mut region, lease, None)?,
            };

            if let Some(owner) = &region.structural_owner {
                self.install_structural_mapping_authority(None, std::sync::Arc::clone(owner))?;
            }

            published.push(region);
        }
        Ok(())
    }
}

/// Exact-MM local publication permit. Only this constructor acquires exclusion;
/// callers cannot substitute an arbitrary FrameCowQuiesce implementation.
pub(super) struct PublicationContext<'a> {
    mm_key: std::num::NonZeroU64,
    state: std::sync::Arc<MmAccessState>,
    custody: std::sync::Arc<CarrierVmCustody>,
    authority: std::sync::Arc<dyn carrick_hal::FrameCowAuthority>,
    mm_root_slot: Option<(u64, u64)>,
    container_root: ContainerRootToken,
    _exclusion: Option<Box<dyn carrick_hal::FrameCowQuiesce>>,
    _invocation: Option<&'a carrick_hal::ForeignMmInvocation>,
    foreign: Option<CarrierForeignMmSnapshot>,
}

impl<'a> PublicationContext<'a> {
    /// A physical grant selected by the target EL1 owner. No host policy
    /// snapshot or caller-vCPU identity can authorize this constructor. The
    /// guest revalidates the generation and window before exposing leaves.
    pub(super) fn for_transfer(
        state: std::sync::Arc<MmAccessState>,
        custody: std::sync::Arc<CarrierVmCustody>,
        target: carrick_aarch64::user_transfer::TransferTarget,
        window: carrick_el1_abi::PortalGrantWindow,
    ) -> Result<Self, TrapError> {
        let invalid =
            || TrapError::Hypervisor("EL1 transfer grant target authority mismatch".to_owned());
        if target.handle().carrier() != custody.transfer_carrier
            || window.operation.carrier != target.handle().carrier()
            || window.operation.mm != target.handle().mm()
            || window.operation.incarnation != target.handle().incarnation()
            || !window.valid()
        {
            return Err(invalid());
        }
        let binding = state.cow_runtime.read().clone().ok_or_else(invalid)?;
        let root = target.ttbr0() & 0x0000_ffff_ffff_f000;
        let asid = (target.ttbr0() >> 48) as u16;
        if binding.identity.mm != target.handle().mm().raw()
            || binding.identity.asid != asid
            || binding.mm_root_slot.map(|root| root.0) != Some(root)
            || !binding.persistent_vm_lifecycle
            || state.page_tables_authority().live_descriptor_owner()
                != carrick_mmu_core::aarch64::LiveDescriptorOwner::Guest
        {
            return Err(invalid());
        }
        Ok(Self {
            mm_key: std::num::NonZeroU64::new(target.handle().mm().raw()).ok_or_else(invalid)?,
            state,
            custody,
            authority: binding.authority,
            mm_root_slot: binding.mm_root_slot,
            container_root: binding.container_root,
            _exclusion: None,
            _invocation: None,
            foreign: None,
        })
    }

    pub(super) fn for_foreign(
        state: std::sync::Arc<MmAccessState>,
        custody: std::sync::Arc<CarrierVmCustody>,
        invocation: &'a carrick_hal::ForeignMmInvocation,
        requested: &CarrierForeignMmSnapshot,
        deadline: std::time::Instant,
    ) -> Result<Self, carrick_hal::ForeignMmTransportError> {
        let binding = state
            .cow_runtime
            .try_read_until(deadline)
            .ok_or(carrick_hal::ForeignMmTransportError::TimedOut)?
            .clone()
            .ok_or(carrick_hal::ForeignMmTransportError::MissingBinding)?;
        if binding.identity.mm != requested.mm.raw_for_probe()
            || binding.identity.asid != requested.binding.asid.raw_for_probe()
            || binding.mm_root_slot.map(|r| r.0) != Some(requested.binding.stage1_root.raw())
            || !binding.persistent_vm_lifecycle
        {
            return Err(carrick_hal::ForeignMmTransportError::MissingBinding);
        }
        Ok(Self {
            mm_key: std::num::NonZeroU64::new(requested.mm.raw_for_probe())
                .ok_or(carrick_hal::ForeignMmTransportError::MissingBinding)?,
            state,
            custody,
            authority: binding.authority,
            mm_root_slot: binding.mm_root_slot,
            container_root: binding.container_root,
            _exclusion: None,
            _invocation: Some(invocation),
            foreign: Some(requested.clone()),
        })
    }

    pub(super) fn for_local(
        state: std::sync::Arc<MmAccessState>,
        custody: std::sync::Arc<CarrierVmCustody>,
        identity: carrick_hal::FrameCowIdentity,
    ) -> Result<Self, TrapError> {
        let binding = state.cow_runtime.read().clone().ok_or_else(|| {
            TrapError::Hypervisor("sparse publication has no MM authority binding".to_owned())
        })?;
        if identity.mm == 0
            || identity.asid == 0
            || identity.mm != binding.identity.mm
            || identity.asid != binding.identity.asid
        {
            return Err(TrapError::Hypervisor(
                "sparse publication MM identity mismatch".to_owned(),
            ));
        }
        let exclusion = binding.authority.quiesce().map_err(|error| {
            TrapError::Hypervisor(format!("quiesce sparse publication MM: {error}"))
        })?;
        {
            // Re-read after quiescing and authenticate the SEMANTIC MM identity
            // — mm, asid, stage-1 root slot, container, persistent lifecycle —
            // NOT the authority's `Arc` pointer.
            //
            // The MM-scoped frame-COW runtime binding carries a per-TASK
            // authority (its `identity.linux_tid` and diagnostic `tid` are the
            // task that last ran), so every sibling thread's first run and
            // every exec REBINDS it with a fresh, equivalent authority object.
            // A `ptr_eq` here therefore treated an unrelated sibling being
            // created — a load-coupled event — as "the MM changed" and refused
            // a correct first-touch publication, which the runtime lowered to
            // SEGV_MAPERR (Go `runtime.persistentalloc1`, ~1 in 8 `go build`).
            // The quiesce is valid regardless of which equivalent authority
            // minted it: `KernelFrameCowAuthority::quiesce` routes through the
            // `PtQuiesce` barrier (the MM's occupancy fence) OWNED BY THE SHARED
            // `DispatchMmAuthority` for this mm, so the guard covers the mm, not
            // an authority instance. The foreign-mm path (`for_foreign`) already
            // authenticates by these same semantic fields and no pointer.
            let current = state.cow_runtime.read();
            if !current.as_ref().is_some_and(|current| {
                current.identity.mm == identity.mm
                    && current.identity.asid == identity.asid
                    && current.mm_root_slot == binding.mm_root_slot
                    && current.container_root == binding.container_root
                    && current.persistent_vm_lifecycle
            }) {
                let describe = |b: &MmCowRuntimeBinding| {
                    format!(
                        "mm={} asid={} tid={} root={:x?} container={:?} lifecycle={}",
                        b.identity.mm,
                        b.identity.asid,
                        b.identity.linux_tid,
                        b.mm_root_slot,
                        b.container_root,
                        b.persistent_vm_lifecycle,
                    )
                };
                return Err(TrapError::Hypervisor(format!(
                    "sparse publication MM identity changed during quiesce: quiesced through [{}], now [{}]",
                    describe(&binding),
                    current
                        .as_ref()
                        .map_or_else(|| "unbound".to_owned(), describe),
                )));
            }
        }
        Ok(Self {
            mm_key: std::num::NonZeroU64::new(identity.mm)
                .ok_or_else(|| TrapError::Hypervisor("zero sparse MM".to_owned()))?,
            state,
            custody,
            authority: binding.authority,
            mm_root_slot: binding.mm_root_slot,
            container_root: binding.container_root,
            _exclusion: Some(exclusion),
            _invocation: None,
            foreign: None,
        })
    }
}

pub(super) struct PublishedSparseExtent {
    pub(super) region: HvfMappedRegion,
    pub(super) extension_regions: Vec<HvfMappedRegion>,
    pub(super) page_granular_arm: bool,
    pub(super) foreign_receipt: Option<CarrierForeignCowReceipt>,
}

/// Publish backing, inventory and stage-1 through one MM-owned implementation.
/// The local adapter only updates its cache and completes deferred protection.
pub(super) fn publish(
    context: &PublicationContext<'_>,
    start: u64,
    end: u64,
    backing: SparseExtentBacking<'_>,
    flush_stage1: &mut dyn carrick_aarch64::vmm::Stage1Services,
) -> Result<PublishedSparseExtent, TrapError> {
    publish_replacing(context, start, end, backing, flush_stage1, &mut || {})
}

/// Retain the caller's old ownership through every fallible publication step.
/// The infallible retirement callback runs after commit and before alias insertion.
pub(super) fn publish_replacing(
    context: &PublicationContext<'_>,
    start: u64,
    end: u64,
    backing: SparseExtentBacking<'_>,
    flush_stage1: &mut dyn carrick_aarch64::vmm::Stage1Services,
    retire_previous: &mut dyn FnMut(),
) -> Result<PublishedSparseExtent, TrapError> {
    let guest_lane = context
        .state
        .page_tables_authority()
        .live_descriptor_owner()
        == carrick_mmu_core::aarch64::LiveDescriptorOwner::Guest;
    if guest_lane && !flush_stage1.guest_publication_available() {
        return Err(TrapError::Hypervisor(
            "guest sparse publication requires its driving vCPU".to_owned(),
        ));
    }
    #[cfg(debug_assertions)]
    const PAGE_SIZE: u64 = 4096;
    #[cfg(debug_assertions)]
    const VALID: u64 = 1;
    #[cfg(debug_assertions)]
    const AP_MASK: u64 = 0b11 << 6;
    #[cfg(debug_assertions)]
    const AP_USER_RO: u64 = 0b11 << 6;
    #[cfg(debug_assertions)]
    const NON_GLOBAL: u64 = 1 << 11;
    let semantic_len = usize::try_from(
        end.checked_sub(start)
            .filter(|len| *len != 0)
            .ok_or_else(|| TrapError::Hypervisor("invalid sparse publication range".to_owned()))?,
    )
    .map_err(|_| TrapError::MappingTooLarge(end - start))?;
    let mut extension_regions = Vec::new();
    let mut reservation = context.authority.reserve(1, 1, 2).map_err(|error| {
        TrapError::Hypervisor(format!("reserve sparse HVPatch mmap inventory: {error}"))
    })?;

    let PreparedSparseBacking {
        physical_host,
        semantic_host,
        physical_ipa,
        semantic_ipa,
        physical_len,
        physical_size,
        stage2_perms,
        inventory_backing,
        page_granular_arm,
        owner_generation,
        owner_rollback,
    } = prepare(std::sync::Arc::clone(&context.custody), start, end, backing)?;
    const TWO_MIB: u64 = 2 * 1024 * 1024;

    let (inventory_mapping, foreign_receipt) = if guest_lane {
        use carrick_mmu_core::aarch64::descriptor_txn::{AliasAccess, DescriptorOp, PageSpan};
        let stage = InventoryMappingStage {
            gpa: physical_ipa,
            length: physical_len,
            permissions: carrick_hal::MemPerms {
                read: true,
                write: !page_granular_arm,
                exec: true,
            },
            backing: inventory_backing,
            inherited_frame: None,
            stage2_lease: Some((physical_ipa, physical_len)),
            stage2_owner: InventoryStage2OwnerIdentity {
                host_addr: physical_host as usize,
                generation: owner_generation,
            },
        };
        // A foreign first write is published user-accessible at once (the
        // host lane's `set_rw`); the grant is its final kernel commit, so the
        // kernel mints the foreign proof with it.
        let (mut prepared, access) = if context.foreign.is_some() {
            let semantic = std::num::NonZeroUsize::new(semantic_len).ok_or_else(|| {
                TrapError::Hypervisor("empty foreign sparse publication".to_owned())
            })?;
            (
                super::cow_engine::GuestPreparedBacking::prepare_owned_foreign(
                    context.custody.clone(),
                    context.authority.clone(),
                    context.state.frame_inventory.ledger.clone(),
                    reservation,
                    context.mm_key,
                    stage,
                    owner_rollback,
                    (carrick_guest_mem::GuestVa(start), semantic),
                )?,
                AliasAccess::User {
                    writable: true,
                    executable: context
                        .state
                        .protections
                        .range_executable(start, semantic_len),
                },
            )
        } else {
            (
                super::cow_engine::GuestPreparedBacking::prepare_owned(
                    context.custody.clone(),
                    context.authority.clone(),
                    context.state.frame_inventory.ledger.clone(),
                    reservation,
                    context.mm_key,
                    stage,
                    owner_rollback,
                )?,
                AliasAccess::Deferred,
            )
        };
        let backing = prepared.backing()?;
        let tables = context.state.page_tables_authority();
        let mut current = start;
        while current < end {
            let count = (end - current).min(TWO_MIB);
            let op = DescriptorOp::MapAlias {
                access,
                span: PageSpan::new(current, count),
                target_ipa: carrick_mmu_core::aarch64::SubstrateGpa(
                    semantic_ipa + (current - start),
                ),
                backing,
            };
            let txn = match tables.prepare_guest_descriptor_txn(context.mm_key, op) {
                Ok(txn) => txn,
                Err(error) if current == start => {
                    return Err(TrapError::Hypervisor(format!(
                        "prepare guest sparse publication: {error:?}"
                    )));
                }
                Err(error) => carrick_fatal!(
                    "hvpatch::sparse_materialization",
                    "partially published guest sparse extent: {error:?}"
                ),
            };
            // Only a clean refusal of the FIRST chunk leaves nothing live;
            // `prepared` then rolls back on return. A later chunk's refusal
            // is a partial publication, and anything else is unknown.
            let receipt = match flush_stage1.publish(&txn) {
                Ok(receipt) => receipt,
                Err(error) => {
                    let clean = error.into_clean_refusal();
                    match clean {
                        Ok(refusal) if current == start => return Err(refusal),
                        Ok(error) | Err(error) => carrick_fatal!(
                            "hvpatch::sparse_materialization",
                            "guest sparse publication lacks verified completion: {error}"
                        ),
                    }
                }
            };
            if *receipt.txn() != txn {
                carrick_fatal!(
                    "hvpatch::sparse_materialization",
                    "guest sparse receipt names another transaction"
                );
            }
            current += count;
        }
        prepared.commit();
        let foreign_receipt = match (&context.foreign, prepared.take_foreign_proof()) {
            (None, None) => None,
            (Some(requested), Some(proof)) => {
                let mut mapping_ids = requested.mapping_ids.clone();
                mapping_ids.retain(|id| !proof.unmapped.contains(id));
                mapping_ids.extend(proof.prepared.iter().copied());
                mapping_ids.sort_unstable();
                mapping_ids.dedup();
                let mut snapshot = requested.clone();
                snapshot.mapping_ids = mapping_ids;
                snapshot.frame_inventory_revision =
                    carrick_hal::ForeignFrameInventoryRevision::from_authority_raw(
                        prepared.revision(),
                    );
                Some(CarrierForeignCowReceipt {
                    snapshot,
                    start: carrick_guest_mem::GuestVa(start),
                    len: semantic_len,
                    mapping: prepared.extent.mapping,
                    frame: prepared.extent.frame,
                    physical_base: carrick_guest_mem::Gpa(physical_ipa),
                    physical_len,
                    owner_generation: proof.owner_generation,
                    kernel_proof: proof.kernel_proof,
                })
            }
            _ => carrick_fatal!(
                "hvpatch::sparse_materialization",
                "guest sparse grant proof does not match its publication's MM"
            ),
        };
        (prepared.extent, foreign_receipt)
    } else {
        let inventory_mapping = {
            let mut inventory = context.state.frame_inventory.ledger.lock();
            HvfVmState::stage_mapping_in(
                &context.custody,
                &mut inventory,
                &mut reservation,
                InventoryMappingStage {
                    gpa: physical_ipa,
                    length: physical_len,
                    permissions: carrick_hal::MemPerms {
                        read: true,
                        write: !page_granular_arm,
                        exec: true,
                    },
                    backing: inventory_backing,
                    inherited_frame: None,
                    stage2_lease: Some((physical_ipa, physical_len)),
                    stage2_owner: InventoryStage2OwnerIdentity {
                        host_addr: physical_host as usize,
                        generation: owner_generation,
                    },
                },
            )?
        };
        let inventory_entry = ((physical_ipa, physical_len), inventory_mapping);
        // A fresh local extent replaces only invalid descriptors: the walker
        // caches nothing for them, so the publication needs ordering (sync before
        // commit) but no stage-1 TLB maintenance. Any transaction that overwrote a
        // live VALID descriptor, and every foreign publication, keeps the flush.
        let mut replaced_valid_descriptor = true;
        // Journal this transaction's descriptor pre-images rather than
        // cloning the whole 1.75 MiB table region (see `begin_undo`).
        let publication = {
            let page_tables_authority = context.state.page_tables_authority();
            let has_source = page_tables_authority.has_source();
            page_tables_authority
            .edit(
                || {
                    Err(TrapError::Hypervisor(
                        "sparse HVPatch mmap page tables are absent".to_owned(),
                    ))
                },
                |editor| -> Result<(), TrapError> {
                    editor.begin_undo().map_err(|error| {
                        sparse_mmap_stage1_error(editor.manager, "begin_undo", error, has_source)
                    })?;
                    HvfVmState::refresh_stage1_exclusivity(editor.manager);
                    // The leaves are built read-only and non-executable; the
                    // permission publication below sets the mapping's own
                    // protection (or PROT_NONE) before the edit commits.
                    use carrick_mmu_core::aarch64::UserLeafAccess;
                    let aligned_start = align_up(start, TWO_MIB)?.min(end);
                    if start < aligned_start {
                        editor
                            .map_private_aliased(
                                start,
                                semantic_ipa,
                                aligned_start - start,
                                UserLeafAccess::READ_ONLY,
                            )
                            .map_err(|error| {
                                sparse_mmap_stage1_error(editor.manager, "leading", error, has_source)
                            })?;
                    }
                    let aligned_len = (end - aligned_start) / TWO_MIB * TWO_MIB;
                    if aligned_len != 0 {
                        editor
                            .map_private_aliased(
                                aligned_start,
                                semantic_ipa + (aligned_start - start),
                                aligned_len,
                                UserLeafAccess::READ_ONLY,
                            )
                            .map_err(|error| {
                                sparse_mmap_stage1_error(editor.manager, "bulk", error, has_source)
                            })?;
                    }
                    let tail_start = aligned_start + aligned_len;
                    if tail_start < end {
                        editor
                            .map_private_aliased(
                                tail_start,
                                semantic_ipa + (tail_start - start),
                                end - tail_start,
                                UserLeafAccess::READ_ONLY,
                            )
                            .map_err(|error| {
                                sparse_mmap_stage1_error(editor.manager, "trailing", error, has_source)
                            })?;
                    }
                    if context.foreign.is_some() {
                        editor.set_rw(start, semantic_len,
                            context.state.protections.range_executable(start, semantic_len))
                    } else {
                        editor.set_prot_none(start, semantic_len)
                    }.map_err(|error| match error {
                        carrick_mmu_core::aarch64::PageTableError::MetadataAllocation => {
                            TrapError::MetadataAllocation
                        }
                        other => TrapError::Hypervisor(format!(
                            "publish sparse HVPatch mmap stage-1 permissions: {other:?}"
                        )),
                    })?;
                    context.state.publish_stage1_extension_arenas_into(
                        // The root region's guest-visible mapping is read-only,
                        // but structural table backing must remain writable for
                        // hardware table-walk updates. Fork construction uses
                        // the same explicit permission for extension arenas.
                        &context.custody,
                        editor.manager,
                        applevisor::memory::MemPerms::ReadWrite,
                        &mut extension_regions,
                    )?;
                    let page_table_resolver = context
                        .state
                        .pinned_stage1_arenas(&context.custody, editor.base())?;
                    unsafe { editor.sync_to_host(&page_table_resolver) }.map_err(|e| match e {
                        carrick_mmu_core::aarch64::PageTableError::MetadataAllocation => {
                            TrapError::MetadataAllocation
                        }
                        other => TrapError::Hypervisor(format!(
                            "sparse HVPatch mmap sync_to_host failed: {other:?}"
                        )),
                    })?;
                    carrick_observability::probes::hvpatch_sparse_boundary_with(end, || unsafe {
                        editor.debug_walk_host(&page_table_resolver, end).ok()
                    });
                    replaced_valid_descriptor = editor.manager.undo_replaced_valid_descriptor();
                    #[cfg(test)]
                    if STAGE2_AUDIT_STATE.with(|state| state.borrow().fail_sparse_publication_after_sync) {
                        return Err(TrapError::Hypervisor(
                            "injected sparse publication failure after sync".to_owned(),
                        ));
                    }
                    #[cfg(debug_assertions)]
                    {
                        let mut page = start;
                        while page < end {
                            let expected_ipa = semantic_ipa + (page - start);
                            let shadow = editor.debug_walk(page);
                            let live = unsafe {
                                editor.debug_walk_host(&page_table_resolver, page)
                            }
                            .map_err(|e| {
                                TrapError::Hypervisor(format!(
                                    "sparse HVPatch mmap debug_walk_host failed: {e:?}"
                                ))
                            })?;
                            let leaf = carrick_mmu_core::aarch64::terminal_descriptor(live);
                            if shadow != live
                                || editor.translate(page) != context.foreign.as_ref().map(|_| expected_ipa)
                                || editor.translate_retained_output(page) != Some(expected_ipa)
                                || leaf & VALID != u64::from(context.foreign.is_some())
                                || leaf & AP_MASK != if context.foreign.is_some() { 0b01 << 6 } else { AP_USER_RO }
                                || leaf & NON_GLOBAL == 0
                            {
                                return Err(TrapError::Hypervisor(format!(
                                    "sparse HVPatch mmap publication failed at VA 0x{page:x}: leaf=0x{leaf:x} expected_ipa=0x{expected_ipa:x}"
                                )));
                            }
                            page = page.saturating_add(PAGE_SIZE);
                        }
                    }
                    Ok(())
                },
            )
        };
        if let Err(error) = publication {
            let rollback = context.state.page_tables_authority().edit(
                || {
                    Err(TrapError::Hypervisor(
                        "rollback page tables disappeared".to_owned(),
                    ))
                },
                |editor| {
                    let resolver = context
                        .state
                        .pinned_stage1_arenas(&context.custody, editor.base())?;
                    // The owned resolver drops its pins before retirement. Exact-MM
                    // exclusion remains held through descriptor restore and TLBI.
                    unsafe {
                        editor.rollback_undo_retiring(
                            resolver,
                            |e| match e {
                                carrick_mmu_core::aarch64::PageTableError::MetadataAllocation => {
                                    TrapError::MetadataAllocation
                                }
                                other => TrapError::Hypervisor(format!(
                                    "failed to rollback stage1 undo: {other:?}"
                                )),
                            },
                            |popped| {
                                flush_stage1.flush()?;
                                let journal = extension_regions
                                    .iter()
                                    .filter_map(|region| {
                                        region.structural_owner.as_ref().map(|owner| {
                                            (owner.physical_ipa, std::sync::Arc::clone(owner))
                                        })
                                    })
                                    .collect();
                                context.state.retire_rolled_back_arenas(
                                    &context.custody,
                                    popped,
                                    &journal,
                                    &mut unmap_global_frame_stage2_record,
                                    &mut release_retired_stage2_ipa,
                                )?;
                                Ok::<(), TrapError>(())
                            },
                        )?;
                    }
                    Ok::<(), TrapError>(())
                },
            );
            if let Err(rollback_error) = rollback {
                carrick_fatal!(
                    "hvpatch::sparse_materialization_rollback",
                    "sparse page-table rollback failed after publication failure: start=0x{start:x} end=0x{end:x} error={rollback_error}"
                );
            }
            HvfVmState::rollback_unpublished_mappings(
                &mut context.state.frame_inventory.ledger.lock(),
                &[inventory_entry],
            )?;
            return Err(error);
        }
        // Publication succeeded: the journalled pre-images are no longer needed.
        let _ = context.state.page_tables_authority().edit(
            || Err(()),
            |editor| {
                editor.commit_undo();
                Ok::<(), ()>(())
            },
        );
        if (replaced_valid_descriptor || context.foreign.is_some())
            && let Err(error) = flush_stage1.flush()
        {
            carrick_fatal!(
                "hvpatch::sparse_materialization_tlbi",
                "sparse page-table stage-1 TLBI failed after publication: start=0x{start:x} end=0x{end:x} error={error}"
            );
        }
        let commit = reservation.commit(());
        let foreign_receipt = if let Some(requested) = &context.foreign {
            let mut mapping_ids = requested.mapping_ids.clone();
            for event in commit.batch().events() {
                match *event {
                    carrick_hal::FrameInventoryEvent::UnmapMapping { mapping, .. } => {
                        mapping_ids.retain(|id| *id != mapping)
                    }
                    carrick_hal::FrameInventoryEvent::PrepareMapping { mapping, .. } => {
                        mapping_ids.push(mapping)
                    }
                    _ => {}
                }
            }
            mapping_ids.sort_unstable();
            mapping_ids.dedup();
            let challenge = commit.receipt_challenge();
            let (receipt, kernel_proof, generation) = context
            .authority
            .apply_foreign_cow(
                commit,
                carrick_guest_mem::GuestVa(start),
                std::num::NonZeroUsize::new(semantic_len).unwrap_or_else(|| {
                    carrick_fatal!(
                        "hvpatch::sparse_materialization_inventory",
                        "sparse publication produced zero semantic length: start=0x{start:x} end=0x{end:x}"
                    );
                }),
                inventory_mapping.mapping,
                inventory_mapping.frame,
                carrick_guest_mem::Gpa(physical_ipa),
                carrick_hal::FrameLength::from_mapping_extent(
                    std::num::NonZeroU64::new(physical_len).unwrap_or_else(|| {
                        carrick_fatal!(
                            "hvpatch::sparse_materialization_inventory",
                            "prepared sparse backing produced zero physical extent: physical_ipa=0x{physical_ipa:x}"
                        );
                    }),
                ),
            )
            .unwrap_or_else(|error| {
                carrick_fatal!(
                    "hvpatch::sparse_materialization_inventory",
                    "kernel foreign-MM inventory application failed: start=0x{start:x} end=0x{end:x} error={error}"
                );
            });
            if generation.raw_for_probe() != owner_generation
            || !challenge.authenticate_apply(
                &receipt,
                std::num::NonZeroU64::new(requested.mm.raw_for_probe()).unwrap_or_else(|| {
                    carrick_fatal!(
                        "hvpatch::sparse_materialization_mm_authority",
                        "foreign-MM snapshot supplied zero MM identity after sparse commit: start=0x{start:x}"
                    );
                }),
            )
            || !receipt.authorizes(inventory_mapping.mapping, inventory_mapping.frame)
        {
            carrick_fatal!(
                "hvpatch::sparse_materialization_inventory",
                "foreign-MM inventory receipt failed verification: generation={} owner_generation={owner_generation} mapping={:?} frame={:?}",
                generation.raw_for_probe(),
                inventory_mapping.mapping,
                inventory_mapping.frame
            );
        }
            let mut snapshot = requested.clone();
            snapshot.mapping_ids = mapping_ids;
            snapshot.frame_inventory_revision =
                carrick_hal::ForeignFrameInventoryRevision::from_authority_raw(receipt.revision());
            Some(CarrierForeignCowReceipt {
                snapshot,
                start: carrick_guest_mem::GuestVa(start),
                len: semantic_len,
                mapping: inventory_mapping.mapping,
                frame: inventory_mapping.frame,
                physical_base: carrick_guest_mem::Gpa(physical_ipa),
                physical_len,
                owner_generation: generation,
                kernel_proof,
            })
        } else {
            if let Err(error) = context.authority.apply(commit) {
                carrick_fatal!(
                    "hvpatch::sparse_materialization_inventory",
                    "local kernel frame-inventory application failed after sparse publication: start=0x{start:x} end=0x{end:x} error={error}"
                );
            }
            None
        };
        owner_rollback.commit();
        (inventory_mapping, foreign_receipt)
    };

    match context.authority.mapping_is_live(
        inventory_mapping.mapping,
        inventory_mapping.frame,
        carrick_guest_mem::Gpa(physical_ipa),
        carrick_hal::FrameLength::from_mapping_extent(
            std::num::NonZeroU64::new(physical_len).unwrap_or_else(|| {
                carrick_fatal!(
                    "hvpatch::sparse_materialization_inventory",
                    "post-commit authentication observed zero physical extent: physical_ipa=0x{physical_ipa:x}"
                );
            }),
        ),
    ) {
        Ok(true) => {}
        Ok(false) => {
            carrick_fatal!(
                "hvpatch::sparse_materialization_inventory",
                "post-commit kernel authentication reported published sparse mapping absent: mapping={:?} frame={:?} physical_ipa=0x{physical_ipa:x}",
                inventory_mapping.mapping,
                inventory_mapping.frame
            );
        }
        Err(error) => {
            carrick_fatal!(
                "hvpatch::sparse_materialization_inventory",
                "post-commit kernel authentication errored for published sparse mapping: mapping={:?} frame={:?} physical_ipa=0x{physical_ipa:x} error={error}",
                inventory_mapping.mapping,
                inventory_mapping.frame
            );
        }
    }

    retire_previous();

    let sharing = GuestMappingSharing::Private;
    register_shared_alias(AliasBacking {
        start,
        ipa: semantic_ipa,
        host_addr: semantic_host as usize,
        size: semantic_len,
        physical_ipa,
        physical_host_addr: physical_host as usize,
        physical_size,
        perms: u64::from(stage2_perms),
        guest_writable: true,
        sharing,
        ownership_scope: alias_ownership_scope(
            sharing,
            context.mm_root_slot,
            context.container_root,
        ),
        inventory_backing,
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation,
    });
    let region = HvfMappedRegion {
        start,
        ipa: semantic_ipa,
        physical_ipa,
        end,
        host_addr: semantic_host,
        size: semantic_len,
        physical_size,
        perms: stage2_perms,
        memory: None,
        host_mapping: None,
        structural_owner: None,
        stage2_lease: None,
        is_dynamic_alias: true,
        sharing,
        guest_writable: true,
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation,
    };
    carrick_observability::probes::hvpatch_mm_publication(
        context.mm_key.get(),
        start,
        semantic_ipa,
        owner_generation,
        context.mm_root_slot.map_or(0, |slot| slot.0),
    );
    Ok(PublishedSparseExtent {
        region,
        extension_regions,
        page_granular_arm,
        foreign_receipt,
    })
}

/// Retain exact structural owners and stage-2 pins for a complete table edit.
/// Raw pointers remain valid even if another holder requests retirement.
struct PinnedStage1Arenas {
    structural:
        std::collections::BTreeMap<u64, (std::sync::Arc<StructuralBackingOwner>, CarrierStage2Pin)>,
    relocated_primary: Option<(u64, GlobalFrameOwnerPin)>,
    /// The instruction-cache authority for executable leaves this edit
    /// publishes.
    custody: std::sync::Arc<CarrierVmCustody>,
}
unsafe impl carrick_mmu_core::aarch64::HostArenaResolver for PinnedStage1Arenas {
    fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
        <&Self as carrick_mmu_core::aarch64::HostArenaResolver>::host_ptr_for_base(&self, base)
    }
    fn publish_user_executable(
        &self,
        output: u64,
        len: u64,
    ) -> Result<(), carrick_mmu_core::aarch64::PageTableError> {
        <&Self as carrick_mmu_core::aarch64::HostArenaResolver>::publish_user_executable(
            &self, output, len,
        )
    }
    fn record_populated_prefix(&self, base: u64, prefix: usize) {
        <&Self as carrick_mmu_core::aarch64::HostArenaResolver>::record_populated_prefix(
            &self, base, prefix,
        );
    }
}
unsafe impl carrick_mmu_core::aarch64::HostArenaResolver for &PinnedStage1Arenas {
    fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
        self.structural
            .get(&base)
            .map(|(owner, _)| owner.ptr())
            .or_else(|| {
                self.relocated_primary
                    .as_ref()
                    .filter(|(primary, _)| *primary == base)
                    .map(|(_, pin)| pin.owner().as_ptr())
            })
    }
    fn record_populated_prefix(&self, base: u64, prefix: usize) {
        if let Some((owner, _)) = self.structural.get(&base) {
            owner.record_populated_prefix(prefix);
        }
    }
    fn publish_user_executable(
        &self,
        output: u64,
        len: u64,
    ) -> Result<(), carrick_mmu_core::aarch64::PageTableError> {
        self.custody
            .publish_user_executable(output, len, |_, _| None, |_, _| None)
            .map(|_| ())
    }
}
impl MmAccessState {
    /// Called only after descriptor rollback and exact-ASID invalidation, while
    /// the transaction still excludes mutations and holds its publication journal.
    fn retire_rolled_back_arenas(
        &self,
        custody: &CarrierVmCustody,
        popped: &[u64],
        journal: &std::collections::BTreeMap<u64, std::sync::Arc<StructuralBackingOwner>>,
        unmap: &mut dyn FnMut(u64, usize) -> Result<(), CarrierStage2BackendError>,
        release_ipa: &mut dyn FnMut(u64, u64) -> Result<(), TrapError>,
    ) -> Result<(), TrapError> {
        for &base in popped {
            let key = (base, 2 * 1024 * 1024);
            let owner = self.structural_owners.read().get(&key).cloned();
            let owner = match (owner, journal.get(&base)) {
                (None, None) => continue, // Never reached backing publication.
                (Some(owner), Some(created)) if std::sync::Arc::ptr_eq(&owner, created) => owner,
                _ => {
                    return Err(TrapError::Hypervisor(
                        "rollback refuses an arena owner outside its publication journal"
                            .to_owned(),
                    ));
                }
            };
            let identity = owner.record_identity();
            owner
                .retained
                .owner_retired
                .store(true, std::sync::atomic::Ordering::Release);
            retry_structural_backing_identities_in_using(custody, &[identity], unmap, release_ipa)?;
            if custody.stage2_record_snapshot(identity.record_id).is_some() {
                return Err(TrapError::Hypervisor(
                    "rollback arena backing remained nonterminal".to_owned(),
                ));
            }
            self.structural_owners.write().remove(&key);
        }
        Ok(())
    }

    fn pinned_stage1_arenas(
        &self,
        custody: &std::sync::Arc<CarrierVmCustody>,
        primary_base: u64,
    ) -> Result<PinnedStage1Arenas, TrapError> {
        let mut structural = std::collections::BTreeMap::new();
        for (&(base, size), owner) in self.structural_owners.read().iter() {
            // Boot primary tables use 0x1c0000 bytes, while reusable roots
            // and extension arenas retain complete 2 MiB structural owners.
            // Both are exact-base table backings; neither may be dropped from
            // the resolver merely because its physical reservation is larger.
            if size != carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize
                && size != 2 * 1024 * 1024
            {
                continue;
            }
            let pin = custody
                .pin_stage2_record(owner.record_identity())
                .map_err(|error| {
                    TrapError::Hypervisor(format!("pin exact stage-1 arena: {error:?}"))
                })?;
            structural.insert(base, (std::sync::Arc::clone(owner), pin));
        }
        // A later container's bootstrap root is relocated through the same
        // global-frame plan as exec. Its primary table therefore has a live
        // global-frame owner rather than a StructuralBackingOwner, while all
        // extension arenas remain structural. Pin the exact current global
        // owner so retirement or IPA reuse cannot invalidate this edit.
        let mut relocated_primary = None;
        if !structural.contains_key(&primary_base) {
            for length in [carrick_mem::memory::LINUX_PAGE_TABLES_SIZE, 2 * 1024 * 1024] {
                let Some((host_addr, generation)) =
                    global_frame_host_owner_identity_in(custody, primary_base, length)
                else {
                    continue;
                };
                let pin = pin_exact_live_global_frame_owner_in(
                    custody,
                    primary_base,
                    length,
                    host_addr,
                    generation,
                )
                .ok_or_else(|| {
                    TrapError::Hypervisor(
                        "relocated stage-1 primary owner changed while acquiring its pin"
                            .to_owned(),
                    )
                })?;
                relocated_primary = Some((primary_base, pin));
                break;
            }
        }
        Ok(PinnedStage1Arenas {
            structural,
            relocated_primary,
            custody: std::sync::Arc::clone(custody),
        })
    }
}

#[cfg(test)]
mod arena_pin_tests {
    use super::*;
    use carrick_mmu_core::aarch64::HostArenaResolver;

    #[test]
    fn publication_resolver_pins_exact_primary_owner_until_edit_finishes() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        check_pinned_arena(carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize);
    }

    #[test]
    fn publication_resolver_pins_exact_full_slot_until_edit_finishes() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        check_pinned_arena(2 * 1024 * 1024);
    }

    #[test]
    fn publication_resolver_pins_relocated_root_global_owner() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let custody = std::sync::Arc::new(CarrierVmCustody::new());
        let carrier_generation = custody.begin_create().unwrap();
        custody.commit_create(carrier_generation).unwrap();
        let base = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x4000_0000;
        let size = carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize;
        let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            size,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .unwrap();
        let pointer = host.as_ptr();
        let mut lease = GlobalFrameStage2Lease::fixed(base, size as u64);
        lease.mark_test_mapped_without_backend();
        register_global_frame_host_owner_in(
            &custody,
            lease,
            host,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .unwrap();
        let state = MmAccessState::new_unbound(
            carrick_aarch64::Stage1Authority::new(),
            std::sync::Arc::new(MemoryProtections::default()),
            std::sync::Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
            std::sync::Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
            std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
            crate::hvf_aarch64_engine::HostCowStats::default(),
        );

        let resolver = state.pinned_stage1_arenas(&custody, base).unwrap();
        assert_eq!(
            resolver.host_ptr_for_base(base),
            Some(pointer),
            "a carrier-reuse root allocated in the global-frame arena must remain writable by its MM's page-table publisher",
        );
    }

    #[test]
    fn rollback_arena_retirement_preserves_pinned_or_failed_backing_until_retry() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        for fail_backend in [false, true] {
            let (state, custody, owner) = rollback_fixture();
            let base = owner.physical_ipa;
            let identity = owner.record_identity();
            let journal = std::collections::BTreeMap::from([(base, owner.clone())]);
            let pin = (!fail_backend).then(|| custody.pin_stage2_record(identity).unwrap());
            let calls = std::cell::Cell::new(0);
            let result = state.retire_rolled_back_arenas(
                &custody,
                &[base],
                &journal,
                &mut |_, _| {
                    calls.set(calls.get() + 1);
                    Err(CarrierStage2BackendError::HvReturn(1))
                },
                &mut |_, _| Ok(()),
            );
            assert!(result.is_err());
            assert_eq!(calls.get(), usize::from(fail_backend));
            assert!(custody.stage2_record_snapshot(identity.record_id).is_some());
            assert!(
                state
                    .structural_owners
                    .read()
                    .contains_key(&(base, owner.physical_size))
            );
            drop(pin);
            state
                .retire_rolled_back_arenas(
                    &custody,
                    &[base],
                    &journal,
                    &mut |ipa, len| {
                        assert_eq!((ipa, len), (base, owner.physical_size));
                        Ok(())
                    },
                    &mut |_, _| Ok(()),
                )
                .unwrap();
            assert!(custody.stage2_record_snapshot(identity.record_id).is_none());
            assert!(state.structural_owners.read().is_empty());
        }
    }

    #[test]
    fn rollback_arena_retirement_rejects_missing_journal_and_missing_mm_owner() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let (state, custody, owner) = rollback_fixture();
        let base = owner.physical_ipa;
        let journal = std::collections::BTreeMap::from([(base, owner.clone())]);
        for missing_mm in [false, true] {
            if missing_mm {
                state.structural_owners.write().clear();
            }
            let empty = std::collections::BTreeMap::new();
            assert!(
                state
                    .retire_rolled_back_arenas(
                        &custody,
                        &[base],
                        if missing_mm { &journal } else { &empty },
                        &mut |_, _| panic!("unmatched owner must not unmap"),
                        &mut |_, _| panic!("unmatched owner must not release address")
                    )
                    .is_err()
            );
            assert!(
                !owner
                    .retained
                    .owner_retired
                    .load(std::sync::atomic::Ordering::Acquire)
            );
        }
        state.install_structural_owner(owner.clone());
        state
            .retire_rolled_back_arenas(
                &custody,
                &[base],
                &journal,
                &mut |_, _| Ok(()),
                &mut |_, _| Ok(()),
            )
            .unwrap();
    }

    #[test]
    fn local_publication_permit_requires_the_bound_mm_and_asid() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let (state, custody, owner) = rollback_fixture();
        let identity = carrick_hal::FrameCowIdentity {
            linux_pid: 7,
            linux_tid: 8,
            mm: 9,
            asid: 10,
        };
        assert!(PublicationContext::for_local(state.clone(), custody.clone(), identity).is_err());
        state.bind_cow_runtime(MmCowRuntimeBinding {
            authority: std::sync::Arc::new(
                super::super::task_only_carrier_directory_tests::TestCowAuthority,
            ),
            identity,
            mm_root_slot: Some((owner.physical_ipa, owner.physical_size as u64)),
            container_root: ContainerRootToken::ROOT,
            persistent_vm_lifecycle: true,
        });
        for invalid in [
            carrick_hal::FrameCowIdentity { mm: 0, ..identity },
            carrick_hal::FrameCowIdentity {
                asid: 0,
                ..identity
            },
            carrick_hal::FrameCowIdentity { mm: 11, ..identity },
            carrick_hal::FrameCowIdentity {
                asid: 11,
                ..identity
            },
        ] {
            assert!(
                PublicationContext::for_local(state.clone(), custody.clone(), invalid).is_err()
            );
        }
        let permit =
            PublicationContext::for_local(state.clone(), custody.clone(), identity).unwrap();
        assert!(std::sync::Arc::ptr_eq(&permit.state, &state));
        assert!(std::sync::Arc::ptr_eq(&permit.custody, &custody));
        assert_eq!(
            permit.mm_root_slot,
            Some((owner.physical_ipa, owner.physical_size as u64))
        );
        drop(permit);
        let journal = std::collections::BTreeMap::from([(owner.physical_ipa, owner.clone())]);
        state
            .retire_rolled_back_arenas(
                &custody,
                &[owner.physical_ipa],
                &journal,
                &mut |_, _| Ok(()),
                &mut |_, _| Ok(()),
            )
            .unwrap();
    }

    /// A COW authority whose `quiesce()` REBINDS the MM's `cow_runtime` with a
    /// fresh, equivalent authority object before returning — the exact,
    /// deterministic shape of a sibling thread's first-run rebind landing
    /// inside a first-touch quiesce window. `rebind_identity` chooses the mm
    /// the sibling publishes; equal to the original models the benign sibling,
    /// a different mm models a genuine MM change the check must still reject.
    struct RebindingCowAuthority {
        state: std::sync::Arc<MmAccessState>,
        rebind_identity: carrick_hal::FrameCowIdentity,
        mm_root_slot: Option<(u64, u64)>,
    }

    impl carrick_hal::FrameCowAuthority for RebindingCowAuthority {
        fn quiesce(
            &self,
        ) -> Result<Box<dyn carrick_hal::FrameCowQuiesce>, Box<dyn std::error::Error + Send + Sync>>
        {
            self.state.bind_cow_runtime(MmCowRuntimeBinding {
                authority: std::sync::Arc::new(
                    super::super::task_only_carrier_directory_tests::TestCowAuthority,
                ),
                identity: self.rebind_identity,
                mm_root_slot: self.mm_root_slot,
                container_root: ContainerRootToken::ROOT,
                persistent_vm_lifecycle: true,
            });
            Ok(Box::new(()))
        }

        fn reserve(
            &self,
            _frame_candidates: usize,
            _mapping_candidates: usize,
            _event_count: usize,
        ) -> Result<carrick_hal::FrameInventoryReservation, Box<dyn std::error::Error + Send + Sync>>
        {
            Err(Box::new(std::io::Error::other("unused test reserve")))
        }

        fn apply(
            &self,
            _commit: carrick_hal::FrameInventoryCommit<()>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Err(Box::new(std::io::Error::other("unused test apply")))
        }

        fn mapping_is_live(
            &self,
            _mapping: carrick_hal::MappingId,
            _frame: carrick_hal::FrameId,
            _gpa: carrick_guest_mem::Gpa,
            _length: carrick_hal::FrameLength,
        ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
            Ok(false)
        }

        fn frame_mapping_count(
            &self,
            _frame: carrick_hal::FrameId,
        ) -> Result<Option<usize>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(None)
        }
    }

    /// Regression for the Go startup `SIGSEGV` (SEGV_MAPERR) in
    /// `runtime.persistentalloc1`: a first-touch publication must survive a
    /// sibling task rebinding the same MM's frame-COW runtime binding with a
    /// fresh (equivalent) authority during the quiesce, and must still reject a
    /// genuine MM identity change.
    #[test]
    fn local_publication_tolerates_equivalent_rebind_during_quiesce() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let (state, custody, owner) = rollback_fixture();
        let identity = carrick_hal::FrameCowIdentity {
            linux_pid: 7,
            linux_tid: 8,
            mm: 9,
            asid: 10,
        };
        let root = Some((owner.physical_ipa, owner.physical_size as u64));

        // A sibling task rebinds the SAME mm/asid/root with a different
        // authority object (its own `linux_tid`) during the quiesce. Before the
        // fix the post-quiesce `Arc::ptr_eq` refused this and the runtime
        // lowered the refusal to SIGSEGV; it must now succeed.
        state.bind_cow_runtime(MmCowRuntimeBinding {
            authority: std::sync::Arc::new(RebindingCowAuthority {
                state: state.clone(),
                rebind_identity: carrick_hal::FrameCowIdentity {
                    linux_tid: 99,
                    ..identity
                },
                mm_root_slot: root,
            }),
            identity,
            mm_root_slot: root,
            container_root: ContainerRootToken::ROOT,
            persistent_vm_lifecycle: true,
        });
        PublicationContext::for_local(state.clone(), custody.clone(), identity)
            .expect("equivalent sibling rebind during quiesce must not refuse the publication");

        // Control: a rebind that changes the MM identity during the quiesce
        // must still be rejected.
        state.bind_cow_runtime(MmCowRuntimeBinding {
            authority: std::sync::Arc::new(RebindingCowAuthority {
                state: state.clone(),
                rebind_identity: carrick_hal::FrameCowIdentity { mm: 11, ..identity },
                mm_root_slot: root,
            }),
            identity,
            mm_root_slot: root,
            container_root: ContainerRootToken::ROOT,
            persistent_vm_lifecycle: true,
        });
        assert!(
            PublicationContext::for_local(state.clone(), custody.clone(), identity).is_err(),
            "a genuine MM change during quiesce must still be rejected"
        );

        drop(state.cow_runtime.write().take());
        let journal = std::collections::BTreeMap::from([(owner.physical_ipa, owner.clone())]);
        state
            .retire_rolled_back_arenas(
                &custody,
                &[owner.physical_ipa],
                &journal,
                &mut |_, _| Ok(()),
                &mut |_, _| Ok(()),
            )
            .unwrap();
    }

    fn rollback_fixture() -> (
        std::sync::Arc<MmAccessState>,
        std::sync::Arc<CarrierVmCustody>,
        std::sync::Arc<StructuralBackingOwner>,
    ) {
        let custody = std::sync::Arc::new(CarrierVmCustody::new());
        let generation = custody.begin_create().unwrap();
        custody.commit_create(generation).unwrap();
        let base = 0x7d00_4000_0000;
        let size = 2 * 1024 * 1024;
        let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            size,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .unwrap();
        let mut lease = GlobalFrameStage2Lease::fixed(base, size as u64);
        // Exercise the injected backend callback as a live stage-2 record.
        lease.mark_mapped();
        let owner = StructuralBackingOwner::new_in(
            &custody,
            host,
            lease,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
            next_structural_epoch().unwrap(),
            base,
            size,
        )
        .unwrap();
        let state = MmAccessState::new_unbound(
            carrick_aarch64::Stage1Authority::new(),
            std::sync::Arc::new(MemoryProtections::default()),
            std::sync::Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
            std::sync::Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
            std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
            crate::hvf_aarch64_engine::HostCowStats::default(),
        );
        state.install_structural_owner(owner.clone());
        (state, custody, owner)
    }

    fn check_pinned_arena(size: usize) {
        let custody = std::sync::Arc::new(CarrierVmCustody::new());
        let generation = custody.begin_create().unwrap();
        custody.commit_create(generation).unwrap();
        let base = 0x7d00_3000_0000;
        let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            size,
            crate::host_mapping::HostMappingKind::PerMmKernelState,
        )
        .unwrap();
        let mut lease = GlobalFrameStage2Lease::fixed(base, size as u64);
        lease.mark_test_mapped_without_backend();
        let owner = StructuralBackingOwner::new_in(
            &custody,
            host,
            lease,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
            next_structural_epoch().unwrap(),
            base,
            size,
        )
        .unwrap();
        let identity = owner.record_identity();
        let pointer = owner.ptr();
        let state = MmAccessState::new_unbound(
            carrick_aarch64::Stage1Authority::new(),
            std::sync::Arc::new(MemoryProtections::default()),
            std::sync::Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
            std::sync::Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
            std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
            crate::hvf_aarch64_engine::HostCowStats::default(),
        );
        state.install_structural_owner(owner);
        let wrong_custody = std::sync::Arc::new(CarrierVmCustody::new());
        let other_generation = wrong_custody.begin_create().unwrap();
        wrong_custody.commit_create(other_generation).unwrap();
        assert!(state.pinned_stage1_arenas(&wrong_custody, base).is_err());
        let resolver = state.pinned_stage1_arenas(&custody, base).unwrap();
        assert_eq!(resolver.host_ptr_for_base(base), Some(pointer));
        assert_eq!(resolver.host_ptr_for_base(base + size as u64), None);
        assert_eq!(
            custody
                .stage2_record_snapshot(identity.record_id)
                .unwrap()
                .pin_count,
            1
        );
        state.structural_owners.write().clear();
        assert_eq!(resolver.host_ptr_for_base(base), Some(pointer));
        assert_eq!(
            custody.retire_stage2_record_using(identity, |_, _| panic!(
                "pinned backing must not unmap"
            )),
            CarrierStage2RetireOutcome::DeferredActivePins
        );
        drop(resolver);
        assert_eq!(
            custody
                .stage2_record_snapshot(identity.record_id)
                .unwrap()
                .pin_count,
            0
        );
        assert_eq!(
            custody.retire_stage2_record_using(identity, |_, _| Ok(())),
            CarrierStage2RetireOutcome::RetiredUnmapped
        );
    }
}

/// A target-selected grant owns its exact physical and inventory receipts
/// before a descriptor can name it. Drop settles only those identities.
pub(super) struct PendingTransferGrant {
    context: PublicationContext<'static>,
    // Failed preparation rolls back under the guard already held by its owner.
    registry: Option<crate::fork_quiesce::FrameRegistryGuard<'static>>,
    publication: Option<PublishedFrameGrant>,
    pin: Option<CarrierStage2Pin>,
    record: Option<CarrierStage2RecordIdentity>,
    txn: Option<carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn>,
    descriptor_settled: bool,
}
impl PublicationContext<'static> {
    pub(super) fn refill_transfer_cow(&self) -> Result<bool, TrapError> {
        let Some(pool) = carrick_el1_abi::cow_grant_pool_host() else {
            return Ok(false);
        };
        self.refill_transfer_cow_in(pool)
    }
    pub(super) fn refill_transfer_cow_in(
        &self,
        pool: &carrick_el1_abi::CowGrantPool,
    ) -> Result<bool, TrapError> {
        if pool.ready(self.mm_key.get()).next().is_some() {
            return Ok(true);
        }
        // The exact EL1 receipt classified a live COW run. Supply physical
        // inventory only; do not reclassify through the host table mirror.
        Ok(super::guest_cow::provision_guest_cow_grants(&self.state, &self.custody, pool, 1)? != 0)
    }
    pub(super) fn prepare_transfer(
        self,
        window: carrick_el1_abi::PortalGrantWindow,
    ) -> Result<Option<Box<dyn carrick_aarch64::user_transfer::TransferGrant>>, TrapError> {
        use carrick_mmu_core::aarch64::descriptor_txn::{BackingIdentity, DescriptorOp, PageSpan};
        let failure = |message: String| TrapError::Hypervisor(format!("target grant: {message}"));
        let binding = self
            .state
            .cow_runtime
            .read()
            .clone()
            .ok_or_else(|| failure("missing binding".into()))?;
        // EL1 chose the source and offset. Complete byte I/O before taking
        // physical publication ownership; no MM editor survives this supply.
        let source_bytes = window
            .host_backing
            .map(|identity| {
                binding
                    .authority
                    .read_host_backing(identity, window.range.len() as usize)
                    .map_err(|error| failure(format!("retained byte source: {error:?}")))
            })
            .transpose()?;
        let registry = crate::fork_quiesce::FrameRegistryGuard::acquire(
            carrick_observability::probes::HvpatchTopologyOperation::SiblingMaterialize,
            binding.identity.linux_pid,
            binding.identity.linux_tid,
        );
        // This adapter supplies an unpublished window; a resident predecessor
        // requires its own owner retirement, never an overwrite of its alias.
        if !alias_registry()
            .lock()
            .overlapping_process_aliases(
                window.range.start(),
                window.range.len() as usize,
                self.mm_root_slot,
                self.container_root,
            )
            .is_empty()
        {
            return Ok(None);
        }
        let publication = publish_frame_grant_backing(
            &self,
            carrick_hal::El1FrameGrantRequest {
                mm_key: window.operation.mm.raw(),
                fault_va: window.fault_page,
                access: 1,
                semantic_base: window.range.start(),
                len: window.range.len(),
                permissions: window.protection.bits(),
            },
            None,
            match source_bytes.as_deref() {
                Some(bytes) => SparseExtentBacking::SeededAnon { bytes },
                None => SparseExtentBacking::Anon,
            },
            &registry,
        )?;
        let mut pending = PendingTransferGrant {
            context: self,
            registry: Some(registry),
            publication: Some(publication),
            pin: None,
            record: None,
            txn: None,
            descriptor_settled: false,
        };
        let publication = pending.publication.as_ref().unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::user_transfer",
                "new pending grant has no publication"
            )
        });
        let owner = pending
            .context
            .custody
            .global_frame_host_owners
            .lock()
            .get(&publication.inventory_entry.0)
            .and_then(GlobalFrameOwnerEntry::live_owner)
            .cloned()
            .ok_or_else(|| failure("new owner missing".into()))?;
        pending.record = Some(owner.record_identity);
        pending.pin = Some(
            pending
                .context
                .custody
                .pin_stage2_record(owner.record_identity)
                .map_err(|error| failure(format!("pin new owner: {error:?}")))?,
        );

        let ready = publication.ready;
        let nz = |value| {
            std::num::NonZeroU64::new(value).unwrap_or_else(|| {
                carrick_fatal!(
                    "hvpatch::user_transfer",
                    "zero authenticated grant identity"
                )
            })
        };
        let op = DescriptorOp::Prepare {
            publication: carrick_mmu_core::aarch64::GuestLeafPublication {
                va: window.range.start(),
                ipa: ready.physical_ipa,
                len: window.range.len(),
                writable: window.protection.bits() & 2 != 0,
                executable: window.protection.bits() & 4 != 0,
            },
            resident: PageSpan::new(window.fault_page, 4096),
            backing: BackingIdentity {
                frame_id: nz(ready.frame_id),
                mapping_id: nz(ready.mapping_id),
                owner_generation: nz(ready.owner_generation),
                inventory_revision: nz(ready.inventory_revision),
            },
        };
        // Build before exposing the semantic association. If preparation fails,
        // the new physical publication is rolled back by the exact receipt.
        pending.txn = Some(
            pending
                .context
                .state
                .page_tables_authority()
                .prepare_guest_descriptor_txn(nz(window.operation.mm.raw()), op)
                .map_err(|error| failure(format!("descriptor preparation: {error:?}")))?,
        );
        // The bytes are final zero-fill before EL1 can expose an executable
        // leaf. Reuse I2's existing first-executable-publication authority,
        // exactly as the normal EL1 lazy-grant path does.
        if window.protection.bits() & carrick_abi::LINUX_PROT_EXEC != 0 {
            pending
                .context
                .custody
                .publish_user_executable(
                    publication.alias.physical_ipa,
                    publication.alias.physical_size as u64,
                    |_, _| None,
                    |_, _| None,
                )
                .map_err(|error| failure(format!("executable grant publication: {error:?}")))?;
        }
        if !global_frame::register_shared_alias_if_vacant(
            publication.alias,
            pending.context.mm_root_slot,
            pending.context.container_root,
        ) {
            return Ok(None);
        }
        drop(pending.registry.take());
        Ok(Some(Box::new(pending)))
    }
}
impl carrick_aarch64::user_transfer::TransferGrant for PendingTransferGrant {
    fn transaction(&self) -> &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn {
        self.txn.as_ref().unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::user_transfer",
                "published pending grant has no descriptor transaction"
            )
        })
    }
    fn settle(
        &mut self,
        receipt: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt,
    ) -> Result<bool, TrapError> {
        use carrick_mmu_core::aarch64::descriptor_txn::DescriptorOutcome;
        let txn = self.txn.as_ref().unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::user_transfer",
                "published pending grant has no descriptor transaction"
            )
        });
        if receipt.id != txn.id
            || receipt.digest != txn.digest()
            || matches!(receipt.outcome, DescriptorOutcome::Indeterminate(_))
        {
            carrick_fatal!(
                "hvpatch::user_transfer",
                "grant completion cannot release uncertain descriptor-visible ownership"
            );
        }
        let applied = matches!(receipt.outcome, DescriptorOutcome::Applied(_));
        let result = self
            .context
            .state
            .page_tables_authority()
            .settle_guest_descriptor_receipt(txn, receipt);
        if applied {
            result.unwrap_or_else(|error| {
                carrick_fatal!(
                    "hvpatch::user_transfer",
                    "applied grant failed exact settlement; physical ownership retained: {error:?}"
                )
            });
            self.publication.take();
        } else if let Err(error) = result {
            if let carrick_aarch64::descriptor_drain::GuestPublishError::Unsettled(error) =
                carrick_aarch64::descriptor_drain::GuestPublishError::from_settle(
                    error,
                    "transfer grant refusal settlement",
                )
            {
                carrick_fatal!("hvpatch::user_transfer", "uncertain grant refusal: {error}");
            }
        }
        self.descriptor_settled = true;
        Ok(applied)
    }
}
impl Drop for PendingTransferGrant {
    fn drop(&mut self) {
        if !self.descriptor_settled
            && let Some(txn) = self.txn.as_ref()
        {
            self.context
                .state
                .page_tables_authority()
                .abandon_guest_descriptor_txn(txn)
                .unwrap_or_else(|error| {
                    carrick_fatal!(
                        "hvpatch::user_transfer",
                        "abandon exact grant tables: {error:?}"
                    )
                });
        }
        let Some(publication) = self.publication.take() else {
            return;
        };
        let binding = self
            .context
            .state
            .cow_runtime
            .read()
            .clone()
            .unwrap_or_else(|| {
                carrick_fatal!(
                    "hvpatch::user_transfer",
                    "pending target lost physical authority"
                )
            });
        let _registry = self.registry.take().unwrap_or_else(|| {
            crate::fork_quiesce::FrameRegistryGuard::acquire(
                carrick_observability::probes::HvpatchTopologyOperation::AliasUnmap,
                binding.identity.linux_pid,
                binding.identity.linux_tid,
            )
        });
        let (key, expected) = publication.inventory_entry;
        let mut inventory = self.context.state.frame_inventory.ledger.lock();
        let actual = inventory.extents.get(&key).copied();
        let length = carrick_hal::FrameLength::from_mapping_extent(
            std::num::NonZeroU64::new(key.1).unwrap_or_else(|| {
                carrick_fatal!(
                    "hvpatch::user_transfer",
                    "pending grant has empty physical extent"
                )
            }),
        );
        let exact_live = || {
            self.context
                .authority
                .mapping_is_live(
                    expected.mapping,
                    expected.frame,
                    carrick_guest_mem::Gpa(key.0),
                    length,
                )
                .unwrap_or_else(|error| {
                    carrick_fatal!(
                        "hvpatch::user_transfer",
                        "authenticate target grant inventory: {error}"
                    )
                })
        };
        let kernel_live = exact_live();
        let record_current = self
            .record
            .and_then(|identity| {
                self.context
                    .custody
                    .stage2_record_snapshot(identity.record_id)
                    .map(|record| (identity, record))
            })
            .is_some_and(|(identity, record)| {
                record.vm_generation == identity.vm_generation
                    && record.logical_owner == identity.logical_owner
            });
        if actual == Some(expected) {
            // Backend retirement can lag the kernel. A receipt-authenticated
            // absent mapping is already retired; never remove any successor.
            if kernel_live
                && let Err(error) = self
                    .context
                    .authority
                    .rollback_frame_grant(&publication.receipt)
            {
                if exact_live() {
                    carrick_fatal!(
                        "hvpatch::user_transfer",
                        "rollback exact target grant: {error}"
                    );
                }
            }
            alias_registry()
                .lock()
                .remove_exact_values_in_batch(&[publication.alias]);
            HvfVmState::rollback_unpublished_mappings(&mut inventory, &[(key, expected)])
                .unwrap_or_else(|error| {
                    carrick_fatal!("hvpatch::user_transfer", "rollback target backend: {error}")
                });
            drop(inventory);
            retire_global_frame_host_owner_if_generation_in(
                &self.context.custody,
                key.0,
                key.1,
                publication.ready.owner_generation,
            );
        } else {
            if kernel_live || !record_current {
                carrick_fatal!(
                    "hvpatch::user_transfer",
                    "pending grant retirement lacks exact inventory and retained owner evidence"
                );
            }
            // The old receipt is retired and the retained generation cannot
            // have been reused. A replacement backend entry belongs to its
            // successor and is untouched.
            alias_registry()
                .lock()
                .remove_exact_values_in_batch(&[publication.alias]);
        }
        let _ = &self.pin;
    }
}

/// A nontransferable source retains its own physical owner. Copying its bytes
/// into a new owner never imports its frame or source-directory authority.
pub struct RetainedImportSource {
    pin: GlobalFrameOwnerPin,
    _custody: std::sync::Arc<CarrierVmCustody>,
    offset: usize,
    len: usize,
}
impl RetainedImportSource {
    pub(crate) fn from_pin(
        pin: GlobalFrameOwnerPin,
        expected: CarrierStage2RecordIdentity,
        offset: usize,
        len: usize,
    ) -> Result<Self, TrapError> {
        let invalid = || TrapError::Hypervisor("stale or invalid retained import source".into());
        if pin.owner.record_identity != expected
            || len == 0
            || len > 16 * 1024
            || offset
                .checked_add(len)
                .is_none_or(|end| end > pin.owner.len())
        {
            return Err(invalid());
        }
        let custody = pin.owner.custody.upgrade().ok_or_else(invalid)?;
        let record = custody
            .stage2_record_snapshot(expected.record_id)
            .ok_or_else(invalid)?;
        // Existing retained pins remain readable after retirement is requested.
        // New acquisition is still governed by CarrierVmCustody::pin_stage2_record.
        if record.vm_generation != expected.vm_generation
            || record.logical_owner != expected.logical_owner
            || !record.mapped
            || record.terminalized_by_vm_destroy
        {
            return Err(invalid());
        }
        Ok(Self {
            pin,
            _custody: custody,
            offset,
            len,
        })
    }
    fn snapshot(&self) -> Vec<u8> {
        let mut bytes = vec![0; self.len];
        // SAFETY: exact source pin and retained mapping own the checked range,
        // including after its original directory or portal is destroyed.
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.pin.owner.ptr().add(self.offset),
                bytes.as_mut_ptr(),
                self.len,
            );
        }
        bytes
    }
}

/// Owns only a freshly acquired loader journal on the retained stage-1
/// authority. All import acquisition uses the same atomic fresh claim; this
/// non-clone owner is installed before source copying or physical publication.
struct ImportDescriptorUndo {
    tables: carrick_aarch64::Stage1Authority,
    resolver: std::sync::Arc<dyn carrick_mmu_core::aarch64::HostArenaResolver + Send + Sync>,
    active: bool,
}
impl ImportDescriptorUndo {
    fn begin(state: &MmAccessState) -> Result<Self, TrapError> {
        let failure =
            || TrapError::Hypervisor("import requires an unclaimed loader journal".into());
        let tables = state.page_tables_authority();
        let resolver = state.live_resolver.read().clone().ok_or_else(failure)?;
        tables.edit(
            || Err(failure()),
            |editor| {
                if !editor.begin_fresh_undo().map_err(|error| {
                    TrapError::Hypervisor(format!("import fresh undo: {error:?}"))
                })? {
                    return Err(failure());
                }
                Ok(())
            },
        )?;
        Ok(Self {
            tables,
            resolver,
            active: true,
        })
    }
    fn commit(&mut self) {
        self.tables.commit_undo();
        self.active = false;
    }
    fn rollback(&mut self) {
        if !self.active {
            return;
        }
        // SAFETY: this owner retains the exact resolver and fresh journal;
        // its caller still holds pre-admission mutation/publication authority.
        unsafe { self.tables.rollback_undo(&self.resolver) }.unwrap_or_else(|error| {
            carrick_fatal!(
                "hvpatch::user_transfer",
                "import descriptor rollback failed before physical release: {error:?}"
            )
        });
        self.active = false;
    }
}
impl Drop for ImportDescriptorUndo {
    fn drop(&mut self) {
        self.rollback();
    }
}

/// Physical publication remains rollback-owned until the same kernel owner
/// confirms normal root admission. The permit keeps publication exclusion alive.
pub struct PendingImport<'a> {
    descriptor_undo: ImportDescriptorUndo,
    permit: carrick_hal::PreAdmissionPermit<'a>,
    pending: PendingTransferGrant,
}
impl PendingImport<'_> {
    pub fn ready(&self) -> carrick_hal::El1FrameGrantReady {
        self.pending
            .publication
            .as_ref()
            .unwrap_or_else(|| {
                carrick_fatal!(
                    "hvpatch::user_transfer",
                    "pending import lost physical publication"
                )
            })
            .ready
    }
    pub fn commit(
        mut self,
        receipt: carrick_hal::PreAdmissionReceipt<'_>,
    ) -> Result<carrick_hal::El1FrameGrantReady, TrapError> {
        if !self.permit.authenticates(&receipt) || self.permit.unpublished() {
            return Err(TrapError::Hypervisor(
                "import admission receipt mismatch".into(),
            ));
        }
        let publication = self.pending.publication.take().unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::user_transfer",
                "pending import lost physical publication"
            )
        });
        self.descriptor_undo.commit();
        Ok(publication.ready)
    }
}
impl Drop for PendingImport<'_> {
    fn drop(&mut self) {
        if self.pending.publication.is_some() && !self.permit.unpublished() {
            carrick_fatal!(
                "hvpatch::user_transfer",
                "unsettled import is visible to an admitted root"
            );
        }
        self.descriptor_undo.rollback();
    }
}

impl PublicationContext<'static> {
    /// Physical setup has the existing kernel publication owner; it cannot
    /// borrow a current fault identity or touch a post-admission root.
    pub(crate) fn for_import(
        state: std::sync::Arc<MmAccessState>,
        custody: std::sync::Arc<CarrierVmCustody>,
        permit: &carrick_hal::PreAdmissionPermit<'_>,
    ) -> Result<Self, TrapError> {
        let invalid =
            || TrapError::Hypervisor("import requires exact unpublished host setup".into());
        let binding = state.cow_runtime.read().clone().ok_or_else(invalid)?;
        if !permit.unpublished()
            || permit.mm().get() != binding.identity.mm
            || state.page_tables_authority().live_descriptor_owner()
                != carrick_mmu_core::aarch64::LiveDescriptorOwner::Host
            || !binding.persistent_vm_lifecycle
        {
            return Err(invalid());
        }
        Ok(Self {
            mm_key: permit.mm(),
            state,
            custody,
            authority: binding.authority,
            mm_root_slot: binding.mm_root_slot,
            container_root: binding.container_root,
            _exclusion: None,
            _invocation: None,
            foreign: None,
        })
    }
    pub(crate) fn prepare_import<'a>(
        self,
        permit: carrick_hal::PreAdmissionPermit<'a>,
        source: RetainedImportSource,
        range: carrick_el1_abi::ReservationRange,
        protection: carrick_el1_abi::ReservationProtection,
    ) -> Result<PendingImport<'a>, TrapError> {
        let invalid = || TrapError::Hypervisor("invalid pre-admission import".into());
        if !permit.unpublished()
            || permit.mm() != self.mm_key
            || range.len() != source.len as u64
            || range.len() > 16 * 1024
            || protection.bits() == 0
            || self.state.page_tables_authority().live_descriptor_owner()
                != carrick_mmu_core::aarch64::LiveDescriptorOwner::Host
        {
            return Err(invalid());
        }
        let descriptor_undo = ImportDescriptorUndo::begin(&self.state)?;
        let bytes = source.snapshot();
        let binding = self.state.cow_runtime.read().clone().ok_or_else(invalid)?;
        let registry = crate::fork_quiesce::FrameRegistryGuard::acquire(
            carrick_observability::probes::HvpatchTopologyOperation::SiblingMaterialize,
            binding.identity.linux_pid,
            binding.identity.linux_tid,
        );
        if !alias_registry()
            .lock()
            .overlapping_process_aliases(
                range.start(),
                range.len() as usize,
                self.mm_root_slot,
                self.container_root,
            )
            .is_empty()
        {
            return Err(invalid());
        }
        let publication = publish_frame_grant_backing(
            &self,
            carrick_hal::El1FrameGrantRequest {
                mm_key: self.mm_key.get(),
                fault_va: range.start(),
                access: 1,
                semantic_base: range.start(),
                len: range.len(),
                permissions: protection.bits(),
            },
            None,
            SparseExtentBacking::SeededAnon { bytes: &bytes },
            &registry,
        )?;
        // From the first successful publication, every fallible step has an
        // exact rollback owner, including the already-held registry guard.
        let mut pending = PendingTransferGrant {
            context: self,
            registry: Some(registry),
            publication: Some(publication),
            pin: None,
            record: None,
            txn: None,
            descriptor_settled: false,
        };
        let publication = pending.publication.as_ref().unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::user_transfer",
                "new import lost physical publication"
            )
        });
        let owner = pending
            .context
            .custody
            .global_frame_host_owners
            .lock()
            .get(&publication.inventory_entry.0)
            .and_then(GlobalFrameOwnerEntry::live_owner)
            .cloned()
            .ok_or_else(invalid)?;
        pending.record = Some(owner.record_identity);
        pending.pin = Some(
            pending
                .context
                .custody
                .pin_stage2_record(owner.record_identity)
                .map_err(|_| invalid())?,
        );
        if !global_frame::register_shared_alias_if_vacant(
            publication.alias,
            pending.context.mm_root_slot,
            pending.context.container_root,
        ) {
            return Err(invalid());
        }
        if protection.bits() & 4 != 0 {
            pending
                .context
                .custody
                .publish_user_executable(
                    publication.alias.physical_ipa,
                    publication.alias.physical_size as u64,
                    |_, _| None,
                    |_, _| None,
                )
                .map_err(|error| {
                    TrapError::Hypervisor(format!("import executable publication: {error:?}"))
                })?;
        }
        drop(pending.registry.take());
        let import = PendingImport {
            permit,
            pending,
            descriptor_undo,
        };
        let resolver = &import.descriptor_undo.resolver;
        let ready = import.ready();
        import.descriptor_undo.tables.edit(
            || Err(invalid()),
            |editor| {
                editor
                    .map_private_aliased(
                        range.start(),
                        ready.physical_ipa,
                        range.len(),
                        carrick_mmu_core::aarch64::UserLeafAccess {
                            writable: protection.bits() & 2 != 0,
                            executable: protection.bits() & 4 != 0,
                        },
                    )
                    .map_err(|error| {
                        TrapError::Hypervisor(format!("import descriptors: {error:?}"))
                    })?;
                // SAFETY: retained resolver names the exact unpublished target.
                unsafe { editor.sync_to_host(resolver) }.map_err(|error| {
                    TrapError::Hypervisor(format!("import descriptor publication: {error:?}"))
                })
            },
        )?;
        Ok(import)
    }
}
