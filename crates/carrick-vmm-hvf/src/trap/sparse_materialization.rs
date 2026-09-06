//! Executor-independent preparation of sparse backing. The returned rollback
//! owner keeps stage-2 custody provisional until the caller publishes inventory
//! and stage-1 successfully. No guest permission is granted by preparation.
use super::*;

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
    // A 2 MiB-aligned global-frame base plus the semantic VA's 2 MiB
    // offset preserves VA/IPA alignment. The stage-1 editor can therefore
    // use block leaves for the aligned bulk and needs 4 KiB leaves only at
    // the two edges. This is still one physical/stage-2 lease per VMA.
    const TWO_MIB: u64 = 2 * 1024 * 1024;
    let physical_offset = start & (TWO_MIB - 1);
    let physical_len = align_up(
        physical_offset
            .checked_add(end - start)
            .ok_or_else(|| TrapError::Hypervisor("sparse mmap size overflow".to_owned()))?,
        HVF_PAGE_SIZE,
    )?;
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
        let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            physical_size,
            crate::host_mapping::HostMappingKind::PrivateAnon,
        )
        .map_err(|error| {
            TrapError::Hypervisor(format!("allocate sparse HVPatch mmap backing: {error}"))
        })?;
        let physical_host = host_mapping.as_ptr();
        let semantic_host = unsafe { physical_host.add(physical_offset as usize) };
        // A file view replaces whole 16 KiB host pages of the anonymous
        // backing with a read-only page-cache view BEFORE stage-2 sees the
        // range: the physical host bytes under a live `hv_vm_map` are never
        // remapped. Congruence (`start ≡ offset mod 16 KiB`, enforced by the
        // driver) makes the host page containing `start` the host page
        // containing the file page at `offset`.
        let (stage2_perms, inventory_backing, page_granular_arm) = match backing {
            SparseExtentBacking::Anon => (
                applevisor::memory::MemPerms::ReadWriteExec,
                HvfVmState::private_backing_identity(),
                false,
            ),
            SparseExtentBacking::FileView {
                fd,
                offset,
                view_len,
                source,
            } => {
                let delta = start & (HVF_PAGE_SIZE - 1);
                if offset & (HVF_PAGE_SIZE - 1) != delta {
                    return Err(TrapError::Hypervisor(format!(
                        "private file view VA 0x{start:x} not congruent with offset 0x{offset:x}"
                    )));
                }
                let host_at = physical_offset - delta;
                let view_len = view_len.min(end - start);
                let view_host_len =
                    align_up(delta + view_len, HVF_PAGE_SIZE)?.min(physical_len - host_at);
                let view_host_size = usize::try_from(view_host_len)
                    .map_err(|_| TrapError::MappingTooLarge(view_host_len))?;
                let file_offset = libc::off_t::try_from(offset - delta).map_err(|_| {
                    TrapError::Hypervisor(format!("private file view offset 0x{offset:x} overflow"))
                })?;
                host_mapping
                    .overlay_file_view(
                        usize::try_from(host_at)
                            .map_err(|_| TrapError::MappingTooLarge(host_at))?,
                        fd,
                        file_offset,
                        view_host_size,
                        source == carrick_guest_mem::PrivateFileSource::ImmutableLower,
                    )
                    .map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "overlay private file view at VA 0x{start:x}: {error}"
                        ))
                    })?;
                // Stage-2 is RWX on the frame; stage-1 carries the guest
                // permission (AP_RO/UXN) and armed page-granular COW until
                // privatized on first write.
                (
                    applevisor::memory::MemPerms::ReadWriteExec,
                    HvfVmState::private_file_view_backing_identity(),
                    true,
                )
            }
        };
        let mut lease = GlobalFrameStage2Lease::reserve(physical_len, TWO_MIB)?;
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
