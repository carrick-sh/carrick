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
    const TWO_MIB: u64 = 2 * 1024 * 1024;
    let block_congruence =
        matches!(backing, SparseExtentBacking::FileView { .. }) || end - start >= TWO_MIB;
    let layout = allocation_layout(start, end, block_congruence)?;
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
    // Bulk mappings and file views retain their existing block congruence.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymous_first_touch_never_allocates_a_block_of_padding() {
        for page in (0..512_u32).rev() {
            let start = u64::from(page) * 4096;
            let layout = allocation_layout(start, start + 4096, false).unwrap();
            assert_eq!(layout.length, HVF_PAGE_SIZE, "4 KiB fault at {start:#x}");
            assert_eq!(layout.alignment, HVF_PAGE_SIZE);
            assert_eq!(layout.offset, start % HVF_PAGE_SIZE);
        }
    }

    #[test]
    fn block_and_file_views_preserve_block_congruence() {
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
    fn sparse_allocation_rejects_invalid_semantic_ranges() {
        for (start, end) in [(0, 0), (4096, 0), (1, 4096), (0, 4097)] {
            assert!(allocation_layout(start, end, false).is_err());
        }
    }
}
