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
            SparseExtentBacking::Anon | SparseExtentBacking::SeededAnon { .. } => (
                applevisor::memory::MemPerms::ReadWriteExec,
                HvfVmState::private_backing_identity(),
                false,
            ),
            SparseExtentBacking::FileView { .. } => {
                // Mutable files use a writable host MAP_SHARED view so HVF can
                // access the VM object and clean pages follow file writes.
                // Immutable lower files use a writable MAP_PRIVATE view. In
                // both cases stage-1 stays page-granular COW armed, so guest
                // and foreign writes first create Carrick-owned private pages.
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
    fn bulk_anonymous_views_preserve_block_congruence() {
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
        manager: &carrick_mem::page_table::PageTableManager,
        root_perms: applevisor::memory::MemPerms,
    ) -> Result<Vec<HvfMappedRegion>, TrapError> {
        let mut published = Vec::new();
        self.publish_stage1_extension_arenas_into(custody, manager, root_perms, &mut published)?;
        Ok(published)
    }

    fn publish_stage1_extension_arenas_into(
        &self,
        custody: &std::sync::Arc<CarrierVmCustody>,
        manager: &carrick_mem::page_table::PageTableManager,
        root_perms: applevisor::memory::MemPerms,
        published: &mut Vec<HvfMappedRegion>,
    ) -> Result<(), TrapError> {
        const TWO_MIB: usize = 2 * 1024 * 1024;
        for base in manager.extension_arena_bases() {
            if self.structural_owners.read().contains_key(&(base, TWO_MIB)) {
                continue;
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

            let mut region = HvfMappedRegion {
                start: base,
                end: base + TWO_MIB as u64,
                ipa: base,
                physical_ipa: base,
                physical_size: TWO_MIB,
                owner_generation: 0,
                host_addr: host_mapping.as_ptr(),
                size: TWO_MIB,
                perms: root_perms,
                memory: None,
                host_mapping: Some(host_mapping),
                structural_owner: None,
                stage2_lease: None,
                is_dynamic_alias: false,
                sharing: GuestMappingSharing::Private,
                guest_writable: true,
                shared_key_base: 0,
                shared_key_offset: 0,
            };

            let _ = publish_exec_region_host_owner_in(custody, &mut region, lease, None)?;

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
            // `PtQuiesce` barrier and executor census OWNED BY THE SHARED
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
    flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
) -> Result<PublishedSparseExtent, TrapError> {
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
                    editor.begin_undo();
                    HvfVmState::refresh_stage1_exclusivity(editor.manager);
                    let aligned_start = align_up(start, TWO_MIB)?.min(end);
                    if start < aligned_start {
                        editor
                            .map_private_aliased(start, semantic_ipa, aligned_start - start, false)
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
                                false,
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
                                false,
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
                    }.map_err(|error| TrapError::Hypervisor(format!(
                        "publish sparse HVPatch mmap stage-1 permissions: {error:?}"
                    )))?;
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
                    unsafe { editor.sync_to_host(&page_table_resolver) }.map_err(|e| {
                        TrapError::Hypervisor(format!(
                            "sparse HVPatch mmap sync_to_host failed: {e:?}"
                        ))
                    })?;
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
                            let leaf = carrick_mem::page_table::terminal_descriptor(live);
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
                    editor.rollback_undo_retiring(resolver, |popped| {
                        flush_stage1()?;
                        let journal = extension_regions
                            .iter()
                            .filter_map(|region| {
                                region
                                    .structural_owner
                                    .as_ref()
                                    .map(|owner| (owner.physical_ipa, std::sync::Arc::clone(owner)))
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
                    })?;
                }
                Ok::<(), TrapError>(())
            },
        );
        if let Err(rollback_error) = rollback {
            eprintln!("carrick: FATAL: sparse HVPatch mmap rollback failed: {rollback_error}");
            std::process::abort();
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
    if let Err(error) = flush_stage1() {
        eprintln!("carrick: FATAL: sparse HVPatch mmap TLBI failed: {error}");
        std::process::abort();
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
                std::num::NonZeroUsize::new(semantic_len).unwrap_or_else(|| std::process::abort()),
                inventory_mapping.mapping,
                inventory_mapping.frame,
                carrick_guest_mem::Gpa(physical_ipa),
                carrick_hal::FrameLength::from_mapping_extent(
                    std::num::NonZeroU64::new(physical_len)
                        .unwrap_or_else(|| std::process::abort()),
                ),
            )
            .unwrap_or_else(|_| std::process::abort());
        if generation.raw_for_probe() != owner_generation
            || !challenge.authenticate_apply(
                &receipt,
                std::num::NonZeroU64::new(requested.mm.raw_for_probe())
                    .unwrap_or_else(|| std::process::abort()),
            )
            || !receipt.authorizes(inventory_mapping.mapping, inventory_mapping.frame)
        {
            std::process::abort();
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
            eprintln!("carrick: FATAL: sparse HVPatch mmap inventory commit failed: {error}");
            std::process::abort();
        }
        None
    };
    owner_rollback.commit();

    match context.authority.mapping_is_live(
        inventory_mapping.mapping,
        inventory_mapping.frame,
        carrick_guest_mem::Gpa(physical_ipa),
        carrick_hal::FrameLength::from_mapping_extent(
            std::num::NonZeroU64::new(physical_len).unwrap_or_else(|| std::process::abort()),
        ),
    ) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("carrick: FATAL: sparse HVPatch mmap absent after commit");
            std::process::abort();
        }
        Err(error) => {
            eprintln!("carrick: FATAL: authenticate sparse HVPatch mmap: {error}");
            std::process::abort();
        }
    }

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
        shared_key_base: 0,
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
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation,
    };
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
}
impl carrick_mem::page_table::HostArenaResolver for PinnedStage1Arenas {
    fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
        <&Self as carrick_mem::page_table::HostArenaResolver>::host_ptr_for_base(&self, base)
    }
    fn record_populated_prefix(&self, base: u64, prefix: usize) {
        <&Self as carrick_mem::page_table::HostArenaResolver>::record_populated_prefix(
            &self, base, prefix,
        );
    }
}
impl carrick_mem::page_table::HostArenaResolver for &PinnedStage1Arenas {
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
        })
    }
}

#[cfg(test)]
mod arena_pin_tests {
    use super::*;
    use carrick_mem::page_table::HostArenaResolver;

    #[test]
    fn publication_resolver_pins_exact_primary_owner_until_edit_finishes() {
        check_pinned_arena(carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize);
    }

    #[test]
    fn publication_resolver_pins_exact_full_slot_until_edit_finishes() {
        check_pinned_arena(2 * 1024 * 1024);
    }

    #[test]
    fn publication_resolver_pins_relocated_root_global_owner() {
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
        let state = MmAccessState::new(
            carrick_aarch64::Stage1Authority::new(),
            std::sync::Arc::new(MemoryProtections::default()),
            std::sync::Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
            std::sync::Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
            std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
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
        let state = MmAccessState::new(
            carrick_aarch64::Stage1Authority::new(),
            std::sync::Arc::new(MemoryProtections::default()),
            std::sync::Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
            std::sync::Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
            std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
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
        let state = MmAccessState::new(
            carrick_aarch64::Stage1Authority::new(),
            std::sync::Arc::new(MemoryProtections::default()),
            std::sync::Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
            std::sync::Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
            std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
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
