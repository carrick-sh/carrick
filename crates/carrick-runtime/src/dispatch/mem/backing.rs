//! Backing store management: host aliases, private file maps, shared apertures,
//! memfd tracking, secretmem, and file lowering.

use super::*;
use crate::dispatch::dispatcher::MemView;
use carrick_abi::LinuxProtFlags;
use carrick_fatal::carrick_fatal;
use carrick_guest_mem::GuestVa;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrivateRepointRecovery {
    RecoveredCleanly,
    FailStopRetainingOwners,
}

#[derive(Clone, Debug)]
pub(crate) struct MremapMappingMetadata {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) prot: LinuxProtFlags,
    pub(crate) sharing: ProcMapSharing,
    pub(crate) path: String,
    pub(crate) file_page_offset: Option<u64>,
    pub(crate) droppable: bool,
    pub(crate) fork_semantics: MremapForkSemantics,
    pub(crate) private_file: Option<PrivateFileMapEntry>,
}

pub(crate) struct DynamicMappingSemantics {
    pub(crate) file_page_offset: Option<u64>,
    pub(crate) droppable: bool,
    pub(crate) semantic_vmas: Option<Vec<SemanticVma>>,
}

pub(crate) fn proc_maps_entry_mremap_metadata(
    map: &ProcMapsEntry,
    file_page_offset: Option<u64>,
    fork_semantics: MremapForkSemantics,
) -> MremapMappingMetadata {
    let mut prot = LinuxProtFlags::empty();
    if map.read {
        prot |= LinuxProtFlags::READ;
    }
    if map.write {
        prot |= LinuxProtFlags::WRITE;
    }
    if map.execute {
        prot |= LinuxProtFlags::EXEC;
    }
    MremapMappingMetadata {
        start: map.start,
        end: map.end,
        prot,
        sharing: map.sharing,
        path: map.path.clone(),
        file_page_offset,
        droppable: fork_semantics.any_droppable(),
        fork_semantics,
        private_file: None,
    }
}

/// Dispatcher metadata published only after a runtime `MapHostAlias` install
/// succeeds. Keeping the complete commit record out of `MemState` until then
/// makes an mmap/protection failure a no-op for the prior VMA and every
/// range-derived classification.
pub(crate) struct HostAliasMmapCommit {
    pub(crate) start: u64,
    pub(crate) len: u64,
    pub(crate) prot: LinuxProtFlags,
    pub(crate) sharing: ProcMapSharing,
    pub(crate) path: String,
    pub(crate) file_page_offset: Option<u64>,
    pub(crate) droppable: bool,
    pub(crate) semantic_vmas: Option<Vec<SemanticVma>>,
    pub(crate) locked: Option<crate::vfs::GuestMemoryRange>,
    pub(crate) resident: bool,
    pub(crate) bus_fault: Option<(u64, u64)>,
    pub(crate) write_sealed_shared: bool,
    pub(crate) read_only_shared_file: bool,
    /// The mapping is backed by a `memfd_secret(2)` fd: its pages are
    /// hidden from `/proc/<pid>/mem` (memfdsecret probe `procmem_hidden`).
    pub(crate) secretmem: bool,
    pub(crate) writable_memfd: Option<Arc<crate::kernel::FileDescription>>,
    /// The open-file description behind a live `MAP_SHARED` file alias, kept so
    /// `mremap` can still find the file after the guest closes its own fd,
    /// paired with the extent base IPA and file offset.
    pub(crate) shared_file_alias: Option<SharedFileAliasCommit>,
    pub(crate) private_file: Option<PrivateFileMapEntry>,
}

#[derive(Clone)]
pub(crate) struct PrivateFileMapEntry {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) offset: u64,
    pub(crate) backing: PrivateFileBacking,
}

#[derive(Clone)]
pub(crate) enum PrivateFileBacking {
    Description(Arc<crate::kernel::objects::MappedFileReference>),
    LoadedImage {
        initialized_offset: u64,
        bytes: Arc<Vec<u8>>,
    },
}

pub(crate) fn boot_private_file_backings(
    image: &crate::memory::AddressSpace,
) -> Vec<PrivateFileMapEntry> {
    let mut sources = Vec::new();
    for mapping in image.file_mappings().iter().filter(|m| !m.path.is_empty()) {
        for region in image.regions() {
            let start = mapping.start.max(region.start);
            let end = mapping.end.min(region.end);
            if start >= end {
                continue;
            }
            // Retain canonical loaded bytes, including backend patches, with
            // no eager copy. Guest stores cannot mutate this image payload.
            let (initialized_offset, bytes) = region.shared_initialized_bytes();
            sources.push(PrivateFileMapEntry {
                start,
                end,
                offset: start - region.start,
                backing: PrivateFileBacking::LoadedImage {
                    initialized_offset,
                    bytes,
                },
            });
        }
    }
    sources
}

impl std::fmt::Debug for PrivateFileMapEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateFileMapEntry")
            .field("start", &self.start)
            .field("end", &self.end)
            .field("offset", &self.offset)
            .finish_non_exhaustive()
    }
}

impl PrivateFileMapEntry {
    pub(crate) fn for_mapping(
        description: &Option<Arc<crate::kernel::objects::MappedFileReference>>,
        start: u64,
        len: u64,
        offset: u64,
    ) -> Option<Self> {
        Some(Self {
            start,
            end: start.checked_add(len)?,
            offset,
            backing: PrivateFileBacking::Description(Arc::clone(description.as_ref()?)),
        })
    }

    pub(crate) fn clip(&self, start: u64, end: u64) -> Option<Self> {
        let start = self.start.max(start);
        let end = self.end.min(end);
        if start >= end {
            return None;
        }
        Some(Self {
            start,
            end,
            offset: self.offset.checked_add(start - self.start)?,
            backing: self.backing.clone(),
        })
    }
}

pub(crate) fn trim_private_file_maps(maps: &mut Vec<PrivateFileMapEntry>, start: u64, len: u64) {
    let end = start.saturating_add(len);
    let mut retained = Vec::with_capacity(maps.len() + 1);
    for entry in maps.drain(..) {
        if entry.end <= start || entry.start >= end {
            retained.push(entry);
        } else {
            retained.extend(entry.clip(entry.start, start));
            retained.extend(entry.clip(end, entry.end));
        }
    }
    *maps = retained;
}

#[derive(Clone)]
pub(crate) struct SharedFileAliasCommit {
    pub(crate) description: Arc<crate::kernel::FileDescription>,
    pub(crate) extent_base: carrick_guest_mem::Gpa,
    pub(crate) row_file_offset: u64,
}

#[derive(Clone)]
pub(crate) struct SharedFileAliasEntry {
    pub(crate) range: crate::vfs::GuestMemoryRange,
    pub(crate) description: Arc<crate::kernel::FileDescription>,
    pub(crate) extent_base: carrick_guest_mem::Gpa,
    pub(crate) row_file_offset: u64,
}

pub(crate) fn prot_to_proc_perms(prot: LinuxProtFlags) -> (bool, bool, bool) {
    (
        prot.contains(LinuxProtFlags::READ),
        prot.contains(LinuxProtFlags::WRITE),
        prot.contains(LinuxProtFlags::EXEC),
    )
}

pub(crate) fn trim_shared_file_alias_maps_for_range(
    maps: &mut Vec<SharedFileAliasEntry>,
    start: u64,
    len: u64,
) {
    let Some(end) = start.checked_add(len) else {
        maps.clear();
        return;
    };
    let mut retained = Vec::with_capacity(maps.len() + 1);
    for entry in maps.drain(..) {
        let range_start = entry.range.start().raw();
        let range_end = entry.range.end().raw();
        if range_start >= end || start >= range_end {
            retained.push(entry);
            continue;
        }
        if range_start < start
            && let Some(prefix) = crate::vfs::GuestMemoryRange::new(
                GuestVa(range_start),
                GuestVa(start.min(range_end)),
            )
        {
            retained.push(SharedFileAliasEntry {
                range: prefix,
                description: Arc::clone(&entry.description),
                extent_base: entry.extent_base,
                row_file_offset: entry.row_file_offset,
            });
        }
        if end < range_end
            && let Some(suffix) =
                crate::vfs::GuestMemoryRange::new(GuestVa(end.max(range_start)), GuestVa(range_end))
        {
            let suffix_start = end.max(range_start);
            let suffix_offset = entry
                .row_file_offset
                .saturating_add(suffix_start.saturating_sub(range_start));
            retained.push(SharedFileAliasEntry {
                range: suffix,
                description: entry.description,
                extent_base: entry.extent_base,
                row_file_offset: suffix_offset,
            });
        }
    }
    *maps = retained;
}

pub(crate) fn trim_writable_memfd_maps_for_range(
    maps: &mut Vec<(
        crate::vfs::GuestMemoryRange,
        Arc<crate::kernel::FileDescription>,
    )>,
    start: u64,
    len: u64,
) {
    let Some(end) = start.checked_add(len) else {
        maps.clear();
        return;
    };
    let mut retained = Vec::with_capacity(maps.len() + 1);
    for (range, description) in maps.drain(..) {
        let range_start = range.start().raw();
        let range_end = range.end().raw();
        if range_start >= end || start >= range_end {
            retained.push((range, description));
            continue;
        }
        if range_start < start
            && let Some(prefix) = crate::vfs::GuestMemoryRange::new(
                GuestVa(range_start),
                GuestVa(start.min(range_end)),
            )
        {
            retained.push((prefix, std::sync::Arc::clone(&description)));
        }
        if end < range_end
            && let Some(suffix) =
                crate::vfs::GuestMemoryRange::new(GuestVa(end.max(range_start)), GuestVa(range_end))
        {
            retained.push((suffix, description));
        }
    }
    *maps = retained;
}

pub(crate) fn trim_ranges_for_range(ranges: &mut Vec<(u64, u64)>, start: u64, len: u64) {
    let Some(end) = start.checked_add(len) else {
        ranges.clear();
        return;
    };
    let mut next = Vec::with_capacity(ranges.len());
    for (range_start, range_len) in ranges.drain(..) {
        let Some(range_end) = range_start.checked_add(range_len) else {
            continue;
        };
        if !ranges_overlap(start, len, range_start, range_end) {
            next.push((range_start, range_len));
            continue;
        }
        if range_start < start {
            next.push((range_start, start - range_start));
        }
        if end < range_end {
            next.push((end, range_end - end));
        }
    }
    *ranges = next;
}

pub(crate) fn trim_remap_snapshots_for_range(
    snapshots: &mut std::collections::HashMap<u64, Vec<u8>>,
    start: u64,
    len: u64,
) {
    let Some(end) = start.checked_add(len) else {
        snapshots.clear();
        return;
    };
    let mut retained = std::collections::HashMap::with_capacity(snapshots.len() + 1);
    for (snapshot_start, bytes) in std::mem::take(snapshots) {
        let Some(snapshot_len) = u64::try_from(bytes.len()).ok() else {
            continue;
        };
        let Some(snapshot_end) = snapshot_start.checked_add(snapshot_len) else {
            continue;
        };
        if snapshot_start >= end || start >= snapshot_end {
            retained.insert(snapshot_start, bytes);
            continue;
        }
        if snapshot_start < start {
            let prefix_len = usize::try_from(start - snapshot_start)
                .unwrap_or(bytes.len())
                .min(bytes.len());
            retained.insert(snapshot_start, bytes[..prefix_len].to_vec());
        }
        if end < snapshot_end {
            let suffix_offset = usize::try_from(end - snapshot_start)
                .unwrap_or(bytes.len())
                .min(bytes.len());
            retained.insert(end, bytes[suffix_offset..].to_vec());
        }
    }
    *snapshots = retained;
}

pub(crate) fn update_proc_map_prot(
    maps: &mut Vec<ProcMapsEntry>,
    start: u64,
    len: u64,
    prot: LinuxProtFlags,
) {
    let (read, write, execute) = prot_to_proc_perms(prot);
    let Some(end) = start.checked_add(len) else {
        return;
    };
    let previous = std::mem::take(maps);
    let mut updated = Vec::with_capacity(previous.len().saturating_add(2));
    for map in previous {
        if map.start >= end || map.end <= start {
            updated.push(map);
            continue;
        }
        let protected_start = map.start.max(start);
        let protected_end = map.end.min(end);
        if map.start < protected_start {
            let mut left = map.clone();
            left.end = protected_start;
            updated.push(left);
        }
        let mut protected = map.clone();
        protected.start = protected_start;
        protected.end = protected_end;
        protected.read = read;
        protected.write = write;
        protected.execute = execute;
        updated.push(protected);
        if protected_end < map.end {
            let mut right = map;
            right.start = protected_end;
            updated.push(right);
        }
    }
    *maps = updated;
}

pub(crate) fn trim_live_boot_regions_for_range(mem: &mut MemState, start: u64, len: u64) {
    let Some(regions) = mem.address_space_regions.as_mut() else {
        return;
    };
    let layout = mem.layout;
    let mut visible = Vec::new();
    let mut reservations = Vec::new();
    for region in regions.drain(..) {
        if boot_region_is_hidden_reservation(&region, layout) {
            reservations.push(region);
        } else {
            visible.push(region);
        }
    }
    trim_dynamic_maps_for_range(&mut visible, start, len);
    visible.extend(reservations);
    visible.sort_by_key(|region| region.start);
    *regions = visible;
}

pub(crate) fn trim_growdown_ranges_for_range(mem: &mut MemState, start: u64, len: u64) {
    let end = start.saturating_add(len);
    mem.growdown_ranges.retain_mut(|(_low, current, vma_end)| {
        if end <= *current || start >= *vma_end {
            return true;
        }
        if start <= *current {
            // Removing the lower edge (or the entire VMA) leaves no live
            // downward-growth frontier. Any surviving upper fragment remains
            // represented by `dynamic_maps` but cannot regrow this hole.
            return false;
        }
        // Removing a suffix or middle range leaves only the lower fragment as
        // the grow-down VMA. The ordinary dynamic-map trim retains any upper
        // non-growing fragment separately.
        *vma_end = start;
        *current < *vma_end
    });
}

pub(crate) fn remove_mapping_metadata_locked(mem: &mut MemState, start: u64, len: u64) {
    // Metadata retirement also revokes zero-read authority for the old VMA.
    if len != 0 {
        let _ = mem.deferred_anonymous.retire(GuestVa(start), len as usize);
    }
    if let Some(end) = start.checked_add(len) {
        mem.semantic_vmas.remove_range(start, end);
    }
    trim_dynamic_maps_for_range(&mut mem.dynamic_maps, start, len);
    trim_core_file_mappings_for_range(&mut mem.core_file_mappings, start, len);
    trim_live_boot_regions_for_range(mem, start, len);
    trim_growdown_ranges_for_range(mem, start, len);
    trim_ranges_for_range(&mut mem.bus_fault_ranges, start, len);
    trim_writable_memfd_maps_for_range(&mut mem.writable_memfd_maps, start, len);
    trim_shared_file_alias_maps_for_range(&mut mem.shared_file_alias_maps, start, len);
    trim_private_file_maps(&mut mem.private_file_maps, start, len);
    trim_remap_snapshots_for_range(&mut mem.remap_snapshots, start, len);
    let Some(remove) =
        crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start.saturating_add(len)))
    else {
        return;
    };
    locked_ranges_remove(&mut mem.locked_ranges, remove);
    locked_ranges_remove(&mut mem.resident_ranges, remove);
    locked_ranges_remove(&mut mem.resident_tracked_ranges, remove);
    mem.resident_fault_ranges.disarm(remove);
    locked_ranges_remove(&mut mem.write_sealed_shared_maps, remove);
    locked_ranges_remove(&mut mem.secretmem_maps, remove);
    locked_ranges_remove(&mut mem.read_only_shared_file_maps, remove);
    locked_ranges_remove(&mut mem.host_alias_backed_ranges, remove);
    locked_ranges_remove(&mut mem.alias_vma_ranges, remove);
}

pub(crate) fn trim_core_file_mappings_for_range(
    mappings: &mut Vec<crate::core_dump::FileMapping>,
    start: u64,
    len: u64,
) {
    let Some(end) = start.checked_add(len) else {
        mappings.clear();
        return;
    };
    let mut next = Vec::with_capacity(mappings.len() + 1);
    for mapping in mappings.drain(..) {
        if end <= mapping.start || start >= mapping.end {
            next.push(mapping);
            continue;
        }
        if mapping.start < start {
            let mut left = mapping.clone();
            left.end = start;
            next.push(left);
        }
        if end < mapping.end {
            let mut right = mapping;
            let removed_pages =
                end.saturating_sub(right.start) / crate::core_dump::GUEST_PAGE as u64;
            right.start = end;
            right.file_page_offset = right.file_page_offset.saturating_add(removed_pages);
            next.push(right);
        }
    }
    next.sort_by_key(|mapping| (mapping.start, mapping.end));
    *mappings = next;
}

pub(crate) fn shared_file_bus_offset(
    file_len: u64,
    offset: u64,
    length: u64,
    page_size: u64,
) -> Option<u64> {
    let bytes_available = file_len.saturating_sub(offset).min(length);
    let bus_start = align_up_u64(bytes_available, page_size)?;
    (bus_start < length).then_some(bus_start)
}

/// Can `fd` back a live `MAP_SHARED` stage-2 alias?
///
/// Darwin caps a `MAP_SHARED` file mapping's `max_protection` at the backing
/// fd's access mode: an `O_RDONLY` fd yields `max_protection = READ|EXECUTE`,
/// and `mprotect(PROT_WRITE)` on that region fails `EACCES` no matter what
/// `protection` the mapping was created with. `hv_vm_map` then refuses the
/// region outright with `HV_ERROR` — carrick installs alias extents with
/// permissive RWX stage-2 rights, so HVF requires a host region whose
/// `max_protection` includes write. The requested protection is NOT the
/// discriminator: a `PROT_READ` mapping of an `O_RDWR` fd maps fine.
///
/// Host opens carry the guest's own access mode (an `O_RDWR` APFS open costs
/// ~1.7x an `O_RDONLY` one, and most guest opens are read-only), so a
/// guest-read-only description normally fails this check; the mmap alias path
/// then asks the backend to re-open the fd `O_RDWR` in place
/// (`FsBackend::upgrade_host_fd_for_shared_map`) before giving up. Files
/// served from the IMMUTABLE shared layer cache are the case the upgrade
/// refuses, and deliberately so: that store is content-addressed and shared
/// across containers and runs, so handing a guest an RWX stage-2 view of it
/// would let one guest corrupt every other run's cache and would defeat the
/// overlay's copy-up. Such a mapping falls back to the snapshot path instead
/// — observationally equivalent for a read-only mapping of a layer that
/// cannot change under it.
///
/// Only Darwin/HVF carries this constraint; other hosts keep the live alias.
#[cfg(target_os = "macos")]
pub(crate) fn host_fd_can_back_shared_alias(fd: i32) -> bool {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDWR
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn host_fd_can_back_shared_alias(_fd: i32) -> bool {
    true
}

pub(crate) fn host_fd_file_len(fd: i32) -> Option<u64> {
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } == 0 && st.st_size >= 0 {
        Some(st.st_size as u64)
    } else {
        None
    }
}

/// Move-3 E1 opt-out hatch: the file-backed `MAP_PRIVATE` lowering is ON by
/// default; `CARRICK_MMAP_FILE_BACKED=0` restores the eager snapshot path for
/// bisection. Read per call (a handful of guest mmaps per millisecond at
/// worst; `getenv` is allocation- and syscall-free) so tests and forked guests
/// observe the current environment rather than a process-cached copy.
pub(crate) fn mmap_file_backed_lowering_enabled() -> bool {
    std::env::var_os("CARRICK_MMAP_FILE_BACKED").is_none_or(|value| value != *"0")
}

/// Eager MAP_PRIVATE materialization plus its map-time Linux EOF contract.
/// Bytes through the last partially backed page are snapshotted and its EOF
/// remainder stays zero-filled; pages wholly beyond that boundary are published
/// as BUS_ADRERR. Carrick's existing private-file approximation is detached from
/// the vnode, so a later external truncate is deliberately not tracked.
pub(crate) struct PrivateMmapSnapshot {
    pub(crate) bytes: Vec<u8>,
    pub(crate) bus_fault_offset: Option<u64>,
}

pub(crate) fn snapshot_private_host_file(
    host_fd: i32,
    offset: u64,
    bytes: &mut [u8],
) -> Result<(), LinuxErrno> {
    let mut copied = 0usize;
    while copied < bytes.len() {
        let copied_offset = u64::try_from(copied).map_err(|_| linux_errno::EOVERFLOW)?;
        let file_offset = offset
            .checked_add(copied_offset)
            .and_then(|value| libc::off_t::try_from(value).ok())
            .ok_or(linux_errno::EOVERFLOW)?;
        let read = unsafe {
            libc::pread(
                host_fd,
                bytes[copied..].as_mut_ptr().cast::<libc::c_void>(),
                bytes.len() - copied,
                file_offset,
            )
        };
        if read == 0 {
            break;
        }
        if read < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(linux_errno::EIO);
        }
        let read = usize::try_from(read).map_err(|_| linux_errno::EIO)?;
        if read > bytes.len() - copied {
            return Err(linux_errno::EIO);
        }
        copied += read;
    }
    Ok(())
}

pub(crate) fn mark_range_unmapped(memory: &mut impl CurrentMmMemory, address: u64, len: usize) {
    // `no_write` describes a live read-only VMA. It must not survive unmap:
    // fault delivery uses this metadata to distinguish Linux ACCERR from
    // MAPERR, and a reused VA must start without its prior owner's permission.
    memory.set_unmapped(address, len, true);
}

/// Select the legacy dispatcher IPA token for an alias publication.
///
/// HVPatch assigns the real, reusable global frame IPA in its backend after
/// the guest VA is already fixed. Consuming the old process-tree-global,
/// monotonic alias cursor in that case would leave a dead allocator as a
/// 32,768-publication lifetime limit. The legacy cursor is still needed when
/// the offset selects a fresh guest VA.
pub(crate) fn alloc_alias_ipa_for_publication(
    length: u64,
    guest_va_already_selected: bool,
) -> Option<u64> {
    alloc_alias_ipa_for_publication_with(
        length,
        guest_va_already_selected,
        crate::memory::alloc_alias_ipa,
    )
}

pub(crate) fn alloc_alias_ipa_for_publication_with(
    length: u64,
    guest_va_already_selected: bool,
    allocate: impl FnOnce(u64) -> Option<u64>,
) -> Option<u64> {
    if guest_va_already_selected {
        // A deliberately non-authoritative, aligned sentinel. HVPatch replaces
        // it with its GlobalFrameStage2Lease before calling hv_vm_map.
        Some(crate::memory::LINUX_ALIAS_IPA_BASE)
    } else {
        allocate(length)
    }
}

impl<'a> MemView<'a> {
    pub(in crate::dispatch::mem) fn recover_private_repoint_failure(
        &self,
        candidate: u64,
        failure: carrick_guest_mem::RepointPrivateError,
    ) -> PrivateRepointRecovery {
        match failure {
            carrick_guest_mem::RepointPrivateError::Clean(_) => {
                if self.mem().lock().overlay.free(candidate).is_none() {
                    carrick_fatal!(
                        "dispatch::mem_overlay",
                        "freeing candidate private overlay slot failed"
                    );
                }
                PrivateRepointRecovery::RecoveredCleanly
            }
            carrick_guest_mem::RepointPrivateError::Indeterminate(_) => {
                PrivateRepointRecovery::FailStopRetainingOwners
            }
        }
    }

    pub(crate) fn commit_host_alias_mmap_observed(
        &self,
        authority: &super::DispatchMmAuthority,
        commit: HostAliasMmapCommit,
    ) {
        // The matching install guard keeps HostAliasTransactions non-idle for
        // this complete state+revision publication. Snapshot and fork observers
        // acquire that same exclusion before MemState, so neither can enter the
        // narrow interval between the state unlock and release-ordered revision.
        Self::commit_host_alias_mmap_on(authority, commit);
        authority.mem.bump_revision();
    }

    pub(crate) fn commit_host_alias_mmap(&self, commit: HostAliasMmapCommit) {
        let authority = self.mm_authority();
        Self::commit_host_alias_mmap_on(&authority, commit);
    }

    pub(crate) fn commit_host_alias_mmap_on(
        authority: &super::DispatchMmAuthority,
        commit: HostAliasMmapCommit,
    ) {
        let Some(end) = commit.start.checked_add(commit.len) else {
            carrick_fatal!(
                "dispatch::host_alias",
                "commit_host_alias_mmap_on end address overflow"
            );
        };
        let Some(replacement) =
            crate::vfs::GuestMemoryRange::new(GuestVa(commit.start), GuestVa(end))
        else {
            carrick_fatal!(
                "dispatch::host_alias",
                "commit_host_alias_mmap_on invalid replacement range"
            );
        };
        let (read, write, execute) = prot_to_proc_perms(commit.prot);
        let mut mem = authority.mem.lock();

        // Remove only the replaced range from every classification. This is
        // the same cleanup used by munmap/shmdt; range-aware trimming preserves
        // disjoint sibling changes and both fragments of a partial replacement.
        remove_mapping_metadata_locked(&mut mem, commit.start, commit.len);

        if let Some((start, len)) = commit.bus_fault {
            mem.bus_fault_ranges.push((start, len));
        }
        if commit.resident {
            locked_ranges_insert(&mut mem.resident_ranges, replacement);
        }
        if let Some(locked) = commit.locked {
            locked_ranges_insert(&mut mem.resident_ranges, locked);
            locked_ranges_insert(&mut mem.locked_ranges, locked);
        }
        if commit.write_sealed_shared {
            locked_ranges_insert(&mut mem.write_sealed_shared_maps, replacement);
        }
        if commit.read_only_shared_file {
            locked_ranges_insert(&mut mem.read_only_shared_file_maps, replacement);
        }
        if commit.secretmem {
            locked_ranges_insert(&mut mem.secretmem_maps, replacement);
        }
        if let Some(description) = commit.writable_memfd {
            mem.writable_memfd_maps.push((replacement, description));
        }
        if let Some(shared_alias) = commit.shared_file_alias {
            mem.shared_file_alias_maps.push(SharedFileAliasEntry {
                range: replacement,
                description: shared_alias.description,
                extent_base: shared_alias.extent_base,
                row_file_offset: shared_alias.row_file_offset,
            });
        }
        if let Some(source) = commit.private_file {
            mem.private_file_maps.push(source);
        }
        if let Some(file_page_offset) = commit.file_page_offset
            && !commit.path.is_empty()
        {
            mem.core_file_mappings.push(crate::core_dump::FileMapping {
                start: commit.start,
                end,
                file_page_offset,
                path: commit.path.clone(),
            });
            mem.core_file_mappings
                .sort_by_key(|mapping| (mapping.start, mapping.end));
        }
        locked_ranges_insert(&mut mem.host_alias_backed_ranges, replacement);
        locked_ranges_insert(&mut mem.alias_vma_ranges, replacement);
        let entry = ProcMapsEntry {
            start: commit.start,
            end,
            read,
            write,
            execute,
            sharing: commit.sharing,
            path: commit.path,
        };
        let semantic = if let Some(semantic_vmas) = commit.semantic_vmas {
            MremapForkSemantics::capture(&semantic_vmas, commit.start, commit.len)
                .unwrap_or_else(|| {
                    carrick_fatal!(
                        "dispatch::host_alias",
                        "commit_host_alias_mmap_on semantic capture failed"
                    )
                })
                .vmas
        } else {
            let mut semantic = semantic_vmas_from_boot_regions(
                std::slice::from_ref(&entry),
                &mem.core_file_mappings,
                mem.layout,
                mem.brk_current,
            );
            for vma in semantic.iter_mut() {
                vma.droppable = commit.droppable;
            }
            semantic.into_vec()
        };
        mem.semantic_vmas.insert_many_replacing(semantic);
        let idx = mem
            .dynamic_maps
            .partition_point(|map| map.start < commit.start);
        mem.dynamic_maps.insert(idx, entry);
    }

    /// Snapshot one MAP_PRIVATE file payload into anonymous materialization
    /// bytes. The destination starts zeroed, so EOF supplies the Linux mapping's
    /// zero tail. Every fallible file/device operation completes before a fixed
    /// replacement can touch the prior VMA.
    pub(in crate::dispatch::mem) fn snapshot_private_mmap_file(
        &self,
        fd: Fd,
        offset: u64,
        length: usize,
    ) -> Result<PrivateMmapSnapshot, LinuxErrno> {
        let Some(open_file) = self.open_file(fd.0) else {
            return Err(LINUX_EBADF);
        };
        self.snapshot_private_mmap_description(&open_file.description, offset, length)
    }

    fn snapshot_private_mmap_description(
        &self,
        description: &crate::kernel::FileDescription,
        offset: u64,
        length: usize,
    ) -> Result<PrivateMmapSnapshot, LinuxErrno> {
        let mut bytes = vec![0; length];
        let length_u64 = u64::try_from(length).map_err(|_| linux_errno::EOVERFLOW)?;
        let page_size = self.linux_page_size();
        let Some(open) = description.read() else {
            return Err(LINUX_EBADF);
        };
        let offset_usize = usize::try_from(offset).map_err(|_| linux_errno::EOVERFLOW)?;
        let bus_fault_offset = match &*open {
            OpenDescription::File { contents, .. } => {
                contents.read_at(offset, &mut bytes)?;
                let file_len = contents.len()?;
                shared_file_bus_offset(file_len, offset, length_u64, page_size)
            }
            OpenDescription::SyntheticFile { contents, .. } => {
                if offset_usize < contents.len() {
                    let available = &contents[offset_usize..];
                    let copy_len = available.len().min(length);
                    bytes[..copy_len].copy_from_slice(&available[..copy_len]);
                }
                shared_file_bus_offset(contents.len() as u64, offset, length_u64, page_size)
            }
            OpenDescription::InMemoryFile { contents, .. } => {
                let data = contents.read();
                let read_bytes = data.read_range(offset_usize, length);
                bytes[..read_bytes.len()].copy_from_slice(&read_bytes);
                shared_file_bus_offset(data.len() as u64, offset, length_u64, page_size)
            }
            OpenDescription::HostFile { host_fd, .. } => {
                let file_len = host_fd_file_len(host_fd.raw()).ok_or(linux_errno::EIO)?;
                snapshot_private_host_file(host_fd.raw(), offset, &mut bytes)?;
                shared_file_bus_offset(file_len, offset, length_u64, page_size)
            }
            OpenDescription::HostPipe { host_fd, .. } => {
                let mut st: libc::stat = unsafe { core::mem::zeroed() };
                let is_chardev = unsafe { libc::fstat(host_fd.raw(), &mut st) } == 0
                    && (st.st_mode as u32 & libc::S_IFMT as u32) == libc::S_IFCHR as u32;
                if !is_chardev {
                    return Err(linux_errno::ENODEV);
                }
                None
            }
            OpenDescription::SyntheticDevice { kind, .. } => {
                if *kind == crate::vfs::SyntheticDeviceKind::Zero {
                    None
                } else {
                    return Err(linux_errno::ENODEV);
                }
            }
            OpenDescription::Packet { socket, .. } => {
                let init = socket.initial_ring_bytes().ok_or(linux_errno::EINVAL)?;
                if offset_usize < init.len() {
                    let available = &init[offset_usize..];
                    let copy_len = available.len().min(length);
                    bytes[..copy_len].copy_from_slice(&available[..copy_len]);
                }
                None
            }
            _ => return Err(LINUX_EBADF),
        };
        Ok(PrivateMmapSnapshot {
            bytes,
            bus_fault_offset,
        })
    }

    /// Restore mapped file identity, including after fd close or pathname
    /// replacement. A direct view returns mutable pages to clean-page tracking;
    /// byte-backed engines use the existing snapshot lowering.
    pub(crate) fn discard_private_file_segment(
        &self,
        memory: &mut impl CurrentMmMemory,
        segment: &MadviseCoveredSegment,
    ) -> Result<(), LinuxErrno> {
        let mut sources: Vec<_> = self
            .mem()
            .lock()
            .private_file_maps
            .iter()
            .filter_map(|source| source.clip(segment.start, segment.end))
            .collect();
        sources.sort_by_key(|source| source.start);
        let mut cursor = segment.start;
        for source in &sources {
            if source.start != cursor {
                return Err(LINUX_ENOMEM);
            }
            cursor = source.end;
        }
        if cursor != segment.end {
            return Err(LINUX_ENOMEM);
        }
        for source in sources {
            let len = usize::try_from(source.end - source.start).map_err(|_| LINUX_ENOMEM)?;
            let description = match &source.backing {
                PrivateFileBacking::Description(description) => description,
                PrivateFileBacking::LoadedImage {
                    initialized_offset,
                    bytes,
                } => {
                    let mut restored = vec![0; len];
                    let initialized_end = initialized_offset
                        .checked_add(bytes.len() as u64)
                        .ok_or(LINUX_ENOMEM)?;
                    let start = source.offset.max(*initialized_offset);
                    let end = source
                        .offset
                        .checked_add(len as u64)
                        .ok_or(LINUX_ENOMEM)?
                        .min(initialized_end);
                    if start < end {
                        let dst =
                            usize::try_from(start - source.offset).map_err(|_| LINUX_ENOMEM)?;
                        let src = usize::try_from(start - initialized_offset)
                            .map_err(|_| LINUX_ENOMEM)?;
                        let count = usize::try_from(end - start).map_err(|_| LINUX_ENOMEM)?;
                        restored[dst..dst + count].copy_from_slice(&bytes[src..src + count]);
                    }
                    memory
                        .write_bytes_unchecked(source.start, &restored)
                        .map_err(|_| LINUX_ENOMEM)?;
                    continue;
                }
            };
            let snapshot = self.snapshot_private_mmap_description(
                description.description(),
                source.offset,
                len,
            )?;
            let valid_len = usize::try_from(snapshot.bus_fault_offset.unwrap_or(len as u64))
                .map_err(|_| LINUX_ENOMEM)?;
            if valid_len != 0 {
                let direct = {
                    let open = description.description().read().ok_or(LINUX_EBADF)?;
                    if let Some(fd) = open.shared_alias_host_fd() {
                        let provenance = match &*open {
                            OpenDescription::HostFile { host_fd, .. } => {
                                host_fd.private_file_source()
                            }
                            _ => carrick_guest_mem::PrivateFileSource::Mutable,
                        };
                        // SAFETY: the description guard retains the owning fd
                        // throughout this synchronous mapping operation.
                        let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
                        memory
                            .map_private_file_backed(
                                source.start,
                                valid_len,
                                fd,
                                source.offset,
                                provenance,
                            )
                            .map_err(|error| {
                                carrick_observability::probes::mmap_lowering_error(
                                    source.start,
                                    valid_len as u64,
                                    source.offset,
                                    &error,
                                );
                                LINUX_ENOMEM
                            })?
                    } else {
                        false
                    }
                };
                if !direct {
                    memory
                        .write_bytes_unchecked(source.start, &snapshot.bytes[..valid_len])
                        .map_err(|_| LINUX_ENOMEM)?;
                }
                memory
                    .protect_range(source.start, valid_len, segment.prot.bits())
                    .map_err(|_| LINUX_ENOMEM)?;
                memory.set_mapping_protection(
                    source.start,
                    valid_len,
                    segment.prot.is_empty(),
                    !segment.prot.contains(LinuxProtFlags::WRITE),
                );
                if let Some(protections) = memory.protections() {
                    protections.set_bus_fault(source.start, valid_len, false);
                }
            }
            if valid_len < len {
                let bus_start = source.start + valid_len as u64;
                memory
                    .protect_range(bus_start, len - valid_len, 0)
                    .map_err(|_| LINUX_ENOMEM)?;
                if let Some(protections) = memory.protections() {
                    protections.set_bus_fault(bus_start, len - valid_len, true);
                }
            }
            let authority = self.mem();
            let mut mem = authority.lock();
            trim_ranges_for_range(&mut mem.bus_fault_ranges, source.start, len as u64);
            if valid_len < len {
                mem.bus_fault_ranges
                    .push((source.start + valid_len as u64, (len - valid_len) as u64));
            }
        }
        Ok(())
    }

    pub(crate) fn record_write_sealed_shared_map(&self, start: u64, len: u64) {
        if let Some(range) =
            crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start.saturating_add(len)))
        {
            locked_ranges_insert(&mut self.mem().lock().write_sealed_shared_maps, range);
        }
    }

    pub(crate) fn record_read_only_shared_file_map(&self, start: u64, len: u64) {
        if let Some(range) =
            crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start.saturating_add(len)))
        {
            locked_ranges_insert(&mut self.mem().lock().read_only_shared_file_maps, range);
        }
    }

    pub(crate) fn shared_file_alias_entry(
        &self,
        start: u64,
        len: u64,
    ) -> Option<SharedFileAliasEntry> {
        let end = start.checked_add(len)?;
        self.mem()
            .lock()
            .shared_file_alias_maps
            .iter()
            .find(|entry| entry.range.start().raw() <= start && entry.range.end().raw() >= end)
            .cloned()
    }

    /// The open-file description behind the live `MAP_SHARED` alias covering
    /// `[start, start+len)`, if that whole range is one recorded alias. Callers
    /// use it to re-derive a fact about the FILE (notably its length) after the
    /// guest has closed its own descriptor.
    pub(in crate::dispatch::mem) fn shared_file_alias_description(
        &self,
        start: u64,
        len: u64,
    ) -> Option<Arc<crate::kernel::FileDescription>> {
        self.shared_file_alias_entry(start, len)
            .map(|entry| entry.description)
    }

    pub(crate) fn range_is_read_only_shared_file(&self, start: u64, len: u64) -> bool {
        self.mem()
            .lock()
            .read_only_shared_file_maps
            .iter()
            .any(|r| ranges_overlap(start, len, r.start().raw(), r.end().raw()))
    }

    pub(crate) fn range_is_write_sealed_shared(&self, start: u64, len: u64) -> bool {
        self.mem()
            .lock()
            .write_sealed_shared_maps
            .iter()
            .any(|r| ranges_overlap(start, len, r.start().raw(), r.end().raw()))
    }

    pub(in crate::dispatch::mem) fn record_secretmem_map(&self, start: u64, len: u64) {
        if let Some(range) =
            crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start.saturating_add(len)))
        {
            self.mem().lock().secretmem_maps.push(range);
        }
    }

    /// True iff `[start, start+len)` touches a live secretmem mapping — used
    /// by the `/proc/<pid>/mem` read path to fail with EIO (the kernel cannot
    /// GUP secret pages; memfdsecret probe `procmem_hidden`).
    pub(in crate::dispatch) fn range_touches_secretmem(&self, start: u64, len: u64) -> bool {
        self.mem()
            .lock()
            .secretmem_maps
            .iter()
            .any(|r| ranges_overlap(start, len, r.start().raw(), r.end().raw()))
    }

    #[cfg(test)]
    pub(in crate::dispatch::mem) fn remove_secretmem_map(&self, start: u64, len: u64) {
        if let Some(range) =
            crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start.saturating_add(len)))
        {
            locked_ranges_remove(&mut self.mem().lock().secretmem_maps, range);
        }
    }

    pub(crate) fn record_writable_memfd_map(
        &self,
        start: u64,
        len: u64,
        description: Arc<crate::kernel::FileDescription>,
    ) {
        if let Some(range) =
            crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start.saturating_add(len)))
        {
            self.mem()
                .lock()
                .writable_memfd_maps
                .push((range, description));
        }
    }

    /// Remove every dispatcher-owned mmap classification for a committed range.
    /// Call only after the backend unmap has succeeded: metadata is the commit
    /// record, not a prediction of a fallible page-table/host operation.
    ///
    /// `pub(super)` is intentional: SysV `shmdt` owns an mmap-classified host
    /// alias too and must retire the same VMA/residency/lock/fault/bus/seal/memfd
    /// state before it removes the attachment and decrements `nattch`.
    pub(crate) fn remove_mapping_metadata(&self, start: u64, len: u64) {
        remove_mapping_metadata_locked(&mut self.mem().lock(), start, len);
        self.captured_mm()
            .replace_io_uring_mappings(start, len, None);
    }

    /// True iff a live MAP_SHARED, PROT_WRITE mapping backed by `description`
    /// exists — used to reject `F_ADD_SEALS` F_SEAL_WRITE with EBUSY.
    pub(in crate::dispatch) fn memfd_has_writable_shared_map(
        &self,
        description: &Arc<crate::kernel::FileDescription>,
    ) -> bool {
        self.mem()
            .lock()
            .writable_memfd_maps
            .iter()
            .any(|(_, desc)| std::sync::Arc::ptr_eq(desc, description))
    }

    #[cfg(test)]
    pub(crate) fn record_dynamic_mapping(
        &self,
        start: u64,
        len: u64,
        prot: LinuxProtFlags,
        sharing: ProcMapSharing,
        path: String,
    ) {
        self.record_dynamic_mapping_with_file_offset(
            start,
            len,
            prot,
            sharing,
            path,
            DynamicMappingSemantics {
                file_page_offset: None,
                droppable: false,
                semantic_vmas: None,
            },
        );
    }

    pub(in crate::dispatch::mem) fn record_dynamic_mapping_with_file_offset(
        &self,
        start: u64,
        len: u64,
        prot: LinuxProtFlags,
        sharing: ProcMapSharing,
        path: String,
        semantics: DynamicMappingSemantics,
    ) {
        let DynamicMappingSemantics {
            file_page_offset,
            droppable,
            semantic_vmas,
        } = semantics;
        let Some(end) = start.checked_add(len) else {
            return;
        };
        let (read, write, execute) = prot_to_proc_perms(prot);
        let mem_authority_4 = self.mem();
        let mut mem = mem_authority_4.lock();
        trim_core_file_mappings_for_range(&mut mem.core_file_mappings, start, len);
        if let Some(file_page_offset) = file_page_offset
            && !path.is_empty()
        {
            mem.core_file_mappings.push(crate::core_dump::FileMapping {
                start,
                end,
                file_page_offset,
                path: path.clone(),
            });
            mem.core_file_mappings
                .sort_by_key(|mapping| (mapping.start, mapping.end));
        }
        mem.remap_snapshots.remove(&start);
        let entry = ProcMapsEntry {
            start,
            end,
            read,
            write,
            execute,
            sharing,
            path,
        };
        let semantic = semantic_vmas.map(VmaMap::from_vec).unwrap_or_else(|| {
            let mut semantic = semantic_vmas_from_boot_regions(
                std::slice::from_ref(&entry),
                &mem.core_file_mappings,
                mem.layout,
                mem.brk_current,
            );
            for vma in semantic.iter_mut() {
                vma.droppable = droppable;
            }
            semantic
        });
        if let Some(end) = start.checked_add(len) {
            mem.semantic_vmas.remove_range(start, end);
        }
        mem.semantic_vmas.insert_many_replacing(semantic);

        if !dynamic_mapping_overlaps_sorted(&mem.dynamic_maps, start, len) {
            let idx = mem.dynamic_maps.partition_point(|map| map.start < start);
            mem.dynamic_maps.insert(idx, entry);
            return;
        }

        trim_dynamic_maps_for_range(&mut mem.dynamic_maps, start, len);
        let idx = mem.dynamic_maps.partition_point(|map| map.start < start);
        mem.dynamic_maps.insert(idx, entry);
    }

    pub(crate) fn record_remapped_dynamic_mapping(
        &self,
        start: u64,
        len: u64,
        source: &MremapMappingMetadata,
    ) {
        let semantic_vmas = source
            .fork_semantics
            .project(start, len)
            .unwrap_or_else(|| {
                carrick_fatal!(
                    "dispatch::mremap",
                    "record_remapped_dynamic_mapping projection failed"
                )
            });
        self.record_dynamic_mapping_with_file_offset(
            start,
            len,
            source.prot,
            source.sharing,
            source.path.clone(),
            DynamicMappingSemantics {
                file_page_offset: source.file_page_offset,
                droppable: source.droppable,
                semantic_vmas: Some(semantic_vmas),
            },
        );
        if let Some(source) = &source.private_file
            && let Some(end) = start.checked_add(len)
        {
            let mut entry = source.clone();
            entry.start = start;
            entry.end = end;
            self.mem().lock().private_file_maps.push(entry);
        }
    }

    /// Whether one committed host-alias extent fully backs this guest-VA range.
    /// VMA presence alone is insufficient: lazy anonymous `PROT_NONE` reserves
    /// the address now and installs physical backing only on first commit.
    pub(in crate::dispatch::mem) fn range_has_host_alias_backing(
        &self,
        start: u64,
        len: u64,
    ) -> bool {
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        self.mem()
            .lock()
            .host_alias_backed_ranges
            .iter()
            .any(|range| range.start().raw() <= start && range.end().raw() >= end)
    }

    pub(crate) fn range_is_alias_vma(&self, start: u64, len: u64) -> bool {
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        self.mem()
            .lock()
            .alias_vma_ranges
            .iter()
            .any(|range| range.start().raw() <= start && range.end().raw() >= end)
    }

    pub(crate) fn record_alias_vma(&self, start: u64, len: u64) {
        let Some(end) = start.checked_add(len) else {
            carrick_fatal!(
                "dispatch::host_alias",
                "record_alias_vma end address overflow"
            );
        };
        let Some(range) = crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(end)) else {
            carrick_fatal!(
                "dispatch::host_alias",
                "record_alias_vma invalid guest memory range"
            );
        };
        locked_ranges_insert(&mut self.mem().lock().alias_vma_ranges, range);
    }

    /// Snapshot one `SharedFile` fragment while its old guest translation is
    /// still live. The snapshot is committed only after backend mutation
    /// succeeds, so a clean failure cannot produce duplicate writeback.
    pub(crate) fn snapshot_shared_writeback<M: CurrentMmMemory>(
        &self,
        memory: &mut M,
        alloc: &crate::shared_aperture::SharedAlloc,
    ) -> Option<Vec<u8>> {
        alloc.backing.shared_file_parts()?;
        let len = usize::try_from(alloc.live_len).ok()?;
        if len == 0 {
            return None;
        }
        memory.read_bytes(alloc.guest_addr, len).ok()
    }

    /// Commit bytes captured by [`Self::snapshot_shared_writeback`]. Descriptor
    /// ownership lives in the backing's shared RAII owner: carving clones that
    /// owner into survivors, so fragment retirement never double-closes.
    pub(crate) fn writeback_shared_snapshot(
        &self,
        alloc: &crate::shared_aperture::SharedAlloc,
        bytes: &[u8],
    ) {
        let Some((host_fd, offset)) = alloc.backing.shared_file_parts() else {
            return;
        };
        let mut written = 0usize;
        while written < bytes.len() {
            let Ok(written_offset) = u64::try_from(written) else {
                break;
            };
            let Some(file_offset) = offset
                .checked_add(written_offset)
                .and_then(|value| libc::off_t::try_from(value).ok())
            else {
                break;
            };
            let result = unsafe {
                libc::pwrite(
                    host_fd,
                    bytes[written..].as_ptr().cast(),
                    bytes.len() - written,
                    file_offset,
                )
            };
            if result > 0 {
                let Ok(count) = usize::try_from(result) else {
                    break;
                };
                written = written.saturating_add(count);
                continue;
            }
            if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
    }

    pub(crate) fn writeback_shared<M: CurrentMmMemory>(
        &self,
        memory: &mut M,
        alloc: &crate::shared_aperture::SharedAlloc,
    ) {
        if let Some(bytes) = self.snapshot_shared_writeback(memory, alloc) {
            self.writeback_shared_snapshot(alloc, &bytes);
        }
    }
}

#[cfg(test)]
mod tests;
