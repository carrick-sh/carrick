//! Memory management: `brk`, `mmap`/`munmap`/`mremap`, `mprotect`, `madvise`,
//! and the `/proc/self/maps` & `auxv` views.
//!
//! # Theory of operation
//!
//! Guest memory is HVF stage-2-mapped guest RAM, and the central constraint is:
//! mutating stage-2 mappings AFTER a sibling vCPU exists is unsafe on arm64 HVF
//! (there is no EL0-reachable stage-2 TLB flush — the coherence bug documented
//! in the project history). So this allocator is designed to avoid post-boot
//! `hv_vm_map` almost entirely. It does its work by carving guest virtual
//! address space out of regions that were already mapped at boot, and by
//! re-pointing stage-1 page-table leaves rather than touching stage-2.
//!
//! ## Three arenas ([`MemState`])
//!
//! 1. **The anonymous mmap bump arena** (`mmap_next`). A plain bump cursor over
//!    lazily-zeroed guest RAM. `MAP_PRIVATE|MAP_ANONYMOUS` allocations bump it;
//!    `free_regions` reclaims `munmap`'d holes (coalesced) so a churning guest
//!    does not exhaust the arena. The **zero-fill invariant** is the sharp edge:
//!    the bump path assumes `[mmap_next, …)` is pristine and SKIPS zero-fill,
//!    while reused free regions get zeroed. That breaks when `munmap` lowers
//!    `mmap_next` back over pages the guest already dirtied — a later bump
//!    allocation would hand back STALE bytes instead of the zeroed anon memory
//!    Linux guarantees. `mmap_dirty_high` is the fix: a MONOTONIC high-water
//!    that `munmap` never lowers, so the mmap handler can zero exactly the
//!    re-handed-out (below-high-water) ranges and leave the genuinely-fresh
//!    tail lazily zero. (This is the CPython `test_subprocess` SEGV root cause —
//!    see the `mmap_dirty_high` field doc and the project memory.)
//! 2. **The shared aperture** (`shared`). A single region `hv_vm_map`'d ONCE at
//!    boot; `MAP_SHARED` mmaps (including SysV `shmat`) carve sub-ranges out of
//!    it, so no stage-2 mutation happens at mmap time.
//! 3. **The private overlay aperture** (`overlay`). A `MAP_FIXED|MAP_PRIVATE`
//!    that lands on a shared-aperture VA carves a slot here and re-points the
//!    VA's stage-1 leaf to it (stores stay private), again with no post-vCPU
//!    `hv_vm_map`. Per-process — fork snapshots it.
//!
//! ## `brk` and the `/proc` views
//!
//! `brk` advances/retreats the program break (`brk_current`) within the heap
//! region. Shrinking scrubs the page-aligned released backing so a later growth
//! re-exposes zero-filled memory, matching Linux's anonymous-memory contract.
//! `/proc/self/maps` is rendered from the boot-captured `AddressSpace`
//! snapshot (`address_space_regions`) with the heap end tracking `brk_current`
//! and the mmap arena end tracking `mmap_next`; `/proc/self/auxv` echoes the
//! exact serialized ELF auxiliary vector written to the guest stack at exec
//! (`linux_auxv_image`). `mprotect` adjusts stage-1 leaf permissions;
//! `madvise`/`msync`/`mlock`/`mincore`/`membarrier` are mostly advisory or
//! best-effort given the boot-mapped model.
//!
//! Methods are `impl` blocks on [`SyscallDispatcher`]; see [`super`] for the
//! dispatcher struct and the normalized dispatch table.
use super::*;

syscall_table! {
    /// Per-module syscall routing for the `mem` subsystem (Task A1).
    ///
    /// Owns the `number → handler` arms for every syscall this module
    /// implements. `resolve_handler` in `dispatch/mod.rs` chains this with
    /// the other modules' tables. Add a `mem` syscall by adding an arm
    /// HERE — no shared routing table to edit.
    pub(crate) fn dispatch_mem;
    214 => brk,
    215 => munmap,
    216 => mremap,
    213 => readahead,
    222 => mmap,
    223 => fadvise64,
    226 => mprotect,
    227 => msync,
    228 => mlock,
    229 => munlock,
    230 => mlockall,
    231 => munlockall,
    232 => mincore,
    233 => madvise,
    234 => remap_file_pages,
    284 => mlock2,
    425 => io_uring_setup,
    426 => io_uring_enter,
    427 => io_uring_register,
    283 => sys_membarrier,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivateRepointRecovery {
    RecoveredCleanly,
    FailStopRetainingOwners,
}

/// Dispatcher-owned, revisioned wrapper around the sole production memory/VMA
/// authority. Ordinary syscall and `/proc` access keeps using this same
/// `MemState` mutex; the K1 observer only derives owned occupancy rows from it.
pub(crate) struct MemAuthority {
    state: parking_lot::Mutex<MemState>,
    revision: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl std::fmt::Debug for MemAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MemAuthority")
            .field("revision", &self.vma_revision())
            .finish_non_exhaustive()
    }
}

impl MemAuthority {
    pub(super) fn new(state: MemState) -> Self {
        Self::with_revision(state, crate::kernel::VmaRevision::INITIAL)
    }

    fn with_revision(state: MemState, revision: crate::kernel::VmaRevision) -> Self {
        Self {
            state: parking_lot::Mutex::new(state),
            revision: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(revision.raw())),
        }
    }

    pub(super) fn lock(&self) -> parking_lot::MutexGuard<'_, MemState> {
        self.state.lock()
    }

    pub(super) fn revision_publisher(&self) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
        std::sync::Arc::clone(&self.revision)
    }

    pub(super) fn fork_private(&self) -> std::sync::Arc<Self> {
        let state = self.state.lock();
        let revision = self.vma_revision();
        let forked = state.clone();
        drop(state);
        std::sync::Arc::new(Self::with_revision(forked, revision))
    }

    pub(super) fn vma_revision(&self) -> crate::kernel::VmaRevision {
        crate::kernel::VmaRevision::from_authority_raw(
            self.revision.load(std::sync::atomic::Ordering::Acquire),
        )
    }

    pub(super) fn snapshot_until(
        &self,
        deadline: std::time::Instant,
    ) -> Result<crate::kernel::OwnedVmaSnapshot, crate::kernel::SnapshotError> {
        let Some(state) = self.state.try_lock_until(deadline) else {
            return Err(if std::time::Instant::now() >= deadline {
                crate::kernel::SnapshotError::TimedOut
            } else {
                crate::kernel::SnapshotError::Busy
            });
        };
        let revision = self.vma_revision();
        let vmas = project_vma_summaries(&state);
        Ok(crate::kernel::OwnedVmaSnapshot { revision, vmas })
    }

    fn bump_revision(&self) {
        if self
            .revision
            .fetch_add(1, std::sync::atomic::Ordering::Release)
            == u64::MAX
        {
            std::process::abort();
        }
    }
}

/// Owned memory-subsystem state. Split out of `SyscallDispatcher`.
#[derive(Clone)]
pub(super) struct MemState {
    pub layout: MemoryLayout,
    /// Current program break (`brk`/`sbrk`).
    pub brk_current: u64,
    /// Bump cursor for the anonymous mmap arena.
    pub mmap_next: u64,
    /// MONOTONIC high-water of the arena: the highest address ever handed out by
    /// the bump allocator, which `munmap` NEVER lowers (unlike `mmap_next`).
    ///
    /// The bump path assumes `[mmap_next, ...)` is pristine (lazily zero-filled
    /// guest RAM), so it skips the zero-fill that reused `free_regions` get. That
    /// invariant breaks when `munmap` frees the TOP region and LOWERS `mmap_next`
    /// back over pages the guest already dirtied: a later bump allocation at the
    /// lowered cursor would return that STALE data instead of the zeroed anon
    /// memory Linux guarantees. Tracking the true dirty high-water lets the mmap
    /// handler zero exactly the re-handed-out (below-high-water) ranges and keep
    /// the genuinely-fresh tail lazily zero. (CPython test_subprocess SEGV:
    /// pymalloc got 'x'-filled stderr-buffer pages back from a post-munmap mmap.)
    pub mmap_dirty_high: u64,
    /// Sub-allocator for the boot-mapped shared aperture. Guest `MAP_SHARED`
    /// mmaps carve sub-ranges here; the aperture itself is `hv_vm_map`'d once
    /// at boot, so no stage-2 mutation happens at mmap time.
    pub shared: crate::shared_aperture::SharedAperture,
    /// Sub-allocator for the boot-mapped PRIVATE overlay aperture. A guest
    /// `MAP_FIXED|MAP_PRIVATE` that lands on a shared-aperture VA carves a slot
    /// here and repoints the VA's stage-1 leaf to it (so stores stay private),
    /// without any post-vCPU `hv_vm_map`. Per-process (fork snapshots it).
    pub overlay: crate::shared_aperture::SharedAperture,
    /// Freed in-arena anonymous/private ranges available for reuse, kept sorted
    /// by start and coalesced. Reclaiming `munmap`'d space so a churning guest
    /// doesn't exhaust the bump arena. NOT used for MAP_FIXED or shared-file
    /// maps (those have their own lifecycles).
    pub free_regions: Vec<(u64, u64)>,
    /// Snapshot of the guest's `AddressSpace` regions, captured at boot
    /// via [`SyscallDispatcher::set_address_space_regions`]. When present,
    /// `/proc/self/maps` is rendered from this list (with the heap end
    /// tracking `brk_current` and the mmap arena end tracking `mmap_next`)
    /// instead of the hard-coded four-line summary.
    pub address_space_regions: Option<Vec<ProcMapsEntry>>,
    /// Linux-visible dynamic mappings created after exec. The boot address-space
    /// snapshot contains the backing arenas, but `/proc/self/maps` must show the
    /// VMAs Linux would have installed inside those arenas with their actual
    /// permissions and private/shared bit.
    pub dynamic_maps: Vec<ProcMapsEntry>,
    /// Original bytes for mappings that have used remap_file_pages(2). Carrick's
    /// low fixed MAP_SHARED path is byte-backed guest memory rather than a live
    /// nonlinear VM object, so remap_file_pages copies windows from this stable
    /// image instead of from already-rearranged bytes.
    pub remap_snapshots: std::collections::HashMap<u64, Vec<u8>>,
    /// Ranges inside mapped files where Linux delivers SIGBUS on access: pages
    /// wholly beyond the backing file's EOF. Live MAP_SHARED aliases inherit
    /// later vnode truncation from the host; materialized MAP_PRIVATE mappings
    /// publish the exact page-rounded tail observed at map time.
    pub bus_fault_ranges: Vec<(u64, u64)>,
    /// Page-rounded guest virtual ranges currently counted as mlocked. Stored as
    /// typed guest-VA ranges so `/proc` accounting cannot mix them with host or
    /// physical addresses.
    pub locked_ranges: Vec<crate::vfs::GuestMemoryRange>,
    /// Guest-page resident ranges for Carrick-managed mappings where host
    /// `mincore` is too coarse (notably 4 KiB Linux pages on a 16 KiB Darwin
    /// host page).
    pub resident_ranges: Vec<crate::vfs::GuestMemoryRange>,
    /// Ranges whose `mincore` answer is derived from `resident_ranges`.
    pub resident_tracked_ranges: Vec<crate::vfs::GuestMemoryRange>,
    /// Shared-anon ranges that should fault once per guest page to become
    /// resident, with the protection to restore after that first touch.
    resident_fault_ranges: Vec<ResidentFaultRange>,
    /// MAP_GROWSDOWN VMAs that may expand downward on a stack fault:
    /// `(low_bound, current_start, end)`.
    pub growdown_ranges: Vec<(u64, u64, u64)>,
    /// VA ranges of MAP_SHARED mappings backed by a memfd sealed F_SEAL_WRITE
    /// (or F_SEAL_FUTURE_WRITE): `mprotect(PROT_WRITE)` on them must fail EPERM,
    /// since the sealed backing can never gain a shared writable view
    /// (memfd_create01 check_mfd_non_writeable's mmap+mprotect case).
    write_sealed_shared_maps: Vec<crate::vfs::GuestMemoryRange>,
    /// Active MAP_SHARED, PROT_WRITE mappings of a (sealable) memfd, paired with
    /// the backing open-file description. While one is live, `F_ADD_SEALS`
    /// F_SEAL_WRITE on that memfd must fail EBUSY (memfd_create01 test_share_mmap).
    writable_memfd_maps: Vec<(crate::vfs::GuestMemoryRange, OpenDescriptionRef)>,
    /// The exact serialized ELF auxiliary vector written to the guest stack at
    /// exec, captured from the `AddressSpace` via
    /// [`SyscallDispatcher::set_auxv_image`]. Mirrored to `/proc/self/auxv`.
    /// Empty until an image with an initial stack is loaded.
    pub linux_auxv_image: Vec<u8>,
    // NOTE: the alias-IPA cursor used to live here, but a per-process field is
    // COPIED on fork, so sibling guest processes reused the same IPAs into the
    // shared `hv_vm` (whose stage-2 TLB can't be flushed) and read each other's
    // stale pages — the go-build crash. It now lives in a fork-SHARED counter:
    // `crate::memory::alloc_alias_ipa`.
}

// Moved to `carrick_mem::memory::MemoryLayout` as part of the staged
// native-backend extraction (docs/superpowers/specs/
// 2026-07-17-native-backend-portability-seams-design.md) so `carrick-dsr` can
// share it; re-exported so every `crate::dispatch::MemoryLayout` call site is
// unchanged.
pub(crate) use carrick_mem::memory::MemoryLayout;

impl MemState {
    pub(super) fn new() -> Self {
        Self::new_with_layout(MemoryLayout::hvf_default())
    }

    pub(super) fn new_with_layout(layout: MemoryLayout) -> Self {
        Self {
            layout,
            brk_current: layout.heap_base,
            mmap_next: layout.mmap_base,
            mmap_dirty_high: layout.mmap_base,
            shared: crate::shared_aperture::SharedAperture::new(),
            overlay: crate::shared_aperture::SharedAperture::with_window(
                crate::memory::LINUX_PRIVATE_OVERLAY_BASE,
                crate::memory::LINUX_PRIVATE_OVERLAY_SIZE,
            ),
            free_regions: Vec::new(),
            address_space_regions: None,
            dynamic_maps: Vec::new(),
            remap_snapshots: std::collections::HashMap::new(),
            bus_fault_ranges: Vec::new(),
            locked_ranges: Vec::new(),
            resident_ranges: Vec::new(),
            resident_tracked_ranges: Vec::new(),
            resident_fault_ranges: Vec::new(),
            growdown_ranges: Vec::new(),
            write_sealed_shared_maps: Vec::new(),
            writable_memfd_maps: Vec::new(),
            linux_auxv_image: Vec::new(),
        }
    }

    pub(super) fn reset_for_execve(&mut self) {
        let layout = self.layout;
        let address_space_regions = self.address_space_regions.take();
        let linux_auxv_image = std::mem::take(&mut self.linux_auxv_image);
        *self = Self::new_with_layout(layout);
        self.address_space_regions = address_space_regions;
        self.linux_auxv_image = linux_auxv_image;
    }
}

#[derive(Clone, Copy)]
struct ResidentFaultRange {
    range: crate::vfs::GuestMemoryRange,
    prot: LinuxProtFlags,
}

/// Insert `[addr, addr+len)` into `regions` (sorted by start), coalescing any
/// adjacent or overlapping ranges. `len` must be > 0.
fn free_regions_insert(regions: &mut Vec<(u64, u64)>, addr: u64, len: u64) {
    let mut new_start = addr;
    let mut new_end = addr.saturating_add(len);
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(regions.len() + 1);
    let mut inserted = false;
    for &(s, l) in regions.iter() {
        let e = s.saturating_add(l);
        if e < new_start || s > new_end {
            // Disjoint from the (growing) merged range. Emit in sorted order.
            if !inserted && s > new_end {
                out.push((new_start, new_end - new_start));
                inserted = true;
            }
            out.push((s, l));
        } else {
            // Overlapping or adjacent — absorb into the merged range.
            new_start = new_start.min(s);
            new_end = new_end.max(e);
        }
    }
    if !inserted {
        out.push((new_start, new_end - new_start));
    }
    out.sort_by_key(|&(s, _)| s);
    *regions = out;
}

fn page_floor(value: u64, page_size: u64) -> u64 {
    value & !(page_size - 1)
}

fn page_ceil(value: u64, page_size: u64) -> Option<u64> {
    value
        .checked_add(page_size - 1)
        .map(|end| page_floor(end, page_size))
}

fn page_rounded_range(
    address: GuestPtr,
    length: u64,
    page_size: u64,
) -> Result<Option<crate::vfs::GuestMemoryRange>, LinuxErrno> {
    if length == 0 {
        return Ok(None);
    }
    let start = GuestVa(page_floor(address.0, page_size));
    let end = address
        .0
        .checked_add(length)
        .and_then(|end| page_ceil(end, page_size))
        .map(GuestVa)
        .ok_or(LINUX_ENOMEM)?;
    crate::vfs::GuestMemoryRange::new(start, end)
        .map(Some)
        .ok_or(LINUX_ENOMEM)
}

fn range_len_usize(range: crate::vfs::GuestMemoryRange) -> Result<usize, LinuxErrno> {
    usize::try_from(range.len()).map_err(|_| LINUX_ENOMEM)
}

fn validate_mlock_range(
    memory: &mut impl GuestMemory,
    range: crate::vfs::GuestMemoryRange,
    populate: bool,
    page_size: u64,
) -> Result<(), LinuxErrno> {
    let len = range_len_usize(range)?;
    if memory.has_complete_mapping_metadata()
        && memory
            .protections()
            .is_some_and(|protections| !protections.range_unmapped(range.start().raw(), len))
    {
        return Ok(());
    }
    if !populate && memory.host_ptr_for_read(range.start().raw(), len).is_some() {
        return Ok(());
    }
    let mut page = range.start().raw();
    while page < range.end().raw() {
        if memory.read_bytes(page, 1).is_err() {
            return Err(LINUX_ENOMEM);
        }
        page = page.checked_add(page_size).ok_or(LINUX_ENOMEM)?;
    }
    Ok(())
}

fn locked_ranges_insert(
    ranges: &mut Vec<crate::vfs::GuestMemoryRange>,
    range: crate::vfs::GuestMemoryRange,
) {
    ranges.push(range);
    ranges.sort_by_key(|range| range.start());
    let mut merged: Vec<crate::vfs::GuestMemoryRange> = Vec::with_capacity(ranges.len());
    for range in ranges.drain(..) {
        if let Some(last) = merged.last_mut()
            && range.start().raw() <= last.end().raw()
        {
            let end = GuestVa(last.end().raw().max(range.end().raw()));
            if let Some(coalesced) = crate::vfs::GuestMemoryRange::new(last.start(), end) {
                *last = coalesced;
            }
            continue;
        }
        merged.push(range);
    }
    *ranges = merged;
}

fn locked_ranges_remove(
    ranges: &mut Vec<crate::vfs::GuestMemoryRange>,
    remove: crate::vfs::GuestMemoryRange,
) {
    let mut out = Vec::with_capacity(ranges.len());
    for range in ranges.drain(..) {
        if remove.end() <= range.start() || remove.start() >= range.end() {
            out.push(range);
            continue;
        }
        if remove.start() > range.start()
            && let Some(left) = crate::vfs::GuestMemoryRange::new(range.start(), remove.start())
        {
            out.push(left);
        }
        if remove.end() < range.end()
            && let Some(right) = crate::vfs::GuestMemoryRange::new(remove.end(), range.end())
        {
            out.push(right);
        }
    }
    *ranges = out;
}

fn locked_ranges_total(ranges: &[crate::vfs::GuestMemoryRange]) -> u64 {
    ranges.iter().map(|range| range.len()).sum()
}

fn ranges_contain_page(ranges: &[crate::vfs::GuestMemoryRange], page: u64) -> bool {
    ranges
        .iter()
        .any(|range| page >= range.start().raw() && page < range.end().raw())
}

fn remove_fault_range(ranges: &mut Vec<ResidentFaultRange>, remove: crate::vfs::GuestMemoryRange) {
    let mut out = Vec::with_capacity(ranges.len());
    for fault in ranges.drain(..) {
        let range = fault.range;
        if remove.end() <= range.start() || remove.start() >= range.end() {
            out.push(fault);
            continue;
        }
        if remove.start() > range.start()
            && let Some(left) = crate::vfs::GuestMemoryRange::new(range.start(), remove.start())
        {
            out.push(ResidentFaultRange {
                range: left,
                prot: fault.prot,
            });
        }
        if remove.end() < range.end()
            && let Some(right) = crate::vfs::GuestMemoryRange::new(remove.end(), range.end())
        {
            out.push(ResidentFaultRange {
                range: right,
                prot: fault.prot,
            });
        }
    }
    *ranges = out;
}

fn fault_range_intersections(
    ranges: &[ResidentFaultRange],
    populate: crate::vfs::GuestMemoryRange,
) -> Vec<ResidentFaultRange> {
    ranges
        .iter()
        .filter_map(|fault| {
            let start = fault.range.start().raw().max(populate.start().raw());
            let end = fault.range.end().raw().min(populate.end().raw());
            crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(end)).map(|range| {
                ResidentFaultRange {
                    range,
                    prot: fault.prot,
                }
            })
        })
        .collect()
}

fn mincore_page_is_mapped(memory: &impl GuestMemory, page: u64) -> bool {
    memory.host_ptr_for_read(page, 1).is_some() || memory.read_bytes(page, 1).is_ok()
}

fn ranges_overlap(a_start: u64, a_len: u64, b_start: u64, b_end: u64) -> bool {
    let Some(a_end) = a_start.checked_add(a_len) else {
        return true;
    };
    a_start < b_end && b_start < a_end
}

fn dynamic_mapping_overlaps_sorted(maps: &[ProcMapsEntry], start: u64, len: u64) -> bool {
    let Some(end) = start.checked_add(len) else {
        return true;
    };
    let idx = maps.partition_point(|map| map.end <= start);
    maps.get(idx).is_some_and(|map| map.start < end)
}

fn guest_vma_overlaps_locked(mem: &MemState, start: u64, len: u64) -> bool {
    let Some(end) = start.checked_add(len) else {
        return true;
    };
    dynamic_mapping_overlaps_sorted(&mem.dynamic_maps, start, len)
        || mem
            .growdown_ranges
            .iter()
            .any(|(_, current, vma_end)| *current < end && start < *vma_end)
        || (mem.brk_current > mem.layout.heap_base
            && start < mem.brk_current
            && mem.layout.heap_base < end)
        || mem.address_space_regions.iter().flatten().any(|map| {
            map.start < end
                && start < map.end
                && !boot_region_is_hidden_reservation(map, mem.layout)
        })
}

fn boot_region_is_hidden_mmap_backing(map: &ProcMapsEntry, layout: MemoryLayout) -> bool {
    map.start == layout.mmap_base && map.end == layout.mmap_base.saturating_add(layout.mmap_size)
}

fn boot_region_is_hidden_heap_backing(map: &ProcMapsEntry, layout: MemoryLayout) -> bool {
    map.start == layout.heap_base && map.end == layout.heap_base.saturating_add(layout.heap_size)
}

fn boot_region_is_hidden_shared_aperture(map: &ProcMapsEntry) -> bool {
    map.start == crate::memory::LINUX_SHARED_FILE_BASE
        && map.end
            == crate::memory::LINUX_SHARED_FILE_BASE
                .saturating_add(crate::memory::LINUX_SHARED_FILE_SIZE)
}

fn boot_region_is_hidden_private_overlay(map: &ProcMapsEntry) -> bool {
    map.start == crate::memory::LINUX_PRIVATE_OVERLAY_BASE
        && map.end
            == crate::memory::LINUX_PRIVATE_OVERLAY_BASE
                .saturating_add(crate::memory::LINUX_PRIVATE_OVERLAY_SIZE)
}

fn boot_region_is_hidden_reservation(map: &ProcMapsEntry, layout: MemoryLayout) -> bool {
    boot_region_is_hidden_mmap_backing(map, layout)
        || boot_region_is_hidden_heap_backing(map, layout)
        || boot_region_is_hidden_shared_aperture(map)
        || boot_region_is_hidden_private_overlay(map)
}

fn project_vma_summaries(mem: &MemState) -> Vec<crate::kernel::VmaSummary> {
    let mut ranges: Vec<(u64, u64)> = mem
        .address_space_regions
        .iter()
        .flatten()
        .filter(|map| !boot_region_is_hidden_reservation(map, mem.layout))
        .chain(mem.dynamic_maps.iter())
        .filter_map(|map| (map.start < map.end).then_some((map.start, map.end)))
        .collect();
    ranges.extend(
        mem.growdown_ranges
            .iter()
            .filter_map(|(_, current, end)| (current < end).then_some((*current, *end))),
    );
    if mem.layout.heap_base < mem.brk_current {
        ranges.push((mem.layout.heap_base, mem.brk_current));
    }
    ranges.sort_unstable();

    let mut unioned: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some((_, previous_end)) = unioned.last_mut()
            && start < *previous_end
        {
            *previous_end = (*previous_end).max(end);
        } else {
            unioned.push((start, end));
        }
    }
    unioned
        .into_iter()
        .map(|(start, end)| crate::kernel::VmaSummary {
            start: GuestVa(start),
            end: GuestVa(end),
        })
        .collect()
}

fn boot_region_source_intersects_hidden_backing(
    map: &ProcMapsEntry,
    mem: &MemState,
    end: u64,
) -> bool {
    if boot_region_is_hidden_mmap_backing(map, mem.layout)
        || boot_region_is_hidden_shared_aperture(map)
        || boot_region_is_hidden_private_overlay(map)
    {
        return true;
    }
    boot_region_is_hidden_heap_backing(map, mem.layout) && end > mem.brk_current
}

fn trim_dynamic_maps_for_range(maps: &mut Vec<ProcMapsEntry>, start: u64, len: u64) {
    let Some(end) = start.checked_add(len) else {
        maps.clear();
        return;
    };
    let mut next = Vec::with_capacity(maps.len());
    for map in maps.drain(..) {
        if !ranges_overlap(start, len, map.start, map.end) {
            next.push(map);
            continue;
        }
        if map.start < start {
            let mut left = map.clone();
            left.end = start;
            next.push(left);
        }
        if end < map.end {
            let mut right = map;
            right.start = end;
            next.push(right);
        }
    }
    *maps = next;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MmapSharing {
    Private,
    Shared,
}

impl MmapSharing {
    fn proc_map_sharing(self) -> ProcMapSharing {
        match self {
            Self::Private => ProcMapSharing::Private,
            Self::Shared => ProcMapSharing::Shared,
        }
    }

    fn guest_mapping_sharing(self) -> carrick_guest_mem::MappingSharing {
        match self {
            Self::Private => carrick_guest_mem::MappingSharing::Private,
            Self::Shared => carrick_guest_mem::MappingSharing::Shared,
        }
    }
}

fn proc_mapping_sharing(sharing: ProcMapSharing) -> carrick_guest_mem::MappingSharing {
    match sharing {
        ProcMapSharing::Private => carrick_guest_mem::MappingSharing::Private,
        ProcMapSharing::Shared => carrick_guest_mem::MappingSharing::Shared,
    }
}

#[derive(Clone, Debug)]
struct MremapMappingMetadata {
    start: u64,
    end: u64,
    prot: LinuxProtFlags,
    sharing: ProcMapSharing,
    path: String,
}

fn proc_maps_entry_mremap_metadata(map: &ProcMapsEntry) -> MremapMappingMetadata {
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
    }
}

/// Dispatcher metadata published only after a runtime `MapHostAlias` install
/// succeeds. Keeping the complete commit record out of `MemState` until then
/// makes an mmap/protection failure a no-op for the prior VMA and every
/// range-derived classification.
pub(crate) struct HostAliasMmapCommit {
    pub(super) start: u64,
    pub(super) len: u64,
    pub(super) prot: LinuxProtFlags,
    pub(super) sharing: ProcMapSharing,
    pub(super) path: String,
    pub(super) locked: Option<crate::vfs::GuestMemoryRange>,
    pub(super) resident: bool,
    pub(super) bus_fault: Option<(u64, u64)>,
    pub(super) write_sealed_shared: bool,
    pub(super) writable_memfd: Option<OpenDescriptionRef>,
}

fn prot_to_proc_perms(prot: LinuxProtFlags) -> (bool, bool, bool) {
    (
        prot.contains(LinuxProtFlags::READ),
        prot.contains(LinuxProtFlags::WRITE),
        prot.contains(LinuxProtFlags::EXEC),
    )
}

fn trim_writable_memfd_maps_for_range(
    maps: &mut Vec<(crate::vfs::GuestMemoryRange, OpenDescriptionRef)>,
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

fn trim_ranges_for_range(ranges: &mut Vec<(u64, u64)>, start: u64, len: u64) {
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

fn trim_remap_snapshots_for_range(
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

fn update_proc_map_prot(maps: &mut Vec<ProcMapsEntry>, start: u64, len: u64, prot: LinuxProtFlags) {
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

fn trim_live_boot_regions_for_range(mem: &mut MemState, start: u64, len: u64) {
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

fn trim_growdown_ranges_for_range(mem: &mut MemState, start: u64, len: u64) {
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

fn remove_mapping_metadata_locked(mem: &mut MemState, start: u64, len: u64) {
    trim_dynamic_maps_for_range(&mut mem.dynamic_maps, start, len);
    trim_live_boot_regions_for_range(mem, start, len);
    trim_growdown_ranges_for_range(mem, start, len);
    trim_ranges_for_range(&mut mem.bus_fault_ranges, start, len);
    trim_writable_memfd_maps_for_range(&mut mem.writable_memfd_maps, start, len);
    trim_remap_snapshots_for_range(&mut mem.remap_snapshots, start, len);
    let Some(remove) =
        crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start.saturating_add(len)))
    else {
        return;
    };
    locked_ranges_remove(&mut mem.locked_ranges, remove);
    locked_ranges_remove(&mut mem.resident_ranges, remove);
    locked_ranges_remove(&mut mem.resident_tracked_ranges, remove);
    remove_fault_range(&mut mem.resident_fault_ranges, remove);
    locked_ranges_remove(&mut mem.write_sealed_shared_maps, remove);
}

fn shared_file_bus_offset(file_len: u64, offset: u64, length: u64, page_size: u64) -> Option<u64> {
    let bytes_available = file_len.saturating_sub(offset).min(length);
    let bus_start = align_up_u64(bytes_available, page_size)?;
    (bus_start < length).then_some(bus_start)
}

fn host_fd_file_len(fd: i32) -> Option<u64> {
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
fn mmap_file_backed_lowering_enabled() -> bool {
    std::env::var_os("CARRICK_MMAP_FILE_BACKED").is_none_or(|value| value != *"0")
}

/// Eager MAP_PRIVATE materialization plus its map-time Linux EOF contract.
/// Bytes through the last partially backed page are snapshotted and its EOF
/// remainder stays zero-filled; pages wholly beyond that boundary are published
/// as BUS_ADRERR. Carrick's existing private-file approximation is detached from
/// the vnode, so a later external truncate is deliberately not tracked.
struct PrivateMmapSnapshot {
    bytes: Vec<u8>,
    bus_fault_offset: Option<u64>,
}

fn snapshot_private_host_file(
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

fn mark_range_unmapped(memory: &mut impl GuestMemory, address: u64, len: usize) {
    // `no_write` describes a live read-only VMA. It must not survive unmap:
    // fault delivery uses this metadata to distinguish Linux ACCERR from
    // MAPERR, and a reused VA must start without its prior owner's permission.
    memory.set_unmapped(address, len, true);
}

/// VMA-metadata answer for a `madvise` range, computed without touching guest
/// memory. `fully_mapped` is false when any page in the range falls in an
/// unmapped hole (→ ENOMEM). `writable`/`shared` describe the covering VMAs and
/// `locked` reports whether the range intersects an mlocked span.
struct MadviseRangeMeta {
    fully_mapped: bool,
    writable: bool,
    shared: bool,
    locked: bool,
}

/// Owns alias exclusion from grow-down fault lookup through backend protection
/// and dispatcher metadata publication.
pub(crate) struct MmapGrowdownFaultPlan {
    start: u64,
    len: usize,
    exclusion: super::HostAliasDispatchGuard,
}

impl MmapGrowdownFaultPlan {
    pub(crate) fn start(&self) -> u64 {
        self.start
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

/// Owns alias exclusion from resident-fault lookup through backend protection
/// and residency publication.
pub(crate) struct ResidentFaultPlan {
    page: u64,
    prot: u64,
    exclusion: super::HostAliasDispatchGuard,
}

impl ResidentFaultPlan {
    pub(crate) fn page(&self) -> u64 {
        self.page
    }

    pub(crate) fn prot(&self) -> u64 {
        self.prot
    }
}

impl SyscallDispatcher {
    fn recover_private_repoint_failure(
        &self,
        candidate: u64,
        failure: carrick_guest_mem::RepointPrivateError,
    ) -> PrivateRepointRecovery {
        match failure {
            carrick_guest_mem::RepointPrivateError::Clean(_) => {
                if self.mem.lock().overlay.free(candidate).is_none() {
                    std::process::abort();
                }
                PrivateRepointRecovery::RecoveredCleanly
            }
            carrick_guest_mem::RepointPrivateError::Indeterminate(_) => {
                PrivateRepointRecovery::FailStopRetainingOwners
            }
        }
    }

    pub(super) fn commit_host_alias_mmap_observed(&self, commit: HostAliasMmapCommit) {
        // The matching install guard keeps HostAliasTransactions non-idle for
        // this complete state+revision publication. Snapshot and fork observers
        // acquire that same exclusion before MemState, so neither can enter the
        // narrow interval between the state unlock and release-ordered revision.
        self.commit_host_alias_mmap(commit);
        self.mem.bump_revision();
    }

    pub(super) fn commit_host_alias_mmap(&self, commit: HostAliasMmapCommit) {
        let Some(end) = commit.start.checked_add(commit.len) else {
            std::process::abort();
        };
        let Some(replacement) =
            crate::vfs::GuestMemoryRange::new(GuestVa(commit.start), GuestVa(end))
        else {
            std::process::abort();
        };
        let (read, write, execute) = prot_to_proc_perms(commit.prot);
        let mut mem = self.mem.lock();

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
        if let Some(description) = commit.writable_memfd {
            mem.writable_memfd_maps.push((replacement, description));
        }
        let entry = ProcMapsEntry {
            start: commit.start,
            end,
            read,
            write,
            execute,
            sharing: commit.sharing,
            path: commit.path,
        };
        let idx = mem
            .dynamic_maps
            .partition_point(|map| map.start < commit.start);
        mem.dynamic_maps.insert(idx, entry);
    }

    /// Snapshot one MAP_PRIVATE file payload into anonymous materialization
    /// bytes. The destination starts zeroed, so EOF supplies the Linux mapping's
    /// zero tail. Every fallible file/device operation completes before a fixed
    /// replacement can touch the prior VMA.
    fn snapshot_private_mmap_file(
        &self,
        fd: Fd,
        offset: u64,
        length: usize,
    ) -> Result<PrivateMmapSnapshot, LinuxErrno> {
        let mut bytes = vec![0; length];
        let length_u64 = u64::try_from(length).map_err(|_| linux_errno::EOVERFLOW)?;
        let page_size = self.linux_page_size();
        let Some(open_file) = self.open_file(fd.0) else {
            return Err(LINUX_EBADF);
        };
        let open = open_file.description.read();
        let offset_usize = usize::try_from(offset).map_err(|_| linux_errno::EOVERFLOW)?;
        let bus_fault_offset = match &*open {
            OpenDescription::File { contents, .. } => {
                let available = contents.read_at(offset_usize, length);
                bytes[..available.len()].copy_from_slice(&available);
                shared_file_bus_offset(contents.len() as u64, offset, length_u64, page_size)
            }
            OpenDescription::SyntheticFile { contents, .. } => {
                if offset_usize < contents.len() {
                    let available = &contents[offset_usize..];
                    let copy_len = available.len().min(length);
                    bytes[..copy_len].copy_from_slice(&available[..copy_len]);
                }
                shared_file_bus_offset(contents.len() as u64, offset, length_u64, page_size)
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
            _ => return Err(LINUX_EBADF),
        };
        Ok(PrivateMmapSnapshot {
            bytes,
            bus_fault_offset,
        })
    }

    /// Derive `madvise` range validity + properties from carrick's mapping
    /// metadata (`dynamic_maps` plus the boot address-space regions), never by
    /// probing a page. Coverage unions both sources so an advise on an
    /// untracked initial region (heap/stack/ELF) is not mis-reported as a hole;
    /// a post-`munmap` hole in a file/anon VMA (removed from `dynamic_maps`)
    /// stays uncovered → ENOMEM.
    fn madvise_range_meta(&self, start: u64, end: u64) -> MadviseRangeMeta {
        let mem = self.mem.lock();
        // (start, end, writable, shared) for every VMA overlapping [start, end).
        let mut intervals: Vec<(u64, u64, bool, bool)> = Vec::new();
        let mut push = |map: &ProcMapsEntry| {
            if map.start < end && map.end > start {
                intervals.push((
                    map.start,
                    map.end,
                    map.write,
                    map.sharing == ProcMapSharing::Shared,
                ));
            }
        };
        for map in &mem.dynamic_maps {
            push(map);
        }
        if let Some(regions) = &mem.address_space_regions {
            for map in regions {
                push(map);
            }
        }
        intervals.sort_by_key(|&(s, ..)| s);
        // Walk the sorted intervals to confirm contiguous coverage of the range
        // and fold the covering VMAs' writable/shared bits.
        let mut covered_to = start;
        let mut writable = true;
        let mut shared = false;
        for (s, e, w, sh) in intervals {
            if s > covered_to {
                break; // gap before this interval → unmapped hole
            }
            if e > covered_to {
                // This interval extends coverage; its bits apply to the range.
                if !w {
                    writable = false;
                }
                if sh {
                    shared = true;
                }
                covered_to = e;
            }
            if covered_to >= end {
                break;
            }
        }
        let fully_mapped = covered_to >= end;
        let locked = mem.locked_ranges.iter().any(|r| {
            let (rs, re) = (r.start().raw(), r.end().raw());
            rs < end && re > start
        });
        MadviseRangeMeta {
            fully_mapped,
            writable: fully_mapped && writable,
            shared,
            locked,
        }
    }

    /// Private VMAs added after image construction. Native vfork backends use
    /// these ranges in addition to their fixed image/arena mappings so
    /// `CLONE_VM` also covers high aliases selected by `mmap(MAP_FIXED)`.
    ///
    /// Only the FreeBSD/x86_64 native lane (`native_freebsd.rs`) consumes this
    /// (and its `shared_dynamic_mapping_ranges`/`dynamic_mapping_ranges`
    /// helpers) today, so the cluster is otherwise unreachable — same
    /// target-gating rationale as `carrick-dsr-x86`'s Cargo dependency edge.
    #[cfg_attr(
        not(all(target_os = "freebsd", target_arch = "x86_64")),
        allow(dead_code)
    )]
    pub(crate) fn private_dynamic_mapping_ranges(&self) -> Vec<(u64, usize)> {
        self.dynamic_mapping_ranges(ProcMapSharing::Private)
    }

    /// Shared VMAs must be excluded from a temporary `INHERIT_SHARE`/COPY
    /// cycle: FreeBSD documents that changing a `MAP_SHARED` mapping to
    /// `INHERIT_COPY` permanently severs its backing-store sharing.
    #[cfg_attr(
        not(all(target_os = "freebsd", target_arch = "x86_64")),
        allow(dead_code)
    )]
    pub(crate) fn shared_dynamic_mapping_ranges(&self) -> Vec<(u64, usize)> {
        self.dynamic_mapping_ranges(ProcMapSharing::Shared)
    }

    #[cfg_attr(
        not(all(target_os = "freebsd", target_arch = "x86_64")),
        allow(dead_code)
    )]
    fn dynamic_mapping_ranges(&self, sharing: ProcMapSharing) -> Vec<(u64, usize)> {
        self.mem
            .lock()
            .dynamic_maps
            .iter()
            .filter(|map| map.sharing == sharing)
            .filter_map(|map| {
                usize::try_from(map.end.saturating_sub(map.start))
                    .ok()
                    .map(|len| (map.start, len))
            })
            .collect()
    }

    fn dynamic_mapping_overlaps(&self, start: u64, len: u64) -> bool {
        dynamic_mapping_overlaps_sorted(&self.mem.lock().dynamic_maps, start, len)
    }

    /// Whether `[start, start + len)` overlaps a Linux-visible guest VMA.
    ///
    /// The boot snapshot includes Carrick's hidden heap and mmap backing arenas;
    /// those reservations are not VMAs by themselves. Dynamic mappings inside
    /// either arena and the live `[heap_base, brk_current)` span are real VMAs and
    /// are checked separately before the hidden boot reservations are filtered.
    pub(super) fn guest_vma_overlaps(&self, start: u64, len: u64) -> bool {
        guest_vma_overlaps_locked(&self.mem.lock(), start, len)
    }

    fn range_intersects_shared_mapping(&self, start: u64, len: u64) -> bool {
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        let mem = self.mem.lock();
        mem.dynamic_maps
            .iter()
            .chain(mem.address_space_regions.iter().flatten())
            .any(|map| map.sharing == ProcMapSharing::Shared && map.start < end && map.end > start)
    }

    fn native16k_write_exec_rejection(
        &self,
        memory: &dyn GuestMemory,
        thread: Option<ThreadCtx<'_>>,
        shared: bool,
        alias: bool,
    ) -> Option<&'static str> {
        if self.page_geometry.native_profile != Some(carrick_spec::NativePageProfile::Native16k) {
            return None;
        }
        if shared {
            return Some("native16k shared write-exec mappings are not yet coherent across fork");
        }
        if memory.supports_concurrent_exec_protection() {
            return None;
        }
        if alias {
            return Some("native16k alias write-exec mmap is not yet protection-aware");
        }
        thread
            .is_some_and(|thread| thread.registry.live_count() > 1)
            .then_some(
                "native16k write-exec mappings are not safe with multiple live guest threads",
            )
    }

    fn native16k_exec_transition_rejection(
        &self,
        memory: &dyn GuestMemory,
        thread: Option<ThreadCtx<'_>>,
    ) -> Option<&'static str> {
        if memory.supports_concurrent_exec_protection() {
            return None;
        }
        (self.page_geometry.native_profile == Some(carrick_spec::NativePageProfile::Native16k)
            && thread.is_some_and(|thread| thread.registry.live_count() > 1))
        .then_some(
            "native16k executable protection transition is not safe with multiple live guest threads",
        )
    }

    fn record_write_sealed_shared_map(&self, start: u64, len: u64) {
        if let Some(range) =
            crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start.saturating_add(len)))
        {
            self.mem.lock().write_sealed_shared_maps.push(range);
        }
    }

    fn range_is_write_sealed_shared(&self, start: u64, len: u64) -> bool {
        self.mem
            .lock()
            .write_sealed_shared_maps
            .iter()
            .any(|r| ranges_overlap(start, len, r.start().raw(), r.end().raw()))
    }

    fn record_writable_memfd_map(&self, start: u64, len: u64, description: OpenDescriptionRef) {
        if let Some(range) =
            crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start.saturating_add(len)))
        {
            self.mem
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
    pub(super) fn remove_mapping_metadata(&self, start: u64, len: u64) {
        remove_mapping_metadata_locked(&mut self.mem.lock(), start, len);
    }

    /// True iff a live MAP_SHARED, PROT_WRITE mapping backed by `description`
    /// exists — used to reject `F_ADD_SEALS` F_SEAL_WRITE with EBUSY.
    pub(in crate::dispatch) fn memfd_has_writable_shared_map(
        &self,
        description: &OpenDescriptionRef,
    ) -> bool {
        self.mem
            .lock()
            .writable_memfd_maps
            .iter()
            .any(|(_, desc)| std::sync::Arc::ptr_eq(desc, description))
    }

    fn record_dynamic_mapping(
        &self,
        start: u64,
        len: u64,
        prot: LinuxProtFlags,
        sharing: ProcMapSharing,
        path: String,
    ) {
        let Some(end) = start.checked_add(len) else {
            return;
        };
        let (read, write, execute) = prot_to_proc_perms(prot);
        let mut mem = self.mem.lock();
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

        if !dynamic_mapping_overlaps_sorted(&mem.dynamic_maps, start, len) {
            let idx = mem.dynamic_maps.partition_point(|map| map.start < start);
            mem.dynamic_maps.insert(idx, entry);
            return;
        }

        trim_dynamic_maps_for_range(&mut mem.dynamic_maps, start, len);
        let idx = mem.dynamic_maps.partition_point(|map| map.start < start);
        mem.dynamic_maps.insert(idx, entry);
    }

    /// Recover the one source VMA `mremap` is allowed to transform. Combining
    /// adjacent VMAs by OR-ing their permission bits can manufacture broader
    /// access than either source had (for example RX + R becoming one RX move),
    /// and a byte-copy cannot preserve mixed backing identities. Reject a gap or
    /// any range spanning more than one VMA before touching allocator/backing
    /// state, matching Linux's `EFAULT` for an invalid old mapping range.
    fn mremap_mapping_metadata(
        &self,
        memory: &impl GuestMemory,
        start: u64,
        len: u64,
    ) -> Result<MremapMappingMetadata, LinuxErrno> {
        let end = start.checked_add(len).ok_or(LINUX_EFAULT)?;
        let mem = self.mem.lock();
        let mut overlapping_dynamic = mem
            .dynamic_maps
            .iter()
            .filter(|map| map.start < end && map.end > start);
        if let Some(first) = overlapping_dynamic.next() {
            if first.start > start || first.end < end || overlapping_dynamic.next().is_some() {
                return Err(LINUX_EFAULT);
            }
            return Ok(proc_maps_entry_mremap_metadata(first));
        }

        // Complete mapping metadata is authoritative over the retained boot
        // backing. A prior munmap leaves the arena bytes addressable to some VMM
        // backends, but it must not let the boot snapshot recreate a source VMA.
        let len_usize = usize::try_from(len).map_err(|_| LINUX_EFAULT)?;
        if memory.has_complete_mapping_metadata()
            && memory.protections().is_some_and(|protections| {
                !protections
                    .unmapped_intersections(start, len_usize)
                    .is_empty()
            })
        {
            return Err(LINUX_EFAULT);
        }
        let mut covering_regions = mem
            .address_space_regions
            .iter()
            .flatten()
            .filter(|map| map.start <= start && map.end >= end);
        let Some(region) = covering_regions.next() else {
            return Err(LINUX_EFAULT);
        };
        if covering_regions.next().is_some() {
            return Err(LINUX_EFAULT);
        }
        // The real boot snapshot includes full heap/mmap backing reservations.
        // Identify those by their exact layout extent rather than by address:
        // an ELF/test VMA may legitimately live at the same VA as a synthetic
        // arena in a custom layout. The mmap reservation is never a source VMA;
        // only the live brk prefix of the heap reservation is.
        if boot_region_source_intersects_hidden_backing(region, &mem, end) {
            return Err(LINUX_EFAULT);
        }
        Ok(proc_maps_entry_mremap_metadata(region))
    }

    pub(in crate::dispatch) fn record_mmap_bus_fault_range(&self, start: u64, len: u64) {
        if len == 0 {
            return;
        }
        self.mem.lock().bus_fault_ranges.push((start, len));
    }

    pub(crate) fn mmap_fault_is_sigbus(&self, addr: u64) -> bool {
        let _host_alias_dispatch = self.begin_host_alias_dispatch();
        self.mem
            .lock()
            .bus_fault_ranges
            .iter()
            .any(|&(start, len)| {
                start
                    .checked_add(len)
                    .is_some_and(|end| addr >= start && addr < end)
            })
    }

    fn record_growdown_mapping(&self, start: u64, len: u64) {
        let Some(end) = start.checked_add(len) else {
            return;
        };
        let page_size = self.linux_page_size();
        let stack_span = 256 * page_size;
        let low = end.saturating_sub(stack_span);
        self.mem.lock().growdown_ranges.push((low, start, end));
    }

    pub(crate) fn mmap_growdown_fault_plan(&self, addr: u64) -> Option<MmapGrowdownFaultPlan> {
        let exclusion = self.begin_host_alias_dispatch();
        let page = page_floor(addr, self.linux_page_size());
        let mem = self.mem.lock();
        for &(low, current, _end) in &mem.growdown_ranges {
            if page >= low && page < current {
                let obstacle = mem
                    .dynamic_maps
                    .iter()
                    .any(|map| map.start < current && map.end > low && map.start != current);
                if obstacle {
                    return None;
                }
                let len = usize::try_from(current - page).ok()?;
                return Some(MmapGrowdownFaultPlan {
                    start: page,
                    len,
                    exclusion: exclusion.with_vma_revision(self.mem.revision_publisher()),
                });
            }
        }
        None
    }

    pub(crate) fn commit_mmap_growdown(&self, plan: MmapGrowdownFaultPlan) {
        if !self.owns_host_alias_dispatch(&plan.exclusion) {
            std::process::abort();
        }
        let mut mem = self.mem.lock();
        for (_low, current, _end) in &mut mem.growdown_ranges {
            if plan.start < *current {
                *current = plan.start;
                break;
            }
        }
        drop(mem);
    }

    fn update_dynamic_mapping_prot(&self, start: u64, len: u64, prot: LinuxProtFlags) {
        let mut mem = self.mem.lock();
        update_proc_map_prot(&mut mem.dynamic_maps, start, len, prot);

        let layout = mem.layout;
        if let Some(regions) = mem.address_space_regions.as_mut() {
            let mut visible = Vec::new();
            let mut reservations = Vec::new();
            for region in regions.drain(..) {
                if boot_region_is_hidden_reservation(&region, layout) {
                    reservations.push(region);
                } else {
                    visible.push(region);
                }
            }
            update_proc_map_prot(&mut visible, start, len, prot);
            visible.extend(reservations);
            visible.sort_by_key(|region| region.start);
            *regions = visible;
        }
    }

    /// Reset memory-accounting state that Linux destroys across `execve(2)`.
    ///
    /// The guest VM is rebuilt separately by the active engine; this resets the
    /// dispatcher-owned view of that VM: program break, mmap bump/free lists,
    /// shared/overlay aperture allocators, and any mprotect state implied by the
    /// old image. The proc/auxv snapshot is preserved because callers refresh it
    /// for the new image in the same execve transition.
    pub(crate) fn reset_memory_state_on_execve(&self) {
        let _vma_dispatch = self.begin_vma_dispatch();
        self.mem.lock().reset_for_execve();
    }

    pub(in crate::dispatch) fn next_mmap_address(
        &self,
        requested: u64,
        length: u64,
        _prot: u64,
        flags: u64,
    ) -> Option<(u64, bool)> {
        let page_size = self.linux_page_size();
        let layout = self.mem.lock().layout;
        if flags & LINUX_MAP_FIXED != 0 {
            if requested == 0 || !requested.is_multiple_of(page_size) {
                return None;
            }
            return Some((requested, false));
        }

        if requested != 0 {
            let aligned_hint = requested.is_multiple_of(page_size);
            let arena_hint =
                aligned_hint && range_within(requested, length, layout.mmap_base, layout.mmap_size);
            if arena_hint {
                let mut mem = self.mem.lock();
                let end = requested.checked_add(length)?;
                if requested >= mem.mmap_next {
                    mem.mmap_next = end;
                    // `reused` (forces a zero-fill) iff this bump landed on memory
                    // the guest already dirtied below the monotonic dirty high-
                    // water (mmap_next was lowered by a prior munmap). Above the
                    // high-water it's pristine guest RAM — keep it lazily zero.
                    let stale = requested < mem.mmap_dirty_high;
                    mem.mmap_dirty_high = mem.mmap_dirty_high.max(end);
                    return Some((requested, stale));
                }
            }
            let canonical_alias_hint =
                aligned_hint && mmap_address_uses_alias(requested, length, layout);
            if canonical_alias_hint {
                return Some((requested, false));
            }
        }

        let mut mem = self.mem.lock();
        if let Some(pos) = mem.free_regions.iter().position(|&(_, l)| l >= length) {
            let (s, l) = mem.free_regions[pos];
            if l == length {
                mem.free_regions.remove(pos);
            } else {
                mem.free_regions[pos] = (s + length, l - length);
            }
            return Some((s, true));
        }
        let address = align_up_u64(mem.mmap_next, page_size)?;
        if !range_within(address, length, layout.mmap_base, layout.mmap_size) {
            return None;
        }
        let end = address.checked_add(length)?;
        mem.mmap_next = end;
        // Same dirty-high-water discipline as the hint path: a bump allocation
        // that dips below the high-water (because munmap lowered mmap_next over
        // already-touched pages) must be zeroed, not returned with stale bytes.
        let stale = address < mem.mmap_dirty_high;
        mem.mmap_dirty_high = mem.mmap_dirty_high.max(end);
        Some((address, stale))
    }

    /// Snapshot one `SharedFile` fragment while its old guest translation is
    /// still live. The snapshot is committed only after backend mutation
    /// succeeds, so a clean failure cannot produce duplicate writeback.
    fn snapshot_shared_writeback<M: GuestMemory>(
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
    fn writeback_shared_snapshot(&self, alloc: &crate::shared_aperture::SharedAlloc, bytes: &[u8]) {
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

    fn writeback_shared<M: GuestMemory>(
        &self,
        memory: &mut M,
        alloc: &crate::shared_aperture::SharedAlloc,
    ) {
        if let Some(bytes) = self.snapshot_shared_writeback(memory, alloc) {
            self.writeback_shared_snapshot(alloc, &bytes);
        }
    }

    fn membarrier(&self, command: u64, flags: u64) -> DispatchOutcome {
        // membarrier(2) command bits (also the CMD_QUERY reply mask). carrick
        // has a globally-coherent guest address space, so every barrier is a
        // no-op that succeeds once its precondition (registration, for the
        // expedited-private variants) is met.
        const CMD_GLOBAL: u64 = 1 << 0;
        const CMD_GLOBAL_EXPEDITED: u64 = 1 << 1;
        const CMD_REGISTER_GLOBAL_EXPEDITED: u64 = 1 << 2;
        const CMD_PRIVATE_EXPEDITED: u64 = 1 << 3;
        const CMD_REGISTER_PRIVATE_EXPEDITED: u64 = 1 << 4;
        const CMD_PRIVATE_EXPEDITED_SYNC_CORE: u64 = 1 << 5;
        const CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: u64 = 1 << 6;
        const SUPPORTED: u64 = CMD_GLOBAL
            | CMD_GLOBAL_EXPEDITED
            | CMD_REGISTER_GLOBAL_EXPEDITED
            | CMD_PRIVATE_EXPEDITED
            | CMD_REGISTER_PRIVATE_EXPEDITED
            | CMD_PRIVATE_EXPEDITED_SYNC_CORE
            | CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE;

        // No advertised command takes a flag (only the un-advertised RSEQ CPU
        // variant does), so any non-zero flags arg is EINVAL — checked before
        // the command, matching the kernel (and QUERY|flags=1 → EINVAL).
        if flags != 0 {
            return DispatchOutcome::errno(LINUX_EINVAL);
        }
        if command == LINUX_MEMBARRIER_CMD_QUERY {
            return DispatchOutcome::Returned {
                value: SUPPORTED as i64,
            };
        }
        match command {
            // A global (or global-expedited) barrier needs no registration.
            CMD_GLOBAL | CMD_GLOBAL_EXPEDITED | CMD_REGISTER_GLOBAL_EXPEDITED => {
                DispatchOutcome::Returned { value: 0 }
            }
            // Registering an expedited-private intent records the readiness bit
            // so a subsequent expedited-private barrier succeeds.
            CMD_REGISTER_PRIVATE_EXPEDITED => {
                self.proc.lock().membarrier_ready |= CMD_PRIVATE_EXPEDITED;
                DispatchOutcome::Returned { value: 0 }
            }
            CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE => {
                self.proc.lock().membarrier_ready |= CMD_PRIVATE_EXPEDITED_SYNC_CORE;
                DispatchOutcome::Returned { value: 0 }
            }
            // An expedited-private barrier requires prior registration; an
            // unregistered call is EPERM (Linux >= 4.16).
            CMD_PRIVATE_EXPEDITED | CMD_PRIVATE_EXPEDITED_SYNC_CORE => {
                if self.proc.lock().membarrier_ready & command != 0 {
                    DispatchOutcome::Returned { value: 0 }
                } else {
                    DispatchOutcome::errno(LINUX_EPERM)
                }
            }
            _ => DispatchOutcome::errno(LINUX_EINVAL),
        }
    }
}

impl SyscallDispatcher {
    define_syscall! {
        fn readahead(this, cx, fd: Fd, _offset: u64, _count: u64) {
            // readahead(2) warms the page cache. carrick has no guest page
            // cache to populate, so the operation itself is a no-op returning
            // 0 — but it must reproduce the kernel's fd validation, which LTP
            // readahead01 asserts. Order matches ksys_readahead: FMODE_READ is
            // checked FIRST (EBADF), THEN the mapping type (EINVAL).
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let desc = open_file.description.read();
            // An O_PATH descriptor (or an O_WRONLY fd) is not open for reading.
            if desc.status_flags() & crate::linux_abi::LINUX_O_PATH != 0
                || desc.status_flags() & LINUX_O_ACCMODE == LINUX_O_WRONLY
            {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // readahead only applies to objects with a readahead-capable
            // address space — regular files (and block devices). Pipes, FIFOs,
            // sockets, char devices, directories, and the anonymous fd types
            // (eventfd/timerfd/epoll/…) all lack one and are EINVAL.
            let applicable = matches!(
                &*desc,
                OpenDescription::File { .. } | OpenDescription::HostFile { .. }
            );
            if !applicable {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn fadvise64(this, cx, fd: Fd, _offset: u64, _len: u64, advice: u64) {
            if !this.fd_is_valid(fd.0) && !is_stdio_fd(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // Linux's generic_fadvise rejects a pipe/FIFO with ESPIPE (checked
            // before the advice value), so posix_fadvise04 (a real pipe) → ESPIPE.
            // A /dev chardev is also a HostPipe in carrick but is NOT a FIFO, so
            // ask the host kernel (fstat S_IFIFO) rather than keying on the
            // variant alone.
            if let Some(open_file) = this.open_file(fd.0) {
                let is_fifo = match &*open_file.description.read() {
                    OpenDescription::PipeReader { .. } | OpenDescription::PipeWriter { .. } => true,
                    OpenDescription::HostPipe { host_fd, .. } => {
                        let mut st: libc::stat = unsafe { core::mem::zeroed() };
                        let fstat_ok = unsafe { libc::fstat(host_fd.raw(), &mut st) } == 0;
                        fstat_ok
                            && (st.st_mode as u32 & libc::S_IFMT as u32)
                                == libc::S_IFIFO as u32
                    }
                    _ => false,
                };
                if is_fifo {
                    return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
                }
            }
            // POSIX_FADV_{NORMAL,RANDOM,SEQUENTIAL,WILLNEED,DONTNEED,NOREUSE} =
            // 0..=5 on aarch64 (asm-generic values); anything else is EINVAL
            // (posix_fadvise03). advice is u64, so a negative arg is huge → caught.
            if advice > 5 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn brk(this, cx, requested: u64) {
            let mut host_alias_dispatch = this.begin_host_alias_dispatch();
            let mut mem = this.mem.lock();
            let current = mem.brk_current;
            if requested == 0 {
                return Ok(DispatchOutcome::Returned {
                    value: current as i64,
                });
            }
            if range_within(requested, 0, mem.layout.heap_base, mem.layout.heap_size) {
                if requested < current {
                    let page_size = this.linux_page_size();
                    let Some(clear_start) = align_up_u64(requested, page_size) else {
                        return Ok(DispatchOutcome::Returned {
                            value: current as i64,
                        });
                    };
                    let Some(clear_end) = align_up_u64(current, page_size) else {
                        return Ok(DispatchOutcome::Returned {
                            value: current as i64,
                        });
                    };
                    let Some(clear_len) = clear_end
                        .checked_sub(clear_start)
                        .and_then(|len| usize::try_from(len).ok())
                    else {
                        return Ok(DispatchOutcome::Returned {
                            value: current as i64,
                        });
                    };
                    if clear_len != 0
                        && cx.memory.zero_backing(clear_start, clear_len).is_err()
                    {
                        return Ok(DispatchOutcome::Returned {
                            value: current as i64,
                        });
                    }
                }
                if requested != current {
                    mem.brk_current = requested;
                    host_alias_dispatch.mark_vma_revision(this.mem.revision_publisher());
                }
            }
            Ok(DispatchOutcome::Returned {
                value: mem.brk_current as i64,
            })
        }

        fn mmap(this, cx, requested: GuestPtr, length: u64, prot: u64, flags: u64, fd: Fd, offset: u64) {
            let mut host_alias_dispatch = this.begin_conditional_vma_dispatch();
            let mut flags = flags;
            let memory = &mut *cx.memory;
            let page_size = this.linux_page_size();

            // Apple Rosetta tags pointers in bits 63:48 (a 16-bit value space)
            // and maps its translated ELF into the x86-64 high half. Strip the
            // tag so the request resolves into the 48-bit VA space the stage-1
            // tables address; with TCR_EL1.TBI the guest's own accesses ignore
            // the top byte, and TTBR1 (shared root) translates the canonical
            // high half (bits[47:0] index the same slot as the stripped VA). The
            // un-stripped value is kept to reject a non-canonical hint below.
            // No-op for native (top-16-zero) guests.
            let requested_raw = requested.0;
            let requested = GuestPtr(requested.0 & 0x0000_FFFF_FFFF_FFFF);

            // io_uring ring mapping: the SQ/CQ rings and SQE array already live
            // in the guest arena (allocated by io_uring_setup); the guest maps
            // them off the ring fd with offset = IORING_OFF_*. Hand back the
            // address carrick placed them at, so guest and runtime share the
            // same coherent ring memory.
            if flags & LINUX_MAP_ANONYMOUS == 0 && fd.0 >= 0
                && let Some(addr) = this.io_uring_mmap_addr(fd.0, offset) {
                    return Ok(DispatchOutcome::Returned { value: addr as i64 });
                }

            let fixed_noreplace = flags & LINUX_MAP_FIXED_NOREPLACE != 0;
            if fixed_noreplace {
                flags |= LINUX_MAP_FIXED;
            }
            // Parse once after FIXED_NOREPLACE -> FIXED normalization; raw
            // syscall words stay at this boundary.
            let map_flags = LinuxMmapFlags::from_bits_retain(flags);
            let prot_flags = LinuxProtFlags::from_bits_retain(prot);

            // Linux validates the fd FIRST for a file mapping: ksys_mmap_pgoff
            // does fget(fd) and returns EBADF before do_mmap ever checks the
            // length/prot/flags (which would yield EINVAL). So a bad fd beats a
            // bad length — LTP mmap08 maps length 0 on a closed fd and expects
            // EBADF, not EINVAL. (Anonymous mappings take no fd → skip.)
            if !map_flags.contains(LinuxMmapFlags::ANONYMOUS) && this.open_file(fd.0).is_none() {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }

            // glibc's vDSO getrandom state page is mapped MAP_ANONYMOUS|
            // MAP_DROPPABLE (0x28) with NO MAP_PRIVATE/MAP_SHARED bit; the kernel
            // treats MAP_DROPPABLE as a private anon mapping, so default the type
            // to PRIVATE rather than rejecting it with EINVAL.
            let map_sharing = {
                let t = map_flags & (LinuxMmapFlags::SHARED | LinuxMmapFlags::PRIVATE);
                if t == (LinuxMmapFlags::SHARED | LinuxMmapFlags::PRIVATE) {
                    // MAP_SHARED_VALIDATE (0x3): a valid map type that, unlike
                    // plain MAP_SHARED, STRICTLY validates the flag word — an
                    // unknown flag bit is EOPNOTSUPP, not the EINVAL that
                    // plain MAP_SHARED gets (which silently ignores unknown
                    // bits for back-compat). mmap20. Otherwise behaves like
                    // MAP_SHARED.
                    if map_flags.bits() & !LinuxMmapFlags::SUPPORTED_MASK != 0 {
                        return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EOPNOTSUPP));
                    }
                    Some(MmapSharing::Shared)
                } else if t == LinuxMmapFlags::SHARED {
                    Some(MmapSharing::Shared)
                } else if t == LinuxMmapFlags::PRIVATE
                    || (t.is_empty() && map_flags.contains(LinuxMmapFlags::DROPPABLE))
                {
                    Some(MmapSharing::Private)
                } else {
                    None
                }
            };
            if length == 0
                || prot_flags.bits() & !LinuxProtFlags::SUPPORTED_MASK != 0
                || map_flags.bits() & !LinuxMmapFlags::SUPPORTED_MASK != 0
                || map_sharing.is_none()
                || (!map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                    && !offset.is_multiple_of(page_size))
                || (map_flags.contains(LinuxMmapFlags::FIXED)
                    && !requested.0.is_multiple_of(page_size))
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let Some(map_sharing) = map_sharing else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let length = match align_up_u64(length, page_size) {
                Some(length) => length,
                None => {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
            };
            let length_usize =
                usize::try_from(length).map_err(|_| DispatchError::LengthTooLarge(length))?;

            // An O_PATH descriptor is not open for I/O — mmap on it returns
            // EBADF (LTP open13 maps an O_PATH fd and expects failure).
            if !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && let Some(open_file) = this.open_file(fd.0)
                && open_file.description.read().status_flags() & crate::linux_abi::LINUX_O_PATH != 0
            {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }

            if !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && let Some(open_file) = this.open_file(fd.0)
                && open_file.description.read().status_flags() & LINUX_O_ACCMODE == LINUX_O_WRONLY
            {
                return Ok(DispatchOutcome::errno(LINUX_EACCES));
            }

            // A memfd sealed F_SEAL_WRITE (or F_SEAL_FUTURE_WRITE) cannot back a
            // shared, writable mapping — Linux returns EPERM (memfd_create01
            // check_mmap_fail). A private (MAP_PRIVATE) writable mapping is fine:
            // its stores never reach the sealed backing.
            if !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && map_sharing == MmapSharing::Shared
                && prot_flags.contains(LinuxProtFlags::WRITE)
                && let Some(open_file) = this.open_file(fd.0)
                && let Some(seals) = open_file.description.read().seals()
                && seals
                    & (crate::linux_abi::LINUX_F_SEAL_WRITE
                        | crate::linux_abi::LINUX_F_SEAL_FUTURE_WRITE)
                    != 0
            {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }

            let fixed_write_exec_alias = if map_flags.contains(LinuxMmapFlags::FIXED) {
                let layout = this.mem.lock().layout;
                !range_within(requested.0, length, layout.mmap_base, layout.mmap_size)
            } else {
                false
            };
            if prot_flags.contains(LinuxProtFlags::WRITE | LinuxProtFlags::EXEC)
                && let Some(reason) = this.native16k_write_exec_rejection(
                    &*memory,
                    cx.thread,
                    map_sharing == MmapSharing::Shared,
                    fixed_write_exec_alias,
                )
            {
                cx.reporter.record(CompatEvent::partial_syscall(
                    cx.number(),
                    "mmap",
                    cx.raw_args(),
                    reason,
                ));
                return Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP));
            }

            if fixed_noreplace && this.dynamic_mapping_overlaps(requested.0, length) {
                return Ok(DispatchOutcome::errno(linux_errno::EEXIST));
            }

            if map_flags.contains(LinuxMmapFlags::FIXED)
                && requested_raw >> 48 == 0xffff
                && this.proc.lock().reported_arch()
                    == crate::vfs::GuestReportedArch::Aarch64
            {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }

            // MAP_FIXED|MAP_PRIVATE landing on a shared-aperture VA needs a
            // genuine per-process backing object before any Private provenance or
            // executable cacheability is published. File mappings are eagerly
            // snapshotted into a complete zero-tailed payload first; anonymous
            // mappings use the same transaction with an all-zero snapshot. Then
            // repoint stage-1 into a fresh private-overlay slot. The boot-mapped
            // overlay avoids post-vCPU stage-2 mutation, and native identity
            // backends atomically replace the host mapping with MAP_PRIVATE anon.
            if map_flags.contains(LinuxMmapFlags::FIXED)
                && map_sharing == MmapSharing::Private
                && crate::memory::va_in_shared_aperture(requested.0, length)
            {
                let snapshot = if map_flags.contains(LinuxMmapFlags::ANONYMOUS) {
                    PrivateMmapSnapshot {
                        bytes: vec![0u8; length_usize],
                        bus_fault_offset: None,
                    }
                } else {
                    match this.snapshot_private_mmap_file(fd, offset, length_usize) {
                        Ok(snapshot) => snapshot,
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    }
                };
                let bus_fault = snapshot.bus_fault_offset.and_then(|bus_offset| {
                    Some((
                        requested.0.checked_add(bus_offset)?,
                        length.checked_sub(bus_offset)?,
                    ))
                });
                let locked_range =
                    this.prepare_mmap_locked_range(map_flags, requested.0, length)?;
                // Keep every prior overlay fragment live until the fresh
                // replacement is installed. A clean repoint failure can then free
                // only the candidate and leave old translation/ownership exact.
                // Exact sub-granule fragments stay quarantined in the aperture
                // free list until they coalesce into an aligned allocation.
                let (overlay_va, displaced_shared_preview) = {
                    let mut mem = this.mem.lock();
                    if !mem
                        .overlay
                        .source_range_is_carvable(requested.0, length, None)
                        || !mem.shared.guest_range_is_carvable(requested.0, length)
                    {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    }
                    let Some(displaced) = mem.shared.guest_range_fragments(requested.0, length)
                    else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    };
                    let overlay = mem.overlay.alloc_sourced(
                        length,
                        crate::shared_aperture::BackingObject::PrivateAnon,
                        Some(requested.0),
                    );
                    (overlay, displaced)
                };
                let Some(overlay_va) = overlay_va else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                // Capture exact SharedFile fragments while the old translation
                // is live, but defer pwrite until repoint succeeds. A clean
                // backend failure therefore leaves ownership and writeback both
                // uncommitted.
                let displaced_shared_snapshots = displaced_shared_preview
                    .iter()
                    .map(|alloc| this.snapshot_shared_writeback(memory, alloc))
                    .collect::<Vec<_>>();
                if let Err(failure) = memory.repoint_private(
                    requested.0,
                    overlay_va,
                    length_usize,
                    &snapshot.bytes,
                ) {
                    match this.recover_private_repoint_failure(overlay_va, failure) {
                        PrivateRepointRecovery::RecoveredCleanly => {
                            return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                        }
                        PrivateRepointRecovery::FailStopRetainingOwners => {
                            // Live translation state is unknown. Retain BOTH the
                            // fresh candidate and prior owners; recycling either
                            // could hand active guest leaves to another mapping.
                            std::process::abort();
                        }
                    }
                }
                for (alloc, bytes) in displaced_shared_preview
                    .iter()
                    .zip(&displaced_shared_snapshots)
                {
                    if let Some(bytes) = bytes {
                        this.writeback_shared_snapshot(alloc, bytes);
                    }
                }
                let displaced_shared = {
                    let mut mem = this.mem.lock();
                    if mem
                        .overlay
                        .carve_source_range(requested.0, length, Some(overlay_va))
                        .is_none()
                    {
                        // Backend publication succeeded, so ownership cannot be
                        // recovered if the validated carve transaction disappeared.
                        std::process::abort();
                    }
                    let Some(displaced) = mem
                        .shared
                        .reserve_private_range(requested.0, length)
                    else {
                        std::process::abort();
                    };
                    displaced
                };
                drop(displaced_shared);
                drop(displaced_shared_preview);
                let prot_none = prot_flags.is_empty();
                memory.set_mapping_protection_and_sharing(
                    requested.0,
                    length_usize,
                    prot_none,
                    !prot_none && !prot_flags.contains(LinuxProtFlags::WRITE),
                    carrick_guest_mem::MappingSharing::Private,
                );
                if memory
                    .protect_range(requested.0, length_usize, prot)
                    .is_err()
                {
                    // Repoint succeeded, so the prior mapping cannot be restored.
                    // Match the runtime alias transaction: do not return to the
                    // guest with split backing/metadata ownership after a
                    // post-replacement failure.
                    mark_range_unmapped(memory, requested.0, length_usize);
                    std::process::abort();
                }
                if let Some((bus_start, bus_len)) = bus_fault {
                    let Ok(bus_len_usize) = usize::try_from(bus_len) else {
                        std::process::abort();
                    };
                    if memory
                        .protect_range(bus_start, bus_len_usize, 0)
                        .is_err()
                    {
                        mark_range_unmapped(memory, requested.0, length_usize);
                        std::process::abort();
                    }
                    memory.set_mapping_protection(bus_start, bus_len_usize, true, false);
                    if let Some(protections) = memory.protections() {
                        protections.set_bus_fault(bus_start, bus_len_usize, true);
                    }
                }
                // The physical replacement and every required protection are
                // now infallible history. Retire the exact predecessor range from
                // all dispatcher classifications, then publish the new EOF tail,
                // residency/lock state, and VMA as one ordered metadata commit.
                this.commit_host_alias_mmap(HostAliasMmapCommit {
                    start: requested.0,
                    len: length,
                    prot: prot_flags,
                    sharing: ProcMapSharing::Private,
                    path: String::new(),
                    locked: locked_range,
                    resident: !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                        || map_flags.contains(LinuxMmapFlags::POPULATE),
                    bus_fault,
                    write_sealed_shared: false,
                    writable_memfd: None,
                });
                return Ok(DispatchOutcome::Returned {
                    value: requested.0 as i64,
                });
            }

            let hvf_page = crate::trap::HVF_PAGE_SIZE;
            // Guest MAP_SHARED of a file: back the guest region with the host
            // file's page cache LIVE, via an aliased stage-2 mapping at a fresh
            // high VA. `mmap(MAP_SHARED, fd)` on the host means guest writes hit
            // the page cache directly — coherent with any other opener (and with
            // a sibling mapping of the same file) and inherited across fork,
            // because the backing kernel object is the file, not a snapshot.
            // This replaces the old aperture-snapshot+msync-writeback model,
            // which was only coherent at msync/munmap time (the memmap b_*
            // invariant). The dispatcher reserves the alias IPA and hands the
            // runtime a MapHostAlias carrying a dup'd fd; the runtime mmaps it
            // and builds the VA->IPA stage-1 path.
            if !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && map_sharing == MmapSharing::Shared
                && !map_flags.contains(LinuxMmapFlags::FIXED)
                && offset.is_multiple_of(hvf_page)
            {
                let dup_fd = {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    let open = open_file.description.read();
                    match &*open {
                        OpenDescription::HostFile { host_fd, .. } => {
                            if host_fd_file_len(host_fd.raw())
                                .and_then(|len| {
                                    shared_file_bus_offset(len, offset, length, page_size)
                                })
                                .is_some()
                            {
                                None
                            } else {
                                let d = unsafe { libc::dup(host_fd.raw()) };
                                if d < 0 { None } else { Some(d) }
                            }
                        }
                        _ => None,
                    }
                };
                if let Some(dup_fd) = dup_fd {
                    let locked_len = match this.prepare_fresh_mmap_locked_length(map_flags, length)
                    {
                        Ok(length) => length,
                        Err(errno) => {
                            unsafe { libc::close(dup_fd) };
                            return Ok(DispatchOutcome::errno(errno));
                        }
                    };
                    // Reserve a FRESH alias IPA (2 MiB-block-aligned so no two
                    // file mappings share a stage-1 block). The allocator is
                    // PROCESS-TREE-GLOBAL and monotonic — never reused — because
                    // the one shared `hv_vm`'s stage-2 TLB can't be flushed on
                    // arm64, so reusing an IPA across host-forked guests reads a
                    // stale page (a latent cross-process coherence hazard; NOT
                    // the go-build crash, which is a separate trap-path bug).
                    // The stage-1 mapping still covers EXACTLY the guest's
                    // page-aligned `length`; map_host_alias rounds the
                    // host/hv_vm_map size up to the 16 KiB HVF granule.
                    let Some(ipa) = crate::memory::alloc_alias_ipa(length) else {
                        // Alias arena exhausted: drop the dup, surface ENOMEM.
                        unsafe { libc::close(dup_fd) };
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    };
                    let va = crate::memory::LINUX_HIGH_VA_THRESHOLD
                        + (ipa - crate::memory::LINUX_ALIAS_IPA_BASE);
                    let locked_range = match locked_len {
                        Some(length) => match va.checked_add(length).and_then(|end| {
                            crate::vfs::GuestMemoryRange::new(GuestVa(va), GuestVa(end))
                        }) {
                            Some(range) => Some(range),
                            None => {
                                unsafe { libc::close(dup_fd) };
                                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                            }
                        },
                        None => None,
                    };
                    // Host mmap prot MUST match the guest's request (and thus the
                    // fd's access mode) for READ/WRITE: MAP_SHARED|PROT_WRITE of a
                    // read-only fd is EACCES. Translate the guest PROT_* bits to
                    // host PROT_*. NOTE: deliberately DROP PROT_EXEC. The guest
                    // executes through HVF's stage-2 (mapped RWX) and its own
                    // stage-1 page tables (UXN clear), never through carrick's host
                    // pointer (which we only ever read for syscall emulation), so
                    // the host backing needs no exec right. macOS's hardened
                    // runtime REJECTS MAP_SHARED|PROT_EXEC of an ordinary file with
                    // EPERM — forwarding the guest's PROT_EXEC here failed the host
                    // mmap and wedged the guest. Linux maps such files fine (the
                    // dynamic loader; CPython test_mmap test_access_parameter's
                    // `mmap(fd, n, prot=PROT_READ|PROT_EXEC)`), and so must we.
                    let pf = prot_flags;
                    let mut host_prot = 0;
                    if pf.intersects(LinuxProtFlags::READ | LinuxProtFlags::EXEC) {
                        // PROT_EXEC implies a host-readable backing (carrick reads
                        // it to service the guest's reads; the exec right itself
                        // lives in the guest's stage-1/stage-2, not the host map).
                        host_prot |= libc::PROT_READ;
                    }
                    if pf.contains(LinuxProtFlags::WRITE) {
                        host_prot |= libc::PROT_WRITE;
                    }
                    // Host-side EFAULT gate for a PROT_NONE file mapping. The
                    // runtime publishes permission + Shared metadata only after
                    // the live host file mapping succeeds; publishing here would
                    // expose a transient private/cacheable executable view.
                    let prot_none = pf.is_empty();
                    let transaction = host_alias_dispatch.publish(HostAliasCommit::mmap(
                        HostAliasMmapCommit {
                            start: va,
                            len: length,
                            prot: prot_flags,
                            sharing: ProcMapSharing::Shared,
                            path: String::new(),
                            locked: locked_range,
                            resident: true,
                            bus_fault: None,
                            write_sealed_shared: false,
                            writable_memfd: None,
                        },
                    ));
                    return Ok(DispatchOutcome::MapHostAlias {
                        transaction,
                        va: GuestVa(va),
                        ipa: Gpa(ipa),
                        len: length,
                        payload: Vec::new(),
                        file: Some((
                            // SAFETY: `dup_fd` is the successful, uniquely-owned
                            // descriptor created above and is transferred into
                            // the non-cloneable outcome exactly once.
                            unsafe { HostAliasOwnedFd::from_raw_fd(dup_fd) },
                            offset as libc::off_t,
                            host_prot,
                        )),
                        shared: true,
                        prot,
                        prot_none,
                    });
                }
            }

            // Guest MAP_SHARED|MAP_ANON: a sub-range of the shared aperture.
            // The bytes already live in the boot-mapped shared region, so we
            // only allocate, zero (recycled memory), and return.
            if map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && map_sharing == MmapSharing::Shared
                && !map_flags.contains(LinuxMmapFlags::FIXED)
            {
                let map_len = align_up_u64(length, hvf_page).unwrap_or(length);
                let alloc = {
                    let mut mem = this.mem.lock();
                    mem.shared.alloc_sourced_with_reuse(
                        length,
                        crate::shared_aperture::BackingObject::SharedAnon,
                        None,
                    )
                };
                if let Some((addr, reused)) = alloc {
                    let map_len_usize = usize::try_from(map_len)
                        .map_err(|_| DispatchError::LengthTooLarge(map_len))?;
                    let locked_range = this.prepare_mmap_locked_range(map_flags, addr, length)?;
                    if reused
                        && memory
                            .zero_anonymous_reuse(
                                addr,
                                map_len_usize,
                                carrick_guest_mem::MappingSharing::Shared,
                            )
                            .is_err()
                    {
                        this.mem.lock().shared.free(addr);
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    }
                    let needs_identity_restore = this
                        .mem
                        .lock()
                        .shared
                        .range_needs_identity_restore(addr, map_len);
                    if needs_identity_restore {
                        if memory.restore_shared_identity(addr, map_len_usize).is_err() {
                            // The page-table edit may already be live even when
                            // its required TLB flush reports failure. Recycling
                            // this VA would publish unowned translation state.
                            std::process::abort();
                        }
                        if this
                            .mem
                            .lock()
                            .shared
                            .mark_identity_restored(addr, map_len)
                            .is_none()
                        {
                            std::process::abort();
                        }
                    }
                    // Make the REQUESTED protection guest-visible: the
                    // aperture is boot-mapped RW, so without this a store
                    // to a PROT_READ anon-shared mapping silently succeeds
                    // (Go runtime/debug TestPanicOnFault: "write did not
                    // fault"). Also restores RW for a recycled chunk whose
                    // prior owner was read-only/none. Best-effort outside
                    // the eager arena (mirrors the file-mmap arm); the
                    // host-side no_access gate is kept in sync for EFAULT.
                    let prot_none = prot_flags.is_empty();
                    memory.set_mapping_protection_and_sharing(
                        addr,
                        map_len_usize,
                        prot_none,
                        !prot_none && !prot_flags.contains(LinuxProtFlags::WRITE),
                        carrick_guest_mem::MappingSharing::Shared,
                    );
                    let protection = if prot_none {
                        memory.protect_range(addr, map_len_usize, 0)
                    } else if memory
                        .resident_pages(GuestVa(addr), 1, this.linux_page_size())
                        .is_none()
                    {
                        // Backends without live host residency use a temporary
                        // inaccessible mapping to observe the first touch.
                        let protected = memory.protect_range(addr, map_len_usize, 0);
                        if protected.is_ok() {
                            this.track_resident_fault_range(addr, length, prot_flags);
                            // The temporary backing state is not the guest VMA
                            // permission. Preserve the requested Linux metadata.
                            memory.set_mapping_protection(
                                addr,
                                map_len_usize,
                                false,
                                !prot_flags.contains(LinuxProtFlags::WRITE),
                            );
                            if let Some(protections) = memory.protections() {
                                protections.set_executable(
                                    addr,
                                    map_len_usize,
                                    prot_flags.contains(LinuxProtFlags::EXEC),
                                );
                            }
                        }
                        protected
                    } else {
                        // Native identity mappings expose real host residency;
                        // apply the requested guest permission directly without
                        // manufacturing a demand fault. This call also consumes
                        // a failure recorded by the preceding void metadata
                        // setter; an error must roll the allocation back.
                        memory.protect_range(addr, map_len_usize, prot)
                    };
                    if protection.is_err() && memory.supports_concurrent_exec_protection() {
                        this.rollback_shared_anon_mapping(
                            memory,
                            addr,
                            length,
                            map_len_usize,
                        )?;
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    }
                    if let Err(errno) = this.commit_mmap_locked_range(memory, locked_range) {
                        memory.set_mapping_protection(addr, map_len_usize, false, false);
                        let _ = memory.protect_range(
                            addr,
                            map_len_usize,
                            crate::linux_abi::LINUX_PROT_READ
                                | crate::linux_abi::LINUX_PROT_WRITE,
                        );
                        this.rollback_shared_anon_mapping(
                            memory,
                            addr,
                            length,
                            map_len_usize,
                        )?;
                        return Ok(DispatchOutcome::errno(errno));
                    }
                    this.record_dynamic_mapping(
                        addr,
                        length,
                        prot_flags,
                        ProcMapSharing::Shared,
                        String::new(),
                    );
                    this.mark_vma_dispatch(&mut host_alias_dispatch);
                    return Ok(DispatchOutcome::Returned { value: addr as i64 });
                }
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }

            let (address, reused) = match this.next_mmap_address(requested.0, length, prot, flags) {
                Some(pair) => pair,
                None => {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
            };

            let fixed_anonymous = map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && map_flags.contains(LinuxMmapFlags::FIXED);
            let layout = this.mem.lock().layout;
            if (reused || fixed_anonymous)
                && !mmap_address_uses_alias(address, length, layout)
            {
                // Scrub the reused region's PHYSICAL backing. MUST bypass the
                // guest-visible permission: a region just reclaimed from munmap
                // is stage-1-invalidated (no-access) and a PROT_NONE mmap is not
                // writable, so the permission-checked write_bytes silently faults
                // and leaves the prior mapping's bytes — which then surface after
                // the guest mprotects the region to RW (CPython multiprocessing
                // Pool built on a freed 16 MiB b'X' buffer → 0x58.. ptr → SIGSEGV).
                // MAP_FIXED|ANON also overwrites a caller-selected range, so it
                // cannot rely on the bump allocator's pristine-tail invariant.
                if memory
                    .zero_anonymous_reuse(
                        address,
                        length_usize,
                        map_sharing.guest_mapping_sharing(),
                    )
                    .is_err()
                {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
            }

            // Restore guest-visible stage-1 validity for arena allocations: a
            // page reclaimed from a prior munmap (which invalidated it) must be
            // valid+RW again, and a PROT_NONE mmap must actually fault. No-op
            // (no TLBI) when the page is already at the target protection.
            let in_arena = range_within(address, length, layout.mmap_base, layout.mmap_size);

            let prot_none = prot_flags.is_empty();
            if prot_none && map_flags.contains(LinuxMmapFlags::ANONYMOUS) {
                let locked_range = this.prepare_mmap_locked_range(map_flags, address, length)?;
                memory.set_mapping_protection_and_sharing(
                    address,
                    length_usize,
                    true,
                    false,
                    map_sharing.guest_mapping_sharing(),
                );
                // protect_range runs UNCONDITIONALLY so a demand-paged backend
                // (bhyve) records a reservation across the WHOLE mmap arena,
                // not just the first `mmap_arena_size()` bytes — Go's page
                // allocator bumps its summary mmaps well past that. The error
                // is fatal only inside the eager arena (where eager backends
                // must succeed); an out-of-arena protect_range failure is
                // benign (KVM/NVMM host-map lazily, HVF maps the arena eagerly).
                if memory.protect_range(address, length_usize, 0).is_err()
                    && (in_arena || memory.supports_concurrent_exec_protection())
                {
                    mark_range_unmapped(memory, address, length_usize);
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
                this.commit_mmap_locked_range(memory, locked_range)?;
                this.record_dynamic_mapping(
                    address,
                    length,
                    prot_flags,
                    map_sharing.proc_map_sharing(),
                    String::new(),
                );
                if map_flags.contains(LinuxMmapFlags::GROWSDOWN) {
                    this.record_growdown_mapping(address, length);
                }
                this.mark_vma_dispatch(&mut host_alias_dispatch);
                return Ok(DispatchOutcome::Returned {
                    value: address as i64,
                });
            }

            if map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && !mmap_address_uses_alias(address, length, layout)
            {
                let locked_range = this.prepare_mmap_locked_range(map_flags, address, length)?;
                memory.set_mapping_protection_and_sharing(
                    address,
                    length_usize,
                    false,
                    !prot_flags.contains(LinuxProtFlags::WRITE),
                    map_sharing.guest_mapping_sharing(),
                );
                // Unconditional (see the PROT_NONE arm above): reserve across
                // the whole arena for demand-paged backends; fatal only in-arena.
                if memory.protect_range(address, length_usize, prot).is_err()
                    && (in_arena || memory.supports_concurrent_exec_protection())
                {
                    mark_range_unmapped(memory, address, length_usize);
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
                this.commit_mmap_locked_range(memory, locked_range)?;
                this.record_dynamic_mapping(
                    address,
                    length,
                    prot_flags,
                    map_sharing.proc_map_sharing(),
                    String::new(),
                );
                if map_flags.contains(LinuxMmapFlags::GROWSDOWN) {
                    this.record_growdown_mapping(address, length);
                }
                this.mark_vma_dispatch(&mut host_alias_dispatch);
                return Ok(DispatchOutcome::Returned {
                    value: address as i64,
                });
            }

            let mut bus_fault_offset = None;
            let mut bus_fault_debug = None;
            // A MAP_SHARED mapping of a memfd sealed F_SEAL_WRITE is created
            // read-only here (a writable one already returned EPERM above); record
            // it so a later mprotect(PROT_WRITE) is rejected.
            let mut mmap_write_sealed_shared = false;
            // A live MAP_SHARED, PROT_WRITE mapping of an (unsealed) memfd — its
            // backing description is recorded so F_ADD_SEALS F_SEAL_WRITE can
            // EBUSY while it is mapped.
            let mut writable_memfd_desc: Option<OpenDescriptionRef> = None;
            // Move-3 E1: an eligible MAP_PRIVATE file mmap lowers to ONE host
            // file-backed `MAP_PRIVATE|MAP_FIXED` mapping (demand-paged from
            // the unified buffer cache) instead of the eager full-length
            // `vec![0]` + `pread` + arena-copy materialization, whose three
            // whole-length passes put 36% of the cold build's zero-fill
            // faults inside guest mmap service windows
            // (docs/perf-results/2026-08-06-build-lane-amplification-ledger.md §7).
            // Eligibility is narrow and explicit; every other shape keeps the
            // snapshot path below, each exclusion for a named reason:
            //   * Private only (a Shared mapping's stores must reach the file);
            //   * no GROWSDOWN (stack-shaped file maps stay on the audited path);
            //   * no PROT_EXEC request (executable content must flow through
            //     the write path's W^X/translation-invalidation metadata);
            //   * `OpenDescription::HostFile` only (in-memory VFS contents
            //     have no host object to map; chardevs keep their zero-fill);
            //   * a non-alias VA (alias IPAs publish via `MapHostAlias`, whose
            //     payload transaction owns the backing);
            //   * the backend's own refusals (identity host ownership,
            //     host-page alignment, linux4k subpage sharing, may-execute).
            // The beyond-EOF tail is then published as BUS_ADRERR through the
            // same bus machinery the Shared path uses — which the eager arena
            // path never did for private maps (it zero-filled instead; Linux
            // faults). Probe `mmapprivfile`'s beyond_eof_page clause is the
            // conformance receipt for that correction.
            // Opt-out hatch for bisection: CARRICK_MMAP_FILE_BACKED=0.
            //
            // Two phases: the CANDIDATE check here (so no snapshot buffer is
            // materialized for a mapping about to demand-page), and the actual
            // backend replacement in the general path below — strictly AFTER
            // `prepare_mmap_locked_range`, the last fallible pre-step, so a
            // failed mmap still leaves a MAP_FIXED target's prior mapping
            // intact (Linux's failure atomicity; the eager path gets this for
            // free by building its buffer before touching backing).
            let mut lowering_candidate = false;
            if map_sharing == MmapSharing::Private
                && !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && !map_flags.contains(LinuxMmapFlags::GROWSDOWN)
                && !prot_flags.contains(LinuxProtFlags::EXEC)
                && !mmap_address_uses_alias(address, length, layout)
                && mmap_file_backed_lowering_enabled()
                && let Some(open_file) = this.open_file(fd.0)
            {
                lowering_candidate =
                    matches!(&*open_file.description.read(), OpenDescription::HostFile { .. });
            }
            let bytes = if map_flags.contains(LinuxMmapFlags::ANONYMOUS) || lowering_candidate {
                Vec::new()
            } else {
                let mut bytes = vec![0; length_usize];
                let Some(open_file) = this.open_file(fd.0) else {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                };
                // Independently opened in-memory descriptions are snapshots of
                // one shared overlay inode. Another process can extend/write
                // that inode after this description was opened (Go telemetry
                // does exactly this before MAP_SHARED). Refresh at map time so
                // EOF classification and the initial mapped bytes come from the
                // live inode rather than a stale per-open snapshot.
                if map_sharing == MmapSharing::Shared {
                    let path = match &*open_file.description.read() {
                        OpenDescription::File { path, .. } => Some(path.clone()),
                        _ => None,
                    };
                    if let Some(path) = path
                        && let Some(live) = this.fs.rootfs_vfs.overlay.file_contents(&path)
                    {
                        let mut open = open_file.description.write();
                        if let OpenDescription::File {
                            path: open_path,
                            contents,
                            metadata,
                            ..
                        } = &mut *open
                            && *open_path == path
                        {
                            metadata.size = live.len();
                            *contents = FileContents::dense(live);
                        }
                    }
                }
                let open = open_file.description.read();
                let offset_usize =
                    usize::try_from(offset).map_err(|_| DispatchError::LengthTooLarge(offset))?;
                match &*open {
                    OpenDescription::File {
                        contents,
                        base,
                        path,
                        ..
                    } => {
                        if map_sharing == MmapSharing::Shared
                            && let Some(bus_offset) = shared_file_bus_offset(
                                contents.len() as u64,
                                offset,
                                length,
                                page_size,
                            )
                        {
                            bus_fault_offset = Some(bus_offset);
                            bus_fault_debug = Some(format!(
                                "vfs path={path:?} file_len={} desc=File",
                                contents.len()
                            ));
                        }
                        if map_sharing == MmapSharing::Shared
                            && matches!(base.seals(), Some(s) if s
                                & (crate::linux_abi::LINUX_F_SEAL_WRITE
                                    | crate::linux_abi::LINUX_F_SEAL_FUTURE_WRITE)
                                != 0)
                        {
                            mmap_write_sealed_shared = true;
                        }
                        if map_sharing == MmapSharing::Shared
                            && prot_flags.contains(LinuxProtFlags::WRITE)
                            && base.seals().is_some()
                        {
                            writable_memfd_desc =
                                Some(std::sync::Arc::clone(&open_file.description));
                        }
                        let available = contents.read_at(offset_usize, length_usize);
                        bytes[..available.len()].copy_from_slice(&available);
                    }
                    OpenDescription::SyntheticFile { contents, path, .. } => {
                        if map_sharing == MmapSharing::Shared
                            && let Some(bus_offset) = shared_file_bus_offset(
                                contents.len() as u64,
                                offset,
                                length,
                                page_size,
                            )
                        {
                            bus_fault_offset = Some(bus_offset);
                            bus_fault_debug = Some(format!(
                                "vfs path={path:?} file_len={} desc=SyntheticFile",
                                contents.len()
                            ));
                        }
                        if offset_usize < contents.len() {
                            let available = &contents[offset_usize..];
                            let copy_len = available.len().min(length_usize);
                            bytes[..copy_len].copy_from_slice(&available[..copy_len]);
                        }
                    }
                    OpenDescription::HostFile { host_fd, .. } => {
                        if map_sharing == MmapSharing::Shared
                            && let Some(file_len) = host_fd_file_len(host_fd.raw())
                            && let Some(bus_offset) =
                                shared_file_bus_offset(file_len, offset, length, page_size)
                        {
                            bus_fault_offset = Some(bus_offset);
                            bus_fault_debug = Some(format!(
                                "host path={:?} file_len={file_len} desc=HostFile host_fd={}",
                                carrick_portable::fd_abs_path(host_fd.raw()),
                                host_fd.raw()
                            ));
                        }
                        let n = unsafe {
                            libc::pread(
                                host_fd.raw(),
                                bytes.as_mut_ptr() as *mut _,
                                length_usize,
                                offset as libc::off_t,
                            )
                        };
                        let _ = n;
                    }
                    // `/dev/zero` (and other zero-fill char devices) open as a
                    // HostPipe — carrick routes all `/dev/*` chardevs through the
                    // pipe variant. Linux maps `/dev/zero` as zero-fill memory, so
                    // MAP_PRIVATE of it must SUCCEED with a zeroed region, not the
                    // spurious EBADF this catch-all gave (LTP mmap10 maps
                    // `/dev/zero` MAP_PRIVATE and asserts success). `bytes` is
                    // already zeroed; only fail a genuine pipe/FIFO (not a char
                    // device), which Linux rejects with ENODEV. Narrow probe via
                    // fstat S_IFCHR so a real pipe still fails.
                    OpenDescription::HostPipe { host_fd, .. } => {
                        let mut st: libc::stat = unsafe { core::mem::zeroed() };
                        let is_chardev = unsafe { libc::fstat(host_fd.raw(), &mut st) } == 0
                            && (st.st_mode as u32 & libc::S_IFMT as u32)
                                == libc::S_IFCHR as u32;
                        if !is_chardev {
                            return Ok(DispatchOutcome::errno(linux_errno::ENODEV));
                        }
                        // chardev zero-fill: keep `bytes` zeroed (no read).
                    }
                    _ => {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                }
                bytes
            };

            // Auxiliary memfd/seal state is published only after every
            // fallible backing/protection operation below succeeds. Recording
            // it here would leave a ghost live mapping when an identity-host
            // mprotect fails before dynamic VMA publication.

            // Guest-chosen mmap addresses outside Carrick's low identity arenas
            // use alias backing. VAs >= 1 TiB need this because HVF's IPA is
            // 40 bits; lower canonical hints in the free gap above the shared
            // aperture use the same machinery so Linux-style advisory hints
            // (notably Go's 0xc000000000 arena probe) are preserved instead of
            // being relocated into the low mmap arena.
            if mmap_address_uses_alias(address, length, layout) {
                if prot_flags.contains(LinuxProtFlags::WRITE | LinuxProtFlags::EXEC)
                    && let Some(reason) =
                        this.native16k_write_exec_rejection(&*memory, cx.thread, false, true)
                {
                    cx.reporter.record(CompatEvent::partial_syscall(
                        cx.number(),
                        "mmap",
                        cx.raw_args(),
                        reason,
                    ));
                    return Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP));
                }
                // Reject a genuinely non-canonical hint (bits 55:48 of the
                // ORIGINAL address neither all-0 nor all-1). With TCR_EL1.TBI on,
                // canonicality is decided by bits 55:48, not 63:48. A canonical
                // high-half address is translatable via TTBR1 and is aliased
                // below; MAP_FIXED_NOREPLACE is a hint the caller retries without.
                let bits_55_48 = (requested_raw >> 48) & 0xff;
                if bits_55_48 != 0x00 && bits_55_48 != 0xff {
                    if map_flags.contains(LinuxMmapFlags::FIXED_NOREPLACE) {
                        return Ok(DispatchOutcome::errno(linux_errno::EEXIST));
                    }
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
                let locked_range = this.prepare_mmap_locked_range(map_flags, address, length)?;
                // Reserve a FRESH alias IPA (2 MiB-block-aligned). Process-tree-
                // global + monotonic, NEVER reused — the shared `hv_vm`'s stage-2
                // TLB can't be flushed on arm64, so a reused IPA reads a stale
                // page. NOTE: the stage-1 mapping must cover EXACTLY the guest's
                // page-aligned `length`, NOT the 2 MiB block — a sub-16 KiB mmap
                // rounded up would map extra 4 KiB guest pages and clobber the next
                // region's page-table entries. hv_vm_map's own 16 KiB IPA-size
                // requirement is satisfied separately inside map_host_alias.
                let Some(ipa) = crate::memory::alloc_alias_ipa(length) else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                // Alias VMA/lock/residency/bus/seal state is a pending commit:
                // no dispatcher metadata changes until the runtime reports the
                // host mapping and every subrange protection successful.
                let bus_fault = bus_fault_offset.and_then(|bus_offset| {
                    Some((
                        address.checked_add(bus_offset)?,
                        length.checked_sub(bus_offset)?,
                    ))
                });
                let transaction = host_alias_dispatch.publish(HostAliasCommit::mmap(
                    HostAliasMmapCommit {
                        start: address,
                        len: length,
                        prot: prot_flags,
                        sharing: map_sharing.proc_map_sharing(),
                        path: String::new(),
                        locked: locked_range,
                        resident: !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                            || map_flags.contains(LinuxMmapFlags::POPULATE),
                        bus_fault,
                        write_sealed_shared: mmap_write_sealed_shared,
                        writable_memfd: writable_memfd_desc,
                    },
                ));
                return Ok(DispatchOutcome::MapHostAlias {
                    transaction,
                    va: GuestVa(address),
                    ipa: Gpa(ipa),
                    len: length,
                    payload: bytes,
                    file: None,
                    shared: map_sharing == MmapSharing::Shared,
                    prot,
                    prot_none,
                });
            }

            let locked_range = this.prepare_mmap_locked_range(map_flags, address, length)?;
            // Move-3 E1, phase 2: replace the arena backing with the host file
            // mapping now that every fallible pre-step has passed. On backend
            // refusal (alignment, ownership, may-execute, linux4k, host mmap
            // failure) — or an unstattable fd — fall back to the legacy eager
            // materialization INLINE, bit-compatible with the pre-E1 arena
            // path: a zeroed buffer plus a best-effort `pread` whose failure
            // leaves zeros. The fallback must not introduce ANY new errno
            // here: by this point the address/scrub steps have already run, so
            // a fresh failure would break mmap's failure atomicity exactly
            // where the eager path never failed (it read best-effort and
            // succeeded). It also keeps the legacy arena contract — no
            // private BUS tail on ineligible shapes (the VMM lanes share this
            // path); only a LOWERED mapping publishes beyond-EOF BUS_ADRERR.
            let mut bytes = bytes;
            let mut lowered_file_backed = false;
            if lowering_candidate {
                let Some(open_file) = this.open_file(fd.0) else {
                    // The description vanished mid-dispatch; the eager path's
                    // own EBADF position for the same state.
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                };
                let open = open_file.description.read();
                let OpenDescription::HostFile { host_fd, .. } = &*open else {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                };
                if let Some(file_len) = host_fd_file_len(host_fd.raw()) {
                    // SAFETY: the description read guard (`open`) keeps the
                    // owning `HostFdRef` alive across the borrow.
                    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(host_fd.raw()) };
                    if matches!(
                        memory.map_private_file_backed(address, length_usize, borrowed, offset),
                        Ok(true)
                    ) {
                        lowered_file_backed = true;
                        bus_fault_offset =
                            shared_file_bus_offset(file_len, offset, length, page_size);
                        if bus_fault_offset.is_some() {
                            bus_fault_debug = Some(format!(
                                "host path={:?} file_len={file_len} desc=HostFile host_fd={}",
                                carrick_portable::fd_abs_path(host_fd.raw()),
                                host_fd.raw()
                            ));
                        }
                    }
                }
                if !lowered_file_backed {
                    let mut fallback = vec![0; length_usize];
                    let n = unsafe {
                        libc::pread(
                            host_fd.raw(),
                            fallback.as_mut_ptr() as *mut _,
                            length_usize,
                            offset as libc::off_t,
                        )
                    };
                    let _ = n;
                    bytes = fallback;
                }
            }
            // Stamp file content through the unchecked path: this is carrick
            // loading the mapping, not a guest write. The dynamic loader often
            // reserves a whole DSO as PROT_NONE before MAP_FIXED segment loads;
            // on identity-native backends that is a real host mprotect, so make
            // the backing temporarily writable before memcpy and apply the
            // requested Linux permission immediately afterward.
            if !bytes.is_empty() {
                let rw = crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE;
                if memory.protect_range(address, length_usize, rw).is_err()
                    && (in_arena || memory.supports_concurrent_exec_protection())
                {
                    mark_range_unmapped(memory, address, length_usize);
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
                if memory.write_bytes_unchecked(address, &bytes).is_err() {
                    mark_range_unmapped(memory, address, length_usize);
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
            }
            memory.set_mapping_protection_and_sharing(
                address,
                length_usize,
                prot_none,
                !prot_none && !prot_flags.contains(LinuxProtFlags::WRITE),
                map_sharing.guest_mapping_sharing(),
            );
            // Make the requested protection guest-visible (also restores RW for
            // a reused range). prot==0 here means file-backed PROT_NONE.
            // Unconditional: reserve across the whole arena; fatal only in-arena.
            if memory.protect_range(address, length_usize, prot).is_err()
                && (in_arena || memory.supports_concurrent_exec_protection())
            {
                mark_range_unmapped(memory, address, length_usize);
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            if let Some(bus_offset) = bus_fault_offset
                && let Some(bus_start) = address.checked_add(bus_offset)
                && let Some(bus_len) = length.checked_sub(bus_offset)
                && let Ok(bus_len_usize) = usize::try_from(bus_len)
            {
                if std::env::var_os("CARRICK_FAULT_DEBUG").is_some() {
                    eprintln!(
                        "[FAULTDBG] mmap BUS fd={} addr={address:#x} len={length:#x} \
                         offset={offset:#x} bus_offset={bus_offset:#x} sharing={map_sharing:?} \
                         prot={prot_flags:?} flags={map_flags:?} {}",
                        fd.0,
                        bus_fault_debug.as_deref().unwrap_or("desc=unknown")
                    );
                }
                memory.set_no_access(bus_start, bus_len_usize, true);
                if memory.protect_range(bus_start, bus_len_usize, 0).is_err()
                    && memory.supports_concurrent_exec_protection()
                {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
                this.record_mmap_bus_fault_range(bus_start, bus_len);
            }
            // A file-backed mapping's content is loaded eagerly (above), and
            // MAP_POPULATE prefaults anonymous pages — so mincore must report
            // those pages resident even before the guest touches them (LTP
            // mincore04 mlocks in a child, then the parent queries mincore).
            if !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                || map_flags.contains(LinuxMmapFlags::POPULATE)
            {
                this.mark_range_resident(address, length);
            }
            this.commit_mmap_locked_range(memory, locked_range)?;
            if mmap_write_sealed_shared {
                this.record_write_sealed_shared_map(address, length);
            }
            if let Some(description) = writable_memfd_desc {
                this.record_writable_memfd_map(address, length, description);
            }
            this.record_dynamic_mapping(
                address,
                length,
                prot_flags,
                map_sharing.proc_map_sharing(),
                String::new(),
            );
            this.mark_vma_dispatch(&mut host_alias_dispatch);
            Ok(DispatchOutcome::Returned {
                value: address as i64,
            })
        }

        fn munmap(this, cx, address: GuestPtr, length: u64) {
            let mut host_alias_dispatch = this.begin_conditional_vma_dispatch();
            let page_size = this.linux_page_size();
            // Linux munmap EINVAL edges (__vm_munmap): the address must be
            // page-aligned and the length non-zero. LTP munmap03 munmaps the
            // address of a BSS global (8-aligned, not page-aligned) and that
            // address + 8, expecting EINVAL — carrick lacked the alignment gate.
            if !address.0.is_multiple_of(page_size) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if length == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let Some(aligned_len) = align_up_u64(length, page_size) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
            let had_vma = guest_vma_overlaps_locked(&this.mem.lock(), address.0, aligned_len);
            let (
                shared_owned,
                shared_carvable,
                shared_preview,
                overlay_owned,
                overlay_carvable,
            ) = {
                let mem = this.mem.lock();
                (
                    mem.shared.guest_range_has_owner(address.0, aligned_len),
                    mem.shared.guest_range_is_carvable(address.0, aligned_len),
                    mem.shared.guest_range_fragments(address.0, aligned_len),
                    mem.overlay.source_range_has_owner(address.0, aligned_len),
                    mem.overlay
                        .source_range_is_carvable(address.0, aligned_len, None),
                )
            };
            if shared_owned && !shared_carvable || overlay_owned && !overlay_carvable {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            if !shared_owned && overlay_owned {
                let Ok(len_usize) = usize::try_from(aligned_len) else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                if cx.memory.unmap_range(address.0, len_usize).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
                mark_range_unmapped(&mut *cx.memory, address.0, len_usize);
                this.remove_mapping_metadata(address.0, aligned_len);
                if this
                    .mem
                    .lock()
                    .overlay
                    .carve_source_range(address.0, aligned_len, None)
                    .is_none()
                {
                    std::process::abort();
                }
                if had_vma {
                    this.mark_vma_dispatch(&mut host_alias_dispatch);
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if shared_owned {
                // SharedFile fragments write their exact dirty intervals back;
                // SharedAnon removes are pure bookkeeping. The aperture stays
                // stage-2 mapped — no hv_vm_unmap.
                let Ok(len_usize) = usize::try_from(aligned_len) else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                let Some(shared_preview) = shared_preview else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                // Capture while the shared guest translation is still live;
                // commit pwrite only after backend unmap succeeds.
                let shared_snapshots = shared_preview
                    .iter()
                    .map(|alloc| this.snapshot_shared_writeback(&mut *cx.memory, alloc))
                    .collect::<Vec<_>>();
                if cx.memory.unmap_range(address.0, len_usize).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
                mark_range_unmapped(&mut *cx.memory, address.0, len_usize);
                this.remove_mapping_metadata(address.0, aligned_len);
                let displaced_shared = {
                    let mut mem = this.mem.lock();
                    if mem
                        .overlay
                        .carve_source_range(address.0, aligned_len, None)
                        .is_none()
                    {
                        std::process::abort();
                    }
                    let Some(displaced) = mem.shared.carve_guest_range(address.0, aligned_len) else {
                        std::process::abort();
                    };
                    displaced
                };
                for (alloc, bytes) in shared_preview.iter().zip(&shared_snapshots) {
                    if let Some(bytes) = bytes {
                        this.writeback_shared_snapshot(alloc, bytes);
                    }
                }
                drop(displaced_shared);
                drop(shared_preview);
                if had_vma {
                    this.mark_vma_dispatch(&mut host_alias_dispatch);
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // A canonical alias-window guest VA is a dynamic alias mapping:
            // either a MAP_SHARED file region (carrick-chosen VA in the narrow
            // alias window, backed LIVE by the host page cache, so no writeback
            // is owed), a MAP_FIXED mapping at a guest-chosen high VA (Apple
            // Rosetta maps its translated ELF + arenas in the x86-64 high half),
            // or a Linux-style advisory hint in the free gap above Carrick's
            // shared aperture. All are valid mappings/reservations, so munmap
            // must succeed. Best-effort stage-1 invalidate so use-after-munmap
            // faults; arm64 HVF has no stage-2 unmap, so the alias IPA + any dup
            // fd are reclaimed at process teardown.
            // Misaligned addresses (e.g. RLIM_INFINITY, which LTP munmap03 passes
            // to assert EINVAL) are already rejected by the alignment gate above;
            // addresses >= 2^48 stay EINVAL via the range check below.
            let layout = this.mem.lock().layout;
            if mmap_address_uses_alias(address.0, length, layout) {
                let Ok(len_usize) = usize::try_from(aligned_len) else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                // Alias teardown: invalidate AND reclaim the now-empty per-
                // alias stage-1 sub-table (each MAP_SHARED file mapping took
                // its own 2 MiB block + L3 table) — else the spare pool leaks
                // one table per alias and a churning guest hits OutOfTables.
                if cx
                    .memory
                    .unmap_alias_range(address.0, len_usize)
                    .is_err()
                {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
                mark_range_unmapped(&mut *cx.memory, address.0, len_usize);
                this.remove_mapping_metadata(address.0, aligned_len);
                if had_vma {
                    this.mark_vma_dispatch(&mut host_alias_dispatch);
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if !range_within(address.0, length, layout.mmap_base, layout.mmap_size) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let Ok(len_usize) = usize::try_from(aligned_len) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
            // Invalidate the freed range before removing any dispatcher VMA
            // metadata or returning it to the allocator.
            if cx.memory.unmap_range(address.0, len_usize).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            mark_range_unmapped(&mut *cx.memory, address.0, len_usize);
            this.remove_mapping_metadata(address.0, aligned_len);
            let mut mem = this.mem.lock();
            if mem
                .overlay
                .carve_source_range(address.0, aligned_len, None)
                .is_none()
            {
                std::process::abort();
            }
            if address.0.checked_add(aligned_len) == Some(mem.mmap_next) {
                mem.mmap_next = address.0;
                while let Some(pos) = mem
                    .free_regions
                    .iter()
                    .position(|&(s, l)| s.checked_add(l) == Some(mem.mmap_next))
                {
                    let (s, _l) = mem.free_regions.remove(pos);
                    mem.mmap_next = s;
                }
            } else {
                free_regions_insert(&mut mem.free_regions, address.0, aligned_len);
            }
            drop(mem);
            if had_vma {
                this.mark_vma_dispatch(&mut host_alias_dispatch);
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn msync(this, cx, address: GuestPtr, length: u64, flags: u64) {
            let _host_alias_dispatch = this.begin_host_alias_dispatch();
            if flags & !(LINUX_MS_ASYNC | LINUX_MS_INVALIDATE | LINUX_MS_SYNC) != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if flags & LINUX_MS_ASYNC != 0 && flags & LINUX_MS_SYNC != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // msync requires a page-aligned start address (Linux checks this
            // before anything else). CPython's mmap.flush(offset, size) calls
            // msync(data + offset, size, ...), so flush(1, n) must EINVAL —
            // test_mmap.test_flush_return_value asserts it on Linux.
            if !address.0.is_multiple_of(this.linux_page_size()) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if length == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let alloc = {
                let mem = this.mem.lock();
                mem.shared
                    .live()
                    .iter()
                    .find(|a| a.guest_addr == address.0)
                    .cloned()
            };
            if let Some(alloc) = alloc {
                // Write a SharedFile backing's dirty bytes back without freeing.
                this.writeback_shared(&mut *cx.memory, &alloc);
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if cx.memory.read_bytes(address.0, 1).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn mlock(this, cx, address: GuestPtr, length: u64) {
            let _host_alias_dispatch = this.begin_host_alias_dispatch();
            let page_size = this.linux_page_size();
            let Some(range) = page_rounded_range(address, length, page_size)? else {
                return Ok(DispatchOutcome::Returned { value: 0 });
            };
            validate_mlock_range(&mut *cx.memory, range, true, page_size)?;
            this.populate_resident_range(&mut *cx.memory, range)?;
            this.add_locked_range(range)?;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn munlock(this, cx, address: GuestPtr, length: u64) {
            let _host_alias_dispatch = this.begin_host_alias_dispatch();
            let page_size = this.linux_page_size();
            let Some(range) = page_rounded_range(address, length, page_size)? else {
                return Ok(DispatchOutcome::Returned { value: 0 });
            };
            validate_mlock_range(&mut *cx.memory, range, false, page_size)?;
            this.remove_locked_range(range);
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn mlockall(this, cx, flags: u64) {
            let _host_alias_dispatch = this.begin_host_alias_dispatch();
            let Some(flags) = LinuxMlockallFlags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            if flags.is_empty()
                || flags.contains(LinuxMlockallFlags::ONFAULT)
                    && !flags.intersects(
                        LinuxMlockallFlags::CURRENT | LinuxMlockallFlags::FUTURE,
                    )
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if flags.contains(LinuxMlockallFlags::CURRENT) {
                this.lock_current_mappings(
                    &mut *cx.memory,
                    flags.contains(LinuxMlockallFlags::ONFAULT),
                )?;
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn munlockall(this, cx) {
            let _host_alias_dispatch = this.begin_host_alias_dispatch();
            this.mem.lock().locked_ranges.clear();
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn mlock2(this, cx, address: GuestPtr, length: u64, flags: u64) {
            let _host_alias_dispatch = this.begin_host_alias_dispatch();
            let Some(flags) = LinuxMlock2Flags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let page_size = this.linux_page_size();
            let Some(range) = page_rounded_range(address, length, page_size)? else {
                return Ok(DispatchOutcome::Returned { value: 0 });
            };
            validate_mlock_range(
                &mut *cx.memory,
                range,
                !flags.contains(LinuxMlock2Flags::ONFAULT),
                page_size,
            )?;
            if !flags.contains(LinuxMlock2Flags::ONFAULT) {
                this.populate_resident_range(&mut *cx.memory, range)?;
            }
            this.add_locked_range(range)?;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn mincore(this, cx, address: GuestPtr, length: u64, vec: GuestPtr) {
            let _host_alias_dispatch = this.begin_host_alias_dispatch();
            let memory = &mut *cx.memory;
            let page_size = this.linux_page_size();
            // Linux requires a page-aligned start address, else EINVAL (this is
            // what Go's TestMincoreErrorSign checks — the errno must be -EINVAL).
            if !address.0.is_multiple_of(page_size) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if length == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if !mincore_page_is_mapped(memory, address.0) {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            // Linux returns ENOMEM unless the WHOLE [address, address+length)
            // range is mapped. Validate the last page first to reject overflow
            // and bound the residency vec below — without it a guest-controlled
            // `length` (up to u64::MAX) forces a petabyte `vec![1u8; pages]`
            // that aborts the carrick process (alloc failure is not a
            // catchable panic). Then walk each page start so mapped first+last
            // pages with a hole in the middle still report ENOMEM.
            let last_page = match address.0.checked_add(length - 1) {
                Some(end) => page_floor(end, page_size),
                None => return Ok(DispatchOutcome::errno(LINUX_ENOMEM)),
            };
            if !mincore_page_is_mapped(memory, last_page) {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            let mut page = address.0;
            while page <= last_page {
                if !mincore_page_is_mapped(memory, page) {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
                page = match page.checked_add(page_size) {
                    Some(next) => next,
                    None => return Ok(DispatchOutcome::errno(LINUX_ENOMEM)),
                };
            }
            let pages = length.div_ceil(page_size);
            let bytes = this
                .mincore_residency_vector(memory, address.0, pages, page_size)
                .unwrap_or_else(|| vec![1u8; pages as usize]);
            memory.write_bytes(vec.0, &bytes)?;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn mremap(this, cx, old_address: GuestPtr, old_size: u64, new_size_req: u64, flags: u64, _new_address: GuestPtr) {
            let mut host_alias_dispatch = this.begin_conditional_vma_dispatch();
            let memory = &mut *cx.memory;
            let page_size = this.linux_page_size();
            // Errno precedence below is oracle-derived (real Linux 6.12.76,
            // docker gcc:latest, 2026-07-23 — see
            // .superpowers/sdd/mremap-ruling-report.md) and follows man 2 mremap's
            // documented EINVAL conditions: no unrecognized flag bits,
            // new_size != 0, MREMAP_FIXED/MREMAP_DONTUNMAP only paired with
            // MREMAP_MAYMOVE, and MREMAP_DONTUNMAP only with old_size ==
            // new_size. Real Linux validates ALL of these — even for
            // requests that use MREMAP_FIXED or MREMAP_DONTUNMAP, since real
            // Linux actually implements both flags — before it would ever
            // attempt the remap. So every one of these well-formedness
            // checks must run BEFORE carrick's own "not yet implemented"
            // refusal just below: a malformed request (e.g. an unrelated
            // garbage bit ORed onto MREMAP_FIXED) must surface the EINVAL
            // real Linux would give, not carrick's EOPNOTSUPP stand-in for a
            // shape real Linux would have actually performed.
            if new_size_req == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if flags & !(LINUX_MREMAP_MAYMOVE | LINUX_MREMAP_FIXED | LINUX_MREMAP_DONTUNMAP) != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let Some(old_size) = align_up_u64(old_size, page_size) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
            let Some(new_size) = align_up_u64(new_size_req, page_size) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
            let move_fixed = flags & LINUX_MREMAP_FIXED != 0;
            let dontunmap = flags & LINUX_MREMAP_DONTUNMAP != 0;
            if (move_fixed || dontunmap) && flags & LINUX_MREMAP_MAYMOVE == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if dontunmap && new_size != old_size {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if move_fixed || dontunmap {
                // Only now — once the request has passed every
                // well-formedness check real Linux performs first — refuse
                // the FIXED/DONTUNMAP shapes carrick cannot yet faithfully
                // emulate (exact fixed-replacement or DONTUNMAP zero-fill/
                // fault contract on every backend). No allocator, backing,
                // or VMA mutation has happened yet.
                //
                // Everything below this point in the handler runs ONLY when
                // both flags are false (this is the only return before it),
                // so it never needs to special-case a fixed destination or a
                // retained source — that logic lived here until it was
                // proven unreachable and deleted (see
                // `.superpowers/sdd/mremap-ruling-report.md` and the
                // Phase-2 final-review). Reintroducing MREMAP_FIXED/
                // MREMAP_DONTUNMAP support means adding it back deliberately,
                // not resurrecting dead branches.
                return Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP));
            }
            let layout = this.mem.lock().layout;
            let source_in_arena =
                range_within(old_address.0, old_size, layout.mmap_base, layout.mmap_size);
            if !source_in_arena && memory.read_bytes(old_address.0, 1).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let source_metadata = match this.mremap_mapping_metadata(memory, old_address.0, old_size) {
                Ok(metadata) => metadata,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            if source_metadata.sharing == ProcMapSharing::Shared && new_size > old_size {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            let shared_aperture_alloc = this
                .mem
                .lock()
                .shared
                .live()
                .iter()
                .find(|alloc| {
                    ranges_overlap(
                        old_address.0,
                        old_size,
                        alloc.guest_addr,
                        alloc.guest_addr.saturating_add(alloc.live_len),
                    )
                })
                .cloned();
            if let Some(ref alloc) = shared_aperture_alloc
                && (alloc.guest_addr != old_address.0
                    || old_size != alloc.live_len
                    || source_metadata.start != old_address.0
                    || source_metadata.end != old_address.0.saturating_add(old_size))
            {
                // Carrick cannot split one shared-aperture backing owner during
                // mremap. Reject prefix/suffix shrink before touching page tables,
                // residency, VMA metadata, or the aperture free list.
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            if !source_in_arena {
                // The mapping is not in the mmap arena: it's a MAP_SHARED file
                // alias (high VA) or a MAP_SHARED anonymous shared-aperture
                // region. CPython's mmap.resize() shrinks both of these
                // (test_mmap test_basic on a file mapping, test_resize_past_pos
                // on an anonymous one), tolerating only success or SystemError —
                // never the OSError we raised by rejecting them here.
                //
                // Support resize-DOWN: the backing stays at the same VA with a
                // smaller logical size. CPython already ftruncate'd a file
                // backing to the new size; the freed tail is not accessed (Python
                // tracks the new size/position), so we return the unchanged base.
                // Shrink revokes the tail in both backend and sharing metadata;
                // retaining a logically removed shared executable tail would let
                // native translation classify replacement bytes from stale VMA
                // state. A grow without MAYMOVE cannot be placed in situ, which
                // Linux reports as ENOMEM. Musl relies on that distinction while
                // probing the main stack VMA.
                if memory.read_bytes(old_address.0, 1).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                if new_size <= old_size {
                    let tail_start = old_address.0.saturating_add(new_size);
                    let tail_len = old_size.saturating_sub(new_size);
                    if tail_len != 0 {
                        let Ok(tail_len_usize) = usize::try_from(tail_len) else {
                            return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                        };
                        let tracked_shared = shared_aperture_alloc.is_some();
                        let (tracked_overlay, overlay_tail_carvable) = {
                            let mem = this.mem.lock();
                            (
                                mem.overlay.source_range_has_owner(tail_start, tail_len),
                                mem.overlay
                                    .source_range_is_carvable(tail_start, tail_len, None),
                            )
                        };
                        if tracked_overlay && !overlay_tail_carvable {
                            return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                        }
                        let unmap_result = if !tracked_shared
                            && !tracked_overlay
                            && mmap_address_uses_alias(old_address.0, old_size, layout)
                        {
                            memory.unmap_alias_range(tail_start, tail_len_usize)
                        } else {
                            memory.unmap_range(tail_start, tail_len_usize)
                        };
                        if unmap_result.is_err() {
                            return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                        }
                        mark_range_unmapped(memory, tail_start, tail_len_usize);
                        this.remove_mapping_metadata(tail_start, tail_len);
                        if tracked_shared
                            && this
                                .mem
                                .lock()
                                .shared
                                .shrink(old_address.0, new_size)
                                .is_none()
                        {
                            // The backend tail is already gone. Preflight above
                            // proved this exact shrink valid, so failure here is
                            // an internal ownership/accounting violation.
                            std::process::abort();
                        }
                        if tracked_overlay
                            && this
                                .mem
                                .lock()
                                .overlay
                                .carve_source_range(tail_start, tail_len, None)
                                .is_none()
                        {
                            // The SOURCE tail is no longer reachable after the
                            // backend unmap. Losing the preflighted overlay carve
                            // would leave reusable storage with stale ownership.
                            std::process::abort();
                        }
                    }
                    this.record_dynamic_mapping(
                        old_address.0,
                        new_size,
                        source_metadata.prot,
                        source_metadata.sharing,
                        source_metadata.path.clone(),
                    );
                    if new_size != old_size {
                        this.mark_vma_dispatch(&mut host_alias_dispatch);
                    }
                    return Ok(DispatchOutcome::Returned {
                        value: old_address.0 as i64,
                    });
                }
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            if new_size <= old_size {
                // Linux mremap shrink unmaps the freed tail [old+new_size,
                // old+old_size); carrick used to leave it mapped (a leak, and
                // the stale bytes there could later be misread). Reclaim the
                // whole-page tail exactly as munmap does — invalidate stage-1,
                // then lower mmap_next (if it's the high-water) or return it to
                // free_regions (a future mmap reuse zero-fills it).
                let tail_start = old_address.0 + new_size; // new_size is page-aligned ≤ old_size
                let tail_end = old_address
                    .0
                    .checked_add(old_size)
                    .map(|e| page_floor(e, page_size));
                if let Some(tail_end) = tail_end
                    && tail_end > tail_start
                {
                    let tail_len = tail_end - tail_start;
                    let Ok(tl) = usize::try_from(tail_len) else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    };
                    // Invalidate guest translation first, then publish the
                    // post-unmap VMA state last so backend protection hooks
                    // cannot overwrite it with live PROT_NONE metadata.
                    if memory.unmap_range(tail_start, tl).is_err() {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    }
                    mark_range_unmapped(memory, tail_start, tl);
                    this.remove_mapping_metadata(tail_start, tail_len);
                    let mut mem = this.mem.lock();
                    if tail_end == mem.mmap_next {
                        mem.mmap_next = tail_start;
                        while let Some(pos) = mem
                            .free_regions
                            .iter()
                            .position(|&(s, l)| s.checked_add(l) == Some(mem.mmap_next))
                        {
                            let (s, _l) = mem.free_regions.remove(pos);
                            mem.mmap_next = s;
                        }
                    } else {
                        free_regions_insert(&mut mem.free_regions, tail_start, tail_len);
                    }
                }
                this.record_dynamic_mapping(
                    old_address.0,
                    new_size,
                    source_metadata.prot,
                    source_metadata.sharing,
                    source_metadata.path.clone(),
                );
                if new_size != old_size {
                    this.mark_vma_dispatch(&mut host_alias_dispatch);
                }
                return Ok(DispatchOutcome::Returned {
                    value: old_address.0 as i64,
                });
            }

            if old_address.0.checked_add(old_size) == Some(this.mem.lock().mmap_next) {
                let Some(old_end) = old_address.0.checked_add(old_size) else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                let Some(new_end) = old_address.0.checked_add(new_size) else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                if range_within(old_address.0, new_size, layout.mmap_base, layout.mmap_size) {
                    // Re-validate the freshly-grown tail with the source VMA's
                    // exact protection and sharing. Sharing is published before
                    // execute permission, so an RX shared grow can never appear
                    // transiently private/cacheable to native translation.
                    let grow_len_u64 = new_size - old_size;
                    let Ok(grow_len) = usize::try_from(grow_len_u64) else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    };
                    let prot_none = source_metadata.prot.is_empty();
                    memory.set_mapping_protection_and_sharing(
                        old_end,
                        grow_len,
                        prot_none,
                        !prot_none && !source_metadata.prot.contains(LinuxProtFlags::WRITE),
                        proc_mapping_sharing(source_metadata.sharing),
                    );
                    if memory
                        .protect_range(old_end, grow_len, source_metadata.prot.bits())
                        .is_err()
                    {
                        mark_range_unmapped(memory, old_end, grow_len);
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    }
                    {
                        let mut mem = this.mem.lock();
                        mem.mmap_next = new_end;
                        // The dirty high-water stays monotonic so a later
                        // munmap+rebump cannot expose bytes dirtied in this tail.
                        mem.mmap_dirty_high = mem.mmap_dirty_high.max(new_end);
                    }
                    this.record_dynamic_mapping(
                        old_address.0,
                        new_size,
                        source_metadata.prot,
                        source_metadata.sharing,
                        source_metadata.path.clone(),
                    );
                    this.mark_vma_dispatch(&mut host_alias_dispatch);
                    return Ok(DispatchOutcome::Returned {
                        value: old_address.0 as i64,
                    });
                }
            }

            if flags & LINUX_MREMAP_MAYMOVE == 0 {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            let Some((new_addr, reused)) = this.next_mmap_address(
                0,
                new_size,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                0,
            ) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
            let new_len = match usize::try_from(new_size) {
                Ok(n) => n,
                Err(_) => return Ok(DispatchOutcome::errno(LINUX_ENOMEM)),
            };
            let copy_len = match usize::try_from(old_size.min(new_size)) {
                Ok(len) => len,
                Err(_) => {
                    this.rollback_fresh_arena_mapping(memory, new_addr, new_size)?;
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
            };
            let copied = if copy_len == 0 {
                Vec::new()
            } else {
                match memory.read_bytes_raw(old_address.0, copy_len) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        this.rollback_fresh_arena_mapping(memory, new_addr, new_size)?;
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                }
            };
            if reused && memory.zero_backing(new_addr, new_len).is_err() {
                this.rollback_fresh_arena_mapping(memory, new_addr, new_size)?;
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            // Publish the destination as non-executable RW while copying, but
            // with its final sharing already installed. This is restrictive for
            // RX sources and prevents a stale executable replacement from being
            // observed as private/cacheable during the move.
            memory.set_mapping_protection_and_sharing(
                new_addr,
                new_len,
                false,
                false,
                proc_mapping_sharing(source_metadata.sharing),
            );
            if memory
                .protect_range(new_addr, new_len, LINUX_PROT_READ | LINUX_PROT_WRITE)
                .is_err()
            {
                this.rollback_fresh_arena_mapping(memory, new_addr, new_size)?;
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            if !copied.is_empty()
                && memory
                    .write_bytes_unchecked(new_addr, &copied)
                    .is_err()
            {
                this.rollback_fresh_arena_mapping(memory, new_addr, new_size)?;
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            let prot_none = source_metadata.prot.is_empty();
            memory.set_mapping_protection(
                new_addr,
                new_len,
                prot_none,
                !prot_none && !source_metadata.prot.contains(LinuxProtFlags::WRITE),
            );
            if memory
                .protect_range(new_addr, new_len, source_metadata.prot.bits())
                .is_err()
            {
                this.rollback_fresh_arena_mapping(memory, new_addr, new_size)?;
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            this.record_dynamic_mapping(
                new_addr,
                new_size,
                source_metadata.prot,
                source_metadata.sharing,
                source_metadata.path.clone(),
            );
            // mremap MOVE on Linux UNMAPS the source [old, old+old_size) (unless
            // MREMAP_DONTUNMAP — refused above, so never true here: this handler
            // always reclaims the source). carrick previously LEAKED it: the
            // source VA stayed mapped with its stale bytes and was never
            // returned to the allocator, so `mmap_next` ran away and glibc's
            // view of which VAs are mapped diverged from carrick's (glibc
            // considers the source freed). Reclaim the source exactly like
            // munmap, so a later access faults and the VA is reusable —
            // matching Linux and keeping the mmapped-chunk bookkeeping
            // coherent across the BytesIO/recv_bytes realloc-grow cascade
            // (test_multiprocessing test_connection's 16 MiB round-trip).
            // Guard: the destination must not overlap the source (it never does —
            // `new_addr` is freshly bump-allocated or a disjoint free region —
            // but reclaiming an overlapping source would unmap the live copy).
            let dst_overlaps_src = new_addr < old_address.0.wrapping_add(old_size)
                && old_address.0 < new_addr.wrapping_add(new_size);
            if !dst_overlaps_src
                && let Ok(old_len) = usize::try_from(old_size)
                    && old_len > 0
                {
                    if let Err(first) = memory.unmap_range(old_address.0, old_len)
                        && let Err(retry) = memory.unmap_range(old_address.0, old_len)
                    {
                        let _ = (first, retry);
                        // The destination is already published; returning would
                        // expose two owners while reporting failure. Retain
                        // fail-stop semantics so host teardown reclaims both.
                        std::process::abort();
                    }
                    mark_range_unmapped(memory, old_address.0, old_len);
                    this.remove_mapping_metadata(old_address.0, old_size);
                    let mut mem = this.mem.lock();
                    if old_address.0.checked_add(old_size) == Some(mem.mmap_next) {
                        mem.mmap_next = old_address.0;
                        while let Some(pos) = mem
                            .free_regions
                            .iter()
                            .position(|&(s, l)| s.checked_add(l) == Some(mem.mmap_next))
                        {
                            let (s, _l) = mem.free_regions.remove(pos);
                            mem.mmap_next = s;
                        }
                    } else {
                        free_regions_insert(&mut mem.free_regions, old_address.0, old_size);
                    }
                }
            this.mark_vma_dispatch(&mut host_alias_dispatch);
            Ok(DispatchOutcome::Returned {
                value: new_addr as i64,
            })
        }

        fn mprotect(this, cx, address: GuestPtr, length: u64, prot: u64) {
            let mut host_alias_dispatch = this.begin_conditional_vma_dispatch();
            let page_size = this.linux_page_size();
            if prot & !LinuxProtFlags::SUPPORTED_MASK != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let prot_flags = LinuxProtFlags::from_bits_retain(prot);
            if length == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if !address.0.is_multiple_of(page_size) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let Some(length) = align_up_u64(length, page_size) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
            let Ok(len) = usize::try_from(length) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
            // Linux mprotect returns ENOMEM when the range covers unmapped VA
            // (a hole in the address space). carrick previously SUCCEEDED on any
            // page-aligned address regardless of whether it was mapped (LTP
            // mprotect01's "call succeeded unexpectedly" — it mprotects an
            // unmapped page at addr=NULL and asserts ENOMEM). Probe the start
            // page with the BACKING-ONLY read (`read_bytes_raw`), NOT the
            // PROT_NONE-gated `read_bytes`: a legitimately-mapped region the guest
            // already mprotect'd to PROT_NONE (glibc/Go/jemalloc guard pages —
            // the dominant re-mprotect pattern) is no_access, so the gated read
            // would FALSELY report it unmapped and ENOMEM the common case.
            // `read_bytes_raw` catches an address with no backing (e.g. NULL),
            // while the explicit unmapped set catches retained arena backing
            // after munmap across the whole rounded range. Probe BEFORE changing
            // protection metadata so a hole cannot be resurrected as a VMA.
            let metadata_says_unmapped = cx
                .memory
                .protections()
                .is_some_and(|p| p.range_unmapped(address.0, len));
            let needs_backing_probe = !cx.memory.has_complete_mapping_metadata();
            if metadata_says_unmapped
                || (needs_backing_probe && cx.memory.read_bytes_raw(address.0, 1).is_err())
            {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            // A shared mapping of a F_SEAL_WRITE memfd cannot be upgraded to
            // writable (memfd_create01 check_mfd_non_writeable).
            if prot & LINUX_PROT_WRITE != 0 && this.range_is_write_sealed_shared(address.0, length) {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            let layout = this.mem.lock().layout;
            if prot_flags.contains(LinuxProtFlags::EXEC)
                && let Some(reason) =
                    this.native16k_exec_transition_rejection(cx.memory, cx.thread)
            {
                cx.reporter.record(CompatEvent::partial_syscall(
                    cx.number(),
                    "mprotect",
                    cx.raw_args(),
                    reason,
                ));
                return Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP));
            }
            if prot_flags.contains(LinuxProtFlags::WRITE | LinuxProtFlags::EXEC)
                && let Some(reason) = this.native16k_write_exec_rejection(
                    cx.memory,
                    cx.thread,
                    this.range_intersects_shared_mapping(address.0, length),
                    mmap_address_uses_alias(address.0, length, layout),
                )
            {
                cx.reporter.record(CompatEvent::partial_syscall(
                    cx.number(),
                    "mprotect",
                    cx.raw_args(),
                    reason,
                ));
                return Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP));
            }
            // Preserve file-hole identity across the permission transition.
            // Linux mprotect changes VMA permissions but never turns a page
            // wholly beyond the mapped file's map-time EOF into zero backing.
            // Snapshot before any backend edit; the protection registry keeps
            // this backing classification independent of R/W/X permission.
            let bus_faults = cx
                .memory
                .protections()
                .map(|protections| protections.bus_fault_intersections(address.0, len))
                .unwrap_or_default();

            // Make the new protection guest-VISIBLE (a violating access
            // faults during EL0 execution) by editing the stage-1/PML4
            // page tables. In the private mmap arena a failed edit is
            // fatal (eager backends must succeed there). The identity
            // image/heap/interpreter ranges are edited BEST-EFFORT: the
            // ELF loader now boots .text/.rodata read-only, so a guest
            // mprotect there (ld.so RELRO, a test unprotecting .rodata)
            // must actually flip the leaves — but a hole inside the
            // range (unmapped identity VA on x86) degrades to the
            // historical host-side-only behaviour instead of failing.
            // The shared/overlay apertures and high-VA aliases keep
            // host-side checks only (unchanged).
            if range_within(address.0, length, layout.mmap_base, layout.mmap_size) {
                if cx.memory.protect_range(address.0, len, prot).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
            } else if mprotect_range_in_identity_image(address.0, length, layout) {
                if cx.memory.protect_range(address.0, len, prot).is_err()
                    && this.page_geometry.native_profile
                        == Some(carrick_spec::NativePageProfile::Native16k)
                {
                    cx.reporter.record(CompatEvent::partial_syscall(
                        cx.number(),
                        "mprotect",
                        cx.raw_args(),
                        "native16k backend protection failure",
                    ));
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
            } else if cx.memory.supports_concurrent_exec_protection()
                && cx.memory.protect_range(address.0, len, prot).is_err()
            {
                // DSR-backed native aliases are real host mappings and keep
                // executable bytes non-executable. Apply the protection so a
                // write to an RWX page faults through generation invalidation;
                // legacy VMM aliases retain their host-side-only behavior.
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            // A backend protection call above may have made the whole VMA
            // accessible. Re-apply the physical hole before publishing the new
            // permission metadata, including on legacy shared/overlay aliases
            // whose ordinary mprotect path is host-side-only.
            for (bus_start, bus_end) in bus_faults {
                let Ok(bus_len) = usize::try_from(bus_end - bus_start) else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                if cx.memory.protect_range(bus_start, bus_len, 0).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
            }
            let prot_none = LinuxProtFlags::from_bits_truncate(prot).is_empty();
            cx.memory.set_mapping_protection(
                address.0,
                len,
                prot_none,
                !prot_none && prot & LINUX_PROT_WRITE == 0,
            );
            this.update_dynamic_mapping_prot(address.0, length, prot_flags);
            this.mark_vma_dispatch(&mut host_alias_dispatch);
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn madvise(this, cx, address: GuestPtr, length: u64, advice: u64) {
            let _host_alias_dispatch = this.begin_host_alias_dispatch();
            let page_size = this.linux_page_size();
            if !address.0.is_multiple_of(page_size) || !linux_madvise_advice_is_supported(advice) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if length == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }

            let Ok(length) = usize::try_from(length) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
            // Validity is derived from carrick's VMA metadata, NEVER by touching
            // a page: a physical probe SIGBUSes the runtime on a read-only /
            // past-EOF file page (madvise02 MADV_DONTNEED on a locked read-only
            // MAP_SHARED file) and false-ENOMEMs a mapped-but-PROT_NONE range
            // (madvise05 MADV_WILLNEED on an mprotect(PROT_NONE) anon region).
            // An unmapped hole anywhere in [address, address+length) → ENOMEM,
            // matching madvise_walk_vmas.
            let Some(raw_end) = address.0.checked_add(length as u64) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
            let Some(end) = align_up_u64(raw_end, page_size) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
            let meta = this.madvise_range_meta(address.0, end);
            if !meta.fully_mapped {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            match advice {
                LINUX_MADV_DONTNEED => {
                    // Linux can_madv_lru_vma rejects VM_LOCKED (also VM_HUGETLB /
                    // VM_PFNMAP, which carrick does not model) with EINVAL before
                    // dropping any page — derived from the locked-range table.
                    if meta.locked {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    // Drop the pages by zeroing the writable PRIVATE/anonymous
                    // backing — only such mappings get zero-fill-on-next-access.
                    // A read-only mapping must NOT be written (would SIGBUS the
                    // runtime); a MAP_SHARED mapping must NOT be written either —
                    // for a shared FILE mapping zero_backing writes straight
                    // through to the file and CORRUPTS it, and Linux
                    // MADV_DONTNEED on a shared mapping does not zero (the next
                    // access re-faults the original content from the file). In
                    // all those cases treat DONTNEED as a success no-op, matching
                    // Linux dropping clean cache pages. zero_backing writes the
                    // host backing directly (same call the MAP_FIXED/munmap-reuse
                    // scrub uses), bypassing the guest write-protection gate.
                    if meta.writable
                        && !meta.shared
                        && cx.memory.zero_backing(address.0, length).is_err()
                    {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    }
                }
                // MADV_FREE only applies to private anonymous mappings; a shared
                // mapping (file- or anon-backed) → EINVAL.
                LINUX_MADV_FREE if meta.shared => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                _ => {}
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn remap_file_pages(this, cx, addr: u64, size: u64, prot: u64, pgoff: u64, _flags: u64) {
            let _host_alias_dispatch = this.begin_host_alias_dispatch();
            if addr == 0 || size == 0 || prot != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let Some(end) = addr.checked_add(size) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            match this.note_sysv_remap_file_pages(addr, end) {
                Ok(true) => return Ok(DispatchOutcome::Returned { value: 0 }),
                Ok(false) => {}
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            }
            let shared_map = {
                this.mem
                    .lock()
                    .dynamic_maps
                    .iter()
                    .find(|map| map.sharing == ProcMapSharing::Shared && addr >= map.start && end <= map.end)
                    .cloned()
            };
            if let Some(map) = shared_map {
                let map_len = map.end.saturating_sub(map.start);
                let snapshot = {
                    let mut mem = this.mem.lock();
                    if let Some(snapshot) = mem.remap_snapshots.get(&map.start) {
                        snapshot.clone()
                    } else {
                        let Ok(map_len_usize) = usize::try_from(map_len) else {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        };
                        let Ok(bytes) = cx.memory.read_bytes(map.start, map_len_usize) else {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        };
                        mem.remap_snapshots.insert(map.start, bytes.clone());
                        bytes
                    }
                };
                let source_offset = match pgoff
                    .checked_mul(this.linux_page_size())
                    .and_then(|off| usize::try_from(off).ok())
                {
                    Some(off) => off,
                    None => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                };
                let size_usize = match usize::try_from(size) {
                    Ok(size) => size,
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                };
                let Some(source_end) = source_offset.checked_add(size_usize) else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                let Some(bytes) = snapshot.get(source_offset..source_end) else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                if cx.memory.write_bytes(addr, bytes).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // Linux rejects remap_file_pages for addresses that are not in a
            // MAP_SHARED mapping; carrick does not emulate nonlinear remapping, so
            // the valid no-op path is limited to ranges that already identify one.
            Ok(DispatchOutcome::errno(LINUX_EINVAL))
        }

        fn sys_membarrier(this, cx, command: u64, flags: u64) {
            Ok(this.membarrier(command, flags))
        }

        // io_uring (WS-H4-B1). setup allocates the rings in the guest arena and
        // returns a ring fd; the guest mmaps the rings off it (handled in the
        // mmap path); enter drains the SQ ring. register is ENOSYS for now (the
        // fixed-file/buffer optimization, not needed for correctness).
        fn io_uring_setup(this, cx, entries: u64, params_ptr: GuestPtr) {
            Ok(this.io_uring_setup_impl(cx.memory, entries as u32, params_ptr.0))
        }

        // `_min_complete` stays unused: carrick's enter is synchronous, so every
        // CQE the guest waited for is posted by the time enter returns. flags/
        // argp/argsz are now validated by the impl. (audit M4)
        fn io_uring_enter(this, cx, fd: Fd, to_submit: u64, _min_complete: u64, flags: u64, argp: GuestPtr, argsz: u64) {
            Ok(this.io_uring_enter_impl(cx.memory, fd.0, to_submit as u32, flags as u32, argp.0, argsz))
        }

        fn io_uring_register(this, cx, _fd: Fd, _opcode: u64, _arg: GuestPtr, _nr_args: u64) {
            Ok(DispatchOutcome::errno(LINUX_ENOSYS))
        }
    }
}

impl SyscallDispatcher {
    fn track_resident_fault_range(&self, address: u64, length: u64, prot: LinuxProtFlags) {
        let Some(range) = crate::vfs::GuestMemoryRange::new(
            GuestVa(address),
            GuestVa(address.saturating_add(length)),
        ) else {
            return;
        };
        let mut mem = self.mem.lock();
        locked_ranges_insert(&mut mem.resident_tracked_ranges, range);
        mem.resident_fault_ranges
            .push(ResidentFaultRange { range, prot });
    }

    /// Residency vector for `mincore`, derived from carrick's mapping metadata
    /// rather than host `mincore` (which is useless on macOS — it reports
    /// unmapped/untouched pages as resident). A page inside a post-exec VMA
    /// (`dynamic_maps`) is resident only when carrick has populated it: a file
    /// load / MAP_POPULATE marks `resident_ranges`, a fault commits it, and
    /// `mlock` without `MLOCK_ONFAULT` populates before recording the lock. A
    /// lock created with `MLOCK_ONFAULT` remains only in `locked_ranges` until
    /// each page faults, so lock accounting alone must not imply residency. A
    /// fresh, untouched anonymous mapping is therefore NOT resident (LTP
    /// mincore03), while a file-backed or populated mlocked mapping is
    /// (mincore02/04). Pages outside every post-exec VMA belong to loader-
    /// populated initial regions (ELF text/data, heap, stack, trampolines) and
    /// stay resident, matching the prior conservative default.
    fn mincore_residency_vector(
        &self,
        memory: &impl GuestMemory,
        address: u64,
        pages: u64,
        page_size: u64,
    ) -> Option<Vec<u8>> {
        let live_residency = memory.resident_pages(GuestVa(address), pages, page_size);
        let mem = self.mem.lock();
        let mut out = Vec::with_capacity(usize::try_from(pages).ok()?);
        for index in 0..pages {
            let page = address.checked_add(index.checked_mul(page_size)?)?;
            let in_dynamic = mem
                .dynamic_maps
                .iter()
                .any(|m| page >= m.start && page < m.end);
            let resident = if in_dynamic {
                ranges_contain_page(&mem.resident_ranges, page)
                    || live_residency
                        .as_ref()
                        .and_then(|vector| vector.get(index as usize))
                        .is_some_and(|byte| byte & 1 != 0)
            } else {
                true
            };
            out.push(u8::from(resident));
        }
        Some(out)
    }

    /// Record a range as populated (resident) — used when carrick eagerly loads
    /// a file-backed or MAP_POPULATE mapping's content, so a later `mincore`
    /// reports those pages resident.
    #[cfg(test)]
    pub(crate) fn dynamic_mapping_for_test(&self, start: u64) -> Option<ProcMapsEntry> {
        self.mem
            .lock()
            .dynamic_maps
            .iter()
            .find(|map| map.start == start)
            .cloned()
    }

    #[cfg(test)]
    pub(super) fn range_has_mapping_metadata_for_test(&self, start: u64, len: u64) -> bool {
        let Some(end) = start.checked_add(len) else {
            return true;
        };
        let mem = self.mem.lock();
        let overlaps = |range: &crate::vfs::GuestMemoryRange| {
            range.start().raw() < end && start < range.end().raw()
        };
        dynamic_mapping_overlaps_sorted(&mem.dynamic_maps, start, len)
            || mem.remap_snapshots.iter().any(|(snapshot_start, bytes)| {
                *snapshot_start < end && start < snapshot_start.saturating_add(bytes.len() as u64)
            })
            || mem.bus_fault_ranges.iter().any(|(range_start, range_len)| {
                *range_start < end && start < range_start.saturating_add(*range_len)
            })
            || mem.locked_ranges.iter().any(overlaps)
            || mem.resident_ranges.iter().any(overlaps)
            || mem.resident_tracked_ranges.iter().any(overlaps)
            || mem
                .resident_fault_ranges
                .iter()
                .any(|fault| overlaps(&fault.range))
            || mem.write_sealed_shared_maps.iter().any(overlaps)
            || mem
                .writable_memfd_maps
                .iter()
                .any(|(range, _)| overlaps(range))
    }

    fn mark_range_resident(&self, start: u64, len: u64) {
        if let Some(range) =
            crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start.saturating_add(len)))
        {
            locked_ranges_insert(&mut self.mem.lock().resident_ranges, range);
        }
    }

    pub(crate) fn resident_fault_plan(&self, address: u64) -> Option<ResidentFaultPlan> {
        let exclusion = self.begin_host_alias_dispatch();
        let page = page_floor(address, self.linux_page_size());
        let mem = self.mem.lock();
        let prot = mem
            .resident_fault_ranges
            .iter()
            .find(|fault| page >= fault.range.start().raw() && page < fault.range.end().raw())?
            .prot
            .bits();
        Some(ResidentFaultPlan {
            page,
            prot,
            exclusion,
        })
    }

    pub(crate) fn commit_resident_fault(&self, plan: ResidentFaultPlan) {
        if !self.owns_host_alias_dispatch(&plan.exclusion) {
            std::process::abort();
        }
        let Some(end) = plan.page.checked_add(self.linux_page_size()) else {
            return;
        };
        let Some(range) = crate::vfs::GuestMemoryRange::new(GuestVa(plan.page), GuestVa(end))
        else {
            return;
        };
        let mut mem = self.mem.lock();
        locked_ranges_insert(&mut mem.resident_ranges, range);
        remove_fault_range(&mut mem.resident_fault_ranges, range);
    }

    fn populate_resident_range(
        &self,
        memory: &mut impl GuestMemory,
        range: crate::vfs::GuestMemoryRange,
    ) -> Result<(), LinuxErrno> {
        let faults = {
            let mem = self.mem.lock();
            fault_range_intersections(&mem.resident_fault_ranges, range)
        };
        for fault in &faults {
            let len = range_len_usize(fault.range)?;
            memory
                .protect_range(fault.range.start().raw(), len, fault.prot.bits())
                .map_err(|_| LINUX_ENOMEM)?;
        }
        let mut mem = self.mem.lock();
        locked_ranges_insert(&mut mem.resident_ranges, range);
        remove_fault_range(&mut mem.resident_fault_ranges, range);
        Ok(())
    }

    fn add_locked_range(&self, range: crate::vfs::GuestMemoryRange) -> Result<(), LinuxErrno> {
        self.check_locked_range_limit(range)?;
        locked_ranges_insert(&mut self.mem.lock().locked_ranges, range);
        Ok(())
    }

    fn prepare_mmap_locked_range(
        &self,
        flags: LinuxMmapFlags,
        address: u64,
        length: u64,
    ) -> Result<Option<crate::vfs::GuestMemoryRange>, LinuxErrno> {
        if !flags.contains(LinuxMmapFlags::LOCKED) {
            return Ok(None);
        }
        let Some(range) = page_rounded_range(GuestPtr(address), length, self.linux_page_size())?
        else {
            return Ok(None);
        };
        self.check_locked_range_limit(range)?;
        Ok(Some(range))
    }

    fn prepare_fresh_mmap_locked_length(
        &self,
        flags: LinuxMmapFlags,
        length: u64,
    ) -> Result<Option<u64>, LinuxErrno> {
        if !flags.contains(LinuxMmapFlags::LOCKED) {
            return Ok(None);
        }
        let length = align_up_u64(length, self.linux_page_size()).ok_or(LINUX_ENOMEM)?;
        let creds = self.cred_snapshot();
        if creds.euid == 0 {
            return Ok(Some(length));
        }
        let limit = self.effective_resource_limit(LINUX_RLIMIT_MEMLOCK).rlim_cur;
        if limit == 0 {
            return Err(LINUX_EPERM);
        }
        let locked = locked_ranges_total(&self.mem.lock().locked_ranges);
        if locked.checked_add(length).is_none_or(|total| total > limit) {
            return Err(LINUX_ENOMEM);
        }
        Ok(Some(length))
    }

    fn check_locked_range_limit(
        &self,
        range: crate::vfs::GuestMemoryRange,
    ) -> Result<(), LinuxErrno> {
        let creds = self.cred_snapshot();
        let memlock_limit = if creds.euid == 0 {
            None
        } else {
            Some(self.effective_resource_limit(LINUX_RLIMIT_MEMLOCK).rlim_cur)
        };
        let mem = self.mem.lock();
        let mut next = mem.locked_ranges.clone();
        locked_ranges_insert(&mut next, range);
        if let Some(limit) = memlock_limit {
            if limit == 0 {
                return Err(LINUX_EPERM);
            }
            if locked_ranges_total(&next) > limit {
                return Err(LINUX_ENOMEM);
            }
        }
        Ok(())
    }

    fn commit_mmap_locked_range(
        &self,
        memory: &mut impl GuestMemory,
        range: Option<crate::vfs::GuestMemoryRange>,
    ) -> Result<(), LinuxErrno> {
        let Some(range) = range else {
            return Ok(());
        };
        self.populate_resident_range(memory, range)?;
        locked_ranges_insert(&mut self.mem.lock().locked_ranges, range);
        Ok(())
    }

    #[cfg(test)]
    #[cfg(test)]
    fn commit_eager_locked_range(&self, range: Option<crate::vfs::GuestMemoryRange>) {
        let Some(range) = range else {
            return;
        };
        let mut mem = self.mem.lock();
        locked_ranges_insert(&mut mem.resident_ranges, range);
        locked_ranges_insert(&mut mem.locked_ranges, range);
    }

    fn rollback_shared_anon_mapping(
        &self,
        memory: &mut impl GuestMemory,
        address: u64,
        guest_length: u64,
        mapped_length: usize,
    ) -> Result<(), MemoryError> {
        let Some(end) = address.checked_add(guest_length) else {
            return Err(MemoryError::HostMap(format!(
                "shared-anon rollback range overflows at 0x{address:x} for {guest_length} bytes"
            )));
        };
        let Some(range) = crate::vfs::GuestMemoryRange::new(GuestVa(address), GuestVa(end)) else {
            return Err(MemoryError::HostMap(format!(
                "shared-anon rollback range is empty at 0x{address:x}"
            )));
        };
        if let Err(first) = memory.unmap_range(address, mapped_length)
            && let Err(retry) = memory.unmap_range(address, mapped_length)
        {
            // A concurrent-exec backend maps guest bytes into this host
            // process. Returning would destroy the only rollback authority
            // while a live host mapping remains outside the VMA allocator.
            // Fail-stop so the host kernel reclaims it with the process.
            if memory.supports_concurrent_exec_protection() {
                std::process::abort();
            }
            return Err(MemoryError::HostMap(format!(
                "shared-anon rollback unmap at 0x{address:x} for {mapped_length} bytes failed: \
                 {first}; retry failed: {retry}"
            )));
        }
        memory.set_unmapped(address, mapped_length, true);
        let mut mem = self.mem.lock();
        mem.shared.free(address);
        locked_ranges_remove(&mut mem.locked_ranges, range);
        locked_ranges_remove(&mut mem.resident_ranges, range);
        locked_ranges_remove(&mut mem.resident_tracked_ranges, range);
        remove_fault_range(&mut mem.resident_fault_ranges, range);
        Ok(())
    }

    /// Roll back a freshly allocated private-arena mapping. Native direct
    /// execution cannot return while a failed publication remains host-mapped:
    /// retry once, then retain Task 51's fail-stop behavior so process teardown
    /// is the final ownership backstop.
    fn rollback_fresh_arena_mapping(
        &self,
        memory: &mut impl GuestMemory,
        address: u64,
        len: u64,
    ) -> Result<(), MemoryError> {
        let len_usize = usize::try_from(len).map_err(|_| {
            MemoryError::HostMap(format!("arena rollback length does not fit usize: {len}"))
        })?;
        if let Err(first) = memory.unmap_range(address, len_usize)
            && let Err(retry) = memory.unmap_range(address, len_usize)
        {
            if memory.supports_concurrent_exec_protection() {
                std::process::abort();
            }
            return Err(MemoryError::HostMap(format!(
                "arena rollback unmap at 0x{address:x} for {len} bytes failed: \
                 {first}; retry failed: {retry}"
            )));
        }
        mark_range_unmapped(memory, address, len_usize);
        let mut mem = self.mem.lock();
        if address.checked_add(len) == Some(mem.mmap_next) {
            mem.mmap_next = address;
        } else {
            free_regions_insert(&mut mem.free_regions, address, len);
        }
        Ok(())
    }

    fn remove_locked_range(&self, range: crate::vfs::GuestMemoryRange) {
        locked_ranges_remove(&mut self.mem.lock().locked_ranges, range);
    }

    fn lock_current_mappings(
        &self,
        memory: &mut impl GuestMemory,
        onfault: bool,
    ) -> Result<(), LinuxErrno> {
        let mem = self.mem.lock();
        let mut ranges = mem.locked_ranges.clone();
        if let Some(regions) = &mem.address_space_regions {
            for region in regions {
                if let Some(range) =
                    crate::vfs::GuestMemoryRange::new(GuestVa(region.start), GuestVa(region.end))
                {
                    locked_ranges_insert(&mut ranges, range);
                }
            }
        }
        for region in &mem.dynamic_maps {
            if let Some(range) =
                crate::vfs::GuestMemoryRange::new(GuestVa(region.start), GuestVa(region.end))
            {
                locked_ranges_insert(&mut ranges, range);
            }
        }
        drop(mem);

        let creds = self.cred_snapshot();
        if creds.euid != 0 {
            let limit = self.effective_resource_limit(LINUX_RLIMIT_MEMLOCK).rlim_cur;
            if limit == 0 {
                return Err(LINUX_EPERM);
            }
            if locked_ranges_total(&ranges) > limit {
                return Err(LINUX_ENOMEM);
            }
        }
        if !onfault {
            for range in &ranges {
                self.populate_resident_range(memory, *range)?;
            }
        }
        self.mem.lock().locked_ranges = ranges;
        Ok(())
    }

    pub(crate) fn mem_after_fork_child(&self) {
        let mut mem = self.mem.lock();
        mem.locked_ranges.clear();
        // The child does not inherit the parent's writable-memfd-map bookkeeping
        // (the descriptions it references may be closed in the child); a stale
        // entry would spuriously EBUSY a child's F_ADD_SEALS.
        mem.writable_memfd_maps.clear();
    }
}

fn linux_madvise_advice_is_supported(advice: u64) -> bool {
    matches!(
        advice,
        LINUX_MADV_NORMAL
            | LINUX_MADV_RANDOM
            | LINUX_MADV_SEQUENTIAL
            | LINUX_MADV_WILLNEED
            | LINUX_MADV_DONTNEED
            | LINUX_MADV_FREE
            | LINUX_MADV_DONTFORK
            | LINUX_MADV_DOFORK
            // THP hints: advisory, accepted as a success no-op (see the abi
            // constants). carrick can't promote to huge pages, but neither must
            // it reject the hint — real Linux with THP built in returns 0.
            | LINUX_MADV_HUGEPAGE
            | LINUX_MADV_NOHUGEPAGE
            | LINUX_MADV_COLLAPSE
    )
}

fn range_within(address: u64, length: u64, base: u64, size: u64) -> bool {
    let Some(end) = address.checked_add(length) else {
        return false;
    };
    let Some(limit) = base.checked_add(size) else {
        return false;
    };
    address >= base && end <= limit
}

/// Identity-mapped guest ranges where an `mprotect` edits the live page tables
/// BEST-EFFORT (see the mprotect handler): the low image space (main ELF, up to
/// but excluding the kernel region — its first 2 MiB block is EL1-only and must
/// never be rewritten with user leaf flags), the brk heap, the dynamic
/// interpreter window, and the anon `MAP_SHARED` aperture (whose mappings now
/// boot with their REQUESTED protection, so a later mprotect must reach the
/// leaves too; the stage-1 editor flips protection IN PLACE, preserving a
/// `repoint_private` overlay leaf's output address). The ELF loader boots
/// `.text`/`.rodata` read-only, so a guest `mprotect` on these ranges (ld.so
/// RELRO; a handler unprotecting a faulted page) has to reach the real leaves —
/// host-side-only tracking would leave the guest's own stores enforcing the OLD
/// protection.
fn mprotect_range_in_identity_image(address: u64, length: u64, layout: MemoryLayout) -> bool {
    use crate::memory::{
        LINUX_INTERPRETER_BASE as INTERP, LINUX_KERNEL_REGION_BASE as KERNEL,
        LINUX_NULL_GUARD_END as GUARD_END, LINUX_SHARED_FILE_BASE as SHARED,
    };
    range_within(address, length, GUARD_END, KERNEL - GUARD_END)
        || range_within(address, length, layout.heap_base, layout.heap_size)
        || range_within(address, length, INTERP, SHARED - INTERP)
        || range_within(
            address,
            length,
            SHARED,
            crate::memory::LINUX_SHARED_FILE_SIZE,
        )
}

fn mmap_address_uses_alias(address: u64, length: u64, layout: MemoryLayout) -> bool {
    let Some(end) = address.checked_add(length) else {
        return false;
    };
    if end > (1u64 << 48) {
        return false;
    }
    if range_within(address, length, layout.mmap_base, layout.mmap_size) {
        return false;
    }
    if crate::memory::is_high_va(address) {
        return true;
    }

    let alias_low_base =
        crate::memory::LINUX_SHARED_FILE_BASE + crate::memory::LINUX_SHARED_FILE_SIZE;
    let stack_base = crate::memory::LINUX_STACK_TOP - crate::memory::LINUX_STACK_SIZE;
    range_within(address, length, alias_low_base, stack_base - alias_low_base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_abi::LINUX_PROT_EXEC;
    use crate::memory::{LINUX_HEAP_BASE, LINUX_MMAP_BASE};
    use std::cell::Cell;

    struct CountingMmapMemory {
        base: u64,
        bytes: Vec<u8>,
        write_calls: Cell<usize>,
        write_bytes_total: Cell<usize>,
        zero_backing_calls: Cell<usize>,
        protect_calls: Cell<usize>,
    }

    #[test]
    fn backend_mmap_arena_is_not_classified_as_an_alias() {
        let native_layout = MemoryLayout {
            heap_base: 0x8_0000_0000,
            heap_size: 128 * 1024 * 1024,
            mmap_base: 0xa0_0000_0000,
            mmap_size: 32 * 1024 * 1024 * 1024,
        };
        let address = native_layout.mmap_base;

        assert!(!mmap_address_uses_alias(
            address,
            LINUX_PAGE_SIZE,
            native_layout,
        ));
        assert!(mmap_address_uses_alias(
            address,
            LINUX_PAGE_SIZE,
            MemoryLayout::hvf_default(),
        ));
    }

    impl CountingMmapMemory {
        fn new(base: u64, len: usize) -> Self {
            Self {
                base,
                bytes: vec![0u8; len],
                write_calls: Cell::new(0),
                write_bytes_total: Cell::new(0),
                zero_backing_calls: Cell::new(0),
                protect_calls: Cell::new(0),
            }
        }

        fn range_offset(&self, address: u64, length: usize) -> Result<usize, MemoryError> {
            let offset = address
                .checked_sub(self.base)
                .ok_or(MemoryError::OutOfBounds { address, length })?;
            let offset = usize::try_from(offset)
                .map_err(|_| MemoryError::OutOfBounds { address, length })?;
            let end = offset
                .checked_add(length)
                .ok_or(MemoryError::OutOfBounds { address, length })?;
            if end > self.bytes.len() {
                return Err(MemoryError::OutOfBounds { address, length });
            }
            Ok(offset)
        }
    }

    impl GuestMemory for CountingMmapMemory {
        fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
            let offset = self.range_offset(address, length)?;
            Ok(self.bytes[offset..offset + length].to_vec())
        }

        fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            let offset = self.range_offset(address, bytes.len())?;
            self.write_calls.set(self.write_calls.get() + 1);
            self.write_bytes_total
                .set(self.write_bytes_total.get() + bytes.len());
            self.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
            Ok(())
        }

        fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
            let offset = self.range_offset(address, len)?;
            self.zero_backing_calls
                .set(self.zero_backing_calls.get() + 1);
            self.bytes[offset..offset + len].fill(0);
            Ok(())
        }

        fn protect_range(
            &mut self,
            _address: u64,
            _len: usize,
            _prot: u64,
        ) -> Result<(), MemoryError> {
            self.protect_calls.set(self.protect_calls.get() + 1);
            Ok(())
        }
    }

    struct ConcurrentExecMemory(CountingMmapMemory);

    impl GuestMemory for ConcurrentExecMemory {
        fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
            self.0.read_bytes_raw(address, length)
        }

        fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            self.0.write_bytes_raw(address, bytes)
        }

        fn protect_range(
            &mut self,
            address: u64,
            len: usize,
            prot: u64,
        ) -> Result<(), MemoryError> {
            self.0.protect_range(address, len, prot)
        }

        fn supports_concurrent_exec_protection(&self) -> bool {
            true
        }
    }

    struct ProtectionTrackingMemory {
        inner: CountingMmapMemory,
        protections: carrick_guest_mem::protections::MemoryProtections,
        repoint_calls: usize,
        repoint_payload: Vec<u8>,
        repoint_observed_shared: Vec<bool>,
        restored_shared_identity: Vec<(u64, usize)>,
        fail_repoint: bool,
        fail_repoint_indeterminate: bool,
        fail_protect: bool,
    }

    struct FailingProtectMemory {
        inner: CountingMmapMemory,
    }

    struct DeferredSetterFailureMemory {
        inner: CountingMmapMemory,
        pending_failure: bool,
        protect_calls: usize,
        unmap_calls: usize,
        unmap_failures_remaining: usize,
        concurrent_exec: bool,
        unmapped: carrick_guest_mem::protections::MemoryProtections,
    }

    impl DeferredSetterFailureMemory {
        fn new(base: u64, len: usize) -> Self {
            Self {
                inner: CountingMmapMemory::new(base, len),
                pending_failure: false,
                protect_calls: 0,
                unmap_calls: 0,
                unmap_failures_remaining: 0,
                concurrent_exec: true,
                unmapped: carrick_guest_mem::protections::MemoryProtections::default(),
            }
        }

        fn fail_unmaps(mut self, count: usize) -> Self {
            self.unmap_failures_remaining = count;
            self
        }

        fn demand_paged(mut self) -> Self {
            self.concurrent_exec = false;
            self
        }
    }

    impl GuestMemory for DeferredSetterFailureMemory {
        fn protections(&self) -> Option<&carrick_guest_mem::protections::MemoryProtections> {
            Some(&self.unmapped)
        }

        fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
            self.inner.read_bytes_raw(address, length)
        }

        fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            self.inner.write_bytes_raw(address, bytes)
        }

        fn set_mapping_protection(
            &mut self,
            _address: u64,
            _len: usize,
            _no_access: bool,
            _no_write: bool,
        ) {
            self.pending_failure = true;
        }

        fn protect_range(
            &mut self,
            _address: u64,
            _len: usize,
            _prot: u64,
        ) -> Result<(), MemoryError> {
            self.protect_calls += 1;
            if std::mem::take(&mut self.pending_failure) {
                Err(MemoryError::HostMap(
                    "deferred eager mapping failure".to_string(),
                ))
            } else {
                Ok(())
            }
        }

        fn unmap_range(&mut self, _address: u64, _len: usize) -> Result<(), MemoryError> {
            self.unmap_calls += 1;
            if self.unmap_failures_remaining != 0 {
                self.unmap_failures_remaining -= 1;
                return Err(MemoryError::HostMap(
                    "injected persistent unmap failure".into(),
                ));
            }
            Ok(())
        }

        fn set_unmapped(&mut self, address: u64, len: usize, unmapped: bool) {
            self.unmapped.set_unmapped(address, len, unmapped);
        }

        fn supports_concurrent_exec_protection(&self) -> bool {
            self.concurrent_exec
        }
    }

    impl GuestMemory for FailingProtectMemory {
        fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
            self.inner.read_bytes_raw(address, length)
        }

        fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            self.inner.write_bytes_raw(address, bytes)
        }

        fn protect_range(
            &mut self,
            _address: u64,
            _len: usize,
            _prot: u64,
        ) -> Result<(), MemoryError> {
            Err(MemoryError::Unsupported)
        }
    }

    impl ProtectionTrackingMemory {
        fn new(base: u64, len: usize) -> Self {
            Self {
                inner: CountingMmapMemory::new(base, len),
                protections: carrick_guest_mem::protections::MemoryProtections::default(),
                repoint_calls: 0,
                repoint_payload: Vec::new(),
                repoint_observed_shared: Vec::new(),
                restored_shared_identity: Vec::new(),
                fail_repoint: false,
                fail_repoint_indeterminate: false,
                fail_protect: false,
            }
        }
    }

    impl GuestMemory for ProtectionTrackingMemory {
        fn protections(&self) -> Option<&carrick_guest_mem::protections::MemoryProtections> {
            Some(&self.protections)
        }

        fn has_complete_mapping_metadata(&self) -> bool {
            true
        }

        fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
            self.inner.read_bytes_raw(address, length)
        }

        fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            self.inner.write_bytes_raw(address, bytes)
        }

        fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
            self.inner.zero_backing(address, len)
        }

        fn restore_shared_identity(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
            self.restored_shared_identity.push((address, len));
            Ok(())
        }

        fn repoint_private(
            &mut self,
            address: u64,
            _overlay_ipa: u64,
            len: usize,
            content: &[u8],
        ) -> Result<(), carrick_guest_mem::RepointPrivateError> {
            if content.len() != len {
                return Err(carrick_guest_mem::RepointPrivateError::clean(
                    MemoryError::OutOfBounds {
                        address,
                        length: content.len(),
                    },
                ));
            }
            let offset = self
                .inner
                .range_offset(address, len)
                .map_err(carrick_guest_mem::RepointPrivateError::clean)?;
            self.repoint_observed_shared
                .push(self.protections.range_mutable_shared_backing(address, len));
            self.repoint_calls += 1;
            if self.fail_repoint {
                return Err(carrick_guest_mem::RepointPrivateError::clean(
                    MemoryError::HostMap("injected private repoint failure".into()),
                ));
            }
            if self.fail_repoint_indeterminate {
                return Err(carrick_guest_mem::RepointPrivateError::indeterminate(
                    MemoryError::HostMap("injected post-publication repoint failure".into()),
                ));
            }
            self.repoint_payload.clear();
            self.repoint_payload.extend_from_slice(content);
            self.inner.bytes[offset..offset + len].copy_from_slice(content);
            Ok(())
        }

        fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
            self.protections.set_no_access(address, len, no_access);
        }

        fn set_no_write(&mut self, address: u64, len: usize, no_write: bool) {
            self.protections.set_no_write(address, len, no_write);
        }

        fn set_unmapped(&mut self, address: u64, len: usize, unmapped: bool) {
            self.protections.set_unmapped(address, len, unmapped);
        }

        fn set_mapping_protection(
            &mut self,
            address: u64,
            len: usize,
            no_access: bool,
            no_write: bool,
        ) {
            self.protections
                .set_mapping_protection(address, len, no_access, no_write);
        }

        fn set_mapping_sharing(
            &mut self,
            address: u64,
            len: usize,
            sharing: carrick_guest_mem::MappingSharing,
        ) {
            self.protections.set_mapping_sharing(address, len, sharing);
        }

        fn set_mapping_protection_and_sharing(
            &mut self,
            address: u64,
            len: usize,
            no_access: bool,
            no_write: bool,
            sharing: carrick_guest_mem::MappingSharing,
        ) {
            self.protections
                .set_mapping_protection_and_sharing(address, len, no_access, no_write, sharing);
        }

        fn protect_range(
            &mut self,
            address: u64,
            len: usize,
            prot: u64,
        ) -> Result<(), MemoryError> {
            if self.fail_protect {
                return Err(MemoryError::HostMap(
                    "injected private protection failure".into(),
                ));
            }
            self.protections
                .set_executable(address, len, prot & LINUX_PROT_EXEC != 0);
            self.inner.protect_range(address, len, prot)
        }
    }

    fn returned(outcome: DispatchOutcome) -> i64 {
        match outcome {
            DispatchOutcome::Returned { value } => value,
            other => panic!("expected Returned, got {other:?}"),
        }
    }

    fn native16k_dispatcher() -> SyscallDispatcher {
        SyscallDispatcher::with_page_geometry(crate::page_profile::PageGeometry {
            host_page_size: 16 * 1024,
            linux_page_size: 16 * 1024,
            native_profile: Some(carrick_spec::NativePageProfile::Native16k),
        })
    }

    fn threaded_memory_call(
        dispatcher: &SyscallDispatcher,
        memory: &mut impl GuestMemory,
        registry: &crate::thread::ThreadRegistry,
        reporter: &CompatReporter,
        request: SyscallRequest,
    ) -> DispatchOutcome {
        dispatcher
            .dispatch_threaded(
                &dispatcher.capture_one_task_context().unwrap(),
                request,
                memory,
                reporter,
                registry.main_tid(),
                registry,
                &crate::thread::FutexTable::new(),
            )
            .expect("threaded memory dispatch")
    }

    fn assert_partial_reason(reporter: &CompatReporter, syscall: &str, needle: &str) {
        let report = reporter.snapshot();
        assert!(
            report
                .partial_syscalls
                .iter()
                .any(|entry| entry.name == syscall && entry.reason.contains(needle)),
            "missing {syscall} partial-syscall reason containing {needle:?}: {report:?}"
        );
    }

    fn assert_operation_waits_for_host_alias_idle<F>(label: &'static str, operation: F)
    where
        F: FnOnce(std::sync::Arc<SyscallDispatcher>) + Send + 'static,
    {
        let dispatcher = std::sync::Arc::new(SyscallDispatcher::new());
        let guard = dispatcher.begin_host_alias_dispatch();
        let transaction = guard.publish(HostAliasCommit::mmap(HostAliasMmapCommit {
            start: crate::memory::LINUX_HIGH_VA_THRESHOLD,
            len: LINUX_PAGE_SIZE,
            prot: LinuxProtFlags::READ,
            sharing: ProcMapSharing::Private,
            path: String::new(),
            locked: None,
            resident: false,
            bus_fault: None,
            write_sealed_shared: false,
            writable_memfd: None,
        }));
        let install = transaction
            .claim()
            .expect("claim pending host alias install");
        let sibling = std::sync::Arc::clone(&dispatcher);
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            operation(sibling);
            entered_tx.send(()).expect("report blocked operation");
        });
        assert!(
            entered_rx
                .recv_timeout(std::time::Duration::from_millis(25))
                .is_err(),
            "{label} raced an installing host alias"
        );
        drop(install);
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("operation admitted after abort");
        thread.join().expect("join blocked operation thread");
    }

    #[test]
    fn native16k_rejects_shared_write_exec_mmap() {
        const SYS_MMAP: u64 = 222;
        const PAGE_SIZE: u64 = 16 * 1024;

        let dispatcher = native16k_dispatcher();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1000));
        let reporter = CompatReporter::default();
        let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, PAGE_SIZE as usize);
        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    PAGE_SIZE,
                    LINUX_PROT_READ | LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC,
                    LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        );

        assert_eq!(outcome, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
        assert_partial_reason(&reporter, "mmap", "shared write-exec");
    }

    #[test]
    fn shared_anon_deferred_setter_failure_rolls_back_before_commit() {
        const SYS_MMAP: u64 = 222;
        const LENGTH: u64 = 4096;
        const MAPPED_LENGTH: usize = crate::trap::HVF_PAGE_SIZE as usize;

        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1050));
        let reporter = CompatReporter::default();
        let mut memory =
            DeferredSetterFailureMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, MAPPED_LENGTH);
        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        );

        assert_eq!(outcome, DispatchOutcome::errno(LINUX_ENOMEM));
        assert_eq!(memory.protect_calls, 1, "setter failure consumed once");
        assert_eq!(memory.unmap_calls, 1, "candidate backing rolled back");
        assert!(
            memory
                .unmapped
                .range_unmapped(crate::memory::LINUX_SHARED_FILE_BASE, MAPPED_LENGTH)
        );
        let mem = dispatcher.mem.lock();
        assert!(mem.shared.live().is_empty(), "allocation must not commit");
        assert!(mem.dynamic_maps.is_empty(), "VMA metadata must not commit");
    }

    #[test]
    fn mmap_publishes_shared_rx_and_private_fixed_replacement() {
        const SYS_MMAP: u64 = 222;
        const LENGTH: u64 = 4096;
        const MAPPED_LENGTH: usize = crate::trap::HVF_PAGE_SIZE as usize;

        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1060));
        let reporter = CompatReporter::default();
        let mut memory =
            ProtectionTrackingMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, MAPPED_LENGTH);
        let mapped = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_EXEC,
                    LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        assert!(memory.protections.range_executable(mapped, LENGTH as usize));
        assert!(
            memory
                .protections
                .range_mutable_shared_backing(mapped, LENGTH as usize)
        );
        assert!(
            memory
                .protections
                .range_translation_requires_ephemeral(mapped, LENGTH as usize)
        );

        let replaced = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    mapped,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_EXEC,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        assert_eq!(replaced, mapped);
        assert!(memory.protections.range_executable(mapped, LENGTH as usize));
        assert!(
            !memory
                .protections
                .range_mutable_shared_backing(mapped, LENGTH as usize)
        );
        assert!(
            !memory
                .protections
                .range_translation_requires_ephemeral(mapped, LENGTH as usize)
        );
    }

    #[test]
    fn file_private_fixed_shared_aperture_repoints_snapshot_and_publishes_map_time_bus_tail() {
        const SYS_MMAP: u64 = 222;
        const SYS_MPROTECT: u64 = 226;
        const LENGTH: u64 = 3 * LINUX_PAGE_SIZE;
        const MAPPED_LENGTH: usize = crate::trap::HVF_PAGE_SIZE as usize;
        const FD: i32 = 9;

        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1061));
        let reporter = CompatReporter::default();
        let mut memory =
            ProtectionTrackingMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, MAPPED_LENGTH);
        let mapped = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_EXEC,
                    LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        assert!(
            memory
                .protections
                .range_mutable_shared_backing(mapped, LENGTH as usize)
        );

        let mut file_bytes = vec![0x7d; LINUX_PAGE_SIZE as usize];
        file_bytes.extend_from_slice(&[0x90, 0xc3, 0x4a]);
        dispatcher.io.open_files.write().insert(
            FD,
            OpenFile::new(
                std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::SyntheticFile {
                    base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDONLY),
                    path: "private-replacement".into(),
                    contents: file_bytes,
                    offset: 0,
                })),
                0,
            ),
        );

        let replaced = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    mapped,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_EXEC,
                    LINUX_MAP_PRIVATE | LINUX_MAP_FIXED,
                    FD as u64,
                    LINUX_PAGE_SIZE,
                ]),
            ),
        )) as u64;

        assert_eq!(replaced, mapped);
        assert_eq!(memory.repoint_calls, 1);
        assert_eq!(memory.repoint_observed_shared, [true]);
        assert_eq!(memory.repoint_payload.len(), LENGTH as usize);
        assert_eq!(&memory.repoint_payload[..3], &[0x90, 0xc3, 0x4a]);
        assert!(
            memory.repoint_payload[3..LINUX_PAGE_SIZE as usize]
                .iter()
                .all(|byte| *byte == 0),
            "the remainder of the partially backed last page is readable zero-fill"
        );
        assert!(
            memory.repoint_payload[LINUX_PAGE_SIZE as usize..]
                .iter()
                .all(|byte| *byte == 0),
            "materialization bytes stay zeroed even though full pages past EOF fault"
        );
        assert_eq!(
            memory
                .read_bytes(mapped, 3)
                .expect("within-file private snapshot bytes"),
            vec![0x90, 0xc3, 0x4a]
        );
        assert_eq!(
            memory
                .read_bytes(mapped + LINUX_PAGE_SIZE - 1, 1)
                .expect("partial-page EOF zero tail"),
            vec![0]
        );
        assert!(
            memory.read_bytes(mapped + LINUX_PAGE_SIZE, 1).is_err(),
            "the first page wholly beyond map-time EOF is inaccessible"
        );
        assert!(
            !memory.protections.range_bus_fault(mapped, 1)
                && memory
                    .protections
                    .range_bus_fault(mapped + LINUX_PAGE_SIZE, 1)
        );
        assert!(dispatcher.mmap_fault_is_sigbus(mapped + LINUX_PAGE_SIZE));
        assert!(!dispatcher.mmap_fault_is_sigbus(mapped + LINUX_PAGE_SIZE - 1));

        assert_eq!(
            returned(threaded_memory_call(
                &dispatcher,
                &mut memory,
                &registry,
                &reporter,
                SyscallRequest::new(
                    SYS_MPROTECT,
                    SyscallArgs([mapped, LENGTH, LINUX_PROT_READ | LINUX_PROT_EXEC, 0, 0, 0,]),
                ),
            )),
            0
        );
        assert!(
            memory.read_bytes(mapped + LINUX_PAGE_SIZE - 1, 1).is_ok(),
            "mprotect preserves the readable partial-page zero tail"
        );
        assert!(
            memory.read_bytes(mapped + LINUX_PAGE_SIZE, 1).is_err(),
            "mprotect cannot reopen a full page beyond map-time EOF"
        );
        assert!(
            memory
                .protections
                .range_bus_fault(mapped + LINUX_PAGE_SIZE, 1)
                && memory
                    .protections
                    .range_no_access(mapped + LINUX_PAGE_SIZE, 1)
        );
        assert_eq!(
            memory.inner.write_calls.get(),
            0,
            "file payload must not be copied through the still-shared VA"
        );
        assert!(
            memory
                .protections
                .range_executable(mapped, LINUX_PAGE_SIZE as usize),
            "the partially backed page remains executable"
        );
        assert!(
            !memory
                .protections
                .range_executable(mapped + LINUX_PAGE_SIZE, 1),
            "the BUS_ADRERR tail cannot remain executable"
        );
        assert!(
            !memory
                .protections
                .range_mutable_shared_backing(mapped, LENGTH as usize)
        );
        assert!(
            !memory
                .protections
                .range_translation_requires_ephemeral(mapped, LENGTH as usize)
        );
        let replacement = dispatcher
            .dynamic_mapping_for_test(mapped)
            .expect("private fixed replacement VMA");
        assert_eq!(replacement.sharing, ProcMapSharing::Private);
        assert!(replacement.execute);
        assert!(dispatcher.mem.lock().resident_ranges.iter().any(|range| {
            range.start().raw() == mapped && range.end().raw() == mapped + LENGTH
        }));
    }

    #[test]
    fn private_file_snapshot_computes_identical_bus_tail_for_memfd_synthetic_and_host_sources() {
        use std::os::fd::{AsRawFd, IntoRawFd};

        const LENGTH: usize = 3 * LINUX_PAGE_SIZE as usize;
        const FILE_LENGTH: usize = LINUX_PAGE_SIZE as usize + 3;
        let dispatcher = SyscallDispatcher::new();
        let payload = {
            let mut bytes = vec![0x7d; LINUX_PAGE_SIZE as usize];
            bytes.extend_from_slice(&[0x90, 0xc3, 0x4a]);
            bytes
        };
        let metadata = RootFsMetadata {
            path: std::path::PathBuf::from("/memfd:private-eof"),
            kind: RootFsEntryKind::File,
            mode: 0o600,
            size: FILE_LENGTH,
        };
        let mut memfd_base = OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDWR);
        memfd_base.set_seals(Some(0));
        dispatcher.io.open_files.write().insert(
            20,
            OpenFile::new(
                std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::File {
                    base: memfd_base,
                    path: "/memfd:private-eof".into(),
                    metadata: metadata.clone(),
                    contents: FileContents::dense(payload.clone()),
                    offset: 0,
                    writable: true,
                })),
                0,
            ),
        );
        dispatcher.io.open_files.write().insert(
            21,
            OpenFile::new(
                std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::SyntheticFile {
                    base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDONLY),
                    path: "/synthetic-private-eof".into(),
                    contents: payload.clone(),
                    offset: 0,
                })),
                0,
            ),
        );
        let host_file = tempfile::tempfile().expect("temporary host private-map source");
        assert_eq!(
            unsafe {
                libc::pwrite(
                    host_file.as_raw_fd(),
                    payload.as_ptr().cast(),
                    payload.len(),
                    0,
                )
            },
            payload.len() as isize
        );
        dispatcher.io.open_files.write().insert(
            22,
            OpenFile::new(
                std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::HostFile {
                    base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDONLY),
                    host_fd: HostFdRef::new(host_file.into_raw_fd()),
                    metadata,
                    writable: false,
                })),
                0,
            ),
        );

        for (fd, source) in [(20, "memfd"), (21, "synthetic"), (22, "host")] {
            let snapshot = dispatcher
                .snapshot_private_mmap_file(Fd(fd), LINUX_PAGE_SIZE, LENGTH)
                .unwrap_or_else(|error| panic!("snapshot {source} source: {error:?}"));
            assert_eq!(
                snapshot.bus_fault_offset,
                Some(LINUX_PAGE_SIZE),
                "{source} first full page beyond EOF"
            );
            assert_eq!(&snapshot.bytes[..3], &[0x90, 0xc3, 0x4a]);
            assert!(
                snapshot.bytes[3..LINUX_PAGE_SIZE as usize]
                    .iter()
                    .all(|byte| *byte == 0),
                "{source} partial-page tail must be zero-filled"
            );
        }
    }

    #[test]
    fn shared_mmap_refreshes_an_independently_opened_vfs_inode() {
        const SYS_PWRITE64: u64 = 68;
        const SYS_MMAP: u64 = 222;
        const FILE_LEN: u64 = 16 * 1024;
        const WRITER_FD: i32 = 23;
        const MAPPER_FD: i32 = 24;
        const PATH: &str = "/telemetry.count";

        let dispatcher = native16k_dispatcher();
        dispatcher
            .fs
            .rootfs_vfs
            .overlay
            .set_file_contents(PATH, Vec::new())
            .expect("create shared overlay inode");
        let install_snapshot = |fd| {
            dispatcher.io.open_files.write().insert(
                fd,
                OpenFile::new(
                    std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::File {
                        base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDWR),
                        path: PATH.into(),
                        metadata: RootFsMetadata {
                            path: PATH.into(),
                            kind: RootFsEntryKind::File,
                            mode: 0o600,
                            size: 0,
                        },
                        contents: FileContents::dense(Vec::new()),
                        offset: 0,
                        writable: true,
                    })),
                    0,
                ),
            );
        };
        install_snapshot(WRITER_FD);
        install_snapshot(MAPPER_FD);

        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1299));
        let reporter = CompatReporter::default();
        let mut memory =
            CountingMmapMemory::new(crate::memory::LINUX_MMAP_BASE, 4 * FILE_LEN as usize);
        let header_address = crate::memory::LINUX_MMAP_BASE + 2 * FILE_LEN;
        memory
            .write_bytes(header_address, b"telemetry-header")
            .expect("stage header write payload");
        memory
            .write_bytes(header_address + 32, &[0; 4])
            .expect("stage extension write payload");

        assert_eq!(
            returned(threaded_memory_call(
                &dispatcher,
                &mut memory,
                &registry,
                &reporter,
                SyscallRequest::new(
                    SYS_PWRITE64,
                    SyscallArgs([
                        WRITER_FD as u64,
                        header_address,
                        b"telemetry-header".len() as u64,
                        0,
                        0,
                        0,
                    ]),
                ),
            )),
            b"telemetry-header".len() as i64
        );
        assert_eq!(
            returned(threaded_memory_call(
                &dispatcher,
                &mut memory,
                &registry,
                &reporter,
                SyscallRequest::new(
                    SYS_PWRITE64,
                    SyscallArgs([WRITER_FD as u64, header_address + 32, 4, FILE_LEN - 4, 0, 0,]),
                ),
            )),
            4
        );
        let mapper = dispatcher.open_file(MAPPER_FD).expect("mapper fd");
        assert_eq!(
            match &*mapper.description.read() {
                OpenDescription::File { contents, .. } => contents.len(),
                other => panic!("expected File, got {other:?}"),
            },
            0,
            "the independently opened description deliberately retains its stale snapshot"
        );

        let mapped = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    FILE_LEN,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_SHARED,
                    MAPPER_FD as u64,
                    0,
                ]),
            ),
        )) as u64;

        assert_eq!(
            memory
                .read_bytes(mapped, b"telemetry-header".len())
                .expect("mapped header"),
            b"telemetry-header"
        );
        assert!(
            !dispatcher.mmap_fault_is_sigbus(mapped),
            "a live 16 KiB inode must not inherit the stale zero-length description's BUS range"
        );
    }

    /// Mock backend for the Move-3 E1 lowering: records every
    /// `map_private_file_backed` offer and answers with a configured verdict,
    /// so the dispatch-side eligibility and fallback are testable without a
    /// real identity host mapping.
    struct FileBackedLoweringMemory {
        inner: CountingMmapMemory,
        accept: bool,
        offers: std::cell::RefCell<Vec<(u64, usize, u64)>>,
    }

    impl FileBackedLoweringMemory {
        fn new(base: u64, len: usize, accept: bool) -> Self {
            Self {
                inner: CountingMmapMemory::new(base, len),
                accept,
                offers: std::cell::RefCell::new(Vec::new()),
            }
        }
    }

    impl GuestMemory for FileBackedLoweringMemory {
        fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
            self.inner.read_bytes_raw(address, length)
        }

        fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            self.inner.write_bytes_raw(address, bytes)
        }

        fn protect_range(
            &mut self,
            address: u64,
            len: usize,
            prot: u64,
        ) -> Result<(), MemoryError> {
            self.inner.protect_range(address, len, prot)
        }

        fn map_private_file_backed(
            &mut self,
            address: u64,
            len: usize,
            _host_fd: std::os::fd::BorrowedFd<'_>,
            offset: u64,
        ) -> Result<bool, MemoryError> {
            self.offers.borrow_mut().push((address, len, offset));
            Ok(self.accept)
        }
    }

    /// Install a HostFile-backed guest fd whose backing file holds `payload`,
    /// returning the guest fd number.
    fn install_host_file_fd(dispatcher: &SyscallDispatcher, fd: i32, payload: &[u8]) {
        use std::os::fd::{AsRawFd, IntoRawFd};
        let host_file = tempfile::tempfile().expect("temporary host private-map source");
        assert_eq!(
            unsafe {
                libc::pwrite(
                    host_file.as_raw_fd(),
                    payload.as_ptr().cast(),
                    payload.len(),
                    0,
                )
            },
            payload.len() as isize
        );
        dispatcher.io.open_files.write().insert(
            fd,
            OpenFile::new(
                std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::HostFile {
                    base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDONLY),
                    host_fd: HostFdRef::new(host_file.into_raw_fd()),
                    metadata: RootFsMetadata {
                        path: std::path::PathBuf::from("/host-private-map"),
                        kind: RootFsEntryKind::File,
                        mode: 0o644,
                        size: payload.len(),
                    },
                    writable: false,
                })),
                0,
            ),
        );
    }

    #[test]
    fn mmap_private_hostfile_lowers_file_backed_and_publishes_bus_tail() {
        const SYS_MMAP: u64 = 222;
        const PAGE_SIZE: u64 = 16 * 1024;
        const LENGTH: u64 = 3 * PAGE_SIZE;

        let dispatcher = native16k_dispatcher();
        // File backs one full page plus 3 bytes: page 1 is the partially
        // backed page (zero tail), page 2 is wholly beyond EOF -> BUS.
        install_host_file_fd(&dispatcher, 30, &vec![0x7d; PAGE_SIZE as usize + 3]);
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1300));
        let reporter = CompatReporter::default();
        let mut memory =
            FileBackedLoweringMemory::new(LINUX_MMAP_BASE, 4 * PAGE_SIZE as usize, true);
        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LENGTH,
                    LINUX_PROT_READ,
                    crate::linux_abi::LINUX_MAP_PRIVATE,
                    30,
                    0,
                ]),
            ),
        );
        let DispatchOutcome::Returned { value } = outcome else {
            panic!("private host-file mmap must succeed, got {outcome:?}");
        };
        let address = value as u64;
        assert_eq!(
            memory.offers.borrow().as_slice(),
            &[(address, LENGTH as usize, 0)],
            "the backend must be offered exactly the mapped range"
        );
        assert_eq!(
            memory.inner.write_calls.get(),
            0,
            "a lowered mapping must not be eagerly materialized"
        );
        // Map-time EOF contract: the wholly-beyond page is BUS, the partially
        // backed page is not.
        assert!(dispatcher.mmap_fault_is_sigbus(address + 2 * PAGE_SIZE));
        assert!(!dispatcher.mmap_fault_is_sigbus(address + PAGE_SIZE));
    }

    #[test]
    fn mmap_private_hostfile_backend_refusal_falls_back_to_snapshot() {
        const SYS_MMAP: u64 = 222;
        const PAGE_SIZE: u64 = 16 * 1024;
        const LENGTH: u64 = 2 * PAGE_SIZE;

        let dispatcher = native16k_dispatcher();
        install_host_file_fd(&dispatcher, 31, &[0x51u8; 64]);
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1310));
        let reporter = CompatReporter::default();
        let mut memory =
            FileBackedLoweringMemory::new(LINUX_MMAP_BASE, 4 * PAGE_SIZE as usize, false);
        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LENGTH,
                    LINUX_PROT_READ,
                    crate::linux_abi::LINUX_MAP_PRIVATE,
                    31,
                    0,
                ]),
            ),
        );
        let DispatchOutcome::Returned { value } = outcome else {
            panic!("refused lowering must fall back, got {outcome:?}");
        };
        let address = value as u64;
        assert_eq!(memory.offers.borrow().len(), 1, "the backend was offered");
        assert!(
            memory.inner.write_calls.get() > 0,
            "the fallback must eagerly materialize the snapshot"
        );
        assert_eq!(
            memory.inner.read_bytes_raw(address, 64).expect("content"),
            vec![0x51u8; 64],
            "fallback content must be the file bytes"
        );
        // Legacy arena contract on the fallback: no private BUS tail.
        assert!(!dispatcher.mmap_fault_is_sigbus(address + PAGE_SIZE));
    }

    #[test]
    fn mmap_private_hostfile_refusal_with_unstattable_fd_keeps_legacy_success() {
        const SYS_MMAP: u64 = 222;
        const PAGE_SIZE: u64 = 16 * 1024;

        let dispatcher = native16k_dispatcher();
        // A HostFile description whose backing host fd is already closed:
        // fstat and pread both fail. The pre-E1 eager path SUCCEEDED here
        // (best-effort pread, errors left the zeroed buffer), and mmap
        // failure atomicity demands the candidate path not invent a new
        // errno AFTER the address/scrub steps have run — so a refused
        // candidate must reproduce the legacy zero-filled success exactly.
        let dead = unsafe { libc::dup(0) };
        assert!(dead >= 0);
        assert_eq!(unsafe { libc::close(dead) }, 0);
        dispatcher.io.open_files.write().insert(
            34,
            OpenFile::new(
                std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::HostFile {
                    base: OpenDescriptionBase::new(crate::linux_abi::LINUX_O_RDONLY),
                    host_fd: HostFdRef::new(dead),
                    metadata: RootFsMetadata {
                        path: std::path::PathBuf::from("/host-private-map-dead"),
                        kind: RootFsEntryKind::File,
                        mode: 0o644,
                        size: 0,
                    },
                    writable: false,
                })),
                0,
            ),
        );
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1340));
        let reporter = CompatReporter::default();
        let mut memory =
            FileBackedLoweringMemory::new(LINUX_MMAP_BASE, 4 * PAGE_SIZE as usize, false);
        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    PAGE_SIZE,
                    LINUX_PROT_READ,
                    crate::linux_abi::LINUX_MAP_PRIVATE,
                    34,
                    0,
                ]),
            ),
        );
        let DispatchOutcome::Returned { value } = outcome else {
            panic!("legacy contract: unreadable backing still maps zero-filled, got {outcome:?}");
        };
        let address = value as u64;
        assert_eq!(
            memory
                .inner
                .read_bytes_raw(address, 32)
                .expect("mapped range readable"),
            vec![0u8; 32],
            "unreadable backing must surface as zeros, the pre-E1 contract"
        );
        assert!(
            !dispatcher.mmap_fault_is_sigbus(address),
            "no BUS tail may be published without a known file length"
        );
    }

    #[test]
    fn mmap_shared_or_exec_private_is_never_offered_the_lowering() {
        const SYS_MMAP: u64 = 222;
        const PAGE_SIZE: u64 = 16 * 1024;

        let dispatcher = native16k_dispatcher();
        install_host_file_fd(&dispatcher, 32, &[0x11u8; 32]);
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1320));
        let reporter = CompatReporter::default();
        let mut memory =
            FileBackedLoweringMemory::new(LINUX_MMAP_BASE, 4 * PAGE_SIZE as usize, true);
        for flags_prot in [
            (crate::linux_abi::LINUX_MAP_SHARED, LINUX_PROT_READ),
            (
                crate::linux_abi::LINUX_MAP_PRIVATE,
                LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
            ),
        ] {
            let outcome = threaded_memory_call(
                &dispatcher,
                &mut memory,
                &registry,
                &reporter,
                SyscallRequest::new(
                    SYS_MMAP,
                    SyscallArgs([0, PAGE_SIZE, flags_prot.1, flags_prot.0, 32, 0]),
                ),
            );
            // A MAP_SHARED file mapping legitimately publishes via the alias
            // transaction; the exec-prot private control returns in place.
            // Either way it must never be OFFERED the lowering.
            assert!(
                matches!(
                    outcome,
                    DispatchOutcome::Returned { .. } | DispatchOutcome::MapHostAlias { .. }
                ),
                "control mapping must still succeed, got {outcome:?}"
            );
        }
        assert!(
            memory.offers.borrow().is_empty(),
            "shared and exec-prot mappings must keep the snapshot path: {:?}",
            memory.offers.borrow()
        );
    }

    /// Pin the Darwin primitive the E1 lowering's detachment claim rests on:
    /// a `MAP_PRIVATE` file mapping keeps BOTH a COW'd (written) page and a
    /// never-touched page readable, with map-time content, across a later
    /// `ftruncate` of the backing file. Linux diverges on the untouched page
    /// (SIGBUS), so the `mmapprivfile` conformance probe deliberately cannot
    /// pin this clause — it is host behaviour and lives here. The faulting-
    /// risk reads run in a forked child so a regression reports as a failed
    /// assertion, not a dead test harness (`just test` runs this crate
    /// single-threaded, the house fork-in-test precondition).
    #[test]
    #[cfg(target_os = "macos")]
    fn darwin_private_file_mapping_detaches_from_truncate() {
        use std::os::fd::AsRawFd;
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let file = tempfile::tempfile().expect("backing file");
        let fd = file.as_raw_fd();
        let content = vec![0xabu8; 2 * page];
        assert_eq!(
            unsafe { libc::pwrite(fd, content.as_ptr().cast(), content.len(), 0) },
            content.len() as isize
        );
        let child = unsafe { libc::fork() };
        if child == 0 {
            let exit = unsafe {
                let p = libc::mmap(
                    core::ptr::null_mut(),
                    2 * page,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE,
                    fd,
                    0,
                );
                if p == libc::MAP_FAILED {
                    10
                } else {
                    let p = p.cast::<u8>();
                    *p = 0x55; // COW page 0
                    if libc::ftruncate(fd, 1) != 0 {
                        11
                    } else if *p != 0x55 {
                        12 // written page must survive truncate
                    } else if *p.add(page) != 0xab {
                        13 // untouched page must stay readable with map-time content
                    } else {
                        0
                    }
                }
            };
            unsafe { libc::_exit(exit) };
        }
        assert!(child > 0, "fork failed");
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "Darwin private-file truncate detachment regressed: the E1 \
             file-backed lowering relies on it (status {status:#x}); if this \
             ever fires, the lowering must re-snapshot or be gated off"
        );
    }

    #[test]
    fn mmap_private_hostfile_hatch_zero_keeps_snapshot_path() {
        const SYS_MMAP: u64 = 222;
        const PAGE_SIZE: u64 = 16 * 1024;

        let dispatcher = native16k_dispatcher();
        install_host_file_fd(&dispatcher, 33, &[0x22u8; 16]);
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1330));
        let reporter = CompatReporter::default();
        let mut memory =
            FileBackedLoweringMemory::new(LINUX_MMAP_BASE, 4 * PAGE_SIZE as usize, true);
        // SAFETY: `just test` runs carrick-runtime single-threaded
        // (RUST_TEST_THREADS=1), the house pattern for env-hatch tests.
        unsafe { std::env::set_var("CARRICK_MMAP_FILE_BACKED", "0") };
        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    PAGE_SIZE,
                    LINUX_PROT_READ,
                    crate::linux_abi::LINUX_MAP_PRIVATE,
                    33,
                    0,
                ]),
            ),
        );
        unsafe { std::env::remove_var("CARRICK_MMAP_FILE_BACKED") };
        assert!(
            matches!(outcome, DispatchOutcome::Returned { .. }),
            "hatched mapping must still succeed, got {outcome:?}"
        );
        assert!(
            memory.offers.borrow().is_empty(),
            "CARRICK_MMAP_FILE_BACKED=0 must keep the snapshot path"
        );
        assert!(
            memory.inner.write_calls.get() > 0,
            "the hatched path must eagerly materialize"
        );
    }

    #[test]
    fn private_repoint_failure_preserves_prior_overlay_owner_and_vma() {
        const SYS_MMAP: u64 = 222;
        const LENGTH: u64 = 4096;
        const MAPPED_LENGTH: usize = crate::trap::HVF_PAGE_SIZE as usize;

        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1062));
        let reporter = CompatReporter::default();
        let mut memory =
            ProtectionTrackingMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, MAPPED_LENGTH);
        let shared = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        let first = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    shared,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        assert_eq!(first, shared);
        let prior_overlay = dispatcher
            .mem
            .lock()
            .overlay
            .find_by_source(shared)
            .expect("first private overlay owner");
        memory.inner.bytes[0] = 0x5a;
        let prior_map = dispatcher
            .dynamic_mapping_for_test(shared)
            .expect("first private VMA");
        memory.fail_repoint = true;

        let failed = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    shared,
                    LENGTH,
                    LINUX_PROT_READ,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                    u64::MAX,
                    0,
                ]),
            ),
        );

        assert_eq!(failed, DispatchOutcome::errno(LINUX_ENOMEM));
        assert_eq!(memory.inner.bytes[0], 0x5a);
        assert_eq!(dispatcher.dynamic_mapping_for_test(shared), Some(prior_map));
        let mut mem = dispatcher.mem.lock();
        assert_eq!(mem.overlay.find_by_source(shared), Some(prior_overlay));
        assert_eq!(
            mem.overlay
                .live()
                .iter()
                .filter(|slot| slot.source == Some(shared))
                .count(),
            1,
            "failed candidate must be returned without retiring the prior owner"
        );
        let reused = mem
            .overlay
            .alloc(
                crate::trap::HVF_PAGE_SIZE,
                crate::shared_aperture::BackingObject::PrivateAnon,
            )
            .expect("clean failure candidate is reusable");
        assert_eq!(reused, prior_overlay + crate::trap::HVF_PAGE_SIZE);
    }

    #[test]
    fn indeterminate_repoint_policy_retains_old_and_candidate_storage() {
        const GRANULE: u64 = crate::trap::HVF_PAGE_SIZE;
        let dispatcher = SyscallDispatcher::new();
        let source = crate::memory::LINUX_SHARED_FILE_BASE;
        let (old, candidate) = {
            let mut mem = dispatcher.mem.lock();
            let old = mem
                .overlay
                .alloc_sourced(
                    GRANULE,
                    crate::shared_aperture::BackingObject::PrivateAnon,
                    Some(source),
                )
                .expect("old overlay");
            let candidate = mem
                .overlay
                .alloc_sourced(
                    GRANULE,
                    crate::shared_aperture::BackingObject::PrivateAnon,
                    Some(source),
                )
                .expect("candidate overlay");
            (old, candidate)
        };

        let action = dispatcher.recover_private_repoint_failure(
            candidate,
            carrick_guest_mem::RepointPrivateError::indeterminate(MemoryError::HostMap(
                "injected post-publication failure".into(),
            )),
        );
        assert_eq!(action, PrivateRepointRecovery::FailStopRetainingOwners);
        let mut mem = dispatcher.mem.lock();
        assert!(mem.overlay.live().iter().any(|slot| slot.guest_addr == old));
        assert!(
            mem.overlay
                .live()
                .iter()
                .any(|slot| slot.guest_addr == candidate)
        );
        let next = mem
            .overlay
            .alloc(GRANULE, crate::shared_aperture::BackingObject::PrivateAnon)
            .expect("retained owners force fresh allocation");
        assert_eq!(next, candidate + GRANULE);
    }

    #[test]
    fn indeterminate_private_repoint_failure_fails_stopped() {
        const SYS_MMAP: u64 = 222;
        const LENGTH: u64 = crate::trap::HVF_PAGE_SIZE;

        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork indeterminate-repoint child failed");
        if child == 0 {
            let no_core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) };
            let dispatcher = SyscallDispatcher::new();
            let registry = crate::thread::ThreadRegistry::new(
                crate::thread::ThreadId::synthetic_for_tests(1165),
            );
            let reporter = CompatReporter::default();
            let mut memory = ProtectionTrackingMemory::new(
                crate::memory::LINUX_SHARED_FILE_BASE,
                LENGTH as usize,
            );
            let source = returned(threaded_memory_call(
                &dispatcher,
                &mut memory,
                &registry,
                &reporter,
                SyscallRequest::new(
                    SYS_MMAP,
                    SyscallArgs([
                        0,
                        LENGTH,
                        LINUX_PROT_READ | LINUX_PROT_WRITE,
                        LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                        u64::MAX,
                        0,
                    ]),
                ),
            )) as u64;
            let _ = returned(threaded_memory_call(
                &dispatcher,
                &mut memory,
                &registry,
                &reporter,
                SyscallRequest::new(
                    SYS_MMAP,
                    SyscallArgs([
                        source,
                        LENGTH,
                        LINUX_PROT_READ | LINUX_PROT_WRITE,
                        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                        u64::MAX,
                        0,
                    ]),
                ),
            ));
            memory.fail_repoint_indeterminate = true;
            let _ = threaded_memory_call(
                &dispatcher,
                &mut memory,
                &registry,
                &reporter,
                SyscallRequest::new(
                    SYS_MMAP,
                    SyscallArgs([
                        source,
                        LENGTH,
                        LINUX_PROT_READ,
                        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                        u64::MAX,
                        0,
                    ]),
                ),
            );
            unsafe { libc::_exit(93) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFSIGNALED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
    }

    fn assert_partial_private_overlay_replacement(replace_offset: u64) {
        const SYS_MMAP: u64 = 222;
        const GRANULE: u64 = crate::trap::HVF_PAGE_SIZE;
        const LENGTH: u64 = 3 * GRANULE;

        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(
                1160 + i32::try_from(replace_offset / GRANULE).unwrap(),
            ));
        let reporter = CompatReporter::default();
        let mut memory =
            ProtectionTrackingMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, LENGTH as usize);
        let source = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        let first = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    source,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        assert_eq!(first, source);
        let old_overlay = dispatcher
            .mem
            .lock()
            .overlay
            .translate_source_range(source, LENGTH)
            .expect("whole initial overlay");

        memory.inner.bytes[..GRANULE as usize].fill(0x11);
        memory.inner.bytes[GRANULE as usize..(2 * GRANULE) as usize].fill(0x22);
        memory.inner.bytes[(2 * GRANULE) as usize..].fill(0x33);
        let replaced = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    source + replace_offset,
                    GRANULE,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        assert_eq!(replaced, source + replace_offset);

        let replaced_index = usize::try_from(replace_offset).unwrap();
        assert!(
            memory.inner.bytes[replaced_index..replaced_index + GRANULE as usize]
                .iter()
                .all(|byte| *byte == 0),
            "replacement payload must touch only the replaced source interval"
        );
        if replace_offset != 0 {
            assert!(
                memory.inner.bytes[..replaced_index]
                    .iter()
                    .all(|byte| *byte != 0)
            );
        }
        let replacement_end = replaced_index + GRANULE as usize;
        if replacement_end < LENGTH as usize {
            assert!(
                memory.inner.bytes[replacement_end..]
                    .iter()
                    .all(|byte| *byte != 0)
            );
        }

        let mut mem = dispatcher.mem.lock();
        let replacement_overlay = mem
            .overlay
            .translate_source_range(source + replace_offset, GRANULE)
            .expect("replacement overlay translation");
        assert_ne!(replacement_overlay, old_overlay + replace_offset);
        if replace_offset != 0 {
            assert_eq!(
                mem.overlay.translate_source_range(source, replace_offset),
                Some(old_overlay)
            );
        }
        let suffix_start = replace_offset + GRANULE;
        if suffix_start < LENGTH {
            assert_eq!(
                mem.overlay
                    .translate_source_range(source + suffix_start, LENGTH - suffix_start),
                Some(old_overlay + suffix_start)
            );
        }
        let reused = mem
            .overlay
            .alloc(GRANULE, crate::shared_aperture::BackingObject::PrivateAnon)
            .expect("only overwritten overlay storage is reusable");
        assert_eq!(reused, old_overlay + replace_offset);
        let after_reuse = mem
            .overlay
            .alloc(GRANULE, crate::shared_aperture::BackingObject::PrivateAnon)
            .expect("preserved storage remains unavailable");
        assert!(
            after_reuse >= replacement_overlay + GRANULE,
            "preserved prefix/suffix must not be reallocated"
        );
        drop(mem);

        // The mapped bytes survive a real fork snapshot. Child mutations to the
        // private replacement model cannot bleed back into the parent, while the
        // parent retains every preserved prefix/suffix byte.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork partial-overlay snapshot failed");
        if child == 0 {
            if memory.inner.bytes[replaced_index] != 0 {
                unsafe { libc::_exit(81) };
            }
            memory.inner.bytes.fill(0x7e);
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert_eq!(memory.inner.bytes[replaced_index], 0);
        if replace_offset != 0 {
            assert_ne!(memory.inner.bytes[0], 0x7e);
        }
        if replacement_end < LENGTH as usize {
            assert_ne!(memory.inner.bytes[replacement_end], 0x7e);
        }
    }

    fn assert_shared_owner_survives_partial_private_replacement(replace_offset: u64) {
        const SYS_MMAP: u64 = 222;
        const SYS_MUNMAP: u64 = 215;
        const GRANULE: u64 = crate::trap::HVF_PAGE_SIZE;
        const LENGTH: u64 = 3 * GRANULE;

        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(
                1180 + i32::try_from(replace_offset / GRANULE).unwrap(),
            ));
        let reporter = CompatReporter::default();
        let mut memory = ProtectionTrackingMemory::new(
            crate::memory::LINUX_SHARED_FILE_BASE,
            (5 * GRANULE) as usize,
        );
        let source = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        memory.inner.bytes[..GRANULE as usize].fill(0x11);
        memory.inner.bytes[GRANULE as usize..(2 * GRANULE) as usize].fill(0x22);
        memory.inner.bytes[(2 * GRANULE) as usize..(3 * GRANULE) as usize].fill(0x33);

        assert_eq!(
            returned(threaded_memory_call(
                &dispatcher,
                &mut memory,
                &registry,
                &reporter,
                SyscallRequest::new(
                    SYS_MMAP,
                    SyscallArgs([
                        source + replace_offset,
                        GRANULE,
                        LINUX_PROT_READ | LINUX_PROT_WRITE,
                        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                        u64::MAX,
                        0,
                    ]),
                ),
            )),
            (source + replace_offset) as i64
        );
        {
            let mem = dispatcher.mem.lock();
            if replace_offset != 0 {
                assert!(mem.shared.guest_range_has_owner(source, replace_offset));
            }
            let suffix_start = replace_offset + GRANULE;
            if suffix_start < LENGTH {
                assert!(
                    mem.shared
                        .guest_range_has_owner(source + suffix_start, LENGTH - suffix_start)
                );
            }
            assert!(
                mem.shared
                    .guest_range_is_private_reservation(source + replace_offset, GRANULE)
            );
        }

        let blocked = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    GRANULE,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        assert!(
            blocked >= source + LENGTH,
            "live private reservation must keep nonfixed MAP_SHARED away from its source VA"
        );

        assert_eq!(
            threaded_memory_call(
                &dispatcher,
                &mut memory,
                &registry,
                &reporter,
                SyscallRequest::new(
                    SYS_MUNMAP,
                    SyscallArgs([source + replace_offset, GRANULE, 0, 0, 0, 0]),
                ),
            ),
            DispatchOutcome::Returned { value: 0 }
        );
        let reused = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    GRANULE,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        assert_eq!(reused, source + replace_offset);
        assert_eq!(
            memory.restored_shared_identity.last(),
            Some(&(source + replace_offset, GRANULE as usize)),
            "reusing the exact private source must restore VA to shared identity backing"
        );

        for (index, expected) in [0x11, 0x22, 0x33].into_iter().enumerate() {
            let offset = (index as u64) * GRANULE;
            if offset != replace_offset {
                let start = usize::try_from(offset).unwrap();
                assert!(
                    memory.inner.bytes[start..start + GRANULE as usize]
                        .iter()
                        .all(|byte| *byte == expected),
                    "reusing the displaced interval overwrote a live shared fragment"
                );
            }
        }
        let next = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    GRANULE,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        assert!(
            next >= source + LENGTH,
            "a preserved prefix/suffix was returned to the shared allocator"
        );
    }

    #[test]
    fn shared_owner_prefix_replacement_then_unmap_reuses_only_prefix() {
        assert_shared_owner_survives_partial_private_replacement(0);
    }

    #[test]
    fn shared_owner_middle_replacement_then_unmap_reuses_only_middle() {
        assert_shared_owner_survives_partial_private_replacement(crate::trap::HVF_PAGE_SIZE);
    }

    #[test]
    fn shared_owner_suffix_replacement_then_unmap_reuses_only_suffix() {
        assert_shared_owner_survives_partial_private_replacement(2 * crate::trap::HVF_PAGE_SIZE);
    }

    #[test]
    fn partial_shared_file_munmaps_write_exact_fragments_and_close_once() {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        const SYS_MUNMAP: u64 = 215;
        const GRANULE: u64 = crate::trap::HVF_PAGE_SIZE;
        const LENGTH: u64 = 3 * GRANULE;

        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1190));
        let reporter = CompatReporter::default();
        let file = tempfile::tempfile().expect("temporary shared backing");
        file.set_len(LENGTH).expect("size shared backing");
        let dup = unsafe { libc::dup(file.as_raw_fd()) };
        assert!(
            dup >= 0,
            "dup shared backing: {}",
            std::io::Error::last_os_error()
        );
        let owned = unsafe { OwnedFd::from_raw_fd(dup) };
        let owned_raw = owned.as_raw_fd();
        let source = dispatcher
            .mem
            .lock()
            .shared
            .alloc(
                LENGTH,
                crate::shared_aperture::BackingObject::shared_file(owned, 0),
            )
            .expect("shared file aperture allocation");
        dispatcher.record_dynamic_mapping(
            source,
            LENGTH,
            LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            ProcMapSharing::Shared,
            "shared-file".into(),
        );
        let mut memory = ProtectionTrackingMemory::new(source, LENGTH as usize);
        memory.inner.bytes[..GRANULE as usize].fill(0x11);
        memory.inner.bytes[GRANULE as usize..(2 * GRANULE) as usize].fill(0x22);
        memory.inner.bytes[(2 * GRANULE) as usize..].fill(0x33);

        for offset in [GRANULE, 0, 2 * GRANULE] {
            assert_eq!(
                threaded_memory_call(
                    &dispatcher,
                    &mut memory,
                    &registry,
                    &reporter,
                    SyscallRequest::new(
                        SYS_MUNMAP,
                        SyscallArgs([source + offset, GRANULE, 0, 0, 0, 0]),
                    ),
                ),
                DispatchOutcome::Returned { value: 0 }
            );
            if offset != 2 * GRANULE {
                assert_ne!(
                    unsafe { libc::fcntl(owned_raw, libc::F_GETFD) },
                    -1,
                    "a surviving fragment must retain the one fd owner"
                );
            }
        }
        assert_eq!(unsafe { libc::fcntl(owned_raw, libc::F_GETFD) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );

        let mut actual = vec![0_u8; LENGTH as usize];
        assert_eq!(
            unsafe {
                libc::pread(
                    file.as_raw_fd(),
                    actual.as_mut_ptr().cast(),
                    actual.len(),
                    0,
                )
            },
            LENGTH as isize
        );
        assert!(actual[..GRANULE as usize].iter().all(|byte| *byte == 0x11));
        assert!(
            actual[GRANULE as usize..(2 * GRANULE) as usize]
                .iter()
                .all(|byte| *byte == 0x22)
        );
        assert!(
            actual[(2 * GRANULE) as usize..]
                .iter()
                .all(|byte| *byte == 0x33)
        );
    }

    #[test]
    fn clean_private_repoint_failure_does_not_commit_shared_file_writeback() {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        const SYS_MMAP: u64 = 222;
        const SYS_MUNMAP: u64 = 215;
        const LENGTH: u64 = crate::trap::HVF_PAGE_SIZE;

        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1191));
        let reporter = CompatReporter::default();
        let file = tempfile::tempfile().expect("temporary repoint backing");
        file.set_len(LENGTH).expect("size repoint backing");
        let dup = unsafe { libc::dup(file.as_raw_fd()) };
        assert!(dup >= 0, "dup repoint backing");
        let owned = unsafe { OwnedFd::from_raw_fd(dup) };
        let owned_raw = owned.as_raw_fd();
        let source = dispatcher
            .mem
            .lock()
            .shared
            .alloc(
                LENGTH,
                crate::shared_aperture::BackingObject::shared_file(owned, 0),
            )
            .expect("shared file source");
        dispatcher.record_dynamic_mapping(
            source,
            LENGTH,
            LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            ProcMapSharing::Shared,
            "shared-file".into(),
        );
        let mut memory = ProtectionTrackingMemory::new(source, LENGTH as usize);
        memory.inner.bytes.fill(0x61);
        memory.fail_repoint = true;

        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    source,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                    u64::MAX,
                    0,
                ]),
            ),
        );
        assert_eq!(outcome, DispatchOutcome::errno(LINUX_ENOMEM));
        let mut byte = [0xff_u8; 1];
        assert_eq!(
            unsafe { libc::pread(file.as_raw_fd(), byte.as_mut_ptr().cast(), 1, 0) },
            1
        );
        assert_eq!(byte, [0], "clean failure must not commit writeback");
        assert!(
            dispatcher
                .mem
                .lock()
                .shared
                .guest_range_has_owner(source, LENGTH)
        );
        assert_ne!(unsafe { libc::fcntl(owned_raw, libc::F_GETFD) }, -1);

        assert_eq!(
            threaded_memory_call(
                &dispatcher,
                &mut memory,
                &registry,
                &reporter,
                SyscallRequest::new(SYS_MUNMAP, SyscallArgs([source, LENGTH, 0, 0, 0, 0]),),
            ),
            DispatchOutcome::Returned { value: 0 }
        );
        assert_eq!(unsafe { libc::fcntl(owned_raw, libc::F_GETFD) }, -1);
        assert_eq!(
            unsafe { libc::pread(file.as_raw_fd(), byte.as_mut_ptr().cast(), 1, 0) },
            1
        );
        assert_eq!(byte, [0x61]);
    }

    #[test]
    fn private_overlay_prefix_replacement_carves_exact_storage() {
        assert_partial_private_overlay_replacement(0);
    }

    #[test]
    fn private_overlay_middle_replacement_carves_exact_storage() {
        assert_partial_private_overlay_replacement(crate::trap::HVF_PAGE_SIZE);
    }

    #[test]
    fn private_overlay_suffix_replacement_carves_exact_storage() {
        assert_partial_private_overlay_replacement(2 * crate::trap::HVF_PAGE_SIZE);
    }

    #[test]
    fn exact_partial_granule_replacement_splits_owner_without_reusing_live_storage() {
        const SYS_MMAP: u64 = 222;
        const LENGTH: u64 = 2 * crate::trap::HVF_PAGE_SIZE;
        const PARTIAL: u64 = LINUX_PAGE_SIZE;

        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1164));
        let reporter = CompatReporter::default();
        let mut memory =
            ProtectionTrackingMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, LENGTH as usize);
        let source = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        let _ = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    source,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                    u64::MAX,
                    0,
                ]),
            ),
        ));
        let prior_calls = memory.repoint_calls;
        let prior_overlay = dispatcher
            .mem
            .lock()
            .overlay
            .translate_source_range(source, LENGTH)
            .expect("prior overlay");

        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    source,
                    PARTIAL,
                    LINUX_PROT_READ,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                    u64::MAX,
                    0,
                ]),
            ),
        );

        assert_eq!(
            outcome,
            DispatchOutcome::Returned {
                value: source as i64
            }
        );
        assert_eq!(memory.repoint_calls, prior_calls + 1);
        let mut mem = dispatcher.mem.lock();
        let replacement = mem
            .overlay
            .translate_source_range(source, PARTIAL)
            .expect("exact partial replacement owner");
        assert_ne!(replacement, prior_overlay);
        assert_eq!(
            mem.overlay
                .translate_source_range(source + PARTIAL, LENGTH - PARTIAL),
            Some(prior_overlay + PARTIAL)
        );
        let fresh = mem
            .overlay
            .alloc(
                crate::trap::HVF_PAGE_SIZE,
                crate::shared_aperture::BackingObject::PrivateAnon,
            )
            .expect("partial physical hole is not independently reusable");
        assert!(fresh >= replacement + crate::trap::HVF_PAGE_SIZE);
    }

    #[test]
    fn post_repoint_protection_failure_aborts_instead_of_publishing_split_ownership() {
        const SYS_MMAP: u64 = 222;
        const LENGTH: u64 = 4096;
        const MAPPED_LENGTH: usize = crate::trap::HVF_PAGE_SIZE as usize;

        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork protection-failure child failed");
        if child == 0 {
            let no_core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) };
            let dispatcher = SyscallDispatcher::new();
            let registry = crate::thread::ThreadRegistry::new(
                crate::thread::ThreadId::synthetic_for_tests(1063),
            );
            let reporter = CompatReporter::default();
            let mut memory =
                ProtectionTrackingMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, MAPPED_LENGTH);
            let shared = returned(threaded_memory_call(
                &dispatcher,
                &mut memory,
                &registry,
                &reporter,
                SyscallRequest::new(
                    SYS_MMAP,
                    SyscallArgs([
                        0,
                        LENGTH,
                        LINUX_PROT_READ | LINUX_PROT_WRITE,
                        LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                        u64::MAX,
                        0,
                    ]),
                ),
            )) as u64;
            memory.fail_protect = true;
            let _ = threaded_memory_call(
                &dispatcher,
                &mut memory,
                &registry,
                &reporter,
                SyscallRequest::new(
                    SYS_MMAP,
                    SyscallArgs([
                        shared,
                        LENGTH,
                        LINUX_PROT_READ,
                        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                        u64::MAX,
                        0,
                    ]),
                ),
            );
            unsafe { libc::_exit(92) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFSIGNALED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
    }

    #[test]
    fn moving_shared_mremap_fails_before_private_copy_or_metadata_mutation() {
        const SYS_MMAP: u64 = 222;
        const SYS_MREMAP: u64 = 216;
        const LENGTH: u64 = LINUX_PAGE_SIZE;

        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1065));
        let reporter = CompatReporter::default();
        let mut memory =
            ProtectionTrackingMemory::new(LINUX_MMAP_BASE, (8 * LINUX_PAGE_SIZE) as usize);
        let old = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_EXEC,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        let _blocker = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        ));
        memory.protections.set_mapping_sharing(
            old,
            LENGTH as usize,
            carrick_guest_mem::MappingSharing::Shared,
        );
        dispatcher.record_dynamic_mapping(
            old,
            LENGTH,
            LinuxProtFlags::READ | LinuxProtFlags::EXEC,
            ProcMapSharing::Shared,
            "shared-code".into(),
        );

        let mmap_next_before = dispatcher.mem.lock().mmap_next;
        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MREMAP,
                SyscallArgs([old, LENGTH, 2 * LENGTH, LINUX_MREMAP_MAYMOVE, 0, 0]),
            ),
        );
        assert_eq!(outcome, DispatchOutcome::errno(LINUX_ENOMEM));
        assert_eq!(dispatcher.mem.lock().mmap_next, mmap_next_before);
        assert!(
            memory
                .protections
                .range_mutable_shared_backing(old, LENGTH as usize)
        );
        assert!(!memory.protections.range_unmapped(old, LENGTH as usize));
        let mem = dispatcher.mem.lock();
        assert!(mem.dynamic_maps.iter().any(|map| {
            map.start == old
                && map.end == old + LENGTH
                && map.execute
                && map.sharing == ProcMapSharing::Shared
                && map.path == "shared-code"
        }));
        assert_eq!(mem.dynamic_maps.len(), 2, "source plus blocker only");
    }

    #[test]
    fn mixed_rx_and_r_mremap_source_is_rejected_without_broadening_permissions() {
        const SYS_MMAP: u64 = 222;
        const SYS_MPROTECT: u64 = 226;
        const SYS_MREMAP: u64 = 216;
        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1066));
        let reporter = CompatReporter::default();
        let mut memory =
            ProtectionTrackingMemory::new(LINUX_MMAP_BASE, (8 * LINUX_PAGE_SIZE) as usize);
        let source = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    2 * LINUX_PAGE_SIZE,
                    LINUX_PROT_READ | LINUX_PROT_EXEC,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        assert_eq!(
            threaded_memory_call(
                &dispatcher,
                &mut memory,
                &registry,
                &reporter,
                SyscallRequest::new(
                    SYS_MPROTECT,
                    SyscallArgs([
                        source + LINUX_PAGE_SIZE,
                        LINUX_PAGE_SIZE,
                        LINUX_PROT_READ,
                        0,
                        0,
                        0,
                    ]),
                ),
            ),
            DispatchOutcome::Returned { value: 0 }
        );
        let maps_before = dispatcher.mem.lock().dynamic_maps.clone();
        let mmap_next_before = dispatcher.mem.lock().mmap_next;

        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MREMAP,
                SyscallArgs([
                    source,
                    2 * LINUX_PAGE_SIZE,
                    3 * LINUX_PAGE_SIZE,
                    LINUX_MREMAP_MAYMOVE,
                    0,
                    0,
                ]),
            ),
        );
        assert_eq!(outcome, DispatchOutcome::errno(LINUX_EFAULT));
        assert_eq!(dispatcher.mem.lock().dynamic_maps, maps_before);
        assert_eq!(dispatcher.mem.lock().mmap_next, mmap_next_before);
    }

    #[test]
    fn mremap_shrink_unmap_failure_keeps_source_metadata_and_allocator() {
        const SYS_MREMAP: u64 = 216;
        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1067));
        let reporter = CompatReporter::default();
        let source = LINUX_MMAP_BASE;
        dispatcher.record_dynamic_mapping(
            source,
            2 * LINUX_PAGE_SIZE,
            LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            ProcMapSharing::Private,
            "source".into(),
        );
        dispatcher.mem.lock().mmap_next = source + 2 * LINUX_PAGE_SIZE;
        let mut memory =
            DeferredSetterFailureMemory::new(source, (2 * LINUX_PAGE_SIZE) as usize).fail_unmaps(1);
        let maps_before = dispatcher.mem.lock().dynamic_maps.clone();
        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MREMAP,
                SyscallArgs([source, 2 * LINUX_PAGE_SIZE, LINUX_PAGE_SIZE, 0, 0, 0]),
            ),
        );
        assert_eq!(outcome, DispatchOutcome::errno(LINUX_ENOMEM));
        assert_eq!(dispatcher.mem.lock().dynamic_maps, maps_before);
        assert_eq!(
            dispatcher.mem.lock().mmap_next,
            source + 2 * LINUX_PAGE_SIZE
        );
    }

    #[test]
    fn shared_anonymous_mremap_shrink_retains_shared_prefix_metadata() {
        const SYS_MMAP: u64 = 222;
        const SYS_MREMAP: u64 = 216;
        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1068));
        let reporter = CompatReporter::default();
        let base = crate::memory::LINUX_SHARED_FILE_BASE;
        let map_len = crate::trap::HVF_PAGE_SIZE * 2;
        let mut memory = CountingMmapMemory::new(base, map_len as usize);
        let source = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    map_len,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        let shrunk = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MREMAP,
                SyscallArgs([source, map_len, crate::trap::HVF_PAGE_SIZE, 0, 0, 0]),
            ),
        );
        assert_eq!(
            shrunk,
            DispatchOutcome::Returned {
                value: source as i64
            }
        );
        let mem = dispatcher.mem.lock();
        assert!(mem.dynamic_maps.iter().any(|map| {
            map.start == source
                && map.end == source + crate::trap::HVF_PAGE_SIZE
                && map.sharing == ProcMapSharing::Shared
        }));
    }

    #[test]
    fn private_overlay_mremap_shrink_carves_source_tail_and_reuses_only_storage() {
        const SYS_MMAP: u64 = 222;
        const SYS_MREMAP: u64 = 216;
        const GRANULE: u64 = crate::trap::HVF_PAGE_SIZE;
        const LENGTH: u64 = 2 * GRANULE;

        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1174));
        let reporter = CompatReporter::default();
        let mut memory =
            ProtectionTrackingMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, LENGTH as usize);
        let source = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        assert_eq!(
            returned(threaded_memory_call(
                &dispatcher,
                &mut memory,
                &registry,
                &reporter,
                SyscallRequest::new(
                    SYS_MMAP,
                    SyscallArgs([
                        source,
                        LENGTH,
                        LINUX_PROT_READ | LINUX_PROT_WRITE,
                        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                        u64::MAX,
                        0,
                    ]),
                ),
            )),
            source as i64
        );
        let old_overlay = dispatcher
            .mem
            .lock()
            .overlay
            .translate_source_range(source, LENGTH)
            .expect("whole private overlay before shrink");
        memory.inner.bytes[..GRANULE as usize].fill(0x41);
        memory.inner.bytes[GRANULE as usize..].fill(0x52);

        assert_eq!(
            threaded_memory_call(
                &dispatcher,
                &mut memory,
                &registry,
                &reporter,
                SyscallRequest::new(SYS_MREMAP, SyscallArgs([source, LENGTH, GRANULE, 0, 0, 0]),),
            ),
            DispatchOutcome::Returned {
                value: source as i64
            }
        );

        let mut mem = dispatcher.mem.lock();
        assert_eq!(
            mem.overlay.translate_source_range(source, GRANULE),
            Some(old_overlay),
            "retained source prefix must keep its physical overlay translation"
        );
        assert_eq!(
            mem.overlay
                .translate_source_range(source + GRANULE, GRANULE),
            None,
            "removed source tail must not retain stale overlay ownership"
        );
        assert!(
            mem.shared
                .guest_range_is_private_reservation(source, GRANULE)
        );
        assert!(!mem.shared.guest_range_has_owner(source + GRANULE, GRANULE));
        assert!(
            mem.shared
                .range_needs_identity_restore(source + GRANULE, GRANULE)
        );
        let reused = mem
            .overlay
            .alloc_sourced(
                GRANULE,
                crate::shared_aperture::BackingObject::PrivateAnon,
                Some(source + (8 * GRANULE)),
            )
            .expect("reuse removed overlay tail for a distinct source");
        assert_eq!(reused, old_overlay + GRANULE);
        assert_eq!(
            mem.overlay
                .translate_source_range(source + (8 * GRANULE), GRANULE),
            Some(old_overlay + GRANULE)
        );
        drop(mem);

        assert!(
            memory
                .protections
                .range_unmapped(source + GRANULE, GRANULE as usize),
            "VMM/identity guest metadata must keep the removed VA inaccessible"
        );
        assert!(
            memory.inner.bytes[..GRANULE as usize]
                .iter()
                .all(|byte| *byte == 0x41)
        );
        let map = dispatcher
            .dynamic_mapping_for_test(source)
            .expect("retained private prefix VMA");
        assert_eq!(map.end, source + GRANULE);
        assert_eq!(map.sharing, ProcMapSharing::Private);
        assert!(
            dispatcher
                .dynamic_mapping_for_test(source + GRANULE)
                .is_none()
        );
    }

    #[test]
    fn mremap_fixed_is_rejected_before_source_or_destination_mutation() {
        const SYS_MMAP: u64 = 222;
        const SYS_MREMAP: u64 = 216;
        const MREMAP_MAYMOVE: u64 = 0x01;
        const MREMAP_FIXED: u64 = 0x02;

        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1069));
        let reporter = CompatReporter::default();
        let mut memory =
            ProtectionTrackingMemory::new(LINUX_MMAP_BASE, (8 * LINUX_PAGE_SIZE) as usize);
        let source = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LINUX_PAGE_SIZE,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        let destination = source + (2 * LINUX_PAGE_SIZE);
        memory
            .write_bytes(source, b"move")
            .expect("seed source bytes before fixed move");

        // new_size == 0 is EINVAL on real Linux regardless of any other
        // flag bit (confirmed against a real-Linux oracle, 2026-07-23,
        // Linux 6.12.76 — see .superpowers/sdd/mremap-ruling-report.md): it must win
        // over carrick's MREMAP_FIXED-not-yet-implemented refusal, not be
        // masked by it.
        let zero_size = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MREMAP,
                SyscallArgs([u64::MAX, LINUX_PAGE_SIZE, 0, MREMAP_FIXED, 1, 0]),
            ),
        );
        assert_eq!(zero_size, DispatchOutcome::errno(LINUX_EINVAL));
        // An unrecognized flag bit (1 << 63) ORed onto an otherwise-valid
        // MREMAP_FIXED request is EINVAL on real Linux, not EOPNOTSUPP:
        // real Linux actually implements MREMAP_FIXED (confirmed by the
        // same oracle run — MREMAP_FIXED|MREMAP_MAYMOVE with the garbage
        // bit removed succeeds), so an unknown bit is what makes this
        // request invalid, and that check must run before carrick's
        // "not yet implemented" refusal for the FIXED shape itself.
        let invalid_combo = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MREMAP,
                SyscallArgs([u64::MAX, u64::MAX, u64::MAX, MREMAP_FIXED | (1 << 63), 3, 0]),
            ),
        );
        assert_eq!(invalid_combo, DispatchOutcome::errno(LINUX_EINVAL));

        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MREMAP,
                SyscallArgs([
                    source,
                    LINUX_PAGE_SIZE,
                    LINUX_PAGE_SIZE,
                    MREMAP_MAYMOVE | MREMAP_FIXED,
                    destination,
                    0,
                ]),
            ),
        );
        assert_eq!(outcome, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
        assert_eq!(memory.read_bytes(source, 4).unwrap(), b"move");
        assert_eq!(memory.read_bytes(destination, 4).unwrap(), &[0; 4]);
        assert!(
            !memory
                .protections
                .range_unmapped(source, LINUX_PAGE_SIZE as usize)
        );
        let mem = dispatcher.mem.lock();
        assert!(mem.dynamic_maps.iter().any(|map| map.start == source));
        assert!(!mem.dynamic_maps.iter().any(|map| map.start == destination));
    }

    #[test]
    fn mremap_dontunmap_is_rejected_before_source_or_allocator_mutation() {
        const SYS_MMAP: u64 = 222;
        const SYS_MREMAP: u64 = 216;
        const MREMAP_MAYMOVE: u64 = 0x01;
        const MREMAP_DONTUNMAP: u64 = 0x04;

        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1070));
        let reporter = CompatReporter::default();
        let mut memory =
            ProtectionTrackingMemory::new(LINUX_MMAP_BASE, (8 * LINUX_PAGE_SIZE) as usize);
        let source = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LINUX_PAGE_SIZE,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        memory
            .write_bytes(source, b"keep")
            .expect("seed source bytes before dontunmap move");

        // new_size == 0 (and, independently, the unrecognized 1 << 63 bit)
        // is EINVAL on real Linux, not EOPNOTSUPP: confirmed against a
        // real-Linux oracle, 2026-07-23, Linux 6.12.76 — see
        // .superpowers/sdd/mremap-ruling-report.md. Either well-formedness check must
        // win over carrick's MREMAP_DONTUNMAP-not-yet-implemented refusal.
        let invalid_precedence = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MREMAP,
                SyscallArgs([u64::MAX, 0, 0, MREMAP_DONTUNMAP | (1 << 63), 0, 0]),
            ),
        );
        assert_eq!(invalid_precedence, DispatchOutcome::errno(LINUX_EINVAL));

        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MREMAP,
                SyscallArgs([
                    source,
                    LINUX_PAGE_SIZE,
                    LINUX_PAGE_SIZE,
                    MREMAP_MAYMOVE | MREMAP_DONTUNMAP,
                    0,
                    0,
                ]),
            ),
        );
        assert_eq!(outcome, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
        assert_eq!(memory.read_bytes(source, 4).unwrap(), b"keep");
        let mem = dispatcher.mem.lock();
        assert_eq!(mem.dynamic_maps.len(), 1);
        assert_eq!(mem.dynamic_maps[0].start, source);
    }

    #[test]
    fn shared_fixed_mremap_move_fails_before_source_mutation() {
        const SYS_MMAP: u64 = 222;
        const SYS_MREMAP: u64 = 216;
        const MREMAP_MAYMOVE: u64 = 0x01;
        const MREMAP_FIXED: u64 = 0x02;

        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1071));
        let reporter = CompatReporter::default();
        let mut memory =
            ProtectionTrackingMemory::new(LINUX_MMAP_BASE, (8 * LINUX_PAGE_SIZE) as usize);
        let source = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LINUX_PAGE_SIZE,
                    LINUX_PROT_READ | LINUX_PROT_EXEC,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        memory.protections.set_mapping_sharing(
            source,
            LINUX_PAGE_SIZE as usize,
            carrick_guest_mem::MappingSharing::Shared,
        );
        dispatcher.record_dynamic_mapping(
            source,
            LINUX_PAGE_SIZE,
            LinuxProtFlags::READ | LinuxProtFlags::EXEC,
            ProcMapSharing::Shared,
            "shared-fixed".into(),
        );
        let before = dispatcher.mem.lock().dynamic_maps.clone();

        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MREMAP,
                SyscallArgs([
                    source,
                    LINUX_PAGE_SIZE,
                    LINUX_PAGE_SIZE,
                    MREMAP_MAYMOVE | MREMAP_FIXED,
                    source + (2 * LINUX_PAGE_SIZE),
                    0,
                ]),
            ),
        );
        assert_eq!(outcome, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
        assert_eq!(dispatcher.mem.lock().dynamic_maps, before);
        assert!(
            !memory
                .protections
                .range_unmapped(source, LINUX_PAGE_SIZE as usize)
        );
    }

    #[test]
    fn shared_fixed_mremap_shrink_fails_before_source_tail_mutation() {
        const SYS_MMAP: u64 = 222;
        const SYS_MREMAP: u64 = 216;
        const MREMAP_MAYMOVE: u64 = 0x01;
        const MREMAP_FIXED: u64 = 0x02;

        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1073));
        let reporter = CompatReporter::default();
        let mut memory =
            ProtectionTrackingMemory::new(LINUX_MMAP_BASE, (8 * LINUX_PAGE_SIZE) as usize);
        let source = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    2 * LINUX_PAGE_SIZE,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        memory.protections.set_mapping_sharing(
            source,
            (2 * LINUX_PAGE_SIZE) as usize,
            carrick_guest_mem::MappingSharing::Shared,
        );
        dispatcher.record_dynamic_mapping(
            source,
            2 * LINUX_PAGE_SIZE,
            LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            ProcMapSharing::Shared,
            "shared-fixed-shrink".into(),
        );
        let before = dispatcher.mem.lock().dynamic_maps.clone();

        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MREMAP,
                SyscallArgs([
                    source,
                    2 * LINUX_PAGE_SIZE,
                    LINUX_PAGE_SIZE,
                    MREMAP_MAYMOVE | MREMAP_FIXED,
                    source + (3 * LINUX_PAGE_SIZE),
                    0,
                ]),
            ),
        );

        assert_eq!(outcome, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
        assert_eq!(dispatcher.mem.lock().dynamic_maps, before);
        assert!(
            !memory
                .protections
                .range_unmapped(source + LINUX_PAGE_SIZE, LINUX_PAGE_SIZE as usize),
            "fixed shared shrink must not unmap the source tail before rejection"
        );
    }

    #[test]
    fn mremap_boot_region_metadata_fallback_preserves_exact_properties() {
        const SYS_MREMAP: u64 = 216;
        const BOOT_VMA: u64 = LINUX_MMAP_BASE - (8 * LINUX_PAGE_SIZE);
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_address_space_regions(vec![ProcMapsEntry {
            start: BOOT_VMA,
            end: BOOT_VMA + (2 * LINUX_PAGE_SIZE),
            read: true,
            write: true,
            execute: false,
            sharing: ProcMapSharing::Private,
            path: "boot-region".into(),
        }]);
        let reporter = CompatReporter::default();
        let mut memory = ProtectionTrackingMemory::new(BOOT_VMA, (4 * LINUX_PAGE_SIZE) as usize);

        let outcome = dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    SYS_MREMAP,
                    SyscallArgs([BOOT_VMA, 2 * LINUX_PAGE_SIZE, LINUX_PAGE_SIZE, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .expect("boot-region shrink dispatch");
        assert_eq!(
            outcome,
            DispatchOutcome::Returned {
                value: BOOT_VMA as i64
            }
        );
        let map = dispatcher
            .dynamic_mapping_for_test(BOOT_VMA)
            .expect("fallback should publish exact boot-region metadata");
        assert_eq!(map.end, BOOT_VMA + LINUX_PAGE_SIZE);
        assert!((map.read, map.write, map.execute) == (true, true, false));
        assert_eq!(map.sharing, ProcMapSharing::Private);
        assert_eq!(map.path, "boot-region");
    }

    #[test]
    fn mremap_rejects_boot_region_source_spanning_multiple_regions() {
        const SYS_MREMAP: u64 = 216;
        const BOOT_VMA: u64 = LINUX_MMAP_BASE - (8 * LINUX_PAGE_SIZE);
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_address_space_regions(vec![
            ProcMapsEntry {
                start: BOOT_VMA,
                end: BOOT_VMA + LINUX_PAGE_SIZE,
                read: true,
                write: true,
                execute: false,
                sharing: ProcMapSharing::Private,
                path: "boot-left".into(),
            },
            ProcMapsEntry {
                start: BOOT_VMA + LINUX_PAGE_SIZE,
                end: BOOT_VMA + (2 * LINUX_PAGE_SIZE),
                read: true,
                write: false,
                execute: false,
                sharing: ProcMapSharing::Private,
                path: "boot-right".into(),
            },
        ]);
        let reporter = CompatReporter::default();
        let mut memory = ProtectionTrackingMemory::new(BOOT_VMA, (4 * LINUX_PAGE_SIZE) as usize);

        let outcome = dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    SYS_MREMAP,
                    SyscallArgs([
                        BOOT_VMA,
                        2 * LINUX_PAGE_SIZE,
                        3 * LINUX_PAGE_SIZE,
                        LINUX_MREMAP_MAYMOVE,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .expect("mixed boot-span shrink dispatch");
        assert_eq!(outcome, DispatchOutcome::errno(LINUX_EFAULT));
        assert!(dispatcher.mem.lock().dynamic_maps.is_empty());
    }

    #[test]
    fn mremap_rejects_hidden_mmap_backing_boot_region() {
        const SYS_MREMAP: u64 = 216;
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_address_space_regions(vec![ProcMapsEntry {
            start: LINUX_MMAP_BASE,
            end: LINUX_MMAP_BASE + crate::memory::LINUX_MMAP_SIZE,
            read: true,
            write: true,
            execute: false,
            sharing: ProcMapSharing::Private,
            path: "hidden-mmap-backing".into(),
        }]);
        let mut memory =
            ProtectionTrackingMemory::new(LINUX_MMAP_BASE, (2 * LINUX_PAGE_SIZE) as usize);
        let outcome = dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    SYS_MREMAP,
                    SyscallArgs([LINUX_MMAP_BASE, LINUX_PAGE_SIZE, LINUX_PAGE_SIZE, 0, 0, 0]),
                ),
                &mut memory,
                &CompatReporter::default(),
            )
            .expect("hidden backing mremap dispatch");
        assert_eq!(outcome, DispatchOutcome::errno(LINUX_EFAULT));
        assert!(dispatcher.mem.lock().dynamic_maps.is_empty());
    }

    #[test]
    fn mremap_rejects_hidden_shared_and_private_aperture_boot_regions() {
        const SYS_MREMAP: u64 = 216;
        for (base, size, label) in [
            (
                crate::memory::LINUX_SHARED_FILE_BASE,
                crate::memory::LINUX_SHARED_FILE_SIZE,
                "hidden-shared-aperture",
            ),
            (
                crate::memory::LINUX_PRIVATE_OVERLAY_BASE,
                crate::memory::LINUX_PRIVATE_OVERLAY_SIZE,
                "hidden-private-overlay",
            ),
        ] {
            let mut dispatcher = SyscallDispatcher::new();
            dispatcher.set_address_space_regions(vec![ProcMapsEntry {
                start: base,
                end: base + size,
                read: true,
                write: true,
                execute: false,
                sharing: ProcMapSharing::Private,
                path: label.into(),
            }]);
            let mut memory = ProtectionTrackingMemory::new(base, LINUX_PAGE_SIZE as usize);
            let outcome = dispatcher
                .dispatch(
                    &dispatcher.capture_one_task_context().unwrap(),
                    SyscallRequest::new(
                        SYS_MREMAP,
                        SyscallArgs([base, LINUX_PAGE_SIZE, LINUX_PAGE_SIZE, 0, 0, 0]),
                    ),
                    &mut memory,
                    &CompatReporter::default(),
                )
                .expect("hidden aperture mremap dispatch");
            assert_eq!(outcome, DispatchOutcome::errno(LINUX_EFAULT), "{label}");
            assert!(dispatcher.mem.lock().dynamic_maps.is_empty(), "{label}");
        }
    }

    #[test]
    fn mremap_boot_heap_fallback_accepts_live_prefix_and_rejects_hidden_suffix() {
        const SYS_MREMAP: u64 = 216;
        let mut dispatcher = SyscallDispatcher::new();
        let layout = dispatcher.mem.lock().layout;
        dispatcher.set_address_space_regions(vec![ProcMapsEntry {
            start: layout.heap_base,
            end: layout.heap_base + layout.heap_size,
            read: true,
            write: true,
            execute: false,
            sharing: ProcMapSharing::Private,
            path: "hidden-heap-backing".into(),
        }]);
        dispatcher.mem.lock().brk_current = layout.heap_base + (2 * LINUX_PAGE_SIZE);
        let mut memory =
            ProtectionTrackingMemory::new(layout.heap_base, (4 * LINUX_PAGE_SIZE) as usize);
        let reporter = CompatReporter::default();

        let live = dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    SYS_MREMAP,
                    SyscallArgs([layout.heap_base, LINUX_PAGE_SIZE, LINUX_PAGE_SIZE, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .expect("live heap-prefix mremap");
        assert_eq!(
            live,
            DispatchOutcome::Returned {
                value: layout.heap_base as i64
            }
        );

        let hidden = dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    SYS_MREMAP,
                    SyscallArgs([
                        layout.heap_base + (2 * LINUX_PAGE_SIZE),
                        LINUX_PAGE_SIZE,
                        LINUX_PAGE_SIZE,
                        0,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .expect("hidden heap-suffix mremap");
        assert_eq!(hidden, DispatchOutcome::errno(LINUX_EFAULT));
        assert!(
            dispatcher
                .dynamic_mapping_for_test(layout.heap_base)
                .is_some()
        );
        assert!(
            dispatcher
                .dynamic_mapping_for_test(layout.heap_base + (2 * LINUX_PAGE_SIZE))
                .is_none()
        );
    }

    #[test]
    fn munmap_hole_cannot_fall_back_to_boot_metadata_during_mremap() {
        const SYS_MMAP: u64 = 222;
        const SYS_MUNMAP: u64 = 215;
        const SYS_MREMAP: u64 = 216;
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_address_space_regions(vec![ProcMapsEntry {
            start: LINUX_MMAP_BASE,
            end: LINUX_MMAP_BASE + (4 * LINUX_PAGE_SIZE),
            read: true,
            write: true,
            execute: false,
            sharing: ProcMapSharing::Private,
            path: "hidden-mmap-backing".into(),
        }]);
        let mut memory =
            ProtectionTrackingMemory::new(LINUX_MMAP_BASE, (4 * LINUX_PAGE_SIZE) as usize);
        let reporter = CompatReporter::default();
        let mapped = dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    SYS_MMAP,
                    SyscallArgs([
                        0,
                        LINUX_PAGE_SIZE,
                        LINUX_PROT_READ | LINUX_PROT_WRITE,
                        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                        u64::MAX,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .expect("mmap before hole regression");
        assert_eq!(returned(mapped), LINUX_MMAP_BASE as i64);
        let unmapped = dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    SYS_MUNMAP,
                    SyscallArgs([LINUX_MMAP_BASE, LINUX_PAGE_SIZE, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .expect("munmap before hole regression");
        assert_eq!(unmapped, DispatchOutcome::Returned { value: 0 });

        let remapped = dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    SYS_MREMAP,
                    SyscallArgs([LINUX_MMAP_BASE, LINUX_PAGE_SIZE, LINUX_PAGE_SIZE, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .expect("mremap of munmap hole");
        assert_eq!(remapped, DispatchOutcome::errno(LINUX_EFAULT));
        assert!(dispatcher.mem.lock().dynamic_maps.is_empty());
        assert!(
            memory
                .protections
                .range_unmapped(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize)
        );
    }

    #[test]
    fn shared_aperture_partial_and_shifted_sources_reject_before_backend_mutation() {
        const SYS_MMAP: u64 = 222;
        const SYS_MREMAP: u64 = 216;
        const OLD_LEN: u64 = 32 * 1024;
        const PREFIX_LEN: u64 = 16 * 1024;
        const NEW_LEN: u64 = 8 * 1024;

        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1073));
        let reporter = CompatReporter::default();
        let mut memory = ProtectionTrackingMemory::new(
            crate::memory::LINUX_SHARED_FILE_BASE,
            (OLD_LEN + LINUX_PAGE_SIZE) as usize,
        );
        let source = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    OLD_LEN,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MREMAP,
                SyscallArgs([source, PREFIX_LEN, NEW_LEN, 0, 0, 0]),
            ),
        );
        assert_eq!(outcome, DispatchOutcome::errno(LINUX_EFAULT));
        let suffix_outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MREMAP,
                SyscallArgs([source + PREFIX_LEN, PREFIX_LEN, NEW_LEN, 0, 0, 0]),
            ),
        );
        assert_eq!(suffix_outcome, DispatchOutcome::errno(LINUX_EFAULT));

        // Fabricate an exact VMA that starts inside the allocation and has the
        // same length as its owner. Without an explicit allocation-start check,
        // this shape passed the live_len test and released pages it did not own.
        dispatcher.remove_mapping_metadata(source, OLD_LEN);
        dispatcher.record_dynamic_mapping(
            source + LINUX_PAGE_SIZE,
            OLD_LEN,
            LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            ProcMapSharing::Shared,
            "shifted-shared-vma".into(),
        );
        let shifted_outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MREMAP,
                SyscallArgs([source + LINUX_PAGE_SIZE, OLD_LEN, PREFIX_LEN, 0, 0, 0]),
            ),
        );
        assert_eq!(shifted_outcome, DispatchOutcome::errno(LINUX_EFAULT));
        let mem = dispatcher.mem.lock();
        let alloc = mem
            .shared
            .live()
            .iter()
            .find(|alloc| alloc.guest_addr == source)
            .expect("whole shared allocation retained");
        assert_eq!(alloc.live_len, OLD_LEN);
        assert_eq!(alloc.len, OLD_LEN);
        assert!(!memory.protections.range_unmapped(source + NEW_LEN, 1));
    }

    #[test]
    fn odd_shared_mmap_tracks_logical_length_and_granule_reservation() {
        const SYS_MMAP: u64 = 222;
        const REQUESTED: u64 = 4097;
        const LOGICAL: u64 = 8192;
        const RESERVED: u64 = 16 * 1024;
        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1074));
        let mut memory =
            ProtectionTrackingMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, RESERVED as usize);
        let source = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &CompatReporter::default(),
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    REQUESTED,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;
        let mem = dispatcher.mem.lock();
        let alloc = mem
            .shared
            .live()
            .iter()
            .find(|alloc| alloc.guest_addr == source)
            .expect("odd shared allocation");
        assert_eq!(alloc.live_len, LOGICAL);
        assert_eq!(alloc.len, RESERVED);
        let map = mem
            .dynamic_maps
            .iter()
            .find(|map| map.start == source)
            .expect("odd logical VMA");
        assert_eq!(map.end - map.start, LOGICAL);
    }

    #[test]
    fn shared_mremap_shrink_unmap_failure_keeps_live_length_and_tail_accounting() {
        const SYS_MMAP: u64 = 222;
        const SYS_MREMAP: u64 = 216;

        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1072));
        let reporter = CompatReporter::default();
        let map_len = crate::trap::HVF_PAGE_SIZE * 2;
        let mut memory = DeferredSetterFailureMemory::new(
            crate::memory::LINUX_SHARED_FILE_BASE,
            map_len as usize,
        )
        .demand_paged()
        .fail_unmaps(1);
        let source = returned(threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    map_len,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        )) as u64;

        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MREMAP,
                SyscallArgs([source, map_len, crate::trap::HVF_PAGE_SIZE, 0, 0, 0]),
            ),
        );
        assert_eq!(outcome, DispatchOutcome::errno(LINUX_ENOMEM));
        {
            let mem = dispatcher.mem.lock();
            let alloc = mem
                .shared
                .live()
                .iter()
                .find(|alloc| alloc.guest_addr == source)
                .unwrap();
            assert_eq!(alloc.live_len, map_len);
            assert_eq!(alloc.len, map_len);
        }
        let next = {
            let mut mem = dispatcher.mem.lock();
            mem.shared
                .alloc(
                    crate::trap::HVF_PAGE_SIZE,
                    crate::shared_aperture::BackingObject::SharedAnon,
                )
                .expect("failed shrink must not free the tail for reuse")
        };
        assert_eq!(next, source + map_len);
    }

    #[test]
    fn demand_paged_shared_anon_keeps_best_effort_mapping_on_protection_failure() {
        const SYS_MMAP: u64 = 222;
        const LENGTH: u64 = 4096;
        const MAPPED_LENGTH: usize = crate::trap::HVF_PAGE_SIZE as usize;

        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1070));
        let reporter = CompatReporter::default();
        let mut memory =
            DeferredSetterFailureMemory::new(crate::memory::LINUX_SHARED_FILE_BASE, MAPPED_LENGTH)
                .demand_paged();
        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        );

        assert!(matches!(outcome, DispatchOutcome::Returned { .. }));
        assert_eq!(memory.protect_calls, 1);
        assert_eq!(
            memory.unmap_calls, 0,
            "demand-paged backend keeps reservation"
        );
        assert_eq!(dispatcher.mem.lock().dynamic_maps.len(), 1);
    }

    #[test]
    fn concurrent_exec_mmap_does_not_commit_consumed_protection_failure_outside_arena() {
        const SYS_MMAP: u64 = 222;
        const ADDRESS: u64 = 0x2000_0000;
        const LENGTH: u64 = 4096;

        let dispatcher = SyscallDispatcher::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1075));
        let reporter = CompatReporter::default();
        let mut memory = DeferredSetterFailureMemory::new(ADDRESS, LENGTH as usize);
        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    ADDRESS,
                    LENGTH,
                    LINUX_PROT_READ | LINUX_PROT_WRITE,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS | LINUX_MAP_FIXED,
                    u64::MAX,
                    0,
                ]),
            ),
        );

        assert_eq!(outcome, DispatchOutcome::errno(LINUX_ENOMEM));
        assert_eq!(
            memory.protect_calls, 1,
            "deferred failure consumed exactly once"
        );
        assert!(dispatcher.mem.lock().dynamic_maps.is_empty());
    }

    #[test]
    fn shared_anon_persistent_rollback_failure_aborts_concurrent_exec_backend() {
        const SYS_MMAP: u64 = 222;
        const LENGTH: u64 = 4096;
        const MAPPED_LENGTH: usize = crate::trap::HVF_PAGE_SIZE as usize;

        // SAFETY: the child owns an isolated dispatcher and intentionally takes
        // the fail-stop abort after two injected host-unmap failures.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let no_core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) };
            let dispatcher = SyscallDispatcher::new();
            let registry = crate::thread::ThreadRegistry::new(
                crate::thread::ThreadId::synthetic_for_tests(1080),
            );
            let reporter = CompatReporter::default();
            let mut memory = DeferredSetterFailureMemory::new(
                crate::memory::LINUX_SHARED_FILE_BASE,
                MAPPED_LENGTH,
            )
            .fail_unmaps(2);
            let _ = threaded_memory_call(
                &dispatcher,
                &mut memory,
                &registry,
                &reporter,
                SyscallRequest::new(
                    SYS_MMAP,
                    SyscallArgs([
                        0,
                        LENGTH,
                        LINUX_PROT_READ | LINUX_PROT_WRITE,
                        LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                        u64::MAX,
                        0,
                    ]),
                ),
            );
            unsafe { libc::_exit(92) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFSIGNALED(status));
        assert_eq!(libc::WTERMSIG(status), libc::SIGABRT);
    }

    #[test]
    fn native16k_rejects_multithreaded_write_exec_mmap() {
        const SYS_MMAP: u64 = 222;
        const PAGE_SIZE: u64 = 16 * 1024;

        let dispatcher = native16k_dispatcher();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1100));
        registry.register_child(0);
        let reporter = CompatReporter::default();
        let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, PAGE_SIZE as usize);
        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    0,
                    PAGE_SIZE,
                    LINUX_PROT_READ | LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        );

        assert_eq!(outcome, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
        assert_partial_reason(&reporter, "mmap", "multiple live guest threads");
    }

    #[test]
    fn native16k_rejects_write_exec_alias_mmap() {
        const SYS_MMAP: u64 = 222;
        const PAGE_SIZE: u64 = 16 * 1024;

        let dispatcher = native16k_dispatcher();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1150));
        let reporter = CompatReporter::default();
        let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, PAGE_SIZE as usize);
        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MMAP,
                SyscallArgs([
                    crate::memory::LINUX_HIGH_VA_THRESHOLD,
                    PAGE_SIZE,
                    LINUX_PROT_READ | LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC,
                    LINUX_MAP_FIXED | LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ]),
            ),
        );

        assert_eq!(outcome, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
        assert_partial_reason(&reporter, "mmap", "alias write-exec");
    }

    #[test]
    fn native16k_rejects_write_exec_alias_mprotect() {
        const SYS_MPROTECT: u64 = 226;
        const PAGE_SIZE: u64 = 16 * 1024;
        let address = crate::memory::LINUX_HIGH_VA_THRESHOLD;

        let dispatcher = native16k_dispatcher();
        dispatcher.record_dynamic_mapping(
            address,
            PAGE_SIZE,
            LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            ProcMapSharing::Private,
            String::new(),
        );
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1160));
        let reporter = CompatReporter::default();
        let mut memory = CountingMmapMemory::new(address, PAGE_SIZE as usize);
        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MPROTECT,
                SyscallArgs([
                    address,
                    PAGE_SIZE,
                    LINUX_PROT_READ | LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC,
                    0,
                    0,
                    0,
                ]),
            ),
        );

        assert_eq!(outcome, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
        assert_partial_reason(&reporter, "mprotect", "alias write-exec");
        assert_eq!(memory.protect_calls.get(), 0);
    }

    #[test]
    fn native16k_shared_provenance_survives_partial_mprotect() {
        const SYS_MPROTECT: u64 = 226;
        const PAGE_SIZE: u64 = 16 * 1024;
        const MAP_LEN: u64 = 3 * PAGE_SIZE;

        let dispatcher = native16k_dispatcher();
        dispatcher.record_dynamic_mapping(
            LINUX_MMAP_BASE,
            MAP_LEN,
            LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            ProcMapSharing::Shared,
            String::new(),
        );
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1175));
        let reporter = CompatReporter::default();
        let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, MAP_LEN as usize);

        let middle = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MPROTECT,
                SyscallArgs([
                    LINUX_MMAP_BASE + PAGE_SIZE,
                    PAGE_SIZE,
                    LINUX_PROT_READ,
                    0,
                    0,
                    0,
                ]),
            ),
        );
        assert_eq!(middle, DispatchOutcome::Returned { value: 0 });
        let maps = dispatcher.mem.lock().dynamic_maps.clone();
        assert_eq!(
            maps.len(),
            3,
            "partial mprotect must preserve VMA fragments"
        );
        assert!(
            maps.iter().all(|map| map.sharing == ProcMapSharing::Shared),
            "all fragments must retain shared provenance: {maps:?}"
        );

        let left_write_exec = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MPROTECT,
                SyscallArgs([
                    LINUX_MMAP_BASE,
                    PAGE_SIZE,
                    LINUX_PROT_READ | LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC,
                    0,
                    0,
                    0,
                ]),
            ),
        );
        assert_eq!(left_write_exec, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
        assert_partial_reason(&reporter, "mprotect", "shared write-exec");
    }

    #[test]
    fn native16k_rejects_multithreaded_exec_mprotect() {
        const SYS_MPROTECT: u64 = 226;
        const PAGE_SIZE: u64 = 16 * 1024;

        let dispatcher = native16k_dispatcher();
        dispatcher.record_dynamic_mapping(
            LINUX_MMAP_BASE,
            PAGE_SIZE,
            LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            ProcMapSharing::Private,
            String::new(),
        );
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1185));
        registry.register_child(0);
        let reporter = CompatReporter::default();
        let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, PAGE_SIZE as usize);
        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MPROTECT,
                SyscallArgs([
                    LINUX_MMAP_BASE,
                    PAGE_SIZE,
                    LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
                    0,
                    0,
                    0,
                ]),
            ),
        );

        assert_eq!(outcome, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
        assert_partial_reason(&reporter, "mprotect", "executable protection transition");
        assert_eq!(memory.protect_calls.get(), 0);
    }

    #[test]
    fn native16k_allows_multithreaded_exec_mprotect_for_translation_backend() {
        const SYS_MPROTECT: u64 = 226;
        const PAGE_SIZE: u64 = 16 * 1024;

        let dispatcher = native16k_dispatcher();
        dispatcher.record_dynamic_mapping(
            LINUX_MMAP_BASE,
            PAGE_SIZE,
            LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            ProcMapSharing::Private,
            String::new(),
        );
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1186));
        registry.register_child(0);
        let reporter = CompatReporter::default();
        let mut memory =
            ConcurrentExecMemory(CountingMmapMemory::new(LINUX_MMAP_BASE, PAGE_SIZE as usize));
        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MPROTECT,
                SyscallArgs([
                    LINUX_MMAP_BASE,
                    PAGE_SIZE,
                    LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
                    0,
                    0,
                    0,
                ]),
            ),
        );

        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
        assert_eq!(memory.0.protect_calls.get(), 1);
    }

    #[test]
    fn native16k_allows_private_alias_write_exec_for_translation_backend() {
        const SYS_MPROTECT: u64 = 226;
        const PAGE_SIZE: u64 = 16 * 1024;
        let address = crate::memory::LINUX_HIGH_VA_THRESHOLD;

        let dispatcher = native16k_dispatcher();
        dispatcher.record_dynamic_mapping(
            address,
            PAGE_SIZE,
            LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            ProcMapSharing::Private,
            String::new(),
        );
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1187));
        registry.register_child(0);
        let reporter = CompatReporter::default();
        let mut memory = ConcurrentExecMemory(CountingMmapMemory::new(address, PAGE_SIZE as usize));
        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MPROTECT,
                SyscallArgs([
                    address,
                    PAGE_SIZE,
                    LINUX_PROT_READ | LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC,
                    0,
                    0,
                    0,
                ]),
            ),
        );

        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
        assert_eq!(memory.0.protect_calls.get(), 1);
    }

    #[test]
    fn native16k_identity_mprotect_propagates_backend_failure() {
        const SYS_MPROTECT: u64 = 226;
        const PAGE_SIZE: u64 = 16 * 1024;

        let mut dispatcher = native16k_dispatcher();
        let reporter = CompatReporter::default();
        let mut memory = FailingProtectMemory {
            inner: CountingMmapMemory::new(LINUX_HEAP_BASE, PAGE_SIZE as usize),
        };
        let outcome = dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(
                    SYS_MPROTECT,
                    SyscallArgs([LINUX_HEAP_BASE, PAGE_SIZE, LINUX_PROT_READ, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .expect("identity mprotect dispatch");

        assert_eq!(outcome, DispatchOutcome::errno(LINUX_ENOMEM));
        assert_partial_reason(&reporter, "mprotect", "backend protection failure");
    }

    #[test]
    fn native16k_rejects_shared_write_exec_mprotect() {
        const SYS_MPROTECT: u64 = 226;
        const PAGE_SIZE: u64 = 16 * 1024;

        let dispatcher = native16k_dispatcher();
        dispatcher.record_dynamic_mapping(
            LINUX_MMAP_BASE,
            PAGE_SIZE,
            LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            ProcMapSharing::Shared,
            String::new(),
        );
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1200));
        let reporter = CompatReporter::default();
        let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, PAGE_SIZE as usize);
        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MPROTECT,
                SyscallArgs([
                    LINUX_MMAP_BASE,
                    PAGE_SIZE,
                    LINUX_PROT_READ | LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC,
                    0,
                    0,
                    0,
                ]),
            ),
        );

        assert_eq!(outcome, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
        assert_partial_reason(&reporter, "mprotect", "shared write-exec");
        assert_eq!(memory.protect_calls.get(), 0);
    }

    #[test]
    fn native16k_rejects_multithreaded_write_exec_mprotect() {
        const SYS_MPROTECT: u64 = 226;
        const PAGE_SIZE: u64 = 16 * 1024;

        let dispatcher = native16k_dispatcher();
        dispatcher.record_dynamic_mapping(
            LINUX_MMAP_BASE,
            PAGE_SIZE,
            LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            ProcMapSharing::Private,
            String::new(),
        );
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1300));
        registry.register_child(0);
        let reporter = CompatReporter::default();
        let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, PAGE_SIZE as usize);
        let outcome = threaded_memory_call(
            &dispatcher,
            &mut memory,
            &registry,
            &reporter,
            SyscallRequest::new(
                SYS_MPROTECT,
                SyscallArgs([
                    LINUX_MMAP_BASE,
                    PAGE_SIZE,
                    LINUX_PROT_READ | LINUX_PROT_WRITE | crate::linux_abi::LINUX_PROT_EXEC,
                    0,
                    0,
                    0,
                ]),
            ),
        );

        assert_eq!(outcome, DispatchOutcome::errno(LINUX_EOPNOTSUPP));
        assert_partial_reason(&reporter, "mprotect", "multiple live guest threads");
        assert_eq!(memory.protect_calls.get(), 0);
    }

    #[test]
    fn munmap_clears_read_only_tracking_before_writable_reuse() {
        const SYS_MMAP: u64 = 222;
        const SYS_MUNMAP: u64 = 215;
        const SYS_MPROTECT: u64 = 226;

        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = ProtectionTrackingMemory::new(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize);
        let reporter = CompatReporter::default();
        let read_only = SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                LINUX_PAGE_SIZE,
                LINUX_PROT_READ,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        );

        assert_eq!(
            returned(
                dispatcher
                    .dispatch(
                        &dispatcher.capture_one_task_context().unwrap(),
                        read_only,
                        &mut memory,
                        &reporter
                    )
                    .expect("read-only mmap dispatch")
            ),
            LINUX_MMAP_BASE as i64
        );
        assert!(
            memory
                .protections
                .range_no_write(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize)
        );

        let unmap = SyscallRequest::new(
            SYS_MUNMAP,
            SyscallArgs([LINUX_MMAP_BASE, LINUX_PAGE_SIZE, 0, 0, 0, 0]),
        );
        assert_eq!(
            dispatcher
                .dispatch(
                    &dispatcher.capture_one_task_context().unwrap(),
                    unmap,
                    &mut memory,
                    &reporter
                )
                .expect("munmap dispatch"),
            DispatchOutcome::Returned { value: 0 }
        );
        assert!(
            memory
                .protections
                .range_no_access(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize)
        );
        assert!(
            !memory
                .protections
                .range_no_write(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize),
            "an unmapped VA must not retain stale read-only VMA evidence"
        );
        assert_eq!(
            crate::vcpu_loop::upgrade_protection_si_code(
                &memory,
                crate::linux_abi::LINUX_SIGSEGV,
                1,
                LINUX_MMAP_BASE,
            ),
            1,
            "a post-munmap translation fault is SEGV_MAPERR, not a permission fault"
        );

        let protect_hole = SyscallRequest::new(
            SYS_MPROTECT,
            SyscallArgs([LINUX_MMAP_BASE, LINUX_PAGE_SIZE, LINUX_PROT_READ, 0, 0, 0]),
        );
        assert_eq!(
            dispatcher
                .dispatch(
                    &dispatcher.capture_one_task_context().unwrap(),
                    protect_hole,
                    &mut memory,
                    &reporter
                )
                .expect("mprotect post-munmap hole dispatch"),
            DispatchOutcome::errno(LINUX_ENOMEM),
            "retained host backing must not let mprotect resurrect an unmapped VMA"
        );
        assert!(
            memory
                .protections
                .range_unmapped(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize)
        );

        let writable = SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                LINUX_PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        );
        assert_eq!(
            returned(
                dispatcher
                    .dispatch(
                        &dispatcher.capture_one_task_context().unwrap(),
                        writable,
                        &mut memory,
                        &reporter
                    )
                    .expect("writable reuse mmap dispatch")
            ),
            LINUX_MMAP_BASE as i64
        );
        assert!(
            !memory
                .protections
                .range_no_access(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize)
        );
        assert!(
            !memory
                .protections
                .range_no_write(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize)
        );
    }

    #[test]
    fn free_regions_coalesce_adjacent() {
        let mut r = vec![];
        free_regions_insert(&mut r, 0x1000, 0x1000); // [0x1000,0x2000)
        free_regions_insert(&mut r, 0x3000, 0x1000); // [0x3000,0x4000)
        free_regions_insert(&mut r, 0x2000, 0x1000); // bridges → one [0x1000,0x4000)
        assert_eq!(r, vec![(0x1000, 0x3000)]);
    }

    #[test]
    fn guest_vma_occupancy_excludes_hidden_arenas_but_includes_live_ranges() {
        let dispatcher = SyscallDispatcher::new();
        let layout = dispatcher.mem.lock().layout;
        const BOOT: u64 = 0x20_0000_0000;
        dispatcher.set_address_space_regions(vec![
            ProcMapsEntry {
                start: layout.heap_base,
                end: layout.heap_base + layout.heap_size,
                read: true,
                write: true,
                execute: false,
                sharing: ProcMapSharing::Private,
                path: "heap-backing".into(),
            },
            ProcMapsEntry {
                start: layout.mmap_base,
                end: layout.mmap_base + layout.mmap_size,
                read: true,
                write: true,
                execute: true,
                sharing: ProcMapSharing::Private,
                path: "mmap-backing".into(),
            },
            ProcMapsEntry {
                start: BOOT,
                end: BOOT + LINUX_PAGE_SIZE,
                read: true,
                write: false,
                execute: true,
                sharing: ProcMapSharing::Private,
                path: "boot-text".into(),
            },
        ]);
        dispatcher.mem.lock().brk_current = layout.heap_base + LINUX_PAGE_SIZE;
        dispatcher.record_dynamic_mapping(
            layout.mmap_base + (2 * LINUX_PAGE_SIZE),
            LINUX_PAGE_SIZE,
            LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            ProcMapSharing::Private,
            String::new(),
        );

        assert!(dispatcher.guest_vma_overlaps(layout.heap_base, LINUX_PAGE_SIZE));
        assert!(
            !dispatcher.guest_vma_overlaps(layout.heap_base + LINUX_PAGE_SIZE, LINUX_PAGE_SIZE)
        );
        assert!(
            dispatcher
                .guest_vma_overlaps(layout.mmap_base + (2 * LINUX_PAGE_SIZE), LINUX_PAGE_SIZE)
        );
        assert!(!dispatcher.guest_vma_overlaps(layout.mmap_base, LINUX_PAGE_SIZE));
        assert!(dispatcher.guest_vma_overlaps(BOOT, LINUX_PAGE_SIZE));

        let snapshot = dispatcher
            .mem
            .snapshot_until(std::time::Instant::now() + std::time::Duration::from_secs(1))
            .expect("VMA authority snapshot");
        assert!(snapshot.vmas.contains(&crate::kernel::VmaSummary {
            start: GuestVa(layout.heap_base),
            end: GuestVa(layout.heap_base + LINUX_PAGE_SIZE),
        }));
        assert!(snapshot.vmas.contains(&crate::kernel::VmaSummary {
            start: GuestVa(layout.mmap_base + (2 * LINUX_PAGE_SIZE)),
            end: GuestVa(layout.mmap_base + (3 * LINUX_PAGE_SIZE)),
        }));
        assert!(snapshot.vmas.contains(&crate::kernel::VmaSummary {
            start: GuestVa(BOOT),
            end: GuestVa(BOOT + LINUX_PAGE_SIZE),
        }));
        assert!(!snapshot.vmas.iter().any(|vma| {
            vma.start == GuestVa(layout.mmap_base)
                || vma.end == GuestVa(layout.heap_base + layout.heap_size)
        }));
        assert!(
            snapshot
                .vmas
                .windows(2)
                .all(|rows| rows[0].end.raw() < rows[1].start.raw())
        );
    }

    #[test]
    fn vma_projection_preserves_adjacency_and_removes_unmapped_boot_ranges() {
        let dispatcher = SyscallDispatcher::new();
        dispatcher.set_address_space_regions(vec![
            ProcMapsEntry {
                start: 0x1000,
                end: 0x2000,
                read: true,
                write: false,
                execute: true,
                sharing: ProcMapSharing::Private,
                path: "text".to_owned(),
            },
            ProcMapsEntry {
                start: 0x2000,
                end: 0x3000,
                read: true,
                write: false,
                execute: false,
                sharing: ProcMapSharing::Private,
                path: "rodata".to_owned(),
            },
        ]);
        let before = dispatcher
            .mem
            .snapshot_until(std::time::Instant::now() + std::time::Duration::from_secs(1))
            .expect("adjacent VMA snapshot");
        assert_eq!(before.vmas.len(), 2);

        let vma_dispatch = dispatcher.begin_vma_dispatch();
        dispatcher.remove_mapping_metadata(0x1000, 0x1000);
        drop(vma_dispatch);
        let after = dispatcher
            .mem
            .snapshot_until(std::time::Instant::now() + std::time::Duration::from_secs(1))
            .expect("trimmed VMA snapshot");
        assert_eq!(
            after.vmas,
            vec![crate::kernel::VmaSummary {
                start: GuestVa(0x2000),
                end: GuestVa(0x3000),
            }]
        );
    }

    #[test]
    fn mem_authority_revises_once_per_published_vma_transaction() {
        let dispatcher = SyscallDispatcher::new();
        let initial = dispatcher.mem.vma_revision();

        let _layout = dispatcher.mem.lock().layout;
        dispatcher.mem.lock().linux_auxv_image.push(1);
        assert_eq!(dispatcher.mem.vma_revision(), initial);

        // Failed/no-op mapping paths take exclusion but never arm publication.
        drop(dispatcher.begin_conditional_vma_dispatch());
        assert_eq!(dispatcher.mem.vma_revision(), initial);

        let vma_dispatch = dispatcher.begin_vma_dispatch();
        dispatcher.mem.lock().brk_current += LINUX_PAGE_SIZE;
        drop(vma_dispatch);
        assert_eq!(
            dispatcher.mem.vma_revision(),
            initial.next().expect("revision")
        );

        let mut conditional = dispatcher.begin_conditional_vma_dispatch();
        dispatcher.mark_vma_dispatch(&mut conditional);
        drop(conditional);
        assert_eq!(
            dispatcher.mem.vma_revision(),
            initial
                .next()
                .and_then(crate::kernel::VmaRevision::next)
                .expect("second revision")
        );
    }

    #[test]
    fn revision_checked_publication_excludes_concurrent_vma_mutation() {
        let dispatcher = std::sync::Arc::new(SyscallDispatcher::new());
        let source = dispatcher.vma_snapshot_source();
        let expected = source.revision();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let acquired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (attempting_tx, attempting_rx) = std::sync::mpsc::sync_channel(0);
        let worker_dispatcher = std::sync::Arc::clone(&dispatcher);
        let worker_barrier = std::sync::Arc::clone(&barrier);
        let worker_acquired = std::sync::Arc::clone(&acquired);
        let worker = std::thread::spawn(move || {
            worker_barrier.wait();
            attempting_tx.send(()).expect("announce mutation attempt");
            let _guard = worker_dispatcher.begin_conditional_vma_dispatch();
            worker_acquired.store(true, std::sync::atomic::Ordering::Release);
        });

        source
            .publish_if_revision(
                expected,
                std::time::Instant::now() + std::time::Duration::from_secs(1),
                &mut || {
                    barrier.wait();
                    attempting_rx
                        .recv_timeout(std::time::Duration::from_secs(1))
                        .expect("mutation waiter reached acquisition");
                    let waiter_deadline =
                        std::time::Instant::now() + std::time::Duration::from_secs(1);
                    while dispatcher.host_alias_transactions.waiting_dispatchers() == 0 {
                        assert!(
                            std::time::Instant::now() < waiter_deadline,
                            "mutation thread never blocked on VMA exclusion"
                        );
                        std::thread::yield_now();
                    }
                    assert!(!acquired.load(std::sync::atomic::Ordering::Acquire));
                    Ok(())
                },
            )
            .expect("revision-checked publication");
        worker.join().expect("mutation waiter");
        assert!(acquired.load(std::sync::atomic::Ordering::Acquire));
    }

    #[test]
    fn growdown_metadata_is_trimmed_with_mapping_teardown() {
        let dispatcher = SyscallDispatcher::new();
        let page = dispatcher.linux_page_size();
        let start = 0x10_000;
        dispatcher.record_dynamic_mapping(
            start,
            page * 4,
            LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            ProcMapSharing::Private,
            "stack".to_owned(),
        );
        dispatcher.record_growdown_mapping(start, page * 4);
        let plan = dispatcher
            .mmap_growdown_fault_plan(start - page)
            .expect("grow-down plan");
        dispatcher.commit_mmap_growdown(plan);

        let vma_dispatch = dispatcher.begin_vma_dispatch();
        dispatcher.remove_mapping_metadata(start + page, page);
        drop(vma_dispatch);
        let split = dispatcher
            .vma_snapshot_source()
            .snapshot(std::time::Instant::now() + std::time::Duration::from_secs(1))
            .expect("split grow-down snapshot");
        assert_eq!(
            split.vmas,
            vec![
                crate::kernel::VmaSummary {
                    start: GuestVa(start - page),
                    end: GuestVa(start + page),
                },
                crate::kernel::VmaSummary {
                    start: GuestVa(start + page * 2),
                    end: GuestVa(start + page * 4),
                },
            ]
        );

        let vma_dispatch = dispatcher.begin_vma_dispatch();
        dispatcher.remove_mapping_metadata(start - page, page * 2);
        drop(vma_dispatch);
        assert!(
            dispatcher
                .mmap_growdown_fault_plan(start - page * 2)
                .is_none()
        );
        let retired = dispatcher
            .vma_snapshot_source()
            .snapshot(std::time::Instant::now() + std::time::Duration::from_secs(1))
            .expect("retired grow-down snapshot");
        assert_eq!(
            retired.vmas,
            vec![crate::kernel::VmaSummary {
                start: GuestVa(start + page * 2),
                end: GuestVa(start + page * 4),
            }]
        );
    }

    #[test]
    fn mem_authority_fork_is_independent_after_one_existing_state_clone() {
        let parent = SyscallDispatcher::new();
        let layout = parent.mem.lock().layout;
        let parent_vma_dispatch = parent.begin_vma_dispatch();
        parent.mem.lock().brk_current = layout.heap_base + LINUX_PAGE_SIZE;
        drop(parent_vma_dispatch);
        let parent_revision = parent.mem.vma_revision();
        let child = parent.fork_clone_in_process(
            crate::thread::ThreadId::synthetic_for_tests(71),
            crate::thread::ThreadId::synthetic_for_tests(72),
            71,
            72,
        );

        assert!(!std::sync::Arc::ptr_eq(&parent.mem, &child.mem));
        assert_eq!(child.mem.vma_revision(), parent_revision);
        let child_vma_dispatch = child.begin_vma_dispatch();
        child.mem.lock().brk_current += LINUX_PAGE_SIZE;
        drop(child_vma_dispatch);
        assert_eq!(
            parent.mem.lock().brk_current,
            layout.heap_base + LINUX_PAGE_SIZE
        );
        assert_eq!(parent.mem.vma_revision(), parent_revision);
        assert_eq!(
            child.mem.vma_revision(),
            parent_revision.next().expect("child revision")
        );
    }

    #[test]
    fn mem_authority_snapshot_honors_deadline_contention() {
        let dispatcher = std::sync::Arc::new(SyscallDispatcher::new());
        let source = dispatcher.vma_snapshot_source();
        let held = std::sync::Arc::clone(&dispatcher);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let worker_barrier = std::sync::Arc::clone(&barrier);
        let worker = std::thread::spawn(move || {
            let _dispatch = held.begin_vma_dispatch();
            worker_barrier.wait();
            std::thread::sleep(std::time::Duration::from_millis(40));
        });
        barrier.wait();

        assert_eq!(
            source.snapshot(std::time::Instant::now() + std::time::Duration::from_millis(5)),
            Err(crate::kernel::SnapshotError::TimedOut)
        );
        worker.join().expect("authority lock worker");
    }

    #[test]
    fn dynamic_mapping_overlap_uses_sorted_boundaries() {
        let maps = vec![
            ProcMapsEntry {
                start: 0x1000,
                end: 0x2000,
                read: true,
                write: false,
                execute: false,
                sharing: ProcMapSharing::Private,
                path: String::new(),
            },
            ProcMapsEntry {
                start: 0x4000,
                end: 0x5000,
                read: true,
                write: false,
                execute: false,
                sharing: ProcMapSharing::Private,
                path: String::new(),
            },
        ];

        assert!(!dynamic_mapping_overlaps_sorted(&maps, 0x2000, 0x2000));
        assert!(dynamic_mapping_overlaps_sorted(&maps, 0x1fff, 1));
        assert!(dynamic_mapping_overlaps_sorted(&maps, 0x3000, 0x1001));
    }

    #[test]
    fn trim_dynamic_maps_preserves_sorted_order_without_full_resort() {
        let mut maps = vec![
            ProcMapsEntry {
                start: 0x1000,
                end: 0x5000,
                read: true,
                write: true,
                execute: false,
                sharing: ProcMapSharing::Private,
                path: String::new(),
            },
            ProcMapsEntry {
                start: 0x8000,
                end: 0x9000,
                read: true,
                write: false,
                execute: false,
                sharing: ProcMapSharing::Private,
                path: String::new(),
            },
        ];

        trim_dynamic_maps_for_range(&mut maps, 0x2000, 0x2000);

        let ranges: Vec<(u64, u64)> = maps.iter().map(|map| (map.start, map.end)).collect();
        assert_eq!(
            ranges,
            vec![(0x1000, 0x2000), (0x4000, 0x5000), (0x8000, 0x9000)]
        );
    }

    #[test]
    fn mincore_onfault_lock_is_not_resident_until_page_is_touched() {
        let dispatcher = SyscallDispatcher::new();
        let base = LINUX_MMAP_BASE;
        let length = 2 * LINUX_PAGE_SIZE;
        dispatcher.record_dynamic_mapping(
            base,
            length,
            LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            ProcMapSharing::Shared,
            String::new(),
        );
        let range =
            crate::vfs::GuestMemoryRange::new(GuestVa(base), GuestVa(base.saturating_add(length)))
                .expect("valid locked range");
        locked_ranges_insert(&mut dispatcher.mem.lock().locked_ranges, range);
        let memory = LinearMemory::new(base, vec![0; length as usize]);

        assert_eq!(
            dispatcher.mincore_residency_vector(&memory, base, 2, LINUX_PAGE_SIZE),
            Some(vec![0, 0]),
            "MLOCK_ONFAULT accounting alone must not make pages resident"
        );

        dispatcher.mark_range_resident(base, LINUX_PAGE_SIZE);
        assert_eq!(
            dispatcher.mincore_residency_vector(&memory, base, 2, LINUX_PAGE_SIZE),
            Some(vec![1, 0]),
            "only the populated page becomes resident"
        );
    }

    #[test]
    fn eager_lock_paths_populate_mincore_residency() {
        let base = LINUX_MMAP_BASE;
        let length = 2 * LINUX_PAGE_SIZE;
        let range =
            crate::vfs::GuestMemoryRange::new(GuestVa(base), GuestVa(base.saturating_add(length)))
                .expect("valid locked range");
        let mut memory = LinearMemory::new(base, vec![0; length as usize]);

        let map_locked = SyscallDispatcher::new();
        map_locked.record_dynamic_mapping(
            base,
            length,
            LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            ProcMapSharing::Private,
            String::new(),
        );
        map_locked
            .commit_mmap_locked_range(&mut memory, Some(range))
            .expect("populate MAP_LOCKED range");
        assert_eq!(
            map_locked.mincore_residency_vector(&memory, base, 2, LINUX_PAGE_SIZE),
            Some(vec![1, 1]),
            "MAP_LOCKED must populate the mapping"
        );

        let mlockall = SyscallDispatcher::new();
        mlockall.record_dynamic_mapping(
            base,
            length,
            LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            ProcMapSharing::Private,
            String::new(),
        );
        mlockall
            .lock_current_mappings(&mut memory, false)
            .expect("populate MCL_CURRENT mappings");
        assert_eq!(
            mlockall.mincore_residency_vector(&memory, base, 2, LINUX_PAGE_SIZE),
            Some(vec![1, 1]),
            "MCL_CURRENT without MCL_ONFAULT must populate current mappings"
        );

        let alias_locked = SyscallDispatcher::new();
        alias_locked.commit_eager_locked_range(Some(range));
        alias_locked.record_dynamic_mapping(
            base,
            length,
            LinuxProtFlags::READ,
            ProcMapSharing::Shared,
            String::new(),
        );
        assert_eq!(
            alias_locked.mincore_residency_vector(&memory, base, 2, LINUX_PAGE_SIZE),
            Some(vec![1, 1]),
            "deferred host aliases must publish eager MAP_LOCKED residency"
        );
    }

    // mincore (syscall 232) failure-arm guards: a guest-controlled `length` must
    // never drive the residency-vec allocation past the actual mapping (the
    // `vec![1u8; pages]` is uncatchable on alloc failure). Both arms must report
    // ENOMEM (errno 12), never panic/abort. The success path is covered by the
    // integration test `mm_lock_msync_mincore_stubs_validate_args_and_succeed`.
    fn mincore(memory: &mut impl GuestMemory, address: u64, length: u64) -> DispatchOutcome {
        let reporter = CompatReporter::default();
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(232, SyscallArgs::from([address, length, address, 0, 0, 0])),
                memory,
                &reporter,
            )
            .expect("mincore dispatch must not be a fatal DispatchError")
    }

    struct GapMemory {
        base: u64,
    }

    impl GapMemory {
        fn page_is_mapped(&self, address: u64, length: usize) -> bool {
            let Some(end) = address.checked_add(length as u64) else {
                return false;
            };
            let first_start = self.base;
            let first_end = self.base + LINUX_PAGE_SIZE;
            let last_start = self.base + 2 * LINUX_PAGE_SIZE;
            let last_end = self.base + 3 * LINUX_PAGE_SIZE;
            (address >= first_start && end <= first_end)
                || (address >= last_start && end <= last_end)
        }
    }

    impl GuestMemory for GapMemory {
        fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
            if self.page_is_mapped(address, length) {
                Ok(vec![0; length])
            } else {
                Err(MemoryError::OutOfBounds { address, length })
            }
        }

        fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            if self.page_is_mapped(address, bytes.len()) {
                Ok(())
            } else {
                Err(MemoryError::OutOfBounds {
                    address,
                    length: bytes.len(),
                })
            }
        }
    }

    #[test]
    fn mincore_unmapped_end_page_is_enomem_not_abort() {
        // One mapped page at the base; a length that spans into the unmapped next
        // page must be ENOMEM — Linux requires the WHOLE range mapped, and the
        // unmapped end caps the residency-vec bound.
        let base = LINUX_MMAP_BASE;
        let mut memory = LinearMemory::new(base, vec![0u8; LINUX_PAGE_SIZE as usize]);
        assert_eq!(
            mincore(&mut memory, base, 2 * LINUX_PAGE_SIZE),
            DispatchOutcome::Errno {
                errno: LinuxErrno::new(12),
            },
            "a range whose end page is unmapped must be ENOMEM"
        );
    }

    #[test]
    fn mincore_mapped_first_and_last_with_hole_is_enomem() {
        let base = LINUX_MMAP_BASE;
        let mut memory = GapMemory { base };
        assert_eq!(
            mincore(&mut memory, base, 3 * LINUX_PAGE_SIZE),
            DispatchOutcome::Errno {
                errno: LinuxErrno::new(12),
            },
            "a range with a mapped first and last page but an unmapped middle page must be ENOMEM"
        );
    }

    #[test]
    fn mincore_overflowing_length_is_enomem_not_abort() {
        // address + length overflows u64: the bound guard must turn this into
        // ENOMEM rather than computing a u64::MAX-page residency vec (an
        // uncatchable allocation abort).
        let base = LINUX_MMAP_BASE;
        let mut memory = LinearMemory::new(base, vec![0u8; LINUX_PAGE_SIZE as usize]);
        assert_eq!(
            mincore(&mut memory, base, u64::MAX),
            DispatchOutcome::Errno {
                errno: LinuxErrno::new(12),
            },
            "a length that overflows the [address, address+length) range must be ENOMEM"
        );
    }

    #[test]
    fn free_regions_coalesce_overlap_and_keep_disjoint() {
        let mut r = vec![];
        free_regions_insert(&mut r, 0x1000, 0x2000); // [0x1000,0x3000)
        free_regions_insert(&mut r, 0x2000, 0x2000); // overlaps → [0x1000,0x4000)
        free_regions_insert(&mut r, 0x9000, 0x1000); // disjoint
        assert_eq!(r, vec![(0x1000, 0x3000), (0x9000, 0x1000)]);
    }

    #[test]
    fn next_mmap_address_reuses_freed_arena_region() {
        let dispatcher = SyscallDispatcher::new();
        let freed = LINUX_MMAP_BASE + (4 * LINUX_PAGE_SIZE);
        {
            let mut mem = dispatcher.mem.lock();
            free_regions_insert(&mut mem.free_regions, freed, 2 * LINUX_PAGE_SIZE);
        }

        let first = dispatcher.next_mmap_address(0, LINUX_PAGE_SIZE, 0, 0);
        assert_eq!(first, Some((freed, true)));

        let second = dispatcher.next_mmap_address(0, LINUX_PAGE_SIZE, 0, 0);
        assert_eq!(second, Some((freed + LINUX_PAGE_SIZE, true)));

        assert!(dispatcher.mem.lock().free_regions.is_empty());
    }

    #[test]
    fn reset_memory_state_on_execve_resets_arenas_and_preserves_auxv_snapshot() {
        let dispatcher = SyscallDispatcher::new();
        dispatcher.set_auxv_image(vec![1, 2, 3, 4]);
        {
            let mut mem = dispatcher.mem.lock();
            mem.brk_current = LINUX_HEAP_BASE + 0x21000;
            mem.mmap_next = LINUX_MMAP_BASE + 0x8000;
            mem.mmap_dirty_high = LINUX_MMAP_BASE + 0x9000;
            free_regions_insert(&mut mem.free_regions, LINUX_MMAP_BASE + 0x1000, 0x1000);
        }

        dispatcher.reset_memory_state_on_execve();

        {
            let mem = dispatcher.mem.lock();
            assert_eq!(mem.brk_current, LINUX_HEAP_BASE);
            assert_eq!(mem.mmap_next, LINUX_MMAP_BASE);
            assert_eq!(mem.mmap_dirty_high, LINUX_MMAP_BASE);
            assert!(mem.free_regions.is_empty());
            assert_eq!(mem.linux_auxv_image, vec![1, 2, 3, 4]);
        }
        assert_eq!(
            dispatcher.next_mmap_address(0, LINUX_PAGE_SIZE, 0, 0),
            Some((LINUX_MMAP_BASE, false))
        );
    }

    #[test]
    fn brk_shrink_scrubs_backing_before_regrowth() {
        const SYS_BRK: u64 = 214;
        const PAGES: u64 = 3;

        let mut dispatcher = SyscallDispatcher::new();
        let initial = dispatcher.mem.lock().layout.heap_base;
        let grown = initial + PAGES * LINUX_PAGE_SIZE;
        dispatcher.mem.lock().brk_current = grown;

        let mut memory = CountingMmapMemory::new(initial, (PAGES * LINUX_PAGE_SIZE) as usize);
        memory.bytes.fill(0xa5);
        let reporter = CompatReporter::default();
        let shrink = SyscallRequest::new(SYS_BRK, SyscallArgs([initial, 0, 0, 0, 0, 0]));

        let outcome = dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                shrink,
                &mut memory,
                &reporter,
            )
            .expect("brk shrink dispatch should succeed");

        assert_eq!(returned(outcome), initial as i64);
        assert_eq!(memory.zero_backing_calls.get(), 1);
        assert!(
            memory.bytes.iter().all(|byte| *byte == 0),
            "a later brk growth must not re-expose stale heap bytes"
        );
    }

    #[test]
    fn fresh_private_anonymous_mmap_skips_zero_write() {
        const SYS_MMAP: u64 = 222;

        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize);
        let reporter = CompatReporter::default();
        let request = SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                LINUX_PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        );

        let outcome = dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                request,
                &mut memory,
                &reporter,
            )
            .expect("mmap dispatch should succeed");

        assert_eq!(returned(outcome), LINUX_MMAP_BASE as i64);
        assert_eq!(
            memory.write_calls.get(),
            0,
            "fresh anonymous mmap should rely on lazy-zero backing, not write a zero buffer"
        );
        assert_eq!(memory.write_bytes_total.get(), 0);
        assert_eq!(memory.zero_backing_calls.get(), 0);
        assert_eq!(
            memory.protect_calls.get(),
            1,
            "fresh mapping should still install the requested guest protection"
        );
    }

    #[test]
    fn reused_private_anonymous_mmap_zeroes_backing_without_zero_write() {
        const SYS_MMAP: u64 = 222;

        let mut dispatcher = SyscallDispatcher::new();
        {
            let mut mem = dispatcher.mem.lock();
            free_regions_insert(&mut mem.free_regions, LINUX_MMAP_BASE, LINUX_PAGE_SIZE);
        }
        let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize);
        memory.bytes.fill(0x5a);
        let reporter = CompatReporter::default();
        let request = SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                LINUX_PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        );

        let outcome = dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                request,
                &mut memory,
                &reporter,
            )
            .expect("mmap dispatch should succeed");

        assert_eq!(returned(outcome), LINUX_MMAP_BASE as i64);
        assert_eq!(
            memory.zero_backing_calls.get(),
            1,
            "reused anonymous mmap must scrub stale physical backing"
        );
        assert_eq!(
            memory.write_calls.get(),
            0,
            "zero_backing should be the only scrub path for reused anonymous mmap"
        );
        assert!(
            memory
                .read_bytes(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize)
                .unwrap()
                .iter()
                .all(|byte| *byte == 0),
            "stale bytes must not remain visible after reuse"
        );
        assert_eq!(
            memory.protect_calls.get(),
            1,
            "reused mapping should still install the requested guest protection"
        );
    }

    #[test]
    fn range_owned_metadata_removal_clears_every_mmap_classification() {
        let dispatcher = SyscallDispatcher::new();
        let start = crate::memory::LINUX_HIGH_VA_THRESHOLD;
        let len = 2 * LINUX_PAGE_SIZE;
        let range = crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start + len))
            .expect("metadata range");
        let writable_memfd =
            std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::SyntheticFile {
                base: OpenDescriptionBase::new(0),
                path: "memfd:metadata-remove".into(),
                contents: Vec::new(),
                offset: 0,
            }));
        dispatcher.record_dynamic_mapping(
            start,
            len,
            LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            ProcMapSharing::Shared,
            String::new(),
        );
        {
            let mut mem = dispatcher.mem.lock();
            mem.remap_snapshots.insert(start, vec![0; len as usize]);
            mem.bus_fault_ranges.push((start, len));
            locked_ranges_insert(&mut mem.locked_ranges, range);
            locked_ranges_insert(&mut mem.resident_ranges, range);
            locked_ranges_insert(&mut mem.resident_tracked_ranges, range);
            mem.resident_fault_ranges.push(ResidentFaultRange {
                range,
                prot: LinuxProtFlags::READ,
            });
            locked_ranges_insert(&mut mem.write_sealed_shared_maps, range);
            mem.writable_memfd_maps.push((range, writable_memfd));
        }
        assert!(dispatcher.range_has_mapping_metadata_for_test(start, len));

        dispatcher.remove_mapping_metadata(start, len);

        assert!(!dispatcher.range_has_mapping_metadata_for_test(start, len));
    }

    #[test]
    fn replacement_commit_trims_every_predecessor_classification_to_prefix_and_suffix() {
        let dispatcher = SyscallDispatcher::new();
        let start = crate::memory::LINUX_HIGH_VA_THRESHOLD;
        let page = LINUX_PAGE_SIZE;
        let len = 3 * page;
        let middle = start + page;
        let whole = crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start + len))
            .expect("whole predecessor range");
        let writable_memfd =
            std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::SyntheticFile {
                base: OpenDescriptionBase::new(0),
                path: "memfd:split-predecessor".into(),
                contents: Vec::new(),
                offset: 0,
            }));
        dispatcher.record_dynamic_mapping(
            start,
            len,
            LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            ProcMapSharing::Shared,
            "predecessor".into(),
        );
        {
            let mut mem = dispatcher.mem.lock();
            let mut snapshot = vec![0x11; page as usize];
            snapshot.extend(std::iter::repeat_n(0x22, page as usize));
            snapshot.extend(std::iter::repeat_n(0x33, page as usize));
            mem.remap_snapshots.insert(start, snapshot);
            mem.bus_fault_ranges.push((start, len));
            locked_ranges_insert(&mut mem.locked_ranges, whole);
            locked_ranges_insert(&mut mem.resident_ranges, whole);
            locked_ranges_insert(&mut mem.resident_tracked_ranges, whole);
            mem.resident_fault_ranges.push(ResidentFaultRange {
                range: whole,
                prot: LinuxProtFlags::READ,
            });
            locked_ranges_insert(&mut mem.write_sealed_shared_maps, whole);
            mem.writable_memfd_maps
                .push((whole, std::sync::Arc::clone(&writable_memfd)));
        }

        dispatcher.commit_host_alias_mmap(HostAliasMmapCommit {
            start: middle,
            len: page,
            prot: LinuxProtFlags::READ | LinuxProtFlags::EXEC,
            sharing: ProcMapSharing::Private,
            path: "replacement".into(),
            locked: None,
            resident: false,
            bus_fault: None,
            write_sealed_shared: false,
            writable_memfd: None,
        });

        let mem = dispatcher.mem.lock();
        assert_eq!(mem.dynamic_maps.len(), 3);
        assert_eq!(
            mem.dynamic_maps
                .iter()
                .map(|map| (map.start, map.end, map.path.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (start, middle, "predecessor"),
                (middle, middle + page, "replacement"),
                (middle + page, start + len, "predecessor"),
            ]
        );
        assert_eq!(
            mem.bus_fault_ranges,
            vec![(start, page), (middle + page, page)]
        );
        let expected_ranges = vec![
            crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(middle)).expect("prefix"),
            crate::vfs::GuestMemoryRange::new(GuestVa(middle + page), GuestVa(start + len))
                .expect("suffix"),
        ];
        assert_eq!(mem.locked_ranges, expected_ranges);
        assert_eq!(mem.resident_ranges, expected_ranges);
        assert_eq!(mem.resident_tracked_ranges, expected_ranges);
        assert_eq!(mem.write_sealed_shared_maps, expected_ranges);
        assert_eq!(mem.resident_fault_ranges.len(), 2);
        assert_eq!(mem.resident_fault_ranges[0].range, expected_ranges[0]);
        assert_eq!(mem.resident_fault_ranges[1].range, expected_ranges[1]);
        assert!(
            mem.resident_fault_ranges
                .iter()
                .all(|fault| fault.prot == LinuxProtFlags::READ)
        );
        assert_eq!(mem.writable_memfd_maps.len(), 2);
        assert_eq!(mem.writable_memfd_maps[0].0, expected_ranges[0]);
        assert_eq!(mem.writable_memfd_maps[1].0, expected_ranges[1]);
        assert!(
            mem.writable_memfd_maps
                .iter()
                .all(|(_, description)| std::sync::Arc::ptr_eq(description, &writable_memfd))
        );
        assert_eq!(mem.remap_snapshots.len(), 2);
        assert_eq!(
            mem.remap_snapshots.get(&start).map(Vec::as_slice),
            Some(vec![0x11; page as usize].as_slice())
        );
        assert_eq!(
            mem.remap_snapshots.get(&(middle + page)).map(Vec::as_slice),
            Some(vec![0x33; page as usize].as_slice())
        );
    }

    #[test]
    fn host_alias_abort_preserves_replaced_vma_lock_residency_bus_and_seal_metadata() {
        let dispatcher = SyscallDispatcher::new();
        let start = crate::memory::LINUX_HIGH_VA_THRESHOLD;
        let len = LINUX_PAGE_SIZE * 2;
        let replacement = crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start + len))
            .expect("replacement range");
        dispatcher.record_dynamic_mapping(
            start,
            len,
            LinuxProtFlags::READ | LinuxProtFlags::EXEC,
            ProcMapSharing::Private,
            "prior".to_string(),
        );
        let writable_memfd =
            std::sync::Arc::new(parking_lot::RwLock::new(OpenDescription::SyntheticFile {
                base: OpenDescriptionBase::new(0),
                path: "memfd:test".into(),
                contents: Vec::new(),
                offset: 0,
            }));
        {
            let mut mem = dispatcher.mem.lock();
            locked_ranges_insert(&mut mem.locked_ranges, replacement);
            locked_ranges_insert(&mut mem.resident_ranges, replacement);
            locked_ranges_insert(&mut mem.write_sealed_shared_maps, replacement);
            mem.writable_memfd_maps
                .push((replacement, std::sync::Arc::clone(&writable_memfd)));
            mem.bus_fault_ranges
                .push((start + LINUX_PAGE_SIZE, LINUX_PAGE_SIZE));
        }
        let before = dispatcher.mem.lock().clone();
        let vma_source = dispatcher.vma_snapshot_source();
        let guard = dispatcher.begin_host_alias_dispatch();
        let transaction = guard.publish(HostAliasCommit::mmap(HostAliasMmapCommit {
            start,
            len,
            prot: LinuxProtFlags::READ | LinuxProtFlags::WRITE,
            sharing: ProcMapSharing::Shared,
            path: "replacement".to_string(),
            locked: None,
            resident: false,
            bus_fault: None,
            write_sealed_shared: false,
            writable_memfd: None,
        }));

        assert_eq!(
            vma_source.snapshot(std::time::Instant::now() + std::time::Duration::from_millis(5)),
            Err(crate::kernel::SnapshotError::TimedOut)
        );
        let pending = dispatcher.mem.lock().clone();
        assert_eq!(pending.dynamic_maps, before.dynamic_maps);
        assert_eq!(pending.locked_ranges, before.locked_ranges);
        assert_eq!(pending.resident_ranges, before.resident_ranges);
        assert_eq!(pending.bus_fault_ranges, before.bus_fault_ranges);
        assert_eq!(
            pending.write_sealed_shared_maps,
            before.write_sealed_shared_maps
        );
        assert_eq!(pending.writable_memfd_maps.len(), 1);
        assert!(std::sync::Arc::ptr_eq(
            &pending.writable_memfd_maps[0].1,
            &writable_memfd
        ));
        let install = transaction
            .claim()
            .expect("claim pending host alias install");
        drop(install);

        let after = dispatcher.mem.lock().clone();
        assert_eq!(after.dynamic_maps, before.dynamic_maps);
        assert_eq!(after.locked_ranges, before.locked_ranges);
        assert_eq!(after.resident_ranges, before.resident_ranges);
        assert_eq!(after.bus_fault_ranges, before.bus_fault_ranges);
        assert_eq!(
            after.write_sealed_shared_maps,
            before.write_sealed_shared_maps
        );
        assert_eq!(after.writable_memfd_maps.len(), 1);
        assert!(std::sync::Arc::ptr_eq(
            &after.writable_memfd_maps[0].1,
            &writable_memfd
        ));
    }

    #[test]
    fn pending_host_alias_transaction_drop_aborts_and_notifies_waiters() {
        let dispatcher = std::sync::Arc::new(SyscallDispatcher::new());
        let guard = dispatcher.begin_host_alias_dispatch();
        let transaction = guard.publish(HostAliasCommit::mmap(HostAliasMmapCommit {
            start: crate::memory::LINUX_HIGH_VA_THRESHOLD,
            len: LINUX_PAGE_SIZE,
            prot: LinuxProtFlags::READ,
            sharing: ProcMapSharing::Private,
            path: String::new(),
            locked: None,
            resident: false,
            bus_fault: None,
            write_sealed_shared: false,
            writable_memfd: None,
        }));
        let sibling = std::sync::Arc::clone(&dispatcher);
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            started_tx.send(()).expect("report pending waiter start");
            let _guard = sibling.begin_host_alias_dispatch();
            entered_tx
                .send(())
                .expect("report pending waiter admission");
        });
        started_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("pending waiter reached exclusion");
        assert!(
            entered_rx
                .recv_timeout(std::time::Duration::from_millis(25))
                .is_err(),
            "pending transaction did not exclude a sibling"
        );
        drop(transaction);
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("pending transaction Drop notified sibling");
        thread.join().expect("join pending transaction waiter");
    }

    #[test]
    fn dropping_unconsumed_host_alias_outcome_closes_fd_and_aborts_transaction() {
        let dispatcher = SyscallDispatcher::new();
        let guard = dispatcher.begin_host_alias_dispatch();
        let transaction = guard.publish(HostAliasCommit::mmap(HostAliasMmapCommit {
            start: crate::memory::LINUX_HIGH_VA_THRESHOLD,
            len: LINUX_PAGE_SIZE,
            prot: LinuxProtFlags::READ,
            sharing: ProcMapSharing::Shared,
            path: String::new(),
            locked: None,
            resident: false,
            bus_fault: None,
            write_sealed_shared: false,
            writable_memfd: None,
        }));
        let mut pipe = [-1; 2];
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        let read_fd = pipe[0];
        let outcome = DispatchOutcome::MapHostAlias {
            transaction,
            va: GuestVa(crate::memory::LINUX_HIGH_VA_THRESHOLD),
            ipa: Gpa(crate::memory::LINUX_ALIAS_IPA_BASE),
            len: LINUX_PAGE_SIZE,
            payload: Vec::new(),
            file: Some((
                // SAFETY: the successful pipe read end is uniquely transferred.
                unsafe { HostAliasOwnedFd::from_raw_fd(read_fd) },
                0,
                libc::PROT_READ,
            )),
            shared: true,
            prot: crate::linux_abi::LINUX_PROT_READ,
            prot_none: false,
        };

        drop(outcome);
        assert_eq!(unsafe { libc::fcntl(read_fd, libc::F_GETFD) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
        assert_eq!(unsafe { libc::close(pipe[1]) }, 0);
        // Drop of the transaction handle also returned the exclusion to Idle.
        drop(dispatcher.begin_host_alias_dispatch());
    }

    #[test]
    fn installing_host_alias_blocks_sibling_mapping_dispatch_until_resolution() {
        let dispatcher = std::sync::Arc::new(SyscallDispatcher::new());
        let guard = dispatcher.begin_host_alias_dispatch();
        let transaction = guard.publish(HostAliasCommit::mmap(HostAliasMmapCommit {
            start: crate::memory::LINUX_HIGH_VA_THRESHOLD,
            len: LINUX_PAGE_SIZE,
            prot: LinuxProtFlags::READ,
            sharing: ProcMapSharing::Private,
            path: String::new(),
            locked: None,
            resident: false,
            bus_fault: None,
            write_sealed_shared: false,
            writable_memfd: None,
        }));
        let install = transaction
            .claim()
            .expect("claim pending host alias install");
        let sibling = std::sync::Arc::clone(&dispatcher);
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            started_tx.send(()).expect("report install waiter start");
            let _guard = sibling.begin_host_alias_dispatch();
            entered_tx.send(()).expect("report mapping admission");
        });
        started_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("install waiter reached exclusion");
        assert!(
            entered_rx
                .recv_timeout(std::time::Duration::from_millis(25))
                .is_err(),
            "sibling mapping dispatch raced an installing host alias"
        );
        drop(install);
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("sibling admitted after abort");
        thread.join().expect("join sibling mapping dispatch");
    }

    #[test]
    fn brk_waits_for_host_alias_idle() {
        const SYS_BRK: u64 = 214;
        assert_operation_waits_for_host_alias_idle("brk", move |dispatcher| {
            let reporter = CompatReporter::default();
            let registry = crate::thread::ThreadRegistry::new(
                crate::thread::ThreadId::synthetic_for_tests(1300),
            );
            let mut memory = LinearMemory::new(LINUX_HEAP_BASE, vec![0; LINUX_PAGE_SIZE as usize]);
            dispatcher
                .dispatch_threaded(
                    &dispatcher.capture_one_task_context().unwrap(),
                    SyscallRequest::new(SYS_BRK, SyscallArgs([0, 0, 0, 0, 0, 0])),
                    &mut memory,
                    &reporter,
                    registry.main_tid(),
                    &registry,
                    &crate::thread::FutexTable::new(),
                )
                .expect("brk dispatch while alias install is pending");
        });
    }

    #[test]
    fn msync_waits_for_host_alias_idle() {
        const SYS_MSYNC: u64 = 227;
        assert_operation_waits_for_host_alias_idle("msync", move |dispatcher| {
            let reporter = CompatReporter::default();
            let registry = crate::thread::ThreadRegistry::new(
                crate::thread::ThreadId::synthetic_for_tests(1301),
            );
            let mut memory = LinearMemory::new(LINUX_MMAP_BASE, vec![0; LINUX_PAGE_SIZE as usize]);
            dispatcher
                .dispatch_threaded(
                    &dispatcher.capture_one_task_context().unwrap(),
                    SyscallRequest::new(
                        SYS_MSYNC,
                        SyscallArgs([LINUX_MMAP_BASE, LINUX_PAGE_SIZE, 0, 0, 0, 0]),
                    ),
                    &mut memory,
                    &reporter,
                    registry.main_tid(),
                    &registry,
                    &crate::thread::FutexTable::new(),
                )
                .expect("msync dispatch while alias install is pending");
        });
    }

    #[test]
    fn mincore_waits_for_host_alias_idle() {
        const SYS_MINCORE: u64 = 232;
        assert_operation_waits_for_host_alias_idle("mincore", move |dispatcher| {
            let reporter = CompatReporter::default();
            let registry = crate::thread::ThreadRegistry::new(
                crate::thread::ThreadId::synthetic_for_tests(1302),
            );
            let mut memory =
                LinearMemory::new(LINUX_MMAP_BASE, vec![0; (2 * LINUX_PAGE_SIZE) as usize]);
            dispatcher
                .dispatch_threaded(
                    &dispatcher.capture_one_task_context().unwrap(),
                    SyscallRequest::new(
                        SYS_MINCORE,
                        SyscallArgs([
                            LINUX_MMAP_BASE,
                            LINUX_PAGE_SIZE,
                            LINUX_MMAP_BASE + LINUX_PAGE_SIZE,
                            0,
                            0,
                            0,
                        ]),
                    ),
                    &mut memory,
                    &reporter,
                    registry.main_tid(),
                    &registry,
                    &crate::thread::FutexTable::new(),
                )
                .expect("mincore dispatch while alias install is pending");
        });
    }

    #[test]
    fn high_va_private_anonymous_mmap_returns_empty_alias_payload() {
        const SYS_MMAP: u64 = 222;

        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize);
        let reporter = CompatReporter::default();
        let va = crate::memory::LINUX_HIGH_VA_THRESHOLD;
        let request = SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                va,
                LINUX_PAGE_SIZE,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_FIXED | LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        );

        let outcome = dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                request,
                &mut memory,
                &reporter,
            )
            .expect("mmap dispatch should succeed");

        let DispatchOutcome::MapHostAlias {
            va: mapped_va,
            len,
            payload,
            file,
            ..
        } = outcome
        else {
            panic!("expected high-VA alias outcome, got {outcome:?}");
        };
        assert_eq!(mapped_va, GuestVa(va));
        assert_eq!(len, LINUX_PAGE_SIZE);
        assert!(file.is_none(), "anonymous alias should not carry a file");
        assert!(
            payload.is_empty(),
            "fresh high-VA anonymous mmap should use the zeroed host anon alias without carrying a zero payload"
        );
        assert_eq!(memory.write_calls.get(), 0);
        assert_eq!(memory.zero_backing_calls.get(), 0);
        assert_eq!(memory.protect_calls.get(), 0);
    }

    #[test]
    fn alias_window_advisory_hint_is_honored_without_consuming_low_arena() {
        const SYS_MMAP: u64 = 222;
        const SYS_MUNMAP: u64 = 215;

        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize);
        let reporter = CompatReporter::default();
        let va = 0xc000000000;
        let len = 0x4000000;
        let request = SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                va,
                len,
                0,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        );

        let outcome = dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                request,
                &mut memory,
                &reporter,
            )
            .expect("mmap dispatch should succeed");

        assert_eq!(outcome, DispatchOutcome::Returned { value: va as i64 });
        let unmap = SyscallRequest::new(SYS_MUNMAP, SyscallArgs([va, len, 0, 0, 0, 0]));
        let unmap_outcome = dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                unmap,
                &mut memory,
                &reporter,
            )
            .expect("munmap dispatch should succeed");
        assert_eq!(unmap_outcome, DispatchOutcome::Returned { value: 0 });
        assert_eq!(
            dispatcher.next_mmap_address(0, LINUX_PAGE_SIZE, 0, 0),
            Some((LINUX_MMAP_BASE, false)),
            "alias-window advisory reservations must not consume the low mmap arena"
        );
    }

    #[test]
    fn alias_window_advisory_hint_with_protection_maps_alias() {
        const SYS_MMAP: u64 = 222;

        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, LINUX_PAGE_SIZE as usize);
        let reporter = CompatReporter::default();
        let va = 0xc000000000;
        let len = LINUX_PAGE_SIZE;
        let request = SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                va,
                len,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        );

        let outcome = dispatcher
            .dispatch(
                &dispatcher.capture_one_task_context().unwrap(),
                request,
                &mut memory,
                &reporter,
            )
            .expect("mmap dispatch should succeed");

        let DispatchOutcome::MapHostAlias {
            va: mapped_va,
            len: mapped_len,
            payload,
            file,
            ..
        } = outcome
        else {
            panic!("expected protected high advisory hint to map an alias, got {outcome:?}");
        };
        assert_eq!(mapped_va, GuestVa(va));
        assert_eq!(mapped_len, len);
        assert!(payload.is_empty());
        assert!(file.is_none());
        assert_eq!(
            dispatcher.next_mmap_address(0, LINUX_PAGE_SIZE, 0, 0),
            Some((LINUX_MMAP_BASE, false)),
            "alias-window advisory aliases must not consume the low mmap arena"
        );
    }
}
