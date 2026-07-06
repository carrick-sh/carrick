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
//! region. `/proc/self/maps` is rendered from the boot-captured `AddressSpace`
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

/// Owned memory-subsystem state. Split out of `SyscallDispatcher`.
#[derive(Clone)]
pub(super) struct MemState {
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
    /// wholly beyond the backing file's EOF for a MAP_SHARED file mapping.
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

impl MemState {
    pub(super) fn new() -> Self {
        Self {
            brk_current: LINUX_HEAP_BASE,
            mmap_next: LINUX_MMAP_BASE,
            mmap_dirty_high: LINUX_MMAP_BASE,
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

    fn reset_for_execve(&mut self) {
        let address_space_regions = self.address_space_regions.take();
        let linux_auxv_image = std::mem::take(&mut self.linux_auxv_image);
        *self = Self::new();
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

fn page_rounded_range(
    address: GuestPtr,
    length: u64,
) -> Result<Option<crate::vfs::GuestMemoryRange>, LinuxErrno> {
    if length == 0 {
        return Ok(None);
    }
    let start = GuestVa(address.0 & !(LINUX_PAGE_SIZE - 1));
    let end = address
        .0
        .checked_add(length)
        .and_then(|end| end.checked_add(LINUX_PAGE_SIZE - 1))
        .map(|end| GuestVa(end & !(LINUX_PAGE_SIZE - 1)))
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
) -> Result<(), LinuxErrno> {
    let len = range_len_usize(range)?;
    if !populate && memory.host_ptr_for_read(range.start().raw(), len).is_some() {
        return Ok(());
    }
    let mut page = range.start().raw();
    while page < range.end().raw() {
        if memory.read_bytes(page, 1).is_err() {
            return Err(LINUX_ENOMEM);
        }
        page = page.checked_add(LINUX_PAGE_SIZE).ok_or(LINUX_ENOMEM)?;
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
    next.sort_by_key(|map| map.start);
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
}

fn prot_to_proc_perms(prot: LinuxProtFlags) -> (bool, bool, bool) {
    (
        prot.contains(LinuxProtFlags::READ),
        prot.contains(LinuxProtFlags::WRITE),
        prot.contains(LinuxProtFlags::EXEC),
    )
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

fn shared_file_bus_offset(file_len: u64, offset: u64, length: u64) -> Option<u64> {
    let bytes_available = file_len.saturating_sub(offset).min(length);
    let bus_start = align_up_u64(bytes_available, LINUX_PAGE_SIZE)?;
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

impl SyscallDispatcher {
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

    fn dynamic_mapping_overlaps(&self, start: u64, len: u64) -> bool {
        self.mem
            .lock()
            .dynamic_maps
            .iter()
            .any(|map| ranges_overlap(start, len, map.start, map.end))
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

    fn remove_write_sealed_shared_map(&self, start: u64, len: u64) {
        if let Some(range) =
            crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start.saturating_add(len)))
        {
            locked_ranges_remove(&mut self.mem.lock().write_sealed_shared_maps, range);
        }
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

    fn remove_writable_memfd_map(&self, start: u64, len: u64) {
        let Some(end) = start.checked_add(len) else {
            return;
        };
        self.mem
            .lock()
            .writable_memfd_maps
            .retain(|(range, _)| !(range.start().raw() < end && start < range.end().raw()));
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
        trim_dynamic_maps_for_range(&mut mem.dynamic_maps, start, len);
        mem.remap_snapshots.remove(&start);
        mem.dynamic_maps.push(ProcMapsEntry {
            start,
            end,
            read,
            write,
            execute,
            sharing,
            path,
        });
        mem.dynamic_maps.sort_by_key(|map| map.start);
    }

    fn remove_dynamic_mapping(&self, start: u64, len: u64) {
        let mut mem = self.mem.lock();
        trim_dynamic_maps_for_range(&mut mem.dynamic_maps, start, len);
        if start.checked_add(len).is_none() {
            mem.remap_snapshots.clear();
            return;
        }
        mem.remap_snapshots.retain(|snapshot_start, bytes| {
            let snapshot_end = snapshot_start
                .checked_add(bytes.len() as u64)
                .unwrap_or(u64::MAX);
            !ranges_overlap(start, len, *snapshot_start, snapshot_end)
        });
    }

    pub(in crate::dispatch) fn record_mmap_bus_fault_range(&self, start: u64, len: u64) {
        if len == 0 {
            return;
        }
        self.mem.lock().bus_fault_ranges.push((start, len));
    }

    pub(crate) fn mmap_fault_is_sigbus(&self, addr: u64) -> bool {
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
        let stack_span = 256 * LINUX_PAGE_SIZE;
        let low = end.saturating_sub(stack_span);
        self.mem.lock().growdown_ranges.push((low, start, end));
    }

    pub(crate) fn mmap_growdown_fault_plan(&self, addr: u64) -> Option<(u64, usize)> {
        let page = addr & !(LINUX_PAGE_SIZE - 1);
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
                return Some((page, len));
            }
        }
        None
    }

    pub(crate) fn commit_mmap_growdown(&self, new_start: u64) {
        let mut mem = self.mem.lock();
        for (_low, current, _end) in &mut mem.growdown_ranges {
            if new_start < *current {
                *current = new_start;
                break;
            }
        }
    }

    fn update_dynamic_mapping_prot(&self, start: u64, len: u64, prot: LinuxProtFlags) {
        let (read, write, execute) = prot_to_proc_perms(prot);
        let Some(end) = start.checked_add(len) else {
            return;
        };
        let mut mem = self.mem.lock();
        for map in &mut mem.dynamic_maps {
            if ranges_overlap(start, len, map.start, map.end) {
                map.read = read;
                map.write = write;
                map.execute = execute;
                map.start = map.start.max(start);
                map.end = map.end.min(end);
            }
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
        self.mem.lock().reset_for_execve();
    }

    pub(in crate::dispatch) fn next_mmap_address(
        &self,
        requested: u64,
        length: u64,
        _prot: u64,
        flags: u64,
    ) -> Option<(u64, bool)> {
        if flags & LINUX_MAP_FIXED != 0 {
            if requested == 0 || !requested.is_multiple_of(LINUX_PAGE_SIZE) {
                return None;
            }
            return Some((requested, false));
        }

        if requested != 0 {
            let aligned_hint = requested.is_multiple_of(LINUX_PAGE_SIZE);
            let arena_hint = aligned_hint
                && range_within(
                    requested,
                    length,
                    LINUX_MMAP_BASE,
                    crate::memory::mmap_arena_size(),
                );
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
            let canonical_alias_hint = aligned_hint && mmap_address_uses_alias(requested, length);
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
        let address = align_up_u64(mem.mmap_next, LINUX_PAGE_SIZE)?;
        if !range_within(
            address,
            length,
            LINUX_MMAP_BASE,
            crate::memory::mmap_arena_size(),
        ) {
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

    /// Write a freed `SharedFile` allocation's bytes back to its host fd and
    /// close the owned dup. `SharedAnon` frees need no writeback. Called from
    /// `munmap` (close_fd=true) and `msync` (close_fd=false, no free).
    fn writeback_shared<M: GuestMemory>(
        &self,
        cx: &mut SyscallCtx<'_, M>,
        alloc: &crate::shared_aperture::SharedAlloc,
        close_fd: bool,
    ) {
        if let crate::shared_aperture::BackingObject::SharedFile { host_fd, offset } = alloc.backing
        {
            let len = usize::try_from(alloc.len).unwrap_or(0);
            if len > 0
                && let Ok(bytes) = cx.memory.read_bytes(alloc.guest_addr, len)
            {
                unsafe {
                    libc::pwrite(
                        host_fd,
                        bytes.as_ptr() as *const _,
                        bytes.len(),
                        offset as libc::off_t,
                    );
                }
            }
            if close_fd {
                unsafe { libc::close(host_fd) };
            }
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
            let mut mem = this.mem.lock();
            if requested == 0 {
                return Ok(DispatchOutcome::Returned {
                    value: mem.brk_current as i64,
                });
            }
            if range_within(requested, 0, LINUX_HEAP_BASE, LINUX_HEAP_SIZE) {
                mem.brk_current = requested;
            }
            Ok(DispatchOutcome::Returned {
                value: mem.brk_current as i64,
            })
        }

        fn mmap(this, cx, requested: GuestPtr, length: u64, prot: u64, flags: u64, fd: Fd, offset: u64) {
            let mut flags = flags;
            let memory = &mut *cx.memory;

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
                || (!map_flags.contains(LinuxMmapFlags::ANONYMOUS) && !offset.is_multiple_of(LINUX_PAGE_SIZE))
                || (map_flags.contains(LinuxMmapFlags::FIXED) && !requested.0.is_multiple_of(LINUX_PAGE_SIZE))
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let Some(map_sharing) = map_sharing else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let length = match align_up_u64(length, LINUX_PAGE_SIZE) {
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

            // MAP_FIXED|MAP_PRIVATE|ANON landing on a shared-aperture VA: the
            // guest wants a genuinely PRIVATE page at exactly this (currently
            // shared) address. Writing through to the shared backing would leak
            // the guest's "private" stores to every other mapper and across
            // fork (the mapfixed privacy bug). Instead carve a slot in the
            // per-process private overlay aperture and repoint this VA's stage-1
            // leaf to it — stage-1 ONLY, since the overlay window is boot-mapped
            // (no post-vCPU hv_vm_map, per the durable-memory rule). requested.0
            // and length are already validated page-aligned/non-zero above.
            // (MAP_FIXED|MAP_PRIVATE of a FILE over a shared-aperture VA is a
            // tracked remainder — the probe and common case are anon.)
            if map_flags.contains(LinuxMmapFlags::FIXED)
                && map_sharing == MmapSharing::Private
                && map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && crate::memory::va_in_shared_aperture(requested.0, length)
            {
                let locked_range =
                    this.prepare_mmap_locked_range(map_flags, requested.0, length)?;
                let overlay_va = {
                    let mut mem = this.mem.lock();
                    // Re-MAP_FIXED over the same VA: free the prior overlay slot.
                    if let Some(old) = mem.overlay.find_by_source(requested.0) {
                        mem.overlay.free(old);
                    }
                    mem.overlay.alloc_sourced(
                        length,
                        crate::shared_aperture::BackingObject::PrivateAnon,
                        Some(requested.0),
                    )
                };
                let Some(overlay_va) = overlay_va else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                // Anonymous => fresh zero page. Seed + stage-1 repoint atomically
                // on the engine; on failure roll the slot back so it's reusable.
                let zeros = vec![0u8; length_usize];
                if memory
                    .repoint_private(requested.0, overlay_va, length_usize, &zeros)
                    .is_err()
                {
                    this.mem.lock().overlay.free(overlay_va);
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
                this.record_dynamic_mapping(
                    requested.0,
                    length,
                    prot_flags,
                    ProcMapSharing::Private,
                    String::new(),
                );
                this.commit_mmap_locked_range(locked_range);
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
                                .and_then(|len| shared_file_bus_offset(len, offset, length))
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
                    // Host-side EFAULT gate for a PROT_NONE file mapping: a
                    // syscall buffer here must fault (the host backing is
                    // itself PROT_NONE — touching it would crash carrick).
                    let prot_none = pf.is_empty();
                    if let Ok(l) = usize::try_from(length) {
                        memory.set_no_access(va, l, prot_none);
                    }
                    this.record_dynamic_mapping(
                        va,
                        length,
                        prot_flags,
                        ProcMapSharing::Shared,
                        String::new(),
                    );
                    return Ok(DispatchOutcome::MapHostAlias {
                        va: GuestVa(va),
                        ipa: Gpa(ipa),
                        len: length,
                        payload: Vec::new(),
                        file: Some((dup_fd, offset as libc::off_t, host_prot)),
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
                    mem.shared
                        .alloc_sourced_with_reuse(
                            map_len,
                            crate::shared_aperture::BackingObject::SharedAnon,
                            None,
                        )
                };
                if let Some((addr, reused)) = alloc {
                    let map_len_usize = usize::try_from(map_len)
                        .map_err(|_| DispatchError::LengthTooLarge(map_len))?;
                    let locked_range = this.prepare_mmap_locked_range(map_flags, addr, length)?;
                    if reused {
                        let _ = memory.zero_backing(addr, map_len_usize);
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
                    memory.set_no_access(addr, map_len_usize, false);
                    memory.set_no_write(
                        addr,
                        map_len_usize,
                        !prot_none && !prot_flags.contains(LinuxProtFlags::WRITE),
                    );
                    if prot_none {
                        memory.set_no_access(addr, map_len_usize, true);
                        let _ = memory.protect_range(addr, map_len_usize, 0);
                    } else {
                        let _ = memory.protect_range(addr, map_len_usize, 0);
                        this.track_resident_fault_range(addr, length, prot_flags);
                    }
                    this.record_dynamic_mapping(
                        addr,
                        length,
                        prot_flags,
                        ProcMapSharing::Shared,
                        String::new(),
                    );
                    this.commit_mmap_locked_range(locked_range);
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
            if (reused || fixed_anonymous) && !mmap_address_uses_alias(address, length) {
                // Scrub the reused region's PHYSICAL backing. MUST bypass the
                // guest-visible permission: a region just reclaimed from munmap
                // is stage-1-invalidated (no-access) and a PROT_NONE mmap is not
                // writable, so the permission-checked write_bytes silently faults
                // and leaves the prior mapping's bytes — which then surface after
                // the guest mprotects the region to RW (CPython multiprocessing
                // Pool built on a freed 16 MiB b'X' buffer → 0x58.. ptr → SIGSEGV).
                // MAP_FIXED|ANON also overwrites a caller-selected range, so it
                // cannot rely on the bump allocator's pristine-tail invariant.
                let _ = memory.zero_backing(address, length_usize);
            }

            // Restore guest-visible stage-1 validity for arena allocations: a
            // page reclaimed from a prior munmap (which invalidated it) must be
            // valid+RW again, and a PROT_NONE mmap must actually fault. No-op
            // (no TLBI) when the page is already at the target protection.
            let in_arena = range_within(address, length, LINUX_MMAP_BASE, crate::memory::mmap_arena_size());

            let prot_none = prot_flags.is_empty();
            if prot_none && map_flags.contains(LinuxMmapFlags::ANONYMOUS) {
                let locked_range = this.prepare_mmap_locked_range(map_flags, address, length)?;
                memory.set_no_access(address, length_usize, false);
                memory.set_no_write(address, length_usize, false);
                memory.set_no_access(address, length_usize, true);
                // protect_range runs UNCONDITIONALLY so a demand-paged backend
                // (bhyve) records a reservation across the WHOLE mmap arena,
                // not just the first `mmap_arena_size()` bytes — Go's page
                // allocator bumps its summary mmaps well past that. The error
                // is fatal only inside the eager arena (where eager backends
                // must succeed); an out-of-arena protect_range failure is
                // benign (KVM/NVMM host-map lazily, HVF maps the arena eagerly).
                if memory.protect_range(address, length_usize, 0).is_err() && in_arena {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
                this.record_dynamic_mapping(
                    address,
                    length,
                    prot_flags,
                    map_sharing.proc_map_sharing(),
                    String::new(),
                );
                this.commit_mmap_locked_range(locked_range);
                if map_flags.contains(LinuxMmapFlags::GROWSDOWN) {
                    this.record_growdown_mapping(address, length);
                }
                return Ok(DispatchOutcome::Returned {
                    value: address as i64,
                });
            }

            if map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && !mmap_address_uses_alias(address, length)
            {
                let locked_range = this.prepare_mmap_locked_range(map_flags, address, length)?;
                memory.set_no_access(address, length_usize, false);
                memory.set_no_write(
                    address,
                    length_usize,
                    !prot_flags.contains(LinuxProtFlags::WRITE),
                );
                // Unconditional (see the PROT_NONE arm above): reserve across
                // the whole arena for demand-paged backends; fatal only in-arena.
                if memory.protect_range(address, length_usize, prot).is_err() && in_arena {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
                this.record_dynamic_mapping(
                    address,
                    length,
                    prot_flags,
                    map_sharing.proc_map_sharing(),
                    String::new(),
                );
                this.commit_mmap_locked_range(locked_range);
                if map_flags.contains(LinuxMmapFlags::GROWSDOWN) {
                    this.record_growdown_mapping(address, length);
                }
                return Ok(DispatchOutcome::Returned {
                    value: address as i64,
                });
            }

            let mut bus_fault_offset = None;
            // A MAP_SHARED mapping of a memfd sealed F_SEAL_WRITE is created
            // read-only here (a writable one already returned EPERM above); record
            // it so a later mprotect(PROT_WRITE) is rejected.
            let mut mmap_write_sealed_shared = false;
            // A live MAP_SHARED, PROT_WRITE mapping of an (unsealed) memfd — its
            // backing description is recorded so F_ADD_SEALS F_SEAL_WRITE can
            // EBUSY while it is mapped.
            let mut writable_memfd_desc: Option<OpenDescriptionRef> = None;
            let bytes = if map_flags.contains(LinuxMmapFlags::ANONYMOUS) {
                Vec::new()
            } else {
                let mut bytes = vec![0; length_usize];
                let Some(open_file) = this.open_file(fd.0) else {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                };
                let open = open_file.description.read();
                let offset_usize =
                    usize::try_from(offset).map_err(|_| DispatchError::LengthTooLarge(offset))?;
                match &*open {
                    OpenDescription::File { contents, base, .. } => {
                        if map_sharing == MmapSharing::Shared
                            && let Some(bus_offset) = shared_file_bus_offset(
                                contents.len() as u64,
                                offset,
                                length,
                            )
                        {
                            bus_fault_offset = Some(bus_offset);
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
                    OpenDescription::SyntheticFile { contents, .. } => {
                        if map_sharing == MmapSharing::Shared
                            && let Some(bus_offset) = shared_file_bus_offset(
                                contents.len() as u64,
                                offset,
                                length,
                            )
                        {
                            bus_fault_offset = Some(bus_offset);
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
                                shared_file_bus_offset(file_len, offset, length)
                        {
                            bus_fault_offset = Some(bus_offset);
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

            if mmap_write_sealed_shared {
                this.record_write_sealed_shared_map(address, length);
            }
            if let Some(description) = writable_memfd_desc {
                this.record_writable_memfd_map(address, length, description);
            }

            // Guest-chosen mmap addresses outside Carrick's low identity arenas
            // use alias backing. VAs >= 1 TiB need this because HVF's IPA is
            // 40 bits; lower canonical hints in the free gap above the shared
            // aperture use the same machinery so Linux-style advisory hints
            // (notably Go's 0xc000000000 arena probe) are preserved instead of
            // being relocated into the low mmap arena.
            if mmap_address_uses_alias(address, length) {
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
                // Alias mappings frequently overlay an earlier PROT_NONE
                // reservation (Rosetta reserves the x86 stack/binary span anon
                // PROT_NONE, then MAP_FIXEDs RW/file segments in; Go probes its
                // arena with PROT_NONE before mapping usable pages). The guest's
                // own accesses translate via the page tables map_aliased installs,
                // but carrick's syscall-path EFAULT check consults `no_access` —
                // clear it here, or reads/writes of guest buffers in this range
                // wrongly EFAULT.
                memory.set_no_access(address, length_usize, prot_none);
                memory.set_no_write(
                    address,
                    length_usize,
                    !prot_none && !prot_flags.contains(LinuxProtFlags::WRITE),
                );
                this.record_dynamic_mapping(
                    address,
                    length,
                    prot_flags,
                    map_sharing.proc_map_sharing(),
                    String::new(),
                );
                if let Some(bus_offset) = bus_fault_offset
                    && let Some(bus_start) = address.checked_add(bus_offset)
                    && let Some(bus_len) = length.checked_sub(bus_offset)
                    && let Ok(bus_len_usize) = usize::try_from(bus_len)
                {
                    memory.set_no_access(bus_start, bus_len_usize, true);
                    let _ = memory.protect_range(bus_start, bus_len_usize, 0);
                    this.record_mmap_bus_fault_range(bus_start, bus_len);
                }
                return Ok(DispatchOutcome::MapHostAlias {
                    va: GuestVa(address),
                    ipa: Gpa(ipa),
                    len: length,
                    payload: bytes,
                    file: None,
                    prot_none,
                });
            }

            let locked_range = this.prepare_mmap_locked_range(map_flags, address, length)?;
            memory.set_no_access(address, length_usize, false);
            // Stamp the file content via the UNCHECKED path: this is carrick
            // loading the mapping, not a guest write. The final prot may be
            // read-only, and the dynamic loader's `mmap(whole-lib, PROT_READ)`
            // placeholder may have already marked this range `no_write` before
            // it `MAP_FIXED`s each segment in — so the checked `write_bytes`
            // (x86's read-only write gate) would wrongly EFAULT our own load.
            let _ = memory.write_bytes_unchecked(address, &bytes);
            if prot_none {
                memory.set_no_access(address, length_usize, true);
            }
            memory.set_no_write(
                address,
                length_usize,
                !prot_none && !prot_flags.contains(LinuxProtFlags::WRITE),
            );
            // Make the requested protection guest-visible (also restores RW for
            // a reused range). prot==0 here means file-backed PROT_NONE.
            // Unconditional: reserve across the whole arena; fatal only in-arena.
            if memory.protect_range(address, length_usize, prot).is_err() && in_arena {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            if let Some(bus_offset) = bus_fault_offset
                && let Some(bus_start) = address.checked_add(bus_offset)
                && let Some(bus_len) = length.checked_sub(bus_offset)
                && let Ok(bus_len_usize) = usize::try_from(bus_len)
            {
                cx.memory.set_no_access(bus_start, bus_len_usize, true);
                let _ = cx.memory.protect_range(bus_start, bus_len_usize, 0);
                this.record_mmap_bus_fault_range(bus_start, bus_len);
            }
            this.record_dynamic_mapping(
                address,
                length,
                prot_flags,
                map_sharing.proc_map_sharing(),
                String::new(),
            );
            // A file-backed mapping's content is loaded eagerly (above), and
            // MAP_POPULATE prefaults anonymous pages — so mincore must report
            // those pages resident even before the guest touches them (LTP
            // mincore04 mlocks in a child, then the parent queries mincore).
            if !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                || map_flags.contains(LinuxMmapFlags::POPULATE)
            {
                this.mark_range_resident(address, length);
            }
            this.commit_mmap_locked_range(locked_range);
            Ok(DispatchOutcome::Returned {
                value: address as i64,
            })
        }

        fn munmap(this, cx, address: GuestPtr, length: u64) {
            // Linux munmap EINVAL edges (__vm_munmap): the address must be
            // page-aligned and the length non-zero. LTP munmap03 munmaps the
            // address of a BSS global (8-aligned, not page-aligned) and that
            // address + 8, expecting EINVAL — carrick lacked the alignment gate.
            if !address.0.is_multiple_of(LINUX_PAGE_SIZE) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if length == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if let Some(len) = align_up_u64(length, LINUX_PAGE_SIZE) {
                this.remove_dynamic_mapping(address.0, len);
                this.remove_write_sealed_shared_map(address.0, len);
                this.remove_writable_memfd_map(address.0, len);
                trim_ranges_for_range(&mut this.mem.lock().bus_fault_ranges, address.0, len);
                if let Some(remove) = crate::vfs::GuestMemoryRange::new(
                    GuestVa(address.0),
                    GuestVa(address.0.saturating_add(len)),
                ) {
                    let mut mem = this.mem.lock();
                    locked_ranges_remove(&mut mem.locked_ranges, remove);
                    locked_ranges_remove(&mut mem.resident_ranges, remove);
                    locked_ranges_remove(&mut mem.resident_tracked_ranges, remove);
                    remove_fault_range(&mut mem.resident_fault_ranges, remove);
                }
            }
            let freed = {
                let mut mem = this.mem.lock();
                // Release any private-overlay slot repointed at this VA (a
                // MAP_FIXED|MAP_PRIVATE over a shared-aperture VA carved one via
                // alloc_sourced + repoint_private); without this it leaks a slot
                // in the bounded overlay window. Mirrors the re-MAP_FIXED path.
                // (audit M11)
                if let Some(slot) = mem.overlay.find_by_source(address.0) {
                    mem.overlay.free(slot);
                }
                mem.shared.free(address.0)
            };
            if let Some(alloc) = freed {
                // SharedFile backings write dirty bytes back and close the dup;
                // SharedAnon frees are pure bookkeeping. The aperture stays
                // stage-2 mapped — no hv_vm_unmap.
                if let Some(len) = align_up_u64(length, LINUX_PAGE_SIZE)
                    && let Ok(len_usize) = usize::try_from(len)
                {
                    cx.memory.set_no_access(address.0, len_usize, true);
                }
                this.writeback_shared(cx, &alloc, true);
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
            if mmap_address_uses_alias(address.0, length) {
                if let Some(len) = align_up_u64(length, LINUX_PAGE_SIZE)
                    && let Ok(len_usize) = usize::try_from(len)
                {
                    // Alias teardown: invalidate AND reclaim the now-empty per-
                    // alias stage-1 sub-table (each MAP_SHARED file mapping took
                    // its own 2 MiB block + L3 table) — else the spare pool leaks
                    // one table per alias and a churning guest hits OutOfTables.
                    let _ = cx.memory.unmap_alias_range(address.0, len_usize);
                    cx.memory.set_no_access(address.0, len_usize, true);
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if !range_within(address.0, length, LINUX_MMAP_BASE, crate::memory::mmap_arena_size()) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if let Some(len) = align_up_u64(length, LINUX_PAGE_SIZE) {
                let mut mem = this.mem.lock();
                // Invalidate the freed range in stage-1 (use-after-munmap faults
                // in-guest) BEFORE returning it to the allocator, holding `mem`
                // across the edit. A concurrent mmap that reuses this address
                // must re-acquire `mem` to allocate it, so its validity-restore
                // is strictly ordered AFTER this invalidate — otherwise a late
                // invalidate could clobber the new owner's mapping and fault it.
                // Best-effort: a failure leaves it accessible (pre-existing
                // behavior).
                if let Ok(len_usize) = usize::try_from(len) {
                    let _ = cx.memory.unmap_range(address.0, len_usize);
                    cx.memory.set_no_access(address.0, len_usize, true);
                }
                if address.0.checked_add(len) == Some(mem.mmap_next) {
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
                    free_regions_insert(&mut mem.free_regions, address.0, len);
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn msync(this, cx, address: GuestPtr, length: u64, flags: u64) {
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
            if !address.0.is_multiple_of(LINUX_PAGE_SIZE) {
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
                    .copied()
            };
            if let Some(alloc) = alloc {
                // Write a SharedFile backing's dirty bytes back without freeing.
                this.writeback_shared(cx, &alloc, false);
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if cx.memory.read_bytes(address.0, 1).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn mlock(this, cx, address: GuestPtr, length: u64) {
            let Some(range) = page_rounded_range(address, length)? else {
                return Ok(DispatchOutcome::Returned { value: 0 });
            };
            validate_mlock_range(&mut *cx.memory, range, true)?;
            this.populate_resident_range(&mut *cx.memory, range)?;
            this.add_locked_range(range)?;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn munlock(this, cx, address: GuestPtr, length: u64) {
            let Some(range) = page_rounded_range(address, length)? else {
                return Ok(DispatchOutcome::Returned { value: 0 });
            };
            validate_mlock_range(&mut *cx.memory, range, false)?;
            this.remove_locked_range(range);
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn mlockall(this, cx, flags: u64) {
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
                this.lock_current_mappings()?;
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn munlockall(this, cx) {
            this.mem.lock().locked_ranges.clear();
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn mlock2(this, cx, address: GuestPtr, length: u64, flags: u64) {
            let Some(flags) = LinuxMlock2Flags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let Some(range) = page_rounded_range(address, length)? else {
                return Ok(DispatchOutcome::Returned { value: 0 });
            };
            validate_mlock_range(
                &mut *cx.memory,
                range,
                !flags.contains(LinuxMlock2Flags::ONFAULT),
            )?;
            if !flags.contains(LinuxMlock2Flags::ONFAULT) {
                this.populate_resident_range(&mut *cx.memory, range)?;
            }
            this.add_locked_range(range)?;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn mincore(this, cx, address: GuestPtr, length: u64, vec: GuestPtr) {
            let memory = &mut *cx.memory;
            // Linux requires a page-aligned start address, else EINVAL (this is
            // what Go's TestMincoreErrorSign checks — the errno must be -EINVAL).
            if !address.0.is_multiple_of(LINUX_PAGE_SIZE) {
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
                Some(end) => end & !(LINUX_PAGE_SIZE - 1),
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
                page = match page.checked_add(LINUX_PAGE_SIZE) {
                    Some(next) => next,
                    None => return Ok(DispatchOutcome::errno(LINUX_ENOMEM)),
                };
            }
            let pages = length.div_ceil(LINUX_PAGE_SIZE);
            let bytes = this
                .mincore_residency_vector(address.0, pages)
                .unwrap_or_else(|| vec![1u8; pages as usize]);
            memory.write_bytes(vec.0, &bytes)?;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn mremap(this, cx, old_address: GuestPtr, old_size: u64, new_size_req: u64, flags: u64, _new_address: GuestPtr) {
            let memory = &mut *cx.memory;
            if new_size_req == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if flags & !(LINUX_MREMAP_MAYMOVE | LINUX_MREMAP_FIXED | LINUX_MREMAP_DONTUNMAP) != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if !range_within(old_address.0, old_size, LINUX_MMAP_BASE, crate::memory::mmap_arena_size()) {
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
                // (Unlike the arena shrink below we do NOT eagerly unmap the tail
                // here — invalidating a high-VA alias tail needs trap-engine
                // coordination; no caller reads it. A grow would mean relocating
                // a file/shared backing, which we don't do → EINVAL as before.)
                let Some(new_size) = align_up_u64(new_size_req, LINUX_PAGE_SIZE) else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                if memory.read_bytes(old_address.0, 1).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                if new_size <= old_size {
                    return Ok(DispatchOutcome::Returned {
                        value: old_address.0 as i64,
                    });
                }
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let Some(new_size) = align_up_u64(new_size_req, LINUX_PAGE_SIZE) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
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
                    .map(|e| e & !(LINUX_PAGE_SIZE - 1));
                if let Some(tail_end) = tail_end
                    && tail_end > tail_start
                {
                    let tail_len = tail_end - tail_start;
                    if let Ok(tl) = usize::try_from(tail_len) {
                        // Mark no-access so the SYSCALL path (mincore/read_bytes)
                        // also reports the tail unmapped (mincore → ENOMEM),
                        // matching Linux — not just a stage-1 fault on EL0 access.
                        // A reusing mmap clears no-access in its seed.
                        memory.set_no_access(tail_start, tl, true);
                        let _ = memory.unmap_range(tail_start, tl);
                    }
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
                if range_within(old_address.0, new_size, LINUX_MMAP_BASE, crate::memory::mmap_arena_size()) {
                    {
                        let mut mem = this.mem.lock();
                        mem.mmap_next = new_end;
                        // Advance the dirty high-water to cover the grown tail.
                        // The guest dirties [old_end, new_end); without this, a
                        // later munmap+rebump into that range sees addr >=
                        // mmap_dirty_high, assumes it pristine, SKIPS the
                        // zero-fill, and hands back STALE bytes — read as a
                        // pointer (far=0x5858…='X'*8) → SIGSEGV in multiprocessing
                        // Pool (test_async_timeout). Same stale-memory class as
                        // the mmap-bump zero-fill fix; the in-place-grow path was
                        // the missed sibling.
                        mem.mmap_dirty_high = mem.mmap_dirty_high.max(new_end);
                    }
                    // Re-validate the freshly-grown tail [old_end, new_end). Those
                    // pages can be a range reclaimed from a prior munmap (which
                    // invalidated their stage-1 leaves and rolled mmap_next back),
                    // so without restoring RW validity here the guest FAULTS on
                    // first access to the grown region — exactly as the move path
                    // below and the regular mmap path do. (CPython's obmalloc/
                    // realloc grows an arena buffer in place; the tail landed on
                    // invalidated pages → a level-3 translation fault.)
                    let grow_len_u64 = new_size - old_size;
                    if let Ok(grow_len) = usize::try_from(grow_len_u64) {
                        memory.set_no_access(old_end, grow_len, false);
                        if memory
                            .protect_range(old_end, grow_len, LINUX_PROT_READ | LINUX_PROT_WRITE)
                            .is_err()
                        {
                            return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                        }
                    }
                    return Ok(DispatchOutcome::Returned {
                        value: old_address.0 as i64,
                    });
                }
            }

            if flags & LINUX_MREMAP_MAYMOVE == 0 {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            let Some((new_addr, reused)) =
                this.next_mmap_address(0, new_size, LINUX_PROT_READ | LINUX_PROT_WRITE, 0)
            else {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
            let new_len = match usize::try_from(new_size) {
                Ok(n) => n,
                Err(_) => return Ok(DispatchOutcome::errno(LINUX_ENOMEM)),
            };
            // Clear stale no-access tracking on the destination — it may be a
            // range reclaimed from a prior munmap (which marked it no-access).
            memory.set_no_access(new_addr, new_len, false);
            if reused {
                let _ = memory.zero_guest_range(new_addr, new_len);
            }
            let copy_len = match usize::try_from(old_size) {
                Ok(len) => len,
                Err(_) => {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
            };
            if copy_len > 0 {
                match memory.read_bytes(old_address.0, copy_len) {
                    Ok(bytes) => {
                        let _ = memory.write_bytes(new_addr, &bytes);
                    }
                    Err(_) => {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                }
            }
            // Re-validate the destination's guest stage-1 entries, exactly as
            // mmap does. A range reused from a munmap'd region was invalidated;
            // without this the guest FAULTS reading the freshly-mremap'd memory
            // (carrick wrote the copy host-side, so no guest write-fault ever
            // re-established the page). new_addr is always in the arena here.
            if memory
                .protect_range(new_addr, new_len, LINUX_PROT_READ | LINUX_PROT_WRITE)
                .is_err()
            {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            // mremap MOVE on Linux UNMAPS the source [old, old+old_size) (unless
            // MREMAP_DONTUNMAP). carrick previously LEAKED it: the source VA
            // stayed mapped with its stale bytes and was never returned to the
            // allocator, so `mmap_next` ran away and glibc's view of which VAs
            // are mapped diverged from carrick's (glibc considers the source
            // freed). Reclaim the source exactly like munmap, so a later access
            // faults and the VA is reusable — matching Linux and keeping the
            // mmapped-chunk bookkeeping coherent across the BytesIO/recv_bytes
            // realloc-grow cascade (test_multiprocessing test_connection's 16 MiB
            // round-trip). MREMAP_DONTUNMAP keeps the source mapped.
            // Guard: the destination must not overlap the source (it never does —
            // `new_addr` is freshly bump-allocated or a disjoint free region —
            // but reclaiming an overlapping source would unmap the live copy).
            let dst_overlaps_src = new_addr < old_address.0.wrapping_add(old_size)
                && old_address.0 < new_addr.wrapping_add(new_size);
            if flags & LINUX_MREMAP_DONTUNMAP == 0 && !dst_overlaps_src
                && let Some(old_size_a) = align_up_u64(old_size, LINUX_PAGE_SIZE)
                    && let Ok(old_len) = usize::try_from(old_size_a)
                    && old_len > 0
                {
                    let mut mem = this.mem.lock();
                    // No-access so the syscall path also reports the source
                    // unmapped (mincore → ENOMEM), matching Linux; a reusing
                    // mmap clears it in its seed.
                    memory.set_no_access(old_address.0, old_len, true);
                    let _ = memory.unmap_range(old_address.0, old_len);
                    if old_address.0.checked_add(old_size_a) == Some(mem.mmap_next) {
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
                        free_regions_insert(&mut mem.free_regions, old_address.0, old_size_a);
                    }
                }
            Ok(DispatchOutcome::Returned {
                value: new_addr as i64,
            })
        }

        fn mprotect(this, cx, address: GuestPtr, length: u64, prot: u64) {
            if prot & !LinuxProtFlags::SUPPORTED_MASK != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if length == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if !address.0.is_multiple_of(LINUX_PAGE_SIZE) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
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
            // `read_bytes_raw` faults only on a genuine backing hole (an address
            // in no mapped region, e.g. NULL), exactly Linux's "unmapped VA"
            // condition. It is strictly more permissive than Linux (which requires
            // the WHOLE range mapped — we only probe the start page), so it never
            // rejects a valid mapping. Probe BEFORE mutating no_access so we don't
            // stamp tracking onto a foreign/unmapped range.
            if cx.memory.read_bytes_raw(address.0, 1).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            // A shared mapping of a F_SEAL_WRITE memfd cannot be upgraded to
            // writable (memfd_create01 check_mfd_non_writeable).
            if prot & LINUX_PROT_WRITE != 0 && this.range_is_write_sealed_shared(address.0, length) {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            if let Ok(len) = usize::try_from(length) {
                let prot_none = LinuxProtFlags::from_bits_truncate(prot).is_empty();
                cx.memory.set_no_access(address.0, len, prot_none);
                cx.memory.set_no_write(
                    address.0,
                    len,
                    !prot_none && prot & LINUX_PROT_WRITE == 0,
                );
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
                if range_within(address.0, length, LINUX_MMAP_BASE, crate::memory::mmap_arena_size()) {
                    if cx.memory.protect_range(address.0, len, prot).is_err() {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    }
                } else if mprotect_range_in_identity_image(address.0, length) {
                    let _ = cx.memory.protect_range(address.0, len, prot);
                }
                this.update_dynamic_mapping_prot(
                    address.0,
                    length,
                    LinuxProtFlags::from_bits_retain(prot),
                );
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn madvise(this, cx, address: GuestPtr, length: u64, advice: u64) {
            if !address.0.is_multiple_of(LINUX_PAGE_SIZE) || !linux_madvise_advice_is_supported(advice) {
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
            let Some(end) = align_up_u64(raw_end, LINUX_PAGE_SIZE) else {
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
                    // Drop the pages by zeroing the writable anonymous backing.
                    // A read-only or shared-file mapping must NOT be written —
                    // that would SIGBUS the runtime or corrupt the file — so treat
                    // it as a success no-op, matching Linux dropping clean cache
                    // pages. zero_backing writes the host backing directly (same
                    // call the MAP_FIXED/munmap-reuse scrub uses), bypassing the
                    // guest write-protection gate.
                    if meta.writable && cx.memory.zero_backing(address.0, length).is_err() {
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
                    .checked_mul(LINUX_PAGE_SIZE)
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
    /// `mlock` records both `resident_ranges` and `locked_ranges`. A fresh,
    /// untouched anonymous mapping is therefore NOT resident (LTP mincore03),
    /// while a file-backed or mlocked mapping is (mincore02/04). Pages outside
    /// every post-exec VMA belong to loader-populated initial regions (ELF
    /// text/data, heap, stack, trampolines) and stay resident, matching the
    /// prior conservative default.
    fn mincore_residency_vector(&self, address: u64, pages: u64) -> Option<Vec<u8>> {
        let mem = self.mem.lock();
        let mut out = Vec::with_capacity(usize::try_from(pages).ok()?);
        for index in 0..pages {
            let page = address.checked_add(index.checked_mul(LINUX_PAGE_SIZE)?)?;
            let in_dynamic = mem
                .dynamic_maps
                .iter()
                .any(|m| page >= m.start && page < m.end);
            let resident = if in_dynamic {
                ranges_contain_page(&mem.resident_ranges, page)
                    || ranges_contain_page(&mem.locked_ranges, page)
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
    fn mark_range_resident(&self, start: u64, len: u64) {
        if let Some(range) =
            crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start.saturating_add(len)))
        {
            locked_ranges_insert(&mut self.mem.lock().resident_ranges, range);
        }
    }

    pub(crate) fn resident_fault_plan(&self, address: u64) -> Option<(u64, u64)> {
        let page = address & !(LINUX_PAGE_SIZE - 1);
        let mem = self.mem.lock();
        mem.resident_fault_ranges
            .iter()
            .find(|fault| page >= fault.range.start().raw() && page < fault.range.end().raw())
            .map(|fault| (page, fault.prot.bits()))
    }

    pub(crate) fn commit_resident_fault(&self, page: u64) {
        let Some(range) =
            crate::vfs::GuestMemoryRange::new(GuestVa(page), GuestVa(page + LINUX_PAGE_SIZE))
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
        self.commit_mmap_locked_range(Some(range));
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
        let Some(range) = page_rounded_range(GuestPtr(address), length)? else {
            return Ok(None);
        };
        self.check_locked_range_limit(range)?;
        Ok(Some(range))
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

    fn commit_mmap_locked_range(&self, range: Option<crate::vfs::GuestMemoryRange>) {
        let Some(range) = range else {
            return;
        };
        locked_ranges_insert(&mut self.mem.lock().locked_ranges, range);
    }

    fn remove_locked_range(&self, range: crate::vfs::GuestMemoryRange) {
        locked_ranges_remove(&mut self.mem.lock().locked_ranges, range);
    }

    fn lock_current_mappings(&self) -> Result<(), LinuxErrno> {
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
fn mprotect_range_in_identity_image(address: u64, length: u64) -> bool {
    use crate::memory::{
        LINUX_HEAP_BASE as HEAP, LINUX_INTERPRETER_BASE as INTERP,
        LINUX_KERNEL_REGION_BASE as KERNEL, LINUX_NULL_GUARD_END as GUARD_END,
        LINUX_SHARED_FILE_BASE as SHARED,
    };
    range_within(address, length, GUARD_END, KERNEL - GUARD_END)
        || range_within(address, length, HEAP, crate::memory::LINUX_HEAP_SIZE)
        || range_within(address, length, INTERP, SHARED - INTERP)
        || range_within(
            address,
            length,
            SHARED,
            crate::memory::LINUX_SHARED_FILE_SIZE,
        )
}

fn mmap_address_uses_alias(address: u64, length: u64) -> bool {
    let Some(end) = address.checked_add(length) else {
        return false;
    };
    if end > (1u64 << 48) {
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
    use std::cell::Cell;

    struct CountingMmapMemory {
        base: u64,
        bytes: Vec<u8>,
        write_calls: Cell<usize>,
        write_bytes_total: Cell<usize>,
        zero_backing_calls: Cell<usize>,
        protect_calls: Cell<usize>,
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

    fn returned(outcome: DispatchOutcome) -> i64 {
        match outcome {
            DispatchOutcome::Returned { value } => value,
            other => panic!("expected Returned, got {other:?}"),
        }
    }

    #[test]
    fn free_regions_coalesce_adjacent() {
        let mut r = vec![];
        free_regions_insert(&mut r, 0x1000, 0x1000); // [0x1000,0x2000)
        free_regions_insert(&mut r, 0x3000, 0x1000); // [0x3000,0x4000)
        free_regions_insert(&mut r, 0x2000, 0x1000); // bridges → one [0x1000,0x4000)
        assert_eq!(r, vec![(0x1000, 0x3000)]);
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
            .dispatch(request, &mut memory, &reporter)
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
            .dispatch(request, &mut memory, &reporter)
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
            .dispatch(request, &mut memory, &reporter)
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
            .dispatch(request, &mut memory, &reporter)
            .expect("mmap dispatch should succeed");

        assert_eq!(outcome, DispatchOutcome::Returned { value: va as i64 });
        let unmap = SyscallRequest::new(SYS_MUNMAP, SyscallArgs([va, len, 0, 0, 0, 0]));
        let unmap_outcome = dispatcher
            .dispatch(unmap, &mut memory, &reporter)
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
            .dispatch(request, &mut memory, &reporter)
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
