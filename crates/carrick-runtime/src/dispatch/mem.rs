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
//!    Linux guarantees. `mmap_writable_high` is the fix: a MONOTONIC high-water
//!    that `munmap` never lowers, so the mmap handler can zero exactly the
//!    re-handed-out (below-high-water) ranges and leave the genuinely-fresh
//!    tail lazily zero. (This is the CPython `test_subprocess` SEGV root cause —
//!    see the `mmap_writable_high` field doc and the project memory.)
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
pub(crate) use super::dispatcher::MemView;
use super::*;
use carrick_fatal::carrick_fatal;

pub(crate) mod brk;
#[cfg(test)]
pub(super) use brk::update_semantic_heap_pages;
pub(crate) mod madvise;
pub(crate) mod vma;
pub use self::vma::*;
pub(crate) mod fault;
pub(crate) use self::fault::*;
pub(crate) use madvise::MadviseCoveredSegment;
pub(crate) mod backing;
pub(crate) use self::backing::*;
pub(crate) mod mmap;
#[cfg(test)]
pub(crate) use madvise::MadviseRangeMeta;

syscall_table! {
    /// Per-module syscall routing for the `mem` subsystem (Task A1).
    ///
    /// Owns the `number → handler` arms for every syscall this module
    /// implements. `resolve_handler` in `dispatch/mod.rs` chains this with
    /// the other modules' tables. Add a `mem` syscall by adding an arm
    /// HERE — no shared routing table to edit.
    pub(crate) fn dispatch_mem;
    213 => readahead,
    223 => fadvise64,
    425 => io_uring_setup,
    426 => io_uring_enter,
    427 => io_uring_register,
    283 => sys_membarrier,
    282 => userfaultfd,
}

mutation_syscall_table! {
    pub(crate) fn dispatch_mem_mutation;
    214 => brk,
    215 => munmap,
    216 => mremap,
    222 => mmap,
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
}

/// Dispatcher-owned, revisioned wrapper around the sole production memory/VMA
/// authority. Ordinary syscall and `/proc` access keeps using this same
/// `MemState` mutex; the K1 observer only derives owned occupancy rows from it.
pub(crate) struct MemAuthority {
    state: parking_lot::Mutex<MemState>,
    revision: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

struct DerivedForkProjection {
    ranges: Vec<carrick_hal::ForkProjectionRange>,
    omitted_ranges: Vec<(u64, u64)>,
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

    pub(super) fn with_revision(state: MemState, revision: crate::kernel::VmaRevision) -> Self {
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

    fn derive_fork_projection(
        state: &MemState,
    ) -> Result<DerivedForkProjection, carrick_hal::ForkProjectionError> {
        let mut projection_ranges = Vec::with_capacity(state.semantic_vmas.len());
        let mut omitted_ranges = Vec::new();
        let mut live_vmas = Vec::with_capacity(state.semantic_vmas.len());

        for vma in &state.semantic_vmas {
            let len = vma
                .end
                .checked_sub(vma.start)
                .filter(|len| *len != 0)
                .ok_or(carrick_hal::ForkProjectionError::ZeroLength)?;
            let disposition = if vma.fork_policy.copy == carrick_abi::VmaForkCopyPolicy::Omit {
                omitted_ranges.push((vma.start, len));
                carrick_hal::ForkLeafDisposition::Omit
            } else if vma.fork_policy.child_contents == carrick_abi::VmaForkChildPolicy::ZeroInChild
            {
                carrick_hal::ForkLeafDisposition::Zero
            } else {
                carrick_hal::ForkLeafDisposition::Preserve
            };
            live_vmas.push((vma.start, vma.end));
            projection_ranges.push(carrick_hal::ForkProjectionRange {
                va: vma.start,
                len,
                disposition,
            });
        }
        carrick_hal::validate_total_fork_projection(&projection_ranges, &live_vmas)?;
        Ok(DerivedForkProjection {
            ranges: projection_ranges,
            omitted_ranges,
        })
    }

    pub(super) fn fork_private_with_policy(
        &self,
    ) -> Result<
        (
            Self,
            crate::kernel::VmaRevision,
            std::sync::Arc<[carrick_hal::ForkProjectionRange]>,
        ),
        carrick_hal::ForkProjectionError,
    > {
        let state = self.state.lock();
        let revision = self.vma_revision();
        let mut forked = state.clone();
        forked.deferred_anonymous = std::sync::Arc::new(state.deferred_anonymous.fork_private());
        let projection = Self::derive_fork_projection(&state)?;

        for (start, len) in projection.omitted_ranges {
            remove_mapping_metadata_locked(&mut forked, start, len);
        }
        for range in &projection.ranges {
            if range.disposition == carrick_hal::ForkLeafDisposition::Zero {
                // WIPEONFORK does not inherit the parent's logical zero-page
                // residency. Keep pristine provenance only where it already
                // existed; the backend owns materialized child zero frames.
                forked
                    .deferred_anonymous
                    .clear_zero_read_residency(GuestVa(range.va), range.len as usize)
                    .unwrap_or_else(|_| {
                        carrick_fatal!(
                            "dispatch::deferred_anonymous_fork",
                            "wipeonfork clear_zero_read_residency failed"
                        )
                    });
            }
        }
        Ok((
            Self::with_revision(forked, revision),
            revision,
            std::sync::Arc::from(projection.ranges.into_boxed_slice()),
        ))
    }

    pub(super) fn fork_projection_with_revision(
        &self,
    ) -> Result<
        (
            crate::kernel::VmaRevision,
            std::sync::Arc<[carrick_hal::ForkProjectionRange]>,
        ),
        carrick_hal::ForkProjectionError,
    > {
        let state = self.state.lock();
        let revision = self.vma_revision();
        let projection = Self::derive_fork_projection(&state)?;
        Ok((
            revision,
            std::sync::Arc::from(projection.ranges.into_boxed_slice()),
        ))
    }

    pub(super) fn fork_private(&self) -> std::sync::Arc<Self> {
        let state = self.state.lock();
        let revision = self.vma_revision();
        let mut forked = state.clone();
        forked.deferred_anonymous = std::sync::Arc::new(state.deferred_anonymous.fork_private());
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

    pub(super) fn bump_revision(&self) {
        if self
            .revision
            .fetch_add(1, std::sync::atomic::Ordering::Release)
            == u64::MAX
        {
            carrick_fatal!(
                "dispatch::mem_revision",
                "mem authority revision counter overflow"
            );
        }
    }
}

/// Owned memory-subsystem state. Split out of `SyscallDispatcher`.
#[derive(Clone)]
pub(crate) struct MemState {
    pub(super) deferred_anonymous: std::sync::Arc<carrick_guest_mem::DeferredAnonymousState>,
    pub layout: MemoryLayout,
    /// Canonical semantic VMAs owned by this address space.
    pub semantic_vmas: VmaMap,
    /// Current program break (`brk`/`sbrk`).
    pub brk_current: u64,
    /// Bump cursor for the anonymous mmap arena.
    pub mmap_next: u64,
    /// MONOTONIC high-water of the arena: the highest address the guest could
    /// EVER have stored a non-zero byte into. `munmap` NEVER lowers it (unlike
    /// `mmap_next`).
    ///
    /// The bump path assumes `[mmap_next, ...)` is pristine (lazily zero-filled
    /// guest RAM), so it skips the zero-fill that reused `free_regions` get. That
    /// invariant breaks when `munmap` frees the TOP region and LOWERS `mmap_next`
    /// back over pages the guest already dirtied: a later bump allocation at the
    /// lowered cursor would return that STALE data instead of the zeroed anon
    /// memory Linux guarantees. Tracking the high-water lets the mmap handler
    /// zero exactly the re-handed-out (below-high-water) ranges and keep the
    /// genuinely-fresh tail lazily zero. (CPython test_subprocess SEGV:
    /// pymalloc got 'x'-filled stderr-buffer pages back from a post-munmap mmap.)
    ///
    /// **It is raised by WRITABILITY, not by allocation, and the distinction is
    /// the whole point of the name.** It was previously raised at every
    /// hand-out regardless of protection, so a `PROT_NONE` reservation — memory
    /// the guest cannot store into by definition — pushed the watermark past
    /// itself and forced every later allocation below it to be scrubbed. Go's
    /// allocator reserves enormous `PROT_NONE` regions and commits sub-ranges,
    /// so that over-approximation is the dominant shape on a build: measured at
    /// 145,453 zero-fill faults inside guest `mmap` service windows, against a
    /// workload whose real touched set is ~10.5x smaller
    /// (`docs/perf-results/2026-08-13-hvpatch-kf-scrub-ceiling.md`).
    ///
    /// SOUNDNESS: a page can only hold a non-zero byte if the guest could write
    /// it, and there are exactly two ways a guest range becomes writable — the
    /// `mmap` that creates it, and an `mprotect` that adds `PROT_WRITE`. BOTH
    /// raise this watermark. Anything that cannot prove non-writability raises
    /// it too, so the error direction is always "scrub something already zero",
    /// never "hand back stale bytes".
    pub mmap_writable_high: u64,
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
    /// via `SyscallDispatcher::set_address_space_regions`. When present,
    /// `/proc/self/maps` is rendered from this list (with the heap end
    /// tracking `brk_current` and the mmap arena end tracking `mmap_next`)
    /// instead of the hard-coded four-line summary.
    pub address_space_regions: Option<Vec<ProcMapsEntry>>,
    /// Linux-visible dynamic mappings created after exec. The boot address-space
    /// snapshot contains the backing arenas, but `/proc/self/maps` must show the
    /// VMAs Linux would have installed inside those arenas with their actual
    /// permissions and private/shared bit.
    pub dynamic_maps: Vec<ProcMapsEntry>,
    /// Guest-VA ranges whose post-boot host alias backing has been physically
    /// installed and committed. This is deliberately separate from
    /// `dynamic_maps`: a lazy anonymous `PROT_NONE` reservation owns a Linux VMA
    /// before it owns host/stage-2 backing. Fork clones both inventories;
    /// munmap/MAP_FIXED replacement trims both atomically.
    host_alias_backed_ranges: Vec<crate::vfs::GuestMemoryRange>,
    /// Linux VMAs whose guest VA is implemented by a non-identity host alias.
    /// Unlike `host_alias_backed_ranges`, this also includes lazy PROT_NONE
    /// reservations that have not acquired a physical frame yet. Keeping the
    /// routing identity explicit is required for low `MAP_FIXED` VAs: address
    /// shape alone cannot distinguish a replaced ELF hole from eager RAM.
    alias_vma_ranges: Vec<crate::vfs::GuestMemoryRange>,
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
    resident_fault_ranges: FirstTouchArming,
    /// MAP_GROWSDOWN VMAs that may expand downward on a stack fault:
    /// `(low_bound, current_start, end)`.
    pub growdown_ranges: Vec<(u64, u64, u64)>,
    /// VA ranges of MAP_SHARED mappings whose backing file was opened
    /// read-only. Linux clears `VM_MAYWRITE` for them, so `mprotect(PROT_WRITE)`
    /// is EACCES no matter what the mapping's current protection is
    /// (`mprotect(2)`: "you mmap(2) a file to which you have read-only access,
    /// then ask mprotect() to mark it PROT_WRITE"; LTP mprotect01 case 3). The
    /// ceiling is a MAP TIME fact — the fd may be closed long before the
    /// mprotect — so it is recorded here rather than re-derived.
    read_only_shared_file_maps: Vec<crate::vfs::GuestMemoryRange>,
    /// VA ranges of MAP_SHARED mappings backed by a memfd sealed F_SEAL_WRITE
    /// (or F_SEAL_FUTURE_WRITE): `mprotect(PROT_WRITE)` on them must fail EPERM,
    /// since the sealed backing can never gain a shared writable view
    /// (memfd_create01 check_mfd_non_writeable's mmap+mprotect case).
    write_sealed_shared_maps: Vec<crate::vfs::GuestMemoryRange>,
    /// Active MAP_SHARED, PROT_WRITE mappings of a (sealable) memfd, paired with
    /// the backing open-file description. While one is live, `F_ADD_SEALS`
    /// F_SEAL_WRITE on that memfd must fail EBUSY (memfd_create01 test_share_mmap).
    writable_memfd_maps: Vec<(
        crate::vfs::GuestMemoryRange,
        Arc<crate::kernel::FileDescription>,
    )>,
    /// Live `MAP_SHARED` file aliases, paired with the open-file description
    /// they alias. The alias itself keeps only a dup'd host fd that the runtime
    /// closes right after mapping, so without this the file behind a mapping is
    /// unrecoverable once the guest closes its own fd — and `mremap` needs it to
    /// answer "where does this file end?" before it can grow the mapping (the
    /// tail past EOF is SIGBUS, not zeroes). Same shape and lifetime rules as
    /// `writable_memfd_maps`: trimmed by range whenever a mapping goes away.
    shared_file_alias_maps: Vec<SharedFileAliasEntry>,
    /// File identity retained by private mmap, independent of descriptor lifetime
    /// and pathname replacement. Discard must return to this original source.
    pub(super) private_file_maps: Vec<PrivateFileMapEntry>,
    /// VA ranges of live MAP_SHARED mappings backed by a `memfd_secret(2)` fd.
    /// Secret memory is hidden from the kernel's own view of the process, so
    /// `/proc/<pid>/mem` reads that touch one of these ranges fail EIO
    /// (memfdsecret probe `procmem_hidden`).
    secretmem_maps: Vec<crate::vfs::GuestMemoryRange>,
    /// The exact serialized ELF auxiliary vector written to the guest stack at
    /// exec, captured from the `AddressSpace` via
    /// [`SyscallDispatcher::set_auxv_image`]. Mirrored to `/proc/self/auxv`.
    /// Empty until an image with an initial stack is loaded.
    pub linux_auxv_image: Vec<u8>,
    /// Exact NT_FILE provenance. Boot PT_LOAD records are replaced on exec;
    /// file-backed mmap records are added/trimmed with dynamic VMA commits.
    pub(super) core_file_mappings: Vec<crate::core_dump::FileMapping>,
    // NOTE: the alias-IPA cursor used to live here, but a per-process field is
    // COPIED on fork, so sibling guest processes reused the same IPAs into the
    // shared `hv_vm` (whose stage-2 TLB can't be flushed) and read each other's
    // stale pages — the go-build crash. It now lives in a fork-SHARED counter:
    // `crate::memory::alloc_alias_ipa`.
}

// Moved to `carrick_mem::memory::MemoryLayout` as part of the staged
// backend extraction (docs/superpowers/specs/
// 2026-07-17-native-backend-portability-seams-design.md) so multiple crates
// can share it; re-exported so every `crate::dispatch::MemoryLayout` call site
// is unchanged.
pub(crate) use carrick_mem::memory::MemoryLayout;

impl MemState {
    pub(super) fn new() -> Self {
        Self::new_with_layout(MemoryLayout::hvf_default())
    }

    pub(super) fn new_with_layout(layout: MemoryLayout) -> Self {
        Self {
            layout,
            semantic_vmas: VmaMap::new(),
            brk_current: layout.heap_base,
            mmap_next: layout.mmap_base,
            mmap_writable_high: layout.mmap_base,
            shared: crate::shared_aperture::SharedAperture::new(),
            overlay: crate::shared_aperture::SharedAperture::with_window(
                crate::memory::LINUX_PRIVATE_OVERLAY_BASE,
                crate::memory::LINUX_PRIVATE_OVERLAY_SIZE,
            ),
            free_regions: Vec::new(),
            address_space_regions: None,
            dynamic_maps: Vec::new(),
            host_alias_backed_ranges: Vec::new(),
            alias_vma_ranges: Vec::new(),
            remap_snapshots: std::collections::HashMap::new(),
            bus_fault_ranges: Vec::new(),
            locked_ranges: Vec::new(),
            resident_ranges: Vec::new(),
            resident_tracked_ranges: Vec::new(),
            resident_fault_ranges: FirstTouchArming::default(),
            deferred_anonymous: std::sync::Arc::new(
                carrick_guest_mem::DeferredAnonymousState::new(),
            ),
            growdown_ranges: Vec::new(),
            read_only_shared_file_maps: Vec::new(),
            write_sealed_shared_maps: Vec::new(),
            writable_memfd_maps: Vec::new(),
            shared_file_alias_maps: Vec::new(),
            private_file_maps: Vec::new(),
            secretmem_maps: Vec::new(),
            linux_auxv_image: Vec::new(),
            core_file_mappings: Vec::new(),
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

    #[allow(dead_code)]
    pub(super) fn semantic_vmas(&self) -> &[SemanticVma] {
        self.semantic_vmas.as_slice()
    }
}

/// Debug: log any `mmap_next` LOWERING that crosses `CARRICK_FORK_DEBUG_VA`.
/// The bump allocator's invariant is "everything at/above `mmap_next` is
/// unallocated"; a lowering that crosses a LIVE mapping breaks it and the next
/// bump grant then hands out (and scrubs) memory the guest still owns — the
/// forkserver zeroed-granule corruption. `new` may come from the free-region
/// merge loop, so call this AFTER the final value is computed.
pub(super) fn debug_mmap_next_lowering(old: u64, new: u64) {
    if let Some(debug_va) = std::env::var("CARRICK_FORK_DEBUG_VA")
        .ok()
        .and_then(|raw| u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok())
        && new <= debug_va
        && debug_va < old
    {
        eprintln!(
            "[BUMPDBG] mmap_next lowered {old:#x} -> {new:#x} (crosses debug VA)\n{}",
            std::backtrace::Backtrace::force_capture(),
        );
    }
}

/// Lower the bump cursor to `new_next`, restoring BOTH halves of the invariant
/// stated on `mmap_next`: everything at/above the cursor is unallocated, AND no
/// `free_regions` entry describes memory at/above it.
///
/// Only the first half was ever maintained. The absorb loop reclaims regions
/// CONTIGUOUS BELOW the new cursor, but a lowering can jump PAST an interior
/// hole — a superset `munmap` over a range that already had one — and that hole
/// then sits recorded above the cursor. From there the two hand-out paths
/// disagree: the free-list first fit returns the stale region, and the bump
/// path, which never consults `free_regions`, climbs over the same VA and
/// returns it a SECOND time. The second hand-out is below `mmap_writable_high`,
/// so it is flagged `stale` and its anonymous-reuse scrub memsets the first
/// grant's LIVE mapping to zero.
///
/// Reproduced in about a second with no threads and no fork by
/// `docs/perf-results/2026-08-18-mmap-double-grant/reducers/arena-double-grant.py`:
/// carrick returned `alias=True zeroed_of_first=131072` where Docker returned
/// `alias=False zeroed_of_first=0`.
///
/// Dropping an entry at/above the cursor loses nothing — by the invariant that
/// memory is already unallocated, and the bump path will hand it out again.
pub(super) fn lower_mmap_next(
    mmap_next: &mut u64,
    free_regions: &mut Vec<(u64, u64)>,
    new_next: u64,
) {
    let lowered_from = *mmap_next;
    *mmap_next = new_next;
    // Absorb anything contiguous BELOW the new cursor, repeatedly: each
    // absorbed region can expose another one below it.
    while let Some(pos) = free_regions
        .iter()
        .position(|&(s, l)| s.checked_add(l) == Some(*mmap_next))
    {
        let (s, _l) = free_regions.remove(pos);
        *mmap_next = s;
    }
    let cursor = *mmap_next;
    free_regions.retain_mut(|(start, len)| {
        let end = start.saturating_add(*len);
        if *start >= cursor {
            false
        } else if end > cursor {
            // Straddles the cursor: keep only the part that is still below it.
            *len = cursor - *start;
            true
        } else {
            true
        }
    });
    debug_assert!(
        free_regions
            .iter()
            .all(|&(s, l)| s.saturating_add(l) <= cursor),
        "free region at/above mmap_next {cursor:#x} after lowering from {lowered_from:#x}",
    );
    debug_mmap_next_lowering(lowered_from, cursor);
}

/// Remove `[addr, addr+len)` from the free list, splitting any entry it only
/// partially covers.
///
/// A `MAP_FIXED` allocation inside the arena consumes VA that the free list may
/// still be holding; leaving it listed lets the first fit hand the same address
/// out underneath the live fixed mapping — the same double grant
/// [`lower_mmap_next`] describes, reached from the other direction.
/// Where a non-`MAP_FIXED` arena grant may land relative to a modulus.
///
/// A `mmap(MAP_PRIVATE, fd)` lowered to a host page-cache view needs the guest
/// address congruent to the file offset modulo the HOST page size (16 KiB on
/// Apple Silicon): the view maps whole host pages, so an incongruent grant
/// cannot be backed by the page cache and falls back to an eager snapshot.
/// Linux only promises page alignment for a hint-less grant, so choosing a
/// congruent address is ABI-legal and costs at most `modulus - page` of arena
/// VA, which the allocator parks in its free list rather than stranding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::dispatch) enum MmapGrantCongruence {
    /// Any page-aligned address.
    Any,
    /// `address % modulus == residue` (`modulus` a power of two, `residue`
    /// page-aligned and below `modulus`).
    Residue { modulus: u64, residue: u64 },
}

impl MmapGrantCongruence {
    /// The congruence a private file mapping at `offset` needs to be lowered to
    /// a host page-cache view. `Any` when the host page IS the Linux page.
    pub(in crate::dispatch) fn for_file_offset(offset: u64, linux_page_size: u64) -> Self {
        let modulus = crate::page_profile::host_page_size();
        if modulus <= linux_page_size || !modulus.is_power_of_two() {
            return Self::Any;
        }
        Self::Residue {
            modulus,
            residue: offset & (modulus - 1),
        }
    }

    /// The first address `>= from` that satisfies the congruence.
    fn first_at_or_after(self, from: u64) -> Option<u64> {
        match self {
            Self::Any => Some(from),
            Self::Residue { modulus, residue } => {
                let current = from & (modulus - 1);
                let step = residue.wrapping_sub(current) & (modulus - 1);
                from.checked_add(step)
            }
        }
    }
}

pub(super) fn free_regions_remove_range(regions: &mut Vec<(u64, u64)>, addr: u64, len: u64) {
    let end = addr.saturating_add(len);
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(regions.len() + 1);
    for &(s, l) in regions.iter() {
        let e = s.saturating_add(l);
        if e <= addr || s >= end {
            out.push((s, l));
            continue;
        }
        if s < addr {
            out.push((s, addr - s));
        }
        if e > end {
            out.push((end, e - end));
        }
    }
    *regions = out;
}

/// Insert `[addr, addr+len)` into `regions` (sorted by start), coalescing any
/// adjacent or overlapping ranges. `len` must be > 0.
pub(super) fn free_regions_insert(regions: &mut Vec<(u64, u64)>, addr: u64, len: u64) {
    // Free-list audit: CARRICK_FORK_DEBUG_VA=<hex> logs any insert covering
    // that VA, with the caller — the final provenance hook in the forkserver
    // zeroed-granule chain (an insert overlapping a live mapping is the seed
    // corruption every later grant faithfully amplifies).
    if let Some(debug_va) = std::env::var("CARRICK_FORK_DEBUG_VA")
        .ok()
        .and_then(|raw| u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok())
        && addr <= debug_va
        && debug_va < addr.saturating_add(len)
    {
        eprintln!(
            "[FREEDBG tid={:?}] free_regions_insert {addr:#x}+{len:#x}\n{}",
            std::thread::current().id(),
            std::backtrace::Backtrace::force_capture(),
        );
    }
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

pub(super) fn page_floor(value: u64, page_size: u64) -> u64 {
    value & !(page_size - 1)
}

pub(super) fn page_ceil(value: u64, page_size: u64) -> Option<u64> {
    value
        .checked_add(page_size - 1)
        .map(|end| page_floor(end, page_size))
}

pub(super) fn page_rounded_range(
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

pub(super) fn range_len_usize(range: crate::vfs::GuestMemoryRange) -> Result<usize, LinuxErrno> {
    Ok(range.len())
}

/// Insert `range` into a SORTED, MERGED, non-overlapping range set, coalescing
/// with every entry it touches or abuts.
///
/// The sorted-merged shape is the set's invariant, maintained by this function
/// and by [`locked_ranges_remove`], so only the run of entries that actually
/// touch `range` can change: `partition_point` finds that run's head in
/// O(log n) and one `splice` rewrites just the run.
///
/// This used to `push` + `sort_by_key` the WHOLE vector and then rebuild it
/// into a fresh `Vec` on EVERY insert — O(n log n) time and an O(n) copy per
/// mapping, so O(n^2 log n) over a process's lifetime. LTP `munmap04` builds
/// ~65,000 VMAs and a `sample` of the guest carrier put 769 of ~1,300
/// non-idle samples in this function, with its `slice::sort` (263) and
/// `memmove` (257) callees taking essentially all the rest: the suite ran
/// 2,936 ms against a 402 ms Docker oracle almost entirely inside here. This
/// is the same shape the 2026-07-07 bless fixed in
/// `MemoryProtections::RangeSet` and `dynamic_maps`; this set was missed.
pub(super) fn locked_ranges_insert(
    ranges: &mut Vec<crate::vfs::GuestMemoryRange>,
    range: crate::vfs::GuestMemoryRange,
) {
    let mut start = range.start().raw();
    let mut end = range.end().raw();
    // `<` not `<=`: an entry ending exactly where this one starts ABUTS it and
    // must be coalesced, which is what the old whole-vector merge did.
    let index = ranges.partition_point(|existing| existing.end().raw() < start);
    let mut remove_end = index;
    while let Some(existing) = ranges.get(remove_end) {
        if existing.start().raw() > end {
            break;
        }
        start = start.min(existing.start().raw());
        end = end.max(existing.end().raw());
        remove_end += 1;
    }
    let Some(merged) = crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(end)) else {
        return;
    };
    ranges.splice(index..remove_end, [merged]);
}

pub(super) fn locked_ranges_remove(
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

pub(super) fn locked_ranges_total(ranges: &[crate::vfs::GuestMemoryRange]) -> u64 {
    ranges.iter().map(|range| range.len() as u64).sum()
}

/// Does a SORTED, MERGED, non-overlapping range set (the shape
/// [`locked_ranges_insert`] and [`locked_ranges_remove`] maintain) contain
/// `page`?
///
/// Binary search, not a scan: `fault_requires_mm_mutation` asks this of
/// `resident_tracked_ranges` on EVERY guest fault, and a memory-hungry guest
/// holds thousands of live anonymous extents.
pub(super) fn ranges_contain_page(ranges: &[crate::vfs::GuestMemoryRange], page: u64) -> bool {
    let index = ranges.partition_point(|range| range.end().raw() <= page);
    ranges
        .get(index)
        .is_some_and(|range| range.start().raw() <= page)
}

pub(super) fn ranges_overlap(a_start: u64, a_len: u64, b_start: u64, b_end: u64) -> bool {
    let Some(a_end) = a_start.checked_add(a_len) else {
        return true;
    };
    a_start < b_end && b_start < a_end
}

pub(super) fn dynamic_mapping_overlaps_sorted(
    maps: &[ProcMapsEntry],
    start: u64,
    len: u64,
) -> bool {
    let Some(end) = start.checked_add(len) else {
        return true;
    };
    let idx = maps.partition_point(|map| map.end <= start);
    maps.get(idx).is_some_and(|map| map.start < end)
}

pub(super) fn guest_vma_overlaps_locked(mem: &MemState, start: u64, len: u64) -> bool {
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

pub(super) fn guest_vma_covers_locked(mem: &MemState, start: u64, len: u64) -> bool {
    let Some(end) = start.checked_add(len) else {
        return false;
    };
    let mut cursor = start;
    for vma in project_vma_summaries(mem) {
        if vma.end.raw() <= cursor {
            continue;
        }
        if vma.start.raw() > cursor {
            return false;
        }
        cursor = cursor.max(vma.end.raw());
        if cursor >= end {
            return true;
        }
    }
    false
}

pub(super) fn boot_region_is_hidden_mmap_backing(
    map: &ProcMapsEntry,
    layout: MemoryLayout,
) -> bool {
    map.start == layout.mmap_base && map.end == layout.mmap_base.saturating_add(layout.mmap_size)
}

pub(super) fn boot_region_is_hidden_heap_backing(
    map: &ProcMapsEntry,
    layout: MemoryLayout,
) -> bool {
    map.start == layout.heap_base && map.end == layout.heap_base.saturating_add(layout.heap_size)
}

pub(super) fn boot_region_is_hidden_shared_aperture(map: &ProcMapsEntry) -> bool {
    map.start == crate::memory::LINUX_SHARED_FILE_BASE
        && map.end
            == crate::memory::LINUX_SHARED_FILE_BASE
                .saturating_add(crate::memory::LINUX_SHARED_FILE_SIZE)
}

pub(super) fn boot_region_is_hidden_private_overlay(map: &ProcMapsEntry) -> bool {
    map.start == crate::memory::LINUX_PRIVATE_OVERLAY_BASE
        && map.end
            == crate::memory::LINUX_PRIVATE_OVERLAY_BASE
                .saturating_add(crate::memory::LINUX_PRIVATE_OVERLAY_SIZE)
}

/// Is `map` one of carrick's own EL1-only pages in the kernel hole?
///
/// The 2 MiB block at [`LINUX_KERNEL_REGION_BASE`](crate::memory::LINUX_KERNEL_REGION_BASE)
/// holds the EL0 entry trampoline, the EL1 vector table, the stage-1 page
/// tables, the EL1 maintenance trampoline, the per-process identity page and
/// the syscall mailbox arena. `stage1_identity_page_tables` maps that whole
/// block `AP=00` — kernel-only — so guest EL0 can neither read nor write it.
/// It is carrick implementation exactly like the hidden mmap/heap
/// reservations, Linux has no such VMA, and a real Linux core has no such
/// `PT_LOAD`.
pub(super) fn boot_region_is_carrick_kernel_hole(map: &ProcMapsEntry) -> bool {
    let base = crate::memory::LINUX_KERNEL_REGION_BASE;
    let end = base.saturating_add(crate::memory::LINUX_KERNEL_REGION_SIZE);
    map.start >= base && map.end <= end && map.start < map.end
}

pub(super) fn boot_region_is_hidden_reservation(map: &ProcMapsEntry, layout: MemoryLayout) -> bool {
    boot_region_is_hidden_mmap_backing(map, layout)
        || boot_region_is_hidden_heap_backing(map, layout)
        || boot_region_is_hidden_shared_aperture(map)
        || boot_region_is_hidden_private_overlay(map)
}

pub(super) fn find_canonical_high_va_gap(
    mem: &MemState,
    length: u64,
    congruence: MmapGrantCongruence,
) -> Option<(u64, bool)> {
    if length == 0 || length > (1u64 << 48) {
        return None;
    }
    let mut occupied: Vec<(u64, u64)> = Vec::new();

    for map in &mem.dynamic_maps {
        if map.end > crate::memory::LINUX_HIGH_VA_THRESHOLD {
            occupied.push((
                map.start.max(crate::memory::LINUX_HIGH_VA_THRESHOLD),
                map.end,
            ));
        }
    }
    for (_, current, vma_end) in &mem.growdown_ranges {
        if *vma_end > crate::memory::LINUX_HIGH_VA_THRESHOLD {
            occupied.push((
                (*current).max(crate::memory::LINUX_HIGH_VA_THRESHOLD),
                *vma_end,
            ));
        }
    }
    if let Some(ref regions) = mem.address_space_regions {
        for map in regions {
            if !boot_region_is_hidden_reservation(map, mem.layout)
                && map.end > crate::memory::LINUX_HIGH_VA_THRESHOLD
            {
                occupied.push((
                    map.start.max(crate::memory::LINUX_HIGH_VA_THRESHOLD),
                    map.end,
                ));
            }
        }
    }
    occupied.push((
        crate::memory::LINUX_ROSETTA_VA_BASE,
        crate::memory::LINUX_ROSETTA_VA_BASE
            .saturating_add(crate::memory::LINUX_ROSETTA_WINDOW_SIZE),
    ));

    occupied.sort_unstable_by_key(|&(s, _)| s);
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(occupied.len());
    for (s, e) in occupied {
        if let Some(last) = merged.last_mut() {
            if s <= last.1 {
                last.1 = last.1.max(e);
                continue;
            }
        }
        merged.push((s, e));
    }

    let high_va_top = 1u64 << 48;
    let mut candidate = crate::memory::LINUX_HIGH_VA_THRESHOLD;

    for (occ_start, occ_end) in merged {
        let start = congruence.first_at_or_after(candidate)?;
        if let Some(end) = start.checked_add(length)
            && end <= occ_start
            && end <= high_va_top
        {
            return Some((start, false));
        }
        candidate = candidate.max(occ_end);
    }

    let start = congruence.first_at_or_after(candidate)?;
    if let Some(end) = start.checked_add(length)
        && end <= high_va_top
    {
        return Some((start, false));
    }

    None
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

pub(super) fn proc_mapping_sharing(sharing: ProcMapSharing) -> carrick_guest_mem::MappingSharing {
    match sharing {
        ProcMapSharing::Private => carrick_guest_mem::MappingSharing::Private,
        ProcMapSharing::Shared => carrick_guest_mem::MappingSharing::Shared,
    }
}

impl<'a> MemView<'a> {
    pub(crate) fn update_madvise_vma_policy(
        &self,
        start: u64,
        len: u64,
        copy_update: Option<carrick_abi::VmaForkCopyPolicy>,
        child_update: Option<carrick_abi::VmaForkChildPolicy>,
        dump_update: Option<carrick_abi::VmaDumpPolicy>,
    ) {
        let Some(end) = start.checked_add(len) else {
            return;
        };
        let mem_authority = self.mem();
        let mut mem = mem_authority.lock();
        mem.semantic_vmas
            .update_policy(start, end, copy_update, child_update, dump_update);
    }

    /// Whether `[start, start + len)` is fully covered by VMAs whose contents
    /// `MADV_DONTDUMP` keeps out of a core dump.
    pub fn vma_dump_omitted_for_test(&self, start: u64, len: u64) -> bool {
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        self.mem()
            .lock()
            .semantic_vmas
            .overlapping(start, end)
            .all(|vma| vma.dump_policy == carrick_abi::VmaDumpPolicy::Omit)
    }

    /// Private VMAs added after image construction. Dynamic mapping helpers
    /// preserve ranges so `CLONE_VM` also covers high aliases selected by
    /// `mmap(MAP_FIXED)`.
    #[allow(dead_code)]
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
        self.mem()
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
        dynamic_mapping_overlaps_sorted(&self.mem().lock().dynamic_maps, start, len)
    }

    /// Whether `[start, start + len)` overlaps a Linux-visible guest VMA.
    ///
    /// The boot snapshot includes Carrick's hidden heap and mmap backing arenas;
    /// those reservations are not VMAs by themselves. Dynamic mappings inside
    /// either arena and the live `[heap_base, brk_current)` span are real VMAs and
    /// are checked separately before the hidden boot reservations are filtered.
    pub(super) fn guest_vma_overlaps(&self, start: u64, len: u64) -> bool {
        guest_vma_overlaps_locked(&self.mem().lock(), start, len)
    }

    fn range_intersects_shared_mapping(&self, start: u64, len: u64) -> bool {
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        let mem_authority_3 = self.mem();
        let mem = mem_authority_3.lock();
        mem.dynamic_maps
            .iter()
            .chain(mem.address_space_regions.iter().flatten())
            .any(|map| map.sharing == ProcMapSharing::Shared && map.start < end && map.end > start)
    }

    fn native16k_write_exec_rejection(
        &self,
        memory: &dyn CurrentMmMemory,
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
        memory: &dyn CurrentMmMemory,
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

    /// Recover the one source VMA `mremap` is allowed to transform. Combining
    /// adjacent VMAs by OR-ing their permission bits can manufacture broader
    /// access than either source had (for example RX + R becoming one RX move),
    /// and a byte-copy cannot preserve mixed backing identities. Reject a gap or
    /// any range spanning more than one VMA before touching allocator/backing
    /// state, matching Linux's `EFAULT` for an invalid old mapping range.
    fn mremap_mapping_metadata(
        &self,
        memory: &impl CurrentMmMemory,
        start: u64,
        len: u64,
    ) -> Result<MremapMappingMetadata, LinuxErrno> {
        let end = start.checked_add(len).ok_or(LINUX_EFAULT)?;
        let mem_authority_5 = self.mem();
        let mem = mem_authority_5.lock();
        let fork_semantics =
            MremapForkSemantics::capture(&mem.semantic_vmas, start, len).ok_or(LINUX_EFAULT)?;
        let private_file = mem
            .private_file_maps
            .iter()
            .find(|source| source.start <= start && end <= source.end)
            .and_then(|source| source.clip(start, end));
        let mut overlapping_dynamic = mem
            .dynamic_maps
            .iter()
            .filter(|map| map.start < end && map.end > start);
        if let Some(first) = overlapping_dynamic.next() {
            let mut mapping = first.clone();
            if first.start > start || first.end < end || overlapping_dynamic.next().is_some() {
                // mprotect may split the proc-map projection and later restore
                // one canonical VMA. Join only fragments of the same retained
                // private-file source with identical permissions and no holes.
                // Independent mappings or mixed semantic VMAs remain refused.
                if private_file.is_none() || fork_semantics.vmas.len() != 1 {
                    return Err(LINUX_EFAULT);
                }
                let mut cursor = start;
                for row in mem
                    .dynamic_maps
                    .iter()
                    .filter(|row| row.start < end && row.end > start)
                {
                    if row.start > cursor
                        || row.read != first.read
                        || row.write != first.write
                        || row.execute != first.execute
                        || row.sharing != first.sharing
                        || row.path != first.path
                    {
                        return Err(LINUX_EFAULT);
                    }
                    cursor = row.end.min(end);
                }
                if cursor != end {
                    return Err(LINUX_EFAULT);
                }
                mapping.start = start;
                mapping.end = end;
            }
            let file_page_offset = mem
                .core_file_mappings
                .iter()
                .find(|mapping| mapping.start <= start && mapping.end >= end)
                .map(|mapping| {
                    mapping.file_page_offset
                        + (start - mapping.start) / crate::core_dump::GUEST_PAGE as u64
                })
                .or_else(|| fork_semantics.vmas.first().and_then(|v| v.file_page_offset));
            let mut metadata =
                proc_maps_entry_mremap_metadata(&mapping, file_page_offset, fork_semantics);
            metadata.private_file = private_file;
            return Ok(metadata);
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
        let file_page_offset = mem
            .core_file_mappings
            .iter()
            .find(|mapping| mapping.start <= start && mapping.end >= end)
            .map(|mapping| {
                mapping.file_page_offset
                    + (start - mapping.start) / crate::core_dump::GUEST_PAGE as u64
            })
            .or_else(|| fork_semantics.vmas.first().and_then(|v| v.file_page_offset));
        Ok(proc_maps_entry_mremap_metadata(
            region,
            file_page_offset,
            fork_semantics,
        ))
    }

    fn update_dynamic_mapping_prot(&self, start: u64, len: u64, prot: LinuxProtFlags) {
        let mem_authority_8 = self.mem();
        let mut mem = mem_authority_8.lock();
        let Some(end) = start.checked_add(len) else {
            return;
        };
        update_proc_map_prot(&mut mem.dynamic_maps, start, len, prot);
        mem.semantic_vmas.update_prot(
            start,
            end,
            prot.contains(LinuxProtFlags::READ),
            prot.contains(LinuxProtFlags::WRITE),
            prot.contains(LinuxProtFlags::EXEC),
        );

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
    #[cfg(test)]
    pub(crate) fn reset_memory_state_on_execve(&self) {
        self.with_vma_dispatch_for_test(|_vma_dispatch| {
            self.mem().lock().reset_for_execve();
        });
    }

    pub(in crate::dispatch) fn next_mmap_address(
        &self,
        requested: u64,
        length: u64,
        prot: u64,
        flags: u64,
        congruence: MmapGrantCongruence,
    ) -> Option<(u64, bool)> {
        let granted = self.next_mmap_address_inner(requested, length, prot, flags, congruence);
        // Grant audit: CARRICK_MMAP_GRANT_DEBUG=1 logs any non-FIXED grant that
        // overlaps a LIVE dynamic mapping, with the allocator state and caller.
        // A double-grant here scrubbed a live CPython interned-dict granule to
        // zeros (the forkserver SIGSEGV cluster); this names the guilty path in
        // one run instead of a day of ledger archaeology.
        if flags & LINUX_MAP_FIXED == 0
            && std::env::var_os("CARRICK_MMAP_GRANT_DEBUG").is_some()
            && let Some((address, _)) = granted
        {
            let mem_authority_9 = self.mem();
            let mem = mem_authority_9.lock();
            let overlaps: Vec<_> = mem
                .dynamic_maps
                .iter()
                .filter(|map| map.start < address.saturating_add(length) && map.end > address)
                .map(|map| (map.start, map.end))
                .collect();
            if !overlaps.is_empty() {
                eprintln!(
                    "[GRANTDBG pid={}] non-fixed grant {address:#x}+{length:#x} OVERLAPS live {overlaps:x?}\n  \
                     mmap_next={:#x} free_regions={:x?}\n{}",
                    self.identity_pid(),
                    mem.mmap_next,
                    mem.free_regions,
                    std::backtrace::Backtrace::force_capture(),
                );
            }
            // Even without a ledger overlap, a grant covering the debug VA is
            // the event under investigation — dump the ledger's view of the
            // neighbourhood so a MISSING dynamic_maps entry is visible too.
            if let Some(debug_va) = std::env::var("CARRICK_FORK_DEBUG_VA")
                .ok()
                .and_then(|raw| u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok())
                && address <= debug_va
                && debug_va < address.saturating_add(length)
            {
                let near: Vec<_> = mem
                    .dynamic_maps
                    .iter()
                    .filter(|map| {
                        map.end > address.saturating_sub(0x200000)
                            && map.start < address.saturating_add(length + 0x200000)
                    })
                    .map(|map| (map.start, map.end))
                    .collect();
                eprintln!(
                    "[GRANTDBG pid={}] grant {address:#x}+{length:#x} covers debug VA; dynamic_maps near: \
                     {near:x?}\n  mmap_next={:#x} free_regions={:x?}\n{}",
                    self.identity_pid(),
                    mem.mmap_next,
                    mem.free_regions,
                    std::backtrace::Backtrace::force_capture(),
                );
            }
        }
        granted
    }

    fn next_mmap_address_inner(
        &self,
        requested: u64,
        length: u64,
        prot: u64,
        flags: u64,
        congruence: MmapGrantCongruence,
    ) -> Option<(u64, bool)> {
        // Only a WRITABLE hand-out can ever leave a non-zero byte behind, so
        // only a writable hand-out raises the watermark. A `PROT_NONE` reserve
        // — Go's allocator makes them by the gigabyte — cannot be stored into,
        // and raising the watermark past it forced every later allocation below
        // it to be scrubbed for nothing. `mprotect` is the other mark point;
        // see `mmap_writable_high`.
        let writable = prot & LINUX_PROT_WRITE != 0;
        let page_size = self.linux_page_size();
        let layout = self.mem().lock().layout;
        if flags & LINUX_MAP_FIXED != 0 {
            if requested == 0 || !requested.is_multiple_of(page_size) {
                return None;
            }
            // THE THIRD MARK POINT, and it closes a hole that predates the
            // writability gate. `MAP_FIXED` returns early without consulting or
            // raising the watermark, so a writable fixed mapping that the guest
            // then wrote to left no trace: a later bump allocation landing on
            // that span would compare against a watermark that never covered it
            // and skip the scrub. It was masked because the scrub site also
            // fires on `fixed_anonymous`, which only protects the FIXED mapping
            // itself — not the plain bump that inherits its pages afterwards.
            // Raising it here is cheap and keeps the invariant whole: every way
            // a range becomes writable raises the watermark.
            if range_within(requested, length, layout.mmap_base, layout.mmap_size)
                && let Some(end) = requested.checked_add(length)
            {
                let mem_authority_10 = self.mem();
                let mut mem = mem_authority_10.lock();
                if prot & LINUX_PROT_WRITE != 0 {
                    mem.mmap_writable_high = mem.mmap_writable_high.max(end);
                }
                // A `MAP_FIXED` inside the arena ALLOCATES arena VA, so both
                // hand-out paths have to be told. Neither was: the free list
                // could still be holding this range, and the bump cursor stayed
                // below it and later climbed straight over it — handing the same
                // address out a second time and scrubbing the live mapping to
                // zero. See `lower_mmap_next` for the full mechanism and the
                // one-second reducer.
                free_regions_remove_range(&mut mem.free_regions, requested, length);
                if end > mem.mmap_next {
                    // Skipping ahead would strand `[mmap_next, requested)`
                    // forever, so hand it to the free list rather than lose it.
                    let gap_start = mem.mmap_next;
                    if requested > gap_start {
                        free_regions_insert(
                            &mut mem.free_regions,
                            gap_start,
                            requested - gap_start,
                        );
                    }
                    mem.mmap_next = end;
                }
            }
            return Some((requested, false));
        }

        if requested != 0 {
            let aligned_hint = requested.is_multiple_of(page_size);
            let arena_hint =
                aligned_hint && range_within(requested, length, layout.mmap_base, layout.mmap_size);
            if arena_hint {
                let mem_authority_11 = self.mem();
                let mut mem = mem_authority_11.lock();
                let end = requested.checked_add(length)?;
                if requested >= mem.mmap_next {
                    mem.mmap_next = end;
                    // `reused` (forces a zero-fill) iff this bump landed on memory
                    // the guest already dirtied below the monotonic dirty high-
                    // water (mmap_next was lowered by a prior munmap). Above the
                    // high-water it's pristine guest RAM — keep it lazily zero.
                    let stale = requested < mem.mmap_writable_high;
                    if writable {
                        mem.mmap_writable_high = mem.mmap_writable_high.max(end);
                    }
                    return Some((requested, stale));
                }
            }
            let canonical_alias_hint =
                aligned_hint && mmap_address_uses_alias(requested, length, layout);
            if canonical_alias_hint {
                let mem_authority_hint = self.mem();
                let mem = mem_authority_hint.lock();
                let rosetta_start = crate::memory::LINUX_ROSETTA_VA_BASE;
                let rosetta_end =
                    rosetta_start.saturating_add(crate::memory::LINUX_ROSETTA_WINDOW_SIZE);
                if !guest_vma_overlaps_locked(&mem, requested, length)
                    && !ranges_overlap(requested, length, rosetta_start, rosetta_end)
                {
                    return Some((requested, false));
                }
            }
        }

        let mem_authority_12 = self.mem();

        let mut mem = mem_authority_12.lock();
        if length <= layout.mmap_size {
            // First free region with a congruent fit. The slack before a congruent
            // start and the remainder after the grant both stay on the free list.
            let fit = mem
                .free_regions
                .iter()
                .enumerate()
                .find_map(|(pos, &(s, l))| {
                    let start = congruence.first_at_or_after(s)?;
                    let region_end = s.checked_add(l)?;
                    let end = start.checked_add(length)?;
                    (end <= region_end).then_some((pos, s, start, end, region_end))
                });
            if let Some((pos, s, start, end, region_end)) = fit {
                mem.free_regions.remove(pos);
                if start > s {
                    free_regions_insert(&mut mem.free_regions, s, start - s);
                }
                if end < region_end {
                    free_regions_insert(&mut mem.free_regions, end, region_end - end);
                }
                return Some((start, true));
            }
            if let Some(cursor) = align_up_u64(mem.mmap_next, page_size)
                && let Some(address) = congruence.first_at_or_after(cursor)
                && range_within(address, length, layout.mmap_base, layout.mmap_size)
                && let Some(end) = address.checked_add(length)
            {
                // A congruent bump skipped `[cursor, address)`; park it for reuse
                // rather than stranding it.
                if address > cursor {
                    free_regions_insert(&mut mem.free_regions, cursor, address - cursor);
                }
                mem.mmap_next = end;
                // Same dirty-high-water discipline as the hint path: a bump allocation
                // that dips below the high-water (because munmap lowered mmap_next over
                // already-touched pages) must be zeroed, not returned with stale bytes.
                let stale = address < mem.mmap_writable_high;
                if writable {
                    mem.mmap_writable_high = mem.mmap_writable_high.max(end);
                }
                return Some((address, stale));
            }
        }

        find_canonical_high_va_gap(&mem, length, congruence)
    }
}

impl<'a> MemView<'a> {
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
    pub(in crate::dispatch::mem) fn mincore_residency_vector(
        &self,
        memory: &impl CurrentMmMemory,
        address: u64,
        pages: u64,
        page_size: u64,
    ) -> Option<Vec<u8>> {
        let live_residency = memory.resident_pages(GuestVa(address), pages, page_size);
        let mem_authority_30 = self.mem();
        let mem = mem_authority_30.lock();
        let zero_reads = mem.deferred_anonymous.snapshot().zero_read_resident;
        let mut out = Vec::with_capacity(usize::try_from(pages).ok()?);
        for index in 0..pages {
            let page = address.checked_add(index.checked_mul(page_size)?)?;
            let in_dynamic = mem
                .dynamic_maps
                .iter()
                .any(|m| page >= m.start && page < m.end);
            let resident = if in_dynamic {
                ranges_contain_page(&mem.resident_ranges, page)
                    || zero_reads
                        .iter()
                        .any(|r| r.start.raw() <= page && page < r.end.raw())
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
        self.mem()
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
        let mem_authority_31 = self.mem();
        let mem = mem_authority_31.lock();
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
            || mem.resident_fault_ranges.overlaps(start, end)
            || mem.write_sealed_shared_maps.iter().any(overlaps)
            || mem
                .writable_memfd_maps
                .iter()
                .any(|(range, _)| overlaps(range))
            || mem.host_alias_backed_ranges.iter().any(overlaps)
            || mem.alias_vma_ranges.iter().any(overlaps)
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

    /// Fast lock-free check for whether `RLIMIT_AS` or (for data mappings) `RLIMIT_DATA`
    /// is finite. If neither applies or both are `LINUX_RLIM_INFINITY` (carrick's default),
    /// returns `None`, allowing callers to skip acquiring `MemState` locks, calculating
    /// `MAP_FIXED` overlaps, and walking/projecting VMAs.
    #[inline]
    pub(super) fn address_space_limits_apply(&self, data: bool) -> Option<(u64, u64)> {
        let mut as_limit = self.effective_resource_limit(LINUX_RLIMIT_AS).rlim_cur;
        if let Some(task) = super::resources::task() {
            if let Some(budget) = task.container().budget() {
                if let Some(max_mem) = budget.max_memory_limit() {
                    as_limit = as_limit.min(max_mem);
                }
            }
        }
        let data_limit = if data {
            self.effective_resource_limit(LINUX_RLIMIT_DATA).rlim_cur
        } else {
            LINUX_RLIM_INFINITY
        };
        if as_limit != LINUX_RLIM_INFINITY || data_limit != LINUX_RLIM_INFINITY {
            Some((as_limit, data_limit))
        } else {
            None
        }
    }

    /// Check address space limits when at least one limit is finite, under an existing `MemState` lock.
    pub(super) fn check_address_space_limits_locked(
        &self,
        mem: &MemState,
        as_limit: u64,
        data_limit: u64,
        grow: u64,
        data: bool,
    ) -> Result<(), LinuxErrno> {
        if as_limit != LINUX_RLIM_INFINITY
            && committed_va_bytes(mem)
                .checked_add(grow)
                .is_none_or(|total| total > as_limit)
        {
            return Err(LINUX_ENOMEM);
        }
        if data
            && data_limit != LINUX_RLIM_INFINITY
            && data_va_bytes(mem)
                .checked_add(grow)
                .is_none_or(|total| total > data_limit)
        {
            return Err(LINUX_ENOMEM);
        }
        Ok(())
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
        if creds.euid.is_root() {
            return Ok(Some(length));
        }
        let limit = self.effective_resource_limit(LINUX_RLIMIT_MEMLOCK).rlim_cur;
        if limit == 0 {
            return Err(LINUX_EPERM);
        }
        let locked = locked_ranges_total(&self.mem().lock().locked_ranges);
        if locked.checked_add(length).is_none_or(|total| total > limit) {
            return Err(LINUX_ENOMEM);
        }
        Ok(Some(length))
    }

    pub(in crate::dispatch::mem) fn commit_mmap_locked_range(
        &self,
        memory: &mut impl CurrentMmMemory,
        range: Option<crate::vfs::GuestMemoryRange>,
    ) -> Result<(), LinuxErrno> {
        let Some(range) = range else {
            return Ok(());
        };
        self.populate_resident_range(memory, range)?;
        locked_ranges_insert(&mut self.mem().lock().locked_ranges, range);
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::dispatch::mem) fn commit_eager_locked_range(
        &self,
        range: Option<crate::vfs::GuestMemoryRange>,
    ) {
        let Some(range) = range else {
            return;
        };
        let mem_authority_37 = self.mem();
        let mut mem = mem_authority_37.lock();
        locked_ranges_insert(&mut mem.resident_ranges, range);
        locked_ranges_insert(&mut mem.locked_ranges, range);
    }

    fn rollback_shared_anon_mapping(
        &self,
        memory: &mut impl CurrentMmMemory,
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
                carrick_fatal!(
                    "dispatch::mmap_rollback",
                    "shared-anon rollback unmap failed under concurrent-exec protection"
                );
            }
            return Err(MemoryError::HostMap(format!(
                "shared-anon rollback unmap at 0x{address:x} for {mapped_length} bytes failed: \
                 {first}; retry failed: {retry}"
            )));
        }
        memory.set_unmapped(address, mapped_length, true);
        let mem_authority_38 = self.mem();
        let mut mem = mem_authority_38.lock();
        mem.shared.free(address);
        locked_ranges_remove(&mut mem.locked_ranges, range);
        locked_ranges_remove(&mut mem.resident_ranges, range);
        locked_ranges_remove(&mut mem.resident_tracked_ranges, range);
        mem.resident_fault_ranges.disarm(range);
        Ok(())
    }

    /// Roll back a freshly allocated private-arena mapping. Native direct
    /// execution cannot return while a failed publication remains host-mapped:
    /// retry once, then retain Task 51's fail-stop behavior so process teardown
    /// is the final ownership backstop.
    fn rollback_fresh_arena_mapping(
        &self,
        memory: &mut impl CurrentMmMemory,
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
                carrick_fatal!(
                    "dispatch::mmap_rollback",
                    "arena rollback unmap failed under concurrent-exec protection"
                );
            }
            return Err(MemoryError::HostMap(format!(
                "arena rollback unmap at 0x{address:x} for {len} bytes failed: \
                 {first}; retry failed: {retry}"
            )));
        }
        mark_range_unmapped(memory, address, len_usize);
        let mem_authority_39 = self.mem();
        let mut mem = mem_authority_39.lock();
        if address.checked_add(len) == Some(mem.mmap_next) {
            let mem = &mut *mem;
            lower_mmap_next(&mut mem.mmap_next, &mut mem.free_regions, address);
        } else {
            free_regions_insert(&mut mem.free_regions, address, len);
        }
        Ok(())
    }
}

macro_rules! forward_mem_handlers {
    ($( $handler:ident ),* $(,)?) => {
        impl SyscallDispatcher {
            $(
                #[inline]
                pub(crate) fn $handler<M: CurrentMmMemory>(
                    &self,
                    cx: &mut SyscallCtx<M>,
                ) -> Result<DispatchOutcome, DispatchError> {
                    self.mem_view().$handler(cx)
                }
            )*
        }
    };
}

forward_mem_handlers! {
    readahead,
    fadvise64,
    io_uring_setup,
    io_uring_enter,
    io_uring_register,
    sys_membarrier,
    userfaultfd,
}

macro_rules! forward_mem_mutation_handlers {
    ($( $handler:ident ),* $(,)?) => {
        impl SyscallDispatcher {
            $(
                #[inline]
                pub(crate) fn $handler<M: CurrentMmMemory>(
                    &self,
                    cx: &mut MutationSyscallCtx<M>,
                ) -> Result<DispatchOutcome, DispatchError> {
                    self.mem_view().$handler(cx)
                }
            )*
        }
    };
}

forward_mem_mutation_handlers! {
    brk,
    munmap,
    mremap,
    mmap,
    mprotect,
    msync,
    mlock,
    munlock,
    mlockall,
    munlockall,
    mincore,
    madvise,
    remap_file_pages,
    mlock2,
}

impl SyscallDispatcher {
    #[inline]
    pub(super) fn commit_host_alias_mmap_observed(
        &self,
        authority: &super::DispatchMmAuthority,
        commit: HostAliasMmapCommit,
    ) {
        self.mem_view()
            .commit_host_alias_mmap_observed(authority, commit);
    }

    #[cfg(test)]
    #[inline]
    pub(super) fn commit_host_alias_mmap(&self, commit: HostAliasMmapCommit) {
        self.mem_view().commit_host_alias_mmap(commit);
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn update_madvise_vma_policy(
        &self,
        start: u64,
        len: u64,
        copy_update: Option<carrick_abi::VmaForkCopyPolicy>,
        child_update: Option<carrick_abi::VmaForkChildPolicy>,
        dump_update: Option<carrick_abi::VmaDumpPolicy>,
    ) {
        self.mem_view().update_madvise_vma_policy(
            start,
            len,
            copy_update,
            child_update,
            dump_update,
        );
    }

    #[inline]
    pub fn vma_dump_omitted_for_test(&self, start: u64, len: u64) -> bool {
        self.mem_view().vma_dump_omitted_for_test(start, len)
    }

    #[inline]
    pub(super) fn guest_vma_overlaps(&self, start: u64, len: u64) -> bool {
        self.mem_view().guest_vma_overlaps(start, len)
    }

    #[inline]
    pub(in crate::dispatch) fn range_touches_secretmem(&self, start: u64, len: u64) -> bool {
        self.mem_view().range_touches_secretmem(start, len)
    }

    #[inline]
    pub(super) fn remove_mapping_metadata(&self, start: u64, len: u64) {
        self.mem_view().remove_mapping_metadata(start, len);
    }

    #[inline]
    pub(in crate::dispatch) fn memfd_has_writable_shared_map(
        &self,
        description: &Arc<crate::kernel::FileDescription>,
    ) -> bool {
        self.mem_view().memfd_has_writable_shared_map(description)
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn record_dynamic_mapping(
        &self,
        start: u64,
        len: u64,
        prot: LinuxProtFlags,
        sharing: ProcMapSharing,
        path: String,
    ) {
        self.mem_view()
            .record_dynamic_mapping(start, len, prot, sharing, path);
    }

    #[cfg(test)]
    #[inline]
    pub(in crate::dispatch::mem) fn record_dynamic_mapping_with_file_offset(
        &self,
        start: u64,
        len: u64,
        prot: LinuxProtFlags,
        sharing: ProcMapSharing,
        path: String,
        semantics: DynamicMappingSemantics,
    ) {
        self.mem_view()
            .record_dynamic_mapping_with_file_offset(start, len, prot, sharing, path, semantics);
    }

    #[inline]
    pub(crate) fn mmap_fault_is_sigbus(&self, addr: u64) -> bool {
        self.mem_view().mmap_fault_is_sigbus(addr)
    }

    #[inline]
    pub(crate) fn fault_requires_mm_mutation(&self, addr: u64) -> bool {
        self.mem_view().fault_requires_mm_mutation(addr)
    }

    #[inline]
    pub(crate) fn mmap_growdown_fault_plan<'permit>(
        &self,
        permit: &'permit super::mm_mutation::HostAliasPermit<'_>,
        addr: u64,
    ) -> Option<MmapGrowdownFaultPlan<'permit>> {
        self.mem_view().mmap_growdown_fault_plan(permit, addr)
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn with_mmap_growdown_fault_plan_for_test<T>(
        &self,
        addr: u64,
        use_plan: impl FnOnce(MmapGrowdownFaultPlan<'_>) -> T,
    ) -> Option<T> {
        self.mem_view()
            .with_mmap_growdown_fault_plan_for_test(addr, use_plan)
    }

    #[inline]
    pub(crate) fn commit_mmap_growdown(&self, plan: MmapGrowdownFaultPlan) {
        self.mem_view().commit_mmap_growdown(plan);
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn reset_memory_state_on_execve(&self) {
        self.mem_view().reset_memory_state_on_execve();
    }

    #[cfg(test)]
    #[inline]
    pub(in crate::dispatch) fn next_mmap_address(
        &self,
        requested: u64,
        length: u64,
        prot: u64,
        flags: u64,
        congruence: MmapGrantCongruence,
    ) -> Option<(u64, bool)> {
        self.mem_view()
            .next_mmap_address(requested, length, prot, flags, congruence)
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn dynamic_mapping_for_test(&self, start: u64) -> Option<ProcMapsEntry> {
        self.mem_view().dynamic_mapping_for_test(start)
    }

    #[cfg(test)]
    #[inline]
    pub(super) fn range_has_mapping_metadata_for_test(&self, start: u64, len: u64) -> bool {
        self.mem_view()
            .range_has_mapping_metadata_for_test(start, len)
    }

    #[inline]
    pub(crate) fn resident_fault_plan<'permit>(
        &self,
        permit: &'permit super::mm_mutation::HostAliasPermit<'_>,
        address: u64,
    ) -> Option<ResidentFaultPlan<'permit>> {
        self.mem_view().resident_fault_plan(permit, address)
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn seed_resident_fault_for_test(&self, page: u64, prot: u64) {
        self.mem_view().seed_resident_fault_for_test(page, prot);
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn with_resident_fault_plan_for_test<T>(
        &self,
        page: u64,
        use_plan: impl FnOnce(ResidentFaultPlan<'_>) -> T,
    ) -> Option<T> {
        self.mem_view()
            .with_resident_fault_plan_for_test(page, use_plan)
    }

    #[inline]
    pub(crate) fn commit_resident_fault(&self, plan: ResidentFaultPlan) {
        self.mem_view().commit_resident_fault(plan);
    }

    #[cfg(test)]
    #[inline]
    pub(super) fn address_space_limits_apply(&self, data: bool) -> Option<(u64, u64)> {
        self.mem_view().address_space_limits_apply(data)
    }

    #[cfg(test)]
    #[inline]
    pub(in crate::dispatch::mem) fn recover_private_repoint_failure(
        &self,
        candidate: u64,
        failure: carrick_guest_mem::RepointPrivateError,
    ) -> PrivateRepointRecovery {
        self.mem_view()
            .recover_private_repoint_failure(candidate, failure)
    }

    #[cfg(test)]
    #[inline]
    pub(in crate::dispatch::mem) fn madvise_range_meta(
        &self,
        start: u64,
        end: u64,
    ) -> MadviseRangeMeta {
        self.mem_view().madvise_range_meta(start, end)
    }

    #[cfg(test)]
    #[inline]
    pub(in crate::dispatch::mem) fn mark_range_resident(&self, start: u64, len: u64) {
        self.mem_view().mark_range_resident(start, len);
    }

    #[cfg(test)]
    #[inline]
    pub(in crate::dispatch::mem) fn mincore_residency_vector(
        &self,
        memory: &impl CurrentMmMemory,
        address: u64,
        pages: u64,
        page_size: u64,
    ) -> Option<Vec<u8>> {
        self.mem_view()
            .mincore_residency_vector(memory, address, pages, page_size)
    }

    #[cfg(test)]
    #[inline]
    pub(in crate::dispatch::mem) fn range_has_host_alias_backing(
        &self,
        start: u64,
        len: u64,
    ) -> bool {
        self.mem_view().range_has_host_alias_backing(start, len)
    }

    #[cfg(test)]
    #[inline]
    pub(in crate::dispatch::mem) fn record_growdown_mapping(&self, start: u64, len: u64) {
        self.mem_view().record_growdown_mapping(start, len);
    }

    #[cfg(test)]
    #[inline]
    pub(in crate::dispatch::mem) fn record_secretmem_map(&self, start: u64, len: u64) {
        self.mem_view().record_secretmem_map(start, len);
    }

    #[cfg(test)]
    #[inline]
    pub(in crate::dispatch::mem) fn remove_secretmem_map(&self, start: u64, len: u64) {
        self.mem_view().remove_secretmem_map(start, len);
    }

    #[cfg(test)]
    #[inline]
    pub(in crate::dispatch::mem) fn track_resident_fault_range(
        &self,
        address: u64,
        length: u64,
        prot: LinuxProtFlags,
    ) {
        self.mem_view()
            .track_resident_fault_range(address, length, prot);
    }

    #[cfg(test)]
    #[inline]
    pub(in crate::dispatch::mem) fn snapshot_private_mmap_file(
        &self,
        fd: Fd,
        offset: u64,
        length: usize,
    ) -> Result<PrivateMmapSnapshot, LinuxErrno> {
        self.mem_view()
            .snapshot_private_mmap_file(fd, offset, length)
    }

    #[cfg(test)]
    #[inline]
    pub(in crate::dispatch::mem) fn commit_mmap_locked_range(
        &self,
        memory: &mut impl CurrentMmMemory,
        range: Option<crate::vfs::GuestMemoryRange>,
    ) -> Result<(), LinuxErrno> {
        self.mem_view().commit_mmap_locked_range(memory, range)
    }

    #[cfg(test)]
    #[inline]
    pub(in crate::dispatch::mem) fn commit_eager_locked_range(
        &self,
        range: Option<crate::vfs::GuestMemoryRange>,
    ) {
        self.mem_view().commit_eager_locked_range(range);
    }

    #[cfg(test)]
    #[inline]
    pub(in crate::dispatch::mem) fn lock_current_mappings(
        &self,
        memory: &mut impl CurrentMmMemory,
        onfault: bool,
    ) -> Result<(), LinuxErrno> {
        self.mem_view().lock_current_mappings(memory, onfault)
    }
}

pub(super) fn range_within(address: u64, length: u64, base: u64, size: u64) -> bool {
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
    use crate::elf::LINUX_PIE_DEFAULT_BASE as IMAGE;
    use crate::memory::{
        LINUX_KERNEL_REGION_BASE as KERNEL, LINUX_NULL_GUARD_END as GUARD_END,
        LINUX_SHARED_FILE_BASE as SHARED,
    };
    range_within(address, length, GUARD_END, KERNEL - GUARD_END)
        || range_within(address, length, layout.heap_base, layout.heap_size)
        || range_within(address, length, IMAGE, SHARED - IMAGE)
        || range_within(
            address,
            length,
            SHARED,
            crate::memory::LINUX_SHARED_FILE_SIZE,
        )
}

pub(super) fn mmap_address_uses_alias(address: u64, length: u64, layout: MemoryLayout) -> bool {
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

/// HVPatch cannot create a new identity stage-2 mapping at a low arbitrary VA
/// after vCPU creation. A `MAP_FIXED` request outside the boot backing must use
/// the same global-frame alias path as high VAs. An already-backed range stays
/// identity, as does the semantic mmap arena: sparse HVPatch deliberately leaves
/// that arena physically absent until protection commits pages on demand, so a
/// raw-backing miss there is not a low fixed hole.
pub(super) fn mmap_request_uses_alias(
    fixed: bool,
    address_uses_alias: bool,
    has_identity_backing: bool,
    semantic_identity_range: bool,
) -> bool {
    address_uses_alias || (fixed && !has_identity_backing && !semantic_identity_range)
}

#[cfg(test)]
#[path = "mem/tests.rs"]
mod tests;
