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
    282 => userfaultfd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivateRepointRecovery {
    RecoveredCleanly,
    FailStopRetainingOwners,
}

/// Why a guest `mmap` was refused — and whether the guest can work that out
/// from its own errno.
///
/// A `MAP_FAILED` carrick cannot explain is a diagnostic hole in its own right.
/// glibc's `dlopen` renders any failed segment mapping as the single line
/// "failed to map segment from shared object", so when carrick refuses one of
/// its own mappings and says nothing, the only evidence left is that string.
/// Ten CPython suites died on exactly that, silently, for as long as CPython
/// had been running on this lane. Every refusal in [`mmap`](SyscallDispatcher)
/// now reports itself through [`MmapRequest::refused`].
///
/// [`SyscallDispatcher::mmap`]: SyscallDispatcher
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MmapRefusal {
    /// Linux itself rejects this request, so the errno handed back IS the
    /// explanation. Logged at `debug`: LTP provokes these by the hundred on
    /// purpose, and promoting them would bury the refusals that matter.
    Spec(&'static str),
    /// Carrick exhausted one of its own arenas, or an internal publication
    /// step failed. Nothing in the guest's arguments predicts it and the
    /// errno names no resource, so it is logged at `warn` — visible under
    /// carrick's default filter — and always names what ran out.
    Internal(&'static str),
}

/// The guest's `mmap` arguments exactly as they arrived, captured before any
/// normalization so a refusal reports what the guest asked for rather than
/// what carrick rewrote it to.
#[derive(Clone, Copy, Debug)]
struct MmapRequest {
    addr: u64,
    length: u64,
    prot: u64,
    flags: u64,
    fd: i32,
    offset: u64,
}

impl MmapRequest {
    /// Record this refusal and build the outcome that carries it to the guest.
    ///
    /// Every `mmap` error return goes through here; there is deliberately no
    /// bare `DispatchOutcome::errno` left in the handler, so a future branch
    /// cannot reintroduce a silent `MAP_FAILED`.
    fn refused(self, refusal: MmapRefusal, errno: LinuxErrno) -> DispatchOutcome {
        self.refused_by(refusal, errno, format_args!("-"))
    }

    /// Same, carrying the failing operation's own error text.
    ///
    /// Use this wherever a fallible host/stage-1 operation produced the
    /// refusal: "protection publication failed" without the backend's reason,
    /// and without the address carrick actually chose, is half a diagnosis —
    /// the guest only ever asked for `addr=0`.
    fn refused_by(
        self,
        refusal: MmapRefusal,
        errno: LinuxErrno,
        cause: std::fmt::Arguments<'_>,
    ) -> DispatchOutcome {
        let Self {
            addr,
            length,
            prot,
            flags,
            fd,
            offset,
        } = self;
        match refusal {
            MmapRefusal::Spec(reason) => tracing::debug!(
                target: "carrick::mmap",
                reason,
                errno = errno.get(),
                addr = format_args!("{addr:#x}"),
                length = format_args!("{length:#x}"),
                prot = format_args!("{prot:#x}"),
                flags = format_args!("{flags:#x}"),
                fd,
                offset = format_args!("{offset:#x}"),
                cause,
                "mmap refused: invalid request",
            ),
            MmapRefusal::Internal(reason) => tracing::warn!(
                target: "carrick::mmap",
                reason,
                errno = errno.get(),
                addr = format_args!("{addr:#x}"),
                length = format_args!("{length:#x}"),
                prot = format_args!("{prot:#x}"),
                flags = format_args!("{flags:#x}"),
                fd,
                offset = format_args!("{offset:#x}"),
                cause,
                "mmap refused: carrick internal limit",
            ),
        }
        DispatchOutcome::errno(errno)
    }
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
    resident_fault_ranges: Vec<ResidentFaultRange>,
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
    shared_file_alias_maps: Vec<(
        crate::vfs::GuestMemoryRange,
        Arc<crate::kernel::FileDescription>,
    )>,
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
            resident_fault_ranges: Vec::new(),
            growdown_ranges: Vec::new(),
            read_only_shared_file_maps: Vec::new(),
            write_sealed_shared_maps: Vec::new(),
            writable_memfd_maps: Vec::new(),
            shared_file_alias_maps: Vec::new(),
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
}

#[derive(Clone, Copy)]
struct ResidentFaultRange {
    range: crate::vfs::GuestMemoryRange,
    prot: LinuxProtFlags,
}

/// Debug: log any `mmap_next` LOWERING that crosses `CARRICK_FORK_DEBUG_VA`.
/// The bump allocator's invariant is "everything at/above `mmap_next` is
/// unallocated"; a lowering that crosses a LIVE mapping breaks it and the next
/// bump grant then hands out (and scrubs) memory the guest still owns — the
/// forkserver zeroed-granule corruption. `new` may come from the free-region
/// merge loop, so call this AFTER the final value is computed.
fn debug_mmap_next_lowering(old: u64, new: u64) {
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
fn lower_mmap_next(mmap_next: &mut u64, free_regions: &mut Vec<(u64, u64)>, new_next: u64) {
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
fn free_regions_remove_range(regions: &mut Vec<(u64, u64)>, addr: u64, len: u64) {
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
fn free_regions_insert(regions: &mut Vec<(u64, u64)>, addr: u64, len: u64) {
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
    Ok(range.len())
}

fn validate_mlock_range(
    memory: &mut impl GuestMemory,
    range: crate::vfs::GuestMemoryRange,
    populate: bool,
    page_size: u64,
    committed_vma_covers_range: bool,
) -> Result<(), LinuxErrno> {
    let len = range_len_usize(range)?;
    if memory
        .protections()
        .is_some_and(|protections| protections.range_unmapped(range.start().raw(), len))
    {
        return Err(LINUX_ENOMEM);
    }
    if committed_vma_covers_range || memory.has_complete_mapping_metadata() {
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
fn locked_ranges_insert(
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
    ranges.iter().map(|range| range.len() as u64).sum()
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

fn guest_vma_covers_locked(mem: &MemState, start: u64, len: u64) -> bool {
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
fn boot_region_is_carrick_kernel_hole(map: &ProcMapsEntry) -> bool {
    let base = crate::memory::LINUX_KERNEL_REGION_BASE;
    let end = base.saturating_add(crate::memory::LINUX_KERNEL_REGION_SIZE);
    map.start >= base && map.end <= end && map.start < map.end
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

/// Exact Linux-visible mapping metadata used by the live core publisher.
/// Hidden reservation apertures and carrick's own EL1-only kernel hole are
/// implementation backing, not VMAs; the heap is clamped to `brk`, and dynamic
/// mappings supply the committed pieces of the hidden mmap arena.
pub(super) fn project_core_maps(mem: &MemState) -> Vec<ProcMapsEntry> {
    let mut maps: Vec<ProcMapsEntry> = mem
        .address_space_regions
        .iter()
        .flatten()
        .filter(|map| !boot_region_is_carrick_kernel_hole(map))
        .filter(|map| {
            !boot_region_is_hidden_reservation(map, mem.layout)
                || boot_region_is_hidden_heap_backing(map, mem.layout)
        })
        .filter_map(|map| {
            let mut map = map.clone();
            if boot_region_is_hidden_heap_backing(&map, mem.layout) {
                map.end = mem.brk_current;
            }
            (map.start < map.end).then_some(map)
        })
        .collect();
    // MAP_FIXED and equivalent committed dynamic mappings replace any
    // Linux-visible boot VMA they overlap. Hidden reservations themselves stay
    // alive as implementation backing, so trim the projected/clamped view
    // rather than mutating that backing authority. The resulting PT_LOADs are
    // a partition with one permission/backing identity per guest byte.
    for dynamic in &mem.dynamic_maps {
        trim_dynamic_maps_for_range(
            &mut maps,
            dynamic.start,
            dynamic.end.saturating_sub(dynamic.start),
        );
    }
    maps.extend(mem.dynamic_maps.iter().cloned());
    maps.sort_by_key(|map| (map.start, map.end));
    maps
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
    file_page_offset: Option<u64>,
}

fn proc_maps_entry_mremap_metadata(
    map: &ProcMapsEntry,
    file_page_offset: Option<u64>,
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
    pub(super) file_page_offset: Option<u64>,
    pub(super) locked: Option<crate::vfs::GuestMemoryRange>,
    pub(super) resident: bool,
    pub(super) bus_fault: Option<(u64, u64)>,
    pub(super) write_sealed_shared: bool,
    pub(super) read_only_shared_file: bool,
    /// The mapping is backed by a `memfd_secret(2)` fd: its pages are
    /// hidden from `/proc/<pid>/mem` (memfdsecret probe `procmem_hidden`).
    pub(super) secretmem: bool,
    pub(super) writable_memfd: Option<Arc<crate::kernel::FileDescription>>,
    /// The open-file description behind a live `MAP_SHARED` file alias, kept so
    /// `mremap` can still find the file after the guest closes its own fd.
    pub(super) shared_file_alias: Option<Arc<crate::kernel::FileDescription>>,
}

fn prot_to_proc_perms(prot: LinuxProtFlags) -> (bool, bool, bool) {
    (
        prot.contains(LinuxProtFlags::READ),
        prot.contains(LinuxProtFlags::WRITE),
        prot.contains(LinuxProtFlags::EXEC),
    )
}

fn trim_writable_memfd_maps_for_range(
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
    // Ledger audit: CARRICK_FORK_DEBUG_VA=<hex> logs any metadata removal
    // covering that VA, with the caller — the hook that named the path
    // deleting a LIVE mapping's ledger entry (the forkserver zeroed-granule
    // corruption: the free list then honestly resold the range).
    if let Some(debug_va) = std::env::var("CARRICK_FORK_DEBUG_VA")
        .ok()
        .and_then(|raw| u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok())
        && start <= debug_va
        && debug_va < start.saturating_add(len)
    {
        eprintln!(
            "[LEDGERDBG tid={:?}] remove_mapping_metadata {start:#x}+{len:#x}\n{}",
            std::thread::current().id(),
            std::backtrace::Backtrace::force_capture(),
        );
    }
    trim_dynamic_maps_for_range(&mut mem.dynamic_maps, start, len);
    trim_core_file_mappings_for_range(&mut mem.core_file_mappings, start, len);
    trim_live_boot_regions_for_range(mem, start, len);
    trim_growdown_ranges_for_range(mem, start, len);
    trim_ranges_for_range(&mut mem.bus_fault_ranges, start, len);
    trim_writable_memfd_maps_for_range(&mut mem.writable_memfd_maps, start, len);
    trim_writable_memfd_maps_for_range(&mut mem.shared_file_alias_maps, start, len);
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
    locked_ranges_remove(&mut mem.secretmem_maps, remove);
    locked_ranges_remove(&mut mem.read_only_shared_file_maps, remove);
    locked_ranges_remove(&mut mem.host_alias_backed_ranges, remove);
    locked_ranges_remove(&mut mem.alias_vma_ranges, remove);
}

fn trim_core_file_mappings_for_range(
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

fn shared_file_bus_offset(file_len: u64, offset: u64, length: u64, page_size: u64) -> Option<u64> {
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
/// carrick already prefers an `O_RDWR` host fd even for a guest `O_RDONLY`
/// open (`fs_backend::fast_open_for_guest`, `open_raw_fd_capstd`,
/// `dispatch::fs`'s trusted-dirfd lane) precisely for this reason. Files
/// served from the IMMUTABLE shared layer cache are the case that preference
/// cannot cover, and deliberately so: that store is content-addressed and
/// shared across containers and runs, so handing a guest an RWX stage-2 view
/// of it would let one guest corrupt every other run's cache and would defeat
/// the overlay's copy-up. Such a mapping falls back to the snapshot path
/// instead — observationally equivalent for a read-only mapping of a layer
/// that cannot change under it.
///
/// Only Darwin/HVF carries this constraint; other hosts keep the live alias.
#[cfg(target_os = "macos")]
fn host_fd_can_back_shared_alias(fd: i32) -> bool {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDWR
}

#[cfg(not(target_os = "macos"))]
fn host_fd_can_back_shared_alias(_fd: i32) -> bool {
    true
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
        if commit.read_only_shared_file {
            locked_ranges_insert(&mut mem.read_only_shared_file_maps, replacement);
        }
        if commit.secretmem {
            locked_ranges_insert(&mut mem.secretmem_maps, replacement);
        }
        if let Some(description) = commit.writable_memfd {
            mem.writable_memfd_maps.push((replacement, description));
        }
        if let Some(description) = commit.shared_file_alias {
            mem.shared_file_alias_maps.push((replacement, description));
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
            locked_ranges_insert(&mut self.mem.lock().write_sealed_shared_maps, range);
        }
    }

    fn record_read_only_shared_file_map(&self, start: u64, len: u64) {
        if let Some(range) =
            crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start.saturating_add(len)))
        {
            locked_ranges_insert(&mut self.mem.lock().read_only_shared_file_maps, range);
        }
    }

    /// The open-file description behind the live `MAP_SHARED` alias covering
    /// `[start, start+len)`, if that whole range is one recorded alias. Callers
    /// use it to re-derive a fact about the FILE (notably its length) after the
    /// guest has closed its own descriptor.
    fn shared_file_alias_description(
        &self,
        start: u64,
        len: u64,
    ) -> Option<Arc<crate::kernel::FileDescription>> {
        let end = start.checked_add(len)?;
        self.mem
            .lock()
            .shared_file_alias_maps
            .iter()
            .find(|(range, _)| range.start().raw() <= start && range.end().raw() >= end)
            .map(|(_, description)| Arc::clone(description))
    }

    fn range_is_read_only_shared_file(&self, start: u64, len: u64) -> bool {
        self.mem
            .lock()
            .read_only_shared_file_maps
            .iter()
            .any(|r| ranges_overlap(start, len, r.start().raw(), r.end().raw()))
    }

    fn range_is_write_sealed_shared(&self, start: u64, len: u64) -> bool {
        self.mem
            .lock()
            .write_sealed_shared_maps
            .iter()
            .any(|r| ranges_overlap(start, len, r.start().raw(), r.end().raw()))
    }

    fn record_secretmem_map(&self, start: u64, len: u64) {
        if let Some(range) =
            crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start.saturating_add(len)))
        {
            self.mem.lock().secretmem_maps.push(range);
        }
    }

    /// True iff `[start, start+len)` touches a live secretmem mapping — used
    /// by the `/proc/<pid>/mem` read path to fail with EIO (the kernel cannot
    /// GUP secret pages; memfdsecret probe `procmem_hidden`).
    pub(in crate::dispatch) fn range_touches_secretmem(&self, start: u64, len: u64) -> bool {
        self.mem
            .lock()
            .secretmem_maps
            .iter()
            .any(|r| ranges_overlap(start, len, r.start().raw(), r.end().raw()))
    }

    #[cfg(test)]
    fn remove_secretmem_map(&self, start: u64, len: u64) {
        if let Some(range) =
            crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(start.saturating_add(len)))
        {
            locked_ranges_remove(&mut self.mem.lock().secretmem_maps, range);
        }
    }

    fn record_writable_memfd_map(
        &self,
        start: u64,
        len: u64,
        description: Arc<crate::kernel::FileDescription>,
    ) {
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
        self.captured_mm()
            .replace_io_uring_mappings(start, len, None);
    }

    /// True iff a live MAP_SHARED, PROT_WRITE mapping backed by `description`
    /// exists — used to reject `F_ADD_SEALS` F_SEAL_WRITE with EBUSY.
    pub(in crate::dispatch) fn memfd_has_writable_shared_map(
        &self,
        description: &Arc<crate::kernel::FileDescription>,
    ) -> bool {
        self.mem
            .lock()
            .writable_memfd_maps
            .iter()
            .any(|(_, desc)| std::sync::Arc::ptr_eq(desc, description))
    }

    #[cfg(test)]
    fn record_dynamic_mapping(
        &self,
        start: u64,
        len: u64,
        prot: LinuxProtFlags,
        sharing: ProcMapSharing,
        path: String,
    ) {
        self.record_dynamic_mapping_with_file_offset(start, len, prot, sharing, path, None);
    }

    fn record_dynamic_mapping_with_file_offset(
        &self,
        start: u64,
        len: u64,
        prot: LinuxProtFlags,
        sharing: ProcMapSharing,
        path: String,
        file_page_offset: Option<u64>,
    ) {
        let Some(end) = start.checked_add(len) else {
            return;
        };
        let (read, write, execute) = prot_to_proc_perms(prot);
        let mut mem = self.mem.lock();
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

        if !dynamic_mapping_overlaps_sorted(&mem.dynamic_maps, start, len) {
            let idx = mem.dynamic_maps.partition_point(|map| map.start < start);
            mem.dynamic_maps.insert(idx, entry);
            return;
        }

        trim_dynamic_maps_for_range(&mut mem.dynamic_maps, start, len);
        let idx = mem.dynamic_maps.partition_point(|map| map.start < start);
        mem.dynamic_maps.insert(idx, entry);
    }

    /// Whether one committed host-alias extent fully backs this guest-VA range.
    /// VMA presence alone is insufficient: lazy anonymous `PROT_NONE` reserves
    /// the address now and installs physical backing only on first commit.
    fn range_has_host_alias_backing(&self, start: u64, len: u64) -> bool {
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        self.mem
            .lock()
            .host_alias_backed_ranges
            .iter()
            .any(|range| range.start().raw() <= start && range.end().raw() >= end)
    }

    fn range_is_alias_vma(&self, start: u64, len: u64) -> bool {
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        self.mem
            .lock()
            .alias_vma_ranges
            .iter()
            .any(|range| range.start().raw() <= start && range.end().raw() >= end)
    }

    fn record_alias_vma(&self, start: u64, len: u64) {
        let Some(end) = start.checked_add(len) else {
            std::process::abort();
        };
        let Some(range) = crate::vfs::GuestMemoryRange::new(GuestVa(start), GuestVa(end)) else {
            std::process::abort();
        };
        locked_ranges_insert(&mut self.mem.lock().alias_vma_ranges, range);
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
            let file_page_offset = mem
                .core_file_mappings
                .iter()
                .find(|mapping| mapping.start <= start && mapping.end >= end)
                .map(|mapping| {
                    mapping.file_page_offset
                        + (start - mapping.start) / crate::core_dump::GUEST_PAGE as u64
                });
            return Ok(proc_maps_entry_mremap_metadata(first, file_page_offset));
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
            });
        Ok(proc_maps_entry_mremap_metadata(region, file_page_offset))
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
    #[cfg(test)]
    pub(crate) fn reset_memory_state_on_execve(&self) {
        let _vma_dispatch = self.begin_vma_dispatch();
        self.mem.lock().reset_for_execve();
    }

    pub(in crate::dispatch) fn next_mmap_address(
        &self,
        requested: u64,
        length: u64,
        prot: u64,
        flags: u64,
    ) -> Option<(u64, bool)> {
        let granted = self.next_mmap_address_inner(requested, length, prot, flags);
        // Grant audit: CARRICK_MMAP_GRANT_DEBUG=1 logs any non-FIXED grant that
        // overlaps a LIVE dynamic mapping, with the allocator state and caller.
        // A double-grant here scrubbed a live CPython interned-dict granule to
        // zeros (the forkserver SIGSEGV cluster); this names the guilty path in
        // one run instead of a day of ledger archaeology.
        if flags & LINUX_MAP_FIXED == 0
            && std::env::var_os("CARRICK_MMAP_GRANT_DEBUG").is_some()
            && let Some((address, _)) = granted
        {
            let mem = self.mem.lock();
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
    ) -> Option<(u64, bool)> {
        // Only a WRITABLE hand-out can ever leave a non-zero byte behind, so
        // only a writable hand-out raises the watermark. A `PROT_NONE` reserve
        // — Go's allocator makes them by the gigabyte — cannot be stored into,
        // and raising the watermark past it forced every later allocation below
        // it to be scrubbed for nothing. `mprotect` is the other mark point;
        // see `mmap_writable_high`.
        let writable = prot & LINUX_PROT_WRITE != 0;
        let page_size = self.linux_page_size();
        let layout = self.mem.lock().layout;
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
                let mut mem = self.mem.lock();
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
                let mut mem = self.mem.lock();
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
        let stale = address < mem.mmap_writable_high;
        if writable {
            mem.mmap_writable_high = mem.mmap_writable_high.max(end);
        }
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
            if LinuxOpenFlags::from_bits_truncate(desc.status_flags()).contains(LinuxOpenFlags::PATH)
                || desc.is_write_only()
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
                        && let Err(error) = cx.memory.zero_backing(clear_start, clear_len)
                    {
                        if std::env::var_os("CARRICK_FORK_DEBUG_VA").is_some() {
                            eprintln!(
                                "[BRKDBG] shrink {current:#x} -> {requested:#x} REFUSED: \
                                 zero_backing({clear_start:#x}, {clear_len:#x}) = {error:?}"
                            );
                        }
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
            // The exact request, for `MmapRequest::refused`. Captured before
            // MAP_FIXED_NOREPLACE normalization and page rounding so a refusal
            // reports the guest's own arguments, not carrick's rewrite of them.
            let request = MmapRequest {
                addr: requested_raw,
                length,
                prot,
                flags,
                fd: fd.0,
                offset,
            };
            let requested = GuestPtr(requested.0 & 0x0000_FFFF_FFFF_FFFF);

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
                return Ok(request.refused(
                    MmapRefusal::Spec("file mapping on a descriptor that is not open"),
                    LINUX_EBADF,
                ));
            }
            // `/proc/*/maps` and NT_FILE identify the backing pathname, not
            // merely that a mapping was file-backed. Preserve the guest path
            // before the mapping branches borrow or duplicate the descriptor.
            // Host-backed overlay files carry that guest-relative authority in
            // RootFsMetadata; never expose the host scratch path from F_GETPATH.
            let proc_map_path = if map_flags.contains(LinuxMmapFlags::ANONYMOUS) {
                String::new()
            } else {
                this.open_file(fd.0)
                    .map(|open_file| {
                        let open = open_file.description.read();
                        match &*open {
                            OpenDescription::File { path, .. }
                            | OpenDescription::SyntheticFile { path, .. } => path.clone(),
                            OpenDescription::HostFile { metadata, .. } => {
                                metadata.path.to_string_lossy().into_owned()
                            }
                            _ => String::new(),
                        }
                    })
                    .unwrap_or_default()
            };

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
                        return Ok(request.refused(
                            MmapRefusal::Spec("MAP_SHARED_VALIDATE with an unknown flag bit"),
                            crate::linux_abi::LINUX_EOPNOTSUPP,
                        ));
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
                return Ok(request.refused(
                    MmapRefusal::Spec("zero length, unsupported prot/flag bits, no map type, or a misaligned offset/fixed address"),
                    LINUX_EINVAL,
                ));
            }
            let Some(map_sharing) = map_sharing else {
                return Ok(request.refused(
                    MmapRefusal::Spec("neither MAP_SHARED nor MAP_PRIVATE"),
                    LINUX_EINVAL,
                ));
            };
            let length = match align_up_u64(length, page_size) {
                Some(length) => length,
                None => {
                    return Ok(request.refused(
                        MmapRefusal::Spec("length rounds up past the end of the address space"),
                        LINUX_ENOMEM,
                    ));
                }
            };
            let length_usize =
                usize::try_from(length).map_err(|_| DispatchError::LengthTooLarge(length))?;

            // io_uring mappings are ordinary MAP_SHARED host aliases. The file
            // description owns the persistent bytes; this mm receives only an
            // attachment after the runtime has installed the alias successfully.
            if let Some(description) = this.io_uring_description(fd.0) {
                let Some(backing) = description
                    .concrete_backing::<crate::dispatch::ioring::IoUringBacking>()
                else {
                    std::process::abort();
                };
                let Some((region, region_layout)) = backing.region(offset) else {
                    return Ok(request.refused(
                        MmapRefusal::Spec("offset does not name an io_uring region"),
                        LINUX_EINVAL,
                    ));
                };
                if map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                    || map_sharing != MmapSharing::Shared
                    || length < region_layout.required_len
                    || length > region_layout.mapped_extent
                {
                    return Ok(request.refused(
                        MmapRefusal::Spec("io_uring mapping must be MAP_SHARED and cover exactly its region"),
                        LINUX_EINVAL,
                    ));
                }
                if fixed_noreplace && this.dynamic_mapping_overlaps(requested.0, length) {
                    return Ok(request.refused(
                        MmapRefusal::Spec("MAP_FIXED_NOREPLACE over a live io_uring mapping"),
                        linux_errno::EEXIST,
                    ));
                }
                let Some(owned_fd) = backing.dup_data_fd() else {
                    return Ok(request.refused(
                        MmapRefusal::Internal("io_uring backing descriptor could not be duplicated"),
                        LINUX_ENOMEM,
                    ));
                };
                let fixed_va = map_flags.contains(LinuxMmapFlags::FIXED);
                let Some(ipa) = alloc_alias_ipa_for_publication(length, fixed_va) else {
                    return Ok(request.refused(
                        MmapRefusal::Internal("alias IPA arena exhausted (io_uring mapping)"),
                        LINUX_ENOMEM,
                    ));
                };
                let address = if fixed_va {
                    requested.0
                } else {
                    crate::memory::LINUX_HIGH_VA_THRESHOLD
                        + (ipa - crate::memory::LINUX_ALIAS_IPA_BASE)
                };
                let Some(end) = address.checked_add(length) else {
                    return Ok(request.refused(
                        MmapRefusal::Spec("io_uring mapping end overflows the address space"),
                        LINUX_ENOMEM,
                    ));
                };
                let mut host_prot = 0;
                if prot_flags.intersects(LinuxProtFlags::READ | LinuxProtFlags::EXEC) {
                    host_prot |= libc::PROT_READ;
                }
                if prot_flags.contains(LinuxProtFlags::WRITE) {
                    host_prot |= libc::PROT_WRITE;
                }
                let mapping = crate::dispatch::ioring::IoUringMapping {
                    description,
                    region,
                    start: address,
                    end,
                    backing_offset: region_layout.backing_offset,
                };
                let mm = this.captured_mm();
                let transaction = host_alias_dispatch.publish(HostAliasCommit::io_uring_mmap(
                    HostAliasMmapCommit {
                        start: address,
                        len: length,
                        prot: prot_flags,
                        sharing: ProcMapSharing::Shared,
                        path: "anon_inode:[io_uring]".to_owned(),
                        file_page_offset: None,
                        locked: this.prepare_mmap_locked_range(map_flags, address, length)?,
                        resident: true,
                        bus_fault: None,
                        write_sealed_shared: false,
                        read_only_shared_file: false,
                        secretmem: false,
                        writable_memfd: None,
                        shared_file_alias: None,
                    },
                    mapping,
                    mm,
                ));
                return Ok(DispatchOutcome::MapHostAlias {
                    success_retval: address as i64,
                    transaction,
                    va: GuestVa(address),
                    ipa: Gpa(ipa),
                    len: length,
                    payload: Vec::new(),
                    file: Some((
                        HostAliasOwnedFd(owned_fd),
                        region_layout.backing_offset as libc::off_t,
                        host_prot,
                    )),
                    shared: true,
                    prot,
                    prot_none: prot_flags.is_empty(),
                });
            }

            // An O_PATH descriptor is not open for I/O — mmap on it returns
            // EBADF (LTP open13 maps an O_PATH fd and expects failure).
            if !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && let Some(open_file) = this.open_file(fd.0)
                && open_file.description.read().status_flags() & crate::linux_abi::LINUX_O_PATH != 0
            {
                return Ok(request.refused(
                    MmapRefusal::Spec("mmap of an O_PATH descriptor"),
                    LINUX_EBADF,
                ));
            }

            if !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && let Some(open_file) = this.open_file(fd.0)
                && open_file.description.read().is_write_only()
            {
                return Ok(request.refused(
                    MmapRefusal::Spec("mmap of a write-only descriptor"),
                    LINUX_EACCES,
                ));
            }

            // A memfd sealed F_SEAL_WRITE (or F_SEAL_FUTURE_WRITE) cannot back a
            // shared, writable mapping — Linux returns EPERM (memfd_create01
            // check_mmap_fail). A private (MAP_PRIVATE) writable mapping is fine:
            // its stores never reach the sealed backing.
            if !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && map_sharing == MmapSharing::Shared
                && prot_flags.contains(LinuxProtFlags::WRITE)
                && let Some(open_file) = this.open_file(fd.0)
                && let Some(seals) = open_file
                    .description
                    .read()
                    .seals()
                    .and_then(carrick_abi::LinuxMemfdSeals::from_bits)
                && seals.intersects(
                    carrick_abi::LinuxMemfdSeals::WRITE
                        | carrick_abi::LinuxMemfdSeals::FUTURE_WRITE,
                )
            {
                return Ok(request.refused(
                    MmapRefusal::Spec("shared writable mapping of a write-sealed memfd"),
                    LINUX_EPERM,
                ));
            }

            // memfd_secret mappings must be MAP_SHARED: secretmem rejects a
            // MAP_PRIVATE mmap with EINVAL (memfdsecret probe
            // `mmap_private_errno=22`). Classified here, ahead of every
            // private/file-backed lowering decision, so no path can materialize
            // a private view of secret memory.
            let secretmem_backed = !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && this
                    .open_file(fd.0)
                    .is_some_and(|open_file| open_file.description.read().is_secretmem());
            if secretmem_backed && map_sharing == MmapSharing::Private {
                return Ok(request.refused(
                    MmapRefusal::Spec("MAP_PRIVATE mapping of a memfd_secret fd"),
                    LINUX_EINVAL,
                ));
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
                return Ok(request.refused(
                    MmapRefusal::Internal("PROT_WRITE|PROT_EXEC is unsupported on this backend"),
                    LINUX_EOPNOTSUPP,
                ));
            }

            if fixed_noreplace && this.dynamic_mapping_overlaps(requested.0, length) {
                return Ok(request.refused(
                    MmapRefusal::Spec("MAP_FIXED_NOREPLACE over a live mapping"),
                    linux_errno::EEXIST,
                ));
            }

            if map_flags.contains(LinuxMmapFlags::FIXED)
                && requested_raw >> 48 == 0xffff
                && this.proc.lock().reported_arch()
                    == crate::vfs::GuestReportedArch::Aarch64
            {
                return Ok(request.refused(
                    MmapRefusal::Spec("MAP_FIXED at a high-half address on an aarch64 guest"),
                    LINUX_ENOMEM,
                ));
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
                        Err(errno) => return Ok(request.refused(
                            MmapRefusal::Internal("private-overlay snapshot of the mapped file failed"),
                            errno,
                        )),
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
                        return Ok(request.refused(
                            MmapRefusal::Internal("shared-aperture range is not carvable for a private overlay"),
                            LINUX_ENOMEM,
                        ));
                    }
                    let Some(displaced) = mem.shared.guest_range_fragments(requested.0, length)
                    else {
                        return Ok(request.refused(
                            MmapRefusal::Internal("shared-aperture range exposes no carvable fragments"),
                            LINUX_ENOMEM,
                        ));
                    };
                    let overlay = mem.overlay.alloc_sourced(
                        length,
                        crate::shared_aperture::BackingObject::PrivateAnon,
                        Some(requested.0),
                    );
                    (overlay, displaced)
                };
                let Some(overlay_va) = overlay_va else {
                    return Ok(request.refused(
                        MmapRefusal::Internal("private overlay aperture exhausted"),
                        LINUX_ENOMEM,
                    ));
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
                            return Ok(request.refused(
                                MmapRefusal::Internal("stage-1 repoint into the private overlay failed"),
                                LINUX_ENOMEM,
                            ));
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
                    path: proc_map_path.clone(),
                    file_page_offset: (!proc_map_path.is_empty()).then_some(
                        offset / crate::core_dump::GUEST_PAGE as u64,
                    ),
                    locked: locked_range,
                    resident: !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                        || map_flags.contains(LinuxMmapFlags::POPULATE),
                    bus_fault,
                    write_sealed_shared: false,
                    read_only_shared_file: false,
                    secretmem: false,
                    writable_memfd: None,
                    shared_file_alias: None,
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
                let mut alias_description: Option<Arc<crate::kernel::FileDescription>> = None;
                let dup_fd = {
                    let Some(open_file) = this.open_file(fd.0) else {
                        return Ok(request.refused(
                            MmapRefusal::Internal("file description vanished mid-dispatch (shared file alias)"),
                            LINUX_EBADF,
                        ));
                    };
                    let open = open_file.description.read();
                    match &*open {
                        OpenDescription::HostFile { host_fd, .. } => {
                            // Two named preconditions decide the live alias, so
                            // neither is discovered as an opaque hypervisor
                            // error deep inside the VMM backend: the mapping
                            // must not run past EOF (that tail is BUS_ADRERR,
                            // served by the snapshot path below), and the host
                            // fd must be able to carry a write max-protection.
                            if host_fd_file_len(host_fd.raw())
                                .and_then(|len| {
                                    shared_file_bus_offset(len, offset, length, page_size)
                                })
                                .is_some()
                                || !host_fd_can_back_shared_alias(host_fd.raw())
                            {
                                None
                            } else {
                                let d = unsafe { libc::dup(host_fd.raw()) };
                                if d < 0 {
                                    None
                                } else {
                                    // Retain the description: the dup above is
                                    // the runtime's and is closed right after
                                    // mapping, so this is the only way a later
                                    // `mremap` can ask where the file ends.
                                    alias_description =
                                        Some(std::sync::Arc::clone(&open_file.description));
                                    Some(d)
                                }
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
                            return Ok(request.refused(
                                MmapRefusal::Spec("MAP_LOCKED refused by RLIMIT_MEMLOCK (shared file alias)"),
                                errno,
                            ));
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
                        return Ok(request.refused(
                            MmapRefusal::Internal("alias IPA arena exhausted (shared file mapping)"),
                            LINUX_ENOMEM,
                        ));
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
                                return Ok(request.refused(
                                    MmapRefusal::Internal("alias VA range overflows the address space"),
                                    LINUX_ENOMEM,
                                ));
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
                            path: proc_map_path.clone(),
                            file_page_offset: (!proc_map_path.is_empty()).then_some(
                                offset / crate::core_dump::GUEST_PAGE as u64,
                            ),
                            locked: locked_range,
                            resident: true,
                            bus_fault: None,
                            write_sealed_shared: false,
                            read_only_shared_file: false,
                            secretmem: false,
                            writable_memfd: None,
                            shared_file_alias: alias_description,
                        },
                    ));
                    return Ok(DispatchOutcome::MapHostAlias {
                        success_retval: va as i64,
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
                // Linux treats a usable non-fixed address as an advisory hint.
                // Keep high canonical hints on the alias path so a later
                // PROT_NONE -> writable commit can install the exact hinted VA
                // while preserving the original MAP_SHARED provenance.
                && (requested.0 == 0
                    || !mmap_address_uses_alias(requested.0, length, this.mem.lock().layout))
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
                        && let Err(error) = memory.zero_anonymous_reuse(
                            addr,
                            map_len_usize,
                            carrick_guest_mem::MappingSharing::Shared,
                        )
                    {
                        this.mem.lock().shared.free(addr);
                        return Ok(request.refused_by(
                            MmapRefusal::Internal("anonymous-reuse scrub failed (shared aperture)"),
                            LINUX_ENOMEM,
                            format_args!("at {addr:#x}+{map_len:#x}: {error}"),
                        ));
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
                    if let Err(error) = protection
                        && memory.supports_concurrent_exec_protection()
                    {
                        this.rollback_shared_anon_mapping(
                            memory,
                            addr,
                            length,
                            map_len_usize,
                        )?;
                        return Ok(request.refused_by(
                            MmapRefusal::Internal(
                                "protection publication failed (shared anonymous mapping)",
                            ),
                            LINUX_ENOMEM,
                            format_args!("at {addr:#x}+{map_len:#x}: {error}"),
                        ));
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
                        return Ok(request.refused(
                            MmapRefusal::Spec("MAP_LOCKED population refused by RLIMIT_MEMLOCK (shared anonymous)"),
                            errno,
                        ));
                    }
                    this.record_dynamic_mapping_with_file_offset(
                        addr,
                        length,
                        prot_flags,
                        ProcMapSharing::Shared,
                        String::new(),
                        None,
                    );
                    this.mark_vma_dispatch(&mut host_alias_dispatch);
                    return Ok(DispatchOutcome::Returned { value: addr as i64 });
                }
                return Ok(request.refused(
                    MmapRefusal::Internal("shared aperture exhausted"),
                    LINUX_ENOMEM,
                ));
            }

            let (address, reused) = match this.next_mmap_address(requested.0, length, prot, flags) {
                Some(pair) => pair,
                None => {
                    // A length that could not fit an EMPTY arena is a property
                    // of the request, and Linux answers ENOMEM for it too —
                    // CPython's `test_io` asks for 0x8000_0000_0000_1000 on
                    // purpose. Only a request that would have fitted, and did
                    // not, is carrick's own arena running out.
                    let arena = this.mem.lock().layout.mmap_size;
                    let refusal = if length > arena {
                        MmapRefusal::Spec("length exceeds the entire mmap address-space arena")
                    } else {
                        MmapRefusal::Internal("no free address-space region: mmap arena exhausted")
                    };
                    return Ok(request.refused(refusal, LINUX_ENOMEM));
                }
            };

            let fixed_anonymous = map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && map_flags.contains(LinuxMmapFlags::FIXED);
            let layout = this.mem.lock().layout;
            let in_arena = range_within(address, length, layout.mmap_base, layout.mmap_size);
            let address_uses_alias = mmap_request_uses_alias(
                map_flags.contains(LinuxMmapFlags::FIXED),
                mmap_address_uses_alias(address, length, layout),
                memory.read_bytes_raw(address, 1).is_ok(),
                in_arena,
            );
            if (reused || fixed_anonymous) && !address_uses_alias {
                // Scrub the reused region's PHYSICAL backing. MUST bypass the
                // guest-visible permission: a region just reclaimed from munmap
                // is stage-1-invalidated (no-access) and a PROT_NONE mmap is not
                // writable, so the permission-checked write_bytes silently faults
                // and leaves the prior mapping's bytes — which then surface after
                // the guest mprotects the region to RW (CPython multiprocessing
                // Pool built on a freed 16 MiB b'X' buffer → 0x58.. ptr → SIGSEGV).
                // MAP_FIXED|ANON also overwrites a caller-selected range, so it
                // cannot rely on the bump allocator's pristine-tail invariant.
                if let Err(error) = memory.zero_anonymous_reuse(
                    address,
                    length_usize,
                    map_sharing.guest_mapping_sharing(),
                ) {
                    return Ok(request.refused_by(
                        MmapRefusal::Internal("anonymous-reuse scrub failed (mmap arena)"),
                        LINUX_ENOMEM,
                        format_args!("at {address:#x}+{length:#x}: {error}"),
                    ));
                }
            }

            // Restore guest-visible stage-1 validity for arena allocations: a
            // page reclaimed from a prior munmap (which invalidated it) must be
            // valid+RW again, and a PROT_NONE mmap must actually fault. No-op
            // (no TLBI) when the page is already at the target protection.
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
                if let Err(error) = memory.protect_range(address, length_usize, 0)
                    && (in_arena || memory.supports_concurrent_exec_protection())
                    && !address_uses_alias
                {
                    mark_range_unmapped(memory, address, length_usize);
                    return Ok(request.refused_by(
                        MmapRefusal::Internal("PROT_NONE reservation failed in the mmap arena"),
                        LINUX_ENOMEM,
                        format_args!(
                            "at {address:#x}+{length:#x} in_arena={in_arena}: {error}"
                        ),
                    ));
                }
                this.commit_mmap_locked_range(memory, locked_range)?;
                this.record_dynamic_mapping_with_file_offset(
                    address,
                    length,
                    prot_flags,
                    map_sharing.proc_map_sharing(),
                    String::new(),
                    None,
                );
                if address_uses_alias {
                    this.record_alias_vma(address, length);
                }
                if map_flags.contains(LinuxMmapFlags::GROWSDOWN) {
                    this.record_growdown_mapping(address, length);
                }
                this.mark_vma_dispatch(&mut host_alias_dispatch);
                return Ok(DispatchOutcome::Returned {
                    value: address as i64,
                });
            }

            if map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && !address_uses_alias
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
                if let Err(error) = memory.protect_range(address, length_usize, prot)
                    && (in_arena || memory.supports_concurrent_exec_protection())
                {
                    mark_range_unmapped(memory, address, length_usize);
                    return Ok(request.refused_by(
                        MmapRefusal::Internal("protection publication failed (anonymous mapping)"),
                        LINUX_ENOMEM,
                        format_args!(
                            "at {address:#x}+{length:#x} in_arena={in_arena}: {error}"
                        ),
                    ));
                }
                this.commit_mmap_locked_range(memory, locked_range)?;
                this.record_dynamic_mapping_with_file_offset(
                    address,
                    length,
                    prot_flags,
                    map_sharing.proc_map_sharing(),
                    String::new(),
                    None,
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
            // mprotect(2) EACCES ceiling: a MAP_SHARED mapping of a file opened
            // read-only can never be made PROT_WRITE. Decided here, at map time,
            // because the backing fd can be closed long before the mprotect.
            // MAP_PRIVATE is deliberately excluded — Linux keeps VM_MAYWRITE for
            // a private map of a read-only file, since its stores are COW and
            // never reach the file.
            let mut mmap_read_only_shared_file = false;
            if map_sharing == MmapSharing::Shared
                && !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                && let Some(open_file) = this.open_file(fd.0)
            {
                mmap_read_only_shared_file = open_file.description.read().is_read_only();
            }
            // A live MAP_SHARED, PROT_WRITE mapping of an (unsealed) memfd — its
            // backing description is recorded so F_ADD_SEALS F_SEAL_WRITE can
            // EBUSY while it is mapped.
            let mut writable_memfd_desc: Option<Arc<crate::kernel::FileDescription>> = None;
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
                && !address_uses_alias
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
                    return Ok(request.refused(
                        MmapRefusal::Internal("file description vanished mid-dispatch (content load)"),
                        LINUX_EBADF,
                    ));
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
                        if let Some(bus_offset) = shared_file_bus_offset(
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
                            && matches!(
                                base.seals().and_then(carrick_abi::LinuxMemfdSeals::from_bits),
                                Some(s) if s.intersects(
                                    carrick_abi::LinuxMemfdSeals::WRITE
                                        | carrick_abi::LinuxMemfdSeals::FUTURE_WRITE,
                                )
                            )
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
                        if let Some(bus_offset) = shared_file_bus_offset(
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
                        if let Some(file_len) = host_fd_file_len(host_fd.raw())
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
                            return Ok(request.refused(
                                MmapRefusal::Spec("mmap of a pipe or FIFO"),
                                linux_errno::ENODEV,
                            ));
                        }
                        // chardev zero-fill: keep `bytes` zeroed (no read).
                    }
                    _ => {
                        return Ok(request.refused(
                            MmapRefusal::Spec("mmap of a descriptor with no mappable backing"),
                            LINUX_EBADF,
                        ));
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
            if address_uses_alias {
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
                    return Ok(request.refused(
                        MmapRefusal::Internal("PROT_WRITE|PROT_EXEC is unsupported on this backend (alias VA)"),
                        LINUX_EOPNOTSUPP,
                    ));
                }
                // Reject a genuinely non-canonical hint (bits 55:48 of the
                // ORIGINAL address neither all-0 nor all-1). With TCR_EL1.TBI on,
                // canonicality is decided by bits 55:48, not 63:48. A canonical
                // high-half address is translatable via TTBR1 and is aliased
                // below; MAP_FIXED_NOREPLACE is a hint the caller retries without.
                let bits_55_48 = (requested_raw >> 48) & 0xff;
                if bits_55_48 != 0x00 && bits_55_48 != 0xff {
                    if map_flags.contains(LinuxMmapFlags::FIXED_NOREPLACE) {
                        return Ok(request.refused(
                            MmapRefusal::Spec("MAP_FIXED_NOREPLACE at a non-canonical address"),
                            linux_errno::EEXIST,
                        ));
                    }
                    return Ok(request.refused(
                        MmapRefusal::Spec("non-canonical address hint"),
                        LINUX_ENOMEM,
                    ));
                }
                let locked_range = this.prepare_mmap_locked_range(map_flags, address, length)?;
                // The guest VA is final. Mature VMM consumes a fresh monotonic
                // alias IPA; HVPatch supplies a sentinel that its reusable
                // GlobalFrameStage2Lease replaces before stage-2 publication.
                // Stage-1 still covers exactly the guest page-aligned length.
                let Some(ipa) = alloc_alias_ipa_for_publication(length, true) else {
                    return Ok(request.refused(
                        MmapRefusal::Internal("alias IPA arena exhausted (guest-chosen VA)"),
                        LINUX_ENOMEM,
                    ));
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
                        path: proc_map_path.clone(),
                        file_page_offset: (!proc_map_path.is_empty()).then_some(
                            offset / crate::core_dump::GUEST_PAGE as u64,
                        ),
                        locked: locked_range,
                        resident: !map_flags.contains(LinuxMmapFlags::ANONYMOUS)
                            || map_flags.contains(LinuxMmapFlags::POPULATE),
                        bus_fault,
                        write_sealed_shared: mmap_write_sealed_shared,
                        read_only_shared_file: mmap_read_only_shared_file,
                        secretmem: secretmem_backed,
                        writable_memfd: writable_memfd_desc,
                        shared_file_alias: None,
                    },
                ));
                return Ok(DispatchOutcome::MapHostAlias {
                    success_retval: address as i64,
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
            // succeeded). A known map-time EOF still publishes BUS_ADRERR for
            // every whole page beyond it: snapshot materialization changes the
            // backing primitive, not Linux's private-file fault contract.
            let mut bytes = bytes;
            let mut lowered_file_backed = false;
            if lowering_candidate {
                let Some(open_file) = this.open_file(fd.0) else {
                    // The description vanished mid-dispatch; the eager path's
                    // own EBADF position for the same state.
                    return Ok(request.refused(
                        MmapRefusal::Internal("file description vanished mid-dispatch (file-backed lowering)"),
                        LINUX_EBADF,
                    ));
                };
                let open = open_file.description.read();
                let OpenDescription::HostFile { host_fd, .. } = &*open else {
                    return Ok(request.refused(
                        MmapRefusal::Internal("file description changed type mid-dispatch (file-backed lowering)"),
                        LINUX_EBADF,
                    ));
                };
                if let Some(file_len) = host_fd_file_len(host_fd.raw()) {
                    bus_fault_offset =
                        shared_file_bus_offset(file_len, offset, length, page_size);
                    if bus_fault_offset.is_some() {
                        bus_fault_debug = Some(format!(
                            "host path={:?} file_len={file_len} desc=HostFile host_fd={}",
                            carrick_portable::fd_abs_path(host_fd.raw()),
                            host_fd.raw()
                        ));
                    }
                    // SAFETY: the description read guard (`open`) keeps the
                    // owning `HostFdRef` alive across the borrow.
                    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(host_fd.raw()) };
                    if matches!(
                        memory.map_private_file_backed(address, length_usize, borrowed, offset),
                        Ok(true)
                    ) {
                        lowered_file_backed = true;
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
                if let Err(error) = memory.protect_range(address, length_usize, rw)
                    && (in_arena || memory.supports_concurrent_exec_protection())
                {
                    mark_range_unmapped(memory, address, length_usize);
                    return Ok(request.refused_by(
                        MmapRefusal::Internal(
                            "temporary writable protection failed while loading file content",
                        ),
                        LINUX_ENOMEM,
                        format_args!(
                            "at {address:#x}+{length:#x} in_arena={in_arena}: {error}"
                        ),
                    ));
                }
                if let Err(error) = memory.write_bytes_unchecked(address, &bytes) {
                    mark_range_unmapped(memory, address, length_usize);
                    return Ok(request.refused_by(
                        MmapRefusal::Internal("file content could not be copied into the mapping"),
                        LINUX_ENOMEM,
                        format_args!("at {address:#x}+{length:#x}: {error}"),
                    ));
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
            if let Err(error) = memory.protect_range(address, length_usize, prot)
                && (in_arena || memory.supports_concurrent_exec_protection())
            {
                mark_range_unmapped(memory, address, length_usize);
                return Ok(request.refused_by(
                    MmapRefusal::Internal("requested protection could not be published"),
                    LINUX_ENOMEM,
                    format_args!("at {address:#x}+{length:#x} in_arena={in_arena}: {error}"),
                ));
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
                if let Err(error) = memory.protect_range(bus_start, bus_len_usize, 0)
                    && memory.supports_concurrent_exec_protection()
                {
                    return Ok(request.refused_by(
                        MmapRefusal::Internal("beyond-EOF SIGBUS protection could not be published"),
                        LINUX_ENOMEM,
                        format_args!("at {bus_start:#x}+{bus_len:#x}: {error}"),
                    ));
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
            if mmap_read_only_shared_file {
                this.record_read_only_shared_file_map(address, length);
            }
            if secretmem_backed {
                this.record_secretmem_map(address, length);
            }
            if let Some(description) = writable_memfd_desc {
                this.record_writable_memfd_map(address, length, description);
            }
            let file_page_offset = (!proc_map_path.is_empty())
                .then_some(offset / crate::core_dump::GUEST_PAGE as u64);
            this.record_dynamic_mapping_with_file_offset(
                address,
                length,
                prot_flags,
                map_sharing.proc_map_sharing(),
                proc_map_path,
                file_page_offset,
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
            if this.range_is_alias_vma(address.0, length)
                || mmap_address_uses_alias(address.0, length, layout)
            {
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
                let mem = &mut *mem;
                lower_mmap_next(&mut mem.mmap_next, &mut mem.free_regions, address.0);
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
            let committed_vma_covers_range = guest_vma_covers_locked(
                &this.mem.lock(),
                range.start().raw(),
                range.len() as u64,
            );
            validate_mlock_range(
                &mut *cx.memory,
                range,
                true,
                page_size,
                committed_vma_covers_range,
            )?;
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
            let committed_vma_covers_range = guest_vma_covers_locked(
                &this.mem.lock(),
                range.start().raw(),
                range.len() as u64,
            );
            validate_mlock_range(
                &mut *cx.memory,
                range,
                false,
                page_size,
                committed_vma_covers_range,
            )?;
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
            let committed_vma_covers_range = guest_vma_covers_locked(
                &this.mem.lock(),
                range.start().raw(),
                range.len() as u64,
            );
            validate_mlock_range(
                &mut *cx.memory,
                range,
                !flags.contains(LinuxMlock2Flags::ONFAULT),
                page_size,
                committed_vma_covers_range,
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

        fn mremap(this, cx, old_address: GuestPtr, old_size: u64, new_size_req: u64, flags: u64, new_address: GuestPtr) {
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
            // Two more well-formedness checks real Linux performs on a
            // MREMAP_FIXED request, both EINVAL, both BEFORE it would attempt
            // the move — so they must precede carrick's "not yet implemented"
            // EOPNOTSUPP stand-in below for the same reason the checks above
            // do. Without them a malformed fixed request reported carrick's
            // refusal instead of the errno Linux gives (mremap05 cases 2/3:
            // "new_addr has to be page aligned" and "old/new area must not
            // overlap", both answered EOPNOTSUPP).
            if move_fixed {
                if !new_address.0.is_multiple_of(page_size) {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                if ranges_overlap(
                    old_address.0,
                    old_size,
                    new_address.0,
                    new_address.0.saturating_add(new_size),
                ) {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
            }
            if this
                .captured_mm()
                .io_uring_mapping_overlaps(old_address.0, old_size)
            {
                // Moving or resizing a ring attachment without a matching host
                // alias transaction would stale the mm join. Fail before any
                // page-table, allocator, or VMA mutation.
                return Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP));
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
            // A shared mapping cannot be grown by copying it somewhere bigger:
            // the whole point of MAP_SHARED is that every mapper of the object
            // observes the same bytes, and a copy would silently unshare it.
            // Linux instead keeps the backing object exactly where it is, so
            // carrick grows the aperture allocation in place. Only a
            // shared-aperture allocation that this request covers exactly can
            // do that; anything else keeps the pre-existing ENOMEM.
            //
            // Measured against real Linux 6.12 (docker gcc:latest, arm64,
            // 2026-08-17): `MAP_SHARED|MAP_ANONYMOUS` 1 page grown to 2 with
            // MREMAP_MAYMOVE succeeds, and WITHOUT MREMAP_MAYMOVE it reports
            // ENOMEM — which is why the grow below is gated on the flag.
            //
            // Restricted to SharedAnon: a SharedFile allocation's grown tail
            // must show the FILE's bytes at the matching offset (measured: a
            // 1-page MAP_SHARED window onto a 4-page file grows and the new
            // page reads and writes the file), and the aperture's granules
            // would come up zeroed instead. That shape still reports ENOMEM
            // here — an honest gap, not a silent wrong answer.
            let shared_grow_in_place = new_size > old_size
                && flags & LINUX_MREMAP_MAYMOVE != 0
                && matches!(
                    shared_aperture_alloc,
                    Some(ref alloc)
                        if alloc.guest_addr == old_address.0
                            && alloc.live_len == old_size
                            && alloc.backing == crate::shared_aperture::BackingObject::SharedAnon
                );
            // File length and mapping offset behind a live MAP_SHARED alias, if
            // this range is one. Shared by the grow plan and the diagnostic
            // below so both report the same numbers.
            let alias_file_extent = (|| {
                let description = this.shared_file_alias_description(old_address.0, old_size)?;
                let file_offset = source_metadata
                    .file_page_offset
                    .unwrap_or(0)
                    .checked_mul(crate::core_dump::GUEST_PAGE as u64)?;
                let open = description.read();
                let file_len = match &*open {
                    OpenDescription::HostFile { host_fd, .. } => host_fd_file_len(host_fd.raw()),
                    _ => None,
                }?;
                Some((file_len, file_offset))
            })();

            // The other shared shape carrick can grow: a live MAP_SHARED file
            // alias whose growth lands entirely PAST the file's end. Linux keeps
            // the object and its live page-cache sharing exactly as they are and
            // simply extends the VMA; every page from EOF on has no backing and
            // faults SIGBUS. Carrick can reproduce that without touching the
            // alias at all — extend the VMA and record the tail as a bus-fault
            // range — which is strictly better than re-establishing the mapping,
            // because the existing alias IS the shared page cache.
            //
            // `ltp-mremap01` is exactly this: a 0x3e8000 MAP_SHARED window onto
            // a 0x3e8000 file, grown to 0x7d0000 with MREMAP_MAYMOVE.
            let shared_file_alias_grow = (new_size > old_size
                && flags & LINUX_MREMAP_MAYMOVE != 0
                && source_metadata.sharing == ProcMapSharing::Shared
                && shared_aperture_alloc.is_none())
            .then(|| {
                let (file_len, file_offset) = alias_file_extent?;
                // Where SIGBUS starts inside the GROWN mapping. The growth is
                // reproducible in place only when every added byte is already
                // past that point; otherwise part of the new tail must show real
                // file bytes, which extending the VMA alone would not deliver.
                let bus_start = shared_file_bus_offset(file_len, file_offset, new_size, page_size)?;
                (bus_start <= old_size).then_some(bus_start)
            })
            .flatten();
            // Offset within the mapping at which SIGBUS starts, when the
            // mapping ALREADY ends past its file's EOF. Read off the bus records
            // the original `mmap` published rather than re-derived from a
            // descriptor: an arena snapshot keeps no fd, and the guest may well
            // have closed its own by now.
            //
            // Read the records directly — `mmap_fault_is_sigbus` opens its own
            // host-alias dispatch guard and `mremap` already holds one, so
            // calling it here DEADLOCKED the guest (the run wedged in mremap and
            // timed out with no output past the mmap).
            let shared_arena_grow_past_eof = (new_size > old_size
                && flags & LINUX_MREMAP_MAYMOVE != 0
                && source_metadata.sharing == ProcMapSharing::Shared
                && source_in_arena
                && old_size != 0)
            .then(|| {
                let last = old_address.0.saturating_add(old_size) - 1;
                this.mem
                    .lock()
                    .bus_fault_ranges
                    .iter()
                    .find(|&&(start, len)| {
                        start
                            .checked_add(len)
                            .is_some_and(|end| last >= start && last < end)
                    })
                    .map(|&(start, _)| start.saturating_sub(old_address.0))
            })
            .flatten();
            // Grow of a live alias whose larger extent is still wholly inside
            // the file: re-established over the same fd below.
            let alias_regrow_within_eof = new_size > old_size
                && flags & LINUX_MREMAP_MAYMOVE != 0
                && source_metadata.sharing == ProcMapSharing::Shared
                && shared_aperture_alloc.is_none()
                && alias_file_extent.is_some_and(|(file_len, file_offset)| {
                    shared_file_bus_offset(file_len, file_offset, new_size, page_size).is_none()
                });
            if new_size > old_size && std::env::var_os("CARRICK_FAULT_DEBUG").is_some() {
                // Which grow plan (if any) matched, and the facts each one keys
                // on. A refused grow is otherwise indistinguishable from a dozen
                // other ENOMEM sources in this handler, and the shapes that need
                // one differ by backing rather than by anything the guest can
                // see. Same hatch as the mmap BUS line above.
                eprintln!(
                    "[FAULTDBG] mremap GROW addr={:#x} old={old_size:#x} new={new_size:#x} \
                     flags={flags:#x} sharing={:?} in_arena={source_in_arena} \
                     aperture={:?} anon_plan={shared_grow_in_place} \
                     arena_past_eof={shared_arena_grow_past_eof:?} \
                     alias_plan={shared_file_alias_grow:?} \
                     alias_file_extent={alias_file_extent:?} \
                     alias_regrow={alias_regrow_within_eof} path={:?}",
                    old_address.0,
                    source_metadata.sharing,
                    shared_aperture_alloc
                        .as_ref()
                        .map(|a| (a.guest_addr, a.live_len, a.len)),
                    source_metadata.path,
                );
            }
            if source_metadata.sharing == ProcMapSharing::Shared
                && new_size > old_size
                && !shared_grow_in_place
                && shared_arena_grow_past_eof.is_none()
                && shared_file_alias_grow.is_none()
                && !alias_regrow_within_eof
            {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
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
                // Grow a live MAP_SHARED file alias whose LARGER extent is still
                // entirely inside the file. Linux backs the added pages from the
                // file, so carrick has to as well — and the only way to keep
                // sharing exact is to re-establish the alias over the same fd at
                // the new length. Re-mmapping the same descriptor aliases the
                // same page cache, so unlike a byte copy this preserves
                // coherence with every other mapper.
                //
                // `ltp-mremap01` is this shape. It builds a SPARSE file with
                // lseek+write (which is why a naive read of its `write` calls
                // suggests a 1-byte file), maps 0x3e8000 of it, EXTENDS the file
                // to 0x7d0001, and then grows the mapping to 0x7d0000 — all
                // inside EOF.
                if let Some((file_len, file_offset)) = alias_file_extent
                    && new_size > old_size
                    && flags & LINUX_MREMAP_MAYMOVE != 0
                    && source_metadata.sharing == ProcMapSharing::Shared
                    && shared_aperture_alloc.is_none()
                    && shared_file_bus_offset(file_len, file_offset, new_size, page_size).is_none()
                {
                    let Some(description) =
                        this.shared_file_alias_description(old_address.0, old_size)
                    else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    };
                    let dup_fd = {
                        let open = description.read();
                        match &*open {
                            OpenDescription::HostFile { host_fd, .. } => {
                                if host_fd_can_back_shared_alias(host_fd.raw()) {
                                    let d = unsafe { libc::dup(host_fd.raw()) };
                                    (d >= 0).then_some(d)
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        }
                    };
                    let Some(dup_fd) = dup_fd else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    };
                    let Some(ipa) = crate::memory::alloc_alias_ipa(new_size) else {
                        unsafe { libc::close(dup_fd) };
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    };
                    let va = crate::memory::LINUX_HIGH_VA_THRESHOLD
                        + (ipa - crate::memory::LINUX_ALIAS_IPA_BASE);
                    // Same translation as the mmap path: PROT_EXEC is dropped
                    // (the guest executes through its own stage-1/stage-2, and
                    // macOS refuses MAP_SHARED|PROT_EXEC of an ordinary file).
                    let pf = source_metadata.prot;
                    let mut host_prot = 0;
                    if pf.intersects(LinuxProtFlags::READ | LinuxProtFlags::EXEC) {
                        host_prot |= libc::PROT_READ;
                    }
                    if pf.contains(LinuxProtFlags::WRITE) {
                        host_prot |= libc::PROT_WRITE;
                    }
                    // Linux unmaps the source. Reclaim the old alias BEFORE
                    // publishing the new one; the destination IPA is freshly
                    // allocated and never reused, so it cannot collide with the
                    // source, and the ordering keeps `mmap_next`-independent
                    // alias VA bookkeeping single-valued. If the runtime's host
                    // mmap then fails the transaction aborts and the guest has
                    // lost the source mapping, where Linux would have kept it —
                    // a divergence confined to that failure path.
                    if let Ok(old_len) = usize::try_from(old_size)
                        && old_len > 0
                    {
                        let _ = memory.unmap_alias_range(old_address.0, old_len);
                        mark_range_unmapped(memory, old_address.0, old_len);
                        this.remove_mapping_metadata(old_address.0, old_size);
                    }
                    let transaction =
                        host_alias_dispatch.publish(HostAliasCommit::mmap(HostAliasMmapCommit {
                            start: va,
                            len: new_size,
                            prot: pf,
                            sharing: ProcMapSharing::Shared,
                            path: source_metadata.path.clone(),
                            file_page_offset: source_metadata.file_page_offset,
                            locked: None,
                            resident: true,
                            bus_fault: None,
                            write_sealed_shared: false,
                            read_only_shared_file: false,
                            secretmem: false,
                            writable_memfd: None,
                            shared_file_alias: Some(Arc::clone(&description)),
                        }));
                    return Ok(DispatchOutcome::MapHostAlias {
                        success_retval: va as i64,
                        transaction,
                        va: GuestVa(va),
                        ipa: Gpa(ipa),
                        len: new_size,
                        payload: Vec::new(),
                        file: Some((
                            // SAFETY: `dup_fd` is the successful, uniquely-owned
                            // descriptor created just above and is transferred
                            // into the non-cloneable outcome exactly once.
                            unsafe { HostAliasOwnedFd::from_raw_fd(dup_fd) },
                            file_offset as libc::off_t,
                            host_prot,
                        )),
                        shared: true,
                        prot: pf.bits(),
                        prot_none: pf.is_empty(),
                    });
                }
                if let Some(bus_start) = shared_file_alias_grow {
                    // Leave the live alias exactly as it is — it IS the shared
                    // page cache, and re-establishing it would be both slower
                    // and a chance to lose coherence — and give the mapping the
                    // unbacked tail Linux gives it. The VA above the alias has
                    // to be free, because nothing is moving.
                    let Some(new_end) = old_address.0.checked_add(new_size) else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    };
                    let old_end = old_address.0.saturating_add(old_size);
                    let tail_occupied = this
                        .mem
                        .lock()
                        .dynamic_maps
                        .iter()
                        .any(|map| map.start < new_end && map.end > old_end);
                    if tail_occupied {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    }
                    // Every page from `bus_start` on is past EOF and must fault
                    // SIGBUS, not read as zeroes. Nothing is mapped there, so
                    // the access takes a translation fault and this record is
                    // what turns the resulting SIGSEGV into the SIGBUS Linux
                    // delivers.
                    this.record_mmap_bus_fault_range(
                        old_address.0.saturating_add(bus_start),
                        new_size.saturating_sub(bus_start),
                    );
                    this.record_dynamic_mapping_with_file_offset(
                        old_address.0,
                        new_size,
                        source_metadata.prot,
                        source_metadata.sharing,
                        source_metadata.path.clone(),
                        source_metadata.file_page_offset,
                    );
                    this.mark_vma_dispatch(&mut host_alias_dispatch);
                    return Ok(DispatchOutcome::Returned {
                        value: old_address.0 as i64,
                    });
                }
                if shared_grow_in_place {
                    // Extend the existing aperture allocation rather than
                    // allocating a bigger one and copying: the backing object
                    // must keep its identity so every other mapper (a forked
                    // child, a second mmap of the same object) still sees this
                    // mapping's stores.
                    let claimed = this.mem.lock().shared.grow(old_address.0, new_size);
                    let Some((claim_start, claim_len)) = claimed else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    };
                    if claim_len != 0 {
                        // The claimed granules may still hold a previous
                        // owner's bytes, and Linux hands out zeroed pages for
                        // anonymous shared memory. Scrub before anything can
                        // read them. The aperture rounds to the host granule,
                        // so this range is already host-page aligned.
                        let Ok(claim_len_usize) = usize::try_from(claim_len) else {
                            return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                        };
                        if memory
                            .zero_anonymous_reuse(
                                claim_start,
                                claim_len_usize,
                                carrick_guest_mem::MappingSharing::Shared,
                            )
                            .is_err()
                        {
                            return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                        }
                        if this
                            .mem
                            .lock()
                            .shared
                            .range_needs_identity_restore(claim_start, claim_len)
                        {
                            if memory
                                .restore_shared_identity(claim_start, claim_len_usize)
                                .is_err()
                            {
                                // The page-table edit may already be live even
                                // when its TLB flush reports failure; recycling
                                // this VA would publish unowned translation.
                                std::process::abort();
                            }
                            if this
                                .mem
                                .lock()
                                .shared
                                .mark_identity_restored(claim_start, claim_len)
                                .is_none()
                            {
                                std::process::abort();
                            }
                        }
                        // The aperture is boot-mapped RW, so the grown tail
                        // needs this mapping's protection published over it
                        // exactly as a fresh MAP_SHARED|MAP_ANON does —
                        // otherwise a store to a read-only mapping's new pages
                        // silently succeeds.
                        let prot_none = source_metadata.prot.is_empty();
                        memory.set_mapping_protection_and_sharing(
                            claim_start,
                            claim_len_usize,
                            prot_none,
                            !prot_none && !source_metadata.prot.contains(LinuxProtFlags::WRITE),
                            carrick_guest_mem::MappingSharing::Shared,
                        );
                        if memory
                            .protect_range(claim_start, claim_len_usize, source_metadata.prot.bits())
                            .is_err()
                        {
                            return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                        }
                    }
                    this.record_dynamic_mapping_with_file_offset(
                        old_address.0,
                        new_size,
                        source_metadata.prot,
                        source_metadata.sharing,
                        source_metadata.path.clone(),
                        source_metadata.file_page_offset,
                    );
                    this.mark_vma_dispatch(&mut host_alias_dispatch);
                    return Ok(DispatchOutcome::Returned {
                        value: old_address.0 as i64,
                    });
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
                            && (this.range_is_alias_vma(old_address.0, old_size)
                                || mmap_address_uses_alias(old_address.0, old_size, layout))
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
                    this.record_dynamic_mapping_with_file_offset(
                        old_address.0,
                        new_size,
                        source_metadata.prot,
                        source_metadata.sharing,
                        source_metadata.path.clone(),
                        source_metadata.file_page_offset,
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
                        let mem = &mut *mem;
                        lower_mmap_next(&mut mem.mmap_next, &mut mem.free_regions, tail_start);
                    } else {
                        free_regions_insert(&mut mem.free_regions, tail_start, tail_len);
                    }
                }
                this.record_dynamic_mapping_with_file_offset(
                    old_address.0,
                    new_size,
                    source_metadata.prot,
                    source_metadata.sharing,
                    source_metadata.path.clone(),
                    source_metadata.file_page_offset,
                );
                if new_size != old_size {
                    this.mark_vma_dispatch(&mut host_alias_dispatch);
                }
                return Ok(DispatchOutcome::Returned {
                    value: old_address.0 as i64,
                });
            }

            // A MAP_SHARED file mapping that already ends past its file's EOF,
            // living in the arena as an eager snapshot. `ltp-mremap01` is this
            // shape. The whole growth is past EOF too — nothing to materialize,
            // just VA to reserve and a tail that has to fault SIGBUS — so it is
            // grown in place rather than moved and copied.
            //
            // "Past EOF" is read off the bus records the original mmap
            // published rather than re-derived from a descriptor: an arena
            // snapshot keeps no fd, and the guest may well have closed its own
            // by now. If the mapping's LAST byte already faults SIGBUS then the
            // file ends at or before it, so every added byte is past EOF too.
            if let Some(bus_rel) = shared_arena_grow_past_eof {
                let Some(new_end) = old_address.0.checked_add(new_size) else {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                };
                let old_end = old_address.0.saturating_add(old_size);
                let can_extend_in_place = old_end == this.mem.lock().mmap_next
                    && range_within(old_address.0, new_size, layout.mmap_base, layout.mmap_size);
                if !can_extend_in_place {
                    // Something already owns the space directly above, so this
                    // has to MOVE — which is what Linux does here too. Moving a
                    // snapshot is a copy, but only of the bytes that exist: the
                    // region from `bus_rel` on is past EOF and is deliberately
                    // inaccessible, so reading it to copy it would EFAULT.
                    let Some((new_addr, reused)) = this.next_mmap_address(
                        0,
                        new_size,
                        LINUX_PROT_READ | LINUX_PROT_WRITE,
                        0,
                    ) else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    };
                    let (Ok(new_len), Ok(copy_len)) = (
                        usize::try_from(new_size),
                        usize::try_from(bus_rel.min(old_size)),
                    ) else {
                        this.rollback_fresh_arena_mapping(memory, new_addr, new_size)?;
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
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
                        && memory.write_bytes_unchecked(new_addr, &copied).is_err()
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
                    // Re-publish the past-EOF tail at the destination exactly as
                    // `mmap` publishes it: no access, then the bus record that
                    // turns the resulting fault into SIGBUS.
                    let bus_start_abs = new_addr.saturating_add(bus_rel);
                    let bus_len = new_size.saturating_sub(bus_rel);
                    if let Ok(bus_len_usize) = usize::try_from(bus_len)
                        && bus_len_usize != 0
                    {
                        memory.set_no_access(bus_start_abs, bus_len_usize, true);
                        let _ = memory.protect_range(bus_start_abs, bus_len_usize, 0);
                    }
                    this.record_mmap_bus_fault_range(bus_start_abs, bus_len);
                    this.record_dynamic_mapping_with_file_offset(
                        new_addr,
                        new_size,
                        source_metadata.prot,
                        source_metadata.sharing,
                        source_metadata.path.clone(),
                        source_metadata.file_page_offset,
                    );
                    // Linux unmaps the source. Reclaim it exactly like munmap so
                    // a later access faults and the VA is reusable.
                    if let Ok(old_len) = usize::try_from(old_size)
                        && old_len > 0
                        && memory.unmap_range(old_address.0, old_len).is_ok()
                    {
                        mark_range_unmapped(memory, old_address.0, old_len);
                        this.remove_mapping_metadata(old_address.0, old_size);
                        let mut mem = this.mem.lock();
                        if old_end == mem.mmap_next {
                            let mem = &mut *mem;
                            lower_mmap_next(
                                &mut mem.mmap_next,
                                &mut mem.free_regions,
                                old_address.0,
                            );
                        } else {
                            free_regions_insert(&mut mem.free_regions, old_address.0, old_size);
                        }
                    }
                    this.mark_vma_dispatch(&mut host_alias_dispatch);
                    return Ok(DispatchOutcome::Returned {
                        value: new_addr as i64,
                    });
                }
                let grow_len_u64 = new_size - old_size;
                // Deliberately NO page-table work: the tail is above the arena
                // bump pointer and so has no stage-1 mapping, which is exactly
                // the state an access has to find. Publishing a PROT_NONE
                // mapping over it instead HUNG the guest (the backend tries to
                // protect backing that was never established), and it would be
                // pointless anyway — reserving the VA and recording the bus
                // range is the whole job.
                {
                    let mut mem = this.mem.lock();
                    mem.mmap_next = new_end;
                }
                this.record_mmap_bus_fault_range(old_end, grow_len_u64);
                this.record_dynamic_mapping_with_file_offset(
                    old_address.0,
                    new_size,
                    source_metadata.prot,
                    source_metadata.sharing,
                    source_metadata.path.clone(),
                    source_metadata.file_page_offset,
                );
                this.mark_vma_dispatch(&mut host_alias_dispatch);
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
                        mem.mmap_writable_high = mem.mmap_writable_high.max(new_end);
                    }
                    this.record_dynamic_mapping_with_file_offset(
                        old_address.0,
                        new_size,
                        source_metadata.prot,
                        source_metadata.sharing,
                        source_metadata.path.clone(),
                        source_metadata.file_page_offset,
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
            this.record_dynamic_mapping_with_file_offset(
                new_addr,
                new_size,
                source_metadata.prot,
                source_metadata.sharing,
                source_metadata.path.clone(),
                source_metadata.file_page_offset,
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
                        let mem = &mut *mem;
                        lower_mmap_next(
                            &mut mem.mmap_next,
                            &mut mem.free_regions,
                            old_address.0,
                        );
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
            let layout = this.mem.lock().layout;
            let address_is_alias_vma = this.range_is_alias_vma(address.0, length)
                || mmap_address_uses_alias(address.0, length, layout);
            // Complete VMA metadata answers whether the Linux address range is
            // mapped; it does NOT answer whether a deliberately-lazy anonymous
            // high-VA reservation has acquired physical alias backing. The
            // dispatcher's committed-alias inventory is authoritative for that
            // second fact: a raw host-pointer read can succeed through a stale
            // post-unmap view even after this mm's stage-1/stage-2 translations
            // were retired. Only a successful host-alias transaction publishes
            // the range, and unmap/replacement trims it with the VMA metadata.
            let lazy_alias_reservation = (!metadata_says_unmapped
                && !prot_flags.is_empty()
                && address_is_alias_vma
                && !this.range_has_host_alias_backing(address.0, length))
            .then(|| this.mremap_mapping_metadata(cx.memory, address.0, length).ok())
            .flatten();
            // A committed kernel VMA can deliberately precede physical
            // backing: HVPatch's low sparse arena and the existing high-alias
            // reservation both materialize on the first accessible
            // protection. Raw backing is therefore only a hole oracle when
            // neither complete backend metadata nor committed VMA metadata
            // covers the request. Explicit post-munmap state still wins above.
            let committed_vma_covers_range =
                guest_vma_covers_locked(&this.mem.lock(), address.0, length);
            let incomplete_backend_says_unmapped = !committed_vma_covers_range
                && !cx.memory.has_complete_mapping_metadata()
                && cx.memory.read_bytes_raw(address.0, 1).is_err();
            if metadata_says_unmapped
                || lazy_alias_reservation.is_some()
                || incomplete_backend_says_unmapped
            {
                // LAZY ALIAS COMMIT. An anonymous PROT_NONE reservation in the
                // alias window is deliberately given no backing at `mmap` time
                // — it is address space, not memory, and eagerly aliasing every
                // reservation exhausts the 64 GiB alias IPA arena, which is
                // never reused because arm64 HVF cannot flush stage-2 TLB.
                // (Measured: eagerly aliasing them breaks `go build` with a
                // child stage-1 VA→IPA mismatch.)
                //
                // So the backing is installed HERE, when the guest actually
                // commits part of the reservation — which is what `mprotect`
                // means. Only the committed subrange costs IPA. This is V8's
                // `AllocateAlignedMemory` shape, and without it Node.js 22 dies
                // in startup-snapshot deserialization: carrick's backing probe
                // sees no backing, reads that as "no mapping", and answers
                // ENOMEM where Linux commits and returns 0.
                //
                // `metadata_says_unmapped` still wins: a range explicitly
                // munmapped is a real hole, and NULL and genuine holes keep
                // answering ENOMEM (LTP mprotect01).
                if !metadata_says_unmapped
                    && !prot_flags.is_empty()
                    && address_is_alias_vma
                    && let Some(ipa) = alloc_alias_ipa_for_publication(length, true)
                {
                    // The reservation's VMA is the source of truth. `mprotect`
                    // replaces only its committed subrange; it must not
                    // manufacture MAP_PRIVATE metadata for a MAP_SHARED
                    // anonymous reservation merely because the backing is being
                    // created late.
                    let Some(reservation) = lazy_alias_reservation.or_else(|| {
                        this.mremap_mapping_metadata(cx.memory, address.0, length)
                            .ok()
                    }) else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                    };
                    let shared = reservation.sharing == ProcMapSharing::Shared;
                    let transaction =
                        host_alias_dispatch.publish(HostAliasCommit::mmap(HostAliasMmapCommit {
                            start: address.0,
                            len: length,
                            prot: prot_flags,
                            sharing: reservation.sharing,
                            path: reservation.path,
                            file_page_offset: reservation.file_page_offset,
                            locked: None,
                            resident: false,
                            bus_fault: None,
                            write_sealed_shared: false,
                            read_only_shared_file: false,
                            secretmem: false,
                            writable_memfd: None,
                            shared_file_alias: None,
                        }));
                    return Ok(DispatchOutcome::MapHostAlias {
                        // mprotect answers 0, not the address.
                        success_retval: 0,
                        transaction,
                        va: GuestVa(address.0),
                        ipa: Gpa(ipa),
                        len: length,
                        payload: Vec::new(),
                        file: None,
                        shared,
                        prot,
                        prot_none: false,
                    });
                }
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            }
            // A shared mapping of a F_SEAL_WRITE memfd cannot be upgraded to
            // writable (memfd_create01 check_mfd_non_writeable).
            if prot & LINUX_PROT_WRITE != 0 && this.range_is_write_sealed_shared(address.0, length) {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            // A MAP_SHARED mapping of a read-only file cannot be upgraded to
            // writable: its stores would have to reach a file the process never
            // opened for writing (mprotect(2) EACCES; LTP mprotect01 case 3,
            // which carrick used to answer with success).
            if prot & LINUX_PROT_WRITE != 0
                && this.range_is_read_only_shared_file(address.0, length)
            {
                return Ok(DispatchOutcome::errno(LINUX_EACCES));
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
                    address_is_alias_vma,
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
                if let Err(error) = cx.memory.protect_range(address.0, len, prot) {
                    tracing::error!(
                        address = address.0,
                        length,
                        prot,
                        %error,
                        "mprotect failed to publish mmap-arena protection"
                    );
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
                // THE SECOND MARK POINT. `mmap` is the first: together they are
                // the only two ways an arena range becomes guest-writable, and
                // the watermark is only sound because BOTH raise it. A
                // `PROT_NONE` reserve that is later committed RW here must push
                // the watermark past itself, or a post-`munmap` bump could hand
                // those written pages back unscrubbed. See
                // `mmap_writable_high`.
                if prot_flags.contains(LinuxProtFlags::WRITE)
                    && let Some(end) = address.0.checked_add(length)
                {
                    let mut mem = this.mem.lock();
                    mem.mmap_writable_high = mem.mmap_writable_high.max(end);
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

        fn userfaultfd(this, cx, _flags: u64) {
            // Container POLICY, not kernel emulation. The differential oracle
            // (native arm64 Docker) denies userfaultfd(2) in its default
            // seccomp profile unless the caller holds CAP_SYS_PTRACE, and the
            // deny fires on the syscall NUMBER alone — before flag validation,
            // so UFFD_USER_MODE_ONLY and even invalid flag bits all yield
            // EPERM (uffdpolicy probe; LTP userfaultfd01/02/06 TCONF with
            // "userfaultfd() requires CAP_SYS_PTRACE ... EPERM"). Carrick's
            // guest runs with the same Docker-default capability set, which
            // lacks CAP_SYS_PTRACE → EPERM.
            //
            // WITH the capability the call would reach the kernel, and
            // carrick's kernel does not implement userfaultfd — exactly what
            // the synthetic /proc/config.gz declares ("# CONFIG_USERFAULTFD
            // is not set", the same answer the oracle's LinuxKit kernel
            // gives) — so that path is an honest ENOSYS, not a fake fd.
            let _ = &this;
            // Per-TASK capability check (`has_effective_capability`), never a
            // process-global one: the carrier hosts many Linux tasks, and a
            // post-setuid task holds nothing at all.
            if !super::creds::has_effective_capability(
                cx.kernel,
                crate::namespace::process::CAP_SYS_PTRACE,
            ) {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            Ok(DispatchOutcome::errno(LINUX_ENOSYS))
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
            || mem.host_alias_backed_ranges.iter().any(overlaps)
            || mem.alias_vma_ranges.iter().any(overlaps)
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
        if creds.euid.is_root() {
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
        let memlock_limit = if creds.euid.is_root() {
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
            let mem = &mut *mem;
            lower_mmap_next(&mut mem.mmap_next, &mut mem.free_regions, address);
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
        if !creds.euid.is_root() {
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

/// HVPatch cannot create a new identity stage-2 mapping at a low arbitrary VA
/// after vCPU creation. A `MAP_FIXED` request outside the boot backing must use
/// the same global-frame alias path as high VAs. An already-backed range stays
/// identity, as does the semantic mmap arena: sparse HVPatch deliberately leaves
/// that arena physically absent until protection commits pages on demand, so a
/// raw-backing miss there is not a low fixed hole.
fn mmap_request_uses_alias(
    fixed: bool,
    address_uses_alias: bool,
    has_identity_backing: bool,
    semantic_identity_range: bool,
) -> bool {
    address_uses_alias || (fixed && !has_identity_backing && !semantic_identity_range)
}

/// Select the legacy dispatcher IPA token for an alias publication.
///
/// HVPatch assigns the real, reusable global frame IPA in its backend after
/// the guest VA is already fixed. Consuming the old process-tree-global,
/// monotonic alias cursor in that case would leave a dead allocator as a
/// 32,768-publication lifetime limit. The legacy cursor is still needed when
/// the offset selects a fresh guest VA.
pub(super) fn alloc_alias_ipa_for_publication(
    length: u64,
    guest_va_already_selected: bool,
) -> Option<u64> {
    alloc_alias_ipa_for_publication_with(
        length,
        guest_va_already_selected,
        crate::memory::alloc_alias_ipa,
    )
}

fn alloc_alias_ipa_for_publication_with(
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

#[cfg(test)]
#[path = "mem/tests.rs"]
mod tests;
