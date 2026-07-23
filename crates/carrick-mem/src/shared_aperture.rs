//! Sub-allocator and backing-object model for the fixed, boot-mapped shared
//! aperture (`LINUX_SHARED_FILE_BASE`, `LINUX_SHARED_FILE_SIZE`).
//!
//! THEORY OF OPERATION
//!
//! The central invariant of carrick's threaded memory model is that the guest's
//! stage-2 mapping topology must be STABLE once vCPU threads exist: arm64 has no
//! host-driven stage-2 TLB flush (it is EL2-only on HVF, and unavailable to a
//! nested guest on KVM), so adding/removing a stage-2 mapping after sibling
//! vCPUs are running can leave a stale stage-2 translation on another core and
//! corrupt or hang the guest. The fix is to map ONE large region — the shared
//! aperture, a single host `MAP_ANON | MAP_SHARED | MAP_NORESERVE` window mapped
//! exactly once at boot, before any vCPU exists (see `linux_runtime_regions` in
//! `memory.rs`) — and satisfy every guest `MAP_SHARED` request by carving a
//! sub-range out of that already-mapped window. This file is that carver. NO
//! hypervisor call ever happens here; it is pure host-memory bookkeeping, so it
//! composes safely with sibling vCPUs running, and is shared verbatim by every
//! backend (HVF / KVM / bhyve) — the stage-2 REGISTRATION of the window is the
//! per-backend glue (`hv_vm_map` / a KVM slot / `vm_mmap_memseg`); this
//! sub-allocator is not.
//!
//! [`SharedAperture`] is a bump-plus-free-list sub-allocator over the window,
//! granule-aligned (`0x4000`). [`BackingObject`] records WHAT backs each live
//! slot — the skeleton of the durable-memory spec's backing-object model:
//! `SharedAnon` (lives in the aperture, shared across `fork`, never copied),
//! `SharedFile` (file bytes copied in on map, dirty bytes written back to a
//! dup'd host fd on `msync`/`munmap`), `PrivateReservation` (guest-VA ownership
//! retained in the shared allocator while a private overlay occupies that VA),
//! and `PrivateAnon` (the corresponding per-process overlay storage, whose
//! stores stay private across fork).
//! The `source` tag on an overlay slot ([`SharedAperture::find_by_source`]) lets
//! a re-`MAP_FIXED` over the same VA find and free the slot it replaces.

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use carrick_abi::align_up_u64;

use crate::memory::{LINUX_SHARED_FILE_BASE, LINUX_SHARED_FILE_SIZE};

/// What backs a live shared-aperture allocation. This is the skeleton of the
/// spec's backing-object model. The shared allocator holds shared backings plus
/// typed `PrivateReservation` occupancy; private bytes themselves live only in
/// the separate overlay aperture.
#[derive(Debug, Clone)]
pub enum BackingObject {
    /// Guest `MAP_SHARED | MAP_ANON`: lives entirely in the aperture's host
    /// backing, shared across `fork(2)`, never copied. No writeback.
    SharedAnon,
    /// Guest `MAP_SHARED` of a file. Bytes are copied into the aperture on map;
    /// dirty bytes are written back to `host_fd` at `offset` on
    /// `msync(MS_SYNC)`/`munmap`. `host_fd` is a dup the allocator owns until
    /// the allocation is freed.
    SharedFile {
        /// One close-on-last-fragment owner for the allocator's dup. Splitting
        /// an allocation clones this `Arc`, so each fragment can write back its
        /// own byte interval without double-closing the descriptor. After a
        /// host `fork`, each process has its own copied refcount and closes its
        /// inherited descriptor exactly once when its last fragment retires.
        host_fd: Arc<OwnedFd>,
        offset: u64,
    },
    /// Guest-VA reservation in the SHARED aperture allocator while a private
    /// overlay owns that source interval. It deliberately owns no shared bytes
    /// and has no writeback; its only job is to keep a nonfixed `MAP_SHARED`
    /// allocation from reusing a VA whose live stage-1 leaf points elsewhere.
    PrivateReservation,
    /// Private overlay slot (lives in the PRIVATE overlay window, not the shared
    /// one): backs a `MAP_FIXED|MAP_PRIVATE` that landed on a shared-aperture VA.
    /// The window's host backing is per-process (fork snapshots it), so stores
    /// stay private. No writeback.
    PrivateAnon,
}

impl BackingObject {
    /// Transfer ownership of a dup'd shared-file descriptor to the aperture.
    pub fn shared_file(host_fd: OwnedFd, offset: u64) -> Self {
        Self::SharedFile {
            host_fd: Arc::new(host_fd),
            offset,
        }
    }

    /// Raw descriptor and fragment-relative file offset for libc writeback.
    pub fn shared_file_parts(&self) -> Option<(RawFd, u64)> {
        match self {
            Self::SharedFile { host_fd, offset } => Some((host_fd.as_raw_fd(), *offset)),
            Self::SharedAnon | Self::PrivateReservation | Self::PrivateAnon => None,
        }
    }

    fn fragment_at(&self, byte_offset: u64) -> Option<Self> {
        match self {
            Self::SharedFile { host_fd, offset } => Some(Self::SharedFile {
                host_fd: Arc::clone(host_fd),
                offset: offset.checked_add(byte_offset)?,
            }),
            Self::SharedAnon => Some(Self::SharedAnon),
            Self::PrivateReservation => Some(Self::PrivateReservation),
            Self::PrivateAnon => Some(Self::PrivateAnon),
        }
    }
}

impl PartialEq for BackingObject {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::SharedAnon, Self::SharedAnon)
            | (Self::PrivateReservation, Self::PrivateReservation)
            | (Self::PrivateAnon, Self::PrivateAnon) => true,
            (
                Self::SharedFile {
                    host_fd: left_fd,
                    offset: left_offset,
                },
                Self::SharedFile {
                    host_fd: right_fd,
                    offset: right_offset,
                },
            ) => left_fd.as_raw_fd() == right_fd.as_raw_fd() && left_offset == right_offset,
            _ => false,
        }
    }
}

impl Eq for BackingObject {}

/// One live allocation within an aperture.
#[derive(Debug, Clone)]
pub struct SharedAlloc {
    pub guest_addr: u64,
    /// Physical aperture bytes still reserved to this logical fragment. An
    /// original allocation is granule-rounded, but an exact carve may split its
    /// reservation at a Linux-page boundary; such partial free ranges are kept
    /// unavailable until adjacent fragments retire and coalesce to a complete,
    /// aligned allocation granule.
    pub len: u64,
    /// Guest-visible bytes still owned by this slot. `SharedFile` writeback and
    /// shrink accounting operate on this logical length, not the rounded
    /// aperture reservation.
    pub live_len: u64,
    pub backing: BackingObject,
    /// For a `PrivateAnon` overlay slot: the shared-aperture VA this slot backs
    /// (so a re-`MAP_FIXED` over the same VA can find and free the old slot).
    /// `None` for ordinary shared-aperture allocations.
    pub source: Option<u64>,
}

/// Bump-plus-free-list sub-allocator over the fixed shared aperture window
/// `[LINUX_SHARED_FILE_BASE, LINUX_SHARED_FILE_BASE + LINUX_SHARED_FILE_SIZE)`.
/// Fresh allocations are mapping-granule (`0x4000`) aligned. Exact logical
/// carves may create smaller fragments; the free-list allocator only reuses a
/// range when it contains a complete aligned granule. No hypervisor calls happen
/// here — the window is stage-2-mapped once at boot.
#[derive(Debug, Clone)]
pub struct SharedAperture {
    base: u64,
    size: u64,
    next: u64,
    /// Freed `(start, len)` ranges, sorted by start, coalesced. Reused before
    /// the bump cursor advances.
    free: Vec<(u64, u64)>,
    /// Freed guest intervals whose last live leaf targeted private-overlay
    /// storage. A later shared allocation must explicitly restore VA→identity
    /// before `protect_range` may make that retained leaf valid again.
    identity_restore: Vec<(u64, u64)>,
    live: Vec<SharedAlloc>,
}

const GRANULE: u64 = 0x4000; // 16 KiB mapping granule; kept local (no backend dep).

impl Default for SharedAperture {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedAperture {
    pub fn new() -> Self {
        Self::with_window(LINUX_SHARED_FILE_BASE, LINUX_SHARED_FILE_SIZE)
    }

    /// A sub-allocator over an arbitrary boot-mapped window. The shared aperture
    /// uses `new()`; the private overlay aperture uses this with its own window.
    pub fn with_window(base: u64, size: u64) -> Self {
        Self {
            base,
            size,
            next: base,
            free: Vec::new(),
            identity_restore: Vec::new(),
            live: Vec::new(),
        }
    }

    fn window_end(&self) -> u64 {
        self.base + self.size
    }

    /// Reserve `len` bytes (rounded up to the granule). Returns the guest IPA,
    /// or `None` if the window is exhausted. Records the backing.
    pub fn alloc(&mut self, len: u64, backing: BackingObject) -> Option<u64> {
        self.alloc_sourced_with_reuse(len, backing, None)
            .map(|(addr, _reused)| addr)
    }

    /// Like [`alloc`](Self::alloc), but tags the slot with the shared-aperture
    /// VA it backs (a `PrivateAnon` overlay slot), so
    /// [`find_by_source`](Self::find_by_source) can locate it for a re-`MAP_FIXED`
    /// over the same VA.
    pub fn alloc_sourced(
        &mut self,
        len: u64,
        backing: BackingObject,
        source: Option<u64>,
    ) -> Option<u64> {
        self.alloc_sourced_with_reuse(len, backing, source)
            .map(|(addr, _reused)| addr)
    }

    /// Like [`alloc_sourced`](Self::alloc_sourced), but also reports whether
    /// the returned range came from the free list and may contain stale bytes.
    pub fn alloc_sourced_with_reuse(
        &mut self,
        len: u64,
        backing: BackingObject,
        source: Option<u64>,
    ) -> Option<(u64, bool)> {
        self.alloc_sourced_with_reuse_avoiding(len, backing, source, |_, _| false)
    }

    /// Allocate while excluding guest intervals that remain owned by another
    /// address-space object (notably a live private overlay over an identity
    /// shared-aperture VA). Excluded free ranges remain available for a later
    /// allocation after that owner retires; excluded bump ranges are recorded
    /// in the free list rather than leaked.
    pub fn alloc_sourced_with_reuse_avoiding<F>(
        &mut self,
        len: u64,
        backing: BackingObject,
        source: Option<u64>,
        mut avoid: F,
    ) -> Option<(u64, bool)>
    where
        F: FnMut(u64, u64) -> bool,
    {
        if len == 0 {
            return None;
        }
        let live_len = len;
        let len = align_up_u64(len, GRANULE)?;
        // Reuse a freed range first, but only at an aligned point that fits a
        // complete rounded allocation. Exact 4 KiB carves can leave partial
        // 16 KiB free fragments; those must not be handed out until adjacent
        // retirements coalesce them into an aligned whole granule.
        let mut reusable = None;
        'ranges: for (pos, &(start, range_len)) in self.free.iter().enumerate() {
            let range_end = start.checked_add(range_len)?;
            let mut candidate = align_up_u64(start, GRANULE)?;
            while candidate
                .checked_add(len)
                .is_some_and(|end| end <= range_end)
            {
                if !self.physical_range_has_owner(candidate, len) && !avoid(candidate, len) {
                    reusable = Some((pos, candidate));
                    break 'ranges;
                }
                candidate = candidate.checked_add(GRANULE)?;
            }
        }
        if let Some((pos, addr)) = reusable {
            let (s, l) = self.free.remove(pos);
            let range_end = s.checked_add(l)?;
            let alloc_end = addr.checked_add(len)?;
            if addr > s {
                free_insert(&mut self.free, s, addr - s);
            }
            if alloc_end < range_end {
                free_insert(&mut self.free, alloc_end, range_end - alloc_end);
            }
            self.live.push(SharedAlloc {
                guest_addr: addr,
                len,
                live_len,
                backing,
                source,
            });
            return Some((addr, true));
        }

        let mut addr = align_up_u64(self.next, GRANULE)?;
        loop {
            let end = addr.checked_add(len)?;
            if end > self.window_end() {
                return None;
            }
            self.next = end;
            if self.physical_range_has_owner(addr, len) || avoid(addr, len) {
                free_insert(&mut self.free, addr, len);
                addr = align_up_u64(self.next, GRANULE)?;
                continue;
            }
            self.live.push(SharedAlloc {
                guest_addr: addr,
                len,
                live_len,
                backing,
                source,
            });
            return Some((addr, false));
        }
    }

    /// Whether a physical allocator interval intersects any live slot. Normally
    /// `free` and `live` are disjoint; fixed private reservations intentionally
    /// remain present in `free` so releasing the reservation makes the exact
    /// coalesced interval reusable without reconstructing allocator history.
    fn physical_range_has_owner(&self, guest_addr: u64, len: u64) -> bool {
        let Some(end) = guest_addr.checked_add(len) else {
            return true;
        };
        self.live.iter().any(|alloc| {
            let Some(alloc_end) = alloc.guest_addr.checked_add(alloc.len) else {
                return true;
            };
            guest_addr < alloc_end && alloc.guest_addr < end
        })
    }

    /// The overlay slot (guest_addr) whose owned source interval starts exactly
    /// at `source`, if any. New replacement/teardown code must use
    /// [`Self::translate_source_range`] and [`Self::carve_source_range`] rather
    /// than freeing this whole allocation for a partial source interval.
    pub fn find_by_source(&self, source: u64) -> Option<u64> {
        self.live
            .iter()
            .find(|a| a.source == Some(source))
            .map(|a| a.guest_addr)
    }

    /// Translate a complete source interval into its contiguous overlay interval.
    /// Returns `None` if the range is not wholly owned by one live overlay
    /// fragment. Carved suffixes retain `source + delta -> guest_addr + delta`.
    pub fn translate_source_range(&self, source: u64, len: u64) -> Option<u64> {
        let end = source.checked_add(len)?;
        self.live.iter().find_map(|alloc| {
            let alloc_source = alloc.source?;
            let alloc_end = alloc_source.checked_add(alloc.live_len)?;
            if source < alloc_source || end > alloc_end {
                return None;
            }
            alloc
                .guest_addr
                .checked_add(source.checked_sub(alloc_source)?)
        })
    }

    /// Whether any live overlay owner intersects the source interval.
    pub fn source_range_has_owner(&self, source: u64, len: u64) -> bool {
        let Some(end) = source.checked_add(len) else {
            return false;
        };
        self.live.iter().any(|alloc| {
            let Some(alloc_source) = alloc.source else {
                return false;
            };
            let Some(alloc_end) = alloc_source.checked_add(alloc.live_len) else {
                return false;
            };
            source < alloc_end && alloc_source < end
        })
    }

    /// Whether removing `source..source+len` from every overlapping overlay owner
    /// is arithmetically representable. Exact Linux-page boundaries are valid:
    /// partial physical free fragments remain quarantined until they coalesce to
    /// a complete aligned allocation granule.
    pub fn source_range_is_carvable(
        &self,
        source: u64,
        len: u64,
        exclude_guest_addr: Option<u64>,
    ) -> bool {
        let Some(end) = source.checked_add(len) else {
            return false;
        };
        self.live.iter().all(|alloc| {
            if Some(alloc.guest_addr) == exclude_guest_addr {
                return true;
            }
            let Some(alloc_source) = alloc.source else {
                return true;
            };
            let Some(alloc_end) = alloc_source.checked_add(alloc.live_len) else {
                return false;
            };
            let overlap_start = source.max(alloc_source);
            let overlap_end = end.min(alloc_end);
            if overlap_start >= overlap_end {
                return true;
            }
            overlap_start.checked_sub(alloc_source).is_some()
                && overlap_end.checked_sub(alloc_source).is_some()
        })
    }

    /// Remove exactly the overwritten source interval from every overlapping
    /// overlay owner and split surviving prefix/suffix ownership. Physical
    /// fragments return to the free list immediately, but allocation only
    /// consumes complete aligned granules.
    ///
    /// `exclude_guest_addr` identifies the freshly installed replacement owner;
    /// it may have the same source interval and must remain live. Validation is
    /// all-or-nothing: `None` leaves `live` and `free` unchanged.
    pub fn carve_source_range(
        &mut self,
        source: u64,
        len: u64,
        exclude_guest_addr: Option<u64>,
    ) -> Option<usize> {
        if !self.source_range_is_carvable(source, len, exclude_guest_addr) {
            return None;
        }
        let end = source.checked_add(len)?;
        let mut next_live = Vec::with_capacity(self.live.len() + 1);
        let mut released = Vec::new();
        let mut carved = 0usize;

        for alloc in self.live.iter().cloned() {
            if Some(alloc.guest_addr) == exclude_guest_addr {
                next_live.push(alloc);
                continue;
            }
            let Some(alloc_source) = alloc.source else {
                next_live.push(alloc);
                continue;
            };
            let alloc_end = alloc_source.checked_add(alloc.live_len)?;
            let overlap_start = source.max(alloc_source);
            let overlap_end = end.min(alloc_end);
            if overlap_start >= overlap_end {
                next_live.push(alloc);
                continue;
            }

            let prefix_live_len = overlap_start.checked_sub(alloc_source)?;
            let suffix_offset = overlap_end.checked_sub(alloc_source)?;
            let suffix_live_len = alloc_end.checked_sub(overlap_end)?;
            let release_start = alloc.guest_addr.checked_add(prefix_live_len)?;
            let release_end = if suffix_live_len == 0 {
                alloc.guest_addr.checked_add(alloc.len)?
            } else {
                alloc.guest_addr.checked_add(suffix_offset)?
            };
            let release_len = release_end.checked_sub(release_start)?;

            if prefix_live_len != 0 {
                next_live.push(SharedAlloc {
                    guest_addr: alloc.guest_addr,
                    len: prefix_live_len,
                    live_len: prefix_live_len,
                    backing: alloc.backing.clone(),
                    source: Some(alloc_source),
                });
            }
            if suffix_live_len != 0 {
                next_live.push(SharedAlloc {
                    guest_addr: alloc.guest_addr.checked_add(suffix_offset)?,
                    len: alloc.len.checked_sub(suffix_offset)?,
                    live_len: suffix_live_len,
                    backing: alloc.backing.fragment_at(suffix_offset)?,
                    source: Some(overlap_end),
                });
            }
            if release_len != 0 {
                released.push((release_start, release_len));
            }
            carved = carved.checked_add(1)?;
        }

        self.live = next_live;
        for (start, release_len) in released {
            free_insert(&mut self.free, start, release_len);
        }
        Some(carved)
    }

    /// Whether an ordinary (`source == None`) allocation intersects the guest
    /// interval. Overlay allocations are deliberately ignored: their physical
    /// slot address is not the guest VA whose ownership is being queried.
    pub fn guest_range_has_owner(&self, guest_addr: u64, len: u64) -> bool {
        let Some(end) = guest_addr.checked_add(len) else {
            return false;
        };
        self.live.iter().any(|alloc| {
            if alloc.source.is_some() {
                return false;
            }
            let Some(alloc_end) = alloc.guest_addr.checked_add(alloc.live_len) else {
                return false;
            };
            guest_addr < alloc_end && alloc.guest_addr < end
        })
    }

    /// Preflight an exact guest-interval carve from ordinary allocations.
    /// Surviving fragments may share the original file-fd owner. Partial free
    /// fragments remain quarantined until a whole aligned granule is available.
    pub fn guest_range_is_carvable(&self, guest_addr: u64, len: u64) -> bool {
        let Some(end) = guest_addr.checked_add(len) else {
            return false;
        };
        if len == 0 {
            return false;
        }
        self.live.iter().all(|alloc| {
            if alloc.source.is_some() {
                return true;
            }
            let Some(alloc_end) = alloc.guest_addr.checked_add(alloc.live_len) else {
                return false;
            };
            let overlap_start = guest_addr.max(alloc.guest_addr);
            let overlap_end = end.min(alloc_end);
            if overlap_start >= overlap_end {
                return true;
            }
            overlap_start.checked_sub(alloc.guest_addr).is_some()
                && overlap_end.checked_sub(alloc.guest_addr).is_some()
        })
    }

    /// Preview the exact ordinary fragments an interval carve would displace,
    /// without changing allocator state. Shared-file owners stay alive in the
    /// returned clones so callers can write back while the old guest translation
    /// is still installed, then commit [`Self::carve_guest_range`] only after a
    /// successful backend operation.
    pub fn guest_range_fragments(&self, guest_addr: u64, len: u64) -> Option<Vec<SharedAlloc>> {
        let mut preview = self.clone();
        preview.carve_guest_range(guest_addr, len)
    }

    /// Remove exactly `guest_addr..guest_addr+len` from every overlapping
    /// ordinary allocation, preserving prefix/suffix owners and returning the
    /// displaced fragments for exact file writeback. Shared-file fragments
    /// share one `Arc<OwnedFd>` owner; the descriptor closes only after the
    /// returned fragment and every survivor have retired.
    ///
    /// Validation is all-or-nothing: `None` leaves allocator state unchanged.
    pub fn carve_guest_range(&mut self, guest_addr: u64, len: u64) -> Option<Vec<SharedAlloc>> {
        if !self.guest_range_is_carvable(guest_addr, len) {
            return None;
        }
        let end = guest_addr.checked_add(len)?;
        let mut next_live = Vec::with_capacity(self.live.len() + 1);
        let mut released = Vec::new();
        let mut displaced = Vec::new();

        for alloc in self.live.iter().cloned() {
            if alloc.source.is_some() {
                next_live.push(alloc);
                continue;
            }
            let alloc_end = alloc.guest_addr.checked_add(alloc.live_len)?;
            let overlap_start = guest_addr.max(alloc.guest_addr);
            let overlap_end = end.min(alloc_end);
            if overlap_start >= overlap_end {
                next_live.push(alloc);
                continue;
            }

            let prefix_live_len = overlap_start.checked_sub(alloc.guest_addr)?;
            let overlap_offset = prefix_live_len;
            let overlap_live_len = overlap_end.checked_sub(overlap_start)?;
            let suffix_offset = overlap_end.checked_sub(alloc.guest_addr)?;
            let suffix_live_len = alloc_end.checked_sub(overlap_end)?;
            let release_start = alloc.guest_addr.checked_add(prefix_live_len)?;
            let release_end = if suffix_live_len == 0 {
                alloc.guest_addr.checked_add(alloc.len)?
            } else {
                alloc.guest_addr.checked_add(suffix_offset)?
            };
            let release_len = release_end.checked_sub(release_start)?;

            if prefix_live_len != 0 {
                next_live.push(SharedAlloc {
                    guest_addr: alloc.guest_addr,
                    len: prefix_live_len,
                    live_len: prefix_live_len,
                    backing: alloc.backing.clone(),
                    source: None,
                });
            }
            if suffix_live_len != 0 {
                next_live.push(SharedAlloc {
                    guest_addr: alloc.guest_addr.checked_add(suffix_offset)?,
                    len: alloc.len.checked_sub(suffix_offset)?,
                    live_len: suffix_live_len,
                    backing: alloc.backing.fragment_at(suffix_offset)?,
                    source: None,
                });
            }
            displaced.push(SharedAlloc {
                guest_addr: overlap_start,
                len: release_len,
                live_len: overlap_live_len,
                backing: alloc.backing.fragment_at(overlap_offset)?,
                source: None,
            });
            if release_len != 0 {
                released.push((release_start, release_len));
            }
        }

        self.live = next_live;
        for (start, release_len) in released {
            free_insert(&mut self.free, start, release_len);
        }
        for alloc in &displaced {
            if matches!(alloc.backing, BackingObject::PrivateReservation) {
                free_insert(&mut self.identity_restore, alloc.guest_addr, alloc.live_len);
            }
        }
        Some(displaced)
    }

    /// Replace exact ordinary guest-VA ownership with a typed private-overlay
    /// reservation. Existing shared-file/anon owners are split exactly and
    /// returned to the caller for writeback/retirement; an existing reservation
    /// is split the same way when one private overlay replaces part of another.
    ///
    /// The reservation is deliberately recorded after the carve has returned its
    /// physical bytes to `free`. Allocation consults `live` as well as `free`, so
    /// those bytes remain quarantined until a matching unmap/shrink carves this
    /// reservation. Validation is all-or-nothing.
    pub fn reserve_private_range(&mut self, guest_addr: u64, len: u64) -> Option<Vec<SharedAlloc>> {
        let end = guest_addr.checked_add(len)?;
        if len == 0 || guest_addr < self.base || end > self.window_end() {
            return None;
        }
        let displaced = self.carve_guest_range(guest_addr, len)?;
        self.live.push(SharedAlloc {
            guest_addr,
            len,
            live_len: len,
            backing: BackingObject::PrivateReservation,
            source: None,
        });
        Some(displaced)
    }

    /// True when the complete guest interval is covered by private-reservation
    /// fragments and by no ordinary shared owner. Used by mapping tests and by
    /// callers that must distinguish occupancy from file/anon ownership.
    pub fn guest_range_is_private_reservation(&self, guest_addr: u64, len: u64) -> bool {
        let Some(end) = guest_addr.checked_add(len) else {
            return false;
        };
        if len == 0 {
            return false;
        }
        let mut fragments = self
            .live
            .iter()
            .filter(|alloc| {
                alloc.source.is_none()
                    && matches!(alloc.backing, BackingObject::PrivateReservation)
                    && alloc.guest_addr < end
                    && alloc
                        .guest_addr
                        .checked_add(alloc.live_len)
                        .is_some_and(|alloc_end| guest_addr < alloc_end)
            })
            .collect::<Vec<_>>();
        fragments.sort_by_key(|alloc| alloc.guest_addr);
        let mut cursor = guest_addr;
        for alloc in fragments {
            if alloc.guest_addr > cursor {
                return false;
            }
            let Some(alloc_end) = alloc.guest_addr.checked_add(alloc.live_len) else {
                return false;
            };
            cursor = cursor.max(alloc_end.min(end));
            if cursor == end {
                return true;
            }
        }
        false
    }

    /// Whether any part of this allocation needs an explicit identity-leaf
    /// restore before it can become a shared mapping again.
    pub fn range_needs_identity_restore(&self, guest_addr: u64, len: u64) -> bool {
        let Some(end) = guest_addr.checked_add(len) else {
            return true;
        };
        self.identity_restore.iter().any(|&(start, restore_len)| {
            let restore_end = start.saturating_add(restore_len);
            guest_addr < restore_end && start < end
        })
    }

    /// Commit a successful backend identity-leaf restore for the exact range.
    /// Interval subtraction preserves any stale prefix/suffix for later reuse.
    pub fn mark_identity_restored(&mut self, guest_addr: u64, len: u64) -> Option<()> {
        let end = guest_addr.checked_add(len)?;
        interval_remove(&mut self.identity_restore, guest_addr, end);
        Some(())
    }

    /// Shrink the guest-visible length of a live allocation. Any now-unused
    /// whole-granule tail is released back to the free list; a partial leading
    /// granule stays reserved to the allocation until a later free.
    pub fn shrink(&mut self, guest_addr: u64, new_live_len: u64) -> Option<()> {
        if new_live_len == 0 {
            return None;
        }
        let (old_live_len, private_reservation) = {
            let alloc = self.live.iter_mut().find(|a| a.guest_addr == guest_addr)?;
            if new_live_len > alloc.live_len {
                return None;
            }
            let old_live_len = alloc.live_len;
            let private_reservation = matches!(alloc.backing, BackingObject::PrivateReservation);
            alloc.live_len = new_live_len;
            (old_live_len, private_reservation)
        };
        self.release_tail(guest_addr)?;
        if private_reservation && new_live_len < old_live_len {
            free_insert(
                &mut self.identity_restore,
                guest_addr.checked_add(new_live_len)?,
                old_live_len - new_live_len,
            );
        }
        Some(())
    }

    /// Release any whole-granule tail beyond the allocation's current
    /// `live_len`, updating its reserved length and free accounting.
    pub fn release_tail(&mut self, guest_addr: u64) -> Option<()> {
        let released = {
            let alloc = self.live.iter_mut().find(|a| a.guest_addr == guest_addr)?;
            let keep_len = align_up_u64(alloc.live_len, GRANULE)?;
            if keep_len >= alloc.len {
                None
            } else {
                let release_start = alloc.guest_addr.checked_add(keep_len)?;
                let release_len = alloc.len.checked_sub(keep_len)?;
                alloc.len = keep_len;
                Some((release_start, release_len))
            }
        };
        if let Some((start, len)) = released {
            free_insert(&mut self.free, start, len);
        }
        Some(())
    }

    /// Free the allocation starting at `guest_addr`. Returns the removed
    /// allocation (so the caller can write it back); the shared RAII owner closes
    /// its fd when the last fragment drops. Returns `None` if no live allocation
    /// starts there.
    pub fn free(&mut self, guest_addr: u64) -> Option<SharedAlloc> {
        let pos = self.live.iter().position(|a| a.guest_addr == guest_addr)?;
        let alloc = self.live.remove(pos);
        free_insert(&mut self.free, alloc.guest_addr, alloc.len);
        Some(alloc)
    }

    /// All live allocations (used by `msync`-all and fork bookkeeping).
    pub fn live(&self) -> &[SharedAlloc] {
        &self.live
    }
}

/// Insert `[addr, addr+len)` into `regions`, coalescing adjacent/overlapping.
fn interval_remove(regions: &mut Vec<(u64, u64)>, remove_start: u64, remove_end: u64) {
    let mut out = Vec::with_capacity(regions.len() + 1);
    for &(start, len) in regions.iter() {
        let end = start.saturating_add(len);
        if remove_end <= start || remove_start >= end {
            out.push((start, len));
            continue;
        }
        if start < remove_start {
            out.push((start, remove_start - start));
        }
        if remove_end < end {
            out.push((remove_end, end - remove_end));
        }
    }
    *regions = out;
}

fn free_insert(regions: &mut Vec<(u64, u64)>, addr: u64, len: u64) {
    let mut start = addr;
    let mut end = addr.saturating_add(len);
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(regions.len() + 1);
    let mut inserted = false;
    for &(s, l) in regions.iter() {
        let e = s.saturating_add(l);
        if e < start || s > end {
            if !inserted && s > end {
                out.push((start, end - start));
                inserted = true;
            }
            out.push((s, l));
        } else {
            start = start.min(s);
            end = end.max(e);
        }
    }
    if !inserted {
        out.push((start, end - start));
    }
    out.sort_by_key(|&(s, _)| s);
    *regions = out;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `shared_file_fragments_adjust_offsets_and_close_once_after_last_owner`
    /// asserts that a just-FREED numeric fd is dead (`fcntl(F_GETFD) == -1`,
    /// `errno == EBADF`) -- which races any concurrent test in this same
    /// binary that opens its own fd around the same moment (cargo runs a
    /// crate's tests in parallel by default): the kernel is free to hand the
    /// just-closed number straight back out to a sibling test's `open()`
    /// before this test's probe runs, making `F_GETFD` unexpectedly succeed
    /// (flaky under load). Serialize every test in this module that probes a
    /// numeric fd after close so no sibling test's fd churn lands in the
    /// window between close and probe. Poison-recovering, mirroring
    /// `carrick-host`'s `host_mapping.rs::MMAP_TEST_LOCK`, so a panic in one
    /// test doesn't cascade-fail the others.
    static FD_PROBE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn base() -> u64 {
        LINUX_SHARED_FILE_BASE
    }

    fn owned_dev_null() -> OwnedFd {
        std::fs::File::options()
            .read(true)
            .write(true)
            .open("/dev/null")
            .expect("open /dev/null")
            .into()
    }

    #[test]
    fn bump_allocates_aligned_within_window() {
        let mut ap = SharedAperture::new();
        let a = ap.alloc(0x4000, BackingObject::SharedAnon).expect("alloc");
        let b = ap.alloc(0x1000, BackingObject::SharedAnon).expect("alloc");
        assert_eq!(a, base());
        // Second allocation is rounded up to the 16 KiB granule (0x4000).
        assert_eq!(b, base() + 0x4000);
    }

    #[test]
    fn rejects_allocation_past_window_end() {
        let mut ap = SharedAperture::new();
        assert!(
            ap.alloc(LINUX_SHARED_FILE_SIZE + 0x4000, BackingObject::SharedAnon)
                .is_none()
        );
    }

    #[test]
    fn free_then_realloc_reuses_space() {
        let mut ap = SharedAperture::new();
        let a = ap.alloc(0x8000, BackingObject::SharedAnon).expect("alloc");
        let freed = ap.free(a).expect("freed backing");
        assert!(matches!(freed.backing, BackingObject::SharedAnon));
        // The freed range is reused before the bump cursor advances.
        let b = ap.alloc(0x8000, BackingObject::SharedAnon).expect("alloc");
        assert_eq!(b, a);
    }

    #[test]
    fn free_unknown_address_returns_none() {
        let mut ap = SharedAperture::new();
        assert!(ap.free(base() + 0x123).is_none());
    }

    #[test]
    fn lookup_returns_backing_for_live_alloc() {
        let mut ap = SharedAperture::new();
        let fd = owned_dev_null();
        let raw_fd = fd.as_raw_fd();
        let a = ap
            .alloc(0x4000, BackingObject::shared_file(fd, 0x1000))
            .expect("alloc");
        let got = ap.live().iter().find(|x| x.guest_addr == a).expect("live");
        assert_eq!(got.backing.shared_file_parts(), Some((raw_fd, 0x1000)));
        assert_eq!(got.live_len, 0x4000);
    }

    #[test]
    fn shrink_releases_whole_granule_tail_and_coalesces_on_free() {
        let mut ap = SharedAperture::new();
        let a = ap.alloc(0x8000, BackingObject::SharedAnon).expect("alloc");

        ap.shrink(a, 0x1000).expect("shrink live len");
        let live = ap
            .live()
            .iter()
            .find(|alloc| alloc.guest_addr == a)
            .unwrap();
        assert_eq!(live.live_len, 0x1000);
        assert_eq!(live.len, 0x4000);

        let reused_tail = ap
            .alloc(0x4000, BackingObject::SharedAnon)
            .expect("reuse tail");
        assert_eq!(reused_tail, a + 0x4000);
        ap.free(reused_tail).expect("free reused tail");
        ap.free(a).expect("free head");

        let whole = ap
            .alloc(0x8000, BackingObject::SharedAnon)
            .expect("coalesced reuse");
        assert_eq!(whole, a);
    }

    #[test]
    fn shrink_preserves_shared_file_fd_and_offset_metadata() {
        let mut ap = SharedAperture::new();
        let fd = owned_dev_null();
        let raw_fd = fd.as_raw_fd();
        let a = ap
            .alloc(0x8000, BackingObject::shared_file(fd, 0x2000))
            .expect("file alloc");

        ap.shrink(a, 0x1000).expect("shrink file allocation");
        let live = ap
            .live()
            .iter()
            .find(|alloc| alloc.guest_addr == a)
            .unwrap();
        assert_eq!(live.backing.shared_file_parts(), Some((raw_fd, 0x2000)));
        assert_eq!(live.live_len, 0x1000);
        assert_eq!(live.len, 0x4000);
        let freed = ap.free(a).expect("free file allocation");
        assert_eq!(freed.backing.shared_file_parts(), Some((raw_fd, 0x2000)));
    }

    #[test]
    fn invalid_shrink_preserves_live_and_free_accounting() {
        let mut ap = SharedAperture::new();
        let a = ap.alloc(0x1000, BackingObject::SharedAnon).expect("alloc");

        assert!(ap.shrink(a, 0x5000).is_none(), "grow must be rejected");
        assert!(ap.free.is_empty(), "failed shrink must not free tail space");

        let live = ap
            .live()
            .iter()
            .find(|alloc| alloc.guest_addr == a)
            .unwrap();
        assert_eq!(live.live_len, 0x1000);
        assert_eq!(live.len, 0x4000);
    }

    #[test]
    fn guest_carve_middle_preserves_prefix_suffix_and_reuses_only_middle() {
        let mut ap = SharedAperture::with_window(0x0800_0000, 0x10_0000);
        let allocation = ap
            .alloc(3 * GRANULE, BackingObject::SharedAnon)
            .expect("ordinary shared allocation");

        let displaced = ap
            .carve_guest_range(allocation + GRANULE, GRANULE)
            .expect("exact middle carve");
        assert_eq!(displaced.len(), 1);
        assert_eq!(displaced[0].guest_addr, allocation + GRANULE);
        assert_eq!(displaced[0].live_len, GRANULE);
        assert!(ap.guest_range_has_owner(allocation, GRANULE));
        assert!(ap.guest_range_has_owner(allocation + (2 * GRANULE), GRANULE));
        assert!(!ap.guest_range_has_owner(allocation + GRANULE, GRANULE));

        let reused = ap
            .alloc(GRANULE, BackingObject::SharedAnon)
            .expect("reuse displaced middle");
        assert_eq!(reused, allocation + GRANULE);
        let next = ap
            .alloc(GRANULE, BackingObject::SharedAnon)
            .expect("surviving fragments remain reserved");
        assert_eq!(next, allocation + (3 * GRANULE));
    }

    #[test]
    fn private_reservation_blocks_reuse_until_exact_release() {
        let mut ap = SharedAperture::with_window(0x0880_0000, 0x10_0000);
        let allocation = ap
            .alloc(3 * GRANULE, BackingObject::SharedAnon)
            .expect("ordinary shared allocation");

        let displaced = ap
            .reserve_private_range(allocation + GRANULE, GRANULE)
            .expect("reserve displaced middle");
        assert_eq!(displaced.len(), 1);
        assert!(matches!(displaced[0].backing, BackingObject::SharedAnon));
        assert!(ap.guest_range_is_private_reservation(allocation + GRANULE, GRANULE));
        let while_private = ap
            .alloc(GRANULE, BackingObject::SharedAnon)
            .expect("allocate around private reservation");
        assert_eq!(while_private, allocation + (3 * GRANULE));

        let released = ap
            .carve_guest_range(allocation + GRANULE, GRANULE)
            .expect("release exact private reservation");
        assert_eq!(released.len(), 1);
        assert!(matches!(
            released[0].backing,
            BackingObject::PrivateReservation
        ));
        assert!(ap.range_needs_identity_restore(allocation + GRANULE, GRANULE));
        let reused = ap
            .alloc(GRANULE, BackingObject::SharedAnon)
            .expect("reuse released private source");
        assert_eq!(reused, allocation + GRANULE);
        ap.mark_identity_restored(reused, GRANULE)
            .expect("commit identity restore");
        assert!(!ap.range_needs_identity_restore(reused, GRANULE));
    }

    #[test]
    fn shared_file_fragments_adjust_offsets_and_close_once_after_last_owner() {
        let _serialize = FD_PROBE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut ap = SharedAperture::with_window(0x0900_0000, 0x10_0000);
        let fd = owned_dev_null();
        let raw_fd = fd.as_raw_fd();
        let allocation = ap
            .alloc(3 * GRANULE, BackingObject::shared_file(fd, 0x20_0000))
            .expect("shared file allocation");

        let displaced = ap
            .carve_guest_range(allocation + GRANULE, GRANULE)
            .expect("split file allocation");
        assert_eq!(
            displaced[0].backing.shared_file_parts(),
            Some((raw_fd, 0x20_0000 + GRANULE))
        );
        let suffix = ap
            .live()
            .iter()
            .find(|alloc| alloc.guest_addr == allocation + (2 * GRANULE))
            .expect("file suffix");
        assert_eq!(
            suffix.backing.shared_file_parts(),
            Some((raw_fd, 0x20_0000 + (2 * GRANULE)))
        );
        drop(displaced);
        assert_ne!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) }, -1);

        drop(ap.free(allocation).expect("free file prefix"));
        assert_ne!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) }, -1);
        drop(
            ap.free(allocation + (2 * GRANULE))
                .expect("free file suffix"),
        );
        assert_eq!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
    }

    #[test]
    fn source_carve_prefix_preserves_suffix_translation_and_reuses_only_prefix() {
        let mut ap = SharedAperture::with_window(0x1000_0000, 0x10_0000);
        let source = 0x2000_0000;
        let overlay = ap
            .alloc_sourced(3 * GRANULE, BackingObject::PrivateAnon, Some(source))
            .expect("overlay");

        assert_eq!(ap.carve_source_range(source, GRANULE, None), Some(1));
        assert_eq!(
            ap.translate_source_range(source + GRANULE, 2 * GRANULE),
            Some(overlay + GRANULE)
        );
        let reused = ap
            .alloc(GRANULE, BackingObject::PrivateAnon)
            .expect("reuse carved prefix");
        assert_eq!(reused, overlay);
        let next = ap
            .alloc(GRANULE, BackingObject::PrivateAnon)
            .expect("suffix remains reserved");
        assert_eq!(next, overlay + (3 * GRANULE));
    }

    #[test]
    fn source_carve_middle_preserves_both_translations_and_reuses_only_middle() {
        let mut ap = SharedAperture::with_window(0x3000_0000, 0x10_0000);
        let source = 0x4000_0000;
        let overlay = ap
            .alloc_sourced(3 * GRANULE, BackingObject::PrivateAnon, Some(source))
            .expect("overlay");

        assert_eq!(
            ap.carve_source_range(source + GRANULE, GRANULE, None),
            Some(1)
        );
        assert_eq!(ap.translate_source_range(source, GRANULE), Some(overlay));
        assert_eq!(
            ap.translate_source_range(source + (2 * GRANULE), GRANULE),
            Some(overlay + (2 * GRANULE))
        );
        let reused = ap
            .alloc(GRANULE, BackingObject::PrivateAnon)
            .expect("reuse carved middle");
        assert_eq!(reused, overlay + GRANULE);
        let next = ap
            .alloc(GRANULE, BackingObject::PrivateAnon)
            .expect("prefix and suffix remain reserved");
        assert_eq!(next, overlay + (3 * GRANULE));
    }

    #[test]
    fn source_carve_suffix_preserves_prefix_and_trailing_padding_accounting() {
        let mut ap = SharedAperture::with_window(0x5000_0000, 0x10_0000);
        let source = 0x6000_0000;
        let overlay = ap
            .alloc_sourced(
                (2 * GRANULE) + 0x1000,
                BackingObject::PrivateAnon,
                Some(source),
            )
            .expect("overlay");

        assert_eq!(
            ap.carve_source_range(source + (2 * GRANULE), 0x1000, None),
            Some(1)
        );
        assert_eq!(
            ap.translate_source_range(source, 2 * GRANULE),
            Some(overlay)
        );
        let reused = ap
            .alloc(GRANULE, BackingObject::PrivateAnon)
            .expect("reuse suffix granule including padding");
        assert_eq!(reused, overlay + (2 * GRANULE));
    }

    #[test]
    fn partial_granule_source_carve_splits_exactly_but_quarantines_storage() {
        let mut ap = SharedAperture::with_window(0x7000_0000, 0x10_0000);
        let source = 0x8000_0000;
        let overlay = ap
            .alloc_sourced(2 * GRANULE, BackingObject::PrivateAnon, Some(source))
            .expect("overlay");

        assert!(ap.source_range_is_carvable(source, 0x1000, None));
        assert_eq!(ap.carve_source_range(source, 0x1000, None), Some(1));
        assert_eq!(
            ap.translate_source_range(source + 0x1000, (2 * GRANULE) - 0x1000),
            Some(overlay + 0x1000)
        );
        let next = ap
            .alloc(GRANULE, BackingObject::PrivateAnon)
            .expect("partial free must force a fresh aligned granule");
        assert_eq!(next, overlay + (2 * GRANULE));

        assert_eq!(
            ap.carve_source_range(source + 0x1000, (2 * GRANULE) - 0x1000, None),
            Some(1)
        );
        let reused = ap
            .alloc(2 * GRANULE, BackingObject::PrivateAnon)
            .expect("all fragments coalesce to the original reservation");
        assert_eq!(reused, overlay);
    }

    #[test]
    fn partial_granule_guest_carve_never_reuses_live_suffix_bytes() {
        let mut ap = SharedAperture::with_window(0x9000_0000, 0x10_0000);
        let allocation = ap
            .alloc(GRANULE, BackingObject::SharedAnon)
            .expect("ordinary shared allocation");

        let removed = ap
            .carve_guest_range(allocation + 0x1000, 0x1000)
            .expect("exact logical middle carve");
        assert_eq!(removed[0].guest_addr, allocation + 0x1000);
        assert!(ap.guest_range_has_owner(allocation, 0x1000));
        assert!(ap.guest_range_has_owner(allocation + 0x2000, 0x2000));
        let fresh = ap
            .alloc(GRANULE, BackingObject::SharedAnon)
            .expect("unaligned hole is not reusable");
        assert_eq!(fresh, allocation + GRANULE);
    }
}
