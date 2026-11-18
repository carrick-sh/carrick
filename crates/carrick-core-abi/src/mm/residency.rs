//! Exact live residency and retained grant-window custody for either ISA.
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
pub const FRAME_GRANT_RESIDENCY_SLOTS: usize = 4096;
pub const FRAME_GRANT_RESIDENCY_OVERFLOW_SLOTS: usize = 2048;
pub const MAX_FRAME_GRANT_RESIDENCY_OVERFLOW_SEGMENTS: usize = 63;
/// Requested bulk extent: 512 Linux pages, clamped by the supplying adapter
/// at the exact VMA or alignment edge.
pub const EL1_FRAME_GRANT_TARGET_SIZE: u64 = 2 * 1024 * 1024;

const GRANT_EMPTY: u64 = 0;
const GRANT_RETIRED: u64 = 1;
const GRANT_WRITING: u64 = 2;
const GRANT_LIVE: u64 = 3;
const GRANT_STATE_MASK: u64 = 3;
pub const GRANT_PAGE_SIZE: u64 = 4096;
const GRANT_PROBES: usize = 64;
pub const TRANSFER_PIN_RETIRED: u64 = 1 << 63;
const TRANSFER_PIN_RETIRING: u64 = TRANSFER_PIN_RETIRED | 1;

/// Exact frame ownership carried beside the residency bits. A slot cannot
/// authorize a reused mapping or frame with the same VA and IPA but a new
/// owner generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameGrantResidencyIdentity {
    pub mm_key: u64,
    pub semantic_base: u64,
    pub physical_ipa: u64,
    pub len: u64,
    pub mapping_id: u64,
    pub frame_id: u64,
    pub owner_generation: u64,
    pub inventory_revision: u64,
}

impl FrameGrantResidencyIdentity {
    fn valid(self) -> bool {
        let Some(end) = self.semantic_base.checked_add(self.len) else {
            return false;
        };
        self.mm_key != 0
            && self.mapping_id != 0
            && self.frame_id != 0
            && self.owner_generation != 0
            && self.inventory_revision != 0
            && self.len != 0
            && self.len <= EL1_FRAME_GRANT_TARGET_SIZE
            && self.semantic_base.is_multiple_of(GRANT_PAGE_SIZE)
            && self.physical_ipa.is_multiple_of(GRANT_PAGE_SIZE)
            && self.len.is_multiple_of(GRANT_PAGE_SIZE)
            && self.physical_ipa.checked_add(self.len).is_some()
            && (self.semantic_base / EL1_FRAME_GRANT_TARGET_SIZE)
                == ((end - 1) / EL1_FRAME_GRANT_TARGET_SIZE)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameGrantResidencyPage {
    pub slot: usize,
    pub identity: FrameGrantResidencyIdentity,
    pub expected_ipa: u64,
    epoch: u64,
    bit: usize,
}

/// One grant's identity and 512 per-page residency bits. `GRANT_LIVE` is
/// published last; retirement removes it first. All callers changing leaves
/// or bits hold the exact-MM editor, including the host mutation pause.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct FrameGrantResidencyRecord {
    state: AtomicU64,
    mm_key: AtomicU64,
    semantic_base: AtomicU64,
    physical_ipa: AtomicU64,
    len: AtomicU64,
    mapping_id: AtomicU64,
    frame_id: AtomicU64,
    owner_generation: AtomicU64,
    inventory_revision: AtomicU64,
    committed: [AtomicU64; 8],
    transfer_pins: AtomicU64,
    // Keep the existing 192-byte wire record fully initialized. This occupies
    // the former tail padding without moving any published field.
    _reserved: [u64; 6],
}

impl FrameGrantResidencyRecord {
    pub const COMMITTED_OFFSET: usize = core::mem::offset_of!(Self, committed);
    pub const TRANSFER_PINS_OFFSET: usize = core::mem::offset_of!(Self, transfer_pins);
    pub const fn new() -> Self {
        Self {
            state: AtomicU64::new(GRANT_EMPTY),
            mm_key: AtomicU64::new(0),
            semantic_base: AtomicU64::new(0),
            physical_ipa: AtomicU64::new(0),
            len: AtomicU64::new(0),
            mapping_id: AtomicU64::new(0),
            frame_id: AtomicU64::new(0),
            owner_generation: AtomicU64::new(0),
            inventory_revision: AtomicU64::new(0),
            committed: [const { AtomicU64::new(0) }; 8],
            transfer_pins: AtomicU64::new(TRANSFER_PIN_RETIRED),
            _reserved: [0; 6],
        }
    }

    fn identity(&self) -> FrameGrantResidencyIdentity {
        FrameGrantResidencyIdentity {
            mm_key: self.mm_key.load(Ordering::Relaxed),
            semantic_base: self.semantic_base.load(Ordering::Relaxed),
            physical_ipa: self.physical_ipa.load(Ordering::Relaxed),
            len: self.len.load(Ordering::Relaxed),
            mapping_id: self.mapping_id.load(Ordering::Relaxed),
            frame_id: self.frame_id.load(Ordering::Relaxed),
            owner_generation: self.owner_generation.load(Ordering::Relaxed),
            inventory_revision: self.inventory_revision.load(Ordering::Relaxed),
        }
    }

    fn publish(&self, identity: FrameGrantResidencyIdentity) {
        self.mm_key.store(identity.mm_key, Ordering::Relaxed);
        self.semantic_base
            .store(identity.semantic_base, Ordering::Relaxed);
        self.physical_ipa
            .store(identity.physical_ipa, Ordering::Relaxed);
        self.len.store(identity.len, Ordering::Relaxed);
        self.mapping_id
            .store(identity.mapping_id, Ordering::Relaxed);
        self.frame_id.store(identity.frame_id, Ordering::Relaxed);
        self.owner_generation
            .store(identity.owner_generation, Ordering::Relaxed);
        self.inventory_revision
            .store(identity.inventory_revision, Ordering::Relaxed);
        for word in &self.committed {
            word.store(0, Ordering::Relaxed);
        }
        self.transfer_pins.store(0, Ordering::Release);
        let writing = self.state.load(Ordering::Relaxed);
        self.state.store(
            (writing & !GRANT_STATE_MASK) | GRANT_LIVE,
            Ordering::Release,
        );
    }
}

impl Default for FrameGrantResidencyRecord {
    fn default() -> Self {
        Self::new()
    }
}

/// An exact-generation grant-window residency lease. Retirement is refused
/// until every lease drops. This guards grant-window publication only; it
/// does not retain physical frames. Physical custody belongs to the host
/// CarrierVmCustody stage-2 pin and retirement protocol.
/// The shared table must outlive every lease, including canceled operations.
pub struct FrameGrantTransferPin<'a> {
    record: &'a FrameGrantResidencyRecord,
}
impl Drop for FrameGrantTransferPin<'_> {
    fn drop(&mut self) {
        self.record.transfer_pins.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Exact-MM reservation of every residency row overlapping one descriptor
/// retirement. The caller either commits after the descriptor transaction or
/// drops this token to reopen transfer admission without changing residency.
pub struct FrameGrantResidencyRetirement<'a> {
    table: &'a FrameGrantResidencyTable,
    mm_key: u64,
    start: u64,
    end: u64,
    active: bool,
}
impl FrameGrantResidencyRetirement<'_> {
    /// Retire the preclaimed rows after their stage-1 leaves are unreachable.
    /// Exact-MM exclusion makes a failed commit an invariant violation.
    #[must_use]
    pub fn commit(mut self) -> bool {
        let committed = self
            .table
            .commit_retirement(self.mm_key, self.start, self.end);
        self.active = false;
        committed
    }
}
impl Drop for FrameGrantResidencyRetirement<'_> {
    fn drop(&mut self) {
        if self.active {
            self.table
                .cancel_retirement(self.mm_key, self.start, self.end);
        }
    }
}

/// Why a grant's residency row was not published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidencyPublishError {
    Invalid,
    Overlap,
    Capacity,
}

/// Why an overflow residency segment was not installed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidencySegmentInstallError {
    InvalidExtent,
    AlreadyGrown,
    Exhausted,
}

/// One dynamically provisioned 2,048-slot residency segment, sized to fit inside
/// one 512 KiB metadata extent (`EL1_DYNAMIC_METADATA_EXTENT_SIZE`).
#[repr(C, align(64))]
#[derive(Debug)]
pub struct FrameGrantResidencyOverflowSegment {
    slots: [FrameGrantResidencyRecord; FRAME_GRANT_RESIDENCY_OVERFLOW_SLOTS],
    dirty: [AtomicU64; FRAME_GRANT_RESIDENCY_OVERFLOW_SLOTS / 64],
}

const _: () = assert!(
    core::mem::size_of::<FrameGrantResidencyOverflowSegment>()
        <= crate::EL1_DYNAMIC_METADATA_EXTENT_SIZE
);

impl FrameGrantResidencyOverflowSegment {
    pub const fn new() -> Self {
        Self {
            slots: [const { FrameGrantResidencyRecord::new() };
                FRAME_GRANT_RESIDENCY_OVERFLOW_SLOTS],
            dirty: [const { AtomicU64::new(0) }; FRAME_GRANT_RESIDENCY_OVERFLOW_SLOTS / 64],
        }
    }

    /// Initialize an overflow segment in place without a large stack temporary.
    ///
    /// # Safety
    /// `ptr` must be valid for writes, non-null, aligned to `align_of::<Self>()`,
    /// and point to storage of at least `size_of::<Self>()` bytes.
    pub unsafe fn init_in_place(ptr: *mut Self) {
        unsafe {
            let slots = core::ptr::addr_of_mut!((*ptr).slots).cast::<FrameGrantResidencyRecord>();
            for index in 0..FRAME_GRANT_RESIDENCY_OVERFLOW_SLOTS {
                slots.add(index).write(FrameGrantResidencyRecord::new());
            }
            let dirty = core::ptr::addr_of_mut!((*ptr).dirty).cast::<AtomicU64>();
            for index in 0..FRAME_GRANT_RESIDENCY_OVERFLOW_SLOTS / 64 {
                dirty.add(index).write(AtomicU64::new(0));
            }
        }
    }
}

impl Default for FrameGrantResidencyOverflowSegment {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C)]
#[derive(Debug)]
struct ResidencyOverflowDescriptor {
    guest_base: AtomicU64,
    extent_base: AtomicU64,
    extent_len: AtomicU64,
    token: AtomicU64,
}

impl ResidencyOverflowDescriptor {
    const fn new() -> Self {
        Self {
            guest_base: AtomicU64::new(0),
            extent_base: AtomicU64::new(0),
            extent_len: AtomicU64::new(0),
            token: AtomicU64::new(0),
        }
    }
}

struct SegmentView<'a> {
    base_slot: usize,
    slots: &'a [FrameGrantResidencyRecord],
    dirty: &'a [AtomicU64],
}

#[cfg(not(target_os = "none"))]
type HostSegmentProvider =
    alloc::boxed::Box<dyn Fn(&FrameGrantResidencyTable, u32) -> bool + Send + Sync>;

#[cfg(not(target_os = "none"))]
struct HostTableSegments {
    provider_lock: AtomicU32,
    elastic_enabled: AtomicU32,
    provider: core::cell::UnsafeCell<Option<HostSegmentProvider>>,
    segments: [core::sync::atomic::AtomicPtr<FrameGrantResidencyOverflowSegment>;
        MAX_FRAME_GRANT_RESIDENCY_OVERFLOW_SEGMENTS],
    owned: [AtomicU32; MAX_FRAME_GRANT_RESIDENCY_OVERFLOW_SEGMENTS],
}

#[cfg(not(target_os = "none"))]
// SAFETY: `segments` and `owned` are atomic; `provider` is accessed only under `provider_lock`.
unsafe impl Sync for HostTableSegments {}
#[cfg(not(target_os = "none"))]
unsafe impl Send for HostTableSegments {}

#[cfg(not(target_os = "none"))]
impl HostTableSegments {
    fn new() -> Self {
        Self {
            provider_lock: AtomicU32::new(0),
            elastic_enabled: AtomicU32::new(1),
            provider: core::cell::UnsafeCell::new(None),
            segments: [const { core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()) };
                MAX_FRAME_GRANT_RESIDENCY_OVERFLOW_SEGMENTS],
            owned: [const { AtomicU32::new(0) }; MAX_FRAME_GRANT_RESIDENCY_OVERFLOW_SEGMENTS],
        }
    }

    fn find(table: &FrameGrantResidencyTable) -> Option<&Self> {
        let raw = table.host_state.load(Ordering::Acquire) as usize as *const Self;
        if raw.is_null() {
            None
        } else {
            // SAFETY: `host_state` lives in supervisor-only memory, is published
            // once via `Box::into_raw` in `get_or_insert`, and is reclaimed only
            // under `&mut self` in `Drop`.
            Some(unsafe { &*raw })
        }
    }

    fn get_or_insert(table: &FrameGrantResidencyTable) -> Option<&Self> {
        if let Some(existing) = Self::find(table) {
            return Some(existing);
        }
        let raw = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(Self::new()));
        match table.host_state.compare_exchange(
            0,
            raw.addr() as u64,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Some(unsafe { &*raw }),
            Err(actual) => {
                // SAFETY: `raw` lost the CAS and was never published.
                unsafe { drop(alloc::boxed::Box::from_raw(raw)) };
                let ptr = actual as usize as *const Self;
                (!ptr.is_null()).then(|| unsafe { &*ptr })
            }
        }
    }
}

/// Shared open-addressed residency index with an inline 4,096-slot primary
/// segment and up to 63 on-demand 2,048-slot overflow segments. Grants hash by
/// their smallest power-of-two page-count bucket. A page in a grant lies in
/// its base bucket or the next bucket, so lookups check those two buckets for
/// each size class in each active segment.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct FrameGrantResidencyTable {
    slots: [FrameGrantResidencyRecord; FRAME_GRANT_RESIDENCY_SLOTS],
    dirty: [AtomicU64; FRAME_GRANT_RESIDENCY_SLOTS / 64],
    publishing: AtomicU32,
    overflow_count: AtomicU32,
    host_state: AtomicU64,
    _header_reserved: [u64; 6],
    overflow: [ResidencyOverflowDescriptor; MAX_FRAME_GRANT_RESIDENCY_OVERFLOW_SEGMENTS],
    _tail_reserved: [u64; 4],
}

impl FrameGrantResidencyTable {
    const fn initial_slot() -> FrameGrantResidencyRecord {
        FrameGrantResidencyRecord::new()
    }

    const fn initial_dirty() -> AtomicU64 {
        AtomicU64::new(0)
    }

    pub const fn new() -> Self {
        Self {
            slots: [const { Self::initial_slot() }; FRAME_GRANT_RESIDENCY_SLOTS],
            dirty: [const { Self::initial_dirty() }; FRAME_GRANT_RESIDENCY_SLOTS / 64],
            publishing: AtomicU32::new(0),
            overflow_count: AtomicU32::new(0),
            host_state: AtomicU64::new(0),
            _header_reserved: [0; 6],
            overflow: [const { ResidencyOverflowDescriptor::new() };
                MAX_FRAME_GRANT_RESIDENCY_OVERFLOW_SEGMENTS],
            _tail_reserved: [0; 4],
        }
    }

    /// Initialize in place without materializing a large stack temporary.
    ///
    /// # Safety
    /// `ptr` must be valid for writes, non-null, aligned to `align_of::<Self>()`,
    /// and point to storage of at least `size_of::<Self>()` bytes.
    pub unsafe fn init_in_place(ptr: *mut Self) {
        // SAFETY: caller guarantees aligned, writable storage for the table.
        // Each record constructor initializes its complete wire image; no
        // reference to partially initialized storage is formed.
        unsafe {
            let slots = core::ptr::addr_of_mut!((*ptr).slots).cast::<FrameGrantResidencyRecord>();
            for index in 0..FRAME_GRANT_RESIDENCY_SLOTS {
                slots.add(index).write(Self::initial_slot());
            }
            let dirty = core::ptr::addr_of_mut!((*ptr).dirty).cast::<AtomicU64>();
            for index in 0..FRAME_GRANT_RESIDENCY_SLOTS / 64 {
                dirty.add(index).write(Self::initial_dirty());
            }
            core::ptr::addr_of_mut!((*ptr).publishing).write(AtomicU32::new(0));
            core::ptr::addr_of_mut!((*ptr).overflow_count).write(AtomicU32::new(0));
            core::ptr::addr_of_mut!((*ptr).host_state).write(AtomicU64::new(0));
            core::ptr::addr_of_mut!((*ptr)._header_reserved).write([0; 6]);
            let overflow =
                core::ptr::addr_of_mut!((*ptr).overflow).cast::<ResidencyOverflowDescriptor>();
            for index in 0..MAX_FRAME_GRANT_RESIDENCY_OVERFLOW_SEGMENTS {
                overflow
                    .add(index)
                    .write(ResidencyOverflowDescriptor::new());
            }
            core::ptr::addr_of_mut!((*ptr)._tail_reserved).write([0; 4]);
        }
    }

    pub fn overflow_segment_count(&self) -> u32 {
        self.overflow_count
            .load(Ordering::Acquire)
            .min(MAX_FRAME_GRANT_RESIDENCY_OVERFLOW_SEGMENTS as u32)
    }

    pub fn slot_capacity(&self) -> usize {
        FRAME_GRANT_RESIDENCY_SLOTS
            + (self.overflow_segment_count() as usize) * FRAME_GRANT_RESIDENCY_OVERFLOW_SLOTS
    }

    fn segment_view(&self, segment: usize) -> Option<SegmentView<'_>> {
        if segment == 0 {
            return Some(SegmentView {
                base_slot: 0,
                slots: &self.slots,
                dirty: &self.dirty,
            });
        }
        let overflow_idx = segment - 1;
        if overflow_idx >= self.overflow_segment_count() as usize {
            return None;
        }
        let base_slot =
            FRAME_GRANT_RESIDENCY_SLOTS + overflow_idx * FRAME_GRANT_RESIDENCY_OVERFLOW_SLOTS;
        #[cfg(target_os = "none")]
        {
            let desc = &self.overflow[overflow_idx];
            let guest_base = desc.guest_base.load(Ordering::Relaxed);
            let extent = crate::MetadataExtent::new(
                desc.extent_base.load(Ordering::Relaxed),
                desc.extent_len.load(Ordering::Relaxed),
                desc.token.load(Ordering::Relaxed),
            )?;
            if guest_base == 0
                || !guest_base.is_multiple_of(core::mem::align_of::<
                    FrameGrantResidencyOverflowSegment,
                >() as u64)
                || !extent.contains(
                    guest_base,
                    core::mem::size_of::<FrameGrantResidencyOverflowSegment>() as u64,
                )
            {
                return None;
            }
            // SAFETY: on `target_os = "none"`, the host carrier mapped this
            // kernel-only metadata extent before publishing `overflow_count`
            // with Release ordering, and retains it for the carrier lifetime.
            let seg = unsafe { &*(guest_base as *const FrameGrantResidencyOverflowSegment) };
            Some(SegmentView {
                base_slot,
                slots: &seg.slots,
                dirty: &seg.dirty,
            })
        }
        #[cfg(not(target_os = "none"))]
        {
            let host = HostTableSegments::find(self)?;
            let ptr = host.segments.get(overflow_idx)?.load(Ordering::Acquire);
            if ptr.is_null() {
                return None;
            }
            // SAFETY: `ptr` comes exclusively from host-owned memory (never
            // guest-writable ABI words) and remains valid for `&self`'s lifetime.
            let seg = unsafe { &*ptr };
            Some(SegmentView {
                base_slot,
                slots: &seg.slots,
                dirty: &seg.dirty,
            })
        }
    }

    fn slot_parts(&self, slot: usize) -> Option<(&FrameGrantResidencyRecord, &AtomicU64, usize)> {
        if slot < FRAME_GRANT_RESIDENCY_SLOTS {
            return Some((&self.slots[slot], &self.dirty[slot / 64], slot % 64));
        }
        let rem = slot - FRAME_GRANT_RESIDENCY_SLOTS;
        let overflow_idx = rem / FRAME_GRANT_RESIDENCY_OVERFLOW_SLOTS;
        let local = rem % FRAME_GRANT_RESIDENCY_OVERFLOW_SLOTS;
        let view = self.segment_view(1 + overflow_idx)?;
        Some((
            view.slots.get(local)?,
            view.dirty.get(local / 64)?,
            local % 64,
        ))
    }

    fn first_slot_in_segment(
        mm_key: u64,
        bucket: u64,
        class: u32,
        segment: usize,
        segment_slots: usize,
    ) -> usize {
        let salt = (segment as u64).wrapping_mul(0xd6e8_feb8_6659_fd93);
        let mixed = mm_key.wrapping_mul(0x9e37_79b9_7f4a_7c15)
            ^ bucket.wrapping_mul(0xbf58_476d_1ce4_e5b9)
            ^ u64::from(class).wrapping_mul(0x94d0_49bb_1331_11eb)
            ^ salt;
        (mixed as usize) & (segment_slots - 1)
    }

    fn probe_in_segment(
        mm_key: u64,
        bucket: u64,
        class: u32,
        segment: usize,
        segment_slots: usize,
        offset: usize,
    ) -> usize {
        (Self::first_slot_in_segment(mm_key, bucket, class, segment, segment_slots) + offset)
            & (segment_slots - 1)
    }

    /// True if currently published segments hold at least `min_slots` empty or
    /// retired slots in the bounded probe chain for `(mm_key, semantic_base, len)`.
    pub fn has_probe_headroom(
        &self,
        mm_key: u64,
        semantic_base: u64,
        len: u64,
        min_slots: usize,
    ) -> bool {
        if min_slots == 0 {
            return true;
        }
        if mm_key == 0
            || len == 0
            || len > EL1_FRAME_GRANT_TARGET_SIZE
            || !semantic_base.is_multiple_of(GRANT_PAGE_SIZE)
            || !len.is_multiple_of(GRANT_PAGE_SIZE)
        {
            return false;
        }
        let class = (len / GRANT_PAGE_SIZE).next_power_of_two().trailing_zeros();
        let bucket = semantic_base / (GRANT_PAGE_SIZE << class);
        let total_segments = 1 + self.overflow_segment_count() as usize;
        let mut available = 0usize;
        for segment in 0..total_segments {
            let Some(view) = self.segment_view(segment) else {
                continue;
            };
            let segment_slots = view.slots.len();
            for probe in 0..GRANT_PROBES {
                let local =
                    Self::probe_in_segment(mm_key, bucket, class, segment, segment_slots, probe);
                let state = view.slots[local].state.load(Ordering::Acquire);
                if state == GRANT_EMPTY || state & GRANT_STATE_MASK == GRANT_RETIRED {
                    available += 1;
                    if available >= min_slots {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// True if at least one currently published segment has an empty or retired
    /// slot in the bounded probe chain for `(mm_key, semantic_base, len)`.
    pub fn has_probe_slot(&self, mm_key: u64, semantic_base: u64, len: u64) -> bool {
        self.has_probe_headroom(mm_key, semantic_base, len, 1)
    }

    /// Register a carrier-specific segment allocator once on the host. When set,
    /// `provision_overflow_segment` maps shared guest+host metadata extents via
    /// this carrier callback instead of unmapped host heap memory.
    #[cfg(not(target_os = "none"))]
    pub fn register_host_segment_provider_if_unset(&self, provider: HostSegmentProvider) {
        let Some(host) = HostTableSegments::get_or_insert(self) else {
            return;
        };
        while host
            .provider_lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // SAFETY: `provider_lock` serializes all access to `host.provider`.
        unsafe {
            let slot = &mut *host.provider.get();
            if slot.is_none() {
                *slot = Some(provider);
            }
        }
        host.provider_lock.store(0, Ordering::Release);
    }

    /// Enable or withhold host-driven segment growth (used by capacity-refusal
    /// unit witnesses to observe `DescriptorRefusal::ResidencyCapacity` before
    /// explicitly provisioning the next segment).
    #[cfg(not(target_os = "none"))]
    pub fn set_elastic_growth_enabled(&self, enabled: bool) {
        if let Some(host) = HostTableSegments::get_or_insert(self) {
            host.elastic_enabled
                .store(u32::from(enabled), Ordering::Release);
        }
    }

    /// Install a carrier-retained shared overflow segment at `expected_overflow_count`.
    ///
    /// # Safety
    /// `host_ptr` must point to valid, writable, 64-byte-aligned storage of at
    /// least `size_of::<FrameGrantResidencyOverflowSegment>()` bytes that
    /// outlives `self` and every `FrameGrantTransferPin` borrowed from `self`,
    /// mapped into the guest kernel metadata aperture at `guest_base` within `extent`.
    #[cfg(not(target_os = "none"))]
    pub unsafe fn install_external_overflow_segment(
        &self,
        host_ptr: core::ptr::NonNull<FrameGrantResidencyOverflowSegment>,
        guest_base: u64,
        extent: crate::MetadataExtent,
        expected_overflow_count: u32,
    ) -> Result<u32, ResidencySegmentInstallError> {
        unsafe {
            self.install_overflow_segment_inner(
                host_ptr,
                guest_base,
                extent,
                expected_overflow_count,
                false,
            )
        }
    }

    #[cfg(not(target_os = "none"))]
    unsafe fn install_overflow_segment_inner(
        &self,
        host_ptr: core::ptr::NonNull<FrameGrantResidencyOverflowSegment>,
        guest_base: u64,
        extent: crate::MetadataExtent,
        expected_overflow_count: u32,
        owned_by_table: bool,
    ) -> Result<u32, ResidencySegmentInstallError> {
        let seg_bytes = core::mem::size_of::<FrameGrantResidencyOverflowSegment>() as u64;
        let seg_align = core::mem::align_of::<FrameGrantResidencyOverflowSegment>();
        if guest_base == 0
            || !guest_base.is_multiple_of(seg_align as u64)
            || !host_ptr.as_ptr().addr().is_multiple_of(seg_align)
            || !extent.contains(guest_base, seg_bytes)
        {
            return Err(ResidencySegmentInstallError::InvalidExtent);
        }
        let Some(host) = HostTableSegments::get_or_insert(self) else {
            return Err(ResidencySegmentInstallError::Exhausted);
        };
        if self.overflow_segment_count() > expected_overflow_count {
            return Err(ResidencySegmentInstallError::AlreadyGrown);
        }
        if (expected_overflow_count as usize) >= MAX_FRAME_GRANT_RESIDENCY_OVERFLOW_SEGMENTS {
            return Err(ResidencySegmentInstallError::Exhausted);
        }
        // SAFETY: caller owns `host_ptr` exclusively prior to publication.
        unsafe { FrameGrantResidencyOverflowSegment::init_in_place(host_ptr.as_ptr()) };

        while self
            .publishing
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        let current = self.overflow_count.load(Ordering::Relaxed);
        if current != expected_overflow_count {
            self.publishing.store(0, Ordering::Release);
            return Err(ResidencySegmentInstallError::AlreadyGrown);
        }
        let idx = current as usize;
        if idx >= MAX_FRAME_GRANT_RESIDENCY_OVERFLOW_SEGMENTS {
            self.publishing.store(0, Ordering::Release);
            return Err(ResidencySegmentInstallError::Exhausted);
        }
        host.owned[idx].store(u32::from(owned_by_table), Ordering::Relaxed);
        host.segments[idx].store(host_ptr.as_ptr(), Ordering::Release);
        let desc = &self.overflow[idx];
        desc.guest_base.store(guest_base, Ordering::Relaxed);
        desc.extent_base.store(extent.base(), Ordering::Relaxed);
        desc.extent_len.store(extent.len(), Ordering::Relaxed);
        desc.token.store(extent.token(), Ordering::Relaxed);
        self.overflow_count.store(current + 1, Ordering::Release);
        self.publishing.store(0, Ordering::Release);
        Ok(current + 1)
    }

    /// Provision one overflow segment when `overflow_segment_count() == expected_overflow_count`.
    /// Uses the carrier's registered shared-aperture provider when attached, or
    /// fallible host allocation in VM-free / host-only configurations.
    #[cfg(not(target_os = "none"))]
    pub fn provision_overflow_segment(&self, expected_overflow_count: u32) -> bool {
        if self.overflow_segment_count() > expected_overflow_count {
            return true;
        }
        if (expected_overflow_count as usize) >= MAX_FRAME_GRANT_RESIDENCY_OVERFLOW_SEGMENTS {
            return false;
        }
        let Some(host) = HostTableSegments::get_or_insert(self) else {
            return false;
        };
        while host
            .provider_lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        let result = if self.overflow_segment_count() > expected_overflow_count {
            true
        } else {
            // SAFETY: `provider_lock` is held exclusively here.
            let provider = unsafe { (*host.provider.get()).as_ref() };
            if let Some(provide) = provider {
                provide(self, expected_overflow_count)
            } else {
                self.provision_host_only_segment(expected_overflow_count)
            }
        };
        host.provider_lock.store(0, Ordering::Release);
        result
    }

    #[cfg(not(target_os = "none"))]
    fn provision_host_only_segment(&self, expected_overflow_count: u32) -> bool {
        let layout = core::alloc::Layout::new::<FrameGrantResidencyOverflowSegment>();
        // SAFETY: layout has nonzero size (`393,472` bytes) and 64-byte alignment;
        // null return is handled fallibly without aborting.
        let raw = unsafe { alloc::alloc::alloc_zeroed(layout) }
            .cast::<FrameGrantResidencyOverflowSegment>();
        let Some(ptr) = core::ptr::NonNull::new(raw) else {
            return false;
        };
        let addr = ptr.as_ptr().addr() as u64;
        let Some(extent) = crate::MetadataExtent::new(
            addr,
            layout.size() as u64,
            u64::from(expected_overflow_count) + 1,
        ) else {
            unsafe { alloc::alloc::dealloc(ptr.as_ptr().cast(), layout) };
            return false;
        };
        // SAFETY: freshly allocated zeroed host segment owned by `HostTableSegments`
        // until `Self::drop` reclaims it.
        let installed = unsafe {
            self.install_overflow_segment_inner(ptr, addr, extent, expected_overflow_count, true)
        };
        if installed.is_err() {
            unsafe { alloc::alloc::dealloc(ptr.as_ptr().cast(), layout) };
            return self.overflow_segment_count() > expected_overflow_count;
        }
        true
    }

    /// Ensure at least one probe slot exists for `(mm_key, semantic_base, len)`
    /// before entering an exact-MM editor, growing on demand when enabled.
    #[cfg(not(target_os = "none"))]
    pub fn ensure_capacity_for(&self, mm_key: u64, semantic_base: u64, len: u64) -> bool {
        const PREFLIGHT_HEADROOM: usize = 4;
        if self.has_probe_headroom(mm_key, semantic_base, len, PREFLIGHT_HEADROOM) {
            return true;
        }
        if let Some(host) = HostTableSegments::find(self)
            && host.elastic_enabled.load(Ordering::Acquire) == 0
        {
            return self.has_probe_slot(mm_key, semantic_base, len);
        }
        while !self.has_probe_headroom(mm_key, semantic_base, len, PREFLIGHT_HEADROOM) {
            let current = self.overflow_segment_count();
            if current as usize >= MAX_FRAME_GRANT_RESIDENCY_OVERFLOW_SEGMENTS
                || !self.provision_overflow_segment(current)
            {
                return self.has_probe_slot(mm_key, semantic_base, len);
            }
        }
        true
    }

    /// Publish an authenticated grant while the exact-MM mutation guard
    /// excludes a guest editor, returning the typed refusal reason on failure.
    pub fn try_publish(
        &self,
        identity: FrameGrantResidencyIdentity,
    ) -> Result<usize, ResidencyPublishError> {
        if !identity.valid() {
            return Err(ResidencyPublishError::Invalid);
        }
        // All size classes and segments share one logical index. Check every
        // covered page before admission so unlike classes or segments cannot
        // publish overlapping grants. Exact-MM editors serialize publications
        // for this MM.
        for page in (identity.semantic_base..identity.semantic_base + identity.len)
            .step_by(GRANT_PAGE_SIZE as usize)
        {
            if self.lookup(identity.mm_key, page).is_some() {
                return Err(ResidencyPublishError::Overlap);
            }
        }
        let class = (identity.len / GRANT_PAGE_SIZE)
            .next_power_of_two()
            .trailing_zeros();
        let bucket = identity.semantic_base / (GRANT_PAGE_SIZE << class);
        let total_segments = 1 + self.overflow_segment_count() as usize;
        let mut available: Option<(usize, &FrameGrantResidencyRecord)> = None;

        for segment in 0..total_segments {
            let Some(view) = self.segment_view(segment) else {
                continue;
            };
            let segment_slots = view.slots.len();
            for probe in 0..GRANT_PROBES {
                let local = Self::probe_in_segment(
                    identity.mm_key,
                    bucket,
                    class,
                    segment,
                    segment_slots,
                    probe,
                );
                let global_slot = view.base_slot + local;
                let record = &view.slots[local];
                let state = record.state.load(Ordering::Acquire);
                if state & GRANT_STATE_MASK == GRANT_LIVE {
                    let prior = record.identity();
                    if prior.mm_key == identity.mm_key
                        && prior.semantic_base < identity.semantic_base + identity.len
                        && identity.semantic_base < prior.semantic_base + prior.len
                    {
                        return Err(ResidencyPublishError::Overlap);
                    }
                } else if state == GRANT_EMPTY {
                    if available.is_none() {
                        available = Some((global_slot, record));
                    }
                    break;
                } else if state & GRANT_STATE_MASK == GRANT_RETIRED && available.is_none() {
                    available = Some((global_slot, record));
                }
            }
            if available.is_some() {
                break;
            }
        }

        let Some((slot, record)) = available else {
            return Err(ResidencyPublishError::Capacity);
        };
        let state = record.state.load(Ordering::Acquire);
        if state & GRANT_STATE_MASK == GRANT_LIVE
            || state & GRANT_STATE_MASK == GRANT_WRITING
            || record
                .state
                .compare_exchange(
                    state,
                    (state & !GRANT_STATE_MASK).wrapping_add(4) | GRANT_WRITING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            return Err(ResidencyPublishError::Capacity);
        }
        record.publish(identity);
        Ok(slot)
    }

    /// Host: publish an authenticated grant while the exact-MM mutation guard
    /// excludes a guest editor. Failure leaves ordinary host first touch live.
    pub fn publish(&self, identity: FrameGrantResidencyIdentity) -> Option<usize> {
        self.try_publish(identity).ok()
    }

    /// Diagnostic sample of occupied slots across all active segments, including
    /// in-flight publishers. Other MMs can change the table during the scan.
    pub fn observed_slots_used(&self) -> usize {
        let total_segments = 1 + self.overflow_segment_count() as usize;
        let mut count = 0;
        for segment in 0..total_segments {
            let Some(view) = self.segment_view(segment) else {
                continue;
            };
            count += view
                .slots
                .iter()
                .filter(|record| {
                    matches!(
                        record.state.load(Ordering::Relaxed) & GRANT_STATE_MASK,
                        GRANT_WRITING | GRANT_LIVE
                    )
                })
                .count();
        }
        count
    }

    /// Guest: find the exact live grant covering a prepared leaf.
    pub fn lookup(&self, mm_key: u64, va: u64) -> Option<FrameGrantResidencyPage> {
        let page = va & !(GRANT_PAGE_SIZE - 1);
        let max_class = EL1_FRAME_GRANT_TARGET_SIZE
            .div_ceil(GRANT_PAGE_SIZE)
            .trailing_zeros();
        let total_segments = 1 + self.overflow_segment_count() as usize;
        for segment in 0..total_segments {
            let Some(view) = self.segment_view(segment) else {
                continue;
            };
            let segment_slots = view.slots.len();
            for class in 0..=max_class {
                let bucket = page / (GRANT_PAGE_SIZE << class);
                for candidate in [Some(bucket), (class > 0 && bucket > 0).then(|| bucket - 1)]
                    .into_iter()
                    .flatten()
                {
                    for probe in 0..GRANT_PROBES {
                        let local = Self::probe_in_segment(
                            mm_key,
                            candidate,
                            class,
                            segment,
                            segment_slots,
                            probe,
                        );
                        let record = &view.slots[local];
                        let epoch = record.state.load(Ordering::Acquire);
                        match epoch & GRANT_STATE_MASK {
                            GRANT_EMPTY => break,
                            GRANT_LIVE => {
                                let identity = record.identity();
                                if identity.mm_key == mm_key
                                    && page >= identity.semantic_base
                                    && page - identity.semantic_base < identity.len
                                    && record.state.load(Ordering::Acquire) == epoch
                                {
                                    let bit = ((page - identity.semantic_base) / GRANT_PAGE_SIZE)
                                        as usize;
                                    return Some(FrameGrantResidencyPage {
                                        slot: view.base_slot + local,
                                        identity,
                                        expected_ipa: identity.physical_ipa
                                            + bit as u64 * GRANT_PAGE_SIZE,
                                        epoch,
                                        bit,
                                    });
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        None
    }

    /// Retain an exact live residency generation independently of the MM
    /// editor. A racing retirement either closes admission first or observes
    /// this pin and refuses; stale page tokens cannot pin a successor.
    pub fn pin_transfer(&self, page: FrameGrantResidencyPage) -> Option<FrameGrantTransferPin<'_>> {
        let (record, _, _) = self.slot_parts(page.slot)?;
        if record.state.load(Ordering::Acquire) != page.epoch || record.identity() != page.identity
        {
            return None;
        }
        record
            .transfer_pins
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pins| {
                (pins < TRANSFER_PIN_RETIRED - 1).then_some(pins + 1)
            })
            .ok()?;
        let pin = FrameGrantTransferPin { record };
        if record.state.load(Ordering::Acquire) != page.epoch || record.identity() != page.identity
        {
            drop(pin);
            return None;
        }
        Some(pin)
    }

    /// Guest: record a committed VALID leaf before releasing the MM editor.
    pub fn record_commit(&self, page: FrameGrantResidencyPage) -> bool {
        let Some((record, dirty_word, dirty_bit)) = self.slot_parts(page.slot) else {
            return false;
        };
        if record.state.load(Ordering::Acquire) != page.epoch
            || record.identity() != page.identity
            || page.bit >= (page.identity.len / GRANT_PAGE_SIZE) as usize
            || page.expected_ipa != page.identity.physical_ipa + page.bit as u64 * GRANT_PAGE_SIZE
        {
            return false;
        }
        record.committed[page.bit / 64].fetch_or(1 << (page.bit % 64), Ordering::Release);
        dirty_word.fetch_or(1 << dirty_bit, Ordering::Release);
        true
    }

    /// Host mincore view. The slot must still be live for this exact MM and
    /// grant; retirement removes visibility before backing can be reused.
    pub fn is_guest_committed(&self, mm_key: u64, va: u64) -> bool {
        let Some(page) = self.lookup(mm_key, va) else {
            return false;
        };
        let Some((record, _, _)) = self.slot_parts(page.slot) else {
            return false;
        };
        record.state.load(Ordering::Acquire) == page.epoch
            && record.identity() == page.identity
            && record.committed[page.bit / 64].load(Ordering::Acquire) & (1 << (page.bit % 64)) != 0
            && record.state.load(Ordering::Acquire) == page.epoch
    }

    /// Host: visit only records changed since their last reconciliation. The
    /// callback must validate the live leaf and update host residency before
    /// `ack_dirty` is called; exact-MM exclusion prevents same-MM new bits.
    pub fn for_each_dirty_mm<B>(
        &self,
        mm_key: u64,
        mut visit: impl FnMut(usize, FrameGrantResidencyIdentity, [u64; 8]) -> core::ops::ControlFlow<B>,
    ) -> core::ops::ControlFlow<B> {
        let total_segments = 1 + self.overflow_segment_count() as usize;
        for segment in 0..total_segments {
            let Some(view) = self.segment_view(segment) else {
                continue;
            };
            for (word_index, word) in view.dirty.iter().enumerate() {
                let mut pending = word.load(Ordering::Acquire);
                while pending != 0 {
                    let bit = pending.trailing_zeros() as usize;
                    pending &= pending - 1;
                    let local = word_index * 64 + bit;
                    let record = &view.slots[local];
                    let epoch = record.state.load(Ordering::Acquire);
                    if epoch & GRANT_STATE_MASK == GRANT_LIVE {
                        let identity = record.identity();
                        if identity.mm_key == mm_key
                            && record.state.load(Ordering::Acquire) == epoch
                        {
                            let bits = core::array::from_fn(|i| {
                                record.committed[i].load(Ordering::Acquire)
                            });
                            if record.state.load(Ordering::Acquire) == epoch {
                                visit(view.base_slot + local, identity, bits)?;
                            }
                        }
                    }
                }
            }
        }
        core::ops::ControlFlow::Continue(())
    }

    pub fn ack_dirty(&self, slot: usize, identity: FrameGrantResidencyIdentity) -> bool {
        let Some((record, dirty_word, dirty_bit)) = self.slot_parts(slot) else {
            return false;
        };
        if record.state.load(Ordering::Acquire) & GRANT_STATE_MASK != GRANT_LIVE
            || record.identity() != identity
        {
            return false;
        }
        dirty_word.fetch_and(!(1 << dirty_bit), Ordering::AcqRel);
        true
    }

    /// Host: snapshot the guest commits while holding the exact-MM guard.
    pub fn committed_words(
        &self,
        slot: usize,
        identity: FrameGrantResidencyIdentity,
    ) -> Option<[u64; 8]> {
        let (record, _, _) = self.slot_parts(slot)?;
        let epoch = record.state.load(Ordering::Acquire);
        if epoch & GRANT_STATE_MASK != GRANT_LIVE || record.identity() != identity {
            return None;
        }
        let bits = core::array::from_fn(|i| record.committed[i].load(Ordering::Acquire));
        (record.state.load(Ordering::Acquire) == epoch).then_some(bits)
    }

    /// Host: retire this exact grant before unmapping or reusing its owner.
    pub fn retire(&self, slot: usize, identity: FrameGrantResidencyIdentity) -> bool {
        let Some((record, dirty_word, dirty_bit)) = self.slot_parts(slot) else {
            return false;
        };
        let epoch = record.state.load(Ordering::Acquire);
        if epoch & GRANT_STATE_MASK != GRANT_LIVE || record.identity() != identity {
            return false;
        }
        if record
            .transfer_pins
            .compare_exchange(0, TRANSFER_PIN_RETIRED, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        if record
            .state
            .compare_exchange(
                epoch,
                (epoch & !GRANT_STATE_MASK) | GRANT_RETIRED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            record.transfer_pins.store(0, Ordering::Release);
            return false;
        }
        dirty_word.fetch_and(!(1 << dirty_bit), Ordering::AcqRel);
        true
    }

    /// Host: visit `[base, end)` of every live grant of `mm_key` that
    /// overlaps `[start, start + len)`: backing already prepared for this
    /// exact MM, which no second grant may cover. One pass over the table.
    pub fn live_spans_overlapping(
        &self,
        mm_key: u64,
        start: u64,
        len: u64,
        mut visit: impl FnMut(u64, u64),
    ) {
        let end = start.saturating_add(len);
        let total_segments = 1 + self.overflow_segment_count() as usize;
        for segment in 0..total_segments {
            let Some(view) = self.segment_view(segment) else {
                continue;
            };
            for record in view.slots {
                let state = record.state.load(Ordering::Acquire);
                if state & GRANT_STATE_MASK != GRANT_LIVE {
                    continue;
                }
                let identity = record.identity();
                let grant_end = identity.semantic_base.saturating_add(identity.len);
                if identity.mm_key == mm_key
                    && identity.semantic_base < end
                    && start < grant_end
                    && record.state.load(Ordering::Acquire) == state
                {
                    visit(identity.semantic_base, grant_end);
                }
            }
        }
    }

    /// Revoke only replaced pages. Preserve the exact owner and committed
    /// bits of each outside fragment, under the caller's exact-MM editor.
    /// Republished fragments have fresh epochs: no captured pre-edit page
    /// token can authorize a replaced or recycled page. Index saturation
    /// declines fragment acceleration, as it does initial publication.
    /// Returns false if a grant-window lease prevents revocation. Earlier
    /// revocations remain valid; callers must not replace leaves on refusal.
    pub fn retire_overlapping(&self, mm_key: u64, start: u64, len: u64) -> bool {
        let end = start.saturating_add(len);
        if start >= end {
            return true;
        }
        let total_segments = 1 + self.overflow_segment_count() as usize;
        for segment in 0..total_segments {
            let Some(view) = self.segment_view(segment) else {
                continue;
            };
            for (local, record) in view.slots.iter().enumerate() {
                if record.state.load(Ordering::Acquire) & GRANT_STATE_MASK != GRANT_LIVE {
                    continue;
                }
                let identity = record.identity();
                if identity.mm_key == mm_key
                    && identity.semantic_base < end
                    && start < identity.semantic_base.saturating_add(identity.len)
                    && !self.retire_fragment(view.base_slot + local, identity, start, end)
                {
                    return false;
                }
            }
        }
        true
    }

    /// Close transfer admission for every live row the descriptor retirement
    /// will replace. No row or committed bit changes until [`commit`](FrameGrantResidencyRetirement::commit),
    /// and dropping the token restores the exact preclaim state.
    pub fn begin_retire_overlapping(
        &self,
        mm_key: u64,
        start: u64,
        len: u64,
    ) -> Option<FrameGrantResidencyRetirement<'_>> {
        let end = start.checked_add(len)?;
        if mm_key == 0 || start >= end {
            return None;
        }
        let total_segments = 1 + self.overflow_segment_count() as usize;
        for segment in 0..total_segments {
            let Some(view) = self.segment_view(segment) else {
                continue;
            };
            for record in view.slots {
                let state = record.state.load(Ordering::Acquire);
                if state & GRANT_STATE_MASK != GRANT_LIVE {
                    continue;
                }
                let identity = record.identity();
                if identity.mm_key != mm_key
                    || identity.semantic_base >= end
                    || start >= identity.semantic_base.saturating_add(identity.len)
                    || record.state.load(Ordering::Acquire) != state
                {
                    continue;
                }
                if record
                    .transfer_pins
                    .compare_exchange(
                        0,
                        TRANSFER_PIN_RETIRING,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_err()
                {
                    self.cancel_retirement(mm_key, start, end);
                    return None;
                }
                if record.state.load(Ordering::Acquire) != state || record.identity() != identity {
                    record.transfer_pins.store(0, Ordering::Release);
                    self.cancel_retirement(mm_key, start, end);
                    return None;
                }
            }
        }
        Some(FrameGrantResidencyRetirement {
            table: self,
            mm_key,
            start,
            end,
            active: true,
        })
    }

    fn cancel_retirement(&self, mm_key: u64, start: u64, end: u64) {
        let total_segments = 1 + self.overflow_segment_count() as usize;
        for segment in 0..total_segments {
            let Some(view) = self.segment_view(segment) else {
                continue;
            };
            for record in view.slots {
                let state = record.state.load(Ordering::Acquire);
                if state & GRANT_STATE_MASK != GRANT_LIVE {
                    continue;
                }
                let identity = record.identity();
                if identity.mm_key == mm_key
                    && identity.semantic_base < end
                    && start < identity.semantic_base.saturating_add(identity.len)
                    && record.state.load(Ordering::Acquire) == state
                {
                    let _ = record.transfer_pins.compare_exchange(
                        TRANSFER_PIN_RETIRING,
                        0,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                }
            }
        }
    }

    fn commit_retirement(&self, mm_key: u64, start: u64, end: u64) -> bool {
        let total_segments = 1 + self.overflow_segment_count() as usize;
        for segment in 0..total_segments {
            let Some(view) = self.segment_view(segment) else {
                continue;
            };
            for (local, record) in view.slots.iter().enumerate() {
                let state = record.state.load(Ordering::Acquire);
                if state & GRANT_STATE_MASK != GRANT_LIVE {
                    continue;
                }
                let identity = record.identity();
                if identity.mm_key == mm_key
                    && identity.semantic_base < end
                    && start < identity.semantic_base.saturating_add(identity.len)
                    && !self.retire_claimed_fragment(view.base_slot + local, identity, start, end)
                {
                    return false;
                }
            }
        }
        true
    }
    /// Revoke a small page-aligned span using bounded grant lookups instead
    /// of scanning the carrier's index. Intended for one COW compound.
    /// The exact-MM editor excludes concurrent leaf/publication changes.
    pub fn retire_small_span(&self, mm_key: u64, start: u64, len: u64) -> bool {
        if !start.is_multiple_of(GRANT_PAGE_SIZE)
            || !len.is_multiple_of(GRANT_PAGE_SIZE)
            || len > crate::COW_GRANT_SIZE
        {
            return false;
        }
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        for page in (start..end).step_by(GRANT_PAGE_SIZE as usize) {
            if let Some(found) = self.lookup(mm_key, page)
                && !self.retire_fragment(found.slot, found.identity, start, end)
            {
                return false;
            }
        }
        true
    }

    fn retire_fragment(
        &self,
        slot: usize,
        identity: FrameGrantResidencyIdentity,
        start: u64,
        end: u64,
    ) -> bool {
        let Some(bits) = self.committed_words(slot, identity) else {
            return false;
        };
        if !self.retire(slot, identity) {
            return false;
        }
        self.publish_retirement_fragments(identity, bits, start, end);
        true
    }

    fn retire_claimed_fragment(
        &self,
        slot: usize,
        identity: FrameGrantResidencyIdentity,
        start: u64,
        end: u64,
    ) -> bool {
        let Some((record, dirty_word, dirty_bit)) = self.slot_parts(slot) else {
            return false;
        };
        let state = record.state.load(Ordering::Acquire);
        if state & GRANT_STATE_MASK != GRANT_LIVE
            || record.identity() != identity
            || record.transfer_pins.load(Ordering::Acquire) != TRANSFER_PIN_RETIRING
        {
            return false;
        }
        let bits = core::array::from_fn(|index| record.committed[index].load(Ordering::Acquire));
        if record
            .state
            .compare_exchange(
                state,
                (state & !GRANT_STATE_MASK) | GRANT_RETIRED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        dirty_word.fetch_and(!(1 << dirty_bit), Ordering::AcqRel);
        self.publish_retirement_fragments(identity, bits, start, end);
        true
    }

    fn publish_retirement_fragments(
        &self,
        identity: FrameGrantResidencyIdentity,
        bits: [u64; 8],
        start: u64,
        end: u64,
    ) {
        let base = identity.semantic_base;
        let grant_end = base + identity.len;
        let cut_start = start & !(GRANT_PAGE_SIZE - 1);
        let cut_end = end.saturating_add(GRANT_PAGE_SIZE - 1) & !(GRANT_PAGE_SIZE - 1);
        for (fragment_start, fragment_end) in [
            (base, cut_start.min(grant_end)),
            (cut_end.max(base), grant_end),
        ] {
            if fragment_start >= fragment_end {
                continue;
            }
            let fragment = FrameGrantResidencyIdentity {
                semantic_base: fragment_start,
                physical_ipa: identity.physical_ipa + fragment_start - base,
                len: fragment_end - fragment_start,
                ..identity
            };
            #[cfg(not(target_os = "none"))]
            let _ = self.ensure_capacity_for(fragment.mm_key, fragment.semantic_base, fragment.len);
            if let Some(fragment_slot) = self.publish(fragment)
                && let Some((record, dirty_word, dirty_bit)) = self.slot_parts(fragment_slot)
            {
                let shift = ((fragment_start - base) / GRANT_PAGE_SIZE) as usize;
                let count = (fragment.len / GRANT_PAGE_SIZE) as usize;
                for bit in 0..count {
                    let old_bit = shift + bit;
                    if bits[old_bit / 64] & (1 << (old_bit % 64)) != 0 {
                        record.committed[bit / 64].fetch_or(1 << (bit % 64), Ordering::Release);
                        dirty_word.fetch_or(1 << dirty_bit, Ordering::Release);
                    }
                }
            }
        }
    }
}

#[cfg(not(target_os = "none"))]
impl Drop for FrameGrantResidencyTable {
    fn drop(&mut self) {
        let raw = self.host_state.swap(0, Ordering::AcqRel) as usize as *mut HostTableSegments;
        if raw.is_null() {
            return;
        }
        // SAFETY: `&mut self` guarantees exclusive ownership of `host_state`.
        let host = unsafe { alloc::boxed::Box::from_raw(raw) };
        let layout = core::alloc::Layout::new::<FrameGrantResidencyOverflowSegment>();
        for idx in 0..MAX_FRAME_GRANT_RESIDENCY_OVERFLOW_SEGMENTS {
            let ptr = host.segments[idx].swap(core::ptr::null_mut(), Ordering::AcqRel);
            if !ptr.is_null() && host.owned[idx].swap(0, Ordering::AcqRel) != 0 {
                // SAFETY: `owned != 0` marks segments allocated by
                // `provision_host_only_segment` with `layout`, and `&mut self`
                // guarantees all `FrameGrantTransferPin` borrows have ended.
                unsafe { alloc::alloc::dealloc(ptr.cast(), layout) };
            }
        }
    }
}

impl Default for FrameGrantResidencyTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn table() -> std::boxed::Box<FrameGrantResidencyTable> {
        let layout = std::alloc::Layout::new::<FrameGrantResidencyTable>();
        // SAFETY: allocation uses the table layout and is initialized before
        // the owning Box is constructed.
        unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<FrameGrantResidencyTable>();
            assert!(!ptr.is_null());
            FrameGrantResidencyTable::init_in_place(ptr);
            std::boxed::Box::from_raw(ptr)
        }
    }

    fn identity() -> FrameGrantResidencyIdentity {
        FrameGrantResidencyIdentity {
            mm_key: 7,
            semantic_base: 0x10_0000,
            physical_ipa: 0x20_0000,
            len: 16 * GRANT_PAGE_SIZE,
            mapping_id: 11,
            frame_id: 12,
            owner_generation: 13,
            inventory_revision: 14,
        }
    }

    #[test]
    fn retirement_preclaim_refuses_pins_and_rolls_back_or_commits_whole() {
        let table = table();
        let identity = identity();
        assert!(table.publish(identity).is_some());
        let page = table
            .lookup(
                identity.mm_key,
                identity.semantic_base + 2 * GRANT_PAGE_SIZE,
            )
            .unwrap();
        let pin = table.pin_transfer(page).unwrap();
        assert!(
            table
                .begin_retire_overlapping(
                    identity.mm_key,
                    identity.semantic_base + GRANT_PAGE_SIZE,
                    2 * GRANT_PAGE_SIZE,
                )
                .is_none(),
            "a live transfer must refuse before descriptor retirement"
        );
        drop(pin);

        let retirement = table
            .begin_retire_overlapping(
                identity.mm_key,
                identity.semantic_base + GRANT_PAGE_SIZE,
                2 * GRANT_PAGE_SIZE,
            )
            .unwrap();
        assert!(
            table.pin_transfer(page).is_none(),
            "preclaim closes admission"
        );
        drop(retirement);
        assert!(
            table.pin_transfer(page).is_some(),
            "dropping an uncommitted claim restores the row"
        );

        let retirement = table
            .begin_retire_overlapping(
                identity.mm_key,
                identity.semantic_base + GRANT_PAGE_SIZE,
                2 * GRANT_PAGE_SIZE,
            )
            .unwrap();
        assert!(retirement.commit());
        assert!(
            table
                .lookup(identity.mm_key, identity.semantic_base)
                .is_some(),
            "prefix survives"
        );
        assert!(
            table
                .lookup(identity.mm_key, identity.semantic_base + GRANT_PAGE_SIZE)
                .is_none(),
            "replaced pages are revoked"
        );
        assert!(
            table
                .lookup(
                    identity.mm_key,
                    identity.semantic_base + 3 * GRANT_PAGE_SIZE
                )
                .is_some(),
            "suffix survives"
        );
    }

    #[test]
    fn overflow_segments_preserve_dirty_commit_pin_and_retirement_invariants() {
        let table = table();
        let count = FRAME_GRANT_RESIDENCY_SLOTS + FRAME_GRANT_RESIDENCY_OVERFLOW_SLOTS + 64;
        for index in 0..count {
            let va = 0x4000_0000 + index as u64 * GRANT_PAGE_SIZE;
            let row = FrameGrantResidencyIdentity {
                mm_key: 9,
                semantic_base: va,
                physical_ipa: 0x8000_0000 + index as u64 * GRANT_PAGE_SIZE,
                len: GRANT_PAGE_SIZE,
                mapping_id: index as u64 + 1,
                frame_id: index as u64 + 1,
                owner_generation: 1,
                inventory_revision: 1,
            };
            assert!(table.ensure_capacity_for(row.mm_key, row.semantic_base, row.len));
            let slot = table.try_publish(row).expect("elastic residency slot");
            let page = table.lookup(9, va).expect("lookup across segments");
            assert_eq!(page.slot, slot);
            assert!(table.record_commit(page));
            assert!(table.is_guest_committed(9, va));
        }
        assert!(table.overflow_segment_count() >= 2);
        let mut dirty_seen = 0usize;
        let _ = table.for_each_dirty_mm::<()>(9, |slot, row, _| {
            dirty_seen += 1;
            assert!(table.ack_dirty(slot, row));
            core::ops::ControlFlow::Continue(())
        });
        assert_eq!(dirty_seen, count);

        let tail_va = 0x4000_0000 + (count as u64 - 1) * GRANT_PAGE_SIZE;
        let tail_page = table.lookup(9, tail_va).unwrap();
        let pin = table.pin_transfer(tail_page).unwrap();
        assert!(
            table
                .begin_retire_overlapping(9, tail_va, GRANT_PAGE_SIZE)
                .is_none()
        );
        drop(pin);
        let retirement = table
            .begin_retire_overlapping(9, 0x4000_0000, count as u64 * GRANT_PAGE_SIZE)
            .unwrap();
        assert!(retirement.commit());
        assert_eq!(table.observed_slots_used(), 0);
    }

    #[test]
    fn constructors_have_identical_wire_bytes_and_frozen_arm_layout() {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(compare_constructors)
            .expect("spawn layout test")
            .join()
            .expect("compare constructors");
    }

    fn compare_constructors() {
        assert_eq!(core::mem::size_of::<FrameGrantResidencyRecord>(), 192);
        assert_eq!(core::mem::align_of::<FrameGrantResidencyRecord>(), 64);
        assert_eq!(FrameGrantResidencyRecord::COMMITTED_OFFSET, 72);
        assert_eq!(FrameGrantResidencyRecord::TRANSFER_PINS_OFFSET, 136);
        assert_eq!(
            core::mem::size_of::<FrameGrantResidencyOverflowSegment>(),
            393_472
        );
        assert_eq!(
            core::mem::align_of::<FrameGrantResidencyOverflowSegment>(),
            64
        );
        assert_eq!(core::mem::size_of::<FrameGrantResidencyTable>(), 789_056);
        assert_eq!(core::mem::align_of::<FrameGrantResidencyTable>(), 64);

        let layout = std::alloc::Layout::new::<FrameGrantResidencyTable>();
        // SAFETY: both allocations use the table layout, are checked for null,
        // initialized before reading, and deallocated using that same layout.
        unsafe {
            let ordinary = std::alloc::alloc(layout).cast::<FrameGrantResidencyTable>();
            let inplace = std::alloc::alloc(layout).cast::<FrameGrantResidencyTable>();
            assert!(!ordinary.is_null() && !inplace.is_null());
            ordinary.write(FrameGrantResidencyTable::new());
            FrameGrantResidencyTable::init_in_place(inplace);
            let ordinary_bytes = core::slice::from_raw_parts(ordinary.cast::<u8>(), layout.size());
            let inplace_bytes = core::slice::from_raw_parts(inplace.cast::<u8>(), layout.size());
            assert_eq!(ordinary_bytes, inplace_bytes);
            std::alloc::dealloc(ordinary.cast(), layout);
            std::alloc::dealloc(inplace.cast(), layout);
        }

        let seg_layout = std::alloc::Layout::new::<FrameGrantResidencyOverflowSegment>();
        unsafe {
            let ordinary =
                std::alloc::alloc(seg_layout).cast::<FrameGrantResidencyOverflowSegment>();
            let inplace =
                std::alloc::alloc(seg_layout).cast::<FrameGrantResidencyOverflowSegment>();
            assert!(!ordinary.is_null() && !inplace.is_null());
            ordinary.write(FrameGrantResidencyOverflowSegment::new());
            FrameGrantResidencyOverflowSegment::init_in_place(inplace);
            let ordinary_bytes =
                core::slice::from_raw_parts(ordinary.cast::<u8>(), seg_layout.size());
            let inplace_bytes =
                core::slice::from_raw_parts(inplace.cast::<u8>(), seg_layout.size());
            assert_eq!(ordinary_bytes, inplace_bytes);
            std::alloc::dealloc(ordinary.cast(), seg_layout);
            std::alloc::dealloc(inplace.cast(), seg_layout);
        }
    }
}
