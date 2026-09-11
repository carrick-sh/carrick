//! # Global Frame Lifecycle, Backing, and Stage-2 Leases
//!
//! Manages carrier-global frame IPAs, host owner registrations, stage-2 leases,
//! physical copy-on-write (COW) sources, and structural backing owners.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use super::*;

#[derive(Debug)]
pub(crate) struct GlobalFrameIpaAllocator {
    pub(crate) next: u64,
    pub(crate) free: Vec<(u64, u64)>,
    pub(crate) live: std::collections::BTreeMap<u64, u64>,
    pub(crate) drop_release_retry: Vec<(u64, u64)>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl GlobalFrameIpaAllocator {
    pub(crate) fn new() -> Self {
        Self {
            next: carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE,
            free: Vec::new(),
            live: std::collections::BTreeMap::new(),
            drop_release_retry: Vec::new(),
        }
    }

    pub(crate) fn allocate(&mut self, length: u64, alignment: u64) -> Result<u64, TrapError> {
        let pending = std::mem::take(&mut self.drop_release_retry);
        for (base, length) in pending {
            if self.release(base, length).is_err() {
                self.drop_release_retry.push((base, length));
            }
        }
        let length = align_up(length, CowArmedRanges::COMPOUND_SIZE)?;
        if length == 0 {
            return Err(TrapError::Hypervisor(
                "cannot reserve an empty global frame IPA extent".to_owned(),
            ));
        }
        let mut best: Option<(u64, u64, usize, u64, u64)> = None;
        for (index, &(free_base, free_len)) in self.free.iter().enumerate() {
            let base = align_up(free_base, alignment)?;
            let Some(end) = base.checked_add(length) else {
                continue;
            };
            let free_end = free_base.saturating_add(free_len);
            if end > free_end {
                continue;
            }

            // Preserve the large contiguous holes needed by HVPatch exec
            // frames: use the smallest fitting extent, with the lowest base as
            // a deterministic tie-breaker.  The exact live-extent ledger below
            // remains the fail-closed authority for release validation.
            if best.is_none_or(|(best_len, best_base, ..)| {
                (free_len, free_base) < (best_len, best_base)
            }) {
                best = Some((free_len, free_base, index, base, end));
            }
        }
        if let Some((free_len, free_base, index, base, end)) = best {
            let free_end = free_base.saturating_add(free_len);
            self.free.swap_remove(index);
            if base > free_base {
                self.free.push((free_base, base - free_base));
            }
            if end < free_end {
                self.free.push((end, free_end - end));
            }
            self.live.insert(base, length);
            return Ok(base);
        }

        let base = align_up(self.next, alignment)?;
        let end = base
            .checked_add(length)
            .ok_or_else(|| TrapError::Hypervisor("global frame IPA overflow".to_owned()))?;
        let limit = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE
            .checked_add(carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_SIZE)
            .ok_or_else(|| TrapError::Hypervisor("global frame IPA limit overflow".to_owned()))?;
        if end > limit {
            return Err(TrapError::Hypervisor(
                "global frame IPA arena exhausted".to_owned(),
            ));
        }
        self.next = end;
        self.live.insert(base, length);
        Ok(base)
    }

    pub(crate) fn release(&mut self, base: u64, length: u64) -> Result<(), TrapError> {
        let arena_base = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE;
        let arena_end =
            arena_base.saturating_add(carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_SIZE);
        let length = align_up(length, CowArmedRanges::COMPOUND_SIZE)?;
        if length == 0 {
            return Err(TrapError::Hypervisor(
                "cannot release an empty global frame IPA extent".to_owned(),
            ));
        }
        let end = base
            .checked_add(length)
            .ok_or_else(|| TrapError::Hypervisor("global frame IPA release overflow".to_owned()))?;
        if base < arena_base || end > arena_end {
            return Err(TrapError::Hypervisor(format!(
                "global frame IPA release is outside the arena: base=0x{base:x} length=0x{length:x}"
            )));
        }
        if self.live.get(&base).copied() != Some(length) {
            return Err(TrapError::Hypervisor(format!(
                "global frame IPA release does not match a live exact extent: base=0x{base:x} length=0x{length:x}"
            )));
        }
        self.live.remove(&base);
        self.free.push((base, length));
        self.free.sort_unstable_by_key(|extent| extent.0);
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(self.free.len());
        for (extent_base, extent_len) in self.free.drain(..) {
            if let Some((last_base, last_len)) = merged.last_mut()
                && last_base.saturating_add(*last_len) == extent_base
            {
                *last_len = last_len.saturating_add(extent_len);
            } else {
                merged.push((extent_base, extent_len));
            }
        }
        self.free = merged;
        Ok(())
    }

    pub(crate) fn is_live(&self, base: u64, length: u64) -> bool {
        let length = align_up(length, CowArmedRanges::COMPOUND_SIZE).unwrap_or(length);
        self.live.get(&base).copied() == Some(length)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn global_frame_ipa_allocator() -> &'static parking_lot::Mutex<GlobalFrameIpaAllocator> {
    static ALLOCATOR: std::sync::OnceLock<parking_lot::Mutex<GlobalFrameIpaAllocator>> =
        std::sync::OnceLock::new();
    ALLOCATOR.get_or_init(|| parking_lot::Mutex::new(GlobalFrameIpaAllocator::new()))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn reserve_global_frame_ipa_aligned(
    length: u64,
    alignment: u64,
) -> Result<u64, TrapError> {
    global_frame_ipa_allocator()
        .lock()
        .allocate(length, alignment)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn release_global_frame_ipa(base: u64, length: u64) -> Result<(), TrapError> {
    global_frame_ipa_allocator().lock().release(base, length)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn release_retired_stage2_ipa(base: u64, length: u64) -> Result<(), TrapError> {
    // Boot identity mappings and fixed root slots are stage-2 extents but were
    // never allocated from the reusable global-frame arena. They still need
    // unmapping; they must not be presented as allocator releases.
    if !is_reusable_global_frame_extent(base, length) {
        return Ok(());
    }
    release_global_frame_ipa(base, length)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct GlobalFrameStage2Lease {
    pub(crate) base: u64,
    pub(crate) length: u64,
    pub(crate) mapped: bool,
    pub(crate) active: bool,
    pub(crate) release_ipa: bool,
    #[cfg(any(test, feature = "foreign-cow-test-support"))]
    pub(crate) drop_backing_audit: Option<(usize, std::sync::Arc<std::sync::atomic::AtomicBool>)>,
    pub(crate) backend_map_installed: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl GlobalFrameStage2Lease {
    pub(crate) fn reserve(length: u64, alignment: u64) -> Result<Self, TrapError> {
        let length = align_up(length, CowArmedRanges::COMPOUND_SIZE)?;
        Ok(Self {
            base: reserve_global_frame_ipa_aligned(length, alignment)?,
            length,
            mapped: false,
            active: true,
            release_ipa: true,
            #[cfg(any(test, feature = "foreign-cow-test-support"))]
            drop_backing_audit: None,
            backend_map_installed: false,
        })
    }

    pub(crate) fn base(&self) -> u64 {
        self.base
    }

    #[allow(dead_code)]
    pub(crate) fn length(&self) -> u64 {
        self.length
    }

    pub(crate) fn fixed(base: u64, length: u64) -> Self {
        Self {
            base,
            length,
            mapped: false,
            active: true,
            release_ipa: false,
            #[cfg(any(test, feature = "foreign-cow-test-support"))]
            drop_backing_audit: None,
            backend_map_installed: false,
        }
    }

    pub(crate) fn mark_mapped(&mut self) {
        self.mapped = true;
        self.backend_map_installed = true;
    }

    pub(crate) fn mark_pre_mapped(&mut self) {
        self.mapped = true;
        self.backend_map_installed = false;
    }

    #[cfg(any(test, feature = "foreign-cow-test-support"))]
    pub(crate) fn mark_test_mapped_without_backend(&mut self) {
        self.mapped = true;
    }

    pub(crate) fn key(&self) -> (u64, u64) {
        (self.base, self.length)
    }

    /// Disarm the backend unmap because the VM that held this stage-2 mapping
    /// is already gone.
    ///
    /// Retiring a lease normally issues `hv_vm_unmap`, but an exact custody
    /// destroy takes the whole VM's stage-2 with it, so that call would fail
    /// against a destroyed VM. The IPA reservation is still this lease's to
    /// release, which `Drop` then does.
    pub(crate) fn forget_backend_mapping(&mut self) {
        self.mapped = false;
        self.backend_map_installed = false;
    }

    #[allow(dead_code)]
    pub(crate) fn try_retire(&mut self) -> Result<(), TrapError> {
        if !self.active {
            return Ok(());
        }
        #[cfg(any(test, feature = "foreign-cow-test-support"))]
        if let Some((host_addr, observed)) = &self.drop_backing_audit {
            observed.store(
                alias_backing_is_live(*host_addr),
                std::sync::atomic::Ordering::SeqCst,
            );
        }
        let unmap_backend = self.backend_map_installed;
        if unmap_backend {
            let size = usize::try_from(self.length).map_err(|_| {
                TrapError::Hypervisor("global frame stage-2 lease is too large".to_owned())
            })?;
            let rc = unsafe { inventory_hv_vm_unmap(self.base, size) };
            if rc != 0 {
                return Err(TrapError::Hypervisor(format!(
                    "guest-memory unmap(guest=0x{:x}, size={}) failed: 0x{:x}",
                    self.base, size, rc
                )));
            }
            self.mapped = false;
            self.backend_map_installed = false;
        }
        if self.release_ipa {
            release_global_frame_ipa(self.base, self.length)?;
            self.release_ipa = false;
        }
        self.active = false;
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for GlobalFrameStage2Lease {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        debug_assert!(
            !self.mapped,
            "mapped global-frame lease escaped without custody transfer or explicit rollback"
        );
        if !self.mapped && self.release_ipa {
            let mut allocator = global_frame_ipa_allocator().lock();
            if let Err(error) = allocator.release(self.base, self.length) {
                eprintln!(
                    "carrick: retaining unmapped global-frame reservation for allocator retry: {error}"
                );
                allocator.drop_release_retry.push((self.base, self.length));
            } else {
                self.release_ipa = false;
            }
        }
        self.active = false;
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Clone)]
pub(crate) enum GlobalFrameOwnerEntry {
    Live(std::sync::Arc<GlobalFrameHostOwner>),
    RetirementPending {
        owner: std::sync::Arc<GlobalFrameHostOwner>,
        #[allow(dead_code)]
        error: Option<String>,
        in_flight: bool,
    },
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl GlobalFrameOwnerEntry {
    pub(crate) fn owner(&self) -> &std::sync::Arc<GlobalFrameHostOwner> {
        match self {
            Self::Live(owner) | Self::RetirementPending { owner, .. } => owner,
        }
    }

    pub(crate) fn live_owner(&self) -> Option<&std::sync::Arc<GlobalFrameHostOwner>> {
        match self {
            Self::Live(owner) => Some(owner),
            Self::RetirementPending { .. } => None,
        }
    }

    pub(crate) fn is_live_exact(&self, expected: &std::sync::Arc<GlobalFrameHostOwner>) -> bool {
        self.live_owner()
            .is_some_and(|owner| std::sync::Arc::ptr_eq(owner, expected))
    }

    #[allow(dead_code)]
    pub(crate) fn is_live(&self) -> bool {
        matches!(self, Self::Live(_))
    }

    #[allow(dead_code)]
    pub(crate) fn is_pending(&self) -> bool {
        matches!(self, Self::RetirementPending { .. })
    }
}

/// Carrier-scoped ownership of host mappings installed at reusable global frame
/// IPAs. Per-vCPU mapping rows are non-owning views; otherwise the vCPU that
/// happened to service `mmap` would pin the host extent until process exit even
/// after another thread completed the final `munmap`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) enum GlobalFrameBacking {
    Owned(crate::host_mapping::OwnedHostMapping),
    Pooled(crate::frame_pool::PooledFrameHandle),
    PooledRoot(crate::frame_pool::PooledRootSlotHandle),
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl GlobalFrameBacking {
    pub(crate) fn as_ptr(&self) -> *mut u8 {
        match self {
            Self::Owned(mapping) => mapping.as_ptr(),
            Self::Pooled(handle) => handle.as_mut_ptr(),
            Self::PooledRoot(handle) => handle.as_mut_ptr(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Owned(mapping) => mapping.len(),
            Self::Pooled(handle) => handle.len(),
            Self::PooledRoot(handle) => handle.len(),
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct GlobalFrameSharedMapping {
    backing: GlobalFrameBacking,
    logical_pin_count: parking_lot::Mutex<u64>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl GlobalFrameSharedMapping {
    fn new(mapping: crate::host_mapping::OwnedHostMapping) -> Self {
        Self {
            backing: GlobalFrameBacking::Owned(mapping),
            logical_pin_count: parking_lot::Mutex::new(0),
        }
    }

    fn from_pooled(handle: crate::frame_pool::PooledFrameHandle) -> Self {
        Self {
            backing: GlobalFrameBacking::Pooled(handle),
            logical_pin_count: parking_lot::Mutex::new(0),
        }
    }

    fn from_pooled_root(handle: crate::frame_pool::PooledRootSlotHandle) -> Self {
        Self {
            backing: GlobalFrameBacking::PooledRoot(handle),
            logical_pin_count: parking_lot::Mutex::new(0),
        }
    }

    pub(crate) fn pin(&self) -> Result<(), CarrierStage2PinError> {
        let mut count = self.logical_pin_count.lock();
        *count = count
            .checked_add(1)
            .ok_or(CarrierStage2PinError::PinCountExhausted)?;
        Ok(())
    }

    pub(crate) fn unpin(&self) {
        let mut count = self.logical_pin_count.lock();
        *count = count.saturating_sub(1);
    }

    pub(crate) fn pin_count(&self) -> u64 {
        *self.logical_pin_count.lock()
    }
}

// SAFETY: this mapping is immutable after publication. Its process address is
// stable, reads are guarded by typed custody pins, and only explicit terminal
// custody retirement can drop the final shared owner.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Send for GlobalFrameSharedMapping {}

// SAFETY: see the Send argument above; concurrent users only read/copy bytes
// from the stable MAP_SHARED extent.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Sync for GlobalFrameSharedMapping {}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct GlobalFrameHostOwner {
    pub(crate) mapping: std::sync::Arc<GlobalFrameSharedMapping>,
    pub(crate) custody: std::sync::Weak<CarrierVmCustody>,
    pub(crate) record_identity: CarrierStage2RecordIdentity,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl GlobalFrameHostOwner {
    pub(crate) fn from_record(
        mapping: std::sync::Arc<GlobalFrameSharedMapping>,
        custody: std::sync::Arc<CarrierVmCustody>,
        record_identity: CarrierStage2RecordIdentity,
    ) -> Self {
        Self {
            mapping,
            custody: std::sync::Arc::downgrade(&custody),
            record_identity,
        }
    }

    #[cfg(test)]
    pub(crate) fn new(
        mut lease: GlobalFrameStage2Lease,
        mapping: crate::host_mapping::OwnedHostMapping,
        perms: u64,
        generation: u64,
        ipa: u64,
        length: u64,
    ) -> Self {
        if !lease.mapped {
            lease.mark_test_mapped_without_backend();
        }
        let custody = std::sync::Arc::clone(legacy_test_carrier_vm_custody_arc());
        let identity = transfer_global_frame_stage2_lease_to_custody(
            &custody,
            lease,
            mapping.as_ptr() as usize,
            perms,
            Some(CarrierLogicalOwner {
                id: generation,
                generation,
            }),
        )
        .unwrap_or_else(|error| panic!("register test global owner record: {error}"));
        assert_eq!(
            custody
                .stage2_record_snapshot(identity.record_id)
                .map(|snapshot| (snapshot.ipa, snapshot.len as u64)),
            Some((ipa, length))
        );
        Self::from_record(
            std::sync::Arc::new(GlobalFrameSharedMapping::new(mapping)),
            custody,
            identity,
        )
    }

    pub(crate) fn snapshot(&self) -> Option<CarrierStage2RecordSnapshot> {
        self.custody
            .upgrade()?
            .stage2_record_snapshot(self.record_identity.record_id)
    }

    pub(crate) fn pin(
        self: &std::sync::Arc<Self>,
    ) -> Result<GlobalFrameOwnerPin, CarrierStage2PinError> {
        let custody = self
            .custody
            .upgrade()
            .ok_or(CarrierStage2PinError::NotFound)?;
        let stage2_pin = custody.pin_stage2_record(self.record_identity)?;
        self.mapping.pin()?;
        Ok(GlobalFrameOwnerPin {
            owner: std::sync::Arc::clone(self),
            _stage2_pin: stage2_pin,
        })
    }

    pub(crate) fn host_addr(&self) -> usize {
        self.mapping.backing.as_ptr() as usize
    }

    pub(crate) fn generation(&self) -> u64 {
        self.record_identity
            .logical_owner
            .map_or(0, |owner| owner.generation)
    }

    #[allow(dead_code)]
    pub(crate) fn ipa(&self) -> u64 {
        self.snapshot().map_or(0, |snapshot| snapshot.ipa)
    }

    pub(crate) fn length(&self) -> u64 {
        self.mapping.backing.len() as u64
    }

    pub(crate) fn perms(&self) -> u64 {
        self.snapshot().map_or(0, |snapshot| snapshot.perms)
    }

    pub(crate) fn ptr(&self) -> *mut u8 {
        self.mapping.backing.as_ptr()
    }

    pub(crate) fn as_ptr(&self) -> *mut u8 {
        self.ptr()
    }

    pub(crate) fn len(&self) -> usize {
        self.mapping.backing.len()
    }

    #[allow(dead_code)]
    pub(crate) fn is_retired(&self) -> bool {
        self.snapshot()
            .is_none_or(|snapshot| !snapshot.mapped || snapshot.terminalized_by_vm_destroy)
    }

    pub(crate) fn lease_fingerprint(&self) -> Option<ExecLeaseFingerprint> {
        self.snapshot().map(|snapshot| ExecLeaseFingerprint {
            base: snapshot.ipa,
            length: snapshot.len as u64,
            mapped: snapshot.mapped,
            active: !snapshot.terminalized_by_vm_destroy,
            release_ipa: snapshot.release_ipa,
        })
    }

    #[cfg(test)]
    pub(crate) fn try_retire(&self) -> Result<(), TrapError> {
        let custody = self.custody.upgrade().ok_or_else(|| {
            TrapError::Hypervisor("global owner carrier custody disappeared".to_owned())
        })?;
        match custody
            .retire_stage2_record_using(self.record_identity, unmap_global_frame_stage2_record)
        {
            CarrierStage2RetireOutcome::RetiredUnmapped
            | CarrierStage2RetireOutcome::TerminalizedByVmDestroy => {
                finalize_global_frame_owner_record(&custody, self)
            }
            CarrierStage2RetireOutcome::DeferredActivePins => Err(TrapError::Hypervisor(
                "global owner retirement deferred by active pins".to_owned(),
            )),
            CarrierStage2RetireOutcome::RetryPending(error) => Err(TrapError::Hypervisor(format!(
                "global owner retirement retry pending: {error:?}"
            ))),
            outcome => Err(TrapError::Hypervisor(format!(
                "global owner retirement identity failure: {outcome:?}"
            ))),
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct GlobalFrameOwnerPin {
    pub(crate) owner: std::sync::Arc<GlobalFrameHostOwner>,
    pub(crate) _stage2_pin: CarrierStage2Pin,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl GlobalFrameOwnerPin {
    pub(crate) fn owner(&self) -> &GlobalFrameHostOwner {
        &self.owner
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct PhysicalCowSource {
    host_addr: *mut u8,
    physical_ipa: u64,
    _owner_pin: Option<GlobalFrameOwnerPin>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PhysicalCowSource {
    pub(crate) fn unpinned(host_addr: *mut u8, physical_ipa: u64) -> Self {
        Self {
            host_addr,
            physical_ipa,
            _owner_pin: None,
        }
    }

    pub(crate) fn pinned(pin: GlobalFrameOwnerPin, offset: usize, physical_ipa: u64) -> Self {
        let host_addr = unsafe { pin.owner().as_ptr().add(offset) };
        Self {
            host_addr,
            physical_ipa,
            _owner_pin: Some(pin),
        }
    }

    pub(crate) fn host_addr(&self) -> *mut u8 {
        self.host_addr
    }

    pub(crate) fn physical_ipa(&self) -> u64 {
        self.physical_ipa
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for GlobalFrameOwnerPin {
    fn drop(&mut self) {
        self.owner.mapping.unpin();
    }
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn next_global_frame_owner_generation() -> u64 {
    legacy_test_carrier_vm_custody()
        .allocate_logical_owner()
        .map_or(0, |owner| owner.generation)
}

/// The live owner generation for `(ipa, length)`, or 0 when unowned.
///
/// Rows stamp this at publication, which always happens while the lease is
/// live, so a row records the incarnation it was actually published against.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn global_frame_host_owner_generation_in(
    custody: &CarrierVmCustody,
    ipa: u64,
    length: u64,
) -> u64 {
    global_frame_host_owner_identity_in(custody, ipa, length)
        .map_or(0, |(_, generation)| generation)
}

/// The exact host pointer and generation currently owning a reusable extent.
///
/// Retirement diagnostics and inventory authentication need the complete
/// identity. A generation or a recycled host pointer alone is insufficient.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn global_frame_host_owner_identity_in(
    custody: &CarrierVmCustody,
    ipa: u64,
    length: u64,
) -> Option<(usize, u64)> {
    custody
        .global_frame_host_owners
        .lock()
        .get(&(ipa, length))
        .and_then(|entry| match entry {
            GlobalFrameOwnerEntry::Live(owner) => Some((owner.host_addr(), owner.generation())),
            GlobalFrameOwnerEntry::RetirementPending { .. } => None,
        })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn pin_exact_live_global_frame_owner_in(
    custody: &CarrierVmCustody,
    ipa: u64,
    length: u64,
    expected_host_addr: usize,
    expected_generation: u64,
) -> Option<GlobalFrameOwnerPin> {
    if expected_generation == 0 {
        return None;
    }
    let owner = custody
        .global_frame_host_owners
        .lock()
        .get(&(ipa, length))
        .and_then(GlobalFrameOwnerEntry::live_owner)
        .filter(|owner| {
            owner.host_addr() == expected_host_addr && owner.generation() == expected_generation
        })
        .cloned()?;
    let pin = owner.pin().ok()?;
    let still_current = custody
        .global_frame_host_owners
        .lock()
        .get(&(ipa, length))
        .is_some_and(|entry| entry.is_live_exact(&owner));
    still_current.then_some(pin)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn global_frame_owner_is_replayable_in(
    custody: &CarrierVmCustody,
    ipa: u64,
    length: u64,
    host_addr: usize,
    generation: u64,
) -> bool {
    match custody.global_frame_host_owners.lock().get(&(ipa, length)) {
        Some(GlobalFrameOwnerEntry::Live(owner)) => {
            owner.host_addr() == host_addr && (generation == 0 || owner.generation() == generation)
        }
        Some(GlobalFrameOwnerEntry::RetirementPending { .. }) => false,
        None => generation == 0,
    }
}

// SAFETY: the mapping is process-address-space state. Its address is stable,
// HVF and guest-memory access already cross host threads, and explicit custody
// retirement serializes stage-2 unmap before the final owning Arc is removed.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Send for GlobalFrameHostOwner {}

// SAFETY: all owner fields are immutable after publication. Reads hold a typed
// custody pin for the exact record, and retirement cannot remove the backing
// until every such pin is released.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Sync for GlobalFrameHostOwner {}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct CarrierFrameCowOwnerLease {
    pub(crate) key: (u64, u64),
    pub(crate) pin: GlobalFrameOwnerPin,
    pub(crate) generation: carrick_hal::ForeignOwnerGeneration,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl carrick_hal::FrameCowOwnerLease for CarrierFrameCowOwnerLease {
    fn generation(&self) -> carrick_hal::ForeignOwnerGeneration {
        self.generation
    }

    fn is_current(&self) -> bool {
        self.pin.owner().custody.upgrade().is_some_and(|custody| {
            custody
                .global_frame_host_owners
                .lock()
                .get(&self.key)
                .is_some_and(|current| current.is_live_exact(&self.pin.owner))
        })
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct CarrierFrameCowOwnerInventory {
    pub(crate) custody: std::sync::Arc<CarrierVmCustody>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl carrick_hal::FrameCowOwnerInventory for CarrierFrameCowOwnerInventory {
    fn retain_current(
        &self,
        gpa: carrick_guest_mem::Gpa,
        length: carrick_hal::FrameLength,
    ) -> Result<Box<dyn carrick_hal::FrameCowOwnerLease>, Box<dyn std::error::Error + Send + Sync>>
    {
        let key = (gpa.raw(), length.raw());
        let owner = self
            .custody
            .global_frame_host_owners
            .lock()
            .get(&key)
            .and_then(|entry| match entry {
                GlobalFrameOwnerEntry::Live(owner) => Some(std::sync::Arc::clone(owner)),
                GlobalFrameOwnerEntry::RetirementPending { .. } => None,
            })
            .ok_or_else(|| std::io::Error::other("foreign COW extent has no current host owner"))?;
        let generation = std::num::NonZeroU64::new(owner.generation())
            .map(carrick_hal::ForeignOwnerGeneration::from_backend_counter)
            .ok_or_else(|| std::io::Error::other("foreign COW host owner generation is zero"))?;
        let pin = owner.pin().map_err(|error| {
            std::io::Error::other(format!(
                "foreign COW host owner cannot be pinned: {error:?}"
            ))
        })?;
        Ok(Box::new(CarrierFrameCowOwnerLease {
            key,
            pin,
            generation,
        }))
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn carrier_frame_cow_owner_inventory_in(
    custody: std::sync::Arc<CarrierVmCustody>,
) -> std::sync::Arc<dyn carrick_hal::FrameCowOwnerInventory> {
    std::sync::Arc::new(CarrierFrameCowOwnerInventory { custody })
}

/// Global-frame stage-2 leases owned by a CARRIER MM rather than by a mapping
/// row or a host-owner registration.
///
/// A forked process's fresh kernel-state frames are reserved by the fork path
/// and must outlive every per-task mapping projection, which are `unowned` and
/// carry no lease. Parking them in the carrier alone made them invisible to
/// `retire_stage2_extent_from_mappings`, whose fallback then released the IPA
/// while the lease was still live — and the lease's own `Drop` released it a
/// second time, tripping the allocator's exact-extent check and aborting the
/// carrier. Keying them here makes the owner findable, so the extent is
/// released exactly once, by whichever of retirement or carrier teardown
/// reaches it first.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn register_carrier_stage2_leases(
    custody: &std::sync::Arc<CarrierVmCustody>,
    leases: &mut Vec<GlobalFrameStage2Lease>,
    owner_hosts: &std::collections::BTreeMap<(u64, u64), usize>,
) -> Result<Vec<CarrierStage2RecordIdentity>, TrapError> {
    let keys: Vec<_> = leases.iter().map(GlobalFrameStage2Lease::key).collect();
    let mut distinct = std::collections::BTreeSet::new();
    let registered = custody.carrier_stage2_records.lock();
    let mut validation_error = None;
    for (&key, lease) in keys.iter().zip(leases.iter()) {
        if !distinct.insert(key) || registered.contains_key(&key) {
            validation_error = Some(TrapError::Hypervisor(format!(
                "carrier stage-2 lease collision at IPA 0x{:x} size {}",
                key.0, key.1
            )));
            break;
        }
        let host_addr = owner_hosts.get(&key).copied().unwrap_or_default();
        if host_addr == 0 || !lease.active || !lease.mapped {
            validation_error = Some(TrapError::Hypervisor(format!(
                "carrier stage-2 lease {key:?} has no exact active mapped host owner: host=0x{host_addr:x} active={} mapped={}",
                lease.active, lease.mapped
            )));
            break;
        }
    }
    drop(registered);
    if let Some(error) = validation_error {
        for (key, mut lease) in keys.iter().copied().zip(leases.drain(..)) {
            if lease.try_retire().is_err() {
                let identity = transfer_global_frame_stage2_lease_to_custody(
                    custody,
                    lease,
                    owner_hosts.get(&key).copied().unwrap_or(1),
                    0,
                    None,
                )?;
                let _ = custody.request_stage2_record_retirement(identity);
            }
        }
        return Err(error);
    }
    let mut registered = custody.carrier_stage2_records.lock();
    let mut identities = Vec::with_capacity(keys.len());
    for (key, lease) in keys.iter().copied().zip(leases.drain(..)) {
        let identity = transfer_global_frame_stage2_lease_to_custody(
            custody,
            lease,
            owner_hosts[&key],
            0,
            None,
        )?;
        registered.insert(key, identity);
        identities.push(identity);
    }
    Ok(identities)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn carrier_stage2_lease_owner_matches(
    custody: &CarrierVmCustody,
    ipa: u64,
    length: u64,
    host_addr: usize,
) -> bool {
    custody
        .carrier_stage2_records
        .lock()
        .get(&(ipa, length))
        .and_then(|identity| custody.stage2_record_snapshot(identity.record_id))
        .is_some_and(|record| {
            record.mapped && !record.terminalized_by_vm_destroy && record.host_addr == host_addr
        })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn collect_carrier_stage2_owner_hosts(
    identities: impl IntoIterator<Item = ((u64, u64), usize)>,
) -> Result<std::collections::BTreeMap<(u64, u64), usize>, TrapError> {
    let mut owners = std::collections::BTreeMap::new();
    for (key, host_addr) in identities {
        if let Some(previous) = owners.insert(key, host_addr)
            && previous != host_addr
        {
            return Err(TrapError::Hypervisor(format!(
                "carrier stage-2 lease {key:?} has conflicting host owners 0x{previous:x} and 0x{host_addr:x}"
            )));
        }
    }
    Ok(owners)
}

/// Take the carrier-owned exact record for an explicit retirement safe point.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn take_carrier_stage2_record(
    custody: &CarrierVmCustody,
    ipa: u64,
    length: u64,
) -> Option<CarrierStage2RecordIdentity> {
    custody
        .carrier_stage2_records
        .lock()
        .get(&(ipa, length))
        .copied()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn take_carrier_stage2_record_if_owner(
    custody: &CarrierVmCustody,
    ipa: u64,
    length: u64,
    host_addr: usize,
) -> Option<CarrierStage2RecordIdentity> {
    let owners = custody.carrier_stage2_records.lock();
    let matches = owners
        .get(&(ipa, length))
        .and_then(|identity| custody.stage2_record_snapshot(identity.record_id))
        .is_some_and(|record| {
            record.mapped && !record.terminalized_by_vm_destroy && record.host_addr == host_addr
        });
    matches
        .then(|| owners.get(&(ipa, length)).copied())
        .flatten()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn retire_carrier_stage2_record_at_safe_point(
    custody: &CarrierVmCustody,
    identity: CarrierStage2RecordIdentity,
) -> Result<(), TrapError> {
    retire_carrier_stage2_record_at_safe_point_using(
        custody,
        identity,
        unmap_global_frame_stage2_record,
        release_retired_stage2_ipa,
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn retire_carrier_stage2_record_at_safe_point_using(
    custody: &CarrierVmCustody,
    identity: CarrierStage2RecordIdentity,
    unmap: impl FnOnce(u64, usize) -> Result<(), CarrierStage2BackendError>,
    mut release: impl FnMut(u64, u64) -> Result<(), TrapError>,
) -> Result<(), TrapError> {
    let snapshot = custody
        .stage2_record_snapshot(identity.record_id)
        .ok_or_else(|| TrapError::Hypervisor("carrier stage-2 record disappeared".to_owned()))?;
    let key = (snapshot.ipa, snapshot.len as u64);
    match custody.retire_stage2_record_using(identity, unmap) {
        CarrierStage2RetireOutcome::RetiredUnmapped
        | CarrierStage2RetireOutcome::TerminalizedByVmDestroy => {
            finalize_terminal_stage2_record_using(custody, identity, &mut release)?;
            let mut records = custody.carrier_stage2_records.lock();
            if records.get(&key) == Some(&identity) {
                records.remove(&key);
            }
            Ok(())
        }
        CarrierStage2RetireOutcome::DeferredActivePins => Ok(()),
        outcome => Err(TrapError::Hypervisor(format!(
            "retire carrier stage-2 record at safe point: {outcome:?}"
        ))),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn transfer_global_frame_stage2_lease_to_custody(
    custody: &std::sync::Arc<CarrierVmCustody>,
    mut lease: GlobalFrameStage2Lease,
    host_addr: usize,
    perms: u64,
    logical_owner: Option<CarrierLogicalOwner>,
) -> Result<CarrierStage2RecordIdentity, TrapError> {
    if !lease.active || !lease.mapped || host_addr == 0 {
        return Err(TrapError::Hypervisor(format!(
            "global frame host owner lease is not active and mapped: key={:?} active={} mapped={} host=0x{host_addr:x}",
            lease.key(),
            lease.active,
            lease.mapped,
        )));
    }
    let registration = (|| {
        let vm_generation = custody.setup_generation().ok_or_else(|| {
            TrapError::Hypervisor(
                "global frame owner registration has no creating/live carrier VM".to_owned(),
            )
        })?;
        let logical_owner = match logical_owner {
            Some(owner) => owner,
            None => custody.allocate_logical_owner().map_err(|error| {
                TrapError::Hypervisor(format!(
                    "allocate carrier-local global frame owner identity: {error:?}"
                ))
            })?,
        };
        let backend_map_installed = lease.backend_map_installed;
        custody
            .register_stage2_record(CarrierStage2RecordSpec {
                vm_generation,
                ipa: lease.base,
                len: usize::try_from(lease.length).map_err(|_| {
                    TrapError::Hypervisor("global frame owner lease is too large".to_owned())
                })?,
                host_addr,
                mapped: lease.mapped,
                backend_map_installed,
                release_ipa: lease.release_ipa,
                perms,
                logical_owner: Some(logical_owner),
            })
            .map_err(|error| {
                TrapError::Hypervisor(format!(
                    "transfer global frame lease into carrier custody: {error:?}"
                ))
            })
    })();
    let identity = match registration {
        Ok(identity) => identity,
        Err(registration_error) => {
            lease.try_retire().map_err(|rollback_error| {
                TrapError::Hypervisor(format!(
                    "{registration_error}; explicit pre-custody rollback failed: {rollback_error}"
                ))
            })?;
            return Err(registration_error);
        }
    };
    lease.active = false;
    lease.mapped = false;
    lease.release_ipa = false;
    #[cfg(any(test, feature = "foreign-cow-test-support"))]
    {
        lease.backend_map_installed = false;
        lease.drop_backing_audit = None;
    }
    Ok(identity)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn unmap_global_frame_stage2_record(
    ipa: u64,
    len: usize,
) -> Result<(), CarrierStage2BackendError> {
    let rc = unsafe { inventory_hv_vm_unmap(ipa, len) };
    if rc == 0 {
        Ok(())
    } else {
        Err(CarrierStage2BackendError::HvReturn(rc as u32))
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn register_global_frame_host_owner_in(
    custody: &std::sync::Arc<CarrierVmCustody>,
    lease: GlobalFrameStage2Lease,
    mapping: crate::host_mapping::OwnedHostMapping,
    perms: u64,
) -> Result<u64, TrapError> {
    register_global_frame_host_owner_in_using(
        custody,
        lease,
        mapping,
        perms,
        &mut unmap_global_frame_stage2_record,
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn register_global_frame_host_owner_in_using(
    custody: &std::sync::Arc<CarrierVmCustody>,
    lease: GlobalFrameStage2Lease,
    mapping: crate::host_mapping::OwnedHostMapping,
    perms: u64,
    rollback_unmap: &mut dyn FnMut(u64, usize) -> Result<(), CarrierStage2BackendError>,
) -> Result<u64, TrapError> {
    let key = lease.key();
    if key.1 != mapping.len() as u64 || !lease.mapped {
        return Err(TrapError::Hypervisor(format!(
            "global frame host owner lease/backing mismatch: lease={key:?} backing={} mapped={}",
            mapping.len(),
            lease.mapped,
        )));
    }
    if let Some(debug_ipa) = fork_debug_ipa()
        && key.0 <= debug_ipa
        && debug_ipa < key.0.saturating_add(key.1)
    {
        eprintln!(
            "[FORKDBG] register_global_frame_host_owner ipa={:#x} len={:#x} host={:p}\n{}",
            key.0,
            key.1,
            mapping.as_ptr(),
            std::backtrace::Backtrace::force_capture(),
        );
    }
    let record_identity = transfer_global_frame_stage2_lease_to_custody(
        custody,
        lease,
        mapping.as_ptr() as usize,
        perms,
        None,
    )?;
    let generation = record_identity
        .logical_owner
        .map_or(0, |owner| owner.generation);
    let owner = std::sync::Arc::new(GlobalFrameHostOwner::from_record(
        std::sync::Arc::new(GlobalFrameSharedMapping::new(mapping)),
        std::sync::Arc::clone(custody),
        record_identity,
    ));
    let mut owners = custody.global_frame_host_owners.lock();
    if owners.contains_key(&key) {
        drop(owners);
        let outcome = custody.retire_stage2_record_using(record_identity, rollback_unmap);
        match outcome {
            CarrierStage2RetireOutcome::RetiredUnmapped
            | CarrierStage2RetireOutcome::TerminalizedByVmDestroy => {
                if finalize_global_frame_owner_record(custody, &owner).is_err() {
                    retain_pending_global_frame_owner(custody, owner);
                }
            }
            CarrierStage2RetireOutcome::DeferredActivePins
            | CarrierStage2RetireOutcome::RetryPending(_)
            | CarrierStage2RetireOutcome::NotFound
            | CarrierStage2RetireOutcome::OwnerIdentityMismatch
            | CarrierStage2RetireOutcome::OwnerGenerationMismatch
            | CarrierStage2RetireOutcome::VmGenerationMismatch => {
                retain_pending_global_frame_owner(custody, owner);
            }
        }
        return Err(TrapError::Hypervisor(format!(
            "global frame host owner collision at IPA 0x{:x} size {}",
            key.0, key.1
        )));
    }
    owners.insert(key, GlobalFrameOwnerEntry::Live(owner));
    Ok(generation)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn register_pooled_global_frame_host_owner_in(
    custody: &std::sync::Arc<CarrierVmCustody>,
    handle: crate::frame_pool::PooledFrameHandle,
    perms: u64,
) -> Result<u64, TrapError> {
    let key = (handle.ipa(), handle.len() as u64);
    let host_addr = handle.as_mut_ptr() as usize;
    let vm_generation = custody.setup_generation().ok_or_else(|| {
        TrapError::Hypervisor(
            "pooled global frame owner registration has no creating/live carrier VM".to_owned(),
        )
    })?;
    let logical_owner = custody.allocate_logical_owner().map_err(|error| {
        TrapError::Hypervisor(format!(
            "allocate carrier-local global frame owner identity: {error:?}"
        ))
    })?;
    let record_identity = custody
        .register_stage2_record(CarrierStage2RecordSpec {
            vm_generation,
            ipa: key.0,
            len: handle.len(),
            host_addr,
            mapped: true,
            backend_map_installed: false,
            release_ipa: false,
            perms,
            logical_owner: Some(logical_owner),
        })
        .map_err(|error| {
            TrapError::Hypervisor(format!(
                "register pooled global frame record into carrier custody: {error:?}"
            ))
        })?;
    let generation = record_identity
        .logical_owner
        .map_or(0, |owner| owner.generation);
    let owner = std::sync::Arc::new(GlobalFrameHostOwner::from_record(
        std::sync::Arc::new(GlobalFrameSharedMapping::from_pooled(handle)),
        std::sync::Arc::clone(custody),
        record_identity,
    ));
    let mut owners = custody.global_frame_host_owners.lock();
    if owners.contains_key(&key) {
        drop(owners);
        let outcome =
            custody.retire_stage2_record_using(record_identity, unmap_global_frame_stage2_record);
        match outcome {
            CarrierStage2RetireOutcome::RetiredUnmapped
            | CarrierStage2RetireOutcome::TerminalizedByVmDestroy => {
                if finalize_global_frame_owner_record(custody, &owner).is_err() {
                    retain_pending_global_frame_owner(custody, owner);
                }
            }
            CarrierStage2RetireOutcome::DeferredActivePins
            | CarrierStage2RetireOutcome::RetryPending(_)
            | CarrierStage2RetireOutcome::NotFound
            | CarrierStage2RetireOutcome::OwnerIdentityMismatch
            | CarrierStage2RetireOutcome::OwnerGenerationMismatch
            | CarrierStage2RetireOutcome::VmGenerationMismatch => {
                retain_pending_global_frame_owner(custody, owner);
            }
        }
        return Err(TrapError::Hypervisor(format!(
            "pooled global frame host owner collision at IPA 0x{:x} size {}",
            key.0, key.1
        )));
    }
    owners.insert(key, GlobalFrameOwnerEntry::Live(owner));
    Ok(generation)
}

/// Publish the host backing owner for a prepared exec mapping and stamp its
/// live generation directly onto the region state.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn publish_exec_region_host_owner_in(
    custody: &std::sync::Arc<CarrierVmCustody>,
    region: &mut HvfMappedRegion,
    lease: GlobalFrameStage2Lease,
    mm_root_slot: Option<(u64, u64)>,
) -> Result<u64, TrapError> {
    let key = lease.key();
    let host_mapping = region.host_mapping.take().ok_or_else(|| {
        TrapError::Hypervisor(format!(
            "HVPatch exec mapping IPA 0x{:x} has no host owner",
            key.0
        ))
    })?;
    let is_structural = !is_reusable_global_frame_extent(key.0, key.1);
    let owner_generation = if is_structural {
        if let Some(root_slot) = mm_root_slot.filter(|slot| slot.0 == key.0) {
            if key.1 == 0
                || key
                    .0
                    .checked_add(key.1)
                    .is_none_or(|end| end > root_slot.0.saturating_add(root_slot.1))
            {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch exec stage-1 root mapping ({:#x}, {:#x}) escapes slot ({:#x}, {:#x})",
                    key.0, key.1, root_slot.0, root_slot.1
                )));
            }
        }
        let epoch = next_structural_epoch()?;
        let owner = StructuralBackingOwner::new_in(
            custody,
            host_mapping,
            lease,
            u64::from(region.perms),
            epoch,
            key.0,
            usize::try_from(key.1).map_err(|_| TrapError::MappingTooLarge(key.1))?,
        )?;
        region.structural_owner = Some(owner);
        epoch.raw()
    } else {
        register_global_frame_host_owner_in(custody, lease, host_mapping, u64::from(region.perms))?
    };
    region.owner_generation = owner_generation;
    Ok(owner_generation)
}

/// Cached `CARRICK_FORK_DEBUG_IPA` / `CARRICK_FORK_DEBUG_VA` (parsed once).
/// `std::env::var` serializes on std's process-wide environment lock; calling
/// Monotonic source for [`StructuralEpoch`]. Never reset, monotonically increasing.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
static STRUCTURAL_EPOCH_ALLOCATOR: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

/// A non-zero monotonically generated structural backing epoch.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct StructuralEpoch(std::num::NonZeroU64);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn next_structural_epoch() -> Result<StructuralEpoch, TrapError> {
    let mut current = STRUCTURAL_EPOCH_ALLOCATOR.load(std::sync::atomic::Ordering::Relaxed);
    loop {
        if current == u64::MAX {
            return Err(TrapError::Hypervisor(
                "structural epoch allocation exhausted".to_owned(),
            ));
        }
        let next = current.checked_add(1).ok_or_else(|| {
            TrapError::Hypervisor("structural epoch allocation overflow".to_owned())
        })?;
        match STRUCTURAL_EPOCH_ALLOCATOR.compare_exchange_weak(
            current,
            next,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::Relaxed,
        ) {
            Ok(_) => {
                let non_zero = std::num::NonZeroU64::new(current).ok_or_else(|| {
                    TrapError::Hypervisor("structural epoch allocation zero".to_owned())
                })?;
                return Ok(StructuralEpoch(non_zero));
            }
            Err(actual) => current = actual,
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl StructuralEpoch {
    pub(crate) const fn raw(self) -> u64 {
        self.0.get()
    }

    #[allow(dead_code)]
    pub(crate) const fn to_owner_generation(self) -> carrick_hal::ForeignOwnerGeneration {
        carrick_hal::ForeignOwnerGeneration::from_backend_counter(self.0)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct StructuralBackingOwner {
    pub(crate) custody: std::sync::Weak<CarrierVmCustody>,
    pub(crate) retained: std::sync::Arc<StructuralBackingCustodyEntry>,
    pub(crate) epoch: StructuralEpoch,
    pub(crate) physical_ipa: u64,
    pub(crate) physical_size: usize,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct StructuralBackingCustodyEntry {
    pub(crate) mapping: std::sync::Arc<GlobalFrameSharedMapping>,
    pub(crate) record_identity: parking_lot::Mutex<CarrierStage2RecordIdentity>,
    pub(crate) owner_retired: std::sync::atomic::AtomicBool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl StructuralBackingOwner {
    #[cfg(test)]
    pub(crate) fn new(
        mapping: crate::host_mapping::OwnedHostMapping,
        mut stage2_lease: GlobalFrameStage2Lease,
        epoch: StructuralEpoch,
        physical_ipa: u64,
        physical_size: usize,
    ) -> Result<std::sync::Arc<Self>, TrapError> {
        if !stage2_lease.mapped {
            stage2_lease.mark_test_mapped_without_backend();
        }
        Self::new_in(
            legacy_test_carrier_vm_custody_arc(),
            mapping,
            stage2_lease,
            u64::from(applevisor::memory::MemPerms::ReadWriteExec),
            epoch,
            physical_ipa,
            physical_size,
        )
    }

    pub(crate) fn new_in(
        custody: &std::sync::Arc<CarrierVmCustody>,
        mapping: crate::host_mapping::OwnedHostMapping,
        mut stage2_lease: GlobalFrameStage2Lease,
        perms: u64,
        epoch: StructuralEpoch,
        physical_ipa: u64,
        physical_size: usize,
    ) -> Result<std::sync::Arc<Self>, TrapError> {
        if mapping.len() != physical_size
            || mapping.as_ptr().is_null()
            || physical_size == 0
            || physical_ipa.checked_add(physical_size as u64).is_none()
            || epoch.raw() == 0
        {
            stage2_lease.try_retire().map_err(|rollback| {
                TrapError::Hypervisor(format!(
                    "invalid structural backing owner and explicit lease rollback failed: {rollback}"
                ))
            })?;
            return Err(TrapError::Hypervisor(format!(
                "invalid structural backing owner identity: epoch={:?} ipa=0x{:x} len={}",
                epoch, physical_ipa, physical_size
            )));
        }
        let (lease_base, lease_len) = stage2_lease.key();
        if lease_base != physical_ipa || lease_len != physical_size as u64 {
            stage2_lease.try_retire().map_err(|rollback| {
                TrapError::Hypervisor(format!(
                    "mismatched structural backing owner and explicit lease rollback failed: {rollback}"
                ))
            })?;
            return Err(TrapError::Hypervisor(format!(
                "structural stage-2 lease ({lease_base:#x}, {lease_len:#x}) does not match physical extent ({physical_ipa:#x}, {physical_size:#x})"
            )));
        }
        let identity = transfer_global_frame_stage2_lease_to_custody(
            custody,
            stage2_lease,
            mapping.as_ptr() as usize,
            perms,
            Some(CarrierLogicalOwner {
                id: epoch.raw(),
                generation: epoch.raw(),
            }),
        )?;
        let retained = std::sync::Arc::new(StructuralBackingCustodyEntry {
            mapping: std::sync::Arc::new(GlobalFrameSharedMapping::new(mapping)),
            record_identity: parking_lot::Mutex::new(identity),
            owner_retired: std::sync::atomic::AtomicBool::new(false),
        });
        custody
            .structural_backings
            .lock()
            .insert(identity.record_id, std::sync::Arc::clone(&retained));
        Ok(std::sync::Arc::new(Self {
            custody: std::sync::Arc::downgrade(custody),
            retained,
            epoch,
            physical_ipa,
            physical_size,
        }))
    }

    pub(crate) fn new_pooled_root_in(
        custody: &std::sync::Arc<CarrierVmCustody>,
        handle: crate::frame_pool::PooledRootSlotHandle,
        mut stage2_lease: GlobalFrameStage2Lease,
        perms: u64,
        epoch: StructuralEpoch,
        physical_ipa: u64,
        physical_size: usize,
    ) -> Result<std::sync::Arc<Self>, TrapError> {
        if handle.len() != physical_size
            || handle.as_mut_ptr().is_null()
            || physical_size == 0
            || physical_ipa.checked_add(physical_size as u64).is_none()
            || epoch.raw() == 0
        {
            stage2_lease.try_retire().map_err(|rollback| {
                TrapError::Hypervisor(format!(
                    "invalid pooled root structural backing owner and explicit lease rollback failed: {rollback}"
                ))
            })?;
            return Err(TrapError::Hypervisor(format!(
                "invalid pooled root structural backing owner identity: epoch={:?} ipa=0x{:x} len={}",
                epoch, physical_ipa, physical_size
            )));
        }
        let (lease_base, lease_len) = stage2_lease.key();
        if lease_base != physical_ipa || lease_len != physical_size as u64 {
            stage2_lease.try_retire().map_err(|rollback| {
                TrapError::Hypervisor(format!(
                    "mismatched pooled root structural backing owner and explicit lease rollback failed: {rollback}"
                ))
            })?;
            return Err(TrapError::Hypervisor(format!(
                "structural stage-2 lease ({lease_base:#x}, {lease_len:#x}) does not match physical extent ({physical_ipa:#x}, {physical_size:#x})"
            )));
        }
        let host_addr = handle.as_mut_ptr() as usize;
        let identity = transfer_global_frame_stage2_lease_to_custody(
            custody,
            stage2_lease,
            host_addr,
            perms,
            Some(CarrierLogicalOwner {
                id: epoch.raw(),
                generation: epoch.raw(),
            }),
        )?;
        let retained = std::sync::Arc::new(StructuralBackingCustodyEntry {
            mapping: std::sync::Arc::new(GlobalFrameSharedMapping::from_pooled_root(handle)),
            record_identity: parking_lot::Mutex::new(identity),
            owner_retired: std::sync::atomic::AtomicBool::new(false),
        });
        custody
            .structural_backings
            .lock()
            .insert(identity.record_id, std::sync::Arc::clone(&retained));
        Ok(std::sync::Arc::new(Self {
            custody: std::sync::Arc::downgrade(custody),
            retained,
            epoch,
            physical_ipa,
            physical_size,
        }))
    }

    pub(crate) fn record_populated_prefix(&self, prefix: usize) {
        if let GlobalFrameBacking::PooledRoot(ref handle) = self.retained.mapping.backing {
            handle.record_populated_prefix(prefix);
        }
    }

    pub(crate) fn ptr(&self) -> *mut u8 {
        self.retained.mapping.backing.as_ptr()
    }

    pub(crate) fn len(&self) -> usize {
        self.retained.mapping.backing.len()
    }

    pub(crate) fn epoch(&self) -> StructuralEpoch {
        self.epoch
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn stage2_key(&self) -> (u64, u64) {
        (self.physical_ipa, self.physical_size as u64)
    }

    pub(crate) fn record_identity(&self) -> CarrierStage2RecordIdentity {
        *self.retained.record_identity.lock()
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for StructuralBackingOwner {
    fn drop(&mut self) {
        self.retained
            .owner_retired
            .store(true, std::sync::atomic::Ordering::Release);
        let Some(custody) = self.custody.upgrade() else {
            return;
        };
        let identity = *self.retained.record_identity.lock();
        let _ = custody.request_stage2_record_retirement(identity);
    }
}

// SAFETY: StructuralBackingOwner owns a private, immutable host mmap region backing
// guest physical memory. Its fields and host memory pointers are sealed and immutable
// after publication. Access occurs only through Arc references while live, and final
// drop (munmap) occurs only when the last Arc drops.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Send for StructuralBackingOwner {}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Sync for StructuralBackingOwner {}

/// it per retirement / fault-path event measurably contended the 1000-process
/// exit storm, so the debug gates read this cache instead.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn fork_debug_ipa() -> Option<u64> {
    static CELL: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *CELL.get_or_init(|| {
        std::env::var("CARRICK_FORK_DEBUG_IPA")
            .ok()
            .and_then(|raw| u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok())
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn fork_debug_va() -> Option<u64> {
    static CELL: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *CELL.get_or_init(|| {
        std::env::var("CARRICK_FORK_DEBUG_VA")
            .ok()
            .and_then(|raw| u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok())
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) const COW_DIAGNOSTIC_HISTORY_LIMIT: usize = 256;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn cow_refusal_diagnostics_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("CARRICK_COW_REFUSAL_DIAGNOSTICS")
            .ok()
            .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "yes"))
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn cow_diagnostic_history() -> &'static parking_lot::Mutex<CowDiagnosticHistory> {
    static HISTORY: std::sync::OnceLock<parking_lot::Mutex<CowDiagnosticHistory>> =
        std::sync::OnceLock::new();
    HISTORY.get_or_init(|| parking_lot::Mutex::new(CowDiagnosticHistory::default()))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn finalize_global_frame_owner_record(
    custody: &CarrierVmCustody,
    owner: &GlobalFrameHostOwner,
) -> Result<(), TrapError> {
    finalize_global_frame_owner_record_using(custody, owner, &mut release_retired_stage2_ipa)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn finalize_global_frame_owner_record_using(
    custody: &CarrierVmCustody,
    owner: &GlobalFrameHostOwner,
    release_ipa: &mut dyn FnMut(u64, u64) -> Result<(), TrapError>,
) -> Result<(), TrapError> {
    finalize_terminal_stage2_record_using(custody, owner.record_identity, release_ipa)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn finalize_terminal_stage2_record_using(
    custody: &CarrierVmCustody,
    identity: CarrierStage2RecordIdentity,
    release_ipa: &mut dyn FnMut(u64, u64) -> Result<(), TrapError>,
) -> Result<(), TrapError> {
    let claim = custody
        .claim_terminal_stage2_release(identity)
        .map_err(|error| {
            TrapError::Hypervisor(format!("claim global owner terminal release: {error:?}"))
        })?;
    if let Some((ipa, length)) = claim {
        if let Err(error) = release_ipa(ipa, length) {
            custody.abort_terminal_stage2_release(identity);
            return Err(error);
        }
        custody.commit_terminal_stage2_release(identity);
    }
    custody
        .structural_backings
        .lock()
        .remove(&identity.record_id);
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn retry_structural_backing_retirements_in_using(
    custody: &CarrierVmCustody,
    unmap: &mut dyn FnMut(u64, usize) -> Result<(), CarrierStage2BackendError>,
    release_ipa: &mut dyn FnMut(u64, u64) -> Result<(), TrapError>,
) -> Result<(), TrapError> {
    let retained = custody
        .structural_backings
        .lock()
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let identities = retained
        .iter()
        .map(|retained| *retained.record_identity.lock())
        .collect::<Vec<_>>();
    retry_structural_backing_identities_in_using(custody, &identities, unmap, release_ipa)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn rollback_partial_process_stage2_authorities(
    custody: &CarrierVmCustody,
    stage2_leases: &mut [GlobalFrameStage2Lease],
    registered_global_owners: &[(u64, u64, u64)],
    structural_identities: &[CarrierStage2RecordIdentity],
    structural_owners: std::collections::BTreeMap<
        (u64, usize),
        std::sync::Arc<StructuralBackingOwner>,
    >,
) -> Result<(), TrapError> {
    let mut rollback_error = None;
    for lease in stage2_leases {
        if let Err(error) = lease.try_retire() {
            rollback_error.get_or_insert(error);
        }
    }
    for &(ipa, length, generation) in registered_global_owners {
        let outcome =
            retire_global_frame_host_owner_if_generation_in(custody, ipa, length, generation);
        if !outcome.is_retired() {
            rollback_error.get_or_insert_with(|| {
                TrapError::Hypervisor(format!(
                    "partial process owner rollback deferred: {outcome:?}"
                ))
            });
        }
    }

    // The structural record becomes retry-eligible only when the final owner
    // Arc drops. Drive that exact custody identity to terminal state before a
    // PreparedStage1Mm can return its numeric root slot to the pool.
    drop(structural_owners);
    for &identity in structural_identities {
        if let Err(error) = retry_structural_backing_identities_in_using(
            custody,
            &[identity],
            &mut unmap_global_frame_stage2_record,
            &mut release_retired_stage2_ipa,
        ) {
            rollback_error.get_or_insert(error);
        }
        if let Some(snapshot) = custody.stage2_record_snapshot(identity.record_id) {
            rollback_error.get_or_insert_with(|| {
                TrapError::Hypervisor(format!(
                    "exact partial process structural rollback remained nonterminal: {snapshot:?}"
                ))
            });
        }
    }
    rollback_error.map_or(Ok(()), Err)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn fail_stop_partial_process_stage2_rollback(context: &str, error: &TrapError) -> ! {
    eprintln!(
        "carrick: FATAL: {context}: structural stage-2 rollback could not terminalize before root-slot release: {error}"
    );
    #[cfg(test)]
    std::panic::resume_unwind(Box::new(
        "test carrier fail-stop after nonterminal structural stage-2 rollback",
    ));
    #[cfg(not(test))]
    carrick_fatal!(
        "hvpatch::mm_authority",
        "{context}: structural stage-2 rollback could not terminalize before root-slot release: {error}"
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn retry_structural_backing_identities_in_using(
    custody: &CarrierVmCustody,
    identities: &[CarrierStage2RecordIdentity],
    unmap: &mut dyn FnMut(u64, usize) -> Result<(), CarrierStage2BackendError>,
    release_ipa: &mut dyn FnMut(u64, u64) -> Result<(), TrapError>,
) -> Result<(), TrapError> {
    for &identity in identities {
        let Some(retained) = custody
            .structural_backings
            .lock()
            .get(&identity.record_id)
            .cloned()
        else {
            continue;
        };
        if custody.stage2_record_snapshot(identity.record_id).is_none() {
            continue;
        }
        if !retained
            .owner_retired
            .load(std::sync::atomic::Ordering::Acquire)
        {
            continue;
        }
        match custody.retire_stage2_record_using(identity, &mut *unmap) {
            CarrierStage2RetireOutcome::RetiredUnmapped
            | CarrierStage2RetireOutcome::TerminalizedByVmDestroy => {
                finalize_terminal_stage2_record_using(custody, identity, release_ipa)?;
            }
            CarrierStage2RetireOutcome::DeferredActivePins => {}
            outcome => {
                return Err(TrapError::Hypervisor(format!(
                    "retire structural backing at explicit safe point: {outcome:?}"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GlobalFrameReplayExtent {
    pub(crate) ipa: u64,
    pub(crate) length: u64,
    pub(crate) host_addr: usize,
    pub(crate) perms: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl GlobalFrameReplayExtent {
    pub(crate) fn key(self) -> (u64, u64) {
        (self.ipa, self.length)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct GlobalFrameReplayReconcileReport {
    pub(crate) rebound: usize,
    pub(crate) retired: usize,
    pub(crate) deferred: usize,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn reconcile_global_frame_owners_after_replay_in(
    custody: &std::sync::Arc<CarrierVmCustody>,
    replayed: &[GlobalFrameReplayExtent],
    retire_unreplayed: bool,
) -> Result<GlobalFrameReplayReconcileReport, TrapError> {
    reconcile_global_frame_owners_after_replay_in_using(
        custody,
        replayed,
        retire_unreplayed,
        &mut release_retired_stage2_ipa,
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn finalize_carrier_exit_global_frame_owners_in(
    custody: &std::sync::Arc<CarrierVmCustody>,
) -> Result<(), TrapError> {
    finalize_carrier_exit_global_frame_owners_in_using(custody, &mut release_retired_stage2_ipa)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn finalize_carrier_exit_global_frame_owners_in_using(
    custody: &std::sync::Arc<CarrierVmCustody>,
    release_ipa: &mut dyn FnMut(u64, u64) -> Result<(), TrapError>,
) -> Result<(), TrapError> {
    let report = reconcile_global_frame_owners_after_replay_in_using(
        custody,
        &[],
        true,
        release_ipa,
    )
    .map_err(|error| {
        TrapError::Hypervisor(format!(
            "carrier-exit terminal global frame cleanup after successful VM destroy failed: {error}"
        ))
    })?;
    if report.deferred != 0 {
        return Err(TrapError::Hypervisor(format!(
            "carrier-exit terminal global frame cleanup deferred {} pinned owner(s)",
            report.deferred
        )));
    }
    let carrier_records = custody
        .carrier_stage2_records
        .lock()
        .iter()
        .map(|(&key, &identity)| (key, identity))
        .collect::<Vec<_>>();
    for (key, identity) in carrier_records {
        let snapshot = custody
            .stage2_record_snapshot(identity.record_id)
            .ok_or_else(|| {
                TrapError::Hypervisor(
                    "carrier-exit carrier-MM stage-2 record disappeared".to_owned(),
                )
            })?;
        if !snapshot.terminalized_by_vm_destroy || snapshot.pin_count != 0 {
            return Err(TrapError::Hypervisor(format!(
                "carrier-exit carrier-MM terminal cleanup deferred IPA 0x{:x} size {}",
                key.0, key.1
            )));
        }
        finalize_terminal_stage2_record_using(custody, identity, release_ipa)?;
        custody.carrier_stage2_records.lock().remove(&key);
    }
    for identity in custody.stage2_record_identities() {
        let snapshot = custody
            .stage2_record_snapshot(identity.record_id)
            .ok_or_else(|| {
                TrapError::Hypervisor("carrier-exit detached stage-2 record disappeared".to_owned())
            })?;
        if !snapshot.terminalized_by_vm_destroy || snapshot.pin_count != 0 {
            return Err(TrapError::Hypervisor(format!(
                "carrier-exit detached terminal cleanup deferred IPA 0x{:x} size {}",
                snapshot.ipa, snapshot.len
            )));
        }
        finalize_terminal_stage2_record_using(custody, identity, release_ipa)?;
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn reconcile_global_frame_owners_after_replay_in_using(
    custody: &std::sync::Arc<CarrierVmCustody>,
    replayed: &[GlobalFrameReplayExtent],
    retire_unreplayed: bool,
    release_ipa: &mut dyn FnMut(u64, u64) -> Result<(), TrapError>,
) -> Result<GlobalFrameReplayReconcileReport, TrapError> {
    let mut replayed_by_key = std::collections::BTreeMap::new();
    for extent in replayed.iter().copied() {
        if replayed_by_key.insert(extent.key(), extent).is_some() {
            return Err(TrapError::Hypervisor(
                "global frame replay contains duplicate extents".to_owned(),
            ));
        }
    }
    let entries = custody
        .global_frame_host_owners
        .lock()
        .iter()
        .map(|(&key, entry)| (key, entry.is_live(), std::sync::Arc::clone(entry.owner())))
        .collect::<Vec<_>>();
    let mut report = GlobalFrameReplayReconcileReport::default();

    for (key, was_live, owner) in entries {
        let replay = replayed_by_key.get(&key).copied();
        if let (true, Some(replay)) = (was_live, replay) {
            if replay.host_addr != owner.host_addr() {
                return Err(TrapError::Hypervisor(format!(
                    "global frame replay host drift at IPA 0x{:x} size {}: expected=0x{:x} actual=0x{:x}",
                    key.0,
                    key.1,
                    owner.host_addr(),
                    replay.host_addr,
                )));
            }
            let old_snapshot = custody
                .stage2_record_snapshot(owner.record_identity.record_id)
                .ok_or_else(|| {
                    TrapError::Hypervisor("global frame replay owner record disappeared".to_owned())
                })?;
            if (
                old_snapshot.ipa,
                old_snapshot.len as u64,
                old_snapshot.host_addr,
            ) != (key.0, key.1, replay.host_addr)
            {
                return Err(TrapError::Hypervisor(
                    "global frame replay record extent identity drifted".to_owned(),
                ));
            }
            if old_snapshot.perms != replay.perms {
                return Err(TrapError::Hypervisor(format!(
                    "global frame replay permission drift at IPA 0x{:x} size {}: expected=0x{:x} actual=0x{:x}",
                    key.0, key.1, old_snapshot.perms, replay.perms
                )));
            }
            if old_snapshot.vm_generation
                == custody.setup_generation().ok_or_else(|| {
                    TrapError::Hypervisor(
                        "global frame replay has no creating/live VM generation".to_owned(),
                    )
                })?
                && old_snapshot.mapped
            {
                continue;
            }
            let mut owners = custody.global_frame_host_owners.lock();
            let current = owners.get(&key).ok_or_else(|| {
                TrapError::Hypervisor("global frame owner disappeared during rebind".to_owned())
            })?;
            if !current.is_live() || !std::sync::Arc::ptr_eq(current.owner(), &owner) {
                return Err(TrapError::Hypervisor(
                    "global frame owner changed during replay rebind".to_owned(),
                ));
            }
            let new_identity = custody
                .rebind_terminal_stage2_record(
                    owner.record_identity,
                    replay.host_addr,
                    replay.perms,
                )
                .map_err(|error| {
                    TrapError::Hypervisor(format!(
                        "rebind global frame owner after VM replay: {error:?}"
                    ))
                })?;
            let successor = std::sync::Arc::new(GlobalFrameHostOwner::from_record(
                std::sync::Arc::clone(&owner.mapping),
                std::sync::Arc::clone(custody),
                new_identity,
            ));
            owners.insert(key, GlobalFrameOwnerEntry::Live(successor));
            drop(owners);
            let _ = custody.remove_terminal_stage2_record(owner.record_identity);
            report.rebound += 1;
            continue;
        }

        if was_live && !retire_unreplayed {
            return Err(TrapError::Hypervisor(format!(
                "live global frame owner IPA 0x{:x} size {} was not replayed into the current VM",
                key.0, key.1
            )));
        }
        if replay.is_some() {
            return Err(TrapError::Hypervisor(format!(
                "retired global frame owner IPA 0x{:x} size {} was replayed",
                key.0, key.1
            )));
        }

        let snapshot = custody
            .stage2_record_snapshot(owner.record_identity.record_id)
            .ok_or_else(|| {
                TrapError::Hypervisor("retired global frame owner record disappeared".to_owned())
            })?;
        if !snapshot.terminalized_by_vm_destroy {
            return Err(TrapError::Hypervisor(
                "unreplayed global frame owner is not terminalized by VM destroy".to_owned(),
            ));
        }
        if snapshot.pin_count != 0 {
            let owner_generation = owner.generation();
            custody.global_frame_host_owners.lock().insert(
                key,
                GlobalFrameOwnerEntry::RetirementPending {
                    owner,
                    error: None,
                    in_flight: false,
                },
            );
            custody.enqueue_directory_global_frame_retirement(key, owner_generation);
            report.deferred += 1;
            continue;
        }
        finalize_global_frame_owner_record_using(custody, &owner, release_ipa)?;
        let mut owners = custody.global_frame_host_owners.lock();
        if owners
            .get(&key)
            .is_some_and(|entry| std::sync::Arc::ptr_eq(entry.owner(), &owner))
        {
            owners.remove(&key);
        }
        report.retired += 1;
    }

    let detached = custody
        .pending_global_frame_owners
        .lock()
        .values()
        .cloned()
        .collect::<Vec<_>>();
    for owner in detached {
        let Some(snapshot) = custody.stage2_record_snapshot(owner.record_identity.record_id) else {
            custody
                .pending_global_frame_owners
                .lock()
                .remove(&owner.record_identity.record_id);
            custody
                .pending_global_frame_detached_retries
                .lock()
                .complete(owner.record_identity.record_id);
            continue;
        };
        if !snapshot.terminalized_by_vm_destroy || snapshot.pin_count != 0 {
            report.deferred += 1;
            continue;
        }
        finalize_global_frame_owner_record_using(custody, &owner, release_ipa)?;
        custody
            .pending_global_frame_owners
            .lock()
            .remove(&owner.record_identity.record_id);
        custody
            .pending_global_frame_detached_retries
            .lock()
            .complete(owner.record_identity.record_id);
        report.retired += 1;
    }

    let carrier_records = custody
        .carrier_stage2_records
        .lock()
        .iter()
        .map(|(&key, &identity)| (key, identity))
        .collect::<Vec<_>>();
    for (key, old_identity) in carrier_records {
        let snapshot = custody
            .stage2_record_snapshot(old_identity.record_id)
            .ok_or_else(|| {
                TrapError::Hypervisor("carrier-MM replay stage-2 record disappeared".to_owned())
            })?;
        let replay = replayed_by_key.get(&key).copied();
        if let Some(replay) = replay {
            if (replay.host_addr, replay.perms) != (snapshot.host_addr, snapshot.perms) {
                return Err(TrapError::Hypervisor(format!(
                    "carrier-MM replay identity drift at IPA 0x{:x} size {}",
                    key.0, key.1
                )));
            }
            let current_generation = custody.setup_generation().ok_or_else(|| {
                TrapError::Hypervisor(
                    "carrier-MM replay has no creating/live VM generation".to_owned(),
                )
            })?;
            if snapshot.vm_generation == current_generation && snapshot.mapped {
                continue;
            }
            let new_identity = custody
                .rebind_terminal_stage2_record(old_identity, replay.host_addr, replay.perms)
                .map_err(|error| {
                    TrapError::Hypervisor(format!(
                        "rebind carrier-MM stage-2 record after VM replay: {error:?}"
                    ))
                })?;
            let mut records = custody.carrier_stage2_records.lock();
            if records.get(&key) != Some(&old_identity) {
                return Err(TrapError::Hypervisor(
                    "carrier-MM stage-2 owner changed during replay rebind".to_owned(),
                ));
            }
            records.insert(key, new_identity);
            drop(records);
            let _ = custody.remove_terminal_stage2_record(old_identity);
            report.rebound += 1;
            continue;
        }
        if !retire_unreplayed {
            return Err(TrapError::Hypervisor(format!(
                "live carrier-MM stage-2 record IPA 0x{:x} size {} was not replayed into the current VM",
                key.0, key.1
            )));
        }
        if !snapshot.terminalized_by_vm_destroy {
            return Err(TrapError::Hypervisor(
                "unreplayed carrier-MM stage-2 record is not terminalized by VM destroy".to_owned(),
            ));
        }
        finalize_terminal_stage2_record_using(custody, old_identity, release_ipa)?;
        let mut records = custody.carrier_stage2_records.lock();
        if records.get(&key) == Some(&old_identity) {
            records.remove(&key);
        }
        report.retired += 1;
    }

    let structural = custody
        .structural_backings
        .lock()
        .values()
        .cloned()
        .collect::<Vec<_>>();
    for retained in structural {
        let identity = *retained.record_identity.lock();
        let snapshot = custody
            .stage2_record_snapshot(identity.record_id)
            .ok_or_else(|| {
                TrapError::Hypervisor("structural backing stage-2 record disappeared".to_owned())
            })?;
        let key = (snapshot.ipa, snapshot.len as u64);
        let replay = replayed_by_key.get(&key).copied();

        if retained
            .owner_retired
            .load(std::sync::atomic::Ordering::Acquire)
        {
            if !snapshot.terminalized_by_vm_destroy {
                return Err(TrapError::Hypervisor(format!(
                    "retired structural backing IPA 0x{:x} size {} survived VM destroy",
                    key.0, key.1
                )));
            }
            finalize_terminal_stage2_record_using(custody, identity, release_ipa)?;
            report.retired += 1;
            continue;
        }
        if replay.is_none()
            && custody.setup_generation() == Some(snapshot.vm_generation)
            && snapshot.mapped
            && snapshot.backend_map_installed
            && !snapshot.retirement_requested
            && !snapshot.terminalized_by_vm_destroy
        {
            // A record installed directly while creating the current VM is
            // already authoritative stage-2 state, not a replay candidate.
            // Only an older/terminal/retiring or backend-disarmed record must
            // authenticate through an explicit replay extent below.
            continue;
        }
        if let Some(replay) = replay {
            if (replay.host_addr, replay.perms) != (snapshot.host_addr, snapshot.perms) {
                return Err(TrapError::Hypervisor(format!(
                    "structural backing replay identity drift at IPA 0x{:x} size {}",
                    key.0, key.1
                )));
            }
            let current_generation = custody.setup_generation().ok_or_else(|| {
                TrapError::Hypervisor(
                    "structural backing replay has no creating/live VM generation".to_owned(),
                )
            })?;
            if snapshot.vm_generation == current_generation && snapshot.mapped {
                continue;
            }
            let old_identity = identity;
            let new_identity = custody
                .rebind_terminal_stage2_record(old_identity, replay.host_addr, replay.perms)
                .map_err(|error| {
                    TrapError::Hypervisor(format!(
                        "rebind structural backing after VM replay: {error:?}"
                    ))
                })?;
            *retained.record_identity.lock() = new_identity;
            let mut retained_by_record = custody.structural_backings.lock();
            retained_by_record.remove(&old_identity.record_id);
            retained_by_record.insert(new_identity.record_id, std::sync::Arc::clone(&retained));
            drop(retained_by_record);
            let _ = custody.remove_terminal_stage2_record(old_identity);
            report.rebound += 1;
            continue;
        }
        if !retire_unreplayed {
            return Err(TrapError::Hypervisor(format!(
                "live structural backing IPA 0x{:x} size {} was not replayed into the current VM",
                key.0, key.1
            )));
        }
        if !snapshot.terminalized_by_vm_destroy {
            return Err(TrapError::Hypervisor(
                "unreplayed structural backing is not terminalized by VM destroy".to_owned(),
            ));
        }
        finalize_terminal_stage2_record_using(custody, identity, release_ipa)?;
        report.retired += 1;
    }
    Ok(report)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn retire_global_frame_host_owner_in(
    custody: &CarrierVmCustody,
    ipa: u64,
    length: u64,
) -> GlobalFrameRetirementOutcome {
    retire_global_frame_host_owner_inner_in(custody, ipa, length, None)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn retire_global_frame_host_owner_if_generation_in(
    custody: &CarrierVmCustody,
    ipa: u64,
    length: u64,
    expected_generation: u64,
) -> GlobalFrameRetirementOutcome {
    retire_global_frame_host_owner_if_generation_in_using(
        custody,
        ipa,
        length,
        expected_generation,
        &mut unmap_global_frame_stage2_record,
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn retire_global_frame_host_owner_inner_in(
    custody: &CarrierVmCustody,
    ipa: u64,
    length: u64,
    expected_generation: Option<u64>,
) -> GlobalFrameRetirementOutcome {
    retire_global_frame_host_owner_inner_in_using(
        custody,
        ipa,
        length,
        expected_generation,
        &mut unmap_global_frame_stage2_record,
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn retire_global_frame_host_owner_if_generation_in_using(
    custody: &CarrierVmCustody,
    ipa: u64,
    length: u64,
    expected_generation: u64,
    unmap: &mut dyn FnMut(u64, usize) -> Result<(), CarrierStage2BackendError>,
) -> GlobalFrameRetirementOutcome {
    retire_global_frame_host_owner_inner_in_using(
        custody,
        ipa,
        length,
        Some(expected_generation),
        unmap,
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn retire_global_frame_host_owner_inner_in_using(
    custody: &CarrierVmCustody,
    ipa: u64,
    length: u64,
    expected_generation: Option<u64>,
    unmap: &mut dyn FnMut(u64, usize) -> Result<(), CarrierStage2BackendError>,
) -> GlobalFrameRetirementOutcome {
    let outcome = (|| {
        // Lifecycle debug: CARRICK_FORK_DEBUG_IPA=<hex> logs every owner
        // retirement overlapping that IPA, with the caller. Retiring an owner
        // drops its OwnedHostMapping — macOS can recycle the host VA immediately —
        // so a retire while a live process still references the frame is the
        // scrubbed-shared-granule bug's trigger shape.
        if let Some(debug_ipa) = fork_debug_ipa()
            && ipa <= debug_ipa
            && debug_ipa < ipa.saturating_add(length)
        {
            eprintln!(
                "[FORKDBG] retire_global_frame_host_owner ipa={ipa:#x} len={length:#x}\n{}",
                std::backtrace::Backtrace::force_capture(),
            );
        }
        let key = (ipa, length);
        // Claim the exact directory slot before record retirement, but do not hold
        // the directory lock across the backend unmap. The backend also retires
        // replay/alias state, whose lock order can meet a concurrent semantic owner
        // lookup in the opposite direction. `RetirementPending` is the exclusive
        // publication: readers and successor registration reject it until this
        // transaction either removes the exact Arc or records a retryable failure.
        let mut owners = custody.global_frame_host_owners.lock();
        let owner = match owners.get(&key) {
            Some(GlobalFrameOwnerEntry::Live(owner))
            | Some(GlobalFrameOwnerEntry::RetirementPending {
                owner,
                in_flight: false,
                ..
            }) => std::sync::Arc::clone(owner),
            Some(entry) => {
                return GlobalFrameRetirementOutcome::RetryPending {
                    ipa,
                    length,
                    generation: entry.owner().generation(),
                    error: "global frame owner retirement is already claimed".to_owned(),
                };
            }
            None => return GlobalFrameRetirementOutcome::NotFound { ipa, length },
        };
        if let Some(expected) = expected_generation {
            if owner.generation() != expected {
                return GlobalFrameRetirementOutcome::MismatchedGeneration {
                    ipa,
                    length,
                    current_generation: owner.generation(),
                    expected_generation: expected,
                };
            }
        }
        let generation = owner.generation();
        if owner.mapping.pin_count() != 0 {
            let outcome = custody.request_stage2_record_retirement(owner.record_identity);
            if outcome != CarrierStage2RetireOutcome::DeferredActivePins {
                return GlobalFrameRetirementOutcome::RetryPending {
                    ipa,
                    length,
                    generation,
                    error: format!("carrier stage-2 retirement request failed: {outcome:?}"),
                };
            }
            owners.insert(
                (ipa, length),
                GlobalFrameOwnerEntry::RetirementPending {
                    owner,
                    error: None,
                    in_flight: false,
                },
            );
            return GlobalFrameRetirementOutcome::DeferredActivePins {
                ipa,
                length,
                generation,
            };
        }
        owners.insert(
            key,
            GlobalFrameOwnerEntry::RetirementPending {
                owner: std::sync::Arc::clone(&owner),
                error: None,
                in_flight: true,
            },
        );
        drop(owners);

        let outcome = custody.retire_stage2_record_using(owner.record_identity, unmap);
        let mut owners = custody.global_frame_host_owners.lock();
        if !matches!(
            owners.get(&key),
            Some(GlobalFrameOwnerEntry::RetirementPending {
                owner: pending,
                in_flight: true,
                ..
            }) if std::sync::Arc::ptr_eq(pending, &owner)
        ) {
            drop(owners);
            retain_pending_global_frame_owner(custody, std::sync::Arc::clone(&owner));
            return GlobalFrameRetirementOutcome::RetryPending {
                ipa,
                length,
                generation,
                error: "global frame owner changed during exact retirement".to_owned(),
            };
        }
        match outcome {
            CarrierStage2RetireOutcome::RetiredUnmapped
            | CarrierStage2RetireOutcome::TerminalizedByVmDestroy => {
                let terminalized =
                    matches!(outcome, CarrierStage2RetireOutcome::TerminalizedByVmDestroy);
                if let Err(error) = finalize_global_frame_owner_record(custody, &owner) {
                    owners.insert(
                        (ipa, length),
                        GlobalFrameOwnerEntry::RetirementPending {
                            owner,
                            error: Some(error.to_string()),
                            in_flight: false,
                        },
                    );
                    return GlobalFrameRetirementOutcome::RetryPending {
                        ipa,
                        length,
                        generation,
                        error: error.to_string(),
                    };
                }
                owners.remove(&key);
                if terminalized {
                    GlobalFrameRetirementOutcome::TerminalizedByVmDestroy {
                        ipa,
                        length,
                        generation,
                    }
                } else {
                    GlobalFrameRetirementOutcome::RetiredUnmapped {
                        ipa,
                        length,
                        generation,
                    }
                }
            }
            CarrierStage2RetireOutcome::DeferredActivePins => {
                owners.insert(
                    (ipa, length),
                    GlobalFrameOwnerEntry::RetirementPending {
                        owner,
                        error: None,
                        in_flight: false,
                    },
                );
                GlobalFrameRetirementOutcome::DeferredActivePins {
                    ipa,
                    length,
                    generation,
                }
            }
            CarrierStage2RetireOutcome::RetryPending(error) => {
                owners.insert(
                    (ipa, length),
                    GlobalFrameOwnerEntry::RetirementPending {
                        owner,
                        error: Some(format!("{error:?}")),
                        in_flight: false,
                    },
                );
                GlobalFrameRetirementOutcome::RetryPending {
                    ipa,
                    length,
                    generation,
                    error: format!("{error:?}"),
                }
            }
            unexpected => {
                let error = format!("carrier stage-2 record identity failure: {unexpected:?}");
                owners.insert(
                    key,
                    GlobalFrameOwnerEntry::RetirementPending {
                        owner,
                        error: Some(error.clone()),
                        in_flight: false,
                    },
                );
                GlobalFrameRetirementOutcome::RetryPending {
                    ipa,
                    length,
                    generation,
                    error,
                }
            }
        }
    })();
    match outcome {
        GlobalFrameRetirementOutcome::DeferredActivePins {
            ipa,
            length,
            generation,
        }
        | GlobalFrameRetirementOutcome::RetryPending {
            ipa,
            length,
            generation,
            ..
        } => custody.enqueue_directory_global_frame_retirement((ipa, length), generation),
        GlobalFrameRetirementOutcome::RetiredUnmapped {
            ipa,
            length,
            generation,
        }
        | GlobalFrameRetirementOutcome::TerminalizedByVmDestroy {
            ipa,
            length,
            generation,
        } => custody
            .pending_global_frame_directory_retries
            .lock()
            .complete(((ipa, length), generation)),
        _ => {}
    }
    record_cow_diagnostic_event(CowDiagnosticEvent::Retirement {
        custody: custody as *const CarrierVmCustody as usize,
        ipa,
        length,
        expected_generation,
        outcome: CowDiagnosticRetirementOutcome::from(&outcome),
    });
    outcome
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn drain_and_retry_pending_global_frame_retirements_in(
    custody: &CarrierVmCustody,
) -> Result<(), TrapError> {
    drain_all_global_frame_retirements_in_using(custody, &mut unmap_global_frame_stage2_record)
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn drain_all_global_frame_retirements_in_using(
    custody: &CarrierVmCustody,
    unmap: &mut dyn FnMut(u64, usize) -> Result<(), CarrierStage2BackendError>,
) -> Result<(), TrapError> {
    let directory = custody
        .global_frame_host_owners
        .lock()
        .iter()
        .filter_map(|(&key, entry)| entry.is_live().then_some((key, entry.owner().generation())))
        .collect::<Vec<_>>();
    for ((ipa, length), generation) in directory {
        let _ = retire_global_frame_host_owner_inner_in_using(
            custody,
            ipa,
            length,
            Some(generation),
            unmap,
        );
    }

    // A carrier safe point is also the explicit retry point for directory and
    // collision candidates whose first retirement attempt was deferred.
    let _ = retry_pending_global_frame_retirements_in_using(custody, unmap);
    let directory_remaining = custody.global_frame_host_owners.lock().len();
    let collision_remaining = custody.pending_global_frame_owners.lock().len();
    if directory_remaining == 0 && collision_remaining == 0 {
        Ok(())
    } else {
        Err(TrapError::Hypervisor(format!(
            "global frame host owner custody has {directory_remaining} directory and {collision_remaining} collision entries remaining at carrier drain"
        )))
    }
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn retry_pending_global_frame_retirements_in_using(
    custody: &CarrierVmCustody,
    unmap: &mut dyn FnMut(u64, usize) -> Result<(), CarrierStage2BackendError>,
) -> Result<(), TrapError> {
    let pending_directory = custody
        .global_frame_host_owners
        .lock()
        .iter()
        .filter_map(|(&key, entry)| match entry {
            GlobalFrameOwnerEntry::RetirementPending {
                owner,
                in_flight: false,
                ..
            } => Some((key, owner.generation())),
            GlobalFrameOwnerEntry::Live(_)
            | GlobalFrameOwnerEntry::RetirementPending {
                in_flight: true, ..
            } => None,
        })
        .collect::<Vec<_>>();
    for ((ipa, length), generation) in pending_directory {
        let _ = retire_global_frame_host_owner_inner_in_using(
            custody,
            ipa,
            length,
            Some(generation),
            unmap,
        );
    }

    let detached = custody
        .pending_global_frame_owners
        .lock()
        .values()
        .cloned()
        .collect::<Vec<_>>();
    for owner in detached {
        let outcome = custody.retire_stage2_record_using(owner.record_identity, &mut *unmap);
        if matches!(
            outcome,
            CarrierStage2RetireOutcome::RetiredUnmapped
                | CarrierStage2RetireOutcome::TerminalizedByVmDestroy
        ) && finalize_global_frame_owner_record(custody, &owner).is_ok()
        {
            custody
                .pending_global_frame_owners
                .lock()
                .remove(&owner.record_identity.record_id);
        }
    }

    let directory_pending = custody
        .global_frame_host_owners
        .lock()
        .values()
        .filter(|entry| entry.is_pending())
        .count();
    let detached_pending = custody.pending_global_frame_owners.lock().len();
    if directory_pending == 0 && detached_pending == 0 {
        Ok(())
    } else {
        Err(TrapError::Hypervisor(format!(
            "global frame host owner custody has {directory_pending} directory and {detached_pending} collision entries pending retirement"
        )))
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const PENDING_GLOBAL_FRAME_RETIREMENTS_PER_IDLE_TURN: usize = 32;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const PENDING_GLOBAL_FRAME_RETIREMENTS_PER_CLASS_PER_IDLE_TURN: usize =
    PENDING_GLOBAL_FRAME_RETIREMENTS_PER_IDLE_TURN / 2;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct PendingGlobalFrameRetirementQueue<K: Copy + Ord> {
    next_sequence: u64,
    by_sequence: std::collections::BTreeMap<u64, K>,
    by_item: std::collections::BTreeMap<K, Option<u64>>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl<K: Copy + Ord> Default for PendingGlobalFrameRetirementQueue<K> {
    fn default() -> Self {
        Self {
            next_sequence: 1,
            by_sequence: std::collections::BTreeMap::new(),
            by_item: std::collections::BTreeMap::new(),
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl<K: Copy + Ord> PendingGlobalFrameRetirementQueue<K> {
    fn allocate_sequence(&mut self) -> u64 {
        loop {
            let sequence = self.next_sequence;
            self.next_sequence = self.next_sequence.wrapping_add(1);
            if !self.by_sequence.contains_key(&sequence) {
                return sequence;
            }
        }
    }

    pub(crate) fn enqueue(&mut self, item: K) {
        if !self.by_item.contains_key(&item) {
            let sequence = self.allocate_sequence();
            self.by_sequence.insert(sequence, item);
            self.by_item.insert(item, Some(sequence));
        }
    }

    fn pop_front(&mut self) -> Option<K> {
        let (_, item) = self.by_sequence.pop_first()?;
        self.by_item.insert(item, None);
        Some(item)
    }

    fn requeue(&mut self, item: K) {
        if self.by_item.get(&item) == Some(&None) {
            let sequence = self.allocate_sequence();
            self.by_sequence.insert(sequence, item);
            self.by_item.insert(item, Some(sequence));
        }
    }

    fn complete(&mut self, item: K) {
        if let Some(Some(sequence)) = self.by_item.remove(&item) {
            self.by_sequence.remove(&sequence);
        }
    }

    fn len(&self) -> usize {
        self.by_item.len()
    }

    #[cfg(test)]
    pub(crate) fn storage_len(&self) -> usize {
        self.by_sequence.len()
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PendingGlobalFrameRetirementTurnReport {
    pub(crate) remaining: usize,
    pub(crate) inspected_directory: usize,
    pub(crate) inspected_detached: usize,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PartialEq<usize> for PendingGlobalFrameRetirementTurnReport {
    fn eq(&self, other: &usize) -> bool {
        self.remaining == *other
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn retain_pending_global_frame_owner(
    custody: &CarrierVmCustody,
    owner: std::sync::Arc<GlobalFrameHostOwner>,
) {
    let record_id = owner.record_identity.record_id;
    custody
        .pending_global_frame_owners
        .lock()
        .insert(record_id, owner);
    custody.enqueue_detached_global_frame_retirement(record_id);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct PendingGlobalFrameRetirementTurn<'a>(&'a CarrierVmCustody);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for PendingGlobalFrameRetirementTurn<'_> {
    fn drop(&mut self) {
        self.0
            .pending_global_frame_retirement_turn_in_flight
            .store(false, std::sync::atomic::Ordering::Release);
    }
}

/// Perform one bounded carrier-idle retry turn. The caller is the named
/// persistent-executor idle boundary, after task/binding/topology authority has
/// been released. Failed or excess work remains explicitly requested for the
/// next idle turn.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn retry_pending_global_frame_retirements_at_idle_in_using(
    custody: &CarrierVmCustody,
    unmap: &mut dyn FnMut(u64, usize) -> Result<(), CarrierStage2BackendError>,
) -> PendingGlobalFrameRetirementTurnReport {
    if !custody.take_global_frame_retirement_retry_request() {
        return PendingGlobalFrameRetirementTurnReport::default();
    }
    if custody
        .pending_global_frame_retirement_turn_in_flight
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .is_err()
    {
        custody.request_global_frame_retirement_retry();
        return PendingGlobalFrameRetirementTurnReport {
            remaining: custody.pending_global_frame_directory_retries.lock().len()
                + custody.pending_global_frame_detached_retries.lock().len(),
            ..PendingGlobalFrameRetirementTurnReport::default()
        };
    }
    let _turn = PendingGlobalFrameRetirementTurn(custody);
    let mut report = PendingGlobalFrameRetirementTurnReport::default();
    let directory_attempts = custody
        .pending_global_frame_directory_retries
        .lock()
        .len()
        .min(PENDING_GLOBAL_FRAME_RETIREMENTS_PER_CLASS_PER_IDLE_TURN);
    for _ in 0..directory_attempts {
        let Some((key @ (ipa, length), generation)) = custody
            .pending_global_frame_directory_retries
            .lock()
            .pop_front()
        else {
            break;
        };
        report.inspected_directory += 1;
        let exact_retryable = custody
            .global_frame_host_owners
            .lock()
            .get(&key)
            .is_some_and(|entry| {
                matches!(entry, GlobalFrameOwnerEntry::RetirementPending { owner, in_flight: false, .. }
                    if owner.generation() == generation)
            });
        if !exact_retryable {
            custody
                .pending_global_frame_directory_retries
                .lock()
                .complete((key, generation));
            continue;
        }
        let outcome = retire_global_frame_host_owner_inner_in_using(
            custody,
            ipa,
            length,
            Some(generation),
            unmap,
        );
        let mut retries = custody.pending_global_frame_directory_retries.lock();
        if matches!(
            outcome,
            GlobalFrameRetirementOutcome::DeferredActivePins { .. }
                | GlobalFrameRetirementOutcome::RetryPending { .. }
        ) {
            retries.requeue((key, generation));
        } else {
            retries.complete((key, generation));
        }
    }

    let detached_attempts = custody
        .pending_global_frame_detached_retries
        .lock()
        .len()
        .min(PENDING_GLOBAL_FRAME_RETIREMENTS_PER_CLASS_PER_IDLE_TURN);
    for _ in 0..detached_attempts {
        let Some(record_id) = custody
            .pending_global_frame_detached_retries
            .lock()
            .pop_front()
        else {
            break;
        };
        report.inspected_detached += 1;
        let Some(owner) = custody
            .pending_global_frame_owners
            .lock()
            .get(&record_id)
            .cloned()
        else {
            custody
                .pending_global_frame_detached_retries
                .lock()
                .complete(record_id);
            continue;
        };
        let outcome = custody.retire_stage2_record_using(owner.record_identity, &mut *unmap);
        let completed = matches!(
            outcome,
            CarrierStage2RetireOutcome::RetiredUnmapped
                | CarrierStage2RetireOutcome::TerminalizedByVmDestroy
        ) && finalize_global_frame_owner_record(custody, &owner).is_ok();
        if completed {
            custody
                .pending_global_frame_owners
                .lock()
                .remove(&record_id);
            custody
                .pending_global_frame_detached_retries
                .lock()
                .complete(record_id);
        } else {
            custody
                .pending_global_frame_detached_retries
                .lock()
                .requeue(record_id);
        }
    }

    report.remaining = custody.pending_global_frame_directory_retries.lock().len()
        + custody.pending_global_frame_detached_retries.lock().len();
    if report.remaining != 0 {
        custody.request_global_frame_retirement_retry();
    }
    report
}

/// Authenticate a non-owning mapping/alias row against the exact live global
/// owner, not merely against the current host VM map.
///
/// Dynamic rows deliberately outlive individual COW generations in per-vCPU
/// metadata. After the last logical reference retires, macOS may immediately
/// recycle that host VA for an unrelated frame. A `mach_vm_region` liveness
/// query would then accept the stale pointer and let anonymous-reuse zeroing
/// scrub the unrelated allocation. The `(IPA, length, host pointer)` triple is
/// the owning lease identity and therefore the only safe HVPatch predicate.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn global_frame_host_owner_matches_in(
    custody: &CarrierVmCustody,
    ipa: u64,
    length: u64,
    host_addr: usize,
    generation: u64,
) -> bool {
    let owner = custody
        .global_frame_host_owners
        .lock()
        .get(&(ipa, length))
        .map(|entry| match entry {
            GlobalFrameOwnerEntry::Live(owner) => Some((owner.host_addr(), owner.generation())),
            GlobalFrameOwnerEntry::RetirementPending { .. } => None,
        });
    // The GENERATION is what turns this into an identity. Without it the triple
    // re-authenticates against a DIFFERENT incarnation of the same recycled
    // `(IPA, length, host VA)`, which is measured to happen every single time.
    //
    // A row stamped with 0 was published while NOTHING owned its extent
    // (`global_frame_host_owner_generation` returns 0 when unowned), so it keeps
    // the historical pointer-only behaviour — tightening those to "no match"
    // unmapped the syscall mailbox and killed the guest outright. Where a row
    // DOES carry an incarnation, that incarnation must be the live one.
    let matches = match (owner, generation) {
        // Owned extent: the row must name that exact host mapping, and — when
        // it recorded an incarnation — that exact incarnation.
        (Some(Some((owner_host_addr, owner_generation))), _) => {
            owner_host_addr != 0
                && owner_host_addr == host_addr
                && (generation == 0 || owner_generation == generation)
        }
        // A pending extent still owns its host mapping for rollback/retry, but
        // it is no longer live authority and cannot authenticate new access.
        (Some(None), _) => false,
        // Unowned extent and a row that recorded no incarnation either. This
        // predicate has no owner to authenticate against, and absence of an
        // authority is not a rejection: it is the same unowned state the row was
        // published in. A forked child inherits its kernel regions — the
        // identity page among them — exactly like this, and rejecting them here
        // failed every child's identity stamp inside
        // `validate_guest_write_range` as a spurious out-of-bounds.
        (None, 0) => true,
        // The row recorded an incarnation, so an owner existed when it was
        // published and has since retired. macOS may have recycled the host VA
        // under it, so the row is stale and must not authenticate.
        (None, _) => false,
    };
    if !matches {
        crate::probes::hvpatch_global_frame_owner_miss(
            ipa,
            length,
            host_addr as u64,
            owner
                .flatten()
                .map_or(0, |(owner_host_addr, _)| owner_host_addr) as u64,
        );
    }
    matches
}

/// Copy through the exact currently-owned reusable frame selected by a live
/// stage-1 leaf. The owner lock pins both the host mapping and its generation
/// for the duration of the copy; absence is authoritative failure, never a
/// reason to dereference a retired per-vCPU descriptor.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn copy_from_global_frame_owner_in(
    custody: &CarrierVmCustody,
    ipa: u64,
    dst: &mut [u8],
) -> Option<(u64, u64)> {
    let length = u64::try_from(dst.len()).ok()?;
    let end = ipa.checked_add(length)?;
    let owners = custody.global_frame_host_owners.lock();
    let (&(owner_ipa, owner_length), owner) =
        owners.iter().find_map(|(key @ (base, size), entry)| {
            if ipa < *base || end > base.saturating_add(*size) {
                return None;
            }
            match entry {
                GlobalFrameOwnerEntry::Live(owner) => Some((key, owner)),
                GlobalFrameOwnerEntry::RetirementPending { .. } => None,
            }
        })?;
    let offset = usize::try_from(ipa.checked_sub(owner_ipa)?).ok()?;
    let host = owner.as_ptr();
    unsafe {
        volatile_copy_from_guest(host.add(offset), dst.as_mut_ptr(), dst.len());
    }
    Some((owner_ipa, owner_ipa.saturating_add(owner_length)))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn is_reusable_global_frame_extent(ipa: u64, length: u64) -> bool {
    let base = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE;
    let end = base.saturating_add(carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_SIZE);
    ipa >= base
        && ipa
            .checked_add(length)
            .is_some_and(|extent_end| extent_end <= end)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn mapped_region_stage2_owner_identity(
    mapping: &HvfMappedRegion,
) -> Option<InventoryStage2OwnerIdentity> {
    let semantic_offset = usize::try_from(mapping.ipa.checked_sub(mapping.physical_ipa)?).ok()?;
    let host_addr = (mapping.host_addr as usize).checked_sub(semantic_offset)?;
    Some(InventoryStage2OwnerIdentity {
        host_addr,
        generation: mapping.owner_generation,
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn replayed_global_frame_owners_for_regions_in<'a>(
    custody: &CarrierVmCustody,
    regions: impl Iterator<Item = &'a HvfMappedRegion>,
) -> Vec<GlobalFrameReplayExtent> {
    let owners = custody.global_frame_host_owners.lock();
    let mut replayed = std::collections::BTreeMap::new();
    for mapping in regions {
        let Some(identity) = mapped_region_stage2_owner_identity(mapping) else {
            continue;
        };
        let key = (mapping.physical_ipa, mapping.physical_size as u64);
        if owners
            .get(&key)
            .is_some_and(|entry| entry.is_live() && entry.owner().host_addr() == identity.host_addr)
        {
            replayed.entry(key).or_insert(GlobalFrameReplayExtent {
                ipa: key.0,
                length: key.1,
                host_addr: identity.host_addr,
                perms: u64::from(mapping.perms),
            });
        }
    }
    replayed.into_values().collect()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn global_frame_region_owner_matches_in(
    custody: &CarrierVmCustody,
    mapping: &HvfMappedRegion,
) -> bool {
    let Some(identity) = mapped_region_stage2_owner_identity(mapping) else {
        return false;
    };
    let locally_owned = mapping.host_mapping.as_ref().is_some_and(|owner| {
        owner.as_ptr() as usize == identity.host_addr && owner.len() == mapping.physical_size
    }) && mapping.stage2_lease.as_ref().is_some_and(|lease| {
        lease.active
            && lease.mapped
            && lease.key() == (mapping.physical_ipa, mapping.physical_size as u64)
    });
    if locally_owned {
        return true;
    }
    global_frame_host_owner_matches_in(
        custody,
        mapping.physical_ipa,
        mapping.physical_size as u64,
        identity.host_addr,
        identity.generation,
    )
}

// Legacy fixtures share one directory only inside this test binary. Production
// code cannot name these adapters because they do not exist in a non-test build.
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn global_frame_host_owner_generation(ipa: u64, length: u64) -> u64 {
    global_frame_host_owner_generation_in(legacy_test_carrier_vm_custody(), ipa, length)
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn global_frame_host_owner_identity(ipa: u64, length: u64) -> Option<(usize, u64)> {
    global_frame_host_owner_identity_in(legacy_test_carrier_vm_custody(), ipa, length)
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn register_global_frame_host_owner(
    lease: GlobalFrameStage2Lease,
    mapping: crate::host_mapping::OwnedHostMapping,
    perms: u64,
) -> Result<u64, TrapError> {
    register_global_frame_host_owner_in(legacy_test_carrier_vm_custody_arc(), lease, mapping, perms)
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn publish_exec_region_host_owner(
    region: &mut HvfMappedRegion,
    lease: GlobalFrameStage2Lease,
) -> Result<u64, TrapError> {
    publish_exec_region_host_owner_in(legacy_test_carrier_vm_custody_arc(), region, lease, None)
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn retire_global_frame_host_owner(
    ipa: u64,
    length: u64,
) -> GlobalFrameRetirementOutcome {
    retire_global_frame_host_owner_in(legacy_test_carrier_vm_custody(), ipa, length)
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn retire_global_frame_host_owner_if_generation(
    ipa: u64,
    length: u64,
    generation: u64,
) -> GlobalFrameRetirementOutcome {
    retire_global_frame_host_owner_if_generation_in(
        legacy_test_carrier_vm_custody(),
        ipa,
        length,
        generation,
    )
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn drain_and_retry_pending_global_frame_retirements() -> Result<(), TrapError> {
    drain_and_retry_pending_global_frame_retirements_in(legacy_test_carrier_vm_custody())
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn global_frame_host_owner_matches(
    ipa: u64,
    length: u64,
    host_addr: usize,
    generation: u64,
) -> bool {
    global_frame_host_owner_matches_in(
        legacy_test_carrier_vm_custody(),
        ipa,
        length,
        host_addr,
        generation,
    )
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn global_frame_region_owner_matches(mapping: &HvfMappedRegion) -> bool {
    global_frame_region_owner_matches_in(legacy_test_carrier_vm_custody(), mapping)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
/// Exact installed stage-2 replay identity: physical IPA, size, host address,
/// permissions and reusable-owner generation. The generation is load-bearing:
/// after an old COW releases an IPA, delayed semantic cleanup must not erase a
/// successor incarnation that reused the same extent (or even the same host VA).
pub(crate) type ReplayMappingKey = (u64, usize, usize, u64, u64);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn replay_mappings()
-> &'static parking_lot::Mutex<std::collections::BTreeSet<ReplayMappingKey>> {
    static CELL: std::sync::OnceLock<
        parking_lot::Mutex<std::collections::BTreeSet<ReplayMappingKey>>,
    > = std::sync::OnceLock::new();
    CELL.get_or_init(|| parking_lot::Mutex::new(std::collections::BTreeSet::new()))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn replay_mapping_key(backing: AliasBacking) -> ReplayMappingKey {
    (
        backing.physical_ipa,
        backing.physical_size,
        backing.physical_host_addr,
        backing.perms,
        backing.owner_generation,
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn forget_replay_extent(ipa: u64, size: usize) {
    let mut replay = replay_mappings().lock();
    let _registry = alias_registry().lock();
    let doomed: Vec<ReplayMappingKey> = replay
        .range((ipa, 0, 0, 0, 0)..=(ipa, usize::MAX, usize::MAX, u64::MAX, u64::MAX))
        .filter(|(_, mapped_size, _, _, _)| *mapped_size == size)
        .copied()
        .collect();
    if doomed.is_empty() {
        return;
    }
    for row in &doomed {
        replay.remove(row);
    }
    let mut versions = alias_version_registry().lock();
    scoped_alias_epoch_update(&mut versions, None, &[ipa], &replay);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn clear_replay_mappings() {
    mutate_external_alias_state(|replay, _| replay.clear());
}

/// Diagnostic: lazy-alias re-map count (the `debug-stats` feature logs every 256th).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(dead_code)]
pub static ALIAS_REMAP_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Record an alias (any `map_host_alias` region — file OR private anon) so the
/// stage-2 lazy remap and the syscall-path cross-thread fallback can resolve it
/// from any thread. Idempotent per semantic `(VA start, IPA, scope)`: a
/// re-register (e.g. a forked child overwriting the inherited PARENT host_addr
/// with its private snapshot pointer) replaces that entry without collapsing a
/// distant VA that aliases the same physical frame.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn register_shared_alias(b: AliasBacking) {
    // Same replay -> alias -> version lock order as every other writer.
    let mut replay = replay_mappings().lock();
    let mut registry = alias_registry().lock();
    let key = replay_mapping_key(b);
    let replay_rows_changed = {
        let mut had_other = false;
        let mut had_exact = false;
        for row in replay.range(
            (b.physical_ipa, 0, 0, 0, 0)
                ..=(b.physical_ipa, usize::MAX, usize::MAX, u64::MAX, u64::MAX),
        ) {
            if *row == key {
                had_exact = true;
            } else {
                had_other = true;
            }
        }
        had_other || !had_exact
    };
    if replay_rows_changed {
        // At most a handful of rows share one physical IPA. `BTreeSet::retain`
        // still walks the WHOLE set to find them, so remove exactly the rows
        // the range query names.
        for row in replay_rows_for_ipa(&replay, b.physical_ipa) {
            replay.remove(&row);
        }
        replay.insert(key);
    }
    // Bucket-scoped: this used to scan every live process's alias rows to find
    // one exact semantic identity, on a path every shared-alias registration takes.
    let old_entry = registry.upsert_by_key(b);
    let entry_changed = old_entry != Some(b);
    let mut versions = alias_version_registry().lock();
    let mut replay_ipas: Vec<u64> = Vec::new();
    if replay_rows_changed || entry_changed {
        replay_ipas.push(b.physical_ipa);
    }
    if entry_changed
        && let Some(old) = old_entry
        && old.physical_ipa != b.physical_ipa
    {
        replay_ipas.push(old.physical_ipa);
    }
    scoped_alias_epoch_update(
        &mut versions,
        entry_changed.then_some((alias_version_key(&b), Some(b))),
        &replay_ipas,
        &replay,
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RetiredStage2Projection {
    pub(crate) physical_ipa: u64,
    pub(crate) physical_length: u64,
    pub(crate) owner: InventoryStage2OwnerIdentity,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl From<InventoryExtent> for RetiredStage2Projection {
    fn from(extent: InventoryExtent) -> Self {
        Self {
            physical_ipa: extent.stage2_base,
            physical_length: extent.stage2_length,
            owner: extent.stage2_owner,
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Default)]
pub(crate) struct RetiredProjectionCleanup {
    pub(crate) removed_aliases: Vec<AliasBacking>,
    pub(crate) preserved_reused_aliases: Vec<AliasBacking>,
    pub(crate) removed_replay: Vec<ReplayMappingKey>,
    pub(crate) preserved_reused_replay: Vec<ReplayMappingKey>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg(test)]
pub(crate) fn remove_rows_for_retired_stage2_projection(
    replay: &mut std::collections::BTreeSet<ReplayMappingKey>,
    registry: &mut AliasRegistry,
    retired: RetiredStage2Projection,
) -> RetiredProjectionCleanup {
    remove_rows_for_retired_stage2_projections(replay, registry, &[retired])
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn remove_rows_for_retired_stage2_projections(
    replay: &mut std::collections::BTreeSet<ReplayMappingKey>,
    registry: &mut AliasRegistry,
    retired: &[RetiredStage2Projection],
) -> RetiredProjectionCleanup {
    let mut owners_by_extent =
        std::collections::BTreeMap::<(u64, u64), std::collections::BTreeSet<(usize, u64)>>::new();
    for retired in retired {
        if retired.owner.host_addr == 0
            || (retired.owner.generation == 0
                && is_reusable_global_frame_extent(retired.physical_ipa, retired.physical_length))
        {
            continue;
        }
        owners_by_extent
            .entry((retired.physical_ipa, retired.physical_length))
            .or_default()
            .insert((retired.owner.host_addr, retired.owner.generation));
    }
    let mut cleanup = RetiredProjectionCleanup::default();
    let mut remove_aliases = Vec::new();
    for (&(physical_ipa, physical_length), owners) in &owners_by_extent {
        for &(_, alias) in registry.physical_start_rows(physical_ipa) {
            if alias.physical_size as u64 != physical_length {
                continue;
            }
            if owners.contains(&(alias.physical_host_addr, alias.owner_generation)) {
                remove_aliases.push(alias);
            } else {
                cleanup.preserved_reused_aliases.push(alias);
            }
        }
        for row in replay_rows_for_ipa(replay, physical_ipa) {
            if row.1 as u64 != physical_length {
                continue;
            }
            if owners.contains(&(row.2, row.4)) {
                replay.remove(&row);
                cleanup.removed_replay.push(row);
            } else {
                cleanup.preserved_reused_replay.push(row);
            }
        }
    }
    cleanup.removed_aliases = registry.remove_exact_values_in_batch(&remove_aliases);
    cleanup
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn mapped_region_matches_retired_inventory_extent(
    mapping: &HvfMappedRegion,
    retired: RetiredStage2Projection,
) -> bool {
    retired.owner.host_addr != 0
        && (retired.owner.generation != 0
            || !is_reusable_global_frame_extent(retired.physical_ipa, retired.physical_length))
        && (mapping.physical_ipa, mapping.physical_size as u64)
            == (retired.physical_ipa, retired.physical_length)
        && mapping.owner_generation == retired.owner.generation
        && mapped_region_physical_host_addr(mapping)
            .is_some_and(|host| host as usize == retired.owner.host_addr)
}
