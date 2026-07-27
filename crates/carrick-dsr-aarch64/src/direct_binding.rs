//! Typed process-local direct-binding cells and immutable target descriptors.

use std::cmp::Ordering as CmpOrdering;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, Ordering};

use carrick_guest_mem::GuestVa;

use crate::shared_cache::{
    DIRECT_BINDING_CELL_SIZE, DirectBindingLayout, SharedLoadedTranslationUnit, TranslationUnitKey,
    UnresolvedDirectBindingRecord,
};
use crate::types::{CodeGeneration, DsrError};

/// Dense identity of one unresolved direct-binding stub in a translation unit.
#[repr(transparent)]
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct DirectBindingOrdinal(u32);

impl DirectBindingOrdinal {
    /// Claims an ordinal already validated against its owning manifest.
    pub const fn claimed(value: u32) -> Self {
        Self(value)
    }

    /// Returns the manifest ordinal.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Host virtual address of one mapped, naturally aligned binding cell.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DirectBindingCellVa(usize);

impl DirectBindingCellVa {
    /// Validates a non-null, naturally aligned mapped-cell address.
    pub fn mapped(value: usize) -> Option<Self> {
        let alignment = std::mem::align_of::<AtomicPtr<DirectBindingTarget>>();
        (value != 0 && value.is_multiple_of(alignment)).then_some(Self(value))
    }

    /// Returns the mapped host address.
    pub const fn get(self) -> usize {
        self.0
    }
}

/// Fixed translated-code ABI prefix acquired through a binding cell.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectBindingTargetPrefix {
    pub target_cache_pc: u64,
    pub cache_start: u64,
    pub cache_end: u64,
    pub generation_bindings: u64,
}

const _: () = assert!(std::mem::size_of::<DirectBindingTargetPrefix>() == 32);
const _: () = assert!(std::mem::offset_of!(DirectBindingTargetPrefix, target_cache_pc) == 0);
const _: () = assert!(std::mem::offset_of!(DirectBindingTargetPrefix, generation_bindings) == 24);
const _: () = assert!(std::mem::align_of::<AtomicPtr<DirectBindingTarget>>() == 8);

/// Process-owner token for one append-only private JIT address epoch.
#[derive(Debug)]
pub struct PrivateJitEpoch {
    _private: (),
}

impl PrivateJitEpoch {
    /// Creates the sole process-owner reference for a new private JIT epoch.
    pub fn process_owner() -> Arc<Self> {
        Arc::new(Self { _private: () })
    }

    /// Reports descriptor leases in addition to the process-owner reference.
    pub fn live_descriptor_leases(process_owner: &Arc<Self>) -> usize {
        Arc::strong_count(process_owner).saturating_sub(1)
    }
}

/// Immutable target, authority, generation identity, and lifetime lease.
#[repr(C)]
pub struct DirectBindingTarget {
    pub prefix: DirectBindingTargetPrefix,
    target_page: GuestVa,
    target_generation: CodeGeneration,
    private_epoch: Option<Arc<PrivateJitEpoch>>,
    shared_lease: Option<SharedLoadedTranslationUnit>,
    shared_unit_index: Option<usize>,
}

impl DirectBindingTarget {
    /// Constructs a target backed by the current append-only private JIT epoch.
    pub fn private(
        prefix: DirectBindingTargetPrefix,
        target_page: GuestVa,
        target_generation: CodeGeneration,
        process_epoch: &Arc<PrivateJitEpoch>,
    ) -> Self {
        Self {
            prefix,
            target_page,
            target_generation,
            private_epoch: Some(Arc::clone(process_epoch)),
            shared_lease: None,
            shared_unit_index: None,
        }
    }

    /// Constructs a target backed by an exact loaded shared-unit lease.
    pub fn shared(
        prefix: DirectBindingTargetPrefix,
        target_page: GuestVa,
        target_generation: CodeGeneration,
        shared_lease: SharedLoadedTranslationUnit,
    ) -> Self {
        Self {
            prefix,
            target_page,
            target_generation,
            private_epoch: None,
            shared_lease: Some(shared_lease),
            shared_unit_index: None,
        }
    }

    /// Constructs a target backed by one exact process-loaded shared unit.
    pub(crate) fn shared_in_unit(
        prefix: DirectBindingTargetPrefix,
        target_page: GuestVa,
        target_generation: CodeGeneration,
        shared_lease: SharedLoadedTranslationUnit,
        shared_unit_index: usize,
    ) -> Self {
        Self {
            prefix,
            target_page,
            target_generation,
            private_epoch: None,
            shared_lease: Some(shared_lease),
            shared_unit_index: Some(shared_unit_index),
        }
    }

    /// Returns the guest page whose generation owns this target.
    pub const fn target_page(&self) -> GuestVa {
        self.target_page
    }

    /// Returns the guest-code generation whose bytes this target executes.
    pub const fn target_generation(&self) -> CodeGeneration {
        self.target_generation
    }

    /// Returns the retained private JIT epoch, when this is a private target.
    pub fn private_epoch(&self) -> Option<&Arc<PrivateJitEpoch>> {
        self.private_epoch.as_ref()
    }

    /// Returns the retained shared-unit lease, when this is a shared target.
    pub fn shared_lease(&self) -> Option<&SharedLoadedTranslationUnit> {
        self.shared_lease.as_ref()
    }

    fn has_valid_authority(&self) -> bool {
        let target = self.prefix.target_cache_pc;
        self.prefix.cache_start < self.prefix.cache_end
            && (self.prefix.cache_start..self.prefix.cache_end).contains(&target)
            && matches!(
                (&self.private_epoch, &self.shared_lease),
                (Some(_), None) | (None, Some(_))
            )
    }

    fn same_complete_target(&self, other: &Self) -> bool {
        if self.prefix != other.prefix
            || self.target_page != other.target_page
            || self.target_generation != other.target_generation
        {
            return false;
        }
        match (
            &self.private_epoch,
            &self.shared_lease,
            self.shared_unit_index,
            &other.private_epoch,
            &other.shared_lease,
            other.shared_unit_index,
        ) {
            (Some(left), None, None, Some(right), None, None) => Arc::ptr_eq(left, right),
            (None, Some(left), Some(left_index), None, Some(right), Some(right_index)) => {
                left_index == right_index
                    && left.base == right.base
                    && left.binding_base == right.binding_base
                    && left.manifest.key == right.manifest.key
            }
            (None, Some(left), None, None, Some(right), None) => {
                left.base == right.base
                    && left.binding_base == right.binding_base
                    && left.manifest.key == right.manifest.key
            }
            _ => false,
        }
    }
}

/// Exact process-local owner identity for one direct-binding cell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectBindingOwnerKey {
    pub unit: TranslationUnitKey,
    pub ordinal: DirectBindingOrdinal,
}

impl PartialOrd for DirectBindingOwnerKey {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl Ord for DirectBindingOwnerKey {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        let left = serde_json::to_vec(&self.unit)
            .unwrap_or_else(|_| format!("{:?}", self.unit).into_bytes());
        let right = serde_json::to_vec(&other.unit)
            .unwrap_or_else(|_| format!("{:?}", other.unit).into_bytes());
        left.cmp(&right)
            .then_with(|| self.ordinal.cmp(&other.ordinal))
    }
}

/// Exact record and loaded-unit index owning one mapped cell.
pub struct DirectBindingOwner {
    unit_index: usize,
    record: UnresolvedDirectBindingRecord,
    cell: DirectBindingCellVa,
}

/// Process-owned metadata and source lease for one loaded sidecar unit.
pub struct DirectBindingUnitOwner {
    key: TranslationUnitKey,
    binding_base: DirectBindingCellVa,
    records: Box<[UnresolvedDirectBindingRecord]>,
    published_bitmap: Box<[u64]>,
    source_lease: SharedLoadedTranslationUnit,
}

/// Reverse edge retained after a successful direct-binding publication.
pub struct IncomingDirectBinding {
    source: DirectBindingOwnerKey,
    cell: DirectBindingCellVa,
    expected: *mut DirectBindingTarget,
}

// SAFETY: `expected` names an immutable descriptor owned by the same registry,
// and every cell access is atomic. The registry itself is mutated only while
// its containing `ProcessState` write lock is held.
unsafe impl Send for IncomingDirectBinding {}
// SAFETY: See the `Send` rationale; shared access never mutates the pointer or
// dereferences it without first finding the retained descriptor owner.
unsafe impl Sync for IncomingDirectBinding {}

/// Low-frequency process counters for registry validation and publication.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirectBindingCounters {
    pub owner_validation_failures: u64,
    pub authority_validation_failures: u64,
    pub cas_wins: u64,
    pub cas_losses: u64,
    pub stale_winner_clears: u64,
    pub publication_retries: u64,
}

/// Result of clearing the incoming cells for one exact target generation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirectBindingClearStats {
    pub visited: u64,
    pub exact_clears: u64,
    pub newer_publication_misses: u64,
    pub bitmap_bits_cleared: u64,
}

/// Result of one cold-path publication attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectBindingPublishOutcome {
    Published,
    PublishedAfterStale,
    ExistingWinner,
    Rejected,
}

/// Sole process-owned index for loaded sidecar cells and retained descriptors.
pub struct DirectBindingRegistry {
    enabled: bool,
    owners_by_cell: BTreeMap<DirectBindingCellVa, DirectBindingOwner>,
    units: Vec<DirectBindingUnitOwner>,
    #[allow(
        clippy::vec_box,
        reason = "descriptor addresses must remain stable after publication"
    )]
    descriptors: Vec<Box<DirectBindingTarget>>,
    incoming: BTreeMap<(GuestVa, CodeGeneration), Vec<IncomingDirectBinding>>,
    counters: DirectBindingCounters,
}

impl DirectBindingRegistry {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            owners_by_cell: BTreeMap::new(),
            units: Vec::new(),
            descriptors: Vec::new(),
            incoming: BTreeMap::new(),
            counters: DirectBindingCounters::default(),
        }
    }

    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Registers the exact cells and retained source lease of a loaded unit.
    ///
    /// Disabled-layout units have no cells and return `Ok(None)`.
    pub fn register_loaded_unit(
        &mut self,
        unit: &SharedLoadedTranslationUnit,
    ) -> Result<Option<usize>, DsrError> {
        if !self.enabled || unit.manifest.binding_layout == DirectBindingLayout::Disabled {
            return Ok(None);
        }
        if unit.manifest.binding_layout != DirectBindingLayout::SidecarV1
            || unit.manifest.cell_size != DIRECT_BINDING_CELL_SIZE
        {
            return Err(DsrError::CachePolicy(
                "direct-binding unit has an unsupported cell layout".to_string(),
            ));
        }
        let binding_base = unit.binding_base.ok_or_else(|| {
            DsrError::CachePolicy("direct-binding unit has no mapped cell base".to_string())
        })?;
        if self
            .units
            .iter()
            .any(|owner| owner.key == unit.manifest.key)
        {
            return Err(DsrError::CachePolicy(
                "direct-binding unit owner is duplicated".to_string(),
            ));
        }
        let records = unit.manifest.bindings.clone().into_boxed_slice();
        let expected_len = records
            .len()
            .checked_mul(DIRECT_BINDING_CELL_SIZE as usize)
            .ok_or_else(|| {
                DsrError::CachePolicy("direct-binding cell range overflow".to_string())
            })?;
        let binding_len = usize::try_from(unit.manifest.binding_data_len).map_err(|_| {
            DsrError::CachePolicy("direct-binding data length does not fit usize".to_string())
        })?;
        if binding_len != expected_len {
            return Err(DsrError::CachePolicy(
                "direct-binding data length does not match its owner records".to_string(),
            ));
        }
        let binding_end = binding_base.get().checked_add(binding_len).ok_or_else(|| {
            DsrError::CachePolicy("direct-binding cell range overflow".to_string())
        })?;
        let unit_index = self.units.len();
        let mut owners = Vec::with_capacity(records.len());
        for record in &records {
            let offset = usize::try_from(record.ordinal.get())
                .ok()
                .and_then(|ordinal| ordinal.checked_mul(DIRECT_BINDING_CELL_SIZE as usize))
                .ok_or_else(|| {
                    DsrError::CachePolicy("direct-binding cell offset overflow".to_string())
                })?;
            let address = binding_base.get().checked_add(offset).ok_or_else(|| {
                DsrError::CachePolicy("direct-binding cell address overflow".to_string())
            })?;
            let cell_end = address
                .checked_add(DIRECT_BINDING_CELL_SIZE as usize)
                .ok_or_else(|| {
                    DsrError::CachePolicy("direct-binding cell range overflow".to_string())
                })?;
            if cell_end > binding_end {
                return Err(DsrError::CachePolicy(
                    "direct-binding cell is outside its mapped owner range".to_string(),
                ));
            }
            let cell = DirectBindingCellVa::mapped(address).ok_or_else(|| {
                DsrError::CachePolicy(format!(
                    "direct-binding cell address 0x{address:x} is invalid"
                ))
            })?;
            if self.owners_by_cell.contains_key(&cell)
                || owners
                    .iter()
                    .any(|candidate: &DirectBindingOwner| candidate.cell == cell)
            {
                return Err(DsrError::CachePolicy(
                    "direct-binding cell owner is duplicated".to_string(),
                ));
            }
            // SAFETY: the loaded unit's source lease owns the mapped sidecar
            // range, and the loader exposes it only through typed atomics.
            let cell_ref = unsafe { DirectBindingCellRef::from_mapped_address(cell)? };
            if !cell_ref.load_acquire().is_null() {
                return Err(DsrError::CachePolicy(
                    "direct-binding owner cell is not initially zero".to_string(),
                ));
            }
            owners.push(DirectBindingOwner {
                unit_index,
                record: record.clone(),
                cell,
            });
        }
        let bitmap_words = records.len().div_ceil(u64::BITS as usize);
        let published_bitmap = vec![0; bitmap_words].into_boxed_slice();
        self.units.push(DirectBindingUnitOwner {
            key: unit.manifest.key.clone(),
            binding_base,
            records,
            published_bitmap,
            source_lease: unit.clone(),
        });
        for owner in owners {
            self.owners_by_cell.insert(owner.cell, owner);
        }
        Ok(Some(unit_index))
    }

    /// Returns the one exact loaded owner matching a miss-carried cell.
    pub fn owner_key(
        &mut self,
        miss: DirectBindingMiss,
        source: GuestVa,
        target: GuestVa,
    ) -> Option<DirectBindingOwnerKey> {
        match self.validated_owner(miss, source, target) {
            Some((key, _)) => Some(key),
            None => {
                self.counters.owner_validation_failures =
                    self.counters.owner_validation_failures.saturating_add(1);
                None
            }
        }
    }

    /// Retains and publishes a complete target descriptor for an exact owner.
    pub fn publish(
        &mut self,
        miss: DirectBindingMiss,
        source: GuestVa,
        target: GuestVa,
        descriptor: DirectBindingTarget,
    ) -> DirectBindingPublishOutcome {
        self.publish_with_stale_observer(miss, source, target, descriptor, |_, _| {})
    }

    #[cfg(test)]
    pub fn publish_with_stale_observer_for_test<F>(
        &mut self,
        miss: DirectBindingMiss,
        source: GuestVa,
        target: GuestVa,
        descriptor: DirectBindingTarget,
        observer: F,
    ) -> DirectBindingPublishOutcome
    where
        F: FnOnce(&mut Self, *mut DirectBindingTarget),
    {
        self.publish_with_stale_observer(miss, source, target, descriptor, observer)
    }

    fn publish_with_stale_observer<F>(
        &mut self,
        miss: DirectBindingMiss,
        source: GuestVa,
        target: GuestVa,
        descriptor: DirectBindingTarget,
        observer: F,
    ) -> DirectBindingPublishOutcome
    where
        F: FnOnce(&mut Self, *mut DirectBindingTarget),
    {
        let Some((source_key, unit_index)) = self.validated_owner(miss, source, target) else {
            self.counters.owner_validation_failures =
                self.counters.owner_validation_failures.saturating_add(1);
            return DirectBindingPublishOutcome::Rejected;
        };
        if descriptor.target_page != target || !descriptor.has_valid_authority() {
            self.counters.authority_validation_failures = self
                .counters
                .authority_validation_failures
                .saturating_add(1);
            return DirectBindingPublishOutcome::Rejected;
        }
        // No descriptor reclamation is permitted yet. Retain the complete
        // lease-bearing object before its address can become cell-visible.
        self.descriptors.push(Box::new(descriptor));
        let descriptor_index = self.descriptors.len() - 1;
        let pointer = std::ptr::from_mut(self.descriptors[descriptor_index].as_mut());
        // SAFETY: owner validation re-established that the unit lease owns
        // this exact mapped cell for the registry lifetime.
        let Ok(cell) = (unsafe { DirectBindingCellRef::from_mapped_address(miss.cell) }) else {
            self.counters.owner_validation_failures =
                self.counters.owner_validation_failures.saturating_add(1);
            return DirectBindingPublishOutcome::Rejected;
        };
        match cell.publish_null(pointer) {
            Ok(()) => {
                self.record_publication(source_key, unit_index, miss.cell, pointer);
                DirectBindingPublishOutcome::Published
            }
            Err(winner) => {
                self.counters.cas_losses = self.counters.cas_losses.saturating_add(1);
                if self.winner_matches(winner, descriptor_index) {
                    return DirectBindingPublishOutcome::ExistingWinner;
                }
                observer(self, winner);
                if !cell.clear_if(winner) {
                    // The cell no longer contains the exact pointer this
                    // publisher classified as stale. A replacement belongs to
                    // its own publisher and must never be cleared here.
                    let current = cell.load_acquire();
                    if self.winner_matches(current, descriptor_index) {
                        return DirectBindingPublishOutcome::ExistingWinner;
                    }
                    return DirectBindingPublishOutcome::Rejected;
                }
                self.counters.stale_winner_clears =
                    self.counters.stale_winner_clears.saturating_add(1);
                self.counters.publication_retries =
                    self.counters.publication_retries.saturating_add(1);
                match cell.publish_null(pointer) {
                    Ok(()) => {
                        self.record_publication(source_key, unit_index, miss.cell, pointer);
                        DirectBindingPublishOutcome::PublishedAfterStale
                    }
                    Err(retry_winner) => {
                        self.counters.cas_losses = self.counters.cas_losses.saturating_add(1);
                        if self.winner_matches(retry_winner, descriptor_index) {
                            DirectBindingPublishOutcome::ExistingWinner
                        } else {
                            // The single retry is consumed. This winner was
                            // never classified as stale, so leave it untouched.
                            DirectBindingPublishOutcome::Rejected
                        }
                    }
                }
            }
        }
    }

    pub fn is_published(&self, unit_index: usize, ordinal: DirectBindingOrdinal) -> bool {
        let Some(unit) = self.units.get(unit_index) else {
            return false;
        };
        let ordinal = ordinal.get() as usize;
        let Some(word) = unit.published_bitmap.get(ordinal / u64::BITS as usize) else {
            return false;
        };
        word & (1_u64 << (ordinal % u64::BITS as usize)) != 0
    }

    pub fn incoming_count(&self, target: GuestVa, generation: CodeGeneration) -> usize {
        self.incoming.get(&(target, generation)).map_or(0, Vec::len)
    }

    /// Clears cells that still publish this exact target generation.
    ///
    /// The reverse key prevents unrelated targets or generations from being
    /// visited. Descriptors remain pinned so a reader that acquired `expected`
    /// before the clear can safely reach the target's generation guard.
    pub fn invalidate_target(
        &mut self,
        page: GuestVa,
        generation: CodeGeneration,
    ) -> DirectBindingClearStats {
        let Some(incoming) = self.incoming.remove(&(page, generation)) else {
            return DirectBindingClearStats::default();
        };
        let mut stats = DirectBindingClearStats::default();
        for record in incoming {
            stats.visited = stats.visited.saturating_add(1);
            let cell = DirectBindingCellRef::registered(record.cell);
            if !cell.clear_if(record.expected) {
                // A later publisher owns the current pointer and its source
                // bitmap bit. Exact invalidation must leave both untouched.
                stats.newer_publication_misses = stats.newer_publication_misses.saturating_add(1);
                continue;
            }
            stats.exact_clears = stats.exact_clears.saturating_add(1);
            if self.clear_publication_bit(&record.source) {
                stats.bitmap_bits_cleared = stats.bitmap_bits_cleared.saturating_add(1);
            }
        }
        stats
    }

    pub const fn counters(&self) -> DirectBindingCounters {
        self.counters
    }

    fn validated_owner(
        &self,
        miss: DirectBindingMiss,
        source: GuestVa,
        target: GuestVa,
    ) -> Option<(DirectBindingOwnerKey, usize)> {
        if !self.enabled {
            return None;
        }
        let owner = self.owners_by_cell.get(&miss.cell)?;
        if owner.cell != miss.cell
            || owner.record.ordinal != miss.ordinal
            || owner.record.source != source
            || owner.record.target != target
        {
            return None;
        }
        let unit = self.units.get(owner.unit_index)?;
        let record = unit.records.get(miss.ordinal.get() as usize)?;
        let offset = usize::try_from(miss.ordinal.get())
            .ok()?
            .checked_mul(DIRECT_BINDING_CELL_SIZE as usize)?;
        let expected_cell =
            DirectBindingCellVa::mapped(unit.binding_base.get().checked_add(offset)?)?;
        if record != &owner.record
            || expected_cell != miss.cell
            || unit.source_lease.manifest.key != unit.key
            || unit.source_lease.binding_base != Some(unit.binding_base)
            || unit.source_lease.manifest.bindings.as_slice() != unit.records.as_ref()
        {
            return None;
        }
        Some((
            DirectBindingOwnerKey {
                unit: unit.key.clone(),
                ordinal: miss.ordinal,
            },
            owner.unit_index,
        ))
    }

    fn winner_matches(&self, winner: *mut DirectBindingTarget, intended_index: usize) -> bool {
        if winner.is_null() {
            return false;
        }
        let Some(winner) = self
            .descriptors
            .iter()
            .find(|descriptor| std::ptr::eq(descriptor.as_ref(), winner.cast_const()))
        else {
            return false;
        };
        winner.same_complete_target(&self.descriptors[intended_index])
    }

    fn clear_publication_bit(&mut self, source: &DirectBindingOwnerKey) -> bool {
        let Some(unit) = self.units.iter_mut().find(|unit| unit.key == source.unit) else {
            return false;
        };
        let ordinal = source.ordinal.get() as usize;
        let Some(word) = unit.published_bitmap.get_mut(ordinal / u64::BITS as usize) else {
            return false;
        };
        let mask = 1_u64 << (ordinal % u64::BITS as usize);
        let was_published = *word & mask != 0;
        *word &= !mask;
        was_published
    }

    fn record_publication(
        &mut self,
        source: DirectBindingOwnerKey,
        unit_index: usize,
        cell: DirectBindingCellVa,
        expected: *mut DirectBindingTarget,
    ) {
        let ordinal = source.ordinal.get() as usize;
        let unit = &mut self.units[unit_index];
        unit.published_bitmap[ordinal / u64::BITS as usize] |=
            1_u64 << (ordinal % u64::BITS as usize);
        let descriptor = &self.descriptors[self.descriptors.len() - 1];
        self.incoming
            .entry((descriptor.target_page, descriptor.target_generation))
            .or_default()
            .push(IncomingDirectBinding {
                source,
                cell,
                expected,
            });
        self.counters.cas_wins = self.counters.cas_wins.saturating_add(1);
    }
}

/// Cold-path identity of the exact direct-binding cell that missed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectBindingMiss {
    pub cell: DirectBindingCellVa,
    pub ordinal: DirectBindingOrdinal,
}

/// The sole adapter from a validated mapped-cell address to atomic operations.
#[derive(Clone, Copy, Debug)]
pub struct DirectBindingCellRef {
    address: DirectBindingCellVa,
}

impl DirectBindingCellRef {
    fn registered(address: DirectBindingCellVa) -> Self {
        Self { address }
    }

    /// Creates an atomic adapter for a live writable binding cell.
    ///
    /// # Safety
    ///
    /// `address` must point to a mapped, writable, initialized
    /// `AtomicPtr<DirectBindingTarget>` that remains live for every copied
    /// adapter and every operation performed through it.
    pub unsafe fn from_mapped_address(address: DirectBindingCellVa) -> Result<Self, DsrError> {
        let value = address.get();
        let alignment = std::mem::align_of::<AtomicPtr<DirectBindingTarget>>();
        if value == 0 || !value.is_multiple_of(alignment) {
            return Err(DsrError::CachePolicy(format!(
                "direct-binding cell address 0x{value:x} is not naturally aligned"
            )));
        }
        Ok(Self { address })
    }

    /// Acquires the complete immutable descriptor currently published.
    pub fn load_acquire(self) -> *mut DirectBindingTarget {
        self.cell().load(Ordering::Acquire)
    }

    /// Release-publishes `target` only when the cell is null.
    pub fn publish_null(
        self,
        target: *mut DirectBindingTarget,
    ) -> Result<(), *mut DirectBindingTarget> {
        self.cell()
            .compare_exchange(
                std::ptr::null_mut(),
                target,
                Ordering::Release,
                Ordering::Acquire,
            )
            .map(|_| ())
    }

    /// Clears the cell only if it still contains `expected`.
    pub fn clear_if(self, expected: *mut DirectBindingTarget) -> bool {
        self.cell()
            .compare_exchange(
                expected,
                std::ptr::null_mut(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Release-clears the cell after callers have established quiescence.
    pub fn clear_release(self) {
        self.cell().store(std::ptr::null_mut(), Ordering::Release);
    }

    fn cell(self) -> &'static AtomicPtr<DirectBindingTarget> {
        // SAFETY: `from_mapped_address` requires this address to identify a
        // live initialized `AtomicPtr` for the lifetime of every copied
        // adapter. All mapped-cell access is centralized in this adapter.
        unsafe { &*(self.address.get() as *const AtomicPtr<DirectBindingTarget>) }
    }
}
