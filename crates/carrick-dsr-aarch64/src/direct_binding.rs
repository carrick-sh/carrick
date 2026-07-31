//! Typed process-local direct-binding cells and immutable target descriptors.

use std::cmp::Ordering as CmpOrdering;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::time::{Duration, Instant};

use carrick_guest_mem::GuestVa;
use sha2::{Digest, Sha256};

use crate::shared_cache::{
    DIRECT_BINDING_CELL_SIZE, DirectBindingLayout, SharedLoadedTranslationUnit, TranslationUnitKey,
    UnresolvedDirectBindingRecord,
};
use crate::types::{CodeGeneration, DsrError};

const DARWIN_HOST_PAGE_SIZE: usize = 16 * 1024;

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

/// Typed reason for an actual non-null-to-null direct-binding clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum DirectBindingClearReason {
    TargetInvalidation = 1,
    StaleWinnerRemoval = 2,
    ForkReset = 3,
    ExecReset = 4,
}

impl DirectBindingClearReason {
    pub const fn raw(self) -> u64 {
        self as u64
    }
}

/// Typed reason a cold direct-binding authority check failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum DirectBindingValidationReason {
    MissingEligibleRecord = 1,
    AmbiguousEligibleRecord = 2,
    MissMetadataMismatch = 3,
    OwnerMismatch = 4,
    AuthorityMismatch = 5,
    MappedCellFailure = 6,
}

impl DirectBindingValidationReason {
    pub const fn raw(self) -> u64 {
        self as u64
    }
}

/// Exact manifest record selected at one cold direct-resolver exit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectBindingEligibility {
    pub unit: TranslationUnitKey,
    pub ordinal: DirectBindingOrdinal,
    pub cell: Option<DirectBindingCellVa>,
}

/// Stable 64-bit diagnostic digest of one translation-unit key.
pub fn direct_binding_unit_digest(key: &TranslationUnitKey) -> Result<u64, DsrError> {
    let encoded = serde_json::to_vec(key).map_err(|error| {
        DsrError::CachePolicy(format!(
            "direct-binding unit key cannot be serialized for evidence: {error}"
        ))
    })?;
    let digest: [u8; 32] = Sha256::digest(encoded).into();
    let [b0, b1, b2, b3, b4, b5, b6, b7, ..] = digest;
    Ok(u64::from_le_bytes([b0, b1, b2, b3, b4, b5, b6, b7]))
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
    binding_base: Option<DirectBindingCellVa>,
    binding_layout: DirectBindingLayout,
    records: Box<[UnresolvedDirectBindingRecord]>,
    published_bitmap: Box<[u64]>,
    source_lease: SharedLoadedTranslationUnit,
}

pub(crate) struct PreparedDirectBindingUnit {
    unit_index: usize,
    owner: DirectBindingUnitOwner,
    cell_owners: Vec<DirectBindingOwner>,
    edge_records: Vec<PreparedDirectBindingEdge>,
}

pub(crate) struct PreparedDirectBindingEdge {
    key: (GuestVa, GuestVa),
    records: Vec<(usize, usize)>,
    existing: bool,
}

impl PreparedDirectBindingUnit {
    pub(crate) const fn unit_index(&self) -> usize {
        self.unit_index
    }
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

/// Sparse child-side repair statistics for inherited sidecar publications.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ForkBindingClearStats {
    pub cells_cleared: u64,
    pub pages_touched: u64,
    pub duration: Duration,
}

/// Whole-image direct-binding teardown statistics for exec diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExecBindingClearStats {
    pub cells_cleared: u64,
    pub pages_touched: u64,
    pub descriptors_dropped: u64,
    pub units_dropped: u64,
    pub duration: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectBindingExecClearPhase {
    Cells,
    Indexes,
    Descriptors,
}

/// Result of one cold-path publication attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectBindingPublishOutcome {
    Published,
    PublishedAfterStale,
    ExistingWinner,
    Rejected,
}

/// Cold-path evidence produced by one publication attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectBindingPublishEvidence {
    pub outcome: DirectBindingPublishOutcome,
    pub cas_losses: u64,
    pub stale_clear_generation: Option<CodeGeneration>,
    pub validation_failure: Option<DirectBindingValidationReason>,
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
    /// `(source, target)` -> the `(unit_index, record_index)` slots that name
    /// that edge, built once per registered unit.
    ///
    /// `classify_cold_exit` runs on EVERY cold exit, and it used to find its
    /// candidates by scanning every binding record of every loaded unit and
    /// collecting them into a fresh `Vec`. With no units loaded that costs
    /// nothing -- the iterator is empty and an empty `Vec` does not allocate --
    /// which is why it went unnoticed: the scan only has records to walk when
    /// shared translation is on. Measured cost of that asymmetry on one cold
    /// go-build: 17-50x slower with `CARRICK_DSR_SHARED_TRANSLATION=1` (>300 s
    /// against 17.2 s and 18.8 s controls), with the seven hottest user stacks
    /// all being this function.
    ///
    /// Unit indices stay valid because `units` is only ever pushed to or
    /// cleared wholesale -- never removed from individually.
    records_by_edge: BTreeMap<(GuestVa, GuestVa), Vec<(usize, usize)>>,
    counters: DirectBindingCounters,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectBindingArenaSnapshot {
    pub owners_len: usize,
    pub units_len: usize,
    pub units_capacity: usize,
    pub descriptors_len: usize,
    pub descriptors_capacity: usize,
    pub incoming_len: usize,
    pub records_address: usize,
    pub records_len: usize,
    pub bitmap_address: usize,
    pub bitmap_len: usize,
}

#[cfg(test)]
type DirectBindingOwnerSnapshot = (DirectBindingCellVa, usize, UnresolvedDirectBindingRecord);

#[cfg(test)]
type DirectBindingEdgeSnapshot = ((GuestVa, GuestVa), Vec<(usize, usize)>);

#[cfg(test)]
type DirectBindingUnitSnapshot = (
    TranslationUnitKey,
    Option<DirectBindingCellVa>,
    DirectBindingLayout,
    Vec<UnresolvedDirectBindingRecord>,
    Vec<u64>,
    TranslationUnitKey,
    usize,
    Option<DirectBindingCellVa>,
);

#[cfg(test)]
type DirectBindingDescriptorSnapshot = (
    DirectBindingTargetPrefix,
    GuestVa,
    CodeGeneration,
    Option<usize>,
    Option<(TranslationUnitKey, usize, Option<DirectBindingCellVa>)>,
    Option<usize>,
);

#[cfg(test)]
type DirectBindingIncomingSnapshot = (
    (GuestVa, CodeGeneration),
    Vec<(DirectBindingOwnerKey, DirectBindingCellVa, usize)>,
);

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DirectBindingLogicalSnapshot {
    enabled: bool,
    units: Vec<DirectBindingUnitSnapshot>,
    owners: Vec<DirectBindingOwnerSnapshot>,
    edges: Vec<DirectBindingEdgeSnapshot>,
    descriptors: Vec<DirectBindingDescriptorSnapshot>,
    incoming: Vec<DirectBindingIncomingSnapshot>,
    counters: DirectBindingCounters,
}

#[cfg(test)]
impl DirectBindingLogicalSnapshot {
    pub(crate) fn has_published_exec_reset_state(&self) -> bool {
        self.units
            .iter()
            .any(|unit| unit.4.iter().any(|word| *word != 0))
            && !self.descriptors.is_empty()
            && !self.incoming.is_empty()
            && self.counters.cas_wins != 0
    }
}

impl DirectBindingRegistry {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            owners_by_cell: BTreeMap::new(),
            units: Vec::new(),
            records_by_edge: BTreeMap::new(),
            descriptors: Vec::new(),
            incoming: BTreeMap::new(),
            counters: DirectBindingCounters::default(),
        }
    }

    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn unit_count(&self) -> usize {
        self.units.len()
    }

    /// Counts registry-owned private descriptor leases for one exact process
    /// epoch, rejecting a descriptor retained from any other private epoch.
    pub(crate) fn private_descriptor_leases_for(
        &self,
        process_epoch: &Arc<PrivateJitEpoch>,
    ) -> Result<usize, DsrError> {
        let mut count = 0_usize;
        for descriptor in &self.descriptors {
            let Some(descriptor_epoch) = descriptor.private_epoch() else {
                continue;
            };
            if !Arc::ptr_eq(descriptor_epoch, process_epoch) {
                return Err(DsrError::CachePolicy(
                    "direct-binding registry retains a stale private JIT descriptor lease"
                        .to_string(),
                ));
            }
            count = count.checked_add(1).ok_or_else(|| {
                DsrError::CachePolicy("private JIT descriptor lease count overflow".to_string())
            })?;
        }
        Ok(count)
    }

    /// Registers the exact cells and retained source lease of a loaded unit.
    ///
    /// Disabled-layout units have no cells and return `Ok(None)`.
    pub fn register_loaded_unit(
        &mut self,
        unit: &SharedLoadedTranslationUnit,
    ) -> Result<Option<usize>, DsrError> {
        let prepared = self.prepare_loaded_unit(unit)?;
        Ok(self.commit_loaded_unit(prepared))
    }

    pub(crate) fn prepare_loaded_unit(
        &mut self,
        unit: &SharedLoadedTranslationUnit,
    ) -> Result<PreparedDirectBindingUnit, DsrError> {
        if self
            .units
            .iter()
            .any(|owner| owner.key == unit.manifest.key)
        {
            return Err(DsrError::CachePolicy(
                "direct-binding unit owner is duplicated".to_string(),
            ));
        }
        self.units.try_reserve(1).map_err(|error| {
            DsrError::CachePolicy(format!(
                "direct-binding unit owner reservation failed: {error}"
            ))
        })?;
        let unit_index = self.units.len();
        if !self.enabled || unit.manifest.binding_layout == DirectBindingLayout::Disabled {
            let owner = DirectBindingUnitOwner {
                key: unit.manifest.key.clone(),
                binding_base: None,
                binding_layout: DirectBindingLayout::Disabled,
                records: unit.manifest.bindings.clone().into_boxed_slice(),
                published_bitmap: Box::new([]),
                source_lease: unit.clone(),
            };
            let edge_records = self.prepare_unit_edges(unit_index, &owner.records)?;
            return Ok(PreparedDirectBindingUnit {
                unit_index,
                owner,
                cell_owners: Vec::new(),
                edge_records,
            });
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
        let mut owners = Vec::new();
        owners.try_reserve(records.len()).map_err(|error| {
            DsrError::CachePolicy(format!(
                "direct-binding cell owner reservation failed for {} records: {error}",
                records.len()
            ))
        })?;
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
        let mut published_bitmap = Vec::new();
        published_bitmap
            .try_reserve_exact(bitmap_words)
            .map_err(|error| {
                DsrError::CachePolicy(format!(
                    "direct-binding publication bitmap reservation failed for {bitmap_words} words: {error}"
                ))
            })?;
        published_bitmap.resize(bitmap_words, 0);
        let owner = DirectBindingUnitOwner {
            key: unit.manifest.key.clone(),
            binding_base: Some(binding_base),
            binding_layout: DirectBindingLayout::SidecarV1,
            records,
            published_bitmap: published_bitmap.into_boxed_slice(),
            source_lease: unit.clone(),
        };
        let edge_records = self.prepare_unit_edges(unit_index, &owner.records)?;
        Ok(PreparedDirectBindingUnit {
            unit_index,
            owner,
            cell_owners: owners,
            edge_records,
        })
    }

    fn prepare_unit_edges(
        &mut self,
        unit_index: usize,
        records: &[UnresolvedDirectBindingRecord],
    ) -> Result<Vec<PreparedDirectBindingEdge>, DsrError> {
        let mut counts = BTreeMap::<(GuestVa, GuestVa), usize>::new();
        for record in records {
            let count = counts.entry((record.source, record.target)).or_default();
            *count = count.checked_add(1).ok_or_else(|| {
                DsrError::CachePolicy("direct-binding edge record count overflow".to_string())
            })?;
        }
        let mut grouped = BTreeMap::<(GuestVa, GuestVa), Vec<(usize, usize)>>::new();
        for (edge, count) in counts {
            let mut slots = Vec::new();
            slots.try_reserve_exact(count).map_err(|error| {
                DsrError::CachePolicy(format!(
                    "direct-binding edge reservation failed for {count} records: {error}"
                ))
            })?;
            grouped.insert(edge, slots);
        }
        for (record_index, record) in records.iter().enumerate() {
            if let Some(slots) = grouped.get_mut(&(record.source, record.target)) {
                slots.push((unit_index, record_index));
            }
        }

        let mut prepared = Vec::new();
        prepared.try_reserve(grouped.len()).map_err(|error| {
            DsrError::CachePolicy(format!(
                "direct-binding edge batch reservation failed for {} edges: {error}",
                grouped.len()
            ))
        })?;
        for (key, records) in grouped {
            let existing = self.records_by_edge.contains_key(&key);
            if existing && let Some(destination) = self.records_by_edge.get_mut(&key) {
                destination.try_reserve(records.len()).map_err(|error| {
                    DsrError::CachePolicy(format!(
                        "direct-binding existing edge reservation failed for {} records: {error}",
                        records.len()
                    ))
                })?;
            }
            prepared.push(PreparedDirectBindingEdge {
                key,
                records,
                existing,
            });
        }
        Ok(prepared)
    }

    pub(crate) fn commit_loaded_unit(
        &mut self,
        prepared: PreparedDirectBindingUnit,
    ) -> Option<usize> {
        let mapped = prepared.owner.binding_base.is_some();
        self.units.push(prepared.owner);
        for edge in prepared.edge_records {
            if edge.existing {
                if let Some(destination) = self.records_by_edge.get_mut(&edge.key) {
                    destination.extend(edge.records);
                }
            } else {
                self.records_by_edge.insert(edge.key, edge.records);
            }
        }
        for owner in prepared.cell_owners {
            self.owners_by_cell.insert(owner.cell, owner);
        }
        mapped.then_some(prepared.unit_index)
    }

    /// Selects the exact predeclared manifest record for one cold direct exit.
    ///
    /// This deliberately does not accept the initially prepared unit as
    /// authority: a cache or direct-binding hit may have crossed unit
    /// boundaries before the gateway returned to Rust.
    pub fn classify_cold_exit(
        &mut self,
        source: GuestVa,
        target: GuestVa,
        binding: DirectBindingExitMetadata,
    ) -> Result<DirectBindingEligibility, DirectBindingValidationReason> {
        let miss = match binding {
            DirectBindingExitMetadata::Absent => None,
            DirectBindingExitMetadata::Mapped(miss) => Some(miss),
            DirectBindingExitMetadata::MappedCellFailure { .. } => {
                self.counters.owner_validation_failures =
                    self.counters.owner_validation_failures.saturating_add(1);
                return Err(DirectBindingValidationReason::MappedCellFailure);
            }
        };
        // Indexed lookup, not a scan: see `records_by_edge`. Allocation-free on
        // every path, which matters because this runs on every cold exit.
        let selection = (|| -> Result<(usize, usize), DirectBindingValidationReason> {
            let slots = self
                .records_by_edge
                .get(&(source, target))
                .filter(|slots| !slots.is_empty())
                .ok_or(DirectBindingValidationReason::MissingEligibleRecord)?;
            if let [only] = slots.as_slice() {
                return Ok(*only);
            }
            // Several units declare this edge. Exactly as before, disambiguating
            // needs the miss metadata; without it the edge stays ambiguous.
            let exact_miss = miss.ok_or(DirectBindingValidationReason::AmbiguousEligibleRecord)?;
            let mut chosen = None;
            for &(unit_index, record_index) in slots {
                let Some(unit) = self.units.get(unit_index) else {
                    continue;
                };
                let Some(record) = unit.records.get(record_index) else {
                    continue;
                };
                let eligible = record.ordinal == exact_miss.ordinal
                    && self
                        .owners_by_cell
                        .get(&exact_miss.cell)
                        .is_some_and(|owner| {
                            owner.unit_index == unit_index
                                && owner.record == *record
                                && owner.cell == exact_miss.cell
                        });
                if eligible {
                    if chosen.is_some() {
                        return Err(DirectBindingValidationReason::AmbiguousEligibleRecord);
                    }
                    chosen = Some((unit_index, record_index));
                }
            }
            chosen.ok_or(DirectBindingValidationReason::AmbiguousEligibleRecord)
        })();
        let (unit_index, record_index) = match selection {
            Ok(selected) => selected,
            Err(reason) => {
                self.counters.owner_validation_failures =
                    self.counters.owner_validation_failures.saturating_add(1);
                return Err(reason);
            }
        };
        let unit = &self.units[unit_index];
        let record = &unit.records[record_index];
        let cell = match unit.binding_layout {
            DirectBindingLayout::Disabled => {
                if miss.is_some() {
                    self.counters.owner_validation_failures =
                        self.counters.owner_validation_failures.saturating_add(1);
                    return Err(DirectBindingValidationReason::MissMetadataMismatch);
                }
                None
            }
            DirectBindingLayout::SidecarV1 => {
                let Some(miss) = miss else {
                    self.counters.owner_validation_failures =
                        self.counters.owner_validation_failures.saturating_add(1);
                    return Err(DirectBindingValidationReason::MissMetadataMismatch);
                };
                if miss.ordinal != record.ordinal {
                    self.counters.owner_validation_failures =
                        self.counters.owner_validation_failures.saturating_add(1);
                    return Err(DirectBindingValidationReason::MissMetadataMismatch);
                }
                let Some(owner) = self.owners_by_cell.get(&miss.cell) else {
                    self.counters.owner_validation_failures =
                        self.counters.owner_validation_failures.saturating_add(1);
                    return Err(DirectBindingValidationReason::OwnerMismatch);
                };
                if owner.unit_index != unit_index
                    || owner.record != *record
                    || owner.cell != miss.cell
                {
                    self.counters.owner_validation_failures =
                        self.counters.owner_validation_failures.saturating_add(1);
                    return Err(DirectBindingValidationReason::OwnerMismatch);
                }
                Some(miss.cell)
            }
        };
        Ok(DirectBindingEligibility {
            unit: unit.key.clone(),
            ordinal: record.ordinal,
            cell,
        })
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

    /// Publishes while retaining exact cold-path evidence for probes.
    pub fn publish_with_evidence(
        &mut self,
        miss: DirectBindingMiss,
        source: GuestVa,
        target: GuestVa,
        descriptor: DirectBindingTarget,
    ) -> DirectBindingPublishEvidence {
        let before = self.counters;
        let existing = DirectBindingCellRef::registered(miss.cell).load_acquire();
        let stale_generation = self
            .descriptors
            .iter()
            .find(|candidate| std::ptr::eq(candidate.as_ref(), existing.cast_const()))
            .map(|candidate| candidate.target_generation);
        let outcome = self.publish_with_stale_observer(miss, source, target, descriptor, |_, _| {});
        let after = self.counters;
        let validation_failure =
            if after.authority_validation_failures > before.authority_validation_failures {
                Some(DirectBindingValidationReason::AuthorityMismatch)
            } else if after.owner_validation_failures > before.owner_validation_failures {
                Some(DirectBindingValidationReason::OwnerMismatch)
            } else {
                None
            };
        DirectBindingPublishEvidence {
            outcome,
            cas_losses: after.cas_losses.saturating_sub(before.cas_losses),
            stale_clear_generation: (after.stale_winner_clears > before.stale_winner_clears)
                .then_some(stale_generation)
                .flatten(),
            validation_failure,
        }
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
        self.invalidate_target_with_recorder(page, generation, |_| {})
    }

    pub fn invalidate_target_with_recorder(
        &mut self,
        page: GuestVa,
        generation: CodeGeneration,
        mut recorder: impl FnMut(DirectBindingCellVa),
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
            recorder(record.cell);
            if self.clear_publication_bit(&record.source) {
                stats.bitmap_bits_cleared = stats.bitmap_bits_cleared.saturating_add(1);
            }
        }
        stats
    }

    pub const fn counters(&self) -> DirectBindingCounters {
        self.counters
    }

    /// Clears only bitmap-published cells in a fork child's COW sidecars.
    ///
    /// The walk is allocation-free: it visits the already allocated unit
    /// array, bitmap words, and record arrays, and retains every descriptor,
    /// reverse edge, owner, and unit arena for safe child-side rebinding.
    pub fn clear_inherited_after_fork(&mut self) -> ForkBindingClearStats {
        self.clear_inherited_after_fork_with_recorder(|_| {})
    }

    pub fn clear_inherited_after_fork_with_recorder(
        &mut self,
        recorder: impl FnMut(DirectBindingCellVa),
    ) -> ForkBindingClearStats {
        let started = Instant::now();
        let (cells_cleared, pages_touched) = self.clear_published_cells(recorder);
        self.counters = DirectBindingCounters::default();
        ForkBindingClearStats {
            cells_cleared,
            pages_touched,
            duration: started.elapsed(),
        }
    }

    /// Clears every published cell and retires all direct-binding ownership.
    pub fn clear_all_before_exec(&mut self) -> ExecBindingClearStats {
        self.clear_all_before_exec_with_recorder(|_| {})
    }

    pub(crate) fn clear_all_before_exec_with_recorder(
        &mut self,
        recorder: impl FnMut(DirectBindingExecClearPhase),
    ) -> ExecBindingClearStats {
        self.clear_all_before_exec_with_evidence(recorder, |_| {})
    }

    pub(crate) fn clear_all_before_exec_with_evidence(
        &mut self,
        mut recorder: impl FnMut(DirectBindingExecClearPhase),
        cell_recorder: impl FnMut(DirectBindingCellVa),
    ) -> ExecBindingClearStats {
        let started = Instant::now();
        let (cells_cleared, pages_touched) = self.clear_published_cells(cell_recorder);
        recorder(DirectBindingExecClearPhase::Cells);

        self.incoming.clear();
        self.owners_by_cell.clear();
        recorder(DirectBindingExecClearPhase::Indexes);

        let descriptors_dropped = u64::try_from(self.descriptors.len()).unwrap_or(u64::MAX);
        self.descriptors.clear();
        recorder(DirectBindingExecClearPhase::Descriptors);

        let units_dropped = u64::try_from(self.units.len()).unwrap_or(u64::MAX);
        self.units.clear();
        self.records_by_edge.clear();
        self.counters = DirectBindingCounters::default();
        ExecBindingClearStats {
            cells_cleared,
            pages_touched,
            descriptors_dropped,
            units_dropped,
            duration: started.elapsed(),
        }
    }

    #[cfg(test)]
    pub fn arena_snapshot_for_test(&self, unit_index: usize) -> DirectBindingArenaSnapshot {
        let unit = &self.units[unit_index];
        DirectBindingArenaSnapshot {
            owners_len: self.owners_by_cell.len(),
            units_len: self.units.len(),
            units_capacity: self.units.capacity(),
            descriptors_len: self.descriptors.len(),
            descriptors_capacity: self.descriptors.capacity(),
            incoming_len: self.incoming.len(),
            records_address: unit.records.as_ptr() as usize,
            records_len: unit.records.len(),
            bitmap_address: unit.published_bitmap.as_ptr() as usize,
            bitmap_len: unit.published_bitmap.len(),
        }
    }

    #[cfg(test)]
    pub(crate) fn logical_snapshot_for_test(&self) -> DirectBindingLogicalSnapshot {
        DirectBindingLogicalSnapshot {
            enabled: self.enabled,
            units: self
                .units
                .iter()
                .map(|unit| {
                    (
                        unit.key.clone(),
                        unit.binding_base,
                        unit.binding_layout,
                        unit.records.to_vec(),
                        unit.published_bitmap.to_vec(),
                        unit.source_lease.manifest.key.clone(),
                        unit.source_lease.base,
                        unit.source_lease.binding_base,
                    )
                })
                .collect(),
            owners: self
                .owners_by_cell
                .iter()
                .map(|(cell, owner)| (*cell, owner.unit_index, owner.record.clone()))
                .collect(),
            edges: self
                .records_by_edge
                .iter()
                .map(|(edge, records)| (*edge, records.clone()))
                .collect(),
            descriptors: self
                .descriptors
                .iter()
                .map(|descriptor| {
                    (
                        descriptor.prefix,
                        descriptor.target_page,
                        descriptor.target_generation,
                        descriptor
                            .private_epoch
                            .as_ref()
                            .map(|epoch| Arc::as_ptr(epoch) as usize),
                        descriptor.shared_lease.as_ref().map(|lease| {
                            (lease.manifest.key.clone(), lease.base, lease.binding_base)
                        }),
                        descriptor.shared_unit_index,
                    )
                })
                .collect(),
            incoming: self
                .incoming
                .iter()
                .map(|(target, incoming)| {
                    (
                        *target,
                        incoming
                            .iter()
                            .map(|entry| {
                                (entry.source.clone(), entry.cell, entry.expected as usize)
                            })
                            .collect(),
                    )
                })
                .collect(),
            counters: self.counters,
        }
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
        let binding_base = unit.binding_base?;
        let expected_cell = DirectBindingCellVa::mapped(binding_base.get().checked_add(offset)?)?;
        if record != &owner.record
            || expected_cell != miss.cell
            || unit.source_lease.manifest.key != unit.key
            || unit.source_lease.binding_base != Some(binding_base)
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

    fn clear_published_cells(
        &mut self,
        mut recorder: impl FnMut(DirectBindingCellVa),
    ) -> (u64, u64) {
        let mut cells_cleared = 0_u64;
        let mut pages_touched = 0_u64;
        for unit in &mut self.units {
            let Some(binding_base) = unit.binding_base else {
                continue;
            };
            let mut last_page = None;
            for (word_index, word) in unit.published_bitmap.iter_mut().enumerate() {
                let mut published = *word;
                *word = 0;
                while published != 0 {
                    let bit = published.trailing_zeros() as usize;
                    published &= published - 1;
                    let ordinal = word_index * u64::BITS as usize + bit;
                    if ordinal >= unit.records.len() {
                        continue;
                    }
                    let address = binding_base.get() + ordinal * DIRECT_BINDING_CELL_SIZE as usize;
                    let cell = DirectBindingCellVa(address);
                    if !DirectBindingCellRef::registered(cell).clear_release() {
                        continue;
                    }
                    recorder(cell);
                    cells_cleared = cells_cleared.saturating_add(1);
                    let page = address & !(DARWIN_HOST_PAGE_SIZE - 1);
                    if last_page != Some(page) {
                        pages_touched = pages_touched.saturating_add(1);
                        last_page = Some(page);
                    }
                }
            }
        }
        (cells_cleared, pages_touched)
    }
}

/// Cold-path identity of the exact direct-binding cell that missed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectBindingMiss {
    pub cell: DirectBindingCellVa,
    pub ordinal: DirectBindingOrdinal,
}

/// Exit-time direct-binding metadata before cold-path authority validation.
///
/// A present-but-invalid mapped-cell value remains distinct from an absent
/// sidecar binding so the validation probe can report the mapped-cell failure
/// without guessing at a typed address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectBindingExitMetadata {
    Absent,
    Mapped(DirectBindingMiss),
    MappedCellFailure {
        raw_cell: u64,
        ordinal: DirectBindingOrdinal,
    },
}

impl DirectBindingExitMetadata {
    /// Returns the exact exit-time cell field for validation evidence.
    pub const fn raw_cell(self) -> u64 {
        match self {
            Self::Absent => 0,
            Self::Mapped(miss) => miss.cell.get() as u64,
            Self::MappedCellFailure { raw_cell, .. } => raw_cell,
        }
    }
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
    pub fn clear_release(self) -> bool {
        if self.load_acquire().is_null() {
            return false;
        }
        self.cell().store(std::ptr::null_mut(), Ordering::Release);
        true
    }

    fn cell(self) -> &'static AtomicPtr<DirectBindingTarget> {
        // SAFETY: `from_mapped_address` requires this address to identify a
        // live initialized `AtomicPtr` for the lifetime of every copied
        // adapter. All mapped-cell access is centralized in this adapter.
        unsafe { &*(self.address.get() as *const AtomicPtr<DirectBindingTarget>) }
    }
}

#[cfg(test)]
mod evidence_reason_tests {
    use super::{DirectBindingClearReason, DirectBindingValidationReason};

    #[test]
    fn direct_binding_evidence_reasons_are_nonzero_stable_and_unique() {
        let clear = [
            DirectBindingClearReason::TargetInvalidation.raw(),
            DirectBindingClearReason::StaleWinnerRemoval.raw(),
            DirectBindingClearReason::ForkReset.raw(),
            DirectBindingClearReason::ExecReset.raw(),
        ];
        assert_eq!(clear, [1, 2, 3, 4]);
        assert_eq!(
            clear
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            clear.len()
        );

        let validation = [
            DirectBindingValidationReason::MissingEligibleRecord.raw(),
            DirectBindingValidationReason::AmbiguousEligibleRecord.raw(),
            DirectBindingValidationReason::MissMetadataMismatch.raw(),
            DirectBindingValidationReason::OwnerMismatch.raw(),
            DirectBindingValidationReason::AuthorityMismatch.raw(),
            DirectBindingValidationReason::MappedCellFailure.raw(),
        ];
        assert_eq!(validation, [1, 2, 3, 4, 5, 6]);
        assert_eq!(
            validation
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            validation.len()
        );
    }
}
