//! Runtime authority for the pointer-free HAL frame inventory.
//!
//! Mapping generations are per-`MappingId` lifecycle versions. Preparation
//! starts at generation 1; publication retains that generation; each protect
//! or unmap advances it by exactly one. Frame retirement must share the final
//! unmap generation in the same transaction. IDs and generations never restart.

use std::collections::{BTreeMap, HashMap};
use std::num::NonZeroU64;

use carrick_guest_mem::Gpa;
use carrick_hal::{
    FrameEventCapacity, FrameId, FrameInventoryBatch, FrameInventoryBatchError,
    FrameInventoryCommit, FrameInventoryEvent, FrameInventoryProvenance, FrameInventoryReservation,
    FrameLength, KernelTransactionId, MappingGeneration, MappingId, MemPerms,
};
use parking_lot::Mutex;

use super::{MmId, ObjectIdError, ObjectIdRegistry};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameRow {
    pub frame: FrameId,
    pub length: FrameLength,
    pub mappings: Vec<MappingId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingRow {
    pub mapping: MappingId,
    pub frame: FrameId,
    pub mm: MmId,
    pub generation: MappingGeneration,
    pub gpa: Gpa,
    pub length: FrameLength,
    pub permissions: MemPerms,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameInventorySnapshot {
    pub revision: u64,
    pub frames: Vec<FrameRow>,
    pub mappings: Vec<MappingRow>,
}

#[derive(Debug, Default)]
pub struct FrameInventoryAuthority {
    state: Mutex<InventoryState>,
}

#[derive(Debug, Default, Eq, PartialEq)]
struct InventoryState {
    revision: u64,
    reservations: BTreeMap<KernelTransactionId, ReservationRecord>,
    frames: BTreeMap<FrameId, FrameEntry>,
    mappings: BTreeMap<MappingId, MappingEntry>,
}

#[derive(Debug, Eq, PartialEq)]
struct ReservationRecord {
    provenance: FrameInventoryProvenance,
    frames: Vec<FrameId>,
    mappings: Vec<MappingId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FrameEntry {
    length: FrameLength,
    mapping_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MappingEntry {
    frame: FrameId,
    mm: MmId,
    generation: MappingGeneration,
    gpa: Gpa,
    length: FrameLength,
    permissions: MemPerms,
    state: MappingState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MappingState {
    Prepared(KernelTransactionId),
    Published,
}

/// Transaction-local copy-on-write view. Only touched mappings and frames are
/// cloned, so applying one alias remains O(events + aliases of touched frames)
/// rather than O(the process-wide inventory).
struct InventoryOverlay<'a> {
    base: &'a InventoryState,
    frames: BTreeMap<FrameId, Option<FrameEntry>>,
    mappings: BTreeMap<MappingId, Option<MappingEntry>>,
    last_unmapped: BTreeMap<FrameId, MappingGeneration>,
}

struct InventoryChanges {
    frames: BTreeMap<FrameId, Option<FrameEntry>>,
    mappings: BTreeMap<MappingId, Option<MappingEntry>>,
}

impl<'a> InventoryOverlay<'a> {
    fn new(base: &'a InventoryState) -> Self {
        Self {
            base,
            frames: BTreeMap::new(),
            mappings: BTreeMap::new(),
            last_unmapped: BTreeMap::new(),
        }
    }

    fn mapping(&self, mapping: MappingId) -> Option<&MappingEntry> {
        match self.mappings.get(&mapping) {
            Some(Some(entry)) => Some(entry),
            Some(None) => None,
            None => self.base.mappings.get(&mapping),
        }
    }

    fn mapping_mut(&mut self, mapping: MappingId) -> Option<&mut MappingEntry> {
        if !self.mappings.contains_key(&mapping) {
            let entry = *self.base.mappings.get(&mapping)?;
            self.mappings.insert(mapping, Some(entry));
        }
        self.mappings.get_mut(&mapping)?.as_mut()
    }

    fn insert_mapping(&mut self, mapping: MappingId, entry: MappingEntry) {
        self.mappings.insert(mapping, Some(entry));
    }

    fn unmap_mapping(&mut self, mapping: MappingId, frame: FrameId, generation: MappingGeneration) {
        self.mappings.insert(mapping, None);
        self.last_unmapped.insert(frame, generation);
    }

    fn frame(&self, frame: FrameId) -> Option<&FrameEntry> {
        match self.frames.get(&frame) {
            Some(Some(entry)) => Some(entry),
            Some(None) => None,
            None => self.base.frames.get(&frame),
        }
    }

    fn frame_mut(&mut self, frame: FrameId) -> Option<&mut FrameEntry> {
        if !self.frames.contains_key(&frame) {
            let entry = *self.base.frames.get(&frame)?;
            self.frames.insert(frame, Some(entry));
        }
        self.frames.get_mut(&frame)?.as_mut()
    }

    fn insert_frame(&mut self, frame: FrameId, entry: FrameEntry) {
        self.frames.insert(frame, Some(entry));
    }

    fn retire_frame(&mut self, frame: FrameId) {
        self.frames.insert(frame, None);
    }

    fn into_changes(self) -> InventoryChanges {
        InventoryChanges {
            frames: self.frames,
            mappings: self.mappings,
        }
    }
}

impl FrameInventoryAuthority {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate and register the only candidate IDs this transaction may
    /// publish. A forged HAL batch therefore cannot become authoritative.
    pub fn reserve(
        &self,
        ids: &ObjectIdRegistry,
        frame_candidates: usize,
        mapping_candidates: usize,
        event_capacity: FrameEventCapacity,
    ) -> Result<FrameInventoryReservation, FrameInventoryReserveError> {
        let (reservation, record) =
            prepare_reservation(ids, frame_candidates, mapping_candidates, event_capacity)?;
        let transaction = reservation.transaction();
        if self
            .state
            .lock()
            .reservations
            .insert(transaction, record)
            .is_some()
        {
            return Err(FrameInventoryReserveError::DuplicateTransaction);
        }
        Ok(reservation)
    }

    /// Release provenance after backend work fails before publication.
    /// Candidate IDs remain burned in the monotonic registry.
    pub fn abandon(&self, transaction: KernelTransactionId) -> bool {
        self.state
            .lock()
            .reservations
            .remove(&transaction)
            .is_some()
    }

    /// Apply one backend commit atomically after backend locks are released.
    pub fn apply<T>(
        &self,
        mm: MmId,
        commit: FrameInventoryCommit<T>,
    ) -> Result<(T, u64), FrameInventoryError> {
        self.apply_inner(mm, commit, None)
    }

    fn apply_inner<T>(
        &self,
        mm: MmId,
        commit: FrameInventoryCommit<T>,
        fail_before_event: Option<usize>,
    ) -> Result<(T, u64), FrameInventoryError> {
        let transaction = commit.batch().transaction();
        let mut state = self.state.lock();
        let reserved_provenance = state
            .reservations
            .get(&transaction)
            .map(|reservation| reservation.provenance)
            .ok_or(FrameInventoryError::UnreservedTransaction(transaction))?;
        if !commit.provenance_matches(reserved_provenance) {
            return Err(FrameInventoryError::UnauthenticatedCommit(transaction));
        }
        let reservation = state
            .reservations
            .remove(&transaction)
            .ok_or(FrameInventoryError::UnreservedTransaction(transaction))?;
        let (outcome, batch) = commit.into_parts();
        if batch.events().is_empty() {
            return Err(FrameInventoryError::EmptyBatch);
        }
        let next_revision = state
            .revision
            .checked_add(1)
            .ok_or(FrameInventoryError::RevisionExhausted)?;
        let mut candidate = InventoryOverlay::new(&state);
        for (index, event) in batch.events().iter().copied().enumerate() {
            if fail_before_event == Some(index) {
                return Err(FrameInventoryError::InjectedFailure(index));
            }
            apply_event(&mut candidate, &reservation, mm, transaction, event)?;
        }
        if fail_before_event == Some(batch.events().len()) {
            return Err(FrameInventoryError::InjectedFailure(batch.events().len()));
        }
        if candidate.mappings.values().flatten().any(|mapping| {
            matches!(mapping.state, MappingState::Prepared(owner) if owner == transaction)
        }) {
            return Err(FrameInventoryError::UnpublishedMapping);
        }
        let changes = candidate.into_changes();
        for (frame, entry) in changes.frames {
            match entry {
                Some(entry) => {
                    state.frames.insert(frame, entry);
                }
                None => {
                    state.frames.remove(&frame);
                }
            }
        }
        for (mapping, entry) in changes.mappings {
            match entry {
                Some(entry) => {
                    state.mappings.insert(mapping, entry);
                }
                None => {
                    state.mappings.remove(&mapping);
                }
            }
        }
        state.revision = next_revision;
        Ok((outcome, next_revision))
    }

    pub fn snapshot(&self) -> FrameInventorySnapshot {
        snapshot_state(&self.state.lock(), None)
    }

    pub fn snapshot_for_mm(&self, mm: MmId) -> FrameInventorySnapshot {
        snapshot_state(&self.state.lock(), Some(mm))
    }

    #[cfg(test)]
    fn apply_with_failpoint<T>(
        &self,
        mm: MmId,
        commit: FrameInventoryCommit<T>,
        fail_before_event: usize,
    ) -> Result<(T, u64), FrameInventoryError> {
        self.apply_inner(mm, commit, Some(fail_before_event))
    }
}

fn apply_event(
    state: &mut InventoryOverlay<'_>,
    reservation: &ReservationRecord,
    mm: MmId,
    transaction: KernelTransactionId,
    event: FrameInventoryEvent,
) -> Result<(), FrameInventoryError> {
    if event.transaction() != transaction {
        return Err(FrameInventoryError::TransactionMismatch);
    }
    match event {
        FrameInventoryEvent::PrepareMapping {
            frame,
            mapping,
            generation,
            gpa,
            length,
            permissions,
            ..
        } => {
            if reservation.mappings.binary_search(&mapping).is_err() {
                return Err(FrameInventoryError::UnreservedMapping(mapping));
            }
            if gpa.0.checked_add(length.raw()).is_none() {
                return Err(FrameInventoryError::ExtentOverflow { gpa, length });
            }
            if generation.raw() != 1 {
                return Err(FrameInventoryError::GenerationMismatch {
                    mapping,
                    expected: 1,
                    actual: generation.raw(),
                });
            }
            if let Some(existing) = state.mapping(mapping) {
                return Err(if existing.mm != mm {
                    FrameInventoryError::CrossMmMappingReuse {
                        mapping,
                        owner: existing.mm,
                        attempted: mm,
                    }
                } else {
                    FrameInventoryError::DuplicateMapping(mapping)
                });
            }
            if state.frame(frame).is_none() {
                if reservation.frames.binary_search(&frame).is_err() {
                    return Err(FrameInventoryError::UnreservedFrame(frame));
                }
                state.insert_frame(
                    frame,
                    FrameEntry {
                        length,
                        mapping_count: 0,
                    },
                );
            }
            let frame_entry = state
                .frame_mut(frame)
                .ok_or(FrameInventoryError::RetiredFrame(frame))?;
            if frame_entry.length != length {
                return Err(FrameInventoryError::FrameLengthMismatch {
                    frame,
                    expected: frame_entry.length,
                    actual: length,
                });
            }
            frame_entry.mapping_count = frame_entry
                .mapping_count
                .checked_add(1)
                .ok_or(FrameInventoryError::MappingCountExhausted(frame))?;
            state.insert_mapping(
                mapping,
                MappingEntry {
                    frame,
                    mm,
                    generation,
                    gpa,
                    length,
                    permissions,
                    state: MappingState::Prepared(transaction),
                },
            );
        }
        FrameInventoryEvent::PublishMapping {
            mapping,
            generation,
            ..
        } => {
            let entry = state
                .mapping_mut(mapping)
                .ok_or(FrameInventoryError::NonliveMapping(mapping))?;
            if entry.mm != mm {
                return Err(FrameInventoryError::CrossMmMappingReuse {
                    mapping,
                    owner: entry.mm,
                    attempted: mm,
                });
            }
            if entry.generation != generation {
                return Err(generation_error(mapping, entry.generation, generation));
            }
            if entry.state != MappingState::Prepared(transaction) {
                return Err(FrameInventoryError::InvalidOrdering(mapping));
            }
            entry.state = MappingState::Published;
        }
        FrameInventoryEvent::ProtectMapping {
            mapping,
            generation,
            permissions,
            ..
        } => {
            let entry = live_mapping_mut(state, mm, mapping)?;
            require_next_generation(mapping, entry.generation, generation)?;
            entry.generation = generation;
            entry.permissions = permissions;
        }
        FrameInventoryEvent::UnmapMapping {
            mapping,
            generation,
            ..
        } => {
            let frame_id = {
                let entry = live_mapping_mut(state, mm, mapping)?;
                require_next_generation(mapping, entry.generation, generation)?;
                entry.frame
            };
            let frame = state
                .frame_mut(frame_id)
                .ok_or(FrameInventoryError::RetiredFrame(frame_id))?;
            frame.mapping_count = frame
                .mapping_count
                .checked_sub(1)
                .ok_or(FrameInventoryError::MappingCountUnderflow(frame_id))?;
            state.unmap_mapping(mapping, frame_id, generation);
        }
        FrameInventoryEvent::RetireFrame {
            frame, generation, ..
        } => {
            let entry = state
                .frame(frame)
                .ok_or(FrameInventoryError::RetiredFrame(frame))?;
            if entry.mapping_count != 0 {
                return Err(FrameInventoryError::FrameStillMapped(frame));
            }
            let expected = state
                .last_unmapped
                .get(&frame)
                .copied()
                .ok_or(FrameInventoryError::RetireWithoutUnmap(frame))?;
            if generation != expected {
                return Err(FrameInventoryError::FrameGenerationMismatch {
                    frame,
                    expected: expected.raw(),
                    actual: generation.raw(),
                });
            }
            state.retire_frame(frame);
        }
    }
    Ok(())
}

fn live_mapping_mut<'a>(
    state: &'a mut InventoryOverlay<'_>,
    mm: MmId,
    mapping: MappingId,
) -> Result<&'a mut MappingEntry, FrameInventoryError> {
    let entry = state
        .mapping_mut(mapping)
        .ok_or(FrameInventoryError::NonliveMapping(mapping))?;
    if entry.mm != mm {
        return Err(FrameInventoryError::CrossMmMappingReuse {
            mapping,
            owner: entry.mm,
            attempted: mm,
        });
    }
    if entry.state != MappingState::Published {
        return Err(FrameInventoryError::NonliveMapping(mapping));
    }
    Ok(entry)
}

fn require_next_generation(
    mapping: MappingId,
    current: MappingGeneration,
    actual: MappingGeneration,
) -> Result<(), FrameInventoryError> {
    let expected = next_generation(current)?;
    if expected != actual {
        return Err(generation_error(mapping, expected, actual));
    }
    Ok(())
}

fn next_generation(
    generation: MappingGeneration,
) -> Result<MappingGeneration, FrameInventoryError> {
    let raw = generation
        .raw()
        .checked_add(1)
        .and_then(NonZeroU64::new)
        .ok_or(FrameInventoryError::GenerationExhausted)?;
    Ok(MappingGeneration::from_backend_counter(raw))
}

fn generation_error(
    mapping: MappingId,
    expected: MappingGeneration,
    actual: MappingGeneration,
) -> FrameInventoryError {
    FrameInventoryError::GenerationMismatch {
        mapping,
        expected: expected.raw(),
        actual: actual.raw(),
    }
}

fn snapshot_state(state: &InventoryState, mm_filter: Option<MmId>) -> FrameInventorySnapshot {
    let mut frames = Vec::with_capacity(state.frames.len());
    let mut frame_indexes = HashMap::with_capacity(state.frames.len());
    for (index, (frame, entry)) in state.frames.iter().enumerate() {
        frame_indexes.insert(*frame, index);
        frames.push(FrameRow {
            frame: *frame,
            length: entry.length,
            mappings: Vec::new(),
        });
    }
    let mut mappings = Vec::with_capacity(state.mappings.len());
    for (mapping, entry) in &state.mappings {
        if entry.state != MappingState::Published || mm_filter.is_some_and(|mm| entry.mm != mm) {
            continue;
        }
        let row = MappingRow {
            mapping: *mapping,
            frame: entry.frame,
            mm: entry.mm,
            generation: entry.generation,
            gpa: entry.gpa,
            length: entry.length,
            permissions: entry.permissions,
        };
        if let Some(index) = frame_indexes.get(&entry.frame).copied() {
            frames[index].mappings.push(*mapping);
        }
        mappings.push(row);
    }
    if mm_filter.is_some() {
        frames.retain(|frame| !frame.mappings.is_empty());
    }
    FrameInventorySnapshot {
        revision: state.revision,
        frames,
        mappings,
    }
}

fn prepare_reservation(
    ids: &ObjectIdRegistry,
    frame_candidates: usize,
    mapping_candidates: usize,
    event_capacity: FrameEventCapacity,
) -> Result<(FrameInventoryReservation, ReservationRecord), FrameInventoryReserveError> {
    if frame_candidates > event_capacity.get() || mapping_candidates > event_capacity.get() {
        return Err(FrameInventoryReserveError::CandidateCountExceedsEvents);
    }
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(frame_candidates)
        .map_err(|_| FrameInventoryReserveError::AllocationFailed)?;
    let mut mappings = Vec::new();
    mappings
        .try_reserve_exact(mapping_candidates)
        .map_err(|_| FrameInventoryReserveError::AllocationFailed)?;
    let mut recorded_frames = Vec::new();
    recorded_frames
        .try_reserve_exact(frame_candidates)
        .map_err(|_| FrameInventoryReserveError::AllocationFailed)?;
    let mut recorded_mappings = Vec::new();
    recorded_mappings
        .try_reserve_exact(mapping_candidates)
        .map_err(|_| FrameInventoryReserveError::AllocationFailed)?;
    let transaction = ids.transaction_id()?;
    let mut provenance_bytes = [0_u8; 32];
    getrandom::fill(&mut provenance_bytes)
        .map_err(|_| FrameInventoryReserveError::EntropyUnavailable)?;
    let provenance = FrameInventoryProvenance::from_kernel_entropy(provenance_bytes);
    let batch = FrameInventoryBatch::prepare(transaction, event_capacity)?;
    for _ in 0..frame_candidates {
        let frame = ids.frame_id()?;
        frames.push(frame);
        recorded_frames.push(frame);
    }
    for _ in 0..mapping_candidates {
        let mapping = ids.mapping_id()?;
        mappings.push(mapping);
        recorded_mappings.push(mapping);
    }
    let record = ReservationRecord {
        provenance,
        frames: recorded_frames,
        mappings: recorded_mappings,
    };
    Ok((
        FrameInventoryReservation::from_kernel_candidates(provenance, batch, frames, mappings),
        record,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FrameInventoryReserveError {
    #[error("candidate count exceeds the bounded event capacity")]
    CandidateCountExceedsEvents,
    #[error("frame inventory candidate storage allocation failed")]
    AllocationFailed,
    #[error("frame inventory transaction candidate was already registered")]
    DuplicateTransaction,
    #[error("frame inventory reservation entropy is unavailable")]
    EntropyUnavailable,
    #[error(transparent)]
    ObjectId(#[from] ObjectIdError),
    #[error(transparent)]
    Batch(#[from] FrameInventoryBatchError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FrameInventoryError {
    #[error("frame inventory batch is empty")]
    EmptyBatch,
    #[error("frame inventory transaction {0:?} was not reserved by this authority")]
    UnreservedTransaction(KernelTransactionId),
    #[error("frame inventory transaction {0:?} has invalid provenance")]
    UnauthenticatedCommit(KernelTransactionId),
    #[error("frame {0:?} was not reserved by this authority")]
    UnreservedFrame(FrameId),
    #[error("mapping {0:?} was not reserved by this authority")]
    UnreservedMapping(MappingId),
    #[error("frame inventory event transaction does not match its batch")]
    TransactionMismatch,
    #[error("mapping {0:?} is duplicated")]
    DuplicateMapping(MappingId),
    #[error("mapping {mapping:?} belongs to mm {owner:?}, not {attempted:?}")]
    CrossMmMappingReuse {
        mapping: MappingId,
        owner: MmId,
        attempted: MmId,
    },
    #[error("mapping {0:?} is not live")]
    NonliveMapping(MappingId),
    #[error("mapping {0:?} event is out of lifecycle order")]
    InvalidOrdering(MappingId),
    #[error("mapping {mapping:?} generation {actual} does not match expected {expected}")]
    GenerationMismatch {
        mapping: MappingId,
        expected: u64,
        actual: u64,
    },
    #[error("frame {frame:?} generation {actual} does not match expected {expected}")]
    FrameGenerationMismatch {
        frame: FrameId,
        expected: u64,
        actual: u64,
    },
    #[error("mapping extent at {gpa:?} with length {length:?} overflows the GPA domain")]
    ExtentOverflow { gpa: Gpa, length: FrameLength },
    #[error("frame {frame:?} length {actual:?} does not match {expected:?}")]
    FrameLengthMismatch {
        frame: FrameId,
        expected: FrameLength,
        actual: FrameLength,
    },
    #[error("frame {0:?} is retired or unknown")]
    RetiredFrame(FrameId),
    #[error("frame {0:?} still has live mappings")]
    FrameStillMapped(FrameId),
    #[error("frame {0:?} retirement is not paired with its last unmap")]
    RetireWithoutUnmap(FrameId),
    #[error("batch leaves a prepared mapping unpublished")]
    UnpublishedMapping,
    #[error("mapping generation space exhausted")]
    GenerationExhausted,
    #[error("frame {0:?} mapping count exhausted")]
    MappingCountExhausted(FrameId),
    #[error("frame {0:?} mapping count underflowed")]
    MappingCountUnderflow(FrameId),
    #[error("frame inventory revision space exhausted")]
    RevisionExhausted,
    #[error("test failpoint before event {0}")]
    InjectedFailure(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nz(raw: u64) -> NonZeroU64 {
        NonZeroU64::new(raw).expect("nonzero fixture value")
    }

    fn generation(raw: u64) -> MappingGeneration {
        MappingGeneration::from_backend_counter(nz(raw))
    }

    fn length(raw: u64) -> FrameLength {
        FrameLength::from_mapping_extent(nz(raw))
    }

    fn perms(write: bool) -> MemPerms {
        MemPerms {
            read: true,
            write,
            exec: false,
        }
    }

    struct Fixture {
        ids: ObjectIdRegistry,
        authority: FrameInventoryAuthority,
        mm1: MmId,
        mm2: MmId,
    }

    impl Fixture {
        fn new() -> Self {
            let ids = ObjectIdRegistry::new();
            let mm1 = ids.mm_id().expect("first mm");
            let mm2 = ids.mm_id().expect("second mm");
            Self {
                ids,
                authority: FrameInventoryAuthority::new(),
                mm1,
                mm2,
            }
        }

        fn batch(
            &self,
            events: usize,
            build: impl FnOnce(KernelTransactionId, &mut FrameInventoryReservation),
        ) -> FrameInventoryCommit<()> {
            let capacity = FrameEventCapacity::for_event_count(events).expect("capacity");
            let mut reservation = self
                .authority
                .reserve(&self.ids, events, events, capacity)
                .expect("reservation");
            let transaction = reservation.transaction();
            build(transaction, &mut reservation);
            reservation.commit(())
        }
    }

    fn prepare_publish(
        reservation: &mut FrameInventoryReservation,
        transaction: KernelTransactionId,
        frame: FrameId,
        mapping: MappingId,
        gpa: u64,
        len: u64,
    ) {
        reservation
            .push(FrameInventoryEvent::PrepareMapping {
                transaction,
                frame,
                mapping,
                generation: generation(1),
                gpa: Gpa(gpa),
                length: length(len),
                permissions: perms(true),
            })
            .expect("prepare");
        reservation
            .push(FrameInventoryEvent::PublishMapping {
                transaction,
                mapping,
                generation: generation(1),
            })
            .expect("publish");
    }

    #[test]
    fn sparse_40_gib_extent_stays_one_k1_frame_and_mapping() {
        let fixture = Fixture::new();
        const SPARSE_BANK_LEN: u64 = 40 * 1024 * 1024 * 1024;
        let batch = fixture.batch(2, |transaction, reservation| {
            let frame = reservation.claim_frame().expect("extent frame");
            let mapping = reservation.claim_mapping().expect("extent mapping");
            prepare_publish(
                reservation,
                transaction,
                frame,
                mapping,
                0x4000,
                SPARSE_BANK_LEN,
            );
        });
        fixture
            .authority
            .apply(fixture.mm1, batch)
            .expect("apply sparse extent");

        let snapshot = fixture.authority.snapshot();
        assert_eq!(snapshot.frames.len(), 1);
        assert_eq!(snapshot.mappings.len(), 1);
        assert_eq!(snapshot.frames[0].length.raw(), SPARSE_BANK_LEN);
        assert_eq!(snapshot.mappings[0].length.raw(), SPARSE_BANK_LEN);
    }

    #[test]
    fn high_alias_frame_keeps_constant_size_apply_state() {
        let fixture = Fixture::new();
        const ALIASES: usize = 1_024;
        assert_eq!(std::mem::size_of::<FrameEntry>(), 16);
        let mut first_mapping = None;
        let publish = fixture.batch(ALIASES * 2, |transaction, reservation| {
            let frame = reservation.claim_frame().expect("shared frame");
            for index in 0..ALIASES {
                let mapping = reservation.claim_mapping().expect("alias mapping");
                first_mapping.get_or_insert(mapping);
                prepare_publish(
                    reservation,
                    transaction,
                    frame,
                    mapping,
                    0x4000 + u64::try_from(index).expect("bounded index") * 0x4000,
                    0x4000,
                );
            }
        });
        fixture
            .authority
            .apply(fixture.mm1, publish)
            .expect("publish aliases");
        assert_eq!(
            fixture.authority.snapshot().frames[0].mappings.len(),
            ALIASES
        );

        let mapping = first_mapping.expect("first alias");
        let protect = fixture.batch(1, |transaction, reservation| {
            reservation
                .push(FrameInventoryEvent::ProtectMapping {
                    transaction,
                    mapping,
                    generation: generation(2),
                    permissions: perms(false),
                })
                .expect("protect one alias");
        });
        fixture
            .authority
            .apply(fixture.mm1, protect)
            .expect("constant-size protect");
        assert_eq!(
            fixture.authority.snapshot().frames[0].mappings.len(),
            ALIASES
        );
    }

    #[test]
    fn shared_frame_aliases_and_copied_frames_have_exact_sorted_joins() {
        let fixture = Fixture::new();
        let batch = fixture.batch(6, |transaction, reservation| {
            let shared = reservation.claim_frame().expect("shared frame");
            let copied = reservation.claim_frame().expect("copied frame");
            let high = reservation.claim_mapping().expect("mapping");
            let low = reservation.claim_mapping().expect("mapping");
            let copy = reservation.claim_mapping().expect("mapping");
            prepare_publish(reservation, transaction, shared, high, 0x8000, 0x4000);
            prepare_publish(reservation, transaction, shared, low, 0x4000, 0x4000);
            prepare_publish(reservation, transaction, copied, copy, 0xc000, 0x4000);
        });
        fixture.authority.apply(fixture.mm1, batch).expect("apply");

        let snapshot = fixture.authority.snapshot();
        assert_eq!(snapshot.revision, 1);
        assert_eq!(snapshot.frames.len(), 2);
        assert_eq!(snapshot.mappings.len(), 3);
        assert!(
            snapshot
                .frames
                .windows(2)
                .all(|rows| rows[0].frame < rows[1].frame)
        );
        assert!(
            snapshot
                .mappings
                .windows(2)
                .all(|rows| rows[0].mapping < rows[1].mapping)
        );
        for frame in &snapshot.frames {
            for mapping in &frame.mappings {
                assert_eq!(
                    snapshot
                        .mappings
                        .iter()
                        .find(|row| row.mapping == *mapping)
                        .map(|row| row.frame),
                    Some(frame.frame)
                );
            }
        }
        assert_eq!(fixture.authority.snapshot_for_mm(fixture.mm1), snapshot);
        assert!(
            fixture
                .authority
                .snapshot_for_mm(fixture.mm2)
                .mappings
                .is_empty()
        );
    }

    #[test]
    fn one_frame_can_join_aliases_from_distinct_mms() {
        let fixture = Fixture::new();
        let mut shared = None;
        let first = fixture.batch(2, |transaction, reservation| {
            let frame = reservation.claim_frame().expect("frame");
            let mapping = reservation.claim_mapping().expect("mapping");
            shared = Some((frame, mapping));
            prepare_publish(reservation, transaction, frame, mapping, 0x4000, 0x4000);
        });
        fixture
            .authority
            .apply(fixture.mm1, first)
            .expect("first alias");
        let (frame, first_mapping) = shared.expect("shared frame ID");
        let mut second_mapping = None;
        let second = fixture.batch(2, |transaction, reservation| {
            let mapping = reservation.claim_mapping().expect("mapping");
            second_mapping = Some(mapping);
            prepare_publish(reservation, transaction, frame, mapping, 0x8000, 0x4000);
        });
        fixture
            .authority
            .apply(fixture.mm2, second)
            .expect("second alias");

        assert_eq!(fixture.authority.snapshot().frames[0].mappings.len(), 2);
        assert_eq!(
            fixture.authority.snapshot_for_mm(fixture.mm1).frames[0]
                .mappings
                .len(),
            1
        );
        assert_eq!(
            fixture.authority.snapshot_for_mm(fixture.mm2).frames[0]
                .mappings
                .len(),
            1
        );

        let unmap_first = fixture.batch(1, |transaction, reservation| {
            reservation
                .push(FrameInventoryEvent::UnmapMapping {
                    transaction,
                    mapping: first_mapping,
                    generation: generation(2),
                })
                .expect("unmap first alias");
        });
        fixture
            .authority
            .apply(fixture.mm1, unmap_first)
            .expect("remove first alias");
        assert!(
            fixture
                .authority
                .snapshot_for_mm(fixture.mm1)
                .frames
                .is_empty()
        );
        assert_eq!(fixture.authority.snapshot().frames[0].mappings.len(), 1);

        let second_mapping = second_mapping.expect("second mapping");
        let retire = fixture.batch(2, |transaction, reservation| {
            reservation
                .push(FrameInventoryEvent::UnmapMapping {
                    transaction,
                    mapping: second_mapping,
                    generation: generation(2),
                })
                .expect("unmap second alias");
            reservation
                .push(FrameInventoryEvent::RetireFrame {
                    transaction,
                    frame,
                    generation: generation(2),
                })
                .expect("retire shared frame");
        });
        fixture
            .authority
            .apply(fixture.mm2, retire)
            .expect("retire last cross-mm alias");
        assert!(fixture.authority.snapshot().frames.is_empty());
        assert!(fixture.authority.snapshot().mappings.is_empty());
    }

    #[test]
    fn protect_then_atomic_unmap_retire_advances_generation_and_reclaims_rows() {
        let fixture = Fixture::new();
        let (frame, mapping) = {
            let mut values = None;
            let batch = fixture.batch(2, |transaction, reservation| {
                let frame = reservation.claim_frame().expect("frame");
                let mapping = reservation.claim_mapping().expect("mapping");
                values = Some((frame, mapping));
                prepare_publish(reservation, transaction, frame, mapping, 0x4000, 0x4000);
            });
            fixture
                .authority
                .apply(fixture.mm1, batch)
                .expect("publish");
            values.expect("IDs")
        };
        let protect = fixture.batch(1, |transaction, reservation| {
            reservation
                .push(FrameInventoryEvent::ProtectMapping {
                    transaction,
                    mapping,
                    generation: generation(2),
                    permissions: perms(false),
                })
                .expect("protect");
        });
        fixture
            .authority
            .apply(fixture.mm1, protect)
            .expect("protect apply");
        assert!(!fixture.authority.snapshot().mappings[0].permissions.write);

        let retire = fixture.batch(2, |transaction, reservation| {
            reservation
                .push(FrameInventoryEvent::UnmapMapping {
                    transaction,
                    mapping,
                    generation: generation(3),
                })
                .expect("unmap");
            reservation
                .push(FrameInventoryEvent::RetireFrame {
                    transaction,
                    frame,
                    generation: generation(3),
                })
                .expect("retire");
        });
        fixture
            .authority
            .apply(fixture.mm1, retire)
            .expect("unmap and retire apply");
        assert_eq!(fixture.authority.snapshot().revision, 3);
        assert!(fixture.authority.snapshot().frames.is_empty());
        assert!(fixture.authority.snapshot().mappings.is_empty());
    }

    #[test]
    fn rejects_duplicate_transaction_generation_length_order_and_cross_mm_reuse() {
        let fixture = Fixture::new();
        let mut ids = None;
        let original = fixture.batch(2, |transaction, reservation| {
            let frame = reservation.claim_frame().expect("frame");
            let mapping = reservation.claim_mapping().expect("mapping");
            ids = Some((frame, mapping));
            prepare_publish(reservation, transaction, frame, mapping, 0x4000, 0x4000);
        });
        let transaction = original.batch().transaction();
        let duplicate = FrameInventoryReservation::from_kernel_candidates(
            FrameInventoryProvenance::from_kernel_entropy([0x55; 32]),
            FrameInventoryBatch::prepare(
                transaction,
                FrameEventCapacity::for_event_count(1).expect("capacity"),
            )
            .expect("forged batch"),
            Vec::new(),
            Vec::new(),
        )
        .commit(());
        fixture
            .authority
            .apply(fixture.mm1, original)
            .expect("first");
        assert!(matches!(
            fixture.authority.apply(fixture.mm1, duplicate),
            Err(FrameInventoryError::UnreservedTransaction(_))
        ));
        let (frame, mapping) = ids.expect("IDs");

        let stale = fixture.batch(1, |transaction, reservation| {
            reservation
                .push(FrameInventoryEvent::ProtectMapping {
                    transaction,
                    mapping,
                    generation: generation(3),
                    permissions: perms(false),
                })
                .expect("event");
        });
        assert!(matches!(
            fixture.authority.apply(fixture.mm1, stale),
            Err(FrameInventoryError::GenerationMismatch { .. })
        ));
        let cross_mm = fixture.batch(1, |transaction, reservation| {
            reservation
                .push(FrameInventoryEvent::ProtectMapping {
                    transaction,
                    mapping,
                    generation: generation(2),
                    permissions: perms(false),
                })
                .expect("event");
        });
        assert!(matches!(
            fixture.authority.apply(fixture.mm2, cross_mm),
            Err(FrameInventoryError::CrossMmMappingReuse { .. })
        ));
        let alias_wrong_length = fixture.batch(2, |transaction, reservation| {
            let alias = reservation.claim_mapping().expect("alias");
            prepare_publish(reservation, transaction, frame, alias, 0x8000, 0x8000);
        });
        assert!(matches!(
            fixture.authority.apply(fixture.mm1, alias_wrong_length),
            Err(FrameInventoryError::FrameLengthMismatch { .. })
        ));
        let unmap_unknown = fixture.batch(1, |transaction, reservation| {
            let unknown = reservation.claim_mapping().expect("unknown");
            reservation
                .push(FrameInventoryEvent::UnmapMapping {
                    transaction,
                    mapping: unknown,
                    generation: generation(1),
                })
                .expect("event");
        });
        assert!(matches!(
            fixture.authority.apply(fixture.mm1, unmap_unknown),
            Err(FrameInventoryError::NonliveMapping(_))
        ));
    }

    #[test]
    fn invalid_lifecycle_ordering_and_duplicate_mapping_roll_back_exactly() {
        let fixture = Fixture::new();
        let mut ids = None;
        let initial = fixture.batch(2, |transaction, reservation| {
            let frame = reservation.claim_frame().expect("frame");
            let mapping = reservation.claim_mapping().expect("mapping");
            ids = Some((frame, mapping));
            prepare_publish(reservation, transaction, frame, mapping, 0x4000, 0x4000);
        });
        fixture
            .authority
            .apply(fixture.mm1, initial)
            .expect("initial mapping");
        let (frame, mapping) = ids.expect("IDs");
        let before = fixture.authority.snapshot();

        let duplicate = fixture.batch(2, |transaction, reservation| {
            prepare_publish(reservation, transaction, frame, mapping, 0x8000, 0x4000);
        });
        assert_eq!(
            fixture.authority.apply(fixture.mm1, duplicate),
            Err(FrameInventoryError::UnreservedMapping(mapping))
        );
        assert_eq!(fixture.authority.snapshot(), before);

        let publish_again = fixture.batch(1, |transaction, reservation| {
            reservation
                .push(FrameInventoryEvent::PublishMapping {
                    transaction,
                    mapping,
                    generation: generation(1),
                })
                .expect("publish event");
        });
        assert_eq!(
            fixture.authority.apply(fixture.mm1, publish_again),
            Err(FrameInventoryError::InvalidOrdering(mapping))
        );
        assert_eq!(fixture.authority.snapshot(), before);

        let retire_live = fixture.batch(1, |transaction, reservation| {
            reservation
                .push(FrameInventoryEvent::RetireFrame {
                    transaction,
                    frame,
                    generation: generation(2),
                })
                .expect("retire event");
        });
        assert_eq!(
            fixture.authority.apply(fixture.mm1, retire_live),
            Err(FrameInventoryError::FrameStillMapped(frame))
        );
        assert_eq!(fixture.authority.snapshot(), before);
    }

    #[test]
    fn unused_candidate_ids_burn_in_the_runtime_registry() {
        let fixture = Fixture::new();
        let capacity = FrameEventCapacity::for_event_count(2).expect("capacity");
        let mut abandoned = fixture
            .authority
            .reserve(&fixture.ids, 2, 2, capacity)
            .expect("reservation");
        let transaction = abandoned.transaction();
        let claimed_frame = abandoned.claim_frame().expect("frame");
        let claimed_mapping = abandoned.claim_mapping().expect("mapping");
        drop(abandoned);
        assert!(fixture.authority.abandon(transaction));

        let mut replacement = fixture
            .authority
            .reserve(&fixture.ids, 1, 1, capacity)
            .expect("replacement");
        assert!(replacement.claim_frame().expect("new frame").raw() > claimed_frame.raw());
        assert!(replacement.claim_mapping().expect("new mapping").raw() > claimed_mapping.raw());
    }

    #[test]
    fn rejects_an_unreserved_new_frame_even_with_a_reserved_mapping() {
        let fixture = Fixture::new();
        let forged = fixture.ids.frame_id().expect("forged frame");
        let batch = fixture.batch(2, |transaction, reservation| {
            let mapping = reservation.claim_mapping().expect("mapping");
            prepare_publish(reservation, transaction, forged, mapping, 0x4000, 0x4000);
        });
        assert_eq!(
            fixture.authority.apply(fixture.mm1, batch),
            Err(FrameInventoryError::UnreservedFrame(forged))
        );
        assert!(fixture.authority.snapshot().frames.is_empty());
    }

    #[test]
    fn guessed_ids_cannot_forge_a_reserved_transaction_capability() {
        let fixture = Fixture::new();
        let capacity = FrameEventCapacity::for_event_count(2).expect("capacity");
        let mut legitimate = fixture
            .authority
            .reserve(&fixture.ids, 1, 1, capacity)
            .expect("legitimate reservation");
        let transaction = legitimate.transaction();
        let frame = legitimate.claim_frame().expect("frame");
        let mapping = legitimate.claim_mapping().expect("mapping");
        prepare_publish(&mut legitimate, transaction, frame, mapping, 0x4000, 0x4000);

        let mut forged_batch =
            FrameInventoryBatch::prepare(transaction, capacity).expect("forged batch");
        forged_batch
            .push(FrameInventoryEvent::PrepareMapping {
                transaction,
                frame,
                mapping,
                generation: generation(1),
                gpa: Gpa(0x4000),
                length: length(0x4000),
                permissions: perms(true),
            })
            .expect("forged prepare");
        forged_batch
            .push(FrameInventoryEvent::PublishMapping {
                transaction,
                mapping,
                generation: generation(1),
            })
            .expect("forged publish");
        let forged = FrameInventoryReservation::from_kernel_candidates(
            FrameInventoryProvenance::from_kernel_entropy([0x99; 32]),
            forged_batch,
            vec![frame],
            vec![mapping],
        )
        .commit(());
        assert_eq!(
            fixture.authority.apply(fixture.mm1, forged),
            Err(FrameInventoryError::UnauthenticatedCommit(transaction))
        );
        fixture
            .authority
            .apply(fixture.mm1, legitimate.commit(()))
            .expect("real capability remains valid");
        assert_eq!(fixture.authority.snapshot().mappings.len(), 1);
    }

    #[test]
    fn duplicate_mapping_inside_one_reserved_batch_is_rejected_atomically() {
        let fixture = Fixture::new();
        let mut duplicate = None;
        let batch = fixture.batch(3, |transaction, reservation| {
            let frame = reservation.claim_frame().expect("frame");
            let mapping = reservation.claim_mapping().expect("mapping");
            duplicate = Some(mapping);
            prepare_publish(reservation, transaction, frame, mapping, 0x4000, 0x4000);
            reservation
                .push(FrameInventoryEvent::PrepareMapping {
                    transaction,
                    frame,
                    mapping,
                    generation: generation(1),
                    gpa: Gpa(0x8000),
                    length: length(0x4000),
                    permissions: perms(true),
                })
                .expect("duplicate prepare");
        });
        let mapping = duplicate.expect("mapping ID");
        assert_eq!(
            fixture.authority.apply(fixture.mm1, batch),
            Err(FrameInventoryError::DuplicateMapping(mapping))
        );
        assert!(fixture.authority.snapshot().mappings.is_empty());
    }

    #[test]
    fn completed_mapping_churn_reclaims_rows_and_provenance() {
        let fixture = Fixture::new();
        for index in 0..128_u64 {
            let mut ids = None;
            let publish = fixture.batch(2, |transaction, reservation| {
                let frame = reservation.claim_frame().expect("frame");
                let mapping = reservation.claim_mapping().expect("mapping");
                ids = Some((frame, mapping));
                prepare_publish(
                    reservation,
                    transaction,
                    frame,
                    mapping,
                    0x4000 + index * 0x4000,
                    0x4000,
                );
            });
            fixture
                .authority
                .apply(fixture.mm1, publish)
                .expect("publish");
            let (frame, mapping) = ids.expect("IDs");
            let retire = fixture.batch(2, |transaction, reservation| {
                reservation
                    .push(FrameInventoryEvent::UnmapMapping {
                        transaction,
                        mapping,
                        generation: generation(2),
                    })
                    .expect("unmap");
                reservation
                    .push(FrameInventoryEvent::RetireFrame {
                        transaction,
                        frame,
                        generation: generation(2),
                    })
                    .expect("retire");
            });
            fixture
                .authority
                .apply(fixture.mm1, retire)
                .expect("retire");
        }
        let snapshot = fixture.authority.snapshot();
        assert_eq!(snapshot.revision, 256);
        assert!(snapshot.frames.is_empty());
        assert!(snapshot.mappings.is_empty());
        let state = fixture.authority.state.lock();
        assert!(state.reservations.is_empty());
        assert!(state.frames.is_empty());
        assert!(state.mappings.is_empty());
    }

    #[test]
    fn every_event_failpoint_rolls_back_the_whole_batch() {
        for failpoint in 0..=3 {
            let fixture = Fixture::new();
            let batch = fixture.batch(3, |transaction, reservation| {
                let frame = reservation.claim_frame().expect("frame");
                let mapping = reservation.claim_mapping().expect("mapping");
                prepare_publish(reservation, transaction, frame, mapping, 0x4000, 0x4000);
                reservation
                    .push(FrameInventoryEvent::ProtectMapping {
                        transaction,
                        mapping,
                        generation: generation(2),
                        permissions: perms(false),
                    })
                    .expect("protect");
            });
            let before = fixture.authority.snapshot();
            assert_eq!(
                fixture
                    .authority
                    .apply_with_failpoint(fixture.mm1, batch, failpoint),
                Err(FrameInventoryError::InjectedFailure(failpoint))
            );
            assert_eq!(fixture.authority.snapshot(), before);
            assert!(fixture.authority.state.lock().reservations.is_empty());
        }
    }

    #[test]
    fn unpublished_prepare_rolls_back_without_revision_or_join_changes() {
        let fixture = Fixture::new();
        let batch = fixture.batch(1, |transaction, reservation| {
            let frame = reservation.claim_frame().expect("frame");
            let mapping = reservation.claim_mapping().expect("mapping");
            reservation
                .push(FrameInventoryEvent::PrepareMapping {
                    transaction,
                    frame,
                    mapping,
                    generation: generation(1),
                    gpa: Gpa(0x4000),
                    length: length(0x4000),
                    permissions: perms(true),
                })
                .expect("prepare");
        });
        assert_eq!(
            fixture.authority.apply(fixture.mm1, batch),
            Err(FrameInventoryError::UnpublishedMapping)
        );
        assert_eq!(
            fixture.authority.snapshot(),
            FrameInventorySnapshot {
                revision: 0,
                frames: Vec::new(),
                mappings: Vec::new(),
            }
        );
        assert!(fixture.authority.state.lock().reservations.is_empty());
    }
}
