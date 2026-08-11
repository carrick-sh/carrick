//! Dependency-neutral kernel object identities shared by runtimes and VMMs.
//!
//! These values are allocated by the kernel object model and cross the
//! runtime/backend boundary without exposing pointers or raw host identities.

use std::fmt;
use std::num::{NonZeroU64, NonZeroUsize};

use carrick_guest_mem::Gpa;

use crate::MemPerms;

/// Fail closed before one operation can stage an unbounded diagnostic batch.
pub const MAX_FRAME_INVENTORY_EVENTS_PER_BATCH: usize = 262_144;

macro_rules! hal_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr(transparent)]
        pub struct $name(NonZeroU64);

        impl $name {
            /// Construct an ID from the kernel allocator's nonzero output.
            pub const fn from_kernel_allocation(raw: NonZeroU64) -> Self {
                Self(raw)
            }

            /// Export the scalar only at a wire, probe, or persistence boundary.
            pub const fn raw(self) -> u64 {
                self.0.get()
            }
        }
    };
}

hal_id!(FrameId);
hal_id!(MappingId);
hal_id!(KernelTransactionId);

/// Unpredictable authority capability bound to one runtime reservation.
///
/// The bytes are deliberately not exported or printed. Public construction
/// lets a dependency-neutral HAL accept kernel entropy, while authentication
/// still requires matching the authority's independently retained capability.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FrameInventoryProvenance([u8; 32]);

impl FrameInventoryProvenance {
    pub const fn from_kernel_entropy(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for FrameInventoryProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrameInventoryProvenance(REDACTED)")
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct MappingGeneration(NonZeroU64);

impl MappingGeneration {
    pub const fn from_backend_counter(raw: NonZeroU64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct FrameLength(NonZeroU64);

impl FrameLength {
    pub const fn from_mapping_extent(raw: NonZeroU64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0.get()
    }
}

/// Validated number of records one operation may stage. The batch reserves the
/// complete allocation before a backend lock can be acquired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct FrameEventCapacity(NonZeroUsize);

impl FrameEventCapacity {
    pub fn for_event_count(count: usize) -> Result<Self, FrameInventoryBatchError> {
        let Some(count) = NonZeroUsize::new(count) else {
            return Err(FrameInventoryBatchError::EmptyCapacity);
        };
        if count.get() > MAX_FRAME_INVENTORY_EVENTS_PER_BATCH {
            return Err(FrameInventoryBatchError::CapacityTooLarge {
                requested: count.get(),
                maximum: MAX_FRAME_INVENTORY_EVENTS_PER_BATCH,
            });
        }
        Ok(Self(count))
    }

    pub const fn get(self) -> usize {
        self.0.get()
    }
}

/// One staged frame-inventory change. Backends build these while committing
/// mappings and return the complete batch only after releasing backend locks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameInventoryEvent {
    PrepareMapping {
        transaction: KernelTransactionId,
        frame: FrameId,
        mapping: MappingId,
        generation: MappingGeneration,
        gpa: Gpa,
        length: FrameLength,
        permissions: MemPerms,
    },
    PublishMapping {
        transaction: KernelTransactionId,
        mapping: MappingId,
        generation: MappingGeneration,
    },
    ProtectMapping {
        transaction: KernelTransactionId,
        mapping: MappingId,
        generation: MappingGeneration,
        permissions: MemPerms,
    },
    UnmapMapping {
        transaction: KernelTransactionId,
        mapping: MappingId,
        generation: MappingGeneration,
    },
    RetireFrame {
        transaction: KernelTransactionId,
        frame: FrameId,
        generation: MappingGeneration,
    },
}

impl FrameInventoryEvent {
    pub const fn transaction(self) -> KernelTransactionId {
        match self {
            Self::PrepareMapping { transaction, .. }
            | Self::PublishMapping { transaction, .. }
            | Self::ProtectMapping { transaction, .. }
            | Self::UnmapMapping { transaction, .. }
            | Self::RetireFrame { transaction, .. } => transaction,
        }
    }

    pub const fn generation(self) -> MappingGeneration {
        match self {
            Self::PrepareMapping { generation, .. }
            | Self::PublishMapping { generation, .. }
            | Self::ProtectMapping { generation, .. }
            | Self::UnmapMapping { generation, .. }
            | Self::RetireFrame { generation, .. } => generation,
        }
    }
}

/// Uniquely owned operation-local inventory changes. Capacity is allocated
/// before backend locking; `push` cannot allocate and consumes the batch only
/// through `into_events`.
#[derive(Debug, Eq, PartialEq)]
pub struct FrameInventoryBatch {
    transaction: KernelTransactionId,
    event_capacity: FrameEventCapacity,
    events: Vec<FrameInventoryEvent>,
}

impl FrameInventoryBatch {
    pub fn prepare(
        transaction: KernelTransactionId,
        event_capacity: FrameEventCapacity,
    ) -> Result<Self, FrameInventoryBatchError> {
        let mut events = Vec::new();
        events
            .try_reserve_exact(event_capacity.get())
            .map_err(|_| FrameInventoryBatchError::AllocationFailed {
                requested: event_capacity.get(),
            })?;
        Ok(Self {
            transaction,
            event_capacity,
            events,
        })
    }

    pub fn push(&mut self, event: FrameInventoryEvent) -> Result<(), FrameInventoryBatchError> {
        if event.transaction() != self.transaction {
            return Err(FrameInventoryBatchError::TransactionMismatch {
                expected: self.transaction,
                actual: event.transaction(),
            });
        }
        if self.events.len() == self.event_capacity.get() {
            return Err(FrameInventoryBatchError::BatchFull {
                capacity: self.event_capacity.get(),
            });
        }
        self.events.push(event);
        Ok(())
    }

    pub const fn transaction(&self) -> KernelTransactionId {
        self.transaction
    }

    pub fn events(&self) -> &[FrameInventoryEvent] {
        &self.events
    }

    pub fn into_events(self) -> Vec<FrameInventoryEvent> {
        self.events
    }
}

/// Candidate identities and event storage reserved by the runtime before a
/// backend topology lock is acquired.
///
/// The reservation is intentionally non-cloneable. A backend may consume each
/// candidate at most once, and cannot manufacture replacements when it runs
/// short. Candidates left in a dropped or committed reservation are burned:
/// the runtime's monotonic object-ID registry never reissues them.
#[derive(Debug, Eq, PartialEq)]
pub struct FrameInventoryReservation {
    provenance: FrameInventoryProvenance,
    batch: FrameInventoryBatch,
    frame_candidates: Vec<FrameId>,
    mapping_candidates: Vec<MappingId>,
    next_frame: usize,
    next_mapping: usize,
}

impl FrameInventoryReservation {
    /// Assemble candidates allocated by the runtime kernel's object registry.
    /// Both candidate vectors and the event batch must already own all storage
    /// needed while backend locks are held.
    pub fn from_kernel_candidates(
        provenance: FrameInventoryProvenance,
        batch: FrameInventoryBatch,
        frame_candidates: Vec<FrameId>,
        mapping_candidates: Vec<MappingId>,
    ) -> Self {
        Self {
            provenance,
            batch,
            frame_candidates,
            mapping_candidates,
            next_frame: 0,
            next_mapping: 0,
        }
    }

    pub const fn transaction(&self) -> KernelTransactionId {
        self.batch.transaction()
    }

    pub fn claim_frame(&mut self) -> Result<FrameId, FrameInventoryReservationError> {
        let Some(candidate) = self.frame_candidates.get(self.next_frame).copied() else {
            return Err(FrameInventoryReservationError::FrameCandidatesExhausted);
        };
        self.next_frame += 1;
        Ok(candidate)
    }

    pub fn claim_mapping(&mut self) -> Result<MappingId, FrameInventoryReservationError> {
        let Some(candidate) = self.mapping_candidates.get(self.next_mapping).copied() else {
            return Err(FrameInventoryReservationError::MappingCandidatesExhausted);
        };
        self.next_mapping += 1;
        Ok(candidate)
    }

    pub fn push(
        &mut self,
        event: FrameInventoryEvent,
    ) -> Result<(), FrameInventoryReservationError> {
        self.batch.push(event).map_err(Into::into)
    }

    /// Finish backend work and carry its ordinary outcome beside the complete
    /// pointer-free inventory batch. This performs no runtime callback.
    pub fn commit<T>(self, outcome: T) -> FrameInventoryCommit<T> {
        FrameInventoryCommit {
            provenance: self.provenance,
            outcome,
            batch: self.batch,
        }
    }
}

/// Backend outcome paired with the inventory transaction runtime must apply
/// after releasing all backend locks.
#[derive(Debug, Eq, PartialEq)]
pub struct FrameInventoryCommit<T> {
    provenance: FrameInventoryProvenance,
    outcome: T,
    batch: FrameInventoryBatch,
}

impl<T> FrameInventoryCommit<T> {
    pub fn provenance_matches(&self, expected: FrameInventoryProvenance) -> bool {
        self.provenance == expected
    }

    pub fn outcome(&self) -> &T {
        &self.outcome
    }

    pub fn batch(&self) -> &FrameInventoryBatch {
        &self.batch
    }

    pub fn into_parts(self) -> (T, FrameInventoryBatch) {
        (self.outcome, self.batch)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FrameInventoryReservationError {
    #[error("frame inventory reservation has no unused frame candidate")]
    FrameCandidatesExhausted,
    #[error("frame inventory reservation has no unused mapping candidate")]
    MappingCandidatesExhausted,
    #[error(transparent)]
    Batch(#[from] FrameInventoryBatchError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FrameInventoryBatchError {
    #[error("frame inventory batches must reserve at least one event")]
    EmptyCapacity,
    #[error("frame inventory batch requested {requested} events, maximum is {maximum}")]
    CapacityTooLarge { requested: usize, maximum: usize },
    #[error("frame inventory batch could not reserve {requested} events")]
    AllocationFailed { requested: usize },
    #[error("frame inventory event belongs to transaction {actual:?}, expected {expected:?}")]
    TransactionMismatch {
        expected: KernelTransactionId,
        actual: KernelTransactionId,
    },
    #[error("frame inventory batch reached its {capacity}-event capacity")]
    BatchFull { capacity: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(raw: u64) -> NonZeroU64 {
        NonZeroU64::new(raw).expect("test ID is nonzero")
    }

    fn capacity(raw: usize) -> FrameEventCapacity {
        FrameEventCapacity::for_event_count(raw).expect("valid test capacity")
    }

    #[test]
    fn batch_rejects_cross_transaction_events() {
        let first = KernelTransactionId::from_kernel_allocation(id(1));
        let second = KernelTransactionId::from_kernel_allocation(id(2));
        let frame = FrameId::from_kernel_allocation(id(3));
        let generation = MappingGeneration::from_backend_counter(id(4));
        let mut batch = FrameInventoryBatch::prepare(first, capacity(1)).expect("batch allocation");

        let error = batch
            .push(FrameInventoryEvent::RetireFrame {
                transaction: second,
                frame,
                generation,
            })
            .expect_err("cross-transaction event must fail closed");

        assert_eq!(
            error,
            FrameInventoryBatchError::TransactionMismatch {
                expected: first,
                actual: second,
            }
        );
        assert!(batch.events().is_empty());
    }

    #[test]
    fn batch_preserves_typed_mapping_identity() {
        let transaction = KernelTransactionId::from_kernel_allocation(id(1));
        let frame = FrameId::from_kernel_allocation(id(2));
        let mapping = MappingId::from_kernel_allocation(id(3));
        let generation = MappingGeneration::from_backend_counter(id(4));
        let event = FrameInventoryEvent::PrepareMapping {
            transaction,
            frame,
            mapping,
            generation,
            gpa: Gpa(0x4000),
            length: FrameLength::from_mapping_extent(id(0x4000)),
            permissions: MemPerms {
                read: true,
                write: false,
                exec: false,
            },
        };
        let mut batch =
            FrameInventoryBatch::prepare(transaction, capacity(1)).expect("batch allocation");
        batch.push(event).expect("matching transaction");

        assert_eq!(batch.events(), &[event]);
        assert_eq!(batch.into_events(), vec![event]);
    }

    #[test]
    fn batch_fails_closed_at_preallocated_capacity() {
        let transaction = KernelTransactionId::from_kernel_allocation(id(1));
        let frame = FrameId::from_kernel_allocation(id(2));
        let generation = MappingGeneration::from_backend_counter(id(3));
        let event = FrameInventoryEvent::RetireFrame {
            transaction,
            frame,
            generation,
        };
        let mut batch =
            FrameInventoryBatch::prepare(transaction, capacity(1)).expect("batch allocation");

        batch.push(event).expect("first event");
        assert_eq!(
            batch.push(event),
            Err(FrameInventoryBatchError::BatchFull { capacity: 1 })
        );
    }

    #[test]
    fn reservation_consumes_candidates_and_carries_backend_outcome() {
        let transaction = KernelTransactionId::from_kernel_allocation(id(1));
        let frames = vec![FrameId::from_kernel_allocation(id(2))];
        let mappings = vec![MappingId::from_kernel_allocation(id(3))];
        let batch = FrameInventoryBatch::prepare(transaction, capacity(1)).expect("batch");
        let provenance = FrameInventoryProvenance::from_kernel_entropy([7; 32]);
        let mut reservation = FrameInventoryReservation::from_kernel_candidates(
            provenance,
            batch,
            frames.clone(),
            mappings.clone(),
        );

        assert_eq!(reservation.claim_frame(), Ok(frames[0]));
        assert_eq!(
            reservation.claim_frame(),
            Err(FrameInventoryReservationError::FrameCandidatesExhausted)
        );
        assert_eq!(reservation.claim_mapping(), Ok(mappings[0]));
        let commit = reservation.commit("mapped");
        assert_eq!(commit.outcome(), &"mapped");
        assert!(commit.provenance_matches(provenance));
        assert!(!commit.provenance_matches(FrameInventoryProvenance::from_kernel_entropy([8; 32])));
        assert_eq!(commit.batch().transaction(), transaction);
        let (outcome, batch) = commit.into_parts();
        assert_eq!(outcome, "mapped");
        assert!(batch.events().is_empty());
    }

    #[test]
    fn capacity_rejects_zero_and_unbounded_requests() {
        assert_eq!(
            FrameEventCapacity::for_event_count(0),
            Err(FrameInventoryBatchError::EmptyCapacity)
        );
        assert_eq!(
            FrameEventCapacity::for_event_count(MAX_FRAME_INVENTORY_EVENTS_PER_BATCH + 1),
            Err(FrameInventoryBatchError::CapacityTooLarge {
                requested: MAX_FRAME_INVENTORY_EVENTS_PER_BATCH + 1,
                maximum: MAX_FRAME_INVENTORY_EVENTS_PER_BATCH,
            })
        );
    }
}
