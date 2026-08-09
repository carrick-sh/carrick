//! Dependency-neutral kernel object identities shared by runtimes and VMMs.
//!
//! These values are allocated by the kernel object model and cross the
//! runtime/backend boundary without exposing pointers or raw host identities.

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
