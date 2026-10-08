//! Exact execution identity presented at a native entry boundary.
use carrick_sched_core::{RecordId, SlotId, ThreadCtx, ZoneTables};

/// A scheduler-owned context image; entry custody never interprets its words.
pub trait EntryContext: Copy + Send + Sync + zerocopy::FromZeros {}
impl<C: Copy + Send + Sync + zerocopy::FromZeros> EntryContext for C {}
use core::ptr::NonNull;
use core::sync::atomic::AtomicU64;

macro_rules! binding_word {
    ($($name:ident),+) => {$(
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[repr(transparent)]
        pub struct $name(u64);
        impl $name {
            pub const fn from_raw(raw: u64) -> Self { Self(raw) }
            pub const fn raw(self) -> u64 { self.0 }
        }
    )+};
}
binding_word!(
    EntryTaskKey,
    EntryGeneration,
    EntryMmKey,
    EntryThreadGeneration
);

/// The execution prefix of the existing shared current-task wire record.
#[repr(C, align(8))]
#[derive(Debug)]
pub struct ExecutionIdentity {
    pub generation: AtomicU64,
    pub task: AtomicU64,
}
impl ExecutionIdentity {
    pub const fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            task: AtomicU64::new(0),
        }
    }
}
impl Default for ExecutionIdentity {
    fn default() -> Self {
        Self::new()
    }
}

/// The MM/thread suffix of that same record. Linux diagnostics occupy the
/// intervening wire bytes; grouping must not move or reinterpret these words.
#[repr(C, align(8))]
#[derive(Debug)]
pub struct ExecutionMm {
    pub key: AtomicU64,
    pub thread_generation: AtomicU64,
}
impl ExecutionMm {
    pub const fn new() -> Self {
        Self {
            key: AtomicU64::new(0),
            thread_generation: AtomicU64::new(0),
        }
    }
}
impl Default for ExecutionMm {
    fn default() -> Self {
        Self::new()
    }
}
const _: () = {
    assert!(core::mem::size_of::<ExecutionIdentity>() == 16);
    assert!(core::mem::offset_of!(ExecutionIdentity, generation) == 0);
    assert!(core::mem::offset_of!(ExecutionIdentity, task) == 8);
    assert!(core::mem::size_of::<ExecutionMm>() == 16);
    assert!(core::mem::offset_of!(ExecutionMm, key) == 0);
    assert!(core::mem::offset_of!(ExecutionMm, thread_generation) == 8);
};

/// Neutral binding between one executor entry and its exact task/MM owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionBinding {
    pub task: EntryTaskKey,
    pub generation: EntryGeneration,
    pub mm: EntryMmKey,
    pub thread_generation: EntryThreadGeneration,
}

impl ExecutionBinding {
    pub const fn issued(self) -> bool {
        self.task.raw() != 0 && self.generation.raw() != 0
    }
}

/// Exact native scheduler region/slot; core authenticates its live record.
#[derive(Clone, Copy)]
pub struct BornInZoneSource<'a, C: EntryContext = ThreadCtx> {
    pub zone: &'a ZoneTables<C>,
    pub slot: SlotId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct EntryRecordGeneration(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct EntryRecordIncarnation(pub u64);

/// Record provenance retained through one entry turn; never dereferenced from
/// the token. Completion compares it with freshly authenticated native custody.
#[derive(Clone, Copy, Debug)]
pub struct EntryRecordBinding<C: EntryContext = ThreadCtx> {
    pub owner: NonNull<ZoneTables<C>>,
    pub slot: SlotId,
    pub record: RecordId,
    pub generation: EntryRecordGeneration,
    pub incarnation: EntryRecordIncarnation,
}

/// Owns ordinary completion for one host-generation-bound entry.
#[derive(Debug)]
pub struct EntryCompletion<'a, C: EntryContext = ThreadCtx> {
    binding: ExecutionBinding,
    scope: Option<EntryExecutionScope<C>>,
    owner_lifetime: core::marker::PhantomData<&'a ZoneTables<C>>,
}
#[derive(Clone, Copy, Debug)]
pub struct EntryExecutionScope<C: EntryContext = ThreadCtx> {
    pub owner: NonNull<ZoneTables<C>>,
    pub slot: SlotId,
    pub record: Option<EntryRecordBinding<C>>,
}
impl<'a, C: EntryContext> EntryCompletion<'a, C> {
    /// # Safety
    /// The caller must authenticate an issued host execution generation and
    /// retain the exact MM/thread binding for this one entry completion. Any
    /// scope must name that same retained owner, slot and live record epoch.
    pub const unsafe fn from_admitted_binding(
        binding: ExecutionBinding,
        scope: Option<EntryExecutionScope<C>>,
        _owner: Option<&'a ZoneTables<C>>,
    ) -> Self {
        Self {
            binding,
            scope,
            owner_lifetime: core::marker::PhantomData,
        }
    }
    pub const fn binding(&self) -> ExecutionBinding {
        self.binding
    }
}

impl<C: EntryContext> EntryCompletion<'_, C> {
    pub const fn scope(&self) -> Option<EntryExecutionScope<C>> {
        self.scope
    }
}

/// Owns one unadopted in-zone entry. This cannot be passed to ordinary host
/// completion; its exact record owner/claim/incarnation must be reauthenticated.
#[derive(Debug)]
pub struct BornEntryCompletion<'a, C: EntryContext = ThreadCtx> {
    binding: ExecutionBinding,
    record: EntryRecordBinding<C>,
    owner_lifetime: core::marker::PhantomData<&'a ZoneTables<C>>,
}
impl<'a, C: EntryContext> BornEntryCompletion<'a, C> {
    /// # Safety
    /// The caller must authenticate an unadopted running record, its exact
    /// owner/slot/claim/incarnation, installed MM and all loaded identity words.
    pub const unsafe fn from_admitted_record(
        binding: ExecutionBinding,
        record: EntryRecordBinding<C>,
        _owner: &'a ZoneTables<C>,
    ) -> Self {
        Self {
            binding,
            record,
            owner_lifetime: core::marker::PhantomData,
        }
    }
    pub const fn binding(&self) -> ExecutionBinding {
        self.binding
    }
    pub const fn record(&self) -> EntryRecordBinding<C> {
        self.record
    }
}

/// Native execution progress, without a syscall result or Linux return policy.
/// Admission/completion authority remains the consuming entry token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Served {
    /// The execution turn returned; switching changed the native context owner.
    Returned { switched: bool },
    /// No execution is currently installed after suspension and native idle.
    Idle,
}

/// Owned evidence of the initiating record's successful park or retirement.
/// This is turn-local evidence, never a second continuation record.
#[derive(Debug)]
pub struct EntryHandoffReceipt<C: EntryContext = ThreadCtx> {
    binding: ExecutionBinding,
    record: EntryRecordBinding<C>,
}
impl<C: EntryContext> EntryHandoffReceipt<C> {
    /// # Safety
    /// The issuer authenticated the exact initiating binding/record before
    /// publishing its successful owned scheduler/wait transition. No context
    /// access may follow publication; this receipt is issued once for that turn.
    pub const unsafe fn from_published_transition(
        binding: ExecutionBinding,
        record: EntryRecordBinding<C>,
    ) -> Self {
        Self { binding, record }
    }
    pub const fn binding(&self) -> ExecutionBinding {
        self.binding
    }
    pub const fn record(&self) -> EntryRecordBinding<C> {
        self.record
    }
}

impl<C: EntryContext> PartialEq for EntryRecordBinding<C> {
    fn eq(&self, other: &Self) -> bool {
        self.owner == other.owner
            && self.slot == other.slot
            && self.record == other.record
            && self.generation == other.generation
            && self.incarnation == other.incarnation
    }
}
impl<C: EntryContext> Eq for EntryRecordBinding<C> {}
impl<C: EntryContext> PartialEq for EntryExecutionScope<C> {
    fn eq(&self, other: &Self) -> bool {
        self.owner == other.owner && self.slot == other.slot && self.record == other.record
    }
}
impl<C: EntryContext> Eq for EntryExecutionScope<C> {}
impl<C: EntryContext> PartialEq for EntryCompletion<'_, C> {
    fn eq(&self, other: &Self) -> bool {
        self.binding == other.binding && self.scope == other.scope
    }
}
impl<C: EntryContext> Eq for EntryCompletion<'_, C> {}
impl<C: EntryContext> PartialEq for BornEntryCompletion<'_, C> {
    fn eq(&self, other: &Self) -> bool {
        self.binding == other.binding && self.record == other.record
    }
}
impl<C: EntryContext> Eq for BornEntryCompletion<'_, C> {}

// Literal wire layout captured from 3fd7862be on a 64-bit host.
// Keep these values fixed when moving the shared kernel implementation.
#[cfg(test)]
mod layout_manifest {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    macro_rules! field {
        ($record:ty, $field:ident, $ty:ty, $offset:literal, $size:literal, $align:literal) => {
            // Type-check the manifest's field type without constructing a record.
            let _ = |record: &$record| {
                let _: &$ty = &record.$field;
            };
            assert_eq!(
                (
                    offset_of!($record, $field),
                    size_of::<$ty>(),
                    align_of::<$ty>()
                ),
                ($offset, $size, $align),
                concat!(stringify!($record), "::", stringify!($field))
            );
        };
    }

    #[test]
    fn execution_identity() {
        assert_eq!(
            (
                size_of::<ExecutionIdentity>(),
                align_of::<ExecutionIdentity>()
            ),
            (16, 8)
        );
        // Exhaustive pattern makes newly added fields require a manifest entry.
        let _ = |ExecutionIdentity {
                     generation: _,
                     task: _,
                 }: ExecutionIdentity| {};
        field!(ExecutionIdentity, generation, AtomicU64, 0, 8, 8);
        field!(ExecutionIdentity, task, AtomicU64, 8, 8, 8);
    }

    #[test]
    fn execution_mm() {
        assert_eq!(
            (size_of::<ExecutionMm>(), align_of::<ExecutionMm>()),
            (16, 8)
        );
        // Exhaustive pattern makes newly added fields require a manifest entry.
        let _ = |ExecutionMm {
                     key: _,
                     thread_generation: _,
                 }: ExecutionMm| {};
        field!(ExecutionMm, key, AtomicU64, 0, 8, 8);
        field!(ExecutionMm, thread_generation, AtomicU64, 8, 8, 8);
    }
}
