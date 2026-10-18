//! Generation-keyed object pins, handle-table operations, and per-task handle
//! hosting built on [`Core`], [`TableStorage`], and [`OpenLifetime`].
//!
//! All state lives in `repr(C)` atomic records placeable in shared memory:
//! - Slot allocation and lookup reuse [`crate::DescriptorSlot`], [`Extent`], and the
//!   64-ary hierarchical free-slot bitmap in [`TableStorage`].
//! - Object reference counting and incarnation authentication use the single
//!   64-bit [`OpenLifetime`] word from `carrick-core-abi` (no second reference
//!   count, no `Arc` strong count as a lifetime, and no finalizer in `Drop`).
//! - Exhausted slot generations (`Generation::MAX`) permanently retire the slot
//!   on every path ([`Authority::close_handle`], [`Authority::close_all_handles`],
//!   [`Authority::destroy_handle_table`], [`Authority::inherit_handle_table`],
//!   [`TaskHandleHost::exit_task`], and [`TaskHandleHost::inherit_task`]): the
//!   object reference is still released, the slot is never reused, and reported
//!   table capacity decreases by one.
//! - [`TaskHandleCore`] / [`TaskHandleHost`] map [`TaskKey`] to [`TableId`] via
//!   fixed-bucket hash chains in shared-memory records with lock-free
//!   sequence-validated lookup (no `O(max_tasks)` scans), unlinking and
//!   reclaiming the binding record on [`TaskHandleHost::exit_task`].

use core::fmt;
use core::num::{NonZeroU32, NonZeroU64};

use carrick_core_abi::{OpenLifetime, OpenReferenceKey, OpenRelease};
use carrick_sched_core::process::TaskKey;

use crate::free_list::{pop, push};
use crate::{
    AtomicU32, AtomicU64, Authority, BackingToken, Core, Error, Extent, FREE_INDEX, LockWait,
    Locked, MAX_DESCRIPTORS, Ordering, SeqWord, SlotBacking, TABLE_BOUND_TASK, TABLE_FREE,
    TABLE_LIVE_HANDLES, TableId, TableRecord, TableStorage,
};

#[cfg(all(test, not(feature = "loom")))]
std::thread_local! {
    pub(crate) static AFTER_HANDLE_SLOT_STORE: core::cell::RefCell<Option<std::boxed::Box<dyn FnOnce()>>> = const { core::cell::RefCell::new(None) };
}
#[cfg(test)]
std::thread_local! {
    /// Task-bucket chain steps visited during [`TaskHandleHost::table_id`].
    pub(crate) static TASK_LOOKUP_STEPS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}
const HANDLE_TABLE_STATES: &[u32] = &[TABLE_LIVE_HANDLES, TABLE_LIVE_HANDLES | TABLE_BOUND_TASK];

/// Maximum reference/pin count representable in the low 31 bits of [`OpenLifetime`].
pub const MAX_OBJECT_PINS: u32 = (1u32 << 31) - 1;

/// Maximum object index encodable in a 64-bit handle slot word (`2^29 - 2`).
pub const MAX_HANDLE_OBJECTS: usize = (1usize << 29) - 2;

pub(crate) const HANDLE_SLOT_CLOEXEC: u64 = 1 << 31;
pub(crate) const HANDLE_SLOT_INHERITABLE: u64 = 1 << 30;
pub(crate) const HANDLE_SLOT_RETIRED: u64 = 1 << 29;
pub(crate) const HANDLE_SLOT_OBJECT_MASK: u64 = (1 << 29) - 1;
pub(crate) const HANDLE_SLOT_GENERATION_SHIFT: u64 = 32;

#[cfg(all(test, feature = "loom"))]
#[repr(transparent)]
#[derive(Debug, Default)]
pub(crate) struct LoomAtomicU64(AtomicU64);

#[cfg(all(test, feature = "loom"))]
impl carrick_core_abi::OpenLifetimeAtomic for LoomAtomicU64 {
    #[inline]
    fn load(&self, order: core::sync::atomic::Ordering) -> u64 {
        self.0.load(order)
    }

    #[inline]
    fn compare_exchange(
        &self,
        current: u64,
        new: u64,
        success: core::sync::atomic::Ordering,
        failure: core::sync::atomic::Ordering,
    ) -> Result<u64, u64> {
        self.0.compare_exchange(current, new, success, failure)
    }
}

#[cfg(not(all(test, feature = "loom")))]
type ObjectLifetime = OpenLifetime;

#[cfg(all(test, feature = "loom"))]
type ObjectLifetime = OpenLifetime<LoomAtomicU64>;

/// Zero-based handle-table slot index.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SlotIndex(pub u32);

impl SlotIndex {
    /// Wrap a raw zero-based slot index.
    #[inline]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Underlying zero-based slot index.
    #[inline]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Zero-based slot index as `usize`.
    #[inline]
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for SlotIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "slot#{}", self.0)
    }
}

/// Non-zero per-slot generation counter for ABA detection on recycled slots.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Generation(NonZeroU32);

impl Generation {
    /// Initial generation assigned when a slot is allocated for the first time.
    pub const INITIAL: Self = match NonZeroU32::new(1) {
        Some(v) => Self(v),
        None => unreachable!(),
    };

    /// Maximum representable 32-bit generation (`u32::MAX`).
    ///
    /// Closing, exiting, or declining to inherit a slot at `MAX` retires the
    /// slot permanently rather than wrapping or saturating.
    pub const MAX: Self = match NonZeroU32::new(u32::MAX) {
        Some(v) => Self(v),
        None => unreachable!(),
    };

    /// Construct a generation from a raw non-zero `u32`.
    #[inline]
    pub const fn new(raw: u32) -> Option<Self> {
        match NonZeroU32::new(raw) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// Underlying non-zero `u32` generation value.
    #[inline]
    pub const fn raw(self) -> u32 {
        self.0.get()
    }

    /// Underlying non-zero `u64` generation value.
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0.get() as u64
    }

    /// Advance to the next generation on slot close, returning `None` when the
    /// generation space (`u32::MAX`) is exhausted so the slot is retired.
    #[inline]
    pub const fn next(self) -> Option<Self> {
        match self.0.get().checked_add(1) {
            Some(next) => Self::new(next),
            None => None,
        }
    }
}

impl Default for Generation {
    fn default() -> Self {
        Self::INITIAL
    }
}

impl fmt::Display for Generation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "gen#{}", self.0.get())
    }
}

/// Generation-keyed object pin `{ slot, generation }`.
///
/// Naming an `ObjectPin` does not retain the object; resolving a pin through
/// [`Authority::get_handle_pin`] returns an owned [`ObjectGuard`] that retains
/// the underlying [`OpenLifetime`] word.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObjectPin {
    pub slot: SlotIndex,
    pub generation: Generation,
}

impl ObjectPin {
    /// Construct a generation-keyed object pin for `(slot, generation)`.
    #[inline]
    pub const fn new(slot: SlotIndex, generation: Generation) -> Self {
        Self { slot, generation }
    }
}

impl fmt::Display for ObjectPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.slot, self.generation)
    }
}

/// Table-scoped handle returned by [`Authority::insert_handle`] and
/// [`Authority::duplicate_handle`].
///
/// Because every `Handle` carries its owning [`TableId`] (authority, table
/// index, and table generation), a handle from a parent table cannot be passed
/// directly to a child table after [`Authority::inherit_handle_table`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Handle {
    table: TableId,
    pin: ObjectPin,
}

impl Handle {
    /// Construct a handle scoped to `table` and `pin`.
    #[inline]
    pub const fn new(table: TableId, pin: ObjectPin) -> Self {
        Self { table, pin }
    }

    /// The [`TableId`] this handle belongs to.
    #[inline]
    pub const fn table(self) -> TableId {
        self.table
    }

    /// Generation-keyed [`ObjectPin`] of this handle.
    #[inline]
    pub const fn pin(self) -> ObjectPin {
        self.pin
    }

    /// Table slot index of this handle.
    #[inline]
    pub const fn slot(self) -> SlotIndex {
        self.pin.slot
    }

    /// Slot generation of this handle.
    #[inline]
    pub const fn generation(self) -> Generation {
        self.pin.generation
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "handle({})", self.pin)
    }
}

/// Typed user-visible handle number in a personality's ABI domain.
///
/// Personalities translate between `HandleNumber` and [`SlotIndex`] using a
/// pure [`HandleNumberCodec`] with no host descriptor or pointer in the key.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialOrd, PartialEq)]
pub struct HandleNumber(pub u64);

impl HandleNumber {
    /// Wrap a raw user-visible handle number.
    #[inline]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Underlying raw integer value.
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl fmt::Display for HandleNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// Pure arithmetic mapping between [`SlotIndex`] and [`HandleNumber`].
///
/// Encodes `SlotIndex(i)` as `(base + i * stride) | required_tag`, validating
/// that `required_tag` fits inside `tag_mask` and does not overlap scaled slot
/// bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandleNumberCodec {
    pub base: u64,
    pub stride: NonZeroU64,
    pub tag_mask: u64,
    pub required_tag: u64,
}

impl HandleNumberCodec {
    /// Identity 1:1 mapping (`handle_number == slot_index`).
    pub const DIRECT: Self = Self {
        base: 0,
        stride: match NonZeroU64::new(1) {
            Some(v) => v,
            None => unreachable!(),
        },
        tag_mask: 0,
        required_tag: 0,
    };

    /// Construct a custom pure handle-number codec.
    pub const fn new(
        base: u64,
        stride: NonZeroU64,
        tag_mask: u64,
        required_tag: u64,
    ) -> Result<Self, HandleError> {
        if (required_tag & !tag_mask) != 0 || (base & tag_mask) != 0 {
            return Err(HandleError::InvalidHandle);
        }
        Ok(Self {
            base,
            stride,
            tag_mask,
            required_tag,
        })
    }

    /// Encode a table [`SlotIndex`] into a user-visible [`HandleNumber`].
    pub const fn encode(self, slot: SlotIndex) -> Result<HandleNumber, HandleError> {
        if (self.required_tag & !self.tag_mask) != 0 || (self.base & self.tag_mask) != 0 {
            return Err(HandleError::InvalidHandle);
        }
        let Some(scaled) = (slot.0 as u64).checked_mul(self.stride.get()) else {
            return Err(HandleError::InvalidHandle);
        };
        let Some(untagged) = self.base.checked_add(scaled) else {
            return Err(HandleError::InvalidHandle);
        };
        if (untagged & self.tag_mask) != 0 {
            return Err(HandleError::InvalidHandle);
        }
        Ok(HandleNumber(untagged | self.required_tag))
    }

    /// Decode a user-visible [`HandleNumber`] into a table [`SlotIndex`].
    pub const fn decode(self, number: HandleNumber) -> Result<SlotIndex, HandleError> {
        if (self.required_tag & !self.tag_mask) != 0 || (self.base & self.tag_mask) != 0 {
            return Err(HandleError::InvalidHandle);
        }
        if (number.0 & self.tag_mask) != self.required_tag {
            return Err(HandleError::InvalidHandle);
        }
        let untagged = number.0 & !self.tag_mask;
        let Some(offset) = untagged.checked_sub(self.base) else {
            return Err(HandleError::InvalidHandle);
        };
        if offset % self.stride.get() != 0 {
            return Err(HandleError::InvalidHandle);
        }
        let raw_slot = offset / self.stride.get();
        if raw_slot > u32::MAX as u64 {
            return Err(HandleError::InvalidHandle);
        }
        Ok(SlotIndex(raw_slot as u32))
    }
}

impl Default for HandleNumberCodec {
    fn default() -> Self {
        Self::DIRECT
    }
}

/// Pure helper mapping a [`SlotIndex`] to a [`HandleNumber`].
#[inline]
pub const fn encode_handle_number(
    codec: HandleNumberCodec,
    slot: SlotIndex,
) -> Result<HandleNumber, HandleError> {
    codec.encode(slot)
}

/// Pure helper mapping a [`HandleNumber`] to a [`SlotIndex`].
#[inline]
pub const fn decode_handle_number(
    codec: HandleNumberCodec,
    number: HandleNumber,
) -> Result<SlotIndex, HandleError> {
    codec.decode(number)
}

/// Per-handle metadata flags stored in the descriptor slot word.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct HandleFlags {
    /// Whether this handle is eligible for inheritance in [`Authority::inherit_handle_table`].
    pub inheritable: bool,
    /// Whether this handle is closed on image replacement (`exec_handle_table`).
    pub close_on_exec: bool,
}

impl HandleFlags {
    /// Default handle flags: neither inheritable nor close-on-exec.
    pub const DEFAULT: Self = Self {
        inheritable: false,
        close_on_exec: false,
    };

    /// Inheritable across process creation.
    pub const INHERITABLE: Self = Self {
        inheritable: true,
        close_on_exec: false,
    };

    /// Closed on image replacement (`exec`).
    pub const CLOSE_ON_EXEC: Self = Self {
        inheritable: false,
        close_on_exec: true,
    };

    /// Construct explicit handle flags.
    #[inline]
    pub const fn new(inheritable: bool, close_on_exec: bool) -> Self {
        Self {
            inheritable,
            close_on_exec,
        }
    }

    /// Whether the handle is marked inheritable.
    #[inline]
    pub const fn is_inheritable(self) -> bool {
        self.inheritable
    }

    /// Whether the handle is marked close-on-exec.
    #[inline]
    pub const fn is_close_on_exec(self) -> bool {
        self.close_on_exec
    }
}

/// Neutral errors returned by handle-table and object-pin operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleError {
    /// Handle, pin, guard, or table is closed, forged, from another
    /// table/authority, or from an older generation/incarnation.
    Stale,
    /// The handle table reached its bounded capacity (including permanently
    /// retired slots) or all table records in the core are in use.
    TableFull,
    /// User handle number failed codec validation or limit is out of bounds.
    InvalidHandle,
    /// The 31-bit [`OpenLifetime`] reference count (`MAX_OBJECT_PINS`) is saturated.
    PinOverflow,
    /// Every published [`ObjectRecord`] in the authority is in use; the venue
    /// must publish more via [`Authority::publish_objects`].
    NeedsObjects,
    /// The table's [`Extent`] must be grown to at least `slots` entries.
    NeedsBacking { slots: usize },
    /// The [`LockWait`] policy gave up before any effect.
    Contended,
    /// The venue's [`SlotBacking`] could not resolve a published extent or object.
    BadBacking,
}

impl fmt::Display for HandleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stale => f.write_str("stale handle, object pin, or table"),
            Self::TableFull => f.write_str("handle table capacity exhausted"),
            Self::InvalidHandle => f.write_str("invalid handle number or configuration"),
            Self::PinOverflow => f.write_str("object pin count saturated"),
            Self::NeedsObjects => f.write_str("all published object records are in use"),
            Self::NeedsBacking { slots } => {
                write!(f, "handle table backing needs at least {slots} slots")
            }
            Self::Contended => f.write_str("handle table lock contended"),
            Self::BadBacking => f.write_str("venue failed to resolve handle backing"),
        }
    }
}

impl core::error::Error for HandleError {}

/// One personality object record in shared/venue memory.
///
/// Reference counting and incarnation authentication use the single
/// [`OpenLifetime`] word: table slots and in-flight [`ObjectGuard`]s share its
/// 31-bit count, and whoever drops the count to zero receives
/// [`OpenRelease::Terminal`] and performs the single final release.
#[repr(C, align(64))]
#[derive(Debug, Default)]
pub struct ObjectRecord {
    pub(crate) lifetime: ObjectLifetime,
    pub(crate) incarnation: AtomicU64,
    pub(crate) backing: AtomicU64,
    pub(crate) next_free: AtomicU64,
    _reserved: [u64; 4],
}

impl ObjectRecord {
    /// Construct a zeroed unpublished object record.
    #[cfg(not(all(test, feature = "loom")))]
    pub const fn new() -> Self {
        Self {
            lifetime: OpenLifetime::new(),
            incarnation: AtomicU64::new(0),
            backing: AtomicU64::new(0),
            next_free: AtomicU64::new(0),
            _reserved: [0; 4],
        }
    }

    #[cfg(all(test, not(feature = "loom")))]
    pub(crate) fn lifetime_word_for_test(&self) -> &AtomicU64 {
        // SAFETY: OpenLifetime is #[repr(transparent)] over AtomicU64.
        unsafe { &*(&raw const self.lifetime).cast::<AtomicU64>() }
    }
}

/// Owned retention guard for a resolved handle or [`ObjectPin`].
///
/// While an `ObjectGuard` exists, concurrent `close_handle`,
/// `close_all_handles`, or `destroy_handle_table` calls cannot finalize the
/// underlying [`ObjectRecord`]. Not `Clone` or `Copy`: release it
/// exactly once by passing it by value to [`Authority::release_handle_pin`].
#[must_use = "an ObjectGuard retains its object until release_handle_pin"]
#[derive(Debug, Eq, PartialEq)]
pub struct ObjectGuard {
    authority: u64,
    object_index: u32,
    incarnation: u64,
    pin: ObjectPin,
    backing: BackingToken,
    flags: HandleFlags,
}

/// Move-only `repr(C)` representation of an [`ObjectGuard`] for storing a
/// retained pin by value in a continuation record.
///
/// Produced by [`ObjectGuard::into_raw`] and consumed by
/// [`ObjectGuard::from_raw`] without changing the [`OpenLifetime`] count.
/// Because `RawObjectGuard` is neither `Copy` nor `Clone` and its fields are
/// private, a raw guard cannot be duplicated in safe code; continuation slots
/// extract ownership via [`RawObjectGuard::take`], which leaves a vacant zeroed
/// value that [`ObjectGuard::from_raw`] rejects with [`HandleError::Stale`].
#[repr(C)]
#[must_use = "a RawObjectGuard retains its object until restored with ObjectGuard::from_raw and released"]
#[derive(Debug, Default, Eq, PartialEq)]
pub struct RawObjectGuard {
    pub(crate) authority: u64,
    pub(crate) incarnation: u64,
    pub(crate) backing: u64,
    pub(crate) object_index: u32,
    pub(crate) slot: u32,
    pub(crate) slot_generation: u32,
    pub(crate) flags_bits: u32,
}

impl RawObjectGuard {
    /// Move this raw guard out of `*self`, leaving a zeroed vacant record that
    /// [`ObjectGuard::from_raw`] rejects with [`HandleError::Stale`].
    ///
    /// Requires exclusive (`&mut`) ownership of the continuation record slot so
    /// the stored guard is extracted at most once.
    #[inline]
    pub const fn take(&mut self) -> Self {
        let taken = Self {
            authority: self.authority,
            incarnation: self.incarnation,
            backing: self.backing,
            object_index: self.object_index,
            slot: self.slot,
            slot_generation: self.slot_generation,
            flags_bits: self.flags_bits,
        };
        *self = Self {
            authority: 0,
            incarnation: 0,
            backing: 0,
            object_index: 0,
            slot: 0,
            slot_generation: 0,
            flags_bits: 0,
        };
        taken
    }
}

impl ObjectGuard {
    /// Generation-keyed [`ObjectPin`] that was resolved to produce this guard.
    #[inline]
    pub const fn pin(&self) -> ObjectPin {
        self.pin
    }

    /// Opaque venue [`BackingToken`] of the retained object.
    #[inline]
    pub const fn backing(&self) -> BackingToken {
        self.backing
    }

    /// Snapshot of the slot's [`HandleFlags`] when the guard was acquired.
    #[inline]
    pub const fn flags(&self) -> HandleFlags {
        self.flags
    }

    /// Underlying [`OpenReferenceKey`] (`{ handle: object_index, incarnation }`)
    /// in the shared [`OpenLifetime`] domain.
    #[inline]
    pub const fn open_reference_key(&self) -> OpenReferenceKey {
        OpenReferenceKey {
            handle: self.object_index,
            incarnation: self.incarnation,
        }
    }

    /// Move ownership into a move-only [`RawObjectGuard`] for a continuation record.
    #[inline]
    pub const fn into_raw(self) -> RawObjectGuard {
        let flags_bits = (if self.flags.inheritable { 1 } else { 0 })
            | (if self.flags.close_on_exec { 2 } else { 0 });
        RawObjectGuard {
            authority: self.authority,
            incarnation: self.incarnation,
            backing: self.backing.0,
            object_index: self.object_index,
            slot: self.pin.slot.0,
            slot_generation: self.pin.generation.raw(),
            flags_bits,
        }
    }

    /// Reclaim ownership moved out by [`ObjectGuard::into_raw`].
    ///
    /// Rejects zeroed/vacant raw guards (`slot_generation == 0`,
    /// `authority == 0`, or `incarnation == 0`) with [`HandleError::Stale`].
    #[inline]
    pub const fn from_raw(raw: RawObjectGuard) -> Result<Self, HandleError> {
        let Some(generation) = Generation::new(raw.slot_generation) else {
            return Err(HandleError::Stale);
        };
        if raw.authority == 0 || raw.incarnation == 0 {
            return Err(HandleError::Stale);
        }
        Ok(Self {
            authority: raw.authority,
            object_index: raw.object_index,
            incarnation: raw.incarnation,
            pin: ObjectPin {
                slot: SlotIndex(raw.slot),
                generation,
            },
            backing: BackingToken(raw.backing),
            flags: HandleFlags {
                inheritable: (raw.flags_bits & 1) != 0,
                close_on_exec: (raw.flags_bits & 2) != 0,
            },
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HandleSlotEntry {
    object_index: u32,
    generation: Generation,
    flags: HandleFlags,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotState {
    Vacant { next_generation: Generation },
    Occupied(HandleSlotEntry),
    Retired,
}

const fn encode_vacant_slot(next_generation: Generation) -> u64 {
    (next_generation.raw() as u64) << 32
}

const fn encode_retired_slot() -> u64 {
    ((Generation::MAX.raw() as u64) << 32) | HANDLE_SLOT_RETIRED
}

const fn encode_occupied_slot(entry: HandleSlotEntry) -> u64 {
    ((entry.generation.raw() as u64) << 32)
        | if entry.flags.close_on_exec {
            HANDLE_SLOT_CLOEXEC
        } else {
            0
        }
        | if entry.flags.inheritable {
            HANDLE_SLOT_INHERITABLE
        } else {
            0
        }
        | ((entry.object_index as u64) + 1)
}

const fn decode_handle_slot(word: u64) -> SlotState {
    if (word & HANDLE_SLOT_RETIRED) != 0 {
        return SlotState::Retired;
    }
    let raw_gen = (word >> 32) as u32;
    let generation = match Generation::new(raw_gen) {
        Some(g) => g,
        None => Generation::INITIAL,
    };
    let obj = word & HANDLE_SLOT_OBJECT_MASK;
    if obj == 0 {
        SlotState::Vacant {
            next_generation: generation,
        }
    } else {
        SlotState::Occupied(HandleSlotEntry {
            object_index: (obj - 1) as u32,
            generation,
            flags: HandleFlags {
                inheritable: (word & HANDLE_SLOT_INHERITABLE) != 0,
                close_on_exec: (word & HANDLE_SLOT_CLOEXEC) != 0,
            },
        })
    }
}

struct HandleTable<'a> {
    storage: TableStorage<'a>,
    limit: usize,
}

impl HandleTable<'_> {
    fn allocate(&self) -> Result<usize, HandleError> {
        if self.limit == 0 {
            return Err(HandleError::TableFull);
        }
        let mut reads = 0;
        if let Some(slot) = self
            .storage
            .next_bit(0, 0, &mut reads)
            .filter(|slot| *slot < self.limit)
        {
            return Ok(slot);
        }
        if self.storage.capacity() < self.limit {
            Err(HandleError::NeedsBacking {
                slots: self.storage.capacity() + 1,
            })
        } else {
            Err(HandleError::TableFull)
        }
    }

    fn slot_state(&self, slot: SlotIndex) -> Option<SlotState> {
        let index = slot.as_usize();
        if index >= self.limit {
            return None;
        }
        self.storage
            .entries
            .get(index)
            .map(|cell| decode_handle_slot(cell.0.load(Ordering::Acquire)))
    }

    fn occupied_entry(&self, slot: SlotIndex) -> Result<HandleSlotEntry, HandleError> {
        match self.slot_state(slot) {
            Some(SlotState::Occupied(entry)) => Ok(entry),
            _ => Err(HandleError::Stale),
        }
    }
}

fn map_core_error(err: Error) -> HandleError {
    match err {
        Error::StaleTable | Error::BadFd | Error::StalePin | Error::PinRaced(_) => {
            HandleError::Stale
        }
        Error::InvalidArgument => HandleError::InvalidHandle,
        Error::TooManyFiles | Error::NoMemory => HandleError::TableFull,
        Error::NeedsOfds => HandleError::NeedsObjects,
        Error::NeedsBacking { descriptors } => HandleError::NeedsBacking { slots: descriptors },
        Error::Contended => HandleError::Contended,
        Error::BadBacking => HandleError::BadBacking,
    }
}

fn retire_or_free_slot(
    record: &TableRecord,
    storage: &TableStorage<'_>,
    slot: usize,
    generation: Generation,
) {
    match generation.next() {
        Some(next_generation) => {
            storage.entries[slot]
                .0
                .store(encode_vacant_slot(next_generation), Ordering::Release);
            storage.mark_free(slot, true);
        }
        None => {
            storage.entries[slot]
                .0
                .store(encode_retired_slot(), Ordering::Release);
            storage.mark_free(slot, false);
            record.retired.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl<'a, B: SlotBacking, W: LockWait, const T: usize> Authority<'a, B, W, T> {
    fn handle_identity(&self) -> Result<u64, HandleError> {
        self.identity().map_err(map_core_error)
    }

    fn object(&self, index: u32) -> Result<&'a ObjectRecord, HandleError> {
        if u64::from(index) >= self.core.object_count.load(Ordering::Acquire) {
            return Err(HandleError::BadBacking);
        }
        self.backing
            .object(index as usize)
            .ok_or(HandleError::BadBacking)
    }

    /// Publish `count` more [`ObjectRecord`]s in venue memory (`0..object_count`).
    ///
    /// Mirrors [`Authority::publish_ofds`]: the count is published with Release
    /// before the records join `free_objects`.
    pub fn publish_objects(&self, count: usize) -> Result<(), HandleError> {
        self.handle_identity()?;
        let first = self.core.object_count.load(Ordering::Acquire);
        let end = first
            .checked_add(count as u64)
            .filter(|end| *end <= MAX_HANDLE_OBJECTS as u64 && *end < FREE_INDEX)
            .ok_or(HandleError::InvalidHandle)?;
        if count == 0 {
            return Ok(());
        }
        for index in [first, end - 1] {
            let record = self
                .backing
                .object(index as usize)
                .ok_or(HandleError::BadBacking)?;
            let inc = record.incarnation.load(Ordering::Relaxed);
            if inc != 0 && !record.lifetime.is_terminal(inc) {
                return Err(HandleError::BadBacking);
            }
        }
        self.core
            .object_count
            .compare_exchange(first, end, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| HandleError::Contended)?;
        for index in (first..end).rev() {
            let record = self.object(index as u32)?;
            push(&self.core.free_objects, index as usize, &record.next_free);
        }
        Ok(())
    }

    fn alloc_object(&self, backing: BackingToken) -> Result<(u32, u64), HandleError> {
        let raw_index = pop(&self.core.free_objects, |i| {
            self.object(u32::try_from(i).ok()?)
                .ok()
                .map(|o| o.next_free.load(Ordering::Relaxed))
        })
        .ok_or(HandleError::NeedsObjects)?;
        let Ok(index) = u32::try_from(raw_index) else {
            return Err(HandleError::BadBacking);
        };
        let Ok(record) = self.object(index) else {
            return Err(HandleError::BadBacking);
        };
        let prev = record.incarnation.load(Ordering::Relaxed);
        let Some(incarnation) = prev
            .checked_add(1)
            .filter(|inc| *inc <= u64::from(u32::MAX))
        else {
            return Err(HandleError::NeedsObjects);
        };
        if !record.lifetime.initialize(incarnation, false) {
            push(&self.core.free_objects, raw_index, &record.next_free);
            return Err(HandleError::BadBacking);
        }
        record.backing.store(backing.0, Ordering::Relaxed);
        record.incarnation.store(incarnation, Ordering::Release);
        Ok((index, incarnation))
    }

    fn free_object(&self, index: u32, incarnation: u64) -> Result<(), HandleError> {
        let record = self.object(index)?;
        if incarnation < u64::from(u32::MAX) {
            push(&self.core.free_objects, index as usize, &record.next_free);
        }
        Ok(())
    }

    fn retain_object(&self, index: u32, incarnation: u64) -> Result<(), HandleError> {
        let record = self.object(index)?;
        if record.lifetime.retain(incarnation) {
            return Ok(());
        }
        if record.lifetime.ring_references(incarnation) == Some(MAX_OBJECT_PINS) {
            Err(HandleError::PinOverflow)
        } else {
            Err(HandleError::Stale)
        }
    }

    fn release_object(
        &self,
        index: u32,
        incarnation: u64,
    ) -> Result<Option<BackingToken>, HandleError> {
        let record = self.object(index)?;
        // Read `backing` before releasing our hold so a concurrent reuse after
        // Terminal cannot overwrite the token we return.
        let backing = BackingToken(record.backing.load(Ordering::Acquire));
        match record.lifetime.release(incarnation) {
            OpenRelease::Live => Ok(None),
            OpenRelease::Terminal => {
                self.free_object(index, incarnation)?;
                Ok(Some(backing))
            }
            OpenRelease::Stale => Err(HandleError::Stale),
        }
    }

    fn publish_handle_table(
        &self,
        index: usize,
        limit: usize,
        retired: u64,
        storage: Extent,
    ) -> TableId {
        let record = &self.core.tables[index];
        let generation = record.generation.load(Ordering::Relaxed) + 1;
        record.begin_write();
        record.limit.store(limit as u64, Ordering::Relaxed);
        record.retired.store(retired, Ordering::Relaxed);
        record.extent_token.store(storage.token, Ordering::Relaxed);
        record
            .extent_capacity
            .store(storage.capacity, Ordering::Relaxed);
        record.generation.store(generation, Ordering::Relaxed);
        record.state.store(TABLE_LIVE_HANDLES, Ordering::Release);
        record.end_write();
        TableId {
            authority: self.core.identity.load(Ordering::Relaxed),
            index,
            generation,
        }
    }

    fn lock_handle_table(&self, id: TableId) -> Result<(Locked<'a>, HandleTable<'a>), HandleError> {
        self.lock_handle_table_in_states(id, HANDLE_TABLE_STATES)
    }

    fn lock_handle_table_in_states(
        &self,
        id: TableId,
        states: &[u32],
    ) -> Result<(Locked<'a>, HandleTable<'a>), HandleError> {
        let (guard, table) = self.lock_in_states(id, states).map_err(map_core_error)?;
        Ok((
            guard,
            HandleTable {
                storage: table.storage,
                limit: table.limit,
            },
        ))
    }

    pub(crate) fn lock_unbound_handle_table(&self, id: TableId) -> Result<Locked<'a>, HandleError> {
        let (guard, _) = self
            .lock_in_states(
                id,
                &[
                    crate::TABLE_LIVE,
                    TABLE_LIVE_HANDLES,
                    TABLE_LIVE_HANDLES | TABLE_BOUND_TASK,
                ],
            )
            .map_err(map_core_error)?;
        if guard.record.state.load(Ordering::Acquire) != TABLE_LIVE_HANDLES {
            return Err(HandleError::InvalidHandle);
        }
        Ok(guard)
    }

    fn lock_bound_handle_table(
        &self,
        id: TableId,
    ) -> Result<(Locked<'a>, HandleTable<'a>), HandleError> {
        self.lock_handle_table_in_states(id, &[TABLE_LIVE_HANDLES | TABLE_BOUND_TASK])
    }

    fn read_handle_table(
        &self,
        id: TableId,
    ) -> Result<(&'a TableRecord, u64, TableStorage<'a>, usize), HandleError> {
        self.read_table_in_states(id, HANDLE_TABLE_STATES)
            .map_err(map_core_error)
    }

    /// Create an empty personality handle table with bounded `limit` over `storage`.
    ///
    /// Consumes `storage` (swapping in [`Extent::EMPTY`]) only on success.
    pub fn create_handle_table(
        &self,
        limit: usize,
        storage: &mut Extent,
    ) -> Result<TableId, HandleError> {
        self.handle_identity()?;
        if limit == 0 || limit > MAX_DESCRIPTORS {
            return Err(HandleError::InvalidHandle);
        }
        let view = self.storage(*storage).map_err(map_core_error)?;
        let index = self.pop_table().map_err(map_core_error)?;
        let guard = match self.acquire(&self.core.tables[index]) {
            Ok(guard) => guard,
            Err(err) => {
                self.push_table(index);
                return Err(map_core_error(err));
            }
        };
        view.clear();
        let id = self.publish_handle_table(index, limit, 0, core::mem::take(storage));
        drop(guard);
        Ok(id)
    }

    /// Replace a handle table's backing extent with a larger extent without
    /// changing table identity, slot generations, or object reference counts.
    pub fn grow_handle_table(
        &self,
        table: TableId,
        storage: &mut Extent,
    ) -> Result<(), HandleError> {
        self.grow_table_in_states(table, storage, HANDLE_TABLE_STATES)
            .map_err(map_core_error)
    }

    /// Reported usable slot capacity of `table` (`limit - retired_slots`).
    ///
    /// Permanently retiring a slot on generation exhaustion (`Generation::MAX`)
    /// lowers this reported capacity by one.
    pub fn handle_table_capacity(&self, table: TableId) -> Result<usize, HandleError> {
        let (guard, _) = self.lock_handle_table(table)?;
        let limit = guard.record.limit.load(Ordering::Relaxed) as usize;
        let retired = guard.record.retired.load(Ordering::Relaxed) as usize;
        Ok(limit.saturating_sub(retired))
    }

    /// Number of permanently retired (generation-exhausted) slots in `table`.
    pub fn handle_table_retired_count(&self, table: TableId) -> Result<usize, HandleError> {
        let (guard, _) = self.lock_handle_table(table)?;
        Ok(guard.record.retired.load(Ordering::Relaxed) as usize)
    }

    /// Number of currently occupied handle slots in `table`.
    pub fn handle_table_live_count(&self, table: TableId) -> Result<usize, HandleError> {
        let (_guard, t) = self.lock_handle_table(table)?;
        let end = t.limit.min(t.storage.capacity());
        let mut live = 0usize;
        for slot in 0..end {
            if matches!(
                decode_handle_slot(t.storage.entries[slot].0.load(Ordering::Relaxed)),
                SlotState::Occupied(_)
            ) {
                live += 1;
            }
        }
        Ok(live)
    }

    /// Seed the next vacant generation of `slot` in `table` (when `slot` is
    /// currently vacant). Used to deterministically test boundary generations
    /// such as [`Generation::MAX`].
    #[cfg(any(test, feature = "test-support"))]
    pub fn seed_handle_slot_generation(
        &self,
        table: TableId,
        slot: SlotIndex,
        generation: Generation,
    ) -> Result<(), HandleError> {
        let (_guard, t) = self.lock_handle_table(table)?;
        let idx = slot.as_usize();
        if idx >= t.limit {
            return Err(HandleError::InvalidHandle);
        }
        if idx >= t.storage.capacity() {
            return Err(HandleError::NeedsBacking { slots: idx + 1 });
        }
        match decode_handle_slot(t.storage.entries[idx].0.load(Ordering::Relaxed)) {
            SlotState::Vacant { .. } => {
                t.storage.entries[idx]
                    .0
                    .store(encode_vacant_slot(generation), Ordering::Release);
                t.storage.mark_free(idx, true);
                Ok(())
            }
            SlotState::Occupied(_) | SlotState::Retired => Err(HandleError::InvalidHandle),
        }
    }

    /// Insert a new object with `backing` and `flags` at the lowest free slot
    /// in `table`.
    ///
    /// Allocates one [`ObjectRecord`] initialized with one hold in its
    /// [`OpenLifetime`] word and returns the table-scoped [`Handle`].
    pub fn insert_handle(
        &self,
        table: TableId,
        backing: BackingToken,
        flags: HandleFlags,
    ) -> Result<Handle, HandleError> {
        let (_guard, t) = self.lock_handle_table(table)?;
        let slot = t.allocate()?;
        let next_generation =
            match decode_handle_slot(t.storage.entries[slot].0.load(Ordering::Relaxed)) {
                SlotState::Vacant { next_generation } => next_generation,
                SlotState::Occupied(_) | SlotState::Retired => return Err(HandleError::BadBacking),
            };
        let (object_index, _incarnation) = self.alloc_object(backing)?;
        let entry = HandleSlotEntry {
            object_index,
            generation: next_generation,
            flags,
        };
        t.storage.entries[slot]
            .0
            .store(encode_occupied_slot(entry), Ordering::Release);
        #[cfg(all(test, not(feature = "loom")))]
        AFTER_HANDLE_SLOT_STORE.with(|hook| {
            if let Some(probe) = hook.borrow_mut().take() {
                probe();
            }
        });
        t.storage.mark_free(slot, false);
        Ok(Handle::new(
            table,
            ObjectPin::new(SlotIndex(slot as u32), next_generation),
        ))
    }

    /// Look up the current table-scoped [`Handle`] occupying `slot` in `table`.
    ///
    /// Personalities use [`decode_handle_number`] followed by `handle_at` (or
    /// [`Authority::get_handle_by_number`]) to map a user-visible
    /// [`HandleNumber`] into a table-scoped handle.
    pub fn handle_at(&self, table: TableId, slot: SlotIndex) -> Result<Handle, HandleError> {
        let (_guard, t) = self.lock_handle_table(table)?;
        let entry = t.occupied_entry(slot)?;
        Ok(Handle::new(table, ObjectPin::new(slot, entry.generation)))
    }

    /// Resolve a table-scoped [`Handle`] and retain its object in an
    /// [`ObjectGuard`].
    ///
    /// Takes no table lock: validates `handle.table == table`, reads the slot
    /// and object incarnation with exact-slot validation (the sequence protects
    /// only table-wide changes), and retains a hold in [`OpenLifetime`] before returning the guard.
    pub fn get_handle(&self, table: TableId, handle: Handle) -> Result<ObjectGuard, HandleError> {
        if handle.table != table {
            return Err(HandleError::Stale);
        }
        self.get_handle_pin(table, handle.pin)
    }

    fn resolve_slot_guard(
        &self,
        table: TableId,
        slot: SlotIndex,
        expected_generation: Option<Generation>,
    ) -> Result<(Handle, ObjectGuard), HandleError> {
        let authority = self.handle_identity()?;
        let mut attempt: u32 = 0;
        loop {
            let (record, seq, storage, limit) = self.read_handle_table(table)?;
            let idx = slot.as_usize();
            if idx >= limit || idx >= storage.capacity() {
                if record.unchanged_since(seq) {
                    return Err(HandleError::Stale);
                }
            } else {
                let word = storage.entries[idx].0.load(Ordering::Acquire);
                let settled = || {
                    storage.entries[idx].0.load(Ordering::Acquire) == word
                        && record.unchanged_since(seq)
                };
                match decode_handle_slot(word) {
                    SlotState::Occupied(entry)
                        if expected_generation.is_none_or(|g| entry.generation == g) =>
                    {
                        match self.object(entry.object_index) {
                            Ok(obj) => {
                                let incarnation = obj.incarnation.load(Ordering::Acquire);
                                if settled() {
                                    match self.retain_object(entry.object_index, incarnation) {
                                        Ok(()) => {
                                            let pin = ObjectPin::new(slot, entry.generation);
                                            let backing =
                                                BackingToken(obj.backing.load(Ordering::Acquire));
                                            return Ok((
                                                Handle::new(table, pin),
                                                ObjectGuard {
                                                    authority,
                                                    object_index: entry.object_index,
                                                    incarnation,
                                                    pin,
                                                    backing,
                                                    flags: entry.flags,
                                                },
                                            ));
                                        }
                                        Err(err) => {
                                            if matches!(err, HandleError::PinOverflow) {
                                                return Err(HandleError::PinOverflow);
                                            }
                                            if settled() {
                                                return Err(HandleError::Stale);
                                            }
                                        }
                                    }
                                }
                            }
                            Err(err) if settled() => return Err(err),
                            Err(_) => {}
                        }
                    }
                    _ => {
                        if settled() {
                            return Err(HandleError::Stale);
                        }
                    }
                }
            }
            attempt = attempt.saturating_add(1);
            if !self.wait.wait(attempt) {
                return Err(HandleError::Contended);
            }
        }
    }

    /// Resolve a generation-keyed [`ObjectPin`] in `table` and retain its
    /// object in an [`ObjectGuard`].
    pub fn get_handle_pin(
        &self,
        table: TableId,
        pin: ObjectPin,
    ) -> Result<ObjectGuard, HandleError> {
        self.resolve_slot_guard(table, pin.slot, Some(pin.generation))
            .map(|(_, guard)| guard)
    }

    /// Decode a user-visible [`HandleNumber`] with `codec`, resolve the slot in
    /// `table`, and return both the table-scoped [`Handle`] and its retained
    /// [`ObjectGuard`].
    pub fn get_handle_by_number(
        &self,
        table: TableId,
        codec: HandleNumberCodec,
        number: HandleNumber,
    ) -> Result<(Handle, ObjectGuard), HandleError> {
        let slot = codec.decode(number)?;
        self.resolve_slot_guard(table, slot, None)
    }

    /// Acquire an additional owned [`ObjectGuard`] from an existing guard by
    /// incrementing the [`OpenLifetime`] reference count.
    pub fn retain_handle_pin(&self, guard: &ObjectGuard) -> Result<ObjectGuard, HandleError> {
        if guard.authority != self.handle_identity()? {
            return Err(HandleError::Stale);
        }
        let obj = self.object(guard.object_index)?;
        if obj.incarnation.load(Ordering::Acquire) != guard.incarnation {
            return Err(HandleError::Stale);
        }
        self.retain_object(guard.object_index, guard.incarnation)?;
        Ok(ObjectGuard {
            authority: guard.authority,
            object_index: guard.object_index,
            incarnation: guard.incarnation,
            pin: guard.pin,
            backing: guard.backing,
            flags: guard.flags,
        })
    }

    /// Release an owned [`ObjectGuard`] (consuming it by value).
    ///
    /// Returns `Ok(Some(backing))` when this guard dropped the final reference
    /// in [`OpenLifetime`] (after all table slots naming the object were closed).
    #[must_use = "the last-reference backing token must be finalized by the caller"]
    pub fn release_handle_pin(
        &self,
        guard: ObjectGuard,
    ) -> Result<Option<BackingToken>, HandleError> {
        if guard.authority != self.handle_identity()? {
            return Err(HandleError::Stale);
        }
        let obj = self.object(guard.object_index)?;
        if obj.incarnation.load(Ordering::Acquire) != guard.incarnation {
            return Err(HandleError::Stale);
        }
        self.release_object(guard.object_index, guard.incarnation)
    }

    /// Active reference/pin count in [`OpenLifetime`] for the object held by `guard`.
    pub fn handle_pin_count(&self, guard: &ObjectGuard) -> Result<u32, HandleError> {
        if guard.authority != self.handle_identity()? {
            return Err(HandleError::Stale);
        }
        let obj = self.object(guard.object_index)?;
        if obj.incarnation.load(Ordering::Acquire) != guard.incarnation {
            return Err(HandleError::Stale);
        }
        obj.lifetime
            .ring_references(guard.incarnation)
            .filter(|count| *count > 0)
            .ok_or(HandleError::Stale)
    }

    /// Read the [`HandleFlags`] of `handle` in `table`.
    pub fn handle_flags(&self, table: TableId, handle: Handle) -> Result<HandleFlags, HandleError> {
        if handle.table != table {
            return Err(HandleError::Stale);
        }
        let (_guard, t) = self.lock_handle_table(table)?;
        let entry = t.occupied_entry(handle.pin.slot)?;
        if entry.generation != handle.pin.generation {
            return Err(HandleError::Stale);
        }
        Ok(entry.flags)
    }

    /// Update the [`HandleFlags`] of `handle` in `table`.
    pub fn set_handle_flags(
        &self,
        table: TableId,
        handle: Handle,
        flags: HandleFlags,
    ) -> Result<(), HandleError> {
        if handle.table != table {
            return Err(HandleError::Stale);
        }
        let (_guard, t) = self.lock_handle_table(table)?;
        let mut entry = t.occupied_entry(handle.pin.slot)?;
        if entry.generation != handle.pin.generation {
            return Err(HandleError::Stale);
        }
        entry.flags = flags;
        t.storage.entries[handle.pin.slot.as_usize()]
            .0
            .store(encode_occupied_slot(entry), Ordering::Release);
        Ok(())
    }

    /// Duplicate `handle` into a new slot in `table`, preserving its [`HandleFlags`]
    /// and incrementing the shared [`OpenLifetime`] reference count.
    pub fn duplicate_handle(&self, table: TableId, handle: Handle) -> Result<Handle, HandleError> {
        self.duplicate_handle_inner(table, handle, None)
    }

    /// Duplicate `handle` into a new slot in `table` with explicit `flags`.
    pub fn duplicate_handle_with_flags(
        &self,
        table: TableId,
        handle: Handle,
        flags: HandleFlags,
    ) -> Result<Handle, HandleError> {
        self.duplicate_handle_inner(table, handle, Some(flags))
    }

    fn duplicate_handle_inner(
        &self,
        table: TableId,
        handle: Handle,
        override_flags: Option<HandleFlags>,
    ) -> Result<Handle, HandleError> {
        if handle.table != table {
            return Err(HandleError::Stale);
        }
        let (_guard, t) = self.lock_handle_table(table)?;
        let source = t.occupied_entry(handle.pin.slot)?;
        if source.generation != handle.pin.generation {
            return Err(HandleError::Stale);
        }
        let new_slot = t.allocate()?;
        let next_generation =
            match decode_handle_slot(t.storage.entries[new_slot].0.load(Ordering::Relaxed)) {
                SlotState::Vacant { next_generation } => next_generation,
                SlotState::Occupied(_) | SlotState::Retired => return Err(HandleError::BadBacking),
            };
        let obj = self.object(source.object_index)?;
        let incarnation = obj.incarnation.load(Ordering::Acquire);
        self.retain_object(source.object_index, incarnation)?;
        let new_entry = HandleSlotEntry {
            object_index: source.object_index,
            generation: next_generation,
            flags: override_flags.unwrap_or(source.flags),
        };
        t.storage.entries[new_slot]
            .0
            .store(encode_occupied_slot(new_entry), Ordering::Release);
        t.storage.mark_free(new_slot, false);
        Ok(Handle::new(
            table,
            ObjectPin::new(SlotIndex(new_slot as u32), next_generation),
        ))
    }

    /// Close `handle` in `table`, advancing its slot generation (or permanently
    /// retiring the slot if at [`Generation::MAX`]) and releasing one hold on
    /// the object's [`OpenLifetime`].
    ///
    /// Returns `Ok(Some(backing))` iff this close dropped the final reference
    /// (no duplicate slot, inherited child slot, or in-flight [`ObjectGuard`]
    /// remains). Never returns `Err` after closing a slot.
    #[must_use = "the last-reference backing token must be finalized by the caller"]
    pub fn close_handle(
        &self,
        table: TableId,
        handle: Handle,
    ) -> Result<Option<BackingToken>, HandleError> {
        if handle.table != table {
            return Err(HandleError::Stale);
        }
        let (object_index, incarnation) = {
            let (guard, t) = self.lock_handle_table(table)?;
            let entry = t.occupied_entry(handle.pin.slot)?;
            if entry.generation != handle.pin.generation {
                return Err(HandleError::Stale);
            }
            let obj = self.object(entry.object_index)?;
            let incarnation = obj.incarnation.load(Ordering::Acquire);
            if obj.lifetime.ring_references(incarnation).unwrap_or(0) == 0 {
                return Err(HandleError::Stale);
            }
            let slot_idx = handle.pin.slot.as_usize();
            retire_or_free_slot(guard.record, &t.storage, slot_idx, entry.generation);
            drop(guard);
            (entry.object_index, incarnation)
        };
        self.release_object(object_index, incarnation)
    }

    fn validate_closing_slots(
        &self,
        storage: &TableStorage<'_>,
        end: usize,
        only_cloexec: bool,
    ) -> Result<(), HandleError> {
        for slot in 0..end {
            let SlotState::Occupied(entry) =
                decode_handle_slot(storage.entries[slot].0.load(Ordering::Relaxed))
            else {
                continue;
            };
            if only_cloexec && !entry.flags.close_on_exec {
                continue;
            }
            let obj = self.object(entry.object_index)?;
            let incarnation = obj.incarnation.load(Ordering::Acquire);
            if obj.lifetime.ring_references(incarnation).unwrap_or(0) == 0 {
                return Err(HandleError::Stale);
            }
        }
        Ok(())
    }

    /// Retire/free closing slots under `record.begin_write()..end_write()` and
    /// link any [`OpenRelease::Terminal`] object indices through `next_free` so
    /// the caller can drop the table lock before running finalizers.
    fn collect_retired_slots(
        &self,
        record: &TableRecord,
        storage: &TableStorage<'_>,
        end: usize,
        only_cloexec: bool,
    ) -> u64 {
        let mut head: u64 = 0;
        let mut tail: u64 = 0;
        record.begin_write();
        for slot in 0..end {
            let SlotState::Occupied(entry) =
                decode_handle_slot(storage.entries[slot].0.load(Ordering::Relaxed))
            else {
                continue;
            };
            if only_cloexec && !entry.flags.close_on_exec {
                continue;
            }
            let Ok(obj) = self.object(entry.object_index) else {
                continue;
            };
            let incarnation = obj.incarnation.load(Ordering::Acquire);
            retire_or_free_slot(record, storage, slot, entry.generation);
            self.release_into_retired_list(
                obj,
                entry.object_index,
                incarnation,
                &mut head,
                &mut tail,
            );
        }
        record.end_write();
        head
    }

    fn release_into_retired_list(
        &self,
        obj: &ObjectRecord,
        index: u32,
        incarnation: u64,
        head: &mut u64,
        tail: &mut u64,
    ) {
        if matches!(obj.lifetime.release(incarnation), OpenRelease::Terminal) {
            obj.next_free.store(0, Ordering::Relaxed);
            let encoded = u64::from(index) + 1;
            if *tail == 0 {
                *head = encoded;
            } else if let Ok(prev) = self.object((*tail - 1) as u32) {
                prev.next_free.store(encoded, Ordering::Relaxed);
            }
            *tail = encoded;
        }
    }

    fn finalize_retired_objects(&self, mut head: u64, mut release: impl FnMut(BackingToken)) {
        while head != 0 {
            let index = (head - 1) as u32;
            let Ok(obj) = self.object(index) else {
                break;
            };
            let next = obj.next_free.load(Ordering::Relaxed);
            let backing = BackingToken(obj.backing.load(Ordering::Acquire));
            let incarnation = obj.incarnation.load(Ordering::Acquire);
            let _ = self.free_object(index, incarnation);
            release(backing);
            head = next;
        }
    }

    /// Close every handle in `table` marked `close_on_exec`, delivering each
    /// finalized [`BackingToken`] to `release` exactly once after `end_write`
    /// and outside the table lock.
    pub fn exec_handle_table(
        &self,
        table: TableId,
        release: impl FnMut(BackingToken),
    ) -> Result<(), HandleError> {
        let head = {
            let (guard, t) = self.lock_handle_table(table)?;
            let end = t.limit.min(t.storage.capacity());
            self.validate_closing_slots(&t.storage, end, true)?;
            let head = self.collect_retired_slots(guard.record, &t.storage, end, true);
            drop(guard);
            head
        };
        self.finalize_retired_objects(head, release);
        Ok(())
    }

    /// Close all live handles in `table` in place (retiring any slots at
    /// [`Generation::MAX`]), delivering each finalized [`BackingToken`] to
    /// `release` exactly once after `end_write` and outside the table lock while
    /// keeping `table` live for inspection or reuse.
    pub fn close_all_handles(
        &self,
        table: TableId,
        release: impl FnMut(BackingToken),
    ) -> Result<(), HandleError> {
        let head = {
            let (guard, t) = self.lock_handle_table(table)?;
            let end = t.limit.min(t.storage.capacity());
            self.validate_closing_slots(&t.storage, end, false)?;
            let head = self.collect_retired_slots(guard.record, &t.storage, end, false);
            drop(guard);
            head
        };
        self.finalize_retired_objects(head, release);
        Ok(())
    }

    fn destroy_locked_handle_table(
        &self,
        index: usize,
        guard: Locked<'a>,
        t: HandleTable<'a>,
        end: usize,
        release: impl FnMut(BackingToken),
    ) -> Extent {
        let extent = Self::record_extent(guard.record);
        let head = self.collect_retired_slots(guard.record, &t.storage, end, false);
        guard.record.begin_write();
        guard.record.extent_token.store(0, Ordering::Relaxed);
        guard.record.extent_capacity.store(0, Ordering::Relaxed);
        guard.record.state.store(TABLE_FREE, Ordering::Release);
        guard.record.end_write();
        drop(guard);
        self.push_table(index);
        self.finalize_retired_objects(head, release);
        extent
    }

    /// Destroy an unbound `table`, releasing every remaining handle's pin
    /// exactly once after `end_write` and outside the table lock, and returning
    /// the table's [`Extent`] to the venue.
    ///
    /// Refuses with [`HandleError::InvalidHandle`] if `table` is currently
    /// bound to a [`TaskKey`] in a [`TaskHandleCore`] (use
    /// [`TaskHandleHost::exit_task`] so the task binding cannot be orphaned).
    pub fn destroy_handle_table(
        &self,
        table: TableId,
        release: impl FnMut(BackingToken),
    ) -> Result<Extent, HandleError> {
        let (guard, t) = self.lock_handle_table(table)?;
        if (guard.record.state.load(Ordering::Relaxed) & TABLE_BOUND_TASK) != 0 {
            return Err(HandleError::InvalidHandle);
        }
        let end = t.limit.min(t.storage.capacity());
        self.validate_closing_slots(&t.storage, end, false)?;
        Ok(self.destroy_locked_handle_table(table.index, guard, t, end, release))
    }

    /// Inherit one coherent parent snapshot, retaining all eligible candidates
    /// under one parent lock before running `filter` outside that lock.
    /// Parent close, move, flag changes or destruction during filtering cannot
    /// change the snapshot. Rejected candidates advance their slot generation
    /// (or retire at MAX); terminal releases run outside both table locks.
    pub fn inherit_handle_table(
        &self,
        parent: TableId,
        mut filter: impl FnMut(ObjectPin, BackingToken, HandleFlags) -> bool,
        storage: &mut Extent,
        mut release: impl FnMut(BackingToken),
    ) -> Result<TableId, HandleError> {
        let (parent_guard, p) = self.lock_handle_table(parent)?;
        let parent_limit = p.limit;
        let scan_end = parent_limit.min(p.storage.capacity());
        if (storage.capacity as usize) < p.storage.capacity() {
            return Err(HandleError::NeedsBacking {
                slots: p.storage.capacity(),
            });
        }
        let child = self.storage(*storage).map_err(map_core_error)?;
        let child_index = self.pop_table().map_err(map_core_error)?;
        let child_guard = match self.acquire(&self.core.tables[child_index]) {
            Ok(guard) => guard,
            Err(err) => {
                self.push_table(child_index);
                return Err(map_core_error(err));
            }
        };
        child.clear();
        let mut child_retired = 0u64;
        let snapshot = (|| {
            for slot in 0..scan_end {
                let word = p.storage.entries[slot].0.load(Ordering::Relaxed);
                let copied = match decode_handle_slot(word) {
                    SlotState::Occupied(entry) => {
                        let retained = if entry.flags.is_inheritable() {
                            let obj = self.object(entry.object_index)?;
                            let inc = obj.incarnation.load(Ordering::Acquire);
                            match self.retain_object(entry.object_index, inc) {
                                Ok(()) => true,
                                Err(HandleError::PinOverflow) => {
                                    return Err(HandleError::PinOverflow);
                                }
                                Err(_) => false,
                            }
                        } else {
                            false
                        };
                        if retained {
                            word
                        } else {
                            match entry.generation.next() {
                                Some(next) => encode_vacant_slot(next),
                                None => {
                                    child_retired += 1;
                                    encode_retired_slot()
                                }
                            }
                        }
                    }
                    SlotState::Retired => {
                        child_retired += 1;
                        word
                    }
                    SlotState::Vacant { .. } => word,
                };
                child.entries[slot].0.store(copied, Ordering::Relaxed);
            }
            Ok(())
        })();
        drop(parent_guard);
        if let Err(err) = snapshot {
            drop(child_guard);
            self.push_table(child_index);
            self.rollback_inherited_slots(&child, scan_end, &mut release);
            return Err(err);
        }
        let (mut head, mut tail) = (0, 0);
        for slot in 0..scan_end {
            let SlotState::Occupied(entry) =
                decode_handle_slot(child.entries[slot].0.load(Ordering::Relaxed))
            else {
                continue;
            };
            // The snapshot's retained reference authenticates and keeps this
            // exact object incarnation alive even if the parent is destroyed.
            let obj = match self.object(entry.object_index) {
                Ok(obj) => obj,
                Err(err) => {
                    drop(child_guard);
                    self.push_table(child_index);
                    self.rollback_inherited_slots(&child, scan_end, &mut release);
                    self.finalize_retired_objects(head, release);
                    return Err(err);
                }
            };
            let backing = BackingToken(obj.backing.load(Ordering::Acquire));
            let pin = ObjectPin::new(SlotIndex(slot as u32), entry.generation);
            if !filter(pin, backing, entry.flags) {
                let word = match entry.generation.next() {
                    Some(next) => encode_vacant_slot(next),
                    None => {
                        child_retired += 1;
                        encode_retired_slot()
                    }
                };
                child.entries[slot].0.store(word, Ordering::Relaxed);
                let inc = obj.incarnation.load(Ordering::Acquire);
                self.release_into_retired_list(obj, entry.object_index, inc, &mut head, &mut tail);
            }
        }
        child.rebuild();
        let child_id = self.publish_handle_table(
            child_index,
            parent_limit,
            child_retired,
            core::mem::take(storage),
        );
        drop(child_guard);
        self.finalize_retired_objects(head, release);
        Ok(child_id)
    }

    fn rollback_inherited_slots(
        &self,
        child: &TableStorage<'_>,
        upto: usize,
        mut release: impl FnMut(BackingToken),
    ) {
        for slot in 0..upto {
            if let SlotState::Occupied(entry) =
                decode_handle_slot(child.entries[slot].0.load(Ordering::Relaxed))
                && let Ok(obj) = self.object(entry.object_index)
            {
                let inc = obj.incarnation.load(Ordering::Acquire);
                if let Ok(Some(backing)) = self.release_object(entry.object_index, inc) {
                    release(backing);
                }
            }
            child.entries[slot].0.store(0, Ordering::Relaxed);
        }
    }
}

/// One hash bucket in [`TaskHandleCore`]: per-bucket spinlock (`lock`),
/// 1-based head index into `bindings` (`head`, `0` = empty), and a shared
/// `SeqWord` sequence counter (`seq`, odd while a writer mutates the bucket
/// chain or a binding record) so [`TaskHandleHost::table_id`] walks the bucket
/// chain lock-free with the same release/acquire fence discipline as
/// [`TableRecord`].
///
/// Cache-line aligned and padded to 64 bytes so concurrent bucket locks and
/// sequence words across adjacent buckets do not share a cache line.
#[repr(C, align(64))]
#[derive(Debug, Default)]
pub struct TaskBucket {
    pub(crate) lock: AtomicU32,
    pub(crate) head: AtomicU32,
    pub(crate) seq: SeqWord,
    _reserved: [u64; 6],
}

impl TaskBucket {
    #[inline]
    pub(crate) fn begin_write(&self) {
        self.seq.begin_write();
    }

    #[inline]
    pub(crate) fn end_write(&self) {
        self.seq.end_write();
    }

    #[inline]
    pub(crate) fn unchanged_since(&self, seq: u64) -> bool {
        self.seq.unchanged_since(seq)
    }
}

/// One task-to-table binding record in [`TaskHandleCore`].
#[repr(C, align(64))]
#[derive(Debug, Default)]
pub struct TaskBindingRecord {
    pub(crate) task_id: AtomicU32,
    pub(crate) hash_next: AtomicU32,
    pub(crate) task_serial: AtomicU64,
    pub(crate) table_authority: AtomicU64,
    pub(crate) table_index: AtomicU64,
    pub(crate) table_generation: AtomicU64,
    pub(crate) next_free: AtomicU64,
    _reserved: [u64; 2],
}

/// Shared-memory `repr(C)` core hosting per-task handle tables keyed by
/// [`TaskKey`].
///
/// Combines [`Core<T>`] with an `O(1)` hash-bucketed task index and a lock-free
/// free list of `T` [`TaskBindingRecord`]s so [`TaskHandleHost::exit_task`]
/// removes exited tasks and reclaims slots across unbounded task churn.
#[repr(C, align(64))]
pub struct TaskHandleCore<const T: usize> {
    pub(crate) core: Core<T>,
    pub(crate) free_bindings: AtomicU64,
    _reserved: [u64; 7],
    pub(crate) buckets: [TaskBucket; T],
    pub(crate) bindings: [TaskBindingRecord; T],
}

impl<const T: usize> TaskHandleCore<T> {
    /// Create and initialize a [`TaskHandleCore`] for a single address space.
    pub fn new() -> Result<Self, HandleError> {
        if T == 0 {
            return Err(HandleError::InvalidHandle);
        }
        let task_core = Self {
            core: Core::new().map_err(map_core_error)?,
            free_bindings: AtomicU64::new(0),
            _reserved: [0; 7],
            buckets: core::array::from_fn(|_| TaskBucket::default()),
            bindings: core::array::from_fn(|_| TaskBindingRecord::default()),
        };
        for i in (0..T).rev() {
            push(
                &task_core.free_bindings,
                i,
                &task_core.bindings[i].next_free,
            );
        }
        Ok(task_core)
    }

    /// Initialize a zeroed [`TaskHandleCore`] in place with `identity`.
    pub fn initialize(&self, identity: u64) -> Result<(), HandleError> {
        if T == 0 || (T as u64) >= FREE_INDEX || identity == 0 {
            return Err(HandleError::InvalidHandle);
        }
        if self.core.identity.load(Ordering::Acquire) != 0
            || self.free_bindings.load(Ordering::Acquire) != 0
        {
            return Err(HandleError::InvalidHandle);
        }
        self.core.initialize(identity).map_err(map_core_error)?;
        for i in (0..T).rev() {
            push(&self.free_bindings, i, &self.bindings[i].next_free);
        }
        Ok(())
    }

    /// Underlying [`Core`] reference.
    pub const fn core(&self) -> &Core<T> {
        &self.core
    }

    /// Bind this [`TaskHandleCore`] to a venue's [`SlotBacking`] and [`LockWait`] policy.
    pub fn bind<'a, B: SlotBacking, W: LockWait>(
        &'a self,
        backing: &'a B,
        wait: W,
    ) -> TaskHandleHost<'a, B, W, T> {
        TaskHandleHost {
            task_core: self,
            backing,
            wait,
        }
    }
}

struct RefWait<'a, W>(&'a W);

impl<W> Clone for RefWait<'_, W> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<W> Copy for RefWait<'_, W> {}

impl<W: LockWait> LockWait for RefWait<'_, W> {
    #[inline]
    fn wait(&self, attempt: u32) -> bool {
        self.0.wait(attempt)
    }
}

struct LockedBucket<'a> {
    bucket: &'a TaskBucket,
}

impl Drop for LockedBucket<'_> {
    fn drop(&mut self) {
        self.bucket.lock.store(0, Ordering::Release);
    }
}

/// Bound venue view over a [`TaskHandleCore`]: `O(1)` task-keyed handle-table
/// operations, inheritance attachment, and concurrent-safe task exit.
pub struct TaskHandleHost<'a, B: SlotBacking, W: LockWait, const T: usize> {
    task_core: &'a TaskHandleCore<T>,
    backing: &'a B,
    wait: W,
}

impl<'a, B: SlotBacking, W: LockWait, const T: usize> TaskHandleHost<'a, B, W, T> {
    /// Underlying [`Authority`] view over [`Core<T>`].
    #[inline]
    pub fn authority(&self) -> Authority<'a, B, impl LockWait + Copy + '_, T> {
        self.task_core.core.bind(self.backing, RefWait(&self.wait))
    }

    /// Publish `count` more [`ObjectRecord`]s in venue memory.
    #[inline]
    pub fn publish_objects(&self, count: usize) -> Result<(), HandleError> {
        self.authority().publish_objects(count)
    }

    fn bucket_index(task: TaskKey) -> usize {
        // Bijective 64-bit mix over the task's slot ID so all serial
        // incarnations of the same TaskId map to one bucket while distinct
        // TaskIds spread evenly across `0..T`.
        let mut z = (task.id.raw() as u32 as u64).wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        (z as usize) % T
    }

    fn lock_bucket(&self, bucket_idx: usize) -> Result<LockedBucket<'a>, HandleError> {
        let bucket = self
            .task_core
            .buckets
            .get(bucket_idx)
            .ok_or(HandleError::Stale)?;
        let mut attempt: u32 = 0;
        loop {
            if bucket
                .lock
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(LockedBucket { bucket });
            }
            attempt = attempt.saturating_add(1);
            if !self.wait.wait(attempt) {
                return Err(HandleError::Contended);
            }
        }
    }

    fn pop_binding(&self) -> Result<usize, HandleError> {
        let bindings = &self.task_core.bindings;
        pop(&self.task_core.free_bindings, |i| {
            bindings.get(i).map(|b| b.next_free.load(Ordering::Relaxed))
        })
        .ok_or(HandleError::TableFull)
    }

    fn push_binding(&self, index: usize) {
        let binding = &self.task_core.bindings[index];
        push(&self.task_core.free_bindings, index, &binding.next_free);
    }

    /// Attach an existing, unbound live handle `table` to `task` in the `O(1)`
    /// hash index.
    ///
    /// Refuses if `task` is already bound (`Err(HandleError::InvalidHandle)`),
    /// if `table` is closed or from another authority (`Err(HandleError::Stale)`),
    /// or if `table` is a descriptor table or already bound to a task
    /// (`Err(HandleError::InvalidHandle)`).
    pub fn attach_task_table(&self, task: TaskKey, table: TableId) -> Result<(), HandleError> {
        let auth = self.authority();
        auth.handle_identity()?;
        if task.id.raw() <= 0 || task.serial.raw() == 0 {
            return Err(HandleError::InvalidHandle);
        }
        let bucket_idx = Self::bucket_index(task);
        let guard = self.lock_bucket(bucket_idx)?;
        let raw_id = task.id.raw() as u32;
        let raw_serial = task.serial.raw();
        let mut cur = guard.bucket.head.load(Ordering::Relaxed);
        while cur != 0 {
            let idx = (cur - 1) as usize;
            let existing = self
                .task_core
                .bindings
                .get(idx)
                .ok_or(HandleError::BadBacking)?;
            if existing.task_id.load(Ordering::Relaxed) == raw_id {
                return Err(HandleError::InvalidHandle);
            }
            cur = existing.hash_next.load(Ordering::Relaxed);
        }
        // Lock order: TaskBucket -> TableRecord.
        let table_guard = auth.lock_unbound_handle_table(table)?;
        let binding_idx = self.pop_binding()?;

        let record = self
            .task_core
            .bindings
            .get(binding_idx)
            .ok_or(HandleError::BadBacking)?;
        table_guard.record.begin_write();
        table_guard
            .record
            .state
            .store(TABLE_LIVE_HANDLES | TABLE_BOUND_TASK, Ordering::Release);
        table_guard.record.end_write();

        let head = guard.bucket.head.load(Ordering::Relaxed);
        guard.bucket.begin_write();
        record.task_id.store(raw_id, Ordering::Relaxed);
        record.task_serial.store(raw_serial, Ordering::Relaxed);
        record
            .table_authority
            .store(table.authority, Ordering::Relaxed);
        record
            .table_index
            .store(table.index as u64, Ordering::Relaxed);
        record
            .table_generation
            .store(table.generation, Ordering::Relaxed);
        record.hash_next.store(head, Ordering::Relaxed);
        guard
            .bucket
            .head
            .store((binding_idx as u32) + 1, Ordering::Relaxed);
        guard.bucket.end_write();
        drop(table_guard);
        drop(guard);
        Ok(())
    }

    /// Create a new handle table with `limit` over `storage` and attach it to `task`.
    pub fn create_task_table(
        &self,
        task: TaskKey,
        limit: usize,
        storage: &mut Extent,
    ) -> Result<TableId, HandleError> {
        let auth = self.authority();
        let table = auth.create_handle_table(limit, storage)?;
        if let Err(err) = self.attach_task_table(task, table) {
            *storage = auth.destroy_handle_table(table, |_| {})?;
            return Err(err);
        }
        Ok(table)
    }

    /// Look up `task`'s [`TableId`] in `O(1)` via its hash bucket without
    /// taking the bucket spinlock (sequence-validated against [`TaskBucket`]).
    ///
    /// Rejects a stale [`TaskKey`] (including a recycled `TaskId` with an older
    /// `TaskSerial`) with [`HandleError::Stale`].
    pub fn table_id(&self, task: TaskKey) -> Result<TableId, HandleError> {
        self.authority().handle_identity()?;
        if task.id.raw() <= 0 || task.serial.raw() == 0 {
            return Err(HandleError::Stale);
        }
        let bucket_idx = Self::bucket_index(task);
        let bucket = self
            .task_core
            .buckets
            .get(bucket_idx)
            .ok_or(HandleError::Stale)?;
        let raw_id = task.id.raw() as u32;
        let raw_serial = task.serial.raw();
        let mut attempt: u32 = 0;
        loop {
            let seq = bucket.seq.load(Ordering::Acquire);
            if seq & 1 == 0 {
                let mut cur = bucket.head.load(Ordering::Relaxed);
                let mut steps = 0usize;
                let mut found: Option<TableId> = None;
                let mut consistent = true;
                while cur != 0 {
                    if steps >= T {
                        consistent = false;
                        break;
                    }
                    steps += 1;
                    #[cfg(test)]
                    TASK_LOOKUP_STEPS.with(|n| n.set(n.get() + 1));
                    let idx = (cur - 1) as usize;
                    let Some(record) = self.task_core.bindings.get(idx) else {
                        consistent = false;
                        break;
                    };
                    if record.task_id.load(Ordering::Relaxed) == raw_id
                        && record.task_serial.load(Ordering::Relaxed) == raw_serial
                    {
                        found = Some(TableId {
                            authority: record.table_authority.load(Ordering::Relaxed),
                            index: record.table_index.load(Ordering::Relaxed) as usize,
                            generation: record.table_generation.load(Ordering::Relaxed),
                        });
                        break;
                    }
                    cur = record.hash_next.load(Ordering::Relaxed);
                }
                if consistent && bucket.unchanged_since(seq) {
                    return found.ok_or(HandleError::Stale);
                }
            }
            attempt = attempt.saturating_add(1);
            if !self.wait.wait(attempt) {
                return Err(HandleError::Contended);
            }
        }
    }

    /// Reported usable slot capacity of `task`'s handle table (`limit - retired`).
    pub fn capacity(&self, task: TaskKey) -> Result<usize, HandleError> {
        let table = self.table_id(task)?;
        self.authority().handle_table_capacity(table)
    }

    /// Number of currently occupied handle slots in `task`'s handle table.
    pub fn live_count(&self, task: TaskKey) -> Result<usize, HandleError> {
        let table = self.table_id(task)?;
        self.authority().handle_table_live_count(table)
    }

    /// Seed the next vacant generation of `slot` in `task`'s table.
    #[cfg(any(test, feature = "test-support"))]
    pub fn seed_slot_generation(
        &self,
        task: TaskKey,
        slot: SlotIndex,
        generation: Generation,
    ) -> Result<(), HandleError> {
        let table = self.table_id(task)?;
        self.authority()
            .seed_handle_slot_generation(table, slot, generation)
    }

    /// Insert a new handle into `task`'s table.
    pub fn insert(
        &self,
        task: TaskKey,
        backing: BackingToken,
        flags: HandleFlags,
    ) -> Result<Handle, HandleError> {
        let table = self.table_id(task)?;
        self.authority().insert_handle(table, backing, flags)
    }

    /// Look up the table-scoped [`Handle`] currently at `slot` in `task`'s table.
    pub fn handle_at(&self, task: TaskKey, slot: SlotIndex) -> Result<Handle, HandleError> {
        let table = self.table_id(task)?;
        self.authority().handle_at(table, slot)
    }

    /// Resolve `handle` in `task`'s table and return a retained [`ObjectGuard`].
    pub fn get(&self, task: TaskKey, handle: Handle) -> Result<ObjectGuard, HandleError> {
        let table = self.table_id(task)?;
        self.authority().get_handle(table, handle)
    }

    /// Resolve `pin` in `task`'s table and return a retained [`ObjectGuard`].
    pub fn get_pin(&self, task: TaskKey, pin: ObjectPin) -> Result<ObjectGuard, HandleError> {
        let table = self.table_id(task)?;
        self.authority().get_handle_pin(table, pin)
    }

    /// Decode `number` with `codec`, resolve it in `task`'s table, and return
    /// both the table-scoped [`Handle`] and its retained [`ObjectGuard`].
    pub fn get_by_number(
        &self,
        task: TaskKey,
        codec: HandleNumberCodec,
        number: HandleNumber,
    ) -> Result<(Handle, ObjectGuard), HandleError> {
        let table = self.table_id(task)?;
        self.authority().get_handle_by_number(table, codec, number)
    }

    /// Acquire an additional owned [`ObjectGuard`] from an existing guard.
    pub fn retain_pin(&self, guard: &ObjectGuard) -> Result<ObjectGuard, HandleError> {
        self.authority().retain_handle_pin(guard)
    }

    /// Release an owned [`ObjectGuard`] (consuming it by value).
    #[must_use = "the last-reference backing token must be finalized by the caller"]
    pub fn release_pin(&self, guard: ObjectGuard) -> Result<Option<BackingToken>, HandleError> {
        self.authority().release_handle_pin(guard)
    }

    /// Active reference/pin count in [`OpenLifetime`] for `guard`.
    pub fn pin_count(&self, guard: &ObjectGuard) -> Result<u32, HandleError> {
        self.authority().handle_pin_count(guard)
    }

    /// Duplicate `handle` in `task`'s table.
    pub fn duplicate(&self, task: TaskKey, handle: Handle) -> Result<Handle, HandleError> {
        let table = self.table_id(task)?;
        self.authority().duplicate_handle(table, handle)
    }

    /// Duplicate `handle` in `task`'s table with explicit `flags`.
    pub fn duplicate_with_flags(
        &self,
        task: TaskKey,
        handle: Handle,
        flags: HandleFlags,
    ) -> Result<Handle, HandleError> {
        let table = self.table_id(task)?;
        self.authority()
            .duplicate_handle_with_flags(table, handle, flags)
    }

    /// Read [`HandleFlags`] for `handle` in `task`'s table.
    pub fn flags(&self, task: TaskKey, handle: Handle) -> Result<HandleFlags, HandleError> {
        let table = self.table_id(task)?;
        self.authority().handle_flags(table, handle)
    }

    /// Update [`HandleFlags`] for `handle` in `task`'s table.
    pub fn set_flags(
        &self,
        task: TaskKey,
        handle: Handle,
        flags: HandleFlags,
    ) -> Result<(), HandleError> {
        let table = self.table_id(task)?;
        self.authority().set_handle_flags(table, handle, flags)
    }

    /// Close `handle` in `task`'s table, returning `Ok(Some(backing))` when
    /// this dropped the final reference in [`OpenLifetime`].
    #[must_use = "the last-reference backing token must be finalized by the caller"]
    pub fn close(
        &self,
        task: TaskKey,
        handle: Handle,
    ) -> Result<Option<BackingToken>, HandleError> {
        let table = self.table_id(task)?;
        self.authority().close_handle(table, handle)
    }

    /// Inherit handles from `parent_task` into a new table attached to
    /// `child_task`, honouring `flags.is_inheritable()` and `filter`.
    ///
    /// Any [`OpenRelease::Terminal`] token produced during rollback (if
    /// `parent_task` closes or exits while `filter` runs) or on
    /// `attach_task_table` failure is delivered to `release` so no last
    /// reference is dropped without finalization.
    pub fn inherit_task(
        &self,
        parent_task: TaskKey,
        child_task: TaskKey,
        filter: impl FnMut(ObjectPin, BackingToken, HandleFlags) -> bool,
        storage: &mut Extent,
        mut release: impl FnMut(BackingToken),
    ) -> Result<TableId, HandleError> {
        if parent_task == child_task {
            return Err(HandleError::InvalidHandle);
        }
        let parent_table = self.table_id(parent_task)?;
        let auth = self.authority();
        let child_table = auth.inherit_handle_table(parent_table, filter, storage, &mut release)?;
        if let Err(err) = self.attach_task_table(child_task, child_table) {
            *storage = auth.destroy_handle_table(child_table, &mut release)?;
            return Err(err);
        }
        Ok(child_table)
    }

    /// Destroy `task`'s handle table, remove `task` from the host's bucket
    /// index, reclaim its binding and table slots, and release every remaining
    /// handle's pin exactly once after `end_write` and outside both the bucket
    /// lock and the table lock.
    ///
    /// All-or-nothing under a bounded [`LockWait`]: if acquiring the bucket or
    /// table lock returns [`HandleError::Contended`], neither the task binding
    /// nor the table is modified ("gave up before any effect").
    pub fn exit_task(
        &self,
        task: TaskKey,
        release: impl FnMut(BackingToken),
    ) -> Result<Extent, HandleError> {
        let auth = self.authority();
        auth.handle_identity()?;
        if task.id.raw() <= 0 || task.serial.raw() == 0 {
            return Err(HandleError::Stale);
        }
        let bucket_idx = Self::bucket_index(task);
        let guard = self.lock_bucket(bucket_idx)?;
        let raw_id = task.id.raw() as u32;
        let raw_serial = task.serial.raw();
        let mut prev_idx: Option<usize> = None;
        let mut cur = guard.bucket.head.load(Ordering::Relaxed);
        let mut found: Option<(usize, Option<usize>, u32, TableId)> = None;
        while cur != 0 {
            let idx = (cur - 1) as usize;
            let record = self
                .task_core
                .bindings
                .get(idx)
                .ok_or(HandleError::BadBacking)?;
            let next = record.hash_next.load(Ordering::Relaxed);
            if record.task_id.load(Ordering::Relaxed) == raw_id
                && record.task_serial.load(Ordering::Relaxed) == raw_serial
            {
                let id = TableId {
                    authority: record.table_authority.load(Ordering::Relaxed),
                    index: record.table_index.load(Ordering::Relaxed) as usize,
                    generation: record.table_generation.load(Ordering::Relaxed),
                };
                found = Some((idx, prev_idx, next, id));
                break;
            }
            prev_idx = Some(idx);
            cur = next;
        }
        let Some((binding_idx, prev_idx, next, table_id)) = found else {
            return Err(HandleError::Stale);
        };

        // Lock and validate the bound handle table BEFORE unlinking the binding
        // so `Contended` leaves both the binding and the table untouched.
        let (table_guard, t) = auth.lock_bound_handle_table(table_id)?;
        let end = t.limit.min(t.storage.capacity());
        auth.validate_closing_slots(&t.storage, end, false)?;

        // Unlink the binding under the bucket seqlock, return the binding to
        // `free_bindings`, and drop `guard` (`TaskBucket` spinlock) BEFORE
        // running any finalizer.
        let record = self
            .task_core
            .bindings
            .get(binding_idx)
            .ok_or(HandleError::BadBacking)?;
        let previous = prev_idx
            .map(|idx| {
                self.task_core
                    .bindings
                    .get(idx)
                    .ok_or(HandleError::BadBacking)
            })
            .transpose()?;
        guard.bucket.begin_write();
        if let Some(prev) = previous {
            prev.hash_next.store(next, Ordering::Relaxed);
        } else {
            guard.bucket.head.store(next, Ordering::Relaxed);
        }
        record.task_id.store(0, Ordering::Relaxed);
        record.task_serial.store(0, Ordering::Relaxed);
        record.table_authority.store(0, Ordering::Relaxed);
        record.table_index.store(0, Ordering::Relaxed);
        record.table_generation.store(0, Ordering::Relaxed);
        record.hash_next.store(0, Ordering::Relaxed);
        guard.bucket.end_write();
        drop(guard);
        self.push_binding(binding_idx);

        // Unpublish the table (`record.seq` even), drop the table lock, and run
        // `release` finalizers outside both the bucket lock and the table lock.
        Ok(auth.destroy_locked_handle_table(table_id.index, table_guard, t, end, release))
    }
}

#[cfg(not(all(test, feature = "loom")))]
const _: () = {
    assert!(matches!(crate::layout_fact("Core.free_objects"), Some(32)));
    assert!(matches!(crate::layout_fact("Core.object_count"), Some(40)));
    assert!(matches!(
        crate::layout_fact("TableRecord.retired"),
        Some(56)
    ));
    assert!(matches!(crate::layout_fact("TABLE_LIVE_HANDLES"), Some(2)));
    assert!(matches!(crate::layout_fact("TABLE_BOUND_TASK"), Some(4)));
    assert!(matches!(crate::layout_fact("ObjectRecord.size"), Some(64)));
    assert!(matches!(crate::layout_fact("ObjectRecord.align"), Some(64)));
    assert!(matches!(
        crate::layout_fact("ObjectRecord.lifetime"),
        Some(0)
    ));
    assert!(matches!(
        crate::layout_fact("ObjectRecord.incarnation"),
        Some(8)
    ));
    assert!(matches!(
        crate::layout_fact("ObjectRecord.backing"),
        Some(16)
    ));
    assert!(matches!(
        crate::layout_fact("ObjectRecord.next_free"),
        Some(24)
    ));
    assert!(matches!(
        crate::layout_fact("RawObjectGuard.size"),
        Some(40)
    ));
    assert!(matches!(
        crate::layout_fact("RawObjectGuard.align"),
        Some(8)
    ));
    assert!(matches!(
        crate::layout_fact("RawObjectGuard.authority"),
        Some(0)
    ));
    assert!(matches!(
        crate::layout_fact("RawObjectGuard.incarnation"),
        Some(8)
    ));
    assert!(matches!(
        crate::layout_fact("RawObjectGuard.backing"),
        Some(16)
    ));
    assert!(matches!(
        crate::layout_fact("RawObjectGuard.object_index"),
        Some(24)
    ));
    assert!(matches!(
        crate::layout_fact("RawObjectGuard.slot"),
        Some(28)
    ));
    assert!(matches!(
        crate::layout_fact("RawObjectGuard.slot_generation"),
        Some(32)
    ));
    assert!(matches!(
        crate::layout_fact("RawObjectGuard.flags_bits"),
        Some(36)
    ));
    assert!(matches!(crate::layout_fact("TaskBucket.size"), Some(64)));
    assert!(matches!(crate::layout_fact("TaskBucket.align"), Some(64)));
    assert!(matches!(crate::layout_fact("TaskBucket.head"), Some(4)));
    assert!(matches!(crate::layout_fact("TaskBucket.seq"), Some(8)));
    assert!(matches!(
        crate::layout_fact("TaskBindingRecord.size"),
        Some(64)
    ));
    assert!(matches!(
        crate::layout_fact("TaskBindingRecord.align"),
        Some(64)
    ));
    assert!(matches!(
        crate::layout_fact("TaskBindingRecord.task_id"),
        Some(0)
    ));
    assert!(matches!(
        crate::layout_fact("TaskBindingRecord.hash_next"),
        Some(4)
    ));
    assert!(matches!(
        crate::layout_fact("TaskBindingRecord.task_serial"),
        Some(8)
    ));
    assert!(matches!(
        crate::layout_fact("TaskBindingRecord.table_authority"),
        Some(16)
    ));
    assert!(matches!(
        crate::layout_fact("TaskBindingRecord.table_index"),
        Some(24)
    ));
    assert!(matches!(
        crate::layout_fact("TaskBindingRecord.table_generation"),
        Some(32)
    ));
    assert!(matches!(
        crate::layout_fact("TaskBindingRecord.next_free"),
        Some(40)
    ));
    assert!(matches!(
        crate::layout_fact("TaskHandleCore.size"),
        Some(320)
    ));
    assert!(matches!(
        crate::layout_fact("TaskHandleCore.align"),
        Some(64)
    ));
    assert!(matches!(
        crate::layout_fact("TaskHandleCore.free_bindings"),
        Some(128)
    ));
    assert!(matches!(
        crate::layout_fact("TaskHandleCore.buckets"),
        Some(192)
    ));
    assert!(matches!(
        crate::layout_fact("TaskHandleCore.bindings"),
        Some(256)
    ));
};
