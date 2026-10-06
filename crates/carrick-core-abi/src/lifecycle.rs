//! Neutral thread lifecycle notification authority.

use core::sync::atomic::{AtomicU64, Ordering};

/// One retained notification authority for a kernel graph's thread ledger.
#[repr(C, align(16))]
#[derive(Debug)]
pub struct ThreadLedgerActivity {
    pending: AtomicU64,
}

impl ThreadLedgerActivity {
    pub const fn new() -> Self {
        Self {
            pending: AtomicU64::new(0),
        }
    }
    pub fn pending(&self) -> u64 {
        self.pending.load(Ordering::Acquire)
    }
    pub fn announce(&self) {
        self.pending.fetch_add(1, Ordering::Release);
    }
    pub fn complete(&self, count: u64) -> Result<(), u64> {
        self.pending
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                pending.checked_sub(count)
            })
            .map(|_| ())
    }
}

impl Default for ThreadLedgerActivity {
    fn default() -> Self {
        Self::new()
    }
}

/// Life stage of a pool entry.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryState {
    /// Never stocked (initial).
    Vacant = 0,
    /// Being stocked by the kernel; identity fields are not yet valid.
    Stocking = 1,
    /// Identity issued, unclaimed.
    Reserved = 2,
    /// An EL1 clone owns it and is filling in the Born record.
    Claimed = 3,
    /// Child exists; the host has not yet observed it.
    Born = 4,
    /// The host settled the birth.
    Published = 5,
    /// The thread exited in the zone; the host has not yet folded the exit.
    ExitedInZone = 6,
    /// The host folded the exit; the identity is free to restock.
    Reaped = 7,
    /// Withdrawn before use.
    Revoked = 8,
    /// Exit owns admission; a host must drain it before conflicting work.
    ExitingBorn = 9,
    /// The host published a birth whose exit still owns admission.
    ExitingPublished = 10,
}

impl EntryState {
    pub const fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::Stocking,
            2 => Self::Reserved,
            3 => Self::Claimed,
            4 => Self::Born,
            5 => Self::Published,
            6 => Self::ExitedInZone,
            7 => Self::Reaped,
            8 => Self::Revoked,
            9 => Self::ExitingBorn,
            10 => Self::ExitingPublished,
            _ => Self::Vacant,
        }
    }
}

pub const fn pack(generation: u64, state: EntryState) -> EntryWord {
    EntryWord((generation << 8) | state as u64)
}
pub const fn unpack(word: EntryWord) -> (u64, EntryState) {
    (word.0 >> 8, EntryState::from_raw(word.0 as u8))
}

/// Why a transition was refused. `observed` is the state (or generation)
/// found instead; nothing was changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionError {
    /// The entry was not in a state this transition starts from.
    WrongState(EntryState),
    /// The entry was recycled since the reference was taken (ABA).
    StaleGeneration,
    /// The gate was not open; the claim was backed out.
    GateClosed(GateState),
    /// The index is outside the pool.
    NoSuchEntry,
    /// No entry is `Reserved` (the owner claim scan).
    PoolEmpty,
}

/// A reference to one incarnation of one entry. Copyable: it proves nothing
/// by itself, every transition re-validates the generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryRef {
    index: u32,
    generation: u64,
}
impl EntryRef {
    pub const fn new(index: u32, generation: u64) -> Self {
        Self { index, generation }
    }
    pub const fn index(self) -> usize {
        self.index as usize
    }
    pub const fn generation(self) -> u64 {
        self.generation
    }
    /// One word for a a Linux control sidecar: never 0, since a stocked entry's
    /// generation is at least 1.
    pub const fn pack(self) -> u64 {
        (self.generation << 8) | self.index as u64
    }
    pub const fn unpack(word: u64) -> Option<Self> {
        if word == 0 {
            return None;
        }
        Some(Self {
            index: (word & 0xff) as u32,
            generation: word >> 8,
        })
    }
}

/// Fork/exec gate for EL1 lifecycle serving.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateState {
    Open = 0,
    /// A fork transaction is settling claims; new claims back out.
    ForkClosing = 1,
    /// Terminal for this page: exec, tracer, seccomp or opt-out. A new page
    /// is stocked for the next incarnation.
    Closed = 2,
    /// Exec committed; no conflicting operation owns this page, but its new
    /// image has not installed executable birth capacity yet.
    AwaitingExecBinding = 3,
}
impl GateState {
    pub const fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::Open,
            1 => Self::ForkClosing,
            3 => Self::AwaitingExecBinding,
            _ => Self::Closed,
        }
    }
}

/// A membership release would cross its caller-selected lower bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MembershipFloor;

/// Encoded neutral state, never a Linux payload or a visible task identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryWord(u64);

/// Atomic storage for one neutral entry's state and exact incarnation.
#[repr(transparent)]
#[derive(Debug)]
pub struct AtomicEntry(AtomicU64);
impl AtomicEntry {
    pub const fn new(word: EntryWord) -> Self {
        Self(AtomicU64::new(word.0))
    }
    pub fn load(&self, ordering: Ordering) -> EntryWord {
        EntryWord(self.0.load(ordering))
    }
    pub fn store(&self, word: EntryWord, ordering: Ordering) {
        self.0.store(word.0, ordering);
    }
    pub fn compare_exchange(
        &self,
        current: EntryWord,
        new: EntryWord,
        success: Ordering,
        failure: Ordering,
    ) -> Result<EntryWord, EntryWord> {
        self.0
            .compare_exchange(current.0, new.0, success, failure)
            .map(EntryWord)
            .map_err(EntryWord)
    }
}
