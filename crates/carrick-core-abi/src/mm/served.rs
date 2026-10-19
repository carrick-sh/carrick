//! Shared-memory layout of the neutral TLB invalidation domain (#681).
//!
//! One [`ServedTable`] covers every execution member (CPU slot) that can cache
//! translations for one carrier. Each [`ResidencyMember`] keeps its own debt:
//! `owed[kind]` is raised by any requester with `fetch_max`, `served[kind]` is
//! written only by the member after its local invalidation completed. There
//! are no per-sender request cells, so a later request can never overwrite a
//! stopped member's earlier debt. The protocol lives in
//! `carrick_core::mm::retirement::invalidation`; this module owns only words,
//! layout and the refusing generation counter.
use core::fmt;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

/// Number of [`InvalidationKind`] values; the length of `owed` and `served`.
pub const INVALIDATION_KINDS: usize = 2;
/// Members are tracked in one 64-bit counted mask per request.
pub const SERVED_TABLE_MAX_MEMBERS: usize = 64;

/// What a request removes from cached translations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum InvalidationKind {
    /// A leaf was removed or replaced; every cached translation is stale.
    Unmap = 0,
    /// Write permission was revoked (code publication, COW arming).
    RevokeWrite = 1,
}

impl InvalidationKind {
    pub const ALL: [Self; INVALIDATION_KINDS] = [Self::Unmap, Self::RevokeWrite];

    /// Index of this kind in `owed` and `served`.
    pub const fn index(self) -> usize {
        self as usize
    }
}

/// One shared 64-bit word of the domain. Production uses [`AtomicU64`];
/// model checkers and structural-budget tests substitute their own word.
pub trait ServedWord: Default + Sync {
    fn load(&self, order: Ordering) -> u64;
    fn store(&self, value: u64, order: Ordering);
    fn fetch_max(&self, value: u64, order: Ordering) -> u64;
    fn compare_exchange(
        &self,
        current: u64,
        new: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64>;
    fn fetch_update<F: FnMut(u64) -> Option<u64>>(
        &self,
        set_order: Ordering,
        fetch_order: Ordering,
        f: F,
    ) -> Result<u64, u64>;
    /// A memory fence in the same memory model as this word.
    fn fence(order: Ordering);
}

impl ServedWord for AtomicU64 {
    #[inline]
    fn load(&self, order: Ordering) -> u64 {
        AtomicU64::load(self, order)
    }
    #[inline]
    fn store(&self, value: u64, order: Ordering) {
        AtomicU64::store(self, value, order);
    }
    #[inline]
    fn fetch_max(&self, value: u64, order: Ordering) -> u64 {
        AtomicU64::fetch_max(self, value, order)
    }
    #[inline]
    fn compare_exchange(
        &self,
        current: u64,
        new: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64> {
        AtomicU64::compare_exchange(self, current, new, success, failure)
    }
    #[inline]
    fn fetch_update<F: FnMut(u64) -> Option<u64>>(
        &self,
        set_order: Ordering,
        fetch_order: Ordering,
        f: F,
    ) -> Result<u64, u64> {
        AtomicU64::fetch_update(self, set_order, fetch_order, f)
    }
    #[inline]
    fn fence(order: Ordering) {
        core::sync::atomic::fence(order);
    }
}

/// One issued invalidation generation. Zero is never issued, so a zero
/// `owed`/`served` word means "nothing".
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct InvalidationGeneration(NonZeroU64);

impl InvalidationGeneration {
    pub const fn get(self) -> NonZeroU64 {
        self.0
    }
    /// Whether a `served` word records completion of this generation.
    pub const fn served_by(self, word: u64) -> bool {
        word >= self.0.get()
    }
}

/// The counter reached `u64::MAX`; it stays pinned there and refuses forever.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationExhausted;

impl fmt::Display for GenerationExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalidation generation counter exhausted")
    }
}
impl core::error::Error for GenerationExhausted {}

/// Carrier-wide issue counter. The stored word is the latest issued
/// generation; it only moves forward and never wraps.
#[repr(C)]
#[derive(Debug, Default)]
pub struct GenerationCounter<W: ServedWord = AtomicU64> {
    latest: W,
}

impl GenerationCounter<AtomicU64> {
    pub const fn new() -> Self {
        Self {
            latest: AtomicU64::new(0),
        }
    }
}

impl<W: ServedWord> GenerationCounter<W> {
    /// Issue the next generation. Mirrors `RootQuarantine::reserve_with_counter`:
    /// a `checked_add` refusal performs no store, so the word stays at MAX.
    pub fn issue(&self) -> Result<InvalidationGeneration, GenerationExhausted> {
        let previous = self
            .latest
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_add(1)
            })
            .map_err(|_| GenerationExhausted)?;
        previous
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .map(InvalidationGeneration)
            .ok_or(GenerationExhausted)
    }

    /// The latest issued generation (zero before the first issue).
    pub fn latest(&self, order: Ordering) -> u64 {
        self.latest.load(order)
    }
}

/// One member's residency and debt. The first cache line holds everything
/// the member's steady-state check reads and everything a requester writes,
/// so the check is own-line loads only.
///
/// Writers: `owed` by any requester (`fetch_max`); `served`, `revision`,
/// `tag`, `mm`, `context` and `running` only by the seat holder; `seat` by
/// claim/release compare-exchange.
#[repr(C, align(64))]
#[derive(Debug, Default)]
pub struct ResidencyMember<W: ServedWord = AtomicU64> {
    pub owed: [W; INVALIDATION_KINDS],
    pub served: [W; INVALIDATION_KINDS],
    /// Nonzero while the member may execute with cached translations.
    pub running: W,
    /// Seqlock over `tag`/`mm`/`context`; odd while a context is installed.
    pub revision: W,
    /// Venue translation tag (root or ASID word) of the installed context.
    pub tag: W,
    /// `MmGeneration` of the installed context; zero means none installed.
    pub mm: W,
    /// `ContextGeneration` of the installed context.
    pub context: W,
    /// Zero when unclaimed; one while a seat holder owns this member.
    pub seat: W,
}

impl ResidencyMember<AtomicU64> {
    pub const fn new() -> Self {
        Self {
            owed: [const { AtomicU64::new(0) }; INVALIDATION_KINDS],
            served: [const { AtomicU64::new(0) }; INVALIDATION_KINDS],
            running: AtomicU64::new(0),
            revision: AtomicU64::new(0),
            tag: AtomicU64::new(0),
            mm: AtomicU64::new(0),
            context: AtomicU64::new(0),
            seat: AtomicU64::new(0),
        }
    }
}

/// The counter on its own line, so issuing never bounces a member line.
#[repr(C, align(64))]
#[derive(Debug, Default)]
pub struct GenerationLine<W: ServedWord = AtomicU64> {
    pub counter: GenerationCounter<W>,
}

/// One invalidation domain of `N` members.
#[repr(C)]
#[derive(Debug)]
pub struct ServedTable<const N: usize, W: ServedWord = AtomicU64> {
    pub issue: GenerationLine<W>,
    pub members: [ResidencyMember<W>; N],
}

impl<const N: usize, W: ServedWord> ServedTable<N, W> {
    const MEMBERS_FIT: () = assert!(N != 0 && N <= SERVED_TABLE_MAX_MEMBERS);

    /// Member count, checked against the counted-mask width at compile time.
    pub const fn member_count() -> usize {
        let () = Self::MEMBERS_FIT;
        N
    }
}

impl<const N: usize> ServedTable<N, AtomicU64> {
    pub const fn new() -> Self {
        let () = Self::MEMBERS_FIT;
        Self {
            issue: GenerationLine {
                counter: GenerationCounter::new(),
            },
            members: [const { ResidencyMember::new() }; N],
        }
    }
}

impl<const N: usize, W: ServedWord> Default for ServedTable<N, W> {
    fn default() -> Self {
        let () = Self::MEMBERS_FIT;
        Self {
            issue: GenerationLine::default(),
            members: core::array::from_fn(|_| ResidencyMember::default()),
        }
    }
}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<GenerationCounter>() == 8);
    assert!(size_of::<GenerationLine>() == 64);
    assert!(align_of::<ResidencyMember>() == 64);
    assert!(size_of::<ResidencyMember>() == 128);
    assert!(offset_of!(ResidencyMember, owed) == 0);
    assert!(offset_of!(ResidencyMember, served) == 16);
    assert!(offset_of!(ResidencyMember, running) == 32);
    assert!(offset_of!(ResidencyMember, revision) == 40);
    assert!(offset_of!(ResidencyMember, tag) == 48);
    assert!(offset_of!(ResidencyMember, mm) == 56);
    assert!(offset_of!(ResidencyMember, context) == 64);
    assert!(offset_of!(ResidencyMember, seat) == 72);
    assert!(offset_of!(ServedTable<2>, issue) == 0);
    assert!(offset_of!(ServedTable<2>, members) == 64);
    assert!(size_of::<ServedTable<2>>() == 64 + 2 * 128);
    assert!(align_of::<ServedTable<2>>() == 64);
    assert!(InvalidationKind::Unmap.index() == 0);
    assert!(InvalidationKind::RevokeWrite.index() == 1);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_counter_pins_at_max_and_keeps_refusing() {
        let counter = GenerationCounter {
            latest: AtomicU64::new(u64::MAX - 1),
        };
        let last = counter.issue().expect("the last generation is issuable");
        assert_eq!(last.get().get(), u64::MAX);
        for _ in 0..3 {
            assert_eq!(counter.issue(), Err(GenerationExhausted));
            assert_eq!(counter.latest(Ordering::Relaxed), u64::MAX);
        }
    }

    #[test]
    fn generations_start_at_one_and_increase() {
        let counter = GenerationCounter::new();
        let first = counter.issue().expect("fresh counter issues");
        let second = counter.issue().expect("fresh counter issues");
        assert_eq!(first.get().get(), 1);
        assert!(second > first);
        assert!(first.served_by(1) && !second.served_by(1));
    }
}
