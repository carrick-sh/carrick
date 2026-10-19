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
/// Coherence granule the layout is padded to. Apple Silicon reports
/// `hw.cachelinesize` = 128; x86 adjacent-line prefetch pairs 64-byte lines.
pub const SERVED_LINE: usize = 128;

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

/// Identity of one [`ServedTable`]. Issued once per table by
/// `carrick_core::mm::retirement::invalidation::issue_domain_nonce` from the
/// carrier-wide refusing retirement-nonce counter, so two tables (including
/// a table reallocated at a freed table's address) never share a nonce, and
/// a generation or completion from one domain never satisfies another.
///
/// `DomainNonce` is move-only (no `Copy` or `Clone`) so it cannot be duplicated
/// in safe code.
#[derive(Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct DomainNonce(NonZeroU64);

impl DomainNonce {
    /// # Safety
    /// `raw` was issued by the retirement-nonce counter for this domain and
    /// is never given to another table. A duplicate nonce lets one domain's
    /// completion satisfy another domain's retirement or reclaim.
    pub const unsafe fn from_issued(raw: NonZeroU64) -> Self {
        Self(raw)
    }
    pub const fn get(&self) -> NonZeroU64 {
        self.0
    }
}

/// One issued invalidation generation of one domain. Zero is never issued,
/// so a zero `owed`/`served` word means "nothing". Equality includes the
/// domain; values of different domains are not ordered.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct InvalidationGeneration {
    domain: NonZeroU64,
    value: NonZeroU64,
}

impl InvalidationGeneration {
    /// The raw domain identity this generation was issued for.
    pub const fn raw_domain(self) -> NonZeroU64 {
        self.domain
    }
    /// The value stored in `owed`/`served` words of this generation's domain.
    pub const fn value(self) -> NonZeroU64 {
        self.value
    }
    /// Whether an issued generation records completion of this generation.
    pub const fn served_by(self, served: Option<InvalidationGeneration>) -> bool {
        match served {
            Some(s) => s.domain.get() == self.domain.get() && s.value.get() >= self.value.get(),
            None => false,
        }
    }
    /// Whether `served` records completion of this generation.
    pub const fn served_by_generation(self, served: InvalidationGeneration) -> bool {
        served.domain.get() == self.domain.get() && served.value.get() >= self.value.get()
    }
}

impl PartialOrd for InvalidationGeneration {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        if self.domain.get() == other.domain.get() {
            self.value.partial_cmp(&other.value)
        } else {
            None
        }
    }
}

/// The counter reached `u64::MAX`; it stays pinned there and refuses forever.
/// Exhaustion is terminal for the domain: the caller has already edited
/// translations it can no longer request invalidation for, so it must stop
/// the carrier rather than continue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationExhausted;

impl fmt::Display for GenerationExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalidation generation counter exhausted")
    }
}
impl core::error::Error for GenerationExhausted {}

/// Carrier-wide issue counter of one domain. The stored word is the latest
/// issued value; it only moves forward and never wraps.
#[repr(C)]
#[derive(Debug)]
pub struct GenerationCounter<W: ServedWord = AtomicU64> {
    latest: W,
    domain: DomainNonce,
}

impl GenerationCounter<AtomicU64> {
    pub const fn new(domain: DomainNonce) -> Self {
        Self {
            latest: AtomicU64::new(0),
            domain,
        }
    }
}

impl<W: ServedWord> GenerationCounter<W> {
    pub fn with_domain(domain: DomainNonce) -> Self {
        Self {
            latest: W::default(),
            domain,
        }
    }

    pub const fn domain(&self) -> &DomainNonce {
        &self.domain
    }

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
            .map(|value| InvalidationGeneration {
                domain: self.domain.get(),
                value,
            })
            .ok_or(GenerationExhausted)
    }

    /// The latest issued generation (`None` before the first issue).
    pub fn latest(&self, order: Ordering) -> Option<InvalidationGeneration> {
        NonZeroU64::new(self.latest.load(order)).map(|value| InvalidationGeneration {
            domain: self.domain.get(),
            value,
        })
    }
}

/// The raw words of one member. Reachable only through the `unsafe`
/// [`ResidencyMember::words`]; see its contract.
#[repr(C)]
#[derive(Debug, Default)]
pub struct MemberWords<W: ServedWord = AtomicU64> {
    pub owed: [W; INVALIDATION_KINDS],
    pub served: [W; INVALIDATION_KINDS],
    /// Nonzero while the member may execute with cached translations.
    pub running: W,
    /// Seqlock over `tag`/`mm`/`context`: odd while the seat holder is
    /// publishing a context switch, even when the published triple is stable.
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

/// One member's residency and debt, padded to its own coherence granule so
/// the steady-state check is own-line loads only and no member shares a line
/// with another member or the issue counter.
#[repr(C, align(128))]
#[derive(Debug)]
pub struct ResidencyMember<W: ServedWord = AtomicU64> {
    words: MemberWords<W>,
    domain: NonZeroU64,
}

impl ResidencyMember<AtomicU64> {
    pub const fn new(domain: NonZeroU64) -> Self {
        Self {
            words: MemberWords {
                owed: [const { AtomicU64::new(0) }; INVALIDATION_KINDS],
                served: [const { AtomicU64::new(0) }; INVALIDATION_KINDS],
                running: AtomicU64::new(0),
                revision: AtomicU64::new(0),
                tag: AtomicU64::new(0),
                mm: AtomicU64::new(0),
                context: AtomicU64::new(0),
                seat: AtomicU64::new(0),
            },
            domain,
        }
    }
}

impl<W: ServedWord> ResidencyMember<W> {
    pub fn with_domain(domain: NonZeroU64) -> Self {
        Self {
            words: MemberWords::default(),
            domain,
        }
    }

    pub fn owed(&self, kind: InvalidationKind) -> Option<InvalidationGeneration> {
        NonZeroU64::new(self.words.owed[kind.index()].load(Ordering::Acquire)).map(|value| {
            InvalidationGeneration {
                domain: self.domain,
                value,
            }
        })
    }
    pub fn served(&self, kind: InvalidationKind) -> Option<InvalidationGeneration> {
        NonZeroU64::new(self.words.served[kind.index()].load(Ordering::Acquire)).map(|value| {
            InvalidationGeneration {
                domain: self.domain,
                value,
            }
        })
    }
    pub fn is_running(&self) -> bool {
        self.words.running.load(Ordering::Acquire) != 0
    }
    pub fn is_seated(&self) -> bool {
        self.words.seat.load(Ordering::Acquire) != 0
    }

    /// The raw words, for the invalidation protocol and ring-side writers.
    ///
    /// # Safety
    /// Every write through the returned reference keeps the protocol's
    /// writer discipline, or a false completion can be minted:
    /// - `owed` is only raised, with `fetch_max`, to a value issued by this
    ///   member's table counter;
    /// - `served`, `running`, `revision`, `tag`, `mm` and `context` are
    ///   written only by the current seat holder, and `served` only after an
    ///   architecturally complete local invalidation covering every value up
    ///   to the one stored;
    /// - `seat` changes only by the claim (0 to 1) and release (1 to 0)
    ///   compare-exchange of the seat holder.
    pub unsafe fn words(&self) -> &MemberWords<W> {
        &self.words
    }
}

/// The issue counter alone on its coherence granule, so issuing never
/// bounces a member line.
#[repr(C, align(128))]
#[derive(Debug)]
pub struct GenerationLine<W: ServedWord = AtomicU64> {
    counter: GenerationCounter<W>,
}

/// One invalidation domain of `N` members.
///
/// A domain cannot be duplicated in safe code because `DomainNonce` is move-only.
/// Dereferencing `domain()` fails because `DomainNonce` is not `Copy`:
/// ```compile_fail
/// use carrick_core_abi::mm::served::{DomainNonce, ServedTable};
/// use core::num::NonZeroU64;
///
/// let nonce = unsafe { DomainNonce::from_issued(NonZeroU64::new(1).unwrap()) };
/// let t1 = ServedTable::<1>::new(nonce);
/// let _n: DomainNonce = *t1.domain();
/// ```
///
/// Cloning `domain()` fails to produce an owned `DomainNonce` for a new table
/// because `DomainNonce` is not `Clone`:
/// ```compile_fail
/// use carrick_core_abi::mm::served::{DomainNonce, ServedTable};
/// use core::num::NonZeroU64;
///
/// let nonce = unsafe { DomainNonce::from_issued(NonZeroU64::new(1).unwrap()) };
/// let t1 = ServedTable::<1>::new(nonce);
/// let n = t1.domain().clone();
/// ServedTable::<1>::new(n);
/// ```
#[repr(C)]
#[derive(Debug)]
pub struct ServedTable<const N: usize, W: ServedWord = AtomicU64> {
    issue: GenerationLine<W>,
    members: [ResidencyMember<W>; N],
}

impl<const N: usize, W: ServedWord> ServedTable<N, W> {
    const MEMBERS_FIT: () = assert!(N != 0 && N <= SERVED_TABLE_MAX_MEMBERS);

    /// Member count, checked against the counted-mask width at compile time.
    pub const fn member_count() -> usize {
        let () = Self::MEMBERS_FIT;
        N
    }

    pub fn with_domain(domain: DomainNonce) -> Self {
        let () = Self::MEMBERS_FIT;
        let domain_raw = domain.get();
        Self {
            issue: GenerationLine {
                counter: GenerationCounter::with_domain(domain),
            },
            members: core::array::from_fn(|_| ResidencyMember::with_domain(domain_raw)),
        }
    }

    pub const fn counter(&self) -> &GenerationCounter<W> {
        &self.issue.counter
    }
    pub const fn domain(&self) -> &DomainNonce {
        self.issue.counter.domain()
    }
    pub const fn members(&self) -> &[ResidencyMember<W>; N] {
        &self.members
    }
}

impl<const N: usize> ServedTable<N, AtomicU64> {
    pub fn new(domain: DomainNonce) -> Self {
        let () = Self::MEMBERS_FIT;
        let domain_raw = domain.get();
        Self {
            issue: GenerationLine {
                counter: GenerationCounter::new(domain),
            },
            members: core::array::from_fn(|_| ResidencyMember::new(domain_raw)),
        }
    }
}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<GenerationCounter>() == 16);
    assert!(align_of::<GenerationLine>() == SERVED_LINE);
    assert!(size_of::<GenerationLine>() == SERVED_LINE);
    assert!(align_of::<ResidencyMember>() == SERVED_LINE);
    assert!(size_of::<ResidencyMember>() == SERVED_LINE);
    assert!(size_of::<MemberWords>() <= SERVED_LINE);
    assert!(offset_of!(ResidencyMember, words) == 0);
    assert!(offset_of!(ResidencyMember, domain) == 80);
    assert!(offset_of!(MemberWords, owed) == 0);
    assert!(offset_of!(MemberWords, served) == 16);
    assert!(offset_of!(MemberWords, running) == 32);
    assert!(offset_of!(MemberWords, revision) == 40);
    assert!(offset_of!(MemberWords, tag) == 48);
    assert!(offset_of!(MemberWords, mm) == 56);
    assert!(offset_of!(MemberWords, context) == 64);
    assert!(offset_of!(MemberWords, seat) == 72);
    assert!(offset_of!(ServedTable<2>, issue) == 0);
    assert!(offset_of!(ServedTable<2>, members) == SERVED_LINE);
    assert!(size_of::<ServedTable<2>>() == SERVED_LINE * 3);
    assert!(align_of::<ServedTable<2>>() == SERVED_LINE);
    assert!(InvalidationKind::Unmap.index() == 0);
    assert!(InvalidationKind::RevokeWrite.index() == 1);
};

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(raw: u64) -> DomainNonce {
        // SAFETY: each test value names one table only.
        unsafe { DomainNonce::from_issued(NonZeroU64::new(raw).expect("nonzero")) }
    }

    #[test]
    fn generation_counter_pins_at_max_and_keeps_refusing() {
        let counter = GenerationCounter {
            latest: AtomicU64::new(u64::MAX - 1),
            domain: domain(1),
        };
        let last = counter.issue().expect("the last generation is issuable");
        assert_eq!(last.value().get(), u64::MAX);
        for _ in 0..3 {
            assert_eq!(counter.issue(), Err(GenerationExhausted));
            assert_eq!(counter.latest(Ordering::Relaxed), Some(last));
        }
    }

    #[test]
    fn generations_start_at_one_and_carry_their_domain() {
        let counter = GenerationCounter::new(domain(2));
        let other = GenerationCounter::new(domain(3));
        let first = counter.issue().expect("fresh counter issues");
        let second = counter.issue().expect("fresh counter issues");
        let foreign = other.issue().expect("fresh counter issues");
        assert_eq!(first.value().get(), 1);
        assert!(second.value() > first.value());
        assert!(first.served_by(Some(first)) && !second.served_by(Some(first)));
        assert_eq!(foreign.value(), first.value());
        assert_ne!(foreign, first, "equal values of different domains differ");
        assert!(
            !first.served_by(Some(foreign)),
            "foreign domain cannot serve first"
        );
    }
}
