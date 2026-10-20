//! The neutral TLB invalidation domain (#681, slice 1a: per-CPU scope).
//!
//! A requester that changed translations of one [`AddressContext`] stages an
//! invalidation inside its page-table transaction ([`stage`]); commit is the
//! only route to a request. A request issues one [`InvalidationGeneration`],
//! raises `owed[kind]` with `fetch_max` on every member whose installed
//! context matches (or is changing), kicks the running ones and serves the
//! requester inline. Members serve at safe points with
//! [`MemberSeat::serve`], whose steady-state check is own-line loads with
//! zero read-modify-writes. [`PendingInvalidation`] completes into a
//! [`DomainCompletion`], the proof that releases a [`ReclaimQueue`].
//!
//! Debt is per member, never per sender: a stopped member keeps every
//! generation it owes until it re-enters (#692 is the per-sender-cell
//! overwrite this replaces). Everything here is `no_std` and atomics-only;
//! there is no table lock.
//!
//! Two Dekker pairs carry the protocol, each closed by `SeqCst` fences:
//! - install: a member publishes its context, fences, then reads the latest
//!   issued generation; a requester issues, fences, then reads the member's
//!   context. Either the requester counts the member, or the member's install
//!   serves the generation.
//! - entry: a member sets `running`, fences, then reads `owed`; a requester
//!   raises `owed`, fences, then reads `running`. Either the requester kicks
//!   the member, or the member serves before it executes.
//!
//! [`PendingInvalidation::try_complete`] needs no fence of its own: it runs
//! after the commit that created the request (it owns the request), and
//! commit's entry-side fence and `running` read already happened. A member
//! commit saw running stays visible as running (read-read coherence) until it
//! stops; a member commit saw stopped serves in `enter`. The three-thread
//! loom model checks this with the fence absent.
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};

use carrick_guest_arch::{AddressContext, CpuId, RootGpa};

use super::InvalidationProof;

pub use carrick_core_abi::mm::served::{
    DomainNonce, GenerationCounter, GenerationExhausted, INVALIDATION_KINDS,
    InvalidationGeneration, InvalidationKind, MemberWords, ResidencyMember, SERVED_LINE,
    SERVED_TABLE_MAX_MEMBERS, ServedTable, ServedWord,
};

#[cfg(all(test, not(feature = "loom")))]
mod tests;

#[cfg(all(test, feature = "loom"))]
mod loom_models;

/// Issue the identity of a new invalidation domain. Domains draw from the
/// same carrier-wide refusing counter as root retirement tickets
/// (`NEXT_ROOT_RETIREMENT_NONCE`): both are retirement-custody identities
/// whose only property is uniqueness, so a nonce is never shared between a
/// table and any other table, including one reallocated at its address.
pub fn issue_domain_nonce() -> Result<DomainNonce, GenerationExhausted> {
    issue_domain_nonce_with(&super::NEXT_ROOT_RETIREMENT_NONCE)
}

fn issue_domain_nonce_with(counter: &AtomicU64) -> Result<DomainNonce, GenerationExhausted> {
    let raw = counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| GenerationExhausted)?;
    let raw = core::num::NonZeroU64::new(raw).ok_or(GenerationExhausted)?;
    // SAFETY: `raw` was just taken from the refusing retirement-nonce
    // counter, which never returns a value twice.
    Ok(unsafe { DomainNonce::from_issued(raw) })
}

/// Which caches one local invalidation covers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidationScope {
    /// Every member flushes its own translations (x86 CR3 reload, the soft
    /// flush). Broadcast (ARM TLBI IS) arrives with slice 1b.
    PerCpu,
}

/// A venue translation tag (root or ASID) stored in a member's `tag` word.
///
/// Requests match a member by the exact `(tag, MmGeneration,
/// ContextGeneration)` triple, so the venue must keep this key invariant:
/// every translation a CPU can cache while a context is installed belongs to
/// that context's exact triple. A tag reused for another address space must
/// come with a new `MmGeneration` or `ContextGeneration`, and translations of
/// one address space must never be reachable under two different triples at
/// once (two triples for one cache is two keys, one of which no request
/// names).
pub trait ResidencyTag: Copy + Eq {
    fn residency_word(self) -> u64;
}

impl ResidencyTag for RootGpa {
    fn residency_word(self) -> u64 {
        self.address().raw()
    }
}

/// Architectural invalidation and notification for one execution venue.
///
/// # Safety
/// - **One cache owner per seat.** While a [`MemberSeat`] for member `i` is
///   held, member `i` stands for exactly one translation cache (one CPU's
///   TLB, or one soft TLB), and that cache is served only through that seat.
///   A cache moving to another member index re-enters through
///   [`MemberSeat::claim`], which flushes it.
/// - A [`MemberSeat`] is dropped only once its cache is stopped.
/// - `invalidate_local(kind, scope)` returns `Ok` only after every
///   translation this cache could hold that is stale for `kind` has been
///   architecturally invalidated, **for every tag the cache holds** (not only
///   the installed context's), including any barrier the ISA requires before
///   the next translation use (x86 CR3 reload, ARM DSB/ISB). Returning `Ok`
///   early mints a false [`DomainCompletion`].
/// - **Stopped** means no hardware regime references any context through this
///   cache: no vCPU is in guest mode on it, and no CPU idles with a root
///   loaded whose translations it may still fetch (an x86 CPU halted with CR3
///   loaded is running, not stopped). A member reports stopped only through
///   [`MemberSeat::stop`] after reaching that state, and every return to
///   translation use goes through [`MemberSeat::enter`] first.
/// - Every context switch goes through [`MemberSeat::install`].
/// - `kick(cpu)` makes a running member reach a safe point that calls
///   [`MemberSeat::serve`] in bounded time.
pub unsafe trait InvalidationVenue {
    type Tag: ResidencyTag;
    type Error;
    const SCOPE: InvalidationScope;
    fn kick(&self, cpu: CpuId);
    fn invalidate_local(
        &mut self,
        kind: InvalidationKind,
        scope: InvalidationScope,
    ) -> Result<(), Self::Error>;
    /// Called between polls of [`PendingInvalidation::wait`]. The venue owns
    /// the wait policy and its bound; an error ends the wait.
    fn relax(&mut self) -> Result<(), Self::Error>;
}

/// The protocol's single access path to member words.
fn words<W: ServedWord>(member: &ResidencyMember<W>) -> &MemberWords<W> {
    // SAFETY: this module is the invalidation protocol. Requesters only
    // `fetch_max` `owed` with generations issued by the member's own table;
    // `served`, `running`, `revision`, `tag`, `mm` and `context` are written
    // only through a `MemberSeat` (the seat holder), `served` only after the
    // venue's architecturally complete `invalidate_local`; `seat` changes
    // only by the claim/release compare-exchange below.
    unsafe { member.words() }
}

/// How a seat, a stage or a pending request reaches its table.
///
/// A borrow (`&ServedTable`) serves members that live inside the table's
/// scope. A member that must outlive any borrow scope (a software vCPU
/// thread whose table is owned by a shared physical inventory) uses an
/// owning handle instead, so its seat is held without a self-referential
/// borrow. Requests from either handle reach the same member words.
///
/// # Safety
/// Every call to [`Self::table`], through this handle and every clone of it,
/// returns the same table for as long as any of them lives. A seat names a
/// member by index; a handle that changed tables would let one seat write
/// another table's member words and mint a completion for it.
pub unsafe trait TableHandle<const N: usize, W: ServedWord>: Clone {
    fn table(&self) -> &ServedTable<N, W>;
}

// SAFETY: a shared reference always names the one table it borrows.
unsafe impl<const N: usize, W: ServedWord> TableHandle<N, W> for &ServedTable<N, W> {
    fn table(&self) -> &ServedTable<N, W> {
        self
    }
}

/// Which members one request counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestTarget {
    /// Members whose installed context is exactly this key, or changing.
    Context(ContextKey),
    /// Every seated member, whatever context it has installed. Used when the
    /// edit is keyed by physical ownership rather than by one address space
    /// (an extent or table frame retired from under every context at once).
    Domain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContextKey {
    tag: u64,
    mm: u64,
    context: u64,
}

impl ContextKey {
    fn of<T: ResidencyTag>(context: AddressContext<T>) -> Self {
        Self {
            tag: context.root.residency_word(),
            mm: context.mm.raw().get(),
            context: context.generation.raw().get(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeatError<E> {
    /// The CPU index is not a member of this table.
    OutOfRange,
    /// Another holder already owns this member.
    Claimed,
    /// The admission flush failed; the seat was released.
    Venue(E),
}

/// Exclusive ownership of one member: the only writer of its context,
/// `running` and `served` words. Not cloneable; dropping it stops the member
/// and releases the seat.
#[derive(Debug)]
pub struct MemberSeat<H, const N: usize, W: ServedWord = AtomicU64>
where
    H: TableHandle<N, W>,
{
    handle: H,
    index: usize,
    word: PhantomData<fn() -> W>,
}

impl<H, const N: usize, W: ServedWord> MemberSeat<H, N, W>
where
    H: TableHandle<N, W>,
{
    /// Claim member `cpu` for the venue's cache. The member's `served`
    /// watermark describes the previous holder's cache, not this one, so
    /// admission flushes this cache for every kind before adopting it: read
    /// the latest issued generation after a `SeqCst` fence, invalidate, then
    /// publish that generation as served. Every translation edit at or below
    /// it preceded its issue, so the flush covers it; later generations stay
    /// owed.
    pub fn claim<V: InvalidationVenue>(
        handle: H,
        cpu: CpuId,
        venue: &mut V,
    ) -> Result<Self, SeatError<V::Error>> {
        let index = usize::try_from(cpu.raw()).map_err(|_| SeatError::OutOfRange)?;
        if index >= ServedTable::<N, W>::member_count() {
            return Err(SeatError::OutOfRange);
        }
        // Seat Dekker (domain requests): the claim before reading the issue
        // counter; a domain request issues, fences, then reads `seat`.
        words(&handle.table().members()[index])
            .seat
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| SeatError::Claimed)?;
        let seat = Self {
            handle,
            index,
            word: PhantomData,
        };
        W::fence(Ordering::SeqCst);
        let latest = seat.handle.table().counter().latest(Ordering::Acquire);
        for kind in InvalidationKind::ALL {
            // On error the seat drops: the member stops and is released.
            venue
                .invalidate_local(kind, V::SCOPE)
                .map_err(SeatError::Venue)?;
        }
        if let Some(latest) = latest {
            for kind in InvalidationKind::ALL {
                let served = &seat.words().served[kind.index()];
                if served.load(Ordering::Relaxed) < latest.value().get() {
                    served.store(latest.value().get(), Ordering::Release);
                }
            }
        }
        Ok(seat)
    }

    pub fn cpu(&self) -> CpuId {
        // `claim` admitted the index from a `u32`.
        CpuId::new(self.index as u32)
    }

    fn words(&self) -> &MemberWords<W> {
        words(&self.handle.table().members()[self.index])
    }

    /// The handle this seat was claimed through.
    pub fn handle(&self) -> &H {
        &self.handle
    }

    /// Whether this member is admitted to execution (between
    /// [`Self::enter`] and [`Self::stop`]). Own-line load; the seat holder
    /// is the only writer of `running`.
    pub fn is_running(&self) -> bool {
        self.words().running.load(Ordering::Relaxed) != 0
    }

    /// Publish `context` as this member's installed context, then serve
    /// every generation issued before the publication became visible. That
    /// debt is first raised into this member's own `owed`, so a failed local
    /// invalidation leaves it visible to [`Self::has_debt`] and the next
    /// [`Self::serve`] or [`Self::enter`].
    pub fn install<V: InvalidationVenue>(
        &mut self,
        context: AddressContext<V::Tag>,
        venue: &mut V,
    ) -> Result<(), V::Error> {
        let key = ContextKey::of(context);
        let words = self.words();
        let revision = words.revision.load(Ordering::Relaxed);
        words
            .revision
            .store(revision.wrapping_add(1), Ordering::Relaxed);
        W::fence(Ordering::Release);
        words.tag.store(key.tag, Ordering::Relaxed);
        words.mm.store(key.mm, Ordering::Relaxed);
        words.context.store(key.context, Ordering::Relaxed);
        words
            .revision
            .store(revision.wrapping_add(2), Ordering::Release);
        // Install Dekker: publication before reading the issue counter.
        W::fence(Ordering::SeqCst);
        let latest = self.handle.table().counter().latest(Ordering::Acquire);
        if let Some(latest) = latest {
            for kind in InvalidationKind::ALL {
                if words.served[kind.index()].load(Ordering::Relaxed) < latest.value().get() {
                    words.owed[kind.index()].fetch_max(latest.value().get(), Ordering::AcqRel);
                }
            }
        }
        self.serve(venue)
    }

    /// Admit this member to execution, serving any debt recorded while it
    /// was stopped before it can use a translation.
    pub fn enter<V: InvalidationVenue>(&mut self, venue: &mut V) -> Result<(), V::Error> {
        self.words().running.store(1, Ordering::Relaxed);
        // Entry Dekker: `running` before reading `owed`.
        W::fence(Ordering::SeqCst);
        self.serve(venue)
    }

    /// Leave execution once the cache is stopped (see the venue contract).
    /// Outstanding debt stays recorded and is served by the next
    /// [`Self::enter`].
    pub fn stop(&mut self) {
        self.words().running.store(0, Ordering::Release);
    }

    /// The steady-state check: own-line loads only, zero read-modify-writes.
    pub fn has_debt(&self) -> bool {
        let words = self.words();
        InvalidationKind::ALL.iter().any(|kind| {
            words.owed[kind.index()].load(Ordering::Acquire)
                > words.served[kind.index()].load(Ordering::Relaxed)
        })
    }

    /// Safe-point serve: invalidate locally for each kind with debt and
    /// publish the owed generation as served. With no debt this is the
    /// steady-state check and nothing else.
    pub fn serve<V: InvalidationVenue>(&mut self, venue: &mut V) -> Result<(), V::Error> {
        let words = self.words();
        for kind in InvalidationKind::ALL {
            let owed = words.owed[kind.index()].load(Ordering::Acquire);
            let served = &words.served[kind.index()];
            if owed > served.load(Ordering::Relaxed) {
                venue.invalidate_local(kind, V::SCOPE)?;
                served.store(owed, Ordering::Release);
            }
        }
        Ok(())
    }
}

impl<H, const N: usize, W: ServedWord> Drop for MemberSeat<H, N, W>
where
    H: TableHandle<N, W>,
{
    fn drop(&mut self) {
        let words = self.words();
        words.running.store(0, Ordering::Release);
        words.seat.store(0, Ordering::Release);
    }
}

/// Stage an invalidation of `context` inside a page-table transaction's
/// prepare step. Staging has no global effect; [`StagedInvalidation::commit`]
/// is the only route to a request and dropping the stage is rollback.
pub fn stage<H, const N: usize, W: ServedWord, T: ResidencyTag>(
    table: H,
    context: AddressContext<T>,
    kind: InvalidationKind,
) -> StagedInvalidation<H, N, W, T>
where
    H: TableHandle<N, W>,
{
    // The counted mask is one bit per member: N <= 64 is a compile-time fact.
    let _members = ServedTable::<N, W>::member_count();
    StagedInvalidation {
        handle: table,
        target: RequestTarget::Context(ContextKey::of(context)),
        kind,
        tag: PhantomData,
        word: PhantomData,
    }
}

/// Stage an invalidation that every seated member owes, whatever context it
/// has installed. For edits keyed by physical ownership (a retired extent or
/// table frame) that no single [`AddressContext`] names. Same transaction
/// rules as [`stage`].
///
/// A member claiming its seat concurrently is either counted (the request
/// read its seat) or its claim flush covers the generation (the claim read
/// the issue counter after the issue): the seat Dekker pair.
pub fn stage_domain<H, const N: usize, W: ServedWord, T: ResidencyTag>(
    table: H,
    kind: InvalidationKind,
) -> StagedInvalidation<H, N, W, T>
where
    H: TableHandle<N, W>,
{
    let _members = ServedTable::<N, W>::member_count();
    StagedInvalidation {
        handle: table,
        target: RequestTarget::Domain,
        kind,
        tag: PhantomData,
        word: PhantomData,
    }
}

#[derive(Debug)]
pub enum CommitError<H, const N: usize, W: ServedWord, E>
where
    H: TableHandle<N, W>,
{
    /// No generation was issued; nothing was published. Exhaustion is
    /// terminal for the domain: the caller's translation edits are already
    /// in place and can no longer be invalidated through it, so the caller
    /// must stop the carrier, never continue or retry.
    Exhausted,
    /// The requester seat belongs to another table; nothing was published.
    ForeignSeat,
    /// The request was published but the requester's inline serve failed.
    /// Its debt stays recorded in `owed` and is served by the next safe
    /// point; [`PendingInvalidation::wait`] retries it. Dropping `pending`
    /// loses only the completion proof, never the debt.
    Venue {
        pending: PendingInvalidation<H, N, W>,
        error: E,
    },
}

/// A prepared, unpublished invalidation. Not cloneable.
#[must_use = "dropping a staged invalidation rolls it back"]
#[derive(Debug)]
pub struct StagedInvalidation<H, const N: usize, W: ServedWord, T: ResidencyTag>
where
    H: TableHandle<N, W>,
{
    handle: H,
    target: RequestTarget,
    kind: InvalidationKind,
    tag: PhantomData<T>,
    word: PhantomData<fn() -> W>,
}

impl<H, const N: usize, W: ServedWord, T: ResidencyTag> StagedInvalidation<H, N, W, T>
where
    H: TableHandle<N, W>,
{
    /// Discard the stage. Equivalent to dropping it: nothing was published.
    pub fn rollback(self) {}

    /// Publish the request after the transaction's translation edits.
    ///
    /// A requester that is itself a member of this table must pass its seat:
    /// it is then served inline and never kicked. Without its seat, a running
    /// requester counted by its own request would kick itself and complete
    /// only after reaching a safe point it is not at.
    pub fn commit<V: InvalidationVenue<Tag = T>>(
        self,
        requester: Option<&mut MemberSeat<H, N, W>>,
        venue: &mut V,
    ) -> Result<PendingInvalidation<H, N, W>, CommitError<H, N, W, V::Error>> {
        let _members = ServedTable::<N, W>::member_count();
        let table = self.handle.table();
        if requester
            .as_ref()
            .is_some_and(|seat| !core::ptr::eq(seat.handle.table(), table))
        {
            return Err(CommitError::ForeignSeat);
        }
        let generation = table
            .counter()
            .issue()
            .map_err(|GenerationExhausted| CommitError::Exhausted)?;
        // Install (and seat) Dekker: issue before reading member contexts.
        W::fence(Ordering::SeqCst);
        let mut counted = 0u64;
        for (index, member) in table.members().iter().enumerate() {
            let words = words(member);
            let owes = match self.target {
                RequestTarget::Context(key) => matches_or_changing(words, key),
                RequestTarget::Domain => words.seat.load(Ordering::Acquire) != 0,
            };
            if owes {
                words.owed[self.kind.index()].fetch_max(generation.value().get(), Ordering::AcqRel);
                counted |= 1 << index;
            }
        }
        // Entry Dekker: `owed` before reading `running`.
        W::fence(Ordering::SeqCst);
        let requester_index = requester.as_ref().map(|seat| seat.index);
        for (index, member) in table.members().iter().enumerate() {
            if counted & (1 << index) != 0
                && Some(index) != requester_index
                && words(member).running.load(Ordering::Relaxed) != 0
            {
                venue.kick(CpuId::new(index as u32));
            }
        }
        let pending = PendingInvalidation {
            handle: self.handle,
            generation,
            kind: self.kind,
            counted,
            domain_wide: matches!(self.target, RequestTarget::Domain),
            word: PhantomData,
        };
        if let Some(seat) = requester
            && let Err(error) = seat.serve(venue)
        {
            return Err(CommitError::Venue { pending, error });
        }
        Ok(pending)
    }
}

/// Seqlock read of a member's installed context. A context switch in
/// progress, or one that completed during the read, counts as a match.
fn matches_or_changing<W: ServedWord>(words: &MemberWords<W>, key: ContextKey) -> bool {
    let first = words.revision.load(Ordering::Acquire);
    if first & 1 != 0 {
        return true;
    }
    let observed = ContextKey {
        tag: words.tag.load(Ordering::Relaxed),
        mm: words.mm.load(Ordering::Relaxed),
        context: words.context.load(Ordering::Relaxed),
    };
    W::fence(Ordering::Acquire);
    let last = words.revision.load(Ordering::Relaxed);
    first != last || (observed.mm != 0 && observed == key)
}

/// A published request. Linear: not cloneable, consumed by
/// [`Self::try_complete`] or [`Self::wait`], which return it on refusal.
/// Dropping it loses only the completion proof: the debt stays in `owed`.
#[must_use = "a pending invalidation must complete before its reclaim is released"]
#[derive(Debug)]
pub struct PendingInvalidation<H, const N: usize, W: ServedWord = AtomicU64>
where
    H: TableHandle<N, W>,
{
    handle: H,
    generation: InvalidationGeneration,
    kind: InvalidationKind,
    counted: u64,
    /// Whether the request counted every seated member (`stage_domain`).
    domain_wide: bool,
    word: PhantomData<fn() -> W>,
}

impl<H, const N: usize, W: ServedWord> PendingInvalidation<H, N, W>
where
    H: TableHandle<N, W>,
{
    pub fn generation(&self) -> InvalidationGeneration {
        self.generation
    }
    pub fn kind(&self) -> InvalidationKind {
        self.kind
    }
    /// The handle of the table this request was published in.
    pub fn handle(&self) -> &H {
        &self.handle
    }
    /// Whether this member was counted (owes this generation).
    pub fn counts(&self, cpu: CpuId) -> bool {
        u32::try_from(N).is_ok_and(|n| cpu.raw() < n) && self.counted & (1 << cpu.raw()) != 0
    }
    /// Whether this member was counted by this request and has not yet served
    /// this request's specific generation and kind.
    pub fn still_owes(&self, cpu: CpuId) -> bool {
        self.counts(cpu)
            && self
                .handle
                .table()
                .members()
                .get(cpu.raw() as usize)
                .is_some_and(|member| !self.generation.served_by(member.served(self.kind)))
    }
    /// How many members owe this generation: the request's per-member work.
    pub fn counted_members(&self) -> u32 {
        self.counted.count_ones()
    }

    /// Tag an object whose reuse must wait for this request's completion.
    pub fn reclaim_tag(&self) -> ReclaimTag {
        ReclaimTag {
            generation: self.generation,
            kind: self.kind,
            domain_wide: self.domain_wide,
        }
    }

    /// Lock-free completion check. Every counted member has served, or is
    /// stopped with the debt recorded (it serves in [`MemberSeat::enter`]
    /// before any translation use). No fence is needed; see the module docs.
    pub fn try_complete(self) -> Result<DomainCompletion, Self> {
        for (index, member) in self.handle.table().members().iter().enumerate() {
            if self.counted & (1 << index) == 0 {
                continue;
            }
            let words = words(member);
            if self.generation.served_by(member.served(self.kind)) {
                continue;
            }
            if words.running.load(Ordering::Acquire) == 0 {
                continue;
            }
            return Err(self);
        }
        Ok(DomainCompletion {
            generation: self.generation,
            kind: self.kind,
            domain_wide: self.domain_wide,
        })
    }

    /// Venue-driven wait. Serves the requester's own debt between polls so
    /// mutual requests cannot deadlock; never runs under any table lock
    /// (there is none). A requester that is a member must pass its seat. On
    /// a venue error the request is handed back.
    pub fn wait<V: InvalidationVenue>(
        mut self,
        mut requester: Option<&mut MemberSeat<H, N, W>>,
        venue: &mut V,
    ) -> Result<DomainCompletion, (Self, V::Error)> {
        loop {
            if let Some(seat) = requester.as_deref_mut()
                && let Err(error) = seat.serve(venue)
            {
                return Err((self, error));
            }
            match self.try_complete() {
                Ok(completion) => return Ok(completion),
                Err(pending) => self = pending,
            }
            if let Err(error) = venue.relax() {
                return Err((self, error));
            }
        }
    }
}

/// Proof that one generation completed across its domain. The only
/// [`InvalidationProof`] for [`InvalidationGeneration`]; minted only by
/// [`PendingInvalidation::try_complete`]. Its generation carries the domain
/// nonce, so it never satisfies another table's retirement or reclaim.
#[derive(Debug)]
pub struct DomainCompletion {
    generation: InvalidationGeneration,
    kind: InvalidationKind,
    domain_wide: bool,
}

impl DomainCompletion {
    pub fn kind(&self) -> InvalidationKind {
        self.kind
    }
}

// SAFETY: minted only after every counted member published `served` at or
// beyond this generation after an architecturally complete local
// invalidation, or is stopped with the debt recorded and serves it before
// its next translation use (the `InvalidationVenue` contract).
unsafe impl InvalidationProof<InvalidationGeneration> for DomainCompletion {
    fn generation(&self) -> InvalidationGeneration {
        self.generation
    }
}

/// Non-forgeable reclaim key, minted only from a published request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReclaimTag {
    generation: InvalidationGeneration,
    kind: InvalidationKind,
    domain_wide: bool,
}

impl ReclaimTag {
    pub fn generation(&self) -> InvalidationGeneration {
        self.generation
    }
    /// Exact release, or coverage by a later domain-wide completion.
    ///
    /// A domain-wide request counts every member seated at its commit. A
    /// member counted by an earlier domain-wide request of the same kind
    /// that is still seated at the later commit is counted again, so the
    /// later completion means it served at or past the later generation
    /// (`served` is a watermark), or is stopped owing it and serves before
    /// any translation use. A member that released its seat in between left
    /// no cache behind: a cache re-enters only through a claim, which
    /// flushes. So the later completion also completes the earlier request.
    /// Context-keyed requests count by context and get no such coverage.
    fn released_by(&self, completion: &DomainCompletion) -> bool {
        if self.kind != completion.kind {
            return false;
        }
        if self.generation == completion.generation {
            return true;
        }
        self.domain_wide
            && completion.domain_wide
            && self.generation.raw_domain() == completion.generation.raw_domain()
            && self.generation.value() <= completion.generation.value()
    }
}

/// Objects (frames, tags, extents) whose reuse waits for an exact completion.
#[derive(Debug)]
pub struct ReclaimQueue<T> {
    entries: alloc::vec::Vec<(ReclaimTag, T)>,
}

impl<T> Default for ReclaimQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> ReclaimQueue<T> {
    pub const fn new() -> Self {
        Self {
            entries: alloc::vec::Vec::new(),
        }
    }
    pub fn push(&mut self, tag: ReclaimTag, item: T) {
        self.entries.push((tag, item));
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// The objects still waiting, for owners that must refuse reuse of an
    /// identity while its retirement is outstanding.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.entries.iter().map(|(_, item)| item)
    }
    /// The objects still waiting and the tag each waits on.
    pub fn iter_tagged(&self) -> impl Iterator<Item = (ReclaimTag, &T)> {
        self.entries.iter().map(|(tag, item)| (*tag, item))
    }
    /// Release every object tagged with exactly this completion's domain,
    /// generation and kind. A completion for one context's generation says
    /// nothing about another context's, so release is exact, not a
    /// watermark; the one exception is a domain-wide completion, which also
    /// covers every earlier domain-wide request of its domain and kind (see
    /// `ReclaimTag::released_by`). That is what lets an owner recover the
    /// entries of a retirement whose pending request was dropped.
    pub fn drain_ready(&mut self, completion: &DomainCompletion) -> alloc::vec::Vec<T> {
        let mut ready = alloc::vec::Vec::new();
        let mut index = 0;
        while index < self.entries.len() {
            if self.entries[index].0.released_by(completion) {
                ready.push(self.entries.swap_remove(index).1);
            } else {
                index += 1;
            }
        }
        ready
    }
}
