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
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};

use carrick_guest_arch::{AddressContext, CpuId, RootGpa};

use super::InvalidationProof;

pub use carrick_core_abi::mm::served::{
    GenerationCounter, GenerationExhausted, INVALIDATION_KINDS, InvalidationGeneration,
    InvalidationKind, ResidencyMember, SERVED_TABLE_MAX_MEMBERS, ServedTable, ServedWord,
};

#[cfg(all(test, not(feature = "loom")))]
mod tests;

#[cfg(all(test, feature = "loom"))]
mod loom_models;

/// Which caches one local invalidation covers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidationScope {
    /// Every member flushes its own translations (x86 CR3 reload, the soft
    /// flush). Broadcast (ARM TLBI IS) arrives with slice 1b.
    PerCpu,
}

/// A venue translation tag (root or ASID) stored in a member's `tag` word.
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
/// - `invalidate_local(kind, scope)` returns `Ok` only after every
///   translation this CPU could have cached that is stale for `kind` has been
///   architecturally invalidated, including any barrier the ISA requires
///   before the next translation use (x86 CR3 reload, ARM DSB/ISB). Returning
///   `Ok` early mints a false [`DomainCompletion`].
/// - `kick(cpu)` makes a running member reach a safe point that calls
///   [`MemberSeat::serve`] in bounded time.
/// - Each member calls [`MemberSeat::enter`] before using translations after
///   being stopped, and [`MemberSeat::install`] for every context switch.
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

/// Identity of one [`ServedTable`]: tags and completions from different
/// domains never match even when their generation numbers do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DomainId(usize);

fn domain_of<const N: usize, W: ServedWord>(table: &ServedTable<N, W>) -> DomainId {
    DomainId(core::ptr::from_ref(table).addr())
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
pub enum SeatError {
    /// The CPU index is not a member of this table.
    OutOfRange,
    /// Another holder already owns this member.
    Claimed,
}

/// Exclusive ownership of one member: the only writer of its context,
/// `running` and `served` words. Not cloneable; dropping it releases the seat.
#[derive(Debug)]
pub struct MemberSeat<'t, const N: usize, W: ServedWord = AtomicU64> {
    table: &'t ServedTable<N, W>,
    index: usize,
}

impl<'t, const N: usize, W: ServedWord> MemberSeat<'t, N, W> {
    pub fn claim(table: &'t ServedTable<N, W>, cpu: CpuId) -> Result<Self, SeatError> {
        let index = usize::try_from(cpu.raw()).map_err(|_| SeatError::OutOfRange)?;
        if index >= ServedTable::<N, W>::member_count() {
            return Err(SeatError::OutOfRange);
        }
        table.members[index]
            .seat
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| SeatError::Claimed)?;
        Ok(Self { table, index })
    }

    pub fn cpu(&self) -> CpuId {
        // `claim` admitted the index from a `u32`.
        CpuId::new(self.index as u32)
    }

    fn member(&self) -> &'t ResidencyMember<W> {
        &self.table.members[self.index]
    }

    /// Publish `context` as this member's installed context, then serve
    /// every generation issued before the publication became visible.
    pub fn install<V: InvalidationVenue>(
        &mut self,
        context: AddressContext<V::Tag>,
        venue: &mut V,
    ) -> Result<(), V::Error> {
        let key = ContextKey::of(context);
        let member = self.member();
        let revision = member.revision.load(Ordering::Relaxed);
        member
            .revision
            .store(revision.wrapping_add(1), Ordering::Relaxed);
        W::fence(Ordering::Release);
        member.tag.store(key.tag, Ordering::Relaxed);
        member.mm.store(key.mm, Ordering::Relaxed);
        member.context.store(key.context, Ordering::Relaxed);
        member
            .revision
            .store(revision.wrapping_add(2), Ordering::Release);
        // Install Dekker: publication before reading the issue counter.
        W::fence(Ordering::SeqCst);
        let latest = self.table.issue.counter.latest(Ordering::Acquire);
        for kind in InvalidationKind::ALL {
            let served = &member.served[kind.index()];
            if served.load(Ordering::Relaxed) < latest {
                venue.invalidate_local(kind, V::SCOPE)?;
                served.store(latest, Ordering::Release);
            }
        }
        Ok(())
    }

    /// Admit this member to execution, serving any debt recorded while it
    /// was stopped before it can use a translation.
    pub fn enter<V: InvalidationVenue>(&mut self, venue: &mut V) -> Result<(), V::Error> {
        self.member().running.store(1, Ordering::Relaxed);
        // Entry Dekker: `running` before reading `owed`.
        W::fence(Ordering::SeqCst);
        self.serve(venue)
    }

    /// Leave execution at a safe point. Outstanding debt stays recorded and
    /// is served by the next [`Self::enter`].
    pub fn stop(&mut self) {
        self.member().running.store(0, Ordering::Release);
    }

    /// The steady-state check: own-line loads only, zero read-modify-writes.
    pub fn has_debt(&self) -> bool {
        let member = self.member();
        InvalidationKind::ALL.iter().any(|kind| {
            member.owed[kind.index()].load(Ordering::Acquire)
                > member.served[kind.index()].load(Ordering::Relaxed)
        })
    }

    /// Safe-point serve: invalidate locally for each kind with debt and
    /// publish the owed generation as served. With no debt this is the
    /// steady-state check and nothing else.
    pub fn serve<V: InvalidationVenue>(&mut self, venue: &mut V) -> Result<(), V::Error> {
        let member = self.member();
        for kind in InvalidationKind::ALL {
            let owed = member.owed[kind.index()].load(Ordering::Acquire);
            let served = &member.served[kind.index()];
            if owed > served.load(Ordering::Relaxed) {
                venue.invalidate_local(kind, V::SCOPE)?;
                served.store(owed, Ordering::Release);
            }
        }
        Ok(())
    }
}

impl<const N: usize, W: ServedWord> Drop for MemberSeat<'_, N, W> {
    fn drop(&mut self) {
        self.member().seat.store(0, Ordering::Release);
    }
}

/// Stage an invalidation of `context` inside a page-table transaction's
/// prepare step. Staging has no global effect; [`StagedInvalidation::commit`]
/// is the only route to a request and dropping the stage is rollback.
pub fn stage<'t, const N: usize, W: ServedWord, T: ResidencyTag>(
    table: &'t ServedTable<N, W>,
    context: AddressContext<T>,
    kind: InvalidationKind,
) -> StagedInvalidation<'t, N, W, T> {
    StagedInvalidation {
        table,
        key: ContextKey::of(context),
        kind,
        tag: PhantomData,
    }
}

#[derive(Debug)]
pub enum CommitError<'t, const N: usize, W: ServedWord, E> {
    /// No generation was issued; nothing was published.
    Exhausted,
    /// The requester seat belongs to another table; nothing was published.
    ForeignSeat,
    /// The request was published but the requester's inline serve failed.
    /// Its debt stays recorded; [`PendingInvalidation::wait`] serves it.
    Venue {
        pending: PendingInvalidation<'t, N, W>,
        error: E,
    },
}

/// A prepared, unpublished invalidation. Not cloneable.
#[must_use = "dropping a staged invalidation rolls it back"]
#[derive(Debug)]
pub struct StagedInvalidation<'t, const N: usize, W: ServedWord, T: ResidencyTag> {
    table: &'t ServedTable<N, W>,
    key: ContextKey,
    kind: InvalidationKind,
    tag: PhantomData<T>,
}

impl<'t, const N: usize, W: ServedWord, T: ResidencyTag> StagedInvalidation<'t, N, W, T> {
    /// Discard the stage. Equivalent to dropping it: nothing was published.
    pub fn rollback(self) {}

    /// Publish the request after the transaction's translation edits.
    pub fn commit<V: InvalidationVenue<Tag = T>>(
        self,
        requester: Option<&mut MemberSeat<'t, N, W>>,
        venue: &mut V,
    ) -> Result<PendingInvalidation<'t, N, W>, CommitError<'t, N, W, V::Error>> {
        if requester
            .as_ref()
            .is_some_and(|seat| !core::ptr::eq(seat.table, self.table))
        {
            return Err(CommitError::ForeignSeat);
        }
        let generation = self
            .table
            .issue
            .counter
            .issue()
            .map_err(|GenerationExhausted| CommitError::Exhausted)?;
        // Install Dekker: issue before reading member contexts.
        W::fence(Ordering::SeqCst);
        let mut counted = 0u64;
        for (index, member) in self.table.members.iter().enumerate() {
            if matches_or_changing(member, self.key) {
                member.owed[self.kind.index()].fetch_max(generation.get().get(), Ordering::AcqRel);
                counted |= 1 << index;
            }
        }
        // Entry Dekker: `owed` before reading `running`.
        W::fence(Ordering::SeqCst);
        let requester_index = requester.as_ref().map(|seat| seat.index);
        for (index, member) in self.table.members.iter().enumerate() {
            if counted & (1 << index) != 0
                && Some(index) != requester_index
                && member.running.load(Ordering::Relaxed) != 0
            {
                venue.kick(CpuId::new(index as u32));
            }
        }
        let pending = PendingInvalidation {
            table: self.table,
            generation,
            kind: self.kind,
            counted,
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
fn matches_or_changing<W: ServedWord>(member: &ResidencyMember<W>, key: ContextKey) -> bool {
    let first = member.revision.load(Ordering::Acquire);
    if first & 1 != 0 {
        return true;
    }
    let observed = ContextKey {
        tag: member.tag.load(Ordering::Relaxed),
        mm: member.mm.load(Ordering::Relaxed),
        context: member.context.load(Ordering::Relaxed),
    };
    W::fence(Ordering::Acquire);
    let last = member.revision.load(Ordering::Relaxed);
    first != last || (observed.mm != 0 && observed == key)
}

/// A published request. Linear: not cloneable, consumed by
/// [`Self::try_complete`] or [`Self::wait`], which return it on refusal.
#[must_use = "a pending invalidation must complete before its reclaim is released"]
#[derive(Debug)]
pub struct PendingInvalidation<'t, const N: usize, W: ServedWord = AtomicU64> {
    table: &'t ServedTable<N, W>,
    generation: InvalidationGeneration,
    kind: InvalidationKind,
    counted: u64,
}

impl<'t, const N: usize, W: ServedWord> PendingInvalidation<'t, N, W> {
    pub fn generation(&self) -> InvalidationGeneration {
        self.generation
    }
    pub fn kind(&self) -> InvalidationKind {
        self.kind
    }
    /// Whether this member was counted (owes this generation).
    pub fn counts(&self, cpu: CpuId) -> bool {
        u32::try_from(N).is_ok_and(|n| cpu.raw() < n) && self.counted & (1 << cpu.raw()) != 0
    }

    /// Tag an object whose reuse must wait for this request's completion.
    pub fn reclaim_tag(&self) -> ReclaimTag {
        ReclaimTag {
            domain: domain_of(self.table),
            generation: self.generation,
            kind: self.kind,
        }
    }

    /// Lock-free completion check. Every counted member has served, or is
    /// stopped with the debt recorded (it serves in [`MemberSeat::enter`]
    /// before any translation use).
    pub fn try_complete(self) -> Result<DomainCompletion, Self> {
        // Pairs with the entry fence: a member that starts running after
        // this fence reads the `owed` raised before it.
        W::fence(Ordering::SeqCst);
        for (index, member) in self.table.members.iter().enumerate() {
            if self.counted & (1 << index) == 0 {
                continue;
            }
            if self
                .generation
                .served_by(member.served[self.kind.index()].load(Ordering::Acquire))
            {
                continue;
            }
            if member.running.load(Ordering::Acquire) == 0 {
                continue;
            }
            return Err(self);
        }
        Ok(DomainCompletion {
            domain: domain_of(self.table),
            generation: self.generation,
            kind: self.kind,
        })
    }

    /// Venue-driven wait. Serves the requester's own debt between polls so
    /// mutual requests cannot deadlock; never runs under any table lock
    /// (there is none). On a venue error the request is handed back.
    pub fn wait<V: InvalidationVenue>(
        mut self,
        mut requester: Option<&mut MemberSeat<'t, N, W>>,
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
/// [`PendingInvalidation::try_complete`].
#[derive(Debug)]
pub struct DomainCompletion {
    domain: DomainId,
    generation: InvalidationGeneration,
    kind: InvalidationKind,
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
#[derive(Debug, Eq, PartialEq)]
pub struct ReclaimTag {
    domain: DomainId,
    generation: InvalidationGeneration,
    kind: InvalidationKind,
}

impl ReclaimTag {
    pub fn generation(&self) -> InvalidationGeneration {
        self.generation
    }
    fn released_by(&self, completion: &DomainCompletion) -> bool {
        self.domain == completion.domain
            && self.generation == completion.generation
            && self.kind == completion.kind
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
    /// Release every object tagged with exactly this completion's domain,
    /// generation and kind. A completion for one context's generation says
    /// nothing about another context's, so release is exact, not a watermark.
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
