//! The software MMU's physical-retirement venue on the neutral invalidation
//! domain (`carrick_core::mm::retirement::invalidation`, #681 slice 2, #607).
//!
//! An [`ExtentTable`](crate::ExtentTable) owns one domain. Every soft vCPU is
//! a member holding a [`SoftVcpuSeat`]; its translation cache is its
//! [`SoftTlb`]. Physical ownership retirement (an extent removed or replaced,
//! a root generation removed or replaced) is keyed by the frame, not by one
//! address space, so it is a domain-wide request: every seated member owes
//! it, whatever root it runs. The venue:
//! - kick: the member's exit flag. Level 0 never chains blocks, so a running
//!   member returns to block entry within one bounded block; the flag tells
//!   an embedder's run loop the same thing;
//! - safe point: block entry, a lock-free own-line `has_debt` check;
//! - local invalidation: [`SoftTlb::flush_all`] for
//!   [`InvalidationKind::Unmap`], [`SoftTlb::flush_write_plane`] for
//!   [`InvalidationKind::RevokeWrite`] (#684).
//!
//! A running member serves only at block entry, never inside a block: a
//! pointer translated inside a block stays usable until the block ends,
//! because no request it owes can complete before its next safe point. A
//! parked member serves when it re-enters, and host-side guest access on a
//! parked member enters for the whole access (see [`SoftVcpuSeat::admit`]).
//!
//! There is no lock and no coordinator: completion is the neutral
//! [`PendingInvalidation::try_complete`], and retired identities wait in a
//! [`ReclaimQueue`] that only a [`DomainCompletion`] drains.
use alloc::sync::Arc;
use core::convert::Infallible;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use carrick_core::mm::retirement::invalidation::{
    DomainCompletion, GenerationExhausted, InvalidationGeneration, InvalidationKind,
    InvalidationScope, InvalidationVenue, MemberSeat, PendingInvalidation, ReclaimTag, SeatError,
    ServedTable, ServedWord, TableHandle, issue_domain_nonce,
};
use carrick_guest_arch::{CpuId, RootGpa};

use crate::tlb::SoftTlb;

/// Soft vCPUs one physical inventory can seat: the neutral table's
/// counted-mask width.
pub const SOFT_VCPU_MEMBERS: usize =
    carrick_core::mm::retirement::invalidation::SERVED_TABLE_MAX_MEMBERS;

/// One member's exit flag, alone on its coherence granule so a kick never
/// bounces another member's line.
#[repr(C, align(128))]
#[derive(Debug)]
struct ExitFlag(AtomicBool);

/// The invalidation domain of one physical inventory: the neutral served
/// table, one exit flag per member, and the kick count.
#[derive(Debug)]
pub(crate) struct SoftDomain {
    table: ServedTable<SOFT_VCPU_MEMBERS>,
    exits: [ExitFlag; SOFT_VCPU_MEMBERS],
    /// Kicks issued by retirements (a retirement-path RMW, never per block).
    kicks: AtomicU64,
}

/// Owning handle to a [`SoftDomain`]: a soft vCPU outlives any borrow of its
/// inventory, so its seat holds the domain through this handle.
#[derive(Clone, Debug)]
pub struct SoftDomainHandle(Arc<SoftDomain>);

// SAFETY: every clone shares one `Arc`, so every call returns the same table.
unsafe impl TableHandle<SOFT_VCPU_MEMBERS, AtomicU64> for SoftDomainHandle {
    fn table(&self) -> &ServedTable<SOFT_VCPU_MEMBERS> {
        &self.0.table
    }
}

impl SoftDomainHandle {
    pub(crate) fn new() -> Result<Self, GenerationExhausted> {
        let nonce = issue_domain_nonce()?;
        Ok(Self(Arc::new(SoftDomain {
            table: ServedTable::new(nonce),
            exits: [const { ExitFlag(AtomicBool::new(false)) }; SOFT_VCPU_MEMBERS],
            kicks: AtomicU64::new(0),
        })))
    }

    pub(crate) fn same_domain(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    fn venue<'a, F>(&'a self, tlb: Option<&'a mut SoftTlb>, relax: F) -> SoftVenue<'a, F> {
        SoftVenue {
            tlb,
            exits: &self.0.exits,
            kicks: &self.0.kicks,
            relax,
        }
    }

    pub(crate) fn kicks(&self) -> u64 {
        self.0.kicks.load(Ordering::Relaxed)
    }
}

type NoRelax = fn() -> Result<(), Infallible>;

const fn no_relax() -> Result<(), Infallible> {
    Ok(())
}

/// The soft venue: the member's own [`SoftTlb`] (absent for a host
/// requester, which caches no translations), the domain's exit flags, and
/// the wait policy of whoever waits.
pub(crate) struct SoftVenue<'a, F> {
    tlb: Option<&'a mut SoftTlb>,
    exits: &'a [ExitFlag],
    kicks: &'a AtomicU64,
    relax: F,
}

// SAFETY:
// - one cache owner per seat: a `SoftVcpuSeat` is owned by exactly one soft
//   CPU context together with its one `SoftTlb`, and every serve passes that
//   TLB; a fresh seat is claimed with the TLB it will serve;
// - `invalidate_local` is complete on return: the soft TLB is plain memory
//   owned by the calling thread, and both flushes overwrite every entry the
//   kind makes stale (all three planes for Unmap, the write plane and its
//   large-page shifts for RevokeWrite), for every root at once. A host
//   requester (`tlb: None`) caches no translations, so its flush is vacuous;
// - stopped: `SoftVcpuSeat::park` is the only stop, and every lookup by a
//   parked CPU goes through `SoftVcpuSeat::admit` (enter) first;
// - kick: level 0 never chains blocks, so a running member reaches block
//   entry (its safe point) within one bounded block;
// - no `install`: requests here are domain-wide and never match a context.
unsafe impl<F, E> InvalidationVenue for SoftVenue<'_, F>
where
    F: FnMut() -> Result<(), E>,
{
    type Tag = RootGpa;
    type Error = E;
    const SCOPE: InvalidationScope = InvalidationScope::PerCpu;

    fn kick(&self, cpu: CpuId) {
        if let Some(flag) = usize::try_from(cpu.raw())
            .ok()
            .and_then(|index| self.exits.get(index))
        {
            flag.0.store(true, Ordering::Release);
            self.kicks.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn invalidate_local(
        &mut self,
        kind: InvalidationKind,
        _scope: InvalidationScope,
    ) -> Result<(), E> {
        if let Some(tlb) = self.tlb.as_deref_mut() {
            match kind {
                InvalidationKind::Unmap => tlb.flush_all(),
                InvalidationKind::RevokeWrite => tlb.flush_write_plane(),
            }
        }
        Ok(())
    }

    fn relax(&mut self) -> Result<(), E> {
        (self.relax)()
    }
}

/// The block-entry safe point, generic over the served word so a structural
/// test can count its accesses on the exact code path production runs.
/// Returns whether it invalidated.
pub(crate) fn block_entry<H, const N: usize, W, V>(
    seat: &mut MemberSeat<H, N, W>,
    running: &mut bool,
    venue: &mut V,
) -> Result<bool, V::Error>
where
    H: TableHandle<N, W>,
    W: ServedWord,
    V: InvalidationVenue,
{
    if !*running {
        let owed = seat.has_debt();
        seat.enter(venue)?;
        *running = true;
        return Ok(owed);
    }
    if seat.has_debt() {
        seat.serve(venue)?;
        return Ok(true);
    }
    Ok(false)
}

/// Why a soft vCPU could not join an inventory's domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SoftSeatError {
    /// Every member of the domain is seated.
    Full,
}

/// How a host-side guest access was admitted; hand it back to
/// [`SoftVcpuSeat::release`] when the access (including every use of the
/// pointers it produced) is over.
#[must_use = "a parked CPU stays admitted until the admission is released"]
#[derive(Debug, Eq, PartialEq)]
pub enum LookupAdmission {
    /// The CPU was already running; nothing to undo.
    Running,
    /// The CPU was parked and entered for this access; it parks again.
    Entered,
}

/// One soft vCPU's membership in its inventory's domain: the only writer of
/// its member words. Dropping it stops the member and frees the seat.
#[derive(Debug)]
pub struct SoftVcpuSeat {
    seat: MemberSeat<SoftDomainHandle, SOFT_VCPU_MEMBERS>,
    domain: SoftDomainHandle,
    running: bool,
}

impl SoftVcpuSeat {
    pub(crate) fn claim(
        domain: &SoftDomainHandle,
        tlb: &mut SoftTlb,
    ) -> Result<Self, SoftSeatError> {
        for index in 0..SOFT_VCPU_MEMBERS {
            let cpu = CpuId::new(index as u32);
            let mut venue = domain.venue(Some(&mut *tlb), no_relax as NoRelax);
            match MemberSeat::claim(domain.clone(), cpu, &mut venue) {
                Ok(seat) => {
                    return Ok(Self {
                        seat,
                        domain: domain.clone(),
                        running: false,
                    });
                }
                Err(SeatError::Claimed) => {}
                Err(SeatError::OutOfRange) => break,
                Err(SeatError::Venue(never)) => match never {},
            }
        }
        Err(SoftSeatError::Full)
    }

    /// This member's index in the domain.
    pub fn cpu(&self) -> CpuId {
        self.seat.cpu()
    }

    /// Whether this CPU is admitted to translate (between block entry and
    /// [`Self::park`]).
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Whether this seat is a member of `domain`.
    pub(crate) fn belongs_to(&self, domain: &SoftDomainHandle) -> bool {
        self.domain.same_domain(domain)
    }

    /// Block entry: the safe point. A parked CPU enters (serving what it owes
    /// before its first translation); a running CPU checks its own debt with
    /// own-line loads and serves only when it owes. Returns whether it
    /// flushed.
    pub fn block_entry(&mut self, tlb: &mut SoftTlb) -> bool {
        let mut venue = self.domain.venue(Some(tlb), no_relax as NoRelax);
        let Ok(flushed) = block_entry(&mut self.seat, &mut self.running, &mut venue);
        if flushed {
            // The debt is served; a kick racing this store is advisory only,
            // its debt stays in `owed` for the next entry.
            self.exit_flag().store(false, Ordering::Relaxed);
        }
        flushed
    }

    /// Stop translating: the CPU will not use its TLB again until
    /// [`Self::block_entry`] or [`Self::admit`]. Call before blocking (a
    /// host wait, a halted vCPU), so retirements never wait for this CPU.
    pub fn park(&mut self) {
        if self.running {
            self.seat.stop();
            self.running = false;
        }
    }

    /// Admit a host-side guest access (a syscall copy, a fault-time read).
    /// A running CPU needs nothing: requests it owes cannot complete before
    /// its next block entry. A parked CPU enters, serving its debt first, and
    /// stays admitted until [`Self::release`], which must come after every use
    /// of the translations the access produced.
    pub fn admit(&mut self, tlb: &mut SoftTlb) -> LookupAdmission {
        if self.running {
            return LookupAdmission::Running;
        }
        let mut venue = self.domain.venue(Some(tlb), no_relax as NoRelax);
        let Ok(()) = self.seat.enter(&mut venue);
        self.running = true;
        LookupAdmission::Entered
    }

    /// End a host-side access admitted by [`Self::admit`].
    pub fn release(&mut self, admission: LookupAdmission) {
        if admission == LookupAdmission::Entered {
            self.park();
        }
    }

    /// Whether a retirement asked this CPU to reach block entry.
    pub fn exit_requested(&self) -> bool {
        self.exit_flag().load(Ordering::Acquire)
    }

    fn exit_flag(&self) -> &AtomicBool {
        &self.domain.0.exits[self.seat.cpu().raw() as usize].0
    }
}

/// A soft vCPU retiring from inside its own execution: its seat is served
/// inline and never kicked, so it cannot wait on itself.
#[derive(Debug)]
pub struct SoftRequester<'a> {
    pub(crate) seat: &'a mut SoftVcpuSeat,
    pub(crate) tlb: &'a mut SoftTlb,
}

impl<'a> SoftRequester<'a> {
    pub fn new(seat: &'a mut SoftVcpuSeat, tlb: &'a mut SoftTlb) -> Self {
        Self { seat, tlb }
    }
}

/// A published retirement. Not cloneable; completes into the
/// [`DomainCompletion`] that [`ExtentTable::reclaim`](crate::ExtentTable::reclaim)
/// takes. Dropping it loses only the proof: every member's debt stays
/// recorded, and the retired identities stay refused for reuse.
#[must_use = "retired identities stay refused until the retirement completes"]
#[derive(Debug)]
pub struct PendingRetirement {
    pending: PendingInvalidation<SoftDomainHandle, SOFT_VCPU_MEMBERS>,
}

impl PendingRetirement {
    pub(crate) fn new(pending: PendingInvalidation<SoftDomainHandle, SOFT_VCPU_MEMBERS>) -> Self {
        Self { pending }
    }

    pub fn generation(&self) -> InvalidationGeneration {
        self.pending.generation()
    }

    /// Members that owe this retirement (its per-member work).
    pub fn counted_members(&self) -> u32 {
        self.pending.counted_members()
    }

    pub(crate) fn reclaim_tag(&self) -> ReclaimTag {
        self.pending.reclaim_tag()
    }

    /// Whether `cpu` owes this retirement.
    pub fn counts(&self, cpu: CpuId) -> bool {
        self.pending.counts(cpu)
    }

    /// Lock-free completion check.
    pub fn try_complete(self) -> Result<DomainCompletion, Self> {
        self.pending
            .try_complete()
            .map_err(|pending| Self { pending })
    }

    /// Wait for every running member to reach block entry. `relax` owns the
    /// wait policy and its bound; an error hands the retirement back. A soft
    /// vCPU waiting on its own retirement passes itself as `requester` and
    /// keeps serving its own debt between polls. Never call this while
    /// holding a lock a running member needs to reach block entry.
    pub fn wait<F, E>(
        self,
        requester: Option<SoftRequester<'_>>,
        relax: F,
    ) -> Result<DomainCompletion, (Self, E)>
    where
        F: FnMut() -> Result<(), E>,
    {
        let domain = self.pending_domain();
        match requester {
            Some(SoftRequester { seat, tlb }) => {
                let mut venue = domain.venue(Some(tlb), relax);
                self.pending
                    .wait(Some(&mut seat.seat), &mut venue)
                    .map_err(|(pending, error)| (Self { pending }, error))
            }
            None => {
                let mut venue = domain.venue(None, relax);
                self.pending
                    .wait(None, &mut venue)
                    .map_err(|(pending, error)| (Self { pending }, error))
            }
        }
    }

    fn pending_domain(&self) -> SoftDomainHandle {
        // One `Arc` clone per wait, on the retirement path only.
        self.pending.handle().clone()
    }
}

/// Commit a domain-wide request for `kind` after the caller's edit. The
/// requester, when given, belongs to `domain` (checked by the caller before
/// the edit).
pub(crate) fn commit_domain(
    domain: &SoftDomainHandle,
    kind: InvalidationKind,
    requester: Option<SoftRequester<'_>>,
) -> Result<PendingRetirement, CommitRefused> {
    use carrick_core::mm::retirement::invalidation::{CommitError, stage_domain};
    let staged = stage_domain::<_, SOFT_VCPU_MEMBERS, AtomicU64, RootGpa>(domain.clone(), kind);
    let result = match requester {
        Some(SoftRequester { seat, tlb }) => {
            let mut venue = domain.venue(Some(tlb), no_relax as NoRelax);
            staged.commit(Some(&mut seat.seat), &mut venue)
        }
        None => {
            let mut venue = domain.venue(None, no_relax as NoRelax);
            staged.commit(None, &mut venue)
        }
    };
    match result {
        Ok(pending) => Ok(PendingRetirement::new(pending)),
        Err(CommitError::Venue { error, .. }) => match error {},
        Err(CommitError::Exhausted) => Err(CommitRefused::Exhausted),
        Err(CommitError::ForeignSeat) => Err(CommitRefused::ForeignRequester),
    }
}

/// A commit that published nothing after the caller's edit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommitRefused {
    Exhausted,
    ForeignRequester,
}

#[cfg(test)]
mod tests;
