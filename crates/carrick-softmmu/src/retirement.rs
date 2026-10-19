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
//! Running is a scope, not a flag a caller must remember to clear: a CPU
//! runs only inside a [`RunningSeat`] (or an embedder's guard built on the
//! `unsafe` unguarded entry points), whose drop parks it, and host-side
//! access of a parked CPU runs inside a [`SeatAdmission`], whose drop parks
//! it again. A parked CPU is never waited on.
//!
//! A running member serves only at block entry, never inside a block: a
//! pointer translated inside a block stays usable until the block ends,
//! because no request it owes can complete before its next safe point.
//!
//! There is no lock and no coordinator: completion is the neutral
//! [`PendingInvalidation::try_complete`], and retired identities wait in a
//! [`ReclaimQueue`](carrick_core::mm::retirement::invalidation::ReclaimQueue)
//! that only a [`DomainCompletion`] drains.
use alloc::sync::Arc;
use core::convert::Infallible;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

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

/// One member's exit flag and runner token, alone on its coherence granule
/// so a kick never bounces another member's line.
#[repr(C, align(128))]
#[derive(Debug)]
struct MemberSlot {
    exit: AtomicBool,
    /// Identity of the thread running this member, zero when parked. Written
    /// only on a park/run transition, never per block.
    runner: AtomicUsize,
}

impl MemberSlot {
    const fn new() -> Self {
        Self {
            exit: AtomicBool::new(false),
            runner: AtomicUsize::new(0),
        }
    }
}

/// The calling thread's identity: the address of a thread-local, unique
/// among live threads. Without `std` there are no threads to tell apart.
#[cfg(any(test, feature = "std"))]
fn current_thread_token() -> usize {
    std::thread_local! {
        static TOKEN: u8 = const { 0 };
    }
    TOKEN.with(|token| core::ptr::from_ref(token) as usize)
}

#[cfg(not(any(test, feature = "std")))]
fn current_thread_token() -> usize {
    0
}

/// The terminal flag alone on its line: read (never written) per block.
#[repr(C, align(128))]
#[derive(Debug)]
struct TerminalLine(AtomicBool);

/// The invalidation domain of one physical inventory: the neutral served
/// table, one slot per member, the terminal flag and the kick count.
#[derive(Debug)]
pub(crate) struct SoftDomain<W: ServedWord = AtomicU64> {
    table: ServedTable<SOFT_VCPU_MEMBERS, W>,
    slots: [MemberSlot; SOFT_VCPU_MEMBERS],
    /// Set once, when a retirement could not be published: every member
    /// refuses to translate from then on.
    terminal: TerminalLine,
    /// Kicks issued by retirements (a retirement-path RMW, never per block).
    kicks: AtomicU64,
}

/// Owning handle to a [`SoftDomain`]: a soft vCPU outlives any borrow of its
/// inventory, so its seat holds the domain through this handle.
#[derive(Debug)]
pub struct SoftDomainHandle<W: ServedWord = AtomicU64>(Arc<SoftDomain<W>>);

impl<W: ServedWord> Clone for SoftDomainHandle<W> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

// SAFETY: every clone shares one `Arc`, so every call returns the same table.
unsafe impl<W: ServedWord> TableHandle<SOFT_VCPU_MEMBERS, W> for SoftDomainHandle<W> {
    fn table(&self) -> &ServedTable<SOFT_VCPU_MEMBERS, W> {
        &self.0.table
    }
}

impl<W: ServedWord> SoftDomainHandle<W> {
    pub(crate) fn new() -> Result<Self, GenerationExhausted> {
        let nonce = issue_domain_nonce()?;
        Ok(Self(Arc::new(SoftDomain {
            table: ServedTable::with_domain(nonce),
            slots: [const { MemberSlot::new() }; SOFT_VCPU_MEMBERS],
            terminal: TerminalLine(AtomicBool::new(false)),
            kicks: AtomicU64::new(0),
        })))
    }

    pub(crate) fn same_domain(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    fn venue<'a, F>(&'a self, tlb: Option<&'a mut SoftTlb>, relax: F) -> SoftVenue<'a, F> {
        SoftVenue {
            tlb,
            slots: &self.0.slots,
            kicks: &self.0.kicks,
            relax,
        }
    }

    pub(crate) fn kicks(&self) -> u64 {
        self.0.kicks.load(Ordering::Relaxed)
    }

    /// Stop every member: the domain can no longer publish retirements, so
    /// no CPU may keep translating through caches it cannot invalidate.
    pub(crate) fn make_terminal(&self) {
        self.0.terminal.0.store(true, Ordering::SeqCst);
    }

    pub(crate) fn is_terminal(&self) -> bool {
        self.0.terminal.0.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn table_for_test(&self) -> &ServedTable<SOFT_VCPU_MEMBERS, W> {
        &self.0.table
    }
}

type NoRelax = fn() -> Result<(), Infallible>;

const fn no_relax() -> Result<(), Infallible> {
    Ok(())
}

/// The soft venue: the member's own [`SoftTlb`] (absent for a host
/// requester, which caches no translations), the domain's member slots, and
/// the wait policy of whoever waits.
pub(crate) struct SoftVenue<'a, F> {
    tlb: Option<&'a mut SoftTlb>,
    slots: &'a [MemberSlot],
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
// - stopped: a member runs only inside a `RunningSeat`/`SeatAdmission` (or
//   an unguarded entry whose caller parks on every path), whose drop parks;
//   every return to translation enters first;
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
        if let Some(slot) = usize::try_from(cpu.raw())
            .ok()
            .and_then(|index| self.slots.get(index))
        {
            slot.exit.store(true, Ordering::Release);
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

/// Why a soft vCPU could not join an inventory's domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SoftSeatError {
    /// Every member of the domain is seated.
    Full,
}

/// The inventory can no longer publish retirements: no CPU may translate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InventoryTerminal;

/// How a host-side guest access was admitted by an unguarded entry; hand it
/// back to [`SoftVcpuSeat::release`] after the access.
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
pub struct SoftVcpuSeat<W: ServedWord = AtomicU64> {
    seat: MemberSeat<SoftDomainHandle<W>, SOFT_VCPU_MEMBERS, W>,
    domain: SoftDomainHandle<W>,
    running: bool,
}

impl<W: ServedWord> SoftVcpuSeat<W> {
    pub(crate) fn claim(
        domain: &SoftDomainHandle<W>,
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

    /// Whether this CPU is admitted to translate.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Whether this seat is a member of `domain`.
    pub(crate) fn belongs_to(&self, domain: &SoftDomainHandle<W>) -> bool {
        self.domain.same_domain(domain)
    }

    fn slot(&self) -> &MemberSlot {
        &self.domain.0.slots[self.seat.cpu().raw() as usize]
    }

    fn enter(&mut self, tlb: &mut SoftTlb) {
        self.slot()
            .runner
            .store(current_thread_token(), Ordering::Relaxed);
        let mut venue = self.domain.venue(Some(tlb), no_relax as NoRelax);
        let Ok(()) = self.seat.enter(&mut venue);
        self.running = true;
    }

    /// Run a sequence of blocks; the CPU parks when the guard drops.
    pub fn run(&mut self) -> RunningSeat<'_, W> {
        RunningSeat { seat: self }
    }

    /// Block entry without a guard. A parked CPU enters (serving what it owes
    /// before its first translation); a running CPU checks its own debt with
    /// own-line loads and serves only when it owes. Returns whether it
    /// flushed, or refuses once the inventory is terminal.
    ///
    /// # Safety
    /// The caller is a guard owning this seat whose drop calls
    /// [`Self::park`], on every path (unwinding included), before the
    /// thread blocks or stops stepping blocks: a running member that never
    /// reaches block entry again wedges every retirement until its waiter's
    /// bound. [`RunningSeat`] is that guard; an embedder that holds the seat
    /// inside a larger CPU object uses this with its own.
    pub unsafe fn block_entry_unguarded(
        &mut self,
        tlb: &mut SoftTlb,
    ) -> Result<bool, InventoryTerminal> {
        if self.domain.is_terminal() {
            self.park();
            return Err(InventoryTerminal);
        }
        if !self.running {
            let owed = self.seat.has_debt();
            self.enter(tlb);
            return Ok(owed);
        }
        if self.seat.has_debt() {
            // Clear the advisory exit flag before serving: a kick for a
            // later request that lands after this store stays set.
            self.slot().exit.store(false, Ordering::SeqCst);
            let mut venue = self.domain.venue(Some(tlb), no_relax as NoRelax);
            let Ok(()) = self.seat.serve(&mut venue);
            return Ok(true);
        }
        Ok(false)
    }

    /// Stop translating: the CPU will not use its TLB again until it enters.
    /// Always safe; the guards call it on drop.
    pub fn park(&mut self) {
        if self.running {
            self.seat.stop();
            self.slot().runner.store(0, Ordering::Relaxed);
            self.running = false;
        }
    }

    /// Admit a host-side guest access (a syscall copy, a fault-time read);
    /// a parked CPU parks again when the admission drops.
    pub fn admit<'s>(
        &'s mut self,
        tlb: &mut SoftTlb,
    ) -> Result<SeatAdmission<'s, W>, InventoryTerminal> {
        // SAFETY: the returned guard releases the admission on drop.
        let admission = unsafe { self.admit_unguarded(tlb) }?;
        Ok(SeatAdmission {
            seat: self,
            admission: Some(admission),
        })
    }

    /// Admission without a guard. A running CPU needs nothing: requests it
    /// owes cannot complete before its next block entry. A parked CPU enters,
    /// serving its debt first.
    ///
    /// # Safety
    /// The caller is a guard owning this seat that passes the admission to
    /// [`Self::release`] on every path after the last use of the translations
    /// the access produced. Leaking an `Entered` admission leaves the CPU
    /// running with no safe point to come.
    pub unsafe fn admit_unguarded(
        &mut self,
        tlb: &mut SoftTlb,
    ) -> Result<LookupAdmission, InventoryTerminal> {
        if self.domain.is_terminal() {
            self.park();
            return Err(InventoryTerminal);
        }
        if self.running {
            return Ok(LookupAdmission::Running);
        }
        self.enter(tlb);
        Ok(LookupAdmission::Entered)
    }

    /// End a host-side access admitted by [`Self::admit_unguarded`].
    pub fn release(&mut self, admission: LookupAdmission) {
        if admission == LookupAdmission::Entered {
            self.park();
        }
    }

    /// Whether a retirement asked this CPU to reach block entry.
    pub fn exit_requested(&self) -> bool {
        self.slot().exit.load(Ordering::Acquire)
    }
}

/// A run of blocks on one seat. Block entry inside the run costs own-line
/// loads only; dropping the guard parks the CPU, so a finished run never
/// holds a retirement up.
#[derive(Debug)]
pub struct RunningSeat<'s, W: ServedWord = AtomicU64> {
    seat: &'s mut SoftVcpuSeat<W>,
}

impl<W: ServedWord> RunningSeat<'_, W> {
    /// The block-entry safe point. Returns whether it flushed.
    pub fn block_entry(&mut self, tlb: &mut SoftTlb) -> Result<bool, InventoryTerminal> {
        // SAFETY: this guard parks the seat on drop.
        unsafe { self.seat.block_entry_unguarded(tlb) }
    }

    pub fn seat(&self) -> &SoftVcpuSeat<W> {
        self.seat
    }

    /// Whether a retirement asked this CPU to reach block entry.
    pub fn exit_requested(&self) -> bool {
        self.seat.exit_requested()
    }
}

impl<'s> RunningSeat<'s, AtomicU64> {
    /// This running CPU as the requester of a retirement it issues itself.
    pub fn requester<'a>(&'a mut self, tlb: &'a mut SoftTlb) -> SoftRequester<'a> {
        SoftRequester::new(self.seat, tlb)
    }
}

impl<W: ServedWord> Drop for RunningSeat<'_, W> {
    fn drop(&mut self) {
        self.seat.park();
    }
}

/// A host-side access of one seat; a parked CPU parks again on drop.
#[derive(Debug)]
pub struct SeatAdmission<'s, W: ServedWord = AtomicU64> {
    seat: &'s mut SoftVcpuSeat<W>,
    admission: Option<LookupAdmission>,
}

impl<W: ServedWord> SeatAdmission<'_, W> {
    pub fn seat(&self) -> &SoftVcpuSeat<W> {
        self.seat
    }
}

impl<W: ServedWord> Drop for SeatAdmission<'_, W> {
    fn drop(&mut self) {
        if let Some(admission) = self.admission.take() {
            self.seat.release(admission);
        }
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

/// Why [`PendingRetirement::wait`] handed the retirement back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetirementWaitError<E> {
    /// The waiting thread itself runs a CPU that owes this retirement and
    /// passed no requester: it would wait on its own safe point. Retry with
    /// that CPU as the requester, or park it first.
    SelfWait,
    /// The caller's relax policy ended the wait.
    Relax(E),
}

/// A published retirement. Not cloneable; completes into the
/// [`DomainCompletion`] that [`ExtentTable::reclaim`](crate::ExtentTable::reclaim)
/// takes. Dropping it loses only the proof: every member's debt stays
/// recorded, the retired identities stay refused, and any later completed
/// retirement of the same inventory releases them
/// ([`ExtentTable::retire_abandoned`](crate::ExtentTable::retire_abandoned)
/// issues one on demand).
#[must_use = "retired identities stay refused until a retirement completes"]
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
    /// keeps serving its own debt between polls; a thread that runs a
    /// counted CPU and passes no requester is refused
    /// ([`RetirementWaitError::SelfWait`]) instead of waiting on itself.
    pub fn wait<F, E>(
        self,
        requester: Option<SoftRequester<'_>>,
        relax: F,
    ) -> Result<DomainCompletion, (Self, RetirementWaitError<E>)>
    where
        F: FnMut() -> Result<(), E>,
    {
        let domain = self.pending.handle().clone();
        match requester {
            Some(SoftRequester { seat, tlb }) => {
                let mut venue = domain.venue(Some(tlb), relax);
                self.pending
                    .wait(Some(&mut seat.seat), &mut venue)
                    .map_err(|(pending, error)| {
                        (Self { pending }, RetirementWaitError::Relax(error))
                    })
            }
            None => {
                if self.waits_on_current_thread(&domain) {
                    return Err((self, RetirementWaitError::SelfWait));
                }
                let mut venue = domain.venue(None, relax);
                self.pending
                    .wait(None, &mut venue)
                    .map_err(|(pending, error)| {
                        (Self { pending }, RetirementWaitError::Relax(error))
                    })
            }
        }
    }

    /// Whether a counted member is running on the calling thread.
    fn waits_on_current_thread(&self, domain: &SoftDomainHandle) -> bool {
        let token = current_thread_token();
        token != 0
            && domain.0.slots.iter().enumerate().any(|(index, slot)| {
                self.pending.counts(CpuId::new(index as u32))
                    && slot.runner.load(Ordering::Relaxed) == token
            })
    }
}

/// Commit a domain-wide request for `kind`. The requester, when given,
/// belongs to `domain` (checked by the caller before any edit).
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
#[path = "../test-support/retirement_unit.rs"]
mod tests;
