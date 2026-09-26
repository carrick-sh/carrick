//! Exact-mm stage-1 quiesce: the authority a page-table edit holds while it
//! runs, and how dispatch and the carrier obtain it.
//!
//! Every stage-1 mutation of one Linux process's address space runs under a
//! Pause-Modify-Resume over the MM's [`crate::fork_quiesce::PtQuiesce`]
//! barrier (its fence): the editor wins the barrier's election, raises the
//! fence, then snapshots which vCPUs run the MM from the address-space
//! occupancy authority ([`crate::kernel::mm_occupancy`]) and kicks and drains
//! every one of them in guest. The proof comes in three shapes:
//!
//! - [`SoleMmStage1`]: the snapshot held no vCPU but the caller's own, so
//!   nothing was kicked;
//! - [`PtPauseGuard`]: the drain kicked and waited for every other vCPU
//!   running the MM;
//! - [`FrameCowExactMmGuard`]: the frame-COW variant, which may instead
//!   borrow the pause this host thread already holds (the `EXACT_MM_STAGE1`
//!   thread-local is only that lookup; authority is the upgraded lease).
//!
//! Every shape holds the raised fence until drop, so no vCPU can start
//! running the MM behind the proof: an executor marks itself in guest and
//! then reads the fence before every entry, and the occupancy snapshot is
//! taken after the raise (the ordering argument is in
//! [`crate::kernel::mm_occupancy`]).
//!
//! `dispatch::mm_mutation` seals each proof into an `MmMutationGuard`; the
//! carrier takes [`acquire_mm_stage1_authority`] before a fork/exec install.
//! The protocol names the occupancy authority, the dispatch coordinator and
//! the `carrick_thread` barrier only; no VMM type appears here, which is what
//! lets the dispatcher unit tests take the sole arm with no carrier.

use std::sync::Arc;
use std::time::{Duration, Instant};

use carrick_fatal::carrick_fatal;
use carrick_hal::ThreadId;
use carrick_hal::stage1_mm::Stage1MmProjection;

thread_local! {
    /// Exact live stage-1 leases on this vCPU service thread. The weak entry is
    /// only a lookup path for synchronous backend re-entry; authority is the
    /// upgraded, exact-MM `Rc<ExactMmStage1Lease>`, which owns the real fenced
    /// election or pause and therefore remains valid even if the outer wrapper
    /// is dropped first. A boolean/thread-local observation is never accepted.
    static EXACT_MM_STAGE1: std::cell::RefCell<Vec<(crate::kernel::MmId, std::rc::Weak<ExactMmStage1Lease>)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Enter sole stage-1 authority for an admitted executor: `None` when
/// another vCPU runs the MM (the caller must take a real pause instead).
/// Normalized handlers receive no such token.
pub(crate) fn with_sole_mm_stage1<T>(
    participation: &mut crate::dispatch::MmExecutorParticipation,
    run: impl FnOnce(&mut SoleMmStage1<'_>) -> T,
) -> Option<T> {
    let mut authority = SoleMmStage1::claim(participation)?;
    Some(run(&mut authority))
}

/// Holds this thread's stage-1 exclusivity claim for a mapping syscall's whole
/// dispatch. The pause raises the same marker, so the two nest harmlessly.
pub struct Stage1Exclusive {
    _private: (),
}

/// Shareable only within the current host service thread. A nested frame-COW
/// borrow clones this exact lease rather than trusting ambient thread state.
pub struct ExactMmStage1Lease {
    mm: crate::kernel::MmId,
    // Drop the engine-visible marker before the barrier guard resumes the
    // MM's vCPUs.
    _stage1: Stage1Exclusive,
    inner: crate::fork_quiesce::PtPauseGuard,
    /// The vCPUs the drain waited for (empty for a sole proof).
    residents: crate::kernel::mm_occupancy::MmResidents,
    _not_send_or_sync: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl ExactMmStage1Lease {
    fn new(
        mm: crate::kernel::MmId,
        inner: crate::fork_quiesce::PtPauseGuard,
        residents: crate::kernel::mm_occupancy::MmResidents,
    ) -> std::rc::Rc<Self> {
        std::rc::Rc::new(Self {
            mm,
            _stage1: Stage1Exclusive::claim(),
            inner,
            residents,
            _not_send_or_sync: std::marker::PhantomData,
        })
    }
}

struct ExactMmStage1Scope {
    mm: crate::kernel::MmId,
    lease: std::rc::Weak<ExactMmStage1Lease>,
}

impl ExactMmStage1Scope {
    fn enter(lease: &std::rc::Rc<ExactMmStage1Lease>) -> Self {
        let mm = lease.mm;
        let weak = std::rc::Rc::downgrade(lease);
        EXACT_MM_STAGE1.with(|stack| stack.borrow_mut().push((mm, weak.clone())));
        Self { mm, lease: weak }
    }
}

impl Drop for ExactMmStage1Scope {
    fn drop(&mut self) {
        EXACT_MM_STAGE1.with(|stack| {
            let mut stack = stack.borrow_mut();
            let (mm, lease) = stack.pop().unwrap_or_else(|| {
                carrick_fatal!(
                    "vcpu_loop::exact_mm_stage1_scope",
                    "ExactMmStage1Scope stack underflow on drop: mm={:?}",
                    self.mm
                )
            });
            if mm != self.mm || !std::rc::Weak::ptr_eq(&lease, &self.lease) {
                carrick_fatal!(
                    "vcpu_loop::exact_mm_stage1_scope",
                    "ExactMmStage1Scope mismatched MM ID or lease pointer on drop: expected_mm={:?}, found_mm={:?}",
                    self.mm,
                    mm
                );
            }
        });
    }
}

fn borrow_current_exact_mm_stage1(
    mm: crate::kernel::MmId,
) -> Option<std::rc::Rc<ExactMmStage1Lease>> {
    EXACT_MM_STAGE1.with(|stack| {
        stack
            .borrow()
            .iter()
            .rev()
            .find_map(|(candidate, lease)| (*candidate == mm).then(|| lease.upgrade()).flatten())
    })
}

#[cfg(any(test, feature = "test-support"))]
pub fn current_thread_holds_pt_pause() -> bool {
    EXACT_MM_STAGE1.with(|stack| {
        stack
            .borrow()
            .iter()
            .any(|(_, lease)| lease.upgrade().is_some())
    })
}

impl Stage1Exclusive {
    fn claim() -> Self {
        carrick_hal::stage1_exclusive::enter();
        Self { _private: () }
    }
}

impl Drop for Stage1Exclusive {
    fn drop(&mut self) {
        carrick_hal::stage1_exclusive::exit();
    }
}

/// Stage-1 authority for an executor that is the only vCPU running its MM.
///
/// The fence stays raised until drop, so no other vCPU can start running the
/// MM after the proof is minted.
pub struct SoleMmStage1<'participant> {
    // Scope drops first, removing the lookup before this wrapper releases its
    // lease. Nested borrowers own their own `Rc` and keep exclusion alive.
    _scope: ExactMmStage1Scope,
    _lease: std::rc::Rc<ExactMmStage1Lease>,
    _linear: std::marker::PhantomData<&'participant mut crate::dispatch::MmExecutorParticipation>,
    mm: crate::kernel::MmId,
    coordinator: Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>,
}

impl<'participant> SoleMmStage1<'participant> {
    fn claim(
        participation: &'participant mut crate::dispatch::MmExecutorParticipation,
    ) -> Option<Self> {
        let mm = participation.mm_id();
        let coordinator = participation.mutation_coordinator();
        let barrier = Arc::clone(participation.pt_quiesce());
        let own = participation.occupied_slot();
        // An election timeout here is a peer editor that never finished: the
        // caller reports it like any other peer (it cannot wait either way).
        begin_pt_pause(&barrier, ThreadId::NONE, PtPauseBudget::DEFAULT).ok()?;
        let residents = crate::kernel::mm_occupancy::residents(mm, &barrier, own);
        if !residents.is_empty() {
            barrier.end();
            return None;
        }
        let lease = ExactMmStage1Lease::new(mm, barrier.pause_guard(ThreadId::NONE), residents);
        Some(Self {
            _scope: ExactMmStage1Scope::enter(&lease),
            _lease: lease,
            _linear: std::marker::PhantomData,
            mm,
            coordinator,
        })
    }

    pub(crate) fn authorizes(
        &self,
        coordinator: &Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>,
        mm: crate::kernel::MmId,
    ) -> bool {
        self.mm == mm && Arc::ptr_eq(&self.coordinator, coordinator)
    }
}

pub enum MmStage1Authority<'participant> {
    Sole(SoleMmStage1<'participant>),
    Paused(PtPauseGuard<'participant>),
}

pub fn acquire_mm_stage1_authority<'participant>(
    participation: &'participant mut crate::dispatch::MmExecutorParticipation,
    tid: ThreadId,
    budget: PtPauseBudget,
) -> Result<MmStage1Authority<'participant>, PtPauseError> {
    let mm = participation.mm_id();
    let coordinator = participation.mutation_coordinator();
    let barrier = Arc::clone(participation.pt_quiesce());
    let own = participation.occupied_slot();
    begin_pt_pause(&barrier, tid, budget)?;
    let residents = crate::kernel::mm_occupancy::residents(mm, &barrier, own);
    if residents.is_empty() {
        let lease = ExactMmStage1Lease::new(mm, barrier.pause_guard(tid), residents);
        return Ok(MmStage1Authority::Sole(SoleMmStage1 {
            _scope: ExactMmStage1Scope::enter(&lease),
            _lease: lease,
            _linear: std::marker::PhantomData,
            mm,
            coordinator,
        }));
    }
    Ok(MmStage1Authority::Paused(drain_exact_mm(
        &barrier,
        mm,
        Some(coordinator),
        residents,
        tid,
    )))
}

pub struct PtPauseGuard<'mm> {
    _scope: ExactMmStage1Scope,
    _lease: std::rc::Rc<ExactMmStage1Lease>,
    mutation_coordinator: Option<Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>>,
    _authority: std::marker::PhantomData<&'mm mut ()>,
}

impl<'mm> PtPauseGuard<'mm> {
    fn new(
        mm: crate::kernel::MmId,
        mutation_coordinator: Option<Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>>,
        residents: crate::kernel::mm_occupancy::MmResidents,
        inner: crate::fork_quiesce::PtPauseGuard,
    ) -> Self {
        let lease = ExactMmStage1Lease::new(mm, inner, residents);
        Self {
            _scope: ExactMmStage1Scope::enter(&lease),
            _lease: lease,
            mutation_coordinator,
            _authority: std::marker::PhantomData,
        }
    }

    pub(crate) fn mutation_identity(
        &self,
    ) -> Option<(
        Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>,
        crate::kernel::MmId,
    )> {
        self.mutation_coordinator
            .as_ref()
            .map(|coordinator| (Arc::clone(coordinator), self._lease.mm))
    }

    /// The vCPUs this pause drained.
    #[cfg(any(test, feature = "test-support"))]
    pub fn drained_count(&self) -> usize {
        self._lease.residents.len()
    }
}

/// Process-wide page-table-edit Pause-Modify-Resume barrier.
#[cfg_attr(not(test), allow(dead_code))]
pub fn pt_barrier() -> &'static Arc<crate::fork_quiesce::PtQuiesce> {
    crate::fork_quiesce::pt_barrier()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtPauseError {
    /// The coordinator election exceeded [`PtPauseBudget::election`]. The drain
    /// itself never times out; it waits for acknowledgement.
    TimedOut,
}

/// The bound on a page-table pause: the election only.
///
/// Wait for the CURRENT coordinator to finish, before we hold anything. Real
/// contention resolves in low milliseconds (a loser waits out one page-table
/// edit), so a wait this long is not contention: the coordinator is blocked on
/// something the waiter holds. That was a live deadlock — the host-alias/pt-pause
/// ABBA — and the class survives its fix, since any syscall that takes the
/// host-alias phase and then triggers frame COW can rebuild it. Bounding here
/// makes the next instance a named `pt__pause__election__timeout` and a guest
/// `ENOMEM` instead of a silent, unrecoverable carrier stop.
///
/// There is deliberately NO drain budget. Once this thread is the coordinator
/// it waits for every sibling's acknowledgement (its in-guest flag falling),
/// however long the host takes to schedule that sibling: the old 500 ms drain
/// deadline turned host scheduling delay — and kicks that Carrick's own EL1
/// code absorbed — into `fault page-table pause failed before mutation:
/// TimedOut`, a fatal guest error under ordinary load. The drain terminates
/// because a kicked sibling always reaches an exit (see
/// `carrick_aarch64::engine`'s owed-kick handling) and exit/exec teardown
/// kicks every sibling out of guest too; it sleeps on a
/// [`carrick_hal::GuestLeaveWake`] rather than spinning, so it does not compete
/// for the CPU the siblings need to get there. The coordinator keeps its own
/// executor while it waits: nothing the siblings need to leave guest depends on
/// that capacity (each already occupies its vCPU, and every other executor of
/// this MM parks at the raised barrier regardless).
#[derive(Debug, Clone, Copy)]
pub struct PtPauseBudget {
    pub election: Duration,
}

impl PtPauseBudget {
    pub const DEFAULT: Self = Self {
        election: Duration::from_secs(30),
    };
}

/// Win the stop-the-world election and raise `quiescing` — the FIRST HALF of a
/// page-table pause, and no more than that.
///
/// On success this thread is the coordinator and no executor may re-enter
/// guest, but nothing has been drained and NO guard exists: the siblings
/// already inside the guest are still there. The caller owes the rest of the
/// protocol — `drain_exact_mm`, which kicks and observes every registered
/// participant out of guest and only then mints the [`PtPauseGuard`] whose drop
/// calls `barrier.end()`. Returning early between the two leaks the coordinator
/// flag and wedges every later editor, which is why this is private and the
/// complete protocols ([`acquire_mm_stage1_authority`],
/// [`acquire_frame_cow_quiesce`]) are what callers get.
///
/// A loser parks until the coordinator finishes or `budget.election` expires;
/// it holds nothing while waiting, so a timeout is a plain
/// [`PtPauseError::TimedOut`] with nothing to roll back.
fn begin_pt_pause(
    barrier: &crate::fork_quiesce::PtQuiesce,
    tid: ThreadId,
    budget: PtPauseBudget,
) -> Result<(), PtPauseError> {
    // Serialize editors: at most one stop-the-world at a time. A loser parks
    // (if the winner has raised quiescing) or yields (tiny pre-flag window),
    // then retries. This stays independent of the fork/topology lock.
    let election_start = Instant::now();
    let election_deadline = election_start + budget.election;
    loop {
        if barrier.try_become_coordinator() {
            break;
        }
        // Give up only from the LOSER side, and only before taking anything:
        // no coordinator flag, no `quiescing`, so there is nothing to roll
        // back and — critically — no `barrier.end()`, which from here would
        // clear the live coordinator's state and let it edit unpaused tables.
        if barrier.is_quiescing() {
            if !barrier.park_until(election_deadline) {
                crate::probes::pt_pause_election_timeout(
                    tid.raw(),
                    election_start.elapsed().as_micros() as i64,
                );
                return Err(PtPauseError::TimedOut);
            }
        } else {
            if Instant::now() >= election_deadline {
                crate::probes::pt_pause_election_timeout(
                    tid.raw(),
                    election_start.elapsed().as_micros() as i64,
                );
                return Err(PtPauseError::TimedOut);
            }
            std::thread::yield_now();
        }
    }
    barrier.set_quiescing();
    Ok(())
}

/// Raise a page-table pause WITHOUT draining or taking a guard — test-only.
///
/// This is [`begin_pt_pause`]'s half-protocol deliberately exposed, for the one
/// assertion that needs the raised-but-not-yet-drained state as its setup: the
/// carrier's `raised_pt_pause_denies_guest_reentry_until_guard_releases` proves
/// an executor cannot re-enter guest while `quiescing` is up, which is exactly
/// the window a real pause passes through before its guard exists. The caller
/// owns `barrier.end()`; production code must use a complete protocol
/// ([`acquire_mm_stage1_authority`], [`acquire_frame_cow_quiesce`]) instead.
#[cfg(any(test, feature = "test-support"))]
pub fn raise_pt_pause_for_test(
    barrier: &crate::fork_quiesce::PtQuiesce,
    tid: ThreadId,
    budget: PtPauseBudget,
) -> Result<(), PtPauseError> {
    begin_pt_pause(barrier, tid, budget)
}

/// Kick every other vCPU running the exact MM out of guest and wait for each
/// one's acknowledgement, then mint the guard.
///
/// `residents` was taken after the fence was raised, so a vCPU that installs
/// the MM later sees the fence before it can enter the guest and is not
/// waited for (`crate::kernel::mm_occupancy`). Each round reads the wake
/// generation, then re-takes a watch on every resident (an executor may
/// register its vCPU mid-drain, onto a cell the previous round could not
/// watch), then reads the predicate, so no leave or registration can fall
/// between the check and the sleep.
fn drain_exact_mm<'mm>(
    barrier: &Arc<crate::fork_quiesce::PtQuiesce>,
    mm: crate::kernel::MmId,
    mutation_coordinator: Option<Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>>,
    residents: crate::kernel::mm_occupancy::MmResidents,
    tid: ThreadId,
) -> PtPauseGuard<'mm> {
    crate::probes::pt_pause_begin(
        tid.raw(),
        i32::from(residents.any_in_guest()),
        residents.first_in_guest_tid().map_or(0, ThreadId::raw),
        i32::try_from(residents.len()).unwrap_or(i32::MAX),
    );

    let start = Instant::now();
    let wake = carrick_hal::GuestLeaveWake::new();
    residents.kick_all_in_guest();
    let mut rounds: i32 = 0;
    loop {
        // Generation first, then fresh watches, then the predicate: any
        // leave, registration or removal after `seen` bumps the generation,
        // and anything before it is visible to the watches or the read.
        let seen = wake.generation();
        let _watches = residents.watch_leaves(&wake);
        if !residents.any_in_guest() {
            break;
        }
        if rounds == 0 {
            for sibling in residents.in_guest_tids() {
                crate::probes::pt_pause_drain_wait(
                    tid.raw(),
                    sibling.raw(),
                    start.elapsed().as_micros() as i64,
                );
            }
        }
        rounds = rounds.saturating_add(1);
        wake.wait_past(seen);
    }
    crate::probes::pt_pause_ready(tid.raw(), rounds, start.elapsed().as_micros() as i64);
    PtPauseGuard::new(
        mm,
        mutation_coordinator,
        residents,
        barrier.pause_guard(tid),
    )
}

/// A non-blocking drain for single-thread test fixtures whose only "sibling"
/// is native code the same thread must run to its checkpoint: report whether
/// the drain would have to wait instead of waiting. Production has no such
/// arm; it always waits for acknowledgement.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtPauseTryError {
    Pause(PtPauseError),
    SiblingInGuest,
}

#[cfg(any(test, feature = "test-support"))]
fn try_drain_exact_mm<'mm>(
    barrier: &Arc<crate::fork_quiesce::PtQuiesce>,
    mm: crate::kernel::MmId,
    mutation_coordinator: Option<Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>>,
    residents: crate::kernel::mm_occupancy::MmResidents,
    tid: ThreadId,
) -> Result<PtPauseGuard<'mm>, PtPauseTryError> {
    residents.kick_all_in_guest();
    if residents.any_in_guest() {
        barrier.end();
        return Err(PtPauseTryError::SiblingInGuest);
    }
    Ok(PtPauseGuard::new(
        mm,
        mutation_coordinator,
        residents,
        barrier.pause_guard(tid),
    ))
}

/// A real pause of `mm` under `barrier`: every vCPU running it but `own`
/// is kicked and drained, and none can start running it until the guard
/// drops. For host readers that need the MM still (crash capture) as well
/// as editors.
pub(crate) fn pause_exact_mm<'mm>(
    barrier: &Arc<crate::fork_quiesce::PtQuiesce>,
    mm: crate::kernel::MmId,
    own: Option<crate::kernel::ExecutionSlot>,
    tid: ThreadId,
    budget: PtPauseBudget,
) -> Result<PtPauseGuard<'mm>, PtPauseError> {
    begin_pt_pause(barrier, tid, budget)?;
    let residents = crate::kernel::mm_occupancy::residents(mm, barrier, own);
    Ok(drain_exact_mm(barrier, mm, None, residents, tid))
}

/// A real pause of `mm` under `barrier`, by an editor that occupies no slot
/// (every occupant is drained).
#[cfg(any(test, feature = "test-support"))]
pub fn acquire_pt_pause<'mm>(
    barrier: &Arc<crate::fork_quiesce::PtQuiesce>,
    mm: crate::kernel::MmId,
    tid: ThreadId,
    budget: PtPauseBudget,
) -> Result<PtPauseGuard<'mm>, PtPauseError> {
    pause_exact_mm(barrier, mm, None, tid, budget)
}

/// [`acquire_pt_pause`] for a fixture whose in-guest sibling is driven by the
/// calling thread itself: fail instead of waiting.
#[cfg(any(test, feature = "test-support"))]
pub fn try_acquire_pt_pause_for_test<'mm>(
    barrier: &Arc<crate::fork_quiesce::PtQuiesce>,
    mm: crate::kernel::MmId,
    tid: ThreadId,
    budget: PtPauseBudget,
) -> Result<PtPauseGuard<'mm>, PtPauseTryError> {
    begin_pt_pause(barrier, tid, budget).map_err(PtPauseTryError::Pause)?;
    let residents = crate::kernel::mm_occupancy::residents(mm, barrier, None);
    try_drain_exact_mm(barrier, mm, None, residents, tid)
}

// Test fixture reachable through `test-support`, so `cfg(test)` is not set
// for it and clippy's `allow-{unwrap,expect}-in-tests` does not apply.
#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::expect_used, clippy::unwrap_used)]
pub fn with_real_pt_pause_for_test<T>(
    coordinator: Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>,
    run: impl FnOnce(&mut PtPauseGuard<'_>) -> T,
) -> T {
    let barrier = Arc::new(crate::fork_quiesce::PtQuiesce::new());
    let tid = ThreadId::synthetic_for_tests(20_900);
    begin_pt_pause(&barrier, tid, PtPauseBudget::DEFAULT)
        .expect("test must elect a real page-table pause");
    let mm = coordinator.mm();
    let residents = crate::kernel::mm_occupancy::residents(mm, &barrier, None);
    let mut authority = drain_exact_mm(&barrier, mm, Some(coordinator), residents, tid);
    run(&mut authority)
}

#[allow(dead_code)] // Foreign variants are consumed by the canonical Task 8 syscall path.
pub enum FrameCowExactMmGuard {
    /// This host thread already holds a pause of the MM.
    Nested {
        _lease: std::rc::Rc<ExactMmStage1Lease>,
        mutation_coordinator: Option<Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>>,
        foreign_stage1: Option<Arc<dyn Stage1MmProjection>>,
    },
    /// A pause of the MM that drained nothing: no other vCPU was in guest
    /// running it (for a foreign target: none ran it at all).
    Sole {
        _guard: PtPauseGuard<'static>,
        mutation_coordinator: Option<Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>>,
        foreign_stage1: Option<Arc<dyn Stage1MmProjection>>,
    },
    /// A pause that kicked and drained the vCPUs running the MM.
    Paused {
        _guard: PtPauseGuard<'static>,
        foreign_stage1: Option<Arc<dyn Stage1MmProjection>>,
    },
}

impl FrameCowExactMmGuard {
    fn exact_mm(&self) -> crate::kernel::MmId {
        match self {
            Self::Nested { _lease, .. } => _lease.mm,
            Self::Sole { _guard, .. } | Self::Paused { _guard, .. } => _guard._lease.mm,
        }
    }

    #[allow(dead_code)] // Canonical process_vm consumer lands in Task 8.
    pub(crate) fn mutation_identity(
        &self,
    ) -> Option<(
        Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>,
        crate::kernel::MmId,
    )> {
        match self {
            Self::Nested {
                _lease,
                mutation_coordinator,
                ..
            } => mutation_coordinator
                .as_ref()
                .map(|coordinator| (Arc::clone(coordinator), _lease.mm)),
            Self::Sole {
                _guard,
                mutation_coordinator,
                ..
            } => mutation_coordinator
                .as_ref()
                .map(|coordinator| (Arc::clone(coordinator), _guard._lease.mm)),
            Self::Paused { _guard, .. } => _guard.mutation_identity(),
        }
    }

    pub(crate) fn publish_foreign_cow_invalidation(
        &mut self,
        expected_binding: carrick_hal::ForeignMmBinding,
        deadline: Instant,
    ) -> Result<(), ForeignCowInvalidationError> {
        let exact_mm = self.exact_mm();
        let stage1 = match self {
            Self::Nested { foreign_stage1, .. }
            | Self::Sole { foreign_stage1, .. }
            | Self::Paused { foreign_stage1, .. } => foreign_stage1
                .as_ref()
                .ok_or(ForeignCowInvalidationError::MissingStage1Lease)?,
        };
        if stage1.foreign_mm_binding() != expected_binding {
            return Err(ForeignCowInvalidationError::BindingMismatch);
        }
        let generation = stage1.publish_foreign_cow_invalidation();
        let identity = carrick_hal::ForeignCowInvalidationIdentity::new(
            stage1.foreign_stage1_identity(carrick_hal::ForeignMmId::from_kernel_allocation(
                exact_mm.nonzero(),
            )),
            generation,
        );
        let Self::Paused { _guard, .. } = self else {
            return Ok(());
        };
        let lease = &_guard._lease;
        let phase = lease
            .inner
            .publish_exact_invalidation(identity, lease.residents.hardware_invalidation_tids())
            .map_err(ForeignCowInvalidationError::Pause)?;
        let result = lease.inner.wait_invalidation(&phase, deadline);
        lease
            .inner
            .finish_invalidation(&phase)
            .map_err(ForeignCowInvalidationError::Pause)?;
        result.map_err(ForeignCowInvalidationError::Pause)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ForeignCowInvalidationError {
    #[error("foreign COW mutation has no exact stage-1 lease")]
    MissingStage1Lease,
    #[error("foreign COW mutation with active target executors has no pause")]
    MissingPause,
    #[error("foreign COW invalidation binding does not match the exact stage-1 lease")]
    BindingMismatch,
    #[error("foreign COW exact-ASID invalidation failed: {0}")]
    Pause(#[from] crate::fork_quiesce::PtInvalidationError),
}

/// Stage-1 authority for a frame-COW edit of `mm`: the pause this thread
/// already holds, or a new one. A vCPU of the MM stopped at an exit need not
/// be drained (the raised fence keeps it out of the guest), so the pause is
/// `Sole` when none is in guest.
pub fn acquire_frame_cow_quiesce(
    barrier: &Arc<crate::fork_quiesce::PtQuiesce>,
    mm: crate::kernel::MmId,
    tid: ThreadId,
    budget: PtPauseBudget,
) -> Result<FrameCowExactMmGuard, PtPauseError> {
    if let Some(lease) = borrow_current_exact_mm_stage1(mm) {
        return Ok(FrameCowExactMmGuard::Nested {
            _lease: lease,
            mutation_coordinator: None,
            foreign_stage1: None,
        });
    }
    begin_pt_pause(barrier, tid, budget)?;
    let residents = crate::kernel::mm_occupancy::residents(mm, barrier, None);
    if !residents.any_in_guest() {
        return Ok(FrameCowExactMmGuard::Sole {
            _guard: PtPauseGuard::new(mm, None, residents, barrier.pause_guard(tid)),
            mutation_coordinator: None,
            foreign_stage1: None,
        });
    }
    Ok(FrameCowExactMmGuard::Paused {
        _guard: drain_exact_mm(barrier, mm, None, residents, tid),
        foreign_stage1: None,
    })
}

/// Stage-1 authority for a foreign-MM edit (the caller runs another MM).
/// `Sole` only when no vCPU runs the target at all: a resident target vCPU
/// must acknowledge the exact-ASID invalidation phase.
#[allow(dead_code)] // Canonical process_vm consumer lands in Task 8.
pub(crate) fn acquire_foreign_mm_mutation_quiesce(
    barrier: &Arc<crate::fork_quiesce::PtQuiesce>,
    mm: crate::kernel::MmId,
    coordinator: Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>,
    stage1: Arc<dyn Stage1MmProjection>,
    tid: ThreadId,
    budget: PtPauseBudget,
) -> Result<FrameCowExactMmGuard, PtPauseError> {
    if let Some(lease) = borrow_current_exact_mm_stage1(mm) {
        return Ok(FrameCowExactMmGuard::Nested {
            _lease: lease,
            mutation_coordinator: Some(coordinator),
            foreign_stage1: Some(stage1),
        });
    }
    begin_pt_pause(barrier, tid, budget)?;
    let residents = crate::kernel::mm_occupancy::residents(mm, barrier, None);
    if residents.is_empty() {
        return Ok(FrameCowExactMmGuard::Sole {
            _guard: PtPauseGuard::new(mm, None, residents, barrier.pause_guard(tid)),
            mutation_coordinator: Some(coordinator),
            foreign_stage1: Some(stage1),
        });
    }
    Ok(FrameCowExactMmGuard::Paused {
        _guard: drain_exact_mm(barrier, mm, Some(coordinator), residents, tid),
        foreign_stage1: Some(stage1),
    })
}

#[cfg(any(test, feature = "test-support"))]
pub fn acquire_mutation_pause_for_test<'mm>(
    barrier: &Arc<crate::fork_quiesce::PtQuiesce>,
    tid: ThreadId,
    mm: crate::kernel::MmId,
    coordinator: Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>,
    budget: PtPauseBudget,
) -> Result<PtPauseGuard<'mm>, PtPauseError> {
    begin_pt_pause(barrier, tid, budget)?;
    let residents = crate::kernel::mm_occupancy::residents(mm, barrier, None);
    Ok(drain_exact_mm(
        barrier,
        mm,
        Some(coordinator),
        residents,
        tid,
    ))
}

/// [`acquire_mutation_pause_for_test`] for a fixture whose in-guest sibling is
/// driven by the calling thread itself: fail instead of waiting.
#[cfg(any(test, feature = "test-support"))]
pub fn try_acquire_mutation_pause_for_test<'mm>(
    barrier: &Arc<crate::fork_quiesce::PtQuiesce>,
    tid: ThreadId,
    mm: crate::kernel::MmId,
    coordinator: Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>,
    budget: PtPauseBudget,
) -> Result<PtPauseGuard<'mm>, PtPauseTryError> {
    begin_pt_pause(barrier, tid, budget).map_err(PtPauseTryError::Pause)?;
    let residents = crate::kernel::mm_occupancy::residents(mm, barrier, None);
    try_drain_exact_mm(barrier, mm, Some(coordinator), residents, tid)
}
