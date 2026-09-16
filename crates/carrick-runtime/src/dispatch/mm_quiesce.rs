//! Exact-mm stage-1 quiesce: the authority a page-table edit holds while it
//! runs, and how dispatch and the carrier obtain it.
//!
//! Every stage-1 mutation of one Linux process's address space runs under
//! exactly one of three proofs that no other executor can observe the tables
//! mid-edit:
//!
//! - [`SoleMmStage1`]: the exact-MM census counted one executor and the
//!   election stays locked until drop, so nothing can enter behind the proof;
//! - [`PtPauseGuard`]: a Pause-Modify-Resume over the process-wide
//!   [`crate::fork_quiesce::PtQuiesce`] barrier that kicked and drained every
//!   peer out of guest;
//! - [`FrameCowExactMmGuard`]: the frame-COW variant, which may instead
//!   borrow the pause this host thread already holds (the `EXACT_MM_STAGE1`
//!   thread-local is only that lookup; authority is the upgraded lease).
//!
//! `dispatch::mm_mutation` seals each proof into an `MmMutationGuard`; the
//! carrier takes [`acquire_mm_stage1_authority`] before a fork/exec install.
//! The protocol names the kernel census, the dispatch coordinator and the
//! `carrick_thread` barrier only; no VMM type appears here, which is what
//! lets the dispatcher unit tests take the sole-executor arm with no carrier.

use std::sync::Arc;
use std::time::{Duration, Instant};

use carrick_fatal::carrick_fatal;
use carrick_hal::ThreadId;
use carrick_hal::stage1_mm::Stage1MmProjection;

thread_local! {
    /// Exact live stage-1 leases on this vCPU service thread. The weak entry is
    /// only a lookup path for synchronous backend re-entry; authority is the
    /// upgraded, exact-MM `Rc<ExactMmStage1Lease>`, which owns the real census
    /// election or pause and therefore remains valid even if the outer wrapper
    /// is dropped first. A boolean/thread-local observation is never accepted.
    static EXACT_MM_STAGE1: std::cell::RefCell<Vec<(crate::kernel::MmId, std::rc::Weak<ExactMmStage1Lease>)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Enter sole-executor stage-1 authority only from an exact-MM census token.
/// Normalized handlers receive no such token.
pub(crate) fn with_sole_mm_stage1<T>(
    participation: &mut crate::dispatch::MmExecutorParticipation,
    run: impl FnOnce(&mut SoleMmStage1<'_>) -> T,
) -> Option<T> {
    let mut authority = SoleMmStage1::claim(participation)?;
    Some(run(&mut authority))
}

/// Holds this thread's stage-1 exclusivity claim for a mapping syscall's whole
/// dispatch. Separate from [`PtPauseGuard`] because exclusivity has two
/// sources: the pause (which raises the same marker, so the two nest harmlessly
/// when both apply) and simply having no peer that can execute guest code.
pub(crate) struct Stage1Exclusive {
    _private: (),
}

enum ExactMmStage1LeaseKind {
    Sole {
        // Drop the engine-visible marker before releasing census admission.
        _stage1: Stage1Exclusive,
        _census: crate::kernel::ExactMmCensusGuard,
    },
    Paused {
        // Drop the marker before the barrier guard resumes peer vCPUs.
        _stage1: Stage1Exclusive,
        _inner: crate::fork_quiesce::PtPauseGuard,
        _census: crate::kernel::ExactMmCensusGuard,
    },
}

/// Shareable only within the current host service thread. A nested frame-COW
/// borrow clones this exact lease rather than trusting ambient thread state.
pub(crate) struct ExactMmStage1Lease {
    mm: crate::kernel::MmId,
    _kind: ExactMmStage1LeaseKind,
    _not_send_or_sync: std::marker::PhantomData<std::rc::Rc<()>>,
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

#[cfg(test)]
pub(crate) fn current_thread_holds_pt_pause() -> bool {
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

/// Stage-1 authority for one executor proven sole in the exact MM census.
///
/// The census election stays locked until drop, preventing a CLONE_VM peer
/// dispatcher from entering after the proof is minted.
pub(crate) struct SoleMmStage1<'participant> {
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
        let census = participation.participation_mut().lock_exact_mm();
        if census.participant_count() != 1 {
            return None;
        }
        let lease = std::rc::Rc::new(ExactMmStage1Lease {
            mm,
            _kind: ExactMmStage1LeaseKind::Sole {
                _stage1: Stage1Exclusive::claim(),
                _census: census,
            },
            _not_send_or_sync: std::marker::PhantomData,
        });
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

pub(crate) enum MmStage1Authority<'participant> {
    Sole(SoleMmStage1<'participant>),
    Paused(PtPauseGuard<'participant>),
}

pub(crate) fn acquire_mm_stage1_authority<'participant>(
    participation: &'participant mut crate::dispatch::MmExecutorParticipation,
    tid: ThreadId,
    budget: PtPauseBudget,
) -> Result<MmStage1Authority<'participant>, PtPauseError> {
    let mm = participation.mm_id();
    let coordinator = participation.mutation_coordinator();
    let census = participation.participation_mut().lock_exact_mm();
    if census.participant_count() == 1 {
        let lease = std::rc::Rc::new(ExactMmStage1Lease {
            mm,
            _kind: ExactMmStage1LeaseKind::Sole {
                _stage1: Stage1Exclusive::claim(),
                _census: census,
            },
            _not_send_or_sync: std::marker::PhantomData,
        });
        return Ok(MmStage1Authority::Sole(SoleMmStage1 {
            _scope: ExactMmStage1Scope::enter(&lease),
            _lease: lease,
            _linear: std::marker::PhantomData,
            mm,
            coordinator,
        }));
    }
    drop(census);
    let pt_quiesce = Arc::clone(participation.pt_quiesce());
    begin_pt_pause(&pt_quiesce, tid, budget)?;
    let census = participation.participation_mut().lock_exact_mm();
    drain_exact_mm(&pt_quiesce, mm, Some(coordinator), census, tid, budget)
        .map(MmStage1Authority::Paused)
}

pub(crate) struct PtPauseGuard<'mm> {
    _scope: ExactMmStage1Scope,
    _lease: std::rc::Rc<ExactMmStage1Lease>,
    mutation_coordinator: Option<Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>>,
    _authority: std::marker::PhantomData<&'mm mut ()>,
}

impl<'mm> PtPauseGuard<'mm> {
    fn new(
        mm: crate::kernel::MmId,
        mutation_coordinator: Option<Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>>,
        census: crate::kernel::ExactMmCensusGuard,
        inner: crate::fork_quiesce::PtPauseGuard,
    ) -> Self {
        let lease = std::rc::Rc::new(ExactMmStage1Lease {
            mm,
            _kind: ExactMmStage1LeaseKind::Paused {
                _stage1: Stage1Exclusive::claim(),
                _inner: inner,
                _census: census,
            },
            _not_send_or_sync: std::marker::PhantomData,
        });
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
}

/// Process-wide page-table-edit Pause-Modify-Resume barrier.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn pt_barrier() -> &'static Arc<crate::fork_quiesce::PtQuiesce> {
    crate::fork_quiesce::pt_barrier()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PtPauseError {
    TimedOut,
    UnkickableExecutor,
}

/// The two independent budgets in a page-table pause.
///
/// Named rather than passed as two adjacent `Duration`s because they mean
/// opposite things and swapping them is silent: the election would get 500 ms
/// (spurious `ENOMEM` the moment two threads `mmap` at once) and the drain 30 s
/// (one stalled sibling freezing the VM for half a minute).
#[derive(Debug, Clone, Copy)]
pub(crate) struct PtPauseBudget {
    /// Wait for the CURRENT coordinator to finish, before we hold anything.
    ///
    /// Far larger than `drain`, and deliberately not shared with it: charging a
    /// loser for the winner's whole editing syscall would turn honest
    /// multi-threaded `mmap` contention into spurious `ENOMEM` — trading a rare
    /// wedge for a common correctness bug. Real contention resolves in low
    /// milliseconds (a loser waits out one page-table edit), so a wait this long
    /// is not contention: the coordinator is blocked on something the waiter
    /// holds. That was a live deadlock — the host-alias/pt-pause ABBA — and the
    /// class survives its fix, since any syscall that takes the host-alias phase
    /// and then triggers frame COW can rebuild it. Bounding here makes the next
    /// instance a named `pt__pause__election__timeout` and a guest `ENOMEM`
    /// instead of a silent, unrecoverable carrier stop.
    pub(crate) election: Duration,
    /// Wait for siblings to leave guest once WE are the coordinator.
    pub(crate) drain: Duration,
}

impl PtPauseBudget {
    pub(crate) const DEFAULT: Self = Self {
        election: Duration::from_secs(30),
        drain: Duration::from_millis(500),
    };
}

/// Pure mapper from [`carrick_hal::VcpuLeaseDrainPoll`] to diagnostic thread ID.
///
/// Maps [`carrick_hal::VcpuLeaseDrainPoll::Complete`] to 0 and
/// [`carrick_hal::VcpuLeaseDrainPoll::Waiting`] to its exact raw `ThreadId`.
/// Acquire and hold exact-MM admission while every registered participant is
/// kicked and observed out of guest across all process-local registries.
pub(crate) fn begin_pt_pause(
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

fn drain_exact_mm<'mm>(
    barrier: &Arc<crate::fork_quiesce::PtQuiesce>,
    mm: crate::kernel::MmId,
    mutation_coordinator: Option<Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>>,
    census: crate::kernel::ExactMmCensusGuard,
    tid: ThreadId,
    budget: PtPauseBudget,
) -> Result<PtPauseGuard<'mm>, PtPauseError> {
    if !census.all_have_pause_endpoints() {
        barrier.end();
        return Err(PtPauseError::UnkickableExecutor);
    }
    crate::probes::pt_pause_begin(
        tid.raw(),
        i32::from(census.any_in_guest()),
        census.first_in_guest_tid().map_or(0, ThreadId::raw),
        i32::try_from(census.participant_count()).unwrap_or(i32::MAX),
    );

    let start = Instant::now();
    let deadline = start + budget.drain;
    let mut spins: i32 = 0;
    while census.any_in_guest() {
        census.kick_all_in_guest();
        if Instant::now() >= deadline {
            crate::probes::pt_pause_timeout(tid.raw(), start.elapsed().as_micros() as i64);
            // Roll back BOTH persistent request bits and wake every sibling that
            // already parked. Returning a guard while the predicate is still
            // true would let the caller edit live page tables.
            barrier.end();
            return Err(PtPauseError::TimedOut);
        }
        spins = spins.saturating_add(1);
        std::thread::yield_now();
    }
    crate::probes::pt_pause_ready(tid.raw(), spins, start.elapsed().as_micros() as i64);
    Ok(PtPauseGuard::new(
        mm,
        mutation_coordinator,
        census,
        barrier.pause_guard(tid),
    ))
}

#[cfg(test)]
pub(crate) fn acquire_pt_pause<'participant>(
    barrier: &Arc<crate::fork_quiesce::PtQuiesce>,
    participation: &'participant mut crate::kernel::GuestExecutorParticipation,
    tid: ThreadId,
    budget: PtPauseBudget,
) -> Result<PtPauseGuard<'participant>, PtPauseError> {
    begin_pt_pause(barrier, tid, budget)?;
    let mm = crate::kernel::MmId::from_registry_allocation(
        std::num::NonZeroU64::new(tid.raw() as u64)
            .unwrap_or_else(|| std::num::NonZeroU64::new(1).unwrap()),
    );
    let census = participation.lock_exact_mm();
    drain_exact_mm(barrier, mm, None, census, tid, budget)
}

#[cfg(test)]
pub(crate) fn with_real_pt_pause_for_test<T>(
    coordinator: Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>,
    run: impl FnOnce(&mut PtPauseGuard<'_>) -> T,
) -> T {
    let barrier = Arc::new(crate::fork_quiesce::PtQuiesce::new());
    let registry: Arc<dyn carrick_hal::VcpuRegistry> =
        Arc::new(carrick_hal::GenericVcpuRegistry::new());
    let census = Arc::new(crate::kernel::GuestExecutorCensus::default());
    let tid = ThreadId::synthetic_for_tests(20_900);
    let mut participation = census
        .enter_with_pause_endpoint(None, registry, tid)
        .expect("test exact-MM participation");
    begin_pt_pause(&barrier, tid, PtPauseBudget::DEFAULT)
        .expect("test must elect a real page-table pause");
    let mm = coordinator.mm();
    let census = participation.lock_exact_mm();
    let mut authority = drain_exact_mm(
        &barrier,
        mm,
        Some(coordinator),
        census,
        tid,
        PtPauseBudget::DEFAULT,
    )
    .expect("test must acquire a real page-table pause");
    run(&mut authority)
}

#[allow(dead_code)] // Foreign variants are consumed by the canonical Task 8 syscall path.
pub(crate) enum FrameCowExactMmGuard {
    Nested {
        _lease: std::rc::Rc<ExactMmStage1Lease>,
        mutation_coordinator: Option<Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>>,
        foreign_stage1: Option<Arc<dyn Stage1MmProjection>>,
    },
    Sole {
        _stage1: Stage1Exclusive,
        _census: crate::kernel::ExactMmCensusGuard,
        mm: crate::kernel::MmId,
        mutation_coordinator: Option<Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>>,
        foreign_stage1: Option<Arc<dyn Stage1MmProjection>>,
    },
    Paused {
        _guard: PtPauseGuard<'static>,
        foreign_stage1: Option<Arc<dyn Stage1MmProjection>>,
    },
}

impl FrameCowExactMmGuard {
    fn exact_mm(&self) -> crate::kernel::MmId {
        match self {
            Self::Nested { _lease, .. } => _lease.mm,
            Self::Sole { mm, .. } => *mm,
            Self::Paused { _guard, .. } => _guard._lease.mm,
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
                mm,
                mutation_coordinator,
                ..
            } => mutation_coordinator
                .as_ref()
                .map(|coordinator| (Arc::clone(coordinator), *mm)),
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
        let (inner, expected) = match &_guard._lease._kind {
            ExactMmStage1LeaseKind::Paused {
                _inner, _census, ..
            } => (_inner, _census.pause_endpoint_tids()),
            ExactMmStage1LeaseKind::Sole { .. } => {
                return Err(ForeignCowInvalidationError::MissingPause);
            }
        };
        let phase = inner
            .publish_exact_invalidation(identity, expected)
            .map_err(ForeignCowInvalidationError::Pause)?;
        let result = inner.wait_invalidation(&phase, deadline);
        inner
            .finish_invalidation(&phase)
            .map_err(ForeignCowInvalidationError::Pause)?;
        result.map_err(ForeignCowInvalidationError::Pause)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ForeignCowInvalidationError {
    #[error("foreign COW mutation has no exact stage-1 lease")]
    MissingStage1Lease,
    #[error("foreign COW mutation with active target executors has no pause")]
    MissingPause,
    #[error("foreign COW invalidation binding does not match the exact stage-1 lease")]
    BindingMismatch,
    #[error("foreign COW exact-ASID invalidation failed: {0}")]
    Pause(#[from] crate::fork_quiesce::PtInvalidationError),
}

pub(crate) fn acquire_frame_cow_quiesce(
    barrier: &Arc<crate::fork_quiesce::PtQuiesce>,
    mm: crate::kernel::MmId,
    census: &crate::kernel::GuestExecutorCensus,
    tid: ThreadId,
    budget: PtPauseBudget,
) -> Result<FrameCowExactMmGuard, PtPauseError> {
    acquire_frame_cow_quiesce_inner(barrier, mm, census, None, tid, budget)
}

#[allow(dead_code)] // Canonical process_vm consumer lands in Task 8.
pub(crate) fn acquire_foreign_mm_mutation_quiesce(
    barrier: &Arc<crate::fork_quiesce::PtQuiesce>,
    mm: crate::kernel::MmId,
    census: &crate::kernel::GuestExecutorCensus,
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
    let sole = census.lock_for_frame_cow();
    if sole.participant_count() == 0 {
        return Ok(FrameCowExactMmGuard::Sole {
            _stage1: Stage1Exclusive::claim(),
            _census: sole,
            mm,
            mutation_coordinator: Some(coordinator),
            foreign_stage1: Some(stage1),
        });
    }
    drop(sole);
    begin_pt_pause(barrier, tid, budget)?;
    let census = census.lock_for_frame_cow();
    drain_exact_mm(barrier, mm, Some(coordinator), census, tid, budget).map(|guard| {
        FrameCowExactMmGuard::Paused {
            _guard: guard,
            foreign_stage1: Some(stage1),
        }
    })
}

fn acquire_frame_cow_quiesce_inner(
    barrier: &Arc<crate::fork_quiesce::PtQuiesce>,
    mm: crate::kernel::MmId,
    census: &crate::kernel::GuestExecutorCensus,
    mutation_coordinator: Option<Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>>,
    tid: ThreadId,
    budget: PtPauseBudget,
) -> Result<FrameCowExactMmGuard, PtPauseError> {
    if let Some(lease) = borrow_current_exact_mm_stage1(mm) {
        return Ok(FrameCowExactMmGuard::Nested {
            _lease: lease,
            mutation_coordinator,
            foreign_stage1: None,
        });
    }
    let sole = census.lock_for_frame_cow();
    if sole.participant_count() <= 1 && !sole.any_in_guest() {
        return Ok(FrameCowExactMmGuard::Sole {
            _stage1: Stage1Exclusive::claim(),
            _census: sole,
            mm,
            mutation_coordinator,
            foreign_stage1: None,
        });
    }
    drop(sole);
    begin_pt_pause(barrier, tid, budget)?;
    let census = census.lock_for_frame_cow();
    drain_exact_mm(barrier, mm, mutation_coordinator, census, tid, budget).map(|guard| {
        FrameCowExactMmGuard::Paused {
            _guard: guard,
            foreign_stage1: None,
        }
    })
}

#[cfg(test)]
pub(crate) fn acquire_mutation_pause_for_test<'participant>(
    barrier: &Arc<crate::fork_quiesce::PtQuiesce>,
    participation: &'participant mut crate::kernel::GuestExecutorParticipation,
    tid: ThreadId,
    mm: crate::kernel::MmId,
    coordinator: Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>,
    budget: PtPauseBudget,
) -> Result<PtPauseGuard<'participant>, PtPauseError> {
    begin_pt_pause(barrier, tid, budget)?;
    let census = participation.lock_exact_mm();
    drain_exact_mm(barrier, mm, Some(coordinator), census, tid, budget)
}
