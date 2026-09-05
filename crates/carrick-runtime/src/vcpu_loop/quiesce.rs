//! MEM concern: fork / page-table quiesce of the vCPU run loop.
//!
//! Split out of `vcpu_loop/mod.rs` (Task A2). The page-table pause is a
//! transactional typed gate: timeout rolls the request back before dispatch;
//! fork quiesce remains the separate process-topology protocol below.

use super::*;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
enum PreparedHvpatchProcessMm {
    Copied(crate::hvpatch::PreparedStage1Mm),
    Shared {
        parent_task: crate::kernel::TaskKey,
        lease: Arc<crate::hvpatch::Stage1MmLease>,
        /// Admission against the shared generation's exec reservations, held
        /// until `publish_shared_child` so an exec cannot freeze the owner
        /// set between admission and publication.
        hold: crate::hvpatch::OwnerSetEditHold,
    },
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PreparedHvpatchProcessMm {
    fn binding(&self) -> crate::kernel::MmBinding {
        match self {
            Self::Copied(mm) => mm.binding(),
            Self::Shared { lease, .. } => lease.binding(),
        }
    }

    fn asid_generation(&self) -> u64 {
        match self {
            Self::Copied(mm) => mm.asid_generation().generation(),
            Self::Shared { lease, .. } => lease.asid_generation().generation(),
        }
    }
}

fn read_optional_fork_output(
    memory: &impl CurrentMmMemory,
    address: Option<u64>,
) -> Option<Option<Vec<u8>>> {
    match address {
        None => Some(None),
        Some(address) => memory
            .read_bytes(address, std::mem::size_of::<i32>())
            .ok()
            .map(Some),
    }
}

thread_local! {
    /// Exact live stage-1 leases on this vCPU service thread. The weak entry is
    /// only a lookup path for synchronous backend re-entry; authority is the
    /// upgraded, exact-MM `Rc<ExactMmStage1Lease>`, which owns the real census
    /// election or pause and therefore remains valid even if the outer wrapper
    /// is dropped first. A boolean/thread-local observation is never accepted.
    static EXACT_MM_STAGE1: std::cell::RefCell<Vec<(crate::kernel::MmId, std::rc::Weak<ExactMmStage1Lease>)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Publish guest entry and re-check the page-table pause before crossing into
/// the engine. Together with the coordinator's SeqCst `quiescing` publication
/// and exact in-guest reads, this is the other half of the Dekker handshake:
/// either the executor observes the pause and parks, or the coordinator
/// observes the executor and kicks/drains it before editing.
#[cfg_attr(all(target_os = "macos", target_arch = "aarch64"), allow(dead_code))]
pub(super) fn enter_guest_or_park(
    in_guest: &carrick_hal::InGuestFlag,
    barrier: &'static crate::fork_quiesce::PtQuiesce,
) -> bool {
    in_guest.enter_guest();
    if !barrier.is_quiescing() {
        return true;
    }
    in_guest.leave_guest();
    barrier.park();
    false
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn enter_hvpatch_guest_or_service_invalidation(
    in_guest: &carrick_hal::InGuestFlag,
    barrier: &'static crate::fork_quiesce::PtQuiesce,
    tid: carrick_hal::ThreadId,
    engine: &mut dyn std::any::Any,
    control: &crate::vcpu_loop::executor::HvpatchQuantumControl<'_, '_>,
) -> Result<bool, carrick_hal::TrapError> {
    enter_hvpatch_guest_or_service_invalidation_inner(
        in_guest,
        barrier,
        tid,
        control.cow_invalidation_binding(),
        |asid| {
            let engine = engine
                .downcast_mut::<carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Engine>()
                .ok_or_else(|| {
                    carrick_hal::TrapError::Hypervisor(
                        "foreign COW invalidation reached a non-HVF owner engine".to_owned(),
                    )
                })?;
            carrick_vmm_hvf::hvf_aarch64_engine::invalidate_loaded_asid(engine, asid)
        },
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn enter_hvpatch_guest_or_service_invalidation_inner(
    in_guest: &carrick_hal::InGuestFlag,
    barrier: &'static crate::fork_quiesce::PtQuiesce,
    tid: carrick_hal::ThreadId,
    cow_binding: Option<(
        crate::kernel::objects::ExecutorId,
        &Arc<crate::vcpu_loop::continuation::HvpatchTaskBinding>,
        &crate::hvpatch::CowInvalidationObserver,
    )>,
    mut invalidate: impl FnMut(u16) -> Result<(), carrick_hal::TrapError>,
) -> Result<bool, carrick_hal::TrapError> {
    in_guest.enter_guest();
    // A resident executor can have been inactive when a foreign COW was
    // published, so task-load service alone is insufficient. Marking in_guest
    // first closes the race with a new pause: a coordinator must now drain us
    // before it can edit/publish, while an older deferred generation can be
    // serviced immediately on this exact loaded owner vCPU.
    if !barrier.is_quiescing() {
        if let Some((_executor, binding, observer)) = cow_binding {
            binding.service_pending_cow_invalidation(observer, |generation| {
                invalidate(generation.raw())
            })?;
        } else {
            #[cfg(not(test))]
            return Err(carrick_hal::TrapError::Hypervisor(
                "HVPatch guest entry lacks exact executor/MM invalidation binding".to_owned(),
            ));
        }
        if !barrier.is_quiescing() {
            return Ok(true);
        }
    }
    in_guest.leave_guest();
    let (executor, binding, _observer) = cow_binding.ok_or_else(|| {
        carrick_hal::TrapError::Hypervisor(
            "quiesced HVPatch executor lacks exact invalidation binding".to_owned(),
        )
    })?;
    let identity = binding.foreign_stage1_identity();
    let mut failure = None;
    barrier.park_servicing_exact_invalidation(identity, tid, |request| {
        let result = (|| {
            if request.identity().stage1() != identity {
                return Err(carrick_hal::TrapError::Hypervisor(
                    "foreign COW invalidation named another MM/ASID generation".to_owned(),
                ));
            }
            let ticket = binding.pending_cow_invalidation(executor).ok_or_else(|| {
                carrick_hal::TrapError::Hypervisor(
                    "active target executor lacked its foreign COW invalidation ticket".to_owned(),
                )
            })?;
            let ticket_identity =
                carrick_hal::ForeignCowInvalidationIdentity::new(identity, ticket.generation());
            if ticket_identity != request.identity() {
                return Err(carrick_hal::TrapError::Hypervisor(
                    "active target executor observed a stale foreign COW invalidation phase"
                        .to_owned(),
                ));
            }
            invalidate(request.identity().stage1().binding().asid().raw_for_probe())?;
            binding
                .acknowledge_cow_invalidation(executor, ticket)
                .map_err(|error| carrick_hal::TrapError::Hypervisor(error.to_string()))
        })();
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                failure = Some(error);
                Err(())
            }
        }
    });
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(false)
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn enter_hvpatch_guest_or_service_invalidation_for_test(
    in_guest: &carrick_hal::InGuestFlag,
    tid: carrick_hal::ThreadId,
    executor: crate::kernel::objects::ExecutorId,
    binding: &Arc<crate::vcpu_loop::continuation::HvpatchTaskBinding>,
    observer: &crate::hvpatch::CowInvalidationObserver,
    invalidate: impl FnMut(u16) -> Result<(), carrick_hal::TrapError>,
) -> Result<bool, carrick_hal::TrapError> {
    enter_hvpatch_guest_or_service_invalidation_inner(
        in_guest,
        pt_barrier(),
        tid,
        Some((executor, binding, observer)),
        invalidate,
    )
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn foreign_cow_task_binding_for_test(
    stage1: Arc<crate::hvpatch::Stage1MmLease>,
    mm: crate::kernel::MmId,
) -> Result<Arc<crate::vcpu_loop::continuation::HvpatchTaskBinding>, carrick_hal::TrapError> {
    struct ExitJob;

    impl crate::vcpu_loop::continuation::PersistentQuantumJob for ExitJob {
        fn poll_quantum_with_engine(
            &mut self,
            _engine: &mut dyn std::any::Any,
            _control: &mut crate::vcpu_loop::executor::HvpatchQuantumControl<'_, '_>,
        ) -> crate::vcpu_loop::executor::ExecutorExit {
            crate::vcpu_loop::executor::ExecutorExit::Exited
        }
    }

    crate::vcpu_loop::continuation::HvpatchTaskBinding::new_with_stage1_mm(
        crate::vcpu_loop::executor::TaskLoadIdentity {
            abi: carrick_abi::LinuxGuestAbi::Aarch64,
            version: 1,
            mm,
            asid_generation: stage1.asid_generation().generation(),
        },
        Arc::new(crate::vcpu_loop::continuation::HvpatchTaskQuantum::new(
            Box::new(ExitJob),
            crate::vcpu_loop::continuation::LogicalJobCompletion::pending(),
        )),
        Box::new(()),
        stage1,
    )
    .map(Arc::new)
}

#[cfg(test)]
pub(crate) fn foreign_cow_handshake_test_lock() -> parking_lot::MutexGuard<'static, ()> {
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    LOCK.lock()
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
            let (mm, lease) = stack.pop().unwrap_or_else(|| std::process::abort());
            if mm != self.mm || !std::rc::Weak::ptr_eq(&lease, &self.lease) {
                std::process::abort();
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
fn current_thread_holds_pt_pause() -> bool {
    EXACT_MM_STAGE1.with(|stack| {
        stack
            .borrow()
            .iter()
            .any(|(_, lease)| lease.upgrade().is_some())
    })
}

impl Stage1Exclusive {
    pub(super) fn claim() -> Self {
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
    pub(super) fn claim(
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

pub(super) enum MmStage1Authority<'participant> {
    Sole(SoleMmStage1<'participant>),
    Paused(PtPauseGuard<'participant>),
}

pub(super) fn acquire_mm_stage1_authority<'participant>(
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
    begin_pt_pause(pt_barrier(), tid, budget)?;
    let census = participation.participation_mut().lock_exact_mm();
    drain_exact_mm(pt_barrier(), mm, Some(coordinator), census, tid, budget)
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

/// Keeps runtime provenance live while a non-cloneable reservation is owned
/// by the backend. Every pre-publication return abandons the authority record;
/// successful application has already consumed it, making Drop a no-op.
///
/// A slot is `None` when that half of the operation was never reserved — an
/// exec whose old mm stays owned by a live sharer arms no retirement — so the
/// guard covers a partially armed operation without inventing a transaction id.
pub(super) struct InventoryAbandon<'a, const N: usize> {
    authority: &'a crate::kernel::FrameInventoryAuthority,
    transactions: [Option<carrick_hal::KernelTransactionId>; N],
}

impl<'a, const N: usize> InventoryAbandon<'a, N> {
    pub(super) const fn new(
        authority: &'a crate::kernel::FrameInventoryAuthority,
        transactions: [Option<carrick_hal::KernelTransactionId>; N],
    ) -> Self {
        Self {
            authority,
            transactions,
        }
    }
}

impl<const N: usize> Drop for InventoryAbandon<'_, N> {
    fn drop(&mut self) {
        for transaction in self.transactions.into_iter().flatten() {
            self.authority.abandon(transaction);
        }
    }
}

enum ProcessForkStart {
    Busy,
    /// Exec or exit closed admission for good: `EAGAIN`.
    AdmissionClosed,
    /// A sibling process fork's transient close; retry when it lifts.
    AdmissionDeferred {
        observed_epoch: u64,
    },
    Admitted {
        admission: CloneAdmissionPermit,
    },
}

/// Serialize process forks before enrolling the winner in clone admission.
///
/// A losing forker is a registered sibling that the winner must quiesce. It
/// must therefore own no admission permit while it parks behind the process
/// barrier; otherwise the winner's admission drain cancels the loser and leaks
/// an internal arbitration event to Linux as `EAGAIN`.
fn try_begin_hvpatch_process_fork_with_admission(
    barrier: &crate::fork_quiesce::QuiesceBarrier,
    tid: ThreadId,
    admission_gate: &Arc<CloneAdmissionGate>,
) -> ProcessForkStart {
    if !barrier.try_begin_fork() {
        return ProcessForkStart::Busy;
    }
    match admission_gate.enroll_process_fork(tid) {
        CloneEnrollment::Admitted(admission) => ProcessForkStart::Admitted { admission },
        CloneEnrollment::Deferred { observed_epoch } => {
            barrier.end_fork();
            ProcessForkStart::AdmissionDeferred { observed_epoch }
        }
        CloneEnrollment::Refused => {
            barrier.end_fork();
            ProcessForkStart::AdmissionClosed
        }
    }
}

/// Process-wide page-table-edit Pause-Modify-Resume barrier.
pub(crate) fn pt_barrier() -> &'static crate::fork_quiesce::PtQuiesce {
    crate::fork_quiesce::pt_barrier()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PtPauseError {
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
pub(super) struct PtPauseBudget {
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
    election: Duration,
    /// Wait for siblings to leave guest once WE are the coordinator.
    drain: Duration,
}

impl PtPauseBudget {
    pub(super) const DEFAULT: Self = Self {
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
fn begin_pt_pause(
    barrier: &'static crate::fork_quiesce::PtQuiesce,
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
    barrier: &'static crate::fork_quiesce::PtQuiesce,
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
pub(super) fn acquire_pt_pause<'participant>(
    barrier: &'static crate::fork_quiesce::PtQuiesce,
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
pub(super) fn with_real_mutation_pause_for_test<T>(
    coordinator: Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>,
    run: impl FnOnce(&mut PtPauseGuard<'_>) -> T,
) -> T {
    let barrier: &'static crate::fork_quiesce::PtQuiesce =
        Box::leak(Box::new(crate::fork_quiesce::PtQuiesce::new()));
    let registry: Arc<dyn carrick_hal::VcpuRegistry> =
        Arc::new(carrick_hal::GenericVcpuRegistry::new());
    let census = Arc::new(crate::kernel::GuestExecutorCensus::default());
    let tid = ThreadId::synthetic_for_tests(20_900);
    let mut participation = census
        .enter_with_pause_endpoint(None, registry, tid)
        .expect("test exact-MM participation");
    begin_pt_pause(barrier, tid, PtPauseBudget::DEFAULT)
        .expect("test must elect a real page-table pause");
    let mm = coordinator.mm();
    let census = participation.lock_exact_mm();
    let mut authority = drain_exact_mm(
        barrier,
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
        foreign_stage1: Option<Arc<crate::hvpatch::Stage1MmLease>>,
    },
    Sole {
        _stage1: Stage1Exclusive,
        _census: crate::kernel::ExactMmCensusGuard,
        mm: crate::kernel::MmId,
        mutation_coordinator: Option<Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>>,
        foreign_stage1: Option<Arc<crate::hvpatch::Stage1MmLease>>,
    },
    Paused {
        _guard: PtPauseGuard<'static>,
        foreign_stage1: Option<Arc<crate::hvpatch::Stage1MmLease>>,
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
        let binding = stage1.binding();
        if binding.asid.raw() != expected_binding.asid().raw_for_probe()
            || binding.stage1_root.gpa() != expected_binding.stage1_root()
        {
            return Err(ForeignCowInvalidationError::BindingMismatch);
        }
        let publication = stage1.publish_cow_invalidation();
        let identity = carrick_hal::ForeignCowInvalidationIdentity::new(
            stage1.foreign_stage1_identity(exact_mm),
            publication.ticket().generation(),
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

pub(super) fn acquire_frame_cow_quiesce(
    barrier: &'static crate::fork_quiesce::PtQuiesce,
    mm: crate::kernel::MmId,
    census: &crate::kernel::GuestExecutorCensus,
    tid: ThreadId,
    budget: PtPauseBudget,
) -> Result<FrameCowExactMmGuard, PtPauseError> {
    acquire_frame_cow_quiesce_inner(barrier, mm, census, None, tid, budget)
}

#[allow(dead_code)] // Canonical process_vm consumer lands in Task 8.
pub(super) fn acquire_foreign_mm_mutation_quiesce(
    barrier: &'static crate::fork_quiesce::PtQuiesce,
    mm: crate::kernel::MmId,
    census: &crate::kernel::GuestExecutorCensus,
    coordinator: Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>,
    stage1: Arc<crate::hvpatch::Stage1MmLease>,
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
    barrier: &'static crate::fork_quiesce::PtQuiesce,
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

#[derive(Clone, Copy)]
pub(super) struct ForkRequest {
    pub(super) flags: u64,
    pub(super) pidfd_out: Option<u64>,
    pub(super) clone_parent: bool,
    pub(super) parent_tid_addr: Option<u64>,
    pub(super) child_tid_addr: Option<u64>,
    pub(super) exit_signal: u32,
    pub(super) child_stack: u64,
    pub(super) vfork: Option<u64>,
}

pub(super) struct ProcessForkAttempt {
    pub(super) request: ForkRequest,
    pub(super) coordinator: Option<ProcessForkCoordinator>,
    pub(super) external_exec: Option<crate::kernel::control::ExecWork>,
}

pub(super) struct PreparedVforkSuspension {
    pub(super) child_pid: i32,
    pub(super) request: SyscallRequest,
    pub(super) child: crate::kernel::TaskKey,
    pub(super) wait: crate::kernel::VforkParentWait,
    pub(super) activation: executor::PreparedVforkChildActivation,
}

pub(super) enum PreparedInProcessFork {
    Complete(Option<i64>),
    SuspendVfork(PreparedVforkSuspension),
    Retry {
        request: ForkRequest,
        coordinator: Option<ProcessForkCoordinator>,
        external_exec: Option<crate::kernel::control::ExecWork>,
        _subscription: ProcessForkRetrySubscription,
    },
}

pub(super) enum ProcessForkRetrySubscription {
    Barrier {
        _subscription: carrick_thread::fork_quiesce::QuiesceSubscription,
    },
    Lease {
        _subscription: carrick_hal::VcpuLeaseChangeSubscription,
    },
    Topology {
        _subscription: carrick_thread::fork_quiesce::TopologyReleaseSubscription,
    },
    Reservation {
        _subscription: Option<crate::kernel::ReservationChangeSubscription>,
    },
    /// A process fork that found a sibling fork's transient clone-admission
    /// close; woken when that close lifts.
    Admission {
        _subscription: Option<super::CloneAdmissionChangeSubscription>,
    },
    /// A shared-MM fork refused while a sibling's exec reservation owns the
    /// parent's generation; woken when that reservation settles.
    ExecSettlement {
        _subscription: crate::hvpatch::ExecSettlementSubscription,
    },
}

struct ProcessForkRelease {
    barrier: Arc<crate::fork_quiesce::QuiesceBarrier>,
    quiesced: bool,
    drain: Option<carrick_hal::VcpuLeaseDrainGuard>,
    active: bool,
}

impl ProcessForkRelease {
    fn new(
        barrier: Arc<crate::fork_quiesce::QuiesceBarrier>,
        quiesced: bool,
        drain: carrick_hal::VcpuLeaseDrainGuard,
    ) -> Self {
        Self {
            barrier,
            quiesced,
            drain: Some(drain),
            active: true,
        }
    }

    fn release(&mut self) {
        if !self.active {
            return;
        }
        if self.quiesced {
            self.barrier.end_quiesce();
        }
        self.barrier.end_fork();
        drop(self.drain.take());
        self.active = false;
    }
}

impl Drop for ProcessForkRelease {
    fn drop(&mut self) {
        self.release();
    }
}

pub(super) struct ProcessForkCoordinator {
    barrier: Arc<crate::fork_quiesce::QuiesceBarrier>,
    process_admission: Option<CloneAdmissionPermit>,
    clone_admission: Option<ForkCloneAdmission>,
    drain: Option<carrick_hal::VcpuLeaseDrainGuard>,
    quiesced: bool,
    active: bool,
}

impl ProcessForkCoordinator {
    fn new(
        barrier: Arc<crate::fork_quiesce::QuiesceBarrier>,
        process_admission: CloneAdmissionPermit,
    ) -> Self {
        Self {
            barrier,
            process_admission: Some(process_admission),
            clone_admission: None,
            drain: None,
            quiesced: false,
            active: true,
        }
    }

    fn into_parts(mut self) -> (CloneAdmissionPermit, ForkCloneAdmission, ProcessForkRelease) {
        let release = ProcessForkRelease::new(
            Arc::clone(&self.barrier),
            self.quiesced,
            self.drain.take().unwrap_or_else(|| std::process::abort()),
        );
        self.active = false;
        (
            self.process_admission
                .take()
                .unwrap_or_else(|| std::process::abort()),
            self.clone_admission
                .take()
                .unwrap_or_else(|| std::process::abort()),
            release,
        )
    }
}

impl Drop for ProcessForkCoordinator {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if self.quiesced {
            self.barrier.end_quiesce();
        }
        self.barrier.end_fork();
        drop(self.drain.take());
    }
}

impl<E: ThreadedEngine + 'static> ThreadRuntimeState<E>
where
    E::SiblingSpec: 'static,
    E::ProcessSpec: 'static,
{
    pub(super) fn prepare_in_process_fork<M, O>(
        &mut self,
        kernel: &Kernel,
        parent_context: &crate::kernel::KernelContext,
        memory: &mut M,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
        ops: &mut O,
        attempt: ProcessForkAttempt,
    ) -> Result<PreparedInProcessFork, RuntimeError>
    where
        M: CurrentMmMemory + 'static,
        O: HvpatchProcessBackendOps<E, M>,
    {
        let ProcessForkAttempt {
            request,
            coordinator,
            mut external_exec,
        } = attempt;
        let is_external_exec = external_exec.is_some();
        let Some(parent_process) = kernel.hvpatch_process.as_ref() else {
            return Err(RuntimeError::Configuration(
                "in-process fork requested without hvpatch process context".to_owned(),
            ));
        };
        let process_barrier = kernel.process_fork_barrier.as_ref().ok_or_else(|| {
            RuntimeError::Configuration(
                "in-process fork requested without a process-local barrier".to_owned(),
            )
        })?;
        let clone_flags = carrick_abi::LinuxCloneFlags::from_bits_retain(request.flags);
        // `request.exit_signal` is authoritative for both clone spellings: the
        // legacy `CSIGNAL` byte was already lowered out of `flags` by dispatch
        // and `clone3` never carries one there.
        let clone_plan = match crate::kernel::ClonePlan::from_flags(clone_flags) {
            Ok(plan) => plan.with_exit_signal(crate::kernel::ChildExitSignal::for_clone_request(
                request.exit_signal,
            )),
            Err(_) => {
                return Ok(PreparedInProcessFork::Complete(Some(
                    crate::linux_abi::LINUX_EINVAL.guest_retval(),
                )));
            }
        };
        let scheduler = kernel
            .hvpatch_runtime
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
            .continuation_services(parent_context.kernel())
            .0;
        let wake_thread = parent_context.thread().key();
        let subscribe_barrier = || loop {
            let observed = process_barrier.publication_generation();
            let wake_scheduler = Arc::clone(&scheduler);
            match process_barrier.subscribe_quiesce(
                observed,
                Arc::new(move |_| {
                    let _ = if is_external_exec {
                        wake_scheduler.wake_control(wake_thread)
                    } else {
                        wake_scheduler.wake(wake_thread)
                    };
                }),
            ) {
                carrick_thread::fork_quiesce::QuiesceEnrollment::Ready(_) => continue,
                carrick_thread::fork_quiesce::QuiesceEnrollment::Subscribed(subscription) => {
                    break ProcessForkRetrySubscription::Barrier {
                        _subscription: subscription,
                    };
                }
            }
        };
        // A losing process forker becomes a blocked logical task. It owns no
        // admission permit, pthread, or vCPU while waiting for the current
        // coordinator's exact barrier publication.
        // A fork that finds a sibling fork's transient admission close is
        // ordering, not exhaustion: Linux runs the two forks back to back.
        // Park on the close's change epoch and start over.
        let defer_on_admission = |observed_epoch, request, external_exec| {
            let wake_scheduler = Arc::clone(&scheduler);
            let subscription = kernel.clone_admission.subscribe_change(
                observed_epoch,
                Arc::new(move || {
                    let _ = if is_external_exec {
                        wake_scheduler.wake_control(wake_thread)
                    } else {
                        wake_scheduler.wake(wake_thread)
                    };
                }),
            );
            tracing::debug!("hvpatch fork deferred behind a sibling fork's admission close");
            PreparedInProcessFork::Retry {
                request,
                coordinator: None,
                external_exec,
                _subscription: ProcessForkRetrySubscription::Admission {
                    _subscription: subscription,
                },
            }
        };
        let mut coordinator = match coordinator {
            Some(coordinator) => coordinator,
            None => match try_begin_hvpatch_process_fork_with_admission(
                process_barrier,
                self.this_tid,
                &kernel.clone_admission,
            ) {
                ProcessForkStart::Admitted { admission } => {
                    ProcessForkCoordinator::new(Arc::clone(process_barrier), admission)
                }
                ProcessForkStart::AdmissionClosed => {
                    return Ok(PreparedInProcessFork::Complete(Some(
                        crate::linux_abi::LINUX_EAGAIN.guest_retval(),
                    )));
                }
                ProcessForkStart::AdmissionDeferred { observed_epoch } => {
                    return Ok(defer_on_admission(observed_epoch, request, external_exec));
                }
                ProcessForkStart::Busy => {
                    let subscription = subscribe_barrier();
                    match try_begin_hvpatch_process_fork_with_admission(
                        process_barrier,
                        self.this_tid,
                        &kernel.clone_admission,
                    ) {
                        ProcessForkStart::Admitted { admission } => {
                            drop(subscription);
                            ProcessForkCoordinator::new(Arc::clone(process_barrier), admission)
                        }
                        ProcessForkStart::AdmissionClosed => {
                            return Ok(PreparedInProcessFork::Complete(Some(
                                crate::linux_abi::LINUX_EAGAIN.guest_retval(),
                            )));
                        }
                        ProcessForkStart::AdmissionDeferred { observed_epoch } => {
                            drop(subscription);
                            return Ok(defer_on_admission(observed_epoch, request, external_exec));
                        }
                        ProcessForkStart::Busy => {
                            return Ok(PreparedInProcessFork::Retry {
                                request,
                                coordinator: None,
                                external_exec,
                                _subscription: subscription,
                            });
                        }
                    }
                }
            },
        };
        let process_fork_admission = coordinator
            .process_admission
            .as_ref()
            .unwrap_or_else(|| std::process::abort());
        if kernel.process_exiting() || process_fork_admission.is_cancelled() {
            return Ok(PreparedInProcessFork::Complete(Some(
                crate::linux_abi::LINUX_EAGAIN.guest_retval(),
            )));
        }
        // The process-fork coordinator above serializes competing forks, but
        // thread clones can still enroll against the same parent task. Close
        // clone admission before reserving the kernel transaction, then let
        // every clone which enrolled before this close finish publication.
        // Otherwise a new clone can take the task reservation after this fork
        // starts and then remain registered while waiting for the reservation,
        // forming a circular wait with sibling quiescence.
        if coordinator.clone_admission.is_none() {
            let observed = parent_process.kernel_graph().reservation_epoch();
            match process_fork_admission.try_close_for_fork(self.this_tid) {
                Ok(Some(admission)) => coordinator.clone_admission = Some(admission),
                Ok(None) => {
                    let wake_scheduler = Arc::clone(&scheduler);
                    let subscription = parent_process.kernel_graph().subscribe_reservation_change(
                        observed,
                        Arc::new(move || {
                            let _ = if is_external_exec {
                                wake_scheduler.wake_control(wake_thread)
                            } else {
                                wake_scheduler.wake(wake_thread)
                            };
                        }),
                    );
                    return Ok(PreparedInProcessFork::Retry {
                        request,
                        coordinator: Some(coordinator),
                        external_exec,
                        _subscription: ProcessForkRetrySubscription::Reservation {
                            _subscription: subscription,
                        },
                    });
                }
                Err(error) => {
                    tracing::warn!(%error, "hvpatch fork lost clone-admission ownership; fork(2) = EAGAIN");
                    return Ok(PreparedInProcessFork::Complete(Some(
                        crate::linux_abi::LINUX_EAGAIN.guest_retval(),
                    )));
                }
            }
        }
        let parent_pid = parent_process.pid();
        let forking_tid = self.this_tid.raw();
        let emit_fork_runtime_stage =
            |phase: carrick_observability::probes::HvpatchForkRuntimeStagePhase,
             started: Instant,
             child_pid: i32| {
                let elapsed_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
                crate::probes::hvpatch_fork_runtime_stage(
                    carrick_observability::probes::HvpatchForkRuntimeStage::new(
                        phase,
                        parent_pid,
                        child_pid,
                        forking_tid,
                        elapsed_ns,
                    ),
                );
            };
        let fork_total_started = Instant::now();
        let mut fork_stage_started = fork_total_started;
        // Raise the barrier whenever this process has ANOTHER thread that can
        // execute guest code. Live vCPU leases omit every sibling parked in a
        // futex / epoll / fd wait, so lease membership cannot authorize
        // skipping the barrier: those siblings may wake independently through
        // a host fd, `EVFILT_TIMER`, cross-process shared-futex wake, or the
        // signal pump. The identity-aware drain below separately freezes lease
        // registration once all current sibling leases have withdrawn.
        //
        // What matters here is that `quiescing` is RAISED from durable task
        // membership, so a lease-less sibling woken mid-transaction parks at
        // the barrier instead of resuming into it.
        // Kernel thread membership is durable across block/preempt/queue
        // boundaries. The executor census is deliberately transient and can be
        // zero while a same-task sibling is wakeable, so it cannot authorize
        // skipping the COW barrier.
        let fork_participants = match parent_context
            .task()
            .fork_barrier_participants(parent_context.thread().key())
        {
            Ok(participants) => participants,
            Err(error) => {
                tracing::warn!(%error, "hvpatch fork participant witness minting failed; fork(2) = EAGAIN");
                return Ok(PreparedInProcessFork::Complete(Some(
                    crate::linux_abi::LINUX_EAGAIN.guest_retval(),
                )));
            }
        };
        let quiesce_required = fork_participants.requires_quiesce();
        let quiesce_poll_iterations = 0_u64;
        if quiesce_required && !coordinator.quiesced {
            process_barrier.set_quiescing();
            coordinator.quiesced = true;
            self.kicker.kick_all_except(self.this_tid);
            self.futex.notify_signal_pending();
            self.platform_futex.notify_signal_pending();
            kernel.signal_arrival.wake_all_waiters();
        }
        let wake_scheduler = Arc::clone(&scheduler);
        match self.kicker.subscribe_lease_drain(
            self.this_tid,
            Arc::new(move || {
                let _ = if is_external_exec {
                    wake_scheduler.wake_control(wake_thread)
                } else {
                    wake_scheduler.wake(wake_thread)
                };
            }),
        ) {
            carrick_hal::VcpuLeaseDrainEnrollment::Frozen(guard) => {
                if coordinator.drain.is_some() {
                    std::process::abort();
                }
                coordinator.drain = Some(guard);
            }
            carrick_hal::VcpuLeaseDrainEnrollment::Waiting { subscription, .. } => {
                if process_fork_admission.is_cancelled() {
                    return Ok(PreparedInProcessFork::Complete(Some(
                        crate::linux_abi::LINUX_EAGAIN.guest_retval(),
                    )));
                }
                self.kicker.kick_all_except(self.this_tid);
                self.futex.notify_signal_pending();
                self.platform_futex.notify_signal_pending();
                kernel.signal_arrival.wake_all_waiters();
                return Ok(PreparedInProcessFork::Retry {
                    request,
                    coordinator: Some(coordinator),
                    external_exec,
                    _subscription: ProcessForkRetrySubscription::Lease {
                        _subscription: subscription,
                    },
                });
            }
            carrick_hal::VcpuLeaseDrainEnrollment::Busy { subscription, .. } => {
                if process_fork_admission.is_cancelled() {
                    return Ok(PreparedInProcessFork::Complete(Some(
                        crate::linux_abi::LINUX_EAGAIN.guest_retval(),
                    )));
                }
                return Ok(PreparedInProcessFork::Retry {
                    request,
                    coordinator: Some(coordinator),
                    external_exec,
                    _subscription: ProcessForkRetrySubscription::Lease {
                        _subscription: subscription,
                    },
                });
            }
        }
        let (process_fork_admission, fork_clone_admission, mut process_fork_release) =
            coordinator.into_parts();
        let quiesce_elapsed_ns = fork_stage_started
            .elapsed()
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        crate::probes::hvpatch_fork_quiesce(
            carrick_observability::probes::HvpatchForkQuiesce::new(
                parent_pid,
                forking_tid,
                fork_participants.initial_sibling_count_for_probe(),
                quiesce_poll_iterations,
                quiesce_elapsed_ns,
            ),
        );
        crate::probes::hvpatch_fork_runtime_stage(
            carrick_observability::probes::HvpatchForkRuntimeStage::new(
                carrick_observability::probes::HvpatchForkRuntimeStagePhase::Quiesce,
                parent_pid,
                0,
                forking_tid,
                quiesce_elapsed_ns,
            ),
        );

        fork_stage_started = Instant::now();
        if process_fork_admission.is_cancelled() {
            return Ok(PreparedInProcessFork::Complete(Some(
                crate::linux_abi::LINUX_EAGAIN.guest_retval(),
            )));
        }
        // Reserve carrier job custody before any Kernel/backend child
        // publication. Container close rejects a new reservation, while a
        // reservation which won before close remains valid through the
        // transaction and may activate its exact completion during the drain.
        let process_job_reservation = match kernel.reserve_hvpatch_persistent_process_job() {
            Ok(reservation) => reservation,
            Err(RuntimeError::CarrierClosing | RuntimeError::CarrierClosed) => {
                return Ok(PreparedInProcessFork::Complete(Some(
                    crate::linux_abi::LINUX_EAGAIN.guest_retval(),
                )));
            }
            Err(error) => return Err(error),
        };
        // Clone admission is closed and all previously enrolled clone
        // publications have drained before quiescence. Take the authoritative
        // task transaction only after every sibling has either parked or
        // completed its exit transaction. Reserving it before quiescence forms
        // a cycle with a sibling which starts exit concurrently: the fork owns
        // the task and waits for the sibling registration, while the sibling
        // remains registered waiting for the task reservation.
        let observed_reservation_epoch = parent_process.kernel_graph().reservation_epoch();
        let reservation_result = if is_external_exec {
            parent_process.kernel_graph().reserve_external_peer_root(
                parent_context,
                clone_plan,
                format!("carrier-exec-peer-of-{}", parent_process.pid()),
            )
        } else {
            parent_process.kernel_graph().reserve_fork(
                parent_context,
                clone_plan,
                format!("hvpatch-child-of-{}", parent_process.pid()),
                None,
            )
        };
        let reservation = match reservation_result {
            Ok(reservation) => reservation,
            Err(crate::kernel::KernelOperationError::TaskBusy(busy)) => {
                // Another kernel transaction (a sibling's exit, a wait, an
                // exec) holds one of the tasks this fork reserves. That is
                // ordering, not exhaustion: wait for the reservation epoch to
                // move, as the clone-admission close above does, instead of
                // handing the guest `EAGAIN` for a condition it cannot act on.
                let wake_scheduler = Arc::clone(&scheduler);
                let subscription = parent_process.kernel_graph().subscribe_reservation_change(
                    observed_reservation_epoch,
                    Arc::new(move || {
                        let _ = if is_external_exec {
                            wake_scheduler.wake_control(wake_thread)
                        } else {
                            wake_scheduler.wake(wake_thread)
                        };
                    }),
                );
                tracing::debug!(
                    ?busy,
                    "hvpatch fork deferred behind a kernel task reservation"
                );
                return Ok(PreparedInProcessFork::Retry {
                    request,
                    coordinator: None,
                    external_exec,
                    _subscription: ProcessForkRetrySubscription::Reservation {
                        _subscription: subscription,
                    },
                });
            }
            Err(error @ crate::kernel::KernelOperationError::ProcessLimitExceeded { .. }) => {
                // Reaching RLIMIT_NPROC is an expected guest-visible resource
                // result, not a degraded carrier condition.  Keep the detail
                // available to opt-in diagnostics without leaking a host WARN
                // into the guest's stderr stream.
                tracing::debug!(%error, "hvpatch fork reached the guest process limit");
                return Ok(PreparedInProcessFork::Complete(Some(
                    crate::linux_abi::LINUX_EAGAIN.guest_retval(),
                )));
            }
            Err(error) => {
                tracing::warn!(%error, "hvpatch kernel child reservation failed; fork(2) = EAGAIN");
                return Ok(PreparedInProcessFork::Complete(Some(
                    crate::linux_abi::LINUX_EAGAIN.guest_retval(),
                )));
            }
        };
        let shares_mm = clone_plan.mm() == crate::kernel::CloneObjectMode::Share;
        let child_id = reservation.child_id();
        let guest_child_pid = reservation.visible_child_id();
        let child_pid = child_id.raw();
        let parent_task = parent_context.task().key();
        let prepared_mm = if shares_mm {
            // A shared-MM child joins the parent's owner set, which an exec on
            // ANY task sharing that generation freezes for its duration (the
            // reservation pins RetainOldMm/RetireOldMm). The per-process
            // clone-admission gate cannot see that exec: it belongs to the
            // sibling vfork child's own `KernelState`. Admit against the MM
            // scope instead, BEFORE kernel publication, so a conflict is a
            // woken retry (Go os/exec vforks concurrently from several
            // threads) and never the post-publication abort it used to be.
            let hold = loop {
                let settlement = parent_process.mm_resources().exec_settlement_epoch();
                match parent_process
                    .mm_resources()
                    .hold_owner_set_edit(parent_task)
                {
                    Ok(hold) => break hold,
                    Err(crate::hvpatch::MmResourcesError::ExecReservationConflict(conflict)) => {
                        let wake_scheduler = Arc::clone(&scheduler);
                        match parent_process.mm_resources().subscribe_exec_settlement(
                            settlement,
                            Arc::new(move |_| {
                                let _ = if is_external_exec {
                                    wake_scheduler.wake_control(wake_thread)
                                } else {
                                    wake_scheduler.wake(wake_thread)
                                };
                            }),
                        ) {
                            crate::hvpatch::ExecSettlementEnrollment::Ready => continue,
                            crate::hvpatch::ExecSettlementEnrollment::Subscribed(subscription) => {
                                tracing::debug!(
                                    ?conflict,
                                    "shared-MM fork deferred behind a sibling exec reservation"
                                );
                                return Ok(PreparedInProcessFork::Retry {
                                    request,
                                    coordinator: None,
                                    external_exec,
                                    _subscription: ProcessForkRetrySubscription::ExecSettlement {
                                        _subscription: subscription,
                                    },
                                });
                            }
                        }
                    }
                    Err(error) => {
                        return Err(RuntimeError::Configuration(format!(
                            "admit exact shared HVPatch MM for vfork: {error}"
                        )));
                    }
                }
            };
            match parent_process.mm_resources().lease(parent_task) {
                Ok(lease) => PreparedHvpatchProcessMm::Shared {
                    parent_task,
                    lease,
                    hold,
                },
                Err(error) => {
                    return Err(RuntimeError::Configuration(format!(
                        "retain exact shared HVPatch MM for vfork: {error}"
                    )));
                }
            }
        } else {
            match parent_process.mm_resources().prepare_child() {
                Ok(prepared) => PreparedHvpatchProcessMm::Copied(prepared),
                Err(error) => {
                    tracing::warn!(%error, "hvpatch stage-1 root-slot preparation failed; fork(2) = EAGAIN");
                    return Ok(PreparedInProcessFork::Complete(Some(
                        crate::linux_abi::LINUX_EAGAIN.guest_retval(),
                    )));
                }
            }
        };
        let child_binding = prepared_mm.binding();
        let root_slot = match &prepared_mm {
            PreparedHvpatchProcessMm::Copied(prepared) => {
                let Some(root_slot) = prepared.root_slot() else {
                    return Err(RuntimeError::Configuration(
                        "hvpatch prepared child has no stage-1 root slot".to_owned(),
                    ));
                };
                Some(root_slot)
            }
            PreparedHvpatchProcessMm::Shared { .. } => None,
        };
        let child_tid = ThreadId::from_guest_supplied_tid(child_pid);
        // The kernel mm association follows Linux clone semantics even while
        // the K1 execution adapter still prepares a stage-1 root slot for the
        // vCPU. CLONE_VM (including vfork) shares the exact parent `Mm`; plain
        // fork publishes the prepared root-slot backend as the child's copied mm.
        let prepared_result = if clone_plan.mm() == crate::kernel::CloneObjectMode::Share {
            reservation.prepare_shared_mm(child_tid)
        } else {
            let PreparedHvpatchProcessMm::Copied(prepared) = &prepared_mm else {
                std::process::abort();
            };
            reservation.prepare_with_mm_backend(prepared.backend(), child_tid)
        };
        let mut prepared_fork = match prepared_result {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(RuntimeError::Configuration(format!(
                    "prepare authoritative hvpatch child: {error}"
                )));
            }
        };
        if is_external_exec {
            prepared_fork.retain_stdio_only().map_err(|error| {
                RuntimeError::Configuration(format!(
                    "prepare logical exec selected file table: {error}"
                ))
            })?;
        }
        let child_mm_id = prepared_fork.child_mm_id();
        // Page-table authority over the PARENT MM comes FIRST, before the
        // frame-inventory reservation and the backend topology lock, so fork
        // orders P -> topology exactly like the mmap/munmap/mprotect editors
        // (`SyscallMmPhase::Mutation` pauses, then `unmap_range` takes the
        // topology lock for alias teardown). Taking the topology lock first
        // and pausing later inverted that order: a sibling `munmap` holding
        // the pt-barrier coordinator blocked in `acquire_topology_lock(
        // AliasUnmap)` on the lock this forker held while the forker parked
        // in the election, and only the 30 s election budget turned the
        // cycle into fork(2) = EAGAIN instead of a hang (`bt all` of the
        // stalled carrier, 2026-09-02).
        //
        // Sole exact-MM authority is the cheap arm, but it is only ever
        // instantaneous: the process fork barrier parks siblings by DURABLE
        // task membership, while the executor census is transient, so a
        // sibling that withdrew its vCPU lease into a lease-releasing host
        // wait, or is between wake and park, still counts. A multithreaded
        // parent (every Go program) therefore lost sole authority on a
        // steady fraction of forks and lowered fork(2) to EAGAIN -- 27-33
        // per go os/exec run under four concurrent lanes -- for a condition
        // Linux never reports. Pause-modify-resume is the same authority the
        // editors use against live siblings, so take it here too; only a
        // real pause failure remains EAGAIN. Every early return below drops
        // the authority (ending the pause) before the retry re-enters.
        let mut admitted_mm_executor = None;
        let mm_executor: &mut crate::dispatch::MmExecutorParticipation =
            match self.guest_execution.as_mut() {
                Some(participation) => participation,
                None => admitted_mm_executor.insert(
                    kernel.dispatcher.enter_mm_executor().map_err(|error| {
                        RuntimeError::Configuration(format!(
                            "admit exact-MM fork publication authority: {error}"
                        ))
                    })?,
                ),
            };
        let coordinator = kernel.dispatcher.mm_mutation_coordinator();
        let parent_mm_id = parent_context.shared().mm().id();
        let mut install_authority =
            acquire_mm_stage1_authority(mm_executor, self.this_tid, PtPauseBudget::DEFAULT);
        if let Err(install_failure) = install_authority.as_ref() {
            tracing::warn!(
                ?install_failure,
                "dispatcher fork install could not pause the parent MM; fork(2) = EAGAIN"
            );
            return Ok(PreparedInProcessFork::Complete(Some(
                crate::linux_abi::LINUX_EAGAIN.guest_retval(),
            )));
        }
        let mut inventory_transaction = None;
        let mut inventory_reserve =
            |frame_candidates: usize,
             mapping_candidates: usize,
             capacity: carrick_hal::FrameEventCapacity|
             -> Result<carrick_hal::FrameInventoryReservation, RuntimeError> {
                let reservation = parent_process
                    .kernel_graph()
                    .reserve_frame_inventory(frame_candidates, mapping_candidates, capacity)
                    .map_err(|error| {
                        RuntimeError::Configuration(format!(
                            "reserve HVPatch child frame inventory: {error}"
                        ))
                    })?;
                inventory_transaction = Some(reservation.transaction());
                Ok(reservation)
            };
        let inventory_preparation = if shares_mm {
            HvpatchProcessInventoryPreparation::SharedMm {
                kernel_mm: child_mm_id.raw(),
            }
        } else {
            HvpatchProcessInventoryPreparation::Copied(&mut inventory_reserve)
        };
        // The reservation and its complete bounded storage exist before this
        // topology lock. Keep it local until every guest-pointer/pidfd preflight
        // succeeds, so EFAULT cannot occupy the backend's one process slot.
        let topology = loop {
            let observed = crate::fork_quiesce::topology_release_generation();
            if let Some(topology) = crate::fork_quiesce::try_acquire_topology_lock(
                carrick_observability::probes::HvpatchTopologyOperation::InProcessFork,
                parent_process.pid(),
                self.this_tid.raw(),
            ) {
                break topology;
            }
            let wake_scheduler = Arc::clone(&scheduler);
            match crate::fork_quiesce::subscribe_topology_release(
                observed,
                Arc::new(move |_| {
                    let _ = if is_external_exec {
                        wake_scheduler.wake_control(wake_thread)
                    } else {
                        wake_scheduler.wake(wake_thread)
                    };
                }),
            ) {
                carrick_thread::fork_quiesce::TopologyReleaseEnrollment::Ready(_) => continue,
                carrick_thread::fork_quiesce::TopologyReleaseEnrollment::Subscribed(
                    subscription,
                ) => {
                    return Ok(PreparedInProcessFork::Retry {
                        request,
                        coordinator: None,
                        external_exec,
                        _subscription: ProcessForkRetrySubscription::Topology {
                            _subscription: subscription,
                        },
                    });
                }
            }
        };
        emit_fork_runtime_stage(
            carrick_observability::probes::HvpatchForkRuntimeStagePhase::ProcessAllocate,
            fork_stage_started,
            child_pid,
        );
        let child_key = prepared_fork.child_key();

        let Some(parent_tid_original) = read_optional_fork_output(memory, request.parent_tid_addr)
        else {
            return Ok(PreparedInProcessFork::Complete(Some(
                crate::linux_abi::LINUX_EFAULT.guest_retval(),
            )));
        };
        let Some(pidfd_original) = read_optional_fork_output(memory, request.pidfd_out) else {
            return Ok(PreparedInProcessFork::Complete(Some(
                crate::linux_abi::LINUX_EFAULT.guest_retval(),
            )));
        };
        let Some(_child_tid_original) = read_optional_fork_output(memory, request.child_tid_addr)
        else {
            return Ok(PreparedInProcessFork::Complete(Some(
                crate::linux_abi::LINUX_EFAULT.guest_retval(),
            )));
        };
        fork_stage_started = Instant::now();
        let installed_pidfd = if request.pidfd_out.is_some() {
            match kernel
                .dispatcher
                .install_reserved_hvpatch_child_pidfd(parent_context, &mut prepared_fork)
            {
                Ok(fd) => Some(fd),
                Err(errno) => {
                    return Ok(PreparedInProcessFork::Complete(Some(errno.guest_retval())));
                }
            }
        } else {
            None
        };
        let rollback_pidfd = |fd: Option<i32>| {
            if let Some(fd) = fd {
                let _ = kernel.dispatcher.remove_installed_hvpatch_child_pidfd(
                    parent_context,
                    fd,
                    child_key,
                );
            }
        };
        emit_fork_runtime_stage(
            carrick_observability::probes::HvpatchForkRuntimeStagePhase::PidfdParent,
            fork_stage_started,
            child_pid,
        );

        fork_stage_started = Instant::now();
        let (task_key, thread_key, _, generation) = prepared_fork.prepared_execution_identity();
        let asid_generation = prepared_mm.asid_generation();
        let identity = carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskIdentity {
            task_serial: task_key.serial.raw(),
            thread_serial: thread_key.serial.raw(),
            execution_generation: generation.raw(),
            linux_pid: child_pid,
            linux_tid: child_pid,
            asid: child_binding.asid.raw(),
        };
        let prepared_dispatch_mm = match kernel.dispatcher.prepare_fork_mm(
            parent_context.shared().mm().id(),
            child_mm_id,
            clone_plan.mm(),
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "dispatcher fork preparation rejected semantic MM projection; fork(2) = EAGAIN"
                );
                rollback_pidfd(installed_pidfd);
                return Ok(PreparedInProcessFork::Complete(Some(
                    crate::linux_abi::LINUX_EAGAIN.guest_retval(),
                )));
            }
        };
        let table_arena_source = match &prepared_mm {
            PreparedHvpatchProcessMm::Copied(prepared) => Some(prepared.table_arena_source()),
            PreparedHvpatchProcessMm::Shared { .. } => None,
        };
        let (prepared_backend, cpu, child_kicker) = match ops.prepare(
            memory,
            inventory_preparation,
            carrick_hal::ProcessForkRequest {
                entry: carrick_hal::GuestEntryRegs {
                    return_value: 0,
                    stack: (request.child_stack != 0).then_some(request.child_stack),
                    tls: None,
                },
                child_ttbr0: child_binding.ttbr0.raw(),
                root_slot_base: root_slot.map_or(0, |slot| slot.base()),
                root_slot_size: root_slot.map_or(0, |slot| slot.size()),
                plan: prepared_dispatch_mm.fork_projection_plan(),
                child_tid,
                forking_tid: self.this_tid,
                table_arena_source,
            },
            identity,
            child_mm_id.raw(),
            asid_generation,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                rollback_pidfd(installed_pidfd);
                return Err(error);
            }
        };
        if external_exec
            .as_mut()
            .is_some_and(|work| !work.begin_publication())
        {
            if let Err(error) =
                ops.abort_and_rollback_prepared(prepared_backend, memory, !shares_mm)
            {
                return Err(ops.fail_stop(error));
            }
            rollback_pidfd(installed_pidfd);
            return Ok(PreparedInProcessFork::Complete(Some(
                crate::linux_abi::LINUX_EAGAIN.guest_retval(),
            )));
        }
        let _inventory_abandon = inventory_transaction.map(|tx| {
            InventoryAbandon::new(parent_process.kernel_graph().frame_inventory(), [Some(tx)])
        });
        emit_fork_runtime_stage(
            carrick_observability::probes::HvpatchForkRuntimeStagePhase::ProcessSpec,
            fork_stage_started,
            child_pid,
        );

        // Install the child's MM under the page-table authority taken above,
        // before the topology lock.
        let child_dispatcher = install_authority.as_mut().ok().map(|authority| {
            let mutation = match authority {
                MmStage1Authority::Sole(sole) => crate::dispatch::mm_mutation::from_sole_executor(
                    sole,
                    coordinator,
                    parent_mm_id,
                ),
                MmStage1Authority::Paused(pause) => {
                    crate::dispatch::mm_mutation::from_pt_pause(pause)
                }
            };
            let permit = mutation.host_alias_permit();
            kernel.dispatcher.fork_clone_with_prepared_mm_authorized(
                parent_mm_id,
                child_mm_id,
                parent_process.pid() as u32,
                child_pid as u32,
                prepared_dispatch_mm,
                &permit,
            )
        });
        let install_failure = install_authority.as_ref().err().copied();
        drop(install_authority);
        let mut child_dispatcher = match child_dispatcher {
            Some(Ok(dispatcher)) => dispatcher,
            None => {
                tracing::warn!(
                    ?install_failure,
                    "dispatcher fork install could not pause the parent MM; fork(2) = EAGAIN"
                );
                if let Err(error) =
                    ops.abort_and_rollback_prepared(prepared_backend, memory, !shares_mm)
                {
                    return Err(ops.fail_stop(error));
                }
                rollback_pidfd(installed_pidfd);
                return Ok(PreparedInProcessFork::Complete(Some(
                    crate::linux_abi::LINUX_EAGAIN.guest_retval(),
                )));
            }
            Some(Err(error)) => {
                tracing::warn!(
                    ?error,
                    "dispatcher fork install rejected stale parent revision; fork(2) = EAGAIN"
                );
                if let Err(error) =
                    ops.abort_and_rollback_prepared(prepared_backend, memory, !shares_mm)
                {
                    return Err(ops.fail_stop(error));
                }
                rollback_pidfd(installed_pidfd);
                return Ok(PreparedInProcessFork::Complete(Some(
                    crate::linux_abi::LINUX_EAGAIN.guest_retval(),
                )));
            }
        };
        if external_exec.is_some() {
            child_dispatcher.init_external_exec_stdio();
        }
        let child_exit_signal = i32::try_from(request.exit_signal)
            .ok()
            .filter(|signal| *signal != 0);
        let child_registry = Arc::new(ThreadRegistry::new(child_tid));
        let child_futex = Arc::new(crate::thread::FutexTable::new());
        let child_platform_futex = (self.platform_futex_factory)(Arc::clone(&child_futex));
        let child_threads = Arc::new(parking_lot::Mutex::new(Vec::new()));

        // The kernel reservation owns the independently allocated namespace
        // PID until commit. Copy out that captured visible identity while all
        // backend keys continue to use the carrier-global TaskId.
        let parent_outputs_published = request.parent_tid_addr.is_none_or(|address| {
            memory
                .write_bytes(address, &guest_child_pid.to_le_bytes())
                .is_ok()
        }) && match (request.pidfd_out, installed_pidfd) {
            (Some(address), Some(fd)) => memory.write_bytes(address, &fd.to_le_bytes()).is_ok(),
            (None, _) => true,
            (Some(_), None) => false,
        };
        if !parent_outputs_published {
            tracing::error!(
                parent_pid,
                child_pid,
                "parent fork copyout diverged from successful preflight after child materialization"
            );
            std::process::abort();
        }
        if let Err(error) = check_hvpatch_process_failpoint(HvpatchProcessFailpoint::ParentCopyout)
        {
            if let (Some(address), Some(bytes)) =
                (request.parent_tid_addr, parent_tid_original.as_ref())
            {
                memory.write_bytes(address, bytes).unwrap_or_else(|_| {
                    std::process::abort();
                });
            }
            if let (Some(address), Some(bytes)) = (request.pidfd_out, pidfd_original.as_ref()) {
                memory.write_bytes(address, bytes).unwrap_or_else(|_| {
                    std::process::abort();
                });
            }
            if let Err(cleanup_error) =
                ops.abort_and_rollback_prepared(prepared_backend, memory, !shares_mm)
            {
                return Err(ops.fail_stop(cleanup_error));
            }
            rollback_pidfd(installed_pidfd);
            return Err(error);
        }
        if let Err(error) = check_hvpatch_process_failpoint(HvpatchProcessFailpoint::BackendCommit)
        {
            if let (Some(address), Some(bytes)) =
                (request.parent_tid_addr, parent_tid_original.as_ref())
            {
                memory
                    .write_bytes(address, bytes)
                    .unwrap_or_else(|_| std::process::abort());
            }
            if let (Some(address), Some(bytes)) = (request.pidfd_out, pidfd_original.as_ref()) {
                memory
                    .write_bytes(address, bytes)
                    .unwrap_or_else(|_| std::process::abort());
            }
            if let Err(cleanup_error) =
                ops.abort_and_rollback_prepared(prepared_backend, memory, !shares_mm)
            {
                return Err(ops.fail_stop(cleanup_error));
            }
            rollback_pidfd(installed_pidfd);
            return Err(error);
        }
        if let Err(error) = check_hvpatch_process_failpoint(HvpatchProcessFailpoint::KernelCommit) {
            if let (Some(address), Some(bytes)) =
                (request.parent_tid_addr, parent_tid_original.as_ref())
            {
                memory
                    .write_bytes(address, bytes)
                    .unwrap_or_else(|_| std::process::abort());
            }
            if let (Some(address), Some(bytes)) = (request.pidfd_out, pidfd_original.as_ref()) {
                memory
                    .write_bytes(address, bytes)
                    .unwrap_or_else(|_| std::process::abort());
            }
            if let Err(cleanup_error) =
                ops.abort_and_rollback_prepared(prepared_backend, memory, !shares_mm)
            {
                return Err(ops.fail_stop(cleanup_error));
            }
            rollback_pidfd(installed_pidfd);
            return Err(error);
        }
        if !shares_mm {
            ops.commit_parent(memory).unwrap_or_else(|error| {
                tracing::error!(%error, "commit parent HVPatch fork transaction");
                std::process::abort();
            });
        }
        drop(topology);

        fork_stage_started = Instant::now();
        let published = match prepared_fork.commit() {
            Ok(published) => published,
            Err(error) => {
                tracing::error!(
                    child_pid,
                    %error,
                    "authoritative child publication failed after frame inventory commit"
                );
                std::process::abort();
            }
        };
        let child_context = published
            .context()
            .unwrap_or_else(|| std::process::abort())
            .retain_exact();
        let child_key = child_context.task().key();
        if let Some(chain) = kernel.dispatcher.observers() {
            let p = crate::observe::ProcessInfo::new(parent_context);
            chain.on_process_create(&p, child_key);
        }
        let child_backend_result = match prepared_mm {
            PreparedHvpatchProcessMm::Copied(prepared) => parent_process
                .mm_resources()
                .publish_child(child_context.task().key(), prepared),
            PreparedHvpatchProcessMm::Shared {
                parent_task, hold, ..
            } => {
                let published = parent_process
                    .mm_resources()
                    .publish_shared_child(parent_task, child_context.task().key());
                // Release the admission only once the owner edge is published;
                // a waiting exec then recomputes its disposition over the
                // complete owner set.
                drop(hold);
                published
            }
        };
        let child_backend = match child_backend_result {
            Ok(backend) => backend,
            Err(error) => {
                // Kernel publication is already authoritative; a backend root-slot
                // collision now means internal generation accounting is corrupt
                // and cannot be represented as a failed guest fork.
                tracing::error!(child_pid, %error, "publish hvpatch child root slot failed");
                std::process::abort();
            }
        };
        let child_process = parent_process.published_child_context(&child_context, child_backend);
        child_dispatcher.bind_hvpatch_process(child_process.clone());
        let child_kernel = Arc::new(KernelState::new(
            child_dispatcher,
            Arc::clone(&kernel.signal_pump),
            Arc::clone(&kernel.signal_arrival),
            Some(child_process.clone()),
            kernel.hvpatch_runtime.clone(),
            child_exit_signal,
        ));
        if let Some(work) = external_exec {
            child_kernel.install_external_exec_work(work)?;
        }
        let task_state = crate::kernel::objects::MigratableTaskState {
            cpu,
            mm: child_mm_id,
            asid_generation,
        };
        let generation = child_context
            .thread()
            .publish_initial_task_state(task_state.clone())
            .unwrap_or_else(|error| {
                tracing::error!(child_pid, %error, "publish process child task state");
                std::process::abort();
            });
        let runtime = child_kernel
            .hvpatch_runtime
            .as_ref()
            .unwrap_or_else(|| std::process::abort());
        let mut task_backend = ops
            .commit(
                prepared_backend,
                runtime.carrier_tasks(child_context.kernel()),
            )
            .unwrap_or_else(|error| {
                tracing::error!(child_pid, %error, "commit process child task backend");
                std::process::abort();
            });
        let cow_identity = carrick_hal::FrameCowIdentity {
            linux_pid: child_pid,
            linux_tid: child_pid,
            mm: child_mm_id.raw(),
            asid: child_binding.asid.raw(),
        };
        let cow_authority = Arc::new(KernelFrameCowAuthority {
            kernel: Arc::clone(child_context.kernel()),
            mm: child_mm_id,
            owner_inventory: ops.frame_cow_owner_inventory(&task_backend),
            guest_executors: child_kernel.dispatcher.mm_executor_census(),
            tid: child_tid,
            identity: cow_identity,
        });
        let child_token = Arc::clone(&cow_authority)
            .issue_hvpatch_child_token(&child_context)
            .unwrap_or_else(|error| {
                tracing::error!(child_pid, %error, "issue exact process child token");
                std::process::abort();
            });
        ops.bind_child_kernel(&mut task_backend, child_token)
            .unwrap_or_else(|error| {
                tracing::error!(child_pid, %error, "bind exact process child token");
                std::process::abort();
            });
        if let Err(error) = check_hvpatch_process_failpoint(HvpatchProcessFailpoint::TokenBind) {
            return Err(ops.fail_stop(error));
        }
        if !shares_mm {
            ops.apply_inventory(&task_backend, child_context.kernel(), child_mm_id)
                .unwrap_or_else(|error| {
                    tracing::error!(child_pid, %error, "apply process child frame inventory");
                    std::process::abort();
                });
        }
        ops.activate_child(&mut task_backend)
            .unwrap_or_else(|error| {
                tracing::error!(child_pid, %error, "activate process child task state");
                std::process::abort();
            });

        let (execution_lease, injected_lease) = ExecutionLeaseCell::injected();
        let mut child_state = ThreadRuntimeState::<E>::new(
            Arc::clone(&child_registry),
            Arc::clone(&child_futex),
            child_platform_futex,
            Arc::clone(&self.platform_futex_factory),
            child_kernel.process_fork_barrier.clone(),
            child_kernel.crash_capture.clone(),
            Some(Arc::clone(child_context.thread())),
            Some(child_pid),
            crate::kernel::LinuxTid::for_task_leader(child_id),
            child_kernel.fatal_signal.current_generation(),
            child_tid,
            Arc::clone(&child_threads),
            Arc::clone(&child_kicker),
            carrick_hal::InGuestFlag::for_guest_thread(),
            self.max_traps,
        );
        child_state.execution_lease = execution_lease;
        child_state.service_kernel_context = Some(child_context.retain_exact());
        if !is_external_exec {
            let child_syscall = self
                .syscall_completion
                .guest("process child publication lost parent completion token")
                .unwrap_or_else(|error| {
                    tracing::error!(
                        child_pid,
                        %error,
                        "process child publication lost parent completion token"
                    );
                    std::process::abort();
                })
                .syscall();
            child_state.syscall_completion =
                SyscallCompletionOwnership::Guest(SyscallCompletionToken::new(
                    child_syscall,
                    child_context.retain_exact(),
                    child_kernel.dispatcher.observers().cloned(),
                ));
        } else {
            child_state
                .begin_internal_control_exec()
                .unwrap_or_else(|error| {
                    tracing::error!(child_pid, %error, "type external control exec ownership");
                    std::process::abort();
                });
        }
        let mut logical = prepare_hvpatch_logical_job(HvpatchLogicalJobInput {
            kernel: Arc::clone(&child_kernel),
            state: child_state,
            task_backend: ops.make_binding_state(task_backend),
            context: child_context.retain_exact(),
            cpu: task_state,
            generation,
            injected_lease,
            bootstrap_process_child: Some(if is_external_exec {
                ProcessChildBootstrap::ExternalControlExec { shares_mm }
            } else {
                ProcessChildBootstrap::GuestFork {
                    shares_mm,
                    child_settid: request
                        .child_tid_addr
                        .map(|address| (address, guest_child_pid)),
                }
            }),
            bootstrap_thread_child: false,
        })
        .unwrap_or_else(|error| {
            tracing::error!(child_pid, %error, "prepare process child logical job");
            std::process::abort();
        });
        let (grant_thread, grant_generation) =
            control.current_submission_key().unwrap_or_else(|error| {
                tracing::error!(child_pid, %error, "capture process-fork worker grant");
                std::process::abort();
            });
        let shape = if is_external_exec || request.clone_parent {
            executor::HvpatchSubmissionShape::PeerRoot {
                grant: (grant_thread, grant_generation),
            }
        } else {
            executor::HvpatchSubmissionShape::Descendant {
                grant: (grant_thread, grant_generation),
            }
        };
        let dormant = control
            .prepare_hvpatch_submission(
                runtime.persistent_bindings(),
                shape,
                Arc::clone(child_context.thread()),
                generation,
                Arc::clone(&logical.binding),
            )
            .unwrap_or_else(|error| {
                tracing::error!(child_pid, %error, "prepare dormant process child");
                std::process::abort();
            });
        child_kernel
            .register_hvpatch_runtime_endpoint(Arc::clone(&child_futex), Arc::clone(&child_kicker));
        if let Err(error) = child_kernel.admit_external_exec(child_context.task().key()) {
            return Err(ops.fail_stop(error));
        }
        if let Err(error) = check_hvpatch_process_failpoint(HvpatchProcessFailpoint::DormantHandle)
        {
            return Err(ops.fail_stop(error));
        }
        let started = published.start_child().unwrap_or_else(|error| {
            tracing::error!(child_pid, %error, "open process child start gate");
            std::process::abort();
        });
        let start_gate = started
            .context()
            .thread()
            .take_opened_start_gate(generation)
            .unwrap_or_else(|| std::process::abort());
        logical
            .install_start_gate(start_gate)
            .unwrap_or_else(|error| {
                tracing::error!(child_pid, %error, "install process child start proof");
                std::process::abort();
            });
        let proof = logical.activation_proof().unwrap_or_else(|error| {
            tracing::error!(child_pid, %error, "validate process child activation proof");
            std::process::abort();
        });
        if let Err(error) = check_hvpatch_process_failpoint(HvpatchProcessFailpoint::StartProof) {
            return Err(ops.fail_stop(error));
        }
        let member_publication = PersistentProcessMemberPublication::new(
            Arc::clone(&child_threads),
            &logical.terminal_settlement,
        );
        let (_, vfork_parent_wait) = started.into_parts();
        let (scheduler, _) = runtime.continuation_services(child_context.kernel());
        // The committed Kernel row is authoritative now, but a non-vfork
        // child may run and exit as soon as `activate` publishes it to the
        // scheduler. Snapshot and emit the fork lifecycle identity before that
        // edge: forkstackstorm's `_exit` children otherwise legitimately win
        // the race, making this required event disappear and leaking a warning
        // into guest-visible conformance output.
        child_process.trace_lifecycle(
            carrick_observability::probes::HvpatchGuestLifecyclePhase::Fork,
            child_tid,
            0,
        );
        let activation = if vfork_parent_wait.is_some() {
            Some(executor::PreparedVforkChildActivation::new(
                dormant,
                Arc::clone(&scheduler),
                Arc::clone(child_context.thread()),
                proof,
                member_publication,
                process_job_reservation,
                logical.result.clone(),
                logical.completion.clone(),
                logical.process_retirement.clone(),
            ))
        } else {
            dormant
                .activate(&scheduler, Arc::clone(child_context.thread()), proof)
                .unwrap_or_else(|error| {
                    tracing::error!(child_pid, %error, "activate process child logical job");
                    std::process::abort();
                });
            member_publication.commit();
            process_job_reservation.activate_with_process_retirement(
                logical.result.clone(),
                logical.completion.clone(),
                logical.process_retirement.clone(),
            )?;
            if let Err(error) = check_hvpatch_process_failpoint(HvpatchProcessFailpoint::Activation)
            {
                return Err(ops.fail_stop(error));
            }
            None
        };
        process_fork_release.release();
        // Publication is now authoritative and the child has its execution
        // owner. Reopen clone admission and release the process-fork permit
        // before a possible vfork parent wait: a sibling exec must be able to
        // replace a vfork-suspended caller.
        drop(fork_clone_admission);
        drop(process_fork_admission);
        crate::event_ring::rec(crate::event_ring::FORK, child_pid, 0, 0);
        emit_fork_runtime_stage(
            carrick_observability::probes::HvpatchForkRuntimeStagePhase::Publication,
            fork_stage_started,
            child_pid,
        );
        emit_fork_runtime_stage(
            carrick_observability::probes::HvpatchForkRuntimeStagePhase::Total,
            fork_total_started,
            child_pid,
        );
        if let Some(wait) = vfork_parent_wait {
            let current = parent_context
                .task_binding()
                .capture(self.linux_tid)
                .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
            self.service_kernel_context = Some(current.retain_exact());
            let request = SyscallRequest::new(
                220,
                crate::compat::SyscallArgs([
                    request.flags,
                    request.child_stack,
                    request.parent_tid_addr.unwrap_or(0),
                    u64::from(request.exit_signal),
                    request.child_tid_addr.unwrap_or(0),
                    request.vfork.unwrap_or(0),
                ]),
            )
            .with_guest_abi(<E::Arch as carrick_hal::GuestArch>::linux_guest_abi())
            .with_current_guest_sp(ops.guest_sp(memory));
            let activation = activation.unwrap_or_else(|| std::process::abort());
            return Ok(PreparedInProcessFork::SuspendVfork(
                PreparedVforkSuspension {
                    child_pid: guest_child_pid,
                    request,
                    child: child_key,
                    wait,
                    activation,
                },
            ));
        }
        Ok(PreparedInProcessFork::Complete(Some(i64::from(
            guest_child_pid,
        ))))
    }
}

#[cfg(test)]
mod pt_pause_tests {
    use super::*;
    use carrick_hal::vcpu_sched::VcpuScheduler;
    use carrick_hal::{GenericVcpuRegistry, VcpuKickDyn, VcpuRegistry};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct NoopKick;

    impl VcpuKickDyn for NoopKick {
        fn kick(&self) {}
    }

    /// A kick handle that answers the drain the way a real vCPU does: forced
    /// out of the guest, it clears its OWN in-guest flag.
    struct LeaveGuestOnKick(Arc<carrick_hal::InGuestFlag>);

    impl VcpuKickDyn for LeaveGuestOnKick {
        fn kick(&self) {
            self.0.leave_guest();
        }
    }

    struct RecordKick(Arc<AtomicUsize>);

    impl VcpuKickDyn for RecordKick {
        fn kick(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn tid(raw: i32) -> ThreadId {
        ThreadId::synthetic_for_tests(raw)
    }

    fn register_for_test(
        registry: &GenericVcpuRegistry,
        tid: ThreadId,
        flag: &carrick_hal::InGuestFlag,
    ) {
        assert!(matches!(
            registry.subscribe_register(tid, Box::new(NoopKick), flag, Arc::new(|| {})),
            carrick_hal::VcpuRegistrationEnrollment::Registered
        ));
    }

    fn enter_for_test(
        census: &Arc<crate::kernel::GuestExecutorCensus>,
        registry: &Arc<GenericVcpuRegistry>,
        tid: ThreadId,
    ) -> crate::kernel::GuestExecutorParticipation {
        let endpoint: Arc<dyn VcpuRegistry> = registry.clone();
        census
            .enter_with_pause_endpoint(None, endpoint, tid)
            .expect("test exact-MM participation")
    }

    fn acquire_mutation_pause_for_test<'participant>(
        barrier: &'static crate::fork_quiesce::PtQuiesce,
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

    #[test]
    fn foreign_cow_active_target_acks_then_inactive_caller_resident_defers_to_reentry() {
        let _test_lock = foreign_cow_handshake_test_lock();
        let barrier = pt_barrier();
        assert!(!barrier.is_quiescing());
        let registry = Arc::new(GenericVcpuRegistry::new());
        let census = Arc::new(crate::kernel::GuestExecutorCensus::default());
        let active_tid = tid(1_701);
        let caller_tid = tid(1_702);
        let active_flag = carrick_hal::InGuestFlag::for_guest_thread();
        register_for_test(&registry, active_tid, &active_flag);
        let _active_participation = enter_for_test(&census, &registry, active_tid);

        let (_pool, stage1) = crate::hvpatch::Stage1MmPool::new_root_for_tests(0x8000, 1)
            .expect("one-slot target stage-1 pool");
        let active_executor =
            crate::kernel::objects::ExecutorId::for_transitional_thread(active_tid)
                .expect("active executor identity");
        let caller_executor =
            crate::kernel::objects::ExecutorId::for_transitional_thread(caller_tid)
                .expect("caller executor identity");
        for executor in [active_executor, caller_executor] {
            stage1
                .begin_asid_load(executor)
                .expect("record exact target residency")
                .mark_resident()
                .expect("publish exact target residency");
        }
        let caller_observer = stage1.cow_invalidation_observer(caller_executor);
        let mm = crate::kernel::MmId::from_raw_u64(1_703).expect("test MM");
        let coordinator = Arc::new(crate::dispatch::mm_mutation::MmMutationCoordinator::new(mm));
        let authority = crate::dispatch::mm_mutation::ForeignMmMutationAuthority::new(
            mm,
            coordinator,
            Arc::clone(&census),
            Arc::clone(&stage1),
        );
        let identity = stage1.foreign_stage1_identity(mm);
        let worker_stage1 = Arc::clone(&stage1);
        let worker = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(1);
            while !barrier.is_quiescing() {
                assert!(Instant::now() < deadline, "target pause was never raised");
                std::thread::yield_now();
            }
            barrier.park_servicing_exact_invalidation(identity, active_tid, |request| {
                let ticket = worker_stage1
                    .pending_cow_invalidation(active_executor)
                    .expect("active owner has exact target ticket");
                assert_eq!(
                    request.identity(),
                    carrick_hal::ForeignCowInvalidationIdentity::new(identity, ticket.generation(),)
                );
                worker_stage1
                    .acknowledge_cow_invalidation(active_executor, ticket)
                    .map_err(|_| ())
            });
        });

        authority
            .with_guard(caller_tid, |mutation| {
                mutation.with_host_alias(|invalidator| {
                    carrick_hal::ForeignMmInvalidator::invalidate_exact_asid(
                        invalidator,
                        identity.binding(),
                        Instant::now() + Duration::from_secs(1),
                    )
                })
            })
            .expect("acquire exact foreign-MM pause")
            .expect("active target owner acknowledges while remaining paused");
        worker.join().expect("active target owner resumes");

        assert!(stage1.pending_cow_invalidation(active_executor).is_none());
        assert!(
            stage1.pending_cow_invalidation(caller_executor).is_some(),
            "foreign caller must not be awaited as an active target self-command"
        );
        let preentry_calls = AtomicUsize::new(0);
        stage1
            .service_pending_cow_invalidation(&caller_observer, |_| {
                preentry_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<(), ()>(())
            })
            .expect("inactive caller-resident services before next target entry");
        assert_eq!(preentry_calls.load(Ordering::SeqCst), 1);
        assert!(stage1.pending_cow_invalidation(caller_executor).is_none());
    }

    #[test]
    fn foreign_cow_vcpu_budget_one_full_occupancy_never_waits_on_caller_worker_self_ack() {
        let scheduler = carrick_hal::vcpu_sched::HostCondvarScheduler::new(1);
        let occupied = scheduler.acquire(1_711);
        assert_eq!(scheduler.budget(), 1);
        assert!(!scheduler.has_spare_capacity(), "the only vCPU is occupied");

        let census = Arc::new(crate::kernel::GuestExecutorCensus::default());
        let (_pool, stage1) = crate::hvpatch::Stage1MmPool::new_root_for_tests(0x8000, 1)
            .expect("one-slot target stage-1 pool");
        let caller_tid = tid(1_711);
        let caller_executor =
            crate::kernel::objects::ExecutorId::for_transitional_thread(caller_tid)
                .expect("caller executor identity");
        stage1
            .begin_asid_load(caller_executor)
            .expect("record inactive target residency on caller worker")
            .mark_resident()
            .expect("publish inactive target residency");
        let observer = stage1.cow_invalidation_observer(caller_executor);
        let mm = crate::kernel::MmId::from_raw_u64(1_712).expect("test MM");
        let coordinator = Arc::new(crate::dispatch::mm_mutation::MmMutationCoordinator::new(mm));
        let authority = crate::dispatch::mm_mutation::ForeignMmMutationAuthority::new(
            mm,
            coordinator,
            census,
            Arc::clone(&stage1),
        );
        let identity = stage1.foreign_stage1_identity(mm);

        authority
            .with_guard(caller_tid, |mutation| {
                mutation.with_host_alias(|invalidator| {
                    carrick_hal::ForeignMmInvalidator::invalidate_exact_asid(
                        invalidator,
                        identity.binding(),
                        Instant::now() + Duration::from_secs(1),
                    )
                })
            })
            .expect("sole target-MM exclusion")
            .expect("full-occupancy caller must not wait on its own target command");
        assert!(stage1.pending_cow_invalidation(caller_executor).is_some());

        let hardware_calls = AtomicUsize::new(0);
        stage1
            .service_pending_cow_invalidation(&observer, |_| {
                hardware_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<(), ()>(())
            })
            .expect("mandatory exact-target pre-entry service");
        assert_eq!(hardware_calls.load(Ordering::SeqCst), 1);
        scheduler.release(occupied, carrick_hal::vcpu_sched::Yield::Exited);
    }

    #[test]
    fn mm_mutation_alias_waiter_cannot_enter_inner_before_real_pt_pause() {
        let barrier: &'static crate::fork_quiesce::PtQuiesce =
            Box::leak(Box::new(crate::fork_quiesce::PtQuiesce::new()));
        let registry = Arc::new(GenericVcpuRegistry::new());
        let census = Arc::new(crate::kernel::GuestExecutorCensus::default());
        let mut first_executor = enter_for_test(&census, &registry, tid(1591));
        let mut second_executor = enter_for_test(&census, &registry, tid(1592));
        let mm = crate::kernel::MmId::from_raw_u64(91).expect("test MM");
        let coordinator = Arc::new(crate::dispatch::mm_mutation::MmMutationCoordinator::new(mm));

        let mut outer = acquire_mutation_pause_for_test(
            barrier,
            &mut first_executor,
            tid(1591),
            mm,
            Arc::clone(&coordinator),
            PtPauseBudget {
                election: Duration::from_secs(1),
                drain: Duration::from_secs(1),
            },
        )
        .expect("first real page-table pause");
        let mutation = crate::dispatch::mm_mutation::from_pt_pause(&mut outer);
        let permit = mutation.host_alias_permit();
        let alias = coordinator.begin_alias(&permit);

        let worker_coordinator = Arc::clone(&coordinator);
        let (attempted_tx, attempted_rx) = std::sync::mpsc::sync_channel(1);
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            attempted_tx.send(()).expect("announce outer acquisition");
            let mut outer = acquire_mutation_pause_for_test(
                barrier,
                &mut second_executor,
                tid(1592),
                mm,
                Arc::clone(&worker_coordinator),
                PtPauseBudget {
                    election: Duration::from_secs(1),
                    drain: Duration::from_secs(1),
                },
            )
            .expect("second real page-table pause");
            let mutation = crate::dispatch::mm_mutation::from_pt_pause(&mut outer);
            let permit = mutation.host_alias_permit();
            let alias = worker_coordinator.begin_alias(&permit);
            entered_tx.send(()).expect("announce inner alias entry");
            drop(alias);
            drop(permit);
            drop(mutation);
            drop(outer);
        });

        attempted_rx.recv().expect("waiter attempts outer pause");
        assert_eq!(
            entered_rx.recv_timeout(Duration::from_millis(25)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout),
            "a real outer-page-table waiter reached alias work out of order"
        );
        assert_eq!(
            coordinator.alias_waiters(),
            0,
            "inner coordinator must not contain a page-table-exclusion waiter"
        );

        drop(alias);
        drop(permit);
        drop(mutation);
        drop(outer);
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("second editor enters alias only after outer pause releases");
        worker.join().expect("real outer-order worker exits");
    }

    #[test]
    fn pt_pause_probe_abi_and_dtrace_contract() {
        let probes_source = include_str!("../../../carrick-observability/src/probes.rs");
        let dtrace_source = include_str!("../../../../scripts/dtrace/hvpatch-stop-the-world.d");

        // 1. USDT declaration has four i32 arguments.
        assert!(probes_source.contains("fn pt__pause__begin(_: i32, _: i32, _: i32, _: i32) {}"));

        // 2. Real wrapper exact parameter names, types, and order (rejects added 5th arg).
        let wrapper_decl = probes_source
            .split("pub fn pt_pause_begin(")
            .nth(1)
            .expect("real pt_pause_begin wrapper must exist")
            .split(')')
            .next()
            .expect("wrapper parameter list end");
        let wrapper_params: Vec<&str> = wrapper_decl
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(
            wrapper_params,
            vec![
                "coordinator_tid: i32",
                "other_in_guest: i32",
                "waiting_sibling_tid: i32",
                "executor_census: i32",
            ]
        );

        // 3. Real wrapper forwards the exact USDT tuple in the exact order.
        let wrapper_body = probes_source
            .split("pub fn pt_pause_begin(")
            .nth(1)
            .expect("real pt_pause_begin wrapper must exist")
            .split("carrick_usdt::pt__pause__begin!(|| (")
            .nth(1)
            .expect("pt__pause__begin invocation must exist")
            .split("));")
            .next()
            .expect("pt__pause__begin invocation end");
        let forwarded_args: Vec<&str> = wrapper_body
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(
            forwarded_args,
            vec![
                "coordinator_tid",
                "other_in_guest",
                "waiting_sibling_tid",
                "executor_census",
            ]
        );

        // 4. Disabled stub exact parameter names, types, and order (rejects added 5th arg).
        let stub_decl = probes_source
            .split("stub!(pt_pause_begin(")
            .nth(1)
            .expect("pt_pause_begin stub must exist")
            .split("));")
            .next()
            .expect("stub parameter list end");
        let stub_params: Vec<&str> = stub_decl
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(
            stub_params,
            vec![
                "coordinator_tid: i32",
                "other_in_guest: i32",
                "waiting_sibling_tid: i32",
                "executor_census: i32",
            ]
        );

        // 5. Bounded executable DTrace clause in hvpatch-stop-the-world.d.
        let dtrace_clauses: Vec<&str> =
            dtrace_source.split("carrick*:::pt-pause-begin\n").collect();
        let target_clause = dtrace_clauses
            .iter()
            .find(|clause| {
                clause.contains(r#"@c["pt-raised-with-peer-executor-and-no-sibling-lease"]"#)
            })
            .expect("executable pt-pause-begin clause with target aggregation must exist");
        let predicate_end = target_clause.find('{').expect("clause body start");
        let predicate = target_clause[..predicate_end].trim();
        assert_eq!(
            predicate,
            "/(pid == $target || progenyof($target)) && arg2 == 0 && arg3 > 1/"
        );
        let action_end = target_clause.find('}').expect("clause body end");
        let action = target_clause[predicate_end + 1..action_end].trim();
        assert_eq!(
            action,
            r#"@c["pt-raised-with-peer-executor-and-no-sibling-lease"] = count();"#
        );
    }

    #[test]
    fn process_fork_uses_identity_lease_subscription() {
        let source = include_str!("quiesce.rs");
        let prepare = source
            .split("pub(super) fn prepare_in_process_fork")
            .nth(1)
            .unwrap_or_else(|| std::process::abort())
            .split("\n#[cfg(test)]")
            .next()
            .unwrap_or_else(|| std::process::abort());

        assert!(prepare.contains("subscribe_lease_drain"));
        assert!(prepare.contains("ProcessForkRetrySubscription::Lease"));
        assert!(!prepare.contains("kicker.count()"));
        assert!(!prepare.contains("subscribe_quiesced_progress"));
        assert!(!prepare.contains("ProcessForkRetrySubscription::Progress"));
    }

    /// The child-MM install runs under pause-capable page-table authority.
    /// Sole exact-MM authority is transient (a sibling in a lease-releasing
    /// host wait still counts), so demanding it lowered a healthy fork(2) to
    /// EAGAIN on multithreaded parents; the install must take the same
    /// pause-modify-resume arm the stage-1 editors use.
    #[test]
    fn process_fork_install_pauses_peer_executors_instead_of_eagain() {
        let source = include_str!("quiesce.rs");
        let prepare = source
            .split("pub(super) fn prepare_in_process_fork")
            .nth(1)
            .unwrap_or_else(|| std::process::abort())
            .split("\n#[cfg(test)]")
            .next()
            .unwrap_or_else(|| std::process::abort());

        assert!(prepare.contains("acquire_mm_stage1_authority(mm_executor"));
        // Lock order P -> topology: the stage-1 authority is taken before the
        // frame-inventory reservation and the backend topology lock, matching
        // the mmap/munmap editors, so a paused editor can never wait on a
        // topology lock the forker holds while the forker waits for P.
        let authority_at = prepare
            .find("acquire_mm_stage1_authority(mm_executor")
            .expect("fork install acquires stage-1 authority");
        let reserve_at = prepare
            .find(".reserve_frame_inventory(")
            .expect("fork reserves frame inventory");
        let topology_at = prepare
            .find("try_acquire_topology_lock(")
            .expect("fork takes the topology lock");
        assert!(
            authority_at < reserve_at,
            "authority must precede the inventory reservation"
        );
        assert!(
            authority_at < topology_at,
            "authority must precede the topology lock"
        );
        assert!(prepare.contains("MmStage1Authority::Paused(pause)"));
        assert!(prepare.contains("mm_mutation::from_pt_pause(pause)"));
        assert!(!prepare.contains("with_sole_mm_stage1"));
        assert!(!prepare.contains("lost sole exact-MM authority"));
    }

    #[test]
    fn shared_mm_fork_admits_against_exec_reservations_before_kernel_publication() {
        let source = include_str!("quiesce.rs");
        let prepare = source
            .split("pub(super) fn prepare_in_process_fork")
            .nth(1)
            .unwrap_or_else(|| std::process::abort())
            .split("\n#[cfg(test)]")
            .next()
            .unwrap_or_else(|| std::process::abort());

        // The exec reservation is MM-generation scoped and shared by every
        // vfork sibling; the per-process clone-admission gate cannot observe
        // it. The fork must take its shared-publication hold before the
        // stage-1 authority (so a refusal drops nothing) and long before the
        // kernel publishes the child, and a refusal must be a woken Retry.
        let hold_at = prepare
            .find(".hold_owner_set_edit(parent_task)")
            .expect("shared fork admits against the parent's MM generation");
        let authority_at = prepare
            .find("acquire_mm_stage1_authority(mm_executor")
            .expect("fork install acquires stage-1 authority");
        let publish_at = prepare
            .find(".publish_shared_child(parent_task")
            .expect("shared fork publishes its owner edge");
        assert!(hold_at < authority_at, "admission precedes the P authority");
        assert!(hold_at < publish_at, "admission precedes publication");
        assert!(prepare.contains("ProcessForkRetrySubscription::ExecSettlement"));
        assert!(prepare.contains(".subscribe_exec_settlement("));
        let release_at = prepare
            .find("drop(hold);")
            .expect("the hold is released explicitly after publication");
        assert!(publish_at < release_at, "hold outlives publication");
    }

    /// `TaskBusy` from the kernel fork reservation means another operation
    /// (a sibling exit, a parent wait, an exec) is mid-transaction on one of
    /// the reserved tasks. That is a transient ordering condition the fork
    /// must wait out on the reservation epoch, exactly as the clone-admission
    /// close does; surfacing it as `fork(2) = EAGAIN` made Go's `os/exec`
    /// helpers fail under load (`forkabort-E4`, 2026-09-02).
    #[test]
    fn fork_reservation_task_busy_is_retried_on_the_reservation_epoch() {
        let source = include_str!("quiesce.rs");
        let prepare = source
            .split("pub(super) fn prepare_in_process_fork")
            .nth(1)
            .unwrap_or_else(|| std::process::abort())
            .split("\n#[cfg(test)]")
            .next()
            .unwrap_or_else(|| std::process::abort());
        let reserve_at = prepare
            .find("let reservation = match reservation_result {")
            .expect("fork matches its kernel reservation result");
        let reservation_match = &prepare[reserve_at..];
        let match_end = reservation_match
            .find("\n        let shares_mm =")
            .expect("kernel reservation match ends before MM preparation");
        let arm = &reservation_match[..match_end];
        let busy_at = arm
            .find("Err(crate::kernel::KernelOperationError::TaskBusy(")
            .expect("TaskBusy is matched explicitly at the reservation");
        let process_limit_at = arm
            .find("KernelOperationError::ProcessLimitExceeded")
            .expect("expected process-limit refusal is matched explicitly");
        let fallback_at = arm
            .find("\n            Err(error) => {")
            .expect("unexpected reservation failures retain a fallback");
        assert!(
            busy_at < process_limit_at && process_limit_at < fallback_at,
            "TaskBusy and expected process-limit refusal precede the fallback"
        );
        assert!(
            arm[busy_at..process_limit_at].contains("ProcessForkRetrySubscription::Reservation"),
            "TaskBusy is a Retry on the reservation epoch"
        );
        let process_limit_arm = &arm[process_limit_at..fallback_at];
        assert!(process_limit_arm.contains("tracing::debug!"));
        assert!(!process_limit_arm.contains("tracing::warn!"));
        assert!(process_limit_arm.contains("LINUX_EAGAIN"));
        let fallback_arm = &arm[fallback_at..];
        assert!(fallback_arm.contains("tracing::warn!"));
        assert!(fallback_arm.contains("LINUX_EAGAIN"));
        let epoch_at = prepare[..reserve_at]
            .rfind("kernel_graph().reservation_epoch()")
            .expect("the observed epoch is captured before the reservation");
        let reserve_call_at = prepare[..reserve_at]
            .rfind("let reservation_result = ")
            .expect("reservation call precedes its match");
        assert!(
            epoch_at < reserve_call_at,
            "epoch observed before reserving"
        );
    }

    #[test]
    fn fork_lease_wait_wakes_on_terminal_unregister_without_barrier_progress() {
        let registry = GenericVcpuRegistry::new();
        let owner = tid(10);
        let sibling = tid(20);
        let owner_flag = carrick_hal::InGuestFlag::for_guest_thread();
        let sibling_flag = carrick_hal::InGuestFlag::for_guest_thread();
        register_for_test(&registry, owner, &owner_flag);
        register_for_test(&registry, sibling, &sibling_flag);
        let wakes = Arc::new(AtomicUsize::new(0));
        let wake = Arc::clone(&wakes);
        let enrollment = registry.subscribe_lease_drain(
            owner,
            Arc::new(move || {
                wake.fetch_add(1, Ordering::SeqCst);
            }),
        );
        assert!(matches!(
            enrollment,
            carrick_hal::VcpuLeaseDrainEnrollment::Waiting { tid: waiting, .. }
                if waiting == sibling
        ));
        registry.unregister(sibling);
        assert_eq!(wakes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn fork_owner_can_retry_while_its_barrier_remains_raised() {
        let registry = GenericVcpuRegistry::new();
        let barrier = crate::fork_quiesce::QuiesceBarrier::new();
        let owner = tid(10);
        let sibling = tid(20);
        let owner_flag = carrick_hal::InGuestFlag::for_guest_thread();
        let sibling_flag = carrick_hal::InGuestFlag::for_guest_thread();
        register_for_test(&registry, owner, &owner_flag);
        register_for_test(&registry, sibling, &sibling_flag);
        barrier.set_quiescing();
        registry.unregister(owner);
        registry.unregister(sibling);
        assert!(barrier.is_quiescing());
        assert!(matches!(
            registry.subscribe_register(owner, Box::new(NoopKick), &owner_flag, Arc::new(|| {})),
            carrick_hal::VcpuRegistrationEnrollment::Registered
        ));
        assert!(matches!(
            registry.subscribe_lease_drain(owner, Arc::new(|| {})),
            carrick_hal::VcpuLeaseDrainEnrollment::Frozen(_)
        ));
        barrier.end_quiesce();
    }

    #[test]
    fn fork_release_lowers_barriers_before_thaw_callback() {
        let registry = GenericVcpuRegistry::new();
        let barrier = Arc::new(crate::fork_quiesce::QuiesceBarrier::new());
        let owner = tid(10);
        let sibling = tid(20);
        let owner_flag = carrick_hal::InGuestFlag::for_guest_thread();
        register_for_test(&registry, owner, &owner_flag);
        assert!(barrier.try_begin_fork());
        barrier.set_quiescing();
        let guard = match registry.subscribe_lease_drain(owner, Arc::new(|| {})) {
            carrick_hal::VcpuLeaseDrainEnrollment::Frozen(guard) => guard,
            _ => panic!("owner must freeze"),
        };
        let saw_quiescing = Arc::new(AtomicBool::new(true));
        let observed = Arc::clone(&saw_quiescing);
        let sibling_flag = carrick_hal::InGuestFlag::for_guest_thread();
        let registration_wait = registry.subscribe_register(
            sibling,
            Box::new(NoopKick),
            &sibling_flag,
            Arc::new({
                let barrier = Arc::clone(&barrier);
                move || observed.store(barrier.is_quiescing(), Ordering::SeqCst)
            }),
        );
        assert!(matches!(
            &registration_wait,
            carrick_hal::VcpuRegistrationEnrollment::Waiting { .. }
        ));
        let mut release = ProcessForkRelease::new(Arc::clone(&barrier), true, guard);
        release.release();
        assert!(!saw_quiescing.load(Ordering::SeqCst));
        drop(registration_wait);
    }

    #[test]
    fn losing_hvpatch_fork_does_not_enroll_clone_admission() {
        let barrier: &'static crate::fork_quiesce::QuiesceBarrier =
            Box::leak(Box::new(crate::fork_quiesce::QuiesceBarrier::new()));
        assert!(barrier.try_begin_fork(), "model winner owns the fork token");
        let admission = Arc::new(CloneAdmissionGate::default());
        let waiter_admission = Arc::clone(&admission);
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            tx.send(try_begin_hvpatch_process_fork_with_admission(
                barrier,
                tid(1_612),
                &waiter_admission,
            ))
            .unwrap();
            waiter_admission.state.lock().in_flight
        });

        let outcome = rx
            .recv_timeout(Duration::from_millis(20))
            .expect("a losing forker must not wait behind the scheduler");
        assert!(matches!(outcome, ProcessForkStart::Busy));
        assert_eq!(
            waiter.join().unwrap(),
            0,
            "the loser owns no admission permit"
        );
        barrier.end_fork();
    }

    /// A second process fork arriving inside a sibling fork's transient
    /// admission close releases the barrier token it won and reports the
    /// close's epoch so the caller can park on it; only exec/exit closes
    /// are `EAGAIN`.
    #[test]
    fn process_fork_behind_a_sibling_fork_close_is_deferred_with_the_barrier_released() {
        let barrier: &'static crate::fork_quiesce::QuiesceBarrier =
            Box::leak(Box::new(crate::fork_quiesce::QuiesceBarrier::new()));
        let gate = Arc::new(CloneAdmissionGate::default());
        let owner = tid(1_613);
        let sibling = gate
            .enroll_process_fork(owner)
            .admitted()
            .expect("sibling fork admission");
        let close = sibling
            .try_close_for_fork(owner)
            .expect("fork close")
            .expect("no clones in flight");

        let outcome = try_begin_hvpatch_process_fork_with_admission(barrier, tid(1_614), &gate);
        assert!(
            matches!(outcome, ProcessForkStart::AdmissionDeferred { .. }),
            "a transient fork close defers, never EAGAIN"
        );
        assert!(
            barrier.try_begin_fork(),
            "the deferred forker released the barrier token"
        );
        barrier.end_fork();
        drop(close);
        drop(sibling);
        let outcome = try_begin_hvpatch_process_fork_with_admission(barrier, tid(1_614), &gate);
        assert!(matches!(outcome, ProcessForkStart::Admitted { .. }));
        barrier.end_fork();
    }

    #[test]
    fn deferred_process_fork_parks_on_the_admission_epoch() {
        let source = include_str!("quiesce.rs");
        let prepare = source
            .split("pub(super) fn prepare_in_process_fork")
            .nth(1)
            .unwrap_or_else(|| std::process::abort())
            .split("\n#[cfg(test)]")
            .next()
            .unwrap_or_else(|| std::process::abort());
        assert!(prepare.contains("ProcessForkStart::AdmissionDeferred { observed_epoch }"));
        assert!(prepare.contains("ProcessForkRetrySubscription::Admission"));
        assert!(prepare.contains("kernel.clone_admission.subscribe_change("));
    }

    #[test]
    fn inventory_guard_abandons_unpublished_runtime_reservation() {
        let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
            1_530,
            tid(1_530),
            "inventory-abandon".to_owned(),
        )
        .unwrap();
        let (kernel, context) = crate::kernel::Kernel::bootstrap_root(bootstrap).unwrap();
        let reservation = kernel
            .reserve_frame_inventory(
                1,
                1,
                carrick_hal::FrameEventCapacity::for_event_count(2).unwrap(),
            )
            .unwrap();
        let transaction = reservation.transaction();
        let commit = reservation.commit(());
        {
            let _guard = InventoryAbandon::new(kernel.frame_inventory(), [Some(transaction)]);
        }

        assert!(matches!(
            kernel
                .frame_inventory()
                .apply(context.shared().mm().id(), commit),
            Err(crate::kernel::FrameInventoryError::UnreservedTransaction(id)) if id == transaction
        ));
    }

    #[test]
    fn pt_pause_timeout_skips_backend_and_resumes_parked_sibling() {
        let barrier: &'static crate::fork_quiesce::PtQuiesce =
            Box::leak(Box::new(crate::fork_quiesce::PtQuiesce::new()));
        let registry = Arc::new(GenericVcpuRegistry::new());
        // Recorded into `pt-pause-begin` beside the waiting lease identity; these
        // tests exercise the DRAIN, which reads the registry.
        let census = Arc::new(crate::kernel::GuestExecutorCensus::default());
        let coordinator = tid(1501);
        let sibling = tid(1502);
        let mut coordinator_participation = enter_for_test(&census, &registry, coordinator);
        let _sibling_participation = enter_for_test(&census, &registry, sibling);
        let coordinator_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let sibling_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        sibling_in_guest.enter_guest();
        register_for_test(&registry, coordinator, &coordinator_in_guest);
        register_for_test(&registry, sibling, &sibling_in_guest);

        let resumed = Arc::new(AtomicBool::new(false));
        let sibling_resumed = Arc::clone(&resumed);
        let sibling_thread = std::thread::spawn(move || {
            while !barrier.is_quiescing() {
                std::thread::yield_now();
            }
            barrier.park();
            sibling_resumed.store(true, Ordering::SeqCst);
        });
        let backend_repoint_calls = AtomicUsize::new(0);
        let result = acquire_pt_pause(
            barrier,
            &mut coordinator_participation,
            coordinator,
            PtPauseBudget {
                election: Duration::from_secs(30),
                drain: Duration::from_millis(20),
            },
        );
        if result.is_ok() {
            backend_repoint_calls.fetch_add(1, Ordering::SeqCst);
        }

        assert_eq!(result.err(), Some(PtPauseError::TimedOut));
        assert_eq!(backend_repoint_calls.load(Ordering::SeqCst), 0);
        sibling_thread.join().expect("join rolled-back sibling");
        assert!(resumed.load(Ordering::SeqCst));
        assert!(!barrier.is_quiescing());
        assert!(
            barrier.try_become_coordinator(),
            "timeout must release coordinator ownership"
        );
        barrier.end();
    }

    /// A coordinator that never finishes must not wedge the next editor.
    ///
    /// This is the ABBA's second half in isolation: the "coordinator" here
    /// stands in for a thread blocked on a resource the waiter holds. Before the
    /// election bound this test did not fail — it HUNG, because the loser's
    /// `park()` was an unbounded `Condvar::wait` with no deadline to re-check.
    #[test]
    fn pt_pause_election_timeout_gives_up_without_disturbing_the_coordinator() {
        let barrier: &'static crate::fork_quiesce::PtQuiesce =
            Box::leak(Box::new(crate::fork_quiesce::PtQuiesce::new()));
        let registry = Arc::new(GenericVcpuRegistry::new());
        // Recorded into `pt-pause-begin` beside the waiting lease identity; these
        // tests exercise the DRAIN, which reads the registry.
        let census = Arc::new(crate::kernel::GuestExecutorCensus::default());
        let waiter = tid(1521);
        let mut waiter_participation = enter_for_test(&census, &registry, waiter);
        let waiter_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        register_for_test(&registry, waiter, &waiter_in_guest);

        // A stuck coordinator: holds the flags and never calls `end()`.
        assert!(barrier.try_become_coordinator());
        barrier.set_quiescing();

        let result = acquire_pt_pause(
            barrier,
            &mut waiter_participation,
            waiter,
            PtPauseBudget {
                election: Duration::from_millis(50),
                drain: Duration::from_secs(30),
            },
        );

        assert_eq!(result.err(), Some(PtPauseError::TimedOut));
        // The loser must leave the stuck coordinator's state completely alone:
        // calling `end()` from here would drop a pause that is still in force
        // and let the coordinator edit live page tables under running siblings.
        assert!(
            barrier.is_quiescing(),
            "election loser must not clear the live coordinator's pause"
        );
        assert!(
            !barrier.try_become_coordinator(),
            "election loser must not release the live coordinator's ownership"
        );
        assert!(
            !current_thread_holds_pt_pause(),
            "a failed election must leave no pause on this thread"
        );
        barrier.end();
    }

    #[test]
    fn pt_pause_exact_drain_returns_guard_and_allows_backend() {
        let barrier: &'static crate::fork_quiesce::PtQuiesce =
            Box::leak(Box::new(crate::fork_quiesce::PtQuiesce::new()));
        let registry = Arc::new(GenericVcpuRegistry::new());
        // Recorded into `pt-pause-begin` beside the waiting lease identity; these
        // tests exercise the DRAIN, which reads the registry.
        let census = Arc::new(crate::kernel::GuestExecutorCensus::default());
        let coordinator = tid(1511);
        let sibling = tid(1512);
        let mut coordinator_participation = enter_for_test(&census, &registry, coordinator);
        let _sibling_participation = enter_for_test(&census, &registry, sibling);
        let coordinator_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let sibling_in_guest = Arc::new(carrick_hal::InGuestFlag::for_guest_thread());
        sibling_in_guest.enter_guest();
        register_for_test(&registry, coordinator, &coordinator_in_guest);
        assert!(matches!(
            registry.subscribe_register(
                sibling,
                Box::new(LeaveGuestOnKick(Arc::clone(&sibling_in_guest))),
                &sibling_in_guest,
                Arc::new(|| {}),
            ),
            carrick_hal::VcpuRegistrationEnrollment::Registered
        ));

        assert!(!current_thread_holds_pt_pause());
        let guard = acquire_pt_pause(
            barrier,
            &mut coordinator_participation,
            coordinator,
            PtPauseBudget {
                election: Duration::from_secs(30),
                drain: Duration::from_secs(1),
            },
        )
        .expect("sibling drains exactly after kick");
        assert!(
            current_thread_holds_pt_pause(),
            "nested backend work must borrow the syscall's outer pause",
        );
        let backend_repoint_calls = AtomicUsize::new(0);
        backend_repoint_calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(backend_repoint_calls.load(Ordering::SeqCst), 1);
        assert!(barrier.is_quiescing());
        drop(guard);
        assert!(!current_thread_holds_pt_pause());
        assert!(!barrier.is_quiescing());
    }

    #[test]
    fn nested_frame_cow_borrows_exact_mm_lease_and_extends_real_pause() {
        let barrier: &'static crate::fork_quiesce::PtQuiesce =
            Box::leak(Box::new(crate::fork_quiesce::PtQuiesce::new()));
        let registry = Arc::new(GenericVcpuRegistry::new());
        let census = Arc::new(crate::kernel::GuestExecutorCensus::default());
        let coordinator = tid(1513);
        let mut participation = enter_for_test(&census, &registry, coordinator);
        let mm = crate::kernel::MmId::from_registry_allocation(
            std::num::NonZeroU64::new(coordinator.raw() as u64).unwrap(),
        );

        let outer = acquire_pt_pause(
            barrier,
            &mut participation,
            coordinator,
            PtPauseBudget {
                election: Duration::from_secs(1),
                drain: Duration::from_secs(1),
            },
        )
        .expect("outer exact-MM pause");
        let nested = acquire_frame_cow_quiesce(
            barrier,
            mm,
            &census,
            coordinator,
            PtPauseBudget {
                election: Duration::from_millis(10),
                drain: Duration::from_millis(10),
            },
        )
        .expect("nested COW borrows the exact outer lease");

        drop(outer);
        assert!(
            barrier.is_quiescing(),
            "the nested exact-MM lease must keep the real pause alive"
        );
        drop(nested);
        assert!(!barrier.is_quiescing());
    }

    #[test]
    fn exact_mm_pause_drains_distinct_dispatcher_registries_and_blocks_admission() {
        let barrier: &'static crate::fork_quiesce::PtQuiesce =
            Box::leak(Box::new(crate::fork_quiesce::PtQuiesce::new()));
        let census = Arc::new(crate::kernel::GuestExecutorCensus::default());
        let coordinator_registry: Arc<dyn VcpuRegistry> = Arc::new(GenericVcpuRegistry::new());
        let child_registry: Arc<dyn VcpuRegistry> = Arc::new(GenericVcpuRegistry::new());
        let coordinator_tid = tid(1521);
        let child_tid = tid(1522);
        let coordinator_flag = carrick_hal::InGuestFlag::for_guest_thread();
        let child_flag = carrick_hal::InGuestFlag::for_guest_thread();
        let kicks = Arc::new(AtomicUsize::new(0));

        let mut coordinator = census
            .enter_with_pause_endpoint(None, Arc::clone(&coordinator_registry), coordinator_tid)
            .expect("coordinator participation");
        let child = census
            .enter_with_pause_endpoint(None, Arc::clone(&child_registry), child_tid)
            .expect("child participation");
        assert!(matches!(
            coordinator_registry.subscribe_register(
                coordinator_tid,
                Box::new(NoopKick),
                &coordinator_flag,
                Arc::new(|| {}),
            ),
            carrick_hal::VcpuRegistrationEnrollment::Registered
        ));
        assert!(matches!(
            child_registry.subscribe_register(
                child_tid,
                Box::new(RecordKick(Arc::clone(&kicks))),
                &child_flag,
                Arc::new(|| {}),
            ),
            carrick_hal::VcpuRegistrationEnrollment::Registered
        ));
        child_flag.enter_guest();

        let (paused_tx, paused_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let pause_worker = std::thread::spawn(move || {
            let guard = acquire_pt_pause(
                barrier,
                &mut coordinator,
                coordinator_tid,
                PtPauseBudget {
                    election: Duration::from_secs(1),
                    drain: Duration::from_secs(1),
                },
            )
            .expect("cross-dispatcher pause");
            paused_tx.send(()).expect("announce exact-MM pause");
            release_rx.recv().expect("release exact-MM pause");
            drop(guard);
            coordinator
        });

        let kick_deadline = Instant::now() + Duration::from_secs(1);
        while kicks.load(Ordering::SeqCst) == 0 && Instant::now() < kick_deadline {
            std::thread::yield_now();
        }
        assert!(
            kicks.load(Ordering::SeqCst) > 0,
            "child registry was not kicked"
        );
        assert_eq!(
            paused_rx.recv_timeout(Duration::from_millis(25)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout),
            "pause completed while the child dispatcher remained in guest"
        );
        child_flag.leave_guest();
        paused_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("pause completes only after child leaves guest");

        let admission_census = Arc::clone(&census);
        let admission_registry: Arc<dyn VcpuRegistry> = Arc::new(GenericVcpuRegistry::new());
        let (admitted_tx, admitted_rx) = std::sync::mpsc::sync_channel(1);
        let admission = std::thread::spawn(move || {
            let participant = admission_census
                .enter_with_pause_endpoint(None, admission_registry, tid(1523))
                .expect("post-pause participant");
            admitted_tx.send(()).expect("announce admission");
            participant
        });
        assert_eq!(
            admitted_rx.recv_timeout(Duration::from_millis(25)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout),
            "a new exact-MM executor entered during the pause"
        );

        release_tx.send(()).expect("release pause worker");
        let coordinator = pause_worker.join().expect("pause worker");
        admitted_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("admission resumes after pause");
        drop(admission.join().expect("admission worker"));
        drop(coordinator);
        drop(child);
    }

    #[test]
    fn standalone_frame_cow_sole_witness_blocks_exact_mm_admission() {
        let barrier: &'static crate::fork_quiesce::PtQuiesce =
            Box::leak(Box::new(crate::fork_quiesce::PtQuiesce::new()));
        let census = Arc::new(crate::kernel::GuestExecutorCensus::default());
        let registry: Arc<dyn VcpuRegistry> = Arc::new(GenericVcpuRegistry::new());
        let _existing = census
            .enter_with_pause_endpoint(None, registry, tid(1531))
            .expect("existing frame-COW executor");

        let guard = acquire_frame_cow_quiesce(
            barrier,
            crate::kernel::MmId::from_registry_allocation(std::num::NonZeroU64::new(1531).unwrap()),
            &census,
            tid(1531),
            PtPauseBudget {
                election: Duration::from_secs(1),
                drain: Duration::from_secs(1),
            },
        )
        .expect("standalone COW sole witness");

        let admission_census = Arc::clone(&census);
        let admission_registry: Arc<dyn VcpuRegistry> = Arc::new(GenericVcpuRegistry::new());
        let (admitted_tx, admitted_rx) = std::sync::mpsc::sync_channel(1);
        let admission = std::thread::spawn(move || {
            let participant = admission_census
                .enter_with_pause_endpoint(None, admission_registry, tid(1532))
                .expect("frame-COW peer admission");
            admitted_tx.send(()).expect("announce frame-COW peer");
            participant
        });
        assert_eq!(
            admitted_rx.recv_timeout(Duration::from_millis(25)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout),
            "frame-COW sole authority released exact-MM admission"
        );
        drop(guard);
        admitted_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("frame-COW peer enters after sole witness releases");
        drop(admission.join().expect("frame-COW admission worker"));
    }

    #[test]
    fn raised_pt_pause_denies_guest_reentry_until_guard_releases() {
        let production = include_str!("mod.rs")
            .split("fn poll_with_engine(")
            .nth(1)
            .expect("production poll body");
        assert!(
            production.find("enter_guest_or_park").unwrap()
                < production.find("engine.next_syscall()").unwrap(),
            "production must re-check the pause after publishing in-guest and before engine entry"
        );
        let barrier: &'static crate::fork_quiesce::PtQuiesce =
            Box::leak(Box::new(crate::fork_quiesce::PtQuiesce::new()));
        begin_pt_pause(
            barrier,
            tid(1541),
            PtPauseBudget {
                election: Duration::from_secs(1),
                drain: Duration::from_secs(1),
            },
        )
        .expect("raise page-table pause");
        let in_guest = Arc::new(carrick_hal::InGuestFlag::for_guest_thread());
        let worker_flag = Arc::clone(&in_guest);
        let (completed_tx, completed_rx) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let entered = enter_guest_or_park(&worker_flag, barrier);
            completed_tx
                .send(entered)
                .expect("announce re-entry result");
        });

        assert_eq!(
            completed_rx.recv_timeout(Duration::from_millis(25)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout),
            "an executor re-entered guest while page-table pause was raised"
        );
        assert!(
            !in_guest.is_in_guest(),
            "parked executor must withdraw its in-guest publication"
        );

        barrier.end();
        assert!(
            !completed_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("re-entry check resumes after pause")
        );
        worker.join().expect("re-entry worker");
    }

    /// The drain must still see a sibling that went through the blocking-wait
    /// unregister/re-register cycle.
    ///
    /// This is the CONSEQUENCE test for the in-guest registry decay: on a
    /// kicker-refreshing backend (HVF) every futex block unregisters the thread
    /// and re-registers it on wake. When registration carried only the kick
    /// handle, the thread's in-guest flag was gone from the registry forever,
    /// `any_other_in_guest` answered FALSE while the sibling executed guest
    /// code, and `acquire_pt_pause` returned a guard IMMEDIATELY — licensing a
    /// stage-1 page-table edit under a live vCPU with no error, hang, or event.
    /// With one indivisible registration the drain correctly refuses to
    /// complete (here the sibling never leaves, so it is a clean timeout).
    #[test]
    fn pt_pause_drain_sees_a_sibling_that_reregistered_after_a_block() {
        let barrier: &'static crate::fork_quiesce::PtQuiesce =
            Box::leak(Box::new(crate::fork_quiesce::PtQuiesce::new()));
        let registry = Arc::new(GenericVcpuRegistry::new());
        // Recorded into `pt-pause-begin` beside the waiting lease identity; these
        // tests exercise the DRAIN, which reads the registry.
        let census = Arc::new(crate::kernel::GuestExecutorCensus::default());
        let coordinator = tid(1531);
        let sibling = tid(1532);
        let mut coordinator_participation = enter_for_test(&census, &registry, coordinator);
        let _sibling_participation = enter_for_test(&census, &registry, sibling);
        let coordinator_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        // The sibling's ONE lifetime flag, as `ThreadRuntimeState` holds it.
        let sibling_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        register_for_test(&registry, coordinator, &coordinator_in_guest);
        register_for_test(&registry, sibling, &sibling_in_guest);

        // The sibling blocks in a futex: HVF destroys its vCPU, so the runtime
        // unregisters the dead kick handle...
        registry.unregister(sibling);
        // ...and re-registers the rebound vCPU on wake (`register_vcpu`).
        register_for_test(&registry, sibling, &sibling_in_guest);
        // It then re-enters guest code through the flag it has held all along.
        sibling_in_guest.enter_guest();

        let result = acquire_pt_pause(
            barrier,
            &mut coordinator_participation,
            coordinator,
            PtPauseBudget {
                election: Duration::from_secs(30),
                drain: Duration::from_millis(20),
            },
        );
        assert_eq!(
            result.err(),
            Some(PtPauseError::TimedOut),
            "the coordinator must NOT be handed a pause while a re-registered \
             sibling is executing guest code"
        );
        assert!(!barrier.is_quiescing(), "a timeout rolls the request back");
        assert!(barrier.try_become_coordinator());
        barrier.end();
    }
}
