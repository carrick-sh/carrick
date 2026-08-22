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
    memory: &impl GuestMemory,
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

/// Page-table pause ownership is thread-local because the coordinator is the
/// vCPU service thread. Backends can re-enter the authority while a mapping
/// syscall already owns the outer Pause-Modify-Resume transaction (for example,
/// `zero_backing` COW during same-VA mmap reuse). Such a nested acquisition
/// must borrow the outer pause, never park behind itself.
///
/// The marker itself lives in `carrick_hal::stage1_exclusive` rather than here
/// because the ENGINE crates need to read it — they sit below this one — to
/// know that a stage-1 edit is exclusive and its spare sub-tables can be
/// reclaimed. Note the marker is BROADER than pause ownership: a sole guest
/// executor also edits exclusively, without any pause being taken.
pub(super) fn current_thread_holds_pt_pause() -> bool {
    carrick_hal::stage1_exclusive::current_thread_edits_exclusively()
}

/// Holds this thread's stage-1 exclusivity claim for a mapping syscall's whole
/// dispatch. Separate from [`PtPauseGuard`] because exclusivity has two
/// sources: the pause (which raises the same marker, so the two nest harmlessly
/// when both apply) and simply having no peer that can execute guest code.
pub(super) struct Stage1Exclusive {
    _private: (),
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

pub(super) struct PtPauseGuard {
    _inner: crate::fork_quiesce::PtPauseGuard,
}

impl PtPauseGuard {
    fn new(inner: crate::fork_quiesce::PtPauseGuard) -> Self {
        carrick_hal::stage1_exclusive::enter();
        Self { _inner: inner }
    }
}

impl Drop for PtPauseGuard {
    fn drop(&mut self) {
        carrick_hal::stage1_exclusive::exit();
        // `_inner` drops next and resumes sibling vCPUs only after the local
        // ownership marker has been cleared.
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

pub(super) fn inventory_capacity_for_extents(
    extents: usize,
) -> Result<carrick_hal::FrameEventCapacity, RuntimeError> {
    let events = extents.checked_mul(2).ok_or_else(|| {
        RuntimeError::Configuration("HVPatch frame inventory event count overflow".to_owned())
    })?;
    carrick_hal::FrameEventCapacity::for_event_count(events).map_err(|error| {
        RuntimeError::Configuration(format!("invalid HVPatch frame inventory capacity: {error}"))
    })
}

enum ProcessForkStart {
    Busy,
    AdmissionClosed,
    Admitted { admission: CloneAdmissionPermit },
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
    let Some(admission) = admission_gate.try_enroll_process_fork(tid) else {
        barrier.end_fork();
        return ProcessForkStart::AdmissionClosed;
    };
    ProcessForkStart::Admitted { admission }
}

/// Process-wide fork quiesce barrier (defined in `fork_quiesce` so the blocking
/// wait predicates can reach the same instance).
pub(crate) fn fork_barrier() -> &'static crate::fork_quiesce::QuiesceBarrier {
    crate::fork_quiesce::barrier()
}

/// Process-wide page-table-edit Pause-Modify-Resume barrier.
pub(crate) fn pt_barrier() -> &'static crate::fork_quiesce::PtQuiesce {
    crate::fork_quiesce::pt_barrier()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PtPauseError {
    TimedOut,
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

/// `census` is recorded, not consulted: whether to pause at all is decided by
/// the caller (`KernelState::has_peer_guest_executor`). Carrying it into
/// `pt-pause-begin` beside `kicker.count()` keeps the two populations visible
/// side by side, so a reader can never again mistake the lease count for the
/// set of threads that can execute guest code.
pub(super) fn acquire_pt_pause(
    barrier: &'static crate::fork_quiesce::PtQuiesce,
    kicker: &dyn carrick_hal::VcpuRegistry,
    census: &crate::kernel::GuestExecutorCensus,
    tid: ThreadId,
    budget: PtPauseBudget,
) -> Result<PtPauseGuard, PtPauseError> {
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
    crate::probes::pt_pause_begin(
        tid.raw(),
        i32::from(kicker.any_other_in_guest(tid)),
        kicker.count() as i32,
        census.live() as i32,
    );

    let start = Instant::now();
    let deadline = start + budget.drain;
    let mut spins: i32 = 0;
    while kicker.any_other_in_guest(tid) {
        kicker.kick_all_except(tid);
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
    Ok(PtPauseGuard::new(barrier.pause_guard(tid)))
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
}

pub(super) struct PreparedVforkSuspension {
    pub(super) child_pid: i32,
    pub(super) request: SyscallRequest,
    pub(super) child: crate::kernel::TaskKey,
    pub(super) wait: crate::kernel::VforkParentWait,
}

pub(super) enum PreparedInProcessFork {
    Complete(Option<i64>),
    SuspendVfork(PreparedVforkSuspension),
    Retry {
        request: ForkRequest,
        coordinator: Option<ProcessForkCoordinator>,
        _subscription: ProcessForkRetrySubscription,
    },
}

pub(super) enum ProcessForkRetrySubscription {
    Barrier {
        _subscription: carrick_thread::fork_quiesce::QuiesceSubscription,
    },
    Progress {
        _subscription: carrick_thread::fork_quiesce::QuiesceProgressSubscription,
    },
    Topology {
        _subscription: carrick_thread::fork_quiesce::TopologyReleaseSubscription,
    },
    Reservation {
        _subscription: Option<crate::kernel::ReservationChangeSubscription>,
    },
}

pub(super) struct ProcessForkCoordinator {
    barrier: Arc<crate::fork_quiesce::QuiesceBarrier>,
    process_admission: Option<CloneAdmissionPermit>,
    clone_admission: Option<ForkCloneAdmission>,
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
            quiesced: false,
            active: true,
        }
    }

    fn into_parts(mut self) -> (CloneAdmissionPermit, ForkCloneAdmission, bool) {
        self.active = false;
        (
            self.process_admission
                .take()
                .unwrap_or_else(|| std::process::abort()),
            self.clone_admission
                .take()
                .unwrap_or_else(|| std::process::abort()),
            self.quiesced,
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
    }
}

impl<E: ThreadedEngine + 'static> ThreadRuntimeState<E>
where
    E::SiblingSpec: 'static,
    E::ProcessSpec: 'static,
{
    /// Pause sibling vCPUs for a stage-1 page-table edit (mmap/mprotect/munmap),
    /// returning an RAII guard that resumes them on drop. A timeout is a typed
    /// clean failure: nothing is held on the election path and the barrier
    /// request is rolled back on the drain path, so no edit may begin either way.
    pub(super) fn pt_pause(
        &self,
        census: &crate::kernel::GuestExecutorCensus,
    ) -> Result<PtPauseGuard, PtPauseError> {
        acquire_pt_pause(
            pt_barrier(),
            &*self.kicker,
            census,
            self.this_tid,
            PtPauseBudget::DEFAULT,
        )
    }

    pub(super) fn release_and_park_vcpu_for_fork(
        &self,
        engine: &mut E,
    ) -> Result<(), RuntimeError> {
        // A fatal owner reuses the task-local fork barrier to obtain a real
        // stop-the-world point. Publish the complete register file before the
        // kicker unregister makes this sibling count as parked.
        self.publish_crash_registers_if_requested(engine)?;
        if !engine.supports_in_process_fork() {
            engine.release_vcpu_for_fork()?;
        }
        // Drop out of the kicker the instant the vCPU is gone: while parked we
        // have no live vCPU, so another fork must not count us in `others` nor
        // try to kick a destroyed vCPU.
        self.kicker.unregister(self.this_tid);
        self.park_if_fork_quiescing();
        // Recreate the vCPU under the topology lock so vcpu_create cannot race
        // another fork's hv_vm_destroy/create. Register only after it exists.
        {
            let _topo = crate::fork_quiesce::acquire_topology_lock(
                carrick_observability::probes::HvpatchTopologyOperation::VcpuRebind,
                0,
                self.this_tid.raw(),
            );
            if !engine.supports_in_process_fork() {
                engine.rebuild_vcpu_after_fork()?;
            }
            self.register_vcpu(engine);
        }
        Ok(())
    }

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
        M: GuestMemory + 'static,
        O: HvpatchProcessBackendOps<E, M>,
    {
        let ProcessForkAttempt {
            request,
            coordinator,
        } = attempt;
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
        let clone_plan = match crate::kernel::ClonePlan::from_flags(clone_flags) {
            Ok(plan) => plan,
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
                    let _ = wake_scheduler.wake(wake_thread);
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
        let subscribe_progress = || loop {
            let observed = process_barrier.progress_generation();
            let wake_scheduler = Arc::clone(&scheduler);
            match process_barrier.subscribe_quiesced_progress(
                observed,
                Arc::new(move |_| {
                    let _ = wake_scheduler.wake(wake_thread);
                }),
            ) {
                carrick_thread::fork_quiesce::QuiesceProgressEnrollment::Ready(_) => continue,
                carrick_thread::fork_quiesce::QuiesceProgressEnrollment::Subscribed(
                    subscription,
                ) => {
                    break ProcessForkRetrySubscription::Progress {
                        _subscription: subscription,
                    };
                }
            }
        };
        // A losing process forker becomes a blocked logical task. It owns no
        // admission permit, pthread, or vCPU while waiting for the current
        // coordinator's exact barrier publication.
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
                        ProcessForkStart::Busy => {
                            return Ok(PreparedInProcessFork::Retry {
                                request,
                                coordinator: None,
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
                            let _ = wake_scheduler.wake(wake_thread);
                        }),
                    );
                    return Ok(PreparedInProcessFork::Retry {
                        request,
                        coordinator: Some(coordinator),
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
        let mut quiesced = coordinator.quiesced;
        // Raise the barrier whenever this process has ANOTHER thread that can
        // execute guest code. `kicker.count()` counts live vCPU LEASES, so
        // every sibling parked in a futex / epoll / fd wait had already
        // unregistered and this read 0 — and the transaction below then ran
        // with NO BARRIER AT ALL, against siblings whose wake does not require
        // this thread (a host fd readying, an `EVFILT_TIMER`, a cross-process
        // shared-futex wake, or the signal pump). Their run-loop-top quiesce
        // check passed for the same reason: nobody had set `quiescing`.
        //
        // The DRAIN below still keys on the kicker, which is the right question
        // for its own purpose ("has every sibling given its vCPU up yet?") and
        // is satisfied immediately when the siblings were already parked. What
        // matters is that `quiescing` is now RAISED, so a sibling woken
        // mid-transaction parks at the barrier instead of resuming into it.
        // Kernel thread membership is durable across block/preempt/queue
        // boundaries. The executor census is deliberately transient and can be
        // zero while a same-task sibling is wakeable, so it cannot authorize
        // skipping the COW barrier.
        let initial_siblings = parent_context.task().threads().len().saturating_sub(1);
        let quiesce_poll_iterations = 0_u64;
        if initial_siblings > 0 && !quiesced {
            process_barrier.set_quiescing();
            coordinator.quiesced = true;
            quiesced = true;
            self.kicker.kick_all_except(self.this_tid);
            self.futex.notify_signal_pending();
            self.platform_futex.notify_signal_pending();
            kernel.signal_arrival.wake_all_waiters();
        }
        let progress_subscription = quiesced.then(&subscribe_progress);
        if quiesced && self.kicker.count() > 1 {
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
                _subscription: progress_subscription.unwrap_or_else(|| std::process::abort()),
            });
        }
        drop(progress_subscription);
        let (process_fork_admission, fork_clone_admission, quiesced) = coordinator.into_parts();
        let quiesce_elapsed_ns = fork_stage_started
            .elapsed()
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        crate::probes::hvpatch_fork_quiesce(
            carrick_observability::probes::HvpatchForkQuiesce::new(
                parent_pid,
                forking_tid,
                initial_siblings.min(u32::MAX as usize) as u32,
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
            if quiesced {
                process_barrier.end_quiesce();
            }
            process_barrier.end_fork();
            return Ok(PreparedInProcessFork::Complete(Some(
                crate::linux_abi::LINUX_EAGAIN.guest_retval(),
            )));
        }
        // Clone admission is closed and all previously enrolled clone
        // publications have drained before quiescence. Take the authoritative
        // task transaction only after every sibling has either parked or
        // completed its exit transaction. Reserving it before quiescence forms
        // a cycle with a sibling which starts exit concurrently: the fork owns
        // the task and waits for the sibling registration, while the sibling
        // remains registered waiting for the task reservation.
        let reservation = match parent_process.kernel_graph().reserve_fork(
            parent_context,
            clone_plan,
            format!("hvpatch-child-of-{}", parent_process.pid()),
            None,
        ) {
            Ok(reservation) => reservation,
            Err(error) => {
                if quiesced {
                    process_barrier.end_quiesce();
                }
                process_barrier.end_fork();
                tracing::warn!(%error, "hvpatch kernel child reservation failed; fork(2) = EAGAIN");
                return Ok(PreparedInProcessFork::Complete(Some(
                    crate::linux_abi::LINUX_EAGAIN.guest_retval(),
                )));
            }
        };
        let shares_mm = clone_plan.mm() == crate::kernel::CloneObjectMode::Share;
        let child_id = reservation.child_id();
        let child_pid = child_id.raw();
        let parent_task = parent_context.task().key();
        let prepared_mm = if shares_mm {
            match parent_process.mm_resources().lease(parent_task) {
                Ok(lease) => PreparedHvpatchProcessMm::Shared { parent_task, lease },
                Err(error) => {
                    if quiesced {
                        process_barrier.end_quiesce();
                    }
                    process_barrier.end_fork();
                    return Err(RuntimeError::Configuration(format!(
                        "retain exact shared HVPatch MM for vfork: {error}"
                    )));
                }
            }
        } else {
            match parent_process.mm_resources().prepare_child() {
                Ok(prepared) => PreparedHvpatchProcessMm::Copied(prepared),
                Err(error) => {
                    if quiesced {
                        process_barrier.end_quiesce();
                    }
                    process_barrier.end_fork();
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
                    if quiesced {
                        process_barrier.end_quiesce();
                    }
                    process_barrier.end_fork();
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
                if quiesced {
                    process_barrier.end_quiesce();
                }
                process_barrier.end_fork();
                return Err(RuntimeError::Configuration(format!(
                    "prepare authoritative hvpatch child: {error}"
                )));
            }
        };
        let child_mm_id = prepared_fork.child_mm_id();
        let (inventory_preparation, _inventory_abandon) = if shares_mm {
            (
                HvpatchProcessInventoryPreparation::SharedMm {
                    kernel_mm: child_mm_id.raw(),
                },
                None,
            )
        } else {
            let inventory_extent_count = ops.inventory_extent_count(memory);
            let inventory_capacity = match inventory_capacity_for_extents(inventory_extent_count) {
                Ok(capacity) => capacity,
                Err(error) => {
                    if quiesced {
                        process_barrier.end_quiesce();
                    }
                    process_barrier.end_fork();
                    return Err(error);
                }
            };
            let inventory_reservation = match parent_process.kernel_graph().reserve_frame_inventory(
                inventory_extent_count,
                inventory_extent_count,
                inventory_capacity,
            ) {
                Ok(reservation) => reservation,
                Err(error) => {
                    if quiesced {
                        process_barrier.end_quiesce();
                    }
                    process_barrier.end_fork();
                    return Err(RuntimeError::Configuration(format!(
                        "reserve HVPatch child frame inventory: {error}"
                    )));
                }
            };
            let inventory_transaction = inventory_reservation.transaction();
            (
                HvpatchProcessInventoryPreparation::Copied(inventory_reservation),
                Some(InventoryAbandon::new(
                    parent_process.kernel_graph().frame_inventory(),
                    [Some(inventory_transaction)],
                )),
            )
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
                    let _ = wake_scheduler.wake(wake_thread);
                }),
            ) {
                carrick_thread::fork_quiesce::TopologyReleaseEnrollment::Ready(_) => continue,
                carrick_thread::fork_quiesce::TopologyReleaseEnrollment::Subscribed(
                    subscription,
                ) => {
                    if quiesced {
                        process_barrier.end_quiesce();
                    }
                    process_barrier.end_fork();
                    drop(fork_clone_admission);
                    drop(process_fork_admission);
                    return Ok(PreparedInProcessFork::Retry {
                        request,
                        coordinator: None,
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
            if quiesced {
                process_barrier.end_quiesce();
            }
            process_barrier.end_fork();
            return Ok(PreparedInProcessFork::Complete(Some(
                crate::linux_abi::LINUX_EFAULT.guest_retval(),
            )));
        };
        let Some(pidfd_original) = read_optional_fork_output(memory, request.pidfd_out) else {
            if quiesced {
                process_barrier.end_quiesce();
            }
            process_barrier.end_fork();
            return Ok(PreparedInProcessFork::Complete(Some(
                crate::linux_abi::LINUX_EFAULT.guest_retval(),
            )));
        };
        let Some(_child_tid_original) = read_optional_fork_output(memory, request.child_tid_addr)
        else {
            if quiesced {
                process_barrier.end_quiesce();
            }
            process_barrier.end_fork();
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
                    if quiesced {
                        process_barrier.end_quiesce();
                    }
                    process_barrier.end_fork();
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
                shares_mm,
                child_tid,
                forking_tid: self.this_tid,
            },
            identity,
            child_mm_id.raw(),
            asid_generation,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                rollback_pidfd(installed_pidfd);
                if quiesced {
                    process_barrier.end_quiesce();
                }
                process_barrier.end_fork();
                return Err(error);
            }
        };
        emit_fork_runtime_stage(
            carrick_observability::probes::HvpatchForkRuntimeStagePhase::ProcessSpec,
            fork_stage_started,
            child_pid,
        );

        let child_dispatcher = kernel.dispatcher.fork_clone_in_process(
            self.this_tid,
            child_tid,
            parent_process.pid() as u32,
            child_pid as u32,
        );
        let child_exit_signal = i32::try_from(request.exit_signal)
            .ok()
            .filter(|signal| *signal != 0);
        let child_registry = Arc::new(ThreadRegistry::new(child_tid));
        let child_futex = Arc::new(crate::thread::FutexTable::new());
        let child_platform_futex = (self.platform_futex_factory)(Arc::clone(&child_futex));
        let child_threads = Arc::new(parking_lot::Mutex::new(Vec::new()));

        let parent_outputs_published = request.parent_tid_addr.is_none_or(|address| {
            memory
                .write_bytes(address, &child_pid.to_le_bytes())
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
            ops.abort(prepared_backend)
                .unwrap_or_else(|_| std::process::abort());
            if !shares_mm {
                ops.rollback_parent(memory)
                    .unwrap_or_else(|_| std::process::abort());
            }
            rollback_pidfd(installed_pidfd);
            if quiesced {
                process_barrier.end_quiesce();
            }
            process_barrier.end_fork();
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
            ops.abort(prepared_backend)
                .unwrap_or_else(|_| std::process::abort());
            if !shares_mm {
                ops.rollback_parent(memory)
                    .unwrap_or_else(|_| std::process::abort());
            }
            rollback_pidfd(installed_pidfd);
            if quiesced {
                process_barrier.end_quiesce();
            }
            process_barrier.end_fork();
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
            ops.abort(prepared_backend)
                .unwrap_or_else(|_| std::process::abort());
            if !shares_mm {
                ops.rollback_parent(memory)
                    .unwrap_or_else(|_| std::process::abort());
            }
            rollback_pidfd(installed_pidfd);
            if quiesced {
                process_barrier.end_quiesce();
            }
            process_barrier.end_fork();
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
        let child_backend_result = match prepared_mm {
            PreparedHvpatchProcessMm::Copied(prepared) => parent_process
                .mm_resources()
                .publish_child(child_context.task().key(), prepared),
            PreparedHvpatchProcessMm::Shared { parent_task, .. } => parent_process
                .mm_resources()
                .publish_shared_child(parent_task, child_context.task().key()),
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
            Arc::clone(&kernel.fork),
            Arc::clone(&kernel.signal_arrival),
            Some(child_process.clone()),
            kernel.hvpatch_runtime.clone(),
            child_exit_signal,
        ));
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
            guest_executors: Arc::clone(&child_kernel.guest_executors),
            kicker: Arc::clone(&child_kicker),
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

        type HvfEngine = carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Engine;
        let (execution_lease, injected_lease) = ExecutionLeaseCell::injected();
        let mut child_state = ThreadRuntimeState::<HvfEngine>::new(
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
        let mut logical = prepare_hvpatch_logical_job(HvpatchLogicalJobInput {
            kernel: Arc::clone(&child_kernel),
            state: child_state,
            task_backend: ops.make_binding_state(task_backend),
            context: child_context.retain_exact(),
            cpu: task_state,
            generation,
            injected_lease,
            bootstrap_process_child: Some((
                shares_mm,
                request.child_tid_addr.map(|address| (address, child_pid)),
            )),
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
        let shape = if request.clone_parent {
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
        child_kernel.enroll_hvpatch_persistent_process_job(
            logical.result.clone(),
            logical.completion.clone(),
        );
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
        dormant
            .activate(
                &runtime.continuation_services(child_context.kernel()).0,
                Arc::clone(child_context.thread()),
                proof,
            )
            .unwrap_or_else(|error| {
                tracing::error!(child_pid, %error, "activate process child logical job");
                std::process::abort();
            });
        member_publication.commit();
        if let Err(error) = check_hvpatch_process_failpoint(HvpatchProcessFailpoint::Activation) {
            return Err(ops.fail_stop(error));
        }
        let (_, vfork_parent_wait) = started.into_parts();
        if quiesced {
            process_barrier.end_quiesce();
        }
        process_barrier.end_fork();
        // Publication is now authoritative and the child has its execution
        // owner. Reopen clone admission and release the process-fork permit
        // before a possible vfork parent wait: a sibling exec must be able to
        // replace a vfork-suspended caller.
        drop(fork_clone_admission);
        drop(process_fork_admission);
        child_process.trace_lifecycle(
            carrick_observability::probes::HvpatchGuestLifecyclePhase::Fork,
            child_tid,
            0,
        );
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
            return Ok(PreparedInProcessFork::SuspendVfork(
                PreparedVforkSuspension {
                    child_pid,
                    request,
                    child: child_key,
                    wait,
                },
            ));
        }
        Ok(PreparedInProcessFork::Complete(Some(i64::from(child_pid))))
    }
}

#[cfg(test)]
mod pt_pause_tests {
    use super::*;
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

    fn tid(raw: i32) -> ThreadId {
        ThreadId::synthetic_for_tests(raw)
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

    #[test]
    fn inventory_bounds_two_events_per_extent_and_rejects_oversize() {
        assert_eq!(inventory_capacity_for_extents(3).unwrap().get(), 6);
        assert!(
            inventory_capacity_for_extents(
                carrick_hal::MAX_FRAME_INVENTORY_EVENTS_PER_BATCH / 2 + 1
            )
            .is_err()
        );
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
        // Recorded into `pt-pause-begin` beside the lease count; these
        // tests exercise the DRAIN, which reads the registry.
        let census = crate::kernel::GuestExecutorCensus::default();
        let coordinator = tid(1501);
        let sibling = tid(1502);
        let coordinator_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let sibling_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        sibling_in_guest.enter_guest();
        registry.register(coordinator, Box::new(NoopKick), &coordinator_in_guest);
        registry.register(sibling, Box::new(NoopKick), &sibling_in_guest);

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
            &*registry,
            &census,
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
        // Recorded into `pt-pause-begin` beside the lease count; these
        // tests exercise the DRAIN, which reads the registry.
        let census = crate::kernel::GuestExecutorCensus::default();
        let waiter = tid(1521);
        let waiter_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        registry.register(waiter, Box::new(NoopKick), &waiter_in_guest);

        // A stuck coordinator: holds the flags and never calls `end()`.
        assert!(barrier.try_become_coordinator());
        barrier.set_quiescing();

        let result = acquire_pt_pause(
            barrier,
            &*registry,
            &census,
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
        // Recorded into `pt-pause-begin` beside the lease count; these
        // tests exercise the DRAIN, which reads the registry.
        let census = crate::kernel::GuestExecutorCensus::default();
        let coordinator = tid(1511);
        let sibling = tid(1512);
        let coordinator_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let sibling_in_guest = Arc::new(carrick_hal::InGuestFlag::for_guest_thread());
        sibling_in_guest.enter_guest();
        registry.register(coordinator, Box::new(NoopKick), &coordinator_in_guest);
        registry.register(
            sibling,
            Box::new(LeaveGuestOnKick(Arc::clone(&sibling_in_guest))),
            &sibling_in_guest,
        );

        assert!(!current_thread_holds_pt_pause());
        let guard = acquire_pt_pause(
            barrier,
            &*registry,
            &census,
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
        // Recorded into `pt-pause-begin` beside the lease count; these
        // tests exercise the DRAIN, which reads the registry.
        let census = crate::kernel::GuestExecutorCensus::default();
        let coordinator = tid(1531);
        let sibling = tid(1532);
        let coordinator_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        // The sibling's ONE lifetime flag, as `ThreadRuntimeState` holds it.
        let sibling_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        registry.register(coordinator, Box::new(NoopKick), &coordinator_in_guest);
        registry.register(sibling, Box::new(NoopKick), &sibling_in_guest);

        // The sibling blocks in a futex: HVF destroys its vCPU, so the runtime
        // unregisters the dead kick handle...
        registry.unregister(sibling);
        // ...and re-registers the rebound vCPU on wake (`register_vcpu`).
        registry.register(sibling, Box::new(NoopKick), &sibling_in_guest);
        // It then re-enters guest code through the flag it has held all along.
        sibling_in_guest.enter_guest();

        let result = acquire_pt_pause(
            barrier,
            &*registry,
            &census,
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
