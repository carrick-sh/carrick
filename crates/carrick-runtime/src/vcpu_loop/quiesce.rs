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

    pub(super) async fn handle_fork(
        &mut self,
        kernel: &Kernel,
        kernel_context: &crate::kernel::KernelContext,
        engine: &mut E,
        request: ForkRequest,
    ) -> Result<Option<i64>, RuntimeError> {
        let elapsed_us = |start: std::time::Instant| -> u64 {
            let micros = start.elapsed().as_micros();
            micros.min(u128::from(u64::MAX)) as u64
        };
        let ForkRequest {
            flags,
            pidfd_out,
            clone_parent,
            parent_tid_addr,
            child_tid_addr,
            exit_signal,
            child_stack,
            vfork,
        } = request;
        if engine.supports_in_process_fork() {
            return Err(RuntimeError::Configuration(
                "HVPatch process fork requires the persistent executor transaction".to_owned(),
            ));
        }
        if let Some(reason) = crate::dispatch::SyscallDispatcher::host_fork_file_authority_rejection(
            kernel_context,
            flags,
        ) {
            tracing::warn!(flags, reason, "host-fork file authority rejected clone");
            return Ok(Some(crate::linux_abi::LINUX_EOPNOTSUPP.guest_retval()));
        }
        // vfork (CLONE_VM|CLONE_VFORK): the child SHARES the parent's guest RAM
        // (engine.fork_vfork() below) and the parent vCPU is SUSPENDED here until
        // the child execve's or exits (Parent arm below). An ordinary fork keeps
        // the CoW snapshot and does not suspend.
        // Serialize forks: at most one quiesce/fork in flight. When another fork
        // already holds the token, BLOCK rather than surfacing EAGAIN. Park at the
        // in-flight fork's barrier so it can count this thread as quiesced and
        // complete, then retry the token.
        let phase_start = std::time::Instant::now();
        while !fork_barrier().try_begin_fork() {
            if fork_barrier().is_quiescing() {
                self.release_and_park_vcpu_for_fork(engine)?;
            }
            std::thread::yield_now();
        }
        crate::probes::fork_lifecycle(0, 0, elapsed_us(phase_start), 0, 0);
        // Pre-fork admission gate (fork-path exhaustion degradation): prove the
        // host can admit the CHILD's VM before quiescing or tearing anything
        // down. Persistent exhaustion (a parked fleet pinning HVF's ~127-VM
        // ceiling) becomes Linux-shaped `fork(2) = EAGAIN` with the parent VM
        // untouched, instead of the post-fork HV_NO_RESOURCES fatal ("trap
        // engine failed") that killed engines in the procladder_mt red. Only
        // `end_fork` needs unwinding here — the topology lock, quiesce, and
        // child record all come later. vfork is exempt: its child rebuild
        // bypasses the admission permit (the suspended parent and its child
        // sharing the gate can self-deadlock).
        if vfork.is_none()
            && let Err(error) = engine.fork_admission_check()
        {
            tracing::warn!(
                %error,
                "fork admission gate: host VM capacity exhausted; fork(2) = EAGAIN"
            );
            fork_barrier().end_fork();
            return Ok(Some(crate::linux_abi::LINUX_EAGAIN.guest_retval()));
        }
        // Serialize VM topology against sibling vCPU creation for the whole fork.
        let phase_start = std::time::Instant::now();
        let _topology = crate::fork_quiesce::acquire_topology_lock(
            carrick_observability::probes::HvpatchTopologyOperation::LegacyFork,
            kernel
                .hvpatch_process
                .as_ref()
                .map_or(0, crate::hvpatch::ProcessContext::pid),
            self.this_tid.raw(),
        );
        crate::probes::fork_lifecycle(0, 1, elapsed_us(phase_start), 0, 0);
        // Clear any VM published by a previous fork so siblings that release their
        // vCPUs this round see only THIS fork's republished VM. Also reset the
        // sibling-mapping registry so this round collects a clean set (siblings
        // publish their regions in release_vcpu_for_fork, AFTER the kick below, so
        // clearing here can't race a publish).
        crate::trap::clear_rebuilt_vm_for_fork();
        crate::trap::clear_sibling_fork_mappings();
        // Stop-the-world: a multithreaded guest can fork only if every OTHER guest
        // vCPU thread is first paused at its lock-safe run-loop top.
        //
        // "Other guest vCPU THREAD" is the guest-executor census, not the vCPU
        // registry: the registry counts live LEASES, so a sibling parked in a
        // blocking wait had already unregistered and this read 0, leaving
        // `libc::fork` to run with the barrier down while that sibling could be
        // woken independently. `others` is re-read from the kicker inside the
        // drain below, which is the correct question there.
        let mut others = kernel.guest_executors.live().saturating_sub(1);
        crate::probes::fork_quiesce(
            0,
            others as i64,
            self.kicker.count() as i64,
            self.this_tid.raw(),
        );
        let mut quiesced = false;
        let phase_start = std::time::Instant::now();
        if others > 0 {
            let barrier = fork_barrier();
            barrier.set_quiescing();
            // Wake every other thread so it reaches the barrier: kick in-guest
            // vCPUs, and nudge blocked futex / io_wait waiters. The flag is set
            // FIRST so a woken thread observes `is_quiescing()` and parks.
            self.kicker.kick_all_except(self.this_tid);
            self.platform_futex.notify_signal_pending();
            kernel.signal_arrival.wake_all_waiters();
            // Bound the drain. This loop used to spin FOREVER if a sibling never
            // unregistered (i.e. it is stuck in a blocking host wait whose
            // interrupt predicate omits `is_quiescing()`, so a kick/notify never
            // returns it to the run-loop-top barrier). On HVF that ate ~10 min at
            // 100% CPU with every other sibling parked (sample-confirmed under
            // concurrent os/exec); on KVM it hangs eternally (no VCPU_LIVE abort
            // below). A deadline turns that into a bounded, LOGGED abort whose
            // core (bt all) names the stranded thread — the only way to pin which
            // wait arm is missing the predicate. The window is generous (the
            // normal drain is sub-millisecond) so a merely-slow sibling never
            // trips it. (fork_quiesce_no_lost_wakeup_* proves the barrier
            // coordination itself is sound, so a stall here is a stranded sibling,
            // not a lost wake.)
            let drain_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                // The quiesce is complete only when the KICKER COUNT itself
                // drains to 1 (just this forker). A parking sibling UNREGISTERS
                // first and parks second (`release_and_park_vcpu_for_fork`), so
                // the old predicate — parked count >= `count-1`, both re-read —
                // DOUBLE-COUNTED each parker (once for leaving the count, once
                // for joining `paused`) and was satisfied while a
                // STILL-REGISTERED sibling (e.g. a stage-1 page-table editor
                // mid `pt_pause`) had not parked. libc::fork then landed with
                // the PT barrier's `quiescing=true` and the CHILD inherited it
                // and parked FOREVER at its run-loop top (captured live in gdb
                // on KVM under go-os_exec: the child's PtQuiesce bytes showed
                // coordinator=1/quiescing=1 while the parent's were clear).
                // Draining the count to 1 keeps the original stale-HIGH exit
                // fix too: a vCPU that EXITS mid-quiesce unregisters and drops
                // out of this predicate the same way a parker does. (HVF was
                // immune to the double-count only via its extra VCPU_LIVE<=1
                // wait below.)
                others = self.kicker.count().saturating_sub(1);
                if others == 0 {
                    break;
                }
                if std::time::Instant::now() >= drain_deadline {
                    tracing::error!(
                        others,
                        kicker = self.kicker.count(),
                        paused = barrier.paused_count(),
                        pid = std::process::id(),
                        forker_tid = self.this_tid.raw(),
                        "fork quiesce drain: {others} sibling vCPU(s) failed to reach the \
                         run-loop barrier in 10s — a blocking wait arm is not surfacing \
                         is_quiescing(). Aborting (core: `bt all` names the stranded thread) \
                         rather than spinning forever.",
                    );
                    std::process::abort();
                }
                crate::probes::fork_quiesce(
                    1,
                    others as i64,
                    barrier.paused_count() as i64,
                    self.this_tid.raw(),
                );
                // Do not surface EAGAIN to the guest here. Keep nudging every wait
                // class until all live vCPUs leave the kicker, sleeping briefly
                // between nudges (the parked-count condvar can't be used as the
                // sleep: the same unregister-then-park sequence satisfies it
                // immediately).
                self.kicker.kick_all_except(self.this_tid);
                self.platform_futex.notify_signal_pending();
                kernel.signal_arrival.wake_all_waiters();
                std::thread::sleep(Duration::from_micros(200));
            }
            quiesced = true;
        }
        crate::probes::fork_lifecycle(
            0,
            2,
            elapsed_us(phase_start),
            others as i64,
            self.kicker.count() as i64,
        );

        // INVARIANT before tearing down the VM: no OTHER guest vCPU is live
        // besides this forker's (VCPU_LIVE == 1). Give the kicked siblings a
        // BOUNDED window (sleeping, NOT spinning) to finish releasing; if it still
        // doesn't hold, ABORT LOUDLY rather than proceed into a corrupting
        // hv_vm_destroy (HV_BUSY).
        //
        // HVF-ONLY (unlike the execve drain in `terminate_siblings_for_exec`,
        // which is live on both backends): only HVF tears the parent VM down
        // at fork, so only HVF siblings RELEASE their vCPUs at the quiesce
        // barrier. KVM siblings park KEEPING their vCPUs (VCPU_LIVE stays at
        // the thread count — the fork child rebuilds a fresh VM in its own
        // process instead), so waiting for == 1 here would always time out
        // and abort.
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            use std::sync::atomic::Ordering::SeqCst;
            let phase_start = std::time::Instant::now();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while crate::trap::VCPU_LIVE.load(SeqCst) > 1 {
                if std::time::Instant::now() >= deadline {
                    tracing::error!(
                        vcpu_live = crate::trap::VCPU_LIVE.load(SeqCst),
                        kicker = self.kicker.count(),
                        others,
                        pid = std::process::id(),
                        "fork quiesce failed to release sibling vCPUs in 5s; aborting \
                         to avoid HV_BUSY VM corruption"
                    );
                    std::process::abort();
                }
                self.kicker.kick_all_except(self.this_tid);
                self.platform_futex.notify_signal_pending();
                kernel.signal_arrival.wake_all_waiters();
                std::thread::sleep(std::time::Duration::from_micros(200));
            }
            crate::probes::fork_lifecycle(
                0,
                3,
                elapsed_us(phase_start),
                crate::trap::VCPU_LIVE.load(SeqCst),
                self.kicker.count() as i64,
            );
        }

        // Drain in-flight EXIT CLEANUPS before forking. An exiting thread drops
        // out of the kicker (so the quiesce above stops counting it) and THEN
        // mutates process-global host-signal state under a process-wide mutex.
        // `libc::fork` landing inside that window hands the child a mutex held
        // by a thread that does not exist in it: the child deadlocks on its
        // first touch (observed live on KVM: a vfork child of go-os_exec's
        // TestConcurrentExec wedged forever in inherited signal-state cleanup →
        // parking_lot `lock_slow`, surfacing as "vfork parent-suspend timed
        // out"). The cleanups are short, straight-line, and NEVER block on fork
        // state (the gate is a plain atomic count), so this wait is microseconds;
        // the 5s bound exists only against pathology, and on expiry we proceed
        // (the status-quo risk) rather than kill a healthy guest.
        {
            let phase_start = std::time::Instant::now();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while crate::fork_quiesce::exit_cleanups_in_flight() > 0 {
                if std::time::Instant::now() >= deadline {
                    tracing::error!(
                        in_flight = crate::fork_quiesce::exit_cleanups_in_flight(),
                        "fork: exit-cleanup drain timed out after 5s; forking anyway \
                         (child may inherit a held cleanup lock)"
                    );
                    break;
                }
                std::thread::yield_now();
            }
            crate::probes::fork_lifecycle(
                0,
                4,
                elapsed_us(phase_start),
                crate::fork_quiesce::exit_cleanups_in_flight() as i64,
                0,
            );
        }

        let phase_start = std::time::Instant::now();
        let subphase_start = std::time::Instant::now();
        // A shared-VM backend (KVM vfork) uses the arena high-water to bound its
        // per-window residency scan. HVPatch no longer has a whole-arena child
        // snapshot path.
        let arena_high_water = kernel.dispatcher.mmap_arena_high_water();
        engine.set_vfork_arena_high_water(arena_high_water);
        crate::probes::fork_lifecycle(
            0,
            50,
            elapsed_us(subphase_start),
            arena_high_water.min(i64::MAX as u64) as i64,
            0,
        );
        // vfork: an inherited pipe to SUSPEND the parent until the child
        // execve/_exit. Created BEFORE the fork so BOTH processes inherit BOTH
        // ends; these are host fds (NOT in the guest fd table). On a pipe() failure
        // degrade to a non-suspending shared fork (vfork_pipe = None).
        let subphase_start = std::time::Instant::now();
        let vfork_pipe: Option<(i32, i32)> = if vfork.is_some() {
            let mut fds = [0i32; 2];
            if unsafe { libc::pipe(fds.as_mut_ptr()) } == 0 {
                unsafe {
                    libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
                    libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC);
                }
                Some((fds[0], fds[1]))
            } else {
                None
            }
        } else {
            None
        };
        crate::probes::fork_lifecycle(
            0,
            51,
            elapsed_us(subphase_start),
            i64::from(pidfd_out.is_some()),
            i64::from(vfork_pipe.is_some()),
        );
        let subphase_start = std::time::Instant::now();
        let prepared_fork = kernel.fork.prepare_host_fork();
        crate::probes::fork_lifecycle(0, 52, elapsed_us(subphase_start), 0, 0);
        // Hold the quiesce barrier's internal mutex ACROSS the fork: a sibling
        // parking for this quiesce leaves the kicker count BEFORE it parks
        // (`release_and_park_vcpu_for_fork` unregisters first), so the quiesce
        // wait above can be satisfied while that sibling is still inside
        // `park_if_quiescing`'s lock-increment window HOLDING the barrier
        // mutex — and a fork landing there hands the child the mutex locked
        // forever (captured live on KVM: a vfork child of go-os_exec wedged
        // permanently in `end_quiesce` → `Mutex::lock_contended`). Owning the
        // mutex here excludes that window by mutual exclusion; it is dropped on
        // BOTH sides immediately after the fork, before any barrier call.
        let subphase_start = std::time::Instant::now();
        let paused_guard = fork_barrier().lock_paused_across_fork();
        crate::probes::fork_lifecycle(0, 53, elapsed_us(subphase_start), 0, 0);
        // vfork shares the parent's guest RAM (CLONE_VM); an ordinary fork takes a
        // private CoW snapshot. CRITICAL: gate the SHARE on the suspend pipe
        // existing, NOT on vfork.is_some() — if pipe() failed the parent CANNOT be
        // suspended, and sharing RAM with a running parent silently corrupts guest
        // memory. So a pipe() failure degrades to a plain CoW fork.
        let subphase_start = std::time::Instant::now();
        let child_parent = if clone_parent {
            kernel.dispatcher.clone_parent_host_pid()
        } else {
            std::process::id()
        };
        let child_subreaper = kernel.dispatcher.subreaper_for_fork_child();
        let child_ns_pid = crate::namespace::pid::allocate_child_ns_pid_pre_fork();
        crate::probes::fork_lifecycle(
            0,
            54,
            elapsed_us(subphase_start),
            child_ns_pid.map(i64::from).unwrap_or(-1),
            i64::from(child_parent),
        );
        // Section exhaustion (a guest that forks children nobody ever reaps —
        // SIGCHLD ignored, or the parent exited without a subreaper) is
        // Linux-shaped EAGAIN from fork(2), not a guest abort (spec "Failure
        // model"). Unwind exactly like the engine-fork error arm below, but
        // complete the syscall instead of surfacing a runtime error.
        let subphase_start = std::time::Instant::now();
        let prepared_child_record = match crate::guest_cpu::prepare_child_record_pre_fork(
            child_parent,
            child_subreaper,
            child_ns_pid.unwrap_or(0),
            clone_parent && child_parent != 0,
            0,
        ) {
            Ok(r) => {
                crate::probes::fork_lifecycle(
                    0,
                    55,
                    elapsed_us(subphase_start),
                    child_ns_pid.map(i64::from).unwrap_or(-1),
                    0,
                );
                r
            }
            Err(_exhausted) => {
                crate::probes::fork_lifecycle(
                    0,
                    55,
                    elapsed_us(subphase_start),
                    child_ns_pid.map(i64::from).unwrap_or(-1),
                    -1,
                );
                drop(paused_guard);
                if let Some((r, w)) = vfork_pipe {
                    unsafe {
                        libc::close(r);
                        libc::close(w);
                    }
                }
                if quiesced {
                    fork_barrier().end_quiesce();
                }
                fork_barrier().end_fork();
                kernel.fork.restart_after_fork_error(
                    prepared_fork,
                    &self.kicker,
                    &self.platform_futex,
                );
                return Ok(Some(crate::linux_abi::LINUX_EAGAIN.guest_retval()));
            }
        };
        crate::probes::fork_lifecycle(
            0,
            5,
            elapsed_us(phase_start),
            child_ns_pid.map(i64::from).unwrap_or(-1),
            i64::from(vfork_pipe.is_some()),
        );

        let phase_start = std::time::Instant::now();
        let fork_result = if vfork_pipe.is_some() {
            engine.fork_vfork()
        } else {
            engine.fork()
        };
        let engine_fork_elapsed = elapsed_us(phase_start);
        // Release the barrier mutex FIRST THING on both sides (and on the error
        // path): every arm below calls `end_quiesce` / `park_if_quiescing`,
        // which retake it (self-deadlock if still held).
        drop(paused_guard);
        let fork_outcome = match fork_result {
            Ok(outcome) => outcome,
            Err(error) => {
                if let Some((r, w)) = vfork_pipe {
                    unsafe {
                        libc::close(r);
                        libc::close(w);
                    }
                }
                if quiesced {
                    fork_barrier().end_quiesce();
                }
                crate::guest_cpu::abort_prepared_child_record();
                fork_barrier().end_fork();
                kernel.fork.restart_after_fork_error(
                    prepared_fork,
                    &self.kicker,
                    &self.platform_futex,
                );
                return Err(RuntimeError::Trap(error));
            }
        };
        match &fork_outcome {
            crate::trap::ForkOutcome::Parent { child_pid } => {
                crate::probes::fork_lifecycle(0, 6, engine_fork_elapsed, i64::from(*child_pid), 0);
            }
            crate::trap::ForkOutcome::Child => {
                crate::probes::fork_lifecycle(1, 6, engine_fork_elapsed, 0, 0);
            }
        }

        let retval =
            match fork_outcome {
                crate::trap::ForkOutcome::Parent { child_pid } => {
                    let runtime_repair_start = std::time::Instant::now();
                    // Publish the rebuilt VM so quiesced siblings recreate their vCPUs
                    // in it, THEN resume them.
                    if quiesced {
                        engine.publish_vm_for_siblings()?;
                        fork_barrier().end_quiesce();
                    }
                    fork_barrier().end_fork();
                    let child_exit_needs_signal_pump = kernel
                        .dispatcher
                        .child_exit_signal_needs_pump(kernel_context, self.this_tid, exit_signal);
                    kernel.fork.restart_after_parent_fork(
                        prepared_fork,
                        &self.kicker,
                        &self.platform_futex,
                        child_exit_needs_signal_pump,
                    );
                    // engine.fork() rebuilt this thread's own vCPU, so its old kicker
                    // handle is stale. Re-register the new one (under the topology lock
                    // we still hold).
                    self.register_vcpu(engine);
                    if child_exit_needs_signal_pump {
                        // Watch the child's exit (EVFILT_PROC/NOTE_EXIT) so the signal
                        // pump delivers the requested signal to this (parent) tid when
                        // it exits.
                        crate::host_signal::register_child_exit_watch(
                            child_pid,
                            self.this_tid.raw(),
                            i32::try_from(exit_signal).unwrap_or(crate::linux_abi::LINUX_SIGCHLD),
                        );
                    }
                    crate::event_ring::rec(crate::event_ring::FORK, child_pid, 0, 0);
                    // By REF, not via the global stash: end_fork() above released
                    // fork serialization, so another thread's prepare may already
                    // have overwritten the stash (its publish would then stamp OUR
                    // child pid into THAT record — crossed ns-pids).
                    crate::guest_cpu::publish_prepared_child_record_parent_ref(
                        prepared_child_record,
                        child_pid as u32,
                    );
                    crate::namespace::pid::notify_child_registered();
                    // Seed the child's published run-state as Booting NOW, from the
                    // parent, before this fork returns — so a parent that polls
                    // /proc/<child>/stat immediately (pauseinterrupt2) sees `R`, not
                    // the child's host boot-ppoll `S`. The table is shared, so this is
                    // the same slot the child later updates to Running/Blocked.
                    crate::run_state::publish_child_booting(child_pid as u32);
                    // CLONE_PIDFD: allocate a pidfd for the new child and write its fd
                    // to the guest pidfd-out pointer.
                    if let Some(addr) = pidfd_out {
                        let fd = kernel
                            .dispatcher
                            .install_child_pidfd(kernel_context, child_pid)
                            .unwrap_or(-1);
                        let _ = engine.write_bytes(addr, &fd.to_le_bytes());
                    }
                    // PID namespace: the child's ns-pid was allocated and stored in
                    // its prepared record before fork. Identity when namespaces are off.
                    let retval = i64::from(child_ns_pid.unwrap_or(child_pid as u32));
                    if let Some(addr) = parent_tid_addr {
                        let tid = (retval as i32).to_le_bytes();
                        let _ = engine.write_bytes(addr, &tid);
                    }
                    // vfork: SUSPEND this (parent) vCPU thread until the child execve's
                    // (it writes one byte) or exits (the OS closes the child's write
                    // end → our read() returns EOF). We still hold `_topology`, so no
                    // concurrent fork can quiesce us. Retry on EINTR.
                    if let Some((vf_read, _vf_write)) = vfork_pipe {
                        let vfork_wait_start = std::time::Instant::now();
                        unsafe { libc::close(_vf_write) }; // parent only reads
                        // Bounded suspend: the child should execve/_exit within ms, but
                        // a pathological guest must NOT wedge the parent forever — we
                        // still hold topology_lock here. Poll with a deadline; on expiry
                        // resume the parent DEGRADED with a loud diagnostic.
                        const VFORK_SUSPEND_TIMEOUT: Duration = Duration::from_secs(60);
                        let deadline = std::time::Instant::now() + VFORK_SUSPEND_TIMEOUT;
                        let mut byte = [0u8; 1];
                        loop {
                            let now = std::time::Instant::now();
                            if now >= deadline {
                                tracing::error!(
                                    child_pid,
                                    "vfork parent-suspend timed out (60s) waiting for child \
                                 execve/_exit; resuming parent degraded"
                                );
                                break;
                            }
                            let remaining_ms =
                                (deadline - now).as_millis().min(i32::MAX as u128) as i32;
                            let mut pfd = libc::pollfd {
                                fd: vf_read,
                                events: libc::POLLIN,
                                revents: 0,
                            };
                            let r = unsafe { libc::poll(&mut pfd, 1, remaining_ms) };
                            if r > 0 {
                                // Readable: a byte (child execve'd) or EOF (child exited).
                                let _ = unsafe { libc::read(vf_read, byte.as_mut_ptr().cast(), 1) };
                                break;
                            }
                            if r == 0 {
                                continue; // deadline re-checked at loop top
                            }
                            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                                break; // unexpected poll error — stop waiting
                            }
                            // EINTR → re-poll on the remaining budget.
                        }
                        unsafe { libc::close(vf_read) };
                        // The child has now execve'd or exited, so the shared window is
                        // quiescent. Reconcile the child's shared-VM writes back into
                        // the parent's address space and release the share (KVM's shadow
                        // copy-back; a no-op for backends that shared the RAM directly).
                        // Safe to do unconditionally: a non-vfork-shared backend's hook
                        // is a no-op, and on the pipe-failure degrade path nothing was
                        // armed.
                        engine.finish_vfork_parent();
                        // The vfork child shared the parent's guest RAM until it
                        // execve'd or exited. Its child-side identity stamp therefore
                        // overwrote the shared EL1 shim identity page; restore the
                        // parent's getpid/get*id fast-path values before resuming it.
                        let _ = stamp_identity_page(engine, &kernel.dispatcher, kernel_context);
                        crate::probes::fork_lifecycle(
                            0,
                            9,
                            elapsed_us(vfork_wait_start),
                            i64::from(child_pid),
                            0,
                        );
                    }
                    crate::probes::fork_lifecycle(
                        0,
                        7,
                        elapsed_us(runtime_repair_start),
                        i64::from(child_pid),
                        0,
                    );
                    retval
                }
                crate::trap::ForkOutcome::Child => {
                    let runtime_repair_start = std::time::Instant::now();
                    kernel.dispatcher.clear_output_buffers();
                    // A forked child must NOT inherit its PARENT's vfork suspend-pipe
                    // write end (copied across libc::fork). Drop the inherited copy so
                    // only the genuine vfork child holds the writer.
                    if let Some(stale) = self.vfork_release_fd.take() {
                        unsafe { libc::close(stale) };
                    }
                    // vfork: keep the WRITE end of OUR suspend pipe (close the read end
                    // the parent owns).
                    if let Some((vf_read, vf_write)) = vfork_pipe {
                        unsafe { libc::close(vf_read) };
                        self.vfork_release_fd = Some(vf_write);
                    }
                    // An explicit child stack (clone's stack arg != 0, vfork or
                    // ordinary fork-like clone): run the child on it, exactly as
                    // the kernel does — glibc/musl's `__clone` stub pops the child
                    // function off the NEW stack (LTP clone01 crashed on the
                    // parent's frames without this).
                    let requested_stack = vfork.unwrap_or(child_stack);
                    if requested_stack != 0
                        && let Err(e) = engine.set_guest_sp_el0(requested_stack)
                    {
                        tracing::warn!(?e, "clone: failed to set child stack pointer");
                    }
                    // Don't inherit the parent's accumulated guest CPU time.
                    crate::guest_cpu::reset();
                    self.this_tid = ThreadId::main_from_host_pid();
                    // Kernel child publication already retained the forking thread's
                    // exact mask, altstack, and active handler-frame state.
                    self.registry = Arc::new(ThreadRegistry::new(self.this_tid));
                    crate::thread::set_current_registry(Arc::clone(&self.registry));
                    // The other guest threads do not exist in the child (libc::fork
                    // replicated only the calling thread). Drop their stale bookkeeping:
                    // a fresh futex table (no phantom waiters), a fresh kicker (only
                    // this vCPU is registered below), and an empty thread-handle vec.
                    // The fresh kicker comes from `fresh_fork_kicker()` (object-safe,
                    // so the loop never names the concrete kicker); the fresh concrete
                    // private-futex table is built here and the matching `PlatformFutex`
                    // is derived from it via the threaded-through factory, so the two
                    // stay over the SAME table (the notify-signal-pending consistency
                    // invariant) without naming the backend.
                    let fresh_kicker = engine.fresh_fork_kicker();
                    self.kicker = fresh_kicker;
                    self.futex = Arc::new(crate::thread::FutexTable::new());
                    self.platform_futex = (self.platform_futex_factory)(Arc::clone(&self.futex));
                    self.threads = Arc::new(parking_lot::Mutex::new(Vec::new()));
                    // Same reason as the fresh kicker: the guest-executor census
                    // the child inherited counts PARENT vCPU loops, and
                    // `libc::fork` replicated only the calling thread. Nothing
                    // in the child would ever decrement them, so the child
                    // would raise a stop-the-world barrier on every mapping
                    // syscall for threads that do not exist — and its own fork
                    // drain would then wait on a population it can never reach.
                    kernel.guest_executors.reset_for_forked_child();
                    // Clear the quiesce + fork flags the child inherited (copied) from
                    // the parent so the child's single-threaded run loop runs. Also
                    // reset the inherited parked-thread COUNT: it belongs to PARENT
                    // threads that do not exist here and nothing would ever decrement
                    // it, so a child that later goes multithreaded and forks would
                    // see `wait_quiesced` satisfied by phantom parkers and fork
                    // UNQUIESCED (siblings running mid-anything).
                    fork_barrier().end_quiesce();
                    fork_barrier().end_fork();
                    fork_barrier().reset_paused_for_child();
                    // Also clear the inherited PAGE-TABLE-EDIT pause. If the fork
                    // landed while a parent sibling held `pt_pause` (the editor is
                    // not in the child), the inherited coordinator/quiescing flags
                    // would park this child's run loop FOREVER at its first loop
                    // top (captured live: PtQuiesce bytes coordinator=1/quiescing=1
                    // in a wedged go-os_exec vfork child). The count-drain predicate
                    // above makes that window unreachable going forward; this reset
                    // keeps the child self-healing regardless.
                    pt_barrier().end();
                    crate::event_ring::reinit_after_fork();
                    crate::host_signal::reinit_after_fork();
                    crate::dispatch::reset_fifo_beacons_after_fork_child();
                    kernel.dispatcher.epoll_after_fork_child(kernel_context);
                    // Publish THIS child (new host pid) as Booting in the SHARED
                    // run-state table, before any post-fork boot work that parks the
                    // vCPU in the host's internal boot ppoll — so a parent reading
                    // /proc/<child>/stat sees `R` during boot (as real Linux does),
                    // not the `S` of that boot park. Republished `Running` when the
                    // child's vCPU first resumes guest code (run_vcpu_until_exit top).
                    // Publish the child's host pid on its pre-fork record FIRST:
                    // the run-state publish right after adopts that record (one
                    // record per process), which only works once host_pid is set.
                    crate::guest_cpu::complete_child_record_post_fork_child();
                    crate::run_state::reinit_booting_after_fork();
                    // M:N scheduler: the child inherited the parent's pool but has only
                    // THIS thread, now the child's main (remapped to the child VM's vCPU
                    // 0). Drop the inherited (parent-slot) lease, reset to a fresh pool,
                    // and re-acquire slot 0 — otherwise the child's new threads block on
                    // slots held by parent threads that don't exist here.
                    carrick_hal::vcpu_sched::take_current_lease();
                    carrick_hal::vcpu_sched::global().reset_for_fork();
                    carrick_hal::vcpu_sched::set_current_lease(
                        carrick_hal::vcpu_sched::global().acquire(self.this_tid.raw() as u64),
                    );
                    kernel.dispatcher.proc_after_fork_child();
                    let child_context = kernel
                        .dispatcher
                        .reset_one_task_kernel_binding_for_current_process(
                            kernel_context,
                            self.this_tid,
                        )
                        .unwrap_or_else(|error| {
                            tracing::error!(%error, "rebind host-fork child Kernel authority");
                            std::process::abort();
                        });
                    self.linux_tid = child_context.thread().key().tid;
                    // `libc::fork` changed the execution owner. Replace the
                    // syscall-entry parent context before the common signal
                    // boundary so child delivery cannot use or recapture the
                    // retired parent generation.
                    self.service_kernel_context = Some(child_context.retain_exact());
                    // Re-stamp from the exact child generation published above.
                    let _ = stamp_identity_page(engine, &kernel.dispatcher, &child_context);
                    if let Some(addr) = parent_tid_addr {
                        let tid = (crate::namespace::pid::self_ns_pid() as i32).to_le_bytes();
                        let _ = engine.write_bytes(addr, &tid);
                    }
                    if let Some(addr) = child_tid_addr {
                        let tid = (crate::namespace::pid::self_ns_pid() as i32).to_le_bytes();
                        let _ = engine.write_bytes(addr, &tid);
                    }
                    stamp_guest_tid(engine, self.this_tid, &self.registry, Some(self.linux_tid));
                    kernel.dispatcher.sysv_after_fork_child();
                    self.waiter.replace_after_host_fork(self.this_tid);
                    // This host-fork child carries the calling thread's runtime
                    // state, so it re-publishes its OWN lifetime in-guest flag
                    // into the fresh child kicker along with the new handle.
                    self.register_vcpu(engine);
                    kernel.fork.restart_after_child_fork(
                        prepared_fork,
                        &self.kicker,
                        &self.platform_futex,
                    );
                    crate::probes::fork_lifecycle(1, 8, elapsed_us(runtime_repair_start), 0, 0);
                    0
                }
            };
        Ok(Some(retval))
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
