//! Persistent executor pool management, worker lifecycle coordination,
//! and carrier debug provider publication.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;

use parking_lot::Mutex;

use super::backend::*;
use super::binding::*;
use super::executor_worker;
use super::probe_executor_lifecycle;
use super::settlement::*;
#[cfg(test)]
use crate::kernel::SchedulerError;
use crate::kernel::objects::{ExecutionFailure, ExecutionGeneration, ExecutorId, ThreadKey};
use crate::kernel::{
    ExecutorBinding, ExecutorKick, ExecutorKickToken, ExecutorRegistration, Scheduler,
};
use crate::trap::TrapError;
use carrick_fatal::carrick_fatal;

/// How many `M`s a carrier starts.
///
/// An executor is an `M` in Go's G/M/P: a host thread owning one HVF vCPU
/// lease. Each one binds to a guest CPU (`P`) round-robin at registration, so
/// with more `M`s than `P`s several `M`s share one `P`'s run queue.
///
/// The design's steady state is ONE `M` per `P`
/// (`docs/superpowers/specs/2026-09-07-guest-cpu-scheduler-design.md`), because
/// a carrier that runs ten host threads while telling the guest `nproc` = 4 is
/// the over-subscription a four-worker harness turns into load coupling. That
/// reduction is still NOT taken, but the reason recorded here in round 2 is
/// STALE and the correction matters.
///
/// The shapes first: the guest CPU count is the P-core rule —
/// `host_facts::logical_cpu_count()` is
/// `min(hw.perflevel0.logicalcpu, hw.logicalcpu)` = `min(4, 10)` = 4 on the
/// canonical host — while `bound_workers` is `available_parallelism()` = 10.
/// So `M` = `P` means 4 `M`s, not 10, and it is a real reduction.
///
/// Round 2 recorded that `M` = 4 made `go-go_types` complete its tests
/// (`PASS` on stdout) and then WEDGE in carrier teardown, waiting in
/// `HvpatchLoopResult::wait` for a process-job result that was never
/// published, and concluded that phase 3's `handoffp` was the blocker.
/// **That wedge no longer reproduces.** Measured 2026-09-08 on this branch
/// with `CARRICK_BOUND_EXECUTORS` alternating 4 and 10 on ONE signed binary
/// (`7307cc50`), 3 runs each: every `M` = `P` run finished with 150 `--- PASS`
/// and `wedged=0`. The wedge was the stranded process-job publication main has
/// since fixed, and `carrick-embed`'s `go_types_exit_publishes_every_process_job`
/// is its regression test — it was never the phase-3 dependency.
///
/// What blocks the reduction now is timing, and that measurement is NOT yet
/// conclusive, so the count stays at host parallelism. The same run gave
/// `M` = 4 at 186 s / 95 s / 35 s against `M` = 10 at 55 s (aborted) / 35 s /
/// 50 s, but host load fell monotonically from 30 to 15 across the sequence
/// and the `M` = 4 arm ran FIRST in every pair, so it systematically saw the
/// heavier load; pair 3 (35 s at load 13.85 against 50 s at 15.44) points the
/// other way. A single-variable rerun on a quiet host decides it — that is
/// what `CARRICK_BOUND_EXECUTORS` exists for, and it needs no rebuild.
///
/// Phase 3 (`handoffp`: release the `P` to a spare on entry to a blocking host
/// wait) is still unbuilt, and it remains the mechanism that would make `M` =
/// `P` safe under inline host waits: with one `M` per `P` there is no second
/// `M` on that `P` to cover one that blocks. That is the term to measure if
/// the quiet-host rerun does show `M` = `P` slower.
///
/// `spare_executors` are extra `M`s that hold no `P` and park; phase 3 is what
/// will hand one the `P` of an `M` entering a blocking host call. In THIS
/// phase nothing hands off, so they only park.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutorPoolConfig {
    /// `M`s bound to a guest CPU, round-robin. Several may share one `P`.
    pub bound_workers: usize,
    /// Spare `M`s beyond the bound set.
    pub spare_executors: usize,
    pub vcpu_ceiling: usize,
    pub reserve: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ExecutorPoolConfigError {
    #[error("the backend reports zero available vCPUs")]
    ZeroVcpuCeiling,
}

impl ExecutorPoolConfig {
    fn available(self) -> Result<usize, ExecutorPoolConfigError> {
        if self.vcpu_ceiling == 0 {
            return Err(ExecutorPoolConfigError::ZeroVcpuCeiling);
        }
        Ok(self.vcpu_ceiling.saturating_sub(self.reserve))
    }

    /// `M`s bound to a guest CPU. At least one: a carrier with no `M` runs
    /// nothing.
    pub fn bound_worker_count(self) -> Result<usize, ExecutorPoolConfigError> {
        Ok(self.bound_workers.min(self.available()?).max(1))
    }

    /// Spare `M`s, after the bound set has taken its share of the vCPU
    /// budget. Bounded by the backend's ceiling, never by the request alone.
    pub fn spare_worker_count(self) -> Result<usize, ExecutorPoolConfigError> {
        let remaining = self.available()?.saturating_sub(self.bound_worker_count()?);
        Ok(self.spare_executors.min(remaining))
    }

    pub fn executor_count(self) -> Result<usize, ExecutorPoolConfigError> {
        Ok(self.bound_worker_count()? + self.spare_worker_count()?)
    }
}

/// `M`s bound to a guest CPU.
///
/// Host parallelism by default, with `CARRICK_BOUND_EXECUTORS=` as the exact
/// hatch — `=<guest CPU count>` is the design's `M` = `P`, and the two are the
/// A and B of the ablation the doc on [`ExecutorPoolConfig`] describes. It is
/// an env read rather than a rebuild precisely because the open question is a
/// timing comparison that needs a quiet host and many alternating runs, and a
/// second binary would put a second variable in it.
///
/// The backend's vCPU ceiling is the real bound; this is only the request.
pub fn configured_bound_executors(guest_cpus: usize) -> usize {
    let _ = guest_cpus;
    let host_parallelism = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);
    match std::env::var("CARRICK_BOUND_EXECUTORS") {
        Ok(raw) => raw
            .trim()
            .parse::<usize>()
            .unwrap_or(host_parallelism)
            .max(1),
        Err(_) => host_parallelism,
    }
}

/// Spare `M`s to start beyond the bound set.
///
/// `2 x nproc` per the design, with `CARRICK_SPARE_EXECUTORS=` as the exact
/// hatch (`=0` disables spares for bisection). The backend's vCPU ceiling is
/// the real bound; this is only the request.
pub fn configured_spare_executors(guest_cpus: usize) -> usize {
    match std::env::var("CARRICK_SPARE_EXECUTORS") {
        Ok(raw) => raw.trim().parse::<usize>().unwrap_or(2 * guest_cpus),
        Err(_) => 2 * guest_cpus,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutorPoolEvent {
    Created,
    AuditPassed,
    Claimed {
        thread: ThreadKey,
        generation: ExecutionGeneration,
    },
    Loaded {
        thread: ThreadKey,
        generation: ExecutionGeneration,
    },
    InvalidatedAsid {
        generation: u64,
    },
    TopologyRetrying {
        operation: carrick_observability::probes::HvpatchTopologyOperation,
    },
    OrdinarySyscall {
        thread: ThreadKey,
        generation: ExecutionGeneration,
    },
    KickDelivered {
        thread: ThreadKey,
        generation: ExecutionGeneration,
    },
    Saved {
        thread: ThreadKey,
        generation: ExecutionGeneration,
    },
    SettledBlocked {
        thread: ThreadKey,
        generation: ExecutionGeneration,
    },
    SettledRunnable {
        thread: ThreadKey,
        generation: ExecutionGeneration,
    },
    SettledExited {
        thread: ThreadKey,
        generation: ExecutionGeneration,
    },
    DiscardedRow {
        thread: ThreadKey,
        row_generation: ExecutionGeneration,
        observed_state: String,
        reason: String,
    },
    Failed {
        thread: ThreadKey,
        generation: ExecutionGeneration,
    },
    Destroyed,
    Joined,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutorPoolReceipt {
    pub sequence: u64,
    pub executor: ExecutorId,
    pub event: ExecutorPoolEvent,
}

#[derive(Debug, Default)]
struct ReceiptState {
    next_sequence: u64,
    /// Bounded window of the most recent receipts. Unbounded growth turned
    /// a syscall-churn livelock (setidthreadchurn: ~10^5 quantum events/s)
    /// into a memory leak; the window still holds far more history than any
    /// diagnosis has needed (the debug table reads the last 500).
    events: std::collections::VecDeque<ExecutorPoolReceipt>,
    /// Lifetime lifecycle counters, exact regardless of window eviction —
    /// the pool shutdown report MUST NOT count by scanning the window.
    created: usize,
    destroyed: usize,
}

/// Retained receipt-window capacity (see [`ReceiptState::events`]).
const RECEIPT_WINDOW: usize = 4096;

#[derive(Debug, Default)]
pub(crate) struct ReceiptLog(Mutex<ReceiptState>);

impl ReceiptLog {
    pub(crate) fn record(&self, executor: ExecutorId, event: ExecutorPoolEvent) {
        let mut state = self.0.lock();
        state.next_sequence = state.next_sequence.checked_add(1).unwrap_or_else(|| {
            carrick_fatal!(
                "vcpu_loop::executor_receipt_log",
                "executor receipt log sequence counter overflow: executor_id={:?}",
                executor
            );
        });
        let sequence = state.next_sequence;
        match event {
            ExecutorPoolEvent::Created => state.created += 1,
            ExecutorPoolEvent::Destroyed => state.destroyed += 1,
            _ => {}
        }
        state.events.push_back(ExecutorPoolReceipt {
            sequence,
            executor,
            event,
        });
        while state.events.len() > RECEIPT_WINDOW {
            state.events.pop_front();
        }
    }

    pub(crate) fn snapshot(&self) -> Vec<ExecutorPoolReceipt> {
        self.0.lock().events.iter().cloned().collect()
    }

    /// Exact lifetime (created, destroyed) counts, independent of the
    /// bounded receipt window.
    pub(crate) fn lifecycle_counts(&self) -> (usize, usize) {
        let state = self.0.lock();
        (state.created, state.destroyed)
    }
}

impl crate::kernel::scheduler::DiscardRecorder for ReceiptLog {
    fn record_discard(
        &self,
        executor: ExecutorId,
        thread: ThreadKey,
        row_generation: ExecutionGeneration,
        observed_state: String,
        reason: String,
    ) {
        self.record(
            executor,
            ExecutorPoolEvent::DiscardedRow {
                thread,
                row_generation,
                observed_state,
                reason,
            },
        );
    }
}

pub(crate) struct WorkerKick {
    pub(crate) binding: Mutex<Option<ExecutorBinding>>,
    pub(crate) hardware: Mutex<Option<ExactHardwareKick>>,
    pub(crate) need_resched: AtomicBool,
    receipts: Arc<ReceiptLog>,
    #[cfg(test)]
    delivery_validation_gate: Mutex<Option<Arc<std::sync::Barrier>>>,
    #[cfg(test)]
    delivery_receipt_gate: Mutex<Option<Arc<std::sync::Barrier>>>,
}

impl std::fmt::Debug for WorkerKick {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerKick")
            .field("binding", &*self.binding.lock())
            .field("hardware_published", &self.hardware.lock().is_some())
            .field(
                "hardware_vcpu_id",
                &self.hardware.lock().as_ref().map(|kick| kick.raw_vcpu_id),
            )
            .field("need_resched", &self.need_resched.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl WorkerKick {
    pub(crate) fn new(receipts: Arc<ReceiptLog>) -> Self {
        Self {
            binding: Mutex::new(None),
            hardware: Mutex::new(None),
            need_resched: AtomicBool::new(false),
            receipts,
            #[cfg(test)]
            delivery_validation_gate: Mutex::new(None),
            #[cfg(test)]
            delivery_receipt_gate: Mutex::new(None),
        }
    }

    pub(crate) fn publish_hardware(&self, hardware: ExactHardwareKick) -> bool {
        if hardware.owner_thread_port != current_owner_thread_port()
            || self.hardware.lock().is_some()
        {
            return false;
        }
        *self.hardware.lock() = Some(hardware);
        if self.need_resched.load(Ordering::Acquire)
            && let Some(hardware) = self.hardware.lock().as_ref()
        {
            hardware.handle.kick();
        }
        true
    }

    pub(crate) fn audit_hardware(&self, observed: &ExactHardwareKick) -> Result<(), TrapError> {
        if observed.owner_thread_port != current_owner_thread_port() {
            return Err(TrapError::Hypervisor(
                "hardware kick moved off its exact Mach owner".to_owned(),
            ));
        }
        let hardware = self.hardware.lock();
        let published = hardware.as_ref().ok_or_else(|| {
            TrapError::Hypervisor("worker hardware kick was never published".to_owned())
        })?;
        if published.raw_vcpu_id != observed.raw_vcpu_id
            || published.owner_thread_port != observed.owner_thread_port
        {
            return Err(TrapError::Hypervisor(
                "worker hardware kick identity mismatched its created vCPU".to_owned(),
            ));
        }
        Ok(())
    }

    fn poke_control(&self) {
        self.need_resched.store(true, Ordering::Release);
        if let Some(hardware) = self.hardware.lock().as_ref() {
            hardware.handle.kick();
        }
    }

    #[cfg(test)]
    pub(crate) fn install_delivery_validation_gate(&self, gate: Arc<std::sync::Barrier>) {
        *self.delivery_validation_gate.lock() = Some(gate);
    }

    #[cfg(test)]
    pub(crate) fn install_delivery_receipt_gate(&self, gate: Arc<std::sync::Barrier>) {
        *self.delivery_receipt_gate.lock() = Some(gate);
    }
}

impl ExecutorKick for WorkerKick {
    fn try_bind(&self, binding: ExecutorBinding) -> bool {
        let mut current = self.binding.lock();
        if current.is_some() {
            return false;
        }
        self.need_resched.store(false, Ordering::Release);
        *current = Some(binding);
        true
    }

    fn unbind(&self, binding: ExecutorBinding) {
        let mut current = self.binding.lock();
        if *current == Some(binding) {
            *current = None;
            self.need_resched.store(false, Ordering::Release);
        }
    }

    fn rebind_exact_with(
        &self,
        predecessor: ExecutorBinding,
        successor: ExecutorBinding,
        publish: &mut dyn FnMut() -> bool,
    ) -> bool {
        let mut current = self.binding.lock();
        if *current != Some(predecessor) || predecessor.executor() != successor.executor() {
            return false;
        }
        if !publish() {
            return false;
        }
        *current = Some(successor);
        true
    }

    fn deliver_exact(&self, token: ExecutorKickToken) -> bool {
        let current = self.binding.lock();
        if *current != Some(token.binding()) {
            return false;
        }
        #[cfg(test)]
        if let Some(gate) = self.delivery_validation_gate.lock().clone() {
            gate.wait();
            gate.wait();
        }
        self.need_resched.store(true, Ordering::Release);
        if let Some(hardware) = self.hardware.lock().as_ref() {
            hardware.handle.kick();
        }
        #[cfg(test)]
        if let Some(gate) = self.delivery_receipt_gate.lock().clone() {
            gate.wait();
            gate.wait();
        }
        self.receipts.record(
            token.executor(),
            ExecutorPoolEvent::KickDelivered {
                thread: token.thread(),
                generation: token.generation(),
            },
        );
        drop(current);
        true
    }

    fn current_binding(&self) -> Option<ExecutorBinding> {
        *self.binding.lock()
    }

    fn debug_need_resched(&self) -> Option<bool> {
        Some(self.need_resched.load(Ordering::Acquire))
    }

    fn debug_hardware_kick_published(&self) -> Option<bool> {
        Some(self.hardware.lock().is_some())
    }
}

#[derive(Debug)]
pub(crate) enum WorkerCommand {
    Initialize,
    Run,
    InvalidateAsid {
        generation: crate::hvpatch::AsidGeneration,
        response: mpsc::SyncSender<Result<crate::hvpatch::InvalidationAck, String>>,
    },
    Stop,
}

#[derive(Debug)]
pub(crate) struct StartupStatus {
    pub(crate) index: usize,
    pub(crate) error: Option<String>,
    pub(crate) executor: Option<ExecutorId>,
    pub(crate) kick: Option<Arc<WorkerKick>>,
}

#[derive(Debug)]
pub(crate) struct WorkerOutcome {
    pub(crate) executor: Option<ExecutorId>,
    pub(crate) failure: Option<String>,
    pub(crate) retired: bool,
}

#[derive(Debug)]
struct WorkerHandle {
    command: mpsc::Sender<WorkerCommand>,
    join: JoinHandle<WorkerOutcome>,
    executor: Option<ExecutorId>,
    kick: Option<Arc<WorkerKick>>,
}

#[derive(Debug)]
pub(crate) struct WorkerChannels {
    pub(crate) commands: mpsc::Receiver<WorkerCommand>,
    pub(crate) startup: mpsc::Sender<StartupStatus>,
}

pub(crate) struct WorkerRuntime<'a> {
    pub(crate) registration: &'a ExecutorRegistration,
    pub(crate) kick: &'a Arc<WorkerKick>,
    pub(crate) boundary: &'a WorkerBoundaryAudit,
    pub(crate) receipts: &'a Arc<ReceiptLog>,
    pub(crate) control: &'a PoolControl,
}

#[derive(Debug)]
pub(crate) struct PoolControl {
    usable_workers: std::sync::atomic::AtomicUsize,
    pub(crate) wait_service: crate::vcpu_loop::continuation::CarrierWaitService,
    scheduler: Arc<Scheduler>,
    workers: Mutex<std::collections::BTreeMap<ExecutorId, WorkerControlHandle>>,
}

#[derive(Clone, Debug)]
struct WorkerControlHandle {
    command: mpsc::Sender<WorkerCommand>,
    kick: Arc<WorkerKick>,
}

type PendingAsidInvalidation = (
    ExecutorId,
    mpsc::Receiver<Result<crate::hvpatch::InvalidationAck, String>>,
);
type PendingAsidInvalidations = Vec<PendingAsidInvalidation>;

impl PoolControl {
    fn new(workers: usize, scheduler: Arc<Scheduler>) -> Self {
        Self {
            usable_workers: std::sync::atomic::AtomicUsize::new(workers),
            wait_service: crate::vcpu_loop::continuation::CarrierWaitService::new(Arc::clone(
                &scheduler,
            )),
            scheduler,
            workers: Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    fn register_worker(
        &self,
        executor: ExecutorId,
        command: mpsc::Sender<WorkerCommand>,
        kick: Arc<WorkerKick>,
    ) {
        if self
            .workers
            .lock()
            .insert(executor, WorkerControlHandle { command, kick })
            .is_some()
        {
            carrick_fatal!(
                "vcpu_loop::executor_control",
                "duplicate worker registration in PoolControl: executor={:?}",
                executor
            );
        }
    }

    pub(crate) fn retire_failed_worker(&self) -> bool {
        self.usable_workers.fetch_sub(1, Ordering::AcqRel) == 1
    }

    fn dispatch_invalidation_commands(
        &self,
        generation: crate::hvpatch::AsidGeneration,
        targets: impl IntoIterator<Item = ExecutorId>,
    ) -> Result<PendingAsidInvalidations, String> {
        let workers = self.workers.lock();
        let mut pending = Vec::new();
        for target in targets {
            let worker = workers
                .get(&target)
                .ok_or_else(|| format!("ASID retirement resident executor {target:?} is absent"))?;
            let (response_tx, response_rx) = mpsc::sync_channel(1);
            worker
                .command
                .send(WorkerCommand::InvalidateAsid {
                    generation,
                    response: response_tx,
                })
                .map_err(|_| {
                    format!("ASID retirement executor {target:?} command channel closed")
                })?;
            worker.kick.poke_control();
            pending.push((target, response_rx));
        }
        drop(workers);
        // `WorkerKick::poke_control` reaches only a RUNNING quantum (it sets
        // need_resched and kicks live vCPU hardware). An executor IDLE in
        // `Scheduler::take` holds no hardware and checks need_resched only
        // inside a quantum, so its InvalidateAsid command sat unserviced until
        // it next happened to receive work — for a quiet carrier, never. The
        // exec-from-thread survivor in a forked process (which retires an
        // ASID; the root process's exec does not) then waited forever for
        // that idle peer's ack: execfromthread's container wedge, sampled
        // live as one executor parked in `invalidate_after_exec`'s
        // recv_timeout and another in `Scheduler::take`'s condvar. Poke the
        // queue control so every idle executor bounces out with ControlPoked,
        // services its command channel at loop-top, and acks.
        self.scheduler.poke_executor_control();
        if !pending.is_empty() {
            self.scheduler.poke_executor_control();
        }
        Ok(pending)
    }

    /// Wait for peer invalidation acks WHILE SERVICING this executor's own
    /// `InvalidateAsid` commands. A blocking wait deadlocked whole carriers:
    /// with ten executors each inside a process terminal, every one waited in
    /// `consume_invalidation_acks` for peers that were themselves waiting —
    /// commands are otherwise only serviced between quanta — and the frozen
    /// guests showed all ten executors in `invalidate` with hundreds of
    /// claimable Runnable threads starving (futexforkrequeue). Mutual
    /// servicing breaks the cycle. A `Stop` consumed here is REMEMBERED and
    /// returned so the caller can honor shutdown after the terminal settles —
    /// it must not be lost (shutdown stalls) or treated as an error (it is
    /// routine at pool shutdown).
    #[allow(clippy::too_many_arguments)]
    fn consume_invalidation_acks_servicing<E: PersistentExecutor>(
        &self,
        retirement: &crate::hvpatch::Stage1MmRetirement,
        pending: Vec<(
            ExecutorId,
            mpsc::Receiver<Result<crate::hvpatch::InvalidationAck, String>>,
        )>,
        current: ExecutorId,
        backend: &mut E,
        boundary: &WorkerBoundaryAudit,
        receipts: &ReceiptLog,
        commands: &mpsc::Receiver<WorkerCommand>,
    ) -> Result<bool, String> {
        let mut stop_seen = false;
        // Re-poke cadence: the dispatch-side queue poke can race an executor
        // that is between its epoch check and its condvar enroll, or one that
        // re-enters `Scheduler::take` after servicing an unrelated poke.
        // Waiting here is fail-open without a periodic re-poke — the peer
        // never re-checks its command channel and the ack never comes.
        let mut ticks_since_poke = 0u32;
        for (target, response) in pending {
            let ack = loop {
                match response.recv_timeout(std::time::Duration::from_millis(1)) {
                    Ok(ack) => break ack?,
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(format!(
                            "ASID retirement executor {target:?} lost acknowledgement"
                        ));
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        ticks_since_poke += 1;
                        if ticks_since_poke >= 20 {
                            ticks_since_poke = 0;
                            self.scheduler.poke_executor_control();
                        }
                        loop {
                            match commands.try_recv() {
                                Ok(WorkerCommand::InvalidateAsid {
                                    generation,
                                    response: peer_response,
                                }) => {
                                    if let Err(error) = boundary.audit_runtime(backend) {
                                        let message = format!(
                                            "executor {current:?} failed boundary audit before ASID invalidation: {error}"
                                        );
                                        let _ = peer_response.send(Err(message.clone()));
                                        return Err(message);
                                    }
                                    if let Err(error) = backend.invalidate_asid(generation) {
                                        let message = format!(
                                            "executor {current:?} failed ASID generation {} invalidation: {error}",
                                            generation.generation()
                                        );
                                        let _ = peer_response.send(Err(message.clone()));
                                        return Err(message);
                                    }
                                    receipts.record(
                                        current,
                                        ExecutorPoolEvent::InvalidatedAsid {
                                            generation: generation.generation(),
                                        },
                                    );
                                    probe_executor_lifecycle(
                                    current,
                                    crate::probes::HvpatchExecutorLifecyclePhase::InvalidateAsid,
                                    None,
                                    None,
                                    generation.generation(),
                                );
                                    let _ = peer_response.send(Ok(
                                        crate::hvpatch::InvalidationAck::new(current, generation),
                                    ));
                                }
                                Ok(WorkerCommand::Stop) => stop_seen = true,
                                Ok(WorkerCommand::Initialize | WorkerCommand::Run) => {
                                    return Err(
                                    "executor received an invalid owner-thread command during                                      ASID acknowledgement wait"
                                        .to_owned(),
                                );
                                }
                                Err(mpsc::TryRecvError::Empty) => break,
                                Err(mpsc::TryRecvError::Disconnected) => {
                                    stop_seen = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            };
            retirement
                .acknowledge(ack)
                .map_err(|error| format!("ASID retirement acknowledgement rejected: {error}"))?;
        }
        Ok(stop_seen)
    }

    /// Test-only external invalidation: the caller is OUTSIDE the executor
    /// pool (no command queue of its own to service), so a plain blocking
    /// ack wait cannot deadlock the mutual-servicing way an executor's does.
    #[cfg(test)]
    pub(crate) fn invalidate_external(
        &self,
        retirement: &crate::hvpatch::Stage1MmRetirement,
    ) -> Result<(), String> {
        self.invalidate_external_timeout(retirement, std::time::Duration::from_secs(5))
    }

    #[cfg(test)]
    pub(crate) fn invalidate_external_timeout(
        &self,
        retirement: &crate::hvpatch::Stage1MmRetirement,
        timeout: std::time::Duration,
    ) -> Result<(), String> {
        let pending = self
            .dispatch_invalidation_commands(retirement.asid_generation(), retirement.pending())?;
        for (target, response) in pending {
            let ack = response.recv_timeout(timeout).map_err(|error| {
                format!("ASID retirement executor {target:?} acknowledgement timed out: {error}")
            })??;
            retirement
                .acknowledge(ack)
                .map_err(|error| format!("ASID retirement acknowledgement rejected: {error}"))?;
        }
        Ok(())
    }

    pub(crate) fn invalidate_after_exec<E: PersistentExecutor>(
        &self,
        retirement: &crate::hvpatch::Stage1MmRetirement,
        current: ExecutorId,
        backend: &mut E,
        boundary: &WorkerBoundaryAudit,
        receipts: &ReceiptLog,
        commands: &mpsc::Receiver<WorkerCommand>,
    ) -> Result<bool, String> {
        let generation = retirement.asid_generation();
        let targets = retirement.pending();
        let pending = self.dispatch_invalidation_commands(
            generation,
            targets.iter().copied().filter(|target| *target != current),
        )?;
        if targets.contains(&current) {
            boundary
                .audit_runtime(backend)
                .map_err(|error| error.to_string())?;
            backend
                .invalidate_asid(generation)
                .map_err(|error| error.to_string())?;
            receipts.record(
                current,
                ExecutorPoolEvent::InvalidatedAsid {
                    generation: generation.generation(),
                },
            );
            retirement
                .acknowledge(crate::hvpatch::InvalidationAck::new(current, generation))
                .map_err(|error| error.to_string())?;
        }
        self.consume_invalidation_acks_servicing(
            retirement, pending, current, backend, boundary, receipts, commands,
        )
    }
}

struct HvpatchKernelDebugAuxProvider {
    scheduler: Arc<Scheduler>,
    receipts: Arc<ReceiptLog>,
}

impl HvpatchKernelDebugAuxProvider {
    fn new(scheduler: Arc<Scheduler>, receipts: Arc<ReceiptLog>) -> Self {
        Self {
            scheduler,
            receipts,
        }
    }
}

impl crate::kernel::debug::KernelDebugAuxProvider for HvpatchKernelDebugAuxProvider {
    fn scheduler_rows(&self) -> Vec<crate::kernel::debug::DebugSchedulerRow> {
        let summary = self.scheduler.scheduler_summary();
        vec![crate::kernel::debug::DebugSchedulerRow {
            lifecycle: summary.lifecycle,
            queued_len: summary.queued_len,
            claimed: summary.claimed,
            waiters: summary.waiters.exact(),
            run_queue_locked: summary.waiters.is_run_queue_locked(),
            control_epoch: summary.control_epoch,
            need_resched: summary.need_resched,
            snapshot_count: summary.snapshot_count,
        }]
    }

    fn run_queue_rows(&self) -> Vec<crate::kernel::debug::DebugRunQueueRow> {
        let rows = self.scheduler.snapshot_run_queue_rows();
        rows.into_iter()
            .enumerate()
            .map(|(position, (thread, generation, closing_authorized))| {
                crate::kernel::debug::DebugRunQueueRow {
                    position,
                    thread: crate::kernel::debug::dto::thread_key(thread),
                    generation: generation.raw(),
                    closing_authorized,
                }
            })
            .collect()
    }

    fn executor_rows(&self) -> Vec<crate::kernel::debug::DebugExecutorRow> {
        let entries = self.scheduler.snapshot_executor_entries();
        entries
            .into_iter()
            .map(
                |(
                    id,
                    binding,
                    control_observation_epoch,
                    close_observation_epoch,
                    need_resched,
                    hardware_kick_published,
                )| {
                    crate::kernel::debug::DebugExecutorRow {
                        id: id.raw(),
                        epoch: binding.as_ref().map(|b| b.executor_epoch()),
                        current_binding: binding.map(|b| {
                            crate::kernel::debug::DebugExecutorBindingRow {
                                thread: crate::kernel::debug::dto::thread_key(b.thread()),
                                generation: b.generation().raw(),
                            }
                        }),
                        control_observation_epoch,
                        close_observation_epoch,
                        pending_commands: None,
                        need_resched,
                        hardware_kick_published,
                    }
                },
            )
            .collect()
    }

    fn executor_receipt_rows(
        &self,
    ) -> (
        Vec<crate::kernel::debug::DebugExecutorReceiptRow>,
        Option<crate::kernel::debug::DebugExecutorReceiptSummary>,
    ) {
        let receipts = self.receipts.snapshot();
        let total = receipts.len();
        let start = total.saturating_sub(500);
        let slice = &receipts[start..];
        let returned = slice.len();
        let rows = slice
            .iter()
            .map(|r| {
                let (event_name, thread, generation, observed_state, reason) = match &r.event {
                    ExecutorPoolEvent::Created => ("Created", None, None, None, None),
                    ExecutorPoolEvent::AuditPassed => ("AuditPassed", None, None, None, None),
                    ExecutorPoolEvent::Claimed { thread, generation } => (
                        "Claimed",
                        Some(crate::kernel::debug::dto::thread_key(*thread)),
                        Some(generation.raw()),
                        None,
                        None,
                    ),
                    ExecutorPoolEvent::Loaded { thread, generation } => (
                        "Loaded",
                        Some(crate::kernel::debug::dto::thread_key(*thread)),
                        Some(generation.raw()),
                        None,
                        None,
                    ),
                    ExecutorPoolEvent::InvalidatedAsid { generation } => {
                        ("InvalidatedAsid", None, Some(*generation), None, None)
                    }
                    ExecutorPoolEvent::OrdinarySyscall { thread, generation } => (
                        "OrdinarySyscall",
                        Some(crate::kernel::debug::dto::thread_key(*thread)),
                        Some(generation.raw()),
                        None,
                        None,
                    ),
                    ExecutorPoolEvent::KickDelivered { thread, generation } => (
                        "KickDelivered",
                        Some(crate::kernel::debug::dto::thread_key(*thread)),
                        Some(generation.raw()),
                        None,
                        None,
                    ),
                    ExecutorPoolEvent::Saved { thread, generation } => (
                        "Saved",
                        Some(crate::kernel::debug::dto::thread_key(*thread)),
                        Some(generation.raw()),
                        None,
                        None,
                    ),
                    ExecutorPoolEvent::SettledBlocked { thread, generation } => (
                        "SettledBlocked",
                        Some(crate::kernel::debug::dto::thread_key(*thread)),
                        Some(generation.raw()),
                        None,
                        None,
                    ),
                    ExecutorPoolEvent::SettledRunnable { thread, generation } => (
                        "SettledRunnable",
                        Some(crate::kernel::debug::dto::thread_key(*thread)),
                        Some(generation.raw()),
                        None,
                        None,
                    ),
                    ExecutorPoolEvent::SettledExited { thread, generation } => (
                        "SettledExited",
                        Some(crate::kernel::debug::dto::thread_key(*thread)),
                        Some(generation.raw()),
                        None,
                        None,
                    ),
                    ExecutorPoolEvent::DiscardedRow {
                        thread,
                        row_generation,
                        observed_state,
                        reason,
                    } => (
                        "DiscardedRow",
                        Some(crate::kernel::debug::dto::thread_key(*thread)),
                        Some(row_generation.raw()),
                        Some(observed_state.clone()),
                        Some(reason.clone()),
                    ),
                    ExecutorPoolEvent::Failed { thread, generation } => (
                        "Failed",
                        Some(crate::kernel::debug::dto::thread_key(*thread)),
                        Some(generation.raw()),
                        None,
                        None,
                    ),
                    ExecutorPoolEvent::Destroyed => ("Destroyed", None, None, None, None),
                    ExecutorPoolEvent::Joined => ("Joined", None, None, None, None),
                    ExecutorPoolEvent::TopologyRetrying { .. } => {
                        ("TopologyRetrying", None, None, None, None)
                    }
                };
                crate::kernel::debug::DebugExecutorReceiptRow {
                    sequence: r.sequence,
                    executor: r.executor.raw(),
                    event: event_name.to_owned(),
                    thread,
                    generation,
                    observed_state,
                    reason,
                }
            })
            .collect();
        let summary = Some(crate::kernel::debug::DebugExecutorReceiptSummary {
            total,
            returned,
            message: format!("showing last {returned} of {total} receipts"),
        });
        (rows, summary)
    }
}

pub(crate) struct ExecutorPool<F, R>
where
    F: PersistentExecutorFactory,
    R: TaskBindingResolver<
        <<F as PersistentExecutorFactory>::Executor as PersistentExecutor>::TaskBinding,
    >,
{
    scheduler: Arc<Scheduler>,
    handles: Vec<WorkerHandle>,
    receipts: Arc<ReceiptLog>,
    _factory: std::marker::PhantomData<F>,
    resolver: Arc<R>,
    _debug_aux_provider: Arc<dyn crate::kernel::debug::KernelDebugAuxProvider>,
    debug_aux_registration: crate::kernel::core::DebugAuxProviderRegistration,
    #[cfg(test)]
    pub(crate) control: Arc<PoolControl>,
}

struct DebugAuxProviderPublication {
    kernel: Arc<crate::kernel::Kernel>,
    registration: Option<crate::kernel::core::DebugAuxProviderRegistration>,
}

impl DebugAuxProviderPublication {
    fn new(
        kernel: Arc<crate::kernel::Kernel>,
        registration: crate::kernel::core::DebugAuxProviderRegistration,
    ) -> Self {
        Self {
            kernel,
            registration: Some(registration),
        }
    }

    fn commit(mut self) -> crate::kernel::core::DebugAuxProviderRegistration {
        self.registration
            .take()
            .unwrap_or_else(|| {
                carrick_fatal!(
                    "vcpu_loop::debug_aux_publication",
                    "committing a debug-provider publication after its exact registration was already consumed"
                );
            })
    }
}

impl Drop for DebugAuxProviderPublication {
    fn drop(&mut self) {
        if let Some(registration) = self.registration.take() {
            self.kernel.unregister_debug_aux_provider(registration);
        }
    }
}

impl<F, R> std::fmt::Debug for ExecutorPool<F, R>
where
    F: PersistentExecutorFactory,
    R: TaskBindingResolver<
        <<F as PersistentExecutorFactory>::Executor as PersistentExecutor>::TaskBinding,
    >,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutorPool")
            .field("workers", &self.handles.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("persistent executor pool startup failed: {message}")]
pub struct ExecutorPoolStartError {
    configured_workers: usize,
    message: String,
}

impl ExecutorPoolStartError {
    pub const fn configured_workers(&self) -> usize {
        self.configured_workers
    }
}

#[derive(Debug)]
pub struct ExecutorPoolReport {
    events: Vec<ExecutorPoolReceipt>,
    created: usize,
    destroyed: usize,
    joined: usize,
}

impl ExecutorPoolReport {
    pub const fn created(&self) -> usize {
        self.created
    }

    pub const fn destroyed(&self) -> usize {
        self.destroyed
    }

    pub const fn joined(&self) -> usize {
        self.joined
    }

    pub fn events(&self) -> &[ExecutorPoolReceipt] {
        &self.events
    }
}

#[derive(Debug, thiserror::Error)]
#[error("persistent executor pool shutdown failed: {message}")]
pub struct ExecutorPoolShutdownError {
    report: ExecutorPoolReport,
    retired_workers: usize,
    message: String,
}

impl ExecutorPoolShutdownError {
    pub const fn retired_workers(&self) -> usize {
        self.retired_workers
    }

    pub const fn report(&self) -> &ExecutorPoolReport {
        &self.report
    }
}

impl<F, R> ExecutorPool<F, R>
where
    F: PersistentExecutorFactory,
    R: TaskBindingResolver<
        <<F as PersistentExecutorFactory>::Executor as PersistentExecutor>::TaskBinding,
    >,
{
    pub fn start(
        config: ExecutorPoolConfig,
        scheduler: Arc<Scheduler>,
        factory: Arc<F>,
        resolver: Arc<R>,
        _audit: ExecutorBoundaryAudit,
    ) -> Result<Self, ExecutorPoolStartError> {
        let bound_workers =
            config
                .bound_worker_count()
                .map_err(|error| ExecutorPoolStartError {
                    configured_workers: 0,
                    message: error.to_string(),
                })?;
        let spare_workers =
            config
                .spare_worker_count()
                .map_err(|error| ExecutorPoolStartError {
                    configured_workers: 0,
                    message: error.to_string(),
                })?;
        let configured_workers = bound_workers + spare_workers;
        resolver
            .install_scheduler(&scheduler)
            .map_err(|error| ExecutorPoolStartError {
                configured_workers,
                message: format!("install combined task resolver: {error}"),
            })?;
        let receipts = Arc::new(ReceiptLog::default());
        let debug_aux_provider: Arc<dyn crate::kernel::debug::KernelDebugAuxProvider> = Arc::new(
            HvpatchKernelDebugAuxProvider::new(Arc::clone(&scheduler), Arc::clone(&receipts)),
        );
        let debug_aux_publication = DebugAuxProviderPublication::new(
            Arc::clone(scheduler.kernel()),
            scheduler
                .kernel()
                .register_debug_aux_provider(&debug_aux_provider)
                .map_err(|error| ExecutorPoolStartError {
                    configured_workers,
                    message: format!("publish carrier debug provider: {error}"),
                })?,
        );
        let control = Arc::new(PoolControl::new(configured_workers, Arc::clone(&scheduler)));
        let (startup_tx, startup_rx) = mpsc::channel();
        let mut handles: Vec<WorkerHandle> = Vec::with_capacity(configured_workers);
        for index in 0..configured_workers {
            // The first `bound_workers` bind a guest CPU each (the scheduler
            // assigns them round-robin); the rest are spares that park.
            let is_spare = index >= bound_workers;
            let (command_tx, command_rx) = mpsc::channel();
            let scheduler = Arc::clone(&scheduler);
            let factory = Arc::clone(&factory);
            let resolver = Arc::clone(&resolver);
            let receipts_for_worker = Arc::clone(&receipts);
            let control_for_worker = Arc::clone(&control);
            let startup_tx = startup_tx.clone();
            let join = match std::thread::Builder::new()
                .name(format!("carrick-executor-{index}"))
                .spawn(move || {
                    executor_worker(
                        WorkerSlot { index, is_spare },
                        scheduler,
                        factory,
                        resolver,
                        receipts_for_worker,
                        control_for_worker,
                        WorkerChannels {
                            commands: command_rx,
                            startup: startup_tx,
                        },
                    )
                }) {
                Ok(join) => join,
                Err(error) => {
                    let cleanup_failures = stop_and_join_startup(handles);
                    let mut message = format!("worker {index} spawn failed: {error}");
                    append_failures(&mut message, cleanup_failures);
                    return Err(ExecutorPoolStartError {
                        configured_workers,
                        message,
                    });
                }
            };
            handles.push(WorkerHandle {
                command: command_tx,
                join,
                executor: None,
                kick: None,
            });
        }
        drop(startup_tx);

        let mut startup_failure = None;
        for (index, handle) in handles.iter_mut().enumerate() {
            if startup_failure.is_some() {
                break;
            }
            if handle.command.send(WorkerCommand::Initialize).is_err() {
                startup_failure = Some(format!("worker {index} stopped before initialization"));
                break;
            }
            match startup_rx.recv() {
                Ok(status) if status.index == index && status.error.is_none() => {
                    handle.executor = status.executor;
                    handle.kick = status.kick;
                    if handle.executor.is_none() || handle.kick.is_none() {
                        startup_failure = Some(format!(
                            "worker {index} omitted exact executor/kick startup identity"
                        ));
                    } else {
                        control.register_worker(
                            handle.executor.unwrap_or_else(|| {
                                carrick_fatal!(
                                    "vcpu_loop::executor_pool",
                                    "worker handle missing assigned ExecutorId during pool initialization: worker_index={index}"
                                );
                            }),
                            handle.command.clone(),
                            Arc::clone(
                                handle
                                    .kick
                                    .as_ref()
                                    .unwrap_or_else(|| {
                                        carrick_fatal!(
                                            "vcpu_loop::executor_pool",
                                            "worker handle missing kick synchronization handle during pool initialization: worker_index={index}"
                                        );
                                    }),
                            ),
                        );
                    }
                }
                Ok(status) => {
                    startup_failure = Some(status.error.unwrap_or_else(|| {
                        format!(
                            "worker startup status mismatch: expected {index}, got {}",
                            status.index
                        )
                    }));
                }
                Err(error) => startup_failure = Some(format!("startup channel failed: {error}")),
            }
        }

        if let Some(mut message) = startup_failure {
            append_failures(&mut message, stop_and_join_startup(handles));
            return Err(ExecutorPoolStartError {
                configured_workers,
                message,
            });
        }

        for handle in &handles {
            if handle.command.send(WorkerCommand::Run).is_err() {
                let mut message = "worker stopped before pool publication".to_owned();
                append_failures(&mut message, stop_and_join_startup(handles));
                return Err(ExecutorPoolStartError {
                    configured_workers,
                    message,
                });
            }
        }

        scheduler.install_discard_recorder(
            Arc::clone(&receipts) as Arc<dyn crate::kernel::scheduler::DiscardRecorder>
        );
        let debug_aux_registration = debug_aux_publication.commit();

        Ok(Self {
            scheduler,
            handles,
            receipts,
            _factory: std::marker::PhantomData,
            resolver,
            _debug_aux_provider: debug_aux_provider,
            debug_aux_registration,
            #[cfg(test)]
            control,
        })
    }

    #[cfg(test)]
    pub(crate) fn executor_ids(&self) -> Vec<ExecutorId> {
        self.handles
            .iter()
            .map(|handle| handle.executor.unwrap_or_else(|| std::process::abort()))
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn invalidate_asid_retirement(
        &self,
        retirement: &crate::hvpatch::Stage1MmRetirement,
    ) -> Result<(), String> {
        self.control.invalidate_external(retirement)
    }

    #[cfg(test)]
    pub(crate) fn invalidate_asid_retirement_timeout(
        &self,
        retirement: &crate::hvpatch::Stage1MmRetirement,
        timeout: std::time::Duration,
    ) -> Result<(), String> {
        self.control
            .invalidate_external_timeout(retirement, timeout)
    }

    pub fn shutdown(self) -> Result<ExecutorPoolReport, ExecutorPoolShutdownError> {
        self.scheduler
            .kernel()
            .unregister_debug_aux_provider(self.debug_aux_registration);
        self.scheduler.close();
        let mut failures = Vec::new();
        if let Err(error) = self
            .resolver
            .cancel_dormant(&self.scheduler, ExecutionFailure::SnapshotRestoreFailed)
        {
            failures.push(format!("dormant task cancellation failed: {error}"));
        }
        let mut retired_workers = 0;
        let mut joined = 0;
        for handle in self.handles {
            match handle.join.join() {
                Ok(outcome) => {
                    joined += 1;
                    if outcome.retired {
                        retired_workers += 1;
                    }
                    if let Some(error) = outcome.failure {
                        failures.push(error);
                    }
                    if let Some(executor) = outcome.executor {
                        self.receipts.record(executor, ExecutorPoolEvent::Joined);
                    }
                }
                Err(_) => {
                    retired_workers += 1;
                    failures.push("executor worker panicked outside containment".to_owned());
                }
            }
        }
        // A task can cross Running -> Blocked after the pre-join cancellation
        // snapshot while its worker is completing save/settlement. Joined
        // workers make the generation set stable; cancel that exact successor
        // before waiting for queue closure or logical completion.
        if let Err(error) = self
            .resolver
            .cancel_dormant(&self.scheduler, ExecutionFailure::SnapshotRestoreFailed)
        {
            tracing::error!(%error, "post-join exact dormant cancellation failed");
            carrick_fatal!(
                "vcpu_loop::executor_pool",
                "post-join exact dormant cancellation failed: error={error}"
            );
        }
        self.scheduler.wait_closed();
        let events = self.receipts.snapshot();
        let (created, destroyed) = self.receipts.lifecycle_counts();
        let report = ExecutorPoolReport {
            events,
            created,
            destroyed,
            joined,
        };
        if failures.is_empty() {
            Ok(report)
        } else {
            Err(ExecutorPoolShutdownError {
                report,
                retired_workers,
                message: failures.join("; "),
            })
        }
    }

    #[cfg(test)]
    pub fn submit_root(
        &self,
        thread: Arc<crate::kernel::Thread>,
        generation: ExecutionGeneration,
    ) -> Result<(), SchedulerError> {
        let authority = self.scheduler.admit_root(thread.key(), generation)?;
        self.resolver
            .publish_test_root(&self.scheduler, thread, authority)
    }

    #[cfg(test)]
    pub fn wait_for_event(
        &self,
        predicate: impl Fn(&ExecutorPoolEvent) -> bool,
        timeout: std::time::Duration,
    ) -> Result<(), String> {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if self.receipts.snapshot().iter().any(|r| predicate(&r.event)) {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        Err("timed out waiting for executor pool event".to_owned())
    }
}

fn stop_and_join_startup(handles: Vec<WorkerHandle>) -> Vec<String> {
    for handle in &handles {
        let _ = handle.command.send(WorkerCommand::Stop);
    }
    let mut failures = Vec::new();
    for handle in handles {
        match handle.join.join() {
            Ok(outcome) => {
                if let Some(failure) = outcome.failure {
                    failures.push(failure);
                }
            }
            Err(_) => failures.push("executor worker panicked during startup rollback".to_owned()),
        }
    }
    failures
}

fn append_failures(message: &mut String, failures: Vec<String>) {
    for failure in failures {
        message.push_str("; ");
        message.push_str(&failure);
    }
}

/// Which slot in the pool a worker occupies: its startup-channel index and
/// whether it is a spare `M` (no guest CPU, parks until phase 3's `handoffp`)
/// rather than one guest CPU's own executor.
#[derive(Clone, Copy, Debug)]
pub(crate) struct WorkerSlot {
    pub(crate) index: usize,
    pub(crate) is_spare: bool,
}
