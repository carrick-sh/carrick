//! Outcome publication, process graph liveness, and carrier abort recording.
//!
//! Owns the `ProcessGraphLiveness` invariant that supervises container jobs,
//! ensures dead graphs fail closed with post-mortem abort records rather
//! than wedging indefinitely, and manages `HvpatchLoopResult` and external
//! terminal settlements for thread and process completion.

use std::sync::{Arc, Weak};
use std::time::Duration;

use carrick_fatal::carrick_fatal;
use parking_lot::{Condvar, Mutex};

use crate::run_result::{RunResult, RuntimeError};
use crate::vcpu_loop::Kernel;
use crate::vcpu_loop::continuation;
use crate::vcpu_loop::terminal::VcpuLoopOutcome;

/// The only points at which the HVPatch logical loop may give its physical
/// executor back to the pool.  Keeping the list typed makes additions
/// fail-closed: a new suspension site must acquire an explicit save/detach and
/// resume case instead of becoming an implicit async-frame borrow of a vCPU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HvpatchLoopSuspension {
    InitialAdmission,
    BlockedContinuation,
    SchedulerYield,
    ExecSiblingDrain,
    VforkParent,
    Preemption,
    TerminalSiblingDrain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(test)]
pub(crate) enum HvpatchLoopPoll {
    Suspended(HvpatchLoopSuspension),
    Exited,
}

/// How often the runner re-evaluates the process-graph predicate while a
/// container job is outstanding.
///
/// This is DETECTION LATENCY, not a timeout. The verdict below is structural —
/// zero live tasks, zero runnable rows, and a job with no result — so a slow
/// run never trips it however long it takes, and shortening or lengthening this
/// interval cannot change any verdict, only when it is reached.
pub(crate) const LIVENESS_POLL: Duration = Duration::from_millis(250);

/// How long the dead-graph census must hold UNCHANGED before the runner
/// aborts.
///
/// The window exists for one real transient: the last task leaves the registry
/// a moment before its settlement publishes the job's result, so an instant
/// verdict would fire on a run that was about to finish correctly. Requiring
/// the same census across the window means nothing in the graph moved — and
/// with no task, no thread and no runnable row, nothing that could publish the
/// job exists.
pub(crate) const LIVENESS_CONFIRM: Duration = Duration::from_secs(2);

/// How many confirm windows an executor claim may sit on an otherwise dead
/// graph without crossing a claim boundary before it stops counting as
/// liveness.
///
/// The claim term exists for the terminal tail -- exit boundary, `PEXIT_BEGIN`,
/// terminal address-space retirement, `PEXIT_END`, settlement -- which under
/// load runs for longer than one confirm window. It must not also excuse a
/// claim nothing will ever release, so it is bounded rather than absolute. The
/// bound is deliberately far above any tail ever measured (a claim that has
/// crossed no boundary for 64 s at the shipped `LIVENESS_CONFIRM`) so that
/// slowness is never mistaken for a wedge; the invariant's job is to turn an
/// infinite park into a named abort, not to be quick about it.
const LIVENESS_CLAIM_STALL_WINDOWS: u32 = 32;

/// The always-on runner invariant of the kernel-audit design: a container job
/// that cannot be published by anything must not be waited on forever.
///
/// The 2026-09-07 exit wedge is the shape it exists for. A `go build` leader
/// that lost its `exit_group` claim settled without publishing its logical
/// result; every Linux task then retired, every executor parked in
/// `RunQueue::take_row`, one unreapable zombie pid 1 remained, and
/// `ContainerJobGroup::join` waited on an `HvpatchLoopResult` for the life of
/// the process. `f8487d23b` removed that particular publisher gap. This removes
/// the CLASS: after this, a job with no result and no live task is not a hang,
/// it is a named `RuntimeError::KernelAborted` carrying a post-mortem.
/// The one abort a carrier suffered, kept so every later wait is answered by
/// the SAME capture rather than a second, later answer to the same question.
#[derive(Clone)]
pub(crate) struct KernelAbortRecord {
    pub(crate) reason: String,
    pub(crate) post_mortem: Arc<crate::kernel::debug::PostMortem>,
}

impl KernelAbortRecord {
    pub(crate) fn error(&self) -> RuntimeError {
        RuntimeError::KernelAborted {
            reason: self.reason.clone(),
            post_mortem: Arc::clone(&self.post_mortem),
        }
    }
}

#[derive(Clone)]
pub(crate) struct ProcessGraphLiveness {
    pub(crate) kernel: Option<Weak<crate::kernel::Kernel>>,
    pub(crate) scheduler: Option<Arc<crate::kernel::scheduler::Scheduler>>,
    /// Where this carrier's one abort is recorded and re-read.
    pub(crate) recorded: Arc<Mutex<Option<KernelAbortRecord>>>,
    /// Test seam: a census the fixture drives directly, so the confirm state
    /// machine can be exercised without retiring a real root task. Never
    /// constructed outside `cfg(test)`; the shipped path has exactly one
    /// census source, the kernel registry.
    #[cfg(test)]
    pub(crate) fixed_census: Option<Arc<Mutex<Option<GraphCensus>>>>,
    pub(crate) poll: std::time::Duration,
    pub(crate) confirm: std::time::Duration,
}

/// A cheap census of everything that could still publish a job result.
///
/// Deliberately cheap: `task_count`/`zombie_count`/`retired_thread_count` are
/// one registry read each and `queued_len` one queue read, so the invariant
/// costs nothing on a healthy run. `retired_threads` carries no verdict of its
/// own — it is the ACTIVITY fingerprint that makes "unchanged" mean "nothing
/// moved", since a thread retiring between two observations bumps it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GraphCensus {
    pub(crate) tasks: usize,
    pub(crate) zombies: usize,
    pub(crate) retired_threads: usize,
    pub(crate) runnable: usize,
    /// Threads an executor currently holds a claim on.
    pub(crate) claimed: usize,
    /// Claim BOUNDARIES the carrier has crossed. The edge term behind
    /// `claimed`: a claim taken or finished bumps it, so an unchanged census
    /// means no executor crossed a claim boundary, not merely that the same
    /// NUMBER of claims is outstanding.
    pub(crate) claim_boundaries: u64,
}

/// What a census says about a job's chance of ever being published.
///
/// Not a bool, because the two dead shapes are confirmed over different
/// windows: an empty graph is dead as soon as it stops moving, while a graph
/// whose only liveness is an executor claim is dead only once that claim has
/// crossed no boundary for [`LIVENESS_CLAIM_STALL_WINDOWS`] of them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CensusVerdict {
    /// A live task, or a queued row: something can still publish.
    Live,
    /// Nothing holds a thread and nothing is queued.
    Dead,
    /// Nothing but an outstanding executor claim.
    ClaimedOnly,
}

impl GraphCensus {
    /// True when nothing in this census can ever run guest code again.
    ///
    /// Zombies are deliberately NOT liveness: a zombie holds no thread and
    /// runs no code, and the wedge's own zombie is pid 1 with no parent — an
    /// unreapable remain, which is the evidence, not a reason to keep waiting.
    ///
    /// A CLAIM is liveness, and it is the signal the other two cannot see. A
    /// thread is claimed from the moment an executor takes it until
    /// `settle_exited` calls `finish_claim`, which spans the whole terminal
    /// tail: the exit boundary, `PEXIT_BEGIN`, the terminal address-space
    /// retirement, `PEXIT_END`, and the settlement that publishes the job. For
    /// all of that the task is already a zombie (`tasks == 0`) and nothing is
    /// queued (`runnable == 0`), so without this term the predicate calls a
    /// carrier dead while the very settlement it is waiting for is running.
    /// A genuinely stranded claim is released without settling — the count
    /// drops and the verdict still fires — so this costs the invariant no
    /// power over real wedges.
    /// A claim is liveness only while it MOVES, though. An executor that
    /// takes a claim and never releases it holds the census permanently
    /// un-dead, so round 7's unconditional `claimed == 0` term handed this
    /// invariant its own failure mode back: `wait_supervised` parks for the
    /// life of the process behind one stranded claim, which is the hang the
    /// invariant exists to remove, reached through a claim instead of an
    /// empty graph. A settlement in flight and a stranded claim are identical
    /// by INSPECTION and differ only in AGE, so the claim term is bounded --
    /// see [`CensusVerdict::ClaimedOnly`] and [`LIVENESS_CLAIM_STALL_WINDOWS`].
    pub(crate) const fn verdict(&self) -> CensusVerdict {
        if self.tasks > 0 || self.runnable > 0 {
            return CensusVerdict::Live;
        }
        if self.claimed > 0 {
            return CensusVerdict::ClaimedOnly;
        }
        CensusVerdict::Dead
    }
}

impl ProcessGraphLiveness {
    /// A liveness handle with no kernel bound. Used by the pure-unit fixtures
    /// and by any lane that has not published a kernel: it observes nothing and
    /// therefore never fires, which is the only safe answer when the invariant
    /// cannot see the graph it would judge.
    #[cfg(test)]
    pub(crate) fn unbound() -> Self {
        Self {
            kernel: None,
            scheduler: None,
            recorded: Arc::default(),
            fixed_census: None,
            poll: LIVENESS_POLL,
            confirm: LIVENESS_CONFIRM,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_tests(
        kernel: Option<&Arc<crate::kernel::Kernel>>,
        fixed_census: Option<Arc<Mutex<Option<GraphCensus>>>>,
        confirm: std::time::Duration,
    ) -> Self {
        Self {
            kernel: kernel.map(Arc::downgrade),
            scheduler: None,
            recorded: Arc::default(),
            fixed_census,
            poll: std::time::Duration::from_millis(10),
            confirm,
        }
    }

    pub(crate) fn census(&self) -> Option<GraphCensus> {
        #[cfg(test)]
        if let Some(fixed) = &self.fixed_census {
            return *fixed.lock();
        }
        let kernel = self.kernel.as_ref()?.upgrade()?;
        let registry = kernel.registry();
        Some(GraphCensus {
            tasks: registry.task_count(),
            zombies: registry.zombie_count(),
            retired_threads: registry.retired_thread_count(),
            runnable: self
                .scheduler
                .as_ref()
                .map_or(0, |scheduler| scheduler.queued_len()),
            claimed: self
                .scheduler
                .as_ref()
                .map_or(0, |scheduler| scheduler.claimed()),
            claim_boundaries: self
                .scheduler
                .as_ref()
                .map_or(0, |scheduler| scheduler.claim_boundaries()),
        })
    }

    /// Freeze, capture, and build the abort every unpublished job is completed
    /// with.
    ///
    /// The freeze is the existing scheduler control epoch: every executor
    /// bounces out of the run queue with `RunQueueError::ControlPoked` at its
    /// next boundary and cannot claim a new row, so the capture reads a graph
    /// nothing is mutating. No new lock is taken.
    pub(crate) fn abort(&self, reason: crate::kernel::debug::AbortReason) -> RuntimeError {
        // One capture per carrier. A second abort would describe a graph that
        // the FIRST abort already froze and published over, so it could only
        // ever be a later, weaker answer to the same question.
        if let Some(recorded) = self.recorded.lock().as_ref() {
            return recorded.error();
        }
        if let Some(scheduler) = &self.scheduler {
            scheduler.poke_executor_control();
        }
        let kernel = self.kernel.as_ref().and_then(Weak::upgrade);
        let run_id = std::env::var("CARRICK_RUN_ID")
            .ok()
            .filter(|id| !id.is_empty());
        let mut post_mortem =
            crate::kernel::debug::PostMortem::capture(kernel.as_ref(), reason, run_id);
        post_mortem.enrich_from_capture();
        let summary = post_mortem.reason.summary();
        tracing::error!(
            target: "carrick::kernel::post_mortem",
            reason = %summary,
            "kernel aborted"
        );
        post_mortem.persist_if_configured();
        let record = KernelAbortRecord {
            reason: summary,
            post_mortem: Arc::new(post_mortem),
        };
        let error = record.error();
        *self.recorded.lock() = Some(record);
        error
    }

    /// The abort this carrier already suffered, if any.
    pub(crate) fn recorded(&self) -> Option<RuntimeError> {
        self.recorded.lock().as_ref().map(KernelAbortRecord::error)
    }

    /// How long a census whose only liveness is an executor claim must hold
    /// unchanged before it is a verdict. See [`LIVENESS_CLAIM_STALL_WINDOWS`].
    pub(crate) fn claim_stall(&self) -> std::time::Duration {
        self.confirm
            .saturating_mul(LIVENESS_CLAIM_STALL_WINDOWS)
            .max(self.poll)
    }

    pub(crate) fn liveness_abort(
        &self,
        census: GraphCensus,
        unpublished_jobs: usize,
    ) -> RuntimeError {
        self.abort(crate::kernel::debug::AbortReason::ProcessGraphLiveness {
            unpublished_jobs,
            live_tasks: census.tasks,
            // Filled from the capture's own rows: naming a zombie costs a
            // snapshot, and one taken before the freeze would describe a
            // different graph from the one in the post-mortem.
            live_threads: 0,
            runnable_rows: census.runnable,
            zombies: Vec::new(),
            confirmed_after_ms: u64::try_from(self.confirm.as_millis()).unwrap_or(u64::MAX),
        })
    }
}

pub(crate) struct HvpatchLoopResultState {
    result: Mutex<Option<Result<VcpuLoopOutcome, RuntimeError>>>,
    ready: Condvar,
}

#[derive(Clone)]
pub(crate) struct HvpatchLoopResult {
    state: Arc<HvpatchLoopResultState>,
}

impl HvpatchLoopResult {
    pub(crate) fn pending() -> Self {
        Self {
            state: Arc::new(HvpatchLoopResultState {
                result: Mutex::new(None),
                ready: Condvar::new(),
            }),
        }
    }

    pub(crate) fn publish(&self, result: Result<VcpuLoopOutcome, RuntimeError>) {
        let mut slot = self.state.result.lock();
        if slot.is_some() {
            carrick_fatal!(
                "kernel::task_activation",
                "TaskActivationProof was published more than once"
            );
        }
        *slot = Some(result);
        self.state.ready.notify_all();
        crate::event_ring::rec_hvpatch_settle_object(Arc::as_ptr(&self.state) as usize, 18);
    }

    #[cfg(test)]
    pub(crate) fn is_ready(&self) -> bool {
        self.state.result.lock().is_some()
    }

    /// Publish `result` only if nothing has published yet.
    ///
    /// [`Self::publish`] aborts the process on a double publication, which is
    /// right for a settlement (two settlements for one job is a kernel bug).
    /// The abort sink is the one publisher that legitimately races a real
    /// settlement: it completes jobs a judge proved nobody will complete, and
    /// a settlement finishing in that same instant is a better outcome, not a
    /// conflict. Returns whether this call was the publisher.
    pub(crate) fn publish_if_pending(&self, result: Result<VcpuLoopOutcome, RuntimeError>) -> bool {
        let mut slot = self.state.result.lock();
        if slot.is_some() {
            return false;
        }
        *slot = Some(result);
        self.state.ready.notify_all();
        true
    }

    /// Unsupervised wait, for FIXTURES ONLY.
    ///
    /// The shipped path has exactly one wait — [`Self::wait_supervised`] — so
    /// a job that nothing can publish is a named abort rather than a parked
    /// thread. A unit fixture publishes its own result before waiting, so the
    /// invariant has nothing to judge and would only add its poll interval.
    #[cfg(test)]
    pub(crate) fn wait(self) -> Result<VcpuLoopOutcome, RuntimeError> {
        let mut slot = self.state.result.lock();
        while slot.is_none() {
            self.state.ready.wait(&mut slot);
        }
        slot.take().unwrap_or_else(|| std::process::abort())
    }

    /// Wait for this job's terminal result under the always-on
    /// `ProcessGraphLiveness` invariant.
    ///
    /// Returns `Err(RuntimeError::KernelAborted)` when the invariant proves the
    /// result can never arrive. Parking forever is no longer representable
    /// here: the only way out of this loop is a published result or a named
    /// abort.
    pub(crate) fn wait_supervised(
        self,
        liveness: &ProcessGraphLiveness,
    ) -> Result<VcpuLoopOutcome, RuntimeError> {
        let mut confirming: Option<(GraphCensus, std::time::Instant)> = None;
        loop {
            // LOCK ORDER: the judging below runs with NO result lock held.
            //
            // `census` takes the kernel registry read lock, and the publishing
            // side reaches `HvpatchLoopResult::publish` -- this same result
            // mutex -- from terminal settlement, which runs under registry
            // locks. Judging under the result lock therefore inverts that
            // order: `result -> registry` here against `registry -> result`
            // there. Nothing is lost by dropping it: a publication that lands
            // between the observation and the verdict is caught by the
            // re-check at the top of the loop and by the confirmed-verdict
            // re-check below, and the confirm window already exists because
            // this observation is not atomic with the graph.
            {
                let mut slot = self.state.result.lock();
                if let Some(result) = slot.take() {
                    return result;
                }
                self.state.ready.wait_for(&mut slot, liveness.poll);
                if slot.is_some() {
                    continue;
                }
            }
            // An abort is carrier-terminal: once one exists, every wait in
            // this carrier is answered by it, including the implicit carrier's
            // own `shutdown_wait` on jobs whose guest tasks are still running.
            if let Some(recorded) = liveness.recorded() {
                return Err(recorded);
            }
            // An operator's `carrick debug abort --run-id` is latched by the
            // debug server and executed HERE, through the same sink, so a
            // requested abort and an invariant abort produce one shape.
            if let Some(reason) = crate::kernel::debug::take_abort_request() {
                // A requested abort is carrier-terminal by the operator's own
                // decision, so it is answered even if this one job settled in
                // the same instant: the point of `carrick debug abort` is that
                // the CARRIER stops and produces evidence.
                return Err(liveness.abort(reason));
            }
            let Some(census) = liveness.census() else {
                // No kernel bound: the invariant cannot see the graph it would
                // judge, so it must not judge. Fail OPEN here rather than
                // inventing a verdict.
                continue;
            };
            // How long this shape must hold before it becomes a verdict. An
            // empty graph needs one confirm window; a graph whose only
            // liveness is an executor claim needs that claim to have crossed
            // no boundary for `LIVENESS_CLAIM_STALL_WINDOWS` of them.
            let hold = match census.verdict() {
                CensusVerdict::Live => {
                    confirming = None;
                    continue;
                }
                CensusVerdict::Dead => liveness.confirm,
                CensusVerdict::ClaimedOnly => liveness.claim_stall(),
            };
            match confirming {
                Some((observed, since)) if observed == census && since.elapsed() >= hold => {
                    return match self.take_published() {
                        // A settlement landed while the verdict was being
                        // formed. A real result always beats an abort: the job
                        // was published, so the premise of the verdict is gone.
                        Some(result) => result,
                        None => {
                            crate::event_ring::rec_hvpatch_settle_object(
                                Arc::as_ptr(&self.state) as usize,
                                19,
                            );
                            Err(liveness.liveness_abort(census, 1))
                        }
                    };
                }
                Some((observed, _)) if observed == census => {}
                _ => confirming = Some((census, std::time::Instant::now())),
            }
        }
    }

    /// Take a published result if one has landed, without waiting.
    pub(crate) fn take_published(&self) -> Option<Result<VcpuLoopOutcome, RuntimeError>> {
        self.state.result.lock().take()
    }
}

pub(crate) struct HvpatchExternalTerminalState {
    published: bool,
    role: HvpatchTerminalSettlementRole,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HvpatchTerminalSettlementRole {
    Member,
    ProcessOwner,
}

/// Acyclic one-shot result authority retained by a process-member handle.
///
/// The logical job and the handle both retain this cell, but it never points
/// back to the binding, quantum, job, or process `threads` vector. Publishing
/// the result and then completion under one mutex makes the ordering exact
/// without creating `handle -> binding -> job -> handles` retention.
#[derive(Clone)]
pub(crate) struct HvpatchExternalTerminalSettlement {
    pub(crate) result: HvpatchLoopResult,
    pub(crate) completion: continuation::LogicalJobCompletion,
    pub(crate) state: Arc<Mutex<HvpatchExternalTerminalState>>,
}

impl HvpatchExternalTerminalSettlement {
    pub(crate) fn new(
        result: HvpatchLoopResult,
        completion: continuation::LogicalJobCompletion,
    ) -> Self {
        Self {
            result,
            completion,
            state: Arc::new(Mutex::new(HvpatchExternalTerminalState {
                published: false,
                role: HvpatchTerminalSettlementRole::Member,
            })),
        }
    }

    pub(crate) fn is_published(&self) -> bool {
        self.state.lock().published
    }

    pub(crate) fn arm_process_owner(&self) -> Result<(), RuntimeError> {
        let mut state = self.state.lock();
        if state.published {
            return Err(RuntimeError::Configuration(
                "terminal owner armed after logical result publication".to_owned(),
            ));
        }
        state.role = HvpatchTerminalSettlementRole::ProcessOwner;
        Ok(())
    }

    pub(crate) fn publish_member(
        &self,
        outcome: Result<VcpuLoopOutcome, RuntimeError>,
    ) -> Result<bool, RuntimeError> {
        let mut state = self.state.lock();
        if state.published {
            return Ok(false);
        }
        if state.role != HvpatchTerminalSettlementRole::Member {
            return Err(RuntimeError::Configuration(
                "drained-member settlement attempted to replace process-owner outcome".to_owned(),
            ));
        }
        self.result.publish(outcome);
        state.published = true;
        drop(state);
        self.completion.publish();
        Ok(true)
    }

    pub(crate) fn publish_terminal(
        &self,
        terminal: Option<Result<VcpuLoopOutcome, RuntimeError>>,
    ) -> bool {
        let mut state = self.state.lock();
        if state.published {
            return false;
        }
        let outcome = terminal_result_for_publication(terminal, state.role);
        self.result.publish(outcome);
        state.published = true;
        drop(state);
        self.completion.publish();
        true
    }

    pub(crate) fn completion(&self) -> continuation::LogicalJobCompletion {
        self.completion.clone()
    }

    #[cfg(test)]
    pub(crate) fn result_is_ready(&self) -> bool {
        self.result.is_ready()
    }
}

pub(crate) fn terminal_result_for_publication(
    terminal: Option<Result<VcpuLoopOutcome, RuntimeError>>,
    role: HvpatchTerminalSettlementRole,
) -> Result<VcpuLoopOutcome, RuntimeError> {
    match (role, terminal) {
        (_, Some(result)) => result,
        (HvpatchTerminalSettlementRole::Member, None) => Err(RuntimeError::CarrierFailed(
            "persistent executor failed before process terminal result publication".to_owned(),
        )),
        (HvpatchTerminalSettlementRole::ProcessOwner, None) => Err(RuntimeError::Configuration(
            "persistent terminal settlement had no logical result".to_owned(),
        )),
    }
}

/// Snapshot the shared kernel buffers + reporter into a RunResult. Called on
/// whole-process exit / trap limit.
pub(crate) fn assemble_run_result(
    kernel: &Kernel,
    exit_code: i32,
    terminating_signal: Option<i32>,
    traps: usize,
    trap_limit_hit: bool,
) -> RunResult {
    crate::probes::guest_exit(exit_code);
    kernel.dispatcher.cleanup_sysv_ipc_on_process_exit();
    let report = kernel.reporter.snapshot();
    let terminal_reason = if trap_limit_hit {
        Some(crate::runtime::TerminalReason::TrapLimit)
    } else {
        None
    };
    RunResult {
        exit_code,
        terminating_signal,
        stdout: kernel.dispatcher.stdout(),
        stderr: kernel.dispatcher.stderr(),
        traps,
        report,
        trap_limit_hit,
        terminal_reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_hal::ThreadId;

    fn dead_census() -> GraphCensus {
        GraphCensus {
            tasks: 0,
            zombies: 1,
            retired_threads: 4,
            runnable: 0,
            claimed: 0,
            claim_boundaries: 12,
        }
    }

    fn live_census() -> GraphCensus {
        GraphCensus {
            tasks: 2,
            zombies: 0,
            retired_threads: 4,
            runnable: 1,
            claimed: 1,
            claim_boundaries: 12,
        }
    }

    /// The graph a terminal settlement is IN FLIGHT on: the exiting task is
    /// already a zombie and nothing is queued, but an executor still holds the
    /// claim it will settle and publish from.
    fn settling_census() -> GraphCensus {
        GraphCensus {
            tasks: 0,
            zombies: 1,
            retired_threads: 4,
            runnable: 0,
            claimed: 1,
            claim_boundaries: 12,
        }
    }

    /// A zombie is not liveness. The wedge's own graph is exactly this: no
    /// task, no runnable row, and one unreapable pid-1 zombie — which is the
    /// EVIDENCE, not a reason to keep waiting for it to be reaped.
    #[test]
    fn a_graph_with_only_zombies_is_dead() {
        assert_eq!(dead_census().verdict(), CensusVerdict::Dead);
        assert_eq!(live_census().verdict(), CensusVerdict::Live);
        assert_eq!(
            GraphCensus {
                tasks: 0,
                zombies: 0,
                retired_threads: 0,
                runnable: 1,
                claimed: 0,
                claim_boundaries: 12,
            }
            .verdict(),
            CensusVerdict::Live,
            "a runnable row can still publish a result"
        );
        assert_eq!(
            settling_census().verdict(),
            CensusVerdict::ClaimedOnly,
            "an executor still holding a claim will settle and publish from it, \
             but only for as long as that claim keeps moving"
        );
    }

    /// The invariant must not touch a job that publishes normally.
    #[test]
    fn a_published_result_returns_from_the_supervised_wait_without_a_verdict() {
        let census = Arc::new(Mutex::new(Some(dead_census())));
        let liveness = ProcessGraphLiveness::for_tests(
            None,
            Some(Arc::clone(&census)),
            Duration::from_secs(30),
        );
        let result = HvpatchLoopResult::pending();
        result.publish(Ok(VcpuLoopOutcome::ThreadDone));
        assert!(matches!(
            result.wait_supervised(&liveness),
            Ok(VcpuLoopOutcome::ThreadDone)
        ));
    }

    /// THE invariant. An unpublished job on a graph that can never publish it
    /// is a named abort with a post-mortem, not a hang.
    #[test]
    fn an_unpublished_job_on_a_dead_graph_aborts_instead_of_parking() {
        let census = Arc::new(Mutex::new(Some(dead_census())));
        let liveness = ProcessGraphLiveness::for_tests(
            None,
            Some(Arc::clone(&census)),
            Duration::from_millis(50),
        );
        let result = HvpatchLoopResult::pending();
        let Err(error) = result.wait_supervised(&liveness) else {
            panic!("a job nothing can publish must not park");
        };
        let RuntimeError::KernelAborted {
            reason,
            post_mortem,
        } = error
        else {
            panic!("expected KernelAborted, got {error}");
        };
        assert!(reason.contains("process-graph liveness"), "{reason}");
        assert!(
            matches!(
                post_mortem.reason,
                crate::kernel::debug::AbortReason::ProcessGraphLiveness {
                    unpublished_jobs: 1,
                    live_tasks: 0,
                    runnable_rows: 0,
                    ..
                }
            ),
            "{:?}",
            post_mortem.reason
        );
    }

    /// A claim an executor still holds is liveness, however dead the registry
    /// looks.
    ///
    /// The round-7 wedge: under load the container leader's terminal
    /// address-space retirement (`PEXIT_BEGIN` -> `PEXIT_END`) runs for longer
    /// than the confirm window while the executor still holds the claim it is
    /// about to settle. `tasks` is already 0 (the task became a zombie) and
    /// `runnable` is 0 (nothing is queued), so the census read DEAD and the
    /// judge aborted a job whose `settle_exited` -> `publish_terminal_result`
    /// landed microseconds later -- the ring shows `job-result-wait-abandoned`
    /// immediately BEFORE `settle-exited-enter` and the matching
    /// `job-result-published` on the very same `HvpatchLoopResultState`.
    /// A claimed thread is the one liveness signal that covers that whole
    /// window, so it belongs in the deadness predicate.
    #[test]
    fn an_outstanding_executor_claim_keeps_the_invariant_from_firing() {
        let census = Arc::new(Mutex::new(Some(settling_census())));
        let liveness = ProcessGraphLiveness::for_tests(
            None,
            Some(Arc::clone(&census)),
            Duration::from_millis(20),
        );
        let result = HvpatchLoopResult::pending();
        let publisher = result.clone();
        let waiter = std::thread::spawn(move || result.wait_supervised(&liveness));
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            !waiter.is_finished(),
            "the invariant fired while an executor still held the claim it settles from"
        );
        publisher.publish(Ok(VcpuLoopOutcome::ThreadDone));
        assert!(matches!(
            waiter.join().expect("waiter"),
            Ok(VcpuLoopOutcome::ThreadDone)
        ));
    }

    /// ...but a claim is liveness only while it MOVES.
    ///
    /// Round 7 bought the test above by putting `claimed == 0` into the
    /// deadness predicate, and in doing so handed the invariant's own failure
    /// mode back: a claim an executor takes and never releases makes the
    /// census permanently un-dead, so the judge never forms a verdict and
    /// `wait_supervised` parks for the life of the process — the exact hang
    /// this invariant exists to remove, now reachable through one stranded
    /// claim instead of an empty graph.
    ///
    /// A settlement in flight and a stranded claim are indistinguishable by
    /// INSPECTION — both are `tasks == 0, runnable == 0, claimed == 1`. They
    /// differ only in AGE: a real terminal tail crosses a claim boundary and
    /// moves the census; a stranded one never does. So the claim term is
    /// bounded rather than unconditional.
    #[test]
    fn a_claim_that_never_makes_boundary_progress_is_eventually_dead() {
        let census = Arc::new(Mutex::new(Some(settling_census())));
        let liveness = ProcessGraphLiveness::for_tests(
            None,
            Some(Arc::clone(&census)),
            Duration::from_millis(20),
        );
        let waiter =
            std::thread::spawn(move || HvpatchLoopResult::pending().wait_supervised(&liveness));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !waiter.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            waiter.is_finished(),
            "a claim held forever must not park the carrier forever"
        );
        let Err(RuntimeError::KernelAborted { reason, .. }) = waiter.join().expect("waiter") else {
            panic!("a stranded claim must produce a named abort");
        };
        assert!(reason.contains("process-graph liveness"), "{reason}");
    }

    /// A live graph never trips it, however long the job takes. The verdict is
    /// structural, so the wait's DURATION is not evidence of anything.
    #[test]
    fn a_live_graph_never_trips_the_invariant_however_long_the_job_takes() {
        let census = Arc::new(Mutex::new(Some(live_census())));
        let liveness = ProcessGraphLiveness::for_tests(
            None,
            Some(Arc::clone(&census)),
            Duration::from_millis(20),
        );
        let result = HvpatchLoopResult::pending();
        let publisher = result.clone();
        let waiter = std::thread::spawn(move || result.wait_supervised(&liveness));
        std::thread::sleep(Duration::from_millis(300));
        assert!(!waiter.is_finished(), "the invariant fired on a live graph");
        publisher.publish(Ok(VcpuLoopOutcome::ThreadDone));
        assert!(matches!(
            waiter.join().expect("waiter"),
            Ok(VcpuLoopOutcome::ThreadDone)
        ));
    }

    /// The confirm window exists for ONE transient: the last task leaves the
    /// registry a moment before its settlement publishes. A graph that goes
    /// dead and then publishes must finish normally.
    #[test]
    fn a_graph_that_goes_dead_and_then_publishes_finishes_normally() {
        let census = Arc::new(Mutex::new(Some(live_census())));
        let liveness = ProcessGraphLiveness::for_tests(
            None,
            Some(Arc::clone(&census)),
            Duration::from_millis(400),
        );
        let result = HvpatchLoopResult::pending();
        let publisher = result.clone();
        let waiter = std::thread::spawn(move || result.wait_supervised(&liveness));
        *census.lock() = Some(dead_census());
        std::thread::sleep(Duration::from_millis(60));
        publisher.publish(Ok(VcpuLoopOutcome::ThreadDone));
        assert!(
            matches!(
                waiter.join().expect("waiter"),
                Ok(VcpuLoopOutcome::ThreadDone)
            ),
            "the settlement won the confirm window and must be honoured"
        );
    }

    /// Census CHANGE restarts confirmation: a graph that is still moving is
    /// still capable of publishing, even when its task count is momentarily 0.
    #[test]
    fn a_changing_census_restarts_confirmation() {
        let census = Arc::new(Mutex::new(Some(dead_census())));
        let liveness = ProcessGraphLiveness::for_tests(
            None,
            Some(Arc::clone(&census)),
            Duration::from_millis(200),
        );
        let result = HvpatchLoopResult::pending();
        let publisher = result.clone();
        let waiter = std::thread::spawn(move || result.wait_supervised(&liveness));
        for retired in 5..14_usize {
            std::thread::sleep(Duration::from_millis(50));
            *census.lock() = Some(GraphCensus {
                retired_threads: retired,
                ..dead_census()
            });
        }
        assert!(
            !waiter.is_finished(),
            "activity in the graph must restart confirmation"
        );
        publisher.publish(Ok(VcpuLoopOutcome::ThreadDone));
        assert!(matches!(
            waiter.join().expect("waiter"),
            Ok(VcpuLoopOutcome::ThreadDone)
        ));
    }

    /// An abort is CARRIER-terminal. Without this, the container's own join
    /// unwedged and the implicit carrier's `shutdown_wait` parked again on the
    /// jobs of guest tasks that are still running — moving the hang instead of
    /// removing it. Every later wait must be answered by the same record.
    #[test]
    fn a_recorded_abort_answers_every_later_wait_in_the_carrier() {
        let census = Arc::new(Mutex::new(Some(dead_census())));
        let liveness = ProcessGraphLiveness::for_tests(
            None,
            Some(Arc::clone(&census)),
            Duration::from_millis(30),
        );
        assert!(liveness.recorded().is_none());

        let first = HvpatchLoopResult::pending();
        let Err(RuntimeError::KernelAborted {
            reason: first_reason,
            post_mortem: first_capture,
        }) = first.wait_supervised(&liveness)
        else {
            panic!("the first wait must abort");
        };

        // A LIVE graph now: a later wait must still be refused, because the
        // carrier's kernel was already frozen and published over.
        *census.lock() = Some(live_census());
        let second = HvpatchLoopResult::pending();
        let Err(RuntimeError::KernelAborted {
            reason: second_reason,
            post_mortem: second_capture,
        }) = second.wait_supervised(&liveness)
        else {
            panic!("a later wait must be answered by the recorded abort");
        };
        assert_eq!(first_reason, second_reason);
        assert!(
            Arc::ptr_eq(&first_capture, &second_capture),
            "one abort must produce exactly one capture"
        );
    }

    /// An unbound liveness sees no graph, so it must never judge one. Failing
    /// OPEN is the only honest answer when the invariant cannot observe.
    #[test]
    fn an_unbound_liveness_never_judges() {
        let liveness = ProcessGraphLiveness::unbound();
        assert!(liveness.census().is_none());
        let result = HvpatchLoopResult::pending();
        let publisher = result.clone();
        let waiter = std::thread::spawn(move || result.wait_supervised(&liveness));
        std::thread::sleep(Duration::from_millis(120));
        assert!(!waiter.is_finished());
        publisher.publish(Ok(VcpuLoopOutcome::ThreadDone));
        assert!(matches!(
            waiter.join().expect("waiter"),
            Ok(VcpuLoopOutcome::ThreadDone)
        ));
    }

    /// The REAL census path, against a real kernel with a live root task: the
    /// fixture seam above proves the state machine, this proves the reading.
    #[test]
    fn a_real_kernel_with_a_live_root_task_reads_as_alive() {
        let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
            81_207,
            ThreadId::synthetic_for_tests(81_207),
            "liveness-census".to_owned(),
        )
        .expect("root bootstrap");
        let (kernel, _context) =
            crate::kernel::Kernel::bootstrap_root(bootstrap).expect("root kernel");
        let liveness = ProcessGraphLiveness::for_tests(Some(&kernel), None, LIVENESS_CONFIRM);
        let census = liveness.census().expect("a bound kernel answers a census");
        assert_eq!(census.tasks, 1, "the root task is live");
        assert_eq!(census.verdict(), CensusVerdict::Live);
    }

    /// A liveness bound to a kernel that has been dropped observes nothing and
    /// must not invent a dead-graph verdict from the absence.
    #[test]
    fn a_dropped_kernel_stops_the_invariant_rather_than_convicting_it() {
        let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
            81_208,
            ThreadId::synthetic_for_tests(81_208),
            "liveness-dropped".to_owned(),
        )
        .expect("root bootstrap");
        let (kernel, context) =
            crate::kernel::Kernel::bootstrap_root(bootstrap).expect("root kernel");
        let liveness = ProcessGraphLiveness::for_tests(Some(&kernel), None, LIVENESS_CONFIRM);
        drop(context);
        drop(kernel);
        assert!(
            liveness.census().is_none(),
            "an unobservable graph is not a dead graph"
        );
    }
}
