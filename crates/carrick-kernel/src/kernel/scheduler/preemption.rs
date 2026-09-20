//! Per-binding residency state, deadline tracking, and preemption coordination.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use carrick_hal::{GuestCpuId, RunBudget};

use crate::kernel::objects::{ExecutionGeneration, ExecutorId, ThreadKey};
use crate::kernel::scheduler::ExecutorBinding;

bitflags::bitflags! {
    /// Independent, typed preemption reasons.
    ///
    /// Maintaining reasons independently guarantees that cancelling fairness
    /// does not clear a concurrent signal or control preemption request.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct PreemptionReasons: u32 {
        /// Quantum budget expired under contention.
        const FAIRNESS         = 1 << 0;
        /// Pending signal delivery to this thread.
        const SIGNAL           = 1 << 1;
        /// Carrier/VM administrative pause or breakpoint.
        const CONTROL          = 1 << 2;
        /// Whole-carrier quiesce for fork or snapshot.
        const QUIESCE          = 1 << 3;
        /// Return from host-wait operation.
        const HOST_WAIT_RETURN = 1 << 4;
    }
}

/// Monotonically increasing ticket identifying a residency demand phase.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DemandTicket(pub u64);

impl fmt::Display for DemandTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ticket#{}", self.0)
    }
}

/// Monotonic clock source for scheduling deadlines and residency measurement.
pub trait MonotonicClock: Send + Sync + fmt::Debug {
    fn now(&self) -> Instant;
}

/// Production monotonic clock using the host monotonic time.
#[derive(Debug, Default)]
pub struct HostMonotonicClock;

impl MonotonicClock for HostMonotonicClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Controllable monotonic clock for deterministic, VM-free scheduling tests.
#[derive(Debug)]
pub struct ManualClock {
    now: parking_lot::Mutex<Instant>,
    notify: parking_lot::Mutex<Vec<Arc<parking_lot::Condvar>>>,
}

impl ManualClock {
    pub fn new(start: Instant) -> Self {
        Self {
            now: parking_lot::Mutex::new(start),
            notify: parking_lot::Mutex::new(Vec::new()),
        }
    }

    pub fn with_condvar(start: Instant, notify: Arc<parking_lot::Condvar>) -> Self {
        Self {
            now: parking_lot::Mutex::new(start),
            notify: parking_lot::Mutex::new(vec![notify]),
        }
    }

    pub fn attach_condvar(&self, notify: Arc<parking_lot::Condvar>) {
        self.notify.lock().push(notify);
    }

    pub fn advance(&self, duration: Duration) {
        let mut now = self.now.lock();
        *now += duration;
        let condvars = self.notify.lock().clone();
        for cv in condvars {
            cv.notify_all();
        }
    }
}

impl MonotonicClock for ManualClock {
    fn now(&self) -> Instant {
        *self.now.lock()
    }
}

impl<T: ?Sized + MonotonicClock> MonotonicClock for Arc<T> {
    fn now(&self) -> Instant {
        (**self).now()
    }
}

/// Active residency of a thread executing on a bound executor.
#[derive(Clone, Debug)]
pub struct BindingResidency {
    pub binding: ExecutorBinding,
    pub ticket: DemandTicket,
    pub start: Instant,
    pub budget: RunBudget,
    pub reasons: PreemptionReasons,
    pub cpu: GuestCpuId,
    pub thread: ThreadKey,
    pub generation: ExecutionGeneration,
    pub ticket_claimed: bool,
}

/// Immutable snapshot of an executor's residency for diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingResidencySnapshot {
    pub binding: ExecutorBinding,
    pub ticket: DemandTicket,
    pub budget: RunBudget,
    pub reasons: PreemptionReasons,
    pub cpu: GuestCpuId,
    pub thread: ThreadKey,
    pub generation: ExecutionGeneration,
}

/// A preemption request due for delivery to a running executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreemptionRequest {
    pub binding: ExecutorBinding,
    pub ticket: DemandTicket,
    pub reasons: PreemptionReasons,
    pub cpu: GuestCpuId,
}

/// An entry in the ordered deadline set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeadlineEntry {
    pub binding: ExecutorBinding,
    pub ticket: DemandTicket,
    pub deadline: Instant,
    pub reasons: PreemptionReasons,
    pub cpu: GuestCpuId,
}

/// Outcome from waiting on preemption work.
#[derive(Debug)]
pub enum PreemptionWork {
    Due(Vec<PreemptionRequest>),
    Shutdown,
}

/// Outcome of attempting to deliver a preemption request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryOutcome {
    Delivered,
    Stale,
    Cancelled,
    Coalesced,
}

/// Typed error when attaching or spawning a preemption driver.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PreemptionDriverError {
    #[error("a preemption driver is already attached to this scheduler")]
    AlreadyAttached,
    #[error("failed to spawn preemption driver thread: {0}")]
    SpawnFailed(String),
}

/// Internal preemption state owned by the [`crate::kernel::Scheduler`].
pub struct PreemptionState {
    pub(crate) residencies: BTreeMap<ExecutorId, BindingResidency>,
    pub(crate) deadlines: BTreeMap<(Instant, ExecutorId), DeadlineEntry>,
    pub(crate) executor_deadlines: BTreeMap<ExecutorId, Instant>,
    pub(crate) demand_counter: u64,
    pub(crate) event_sequence: Arc<AtomicU64>,
    pub(crate) clock: Arc<dyn MonotonicClock>,
    pub(crate) shutdown: bool,
    pub(crate) driver_attached: bool,
}

impl fmt::Debug for PreemptionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreemptionState")
            .field("residencies", &self.residencies.len())
            .field("deadlines", &self.deadlines.len())
            .field("demand_counter", &self.demand_counter)
            .field(
                "event_sequence",
                &self.event_sequence.load(Ordering::Relaxed),
            )
            .field("clock", &self.clock)
            .field("shutdown", &self.shutdown)
            .field("driver_attached", &self.driver_attached)
            .finish()
    }
}

impl PreemptionState {
    pub fn new(clock: Arc<dyn MonotonicClock>, event_sequence: Arc<AtomicU64>) -> Self {
        Self {
            residencies: BTreeMap::new(),
            deadlines: BTreeMap::new(),
            executor_deadlines: BTreeMap::new(),
            demand_counter: 0,
            event_sequence,
            clock,
            shutdown: false,
            driver_attached: false,
        }
    }

    pub fn next_sequence(&self) -> u64 {
        self.event_sequence.fetch_add(1, Ordering::Relaxed)
    }

    fn next_ticket(&mut self) -> DemandTicket {
        self.demand_counter = self.demand_counter.saturating_add(1);
        DemandTicket(self.demand_counter)
    }

    pub fn register_residency(
        &mut self,
        binding: ExecutorBinding,
        cpu: GuestCpuId,
        budget: RunBudget,
        thread: ThreadKey,
        generation: ExecutionGeneration,
    ) -> (DemandTicket, u64) {
        let ticket = self.next_ticket();
        let sequence = self.next_sequence();
        let start = self.clock.now();
        let residency = BindingResidency {
            binding,
            ticket,
            start,
            budget,
            reasons: PreemptionReasons::empty(),
            cpu,
            thread,
            generation,
            ticket_claimed: false,
        };
        self.residencies.insert(binding.executor(), residency);
        (ticket, sequence)
    }

    pub fn finalize_residency(&mut self, executor: ExecutorId) -> Option<BindingResidency> {
        self.cancel_deadline(executor);
        self.residencies.remove(&executor)
    }

    pub fn binding_residency(&self, executor: ExecutorId) -> Option<BindingResidencySnapshot> {
        self.residencies
            .get(&executor)
            .map(|r| BindingResidencySnapshot {
                binding: r.binding,
                ticket: r.ticket,
                budget: r.budget,
                reasons: r.reasons,
                cpu: r.cpu,
                thread: r.thread,
                generation: r.generation,
            })
    }

    pub fn add_preemption_reason(
        &mut self,
        executor: ExecutorId,
        reasons: PreemptionReasons,
    ) -> bool {
        if let Some(residency) = self.residencies.get_mut(&executor) {
            if !residency.reasons.contains(reasons) {
                residency.reasons.insert(reasons);
                residency.ticket_claimed = false;
            }
            true
        } else {
            false
        }
    }

    pub fn clear_preemption_reason(
        &mut self,
        executor: ExecutorId,
        reasons: PreemptionReasons,
    ) -> bool {
        if let Some(residency) = self.residencies.get_mut(&executor) {
            residency.reasons.remove(reasons);
            true
        } else {
            false
        }
    }

    pub fn should_preempt(&self, binding: &ExecutorBinding, queue_len: usize) -> bool {
        if let Some(residency) = self.residencies.get(&binding.executor()) {
            if residency.binding != *binding {
                return false;
            }
            if !residency
                .reasons
                .difference(PreemptionReasons::FAIRNESS)
                .is_empty()
            {
                return true;
            }
            if residency.reasons.contains(PreemptionReasons::FAIRNESS) && queue_len > 0 {
                return true;
            }
            if queue_len > 0 {
                let now = self.clock.now();
                let elapsed = now.saturating_duration_since(residency.start);
                if elapsed >= residency.budget.quantum() {
                    return true;
                }
            }
        }
        false
    }

    pub fn has_pending_preemptions(&self) -> bool {
        self.residencies.values().any(|r| !r.reasons.is_empty())
    }

    pub fn has_expired_budgets(&self) -> bool {
        let now = self.clock.now();
        self.residencies
            .values()
            .any(|r| now.saturating_duration_since(r.start) >= r.budget.quantum())
    }

    pub fn stop_driver(&mut self) {
        self.shutdown = true;
    }

    pub fn is_shutdown(&self) -> bool {
        self.shutdown
    }

    pub fn attach_driver(&mut self) -> Result<(), PreemptionDriverError> {
        if self.driver_attached {
            return Err(PreemptionDriverError::AlreadyAttached);
        }
        self.driver_attached = true;
        Ok(())
    }

    pub fn detach_driver(&mut self) {
        self.driver_attached = false;
        self.shutdown = false;
    }

    pub fn is_driver_attached(&self) -> bool {
        self.driver_attached
    }

    pub fn schedule_deadline(
        &mut self,
        executor: ExecutorId,
        deadline: Instant,
        reasons: PreemptionReasons,
    ) {
        if let Some(residency) = self.residencies.get(&executor) {
            if let Some(old_deadline) = self.executor_deadlines.remove(&executor) {
                self.deadlines.remove(&(old_deadline, executor));
            }
            let entry = DeadlineEntry {
                binding: residency.binding,
                ticket: residency.ticket,
                deadline,
                reasons,
                cpu: residency.cpu,
            };
            self.executor_deadlines.insert(executor, deadline);
            self.deadlines.insert((deadline, executor), entry);
        }
    }

    pub fn cancel_deadline(&mut self, executor: ExecutorId) -> bool {
        if let Some(old_deadline) = self.executor_deadlines.remove(&executor) {
            self.deadlines.remove(&(old_deadline, executor)).is_some()
        } else {
            false
        }
    }

    pub fn has_deadline(&self, executor: ExecutorId) -> bool {
        self.executor_deadlines.contains_key(&executor)
    }

    pub fn deadline_for(&self, executor: ExecutorId) -> Option<Instant> {
        self.executor_deadlines.get(&executor).copied()
    }

    pub fn earliest_deadline(&self) -> Option<Instant> {
        self.deadlines.first_key_value().map(|((inst, _), _)| *inst)
    }

    pub fn live_deadline_count(&self) -> usize {
        self.deadlines.len()
    }

    pub fn poll_due_requests(&mut self) -> Vec<PreemptionRequest> {
        let now = self.clock.now();
        let mut due_executors = Vec::new();

        while let Some((&(deadline, executor), _)) = self.deadlines.first_key_value() {
            if deadline <= now {
                self.deadlines.remove(&(deadline, executor));
                self.executor_deadlines.remove(&executor);
                due_executors.push((executor, PreemptionReasons::FAIRNESS));
            } else {
                break;
            }
        }

        let mut requests = Vec::new();
        for (executor, reasons) in due_executors {
            if let Some(residency) = self.residencies.get_mut(&executor) {
                residency.reasons.insert(reasons);
                if !residency.ticket_claimed {
                    residency.ticket_claimed = true;
                    requests.push(PreemptionRequest {
                        binding: residency.binding,
                        ticket: residency.ticket,
                        reasons: residency.reasons,
                        cpu: residency.cpu,
                    });
                }
            }
        }

        for residency in self.residencies.values_mut() {
            if !residency.reasons.is_empty() && !residency.ticket_claimed {
                residency.ticket_claimed = true;
                requests.push(PreemptionRequest {
                    binding: residency.binding,
                    ticket: residency.ticket,
                    reasons: residency.reasons,
                    cpu: residency.cpu,
                });
            }
        }

        requests
    }
}
