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
    notify: Arc<parking_lot::Condvar>,
}

impl ManualClock {
    pub fn new(start: Instant) -> Self {
        Self {
            now: parking_lot::Mutex::new(start),
            notify: Arc::new(parking_lot::Condvar::new()),
        }
    }

    pub fn with_condvar(start: Instant, notify: Arc<parking_lot::Condvar>) -> Self {
        Self {
            now: parking_lot::Mutex::new(start),
            notify,
        }
    }

    pub fn advance(&self, duration: Duration) {
        let mut now = self.now.lock();
        *now += duration;
        self.notify.notify_all();
    }
}

impl MonotonicClock for ManualClock {
    fn now(&self) -> Instant {
        *self.now.lock()
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
}

/// An entry in the ordered deadline set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeadlineEntry {
    pub binding: ExecutorBinding,
    pub ticket: DemandTicket,
    pub deadline: Instant,
    pub reasons: PreemptionReasons,
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

/// Internal preemption state owned by the [`crate::kernel::Scheduler`].
pub struct PreemptionState {
    pub(crate) residencies: BTreeMap<ExecutorId, BindingResidency>,
    pub(crate) deadlines: BTreeMap<Instant, Vec<DeadlineEntry>>,
    pub(crate) demand_counter: u64,
    pub(crate) event_sequence: Arc<AtomicU64>,
    pub(crate) clock: Box<dyn MonotonicClock>,
    pub(crate) shutdown: bool,
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
            .finish()
    }
}

impl PreemptionState {
    pub fn new(clock: Box<dyn MonotonicClock>, event_sequence: Arc<AtomicU64>) -> Self {
        Self {
            residencies: BTreeMap::new(),
            deadlines: BTreeMap::new(),
            demand_counter: 0,
            event_sequence,
            clock,
            shutdown: false,
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
        };
        self.residencies.insert(binding.executor(), residency);
        (ticket, sequence)
    }

    pub fn finalize_residency(&mut self, executor: ExecutorId) -> Option<BindingResidency> {
        let removed = self.residencies.remove(&executor);
        if removed.is_some() {
            // Remove any deadlines for this executor
            for entries in self.deadlines.values_mut() {
                entries.retain(|e| e.binding.executor() != executor);
            }
            self.deadlines.retain(|_, entries| !entries.is_empty());
        }
        removed
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
            residency.reasons.insert(reasons);
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
            if !residency.reasons.is_empty() {
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

    pub fn schedule_deadline(
        &mut self,
        executor: ExecutorId,
        deadline: Instant,
        reasons: PreemptionReasons,
    ) {
        if let Some(residency) = self.residencies.get(&executor) {
            let entry = DeadlineEntry {
                binding: residency.binding,
                ticket: residency.ticket,
                deadline,
                reasons,
            };
            self.deadlines.entry(deadline).or_default().push(entry);
        }
    }

    pub fn poll_due_requests(&mut self) -> Vec<PreemptionRequest> {
        let now = self.clock.now();
        let mut due_times = Vec::new();
        for &time in self.deadlines.keys() {
            if time <= now {
                due_times.push(time);
            } else {
                break;
            }
        }

        let mut requests = Vec::new();
        for time in due_times {
            if let Some(entries) = self.deadlines.remove(&time) {
                for entry in entries {
                    if let Some(residency) = self.residencies.get_mut(&entry.binding.executor()) {
                        if residency.ticket == entry.ticket && residency.binding == entry.binding {
                            residency.reasons.insert(entry.reasons);
                            requests.push(PreemptionRequest {
                                binding: entry.binding,
                                ticket: entry.ticket,
                                reasons: residency.reasons,
                            });
                        }
                    }
                }
            }
        }
        requests
    }

    pub fn earliest_deadline(&self) -> Option<Instant> {
        self.deadlines.keys().next().copied()
    }
}
