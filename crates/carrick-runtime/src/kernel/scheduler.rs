//! Exact-generation runnable authority for the HVPatch executor migration.
//!
//! The thread execution record is always transitioned before queue state is
//! acquired. Host wake edges and executor slots remain consequences of that
//! state, never authority for it.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use parking_lot::{Condvar, Mutex};

use super::Kernel;
use super::objects::{
    BlockedReason, ExecutionGeneration, ExecutorId, Thread, ThreadExecutionError,
    ThreadExecutionLease, ThreadKey, ThreadSchedulerAction,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct QueueKey {
    pub(crate) thread: ThreadKey,
    pub(crate) generation: ExecutionGeneration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WakeDisposition {
    Queued,
    Coalesced,
    Kicked,
    Pending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RunQueueError {
    #[error("run queue is closed")]
    Closed,
    #[error("new root submissions are rejected while the run queue is closing")]
    SubmissionRejected,
    #[error("run queue publication authority does not match the submitted generation")]
    AuthorityMismatch,
    #[error("executor identifiers are exhausted")]
    ExecutorIdExhausted,
    #[error("executor is already running another exact generation")]
    ExecutorBusy,
    #[error("executor registration is stale")]
    StaleExecutor,
}

#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    #[error("exact thread generation is not live")]
    UnknownThread,
    #[error(transparent)]
    Thread(#[from] ThreadExecutionError),
    #[error(transparent)]
    Queue(#[from] RunQueueError),
}

pub trait ExecutorKick: Send + Sync + std::fmt::Debug {
    /// Atomically install an exact loaded generation at the destination.
    fn try_bind(&self, binding: ExecutorBinding) -> bool;

    /// Clear only the still-matching destination binding.
    fn unbind(&self, binding: ExecutorBinding);

    /// Revalidate and consume the exact token at the destination. The host
    /// nudge may occur only inside the successful exact-binding branch.
    fn deliver_exact(&self, token: ExecutorKickToken) -> bool;

    fn current_binding(&self) -> Option<ExecutorBinding>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutorKickToken {
    executor: ExecutorId,
    executor_epoch: u64,
    thread: ThreadKey,
    generation: ExecutionGeneration,
}

impl ExecutorKickToken {
    pub const fn executor(self) -> ExecutorId {
        self.executor
    }

    pub const fn executor_epoch(self) -> u64 {
        self.executor_epoch
    }

    pub const fn thread(self) -> ThreadKey {
        self.thread
    }

    pub const fn generation(self) -> ExecutionGeneration {
        self.generation
    }

    pub(crate) const fn binding(self) -> ExecutorBinding {
        ExecutorBinding {
            executor: self.executor,
            executor_epoch: self.executor_epoch,
            thread: self.thread,
            generation: self.generation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutorBinding {
    executor: ExecutorId,
    executor_epoch: u64,
    thread: ThreadKey,
    generation: ExecutionGeneration,
}

impl ExecutorBinding {
    pub const fn executor(self) -> ExecutorId {
        self.executor
    }

    pub const fn executor_epoch(self) -> u64 {
        self.executor_epoch
    }

    pub const fn thread(self) -> ThreadKey {
        self.thread
    }

    pub const fn generation(self) -> ExecutionGeneration {
        self.generation
    }

    const fn token(self) -> ExecutorKickToken {
        ExecutorKickToken {
            executor: self.executor,
            executor_epoch: self.executor_epoch,
            thread: self.thread,
            generation: self.generation,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExecutorRegistration {
    id: ExecutorId,
    close_observation_epoch: Arc<AtomicU64>,
}

impl ExecutorRegistration {
    pub const fn id(&self) -> ExecutorId {
        self.id
    }
}

#[derive(Debug)]
struct ExecutorEntry {
    kick: Arc<dyn ExecutorKick>,
}

#[derive(Debug)]
struct ExecutorDirectoryState {
    next_id: u32,
    entries: BTreeMap<ExecutorId, ExecutorEntry>,
}

impl Default for ExecutorDirectoryState {
    fn default() -> Self {
        Self {
            next_id: 1,
            entries: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Default)]
struct ExecutorDirectory {
    state: Mutex<ExecutorDirectoryState>,
}

impl ExecutorDirectory {
    fn register(&self, kick: Arc<dyn ExecutorKick>) -> Result<ExecutorRegistration, RunQueueError> {
        let mut state = self.state.lock();
        let raw = state.next_id;
        if raw == 0 {
            return Err(RunQueueError::ExecutorIdExhausted);
        }
        state.next_id = raw
            .checked_add(1)
            .ok_or(RunQueueError::ExecutorIdExhausted)?;
        let id = ExecutorId::from_scheduler(raw);
        state.entries.insert(id, ExecutorEntry { kick });
        Ok(ExecutorRegistration {
            id,
            close_observation_epoch: Arc::new(AtomicU64::new(0)),
        })
    }

    fn bind(
        &self,
        registration: &ExecutorRegistration,
        binding: ExecutorBinding,
    ) -> Result<(), RunQueueError> {
        let kick = self
            .state
            .lock()
            .entries
            .get(&registration.id)
            .map(|entry| Arc::clone(&entry.kick))
            .ok_or(RunQueueError::StaleExecutor)?;
        if !kick.try_bind(binding) {
            return Err(RunQueueError::ExecutorBusy);
        }
        Ok(())
    }

    fn unregister(&self, registration: &ExecutorRegistration) -> Result<(), RunQueueError> {
        let mut state = self.state.lock();
        let entry = state
            .entries
            .get(&registration.id)
            .ok_or(RunQueueError::StaleExecutor)?;
        if let Some(binding) = entry.kick.current_binding() {
            entry.kick.unbind(binding);
        }
        state.entries.remove(&registration.id);
        Ok(())
    }

    fn clear_binding(&self, registration: &ExecutorRegistration) -> Result<(), RunQueueError> {
        let kick = self
            .state
            .lock()
            .entries
            .get(&registration.id)
            .map(|entry| Arc::clone(&entry.kick))
            .ok_or(RunQueueError::StaleExecutor)?;
        if let Some(binding) = kick.current_binding() {
            kick.unbind(binding);
        }
        Ok(())
    }

    fn unbind(&self, binding: ExecutorBinding) {
        let kick = self
            .state
            .lock()
            .entries
            .get(&binding.executor)
            .map(|entry| Arc::clone(&entry.kick));
        let Some(kick) = kick else {
            return;
        };
        kick.unbind(binding);
    }

    fn binding_for_thread(&self, thread: ThreadKey) -> Option<ExecutorBinding> {
        let kicks: Vec<_> = self
            .state
            .lock()
            .entries
            .values()
            .map(|entry| Arc::clone(&entry.kick))
            .collect();
        kicks
            .into_iter()
            .filter_map(|kick| kick.current_binding())
            .find(|binding| binding.thread == thread)
    }

    fn has_running(&self) -> bool {
        let kicks: Vec<_> = self
            .state
            .lock()
            .entries
            .values()
            .map(|entry| Arc::clone(&entry.kick))
            .collect();
        kicks
            .into_iter()
            .any(|kick| kick.current_binding().is_some())
    }

    fn current_tokens(&self) -> Vec<ExecutorKickToken> {
        let kicks: Vec<_> = self
            .state
            .lock()
            .entries
            .values()
            .map(|entry| Arc::clone(&entry.kick))
            .collect();
        kicks
            .into_iter()
            .filter_map(|kick| kick.current_binding().map(ExecutorBinding::token))
            .collect()
    }

    fn deliver(&self, token: ExecutorKickToken) -> bool {
        let kick = self
            .state
            .lock()
            .entries
            .get(&token.executor)
            .map(|entry| Arc::clone(&entry.kick));
        kick.is_some_and(|kick| kick.deliver_exact(token))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QueueLifecycle {
    Open,
    Closing,
    Closed,
}

#[derive(Debug)]
struct QueueRow {
    key: QueueKey,
    thread: Arc<Thread>,
}

#[derive(Debug)]
struct RunQueueState {
    lifecycle: QueueLifecycle,
    rows: VecDeque<QueueRow>,
    queued: BTreeSet<QueueKey>,
    active_authorities: usize,
    claimed: usize,
    waiters: usize,
    close_epoch: u64,
    close_waiters_expected: usize,
    closed_waiter_observations: usize,
}

impl Default for RunQueueState {
    fn default() -> Self {
        Self {
            lifecycle: QueueLifecycle::Open,
            rows: VecDeque::new(),
            queued: BTreeSet::new(),
            active_authorities: 0,
            claimed: 0,
            waiters: 0,
            close_epoch: 0,
            close_waiters_expected: 0,
            closed_waiter_observations: 0,
        }
    }
}

#[derive(Debug, Default)]
struct RunQueueInner {
    state: Mutex<RunQueueState>,
    changed: Condvar,
    wake_admissions: AtomicU64,
    #[cfg(test)]
    close_observation_gate: Mutex<Option<Arc<std::sync::Barrier>>>,
    #[cfg(test)]
    root_admission_gate: Mutex<Option<Arc<std::sync::Barrier>>>,
}

impl RunQueueInner {
    const CLOSING_BIT: u64 = 1 << 63;

    fn try_admit_wake(self: &Arc<Self>) -> Result<WakeAdmission, RunQueueError> {
        let mut observed = self.wake_admissions.load(Ordering::Acquire);
        loop {
            if observed & Self::CLOSING_BIT != 0 {
                return Err(RunQueueError::Closed);
            }
            let count = observed & !Self::CLOSING_BIT;
            let next = count
                .checked_add(1)
                .filter(|next| *next < Self::CLOSING_BIT)
                .ok_or(RunQueueError::SubmissionRejected)?;
            match self.wake_admissions.compare_exchange_weak(
                observed,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(WakeAdmission {
                        queue: Arc::downgrade(self),
                        active: true,
                    });
                }
                Err(actual) => observed = actual,
            }
        }
    }

    fn begin_close(&self) {
        self.wake_admissions
            .fetch_or(Self::CLOSING_BIT, Ordering::AcqRel);
    }

    fn active_wake_admissions(&self) -> u64 {
        self.wake_admissions.load(Ordering::Acquire) & !Self::CLOSING_BIT
    }

    fn release_wake_admission(&self) {
        let previous = self.wake_admissions.fetch_sub(1, Ordering::AcqRel);
        if previous & !Self::CLOSING_BIT == 0 {
            std::process::abort();
        }
        let mut state = self.state.lock();
        self.maybe_finish_close(&mut state);
        self.changed.notify_all();
    }

    fn drain_ready(&self, state: &RunQueueState) -> bool {
        state.rows.is_empty()
            && state.active_authorities == 0
            && state.claimed == 0
            && self.active_wake_admissions() == 0
    }

    fn maybe_finish_close(&self, state: &mut RunQueueState) {
        if state.lifecycle == QueueLifecycle::Closing
            && self.drain_ready(state)
            && state.closed_waiter_observations >= state.close_waiters_expected
        {
            state.lifecycle = QueueLifecycle::Closed;
            self.changed.notify_all();
        } else if state.lifecycle == QueueLifecycle::Closing && self.drain_ready(state) {
            self.changed.notify_all();
        }
    }

    fn enqueue(&self, row: QueueRow, closing_authorized: bool) -> Result<bool, RunQueueError> {
        let mut state = self.state.lock();
        if state.lifecycle == QueueLifecycle::Closed {
            return Err(RunQueueError::Closed);
        }
        if state.queued.contains(&row.key) {
            return Ok(false);
        }
        if state.lifecycle == QueueLifecycle::Closing && !closing_authorized {
            return Err(RunQueueError::SubmissionRejected);
        }
        state.queued.insert(row.key);
        state.rows.push_back(row);
        self.changed.notify_one();
        Ok(true)
    }

    fn finish_claim(&self) {
        let mut state = self.state.lock();
        state.claimed = state
            .claimed
            .checked_sub(1)
            .unwrap_or_else(|| std::process::abort());
        self.maybe_finish_close(&mut state);
        self.changed.notify_all();
    }

    fn release_authority(&self) {
        let mut state = self.state.lock();
        state.active_authorities = state
            .active_authorities
            .checked_sub(1)
            .unwrap_or_else(|| std::process::abort());
        self.maybe_finish_close(&mut state);
        self.changed.notify_all();
    }
}

#[derive(Debug)]
struct WakeAdmission {
    queue: Weak<RunQueueInner>,
    active: bool,
}

impl Drop for WakeAdmission {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Some(queue) = self.queue.upgrade() {
            queue.release_wake_admission();
        }
        self.active = false;
    }
}

/// Queue authority retained by an exact active generation. New roots may be
/// admitted only while open; descendants of this retained authority may be
/// admitted while closing so recursive fork publication cannot be stranded.
#[derive(Debug)]
pub struct SubmissionAuthority {
    queue: Weak<RunQueueInner>,
    kernel: Weak<Kernel>,
    key: QueueKey,
    active: bool,
}

impl SubmissionAuthority {
    pub(crate) const fn thread_key(&self) -> ThreadKey {
        self.key.thread
    }

    pub(crate) const fn generation(&self) -> ExecutionGeneration {
        self.key.generation
    }

    pub fn admit_descendant(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
    ) -> Result<Self, RunQueueError> {
        if !self.active {
            return Err(RunQueueError::AuthorityMismatch);
        }
        let kernel = self.kernel.upgrade().ok_or(RunQueueError::Closed)?;
        let queue = self.queue.upgrade().ok_or(RunQueueError::Closed)?;
        kernel
            .with_live_scheduler_descendant(
                self.key.thread,
                self.key.generation,
                thread,
                generation,
                || {
                    let mut state = queue.state.lock();
                    if state.lifecycle == QueueLifecycle::Closed {
                        return Err(RunQueueError::Closed);
                    }
                    state.active_authorities = state
                        .active_authorities
                        .checked_add(1)
                        .ok_or(RunQueueError::SubmissionRejected)?;
                    Ok(Self {
                        queue: Arc::downgrade(&queue),
                        kernel: Arc::downgrade(&kernel),
                        key: QueueKey { thread, generation },
                        active: true,
                    })
                },
            )
            .unwrap_or(Err(RunQueueError::AuthorityMismatch))
    }

    pub fn publish(
        &self,
        scheduler: &Scheduler,
        thread: Arc<Thread>,
    ) -> Result<(), SchedulerError> {
        let queue = self.queue.upgrade().ok_or(RunQueueError::Closed)?;
        let exact = scheduler
            .kernel
            .exact_thread_for_scheduler(self.key.thread)
            .ok_or(SchedulerError::UnknownThread)?;
        if !Arc::ptr_eq(&queue, &scheduler.queue.inner)
            || !Arc::ptr_eq(&exact, &thread)
            || thread.key() != self.key.thread
            || thread.execution_state().generation() != Some(self.key.generation)
        {
            return Err(RunQueueError::AuthorityMismatch.into());
        }
        scheduler.enqueue_exact(thread, self.key, true)?;
        Ok(())
    }
}

impl Drop for SubmissionAuthority {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Some(queue) = self.queue.upgrade() {
            queue.release_authority();
        }
        self.active = false;
    }
}

#[derive(Debug, Default)]
pub struct RunQueue {
    inner: Arc<RunQueueInner>,
}

impl RunQueue {
    fn admit_root(
        &self,
        kernel: &Arc<Kernel>,
        key: QueueKey,
    ) -> Result<SubmissionAuthority, RunQueueError> {
        #[cfg(test)]
        if let Some(gate) = {
            let configured = self.inner.root_admission_gate.lock();
            configured.clone()
        } {
            gate.wait();
            gate.wait();
        }
        let mut state = self.inner.state.lock();
        if state.lifecycle != QueueLifecycle::Open
            || self.inner.wake_admissions.load(Ordering::Acquire) & RunQueueInner::CLOSING_BIT != 0
        {
            return Err(RunQueueError::SubmissionRejected);
        }
        state.active_authorities = state
            .active_authorities
            .checked_add(1)
            .ok_or(RunQueueError::SubmissionRejected)?;
        Ok(SubmissionAuthority {
            queue: Arc::downgrade(&self.inner),
            kernel: Arc::downgrade(kernel),
            key,
            active: true,
        })
    }

    fn take_row(&self, executor: &ExecutorRegistration) -> Result<QueueRow, RunQueueError> {
        let mut state = self.inner.state.lock();
        loop {
            if let Some(row) = state.rows.pop_front() {
                state.queued.remove(&row.key);
                state.claimed = state
                    .claimed
                    .checked_add(1)
                    .unwrap_or_else(|| std::process::abort());
                return Ok(row);
            }
            self.inner.maybe_finish_close(&mut state);
            if state.lifecycle == QueueLifecycle::Closed {
                return Err(RunQueueError::Closed);
            }
            if state.lifecycle == QueueLifecycle::Closing && self.inner.drain_ready(&state) {
                if executor.close_observation_epoch.swap(0, Ordering::AcqRel) != 0 {
                    #[cfg(test)]
                    let observation_gate = {
                        let configured = self.inner.close_observation_gate.lock();
                        configured.clone()
                    };
                    #[cfg(test)]
                    if let Some(gate) = observation_gate {
                        drop(state);
                        gate.wait();
                        state = self.inner.state.lock();
                    }
                    state.closed_waiter_observations = state
                        .closed_waiter_observations
                        .checked_add(1)
                        .unwrap_or_else(|| std::process::abort());
                    self.inner.maybe_finish_close(&mut state);
                }
                return Err(RunQueueError::Closed);
            }
            state.waiters = state
                .waiters
                .checked_add(1)
                .unwrap_or_else(|| std::process::abort());
            let close_epoch = state.close_epoch;
            self.inner.changed.wait(&mut state);
            state.waiters = state
                .waiters
                .checked_sub(1)
                .unwrap_or_else(|| std::process::abort());
            if state.close_epoch != close_epoch {
                executor
                    .close_observation_epoch
                    .store(state.close_epoch, Ordering::Release);
            }
        }
    }

    /// Claim the first row that still names the exact current Runnable
    /// generation. Stale rows are consumed here and never escape as runnable
    /// authority.
    pub(crate) fn take(
        &self,
        executor: &ExecutorRegistration,
    ) -> Result<QueueClaim, RunQueueError> {
        loop {
            let row = self.take_row(executor)?;
            if row.thread.key() != row.key.thread
                || row.thread.execution_state().generation() != Some(row.key.generation)
                || !matches!(
                    row.thread.execution_state(),
                    super::objects::ThreadExecutionState::Runnable { .. }
                )
            {
                self.inner.finish_claim();
                continue;
            }
            let lease = match row.thread.claim_runnable(executor.id) {
                Ok(lease) if lease.generation() == row.key.generation => lease,
                Ok(lease) => {
                    drop(lease);
                    self.inner.finish_claim();
                    continue;
                }
                Err(_) => {
                    self.inner.finish_claim();
                    continue;
                }
            };
            return Ok(QueueClaim { row, lease });
        }
    }

    pub fn close(&self) {
        self.inner.begin_close();
        let mut state = self.inner.state.lock();
        if state.lifecycle == QueueLifecycle::Open {
            state.lifecycle = QueueLifecycle::Closing;
            state.close_epoch = state
                .close_epoch
                .checked_add(1)
                .unwrap_or_else(|| std::process::abort());
            state.close_waiters_expected = state.waiters;
        }
        self.inner.maybe_finish_close(&mut state);
        self.inner.changed.notify_all();
    }

    pub fn wait_closed(&self) {
        let mut state = self.inner.state.lock();
        while state.lifecycle != QueueLifecycle::Closed {
            self.inner.changed.wait(&mut state);
        }
    }

    fn retire_executor(&self, executor: &ExecutorRegistration) {
        if executor.close_observation_epoch.swap(0, Ordering::AcqRel) == 0 {
            return;
        }
        let mut state = self.inner.state.lock();
        state.closed_waiter_observations = state
            .closed_waiter_observations
            .checked_add(1)
            .unwrap_or_else(|| std::process::abort());
        self.inner.maybe_finish_close(&mut state);
        self.inner.changed.notify_all();
    }

    fn len(&self) -> usize {
        self.inner.state.lock().rows.len()
    }

    #[cfg(test)]
    fn waiter_count(&self) -> usize {
        self.inner.state.lock().waiters
    }

    #[cfg(test)]
    fn closed_waiter_observations(&self) -> usize {
        self.inner.state.lock().closed_waiter_observations
    }

    #[cfg(test)]
    fn install_close_observation_gate(&self, gate: Arc<std::sync::Barrier>) {
        *self.inner.close_observation_gate.lock() = Some(gate);
    }

    #[cfg(test)]
    fn install_root_admission_gate(&self, gate: Arc<std::sync::Barrier>) {
        *self.inner.root_admission_gate.lock() = Some(gate);
    }
}

pub(crate) struct QueueClaim {
    row: QueueRow,
    lease: ThreadExecutionLease,
}

pub struct RunnableThread {
    thread: Arc<Thread>,
    key: QueueKey,
    binding: ExecutorBinding,
    lease: Option<ThreadExecutionLease>,
    queue: Weak<RunQueueInner>,
    active_claim: bool,
}

impl std::fmt::Debug for RunnableThread {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunnableThread")
            .field("key", &self.key)
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

impl RunnableThread {
    pub const fn thread_key(&self) -> ThreadKey {
        self.key.thread
    }

    pub const fn generation(&self) -> ExecutionGeneration {
        self.key.generation
    }

    pub const fn executor(&self) -> ExecutorId {
        self.binding.executor
    }

    pub const fn executor_epoch(&self) -> u64 {
        self.binding.executor_epoch
    }

    pub fn lease(&self) -> &ThreadExecutionLease {
        self.lease.as_ref().unwrap_or_else(|| std::process::abort())
    }

    pub(crate) fn thread(&self) -> &Arc<Thread> {
        &self.thread
    }

    pub(crate) fn take_lease(&mut self) -> ThreadExecutionLease {
        self.lease.take().unwrap_or_else(|| std::process::abort())
    }

    pub(crate) fn restore_lease(
        &mut self,
        lease: ThreadExecutionLease,
    ) -> Result<(), (ThreadExecutionError, ThreadExecutionLease)> {
        if self.lease.is_some()
            || lease.generation() != self.key.generation
            || lease.executor() != self.binding.executor
            || lease.executor_epoch() != self.binding.executor_epoch
        {
            return Err((
                ThreadExecutionError::StaleLease {
                    generation: lease.generation(),
                    executor: lease.executor(),
                    executor_epoch: lease.executor_epoch(),
                },
                lease,
            ));
        }
        self.lease = Some(lease);
        Ok(())
    }

    fn finish_claim(&mut self) {
        if !self.active_claim {
            return;
        }
        if let Some(queue) = self.queue.upgrade() {
            queue.finish_claim();
        }
        self.active_claim = false;
    }
}

impl Drop for RunnableThread {
    fn drop(&mut self) {
        self.finish_claim();
    }
}

#[derive(Debug)]
enum WakeAction {
    Queue {
        thread: Arc<Thread>,
        key: QueueKey,
        closing_authorized: bool,
    },
    Kick(ExecutorKickToken),
    Pending,
}

#[derive(Debug)]
struct PendingWake {
    action: WakeAction,
    _admission: WakeAdmission,
}

#[derive(Debug)]
pub struct Scheduler {
    kernel: Arc<Kernel>,
    queue: RunQueue,
    executors: ExecutorDirectory,
    need_resched: AtomicBool,
    snapshot_count: AtomicU64,
}

impl Scheduler {
    pub fn new(kernel: Arc<Kernel>) -> Self {
        Self {
            kernel,
            queue: RunQueue::default(),
            executors: ExecutorDirectory::default(),
            need_resched: AtomicBool::new(false),
            snapshot_count: AtomicU64::new(0),
        }
    }

    pub fn register_executor(
        &self,
        kick: Arc<dyn ExecutorKick>,
    ) -> Result<ExecutorRegistration, RunQueueError> {
        self.executors.register(kick)
    }

    pub(crate) fn unregister_executor(
        &self,
        registration: &ExecutorRegistration,
    ) -> Result<(), RunQueueError> {
        self.queue.retire_executor(registration);
        self.executors.unregister(registration)
    }

    pub(crate) fn clear_executor_binding(
        &self,
        registration: &ExecutorRegistration,
    ) -> Result<(), RunQueueError> {
        self.executors.clear_binding(registration)
    }

    pub fn admit_root(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
    ) -> Result<SubmissionAuthority, SchedulerError> {
        self.kernel
            .with_live_active_scheduler_thread(thread, generation, || {
                self.queue
                    .admit_root(&self.kernel, QueueKey { thread, generation })
            })
            .unwrap_or(Err(RunQueueError::AuthorityMismatch))
            .map_err(Into::into)
    }

    pub fn make_runnable(&self, thread: ThreadKey) -> Result<WakeDisposition, SchedulerError> {
        self.wake(thread)
    }

    pub fn wake(&self, thread: ThreadKey) -> Result<WakeDisposition, SchedulerError> {
        let pending = self.begin_wake(thread)?;
        self.commit_wake(pending)
    }

    fn begin_wake(&self, thread: ThreadKey) -> Result<PendingWake, SchedulerError> {
        let admission = self.queue.inner.try_admit_wake()?;
        let action = self.decide_wake(thread)?;
        Ok(PendingWake {
            action,
            _admission: admission,
        })
    }

    fn commit_wake(&self, pending: PendingWake) -> Result<WakeDisposition, SchedulerError> {
        let PendingWake { action, _admission } = pending;
        let result = match action {
            WakeAction::Queue { thread, key, .. } => {
                Ok(if self.enqueue_exact(thread, key, true)? {
                    WakeDisposition::Queued
                } else {
                    WakeDisposition::Coalesced
                })
            }
            action => self.deliver_wake(action),
        };
        drop(_admission);
        result
    }

    fn decide_wake(&self, key: ThreadKey) -> Result<WakeAction, SchedulerError> {
        let thread = self
            .kernel
            .exact_thread_for_scheduler(key)
            .ok_or(SchedulerError::UnknownThread)?;
        let action = thread.scheduler_wake(key)?;
        Ok(match action {
            ThreadSchedulerAction::Queue {
                key,
                generation,
                closing_authorized,
            } => WakeAction::Queue {
                thread,
                key: QueueKey {
                    thread: key,
                    generation,
                },
                closing_authorized,
            },
            ThreadSchedulerAction::Kick {
                executor,
                executor_epoch,
                key,
                generation,
            } => WakeAction::Kick(ExecutorKickToken {
                executor,
                executor_epoch,
                thread: key,
                generation,
            }),
            ThreadSchedulerAction::None => WakeAction::Pending,
        })
    }

    fn deliver_wake(&self, action: WakeAction) -> Result<WakeDisposition, SchedulerError> {
        match action {
            WakeAction::Queue {
                thread,
                key,
                closing_authorized,
            } => Ok(if self.enqueue_exact(thread, key, closing_authorized)? {
                WakeDisposition::Queued
            } else {
                WakeDisposition::Coalesced
            }),
            WakeAction::Kick(token) => {
                if self.executors.deliver(token) {
                    Ok(WakeDisposition::Kicked)
                } else {
                    Ok(WakeDisposition::Pending)
                }
            }
            WakeAction::Pending => Ok(WakeDisposition::Pending),
        }
    }

    fn enqueue_exact(
        &self,
        thread: Arc<Thread>,
        key: QueueKey,
        closing_authorized: bool,
    ) -> Result<bool, RunQueueError> {
        let inserted = self
            .queue
            .inner
            .enqueue(QueueRow { key, thread }, closing_authorized)?;
        if inserted && self.executors.has_running() {
            self.need_resched.store(true, Ordering::Release);
        }
        Ok(inserted)
    }

    pub fn take(&self, executor: &ExecutorRegistration) -> Result<RunnableThread, RunQueueError> {
        let QueueClaim { row, lease } = self.queue.take(executor)?;
        let binding = ExecutorBinding {
            executor: executor.id,
            executor_epoch: lease.executor_epoch(),
            thread: row.key.thread,
            generation: row.key.generation,
        };
        if let Err(error) = self.executors.bind(executor, binding) {
            drop(lease);
            self.queue.inner.finish_claim();
            return Err(error);
        }
        self.need_resched
            .store(self.queue.len() != 0, Ordering::Release);
        Ok(RunnableThread {
            thread: row.thread,
            key: row.key,
            binding,
            lease: Some(lease),
            queue: Arc::downgrade(&self.queue.inner),
            active_claim: true,
        })
    }

    pub fn settle_blocked(
        &self,
        mut running: RunnableThread,
        reason: BlockedReason,
    ) -> Result<(), SchedulerError> {
        let lease = running.take_lease();
        let action = running
            .thread
            .scheduler_park_from_executor(lease, reason)
            .map_err(|(error, _lease)| error)?;
        self.executors.unbind(running.binding);
        self.apply_settlement_action(&running.thread, action)?;
        running.finish_claim();
        Ok(())
    }

    pub(crate) fn begin_switch_out(&self, running: &RunnableThread) -> Result<(), SchedulerError> {
        running.thread.begin_switch_out(running.lease())?;
        Ok(())
    }

    pub(crate) fn restore_saved_lease(
        &self,
        running: &mut RunnableThread,
        lease: ThreadExecutionLease,
    ) -> Result<(), (SchedulerError, ThreadExecutionLease)> {
        running
            .restore_lease(lease)
            .map_err(|(error, lease)| (error.into(), lease))
    }

    pub(crate) fn settle_failed(
        &self,
        mut running: RunnableThread,
        reason: super::objects::ExecutionFailure,
    ) -> Result<(), SchedulerError> {
        let lease = running.take_lease();
        match running.thread.fail_from_executor(lease, reason) {
            Ok(()) => {
                self.executors.unbind(running.binding);
                running.finish_claim();
                Ok(())
            }
            Err((error, lease)) => {
                if let Err((_restore_error, lease)) = running.restore_lease(lease) {
                    drop(lease);
                }
                Err(error.into())
            }
        }
    }

    pub fn settle_runnable(&self, mut running: RunnableThread) -> Result<(), SchedulerError> {
        let lease = running.take_lease();
        let action = running
            .thread
            .scheduler_yield_from_executor(lease)
            .map_err(|(error, _lease)| error)?;
        self.executors.unbind(running.binding);
        self.snapshot_count.fetch_add(1, Ordering::Relaxed);
        self.apply_settlement_action(&running.thread, action)?;
        running.finish_claim();
        Ok(())
    }

    pub fn settle_exited(&self, mut running: RunnableThread) -> Result<(), SchedulerError> {
        let lease = running.take_lease();
        running
            .thread
            .exit_from_executor(lease)
            .map_err(|(error, _lease)| error)?;
        self.executors.unbind(running.binding);
        running.finish_claim();
        Ok(())
    }

    fn apply_settlement_action(
        &self,
        thread: &Arc<Thread>,
        action: ThreadSchedulerAction,
    ) -> Result<(), SchedulerError> {
        match action {
            ThreadSchedulerAction::Queue {
                key,
                generation,
                closing_authorized,
            } => {
                self.enqueue_exact(
                    Arc::clone(thread),
                    QueueKey {
                        thread: key,
                        generation,
                    },
                    closing_authorized,
                )?;
            }
            ThreadSchedulerAction::Kick { .. } | ThreadSchedulerAction::None => {}
        }
        Ok(())
    }

    pub fn binding_for_thread(&self, thread: ThreadKey) -> Option<ExecutorBinding> {
        self.executors.binding_for_thread(thread)
    }

    pub fn queued_len(&self) -> usize {
        self.queue.len()
    }

    pub fn need_resched(&self) -> bool {
        self.need_resched.load(Ordering::Acquire)
    }

    pub fn snapshot_count(&self) -> u64 {
        self.snapshot_count.load(Ordering::Relaxed)
    }

    /// Carrier-timer policy hook. It emits only exact tokens captured from the
    /// current executor directory and every delivery revalidates the complete
    /// binding, so an epoch successor cannot consume a late preemption.
    pub fn request_preemption(&self) -> usize {
        if !self.need_resched() {
            return 0;
        }
        self.executors
            .current_tokens()
            .into_iter()
            .filter(|token| self.executors.deliver(*token))
            .count()
    }

    pub fn note_syscall_boundary(&self, _running: &RunnableThread) {
        if self.queue.len() == 0 {
            self.need_resched.store(false, Ordering::Release);
        }
    }

    pub fn close(&self) {
        self.queue.close();
    }

    pub fn wait_closed(&self) {
        self.queue.wait_closed();
    }

    #[cfg(test)]
    fn is_closing(&self) -> bool {
        self.queue.inner.wake_admissions.load(Ordering::Acquire) & RunQueueInner::CLOSING_BIT != 0
    }

    #[cfg(test)]
    fn waiter_count(&self) -> usize {
        self.queue.waiter_count()
    }

    #[cfg(test)]
    fn closed_waiter_observations(&self) -> usize {
        self.queue.closed_waiter_observations()
    }

    #[cfg(test)]
    fn install_close_observation_gate(&self, gate: Arc<std::sync::Barrier>) {
        self.queue.install_close_observation_gate(gate);
    }

    #[cfg(test)]
    fn install_root_admission_gate(&self, gate: Arc<std::sync::Barrier>) {
        self.queue.install_root_admission_gate(gate);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use carrick_abi::LinuxCloneFlags;
    use carrick_hal::ThreadId;
    use carrick_hal::threaded::{Aarch64TaskCpuStateV1, GuestCpuState};

    use super::{
        ExecutorKick, ExecutorKickToken, QueueKey, RunQueueError, Scheduler, WakeDisposition,
    };
    use crate::kernel::objects::{BlockedReason, MigratableTaskState, ThreadExecutionState};
    use crate::kernel::{ClonePlan, Kernel, KernelContext, RootBootstrap};

    fn bootstrap(pid: i32) -> (Arc<Kernel>, KernelContext) {
        let input = RootBootstrap::for_reference_model(
            pid,
            ThreadId::synthetic_for_tests(pid),
            "scheduler test".to_owned(),
        )
        .expect("bootstrap input");
        Kernel::bootstrap_root(input).expect("kernel")
    }

    fn sibling(kernel: &Arc<Kernel>, parent: &KernelContext, host_tid: i32) -> KernelContext {
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread clone plan");
        kernel
            .reserve_thread_clone(parent, plan, None)
            .expect("reserve sibling")
            .prepare(ThreadId::synthetic_for_tests(host_tid))
            .expect("prepare sibling")
            .commit()
            .expect("publish sibling")
            .start_thread()
            .expect("start sibling")
            .into_context()
    }

    fn process_child(
        kernel: &Arc<Kernel>,
        parent: &KernelContext,
        host_tid: i32,
        name: &str,
    ) -> KernelContext {
        kernel
            .fork_task(
                parent,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("process fork plan"),
                ThreadId::synthetic_for_tests(host_tid),
                name.to_owned(),
                None,
            )
            .expect("fork process child")
    }

    fn task_state(context: &KernelContext, marker: u64) -> MigratableTaskState {
        let mm = context.shared().mm().id();
        MigratableTaskState {
            cpu: GuestCpuState::from_aarch64_v1(Aarch64TaskCpuStateV1 {
                gprs: std::array::from_fn(|index| marker + index as u64),
                pc: marker + 0x1000,
                pstate: marker + 0x2000,
                trap_pc: marker + 0x2100,
                trap_pstate: marker + 0x2200,
                sp_el0: marker + 0x3000,
                elr_el1: marker + 0x3100,
                spsr_el1: marker + 0x3200,
                ttbr0: marker + 0x4000,
                ttbr1: marker + 0x5000,
                tcr: marker + 0x6000,
                actlr_el1: marker + 0x7000,
                tpidr_el0: marker + 0x8000,
                tpidrro_el0: marker + 0x9000,
                contextidr_el1: marker + 0xa000,
                vregs: std::array::from_fn(|index| marker as u128 + index as u128),
                fpsr: marker as u32,
                fpcr: marker as u32 + 1,
                pending_resume_pc: Some(marker + 0xb000),
                last_syscall_nr: Some(marker),
                last_syscall_orig_x0: marker + 2,
                last_fault_esr: marker + 3,
                last_exit_class: marker,
                is_forked_child: false,
                syscall_continuation: None,
                mm_generation: mm.raw(),
                asid_generation: mm.raw(),
            }),
            mm,
            asid_generation: mm.raw(),
        }
    }

    fn publish(context: &KernelContext, marker: u64) {
        context
            .thread()
            .publish_initial_task_state(task_state(context, marker))
            .expect("publish task state");
    }

    #[derive(Debug, Default)]
    struct RecordingKick {
        binding: parking_lot::Mutex<Option<super::ExecutorBinding>>,
        tokens: parking_lot::Mutex<Vec<ExecutorKickToken>>,
    }

    impl ExecutorKick for RecordingKick {
        fn try_bind(&self, binding: super::ExecutorBinding) -> bool {
            let mut current = self.binding.lock();
            if current.is_some() {
                return false;
            }
            *current = Some(binding);
            true
        }

        fn unbind(&self, binding: super::ExecutorBinding) {
            let mut current = self.binding.lock();
            if *current == Some(binding) {
                *current = None;
            }
        }

        fn deliver_exact(&self, token: ExecutorKickToken) -> bool {
            let current = self.binding.lock();
            if (*current).map(super::ExecutorBinding::token) != Some(token) {
                return false;
            }
            self.tokens.lock().push(token);
            true
        }

        fn current_binding(&self) -> Option<super::ExecutorBinding> {
            *self.binding.lock()
        }
    }

    #[derive(Debug)]
    struct BarrierKick {
        entered: Arc<Barrier>,
        resume: Arc<Barrier>,
        binding: parking_lot::Mutex<Option<super::ExecutorBinding>>,
        tokens: parking_lot::Mutex<Vec<ExecutorKickToken>>,
    }

    impl ExecutorKick for BarrierKick {
        fn try_bind(&self, binding: super::ExecutorBinding) -> bool {
            let mut current = self.binding.lock();
            if current.is_some() {
                return false;
            }
            *current = Some(binding);
            true
        }

        fn unbind(&self, binding: super::ExecutorBinding) {
            let mut current = self.binding.lock();
            if *current == Some(binding) {
                *current = None;
            }
        }

        fn deliver_exact(&self, token: ExecutorKickToken) -> bool {
            self.entered.wait();
            self.resume.wait();
            let current = self.binding.lock();
            if (*current).map(super::ExecutorBinding::token) != Some(token) {
                return false;
            }
            self.tokens.lock().push(token);
            true
        }

        fn current_binding(&self) -> Option<super::ExecutorBinding> {
            *self.binding.lock()
        }
    }

    #[test]
    fn blocked_wake_queues_exactly_one_row_for_the_next_generation() {
        let (kernel, context) = bootstrap(12_100);
        publish(&context, 1);
        let scheduler = Scheduler::new(kernel);
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        assert_eq!(
            scheduler.make_runnable(context.thread().key()).unwrap(),
            WakeDisposition::Queued
        );
        let running = scheduler.take(&executor).unwrap();
        let first = running.generation();
        scheduler
            .settle_blocked(running, BlockedReason::HostWait)
            .unwrap();

        assert_eq!(
            scheduler.wake(context.thread().key()).unwrap(),
            WakeDisposition::Queued
        );
        assert_eq!(scheduler.queued_len(), 1);
        let next = scheduler.take(&executor).unwrap();
        assert_eq!(next.generation().raw(), first.raw() + 2);
        scheduler.settle_exited(next).unwrap();
    }

    #[test]
    fn close_between_blocked_transition_and_enqueue_cannot_strand_runnable_generation() {
        let (kernel, context) = bootstrap(12_115);
        publish(&context, 20);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        scheduler
            .settle_blocked(running, BlockedReason::HostWait)
            .unwrap();

        let pending = scheduler
            .begin_wake(context.thread().key())
            .expect("wake admission precedes thread transition");
        let (closed_tx, closed_rx) = std::sync::mpsc::sync_channel(1);
        let close_scheduler = Arc::clone(&scheduler);
        let close = thread::spawn(move || {
            close_scheduler.close();
            close_scheduler.wait_closed();
            closed_tx.send(()).unwrap();
        });
        while !scheduler.is_closing() {
            thread::yield_now();
        }
        assert!(matches!(
            closed_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));

        assert_eq!(
            scheduler.commit_wake(pending).unwrap(),
            WakeDisposition::Queued
        );
        let resumed = scheduler.take(&executor).unwrap();
        scheduler.settle_exited(resumed).unwrap();
        closed_rx.recv().unwrap();
        close.join().unwrap();
    }

    #[test]
    fn post_close_blocked_wake_is_rejected_without_changing_blocked_state() {
        let (kernel, context) = bootstrap(12_116);
        publish(&context, 21);
        let scheduler = Scheduler::new(kernel);
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        scheduler
            .settle_blocked(running, BlockedReason::HostWait)
            .unwrap();
        let blocked = context.thread().execution_state();
        scheduler.close();
        scheduler.wait_closed();

        assert!(scheduler.wake(context.thread().key()).is_err());
        assert_eq!(context.thread().execution_state(), blocked);
        assert_eq!(scheduler.queued_len(), 0);
    }

    #[test]
    fn wake_racing_switch_out_is_durable_and_settles_runnable_once() {
        let (kernel, context) = bootstrap(12_101);
        publish(&context, 2);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        context.thread().begin_switch_out(running.lease()).unwrap();

        let barrier = Arc::new(Barrier::new(3));
        let wake_scheduler = Arc::clone(&scheduler);
        let wake_key = context.thread().key();
        let wake_barrier = Arc::clone(&barrier);
        let wake = thread::spawn(move || {
            wake_barrier.wait();
            wake_scheduler.wake(wake_key)
        });
        let settle_scheduler = Arc::clone(&scheduler);
        let settle_barrier = Arc::clone(&barrier);
        let settle = thread::spawn(move || {
            settle_barrier.wait();
            settle_scheduler.settle_blocked(running, BlockedReason::HostWait)
        });
        barrier.wait();
        wake.join().unwrap().unwrap();
        settle.join().unwrap().unwrap();

        assert!(matches!(
            context.thread().execution_state(),
            ThreadExecutionState::Runnable { .. }
        ));
        assert_eq!(scheduler.queued_len(), 1);
        let resumed = scheduler.take(&executor).unwrap();
        scheduler.settle_exited(resumed).unwrap();
    }

    #[test]
    fn two_concurrent_wakes_coalesce_to_one_exact_row() {
        let (kernel, context) = bootstrap(12_102);
        publish(&context, 3);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        scheduler
            .settle_blocked(running, BlockedReason::HostWait)
            .unwrap();

        let barrier = Arc::new(Barrier::new(3));
        let mut wakes = Vec::new();
        for _ in 0..2 {
            let scheduler = Arc::clone(&scheduler);
            let barrier = Arc::clone(&barrier);
            let key = context.thread().key();
            wakes.push(thread::spawn(move || {
                barrier.wait();
                scheduler.wake(key)
            }));
        }
        barrier.wait();
        for wake in wakes {
            wake.join().unwrap().unwrap();
        }

        assert_eq!(scheduler.queued_len(), 1);
        let resumed = scheduler.take(&executor).unwrap();
        scheduler.settle_exited(resumed).unwrap();
    }

    #[test]
    fn runnable_wake_is_idempotent_and_never_duplicates_the_row() {
        let (kernel, context) = bootstrap(12_103);
        publish(&context, 4);
        let scheduler = Scheduler::new(kernel);
        assert_eq!(
            scheduler.make_runnable(context.thread().key()).unwrap(),
            WakeDisposition::Queued
        );
        assert_eq!(
            scheduler.wake(context.thread().key()).unwrap(),
            WakeDisposition::Coalesced
        );
        assert_eq!(scheduler.queued_len(), 1);
    }

    #[test]
    fn stale_thread_key_and_tid_reuse_lookalike_are_rejected() {
        let (kernel, context) = bootstrap(12_104);
        let other = sibling(&kernel, &context, 22_104);
        publish(&context, 5);
        publish(&other, 6);
        let scheduler = Scheduler::new(kernel);
        let key = context.thread().key();
        let lookalike = crate::kernel::ThreadKey {
            tid: key.tid,
            serial: other.thread().key().serial,
        };

        assert!(scheduler.wake(lookalike).is_err());
        assert!(
            scheduler
                .admit_root(
                    lookalike,
                    context.thread().execution_state().generation().unwrap()
                )
                .is_err()
        );
        assert_eq!(scheduler.queued_len(), 0);
        assert!(matches!(
            context.thread().execution_state(),
            ThreadExecutionState::Runnable { .. }
        ));
    }

    #[test]
    fn current_exited_generation_cannot_admit_root_authority() {
        let (kernel, context) = bootstrap(12_120);
        publish(&context, 28);
        let scheduler = Scheduler::new(kernel);
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        scheduler.settle_exited(running).unwrap();
        let exited_generation = context.thread().execution_state().generation().unwrap();

        assert!(
            scheduler
                .admit_root(context.thread().key(), exited_generation)
                .is_err()
        );
    }

    #[test]
    fn current_failed_generation_cannot_admit_root_authority() {
        let (kernel, context) = bootstrap(12_121);
        publish(&context, 29);
        let scheduler = Scheduler::new(kernel);
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let mut running = scheduler.take(&executor).unwrap();
        let lease = running.take_lease();
        context
            .thread()
            .fail_from_executor(
                lease,
                crate::kernel::objects::ExecutionFailure::SnapshotRestoreFailed,
            )
            .unwrap();
        scheduler.executors.unbind(running.binding);
        running.finish_claim();
        let failed_generation = context.thread().execution_state().generation().unwrap();

        assert!(
            scheduler
                .admit_root(context.thread().key(), failed_generation)
                .is_err()
        );
    }

    #[test]
    fn close_winning_root_admission_race_publishes_no_stale_authority() {
        let (kernel, context) = bootstrap(12_122);
        publish(&context, 30);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        let generation = running.generation();
        let gate = Arc::new(Barrier::new(2));
        scheduler.install_root_admission_gate(Arc::clone(&gate));
        let admission_scheduler = Arc::clone(&scheduler);
        let key = context.thread().key();
        let admission = thread::spawn(move || admission_scheduler.admit_root(key, generation));

        gate.wait();
        let exit_scheduler = Arc::clone(&scheduler);
        let exit = thread::spawn(move || exit_scheduler.settle_exited(running));
        scheduler.close();
        assert!(scheduler.is_closing());
        gate.wait();

        assert!(admission.join().unwrap().is_err());
        exit.join().unwrap().unwrap();
        scheduler.wait_closed();
    }

    #[test]
    fn running_wake_emits_one_exact_kick_after_the_transition_unlocks() {
        let (kernel, context) = bootstrap(12_105);
        publish(&context, 7);
        let scheduler = Scheduler::new(kernel);
        let kicks = Arc::new(RecordingKick::default());
        let executor = scheduler.register_executor(kicks.clone()).unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();

        assert_eq!(
            scheduler.wake(context.thread().key()).unwrap(),
            WakeDisposition::Kicked
        );
        let tokens = kicks.tokens.lock();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].thread(), context.thread().key());
        assert_eq!(tokens[0].generation(), running.generation());
        assert_eq!(tokens[0].executor(), running.executor());
        assert_eq!(tokens[0].executor_epoch(), running.executor_epoch());
        drop(tokens);
        scheduler.settle_exited(running).unwrap();
    }

    #[test]
    fn switching_out_wake_never_kicks_old_executor_and_forces_runnable_settlement() {
        let (kernel, context) = bootstrap(12_106);
        publish(&context, 8);
        let scheduler = Scheduler::new(kernel);
        let kicks = Arc::new(RecordingKick::default());
        let executor = scheduler.register_executor(kicks.clone()).unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        context.thread().begin_switch_out(running.lease()).unwrap();

        assert_eq!(
            scheduler.wake(context.thread().key()).unwrap(),
            WakeDisposition::Pending
        );
        scheduler
            .settle_blocked(running, BlockedReason::HostWait)
            .unwrap();
        assert!(kicks.tokens.lock().is_empty());
        assert_eq!(scheduler.queued_len(), 1);
        let resumed = scheduler.take(&executor).unwrap();
        scheduler.settle_exited(resumed).unwrap();
    }

    #[test]
    fn late_kick_token_cannot_affect_the_executor_epoch_successor() {
        let (kernel, context) = bootstrap(12_107);
        publish(&context, 9);
        let scheduler = Scheduler::new(kernel);
        let kicks = Arc::new(RecordingKick::default());
        let executor = scheduler.register_executor(kicks.clone()).unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let first = scheduler.take(&executor).unwrap();
        let delayed = scheduler.decide_wake(context.thread().key()).unwrap();
        scheduler.settle_runnable(first).unwrap();
        let successor = scheduler.take(&executor).unwrap();

        assert_eq!(
            scheduler.deliver_wake(delayed).unwrap(),
            WakeDisposition::Pending
        );
        assert!(kicks.tokens.lock().is_empty());
        scheduler.settle_exited(successor).unwrap();
    }

    #[test]
    fn executor_rebind_between_directory_validation_and_delivery_never_interrupts_successor() {
        let (kernel, context) = bootstrap(12_117);
        publish(&context, 22);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let entered = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        let kicks = Arc::new(BarrierKick {
            entered: Arc::clone(&entered),
            resume: Arc::clone(&resume),
            binding: parking_lot::Mutex::new(None),
            tokens: parking_lot::Mutex::new(Vec::new()),
        });
        let executor = scheduler.register_executor(kicks.clone()).unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let first = scheduler.take(&executor).unwrap();
        let delayed = scheduler.decide_wake(context.thread().key()).unwrap();
        let delivery_scheduler = Arc::clone(&scheduler);
        let delivery = thread::spawn(move || delivery_scheduler.deliver_wake(delayed));

        entered.wait();
        scheduler.settle_runnable(first).unwrap();
        let successor = scheduler.take(&executor).unwrap();
        resume.wait();
        assert_eq!(delivery.join().unwrap().unwrap(), WakeDisposition::Pending);
        assert!(kicks.tokens.lock().is_empty());
        scheduler.settle_exited(successor).unwrap();
    }

    #[test]
    fn take_discards_stale_rows_and_claims_only_the_exact_current_generation() {
        let (kernel, context) = bootstrap(12_108);
        publish(&context, 10);
        let scheduler = Scheduler::new(kernel);
        scheduler.make_runnable(context.thread().key()).unwrap();

        let bypass = context
            .thread()
            .claim_runnable(crate::kernel::objects::ExecutorId::synthetic_for_tests(99))
            .unwrap();
        context.thread().yield_from_executor(bypass).unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        let claimed = scheduler.take(&executor).unwrap();

        assert_eq!(claimed.generation().raw(), 2);
        assert_eq!(scheduler.queued_len(), 0);
        scheduler.settle_exited(claimed).unwrap();
    }

    #[test]
    fn blocked_state_has_no_executor_binding() {
        let (kernel, context) = bootstrap(12_109);
        publish(&context, 11);
        let scheduler = Scheduler::new(kernel);
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        scheduler
            .settle_blocked(running, BlockedReason::HostWait)
            .unwrap();

        assert!(
            scheduler
                .binding_for_thread(context.thread().key())
                .is_none()
        );
        assert!(matches!(
            context.thread().execution_state(),
            ThreadExecutionState::Blocked { .. }
        ));
    }

    #[test]
    fn close_wakes_all_waiters_rejects_new_roots_and_drains_recursive_publication() {
        let (kernel, root) = bootstrap(12_110);
        let child = process_child(&kernel, &root, 22_110, "scheduler child");
        let grandchild = process_child(&kernel, &child, 22_111, "scheduler grandchild");
        publish(&root, 12);
        publish(&child, 13);
        publish(&grandchild, 14);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let root_generation = root.thread().execution_state().generation().unwrap();
        let root_authority = scheduler
            .admit_root(root.thread().key(), root_generation)
            .unwrap();
        let claimed = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(3));
        let mut waiters = Vec::new();
        for _ in 0..2 {
            let scheduler = Arc::clone(&scheduler);
            let claimed = Arc::clone(&claimed);
            let closed = Arc::clone(&closed);
            let barrier = Arc::clone(&barrier);
            waiters.push(thread::spawn(move || {
                let executor = scheduler
                    .register_executor(Arc::new(RecordingKick::default()))
                    .unwrap();
                barrier.wait();
                loop {
                    match scheduler.take(&executor) {
                        Ok(running) => {
                            claimed.fetch_add(1, Ordering::SeqCst);
                            scheduler.settle_exited(running).unwrap();
                        }
                        Err(RunQueueError::Closed) => {
                            closed.fetch_add(1, Ordering::SeqCst);
                            return;
                        }
                        Err(error) => panic!("unexpected take error: {error:?}"),
                    }
                }
            }));
        }
        barrier.wait();
        while scheduler.waiter_count() != 2 {
            thread::yield_now();
        }

        let observation_gate = Arc::new(Barrier::new(3));
        scheduler.install_close_observation_gate(Arc::clone(&observation_gate));
        scheduler.close();
        let (closed_tx, closed_rx) = std::sync::mpsc::sync_channel(1);
        let close_scheduler = Arc::clone(&scheduler);
        let close_wait = thread::spawn(move || {
            close_scheduler.wait_closed();
            closed_tx.send(()).unwrap();
        });
        assert!(scheduler.make_runnable(child.thread().key()).is_err());
        assert!(
            scheduler
                .admit_root(
                    child.thread().key(),
                    child.thread().execution_state().generation().unwrap()
                )
                .is_err()
        );
        let child_authority = root_authority
            .admit_descendant(
                child.thread().key(),
                child.thread().execution_state().generation().unwrap(),
            )
            .unwrap();
        let grandchild_authority = child_authority
            .admit_descendant(
                grandchild.thread().key(),
                grandchild.thread().execution_state().generation().unwrap(),
            )
            .unwrap();
        child_authority
            .publish(&scheduler, Arc::clone(child.thread()))
            .unwrap();
        grandchild_authority
            .publish(&scheduler, Arc::clone(grandchild.thread()))
            .unwrap();
        drop(grandchild_authority);
        drop(child_authority);
        drop(root_authority);
        assert!(matches!(
            closed_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        observation_gate.wait();
        closed_rx.recv().unwrap();
        close_wait.join().unwrap();
        for waiter in waiters {
            waiter.join().unwrap();
        }

        assert_eq!(claimed.load(Ordering::SeqCst), 2);
        assert_eq!(closed.load(Ordering::SeqCst), 2);
        assert_eq!(scheduler.closed_waiter_observations(), 2);
    }

    #[test]
    fn exited_grant_cannot_authorize_a_descendant_during_close() {
        let (kernel, root) = bootstrap(12_118);
        let child = process_child(&kernel, &root, 22_118, "exited grant child");
        publish(&root, 23);
        publish(&child, 24);
        let scheduler = Scheduler::new(kernel);
        let authority = scheduler
            .admit_root(
                root.thread().key(),
                root.thread().execution_state().generation().unwrap(),
            )
            .unwrap();
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(root.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        scheduler.settle_exited(running).unwrap();
        scheduler.close();

        assert!(
            authority
                .admit_descendant(
                    child.thread().key(),
                    child.thread().execution_state().generation().unwrap(),
                )
                .is_err()
        );
        drop(authority);
        scheduler.wait_closed();
    }

    #[test]
    fn live_unrelated_process_cannot_be_admitted_as_a_descendant() {
        let (kernel, root) = bootstrap(12_119);
        let grant = process_child(&kernel, &root, 22_119, "grant child");
        let unrelated = process_child(&kernel, &root, 22_120, "unrelated child");
        publish(&root, 25);
        publish(&grant, 26);
        publish(&unrelated, 27);
        let scheduler = Scheduler::new(kernel);
        let authority = scheduler
            .admit_root(
                grant.thread().key(),
                grant.thread().execution_state().generation().unwrap(),
            )
            .unwrap();
        scheduler.close();

        assert!(
            authority
                .admit_descendant(
                    unrelated.thread().key(),
                    unrelated.thread().execution_state().generation().unwrap(),
                )
                .is_err()
        );
        drop(authority);
        scheduler.wait_closed();
    }

    #[test]
    fn proc_state_helper_renders_runnable_and_running_as_r_and_blocked_as_s() {
        let (kernel, context) = bootstrap(12_111);
        publish(&context, 14);
        let scheduler = Scheduler::new(kernel);
        assert_eq!(context.thread().linux_run_state(), Some('R'));
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        assert_eq!(context.thread().linux_run_state(), Some('R'));
        scheduler
            .settle_blocked(running, BlockedReason::HostWait)
            .unwrap();
        assert_eq!(context.thread().linux_run_state(), Some('S'));
    }

    #[test]
    fn lone_task_thousands_of_syscalls_never_arm_resched_or_snapshot() {
        let (kernel, context) = bootstrap(12_112);
        publish(&context, 15);
        let scheduler = Scheduler::new(kernel);
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        for _ in 0..10_000 {
            scheduler.note_syscall_boundary(&running);
        }

        assert!(!scheduler.need_resched());
        assert_eq!(scheduler.snapshot_count(), 0);
        scheduler.settle_exited(running).unwrap();
    }

    #[test]
    fn one_executor_preempts_two_compute_generations_and_signal_wake_is_prompt() {
        let (kernel, first) = bootstrap(12_113);
        let second = sibling(&kernel, &first, 22_113);
        publish(&first, 16);
        publish(&second, 17);
        let scheduler = Scheduler::new(kernel);
        let kicks = Arc::new(RecordingKick::default());
        let executor = scheduler.register_executor(kicks.clone()).unwrap();
        scheduler.make_runnable(first.thread().key()).unwrap();
        scheduler.make_runnable(second.thread().key()).unwrap();
        let mut progress = BTreeMap::new();

        for _ in 0..8 {
            let running = scheduler.take(&executor).unwrap();
            *progress.entry(running.thread_key()).or_insert(0_u32) += 1;
            assert!(scheduler.need_resched());
            if progress.values().sum::<u32>() == 1 {
                assert_eq!(scheduler.request_preemption(), 1);
                assert_eq!(kicks.tokens.lock().as_slice(), &[running.binding.token()]);
            }
            scheduler.settle_runnable(running).unwrap();
        }
        assert!(progress[&first.thread().key()] > 0);
        assert!(progress[&second.thread().key()] > 0);
        assert!(scheduler.snapshot_count() >= 8);

        let running = scheduler.take(&executor).unwrap();
        let running_key = running.thread_key();
        scheduler
            .settle_blocked(running, BlockedReason::HostWait)
            .unwrap();
        assert_eq!(
            scheduler.wake(running_key).unwrap(),
            WakeDisposition::Queued
        );
        assert!(scheduler.queued_len() >= 2);
    }

    #[test]
    fn queue_key_static_shape_contains_only_thread_key_and_execution_generation() {
        fn exact_shape(key: QueueKey) -> (crate::kernel::ThreadKey, u64) {
            let QueueKey { thread, generation } = key;
            (thread, generation.raw())
        }

        let (kernel, context) = bootstrap(12_114);
        publish(&context, 18);
        let generation = context.thread().execution_state().generation().unwrap();
        assert_eq!(
            exact_shape(QueueKey {
                thread: context.thread().key(),
                generation,
            }),
            (context.thread().key(), 1)
        );
        drop(kernel);
    }
}
