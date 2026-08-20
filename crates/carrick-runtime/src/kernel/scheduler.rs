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
    fn kick(&self, token: ExecutorKickToken);
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

#[derive(Clone, Copy, Debug)]
pub struct ExecutorRegistration {
    id: ExecutorId,
}

#[derive(Debug)]
struct ExecutorEntry {
    kick: Arc<dyn ExecutorKick>,
    binding: Option<ExecutorBinding>,
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
        state.entries.insert(
            id,
            ExecutorEntry {
                kick,
                binding: None,
            },
        );
        Ok(ExecutorRegistration { id })
    }

    fn bind(
        &self,
        registration: &ExecutorRegistration,
        binding: ExecutorBinding,
    ) -> Result<(), RunQueueError> {
        let mut state = self.state.lock();
        let entry = state
            .entries
            .get_mut(&registration.id)
            .ok_or(RunQueueError::StaleExecutor)?;
        if entry.binding.is_some() {
            return Err(RunQueueError::ExecutorBusy);
        }
        entry.binding = Some(binding);
        Ok(())
    }

    fn unbind(&self, binding: ExecutorBinding) {
        let mut state = self.state.lock();
        let Some(entry) = state.entries.get_mut(&binding.executor) else {
            return;
        };
        if entry.binding == Some(binding) {
            entry.binding = None;
        }
    }

    fn binding_for_thread(&self, thread: ThreadKey) -> Option<ExecutorBinding> {
        self.state
            .lock()
            .entries
            .values()
            .filter_map(|entry| entry.binding)
            .find(|binding| binding.thread == thread)
    }

    fn has_running(&self) -> bool {
        self.state
            .lock()
            .entries
            .values()
            .any(|entry| entry.binding.is_some())
    }

    fn current_tokens(&self) -> Vec<ExecutorKickToken> {
        self.state
            .lock()
            .entries
            .values()
            .filter_map(|entry| entry.binding.map(ExecutorBinding::token))
            .collect()
    }

    fn deliver(&self, token: ExecutorKickToken) -> bool {
        let kick = {
            let state = self.state.lock();
            let Some(entry) = state.entries.get(&token.executor) else {
                return false;
            };
            if entry.binding.map(ExecutorBinding::token) != Some(token) {
                return false;
            }
            Arc::clone(&entry.kick)
        };
        kick.kick(token);
        true
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
            closed_waiter_observations: 0,
        }
    }
}

#[derive(Debug, Default)]
struct RunQueueInner {
    state: Mutex<RunQueueState>,
    changed: Condvar,
}

impl RunQueueInner {
    fn maybe_finish_close(&self, state: &mut RunQueueState) {
        if state.lifecycle == QueueLifecycle::Closing
            && state.rows.is_empty()
            && state.active_authorities == 0
            && state.claimed == 0
        {
            state.lifecycle = QueueLifecycle::Closed;
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
    pub fn admit_descendant(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
    ) -> Result<Self, RunQueueError> {
        if !self.active {
            return Err(RunQueueError::AuthorityMismatch);
        }
        let kernel = self.kernel.upgrade().ok_or(RunQueueError::Closed)?;
        let exact = kernel
            .exact_thread_for_scheduler(thread)
            .ok_or(RunQueueError::AuthorityMismatch)?;
        if exact.execution_state().generation() != Some(generation) {
            return Err(RunQueueError::AuthorityMismatch);
        }
        let queue = self.queue.upgrade().ok_or(RunQueueError::Closed)?;
        let mut state = queue.state.lock();
        if state.lifecycle == QueueLifecycle::Closed {
            return Err(RunQueueError::Closed);
        }
        state.active_authorities = state
            .active_authorities
            .checked_add(1)
            .ok_or(RunQueueError::SubmissionRejected)?;
        drop(state);
        Ok(Self {
            queue: Arc::downgrade(&queue),
            kernel: Arc::downgrade(&kernel),
            key: QueueKey { thread, generation },
            active: true,
        })
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
        let mut state = self.inner.state.lock();
        if state.lifecycle != QueueLifecycle::Open {
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

    fn take_row(&self) -> Result<QueueRow, RunQueueError> {
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
                state.closed_waiter_observations = state
                    .closed_waiter_observations
                    .checked_add(1)
                    .unwrap_or_else(|| std::process::abort());
                return Err(RunQueueError::Closed);
            }
            state.waiters = state
                .waiters
                .checked_add(1)
                .unwrap_or_else(|| std::process::abort());
            self.inner.changed.wait(&mut state);
            state.waiters = state
                .waiters
                .checked_sub(1)
                .unwrap_or_else(|| std::process::abort());
        }
    }

    /// Claim the first row that still names the exact current Runnable
    /// generation. Stale rows are consumed here and never escape as runnable
    /// authority.
    pub(crate) fn take(&self, executor: ExecutorId) -> Result<QueueClaim, RunQueueError> {
        loop {
            let row = self.take_row()?;
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
            let lease = match row.thread.claim_runnable(executor) {
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
        let mut state = self.inner.state.lock();
        if state.lifecycle == QueueLifecycle::Open {
            state.lifecycle = QueueLifecycle::Closing;
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

    fn take_lease(&mut self) -> ThreadExecutionLease {
        self.lease.take().unwrap_or_else(|| std::process::abort())
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

    pub fn admit_root(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
    ) -> Result<SubmissionAuthority, SchedulerError> {
        let exact = self
            .kernel
            .exact_thread_for_scheduler(thread)
            .ok_or(SchedulerError::UnknownThread)?;
        if exact.execution_state().generation() != Some(generation) {
            return Err(RunQueueError::AuthorityMismatch.into());
        }
        Ok(self
            .queue
            .admit_root(&self.kernel, QueueKey { thread, generation })?)
    }

    pub fn make_runnable(&self, thread: ThreadKey) -> Result<WakeDisposition, SchedulerError> {
        self.wake(thread)
    }

    pub fn wake(&self, thread: ThreadKey) -> Result<WakeDisposition, SchedulerError> {
        let action = self.decide_wake(thread)?;
        self.deliver_wake(action)
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
        let QueueClaim { row, lease } = self.queue.take(executor.id)?;
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
    fn waiter_count(&self) -> usize {
        self.queue.waiter_count()
    }

    #[cfg(test)]
    fn closed_waiter_observations(&self) -> usize {
        self.queue.closed_waiter_observations()
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
        tokens: parking_lot::Mutex<Vec<ExecutorKickToken>>,
    }

    impl ExecutorKick for RecordingKick {
        fn kick(&self, token: ExecutorKickToken) {
            self.tokens.lock().push(token);
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
        let child = sibling(&kernel, &root, 22_110);
        publish(&root, 12);
        publish(&child, 13);
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

        scheduler.close();
        assert!(scheduler.make_runnable(child.thread().key()).is_err());
        assert!(
            scheduler
                .admit_root(
                    child.thread().key(),
                    child.thread().execution_state().generation().unwrap()
                )
                .is_err()
        );
        let descendant = root_authority
            .admit_descendant(
                child.thread().key(),
                child.thread().execution_state().generation().unwrap(),
            )
            .unwrap();
        descendant
            .publish(&scheduler, Arc::clone(child.thread()))
            .unwrap();
        drop(descendant);
        drop(root_authority);
        scheduler.wait_closed();
        for waiter in waiters {
            waiter.join().unwrap();
        }

        assert_eq!(claimed.load(Ordering::SeqCst), 1);
        assert_eq!(closed.load(Ordering::SeqCst), 2);
        assert_eq!(scheduler.closed_waiter_observations(), 2);
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
