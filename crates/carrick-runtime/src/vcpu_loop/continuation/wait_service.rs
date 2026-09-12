//! Carrier wait service and registration state machine.
//!
//! Owns [`CarrierWaitService`] and its registration table, reactor thread,
//! and event futures for dispatch continuations.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use carrick_fatal::carrick_fatal;
use parking_lot::{Condvar, Mutex};

use super::{
    BlockedContinuation, CancellationCause, ContinuationEvent, ContinuationId,
    ContinuationRegistration, ContinuationResumeError, ContinuationWakeToken, ReadinessProbe,
    SignalReadinessProbe, next_nonzero,
};
use crate::dispatch::{BlockingHostWrite, DispatchOutcome, WaitFdAuthority};
use crate::kernel::Scheduler;
use crate::kernel::objects::ThreadKey;
use crate::run_result::RuntimeError;

static NEXT_REGISTRATION_GENERATION: AtomicU64 = AtomicU64::new(1);

fn make_control_pipe() -> Result<(OwnedFd, OwnedFd), RuntimeError> {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(RuntimeError::CarrierFailed(format!(
            "host pipe creation failed when initializing wait reactor: errno={err}"
        )));
    }
    for fd in fds {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        let fd_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0
            || fd_flags < 0
            || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            || unsafe { libc::fcntl(fd, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) } < 0
        {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return Err(RuntimeError::CarrierFailed(format!(
                "host fcntl configuration failed on reactor control pipe fd={fd}: errno={err}"
            )));
        }
    }
    Ok((unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
        OwnedFd::from_raw_fd(fds[1])
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::vcpu_loop) enum RegistrationState {
    Prepared,
    Enrolled,
    Ready,
    Cancelled(CancellationCause),
    Consumed,
}

#[allow(dead_code)]
pub(in crate::vcpu_loop) enum ProducerSubscription {
    Futex(carrick_thread::thread::FutexGenerationSubscription),
    Task(crate::kernel::objects::TaskWakeSubscription),
    Vfork(crate::kernel::core::VforkReleaseSubscription),
    FileSlot(crate::kernel::objects::FileSlotSubscription),
    WaitQueue(crate::kernel::WaitCallbackEnrollment),
}

impl std::fmt::Debug for ProducerSubscription {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Futex(_) => formatter.write_str("FutexGenerationSubscription"),
            Self::Task(_) => formatter.write_str("TaskWakeSubscription"),
            Self::Vfork(_) => formatter.write_str("VforkReleaseSubscription"),
            Self::FileSlot(_) => formatter.write_str("FileSlotSubscription"),
            Self::WaitQueue(_) => formatter.write_str("WaitQueueSubscription"),
        }
    }
}

#[derive(Debug)]
pub(in crate::vcpu_loop) struct RegistrationOperationGate {
    pub(super) token: ContinuationWakeToken,
    pub(in crate::vcpu_loop) state: Mutex<OperationGateState>,
    drain_condvar: Condvar,
}

#[derive(Debug)]
pub(in crate::vcpu_loop) struct OperationGateState {
    cancelled: bool,
    consumed: bool,
    in_flight: usize,
    drain_waker: Option<Waker>,
}

pub(in crate::vcpu_loop) struct OperationClaimGuard {
    gate: Arc<RegistrationOperationGate>,
}

impl Drop for OperationClaimGuard {
    fn drop(&mut self) {
        let waker = {
            let mut state = self.gate.state.lock();
            state.in_flight = state.in_flight.saturating_sub(1);
            if state.in_flight == 0 {
                self.gate.drain_condvar.notify_all();
                state.drain_waker.take()
            } else {
                None
            }
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl RegistrationOperationGate {
    fn new(token: ContinuationWakeToken) -> Self {
        Self {
            token,
            state: Mutex::new(OperationGateState {
                cancelled: false,
                consumed: false,
                in_flight: 0,
                drain_waker: None,
            }),
            drain_condvar: Condvar::new(),
        }
    }

    pub(in crate::vcpu_loop) fn try_claim(
        self: &Arc<Self>,
        expected_token: ContinuationWakeToken,
    ) -> Option<OperationClaimGuard> {
        if self.token != expected_token {
            return None;
        }
        let mut state = self.state.lock();
        if state.cancelled || state.consumed {
            return None;
        }
        state.in_flight += 1;
        Some(OperationClaimGuard {
            gate: Arc::clone(self),
        })
    }

    pub(in crate::vcpu_loop) fn close_admission_cancelled(&self) {
        let mut state = self.state.lock();
        state.cancelled = true;
    }

    pub(in crate::vcpu_loop) fn close_admission_consumed(&self) {
        let mut state = self.state.lock();
        state.consumed = true;
    }

    pub(in crate::vcpu_loop) fn drain(&self) {
        let mut state = self.state.lock();
        while state.in_flight > 0 {
            self.drain_condvar.wait(&mut state);
        }
    }
}

#[derive(Debug)]
pub(in crate::vcpu_loop) struct RegistrationEntry {
    pub(in crate::vcpu_loop) token: ContinuationWakeToken,
    pub(in crate::vcpu_loop) state: RegistrationState,
    pub(in crate::vcpu_loop) event: Option<ContinuationEvent>,
    pub(in crate::vcpu_loop) probe: ReadinessProbe,
    pub(in crate::vcpu_loop) deadline: Option<Instant>,
    pub(in crate::vcpu_loop) task_waker: Option<Waker>,
    pub(in crate::vcpu_loop) subscriptions: Vec<ProducerSubscription>,
    pub(in crate::vcpu_loop) signal_readiness: SignalReadinessProbe,
    pub(in crate::vcpu_loop) operation_gate: Arc<RegistrationOperationGate>,
}

/// The reactor's O(1)-per-cycle view of the registration map.
///
/// The reactor used to derive its whole cycle by scanning EVERY registration
/// three times — once to build the poll set and compute the nearest deadline,
/// once to find expired deadlines, once to find record locks — while the rows
/// that contribute a pollfd are a handful. Every futex, timer and child wait
/// parked anywhere in the carrier sat in that scan, so ONE wake cost
/// O(live blocked tasks), and the single reactor thread is on the wake path of
/// every blocking guest syscall. Measured on `go-go_types` (main `251ab7b4f`):
/// 107,881 reactor cycles, host `poll` width 1-4 in every one of them, and
/// `BTreeMap::Values::next` the single hottest Carrick user symbol in the row's
/// profile at 9.1% of carrier user CPU.
///
/// The three sets below carry exactly the three facts a cycle needs. They are
/// maintained by [`CarrierWaitState`]'s mutators, which are the ONLY way to
/// insert, remove or mutate a registration — a bare `entries.get_mut` would let
/// a state transition desynchronise the index, so the source-shape test in this
/// module refuses one.
#[derive(Debug, Default)]
pub(in crate::vcpu_loop) struct ReactorWorkSet {
    /// Enrolled registrations that contribute host pollfds.
    pub(in crate::vcpu_loop) pollable: BTreeSet<ContinuationId>,
    /// Enrolled registrations carrying a deadline, ordered BY deadline, so the
    /// nearest is the first key and the expired set is a prefix.
    pub(in crate::vcpu_loop) deadlines: BTreeSet<(Instant, ContinuationId)>,
    /// Enrolled `RecordLock` registrations, each of which asks the cycle for a
    /// 10 ms retry tick and a drive attempt.
    pub(in crate::vcpu_loop) record_locks: BTreeSet<ContinuationId>,
}

impl ReactorWorkSet {
    /// Recompute this registration's membership from its CURRENT fields.
    ///
    /// Idempotent and total: it both adds and removes, so one call after any
    /// mutation restores the invariant regardless of what changed.
    pub(super) fn sync(&mut self, id: ContinuationId, entry: &RegistrationEntry) {
        let enrolled = entry.state == RegistrationState::Enrolled;
        if enrolled && entry.probe.contributes_pollfds() {
            self.pollable.insert(id);
        } else {
            self.pollable.remove(&id);
        }
        if let Some(deadline) = entry.deadline {
            if enrolled {
                self.deadlines.insert((deadline, id));
            } else {
                self.deadlines.remove(&(deadline, id));
            }
        }
        if enrolled && matches!(entry.probe, ReadinessProbe::RecordLock { .. }) {
            self.record_locks.insert(id);
        } else {
            self.record_locks.remove(&id);
        }
    }

    /// Drop every trace of a registration that no longer exists.
    pub(super) fn forget(&mut self, id: ContinuationId, entry: &RegistrationEntry) {
        self.pollable.remove(&id);
        self.record_locks.remove(&id);
        if let Some(deadline) = entry.deadline {
            self.deadlines.remove(&(deadline, id));
        }
    }

    pub(in crate::vcpu_loop) fn nearest_deadline(&self) -> Option<Instant> {
        self.deadlines.first().map(|(deadline, _)| *deadline)
    }

    /// Enrolled registrations whose deadline has already passed. The set is
    /// ordered by deadline, so the expired rows are its prefix.
    pub(in crate::vcpu_loop) fn expired_at(
        &self,
        now: Instant,
    ) -> impl Iterator<Item = ContinuationId> + '_ {
        self.deadlines
            .iter()
            .take_while(move |(deadline, _)| now >= *deadline)
            .map(|(_, id)| *id)
    }
}

/// A registration borrowed for mutation together with the index that must be
/// resynchronised afterwards. `Drop` does the resync, so a caller cannot leave
/// the reactor's view stale by taking an early return out of the borrow.
pub(in crate::vcpu_loop) struct IndexedEntryMut<'state> {
    id: ContinuationId,
    /// The two facts membership is derived from, read when the borrow opened.
    /// `Drop` resynchronises only when one of them moved, so the many borrows
    /// that merely READ a registration — every `ContinuationEventFuture::poll`,
    /// every readiness recheck — cost nothing. The probe's discriminant is
    /// carried rather than assumed constant: nothing in the type stops a future
    /// caller from replacing a registration's probe in place.
    membership: (RegistrationState, std::mem::Discriminant<ReadinessProbe>),
    entry: &'state mut RegistrationEntry,
    index: &'state mut ReactorWorkSet,
}

impl std::ops::Deref for IndexedEntryMut<'_> {
    type Target = RegistrationEntry;
    fn deref(&self) -> &Self::Target {
        self.entry
    }
}

impl std::ops::DerefMut for IndexedEntryMut<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.entry
    }
}

impl Drop for IndexedEntryMut<'_> {
    fn drop(&mut self) {
        if membership_inputs(self.entry) != self.membership {
            self.index.sync(self.id, self.entry);
        }
    }
}

/// Everything [`ReactorWorkSet::sync`] reads out of a registration. A borrow
/// that leaves these untouched cannot have changed the registration's
/// membership in any of the three sets.
fn membership_inputs(
    entry: &RegistrationEntry,
) -> (RegistrationState, std::mem::Discriminant<ReadinessProbe>) {
    (entry.state, std::mem::discriminant(&entry.probe))
}

#[derive(Debug, Default)]
pub(in crate::vcpu_loop) struct CarrierWaitState {
    pub(super) entries: BTreeMap<ContinuationId, RegistrationEntry>,
    pub(super) reactor_work: ReactorWorkSet,
    #[cfg(test)]
    pub(super) last_prepared: Option<ContinuationWakeToken>,
}

impl CarrierWaitState {
    /// Publish a fresh registration. Returns the displaced row, if any — the
    /// caller treats that as fatal.
    fn insert_registration(
        &mut self,
        id: ContinuationId,
        entry: RegistrationEntry,
    ) -> Option<RegistrationEntry> {
        let replaced = self.entries.insert(id, entry);
        if let Some(replaced) = replaced.as_ref() {
            self.reactor_work.forget(id, replaced);
        }
        if let Some(entry) = self.entries.get(&id) {
            self.reactor_work.sync(id, entry);
        }
        replaced
    }

    /// Retire a registration and every index row derived from it.
    pub(in crate::vcpu_loop) fn remove_registration(
        &mut self,
        id: ContinuationId,
    ) -> Option<RegistrationEntry> {
        let removed = self.entries.remove(&id);
        if let Some(entry) = removed.as_ref() {
            self.reactor_work.forget(id, entry);
        }
        removed
    }

    /// Borrow a registration for mutation; the index is resynchronised when the
    /// guard drops, on every path.
    pub(in crate::vcpu_loop) fn registration_mut(
        &mut self,
        id: ContinuationId,
    ) -> Option<IndexedEntryMut<'_>> {
        let Self {
            entries,
            reactor_work,
            ..
        } = self;
        entries.get_mut(&id).map(|entry| IndexedEntryMut {
            id,
            membership: membership_inputs(entry),
            entry,
            index: reactor_work,
        })
    }

    /// Cancel every registration still awaiting a wake, returning their wakers.
    /// Bulk form of [`Self::registration_mut`] for service shutdown.
    pub(in crate::vcpu_loop) fn cancel_all_active(
        &mut self,
        cause: CancellationCause,
    ) -> (Vec<Waker>, Vec<Arc<RegistrationOperationGate>>) {
        let Self {
            entries,
            reactor_work,
            ..
        } = self;
        let mut wakers = Vec::new();
        let mut gates = Vec::new();
        for (id, entry) in entries.iter_mut() {
            if matches!(
                entry.state,
                RegistrationState::Prepared
                    | RegistrationState::Enrolled
                    | RegistrationState::Ready
            ) {
                entry.operation_gate.close_admission_cancelled();
                entry.state = RegistrationState::Cancelled(cause);
                let _ = entry.event.take();
                if let Some(waker) = entry.task_waker.take() {
                    wakers.push(waker);
                }
                gates.push(Arc::clone(&entry.operation_gate));
                reactor_work.sync(*id, entry);
            }
        }
        (wakers, gates)
    }
}

#[cfg(test)]
#[derive(Default)]
struct ReactorTestHooks {
    before_host_write_drive: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    inside_host_write_drive: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    before_recheck_probe: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    after_recheck_claim: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

#[cfg(test)]
impl std::fmt::Debug for ReactorTestHooks {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ReactorTestHooks")
    }
}

#[derive(Debug)]
pub(in crate::vcpu_loop) struct CarrierWaitServiceInner {
    scheduler: Arc<Scheduler>,
    pub(super) state: Mutex<CarrierWaitState>,
    shutdown: AtomicBool,
    service_handles: AtomicU64,
    reactor: Mutex<Option<std::thread::JoinHandle<()>>>,
    control_read: OwnedFd,
    control_write: OwnedFd,
    reactor_poll_calls: AtomicU64,
    /// Registrations the reactor has TOUCHED to build its poll sets, summed
    /// over every cycle. The number a cycle adds is the reactor's per-wake
    /// cost: it used to be the whole registration map, and this counter is how
    /// a test proves it no longer is.
    reactor_cycle_visits: AtomicU64,
    #[cfg(test)]
    fail_next_enroll: AtomicBool,
    #[cfg(test)]
    /// Test observer for "a poll cycle completed", paired with the
    /// `reactor_poll_calls` value when it was installed so a cycle that had
    /// already counted before installation cannot satisfy it.
    reactor_poll_observer: Mutex<Option<(u64, Arc<std::sync::Barrier>)>>,
    #[cfg(test)]
    test_hooks: ReactorTestHooks,
}

impl CarrierWaitServiceInner {
    pub(super) fn nudge_reactor(&self) {
        let byte = [1u8; 1];
        let _ = unsafe {
            libc::write(
                self.control_write.as_raw_fd(),
                byte.as_ptr().cast(),
                byte.len(),
            )
        };
    }
    fn attach_subscription(
        &self,
        token: ContinuationWakeToken,
        subscription: ProducerSubscription,
    ) {
        let mut state = self.state.lock();
        let Some(mut entry) = state
            .registration_mut(token.continuation)
            .filter(|entry| entry.token == token)
        else {
            return;
        };
        if matches!(
            entry.state,
            RegistrationState::Prepared | RegistrationState::Enrolled
        ) {
            entry.subscriptions.push(subscription);
        }
    }

    fn publish_task_wake(&self, token: ContinuationWakeToken) {
        let (probe, task_event_fired) = {
            let state = self.state.lock();
            let Some(entry) = state
                .entries
                .get(&token.continuation)
                .filter(|entry| entry.token == token)
            else {
                return;
            };
            if !matches!(
                entry.state,
                RegistrationState::Prepared | RegistrationState::Enrolled
            ) {
                return;
            }
            let task_event_fired = entry
                .signal_readiness
                .task_ref
                .upgrade()
                .is_some_and(|task| {
                    task.task_event_generation() != entry.signal_readiness.observed_task_event
                });
            (entry.signal_readiness.clone(), task_event_fired)
        };
        if let Some(event) = probe.event_after_task_wake() {
            self.publish_event(token, event);
        } else if task_event_fired && probe.family.accepts_task_event() {
            self.publish_event(token, ContinuationEvent::Ready);
        }
    }

    pub(super) fn cancel_exact(
        &self,
        token: ContinuationWakeToken,
        cause: CancellationCause,
    ) -> bool {
        let (gate, task_waker, was_active) = {
            let mut state = self.state.lock();
            let Some(mut entry) = state.registration_mut(token.continuation) else {
                return false;
            };
            if entry.token != token {
                return false;
            }
            let gate = Arc::clone(&entry.operation_gate);
            let was_active = matches!(
                entry.state,
                RegistrationState::Prepared | RegistrationState::Enrolled
            );
            if matches!(
                entry.state,
                RegistrationState::Prepared
                    | RegistrationState::Enrolled
                    | RegistrationState::Ready
            ) {
                entry.operation_gate.close_admission_cancelled();
                entry.state = RegistrationState::Cancelled(cause);
                let _ = entry.event.take();
                entry.subscriptions.clear();
            }
            let task_waker = entry.task_waker.take();
            (gate, task_waker, was_active)
        };
        gate.drain();
        self.nudge_reactor();
        if let Some(waker) = task_waker {
            waker.wake();
        }
        was_active
    }

    pub(in crate::vcpu_loop) fn consume_ready_exact(
        &self,
        token: ContinuationWakeToken,
    ) -> Result<(), ContinuationResumeError> {
        let (gate, task_waker) = {
            let mut state = self.state.lock();
            let mut entry = state
                .registration_mut(token.continuation)
                .filter(|entry| entry.token == token)
                .ok_or(ContinuationResumeError::MissingContinuation)?;
            if entry.state != RegistrationState::Ready {
                return Err(ContinuationResumeError::MissingContinuation);
            }
            entry.operation_gate.close_admission_consumed();
            entry.state = RegistrationState::Consumed;
            let gate = Arc::clone(&entry.operation_gate);
            let task_waker = entry.task_waker.take();
            drop(entry);
            (gate, task_waker)
        };
        gate.drain();
        let removed = {
            let mut state = self.state.lock();
            state.remove_registration(token.continuation)
        };
        drop(removed);
        drop(task_waker);
        Ok(())
    }

    fn publish_signal_for_thread(&self, thread: ThreadKey) -> bool {
        let candidates: Vec<(ContinuationWakeToken, SignalReadinessProbe)> = {
            let state = self.state.lock();
            state
                .entries
                .values()
                .filter(|entry| {
                    entry.token.thread == thread
                        && matches!(
                            entry.state,
                            RegistrationState::Prepared | RegistrationState::Enrolled
                        )
                })
                .map(|entry| (entry.token, entry.signal_readiness.clone()))
                .collect()
        };
        let mut published = false;
        for (token, probe) in candidates {
            if let Some(event) = probe.event_after_task_wake() {
                self.publish_event(token, event);
                published = true;
            }
        }
        published
    }

    pub(in crate::vcpu_loop) fn publish_event(
        &self,
        token: ContinuationWakeToken,
        event: ContinuationEvent,
    ) -> WakePublishReceipt {
        let (won, task_waker) = {
            let mut state = self.state.lock();
            let Some(mut entry) = state.registration_mut(token.continuation) else {
                return WakePublishReceipt::rejected();
            };
            if entry.token != token
                || !matches!(
                    entry.state,
                    RegistrationState::Prepared | RegistrationState::Enrolled
                )
            {
                return WakePublishReceipt::rejected();
            }
            entry.state = RegistrationState::Ready;
            entry.event = Some(event);
            let task_waker = entry.task_waker.take();
            (true, task_waker)
        };
        let _ = self.scheduler.wake(token.thread);
        self.nudge_reactor();
        if let Some(waker) = task_waker {
            waker.wake();
        }
        WakePublishReceipt {
            accepted: won,
            first: won,
        }
    }

    fn run_reactor(weak: Weak<Self>) {
        enum FdSource {
            Ready(ContinuationWakeToken),
            HostWrite(
                ContinuationWakeToken,
                Arc<Mutex<BlockingHostWrite>>,
                Arc<Mutex<Option<DispatchOutcome>>>,
                Arc<RegistrationOperationGate>,
            ),
        }
        loop {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            if inner.shutdown.load(Ordering::Acquire) {
                return;
            }
            let control_fd = inner.control_read.as_raw_fd();
            // The cycle reads the reactor work set, never the registration map:
            // the nearest deadline is one lookup and only the pollable rows are
            // visited, so a carrier with thousands of tasks parked on futexes,
            // timers and child waits costs the same here as one with none.
            let (mut pollfds, sources, nearest_deadline, registrations, visited) = {
                let state = inner.state.lock();
                let mut pollfds = vec![libc::pollfd {
                    fd: control_fd,
                    events: libc::POLLIN,
                    revents: 0,
                }];
                let mut sources = Vec::new();
                let mut nearest_deadline = state.reactor_work.nearest_deadline();
                let mut visited = 0u32;
                for id in &state.reactor_work.pollable {
                    let Some(entry) = state.entries.get(id) else {
                        continue;
                    };
                    visited = visited.saturating_add(1);
                    match &entry.probe {
                        ReadinessProbe::Fds { registrations, .. } => {
                            for registration in registrations {
                                pollfds.push(libc::pollfd {
                                    fd: registration.fd.as_raw_fd(),
                                    events: registration.events,
                                    revents: 0,
                                });
                                sources.push(FdSource::Ready(entry.token));
                            }
                        }
                        ReadinessProbe::HostWrite {
                            host_fd,
                            write,
                            completion,
                        } => {
                            pollfds.push(libc::pollfd {
                                fd: *host_fd,
                                events: libc::POLLOUT,
                                revents: 0,
                            });
                            sources.push(FdSource::HostWrite(
                                entry.token,
                                Arc::clone(write),
                                Arc::clone(completion),
                                Arc::clone(&entry.operation_gate),
                            ));
                        }
                        _ => {}
                    }
                }
                // A record lock has no readiness fd: it is retried on a tick, so
                // its presence alone bounds the poll timeout.
                if !state.reactor_work.record_locks.is_empty() {
                    let retry = Instant::now() + Duration::from_millis(10);
                    nearest_deadline =
                        Some(nearest_deadline.map_or(retry, |current| current.min(retry)));
                }
                let registrations = u32::try_from(state.entries.len()).unwrap_or(u32::MAX);
                (pollfds, sources, nearest_deadline, registrations, visited)
            };
            let timeout_ms = nearest_deadline.map_or(-1, |deadline| {
                let remaining = deadline.saturating_duration_since(Instant::now());
                i32::try_from(remaining.as_millis().max(1)).unwrap_or(i32::MAX)
            });
            inner
                .reactor_cycle_visits
                .fetch_add(u64::from(visited), Ordering::Relaxed);
            crate::probes::hvpatch_reactor_cycle(
                registrations,
                visited,
                u32::try_from(pollfds.len()).unwrap_or(u32::MAX),
                timeout_ms,
            );
            drop(inner);
            let result = unsafe {
                libc::poll(
                    pollfds.as_mut_ptr(),
                    pollfds.len() as libc::nfds_t,
                    timeout_ms,
                )
            };
            let Some(inner) = weak.upgrade() else {
                return;
            };
            inner.reactor_poll_calls.fetch_add(1, Ordering::Relaxed);
            if inner.shutdown.load(Ordering::Acquire) {
                return;
            }
            if result >= 0 && pollfds[0].revents != 0 {
                let mut bytes = [0u8; 256];
                loop {
                    let read =
                        unsafe { libc::read(control_fd, bytes.as_mut_ptr().cast(), bytes.len()) };
                    if read <= 0 {
                        break;
                    }
                }
            }
            // The observer means "a poll cycle COMPLETED", and completing one
            // includes draining the control pipe. Signalling before the drain
            // loses a nudge that lands between the take and the drain: the
            // drain swallows the byte, the next `poll` has nothing to wake on,
            // and an installed observer then waits forever on a reactor parked
            // in `poll(-1)`. Taking the observer after the drain closes that
            // window in both directions — a nudge that arrives after the drain
            // is still in the pipe and wakes the next poll, whose take then
            // finds this observer.
            #[cfg(test)]
            {
                // Only a cycle that COUNTED after the observer was installed
                // satisfies it. The increment above happens before this take,
                // so a cycle already in flight when the observer arrived would
                // otherwise rendezvous while the counter it published was
                // already included in the waiter's "before" reading -- the
                // observer fires, the count has not moved, and the waiter
                // concludes the reactor ignored its nudge.
                let mut slot = inner.reactor_poll_observer.lock();
                let stale = slot.as_ref().is_some_and(|(installed_at, _)| {
                    inner.reactor_poll_calls.load(Ordering::Acquire) <= *installed_at
                });
                if stale {
                    drop(slot);
                    // Declining costs a wakeup: this cycle may have drained the
                    // very byte that was meant to wake the next one, which
                    // would park the reactor in `poll(-1)` with an observer
                    // nobody can satisfy. Re-arm so the next cycle runs
                    // immediately and finds this observer.
                    inner.nudge_reactor();
                } else if let Some((_, observer)) = slot.take() {
                    drop(slot);
                    observer.wait();
                }
            }
            if result < 0 {
                continue;
            }
            for (pollfd, source) in pollfds.iter().skip(1).zip(sources) {
                if pollfd.revents == 0 {
                    continue;
                }
                match source {
                    FdSource::Ready(token) => {
                        inner.publish_event(token, ContinuationEvent::Ready);
                    }
                    FdSource::HostWrite(token, write, completion, gate) => {
                        #[cfg(test)]
                        if let Some(hook) = inner.test_hooks.before_host_write_drive.lock().as_ref()
                        {
                            hook();
                        }
                        if let Some(claim) = gate.try_claim(token) {
                            let outcome = {
                                let mut write = write.lock();
                                #[cfg(test)]
                                if let Some(hook) =
                                    inner.test_hooks.inside_host_write_drive.lock().as_ref()
                                {
                                    hook();
                                }
                                match crate::dispatch::drive_blocking_host_write(&mut write) {
                                    crate::dispatch::BlockingHostWriteStep::Done(outcome) => {
                                        Some(outcome)
                                    }
                                    crate::dispatch::BlockingHostWriteStep::Wait => None,
                                }
                            };
                            let done = outcome.is_some();
                            if let Some(outcome) = outcome {
                                *completion.lock() = Some(outcome);
                            }
                            drop(claim);
                            if done {
                                inner.publish_event(token, ContinuationEvent::Ready);
                            }
                        }
                    }
                }
            }
            let now = Instant::now();
            let expired = {
                let state = inner.state.lock();
                state
                    .reactor_work
                    .expired_at(now)
                    .filter_map(|id| state.entries.get(&id).map(|entry| entry.token))
                    .collect::<Vec<_>>()
            };
            for token in expired {
                inner.publish_event(token, ContinuationEvent::Timeout);
            }
            let record_locks = {
                let state = inner.state.lock();
                state
                    .reactor_work
                    .record_locks
                    .iter()
                    .filter_map(|id| {
                        let entry = state.entries.get(id)?;
                        let ReadinessProbe::RecordLock { lock, completion } = &entry.probe else {
                            return None;
                        };
                        Some((
                            entry.token,
                            Arc::clone(lock),
                            Arc::clone(completion),
                            Arc::clone(&entry.operation_gate),
                        ))
                    })
                    .collect::<Vec<_>>()
            };
            for (token, lock, completion, gate) in record_locks {
                if let Some(claim) = gate.try_claim(token) {
                    let outcome = match crate::dispatch::try_drive_blocking_record_lock(&lock) {
                        crate::dispatch::BlockingRecordLockStep::Done(outcome) => Some(outcome),
                        crate::dispatch::BlockingRecordLockStep::Wait => None,
                    };
                    let done = outcome.is_some();
                    if let Some(outcome) = outcome {
                        *completion.lock() = Some(outcome);
                    }
                    drop(claim);
                    if done {
                        inner.publish_event(token, ContinuationEvent::Ready);
                    }
                }
            }
        }
    }
}

impl Drop for CarrierWaitServiceInner {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        self.nudge_reactor();
        if let Some(handle) = self.reactor.get_mut().take()
            && handle.thread().id() != std::thread::current().id()
        {
            let _ = handle.join();
        }
    }
}

#[derive(Debug)]
pub struct CarrierWaitService {
    pub(in crate::vcpu_loop) inner: Arc<CarrierWaitServiceInner>,
}

impl Clone for CarrierWaitService {
    fn clone(&self) -> Self {
        self.inner.service_handles.fetch_add(1, Ordering::Relaxed);
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Drop for CarrierWaitService {
    fn drop(&mut self) {
        if self.inner.service_handles.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        let (wakers, gates) = {
            let mut state = self.inner.state.lock();
            state.cancel_all_active(CancellationCause::ServiceShutdown)
        };
        self.inner.shutdown.store(true, Ordering::Release);
        self.inner.nudge_reactor();
        for gate in gates {
            gate.drain();
        }
        for waker in wakers {
            waker.wake();
        }
        if let Some(handle) = self.inner.reactor.lock().take()
            && handle.thread().id() != std::thread::current().id()
        {
            let _ = handle.join();
        }
    }
}

impl CarrierWaitService {
    pub fn try_new(scheduler: Arc<Scheduler>) -> Result<Self, RuntimeError> {
        let (control_read, control_write) = make_control_pipe()?;
        let inner = Arc::new(CarrierWaitServiceInner {
            scheduler,
            state: Mutex::new(CarrierWaitState::default()),
            shutdown: AtomicBool::new(false),
            service_handles: AtomicU64::new(1),
            reactor: Mutex::new(None),
            control_read,
            control_write,
            reactor_poll_calls: AtomicU64::new(0),
            reactor_cycle_visits: AtomicU64::new(0),
            #[cfg(test)]
            fail_next_enroll: AtomicBool::new(false),
            #[cfg(test)]
            reactor_poll_observer: Mutex::new(None),
            #[cfg(test)]
            test_hooks: ReactorTestHooks::default(),
        });
        let weak = Arc::downgrade(&inner);
        let handle = std::thread::Builder::new()
            .name("carrick-carrier-wait".to_owned())
            .spawn(move || CarrierWaitServiceInner::run_reactor(weak))
            .map_err(|e| {
                RuntimeError::CarrierFailed(format!(
                    "host thread spawn failure for carrier wait reactor: error={e}"
                ))
            })?;
        *inner.reactor.lock() = Some(handle);
        Ok(Self { inner })
    }

    #[allow(clippy::expect_used)]
    pub fn new(scheduler: Arc<Scheduler>) -> Self {
        Self::try_new(scheduler).expect("carrier wait service initialization")
    }

    pub fn prepare_registration(
        &self,
        continuation: &BlockedContinuation,
    ) -> ContinuationRegistration {
        let authority = continuation.authority();
        let token = ContinuationWakeToken {
            continuation: continuation.id(),
            thread: authority.thread(),
            thread_serial: authority.thread().serial.raw(),
            execution: authority.execution_generation(),
            execution_raw: authority.execution_generation().raw(),
            mm_generation: authority.mm().raw(),
            asid_generation: authority.asid_generation(),
            resource_generation: continuation.state().resource_generation,
            registration_generation: next_nonzero(&NEXT_REGISTRATION_GENERATION),
        };
        let _resource_fingerprint = continuation.resource_fingerprint();
        let probe = ReadinessProbe::from_continuation(continuation);
        let signal_readiness = SignalReadinessProbe::from_continuation(continuation);
        let operation_gate = Arc::new(RegistrationOperationGate::new(token));
        let mut state = self.inner.state.lock();
        let replaced = state.insert_registration(
            token.continuation,
            RegistrationEntry {
                token,
                state: RegistrationState::Prepared,
                event: None,
                probe,
                deadline: continuation.deadline(),
                task_waker: None,
                subscriptions: Vec::new(),
                signal_readiness,
                operation_gate,
            },
        );
        if replaced.is_some() {
            carrick_fatal!(
                "vcpu_loop::continuation_registry",
                "duplicate continuation token in active registration table: token={:?}",
                token
            );
        }
        #[cfg(test)]
        {
            state.last_prepared = Some(token);
        }
        drop(state);
        self.inner.nudge_reactor();
        ContinuationRegistration {
            token,
            service: Arc::downgrade(&self.inner),
            enrolled: false,
            settled: false,
        }
    }

    pub fn enroll(
        &self,
        registration: &mut ContinuationRegistration,
    ) -> Result<(), WaitServiceError> {
        #[cfg(test)]
        if self.inner.fail_next_enroll.swap(false, Ordering::AcqRel) {
            return Err(WaitServiceError::StaleRegistration);
        }
        if registration.enrolled
            || !Weak::ptr_eq(&registration.service, &Arc::downgrade(&self.inner))
        {
            return Err(WaitServiceError::StaleRegistration);
        }
        let mut state = self.inner.state.lock();
        let mut entry = state
            .registration_mut(registration.token.continuation)
            .filter(|entry| entry.token == registration.token)
            .ok_or(WaitServiceError::StaleRegistration)?;
        if entry.state == RegistrationState::Prepared {
            entry.state = RegistrationState::Enrolled;
        }
        registration.enrolled = true;
        drop(entry);
        drop(state);
        self.install_producer_subscriptions(registration.token)?;
        // A producer edge may already be reflected in authoritative state by
        // the time the continuation captures its observed generations. In
        // that case subscription is correctly installed at the new generation
        // but has no later edge to report. Sample once after every subscription
        // is live so pre-capture signals/readiness cannot strand the task.
        let _ = self.recheck_registration(registration)?;
        self.inner.nudge_reactor();
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn fail_next_enroll_for_test(&self) {
        self.inner.fail_next_enroll.store(true, Ordering::Release);
    }

    fn install_producer_subscriptions(
        &self,
        token: ContinuationWakeToken,
    ) -> Result<(), WaitServiceError> {
        let (probe, signal, gate) = {
            let state = self.inner.state.lock();
            let entry = state
                .entries
                .get(&token.continuation)
                .filter(|entry| entry.token == token)
                .ok_or(WaitServiceError::StaleRegistration)?;
            (
                entry.probe.clone(),
                entry.signal_readiness.clone(),
                Arc::clone(&entry.operation_gate),
            )
        };
        let weak = Arc::downgrade(&self.inner);
        let futex_source = match &probe {
            ReadinessProbe::Futex { table, wait, .. } => Some((table.0.clone(), wait.clone())),
            ReadinessProbe::SharedWord { generation, .. } => Some((
                Arc::clone(carrick_thread::platform_futex::carrier_shared_futex_table()),
                generation.clone(),
            )),
            _ => None,
        };
        if let Some((table, wait)) = futex_source {
            let callback_weak = weak.clone();
            match table.subscribe_generation(
                wait,
                Arc::new(move |_| {
                    if let Some(inner) = callback_weak.upgrade() {
                        inner.publish_event(token, ContinuationEvent::Ready);
                    }
                }),
            ) {
                carrick_thread::thread::FutexGenerationEnrollment::Ready(_) => {
                    self.inner.publish_event(token, ContinuationEvent::Ready);
                }
                carrick_thread::thread::FutexGenerationEnrollment::Subscribed(subscription) => {
                    self.inner
                        .attach_subscription(token, ProducerSubscription::Futex(subscription));
                }
            }
        }
        if let Some(task) = signal.task_ref.upgrade() {
            let callback_weak = weak.clone();
            let mut observed = signal.observed_task_wake;
            loop {
                let callback = Arc::new({
                    let callback_weak = callback_weak.clone();
                    move |_| {
                        if let Some(inner) = callback_weak.upgrade() {
                            inner.publish_task_wake(token);
                        }
                    }
                });
                match task.subscribe_wake(observed, callback) {
                    crate::kernel::objects::TaskWakeEnrollment::Ready(current) => {
                        self.inner.publish_task_wake(token);
                        observed = current;
                    }
                    crate::kernel::objects::TaskWakeEnrollment::Subscribed(subscription) => {
                        self.inner
                            .attach_subscription(token, ProducerSubscription::Task(subscription));
                        break;
                    }
                }
            }
        }
        if let ReadinessProbe::Fds {
            file_table,
            fd_authority,
            ..
        } = &probe
            && let WaitFdAuthority::Logical { strict, watched } = fd_authority
        {
            for authority in strict.iter().chain(watched) {
                let callback_weak = weak.clone();
                let Some(subscription) = file_table.subscribe_slot_authority(
                    *authority,
                    Arc::new(move |_| {
                        if let Some(inner) = callback_weak.upgrade() {
                            inner.publish_event(token, ContinuationEvent::Ready);
                        }
                    }),
                ) else {
                    self.inner.publish_event(token, ContinuationEvent::Ready);
                    continue;
                };
                self.inner
                    .attach_subscription(token, ProducerSubscription::FileSlot(subscription));

                if let Some(description) = file_table.resolve_slot_authority(*authority)
                    && let Some(wq) = description.wait_queue()
                {
                    let callback_weak = weak.clone();
                    let enrollment = wq.enroll_callback(move |_| {
                        if let Some(inner) = callback_weak.upgrade() {
                            inner.publish_event(token, ContinuationEvent::Ready);
                        }
                    });
                    self.inner
                        .attach_subscription(token, ProducerSubscription::WaitQueue(enrollment));
                }
            }
        }
        if let ReadinessProbe::Vfork { wait } = &probe {
            let wait = wait.clone();
            let callback_weak = weak;
            match wait.subscribe_release(Arc::new(move |_| {
                if let Some(inner) = callback_weak.upgrade() {
                    inner.publish_event(token, ContinuationEvent::Ready);
                }
            })) {
                crate::kernel::core::VforkReleaseEnrollment::Ready(_) => {
                    self.inner.publish_event(token, ContinuationEvent::Ready);
                }
                crate::kernel::core::VforkReleaseEnrollment::Subscribed(subscription) => {
                    self.inner
                        .attach_subscription(token, ProducerSubscription::Vfork(subscription));
                }
            }
        }
        if let ReadinessProbe::SharedWord {
            location, value, ..
        } = &probe
        {
            if let Some(claim) = gate.try_claim(token) {
                let current = unsafe {
                    (location.wait_addr().raw() as *const std::sync::atomic::AtomicU32)
                        .as_ref()
                        .map(|word| word.load(Ordering::Acquire))
                };
                drop(claim);
                if current.is_none_or(|current| current != *value) {
                    self.inner.publish_event(token, ContinuationEvent::Ready);
                }
            }
        }
        Ok(())
    }

    /// Durable post-enrollment sample. [`Self::enroll`] calls this after every
    /// producer subscription is installed; explicit callers may repeat it
    /// before a destructive backend save. The shared reactor repeats the same
    /// readiness probes afterward, closing both sides of the registration
    /// window.
    pub fn recheck_registration(
        &self,
        registration: &ContinuationRegistration,
    ) -> Result<Option<ContinuationEvent>, WaitServiceError> {
        let (probe, signal_readiness, gate) = {
            let state = self.inner.state.lock();
            let entry = state
                .entries
                .get(&registration.token.continuation)
                .filter(|entry| entry.token == registration.token)
                .ok_or(WaitServiceError::StaleRegistration)?;
            if !matches!(
                entry.state,
                RegistrationState::Enrolled | RegistrationState::Prepared
            ) {
                return Ok(entry.event.clone());
            }
            (
                entry.probe.clone(),
                entry.signal_readiness.clone(),
                Arc::clone(&entry.operation_gate),
            )
        };

        #[cfg(test)]
        if let Some(hook) = self.inner.test_hooks.before_recheck_probe.lock().as_ref() {
            hook();
        }

        let Some(claim) = gate.try_claim(registration.token) else {
            let state = self.inner.state.lock();
            if let Some(entry) = state
                .entries
                .get(&registration.token.continuation)
                .filter(|entry| entry.token == registration.token)
            {
                return Ok(entry.event.clone());
            }
            return Err(WaitServiceError::StaleRegistration);
        };

        #[cfg(test)]
        if let Some(hook) = self.inner.test_hooks.after_recheck_claim.lock().as_ref() {
            hook();
        }

        let mut probe = probe;
        let event = signal_readiness.event().or_else(|| probe.poll());
        drop(claim);
        if let Some(event) = event {
            let receipt = self.inner.publish_event(registration.token, event.clone());
            if receipt.accepted() {
                return Ok(Some(event));
            }
        }
        Ok(None)
    }

    pub fn publish_ready(&self, token: ContinuationWakeToken) -> WakePublishReceipt {
        self.inner.publish_event(token, ContinuationEvent::Ready)
    }

    pub fn registration_timing(
        &self,
        token: ContinuationWakeToken,
    ) -> Result<RegistrationTiming, WaitServiceError> {
        let state = self.inner.state.lock();
        let entry = state
            .entries
            .get(&token.continuation)
            .filter(|entry| entry.token == token)
            .ok_or(WaitServiceError::StaleRegistration)?;
        Ok(RegistrationTiming {
            deadline: entry.deadline,
            has_periodic_probe: false,
        })
    }

    pub fn cancel_registration(
        &self,
        registration: ContinuationRegistration,
    ) -> Result<(), WaitServiceError> {
        self.cancel_registration_with_cause(registration, CancellationCause::ServiceShutdown)
    }

    pub fn cancel_registration_with_cause(
        &self,
        mut registration: ContinuationRegistration,
        cause: CancellationCause,
    ) -> Result<(), WaitServiceError> {
        let cancelled = self.inner.cancel_exact(registration.token, cause);
        registration.settled = true;
        if cancelled {
            Ok(())
        } else {
            Err(WaitServiceError::StaleRegistration)
        }
    }

    pub fn publish_signal_for_thread(&self, thread: ThreadKey) -> bool {
        self.inner.publish_signal_for_thread(thread)
    }

    pub fn event(&self, token: ContinuationWakeToken) -> ContinuationEventFuture {
        ContinuationEventFuture {
            service: Arc::clone(&self.inner),
            token,
        }
    }

    pub const fn topology(&self) -> WaitServiceTopology {
        WaitServiceTopology {
            service_threads: 1,
            shared_reactors: 1,
            record_lock_workers: 0,
        }
    }

    #[cfg(test)]
    pub(in crate::vcpu_loop) fn last_prepared_token(&self) -> ContinuationWakeToken {
        self.inner
            .state
            .lock()
            .last_prepared
            .expect("prepared token")
    }

    #[cfg(test)]
    pub(in crate::vcpu_loop) fn reactor_poll_calls(&self) -> u64 {
        self.inner.reactor_poll_calls.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(in crate::vcpu_loop) fn reactor_cycle_visits(&self) -> u64 {
        self.inner.reactor_cycle_visits.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(in crate::vcpu_loop) fn nudge_reactor_for_test(&self) {
        self.inner.nudge_reactor();
    }

    #[cfg(test)]
    pub(in crate::vcpu_loop) fn observe_next_reactor_poll(&self) -> Arc<std::sync::Barrier> {
        let observer = Arc::new(std::sync::Barrier::new(2));
        let installed_at = self.inner.reactor_poll_calls.load(Ordering::Acquire);
        *self.inner.reactor_poll_observer.lock() = Some((installed_at, Arc::clone(&observer)));
        observer
    }

    #[cfg(test)]
    pub(crate) fn set_before_host_write_hook<F: Fn() + Send + Sync + 'static>(&self, hook: F) {
        *self.inner.test_hooks.before_host_write_drive.lock() = Some(Arc::new(hook));
    }

    #[cfg(test)]
    pub(crate) fn set_inside_host_write_hook<F: Fn() + Send + Sync + 'static>(&self, hook: F) {
        *self.inner.test_hooks.inside_host_write_drive.lock() = Some(Arc::new(hook));
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn set_before_recheck_hook<F: Fn() + Send + Sync + 'static>(&self, hook: F) {
        *self.inner.test_hooks.before_recheck_probe.lock() = Some(Arc::new(hook));
    }

    #[cfg(test)]
    pub(crate) fn set_after_recheck_claim_hook<F: Fn() + Send + Sync + 'static>(&self, hook: F) {
        *self.inner.test_hooks.after_recheck_claim.lock() = Some(Arc::new(hook));
    }

    #[cfg(test)]
    pub(crate) fn clear_test_hooks(&self) {
        *self.inner.test_hooks.before_host_write_drive.lock() = None;
        *self.inner.test_hooks.inside_host_write_drive.lock() = None;
        *self.inner.test_hooks.before_recheck_probe.lock() = None;
        *self.inner.test_hooks.after_recheck_claim.lock() = None;
    }
}

pub struct ContinuationEventFuture {
    service: Arc<CarrierWaitServiceInner>,
    token: ContinuationWakeToken,
}

impl Future for ContinuationEventFuture {
    type Output = Result<ContinuationEvent, WaitServiceError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut incoming_drain_waker = Some(context.waker().clone());
        let mut incoming_task_waker = Some(context.waker().clone());
        let mut old_drain_waker = None;
        let mut old_task_waker = None;
        let mut removed_entry = None;

        let result = {
            let mut state = self.service.state.lock();
            let Some(mut entry) = state
                .registration_mut(self.token.continuation)
                .filter(|entry| entry.token == self.token)
            else {
                return Poll::Ready(Err(WaitServiceError::StaleRegistration));
            };
            match entry.state {
                RegistrationState::Ready => Poll::Ready(
                    entry
                        .event
                        .clone()
                        .ok_or(WaitServiceError::StaleRegistration),
                ),
                RegistrationState::Cancelled(cause) => {
                    let gate = Arc::clone(&entry.operation_gate);
                    let (is_in_flight, drain_waker_displaced) = {
                        let mut gate_state = gate.state.lock();
                        gate_state.cancelled = true;
                        if gate_state.in_flight > 0 {
                            let displaced = std::mem::replace(
                                &mut gate_state.drain_waker,
                                incoming_drain_waker.take(),
                            );
                            (true, displaced)
                        } else {
                            (false, None)
                        }
                    };
                    old_drain_waker = drain_waker_displaced;
                    if is_in_flight {
                        old_task_waker =
                            std::mem::replace(&mut entry.task_waker, incoming_task_waker.take());
                        Poll::Pending
                    } else {
                        old_task_waker = entry.task_waker.take();
                        drop(entry);
                        removed_entry = state.remove_registration(self.token.continuation);
                        Poll::Ready(Err(WaitServiceError::Cancelled(cause)))
                    }
                }
                RegistrationState::Consumed => {
                    Poll::Ready(Err(WaitServiceError::StaleRegistration))
                }
                RegistrationState::Prepared | RegistrationState::Enrolled => {
                    old_task_waker =
                        std::mem::replace(&mut entry.task_waker, incoming_task_waker.take());
                    Poll::Pending
                }
            }
        };
        drop(old_drain_waker);
        drop(old_task_waker);
        drop(removed_entry);
        drop(incoming_drain_waker);
        drop(incoming_task_waker);
        result
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitServiceTopology {
    service_threads: usize,
    shared_reactors: usize,
    record_lock_workers: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationTiming {
    deadline: Option<Instant>,
    has_periodic_probe: bool,
}

impl RegistrationTiming {
    pub const fn deadline(self) -> Option<Instant> {
        self.deadline
    }

    pub const fn has_periodic_probe(self) -> bool {
        self.has_periodic_probe
    }
}

impl WaitServiceTopology {
    pub const fn service_threads(self) -> usize {
        self.service_threads
    }

    pub const fn shared_reactors(self) -> usize {
        self.shared_reactors
    }

    pub const fn record_lock_workers(self) -> usize {
        self.record_lock_workers
    }

    pub const fn task_waiter_threads(self) -> usize {
        0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WaitServiceError {
    #[error("wait-service registration is stale")]
    StaleRegistration,
    #[error("wait-service event did not arrive before the caller deadline")]
    TimedOut,
    #[error("wait-service registration was cancelled: {0:?}")]
    Cancelled(CancellationCause),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WakePublishReceipt {
    accepted: bool,
    first: bool,
}

impl WakePublishReceipt {
    const fn rejected() -> Self {
        Self {
            accepted: false,
            first: false,
        }
    }

    pub const fn accepted(self) -> bool {
        self.accepted
    }

    pub const fn first_publication(self) -> bool {
        self.first
    }

    #[cfg(test)]
    pub(in crate::vcpu_loop) fn assert_accepted(self) {
        assert!(self.accepted);
    }
}
