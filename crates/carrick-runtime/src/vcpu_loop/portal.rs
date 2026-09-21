// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use carrick_hal::{PortalEndpoint, PortalPoll, PortalSessionWire, PortalWireRequest};
use carrick_kernel::dispatch::DispatchOutcome;
use carrick_observability::work_meter::{WorkMetric, WorkScope};
use thiserror::Error;

/// Every authority generation that must still name the running syscall owner.
///
/// The tuple contains values from typed Carrick identities only. Host pointers
/// and thread addresses are deliberately absent so allocator reuse cannot make
/// a stale request current again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortalSessionIdentity {
    pub mailbox_generation: u64,
    pub executor_generation: u64,
    pub task_serial: u64,
    pub mm_generation: u64,
    pub quantum_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortalRequest {
    pub identity: PortalSessionIdentity,
    pub native_nr: u64,
    pub args: [u64; 6],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortalRuntimeState {
    Parked,
    Armed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortalBoundaryReason {
    IneligibleSyscall,
    SignalDebt,
    IncompatibleInterceptor,
    ActivityWindowExpired,
    NonScalarOutcome,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PortalCompletion {
    Returned(i64),
    HostBoundary {
        reason: PortalBoundaryReason,
        outcome: Option<DispatchOutcome>,
    },
    StaleRejected,
    DispatchFailed(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortalPolicy {
    Off,
    Adaptive,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PortalPolicyError {
    #[error("CARRICK_HVPATCH_SYSCALL_PORTAL must be `off` or `adaptive`, got {0:?}")]
    Invalid(String),
}

impl PortalPolicy {
    pub fn from_value(value: Option<&str>) -> Result<Self, PortalPolicyError> {
        match value {
            None | Some("off") => Ok(Self::Off),
            Some("adaptive") => Ok(Self::Adaptive),
            Some(other) => Err(PortalPolicyError::Invalid(other.to_owned())),
        }
    }

    pub fn from_environment() -> Result<Self, PortalPolicyError> {
        match std::env::var("CARRICK_HVPATCH_SYSCALL_PORTAL") {
            Ok(value) => Self::from_value(Some(&value)),
            Err(std::env::VarError::NotPresent) => Self::from_value(None),
            Err(std::env::VarError::NotUnicode(value)) => Err(PortalPolicyError::Invalid(
                value.to_string_lossy().into_owned(),
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortalActivityBudget {
    pub max_operations: u32,
    pub idle_window: Duration,
}

impl Default for PortalActivityBudget {
    fn default() -> Self {
        Self {
            max_operations: 256,
            idle_window: Duration::from_millis(2),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct PortalServiceConditions {
    pub signal_debt: bool,
    pub incompatible_interceptor: bool,
}

/// Deterministic policy state shared by the production helper and host tests.
/// Time is supplied by the caller so tests never sleep.
pub struct AdaptivePortalSession {
    policy: PortalPolicy,
    state: PortalRuntimeState,
    identity: Option<PortalSessionIdentity>,
    budget: PortalActivityBudget,
    operations: u32,
    expires_at: Duration,
}

impl AdaptivePortalSession {
    pub fn new(policy: PortalPolicy, budget: PortalActivityBudget) -> Self {
        Self {
            policy,
            state: PortalRuntimeState::Parked,
            identity: None,
            budget,
            operations: 0,
            expires_at: Duration::ZERO,
        }
    }

    pub const fn state(&self) -> PortalRuntimeState {
        self.state
    }

    pub fn arm(&mut self, identity: PortalSessionIdentity, now: Duration) -> bool {
        if self.policy == PortalPolicy::Off || self.budget.max_operations == 0 {
            return false;
        }
        self.identity = Some(identity);
        self.operations = 0;
        self.expires_at = now.saturating_add(self.budget.idle_window);
        self.state = PortalRuntimeState::Armed;
        true
    }

    pub fn cancel(&mut self, next_quantum_epoch: u64) -> bool {
        let was_armed = self.state == PortalRuntimeState::Armed;
        if let Some(identity) = self.identity.as_mut() {
            identity.quantum_epoch = next_quantum_epoch;
        }
        self.park();
        was_armed
    }

    pub fn service(
        &mut self,
        request: PortalRequest,
        now: Duration,
        conditions: PortalServiceConditions,
        eligible: impl FnOnce(u64) -> bool,
        dispatch: impl FnOnce(PortalRequest) -> Result<DispatchOutcome, String>,
    ) -> PortalCompletion {
        if self.state != PortalRuntimeState::Armed || self.identity != Some(request.identity) {
            return PortalCompletion::StaleRejected;
        }
        if now > self.expires_at || self.operations >= self.budget.max_operations {
            self.park();
            return PortalCompletion::HostBoundary {
                reason: PortalBoundaryReason::ActivityWindowExpired,
                outcome: None,
            };
        }
        if conditions.signal_debt {
            self.park();
            return PortalCompletion::HostBoundary {
                reason: PortalBoundaryReason::SignalDebt,
                outcome: None,
            };
        }
        if conditions.incompatible_interceptor {
            self.park();
            return PortalCompletion::HostBoundary {
                reason: PortalBoundaryReason::IncompatibleInterceptor,
                outcome: None,
            };
        }
        if !eligible(request.native_nr) {
            self.park();
            return PortalCompletion::HostBoundary {
                reason: PortalBoundaryReason::IneligibleSyscall,
                outcome: None,
            };
        }

        self.operations = self.operations.saturating_add(1);
        self.expires_at = now.saturating_add(self.budget.idle_window);
        match dispatch(request) {
            Err(error) => {
                self.park();
                PortalCompletion::DispatchFailed(error)
            }
            Ok(DispatchOutcome::Returned { value }) => PortalCompletion::Returned(value),
            Ok(DispatchOutcome::Errno { errno }) => {
                PortalCompletion::Returned(errno.guest_retval())
            }
            Ok(outcome) => {
                self.park();
                PortalCompletion::HostBoundary {
                    reason: PortalBoundaryReason::NonScalarOutcome,
                    outcome: Some(outcome),
                }
            }
        }
    }

    fn park(&mut self) {
        self.state = PortalRuntimeState::Parked;
        self.identity = None;
        self.operations = 0;
        self.expires_at = Duration::ZERO;
    }
}

type PortalDispatch =
    Arc<dyn Fn(PortalRequest) -> Result<DispatchOutcome, String> + Send + Sync + 'static>;
type PortalConditions = Arc<dyn Fn() -> PortalServiceConditions + Send + Sync + 'static>;
type PortalEligibility = Arc<dyn Fn(u64) -> bool + Send + Sync + 'static>;

struct PortalCommand {
    endpoint: PortalEndpoint,
    identity: PortalSessionIdentity,
    dispatch: PortalDispatch,
    conditions: PortalConditions,
    eligible: PortalEligibility,
    work_scope: Option<WorkScope>,
}

#[derive(Default)]
struct PortalHelperState {
    command: Option<PortalCommand>,
    current_endpoint: Option<PortalEndpoint>,
    boundary: Option<(PortalWireRequest, PortalCompletion)>,
    stop: bool,
    cancel_requested: bool,
    parked: bool,
}

/// One parked helper owned by a persistent hardware executor.
///
/// The condition variable is the idle path. The worker polls shared memory
/// only while an adaptive activity window is armed, so an idle carrier does
/// not gain a permanently spinning host thread.
pub(crate) struct PortalHelper {
    shared: Arc<(Mutex<PortalHelperState>, Condvar)>,
    join: Option<JoinHandle<()>>,
    policy: PortalPolicy,
    budget: PortalActivityBudget,
}

impl PortalHelper {
    pub(crate) fn new(policy: PortalPolicy, budget: PortalActivityBudget) -> Result<Self, String> {
        let shared = Arc::new((
            Mutex::new(PortalHelperState {
                parked: true,
                ..PortalHelperState::default()
            }),
            Condvar::new(),
        ));
        let worker_shared = Arc::clone(&shared);
        let join = std::thread::Builder::new()
            .name("carrick-syscall-portal".to_owned())
            .spawn(move || portal_worker(worker_shared, budget))
            .map_err(|error| format!("spawn syscall portal helper: {error}"))?;
        Ok(Self {
            shared,
            join: Some(join),
            policy,
            budget,
        })
    }

    pub(crate) fn arm(
        &self,
        endpoint: PortalEndpoint,
        mut identity: PortalSessionIdentity,
        dispatch: PortalDispatch,
        conditions: PortalConditions,
        eligible: PortalEligibility,
        work_scope: Option<WorkScope>,
    ) -> Result<bool, String> {
        if self.policy == PortalPolicy::Off || self.budget.max_operations == 0 {
            return Ok(false);
        }
        let transport = endpoint.transport();
        let session = PortalSessionWire {
            executor_generation: identity.executor_generation,
            task_serial: identity.task_serial,
            mm_generation: identity.mm_generation,
            quantum_epoch: identity.quantum_epoch,
        };
        identity.mailbox_generation = match transport.arm(session) {
            Ok(generation) => generation,
            Err(_) => return Ok(false),
        };
        let (lock, ready) = self.shared.as_ref();
        let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.command.is_some() || !state.parked {
            return Err("syscall portal helper armed while a prior session is live".to_owned());
        }
        state.boundary = None;
        state.command = Some(PortalCommand {
            endpoint,
            identity,
            dispatch,
            conditions,
            eligible,
            work_scope,
        });
        state.parked = false;
        ready.notify_one();
        Ok(true)
    }

    pub(crate) fn is_parked(&self) -> bool {
        let (lock, _) = self.shared.as_ref();
        lock.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .parked
    }

    pub(crate) fn take_boundary(&self, native_nr: u64, args: [u64; 6]) -> Option<PortalCompletion> {
        let (lock, _) = self.shared.as_ref();
        let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let matches = state
            .boundary
            .as_ref()
            .is_some_and(|(request, _)| request.native_nr == native_nr && request.args == args);
        if matches {
            state.boundary.take().map(|(_, completion)| completion)
        } else {
            None
        }
    }

    pub(crate) fn cancel_and_wait(&self, next_quantum_epoch: u64) -> Result<(), String> {
        let queued_endpoint = {
            let (lock, ready) = self.shared.as_ref();
            let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let endpoint = state.command.take().map(|command| command.endpoint);
            if state.current_endpoint.is_some() {
                state.cancel_requested = true;
            }
            ready.notify_all();
            endpoint
        };
        if let Some(endpoint) = queued_endpoint {
            let _ = endpoint.transport().cancel(next_quantum_epoch);
        }
        let (lock, ready) = self.shared.as_ref();
        let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        while !state.parked {
            state = ready
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        Ok(())
    }
}

impl Drop for PortalHelper {
    fn drop(&mut self) {
        let (lock, ready) = self.shared.as_ref();
        {
            let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            state.stop = true;
            state.command = None;
            ready.notify_all();
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn add_work(scope: Option<&WorkScope>, metric: WorkMetric) {
    if let Some(scope) = scope {
        let _ = scope.add(metric, 1);
    }
}

fn portal_worker(shared: Arc<(Mutex<PortalHelperState>, Condvar)>, budget: PortalActivityBudget) {
    let (lock, ready) = shared.as_ref();
    'worker: loop {
        let command = {
            let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            while state.command.is_none() && !state.stop {
                state.parked = true;
                ready.notify_all();
                state = ready
                    .wait(state)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            if state.stop {
                state.parked = true;
                ready.notify_all();
                return;
            }
            state.parked = false;
            let Some(command) = state.command.take() else {
                state.parked = true;
                ready.notify_all();
                continue 'worker;
            };
            state.current_endpoint = Some(command.endpoint.clone());
            command
        };

        let started = Instant::now();
        let mut last_activity = started;
        let mut session = AdaptivePortalSession::new(PortalPolicy::Adaptive, budget);
        let _ = session.arm(command.identity, Duration::ZERO);
        loop {
            let (stop, cancel_requested) = {
                let state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                (state.stop, state.cancel_requested)
            };
            if stop || cancel_requested {
                let _ = command
                    .endpoint
                    .transport()
                    .cancel(command.identity.quantum_epoch.saturating_add(1));
                if stop {
                    let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    state.current_endpoint = None;
                    state.parked = true;
                    ready.notify_all();
                    return;
                }
                break;
            }
            let elapsed = started.elapsed();
            let poll = command.endpoint.transport().poll();
            let request = match poll {
                Ok(PortalPoll::Idle) => {
                    if last_activity.elapsed() > budget.idle_window {
                        let _ = command
                            .endpoint
                            .transport()
                            .cancel(command.identity.quantum_epoch.saturating_add(1));
                        break;
                    }
                    std::hint::spin_loop();
                    continue;
                }
                Ok(PortalPoll::Request(request)) => request,
                Ok(PortalPoll::HostBoundary | PortalPoll::Cancelling | PortalPoll::Disabled) => {
                    break;
                }
                Err(_) => break,
            };
            let identity = PortalSessionIdentity {
                mailbox_generation: request.mailbox_generation,
                executor_generation: request.session.executor_generation,
                task_serial: request.session.task_serial,
                mm_generation: request.session.mm_generation,
                quantum_epoch: request.session.quantum_epoch,
            };
            if identity != command.identity {
                add_work(command.work_scope.as_ref(), WorkMetric::PortalStaleRejects);
                let _ = command.endpoint.transport().publish_host_boundary(request);
                break;
            }
            // RequestReady is also the ordinary EL1-to-host publication state.
            // The helper may win that race before the vCPU exits, so reject
            // non-allowlisted numbers without changing mailbox ownership. The
            // stopped owner will consume that request through the normal HVC
            // path.
            if !(command.eligible)(request.native_nr) {
                break;
            }
            add_work(command.work_scope.as_ref(), WorkMetric::PortalRequests);
            last_activity = Instant::now();
            let portal_request = PortalRequest {
                identity,
                native_nr: request.native_nr,
                args: request.args,
            };
            let conditions = (command.conditions)();
            let completion = session.service(
                portal_request,
                elapsed,
                conditions,
                |_| true,
                |request| (command.dispatch)(request),
            );
            match completion {
                PortalCompletion::Returned(value) => {
                    if command
                        .endpoint
                        .transport()
                        .publish_returned(request, value)
                        .is_err()
                    {
                        add_work(command.work_scope.as_ref(), WorkMetric::PortalStaleRejects);
                        break;
                    }
                    add_work(command.work_scope.as_ref(), WorkMetric::PortalCompletions);
                }
                PortalCompletion::StaleRejected => {
                    add_work(command.work_scope.as_ref(), WorkMetric::PortalStaleRejects);
                    break;
                }
                completion @ (PortalCompletion::HostBoundary { .. }
                | PortalCompletion::DispatchFailed(_)) => {
                    add_work(command.work_scope.as_ref(), WorkMetric::PortalFallbacks);
                    let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    state.boundary = Some((request, completion));
                    drop(state);
                    let _ = command.endpoint.transport().publish_host_boundary(request);
                    break;
                }
            }
        }
        let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        state.current_endpoint = None;
        state.cancel_requested = false;
        state.parked = true;
        ready.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering};

    use carrick_abi::LinuxErrno;

    use super::*;

    fn identity() -> PortalSessionIdentity {
        PortalSessionIdentity {
            mailbox_generation: 11,
            executor_generation: 12,
            task_serial: 13,
            mm_generation: 14,
            quantum_epoch: 15,
        }
    }

    fn request(identity: PortalSessionIdentity) -> PortalRequest {
        PortalRequest {
            identity,
            native_nr: 62,
            args: [0; 6],
        }
    }

    fn session() -> AdaptivePortalSession {
        AdaptivePortalSession::new(
            PortalPolicy::Adaptive,
            PortalActivityBudget {
                max_operations: 2,
                idle_window: Duration::from_millis(10),
            },
        )
    }

    #[test]
    fn policy_defaults_off_and_rejects_unknown_values() {
        assert_eq!(PortalPolicy::from_value(None), Ok(PortalPolicy::Off));
        assert_eq!(
            PortalPolicy::from_value(Some("adaptive")),
            Ok(PortalPolicy::Adaptive)
        );
        assert_eq!(
            PortalPolicy::from_value(Some("always")),
            Err(PortalPolicyError::Invalid("always".to_owned()))
        );
    }

    #[test]
    fn session_starts_parked_serves_current_identity_and_rejects_stale_reuse() {
        let mut session = session();
        let current = identity();
        assert_eq!(session.state(), PortalRuntimeState::Parked);
        assert!(session.arm(current, Duration::ZERO));
        assert_eq!(session.state(), PortalRuntimeState::Armed);
        assert_eq!(
            session.service(
                request(current),
                Duration::from_millis(1),
                PortalServiceConditions::default(),
                |_| true,
                |_| Ok(DispatchOutcome::Returned { value: 7 }),
            ),
            PortalCompletion::Returned(7)
        );
        let mut stale = current;
        stale.task_serial += 1;
        assert_eq!(
            session.service(
                request(stale),
                Duration::from_millis(2),
                PortalServiceConditions::default(),
                |_| true,
                |_| panic!("stale request dispatched"),
            ),
            PortalCompletion::StaleRejected
        );
        assert!(session.cancel(current.quantum_epoch + 1));
        assert_eq!(session.state(), PortalRuntimeState::Parked);
    }

    #[test]
    fn errno_is_a_direct_scalar_completion() {
        let mut session = session();
        let current = identity();
        assert!(session.arm(current, Duration::ZERO));
        let errno = LinuxErrno::new(9);
        assert_eq!(
            session.service(
                request(current),
                Duration::ZERO,
                PortalServiceConditions::default(),
                |_| true,
                |_| Ok(DispatchOutcome::Errno { errno }),
            ),
            PortalCompletion::Returned(-9)
        );
    }

    #[test]
    fn non_scalar_outcome_crosses_one_host_boundary_without_redispatch() {
        let mut session = session();
        let current = identity();
        let dispatches = Cell::new(0);
        assert!(session.arm(current, Duration::ZERO));
        let completion = session.service(
            request(current),
            Duration::ZERO,
            PortalServiceConditions::default(),
            |_| true,
            |_| {
                dispatches.set(dispatches.get() + 1);
                Ok(DispatchOutcome::SchedulerYield)
            },
        );
        assert_eq!(dispatches.get(), 1);
        assert_eq!(
            completion,
            PortalCompletion::HostBoundary {
                reason: PortalBoundaryReason::NonScalarOutcome,
                outcome: Some(DispatchOutcome::SchedulerYield),
            }
        );
        assert_eq!(session.state(), PortalRuntimeState::Parked);
    }

    #[test]
    fn signal_interceptor_and_expiry_do_not_dispatch() {
        let cases = [
            (
                PortalServiceConditions {
                    signal_debt: true,
                    incompatible_interceptor: false,
                },
                Duration::ZERO,
                PortalBoundaryReason::SignalDebt,
            ),
            (
                PortalServiceConditions {
                    signal_debt: false,
                    incompatible_interceptor: true,
                },
                Duration::ZERO,
                PortalBoundaryReason::IncompatibleInterceptor,
            ),
            (
                PortalServiceConditions::default(),
                Duration::from_millis(11),
                PortalBoundaryReason::ActivityWindowExpired,
            ),
        ];
        for (conditions, now, reason) in cases {
            let mut session = session();
            let dispatches = Cell::new(0);
            assert!(session.arm(identity(), Duration::ZERO));
            assert_eq!(
                session.service(
                    request(identity()),
                    now,
                    conditions,
                    |_| true,
                    |_| {
                        dispatches.set(dispatches.get() + 1);
                        Ok(DispatchOutcome::Returned { value: 0 })
                    },
                ),
                PortalCompletion::HostBoundary {
                    reason,
                    outcome: None,
                }
            );
            assert_eq!(dispatches.get(), 0);
            assert_eq!(session.state(), PortalRuntimeState::Parked);
        }
    }

    struct FakeTransport {
        generation: u64,
        poll: Mutex<PortalPoll>,
        returned: Mutex<Option<i64>>,
        polls: AtomicU64,
    }

    impl FakeTransport {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                generation: 41,
                poll: Mutex::new(PortalPoll::Disabled),
                returned: Mutex::new(None),
                polls: AtomicU64::new(0),
            })
        }

        fn publish_request(&self, session: PortalSessionWire) -> PortalWireRequest {
            self.publish_request_nr(session, 62)
        }

        fn publish_request_nr(
            &self,
            session: PortalSessionWire,
            native_nr: u64,
        ) -> PortalWireRequest {
            let request = PortalWireRequest {
                mailbox_generation: self.generation,
                sequence: 1,
                session,
                native_nr,
                args: [3, 4, 5, 0, 0, 0],
            };
            *self
                .poll
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = PortalPoll::Request(request);
            request
        }
    }

    impl carrick_hal::PortalTransport for FakeTransport {
        fn generation(&self) -> Option<u64> {
            Some(self.generation)
        }

        fn arm(&self, _session: PortalSessionWire) -> Result<u64, carrick_hal::TrapError> {
            *self
                .poll
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = PortalPoll::Idle;
            Ok(self.generation)
        }

        fn cancel(&self, _next_quantum_epoch: u64) -> Result<(), carrick_hal::TrapError> {
            *self
                .poll
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = PortalPoll::Disabled;
            Ok(())
        }

        fn poll(&self) -> Result<PortalPoll, carrick_hal::TrapError> {
            self.polls.fetch_add(1, Ordering::Relaxed);
            Ok(*self
                .poll
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()))
        }

        fn publish_returned(
            &self,
            _request: PortalWireRequest,
            value: i64,
        ) -> Result<(), carrick_hal::TrapError> {
            *self
                .returned
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(value);
            *self
                .poll
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = PortalPoll::Idle;
            Ok(())
        }

        fn publish_host_boundary(
            &self,
            _request: PortalWireRequest,
        ) -> Result<(), carrick_hal::TrapError> {
            *self
                .poll
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = PortalPoll::HostBoundary;
            Ok(())
        }
    }

    fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) {
        let deadline = Instant::now() + timeout;
        while !predicate() && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(predicate(), "condition did not become true before timeout");
    }

    #[test]
    fn helper_is_parked_when_idle_and_publishes_direct_scalar_completion() {
        let helper = PortalHelper::new(
            PortalPolicy::Adaptive,
            PortalActivityBudget {
                max_operations: 4,
                idle_window: Duration::from_millis(20),
            },
        )
        .expect("helper");
        assert!(helper.is_parked());
        let transport = FakeTransport::new();
        let endpoint = PortalEndpoint::new(transport.clone());
        let current = identity();
        assert!(
            helper
                .arm(
                    endpoint,
                    current,
                    Arc::new(|_| Ok(DispatchOutcome::Returned { value: 19 })),
                    Arc::new(PortalServiceConditions::default),
                    Arc::new(|nr| nr == 62),
                    None,
                )
                .expect("arm")
        );
        let session = PortalSessionWire {
            executor_generation: current.executor_generation,
            task_serial: current.task_serial,
            mm_generation: current.mm_generation,
            quantum_epoch: current.quantum_epoch,
        };
        transport.publish_request(session);
        wait_until(Duration::from_millis(100), || {
            *transport
                .returned
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                == Some(19)
        });
        wait_until(Duration::from_millis(100), || helper.is_parked());
        let polls_after_park = transport.polls.load(Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(transport.polls.load(Ordering::Relaxed), polls_after_park);
    }

    #[test]
    fn helper_preserves_non_scalar_outcome_for_owner_without_redispatch() {
        let helper = PortalHelper::new(
            PortalPolicy::Adaptive,
            PortalActivityBudget {
                max_operations: 4,
                idle_window: Duration::from_millis(20),
            },
        )
        .expect("helper");
        let transport = FakeTransport::new();
        let endpoint = PortalEndpoint::new(transport.clone());
        let current = identity();
        let dispatches = Arc::new(AtomicU64::new(0));
        let dispatch_count = Arc::clone(&dispatches);
        helper
            .arm(
                endpoint,
                current,
                Arc::new(move |_| {
                    dispatch_count.fetch_add(1, Ordering::Relaxed);
                    Ok(DispatchOutcome::SchedulerYield)
                }),
                Arc::new(PortalServiceConditions::default),
                Arc::new(|nr| nr == 62),
                None,
            )
            .expect("arm");
        let request = transport.publish_request(PortalSessionWire {
            executor_generation: current.executor_generation,
            task_serial: current.task_serial,
            mm_generation: current.mm_generation,
            quantum_epoch: current.quantum_epoch,
        });
        wait_until(Duration::from_millis(100), || helper.is_parked());
        assert_eq!(dispatches.load(Ordering::Relaxed), 1);
        assert_eq!(
            helper.take_boundary(request.native_nr, request.args),
            Some(PortalCompletion::HostBoundary {
                reason: PortalBoundaryReason::NonScalarOutcome,
                outcome: Some(DispatchOutcome::SchedulerYield),
            })
        );
        assert_eq!(dispatches.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn helper_leaves_ordinary_request_owned_by_hvc_path() {
        let helper = PortalHelper::new(
            PortalPolicy::Adaptive,
            PortalActivityBudget {
                max_operations: 4,
                idle_window: Duration::from_millis(20),
            },
        )
        .expect("helper");
        let transport = FakeTransport::new();
        let endpoint = PortalEndpoint::new(transport.clone());
        let current = identity();
        let dispatches = Arc::new(AtomicU64::new(0));
        let dispatch_count = Arc::clone(&dispatches);
        helper
            .arm(
                endpoint,
                current,
                Arc::new(move |_| {
                    dispatch_count.fetch_add(1, Ordering::Relaxed);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }),
                Arc::new(PortalServiceConditions::default),
                Arc::new(|nr| nr == 62),
                None,
            )
            .expect("arm");
        let request = transport.publish_request_nr(
            PortalSessionWire {
                executor_generation: current.executor_generation,
                task_serial: current.task_serial,
                mm_generation: current.mm_generation,
                quantum_epoch: current.quantum_epoch,
            },
            214,
        );

        wait_until(Duration::from_millis(100), || helper.is_parked());
        assert_eq!(dispatches.load(Ordering::Relaxed), 0);
        assert_eq!(
            *transport
                .poll
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            PortalPoll::Request(request)
        );
        assert_eq!(helper.take_boundary(request.native_nr, request.args), None);
    }
}
