//! Who can execute guest code: the population a stage-1 page-table pause must
//! account for.
//!
//! Carrick coordinates mutations of shared guest state through distinct
//! authorities:
//! - Stage-1 page-table Pause-Modify-Resume holds the exact-MM
//!   [`GuestExecutorCensus`] locked while it either proves sole execution or
//!   kicks and drains every registered executor endpoint.
//! - Process fork and crash snapshot raise their quiesce barriers from their
//!   distinct Task-minted durable-membership witnesses, not this census.
//!
//! A raised quiesce barrier parks admitted executors at the run-loop safe point,
//! but does not itself deny vCPU registration. Registration admission is
//! governed by the identity-aware vCPU registry lease freeze: only a non-owner
//! lease drain freeze denies registration; the exact freeze owner may
//! re-register through its own raised fork barrier.
//!
//! [`GuestExecutorCensus`] tracks live guest executor participation for one
//! exact dispatch MM. Distinct CLONE_VM dispatchers share the census through
//! their shared MM authority. When a thread suspends (for example on a futex,
//! `epoll_wait`, or host blocking wait), suspension drops its
//! [`GuestExecutorParticipation`] via `leave_executor`. Blocked logical loops do
//! not remain in the census while suspended.
//!
//! Upon waking and seeking initial admission or re-admission to execute guest
//! code, a thread enters [`GuestExecutorCensus`] before attempting vCPU
//! registration (`enter_mm_executor_then_register`). If a lease drain freeze is
//! held by another owner, registration admission returns `Waiting`, and the
//! thread suspends again (dropping its participation). This ordering guarantees
//! that any peer thread attempting to enter guest execution is visible in the
//! exact-MM census before its registration can be published.
//!
//! Membership is maintained by [`GuestExecutorParticipation`], an RAII guard
//! held for the lifetime of an admitted guest executor quantum, in the same
//! spirit as the crash-capture quorum's participant flag: a thread published
//! into the task graph whose host loop was cancelled before it started, and a
//! thread that has suspended or returned, are both outside the population. The
//! guard carries the crash-safe-point facet too, so the two cannot drift — they
//! are one fact ("this thread actively participates in guest execution") read by
//! two subsystems.
//!
//! Residual window, stated plainly: participation begins when an admitted
//! executor enters its execution quantum, not when `clone` publishes the thread
//! into the task graph. A thread between publication and execution entry is not
//! yet counted. It also cannot yet execute guest code, and the fork lane
//! separately closes clone admission (`close_for_fork`) before it quiesces, but
//! the page-table lane closes its own admission by holding the exact-MM census
//! lock for the lifetime of its mutation authority.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU64;
use std::sync::Arc;

use carrick_fatal::carrick_fatal;
use parking_lot::{ArcMutexGuard, Mutex, RawMutex};

use super::objects::{
    CrashSafePointParticipation, CrashSafePointParticipationError, ThreadKey, ThreadRef,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum GuestExecutorIdentity {
    Thread(ThreadKey),
    Anonymous(NonZeroU64),
}

#[derive(Debug)]
struct GuestExecutorCensusState {
    participants: BTreeMap<GuestExecutorIdentity, Option<GuestExecutorPauseEndpoint>>,
    next_anonymous: u64,
}

impl Default for GuestExecutorCensusState {
    fn default() -> Self {
        Self {
            participants: BTreeMap::new(),
            next_anonymous: 1,
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
fn saturating_participant_count_for_probe(count: usize) -> i32 {
    i32::try_from(count).unwrap_or(i32::MAX)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GuestExecutorCensusError {
    #[error("thread {thread:?} is already admitted as a guest executor")]
    DuplicateThread { thread: ThreadKey },
    #[error("anonymous guest-executor identities are exhausted")]
    AnonymousIdentityExhausted,
    #[error("thread {thread:?} already owns crash safe-point participation")]
    CrashParticipationAlreadyActive { thread: ThreadKey },
    #[error("thread {thread:?} exhausted crash safe-point participation identities")]
    CrashParticipationIdentityExhausted { thread: ThreadKey },
}

/// Live guest executors for one exact dispatch MM.
///
/// The owning `DispatchMmAuthority` is shared by CLONE_VM dispatchers, so a
/// process boundary cannot conceal a peer that may walk the same stage-1
/// descriptors. Copied forks and exec replacements receive fresh authorities
/// and therefore fresh censuses.
#[derive(Debug, Default)]
pub struct GuestExecutorCensus {
    state: Arc<Mutex<GuestExecutorCensusState>>,
}

impl GuestExecutorCensus {
    /// Join the population for as long as the returned guard lives. Call this
    /// upon entering an admitted guest execution quantum, before the thread
    /// registers a vCPU.
    ///
    /// `thread` is the same thread's Kernel object when the lane has one
    /// (HVPatch); passing it makes this guard carry the crash-safe-point facet
    /// as well, so a loop can never be a member of one population and not the
    /// other.
    pub fn enter(
        self: &Arc<Self>,
        thread: Option<ThreadRef>,
    ) -> Result<GuestExecutorParticipation, GuestExecutorCensusError> {
        self.enter_inner(thread, None)
    }

    pub fn enter_with_pause_endpoint(
        self: &Arc<Self>,
        thread: Option<ThreadRef>,
        registry: Arc<dyn carrick_hal::VcpuRegistry>,
        tid: carrick_hal::ThreadId,
    ) -> Result<GuestExecutorParticipation, GuestExecutorCensusError> {
        self.enter_inner(
            thread,
            Some(GuestExecutorPauseEndpoint::Registered { registry, tid }),
        )
    }

    pub(crate) fn enter_native(
        self: &Arc<Self>,
        thread: ThreadRef,
        state: Arc<crate::dispatch::native_execution::NativeExecutorState>,
    ) -> Result<GuestExecutorParticipation, GuestExecutorCensusError> {
        self.enter_inner(
            Some(thread),
            Some(GuestExecutorPauseEndpoint::Native(state)),
        )
    }

    fn enter_inner(
        self: &Arc<Self>,
        thread: Option<ThreadRef>,
        pause_endpoint: Option<GuestExecutorPauseEndpoint>,
    ) -> Result<GuestExecutorParticipation, GuestExecutorCensusError> {
        let mut state = self.state.lock();
        let identity = match thread.as_ref() {
            Some(thread) => GuestExecutorIdentity::Thread(thread.key()),
            None => {
                let id = NonZeroU64::new(state.next_anonymous)
                    .ok_or(GuestExecutorCensusError::AnonymousIdentityExhausted)?;
                state.next_anonymous = state.next_anonymous.checked_add(1).unwrap_or(0);
                GuestExecutorIdentity::Anonymous(id)
            }
        };
        // Rejection must not replace the admitted owner's pause endpoint.
        // A losing entrant can name an idle registry (or no registry); storing
        // it first would hide the original executor from a live MM drain.
        match state.participants.entry(identity) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(pause_endpoint);
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                return Err(match identity {
                    GuestExecutorIdentity::Thread(thread) => {
                        GuestExecutorCensusError::DuplicateThread { thread }
                    }
                    GuestExecutorIdentity::Anonymous(_) => {
                        GuestExecutorCensusError::AnonymousIdentityExhausted
                    }
                });
            }
        }
        let crash_participation = match thread.as_ref() {
            Some(thread) => match thread.enter_crash_safe_point_participation() {
                Ok(participation) => Some(participation),
                Err(error) => {
                    let removed = state.participants.remove(&identity);
                    debug_assert!(removed.is_some());
                    return Err(match error {
                        CrashSafePointParticipationError::AlreadyActive { thread } => {
                            GuestExecutorCensusError::CrashParticipationAlreadyActive { thread }
                        }
                        CrashSafePointParticipationError::IdentityExhausted { thread } => {
                            GuestExecutorCensusError::CrashParticipationIdentityExhausted { thread }
                        }
                    });
                }
            },
            None => None,
        };
        drop(state);
        Ok(GuestExecutorParticipation {
            census: Arc::clone(self),
            identity,
            crash_participation,
            _not_sync: std::marker::PhantomData,
        })
    }

    /// Test-only instantaneous projection. It is not mutation authority: the
    /// production sole-or-pause decision must hold [`ExactMmCensusGuard`].
    #[cfg(any(test, feature = "test-support"))]
    pub fn has_peer_executor(&self) -> bool {
        self.state.lock().participants.len() > 1
    }

    /// Numeric projection solely for the fixed-width probe ABI.
    #[cfg(any(test, feature = "test-support"))]
    pub fn participant_count_for_probe(&self) -> i32 {
        saturating_participant_count_for_probe(self.state.lock().participants.len())
    }
}

#[derive(Clone)]
enum GuestExecutorPauseEndpoint {
    Registered {
        registry: Arc<dyn carrick_hal::VcpuRegistry>,
        tid: carrick_hal::ThreadId,
    },
    Native(Arc<crate::dispatch::native_execution::NativeExecutorState>),
}

impl GuestExecutorPauseEndpoint {
    fn tid(&self) -> carrick_hal::ThreadId {
        match self {
            Self::Registered { tid, .. } => *tid,
            Self::Native(state) => state.tid(),
        }
    }
    fn is_in_guest(&self) -> bool {
        match self {
            Self::Registered { registry, tid } => registry.is_in_guest(*tid),
            Self::Native(state) => state.is_running(),
        }
    }
    fn kick_if_in_guest(&self) {
        match self {
            Self::Registered { registry, tid } => {
                let _ = registry.kick_if_in_guest(*tid);
            }
            Self::Native(state) => {
                if state.is_running() {
                    state.request_memory_pause();
                }
            }
        }
    }
}

impl fmt::Debug for GuestExecutorPauseEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuestExecutorPauseEndpoint")
            .field("tid", &self.tid())
            .finish()
    }
}

/// Lifetime-held exact-MM census election. While this exists, no new executor
/// can enter the MM, which closes admission across a page-table mutation.
pub struct ExactMmCensusGuard {
    state: ArcMutexGuard<RawMutex, GuestExecutorCensusState>,
}

impl ExactMmCensusGuard {
    pub(crate) fn participant_count(&self) -> usize {
        self.state.participants.len()
    }

    pub(crate) fn all_have_pause_endpoints(&self) -> bool {
        self.state.participants.values().all(Option::is_some)
    }

    #[cfg(test)]
    pub(crate) fn pause_endpoint_tids(&self) -> Vec<carrick_hal::ThreadId> {
        self.state
            .participants
            .values()
            .flatten()
            .map(GuestExecutorPauseEndpoint::tid)
            .collect()
    }

    /// Endpoints that can acknowledge the published hardware ASID phase.
    /// Native endpoints still participate in the running drain, but have no
    /// hardware translation cache. Historical hardware residency remains a
    /// pending stage-1 ticket for the next actual hardware entry.
    pub(crate) fn hardware_invalidation_tids(&self) -> Vec<carrick_hal::ThreadId> {
        self.state
            .participants
            .values()
            .flatten()
            .filter_map(|endpoint| match endpoint {
                GuestExecutorPauseEndpoint::Registered { tid, .. } => Some(*tid),
                GuestExecutorPauseEndpoint::Native(_) => None,
            })
            .collect()
    }

    pub(crate) fn any_in_guest(&self) -> bool {
        self.state
            .participants
            .values()
            .flatten()
            .any(GuestExecutorPauseEndpoint::is_in_guest)
    }

    pub(crate) fn first_in_guest_tid(&self) -> Option<carrick_hal::ThreadId> {
        self.state
            .participants
            .values()
            .flatten()
            .find_map(|endpoint| endpoint.is_in_guest().then_some(endpoint.tid()))
    }

    pub(crate) fn kick_all_in_guest(&self) {
        for endpoint in self.state.participants.values().flatten() {
            endpoint.kick_if_in_guest();
        }
    }
}

/// Membership in a [`GuestExecutorCensus`], held for the duration of an
/// admitted guest executor quantum.
///
/// Released on every exit path — suspension, normal return, error, unwind —
/// because that is the whole point: an abandoned membership makes a page-table
/// mutator pause forever for a thread that will never park, and makes a crash
/// quorum wait out its deadline on a thread that can never answer.
pub struct GuestExecutorParticipation {
    census: Arc<GuestExecutorCensus>,
    identity: GuestExecutorIdentity,
    crash_participation: Option<CrashSafePointParticipation>,
    _not_sync: std::marker::PhantomData<Cell<()>>,
}

impl GuestExecutorParticipation {
    pub(crate) fn lock_exact_mm(&mut self) -> ExactMmCensusGuard {
        let state = self.census.state.lock_arc();
        assert!(
            state.participants.contains_key(&self.identity),
            "executor participation is absent from its exact-MM census"
        );
        ExactMmCensusGuard { state }
    }
}

impl GuestExecutorCensus {
    pub(crate) fn lock_for_frame_cow(&self) -> ExactMmCensusGuard {
        ExactMmCensusGuard {
            state: self.state.lock_arc(),
        }
    }
}

impl Drop for GuestExecutorParticipation {
    fn drop(&mut self) {
        drop(self.crash_participation.take());
        if self
            .census
            .state
            .lock()
            .participants
            .remove(&self.identity)
            .is_none()
        {
            carrick_fatal!(
                "kernel::guest_executor_census",
                "guest executor participation removed an unregistered participant"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use carrick_hal::ThreadId;

    use super::*;
    use crate::kernel::{Kernel, KernelContext, RootBootstrap};

    fn bootstrap_thread(pid: i32) -> (Arc<Kernel>, KernelContext) {
        let input = RootBootstrap::for_reference_model(
            pid,
            ThreadId::synthetic_for_tests(pid),
            "root".to_owned(),
        )
        .expect("bootstrap input");
        Kernel::bootstrap_root(input).expect("kernel")
    }

    #[test]
    fn duplicate_exact_thread_admission_is_rejected() {
        let (_kernel, context) = bootstrap_thread(19_500);
        let census = Arc::new(GuestExecutorCensus::default());
        let _first = census
            .enter(Some(context.thread().clone()))
            .expect("first exact participant");
        assert!(matches!(
            census.enter(Some(context.thread().clone())),
            Err(GuestExecutorCensusError::DuplicateThread { .. })
        ));
    }

    #[test]
    fn duplicate_admission_preserves_live_pause_endpoint() {
        use carrick_hal::{InGuestFlag, VcpuRegistrationEnrollment, VcpuRegistry};
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Clone)]
        struct CountKick(Arc<AtomicUsize>);
        impl carrick_hal::VcpuKick for CountKick {
            fn kick(&self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        use carrick_conformance_contract::{
            Completeness, ContractId, ContractObservation, ContractRegistry, ExecutionLayer,
            SemanticAssertion, WorkMetric, WorkSnapshot, evaluate,
        };
        use sha2::{Digest, Sha256};
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let registry_contracts = ContractRegistry::load(root).unwrap();
        let mut observations = Vec::new();
        for scale in [1, 8, 32, 128] {
            let (_kernel, context) = bootstrap_thread(19_600 + scale);
            let census = Arc::new(GuestExecutorCensus::default());
            let registry = Arc::new(carrick_hal::GenericVcpuRegistry::new());
            let displaced = Arc::new(carrick_hal::GenericVcpuRegistry::new());
            let tid = context.thread().registry_id();
            let running = InGuestFlag::for_guest_thread();
            let idle = InGuestFlag::for_guest_thread();
            let original_kicks = Arc::new(AtomicUsize::new(0));
            let duplicate_kicks = Arc::new(AtomicUsize::new(0));
            assert!(matches!(
                registry.subscribe_register(
                    tid,
                    Box::new(CountKick(original_kicks.clone())),
                    &running,
                    Arc::new(|| {})
                ),
                VcpuRegistrationEnrollment::Registered
            ));
            assert!(matches!(
                displaced.subscribe_register(
                    tid,
                    Box::new(CountKick(duplicate_kicks.clone())),
                    &idle,
                    Arc::new(|| {})
                ),
                VcpuRegistrationEnrollment::Registered
            ));
            let mut original = census
                .enter_with_pause_endpoint(Some(context.thread().clone()), registry.clone(), tid)
                .unwrap();
            running.enter_guest();
            let mut original_visible = true;
            for _ in 0..scale {
                assert!(matches!(
                    census.enter_with_pause_endpoint(
                        Some(context.thread().clone()),
                        displaced.clone(),
                        tid
                    ),
                    Err(GuestExecutorCensusError::DuplicateThread { .. })
                ));
                let held = original.lock_exact_mm();
                assert_eq!(held.participant_count(), 1);
                assert!(held.all_have_pause_endpoints());
                original_visible &= held.any_in_guest() && held.first_in_guest_tid() == Some(tid);
                held.kick_all_in_guest();
            }
            let original_calls = original_kicks.load(Ordering::SeqCst) as u64;
            let rejected_calls = duplicate_kicks.load(Ordering::SeqCst) as u64;
            let mut work = WorkSnapshot::new();
            work.insert(
                WorkMetric::HostBackendCalls,
                original_calls + rejected_calls,
            )
            .unwrap();
            observations.push(ContractObservation {
                contract_id: ContractId::new("kernel.mm.executor-admission").unwrap(),
                layer: ExecutionLayer::VmFree,
                implementation_revision: format!(
                    "sha256:{:x}",
                    Sha256::digest(include_bytes!("guest_execution.rs"))
                ),
                fixture_identity: "unit:duplicate-admission-live-endpoint".into(),
                scale: scale as u64,
                semantic_assertions: vec![
                    SemanticAssertion {
                        name: "rejected_duplicate_preserves_running_owner".into(),
                        passed: original_visible,
                        detail: None,
                    },
                    SemanticAssertion {
                        name: "drain_kicks_only_original_owner".into(),
                        passed: original_calls == scale as u64 && rejected_calls == 0,
                        detail: Some(format!(
                            "original={original_calls}, rejected={rejected_calls}"
                        )),
                    },
                ],
                work: Some(work),
                timing: None,
                completeness: Completeness::Complete,
            });
            running.leave_guest();
            assert!(!original.lock_exact_mm().any_in_guest());
            drop(original);
            assert_eq!(census.participant_count_for_probe(), 0);
            registry.unregister(tid);
            displaced.unregister(tid);
        }
        if let Some(dir) = std::env::var_os("CARRICK_ADMISSION_RECEIPT_DIR") {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                std::path::Path::new(&dir).join("observations.json"),
                serde_json::to_vec_pretty(&observations).unwrap(),
            )
            .unwrap();
        }
        evaluate(
            registry_contracts
                .require("kernel.mm.executor-admission")
                .unwrap(),
            &observations,
        )
        .unwrap();
    }

    #[test]
    fn duplicate_admission_without_endpoint_preserves_original_endpoint() {
        let (_kernel, context) = bootstrap_thread(19_599);
        let census = Arc::new(GuestExecutorCensus::default());
        let registry = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let mut original = census
            .enter_with_pause_endpoint(
                Some(context.thread().clone()),
                registry,
                context.thread().registry_id(),
            )
            .unwrap();
        assert!(matches!(
            census.enter(Some(context.thread().clone())),
            Err(GuestExecutorCensusError::DuplicateThread { .. })
        ));
        assert!(original.lock_exact_mm().all_have_pause_endpoints());
        drop(original);
        assert_eq!(census.participant_count_for_probe(), 0);
    }

    #[test]
    fn rejected_admission_still_drains_original_before_granting_mutation() {
        use carrick_hal::{InGuestFlag, VcpuRegistrationEnrollment, VcpuRegistry};
        use std::sync::atomic::{AtomicUsize, Ordering};
        #[derive(Clone)]
        struct ParkOriginal {
            flag: Arc<InGuestFlag>,
            calls: Arc<AtomicUsize>,
        }
        impl carrick_hal::VcpuKick for ParkOriginal {
            fn kick(&self) {
                self.calls.fetch_add(1, Ordering::SeqCst);
                // Deterministic owner safe point: the original registration's
                // kick is the only operation that makes this executor idle.
                self.flag.leave_guest();
            }
        }
        let (_kernel, context) = bootstrap_thread(19_598);
        let census = Arc::new(GuestExecutorCensus::default());
        let registry = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let wrong = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let flag = Arc::new(InGuestFlag::for_guest_thread());
        let calls = Arc::new(AtomicUsize::new(0));
        let tid = context.thread().registry_id();
        assert!(matches!(
            registry.subscribe_register(
                tid,
                Box::new(ParkOriginal {
                    flag: flag.clone(),
                    calls: calls.clone()
                }),
                &flag,
                Arc::new(|| {})
            ),
            VcpuRegistrationEnrollment::Registered
        ));
        let original = census
            .enter_with_pause_endpoint(Some(context.thread().clone()), registry.clone(), tid)
            .unwrap();
        let editor_tid = ThreadId::synthetic_for_tests(19_597);
        let mut editor = census
            .enter_with_pause_endpoint(None, registry.clone(), editor_tid)
            .unwrap();
        flag.enter_guest();
        assert!(matches!(
            census.enter_with_pause_endpoint(Some(context.thread().clone()), wrong, tid),
            Err(GuestExecutorCensusError::DuplicateThread { .. })
        ));
        let barrier = Arc::new(crate::fork_quiesce::PtQuiesce::new());
        let pause = crate::dispatch::mm_quiesce::acquire_pt_pause(
            &barrier,
            &mut editor,
            editor_tid,
            crate::dispatch::mm_quiesce::PtPauseBudget::DEFAULT,
        )
        .unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the original owner must reach its safe point first"
        );
        assert!(
            !flag.is_in_guest(),
            "mutation permission cannot overlap original execution"
        );
        assert!(barrier.is_quiescing());
        drop(pause);
        assert!(!barrier.is_quiescing());
        drop(editor);
        drop(original);
        assert_eq!(census.participant_count_for_probe(), 0);
        registry.unregister(tid);
    }

    #[test]
    fn failed_crash_participation_unwinds_exact_census_identity() {
        let (_kernel, context) = bootstrap_thread(19_501);
        let thread = context.thread().clone();
        let _outside = thread
            .enter_crash_safe_point_participation()
            .expect("outside participation");
        let census = Arc::new(GuestExecutorCensus::default());

        assert!(matches!(
            census.enter(Some(thread.clone())),
            Err(GuestExecutorCensusError::CrashParticipationAlreadyActive {
                thread: rejected
            }) if rejected == thread.key()
        ));
        assert_eq!(census.participant_count_for_probe(), 0);
    }

    #[test]
    fn dropping_one_exact_participant_preserves_the_other() {
        let census = Arc::new(GuestExecutorCensus::default());
        let first = census.enter(None).expect("first token");
        let second = census.enter(None).expect("second token");
        assert_ne!(
            first.identity, second.identity,
            "two live executors must own distinct linear census identities"
        );
        assert!(census.has_peer_executor());
        drop(second);
        assert!(!census.has_peer_executor());
        drop(first);
        assert_eq!(census.participant_count_for_probe(), 0);
    }

    #[test]
    fn probe_participant_count_saturates_at_i32_max() {
        let max = usize::try_from(i32::MAX).expect("i32 max fits usize");
        assert_eq!(saturating_participant_count_for_probe(max), i32::MAX);
        assert_eq!(
            saturating_participant_count_for_probe(max.saturating_add(1)),
            i32::MAX
        );
    }

    #[test]
    fn anonymous_identity_exhaustion_never_reuses_the_final_token() {
        let census = Arc::new(GuestExecutorCensus::default());
        census.state.lock().next_anonymous = u64::MAX;

        let final_token = census.enter(None).expect("final nonzero token");
        assert!(matches!(
            census.enter(None),
            Err(GuestExecutorCensusError::AnonymousIdentityExhausted)
        ));
        drop(final_token);
        assert_eq!(census.participant_count_for_probe(), 0);
        assert!(matches!(
            census.enter(None),
            Err(GuestExecutorCensusError::AnonymousIdentityExhausted)
        ));
    }

    #[test]
    fn a_sole_executor_needs_no_barrier() {
        let census = Arc::new(GuestExecutorCensus::default());
        let _only = census.enter(None).expect("sole token");
        assert!(!census.has_peer_executor());
    }

    #[test]
    fn a_peer_that_releases_participation_leaves_the_census() {
        // When a peer suspends, it drops its participation and leaves the census.
        let census = Arc::new(GuestExecutorCensus::default());
        let _mutator = census.enter(None).expect("mutator token");
        let parked_sibling = census.enter(None).expect("sibling token");
        assert!(census.has_peer_executor());
        drop(parked_sibling);
        assert!(!census.has_peer_executor());
    }

    #[test]
    fn membership_ends_on_unwind() {
        let census = Arc::new(GuestExecutorCensus::default());
        let _mutator = census.enter(None).expect("mutator token");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
            let census = Arc::clone(&census);
            move || {
                let _doomed = census.enter(None).expect("doomed token");
                assert!(census.has_peer_executor());
                panic!("admitted executor quantum unwound");
            }
        }));
        assert!(result.is_err());
        assert!(
            !census.has_peer_executor(),
            "an unwound executor must leave the population"
        );
    }
}
