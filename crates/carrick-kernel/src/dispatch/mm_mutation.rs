//! Structural authority for the only permitted mutation order:
//! page-table exclusion first, then a host-alias phase for the same MM.

use crate::kernel::MmId;
use carrick_fatal::carrick_fatal;
use parking_lot::{Condvar, Mutex};
use std::marker::PhantomData;
use std::sync::Arc;

/// Operation holding structural alias exclusion, readable directly in cores.
#[derive(Clone, Copy, Debug)]
pub(crate) enum AliasOperation {
    Mutation,
    Dispatch,
    Install,
}

#[derive(Debug)]
struct AliasHolder {
    #[allow(dead_code)] // Acquisition identity retained for offline core inspection.
    host_thread: std::thread::ThreadId,
    host_os_thread: Option<u64>,
    since: std::time::Instant,
    guest_tid: Option<carrick_hal::ThreadId>,
    operation: AliasOperation,
}

#[derive(Debug)]
struct CoordinatorState {
    alias_holder: Option<AliasHolder>,
    alias_waiters: usize,
    snapshot_readers: usize,
}

/// The calling thread's host OS thread id, as lldb prints it (`tid = ...`).
///
/// macOS only, where `carrick debug lldb-run` runs: other hosts have no
/// reviewed, non-raw-syscall thread-id operation yet, so their degraded
/// snapshot reports the holder as unknown rather than inventing one.
fn current_host_thread_id() -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        let mut id = 0_u64;
        // SAFETY: a zero (null) thread names the calling thread; `id` is a valid
        // out-pointer for the duration of the call.
        let rc = unsafe { libc::pthread_threadid_np(0, &mut id) };
        (rc == 0).then_some(id)
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// Per-MM observation point for structural mutation/alias ownership.
#[derive(Debug)]
pub struct MmMutationCoordinator {
    mm: MmId,
    state: Mutex<CoordinatorState>,
    idle: Condvar,
}

impl MmMutationCoordinator {
    pub fn new(mm: MmId) -> Self {
        Self {
            mm,
            state: Mutex::new(CoordinatorState {
                alias_holder: None,
                alias_waiters: 0,
                snapshot_readers: 0,
            }),
            idle: Condvar::new(),
        }
    }

    pub fn begin_alias<'permit>(
        self: &Arc<Self>,
        permit: &'permit HostAliasPermit<'_>,
    ) -> HostAliasCoordinatorGuard<'permit> {
        self.begin_alias_for(permit, AliasOperation::Mutation)
    }

    pub(crate) fn begin_alias_for<'permit>(
        self: &Arc<Self>,
        permit: &'permit HostAliasPermit<'_>,
        operation: AliasOperation,
    ) -> HostAliasCoordinatorGuard<'permit> {
        assert!(
            permit.authorizes(self, self.mm),
            "host-alias permit belongs to another MM"
        );
        let mut state = self.state.lock();
        if state.alias_holder.is_some() || state.snapshot_readers != 0 {
            state.alias_waiters += 1;
            while state.alias_holder.is_some() || state.snapshot_readers != 0 {
                self.idle.wait(&mut state);
            }
            state.alias_waiters -= 1;
        }
        let holder = AliasHolder {
            host_thread: std::thread::current().id(),
            host_os_thread: current_host_thread_id(),
            since: std::time::Instant::now(),
            guest_tid: permit.guest_tid,
            operation,
        };
        self.record_alias(&holder, false);
        state.alias_holder = Some(holder);
        drop(state);
        HostAliasCoordinatorGuard {
            coordinator: Arc::clone(self),
            _permit: PhantomData,
        }
    }

    fn record_alias(&self, holder: &AliasHolder, end: bool) {
        let kind = if end {
            crate::event_ring::ALIAS_END
        } else {
            match holder.operation {
                AliasOperation::Mutation => crate::event_ring::ALIAS_MUTATION,
                AliasOperation::Dispatch => crate::event_ring::ALIAS_DISPATCH,
                AliasOperation::Install => crate::event_ring::ALIAS_INSTALL,
            }
        };
        let address = self as *const Self as usize as u64;
        crate::event_ring::rec(
            kind,
            (address >> 32) as i32,
            address as i32,
            holder.guest_tid.map_or(0, carrick_hal::ThreadId::raw),
        );
    }

    pub(crate) fn begin_snapshot_until(
        self: &Arc<Self>,
        deadline: std::time::Instant,
    ) -> Option<MmSnapshotGuard> {
        let mut state = self.state.lock();
        while state.alias_holder.is_some() {
            let now = std::time::Instant::now();
            if now >= deadline {
                return None;
            }
            if self
                .idle
                .wait_for(&mut state, deadline.saturating_duration_since(now))
                .timed_out()
                && state.alias_holder.is_some()
            {
                return None;
            }
        }
        state.snapshot_readers += 1;
        Some(MmSnapshotGuard {
            coordinator: Arc::clone(self),
        })
    }

    /// Report the coordinator's state without waiting for it: the state
    /// lock is only ever held for a few instructions, so a bounded try-lock
    /// that fails means contention, not a wedge, and reads as `None`.
    pub(crate) fn observe(&self) -> Option<crate::kernel::MmMutationObservation> {
        let state = self
            .state
            .try_lock_for(std::time::Duration::from_millis(10))?;
        let holder = state.alias_holder.as_ref();
        Some(crate::kernel::MmMutationObservation {
            alias_active: holder.is_some(),
            alias_holder_host_thread: holder.and_then(|h| h.host_os_thread),
            alias_held_for: holder.map(|h| h.since.elapsed()),
            alias_waiters: state.alias_waiters,
            snapshot_readers: state.snapshot_readers,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn alias_waiters(&self) -> usize {
        self.state.lock().alias_waiters
    }

    #[cfg(any(test, feature = "test-support"))]
    pub const fn mm(&self) -> MmId {
        self.mm
    }
}

/// A guard minted only after the outer dispatch boundary has established the
/// exact MM's page-table exclusion (or its sealed single-executor equivalent).
///
/// ```compile_fail
/// use carrick_runtime::dispatch::mm_mutation::MmMutationGuard;
/// let _ = MmMutationGuard { coordinator: todo!(), mm: todo!(), _authority: todo!() };
/// ```
///
/// ```compile_fail
/// use carrick_runtime::dispatch::mm_mutation::MmMutationGuard;
/// fn clone_guard(guard: MmMutationGuard<'_>) {
///     let _: MmMutationGuard<'_> = guard.clone();
/// }
/// ```
pub struct MmMutationGuard<'authority> {
    coordinator: Arc<MmMutationCoordinator>,
    mm: MmId,
    operation: carrick_observability::probes::HvpatchTopologyOperation,
    guest_tid: Option<carrick_hal::ThreadId>,
    foreign_authority: Option<&'authority mut super::mm_quiesce::FrameCowExactMmGuard>,
    /// Held for the guard's lifetime: no guest EL1 stage-1 edit of `mm`
    /// runs concurrently with a host edit.
    _el1_editor: Option<crate::kernel::mm_occupancy::El1EditorExclusion>,
    _authority: PhantomData<&'authority mut ()>,
}

impl<'authority> MmMutationGuard<'authority> {
    pub fn with_operation(
        mut self,
        operation: carrick_observability::probes::HvpatchTopologyOperation,
    ) -> Self {
        self.operation = operation;
        self
    }

    /// Borrow the outer authority for one inner host-alias acquisition.
    pub fn host_alias_permit(&self) -> HostAliasPermit<'_> {
        HostAliasPermit {
            coordinator: Arc::clone(&self.coordinator),
            mm: self.mm,
            guest_tid: self.guest_tid,
            _guard: PhantomData,
        }
    }

    /// Begin a topology transaction under this MM mutation authority.
    ///
    /// The transaction borrows the mutation guard so it cannot outlive
    /// the stage-1 page-table exclusion.
    pub fn begin_transaction(&self) -> MmTransactionGuard<'_> {
        MmTransactionGuard {
            depth: {
                carrick_thread::fork_quiesce::emit_topology_lock(
                    self.operation,
                    carrick_observability::probes::HvpatchTopologyPhase::Requested,
                    0,
                    0,
                    0,
                );
                let depth = carrick_thread::fork_quiesce::TopologyDepth::acquire();
                // Depth acquisition is non-blocking (atomic thread counter), so Acquired elapsed_ns is 0.
                carrick_thread::fork_quiesce::emit_topology_lock(
                    self.operation,
                    carrick_observability::probes::HvpatchTopologyPhase::Acquired,
                    0,
                    0,
                    0,
                );
                depth
            },
            operation: self.operation,
            guest_pid: 0,
            guest_tid: 0,
            acquired_at: std::time::Instant::now(),
            _guard: PhantomData,
        }
    }

    #[allow(dead_code)] // Canonical process_vm consumer lands in Task 8.
    pub(crate) fn authorizes(&self, coordinator: &Arc<MmMutationCoordinator>, mm: MmId) -> bool {
        self.mm == mm && self.coordinator.mm == mm && Arc::ptr_eq(&self.coordinator, coordinator)
    }

    #[allow(dead_code)] // Canonical process_vm consumer lands in Task 8.
    pub fn with_host_alias<T>(&mut self, operation: impl FnOnce(&mut Self) -> T) -> T {
        let coordinator = Arc::clone(&self.coordinator);
        let permit = HostAliasPermit {
            coordinator: Arc::clone(&coordinator),
            mm: self.mm,
            guest_tid: self.guest_tid,
            _guard: PhantomData,
        };
        let _alias = coordinator.begin_alias(&permit);
        operation(self)
    }
}

impl carrick_hal::ForeignMmInvalidator for MmMutationGuard<'_> {
    /// Publication is immediate: the guard holds the target MM's fence, and
    /// each vCPU services the invalidation before it runs the MM again, so
    /// nothing is waited for and the deadline is not consulted.
    fn invalidate_exact_asid(
        &mut self,
        binding: carrick_hal::ForeignMmBinding,
        _deadline: std::time::Instant,
    ) -> Result<(), carrick_hal::ForeignMmTransportError> {
        self.foreign_authority
            .as_deref_mut()
            .ok_or(carrick_hal::ForeignMmTransportError::AuthorityUnavailable)?
            .publish_foreign_cow_invalidation(binding)
            .map_err(|_| carrick_hal::ForeignMmTransportError::AuthorityUnavailable)
    }
}

/// Sealed exact-target binding installed alongside the foreign-MM carrier
/// transport. It owns no page-table authority itself; each use pauses the
/// target MM (draining every vCPU that runs it) and borrows the resulting
/// linear guard.
#[derive(Clone, Debug)]
#[allow(dead_code)] // Installed now; canonical process_vm consumer lands in Task 8.
pub struct ForeignMmMutationAuthority {
    mm: MmId,
    coordinator: Arc<MmMutationCoordinator>,
    stage1: Arc<dyn carrick_hal::stage1_mm::Stage1MmProjection>,
    pt_quiesce: Arc<carrick_thread::fork_quiesce::PtQuiesce>,
}

#[allow(dead_code)] // Installed now; canonical process_vm consumer lands in Task 8.
impl ForeignMmMutationAuthority {
    pub fn new(
        mm: MmId,
        coordinator: Arc<MmMutationCoordinator>,
        stage1: Arc<dyn carrick_hal::stage1_mm::Stage1MmProjection>,
        pt_quiesce: Arc<carrick_thread::fork_quiesce::PtQuiesce>,
    ) -> Self {
        assert_eq!(
            coordinator.mm, mm,
            "foreign mutation coordinator/MM mismatch"
        );
        Self {
            mm,
            coordinator,
            stage1,
            pt_quiesce,
        }
    }

    pub(in crate::dispatch) fn matches_native_authority(
        &self,
        authority: &super::DispatchMmAuthority,
    ) -> bool {
        self.mm == authority.mm_id
            && Arc::ptr_eq(&self.coordinator, &authority.mutation_coordinator)
            && Arc::ptr_eq(&self.pt_quiesce, &authority.pt_quiesce)
    }

    pub(crate) fn authorizes(&self, guard: &MmMutationGuard<'_>) -> bool {
        guard.authorizes(&self.coordinator, self.mm)
    }

    pub fn with_guard<T>(
        &self,
        tid: carrick_hal::ThreadId,
        operation: impl FnOnce(&mut MmMutationGuard<'_>) -> T,
    ) -> Result<T, ForeignMmMutationError> {
        let mut authority = super::mm_quiesce::acquire_foreign_mm_mutation_quiesce(
            &self.pt_quiesce,
            self.mm,
            Arc::clone(&self.coordinator),
            Arc::clone(&self.stage1),
            tid,
            super::mm_quiesce::PtPauseBudget::DEFAULT,
        )
        .map_err(|error| match error {
            super::mm_quiesce::PtPauseError::TimedOut => ForeignMmMutationError::TimedOut,
        })?;
        let mut mutation = from_frame_cow(&mut authority);
        Ok(operation(&mut mutation))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[allow(dead_code)] // Canonical process_vm consumer lands in Task 8.
pub enum ForeignMmMutationError {
    #[error("target-MM page-table exclusion timed out")]
    TimedOut,
}

pub fn from_pt_pause<'authority>(
    authority: &'authority mut super::mm_quiesce::PtPauseGuard,
) -> MmMutationGuard<'authority> {
    let (coordinator, mm) = authority.mutation_identity().unwrap_or_else(|| {
        carrick_fatal!(
            "dispatch::mm_mutation",
            "missing mutation identity in from_pt_pause"
        );
    });
    MmMutationGuard {
        coordinator,
        mm,
        operation: carrick_observability::probes::HvpatchTopologyOperation::InProcessFork,
        guest_tid: None,
        foreign_authority: None,
        _el1_editor: crate::kernel::mm_occupancy::exclude_el1_editor(mm),
        _authority: PhantomData,
    }
}

pub fn from_sole_executor<'authority>(
    authority: &'authority mut super::mm_quiesce::SoleMmStage1<'_>,
    coordinator: Arc<MmMutationCoordinator>,
    mm: MmId,
) -> MmMutationGuard<'authority> {
    assert!(
        authority.authorizes(&coordinator, mm),
        "sole-executor authority belongs to another MM"
    );
    MmMutationGuard {
        coordinator,
        mm,
        operation: carrick_observability::probes::HvpatchTopologyOperation::InProcessFork,
        guest_tid: None,
        foreign_authority: None,
        _el1_editor: crate::kernel::mm_occupancy::exclude_el1_editor(mm),
        _authority: PhantomData,
    }
}

pub fn from_executor<'authority>(
    participation: &'authority mut super::MmExecutorParticipation,
) -> MmMutationGuard<'authority> {
    let coordinator = participation.mutation_coordinator();
    let mm = participation.mm_id();
    MmMutationGuard {
        coordinator,
        mm,
        operation: carrick_observability::probes::HvpatchTopologyOperation::InProcessFork,
        guest_tid: participation.guest_tid(),
        foreign_authority: None,
        _el1_editor: crate::kernel::mm_occupancy::exclude_el1_editor(mm),
        _authority: PhantomData,
    }
}

#[allow(dead_code)] // Canonical process_vm consumer lands in Task 8.
pub(crate) fn from_frame_cow<'authority>(
    authority: &'authority mut super::mm_quiesce::FrameCowExactMmGuard,
) -> MmMutationGuard<'authority> {
    let (coordinator, mm) = authority.mutation_identity().unwrap_or_else(|| {
        carrick_fatal!(
            "dispatch::mm_mutation",
            "missing mutation identity in from_frame_cow"
        );
    });
    MmMutationGuard {
        coordinator,
        mm,
        operation: carrick_observability::probes::HvpatchTopologyOperation::FrameCow,
        guest_tid: None,
        foreign_authority: Some(authority),
        _el1_editor: crate::kernel::mm_occupancy::exclude_el1_editor(mm),
        _authority: PhantomData,
    }
}

/// Borrow-bound authority required by every host-alias entry point.
///
/// ```compile_fail
/// use carrick_runtime::dispatch::mm_mutation::{HostAliasPermit, MmMutationGuard};
/// fn leak(guard: &mut MmMutationGuard<'_>) -> HostAliasPermit<'static> {
///     guard.host_alias_permit()
/// }
/// ```
pub struct HostAliasPermit<'guard> {
    coordinator: Arc<MmMutationCoordinator>,
    mm: MmId,
    guest_tid: Option<carrick_hal::ThreadId>,
    _guard: PhantomData<&'guard MmMutationGuard<'guard>>,
}

impl HostAliasPermit<'_> {
    /// Return the exact MM identity already carried by this borrow-bound
    /// permit. This exposes no additional mutation authority: consumers must
    /// still present the permit to every host-alias operation.
    pub const fn mm(&self) -> MmId {
        self.mm
    }

    pub(crate) fn authorizes(&self, coordinator: &Arc<MmMutationCoordinator>, mm: MmId) -> bool {
        self.mm == mm && coordinator.mm == mm && Arc::ptr_eq(&self.coordinator, coordinator)
    }
}

/// Exclusion for one MM's fork/exec/retire transaction. Minted only by the
/// MM's `MmMutationGuard` (`begin_transaction`), so holding it proves the
/// stage-1 pause is already held: the P -> topology order becomes a type,
/// not a comment.
pub struct MmTransactionGuard<'guard> {
    depth: carrick_thread::fork_quiesce::TopologyDepth,
    operation: carrick_observability::probes::HvpatchTopologyOperation,
    guest_pid: i32,
    guest_tid: i32,
    acquired_at: std::time::Instant,
    _guard: PhantomData<&'guard MmMutationGuard<'guard>>,
}

impl<'guard> MmTransactionGuard<'guard> {
    /// Access the underlying topology depth token.
    pub const fn depth(&self) -> &carrick_thread::fork_quiesce::TopologyDepth {
        &self.depth
    }

    pub fn set_identity(&mut self, pid: i32, tid: i32) {
        self.guest_pid = pid;
        self.guest_tid = tid;
    }
}

impl Drop for MmTransactionGuard<'_> {
    fn drop(&mut self) {
        carrick_thread::fork_quiesce::emit_topology_lock(
            self.operation,
            carrick_observability::probes::HvpatchTopologyPhase::Released,
            self.guest_pid,
            self.guest_tid,
            carrick_thread::fork_quiesce::topology_elapsed_ns(self.acquired_at),
        );
    }
}

pub struct HostAliasCoordinatorGuard<'permit> {
    coordinator: Arc<MmMutationCoordinator>,
    _permit: PhantomData<&'permit ()>,
}

pub struct MmSnapshotGuard {
    coordinator: Arc<MmMutationCoordinator>,
}

impl Drop for MmSnapshotGuard {
    fn drop(&mut self) {
        let mut state = self.coordinator.state.lock();
        state.snapshot_readers = state.snapshot_readers.checked_sub(1).unwrap_or_else(|| {
            carrick_fatal!(
                "dispatch::mm_mutation",
                "snapshot readers underflow in MmSnapshotGuard drop"
            );
        });
        if state.snapshot_readers == 0 {
            self.coordinator.idle.notify_all();
        }
    }
}

impl Drop for HostAliasCoordinatorGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.coordinator.state.lock();
        let holder = state.alias_holder.take().unwrap_or_else(|| {
            carrick_fatal!("dispatch::mm_mutation", "host-alias coordinator underflow");
        });
        self.coordinator.record_alias(&holder, true);
        self.coordinator.idle.notify_all();
    }
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) mod test_support {
    use super::*;

    pub(in crate::dispatch) fn with_guard<T>(
        coordinator: Arc<MmMutationCoordinator>,
        use_guard: impl FnOnce(&mut MmMutationGuard<'_>) -> T,
    ) -> T {
        crate::dispatch::mm_quiesce::with_real_pt_pause_for_test(coordinator, |authority| {
            let mut guard = from_pt_pause(authority);
            use_guard(&mut guard)
        })
    }

    pub(in crate::dispatch) fn with_permit<T>(
        coordinator: Arc<MmMutationCoordinator>,
        use_permit: impl FnOnce(&HostAliasPermit<'_>) -> T,
    ) -> T {
        with_guard(coordinator, |guard| {
            let permit = guard.host_alias_permit();
            use_permit(&permit)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{HostAliasPermit, MmMutationCoordinator, MmMutationGuard, MmTransactionGuard};
    use crate::kernel::MmId;
    use static_assertions::assert_not_impl_any;
    use std::num::NonZeroU64;
    use std::sync::Arc;

    assert_not_impl_any!(MmMutationGuard<'static>: Clone, Copy);
    assert_not_impl_any!(HostAliasPermit<'static>: Clone, Copy);
    assert_not_impl_any!(MmTransactionGuard<'static>: Clone, Copy);

    fn mm(raw: u64) -> MmId {
        MmId::from_registry_allocation(NonZeroU64::new(raw).expect("nonzero MM id"))
    }

    #[test]
    fn alias_holder_names_acquisition_and_clears_on_drop() {
        let coordinator = Arc::new(MmMutationCoordinator::new(mm(13)));
        super::test_support::with_guard(Arc::clone(&coordinator), |guard| {
            let tid = carrick_hal::ThreadId::synthetic_for_tests(42);
            guard.guest_tid = Some(tid);
            let permit = guard.host_alias_permit();
            let alias = coordinator.begin_alias_for(&permit, super::AliasOperation::Install);
            {
                let state = coordinator.state.lock();
                let holder = state.alias_holder.as_ref().expect("named holder");
                assert_eq!(holder.host_thread, std::thread::current().id());
                assert_eq!(holder.guest_tid, Some(tid));
                assert!(matches!(holder.operation, super::AliasOperation::Install));
            }
            drop(alias);
            assert!(coordinator.state.lock().alias_holder.is_none());
        });
    }

    #[test]
    fn permit_is_bound_to_the_exact_guard_and_mm_coordinator() {
        let coordinator = Arc::new(MmMutationCoordinator::new(mm(11)));
        super::test_support::with_permit(Arc::clone(&coordinator), |permit| {
            assert_eq!(permit.mm(), mm(11));
            assert!(permit.authorizes(&coordinator, mm(11)));
            assert!(!permit.authorizes(&coordinator, mm(12)));
            assert!(!permit.authorizes(&Arc::new(MmMutationCoordinator::new(mm(11))), mm(11)));
        });
    }

    /// A degraded kernel snapshot must be able to name who holds the alias
    /// phase a strict snapshot is waiting on, without entering it.
    #[test]
    fn observation_names_the_alias_holder_without_waiting() {
        let coordinator = Arc::new(MmMutationCoordinator::new(mm(21)));
        let idle = coordinator.observe().expect("uncontended state");
        assert!(!idle.alias_active);
        assert_eq!(idle.alias_holder_host_thread, None);

        super::test_support::with_permit(Arc::clone(&coordinator), |permit| {
            let alias = coordinator.begin_alias(permit);
            let held = coordinator.observe().expect("uncontended state");
            assert!(held.alias_active);
            assert_eq!(
                held.alias_holder_host_thread,
                super::current_host_thread_id()
            );
            assert!(held.alias_held_for.is_some());
            // The strict snapshot path is what a wedge blocks; it must time
            // out rather than report a snapshot.
            assert!(
                coordinator
                    .begin_snapshot_until(
                        std::time::Instant::now() + std::time::Duration::from_millis(5)
                    )
                    .is_none()
            );
            drop(alias);
        });

        let released = coordinator.observe().expect("uncontended state");
        assert!(!released.alias_active);
        assert_eq!(released.alias_holder_host_thread, None);
        assert_eq!(released.alias_held_for, None);
    }
}

/// The transaction for a process's terminal retirement
/// (`finalize_persistent_process_terminal`), which edits no live stage-1
/// table: the final owner retires the mm whole (no task can run it again)
/// and a non-owner only publishes its own retirement rows. It needs the
/// transaction depth (the executor-boundary invariant) and the registry
/// leaf its callers take, not a page-table pause. Electing a pause there
/// drained sibling executors that `exit_group` had already put beyond
/// kicking — `UnkickableExecutor` → `CarrierFailed`, or a hang — on every
/// threaded Go process exit (2026-09-12). This and
/// `MmMutationGuard::begin_transaction` are the only two construction
/// paths; the source-shape test in `mm_authority.rs` pins both.
pub fn terminal_process_transaction() -> MmTransactionGuard<'static> {
    MmTransactionGuard {
        depth: {
            let operation = carrick_observability::probes::HvpatchTopologyOperation::ProcessRetire;
            carrick_thread::fork_quiesce::emit_topology_lock(
                operation,
                carrick_observability::probes::HvpatchTopologyPhase::Requested,
                0,
                0,
                0,
            );
            let depth = carrick_thread::fork_quiesce::TopologyDepth::acquire();
            // Depth acquisition is non-blocking (atomic thread counter), so Acquired elapsed_ns is 0.
            carrick_thread::fork_quiesce::emit_topology_lock(
                operation,
                carrick_observability::probes::HvpatchTopologyPhase::Acquired,
                0,
                0,
                0,
            );
            depth
        },
        operation: carrick_observability::probes::HvpatchTopologyOperation::ProcessRetire,
        guest_pid: 0,
        guest_tid: 0,
        acquired_at: std::time::Instant::now(),
        _guard: PhantomData,
    }
}
