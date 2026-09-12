//! Structural authority for the only permitted mutation order:
//! page-table exclusion first, then a host-alias phase for the same MM.

use crate::kernel::MmId;
use carrick_fatal::carrick_fatal;
use parking_lot::{Condvar, Mutex};
use std::marker::PhantomData;
use std::sync::Arc;

#[derive(Debug)]
struct CoordinatorState {
    alias_active: bool,
    alias_waiters: usize,
    snapshot_readers: usize,
}

/// Per-MM observation point for structural mutation/alias ownership.
#[derive(Debug)]
pub(crate) struct MmMutationCoordinator {
    mm: MmId,
    state: Mutex<CoordinatorState>,
    idle: Condvar,
}

impl MmMutationCoordinator {
    pub(crate) fn new(mm: MmId) -> Self {
        Self {
            mm,
            state: Mutex::new(CoordinatorState {
                alias_active: false,
                alias_waiters: 0,
                snapshot_readers: 0,
            }),
            idle: Condvar::new(),
        }
    }

    pub(crate) fn begin_alias<'permit>(
        self: &Arc<Self>,
        permit: &'permit HostAliasPermit<'_>,
    ) -> HostAliasCoordinatorGuard<'permit> {
        assert!(
            permit.authorizes(self, self.mm),
            "host-alias permit belongs to another MM"
        );
        let mut state = self.state.lock();
        if state.alias_active || state.snapshot_readers != 0 {
            state.alias_waiters += 1;
            while state.alias_active || state.snapshot_readers != 0 {
                self.idle.wait(&mut state);
            }
            state.alias_waiters -= 1;
        }
        state.alias_active = true;
        drop(state);
        HostAliasCoordinatorGuard {
            coordinator: Arc::clone(self),
            _permit: PhantomData,
        }
    }

    pub(crate) fn begin_snapshot_until(
        self: &Arc<Self>,
        deadline: std::time::Instant,
    ) -> Option<MmSnapshotGuard> {
        let mut state = self.state.lock();
        while state.alias_active {
            let now = std::time::Instant::now();
            if now >= deadline {
                return None;
            }
            if self
                .idle
                .wait_for(&mut state, deadline.saturating_duration_since(now))
                .timed_out()
                && state.alias_active
            {
                return None;
            }
        }
        state.snapshot_readers += 1;
        Some(MmSnapshotGuard {
            coordinator: Arc::clone(self),
        })
    }

    #[cfg(test)]
    pub(crate) fn alias_waiters(&self) -> usize {
        self.state.lock().alias_waiters
    }

    #[cfg(test)]
    pub(crate) const fn mm(&self) -> MmId {
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
    foreign_authority: Option<&'authority mut crate::vcpu_loop::quiesce::FrameCowExactMmGuard>,
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
    pub(crate) fn with_host_alias<T>(&mut self, operation: impl FnOnce(&mut Self) -> T) -> T {
        let coordinator = Arc::clone(&self.coordinator);
        let permit = HostAliasPermit {
            coordinator: Arc::clone(&coordinator),
            mm: self.mm,
            _guard: PhantomData,
        };
        let _alias = coordinator.begin_alias(&permit);
        operation(self)
    }
}

impl carrick_hal::ForeignMmInvalidator for MmMutationGuard<'_> {
    fn invalidate_exact_asid(
        &mut self,
        binding: carrick_hal::ForeignMmBinding,
        deadline: std::time::Instant,
    ) -> Result<(), carrick_hal::ForeignMmTransportError> {
        self.foreign_authority
            .as_deref_mut()
            .ok_or(carrick_hal::ForeignMmTransportError::AuthorityUnavailable)?
            .publish_foreign_cow_invalidation(binding, deadline)
            .map_err(|_| carrick_hal::ForeignMmTransportError::AuthorityUnavailable)
    }
}

/// Sealed exact-target binding installed alongside the foreign-MM carrier
/// transport. It owns no page-table authority itself; each use drains the
/// target dispatcher census and borrows the resulting linear guard.
#[derive(Clone, Debug)]
#[allow(dead_code)] // Installed now; canonical process_vm consumer lands in Task 8.
pub(crate) struct ForeignMmMutationAuthority {
    mm: MmId,
    coordinator: Arc<MmMutationCoordinator>,
    census: Arc<crate::kernel::GuestExecutorCensus>,
    stage1: Arc<crate::hvpatch::Stage1MmLease>,
    pt_quiesce: Arc<carrick_thread::fork_quiesce::PtQuiesce>,
}

#[allow(dead_code)] // Installed now; canonical process_vm consumer lands in Task 8.
impl ForeignMmMutationAuthority {
    pub(crate) fn new(
        mm: MmId,
        coordinator: Arc<MmMutationCoordinator>,
        census: Arc<crate::kernel::GuestExecutorCensus>,
        stage1: Arc<crate::hvpatch::Stage1MmLease>,
        pt_quiesce: Arc<carrick_thread::fork_quiesce::PtQuiesce>,
    ) -> Self {
        assert_eq!(
            coordinator.mm, mm,
            "foreign mutation coordinator/MM mismatch"
        );
        Self {
            mm,
            coordinator,
            census,
            stage1,
            pt_quiesce,
        }
    }

    pub(crate) fn authorizes(&self, guard: &MmMutationGuard<'_>) -> bool {
        guard.authorizes(&self.coordinator, self.mm)
    }

    pub(crate) fn with_guard<T>(
        &self,
        tid: carrick_hal::ThreadId,
        operation: impl FnOnce(&mut MmMutationGuard<'_>) -> T,
    ) -> Result<T, ForeignMmMutationError> {
        crate::vcpu_loop::with_foreign_mm_mutation_guard(
            &self.pt_quiesce,
            self.mm,
            Arc::clone(&self.coordinator),
            &self.census,
            Arc::clone(&self.stage1),
            tid,
            operation,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[allow(dead_code)] // Canonical process_vm consumer lands in Task 8.
pub(crate) enum ForeignMmMutationError {
    #[error("target-MM page-table exclusion timed out")]
    TimedOut,
    #[error("target MM has an executor without a pause endpoint")]
    UnkickableExecutor,
}

pub(crate) fn from_pt_pause<'authority>(
    authority: &'authority mut crate::vcpu_loop::quiesce::PtPauseGuard,
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
        foreign_authority: None,
        _authority: PhantomData,
    }
}

pub(crate) fn from_sole_executor<'authority>(
    authority: &'authority mut crate::vcpu_loop::quiesce::SoleMmStage1<'_>,
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
        foreign_authority: None,
        _authority: PhantomData,
    }
}

#[allow(dead_code)] // Canonical process_vm consumer lands in Task 8.
pub(crate) fn from_frame_cow<'authority>(
    authority: &'authority mut crate::vcpu_loop::quiesce::FrameCowExactMmGuard,
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
        foreign_authority: Some(authority),
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
    _guard: PhantomData<&'guard MmMutationGuard<'guard>>,
}

impl HostAliasPermit<'_> {
    #[cfg(test)]
    pub(crate) const fn mm(&self) -> MmId {
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

pub(crate) struct HostAliasCoordinatorGuard<'permit> {
    coordinator: Arc<MmMutationCoordinator>,
    _permit: PhantomData<&'permit ()>,
}

pub(crate) struct MmSnapshotGuard {
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
        assert!(state.alias_active, "host-alias coordinator underflow");
        state.alias_active = false;
        self.coordinator.idle.notify_all();
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(in crate::dispatch) fn with_guard<T>(
        coordinator: Arc<MmMutationCoordinator>,
        use_guard: impl FnOnce(&mut MmMutationGuard<'_>) -> T,
    ) -> T {
        crate::vcpu_loop::with_real_pt_pause_for_test(coordinator, |authority| {
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
    fn permit_is_bound_to_the_exact_guard_and_mm_coordinator() {
        let coordinator = Arc::new(MmMutationCoordinator::new(mm(11)));
        super::test_support::with_permit(Arc::clone(&coordinator), |permit| {
            assert_eq!(permit.mm(), mm(11));
            assert!(permit.authorizes(&coordinator, mm(11)));
            assert!(!permit.authorizes(&coordinator, mm(12)));
            assert!(!permit.authorizes(&Arc::new(MmMutationCoordinator::new(mm(11))), mm(11)));
        });
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
