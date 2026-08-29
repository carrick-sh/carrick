//! Structural authority for the only permitted mutation order:
//! page-table exclusion first, then a host-alias phase for the same MM.

use crate::kernel::MmId;
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
    foreign_authority: Option<&'authority mut crate::vcpu_loop::quiesce::FrameCowExactMmGuard>,
    _authority: PhantomData<&'authority mut ()>,
}

impl MmMutationGuard<'_> {
    /// Borrow the outer authority for one inner host-alias acquisition.
    pub fn host_alias_permit(&self) -> HostAliasPermit<'_> {
        HostAliasPermit {
            coordinator: Arc::clone(&self.coordinator),
            mm: self.mm,
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
}

#[allow(dead_code)] // Installed now; canonical process_vm consumer lands in Task 8.
impl ForeignMmMutationAuthority {
    pub(crate) fn new(
        mm: MmId,
        coordinator: Arc<MmMutationCoordinator>,
        census: Arc<crate::kernel::GuestExecutorCensus>,
        stage1: Arc<crate::hvpatch::Stage1MmLease>,
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
    let (coordinator, mm) = authority
        .mutation_identity()
        .unwrap_or_else(|| std::process::abort());
    MmMutationGuard {
        coordinator,
        mm,
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
        foreign_authority: None,
        _authority: PhantomData,
    }
}

#[allow(dead_code)] // Canonical process_vm consumer lands in Task 8.
pub(crate) fn from_frame_cow<'authority>(
    authority: &'authority mut crate::vcpu_loop::quiesce::FrameCowExactMmGuard,
) -> MmMutationGuard<'authority> {
    let (coordinator, mm) = authority
        .mutation_identity()
        .unwrap_or_else(|| std::process::abort());
    MmMutationGuard {
        coordinator,
        mm,
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
        state.snapshot_readers = state
            .snapshot_readers
            .checked_sub(1)
            .unwrap_or_else(|| std::process::abort());
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
    use super::{HostAliasPermit, MmMutationCoordinator, MmMutationGuard};
    use crate::kernel::MmId;
    use static_assertions::assert_not_impl_any;
    use std::num::NonZeroU64;
    use std::sync::Arc;

    assert_not_impl_any!(MmMutationGuard<'static>: Clone, Copy);
    assert_not_impl_any!(HostAliasPermit<'static>: Clone, Copy);

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
