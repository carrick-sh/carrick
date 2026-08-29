//! Structural authority for the only permitted mutation order:
//! page-table exclusion first, then a host-alias phase for the same MM.

use crate::kernel::MmId;
use parking_lot::{Condvar, Mutex};
use std::marker::PhantomData;
use std::rc::Rc;
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
    state: Mutex<CoordinatorState>,
    idle: Condvar,
}

impl MmMutationCoordinator {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(CoordinatorState {
                alias_active: false,
                alias_waiters: 0,
                snapshot_readers: 0,
            }),
            idle: Condvar::new(),
        }
    }

    pub(crate) fn begin_alias(
        self: &Arc<Self>,
        permit: &HostAliasPermit<'_>,
    ) -> HostAliasCoordinatorGuard {
        assert!(
            permit.authorizes(self),
            "host-alias permit belongs to another MM"
        );
        let _authorized_mm = permit.mm();
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
    const fn outer_waiters(&self) -> usize {
        // Outer page-table exclusion is acquired before this coordinator can
        // be entered, so this layer has no API capable of waiting for it.
        0
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
/// fn clone_guard(guard: &MmMutationGuard<'_>) { let _ = guard.clone(); }
/// ```
pub struct MmMutationGuard<'authority> {
    coordinator: Arc<MmMutationCoordinator>,
    mm: MmId,
    _authority: PhantomData<&'authority mut ()>,
}

impl MmMutationGuard<'_> {
    /// Borrow the outer authority for one inner host-alias acquisition.
    pub fn host_alias_permit(&mut self) -> HostAliasPermit<'_> {
        HostAliasPermit {
            coordinator: Arc::clone(&self.coordinator),
            mm: self.mm,
            _guard: PhantomData,
        }
    }
}

pub(crate) fn from_pt_pause<'authority>(
    _authority: &'authority mut crate::vcpu_loop::quiesce::PtPauseGuard,
    coordinator: Arc<MmMutationCoordinator>,
    mm: MmId,
) -> MmMutationGuard<'authority> {
    MmMutationGuard {
        coordinator,
        mm,
        _authority: PhantomData,
    }
}

pub(crate) fn from_stage1_exclusive<'authority>(
    _authority: &'authority mut crate::vcpu_loop::quiesce::Stage1Exclusive,
    coordinator: Arc<MmMutationCoordinator>,
    mm: MmId,
) -> MmMutationGuard<'authority> {
    MmMutationGuard {
        coordinator,
        mm,
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
    _guard: PhantomData<&'guard mut MmMutationGuard<'guard>>,
}

impl HostAliasPermit<'_> {
    pub(crate) const fn mm(&self) -> MmId {
        self.mm
    }

    pub(crate) fn authorizes(&self, coordinator: &Arc<MmMutationCoordinator>) -> bool {
        Arc::ptr_eq(&self.coordinator, coordinator)
    }
}

pub(crate) struct HostAliasCoordinatorGuard {
    coordinator: Arc<MmMutationCoordinator>,
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

impl Drop for HostAliasCoordinatorGuard {
    fn drop(&mut self) {
        let mut state = self.coordinator.state.lock();
        assert!(state.alias_active, "host-alias coordinator underflow");
        state.alias_active = false;
        self.coordinator.idle.notify_all();
    }
}

/// Sealed authority for the non-threaded dispatcher boundary. The issuer is
/// neither `Clone` nor `Send`, and its constructor is intentionally kept out of
/// production handler modules.
pub(in crate::dispatch) struct SingleExecutorIssuer {
    coordinator: Arc<MmMutationCoordinator>,
    mm: MmId,
    _not_send: PhantomData<Rc<()>>,
}

impl SingleExecutorIssuer {
    pub(crate) fn guard(&mut self) -> MmMutationGuard<'_> {
        MmMutationGuard {
            coordinator: Arc::clone(&self.coordinator),
            mm: self.mm,
            _authority: PhantomData,
        }
    }
}

pub(super) fn single_executor_boundary(
    coordinator: Arc<MmMutationCoordinator>,
    mm: MmId,
) -> SingleExecutorIssuer {
    SingleExecutorIssuer {
        coordinator,
        mm,
        _not_send: PhantomData,
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::num::NonZeroU64;

    pub(in crate::dispatch) fn single_executor(
        coordinator: Arc<MmMutationCoordinator>,
        mm: MmId,
    ) -> SingleExecutorIssuer {
        single_executor_boundary(coordinator, mm)
    }

    pub(in crate::dispatch) fn with_permit<T>(
        coordinator: Arc<MmMutationCoordinator>,
        use_permit: impl FnOnce(&HostAliasPermit<'_>) -> T,
    ) -> T {
        let mm = MmId::from_registry_allocation(NonZeroU64::new(1).expect("nonzero test MM"));
        let mut issuer = single_executor(coordinator, mm);
        let mut guard = issuer.guard();
        let permit = guard.host_alias_permit();
        use_permit(&permit)
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
        let coordinator = Arc::new(MmMutationCoordinator::new());
        let mut issuer = super::test_support::single_executor(Arc::clone(&coordinator), mm(11));
        let mut guard = issuer.guard();
        let permit = guard.host_alias_permit();

        assert_eq!(permit.mm(), mm(11));
        assert!(permit.authorizes(&coordinator));
        assert!(!permit.authorizes(&Arc::new(MmMutationCoordinator::new())));
    }

    #[test]
    fn alias_waiter_already_owns_outer_mutation_authority() {
        let coordinator = Arc::new(MmMutationCoordinator::new());
        let mut first = super::test_support::single_executor(Arc::clone(&coordinator), mm(21));
        let mut first_guard = first.guard();
        let first_permit = first_guard.host_alias_permit();
        let held = coordinator.begin_alias(&first_permit);

        let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let entered_worker = Arc::clone(&entered);
        let coordinator_worker = Arc::clone(&coordinator);
        let worker = std::thread::spawn(move || {
            let mut second =
                super::test_support::single_executor(Arc::clone(&coordinator_worker), mm(21));
            let mut guard = second.guard();
            entered_worker.store(true, std::sync::atomic::Ordering::Release);
            let permit = guard.host_alias_permit();
            drop(coordinator_worker.begin_alias(&permit));
        });

        while !entered.load(std::sync::atomic::Ordering::Acquire) {
            std::thread::yield_now();
        }
        assert_eq!(coordinator.alias_waiters(), 1);
        assert_eq!(coordinator.outer_waiters(), 0);
        drop(held);
        worker.join().expect("alias waiter exits");
    }
}
