use std::sync::Arc;

use carrick_abi::{LINUX_ENOMEM, LinuxErrno};
use carrick_fatal::carrick_fatal;
use serde::Serialize;

use super::mm_mutation;
use super::{DispatchMmAuthority, SyscallDispatcher, mem, sysv};

/// Typed handle for one dispatcher-to-runtime host-alias installation. The
/// payload is intentionally opaque: exact VMA/SysV commit data stays owned by
/// the dispatcher and is published only after the runtime reports success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub(crate) struct HostAliasTransactionId(pub(crate) u64);

/// Owned dispatcher-to-runtime alias transaction. Dropping an unclaimed
/// transaction aborts the matching pending/installing phase, if any, and wakes
/// blocked sibling mapping syscalls.
pub struct HostAliasTransaction {
    pub(crate) authority: Arc<DispatchMmAuthority>,
    pub(crate) transactions: Arc<HostAliasTransactions>,
    pub(crate) id: HostAliasTransactionId,
    pub(crate) armed: bool,
}

impl std::fmt::Debug for HostAliasTransaction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("HostAliasTransaction")
            .field(&self.id)
            .finish()
    }
}

impl PartialEq for HostAliasTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && Arc::ptr_eq(&self.transactions, &other.transactions)
    }
}

impl Eq for HostAliasTransaction {}

impl Serialize for HostAliasTransaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.id.serialize(serializer)
    }
}

impl HostAliasTransaction {
    pub(crate) fn claim<'permit>(
        mut self,
        permit: &'permit mm_mutation::HostAliasPermit<'_>,
    ) -> Option<HostAliasInstallGuard<'permit>> {
        if !permit.authorizes(&self.authority.mutation_coordinator, self.authority.mm_id) {
            return None;
        }
        // Re-enter the alias coordinator under the caller's still-live outer
        // permit. The pending transaction owns no alias phase, so safe code
        // cannot smuggle exclusion through an owned DispatchOutcome.
        let structural = self.authority.mutation_coordinator.begin_alias(permit);
        let mut phase = self.transactions.phase.lock();
        let HostAliasPhase::Pending { id, commit } = &mut *phase else {
            return None;
        };
        if *id != self.id {
            return None;
        }
        let installing = commit.take();
        *phase = HostAliasPhase::Installing {
            id: self.id,
            commit: installing,
        };
        self.armed = false;
        Some(HostAliasInstallGuard {
            authority: Arc::clone(&self.authority),
            transactions: Arc::clone(&self.transactions),
            _structural: structural,
            id: self.id,
            armed: true,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_claim_for_test<T>(
        self,
        use_install: impl FnOnce(HostAliasInstallGuard<'_>) -> T,
    ) -> Option<T> {
        let coordinator = Arc::clone(&self.authority.mutation_coordinator);
        mm_mutation::test_support::with_permit(coordinator, |permit| {
            self.claim(permit).map(use_install)
        })
    }
}

impl Drop for HostAliasTransaction {
    fn drop(&mut self) {
        if self.armed {
            self.transactions.abort_matching(self.id);
        }
    }
}

pub(crate) struct HostAliasInstallGuard<'permit> {
    pub(crate) authority: Arc<DispatchMmAuthority>,
    pub(crate) transactions: Arc<HostAliasTransactions>,
    pub(crate) _structural: mm_mutation::HostAliasCoordinatorGuard<'permit>,
    pub(crate) id: HostAliasTransactionId,
    pub(crate) armed: bool,
}

impl HostAliasInstallGuard<'_> {
    pub(crate) fn bus_fault_range(&self) -> Option<(u64, u64)> {
        let phase = self.transactions.phase.lock();
        match &*phase {
            HostAliasPhase::Installing { id, commit } if *id == self.id => commit
                .as_ref()
                .and_then(|commit| commit.mmap.as_ref())
                .and_then(|mmap| mmap.bus_fault),
            _ => None,
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for HostAliasInstallGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.transactions.abort_matching(self.id);
        }
    }
}

pub(crate) struct HostAliasCommit {
    mmap: Option<mem::HostAliasMmapCommit>,
    io_uring_mapping: Option<super::ioring::IoUringMapping>,
    io_uring_mm: Option<Arc<crate::kernel::Mm>>,
    shmat: Option<sysv::HostAliasShmatCommit>,
}

impl HostAliasCommit {
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn empty_for_test() -> Self {
        Self {
            mmap: None,
            io_uring_mapping: None,
            io_uring_mm: None,
            shmat: None,
        }
    }

    pub(crate) fn mmap(mmap: mem::HostAliasMmapCommit) -> Self {
        Self {
            mmap: Some(mmap),
            io_uring_mapping: None,
            io_uring_mm: None,
            shmat: None,
        }
    }

    pub(crate) fn io_uring_mmap(
        mmap: mem::HostAliasMmapCommit,
        mapping: super::ioring::IoUringMapping,
        mm: Arc<crate::kernel::Mm>,
    ) -> Self {
        Self {
            mmap: Some(mmap),
            io_uring_mapping: Some(mapping),
            io_uring_mm: Some(mm),
            shmat: None,
        }
    }

    pub(crate) fn shmat(mmap: mem::HostAliasMmapCommit, shmat: sysv::HostAliasShmatCommit) -> Self {
        Self {
            mmap: Some(mmap),
            io_uring_mapping: None,
            io_uring_mm: None,
            shmat: Some(shmat),
        }
    }
}

pub(crate) enum HostAliasPhase {
    Idle,
    Dispatching,
    Pending {
        id: HostAliasTransactionId,
        commit: Option<HostAliasCommit>,
    },
    Installing {
        id: HostAliasTransactionId,
        commit: Option<HostAliasCommit>,
    },
}

pub(crate) struct HostAliasTransactions {
    pub(crate) phase: parking_lot::Mutex<HostAliasPhase>,
    pub(crate) idle: parking_lot::Condvar,
    pub(crate) next_id: std::sync::atomic::AtomicU64,
}

impl HostAliasTransactions {
    pub(crate) fn new() -> Self {
        Self {
            phase: parking_lot::Mutex::new(HostAliasPhase::Idle),
            idle: parking_lot::Condvar::new(),
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    pub(crate) fn begin_dispatch<'permit>(
        self: &Arc<Self>,
        permit: &'permit mm_mutation::HostAliasPermit<'_>,
        coordinator: &Arc<mm_mutation::MmMutationCoordinator>,
    ) -> HostAliasDispatchGuard<'permit> {
        let structural = coordinator.begin_alias(permit);
        let mut phase = self.phase.lock();
        while !matches!(*phase, HostAliasPhase::Idle) {
            self.idle.wait(&mut phase);
        }
        *phase = HostAliasPhase::Dispatching;
        HostAliasDispatchGuard {
            _structural: structural,
            authority: None,
            transactions: Arc::clone(self),
            active: true,
            vma_revision: None,
        }
    }

    pub(crate) fn abort_matching(&self, id: HostAliasTransactionId) {
        let mut phase = self.phase.lock();
        let matches = match &*phase {
            HostAliasPhase::Pending { id: found, .. }
            | HostAliasPhase::Installing { id: found, .. } => *found == id,
            HostAliasPhase::Idle | HostAliasPhase::Dispatching => false,
        };
        if matches {
            *phase = HostAliasPhase::Idle;
            self.idle.notify_all();
        }
    }

    pub(crate) fn with_non_dispatching_phase<R>(&self, publish: impl FnOnce() -> R) -> R {
        let mut phase = self.phase.lock();
        while matches!(*phase, HostAliasPhase::Dispatching) {
            self.idle.wait(&mut phase);
        }
        // Retain the phase lock across publication. An Idle predecessor cannot
        // admit a new dispatcher between the check and CAS, while Pending and
        // Installing deliberately do not block exec promotion.
        publish()
    }
}

pub(crate) struct HostAliasDispatchGuard<'permit> {
    pub(crate) _structural: mm_mutation::HostAliasCoordinatorGuard<'permit>,
    pub(crate) authority: Option<Arc<DispatchMmAuthority>>,
    pub(crate) transactions: Arc<HostAliasTransactions>,
    pub(crate) active: bool,
    pub(crate) vma_revision: Option<Arc<std::sync::atomic::AtomicU64>>,
}

impl HostAliasDispatchGuard<'_> {
    pub(crate) fn with_authority(mut self, authority: Arc<DispatchMmAuthority>) -> Self {
        if !Arc::ptr_eq(&authority.host_alias_transactions, &self.transactions) {
            carrick_fatal!(
                "dispatch::host_alias_transactions",
                "mismatched HostAliasTransactions reference on DispatchMmAuthority during with_authority"
            );
        }
        self.authority = Some(authority);
        self
    }

    pub(crate) fn with_vma_revision(mut self, revision: Arc<std::sync::atomic::AtomicU64>) -> Self {
        self.vma_revision = Some(revision);
        self
    }

    pub(crate) fn mark_vma_revision(&mut self, revision: Arc<std::sync::atomic::AtomicU64>) {
        self.vma_revision = Some(revision);
    }

    pub(crate) fn publish(mut self, commit: HostAliasCommit) -> HostAliasTransaction {
        // A publisher running under the SHARED native `:3440` dispatch guard
        // defers its install past that guard's release: the alias phase then
        // outlives the publisher's memory guard and the install must
        // re-acquire the exclusive guard while sibling mapping syscalls park
        // in `begin_dispatch` holding theirs — the hold-and-wait cycle behind
        // the 2026-08-06 policy-ON go-build wedge. Classify the syscall in
        // `native_syscall_mutates_mappings` instead so the install is consumed
        // in-dispatch under the exclusive guard. ABORT, do not panic: the
        // native lane's guest threads run with no panic backstop, so an
        // unwind here would tear through guest state (same fail-closed
        // contract as `install_native_host_alias`'s abort arms).

        let raw = self
            .transactions
            .next_id
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |id| id.checked_add(1),
            )
            .unwrap_or_else(|_| {
                carrick_fatal!(
                    "dispatch::host_alias_transactions",
                    "host-alias transaction id exhaustion"
                )
            });
        let id = HostAliasTransactionId(raw);
        let mut phase = self.transactions.phase.lock();
        debug_assert!(matches!(*phase, HostAliasPhase::Dispatching));
        *phase = HostAliasPhase::Pending {
            id,
            commit: Some(commit),
        };
        self.transactions.idle.notify_all();
        self.active = false;
        let authority = self.authority.take().unwrap_or_else(|| {
            tracing::error!("host-alias publication lacks MM authority");
            carrick_fatal!(
                "dispatch::host_alias_transactions",
                "host-alias publication lacks MM authority"
            );
        });
        HostAliasTransaction {
            authority,
            transactions: Arc::clone(&self.transactions),
            id,
            armed: true,
        }
    }
}

impl Drop for HostAliasDispatchGuard<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut phase = self.transactions.phase.lock();
        if matches!(*phase, HostAliasPhase::Dispatching) {
            if let Some(revision) = &self.vma_revision
                && revision.fetch_add(1, std::sync::atomic::Ordering::Release) == u64::MAX
            {
                carrick_fatal!(
                    "dispatch::mem_revision",
                    "vma revision atomic generation counter overflow"
                );
            }
            *phase = HostAliasPhase::Idle;
            self.transactions.idle.notify_all();
        }
    }
}

impl SyscallDispatcher {
    pub(crate) fn begin_host_alias_dispatch<'permit>(
        &self,
        permit: &'permit mm_mutation::HostAliasPermit<'_>,
    ) -> HostAliasDispatchGuard<'permit> {
        self.mm_binding.begin_dispatch(permit, false)
    }

    #[allow(dead_code)]
    pub(crate) fn begin_vma_dispatch<'permit>(
        &self,
        permit: &'permit mm_mutation::HostAliasPermit<'_>,
    ) -> HostAliasDispatchGuard<'permit> {
        self.mm_binding.begin_dispatch(permit, true)
    }

    pub(crate) fn begin_conditional_vma_dispatch<'permit>(
        &self,
        permit: &'permit mm_mutation::HostAliasPermit<'_>,
    ) -> HostAliasDispatchGuard<'permit> {
        self.mm_binding.begin_dispatch(permit, false)
    }

    #[cfg(test)]
    pub(crate) fn with_host_alias_dispatch_for_test<T>(
        &self,
        use_guard: impl FnOnce(HostAliasDispatchGuard<'_>) -> T,
    ) -> T {
        mm_mutation::test_support::with_permit(self.mm_mutation_coordinator(), |permit| {
            use_guard(self.begin_host_alias_dispatch(permit))
        })
    }

    #[cfg(test)]
    pub(crate) fn with_vma_dispatch_for_test<T>(
        &self,
        use_guard: impl FnOnce(HostAliasDispatchGuard<'_>) -> T,
    ) -> T {
        mm_mutation::test_support::with_permit(self.mm_mutation_coordinator(), |permit| {
            use_guard(self.begin_vma_dispatch(permit))
        })
    }

    #[cfg(test)]
    pub(crate) fn with_conditional_vma_dispatch_for_test<T>(
        &self,
        use_guard: impl FnOnce(HostAliasDispatchGuard<'_>) -> T,
    ) -> T {
        mm_mutation::test_support::with_permit(self.mm_mutation_coordinator(), |permit| {
            use_guard(self.begin_conditional_vma_dispatch(permit))
        })
    }

    pub(crate) fn mark_vma_dispatch(&self, guard: &mut HostAliasDispatchGuard) {
        let authority = guard.authority.as_ref().unwrap_or_else(|| {
            tracing::error!("VMA dispatch guard lacks MM authority");
            carrick_fatal!(
                "dispatch::mm_binding",
                "VMA dispatch guard lacks MM authority"
            );
        });
        guard.mark_vma_revision(authority.mem.revision_publisher());
    }

    pub(super) fn owns_host_alias_dispatch(&self, guard: &HostAliasDispatchGuard) -> bool {
        guard.authority.as_ref().is_some_and(|authority| {
            Arc::ptr_eq(&authority.host_alias_transactions, &guard.transactions)
        })
    }

    /// Publish exact range-owned metadata after the host alias and every
    /// required subrange protection are installed successfully.
    pub(crate) fn commit_host_alias_install(
        &self,
        mut install: HostAliasInstallGuard,
    ) -> Result<(), LinuxErrno> {
        let authority = Arc::clone(&install.authority);
        let transactions = Arc::clone(&authority.host_alias_transactions);
        if !Arc::ptr_eq(&transactions, &install.transactions) {
            return Err(LINUX_ENOMEM);
        }
        let mut phase = transactions.phase.lock();
        let HostAliasPhase::Installing {
            id: installing,
            commit,
        } = &mut *phase
        else {
            return Err(LINUX_ENOMEM);
        };
        if *installing != install.id {
            return Err(LINUX_ENOMEM);
        }
        let Some(commit) = commit.take() else {
            return Err(LINUX_ENOMEM);
        };

        if let Some(mmap) = commit.mmap {
            let start = mmap.start;
            let len = mmap.len;
            self.commit_host_alias_mmap_observed(&authority, mmap);
            if let Some(mm) = commit.io_uring_mm {
                mm.replace_io_uring_mappings(start, len, commit.io_uring_mapping);
            } else if commit.io_uring_mapping.is_some() {
                carrick_fatal!(
                    "dispatch::host_alias_commit",
                    "ring alias commit missing target Mm reference"
                );
            }
        }
        if let Some(shmat) = commit.shmat {
            self.commit_host_alias_shmat(shmat);
        }
        *phase = HostAliasPhase::Idle;
        transactions.idle.notify_all();
        install.disarm();
        Ok(())
    }
}
