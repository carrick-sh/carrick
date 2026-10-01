//! The kernel authority of one copied-MM fork commit over its child MM.
//!
//! A fork child's MM has never run: no executor admitted it, no vCPU loaded
//! it, and its address space is not published. Its mutation authority is
//! therefore derived, not paused for: the parent's fork transaction (the
//! parent MM's mutation guard and the topology transaction it minted) is the
//! only way to name it. [`ForkCommit`] carries that derivation, so the
//! child's permit and the publication of its address space (and with it its
//! EL1 reservation root) exist only inside a fork commit:
//!
//! ```compile_fail
//! use carrick_kernel::dispatch::mm_mutation::ForkCommit;
//! fn forge<'a>(child: &'a carrick_kernel::dispatch::SyscallDispatcher) -> ForkCommit<'a> {
//!     ForkCommit { _parent: todo!(), parent_coordinator: todo!(), parent_mm: todo!(), child, child_coordinator: todo!(), child_mm: todo!(), _transaction: todo!() }
//! }
//! ```

use super::{HostAliasPermit, MmMutationCoordinator, MmMutationGuard, MmTransactionGuard};
use crate::dispatch::SyscallDispatcher;
use crate::dispatch::mem::el1_reservations::{El1Admission, El1AdmissionOrigin};
use crate::kernel::MmId;
use carrick_el1::memory::reservations::Refusal;
use std::marker::PhantomData;
use std::sync::Arc;

/// Why a fork commit could not be derived for a child MM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForkCommitRefusal {
    /// The transaction was not minted by this parent guard.
    ForeignTransaction,
    /// The "child" is the parent's own MM (a shared-MM clone has no child
    /// MM to commit).
    SharedMm,
    /// The child MM already published its address space: it may have run.
    ChildPublished,
    /// The child is not this parent's fork twin.
    NotThisParentsChild,
}

/// The authority of one copied-MM fork commit over its never-run child MM,
/// minted only by [`MmMutationGuard::fork_commit`] from the parent's
/// exact-MM mutation guard and the fork transaction it began.
pub struct ForkCommit<'fork> {
    /// Borrows the parent's guard and transaction for the whole commit.
    _parent: PhantomData<&'fork MmMutationGuard<'fork>>,
    parent_coordinator: Arc<MmMutationCoordinator>,
    parent_mm: MmId,
    child: &'fork SyscallDispatcher,
    child_coordinator: Arc<MmMutationCoordinator>,
    child_mm: MmId,
    _transaction: PhantomData<&'fork MmTransactionGuard<'fork>>,
}

impl MmMutationGuard<'_> {
    /// Derive the commit authority over `child`, the copied MM this guard's
    /// fork is committing. `transaction` must be the fork's topology
    /// transaction, begun from this guard; `child` must be this MM's fork
    /// twin whose address space was never published.
    pub fn fork_commit<'fork>(
        &'fork self,
        transaction: &'fork MmTransactionGuard<'_>,
        child: &'fork SyscallDispatcher,
    ) -> Result<ForkCommit<'fork>, ForkCommitRefusal> {
        if transaction.mm != Some(self.mm) {
            return Err(ForkCommitRefusal::ForeignTransaction);
        }
        let authority = child.mm_authority();
        if authority.mm_id == self.mm
            || Arc::ptr_eq(&authority.mutation_coordinator, &self.coordinator)
        {
            return Err(ForkCommitRefusal::SharedMm);
        }
        if authority.reservation_provider_published() {
            return Err(ForkCommitRefusal::ChildPublished);
        }
        if !child.mem_view().is_fork_twin_of(self.mm) {
            return Err(ForkCommitRefusal::NotThisParentsChild);
        }
        Ok(ForkCommit {
            _parent: PhantomData,
            parent_coordinator: Arc::clone(&self.coordinator),
            parent_mm: self.mm,
            child,
            child_coordinator: Arc::clone(&authority.mutation_coordinator),
            child_mm: authority.mm_id,
            _transaction: PhantomData,
        })
    }
}

impl ForkCommit<'_> {
    /// The child MM this commit covers.
    pub fn child_mm(&self) -> MmId {
        self.child_mm
    }

    /// The child MM's host-alias permit. Its MM never ran, so the parent's
    /// fork transaction excludes every other editor of it.
    pub fn child_permit(&self) -> HostAliasPermit<'_> {
        HostAliasPermit {
            coordinator: Arc::clone(&self.child_coordinator),
            mm: self.child_mm,
            guest_tid: None,
            _guard: PhantomData,
        }
    }

    /// Publish the child's address space, whose translation roots are
    /// `ttbr0` (the child's `Stage1MmLease` root) and `ttbr1`, for guest EL1
    /// to install, installing its EL1 reservation root with it: the same
    /// publication an MM's first load makes, taken here so the fork commit
    /// can admit the child's root before the child is published. `None`: no
    /// EL1 zone, or the publication was refused (the child then runs with
    /// its address space unpublished, as before).
    pub fn publish_child_address_space(
        &self,
        ttbr0: u64,
        ttbr1: u64,
    ) -> Option<crate::kernel::AddressSpacePublication> {
        self.child
            .mem_view()
            .publish_fork_child_address_space(ttbr0, ttbr1)
    }

    /// Admit the child's published root as the owner of its anonymous
    /// memory, seeded from the parent's committed root
    /// ([`El1AdmissionOrigin::ForkCommit`]). `parent` is the dispatcher of
    /// the MM whose guard minted this commit.
    pub fn admit_child_root(&self, parent: &SyscallDispatcher) -> Result<El1Admission, Refusal> {
        // The parent guard is borrowed for this commit's whole lifetime.
        let parent_permit = HostAliasPermit {
            coordinator: Arc::clone(&self.parent_coordinator),
            mm: self.parent_mm,
            guest_tid: None,
            _guard: PhantomData,
        };
        let permit = self.child_permit();
        self.child.admit_el1_reservations(
            &permit,
            El1AdmissionOrigin::ForkCommit {
                parent,
                parent_permit: &parent_permit,
            },
        )
    }
}
