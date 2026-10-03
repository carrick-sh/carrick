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

impl super::OwnerMmTopologyGuard<'_> {
    /// Compose task birth with an owner-built, still closed child root.
    pub fn fork_commit<'fork>(
        &'fork self,
        transaction: &'fork MmTransactionGuard<'_>,
        child: &'fork SyscallDispatcher,
    ) -> Result<ForkCommit<'fork>, ForkCommitRefusal> {
        let parent = &self.inner;
        if transaction.mm != Some(parent.mm) {
            return Err(ForkCommitRefusal::ForeignTransaction);
        }
        let authority = child.mm_authority();
        if authority.mm_id == parent.mm
            || Arc::ptr_eq(&authority.mutation_coordinator, &parent.coordinator)
        {
            return Err(ForkCommitRefusal::SharedMm);
        }
        if !child.mem_view().is_fork_twin_of(parent.mm) {
            return Err(ForkCommitRefusal::NotThisParentsChild);
        }
        if let Some(zone) = crate::el1_zone::zone() {
            let index = zone
                .spaces
                .find(authority.mm_id.raw())
                .ok_or(ForkCommitRefusal::ChildPublished)?;
            if zone.spaces.gate(index) != carrick_sched_core::GATE_CLOSED {
                return Err(ForkCommitRefusal::ChildPublished);
            }
        }
        Ok(ForkCommit {
            _parent: PhantomData,
            parent_coordinator: Arc::clone(&parent.coordinator),
            parent_mm: parent.mm,
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
    pub(crate) fn publish_child_address_space(
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
    /// ([`El1AdmissionOrigin::SetupForkCommit`]). `parent` is the dispatcher of
    /// the MM whose guard minted this commit.
    pub(crate) fn admit_child_root(
        &self,
        parent: &SyscallDispatcher,
    ) -> Result<El1Admission, Refusal> {
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
            El1AdmissionOrigin::SetupForkCommit {
                parent,
                parent_permit: &parent_permit,
            },
        )
    }

    /// Attach only the child's production owner Fork completion. Its root
    /// already contains owner-selected tables, VMAs and source identities.
    pub fn admit_owner_child_root(
        &self,
        parent: &SyscallDispatcher,
        completion: &carrick_el1_abi::PortalForkCompletion,
        inherited_sources: &[(core::num::NonZeroU64, core::num::NonZeroU64)],
    ) -> Result<El1Admission, Refusal> {
        let parent_permit = HostAliasPermit {
            coordinator: Arc::clone(&self.parent_coordinator),
            mm: self.parent_mm,
            guest_tid: None,
            _guard: PhantomData,
        };
        self.child.admit_el1_reservations(
            &self.child_permit(),
            El1AdmissionOrigin::OwnerForkCommit {
                parent,
                parent_permit: &parent_permit,
                completion,
                inherited_sources,
            },
        )
    }

    /// Publish the never-run child's address space, whose user root is
    /// `child_ttbr0`, and admit its reservation root seeded from the
    /// parent's committed root, as one step of the fork commit: the child is
    /// published only with its admission decided, before it can run, so its
    /// first load finds its address space already settled and never binds
    /// it as a fresh MM. `parent` is the dispatcher of the MM whose guard
    /// minted this commit.
    ///
    /// The child is switchable by guest EL1 exactly when its parent is: a
    /// copied MM keeps its parent's memory model, and an EL1-switchable
    /// address space installs its own root in both `TTBR0_EL1` and
    /// `TTBR1_EL1` (`Aarch64Vcpu::el1_switchable_roots`). `None`: the parent
    /// has no published address space, or the table refused the child.
    /// Every admission outcome fires `hvpatch-el1-root-admission`.
    pub fn publish_and_admit_child(
        &self,
        parent: &SyscallDispatcher,
        child_ttbr0: u64,
    ) -> Option<crate::kernel::AddressSpacePublication> {
        if parent.mem().lock().delegated_root().is_some() {
            return None;
        }
        if !crate::kernel::is_address_space_published(self.parent_mm) {
            return None;
        }
        let publication = self.publish_child_address_space(child_ttbr0, child_ttbr0)?;
        crate::dispatch::mem::el1_reservations::RootAdmission::of(self.admit_child_root(parent))
            .trace(
                self.child_mm,
                carrick_observability::probes::HvpatchEl1RootOrigin::ForkCommit,
            );
        Some(publication)
    }
}
