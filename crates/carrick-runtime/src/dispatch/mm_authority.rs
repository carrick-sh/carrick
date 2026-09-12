//! MM authority and executor census participation for syscall dispatch.

use std::sync::Arc;

use carrick_fatal::carrick_fatal;
use parking_lot::Mutex;

use super::host_alias::{HostAliasDispatchGuard, HostAliasTransactions};
use super::outcome::DispatchError;
#[cfg(test)]
use super::{
    LinearMemory, LinuxErrno, ProcMapSharing, ProcMapsEntry, SyscallCtx, SyscallDispatcher,
    SyscallRequest,
};
use super::{mem, mm_mutation};

pub use super::mm_mutation::MmTransactionGuard;

/// Dispatcher-side authority for one Linux MM.
///
/// Every dispatcher still owns process-private signal, fd, proc, and control
/// state. Only Linux memory metadata and the host-alias transaction boundary
/// travel together here: `CLONE_VM` selects the same authority while a copied
/// MM receives an exact fork-private authority.
pub(crate) struct DispatchMmAuthority {
    pub(crate) mm_id: crate::kernel::MmId,
    pub(crate) mem: Arc<mem::MemAuthority>,
    pub(crate) host_alias_transactions: Arc<HostAliasTransactions>,
    pub(crate) mutation_coordinator: Arc<mm_mutation::MmMutationCoordinator>,
    pub(in crate::dispatch) guest_executors: Arc<crate::kernel::GuestExecutorCensus>,
    pub(in crate::dispatch) pt_quiesce: Arc<carrick_thread::fork_quiesce::PtQuiesce>,
    /// The `guest_realtime_epoch()` under which THIS MM's vvar
    /// `VVAR_OFF_REALTIME_OFF_NS` word was last stamped by the dispatcher
    /// (`SyscallDispatcher::sync_vvar_realtime_offset`). The vvar page is per
    /// MM (it also carries the per-process RNG generation), so the stamp state
    /// is MM state. `u64::MAX` = never.
    ///
    /// While the global epoch is still 0 — no guest has moved the clock in
    /// this carrier — an MM is left at `u64::MAX` and never stamped, because
    /// the VMM stamper's boot-time word is already correct and a re-stamp
    /// would write the same bytes. The first `clock_settime` advances the
    /// epoch past 0, and each MM then re-stamps once on its next syscall (or
    /// at the post-exec identity stamp): a single 8-byte write (a fork child's
    /// vvar frame is already COW-split by the HVPatch RNG-generation
    /// re-stamp, `trap.rs:11281`).
    pub(in crate::dispatch) vvar_realtime_epoch: std::sync::atomic::AtomicU64,
}

impl DispatchMmAuthority {
    pub(in crate::dispatch) fn new(mm_id: crate::kernel::MmId) -> Self {
        Self {
            mm_id,
            mem: Arc::new(mem::MemAuthority::new(mem::MemState::new())),
            host_alias_transactions: Arc::new(HostAliasTransactions::new()),
            mutation_coordinator: Arc::new(mm_mutation::MmMutationCoordinator::new(mm_id)),
            guest_executors: Arc::new(crate::kernel::GuestExecutorCensus::default()),
            pt_quiesce: Arc::new(carrick_thread::fork_quiesce::PtQuiesce::new()),
            vvar_realtime_epoch: std::sync::atomic::AtomicU64::new(u64::MAX),
        }
    }

    pub(in crate::dispatch) fn fork_private(&self, mm_id: crate::kernel::MmId) -> Self {
        Self {
            mm_id,
            mem: self.mem.fork_private(),
            host_alias_transactions: Arc::new(HostAliasTransactions::new()),
            mutation_coordinator: Arc::new(mm_mutation::MmMutationCoordinator::new(mm_id)),
            guest_executors: Arc::new(crate::kernel::GuestExecutorCensus::default()),
            pt_quiesce: Arc::new(carrick_thread::fork_quiesce::PtQuiesce::new()),
            vvar_realtime_epoch: std::sync::atomic::AtomicU64::new(u64::MAX),
        }
    }

    /// Re-key the prepared root dispatcher onto the MM identity committed by
    /// the carrier kernel graph.
    ///
    /// A dispatcher is assembled before carrier admission, so its mandatory
    /// one-task reference binding has an MM id from a throwaway kernel. The
    /// first carrier root happens to receive the same numeric id; later roots
    /// do not. Preserve the prepared VMA state, but mint every coordination
    /// object whose authority is defined by the exact committed MM.
    pub(in crate::dispatch) fn rebind_prepared_root(&self, mm_id: crate::kernel::MmId) -> Self {
        Self {
            mm_id,
            mem: Arc::clone(&self.mem),
            host_alias_transactions: Arc::new(HostAliasTransactions::new()),
            mutation_coordinator: Arc::new(mm_mutation::MmMutationCoordinator::new(mm_id)),
            guest_executors: Arc::new(crate::kernel::GuestExecutorCensus::default()),
            pt_quiesce: Arc::new(carrick_thread::fork_quiesce::PtQuiesce::new()),
            vvar_realtime_epoch: std::sync::atomic::AtomicU64::new(
                self.vvar_realtime_epoch
                    .load(std::sync::atomic::Ordering::Acquire),
            ),
        }
    }

    pub(in crate::dispatch) fn fork_private_with_policy(
        &self,
        mm_id: crate::kernel::MmId,
    ) -> Result<
        (
            Self,
            crate::kernel::VmaRevision,
            Arc<[carrick_hal::ForkProjectionRange]>,
        ),
        carrick_hal::ForkProjectionError,
    > {
        let (forked_mem, revision, ranges) = self.mem.fork_private_with_policy()?;
        Ok((
            Self {
                mm_id,
                mem: Arc::new(forked_mem),
                host_alias_transactions: Arc::new(HostAliasTransactions::new()),
                mutation_coordinator: Arc::new(mm_mutation::MmMutationCoordinator::new(mm_id)),
                guest_executors: Arc::new(crate::kernel::GuestExecutorCensus::default()),
                pt_quiesce: Arc::new(carrick_thread::fork_quiesce::PtQuiesce::new()),
                // Never stamped: the child inherits the parent's vvar content
                // through the COW split, and re-stamps on its next syscall
                // only once a `clock_settime` has moved the global epoch.
                vvar_realtime_epoch: std::sync::atomic::AtomicU64::new(u64::MAX),
            },
            revision,
            ranges,
        ))
    }

    pub(in crate::dispatch) fn fork_projection_with_revision(
        &self,
    ) -> Result<
        (
            crate::kernel::VmaRevision,
            Arc<[carrick_hal::ForkProjectionRange]>,
        ),
        carrick_hal::ForkProjectionError,
    > {
        self.mem.fork_projection_with_revision()
    }

    pub(in crate::dispatch) fn lock(&self) -> parking_lot::MutexGuard<'_, mem::MemState> {
        self.mem.lock()
    }

    pub(in crate::dispatch) fn revision_publisher(&self) -> Arc<std::sync::atomic::AtomicU64> {
        self.mem.revision_publisher()
    }

    pub(crate) fn vma_revision(&self) -> crate::kernel::VmaRevision {
        self.mem.vma_revision()
    }

    #[cfg(test)]
    pub(crate) fn new_for_test_with_revision(revision: crate::kernel::VmaRevision) -> Self {
        let mm_id = crate::kernel::MmId::from_registry_allocation(std::num::NonZeroU64::MIN);
        Self {
            mm_id,
            mem: Arc::new(mem::MemAuthority::with_revision(
                mem::MemState::new(),
                revision,
            )),
            host_alias_transactions: Arc::new(HostAliasTransactions::new()),
            mutation_coordinator: Arc::new(mm_mutation::MmMutationCoordinator::new(mm_id)),
            guest_executors: Arc::new(crate::kernel::GuestExecutorCensus::default()),
            pt_quiesce: Arc::new(carrick_thread::fork_quiesce::PtQuiesce::new()),
            vvar_realtime_epoch: std::sync::atomic::AtomicU64::new(u64::MAX),
        }
    }

    /// Production-shape MM authority for cross-layer foreign-COW tests. This
    /// uses the real dispatch VMA authority, mutation coordinator, and executor
    /// census; only the single test VMA is synthetic.
    #[cfg(test)]
    pub(crate) fn foreign_cow_composition_for_test(
        mm_id: crate::kernel::MmId,
        stage1: Arc<crate::hvpatch::Stage1MmLease>,
        start: u64,
        end: u64,
    ) -> (Arc<Self>, mm_mutation::ForeignMmMutationAuthority) {
        let authority = Arc::new(Self::new(mm_id));
        {
            let mut mem = authority.mem.lock();
            mem.dynamic_maps.push(ProcMapsEntry {
                start,
                end,
                read: true,
                write: true,
                execute: false,
                sharing: ProcMapSharing::Private,
                path: "[foreign-cow-composition]".to_owned(),
            });
        }
        authority.mem.bump_revision();
        let mutation = mm_mutation::ForeignMmMutationAuthority::new(
            mm_id,
            Arc::clone(&authority.mutation_coordinator),
            Arc::clone(&authority.guest_executors),
            stage1,
            Arc::clone(&authority.pt_quiesce),
        );
        (authority, mutation)
    }

    pub(crate) fn pt_quiesce(&self) -> &Arc<carrick_thread::fork_quiesce::PtQuiesce> {
        &self.pt_quiesce
    }

    #[cfg(test)]
    pub(crate) fn foreign_cow_executor_census_for_test(
        &self,
    ) -> Arc<crate::kernel::GuestExecutorCensus> {
        Arc::clone(&self.guest_executors)
    }

    #[cfg(test)]
    pub(crate) fn set_foreign_cow_vma_access_for_test(&self, access: crate::kernel::VmaAccess) {
        let mut mem = self.mem.lock();
        let vma = mem
            .dynamic_maps
            .iter_mut()
            .find(|vma| vma.path == "[foreign-cow-composition]")
            .expect("foreign COW composition VMA");
        vma.read = access.readable;
        vma.write = access.writable;
        vma.execute = access.executable;
        drop(mem);
        self.mem.bump_revision();
    }

    #[cfg(test)]
    pub(in crate::dispatch) fn snapshot_until(
        &self,
        deadline: std::time::Instant,
    ) -> Result<crate::kernel::OwnedVmaSnapshot, crate::kernel::SnapshotError> {
        self.mem.snapshot_until(deadline)
    }
}

/// Opaque participation in the executor census owned by one exact dispatch MM.
///
/// CLONE_VM dispatchers share the same [`DispatchMmAuthority`] and therefore
/// the same census. Holding this token says the caller may execute on that MM;
/// it does not itself grant mutation authority while a peer token exists.
pub struct MmExecutorParticipation {
    pub(in crate::dispatch) authority: Arc<DispatchMmAuthority>,
    pub(in crate::dispatch) admission: MmExecutorAdmissionRecipe,
    pub(in crate::dispatch) participation: Option<crate::kernel::GuestExecutorParticipation>,
}

#[derive(Clone)]
pub(in crate::dispatch) enum MmExecutorAdmissionRecipe {
    Anonymous,
    AnonymousWithPauseEndpoint {
        registry: Arc<dyn carrick_hal::VcpuRegistry>,
        tid: carrick_hal::ThreadId,
    },
    Thread {
        thread: crate::kernel::ThreadRef,
        registry: Arc<dyn carrick_hal::VcpuRegistry>,
        tid: carrick_hal::ThreadId,
    },
}

impl MmExecutorAdmissionRecipe {
    pub(in crate::dispatch) fn enter(
        &self,
        authority: &Arc<DispatchMmAuthority>,
    ) -> Result<crate::kernel::GuestExecutorParticipation, crate::kernel::GuestExecutorCensusError>
    {
        match self {
            Self::Anonymous => authority.guest_executors.enter(None),
            Self::AnonymousWithPauseEndpoint { registry, tid } => authority
                .guest_executors
                .enter_with_pause_endpoint(None, Arc::clone(registry), *tid),
            Self::Thread {
                thread,
                registry,
                tid,
            } => authority.guest_executors.enter_with_pause_endpoint(
                Some(thread.clone()),
                Arc::clone(registry),
                *tid,
            ),
        }
    }
}

impl MmExecutorParticipation {
    pub(crate) fn participation_mut(&mut self) -> &mut crate::kernel::GuestExecutorParticipation {
        self.participation.as_mut().unwrap_or_else(|| {
            tracing::error!("MM executor participation used while temporarily released");
            carrick_fatal!(
                "dispatch::mm_executor_participation",
                "MM executor participation used while temporarily released"
            )
        })
    }

    pub(crate) fn mm_id(&self) -> crate::kernel::MmId {
        self.authority.mm_id
    }

    pub(crate) fn mutation_coordinator(&self) -> Arc<mm_mutation::MmMutationCoordinator> {
        Arc::clone(&self.authority.mutation_coordinator)
    }

    pub(crate) fn pt_quiesce(&self) -> &Arc<carrick_thread::fork_quiesce::PtQuiesce> {
        self.authority.pt_quiesce()
    }

    pub(in crate::dispatch) fn authorizes(&self, authority: &Arc<DispatchMmAuthority>) -> bool {
        Arc::ptr_eq(&self.authority, authority)
    }

    pub(in crate::dispatch) fn validates_thread_identity(
        &self,
        thread: &crate::kernel::ThreadRef,
    ) -> bool {
        match &self.admission {
            MmExecutorAdmissionRecipe::Anonymous
            | MmExecutorAdmissionRecipe::AnonymousWithPauseEndpoint { .. } => true,
            MmExecutorAdmissionRecipe::Thread {
                thread: admitted, ..
            } => Arc::ptr_eq(admitted, thread),
        }
    }

    pub(in crate::dispatch) fn leave_temporarily(&mut self) -> Result<(), DispatchError> {
        let participation = self
            .participation
            .take()
            .ok_or(DispatchError::MmExecutorParticipationUnavailable)?;
        drop(participation);
        Ok(())
    }

    pub(in crate::dispatch) fn reenter_exact(
        &mut self,
    ) -> Result<(), crate::kernel::GuestExecutorCensusError> {
        if self.participation.is_some() {
            tracing::error!("MM executor re-entry attempted while participation is present");
            carrick_fatal!(
                "dispatch::mm_executor_participation",
                "MM executor re-entry attempted while participation is present"
            );
        }
        self.participation = Some(self.admission.enter(&self.authority)?);
        Ok(())
    }
}

#[cfg(test)]
mod mm_executor_release_tests {
    use std::sync::Arc;

    use carrick_hal::threaded::{Aarch64TaskCpuStateV1, GuestCpuState};

    use super::*;
    use crate::compat::{CompatReporter, SyscallArgs};
    use crate::kernel::objects::{ExecutorId, MigratableTaskState, ThreadExecutionLease};

    fn running_lease(context: &crate::kernel::KernelContext) -> ThreadExecutionLease {
        let mm = context.shared().mm().id();
        context
            .thread()
            .publish_initial_task_state(MigratableTaskState {
                cpu: GuestCpuState::from_aarch64_v1(Aarch64TaskCpuStateV1 {
                    gprs: [0; 31],
                    pc: 0,
                    pstate: 0,
                    trap_pc: 0,
                    trap_pstate: 0,
                    sp_el0: 0,
                    elr_el1: 0,
                    spsr_el1: 0,
                    ttbr0: 0,
                    ttbr1: 0,
                    tcr: 0,
                    sctlr_el1: 0,
                    mair_el1: 0,
                    vbar_el1: 0,
                    cpacr_el1: 0,
                    cntkctl_el1: 0,
                    tpidr_el1: 0,
                    actlr_el1: 0,
                    tpidr_el0: 0,
                    tpidrro_el0: 0,
                    contextidr_el1: 0,
                    vregs: [0; 32],
                    fpsr: 0,
                    fpcr: 0,
                    pending_resume_pc: None,
                    last_syscall_nr: Some(271),
                    last_syscall_orig_x0: 0,
                    last_fault_esr: 0,
                    last_exit_class: 0,
                    is_forked_child: false,
                    syscall_continuation: None,
                    mm_generation: mm.raw(),
                    asid_generation: mm.raw(),
                }),
                mm,
                asid_generation: mm.raw(),
            })
            .expect("publish task state");
        context
            .thread()
            .claim_runnable(
                ExecutorId::for_transitional_thread(carrick_hal::ThreadId::synthetic_for_tests(41))
                    .expect("transitional executor"),
            )
            .expect("claim running lease")
    }

    fn boundary_fixture() -> (
        SyscallDispatcher,
        crate::kernel::KernelContext,
        ThreadExecutionLease,
        MmExecutorParticipation,
        Arc<crate::kernel::GuestExecutorCensus>,
        carrick_hal::ThreadId,
    ) {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher
            .capture_one_task_context()
            .expect("capture dispatcher task");
        let lease = running_lease(&context);
        let tid = carrick_hal::ThreadId::synthetic_for_tests(41);
        let registry = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let endpoint: Arc<dyn carrick_hal::VcpuRegistry> = registry;
        let executor = dispatcher
            .enter_mm_executor_for_thread(Some(context.thread().clone()), endpoint, tid)
            .expect("admit exact MM executor");
        let census = dispatcher.mm_executor_census();
        (dispatcher, context, lease, executor, census, tid)
    }

    fn settle_fixture(
        context: &crate::kernel::KernelContext,
        lease: ThreadExecutionLease,
        executor: MmExecutorParticipation,
    ) {
        drop(executor);
        context
            .thread()
            .yield_from_executor(lease)
            .expect("settle execution lease");
    }

    #[test]
    fn caller_mm_executor_is_absent_during_operation_and_exact_identity_is_restored() {
        let (dispatcher, context, lease, mut executor, census, tid) = boundary_fixture();
        let reporter = CompatReporter::default();
        let mut memory = LinearMemory::new(0x1_0000, vec![0; 0x1000]);
        {
            let mut syscall = SyscallCtx {
                kernel: &context,
                request: SyscallRequest::new(271, SyscallArgs::from([0; 6])),
                memory: &mut memory,
                reporter: &reporter,
                thread: None,
                execution_lease: Some(&lease),
                mm_executor: Some(&mut executor),
            };

            let value = dispatcher
                .with_current_mm_executor_released(&mut syscall, || {
                    assert_eq!(census.participant_count_for_probe(), 0);
                    0x5eed_u64
                })
                .expect("release and restore exact caller MM executor");
            assert_eq!(value, 0x5eed);
        }
        assert_eq!(census.participant_count_for_probe(), 1);
        let exact = executor.participation_mut().lock_exact_mm();
        assert_eq!(exact.pause_endpoint_tids(), vec![tid]);
        drop(exact);
        context
            .thread()
            .validate_running_execution_lease(&lease)
            .expect("same execution lease remains running");

        settle_fixture(&context, lease, executor);
    }

    #[test]
    fn caller_mm_executor_is_restored_when_operation_returns_error() {
        let (dispatcher, context, lease, mut executor, census, _) = boundary_fixture();
        let reporter = CompatReporter::default();
        let mut memory = LinearMemory::new(0x1_0000, vec![0; 0x1000]);
        {
            let mut syscall = SyscallCtx {
                kernel: &context,
                request: SyscallRequest::new(271, SyscallArgs::from([0; 6])),
                memory: &mut memory,
                reporter: &reporter,
                thread: None,
                execution_lease: Some(&lease),
                mm_executor: Some(&mut executor),
            };

            let operation = dispatcher
                .with_current_mm_executor_released(&mut syscall, || {
                    assert_eq!(census.participant_count_for_probe(), 0);
                    Err::<(), LinuxErrno>(crate::linux_abi::LINUX_EFAULT)
                })
                .expect("boundary itself succeeds");
            assert_eq!(operation, Err(crate::linux_abi::LINUX_EFAULT));
        }
        assert_eq!(census.participant_count_for_probe(), 1);
        context
            .thread()
            .validate_running_execution_lease(&lease)
            .expect("same execution lease remains running");
        settle_fixture(&context, lease, executor);
    }

    #[test]
    fn caller_mm_executor_is_restored_before_operation_panic_resumes() {
        let (dispatcher, context, lease, mut executor, census, _) = boundary_fixture();
        let reporter = CompatReporter::default();
        let mut memory = LinearMemory::new(0x1_0000, vec![0; 0x1000]);
        {
            let mut syscall = SyscallCtx {
                kernel: &context,
                request: SyscallRequest::new(271, SyscallArgs::from([0; 6])),
                memory: &mut memory,
                reporter: &reporter,
                thread: None,
                execution_lease: Some(&lease),
                mm_executor: Some(&mut executor),
            };

            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = dispatcher.with_current_mm_executor_released(&mut syscall, || -> () {
                    assert_eq!(census.participant_count_for_probe(), 0);
                    panic!("injected operation panic");
                });
            }));
            assert!(panic.is_err(), "operation panic must resume after re-entry");
        }
        assert_eq!(census.participant_count_for_probe(), 1);
        context
            .thread()
            .validate_running_execution_lease(&lease)
            .expect("same execution lease remains running");
        settle_fixture(&context, lease, executor);
    }

    #[test]
    fn caller_mm_executor_reports_dispatcher_binding_drift_after_reentry() {
        let (dispatcher, context, lease, mut executor, census, _) = boundary_fixture();
        let original = dispatcher.mm_binding.current.load_full();
        let replacement = Arc::new(DispatchMmAuthority::new_for_test_with_revision(
            original.vma_revision(),
        ));
        let reporter = CompatReporter::default();
        let mut memory = LinearMemory::new(0x1_0000, vec![0; 0x1000]);
        {
            let mut syscall = SyscallCtx {
                kernel: &context,
                request: SyscallRequest::new(271, SyscallArgs::from([0; 6])),
                memory: &mut memory,
                reporter: &reporter,
                thread: None,
                execution_lease: Some(&lease),
                mm_executor: Some(&mut executor),
            };

            let error = dispatcher
                .with_current_mm_executor_released(&mut syscall, || {
                    assert_eq!(census.participant_count_for_probe(), 0);
                    dispatcher.replace_current_mm_for_test(replacement);
                })
                .expect_err("post-operation dispatcher binding drift must fail typed");
            assert!(matches!(error, DispatchError::MmExecutorBindingDrift));
        }
        assert_eq!(census.participant_count_for_probe(), 1);

        dispatcher.replace_current_mm_for_test(original);
        settle_fixture(&context, lease, executor);
    }
}

pub(crate) struct PreparedDispatchMmFork {
    pub(crate) parent_mm_id: crate::kernel::MmId,
    pub(crate) child_mm_id: crate::kernel::MmId,
    pub(crate) parent_mm: Arc<DispatchMmAuthority>,
    pub(crate) parent_revision: crate::kernel::VmaRevision,
    pub(crate) mode: crate::kernel::CloneObjectMode,
    pub(crate) child_mm: Arc<DispatchMmAuthority>,
    pub(crate) backend_plan: Arc<[carrick_hal::ForkProjectionRange]>,
}

impl PreparedDispatchMmFork {
    pub(crate) fn fork_projection_plan(&self) -> carrick_hal::ForkProjectionPlan {
        match self.mode {
            crate::kernel::CloneObjectMode::Share => carrick_hal::ForkProjectionPlan::Shared {
                parent_mm: self.parent_mm_id.raw(),
                ranges: Arc::clone(&self.backend_plan),
            },
            crate::kernel::CloneObjectMode::Copy => carrick_hal::ForkProjectionPlan::Copied {
                parent_mm: self.parent_mm_id.raw(),
                child_mm: self.child_mm_id.raw(),
                ranges: Arc::clone(&self.backend_plan),
            },
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PrepareDispatchMmForkError {
    #[error(transparent)]
    Projection(#[from] carrick_hal::ForkProjectionError),
    #[error("shared MM preparation requires identical parent and child MM identities")]
    SharedIdentityMismatch,
    #[error("copied MM preparation requires distinct parent and child MM identities")]
    CopiedIdentityCollision,
}

pub(crate) struct DispatchMmBinding {
    pub(in crate::dispatch) current: arc_swap::ArcSwap<DispatchMmAuthority>,
    pub(in crate::dispatch) staged_exec: Mutex<Option<Arc<DispatchMmAuthority>>>,
}

impl DispatchMmBinding {
    pub(in crate::dispatch) fn new(current: Arc<DispatchMmAuthority>) -> Arc<Self> {
        Arc::new(Self {
            current: arc_swap::ArcSwap::new(current),
            staged_exec: Mutex::new(None),
        })
    }

    pub(in crate::dispatch) fn stage_private_exec(
        self: &Arc<Self>,
        replacement_mm_id: crate::kernel::MmId,
    ) -> PreparedDispatchMmExec {
        // The replacement stays private until promotion. Snapshot the current
        // authority; the exec transaction validates its source revision before
        // publication, so this read-only preparation is not host-alias work.
        let current = self.current.load_full();
        let staged = Arc::new(current.fork_private(replacement_mm_id));
        let mut slot = self.staged_exec.lock();
        if slot.is_some() {
            tracing::error!("dispatcher already has a staged exec MM authority");
            carrick_fatal!(
                "dispatch::mm_binding",
                "dispatcher already has a staged exec MM authority"
            );
        }
        *slot = Some(Arc::clone(&staged));
        PreparedDispatchMmExec {
            binding: Arc::clone(self),
            predecessor: current,
            staged,
            committed: false,
        }
    }

    pub(in crate::dispatch) fn rebind_prepared_root(&self, mm_id: crate::kernel::MmId) {
        let staged = self.staged_exec.lock();
        if staged.is_some() {
            tracing::error!("cannot rebind a prepared root with a staged exec MM");
            carrick_fatal!(
                "dispatch::mm_binding",
                "cannot rebind a prepared root with a staged exec MM"
            );
        }
        let current = self.current.load_full();
        if current.mm_id != mm_id {
            self.current
                .store(Arc::new(current.rebind_prepared_root(mm_id)));
        }
    }

    pub(crate) fn begin_dispatch<'permit>(
        &self,
        permit: &'permit mm_mutation::HostAliasPermit<'_>,
        marks_vma: bool,
    ) -> HostAliasDispatchGuard<'permit> {
        loop {
            let authority = self.current.load_full();
            let guard = authority
                .host_alias_transactions
                .begin_dispatch(permit, &authority.mutation_coordinator)
                .with_authority(Arc::clone(&authority));
            if Arc::ptr_eq(&self.current.load_full(), &authority) {
                return if marks_vma {
                    guard.with_vma_revision(authority.mem.revision_publisher())
                } else {
                    guard
                };
            }
            // Promotion won after selection but before exclusion. Releasing
            // the stale guard and retrying prevents an old transaction from
            // ever pairing with the new authority's memory.
            drop(guard);
        }
    }

    /// Begin a host-alias dispatch phase on `expected` only if it is still the
    /// live authority AND `permit` was minted for it.
    ///
    /// `begin_dispatch` retries against whatever authority is current, which is
    /// right for a syscall whose permit came from the same executor turn. A
    /// fork install is different: its permit and its prepared parent were
    /// captured BEFORE the copy phase, so an exec promotion racing the copy
    /// leaves both stale. `MmMutationCoordinator::begin_alias` treats a
    /// permit for another MM as a broken authority chain and aborts the
    /// carrier; here staleness is an ordinary outcome, so it is reported as
    /// `None` and the caller lowers it to a retryable failure.
    pub(in crate::dispatch) fn begin_dispatch_for<'permit>(
        &self,
        permit: &'permit mm_mutation::HostAliasPermit<'_>,
        expected: &Arc<DispatchMmAuthority>,
    ) -> Option<HostAliasDispatchGuard<'permit>> {
        if !permit.authorizes(&expected.mutation_coordinator, expected.mm_id) {
            return None;
        }
        if !Arc::ptr_eq(&self.current.load_full(), expected) {
            return None;
        }
        let guard = expected
            .host_alias_transactions
            .begin_dispatch(permit, &expected.mutation_coordinator)
            .with_authority(Arc::clone(expected));
        if Arc::ptr_eq(&self.current.load_full(), expected) {
            Some(guard)
        } else {
            // Promotion won between selection and exclusion; the caller's
            // observation is stale, not merely delayed.
            drop(guard);
            None
        }
    }
}

pub(crate) struct PreparedDispatchMmExec {
    pub(in crate::dispatch) binding: Arc<DispatchMmBinding>,
    pub(in crate::dispatch) predecessor: Arc<DispatchMmAuthority>,
    pub(in crate::dispatch) staged: Arc<DispatchMmAuthority>,
    pub(in crate::dispatch) committed: bool,
}

impl PreparedDispatchMmExec {
    pub(crate) fn vma_snapshot_source(&self) -> crate::kernel::SharedVmaSnapshotSource {
        self.staged.clone()
    }

    pub(crate) fn commit(mut self) {
        let mut staged = self.binding.staged_exec.lock();
        if !staged
            .as_ref()
            .is_some_and(|candidate| Arc::ptr_eq(candidate, &self.staged))
        {
            tracing::error!("staged dispatcher exec MM authority changed before commit");
            carrick_fatal!(
                "dispatch::mm_exec_commit",
                "staged dispatcher exec MM authority changed before commit"
            );
        }
        let predecessor = self
            .predecessor
            .host_alias_transactions
            .with_non_dispatching_phase(|| {
                self.binding
                    .current
                    .compare_and_swap(&self.predecessor, Arc::clone(&self.staged))
            });
        if !Arc::ptr_eq(&predecessor, &self.predecessor) {
            tracing::error!("dispatcher exec MM predecessor changed before commit");
            carrick_fatal!(
                "dispatch::mm_exec_commit",
                "dispatcher exec MM predecessor changed before commit"
            );
        }
        *staged = None;
        self.committed = true;
    }
}

impl Drop for PreparedDispatchMmExec {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let mut staged = self.binding.staged_exec.lock();
        if staged
            .as_ref()
            .is_some_and(|candidate| Arc::ptr_eq(candidate, &self.staged))
        {
            *staged = None;
        }
    }
}

impl std::fmt::Debug for DispatchMmAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DispatchMmAuthority")
    }
}

impl crate::kernel::VmaSnapshotSource for DispatchMmAuthority {
    fn snapshot(
        &self,
        deadline: std::time::Instant,
    ) -> Result<crate::kernel::OwnedVmaSnapshot, crate::kernel::SnapshotError> {
        let _snapshot = self
            .mutation_coordinator
            .begin_snapshot_until(deadline)
            .ok_or_else(|| {
                if std::time::Instant::now() >= deadline {
                    crate::kernel::SnapshotError::TimedOut
                } else {
                    crate::kernel::SnapshotError::Busy
                }
            })?;
        self.mem.snapshot_until(deadline)
    }

    fn revision(&self) -> crate::kernel::VmaRevision {
        self.mem.vma_revision()
    }

    fn publish_if_revision(
        &self,
        expected: crate::kernel::VmaRevision,
        deadline: std::time::Instant,
        publish: &mut dyn FnMut() -> Result<(), crate::kernel::SnapshotError>,
    ) -> Result<(), crate::kernel::SnapshotError> {
        let _snapshot = self
            .mutation_coordinator
            .begin_snapshot_until(deadline)
            .ok_or_else(|| {
                if std::time::Instant::now() >= deadline {
                    crate::kernel::SnapshotError::TimedOut
                } else {
                    crate::kernel::SnapshotError::Busy
                }
            })?;
        if self.mem.vma_revision() != expected {
            return Err(crate::kernel::SnapshotError::ChangedDuringObservation);
        }
        publish()
    }
}

#[cfg(test)]
mod mm_transaction_tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    #[test]
    fn begin_transaction_increments_and_decrements_topology_depth() {
        let mm_id = crate::kernel::MmId::from_registry_allocation(
            std::num::NonZeroU64::new(42).expect("nonzero MM id"),
        );
        let coordinator = Arc::new(mm_mutation::MmMutationCoordinator::new(mm_id));
        assert_eq!(carrick_thread::fork_quiesce::topology_depth(), 0);
        assert!(carrick_thread::fork_quiesce::topology_depth_is_zero_for_executor_boundary());

        mm_mutation::test_support::with_guard(coordinator, |guard| {
            assert_eq!(carrick_thread::fork_quiesce::topology_depth(), 0);
            assert!(carrick_thread::fork_quiesce::topology_depth_is_zero_for_executor_boundary());
            {
                let tx = guard.begin_transaction();
                assert_eq!(carrick_thread::fork_quiesce::topology_depth(), 1);
                assert!(
                    !carrick_thread::fork_quiesce::topology_depth_is_zero_for_executor_boundary()
                );
                {
                    let tx_nested = guard.begin_transaction();
                    assert_eq!(carrick_thread::fork_quiesce::topology_depth(), 2);
                    assert!(
                        !carrick_thread::fork_quiesce::topology_depth_is_zero_for_executor_boundary(
                        )
                    );
                    drop(tx_nested);
                }
                assert_eq!(carrick_thread::fork_quiesce::topology_depth(), 1);
                assert!(
                    !carrick_thread::fork_quiesce::topology_depth_is_zero_for_executor_boundary()
                );
                drop(tx);
            }
            assert_eq!(carrick_thread::fork_quiesce::topology_depth(), 0);
            assert!(carrick_thread::fork_quiesce::topology_depth_is_zero_for_executor_boundary());
        });

        assert_eq!(carrick_thread::fork_quiesce::topology_depth(), 0);
        assert!(carrick_thread::fork_quiesce::topology_depth_is_zero_for_executor_boundary());
    }

    #[test]
    fn mm_transaction_guard_construction_is_only_begin_transaction() {
        fn visit_rs_files(root: &Path, current: &Path, files: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(current).expect("read directory") {
                let entry = entry.expect("directory entry");
                let path = entry.path();
                if path.is_dir() {
                    visit_rs_files(root, &path, files);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    files.push(path.strip_prefix(root).expect("strip prefix").to_owned());
                }
            }
        }

        let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates directory");
        let mut rs_files = Vec::new();
        visit_rs_files(crates_dir, crates_dir, &mut rs_files);
        assert!(
            !rs_files.is_empty(),
            "must find crate source files in workspace"
        );

        let struct_init_pattern = concat!("MmTransaction", "Guard {");
        let associated_call_pattern = concat!("MmTransaction", "Guard::");

        let mut observed_matches = BTreeSet::new();
        for relative in rs_files {
            let full_path = crates_dir.join(&relative);
            let content = std::fs::read_to_string(&full_path).expect("read source file");
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("//")
                    || trimmed.starts_with("/*")
                    || trimmed.starts_with('*')
                {
                    continue;
                }
                if line.contains(struct_init_pattern) || line.contains(associated_call_pattern) {
                    observed_matches
                        .insert((relative.to_string_lossy().into_owned(), trimmed.to_owned()));
                }
            }
        }

        let expected_matches = BTreeSet::from([(
            "carrick-runtime/src/dispatch/mm_mutation.rs".to_string(),
            concat!("MmTransaction", "Guard {").to_string(),
        )]);

        assert_eq!(
            observed_matches, expected_matches,
            "MmTransactionGuard must have exactly one construction path across workspace crates: MmMutationGuard::begin_transaction in mm_mutation.rs"
        );

        let mutation_source =
            std::fs::read_to_string(crates_dir.join("carrick-runtime/src/dispatch/mm_mutation.rs"))
                .expect("read mm_mutation.rs");
        let expected_snippet_lf = format!(
            "pub fn begin_transaction(&self) -> MmTransactionGuard<'_> {{\n        {struct_init_pattern}"
        );
        let expected_snippet_crlf = format!(
            "pub fn begin_transaction(&self) -> MmTransactionGuard<'_> {{\r\n        {struct_init_pattern}"
        );
        assert!(
            mutation_source.contains(&expected_snippet_lf)
                || mutation_source.contains(&expected_snippet_crlf),
            "MmTransactionGuard construction site must be inside MmMutationGuard::begin_transaction"
        );
    }
}
