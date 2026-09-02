use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::{Condvar, Mutex};

use super::asid::{AsidError, AsidGeneration, AsidLoad, AsidResidencyError};
use super::stage1_mm::{
    PreparedStage1Mm, PreparedStage1MmAbort, Stage1MmBackend, Stage1MmError, Stage1MmLease,
    Stage1MmPool, Stage1MmRetirement,
};
#[cfg(test)]
use crate::kernel::ThreadKey;
use crate::kernel::{Stage1RootError, TaskKey};

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExecOwnerObservation {
    owner_count: u32,
}

#[cfg(test)]
impl ExecOwnerObservation {
    pub(crate) const fn owner_count(self) -> u32 {
        self.owner_count
    }

    pub(crate) const fn final_owner(self) -> bool {
        self.owner_count == 1
    }
}

#[derive(Debug)]
pub(crate) struct RetiredStage1Mm {
    retirement: Option<Stage1MmRetirement>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error(
    "hvpatch exec reservation for task {reserving_task:?} already owns MM generation {generation:?}"
)]
pub(crate) struct ExecReservationConflict {
    pub(crate) reserving_task: TaskKey,
    pub(crate) generation: AsidGeneration,
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
struct ExecReservationId(u64);

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
struct ActiveExecReservation {
    id: Arc<ExecReservationId>,
    task: TaskKey,
    generation: AsidGeneration,
    predecessor: Arc<Stage1MmLease>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ExecReservationConstructionFailpoint {
    #[error("exec reservation construction failpoint is disabled")]
    Disabled,
    #[error("injected exec reservation failure after marker insertion")]
    AfterMarker,
    #[error("injected exec reservation failure after replacement allocation")]
    AfterReplacement,
}

#[cfg(test)]
#[derive(Debug)]
struct MmStateLinearizationHook {
    entered: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}

#[cfg(test)]
impl MmStateLinearizationHook {
    fn run(self) {
        self.entered.wait();
        self.release.wait();
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecConstructionRollbackStep {
    ReplacementSettled,
    MarkerCleared,
}

#[cfg(test)]
#[derive(Clone, Debug, Default)]
struct ExecConstructionRollbackTrace {
    steps: Arc<Mutex<Vec<ExecConstructionRollbackStep>>>,
}

#[cfg(test)]
impl ExecConstructionRollbackTrace {
    fn record(&self, step: ExecConstructionRollbackStep) {
        self.steps.lock().push(step);
    }

    fn snapshot(&self) -> Vec<ExecConstructionRollbackStep> {
        self.steps.lock().clone()
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecDispositionSettlementStep {
    ReplacementSettled,
    MarkerCleared,
}

#[cfg(test)]
#[derive(Clone, Debug, Default)]
struct ExecDispositionSettlementTrace {
    steps: Arc<Mutex<Vec<ExecDispositionSettlementStep>>>,
}

#[cfg(test)]
impl ExecDispositionSettlementTrace {
    fn record(&self, step: ExecDispositionSettlementStep) {
        self.steps.lock().push(step);
    }

    fn snapshot(&self) -> Vec<ExecDispositionSettlementStep> {
        self.steps.lock().clone()
    }
}

/// The topology decision pinned by an exec reservation.
///
/// This is deliberately exhaustive: consumers must route backend sharing and
/// retirement inventory from the reservation, never from a later owner count.
///
/// Pinning the decision does NOT touch the predecessor: a `RetireOldMm`
/// reservation leaves the old address space fully loadable until
/// [`ExecMmReservation::commit`]. The exec'ing thread parks and releases its
/// executor while its siblings drain (`ExecSiblingDrain`), so its executor
/// must be admitted back into the predecessor on resume; preparing the
/// retirement at reservation time refused that reload and externally settled
/// the exec owner as a silently exited thread. Linux orders it the same way:
/// the other threads die in the old mm first, then the mm is replaced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExecMmDispositionKind {
    RetainOldMm,
    RetireOldMm,
}

#[derive(Debug)]
enum ExecMmReservationState {
    Active {
        replacement: PreparedStage1Mm,
        disposition: ExecMmDispositionKind,
    },
    FailClosed,
    Settled,
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum ExecMmAbortReceipt {
    Retained {
        predecessor: Arc<Stage1MmLease>,
        replacement: AsidGeneration,
        settlement: PreparedStage1MmAbort,
    },
    RestoredFinal {
        predecessor: Arc<Stage1MmLease>,
        replacement: AsidGeneration,
        settlement: PreparedStage1MmAbort,
    },
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum ExecMmCommitReceipt {
    Retained {
        predecessor: Arc<Stage1MmLease>,
        replacement: Arc<Stage1MmLease>,
    },
    Retired {
        retirement: Stage1MmRetirement,
        replacement: Arc<Stage1MmLease>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum ExecReservationMismatch {
    #[error("exec MM reservation marker is missing")]
    MarkerMissing,
    #[error("exec MM reservation ID does not match its active marker")]
    ReservationId,
    #[error("exec MM reservation task does not match its active marker")]
    Task,
    #[error("exec MM reservation generation does not match its active marker")]
    Generation,
    #[error("exec MM reservation predecessor does not match its active marker")]
    Predecessor,
    #[error("exec MM reservation task edge no longer owns its exact predecessor")]
    TaskEdge,
    #[error("exec MM replacement lease and backend bindings disagree")]
    ReplacementBinding,
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct ExecMmReservation {
    resources: Arc<MmResources>,
    id: Arc<ExecReservationId>,
    task: TaskKey,
    predecessor: Arc<Stage1MmLease>,
    generation: AsidGeneration,
    state: ExecMmReservationState,
    #[cfg(test)]
    settlement_trace: Option<ExecDispositionSettlementTrace>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl ExecMmReservation {
    #[cfg(test)]
    fn record_settlement(&self, step: ExecDispositionSettlementStep) {
        if let Some(trace) = self.settlement_trace.as_ref() {
            trace.record(step);
        }
    }

    fn validate(&self, state: &MmResourceState) -> Result<(), MmResourcesError> {
        let marker = state
            .exec_reservations
            .get(&self.generation)
            .ok_or(ExecReservationMismatch::MarkerMissing)?;
        if !Arc::ptr_eq(&marker.id, &self.id) {
            return Err(ExecReservationMismatch::ReservationId.into());
        }
        if marker.task != self.task {
            return Err(ExecReservationMismatch::Task.into());
        }
        if marker.generation != self.generation {
            return Err(ExecReservationMismatch::Generation.into());
        }
        if !Arc::ptr_eq(&marker.predecessor, &self.predecessor) {
            return Err(ExecReservationMismatch::Predecessor.into());
        }
        if !state
            .leases
            .get(&self.task)
            .is_some_and(|lease| Arc::ptr_eq(lease, &self.predecessor))
        {
            return Err(ExecReservationMismatch::TaskEdge.into());
        }
        Ok(())
    }

    fn active(&self) -> (&PreparedStage1Mm, ExecMmDispositionKind) {
        match &self.state {
            ExecMmReservationState::Active {
                replacement,
                disposition,
            } => (replacement, *disposition),
            ExecMmReservationState::FailClosed | ExecMmReservationState::Settled => {
                std::process::abort()
            }
        }
    }

    pub(crate) fn replacement_asid_generation(&self) -> AsidGeneration {
        self.active().0.asid_generation()
    }

    pub(crate) fn disposition(&self) -> ExecMmDispositionKind {
        self.active().1
    }

    pub(crate) fn replacement_backend(&self) -> Arc<Stage1MmBackend> {
        self.active().0.backend()
    }

    pub(crate) fn predecessor_backend(&self) -> Arc<Stage1MmBackend> {
        self.predecessor.backend()
    }

    pub(crate) fn replacement_root_slot(&self) -> Option<super::stage1_mm::Stage1RootSlot> {
        self.active().0.root_slot()
    }

    pub(crate) fn begin_replacement_asid_load(
        &self,
        executor: crate::kernel::objects::ExecutorId,
    ) -> Result<AsidLoad, AsidResidencyError> {
        self.active().0.begin_asid_load(executor)
    }

    pub(crate) fn abort(mut self) -> Result<ExecMmAbortReceipt, MmResourcesError> {
        let mut resources_state = self.resources.state.lock();
        self.validate(&resources_state)?;
        let state = std::mem::replace(&mut self.state, ExecMmReservationState::Settled);
        let ExecMmReservationState::Active {
            replacement,
            disposition,
        } = state
        else {
            std::process::abort();
        };
        let replacement_generation = replacement.asid_generation();
        let settlement = match replacement.abort() {
            Ok(settlement) => settlement,
            Err(error) => {
                self.state = ExecMmReservationState::FailClosed;
                return Err(error.into());
            }
        };
        #[cfg(test)]
        self.record_settlement(ExecDispositionSettlementStep::ReplacementSettled);
        // The predecessor was never touched by the reservation, so both
        // dispositions restore by merely dropping the replacement.
        let receipt = match disposition {
            ExecMmDispositionKind::RetainOldMm => ExecMmAbortReceipt::Retained {
                predecessor: Arc::clone(&self.predecessor),
                replacement: replacement_generation,
                settlement,
            },
            ExecMmDispositionKind::RetireOldMm => ExecMmAbortReceipt::RestoredFinal {
                predecessor: Arc::clone(&self.predecessor),
                replacement: replacement_generation,
                settlement,
            },
        };
        let removed = self
            .resources
            .clear_exec_reservation(&mut resources_state, self.generation);
        assert!(
            removed.is_some(),
            "validated exec reservation marker vanished"
        );
        #[cfg(test)]
        self.record_settlement(ExecDispositionSettlementStep::MarkerCleared);
        drop(resources_state);
        Ok(receipt)
    }

    pub(crate) fn commit(
        mut self,
        stage1_root: u64,
    ) -> Result<ExecMmCommitReceipt, MmResourcesError> {
        let mut resources_state = self.resources.state.lock();
        self.validate(&resources_state)?;
        // Close the predecessor's load gate only now, after the sibling drain:
        // its `pending` residency snapshot must name the executors that are
        // resident at the moment the address space is actually replaced. An
        // early return past this point drops the preparation and reopens the
        // predecessor, so the reservation stays abortable.
        let predecessor_retirement = match self.active().1 {
            ExecMmDispositionKind::RetainOldMm => None,
            ExecMmDispositionKind::RetireOldMm => Some(
                self.resources
                    .mm_pool
                    .prepare_retirement(&self.predecessor)?,
            ),
        };
        let replacement_binding = self.active().0.publish_stage1_root(stage1_root)?;
        let replacement_backend = self.active().0.backend();
        replacement_backend.publish_binding(replacement_binding);
        if replacement_backend.binding() != replacement_binding {
            return Err(ExecReservationMismatch::ReplacementBinding.into());
        }

        let state = std::mem::replace(&mut self.state, ExecMmReservationState::Settled);
        let ExecMmReservationState::Active { replacement, .. } = state else {
            std::process::abort();
        };
        let replacement = replacement.commit();
        let receipt = match predecessor_retirement {
            None => ExecMmCommitReceipt::Retained {
                predecessor: Arc::clone(&self.predecessor),
                replacement: Arc::clone(&replacement),
            },
            Some(retirement) => ExecMmCommitReceipt::Retired {
                retirement: retirement.commit(),
                replacement: Arc::clone(&replacement),
            },
        };
        let predecessor = resources_state.leases.insert(self.task, replacement);
        assert!(
            predecessor
                .as_ref()
                .is_some_and(|lease| Arc::ptr_eq(lease, &self.predecessor)),
            "validated exec reservation task edge changed under state authority"
        );
        let removed = self
            .resources
            .clear_exec_reservation(&mut resources_state, self.generation);
        assert!(
            removed.is_some(),
            "validated exec reservation marker vanished"
        );
        drop(resources_state);
        Ok(receipt)
    }
}

impl Drop for ExecMmReservation {
    fn drop(&mut self) {
        let reservation_state = std::mem::replace(&mut self.state, ExecMmReservationState::Settled);
        match reservation_state {
            ExecMmReservationState::Settled | ExecMmReservationState::FailClosed => {}
            ExecMmReservationState::Active { replacement, .. } => {
                let mut resources_state = self.resources.state.lock();
                let marker_matches = self.validate(&resources_state).is_ok();
                match replacement.abort() {
                    Ok(PreparedStage1MmAbort::Unpublished { .. }) => {}
                    Ok(PreparedStage1MmAbort::Retirement(retirement)) => {
                        std::mem::forget(retirement);
                    }
                    Err(error) => {
                        tracing::error!(%error, "failed to settle dropped exec MM replacement");
                        return;
                    }
                }
                #[cfg(test)]
                self.record_settlement(ExecDispositionSettlementStep::ReplacementSettled);
                if marker_matches {
                    self.resources
                        .clear_exec_reservation(&mut resources_state, self.generation);
                    #[cfg(test)]
                    self.record_settlement(ExecDispositionSettlementStep::MarkerCleared);
                } else {
                    tracing::error!(
                        task = ?self.task,
                        generation = ?self.generation,
                        reservation_id = self.id.0,
                        "exec MM reservation identity mismatch during drop; leaving marker fail-closed"
                    );
                }
            }
        }
    }
}

impl RetiredStage1Mm {
    pub(crate) fn retirement(&self) -> Option<&Stage1MmRetirement> {
        self.retirement.as_ref()
    }

    pub(crate) fn complete(self) -> Result<(), MmResourcesError> {
        match self.retirement {
            Some(retirement) => retirement.complete().map_err(Into::into),
            None => Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum MmResourcesError {
    #[error("guest task generation {0:?} has no live hvpatch address space")]
    UnknownTask(TaskKey),
    #[error("guest task generation {0:?} already owns or retired an address space")]
    DuplicateTask(TaskKey),
    #[error("the prepared root address space was already published")]
    RootAlreadyPublished,
    #[error("guest ASID space is exhausted")]
    AsidExhausted,
    #[error(transparent)]
    Asid(AsidError),
    #[error(transparent)]
    Stage1Root(#[from] Stage1RootError),
    #[error("all hvpatch stage-1 root slots are live or awaiting TLB-safe reuse")]
    RootSlotExhausted,
    #[error("hvpatch stage-1 mm retirement still awaits executor invalidation")]
    RetirementIncomplete,
    #[error(transparent)]
    ExecReservationConflict(#[from] ExecReservationConflict),
    #[error(transparent)]
    ExecReservationMismatch(#[from] ExecReservationMismatch),
    #[error(transparent)]
    #[cfg(test)]
    InjectedExecReservationFailure(ExecReservationConstructionFailpoint),
    #[error(transparent)]
    Residency(#[from] AsidResidencyError),
}

impl From<AsidError> for MmResourcesError {
    fn from(error: AsidError) -> Self {
        match error {
            AsidError::Exhausted => Self::AsidExhausted,
            other => Self::Asid(other),
        }
    }
}

impl From<Stage1MmError> for MmResourcesError {
    fn from(error: Stage1MmError) -> Self {
        match error {
            Stage1MmError::AsidExhausted => Self::AsidExhausted,
            Stage1MmError::Asid(error) => Self::Asid(error),
            Stage1MmError::Stage1Root(error) => Self::Stage1Root(error),
            Stage1MmError::RootSlotExhausted | Stage1MmError::Retired => Self::RootSlotExhausted,
            Stage1MmError::RetirementIncomplete => Self::RetirementIncomplete,
            Stage1MmError::Residency(error) => Self::Residency(error),
        }
    }
}

/// Backend-only ownership for HVPatch ASIDs and stage-1 root slots.
///
/// Linux task identity, parentage, groups, sessions, exits, waits, and pidfd
/// readiness live exclusively in [`crate::kernel::Kernel`]. This table retains
/// only the prototype root-slot/ASID leases that K2 will replace.
#[derive(Debug, Default)]
struct MmResourceState {
    leases: BTreeMap<TaskKey, Arc<Stage1MmLease>>,
    exec_reservations: BTreeMap<AsidGeneration, ActiveExecReservation>,
    /// Permanent within one runtime: exact-generation tombstones make delayed
    /// duplicate cleanup idempotent without permitting a reused numeric PID to
    /// target its successor's root-slot/ASID lease.
    retired: BTreeSet<TaskKey>,
}

#[derive(Debug)]
pub(crate) struct MmResources {
    state: Mutex<MmResourceState>,
    exec_reservation_settled: Condvar,
    pending_root: Mutex<Option<Arc<Stage1MmLease>>>,
    mm_pool: Stage1MmPool,
    #[cfg_attr(not(test), allow(dead_code))]
    next_exec_reservation: AtomicU64,
}

impl MmResources {
    fn clear_exec_reservation(
        &self,
        state: &mut MmResourceState,
        generation: AsidGeneration,
    ) -> Option<ActiveExecReservation> {
        let removed = state.exec_reservations.remove(&generation);
        if removed.is_some() {
            self.exec_reservation_settled.notify_all();
        }
        removed
    }

    fn owner_count(state: &MmResourceState, lease: &Arc<Stage1MmLease>) -> u32 {
        u32::try_from(
            state
                .leases
                .values()
                .filter(|candidate| Arc::ptr_eq(candidate, lease))
                .count(),
        )
        .unwrap_or_else(|_| std::process::abort())
    }

    fn exec_conflict(
        state: &MmResourceState,
        lease: &Arc<Stage1MmLease>,
    ) -> Option<ExecReservationConflict> {
        state
            .exec_reservations
            .get(&lease.asid_generation())
            .map(|marker| ExecReservationConflict {
                reserving_task: marker.task,
                generation: marker.generation,
            })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn settle_failed_exec_replacement(
        replacement: PreparedStage1Mm,
    ) -> Result<(), MmResourcesError> {
        match replacement.abort()? {
            PreparedStage1MmAbort::Unpublished { .. } => Ok(()),
            PreparedStage1MmAbort::Retirement(retirement) => {
                // Construction has no receipt owner able to acknowledge a
                // hardware-exposed replacement. Quarantine it permanently.
                std::mem::forget(retirement);
                Ok(())
            }
        }
    }

    fn publish_lifecycle(
        phase: carrick_observability::probes::HvpatchMmLeasePhase,
        task: TaskKey,
        lease: &Stage1MmLease,
        owner_count: u32,
    ) {
        let event = carrick_observability::probes::HvpatchMmLeaseLifecycle::new(
            phase,
            task.id.raw(),
            task.serial.raw(),
            u32::from(lease.binding().asid.raw()),
            owner_count,
        )
        .unwrap_or_else(|_| std::process::abort());
        crate::probes::hvpatch_mm_lease_lifecycle(event);
    }

    fn publish_relation(
        phase: carrick_observability::probes::HvpatchMmLeasePhase,
        task: TaskKey,
        related_pid: i32,
        related_serial: u64,
    ) {
        let event = carrick_observability::probes::HvpatchMmLeaseRelation::new(
            phase,
            task.serial.raw(),
            related_pid,
            related_serial,
        )
        .unwrap_or_else(|_| std::process::abort());
        crate::probes::hvpatch_mm_lease_relation(event);
    }

    pub(crate) fn new_root(
        stage1_root: u64,
    ) -> Result<(Self, Arc<Stage1MmBackend>), MmResourcesError> {
        let (mm_pool, root_mm) = Stage1MmPool::new_root(stage1_root)?;
        let backend = root_mm.backend();
        Ok((
            Self {
                state: Mutex::new(MmResourceState::default()),
                exec_reservation_settled: Condvar::new(),
                pending_root: Mutex::new(Some(root_mm)),
                mm_pool,
                next_exec_reservation: AtomicU64::new(1),
            },
            backend,
        ))
    }

    pub(crate) fn publish_root(&self, root: TaskKey) -> Result<(), MmResourcesError> {
        let mut state = self.state.lock();
        if state.leases.contains_key(&root) || state.retired.contains(&root) {
            return Err(MmResourcesError::DuplicateTask(root));
        }
        let lease = self
            .pending_root
            .lock()
            .take()
            .ok_or(MmResourcesError::RootAlreadyPublished)?;
        state.leases.insert(root, lease);
        Ok(())
    }

    #[cfg(test)]
    fn new_for_tests(
        stage1_root: u64,
        asid_limit: u16,
    ) -> Result<(Self, Arc<Stage1MmBackend>), MmResourcesError> {
        let (mm_pool, root_mm) = Stage1MmPool::new_root_for_tests(stage1_root, asid_limit)?;
        let backend = root_mm.backend();
        Ok((
            Self {
                state: Mutex::new(MmResourceState::default()),
                exec_reservation_settled: Condvar::new(),
                pending_root: Mutex::new(Some(root_mm)),
                mm_pool,
                next_exec_reservation: AtomicU64::new(1),
            },
            backend,
        ))
    }

    pub(crate) fn prepare_child(&self) -> Result<PreparedStage1Mm, MmResourcesError> {
        self.mm_pool.prepare_child().map_err(Into::into)
    }

    pub(crate) fn publish_child(
        &self,
        task: TaskKey,
        prepared: PreparedStage1Mm,
    ) -> Result<Arc<Stage1MmBackend>, MmResourcesError> {
        let mut state = self.state.lock();
        if state.leases.contains_key(&task) || state.retired.contains(&task) {
            return Err(MmResourcesError::DuplicateTask(task));
        }
        // Commit only after the exact-generation vacancy check. On rejection,
        // dropping `prepared` returns its ASID/root-slot reservation to the pool.
        let lease = prepared.commit();
        let backend = lease.backend();
        state.leases.insert(task, lease);
        Ok(backend)
    }

    pub(crate) fn publish_shared_child(
        &self,
        parent: TaskKey,
        child: TaskKey,
    ) -> Result<Arc<Stage1MmBackend>, MmResourcesError> {
        let mut state = self.state.lock();
        self.publish_shared_child_locked(&mut state, parent, child)
    }

    #[cfg(test)]
    fn publish_shared_child_with_state_hook_for_tests(
        &self,
        parent: TaskKey,
        child: TaskKey,
        hook: MmStateLinearizationHook,
    ) -> Result<Arc<Stage1MmBackend>, MmResourcesError> {
        let mut state = self.state.lock();
        hook.run();
        self.publish_shared_child_locked(&mut state, parent, child)
    }

    fn publish_shared_child_locked(
        &self,
        state: &mut MmResourceState,
        parent: TaskKey,
        child: TaskKey,
    ) -> Result<Arc<Stage1MmBackend>, MmResourcesError> {
        if state.leases.contains_key(&child) || state.retired.contains(&child) {
            return Err(MmResourcesError::DuplicateTask(child));
        }
        let lease = state
            .leases
            .get(&parent)
            .cloned()
            .ok_or(MmResourcesError::UnknownTask(parent))?;
        if let Some(conflict) = Self::exec_conflict(state, &lease) {
            return Err(conflict.into());
        }
        let backend = lease.backend();
        state.leases.insert(child, Arc::clone(&lease));
        let owner_count = Self::owner_count(state, &lease);
        Self::publish_relation(
            carrick_observability::probes::HvpatchMmLeasePhase::SharedChildPublished,
            child,
            parent.id.raw(),
            parent.serial.raw(),
        );
        Self::publish_lifecycle(
            carrick_observability::probes::HvpatchMmLeasePhase::SharedChildPublished,
            child,
            &lease,
            owner_count,
        );
        Ok(backend)
    }

    pub(crate) fn root_slot(&self, task: TaskKey) -> Option<super::stage1_mm::Stage1RootSlot> {
        self.state
            .lock()
            .leases
            .get(&task)
            .and_then(|lease| lease.root_slot())
    }

    pub(crate) fn lease(&self, task: TaskKey) -> Result<Arc<Stage1MmLease>, MmResourcesError> {
        self.state
            .lock()
            .leases
            .get(&task)
            .cloned()
            .ok_or(MmResourcesError::UnknownTask(task))
    }

    pub(crate) fn is_final_owner(&self, task: TaskKey) -> Result<bool, MmResourcesError> {
        let state = self.state.lock();
        let lease = state
            .leases
            .get(&task)
            .ok_or(MmResourcesError::UnknownTask(task))?;
        Ok(!state
            .leases
            .iter()
            .any(|(other, candidate)| *other != task && Arc::ptr_eq(candidate, lease)))
    }

    #[cfg(test)]
    pub(crate) fn observe_exec_owners(
        &self,
        task: TaskKey,
        thread: ThreadKey,
    ) -> Result<ExecOwnerObservation, MmResourcesError> {
        let state = self.state.lock();
        let lease = state
            .leases
            .get(&task)
            .ok_or(MmResourcesError::UnknownTask(task))?;
        let owner_count = Self::owner_count(&state, lease);
        Self::publish_relation(
            carrick_observability::probes::HvpatchMmLeasePhase::ExecObserved,
            task,
            thread.tid.raw(),
            thread.serial.raw(),
        );
        Self::publish_lifecycle(
            carrick_observability::probes::HvpatchMmLeasePhase::ExecObserved,
            task,
            lease,
            owner_count,
        );
        Ok(ExecOwnerObservation { owner_count })
    }

    #[cfg(test)]
    pub(crate) fn prepare_exec(&self, task: TaskKey) -> Result<PreparedStage1Mm, MmResourcesError> {
        let state = self.state.lock();
        let predecessor = state
            .leases
            .get(&task)
            .ok_or(MmResourcesError::UnknownTask(task))?;
        if let Some(conflict) = Self::exec_conflict(&state, predecessor) {
            return Err(conflict.into());
        }
        drop(state);
        self.mm_pool.prepare_child().map_err(Into::into)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn reserve_exec(
        self: &Arc<Self>,
        task: TaskKey,
    ) -> Result<ExecMmReservation, MmResourcesError> {
        #[cfg(not(test))]
        {
            self.reserve_exec_inner(task, false)
        }
        #[cfg(test)]
        {
            self.reserve_exec_inner(
                task,
                false,
                ExecReservationConstructionFailpoint::Disabled,
                None,
                None,
            )
        }
    }

    /// Acquire the exact MM-generation exec reservation, waiting for a
    /// distinct task's in-flight exec on the same shared MM to settle.
    ///
    /// The task edge and owner disposition are recomputed after every wake
    /// while holding MM-resource authority. The returned reservation remains
    /// the sole marker owner until its abort, commit, or drop settlement.
    pub(crate) fn reserve_exec_eventual(
        self: &Arc<Self>,
        task: TaskKey,
    ) -> Result<ExecMmReservation, MmResourcesError> {
        #[cfg(not(test))]
        {
            self.reserve_exec_inner(task, true)
        }
        #[cfg(test)]
        {
            self.reserve_exec_inner(
                task,
                true,
                ExecReservationConstructionFailpoint::Disabled,
                None,
                None,
            )
        }
    }

    #[cfg(test)]
    fn reserve_exec_with_failpoint_for_tests(
        self: &Arc<Self>,
        task: TaskKey,
        failpoint: ExecReservationConstructionFailpoint,
    ) -> Result<ExecMmReservation, MmResourcesError> {
        self.reserve_exec_inner(task, false, failpoint, None, None)
    }

    #[cfg(test)]
    fn reserve_exec_with_failpoint_and_trace_for_tests(
        self: &Arc<Self>,
        task: TaskKey,
        failpoint: ExecReservationConstructionFailpoint,
        trace: ExecConstructionRollbackTrace,
    ) -> Result<ExecMmReservation, MmResourcesError> {
        self.reserve_exec_inner(task, false, failpoint, None, Some(trace))
    }

    #[cfg(test)]
    fn reserve_exec_with_state_hook_for_tests(
        self: &Arc<Self>,
        task: TaskKey,
        hook: MmStateLinearizationHook,
    ) -> Result<ExecMmReservation, MmResourcesError> {
        self.reserve_exec_inner(
            task,
            false,
            ExecReservationConstructionFailpoint::Disabled,
            Some(hook),
            None,
        )
    }

    #[cfg(test)]
    fn reserve_exec_with_settlement_trace_for_tests(
        self: &Arc<Self>,
        task: TaskKey,
        trace: ExecDispositionSettlementTrace,
    ) -> Result<ExecMmReservation, MmResourcesError> {
        let mut reservation = self.reserve_exec(task)?;
        reservation.settlement_trace = Some(trace);
        Ok(reservation)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn reserve_exec_inner(
        self: &Arc<Self>,
        task: TaskKey,
        wait_for_conflict: bool,
        #[cfg(test)] failpoint: ExecReservationConstructionFailpoint,
        #[cfg(test)] hook: Option<MmStateLinearizationHook>,
        #[cfg(test)] rollback_trace: Option<ExecConstructionRollbackTrace>,
    ) -> Result<ExecMmReservation, MmResourcesError> {
        let mut state = self.state.lock();
        #[cfg(test)]
        if let Some(hook) = hook {
            hook.run();
        }
        let predecessor = loop {
            let predecessor = state
                .leases
                .get(&task)
                .cloned()
                .ok_or(MmResourcesError::UnknownTask(task))?;
            let generation = predecessor.asid_generation();
            let Some(marker) = state.exec_reservations.get(&generation) else {
                break predecessor;
            };
            if !wait_for_conflict || marker.task == task {
                return Err(ExecReservationConflict {
                    reserving_task: marker.task,
                    generation,
                }
                .into());
            }
            self.exec_reservation_settled.wait(&mut state);
        };
        let generation = predecessor.asid_generation();

        let reservation_id = self
            .next_exec_reservation
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .unwrap_or_else(|_| std::process::abort());
        let id = Arc::new(ExecReservationId(reservation_id));
        let inserted = state.exec_reservations.insert(
            generation,
            ActiveExecReservation {
                id: Arc::clone(&id),
                task,
                generation,
                predecessor: Arc::clone(&predecessor),
            },
        );
        assert!(inserted.is_none(), "exec MM reservation marker replaced");
        #[cfg(test)]
        if failpoint == ExecReservationConstructionFailpoint::AfterMarker {
            self.clear_exec_reservation(&mut state, generation);
            if let Some(trace) = rollback_trace.as_ref() {
                trace.record(ExecConstructionRollbackStep::MarkerCleared);
            }
            return Err(MmResourcesError::InjectedExecReservationFailure(failpoint));
        }

        let disposition = if Self::owner_count(&state, &predecessor) == 1 {
            ExecMmDispositionKind::RetireOldMm
        } else {
            ExecMmDispositionKind::RetainOldMm
        };
        let replacement = match self.mm_pool.prepare_child() {
            Ok(replacement) => replacement,
            Err(error) => {
                self.clear_exec_reservation(&mut state, generation);
                return Err(error.into());
            }
        };
        #[cfg(test)]
        if failpoint == ExecReservationConstructionFailpoint::AfterReplacement {
            Self::settle_failed_exec_replacement(replacement)?;
            if let Some(trace) = rollback_trace.as_ref() {
                trace.record(ExecConstructionRollbackStep::ReplacementSettled);
            }
            self.clear_exec_reservation(&mut state, generation);
            if let Some(trace) = rollback_trace.as_ref() {
                trace.record(ExecConstructionRollbackStep::MarkerCleared);
            }
            return Err(MmResourcesError::InjectedExecReservationFailure(failpoint));
        }

        drop(state);
        Ok(ExecMmReservation {
            resources: Arc::clone(self),
            id,
            task,
            predecessor,
            generation,
            state: ExecMmReservationState::Active {
                replacement,
                disposition,
            },
            #[cfg(test)]
            settlement_trace: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn commit_exec(
        &self,
        task: TaskKey,
        prepared: PreparedStage1Mm,
        stage1_root: u64,
    ) -> Result<(Arc<Stage1MmLease>, Option<Stage1MmRetirement>), MmResourcesError> {
        let mut state = self.state.lock();
        let predecessor = state
            .leases
            .get(&task)
            .cloned()
            .ok_or(MmResourcesError::UnknownTask(task))?;
        if let Some(conflict) = Self::exec_conflict(&state, &predecessor) {
            return Err(conflict.into());
        }
        prepared.publish_stage1_root(stage1_root)?;
        let shared = state
            .leases
            .iter()
            .any(|(other_task, other)| *other_task != task && Arc::ptr_eq(other, &predecessor));
        let predecessor_owner_count = Self::owner_count(&state, &predecessor);
        Self::publish_lifecycle(
            if shared {
                carrick_observability::probes::HvpatchMmLeasePhase::ExecCommitPreShared
            } else {
                carrick_observability::probes::HvpatchMmLeasePhase::ExecCommitPreFinal
            },
            task,
            &predecessor,
            predecessor_owner_count,
        );
        let retirement = if shared {
            None
        } else {
            Some(self.mm_pool.retire(&predecessor)?)
        };
        let replacement = prepared.commit();
        state.leases.insert(task, Arc::clone(&replacement));
        Ok((replacement, retirement))
    }

    /// Detach one exact task generation from its prototype mm. Shared-mm clones
    /// merely release their edge; the final owner performs ASID/root-slot retirement.
    /// A repeated cleanup for the same retired generation is idempotent.
    pub(crate) fn retire(&self, task: TaskKey) -> Result<RetiredStage1Mm, MmResourcesError> {
        let mut state = self.state.lock();
        self.retire_locked(&mut state, task)
    }

    #[cfg(test)]
    fn retire_with_state_hook_for_tests(
        &self,
        task: TaskKey,
        hook: MmStateLinearizationHook,
    ) -> Result<RetiredStage1Mm, MmResourcesError> {
        let mut state = self.state.lock();
        hook.run();
        self.retire_locked(&mut state, task)
    }

    fn retire_locked(
        &self,
        state: &mut MmResourceState,
        task: TaskKey,
    ) -> Result<RetiredStage1Mm, MmResourcesError> {
        if state.retired.contains(&task) {
            return Ok(RetiredStage1Mm { retirement: None });
        }
        let lease = state
            .leases
            .get(&task)
            .cloned()
            .ok_or(MmResourcesError::UnknownTask(task))?;
        if let Some(conflict) = Self::exec_conflict(state, &lease) {
            return Err(conflict.into());
        }
        let shared = state
            .leases
            .iter()
            .any(|(other_task, other)| *other_task != task && Arc::ptr_eq(other, &lease));
        let retirement = if shared {
            None
        } else {
            // Do not tombstone an exact generation until the fallible pool
            // retirement succeeds. A failed attempt must remain retryable and
            // its root-slot/ASID lease must stay live rather than becoming reusable.
            Some(self.mm_pool.retire(&lease)?)
        };
        state.leases.remove(&task);
        state.retired.insert(task);
        let remaining_owner_count = Self::owner_count(state, &lease);
        Self::publish_lifecycle(
            if shared {
                carrick_observability::probes::HvpatchMmLeasePhase::TaskEdgeRetiredShared
            } else {
                carrick_observability::probes::HvpatchMmLeasePhase::TaskEdgeRetiredFinal
            },
            task,
            &lease,
            remaining_owner_count,
        );
        Ok(RetiredStage1Mm { retirement })
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use super::*;
    use crate::kernel::{LinuxTid, TaskId, TaskSerial, ThreadKey, ThreadSerial};

    fn task(raw: i32, serial: u64) -> TaskKey {
        TaskKey {
            id: TaskId::for_root_bootstrap(raw).unwrap(),
            serial: TaskSerial::from_registry_allocation(NonZeroU64::new(serial).unwrap()),
        }
    }

    fn thread(raw: i32, serial: u64) -> ThreadKey {
        ThreadKey {
            tid: LinuxTid::from_abi_positive(raw).unwrap(),
            serial: ThreadSerial::from_registry_allocation(NonZeroU64::new(serial).unwrap()),
        }
    }

    fn executor(raw: i32) -> crate::kernel::objects::ExecutorId {
        crate::kernel::objects::ExecutorId::for_transitional_thread(
            crate::thread::ThreadId::synthetic_for_tests(raw),
        )
        .unwrap()
    }

    fn resources(root: TaskKey, asid_limit: u16) -> (MmResources, Arc<Stage1MmBackend>) {
        let (resources, backend) = MmResources::new_for_tests(0x4000, asid_limit).unwrap();
        resources.publish_root(root).unwrap();
        (resources, backend)
    }

    #[test]
    fn unpublished_child_preparation_rolls_back_root_slot_and_asid() {
        let (resources, _) = resources(task(40, 1), 2);
        let first = resources.prepare_child().unwrap();
        let binding = first.binding();
        drop(first);
        let replacement = resources.prepare_child().unwrap();
        assert_eq!(replacement.binding(), binding);
    }

    #[test]
    fn published_backend_retires_only_after_tlb_acknowledgement() {
        let (resources, _) = resources(task(50, 1), 2);
        let child = task(51, 2);
        let prepared = resources.prepare_child().unwrap();
        let binding = prepared.binding();
        let backend = resources.publish_child(child, prepared).unwrap();
        assert_eq!(backend.binding(), binding);

        let retired = resources.retire(child).unwrap();
        assert!(matches!(
            resources.prepare_child(),
            Err(MmResourcesError::AsidExhausted)
        ));
        retired.complete().expect("complete retirement");
        assert_eq!(
            resources.prepare_child().unwrap().binding().asid,
            binding.asid
        );
    }

    #[test]
    fn shared_mm_child_does_not_retire_parent_lease() {
        let parent = task(60, 1);
        let child = task(61, 2);
        let (resources, backend) = resources(parent, 2);
        let shared = resources.publish_shared_child(parent, child).unwrap();
        assert_eq!(shared.binding(), backend.binding());
        assert!(!resources.is_final_owner(child).unwrap());
        assert!(!resources.is_final_owner(parent).unwrap());

        let retired = resources.retire(child).unwrap();
        retired.complete().expect("complete retirement");
        assert!(resources.is_final_owner(parent).unwrap());
        assert_eq!(backend.binding().stage1_root.gpa().raw(), 0x4000);
        assert!(resources.prepare_child().is_ok());
    }

    #[test]
    fn shared_mm_child_exec_replaces_only_its_edge() {
        let parent = task(62, 1);
        let child = task(63, 2);
        let (resources, parent_backend) = resources(parent, 3);
        let old = parent_backend.binding();
        resources.publish_shared_child(parent, child).unwrap();

        let observation = resources.observe_exec_owners(child, thread(63, 3)).unwrap();
        assert_eq!(observation.owner_count(), 2);
        assert!(!observation.final_owner());

        let prepared = resources.prepare_exec(child).unwrap();
        let replacement_root = prepared.root_slot().unwrap().base();
        let (replacement, retirement) = resources
            .commit_exec(child, prepared, replacement_root)
            .unwrap();
        assert!(retirement.is_none(), "the parent still owns the shared MM");
        assert_eq!(resources.lease(parent).unwrap().binding(), old);
        assert_ne!(replacement.binding(), old);
    }

    #[test]
    fn exec_allocates_fresh_asid_and_root_without_mutating_the_old_observer() {
        let root = task(70, 1);
        let (resources, backend) = resources(root, 2);
        let old = backend.binding();
        let prepared = resources.prepare_exec(root).unwrap();
        let replacement_generation = prepared.asid_generation();
        let replacement_root = prepared.root_slot().unwrap().base();
        let (replacement, retired) = resources
            .commit_exec(root, prepared, replacement_root)
            .unwrap();
        assert_ne!(replacement.binding().asid, old.asid);
        assert_eq!(
            replacement.binding().stage1_root.gpa().raw(),
            replacement_root
        );
        assert_eq!(replacement.asid_generation(), replacement_generation);
        assert_eq!(backend.binding(), old);
        RetiredStage1Mm {
            retirement: Some(retired.unwrap()),
        }
        .complete()
        .unwrap();
    }

    #[test]
    fn delayed_old_generation_cleanup_cannot_touch_reused_pid() {
        let root = task(80, 1);
        let old = task(81, 2);
        let replacement = task(81, 3);
        let (resources, _) = resources(root, 2);
        let old_backend = resources
            .publish_child(old, resources.prepare_child().unwrap())
            .unwrap();
        let old_binding = old_backend.binding();
        let retired = resources.retire(old).unwrap();
        retired.complete().expect("complete retirement");

        let replacement_backend = resources
            .publish_child(replacement, resources.prepare_child().unwrap())
            .unwrap();
        let replacement_binding = replacement_backend.binding();
        assert_eq!(replacement_binding.asid, old_binding.asid);

        let duplicate = resources.retire(old).unwrap();
        duplicate.complete().expect("complete duplicate retirement");
        assert_eq!(replacement_backend.binding(), replacement_binding);
        assert!(matches!(
            resources.prepare_exec(old),
            Err(MmResourcesError::UnknownTask(key)) if key == old
        ));
        assert_eq!(replacement_backend.binding(), replacement_binding);
    }

    #[test]
    fn duplicate_exact_generation_does_not_consume_prepared_root_slot() {
        let root = task(90, 1);
        let child = task(91, 2);
        let (resources, _) = resources(root, 3);
        resources
            .publish_child(child, resources.prepare_child().unwrap())
            .unwrap();
        let duplicate = resources.prepare_child().unwrap();
        let duplicate_binding = duplicate.binding();
        assert!(matches!(
            resources.publish_child(child, duplicate),
            Err(MmResourcesError::DuplicateTask(key)) if key == child
        ));
        assert_eq!(
            resources.prepare_child().unwrap().binding(),
            duplicate_binding
        );
    }

    #[test]
    fn exec_reservation_pins_shared_and_final_predecessor_dispositions() {
        let shared_parent = task(100, 1);
        let shared_child = task(101, 2);
        let (shared_resources, _) = resources(shared_parent, 2);
        let shared_resources = Arc::new(shared_resources);
        shared_resources
            .publish_shared_child(shared_parent, shared_child)
            .unwrap();

        let shared = shared_resources.reserve_exec(shared_child).unwrap();
        assert!(shared.disposition() == ExecMmDispositionKind::RetainOldMm);
        drop(shared);
        let shared_retry = shared_resources.reserve_exec(shared_child).unwrap();
        assert!(shared_retry.disposition() == ExecMmDispositionKind::RetainOldMm);
        drop(shared_retry);

        let final_task = task(102, 3);
        let (final_resources, _) = resources(final_task, 2);
        let final_resources = Arc::new(final_resources);
        let final_reservation = final_resources.reserve_exec(final_task).unwrap();
        assert!(final_reservation.disposition() == ExecMmDispositionKind::RetireOldMm);
        drop(final_reservation);
        let final_retry = final_resources.reserve_exec(final_task).unwrap();
        assert!(final_retry.disposition() == ExecMmDispositionKind::RetireOldMm);
    }

    #[test]
    fn eventual_exec_reservation_waits_then_recomputes_final_owner_disposition() {
        let first = task(105, 1);
        let waiter = task(106, 2);
        let (resources, _) = resources(first, 3);
        let resources = Arc::new(resources);
        resources.publish_shared_child(first, waiter).unwrap();

        let first_reservation = resources.reserve_exec(first).unwrap();
        assert_eq!(
            first_reservation.disposition(),
            ExecMmDispositionKind::RetainOldMm,
        );
        let first_root = first_reservation.replacement_root_slot().unwrap();
        assert!(matches!(
            resources.reserve_exec_eventual(first),
            Err(MmResourcesError::ExecReservationConflict(conflict))
                if conflict.reserving_task == first
                    && conflict.generation
                        == resources.lease(first).unwrap().asid_generation()
        ));

        let (tx, rx) = std::sync::mpsc::channel();
        let waiter_resources = Arc::clone(&resources);
        let waiter_thread = std::thread::spawn(move || {
            tx.send(waiter_resources.reserve_exec_eventual(waiter))
                .unwrap();
        });

        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "distinct-task exec acquired the shared generation concurrently",
        );

        let first_receipt = first_reservation
            .commit(first_root.base() + 0x1000)
            .unwrap();
        assert!(matches!(
            first_receipt,
            ExecMmCommitReceipt::Retained { .. }
        ));

        let waiter_reservation = rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("waiter was not notified when the first reservation settled")
            .unwrap();
        assert_eq!(
            waiter_reservation.disposition(),
            ExecMmDispositionKind::RetireOldMm,
            "waiter reused the pre-wait owner count instead of recomputing after wake",
        );
        let waiter_root = waiter_reservation.replacement_root_slot().unwrap();
        let waiter_receipt = waiter_reservation
            .commit(waiter_root.base() + 0x1000)
            .unwrap();
        let ExecMmCommitReceipt::Retired { retirement, .. } = waiter_receipt else {
            panic!("final waiter did not retire its exact predecessor");
        };
        retirement.complete().unwrap();
        waiter_thread.join().unwrap();
    }

    #[test]
    fn explicit_exec_abort_restores_retained_and_final_topology_for_exact_retry() {
        let shared_parent = task(110, 1);
        let shared_child = task(111, 2);
        let (shared_resources, _) = resources(shared_parent, 2);
        let shared_resources = Arc::new(shared_resources);
        shared_resources
            .publish_shared_child(shared_parent, shared_child)
            .unwrap();
        let shared_predecessor = shared_resources.lease(shared_child).unwrap();
        let shared_reservation = shared_resources.reserve_exec(shared_child).unwrap();
        let shared_replacement = shared_reservation.replacement_asid_generation();
        let shared_root = shared_reservation.replacement_root_slot().unwrap();
        let shared_abort = shared_reservation.abort().unwrap();
        match shared_abort {
            ExecMmAbortReceipt::Retained {
                predecessor,
                replacement,
                settlement: PreparedStage1MmAbort::Unpublished { .. },
            } => {
                assert!(Arc::ptr_eq(&predecessor, &shared_predecessor));
                assert_eq!(replacement, shared_replacement);
            }
            other => panic!("unexpected shared abort receipt: {other:?}"),
        }
        assert!(Arc::ptr_eq(
            &shared_resources.lease(shared_child).unwrap(),
            &shared_predecessor
        ));
        let shared_retry = shared_resources.reserve_exec(shared_child).unwrap();
        assert_eq!(shared_retry.replacement_root_slot(), Some(shared_root));
        assert_eq!(
            shared_retry.replacement_asid_generation().asid(),
            shared_replacement.asid()
        );
        drop(shared_retry);

        let final_task = task(112, 3);
        let (final_resources, _) = resources(final_task, 2);
        let final_resources = Arc::new(final_resources);
        let final_predecessor = final_resources.lease(final_task).unwrap();
        let final_reservation = final_resources.reserve_exec(final_task).unwrap();
        let final_replacement = final_reservation.replacement_asid_generation();
        let final_root = final_reservation.replacement_root_slot().unwrap();
        let final_abort = final_reservation.abort().unwrap();
        match final_abort {
            ExecMmAbortReceipt::RestoredFinal {
                predecessor,
                replacement,
                settlement: PreparedStage1MmAbort::Unpublished { .. },
            } => {
                assert!(Arc::ptr_eq(&predecessor, &final_predecessor));
                assert_eq!(replacement, final_replacement);
            }
            other => panic!("unexpected final abort receipt: {other:?}"),
        }
        assert!(Arc::ptr_eq(
            &final_resources.lease(final_task).unwrap(),
            &final_predecessor
        ));
        let final_retry = final_resources.reserve_exec(final_task).unwrap();
        assert_eq!(final_retry.replacement_root_slot(), Some(final_root));
        assert_eq!(
            final_retry.replacement_asid_generation().asid(),
            final_replacement.asid()
        );
    }

    #[test]
    fn active_exec_marker_rejects_every_same_mm_mutator_before_topology_changes() {
        let parent = task(120, 1);
        let exec_child = task(121, 2);
        let rejected_child = task(122, 3);
        let (resources, _) = resources(parent, 3);
        let resources = Arc::new(resources);
        resources.publish_shared_child(parent, exec_child).unwrap();
        let predecessor = resources.lease(parent).unwrap();
        let legacy_prepared = resources.prepare_exec(parent).unwrap();
        let reservation = resources.reserve_exec(exec_child).unwrap();
        let generation = predecessor.asid_generation();

        assert!(matches!(
            resources.reserve_exec(parent),
            Err(MmResourcesError::ExecReservationConflict(conflict))
                if conflict.reserving_task == exec_child && conflict.generation == generation
        ));
        assert!(matches!(
            resources.publish_shared_child(parent, rejected_child),
            Err(MmResourcesError::ExecReservationConflict(conflict))
                if conflict.reserving_task == exec_child && conflict.generation == generation
        ));
        assert!(matches!(
            resources.retire(parent),
            Err(MmResourcesError::ExecReservationConflict(conflict))
                if conflict.reserving_task == exec_child && conflict.generation == generation
        ));
        assert!(matches!(
            resources.prepare_exec(parent),
            Err(MmResourcesError::ExecReservationConflict(conflict))
                if conflict.reserving_task == exec_child && conflict.generation == generation
        ));
        assert!(matches!(
            resources.commit_exec(
                parent,
                legacy_prepared,
                carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE + 0x1000,
            ),
            Err(MmResourcesError::ExecReservationConflict(conflict))
                if conflict.reserving_task == exec_child && conflict.generation == generation
        ));

        assert!(Arc::ptr_eq(&resources.lease(parent).unwrap(), &predecessor));
        assert!(Arc::ptr_eq(
            &resources.lease(exec_child).unwrap(),
            &predecessor
        ));
        assert!(matches!(
            resources.lease(rejected_child),
            Err(MmResourcesError::UnknownTask(key)) if key == rejected_child
        ));
        reservation.abort().unwrap();
        resources
            .publish_shared_child(parent, rejected_child)
            .expect("exact-MM publication retries after abort");
    }

    #[test]
    fn final_exec_reservation_keeps_predecessor_loadable_until_commit() {
        // The exec'ing thread parks in `ExecSiblingDrain` and releases its
        // executor while siblings die. On resume its executor must be able to
        // load the predecessor address space again: the predecessor retires at
        // exec commit, after the drain, not at reservation time.
        let owner = task(135, 1);
        let (resources, _) = resources(owner, 2);
        let resources = Arc::new(resources);
        let predecessor = resources.lease(owner).unwrap();
        let reservation = resources.reserve_exec(owner).unwrap();
        assert_eq!(
            reservation.disposition(),
            ExecMmDispositionKind::RetireOldMm
        );
        assert!(
            !predecessor.is_retiring(),
            "final-owner exec reservation closed predecessor loads before commit"
        );
        let load = predecessor
            .begin_asid_load(executor(13_501))
            .expect("exec owner reloads its own address space during sibling drain");
        drop(load);

        let root = reservation.replacement_root_slot().unwrap().base() + 0x1000;
        let receipt = reservation.commit(root).unwrap();
        let ExecMmCommitReceipt::Retired { retirement, .. } = receipt else {
            panic!("final-owner commit did not retire the predecessor: {receipt:?}");
        };
        assert!(predecessor.is_retiring());
        assert!(matches!(
            predecessor.begin_asid_load(executor(13_502)),
            Err(AsidResidencyError::Retiring)
        ));
        retirement.complete().unwrap();
    }

    #[test]
    fn aborted_final_exec_reservation_never_touched_predecessor_loads() {
        let owner = task(136, 1);
        let (resources, _) = resources(owner, 2);
        let resources = Arc::new(resources);
        let predecessor = resources.lease(owner).unwrap();
        let reservation = resources.reserve_exec(owner).unwrap();
        let load = predecessor.begin_asid_load(executor(13_601)).unwrap();
        let receipt = reservation.abort().unwrap();
        assert!(matches!(receipt, ExecMmAbortReceipt::RestoredFinal { .. }));
        drop(load);
        assert!(!predecessor.is_retiring());
        predecessor.begin_asid_load(executor(13_601)).unwrap();
    }

    #[test]
    fn exec_commit_consumes_pinned_disposition_and_publishes_one_coherent_replacement() {
        let retained_parent = task(130, 1);
        let exec_child = task(131, 2);
        let (retained_resources, _) = resources(retained_parent, 2);
        let retained_resources = Arc::new(retained_resources);
        retained_resources
            .publish_shared_child(retained_parent, exec_child)
            .unwrap();
        let retained_reservation = retained_resources.reserve_exec(exec_child).unwrap();
        assert_eq!(
            retained_reservation.disposition(),
            ExecMmDispositionKind::RetainOldMm,
        );
        let retained_root = retained_reservation.replacement_root_slot().unwrap();
        let predecessor = retained_resources.lease(exec_child).unwrap();
        let removed = retained_resources
            .state
            .lock()
            .leases
            .remove(&retained_parent);
        assert!(removed.is_some(), "test removes the only surviving alias");
        assert_eq!(
            retained_reservation.disposition(),
            ExecMmDispositionKind::RetainOldMm,
            "later topology cannot change the pinned exec disposition",
        );

        let retained_published_root = retained_root.base() + 0x1000;
        let retained = retained_reservation
            .commit(retained_published_root)
            .unwrap();
        let retained_replacement = match retained {
            ExecMmCommitReceipt::Retained {
                predecessor: receipt_predecessor,
                replacement,
            } => {
                assert!(Arc::ptr_eq(&receipt_predecessor, &predecessor));
                replacement
            }
            other => panic!("commit re-counted the pinned retained disposition: {other:?}"),
        };
        assert!(Arc::ptr_eq(
            &retained_resources.lease(exec_child).unwrap(),
            &retained_replacement
        ));
        assert_eq!(
            retained_replacement.binding().stage1_root.gpa().raw(),
            retained_published_root
        );
        retained_resources
            .mm_pool
            .retire(&predecessor)
            .unwrap()
            .complete()
            .unwrap();

        let final_task = task(132, 3);
        let committed_child = task(133, 4);
        let (final_resources, _) = resources(final_task, 2);
        let final_resources = Arc::new(final_resources);
        let final_reservation = final_resources.reserve_exec(final_task).unwrap();
        let final_root = final_reservation.replacement_root_slot().unwrap();
        let final_published_root = final_root.base() + 0x1000;
        let retired = final_reservation.commit(final_published_root).unwrap();
        let (replacement, retirement) = match retired {
            ExecMmCommitReceipt::Retired {
                retirement,
                replacement,
            } => (replacement, retirement),
            other => panic!("final-owner reservation changed disposition: {other:?}"),
        };
        assert_eq!(replacement.binding(), replacement.backend().binding());
        assert_eq!(
            replacement.binding().stage1_root.gpa().raw(),
            final_published_root
        );
        assert!(Arc::ptr_eq(
            &final_resources.lease(final_task).unwrap(),
            &replacement
        ));
        let shared_backend = final_resources
            .publish_shared_child(final_task, committed_child)
            .unwrap();
        assert_eq!(shared_backend.binding(), replacement.binding());
        assert!(Arc::ptr_eq(
            &final_resources.lease(committed_child).unwrap(),
            &replacement
        ));
        retirement.complete().unwrap();
    }

    #[test]
    fn explicit_exec_abort_returns_dirty_replacement_quarantine_for_both_dispositions() {
        let retained_parent = task(140, 1);
        let retained_child = task(141, 2);
        let retained_executor = executor(14_001);
        let (retained_resources, _) = resources(retained_parent, 2);
        let retained_resources = Arc::new(retained_resources);
        retained_resources
            .publish_shared_child(retained_parent, retained_child)
            .unwrap();
        let retained_predecessor = retained_resources.lease(retained_child).unwrap();
        let retained_reservation = retained_resources.reserve_exec(retained_child).unwrap();
        let mut retained_load = retained_reservation
            .begin_replacement_asid_load(retained_executor)
            .unwrap();
        retained_load.arm_hardware_dirty().unwrap();
        retained_load.mark_resident().unwrap();
        let retained_abort = retained_reservation.abort().unwrap();
        let retained_retirement = match retained_abort {
            ExecMmAbortReceipt::Retained {
                predecessor,
                replacement,
                settlement: PreparedStage1MmAbort::Retirement(retirement),
            } => {
                assert!(Arc::ptr_eq(&predecessor, &retained_predecessor));
                assert_eq!(replacement, retirement.asid_generation());
                retirement
            }
            other => panic!("dirty retained abort was not quarantined: {other:?}"),
        };
        retained_retirement
            .acknowledge(super::super::asid::InvalidationAck::new(
                retained_executor,
                retained_retirement.asid_generation(),
            ))
            .unwrap();
        retained_retirement.complete().unwrap();
        drop(retained_resources.reserve_exec(retained_child).unwrap());

        let final_task = task(142, 3);
        let final_executor = executor(14_002);
        let (final_resources, _) = resources(final_task, 2);
        let final_resources = Arc::new(final_resources);
        let final_predecessor = final_resources.lease(final_task).unwrap();
        let final_reservation = final_resources.reserve_exec(final_task).unwrap();
        let mut final_load = final_reservation
            .begin_replacement_asid_load(final_executor)
            .unwrap();
        final_load.arm_hardware_dirty().unwrap();
        final_load.mark_resident().unwrap();
        let final_abort = final_reservation.abort().unwrap();
        let final_retirement = match final_abort {
            ExecMmAbortReceipt::RestoredFinal {
                predecessor,
                replacement,
                settlement: PreparedStage1MmAbort::Retirement(retirement),
            } => {
                assert!(Arc::ptr_eq(&predecessor, &final_predecessor));
                assert_eq!(replacement, retirement.asid_generation());
                retirement
            }
            other => panic!("dirty final abort was not quarantined: {other:?}"),
        };
        assert!(final_predecessor.begin_asid_load(executor(14_003)).is_ok());
        final_retirement
            .acknowledge(super::super::asid::InvalidationAck::new(
                final_executor,
                final_retirement.asid_generation(),
            ))
            .unwrap();
        final_retirement.complete().unwrap();
        drop(final_resources.reserve_exec(final_task).unwrap());
    }

    #[test]
    fn active_exec_reservation_leaves_unrelated_mm_operations_independent() {
        let reserved_task = task(150, 1);
        let unrelated_owner = task(151, 2);
        let unrelated_alias = task(152, 3);
        let unrelated_final = task(153, 4);
        let (resources, _) = resources(reserved_task, 4);
        let resources = Arc::new(resources);
        resources
            .publish_child(unrelated_owner, resources.prepare_child().unwrap())
            .unwrap();
        resources
            .publish_child(unrelated_final, resources.prepare_child().unwrap())
            .unwrap();
        let held = resources.reserve_exec(reserved_task).unwrap();

        let worker_resources = Arc::clone(&resources);
        let (completed_tx, completed_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            worker_resources
                .publish_shared_child(unrelated_owner, unrelated_alias)
                .unwrap();
            worker_resources
                .retire(unrelated_alias)
                .unwrap()
                .complete()
                .unwrap();
            worker_resources
                .retire(unrelated_final)
                .unwrap()
                .complete()
                .unwrap();
            worker_resources
                .reserve_exec(unrelated_owner)
                .unwrap()
                .abort()
                .unwrap();
            completed_tx.send(()).unwrap();
        });
        completed_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("unrelated MM operations must not wait on a held reservation");
        worker.join().unwrap();
        held.abort().unwrap();
    }

    #[test]
    fn failure_after_exec_marker_insertion_clears_marker_and_permits_exact_retry() {
        let root = task(160, 1);
        let (resources, _) = resources(root, 2);
        let resources = Arc::new(resources);
        let predecessor = resources.lease(root).unwrap();

        assert!(matches!(
            resources.reserve_exec_with_failpoint_for_tests(
                root,
                ExecReservationConstructionFailpoint::AfterMarker,
            ),
            Err(MmResourcesError::InjectedExecReservationFailure(
                ExecReservationConstructionFailpoint::AfterMarker,
            ))
        ));
        assert!(Arc::ptr_eq(&resources.lease(root).unwrap(), &predecessor));
        assert!(predecessor.begin_asid_load(executor(16_001)).is_ok());
        drop(resources.reserve_exec(root).unwrap());
    }

    #[test]
    fn failure_after_replacement_allocation_settles_replacement_before_marker_clear() {
        let root = task(161, 1);
        let (resources, _) = resources(root, 2);
        let resources = Arc::new(resources);
        let predecessor = resources.lease(root).unwrap();
        let probe = resources.prepare_child().unwrap();
        let expected_asid = probe.asid_generation().asid();
        let expected_root = probe.root_slot();
        drop(probe);

        let trace = ExecConstructionRollbackTrace::default();
        assert!(matches!(
            resources.reserve_exec_with_failpoint_and_trace_for_tests(
                root,
                ExecReservationConstructionFailpoint::AfterReplacement,
                trace.clone(),
            ),
            Err(MmResourcesError::InjectedExecReservationFailure(
                ExecReservationConstructionFailpoint::AfterReplacement,
            ))
        ));
        assert_eq!(
            trace.snapshot(),
            vec![
                ExecConstructionRollbackStep::ReplacementSettled,
                ExecConstructionRollbackStep::MarkerCleared,
            ]
        );
        assert!(Arc::ptr_eq(&resources.lease(root).unwrap(), &predecessor));
        assert!(predecessor.begin_asid_load(executor(16_002)).is_ok());
        let retry = resources.reserve_exec(root).unwrap();
        assert_eq!(retry.replacement_asid_generation().asid(), expected_asid);
        assert_eq!(retry.replacement_root_slot(), expected_root);
    }

    #[test]
    fn reserve_vs_shared_publish_barriers_cover_both_linearization_orders() {
        let reserve_first_root = task(170, 1);
        let reserve_first_child = task(171, 2);
        let (reserve_first_resources, _) = resources(reserve_first_root, 2);
        let reserve_first_resources = Arc::new(reserve_first_resources);
        let reserve_entered = Arc::new(std::sync::Barrier::new(2));
        let reserve_release = Arc::new(std::sync::Barrier::new(2));
        let reserve_worker_resources = Arc::clone(&reserve_first_resources);
        let reserve_worker_entered = Arc::clone(&reserve_entered);
        let reserve_worker_release = Arc::clone(&reserve_release);
        let reserve_worker = std::thread::spawn(move || {
            reserve_worker_resources.reserve_exec_with_state_hook_for_tests(
                reserve_first_root,
                MmStateLinearizationHook {
                    entered: reserve_worker_entered,
                    release: reserve_worker_release,
                },
            )
        });
        reserve_entered.wait();
        let publish_worker_resources = Arc::clone(&reserve_first_resources);
        let (publish_tx, publish_rx) = std::sync::mpsc::channel();
        let publish_worker = std::thread::spawn(move || {
            publish_tx
                .send(
                    publish_worker_resources
                        .publish_shared_child(reserve_first_root, reserve_first_child),
                )
                .unwrap();
        });
        assert!(matches!(
            publish_rx.recv_timeout(std::time::Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        reserve_release.wait();
        let reserve_first = reserve_worker.join().unwrap().unwrap();
        assert!(reserve_first.disposition() == ExecMmDispositionKind::RetireOldMm);
        assert!(matches!(
            publish_rx.recv_timeout(std::time::Duration::from_secs(2)),
            Ok(Err(MmResourcesError::ExecReservationConflict(_)))
        ));
        publish_worker.join().unwrap();
        reserve_first.abort().unwrap();

        let publish_first_root = task(172, 3);
        let publish_first_child = task(173, 4);
        let (publish_first_resources, _) = resources(publish_first_root, 2);
        let publish_first_resources = Arc::new(publish_first_resources);
        let publish_entered = Arc::new(std::sync::Barrier::new(2));
        let publish_release = Arc::new(std::sync::Barrier::new(2));
        let publish_owner_resources = Arc::clone(&publish_first_resources);
        let publish_owner_entered = Arc::clone(&publish_entered);
        let publish_owner_release = Arc::clone(&publish_release);
        let publish_owner = std::thread::spawn(move || {
            publish_owner_resources.publish_shared_child_with_state_hook_for_tests(
                publish_first_root,
                publish_first_child,
                MmStateLinearizationHook {
                    entered: publish_owner_entered,
                    release: publish_owner_release,
                },
            )
        });
        publish_entered.wait();
        let reserve_after_publish_resources = Arc::clone(&publish_first_resources);
        let (reserve_tx, reserve_rx) = std::sync::mpsc::channel();
        let reserve_after_publish = std::thread::spawn(move || {
            reserve_tx
                .send(reserve_after_publish_resources.reserve_exec(publish_first_root))
                .unwrap();
        });
        assert!(matches!(
            reserve_rx.recv_timeout(std::time::Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        publish_release.wait();
        publish_owner.join().unwrap().unwrap();
        let publish_first = reserve_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap()
            .unwrap();
        reserve_after_publish.join().unwrap();
        assert!(publish_first.disposition() == ExecMmDispositionKind::RetainOldMm);
        publish_first.abort().unwrap();
    }

    #[test]
    fn reserve_vs_shared_retire_barriers_cover_both_linearization_orders() {
        let reserve_first_root = task(180, 1);
        let reserve_first_alias = task(181, 2);
        let (reserve_first_resources, _) = resources(reserve_first_root, 2);
        let reserve_first_resources = Arc::new(reserve_first_resources);
        reserve_first_resources
            .publish_shared_child(reserve_first_root, reserve_first_alias)
            .unwrap();
        let reserve_entered = Arc::new(std::sync::Barrier::new(2));
        let reserve_release = Arc::new(std::sync::Barrier::new(2));
        let reserve_worker_resources = Arc::clone(&reserve_first_resources);
        let reserve_worker_entered = Arc::clone(&reserve_entered);
        let reserve_worker_release = Arc::clone(&reserve_release);
        let reserve_worker = std::thread::spawn(move || {
            reserve_worker_resources.reserve_exec_with_state_hook_for_tests(
                reserve_first_root,
                MmStateLinearizationHook {
                    entered: reserve_worker_entered,
                    release: reserve_worker_release,
                },
            )
        });
        reserve_entered.wait();
        let retire_worker_resources = Arc::clone(&reserve_first_resources);
        let (retire_tx, retire_rx) = std::sync::mpsc::channel();
        let retire_worker = std::thread::spawn(move || {
            retire_tx
                .send(retire_worker_resources.retire(reserve_first_alias))
                .unwrap();
        });
        assert!(matches!(
            retire_rx.recv_timeout(std::time::Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        reserve_release.wait();
        let reserve_first = reserve_worker.join().unwrap().unwrap();
        assert!(reserve_first.disposition() == ExecMmDispositionKind::RetainOldMm);
        assert!(matches!(
            retire_rx.recv_timeout(std::time::Duration::from_secs(2)),
            Ok(Err(MmResourcesError::ExecReservationConflict(_)))
        ));
        retire_worker.join().unwrap();
        reserve_first.abort().unwrap();
        reserve_first_resources
            .retire(reserve_first_alias)
            .unwrap()
            .complete()
            .unwrap();

        let retire_first_root = task(182, 3);
        let retire_first_alias = task(183, 4);
        let (retire_first_resources, _) = resources(retire_first_root, 2);
        let retire_first_resources = Arc::new(retire_first_resources);
        retire_first_resources
            .publish_shared_child(retire_first_root, retire_first_alias)
            .unwrap();
        let retire_entered = Arc::new(std::sync::Barrier::new(2));
        let retire_release = Arc::new(std::sync::Barrier::new(2));
        let retire_owner_resources = Arc::clone(&retire_first_resources);
        let retire_owner_entered = Arc::clone(&retire_entered);
        let retire_owner_release = Arc::clone(&retire_release);
        let retire_owner = std::thread::spawn(move || {
            retire_owner_resources.retire_with_state_hook_for_tests(
                retire_first_alias,
                MmStateLinearizationHook {
                    entered: retire_owner_entered,
                    release: retire_owner_release,
                },
            )
        });
        retire_entered.wait();
        let reserve_after_retire_resources = Arc::clone(&retire_first_resources);
        let (reserve_tx, reserve_rx) = std::sync::mpsc::channel();
        let reserve_after_retire = std::thread::spawn(move || {
            reserve_tx
                .send(reserve_after_retire_resources.reserve_exec(retire_first_root))
                .unwrap();
        });
        assert!(matches!(
            reserve_rx.recv_timeout(std::time::Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        retire_release.wait();
        retire_owner.join().unwrap().unwrap().complete().unwrap();
        let retire_first = reserve_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap()
            .unwrap();
        reserve_after_retire.join().unwrap();
        assert!(retire_first.disposition() == ExecMmDispositionKind::RetireOldMm);
        retire_first.abort().unwrap();
    }

    #[test]
    fn exec_commit_rejects_task_generation_id_and_predecessor_mismatches_fail_closed() {
        let task_mismatch_root = task(190, 1);
        let (task_mismatch_resources, _) = resources(task_mismatch_root, 2);
        let task_mismatch_resources = Arc::new(task_mismatch_resources);
        let task_mismatch = task_mismatch_resources
            .reserve_exec(task_mismatch_root)
            .unwrap();
        let task_generation = task_mismatch.generation;
        let task_replacement_root = task_mismatch.replacement_root_slot().unwrap().base();
        task_mismatch_resources
            .state
            .lock()
            .exec_reservations
            .get_mut(&task_generation)
            .unwrap()
            .task = task(191, 2);
        assert!(matches!(
            task_mismatch.commit(task_replacement_root),
            Err(MmResourcesError::ExecReservationMismatch(
                ExecReservationMismatch::Task,
            ))
        ));

        let generation_mismatch_root = task(192, 3);
        let (generation_mismatch_resources, _) = resources(generation_mismatch_root, 2);
        let generation_mismatch_resources = Arc::new(generation_mismatch_resources);
        let generation_mismatch = generation_mismatch_resources
            .reserve_exec(generation_mismatch_root)
            .unwrap();
        let predecessor_generation = generation_mismatch.generation;
        let replacement_generation = generation_mismatch.replacement_asid_generation();
        let generation_replacement_root =
            generation_mismatch.replacement_root_slot().unwrap().base();
        generation_mismatch_resources
            .state
            .lock()
            .exec_reservations
            .get_mut(&predecessor_generation)
            .unwrap()
            .generation = replacement_generation;
        assert!(matches!(
            generation_mismatch.commit(generation_replacement_root),
            Err(MmResourcesError::ExecReservationMismatch(
                ExecReservationMismatch::Generation,
            ))
        ));

        let id_mismatch_root = task(193, 4);
        let (id_mismatch_resources, _) = resources(id_mismatch_root, 2);
        let id_mismatch_resources = Arc::new(id_mismatch_resources);
        let id_mismatch = id_mismatch_resources
            .reserve_exec(id_mismatch_root)
            .unwrap();
        let id_generation = id_mismatch.generation;
        let id_replacement_root = id_mismatch.replacement_root_slot().unwrap().base();
        id_mismatch_resources
            .state
            .lock()
            .exec_reservations
            .get_mut(&id_generation)
            .unwrap()
            .id = Arc::new(ExecReservationId(u64::MAX));
        assert!(matches!(
            id_mismatch.commit(id_replacement_root),
            Err(MmResourcesError::ExecReservationMismatch(
                ExecReservationMismatch::ReservationId,
            ))
        ));

        let predecessor_mismatch_root = task(194, 5);
        let unrelated_task = task(195, 6);
        let (predecessor_mismatch_resources, _) = resources(predecessor_mismatch_root, 3);
        let predecessor_mismatch_resources = Arc::new(predecessor_mismatch_resources);
        predecessor_mismatch_resources
            .publish_child(
                unrelated_task,
                predecessor_mismatch_resources.prepare_child().unwrap(),
            )
            .unwrap();
        let unrelated_lease = predecessor_mismatch_resources
            .lease(unrelated_task)
            .unwrap();
        let predecessor_mismatch = predecessor_mismatch_resources
            .reserve_exec(predecessor_mismatch_root)
            .unwrap();
        let predecessor_generation = predecessor_mismatch.generation;
        let predecessor_replacement_root =
            predecessor_mismatch.replacement_root_slot().unwrap().base();
        predecessor_mismatch_resources
            .state
            .lock()
            .exec_reservations
            .get_mut(&predecessor_generation)
            .unwrap()
            .predecessor = Arc::clone(&unrelated_lease);
        assert!(matches!(
            predecessor_mismatch.commit(predecessor_replacement_root),
            Err(MmResourcesError::ExecReservationMismatch(
                ExecReservationMismatch::Predecessor,
            ))
        ));

        let edge_mismatch_root = task(196, 7);
        let edge_unrelated = task(197, 8);
        let (edge_mismatch_resources, _) = resources(edge_mismatch_root, 3);
        let edge_mismatch_resources = Arc::new(edge_mismatch_resources);
        edge_mismatch_resources
            .publish_child(
                edge_unrelated,
                edge_mismatch_resources.prepare_child().unwrap(),
            )
            .unwrap();
        let edge_unrelated_lease = edge_mismatch_resources.lease(edge_unrelated).unwrap();
        let edge_mismatch = edge_mismatch_resources
            .reserve_exec(edge_mismatch_root)
            .unwrap();
        let edge_replacement_root = edge_mismatch.replacement_root_slot().unwrap().base();
        edge_mismatch_resources
            .state
            .lock()
            .leases
            .insert(edge_mismatch_root, edge_unrelated_lease);
        assert!(matches!(
            edge_mismatch.commit(edge_replacement_root),
            Err(MmResourcesError::ExecReservationMismatch(
                ExecReservationMismatch::TaskEdge,
            ))
        ));
    }

    #[test]
    fn exec_abort_uses_the_same_exact_marker_validation_as_commit() {
        let root = task(198, 1);
        let (resources, _) = resources(root, 2);
        let resources = Arc::new(resources);
        let reservation = resources.reserve_exec(root).unwrap();
        let generation = reservation.generation;
        resources
            .state
            .lock()
            .exec_reservations
            .get_mut(&generation)
            .unwrap()
            .id = Arc::new(ExecReservationId(u64::MAX));
        assert!(matches!(
            reservation.abort(),
            Err(MmResourcesError::ExecReservationMismatch(
                ExecReservationMismatch::ReservationId,
            ))
        ));
    }

    #[test]
    fn explicit_dirty_final_abort_orders_replacement_predecessor_marker_settlement() {
        let root = task(199, 1);
        let alias = task(200, 2);
        let dirty_executor = executor(19_901);
        let (resources, _) = resources(root, 2);
        let resources = Arc::new(resources);
        let predecessor = resources.lease(root).unwrap();
        let trace = ExecDispositionSettlementTrace::default();
        let reservation = resources
            .reserve_exec_with_settlement_trace_for_tests(root, trace.clone())
            .unwrap();
        let mut load = reservation
            .begin_replacement_asid_load(dirty_executor)
            .unwrap();
        load.arm_hardware_dirty().unwrap();
        load.mark_resident().unwrap();

        assert!(matches!(
            reservation.abort().unwrap(),
            ExecMmAbortReceipt::RestoredFinal {
                settlement: PreparedStage1MmAbort::Retirement(_),
                ..
            }
        ));
        assert_eq!(
            trace.snapshot(),
            vec![
                ExecDispositionSettlementStep::ReplacementSettled,
                ExecDispositionSettlementStep::MarkerCleared,
            ]
        );
        assert!(Arc::ptr_eq(&resources.lease(root).unwrap(), &predecessor));
        resources.publish_shared_child(root, alias).unwrap();
    }

    #[test]
    fn dropping_dirty_final_reservation_restores_predecessor_and_quarantines_replacement() {
        let root = task(201, 1);
        let alias = task(202, 2);
        let dirty_executor = executor(20_101);
        let (resources, _) = resources(root, 2);
        let resources = Arc::new(resources);
        let predecessor = resources.lease(root).unwrap();
        let trace = ExecDispositionSettlementTrace::default();
        let reservation = resources
            .reserve_exec_with_settlement_trace_for_tests(root, trace.clone())
            .unwrap();
        let mut load = reservation
            .begin_replacement_asid_load(dirty_executor)
            .unwrap();
        load.arm_hardware_dirty().unwrap();
        load.mark_resident().unwrap();
        drop(reservation);

        assert_eq!(
            trace.snapshot(),
            vec![
                ExecDispositionSettlementStep::ReplacementSettled,
                ExecDispositionSettlementStep::MarkerCleared,
            ]
        );
        assert!(Arc::ptr_eq(&resources.lease(root).unwrap(), &predecessor));
        assert!(predecessor.begin_asid_load(executor(20_102)).is_ok());
        resources.publish_shared_child(root, alias).unwrap();
        assert!(matches!(
            resources.prepare_child(),
            Err(MmResourcesError::AsidExhausted)
        ));
    }

    #[test]
    fn dropping_dirty_retained_reservation_quarantines_replacement_and_clears_marker() {
        let root = task(203, 1);
        let exec_child = task(204, 2);
        let post_drop_alias = task(205, 3);
        let dirty_executor = executor(20_301);
        let (resources, _) = resources(root, 2);
        let resources = Arc::new(resources);
        resources.publish_shared_child(root, exec_child).unwrap();
        let predecessor = resources.lease(exec_child).unwrap();
        let trace = ExecDispositionSettlementTrace::default();
        let reservation = resources
            .reserve_exec_with_settlement_trace_for_tests(exec_child, trace.clone())
            .unwrap();
        assert!(reservation.disposition() == ExecMmDispositionKind::RetainOldMm);
        let mut load = reservation
            .begin_replacement_asid_load(dirty_executor)
            .unwrap();
        load.arm_hardware_dirty().unwrap();
        load.mark_resident().unwrap();
        drop(reservation);

        assert_eq!(
            trace.snapshot(),
            vec![
                ExecDispositionSettlementStep::ReplacementSettled,
                ExecDispositionSettlementStep::MarkerCleared,
            ]
        );
        assert!(Arc::ptr_eq(
            &resources.lease(exec_child).unwrap(),
            &predecessor
        ));
        resources
            .publish_shared_child(root, post_drop_alias)
            .unwrap();
        assert!(matches!(
            resources.prepare_child(),
            Err(MmResourcesError::AsidExhausted)
        ));
    }
}
