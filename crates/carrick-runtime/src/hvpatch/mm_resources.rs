use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use parking_lot::Mutex;

use super::asid::AsidError;
use super::stage1_mm::{
    PreparedStage1Mm, Stage1MmBackend, Stage1MmError, Stage1MmLease, Stage1MmPool,
    Stage1MmRetirement,
};
use crate::kernel::{Stage1RootError, TaskKey};

#[derive(Debug)]
pub(crate) struct RetiredStage1Mm {
    retirement: Option<Stage1MmRetirement>,
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
    /// Permanent within one runtime: exact-generation tombstones make delayed
    /// duplicate cleanup idempotent without permitting a reused numeric PID to
    /// target its successor's root-slot/ASID lease.
    retired: BTreeSet<TaskKey>,
}

#[derive(Debug)]
pub(crate) struct MmResources {
    state: Mutex<MmResourceState>,
    pending_root: Mutex<Option<Arc<Stage1MmLease>>>,
    mm_pool: Stage1MmPool,
}

impl MmResources {
    pub(crate) fn new_root(
        stage1_root: u64,
    ) -> Result<(Self, Arc<Stage1MmBackend>), MmResourcesError> {
        let (mm_pool, root_mm) = Stage1MmPool::new_root(stage1_root)?;
        let backend = root_mm.backend();
        Ok((
            Self {
                state: Mutex::new(MmResourceState::default()),
                pending_root: Mutex::new(Some(root_mm)),
                mm_pool,
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
                pending_root: Mutex::new(Some(root_mm)),
                mm_pool,
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

    #[cfg(test)]
    pub(crate) fn publish_shared_child(
        &self,
        parent: TaskKey,
        child: TaskKey,
    ) -> Result<Arc<Stage1MmBackend>, MmResourcesError> {
        let mut state = self.state.lock();
        if state.leases.contains_key(&child) || state.retired.contains(&child) {
            return Err(MmResourcesError::DuplicateTask(child));
        }
        let lease = state
            .leases
            .get(&parent)
            .cloned()
            .ok_or(MmResourcesError::UnknownTask(parent))?;
        let backend = lease.backend();
        state.leases.insert(child, lease);
        Ok(backend)
    }

    pub(crate) fn root_slot(&self, task: TaskKey) -> Option<super::stage1_mm::Stage1RootSlot> {
        self.state
            .lock()
            .leases
            .get(&task)
            .and_then(|lease| lease.root_slot())
    }

    pub(crate) fn publish_exec(
        &self,
        task: TaskKey,
        new_stage1_root: u64,
    ) -> Result<crate::kernel::MmBinding, MmResourcesError> {
        let lease = self
            .state
            .lock()
            .leases
            .get(&task)
            .cloned()
            .ok_or(MmResourcesError::UnknownTask(task))?;
        lease
            .publish_stage1_root(new_stage1_root)
            .map_err(Into::into)
    }

    /// Detach one exact task generation from its prototype mm. Shared-mm clones
    /// merely release their edge; the final owner performs ASID/root-slot retirement.
    /// A repeated cleanup for the same retired generation is idempotent.
    pub(crate) fn retire(&self, task: TaskKey) -> Result<RetiredStage1Mm, MmResourcesError> {
        let mut state = self.state.lock();
        if state.retired.contains(&task) {
            return Ok(RetiredStage1Mm { retirement: None });
        }
        let lease = state
            .leases
            .get(&task)
            .cloned()
            .ok_or(MmResourcesError::UnknownTask(task))?;
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
        Ok(RetiredStage1Mm { retirement })
    }

    /// K1's prototype still self-acknowledges because the signed multi-vCPU TLB
    /// retirement proof is not available until K3. Keeping this call explicit
    /// preserves the honest RED debt rather than forging a proof token.
    pub(crate) fn acknowledge_tlb_flush(
        &self,
        retired: RetiredStage1Mm,
    ) -> Result<(), MmResourcesError> {
        if let Some(retirement) = retired.retirement {
            self.mm_pool.acknowledge_tlb_flush(retirement)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use super::*;
    use crate::kernel::{TaskId, TaskSerial};

    fn task(raw: i32, serial: u64) -> TaskKey {
        TaskKey {
            id: TaskId::for_root_bootstrap(raw).unwrap(),
            serial: TaskSerial::from_registry_allocation(NonZeroU64::new(serial).unwrap()),
        }
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
        resources.acknowledge_tlb_flush(retired).unwrap();
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

        let retired = resources.retire(child).unwrap();
        resources.acknowledge_tlb_flush(retired).unwrap();
        assert_eq!(backend.binding().stage1_root.gpa().raw(), 0x4000);
        assert!(resources.prepare_child().is_ok());
    }

    #[test]
    fn exec_publishes_a_new_binding_without_mutating_the_old_observer() {
        let root = task(70, 1);
        let (resources, backend) = resources(root, 2);
        let old = backend.binding();
        let replacement = resources.publish_exec(root, 0xc000).unwrap();
        assert_eq!(replacement.asid, old.asid);
        assert_eq!(replacement.stage1_root.gpa().raw(), 0xc000);
        assert_eq!(backend.binding(), old);
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
        resources.acknowledge_tlb_flush(retired).unwrap();

        let replacement_backend = resources
            .publish_child(replacement, resources.prepare_child().unwrap())
            .unwrap();
        let replacement_binding = replacement_backend.binding();
        assert_eq!(replacement_binding.asid, old_binding.asid);

        let duplicate = resources.retire(old).unwrap();
        resources.acknowledge_tlb_flush(duplicate).unwrap();
        assert_eq!(replacement_backend.binding(), replacement_binding);
        assert!(matches!(
            resources.publish_exec(old, 0xd000),
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
}
