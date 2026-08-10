use std::collections::BTreeMap;
use std::sync::Arc;

use parking_lot::Mutex;

use super::asid::AsidError;
use super::banked_mm::{
    BankedMmBackend, BankedMmError, BankedMmLease, BankedMmPool, BankedMmRetirement,
    PreparedBankedMm,
};
use crate::kernel::{Stage1RootError, TaskId};

#[derive(Debug)]
pub(crate) struct RetiredBankedMm {
    retirement: Option<BankedMmRetirement>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum BankResourcesError {
    #[error("guest task {0:?} has no live hvpatch address space")]
    UnknownTask(TaskId),
    #[error("guest ASID space is exhausted")]
    AsidExhausted,
    #[error(transparent)]
    Asid(AsidError),
    #[error(transparent)]
    Stage1Root(#[from] Stage1RootError),
    #[error("all hvpatch process address-space banks are live or awaiting teardown")]
    BankExhausted,
}

impl From<AsidError> for BankResourcesError {
    fn from(error: AsidError) -> Self {
        match error {
            AsidError::Exhausted => Self::AsidExhausted,
            other => Self::Asid(other),
        }
    }
}

impl From<BankedMmError> for BankResourcesError {
    fn from(error: BankedMmError) -> Self {
        match error {
            BankedMmError::AsidExhausted => Self::AsidExhausted,
            BankedMmError::Asid(error) => Self::Asid(error),
            BankedMmError::Stage1Root(error) => Self::Stage1Root(error),
            BankedMmError::BankExhausted | BankedMmError::Retired => Self::BankExhausted,
        }
    }
}

/// Backend-only ownership for HVPatch address-space banks.
///
/// Linux task identity, parentage, groups, sessions, exits, waits, and pidfd
/// readiness live exclusively in [`crate::kernel::Kernel`]. This table retains
/// only the prototype bank/ASID leases that K2 will replace.
#[derive(Debug)]
pub(crate) struct BankResources {
    leases: Mutex<BTreeMap<TaskId, Arc<BankedMmLease>>>,
    mm_pool: BankedMmPool,
}

impl BankResources {
    pub(crate) fn new_root(
        root_id: TaskId,
        stage1_root: u64,
    ) -> Result<(Self, Arc<BankedMmBackend>), BankResourcesError> {
        let (mm_pool, root_mm) = BankedMmPool::new_root(stage1_root)?;
        let backend = root_mm.backend();
        Ok((
            Self {
                leases: Mutex::new(BTreeMap::from([(root_id, root_mm)])),
                mm_pool,
            },
            backend,
        ))
    }

    #[cfg(test)]
    fn new_for_tests(
        root_id: TaskId,
        stage1_root: u64,
        asid_limit: u16,
    ) -> Result<(Self, Arc<BankedMmBackend>), BankResourcesError> {
        let (mm_pool, root_mm) = BankedMmPool::new_root_for_tests(stage1_root, asid_limit)?;
        let backend = root_mm.backend();
        Ok((
            Self {
                leases: Mutex::new(BTreeMap::from([(root_id, root_mm)])),
                mm_pool,
            },
            backend,
        ))
    }

    pub(crate) fn prepare_child(&self) -> Result<PreparedBankedMm, BankResourcesError> {
        self.mm_pool.prepare_child().map_err(Into::into)
    }

    pub(crate) fn publish_child(
        &self,
        task_id: TaskId,
        prepared: PreparedBankedMm,
    ) -> Arc<BankedMmBackend> {
        let lease = prepared.commit();
        let backend = lease.backend();
        let replaced = self.leases.lock().insert(task_id, lease);
        debug_assert!(replaced.is_none(), "kernel published a duplicate task id");
        backend
    }

    #[cfg(test)]
    pub(crate) fn publish_shared_child(
        &self,
        parent_id: TaskId,
        child_id: TaskId,
    ) -> Result<Arc<BankedMmBackend>, BankResourcesError> {
        let mut leases = self.leases.lock();
        let lease = leases
            .get(&parent_id)
            .cloned()
            .ok_or(BankResourcesError::UnknownTask(parent_id))?;
        let backend = lease.backend();
        let replaced = leases.insert(child_id, lease);
        debug_assert!(replaced.is_none(), "kernel published a duplicate task id");
        Ok(backend)
    }

    pub(crate) fn bank(&self, task_id: TaskId) -> Option<super::banked_mm::ProcessBank> {
        self.leases
            .lock()
            .get(&task_id)
            .and_then(|lease| lease.bank())
    }

    pub(crate) fn publish_exec(
        &self,
        task_id: TaskId,
        new_stage1_root: u64,
    ) -> Result<(), BankResourcesError> {
        let lease = self
            .leases
            .lock()
            .get(&task_id)
            .cloned()
            .ok_or(BankResourcesError::UnknownTask(task_id))?;
        lease.publish_stage1_root(new_stage1_root)?;
        Ok(())
    }

    /// Detach a task from its prototype mm. Shared-mm clones merely release
    /// their task-to-lease edge; the final owner performs ASID/bank retirement.
    pub(crate) fn retire(&self, task_id: TaskId) -> Result<RetiredBankedMm, BankResourcesError> {
        let mut leases = self.leases.lock();
        let lease = leases
            .remove(&task_id)
            .ok_or(BankResourcesError::UnknownTask(task_id))?;
        let shared = leases.values().any(|other| Arc::ptr_eq(other, &lease));
        drop(leases);
        let retirement = if shared {
            None
        } else {
            Some(self.mm_pool.retire(&lease)?)
        };
        Ok(RetiredBankedMm { retirement })
    }

    /// K1's prototype still self-acknowledges because the signed multi-vCPU TLB
    /// retirement proof is not available until K3. Keeping this call explicit
    /// preserves the honest RED debt rather than forging a proof token.
    pub(crate) fn acknowledge_tlb_flush(
        &self,
        retired: RetiredBankedMm,
    ) -> Result<(), BankResourcesError> {
        if let Some(retirement) = retired.retirement {
            self.mm_pool.acknowledge_tlb_flush(retirement)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::MmBackend as _;

    fn task(raw: i32) -> TaskId {
        TaskId::for_root_bootstrap(raw).unwrap()
    }

    #[test]
    fn unpublished_child_preparation_rolls_back_bank_and_asid() {
        let (resources, _) = BankResources::new_for_tests(task(40), 0x4000, 2).unwrap();
        let first = resources.prepare_child().unwrap();
        let binding = first.binding();
        drop(first);
        let replacement = resources.prepare_child().unwrap();
        assert_eq!(replacement.binding(), binding);
    }

    #[test]
    fn published_backend_retires_only_after_tlb_acknowledgement() {
        let (resources, _) = BankResources::new_for_tests(task(50), 0x4000, 2).unwrap();
        let child_id = task(51);
        let prepared = resources.prepare_child().unwrap();
        let binding = prepared.binding();
        let backend = resources.publish_child(child_id, prepared);
        assert_eq!(backend.binding(), binding);

        let retired = resources.retire(child_id).unwrap();
        assert!(matches!(
            resources.prepare_child(),
            Err(BankResourcesError::AsidExhausted)
        ));
        resources.acknowledge_tlb_flush(retired).unwrap();
        assert_eq!(
            resources.prepare_child().unwrap().binding().asid,
            binding.asid
        );
    }

    #[test]
    fn shared_mm_child_does_not_retire_parent_lease() {
        let parent = task(60);
        let child = task(61);
        let (resources, backend) = BankResources::new_for_tests(parent, 0x4000, 2).unwrap();
        let shared = resources.publish_shared_child(parent, child).unwrap();
        assert_eq!(shared.binding(), backend.binding());

        let retired = resources.retire(child).unwrap();
        resources.acknowledge_tlb_flush(retired).unwrap();
        assert_eq!(backend.binding().stage1_root.gpa().raw(), 0x4000);
        assert!(resources.prepare_child().is_ok());
    }

    #[test]
    fn exec_rebinds_existing_backend_without_replacing_asid() {
        let root = task(70);
        let (resources, backend) = BankResources::new_for_tests(root, 0x4000, 2).unwrap();
        let asid = backend.binding().asid;
        resources.publish_exec(root, 0xc000).unwrap();
        assert_eq!(backend.binding().asid, asid);
        assert_eq!(backend.binding().stage1_root.gpa().raw(), 0xc000);
    }
}
