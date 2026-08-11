use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use parking_lot::Mutex;

use super::asid::AsidError;
use super::banked_mm::{
    BankedMmBackend, BankedMmError, BankedMmLease, BankedMmPool, BankedMmRetirement,
    PreparedBankedMm,
};
use crate::kernel::{Stage1RootError, TaskKey};

#[derive(Debug)]
pub(crate) struct RetiredBankedMm {
    retirement: Option<BankedMmRetirement>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum BankResourcesError {
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
#[derive(Debug, Default)]
struct BankResourceState {
    leases: BTreeMap<TaskKey, Arc<BankedMmLease>>,
    /// Permanent within one runtime: exact-generation tombstones make delayed
    /// duplicate cleanup idempotent without permitting a reused numeric PID to
    /// target its successor's bank.
    retired: BTreeSet<TaskKey>,
}

#[derive(Debug)]
pub(crate) struct BankResources {
    state: Mutex<BankResourceState>,
    pending_root: Mutex<Option<Arc<BankedMmLease>>>,
    mm_pool: BankedMmPool,
}

impl BankResources {
    pub(crate) fn new_root(
        stage1_root: u64,
    ) -> Result<(Self, Arc<BankedMmBackend>), BankResourcesError> {
        let (mm_pool, root_mm) = BankedMmPool::new_root(stage1_root)?;
        let backend = root_mm.backend();
        Ok((
            Self {
                state: Mutex::new(BankResourceState::default()),
                pending_root: Mutex::new(Some(root_mm)),
                mm_pool,
            },
            backend,
        ))
    }

    pub(crate) fn publish_root(&self, root: TaskKey) -> Result<(), BankResourcesError> {
        let mut state = self.state.lock();
        if state.leases.contains_key(&root) || state.retired.contains(&root) {
            return Err(BankResourcesError::DuplicateTask(root));
        }
        let lease = self
            .pending_root
            .lock()
            .take()
            .ok_or(BankResourcesError::RootAlreadyPublished)?;
        state.leases.insert(root, lease);
        Ok(())
    }

    #[cfg(test)]
    fn new_for_tests(
        stage1_root: u64,
        asid_limit: u16,
    ) -> Result<(Self, Arc<BankedMmBackend>), BankResourcesError> {
        let (mm_pool, root_mm) = BankedMmPool::new_root_for_tests(stage1_root, asid_limit)?;
        let backend = root_mm.backend();
        Ok((
            Self {
                state: Mutex::new(BankResourceState::default()),
                pending_root: Mutex::new(Some(root_mm)),
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
        task: TaskKey,
        prepared: PreparedBankedMm,
    ) -> Result<Arc<BankedMmBackend>, BankResourcesError> {
        let mut state = self.state.lock();
        if state.leases.contains_key(&task) || state.retired.contains(&task) {
            return Err(BankResourcesError::DuplicateTask(task));
        }
        // Commit only after the exact-generation vacancy check. On rejection,
        // dropping `prepared` returns its ASID/bank reservation to the pool.
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
    ) -> Result<Arc<BankedMmBackend>, BankResourcesError> {
        let mut state = self.state.lock();
        if state.leases.contains_key(&child) || state.retired.contains(&child) {
            return Err(BankResourcesError::DuplicateTask(child));
        }
        let lease = state
            .leases
            .get(&parent)
            .cloned()
            .ok_or(BankResourcesError::UnknownTask(parent))?;
        let backend = lease.backend();
        state.leases.insert(child, lease);
        Ok(backend)
    }

    pub(crate) fn bank(&self, task: TaskKey) -> Option<super::banked_mm::ProcessBank> {
        self.state
            .lock()
            .leases
            .get(&task)
            .and_then(|lease| lease.bank())
    }

    pub(crate) fn publish_exec(
        &self,
        task: TaskKey,
        new_stage1_root: u64,
    ) -> Result<crate::kernel::MmBinding, BankResourcesError> {
        let lease = self
            .state
            .lock()
            .leases
            .get(&task)
            .cloned()
            .ok_or(BankResourcesError::UnknownTask(task))?;
        lease
            .publish_stage1_root(new_stage1_root)
            .map_err(Into::into)
    }

    /// Detach one exact task generation from its prototype mm. Shared-mm clones
    /// merely release their edge; the final owner performs ASID/bank retirement.
    /// A repeated cleanup for the same retired generation is idempotent.
    pub(crate) fn retire(&self, task: TaskKey) -> Result<RetiredBankedMm, BankResourcesError> {
        let mut state = self.state.lock();
        if state.retired.contains(&task) {
            return Ok(RetiredBankedMm { retirement: None });
        }
        let lease = state
            .leases
            .get(&task)
            .cloned()
            .ok_or(BankResourcesError::UnknownTask(task))?;
        let shared = state
            .leases
            .iter()
            .any(|(other_task, other)| *other_task != task && Arc::ptr_eq(other, &lease));
        let retirement = if shared {
            None
        } else {
            // Do not tombstone an exact generation until the fallible pool
            // retirement succeeds. A failed attempt must remain retryable and
            // its bank/ASID must stay live rather than becoming reusable.
            Some(self.mm_pool.retire(&lease)?)
        };
        state.leases.remove(&task);
        state.retired.insert(task);
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
    use std::num::NonZeroU64;

    use super::*;
    use crate::kernel::{TaskId, TaskSerial};

    fn task(raw: i32, serial: u64) -> TaskKey {
        TaskKey {
            id: TaskId::for_root_bootstrap(raw).unwrap(),
            serial: TaskSerial::from_registry_allocation(NonZeroU64::new(serial).unwrap()),
        }
    }

    fn resources(root: TaskKey, asid_limit: u16) -> (BankResources, Arc<BankedMmBackend>) {
        let (resources, backend) = BankResources::new_for_tests(0x4000, asid_limit).unwrap();
        resources.publish_root(root).unwrap();
        (resources, backend)
    }

    #[test]
    fn unpublished_child_preparation_rolls_back_bank_and_asid() {
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
            Err(BankResourcesError::UnknownTask(key)) if key == old
        ));
        assert_eq!(replacement_backend.binding(), replacement_binding);
    }

    #[test]
    fn duplicate_exact_generation_does_not_consume_prepared_bank() {
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
            Err(BankResourcesError::DuplicateTask(key)) if key == child
        ));
        assert_eq!(
            resources.prepare_child().unwrap().binding(),
            duplicate_binding
        );
    }
}
