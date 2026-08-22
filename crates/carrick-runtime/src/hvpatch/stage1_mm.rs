use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::{Mutex, RwLock};

use super::asid::{
    AsidAllocator, AsidError, AsidGeneration, AsidLoad, AsidResidency, AsidResidencyError,
    AsidRetirement, InvalidationAck, RetiredAsid,
};
use crate::kernel::{
    MmBackend, MmBackendSnapshot, MmBinding, SharedVmaSnapshotSource, SnapshotError, SnapshotTable,
    Stage1Root, Stage1RootError, Ttbr0, VmaRevision,
};

/// Per-mm stage-1 table backing. Guest frames never live in this slot.
const STAGE1_ROOT_SLOT_SIZE: u64 = 2 * 1024 * 1024;
const STAGE1_ROOT_SLOT_COUNT: u32 =
    (carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_ARENA_SIZE / STAGE1_ROOT_SLOT_SIZE) as u32;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct Stage1RootSlot(u32);

impl Stage1RootSlot {
    pub(crate) fn base(self) -> u64 {
        carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE
            + u64::from(self.0) * STAGE1_ROOT_SLOT_SIZE
    }

    pub(crate) fn size(self) -> u64 {
        STAGE1_ROOT_SLOT_SIZE
    }
}

#[derive(Debug)]
pub(crate) struct Stage1MmState {
    binding: RwLock<MmBinding>,
    asid_generation: AsidGeneration,
}

impl Stage1MmState {
    fn new(binding: MmBinding, asid_generation: AsidGeneration) -> Self {
        Self {
            binding: RwLock::new(binding),
            asid_generation,
        }
    }

    pub(crate) fn binding(&self) -> MmBinding {
        *self.binding.read()
    }

    fn publish_binding(&self, binding: MmBinding) {
        *self.binding.write() = binding;
    }
}

#[derive(Debug)]
pub(crate) struct Stage1MmLease {
    state: Arc<Stage1MmState>,
    backend: Arc<Stage1MmBackend>,
    asid: AsidGeneration,
    residency: AsidResidency,
    root_slot: Option<Stage1RootSlot>,
    retired: AtomicBool,
}

impl Stage1MmLease {
    fn new(
        asid: AsidGeneration,
        stage1_root: Stage1Root,
        root_slot: Option<Stage1RootSlot>,
    ) -> Self {
        let state = Arc::new(Stage1MmState::new(
            MmBinding {
                asid: asid.asid(),
                stage1_root,
                ttbr0: Ttbr0::for_aarch64(asid.asid(), stage1_root),
            },
            asid,
        ));
        let backend = Arc::new(Stage1MmBackend::new(Arc::clone(&state)));
        Self {
            state,
            backend,
            asid,
            residency: AsidResidency::new(asid),
            root_slot,
            retired: AtomicBool::new(false),
        }
    }

    pub(crate) fn binding(&self) -> MmBinding {
        self.state.binding()
    }

    pub(crate) fn root_slot(&self) -> Option<Stage1RootSlot> {
        self.root_slot
    }

    pub(crate) fn backend(&self) -> Arc<Stage1MmBackend> {
        Arc::clone(&self.backend)
    }

    pub(crate) const fn asid_generation(&self) -> AsidGeneration {
        self.asid
    }

    pub(crate) fn begin_asid_load(
        &self,
        executor: crate::kernel::objects::ExecutorId,
    ) -> Result<AsidLoad, AsidResidencyError> {
        self.residency.begin_load(executor)
    }

    pub(crate) fn publish_stage1_root(&self, stage1_root: u64) -> Result<MmBinding, Stage1MmError> {
        if self.retired.load(Ordering::Acquire) {
            return Err(Stage1MmError::Retired);
        }
        let stage1_root = Stage1Root::for_aarch64_4k(carrick_guest_mem::Gpa(stage1_root))?;
        let binding = MmBinding {
            asid: self.asid.asid(),
            stage1_root,
            ttbr0: Ttbr0::for_aarch64(self.asid.asid(), stage1_root),
        };
        self.state.publish_binding(binding);
        Ok(binding)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Stage1MmPool {
    inner: Arc<Mutex<Stage1MmPoolInner>>,
}

#[derive(Debug)]
struct Stage1MmPoolInner {
    asids: AsidAllocator,
    free_root_slots: BTreeSet<Stage1RootSlot>,
}

impl Stage1MmPool {
    pub(crate) fn new_root(stage1_root: u64) -> Result<(Self, Arc<Stage1MmLease>), Stage1MmError> {
        Self::with_allocator(stage1_root, AsidAllocator::new())
    }

    #[cfg(test)]
    pub(crate) fn new_root_for_tests(
        stage1_root: u64,
        asid_limit: u16,
    ) -> Result<(Self, Arc<Stage1MmLease>), Stage1MmError> {
        Self::with_allocator(stage1_root, AsidAllocator::with_limit_for_tests(asid_limit))
    }

    fn with_allocator(
        stage1_root: u64,
        mut asids: AsidAllocator,
    ) -> Result<(Self, Arc<Stage1MmLease>), Stage1MmError> {
        let asid = asids.allocate()?;
        let stage1_root = Stage1Root::for_aarch64_4k(carrick_guest_mem::Gpa(stage1_root))?;
        let root = Arc::new(Stage1MmLease::new(asid, stage1_root, None));
        Ok((
            Self {
                inner: Arc::new(Mutex::new(Stage1MmPoolInner {
                    asids,
                    free_root_slots: (0..STAGE1_ROOT_SLOT_COUNT).map(Stage1RootSlot).collect(),
                })),
            },
            root,
        ))
    }

    pub(crate) fn prepare_child(&self) -> Result<PreparedStage1Mm, Stage1MmError> {
        let mut inner = self.inner.lock();
        let root_slot = inner
            .free_root_slots
            .pop_first()
            .ok_or(Stage1MmError::RootSlotExhausted)?;
        let stage1_root = match Stage1Root::for_aarch64_4k(carrick_guest_mem::Gpa(root_slot.base()))
        {
            Ok(root) => root,
            Err(error) => {
                inner.free_root_slots.insert(root_slot);
                return Err(error.into());
            }
        };
        let asid = match inner.asids.allocate() {
            Ok(asid) => asid,
            Err(error) => {
                inner.free_root_slots.insert(root_slot);
                return Err(error.into());
            }
        };
        let lease = Arc::new(Stage1MmLease::new(asid, stage1_root, Some(root_slot)));
        drop(inner);
        Ok(PreparedStage1Mm {
            pool: self.clone(),
            lease,
            committed: false,
        })
    }

    fn release_unpublished(&self, lease: &Stage1MmLease) -> Result<(), Stage1MmError> {
        let mut inner = self.inner.lock();
        inner.asids.release_unpublished(lease.asid)?;
        if let Some(root_slot) = lease.root_slot {
            inner.free_root_slots.insert(root_slot);
        }
        Ok(())
    }

    pub(crate) fn retire(
        &self,
        lease: &Stage1MmLease,
    ) -> Result<Stage1MmRetirement, Stage1MmError> {
        lease
            .retired
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Stage1MmError::Retired)?;
        let residency = lease.residency.begin_retirement()?;
        let mut inner = self.inner.lock();
        let asid = match inner.asids.retire(lease.asid) {
            Ok(asid) => asid,
            Err(error) => {
                return Err(error.into());
            }
        };
        Ok(Stage1MmRetirement {
            pool: self.clone(),
            asid,
            residency,
            root_slot: lease.root_slot,
        })
    }

    pub(crate) fn acknowledge_tlb_flush(
        &self,
        retirement: Stage1MmRetirement,
    ) -> Result<(), Stage1MmError> {
        if !Arc::ptr_eq(&self.inner, &retirement.pool.inner) {
            return Err(Stage1MmError::ForeignRetirement);
        }
        retirement.complete()
    }
}

#[derive(Debug)]
pub(crate) struct PreparedStage1Mm {
    pool: Stage1MmPool,
    lease: Arc<Stage1MmLease>,
    committed: bool,
}

impl PreparedStage1Mm {
    pub(crate) fn binding(&self) -> MmBinding {
        self.lease.binding()
    }

    pub(crate) fn root_slot(&self) -> Option<Stage1RootSlot> {
        self.lease.root_slot()
    }

    pub(crate) fn backend(&self) -> Arc<Stage1MmBackend> {
        self.lease.backend()
    }

    pub(crate) fn publish_stage1_root(&self, stage1_root: u64) -> Result<MmBinding, Stage1MmError> {
        self.lease.publish_stage1_root(stage1_root)
    }

    pub(crate) fn asid_generation(&self) -> AsidGeneration {
        self.lease.asid_generation()
    }

    pub(crate) fn begin_asid_load(
        &self,
        executor: crate::kernel::objects::ExecutorId,
    ) -> Result<AsidLoad, AsidResidencyError> {
        self.lease.begin_asid_load(executor)
    }

    pub(crate) fn commit(mut self) -> Arc<Stage1MmLease> {
        self.committed = true;
        Arc::clone(&self.lease)
    }
}

impl Drop for PreparedStage1Mm {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if let Err(error) = self.pool.release_unpublished(&self.lease) {
            tracing::error!(%error, "failed to release unpublished hvpatch mm root slot");
        }
    }
}

#[derive(Debug)]
pub(crate) struct Stage1MmRetirement {
    pool: Stage1MmPool,
    asid: RetiredAsid,
    residency: AsidRetirement,
    root_slot: Option<Stage1RootSlot>,
}

impl Stage1MmRetirement {
    pub(crate) fn asid_generation(&self) -> AsidGeneration {
        self.residency.generation()
    }

    pub(crate) fn pending(&self) -> Vec<crate::kernel::objects::ExecutorId> {
        self.residency.pending()
    }

    pub(crate) fn acknowledge(&self, ack: InvalidationAck) -> Result<(), AsidResidencyError> {
        self.residency.acknowledge(ack)
    }

    pub(crate) fn complete(self) -> Result<(), Stage1MmError> {
        if !self.residency.is_complete() {
            return Err(Stage1MmError::RetirementIncomplete);
        }
        let mut inner = self.pool.inner.lock();
        inner.asids.acknowledge_tlb_flush(self.asid)?;
        if let Some(root_slot) = self.root_slot {
            inner.free_root_slots.insert(root_slot);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum Stage1MmError {
    #[error("guest ASID space is exhausted")]
    AsidExhausted,
    #[error(transparent)]
    Asid(AsidError),
    #[error(transparent)]
    Stage1Root(#[from] Stage1RootError),
    #[error("all hvpatch stage-1 root slots are live or awaiting TLB-safe reuse")]
    RootSlotExhausted,
    #[error("hvpatch stage-1 mm is already retired")]
    Retired,
    #[error("hvpatch stage-1 mm retirement still awaits executor invalidation")]
    RetirementIncomplete,
    #[error("hvpatch stage-1 retirement belongs to another allocator")]
    ForeignRetirement,
    #[error(transparent)]
    Residency(#[from] AsidResidencyError),
}

impl From<AsidError> for Stage1MmError {
    fn from(error: AsidError) -> Self {
        match error {
            AsidError::Exhausted => Self::AsidExhausted,
            other => Self::Asid(other),
        }
    }
}

/// Live K1 observation seam over each ASID-owned stage-1 root.
/// MmResources publishes every binding into this stable per-mm state before
/// lifecycle retirement, so draining objects cannot follow PID reuse or regress
/// to an older root under concurrent observation.
#[derive(Debug)]
pub(crate) struct Stage1MmBackend {
    binding: RwLock<MmBinding>,
    asid_generation: AsidGeneration,
    inventory: RwLock<Option<InventoryBinding>>,
    vma_source: RwLock<Option<SharedVmaSnapshotSource>>,
    revision: AtomicU64,
}

#[derive(Debug)]
struct InventoryBinding {
    kernel: std::sync::Weak<crate::kernel::Kernel>,
    mm: crate::kernel::MmId,
}

impl Stage1MmBackend {
    pub(crate) fn new(state: Arc<Stage1MmState>) -> Self {
        Self::for_binding(state.binding(), state.asid_generation)
    }

    fn for_binding(binding: MmBinding, asid_generation: AsidGeneration) -> Self {
        Self {
            binding: RwLock::new(binding),
            asid_generation,
            inventory: RwLock::new(None),
            vma_source: RwLock::new(None),
            revision: AtomicU64::new(1),
        }
    }

    pub(crate) fn asid_generation(&self) -> AsidGeneration {
        self.asid_generation
    }

    pub(crate) fn publish_binding(&self, binding: MmBinding) {
        let mut current = self.binding.write();
        *current = binding;
        self.bump_revision();
    }

    pub(crate) fn bind_inventory(
        &self,
        kernel: &Arc<crate::kernel::Kernel>,
        mm: crate::kernel::MmId,
    ) {
        let mut inventory = self.inventory.write();
        *inventory = Some(InventoryBinding {
            kernel: Arc::downgrade(kernel),
            mm,
        });
        self.bump_revision();
    }

    pub(crate) fn bind_vma_source(&self, source: SharedVmaSnapshotSource) {
        *self.vma_source.write() = Some(source);
        self.bump_revision();
    }

    /// Capture the old image without detaching the still-live backend. The
    /// caller publishes this only after engine replacement is irreversible, so
    /// every earlier exec error leaves the old mm following live VMA updates.
    pub(crate) fn prepare_vma_freeze(
        &self,
        deadline: Instant,
    ) -> Result<PreparedVmaFreeze, SnapshotError> {
        let source = self
            .vma_source
            .try_read_until(deadline)
            .ok_or_else(|| deadline_error(deadline))?
            .clone()
            .ok_or(SnapshotError::AuthorityUnavailable(SnapshotTable::Vmas))?;
        let snapshot = source.snapshot(deadline)?;
        if source.revision() != snapshot.revision {
            return Err(SnapshotError::ChangedDuringObservation);
        }
        let expected_revision = snapshot.revision;
        Ok(PreparedVmaFreeze {
            source,
            snapshot,
            expected_revision,
        })
    }

    #[cfg(test)]
    pub(crate) fn inventory_mm_for_tests(&self) -> Option<crate::kernel::MmId> {
        self.inventory.read().as_ref().map(|binding| binding.mm)
    }

    pub(crate) fn binding(&self) -> MmBinding {
        *self.binding.read()
    }

    fn bump_revision(&self) {
        if self.revision.fetch_add(1, Ordering::Release) == u64::MAX {
            std::process::abort();
        }
    }
}

#[derive(Debug)]
pub(crate) struct PreparedVmaFreeze {
    source: SharedVmaSnapshotSource,
    snapshot: crate::kernel::OwnedVmaSnapshot,
    expected_revision: crate::kernel::VmaRevision,
}

impl PreparedVmaFreeze {
    /// Accept the caller's deliberate exec-image staging mutations while
    /// retaining the pre-staging snapshot for the historical MM.
    pub(crate) fn acknowledge_staged_revision(
        &mut self,
        deadline: Instant,
    ) -> Result<(), SnapshotError> {
        self.expected_revision = self.source.snapshot(deadline)?.revision;
        Ok(())
    }

    pub(crate) fn validate(
        &self,
        backend: &Stage1MmBackend,
        deadline: Instant,
    ) -> Result<(), SnapshotError> {
        self.source
            .publish_if_revision(self.expected_revision, deadline, &mut || {
                let slot = backend
                    .vma_source
                    .try_read_until(deadline)
                    .ok_or_else(|| deadline_error(deadline))?;
                let Some(current) = slot.as_ref() else {
                    return Err(SnapshotError::AuthorityUnavailable(SnapshotTable::Vmas));
                };
                if !Arc::ptr_eq(current, &self.source) {
                    return Err(SnapshotError::ChangedDuringObservation);
                }
                Ok(())
            })
    }

    pub(crate) fn commit(
        self,
        backend: &Stage1MmBackend,
        deadline: Instant,
    ) -> Result<(), SnapshotError> {
        let Self {
            source,
            snapshot,
            expected_revision,
        } = self;
        let mut snapshot = Some(snapshot);
        source.publish_if_revision(expected_revision, deadline, &mut || {
            let mut slot = backend
                .vma_source
                .try_write_until(deadline)
                .ok_or_else(|| deadline_error(deadline))?;
            let Some(current) = slot.as_ref() else {
                return Err(SnapshotError::AuthorityUnavailable(SnapshotTable::Vmas));
            };
            if !Arc::ptr_eq(current, &source) {
                return Err(SnapshotError::ChangedDuringObservation);
            }
            let frozen = snapshot
                .take()
                .ok_or(SnapshotError::ChangedDuringObservation)?;
            *slot = Some(Arc::new(frozen));
            drop(slot);
            backend.bump_revision();
            Ok(())
        })
    }
}

fn deadline_error(deadline: Instant) -> SnapshotError {
    if Instant::now() >= deadline {
        SnapshotError::TimedOut
    } else {
        SnapshotError::Busy
    }
}

impl MmBackend for Stage1MmBackend {
    fn snapshot(&self, deadline: Instant) -> Result<MmBackendSnapshot, SnapshotError> {
        let before = self.revision.load(Ordering::Acquire);
        let binding = {
            let Some(guard) = self.binding.try_read_until(deadline) else {
                return Err(deadline_error(deadline));
            };
            *guard
        };
        let vma_source = self
            .vma_source
            .try_read_until(deadline)
            .ok_or_else(|| deadline_error(deadline))?
            .clone()
            .ok_or(SnapshotError::AuthorityUnavailable(SnapshotTable::Vmas))?;
        let (kernel, mm) = {
            let Some(guard) = self.inventory.try_read_until(deadline) else {
                return Err(deadline_error(deadline));
            };
            let inventory = guard.as_ref().ok_or(SnapshotError::AuthorityUnavailable(
                crate::kernel::SnapshotTable::Mappings,
            ))?;
            let kernel = inventory
                .kernel
                .upgrade()
                .ok_or(SnapshotError::AuthorityUnavailable(
                    crate::kernel::SnapshotTable::Mappings,
                ))?;
            (kernel, inventory.mm)
        };
        // No backend lock is held while either independent authority is
        // observed. This preserves the K1 backend/frame/kernel lock boundary.
        let vma_snapshot = vma_source.snapshot(deadline)?;
        let frame_snapshot = kernel
            .frame_inventory()
            .snapshot_for_mm_until(mm, deadline)
            .ok_or_else(|| {
                if Instant::now() >= deadline {
                    SnapshotError::TimedOut
                } else {
                    SnapshotError::Busy
                }
            })?;
        let after = self.revision.load(Ordering::Acquire);
        if before != after || vma_source.revision() != vma_snapshot.revision {
            return Err(SnapshotError::ChangedDuringObservation);
        }
        Ok(MmBackendSnapshot {
            revision: after,
            binding,
            vmas: vma_snapshot.vmas,
            vma_revision: Some(vma_snapshot.revision),
            mapping_ids: frame_snapshot
                .mappings
                .into_iter()
                .map(|mapping| mapping.mapping)
                .collect(),
            frame_inventory_revision: Some(frame_snapshot.revision),
        })
    }

    fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    fn vma_revision(&self, deadline: Instant) -> Result<Option<VmaRevision>, SnapshotError> {
        Ok(self
            .vma_source
            .try_read_until(deadline)
            .ok_or_else(|| deadline_error(deadline))?
            .as_ref()
            .map(|source| source.revision()))
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use super::super::mm_resources::MmResources;
    use super::*;

    fn root_key() -> crate::kernel::TaskKey {
        crate::kernel::TaskKey {
            id: crate::kernel::TaskId::for_root_bootstrap(40).unwrap(),
            serial: crate::kernel::TaskSerial::from_registry_allocation(
                NonZeroU64::new(1).unwrap(),
            ),
        }
    }

    fn executor(raw: i32) -> crate::kernel::objects::ExecutorId {
        crate::kernel::objects::ExecutorId::for_transitional_thread(
            crate::thread::ThreadId::synthetic_for_tests(raw),
        )
        .expect("test executor id")
    }

    #[test]
    fn old_observer_keeps_its_binding_after_exec_and_retirement() {
        let task = root_key();
        let (table, backend) = MmResources::new_root(0x8000).expect("root table");
        table.publish_root(task).expect("publish root");
        let initial = backend.binding();

        let prepared = table.prepare_exec(task).expect("prepare replacement");
        let replacement_root = prepared.root_slot().expect("root slot").base();
        let (replacement, retired) = table
            .commit_exec(task, prepared, replacement_root)
            .expect("commit replacement");
        assert_ne!(replacement.binding().asid, initial.asid);
        assert_ne!(replacement.binding().stage1_root, initial.stage1_root);
        assert_eq!(
            replacement.binding().ttbr0,
            crate::kernel::Ttbr0::for_aarch64(
                replacement.binding().asid,
                replacement.binding().stage1_root,
            )
        );
        assert_eq!(backend.binding(), initial);
        retired
            .expect("unshared exec retirement")
            .complete()
            .expect("ack retire");
        assert_eq!(backend.binding(), initial);
    }

    #[test]
    fn dropped_preparation_returns_root_slot_and_asid_without_retirement_proof() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 2).expect("root pool");
        let prepared = pool.prepare_child().expect("first preparation");
        let first_binding = prepared.binding();
        let first_root_slot = prepared.root_slot();

        drop(prepared);

        let replacement = pool.prepare_child().expect("replacement preparation");
        assert_eq!(replacement.binding().asid, first_binding.asid);
        assert_eq!(replacement.root_slot(), first_root_slot);
        let lease = replacement.commit();
        let retirement = pool.retire(&lease).expect("retire committed lease");
        pool.acknowledge_tlb_flush(retirement)
            .expect("acknowledge retirement");
    }

    #[test]
    fn committed_mm_reuses_neither_asid_nor_root_until_all_residency_acks() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 2).expect("root pool");
        let prepared = pool.prepare_child().expect("child preparation");
        let binding = prepared.binding();
        let root_slot = prepared.root_slot();
        let lease = prepared.commit();
        lease
            .begin_asid_load(executor(20))
            .expect("executor load")
            .mark_resident()
            .expect("executor resident");
        let retirement = pool.retire(&lease).expect("retire live mm");

        assert_eq!(retirement.pending(), vec![executor(20)]);
        assert_eq!(
            pool.prepare_child().unwrap_err(),
            Stage1MmError::AsidExhausted,
            "numeric ASID and root slot stay quarantined"
        );
        retirement
            .acknowledge(super::super::asid::InvalidationAck::new(
                executor(20),
                retirement.asid_generation(),
            ))
            .expect("owner-thread invalidation ack");
        pool.acknowledge_tlb_flush(retirement)
            .expect("complete retirement");

        let replacement = pool.prepare_child().expect("replacement child");
        assert_eq!(replacement.binding().asid, binding.asid);
        assert_eq!(replacement.root_slot(), root_slot);
        assert_ne!(
            replacement.asid_generation(),
            lease.asid_generation(),
            "numeric reuse must mint a new strong generation"
        );
    }

    #[test]
    fn hvpatch_task_binding_carries_the_exact_shared_mm_residency_authority() {
        struct ExitJob;
        impl crate::vcpu_loop::continuation::PersistentQuantumJob for ExitJob {
            fn poll_quantum_with_engine(
                &mut self,
                _engine: &mut dyn std::any::Any,
                _control: &mut crate::vcpu_loop::executor::HvpatchQuantumControl<'_, '_>,
            ) -> crate::vcpu_loop::executor::ExecutorExit {
                crate::vcpu_loop::executor::ExecutorExit::Exited
            }
        }

        let (pool, lease) = Stage1MmPool::new_root_for_tests(0x8000, 1).expect("root pool");
        let generation = lease.asid_generation();
        let binding = crate::vcpu_loop::continuation::HvpatchTaskBinding::new_with_stage1_mm(
            crate::vcpu_loop::executor::TaskLoadIdentity {
                abi: carrick_abi::LinuxGuestAbi::Aarch64,
                version: 1,
                mm: crate::kernel::MmId::from_registry_allocation(NonZeroU64::new(91).unwrap()),
                asid_generation: generation.generation(),
            },
            Arc::new(crate::vcpu_loop::continuation::HvpatchTaskQuantum::new(
                Box::new(ExitJob),
                crate::vcpu_loop::continuation::LogicalJobCompletion::pending(),
            )),
            Box::new(7_u64),
            Arc::clone(&lease),
        )
        .expect("binding owns exact stage-1 lease");
        binding
            .begin_asid_load(executor(21))
            .expect("binding load authority")
            .mark_resident()
            .expect("binding resident");

        let retirement = pool.retire(&lease).expect("retirement");
        assert_eq!(retirement.pending(), vec![executor(21)]);
        assert_eq!(retirement.asid_generation(), generation);
    }

    #[test]
    fn page_table_root_slots_scale_to_the_complete_arena() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 64).expect("root slot pool");
        let prepared: Vec<_> = (0..32)
            .map(|_| pool.prepare_child().expect("dense page-table root slot"))
            .collect();
        assert_eq!(prepared.len(), 32);
    }

    #[test]
    fn fails_closed_when_vma_authority_is_unbound() {
        let (_table, backend) = MmResources::new_root(0x8000).expect("root table");

        assert_eq!(
            backend.snapshot(Instant::now() + std::time::Duration::from_secs(1)),
            Err(SnapshotError::AuthorityUnavailable(
                crate::kernel::SnapshotTable::Vmas
            ))
        );
    }
}
