use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::{Mutex, RwLock};

use super::asid::{AsidAllocator, AsidError, RetiredAsid};
use crate::kernel::{
    Asid, MmBackend, MmBackendSnapshot, MmBinding, SharedVmaSnapshotSource, SnapshotError,
    SnapshotTable, Stage1Root, Stage1RootError, Ttbr0, VmaRevision,
};

const PROCESS_BANK_SIZE: u64 = 40 * 1024 * 1024 * 1024;
const PROCESS_BANK_COUNT: u8 =
    1 + (carrick_mem::memory::LINUX_PROCESS_BANK_SIZE / PROCESS_BANK_SIZE) as u8;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ProcessBank(u8);

impl ProcessBank {
    pub(crate) fn base(self) -> u64 {
        if self.0 == 0 {
            carrick_mem::memory::LINUX_PROCESS_AUX_BANK_BASE
        } else {
            carrick_mem::memory::LINUX_PROCESS_BANK_BASE + u64::from(self.0 - 1) * PROCESS_BANK_SIZE
        }
    }

    pub(crate) fn size(self) -> u64 {
        PROCESS_BANK_SIZE
    }
}

#[derive(Debug)]
pub(crate) struct BankedMmState {
    binding: RwLock<MmBinding>,
}

impl BankedMmState {
    fn new(binding: MmBinding) -> Self {
        Self {
            binding: RwLock::new(binding),
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
pub(crate) struct BankedMmLease {
    state: Arc<BankedMmState>,
    backend: Arc<BankedMmBackend>,
    asid: Asid,
    bank: Option<ProcessBank>,
    retired: AtomicBool,
}

impl BankedMmLease {
    fn new(asid: Asid, stage1_root: Stage1Root, bank: Option<ProcessBank>) -> Self {
        let state = Arc::new(BankedMmState::new(MmBinding {
            asid,
            stage1_root,
            ttbr0: Ttbr0::for_aarch64(asid, stage1_root),
        }));
        let backend = Arc::new(BankedMmBackend::new(Arc::clone(&state)));
        Self {
            state,
            backend,
            asid,
            bank,
            retired: AtomicBool::new(false),
        }
    }

    pub(crate) fn binding(&self) -> MmBinding {
        self.state.binding()
    }

    pub(crate) fn bank(&self) -> Option<ProcessBank> {
        self.bank
    }

    pub(crate) fn backend(&self) -> Arc<BankedMmBackend> {
        Arc::clone(&self.backend)
    }

    pub(crate) fn publish_stage1_root(&self, stage1_root: u64) -> Result<MmBinding, BankedMmError> {
        if self.retired.load(Ordering::Acquire) {
            return Err(BankedMmError::Retired);
        }
        let stage1_root = Stage1Root::for_aarch64_4k(carrick_guest_mem::Gpa(stage1_root))?;
        let binding = MmBinding {
            asid: self.asid,
            stage1_root,
            ttbr0: Ttbr0::for_aarch64(self.asid, stage1_root),
        };
        self.state.publish_binding(binding);
        Ok(binding)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct BankedMmPool {
    inner: Arc<Mutex<BankedMmPoolInner>>,
}

#[derive(Debug)]
struct BankedMmPoolInner {
    asids: AsidAllocator,
    free_banks: BTreeSet<ProcessBank>,
}

impl BankedMmPool {
    pub(crate) fn new_root(stage1_root: u64) -> Result<(Self, Arc<BankedMmLease>), BankedMmError> {
        Self::with_allocator(stage1_root, AsidAllocator::new())
    }

    #[cfg(test)]
    pub(crate) fn new_root_for_tests(
        stage1_root: u64,
        asid_limit: u16,
    ) -> Result<(Self, Arc<BankedMmLease>), BankedMmError> {
        Self::with_allocator(stage1_root, AsidAllocator::with_limit_for_tests(asid_limit))
    }

    fn with_allocator(
        stage1_root: u64,
        mut asids: AsidAllocator,
    ) -> Result<(Self, Arc<BankedMmLease>), BankedMmError> {
        let asid = asids.allocate()?;
        let stage1_root = Stage1Root::for_aarch64_4k(carrick_guest_mem::Gpa(stage1_root))?;
        let root = Arc::new(BankedMmLease::new(asid, stage1_root, None));
        Ok((
            Self {
                inner: Arc::new(Mutex::new(BankedMmPoolInner {
                    asids,
                    free_banks: (0..PROCESS_BANK_COUNT).map(ProcessBank).collect(),
                })),
            },
            root,
        ))
    }

    pub(crate) fn prepare_child(&self) -> Result<PreparedBankedMm, BankedMmError> {
        let mut inner = self.inner.lock();
        let bank = inner
            .free_banks
            .pop_first()
            .ok_or(BankedMmError::BankExhausted)?;
        let stage1_root = match Stage1Root::for_aarch64_4k(carrick_guest_mem::Gpa(bank.base())) {
            Ok(root) => root,
            Err(error) => {
                inner.free_banks.insert(bank);
                return Err(error.into());
            }
        };
        let asid = match inner.asids.allocate() {
            Ok(asid) => asid,
            Err(error) => {
                inner.free_banks.insert(bank);
                return Err(error.into());
            }
        };
        let lease = Arc::new(BankedMmLease::new(asid, stage1_root, Some(bank)));
        drop(inner);
        Ok(PreparedBankedMm {
            pool: self.clone(),
            lease,
            committed: false,
        })
    }

    fn release_unpublished(&self, lease: &BankedMmLease) -> Result<(), BankedMmError> {
        let mut inner = self.inner.lock();
        inner.asids.release_unpublished(lease.asid)?;
        if let Some(bank) = lease.bank {
            inner.free_banks.insert(bank);
        }
        Ok(())
    }

    pub(crate) fn retire(
        &self,
        lease: &BankedMmLease,
    ) -> Result<BankedMmRetirement, BankedMmError> {
        lease
            .retired
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| BankedMmError::Retired)?;
        let mut inner = self.inner.lock();
        let asid = match inner.asids.retire(lease.asid) {
            Ok(asid) => asid,
            Err(error) => {
                lease.retired.store(false, Ordering::Release);
                return Err(error.into());
            }
        };
        Ok(BankedMmRetirement {
            asid,
            bank: lease.bank,
        })
    }

    pub(crate) fn acknowledge_tlb_flush(
        &self,
        retirement: BankedMmRetirement,
    ) -> Result<(), BankedMmError> {
        let mut inner = self.inner.lock();
        inner.asids.acknowledge_tlb_flush(retirement.asid)?;
        if let Some(bank) = retirement.bank {
            inner.free_banks.insert(bank);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct PreparedBankedMm {
    pool: BankedMmPool,
    lease: Arc<BankedMmLease>,
    committed: bool,
}

impl PreparedBankedMm {
    pub(crate) fn binding(&self) -> MmBinding {
        self.lease.binding()
    }

    pub(crate) fn bank(&self) -> Option<ProcessBank> {
        self.lease.bank()
    }

    pub(crate) fn backend(&self) -> Arc<BankedMmBackend> {
        self.lease.backend()
    }

    pub(crate) fn commit(mut self) -> Arc<BankedMmLease> {
        self.committed = true;
        Arc::clone(&self.lease)
    }
}

impl Drop for PreparedBankedMm {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if let Err(error) = self.pool.release_unpublished(&self.lease) {
            tracing::error!(%error, "failed to release unpublished hvpatch banked mm");
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct BankedMmRetirement {
    asid: RetiredAsid,
    bank: Option<ProcessBank>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum BankedMmError {
    #[error("guest ASID space is exhausted")]
    AsidExhausted,
    #[error(transparent)]
    Asid(AsidError),
    #[error(transparent)]
    Stage1Root(#[from] Stage1RootError),
    #[error("all hvpatch process address-space banks are live or awaiting teardown")]
    BankExhausted,
    #[error("hvpatch banked mm is already retired")]
    Retired,
}

impl From<AsidError> for BankedMmError {
    fn from(error: AsidError) -> Self {
        match error {
            AsidError::Exhausted => Self::AsidExhausted,
            other => Self::Asid(other),
        }
    }
}

/// Live K1 observation seam over the existing per-process-bank prototype.
/// BankResources publishes every binding into this stable per-mm state before
/// lifecycle retirement, so draining objects cannot follow PID reuse or regress
/// to an older root under concurrent observation.
#[derive(Debug)]
pub(crate) struct BankedMmBackend {
    binding: RwLock<MmBinding>,
    inventory: RwLock<Option<InventoryBinding>>,
    vma_source: RwLock<Option<SharedVmaSnapshotSource>>,
    revision: AtomicU64,
}

#[derive(Debug)]
struct InventoryBinding {
    kernel: std::sync::Weak<crate::kernel::Kernel>,
    mm: crate::kernel::MmId,
}

impl BankedMmBackend {
    pub(crate) fn new(state: Arc<BankedMmState>) -> Self {
        Self::for_binding(state.binding())
    }

    fn for_binding(binding: MmBinding) -> Self {
        Self {
            binding: RwLock::new(binding),
            inventory: RwLock::new(None),
            vma_source: RwLock::new(None),
            revision: AtomicU64::new(1),
        }
    }

    pub(crate) fn exec_observer(&self) -> Arc<Self> {
        Arc::new(Self::for_binding(self.binding()))
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

    /// Detach this historical observer from the mutable dispatcher authority.
    /// The owned snapshot remains readable for as long as the old typed `Mm`
    /// is retained, even after destructive exec publishes the replacement.
    pub(crate) fn freeze_vmas(&self, deadline: Instant) -> Result<(), SnapshotError> {
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
        let frozen: SharedVmaSnapshotSource = Arc::new(snapshot);
        *self
            .vma_source
            .try_write_until(deadline)
            .ok_or_else(|| deadline_error(deadline))? = Some(frozen);
        self.bump_revision();
        Ok(())
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

fn deadline_error(deadline: Instant) -> SnapshotError {
    if Instant::now() >= deadline {
        SnapshotError::TimedOut
    } else {
        SnapshotError::Busy
    }
}

impl MmBackend for BankedMmBackend {
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

    fn vma_revision(&self) -> Option<VmaRevision> {
        self.vma_source
            .read()
            .as_ref()
            .map(|source| source.revision())
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use super::super::bank_resources::BankResources;
    use super::*;

    fn root_key() -> crate::kernel::TaskKey {
        crate::kernel::TaskKey {
            id: crate::kernel::TaskId::for_root_bootstrap(40).unwrap(),
            serial: crate::kernel::TaskSerial::from_registry_allocation(
                NonZeroU64::new(1).unwrap(),
            ),
        }
    }

    #[test]
    fn old_observer_keeps_its_binding_after_exec_and_retirement() {
        let task = root_key();
        let (table, backend) = BankResources::new_root(0x8000).expect("root table");
        table.publish_root(task).expect("publish root");
        let initial = backend.binding();

        let replaced = table.publish_exec(task, 0xc000).expect("replace root");
        let retired = table.retire(task).expect("retire");
        assert_eq!(replaced.asid, initial.asid);
        assert_ne!(replaced.stage1_root, initial.stage1_root);
        assert_eq!(
            replaced.ttbr0,
            crate::kernel::Ttbr0::for_aarch64(replaced.asid, replaced.stage1_root)
        );
        assert_eq!(backend.binding(), initial);
        table.acknowledge_tlb_flush(retired).expect("ack retire");
        assert_eq!(backend.binding(), initial);
    }

    #[test]
    fn dropped_preparation_returns_bank_and_asid_without_retirement_proof() {
        let (pool, _root) = BankedMmPool::new_root_for_tests(0x8000, 2).expect("root pool");
        let prepared = pool.prepare_child().expect("first preparation");
        let first_binding = prepared.binding();
        let first_bank = prepared.bank();

        drop(prepared);

        let replacement = pool.prepare_child().expect("replacement preparation");
        assert_eq!(replacement.binding().asid, first_binding.asid);
        assert_eq!(replacement.bank(), first_bank);
        let lease = replacement.commit();
        let retirement = pool.retire(&lease).expect("retire committed lease");
        pool.acknowledge_tlb_flush(retirement)
            .expect("acknowledge retirement");
    }

    #[test]
    fn fails_closed_when_vma_authority_is_unbound() {
        let (_table, backend) = BankResources::new_root(0x8000).expect("root table");

        assert_eq!(
            backend.snapshot(Instant::now() + std::time::Duration::from_secs(1)),
            Err(SnapshotError::AuthorityUnavailable(
                crate::kernel::SnapshotTable::Vmas
            ))
        );
    }
}
