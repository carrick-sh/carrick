use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use carrick_hal::MappingId;
use parking_lot::{Mutex, RwLock};

use super::asid::{AsidAllocator, AsidError, RetiredAsid};
use crate::kernel::{
    Asid, MmBackend, MmBinding, SnapshotError, SnapshotTable, Stage1Root, Stage1RootError, Ttbr0,
    VmaSummary,
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
    asid: Asid,
    bank: Option<ProcessBank>,
    retired: AtomicBool,
}

impl BankedMmLease {
    fn new(asid: Asid, stage1_root: Stage1Root, bank: Option<ProcessBank>) -> Self {
        Self {
            state: Arc::new(BankedMmState::new(MmBinding {
                asid,
                stage1_root,
                ttbr0: Ttbr0::for_aarch64(asid, stage1_root),
            })),
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
        Arc::new(BankedMmBackend::new(Arc::clone(&self.state)))
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

#[derive(Debug)]
pub(crate) struct BankedMmPool {
    inner: Mutex<BankedMmPoolInner>,
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
                inner: Mutex::new(BankedMmPoolInner {
                    asids,
                    free_banks: (0..PROCESS_BANK_COUNT).map(ProcessBank).collect(),
                }),
            },
            root,
        ))
    }

    pub(crate) fn allocate_child(&self) -> Result<Arc<BankedMmLease>, BankedMmError> {
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
        Ok(Arc::new(BankedMmLease::new(asid, stage1_root, Some(bank))))
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
/// ProcessTable publishes every binding into this stable per-mm state before
/// lifecycle retirement, so draining objects cannot follow PID reuse or regress
/// to an older root under concurrent observation.
#[derive(Debug)]
pub(crate) struct BankedMmBackend {
    state: Arc<BankedMmState>,
}

impl BankedMmBackend {
    pub(crate) fn new(state: Arc<BankedMmState>) -> Self {
        Self { state }
    }

    fn observed_binding(&self) -> MmBinding {
        self.state.binding()
    }
}

impl MmBackend for BankedMmBackend {
    fn binding(&self) -> MmBinding {
        self.observed_binding()
    }

    fn vma_summaries(&self) -> Result<Vec<VmaSummary>, SnapshotError> {
        // ProcessTable owns only the bank/root lifecycle record. AddressSpace
        // remains the VMA authority until the K2 global-mm cutover.
        Err(SnapshotError::AuthorityUnavailable(SnapshotTable::Vmas))
    }

    fn mapping_ids(&self) -> Result<Vec<MappingId>, SnapshotError> {
        // Runtime frame-inventory application lands with the K1 snapshot slice;
        // never fabricate IDs from bank addresses.
        Err(SnapshotError::AuthorityUnavailable(SnapshotTable::Mappings))
    }
}

#[cfg(test)]
mod tests {
    use super::super::process_table::{GuestPid, ProcessTable};
    use super::*;

    #[test]
    fn observes_live_binding_and_keeps_last_binding_after_retirement() {
        let pid = GuestPid::root();
        let table = Arc::new(ProcessTable::new_root(pid, 0x8000).expect("root table"));
        let backend = table.mm_backend(pid).expect("banked backend");
        let initial = backend.binding();

        table.exec_process(pid, 0xc000).expect("replace root");
        let retired = table.exit_process(pid).expect("retire");
        let replaced = backend.binding();
        assert_eq!(replaced.asid, initial.asid);
        assert_ne!(replaced.stage1_root, initial.stage1_root);
        assert_eq!(
            replaced.ttbr0,
            crate::kernel::Ttbr0::for_aarch64(replaced.asid, replaced.stage1_root)
        );
        assert_eq!(backend.binding(), replaced);
        table.acknowledge_tlb_flush(retired).expect("ack retire");
    }

    #[test]
    fn fails_closed_when_snapshot_authority_is_elsewhere() {
        let pid = GuestPid::root();
        let table = Arc::new(ProcessTable::new_root(pid, 0x8000).expect("root table"));
        let backend = table.mm_backend(pid).expect("banked backend");

        assert_eq!(
            backend.vma_summaries(),
            Err(SnapshotError::AuthorityUnavailable(SnapshotTable::Vmas))
        );
        assert_eq!(
            backend.mapping_ids(),
            Err(SnapshotError::AuthorityUnavailable(SnapshotTable::Mappings))
        );
    }
}
