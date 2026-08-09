use std::sync::Arc;

use carrick_hal::MappingId;
use parking_lot::RwLock;

use crate::kernel::{MmBackend, MmBinding, SnapshotError, SnapshotTable, VmaSummary};

#[derive(Debug)]
pub(crate) struct BankedMmState {
    binding: RwLock<MmBinding>,
}

impl BankedMmState {
    pub(crate) fn new(binding: MmBinding) -> Self {
        Self {
            binding: RwLock::new(binding),
        }
    }

    pub(crate) fn binding(&self) -> MmBinding {
        *self.binding.read()
    }

    pub(crate) fn publish_binding(&self, binding: MmBinding) {
        *self.binding.write() = binding;
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
        let mm = table.mm(pid).expect("typed mm");
        let backend = mm.backend().expect("banked backend");
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
        let mm = table.mm(pid).expect("typed mm");
        let backend = mm.backend().expect("banked backend");

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
