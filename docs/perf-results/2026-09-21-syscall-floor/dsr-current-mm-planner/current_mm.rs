//! Research adapter: current kernel instruction authority into the reusable
//! planner. No NativeMappedMemory, emitted code, cache key or executable entry.
use crate::block::{self, BlockPlan, ExclusiveFusionPolicy, PlannedExit};
use crate::types::{CodeGeneration, DsrError};
use carrick_guest_mem::GuestVa;
use carrick_kernel::kernel::objects::ThreadExecutionLease;
use carrick_kernel::kernel::{InstructionRead, KernelContext, MmAccessError};

#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    #[error(transparent)]
    Memory(#[from] MmAccessError),
    #[error(transparent)]
    Decode(#[from] DsrError),
    #[error("invalid instruction planning bounds")]
    Bounds,
}

/// A decoded draft which cannot be handed to the emitter through this API.
/// Holding a lease and rechecking mappings is insufficient for publication:
/// in-place code writes and direct-link invalidation are not integrated yet.
pub struct UnpublishedPlan<'execution> {
    read: InstructionRead<'execution>,
    plan: BlockPlan,
}
impl UnpublishedPlan<'_> {
    pub fn exit(&self) -> PlannedExit {
        self.plan.terminal_exit()
    }
    pub fn instruction_count(&self) -> usize {
        self.plan.instructions.len()
    }
    pub fn validate_mapping(&self) -> Result<(), MmAccessError> {
        self.read.validate_mapping()
    }
}

pub fn plan_current_mm<'execution>(
    context: &'execution KernelContext,
    execution: &'execution ThreadExecutionLease,
    start: GuestVa,
    max_instructions: usize,
) -> Result<UnpublishedPlan<'execution>, PlanError> {
    const PAGE: u64 = 4096;
    if start.raw() % 4 != 0 || max_instructions == 0 {
        return Err(PlanError::Bounds);
    }
    let length = (PAGE - (start.raw() & (PAGE - 1))) as usize;
    let read = context.fetch_instruction_bytes(execution, start, length)?;
    let plan = block::plan_with_reader(
        start,
        // Decoder annotation only; no generation or cache identity is attested.
        // The draft stays private until real write/revocation authority exists.
        CodeGeneration::INITIAL,
        max_instructions,
        PAGE,
        ExclusiveFusionPolicy::BiasedDisabled,
        |pc| {
            let offset = pc
                .raw()
                .checked_sub(start.raw())
                .and_then(|offset| usize::try_from(offset).ok())
                .ok_or_else(|| DsrError::BlockPolicy("read before authenticated window".into()))?;
            let word = offset
                .checked_add(4)
                .and_then(|end| read.bytes().get(offset..end))
                .ok_or_else(|| DsrError::BlockPolicy("read outside authenticated window".into()))?;
            Ok(u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
        },
    )?;
    read.validate_mapping()?;
    Ok(UnpublishedPlan { read, plan })
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_hal::*;
    use carrick_kernel::kernel::mm_access::test_support::{
        bootstrap, execution_lease, fixture_backend, fork_with_backend,
    };
    use carrick_kernel::kernel::{MmBackend, MmBackendSnapshot, SnapshotError, VmaRevision};
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    use std::time::Instant;

    struct ExecutableBackend {
        inner: Arc<dyn MmBackend>,
        revision: AtomicU64,
    }
    impl MmBackend for ExecutableBackend {
        fn snapshot(&self, deadline: Instant) -> Result<MmBackendSnapshot, SnapshotError> {
            let mut snapshot = self.inner.snapshot(deadline)?;
            snapshot.revision = self.revision();
            for vma in &mut snapshot.vmas {
                vma.access.executable = true;
                vma.access.readable = false;
            }
            Ok(snapshot)
        }
        fn revision(&self) -> u64 {
            self.revision.load(Ordering::Acquire)
        }
        fn vma_revision(&self, deadline: Instant) -> Result<Option<VmaRevision>, SnapshotError> {
            self.inner.vma_revision(deadline)
        }
    }
    // A source fixture for planner integration, not a carrier ownership proof.
    #[derive(Debug)]
    struct Source;
    #[derive(Debug)]
    struct Receipt {
        mm: ForeignMmId,
        bytes: usize,
        owners: [ForeignOwnerGeneration; 1],
    }
    impl ForeignMmReadReceipt for Receipt {
        fn bytes_read(&self) -> usize {
            self.bytes
        }
        fn owner_generations(&self) -> &[ForeignOwnerGeneration] {
            &self.owners
        }
        fn authenticates(&self, snapshot: &dyn ForeignMmSnapshot) -> bool {
            self.mm == snapshot.mm()
        }
    }
    impl ForeignMmReadLease for Source {
        fn read(
            &self,
            _: &ForeignMmInvocation,
            _: &dyn ForeignMmLiveAuthority,
            snapshot: &dyn ForeignMmSnapshot,
            va: GuestVa,
            dst: &mut [u8],
            _: Instant,
        ) -> Result<Box<dyn ForeignMmReadReceipt>, ForeignMmTransportError> {
            assert_eq!(va, GuestVa(0x1000));
            for word in dst.chunks_exact_mut(4) {
                word.copy_from_slice(&0xd503201fu32.to_le_bytes());
            }
            dst[..4].copy_from_slice(&0xd28000e0u32.to_le_bytes()); // mov x0, #7
            dst[4..8].copy_from_slice(&0xd4000001u32.to_le_bytes()); // svc #0
            Ok(Box::new(Receipt {
                mm: snapshot.mm(),
                bytes: dst.len(),
                owners: [ForeignOwnerGeneration::from_backend_counter(
                    std::num::NonZeroU64::MIN,
                )],
            }))
        }
    }
    impl ForeignMmTransport for Source {
        fn retain(
            &self,
            _: &ForeignMmInvocation,
            _: &dyn ForeignMmSnapshot,
            _: Instant,
        ) -> Result<Arc<dyn ForeignMmReadLease>, ForeignMmTransportError> {
            Ok(Arc::new(Source))
        }
    }

    #[test]
    fn current_kernel_reader_plans_syscall_and_keeps_mapping_validation() {
        let (kernel, parent) = bootstrap(32100);
        let backend = Arc::new(ExecutableBackend {
            inner: fixture_backend(),
            revision: AtomicU64::new(17),
        });
        let child = fork_with_backend(
            &kernel,
            &parent,
            32101,
            "DSR planner fixture",
            backend.clone(),
        );
        child
            .shared()
            .mm()
            .install_foreign_mm_endpoint_for_test(ForeignMmEndpoint::for_carrier(Arc::new(Source)));
        let execution = execution_lease(&child, 201);
        let draft = plan_current_mm(&child, &execution, GuestVa(0x1000), 32).unwrap();
        assert_eq!(
            draft.exit(),
            PlannedExit::Syscall {
                guest: GuestVa(0x1004),
                resume: GuestVa(0x1008)
            }
        );
        assert_eq!(draft.instruction_count(), 1);
        draft.validate_mapping().unwrap();
        backend.revision.fetch_add(1, Ordering::AcqRel);
        assert!(matches!(
            draft.validate_mapping(),
            Err(MmAccessError::StaleInstructionRead)
        ));
        let wrong = execution_lease(&parent, 202);
        assert!(matches!(
            plan_current_mm(&child, &wrong, GuestVa(0x1000), 32),
            Err(PlanError::Memory(MmAccessError::ExecutionAuthority(_)))
        ));
    }
}
