//! Borrowed descriptor/backing resolver protocols; no owner state lives here.
use carrick_mmu_core::aarch64::{GuestPreparedCommit, GuestPreparedCommitError, LeafAccess};
use core::num::NonZeroU64;

/// Operation needed to resolve a COW fault in EL1. The caller holds the
/// faulting MM's exact editor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CowResolution {
    Resolved,
    NeedsSupply,
    Refused,
}

pub trait CowResolver {
    /// Resolve the write fault at `far` for `mm_key`, whose live root and
    /// ASID are in `ttbr0`. `true`: retry the faulting instruction.
    fn resolve_cow(&mut self, ttbr0: u64, mm_key: u64, far: u64) -> bool;
    fn executable_publication(&self) -> bool {
        false
    }
    fn resolve_cow_outcome(&mut self, ttbr0: u64, mm_key: u64, far: u64) -> CowResolution {
        if self.resolve_cow(ttbr0, mm_key, far) {
            CowResolution::Resolved
        } else {
            CowResolution::Refused
        }
    }
    fn take_cow_completion(&mut self) -> Option<carrick_core_abi::CowGrantCompletion> {
        None
    }
    /// Drain a resolved COW completion once, including outside fork.
    fn finish_resolution<
        W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords + ?Sized,
    >(
        &mut self,
        slot: u32,
        handle: carrick_core_abi::El1MmHandle,
        sequence: Option<NonZeroU64>,
        words: &W,
    ) -> Result<(), crate::mm::transaction::MmError> {
        if let (Some(sequence), Some(completion)) = (sequence, self.take_cow_completion()) {
            self.reconcile_parent_write(slot, handle, sequence, completion, words)?;
        }
        Ok(())
    }
    fn reconcile_parent_write<
        W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords + ?Sized,
    >(
        &mut self,
        _slot: u32,
        _handle: carrick_core_abi::El1MmHandle,
        _sequence: NonZeroU64,
        _completion: carrick_core_abi::CowGrantCompletion,
        _words: &W,
    ) -> Result<(), crate::mm::transaction::MmError> {
        Ok(())
    }
    /// The MM's editor could not be taken (another EL1 editor, or a host
    /// pause closed its gate): the fault goes to the host.
    fn editor_busy(&mut self) {}
}

#[derive(Default)]
pub struct NoopCowResolver;

impl CowResolver for NoopCowResolver {
    fn resolve_cow(&mut self, _ttbr0: u64, _mm_key: u64, _far: u64) -> bool {
        false
    }
}

pub trait PreparedPageResolver {
    fn commit_prepared(
        &mut self,
        ttbr0: u64,
        va: u64,
        expected_ipa: u64,
        access: LeafAccess,
    ) -> Result<GuestPreparedCommit, GuestPreparedCommitError>;
}

pub struct NoopPreparedResolver;

impl PreparedPageResolver for NoopPreparedResolver {
    fn commit_prepared(
        &mut self,
        _ttbr0: u64,
        _va: u64,
        _expected_ipa: u64,
        _access: LeafAccess,
    ) -> Result<GuestPreparedCommit, GuestPreparedCommitError> {
        Err(GuestPreparedCommitError::NotPrepared)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolved_non_fork_cow_consumes_completion_once() {
        struct CountingCow(u32);
        impl CowResolver for CountingCow {
            fn resolve_cow(&mut self, _: u64, _: u64, _: u64) -> bool {
                false
            }
            fn take_cow_completion(&mut self) -> Option<carrick_core_abi::CowGrantCompletion> {
                self.0 += 1;
                None
            }
        }
        let mut cow = CountingCow(0);
        let tables =
            carrick_el1::personality::mm_portal::test_support::Tables::new(0x10000, 0x40000, 1);
        let maintenance = carrick_mmu_core::aarch64::descriptor_txn::CallerInvalidatesAsid;
        let handle = unsafe {
            carrick_core_abi::El1MmHandle::from_admitted_owner(
                NonZeroU64::new(1).unwrap(),
                carrick_core_abi::ReservationMm::new(1).unwrap(),
                NonZeroU64::new(1).unwrap(),
            )
        };
        cow.finish_resolution(0, handle, None, &tables.live(&maintenance))
            .unwrap();
        assert_eq!(
            cow.0, 1,
            "resolved COW drains the mailbox even outside fork"
        );
    }
}
