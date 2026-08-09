// The retirement half is wired by the in-process fork/exit milestone. Keep the
// complete allocator contract buildable while that integration is in flight.
#![allow(dead_code)]

use std::collections::{BTreeSet, VecDeque};

const FIRST_GUEST_ASID: u16 = 1;
const LAST_GUEST_ASID: u16 = u16::MAX;
const TTBR0_ROOT_ALIGNMENT: u64 = 4096;
const TTBR0_ROOT_MASK: u64 = (1_u64 << 48) - 1;

/// A nonzero AArch64 stage-1 address-space identifier owned by one live guest
/// process. ASID zero remains reserved for bootstrap and diagnostics.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct Asid(u16);

impl Asid {
    pub(crate) fn raw(self) -> u16 {
        self.0
    }

    /// Compose this process's ASID with a 4 KiB-aligned stage-1 root for
    /// `TTBR0_EL1`. Carrick's current AArch64 translation regime uses a 48-bit
    /// base field and the upper 16 bits for the ASID.
    pub(crate) fn ttbr0(self, root_ipa: u64) -> Result<u64, AsidError> {
        if root_ipa & (TTBR0_ROOT_ALIGNMENT - 1) != 0 {
            return Err(AsidError::UnalignedRoot(root_ipa));
        }
        if root_ipa & !TTBR0_ROOT_MASK != 0 {
            return Err(AsidError::RootOutOfRange(root_ipa));
        }
        Ok((u64::from(self.0) << 48) | root_ipa)
    }
}

/// Proof that an ASID left the live set but has not yet had its stale TLB
/// translations invalidated. The token is deliberately neither `Clone` nor
/// constructible outside this module: consuming it is the only route back to
/// the allocator's reusable pool.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RetiredAsid {
    asid: Asid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum AsidError {
    #[error("all guest ASIDs are live or awaiting TLB invalidation")]
    Exhausted,
    #[error("guest ASID {0:?} is not live")]
    NotLive(Asid),
    #[error("guest ASID {0:?} is not awaiting TLB invalidation")]
    NotRetired(Asid),
    #[error("stage-1 root IPA 0x{0:x} is not 4 KiB aligned")]
    UnalignedRoot(u64),
    #[error("stage-1 root IPA 0x{0:x} does not fit TTBR0_EL1's 48-bit base field")]
    RootOutOfRange(u64),
}

/// Allocates nonzero process ASIDs and quarantines retired identifiers until
/// the caller confirms that the matching `TLBI ASIDE1IS` completed.
#[derive(Debug)]
pub(crate) struct AsidAllocator {
    next: u32,
    limit: u16,
    reusable: VecDeque<Asid>,
    live: BTreeSet<Asid>,
    retired: BTreeSet<Asid>,
}

impl Default for AsidAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl AsidAllocator {
    pub(crate) fn new() -> Self {
        Self {
            next: u32::from(FIRST_GUEST_ASID),
            limit: LAST_GUEST_ASID,
            reusable: VecDeque::new(),
            live: BTreeSet::new(),
            retired: BTreeSet::new(),
        }
    }

    #[cfg(test)]
    pub(super) fn with_limit_for_tests(limit: u16) -> Self {
        assert!(limit >= FIRST_GUEST_ASID);
        Self {
            limit,
            ..Self::new()
        }
    }

    pub(crate) fn allocate(&mut self) -> Result<Asid, AsidError> {
        let asid = if let Some(asid) = self.reusable.pop_front() {
            asid
        } else if self.next <= u32::from(self.limit) {
            let Ok(raw) = u16::try_from(self.next) else {
                return Err(AsidError::Exhausted);
            };
            let asid = Asid(raw);
            self.next += 1;
            asid
        } else {
            return Err(AsidError::Exhausted);
        };
        let inserted = self.live.insert(asid);
        debug_assert!(inserted, "allocator returned an ASID that was already live");
        Ok(asid)
    }

    pub(crate) fn retire(&mut self, asid: Asid) -> Result<RetiredAsid, AsidError> {
        if !self.live.remove(&asid) {
            return Err(AsidError::NotLive(asid));
        }
        let inserted = self.retired.insert(asid);
        debug_assert!(inserted, "live ASID was already retired");
        Ok(RetiredAsid { asid })
    }

    /// Make a retired ASID reusable after the caller has completed the
    /// architectural invalidation for that ASID on every vCPU in the VM.
    pub(crate) fn acknowledge_tlb_flush(&mut self, retired: RetiredAsid) -> Result<(), AsidError> {
        if !self.retired.remove(&retired.asid) {
            return Err(AsidError::NotRetired(retired.asid));
        }
        self.reusable.push_back(retired.asid);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{AsidAllocator, AsidError};

    #[test]
    fn allocates_distinct_nonzero_asids_until_exhausted() {
        let mut allocator = AsidAllocator::with_limit_for_tests(3);

        let first = allocator.allocate().expect("first ASID");
        let second = allocator.allocate().expect("second ASID");
        let third = allocator.allocate().expect("third ASID");

        assert_ne!(first, second);
        assert_ne!(second, third);
        assert_ne!(first.raw(), 0);
        assert_eq!(allocator.allocate(), Err(AsidError::Exhausted));
    }

    #[test]
    fn retired_asid_is_quarantined_until_tlb_flush_is_acknowledged() {
        let mut allocator = AsidAllocator::with_limit_for_tests(1);
        let asid = allocator.allocate().expect("ASID");

        let retired = allocator.retire(asid).expect("retire live ASID");
        assert_eq!(allocator.allocate(), Err(AsidError::Exhausted));

        allocator
            .acknowledge_tlb_flush(retired)
            .expect("acknowledge flush");
        assert_eq!(allocator.allocate().expect("recycled ASID"), asid);
    }

    #[test]
    fn rejects_retiring_an_asid_that_is_not_live() {
        let mut allocator = AsidAllocator::with_limit_for_tests(1);
        let asid = allocator.allocate().expect("ASID");
        let _retired = allocator.retire(asid).expect("first retirement");

        assert_eq!(allocator.retire(asid), Err(AsidError::NotLive(asid)));
    }

    #[test]
    fn encodes_asid_and_aligned_root_in_ttbr0() {
        let mut allocator = AsidAllocator::with_limit_for_tests(1);
        let asid = allocator.allocate().expect("ASID");

        assert_eq!(asid.ttbr0(0x1234_5000), Ok(0x0001_0000_1234_5000));
    }

    #[test]
    fn rejects_unaligned_or_out_of_range_ttbr0_roots() {
        let mut allocator = AsidAllocator::with_limit_for_tests(1);
        let asid = allocator.allocate().expect("ASID");

        assert_eq!(
            asid.ttbr0(0x1234_5001),
            Err(AsidError::UnalignedRoot(0x1234_5001))
        );
        assert_eq!(
            asid.ttbr0(0x0001_0000_0000_0000),
            Err(AsidError::RootOutOfRange(0x0001_0000_0000_0000))
        );
    }
}
