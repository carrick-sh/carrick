// The retirement half is wired by the in-process fork/exit milestone. Keep the
// complete allocator contract buildable while that integration is in flight.
#![allow(dead_code)]

use std::collections::{BTreeSet, VecDeque};
use std::num::NonZeroU16;

use crate::kernel::Asid;

const FIRST_GUEST_ASID: u16 = 1;
const LAST_GUEST_ASID: u16 = u16::MAX;

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
        // Prefer a never-used identifier while the 16-bit architectural space
        // has one.  Recycling immediately after a process exit needlessly puts
        // a new address space behind the exact ASID most likely to remain in a
        // physical CPU's translation structures; the acknowledged pool is the
        // exhaustion fallback, not the fast path.
        let asid = if self.next <= u32::from(self.limit) {
            let Ok(raw) = u16::try_from(self.next) else {
                return Err(AsidError::Exhausted);
            };
            let raw = NonZeroU16::new(raw).ok_or(AsidError::Exhausted)?;
            let asid = Asid::from_registry_allocation(raw);
            self.next += 1;
            asid
        } else if let Some(asid) = self.reusable.pop_front() {
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
    fn fresh_asids_are_consumed_before_a_retired_identifier_is_recycled() {
        let mut allocator = AsidAllocator::with_limit_for_tests(3);
        let first = allocator.allocate().expect("first ASID");
        let retired = allocator.retire(first).expect("retire first ASID");
        allocator
            .acknowledge_tlb_flush(retired)
            .expect("acknowledge flush");

        let second = allocator.allocate().expect("fresh second ASID");
        let third = allocator.allocate().expect("fresh third ASID");
        let recycled = allocator.allocate().expect("recycled first ASID");

        assert_eq!(second.raw(), 2);
        assert_eq!(third.raw(), 3);
        assert_eq!(recycled, first);
    }

    #[test]
    fn rejects_retiring_an_asid_that_is_not_live() {
        let mut allocator = AsidAllocator::with_limit_for_tests(1);
        let asid = allocator.allocate().expect("ASID");
        let _retired = allocator.retire(asid).expect("first retirement");

        assert_eq!(allocator.retire(asid), Err(AsidError::NotLive(asid)));
    }
}
