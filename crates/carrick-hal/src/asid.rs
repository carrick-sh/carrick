//! AArch64 Stage-1 Address Space Identifier (ASID) allocation and TLB quarantine.
//!
//! Carrick uses a single carrier-wide ASID authority for all stage-1 address spaces,
//! whether created by host runtime setup or guest fork-stock delegation.

use std::collections::{BTreeSet, VecDeque};
use std::num::{NonZeroU16, NonZeroU64};
use std::sync::Arc;

use parking_lot::Mutex;

pub use carrick_guest_arch::Asid;

const FIRST_GUEST_ASID: u16 = 1;
const LAST_GUEST_ASID: u16 = u16::MAX;

/// Proof that an ASID left the live set but has not yet had its stale TLB
/// translations invalidated. Consuming it is the only route back to
/// the allocator's reusable pool.
#[derive(Debug, Eq, PartialEq)]
pub struct RetiredAsid {
    generation: AsidGeneration,
}

impl RetiredAsid {
    pub const fn generation(&self) -> AsidGeneration {
        self.generation
    }
}

/// Exact lifetime of one numeric architectural ASID. Numeric reuse always
/// receives a fresh generation, so stale residency or acknowledgement tokens
/// cannot authorize its successor.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AsidGeneration {
    asid: Asid,
    generation: NonZeroU64,
}

impl AsidGeneration {
    pub const fn asid(self) -> Asid {
        self.asid
    }

    pub const fn raw(self) -> u16 {
        self.asid.raw()
    }

    pub const fn generation(self) -> u64 {
        self.generation.get()
    }

    pub fn for_tests(raw: u16, generation: u64) -> Self {
        let asid = match NonZeroU16::new(raw) {
            Some(value) => Asid::from_registry_allocation(value),
            None => Asid::first(),
        };
        let generation = NonZeroU64::new(generation).unwrap_or(NonZeroU64::MIN);
        Self { asid, generation }
    }

    pub fn successor_for_tests(self) -> Self {
        let next = self.generation.get().wrapping_add(1).max(1);
        let generation = NonZeroU64::new(next).unwrap_or(NonZeroU64::MIN);
        Self {
            asid: self.asid,
            generation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AsidError {
    #[error("all guest ASIDs are live or awaiting TLB invalidation")]
    Exhausted,
    #[error("guest ASID {0:?} is not live")]
    NotLive(Asid),
    #[error("guest ASID {0:?} is not awaiting TLB invalidation")]
    NotRetired(Asid),
    #[error("slot absence for another MM cannot retire guest ASID {0:?}")]
    AbsenceOfAnotherMm(Asid),
}

/// Allocates nonzero process ASIDs and quarantines retired identifiers until
/// the caller confirms that the matching `TLBI ASIDE1IS` completed.
#[derive(Clone, Debug)]
pub struct AsidAllocator {
    state: Arc<Mutex<AsidAllocatorState>>,
}

#[derive(Debug)]
struct AsidAllocatorState {
    next: u32,
    next_generation: u64,
    limit: u16,
    reusable: VecDeque<Asid>,
    live: BTreeSet<AsidGeneration>,
    retirement_prepared: BTreeSet<AsidGeneration>,
    retired: BTreeSet<AsidGeneration>,
}

impl Default for AsidAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl AsidAllocator {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(AsidAllocatorState {
                next: u32::from(FIRST_GUEST_ASID),
                next_generation: 1,
                limit: LAST_GUEST_ASID,
                reusable: VecDeque::new(),
                live: BTreeSet::new(),
                retirement_prepared: BTreeSet::new(),
                retired: BTreeSet::new(),
            })),
        }
    }

    pub fn with_limit_for_tests(limit: u16) -> Self {
        assert!(limit >= FIRST_GUEST_ASID);
        let allocator = Self::new();
        allocator.state.lock().limit = limit;
        allocator
    }

    pub fn allocate(&self) -> Result<AsidGeneration, AsidError> {
        let mut state = self.state.lock();
        let generation = NonZeroU64::new(state.next_generation).ok_or(AsidError::Exhausted)?;
        let next_generation = state
            .next_generation
            .checked_add(1)
            .ok_or(AsidError::Exhausted)?;
        let asid = if state.next <= u32::from(state.limit) {
            let Ok(raw) = u16::try_from(state.next) else {
                return Err(AsidError::Exhausted);
            };
            let raw = NonZeroU16::new(raw).ok_or(AsidError::Exhausted)?;
            let asid = Asid::from_registry_allocation(raw);
            state.next += 1;
            asid
        } else if let Some(asid) = state.reusable.pop_front() {
            asid
        } else {
            return Err(AsidError::Exhausted);
        };
        state.next_generation = next_generation;
        let generation = AsidGeneration { asid, generation };
        let inserted = state.live.insert(generation);
        debug_assert!(inserted, "allocator returned an ASID that was already live");
        Ok(generation)
    }

    /// Release an ASID reserved for an address space that was never published
    /// to a vCPU. No TLB proof is required because no translation could have
    /// been installed under this identity.
    pub fn release_unpublished(&self, generation: AsidGeneration) -> Result<(), AsidError> {
        let mut state = self.state.lock();
        if !state.live.remove(&generation) {
            return Err(AsidError::NotLive(generation.asid));
        }
        state.reusable.push_back(generation.asid);
        Ok(())
    }

    pub fn prepare_retirement(
        &self,
        generation: AsidGeneration,
    ) -> Result<PreparedAsidAllocatorRetirement, AsidError> {
        let mut state = self.state.lock();
        if !state.live.remove(&generation) {
            return Err(AsidError::NotLive(generation.asid));
        }
        let inserted = state.retirement_prepared.insert(generation);
        assert!(inserted, "live ASID was already prepared for retirement");
        Ok(PreparedAsidAllocatorRetirement {
            allocator: Self {
                state: Arc::clone(&self.state),
            },
            generation,
            active: true,
        })
    }

    pub fn retire(&self, generation: AsidGeneration) -> Result<RetiredAsid, AsidError> {
        Ok(self.prepare_retirement(generation)?.commit())
    }

    /// Retire a fork child's live generation whose own MM the occupancy
    /// authority proved absent from every slot; the proof is the TLB
    /// acknowledgement. The proof must name the tag's MM. Retirement and
    /// acknowledgement are one step under the allocator lock, and a
    /// generation left awaiting acknowledgement by an earlier split retire
    /// is finished here, so a retry never wedges on "not live".
    pub fn retire_absent(
        &self,
        tag: crate::fork_stock::ChildTag<AsidGeneration>,
        absence: crate::fork_stock::SlotAbsence,
    ) -> Result<(), AsidError> {
        let generation = tag
            .discharged_by(&absence)
            .ok_or(AsidError::AbsenceOfAnotherMm(tag.tag().asid))?;
        let mut state = self.state.lock();
        if !state.live.remove(&generation) && !state.retired.remove(&generation) {
            return Err(AsidError::NotLive(generation.asid));
        }
        state.reusable.push_back(generation.asid);
        Ok(())
    }

    /// Make a retired ASID reusable after the caller has completed the
    /// architectural invalidation for that ASID on every vCPU in the VM.
    pub fn acknowledge_tlb_flush(&self, retired: RetiredAsid) -> Result<(), AsidError> {
        let mut state = self.state.lock();
        if !state.retired.remove(&retired.generation) {
            return Err(AsidError::NotRetired(retired.generation.asid));
        }
        state.reusable.push_back(retired.generation.asid);
        Ok(())
    }

    #[doc(hidden)]
    pub fn set_next_generation_for_tests(&self, next: u64) {
        self.state.lock().next_generation = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_distinct_nonzero_asids_until_exhausted() {
        let allocator = AsidAllocator::with_limit_for_tests(3);

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
        let allocator = AsidAllocator::with_limit_for_tests(1);
        let asid = allocator.allocate().expect("ASID");

        let retired = allocator.retire(asid).expect("retire live ASID");
        assert_eq!(allocator.allocate(), Err(AsidError::Exhausted));

        allocator
            .acknowledge_tlb_flush(retired)
            .expect("acknowledge flush");
        assert_eq!(
            allocator.allocate().expect("recycled ASID").asid(),
            asid.asid()
        );
    }

    #[test]
    fn fresh_asids_are_consumed_before_a_retired_identifier_is_recycled() {
        let allocator = AsidAllocator::with_limit_for_tests(3);
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
        assert_eq!(recycled.asid(), first.asid());
    }

    #[test]
    fn unpublished_asid_returns_without_entering_retirement_quarantine() {
        let allocator = AsidAllocator::with_limit_for_tests(1);
        let asid = allocator.allocate().expect("ASID");

        allocator
            .release_unpublished(asid)
            .expect("release unpublished ASID");

        assert_eq!(
            allocator.allocate().expect("recycled ASID").asid(),
            asid.asid()
        );
    }

    #[test]
    fn rejects_retiring_an_asid_that_is_not_live() {
        let allocator = AsidAllocator::with_limit_for_tests(1);
        let asid = allocator.allocate().expect("ASID");
        let _retired = allocator.retire(asid).expect("first retirement");

        assert_eq!(allocator.retire(asid), Err(AsidError::NotLive(asid.asid())));
    }

    #[test]
    fn recycled_numeric_asid_receives_a_distinct_strong_generation() {
        let allocator = AsidAllocator::with_limit_for_tests(1);
        let first = allocator.allocate().expect("first generation");
        let retired = allocator.retire(first).expect("retire first generation");
        allocator
            .acknowledge_tlb_flush(retired)
            .expect("acknowledge first generation");
        let second = allocator.allocate().expect("second generation");

        assert_eq!(first.asid(), second.asid());
        assert_ne!(first, second);
        assert_ne!(first.generation(), second.generation());
    }

    #[test]
    fn generation_overflow_does_not_consume_a_reusable_numeric_asid() {
        let allocator = AsidAllocator::with_limit_for_tests(1);
        let first = allocator.allocate().expect("first generation");
        let retired = allocator.retire(first).expect("retire first generation");
        allocator
            .acknowledge_tlb_flush(retired)
            .expect("acknowledge first generation");
        allocator.set_next_generation_for_tests(u64::MAX);

        assert_eq!(allocator.allocate(), Err(AsidError::Exhausted));

        allocator.set_next_generation_for_tests(9);
        let recovered = allocator
            .allocate()
            .expect("overflow preflight preserves numeric ASID");
        assert_eq!(recovered.asid(), first.asid());
        assert_eq!(recovered.generation(), 9);
    }

    fn mm(raw: u64) -> carrick_el1_abi::ReservationMm {
        carrick_el1_abi::ReservationMm::new(raw).expect("nonzero MM")
    }

    fn absent(raw: u64) -> crate::fork_stock::SlotAbsence {
        crate::fork_stock::SlotAbsence::scan(mm(raw), [0, 7]).expect("absent MM")
    }

    #[test]
    fn absence_of_another_mm_cannot_retire_a_child_tag() {
        let allocator = AsidAllocator::with_limit_for_tests(1);
        let generation = allocator.allocate().expect("ASID");
        let tag = crate::fork_stock::ChildTag::bind(generation, mm(3));

        assert_eq!(
            allocator.retire_absent(tag, absent(4)),
            Err(AsidError::AbsenceOfAnotherMm(generation.asid()))
        );
        // The tag is still live: nothing was retired or made reusable.
        assert_eq!(allocator.allocate(), Err(AsidError::Exhausted));
        allocator
            .retire_absent(tag, absent(3))
            .expect("own absence retires the tag");
        assert_eq!(
            allocator.allocate().expect("recycled ASID").asid(),
            generation.asid()
        );
    }

    #[test]
    fn retire_absent_finishes_a_generation_left_awaiting_acknowledgement() {
        let allocator = AsidAllocator::with_limit_for_tests(1);
        let generation = allocator.allocate().expect("ASID");
        // A split retire whose acknowledgement never ran.
        let retired = allocator.retire(generation).expect("retire");
        let _never_acknowledged = retired;
        let tag = crate::fork_stock::ChildTag::bind(generation, mm(3));

        allocator
            .retire_absent(tag, absent(3))
            .expect("retry completes the retirement");
        assert_eq!(
            allocator.retire_absent(tag, absent(3)),
            Err(AsidError::NotLive(generation.asid()))
        );
        assert_eq!(
            allocator.allocate().expect("recycled ASID").asid(),
            generation.asid()
        );
        assert_eq!(allocator.allocate(), Err(AsidError::Exhausted));
    }
}

/// Exact allocator reservation for a live generation that may either return to
/// the live set on drop or move infallibly into TLB quarantine on commit.
#[derive(Debug)]
pub struct PreparedAsidAllocatorRetirement {
    allocator: AsidAllocator,
    generation: AsidGeneration,
    active: bool,
}

impl PreparedAsidAllocatorRetirement {
    pub fn commit(mut self) -> RetiredAsid {
        {
            let mut state = self.allocator.state.lock();
            assert!(
                state.retirement_prepared.remove(&self.generation),
                "prepared ASID allocator retirement lost its exact generation"
            );
            assert!(
                state.retired.insert(self.generation),
                "prepared ASID allocator retirement committed twice"
            );
        }
        self.active = false;
        RetiredAsid {
            generation: self.generation,
        }
    }
}

impl Drop for PreparedAsidAllocatorRetirement {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.allocator.state.lock();
        let removed = state.retirement_prepared.remove(&self.generation);
        ::std::assert!(
            removed,
            "prepared ASID allocator retirement lost its exact generation"
        );
        let inserted = state.live.insert(self.generation);
        ::std::assert!(
            inserted,
            "prepared ASID allocator retirement returned a generation twice"
        );
    }
}
