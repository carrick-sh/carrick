// The retirement half is wired by the in-process fork/exit milestone. Keep the
// complete allocator contract buildable while that integration is in flight.
#![allow(dead_code)]

use std::collections::{BTreeSet, VecDeque};
use std::num::{NonZeroU16, NonZeroU64};
use std::sync::Arc;

use parking_lot::Mutex;

use crate::kernel::Asid;
use crate::kernel::objects::ExecutorId;

const FIRST_GUEST_ASID: u16 = 1;
const LAST_GUEST_ASID: u16 = u16::MAX;

/// Proof that an ASID left the live set but has not yet had its stale TLB
/// translations invalidated. The token is deliberately neither `Clone` nor
/// constructible outside this module: consuming it is the only route back to
/// the allocator's reusable pool.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RetiredAsid {
    generation: AsidGeneration,
}

/// Exact lifetime of one numeric architectural ASID. Numeric reuse always
/// receives a fresh generation, so stale residency or acknowledgement tokens
/// cannot authorize its successor.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct AsidGeneration {
    asid: Asid,
    generation: NonZeroU64,
}

impl AsidGeneration {
    pub(crate) const fn asid(self) -> Asid {
        self.asid
    }

    pub(crate) const fn raw(self) -> u16 {
        self.asid.raw()
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation.get()
    }

    #[cfg(test)]
    fn successor_for_tests(self) -> Self {
        Self {
            asid: self.asid,
            generation: NonZeroU64::new(self.generation.get().wrapping_add(1).max(1)).unwrap(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InvalidationAck {
    executor: ExecutorId,
    generation: AsidGeneration,
}

impl InvalidationAck {
    pub(crate) const fn new(executor: ExecutorId, generation: AsidGeneration) -> Self {
        Self {
            executor,
            generation,
        }
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, Eq, PartialEq)]
pub(crate) enum AsidResidencyError {
    #[error("ASID generation is closed to new executor loads")]
    Retiring,
    #[error("ASID generation retirement already began")]
    AlreadyRetiring,
    #[error("executor already has an in-flight load for this ASID generation")]
    AlreadyLoading,
    #[error("executor cannot acknowledge this ASID while its load is still in flight")]
    ExecutorStillLoading,
    #[error("ASID load hardware-dirty boundary was already armed")]
    HardwareAlreadyDirty,
    #[error("executor was not pending for this ASID generation")]
    UnexpectedExecutor,
    #[error("stale ASID generation acknowledgement")]
    StaleGeneration,
}

#[derive(Debug, Default)]
struct ResidencyState {
    retiring: bool,
    loading: BTreeSet<ExecutorId>,
    residents: BTreeSet<ExecutorId>,
    pending: BTreeSet<ExecutorId>,
}

#[derive(Clone, Debug)]
pub(crate) struct AsidResidency {
    generation: AsidGeneration,
    state: Arc<Mutex<ResidencyState>>,
}

impl AsidResidency {
    pub(crate) fn new(generation: AsidGeneration) -> Self {
        Self {
            generation,
            state: Arc::new(Mutex::new(ResidencyState::default())),
        }
    }

    pub(crate) fn begin_load(&self, executor: ExecutorId) -> Result<AsidLoad, AsidResidencyError> {
        let mut state = self.state.lock();
        if state.retiring {
            return Err(AsidResidencyError::Retiring);
        }
        if !state.loading.insert(executor) {
            return Err(AsidResidencyError::AlreadyLoading);
        }
        Ok(AsidLoad {
            executor,
            state: Arc::clone(&self.state),
            active: true,
            hardware_dirty: false,
        })
    }

    pub(crate) fn residents(&self) -> Vec<ExecutorId> {
        self.state.lock().residents.iter().copied().collect()
    }

    pub(crate) fn begin_retirement(&self) -> Result<AsidRetirement, AsidResidencyError> {
        let mut state = self.state.lock();
        if state.retiring {
            return Err(AsidResidencyError::AlreadyRetiring);
        }
        state.retiring = true;
        state.pending = state.residents.union(&state.loading).copied().collect();
        Ok(AsidRetirement {
            generation: self.generation,
            state: Arc::clone(&self.state),
        })
    }
}

/// Non-cloneable proof that this executor won admission before retirement
/// closed the ASID generation. Dropping it before task installation cancels
/// the load; committing it records residency only after the TTBR install and
/// required barriers completed.
#[derive(Debug)]
pub(crate) struct AsidLoad {
    executor: ExecutorId,
    state: Arc<Mutex<ResidencyState>>,
    active: bool,
    hardware_dirty: bool,
}

impl AsidLoad {
    pub(crate) fn arm_hardware_dirty(&mut self) -> Result<(), AsidResidencyError> {
        if self.hardware_dirty {
            return Err(AsidResidencyError::HardwareAlreadyDirty);
        }
        if !self.state.lock().loading.contains(&self.executor) {
            return Err(AsidResidencyError::UnexpectedExecutor);
        }
        self.hardware_dirty = true;
        Ok(())
    }

    pub(crate) fn mark_resident(mut self) -> Result<(), AsidResidencyError> {
        let mut state = self.state.lock();
        if !state.loading.remove(&self.executor) {
            return Err(AsidResidencyError::UnexpectedExecutor);
        }
        state.residents.insert(self.executor);
        self.active = false;
        Ok(())
    }
}

impl Drop for AsidLoad {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.state.lock();
        state.loading.remove(&self.executor);
        if self.hardware_dirty {
            state.residents.insert(self.executor);
        } else if state.retiring && !state.residents.contains(&self.executor) {
            state.pending.remove(&self.executor);
        }
    }
}

#[derive(Debug)]
pub(crate) struct AsidRetirement {
    generation: AsidGeneration,
    state: Arc<Mutex<ResidencyState>>,
}

impl AsidRetirement {
    pub(crate) const fn generation(&self) -> AsidGeneration {
        self.generation
    }

    pub(crate) fn pending(&self) -> Vec<ExecutorId> {
        self.state.lock().pending.iter().copied().collect()
    }

    pub(crate) fn acknowledge(&self, ack: InvalidationAck) -> Result<(), AsidResidencyError> {
        if ack.generation != self.generation {
            return Err(AsidResidencyError::StaleGeneration);
        }
        let mut state = self.state.lock();
        if state.loading.contains(&ack.executor) {
            return Err(AsidResidencyError::ExecutorStillLoading);
        }
        if !state.pending.remove(&ack.executor) {
            return Err(AsidResidencyError::UnexpectedExecutor);
        }
        state.residents.remove(&ack.executor);
        Ok(())
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.state.lock().pending.is_empty()
    }
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
    next_generation: u64,
    limit: u16,
    reusable: VecDeque<Asid>,
    live: BTreeSet<AsidGeneration>,
    retired: BTreeSet<AsidGeneration>,
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
            next_generation: 1,
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

    pub(crate) fn allocate(&mut self) -> Result<AsidGeneration, AsidError> {
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
        let generation = NonZeroU64::new(self.next_generation).ok_or(AsidError::Exhausted)?;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(AsidError::Exhausted)?;
        let generation = AsidGeneration { asid, generation };
        let inserted = self.live.insert(generation);
        debug_assert!(inserted, "allocator returned an ASID that was already live");
        Ok(generation)
    }

    /// Release an ASID reserved for an address space that was never published
    /// to a vCPU. No TLB proof is required because no translation could have
    /// been installed under this identity.
    pub(crate) fn release_unpublished(
        &mut self,
        generation: AsidGeneration,
    ) -> Result<(), AsidError> {
        if !self.live.remove(&generation) {
            return Err(AsidError::NotLive(generation.asid));
        }
        self.reusable.push_back(generation.asid);
        Ok(())
    }

    pub(crate) fn retire(&mut self, generation: AsidGeneration) -> Result<RetiredAsid, AsidError> {
        if !self.live.remove(&generation) {
            return Err(AsidError::NotLive(generation.asid));
        }
        let inserted = self.retired.insert(generation);
        debug_assert!(inserted, "live ASID was already retired");
        Ok(RetiredAsid { generation })
    }

    /// Make a retired ASID reusable after the caller has completed the
    /// architectural invalidation for that ASID on every vCPU in the VM.
    pub(crate) fn acknowledge_tlb_flush(&mut self, retired: RetiredAsid) -> Result<(), AsidError> {
        if !self.retired.remove(&retired.generation) {
            return Err(AsidError::NotRetired(retired.generation.asid));
        }
        self.reusable.push_back(retired.generation.asid);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{AsidAllocator, AsidError, AsidResidency, InvalidationAck};
    use crate::kernel::objects::ExecutorId;
    use crate::thread::ThreadId;

    fn executor(raw: i32) -> ExecutorId {
        ExecutorId::for_transitional_thread(ThreadId::synthetic_for_tests(raw))
            .expect("test executor id")
    }

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
        assert_eq!(
            allocator.allocate().expect("recycled ASID").asid(),
            asid.asid()
        );
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
        assert_eq!(recycled.asid(), first.asid());
    }

    #[test]
    fn unpublished_asid_returns_without_entering_retirement_quarantine() {
        let mut allocator = AsidAllocator::with_limit_for_tests(1);
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
        let mut allocator = AsidAllocator::with_limit_for_tests(1);
        let asid = allocator.allocate().expect("ASID");
        let _retired = allocator.retire(asid).expect("first retirement");

        assert_eq!(allocator.retire(asid), Err(AsidError::NotLive(asid.asid())));
    }

    #[test]
    fn recycled_numeric_asid_receives_a_distinct_strong_generation() {
        let mut allocator = AsidAllocator::with_limit_for_tests(1);
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
    fn retirement_requires_every_resident_executor_exact_ack() {
        let first = executor(1);
        let second = executor(2);
        let mut allocator = AsidAllocator::with_limit_for_tests(1);
        let generation = allocator.allocate().expect("ASID generation");
        let residency = AsidResidency::new(generation);
        residency
            .begin_load(first)
            .expect("first load")
            .mark_resident()
            .expect("first residence");
        residency
            .begin_load(second)
            .expect("second load")
            .mark_resident()
            .expect("second residence");
        let retirement = residency.begin_retirement().expect("retirement");

        assert!(residency.begin_load(first).is_err());
        assert_eq!(retirement.pending(), vec![first, second]);
        retirement
            .acknowledge(InvalidationAck::new(first, generation))
            .expect("first exact ack");
        assert!(!retirement.is_complete());
        assert!(
            retirement
                .acknowledge(InvalidationAck::new(first, generation))
                .is_err()
        );
        let stale = generation.successor_for_tests();
        assert!(
            retirement
                .acknowledge(InvalidationAck::new(second, stale))
                .is_err()
        );
        retirement
            .acknowledge(InvalidationAck::new(second, generation))
            .expect("second exact ack");
        assert!(retirement.is_complete());
        assert!(residency.residents().is_empty());
    }

    #[test]
    fn retirement_closes_new_loads_and_waits_for_loading_and_resident_executors() {
        let loading_executor = executor(3);
        let resident_executor = executor(4);
        let rejected_executor = executor(5);
        let mut allocator = AsidAllocator::with_limit_for_tests(1);
        let generation = allocator.allocate().expect("ASID generation");
        let residency = AsidResidency::new(generation);
        let loading = residency
            .begin_load(loading_executor)
            .expect("loading executor admitted");
        residency
            .begin_load(resident_executor)
            .expect("resident executor admitted")
            .mark_resident()
            .expect("resident executor committed");

        let retirement = residency.begin_retirement().expect("retirement");

        assert_eq!(
            residency.begin_load(rejected_executor).unwrap_err(),
            super::AsidResidencyError::Retiring
        );
        assert_eq!(
            retirement.pending(),
            vec![loading_executor, resident_executor]
        );
        assert_eq!(
            retirement
                .acknowledge(InvalidationAck::new(loading_executor, generation))
                .unwrap_err(),
            super::AsidResidencyError::ExecutorStillLoading
        );
        loading
            .mark_resident()
            .expect("winning pre-retirement load becomes resident");
        retirement
            .acknowledge(InvalidationAck::new(loading_executor, generation))
            .expect("loading executor exact ack");
        retirement
            .acknowledge(InvalidationAck::new(resident_executor, generation))
            .expect("resident executor exact ack");
        assert!(retirement.is_complete());
    }

    #[test]
    fn cancelled_preinstall_load_does_not_require_an_invalidation_ack() {
        let executor = executor(6);
        let mut allocator = AsidAllocator::with_limit_for_tests(1);
        let generation = allocator.allocate().expect("ASID generation");
        let residency = AsidResidency::new(generation);
        let load = residency.begin_load(executor).expect("load admitted");
        let retirement = residency.begin_retirement().expect("retirement");
        assert_eq!(retirement.pending(), vec![executor]);

        drop(load);

        assert!(retirement.is_complete());
        assert!(retirement.pending().is_empty());
    }

    #[test]
    fn hardware_dirty_partial_load_survives_concurrent_retirement_until_exact_ack() {
        let executor = executor(7);
        let mut allocator = AsidAllocator::with_limit_for_tests(1);
        let generation = allocator.allocate().expect("ASID generation");
        let residency = AsidResidency::new(generation);
        let mut load = residency.begin_load(executor).expect("load admitted");
        load.arm_hardware_dirty().expect("hardware mutation armed");

        let residency_for_retire = residency.clone();
        let retirement = std::thread::spawn(move || {
            residency_for_retire
                .begin_retirement()
                .expect("concurrent retirement")
        })
        .join()
        .unwrap();
        drop(load);

        assert_eq!(retirement.pending(), vec![executor]);
        retirement
            .acknowledge(InvalidationAck::new(executor, generation))
            .expect("dirty partial load requires exact TLBI ack");
        assert!(retirement.is_complete());
    }
}
