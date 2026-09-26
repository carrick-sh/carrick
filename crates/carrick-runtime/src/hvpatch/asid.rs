// The retirement half is wired by the in-process fork/exit milestone. Keep the
// complete allocator contract buildable while that integration is in flight.
#![allow(dead_code)]

use std::collections::{BTreeSet, VecDeque};
use std::num::{NonZeroU16, NonZeroU64};
use std::sync::Arc;

use parking_lot::Mutex;

use carrick_kernel::kernel::Asid;

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
    pub(crate) fn for_tests(raw: u16, generation: u64) -> Self {
        Self {
            asid: Asid::from_registry_allocation(
                NonZeroU16::new(raw).expect("test ASID must be nonzero"),
            ),
            generation: NonZeroU64::new(generation).expect("test ASID generation must be nonzero"),
        }
    }

    #[cfg(test)]
    fn successor_for_tests(self) -> Self {
        Self {
            asid: self.asid,
            generation: NonZeroU64::new(self.generation.get().wrapping_add(1).max(1)).unwrap(),
        }
    }
}

/// Proof that one broadcast `TLBI ASIDE1IS` for an ASID generation completed
/// on a vCPU of the VM, and therefore on every PE of the Inner Shareable
/// domain, whichever vCPUs ever ran the address space. Minted only by the
/// caller that ran that invalidation to completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BroadcastInvalidation {
    generation: AsidGeneration,
}

impl BroadcastInvalidation {
    /// `generation`'s broadcast invalidation returned successfully.
    pub(crate) const fn completed(generation: AsidGeneration) -> Self {
        Self { generation }
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, Eq, PartialEq)]
pub(crate) enum AsidResidencyError {
    #[error("ASID generation is closed to new executor loads")]
    Retiring,
    #[error("ASID generation retirement already began")]
    AlreadyRetiring,
    #[error("an executor load of this ASID generation is still in flight")]
    ExecutorStillLoading,
    #[error("ASID load hardware-dirty boundary was already armed")]
    HardwareAlreadyDirty,
    #[error("ASID load already completed")]
    UnexpectedLoad,
    #[error("stale ASID generation invalidation")]
    StaleGeneration,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ResidencyLifecycle {
    #[default]
    Live,
    RetirementPrepared,
    Retired,
}

/// Whether an ASID generation may have translations cached anywhere. Which
/// vCPUs run the address space NOW is the occupancy authority's question
/// (`carrick_kernel::kernel::mm_occupancy`); this records only whether any
/// ever installed it, since one broadcast invalidation reaches them all.
#[derive(Debug, Default)]
struct ResidencyState {
    lifecycle: ResidencyLifecycle,
    /// Loads admitted and not yet completed or cancelled.
    loading: usize,
    /// A load armed its hardware boundary: a vCPU may hold translations.
    hardware_dirty: bool,
    /// A load completed its install.
    installed: bool,
    /// The broadcast invalidation after retirement completed.
    invalidated: bool,
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

    pub(crate) fn begin_load(&self) -> Result<AsidLoad, AsidResidencyError> {
        let mut state = self.state.lock();
        if state.lifecycle != ResidencyLifecycle::Live {
            return Err(AsidResidencyError::Retiring);
        }
        state.loading += 1;
        Ok(AsidLoad {
            state: Arc::clone(&self.state),
            active: true,
            hardware_dirty: false,
        })
    }

    /// Whether this generation has stopped admitting executor loads.
    ///
    /// A load rejected because the generation is retiring is not a failure of
    /// the loading executor: some other thread's `execve` (or the process's
    /// exit) is tearing this address space down, which on Linux terminates
    /// every other thread in the group.
    pub(crate) fn is_retiring(&self) -> bool {
        self.state.lock().lifecycle != ResidencyLifecycle::Live
    }

    /// Whether any vCPU may hold translations of this generation.
    pub(crate) fn was_installed(&self) -> bool {
        let state = self.state.lock();
        state.installed || state.hardware_dirty
    }

    pub(crate) fn prepare_retirement(
        &self,
    ) -> Result<PreparedAsidResidencyRetirement, AsidResidencyError> {
        let mut state = self.state.lock();
        if state.lifecycle != ResidencyLifecycle::Live {
            return Err(AsidResidencyError::AlreadyRetiring);
        }
        state.lifecycle = ResidencyLifecycle::RetirementPrepared;
        Ok(PreparedAsidResidencyRetirement {
            residency: self.clone(),
            active: true,
        })
    }

    pub(crate) fn begin_retirement(&self) -> Result<AsidRetirement, AsidResidencyError> {
        Ok(self.prepare_retirement()?.commit())
    }
}

/// Non-cloneable proof that a load won admission before retirement closed
/// the ASID generation. Dropping it before task installation cancels the
/// load; committing it records the install only after the TTBR install and
/// required barriers completed.
#[derive(Debug)]
pub(crate) struct AsidLoad {
    state: Arc<Mutex<ResidencyState>>,
    active: bool,
    hardware_dirty: bool,
}

impl AsidLoad {
    pub(crate) fn arm_hardware_dirty(&mut self) -> Result<(), AsidResidencyError> {
        if self.hardware_dirty {
            return Err(AsidResidencyError::HardwareAlreadyDirty);
        }
        if !self.active {
            return Err(AsidResidencyError::UnexpectedLoad);
        }
        self.state.lock().hardware_dirty = true;
        self.hardware_dirty = true;
        Ok(())
    }

    pub(crate) fn mark_resident(mut self) -> Result<(), AsidResidencyError> {
        let mut state = self.state.lock();
        state.loading = state
            .loading
            .checked_sub(1)
            .ok_or(AsidResidencyError::UnexpectedLoad)?;
        state.installed = true;
        self.active = false;
        Ok(())
    }
}

impl Drop for AsidLoad {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        // An armed load stays recorded as `hardware_dirty` (fail closed): its
        // vCPU may hold translations even though the install did not finish.
        let mut state = self.state.lock();
        state.loading = state.loading.saturating_sub(1);
    }
}

/// Reversible closure of one ASID generation's load admission. Dropping this
/// token restores the live state; committing consumes it into the
/// invalidation authority.
#[derive(Debug)]
pub(crate) struct PreparedAsidResidencyRetirement {
    residency: AsidResidency,
    active: bool,
}

impl PreparedAsidResidencyRetirement {
    /// Whether committing now would owe a broadcast invalidation.
    #[cfg(test)]
    pub(crate) fn needs_invalidation(&self) -> bool {
        let state = self.residency.state.lock();
        state.installed || state.hardware_dirty || state.loading != 0
    }

    pub(crate) fn requires_quarantine(&self) -> bool {
        let state = self.residency.state.lock();
        state.hardware_dirty || state.loading != 0
    }

    pub(crate) fn commit(mut self) -> AsidRetirement {
        {
            let mut state = self.residency.state.lock();
            assert_eq!(
                state.lifecycle,
                ResidencyLifecycle::RetirementPrepared,
                "prepared ASID residency retirement lost its lifecycle reservation"
            );
            state.lifecycle = ResidencyLifecycle::Retired;
        }
        self.active = false;
        AsidRetirement {
            generation: self.residency.generation,
            state: Arc::clone(&self.residency.state),
        }
    }
}

impl Drop for PreparedAsidResidencyRetirement {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.residency.state.lock();
        assert_eq!(
            state.lifecycle,
            ResidencyLifecycle::RetirementPrepared,
            "prepared ASID residency retirement lost its lifecycle reservation"
        );
        state.lifecycle = ResidencyLifecycle::Live;
    }
}

/// A retired ASID generation waiting for its one broadcast invalidation.
#[derive(Debug)]
pub(crate) struct AsidRetirement {
    generation: AsidGeneration,
    state: Arc<Mutex<ResidencyState>>,
}

impl AsidRetirement {
    pub(crate) const fn generation(&self) -> AsidGeneration {
        self.generation
    }

    /// Whether a broadcast invalidation is still owed: some vCPU may hold
    /// translations of this generation. A generation no load ever armed
    /// needs none.
    pub(crate) fn needs_invalidation(&self) -> bool {
        let state = self.state.lock();
        (state.installed || state.hardware_dirty || state.loading != 0) && !state.invalidated
    }

    /// Record the broadcast invalidation. Refused while a load admitted
    /// before retirement is still in flight: it could cache translations
    /// after the invalidation.
    pub(crate) fn acknowledge(
        &self,
        invalidation: BroadcastInvalidation,
    ) -> Result<(), AsidResidencyError> {
        if invalidation.generation != self.generation {
            return Err(AsidResidencyError::StaleGeneration);
        }
        let mut state = self.state.lock();
        if state.loading != 0 {
            return Err(AsidResidencyError::ExecutorStillLoading);
        }
        state.invalidated = true;
        Ok(())
    }

    pub(crate) fn is_complete(&self) -> bool {
        let state = self.state.lock();
        state.invalidated || (!state.installed && !state.hardware_dirty && state.loading == 0)
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
    pub(crate) fn new() -> Self {
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

    #[cfg(test)]
    pub(super) fn with_limit_for_tests(limit: u16) -> Self {
        assert!(limit >= FIRST_GUEST_ASID);
        let allocator = Self::new();
        allocator.state.lock().limit = limit;
        allocator
    }

    pub(crate) fn allocate(&self) -> Result<AsidGeneration, AsidError> {
        let mut state = self.state.lock();
        // Minting the strong generation must be proven possible before a
        // numeric ASID is popped or advanced. Otherwise generation exhaustion
        // would silently lose an otherwise reusable architectural identifier.
        let generation = NonZeroU64::new(state.next_generation).ok_or(AsidError::Exhausted)?;
        let next_generation = state
            .next_generation
            .checked_add(1)
            .ok_or(AsidError::Exhausted)?;
        // Prefer a never-used identifier while the 16-bit architectural space
        // has one.  Recycling immediately after a process exit needlessly puts
        // a new address space behind the exact ASID most likely to remain in a
        // physical CPU's translation structures; the acknowledged pool is the
        // exhaustion fallback, not the fast path.
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
    pub(crate) fn release_unpublished(&self, generation: AsidGeneration) -> Result<(), AsidError> {
        let mut state = self.state.lock();
        if !state.live.remove(&generation) {
            return Err(AsidError::NotLive(generation.asid));
        }
        state.reusable.push_back(generation.asid);
        Ok(())
    }

    pub(crate) fn prepare_retirement(
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

    pub(crate) fn retire(&self, generation: AsidGeneration) -> Result<RetiredAsid, AsidError> {
        Ok(self.prepare_retirement(generation)?.commit())
    }

    /// Make a retired ASID reusable after the caller has completed the
    /// architectural invalidation for that ASID on every vCPU in the VM.
    pub(crate) fn acknowledge_tlb_flush(&self, retired: RetiredAsid) -> Result<(), AsidError> {
        let mut state = self.state.lock();
        if !state.retired.remove(&retired.generation) {
            return Err(AsidError::NotRetired(retired.generation.asid));
        }
        state.reusable.push_back(retired.generation.asid);
        Ok(())
    }
}

/// Exact allocator reservation for a live generation that may either return to
/// the live set on drop or move infallibly into TLB quarantine on commit.
#[derive(Debug)]
pub(crate) struct PreparedAsidAllocatorRetirement {
    allocator: AsidAllocator,
    generation: AsidGeneration,
    active: bool,
}

impl PreparedAsidAllocatorRetirement {
    pub(crate) fn commit(mut self) -> RetiredAsid {
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
        assert!(
            state.retirement_prepared.remove(&self.generation),
            "prepared ASID allocator retirement lost its exact generation"
        );
        assert!(
            state.live.insert(self.generation),
            "prepared ASID allocator retirement returned a generation twice"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{AsidAllocator, AsidError, AsidResidency, BroadcastInvalidation};

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
        allocator.state.lock().next_generation = u64::MAX;

        assert_eq!(allocator.allocate(), Err(AsidError::Exhausted));

        allocator.state.lock().next_generation = 9;
        let recovered = allocator
            .allocate()
            .expect("overflow preflight preserves numeric ASID");
        assert_eq!(recovered.asid(), first.asid());
        assert_eq!(recovered.generation(), 9);
    }

    #[test]
    fn retirement_needs_one_broadcast_invalidation_of_its_exact_generation() {
        let allocator = AsidAllocator::with_limit_for_tests(1);
        let generation = allocator.allocate().expect("ASID generation");
        let residency = AsidResidency::new(generation);
        for _ in 0..2 {
            let mut load = residency.begin_load().expect("load");
            load.arm_hardware_dirty().expect("armed");
            load.mark_resident().expect("installed");
        }
        let retirement = residency.begin_retirement().expect("retirement");

        assert!(residency.begin_load().is_err());
        assert!(retirement.needs_invalidation());
        assert!(!retirement.is_complete());
        let stale = generation.successor_for_tests();
        assert_eq!(
            retirement.acknowledge(BroadcastInvalidation::completed(stale)),
            Err(super::AsidResidencyError::StaleGeneration)
        );
        retirement
            .acknowledge(BroadcastInvalidation::completed(generation))
            .expect("one broadcast invalidation");
        assert!(retirement.is_complete());
        assert!(!retirement.needs_invalidation());
    }

    #[test]
    fn retirement_closes_new_loads_and_waits_for_an_in_flight_load() {
        let allocator = AsidAllocator::with_limit_for_tests(1);
        let generation = allocator.allocate().expect("ASID generation");
        let residency = AsidResidency::new(generation);
        let mut loading = residency.begin_load().expect("loading executor admitted");
        loading.arm_hardware_dirty().expect("armed");

        let retirement = residency.begin_retirement().expect("retirement");

        assert_eq!(
            residency.begin_load().unwrap_err(),
            super::AsidResidencyError::Retiring
        );
        assert_eq!(
            retirement
                .acknowledge(BroadcastInvalidation::completed(generation))
                .unwrap_err(),
            super::AsidResidencyError::ExecutorStillLoading
        );
        loading
            .mark_resident()
            .expect("winning pre-retirement load becomes resident");
        retirement
            .acknowledge(BroadcastInvalidation::completed(generation))
            .expect("broadcast after the load settled");
        assert!(retirement.is_complete());
    }

    #[test]
    fn cancelled_preinstall_load_does_not_require_an_invalidation() {
        let allocator = AsidAllocator::with_limit_for_tests(1);
        let generation = allocator.allocate().expect("ASID generation");
        let residency = AsidResidency::new(generation);
        let load = residency.begin_load().expect("load admitted");
        let retirement = residency.begin_retirement().expect("retirement");
        assert!(!retirement.is_complete());

        drop(load);

        assert!(retirement.is_complete());
        assert!(!retirement.needs_invalidation());
    }

    #[test]
    fn hardware_dirty_partial_load_survives_concurrent_retirement_until_invalidated() {
        let allocator = AsidAllocator::with_limit_for_tests(1);
        let generation = allocator.allocate().expect("ASID generation");
        let residency = AsidResidency::new(generation);
        let mut load = residency.begin_load().expect("load admitted");
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

        assert!(retirement.needs_invalidation());
        retirement
            .acknowledge(BroadcastInvalidation::completed(generation))
            .expect("dirty partial load requires the broadcast");
        assert!(retirement.is_complete());
    }
}
