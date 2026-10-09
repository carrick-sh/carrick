// The retirement half is wired by the in-process fork/exit milestone. Keep the
// complete allocator contract buildable while that integration is in flight.
#![allow(dead_code)]

use std::sync::Arc;

use parking_lot::{Condvar, Mutex};

pub(crate) use carrick_hal::asid::{
    AsidAllocator, AsidError, AsidGeneration, PreparedAsidAllocatorRetirement, RetiredAsid,
};

pub(crate) use carrick_core::mm::retirement::ResidencyError as AsidResidencyError;
use carrick_core::mm::retirement::{InvalidationProof, ResidencyState, ResidencyVenue};

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

/// Native synchronization only; the residency lifecycle belongs to Core.
#[derive(Clone, Debug, Default)]
pub(crate) struct HostResidencyVenue {
    state: Arc<Mutex<ResidencyState>>,
    loads_settled: Arc<Condvar>,
}
// SAFETY: clones share one mutex; Condvar wait atomically releases/reacquires
// that same guard, and notification follows load settlement under the mutex.
unsafe impl ResidencyVenue for HostResidencyVenue {
    type Guard<'a> = parking_lot::MutexGuard<'a, ResidencyState>;
    fn lock(&self) -> Self::Guard<'_> {
        self.state.lock()
    }
    fn wait(&self, guard: &mut Self::Guard<'_>) {
        self.loads_settled.wait(guard);
    }
    fn notify_all(&self) {
        self.loads_settled.notify_all();
    }
}
// SAFETY: the native engine mints this record only after broadcast completion.
unsafe impl InvalidationProof<AsidGeneration> for BroadcastInvalidation {
    fn generation(&self) -> AsidGeneration {
        self.generation
    }
}
pub(crate) type AsidResidency =
    carrick_core::mm::retirement::AddressResidency<HostResidencyVenue, AsidGeneration>;
pub(crate) type AsidLoad = carrick_core::mm::retirement::ResidencyLoad<HostResidencyVenue>;
pub(crate) type PreparedAsidResidencyRetirement =
    carrick_core::mm::retirement::PreparedResidencyRetirement<HostResidencyVenue, AsidGeneration>;
pub(crate) type AsidRetirement =
    carrick_core::mm::retirement::ResidencyRetirement<HostResidencyVenue, AsidGeneration>;

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
        allocator.set_next_generation_for_tests(u64::MAX);

        assert_eq!(allocator.allocate(), Err(AsidError::Exhausted));

        allocator.set_next_generation_for_tests(9);
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
