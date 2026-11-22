//! Carrier custody for authoritative thread lifecycle ABI storage.
//!
//! The slab walk, deduplication, publication and retirement ordering every
//! carrier shares. A backend supplies only the mapping capability
//! ([`RetainedMetadataMapper`]); the bytes are mapped, never copied.

use std::collections::BTreeMap;
use std::sync::Arc;

use carrick_el1_abi::{CurrentTask, Lifecycle, MetadataResolutionError};
use carrick_guest_mem::{GuestVa, HostVa};
use carrick_hal::retained_metadata::{
    RetainedMetadataBacking, RetainedMetadataExtent, RetainedMetadataMapper,
};
use parking_lot::Mutex;

use crate::kernel::objects::{
    ThreadControlLease, ThreadKey, ThreadLedgerActivityLease, ThreadLifecycleLease,
};

fn publish_for_page<R>(
    page: &carrick_el1_abi::ThreadLifecyclePage,
    publish: impl FnOnce() -> R,
) -> Option<R> {
    (page.serves_threads() || page.serves_sigmask()).then(publish)
}

#[derive(Debug, PartialEq, Eq)]
pub enum LifecyclePublication {
    Published,
    HostServed,
}

fn publish_resolved(
    task: &CurrentTask,
    resolve: impl FnOnce() -> Result<(u64, u64), MetadataResolutionError>,
) -> Result<LifecyclePublication, MetadataResolutionError> {
    task.publish_lifecycle(0, 0);
    let (page, control) = match resolve() {
        Ok(binding) => binding,
        Err(MetadataResolutionError::Busy) => {
            return Ok(LifecyclePublication::HostServed);
        }
        Err(error) => return Err(error),
    };
    task.publish_lifecycle(page, control);
    Ok(LifecyclePublication::Published)
}

#[derive(Debug)]
struct ControlBacking(ThreadControlLease);
// SAFETY: the lease retains a MAP_SHARED slab containing only ABI granules.
unsafe impl RetainedMetadataBacking for ControlBacking {
    fn host_base(&self) -> HostVa {
        self.0.backing_base()
    }
    fn mapped_len(&self) -> usize {
        self.0.backing_len()
    }
}

#[derive(Debug)]
struct ActivityBacking(ThreadLedgerActivityLease);
// SAFETY: the retained owner exposes only a closed ABI activity granule.
unsafe impl RetainedMetadataBacking for ActivityBacking {
    fn host_base(&self) -> HostVa {
        self.0.backing_base()
    }
    fn mapped_len(&self) -> usize {
        self.0.backing_len()
    }
}

#[derive(Debug)]
struct LifecycleBacking(ThreadLifecycleLease);
// SAFETY: the lease retains a MAP_SHARED slab containing only ABI granules.
unsafe impl RetainedMetadataBacking for LifecycleBacking {
    fn host_base(&self) -> HostVa {
        self.0.backing_base()
    }
    fn mapped_len(&self) -> usize {
        self.0.backing_len()
    }
}

struct Mapping<X> {
    authority: X,
    guest_base: GuestVa,
}

struct State<X> {
    pages: BTreeMap<usize, Mapping<X>>,
    threads: BTreeMap<(usize, ThreadKey), ThreadControlLease>,
}

impl<X> Default for State<X> {
    fn default() -> Self {
        Self {
            pages: BTreeMap::new(),
            threads: BTreeMap::new(),
        }
    }
}

impl<X> State<X> {
    fn purge_unregistered(&mut self) {
        self.threads
            .retain(|_, control| !control.graph_unregister_receipt());
    }
    fn retain_thread(&mut self, control: ThreadControlLease) {
        self.threads.insert(
            (
                control.lifecycle().page_address().raw(),
                control.identity().1,
            ),
            control,
        );
    }
}

/// Shared by the factory and its executors, never by a process-global static.
/// A thread pin survives every in-zone park and switch, not only a host load.
pub struct CarrierLifecycleMappings<M: RetainedMetadataMapper> {
    mapper: M,
    state: Mutex<State<M::Extent>>,
}

impl<M: RetainedMetadataMapper> CarrierLifecycleMappings<M> {
    pub fn new(mapper: M) -> Self {
        Self {
            mapper,
            state: Mutex::new(State::default()),
        }
    }

    fn map(
        &self,
        state: &mut State<M::Extent>,
        backing: Arc<dyn RetainedMetadataBacking>,
    ) -> Result<GuestVa, MetadataResolutionError> {
        let key = backing.host_base().raw();
        if let Some(mapping) = state.pages.get(&key) {
            return Ok(mapping.guest_base);
        }
        let authority = self.mapper.map_retained(backing)?;
        let guest_base = authority.guest_base()?;
        state.pages.insert(
            key,
            Mapping {
                authority,
                guest_base,
            },
        );
        Ok(guest_base)
    }

    /// Publish the lifecycle page and control slot of the thread loaded on
    /// mailbox `slot`, mapping each retained slab (and, when the page serves
    /// threads, its ledger activity and birth controls) once per carrier.
    pub fn publish(
        &self,
        slot: usize,
        control: ThreadControlLease,
    ) -> Result<LifecyclePublication, MetadataResolutionError> {
        if slot >= carrick_el1_abi::EL1_STACK_SLOTS as usize {
            return Err(MetadataResolutionError::InvalidExtent);
        }
        let lifecycle = control.lifecycle();
        publish_for_page(&lifecycle, || {
            let region = self.mapper.region()?;
            // SAFETY: the exact carrier mapper retains the region and both mapped
            // ABI owners. The executor publishes before entering this slot's EL0.
            let task = unsafe {
                &*region
                    .as_ptr()
                    .add(carrick_el1_abi::EL1_CURRENT_TASKS_OFFSET as usize)
                    .cast::<CurrentTask>()
                    .add(slot)
            };
            publish_resolved(task, || {
                let mut state = self.state.lock();
                state.purge_unregistered();
                let page = self.map(&mut state, Arc::new(LifecycleBacking(control.lifecycle())))?;
                let page_offset = lifecycle.page_address().raw() - lifecycle.backing_base().raw();
                let base = self.map(&mut state, Arc::new(ControlBacking(control.clone())))?;
                let offset = control.slot_address().raw() - control.backing_base().raw();
                // SAFETY: both exact aliases are retained by this carrier map.
                unsafe {
                    control.publish_affinity_aliases(GuestVa::new(base.raw() + offset as u64));
                }
                if lifecycle.serves_threads() {
                    if let Some(activity) = lifecycle.ledger_activity() {
                        let offset =
                            activity.activity_address().raw() - activity.backing_base().raw();
                        let activity_base =
                            self.map(&mut state, Arc::new(ActivityBacking(activity)))?;
                        // SAFETY: this carrier mapping retains the exact immutable activity owner.
                        unsafe {
                            lifecycle.bind_guest_activity(activity_base.raw() + offset as u64);
                        }
                    }
                    for (entry, born) in control.birth_controls() {
                        let base = self.map(&mut state, Arc::new(ControlBacking(born.clone())))?;
                        let offset = born.slot_address().raw() - born.backing_base().raw();
                        let address = base.raw() + offset as u64;
                        // SAFETY: the mapped pool control is retained through birth and retirement.
                        unsafe {
                            born.publish_affinity_aliases(GuestVa::new(address));
                        }
                        if lifecycle.control_address(entry) != Some(address) {
                            let _ = lifecycle.bind_control_address(entry, address);
                        }
                        state.retain_thread(born);
                    }
                }
                state.retain_thread(control);
                Ok((page.raw() + page_offset as u64, base.raw() + offset as u64))
            })
        })
        .unwrap_or(Ok(LifecyclePublication::HostServed))
    }
}

impl<M: RetainedMetadataMapper> Drop for CarrierLifecycleMappings<M> {
    fn drop(&mut self) {
        // The final owner is the factory/last executor: all executor vCPUs
        // have stopped before they release their last mapping-owner reference.
        let state = self.state.get_mut();
        for control in state.threads.values() {
            control.lifecycle().close();
        }
        state.threads.clear();
        for (_, mapping) in std::mem::take(&mut state.pages) {
            // Failed retirement retains bytes in carrier custody through VM
            // destruction; never free storage under a refused stage-2 unmap.
            let _ = mapping.authority.try_retire();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn exhausted_publication_declines_once_and_keeps_the_thread_host_served() {
        let task = CurrentTask::new();
        task.publish_lifecycle(0x1000, 0x2000);
        let attempts = std::cell::Cell::new(0);
        let outcome = publish_resolved(&task, || {
            attempts.set(attempts.get() + 1);
            Err(carrick_el1_abi::MetadataResolutionError::Busy)
        });
        assert_eq!(outcome, Ok(LifecyclePublication::HostServed));
        assert_eq!(attempts.get(), 1, "exhaustion retried publication");
        assert_eq!(
            task.metadata
                .lifecycle_page
                .load(std::sync::atomic::Ordering::Acquire),
            0
        );
        assert_eq!(
            task.metadata
                .control_slot
                .load(std::sync::atomic::Ordering::Acquire),
            0
        );
    }

    #[test]
    fn both_hatches_off_publish_no_carrier_mappings() {
        let page =
            carrick_el1_abi::ThreadLifecyclePage::with_hatches(carrick_el1_abi::LifecycleHatches {
                threads: false,
                sigmask: false,
            });
        let maps = std::cell::Cell::new(0);
        let result = publish_for_page(&page, || {
            maps.set(maps.get() + 1);
        });
        assert!(
            result.is_none(),
            "disabled venue reached carrier publication"
        );
        assert_eq!(
            maps.get(),
            0,
            "disabled venue paid stage-2 publication work"
        );
    }

    fn context() -> crate::kernel::KernelContext {
        let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
            100,
            carrick_hal::ThreadId::synthetic_for_tests(100),
            "lifecycle-owner".to_owned(),
        )
        .unwrap();
        let (_kernel, context) = crate::kernel::Kernel::bootstrap_root(bootstrap).unwrap();
        context
    }

    #[test]
    fn equal_thread_keys_in_two_live_arenas_retain_both_slots() {
        let first_context = context();
        let second_context = context();
        let first = first_context.thread().control_lease();
        let second = second_context.thread().control_lease();
        assert_eq!(first.identity(), second.identity());
        assert_ne!(
            first.lifecycle().backing_base(),
            second.lifecycle().backing_base()
        );
        let mut state = State::<FakeExtent>::default();
        state.retain_thread(first.clone());
        state.retain_thread(second.clone());
        assert_eq!(state.threads.len(), 2);
        let custody = carrick_core::lifecycle::MemberControlCustody::retain(&*first).unwrap();
        // Only a committed registration publishes the unregister receipt on
        // drop; a speculative retain must not manufacture one.
        custody.commit_registration();
        state.purge_unregistered();
        assert_eq!(state.threads.len(), 2);
        drop(custody);
        state.purge_unregistered();
        assert_eq!(
            state.threads.len(),
            1,
            "only the unregister receipt releases a pin"
        );
        first.lifecycle().close();
        assert_eq!(second.lifecycle().gate(), carrick_el1_abi::GateState::Open);
    }

    /// A carrier mapper over a real EL1 region. Each map hands out a distinct
    /// aperture base; once `refuse` is set every map is refused, as a
    /// carrier whose generation went stale between loads is.
    struct FakeMapper {
        region: std::ptr::NonNull<carrick_test_support::TestEl1Region>,
        stale: bool,
        refuse: Arc<std::sync::atomic::AtomicBool>,
        maps: Arc<std::sync::atomic::AtomicUsize>,
        retired: Arc<std::sync::atomic::AtomicUsize>,
    }
    // SAFETY: the region is owned by this mapper and EL1 records in it are
    // accessed only through their atomic fields.
    unsafe impl Send for FakeMapper {}
    unsafe impl Sync for FakeMapper {}

    impl FakeMapper {
        fn new(stale: bool) -> Self {
            Self {
                region: std::ptr::NonNull::from(Box::leak(
                    carrick_test_support::TestEl1Region::zeroed(),
                )),
                stale,
                refuse: Arc::default(),
                maps: Arc::default(),
                retired: Arc::default(),
            }
        }
        fn task(&self, slot: usize) -> &CurrentTask {
            // SAFETY: the region outlives `self`; CurrentTask is atomics only.
            unsafe {
                &*self
                    .region
                    .as_ptr()
                    .cast::<u8>()
                    .add(carrick_el1_abi::EL1_CURRENT_TASKS_OFFSET as usize)
                    .cast::<CurrentTask>()
                    .add(slot)
            }
        }
    }

    impl Drop for FakeMapper {
        fn drop(&mut self) {
            // SAFETY: leaked from a Box in `new`, released exactly once here.
            drop(unsafe { Box::from_raw(self.region.as_ptr()) });
        }
    }

    struct FakeExtent {
        base: GuestVa,
        retired: Arc<std::sync::atomic::AtomicUsize>,
        _backing: Arc<dyn RetainedMetadataBacking>,
    }

    impl RetainedMetadataMapper for FakeMapper {
        type Extent = FakeExtent;
        fn region(&self) -> Result<std::ptr::NonNull<u8>, MetadataResolutionError> {
            if self.stale {
                return Err(MetadataResolutionError::StaleOwner);
            }
            Ok(self.region.cast())
        }
        fn map_retained(
            &self,
            backing: Arc<dyn RetainedMetadataBacking>,
        ) -> Result<FakeExtent, MetadataResolutionError> {
            let index = self.maps.fetch_add(1, Ordering::AcqRel);
            if self.refuse.load(Ordering::Acquire) {
                return Err(MetadataResolutionError::StaleOwner);
            }
            Ok(FakeExtent {
                base: GuestVa::new(
                    carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE + (index as u64) * 0x10_0000,
                ),
                retired: Arc::clone(&self.retired),
                _backing: backing,
            })
        }
    }

    impl RetainedMetadataExtent for FakeExtent {
        fn guest_base(&self) -> Result<GuestVa, MetadataResolutionError> {
            Ok(self.base)
        }
        fn try_retire(self) -> Result<(), Self> {
            self.retired.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    fn published(task: &CurrentTask) -> (u64, u64) {
        (
            task.metadata.lifecycle_page.load(Ordering::Acquire),
            task.metadata.control_slot.load(Ordering::Acquire),
        )
    }

    #[test]
    fn publication_maps_each_slab_once_per_carrier_and_retires_it_once() {
        let context = context();
        let control = context.thread().control_lease();
        let mapper = FakeMapper::new(false);
        let (maps, retired) = (Arc::clone(&mapper.maps), Arc::clone(&mapper.retired));
        let mappings = CarrierLifecycleMappings::new(mapper);
        assert!(
            control.lifecycle().serves_threads() || control.lifecycle().serves_sigmask(),
            "the reference model serves the lifecycle venue"
        );
        assert_eq!(
            mappings.publish(3, control.clone()),
            Ok(LifecyclePublication::Published)
        );
        let first_maps = maps.load(Ordering::Acquire);
        assert!(
            first_maps >= 1,
            "the lifecycle and control slabs are mapped"
        );
        let task = mappings.mapper.task(3);
        let (page, slot) = published(task);
        let lifecycle = control.lifecycle();
        assert_eq!(
            page,
            carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE
                + (lifecycle.page_address().raw() - lifecycle.backing_base().raw()) as u64,
            "the page is published at its offset in the first mapped slab"
        );
        assert_ne!(slot, 0);
        assert_eq!(published(mappings.mapper.task(2)), (0, 0), "only slot 3");
        // A reload of the same thread on another slot reuses every mapping.
        assert_eq!(
            mappings.publish(4, control.clone()),
            Ok(LifecyclePublication::Published)
        );
        assert_eq!(
            maps.load(Ordering::Acquire),
            first_maps,
            "one map per backing"
        );
        assert_eq!(published(mappings.mapper.task(4)), (page, slot));
        assert_eq!(retired.load(Ordering::Acquire), 0);
        drop(mappings);
        assert_eq!(
            retired.load(Ordering::Acquire),
            first_maps,
            "carrier drop retires every mapping exactly once"
        );
        assert_eq!(
            control.lifecycle().gate(),
            carrick_el1_abi::GateState::Closed
        );
    }

    #[test]
    fn stale_carrier_generation_publishes_and_maps_nothing() {
        let context = context();
        let control = context.thread().control_lease();
        let mapper = FakeMapper::new(true);
        let (maps, retired) = (Arc::clone(&mapper.maps), Arc::clone(&mapper.retired));
        let mappings = CarrierLifecycleMappings::new(mapper);
        assert_eq!(
            mappings.publish(3, control.clone()),
            Err(MetadataResolutionError::StaleOwner)
        );
        assert_eq!(
            maps.load(Ordering::Acquire),
            0,
            "no map under a stale carrier"
        );
        drop(mappings);
        assert_eq!(retired.load(Ordering::Acquire), 0);
        assert_eq!(
            control.lifecycle().gate(),
            carrick_el1_abi::GateState::Open,
            "an unpublished thread is not retained or closed by the carrier"
        );
    }

    #[test]
    fn failed_map_publication_rolls_back_the_slot_and_retires_partial_maps_once() {
        let (first_context, second_context) = (context(), context());
        let first = first_context.thread().control_lease();
        let second = second_context.thread().control_lease();
        assert_ne!(
            first.lifecycle().backing_base(),
            second.lifecycle().backing_base()
        );
        let mapper = FakeMapper::new(false);
        let (maps, retired, refuse) = (
            Arc::clone(&mapper.maps),
            Arc::clone(&mapper.retired),
            Arc::clone(&mapper.refuse),
        );
        let mappings = CarrierLifecycleMappings::new(mapper);
        assert_eq!(
            mappings.publish(3, first.clone()),
            Ok(LifecyclePublication::Published)
        );
        let first_maps = maps.load(Ordering::Acquire);
        assert_ne!(published(mappings.mapper.task(3)), (0, 0));
        // The second arena's slabs are refused at the next load of slot 3.
        refuse.store(true, Ordering::Release);
        assert_eq!(
            mappings.publish(3, second.clone()),
            Err(MetadataResolutionError::StaleOwner)
        );
        assert_eq!(
            maps.load(Ordering::Acquire),
            first_maps + 1,
            "one refused map"
        );
        assert_eq!(
            published(mappings.mapper.task(3)),
            (0, 0),
            "neither the previous thread's nor a half-mapped pair stays published"
        );
        assert_eq!(
            retired.load(Ordering::Acquire),
            0,
            "custody keeps live maps"
        );
        drop(mappings);
        assert_eq!(
            retired.load(Ordering::Acquire),
            first_maps,
            "only the committed maps retire, exactly once, with their carrier"
        );
        assert_eq!(first.lifecycle().gate(), carrick_el1_abi::GateState::Closed);
        assert_eq!(
            second.lifecycle().gate(),
            carrick_el1_abi::GateState::Open,
            "a thread whose publication failed was never retained"
        );
    }
}
