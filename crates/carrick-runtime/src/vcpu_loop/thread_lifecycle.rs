//! Carrier custody for authoritative thread lifecycle ABI storage.

use std::collections::BTreeMap;
use std::sync::Arc;

use carrick_el1_abi::{CurrentTask, PinnedMetadataExtent};
use carrick_guest_mem::{GuestVa, HostVa};
use carrick_kernel::kernel::objects::{ThreadControlLease, ThreadKey, ThreadLifecycleLease};
use carrick_vmm_hvf::metadata_grant::{
    CarrierMetadataAccess, RetainedMetadataBacking, RetainedMetadataMapping,
};
use parking_lot::Mutex;

fn publish_for_page<R>(
    page: &carrick_el1_abi::ThreadLifecyclePage,
    publish: impl FnOnce() -> R,
) -> Option<R> {
    (page.serves_threads() || page.serves_sigmask()).then(publish)
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum LifecyclePublication {
    Published,
    HostServed,
}

fn publish_resolved(
    task: &CurrentTask,
    resolve: impl FnOnce() -> Result<(u64, u64), carrick_el1_abi::MetadataResolutionError>,
) -> Result<LifecyclePublication, carrick_el1_abi::MetadataResolutionError> {
    task.publish_lifecycle(0, 0);
    let (page, control) = match resolve() {
        Ok(binding) => binding,
        Err(carrick_el1_abi::MetadataResolutionError::Busy) => {
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
struct ActivityBacking(carrick_kernel::kernel::objects::ThreadLedgerActivityLease);
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

struct Mapping {
    authority: RetainedMetadataMapping,
    guest_base: GuestVa,
}

#[derive(Default)]
struct State {
    pages: BTreeMap<usize, Mapping>,
    threads: BTreeMap<(usize, ThreadKey), ThreadControlLease>,
}

impl State {
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
pub(super) struct CarrierLifecycleMappings {
    access: CarrierMetadataAccess,
    state: Mutex<State>,
}

impl CarrierLifecycleMappings {
    pub(super) fn new(access: CarrierMetadataAccess) -> Self {
        Self {
            access,
            state: Mutex::new(State::default()),
        }
    }

    fn map(
        &self,
        state: &mut State,
        backing: Arc<dyn RetainedMetadataBacking>,
    ) -> Result<GuestVa, carrick_el1_abi::MetadataResolutionError> {
        let key = backing.host_base().raw();
        if let Some(mapping) = state.pages.get(&key) {
            return Ok(mapping.guest_base);
        }
        let authority = self.access.map_retained(backing)?;
        let pin = authority.pin()?;
        let guest_base = GuestVa(pin.extent().base());
        drop(pin);
        state.pages.insert(
            key,
            Mapping {
                authority,
                guest_base,
            },
        );
        Ok(guest_base)
    }

    pub(super) fn publish(
        &self,
        slot: usize,
        control: ThreadControlLease,
    ) -> Result<LifecyclePublication, carrick_el1_abi::MetadataResolutionError> {
        if slot >= carrick_el1_abi::EL1_STACK_SLOTS as usize {
            return Err(carrick_el1_abi::MetadataResolutionError::InvalidExtent);
        }
        let lifecycle = control.lifecycle();
        publish_for_page(&lifecycle, || {
            let region = self.access.region()?;
            // SAFETY: the exact carrier access retains the region and both mapped
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
                state.threads.retain(|_, control| {
                    control.entry().is_none_or(|entry| {
                        !matches!(control.lifecycle().state(entry.index()), Some((generation,
                            carrick_el1_abi::EntryState::Reaped | carrick_el1_abi::EntryState::Revoked))
                            if generation == entry.generation())
                    })
                });
                let page = self.map(&mut state, Arc::new(LifecycleBacking(control.lifecycle())))?;
                let page_offset = lifecycle.page_address().raw() - lifecycle.backing_base().raw();
                let base = self.map(&mut state, Arc::new(ControlBacking(control.clone())))?;
                let offset = control.slot_address().raw() - control.backing_base().raw();
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

impl Drop for CarrierLifecycleMappings {
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
            task.lifecycle_page
                .load(std::sync::atomic::Ordering::Acquire),
            0
        );
        assert_eq!(
            task.control_slot.load(std::sync::atomic::Ordering::Acquire),
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

    fn context() -> carrick_kernel::kernel::KernelContext {
        let bootstrap = carrick_kernel::kernel::RootBootstrap::for_reference_model(
            100,
            carrick_hal::ThreadId::synthetic_for_tests(100),
            "lifecycle-owner".to_owned(),
        )
        .unwrap();
        let (_kernel, context) = carrick_kernel::kernel::Kernel::bootstrap_root(bootstrap).unwrap();
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
        let mut state = State::default();
        state.retain_thread(first.clone());
        state.retain_thread(second.clone());
        assert_eq!(state.threads.len(), 2);
        first.lifecycle().close();
        assert_eq!(second.lifecycle().gate(), carrick_el1_abi::GateState::Open);
    }
}
