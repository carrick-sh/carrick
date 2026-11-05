//! Bridge an actual physical producer to the root owner's existing wait source.
//! The observation precedes physical preparation; enrollment never invents a
//! revision or holds a service/ledger lock while invoking a producer callback.
use carrick_core_abi::service::{ServiceIdentity, ServiceRequest};
use carrick_el1_abi::{Aarch64ParkedContext, PortalOwnerWait, PortalWaitCause};
use carrick_guest_mem::OwnedMemoryWait;
use carrick_hal::TrapError;
use carrick_sched_core::ZoneTables;
use carrick_sched_core::spaces::notification::SpaceWaitCause;
use std::sync::Arc;

#[derive(Clone, Copy, Debug)]
pub(crate) struct RootPhysicalWaitSample {
    identity: ServiceIdentity,
    wait: PortalOwnerWait,
}

#[derive(Debug, Default)]
struct ReleaseState {
    active: bool,
    released: bool,
}

#[derive(Debug)]
struct Subscription {
    gate: Arc<parking_lot::Mutex<ReleaseState>>,
    _wait: OwnedMemoryWait,
    _enrollment: Box<dyn std::fmt::Debug + Send + Sync>,
}
impl Drop for Subscription {
    fn drop(&mut self) {
        // Join any snapshot callback already publishing into the ABI mapping.
        // A snapshotted callback that starts later observes inactive instead.
        self.gate.lock().active = false;
    }
}

#[derive(Debug)]
pub(crate) struct NativeRootWaitLedger {
    // A preparation turn may register an immediately firing callback before
    // it has a row. Teardown joins those turns before draining the rows.
    admission: parking_lot::RwLock<bool>,
    entries: parking_lot::Mutex<Vec<Option<Subscription>>>,
}
impl Default for NativeRootWaitLedger {
    fn default() -> Self {
        Self {
            admission: parking_lot::RwLock::new(false),
            entries: parking_lot::Mutex::new(
                std::iter::repeat_with(|| None)
                    .take(carrick_sched_core::ZONE_RECORDS)
                    .collect(),
            ),
        }
    }
}
impl NativeRootWaitLedger {
    pub(crate) fn sample(
        request: ServiceRequest,
        zone: &ZoneTables<Aarch64ParkedContext>,
    ) -> Result<RootPhysicalWaitSample, TrapError> {
        let handle = request.identity.birth.mm;
        let source = zone
            .space_entry(std::num::NonZeroU64::new(handle.mm().raw()).ok_or_else(failure)?)
            .ok_or_else(failure)?
            .notifications(handle.incarnation())
            .map_err(|_| failure())?;
        let revision = source.observe(SpaceWaitCause::PendingEdit).revision();
        // SAFETY: the exact live owner notification source supplied this
        // observation before the physical preparation can miss readiness.
        let wait =
            unsafe { PortalOwnerWait::from_owner(handle, PortalWaitCause::PendingEdit, revision) };
        Ok(RootPhysicalWaitSample {
            identity: request.identity,
            wait,
        })
    }

    pub(crate) fn enroll(
        &self,
        custody: &Arc<crate::trap::CarrierVmCustody>,
        request: ServiceRequest,
        sample: RootPhysicalWaitSample,
        wait: OwnedMemoryWait,
    ) -> Result<PortalOwnerWait, TrapError> {
        let admitted = self.admission.read();
        if !*admitted {
            return Err(failure());
        }
        if sample.identity != request.identity
            || sample.wait.handle().carrier() != custody.transfer_carrier
            || custody.native_wait_channel_wake.lock().is_none()
        {
            return Err(failure());
        }
        let index = request.identity.birth.record.id.raw() as usize;
        let weak = Arc::downgrade(custody);
        let gate = Arc::new(parking_lot::Mutex::new(ReleaseState {
            active: true,
            released: false,
        }));
        let callback_gate = gate.clone();
        let handle = sample.wait.handle();
        let publish: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            let mut state = callback_gate.lock();
            if !state.active || state.released {
                return;
            }
            state.released = true;
            // Hold through publication: clearing the subscription must join
            // the entire callback before its zone mapping can be released.
            let Some(custody) = weak.upgrade() else {
                return;
            };
            // The runtime owns the zone venue. Never dereference a stopped
            // lane's raw ABI view from this arbitrary producer thread.
            let wake = custody.native_wait_channel_wake.lock().clone();
            if let Some(wake) = wake {
                wake.complete_physical_release(handle);
            }
        });
        // Enroll first, then probe. A release in either interval publishes
        // exactly one owner edge through the shared release gate.
        let (enrollment, ready) = wait.0.enroll(publish.clone());
        if ready || wait.0.is_ready() {
            publish();
        }
        let subscription = Subscription {
            gate,
            _wait: wait,
            _enrollment: enrollment,
        };
        let mut entries = self.entries.lock();
        let Some(entry) = entries.get_mut(index) else {
            drop(entries);
            return Err(failure());
        };
        if entry.is_some() {
            drop(entries);
            return Err(failure());
        }
        *entry = Some(subscription);
        drop(entries);
        drop(admitted);
        Ok(sample.wait)
    }

    /// Authenticated intake proves the current incarnation owns this index.
    /// Its predecessor has retired, so remove any old subscription at the
    /// index and join its callbacks before allowing the new request to prepare.
    pub(crate) fn clear_admitted(
        &self,
        request: ServiceRequest,
        zone: &ZoneTables<Aarch64ParkedContext>,
    ) -> Result<(), TrapError> {
        let admitted = self.admission.read();
        if !*admitted {
            return Err(failure());
        }
        let record = request.identity.birth.record;
        if zone.record_ref(record.id) != record {
            return Err(failure());
        }
        let removed = {
            let mut entries = self.entries.lock();
            entries
                .get_mut(record.id.raw() as usize)
                .ok_or_else(failure)?
                .take()
        };
        drop(removed);
        drop(admitted);
        Ok(())
    }

    /// Join all callback snapshots before any ABI snapshot, unmap or release.
    pub(crate) fn clear_all_before_mapping_release(&self) {
        let mut admitted = self.admission.write();
        *admitted = false;
        let removed = {
            let mut entries = self.entries.lock();
            entries
                .iter_mut()
                .filter_map(Option::take)
                .collect::<Vec<_>>()
        };
        // Keep close custody through the join. A concurrent closer or new
        // VM cannot observe an empty ledger before callbacks have finished.
        drop(removed);
        drop(admitted);
    }

    /// The lifecycle owner opens admission before publishing a new exact VM
    /// generation. Initial creation has no subscriptions; reuse follows closed,
    /// joined teardown. Snapshotted old callbacks keep their inactive gates.
    pub(crate) fn reset_for_new_vm(&self) {
        let mut admitted = self.admission.write();
        assert!(!*admitted, "new VM must follow closed root-wait admission");
        let empty = self.entries.lock().iter().all(Option::is_none);
        assert!(empty, "new VM cannot inherit old subscriptions");
        *admitted = true;
    }
}
fn failure() -> TrapError {
    TrapError::Hypervisor("root physical wait lost exact owner authority".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata_grant::NativeWaitChannelWake;
    use carrick_core_abi::service::{ServiceBirth, ServiceOperation, ServiceOrigin};
    use carrick_sched_core::object_wait::{OperationToken, OwnedObjectWakeEffects};
    use carrick_sched_core::process::{TaskId, TaskKey, TaskSerial};
    use carrick_sched_core::{BoundedSpin, ThreadIdentity};
    use std::num::{NonZeroI32, NonZeroU64};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Wake {
        region: Arc<carrick_test_support::TestEl1Region>,
        carrier: NonZeroU64,
        publications: AtomicUsize,
        handbacks: AtomicUsize,
    }
    impl std::fmt::Debug for Wake {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Wake")
                .field("carrier", &self.carrier)
                .finish_non_exhaustive()
        }
    }
    impl Wake {
        fn zone(&self) -> &ZoneTables<Aarch64ParkedContext> {
            // SAFETY: the retained typed fixture contains aligned ABI storage.
            unsafe {
                &*self
                    .region
                    .as_ptr()
                    .add(carrick_el1_abi::EL1_ZONE_OFFSET as usize)
                    .cast()
            }
        }
    }
    impl crate::metadata_grant::NativeWaitChannelWake for Wake {
        fn complete_physical_release(&self, handle: carrick_el1_abi::El1MmHandle) -> bool {
            if handle.carrier() != self.carrier {
                return false;
            }
            let zone = self.zone();
            let Some(entry) = zone.space_entry(NonZeroU64::new(handle.mm().raw()).unwrap()) else {
                return false;
            };
            let Ok(source) = entry.notifications(handle.incarnation()) else {
                return false;
            };
            self.publications.fetch_add(1, Ordering::AcqRel);
            source
                .reserve(SpaceWaitCause::PendingEdit)
                .publish(carrick_sched_core::Waker::Host, &|effects| {
                    self.complete_mm_wake(zone, effects)
                });
            true
        }
        fn complete_mm_wake(
            &self,
            _: &ZoneTables<Aarch64ParkedContext>,
            effects: OwnedObjectWakeEffects<'_, Aarch64ParkedContext>,
        ) {
            let _ = effects.deliver_handbacks(&mut |_| {
                self.handbacks.fetch_add(1, Ordering::AcqRel);
            });
        }
        fn wake(&self, _: carrick_el1_abi::EntryMmKey, _: NonZeroU64) -> Option<u32> {
            None
        }
    }

    #[derive(Default)]
    struct DelayedPhysical {
        callback: parking_lot::Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
        before_return: parking_lot::Mutex<
            Option<(
                std::sync::mpsc::SyncSender<()>,
                std::sync::mpsc::Receiver<()>,
            )>,
        >,
    }
    impl std::fmt::Debug for DelayedPhysical {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("DelayedPhysical")
        }
    }
    impl carrick_guest_mem::PhysicalMemoryWait for DelayedPhysical {
        fn is_ready(&self) -> bool {
            false
        }
        fn enroll(
            &self,
            callback: Arc<dyn Fn() + Send + Sync>,
        ) -> (Box<dyn std::fmt::Debug + Send + Sync>, bool) {
            *self.callback.lock() = Some(callback);
            if let Some((entered, release)) = self.before_return.lock().take() {
                entered.send(()).unwrap();
                release
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
            }
            (Box::new(()), false)
        }
    }

    #[test]
    fn physical_bridge_preserves_sample_and_publishes_once_before_or_after_enrollment() {
        for ready_before_enrollment in [false, true] {
            let custody = Arc::new(crate::trap::CarrierVmCustody::new_live_fixture());
            let wake = Arc::new(Wake {
                region: Arc::from(carrick_test_support::TestEl1Region::zeroed()),
                carrier: custody.transfer_carrier,
                publications: AtomicUsize::new(0),
                handbacks: AtomicUsize::new(0),
            });
            *custody.native_wait_channel_wake.lock() = Some(wake.clone());
            let zone = wake.zone();
            let index = zone.spaces.publish_closed(77, 0x8000, 0x8000).unwrap();
            zone.spaces.open(index);
            let incarnation = NonZeroU64::new(11).unwrap();
            let entry = zone.space_entry(NonZeroU64::new(77).unwrap()).unwrap();
            entry
                .admit_notifications(incarnation, &BoundedSpin(0), &|effects| {
                    let _ = effects.defer_handbacks();
                })
                .unwrap();
            let record = zone
                .alloc_record(ThreadIdentity {
                    tid: 101,
                    serial: 1001,
                    mm: 77,
                    file_table: 1,
                    generation: 1,
                    affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                    affinity: 0,
                    lifecycle_page: 0,
                    control_slot: 0,
                })
                .unwrap();
            // SAFETY: this fixture admitted the exact live source above.
            let handle = unsafe {
                carrick_el1_abi::El1MmHandle::from_admitted_owner(
                    custody.transfer_carrier,
                    carrick_el1_abi::ReservationMm::new(77).unwrap(),
                    incarnation,
                )
            };
            let request = ServiceRequest {
                identity: ServiceIdentity {
                    birth: ServiceBirth {
                        origin: ServiceOrigin::Initial,
                        process: TaskKey {
                            id: TaskId::from_registry_allocation(NonZeroI32::new(101).unwrap()),
                            serial: TaskSerial::from_registry_allocation(NonZeroU64::MIN),
                        },
                        thread: carrick_core_abi::EntryThreadGeneration::from_raw(1),
                        record: zone.record_ref(record),
                        mm: handle,
                    },
                    execution: carrick_core_abi::SnapshotGeneration::from_raw(1),
                    sequence: NonZeroU64::MIN,
                },
                operation: ServiceOperation::Crossing {
                    ordinal: carrick_guest_arch::NativeOrdinal::new(0),
                },
                fault_sequence: None,
            };
            let ledger = Arc::new(NativeRootWaitLedger::default());
            ledger.reset_for_new_vm();
            let sample = NativeRootWaitLedger::sample(request, zone).unwrap();
            let revision = sample.wait.revision();
            let completion = carrick_thread::physical_grant::PhysicalGrantCompletion::new();
            let physical = OwnedMemoryWait(completion.wait_weak().upgrade().unwrap());
            let mut completion = Some(completion);
            if ready_before_enrollment {
                drop(completion.take());
            }
            let receipt = ledger.enroll(&custody, request, sample, physical).unwrap();
            assert_eq!(
                receipt.revision(),
                revision,
                "never resample after preparation"
            );
            let slots = unsafe {
                &*wake
                    .region
                    .as_ptr()
                    .add(carrick_el1_abi::EL1_MM_PORTAL_OFFSET as usize)
                    .cast::<carrick_el1_abi::MmPortalSlots>()
            };
            assert!(slots.bind_carrier(custody.transfer_carrier));
            let enrollment = slots.authenticate_wait(zone, receipt).unwrap();
            let operation = OperationToken::new(701, 11).unwrap();
            let complete = |effects: OwnedObjectWakeEffects<'_, Aarch64ParkedContext>| {
                wake.complete_mm_wake(zone, effects)
            };
            if ready_before_enrollment {
                let (error, returned) = enrollment
                    .park_host(record, operation, &complete)
                    .unwrap_err();
                assert_eq!(
                    error,
                    carrick_sched_core::object_wait::ObjectWaitError::Changed
                );
                assert_eq!(returned.index(), 701);
            } else {
                enrollment.park_host(record, operation, &complete).unwrap();
                assert_eq!(wake.handbacks.load(Ordering::Acquire), 0);
                drop(completion.take());
                assert_eq!(wake.handbacks.load(Ordering::Acquire), 1);
                assert_eq!(
                    unsafe { zone.record(record).take_object_operation() }
                        .unwrap()
                        .index(),
                    701
                );
            }
            assert_eq!(wake.publications.load(Ordering::Acquire), 1);
            assert_eq!(
                entry
                    .notifications(incarnation)
                    .unwrap()
                    .observe(SpaceWaitCause::PendingEdit)
                    .revision(),
                revision + 1
            );
            ledger.clear_admitted(request, zone).unwrap();
            ledger.clear_all_before_mapping_release();
            ledger.reset_for_new_vm();
            assert_eq!(wake.publications.load(Ordering::Acquire), 1);
            // The producer has already snapshotted this callback. Removing
            // its enrollment cannot revoke that snapshot; the release gate
            // must make it inert before a reused record is admitted.
            let delayed = Arc::new(DelayedPhysical::default());
            let sample = NativeRootWaitLedger::sample(request, zone).unwrap();
            ledger
                .enroll(&custody, request, sample, OwnedMemoryWait(delayed.clone()))
                .unwrap();
            let snapshotted = delayed.callback.lock().as_ref().unwrap().clone();
            zone.free_record(record);
            let reused = zone
                .alloc_record(ThreadIdentity {
                    tid: 102,
                    serial: 1002,
                    mm: 77,
                    file_table: 1,
                    generation: 1,
                    affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                    affinity: 0,
                    lifecycle_page: 0,
                    control_slot: 0,
                })
                .unwrap();
            assert_eq!(reused, record, "fixture must reuse the retired index");
            let mut next = request;
            next.identity.birth.record = zone.record_ref(reused);
            assert_ne!(next.identity.birth.record, request.identity.birth.record);
            assert!(
                ledger.clear_admitted(request, zone).is_err(),
                "stale intake cannot clear successor"
            );
            ledger.clear_admitted(next, zone).unwrap();
            snapshotted();
            assert_eq!(
                wake.publications.load(Ordering::Acquire),
                1,
                "old snapshot is inert after clear"
            );
            let current = Arc::new(DelayedPhysical::default());
            let sample = NativeRootWaitLedger::sample(next, zone).unwrap();
            ledger
                .enroll(&custody, next, sample, OwnedMemoryWait(current.clone()))
                .unwrap();
            let current_snapshot = current.callback.lock().as_ref().unwrap().clone();
            ledger.clear_all_before_mapping_release();
            let sample = NativeRootWaitLedger::sample(next, zone).unwrap();
            assert!(
                ledger
                    .enroll(
                        &custody,
                        next,
                        sample,
                        OwnedMemoryWait(Arc::new(DelayedPhysical::default()))
                    )
                    .is_err(),
                "closed mapping cannot admit a callback"
            );
            current_snapshot();
            assert_eq!(
                wake.publications.load(Ordering::Acquire),
                1,
                "teardown joins and invalidates snapshots before ABI release"
            );
            // A producer may register its callback before enrollment returns
            // and before the ledger has a row. Teardown must join that turn.
            ledger.reset_for_new_vm();
            let blocked = Arc::new(DelayedPhysical::default());
            let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
            let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
            *blocked.before_return.lock() = Some((entered_tx, release_rx));
            let sample = NativeRootWaitLedger::sample(next, zone).unwrap();
            let turn_ledger = ledger.clone();
            let turn_custody = custody.clone();
            let turn_source = blocked.clone();
            let turn = std::thread::spawn(move || {
                turn_ledger.enroll(&turn_custody, next, sample, OwnedMemoryWait(turn_source))
            });
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            assert!(
                ledger.admission.try_write().is_none(),
                "registered but unpublished enrollment retains admission"
            );
            let early_snapshot = blocked.callback.lock().as_ref().unwrap().clone();
            let closing = ledger.clone();
            let (closing_tx, closing_rx) = std::sync::mpsc::sync_channel(0);
            let close = std::thread::spawn(move || {
                closing_tx.send(()).unwrap();
                closing.clear_all_before_mapping_release();
            });
            closing_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            release_tx.send(()).unwrap();
            turn.join().unwrap().unwrap();
            close.join().unwrap();
            early_snapshot();
            assert_eq!(
                wake.publications.load(Ordering::Acquire),
                1,
                "pre-row snapshot is inert after teardown joins admission"
            );
            assert!(!*ledger.admission.read());
            assert!(ledger.entries.lock().iter().all(Option::is_none));
            zone.free_record(reused);
            *custody.native_wait_channel_wake.lock() = None;
        }
    }
}
