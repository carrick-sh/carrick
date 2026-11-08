//! Production lock entry points over shared IPC records.
use super::*;
use carrick_sched_core::object_wait::OwnedObjectWakeEffects;
use carrick_sched_core::object_wait::ipc_release::{IpcLockIndex, IpcLockReleaseVenue};
use carrick_sched_core::refusal::{Attempt, ContentionSource, Refusal, ReleaseCause};
use carrick_sched_core::{ThreadCtx, Waker, ZoneTables};
use core::num::NonZeroU64;

fn zone<C: crate::EntryContext>() -> Box<ZoneTables<C>> {
    // SAFETY: zero is the initial scheduler state; allocate aligned off-stack.
    unsafe {
        let ptr = std::alloc::alloc_zeroed(Layout::new::<ZoneTables<C>>()).cast::<ZoneTables<C>>();
        assert!(!ptr.is_null());
        Box::from_raw(ptr)
    }
}
fn complete<C: crate::EntryContext>(_: &ZoneTables<C>, effects: OwnedObjectWakeEffects<'_, C>) {
    let _ = effects.deliver_handbacks(&mut |_| panic!("unexpected handback"));
}
fn object_release<C: crate::EntryContext>() {
    let zone = zone::<C>();
    let f = fixture(8 * 1024 * 1024);
    let object = f
        .region
        .create_eventfd(7, EventMode::Counter, &EL1)
        .unwrap();
    let index = IpcLockIndex::object(object.index as usize).unwrap();
    let carrier = f.region.operation_slot_generation();
    zone.bind_ipc_lock_release(index, carrier, &EL1, &|e| complete(&zone, e))
        .unwrap();
    let venue = IpcLockReleaseVenue {
        zone: &zone,
        carrier,
        waker: Waker::Host,
        deliver: complete,
    };
    let region = f.region.with_lock_release(&venue);
    let snapshot = || {
        zone.object_wait_with_completion(index.key(carrier), &EL1, &|e| complete(&zone, e))
            .unwrap()
            .snapshot()
    };
    let before = snapshot();
    let held = region.lock(object, &EL1).unwrap();
    assert!(snapshot() == before, "acquire is not release");
    drop(held);
    assert!(snapshot() != before, "object unlock must publish release");
}
#[test]
fn ipc_object_unlock_publishes_release_for_both_contexts() {
    object_release::<carrick_sched_core::ParkedContextWords>();
    object_release::<crate::Aarch64ParkedContext>();
}
#[test]
fn ipc_table_unlock_publishes_release_after_exclusion() {
    let zone = zone::<ThreadCtx>();
    let f = fixture(8 * 1024 * 1024);
    let table = f.table();
    let index = IpcLockIndex::table(table.to_raw().index as usize).unwrap();
    let carrier = f.region.operation_slot_generation();
    zone.bind_ipc_lock_release(index, carrier, &EL1, &|e| complete(&zone, e))
        .unwrap();
    let venue = IpcLockReleaseVenue {
        zone: &zone,
        carrier,
        waker: Waker::Host,
        deliver: complete,
    };
    let region = f.region.with_lock_release(&venue);
    let authority = region.fd(BoundedSpin(0));
    let snapshot = || {
        zone.object_wait_with_completion(index.key(carrier), &EL1, &|e| complete(&zone, e))
            .unwrap()
            .snapshot()
    };
    let before = snapshot();
    let held = authority.transaction(table).unwrap();
    assert!(matches!(
        authority.transaction(table),
        Err(fd::Error::Contended)
    ));
    assert!(snapshot() == before);
    drop(held);
    assert!(snapshot() != before, "table unlock must publish release");
    assert!(
        authority.transaction(table).is_ok(),
        "release precedes completion"
    );
}
#[test]
fn ipc_lock_release_domain_is_disjoint_and_carrier_owned() {
    let zone = zone::<ThreadCtx>();
    let carrier = NonZeroU64::new(11).unwrap();
    let other = NonZeroU64::new(12).unwrap();
    let object = IpcLockIndex::object(0).unwrap();
    let table = IpcLockIndex::table(0).unwrap();
    assert_ne!(object.key(carrier), table.key(carrier));
    for index in [object, table] {
        zone.bind_ipc_lock_release(index, carrier, &EL1, &|e| complete(&zone, e))
            .unwrap();
        zone.bind_ipc_lock_release(index, carrier, &EL1, &|e| complete(&zone, e))
            .unwrap();
        assert_eq!(
            zone.bind_ipc_lock_release(index, other, &EL1, &|e| complete(&zone, e)),
            Err(carrick_sched_core::object_wait::ObjectWaitError::Stale)
        );
        assert!(zone.ipc_lock_release_source(index, other).is_err());
    }
    assert!(IpcLockIndex::object(IPC_MAX_OBJECTS).is_none());
    assert!(IpcLockIndex::table(IPC_FD_TABLES).is_none());
}
#[test]
fn ipc_busy_once_then_success_uses_a_release_ticket() {
    let zone = zone::<ThreadCtx>();
    let f = fixture(8 * 1024 * 1024);
    let object = f
        .region
        .create_eventfd(7, EventMode::Counter, &EL1)
        .unwrap();
    let index = IpcLockIndex::object(object.index as usize).unwrap();
    let carrier = f.region.operation_slot_generation();
    zone.bind_ipc_lock_release(index, carrier, &EL1, &|e| complete(&zone, e))
        .unwrap();
    let venue = IpcLockReleaseVenue {
        zone: &zone,
        carrier,
        waker: Waker::Host,
        deliver: complete,
    };
    let region = f.region.with_lock_release(&venue);
    let source = zone.ipc_lock_release_source(index, carrier).unwrap();
    let held = region.lock(object, &EL1).unwrap();
    let refusal = source.contend(|| {
        region.lock(object, &BoundedSpin(0)).map_err(|e| match e {
            IpcError::Contended => Attempt::<()>::Contended(ReleaseCause::Object),
            _ => panic!("unexpected refusal: {e:?}"),
        })
    });
    let Err(Refusal::Contended(ticket)) = refusal else {
        panic!("contended release ticket");
    };
    drop(held);
    // SAFETY: return the exact owned operation on revision change, without a
    // retained guard or pretending to park an executor worker.
    unsafe {
        ticket.park_and_rerun(object, |operation, enrollment| {
            assert!(
                !enrollment.unchanged(),
                "release before enrollment must rerun"
            );
            assert_eq!(operation, object);
            assert_eq!(
                region
                    .lock(operation, &BoundedSpin(0))
                    .unwrap()
                    .eventfd()
                    .unwrap()
                    .try_read()
                    .result,
                Ok(7)
            );
        })
    };
}

fn defer<C: crate::EntryContext>(_: &ZoneTables<C>, effects: OwnedObjectWakeEffects<'_, C>) {
    let (_, effects, _) = effects.defer_handbacks();
    assert_eq!(effects, carrick_sched_core::WakeEffects::default());
}

fn after_park<C: crate::EntryContext>() {
    use carrick_sched_core::object_wait::OperationToken;
    use carrick_sched_core::{AffinitySource, ThreadIdentity};
    use std::sync::mpsc::channel;
    use std::time::Duration;
    let zone = zone::<C>();
    let f = fixture(8 * 1024 * 1024);
    let object = f
        .region
        .create_eventfd(7, EventMode::Counter, &EL1)
        .unwrap();
    let index = IpcLockIndex::object(object.index as usize).unwrap();
    let carrier = f.region.operation_slot_generation();
    zone.bind_ipc_lock_release(index, carrier, &EL1, &|e| defer(&zone, e))
        .unwrap();
    let venue = IpcLockReleaseVenue {
        zone: &zone,
        carrier,
        waker: Waker::Host,
        deliver: defer,
    };
    let region = f.region.with_lock_release(&venue);
    let source = zone.ipc_lock_release_source(index, carrier).unwrap();
    let record = zone
        .alloc_record(ThreadIdentity {
            tid: 77,
            serial: 1,
            mm: 77,
            file_table: 1,
            generation: 1,
            affinity_source: AffinitySource::UNBOUND,
            affinity: 0,
            lifecycle_page: 0,
            control_slot: 0,
        })
        .unwrap();
    let (locked, locked_rx) = channel();
    let (release, release_rx) = channel();
    let (finished, finished_rx) = channel();
    std::thread::scope(|scope| {
        scope.spawn(move || {
            let held = region.lock(object, &EL1).unwrap();
            locked.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(held);
            finished.send(()).unwrap();
        });
        locked_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let Err(Refusal::Contended(ticket)) = source.contend(|| {
            region.lock(object, &BoundedSpin(0)).map_err(|e| match e {
                IpcError::Contended => Attempt::<()>::Contended(ReleaseCause::Object),
                _ => panic!("unexpected refusal: {e:?}"),
            })
        }) else {
            panic!("held lock must refuse");
        };
        let operation = OperationToken::new(91, 3).unwrap();
        // SAFETY: enroll the exact operation in the existing scheduler queue,
        // without retaining a data or fd guard across the publication.
        unsafe {
            ticket.park_and_rerun(operation, |operation, enrollment| {
                zone.object_wait_with_completion(enrollment.key(), &EL1, &|e| defer(&zone, e))
                    .unwrap()
                    .park_host_rechecked(enrollment.observed(), record, operation, || true)
                    .unwrap();
            })
        };
        let mut handed = Vec::new();
        zone.take_completion_handbacks(&EL1, &mut |r| handed.push(r));
        assert!(
            handed.is_empty(),
            "a held data lock cannot complete the waiter"
        );
        release.send(()).unwrap();
        finished_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        zone.take_completion_handbacks(&EL1, &mut |r| handed.push(r));
        assert_eq!(handed, [zone.record_ref(record)]);
        zone.take_completion_handbacks(&EL1, &mut |r| handed.push(r));
        assert_eq!(handed.len(), 1, "one release, one retained operation");
        // SAFETY: the handback published exclusive host custody and unlinked
        // every registration; the same owned operation is consumed once.
        assert_eq!(
            unsafe { zone.record(record).take_object_operation() },
            Some(OperationToken::new(91, 3).unwrap())
        );
        assert!(region.lock(object, &BoundedSpin(0)).is_ok());
    });
}
#[test]
fn ipc_release_after_park_returns_exact_operation_with_two_live_threads() {
    after_park::<crate::Aarch64ParkedContext>();
    after_park::<carrick_sched_core::ParkedContextWords>();
}

#[test]
fn ipc_release_does_not_wake_an_unrelated_object_lane() {
    let zone = zone::<ThreadCtx>();
    let f = fixture(8 * 1024 * 1024);
    let first = f
        .region
        .create_eventfd(0, EventMode::Counter, &EL1)
        .unwrap();
    let second = f
        .region
        .create_eventfd(0, EventMode::Counter, &EL1)
        .unwrap();
    let carrier = f.region.operation_slot_generation();
    let indices = [first, second].map(|o| IpcLockIndex::object(o.index as usize).unwrap());
    for index in indices {
        zone.bind_ipc_lock_release(index, carrier, &EL1, &|e| complete(&zone, e))
            .unwrap();
    }
    let venue = IpcLockReleaseVenue {
        zone: &zone,
        carrier,
        waker: Waker::Host,
        deliver: complete,
    };
    let region = f.region.with_lock_release(&venue);
    let snapshot = |index: IpcLockIndex| {
        zone.object_wait_with_completion(index.key(carrier), &EL1, &|e| complete(&zone, e))
            .unwrap()
            .snapshot()
    };
    let before = indices.map(snapshot);
    drop(region.lock(first, &EL1).unwrap());
    assert_eq!(snapshot(indices[0]).revision(), before[0].revision() + 1);
    assert_eq!(snapshot(indices[1]), before[1]);
}
