#![allow(clippy::expect_used, clippy::unwrap_used)]

#[cfg(feature = "conformance-metrics")]
use carrick_observability::work_meter::{WorkMeter, WorkMeterError, WorkMetric};
#[cfg(feature = "conformance-metrics")]
use std::sync::{Arc, Barrier};
#[cfg(feature = "conformance-metrics")]
use std::thread;

#[cfg(feature = "conformance-metrics")]
#[test]
fn exact_accumulation_in_scope() {
    let meter = WorkMeter::default();
    let scope = meter.new_scope();
    scope.add(WorkMetric::KernelDispatches, 5).unwrap();
    scope.add(WorkMetric::KernelDispatches, 10).unwrap();
    scope.add(WorkMetric::FutexQueueVisits, 3).unwrap();

    let snapshot = scope.snapshot().unwrap();
    assert_eq!(snapshot.get(WorkMetric::KernelDispatches), Some(15));
    assert_eq!(snapshot.get(WorkMetric::FutexQueueVisits), Some(3));
}

#[cfg(feature = "conformance-metrics")]
#[test]
fn portal_metrics_round_trip() {
    let meter = WorkMeter::default();
    let scope = meter.new_scope();
    for (index, metric) in [
        WorkMetric::HvfSyscallExits,
        WorkMetric::PortalRequests,
        WorkMetric::PortalCompletions,
        WorkMetric::PortalFallbacks,
        WorkMetric::PortalStaleRejects,
    ]
    .into_iter()
    .enumerate()
    {
        scope.add(metric, index as u64 + 1).unwrap();
    }

    let encoded = serde_json::to_vec(&scope.snapshot().unwrap()).unwrap();
    let decoded: carrick_observability::work_meter::WorkSnapshot =
        serde_json::from_slice(&encoded).unwrap();
    for (index, metric) in [
        WorkMetric::HvfSyscallExits,
        WorkMetric::PortalRequests,
        WorkMetric::PortalCompletions,
        WorkMetric::PortalFallbacks,
        WorkMetric::PortalStaleRejects,
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(decoded.get(metric), Some(index as u64 + 1));
    }
}

#[cfg(feature = "conformance-metrics")]
#[test]
fn checked_overflow_sets_flag_and_errors() {
    let meter = WorkMeter::default();
    let scope = meter.new_scope();
    scope.add(WorkMetric::KernelDispatches, u64::MAX).unwrap();
    let err = scope.add(WorkMetric::KernelDispatches, 1).unwrap_err();
    assert_eq!(err, WorkMeterError::Overflow);

    // snapshot must fail once overflowed
    assert_eq!(scope.snapshot().unwrap_err(), WorkMeterError::Overflow);
}

#[cfg(feature = "conformance-metrics")]
#[test]
fn concurrent_scopes_do_not_cross_contaminate() {
    let meter = Arc::new(WorkMeter::default());
    let left = meter.new_scope();
    let right = meter.new_scope();
    let barrier = Arc::new(Barrier::new(3));

    let left_barrier = barrier.clone();
    let left_scope = left.clone();
    let left_handle = thread::spawn(move || {
        left_barrier.wait();
        for _ in 0..10_000 {
            left_scope.add(WorkMetric::KernelDispatches, 1).unwrap();
        }
    });

    let right_barrier = barrier.clone();
    let right_scope = right.clone();
    let right_handle = thread::spawn(move || {
        right_barrier.wait();
        for _ in 0..30_000 {
            right_scope.add(WorkMetric::KernelDispatches, 1).unwrap();
        }
    });

    barrier.wait();
    left_handle.join().unwrap();
    right_handle.join().unwrap();

    let left_snap = left.snapshot().unwrap();
    let right_snap = right.snapshot().unwrap();
    assert_eq!(left_snap.get(WorkMetric::KernelDispatches), Some(10_000));
    assert_eq!(right_snap.get(WorkMetric::KernelDispatches), Some(30_000));
}

#[cfg(feature = "conformance-metrics")]
#[test]
fn retired_scope_rejects_writes() {
    let meter = WorkMeter::default();
    let scope = meter.new_scope();
    scope.add(WorkMetric::KernelDispatches, 1).unwrap();
    scope.retire();

    let err = scope.add(WorkMetric::KernelDispatches, 1).unwrap_err();
    assert_eq!(err, WorkMeterError::RetiredScope);
}

#[cfg(feature = "conformance-metrics")]
#[test]
fn raw_id_reuse_with_new_generation_and_stale_handle() {
    let meter = WorkMeter::default();
    let scope1 = meter.new_scope();
    let stale_handle = scope1.clone();
    let raw1 = scope1.id().raw;
    let gen1 = scope1.id().generation;

    scope1.retire();

    let scope2 = meter.new_scope();
    assert_eq!(scope2.id().raw, raw1);
    assert_ne!(scope2.id().generation, gen1);

    // Stale handle is retired
    assert_eq!(
        stale_handle
            .add(WorkMetric::KernelDispatches, 1)
            .unwrap_err(),
        WorkMeterError::RetiredScope
    );

    // New scope accepts writes
    scope2.add(WorkMetric::KernelDispatches, 42).unwrap();
    assert_eq!(
        scope2.snapshot().unwrap().get(WorkMetric::KernelDispatches),
        Some(42)
    );
}

#[cfg(not(feature = "conformance-metrics"))]
#[test]
fn disabled_feature_behavior_and_size() {
    use carrick_observability::work_meter::{WorkMeter, WorkMeterError, WorkMetric, WorkScope};

    assert!(std::mem::size_of::<WorkScope>() <= 16);
    let meter = WorkMeter::default();
    let scope = meter.new_scope();
    assert!(scope.add(WorkMetric::KernelDispatches, 1).is_ok());
    assert_eq!(scope.snapshot().unwrap_err(), WorkMeterError::Disabled);
}
