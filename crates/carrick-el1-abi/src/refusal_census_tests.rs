//! Counter publication is independent of task, memory and scheduler state.
extern crate std;

use super::Counters;
use core::sync::atomic::Ordering;

#[test]
fn refusal_snapshot_preserves_caller_populations_without_changing_service_counts() {
    let root = Counters::new();
    root.served[34].store(7, Ordering::Relaxed);
    root.forwarded[34].store(5, Ordering::Relaxed);
    for origin in [
        carrick_core_abi::service::ServiceOrigin::Initial,
        carrick_core_abi::service::ServiceOrigin::Descendant,
    ] {
        root.record_refusal(
            carrick_guest_arch::NativeOrdinal::new(34),
            origin,
            super::RefusalVenue::Ring,
        );
    }
    root.record_refusal(
        carrick_guest_arch::NativeOrdinal::new(34),
        carrick_core_abi::service::ServiceOrigin::Descendant,
        super::RefusalVenue::Carrier,
    );
    root.record_refusal(
        carrick_guest_arch::NativeOrdinal::new(34),
        carrick_core_abi::service::ServiceOrigin::Initial,
        super::RefusalVenue::Carrier,
    );
    root.record_refusal(
        carrick_guest_arch::NativeOrdinal::new(u64::MAX),
        carrick_core_abi::service::ServiceOrigin::Descendant,
        super::RefusalVenue::Carrier,
    );
    let snapshot = root.copy_snapshot();
    assert_eq!(snapshot.served[34].load(Ordering::Relaxed), 7);
    assert_eq!(snapshot.forwarded[34].load(Ordering::Relaxed), 5);
    assert_eq!(snapshot.refused[34].load(Ordering::Relaxed), 2);
    assert_eq!(snapshot.refused_child[34].load(Ordering::Relaxed), 1);
    assert_eq!(snapshot.venue_refused[34].load(Ordering::Relaxed), 2);
    assert_eq!(snapshot.venue_refused_child[34].load(Ordering::Relaxed), 1);
    assert_eq!(snapshot.venue_refused[512].load(Ordering::Relaxed), 1);
    assert_eq!(snapshot.venue_refused_child[512].load(Ordering::Relaxed), 1);
    // Another carrier has its own mapped inventory; neither a snapshot nor a
    // refusal publication may leak into it or clear the original carrier.
    let successor = Counters::new().copy_snapshot();
    assert_eq!(successor.refused[34].load(Ordering::Relaxed), 0);
    assert_eq!(root.refused[34].load(Ordering::Relaxed), 2);
}

#[test]
fn typed_refusal_records_total_and_lineage_in_the_same_carrier() {
    use super::RefusalVenue;
    use carrick_core_abi::service::ServiceOrigin;
    let first = Counters::new();
    let second = Counters::new();
    for nr in [34, 512, u64::MAX] {
        for venue in [RefusalVenue::Ring, RefusalVenue::Carrier] {
            first.record_refusal(
                carrick_guest_arch::NativeOrdinal::new(nr),
                ServiceOrigin::Initial,
                venue,
            );
            first.record_refusal(
                carrick_guest_arch::NativeOrdinal::new(nr),
                ServiceOrigin::Descendant,
                venue,
            );
        }
    }
    for (bucket, total, children) in [(34, 2, 1), (512, 4, 2)] {
        assert_eq!(first.refused[bucket].load(Ordering::Relaxed), total);
        assert_eq!(
            first.refused_child[bucket].load(Ordering::Relaxed),
            children
        );
        assert_eq!(first.venue_refused[bucket].load(Ordering::Relaxed), total);
        assert_eq!(
            first.venue_refused_child[bucket].load(Ordering::Relaxed),
            children
        );
        assert_eq!(second.refused[bucket].load(Ordering::Relaxed), 0);
        assert_eq!(second.venue_refused[bucket].load(Ordering::Relaxed), 0);
    }
}

#[test]
fn mmap_failure_capture_is_bounded_coherent_and_carrier_scoped() {
    use super::*;
    let counters = Counters::new();
    let task = CurrentTask::new();
    task.execution.task.store(41, Ordering::Relaxed);
    let layout = Layout {
        heap: ReservationRange::new(4096, 8192).unwrap(),
        arena: ReservationRange::new(0x6000000000, 0x6800000000).unwrap(),
        policy: ReservationPolicyPayload::new([4096, u64::MAX, 0, 7, 9]),
    };
    // Two concurrent writers own distinct slots. The contents of every slot
    // must belong to exactly one invocation; overflow retains the first 16.
    std::thread::scope(|scope| {
        for mm in [77, 78] {
            let counters = &counters;
            let task = &task;
            scope.spawn(move || {
                for index in 0..32 {
                    counters.mmap_failures.record_limit(
                        ReservationMm::new(mm).unwrap(),
                        task,
                        [index, 262144 + mm, 3, 0x22, u64::MAX, 0],
                        layout,
                        carrick_core_abi::Charges {
                            bytes: mm,
                            data: index,
                            locked: 0,
                        },
                    );
                }
            });
        }
    });
    let snapshot = counters.copy_snapshot();
    assert_eq!(snapshot.mmap_failures.attempted.load(Ordering::Acquire), 64);
    assert_eq!(snapshot.mmap_failures.records.len(), 16);
    for record in &snapshot.mmap_failures.records {
        assert_eq!(record.ready.load(Ordering::Acquire), 1);
        let words = record
            .words
            .each_ref()
            .map(|word| word.load(Ordering::Relaxed));
        assert!(matches!(words[0], 77 | 78));
        assert_eq!(words[1], 41);
        assert_eq!(words[3], 262144 + words[0]);
        assert_eq!(words[6], 1);
        assert_eq!(words[10], 0);
        assert_eq!(words[13], words[0]);
        assert_eq!(words[14], words[2]);
    }
    let successor = Counters::new();
    assert_eq!(successor.mmap_failures.attempted.load(Ordering::Acquire), 0);
    assert!(
        successor
            .mmap_failures
            .records
            .iter()
            .all(|r| r.ready.load(Ordering::Acquire) == 0)
    );
}
