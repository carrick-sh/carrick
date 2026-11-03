//! Counter publication is independent of task, memory and scheduler state.
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
