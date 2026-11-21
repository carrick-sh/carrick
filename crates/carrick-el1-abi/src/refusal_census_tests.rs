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
            super::RefusalArguments::Unretained,
        );
    }
    root.record_refusal(
        carrick_guest_arch::NativeOrdinal::new(34),
        carrick_core_abi::service::ServiceOrigin::Descendant,
        super::RefusalVenue::Carrier,
        super::RefusalArguments::Unretained,
    );
    root.record_refusal(
        carrick_guest_arch::NativeOrdinal::new(34),
        carrick_core_abi::service::ServiceOrigin::Initial,
        super::RefusalVenue::Carrier,
        super::RefusalArguments::Unretained,
    );
    root.record_refusal(
        carrick_guest_arch::NativeOrdinal::new(u64::MAX),
        carrick_core_abi::service::ServiceOrigin::Descendant,
        super::RefusalVenue::Carrier,
        super::RefusalArguments::Unretained,
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
                super::RefusalArguments::Unretained,
            );
            first.record_refusal(
                carrick_guest_arch::NativeOrdinal::new(nr),
                ServiceOrigin::Descendant,
                venue,
                super::RefusalArguments::Unretained,
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
fn refused_call_records_keep_each_counted_calls_arguments_in_order() {
    use super::{RefusalArguments, RefusalVenue, RefusedCall};
    use carrick_core_abi::service::ServiceOrigin;
    let counters = Counters::new();
    assert_eq!(counters.refused_calls().count(), 0);
    let pselect = RefusedCall {
        ordinal: carrick_guest_arch::NativeOrdinal::new(72),
        origin: ServiceOrigin::Descendant,
        venue: RefusalVenue::Ring,
        arguments: RefusalArguments::Registers([5, 0x7000, 0x7080, 0, 0x7100, u64::MAX]),
    };
    let exec = RefusedCall {
        ordinal: carrick_guest_arch::NativeOrdinal::new(221),
        origin: ServiceOrigin::Initial,
        venue: RefusalVenue::Carrier,
        arguments: RefusalArguments::Unretained,
    };
    for call in [pselect, exec] {
        counters.record_refusal(call.ordinal, call.origin, call.venue, call.arguments);
    }
    assert_eq!(
        counters.refused_calls().collect::<std::vec::Vec<_>>(),
        [pselect, exec]
    );
    // The census snapshot keeps the records with the counts they explain.
    assert_eq!(
        counters
            .copy_snapshot()
            .refused_calls()
            .collect::<std::vec::Vec<_>>(),
        [pselect, exec]
    );
    assert_eq!(counters.refused[72].load(Ordering::Relaxed), 1);
    assert_eq!(counters.refused_child[72].load(Ordering::Relaxed), 1);
    assert_eq!(counters.venue_refused[221].load(Ordering::Relaxed), 1);
}

#[test]
fn refused_call_ring_overwrites_its_oldest_records_without_allocating() {
    use super::{REFUSED_CALL_RECORDS, RefusalArguments, RefusalVenue};
    use carrick_core_abi::service::ServiceOrigin;
    let counters = Counters::new();
    let total = REFUSED_CALL_RECORDS as u64 + 3;
    for nr in 0..total {
        counters.record_refusal(
            carrick_guest_arch::NativeOrdinal::new(nr),
            ServiceOrigin::Descendant,
            RefusalVenue::Ring,
            RefusalArguments::Registers([nr, nr + 1, nr + 2, nr + 3, nr + 4, nr + 5]),
        );
    }
    let retained: std::vec::Vec<_> = counters.refused_calls().collect();
    assert_eq!(retained.len(), REFUSED_CALL_RECORDS);
    for (call, nr) in retained.iter().zip(3..total) {
        assert_eq!(call.ordinal.raw(), nr);
        assert_eq!(
            call.arguments,
            RefusalArguments::Registers([nr, nr + 1, nr + 2, nr + 3, nr + 4, nr + 5])
        );
    }
    // A row a writer has claimed but not completed is skipped, never torn.
    let next = counters.refused_call_next.load(Ordering::Relaxed);
    counters.refused_calls[((next - 1) % REFUSED_CALL_RECORDS as u64) as usize][0]
        .store((next - 1) * 2 + 1, Ordering::Relaxed);
    assert_eq!(counters.refused_calls().count(), REFUSED_CALL_RECORDS - 1);
}
