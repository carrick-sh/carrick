//! Counter publication is independent of task, memory and scheduler state.
use super::Counters;
use core::sync::atomic::Ordering;

#[test]
fn refusal_snapshot_preserves_caller_populations_without_changing_service_counts() {
    let root = Counters::new();
    root.served[34].store(7, Ordering::Relaxed);
    root.forwarded[34].store(5, Ordering::Relaxed);
    root.refused[34].fetch_add(1, Ordering::Relaxed);
    root.refused[34].fetch_add(1, Ordering::Relaxed);
    root.record_child_refusal(34, true);
    root.record_venue_refusal(carrick_guest_arch::NativeOrdinal::new(34), true);
    root.record_venue_refusal(carrick_guest_arch::NativeOrdinal::new(34), false);
    root.record_venue_refusal(carrick_guest_arch::NativeOrdinal::new(u64::MAX), true);
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
