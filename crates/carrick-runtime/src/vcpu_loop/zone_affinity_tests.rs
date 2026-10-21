//! Placement boundary witnesses, independent of the ring syscall venue.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;

#[test]
fn affinity_reentry_preserves_retired_terminal_custody() {
    let bootstrap = carrick_kernel::kernel::RootBootstrap::for_reference_model(
        78_703,
        carrick_hal::ThreadId::synthetic_for_tests(78_703),
        "affinity reentry".into(),
    )
    .unwrap();
    let (_, context) = carrick_kernel::kernel::Kernel::bootstrap_root(bootstrap).unwrap();
    let region = carrick_test_support::TestEl1Region::zeroed();
    // SAFETY: TestEl1Region owns aligned, zero-valid ABI storage for this scope.
    let zone = unsafe {
        &*region
            .as_ptr()
            .add(carrick_el1_abi::EL1_ZONE_OFFSET as usize)
            .cast::<ZoneTables>()
    };
    let slot = SlotId::new(1);
    zone.publish_slot_with_affinity(
        slot,
        7,
        Some(1),
        context.thread().control_slot().affinity_source(),
    );
    let identity = ThreadIdentity {
        tid: 1,
        serial: 2,
        mm: 7,
        file_table: 1,
        generation: 1,
        affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
        affinity: 3,
        lifecycle_page: 0,
        control_slot: 0,
    };
    zone.publish_terminal(slot, identity);
    assert!(zone.accept_terminal(slot, identity));
    run_guest(Some(context.thread()), Some((zone, slot)), || {
        assert!(
            zone.terminal_matches(slot, identity, carrick_sched_core::TerminalPhase::Retired),
            "affinity refresh cannot erase an owed child wake's retirement receipt"
        );
        assert_eq!(zone.slot(slot).mm(), 7);
        assert_eq!(zone.slot(slot).bound_cpu(), Some(1));
    });
}
