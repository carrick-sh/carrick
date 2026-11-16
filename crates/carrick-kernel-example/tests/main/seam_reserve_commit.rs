//! Personality fixture drives the shared root, never a private MM authority.
use carrick_core::mm::reservation::SharedReservations;
use carrick_el1_abi::{
    Decision, Refusal, ReservationBackingReceipt, ReservationCompletion, ReservationGeometry,
    ReservationMm, ReservationProtection, ReservationRange,
};
use carrick_personality_linux::mm::{LinuxReservationLayout, LinuxReservationPolicy};

struct Geometry;
impl ReservationGeometry for Geometry {
    const RESERVATIONS_OFFSET: usize = 0;
    const ZONE_OFFSET: usize = 0x20000;
    const REGION_BASE: u64 = 0;
    const BOOTSTRAP_BASE: u64 = 0;
    const BOOTSTRAP_SIZE: u64 = 0x100000;
    fn authorizes_internal_read(_: u64, _: u64) -> bool {
        false
    }
}
#[allow(clippy::unwrap_used)] // Fixed, aligned fixture ranges; never product input.
fn range(start: u64, end: u64) -> ReservationRange {
    ReservationRange::new(start, end).unwrap()
}
#[test]
fn address_space_reserve_commit_decommit_witness_contract() {
    let table = SharedReservations::<LinuxReservationPolicy, Geometry>::new();
    let mm = ReservationMm::new(88).unwrap();
    table
        .publish(
            0,
            mm,
            LinuxReservationLayout {
                heap: range(0x1000, 0x100000),
                arena: range(0x100000, 0x8000000),
                brk: 0x1000,
                address_limit: u64::MAX,
                data_limit: u64::MAX,
                external_address_bytes: 0,
                external_data_bytes: 0,
            },
        )
        .unwrap();
    let mut root = table.lock(0, mm).unwrap();
    root.finish_import().unwrap();
    let span = range(0x200000, 0x4200000);
    let page = range(0x200000, 0x201000);
    let decisions = [root.reserve_range(span).unwrap()];
    for decision in decisions {
        let Decision::Work(request) = decision else {
            panic!("expected proposal")
        };
        // SAFETY: fixture models a lazy descriptor transaction, with no backing.
        let receipt = unsafe {
            ReservationCompletion::after_descriptor_and_backing_commit(
                request,
                ReservationBackingReceipt {
                    receipt: request.sequence.raw(),
                    granted_bytes: 0,
                    returned_bytes: 0,
                },
            )
        }
        .unwrap();
        root.complete(receipt).unwrap();
    }
    assert!(root.is_reserved(span));
    assert!(!root.is_committed(page));
    for commit in [true, false, true] {
        let decision = if commit {
            root.commit_range(page, ReservationProtection::READ_WRITE)
        } else {
            root.decommit_range(page)
        }
        .unwrap();
        let Decision::Work(request) = decision else {
            panic!("expected proposal")
        };
        // SAFETY: no page was touched; this fixture's backing transaction is empty.
        let receipt = unsafe {
            ReservationCompletion::after_descriptor_and_backing_commit(
                request,
                ReservationBackingReceipt {
                    receipt: request.sequence.raw(),
                    granted_bytes: 0,
                    returned_bytes: 0,
                },
            )
        }
        .unwrap();
        root.complete(receipt).unwrap();
        assert_eq!(root.is_committed(page), commit);
        assert!(root.is_reserved(span));
    }
    assert_eq!(
        root.commit_range(
            range(0x5000000, 0x5001000),
            ReservationProtection::READ_WRITE
        ),
        Err(Refusal::Hole)
    );
}
