//! Direct witnesses for the memory-ownership core's transitions (#3061).
use super::explore::ExplorerVenue;
use super::*;
use std::string::String;

type Core = CarrierCore<ExplorerVenue, u32>;

const PAGE: u64 = 0x1000;
const HOST: usize = 0x7000_0000_0000;

fn extent(ipa: u64, len: u64) -> GpaExtent {
    GpaExtent::new(ipa, len).unwrap()
}

fn spec(ipa: u64, len: u64, backing: u32) -> ExtentSpec<u32> {
    ExtentSpec {
        extent: extent(ipa, len),
        host_addr: HOST + ipa as usize,
        backing,
    }
}

fn carrier(raw: u64) -> CarrierId {
    CarrierId(NonZeroU64::new(raw).unwrap())
}

/// A live core with one installed mapping `[0, 4 pages)`.
fn live() -> (Core, MappingId) {
    let mut core = Core::new(carrier(1));
    core.create().unwrap();
    let (ticket, action) = core.begin_map(extent(0, 4 * PAGE)).unwrap();
    assert_eq!(action, BackendAction::Map(extent(0, 4 * PAGE)));
    let mapping = core
        .finish_map(ticket, BackendResult::Done)
        .unwrap()
        .unwrap();
    core.commit_create().unwrap();
    (core, mapping)
}

/// Destroy and tear down, asserting nothing is left.
fn finish(mut core: Core) {
    let (ticket, _) = core.begin_destroy().unwrap();
    core.finish_destroy(ticket, BackendResult::Done).unwrap();
    assert!(core.teardown().is_ok(), "the core still holds something");
}

#[test]
fn an_in_flight_map_reserves_its_extent_and_holds_off_destroy() {
    let mut core = Core::new(carrier(1));
    core.create().unwrap();
    let (ticket, _) = core.begin_map(extent(0, 2 * PAGE)).unwrap();
    assert_eq!(
        core.begin_map(extent(PAGE, 2 * PAGE)).map(|_| ()),
        Err(Refusal::Collision),
        "a second mapper cannot collide with an in-flight map"
    );
    assert_eq!(
        core.carve(spec(0, PAGE, 1)).map_err(|r| r.reason),
        Err(Refusal::NotInsideAnInstalledMapping),
        "nothing is carved inside a map that hasn't landed"
    );
    assert_eq!(core.begin_destroy().map(|_| ()), Err(Refusal::InFlight));
    assert_eq!(core.finish_map(ticket, BackendResult::Failed), Ok(None));
    assert_eq!(core.mapping_count(), 0, "a failed map releases its extent");
    let (ticket, _) = core.begin_map(extent(PAGE, 2 * PAGE)).unwrap();
    core.finish_map(ticket, BackendResult::Done).unwrap();
    core.check_invariants().unwrap();
    core.commit_create().unwrap();
    finish(core);
}

#[test]
fn a_carve_is_refused_before_it_exists_and_hands_its_spec_back() {
    let (mut core, _) = live();
    core.carve(spec(PAGE, 2 * PAGE, 1)).unwrap();
    for (bad, reason) in [
        (spec(2 * PAGE, PAGE, 2), Refusal::Collision),
        (
            spec(3 * PAGE, 2 * PAGE, 3),
            Refusal::NotInsideAnInstalledMapping,
        ),
        (
            ExtentSpec {
                host_addr: 0,
                ..spec(0, PAGE, 4)
            },
            Refusal::HostRange,
        ),
        (
            ExtentSpec {
                host_addr: usize::MAX,
                ..spec(0, PAGE, 5)
            },
            Refusal::HostRange,
        ),
    ] {
        let refused = core.carve(bad.clone()).expect_err("refused");
        assert_eq!(refused.reason, reason);
        assert_eq!(refused.offered, bad, "the spec comes back whole");
    }
    assert_eq!(core.extent_count(), 1);
    core.check_invariants().unwrap();
    finish(core);
}

#[test]
fn a_pinned_extent_is_released_only_by_its_last_unpin() {
    let (mut core, mapping) = live();
    let id = core.carve(spec(0, 2 * PAGE, 7)).unwrap();
    let first = core.pin(PAGE + 0x10, 0x10).unwrap();
    assert_eq!(first.host_addr(), HOST + PAGE as usize + 0x10);
    let second = core.pin(0, 2 * PAGE).unwrap();
    assert_eq!(core.pin(PAGE, 2 * PAGE), Err(PinRefusal::Overruns(id)));
    assert_eq!(core.pin(0, 0), Err(PinRefusal::EmptyRange));

    assert_eq!(core.retire_extent(id), Ok(Retire::Deferred));
    assert_eq!(core.pin(0, PAGE), Err(PinRefusal::NoLiveExtent));
    assert_eq!(
        core.begin_unmap(mapping).map(|_| ()),
        Err(Refusal::Carved),
        "a mapping with a pinned extent inside is not unmapped"
    );
    assert_eq!(core.unpin(first), Ok(None));
    let released = core
        .unpin(second)
        .unwrap()
        .expect("the last unpin releases");
    assert_eq!((released.id, released.spec.backing), (id, 7));

    let (ticket, action) = core.begin_unmap(mapping).unwrap();
    assert_eq!(action, BackendAction::Unmap(extent(0, 4 * PAGE)));
    core.finish_unmap(ticket, BackendResult::Done).unwrap();
    assert_eq!(core.mapping_count(), 0);
    finish(core);
}

#[test]
fn a_failed_unmap_keeps_the_mapping_installed_for_a_retry() {
    let (mut core, mapping) = live();
    let (ticket, _) = core.begin_unmap(mapping).unwrap();
    core.finish_unmap(ticket, BackendResult::Failed).unwrap();
    core.carve(spec(0, PAGE, 1)).expect("installed again");
    core.check_invariants().unwrap();
    finish(core);
}

#[test]
fn destroy_terminalizes_pinned_extents_and_releases_the_rest() {
    let (mut core, _) = live();
    let pinned = core.carve(spec(0, PAGE, 1)).unwrap();
    let free = core.carve(spec(PAGE, PAGE, 2)).unwrap();
    let pin = core.pin(0, PAGE).unwrap();

    let (ticket, _) = core.begin_destroy().unwrap();
    assert_eq!(
        core.begin_map(extent(3 * PAGE, PAGE)).map(|_| ()),
        Err(Refusal::Generation(GenerationState::Destroying)),
        "no backend action once the destroy has begun"
    );
    let released = core.finish_destroy(ticket, BackendResult::Done).unwrap();
    assert_eq!(released.iter().map(|r| r.id).collect::<Vec<_>>(), [free]);
    assert_eq!(core.mapping_count(), 0, "no mapping survives the destroy");
    core.check_invariants().unwrap();

    assert_eq!(core.create(), Err(Refusal::InFlight), "a pin is still out");
    let mut core = core
        .teardown()
        .expect_err("a terminal extent is still held");
    let gone = core
        .unpin(pin)
        .unwrap()
        .expect("the last unpin releases it");
    assert_eq!(gone.id, pinned);
    assert_eq!(core.create(), Ok(GenerationId(2)));
    core.commit_create().unwrap();
    finish(core);
}

#[test]
fn a_token_from_another_carrier_or_generation_is_refused_and_comes_back() {
    let (mut mine, _) = live();
    let (mut other, _) = {
        let mut core = Core::new(carrier(2));
        core.create().unwrap();
        let (t, _) = core.begin_map(extent(0, 4 * PAGE)).unwrap();
        let m = core.finish_map(t, BackendResult::Done).unwrap().unwrap();
        core.commit_create().unwrap();
        (core, m)
    };
    mine.carve(spec(0, PAGE, 1)).unwrap();
    other.carve(spec(0, PAGE, 2)).unwrap();
    let pin = mine.pin(0, PAGE).unwrap();
    let refused = other.unpin(pin).expect_err("another carrier's pin");
    assert_eq!(
        mine.unpin(refused.offered),
        Ok(None),
        "it still returns home"
    );

    let (ticket, _) = other.begin_destroy().unwrap();
    let refused = mine
        .finish_destroy(ticket, BackendResult::Done)
        .expect_err("another carrier's destroy ticket");
    other
        .finish_destroy(refused.offered, BackendResult::Done)
        .unwrap();
    assert!(other.teardown().is_ok());
    finish(mine);
}

#[test]
fn a_core_dropped_holding_anything_reaches_its_venue() {
    let (core, _) = live();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(core)))
        .expect_err("dropping a core that holds a mapping is not silent");
    let message = panic.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(
        message.contains("holding 1 mappings and 0 extents"),
        "{message:?}"
    );
    let (core, _) = live();
    let core = core.teardown().expect_err("teardown refuses while holding");
    finish(core);
}
