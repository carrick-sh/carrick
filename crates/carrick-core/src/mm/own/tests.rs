//! Direct witnesses for the memory-ownership core's transitions (#3061).
use super::explore::ExplorerVenue;
use super::*;
use std::string::String;
use std::vec;

/// `M` is the mapping's host allocation, `B` an extent's sub-lease.
type Core = CarrierCore<ExplorerVenue, &'static str, u32>;

const PAGE: u64 = 0x1000;
const HOST: usize = 0x7000_0000_0000;

fn extent(ipa: u64, len: u64) -> GpaExtent {
    GpaExtent::new(ipa, len).unwrap()
}

fn mapping(ipa: u64, len: u64, host: &'static str) -> MappingSpec<&'static str> {
    MappingSpec {
        extent: extent(ipa, len),
        host_addr: HOST + ipa as usize,
        host,
    }
}

fn carrier(raw: u64) -> CarrierId {
    // SAFETY: each test's cores use distinct raw ids.
    unsafe { CarrierId::assume_unique(NonZeroU64::new(raw).unwrap()) }
}

/// A live core of `carrier(raw)` with one installed mapping `[0, 4 pages)`.
fn live(raw: u64) -> (Core, MappingId) {
    let mut core = Core::new(carrier(raw));
    core.create().unwrap();
    let (ticket, action) = core.begin_map(mapping(0, 4 * PAGE, "ram")).unwrap();
    assert_eq!(
        action,
        BackendAction::Map {
            extent: extent(0, 4 * PAGE),
            host_addr: HOST
        }
    );
    let id = ticket.mapping();
    assert_eq!(core.finish_map(ticket, BackendResult::Done), Ok(None));
    core.commit_create().unwrap();
    (core, id)
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
    let (ticket, _) = core.begin_map(mapping(0, 2 * PAGE, "a")).unwrap();
    let refused = core
        .begin_map(mapping(PAGE, 2 * PAGE, "b"))
        .expect_err("a second mapper cannot collide with an in-flight map");
    assert_eq!(
        (refused.reason, refused.offered.host),
        (Refusal::Collision, "b")
    );
    assert_eq!(
        core.carve(extent(0, PAGE), 1),
        Err(Refused {
            offered: 1,
            reason: Refusal::NotInsideAnInstalledMapping
        }),
        "nothing is carved inside a map that hasn't landed"
    );
    assert_eq!(core.begin_destroy().map(|_| ()), Err(Refusal::InFlight));
    assert_eq!(
        core.finish_map(ticket, BackendResult::Failed),
        Ok(Some("a")),
        "a failed map releases its extent and hands its host back"
    );
    assert_eq!(core.mapping_count(), 0);
    let (ticket, _) = core.begin_map(mapping(PAGE, 2 * PAGE, "b")).unwrap();
    core.finish_map(ticket, BackendResult::Done).unwrap();
    core.check_invariants().unwrap();
    core.commit_create().unwrap();
    finish(core);
}

/// `installed_at_or_below` answers with the one mapping that can hold an
/// address only once it is installed, and `reserved_extents` names every
/// mapping in any state, in address order: an allocator must never reuse an
/// extent that is still being mapped.
#[test]
fn the_installed_lookup_skips_in_flight_maps_and_reserved_extents_name_them() {
    let (mut core, ram) = live(31);
    let (ticket, _) = core.begin_map(mapping(8 * PAGE, 2 * PAGE, "late")).unwrap();
    let found = core
        .installed_at_or_below(3 * PAGE)
        .expect("inside the installed ram");
    assert_eq!(
        (found.id, found.extent, found.host_addr, *found.host),
        (ram, extent(0, 4 * PAGE), HOST, "ram")
    );
    // Past the ram's end the lookup still answers with the ram: the caller
    // checks the reach, and the gap holds no other mapping.
    assert_eq!(
        core.installed_at_or_below(6 * PAGE).map(|view| view.id),
        Some(ram)
    );
    assert!(
        core.installed_at_or_below(9 * PAGE).is_none(),
        "an in-flight map is never handed out as installed"
    );
    assert_eq!(
        core.reserved_extents().collect::<Vec<_>>(),
        vec![extent(0, 4 * PAGE), extent(8 * PAGE, 2 * PAGE)],
        "the in-flight map's extent is reserved too"
    );
    core.finish_map(ticket, BackendResult::Done).unwrap();
    assert_eq!(
        core.installed_at_or_below(9 * PAGE).map(|view| *view.host),
        Some("late")
    );
    finish(core);
}

#[test]
fn a_carve_is_refused_before_it_exists_and_derives_its_host_address() {
    let (mut core, _) = live(1);
    core.carve(extent(PAGE, 2 * PAGE), 1).unwrap();
    for (bad, reason) in [
        (extent(2 * PAGE, PAGE), Refusal::Collision),
        (
            extent(3 * PAGE, 2 * PAGE),
            Refusal::NotInsideAnInstalledMapping,
        ),
    ] {
        assert_eq!(core.carve(bad, 2), Err(Refused { offered: 2, reason }));
    }
    let refused = core
        .begin_map(MappingSpec {
            host_addr: usize::MAX,
            ..mapping(8 * PAGE, PAGE, "wraps")
        })
        .expect_err("a host range that overflows");
    assert_eq!(refused.reason, Refusal::HostRange);
    let pin = core.pin(2 * PAGE + 8, 8).unwrap();
    assert_eq!(pin.host_addr(), HOST + 2 * PAGE as usize + 8);
    assert_eq!(core.unpin(pin), Ok(None));
    assert_eq!(core.extent_count(), 1);
    core.check_invariants().unwrap();
    finish(core);
}

#[test]
fn releasing_an_extent_never_releases_the_mapped_host() {
    let (mut core, mapping_id) = live(1);
    let id = core.carve(extent(0, PAGE), 5).unwrap();
    let Ok(Retire::Released(gone)) = core.retire_extent(id) else {
        panic!("an unpinned extent retires at once");
    };
    assert_eq!(gone.lease, 5, "the extent hands back only its lease");
    assert_eq!(core.mapping_count(), 1, "the mapping, and its host, stay");
    let (ticket, _) = core.begin_unmap(mapping_id).unwrap();
    assert_eq!(core.finish_unmap(ticket, BackendResult::Failed), Ok(None));
    let (ticket, _) = core.begin_unmap(mapping_id).unwrap();
    assert_eq!(
        core.finish_unmap(ticket, BackendResult::Done),
        Ok(Some("ram")),
        "the host comes back only once the backend has unmapped it"
    );
    finish(core);
}

#[test]
fn a_pinned_extent_is_released_only_by_its_last_unpin() {
    let (mut core, mapping_id) = live(1);
    let id = core.carve(extent(0, 2 * PAGE), 7).unwrap();
    let first = core.pin(PAGE + 0x10, 0x10).unwrap();
    let second = core.pin(0, 2 * PAGE).unwrap();
    assert_eq!(core.pin(PAGE, 2 * PAGE), Err(PinRefusal::Overruns(id)));
    assert_eq!(core.pin(0, 0), Err(PinRefusal::EmptyRange));

    assert_eq!(core.retire_extent(id), Ok(Retire::Deferred));
    assert_eq!(core.pin(0, PAGE), Err(PinRefusal::NoLiveExtent));
    assert_eq!(
        core.begin_unmap(mapping_id).map(|_| ()),
        Err(Refusal::Carved)
    );
    assert_eq!(core.unpin(first), Ok(None));
    let released = core
        .unpin(second)
        .unwrap()
        .expect("the last unpin releases");
    assert_eq!((released.id, released.lease), (id, 7));
    let (ticket, _) = core.begin_unmap(mapping_id).unwrap();
    assert_eq!(
        core.finish_unmap(ticket, BackendResult::Done),
        Ok(Some("ram"))
    );
    finish(core);
}

#[test]
fn destroy_returns_every_host_and_terminalizes_pinned_extents() {
    let (mut core, _) = live(1);
    let pinned = core.carve(extent(0, PAGE), 1).unwrap();
    let free = core.carve(extent(PAGE, PAGE), 2).unwrap();
    let pin = core.pin(0, PAGE).unwrap();

    let (ticket, _) = core.begin_destroy().unwrap();
    assert_eq!(
        core.begin_map(mapping(8 * PAGE, PAGE, "late"))
            .map(|_| ())
            .map_err(|r| r.reason),
        Err(Refusal::Generation(GenerationState::Destroying))
    );
    let destroyed = core.finish_destroy(ticket, BackendResult::Done).unwrap();
    assert_eq!(destroyed.hosts, vec!["ram"]);
    assert_eq!(
        destroyed.extents.iter().map(|r| r.id).collect::<Vec<_>>(),
        [free]
    );
    assert_eq!(core.mapping_count(), 0);
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
fn a_failed_destroy_returns_to_the_state_it_started_from() {
    let mut core = Core::new(carrier(1));
    core.create().unwrap();
    let (ticket, _) = core.begin_destroy().unwrap();
    core.finish_destroy(ticket, BackendResult::Failed).unwrap();
    assert_eq!(core.generation().1, GenerationState::Creating);
    core.commit_create().unwrap();
    finish(core);
}

#[test]
fn another_carriers_tokens_and_ids_are_refused_and_come_back() {
    let (mut mine, mine_mapping) = live(1);
    let (mut other, other_mapping) = live(2);
    let mine_extent = mine.carve(extent(0, PAGE), 1).unwrap();
    other.carve(extent(0, PAGE), 2).unwrap();
    let pin = mine.pin(0, PAGE).unwrap();
    let refused = other.unpin(pin).expect_err("another carrier's pin");
    assert_eq!(
        mine.unpin(refused.offered),
        Ok(None),
        "it still returns home"
    );
    assert_eq!(other.retire_extent(mine_extent), Err(Refusal::NotFound));
    assert_eq!(
        other.begin_unmap(mine_mapping).map(|_| ()),
        Err(Refusal::NotFound)
    );

    assert_eq!(
        other.begin_unmap(other_mapping).map(|_| ()),
        Err(Refusal::Carved),
        "its own id still works there"
    );
    finish(other);
    finish(mine);
}

#[test]
fn a_core_dropped_holding_anything_reaches_its_venue() {
    // An empty but live generation is held: dropping it would lose the VM.
    let mut core = Core::new(carrier(1));
    core.create().unwrap();
    core.commit_create().unwrap();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(core)))
        .expect_err("dropping a live core is not silent");
    let message = panic.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(
        message.contains("holding Live with 0 mappings and 0 extents"),
        "{message:?}"
    );

    let (core, _) = live(2);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(core)))
        .expect_err("dropping a core that holds a mapping is not silent");
    let message = panic.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(message.contains("with 1 mappings"), "{message:?}");

    let mut core = Core::new(carrier(3));
    core.create().unwrap();
    let (ticket, _) = core.begin_destroy().unwrap();
    let mut core = core
        .teardown()
        .expect_err("teardown refuses while a destroy is outstanding");
    core.finish_destroy(ticket, BackendResult::Done).unwrap();
    assert!(core.teardown().is_ok());
}
