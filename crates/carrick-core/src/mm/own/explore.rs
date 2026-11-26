//! The bounded exhaustive explorer for the memory-ownership core (#3061).
//!
//! It runs every sequence of transitions, up to a depth, over a small
//! universe: overlapping and adjacent mappings, extents carved inside them,
//! pins, retirement, unmap, destroy and teardown, with each backend result
//! chosen both ways. The shell is adversarial: it may hold any ticket or pin
//! as long as it likes, finish them in any order, or never return them.
//!
//! After every transition the explorer checks the core's own invariants
//! (V1-V4) and reconciles the shell's custody with the core's:
//! - V4: a backend action comes only from a `Creating` or `Live` generation,
//!   and a committed destroy leaves no mapping;
//! - V5: an extent is never released while the shell holds a pin on it, a
//!   pin is minted only for a live extent, and the pins the shell holds are
//!   exactly the pins the core counts;
//! - ownership: each mapping's host allocation and each extent's lease is in
//!   exactly one place (the core, or back with the shell), and every
//!   outstanding ticket matches one in-flight state;
//! - V6: `teardown` succeeds only for an ended generation with nothing held;
//! - tokens: a refused ticket, pin, spec or lease comes back whole.
//!
//! States are deduplicated by hash (a `HashSet` compares equal states, so a
//! hash collision never merges two). The explorer drives `CarrierCore`
//! itself, with no double.
use super::*;
use std::collections::{HashSet, VecDeque};
use std::format;
use std::string::String;
use std::vec;

/// The test venue: a dropped core holding anything fails the run.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct ExplorerVenue;

impl CoreVenue for ExplorerVenue {
    fn dropped_holding(holding: Holding) -> ! {
        panic!(
            "core dropped holding {:?} with {} mappings and {} extents",
            holding.state, holding.mappings, holding.extents
        )
    }
}

type Core = CarrierCore<ExplorerVenue, u8, u8>;

const HOST: usize = 0x10_0000;

#[derive(Clone, Hash, PartialEq, Eq)]
struct World {
    core: Core,
    maps: Vec<MapTicket>,
    unmaps: Vec<UnmapTicket>,
    destroy: Option<DestroyTicket>,
    pins: Vec<Pin>,
    /// Host allocations the core holds for its mappings.
    hosts_in_core: usize,
    /// Leases the core holds for its extents.
    leases_in_core: usize,
}

impl Drop for World {
    fn drop(&mut self) {
        // Mid-operation states are discarded by the thousand; teardown and
        // the drop check have their own op and witness.
        self.core.forget_for_explorer();
    }
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Create,
    CommitCreate,
    BeginMap(u64, u64),
    FinishMap(usize, BackendResult),
    Carve(u64, u64),
    Pin(u64, u64),
    Unpin(usize),
    Retire(u64),
    BeginUnmap(u64),
    FinishUnmap(usize, BackendResult),
    BeginDestroy,
    FinishDestroy(BackendResult),
    Teardown,
}

/// The universe, in pages of one byte each so extents stay readable.
const MAPS: [(u64, u64); 3] = [(0, 2), (1, 2), (2, 2)];
const CARVES: [(u64, u64); 4] = [(0, 1), (1, 1), (0, 2), (2, 1)];
const PINS: [(u64, u64); 3] = [(0, 1), (1, 1), (0, 2)];
const RESULTS: [BackendResult; 2] = [BackendResult::Done, BackendResult::Failed];

fn ops(world: &World) -> Vec<Op> {
    let mut ops = vec![Op::Create, Op::CommitCreate, Op::BeginDestroy, Op::Teardown];
    if world.maps.len() < 2 {
        ops.extend(MAPS.iter().map(|&(ipa, len)| Op::BeginMap(ipa, len)));
    }
    for index in 0..world.maps.len() {
        ops.extend(RESULTS.iter().map(|&r| Op::FinishMap(index, r)));
    }
    ops.extend(CARVES.iter().map(|&(ipa, len)| Op::Carve(ipa, len)));
    if world.pins.len() < 2 {
        ops.extend(PINS.iter().map(|&(ipa, len)| Op::Pin(ipa, len)));
    }
    ops.extend((0..world.pins.len()).map(Op::Unpin));
    ops.extend((1..world.core.next_extent).map(Op::Retire));
    ops.extend((1..world.core.next_mapping).map(Op::BeginUnmap));
    for index in 0..world.unmaps.len() {
        ops.extend(RESULTS.iter().map(|&r| Op::FinishUnmap(index, r)));
    }
    if world.destroy.is_some() {
        ops.extend(RESULTS.iter().map(|&r| Op::FinishDestroy(r)));
    }
    ops
}

fn extent(ipa: u64, len: u64) -> GpaExtent {
    GpaExtent::new(ipa, len).unwrap_or_else(|| panic!("universe extent {ipa}+{len}"))
}

/// Apply `op`; `Err` names a broken property.
fn step(world: &mut World, op: Op) -> Result<(), String> {
    let (_, before) = world.core.generation();
    let carrier = world.core.carrier();
    let admits = matches!(before, GenerationState::Creating | GenerationState::Live);
    let mut released = Vec::new();
    let mut action = None;
    match op {
        Op::Create => {
            let _ = world.core.create();
        }
        Op::CommitCreate => {
            let _ = world.core.commit_create();
        }
        Op::BeginMap(ipa, len) => {
            let spec = MappingSpec {
                extent: extent(ipa, len),
                host_addr: HOST + ipa as usize,
                host: ipa as u8,
            };
            match world.core.begin_map(spec.clone()) {
                Ok((ticket, act)) => {
                    world.maps.push(ticket);
                    world.hosts_in_core += 1;
                    action = Some(act);
                }
                Err(refused) if refused.offered != spec => {
                    return Err("a refused map did not hand its spec back".into());
                }
                Err(_) => {}
            }
        }
        Op::FinishMap(index, result) => {
            let ticket = world.maps.remove(index);
            let offered = ticket.clone();
            match world.core.finish_map(ticket, result) {
                Ok(host) => world.hosts_in_core -= usize::from(host.is_some()),
                Err(refused) if refused.offered != offered => {
                    return Err("a refused map ticket did not come back whole".into());
                }
                Err(refused) => world.maps.insert(index, refused.offered),
            }
        }
        Op::Carve(ipa, len) => match world.core.carve(extent(ipa, len), ipa as u8) {
            Ok(_) => world.leases_in_core += 1,
            Err(refused) if refused.offered != ipa as u8 => {
                return Err("a refused carve did not hand its lease back".into());
            }
            Err(_) => {}
        },
        Op::Pin(ipa, len) => {
            if let Ok(pin) = world.core.pin(ipa, len) {
                let live = world
                    .core
                    .extents
                    .values()
                    .any(|e| e.id == pin.extent() && e.state == ExtentState::Live);
                if !live {
                    return Err(format!("pinned {:?}, which is not live", pin.extent()));
                }
                world.pins.push(pin);
            }
        }
        Op::Unpin(index) => {
            let pin = world.pins.remove(index);
            let offered = pin.clone();
            match world.core.unpin(pin) {
                Ok(Some(gone)) => released.push(gone.id),
                Ok(None) => {}
                Err(refused) if refused.offered != offered => {
                    return Err("a refused pin did not come back whole".into());
                }
                Err(refused) => world.pins.insert(index, refused.offered),
            }
        }
        Op::Retire(raw) => {
            let id = ExtentId { carrier, raw };
            if let Ok(Retire::Released(gone)) = world.core.retire_extent(id) {
                released.push(gone.id);
            }
        }
        Op::BeginUnmap(raw) => {
            if let Ok((ticket, act)) = world.core.begin_unmap(MappingId { carrier, raw }) {
                world.unmaps.push(ticket);
                action = Some(act);
            }
        }
        Op::FinishUnmap(index, result) => {
            let ticket = world.unmaps.remove(index);
            match world.core.finish_unmap(ticket, result) {
                Ok(host) => world.hosts_in_core -= usize::from(host.is_some()),
                Err(refused) => world.unmaps.insert(index, refused.offered),
            }
        }
        Op::BeginDestroy => {
            if let Ok((ticket, act)) = world.core.begin_destroy() {
                world.destroy = Some(ticket);
                action = Some(act);
            }
        }
        Op::FinishDestroy(result) => {
            if let Some(ticket) = world.destroy.take() {
                match world.core.finish_destroy(ticket, result) {
                    Ok(gone) => {
                        world.hosts_in_core -= gone.hosts.len();
                        released.extend(gone.extents.into_iter().map(|g| g.id));
                        if result == BackendResult::Done && world.core.mapping_count() != 0 {
                            return Err("a mapping survived a committed destroy".into());
                        }
                    }
                    Err(refused) => world.destroy = Some(refused.offered),
                }
            }
        }
        Op::Teardown => match world.core.clone().teardown() {
            Ok(()) => {
                let ended = matches!(before, GenerationState::Vacant | GenerationState::Gone);
                if !ended || world.hosts_in_core != 0 || world.leases_in_core != 0 {
                    return Err(format!(
                        "teardown accepted a core holding work in {before:?}"
                    ));
                }
            }
            Err(mut kept) => kept.forget_for_explorer(),
        },
    }
    if action.is_some() && !admits {
        return Err(format!("{action:?} issued in generation state {before:?}"));
    }
    world.leases_in_core -= released.len();
    for id in released {
        if world.pins.iter().any(|pin| pin.extent() == id) {
            return Err(format!("{id:?} released while the shell holds a pin on it"));
        }
    }
    reconcile(world)?;
    world
        .core
        .check_invariants()
        .map_err(|violation| format!("{violation:?}"))
}

/// The shell's custody and the core's state agree.
fn reconcile(world: &World) -> Result<(), String> {
    let core = &world.core;
    if world.hosts_in_core != core.mappings.len() {
        return Err(format!(
            "{} host allocations unaccounted for",
            world.hosts_in_core.abs_diff(core.mappings.len())
        ));
    }
    if world.leases_in_core != core.extents.len() {
        return Err("an extent lease was lost or duplicated".into());
    }
    let core_pins: u64 = core.extents.values().map(|e| e.pins).sum();
    if core_pins != world.pins.len() as u64 {
        return Err(format!(
            "the core counts {core_pins} pins, the shell holds {}",
            world.pins.len()
        ));
    }
    for pin in &world.pins {
        if !core
            .extents
            .values()
            .any(|e| e.id == pin.extent() && e.pins > 0)
        {
            return Err(format!(
                "a held pin names {:?}, which is gone",
                pin.extent()
            ));
        }
    }
    let in_state = |state| core.mappings.values().filter(|m| m.state == state).count();
    if in_state(MappingState::Mapping) != world.maps.len()
        || in_state(MappingState::Unmapping) != world.unmaps.len()
        || world.destroy.is_some() != (core.state == GenerationState::Destroying)
    {
        return Err("an outstanding ticket and the in-flight state disagree".into());
    }
    Ok(())
}

/// Shapes the bound must reach, so a green run means the interesting states
/// were checked, not that exploration stopped early.
#[derive(Debug, Default)]
struct Reached {
    two_mappings: bool,
    unmapping: bool,
    retiring: bool,
    terminal: bool,
    second_generation: bool,
}

impl Reached {
    fn note(&mut self, world: &World) {
        let core = &world.core;
        self.two_mappings |= core.mappings.len() == 2;
        self.unmapping |= core
            .mappings
            .values()
            .any(|m| m.state == MappingState::Unmapping);
        self.retiring |= core
            .extents
            .values()
            .any(|e| e.state == ExtentState::Retiring);
        self.terminal |= core
            .extents
            .values()
            .any(|e| e.state == ExtentState::Terminal);
        self.second_generation |= core.generation.0 >= 2;
    }
}

/// Explore every op sequence up to `depth`; returns the number of distinct
/// states and the shapes reached, or the first counterexample trace.
fn explore(depth: usize) -> Result<(usize, Reached), String> {
    // SAFETY: the explorer's cores are its own; no two share a carrier.
    let carrier = unsafe { CarrierId::assume_unique(NonZeroU64::MIN) };
    let root = World {
        core: Core::new(carrier),
        maps: Vec::new(),
        unmaps: Vec::new(),
        destroy: None,
        pins: Vec::new(),
        hosts_in_core: 0,
        leases_in_core: 0,
    };
    let mut seen = HashSet::new();
    let mut reached = Reached::default();
    let mut queue = VecDeque::new();
    seen.insert(root.clone());
    queue.push_back((root, Vec::new()));
    while let Some((world, trace)) = queue.pop_front() {
        if trace.len() == depth {
            continue;
        }
        for op in ops(&world) {
            let mut next = world.clone();
            let mut next_trace: Vec<Op> = trace.clone();
            next_trace.push(op);
            if let Err(broken) = step(&mut next, op) {
                return Err(format!("{broken} after {next_trace:?}"));
            }
            reached.note(&next);
            if seen.insert(next.clone()) {
                queue.push_back((next, next_trace));
            }
        }
    }
    Ok((seen.len(), reached))
}

/// A pinned extent terminalized by a destroy, then a second generation,
/// takes 10 transitions; two more leave room around it.
const DEPTH: usize = 12;

#[test]
fn every_bounded_op_sequence_keeps_the_core_invariants() {
    let (states, reached) =
        explore(DEPTH).unwrap_or_else(|counterexample| panic!("{counterexample}"));
    assert!(
        reached.two_mappings
            && reached.unmapping
            && reached.retiring
            && reached.terminal
            && reached.second_generation,
        "depth {DEPTH} ({states} states) missed a shape: {reached:?}"
    );
    std::println!("explored {states} distinct states to depth {DEPTH}: {reached:?}");
}
