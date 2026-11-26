//! The bounded exhaustive explorer for the memory-ownership core (#3061).
//!
//! It runs every sequence of transitions, up to a depth, over a small
//! universe: overlapping and adjacent mappings, extents carved inside them,
//! pins, retirement, unmap and destroy, with each backend result chosen both
//! ways. The shell is adversarial: it may hold any ticket or pin for as long
//! as it likes, finish them in any order, or never return them. After every
//! transition the explorer checks the core's own invariants (V1-V4) and the
//! model properties only the shell can see:
//! - V4: a backend action comes only from a `Creating` or `Live` generation,
//!   and a committed destroy leaves no mapping;
//! - V5: an extent is never released while the shell holds a pin on it, and a
//!   pin is minted only for a live extent;
//! - tokens: a ticket or pin is consumed exactly once, and a refused one comes
//!   back whole.
//!
//! States are deduplicated by hash. Production code is the system under test:
//! the explorer drives `CarrierCore` itself, with no double.
use super::*;
use std::collections::{HashSet, VecDeque};
use std::format;
use std::string::String;
use std::vec;

/// The explorer's venue: a dropped core holding anything fails the run.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct ExplorerVenue;

impl CoreVenue for ExplorerVenue {
    fn dropped_holding(mappings: usize, extents: usize) -> ! {
        panic!("core dropped holding {mappings} mappings and {extents} extents")
    }
}

type Core = CarrierCore<ExplorerVenue, u8>;

const HOST: usize = 0x10_0000;

#[derive(Clone, Hash, PartialEq, Eq)]
struct World {
    core: Core,
    maps: Vec<MapTicket>,
    unmaps: Vec<UnmapTicket>,
    destroy: Option<DestroyTicket>,
    pins: Vec<Pin>,
}

impl Drop for World {
    fn drop(&mut self) {
        // Mid-operation states are discarded by the thousand; the drop check
        // (V6) has its own witness in `tests.rs`.
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
}

/// The universe, in pages of one byte each so extents stay readable.
const MAPS: [(u64, u64); 3] = [(0, 2), (1, 2), (2, 2)];
const CARVES: [(u64, u64); 4] = [(0, 1), (1, 1), (0, 2), (2, 1)];
const PINS: [(u64, u64); 3] = [(0, 1), (1, 1), (0, 2)];
const RESULTS: [BackendResult; 2] = [BackendResult::Done, BackendResult::Failed];

fn ops(world: &World) -> Vec<Op> {
    let mut ops = vec![Op::Create, Op::CommitCreate, Op::BeginDestroy];
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
    for id in 1..world.core.next_extent {
        ops.push(Op::Retire(id));
    }
    for id in 1..world.core.next_mapping {
        ops.push(Op::BeginUnmap(id));
    }
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
            if let Ok((ticket, act)) = world.core.begin_map(extent(ipa, len)) {
                world.maps.push(ticket);
                action = Some(act);
            }
        }
        Op::FinishMap(index, result) => {
            let ticket = world.maps.remove(index);
            if let Err(refused) = world.core.finish_map(ticket, result) {
                world.maps.insert(index, refused.offered);
            }
        }
        Op::Carve(ipa, len) => {
            let spec = ExtentSpec {
                extent: extent(ipa, len),
                host_addr: HOST + ipa as usize,
                backing: ipa as u8,
            };
            if let Err(refused) = world.core.carve(spec.clone())
                && refused.offered != spec
            {
                return Err("a refused carve did not hand its spec back".into());
            }
        }
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
            match world.core.unpin(pin) {
                Ok(Some(gone)) => released.push(gone.id),
                Ok(None) => {}
                Err(refused) => world.pins.insert(index, refused.offered),
            }
        }
        Op::Retire(id) => {
            if let Ok(Retire::Released(gone)) = world.core.retire_extent(ExtentId(id)) {
                released.push(gone.id);
            }
        }
        Op::BeginUnmap(id) => {
            if let Ok((ticket, act)) = world.core.begin_unmap(MappingId(id)) {
                world.unmaps.push(ticket);
                action = Some(act);
            }
        }
        Op::FinishUnmap(index, result) => {
            let ticket = world.unmaps.remove(index);
            if let Err(refused) = world.core.finish_unmap(ticket, result) {
                world.unmaps.insert(index, refused.offered);
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
                        released.extend(gone.into_iter().map(|g| g.id));
                        if result == BackendResult::Done && world.core.mapping_count() != 0 {
                            return Err("a mapping survived a committed destroy".into());
                        }
                    }
                    Err(refused) => world.destroy = Some(refused.offered),
                }
            }
        }
    }
    if action.is_some() && !admits {
        return Err(format!("{action:?} issued in generation state {before:?}"));
    }
    for id in released {
        if world.pins.iter().any(|pin| pin.extent() == id) {
            return Err(format!("{id:?} released while the shell holds a pin on it"));
        }
    }
    world
        .core
        .check_invariants()
        .map_err(|violation| format!("{violation:?}"))
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
    let root = World {
        core: Core::new(CarrierId(NonZeroU64::MIN)),
        maps: Vec::new(),
        unmaps: Vec::new(),
        destroy: None,
        pins: Vec::new(),
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
