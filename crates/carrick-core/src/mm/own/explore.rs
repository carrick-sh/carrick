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

// ---------------------------------------------------------------------------
// PR 1a: MMs, their editor and their copy-on-write grants.
//
// The universe is two MMs, arenas of two-grant chunks, and three chunk
// extents (two overlapping) the shell may offer for any chunk demand.
// The guest adversary may take or release either MM's editor at any step,
// and the shell may offer any transition at any step, with any outstanding
// ticket or proof, including one it was already refused. Payloads are
// unique bytes, so the explorer can tell whether one was lost or doubled.

impl GrantPayload for u8 {
    type Key = u8;
    fn key(&self) -> &u8 {
        self
    }
}

type GrantCore = CarrierCore<ExplorerVenue, u8, u8, u8>;

#[derive(Clone, Hash, PartialEq, Eq)]
struct GrantWorld {
    core: GrantCore,
    supplies: Vec<SupplyTicket>,
    chunk_demands: Vec<ChunkDemand>,
    settle: Option<SettleProof>,
    /// Payloads handed to the core (`Published`) and not yet back.
    in_core: Vec<(MmKey, u8)>,
    next_payload: u8,
    /// Each MM was refused "not now" at a supply, and supplied since.
    busy_then_supplied: [bool; 2],
    /// A supply was carved from a chunk an earlier supply mapped.
    carved_from_chunk: bool,
    refused_busy: [bool; 2],
    /// Release tickets the shell holds (PR 1b).
    releases: Vec<ReleaseTicket>,
    /// A release came back `Broken`: the venue ends the carrier, so the
    /// world stops here.
    ended: bool,
    /// Each MM had a release answered "not now", and was released since.
    not_now_then_released: [bool; 2],
    deferred: [bool; 2],
}

impl Drop for GrantWorld {
    fn drop(&mut self) {
        self.core.forget_for_explorer();
    }
}

#[derive(Clone, Copy, Debug)]
enum GrantOp {
    GuestHold(usize),
    GuestRelease(usize),
    Supply(usize),
    AdmitChunk(usize, usize),
    CancelChunk(usize),
    FinishSupply(usize, bool),
    BeginSettle(usize),
    Settle(u8),
    FinishSettle,
    Exit(usize),
    BeginRelease(usize),
    /// Finish the ticket at the index with outcome 0 `Done`, 1 `NotNow`
    /// or 2 `Broken`.
    FinishRelease(usize, u8),
    RetireAll,
}

const CHUNK_EXTENTS: [(u64, u64); 3] = [(0x10_000, 0x8000), (0x14_000, 0x8000), (0x20_000, 0x8000)];

fn mm_key(index: usize) -> MmKey {
    MmKey::new(NonZeroU64::new(index as u64 + 1).unwrap_or(NonZeroU64::MIN))
}

fn grant_ops(world: &GrantWorld) -> Vec<GrantOp> {
    if world.ended {
        return Vec::new();
    }
    let mut ops = vec![GrantOp::FinishSettle, GrantOp::RetireAll];
    for mm in 0..2 {
        ops.extend([
            GrantOp::GuestHold(mm),
            GrantOp::GuestRelease(mm),
            GrantOp::BeginSettle(mm),
            GrantOp::Exit(mm),
            GrantOp::BeginRelease(mm),
            GrantOp::Supply(mm),
        ]);
    }
    for index in 0..world.releases.len() {
        ops.extend((0..3).map(|outcome| GrantOp::FinishRelease(index, outcome)));
    }
    for index in 0..world.chunk_demands.len() {
        ops.extend((0..CHUNK_EXTENTS.len()).map(|chunk| GrantOp::AdmitChunk(index, chunk)));
        ops.push(GrantOp::CancelChunk(index));
    }
    for index in 0..world.supplies.len() {
        ops.extend([
            GrantOp::FinishSupply(index, true),
            GrantOp::FinishSupply(index, false),
        ]);
    }
    ops.extend((1..world.next_payload).map(GrantOp::Settle));
    ops
}

/// A copy of the core to compare against; forgotten on drop like a world.
struct Snapshot(GrantCore);

impl Drop for Snapshot {
    fn drop(&mut self) {
        self.0.forget_for_explorer();
    }
}

impl PartialEq<Snapshot> for GrantCore {
    fn eq(&self, other: &Snapshot) -> bool {
        *self == other.0
    }
}

fn grant_step(world: &mut GrantWorld, op: GrantOp) -> Result<(), String> {
    let before = Snapshot(world.core.clone());
    match op {
        GrantOp::GuestHold(mm) => {
            // The guest takes its editor only while no host edit holds it
            // (the guest try-lock is the same word), and only while the MM
            // has members: an exited MM has none.
            if world
                .core
                .editor(mm_key(mm))
                .is_none_or(|e| e == MmEditor::Free)
                && world
                    .core
                    .mm_life(mm_key(mm))
                    .is_none_or(|life| life == MmLife::Live)
            {
                world.core.guest_editor(mm_key(mm), true);
            }
        }
        GrantOp::GuestRelease(mm) => {
            world.core.guest_editor(mm_key(mm), false);
        }
        GrantOp::Supply(mm) => {
            let excluded = ExcludedMm::claimed(mm_key(mm));
            match world.core.supply_cow(&excluded, 0x1000) {
                Ok(supply) => {
                    if before.0.editor(mm_key(mm)) == Some(MmEditor::Guest) {
                        return Err("supplied while the guest held the editor".into());
                    }
                    world.busy_then_supplied[mm] |= world.refused_busy[mm];
                    match supply {
                        CowSupply::Carved(ticket) => {
                            world.carved_from_chunk = true;
                            world.supplies.push(ticket);
                        }
                        CowSupply::NeedsChunk(demand) => {
                            if demand.mm() != mm_key(mm) {
                                return Err("a chunk demand named another MM".into());
                            }
                            world.chunk_demands.push(demand);
                        }
                    }
                }
                Err(MmRefusal::NotNow(NotNow::EditorRelease(key))) => {
                    if key != mm_key(mm) || world.core.editor(key) != Some(MmEditor::Guest) {
                        return Err("not now named the wrong editor".into());
                    }
                    if world.core != before {
                        return Err("a not-now supply changed the core".into());
                    }
                    world.refused_busy[mm] = true;
                }
                Err(MmRefusal::Refused(_)) => {
                    if world.core != before {
                        return Err("a refused supply changed the core".into());
                    }
                }
            }
        }
        GrantOp::AdmitChunk(index, chunk) => {
            let demand = world.chunk_demands.remove(index);
            let mm = demand.mm();
            let (ipa, len) = CHUNK_EXTENTS[chunk];
            let extent = GpaExtent::new(ipa, len).ok_or("universe extent")?;
            match world.core.admit_chunk(demand, extent) {
                Ok(ticket) => {
                    if ticket.mm() != mm || !extent.contains(ticket.extent()) {
                        return Err("a chunk's first grant is not its MM's, inside it".into());
                    }
                    world.supplies.push(ticket);
                }
                Err(refused) => {
                    if world.core != before {
                        return Err("a refused chunk changed the core".into());
                    }
                    world.chunk_demands.insert(index, refused.offered);
                }
            }
        }
        GrantOp::CancelChunk(index) => {
            let demand = world.chunk_demands.remove(index);
            if let Err(refused) = world.core.cancel_chunk(demand) {
                world.chunk_demands.insert(index, refused.offered);
            }
        }
        GrantOp::FinishSupply(index, published) => {
            let ticket = world.supplies.remove(index);
            let mm = ticket.mm();
            let payload = world.next_payload;
            let outcome = if published {
                Supplied::Published(payload)
            } else {
                Supplied::Failed
            };
            match world.core.finish_supply_cow(ticket, outcome.clone()) {
                Ok(_) if published => {
                    world.in_core.push((mm, payload));
                    world.next_payload += 1;
                }
                Ok(_) => {}
                Err(refused) => {
                    if refused.offered.1 != outcome {
                        return Err("a refused supply report lost its payload".into());
                    }
                    world.supplies.insert(index, refused.offered.0);
                }
            }
        }
        GrantOp::BeginSettle(mm) => {
            if world.settle.is_none() {
                let excluded = ExcludedMm::claimed(mm_key(mm));
                match world.core.begin_settle(&excluded) {
                    Ok(proof) => world.settle = Some(proof),
                    Err(_) if world.core != before => {
                        return Err("a refused settle changed the core".into());
                    }
                    Err(_) => {}
                }
            }
        }
        GrantOp::Settle(key) => {
            if let Some(proof) = world.settle.take() {
                if let Ok(payload) = world.core.settle_cow(&proof, &key) {
                    let Some(at) = world.in_core.iter().position(|&(_, p)| p == payload) else {
                        return Err(format!(
                            "settled payload {payload}, which the core never held"
                        ));
                    };
                    if payload != key || world.in_core[at].0 != proof.mm() {
                        return Err("a settlement handed back another MM's or key's grant".into());
                    }
                    world.in_core.remove(at);
                }
                world.settle = Some(proof);
            }
        }
        GrantOp::FinishSettle => {
            if let Some(proof) = world.settle.take()
                && let Err(refused) = world.core.finish_settle(proof)
            {
                world.settle = Some(refused.offered);
            }
        }
        GrantOp::Exit(mm) => match world.core.exit_mm(mm_key(mm)) {
            Ok(()) => {
                if world.core.mm_life(mm_key(mm)) != Some(MmLife::Exiting) {
                    return Err("an exited MM is not exiting".into());
                }
            }
            Err(MmRefusal::NotNow(NotNow::EditorRelease(key))) => {
                if key != mm_key(mm) || before.0.editor(key) != Some(MmEditor::Guest) {
                    return Err("an exit's not now named the wrong editor".into());
                }
                if world.core != before {
                    return Err("a not-now exit changed the core".into());
                }
            }
            Err(MmRefusal::Refused(_)) => {
                if world.core != before {
                    return Err("a refused exit changed the core".into());
                }
            }
        },
        GrantOp::BeginRelease(mm) => match world.core.begin_release(mm_key(mm)) {
            Ok((ticket, returned)) => {
                if before
                    .0
                    .mm_life(mm_key(mm))
                    .is_some_and(|life| life != MmLife::Exiting)
                {
                    return Err("released an MM that was not exiting".into());
                }
                if ticket.mm() != mm_key(mm) {
                    return Err("a release ticket names another MM".into());
                }
                take_returned(world, &returned, Some(mm_key(mm)))?;
                world.releases.push(ticket);
            }
            Err(_) => {
                if world.core != before {
                    return Err("a refused release changed the core".into());
                }
            }
        },
        GrantOp::FinishRelease(index, outcome) => {
            let ticket = world.releases.remove(index);
            let mm = ticket.mm();
            let at = (0..2).find(|&i| mm_key(i) == mm).ok_or("universe MM")?;
            let offered = match outcome {
                0 => ReleaseOutcome::Done,
                1 => ReleaseOutcome::NotNow(ReleaseWait::NextDrain),
                _ => ReleaseOutcome::Broken(BrokenRelease::at("explorer")),
            };
            match world.core.finish_release(ticket, offered) {
                Ok(verdict) => {
                    if verdict != offered {
                        return Err(format!(
                            "release outcome {offered:?} came back as {verdict:?}"
                        ));
                    }
                    let life = world.core.mm_life(mm);
                    match offered {
                        ReleaseOutcome::Done => {
                            if life.is_some() {
                                return Err("a done release left the MM's record".into());
                            }
                            world.not_now_then_released[at] |= world.deferred[at];
                        }
                        ReleaseOutcome::NotNow(_) => {
                            if life != Some(MmLife::Exiting) {
                                return Err("a not-now release did not leave the MM exiting".into());
                            }
                            world.deferred[at] = true;
                        }
                        ReleaseOutcome::Broken(_) => {
                            if life != Some(MmLife::Broken) {
                                return Err("a broken release did not mark the MM broken".into());
                            }
                            world.ended = true;
                        }
                    }
                }
                Err(refused) => {
                    if world.core != before {
                        return Err("a refused release report changed the core".into());
                    }
                    world.releases.insert(index, refused.offered);
                }
            }
        }
        GrantOp::RetireAll => match world.core.retire_all_mms() {
            Ok(returned) => {
                take_returned(world, &returned, None)?;
                if world.core.grant_count() != 0 {
                    return Err("a grant outlived the carrier's retirement".into());
                }
            }
            Err(_) if world.core != before => {
                return Err("a refused carrier retirement changed the core".into());
            }
            Err(_) => {}
        },
    }
    reconcile_grants(world)?;
    world
        .core
        .check_invariants()
        .map_err(|violation| format!("{violation:?}"))
}

fn take_returned(world: &mut GrantWorld, returned: &[u8], mm: Option<MmKey>) -> Result<(), String> {
    for payload in returned {
        let Some(at) = world.in_core.iter().position(|(_, p)| p == payload) else {
            return Err(format!("retirement returned payload {payload} twice"));
        };
        if mm.is_some_and(|mm| world.in_core[at].0 != mm) {
            return Err("an MM's retirement took another MM's grant".into());
        }
        world.in_core.remove(at);
    }
    if let Some(mm) = mm
        && world.in_core.iter().any(|&(owner, _)| owner == mm)
    {
        return Err("a retired MM's grant stayed in the core".into());
    }
    Ok(())
}

/// The shell's custody and the core's grant records agree.
fn reconcile_grants(world: &GrantWorld) -> Result<(), String> {
    let core = &world.core;
    let provisioned: Vec<(MmKey, u8)> = core
        .grants
        .values()
        .filter_map(|g| match g.state {
            grant::GrantState::Provisioned(payload) => Some((g.mm, payload)),
            grant::GrantState::Supplying => None,
        })
        .collect();
    let mut held = world.in_core.clone();
    held.sort_by_key(|&(_, p)| p);
    let mut counted = provisioned;
    counted.sort_by_key(|&(_, p)| p);
    if held != counted {
        return Err(format!(
            "payloads lost or doubled: shell {held:?}, core {counted:?}"
        ));
    }
    let supplying = core
        .grants
        .values()
        .filter(|g| matches!(g.state, grant::GrantState::Supplying))
        .count();
    if supplying != world.supplies.len() {
        return Err("an outstanding supply ticket and the core disagree".into());
    }
    let chunking = core
        .mms
        .values()
        .filter(|m| m.editor == MmEditor::Host(HostEdit::CowChunk))
        .count();
    if chunking != world.chunk_demands.len() {
        return Err("an outstanding chunk demand and the core disagree".into());
    }
    let settling = core
        .mms
        .values()
        .filter(|m| m.editor == MmEditor::Host(HostEdit::Settle))
        .count();
    if settling != usize::from(world.settle.is_some()) {
        return Err("a settle proof and the core disagree".into());
    }
    // L3: one ticket per releasing MM.
    let releasing = core
        .mms
        .values()
        .filter(|m| m.life == MmLife::Releasing)
        .count();
    if releasing != world.releases.len() {
        return Err("an outstanding release ticket and the core disagree".into());
    }
    Ok(())
}

#[derive(Debug, Default)]
struct GrantsReached {
    two_supplying: bool,
    two_provisioned_one_mm: bool,
    busy_then_supplied: bool,
    settled_while_other_supplies: bool,
    carved_from_chunk: bool,
    not_now_then_released: bool,
    released_with_a_grant: bool,
}

fn explore_grants(depth: usize) -> Result<(usize, GrantsReached), String> {
    // SAFETY: the explorer's cores are its own; no two share a carrier.
    let carrier = unsafe { CarrierId::assume_unique(NonZeroU64::MIN) };
    let mut core = GrantCore::new(carrier);
    core.set_cow_geometry(CowArenaGeometry::new(0x4000, 0x8000).ok_or("geometry")?)
        .map_err(|refusal| format!("{refusal:?}"))?;
    let root = GrantWorld {
        core,
        supplies: Vec::new(),
        chunk_demands: Vec::new(),
        carved_from_chunk: false,
        settle: None,
        in_core: Vec::new(),
        next_payload: 1,
        busy_then_supplied: [false; 2],
        refused_busy: [false; 2],
        releases: Vec::new(),
        ended: false,
        not_now_then_released: [false; 2],
        deferred: [false; 2],
    };
    let mut seen = HashSet::new();
    let mut reached = GrantsReached::default();
    let mut queue = VecDeque::new();
    seen.insert(root.clone());
    queue.push_back((root, Vec::new()));
    while let Some((world, trace)) = queue.pop_front() {
        if trace.len() == depth {
            continue;
        }
        for op in grant_ops(&world) {
            let mut next = world.clone();
            let mut next_trace: Vec<GrantOp> = trace.clone();
            next_trace.push(op);
            if let Err(broken) = grant_step(&mut next, op) {
                return Err(format!("{broken} after {next_trace:?}"));
            }
            reached.two_supplying |= next.supplies.len() == 2;
            reached.two_provisioned_one_mm |= (0..2).any(|mm| {
                next.in_core
                    .iter()
                    .filter(|&&(owner, _)| owner == mm_key(mm))
                    .count()
                    == 2
            });
            reached.busy_then_supplied |= next.busy_then_supplied.iter().any(|&b| b);
            reached.settled_while_other_supplies |=
                next.settle.is_some() && !next.supplies.is_empty();
            reached.carved_from_chunk |= next.carved_from_chunk;
            reached.not_now_then_released |= next.not_now_then_released.iter().any(|&b| b);
            reached.released_with_a_grant |=
                matches!(op, GrantOp::BeginRelease(_)) && next.in_core.len() < world.in_core.len();
            if seen.insert(next.clone()) {
                queue.push_back((next, next_trace));
            }
        }
    }
    Ok((seen.len(), reached))
}

/// Busy once then supplied takes three transitions (hold, refused supply,
/// release) plus the supply; two provisioned grants of one MM (a chunk
/// demand, its admission, a finish, a carve, a finish) plus a settle
/// against a second MM's supply need eight; one more leaves room.
const GRANT_DEPTH: usize = 9;

#[test]
fn every_bounded_grant_sequence_keeps_the_mm_and_grant_invariants() {
    let (states, reached) =
        explore_grants(GRANT_DEPTH).unwrap_or_else(|counterexample| panic!("{counterexample}"));
    assert!(
        reached.two_supplying
            && reached.two_provisioned_one_mm
            && reached.busy_then_supplied
            && reached.settled_while_other_supplies
            && reached.carved_from_chunk
            && reached.not_now_then_released
            && reached.released_with_a_grant,
        "depth {GRANT_DEPTH} ({states} states) missed a shape: {reached:?}"
    );
    std::println!("explored {states} distinct grant states to depth {GRANT_DEPTH}: {reached:?}");
}

/// Each seeded mutant of the release (#3061 PR 1b) breaks one rule, and the
/// explorer finds it within a shallow depth: a lifecycle invariant is only
/// as good as the checks that catch its violation.
#[test]
fn every_seeded_release_mutant_is_found() {
    use super::release::mutant::{self, Mutant};
    for which in [
        Mutant::NotNowRetires,
        Mutant::ReleasesLive,
        Mutant::EditsAfterExit,
        Mutant::BrokenDefers,
    ] {
        let found = mutant::with(which, || explore_grants(RELEASE_MUTANT_DEPTH));
        match found {
            Err(counterexample) => {
                std::println!("mutant {which:?} found: {counterexample}");
            }
            Ok((states, _)) => {
                panic!("mutant {which:?} survived {states} states to depth {RELEASE_MUTANT_DEPTH}")
            }
        }
    }
}

/// Exit, begin, a "not now" finish, begin again: four transitions reach
/// every mutant's rule.
const RELEASE_MUTANT_DEPTH: usize = 4;
