//! VM-free witnesses for the softmmu physical-retirement venue
//! (`softmmu.x86.physical-retirement`, #681 slice 2, #607).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::domains::{Access, CpuAccessMode, FrameGpa, GuestVa, OwnerGeneration};
use crate::tlb::{SOFT_TLB_ENTRIES, SoftTlbEntry};
use crate::walker::{ExtentRecord, ExtentTable, Retirement};
use alloc::vec::Vec;
use carrick_conformance_contract::{
    Completeness, ContractId, ContractObservation, ContractRegistry, ExecutionLayer,
    SemanticAssertion, WorkMetric, WorkSnapshot, evaluate,
};
use carrick_core::mm::retirement::invalidation::ResidencyMember;
use std::sync::atomic::AtomicU64 as StdAtomicU64;
use std::sync::mpsc;
use std::sync::{Arc as StdArc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const VA: GuestVa = GuestVa::new(0x4000);
const OLD_ADDEND: u64 = 0x1000;
const EXTENT: u64 = 0x1000;
const WAIT: Duration = Duration::from_secs(5);

fn generation(raw: u64) -> OwnerGeneration {
    OwnerGeneration::from_raw(raw).expect("nonzero")
}

/// Plant a cached read translation for `VA` (what a walk fill leaves).
fn cache_translation(tlb: &mut SoftTlb, addend: u64) {
    let index = SoftTlb::index_for(VA);
    tlb.read.entries[index] = SoftTlbEntry {
        tag: SoftTlb::tag_for(VA, CpuAccessMode::ring3()),
        addend,
    };
}

fn cached(tlb: &SoftTlb) -> Option<usize> {
    tlb.probe_readonly(VA, 1, Access::Read, CpuAccessMode::ring3())
}

fn table_with_extent() -> ExtentTable {
    let mut table = ExtentTable::new().expect("fresh domain");
    assert!(table.install(ExtentRecord::new(
        FrameGpa::new(EXTENT),
        0x1000,
        generation(1)
    )));
    table
}

/// A bounded relax for host-thread waits: a lost wake is a failure, not a hang.
fn bounded() -> impl FnMut() -> Result<(), &'static str> {
    let deadline = Instant::now() + WAIT;
    move || {
        if Instant::now() > deadline {
            return Err("retirement wait exceeded its bound");
        }
        thread::yield_now();
        Ok(())
    }
}

fn wait_for(mut done: impl FnMut() -> bool, what: &str) {
    let deadline = Instant::now() + WAIT;
    while !done() {
        assert!(Instant::now() < deadline, "{what} never happened");
        thread::yield_now();
    }
}

fn remove_extent(table: &StdArc<Mutex<ExtentTable>>) -> Retirement<ExtentRecord> {
    table
        .lock()
        .unwrap()
        .remove(FrameGpa::new(EXTENT), None)
        .expect("edit admitted")
        .expect("extent was live")
}

// ---------------------------------------------------------------------------
// Red-first witness (#607): a running peer holding a translation of a
// retired extent. On main the peer's TLB could only be flushed if the
// retiring thread borrowed it; omitted, the peer kept serving
// `Some(stale_host_address)` after retirement returned.
// ---------------------------------------------------------------------------

#[test]
fn running_peer_cannot_use_stale_addend_after_retirement_completes() {
    let table = StdArc::new(Mutex::new(table_with_extent()));
    let mut tlb = SoftTlb::new();
    let mut seat = table.lock().unwrap().register_vcpu(&mut tlb).unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();

    let peer = thread::spawn(move || {
        assert!(!seat.block_entry(&mut tlb), "a fresh seat owes nothing");
        cache_translation(&mut tlb, OLD_ADDEND);
        assert!(cached(&tlb).is_some(), "the peer hits its translation");
        ready_tx.send(()).unwrap();
        // Running between blocks until the retirement kicks it.
        wait_for(|| seat.exit_requested(), "the kick");
        // Still the old translation: no flush happens inside a block.
        assert!(cached(&tlb).is_some());
        assert!(seat.block_entry(&mut tlb), "block entry serves the debt");
        assert!(!seat.exit_requested(), "serving consumes the exit flag");
        result_tx.send(cached(&tlb)).unwrap();
        seat.park();
    });

    ready_rx.recv_timeout(WAIT).unwrap();
    let Retirement { retired, pending } = remove_extent(&table);
    assert_eq!(retired.generation, generation(1));
    assert!(pending.counts(CpuId::new(0)));
    // The peer is running and has not served: completion is refused.
    let pending = pending
        .try_complete()
        .expect_err("a running peer that has not served blocks completion");
    let completion = pending.wait(None, bounded()).map_err(|(_, e)| e).unwrap();
    assert_eq!(result_rx.recv_timeout(WAIT).unwrap(), None);
    assert_eq!(table.lock().unwrap().reclaim(&completion), 2);
    assert_eq!(table.lock().unwrap().retirement_kicks(), 1);
    peer.join().unwrap();
}

#[test]
fn parked_peer_resynchronizes_at_block_entry_and_is_never_kicked() {
    let mut table = table_with_extent();
    let mut tlb = SoftTlb::new();
    let mut seat = table.register_vcpu(&mut tlb).unwrap();
    seat.block_entry(&mut tlb);
    cache_translation(&mut tlb, OLD_ADDEND);
    seat.park();

    let Retirement { pending, .. } = table.remove(FrameGpa::new(EXTENT), None).unwrap().unwrap();
    // A parked peer never holds the retirement up.
    let completion = pending.try_complete().expect("the only peer is parked");
    assert_eq!(table.retirement_kicks(), 0);
    assert!(!seat.exit_requested());
    table.reclaim(&completion);
    // Its stale entry survives until it resumes, and is gone before use.
    assert!(cached(&tlb).is_some());
    assert!(seat.block_entry(&mut tlb));
    assert_eq!(cached(&tlb), None);
}

#[test]
fn host_admission_of_a_parked_peer_serves_before_its_probe() {
    let mut table = table_with_extent();
    let mut tlb = SoftTlb::new();
    let mut seat = table.register_vcpu(&mut tlb).unwrap();
    cache_translation(&mut tlb, OLD_ADDEND);
    let Retirement { pending, .. } = table.remove(FrameGpa::new(EXTENT), None).unwrap().unwrap();
    let completion = pending.try_complete().expect("parked");
    table.reclaim(&completion);
    let admission = seat.admit(&mut tlb);
    assert_eq!(admission, LookupAdmission::Entered);
    assert_eq!(cached(&tlb), None, "admission served the retirement");
    seat.release(admission);
    assert!(!seat.is_running(), "the admission parks the CPU again");
}

#[test]
fn retirement_from_inside_a_running_peer_serves_itself_without_deadlock() {
    let mut table = table_with_extent();
    let mut tlb = SoftTlb::new();
    let mut seat = table.register_vcpu(&mut tlb).unwrap();
    seat.block_entry(&mut tlb);
    cache_translation(&mut tlb, OLD_ADDEND);
    assert!(seat.is_running());

    let Retirement { pending, .. } = table
        .remove(
            FrameGpa::new(EXTENT),
            Some(SoftRequester::new(&mut seat, &mut tlb)),
        )
        .unwrap()
        .unwrap();
    // Counted, served inline, never kicked: it cannot wait on itself.
    assert!(pending.counts(seat.cpu()));
    assert_eq!(table.retirement_kicks(), 0);
    assert_eq!(cached(&tlb), None);
    let completion = pending
        .wait(Some(SoftRequester::new(&mut seat, &mut tlb)), bounded())
        .map_err(|(_, e)| e)
        .expect("a self-served retirement completes");
    assert_eq!(table.reclaim(&completion), 2);
}

#[test]
fn pending_extent_identities_are_refused_until_their_completion() {
    let mut table = table_with_extent();
    let Retirement { pending, .. } = table.remove(FrameGpa::new(EXTENT), None).unwrap().unwrap();
    assert_eq!(table.pending_identities(), 2);
    // Same base, other generation; other base, same generation: both refused.
    assert!(!table.install(ExtentRecord::new(
        FrameGpa::new(EXTENT),
        0x1000,
        generation(2)
    )));
    assert!(!table.install(ExtentRecord::new(
        FrameGpa::new(0x2000),
        0x1000,
        generation(1)
    )));
    let completion = pending.try_complete().expect("no CPU seated");
    assert_eq!(table.reclaim(&completion), 2);
    assert!(table.install(ExtentRecord::new(
        FrameGpa::new(EXTENT),
        0x1000,
        generation(2)
    )));
}

#[test]
fn pending_root_and_generation_are_refused_until_their_completion() {
    use carrick_guest_arch::RootGpa;
    let mut table = ExtentTable::new().unwrap();
    let root = RootGpa::page_aligned(FrameGpa::new(0x1000)).unwrap();
    let other = RootGpa::page_aligned(FrameGpa::new(0x2000)).unwrap();
    assert!(table.set_root_generation(root, generation(7)));
    let Retirement { retired, pending } =
        table.remove_root_generation(root, None).unwrap().unwrap();
    assert_eq!(retired, generation(7));
    assert!(!table.set_root_generation(root, generation(8)));
    assert!(!table.set_root_generation(other, generation(7)));
    let completion = pending.try_complete().expect("no CPU seated");
    table.reclaim(&completion);
    assert!(table.set_root_generation(root, generation(8)));
}

#[test]
fn a_seat_of_another_inventory_is_refused_before_any_edit() {
    let mut table = table_with_extent();
    let other = ExtentTable::new().unwrap();
    let mut tlb = SoftTlb::new();
    let mut foreign = other.register_vcpu(&mut tlb).unwrap();
    assert!(!table.is_member(&foreign));
    assert_eq!(
        table
            .remove(
                FrameGpa::new(EXTENT),
                Some(SoftRequester::new(&mut foreign, &mut tlb))
            )
            .map(|_| ()),
        Err(crate::walker::ExtentEditError::ForeignRequester)
    );
    assert!(
        table.lookup_span(EXTENT, 0x1000).is_some(),
        "nothing changed"
    );
}

#[test]
fn owner_generation_refuses_exhaustion() {
    let last = OwnerGeneration::from_raw(u64::MAX).unwrap();
    assert_eq!(last.checked_next(), None);
    assert_eq!(OwnerGeneration::FIRST.checked_next(), Some(generation(2)));
    assert_eq!(OwnerGeneration::from_raw(0), None);
}

// ---------------------------------------------------------------------------
// Concurrent Running <-> Parked transitions racing retirements.
// ---------------------------------------------------------------------------

/// A peer cycles block entry, parked host admissions and parks while the
/// main thread retires and reinstalls the extent. Each cached entry is
/// stamped with the number of removals begun before it was cached; removal
/// `b + 1` makes an entry stamped `b` stale. While the peer is admitted
/// (running), that removal cannot have completed unless the peer served it,
/// so once `completed > stamp` its probe must miss.
#[test]
fn concurrent_running_parked_transitions_never_outlive_a_completion() {
    const ROUNDS: u64 = 400;
    let table = StdArc::new(Mutex::new(table_with_extent()));
    let mut tlb = SoftTlb::new();
    let mut seat = table.lock().unwrap().register_vcpu(&mut tlb).unwrap();
    let begun = StdArc::new(StdAtomicU64::new(0));
    let completed = StdArc::new(StdAtomicU64::new(0));
    let stop = StdArc::new(core::sync::atomic::AtomicBool::new(false));

    let peer = {
        let begun = StdArc::clone(&begun);
        let completed = StdArc::clone(&completed);
        let stop = StdArc::clone(&stop);
        thread::spawn(move || {
            let mut step = 0u64;
            let mut stamp = None;
            while !stop.load(Ordering::Acquire) {
                step += 1;
                let admission = match step % 3 {
                    0 => {
                        seat.block_entry(&mut tlb);
                        None
                    }
                    1 => Some(seat.admit(&mut tlb)),
                    _ => {
                        seat.park();
                        stamp = None;
                        continue;
                    }
                };
                if let Some(stamped) = stamp
                    && completed.load(Ordering::Acquire) > stamped
                {
                    assert_eq!(cached(&tlb), None, "stale entry outlived a completion");
                }
                if cached(&tlb).is_none() {
                    stamp = Some(begun.load(Ordering::Acquire));
                    cache_translation(&mut tlb, OLD_ADDEND);
                }
                if let Some(LookupAdmission::Entered) = admission {
                    seat.release(LookupAdmission::Entered);
                    stamp = None;
                }
            }
            seat.park();
        })
    };

    for round in 0..ROUNDS {
        begun.store(round + 1, Ordering::Release);
        let Retirement { pending, .. } = remove_extent(&table);
        // Never wait while holding the table lock.
        let completion = pending.wait(None, bounded()).map_err(|(_, e)| e).unwrap();
        completed.store(round + 1, Ordering::Release);
        let mut guard = table.lock().unwrap();
        assert_eq!(guard.reclaim(&completion), 2);
        assert!(guard.install(ExtentRecord::new(
            FrameGpa::new(EXTENT),
            0x1000,
            generation(1)
        )));
    }
    stop.store(true, Ordering::Release);
    peer.join().unwrap();
    let kicks = table.lock().unwrap().retirement_kicks();
    assert!(
        kicks <= ROUNDS,
        "at most one kick per running peer per retirement"
    );
}

// ---------------------------------------------------------------------------
// Structural budgets: O(peers) members counted, at most one kick per running
// peer, zero shared RMWs or stores per block entry in steady state, O(1) hit.
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct CountingWord {
    value: StdAtomicU64,
    loads: StdAtomicU64,
    stores: StdAtomicU64,
    rmws: StdAtomicU64,
}

impl ServedWord for CountingWord {
    fn load(&self, order: Ordering) -> u64 {
        self.loads.fetch_add(1, Ordering::Relaxed);
        self.value.load(order)
    }
    fn store(&self, value: u64, order: Ordering) {
        self.stores.fetch_add(1, Ordering::Relaxed);
        self.value.store(value, order);
    }
    fn fetch_max(&self, value: u64, order: Ordering) -> u64 {
        self.rmws.fetch_add(1, Ordering::Relaxed);
        self.value.fetch_max(value, order)
    }
    fn compare_exchange(
        &self,
        current: u64,
        new: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64> {
        self.rmws.fetch_add(1, Ordering::Relaxed);
        self.value.compare_exchange(current, new, success, failure)
    }
    fn fetch_update<F: FnMut(u64) -> Option<u64>>(
        &self,
        set_order: Ordering,
        fetch_order: Ordering,
        f: F,
    ) -> Result<u64, u64> {
        self.rmws.fetch_add(1, Ordering::Relaxed);
        self.value.fetch_update(set_order, fetch_order, f)
    }
    fn fence(order: Ordering) {
        core::sync::atomic::fence(order);
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Work {
    loads: u64,
    stores: u64,
    rmws: u64,
}

fn member_work<const N: usize>(table: &ServedTable<N, CountingWord>) -> Work {
    let mut work = Work::default();
    for member in table.members() {
        let member: &ResidencyMember<CountingWord> = member;
        // SAFETY: read-only inspection of instrumentation counters.
        let words = unsafe { member.words() };
        for word in words.owed.iter().chain(words.served.iter()).chain([
            &words.running,
            &words.revision,
            &words.tag,
            &words.mm,
            &words.context,
            &words.seat,
        ]) {
            work.loads += word.loads.load(Ordering::Relaxed);
            work.stores += word.stores.load(Ordering::Relaxed);
            work.rmws += word.rmws.load(Ordering::Relaxed);
        }
    }
    work
}

/// RMWs and stores on every member word across 1000 debt-free block
/// entries of one running seat, on the exact `block_entry` production runs,
/// in a table with `peers` seated members.
fn steady_state_block_entry<const N: usize>(peers: usize) -> Work {
    let table = ServedTable::<N, CountingWord>::with_domain(issue_domain_nonce().unwrap());
    let exits: Vec<ExitFlag> = (0..N).map(|_| ExitFlag(AtomicBool::new(false))).collect();
    let kicks = AtomicU64::new(0);
    let mut tlbs: Vec<SoftTlb> = (0..peers).map(|_| SoftTlb::new()).collect();
    let mut seats = Vec::new();
    for (index, tlb) in tlbs.iter_mut().enumerate() {
        let mut venue = SoftVenue {
            tlb: Some(tlb),
            exits: &exits,
            kicks: &kicks,
            relax: no_relax as NoRelax,
        };
        let mut seat = MemberSeat::claim(&table, CpuId::new(index as u32), &mut venue).unwrap();
        let mut running = false;
        let Ok(_) = block_entry(&mut seat, &mut running, &mut venue);
        seats.push((seat, running));
    }
    let flushes_before = tlbs[0].stats().full_flushes;
    let counter_before = table.counter().latest(Ordering::Relaxed);
    let before = member_work(&table);
    {
        let (seat, running) = &mut seats[0];
        let mut venue = SoftVenue {
            tlb: Some(&mut tlbs[0]),
            exits: &exits,
            kicks: &kicks,
            relax: no_relax as NoRelax,
        };
        for _ in 0..1000 {
            let Ok(flushed) = block_entry(seat, running, &mut venue);
            assert!(!flushed);
        }
    }
    let after = member_work(&table);
    assert_eq!(table.counter().latest(Ordering::Relaxed), counter_before);
    assert_eq!(tlbs[0].stats().full_flushes, flushes_before);
    assert_eq!(kicks.load(Ordering::Relaxed), 0);
    // owed[2] + served[2], own line only, per block entry.
    assert_eq!(after.loads - before.loads, 1000 * 4);
    Work {
        loads: after.loads - before.loads,
        stores: after.stores - before.stores,
        rmws: after.rmws - before.rmws,
    }
}

const FIXTURE: &str = "carrick-softmmu::retirement::tests";

fn observation(peers: u64, counted: u64, kicks: u64, steady: Work) -> ContractObservation {
    let mut work = WorkSnapshot::new();
    work.insert(WorkMetric::InvalidationMembersCounted, counted)
        .unwrap();
    work.insert(WorkMetric::InvalidationKicks, kicks).unwrap();
    work.insert(
        WorkMetric::InvalidationSteadyStateRmws,
        steady.rmws + steady.stores,
    )
    .unwrap();
    ContractObservation {
        contract_id: ContractId::new("softmmu.x86.physical-retirement").unwrap(),
        layer: ExecutionLayer::VmFree,
        implementation_revision: "softmmu-physical-retirement-2".into(),
        fixture_identity: FIXTURE.into(),
        scale: peers,
        semantic_assertions: alloc::vec![SemanticAssertion::pass(
            "every_seated_peer_owes_the_retirement_and_hits_stay_o1",
        )],
        work: Some(work),
        timing: None,
        completeness: Completeness::Complete,
    }
}

/// One retirement over `peers` running peers plus as many parked ones.
fn retirement_work(peers: usize) -> (u64, u64) {
    let mut table = table_with_extent();
    let mut running = Vec::new();
    for _ in 0..peers {
        let mut tlb = SoftTlb::new();
        let mut seat = table.register_vcpu(&mut tlb).unwrap();
        seat.block_entry(&mut tlb);
        cache_translation(&mut tlb, OLD_ADDEND);
        running.push((seat, tlb));
    }
    let mut parked = Vec::new();
    for _ in 0..peers {
        let mut tlb = SoftTlb::new();
        let seat = table.register_vcpu(&mut tlb).unwrap();
        parked.push((seat, tlb));
    }
    let kicks_before = table.retirement_kicks();
    let Retirement { pending, .. } = table.remove(FrameGpa::new(EXTENT), None).unwrap().unwrap();
    let counted = u64::from(pending.counted_members());
    let kicks = table.retirement_kicks() - kicks_before;
    assert_eq!(counted, 2 * peers as u64, "every seated peer owes it once");
    assert_eq!(
        kicks, peers as u64,
        "one kick per running peer, none parked"
    );
    let mut pending = pending;
    for (seat, tlb) in &mut running {
        assert!(seat.exit_requested());
        pending = pending
            .try_complete()
            .expect_err("a running peer is unserved");
        assert!(seat.block_entry(tlb));
        assert_eq!(cached(tlb), None);
    }
    let completion = pending
        .try_complete()
        .expect("running served, parked stopped");
    table.reclaim(&completion);

    // A hit stays O(1): 1024 hits on one entry, no flush, no scan.
    let (_, tlb) = &mut running[0];
    cache_translation(tlb, OLD_ADDEND);
    tlb.reset_stats();
    for _ in 0..SOFT_TLB_ENTRIES {
        assert!(
            tlb.probe(VA, 1, Access::Read, CpuAccessMode::ring3())
                .is_some()
        );
    }
    assert_eq!(tlb.stats().hits, SOFT_TLB_ENTRIES as u64);
    assert_eq!(tlb.stats().misses, 0);
    assert_eq!(tlb.stats().full_flushes, 0);
    (counted, kicks)
}

#[test]
fn retirement_is_linear_in_peers_and_block_entry_is_rmw_free() {
    let scales: [(u64, Work); 3] = [
        (1, steady_state_block_entry::<2>(2)),
        (8, steady_state_block_entry::<16>(16)),
        (32, steady_state_block_entry::<64>(64)),
    ];
    let mut observations = Vec::new();
    for (peers, steady) in scales {
        assert_eq!(steady.rmws, 0, "no shared RMW per block entry");
        assert_eq!(steady.stores, 0, "no shared store per block entry");
        // `peers` running plus `peers` parked members are seated.
        let (counted, kicks) = retirement_work(peers as usize);
        observations.push(observation(2 * peers, counted, kicks, steady));
    }
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .unwrap();
    let registry = ContractRegistry::load(repo_root).unwrap();
    evaluate(
        registry.require("softmmu.x86.physical-retirement").unwrap(),
        &observations,
    )
    .expect("structural budgets hold");
}
