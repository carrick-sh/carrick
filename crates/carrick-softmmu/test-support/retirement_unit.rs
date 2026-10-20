//! VM-free witnesses for the softmmu physical-retirement venue
//! (`softmmu.x86.physical-retirement`, #681 slice 2, #607).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::domains::{Access, CpuAccessMode, FrameGpa, GuestVa, OwnerGeneration};
use crate::tlb::{SOFT_TLB_ENTRIES, SoftTlbEntry};
use crate::walker::{ExtentEditError, ExtentRecord, ExtentTable, Reclaimed, Retirement};
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

fn released(identities: usize) -> Reclaimed {
    Reclaimed {
        identities,
        published: 0,
    }
}

fn host_wait(pending: PendingRetirement) -> DomainCompletion {
    pending
        .wait(None, bounded())
        .map_err(|(_, error)| error)
        .expect("retirement completes")
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
    let mut vcpu = table.lock().unwrap().register_vcpu(SoftTlb::new()).unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();

    let peer = thread::spawn(move || {
        let mut run = vcpu.run();
        assert!(!run.block_entry().unwrap(), "a fresh seat owes nothing");
        cache_translation(run.tlb_mut_for_test(), OLD_ADDEND);
        assert!(cached(run.tlb()).is_some(), "the peer hits its translation");
        ready_tx.send(()).unwrap();
        // Running between blocks until the retirement kicks it.
        wait_for(|| run.exit_requested(), "the kick");
        // Still the old translation: no flush happens inside a block.
        assert!(cached(run.tlb()).is_some());
        assert!(run.block_entry().unwrap(), "block entry serves the debt");
        assert!(!run.exit_requested(), "serving consumes the exit flag");
        result_tx.send(cached(run.tlb())).unwrap();
    });

    ready_rx.recv_timeout(WAIT).unwrap();
    let Retirement { retired, pending } = remove_extent(&table);
    assert_eq!(retired.generation, generation(1));
    assert!(pending.counts(CpuId::new(0)));
    // The peer is running and has not served: completion is refused.
    let pending = pending
        .try_complete()
        .expect_err("a running peer that has not served blocks completion");
    let completion = host_wait(pending);
    assert_eq!(result_rx.recv_timeout(WAIT).unwrap(), None);
    assert_eq!(table.lock().unwrap().reclaim(&completion), released(1));
    assert_eq!(table.lock().unwrap().retirement_kicks(), 1);
    peer.join().unwrap();
}

#[test]
fn parked_peer_resynchronizes_at_block_entry_and_is_never_kicked() {
    let mut table = table_with_extent();
    let mut vcpu = table.register_vcpu(SoftTlb::new()).unwrap();
    vcpu.run().block_entry().unwrap();
    cache_translation(vcpu.tlb_mut_for_test(), OLD_ADDEND);

    let Retirement { pending, .. } = table.remove(FrameGpa::new(EXTENT), None).unwrap().unwrap();
    // A parked peer never holds the retirement up.
    let completion = pending.try_complete().expect("the only peer is parked");
    assert_eq!(table.retirement_kicks(), 0);
    assert!(!vcpu.exit_requested());
    table.reclaim(&completion);
    // Its stale entry survives until it resumes, and is gone before use.
    assert!(cached(vcpu.tlb()).is_some());
    assert!(vcpu.run().block_entry().unwrap());
    assert_eq!(cached(vcpu.tlb()), None);
}

#[test]
fn host_admission_of_a_parked_peer_serves_before_its_probe() {
    let mut table = table_with_extent();
    let other = ExtentTable::new().unwrap();
    let mut vcpu = table.register_vcpu(SoftTlb::new()).unwrap();
    cache_translation(vcpu.tlb_mut_for_test(), OLD_ADDEND);
    assert_eq!(
        vcpu.admit(&other).unwrap_err(),
        SoftAdmitError::ForeignInventory
    );
    assert!(
        cached(vcpu.tlb()).is_some(),
        "foreign inventory admission is refused before touching the TLB"
    );
    let Retirement { pending, .. } = table.remove(FrameGpa::new(EXTENT), None).unwrap().unwrap();
    let completion = pending.try_complete().expect("parked");
    table.reclaim(&completion);
    {
        let admission = vcpu.admit(&table).unwrap();
        assert!(admission.seat().is_running());
        assert_eq!(
            cached(admission.tlb()),
            None,
            "admission served the retirement"
        );
    }
    assert!(!vcpu.is_running(), "dropping the admission parks the CPU");
}

#[test]
fn retirement_from_inside_a_running_peer_serves_itself_without_deadlock() {
    let mut table = table_with_extent();
    let mut vcpu = table.register_vcpu(SoftTlb::new()).unwrap();
    let mut run = vcpu.run();
    run.block_entry().unwrap();
    cache_translation(run.tlb_mut_for_test(), OLD_ADDEND);

    let Retirement { pending, .. } = table
        .remove(FrameGpa::new(EXTENT), Some(run.requester()))
        .unwrap()
        .unwrap();
    // Counted, served inline, never kicked: it cannot wait on itself.
    assert!(pending.counts(run.seat().cpu()));
    assert_eq!(table.retirement_kicks(), 0);
    assert_eq!(cached(run.tlb()), None);
    let completion = pending
        .wait(Some(run.requester()), bounded())
        .map_err(|(_, e)| e)
        .expect("a self-served retirement completes");
    assert_eq!(table.reclaim(&completion), released(1));
}

// ---------------------------------------------------------------------------
// P1-b (#707 review): running is a scope. A finished run parks, so a host
// wait never wedges on it; a CPU's own thread waiting without itself as the
// requester is refused instead of waiting on its own safe point.
// ---------------------------------------------------------------------------

#[test]
fn a_finished_run_parks_so_a_host_wait_never_wedges() {
    let mut table = table_with_extent();
    let mut vcpu = table.register_vcpu(SoftTlb::new()).unwrap();
    // A block ran; the embedder now handles a syscall without parking by
    // hand. The run guard already parked the CPU when it dropped.
    vcpu.run().block_entry().unwrap();
    assert!(!vcpu.is_running());
    let Retirement { pending, .. } = table.remove(FrameGpa::new(EXTENT), None).unwrap().unwrap();
    let mut polls = 0u32;
    let completion = pending
        .wait(None, || {
            polls += 1;
            if polls > 100_000 {
                Err("wedged")
            } else {
                Ok(())
            }
        })
        .map_err(|(_, e)| e)
        .expect("a parked CPU never holds a host wait");
    assert_eq!(polls, 0, "completed without a single relax");
    table.reclaim(&completion);
}

#[test]
fn a_cpu_thread_waiting_without_itself_as_requester_is_refused() {
    let mut table = table_with_extent();
    let mut vcpu = table.register_vcpu(SoftTlb::new()).unwrap();
    let mut run = vcpu.run();
    run.block_entry().unwrap();
    let Retirement { pending, .. } = table.remove(FrameGpa::new(EXTENT), None).unwrap().unwrap();
    let mut polls = 0u32;
    let (pending, error) = pending
        .wait(None, || {
            polls += 1;
            if polls > 10_000 { Err(()) } else { Ok(()) }
        })
        .expect_err("this thread runs a CPU that owes the retirement");
    assert_eq!(error, RetirementWaitError::SelfWait);
    assert_eq!(polls, 0, "refused before waiting");
    // Passing itself serves it inline.
    let completion = pending
        .wait(Some(run.requester()), bounded())
        .map_err(|(_, e)| e)
        .expect("served as its own requester");
    drop(run);
    table.reclaim(&completion);
}

#[test]
fn an_unguarded_running_seat_still_wedges_a_host_wait() {
    // The raw entry point keeps the old shape for embedders with their own
    // guard; without one, the bound is the only way out.
    let mut table = table_with_extent();
    let mut tlb = SoftTlb::new();
    // SAFETY: `tlb` and `seat` stay paired for this test.
    let mut seat = unsafe { table.register_vcpu_unguarded(&mut tlb) }.unwrap();
    // SAFETY: deliberately violated (no park) to witness why it is unsafe;
    // the seat is dropped, stopping it, before the test ends.
    unsafe { seat.block_entry_unguarded(&mut tlb) }.unwrap();
    let Retirement { pending, .. } = table.remove(FrameGpa::new(EXTENT), None).unwrap().unwrap();
    let result = thread::scope(|scope| {
        scope
            .spawn(move || {
                let mut polls = 0u32;
                pending.wait(None, || {
                    polls += 1;
                    if polls > 10_000 {
                        Err("wedged")
                    } else {
                        Ok(())
                    }
                })
            })
            .join()
            .unwrap()
            .map(|_| ())
            .map_err(|(_, e)| e)
    });
    assert_eq!(result, Err(RetirementWaitError::Relax("wedged")));
    drop(seat);
}

// ---------------------------------------------------------------------------
// P1-a (#707 review): a pending retirement holds its whole span, and a
// replacement publishes its new owner only on completion.
// ---------------------------------------------------------------------------

#[test]
fn a_pending_retirement_refuses_any_overlapping_install() {
    let mut table = ExtentTable::new().unwrap();
    assert!(table.install(ExtentRecord::new(
        FrameGpa::new(0x1000),
        0x2000,
        generation(1)
    )));
    let mut vcpu = table.register_vcpu(SoftTlb::new()).unwrap();
    let mut run = vcpu.run();
    run.block_entry().unwrap();
    let Retirement { pending, .. } = table.remove(FrameGpa::new(0x1000), None).unwrap().unwrap();
    let pending = pending.try_complete().expect_err("peer running, unserved");
    // Frame 0x2000 was inside the retired span: no new owner may take it.
    assert!(!table.install(ExtentRecord::new(
        FrameGpa::new(0x2000),
        0x1000,
        generation(9)
    )));
    assert!(!table.install(ExtentRecord::new(FrameGpa::new(0x0), 0x2000, generation(9))));
    // Adjacent, disjoint frames are fine.
    assert!(table.install(ExtentRecord::new(
        FrameGpa::new(0x0),
        0x1000,
        generation(10)
    )));
    run.block_entry().unwrap();
    let completion = pending.try_complete().expect("served");
    table.reclaim(&completion);
    assert!(table.install(ExtentRecord::new(
        FrameGpa::new(0x2000),
        0x1000,
        generation(9)
    )));
}

#[test]
fn a_replacement_publishes_its_new_owner_only_on_completion() {
    let mut table = table_with_extent();
    let mut vcpu = table.register_vcpu(SoftTlb::new()).unwrap();
    let mut run = vcpu.run();
    run.block_entry().unwrap();
    let Retirement { retired, pending } = table
        .replace(
            ExtentRecord::new(FrameGpa::new(EXTENT), 0x1000, generation(5)),
            None,
        )
        .unwrap()
        .unwrap();
    assert_eq!(retired.generation, generation(1));
    let pending = pending.try_complete().expect_err("peer running, unserved");
    // No owner while a peer may still translate to the old one.
    assert_eq!(table.lookup_span(EXTENT, 0x1000), None);
    // The deferred owner holds its span.
    assert!(!table.install(ExtentRecord::new(
        FrameGpa::new(EXTENT),
        0x1000,
        generation(6)
    )));
    run.block_entry().unwrap();
    let completion = pending.try_complete().expect("served");
    assert_eq!(
        table.reclaim(&completion),
        Reclaimed {
            identities: 1,
            published: 1
        }
    );
    assert_eq!(
        table
            .lookup_span(EXTENT, 0x1000)
            .map(|record| record.generation),
        Some(generation(5))
    );
}

#[test]
fn a_root_replacement_publishes_its_new_generation_only_on_completion() {
    use carrick_guest_arch::RootGpa;
    let mut table = ExtentTable::new().unwrap();
    let root = RootGpa::page_aligned(FrameGpa::new(0x1000)).unwrap();
    assert!(table.set_root_generation(root, generation(7)));
    let Retirement { retired, pending } = table
        .replace_root_generation(root, generation(8), None)
        .unwrap()
        .unwrap();
    assert_eq!(retired, generation(7));
    assert_eq!(table.expected_generation(root), None);
    let completion = pending.try_complete().expect("no CPU seated");
    table.reclaim(&completion);
    assert_eq!(table.expected_generation(root), Some(generation(8)));
}

// ---------------------------------------------------------------------------
// P2s (#707 review): dropped retirements recover, exhaustion stops CPUs.
// ---------------------------------------------------------------------------

#[test]
fn a_dropped_retirement_is_recovered_by_a_later_completion() {
    let mut table = table_with_extent();
    let dropped = table.remove(FrameGpa::new(EXTENT), None).unwrap().unwrap();
    drop(dropped);
    assert_eq!(table.pending_identities(), 1);
    assert!(!table.install(ExtentRecord::new(
        FrameGpa::new(EXTENT),
        0x1000,
        generation(2)
    )));
    let recovery = table.retire_abandoned(None).unwrap();
    let completion = recovery.try_complete().expect("no CPU seated");
    assert_eq!(table.reclaim(&completion), released(1));
    assert_eq!(table.pending_identities(), 0);
    assert!(table.install(ExtentRecord::new(
        FrameGpa::new(EXTENT),
        0x1000,
        generation(2)
    )));
}

#[test]
fn an_exhausted_inventory_stops_every_cpu_and_refuses_edits_loudly() {
    let mut table = table_with_extent();
    let mut vcpu = table.register_vcpu(SoftTlb::new()).unwrap();
    let mut run = vcpu.run();
    run.block_entry().unwrap();
    // The real exhaustion path's terminal transition (the issue counter
    // cannot be driven to u64::MAX in a test).
    table.exhaust_for_test();
    assert_eq!(run.block_entry(), Err(InventoryTerminal));
    drop(run);
    assert!(!vcpu.is_running(), "a terminal block entry parks");
    assert!(matches!(vcpu.admit(&table), Err(SoftAdmitError::Terminal)));
    assert_eq!(
        table.remove(FrameGpa::new(EXTENT), None).map(|_| ()),
        Err(ExtentEditError::Terminal)
    );
    assert!(!table.install(ExtentRecord::new(
        FrameGpa::new(0x8000),
        0x1000,
        generation(3)
    )));
}

#[test]
fn pending_extent_identities_are_refused_until_their_completion() {
    let mut table = table_with_extent();
    let Retirement { pending, .. } = table.remove(FrameGpa::new(EXTENT), None).unwrap().unwrap();
    assert_eq!(table.pending_identities(), 1);
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
    assert_eq!(table.reclaim(&completion), released(1));
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
    let mut foreign = other.register_vcpu(SoftTlb::new()).unwrap();
    assert!(!table.is_member(foreign.seat()));
    assert_eq!(
        table
            .remove(FrameGpa::new(EXTENT), Some(foreign.requester()))
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
    let mut vcpu = table.lock().unwrap().register_vcpu(SoftTlb::new()).unwrap();
    let begun = StdArc::new(StdAtomicU64::new(0));
    let completed = StdArc::new(StdAtomicU64::new(0));
    let stop = StdArc::new(core::sync::atomic::AtomicBool::new(false));

    let peer = {
        let table = StdArc::clone(&table);
        let begun = StdArc::clone(&begun);
        let completed = StdArc::clone(&completed);
        let stop = StdArc::clone(&stop);
        thread::spawn(move || {
            // While admitted, a completion after the stamp means this CPU
            // served it, so the stamped entry must be gone.
            let check_and_fill = |tlb: &mut SoftTlb, stamp: &mut Option<u64>| {
                if let Some(stamped) = *stamp
                    && completed.load(Ordering::Acquire) > stamped
                {
                    assert_eq!(cached(tlb), None, "stale entry outlived a completion");
                }
                if cached(tlb).is_none() {
                    *stamp = Some(begun.load(Ordering::Acquire));
                    cache_translation(tlb, OLD_ADDEND);
                }
            };
            let mut step = 0u64;
            while !stop.load(Ordering::Acquire) {
                step += 1;
                let mut stamp = None;
                match step % 3 {
                    0 => {
                        let mut run = vcpu.run();
                        for _ in 0..3 {
                            run.block_entry().unwrap();
                            check_and_fill(run.tlb_mut_for_test(), &mut stamp);
                        }
                    }
                    1 => {
                        let guard = table.lock().unwrap();
                        let mut admitted = vcpu.admit(&guard).unwrap();
                        drop(guard);
                        check_and_fill(admitted.tlb_mut_for_test(), &mut stamp);
                    }
                    _ => thread::yield_now(),
                }
            }
        })
    };

    for round in 0..ROUNDS {
        begun.store(round + 1, Ordering::Release);
        let Retirement { pending, .. } = remove_extent(&table);
        // Never wait while holding the table lock.
        let completion = host_wait(pending);
        completed.store(round + 1, Ordering::Release);
        let mut guard = table.lock().unwrap();
        assert_eq!(guard.reclaim(&completion), released(1));
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
/// entries of one running `SoftVcpu` (the production vCPU type, over an
/// instrumented served word), in a domain with `peers` seated members.
fn steady_state_block_entry(peers: usize) -> Work {
    let domain = SoftDomainHandle::<CountingWord>::new().unwrap();
    let mut vcpus: Vec<SoftVcpu<CountingWord>> = (0..peers)
        .map(|_| SoftVcpu::claim(&domain, SoftTlb::new()).unwrap())
        .collect();
    let mut runs: Vec<RunningSeat<'_, CountingWord>> =
        vcpus.iter_mut().map(|vcpu| vcpu.run()).collect();
    for run in &mut runs {
        run.block_entry().unwrap();
    }
    let table = domain.table_for_test();
    let flushes_before = runs[0].tlb().stats().full_flushes;
    let counter_before = table.counter().latest(Ordering::Relaxed);
    let before = member_work(table);
    for _ in 0..1000 {
        assert!(!runs[0].block_entry().unwrap());
    }
    let after = member_work(table);
    assert_eq!(table.counter().latest(Ordering::Relaxed), counter_before);
    assert_eq!(runs[0].tlb().stats().full_flushes, flushes_before);
    assert_eq!(domain.kicks(), 0);
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
        WorkMetric::InvalidationSteadyStateSharedWrites,
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
    let mut running_vcpus: Vec<SoftVcpu> = (0..peers)
        .map(|_| table.register_vcpu(SoftTlb::new()).unwrap())
        .collect();
    let mut running: Vec<RunningSeat<'_>> =
        running_vcpus.iter_mut().map(|vcpu| vcpu.run()).collect();
    for run in &mut running {
        run.block_entry().unwrap();
        cache_translation(run.tlb_mut_for_test(), OLD_ADDEND);
    }
    let mut parked = Vec::new();
    for _ in 0..peers {
        let vcpu = table.register_vcpu(SoftTlb::new()).unwrap();
        parked.push(vcpu);
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
    for run in &mut running {
        assert!(run.exit_requested());
        pending = pending
            .try_complete()
            .expect_err("a running peer is unserved");
        assert!(run.block_entry().unwrap());
        assert_eq!(cached(run.tlb()), None);
    }
    let completion = pending
        .try_complete()
        .expect("running served, parked stopped");
    table.reclaim(&completion);

    // A hit stays O(1): 1024 hits on one entry, no flush, no scan.
    let tlb = running[0].tlb_mut_for_test();
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
        (1, steady_state_block_entry(2)),
        (8, steady_state_block_entry(16)),
        (32, steady_state_block_entry(64)),
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

#[test]
fn a_copy_cannot_reuse_an_identity_whose_retirement_is_pending() {
    let mut table = table_with_extent();
    let Retirement { pending, .. } = table.remove(FrameGpa::new(EXTENT), None).unwrap().unwrap();
    // A copy would forget the pending identities: refused outright.
    assert_eq!(
        table.try_clone().map(|_| ()),
        Err(crate::walker::ExtentCloneError::Pending)
    );
    let completion = pending.try_complete().expect("no CPU seated");
    table.reclaim(&completion);
    let copy = table.try_clone().expect("nothing pending");
    // The copy is its own domain: a CPU seated here is not its member.
    let vcpu = table.register_vcpu(SoftTlb::new()).unwrap();
    assert!(table.is_member(vcpu.seat()));
    assert!(!copy.is_member(vcpu.seat()));
}

// ---------------------------------------------------------------------------
// #707 director finding: a removal must not lose to a deferred publication,
// and a terminal inventory publishes nothing.
// ---------------------------------------------------------------------------

#[test]
fn removing_an_extent_whose_replacement_is_deferred_is_refused() {
    let mut table = table_with_extent();
    let Retirement { pending, .. } = table
        .replace(
            ExtentRecord::new(FrameGpa::new(EXTENT), 0x1000, generation(5)),
            None,
        )
        .unwrap()
        .unwrap();
    // The new owner is not live yet: there is nothing to retire, and a
    // silent `Ok(None)` would let the reclaim below bring it back.
    assert_eq!(
        table.remove(FrameGpa::new(EXTENT), None).map(|_| ()),
        Err(ExtentEditError::PublicationPending)
    );
    let completion = pending.try_complete().expect("no CPU seated");
    table.reclaim(&completion);
    // After the publication lands, removal retires it normally.
    let Retirement { retired, pending } =
        table.remove(FrameGpa::new(EXTENT), None).unwrap().unwrap();
    assert_eq!(retired.generation, generation(5));
    let completion = pending.try_complete().expect("no CPU seated");
    table.reclaim(&completion);
    assert_eq!(
        table.lookup_span(EXTENT, 0x1000),
        None,
        "the removed owner stays gone"
    );
}

#[test]
fn removing_a_root_whose_replacement_is_deferred_is_refused() {
    use carrick_guest_arch::RootGpa;
    let mut table = ExtentTable::new().unwrap();
    let root = RootGpa::page_aligned(FrameGpa::new(0x1000)).unwrap();
    assert!(table.set_root_generation(root, generation(7)));
    let Retirement { pending, .. } = table
        .replace_root_generation(root, generation(8), None)
        .unwrap()
        .unwrap();
    assert_eq!(
        table.remove_root_generation(root, None).map(|_| ()),
        Err(ExtentEditError::PublicationPending)
    );
    let completion = pending.try_complete().expect("no CPU seated");
    table.reclaim(&completion);
    let Retirement { retired, pending } =
        table.remove_root_generation(root, None).unwrap().unwrap();
    assert_eq!(retired, generation(8));
    let completion = pending.try_complete().expect("no CPU seated");
    table.reclaim(&completion);
    assert_eq!(
        table.expected_generation(root),
        None,
        "the removed root stays gone"
    );
}

#[test]
fn a_terminal_inventory_publishes_no_deferred_owner() {
    let mut table = table_with_extent();
    let Retirement { pending, .. } = table
        .replace(
            ExtentRecord::new(FrameGpa::new(EXTENT), 0x1000, generation(5)),
            None,
        )
        .unwrap()
        .unwrap();
    let completion = pending.try_complete().expect("no CPU seated");
    table.exhaust_for_test();
    assert_eq!(table.reclaim(&completion).published, 0);
    assert_eq!(
        table.lookup_span(EXTENT, 0x1000),
        None,
        "nothing goes live once terminal"
    );
}

// ---------------------------------------------------------------------------
// #707 round-1 review witnesses: deferred publication vs later retirement,
// cross-domain extent/root reservation, exit flag clearing across park/reenter
// and inline requester serve and seat reuse, and wait(Some) validation.
// ---------------------------------------------------------------------------

#[test]
fn an_earlier_replacement_cannot_publish_a_generation_a_later_retirement_still_holds() {
    let mut table = ExtentTable::new().unwrap();
    assert!(table.install(ExtentRecord::new(
        FrameGpa::new(0x1000),
        0x1000,
        generation(1)
    )));
    assert!(table.install(ExtentRecord::new(
        FrameGpa::new(0x3000),
        0x1000,
        generation(2)
    )));

    // R1 replaces E1(0x1000, gen1) with (0x1000, gen2) while no CPU is seated.
    let r1 = table
        .replace(
            ExtentRecord::new(FrameGpa::new(0x1000), 0x1000, generation(2)),
            None,
        )
        .unwrap()
        .unwrap();

    // Now CPU1 claims a seat, enters, and caches a translation under gen2.
    let mut vcpu = table.register_vcpu(SoftTlb::new()).unwrap();
    let mut run = vcpu.run();
    run.block_entry().unwrap();
    cache_translation(run.tlb_mut_for_test(), OLD_ADDEND);

    // R2 removes E2(0x3000, gen2), counting running CPU1.
    let r2 = table.remove(FrameGpa::new(0x3000), None).unwrap().unwrap();
    assert!(r2.pending.counts(run.seat().cpu()));

    // R1 counted nobody, so its completion is immediate. Reclaiming R1 must
    // NOT publish (0x1000, gen2) while R2's retirement of gen2 is still pending.
    let c1 = r1.pending.try_complete().expect("R1 counted no seated CPU");
    let reclaimed1 = table.reclaim(&c1);
    assert_eq!(
        reclaimed1,
        Reclaimed {
            identities: 1,
            published: 0,
        },
        "gen1 is released, but gen2 cannot be published while R2 holds gen2 retired"
    );
    assert_eq!(
        table.lookup_span(0x1000, 0x1000),
        None,
        "gen2 must not go live at 0x1000 before R2 completes"
    );
    assert!(
        !table.install(ExtentRecord::new(
            FrameGpa::new(0x1000),
            0x1000,
            generation(9)
        )),
        "0x1000 stays reserved by the held-back replacement"
    );

    // CPU1 reaches its next safe point, serving R2; reclaiming R2 releases gen2
    // and publishes the held-back (0x1000, gen2) replacement.
    assert!(run.block_entry().unwrap());
    let c2 = r2.pending.try_complete().expect("CPU1 served R2");
    let reclaimed2 = table.reclaim(&c2);
    assert_eq!(
        reclaimed2,
        Reclaimed {
            identities: 1,
            published: 1,
        }
    );
    assert_eq!(
        table.lookup_span(0x1000, 0x1000),
        Some(ExtentRecord::new(
            FrameGpa::new(0x1000),
            0x1000,
            generation(2)
        ))
    );

    // Same-generation replacement publishes immediately when its own retirement
    // completes and no later retirement holds that generation.
    drop(run);
    let r_same = table
        .replace(
            ExtentRecord::new(FrameGpa::new(0x1000), 0x2000, generation(2)),
            None,
        )
        .unwrap()
        .unwrap();
    let c_same = r_same.pending.try_complete().expect("CPU1 parked");
    assert_eq!(
        table.reclaim(&c_same),
        Reclaimed {
            identities: 1,
            published: 1,
        }
    );
    assert_eq!(
        table.lookup_span(0x1000, 0x2000),
        Some(ExtentRecord::new(
            FrameGpa::new(0x1000),
            0x2000,
            generation(2)
        ))
    );
}

#[test]
fn retired_extent_and_root_generations_are_mutually_reserved_until_completion() {
    use carrick_guest_arch::RootGpa;
    let mut table = ExtentTable::new().unwrap();
    let root_in_span = RootGpa::page_aligned(FrameGpa::new(0x2000)).unwrap();
    let root_other = RootGpa::page_aligned(FrameGpa::new(0x5000)).unwrap();
    assert!(table.install(ExtentRecord::new(
        FrameGpa::new(0x1000),
        0x2000,
        generation(1)
    )));
    let r_ext = table.remove(FrameGpa::new(0x1000), None).unwrap().unwrap();
    assert!(
        !table.set_root_generation(root_in_span, generation(9)),
        "root inside retiring extent span is refused"
    );
    assert!(
        !table.set_root_generation(root_other, generation(1)),
        "root reusing retiring extent OwnerGeneration is refused"
    );
    let c_ext = r_ext.pending.try_complete().unwrap();
    table.reclaim(&c_ext);

    assert!(table.set_root_generation(root_other, generation(2)));
    let r_root = table
        .remove_root_generation(root_other, None)
        .unwrap()
        .unwrap();
    assert!(
        !table.install(ExtentRecord::new(
            FrameGpa::new(0x4000),
            0x2000,
            generation(9)
        )),
        "extent overlapping retiring root frame is refused"
    );
    assert!(
        !table.install(ExtentRecord::new(
            FrameGpa::new(0x8000),
            0x1000,
            generation(2)
        )),
        "extent reusing retiring root OwnerGeneration is refused"
    );
    let c_root = r_root.pending.try_complete().unwrap();
    table.reclaim(&c_root);
    assert!(table.install(ExtentRecord::new(
        FrameGpa::new(0x8000),
        0x1000,
        generation(2)
    )));
}

#[test]
fn kicked_seat_clears_exit_on_park_reenter_inline_requester_and_reclaim() {
    let mut table = table_with_extent();
    let mut vcpu = table.register_vcpu(SoftTlb::new()).unwrap();

    // 1. Kick while running, then park by dropping RunningSeat; re-entering
    // serves the debt via enter() and must clear exit_requested.
    let pending = {
        let mut run = vcpu.run();
        run.block_entry().unwrap();
        let retired = table.remove(FrameGpa::new(EXTENT), None).unwrap().unwrap();
        assert!(run.exit_requested());
        retired.pending
    };
    let completion = pending.try_complete().unwrap();
    table.reclaim(&completion);
    {
        let mut run = vcpu.run();
        assert!(run.block_entry().unwrap());
        assert!(
            !run.exit_requested(),
            "serving debt on re-entry must clear the exit flag"
        );
        // A later kick while running remains observable.
        assert!(table.install(ExtentRecord::new(
            FrameGpa::new(EXTENT),
            0x1000,
            generation(2)
        )));
        let retired2 = table.remove(FrameGpa::new(EXTENT), None).unwrap().unwrap();
        assert!(run.exit_requested(), "later kick stays observable");
        let c2 = retired2
            .pending
            .wait(Some(run.requester()), bounded())
            .map_err(|(_, e)| e)
            .unwrap();
        table.reclaim(&c2);
        // 2. Inline requester serve in wait() must also clear exit_requested.
        assert!(
            !run.exit_requested(),
            "inline requester serve in wait must clear exit_requested"
        );
    }

    // 3. Dropping a kicked seat and claiming the slot for a new seat must not
    // leak exit_requested = true to the new claimant.
    assert!(table.install(ExtentRecord::new(
        FrameGpa::new(EXTENT),
        0x1000,
        generation(3)
    )));
    let r3 = {
        let mut run = vcpu.run();
        run.block_entry().unwrap();
        let r3 = table.remove(FrameGpa::new(EXTENT), None).unwrap().unwrap();
        assert!(run.exit_requested());
        r3
    };
    drop(vcpu);
    let c3 = r3.pending.try_complete().unwrap();
    table.reclaim(&c3);
    let fresh_vcpu = table.register_vcpu(SoftTlb::new()).unwrap();
    assert!(
        !fresh_vcpu.exit_requested(),
        "a newly claimed seat must not inherit a prior occupant's exit flag"
    );
}

#[test]
fn wait_with_another_same_thread_seat_or_foreign_requester_is_refused() {
    let mut table = table_with_extent();
    let mut vcpu0 = table.register_vcpu(SoftTlb::new()).unwrap();
    let mut vcpu1 = table.register_vcpu(SoftTlb::new()).unwrap();
    let mut run0 = vcpu0.run();
    let mut run1 = vcpu1.run();
    run0.block_entry().unwrap();
    run1.block_entry().unwrap();

    let Retirement { pending, .. } = table.remove(FrameGpa::new(EXTENT), None).unwrap().unwrap();
    // Passing vcpu1 as requester while vcpu0 is also counted and running on
    // the current thread would wait on vcpu0 forever; must refuse with SelfWait.
    let (pending, err) = pending
        .wait(Some(run1.requester()), || -> Result<(), &'static str> {
            panic!("relax must not be called on a self-wait")
        })
        .expect_err("another counted seat on this thread must refuse with SelfWait");
    assert_eq!(err, RetirementWaitError::SelfWait);

    // Passing a foreign seat to wait(Some) must also refuse without touching its TLB.
    let other_table = ExtentTable::new().unwrap();
    let mut foreign_vcpu = other_table.register_vcpu(SoftTlb::new()).unwrap();
    cache_translation(foreign_vcpu.tlb_mut_for_test(), OLD_ADDEND);
    let (pending, err) = pending
        .wait(
            Some(foreign_vcpu.requester()),
            || -> Result<(), &'static str> { panic!("relax must not be called on foreign seat") },
        )
        .expect_err("foreign requester must be refused");
    assert_eq!(err, RetirementWaitError::ForeignRequester);
    assert!(
        cached(foreign_vcpu.tlb()).is_some(),
        "foreign TLB untouched"
    );

    drop(run0);
    drop(run1);
    let completion = pending.try_complete().unwrap();
    table.reclaim(&completion);
}
