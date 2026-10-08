#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use carrick_core::lifecycle::{AtomicEntry, Lifecycle, pack};
use carrick_core_abi::{EntryMmKey, EntryState, GateState, ThreadLedgerActivity, TransitionError};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// Native storage bindings expose the same neutral cells. Context bytes and
// Linux sidecars are deliberately absent from this publication owner witness.
struct NativePool {
    mm: EntryMmKey,
    gate: AtomicU32,
    live: AtomicU32,
    cells: [AtomicEntry; 8],
    ledger: ThreadLedgerActivity,
    visits: AtomicU64,
}
impl NativePool {
    fn new(mm: u64) -> Self {
        Self {
            mm: EntryMmKey::from_raw(mm),
            gate: AtomicU32::new(0),
            live: AtomicU32::new(1),
            cells: std::array::from_fn(|_| AtomicEntry::new(pack(0, EntryState::Vacant))),
            ledger: ThreadLedgerActivity::new(),
            visits: AtomicU64::new(0),
        }
    }
}
impl Lifecycle for NativePool {
    fn gate_word(&self) -> &AtomicU32 {
        &self.gate
    }
    fn live_word(&self) -> &AtomicU32 {
        &self.live
    }
    fn entry_count(&self) -> usize {
        self.cells.len()
    }
    fn entry_word(&self, index: usize) -> Option<&AtomicEntry> {
        self.visits.fetch_add(1, Ordering::Relaxed);
        self.cells.get(index)
    }
    fn activity(&self) -> Option<&ThreadLedgerActivity> {
        Some(&self.ledger)
    }
}

#[test]
fn x5_lifecycle_publication() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let registry = carrick_conformance_contract::ContractRegistry::load(root).unwrap();
    let contract = registry.require("core.lifecycle.publication").unwrap();
    let mut observations = Vec::new();
    {
        for births in [16, 64, 256] {
            let mut visits = 0;
            let a = NativePool::new(7);
            let b = NativePool::new(8);
            assert_ne!(a.mm, b.mm);
            let mut predecessor = None;
            for _ in 0..births {
                let entry = a.reserve_stock(0).unwrap();
                a.transition(
                    entry,
                    &[EntryState::Stocking],
                    EntryState::Reserved,
                    Ordering::Release,
                )
                .unwrap();
                if let Some(old) = predecessor {
                    assert_eq!(a.claim(old).unwrap_err(), TransitionError::StaleGeneration);
                }
                a.visits.store(0, Ordering::Relaxed);
                let claim = a.claim(entry).unwrap();
                a.thread_born().unwrap();
                a.complete_birth(claim).unwrap();
                let exit = a.begin_exit(entry).unwrap();
                a.publish(entry).unwrap(); // exact publish-vs-exit race
                drop(exit); // restores Published, never stale Born
                assert_eq!(
                    a.state(0),
                    Some((entry.generation(), EntryState::Published))
                );
                let exit = a.begin_exit(entry).unwrap();
                a.release_live(1).unwrap();
                exit.commit().unwrap();
                a.reap(entry).unwrap();
                assert_eq!(
                    a.visits.load(Ordering::Relaxed),
                    13,
                    "constant work: {births}"
                );
                visits += a.visits.load(Ordering::Relaxed);
                assert_eq!(a.state(0), Some((entry.generation(), EntryState::Reaped)));
                assert_eq!(a.live(), 1);
                assert_eq!(a.ledger.pending(), 2);
                a.ledger.complete(2).unwrap();
                assert_eq!(b.state(0), Some((0, EntryState::Vacant)));
                assert_eq!(b.live(), 1);
                assert_eq!(b.ledger.pending(), 0);
                predecessor = Some(entry);
            }
            let reserved = a.reserve_stock(1).unwrap();
            a.transition(
                reserved,
                &[EntryState::Stocking],
                EntryState::Reserved,
                Ordering::Release,
            )
            .unwrap();
            a.close_for_fork().unwrap();
            assert_eq!(
                a.claim(reserved).unwrap_err(),
                TransitionError::GateClosed(GateState::ForkClosing)
            );
            assert_eq!(a.claimed_count(), 0);
            a.reopen_after_fork().unwrap();
            let claim = a.claim(reserved).unwrap();
            a.unclaim(claim).unwrap();
            a.revoke(reserved).unwrap();
            assert_eq!(
                a.claim(reserved).unwrap_err(),
                TransitionError::WrongState(EntryState::Revoked)
            );
            assert_eq!(b.gate(), GateState::Open);
            use carrick_conformance_contract::*;
            let mut work = WorkSnapshot::new();
            work.insert(WorkMetric::LifecycleEntryVisits, visits)
                .unwrap();
            observations.push(ContractObservation {
                contract_id: contract.id.clone(),
                layer: ExecutionLayer::VmFree,
                implementation_revision: "order6-production-lifecycle".into(),
                fixture_identity: contract.fixture.clone(),
                scale: births,
                semantic_assertions: vec![SemanticAssertion::pass(
                    "publish-race rollback, exact reuse and peer isolation",
                )],
                work: Some(work),
                timing: None,
                completeness: Completeness::Complete,
            });
        }
    }
    carrick_conformance_contract::evaluate(contract, &observations).unwrap();
}
