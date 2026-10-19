use super::*;
use crate::{
    Access, CpuAccessMode, ExtentRecord, ExtentTable, FrameGpa, GuestVa, OwnerGeneration, RootGpa,
    SOFT_TLB_ENTRIES, SoftTlbEntry,
};
use std::sync::mpsc;
use std::thread;

const VA: GuestVa = GuestVa::new(0x4000);
const OLD_ADDEND: u64 = 0x1000;

fn cache_old_translation(tlb: &mut SoftTlb) {
    let index = SoftTlb::index_for(VA);
    tlb.read.entries[index] = SoftTlbEntry {
        tag: SoftTlb::tag_for(VA, CpuAccessMode::ring3()),
        addend: OLD_ADDEND,
    };
}

fn table_with_extent() -> ExtentTable {
    let mut table = ExtentTable::new();
    assert!(table.install(ExtentRecord::new(
        FrameGpa::new(0x1000),
        0x1000,
        OwnerGeneration::new(1),
    )));
    table
}

#[test]
fn running_peer_cannot_use_stale_addend_after_retirement_completes() {
    let table = Arc::new(Mutex::new(table_with_extent()));
    let (kick_tx, kick_rx) = mpsc::channel();
    let registration = table
        .lock()
        .unwrap()
        .register_vcpu(Arc::new(move || kick_tx.send(()).unwrap()));
    let (ready_tx, ready_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();

    let peer = thread::spawn(move || {
        let mut tlb = SoftTlb::new();
        cache_old_translation(&mut tlb);
        registration.enter_running(&mut tlb);
        ready_tx.send(()).unwrap();
        kick_rx.recv().unwrap();
        registration.synchronize(&mut tlb);
        result_tx
            .send(tlb.probe_readonly(VA, 1, Access::Read, CpuAccessMode::ring3()))
            .unwrap();
        registration.leave_idle(&mut tlb);
    });

    ready_rx.recv().unwrap();
    let pending = table.lock().unwrap().remove(FrameGpa::new(0x1000)).unwrap();
    let retired = pending.complete();
    assert_eq!(retired.generation, OwnerGeneration::new(1));
    assert_eq!(result_rx.recv().unwrap(), None);
    peer.join().unwrap();
}

#[test]
fn idle_peer_resynchronizes_before_resume_lookup() {
    let mut table = table_with_extent();
    let registration = table.register_vcpu(Arc::new(|| {}));
    let mut tlb = SoftTlb::new();
    cache_old_translation(&mut tlb);

    table.remove(FrameGpa::new(0x1000)).unwrap().complete();
    registration.enter_running(&mut tlb);
    assert_eq!(
        tlb.probe_readonly(VA, 1, Access::Read, CpuAccessMode::ring3()),
        None
    );
    registration.leave_idle(&mut tlb);
}

#[test]
fn parked_peer_does_not_hold_retirement_barrier() {
    let mut table = table_with_extent();
    let registration = table.register_vcpu(Arc::new(|| panic!("parked peer was kicked")));
    let mut tlb = SoftTlb::new();
    cache_old_translation(&mut tlb);
    registration.enter_running(&mut tlb);
    registration.leave_parked(&mut tlb);

    table.remove(FrameGpa::new(0x1000)).unwrap().complete();
    assert_eq!(table.shootdown_stats().kicks, 0);
    registration.enter_running(&mut tlb);
    assert_eq!(
        tlb.probe_readonly(VA, 1, Access::Read, CpuAccessMode::ring3()),
        None
    );
    registration.leave_idle(&mut tlb);
}

#[test]
fn retirement_work_is_linear_in_peers_and_hits_do_not_scan_entries() {
    for peer_count in [1_u64, 8, 32] {
        let mut table = table_with_extent();
        let kicks = Arc::new(AtomicU64::new(0));
        let mut peers = Vec::new();
        for _ in 0..peer_count {
            let counter = Arc::clone(&kicks);
            let registration = table.register_vcpu(Arc::new(move || {
                counter.fetch_add(1, Ordering::Relaxed);
            }));
            let mut tlb = SoftTlb::new();
            registration.enter_running(&mut tlb);
            cache_old_translation(&mut tlb);
            peers.push((registration, tlb));
        }

        let pending = table.remove(FrameGpa::new(0x1000)).unwrap();
        for (registration, tlb) in &mut peers {
            registration.synchronize(tlb);
            registration.leave_idle(tlb);
        }
        pending.complete();
        let stats = table.shootdown_stats();
        assert_eq!(stats.peer_visits, peer_count);
        assert_eq!(stats.kicks, peer_count);
        assert_eq!(kicks.load(Ordering::Relaxed), peer_count);

        let (_, tlb) = &mut peers[0];
        cache_old_translation(tlb);
        tlb.reset_stats();
        let locks_before = table.shootdown_stats().stale_epoch_lock_acquisitions;
        for _ in 0..SOFT_TLB_ENTRIES {
            let _ = tlb.probe(VA, 1, Access::Read, CpuAccessMode::ring3());
        }
        assert_eq!(tlb.stats().hits, SOFT_TLB_ENTRIES as u64);
        assert_eq!(tlb.stats().misses, 0);
        assert_eq!(tlb.stats().full_flushes, 0);
        assert_eq!(
            table.shootdown_stats().stale_epoch_lock_acquisitions,
            locks_before
        );
    }
}

fn resume_race_acknowledges_retirement(initial: VcpuShootdownState) {
    let table = Arc::new(Mutex::new(table_with_extent()));
    let (kick_tx, kick_rx) = mpsc::channel();
    let registration = table
        .lock()
        .unwrap()
        .register_vcpu(Arc::new(move || kick_tx.send(()).unwrap()));
    let mut tlb = SoftTlb::new();
    registration.enter_running(&mut tlb);
    match initial {
        VcpuShootdownState::Idle => registration.leave_idle(&mut tlb),
        VcpuShootdownState::Parked => registration.leave_parked(&mut tlb),
        VcpuShootdownState::Running => unreachable!(),
    }
    cache_old_translation(&mut tlb);
    let (published_tx, published_rx) = mpsc::channel();

    thread::scope(|scope| {
        scope.spawn(move || {
            registration.enter_running_with_hook(&mut tlb, || {
                published_tx.send(()).unwrap();
                kick_rx.recv().unwrap();
            });
            assert_eq!(
                tlb.probe_readonly(VA, 1, Access::Read, CpuAccessMode::ring3()),
                None
            );
            registration.leave_idle(&mut tlb);
        });
        published_rx.recv().unwrap();
        let pending = table.lock().unwrap().remove(FrameGpa::new(0x1000)).unwrap();
        pending.complete();
    });
}

#[test]
fn idle_to_running_race_acknowledges_the_admitted_epoch() {
    resume_race_acknowledges_retirement(VcpuShootdownState::Idle);
}

#[test]
fn parked_to_running_race_acknowledges_the_admitted_epoch() {
    resume_race_acknowledges_retirement(VcpuShootdownState::Parked);
}

#[test]
fn pending_extent_identity_cannot_be_reused_until_completion() {
    let mut table = table_with_extent();
    let pending = table.remove(FrameGpa::new(0x1000)).unwrap();
    assert!(!table.install(ExtentRecord::new(
        FrameGpa::new(0x1000),
        0x1000,
        OwnerGeneration::new(2),
    )));
    assert!(!table.install(ExtentRecord::new(
        FrameGpa::new(0x2000),
        0x1000,
        OwnerGeneration::new(1),
    )));
    pending.complete();
    assert!(table.install(ExtentRecord::new(
        FrameGpa::new(0x1000),
        0x1000,
        OwnerGeneration::new(2),
    )));
}

#[test]
#[should_panic(expected = "pending shootdown dropped without complete()")]
fn dropping_pending_retirement_is_fatal() {
    let mut table = table_with_extent();
    let _pending = table.remove(FrameGpa::new(0x1000)).unwrap();
}

#[test]
fn pending_root_and_generation_cannot_be_reused_until_completion() {
    let mut table = ExtentTable::new();
    let root = RootGpa::page_aligned(FrameGpa::new(0x1000)).unwrap();
    let other = RootGpa::page_aligned(FrameGpa::new(0x2000)).unwrap();
    let generation = OwnerGeneration::new(7);
    assert!(table.set_root_generation(root, generation));
    let pending = table.remove_root_generation(root);
    assert!(!table.set_root_generation(root, OwnerGeneration::new(8)));
    assert!(!table.set_root_generation(other, generation));
    pending.complete();
    assert!(table.set_root_generation(root, OwnerGeneration::new(8)));
}
