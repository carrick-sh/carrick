use super::*;
use crate::{
    Access, CpuAccessMode, ExtentRecord, ExtentTable, FrameGpa, GuestVa, OwnerGeneration,
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
        registration.leave_idle();
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
    registration.leave_idle();
}

#[test]
fn parked_peer_does_not_hold_retirement_barrier() {
    let mut table = table_with_extent();
    let registration = table.register_vcpu(Arc::new(|| panic!("parked peer was kicked")));
    let mut tlb = SoftTlb::new();
    cache_old_translation(&mut tlb);
    registration.enter_running(&mut tlb);
    registration.leave_parked();

    table.remove(FrameGpa::new(0x1000)).unwrap().complete();
    assert_eq!(table.shootdown_stats().kicks, 0);
    registration.enter_running(&mut tlb);
    assert_eq!(
        tlb.probe_readonly(VA, 1, Access::Read, CpuAccessMode::ring3()),
        None
    );
    registration.leave_idle();
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
            peers.push((registration, tlb));
        }

        let pending = table.remove(FrameGpa::new(0x1000)).unwrap();
        for (registration, tlb) in &mut peers {
            registration.synchronize(tlb);
            registration.leave_idle();
        }
        pending.complete();
        let stats = table.shootdown_stats();
        assert_eq!(stats.peer_visits, peer_count);
        assert_eq!(stats.kicks, peer_count);
        assert_eq!(kicks.load(Ordering::Relaxed), peer_count);

        let (_, tlb) = &mut peers[0];
        tlb.reset_stats();
        for _ in 0..SOFT_TLB_ENTRIES {
            let _ = tlb.probe(VA, 1, Access::Read, CpuAccessMode::ring3());
        }
        assert_eq!(tlb.stats().full_flushes, 0);
    }
}
