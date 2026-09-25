#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use std::boxed::Box;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::vec::Vec;

struct HostWait;

impl LockWait for HostWait {
    fn wait(&self, attempt: u32) -> bool {
        if attempt > 64 {
            std::thread::yield_now();
        } else {
            core::hint::spin_loop();
        }
        true
    }
}

/// A zeroed zone on the heap: all-zero is the valid empty state, exactly as
/// the host maps it in the EL1 region.
fn zone() -> Box<ZoneTables> {
    let layout = std::alloc::Layout::new::<ZoneTables>();
    // SAFETY: ZoneTables is atomics and plain data; all-zero is valid.
    unsafe {
        let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables>();
        assert!(!ptr.is_null());
        Box::from_raw(ptr)
    }
}

const MM: u64 = 7;
const SLOT: SlotId = SlotId::new(3);

fn identity(tid: u64) -> ThreadIdentity {
    ThreadIdentity {
        tid,
        serial: tid * 10,
        mm: MM,
        file_table: 99,
        generation: 1,
    }
}

/// Park thread `tid` on `uaddr` the way both venues do: lock, (value checked
/// by the caller), write the context, queue, publish, unlock.
fn park(zone: &ZoneTables, tid: u64, uaddr: u64) -> RecordId {
    let guard = zone
        .lock(ZoneTables::bucket_of(MM, uaddr), &HostWait)
        .unwrap();
    let record = zone.alloc_record(identity(tid)).unwrap();
    // SAFETY: freshly allocated; this party owns it until publish_park.
    unsafe { zone.record(record).ctx_mut().x[0] = uaddr };
    let seq = zone.next_seq(record);
    zone.enqueue(&guard, record, seq, MM, uaddr, u32::MAX, 0)
        .unwrap();
    zone.publish_park(record, seq);
    record
}

fn wake(
    zone: &ZoneTables,
    uaddr: u64,
    count: u32,
    waker: Waker,
) -> Result<Vec<RecordId>, WakeRefusal> {
    let guard = zone
        .lock(ZoneTables::bucket_of(MM, uaddr), &HostWait)
        .unwrap();
    let mut woken = [RecordId::PLACEHOLDER; 16];
    let n = zone.wake(&guard, MM, uaddr, u32::MAX, count, waker, &mut woken)?;
    Ok(woken[..n as usize].to_vec())
}

#[test]
fn claim_word_round_trips() {
    for claim in [
        Claim::Free,
        Claim::Parked { seq: 9 },
        Claim::Queued {
            slot: SlotId::new(255),
            seq: u32::MAX,
        },
        Claim::OnCpu {
            slot: SlotId::new(1),
            seq: 2,
        },
        Claim::Host { seq: 77 },
    ] {
        assert_eq!(Claim::decode(claim.encode()), claim);
    }
}

#[test]
fn wake_is_fifo_and_counts_only_waiters_on_the_address() {
    let zone = zone();
    let a = park(&zone, 1, 0x1000);
    let b = park(&zone, 2, 0x1000);
    let _other = park(&zone, 3, 0x2000);
    let woken = wake(&zone, 0x1000, 1, Waker::Host).unwrap();
    assert_eq!(woken, [a]);
    assert_eq!(zone.record(a).claim(), Claim::Host { seq: 1 });
    assert_eq!(zone.record(a).handback(), Some(Handback::Woken));
    let woken = wake(&zone, 0x1000, 5, Waker::Host).unwrap();
    assert_eq!(woken, [b]);
    assert!(wake(&zone, 0x1000, 5, Waker::Host).unwrap().is_empty());
}

#[test]
fn bitsets_select_waiters() {
    let zone = zone();
    let guard = zone
        .lock(ZoneTables::bucket_of(MM, 0x40), &HostWait)
        .unwrap();
    let record = zone.alloc_record(identity(1)).unwrap();
    let seq = zone.next_seq(record);
    zone.enqueue(&guard, record, seq, MM, 0x40, 0b10, 0)
        .unwrap();
    zone.publish_park(record, seq);
    let mut woken = [RecordId::PLACEHOLDER; 4];
    assert_eq!(
        zone.wake(&guard, MM, 0x40, 0b01, 1, Waker::Host, &mut woken),
        Ok(0)
    );
    assert_eq!(
        zone.wake(&guard, MM, 0x40, 0b10, 1, Waker::Host, &mut woken),
        Ok(1)
    );
}

#[test]
fn el1_wake_queues_on_the_slot_and_switch_in_takes_it() {
    let zone = zone();
    let a = park(&zone, 1, 0x1000);
    let woken = wake(&zone, 0x1000, 1, Waker::El1 { slot: SLOT }).unwrap();
    assert_eq!(woken, [a]);
    assert_eq!(zone.record(a).claim(), Claim::Queued { slot: SLOT, seq: 1 });
    assert_eq!(zone.slot(SLOT).queued(), 1);
    assert_eq!(zone.switch_in(SLOT), Some(a));
    assert_eq!(zone.record(a).claim(), Claim::OnCpu { slot: SLOT, seq: 1 });
    assert_eq!(zone.slot(SLOT).current(), Some(a));
    assert_eq!(zone.slot(SLOT).queued(), 0);
    assert_eq!(zone.switch_in(SLOT), None);
}

#[test]
fn el1_refuses_multi_entry_waiters_and_a_full_run_queue() {
    let zone = zone();
    // A waitv-style park on two futexes.
    let record = zone.alloc_record(identity(1)).unwrap();
    let seq = zone.next_seq(record);
    for (index, uaddr) in [(0u32, 0x10u64), (1, 0x20)] {
        let guard = zone
            .lock(ZoneTables::bucket_of(MM, uaddr), &HostWait)
            .unwrap();
        zone.enqueue(&guard, record, seq, MM, uaddr, u32::MAX, index)
            .unwrap();
    }
    zone.publish_park(record, seq);
    assert_eq!(
        wake(&zone, 0x20, 1, Waker::El1 { slot: SLOT }),
        Err(WakeRefusal::MultiEntry)
    );
    assert_eq!(zone.record(record).claim(), Claim::Parked { seq });
    // The host wakes it through either futex; its result is that index, and
    // unlink_all removes the other entry.
    assert_eq!(wake(&zone, 0x20, 1, Waker::Host).unwrap(), [record]);
    assert_eq!(zone.record(record).result(), 1);
    zone.unlink_all(record, &HostWait);
    assert_eq!(zone.record(record).entry_count(), 0);
    assert!(wake(&zone, 0x10, 1, Waker::Host).unwrap().is_empty());

    let parked: Vec<_> = (0..ZONE_RUNQ_CAPACITY as u64 + 1)
        .map(|tid| park(&zone, 100 + tid, 0x3000))
        .collect();
    assert_eq!(
        wake(&zone, 0x3000, u32::MAX, Waker::El1 { slot: SLOT }),
        Err(WakeRefusal::RunQueueFull)
    );
    assert!(
        parked
            .iter()
            .all(|r| matches!(zone.record(*r).claim(), Claim::Parked { .. }))
    );
}

/// futexforkwakegroups / LTP futex_wake02: `FUTEX_WAKE(9)` with nine or more
/// waiters must wake nine. EL1's buffer is the run queue's capacity (8), so
/// it must refuse rather than return a short count (it returned 8, leaving a
/// waiter asleep until a later wake).
#[test]
fn el1_wake_beyond_run_queue_capacity_refuses_instead_of_waking_fewer() {
    let zone = zone();
    let parked: Vec<_> = (0..ZONE_RUNQ_CAPACITY as u64 + 2)
        .map(|tid| park(&zone, 200 + tid, 0x5000))
        .collect();
    let guard = zone
        .lock(ZoneTables::bucket_of(MM, 0x5000), &HostWait)
        .unwrap();
    let mut woken = [RecordId::PLACEHOLDER; ZONE_RUNQ_CAPACITY];
    let count = ZONE_RUNQ_CAPACITY as u32 + 1;
    assert_eq!(
        zone.wake(
            &guard,
            MM,
            0x5000,
            u32::MAX,
            count,
            Waker::El1 { slot: SLOT },
            &mut woken
        ),
        Err(WakeRefusal::RunQueueFull)
    );
    assert!(
        parked
            .iter()
            .all(|r| matches!(zone.record(*r).claim(), Claim::Parked { .. }))
    );
    // Exactly the capacity is still served in-guest.
    assert_eq!(
        zone.wake(
            &guard,
            MM,
            0x5000,
            u32::MAX,
            ZONE_RUNQ_CAPACITY as u32,
            Waker::El1 { slot: SLOT },
            &mut woken
        ),
        Ok(ZONE_RUNQ_CAPACITY as u32)
    );
    // The host takes batches of its buffer and its caller loops.
    let mut small = [RecordId::PLACEHOLDER; 1];
    assert_eq!(
        zone.wake(&guard, MM, 0x5000, u32::MAX, 5, Waker::Host, &mut small),
        Ok(1)
    );
}

#[test]
fn host_claims_parked_but_is_refused_by_el1_held() {
    let zone = zone();
    let a = park(&zone, 1, 0x1000);
    let r = zone.record_ref(a);
    assert_eq!(
        zone.claim_for_host(r, None, Handback::Signal, &HostWait),
        HostClaim::Claimed
    );
    assert_eq!(zone.record(a).handback(), Some(Handback::Signal));
    assert_eq!(zone.record(a).entry_count(), 0);
    // Claimed records are no longer wakeable.
    assert!(wake(&zone, 0x1000, 1, Waker::Host).unwrap().is_empty());
    assert_eq!(
        zone.claim_for_host(r, None, Handback::Control, &HostWait),
        HostClaim::AlreadyHost
    );

    let b = park(&zone, 2, 0x1000);
    let _ = wake(&zone, 0x1000, 1, Waker::El1 { slot: SLOT }).unwrap();
    assert_eq!(
        zone.claim_for_host(zone.record_ref(b), None, Handback::Signal, &HostWait),
        HostClaim::El1Held { slot: SLOT }
    );
}

#[test]
fn a_timeout_claims_only_the_park_that_armed_it() {
    let zone = zone();
    let a = park(&zone, 1, 0x1000);
    let r = zone.record_ref(a);
    let armed = zone.record(a).claim().seq();
    // EL1 wakes it, runs it, and it parks again (a later park, untimed).
    let _ = wake(&zone, 0x1000, 1, Waker::El1 { slot: SLOT }).unwrap();
    assert_eq!(zone.switch_in(SLOT), Some(a));
    let guard = zone
        .lock(ZoneTables::bucket_of(MM, 0x1000), &HostWait)
        .unwrap();
    let seq = zone.next_seq(a);
    zone.enqueue(&guard, a, seq, MM, 0x1000, u32::MAX, 0)
        .unwrap();
    zone.publish_park(a, seq);
    drop(guard);
    zone.clear_current(SLOT);
    assert_ne!(seq, armed);
    assert_eq!(
        zone.claim_for_host(r, Some(armed), Handback::Timeout, &HostWait),
        HostClaim::Stale
    );
    assert_eq!(
        zone.claim_for_host(r, None, Handback::Signal, &HostWait),
        HostClaim::Claimed
    );
}

#[test]
fn drain_slot_hands_back_queued_and_reports_the_switched_in_record() {
    let zone = zone();
    let a = park(&zone, 1, 0x1000);
    let b = park(&zone, 2, 0x1000);
    let _ = wake(&zone, 0x1000, 2, Waker::El1 { slot: SLOT }).unwrap();
    assert_eq!(zone.switch_in(SLOT), Some(a));
    let mut woken = [RecordId::PLACEHOLDER; ZONE_RUNQ_CAPACITY];
    let mut discarded = [RecordId::PLACEHOLDER; ZONE_RUNQ_CAPACITY];
    let drain = zone.drain_slot(SLOT, &mut woken, &mut discarded);
    assert_eq!(&woken[..drain.woken], [b]);
    assert_eq!(drain.discarded, 0);
    assert_eq!(zone.record(b).claim(), Claim::Host { seq: 1 });
    assert_eq!(zone.record(b).handback(), Some(Handback::Woken));
    assert_eq!(drain.current, Some(a));
    assert_eq!(zone.handback_current(SLOT, a), CurrentHandback::HandedBack);
    assert_eq!(zone.record(a).handback(), Some(Handback::Resumed));
    assert!(zone.reset_slot(SLOT));
}

#[test]
fn requeue_moves_waiters_to_the_new_address() {
    let zone = zone();
    let a = park(&zone, 1, 0x1000);
    let b = park(&zone, 2, 0x1000);
    let from = ZoneTables::bucket_of(MM, 0x1000);
    let to = ZoneTables::bucket_of(MM, 0x5000);
    let moved = if from == to {
        let guard = zone.lock(from, &HostWait).unwrap();
        zone.requeue(&guard, &guard, MM, 0x1000, 0x5000, 1)
    } else {
        let (first, second) = if from < to { (from, to) } else { (to, from) };
        let g1 = zone.lock(first, &HostWait).unwrap();
        let g2 = zone.lock(second, &HostWait).unwrap();
        let (fg, tg) = if from < to { (&g1, &g2) } else { (&g2, &g1) };
        zone.requeue(fg, tg, MM, 0x1000, 0x5000, 1)
    };
    assert_eq!(moved, 1);
    assert_eq!(wake(&zone, 0x5000, 5, Waker::Host).unwrap(), [a]);
    assert_eq!(wake(&zone, 0x1000, 5, Waker::Host).unwrap(), [b]);
}

#[test]
fn records_are_reused_with_a_new_incarnation() {
    let zone = zone();
    let a = park(&zone, 1, 0x1000);
    let r = zone.record_ref(a);
    assert_eq!(
        zone.claim_for_host(r, None, Handback::Cancelled, &HostWait),
        HostClaim::Claimed
    );
    zone.free_record(a);
    assert!(zone.live(r).is_none());
    let again = park(&zone, 2, 0x1000);
    assert_eq!(again, a, "the freed index is reused");
    assert!(zone.live(r).is_none(), "the old reference stays dead");
    assert_eq!(
        zone.claim_for_host(r, None, Handback::Signal, &HostWait),
        HostClaim::Stale
    );
}

/// The ownership invariant under contention: an EL1 waker and host
/// claimants (signals) race for the same parked records; every record ends
/// with exactly one owner, and no record is both on a run queue and host
/// owned.
#[test]
fn concurrent_el1_wakes_and_host_claims_give_each_record_one_owner() {
    const ROUNDS: usize = 2_000;
    let zone: Arc<Box<ZoneTables>> = Arc::new(zone());
    for round in 0..ROUNDS {
        let uaddr = 0x1000 + (round as u64 % 7) * 4;
        let records: Vec<_> = (0..4).map(|t| park(&zone, t + 1, uaddr)).collect();
        let refs: Vec<_> = records.iter().map(|r| zone.record_ref(*r)).collect();
        let go = Arc::new(AtomicBool::new(false));
        let el1 = {
            let zone = Arc::clone(&zone);
            let go = Arc::clone(&go);
            std::thread::spawn(move || {
                while !go.load(Ordering::Acquire) {}
                wake(&zone, uaddr, 2, Waker::El1 { slot: SLOT }).unwrap_or_default()
            })
        };
        let host = {
            let zone = Arc::clone(&zone);
            let go = Arc::clone(&go);
            let refs = refs.clone();
            std::thread::spawn(move || {
                while !go.load(Ordering::Acquire) {}
                refs.iter()
                    .filter(|r| {
                        zone.claim_for_host(**r, None, Handback::Signal, &HostWait)
                            == HostClaim::Claimed
                    })
                    .count()
            })
        };
        go.store(true, Ordering::Release);
        let el1_woken = el1.join().unwrap();
        let host_claimed = host.join().unwrap();
        let mut queued = 0;
        let mut host = 0;
        for record in &records {
            match zone.record(*record).claim() {
                Claim::Queued { slot, .. } => {
                    assert_eq!(slot, SLOT);
                    queued += 1;
                }
                Claim::Host { .. } => host += 1,
                other => panic!("round {round}: record left {other:?}"),
            }
        }
        assert_eq!(queued, el1_woken.len(), "round {round}");
        assert_eq!(host, host_claimed, "round {round}");
        assert_eq!(queued + host, records.len(), "round {round}");
        // Clean up for the next round.
        let mut drained = [RecordId::PLACEHOLDER; ZONE_RUNQ_CAPACITY];
        let mut discarded = [RecordId::PLACEHOLDER; ZONE_RUNQ_CAPACITY];
        let _ = zone.drain_slot(SLOT, &mut drained, &mut discarded);
        for record in &records {
            zone.unlink_all(*record, &HostWait);
            zone.free_record(*record);
        }
    }
}

/// A record the host retired while EL1 held it is never switched to, and the
/// slot's executor discards it instead of handing it back.
#[test]
fn a_cancelled_record_is_discarded_not_run() {
    let zone = zone();
    let a = park(&zone, 1, 0x1000);
    let b = park(&zone, 2, 0x1000);
    let _ = wake(&zone, 0x1000, 2, Waker::El1 { slot: SLOT }).unwrap();
    for r in [a, b] {
        assert!(matches!(
            zone.claim_for_host(zone.record_ref(r), None, Handback::Cancelled, &HostWait),
            HostClaim::El1Held { .. }
        ));
    }
    zone.record(a).request_cancel();
    assert_eq!(
        zone.runnable_head(SLOT),
        None,
        "the cancelled head is not run"
    );
    let mut woken = [RecordId::PLACEHOLDER; ZONE_RUNQ_CAPACITY];
    let mut discarded = [RecordId::PLACEHOLDER; ZONE_RUNQ_CAPACITY];
    let drain = zone.drain_slot(SLOT, &mut woken, &mut discarded);
    assert_eq!(&discarded[..drain.discarded], [a]);
    assert_eq!(&woken[..drain.woken], [b]);
    assert_eq!(zone.record(a).handback(), Some(Handback::Cancelled));
}
