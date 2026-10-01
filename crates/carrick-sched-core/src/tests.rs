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

/// The host loading a task of `mm` on `slot` (or leaving it idle with 0):
/// its published slot state and, as the host's occupancy authority does,
/// the slot's occupancy word.
fn host_publish(zone: &ZoneTables, slot: SlotId, mm: u64, cpu: Option<u32>, affinity: u64) {
    // The executor that loads it drives the slot (one executor per slot).
    zone.drive(slot, u64::from(slot.raw()) + 1);
    zone.publish_slot(slot, mm, cpu, affinity);
    let here = ExecutionSlot::zone(slot);
    zone.occupancy.vacate_any(here);
    if mm != 0 {
        assert!(zone.occupancy.replace(here, 0, mm));
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
        affinity: 0,
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
    // An EL1 waker runs a thread of the process: its slot has the address
    // space installed.
    if let Waker::El1 { slot } = waker
        && zone.slot(slot).mm() == 0
    {
        host_publish(zone, slot, MM, None, 0);
    }
    let guard = zone
        .lock(ZoneTables::bucket_of(MM, uaddr), &HostWait)
        .unwrap();
    let mut woken = [const { WakeRecord::Empty }; 64];
    let n = zone.wake(&guard, MM, uaddr, u32::MAX, count, waker, &mut woken)?;
    drop(guard);
    Ok(woken[..n as usize]
        .iter_mut()
        .filter_map(|r| r.take_ready(&HostWait).map(|r| r.id))
        .collect())
}

/// Drain `slot` as its executor does at an exit: (handed back, discarded).
fn drain(zone: &ZoneTables, slot: SlotId) -> (Vec<RecordId>, Vec<RecordId>, SlotDrain) {
    let mut woken = Vec::new();
    let mut discarded = Vec::new();
    let drain = zone.drain_slot(slot, &mut |record, discard| {
        if discard {
            discarded.push(record.id);
        } else {
            woken.push(record.id);
        }
    });
    (woken, discarded, drain)
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
        Claim::OnCpuRequested {
            slot: SlotId::new(255),
            seq: u32::MAX,
        },
        Claim::Host { seq: 77 },
        Claim::Transferring {
            seq: u32::MAX,
            cancelled: false,
            host_requested: false,
        },
        Claim::Transferring {
            seq: u32::MAX,
            cancelled: false,
            host_requested: true,
        },
        Claim::Transferring {
            seq: u32::MAX,
            cancelled: true,
            host_requested: false,
        },
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
    let mut woken = [const { WakeRecord::Empty }; 4];
    assert_eq!(
        zone.wake(&guard, MM, 0x40, 0b01, 1, Waker::Host, &mut woken),
        Ok(0)
    );
    assert_eq!(
        zone.wake(&guard, MM, 0x40, 0b10, 1, Waker::Host, &mut woken),
        Ok(1)
    );
    drop(guard);
    assert_eq!(woken[0].take_ready(&HostWait).map(|r| r.id), Some(record));
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
fn el1_refuses_multi_entry_waiters() {
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
}

/// futexforkwakegroups / LTP futex_wake02: `FUTEX_WAKE(9)` with more
/// waiters must wake exactly nine. The run queue is unbounded (EL1 plan 1d),
/// so EL1 serves any count itself; 1b-1c refused beyond eight.
#[test]
fn el1_wakes_any_count_and_exactly_that_many() {
    let zone = zone();
    let parked: Vec<_> = (0..20).map(|tid| park(&zone, 200 + tid, 0x5000)).collect();
    host_publish(&zone, SLOT, MM, None, 0);
    let guard = zone
        .lock(ZoneTables::bucket_of(MM, 0x5000), &HostWait)
        .unwrap();
    assert_eq!(
        zone.wake(
            &guard,
            MM,
            0x5000,
            u32::MAX,
            9,
            Waker::El1 { slot: SLOT },
            &mut []
        ),
        Ok(9)
    );
    let queued = parked
        .iter()
        .filter(|r| matches!(zone.record(**r).claim(), Claim::Queued { .. }))
        .count();
    assert_eq!(queued, 9);
    assert_eq!(zone.slot(SLOT).queued(), 9);
    // FIFO: the first nine parked are queued, in order.
    for (index, record) in parked.iter().take(9).enumerate() {
        assert_eq!(zone.switch_in(SLOT), Some(*record), "position {index}");
    }
    // The host takes batches of its buffer and its caller loops.
    let mut small = [const { WakeRecord::Empty }; 1];
    assert_eq!(
        zone.wake(&guard, MM, 0x5000, u32::MAX, 5, Waker::Host, &mut small),
        Ok(1)
    );
    drop(guard);
    assert!(small[0].take_ready(&HostWait).is_some());
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

    // Queued, not running: the host takes it off the run queue, and it keeps
    // its wake's result (the signal acts after it resumes).
    let b = park(&zone, 2, 0x1000);
    let _ = wake(&zone, 0x1000, 1, Waker::El1 { slot: SLOT }).unwrap();
    assert_eq!(
        zone.claim_for_host(zone.record_ref(b), None, Handback::Signal, &HostWait),
        HostClaim::Claimed
    );
    assert_eq!(zone.record(b).handback(), Some(Handback::Woken));
    assert_eq!(zone.runnable_head(SLOT), None);
    assert_eq!(zone.switch_in(SLOT), None);

    // Running on a vCPU: refused, the slot is kicked.
    let c = park(&zone, 3, 0x1000);
    let _ = wake(&zone, 0x1000, 1, Waker::El1 { slot: SLOT }).unwrap();
    assert_eq!(zone.switch_in(SLOT), Some(c));
    assert_eq!(
        zone.claim_for_host(zone.record_ref(c), None, Handback::Signal, &HostWait),
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
    let (woken, discarded, drain) = drain(&zone, SLOT);
    assert_eq!(woken, [b]);
    assert!(discarded.is_empty());
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

/// A callback may be preempted before it inspects its argument. Publishing
/// Host makes cancellation eligible, so the core must supply the identity
/// from before that publication rather than asking its consumer to recover it.
#[test]
fn drain_handback_identity_survives_reuse_before_the_consumer_runs() {
    let zone = zone();
    let record = park(&zone, 1, 0x1000);
    let expected = zone.record_ref(record);
    let _ = wake(&zone, 0x1000, 1, Waker::El1 { slot: SLOT }).unwrap();
    let mut observed = None;
    zone.drain_slot(SLOT, &mut |handed, discard| {
        assert!(!discard);
        // Model cancellation and reuse while the consumer is descheduled.
        assert_eq!(
            zone.claim_for_host(expected, None, Handback::Cancelled, &HostWait),
            HostClaim::AlreadyHost,
        );
        zone.free_record(record);
        let replacement = zone.alloc_record(identity(2)).unwrap();
        assert_eq!(replacement, record);
        let seq = zone.next_seq(replacement);
        zone.publish_park(replacement, seq);
        assert_ne!(zone.record_ref(replacement), expected);
        observed = Some(handed);
    });
    assert_eq!(
        observed,
        Some(expected),
        "handback acquired a replacement identity"
    );
}

#[test]
fn host_wake_batch_keeps_identity_after_return_and_reuse() {
    let zone = zone();
    let record = park(&zone, 1, 0x1000);
    let expected = zone.record_ref(record);
    let mut batch = [const { WakeRecord::Empty }; 1];
    {
        let guard = zone
            .lock(ZoneTables::bucket_of(MM, 0x1000), &HostWait)
            .unwrap();
        assert_eq!(
            zone.wake(&guard, MM, 0x1000, u32::MAX, 1, Waker::Host, &mut batch),
            Ok(1)
        );
    }
    let ready = batch[0].take_ready(&HostWait).unwrap();
    zone.free_record(record);
    assert_eq!(zone.alloc_record(identity(2)).unwrap(), record);
    let seq = zone.next_seq(record);
    zone.publish_park(record, seq);
    assert_eq!(
        ready, expected,
        "returned batch acquired a replacement identity"
    );
}

#[test]
fn service_take_keeps_identity_after_return_and_reuse() {
    let zone = zone();
    let record = service_record(&zone, 1);
    let expected = zone.record_ref(record);
    assert!(zone.requeue_on(SLOT, record));
    let taken = zone.take_service_head(SLOT).unwrap();
    zone.free_record(record);
    assert_eq!(zone.alloc_record(identity(2)).unwrap(), record);
    let seq = zone.next_seq(record);
    zone.publish_park(record, seq);
    assert_eq!(
        taken, expected,
        "returned service acquired a replacement identity"
    );
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
/// claimants (signals) race for the same parked records (and take queued
/// ones off the run queue); every record ends with exactly one owner, and no
/// record is both on a run queue and host owned.
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
        // A host claim may also take a thread EL1 woke off the run queue:
        // every queued record is on the queue, none host owned is.
        assert!(queued <= el1_woken.len(), "round {round}");
        assert_eq!(host, host_claimed, "round {round}");
        assert_eq!(queued + host, records.len(), "round {round}");
        let (drained, _, _) = drain(&zone, SLOT);
        assert_eq!(drained.len(), queued, "round {round}");
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
    // The host retired `a`'s thread while EL1 held it (a vCPU was running
    // it when the claim was refused; it is queued again since).
    zone.record(a)
        .request_cancel(zone.record_ref(a).incarnation);
    assert_eq!(
        zone.runnable_head(SLOT),
        Some(b),
        "the cancelled head is skipped, not run"
    );
    let (woken, discarded, _) = drain(&zone, SLOT);
    assert_eq!(discarded, [a]);
    assert_eq!(woken, [b]);
    assert_eq!(zone.record(a).handback(), Some(Handback::Cancelled));
}

// ---------------------------------------------------------------------------
// EL1 plan 1c: scheduling across vCPU slots.

const OTHER: SlotId = SlotId::new(5);

/// A slot the host loaded a thread of `MM` on, bound to guest CPU `cpu`,
/// and entered.
fn enter(zone: &ZoneTables, slot: SlotId, cpu: u32) {
    assert!(zone.reset_slot(slot));
    host_publish(zone, slot, MM, Some(cpu), 0);
    zone.enter_guest(slot);
}

fn wake_effects(
    zone: &ZoneTables,
    uaddr: u64,
    count: u32,
    slot: SlotId,
) -> (Result<Vec<RecordId>, WakeRefusal>, WakeEffects) {
    let guard = zone
        .lock(ZoneTables::bucket_of(MM, uaddr), &HostWait)
        .unwrap();
    let mut woken = [const { WakeRecord::Empty }; 16];
    let mut effects = WakeEffects::default();
    let result = zone
        .wake_placed(
            &guard,
            MM,
            uaddr,
            u32::MAX,
            count,
            Waker::El1 { slot },
            &mut woken,
            &mut effects,
        )
        .map(|n| {
            drop(guard);
            woken[..n as usize]
                .iter_mut()
                .filter_map(|r| r.take_ready(&HostWait).map(|r| r.id))
                .collect()
        });
    (result, effects)
}

/// Park the thread running on `slot` the way EL1 does: its (home or own)
/// record, published parked on `uaddr`.
fn el1_park(zone: &ZoneTables, slot: SlotId, tid: u64, uaddr: u64, deadline: u64) -> RecordId {
    let guard = zone
        .lock(ZoneTables::bucket_of(MM, uaddr), &HostWait)
        .unwrap();
    let record = zone.current_or_new(slot, identity(tid)).unwrap();
    let seq = zone.next_seq(record);
    zone.enqueue(&guard, record, seq, MM, uaddr, u32::MAX, 0)
        .unwrap();
    zone.set_deadline(record, deadline);
    if deadline != 0 {
        zone.arm_timer(slot, record, seq);
    }
    zone.publish_park(record, seq);
    drop(guard);
    zone.clear_current(slot);
    record
}

#[test]
fn slot_ids_encode_as_plus_one_words() {
    assert_eq!(SlotId::from_plus_one(0), None);
    assert_eq!(SlotId::from_plus_one(SLOT.plus_one()), Some(SLOT));
    assert_eq!(SlotId::from_plus_one(256), Some(SlotId::new(255)));
    assert_eq!(SlotId::from_plus_one(257), None);
}

/// A woken thread goes to an idle slot of the same address space, not to
/// the waker's queue; an idle slot in WFI gets an SGI, a polling one none.
#[test]
fn el1_wake_places_a_floating_thread_on_an_idle_slot() {
    let zone = zone();
    enter(&zone, SLOT, 0);
    enter(&zone, OTHER, 1);
    zone.slot(OTHER).set_sgi_target(0x5_0001);
    let a = park(&zone, 1, 0x1000);
    assert!(!zone.enter_idle(OTHER, false));
    let (woken, effects) = wake_effects(&zone, 0x1000, 1, SLOT);
    assert_eq!(woken.unwrap(), [a]);
    assert_eq!(
        zone.record(a).claim(),
        Claim::Queued {
            slot: OTHER,
            seq: 1
        }
    );
    assert_eq!(zone.slot(OTHER).queued(), 1);
    assert_eq!(zone.slot(SLOT).queued(), 0);
    assert_eq!(
        effects.sgi_slots().count(),
        0,
        "a polling slot needs no SGI"
    );
    assert!(!effects.queued_own && !effects.misplaced);
    assert_eq!(zone.counters.el1_cross_wakes.load(Ordering::Relaxed), 1);
    // The idle slot runs it.
    let switched = zone.switch_in_full(OTHER).unwrap();
    assert_eq!(switched.record, a);
    assert_eq!(switched.result, Some(0));
    assert!(!switched.home);
    assert_eq!(zone.record(a).last_slot(), Some(OTHER));

    // Parked in WFI: the waker must send the SGI.
    let b = park(&zone, 2, 0x2000);
    zone.leave_idle(OTHER);
    assert!(!zone.enter_idle(OTHER, false));
    assert!(zone.enter_idle(OTHER, true));
    let (woken, effects) = wake_effects(&zone, 0x2000, 1, SLOT);
    assert_eq!(woken.unwrap(), [b]);
    assert_eq!(effects.sgi_slots().collect::<Vec<_>>(), [OTHER]);
}

/// A slot does not park in WFI while its queue holds a thread: the check
/// and the state change are one step under the slot's lock.
#[test]
fn enter_idle_refuses_wfi_with_a_queued_thread() {
    let zone = zone();
    enter(&zone, SLOT, 0);
    enter(&zone, OTHER, 1);
    let a = park(&zone, 1, 0x1000);
    assert!(!zone.enter_idle(OTHER, false));
    let (woken, _) = wake_effects(&zone, 0x1000, 1, SLOT);
    assert_eq!(woken.unwrap(), [a]);
    assert!(
        !zone.enter_idle(OTHER, true),
        "a queued thread must run first"
    );
    assert_eq!(zone.slot(OTHER).state(), SlotState::IdleSpin);
}

/// A home record runs only on its home slot. Its home queues it (with an
/// SGI when it is running a thread), refuses it when stopped at a host exit
/// (the wake forwards), and switching it back in frees it.
#[test]
fn a_home_record_runs_only_on_its_home_slot() {
    let zone = zone();
    enter(&zone, SLOT, 0);
    enter(&zone, OTHER, 1);
    zone.slot(OTHER).set_sgi_target(0x77);
    // The thread the host loaded on OTHER parks in EL1: its home record.
    let home = el1_park(&zone, OTHER, 9, 0x3000, 0);
    assert_eq!(zone.record(home).home(), Some(OTHER));
    assert_eq!(zone.slot(OTHER).host_record(), Some(home));
    // A slot SLOT would also take it, but the home record goes home even
    // though OTHER is running (not idle): it gets an SGI.
    let (woken, effects) = wake_effects(&zone, 0x3000, 1, SLOT);
    assert_eq!(woken.unwrap(), [home]);
    assert_eq!(
        zone.record(home).claim(),
        Claim::Queued {
            slot: OTHER,
            seq: 1
        }
    );
    assert_eq!(effects.sgi_slots().collect::<Vec<_>>(), [OTHER]);
    let switched = zone.switch_in_full(OTHER).unwrap();
    assert!(switched.home);
    assert_eq!(
        zone.slot(OTHER).current(),
        Some(home),
        "the loaded thread runs its record"
    );

    // Stopped at a host exit: the wake is refused and nothing changes.
    let home = el1_park(&zone, OTHER, 9, 0x3000, 0);
    zone.leave_guest(OTHER, &HostWait);
    let (woken, _) = wake_effects(&zone, 0x3000, 1, SLOT);
    assert_eq!(woken, Err(WakeRefusal::Unplaceable));
    assert!(matches!(zone.record(home).claim(), Claim::Parked { .. }));
    // The executor settles it: no longer homed, it may run anywhere.
    assert_eq!(zone.unhome(OTHER, home, 0), None);
    assert_eq!(zone.record(home).home(), None);
    let (woken, effects) = wake_effects(&zone, 0x3000, 1, SLOT);
    assert_eq!(woken.unwrap(), [home]);
    assert!(effects.queued_own && !effects.misplaced);
}

/// A floating thread whose affinity excludes the waker's CPU and has no
/// idle slot to go to is refused (the host places it); one queued on the
/// waker's slot anyway is reported misplaced.
#[test]
fn el1_honours_affinity_for_floating_threads() {
    let zone = zone();
    enter(&zone, SLOT, 0);
    enter(&zone, OTHER, 1);
    let guard = zone
        .lock(ZoneTables::bucket_of(MM, 0x4000), &HostWait)
        .unwrap();
    let pinned = zone
        .alloc_record(ThreadIdentity {
            affinity: 1 << 1,
            ..identity(3)
        })
        .unwrap();
    let seq = zone.next_seq(pinned);
    zone.enqueue(&guard, pinned, seq, MM, 0x4000, u32::MAX, 0)
        .unwrap();
    zone.publish_park(pinned, seq);
    drop(guard);
    assert_eq!(zone.placement(pinned, SLOT), None);
    let (woken, _) = wake_effects(&zone, 0x4000, 1, SLOT);
    assert_eq!(woken, Err(WakeRefusal::Unplaceable));
    // CPU 1's slot idles: it takes the pinned thread.
    assert!(!zone.enter_idle(OTHER, false));
    assert_eq!(zone.placement(pinned, SLOT), Some(OTHER));
    let (woken, _) = wake_effects(&zone, 0x4000, 1, SLOT);
    assert_eq!(woken.unwrap(), [pinned]);
    assert_eq!(
        zone.record(pinned).claim(),
        Claim::Queued { slot: OTHER, seq }
    );
}

/// The slot's timer ends its home thread's timed park with the caller-supplied
/// result, once; a waker that wins the record first leaves the timer nothing to
/// claim.
#[test]
fn the_slot_timer_ends_a_timed_park_once() {
    let zone = zone();
    enter(&zone, SLOT, 0);
    let a = el1_park(&zone, SLOT, 1, 0x1000, 500);
    assert_eq!(zone.timer_deadline(SLOT), Some(500));
    assert_eq!(zone.expire_timer(SLOT, 499, 0xdead_beef), Ok(false));
    assert_eq!(zone.expire_timer(SLOT, 500, 0xdead_beef), Ok(true));
    assert_eq!(zone.record(a).claim(), Claim::Queued { slot: SLOT, seq: 1 });
    assert_eq!(zone.record(a).entry_count(), 0);
    assert_eq!(zone.timer_deadline(SLOT), None);
    assert_eq!(zone.expire_timer(SLOT, 900, 0xdead_beef), Ok(false));
    let switched = zone.switch_in_full(SLOT).unwrap();
    assert_eq!(switched.result, Some(0xdead_beef));
    assert!(switched.home);
    // Woken before the deadline: the timer finds the park over.
    let b = el1_park(&zone, SLOT, 1, 0x1000, 500);
    assert_eq!(b, a, "the loaded thread parks into its record again");
    assert!(!zone.enter_idle(SLOT, false));
    let guard = zone
        .lock(ZoneTables::bucket_of(MM, 0x1000), &HostWait)
        .unwrap();
    let mut woken = [const { WakeRecord::Empty }; 4];
    assert_eq!(
        zone.wake(&guard, MM, 0x1000, u32::MAX, 1, Waker::Host, &mut woken),
        Ok(1)
    );
    drop(guard);
    assert_eq!(woken[0].take_ready(&HostWait).map(|r| r.id), Some(b));
    assert!(matches!(zone.record(b).claim(), Claim::Host { .. }));
    assert_eq!(zone.expire_timer(SLOT, 900, 0xdead_beef), Ok(false));
    assert_eq!(zone.counters.el1_timeouts.load(Ordering::Relaxed), 1);
}

/// Arbitrary non-Linux caller results propagate through expire_timer without
/// assuming Linux errno values.
#[test]
fn arbitrary_non_linux_caller_result_propagates_on_timer_expiration() {
    let zone = zone();
    enter(&zone, SLOT, 0);
    let arbitrary_result: u64 = 0xCAFE_BABE_DEAD_BEEF;
    let a = el1_park(&zone, SLOT, 1, 0x2000, 1000);
    assert_eq!(zone.timer_deadline(SLOT), Some(1000));
    assert_eq!(zone.expire_timer(SLOT, 1000, arbitrary_result), Ok(true));
    assert_eq!(zone.record(a).claim(), Claim::Queued { slot: SLOT, seq: 1 });
    let switched = zone.switch_in_full(SLOT).expect("switched in");
    assert_eq!(switched.result, Some(arbitrary_result));
}

/// Preemption: the running thread (the host-loaded one, so a fresh home
/// record) goes to the tail and resumes later with its registers untouched;
/// the executor hands a preempted thread back as `Resumed`, a woken one as
/// `Woken`.
#[test]
fn a_preempted_thread_resumes_without_a_result() {
    let zone = zone();
    enter(&zone, SLOT, 0);
    let b = park(&zone, 2, 0x1000);
    let (woken, effects) = wake_effects(&zone, 0x1000, 1, SLOT);
    assert_eq!(woken.unwrap(), [b]);
    assert!(effects.queued_own);
    // Tick: preempt the host-loaded thread, switch B in.
    let a = zone.current_or_new(SLOT, identity(1)).unwrap();
    let switched = zone.switch_in_full(SLOT).unwrap();
    assert_eq!(switched.record, b);
    zone.requeue_preempted(SLOT, a);
    assert_eq!(zone.record(a).claim(), Claim::Queued { slot: SLOT, seq: 1 });
    assert_eq!(zone.slot(SLOT).current(), Some(b));
    // Next tick: B is preempted, A (home) comes back without a result.
    let prev = zone.current_or_new(SLOT, identity(2)).unwrap();
    assert_eq!(prev, b);
    let switched = zone.switch_in_full(SLOT).unwrap();
    assert_eq!(switched.record, a);
    assert_eq!(switched.result, None);
    assert!(switched.home);
    zone.requeue_preempted(SLOT, b);
    assert_eq!(zone.counters.el1_preemptions.load(Ordering::Relaxed), 2);
    // An exit now hands B back as preempted.
    zone.leave_guest(SLOT, &HostWait);
    let (woken, _, _) = drain(&zone, SLOT);
    assert_eq!(woken, [b]);
    assert_eq!(zone.record(b).handback(), Some(Handback::Resumed));
}

/// A tick moves a queued floating thread to an idle slot instead of making
/// it wait for the running one.
#[test]
fn a_tick_migrates_queued_threads_to_idle_slots() {
    let zone = zone();
    enter(&zone, SLOT, 0);
    enter(&zone, OTHER, 1);
    zone.slot(OTHER).set_sgi_target(0x42);
    let b = park(&zone, 2, 0x1000);
    let (woken, _) = wake_effects(&zone, 0x1000, 1, SLOT);
    assert_eq!(woken.unwrap(), [b]);
    assert_eq!(zone.slot(SLOT).queued(), 1);
    assert!(!zone.enter_idle(OTHER, false));
    assert!(zone.enter_idle(OTHER, true));
    let mut effects = WakeEffects::default();
    assert_eq!(zone.migrate_queued(SLOT, &mut effects), 1);
    assert_eq!(zone.slot(SLOT).queued(), 0);
    assert_eq!(
        zone.record(b).claim(),
        Claim::Queued {
            slot: OTHER,
            seq: 1
        }
    );
    assert_eq!(effects.sgi_slots().collect::<Vec<_>>(), [OTHER]);
}

/// The executor's exit transition and cross-slot queueing are serialized by
/// the slot lock: under contention, every thread another vCPU queued on a
/// slot is either drained by that slot's executor or was never queued there
/// (the waker fell back to its own queue). None is stranded.
#[test]
fn cross_slot_wakes_never_strand_a_thread_on_a_stopped_slot() {
    const ROUNDS: usize = 2_000;
    let zone: Arc<Box<ZoneTables>> = Arc::new(zone());
    for round in 0..ROUNDS {
        enter(&zone, SLOT, 0);
        enter(&zone, OTHER, 1);
        assert!(!zone.enter_idle(OTHER, false));
        let uaddr = 0x1000 + (round as u64 % 5) * 4;
        let records: Vec<_> = (0..4).map(|t| park(&zone, t + 1, uaddr)).collect();
        let go = Arc::new(AtomicBool::new(false));
        let el1 = {
            let zone = Arc::clone(&zone);
            let go = Arc::clone(&go);
            std::thread::spawn(move || {
                while !go.load(Ordering::Acquire) {}
                let mut total = 0;
                for _ in 0..4 {
                    if let (Ok(woken), _) = wake_effects(&zone, uaddr, 1, SLOT) {
                        total += woken.len();
                    }
                }
                total
            })
        };
        let host = {
            let zone = Arc::clone(&zone);
            let go = Arc::clone(&go);
            std::thread::spawn(move || {
                while !go.load(Ordering::Acquire) {}
                zone.leave_guest(OTHER, &HostWait);
                drain(&zone, OTHER).2.woken
            })
        };
        go.store(true, Ordering::Release);
        let woken = el1.join().unwrap();
        let drained = host.join().unwrap();
        let mut own = 0;
        for record in &records {
            match zone.record(*record).claim() {
                Claim::Queued { slot, .. } => {
                    assert_eq!(slot, SLOT, "round {round}: stranded on a stopped slot");
                    own += 1;
                }
                Claim::Host { .. } | Claim::Parked { .. } => {}
                other => panic!("round {round}: {other:?}"),
            }
        }
        assert_eq!(zone.slot(OTHER).queued(), 0, "round {round}");
        assert_eq!(own + drained, woken, "round {round}");
        zone.leave_guest(SLOT, &HostWait);
        let _ = drain(&zone, SLOT);
        for record in &records {
            zone.unlink_all(*record, &HostWait);
            zone.free_record(*record);
        }
    }
}

// ---------------------------------------------------------------------------
// EL1 plan 1d: host-runnable threads in the guest's run queues, stealing and
// host placement.

const THIRD: SlotId = SlotId::new(9);

/// A thread the host made runnable (its record host-owned, handback
/// `Service`), as the host venue creates one for a completed host wait.
fn service_record(zone: &ZoneTables, tid: u64) -> RecordId {
    let record = zone.alloc_record(identity(tid)).unwrap();
    let seq = zone.next_seq(record);
    zone.publish_park(record, seq);
    assert_eq!(
        zone.claim_for_host(zone.record_ref(record), None, Handback::Service, &HostWait),
        HostClaim::Claimed
    );
    assert!(zone.record(record).needs_host());
    record
}

/// The run queue is a FIFO of any length, and a record can leave from the
/// middle (a thief) without breaking the order of the rest.
#[test]
fn run_queue_is_unbounded_fifo_and_survives_removal_from_the_middle() {
    let zone = zone();
    enter(&zone, SLOT, 0);
    let parked: Vec<_> = (0..40).map(|tid| park(&zone, 300 + tid, 0x6000)).collect();
    assert_eq!(
        wake(&zone, 0x6000, 40, Waker::El1 { slot: SLOT })
            .unwrap()
            .len(),
        40
    );
    assert_eq!(zone.slot(SLOT).queued(), 40);
    // An idle thief of the same address space takes the head (the oldest).
    enter(&zone, OTHER, 1);
    assert!(!zone.enter_idle(OTHER, false));
    let stolen = zone.steal(OTHER).unwrap();
    assert_eq!(stolen.record, parked[0]);
    assert_eq!(zone.slot(SLOT).queued(), 39);
    for record in &parked[1..] {
        assert_eq!(zone.switch_in(SLOT), Some(*record));
    }
    assert_eq!(zone.slot(SLOT).queued(), 0);
    assert_eq!(zone.switch_in(SLOT), None);
}

/// A thread that needs its executor is never switched in at EL0: the slot
/// sees it at its head and leaves for the host instead.
#[test]
fn a_service_record_is_never_switched_in() {
    let zone = zone();
    enter(&zone, SLOT, 0);
    let service = service_record(&zone, 1);
    let placed = zone.place_from_host(service).unwrap();
    assert_eq!(placed.slot, SLOT);
    assert!(zone.head_needs_host(SLOT));
    assert_eq!(zone.switch_in_full(SLOT), None);
    assert_eq!(zone.slot(SLOT).queued(), 1);
    // Its executor takes it at the exit, still a service record.
    zone.leave_guest(SLOT, &HostWait);
    let (woken, _, _) = drain(&zone, SLOT);
    assert_eq!(woken, [service]);
    assert_eq!(zone.record(service).handback(), Some(Handback::Service));
}

/// Host placement: a service thread goes to an idle slot of any address
/// space; a thread ready at EL0 only to a slot running its address space,
/// else nowhere (the host serves it). A running or WFI target owes a
/// reschedule SGI, which its run loop takes once.
#[test]
fn host_placement_respects_address_spaces_and_owes_resched_sgis() {
    let zone = zone();
    // SLOT runs MM; OTHER idles with no address space (an executor waiting
    // in the guest); THIRD runs another process.
    enter(&zone, SLOT, 0);
    assert!(zone.reset_slot(OTHER));
    host_publish(&zone, OTHER, 0, Some(1), 0);
    zone.enter_guest(OTHER);
    assert!(!zone.enter_idle(OTHER, false));
    assert!(zone.enter_idle(OTHER, true));
    assert!(zone.reset_slot(THIRD));
    host_publish(&zone, THIRD, MM + 1, Some(2), 0);
    zone.enter_guest(THIRD);

    let service = service_record(&zone, 1);
    let placed = zone.place_from_host(service).unwrap();
    assert_eq!(placed.slot, OTHER, "the idle slot takes a service thread");
    assert!(placed.resched, "a WFI slot needs its SGI");
    assert!(zone.take_resched(OTHER));
    assert!(!zone.take_resched(OTHER), "taken once");

    // A woken thread of MM: OTHER (no address space) cannot run it at EL0;
    // SLOT (running MM) can.
    let ready = park(&zone, 2, 0x7000);
    assert_eq!(wake(&zone, 0x7000, 1, Waker::Host).unwrap(), [ready]);
    let placed = zone.place_from_host(ready).unwrap();
    assert_eq!(placed.slot, SLOT);
    assert!(
        placed.resched,
        "a running slot needs its SGI to start a slice"
    );
    assert_eq!(
        zone.record(ready).claim(),
        Claim::Queued { slot: SLOT, seq: 1 }
    );

    // With SLOT stopped at an exit, nothing runs MM: the host keeps it.
    zone.leave_guest(SLOT, &HostWait);
    let stranded = park(&zone, 3, 0x7004);
    assert_eq!(wake(&zone, 0x7004, 1, Waker::Host).unwrap(), [stranded]);
    assert_eq!(zone.place_from_host(stranded), None);
    assert_eq!(zone.record(stranded).claim(), Claim::Host { seq: 1 });

    // A service thread with every slot stopped still goes to a slot: its
    // executor serves it before it runs the vCPU again.
    zone.leave_guest(OTHER, &HostWait);
    zone.leave_guest(THIRD, &HostWait);
    let late = service_record(&zone, 4);
    let placed = zone.place_from_host(late).unwrap();
    assert!(!placed.resched, "a stopped slot needs no SGI");
    assert_eq!(
        zone.counters
            .host_service_placements
            .load(Ordering::Relaxed),
        2
    );
    assert_eq!(
        zone.counters.host_ready_placements.load(Ordering::Relaxed),
        1
    );
}

/// Stealing never takes a home record or a record needing the thief's host
/// executor. Such a move would wake an idle vCPU only to exit immediately.
#[test]
fn stealing_takes_only_what_the_thief_may_run() {
    let zone = zone();
    enter(&zone, SLOT, 0);
    enter(&zone, OTHER, 1);
    // A home record of OTHER, woken by SLOT: queued on OTHER.
    let home = el1_park(&zone, OTHER, 9, 0x8000, 0);
    let (woken, _) = wake_effects(&zone, 0x8000, 1, SLOT);
    assert_eq!(woken.unwrap(), [home]);
    assert!(zone.reset_slot(THIRD));
    host_publish(&zone, THIRD, MM, Some(2), 0);
    zone.enter_guest(THIRD);
    assert!(!zone.enter_idle(THIRD, false));
    assert_eq!(zone.steal(THIRD), None, "a home record is not stolen");
    // A service thread on OTHER moves to the idle thief's queue.
    let service = service_record(&zone, 5);
    zone.leave_guest(OTHER, &HostWait);
    let placed = zone.place_from_host(service).unwrap();
    assert_eq!(placed.slot, THIRD, "the idle slot is chosen first");
    assert!(zone.head_needs_host(THIRD));
    // An idle slot of another address space leaves both records on THIRD:
    // it cannot install MM and would have to exit for its executor.
    let foreign = SlotId::new(11);
    assert!(zone.reset_slot(foreign));
    host_publish(&zone, foreign, MM + 7, Some(3), 0);
    zone.enter_guest(foreign);
    assert!(!zone.enter_idle(foreign, false));
    let ready = park(&zone, 6, 0x8004);
    let (woken, _) = wake_effects(&zone, 0x8004, 1, SLOT);
    assert_eq!(woken.unwrap(), [ready]);
    assert!(matches!(zone.record(ready).claim(), Claim::Queued { .. }));
    assert_eq!(zone.steal(foreign), None);
    assert!(!zone.head_needs_host(foreign));
    assert_eq!(zone.steal(foreign), None);
    assert_eq!(
        zone.record(ready).claim(),
        Claim::Queued {
            slot: THIRD,
            seq: 1
        },
        "the EL0 thread remains on the vCPU that can run it"
    );
    assert_eq!(zone.counters.el1_steals.load(Ordering::Relaxed), 0);
    assert_eq!(zone.runnable_head(THIRD), Some(service));
    // THIRD's executor retains its service record.
    zone.leave_guest(THIRD, &HostWait);
    assert_eq!(zone.take_service_head(THIRD).map(|r| r.id), Some(service));
    assert_eq!(zone.counters.foreign_adoptions.load(Ordering::Relaxed), 0);
}

/// A service thread the host placed on a stopped slot (its vCPU out of the
/// guest, its executor on the host) must not wait there for an executor that
/// may not come back to that vCPU: an idle vCPU takes it onto its own queue
/// and leaves for its executor. Every vCPU was busy on the host when the
/// thread became runnable, so it went to a live stopped slot; the vCPUs
/// that then came back idle are the only ones that can reach it.
#[test]
fn an_idle_vcpu_rescues_service_work_from_a_stopped_slot() {
    let zone = zone();
    enter(&zone, SLOT, 0);
    zone.leave_guest(SLOT, &HostWait);
    let service = service_record(&zone, 5);
    let placed = zone.place_from_host(service).unwrap();
    assert_eq!(placed.slot, SLOT, "the only live slot is stopped");
    assert!(!placed.resched);
    enter(&zone, OTHER, 1);
    assert!(!zone.enter_idle(OTHER, false));
    assert_eq!(zone.steal(OTHER), None, "EL1 never runs a service thread");
    assert_eq!(zone.runnable_head(SLOT), None);
    assert_eq!(zone.runnable_head(OTHER), Some(service));
    assert!(zone.head_needs_host(OTHER));
    assert_eq!(zone.counters.el1_steals.load(Ordering::Relaxed), 1);
}

/// The executor sweeps records of retired threads off its run queue at an
/// exit, and takes a service thread from the head.
#[test]
fn an_executor_sweeps_cancelled_records_and_takes_its_service_head() {
    let zone = zone();
    enter(&zone, SLOT, 0);
    let a = park(&zone, 1, 0x1000);
    let _ = wake(&zone, 0x1000, 1, Waker::El1 { slot: SLOT }).unwrap();
    zone.record(a)
        .request_cancel(zone.record_ref(a).incarnation);
    let service = zone.alloc_host_runnable(identity(2)).unwrap();
    assert_eq!(zone.place_from_host(service).map(|p| p.slot), Some(SLOT));
    zone.leave_guest(SLOT, &HostWait);
    assert_eq!(
        zone.take_service_head(SLOT).map(|r| r.id),
        None,
        "a cancelled record is first"
    );
    assert_eq!(zone.sweep_cancelled(SLOT), 1);
    assert_eq!(zone.record(a).claim(), Claim::Free);
    assert_eq!(zone.take_service_head(SLOT).map(|r| r.id), Some(service));
    assert_eq!(zone.record(service).claim(), Claim::Host { seq: 1 });
    assert_eq!(zone.slot(SLOT).queued(), 0);
}

// ---------------------------------------------------------------------------
// EL1 plan 1d: the host places ready threads in the guest, never through a
// host-owned state a claimant could take for runnable.

fn host_wake(
    zone: &ZoneTables,
    uaddr: u64,
    count: u32,
    place: bool,
) -> (u32, Vec<RecordId>, Vec<HostPlacement>) {
    let guard = zone
        .lock(ZoneTables::bucket_of(MM, uaddr), &HostWait)
        .unwrap();
    let mut handed = Vec::new();
    let mut placed = Vec::new();
    let n = zone.wake_host(
        &guard,
        MM,
        uaddr,
        u32::MAX,
        count,
        place,
        &mut |record| handed.push(record),
        &mut |placement| placed.push(placement),
    );
    drop(guard);
    let handed = handed
        .into_iter()
        .filter_map(|transfer| transfer.finish(&HostWait).map(|r| r.id))
        .collect();
    (n, handed, placed)
}

#[test]
fn a_host_wake_queues_the_waiter_in_the_guest_directly() {
    let zone = zone();
    enter(&zone, OTHER, 1);
    let a = park(&zone, 1, 0x1000);
    let (n, handed, placed) = host_wake(&zone, 0x1000, 1, true);
    assert_eq!(n, 1);
    assert!(handed.is_empty(), "placed, not handed back");
    assert_eq!(placed.len(), 1);
    assert_eq!(placed[0].slot, OTHER);
    assert!(matches!(zone.record(a).claim(), Claim::Queued { slot, .. } if slot == OTHER));
    assert_eq!(zone.record(a).handback(), Some(Handback::Woken));
    assert_eq!(zone.record(a).entry_count(), 0);
    assert_eq!(zone.counters.host_wakes.load(Ordering::Relaxed), 0);

    // No slot in the guest runs its address space: host owned, handed back.
    let b = park(&zone, 2, 0x2000);
    zone.leave_guest(OTHER, &HostWait);
    let (n, handed, placed) = host_wake(&zone, 0x2000, 1, true);
    assert_eq!((n, handed.as_slice(), placed.len()), (1, [b].as_slice(), 0));
    assert!(matches!(zone.record(b).claim(), Claim::Host { .. }));

    // The hatch (`place` false) never queues in the guest.
    zone.enter_guest(OTHER);
    let c = park(&zone, 3, 0x3000);
    let (_, handed, placed) = host_wake(&zone, 0x3000, 1, false);
    assert_eq!((handed.as_slice(), placed.len()), ([c].as_slice(), 0));
}

#[test]
fn relocation_moves_queued_threads_between_run_queues_without_host_ownership() {
    let zone = zone();
    enter(&zone, SLOT, 0);
    enter(&zone, OTHER, 1);
    let a = park(&zone, 1, 0x1000);
    let b = park(&zone, 2, 0x1000);
    let _ = wake(&zone, 0x1000, 2, Waker::El1 { slot: SLOT }).unwrap();
    zone.leave_guest(SLOT, &HostWait);
    let mut handed = Vec::new();
    let mut placed = Vec::new();
    let moved = zone.relocate(
        SLOT,
        None,
        &mut |record, discard| handed.push((record.id, discard)),
        &mut |placement| placed.push(placement),
    );
    assert_eq!(moved, 2);
    assert!(handed.is_empty());
    assert_eq!(placed.len(), 2);
    for record in [a, b] {
        assert!(matches!(zone.record(record).claim(), Claim::Queued { slot, .. } if slot == OTHER));
    }
    assert_eq!(zone.runnable_head(SLOT), None);
    assert_eq!(zone.runnable_head(OTHER), Some(a));

    // Nowhere to go: host owned and handed back, a retired thread discarded.
    zone.leave_guest(OTHER, &HostWait);
    zone.record(b)
        .request_cancel(zone.record_ref(b).incarnation);
    let moved = zone.relocate(
        OTHER,
        None,
        &mut |record, discard| handed.push((record.id, discard)),
        &mut |placement| placed.push(placement),
    );
    assert_eq!(moved, 2);
    assert_eq!(handed, [(a, false), (b, true)]);
    assert!(matches!(zone.record(a).claim(), Claim::Host { .. }));
    assert_eq!(zone.record(a).handback(), Some(Handback::Woken));
    assert_eq!(zone.record(b).handback(), Some(Handback::Cancelled));
}

/// A thread the host loads on a slot starts a fresh slice: the slot's slice
/// start from what it ran before would preempt it at the first tick (EL1
/// restarts the slice at its next look when the start is 0).
#[test]
fn a_host_load_starts_a_fresh_slice() {
    let zone = zone();
    enter(&zone, SLOT, 0);
    zone.slot(SLOT).restart_slice(1_000);
    zone.leave_guest(SLOT, &HostWait);
    assert!(zone.reset_slot(SLOT));
    assert_eq!(zone.slot(SLOT).queued_since(), 0);
}

/// A slot follows its mailbox lease, which a task carries between executors:
/// the executor that stopped driving a slot vacates it (its queue leaves,
/// no placement chooses it), unless another executor drives it now.
#[test]
fn only_the_executor_still_driving_a_slot_vacates_it() {
    let zone = zone();
    enter(&zone, OTHER, 1);
    enter(&zone, SLOT, 0);
    zone.drive(SLOT, 7);
    let service = service_record(&zone, 5);
    zone.leave_guest(SLOT, &HostWait);
    zone.leave_guest(OTHER, &HostWait);
    zone.enter_guest(OTHER);
    // Queue a service thread on SLOT directly (its executor was about to take
    // it when its lease moved away).
    assert!(zone.requeue_on(SLOT, service));
    let mut taken = Vec::new();
    let mut placed = Vec::new();
    // Another executor drives the slot now: nothing happens.
    zone.drive(SLOT, 9);
    assert!(!zone.leave_slot(SLOT, 7, &mut |r| taken.push(r.id), &mut |p| placed.push(p)));
    assert_eq!(zone.runnable_head(SLOT), Some(service));
    // The executor still driving it leaves: the queue goes, the slot is
    // no longer live for placements.
    assert!(zone.leave_slot(SLOT, 9, &mut |r| taken.push(r.id), &mut |p| placed.push(p)));
    assert_eq!(taken, [service]);
    assert_eq!(zone.runnable_head(SLOT), None);
    assert_eq!(zone.place_from_host(service).map(|p| p.slot), Some(OTHER));
}

/// Contract kernel.el1.slot-liveness: a slot takes work that needs an
/// executor only while an executor that comes back to it drives it.
/// Publishing a slot or entering its vCPU says nothing about who comes back
/// (the host publishes as it loads, EL1 state follows the vCPU): only a drive
/// makes a slot live.
#[test]
fn only_a_drive_makes_a_slot_live() {
    let zone = zone();
    assert!(zone.reset_slot(SLOT));
    zone.publish_slot(SLOT, MM, Some(0), 0);
    zone.enter_guest(SLOT);
    zone.leave_guest(SLOT, &HostWait);
    assert!(!zone.slot(SLOT).is_live());
    let service = service_record(&zone, 5);
    assert_eq!(
        zone.place_from_host(service),
        None,
        "nobody drives the slot"
    );
    zone.drive(SLOT, 7);
    assert!(zone.slot(SLOT).is_live());
    assert_eq!(zone.slot(SLOT).driver(), Some(7));
    assert_eq!(zone.place_from_host(service).map(|p| p.slot), Some(SLOT));
}

/// Contract kernel.el1.slot-liveness: an executor that steps away for a
/// blocking host wait keeps its slot but takes no new work there until it
/// steps back; a service thread nobody else takes may wait for it. Only the
/// executor driving the slot steps away or back: a stale executor whose
/// slot another executor drove and left must not make it live again.
#[test]
fn only_its_driver_steps_away_from_and_back_to_a_slot() {
    let zone = zone();
    enter(&zone, SLOT, 0);
    zone.drive(SLOT, 7);
    zone.leave_guest(SLOT, &HostWait);
    let mut taken = Vec::new();
    let mut placed = Vec::new();
    assert!(!zone.step_away(SLOT, 9, &mut |r| taken.push(r.id), &mut |p| placed.push(p)));
    assert!(zone.slot(SLOT).is_live());
    assert!(zone.step_away(SLOT, 7, &mut |r| taken.push(r.id), &mut |p| placed.push(p)));
    assert!(!zone.slot(SLOT).is_live());
    assert_eq!(zone.slot(SLOT).driver(), Some(7), "away, not gone");
    let service = service_record(&zone, 5);
    assert_eq!(zone.place_from_host(service), None);
    assert!(zone.requeue_on(SLOT, service), "it waits for its driver");
    zone.step_back(SLOT, 9);
    assert!(!zone.slot(SLOT).is_live());
    zone.step_back(SLOT, 7);
    assert!(zone.slot(SLOT).is_live());
    assert_eq!(zone.take_service_head(SLOT).map(|r| r.id), Some(service));

    // Another executor drives the slot, then leaves it: the first one's
    // late return finds nothing to come back to.
    zone.drive(SLOT, 9);
    assert!(zone.leave_slot(SLOT, 9, &mut |r| taken.push(r.id), &mut |p| placed.push(p)));
    zone.step_back(SLOT, 7);
    assert!(!zone.slot(SLOT).is_live());
    assert_eq!(zone.slot(SLOT).driver(), None);
}

/// Contract `kernel.el1.address-space-switch`: the Dekker pair between EL1
/// installing an address space on its vCPU (publish the slot's occupancy
/// word, then read the space's gate) and a page-table pause of that space
/// (raise the gate, then scan the occupancy words and wait for each vCPU
/// found to leave the space). More vCPUs than a pause can keep up with
/// switch between two published spaces through the maintenance root, as
/// EL1 does; any vCPU that runs `Y` while the pauser believes `Y` drained is
/// a violation. With `check_gate` false (the negative control) the install
/// skips the gate read.
fn el1_installs_race_pauses(check_gate: bool) -> (u32, u32) {
    const VCPUS: usize = 6;
    const ROUNDS: u32 = 3_000;
    const MIN_ENTRIES: u32 = 50_000;
    const Y: u64 = 0x1111;
    const Z: u64 = 0x2222;
    let zone: Arc<ZoneTables> = Arc::from(zone());
    zone.spaces.set_idle_ttbr(0x4000_0000);
    for key in [Y, Z] {
        let index = zone
            .spaces
            .publish_closed(key, key << 12, key << 12)
            .unwrap();
        zone.spaces.open(index);
    }
    let y = zone.spaces.find(Y).unwrap();
    let drained = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let violations = Arc::new(core::sync::atomic::AtomicU32::new(0));
    let entries = Arc::new(core::sync::atomic::AtomicU32::new(0));
    let mut vcpus = Vec::new();
    for id in 0..VCPUS {
        let (zone, drained, stop, violations, entries) = (
            zone.clone(),
            drained.clone(),
            stop.clone(),
            violations.clone(),
            entries.clone(),
        );
        vcpus.push(std::thread::spawn(move || {
            let slot = SlotId::new(id as u8);
            let here = ExecutionSlot::zone(slot);
            let mut turn = id;
            while !stop.load(Ordering::Relaxed) {
                turn += 1;
                let to = if turn % 2 == 0 { Y } else { Z };
                // To the maintenance root: the slot holds nothing.
                zone.release_space(slot);
                let installed = if check_gate {
                    zone.install_space(slot, to).is_some()
                } else {
                    let from = zone.occupancy.running_raw(here);
                    zone.occupancy.replace(here, from, to)
                };
                if !installed {
                    continue;
                }
                if to == Y {
                    entries.fetch_add(1, Ordering::Relaxed);
                    for _ in 0..3 {
                        if drained.load(Ordering::SeqCst) {
                            violations.fetch_add(1, Ordering::Relaxed);
                        }
                        for _ in 0..16 {
                            core::hint::spin_loop();
                        }
                    }
                }
            }
            zone.release_space(slot);
        }));
    }
    let mut rounds = 0;
    while rounds < ROUNDS || entries.load(Ordering::Relaxed) < MIN_ENTRIES {
        rounds += 1;
        zone.spaces.raise(y);
        let mut pending = Vec::new();
        zone.occupancy
            .for_each_running(AddressSpaceKey::from_raw(Y).unwrap(), |slot| {
                pending.push(slot)
            });
        // A pause kicks each vCPU found and waits for it to leave the guest;
        // here a vCPU leaves `Y` by itself at its next turn.
        for slot in pending {
            while zone.occupancy.running_raw(slot) == Y {
                core::hint::spin_loop();
            }
        }
        drained.store(true, Ordering::SeqCst);
        for _ in 0..500 {
            core::hint::spin_loop();
        }
        drained.store(false, Ordering::SeqCst);
        zone.spaces.lower(y);
        for _ in 0..200 {
            core::hint::spin_loop();
        }
    }
    stop.store(true, Ordering::Relaxed);
    for vcpu in vcpus {
        vcpu.join().unwrap();
    }
    (
        entries.load(Ordering::Relaxed),
        violations.load(Ordering::Relaxed),
    )
}

#[test]
fn a_pause_never_misses_an_el1_address_space_install() {
    let (entries, violations) = el1_installs_race_pauses(true);
    assert!(entries > 0, "the vCPUs ran the paused space between pauses");
    assert_eq!(violations, 0);
}

/// Negative control: an install that does not read the gate is caught.
#[test]
fn an_install_that_skips_the_gate_is_caught() {
    let (_, violations) = el1_installs_race_pauses(false);
    assert!(violations > 0, "the stress must detect a missing gate read");
}

/// Retirement closes the gate for good: no install after it, and one
/// published before it is visible to the scan that follows.
#[test]
fn a_closed_space_is_never_installed_again() {
    let zone = zone();
    zone.spaces.set_idle_ttbr(0x4000_0000);
    let index = zone.spaces.publish_closed(MM, 0x7000, 0x7000).unwrap();
    assert_eq!(
        zone.install_space(SLOT, MM),
        None,
        "closed while publishing"
    );
    zone.spaces.open(index);
    assert!(zone.install_space(SLOT, MM).is_some());
    zone.spaces.close(index);
    let mut found = Vec::new();
    zone.occupancy
        .for_each_running(AddressSpaceKey::from_raw(MM).unwrap(), |slot| {
            found.push(slot)
        });
    assert_eq!(
        found,
        [ExecutionSlot::zone(SLOT)],
        "the scan sees the earlier install"
    );
    zone.release_space(SLOT);
    assert_eq!(zone.install_space(SLOT, MM), None);
    assert_eq!(zone.installed_space(SLOT), 0);
}

/// A synthetic EL1 save area for a thread EL1 parked (a private futex wait,
/// exactly as `park` above does it), with a distinctive, fully populated
/// [`ThreadCtx`] so a reader must round-trip every field, not just prove
/// SOMETHING came back.
fn distinctive_ctx(seed: u64) -> ThreadCtx {
    let mut ctx = ThreadCtx::ZERO;
    for (index, slot) in ctx.x.iter_mut().enumerate() {
        *slot = seed.wrapping_mul(0x1000).wrapping_add(index as u64);
    }
    ctx.pc = seed.wrapping_mul(0x2000);
    ctx.pstate = seed.wrapping_mul(0x3000);
    ctx.sp_el0 = seed.wrapping_mul(0x4000);
    ctx.tpidr_el0 = seed.wrapping_mul(0x5000);
    ctx.tpidrro_el0 = seed.wrapping_mul(0x6000);
    ctx.contextidr_el1 = seed.wrapping_mul(0x7000);
    for (index, slot) in ctx.v.iter_mut().enumerate() {
        *slot = (seed as u128)
            .wrapping_mul(0x1_0000)
            .wrapping_add(index as u128);
    }
    ctx.fpsr = seed.wrapping_mul(0x8000);
    ctx.fpcr = seed.wrapping_mul(0x9000);
    ctx
}

/// Park `tid` (as `park` does) and overwrite its save area with a
/// distinctive, fully populated context.
fn park_with_ctx(zone: &ZoneTables, tid: u64, uaddr: u64, ctx: ThreadCtx) -> RecordId {
    let record = park(zone, tid, uaddr);
    // SAFETY: this test is the only party touching the zone; the record is
    // `Parked` (nobody else may claim a park this test never wakes).
    unsafe {
        *zone.record(record).ctx_mut() = ctx;
    }
    record
}

/// The EL1 save-area reader crash capture relies on: a thread EL1 holds
/// parked answers with its exact, fully populated context, attributed to
/// the exact `(mm, tid, serial)` a post-mortem reader asked for -- and never
/// to a DIFFERENT thread parked at the same time.
///
/// This is the red-first case for "parked-EL1-thread registers are absent
/// from crash snapshots": before `ZoneTables::read_parked_context` existed,
/// there was no way to answer this question at all, and a crash-capture
/// quorum polling a thread in this exact state (`Claim::Parked`, no vote,
/// not a live host safe-point participant) either hung on `Waiting` forever
/// (if still marked a participant) or silently dropped the thread's
/// `NT_PRSTATUS` note (if not) -- never attributed real registers to it.
#[test]
fn read_parked_context_finds_and_attributes_the_exact_thread() {
    let zone = zone();
    let ctx_a = distinctive_ctx(1);
    let ctx_b = distinctive_ctx(2);
    // Two threads parked at once: the reader must not confuse them.
    let record_a = park_with_ctx(&zone, 101, 0x1000, ctx_a);
    let record_b = park_with_ctx(&zone, 202, 0x2000, ctx_b);
    let identity_a = zone.record(record_a).identity();
    let identity_b = zone.record(record_b).identity();

    // SAFETY: a single-threaded test with no concurrent EL1/host claimant --
    // the authentication the real caller (crash capture) provides via a
    // quiesce barrier holds trivially here.
    let read_a =
        unsafe { zone.read_parked_context(identity_a.mm, identity_a.tid, identity_a.serial) };
    let ParkedContextRead::Found(found_a) = read_a else {
        panic!("expected thread A's parked context, got {read_a:?}");
    };
    assert_eq!(found_a, ctx_a, "thread A's exact save area, not thread B's");

    let read_b =
        unsafe { zone.read_parked_context(identity_b.mm, identity_b.tid, identity_b.serial) };
    let ParkedContextRead::Found(found_b) = read_b else {
        panic!("expected thread B's parked context, got {read_b:?}");
    };
    assert_eq!(found_b, ctx_b, "thread B's exact save area, not thread A's");
}

/// A thread that is not parked (wrong identity, or truly absent) answers
/// `NotParked`, never a synthesized or borrowed register file: the caller's
/// own safe-point protocol (publish/withdraw) owns that thread instead.
#[test]
fn read_parked_context_reports_not_parked_for_an_unmatched_identity() {
    let zone = zone();
    let ctx = distinctive_ctx(3);
    let record = park_with_ctx(&zone, 303, 0x3000, ctx);
    let identity = zone.record(record).identity();

    // Right mm and serial, wrong tid.
    let wrong_tid =
        unsafe { zone.read_parked_context(identity.mm, identity.tid + 1, identity.serial) };
    assert!(matches!(wrong_tid, ParkedContextRead::NotParked));

    // Right tid and serial, wrong mm: a different address space must never
    // be answered from this record even if the numeric ids happen to align.
    let wrong_mm =
        unsafe { zone.read_parked_context(identity.mm + 1, identity.tid, identity.serial) };
    assert!(matches!(wrong_mm, ParkedContextRead::NotParked));

    // A thread EL1 woke (`Claim::Queued`, no longer `Parked`) must not
    // answer from its now-stale-for-this-purpose record either: its
    // registers belong to whichever safe point resumes it, not to this
    // reader.
    let woken = park(&zone, 505, 0x5000);
    let woken_identity = zone.record(woken).identity();
    assert!(wake(&zone, 0x5000, 1, Waker::El1 { slot: SLOT }).is_ok());
    assert!(matches!(zone.record(woken).claim(), Claim::Queued { .. }));
    let no_longer_parked = unsafe {
        zone.read_parked_context(woken_identity.mm, woken_identity.tid, woken_identity.serial)
    };
    assert!(matches!(no_longer_parked, ParkedContextRead::NotParked));
}

/// A target slot can run a placed waiter as soon as its queue lock is
/// released; publication must therefore finish removing its futex entry.
#[test]
fn guest_wake_publication_has_no_remaining_futex_entry() {
    let zone = zone();
    enter(&zone, SLOT, 0);
    for population in [1, 8, 32] {
        let records: Vec<_> = (0..population)
            .map(|i| park(&zone, 100 + i, 0x1000))
            .collect();
        let guard = zone
            .lock(ZoneTables::bucket_of(MM, 0x1000), &HostWait)
            .unwrap();
        let mut remaining_entries = Vec::new();
        let mut unexpected_handbacks = Vec::new();
        let count = zone.wake_host(
            &guard,
            MM,
            0x1000,
            u32::MAX,
            population as u32,
            true,
            &mut |record| unexpected_handbacks.push(record),
            &mut |placement| {
                // This is the real consumer boundary, after the target's
                // lock was released. Take the waiter like a target vCPU.
                let record = zone.switch_in(placement.slot).unwrap();
                remaining_entries.push(zone.record(record).entry_count());
            },
        );
        drop(guard);
        assert_eq!(count, population as u32);
        assert!(unexpected_handbacks.is_empty());
        assert_eq!(
            remaining_entries,
            std::vec![0; population as usize],
            "runnable publication left futex queue entries attached"
        );
        for record in records {
            zone.free_record(record);
        }
    }
}

#[test]
fn host_claim_is_not_published_before_queue_cleanup() {
    struct ObserveWait(std::sync::mpsc::Sender<()>);
    impl LockWait for ObserveWait {
        fn wait(&self, attempt: u32) -> bool {
            if attempt == 1 {
                let _ = self.0.send(());
            }
            std::thread::yield_now();
            true
        }
    }
    let zone = zone();
    let id = park(&zone, 1, 0x1000);
    let original = zone.record_ref(id);
    let guard = zone
        .lock(ZoneTables::bucket_of(MM, 0x1000), &HostWait)
        .unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let observed = std::thread::scope(|scope| {
        let zone = &zone;
        let producer = scope
            .spawn(move || zone.claim_for_host(original, None, Handback::Signal, &ObserveWait(tx)));
        // Observe the real unlink lock boundary, without sleeps or a guest
        // scheduler hook. Release the bucket before assertions or joining.
        let reached = rx.recv_timeout(std::time::Duration::from_secs(5));
        let claim = zone.record(id).claim();
        let entries = zone.record(id).entry_count();
        drop(guard);
        let result = producer.join().unwrap();
        reached.unwrap();
        assert_eq!(result, HostClaim::Claimed);
        (claim, entries)
    });
    assert_eq!(zone.record(id).entry_count(), 0);
    assert_eq!(zone.record(id).handback(), Some(Handback::Signal));
    assert_eq!(observed.1, 1, "producer paused before queue cleanup");
    assert!(
        !matches!(observed.0, Claim::Host { .. }),
        "Host exposed while producer still owns queue cleanup: {:?}",
        observed.0
    );
}

#[test]
fn host_claim_cleanup_does_not_unlink_a_replacement_waiter() {
    struct ObserveWait(std::sync::mpsc::Sender<()>);
    impl LockWait for ObserveWait {
        fn wait(&self, attempt: u32) -> bool {
            if attempt == 1 {
                let _ = self.0.send(());
            }
            std::thread::yield_now();
            true
        }
    }
    let zone = zone();
    let address = 0x1000;
    let id = park(&zone, 1, address);
    let original = zone.record_ref(id);
    let bucket = ZoneTables::bucket_of(MM, address);
    let replacement_address = (0x2000..0x3000)
        .step_by(4)
        .find(|addr| ZoneTables::bucket_of(MM, *addr) != bucket)
        .unwrap();
    let guard = zone.lock(bucket, &HostWait).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let replacement = std::thread::scope(|scope| {
        let zone = &zone;
        let producer = scope
            .spawn(move || zone.claim_for_host(original, None, Handback::Signal, &ObserveWait(tx)));
        let reached = rx.recv_timeout(std::time::Duration::from_secs(5));
        if reached.is_err() {
            drop(guard);
            let _ = producer.join();
            panic!("claim did not reach queue cleanup");
        }
        // Same cancellation decision as el1_zone::cancel: AlreadyHost
        // permits free, although this producer is still in unlink_all.
        let cancellation = zone.claim_for_host(original, None, Handback::Cancelled, &HostWait);
        let replacement = if matches!(cancellation, HostClaim::Claimed | HostClaim::AlreadyHost) {
            zone.free_record(id);
            Some(park(zone, 2, replacement_address))
        } else {
            None
        };
        drop(guard);
        let completion = producer.join().unwrap();
        assert_eq!(
            completion,
            if replacement.is_some() {
                HostClaim::Claimed
            } else {
                HostClaim::Stale
            }
        );
        replacement
    });
    if let Some(replacement) = replacement {
        assert_eq!(replacement, id, "fixture must reuse the retired slot");
        assert_ne!(zone.record_ref(replacement), original);
        assert!(matches!(
            zone.record(replacement).claim(),
            Claim::Parked { .. }
        ));
        assert_eq!(
            zone.record(replacement).entry_count(),
            1,
            "old producer removed the replacement waiter's queue entry"
        );
        assert_eq!(
            wake(&zone, replacement_address, 1, Waker::Host).unwrap(),
            [replacement]
        );
    } else {
        assert_eq!(zone.record(id).entry_count(), 0);
        assert!(
            zone.live(original).is_none(),
            "producer must retire a cancelled transfer"
        );
        assert_eq!(
            zone.alloc_record(identity(3)).unwrap(),
            id,
            "retirement must release the slot"
        );
    }
}

#[test]
fn host_wake_transfer_owns_waitv_cleanup_until_completion() {
    for cancel in [false, true] {
        let zone = zone();
        let addresses = [
            0x1000,
            (0x2000..0x3000)
                .step_by(4)
                .find(|addr| ZoneTables::bucket_of(MM, *addr) != ZoneTables::bucket_of(MM, 0x1000))
                .unwrap(),
        ];
        let record = zone.alloc_record(identity(1)).unwrap();
        let seq = zone.next_seq(record);
        // The fixture has no competing parker; both entries precede publish.
        for (index, address) in addresses.iter().enumerate() {
            let guard = zone
                .lock(ZoneTables::bucket_of(MM, *address), &HostWait)
                .unwrap();
            zone.enqueue(&guard, record, seq, MM, *address, u32::MAX, index as u32)
                .unwrap();
        }
        zone.publish_park(record, seq);
        let original = zone.record_ref(record);
        let mut pending = Vec::new();
        let guard = zone
            .lock(ZoneTables::bucket_of(MM, addresses[1]), &HostWait)
            .unwrap();
        assert_eq!(
            zone.wake_host(
                &guard,
                MM,
                addresses[1],
                u32::MAX,
                1,
                false,
                &mut |transfer| pending.push(transfer),
                &mut |_| panic!("host-only wake placed in guest")
            ),
            1
        );
        drop(guard);
        assert_eq!(zone.record(record).entry_count(), 1);
        assert!(matches!(
            zone.record(record).claim(),
            Claim::Transferring { .. }
        ));
        assert_eq!(
            zone.claim_for_host(
                original,
                None,
                if cancel {
                    Handback::Cancelled
                } else {
                    Handback::Signal
                },
                &HostWait
            ),
            HostClaim::Deferred
        );
        assert!(zone.live(original).is_some());
        let ready = pending.pop().unwrap().finish(&HostWait);
        assert_eq!(zone.record(record).entry_count(), 0);
        for address in addresses {
            let guard = zone
                .lock(ZoneTables::bucket_of(MM, address), &HostWait)
                .unwrap();
            assert_eq!(zone.buckets[guard.bucket()].len.load(Ordering::Relaxed), 0);
        }
        if cancel {
            assert!(ready.is_none());
            assert!(zone.live(original).is_none());
            assert_eq!(zone.alloc_record(identity(2)).unwrap(), record);
        } else {
            assert_eq!(ready, Some(original));
            assert!(matches!(zone.record(record).claim(), Claim::Host { .. }));
            assert_eq!(zone.record(record).result(), 1);
            assert_eq!(zone.record(record).handback(), Some(Handback::Woken));
        }
    }
}

#[test]
fn a_host_request_during_transfer_prevents_guest_relocation() {
    let zone = zone();
    enter(&zone, SLOT, 0);
    enter(&zone, OTHER, 1);
    let record = park(&zone, 1, 0x1000);
    let _ = wake(&zone, 0x1000, 1, Waker::El1 { slot: SLOT }).unwrap();
    let original = zone.record_ref(record);
    let Claim::Queued { slot, .. } = zone.record(record).claim() else {
        panic!("not queued")
    };
    let guard = zone.slot_lock(slot, &HostWait).unwrap();
    let transfer = zone
        .begin_host_transfer(original, zone.record(record).claim())
        .unwrap();
    assert!(zone.remove_locked(&guard, record));
    drop(guard);
    assert_eq!(
        zone.claim_for_host(original, None, Handback::Control, &HostWait),
        HostClaim::Deferred
    );
    let transfer = match transfer.place_in_guest(slot) {
        Err(transfer) => transfer,
        Ok(_) => panic!("pending host request lost to guest placement"),
    };
    assert_eq!(transfer.finish(&HostWait), Some(original));
    assert!(matches!(zone.record(record).claim(), Claim::Host { .. }));
}

#[test]
fn cancelled_on_cpu_claim_is_retired_by_the_next_handback() {
    let zone = zone();
    let record = park(&zone, 1, 0x1000);
    let _ = wake(&zone, 0x1000, 1, Waker::El1 { slot: SLOT }).unwrap();
    assert_eq!(zone.switch_in(SLOT), Some(record));
    let original = zone.record_ref(record);
    assert_eq!(
        zone.claim_for_host(original, None, Handback::Cancelled, &HostWait),
        HostClaim::El1Held { slot: SLOT }
    );
    // The vCPU can hand it back before the host handles El1Held. The
    // cancellation intent must already belong to this incarnation.
    assert_eq!(
        zone.handback_current(SLOT, record),
        CurrentHandback::Retired
    );
    assert!(zone.live(original).is_none());
    assert_eq!(zone.alloc_record(identity(2)).unwrap(), record);
}

#[test]
fn an_admitted_cancel_request_does_not_cancel_a_reused_record() {
    let zone = zone();
    let record = service_record(&zone, 1);
    let original = zone.record_ref(record);
    let admitted = zone.live(original).unwrap();
    // Preemption between the live check and the request store, as in the
    // host's former El1Held cancellation follow-up.
    zone.free_record(record);
    assert_eq!(zone.alloc_host_runnable(identity(2)).unwrap(), record);
    admitted.request_cancel(original.incarnation);
    assert!(
        !zone.record(record).is_cancelled(),
        "late cancellation reached replacement"
    );
}

#[test]
fn exhausted_record_incarnation_is_never_reallocated() {
    let zone = zone();
    let record = zone.alloc_host_runnable(identity(1)).unwrap();
    zone.record(record)
        .incarnation
        .store(u64::MAX, Ordering::Release);
    zone.free_record(record);
    assert_eq!(
        zone.record(record).incarnation(),
        u64::MAX,
        "incarnation exhaustion must not wrap to an old request identity"
    );
    assert_ne!(zone.alloc_host_runnable(identity(2)).unwrap(), record);
}

#[test]
fn late_host_requests_neither_target_nor_mask_a_new_incarnation() {
    let zone = zone();
    let record = park(&zone, 1, 0x1000);
    let original = zone.record_ref(record);
    let admitted = zone.live(original).unwrap();
    assert_eq!(
        zone.claim_for_host(original, None, Handback::Control, &HostWait),
        HostClaim::Claimed
    );
    zone.free_record(record);
    assert_eq!(park(&zone, 2, 0x1000), record);
    let replacement = zone.record_ref(record);
    admitted.host_wanted.publish(original.incarnation);
    assert!(!zone.record(record).host_wanted());
    admitted.host_wanted.publish(replacement.incarnation);
    admitted.host_wanted.publish(original.incarnation);
    assert!(
        zone.record(record).host_wanted(),
        "old publisher masked current request"
    );
    admitted.cancelled.publish(replacement.incarnation);
    admitted.cancelled.publish(original.incarnation);
    assert!(
        zone.record(record).is_cancelled(),
        "old publisher masked current cancellation"
    );
}

#[test]
fn host_request_wins_against_enrolled_guest_park() {
    for kind in [Handback::Signal, Handback::Control, Handback::Cancelled] {
        let zone = zone();
        let record = park(&zone, 1, 0x1000);
        wake(&zone, 0x1000, 1, Waker::El1 { slot: SLOT }).unwrap();
        assert_eq!(zone.switch_in(SLOT), Some(record));
        let original = zone.record_ref(record);
        let guard = zone
            .lock(ZoneTables::bucket_of(MM, 0x2000), &HostWait)
            .unwrap();
        let seq = zone.next_seq(record);
        zone.enqueue(&guard, record, seq, MM, 0x2000, u32::MAX, 0)
            .unwrap();
        zone.set_deadline(record, 100);
        zone.arm_timer(SLOT, record, seq);
        assert_eq!(
            zone.claim_for_host(original, None, kind, &HostWait),
            HostClaim::El1Held { slot: SLOT }
        );
        assert!(!zone.publish_guest_park(&guard, SLOT, record, seq));
        assert_eq!(zone.record(record).entry_count(), 0);
        assert!(zone.slot(SLOT).timer().is_none());
        assert_eq!(zone.slot(SLOT).current(), Some(record));
        drop(guard);
        assert_eq!(
            zone.handback_current(SLOT, record),
            if kind == Handback::Cancelled {
                CurrentHandback::Retired
            } else {
                CurrentHandback::HandedBack
            }
        );
    }
}

#[test]
fn host_request_after_guest_park_claims_the_published_wait() {
    let zone = zone();
    let record = park(&zone, 1, 0x1000);
    wake(&zone, 0x1000, 1, Waker::El1 { slot: SLOT }).unwrap();
    assert_eq!(zone.switch_in(SLOT), Some(record));
    let original = zone.record_ref(record);
    let guard = zone
        .lock(ZoneTables::bucket_of(MM, 0x2000), &HostWait)
        .unwrap();
    let seq = zone.next_seq(record);
    zone.enqueue(&guard, record, seq, MM, 0x2000, u32::MAX, 0)
        .unwrap();
    assert!(zone.publish_guest_park(&guard, SLOT, record, seq));
    drop(guard);
    zone.clear_current(SLOT);
    assert_eq!(
        zone.claim_for_host(original, None, Handback::Signal, &HostWait),
        HostClaim::Claimed
    );
    assert_eq!(zone.record(record).entry_count(), 0);
    assert_eq!(zone.record(record).handback(), Some(Handback::Signal));
}

#[test]
fn requested_running_records_survive_preemption_and_unswitch() {
    for preempt in [false, true] {
        let zone = zone();
        let record = park(&zone, 1, 0x1000);
        wake(&zone, 0x1000, 1, Waker::El1 { slot: SLOT }).unwrap();
        assert_eq!(zone.switch_in(SLOT), Some(record));
        let original = zone.record_ref(record);
        assert_eq!(
            zone.claim_for_host(original, None, Handback::Signal, &HostWait),
            HostClaim::El1Held { slot: SLOT }
        );
        if preempt {
            zone.requeue_preempted(SLOT, record);
        } else {
            zone.unswitch(SLOT, record);
        }
        assert_eq!(zone.slot(SLOT).current(), None);
        assert_eq!(zone.slot(SLOT).queued(), 1);
        let mut handed = Vec::new();
        assert_eq!(
            zone.take_host_wanted(SLOT, &mut |ready| handed.push(ready)),
            1
        );
        assert_eq!(handed, [original]);
        assert_eq!(zone.slot(SLOT).queued(), 0);
        assert_eq!(zone.record(record).entry_count(), 0);
    }
}

mod ipc_wait {
    use super::*;
    use crate::object_wait::*;

    fn key(index: u32, generation: u64) -> ObjectWaitKey {
        ObjectWaitKey::new(index, generation).unwrap()
    }

    fn token(index: u64) -> OperationToken {
        OperationToken::new(index, 9).unwrap()
    }

    fn object_park(zone: &ZoneTables, key: ObjectWaitKey, tid: u64) -> RecordId {
        let guard = zone.object_wait(key, &HostWait).unwrap();
        let record = zone.alloc_record(identity(tid)).unwrap();
        // SAFETY: newly allocated context, not yet published.
        unsafe {
            let ctx = zone.record(record).ctx_mut();
            ctx.x[0] = 0xfeed;
            ctx.pc = 0x8000;
        }
        guard.park(guard.snapshot(), record, token(tid)).unwrap();
        record
    }

    fn notify(zone: &ZoneTables, key: ObjectWaitKey) -> (ObjectWakeReport, WakeEffects) {
        let guard = zone.object_wait(key, &HostWait).unwrap();
        let mut effects = WakeEffects::default();
        let report = guard.notify_object(SLOT, &mut effects).unwrap();
        (report, effects)
    }

    #[test]
    fn el1_ipc_wait_recheck_preserves_pending_result() {
        let zone = zone();
        host_publish(&zone, SLOT, MM, None, 0);
        zone.enter_guest(SLOT);
        let key = key(1, 1);
        zone.bind_object_wait(key, &HostWait).unwrap();
        let record = object_park(&zone, key, 17);
        assert_eq!(notify(&zone, key).0.queued, 1);
        let switched = zone.switch_in_full(SLOT).unwrap();
        assert_eq!(switched.record, record);
        assert_eq!(
            switched.result, None,
            "readiness is not a completed zero-byte read"
        );
        assert_eq!(zone.record(record).handback(), Some(Handback::Resumed));
        // SAFETY: switched record is exclusively owned here.
        unsafe {
            assert_eq!(zone.record(record).ctx_mut().x[0], 0xfeed);
            assert_eq!(zone.record(record).take_object_operation(), Some(token(17)));
            assert_eq!(zone.record(record).take_object_operation(), None);
        }
    }

    #[test]
    fn el1_ipc_wait_check_enroll_park_race() {
        let zone = zone();
        host_publish(&zone, SLOT, MM, None, 0);
        zone.enter_guest(SLOT);
        let key = key(1, 1);
        zone.bind_object_wait(key, &HostWait).unwrap();
        let snapshot = zone.object_wait(key, &HostWait).unwrap().snapshot();
        // Readiness changes after the predicate check, before enrollment;
        // notification has no waiters but must invalidate the observation.
        assert_eq!(notify(&zone, key).0.visited, 0);
        let record = zone.alloc_record(identity(1)).unwrap();
        let guard = zone.object_wait(key, &HostWait).unwrap();
        let (error, operation) = guard.park(snapshot, record, token(1)).unwrap_err();
        assert_eq!(error, ObjectWaitError::Changed);
        assert!(!zone.record(record).has_object_operation());
        guard.park(guard.snapshot(), record, operation).unwrap();
        drop(guard);
        assert_eq!(notify(&zone, key).0.queued, 1);
    }

    #[test]
    fn el1_ipc_wait_object_and_record_reuse_reject_stale_identity() {
        let zone = zone();
        host_publish(&zone, SLOT, MM, None, 0);
        zone.enter_guest(SLOT);
        let old = key(1, 7);
        let new = key(1, 8);
        zone.bind_object_wait(old, &HostWait).unwrap();
        let record = object_park(&zone, old, 1);
        let stale = zone.record_ref(record);
        assert_eq!(
            zone.bind_object_wait(new, &HostWait),
            Err(ObjectWaitError::Occupied)
        );
        assert_eq!(
            zone.claim_for_host(stale, None, Handback::Cancelled, &HostWait),
            HostClaim::Claimed
        );
        zone.free_record(record);
        assert!(
            zone.live(stale).is_some(),
            "cannot recycle a pinned operation"
        );
        // SAFETY: host owns the claimed and unlinked record.
        assert_eq!(
            unsafe { zone.record(record).take_object_operation() },
            Some(token(1))
        );
        zone.free_record(record);
        assert!(zone.live(stale).is_none());
        zone.bind_object_wait(new, &HostWait).unwrap();
        assert!(matches!(
            zone.object_wait(old, &HostWait),
            Err(ObjectWaitError::Stale)
        ));
        assert_eq!(
            zone.bind_object_wait(old, &HostWait),
            Err(ObjectWaitError::Stale)
        );
        let replacement = object_park(&zone, new, 2);
        assert_eq!(
            zone.claim_for_host(stale, None, Handback::Control, &HostWait),
            HostClaim::Stale
        );
        assert!(matches!(
            zone.record(replacement).claim(),
            Claim::Parked { .. }
        ));
    }

    #[test]
    fn el1_ipc_wait_wake_signal_control_have_one_owner() {
        for kind in [Handback::Signal, Handback::Control, Handback::Cancelled] {
            for host_first in [true, false] {
                let zone = zone();
                host_publish(&zone, SLOT, MM, None, 0);
                zone.enter_guest(SLOT);
                let key = key(1, 1);
                zone.bind_object_wait(key, &HostWait).unwrap();
                let record = object_park(&zone, key, 1);
                if !host_first {
                    assert_eq!(notify(&zone, key).0.queued, 1);
                }
                assert_eq!(
                    zone.claim_for_host(zone.record_ref(record), None, kind, &HostWait),
                    HostClaim::Claimed
                );
                assert_eq!(notify(&zone, key).0.queued, 0);
                assert_eq!(zone.record(record).handback(), Some(kind));
                assert!(zone.switch_in_full(SLOT).is_none());
                // SAFETY: host owns it; both wait/run queues detached it.
                unsafe {
                    assert_eq!(zone.record(record).take_object_operation(), Some(token(1)));
                    assert_eq!(zone.record(record).take_object_operation(), None);
                }
                zone.free_record(record);
            }
        }
    }

    #[test]
    fn el1_ipc_wait_scales_with_affected_waiters_not_population() {
        for n in [1, 8, 64] {
            let zone = zone();
            host_publish(&zone, SLOT, MM, None, 0);
            zone.enter_guest(SLOT);
            let affected = key(1, 1);
            let unrelated = key(2, 1);
            zone.bind_object_wait(affected, &HostWait).unwrap();
            zone.bind_object_wait(unrelated, &HostWait).unwrap();
            for tid in 1..=128 {
                object_park(&zone, unrelated, tid);
            }
            for tid in 129..129 + n {
                object_park(&zone, affected, tid);
            }
            let (report, effects) = notify(&zone, affected);
            assert_eq!(
                report,
                ObjectWakeReport {
                    visited: n as u32,
                    queued: n as u32,
                    deferred: 0
                }
            );
            assert!(effects.queued_own);
            assert!(!effects.misplaced);
            assert_eq!(
                zone.slot(SLOT).queued(),
                n as usize,
                "one execution slot serves all waiters"
            );
            assert_eq!(
                zone.counters
                    .host_service_placements
                    .load(Ordering::Relaxed),
                0
            );
            assert_eq!(zone.counters.host_wakes.load(Ordering::Relaxed), 0);
            for _ in 0..n {
                let switched = zone.switch_in_full(SLOT).unwrap();
                assert_eq!(switched.result, None);
                let rec = zone.record(switched.record);
                // SAFETY: this slot owns this OnCpu record.
                assert!(unsafe { rec.take_object_operation() }.is_some());
                assert_eq!(
                    zone.release_current(SLOT, switched.record, &HostWait),
                    CurrentRelease::Released
                );
            }
            assert_eq!(notify(&zone, affected).0.visited, 0);
        }
    }

    #[test]
    fn el1_ipc_wait_concurrent_notify_and_control_detach_once() {
        let zone = zone();
        host_publish(&zone, SLOT, MM, None, 0);
        zone.enter_guest(SLOT);
        let key = key(1, 1);
        zone.bind_object_wait(key, &HostWait).unwrap();
        let records: Vec<_> = (1..=64).map(|tid| object_park(&zone, key, tid)).collect();
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();
                notify(&zone, key);
            });
            barrier.wait();
            for record in &records {
                assert_eq!(
                    zone.claim_for_host(
                        zone.record_ref(*record),
                        None,
                        Handback::Control,
                        &HostWait
                    ),
                    HostClaim::Claimed
                );
                // SAFETY: control claimed and detached this exact record.
                let operation = unsafe { zone.record(*record).take_object_operation() }.unwrap();
                assert_eq!(operation.index(), zone.record(*record).identity().tid);
                zone.free_record(*record);
            }
        });
        assert_eq!(notify(&zone, key).0.visited, 0);
        assert_eq!(zone.slot(SLOT).queued(), 0);
    }

    #[test]
    fn el1_ipc_wait_never_aliases_a_private_futex() {
        let zone = zone();
        host_publish(&zone, SLOT, MM, None, 0);
        zone.enter_guest(SLOT);
        let key = key(MM as u32, 0x1000);
        zone.bind_object_wait(key, &HostWait).unwrap();
        let object = object_park(&zone, key, 1);
        let futex = park(&zone, 2, 0x1000);
        assert_eq!(
            wake(&zone, 0x1000, 1, Waker::El1 { slot: SLOT }).unwrap(),
            [futex]
        );
        assert!(matches!(zone.record(object).claim(), Claim::Parked { .. }));
        assert_eq!(notify(&zone, key).0.queued, 1);
        assert_eq!(zone.record(futex).handback(), Some(Handback::Woken));
        assert_eq!(zone.record(object).handback(), Some(Handback::Resumed));
    }
    #[test]
    fn el1_ipc_wait_interruption_requires_adapter_settlement() {
        for kind in [Handback::Signal, Handback::Control] {
            let zone = zone();
            host_publish(&zone, SLOT, MM, None, 0);
            zone.enter_guest(SLOT);
            let key = key(1, 1);
            zone.bind_object_wait(key, &HostWait).unwrap();
            let record = object_park(&zone, key, 1);
            assert_eq!(
                zone.claim_for_host(zone.record_ref(record), None, kind, &HostWait),
                HostClaim::Claimed
            );
            assert!(
                zone.record(record).needs_host(),
                "pending interruption must not become a zero-byte completion"
            );
        }
    }

    #[test]
    fn el1_ipc_wait_cancelled_pin_reaches_adapter_before_recycling() {
        let zone = zone();
        host_publish(&zone, SLOT, MM, None, 0);
        zone.enter_guest(SLOT);
        let key = key(1, 1);
        zone.bind_object_wait(key, &HostWait).unwrap();
        let record = object_park(&zone, key, 1);
        notify(&zone, key);
        zone.record(record)
            .request_cancel(zone.record_ref(record).incarnation);
        assert_eq!(zone.sweep_cancelled(SLOT), 0);
        assert!(zone.head_needs_host(SLOT));
        assert!(zone.switch_in_full(SLOT).is_none());
        let mut taken = Vec::new();
        assert_eq!(zone.take_host_wanted(SLOT, &mut |r| taken.push(r)), 1);
        assert_eq!(taken, [zone.record_ref(record)]);
        assert_eq!(zone.record(record).handback(), Some(Handback::Cancelled));
        // SAFETY: host took the detached record.
        assert!(unsafe { zone.record(record).take_object_operation() }.is_some());
        zone.free_record(record);
        assert_eq!(zone.record(record).claim(), Claim::Free);
    }

    /// The loaded thread parks its pending object operation in EL1 (its
    /// home record), the object becomes ready and EL1 switches the thread
    /// back in at its SVC; the vCPU then leaves for the host before that SVC
    /// re-executes (host work was pending after the switch, so EL1 left with
    /// `ServedWithWork`; or a kick stopped it at EL0). The host boundary must
    /// leave nothing switched in on the slot, so the thread can be loaded on
    /// it again, and must keep the operation, which never resumed: the record
    /// goes back to the head of the run queue for the host to settle.
    #[test]
    fn a_host_boundary_requeues_the_own_record_switched_in_at_its_operation() {
        let zone = zone();
        host_publish(&zone, SLOT, MM, None, 0);
        zone.enter_guest(SLOT);
        let key = key(5, 1);
        zone.bind_object_wait(key, &HostWait).unwrap();
        let record = zone.current_or_new(SLOT, identity(23)).unwrap();
        {
            let guard = zone.object_wait(key, &HostWait).unwrap();
            // SAFETY: the slot's new home record, not yet published.
            unsafe { zone.record(record).ctx_mut().pc = 0x8000 };
            guard.park(guard.snapshot(), record, token(23)).unwrap();
        }
        zone.clear_current(SLOT);
        assert_eq!(notify(&zone, key).0.queued, 1);
        let switched = zone.switch_in_full(SLOT).unwrap();
        assert_eq!(switched.record, record);
        assert!(switched.home);
        zone.leave_guest(SLOT, &HostWait);
        assert_eq!(zone.slot(SLOT).current(), Some(record));
        assert_eq!(zone.slot(SLOT).host_record(), Some(record));
        assert_eq!(
            zone.release_current(SLOT, record, &HostWait),
            CurrentRelease::Requeued,
            "an operation EL1 never re-entered must not be retired"
        );
        assert_eq!(zone.slot(SLOT).current(), None);
        assert_eq!(zone.slot(SLOT).host_record(), Some(record));
        assert_eq!(zone.slot(SLOT).queued(), 1);
        assert!(matches!(zone.record(record).claim(), Claim::Queued { slot, .. } if slot == SLOT));
        assert!(zone.record(record).has_object_operation());
        // SAFETY: the record is untouched since the switch-in restored it.
        assert_eq!(unsafe { zone.record(record).ctx_mut().pc }, 0x8000);
        assert!(
            zone.reset_slot(SLOT),
            "the slot still held the switched-in record after the host boundary"
        );
    }

    #[test]
    fn cancelled_current_object_retains_cleanup_authority_through_host_transfer() {
        let zone = zone();
        host_publish(&zone, SLOT, MM, None, 0);
        zone.enter_guest(SLOT);
        let key = key(41, 1);
        zone.bind_object_wait(key, &HostWait).unwrap();
        let record = object_park(&zone, key, 71);
        assert_eq!(notify(&zone, key).0.queued, 1);
        assert_eq!(zone.switch_in(SLOT), Some(record));
        let identity = zone.record_ref(record);
        zone.record(record).request_cancel(identity.incarnation);
        assert_eq!(
            zone.handback_current(SLOT, record),
            CurrentHandback::HandedBack
        );
        assert_eq!(zone.record_ref(record), identity);
        assert!(matches!(zone.record(record).claim(), Claim::Host { .. }));
        assert_eq!(zone.record(record).handback(), Some(Handback::Cancelled));
        // SAFETY: the exact host transfer owns the detached operation.
        assert!(unsafe { zone.record(record).take_object_operation() }.is_some());
        zone.free_record(record);
        assert_eq!(zone.record(record).claim(), Claim::Free);
    }
}
