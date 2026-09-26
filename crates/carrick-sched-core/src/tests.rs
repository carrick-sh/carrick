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
        zone.publish_slot(slot, MM, None, 0);
    }
    let guard = zone
        .lock(ZoneTables::bucket_of(MM, uaddr), &HostWait)
        .unwrap();
    let mut woken = [RecordId::PLACEHOLDER; 64];
    let n = zone.wake(&guard, MM, uaddr, u32::MAX, count, waker, &mut woken)?;
    Ok(woken[..n as usize].to_vec())
}

/// Drain `slot` as its executor does at an exit: (handed back, discarded).
fn drain(zone: &ZoneTables, slot: SlotId) -> (Vec<RecordId>, Vec<RecordId>, SlotDrain) {
    let mut woken = Vec::new();
    let mut discarded = Vec::new();
    let drain = zone.drain_slot(slot, &mut |record, discard| {
        if discard {
            discarded.push(record);
        } else {
            woken.push(record);
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
    zone.publish_slot(SLOT, MM, None, 0);
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
        let _ = drain(&zone, SLOT);
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
    zone.publish_slot(slot, MM, Some(cpu), 0);
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
    let mut woken = [RecordId::PLACEHOLDER; 16];
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
        .map(|n| woken[..n as usize].to_vec());
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

/// The slot's timer ends its home thread's timed park with ETIMEDOUT, once;
/// a waker that wins the record first leaves the timer nothing to claim.
#[test]
fn the_slot_timer_ends_a_timed_park_once() {
    let zone = zone();
    enter(&zone, SLOT, 0);
    let a = el1_park(&zone, SLOT, 1, 0x1000, 500);
    assert_eq!(zone.timer_deadline(SLOT), Some(500));
    assert_eq!(zone.expire_timer(SLOT, 499), Ok(false));
    assert_eq!(zone.expire_timer(SLOT, 500), Ok(true));
    assert_eq!(zone.record(a).claim(), Claim::Queued { slot: SLOT, seq: 1 });
    assert_eq!(zone.record(a).entry_count(), 0);
    assert_eq!(zone.timer_deadline(SLOT), None);
    assert_eq!(zone.expire_timer(SLOT, 900), Ok(false));
    let switched = zone.switch_in_full(SLOT).unwrap();
    assert_eq!(switched.result, Some(ETIMEDOUT_RESULT));
    assert!(switched.home);
    // Woken before the deadline: the timer finds the park over.
    let b = el1_park(&zone, SLOT, 1, 0x1000, 500);
    assert_eq!(b, a, "the loaded thread parks into its record again");
    assert!(!zone.enter_idle(SLOT, false));
    let guard = zone
        .lock(ZoneTables::bucket_of(MM, 0x1000), &HostWait)
        .unwrap();
    let mut woken = [RecordId::PLACEHOLDER; 4];
    assert_eq!(
        zone.wake(&guard, MM, 0x1000, u32::MAX, 1, Waker::Host, &mut woken),
        Ok(1)
    );
    drop(guard);
    assert!(matches!(zone.record(b).claim(), Claim::Host { .. }));
    assert_eq!(zone.expire_timer(SLOT, 900), Ok(false));
    assert_eq!(zone.counters.el1_timeouts.load(Ordering::Relaxed), 1);
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
    zone.publish_slot(OTHER, 0, Some(1), 0);
    zone.enter_guest(OTHER);
    assert!(!zone.enter_idle(OTHER, false));
    assert!(zone.enter_idle(OTHER, true));
    assert!(zone.reset_slot(THIRD));
    zone.publish_slot(THIRD, MM + 1, Some(2), 0);
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

/// Stealing never takes a home record (its thread must run where the host
/// loaded it) and never a thread the thief's address space cannot run; a
/// service thread moves to the thief's queue for it to serve.
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
    zone.publish_slot(THIRD, MM, Some(2), 0);
    zone.enter_guest(THIRD);
    assert!(!zone.enter_idle(THIRD, false));
    assert_eq!(zone.steal(THIRD), None, "a home record is not stolen");
    // A service thread on OTHER moves to the idle thief's queue.
    let service = service_record(&zone, 5);
    zone.leave_guest(OTHER, &HostWait);
    let placed = zone.place_from_host(service).unwrap();
    assert_eq!(placed.slot, THIRD, "the idle slot is chosen first");
    assert!(zone.head_needs_host(THIRD));
    // An idle slot of another address space takes neither EL0 thread.
    let foreign = SlotId::new(11);
    assert!(zone.reset_slot(foreign));
    zone.publish_slot(foreign, MM + 7, Some(3), 0);
    zone.enter_guest(foreign);
    assert!(!zone.enter_idle(foreign, false));
    let ready = park(&zone, 6, 0x8004);
    let (woken, _) = wake_effects(&zone, 0x8004, 1, SLOT);
    assert_eq!(woken.unwrap(), [ready]);
    let ready_slot = match zone.record(ready).claim() {
        Claim::Queued { slot, .. } => slot,
        other => panic!("{other:?}"),
    };
    // It takes the service thread (any vCPU may serve one) onto its own
    // queue, but not the EL0 thread of MM.
    assert_eq!(zone.steal(foreign), None);
    assert!(zone.head_needs_host(foreign));
    assert_eq!(zone.counters.el1_steals.load(Ordering::Relaxed), 1);
    assert_eq!(zone.steal(foreign), None);
    assert_eq!(
        zone.record(ready).claim(),
        Claim::Queued {
            slot: ready_slot,
            seq: 1
        }
    );
    assert_eq!(zone.counters.el1_steals.load(Ordering::Relaxed), 1);
}
