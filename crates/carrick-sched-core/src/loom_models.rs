//! Bounded exploration of production first-entry admission, Closing, queues,
//! retirement and index reuse. Only table capacities and atomic storage differ.
//! Native-only subordinate tables stay zero/unused (no waits, timers or MM edits).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use loom::{model::Builder, sync::Arc, thread};
use std::boxed::Box;

fn model(body: impl Fn() + Send + Sync + 'static) {
    model_with_bound(3, body);
}

fn model_composed(body: impl Fn() + Send + Sync + 'static) {
    model_with_bound(2, body);
}

fn model_with_bound(bound: usize, body: impl Fn() + Send + Sync + 'static) {
    // Focused race pairs use 3 preemptions; composed three-actor cases use
    // 2 (the repository's baseline). These are CAS/slot-lock protocols, not
    // Dekker pairs. No duration/permutation cap truncates exploration;
    // exceeding the branch budget fails the test.
    let mut builder = Builder::new();
    builder.preemption_bound = Some(bound);
    builder.max_permutations = None;
    builder.max_duration = None;
    builder.max_branches = 10_000;
    builder.check(body);
}

fn zone() -> Arc<Box<ZoneTables>> {
    // Construction uses more stack than loom's 4 KiB default coroutine.
    thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(make_zone)
        .unwrap()
        .join()
        .unwrap()
}

fn make_zone() -> Arc<Box<ZoneTables>> {
    let layout = std::alloc::Layout::new::<ZoneTables>();
    // SAFETY: native subordinate tables admit zero bytes. Before making a
    // reference, replace EVERY field containing loom atomics by constructed
    // objects; loom atomics must never be zero-initialized or byte-copied.
    unsafe {
        let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables>();
        assert!(!ptr.is_null());
        macro_rules! init {
            ($field:ident, $value:expr) => {
                core::ptr::addr_of_mut!((*ptr).$field).write($value);
            };
        }
        init!(buckets, core::array::from_fn(|_| ZoneBucket::default()));
        init!(slots, core::array::from_fn(|_| ZoneSlot::default()));
        init!(entries, core::array::from_fn(|_| ZoneEntry::default()));
        init!(counters, ZoneCounters::default());
        init!(timers, timer_index::Index::default());
        init!(record_map, core::array::from_fn(|_| AtomicU64::new(0)));
        init!(entry_map, core::array::from_fn(|_| AtomicU64::new(0)));
        init!(idle_map, core::array::from_fn(|_| AtomicU64::new(0)));
        init!(queued_map, core::array::from_fn(|_| AtomicU64::new(0)));
        init!(completion_consumer, AtomicU32::new(0));
        init!(
            delegated_host_pending,
            core::array::from_fn(|_| AtomicU64::new(0))
        );
        init!(
            records,
            core::array::from_fn(|_| ZoneRecord {
                claim: AtomicU64::new(0),
                incarnation: AtomicU64::new(0),
                tid: AtomicU64::new(0),
                serial: AtomicU64::new(0),
                mm: AtomicU64::new(0),
                file_table: AtomicU64::new(0),
                generation: AtomicU64::new(0),
                lifecycle_page: AtomicU64::new(0),
                control_slot: AtomicU64::new(0),
                result: AtomicU64::new(0),
                handback: AtomicU32::new(0),
                first_entry: AtomicU32::new(0),
                entry_count: AtomicU32::new(0),
                last_seq: AtomicU32::new(0),
                home: AtomicU32::new(0),
                last_slot: AtomicU32::new(0),
                next: AtomicU32::new(0),
                deadline: AtomicU64::new(0),
                affinity: AtomicU64::new(0),
                cancelled: IncarnationRequest(AtomicU64::new(0)),
                host_wanted: HostRequest(AtomicU64::new(0)),
                object: core::mem::zeroed(),
                ctx: UnsafeCell::new(zerocopy::FromZeros::new_zeroed()),
            })
        );
        Arc::from(Box::from_raw(ptr))
    }
}

const SLOT: SlotId = SlotId::new(0);
fn birth(zone: &ZoneTables) -> RecordRef {
    let id = zone
        .alloc_host_runnable(ThreadIdentity {
            tid: 1,
            serial: 1,
            mm: 7,
            file_table: 1,
            generation: 0,
            lifecycle_page: 1,
            control_slot: 1,
            affinity: 0,
        })
        .unwrap();
    zone.record_ref(id)
}

#[test]
fn release_races_closing_without_losing_custody() {
    model(|| {
        let zone = zone();
        let record = birth(&zone);
        let custody = zone.claim_first_entry_placement(record).unwrap();
        let producer_zone = zone.clone();
        let producer = thread::spawn(move || {
            let custody = producer_zone.place_first_entry(custody).unwrap_err();
            producer_zone.release_first_entry_placement(custody)
        });
        let closing_zone = zone.clone();
        let closing = thread::spawn(move || {
            closing_zone.claim_for_host(record, None, Handback::Control, &SpinForever)
        });
        let released = producer.join().unwrap();
        closing.join().unwrap();
        assert!(released, "P1 release consumed custody after request CAS");
        assert!(
            matches!(zone.record(record.id).claim(), Claim::FirstEntryHost { .. }),
            "Closing has no eligible owner: {:?}",
            zone.record(record.id).claim()
        );
    });
}

#[test]
fn requested_fallback_on_wfi_owes_a_kick() {
    model(|| {
        let zone = zone();
        let record = birth(&zone);
        zone.record(record.id)
            .last_slot
            .store(SLOT.plus_one(), Ordering::Relaxed);
        let custody = zone.claim_first_entry_placement(record).unwrap();
        // The sleeping/away last driver is ineligible for normal placement.
        assert!(zone.enter_idle(SLOT, true));
        assert_eq!(
            zone.claim_for_host(record, None, Handback::Control, &SpinForever),
            HostClaim::Deferred
        );
        let placement = zone.place_first_entry(custody).ok().unwrap();
        assert!(placement.resched, "WFI receipt must force the vCPU out");
        assert_eq!(placement.slot, SLOT);
        assert!(
            zone.take_resched(SLOT),
            "P1 queued record behind WFI without kick debt"
        );
    });
}

fn stale_admission(placement: bool) {
    model(move || {
        let zone = zone();
        let old = birth(&zone);
        let stale_zone = zone.clone();
        let stale = thread::spawn(move || {
            if placement {
                if let Some(custody) = stale_zone.claim_first_entry_placement(old) {
                    assert_eq!(
                        stale_zone.record(old.id).incarnation(),
                        old.incarnation,
                        "P1 placement token for recycled incarnation"
                    );
                    assert!(stale_zone.release_first_entry_placement(custody));
                }
            } else if let Some(custody) = stale_zone.claim_current_first_entry_activation(old) {
                assert_eq!(
                    stale_zone.record(old.id).incarnation(),
                    old.incarnation,
                    "P1 activation token for recycled incarnation"
                );
                assert!(stale_zone.release_first_entry_activation(custody));
            }
        });
        // A real executor may finish the old birth before stale admission's
        // CAS. Reuse the same allocator index, not a fabricated old token.
        if let Some(custody) = zone.claim_current_first_entry_activation(old) {
            assert!(zone.free_first_entry_activation(custody));
            let new = birth(&zone);
            assert_eq!(new.id, old.id);
            assert_ne!(new.incarnation, old.incarnation);
        }
        stale.join().unwrap();
        assert!(matches!(
            zone.record(old.id).claim(),
            Claim::FirstEntryHost { .. }
        ));
    });
}
#[test]
fn mint_rejects_recycled_incarnation() {
    stale_admission(false);
}
#[test]
fn placement_rejects_recycled_incarnation() {
    stale_admission(true);
}

/// Adapter effects are counted only while holding real scheduler activation
/// custody. The graph/ledger adoption itself is covered by kernel/runtime
/// contract tests, not replaced by a second graph in this model.
fn finish(zone: &ZoneTables, custody: FirstEntryActivation, deliveries: &AtomicU32) {
    let record = custody.record();
    assert_eq!(zone.record(record.id).incarnation(), record.incarnation);
    assert!(
        zone.first_entry_links_clear_for_test(record, &SpinForever)
            .unwrap()
    );
    assert_eq!(
        deliveries.fetch_add(1, Ordering::AcqRel),
        0,
        "duplicate adoption/delivery"
    );
    // Production graph adoption does not rewrite this zone birth's
    // generation. Keep its eligibility bytes unchanged until retirement.
    assert!(
        zone.free_first_entry_activation(custody),
        "retirement refused"
    );
    assert_eq!(zone.record(record.id).claim(), Claim::Free);
    assert_eq!(
        zone.record(record.id).incarnation(),
        record.incarnation + 1,
        "retirement must advance the exact incarnation once"
    );
    assert_eq!(
        zone.slot(SLOT).head.load(Ordering::Acquire),
        NIL,
        "linked after free"
    );
    assert_eq!(
        zone.slot(SLOT).tail.load(Ordering::Acquire),
        NIL,
        "tail linked after free"
    );
    assert_eq!(zone.slot(SLOT).len.load(Ordering::Acquire), 0);
}

#[test]
fn producer_closing_executor_and_second_birth_complete_once() {
    model_composed(|| {
        let zone = zone();
        {
            let record = birth(&zone);
            let deliveries = Arc::new(AtomicU32::new(0));
            let producer_zone = zone.clone();
            let producer = thread::spawn(move || {
                if let Some(custody) = producer_zone.claim_first_entry_placement(record)
                    && let Err(custody) = producer_zone.place_first_entry(custody)
                {
                    assert!(producer_zone.release_first_entry_placement(custody));
                }
            });
            let closing_zone = zone.clone();
            let closing = thread::spawn(move || {
                closing_zone.claim_for_host(record, None, Handback::Control, &SpinForever)
            });
            if let Some(custody) = zone.claim_current_first_entry_activation(record) {
                finish(&zone, custody, &deliveries);
            }
            producer.join().unwrap();
            closing.join().unwrap();
            let state = zone.record(record.id).claim();
            assert!(
                matches!(state, Claim::FirstEntryHost { .. } | Claim::Free),
                "Closing has no eligible or terminal record: {state:?}"
            );
            if !matches!(state, Claim::Free) {
                finish(
                    &zone,
                    zone.claim_current_first_entry_activation(record).unwrap(),
                    &deliveries,
                );
            }
            assert_eq!(deliveries.load(Ordering::Acquire), 1);
            let replacement = birth(&zone);
            assert_eq!(replacement.id, record.id);
            assert_ne!(replacement.incarnation, record.incarnation);
            assert!(zone.claim_current_first_entry_activation(record).is_none());
            let next_delivery = AtomicU32::new(0);
            finish(
                &zone,
                zone.claim_current_first_entry_activation(replacement)
                    .unwrap(),
                &next_delivery,
            );
            assert_eq!(next_delivery.load(Ordering::Acquire), 1);
        }
    });
}

#[test]
fn two_executors_take_mint_and_retire_one_service_delivery() {
    model(|| {
        let zone = zone();
        let record = birth(&zone);
        zone.drive(SLOT, 1);
        let custody = zone.claim_first_entry_placement(record).unwrap();
        assert!(zone.place_first_entry(custody).is_ok());
        let deliveries = Arc::new(AtomicU32::new(0));
        let peer_zone = zone.clone();
        let peer_deliveries = deliveries.clone();
        let peer = thread::spawn(move || {
            if let Some(custody) = peer_zone.claim_current_first_entry_activation(record) {
                finish(&peer_zone, custody, &peer_deliveries);
            }
        });
        if let Some(head) = zone.take_service_head_for_executor(SLOT) {
            match head {
                ServiceHead::FirstEntry(custody) => finish(&zone, custody, &deliveries),
                ServiceHead::Record(_) => panic!("birth lost activation custody"),
            }
        }
        peer.join().unwrap();
        assert_eq!(deliveries.load(Ordering::Acquire), 1);
        assert_eq!(zone.record(record.id).claim(), Claim::Free);
        assert_eq!(zone.slot(SLOT).len.load(Ordering::Acquire), 0);
    });
}

#[test]
fn wfi_entry_races_fallback_publication() {
    model(|| {
        let zone = zone();
        let record = birth(&zone);
        let sleeper_zone = zone.clone();
        let sleeper = thread::spawn(move || sleeper_zone.enter_idle(SLOT, true));
        let placement = zone.requeue_on(SLOT, record.id).unwrap();
        let sleeping = sleeper.join().unwrap();
        assert!(
            !sleeping || placement.resched,
            "missing physical-kick receipt"
        );
        assert!(
            !sleeping || zone.take_resched(SLOT),
            "P1 sleep and fallback publication missed each other"
        );
        assert_eq!(zone.slot(SLOT).len.load(Ordering::Acquire), 1);
    });
}

#[test]
fn closing_producer_executor_sleep_and_reuse_preserve_delivery() {
    model_composed(|| {
        let zone = zone();
        let record = birth(&zone);
        zone.record(record.id)
            .last_slot
            .store(SLOT.plus_one(), Ordering::Relaxed);
        zone.drive(SLOT, 1);
        let deliveries = AtomicU32::new(0);
        let kicks = Arc::new(AtomicU32::new(0));
        let producer_zone = zone.clone();
        let producer_kicks = kicks.clone();
        let producer = thread::spawn(move || {
            if let Some(custody) = producer_zone.claim_first_entry_placement(record) {
                match producer_zone.place_first_entry(custody) {
                    Ok(placement) => {
                        if placement.resched {
                            assert!(producer_zone.take_resched(placement.slot));
                            assert_eq!(producer_kicks.fetch_add(1, Ordering::AcqRel), 0);
                        }
                    }
                    Err(custody) => assert!(producer_zone.release_first_entry_placement(custody)),
                }
            }
        });
        let closing_zone = zone.clone();
        let closing = thread::spawn(move || {
            closing_zone.claim_for_host(record, None, Handback::Control, &SpinForever)
        });
        zone.enter_idle(SLOT, true);
        if let Some(ServiceHead::FirstEntry(custody)) = zone.take_service_head_for_executor(SLOT) {
            finish(&zone, custody, &deliveries);
        }
        producer.join().unwrap();
        closing.join().unwrap();
        match zone.record(record.id).claim() {
            Claim::Queued { slot, .. } => {
                assert!(
                    zone.slot(slot).state() != SlotState::IdleWfi
                        || zone.slot(slot).resched_owed.load(Ordering::Acquire) != 0
                        || kicks.load(Ordering::Acquire) == 1,
                    "queued behind WFI with neither owed nor delivered kick"
                );
                match zone.take_service_head_for_executor(slot).unwrap() {
                    ServiceHead::FirstEntry(custody) => finish(&zone, custody, &deliveries),
                    ServiceHead::Record(_) => panic!("birth escaped activation custody"),
                }
            }
            Claim::FirstEntryHost { .. } => finish(
                &zone,
                zone.claim_current_first_entry_activation(record).unwrap(),
                &deliveries,
            ),
            Claim::Free => {}
            state => panic!("Closing cannot complete from {state:?}"),
        }
        assert_eq!(deliveries.load(Ordering::Acquire), 1);
        let replacement = birth(&zone);
        assert_ne!(record.incarnation, replacement.incarnation);
        assert!(zone.claim_current_first_entry_activation(record).is_none());
        assert!(zone.claim_first_entry_placement(record).is_none());
        finish(
            &zone,
            zone.claim_current_first_entry_activation(replacement)
                .unwrap(),
            &AtomicU32::new(0),
        );
    });
}

#[test]
fn stale_placement_releases_replacement_despite_its_closing_request() {
    model(|| {
        let zone = zone();
        let old = birth(&zone);
        let stale_zone = zone.clone();
        let stale = thread::spawn(move || {
            if let Some(custody) = stale_zone.claim_first_entry_placement(old) {
                assert_eq!(stale_zone.record(old.id).incarnation(), old.incarnation);
                assert!(stale_zone.release_first_entry_placement(custody));
            }
        });
        if let Some(custody) = zone.claim_current_first_entry_activation(old) {
            assert!(zone.free_first_entry_activation(custody));
            let replacement = birth(&zone);
            let closing_zone = zone.clone();
            let closing = thread::spawn(move || {
                closing_zone.claim_for_host(replacement, None, Handback::Control, &SpinForever)
            });
            closing.join().unwrap();
        }
        stale.join().unwrap();
        assert!(
            matches!(zone.record(old.id).claim(), Claim::FirstEntryHost { .. }),
            "rejected stale acquisition poisoned replacement custody"
        );
    });
}

#[test]
fn closing_republishes_while_producer_and_executor_contend() {
    model_composed(|| {
        let zone = zone();
        let record = birth(&zone);
        zone.drive(SLOT, 1);
        zone.record(record.id)
            .last_slot
            .store(SLOT.plus_one(), Ordering::Relaxed);
        let deliveries = AtomicU32::new(0);
        let producer_zone = zone.clone();
        let producer = thread::spawn(move || {
            if let Some(custody) = producer_zone.claim_first_entry_placement(record)
                && let Err(custody) = producer_zone.place_first_entry(custody)
            {
                assert!(producer_zone.release_first_entry_placement(custody));
            }
        });
        let closing_zone = zone.clone();
        let closing = thread::spawn(move || {
            let claim = closing_zone.claim_for_host(record, None, Handback::Control, &SpinForever);
            // The real handback adapter routes Claimed/AlreadyHost records
            // through first-entry admission; Deferred belongs to its owner.
            if matches!(claim, HostClaim::Claimed | HostClaim::AlreadyHost)
                && let Some(custody) = closing_zone.claim_first_entry_placement(record)
                && let Err(custody) = closing_zone.place_first_entry(custody)
            {
                assert!(closing_zone.release_first_entry_placement(custody));
            }
        });
        if let Some(ServiceHead::FirstEntry(custody)) = zone.take_service_head_for_executor(SLOT) {
            finish(&zone, custody, &deliveries);
        } else if let Some(custody) = zone.claim_current_first_entry_activation(record) {
            finish(&zone, custody, &deliveries);
        }
        producer.join().unwrap();
        closing.join().unwrap();
        match zone.record(record.id).claim() {
            Claim::Queued { slot, .. } => {
                match zone.take_service_head_for_executor(slot).unwrap() {
                    ServiceHead::FirstEntry(custody) => finish(&zone, custody, &deliveries),
                    ServiceHead::Record(_) => panic!("republished birth lost activation custody"),
                }
            }
            Claim::FirstEntryHost { .. } => finish(
                &zone,
                zone.claim_current_first_entry_activation(record).unwrap(),
                &deliveries,
            ),
            Claim::Free => {}
            state => panic!("Closing left an ineligible record: {state:?}"),
        }
        assert_eq!(deliveries.load(Ordering::Acquire), 1);
        assert_eq!(zone.slot(SLOT).head.load(Ordering::Acquire), NIL);
        assert_eq!(zone.slot(SLOT).tail.load(Ordering::Acquire), NIL);
    });
}

#[test]
fn stale_mint_cannot_consume_reused_service_head_delivery() {
    model(|| {
        let zone = zone();
        let old = birth(&zone);
        zone.drive(SLOT, 1);
        let stale_zone = zone.clone();
        let stale = thread::spawn(move || {
            if let Some(custody) = stale_zone.claim_current_first_entry_activation(old) {
                assert_eq!(stale_zone.record(old.id).incarnation(), old.incarnation);
                assert!(stale_zone.release_first_entry_activation(custody));
            }
        });
        if let Some(custody) = zone.claim_current_first_entry_activation(old) {
            assert!(zone.free_first_entry_activation(custody));
            let replacement = birth(&zone);
            assert_eq!(replacement.id, old.id);
            assert!(zone.place_from_host(replacement.id).is_some());
            // A stale caller owns no adoption of the replacement. Taking its
            // real service head therefore owes a real first-entry delivery,
            // not merely an unqueued Host state that nobody will rediscover.
            match zone.take_service_head_for_executor(SLOT) {
                Some(ServiceHead::FirstEntry(custody)) => {
                    finish(&zone, custody, &AtomicU32::new(0));
                }
                _ => panic!("stale mint consumed the replacement's service delivery"),
            }
        }
        stale.join().unwrap();
    });
}
