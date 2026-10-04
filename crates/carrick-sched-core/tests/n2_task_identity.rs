//! D-prep: production scheduler storage refuses exhaustion and authenticates
//! late completions by record incarnation, not reusable TID/MM numbers.
//! These are scheduler custody witnesses, not Linux process/uid/executor tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::Ordering;

use carrick_sched_core::{
    BoundedSpin, Claim, Handback, HostClaim, ThreadIdentity, ZONE_RECORDS, ZoneTables,
};

fn zone() -> Box<ZoneTables> {
    // SAFETY: the shared ABI's all-zero state is its empty initialization,
    // as in the crate's existing tests. Heap allocation avoids a large stack.
    unsafe {
        let layout = std::alloc::Layout::new::<ZoneTables>();
        let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables>();
        if ptr.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        Box::from_raw(ptr)
    }
}

fn identity(parent: u64, tid: u64) -> ThreadIdentity {
    ThreadIdentity {
        tid,
        serial: tid * 10,
        mm: parent,
        generation: 1,
        file_table: parent + 100,
        affinity: 0,
        lifecycle_page: 0,
        control_slot: 0,
    }
}

fn no_host_services(zone: &ZoneTables) {
    let counters = &zone.counters;
    for value in [
        &counters.el1_service_exits,
        &counters.service_adoptions,
        &counters.host_service_placements,
        &counters.host_executor_parks,
        &counters.host_queue_claims,
    ] {
        assert_eq!(value.load(Ordering::Acquire), 0);
    }
}

#[test]
fn stale_completion_after_exact_identity_reuse_at_1_8_32() {
    for n in [1, 8, 32] {
        let zone = zone();
        let parents = [
            zone.alloc_record(identity(7, 1)).unwrap(),
            zone.alloc_record(identity(8, 2)).unwrap(),
        ];
        for parent in parents {
            let seq = zone.next_seq(parent);
            zone.publish_park(parent, seq);
        }
        for parent in [7, 8] {
            let mut children = Vec::new();
            for i in 0..n {
                children.push(zone.alloc_record(identity(parent, 10 + i)).unwrap());
            }
            let mut replacements = Vec::new();
            for child in children {
                let old = zone.record_ref(child);
                let exact_identity = zone.record(child).identity();
                zone.free_record(child);
                // Reuse every visible identity field: the allocator's record
                // incarnation is the only authority distinguishing this birth.
                let replacement = zone.alloc_record(exact_identity).unwrap();
                assert_eq!(replacement, child);
                let live = zone.record_ref(replacement);
                assert_ne!(live, old);
                let seq = zone.next_seq(replacement);
                zone.publish_park(replacement, seq);
                let expected = Claim::Parked { seq };
                for reason in [Handback::Woken, Handback::Cancelled, Handback::Control] {
                    assert_eq!(
                        zone.claim_for_host(old, Some(seq), reason, &BoundedSpin(16)),
                        HostClaim::Stale
                    );
                    assert_eq!(zone.record(replacement).claim(), expected);
                    assert!(zone.live(live).is_some());
                    assert!(!zone.record(replacement).is_cancelled());
                }
                replacements.push(replacement);
            }
            for replacement in replacements {
                zone.free_record(replacement);
            }
        }
        for parent in parents {
            assert!(zone.live(zone.record_ref(parent)).is_some());
        }
        no_host_services(&zone);
    }
}

#[test]
fn full_record_pool_refuses_birth_without_mutating_two_parents_at_1_8_32() {
    for n in [1, 8, 32] {
        let zone = zone();
        let parents = [
            zone.alloc_record(identity(7, 1)).unwrap(),
            zone.alloc_record(identity(8, 2)).unwrap(),
        ];
        for parent in parents {
            let seq = zone.next_seq(parent);
            zone.publish_park(parent, seq);
        }
        let parent_refs = parents.map(|p| zone.record_ref(p));
        let mut records = Vec::new();
        // Fill the actual fixed ABI pool; no smaller model or larger pool.
        for i in 0..ZONE_RECORDS - 3 {
            records.push(
                zone.alloc_record(identity(7 + (i % 2) as u64, 10 + i as u64))
                    .unwrap(),
            );
        }
        for parent in [7, 8] {
            for i in 0..n {
                assert!(zone.alloc_record(identity(parent, 10000 + i)).is_err());
            }
        }
        assert_eq!(zone.counters.exhausted.load(Ordering::Acquire), 2 * n);
        for (parent, reference) in parents.into_iter().zip(parent_refs) {
            assert!(zone.live(reference).is_some());
            assert_eq!(zone.record(parent).claim(), Claim::Parked { seq: 1 });
        }
        let retired = records.pop().unwrap();
        zone.free_record(retired);
        let replacement = zone.alloc_record(identity(8, 20000)).unwrap();
        assert_eq!(replacement, retired, "one retired record frees one slot");
        assert!(zone.alloc_record(identity(7, 20001)).is_err());
        no_host_services(&zone);
    }
}
