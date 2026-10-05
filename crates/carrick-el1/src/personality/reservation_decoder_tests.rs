use crate::memory::reservations::*;
use core::sync::atomic::Ordering;
use std::boxed::Box;
fn table() -> Box<SharedReservations> {
    let ptr = unsafe { std::alloc::alloc_zeroed(std::alloc::Layout::new::<SharedReservations>()) };
    assert!(!ptr.is_null());
    unsafe { Box::from_raw(ptr.cast()) }
}
fn layout() -> Layout {
    Layout {
        heap: ReservationRange::new(0x1000, 0x100000).unwrap(),
        arena: ReservationRange::new(0x100000, 0x1000000).unwrap(),
        brk: 0x1000,
        address_limit: u64::MAX,
        data_limit: u64::MAX,
        external_address_bytes: 0,
        external_data_bytes: 0,
    }
}
fn admitted(table: &SharedReservations, index: usize, raw: u64) -> Reservations<'_> {
    let mm = ReservationMm::new(raw).unwrap();
    table.publish(index, mm, layout()).unwrap();
    let mut root = table.lock(index, mm).unwrap();
    root.finish_import().unwrap();
    root
}

fn decide(model: &mut Reservations<'_>, nr: u64, args: [u64; 6]) -> AnonymousRouteKind {
    use crate::{AnonymousReservationRoute, dispatch_anonymous_with_reservations};
    let current = CurrentTask::new();
    current.task_id.store(1, Ordering::Relaxed);
    current.thread_serial.store(11, Ordering::Relaxed);
    current.zone_mm.store(model.mm().raw(), Ordering::Relaxed);
    let counters = Counters::default();
    let mut frame = TrapFrame::default();
    frame.x[8] = nr;
    frame.x[..6].copy_from_slice(&args);
    match dispatch_anonymous_with_reservations(&mut frame, &counters, &current, model) {
        AnonymousReservationRoute::Action(Action::Forward) => AnonymousRouteKind::Forward,
        AnonymousReservationRoute::Action(Action::Served) => {
            AnonymousRouteKind::Return(frame.x[0] as i64)
        }
        AnonymousReservationRoute::Work(mut pending) => {
            pending
                .refuse(&mut frame, &current, &counters, model)
                .unwrap();
            AnonymousRouteKind::Work
        }
        _ => AnonymousRouteKind::Other,
    }
}
#[derive(Debug, PartialEq, Eq)]
enum AnonymousRouteKind {
    Forward,
    Return(i64),
    Work,
    Other,
}
#[test]
fn reservation_decoder_counts_completion_only_and_keeps_two_mm_origins() {
    use crate::{AnonymousReservationRoute, dispatch_anonymous_with_reservations};
    for rounds in [1, 8, 64] {
        let table = table();
        let counters = Counters::default();
        for slot in 0..2 {
            let mm = ReservationMm::new(slot as u64 + 17).unwrap();
            table.publish(slot, mm, layout()).unwrap();
            table.lock(slot, mm).unwrap().finish_import().unwrap();
        }
        for _ in 0..rounds {
            for slot in 0..2 {
                let mm = ReservationMm::new(slot as u64 + 17).unwrap();
                let mut model = table.lock(slot, mm).unwrap();
                let mut frame = TrapFrame {
                    slot: slot as u64,
                    elr: 0x40004,
                    ..TrapFrame::default()
                };
                frame.x[8] = 222;
                frame.x[..6].copy_from_slice(&[0x100000, 4096, 3, 0x32, u64::MAX, 0]);
                let current = CurrentTask::new();
                current.task_id.store(slot as u64 + 1, Ordering::Relaxed);
                current.thread_serial.store(11, Ordering::Relaxed);
                current.zone_mm.store(mm.raw(), Ordering::Relaxed);
                let before = counters.served[222].load(Ordering::Relaxed);
                let AnonymousReservationRoute::Work(mut pending) =
                    dispatch_anonymous_with_reservations(
                        &mut frame, &counters, &current, &mut model,
                    )
                else {
                    panic!("expected shared decision")
                };
                assert_eq!(counters.served[222].load(Ordering::Relaxed), before);
                let receipt = unsafe {
                    ReservationCompletion::after_descriptor_and_backing_commit(
                        pending.request(),
                        ReservationBackingReceipt {
                            receipt: 1,
                            granted_bytes: 4096,
                            returned_bytes: 0,
                        },
                    )
                }
                .unwrap();
                pending
                    .complete(&mut frame, &current, &counters, &mut model, receipt)
                    .unwrap();
                assert_eq!(frame.x[0], 0x100000);
                assert_eq!(counters.served[222].load(Ordering::Relaxed), before + 1);
                assert_eq!(model.complete(receipt), Err(Refusal::Stale));
                assert_eq!(
                    model.mapping(0x100000).unwrap().generation,
                    model.generation()
                );
            }
        }
        assert_eq!(counters.served[222].load(Ordering::Relaxed), rounds * 2);
        assert_eq!(counters.forwarded[222].load(Ordering::Relaxed), 0);
    }
}
#[test]
fn reservation_mmap_overflow_preserves_linux_errno() {
    use crate::{AnonymousReservationRoute, dispatch_anonymous_with_reservations};
    let table = table();
    let mm = ReservationMm::new(17).unwrap();
    table.publish(0, mm, layout()).unwrap();
    let mut model = table.lock(0, mm).unwrap();
    model.finish_import().unwrap();
    let current = CurrentTask::new();
    current.task_id.store(1, Ordering::Relaxed);
    current.thread_serial.store(11, Ordering::Relaxed);
    current.zone_mm.store(mm.raw(), Ordering::Relaxed);
    let counters = Counters::default();
    for (address, length, flags, errno) in [
        (0, 0, 0x22, 22),
        (0, u64::MAX, 0x22, 12),
        (0x100001, 4096, 0x32, 22),
        (!4095u64, 8192, 0x32, 12),
    ] {
        let mut frame = TrapFrame::default();
        frame.x[8] = 222;
        frame.x[..6].copy_from_slice(&[address, length, 3, flags, u64::MAX, 0]);
        assert!(matches!(
            dispatch_anonymous_with_reservations(&mut frame, &counters, &current, &mut model),
            AnonymousReservationRoute::Action(Action::Served)
        ));
        assert_eq!(frame.x[0] as i64, -errno);
        assert!(model.pending().is_none());
    }
    assert_eq!(counters.served[222].load(Ordering::Relaxed), 4);
    assert_eq!(counters.forwarded[222].load(Ordering::Relaxed), 0);
}
#[test]
fn reservation_unadmitted_root_never_serves_a_syscall() {
    use crate::{AnonymousReservationRoute, dispatch_anonymous_with_reservations};
    let table = table();
    let mm = ReservationMm::new(17).unwrap();
    table.publish(0, mm, layout()).unwrap();
    let mut model = table.lock(0, mm).unwrap();
    let current = CurrentTask::new();
    current.task_id.store(1, Ordering::Relaxed);
    current.thread_serial.store(11, Ordering::Relaxed);
    current.zone_mm.store(mm.raw(), Ordering::Relaxed);
    let counters = Counters::default();
    let mut frame = TrapFrame::default();
    frame.x[8] = 222;
    frame.x[3] = 0x22;
    assert!(matches!(
        dispatch_anonymous_with_reservations(&mut frame, &counters, &current, &mut model),
        AnonymousReservationRoute::Unavailable(Refusal::Stale)
    ));
    assert_eq!(counters.served[222].load(Ordering::Relaxed), 0);
}
#[test]
fn reservation_continuation_rejects_rebound_task_without_losing_owner() {
    use crate::{AnonymousReservationRoute, dispatch_anonymous_with_reservations};
    let table = table();
    let mm = ReservationMm::new(17).unwrap();
    table.publish(0, mm, layout()).unwrap();
    let mut model = table.lock(0, mm).unwrap();
    model.finish_import().unwrap();
    let current = CurrentTask::new();
    current.task_id.store(1, Ordering::Relaxed);
    current.thread_serial.store(11, Ordering::Relaxed);
    current.zone_mm.store(mm.raw(), Ordering::Relaxed);
    let counters = Counters::default();
    let mut frame = TrapFrame::default();
    frame.x[8] = 222;
    frame.x[..6].copy_from_slice(&[0x100000, 4096, 3, 0x32, u64::MAX, 0]);
    let AnonymousReservationRoute::Work(mut pending) =
        dispatch_anonymous_with_reservations(&mut frame, &counters, &current, &mut model)
    else {
        panic!()
    };
    let receipt = unsafe {
        ReservationCompletion::after_descriptor_and_backing_commit(
            pending.request(),
            ReservationBackingReceipt {
                receipt: 1,
                granted_bytes: 4096,
                returned_bytes: 0,
            },
        )
    }
    .unwrap();
    current.thread_serial.store(12, Ordering::Relaxed);
    assert_eq!(
        pending.complete(&mut frame, &current, &counters, &mut model, receipt),
        Err(Refusal::Stale)
    );
    assert!(model.mapping(0x100000).is_none());
    assert_eq!(counters.served[222].load(Ordering::Relaxed), 0);
    current.thread_serial.store(11, Ordering::Relaxed);
    frame.slot = 7; // The original thread may resume on a different vCPU.
    pending
        .complete(&mut frame, &current, &counters, &mut model, receipt)
        .unwrap();
    assert_eq!(counters.served[222].load(Ordering::Relaxed), 1);
    let AnonymousReservationRoute::Work(mut pending) =
        dispatch_anonymous_with_reservations(&mut frame, &counters, &current, &mut model)
    else {
        panic!()
    };
    pending
        .refuse(&mut frame, &current, &counters, &mut model)
        .unwrap();
    assert_eq!(frame.x[0] as i64, -12);
    assert_eq!(counters.served[222].load(Ordering::Relaxed), 2);
    assert_eq!(counters.forwarded[222].load(Ordering::Relaxed), 0);
}
#[test]
fn reservation_decoder_forwards_out_of_layout_hint() {
    let table = table();
    let mut g = admitted(&table, 0, 17);
    // mmap(0xc000000000, 64 KiB, RW, MAP_PRIVATE|MAP_ANONYMOUS)
    assert_eq!(
        decide(&mut g, 222, [0xc0_0000_0000, 0x10000, 3, 0x22, u64::MAX, 0]),
        AnonymousRouteKind::Forward
    );
    assert!(g.pending().is_none());
    assert_eq!(
        decide(&mut g, 222, [0x200000, 0x10000, 3, 0x22, u64::MAX, 0]),
        AnonymousRouteKind::Work
    );
}
#[test]
fn reservation_decoder_prot_and_anonymous_offset_linux_routes() {
    let table = table();
    let mut g = admitted(&table, 0, 17);
    assert_eq!(
        decide(&mut g, 222, [0, 4096, 3 | (1 << 28), 0x22, u64::MAX, 0]),
        AnonymousRouteKind::Forward,
        "unknown mmap prot bits retain host mmap decoding"
    );
    assert_eq!(
        decide(&mut g, 222, [0, 4096, 3, 0x22, u64::MAX, 0x800]),
        AnonymousRouteKind::Return(-22),
        "misaligned offset on MAP_ANONYMOUS"
    );
    assert_eq!(
        decide(&mut g, 226, [0x100000, 4096, 1 << 28, 0, 0, 0]),
        AnonymousRouteKind::Return(-22),
        "unknown mprotect prot bit"
    );
    assert!(g.pending().is_none());
}
fn range(start: u64, end: u64) -> ReservationRange {
    ReservationRange::new(start, end).unwrap()
}
fn complete(root: &mut Reservations<'_>, decision: Decision) -> u64 {
    match decision {
        Decision::Complete(result) => result,
        Decision::Work(request) => {
            let receipt = unsafe {
                ReservationCompletion::after_descriptor_and_backing_commit(
                    request,
                    ReservationBackingReceipt {
                        receipt: request.sequence.raw(),
                        granted_bytes: 0,
                        returned_bytes: 0,
                    },
                )
            }
            .unwrap();
            root.complete(receipt).unwrap()
        }
    }
}
fn nodes(root: &mut Reservations<'_>) -> std::vec::Vec<(u64, u64, u64, u32)> {
    let mut nodes = Vec::new();
    root.observe_mappings(&mut |m| {
        nodes.push((
            m.range.start(),
            m.range.end(),
            m.protection.bits(),
            m.flags.bits(),
        ))
    })
    .unwrap();
    nodes
}
use carrick_personality_linux::mm::NodeFlagsPolicy;
#[test]
fn reservation_set_limits_refuses_growth_and_keeps_shrink() {
    let table = table();
    let mut g = admitted(&table, 0, 6);
    let rw = ReservationProtection::READ_WRITE;
    let d = g.mmap(Placement::Anywhere, 0x8000, rw).unwrap();
    complete(&mut g, d);
    let generation = g.generation();
    g.set_limits(0x8000, u64::MAX);
    assert_eq!(g.generation(), generation, "limits do not revoke grants");
    assert_eq!(
        g.mmap(Placement::Anywhere, 0x1000, ReservationProtection::NONE),
        Err(Refusal::Limit),
        "RLIMIT_AS"
    );
    // brk growth under the limit keeps the old break (Linux brk(2)).
    assert_eq!(g.brk(0x3000), Ok(Decision::Complete(0x1000)));
    g.set_limits(u64::MAX, 0x4000);
    assert_eq!(
        g.mmap(Placement::Anywhere, 0x1000, rw),
        Err(Refusal::Limit),
        "RLIMIT_DATA"
    );
    assert_eq!(
        decide(&mut g, 222, [0, 4096, 3, 0x22, u64::MAX, 0]),
        AnonymousRouteKind::Return(-12)
    );
    assert_eq!(
        decide(&mut g, 214, [0x3000, 0, 0, 0, 0, 0]),
        AnonymousRouteKind::Return(0x1000)
    );
    // Shrinking below a lowered limit stays possible.
    let d = g.munmap(range(0x100000, 0x102000)).unwrap();
    complete(&mut g, d);
    let d = g
        .mprotect(range(0x102000, 0x108000), ReservationProtection::NONE)
        .unwrap();
    complete(&mut g, d);
    let d = g.mmap(Placement::Anywhere, 0x4000, rw).unwrap();
    complete(&mut g, d);
}
#[test]
fn reservation_flagged_and_opaque_nodes_force_forward() {
    let table = table();
    let mut g = admitted(&table, 0, 7);
    let rw = ReservationProtection::READ_WRITE;
    let d = g.mmap(Placement::Fixed(0x100000), 0x4000, rw).unwrap();
    complete(&mut g, d);
    // A grow-down stack is host-owned, locked or not: every edit touching
    // it forwards. (The carried attributes alone ride EL1 edits; see
    // `reservation_carried_attributes_ride_el1_edits`.)
    for flag in [
        ReservationNodeFlags::GROWSDOWN,
        ReservationNodeFlags::GROWSDOWN.union(ReservationNodeFlags::LOCKED),
    ] {
        let before = g.generation();
        g.set_flags(range(0x101000, 0x102000), flag, ReservationNodeFlags::EMPTY)
            .unwrap();
        assert!(g.generation().raw() > before.raw());
        assert!(g.mapping(0x101000).unwrap().flags.contains(flag));
        assert!(g.mapping(0x100000).unwrap().flags.root_editable());
        assert!(g.mapping(0x102000).unwrap().flags.root_editable());
        let generation = g.generation();
        assert_eq!(
            g.munmap(range(0x100000, 0x104000)),
            Err(Refusal::ForeignMapping)
        );
        assert_eq!(
            g.mprotect(range(0x101000, 0x102000), ReservationProtection::NONE),
            Err(Refusal::ForeignMapping)
        );
        assert_eq!(
            g.mmap(Placement::Fixed(0x101000), 0x1000, rw),
            Err(Refusal::ForeignMapping)
        );
        assert_eq!(
            g.mremap(range(0x101000, 0x102000), 0x2000, MoveTarget::MayMove),
            Err(Refusal::ForeignMapping)
        );
        assert_eq!(
            decide(&mut g, 215, [0x100000, 0x4000, 0, 0, 0, 0]),
            AnonymousRouteKind::Forward
        );
        assert_eq!(
            decide(&mut g, 226, [0x101000, 0x1000, 1, 0, 0, 0]),
            AnonymousRouteKind::Forward
        );
        assert_eq!(g.generation(), generation);
        assert!(g.pending().is_none());
        // Edits not touching the flagged node remain EL1's.
        let d = g
            .mprotect(range(0x103000, 0x104000), ReservationProtection::NONE)
            .unwrap();
        complete(&mut g, d);
        let d = g.mprotect(range(0x103000, 0x104000), rw).unwrap();
        complete(&mut g, d);
        g.set_flags(range(0x101000, 0x102000), ReservationNodeFlags::EMPTY, flag)
            .unwrap();
        let mut nodes = 0;
        g.observe_mappings(&mut |_| nodes += 1).unwrap();
        assert_eq!(nodes, 1, "clearing the attribute coalesces again");
    }
    // Opaque host obstacle: placement skips it and every edit forwards.
    g.insert_opaque(
        range(0x104000, 0x106000),
        rw,
        ReservationNodeFlags::ANONYMOUS,
    )
    .unwrap();
    assert!(!g.mapping(0x104000).unwrap().anonymous);
    assert_eq!(
        g.fault_plan(0x104000, 4096, rw),
        Err(Refusal::ForeignMapping)
    );
    assert_eq!(
        g.insert_opaque(range(0x105000, 0x107000), rw, ReservationNodeFlags::EMPTY),
        Err(Refusal::Collision)
    );
    let d = g.mmap(Placement::Anywhere, 0x1000, rw).unwrap();
    assert_eq!(complete(&mut g, d), 0x106000);
    assert_eq!(
        decide(&mut g, 215, [0x104000, 0x1000, 0, 0, 0, 0]),
        AnonymousRouteKind::Forward
    );
    assert_eq!(
        g.set_flags(
            range(0x100000, 0x108000),
            ReservationNodeFlags::LOCKED,
            ReservationNodeFlags::EMPTY
        ),
        Err(Refusal::Hole)
    );
    assert_eq!(
        g.set_flags(
            range(0x100000, 0x101000),
            ReservationNodeFlags::PRIVATE,
            ReservationNodeFlags::EMPTY
        ),
        Err(Refusal::Invalid)
    );
    // The host retires across both kinds after serving the munmap itself.
    g.retire_opaque(range(0x103000, 0x105000)).unwrap();
    assert!(g.mapping(0x103000).is_none());
    assert!(g.mapping(0x104000).is_none());
    assert!(!g.mapping(0x105000).unwrap().anonymous);
    assert!(g.mapping(0x102000).unwrap().anonymous);
}
#[test]
fn reservation_carried_attributes_ride_el1_edits() {
    let table = table();
    let mut g = admitted(&table, 0, 9);
    let rw = ReservationProtection::READ_WRITE;
    let r = ReservationProtection::from_bits(1).unwrap();
    let anon = ReservationNodeFlags::ANONYMOUS_PRIVATE.bits();
    for flag in [
        ReservationNodeFlags::LOCKED,
        ReservationNodeFlags::DONTFORK,
        ReservationNodeFlags::WIPEONFORK,
        ReservationNodeFlags::DONTDUMP,
    ] {
        let d = g.mmap(Placement::Fixed(0x100000), 0x4000, rw).unwrap();
        complete(&mut g, d);
        g.set_flags(range(0x101000, 0x103000), flag, ReservationNodeFlags::EMPTY)
            .unwrap();
        let flagged = anon | flag.bits();
        // mlock(2)/madvise(2) attributes stay with the VMA across
        // mprotect(2): the range is still EL1's, and the edit keeps
        // each node's attributes while changing its protection.
        let d = g.mprotect(range(0x100000, 0x102000), r).unwrap();
        complete(&mut g, d);
        assert_eq!(
            nodes(&mut g),
            [
                (0x100000, 0x101000, 1, anon),
                (0x101000, 0x102000, 1, flagged),
                (0x102000, 0x103000, 3, flagged),
                (0x103000, 0x104000, 3, anon),
            ]
        );
        assert!(g.fault_plan(0x101000, 4096, r).is_ok());
        assert_eq!(
            decide(&mut g, 226, [0x101000, 0x1000, 3, 0, 0, 0]),
            AnonymousRouteKind::Work
        );
        // mmap(MAP_FIXED) replaces the attributed VMA with a plain one.
        let d = g.mmap(Placement::Fixed(0x101000), 0x1000, r).unwrap();
        complete(&mut g, d);
        assert_eq!(g.mapping(0x101000).unwrap().flags.bits(), anon);
        // munmap(2) retires attributed memory like any other.
        let d = g.munmap(range(0x100000, 0x104000)).unwrap();
        complete(&mut g, d);
        assert!(nodes(&mut g).is_empty());
    }
}
