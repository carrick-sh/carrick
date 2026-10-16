//! A native parent park retains the child's existing in-ring execution.
use super::*;

#[test]
fn arm_native_wait_runs_ready_child_before_host_handoff() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    fixture.zone.spaces.set_idle_ttbr(0x30000);
    let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        TestStockCrossing::new(&[
            0x20000, 0x21000, 0x22000, 0x23000, 0x24000, 0x25000, 0x26000, 0x27000,
        ]),
    )
    .with_words(words);
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = 220;
    frame.x[0] = 17; // SIGCHLD, no child-TID effect in this scheduler witness.
    arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap();
    let child_pid = frame.x[0];
    assert!(child_pid > 0 && child_pid <= u64::from(u32::MAX));
    let child = fixture.zone.runnable_head(fixture.slot).unwrap();
    let identity = fixture.zone.record(child).identity();
    assert_ne!(identity.mm, fixture.address.mm.raw().get());
    assert!(fixture.zone.spaces.is_open(identity.mm));
    assert_eq!(service.crossing.loans_requested.load(Ordering::Acquire), 1);
    assert_eq!(
        service
            .crossing
            .settlements_committed
            .load(Ordering::Acquire),
        1
    );

    frame.x = [0; 31];
    frame.x[8] = 260;
    frame.x[0] = child_pid;
    let route = arm_call(fixture, fixture.control, &mut service, &mut frame).unwrap();
    assert!(matches!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Served
            | carrick_personality_linux::dispatch::CompletionRoute::WithWork
    ));
    assert_eq!(fixture.zone.slot(fixture.slot).current(), Some(child));
    assert_eq!(
        fixture.task.execution.task.load(Ordering::Acquire),
        identity.tid
    );
    assert_eq!(fixture.task.mm.key.load(Ordering::Acquire), identity.mm);
    assert!(matches!(
        fixture.zone.record(child).claim(),
        carrick_sched_core::Claim::OnCpu { slot, .. } if slot == fixture.slot
    ));
    assert_eq!(frame.x[0], 0, "the child retains its fork return");
    assert_eq!(fixture.zone.slot(fixture.slot).queued(), 0);
    assert_eq!(
        fixture.zone.counters.el1_switches.load(Ordering::Acquire),
        1
    );
    assert_eq!(
        fixture.zone.counters.lost_adoptions.load(Ordering::Acquire),
        0
    );
}
