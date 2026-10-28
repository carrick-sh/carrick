// #978: two admitted live threads; the leader publishes group-exit
// intent while its sibling owns a parked metadata operation.
#[test]
fn exit_drain_abandons_object_wait_exactly_once() {
    object_wait_exit_drain(false);
}

// Negative control for the inferred lost-wake mechanism: no second
// control wake is supplied after the producer starts its transfer.
#[test]
fn exit_drain_control_during_transfer_reaches_the_sibling() {
    object_wait_exit_drain(true);
}

#[cfg(test)]
fn object_wait_exit_drain(defer: bool) {
    use carrick_sched_core::object_wait::{ObjectWaitKey, OperationToken};
    let _region = ZoneRegion::new();
    let zone = carrick_el1_abi::zone_tables().unwrap();
    let (kernel, root) = bootstrap(12_978);
    root.thread().set_affinity(CpuAffinity::all(1));
    let peer = sibling(&kernel, &root, 22_978);
    publish(&root, 978);
    publish(&peer, 979);
    let scheduler = Arc::new(Scheduler::new_with_policy(
        Arc::clone(&kernel),
        Arc::new(GuestCpuPolicy::new(1)),
    ));
    let service = CarrierWaitService::new(Arc::clone(&scheduler));
    let executor = scheduler
        .register_executor(Arc::new(RecordingKick::default()))
        .unwrap();
    scheduler.make_runnable(peer.thread().key()).unwrap();
    let running = scheduler.take(&executor).unwrap();
    let id = zone
        .alloc_record(carrick_el1_abi::ThreadIdentity {
            tid: peer.thread().key().tid.raw() as u64,
            serial: peer.thread().key().serial.raw(),
            mm: peer.shared().mm().id().raw(),
            file_table: 0,
            generation: running.generation().raw(),
            affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
            affinity: 0,
            lifecycle_page: 0,
            control_slot: 0,
        })
        .unwrap();
    let record = zone.record_ref(id);
    let key = ObjectWaitKey::metadata_request(peer.thread().key().serial.raw()).unwrap();
    let complete = |effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
        '_,
        carrick_el1_abi::Aarch64ParkedContext,
    >| {
        let _ = effects.defer_handbacks();
    };
    zone.bind_object_wait_with_completion(key, &crate::el1_zone::HostLockWait, &complete)
        .unwrap();
    let source = zone
        .admit_object_notification(key, &crate::el1_zone::HostLockWait, &complete)
        .unwrap();
    {
        let guard = zone
            .object_wait_with_completion(key, &crate::el1_zone::HostLockWait, &complete)
            .unwrap();
        guard
            .park_host_rechecked(
                guard.snapshot(),
                id,
                OperationToken::metadata_request(peer.thread().key().serial.raw()).unwrap(),
                || true,
            )
            .unwrap();
    }
    let seq = zone.record(id).claim().seq();
    let current = peer
        .task_binding()
        .capture(peer.thread().key().tid)
        .unwrap();
    let continuation = BlockedContinuation::from_zone_park(
        ContinuationCapture::from_lease(
            &current,
            running.lease(),
            SyscallRequest::new(94, SyscallArgs([0; 6])),
            RestartClass::Never,
        )
        .unwrap(),
        crate::kernel::continuation::ZoneWait::new(record, seq),
        None,
    );
    let mut registration = service.prepare_registration(&continuation);
    service.enroll(&mut registration).unwrap();
    scheduler
        .settle_blocked_continuation(running, continuation, registration)
        .unwrap();
    scheduler.make_runnable(root.thread().key()).unwrap();
    let leader = scheduler.take(&executor).unwrap();
    assert_eq!(leader.lease().thread_key(), root.thread().key());
    assert!(root.task().begin_exit());
    scheduler
        .settle_blocked(leader, BlockedReason::HostWait)
        .unwrap();
    if defer {
        source.publish(
            carrick_el1_abi::Waker::El1 {
                slot: carrick_el1_abi::SlotId::new(0),
            },
            &complete,
        );
        assert!(matches!(
            zone.record(id).claim(),
            carrick_el1_abi::Claim::Transferring { .. }
        ));
    }
    scheduler.wake_control(peer.thread().key()).unwrap();
    if defer {
        assert_eq!(
            scheduler.queued_len(),
            0,
            "host cannot run a transferring record"
        );
        zone.take_completion_handbacks(&crate::el1_zone::HostLockWait, &mut |r| {
            scheduler.publish_zone_handback(r)
        });
    }
    assert_eq!(
        scheduler.queued_len(),
        1,
        "one retained control wake must reach the sibling"
    );
    let resumed = scheduler.take(&executor).unwrap();
    assert_eq!(resumed.lease().thread_key(), peer.thread().key());
    // Mirrors poll_with_engine's ThreadDone early return: do not
    // resume or consume the original operation before settling exit.
    scheduler.settle_exited(resumed).unwrap();
    assert!(
        zone.live(record).is_none(),
        "abandoned wait leaked {:?} {:?}",
        zone.record(id).claim(),
        zone.record(id).object_wait_census()
    );
    assert_eq!(zone.record(id).incarnation(), record.incarnation + 1);
    scheduler.wake_control(root.thread().key()).unwrap();
    scheduler
        .settle_exited(scheduler.take(&executor).unwrap())
        .unwrap();
}
