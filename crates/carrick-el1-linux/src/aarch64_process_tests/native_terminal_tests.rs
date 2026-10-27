//! Native process cancellation must reach members without a host task graph.
use super::*;
use crate::thread_setup::{LifecycleThread, LifecycleVenue};

struct ChildVenue;
impl LifecycleVenue for ChildVenue {
    fn thread<'a>(&'a self, task: &'a CurrentTask) -> Option<LifecycleThread<'a>> {
        // SAFETY: the fixture retains the production fork's page and controls.
        let page_address = task.metadata.lifecycle_page.load(Ordering::Acquire);
        let control_address = task.metadata.control_slot.load(Ordering::Acquire);
        if page_address == 0 || control_address == 0 {
            return None;
        }
        let (page, slot) = unsafe {
            (
                &*(page_address as *const ThreadLifecyclePage),
                &*(control_address as *const ThreadControlSlot),
            )
        };
        Some(LifecycleThread { page, slot })
    }
    fn born_slot(
        &self,
        page: &ThreadLifecyclePage,
        entry: carrick_el1_abi::EntryRef,
    ) -> Option<&ThreadControlSlot> {
        // SAFETY: production fork stocked this control in the retained test loan.
        Some(unsafe { &*(page.control_address(entry)? as *const ThreadControlSlot) })
    }
}

/// What the futex-joined leader is parked on when its worker dies.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LeaderWait {
    Futex,
    /// Its own one-description pipe poll: the exit abandons it.
    PipePoll,
    /// A pipe poll operation naming another task: refused untouched.
    ForeignTaskPoll,
    /// A non-IPC queue domain holding a token that collides with a live
    /// IPC operation of this task: never routed to IPC settlement.
    ForeignDomain,
}

#[test]
fn native_fatal_worker_wakes_futex_parked_leader_before_exit_drain() {
    fatal_worker_retires_parked_leader(LeaderWait::Futex);
}

/// A member woken out of a one-description pipe poll by a sibling's fatal
/// exit still owns its poll operation (endpoint pin and operation record)
/// when it is selected. Its exit must abandon that wait before retirement;
/// the scheduler otherwise requeues the leaving record and native
/// retirement quarantines the run (#856, eight-pair two-process pipe case).
#[test]
fn native_fatal_worker_retires_leader_holding_pipe_poll_operation() {
    fatal_worker_retires_parked_leader(LeaderWait::PipePoll);
}

/// Exit settles only the exiting task's own IPC operation: an operation
/// record of another task stays live, its pin held, and the exit reports
/// the typed refusal instead of finishing it.
#[test]
fn native_exit_refuses_pipe_poll_operation_of_another_task() {
    fatal_worker_retires_parked_leader(LeaderWait::ForeignTaskPoll);
}

/// The issuing authority comes from the queue domain the operation parked
/// on, not from the token's shape: a reservation-pool operation whose token
/// equals a live IPC operation's never reaches the IPC table.
#[test]
fn native_exit_never_routes_a_foreign_domain_operation_to_ipc() {
    fatal_worker_retires_parked_leader(LeaderWait::ForeignDomain);
}

fn fatal_worker_retires_parked_leader(wait: LeaderWait) {
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
    service.crossing.terminal_task = Some(&fixture.task);
    let ipc = (wait != LeaderWait::Futex).then(|| {
        use carrick_el1_abi::ipc::{IpcBacking, fd, pipe};
        let owner = std::sync::Arc::new(carrick_kernel::el1_ipc::HostIpc::new(1 << 20).unwrap());
        let table = carrick_kernel::el1_ipc::HostTable::create(owner.clone(), 64, 8).unwrap();
        let object = owner.create_pipe(65536).unwrap();
        let region = owner.region();
        let fd = region.fd(carrick_kernel::el1_zone::HostLockWait);
        for (number, end, access) in [
            (3, pipe::End::Reader, fd::AccessMode::ReadOnly),
            (4, pipe::End::Writer, fd::AccessMode::WriteOnly),
        ] {
            let pin = fd
                .create_pinned(fd::Description::new(
                    IpcBacking::Pipe { object, end }.encode(),
                    access,
                    fd::StatusFlags::default(),
                ))
                .unwrap();
            fd.install_pin(table.id(), fd::Fd(number), &pin, false)
                .unwrap();
            assert_eq!(fd.unpin(pin).unwrap(), None);
        }
        let storage = Box::leak(carrick_test_support::TestEl1Region::zeroed());
        // SAFETY: retained aligned ABI storage contains this zeroed map.
        let map = unsafe {
            &*storage
                .as_ptr()
                .add(carrick_el1_abi::EL1_IPC_TABLE_MAP_OFFSET as usize)
                .cast::<carrick_el1_abi::ipc_tables::IpcTableMap>()
        };
        map.publish(5, table.id().to_raw()).unwrap();
        fixture
            .zone
            .bind_object_wait(
                carrick_el1::substrate::ipc::wait_key(object, pipe::WaitFor::Readable).unwrap(),
                &carrick_sched_core::ShortLockSpin,
            )
            .unwrap();
        service.crossing.ipc = Some((owner.clone(), map));
        (owner, table, map)
    });
    let mut frame = carrick_el1_abi::TrapFrame::default();
    let mut cpu = crate::sched::FakeCpu::default();
    frame.x[8] = 220;
    frame.x[0] = 17;
    arm_call_with_cpu(fixture, fixture.control, &mut service, &mut frame, &mut cpu).unwrap();
    let pid = frame.x[0];
    let leader = fixture.zone.runnable_head(fixture.slot).unwrap();
    frame.x = [0; 31];
    frame.x[8] = 260;
    frame.x[0] = pid;
    arm_call_with_cpu(fixture, fixture.control, &mut service, &mut frame, &mut cpu).unwrap();
    assert_eq!(fixture.zone.slot(fixture.slot).current(), Some(leader));
    let owner = registry()
        .for_record(fixture.zone, fixture.zone.record_ref(leader))
        .unwrap();
    *service.crossing.zone.lock().unwrap() = Some(fixture.zone);
    let child_context = unsafe { *fixture.zone.record(leader).ctx_mut() }
        .address_context()
        .unwrap();
    *service.crossing.child.lock().unwrap() = Some((
        carrick_core::entry::binding(&fixture.task.execution, &fixture.task.mm),
        child_context,
    ));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    assert!(matches!(
        resume_selected(
            &owner,
            registry(),
            source,
            &fixture.task,
            leader,
            &mut service
        ),
        super::super::native_process_runtime::NativeResume::NoPending
    ));

    let call = |service: &mut Aarch64NativeProcessService<'static, TestStockCrossing>,
                frame: &mut carrick_el1_abi::TrapFrame,
                cpu: &mut crate::sched::FakeCpu| {
        let identity = fixture
            .zone
            .record(fixture.zone.slot(fixture.slot).current().unwrap())
            .identity();
        let page = unsafe { &*(identity.lifecycle_page as *const ThreadLifecyclePage) };
        let control = unsafe { &*(identity.control_slot as *const ThreadControlSlot) };
        let rec = fixture.zone.slot(fixture.slot).current().unwrap();
        let saved = unsafe { *fixture.zone.record(rec).ctx_mut() };
        let root = saved.address_context().unwrap().root.address().raw();
        super::super::dispatch::dispatch_arm_syscall_with_native_process(
            frame,
            &carrick_el1_abi::Counters::new(),
            core::slice::from_ref(&fixture.task),
            &[],
            &[],
            &[],
            &[],
            &carrick_el1_abi::InotifyNameCache::new(),
            Some(crate::dispatch::Zone {
                tables: fixture.zone,
                cpu,
                user: &crate::sched::HardwareUserWord,
            }),
            None,
            Some(&ChildVenue),
            page,
            control,
            &saved.native,
            root,
            service,
            |_| core::ptr::null_mut(),
        )
        .unwrap()
    };
    // Use the production pthread birth; both members remain native-owned.
    frame.x = [0; 31];
    frame.x[8] = 220;
    frame.x[0] = 0x50f00;
    frame.x[1] = 0x9000;
    call(&mut service, &mut frame, &mut cpu);
    assert!(
        (frame.x[0] as i64) > 0,
        "native pthread clone: {}",
        frame.x[0] as i64
    );
    let worker = fixture.zone.runnable_head(fixture.slot).unwrap();
    assert!(fixture.zone.record(worker).is_native_owned());
    let join = core::sync::atomic::AtomicU32::new(1);
    frame.x = [0; 31];
    frame.x[8] = 98;
    frame.x[0] = join.as_ptr() as u64;
    frame.x[1] = 128;
    frame.x[2] = 1;
    let poll_operation = ipc.as_ref().map(|(owner, _, map)| {
        // The adapter's fresh-call park (`ipc::poll::serve_one`): pin the
        // inherited reader, find it empty, enroll a PollWait operation on
        // the pipe's readable queue and switch to the runnable worker.
        use carrick_el1_abi::ipc::{IpcOpKind, IpcOperation, IpcUserVa, WriteProgress, fd, pipe};
        let region = owner.region();
        let table = fd::TableId::from_raw(
            map.lookup_owned(fixture.task.linux.file_table.load(Ordering::Acquire))
                .expect("forked leader owns its inherited descriptor table"),
        );
        let (pin, description) = region
            .fd(carrick_sched_core::ShortLockSpin)
            .pin(table, fd::Fd(3))
            .unwrap();
        let Some(carrick_el1_abi::ipc::IpcBacking::Pipe {
            object,
            end: pipe::End::Reader,
        }) = carrick_el1_abi::ipc::IpcBacking::decode(description.backing)
        else {
            panic!("fd 3 is the inherited pipe reader");
        };
        let key = carrick_el1::substrate::ipc::wait_key(object, pipe::WaitFor::Readable).unwrap();
        let token = region
            .begin_operation(IpcOperation {
                kind: IpcOpKind::PollWait,
                pin: pin.into_raw(),
                object: object.to_raw(),
                task: carrick_el1_abi::ipc::IpcTaskKey(
                    fixture.task.execution.task.load(Ordering::Acquire)
                        + u64::from(wait == LeaderWait::ForeignTaskPoll) * 1000,
                ),
                mm: carrick_el1_abi::ipc::IpcMmKey(fixture.task.mm.key.load(Ordering::Acquire)),
                buf: IpcUserVa(0x7000),
                progress: WriteProgress { len: 3, written: 0 },
                nr: 73,
                ..IpcOperation::EMPTY
            })
            .unwrap();
        let raw = token.into_raw();
        let pin_raw = region
            .operation(&carrick_el1_abi::ipc::IpcOpToken::from_raw(raw))
            .unwrap()
            .pin;
        let counters = carrick_el1_abi::Counters::new();
        let mut sched = crate::sched::Sched {
            handoff: None,
            zone: fixture.zone,
            slot: fixture.slot,
            task: &fixture.task,
            cpu: &mut cpu,
            user: &crate::sched::HardwareUserWord,
            counters: &counters,
        };
        frame.x = [0; 31];
        frame.x[8] = 73;
        frame.elr = 0x4004;
        let key = if wait == LeaderWait::ForeignDomain {
            let pool = carrick_sched_core::object_wait::ObjectWaitKey::reservation_pool(
                core::num::NonZeroU64::MIN,
            );
            fixture
                .zone
                .bind_object_wait(pool, &carrick_sched_core::ShortLockSpin)
                .unwrap();
            pool
        } else {
            key
        };
        let snapshot = sched.observe_object(key).unwrap();
        let parked = sched
            .park_object(
                &frame,
                key,
                snapshot,
                carrick_el1::substrate::sched::object_wait::OperationResumePc::new(0x4000).unwrap(),
                carrick_el1::substrate::ipc::to_sched_token(
                    carrick_el1_abi::ipc::IpcOpToken::from_raw(raw),
                )
                .unwrap(),
                None,
            )
            .unwrap();
        assert!(
            sched
                .resume_after_object_park(&mut frame, parked, 0)
                .is_some()
        );
        assert!(fixture.zone.record(leader).has_object_operation());
        (raw, pin_raw)
    });
    if poll_operation.is_none() {
        call(&mut service, &mut frame, &mut cpu);
    }
    assert_eq!(fixture.zone.slot(fixture.slot).current(), Some(worker));
    assert!(matches!(
        fixture.zone.record(leader).claim(),
        carrick_sched_core::Claim::Parked { .. }
    ));
    let saved = unsafe { *fixture.zone.record(worker).ctx_mut() };
    let identity = fixture.zone.record(worker).identity();
    let page = unsafe { &*(identity.lifecycle_page as *const ThreadLifecyclePage) };
    let control = unsafe { &*(identity.control_slot as *const ThreadControlSlot) };
    let status = with_process_entry(
        source,
        &fixture.task,
        &saved.native,
        saved.address_context().unwrap().root.address().raw(),
        page,
        control,
        &mut service,
        |entry| entry.exit_with_signal(11),
    )
    .unwrap()
    .unwrap();
    assert!(matches!(status, LifecycleOutcome::Transferred { .. }));
    assert!(matches!(
        fixture.zone.record(worker).resume_disposition(),
        carrick_sched_core::object_wait::ResumeDisposition::OwnerContinuation(
            carrick_sched_core::object_wait::OwnerEntry::Exception
        )
    ));
    assert!(
        matches!(
            fixture.zone.record(leader).claim(),
            carrick_sched_core::Claim::Queued { .. }
        ),
        "native Closing stranded its futex-parked leader; no host thread owns the wake"
    );
    let select = |service: &mut Aarch64NativeProcessService<'static, TestStockCrossing>| {
        let record = fixture.zone.switch_in_full(fixture.slot).unwrap().record;
        let identity = fixture.zone.record(record).identity();
        fixture
            .zone
            .install_space(fixture.slot, identity.mm)
            .unwrap();
        fixture.task.set(
            El1TaskId::from_linux_tid(identity.tid as i32),
            carrick_el1_abi::SnapshotGeneration::from_raw(identity.generation),
            identity.file_table,
        );
        fixture.task.mm.key.store(identity.mm, Ordering::Release);
        fixture
            .task
            .mm
            .thread_generation
            .store(identity.serial, Ordering::Release);
        fixture
            .task
            .publish_lifecycle(identity.lifecycle_page, identity.control_slot);
        (
            record,
            resume_selected(&owner, registry(), source, &fixture.task, record, service),
        )
    };
    if matches!(
        wait,
        LeaderWait::ForeignTaskPoll | LeaderWait::ForeignDomain
    ) {
        let Err(refused) =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| select(&mut service)))
        else {
            panic!("an operation exit cannot settle must refuse the exit");
        };
        assert!(
            refused
                .downcast_ref::<crate::native_run_failure::NativeRunFailurePanic>()
                .is_some(),
            "the refusal is the typed native run failure, not a fatal"
        );
        let (owner, _, _) = ipc.as_ref().unwrap();
        let (raw, pin_raw) = poll_operation.unwrap();
        let live = owner
            .region()
            .operation(&carrick_el1_abi::ipc::IpcOpToken::from_raw(raw))
            .expect("the refused operation record stays live");
        assert_eq!(live.kind, carrick_el1_abi::ipc::IpcOpKind::PollWait);
        assert_eq!(live.pin, pin_raw);
        assert_eq!(
            pinned_holds(owner, pin_raw).map(|holds| holds.1),
            Some(1),
            "its pin stays held"
        );
        assert!(fixture.zone.record(leader).has_object_operation());
        return;
    }
    let (selected, resumed) = select(&mut service);
    assert_eq!(selected, leader);
    assert!(
        matches!(
            resumed,
            super::super::native_process_runtime::NativeResume::Left(None)
        ),
        "cancelled native leader must retire before EL0"
    );
    let (selected, resumed) = select(&mut service);
    assert_eq!(selected, worker);
    assert!(
        matches!(
            resumed,
            super::super::native_process_runtime::NativeResume::Left(None)
        ),
        "worker must finish the original fatal exit after the exact member receipt"
    );
    assert!(matches!(
        fixture.zone.record(leader).claim(),
        carrick_sched_core::Claim::Free
    ));
    assert!(matches!(
        fixture.zone.record(worker).claim(),
        carrick_sched_core::Claim::Free
    ));
    assert!(!fixture.zone.spaces.is_open(identity.mm));
    if let (Some((owner, _, _)), Some((raw, pin_raw))) = (&ipc, poll_operation) {
        assert_eq!(
            pinned_holds(owner, pin_raw),
            None,
            "the abandoned poll's description pin is dropped"
        );
        assert!(
            owner
                .region()
                .operation(&carrick_el1_abi::ipc::IpcOpToken::from_raw(raw))
                .is_err(),
            "the leader's exit must finish its abandoned poll operation"
        );
    }
}

/// Descriptor references and pins of the description an operation pinned;
/// `None` once no pin holds it (the pin is stale).
fn pinned_holds(
    owner: &carrick_kernel::el1_ipc::HostIpc,
    pin: carrick_el1_abi::ipc::RawOfdPin,
) -> Option<(usize, usize)> {
    let pin = carrick_el1_abi::ipc::OfdPin::from_raw(pin);
    let holds = owner
        .region()
        .fd(carrick_sched_core::ShortLockSpin)
        .holds(&pin)
        .ok();
    let _ = pin.into_raw();
    holds
}
