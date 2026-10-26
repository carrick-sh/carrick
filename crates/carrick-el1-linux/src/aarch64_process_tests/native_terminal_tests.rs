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

#[test]
fn native_fatal_worker_wakes_futex_parked_leader_before_exit_drain() {
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
    call(&mut service, &mut frame, &mut cpu);
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
}
