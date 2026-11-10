//! A clone-born thread's first entry on a vCPU another process last used
//! (#1958). The scheduler switch-in publishes only the record's thread
//! identity; the namespace PID and root incarnation belong to the process
//! owner's resume checkpoint, which the birth must reach before any CPU can
//! select it.
use super::*;

/// Production ARM CPU for the switch-in: registered vs unregistered resume is
/// chosen by `resume_production_with`, exactly as `HardwareCpu` chooses it.
struct ProductionResumeCpu<'a> {
    inner: crate::sched::FakeCpu,
    service: &'a mut Aarch64NativeProcessService<'static, TestStockCrossing>,
}

impl crate::sched::ThreadCpu for ProductionResumeCpu<'_> {
    fn save(
        &mut self,
        frame: &carrick_el1_abi::TrapFrame,
        ctx: &mut Aarch64ParkedContext,
        exit: crate::sched::CpuExitCause,
    ) {
        self.inner.save(frame, ctx, exit);
    }
    fn load(&mut self, frame: &mut carrick_el1_abi::TrapFrame, ctx: &Aarch64ParkedContext) {
        self.inner.load(frame, ctx);
    }
    fn resume_lifecycle(
        &mut self,
        zone: &ZoneTables<Aarch64ParkedContext>,
        task: &CurrentTask,
        slot: SlotId,
        record: RecordId,
    ) -> crate::sched::ResumeAction {
        // SAFETY: the fixture leaks its zone and this slot's task for the
        // life of the test process, as the EL1 image retains both.
        let zone = unsafe { &*(zone as *const ZoneTables<Aarch64ParkedContext>) };
        let task = unsafe { &*(task as *const CurrentTask) };
        super::super::aarch64_process::resume_production_with_service(
            zone,
            task,
            slot,
            record,
            self.service,
        )
    }
    fn set_translation(&mut self, a: u64, b: u64) {
        self.inner.set_translation(a, b);
    }
    fn live_ttbr0(&self) -> Option<u64> {
        self.inner.live_ttbr0()
    }
    fn invalidate_asid(&mut self, root: u64) {
        self.inner.invalidate_asid(root);
    }
    fn now(&self) -> u64 {
        self.inner.now()
    }
    fn freq(&self) -> u64 {
        self.inner.freq()
    }
    fn set_timer(&mut self, deadline: Option<u64>) {
        self.inner.set_timer(deadline);
    }
    fn send_sgi(&mut self, route: u64) {
        self.inner.send_sgi(route);
    }
    fn ack_irq(&mut self) -> u32 {
        self.inner.ack_irq()
    }
    fn end_irq(&mut self, intid: u32) {
        self.inner.end_irq(intid);
    }
    fn wait_for_interrupt(&mut self) {
        self.inner.wait_for_interrupt();
    }
    fn spin(&mut self) {
        self.inner.spin();
    }
    fn own_sgi_target(&self) -> u64 {
        self.inner.own_sgi_target()
    }
}

/// glibc/musl `pthread_create` clone flags.
const THREAD_FLAGS: u64 = 0x003d_0f00;

/// Lifecycle venue that follows the loaded task's published references, as
/// the EL1 image's venue does for a native child's own page.
struct LoadedVenue;

impl crate::thread_setup::LifecycleVenue for LoadedVenue {
    fn thread<'b>(
        &'b self,
        task: &'b CurrentTask,
    ) -> Option<crate::thread_setup::LifecycleThread<'b>> {
        let page = task.metadata.lifecycle_page.load(Ordering::Acquire);
        let slot = task.metadata.control_slot.load(Ordering::Acquire);
        (page != 0 && slot != 0).then(|| {
            // SAFETY: the native owner retains both published allocations.
            unsafe {
                crate::thread_setup::LifecycleThread {
                    page: &*(page as *const ThreadLifecyclePage),
                    slot: &*(slot as *const ThreadControlSlot),
                }
            }
        })
    }
    fn born_slot(
        &self,
        page: &ThreadLifecyclePage,
        entry: carrick_el1_abi::EntryRef,
    ) -> Option<&ThreadControlSlot> {
        let address = page.control_address(entry)?;
        // SAFETY: the production native stock retains the control allocation.
        (address != 0).then(|| unsafe { &*(address as *const ThreadControlSlot) })
    }
}

/// One syscall through the exact ARM adapter the vector uses, for the task
/// currently loaded on `fixture.slot`.
#[allow(clippy::too_many_arguments)]
fn loaded_call(
    fixture: &'static Fixture,
    task: &'static CurrentTask,
    page: &'static ThreadLifecyclePage,
    control: &'static ThreadControlSlot,
    service: &mut Aarch64NativeProcessService<'static, TestStockCrossing>,
    frame: &mut carrick_el1_abi::TrapFrame,
    cpu: &mut crate::sched::FakeCpu,
) -> Result<carrick_personality_linux::dispatch::CompletionRoute, NativeProcessError> {
    let counters = Box::new(carrick_el1_abi::Counters::new());
    let cache = Box::new(carrick_el1_abi::InotifyNameCache::new());
    let current = fixture.zone.slot(fixture.slot).current().unwrap();
    // SAFETY: the scheduler selected this exact record on this slot.
    let saved = unsafe { *fixture.zone.record(current).ctx_mut() };
    let ttbr0 = cpu.ttbr.0;
    super::super::dispatch::dispatch_arm_syscall_with_native_process(
        frame,
        &counters,
        core::slice::from_ref(task),
        &[],
        &[],
        &[],
        &[],
        &cache,
        Some(crate::dispatch::Zone {
            tables: fixture.zone,
            cpu,
            user: &crate::sched::HardwareUserWord,
        }),
        None,
        Some(&LoadedVenue),
        page,
        control,
        &saved.native,
        ttbr0,
        service,
        |_| core::ptr::null_mut(),
    )
}

/// Run the production scheduler's switch-in on `fixture.slot`.
fn switch_in(
    fixture: &'static Fixture,
    task: &'static CurrentTask,
    cpu: &mut crate::sched::FakeCpu,
    frame: &mut carrick_el1_abi::TrapFrame,
) -> carrick_el1_abi::Action {
    let mut service = Aarch64NativeProcessService::with_crossing(
        task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        TestStockCrossing::new(&[]),
    );
    let mut switch = ProductionResumeCpu {
        inner: core::mem::take(cpu),
        service: &mut service,
    };
    let counters = carrick_el1_abi::Counters::new();
    let mut handoff = None;
    let mut zone = crate::dispatch::Zone {
        tables: fixture.zone,
        cpu: &mut switch,
        user: &crate::sched::HardwareUserWord,
    };
    let action = super::super::dispatch::native_scheduler(
        &mut zone,
        task,
        &counters,
        fixture.slot,
        &mut handoff,
    )
    .idle_entry(frame, 0);
    *cpu = core::mem::take(&mut switch.inner);
    action
}

/// Witness for #1958. A native fork child (the shape of #1900's exec'd
/// holders and of `el1_sched_two_processes_share_vcpus`'s child) clones a
/// thread through the production ARM adapter. The child is preempted, and
/// the vCPU's executor now holds a task of another process (`stale_pid`:
/// the root, PID 41) or none (`None`: an executor whose host task was
/// detached). The production scheduler switch-in selects the birth, and its
/// first syscall (`FUTEX_WAKE`) must admit through its process owner.
///
/// On main the ARM birth bypassed the owner's `enqueue_thread`, so it was
/// unregistered: the switch-in took `resume_unregistered`, which publishes
/// no namespace PID, and admission's `group_address` lookup with the stale
/// PID refused the thread as `Stale`. The vector's `dispatch_syscall` then
/// served the call through the owner-free pipeline, and the final signal
/// checkpoint (`arm_signal_user_return`) ran the same admission and aborted
/// the carrier with `entry_binding`.
fn born_thread_first_entry_after_foreign_occupant(stale_pid: Option<u32>) {
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
    let mut cpu = crate::sched::FakeCpu::default();
    // The root forks a native child (SIGCHLD).
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = 220;
    frame.x[0] = 17;
    arm_call_with_cpu(fixture, fixture.control, &mut service, &mut frame, &mut cpu).unwrap();
    assert!(frame.x[0] as i64 > 0, "fork result {}", frame.x[0] as i64);
    let child = fixture.zone.runnable_head(fixture.slot).unwrap();
    let child_identity = fixture.zone.record(child).identity();
    // SAFETY: the child owner retains its lifecycle and control.
    let child_page = unsafe { &*(child_identity.lifecycle_page as *const ThreadLifecyclePage) };
    let child_control = unsafe { &*(child_identity.control_slot as *const ThreadControlSlot) };

    // The root's executor blocked on the host; the child runs on this vCPU.
    let task: &'static CurrentTask = &fixture.task;
    fixture.zone.publish_slot(fixture.slot, 0, None, 0);
    task.mm.key.store(0, Ordering::Release);
    assert_eq!(
        switch_in(fixture, task, &mut cpu, &mut frame),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(fixture.zone.slot(fixture.slot).current(), Some(child));
    let child_pid = task
        .visible_pid()
        .expect("the child's owner published its PID");
    assert_ne!(child_pid, fixture.leader.tid as u32);

    // The child clones a thread.
    service.task = task;
    let stack = carrick_test_support::GuestUserBuffer::zeroed(8192);
    let mut clone = carrick_el1_abi::TrapFrame {
        esr: 0x15 << 26,
        ..Default::default()
    };
    clone.x[8] = 220;
    clone.x[..5].copy_from_slice(&[
        THREAD_FLAGS,
        stack.arg() + 8192,
        stack.arg(),
        stack.arg() + 128,
        stack.arg() + 4,
    ]);
    let route = loaded_call(
        fixture,
        task,
        child_page,
        child_control,
        &mut service,
        &mut clone,
        &mut cpu,
    );
    let tid = clone.x[0] as i64;
    assert!(
        tid > 0 && clone.x[0] != THREAD_FLAGS,
        "child thread clone route {route:?} result {tid}"
    );
    let born = fixture
        .zone
        .runnable_head(fixture.slot)
        .expect("the birth is queued on the clone caller's slot");
    assert_ne!(born, child);
    let born_identity = fixture.zone.record(born).identity();
    assert_eq!(born_identity.mm, child_identity.mm);
    // SAFETY: the published birth retains its control slot.
    let born_control = unsafe { &*(born_identity.control_slot as *const ThreadControlSlot) };
    if let Some(work) = task.linux.take_host_work_doorbell() {
        work.settled();
    }
    let _ = task.linux.take_served_boundary();

    // The child is preempted behind its birth, and this vCPU's executor now
    // holds another process's task, or none.
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, child)
            .is_queued()
    );
    let slot_task: &'static CurrentTask = Box::leak(Box::new(CurrentTask::new()));
    if let Some(pid) = stale_pid {
        slot_task.publish_visible_pid(pid);
    }
    assert_eq!(
        switch_in(fixture, slot_task, &mut cpu, &mut frame),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(fixture.zone.slot(fixture.slot).current(), Some(born));
    assert_eq!(
        slot_task.visible_pid(),
        Some(child_pid),
        "the switched-in birth runs with its own process's namespace PID loaded"
    );

    // The born thread's first syscall: FUTEX_WAKE with no waiter.
    let word = carrick_test_support::GuestUserBuffer::from_value(0u32);
    let mut call = carrick_el1_abi::TrapFrame {
        esr: 0x15 << 26,
        slot: u64::from(fixture.slot.raw()),
        ..Default::default()
    };
    call.x[8] = crate::sched::SYS_FUTEX as u64;
    call.x[0] = word.arg();
    call.x[1] = crate::sched::FUTEX_WAKE_PRIVATE;
    call.x[2] = 1;
    let mut born_service = Aarch64NativeProcessService::with_crossing(
        slot_task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        TestStockCrossing::new(&[]),
    );
    let admitted = loaded_call(
        fixture,
        slot_task,
        child_page,
        born_control,
        &mut born_service,
        &mut call,
        &mut cpu,
    );
    assert!(
        admitted.is_ok(),
        "born thread {tid}'s first entry on a vCPU last loaded with PID {stale_pid:?} \
         was refused by its process owner: {admitted:?}"
    );
    assert_eq!(call.x[0], 0, "FUTEX_WAKE with no waiter wakes none");
}

#[test]
fn arm_born_thread_first_entry_after_another_process_on_the_vcpu() {
    born_thread_first_entry_after_foreign_occupant(Some(41));
}

#[test]
fn arm_born_thread_first_entry_on_a_detached_executor() {
    born_thread_first_entry_after_foreign_occupant(None);
}
