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

/// Run the production scheduler's `sched_yield` boundary on `fixture.slot`
/// for the thread `task` names, switching in the next queued record.
fn yield_on(
    fixture: &'static Fixture,
    task: &'static CurrentTask,
    cpu: &mut crate::sched::FakeCpu,
    frame: &mut carrick_el1_abi::TrapFrame,
) -> Option<crate::sched::Served> {
    if let Some(work) = task.linux.take_host_work_doorbell() {
        work.settled();
    }
    let _ = task.linux.take_served_boundary();
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
    let served = super::super::dispatch::native_scheduler(
        &mut zone,
        task,
        &counters,
        fixture.slot,
        &mut handoff,
    )
    .yield_queued(frame);
    *cpu = core::mem::take(&mut switch.inner);
    served
}

/// The real ARM signal checkpoint's admission and delivery for the task
/// loaded on `fixture.slot` (`arm_signal_user_return` past its vector
/// reads), counting each signal frame it writes.
fn signal_checkpoint(
    fixture: &'static Fixture,
    frame: &mut carrick_el1_abi::TrapFrame,
    stack: &carrick_test_support::GuestUserBuffer,
    delivered: &mut usize,
) -> Result<carrick_el1_abi::Action, NativeProcessError> {
    // The host served the forwarded call, settling its boundary's work.
    let task: &'static CurrentTask = &fixture.task;
    if let Some(work) = task.linux.take_host_work_doorbell() {
        work.settled();
    }
    let _ = task.linux.take_served_boundary();
    let mut service = fixture.process_service();
    let ttbr0 = fixture_ttbr0(fixture);
    let mut saved = Box::new(Aarch64ParkedContext::ZERO);
    crate::sched::ThreadCpu::save(
        &mut crate::sched::FakeCpu::default(),
        frame,
        &mut saved,
        crate::sched::CpuExitCause::Svc,
    );
    super::super::dispatch::arm_signal_user_return_entry(
        BornInZoneSource {
            zone: fixture.zone,
            slot: fixture.slot,
        },
        task,
        &saved.native,
        ttbr0,
        fixture.page,
        fixture.control,
        &mut service,
        |process| {
            super::super::arm_signal::deliver_on_user_return_at(
                task,
                fixture.control,
                process,
                frame,
                |_, _| {
                    *delivered += 1;
                    stack.va_at(stack.len())
                },
            )
        },
    )
}

/// Witness for #1958's `entry_binding` at the signal user-return checkpoint
/// (`dispatch.rs` `arm_signal_user_return`, fatal at 2146:25 on `927df2a8a`).
///
/// `el1_sched_two_processes_share_vcpus`: the host-loaded root (a registered
/// native signal owner, host-managed: no zone record) shares its vCPU with
/// its native fork child. EL1 preempts the root into its slot's home record
/// and runs the child, whose owner publishes the child's namespace PID and
/// root incarnation into the slot's `CurrentTask`. Switching the home record
/// back in frees it (`record=none`) and resumes the root through
/// `resume_unregistered`, which restores only the record's thread identity:
/// the root runs on with the child's PID and root incarnation.
///
/// Its next syscall (`FUTEX_WAKE`) then fails admission (`Stale`) and is
/// served owner-free, and the host's signal checkpoint for any forwarded
/// call (esr 0xfffe) runs the same admission and aborts the carrier.
fn host_loaded_root_returns_after_foreign_occupant(pending_signal: bool) {
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
    let mut cpu = crate::sched::FakeCpu {
        ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
        ..Default::default()
    };
    let task: &'static CurrentTask = &fixture.task;
    let root_pid = fixture.leader.tid as u32;
    let root_generation = task.root_generation();
    assert!(root_generation.is_some());

    if pending_signal {
        // SIGUSR1 has a handler, then the root signals itself. Both calls
        // go through the root's process owner, which leaves SIGUSR1 pending
        // for the next user-return checkpoint.
        let action = carrick_test_support::GuestUserBuffer::from_values(&[
            0x70_0000_u64,
            0x0400_0000,
            0x71_0000,
            0,
        ]);
        let mut frame = carrick_el1_abi::TrapFrame::default();
        frame.x[8] = 134;
        frame.x[0] = 10;
        frame.x[1] = action.arg();
        frame.x[3] = 8;
        arm_call_with_cpu(fixture, fixture.control, &mut service, &mut frame, &mut cpu).unwrap();
        assert_eq!(frame.x[0], 0, "rt_sigaction(SIGUSR1)");
    }

    // The root forks a native child (SIGCHLD); the child is queued here.
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = 220;
    frame.x[0] = 17;
    arm_call_with_cpu(fixture, fixture.control, &mut service, &mut frame, &mut cpu).unwrap();
    assert!(frame.x[0] as i64 > 0, "fork result {}", frame.x[0] as i64);
    let child = fixture.zone.runnable_head(fixture.slot).unwrap();
    assert!(fixture.zone.slot(fixture.slot).current().is_none());

    // The root yields: EL1 parks it in the slot's home record and runs the
    // child, whose owner publishes the child's PID into this slot.
    let mut yielded = carrick_el1_abi::TrapFrame {
        esr: 0x15 << 26,
        slot: u64::from(fixture.slot.raw()),
        ..Default::default()
    };
    yielded.x[8] = 124;
    assert!(yield_on(fixture, task, &mut cpu, &mut yielded).is_some());
    assert_eq!(fixture.zone.slot(fixture.slot).current(), Some(child));
    let home = fixture
        .zone
        .slot(fixture.slot)
        .host_record()
        .expect("the host-loaded root parked in its home record");
    let child_pid = task
        .visible_pid()
        .expect("the child's owner published its PID");
    assert_ne!(child_pid, root_pid);

    // The child yields back: the root's home record is switched in.
    assert!(yield_on(fixture, task, &mut cpu, &mut yielded).is_some());
    assert_eq!(fixture.zone.slot(fixture.slot).current(), Some(home));
    assert_eq!(
        task.execution.task.load(Ordering::Acquire),
        fixture.leader.tid,
        "the home switch-in restores the root's thread identity"
    );
    assert_eq!(
        (task.visible_pid(), task.root_generation()),
        (Some(root_pid), root_generation),
        "the host-loaded root resumes with its own namespace PID and root incarnation"
    );

    // The root's next syscall: FUTEX_WAKE with no waiter, through its owner.
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
    let admitted = arm_call_with_cpu(fixture, fixture.control, &mut service, &mut call, &mut cpu);
    assert!(
        admitted.is_ok(),
        "the root's FUTEX_WAKE was refused by its process owner: {admitted:?}"
    );
    assert_eq!(call.x[0], 0, "FUTEX_WAKE with no waiter wakes none");

    if pending_signal {
        let mut frame = carrick_el1_abi::TrapFrame::default();
        frame.x[8] = 131;
        frame.x[..3].copy_from_slice(&[u64::from(root_pid), u64::from(root_pid), 10]);
        arm_call_with_cpu(fixture, fixture.control, &mut service, &mut frame, &mut cpu).unwrap();
        assert_eq!(frame.x[0], 0, "tgkill(self, SIGUSR1)");
    }

    // The host completed a forwarded call (FUTEX_WAKE woke one) and entered
    // the native signal checkpoint (esr 0xfffe), as in the fatal runs.
    let stack = carrick_test_support::GuestUserBuffer::zeroed(16384);
    let mut checkpoint = carrick_el1_abi::TrapFrame {
        esr: 0xfffe,
        slot: u64::from(fixture.slot.raw()),
        elr: 0x40_0004,
        far: word.arg(),
        ..Default::default()
    };
    checkpoint.x[0] = 1;
    checkpoint.x[1] = crate::sched::FUTEX_WAKE_PRIVATE;
    checkpoint.x[8] = crate::sched::SYS_FUTEX as u64;
    let mut delivered = 0;
    let outcome = signal_checkpoint(fixture, &mut checkpoint, &stack, &mut delivered);
    assert_eq!(
        outcome,
        Ok(carrick_el1_abi::Action::Served),
        "the signal checkpoint refused the host-loaded root (vector: entry_binding)"
    );
    if pending_signal {
        assert_eq!(delivered, 1, "SIGUSR1 is delivered at this checkpoint");
        assert_eq!(checkpoint.elr, 0x70_0000, "the handler runs next");
        assert_eq!(checkpoint.x[0], 10);
    } else {
        assert_eq!(delivered, 0, "no signal is owed");
        assert_eq!(checkpoint.x[0], 1, "the call's result is preserved");
    }
    // A second checkpoint owes nothing: the signal is delivered once.
    let mut again = carrick_el1_abi::TrapFrame {
        esr: 0xfffe,
        slot: u64::from(fixture.slot.raw()),
        elr: checkpoint.elr,
        ..Default::default()
    };
    again.x[0] = 2;
    assert_eq!(
        signal_checkpoint(fixture, &mut again, &stack, &mut delivered),
        Ok(carrick_el1_abi::Action::Served)
    );
    assert_eq!(delivered, usize::from(pending_signal));
    assert_eq!(again.x[0], 2);
}

#[test]
fn arm_host_loaded_root_signal_checkpoint_after_another_process_on_the_vcpu() {
    host_loaded_root_returns_after_foreign_occupant(false);
}

#[test]
fn arm_host_loaded_root_delivers_pending_signal_once_after_another_process_on_the_vcpu() {
    host_loaded_root_returns_after_foreign_occupant(true);
}
