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

/// The signal checkpoint's refusal is returned, never served (#1958 review).
/// A recorded host-loaded root has SIGUSR1 pending when its slot carries a
/// foreign namespace PID: admission refuses the binding as `Stale`, and
/// `arm_signal_user_return_entry` must hand that refusal to the vector
/// (`entry_binding`) without delivering the signal or touching the frame.
/// With its own PID back, the same checkpoint delivers SIGUSR1 once.
#[test]
fn arm_signal_checkpoint_returns_a_stale_admission_refusal() {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    let mut cpu = crate::sched::FakeCpu {
        ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
        ..Default::default()
    };
    let task: &'static CurrentTask = &fixture.task;
    let root_pid = fixture.leader.tid as u32;
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
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = 131;
    frame.x[..3].copy_from_slice(&[u64::from(root_pid), u64::from(root_pid), 10]);
    arm_call_with_cpu(fixture, fixture.control, &mut service, &mut frame, &mut cpu).unwrap();
    assert_eq!(frame.x[0], 0, "tgkill(self, SIGUSR1)");
    assert!(
        fixture.control.zone_record().is_some(),
        "the root's admission recorded it in the zone"
    );

    // Another process's PID and root incarnation are live on the slot: the
    // binding is stale.
    let root_generation = task.root_generation().unwrap();
    task.publish_visible_pid(41);
    task.publish_root_generation(ContextGeneration::new(NonZeroU64::new(202).unwrap()));
    let stack = carrick_test_support::GuestUserBuffer::zeroed(16384);
    let mut checkpoint = carrick_el1_abi::TrapFrame {
        esr: 0xfffe,
        slot: u64::from(fixture.slot.raw()),
        elr: 0x40_0004,
        ..Default::default()
    };
    checkpoint.x[0] = 3;
    checkpoint.x[8] = 63;
    let before = checkpoint;
    let mut delivered = 0;
    assert_eq!(
        signal_checkpoint(fixture, &mut checkpoint, &stack, &mut delivered),
        Err(NativeProcessError::Stale),
        "a stale admission is returned to the vector, never served"
    );
    assert_eq!(delivered, 0, "a refused admission delivers no signal");
    assert_eq!(checkpoint, before, "a refused admission leaves the frame");

    // Its own binding restored, the same checkpoint delivers SIGUSR1 once.
    task.publish_visible_pid(root_pid);
    task.publish_root_generation(root_generation);
    assert_eq!(
        signal_checkpoint(fixture, &mut checkpoint, &stack, &mut delivered),
        Ok(carrick_el1_abi::Action::Served)
    );
    assert_eq!(delivered, 1);
    assert_eq!(checkpoint.elr, 0x70_0000, "the handler runs next");
    assert_eq!(checkpoint.x[0], 10);
}

/// `Quarantined` cannot be forced through the signal checkpoint's admission:
/// for a registered entry every refusal there is `Stale`
/// (`admit_entry_runtime`, `authenticate_registered`), and its delivery
/// closure returns a route, not an error. The nearest production seam over
/// the same admitted delivery that raises it is the declined-fault entry
/// (`deliver_declined_fault_signal_with`): an unexpected completion route is
/// `Quarantined`, and the vector's adapter returns it rather than serving.
#[test]
fn arm_declined_fault_returns_a_quarantined_delivery_refusal() {
    use carrick_signal_core::policy::{Action, Disposition, Signal};

    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    let ignore = Action {
        disposition: Disposition::Ignore,
        ..Default::default()
    };
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |process| {
                process
                    .signal_venue()
                    .unwrap()
                    .rt_sigaction(Signal::PIPE, Some(ignore))
                    .unwrap();
            },
        )
        .unwrap();
    let mut frame = carrick_el1_abi::TrapFrame {
        slot: u64::from(fixture.slot.raw()),
        esr: 0x9200_004f,
        far: crate::mm_portal::test_support::VA,
        elr: 0x40_0200,
        spsr: 0x3c0,
        ..Default::default()
    };
    let before = frame;
    let mut owner_wait = None;
    assert_eq!(
        super::super::dispatch::arm_deliver_declined_fault_signal_with(
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            &fixture.task,
            &ThreadCtx::ZERO,
            fixture_ttbr0(fixture),
            fixture.page,
            fixture.control,
            &mut service,
            &mut frame,
            &mut owner_wait,
            |_, _| Some(carrick_personality_linux::dispatch::CompletionRoute::Forward),
        ),
        Err(NativeProcessError::Quarantined),
        "an unexpected delivery route is returned as Quarantined, never served"
    );
    assert!(owner_wait.is_none());
    assert_eq!(frame, before, "a refused delivery leaves the frame");
}

/// Exact `raw_clone_thread` flags from `fixtures/embed-el1-sched/src/threads.rs`
/// (`tgkill_after_clone`): `CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
/// CLONE_THREAD | CLONE_SYSVSEM | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID`.
const TGKILL_AFTER_CLONE_FLAGS: u64 = 0x0035_0f00;
const SIGUSR1_NUM: u64 = 10;
const SIGUSR2_NUM: u64 = 12;

#[derive(Clone, Copy)]
struct MultiSlotEnv {
    fixture: &'static Fixture,
    tasks: &'static [CurrentTask; 4],
    crossing: &'static TestStockCrossing,
}

impl MultiSlotEnv {
    fn new() -> Self {
        let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
        fixture.zone.spaces.set_idle_ttbr(0x30000);
        let tasks = Box::leak(Box::new(core::array::from_fn(|_| CurrentTask::new())));
        let stock_pages: Vec<u64> = (0..24).map(|i| 0x20000 + i * 0x1000).collect();
        let crossing = Box::leak(Box::new(TestStockCrossing::new(&stock_pages)));
        Self {
            fixture,
            tasks,
            crossing,
        }
    }

    fn service_for(
        self,
        task: &'static CurrentTask,
        slot: SlotId,
    ) -> Aarch64NativeProcessService<'static, &'static TestStockCrossing> {
        let words = Box::leak(Box::new(
            self.fixture.tables.live(&self.fixture.maintenance),
        ));
        Aarch64NativeProcessService::with_crossing(
            task,
            slot,
            self.fixture.zone,
            self.fixture.region.table(),
            NonZeroU64::MIN,
            self.crossing,
        )
        .with_words(words)
    }

    fn service(
        self,
        slot: SlotId,
    ) -> Aarch64NativeProcessService<'static, &'static TestStockCrossing> {
        self.service_for(&self.tasks[slot.index()], slot)
    }

    fn init_guest_slot(self, slot: SlotId) {
        self.fixture.zone.drive(slot, 1);
        self.fixture.zone.publish_slot(slot, 0, None, 0);
        self.fixture.zone.enter_guest(slot);
    }

    fn switch_in(self, slot: SlotId, cpu: &mut crate::sched::FakeCpu) -> carrick_el1_abi::Action {
        let task = &self.tasks[slot.index()];
        let mut service = Aarch64NativeProcessService::with_crossing(
            task,
            slot,
            self.fixture.zone,
            self.fixture.region.table(),
            NonZeroU64::MIN,
            TestStockCrossing::new(&[]),
        );
        let mut switch = ProductionResumeCpu {
            inner: core::mem::take(cpu),
            service: &mut service,
        };
        let counters = carrick_el1_abi::Counters::new();
        let mut handoff = None;
        let mut dummy = carrick_el1_abi::TrapFrame::default();
        let mut zone = crate::dispatch::Zone {
            tables: self.fixture.zone,
            cpu: &mut switch,
            user: &crate::sched::HardwareUserWord,
        };
        let action = super::super::dispatch::native_scheduler(
            &mut zone,
            task,
            &counters,
            slot,
            &mut handoff,
        )
        .idle_entry(&mut dummy, 0);
        *cpu = core::mem::take(&mut switch.inner);
        action
    }

    fn call(
        self,
        slot: SlotId,
        page: &'static ThreadLifecyclePage,
        control: &'static ThreadControlSlot,
        counters: &carrick_el1_abi::Counters,
        frame: &mut carrick_el1_abi::TrapFrame,
        cpu: &mut crate::sched::FakeCpu,
    ) -> carrick_personality_linux::dispatch::CompletionRoute {
        let cache = Box::new(carrick_el1_abi::InotifyNameCache::new());
        let saved_native = match self.fixture.zone.slot(slot).current() {
            // SAFETY: `slot` exclusively owns `current` while OnCpu.
            Some(current) => unsafe { self.fixture.zone.record(current).ctx_mut().native },
            None => ThreadCtx::ZERO,
        };
        let ttbr0 = cpu.ttbr.0;
        frame.slot = u64::from(slot.raw());
        frame.esr = 0x15 << 26;
        let mut service = self.service(slot);
        super::super::dispatch::dispatch_arm_syscall_with_native_process(
            frame,
            counters,
            self.tasks,
            &[],
            &[],
            &[],
            &[],
            &cache,
            Some(crate::dispatch::Zone {
                tables: self.fixture.zone,
                cpu,
                user: &crate::sched::HardwareUserWord,
            }),
            None,
            Some(&LoadedVenue),
            page,
            control,
            &saved_native,
            ttbr0,
            &mut service,
            |_| core::ptr::null_mut(),
        )
        .expect("syscall must dispatch cleanly")
    }

    fn tgkill(
        self,
        slot: SlotId,
        page: &'static ThreadLifecyclePage,
        control: &'static ThreadControlSlot,
        cpu: &mut crate::sched::FakeCpu,
        (tgid, tid): (u32, u32),
        sig: u64,
    ) -> i64 {
        let counters = carrick_el1_abi::Counters::new();
        let mut frame = carrick_el1_abi::TrapFrame::default();
        frame.x[8] = 131; // SYS_tgkill
        frame.x[..3].copy_from_slice(&[u64::from(tgid), u64::from(tid), sig]);
        self.call(slot, page, control, &counters, &mut frame, cpu);
        frame.x[0] as i64
    }

    fn peer_kill(
        self,
        slot: SlotId,
        page: &'static ThreadLifecyclePage,
        control: &'static ThreadControlSlot,
        cpu: &mut crate::sched::FakeCpu,
        pid_or_tid: u32,
        sig: u64,
    ) -> i64 {
        let counters = carrick_el1_abi::Counters::new();
        let mut frame = carrick_el1_abi::TrapFrame::default();
        frame.x[8] = 129; // SYS_kill
        frame.x[..2].copy_from_slice(&[u64::from(pid_or_tid), sig]);
        self.call(slot, page, control, &counters, &mut frame, cpu);
        frame.x[0] as i64
    }

    fn deliver_user_return(
        self,
        slot: SlotId,
        page: &'static ThreadLifecyclePage,
        control: &'static ThreadControlSlot,
        cpu: &crate::sched::FakeCpu,
        user_sp: u64,
        frame: &mut carrick_el1_abi::TrapFrame,
    ) -> Option<carrick_personality_linux::dispatch::CompletionRoute> {
        use zerocopy::IntoBytes;
        struct FirstEntryArmMachine {
            backend: crate::arm_signal::LinuxAarch64Backend,
            user_sp: carrick_guest_arch::UserVa,
        }
        impl crate::signal_delivery::SignalMachine<Aarch64ParkedContext> for FirstEntryArmMachine {
            type Backend = crate::arm_signal::LinuxAarch64Backend;
            fn backend(&mut self) -> &mut Self::Backend {
                &mut self.backend
            }
            fn user_sp(&self, _: &carrick_el1_abi::TrapFrame) -> carrick_guest_arch::UserVa {
                self.user_sp
            }
            fn restart(
                &self,
                _: &mut carrick_el1_abi::TrapFrame,
                _: &Aarch64ParkedContext,
            ) -> bool {
                false
            }
            fn group_exit_custody(
                &self,
                _: &CurrentTask,
            ) -> carrick_personality_linux::dispatch::CompletionRoute {
                carrick_personality_linux::dispatch::CompletionRoute::InvalidCompletion
            }
            fn published_stack(&mut self, sp: carrick_guest_arch::UserVa) {
                self.user_sp = sp;
            }
        }
        let task = &self.tasks[slot.index()];
        let mut service = self.service(slot);
        let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
        let mut machine = FirstEntryArmMachine {
            backend: crate::arm_signal::LinuxAarch64Backend,
            user_sp: carrick_guest_arch::UserVa::new(user_sp),
        };
        with_process_entry(
            BornInZoneSource {
                zone: self.fixture.zone,
                slot,
            },
            task,
            &ThreadCtx::ZERO,
            cpu.ttbr.0,
            page,
            control,
            &mut service,
            |process| {
                crate::arm_signal::deliver_on_user_return_with(
                    task,
                    control,
                    process,
                    frame,
                    fp.as_bytes(),
                    &mut machine,
                )
            },
        )
        .expect("first-entry user-return checkpoint must admit")
    }

    fn poll_sig(
        self,
        slot: SlotId,
        page: &'static ThreadLifecyclePage,
        control: &'static ThreadControlSlot,
        cpu: &mut crate::sched::FakeCpu,
        sig: u64,
    ) -> i64 {
        let sigset = carrick_test_support::GuestUserBuffer::from_value(1u64 << (sig - 1));
        let zero_ts = carrick_test_support::GuestUserBuffer::from_value([0i64, 0i64]);
        let counters = carrick_el1_abi::Counters::new();
        let mut frame = carrick_el1_abi::TrapFrame::default();
        frame.x[8] = 137; // SYS_rt_sigtimedwait
        frame.x[..4].copy_from_slice(&[sigset.arg(), 0, zero_ts.arg(), 8]);
        self.call(slot, page, control, &counters, &mut frame, cpu);
        frame.x[0] as i64
    }

    fn install_handler(
        self,
        slot: SlotId,
        page: &'static ThreadLifecyclePage,
        control: &'static ThreadControlSlot,
        cpu: &mut crate::sched::FakeCpu,
        sig: u64,
    ) {
        let act = carrick_test_support::GuestUserBuffer::from_value([0x40_1000u64, 0u64, 0u64]);
        let counters = carrick_el1_abi::Counters::new();
        let mut frame = carrick_el1_abi::TrapFrame::default();
        frame.x[8] = 134; // SYS_rt_sigaction
        frame.x[..4].copy_from_slice(&[sig, act.arg(), 0, 8]);
        self.call(slot, page, control, &counters, &mut frame, cpu);
        assert_eq!(frame.x[0] as i64, 0);
    }

    fn clone_thread(
        self,
        slot: SlotId,
        page: &'static ThreadLifecyclePage,
        control: &'static ThreadControlSlot,
        counters: &carrick_el1_abi::Counters,
        cpu: &mut crate::sched::FakeCpu,
    ) -> (
        carrick_personality_linux::dispatch::CompletionRoute,
        i64,
        u32,
    ) {
        let stack = carrick_test_support::GuestUserBuffer::zeroed(8192);
        let ptid = carrick_test_support::GuestUserBuffer::from_value(0u32);
        let ctid = carrick_test_support::GuestUserBuffer::from_value(0xffffu32);
        let mut clone = carrick_el1_abi::TrapFrame::default();
        clone.x[8] = 220; // SYS_clone
        clone.x[..5].copy_from_slice(&[
            TGKILL_AFTER_CLONE_FLAGS,
            stack.arg() + 8192,
            ptid.arg(),
            0,
            ctid.arg(),
        ]);
        let route = self.call(slot, page, control, counters, &mut clone, cpu);
        (route, clone.x[0] as i64, ptid.get::<u32>(0))
    }
}

struct NativeOwnedTwoThreadHarness {
    env: MultiSlotEnv,
    target_pid: u32,
    target_page: &'static ThreadLifecyclePage,
    leader_control: &'static ThreadControlSlot,
    leader_cpu: crate::sched::FakeCpu,
    sibling_control: &'static ThreadControlSlot,
    sibling_cpu: crate::sched::FakeCpu,
    born_record: RecordId,
    born_tid: u32,
    born_control: &'static ThreadControlSlot,
    peer_page: &'static ThreadLifecyclePage,
    peer_control: &'static ThreadControlSlot,
    peer_cpu: crate::sched::FakeCpu,
}

fn setup_native_owned_ring_birth_before_first_entry() -> NativeOwnedTwoThreadHarness {
    let env = MultiSlotEnv::new();
    let mut boot_service = env.service_for(&env.fixture.task, env.fixture.slot);
    let mut boot_cpu = crate::sched::FakeCpu {
        ttbr: (fixture_ttbr0(env.fixture), fixture_ttbr0(env.fixture)),
        ..Default::default()
    };
    let mut fork = carrick_el1_abi::TrapFrame::default();
    fork.x[8] = 220;
    fork.x[0] = 17;
    arm_call_with_cpu(
        env.fixture,
        env.fixture.control,
        &mut boot_service,
        &mut fork,
        &mut boot_cpu,
    )
    .unwrap();
    let target_leader = env.fixture.zone.runnable_head(env.fixture.slot).unwrap();
    let target_id = env.fixture.zone.record(target_leader).identity();
    let target_page = unsafe { &*(target_id.lifecycle_page as *const ThreadLifecyclePage) };
    let leader_control = unsafe { &*(target_id.control_slot as *const ThreadControlSlot) };

    let mut fork_peer = carrick_el1_abi::TrapFrame::default();
    fork_peer.x[8] = 220;
    fork_peer.x[0] = 17;
    arm_call_with_cpu(
        env.fixture,
        env.fixture.control,
        &mut boot_service,
        &mut fork_peer,
        &mut boot_cpu,
    )
    .unwrap();

    let mut leader_cpu = crate::sched::FakeCpu::default();
    env.fixture.zone.publish_slot(SlotId::new(0), 0, None, 0);
    assert_eq!(
        env.switch_in(SlotId::new(0), &mut leader_cpu),
        carrick_el1_abi::Action::Served
    );
    let target_pid = env.tasks[0].visible_pid().unwrap();

    env.init_guest_slot(SlotId::new(2));
    let mut peer_cpu = crate::sched::FakeCpu::default();
    assert_eq!(
        env.switch_in(SlotId::new(2), &mut peer_cpu),
        carrick_el1_abi::Action::Served
    );
    assert_ne!(env.tasks[2].visible_pid().unwrap(), target_pid);
    let peer_rec = env.fixture.zone.slot(SlotId::new(2)).current().unwrap();
    let peer_id = env.fixture.zone.record(peer_rec).identity();
    let peer_page = unsafe { &*(peer_id.lifecycle_page as *const ThreadLifecyclePage) };
    let peer_control = unsafe { &*(peer_id.control_slot as *const ThreadControlSlot) };

    for sig in [SIGUSR1_NUM, SIGUSR2_NUM] {
        env.install_handler(
            SlotId::new(0),
            target_page,
            leader_control,
            &mut leader_cpu,
            sig,
        );
    }

    let counters = carrick_el1_abi::Counters::new();
    let (_, sib1_tid, _) = env.clone_thread(
        SlotId::new(0),
        target_page,
        leader_control,
        &counters,
        &mut leader_cpu,
    );
    let sib1_rec = env.fixture.zone.runnable_head(SlotId::new(0)).unwrap();
    let sibling_control = unsafe {
        &*(env.fixture.zone.record(sib1_rec).identity().control_slot as *const ThreadControlSlot)
    };

    env.init_guest_slot(SlotId::new(1));
    let mut sibling_cpu = crate::sched::FakeCpu::default();
    assert_eq!(
        env.switch_in(SlotId::new(1), &mut sibling_cpu),
        carrick_el1_abi::Action::Served
    );
    let mut gettid = carrick_el1_abi::TrapFrame::default();
    gettid.x[8] = 178;
    env.call(
        SlotId::new(1),
        target_page,
        sibling_control,
        &counters,
        &mut gettid,
        &mut sibling_cpu,
    );
    assert_eq!(gettid.x[0] as i64, sib1_tid);

    let (_, born_tid, born_ptid) = env.clone_thread(
        SlotId::new(0),
        target_page,
        leader_control,
        &counters,
        &mut leader_cpu,
    );
    assert!(born_tid > sib1_tid);
    assert_eq!(born_ptid, born_tid as u32);
    let born_record = env.fixture.zone.runnable_head(SlotId::new(0)).unwrap();
    let born_control = unsafe {
        &*(env.fixture.zone.record(born_record).identity().control_slot as *const ThreadControlSlot)
    };
    assert_eq!(
        counters.lifecycle_declines[carrick_el1_abi::LifecycleDecline::ClonePoolEmpty as usize]
            .load(Ordering::Relaxed),
        0
    );

    NativeOwnedTwoThreadHarness {
        env,
        target_pid,
        target_page,
        leader_control,
        leader_cpu,
        sibling_control,
        sibling_cpu,
        born_record,
        born_tid: born_tid as u32,
        born_control,
        peer_page,
        peer_control,
        peer_cpu,
    }
}

fn publish_host_born_sibling_only(
    fixture: &'static Fixture,
    visible_tid: u32,
) -> &'static ThreadControlSlot {
    let mut binding_tid = 0;
    for _ in 0..64 {
        let (issued_tid, reservation) = fixture.host_ids.reserve_thread().unwrap();
        fixture
            .host_threads
            .lock()
            .unwrap()
            .push(reservation.commit());
        binding_tid = issued_tid.raw() as u32;
        if binding_tid >= visible_tid {
            break;
        }
    }
    assert!(binding_tid >= visible_tid);
    let generation = u64::from(binding_tid - 30);
    let thread_generation = u64::from(binding_tid + 60);
    fixture
        .zone
        .namespace()
        .with_view(&carrick_sched_core::ShortLockSpin, |ns| {
            use carrick_sched_core::process::identity_allocator::{
                ClaimKind, VisibleIdentity, VisibleNamespace,
            };
            let raw_tid = binding_tid as i32;
            if !ns.is_reserved_number(raw_tid) {
                ns.reserve_exact(raw_tid, ClaimKind::Thread).unwrap();
            }
            let domain = VisibleNamespace::new(NonZeroU32::MIN, NonZeroU32::MIN);
            let _ = ns.bind_visible_domain(raw_tid, domain);
            ns.advance_visible_past(
                domain,
                VisibleIdentity::from_existing_member(NonZeroU32::new(visible_tid).unwrap()),
            )
            .unwrap();
        });
    let control = Box::leak(Box::new(ThreadControlSlot::new()));
    control
        .reset_for_host_birth(carrick_el1_abi::BlockedMask(0))
        .unwrap();
    assert!(control.publish_visible_tid(visible_tid));
    control.publish_host_birth_identity(
        carrick_core::terminal::ThreadBirthIdentity::from_parts(
            carrick_el1_abi::EntryTaskKey::from_raw(u64::from(binding_tid)),
            carrick_core_abi::entry::BirthSerial::of_task(
                TaskSerial::from_raw_u64(generation).unwrap(),
            ),
            carrick_el1_abi::EntryThreadGeneration::from_raw(thread_generation),
        )
        .unwrap(),
    );
    let birth_slot = fixture.page.reserve_host_birth().expect("host birth slot");
    carrick_el1_abi::Lifecycle::thread_born(fixture.page).unwrap();
    assert!(
        fixture
            .page
            .publish_host_birth(birth_slot, control.host_birth_identity().unwrap())
    );
    control
}

fn adopt_host_sibling_on_slot(
    env: MultiSlotEnv,
    slot: SlotId,
    sib_control: &'static ThreadControlSlot,
    keep_on_cpu: bool,
) -> (RecordId, crate::sched::FakeCpu) {
    let fixture = env.fixture;
    let birth = sib_control.host_birth_identity().unwrap();
    let task = &env.tasks[slot.index()];
    task.set(
        El1TaskId::from_linux_tid(birth.task().raw() as i32),
        carrick_el1_abi::SnapshotGeneration::from_raw(birth.birth().raw()),
        fixture.leader.file_table,
    );
    task.mm.key.store(fixture.leader.mm, Ordering::Release);
    task.mm
        .thread_generation
        .store(birth.thread().raw(), Ordering::Release);
    task.publish_visible_pid(41);
    task.publish_root_generation(fixture.address.generation);
    task.publish_lifecycle(
        fixture.page as *const _ as u64,
        sib_control as *const _ as u64,
    );

    fixture.zone.drive(slot, fixture.leader.mm);
    fixture
        .zone
        .publish_slot(slot, fixture.leader.mm, Some(0), 1);
    fixture.zone.enter_guest(slot);
    fixture.zone.install_space(slot, fixture.leader.mm).unwrap();
    let sib_record = fixture
        .zone
        .current_or_new(
            slot,
            ThreadIdentity {
                tid: birth.task().raw(),
                serial: birth.thread().raw(),
                mm: fixture.leader.mm,
                file_table: fixture.leader.file_table,
                generation: birth.birth().raw(),
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 1,
                lifecycle_page: fixture.page as *const _ as u64,
                control_slot: sib_control as *const _ as u64,
            },
        )
        .unwrap();
    sib_control.bind_zone_record(fixture.zone.record_ref(sib_record));
    unsafe {
        *fixture.zone.record(sib_record).ctx_mut() = Aarch64ParkedContext::from_register(
            ThreadCtx::ZERO,
            fixture_ttbr0(fixture),
            fixture.address.mm.raw().get(),
            fixture.address.generation.raw().get(),
        );
    }
    let mut sib_cpu = crate::sched::FakeCpu {
        ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
        ..Default::default()
    };
    if keep_on_cpu {
        assert!(fixture.zone.requeue_preempted(slot, sib_record).is_queued());
        assert_eq!(
            fixture.zone.switch_in_full(slot).unwrap().record,
            sib_record
        );
        let counters = carrick_el1_abi::Counters::new();
        let mut gettid = carrick_el1_abi::TrapFrame::default();
        gettid.x[8] = 178;
        env.call(
            slot,
            fixture.page,
            sib_control,
            &counters,
            &mut gettid,
            &mut sib_cpu,
        );
        assert_eq!(gettid.x[0] as u32, sib_control.visible_tid().unwrap());
    } else {
        let mut sib_service = env.service(slot);
        with_process_entry(
            BornInZoneSource {
                zone: fixture.zone,
                slot,
            },
            task,
            &ThreadCtx::ZERO,
            sib_cpu.ttbr.0,
            fixture.page,
            sib_control,
            &mut sib_service,
            |_| {
                assert!(fixture.zone.requeue_preempted(slot, sib_record).is_queued());
            },
        )
        .unwrap();
        assert_eq!(fixture.zone.slot(slot).current(), None);
        assert_eq!(fixture.zone.slot(slot).queued(), 1);
    }
    (sib_record, sib_cpu)
}

fn stock_arm_root_pool_identity(
    fixture: &'static Fixture,
    visible_tid: u32,
    serial: u64,
) -> &'static ThreadControlSlot {
    fixture
        .zone
        .namespace()
        .with_view(&carrick_sched_core::ShortLockSpin, |ns| {
            use carrick_sched_core::process::identity_allocator::*;
            let raw_tid = visible_tid as i32;
            if !ns.is_reserved_number(raw_tid) {
                ns.reserve_exact(raw_tid, ClaimKind::Thread).unwrap();
            }
            let domain = VisibleNamespace::new(NonZeroU32::MIN, NonZeroU32::MIN);
            let _ = ns.bind_visible_domain(raw_tid, domain);
            ns.advance_visible_past(
                domain,
                VisibleIdentity::from_existing_member(NonZeroU32::new(visible_tid).unwrap()),
            )
            .unwrap();
        });
    let control = Box::leak(Box::new(ThreadControlSlot::new()));
    // Serial `n` stocks pool entry `n - 1`.
    let entry = fixture
        .page
        .stock(
            serial as usize - 1,
            carrick_el1_abi::EntryIdentity {
                tid: visible_tid,
                visible_tid,
                thread_serial: 200 + serial,
                birth: carrick_core_abi::entry::BirthSerial::of_task(
                    TaskSerial::from_raw_u64(50 + serial).unwrap(),
                ),
                uid_credit: 0,
            },
        )
        .unwrap();
    fixture
        .page
        .bind_control_address(entry, control as *const _ as u64)
        .unwrap();
    control
}

struct ArmRootTwoThreadHarness {
    env: MultiSlotEnv,
    root_cpu: crate::sched::FakeCpu,
    sib_control: &'static ThreadControlSlot,
    sib_cpu: crate::sched::FakeCpu,
    peer_page: &'static ThreadLifecyclePage,
    peer_control: &'static ThreadControlSlot,
    peer_cpu: crate::sched::FakeCpu,
}

fn setup_arm_root_two_live_threads_and_peer() -> ArmRootTwoThreadHarness {
    let env = MultiSlotEnv::new();
    let fixture = env.fixture;
    env.tasks[0].set(
        El1TaskId::from_linux_tid(fixture.leader.tid as i32),
        carrick_el1_abi::SnapshotGeneration::from_raw(fixture.leader.generation),
        fixture.leader.file_table,
    );
    env.tasks[0]
        .mm
        .key
        .store(fixture.leader.mm, Ordering::Release);
    env.tasks[0]
        .mm
        .thread_generation
        .store(fixture.leader.serial, Ordering::Release);
    env.tasks[0].publish_visible_pid(41);
    env.tasks[0].publish_root_generation(fixture.address.generation);
    env.tasks[0].publish_lifecycle(
        fixture.page as *const _ as u64,
        fixture.control as *const _ as u64,
    );

    let root_record = fixture
        .zone
        .current_or_new(SlotId::new(0), fixture.leader)
        .unwrap();
    fixture
        .control
        .bind_zone_record(fixture.zone.record_ref(root_record));
    unsafe {
        *fixture.zone.record(root_record).ctx_mut() = Aarch64ParkedContext::from_register(
            ThreadCtx::ZERO,
            fixture_ttbr0(fixture),
            fixture.address.mm.raw().get(),
            fixture.address.generation.raw().get(),
        );
    }
    assert!(
        fixture
            .zone
            .requeue_preempted(SlotId::new(0), root_record)
            .is_queued()
    );
    assert_eq!(
        fixture.zone.switch_in_full(SlotId::new(0)).unwrap().record,
        root_record
    );

    let mut root_cpu = crate::sched::FakeCpu {
        ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
        ..Default::default()
    };
    let counters = carrick_el1_abi::Counters::new();
    let mut fork_frame = carrick_el1_abi::TrapFrame::default();
    fork_frame.x[8] = 220;
    fork_frame.x[0] = 17;
    env.call(
        SlotId::new(0),
        fixture.page,
        fixture.control,
        &counters,
        &mut fork_frame,
        &mut root_cpu,
    );
    assert!(fork_frame.x[0] as i64 > 41);
    let peer_record = fixture.zone.runnable_head(SlotId::new(0)).unwrap();
    let peer_id = fixture.zone.record(peer_record).identity();
    let peer_page = unsafe { &*(peer_id.lifecycle_page as *const ThreadLifecyclePage) };
    let peer_control = unsafe { &*(peer_id.control_slot as *const ThreadControlSlot) };

    env.init_guest_slot(SlotId::new(2));
    let mut peer_cpu = crate::sched::FakeCpu::default();
    assert_eq!(
        env.switch_in(SlotId::new(2), &mut peer_cpu),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(
        fixture.zone.slot(SlotId::new(2)).current(),
        Some(peer_record)
    );

    let sib_control = publish_host_born_sibling_only(fixture, 43);
    let (_, sib_cpu) = adopt_host_sibling_on_slot(env, SlotId::new(1), sib_control, true);

    for sig in [SIGUSR1_NUM, SIGUSR2_NUM] {
        env.install_handler(
            SlotId::new(0),
            fixture.page,
            fixture.control,
            &mut root_cpu,
            sig,
        );
    }
    assert_eq!(
        fixture.zone.slot(SlotId::new(0)).current(),
        Some(root_record)
    );

    ArmRootTwoThreadHarness {
        env,
        root_cpu,
        sib_control,
        sib_cpu,
        peer_page,
        peer_control,
        peer_cpu,
    }
}

/// Passing CONTROL: in the ARM root two-live-thread harness, a sibling that is
/// registered with the process owner and parked in `Claim::Queued` on its own
/// slot (`SlotId(3)`) accepts `tgkill(41, 44, SIGUSR1) == 0` and observes
/// `SIGUSR1` pending once when selected.
#[test]
fn arm_registered_queued_sibling_tgkill_control() {
    let mut h = setup_arm_root_two_live_threads_and_peer();
    let f = h.env.fixture;
    let queued_control = publish_host_born_sibling_only(f, 44);
    let (queued_rec, mut queued_cpu) =
        adopt_host_sibling_on_slot(h.env, SlotId::new(3), queued_control, false);

    assert_eq!(
        h.env.tgkill(
            SlotId::new(0),
            f.page,
            f.control,
            &mut h.root_cpu,
            (41, 44),
            SIGUSR1_NUM
        ),
        0,
        "registered queued sibling control must accept tgkill"
    );
    assert_eq!(
        h.env.poll_sig(
            SlotId::new(0),
            f.page,
            f.control,
            &mut h.root_cpu,
            SIGUSR1_NUM
        ),
        -11
    );
    assert_eq!(
        h.env.poll_sig(
            SlotId::new(1),
            f.page,
            h.sib_control,
            &mut h.sib_cpu,
            SIGUSR1_NUM
        ),
        -11
    );

    assert_eq!(
        h.env.switch_in(SlotId::new(3), &mut queued_cpu),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(f.zone.slot(SlotId::new(3)).current(), Some(queued_rec));
    assert_eq!(
        h.env.poll_sig(
            SlotId::new(3),
            f.page,
            queued_control,
            &mut queued_cpu,
            SIGUSR1_NUM
        ),
        SIGUSR1_NUM as i64
    );
    assert_eq!(
        h.env.poll_sig(
            SlotId::new(3),
            f.page,
            queued_control,
            &mut queued_cpu,
            SIGUSR1_NUM
        ),
        -11
    );
}

#[test]
fn arm_native_owned_ring_born_tgkill_before_first_entry_queues_signal_once() {
    let mut h = setup_native_owned_ring_birth_before_first_entry();
    assert_eq!(
        h.env.tgkill(
            SlotId::new(0),
            h.target_page,
            h.leader_control,
            &mut h.leader_cpu,
            (h.target_pid, h.born_tid),
            SIGUSR1_NUM,
        ),
        0,
        "native-owned ring-born tgkill before first entry must return 0"
    );
    assert_eq!(
        h.env.poll_sig(
            SlotId::new(0),
            h.target_page,
            h.leader_control,
            &mut h.leader_cpu,
            SIGUSR1_NUM
        ),
        -11
    );
    assert_eq!(
        h.env.poll_sig(
            SlotId::new(1),
            h.target_page,
            h.sibling_control,
            &mut h.sibling_cpu,
            SIGUSR1_NUM
        ),
        -11
    );

    h.env.init_guest_slot(SlotId::new(3));
    let mut born_cpu = crate::sched::FakeCpu::default();
    assert_eq!(
        h.env.switch_in(SlotId::new(3), &mut born_cpu),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(
        h.env.fixture.zone.slot(SlotId::new(3)).current(),
        Some(h.born_record)
    );
    assert_eq!(
        h.env.poll_sig(
            SlotId::new(3),
            h.target_page,
            h.born_control,
            &mut born_cpu,
            SIGUSR1_NUM
        ),
        SIGUSR1_NUM as i64
    );
    assert_eq!(
        h.env.poll_sig(
            SlotId::new(3),
            h.target_page,
            h.born_control,
            &mut born_cpu,
            SIGUSR1_NUM
        ),
        -11
    );
}

#[test]
#[ignore = "red on main: kill(nonleader) is #1994 (assert_eq! at born_thread_entry_tests.rs:1320)"]
fn arm_native_owned_ring_born_peer_kill_before_first_entry() {
    let mut h = setup_native_owned_ring_birth_before_first_entry();
    assert_eq!(
        h.env.tgkill(
            SlotId::new(0),
            h.target_page,
            h.leader_control,
            &mut h.leader_cpu,
            (h.target_pid, h.born_tid),
            SIGUSR1_NUM,
        ),
        0
    );
    let peer_kill_rc = h.env.peer_kill(
        SlotId::new(2),
        h.peer_page,
        h.peer_control,
        &mut h.peer_cpu,
        h.born_tid,
        SIGUSR2_NUM,
    );
    assert_eq!(
        peer_kill_rc, 0,
        "peer kill(born_tid, SIGUSR2) before first entry must return 0"
    );
}

#[test]
fn arm_root_ring_born_tgkill_before_first_entry_queues_signal_once() {
    let mut h = setup_arm_root_two_live_threads_and_peer();
    let f = h.env.fixture;
    let born_control = stock_arm_root_pool_identity(f, 44, 1);
    let counters = carrick_el1_abi::Counters::new();
    let (_, clone_rc, ptid) = h.env.clone_thread(
        SlotId::new(0),
        f.page,
        f.control,
        &counters,
        &mut h.root_cpu,
    );
    assert_eq!(clone_rc, 44, "clone served in ring on ARM root");
    assert_eq!(ptid, 44);
    assert_eq!(
        counters.lifecycle_declines[carrick_el1_abi::LifecycleDecline::ClonePoolEmpty as usize]
            .load(Ordering::Relaxed),
        0
    );
    let born_record = f.zone.runnable_head(SlotId::new(0)).unwrap();

    let tgkill_rc = h.env.tgkill(
        SlotId::new(0),
        f.page,
        f.control,
        &mut h.root_cpu,
        (41, 44),
        SIGUSR1_NUM,
    );
    assert_eq!(
        tgkill_rc, 0,
        "ARM root unmanaged ring-born thread before first entry must accept tgkill"
    );
    assert_eq!(
        h.env.poll_sig(
            SlotId::new(0),
            f.page,
            f.control,
            &mut h.root_cpu,
            SIGUSR1_NUM
        ),
        -11
    );
    assert_eq!(
        h.env.poll_sig(
            SlotId::new(1),
            f.page,
            h.sib_control,
            &mut h.sib_cpu,
            SIGUSR1_NUM
        ),
        -11
    );

    // Switch the unmanaged ring-born child in on its home vCPU (`SlotId(0)`,
    // matching `f.leader.affinity == 1`) after settling the host-birth doorbell
    // and parking the leader behind it, then verify lazy `register_thread` +
    // `project_member` delivers SIGUSR1 once on its first guest syscall.
    let root_record = f.zone.slot(SlotId::new(0)).current().unwrap();
    let _ = h.env.tasks[0].linux.take_host_work_doorbell();
    assert!(
        f.zone
            .requeue_preempted(SlotId::new(0), root_record)
            .is_queued()
    );
    assert_eq!(
        h.env.switch_in(SlotId::new(0), &mut h.root_cpu),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(f.zone.slot(SlotId::new(0)).current(), Some(born_record));
    assert_eq!(
        h.env.poll_sig(
            SlotId::new(0),
            f.page,
            born_control,
            &mut h.root_cpu,
            SIGUSR1_NUM
        ),
        SIGUSR1_NUM as i64
    );
    assert_eq!(
        h.env.poll_sig(
            SlotId::new(0),
            f.page,
            born_control,
            &mut h.root_cpu,
            SIGUSR1_NUM
        ),
        -11
    );
}

/// How the carrier learns that a `CarrierWork` request owes thread stock.
/// Today the demand is a cause bit in the requester's slot doorbell.
fn carrier_stock_demand(
    env: MultiSlotEnv,
    slot: SlotId,
    _request: &carrick_core_abi::service::ServiceRequest,
) -> bool {
    env.tasks[slot.index()]
        .linux
        .take_host_work_doorbell()
        .is_some_and(|doorbell| {
            let demand = doorbell.thread_stock_demand();
            doorbell.settled();
            demand
        })
}

/// The host side of an empty-pool clone's "not now" (#1974 slice 2b): the
/// carrier claims the parked caller's exact `CarrierWork` notice, settles
/// the stock it owes (`stock`: the host ledger's replenish, emulated here by
/// stocking the page the way the ledger does), then acknowledges the exact
/// service ticket and notifies the member's service queue.
fn answer_clone_carrier_work(
    env: MultiSlotEnv,
    slot: SlotId,
    control: &'static ThreadControlSlot,
    record: RecordId,
    stock: impl FnOnce(),
) {
    let zone = env.fixture.zone;
    let reference = zone.record_ref(record);
    let notice = env.tasks[slot.index()]
        .service_notice
        .take()
        .expect("readable service notice")
        .expect("the parked clone published its carrier work");
    assert_eq!(notice.record, reference, "the clone caller's own notice");
    let key = carrick_sched_core::object_wait::ObjectWaitKey::native_service(reference).unwrap();
    let complete: &dyn Fn(
        carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_, Aarch64ParkedContext>,
    ) = &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned);
    let queue = zone
        .object_wait(key, &carrick_sched_core::ShortLockSpin, complete)
        .unwrap();
    // SAFETY: the fixture retains this exact record and authenticates its
    // notice while holding the same service queue as production intake.
    let ticket = unsafe {
        carrick_core_abi::service::ServiceCell::claim_notice(
            &control.service,
            notice,
            NonZeroU64::MIN,
            zone.record(record).identity(),
        )
    }
    .unwrap();
    drop(queue);
    assert!(
        carrier_stock_demand(env, slot, &ticket.request()),
        "the carrier sees the clone's stock demand"
    );
    stock();
    ticket
        .complete(true)
        .unwrap_or_else(|_| panic!("clone carrier-work ticket was cancelled"));
    zone.object_wait(key, &carrick_sched_core::ShortLockSpin, complete)
        .unwrap()
        .notify_object(slot, &mut Default::default())
        .unwrap();
}

/// A thread of the ARM root clones on an empty ring pool and parks: no
/// `ClonePoolEmpty` decline, no host-issued Forward, the caller's execution
/// lease released and the host asked for stock. Returns its record.
fn clone_parks_on_empty_pool(
    env: MultiSlotEnv,
    slot: SlotId,
    control: &'static ThreadControlSlot,
    cpu: &mut crate::sched::FakeCpu,
) -> RecordId {
    let f = env.fixture;
    let caller = f.zone.slot(slot).current().unwrap();
    let counters = carrick_el1_abi::Counters::new();
    let (route, _, _) = env.clone_thread(slot, f.page, control, &counters, cpu);
    assert_ne!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Forward,
        "an empty ring pool is \"not now\", never a host-issued birth"
    );
    assert_eq!(
        counters.lifecycle_declines[carrick_el1_abi::LifecycleDecline::ClonePoolEmpty as usize]
            .load(Ordering::Relaxed),
        0
    );
    assert_ne!(
        f.zone.slot(slot).current(),
        Some(caller),
        "the waiting clone released its execution lease"
    );
    caller
}

fn clone_on_empty_pool_parks(h: &mut ArmRootTwoThreadHarness) -> RecordId {
    let control = h.env.fixture.control;
    clone_parks_on_empty_pool(h.env, SlotId::new(0), control, &mut h.root_cpu)
}

/// The parked caller is selected again and reruns its exact clone. Returns
/// `(route, clone result, PARENT_SETTID word, ClonePoolEmpty declines)`.
fn rerun_clone(
    env: MultiSlotEnv,
    slot: SlotId,
    caller: RecordId,
    control: &'static ThreadControlSlot,
    cpu: &mut crate::sched::FakeCpu,
) -> (
    carrick_personality_linux::dispatch::CompletionRoute,
    i64,
    u32,
    u64,
) {
    let f = env.fixture;
    assert!(
        f.zone.slot(slot).current() == Some(caller)
            || env.switch_in(slot, cpu) == carrick_el1_abi::Action::Served
    );
    assert_eq!(
        f.zone.slot(slot).current(),
        Some(caller),
        "the woken clone caller is selected again"
    );
    let counters = carrick_el1_abi::Counters::new();
    let (route, clone_rc, ptid) = env.clone_thread(slot, f.page, control, &counters, cpu);
    (
        route,
        clone_rc,
        ptid,
        counters.lifecycle_declines[carrick_el1_abi::LifecycleDecline::ClonePoolEmpty as usize]
            .load(Ordering::Relaxed),
    )
}

/// The parked caller reruns its exact clone and completes it in ring.
/// Returns `(clone result, PARENT_SETTID word, born record)`.
fn rerun_clone_in_ring(
    h: &mut ArmRootTwoThreadHarness,
    root_record: RecordId,
) -> (i64, u32, RecordId) {
    let f = h.env.fixture;
    let (route, clone_rc, ptid, declines) = rerun_clone(
        h.env,
        SlotId::new(0),
        root_record,
        f.control,
        &mut h.root_cpu,
    );
    assert_ne!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Forward
    );
    assert_eq!(declines, 0);
    (
        clone_rc,
        ptid,
        f.zone.runnable_head(SlotId::new(0)).unwrap(),
    )
}

/// The #1974 window: the first ARM root clone finds the ring pool empty. It
/// waits for the host to stock the pool instead of becoming a host-issued
/// birth, then completes in ring; `tgkill` on the just-cloned thread succeeds
/// before its first entry and the signal is delivered exactly once. A peer
/// process's `kill(tid)` gets the same answer as for an adopted, registered
/// nonleader sibling (nonleader `kill` itself is #1994).
#[test]
fn arm_empty_pool_clone_waits_for_stock_then_child_accepts_tgkill() {
    let mut h = setup_arm_root_two_live_threads_and_peer();
    let f = h.env.fixture;
    let root_record = clone_on_empty_pool_parks(&mut h);
    let mut born_control = None;
    answer_clone_carrier_work(h.env, SlotId::new(0), f.control, root_record, || {
        born_control = Some(stock_arm_root_pool_identity(f, 44, 1));
    });
    let born_control = born_control.unwrap();
    let (clone_rc, ptid, born_record) = rerun_clone_in_ring(&mut h, root_record);
    assert_eq!((clone_rc, ptid), (44, 44), "clone completes in ring");

    let tgkill_rc = h.env.tgkill(
        SlotId::new(0),
        f.page,
        f.control,
        &mut h.root_cpu,
        (41, 44),
        SIGUSR1_NUM,
    );
    assert_eq!(
        tgkill_rc, 0,
        "the ring-born child before first entry accepts tgkill"
    );
    let peer_kill_child = h.env.peer_kill(
        SlotId::new(2),
        h.peer_page,
        h.peer_control,
        &mut h.peer_cpu,
        44,
        0,
    );
    let peer_kill_sibling = h.env.peer_kill(
        SlotId::new(2),
        h.peer_page,
        h.peer_control,
        &mut h.peer_cpu,
        43,
        0,
    );
    assert_eq!(
        peer_kill_child, peer_kill_sibling,
        "peer kill(tid) treats the ring-born child as a registered nonleader"
    );
    assert_eq!(
        h.env.poll_sig(
            SlotId::new(1),
            f.page,
            h.sib_control,
            &mut h.sib_cpu,
            SIGUSR1_NUM
        ),
        -11,
        "a thread-directed signal is not the sibling's"
    );
    let _ = h.env.tasks[0].linux.take_host_work_doorbell();
    assert!(
        f.zone
            .requeue_preempted(SlotId::new(0), root_record)
            .is_queued()
    );
    assert_eq!(
        h.env.switch_in(SlotId::new(0), &mut h.root_cpu),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(f.zone.slot(SlotId::new(0)).current(), Some(born_record));
    assert_eq!(
        h.env.poll_sig(
            SlotId::new(0),
            f.page,
            born_control,
            &mut h.root_cpu,
            SIGUSR1_NUM
        ),
        SIGUSR1_NUM as i64,
        "SIGUSR1 delivered to the child"
    );
    assert_eq!(
        h.env.poll_sig(
            SlotId::new(0),
            f.page,
            born_control,
            &mut h.root_cpu,
            SIGUSR1_NUM
        ),
        -11,
        "standard signals coalesce: delivered exactly once"
    );
}

/// The peer half of the #1974 window: after the empty-pool wait, a peer
/// process's `kill(tid)` reaches the ring-born child before its first entry.
#[test]
#[ignore = "red until #1994 (kill of a nonleader tid): returns -3 for any nonleader, including the adopted sibling control"]
fn arm_empty_pool_clone_child_accepts_peer_kill_before_first_entry() {
    let mut h = setup_arm_root_two_live_threads_and_peer();
    let f = h.env.fixture;
    let root_record = clone_on_empty_pool_parks(&mut h);
    answer_clone_carrier_work(h.env, SlotId::new(0), f.control, root_record, || {
        stock_arm_root_pool_identity(f, 44, 1);
    });
    let (clone_rc, _, _) = rerun_clone_in_ring(&mut h, root_record);
    assert_eq!(clone_rc, 44);
    let tgkill_rc = h.env.tgkill(
        SlotId::new(0),
        f.page,
        f.control,
        &mut h.root_cpu,
        (41, 44),
        SIGUSR1_NUM,
    );
    let peer_kill_rc = h.env.peer_kill(
        SlotId::new(2),
        h.peer_page,
        h.peer_control,
        &mut h.peer_cpu,
        44,
        SIGUSR2_NUM,
    );
    assert_eq!((tgkill_rc, peer_kill_rc), (0, 0));
}

/// "Busy once, then success": the pool is empty once, the host stocks it, and
/// the same clone completes in ring with a ring-born child (a zone record
/// bound to the stocked control), never a `ClonePoolEmpty` Forward.
#[test]
fn arm_empty_pool_clone_busy_once_then_ring_born() {
    let mut h = setup_arm_root_two_live_threads_and_peer();
    let f = h.env.fixture;
    let root_record = clone_on_empty_pool_parks(&mut h);
    let mut born_control = None;
    answer_clone_carrier_work(h.env, SlotId::new(0), f.control, root_record, || {
        born_control = Some(stock_arm_root_pool_identity(f, 44, 1));
    });
    let born_control = born_control.unwrap();
    let (clone_rc, _, born_record) = rerun_clone_in_ring(&mut h, root_record);
    assert_eq!(clone_rc, 44);
    assert_ne!(born_record, root_record);
    assert_eq!(
        born_control.zone_record(),
        Some(f.zone.record_ref(born_record)),
        "the child is ring-born: its control names its zone record"
    );
    assert_eq!(
        f.zone.record(born_record).identity().control_slot,
        born_control as *const _ as u64
    );
}

/// Two live threads: while the clone caller waits for stock, its vCPU is free
/// and a sibling on another vCPU keeps making progress.
#[test]
fn arm_empty_pool_clone_wait_leaves_sibling_running() {
    let mut h = setup_arm_root_two_live_threads_and_peer();
    let f = h.env.fixture;
    let root_record = clone_on_empty_pool_parks(&mut h);
    assert_eq!(
        f.zone.slot(SlotId::new(0)).current(),
        None,
        "no execution lease is held by the waiting clone"
    );
    for _ in 0..3 {
        let counters = carrick_el1_abi::Counters::new();
        let mut gettid = carrick_el1_abi::TrapFrame::default();
        gettid.x[8] = 178;
        h.env.call(
            SlotId::new(1),
            f.page,
            h.sib_control,
            &counters,
            &mut gettid,
            &mut h.sib_cpu,
        );
        assert_eq!(gettid.x[0], 43, "the sibling keeps running");
    }
    let mut born_control = None;
    answer_clone_carrier_work(h.env, SlotId::new(0), f.control, root_record, || {
        born_control = Some(stock_arm_root_pool_identity(f, 44, 1));
    });
    let (clone_rc, _, _) = rerun_clone_in_ring(&mut h, root_record);
    assert_eq!(clone_rc, 44);
}

/// Lost wakeup: stock that lands after the clone observed the empty pool but
/// before the host consumed its request is not missed; the rerun after the
/// carrier's reply probes the pool again.
#[test]
fn arm_empty_pool_clone_sees_stock_published_before_its_request_is_served() {
    let mut h = setup_arm_root_two_live_threads_and_peer();
    let f = h.env.fixture;
    let root_record = clone_on_empty_pool_parks(&mut h);
    // The stock lands first; the carrier then finds nothing left to stock.
    let born_control = stock_arm_root_pool_identity(f, 44, 1);
    answer_clone_carrier_work(h.env, SlotId::new(0), f.control, root_record, || {});
    let (clone_rc, _, born_record) = rerun_clone_in_ring(&mut h, root_record);
    assert_eq!(clone_rc, 44);
    assert_eq!(
        born_control.zone_record(),
        Some(f.zone.record_ref(born_record))
    );
}

/// No infinite wait: when the host answers without stocking (`RLIMIT_NPROC`,
/// tid exhaustion), the rerun keeps today's host-issued answer for that call.
#[test]
fn arm_empty_pool_clone_unstocked_answer_falls_back_to_host_once() {
    let mut h = setup_arm_root_two_live_threads_and_peer();
    let f = h.env.fixture;
    let root_record = clone_on_empty_pool_parks(&mut h);
    answer_clone_carrier_work(h.env, SlotId::new(0), f.control, root_record, || {});
    if f.zone.slot(SlotId::new(0)).current() != Some(root_record) {
        assert_eq!(
            h.env.switch_in(SlotId::new(0), &mut h.root_cpu),
            carrick_el1_abi::Action::Served
        );
    }
    let counters = carrick_el1_abi::Counters::new();
    let (route, _, _) = h.env.clone_thread(
        SlotId::new(0),
        f.page,
        f.control,
        &counters,
        &mut h.root_cpu,
    );
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Forward,
        "a host that could not stock answers this clone itself"
    );
    assert_eq!(
        counters.lifecycle_declines[carrick_el1_abi::LifecycleDecline::ClonePoolEmpty as usize]
            .load(Ordering::Relaxed),
        1
    );
}

fn register_arm_claim_free_birth(
    h: &NativeOwnedTwoThreadHarness,
    template_id: ThreadIdentity,
    template_ctx: Aarch64ParkedContext,
    blocked: carrick_el1_abi::BlockedMask,
) -> (
    carrick_sched_core::RecordRef,
    u32,
    &'static ThreadControlSlot,
) {
    use carrick_el1_abi::Lifecycle;
    use carrick_personality_linux::lifecycle::ProcessNative;
    let mut leader_service = h.env.service(SlotId::new(0));
    with_process_entry(
        BornInZoneSource {
            zone: h.env.fixture.zone,
            slot: SlotId::new(0),
        },
        &h.env.tasks[0],
        &ThreadCtx::ZERO,
        h.leader_cpu.ttbr.0,
        h.target_page,
        h.leader_control,
        &mut leader_service,
        |process| {
            assert!(matches!(
                process.prepare_thread_birth(),
                carrick_personality_linux::lifecycle::ThreadBirthAdmission::Ready
            ));
            let mut claimed = Some(h.target_page.claim_any().expect("native stock entry"));
            let entry = claimed.as_ref().unwrap().entry();
            let identity = h.target_page.identity(entry).unwrap();
            let address = h.target_page.control_address(entry).unwrap();
            let child_slot = unsafe { &*(address as *const ThreadControlSlot) };
            assert!(child_slot.publish_visible_tid(identity.visible_tid));
            let record_id = h
                .env
                .fixture
                .zone
                .alloc_record(ThreadIdentity {
                    tid: u64::from(identity.tid),
                    serial: identity.thread_serial,
                    mm: template_id.mm,
                    file_table: 0,
                    generation: 0,
                    affinity_source: template_id.affinity_source,
                    affinity: template_id.affinity,
                    lifecycle_page: h.target_page as *const _ as u64,
                    control_slot: address,
                })
                .unwrap();
            let record = h.env.fixture.zone.record_ref(record_id);
            child_slot.reset_for_birth(blocked, 0, entry).unwrap();
            process.bind_thread_birth(record, child_slot).unwrap();
            assert!(h.env.fixture.zone.issue_native_birth(record_id));
            unsafe {
                *h.env.fixture.zone.record(record_id).ctx_mut() = template_ctx;
            }
            process
                .thread_spawned(h.target_pid, identity.visible_tid, &mut || {
                    Lifecycle::thread_born(h.target_page).ok_or(-11)?;
                    h.target_page
                        .record_born(
                            claimed.take().unwrap(),
                            carrick_el1_abi::BornRecord {
                                caller_task: 0,
                                caller_serial: 0,
                                clone_flags: TGKILL_AFTER_CLONE_FLAGS,
                                clear_child_tid: 0,
                                blocked,
                            },
                        )
                        .map_err(|_| -11)?;
                    Ok(())
                })
                .unwrap();
            process.lifecycle_admission_settled().unwrap();
            assert!(
                !process
                    .register_born_before_requeue_for_test(record)
                    .unwrap()
            );
            assert_eq!(
                h.env.fixture.zone.record(record_id).claim(),
                carrick_sched_core::Claim::Free
            );
            assert_eq!(h.env.fixture.zone.record(record_id).home(), None);
            (record, identity.visible_tid, child_slot)
        },
    )
    .unwrap()
}

#[test]
fn arm_registered_claim_free_birth_before_requeue_sibling_tgkill() {
    let mut h = setup_native_owned_ring_birth_before_first_entry();
    let template_id = h.env.fixture.zone.record(h.born_record).identity();
    let template_ctx = unsafe { *h.env.fixture.zone.record(h.born_record).ctx_mut() };

    // Drain the earlier queued `h.born_record` first so SlotId(3) selects our
    // registered-but-unqueued births directly when we requeue them.
    h.env.init_guest_slot(SlotId::new(3));
    let mut drain_cpu = crate::sched::FakeCpu::default();
    assert_eq!(
        h.env.switch_in(SlotId::new(3), &mut drain_cpu),
        carrick_el1_abi::Action::Served
    );
    let _ = h.env.fixture.zone.release_current(
        SlotId::new(3),
        h.born_record,
        &carrick_sched_core::ShortLockSpin,
    );

    // Case A: unmasked at clone (`BlockedMask(0)`). `tgkill` while registered
    // in `Claim::Free` (`home == None`) holds SIGUSR1 on the child, delivers
    // it to the handler at the child's first entry, and does not double it.
    let (unmasked_record, unmasked_tid, unmasked_control) = register_arm_claim_free_birth(
        &h,
        template_id,
        template_ctx,
        carrick_el1_abi::BlockedMask(0),
    );
    let tgkill_rc = h.env.tgkill(
        SlotId::new(1),
        h.target_page,
        h.sibling_control,
        &mut h.sibling_cpu,
        (h.target_pid, unmasked_tid),
        SIGUSR1_NUM,
    );
    assert_eq!(
        tgkill_rc, 0,
        "sibling tgkill during pre-requeue Claim::Free window must resolve"
    );
    assert_eq!(
        h.env.poll_sig(
            SlotId::new(0),
            h.target_page,
            h.leader_control,
            &mut h.leader_cpu,
            SIGUSR1_NUM
        ),
        -11,
        "leader must not steal child's thread-directed signal"
    );
    assert_eq!(
        h.env.poll_sig(
            SlotId::new(1),
            h.target_page,
            h.sibling_control,
            &mut h.sibling_cpu,
            SIGUSR1_NUM
        ),
        -11,
        "sending sibling must not steal child's thread-directed signal"
    );

    assert!(
        h.env
            .fixture
            .zone
            .requeue_preempted(SlotId::new(0), unmasked_record.id)
            .is_queued()
    );
    let mut child_cpu = crate::sched::FakeCpu::default();
    assert_eq!(
        h.env.switch_in(SlotId::new(3), &mut child_cpu),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(
        h.env.fixture.zone.slot(SlotId::new(3)).current(),
        Some(unmasked_record.id)
    );
    let child_stack = carrick_test_support::GuestUserBuffer::zeroed(16384);
    let mut entry_frame = carrick_el1_abi::TrapFrame {
        slot: 3,
        elr: 0x40_0200,
        spsr: 0x3c0,
        ..Default::default()
    };
    assert_eq!(
        h.env.deliver_user_return(
            SlotId::new(3),
            h.target_page,
            unmasked_control,
            &child_cpu,
            child_stack.arg() + 16384,
            &mut entry_frame,
        ),
        None,
        "handler setup completes in-place for user return"
    );
    assert_eq!(
        entry_frame.elr, 0x40_1000,
        "first entry must redirect ELR to the installed SIGUSR1 handler"
    );
    assert_eq!(entry_frame.x[0], SIGUSR1_NUM);

    // Second checkpoint: signal was consumed once (not doubled).
    let mut second_frame = carrick_el1_abi::TrapFrame {
        slot: 3,
        elr: 0x40_0200,
        spsr: 0x3c0,
        ..Default::default()
    };
    assert_eq!(
        h.env.deliver_user_return(
            SlotId::new(3),
            h.target_page,
            unmasked_control,
            &child_cpu,
            child_stack.arg() + 16384,
            &mut second_frame,
        ),
        None
    );
    assert_eq!(
        second_frame.elr, 0x40_0200,
        "SIGUSR1 must not deliver a second time"
    );
    assert_eq!(
        h.env.poll_sig(
            SlotId::new(3),
            h.target_page,
            unmasked_control,
            &mut child_cpu,
            SIGUSR1_NUM
        ),
        -11
    );

    // Negative control: once `free_record` advances the record incarnation,
    // `tgkill` must return `-ESRCH` (`-3`).
    let _ = h.env.fixture.zone.release_current(
        SlotId::new(3),
        unmasked_record.id,
        &carrick_sched_core::ShortLockSpin,
    );
    h.env.fixture.zone.free_record(unmasked_record.id);
    assert_eq!(
        h.env.tgkill(
            SlotId::new(1),
            h.target_page,
            h.sibling_control,
            &mut h.sibling_cpu,
            (h.target_pid, unmasked_tid),
            0,
        ),
        -3,
        "freed record incarnation must never resolve as live"
    );

    // Case B: SIGUSR1 blocked in the inherited clone mask (`BlockedMask(1 << 9)`).
    // `tgkill` while registered-but-unqueued succeeds, first entry keeps ELR at
    // the child's entry PC (`0x40_0200`), and SIGUSR1 stays pending until unmasked.
    let sigusr1_bit = 1u64 << (SIGUSR1_NUM - 1);
    let (masked_record, masked_tid, masked_control) = register_arm_claim_free_birth(
        &h,
        template_id,
        template_ctx,
        carrick_el1_abi::BlockedMask(sigusr1_bit),
    );
    assert_eq!(
        h.env.tgkill(
            SlotId::new(1),
            h.target_page,
            h.sibling_control,
            &mut h.sibling_cpu,
            (h.target_pid, masked_tid),
            SIGUSR1_NUM,
        ),
        0,
        "blocked-at-clone Claim::Free birth must accept tgkill"
    );
    assert!(
        h.env
            .fixture
            .zone
            .requeue_preempted(SlotId::new(0), masked_record.id)
            .is_queued()
    );
    let mut masked_cpu = crate::sched::FakeCpu::default();
    assert_eq!(
        h.env.switch_in(SlotId::new(3), &mut masked_cpu),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(
        h.env.fixture.zone.slot(SlotId::new(3)).current(),
        Some(masked_record.id)
    );
    let masked_stack = carrick_test_support::GuestUserBuffer::zeroed(16384);
    let mut masked_frame = carrick_el1_abi::TrapFrame {
        slot: 3,
        elr: 0x40_0200,
        spsr: 0x3c0,
        ..Default::default()
    };
    assert_eq!(
        h.env.deliver_user_return(
            SlotId::new(3),
            h.target_page,
            masked_control,
            &masked_cpu,
            masked_stack.arg() + 16384,
            &mut masked_frame,
        ),
        None
    );
    assert_eq!(
        masked_frame.elr, 0x40_0200,
        "blocked-at-clone SIGUSR1 must stay pending across first entry"
    );

    // Unmasking SIGUSR1 on the child then delivers the held signal once.
    masked_control.init_blocked(carrick_el1_abi::BlockedMask(0));
    assert_eq!(
        h.env.deliver_user_return(
            SlotId::new(3),
            h.target_page,
            masked_control,
            &masked_cpu,
            masked_stack.arg() + 16384,
            &mut masked_frame,
        ),
        None
    );
    assert_eq!(
        masked_frame.elr, 0x40_1000,
        "unmasking must deliver the pending SIGUSR1 once"
    );
    let mut after_unmask = carrick_el1_abi::TrapFrame {
        slot: 3,
        elr: 0x40_0200,
        spsr: 0x3c0,
        ..Default::default()
    };
    assert_eq!(
        h.env.deliver_user_return(
            SlotId::new(3),
            h.target_page,
            masked_control,
            &masked_cpu,
            masked_stack.arg() + 16384,
            &mut after_unmask,
        ),
        None
    );
    assert_eq!(after_unmask.elr, 0x40_0200);
}

/// Out of scope stays as it was: a HostOnly page (seccomp/ptrace authority)
/// has no Reserved entry, so its claim also reports an empty pool, but the
/// host will never stock it. Its clone stays host-issued at once, with no
/// carrier round trip and no stock demand.
#[test]
fn arm_host_only_empty_pool_clone_stays_host_issued() {
    let mut h = setup_arm_root_two_live_threads_and_peer();
    let f = h.env.fixture;
    carrick_el1_abi::Lifecycle::decline_to_host(f.page);
    assert_eq!(
        carrick_el1_abi::Lifecycle::gate(f.page),
        carrick_el1_abi::GateState::HostOnly
    );
    let root_record = f.zone.slot(SlotId::new(0)).current().unwrap();
    let counters = carrick_el1_abi::Counters::new();
    let (route, _, _) = h.env.clone_thread(
        SlotId::new(0),
        f.page,
        f.control,
        &counters,
        &mut h.root_cpu,
    );
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Forward,
        "a HostOnly clone is the host's"
    );
    assert_eq!(
        f.zone.slot(SlotId::new(0)).current(),
        Some(root_record),
        "no wait: the caller keeps its lease"
    );
    assert!(
        h.env.tasks[0]
            .linux
            .take_host_work_doorbell()
            .is_none_or(|doorbell| {
                let demand = doorbell.thread_stock_demand();
                doorbell.settled();
                !demand
            }),
        "no stock demand for a page the host never stocks"
    );
}

/// #1974 round 2: the stock demand belongs to the clone's own `CarrierWork`
/// request, never to its slot's shared host-work word. Another boundary on
/// the same slot (the ring ran a sibling there, and a settle path swapped
/// the word) consumes that word before the carrier serves this request. The
/// carrier still stocks for it and the clone completes in ring.
#[test]
fn arm_empty_pool_clone_demand_survives_another_settle_of_its_slot_word() {
    let mut h = setup_arm_root_two_live_threads_and_peer();
    let f = h.env.fixture;
    let root_record = clone_on_empty_pool_parks(&mut h);
    if let Some(doorbell) = h.env.tasks[0].linux.take_host_work_doorbell() {
        doorbell.settled();
    }
    let mut born_control = None;
    answer_clone_carrier_work(h.env, SlotId::new(0), f.control, root_record, || {
        born_control = Some(stock_arm_root_pool_identity(f, 44, 1));
    });
    let (clone_rc, _, born_record) = rerun_clone_in_ring(&mut h, root_record);
    assert_eq!(clone_rc, 44, "the clone completes in ring");
    assert_eq!(
        born_control.unwrap().zone_record(),
        Some(f.zone.record_ref(born_record))
    );
}

/// #1974 round 2: two threads clone on one empty pool. The root waits and
/// the host stocks one entry for it, but before the root reruns, its
/// running sibling's own clone takes that entry in ring. The root's rerun
/// finds the pool empty again; the host did stock, so this is "not now"
/// again, never a host-issued birth. It waits once more and completes
/// ring-born.
#[test]
fn arm_empty_pool_clone_loser_of_the_stock_race_waits_again() {
    let mut h = setup_arm_root_two_live_threads_and_peer();
    let f = h.env.fixture;
    let root_record = clone_on_empty_pool_parks(&mut h);
    answer_clone_carrier_work(h.env, SlotId::new(0), f.control, root_record, || {
        stock_arm_root_pool_identity(f, 44, 1);
    });
    let counters = carrick_el1_abi::Counters::new();
    let (route, sibling_rc, _) = h.env.clone_thread(
        SlotId::new(1),
        f.page,
        h.sib_control,
        &counters,
        &mut h.sib_cpu,
    );
    assert_ne!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Forward
    );
    assert_eq!(
        sibling_rc, 44,
        "the sibling's clone takes the stock in ring"
    );

    let (route, _, _, declines) = rerun_clone(
        h.env,
        SlotId::new(0),
        root_record,
        f.control,
        &mut h.root_cpu,
    );
    assert_ne!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Forward,
        "a stocked pool a sibling emptied is \"not now\", never a host birth"
    );
    assert_eq!(declines, 0);
    assert_ne!(
        f.zone.slot(SlotId::new(0)).current(),
        Some(root_record),
        "the loser waits again without its execution lease"
    );
    let mut born_control = None;
    answer_clone_carrier_work(h.env, SlotId::new(0), f.control, root_record, || {
        born_control = Some(stock_arm_root_pool_identity(f, 45, 2));
    });
    let (clone_rc, ptid, born_record) = rerun_clone_in_ring(&mut h, root_record);
    assert_eq!((clone_rc, ptid), (45, 45), "ring-born after waiting again");
    assert_eq!(
        born_control.unwrap().zone_record(),
        Some(f.zone.record_ref(born_record))
    );
}
