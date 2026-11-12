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

/// Dispatch a syscall for the record currently loaded on `slot` through the
/// production ARM vector adapter with `ProductionResumeCpu`, so a parked call
/// switches in and resumes the slot's next runnable record.
fn call_on_slot(
    fixture: &'static Fixture,
    slot: SlotId,
    tasks: &'static [CurrentTask],
    dispatch_service: &mut Aarch64NativeProcessService<'static, TestStockCrossing>,
    resume_service: &mut Aarch64NativeProcessService<'static, TestStockCrossing>,
    frame: &mut carrick_el1_abi::TrapFrame,
    cpu: &mut crate::sched::FakeCpu,
) -> carrick_personality_linux::dispatch::CompletionRoute {
    let current = fixture.zone.slot(slot).current().unwrap();
    let identity = fixture.zone.record(current).identity();
    // SAFETY: the native owner retains its lifecycle page and control slot.
    let page = unsafe { &*(identity.lifecycle_page as *const ThreadLifecyclePage) };
    // SAFETY: see above.
    let control = unsafe { &*(identity.control_slot as *const ThreadControlSlot) };
    // SAFETY: `current` is the slot's active record.
    let saved = unsafe { *fixture.zone.record(current).ctx_mut() };
    let ttbr0 = saved
        .address_context()
        .expect("native record address context")
        .root
        .address()
        .raw();
    cpu.ttbr.0 = ttbr0;
    frame.esr = 0x15 << 26;
    frame.slot = u64::from(slot.raw());
    let mut resume_cpu = ProductionResumeCpu {
        inner: core::mem::take(cpu),
        service: resume_service,
    };
    let counters = carrick_el1_abi::Counters::new();
    let cache = carrick_el1_abi::InotifyNameCache::new();
    let route = super::super::dispatch::dispatch_arm_syscall_with_native_process(
        frame,
        &counters,
        tasks,
        &[],
        &[],
        &[],
        &[],
        &cache,
        Some(crate::dispatch::Zone {
            tables: fixture.zone,
            cpu: &mut resume_cpu,
            user: &crate::sched::HardwareUserWord,
        }),
        None,
        Some(&LoadedVenue),
        page,
        control,
        &saved.native,
        ttbr0,
        dispatch_service,
        |_| core::ptr::null_mut(),
    )
    .expect("production ARM native process dispatch");
    *cpu = core::mem::take(&mut resume_cpu.inner);
    route
}

/// Run the production scheduler's idle entry on `slot` for `task`.
fn switch_on_slot(
    fixture: &'static Fixture,
    slot: SlotId,
    task: &'static CurrentTask,
    resume_service: &mut Aarch64NativeProcessService<'static, TestStockCrossing>,
    cpu: &mut crate::sched::FakeCpu,
    frame: &mut carrick_el1_abi::TrapFrame,
) -> carrick_el1_abi::Action {
    let mut switch = ProductionResumeCpu {
        inner: core::mem::take(cpu),
        service: resume_service,
    };
    let counters = carrick_el1_abi::Counters::new();
    let mut handoff = None;
    let mut zone = crate::dispatch::Zone {
        tables: fixture.zone,
        cpu: &mut switch,
        user: &crate::sched::HardwareUserWord,
    };
    let action =
        super::super::dispatch::native_scheduler(&mut zone, task, &counters, slot, &mut handoff)
            .idle_entry(frame, 0);
    *cpu = core::mem::take(&mut switch.inner);
    action
}

struct ProductionProcessHarness {
    fixture: &'static Fixture,
    task: &'static CurrentTask,
    dispatch_service: Aarch64NativeProcessService<'static, TestStockCrossing>,
    resume_service: Aarch64NativeProcessService<'static, TestStockCrossing>,
    parent_record: RecordId,
    _parent_page: &'static ThreadLifecyclePage,
    _parent_control: &'static ThreadControlSlot,
    _parent_pid: u32,
}

impl ProductionProcessHarness {
    fn new() -> Self {
        let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
        fixture.zone.spaces.set_idle_ttbr(0x30000);
        let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
        let spare_pages: Vec<u64> = (0..28).map(|i| 0x14000 + i * 0x1000).collect();
        let mut dispatch_service = Aarch64NativeProcessService::with_crossing(
            &fixture.task,
            fixture.slot,
            fixture.zone,
            fixture.region.table(),
            NonZeroU64::MIN,
            TestStockCrossing::new(&spare_pages),
        )
        .with_words(words);
        let resume_service = Aarch64NativeProcessService::with_crossing(
            &fixture.task,
            fixture.slot,
            fixture.zone,
            fixture.region.table(),
            NonZeroU64::MIN,
            TestStockCrossing::new(&[]),
        )
        .with_words(words);
        let mut cpu = crate::sched::FakeCpu::default();
        let mut frame = carrick_el1_abi::TrapFrame::default();
        frame.x[8] = 220;
        frame.x[0] = 17;
        arm_call_with_cpu(
            fixture,
            fixture.control,
            &mut dispatch_service,
            &mut frame,
            &mut cpu,
        )
        .unwrap();
        assert!(frame.x[0] as i64 > 0, "fork result {}", frame.x[0] as i64);
        let parent_record = fixture.zone.runnable_head(fixture.slot).unwrap();
        let parent_identity = fixture.zone.record(parent_record).identity();
        // SAFETY: the native owner retains its lifecycle page and control slot.
        let parent_page =
            unsafe { &*(parent_identity.lifecycle_page as *const ThreadLifecyclePage) };
        // SAFETY: see above.
        let parent_control =
            unsafe { &*(parent_identity.control_slot as *const ThreadControlSlot) };
        let task: &'static CurrentTask = &fixture.task;
        fixture.zone.publish_slot(fixture.slot, 0, None, 0);
        task.mm.key.store(0, Ordering::Release);
        assert_eq!(
            switch_in(fixture, task, &mut cpu, &mut frame),
            carrick_el1_abi::Action::Served
        );
        assert_eq!(
            fixture.zone.slot(fixture.slot).current(),
            Some(parent_record)
        );
        let parent_pid = task.visible_pid().expect("published parent pid");
        dispatch_service.task = task;
        Self {
            fixture,
            task,
            dispatch_service,
            resume_service,
            parent_record,
            _parent_page: parent_page,
            _parent_control: parent_control,
            _parent_pid: parent_pid,
        }
    }

    fn settle_doorbells(&self) {
        if let Some(work) = self.task.linux.take_host_work_doorbell() {
            work.settled();
        }
        let _ = self.task.linux.take_served_boundary();
    }

    fn find_record_by_tid(&self, tid: u64) -> Option<RecordId> {
        (0..carrick_sched_core::ZONE_RECORDS as u32)
            .filter_map(RecordId::from_raw)
            .find(|&r| self.fixture.zone.record(r).identity().tid == tid)
    }

    /// Dispatch a syscall for the currently loaded record on `fixture.slot`
    /// through the production ARM vector adapter with `ProductionResumeCpu` so
    /// a parked call switches in and resumes the next runnable record.
    fn call_current(
        &mut self,
        frame: &mut carrick_el1_abi::TrapFrame,
        cpu: &mut crate::sched::FakeCpu,
    ) -> carrick_personality_linux::dispatch::CompletionRoute {
        self.settle_doorbells();
        let route = call_on_slot(
            self.fixture,
            self.fixture.slot,
            core::slice::from_ref(self.task),
            &mut self.dispatch_service,
            &mut self.resume_service,
            frame,
            cpu,
        );
        self.settle_doorbells();
        route
    }

    fn switch_next(
        &mut self,
        cpu: &mut crate::sched::FakeCpu,
        frame: &mut carrick_el1_abi::TrapFrame,
    ) -> carrick_el1_abi::Action {
        self.settle_doorbells();
        let action = switch_on_slot(
            self.fixture,
            self.fixture.slot,
            self.task,
            &mut self.resume_service,
            cpu,
            frame,
        );
        self.settle_doorbells();
        action
    }

    fn spawn_thread(
        &mut self,
        stack: &carrick_test_support::GuestUserBuffer,
        cpu: &mut crate::sched::FakeCpu,
    ) -> (u32, RecordId) {
        let mut clone = carrick_el1_abi::TrapFrame::default();
        clone.x[8] = 220;
        clone.x[..5].copy_from_slice(&[
            THREAD_FLAGS,
            stack.arg() + 4096,
            stack.arg(),
            stack.arg() + 128,
            stack.arg() + 4,
        ]);
        self.call_current(&mut clone, cpu);
        let tid = clone.x[0] as i64;
        assert!(tid > 0, "thread clone failed: {tid}");
        let record = self
            .find_record_by_tid(tid as u64)
            .expect("queued thread record");
        (tid as u32, record)
    }

    fn fork_child(&mut self, cpu: &mut crate::sched::FakeCpu) -> (u32, RecordId) {
        let mut fork = carrick_el1_abi::TrapFrame::default();
        fork.x[8] = 220;
        fork.x[0] = 17;
        self.call_current(&mut fork, cpu);
        let pid = fork.x[0] as i64;
        assert!(pid > 0, "fork failed: {pid}");
        let record = self
            .find_record_by_tid(pid as u64)
            .expect("queued child record");
        (pid as u32, record)
    }

    fn exit_current_child(
        &mut self,
        code: u8,
        cpu: &mut crate::sched::FakeCpu,
        frame: &mut carrick_el1_abi::TrapFrame,
    ) {
        let current = self.fixture.zone.slot(self.fixture.slot).current().unwrap();
        // SAFETY: `current` is the slot's active child record.
        let address = unsafe { *self.fixture.zone.record(current).ctx_mut() }
            .address_context()
            .expect("child address context");
        *self.dispatch_service.crossing.zone.lock().unwrap() = Some(self.fixture.zone);
        *self.dispatch_service.crossing.child.lock().unwrap() = Some((
            super::super::common_entry::execution_binding(self.task),
            address,
        ));
        *frame = carrick_el1_abi::TrapFrame::default();
        frame.x[8] = 94;
        frame.x[0] = u64::from(code);
        self.call_current(frame, cpu);
        if self
            .fixture
            .zone
            .slot(self.fixture.slot)
            .current()
            .is_none()
        {
            assert_eq!(
                self.switch_next(cpu, frame),
                carrick_el1_abi::Action::Served
            );
        }
    }

    fn with_current_entry<R>(
        &mut self,
        cpu: &mut crate::sched::FakeCpu,
        run: impl FnOnce(&mut dyn carrick_personality_linux::ipc::ProcessIpcVenue) -> R,
    ) -> R {
        self.settle_doorbells();
        let current = self.fixture.zone.slot(self.fixture.slot).current().unwrap();
        let identity = self.fixture.zone.record(current).identity();
        // SAFETY: the native owner retains its lifecycle page and control slot.
        let page = unsafe { &*(identity.lifecycle_page as *const ThreadLifecyclePage) };
        // SAFETY: see above.
        let control = unsafe { &*(identity.control_slot as *const ThreadControlSlot) };
        // SAFETY: `current` is the slot's active record.
        let saved = unsafe { *self.fixture.zone.record(current).ctx_mut() };
        let ttbr0 = saved
            .address_context()
            .expect("native record address context")
            .root
            .address()
            .raw();
        cpu.ttbr.0 = ttbr0;
        let source = BornInZoneSource {
            zone: self.fixture.zone,
            slot: self.fixture.slot,
        };
        let out = super::super::aarch64_process::with_process_entry(
            source,
            self.task,
            &saved.native,
            ttbr0,
            page,
            control,
            &mut self.dispatch_service,
            |entry| run(entry),
        )
        .expect("with_process_entry");
        self.settle_doorbells();
        out
    }

    fn msgget_current(&mut self, key: i32, msgflg: i32, cpu: &mut crate::sched::FakeCpu) -> i32 {
        self.with_current_entry(cpu, |venue| venue.msgget(key, msgflg).expect("msgget"))
    }

    fn msgrcv_current(
        &mut self,
        msqid: i32,
        msgp: u64,
        msgsz: usize,
        msgtyp: i64,
        msgflg: i32,
        cpu: &mut crate::sched::FakeCpu,
    ) -> Result<carrick_personality_linux::ipc::IpcOutcome, i64> {
        let result = self.with_current_entry(cpu, |venue| {
            venue
                .msgrcv(msqid, UserVa::new(msgp), msgtyp, msgflg, msgsz)
                .map(|(outcome, _)| outcome)
        });
        if matches!(
            result,
            Ok(carrick_personality_linux::ipc::IpcOutcome::Suspended)
        ) && self
            .fixture
            .zone
            .slot(self.fixture.slot)
            .current()
            .is_none()
        {
            let mut switched_frame = carrick_el1_abi::TrapFrame::default();
            assert_eq!(
                self.switch_next(cpu, &mut switched_frame),
                carrick_el1_abi::Action::Served
            );
        }
        result
    }

    fn msgsnd_current(
        &mut self,
        msqid: i32,
        mtype: i64,
        mtext: &[u8],
        msgflg: i32,
        cpu: &mut crate::sched::FakeCpu,
    ) -> Result<carrick_personality_linux::ipc::IpcOutcome, i64> {
        self.with_current_entry(cpu, |venue| venue.msgsnd(msqid, mtype, mtext, msgflg))
    }
}

/// #2071 witness 1: two members of one native process call blocking `wait4` on
/// different children through the production ARM dispatch entry. Both park (the
/// second never receives `-11` / `-EAGAIN`), a first child exit wakes both so
/// the non-matching waiter rescans and stays parked, and each reaps its own
/// child with exact exit status.
#[test]
fn arm_two_threads_blocking_wait4_reap_distinct_children() {
    let mut harness = ProductionProcessHarness::new();
    let mut cpu = crate::sched::FakeCpu::default();
    let stack = carrick_test_support::GuestUserBuffer::zeroed(8192);
    let (_sibling_tid, sibling) = harness.spawn_thread(&stack, &mut cpu);
    let (child_a_pid, child_a) = harness.fork_child(&mut cpu);
    let (child_b_pid, child_b) = harness.fork_child(&mut cpu);
    let status_a = carrick_test_support::GuestUserBuffer::from_value(-1i32);
    let status_b = carrick_test_support::GuestUserBuffer::from_value(-1i32);

    // Leader calls blocking wait4(child_a): parks and switches to `sibling`.
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = 260;
    frame.x[0] = u64::from(child_a_pid);
    frame.x[1] = status_a.arg();
    harness.call_current(&mut frame, &mut cpu);
    assert!(matches!(
        harness.fixture.zone.record(harness.parent_record).claim(),
        carrick_sched_core::Claim::Parked { .. }
    ));
    assert_eq!(
        harness.fixture.zone.slot(harness.fixture.slot).current(),
        Some(sibling)
    );

    // Sibling calls blocking wait4(child_b): must park too, never return -11.
    let mut sibling_frame = carrick_el1_abi::TrapFrame::default();
    sibling_frame.x[8] = 260;
    sibling_frame.x[0] = u64::from(child_b_pid);
    sibling_frame.x[1] = status_b.arg();
    harness.call_current(&mut sibling_frame, &mut cpu);
    assert!(
        matches!(
            harness.fixture.zone.record(sibling).claim(),
            carrick_sched_core::Claim::Parked { .. }
        ),
        "second thread wait4 failed to park (x0 = {})",
        sibling_frame.x[0] as i64
    );
    assert_eq!(
        harness.fixture.zone.slot(harness.fixture.slot).current(),
        Some(child_a)
    );

    // child_a exits with status 11, waking both waiters onto the run queue
    // behind child_b. Preempt child_b so both waiters run while child_b lives.
    let mut exit_frame = carrick_el1_abi::TrapFrame::default();
    harness.exit_current_child(11, &mut cpu, &mut exit_frame);
    assert_eq!(
        harness.fixture.zone.slot(harness.fixture.slot).current(),
        Some(child_b)
    );
    assert!(
        harness
            .fixture
            .zone
            .requeue_preempted(harness.fixture.slot, child_b)
            .is_queued()
    );

    // Leader switches in and completes wait4(child_a) -> child_a_pid.
    let mut resumed_leader = carrick_el1_abi::TrapFrame::default();
    assert_eq!(
        harness.switch_next(&mut cpu, &mut resumed_leader),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(
        harness.fixture.zone.slot(harness.fixture.slot).current(),
        Some(harness.parent_record)
    );
    assert_eq!(resumed_leader.x[0], u64::from(child_a_pid));
    assert_eq!(
        status_a.get::<i32>(0),
        LinuxWaitStatus::from_wait_encoding(11 << 8).raw()
    );

    // Preempt leader so sibling runs next: child_b is still running, so
    // sibling's resume rescans, re-parks, and switches to child_b!
    assert!(
        harness
            .fixture
            .zone
            .requeue_preempted(harness.fixture.slot, harness.parent_record)
            .is_queued()
    );
    let mut resumed_sibling = carrick_el1_abi::TrapFrame::default();
    assert_eq!(
        harness.switch_next(&mut cpu, &mut resumed_sibling),
        carrick_el1_abi::Action::Served
    );
    assert!(matches!(
        harness.fixture.zone.record(sibling).claim(),
        carrick_sched_core::Claim::Parked { .. }
    ));
    assert_eq!(
        harness.fixture.zone.slot(harness.fixture.slot).current(),
        Some(child_b)
    );

    // child_b exits with status 22, waking sibling.
    harness.exit_current_child(22, &mut cpu, &mut exit_frame);
    if harness.fixture.zone.slot(harness.fixture.slot).current() == Some(harness.parent_record) {
        assert!(
            harness
                .fixture
                .zone
                .requeue_preempted(harness.fixture.slot, harness.parent_record)
                .is_queued()
        );
        assert_eq!(
            harness.switch_next(&mut cpu, &mut resumed_sibling),
            carrick_el1_abi::Action::Served
        );
    } else {
        resumed_sibling = exit_frame;
    }
    assert_eq!(
        harness.fixture.zone.slot(harness.fixture.slot).current(),
        Some(sibling)
    );
    assert_eq!(resumed_sibling.x[0], u64::from(child_b_pid));
    assert_eq!(
        status_b.get::<i32>(0),
        LinuxWaitStatus::from_wait_encoding(22 << 8).raw()
    );
}

/// #2071 witness 2: two members both call `wait4(-1)`; when one child exits
/// while another remains, exactly one waiter reaps and the other stays parked;
/// when the final child exits with both waiters parked in `wait4(-1)`, one
/// reaps and the other gets `-ECHILD` (`-10`).
#[test]
fn arm_two_threads_blocking_wait4_any_one_reaps_other_blocks_then_echild() {
    let mut harness = ProductionProcessHarness::new();
    let mut cpu = crate::sched::FakeCpu::default();
    let stack = carrick_test_support::GuestUserBuffer::zeroed(8192);
    let (_sibling_tid, sibling) = harness.spawn_thread(&stack, &mut cpu);
    let (child_a_pid, child_a) = harness.fork_child(&mut cpu);
    let (child_b_pid, child_b) = harness.fork_child(&mut cpu);
    let status_leader = carrick_test_support::GuestUserBuffer::from_value(-1i32);
    let status_sibling = carrick_test_support::GuestUserBuffer::from_value(-1i32);

    // Both leader and sibling call blocking wait4(-1).
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = 260;
    frame.x[0] = u64::MAX;
    frame.x[1] = status_leader.arg();
    harness.call_current(&mut frame, &mut cpu);
    assert_eq!(
        harness.fixture.zone.slot(harness.fixture.slot).current(),
        Some(sibling)
    );

    let mut sibling_frame = carrick_el1_abi::TrapFrame::default();
    sibling_frame.x[8] = 260;
    sibling_frame.x[0] = u64::MAX;
    sibling_frame.x[1] = status_sibling.arg();
    harness.call_current(&mut sibling_frame, &mut cpu);
    assert!(
        matches!(
            harness.fixture.zone.record(sibling).claim(),
            carrick_sched_core::Claim::Parked { .. }
        ),
        "second wait4(-1) failed to park (x0 = {})",
        sibling_frame.x[0] as i64
    );
    assert_eq!(
        harness.fixture.zone.slot(harness.fixture.slot).current(),
        Some(child_a)
    );

    // child_a exits(13) while child_b is still alive.
    let mut exit_frame = carrick_el1_abi::TrapFrame::default();
    harness.exit_current_child(13, &mut cpu, &mut exit_frame);
    assert_eq!(
        harness.fixture.zone.slot(harness.fixture.slot).current(),
        Some(child_b)
    );
    assert!(
        harness
            .fixture
            .zone
            .requeue_preempted(harness.fixture.slot, child_b)
            .is_queued()
    );

    // First woken waiter reaps child_a; second woken waiter rescans, sees
    // child_b still running, and stays parked!
    let mut resumed_first = carrick_el1_abi::TrapFrame::default();
    assert_eq!(
        harness.switch_next(&mut cpu, &mut resumed_first),
        carrick_el1_abi::Action::Served
    );
    let first_waiter = harness
        .fixture
        .zone
        .slot(harness.fixture.slot)
        .current()
        .unwrap();
    assert_eq!(resumed_first.x[0], u64::from(child_a_pid));

    // Re-enter wait4(-1) on the first waiter so BOTH waiters are parked when
    // the last child (child_b) exits: switching away runs the second waiter's
    // woken resume, which re-parks on child_b and switches to child_b!
    let mut rewait = carrick_el1_abi::TrapFrame::default();
    rewait.x[8] = 260;
    rewait.x[0] = u64::MAX;
    rewait.x[1] = if first_waiter == harness.parent_record {
        status_leader.arg()
    } else {
        status_sibling.arg()
    };
    harness.call_current(&mut rewait, &mut cpu);
    assert!(matches!(
        harness.fixture.zone.record(harness.parent_record).claim(),
        carrick_sched_core::Claim::Parked { .. }
    ));
    assert!(matches!(
        harness.fixture.zone.record(sibling).claim(),
        carrick_sched_core::Claim::Parked { .. }
    ));
    assert_eq!(
        harness.fixture.zone.slot(harness.fixture.slot).current(),
        Some(child_b)
    );

    // Now the last child (child_b) exits(19): one waiter reaps child_b_pid,
    // and the remaining waiter gets -ECHILD (-10).
    harness.exit_current_child(19, &mut cpu, &mut exit_frame);
    let winner_result = exit_frame.x[0] as i64;
    assert_eq!(winner_result, i64::from(child_b_pid));

    let winner = harness
        .fixture
        .zone
        .slot(harness.fixture.slot)
        .current()
        .unwrap();
    assert!(
        harness
            .fixture
            .zone
            .requeue_preempted(harness.fixture.slot, winner)
            .is_queued()
    );
    let mut loser_frame = carrick_el1_abi::TrapFrame::default();
    assert_eq!(
        harness.switch_next(&mut cpu, &mut loser_frame),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(
        loser_frame.x[0] as i64, -10,
        "remaining wait4(-1) waiter with no children left must return -ECHILD (-10)"
    );
}

/// #2071 witness 3: `vfork` (`CLONE_VM | CLONE_VFORK | SIGCHLD`) from one
/// thread while a sibling is parked in a blocking `wait4` must suspend the
/// `vfork` caller until its child execs or exits (never return unsuspended on
/// `Busy`).
#[test]
fn arm_vfork_while_sibling_parked_in_wait4_suspends_parent_until_release() {
    let mut harness = ProductionProcessHarness::new();
    let mut cpu = crate::sched::FakeCpu::default();
    let stack = carrick_test_support::GuestUserBuffer::zeroed(8192);
    let vfork_stack = carrick_test_support::GuestUserBuffer::zeroed(4096);
    let (_sibling_tid, sibling) = harness.spawn_thread(&stack, &mut cpu);
    let (child_a_pid, child_a) = harness.fork_child(&mut cpu);
    let status_a = carrick_test_support::GuestUserBuffer::from_value(-1i32);
    let status_vfork = carrick_test_support::GuestUserBuffer::from_value(-1i32);

    // Leader parks in blocking wait4(child_a), switching to sibling.
    let mut wait_frame = carrick_el1_abi::TrapFrame::default();
    wait_frame.x[8] = 260;
    wait_frame.x[0] = u64::from(child_a_pid);
    wait_frame.x[1] = status_a.arg();
    harness.call_current(&mut wait_frame, &mut cpu);
    assert_eq!(
        harness.fixture.zone.slot(harness.fixture.slot).current(),
        Some(sibling)
    );

    // Sibling calls clone(CLONE_VM | CLONE_VFORK | SIGCHLD = 0x4111): must
    // park (suspend) until vfork_child releases it, NOT return unsuspended!
    let mut vfork_frame = carrick_el1_abi::TrapFrame::default();
    vfork_frame.x[8] = 220;
    vfork_frame.x[0] = 0x4111;
    vfork_frame.x[1] = vfork_stack.arg() + 4096;
    harness.call_current(&mut vfork_frame, &mut cpu);
    assert!(
        matches!(
            harness.fixture.zone.record(sibling).claim(),
            carrick_sched_core::Claim::Parked { .. }
        ),
        "vfork caller returned unsuspended while sibling was parked in wait4 (x0 = {})",
        vfork_frame.x[0] as i64
    );

    // Preempt child_a to run the queued vfork_child, which exits(31) and
    // releases sibling's vfork suspension while leader stays parked on child_a.
    assert_eq!(
        harness.fixture.zone.slot(harness.fixture.slot).current(),
        Some(child_a)
    );
    assert!(
        harness
            .fixture
            .zone
            .requeue_preempted(harness.fixture.slot, child_a)
            .is_queued()
    );
    let mut switched = carrick_el1_abi::TrapFrame::default();
    assert_eq!(
        harness.switch_next(&mut cpu, &mut switched),
        carrick_el1_abi::Action::Served
    );
    let vfork_child = harness
        .fixture
        .zone
        .slot(harness.fixture.slot)
        .current()
        .unwrap();
    let vfork_child_pid = harness.fixture.zone.record(vfork_child).identity().tid as u32;
    assert_ne!(vfork_child, child_a);
    assert_ne!(vfork_child, sibling);

    let mut exit_frame = carrick_el1_abi::TrapFrame::default();
    harness.exit_current_child(31, &mut cpu, &mut exit_frame);
    if harness.fixture.zone.slot(harness.fixture.slot).current() == Some(child_a) {
        assert!(
            harness
                .fixture
                .zone
                .requeue_preempted(harness.fixture.slot, child_a)
                .is_queued()
        );
        assert_eq!(
            harness.switch_next(&mut cpu, &mut switched),
            carrick_el1_abi::Action::Served
        );
    } else {
        switched = exit_frame;
    }
    assert_eq!(
        harness.fixture.zone.slot(harness.fixture.slot).current(),
        Some(sibling)
    );
    assert_eq!(switched.x[0], u64::from(vfork_child_pid));
    assert!(
        matches!(
            harness.fixture.zone.record(harness.parent_record).claim(),
            carrick_sched_core::Claim::Parked { .. }
        ),
        "leader waiting for child_a must remain parked when vfork_child exits"
    );

    // Sibling reaps vfork_child, then child_a exits and leader reaps child_a.
    let mut reap_vfork = carrick_el1_abi::TrapFrame::default();
    reap_vfork.x[8] = 260;
    reap_vfork.x[0] = u64::from(vfork_child_pid);
    reap_vfork.x[1] = status_vfork.arg();
    harness.call_current(&mut reap_vfork, &mut cpu);
    assert_eq!(reap_vfork.x[0], u64::from(vfork_child_pid));
    assert_eq!(
        status_vfork.get::<i32>(0),
        LinuxWaitStatus::from_wait_encoding(31 << 8).raw()
    );

    assert!(
        harness
            .fixture
            .zone
            .requeue_preempted(harness.fixture.slot, sibling)
            .is_queued()
    );
    assert_eq!(
        harness.switch_next(&mut cpu, &mut switched),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(
        harness.fixture.zone.slot(harness.fixture.slot).current(),
        Some(child_a)
    );
    harness.exit_current_child(17, &mut cpu, &mut exit_frame);
    if harness.fixture.zone.slot(harness.fixture.slot).current() == Some(sibling) {
        assert!(
            harness
                .fixture
                .zone
                .requeue_preempted(harness.fixture.slot, sibling)
                .is_queued()
        );
        assert_eq!(
            harness.switch_next(&mut cpu, &mut exit_frame),
            carrick_el1_abi::Action::Served
        );
    }
    assert_eq!(
        harness.fixture.zone.slot(harness.fixture.slot).current(),
        Some(harness.parent_record)
    );
    assert_eq!(exit_frame.x[0], u64::from(child_a_pid));
    assert_eq!(
        status_a.get::<i32>(0),
        LinuxWaitStatus::from_wait_encoding(17 << 8).raw()
    );
}

/// #2071 witness 5: a child exits between the first waiter parking and the
/// second waiter parking (while the first waiter's continuation row is still
/// retained before its resume checkpoint runs, and across channel generation
/// advancement); both waiters must re-scan and complete without `-EAGAIN` or
/// lost wakeups.
#[test]
fn arm_wait4_child_exits_between_two_waiters_parking_rescans_without_lost_wake() {
    let mut harness = ProductionProcessHarness::new();
    let mut cpu = crate::sched::FakeCpu::default();
    let stack = carrick_test_support::GuestUserBuffer::zeroed(8192);
    let (_sibling_tid, sibling) = harness.spawn_thread(&stack, &mut cpu);
    let (child_a_pid, child_a) = harness.fork_child(&mut cpu);
    let (child_b_pid, child_b) = harness.fork_child(&mut cpu);
    let status_a = carrick_test_support::GuestUserBuffer::from_value(-1i32);
    let status_b = carrick_test_support::GuestUserBuffer::from_value(-1i32);

    // Waiter 1 (leader) parks in wait4(child_a); slot switches to sibling.
    let mut wait_a = carrick_el1_abi::TrapFrame::default();
    wait_a.x[8] = 260;
    wait_a.x[0] = u64::from(child_a_pid);
    wait_a.x[1] = status_a.arg();
    harness.call_current(&mut wait_a, &mut cpu);
    assert_eq!(
        harness.fixture.zone.slot(harness.fixture.slot).current(),
        Some(sibling)
    );

    // Before Waiter 2 (sibling) parks, child_a runs and exits(29)! That wakes
    // Waiter 1 from Parked to Queued while Waiter 1's continuation row is
    // STILL retained in PendingTable, and advances the process channel
    // generation before Waiter 2 parks.
    assert!(
        harness
            .fixture
            .zone
            .requeue_preempted(harness.fixture.slot, sibling)
            .is_queued()
    );
    let mut switched = carrick_el1_abi::TrapFrame::default();
    assert_eq!(
        harness.switch_next(&mut cpu, &mut switched),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(
        harness.fixture.zone.slot(harness.fixture.slot).current(),
        Some(child_a)
    );
    let mut exit_frame = carrick_el1_abi::TrapFrame::default();
    harness.exit_current_child(29, &mut cpu, &mut exit_frame);
    assert_eq!(
        harness.fixture.zone.slot(harness.fixture.slot).current(),
        Some(child_b)
    );
    assert!(
        harness
            .fixture
            .zone
            .requeue_preempted(harness.fixture.slot, child_b)
            .is_queued()
    );
    assert_eq!(
        harness.switch_next(&mut cpu, &mut switched),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(
        harness.fixture.zone.slot(harness.fixture.slot).current(),
        Some(sibling)
    );
    assert!(matches!(
        harness.fixture.zone.record(harness.parent_record).claim(),
        carrick_sched_core::Claim::Queued { .. }
    ));

    let mut wait_b = carrick_el1_abi::TrapFrame::default();
    wait_b.x[8] = 260;
    wait_b.x[0] = u64::from(child_b_pid);
    wait_b.x[1] = status_b.arg();
    harness.call_current(&mut wait_b, &mut cpu);
    assert!(
        matches!(
            harness.fixture.zone.record(sibling).claim(),
            carrick_sched_core::Claim::Parked { .. }
        ),
        "second waiter failed to park after child_a exited between parks (x0 = {})",
        wait_b.x[0] as i64
    );
    assert_eq!(
        harness.fixture.zone.slot(harness.fixture.slot).current(),
        Some(harness.parent_record)
    );
    assert_eq!(wait_b.x[0], u64::from(child_a_pid));
    assert_eq!(
        status_a.get::<i32>(0),
        LinuxWaitStatus::from_wait_encoding(29 << 8).raw()
    );

    assert!(
        harness
            .fixture
            .zone
            .requeue_preempted(harness.fixture.slot, harness.parent_record)
            .is_queued()
    );
    assert_eq!(
        harness.switch_next(&mut cpu, &mut switched),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(
        harness.fixture.zone.slot(harness.fixture.slot).current(),
        Some(child_b)
    );
    harness.exit_current_child(37, &mut cpu, &mut exit_frame);
    if harness.fixture.zone.slot(harness.fixture.slot).current() == Some(harness.parent_record) {
        assert!(
            harness
                .fixture
                .zone
                .requeue_preempted(harness.fixture.slot, harness.parent_record)
                .is_queued()
        );
        assert_eq!(
            harness.switch_next(&mut cpu, &mut exit_frame),
            carrick_el1_abi::Action::Served
        );
    }
    assert_eq!(
        harness.fixture.zone.slot(harness.fixture.slot).current(),
        Some(sibling)
    );
    assert_eq!(exit_frame.x[0], u64::from(child_b_pid));
    assert_eq!(
        status_b.get::<i32>(0),
        LinuxWaitStatus::from_wait_encoding(37 << 8).raw()
    );
}

/// #2071 cross-operation witness: a thread parked in SysV `msgrcv` must not
/// cause a sibling's blocking `wait4` to fail with `-EAGAIN`, nor vice versa.
#[test]
fn arm_msgrcv_and_sibling_wait4_do_not_block_each_other() {
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MsgBuf {
        mtype: i64,
        mtext: [u8; 8],
    }

    for msgrcv_first in [true, false] {
        let mut harness = ProductionProcessHarness::new();
        let mut cpu = crate::sched::FakeCpu::default();
        let stack = carrick_test_support::GuestUserBuffer::zeroed(8192);
        let (_sibling_tid, sibling) = harness.spawn_thread(&stack, &mut cpu);
        let (child_pid, child) = harness.fork_child(&mut cpu);
        let status = carrick_test_support::GuestUserBuffer::from_value(-1i32);
        let rx_buf = carrick_test_support::GuestUserBuffer::from_value(MsgBuf {
            mtype: 0,
            mtext: [0; 8],
        });
        let qid = harness.msgget_current(0, 0o1600, &mut cpu);

        if msgrcv_first {
            // Leader parks in blocking msgrcv(qid, rx_buf, 8, 0, 0).
            let rcv = harness.msgrcv_current(qid, rx_buf.arg(), 8, 0, 0, &mut cpu);
            assert!(
                matches!(
                    rcv,
                    Ok(carrick_personality_linux::ipc::IpcOutcome::Suspended)
                ),
                "leader msgrcv must suspend: {rcv:?}"
            );
            assert!(matches!(
                harness.fixture.zone.record(harness.parent_record).claim(),
                carrick_sched_core::Claim::Parked { .. }
            ));
            assert_eq!(
                harness.fixture.zone.slot(harness.fixture.slot).current(),
                Some(sibling)
            );

            // Sibling calls blocking wait4(child_pid): must park, NOT -11!
            let mut wait = carrick_el1_abi::TrapFrame::default();
            wait.x[8] = 260;
            wait.x[0] = u64::from(child_pid);
            wait.x[1] = status.arg();
            harness.call_current(&mut wait, &mut cpu);
            assert!(
                matches!(
                    harness.fixture.zone.record(sibling).claim(),
                    carrick_sched_core::Claim::Parked { .. }
                ),
                "sibling wait4 blocked by parked msgrcv (x0 = {})",
                wait.x[0] as i64
            );
            assert_eq!(
                harness.fixture.zone.slot(harness.fixture.slot).current(),
                Some(child)
            );

            // Child exits(41) -> wakes sibling's wait4, leaving leader parked in msgrcv.
            let mut exit_frame = carrick_el1_abi::TrapFrame::default();
            harness.exit_current_child(41, &mut cpu, &mut exit_frame);
            assert_eq!(
                harness.fixture.zone.slot(harness.fixture.slot).current(),
                Some(sibling)
            );
            assert_eq!(exit_frame.x[0], u64::from(child_pid));
            assert!(matches!(
                harness.fixture.zone.record(harness.parent_record).claim(),
                carrick_sched_core::Claim::Parked { .. }
            ));

            // Sibling sends message -> wakes leader's msgrcv.
            assert!(matches!(
                harness.msgsnd_current(qid, 1, b"carrick!", 0, &mut cpu),
                Ok(carrick_personality_linux::ipc::IpcOutcome::Returned(_))
            ));
            assert!(
                harness
                    .fixture
                    .zone
                    .requeue_preempted(harness.fixture.slot, sibling)
                    .is_queued()
            );
            let mut resumed = carrick_el1_abi::TrapFrame::default();
            assert_eq!(
                harness.switch_next(&mut cpu, &mut resumed),
                carrick_el1_abi::Action::Served
            );
            assert_eq!(resumed.x[0], 8);
            assert_eq!(rx_buf.get::<MsgBuf>(0).mtext, *b"carrick!");
        } else {
            // Leader parks in blocking wait4(child_pid) first.
            let mut wait = carrick_el1_abi::TrapFrame::default();
            wait.x[8] = 260;
            wait.x[0] = u64::from(child_pid);
            wait.x[1] = status.arg();
            harness.call_current(&mut wait, &mut cpu);
            assert_eq!(
                harness.fixture.zone.slot(harness.fixture.slot).current(),
                Some(sibling)
            );

            // Sibling calls blocking msgrcv: must park, NOT -11!
            let rcv = harness.msgrcv_current(qid, rx_buf.arg(), 8, 0, 0, &mut cpu);
            assert!(
                matches!(
                    rcv,
                    Ok(carrick_personality_linux::ipc::IpcOutcome::Suspended)
                ),
                "sibling msgrcv blocked by parked wait4: {rcv:?}"
            );
            assert!(matches!(
                harness.fixture.zone.record(sibling).claim(),
                carrick_sched_core::Claim::Parked { .. }
            ));
            assert_eq!(
                harness.fixture.zone.slot(harness.fixture.slot).current(),
                Some(child)
            );

            // Child exits(43) -> wakes leader's wait4, leaving sibling parked in msgrcv.
            let mut exit_frame = carrick_el1_abi::TrapFrame::default();
            harness.exit_current_child(43, &mut cpu, &mut exit_frame);
            assert_eq!(
                harness.fixture.zone.slot(harness.fixture.slot).current(),
                Some(harness.parent_record)
            );
            assert_eq!(exit_frame.x[0], u64::from(child_pid));
            assert!(matches!(
                harness.fixture.zone.record(sibling).claim(),
                carrick_sched_core::Claim::Parked { .. }
            ));

            // Leader sends message -> wakes sibling's msgrcv.
            assert!(matches!(
                harness.msgsnd_current(qid, 1, b"carrick!", 0, &mut cpu),
                Ok(carrick_personality_linux::ipc::IpcOutcome::Returned(_))
            ));
            assert!(
                harness
                    .fixture
                    .zone
                    .requeue_preempted(harness.fixture.slot, harness.parent_record)
                    .is_queued()
            );
            let mut resumed = carrick_el1_abi::TrapFrame::default();
            assert_eq!(
                harness.switch_next(&mut cpu, &mut resumed),
                carrick_el1_abi::Action::Served
            );
            assert_eq!(resumed.x[0], 8);
            assert_eq!(rx_buf.get::<MsgBuf>(0).mtext, *b"carrick!");
        }
    }
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

/// How the carrier learns that a `CarrierWork` request owes thread stock:
/// from the exact request it claimed, never from a shared slot word.
fn carrier_stock_demand(
    _env: MultiSlotEnv,
    _slot: SlotId,
    request: &carrick_core_abi::service::ServiceRequest,
) -> bool {
    matches!(
        request.operation,
        carrick_core_abi::service::ServiceOperation::CarrierWork {
            demand: carrick_core_abi::service::CarrierDemand::ThreadStock,
            ..
        }
    )
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
    // The host's answer rule (`carrick_kernel::el1_delegation::settle_carrier_work`):
    // stocked iff the page holds claimable stock after its replenish.
    let reply = if carrick_core::lifecycle::stock::claimable(env.fixture.page) {
        carrick_core_abi::service::CarrierWorkReply::Stocked
    } else {
        carrick_core_abi::service::CarrierWorkReply::Unstockable
    };
    ticket
        .complete(
            reply
                .supplied_for(carrick_core_abi::service::CarrierDemand::ThreadStock)
                .unwrap(),
        )
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

/// The host answered the root's empty-pool clone `Unstockable` and the root
/// is selected again with that answer retained for its exact rerun.
fn root_holds_unstockable_answer(h: &mut ArmRootTwoThreadHarness) -> RecordId {
    let f = h.env.fixture;
    let root_record = clone_on_empty_pool_parks(h);
    answer_clone_carrier_work(h.env, SlotId::new(0), f.control, root_record, || {});
    if f.zone.slot(SlotId::new(0)).current() != Some(root_record) {
        assert_eq!(
            h.env.switch_in(SlotId::new(0), &mut h.root_cpu),
            carrick_el1_abi::Action::Served
        );
    }
    root_record
}

/// The root's next thread clone, on an empty pool the host can now stock, is
/// "not now" (no host-issued birth) and completes ring-born once stocked.
fn later_clone_waits_for_stock(h: &mut ArmRootTwoThreadHarness, root_record: RecordId) {
    let f = h.env.fixture;
    let counters = carrick_el1_abi::Counters::new();
    let (route, _, _) = h.env.clone_thread(
        SlotId::new(0),
        f.page,
        f.control,
        &counters,
        &mut h.root_cpu,
    );
    assert_ne!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Forward,
        "a stale `Unstockable` answer must not make a later clone host-issued"
    );
    assert_eq!(
        counters.lifecycle_declines[carrick_el1_abi::LifecycleDecline::ClonePoolEmpty as usize]
            .load(Ordering::Relaxed),
        0
    );
    let mut born_control = None;
    answer_clone_carrier_work(h.env, SlotId::new(0), f.control, root_record, || {
        born_control = Some(stock_arm_root_pool_identity(f, 44, 1));
    });
    let (clone_rc, _, born_record) = rerun_clone_in_ring(h, root_record);
    assert_eq!(clone_rc, 44, "the later clone completes in ring");
    assert_eq!(
        born_control.unwrap().zone_record(),
        Some(f.zone.record_ref(born_record))
    );
}

/// #1974 round 4: a caught signal is delivered between the `Unstockable`
/// carrier-work completion and the clone's rerun. The handler's own thread
/// clone runs on a pool the host can stock by then; the retained answer
/// belonged to the interrupted clone, so the handler's clone is "not now"
/// and gets stocked, never a host-issued birth.
#[test]
fn arm_empty_pool_clone_answer_does_not_cross_signal_delivery() {
    let mut h = setup_arm_root_two_live_threads_and_peer();
    let f = h.env.fixture;
    let root_record = root_holds_unstockable_answer(&mut h);
    assert_eq!(
        h.env.tgkill(
            SlotId::new(1),
            f.page,
            h.sib_control,
            &mut h.sib_cpu,
            (41, 41),
            SIGUSR1_NUM,
        ),
        0,
        "the sibling directs SIGUSR1 at the waiting root"
    );
    let stack = carrick_test_support::GuestUserBuffer::zeroed(16384);
    let mut frame = carrick_el1_abi::TrapFrame {
        slot: 0,
        elr: 0x40_0200,
        spsr: 0x3c0,
        ..Default::default()
    };
    assert_eq!(
        h.env.deliver_user_return(
            SlotId::new(0),
            f.page,
            f.control,
            &h.root_cpu,
            stack.arg() + 16384,
            &mut frame,
        ),
        None
    );
    assert_eq!(frame.elr, 0x40_1000, "the root enters its SIGUSR1 handler");
    later_clone_waits_for_stock(&mut h, root_record);
}

/// #1974 round 4: the retained answer is spent by the very next syscall,
/// whatever it is. After an ordinary syscall, a later clone is "not now".
#[test]
fn arm_empty_pool_clone_answer_does_not_cross_another_syscall() {
    let mut h = setup_arm_root_two_live_threads_and_peer();
    let f = h.env.fixture;
    let root_record = root_holds_unstockable_answer(&mut h);
    let counters = carrick_el1_abi::Counters::new();
    let mut gettid = carrick_el1_abi::TrapFrame::default();
    gettid.x[8] = 178;
    h.env.call(
        SlotId::new(0),
        f.page,
        f.control,
        &counters,
        &mut gettid,
        &mut h.root_cpu,
    );
    assert_eq!(gettid.x[0], 41);
    later_clone_waits_for_stock(&mut h, root_record);
}

/// #1974 round 4: a clone that `serve_clone` turns away before the pool
/// probe (here a thread clone without a stack) also spends the answer.
#[test]
fn arm_empty_pool_clone_answer_does_not_cross_an_early_clone_exit() {
    let mut h = setup_arm_root_two_live_threads_and_peer();
    let f = h.env.fixture;
    let root_record = root_holds_unstockable_answer(&mut h);
    let counters = carrick_el1_abi::Counters::new();
    let mut clone = carrick_el1_abi::TrapFrame::default();
    clone.x[8] = 220; // SYS_clone
    clone.x[0] = TGKILL_AFTER_CLONE_FLAGS;
    let _ = h.env.call(
        SlotId::new(0),
        f.page,
        f.control,
        &counters,
        &mut clone,
        &mut h.root_cpu,
    );
    assert_eq!(
        f.zone.slot(SlotId::new(0)).current(),
        Some(root_record),
        "the stackless clone never waited"
    );
    later_clone_waits_for_stock(&mut h, root_record);
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
            .service_notice
            .take()
            .expect("readable service notice")
            .is_none(),
        "no carrier work, so no stock demand, for a page the host never stocks"
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

/// The production `sched_yield` boundary on `slot` for whatever thread runs
/// there, switching in the next queued record through the production resume.
fn env_yield(
    env: MultiSlotEnv,
    slot: SlotId,
    cpu: &mut crate::sched::FakeCpu,
) -> Option<crate::sched::Served> {
    let task = &env.tasks[slot.index()];
    settle_boundary(task);
    let mut service = Aarch64NativeProcessService::with_crossing(
        task,
        slot,
        env.fixture.zone,
        env.fixture.region.table(),
        NonZeroU64::MIN,
        TestStockCrossing::new(&[]),
    );
    let mut switch = ProductionResumeCpu {
        inner: core::mem::take(cpu),
        service: &mut service,
    };
    let counters = carrick_el1_abi::Counters::new();
    let mut handoff = None;
    let mut frame = carrick_el1_abi::TrapFrame {
        esr: 0x15 << 26,
        slot: u64::from(slot.raw()),
        ..Default::default()
    };
    frame.x[8] = 124;
    let mut zone = crate::dispatch::Zone {
        tables: env.fixture.zone,
        cpu: &mut switch,
        user: &crate::sched::HardwareUserWord,
    };
    let served =
        super::super::dispatch::native_scheduler(&mut zone, task, &counters, slot, &mut handoff)
            .yield_queued(&mut frame);
    *cpu = core::mem::take(&mut switch.inner);
    served
}

/// The host served the boundary's work before the next entry.
fn settle_boundary(task: &CurrentTask) {
    if let Some(work) = task.linux.take_host_work_doorbell() {
        work.settled();
    }
    let _ = task.linux.take_served_boundary();
}

/// Publish a host load of `tid` on `slot`, as `publish_current_task` and the
/// executor's zone-slot publication do, with no zone record.
fn host_load(
    env: MultiSlotEnv,
    slot: SlotId,
    tid: u64,
    birth: u64,
    serial: u64,
    control: &'static ThreadControlSlot,
    driver: u64,
) -> crate::sched::FakeCpu {
    let fixture = env.fixture;
    let task = &env.tasks[slot.index()];
    task.set(
        El1TaskId::from_linux_tid(tid as i32),
        carrick_el1_abi::SnapshotGeneration::from_raw(birth),
        fixture.leader.file_table,
    );
    task.mm.key.store(fixture.leader.mm, Ordering::Release);
    task.mm.thread_generation.store(serial, Ordering::Release);
    task.publish_host_loaded(fixture.leader.tid as u32, fixture.address.generation);
    task.publish_lifecycle(fixture.page as *const _ as u64, control as *const _ as u64);
    if slot != fixture.slot {
        fixture.zone.drive(slot, driver);
        fixture
            .zone
            .publish_slot(slot, fixture.leader.mm, Some(0), 1);
        fixture.zone.enter_guest(slot);
        fixture.zone.install_space(slot, fixture.leader.mm).unwrap();
    }
    crate::sched::FakeCpu {
        ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
        ..Default::default()
    }
}

/// The real ARM signal checkpoint's admission and delivery for the thread
/// running on `slot` (`arm_signal_user_return` past its vector reads),
/// counting each signal frame it writes.
fn env_signal_checkpoint(
    env: MultiSlotEnv,
    slot: SlotId,
    control: &'static ThreadControlSlot,
    cpu: &crate::sched::FakeCpu,
    frame: &mut carrick_el1_abi::TrapFrame,
    stack: &carrick_test_support::GuestUserBuffer,
    delivered: &mut usize,
) -> Result<carrick_el1_abi::Action, NativeProcessError> {
    let task: &'static CurrentTask = &env.tasks[slot.index()];
    settle_boundary(task);
    let mut service = env.service(slot);
    let mut saved = Box::new(Aarch64ParkedContext::ZERO);
    crate::sched::ThreadCpu::save(
        &mut crate::sched::FakeCpu::default(),
        frame,
        &mut saved,
        crate::sched::CpuExitCause::Svc,
    );
    super::super::dispatch::arm_signal_user_return_entry(
        BornInZoneSource {
            zone: env.fixture.zone,
            slot,
        },
        task,
        &saved.native,
        cpu.ttbr.0,
        env.fixture.page,
        control,
        &mut service,
        |process| {
            super::super::arm_signal::deliver_on_user_return_at(
                task,
                control,
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
/// after #2044, on the path #2044's home-record restore does not cover.
///
/// A host-loaded thread of the root (host-born sibling 43 of PID 41) parks on
/// a futex in EL1. Its vCPU has nothing else to run, so it leaves EL1 idle and
/// the executor settles the thread into a host zone wait: the record stops
/// being the slot's home (`unhome`, carrick-runtime `vcpu_loop/zone.rs`) and
/// the executor steps away. The root's `FUTEX_WAKE` on another vCPU places
/// the record on that vCPU's queue, behind the root's native fork child (PID
/// 42). The child runs first, and its owner publishes PID 42 and its root
/// incarnation into the slot. The woken record is then switched in: it is
/// neither home (no #2044 restore) nor registered (its park record is not the
/// owner's), so `resume_unregistered` published no process binding and the
/// thread ran with the child's. Its return checkpoint's admission was refused
/// (`Invalid`) and the vector aborted the carrier with `entry_binding`.
fn unhomed_host_thread_after_another_process(pending_signal: bool) {
    let env = MultiSlotEnv::new();
    let fixture = env.fixture;
    let (slot0, slot1) = (SlotId::new(0), SlotId::new(1));
    let root_pid = fixture.leader.tid as u32;
    let mut root_cpu = host_load(
        env,
        slot0,
        fixture.leader.tid,
        fixture.leader.generation,
        fixture.leader.serial,
        fixture.control,
        1,
    );
    let counters = carrick_el1_abi::Counters::new();
    let mut gettid = carrick_el1_abi::TrapFrame::default();
    gettid.x[8] = 178;
    env.call(
        slot0,
        fixture.page,
        fixture.control,
        &counters,
        &mut gettid,
        &mut root_cpu,
    );
    assert_eq!(gettid.x[0], u64::from(root_pid));
    settle_boundary(&env.tasks[0]);
    if pending_signal {
        env.install_handler(
            slot0,
            fixture.page,
            fixture.control,
            &mut root_cpu,
            SIGUSR1_NUM,
        );
    }
    // The root forks a native child, queued on the root's vCPU.
    let mut fork = carrick_el1_abi::TrapFrame::default();
    fork.x[8] = 220;
    fork.x[0] = 17;
    env.call(
        slot0,
        fixture.page,
        fixture.control,
        &counters,
        &mut fork,
        &mut root_cpu,
    );
    settle_boundary(&env.tasks[0]);
    let child_pid = fork.x[0] as u32;
    assert!(child_pid > root_pid, "fork result {}", fork.x[0] as i64);
    let child = fixture.zone.runnable_head(slot0).unwrap();

    // A host-born sibling of the root runs host-loaded on its own vCPU.
    let sib_control = publish_host_born_sibling_only(fixture, 43);
    let birth = sib_control.host_birth_identity().unwrap();
    let mut sib_cpu = host_load(
        env,
        slot1,
        birth.task().raw(),
        birth.birth().raw(),
        birth.thread().raw(),
        sib_control,
        7,
    );
    let mut gettid = carrick_el1_abi::TrapFrame::default();
    gettid.x[8] = 178;
    env.call(
        slot1,
        fixture.page,
        sib_control,
        &counters,
        &mut gettid,
        &mut sib_cpu,
    );
    assert_eq!(gettid.x[0], 43);
    settle_boundary(&env.tasks[1]);
    assert!(sib_control.native_signal_owner());

    // The sibling waits on a futex: EL1 parks it in its home record, and its
    // vCPU, with nothing else to run, leaves EL1 idle.
    let word = carrick_test_support::GuestUserBuffer::from_value(0u32);
    let mut wait = carrick_el1_abi::TrapFrame {
        elr: 0x40_0004,
        ..Default::default()
    };
    wait.x[8] = crate::sched::SYS_FUTEX as u64;
    wait.x[0] = word.arg();
    wait.x[1] = crate::sched::FUTEX_WAIT_PRIVATE;
    sib_cpu.pending.push_back(carrick_el1_abi::GIC_KICK_INTID);
    assert_eq!(
        env.call(
            slot1,
            fixture.page,
            sib_control,
            &counters,
            &mut wait,
            &mut sib_cpu
        ),
        carrick_personality_linux::dispatch::CompletionRoute::Suspended
    );
    settle_boundary(&env.tasks[1]);
    let parked = fixture.zone.slot(slot1).host_record().unwrap();
    assert!(matches!(
        fixture.zone.record(parked).claim(),
        carrick_sched_core::Claim::Parked { .. }
    ));
    // Its executor settles it into a host zone wait and steps away.
    fixture.zone.unhome(slot1, parked, 1);
    fixture
        .zone
        .leave_guest(slot1, &carrick_sched_core::ShortLockSpin);
    assert!(fixture.zone.step_away(slot1, 7, &mut |_| {}, &mut |_| {}));

    // The root's FUTEX_WAKE places the woken record on the root's vCPU.
    let mut wake = carrick_el1_abi::TrapFrame::default();
    wake.x[8] = crate::sched::SYS_FUTEX as u64;
    wake.x[0] = word.arg();
    wake.x[1] = crate::sched::FUTEX_WAKE_PRIVATE;
    wake.x[2] = 1;
    env.call(
        slot0,
        fixture.page,
        fixture.control,
        &counters,
        &mut wake,
        &mut root_cpu,
    );
    settle_boundary(&env.tasks[0]);
    assert_eq!(wake.x[0], 1, "FUTEX_WAKE woke the sibling");
    assert!(matches!(
        fixture.zone.record(parked).claim(),
        carrick_sched_core::Claim::Queued { slot, .. } if slot == slot0
    ));

    // The root yields: the child runs and publishes its own process binding.
    assert!(env_yield(env, slot0, &mut root_cpu).is_some());
    assert_eq!(fixture.zone.slot(slot0).current(), Some(child));
    assert_eq!(env.tasks[0].visible_pid(), Some(child_pid));
    // The child yields: the woken sibling is switched in after it.
    assert!(env_yield(env, slot0, &mut root_cpu).is_some());
    assert_eq!(fixture.zone.slot(slot0).current(), Some(parked));
    assert_eq!(env.tasks[0].execution.task.load(Ordering::Acquire), 43);

    // The sibling's return to EL0 passes the signal checkpoint.
    let stack = carrick_test_support::GuestUserBuffer::zeroed(16384);
    let mut frame = carrick_el1_abi::TrapFrame {
        esr: 0x15 << 26,
        slot: u64::from(slot0.raw()),
        elr: 0x40_0004,
        ..Default::default()
    };
    let mut delivered = 0;
    assert_eq!(
        env_signal_checkpoint(
            env,
            slot0,
            sib_control,
            &root_cpu,
            &mut frame,
            &stack,
            &mut delivered
        ),
        Ok(carrick_el1_abi::Action::Served),
        "the woken sibling's checkpoint refused its own process (vector: entry_binding)"
    );
    assert_eq!(
        (env.tasks[0].visible_pid(), env.tasks[0].root_generation()),
        (Some(root_pid), Some(fixture.address.generation)),
        "the switched-in sibling runs with its own process's binding"
    );
    assert_eq!(delivered, 0, "no signal is owed");

    // Its next call, an EL1-served FUTEX_WAKE, admits through its owner.
    let mut again = carrick_el1_abi::TrapFrame::default();
    again.x[8] = crate::sched::SYS_FUTEX as u64;
    again.x[0] = word.arg();
    again.x[1] = crate::sched::FUTEX_WAKE_PRIVATE;
    again.x[2] = 1;
    env.call(
        slot0,
        fixture.page,
        sib_control,
        &counters,
        &mut again,
        &mut root_cpu,
    );
    assert_eq!(again.x[0], 0, "FUTEX_WAKE with no waiter wakes none");
    settle_boundary(&env.tasks[0]);
    if pending_signal {
        // SIGUSR1 has the root's handler; the sibling signals itself.
        assert_eq!(
            env.tgkill(
                slot0,
                fixture.page,
                sib_control,
                &mut root_cpu,
                (root_pid, 43),
                SIGUSR1_NUM
            ),
            0,
            "tgkill(self, SIGUSR1)"
        );
    }
    let mut frame = carrick_el1_abi::TrapFrame {
        esr: 0x15 << 26,
        slot: u64::from(slot0.raw()),
        elr: 0x40_0008,
        ..Default::default()
    };
    assert_eq!(
        env_signal_checkpoint(
            env,
            slot0,
            sib_control,
            &root_cpu,
            &mut frame,
            &stack,
            &mut delivered
        ),
        Ok(carrick_el1_abi::Action::Served)
    );
    if pending_signal {
        assert_eq!(delivered, 1, "SIGUSR1 is delivered at this checkpoint");
        assert_eq!(frame.elr, 0x40_1000, "the handler runs next");
        assert_eq!(frame.x[0], SIGUSR1_NUM);
    } else {
        assert_eq!(delivered, 0, "no signal is owed");
        assert_eq!(frame.elr, 0x40_0008, "the call returns in place");
    }
}

#[test]
fn arm_unhomed_host_thread_switched_in_after_another_process_admits() {
    unhomed_host_thread_after_another_process(false);
}

#[test]
fn arm_unhomed_host_thread_switched_in_after_another_process_delivers_pending_signal_once() {
    unhomed_host_thread_after_another_process(true);
}

/// One sibling member running on a second vCPU (`SlotId(1)`) of the
/// harness's process, with its own executor task and services.
struct SecondVcpu {
    slot: SlotId,
    /// Executor tasks indexed by slot, as the vector's `current_tasks`.
    tasks: &'static [CurrentTask; 2],
    task: &'static CurrentTask,
    dispatch_service: Aarch64NativeProcessService<'static, TestStockCrossing>,
    resume_service: Aarch64NativeProcessService<'static, TestStockCrossing>,
    cpu: crate::sched::FakeCpu,
}

impl SecondVcpu {
    fn new(fixture: &'static Fixture) -> Self {
        let slot = SlotId::new(1);
        fixture.zone.drive(slot, 2);
        fixture.zone.publish_slot(slot, 0, None, 0);
        fixture.zone.enter_guest(slot);
        let tasks: &'static [CurrentTask; 2] =
            Box::leak(Box::new([CurrentTask::new(), CurrentTask::new()]));
        let task = &tasks[1];
        let service = || {
            Aarch64NativeProcessService::with_crossing(
                task,
                slot,
                fixture.zone,
                fixture.region.table(),
                NonZeroU64::MIN,
                TestStockCrossing::new(&[]),
            )
        };
        Self {
            slot,
            tasks,
            task,
            dispatch_service: service(),
            resume_service: service(),
            cpu: crate::sched::FakeCpu::default(),
        }
    }

    fn settle_doorbells(&self) {
        if let Some(work) = self.task.linux.take_host_work_doorbell() {
            work.settled();
        }
        let _ = self.task.linux.take_served_boundary();
    }

    fn call_current(
        &mut self,
        fixture: &'static Fixture,
        frame: &mut carrick_el1_abi::TrapFrame,
    ) -> carrick_personality_linux::dispatch::CompletionRoute {
        self.settle_doorbells();
        let route = call_on_slot(
            fixture,
            self.slot,
            self.tasks,
            &mut self.dispatch_service,
            &mut self.resume_service,
            frame,
            &mut self.cpu,
        );
        self.settle_doorbells();
        route
    }

    fn switch_next(
        &mut self,
        fixture: &'static Fixture,
        frame: &mut carrick_el1_abi::TrapFrame,
    ) -> carrick_el1_abi::Action {
        self.settle_doorbells();
        let action = switch_on_slot(
            fixture,
            self.slot,
            self.task,
            &mut self.resume_service,
            &mut self.cpu,
            frame,
        );
        self.settle_doorbells();
        action
    }
}

/// What the sibling's `wait4` did while the forking thread held its birth
/// reservation.
#[derive(Debug)]
struct ContendedWait {
    x0: i64,
    parked: bool,
}

/// #2095: thread A's `fork`/`vfork` holds its process's birth reservation
/// (`reserve_birth`) across its stock loan crossing. A sibling thread B on a
/// second vCPU calls blocking `wait4` for an already exited child at that
/// moment. Contention is "not now": B must enrol on the reservation's
/// release, park, and reap the zombie once A releases, never return `-11`
/// (`-EAGAIN`). A `vfork` caller still stays suspended until its child exits.
fn wait4_reaps_zombie_while_sibling_holds_birth_reservation(vfork: bool) {
    let mut harness = ProductionProcessHarness::new();
    let fixture = harness.fixture;
    let slot0 = fixture.slot;
    let mut cpu = crate::sched::FakeCpu::default();
    let stack = carrick_test_support::GuestUserBuffer::zeroed(8192);
    let vfork_stack = carrick_test_support::GuestUserBuffer::zeroed(4096);
    let status = carrick_test_support::GuestUserBuffer::from_value(-1i32);

    // A zombie child first, then the sibling thread B.
    let (zombie_pid, zombie) = harness.fork_child(&mut cpu);
    let (_sibling_tid, sibling) = harness.spawn_thread(&stack, &mut cpu);
    assert!(
        fixture
            .zone
            .requeue_preempted(slot0, harness.parent_record)
            .is_queued()
    );
    let mut frame = carrick_el1_abi::TrapFrame::default();
    assert_eq!(
        harness.switch_next(&mut cpu, &mut frame),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(fixture.zone.slot(slot0).current(), Some(zombie));
    harness.exit_current_child(5, &mut cpu, &mut frame);
    // The leader runs on vCPU 0; B waits in vCPU 0's run queue.
    if fixture.zone.slot(slot0).current() == Some(sibling) {
        assert!(fixture.zone.requeue_preempted(slot0, sibling).is_queued());
        assert_eq!(
            harness.switch_next(&mut cpu, &mut frame),
            carrick_el1_abi::Action::Served
        );
    }
    assert_eq!(
        fixture.zone.slot(slot0).current(),
        Some(harness.parent_record)
    );

    // vCPU 1 takes B from vCPU 0's queue.
    let second: &'static mut SecondVcpu = Box::leak(Box::new(SecondVcpu::new(fixture)));
    let mut idle = carrick_el1_abi::TrapFrame::default();
    assert_eq!(
        second.switch_next(fixture, &mut idle),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(fixture.zone.slot(second.slot).current(), Some(sibling));

    // A's stock loan crossing runs B's wait4 on vCPU 1 while A holds the
    // reservation, as a sibling vCPU does during a real synchronous crossing.
    let observed = Arc::new(std::sync::Mutex::new(None));
    let observed_by_hook = observed.clone();
    let second_address = core::ptr::from_mut(second) as usize;
    let fixture_address = core::ptr::from_ref(fixture) as usize;
    let status_arg = status.arg();
    *harness.dispatch_service.crossing.on_loan.lock().unwrap() = Some(Box::new(move || {
        // SAFETY: the leaked vCPU outlives the test; the outer fork runs
        // this hook synchronously and never touches vCPU 1's state.
        let second = unsafe { &mut *(second_address as *mut SecondVcpu) };
        // SAFETY: the harness leaks its fixture for the life of the test.
        let fixture: &'static Fixture = unsafe { &*(fixture_address as *const Fixture) };
        let mut wait = carrick_el1_abi::TrapFrame::default();
        wait.x[8] = 260;
        wait.x[0] = u64::from(zombie_pid);
        wait.x[1] = status_arg;
        second.call_current(fixture, &mut wait);
        let parked = matches!(
            fixture.zone.record(sibling).claim(),
            carrick_sched_core::Claim::Parked { .. }
        );
        *observed_by_hook.lock().unwrap() = Some(ContendedWait {
            x0: wait.x[0] as i64,
            parked,
        });
    }));

    let mut clone = carrick_el1_abi::TrapFrame::default();
    clone.x[8] = 220;
    if vfork {
        clone.x[0] = 0x4111;
        clone.x[1] = vfork_stack.arg() + 4096;
    } else {
        clone.x[0] = 17;
    }
    harness.call_current(&mut clone, &mut cpu);
    let contended = observed
        .lock()
        .unwrap()
        .take()
        .expect("A's fork crossed for stock while holding its reservation");
    assert!(
        contended.parked,
        "B's wait4 returned {} while A held its birth reservation instead of \
         waiting for the release",
        contended.x0
    );
    assert_eq!(status.get::<i32>(0), -1, "B parked before copying status");

    if vfork {
        assert!(
            matches!(
                fixture.zone.record(harness.parent_record).claim(),
                carrick_sched_core::Claim::Parked { .. }
            ),
            "the vfork caller returned unsuspended (x0 = {})",
            clone.x[0] as i64
        );
    } else {
        assert!(clone.x[0] as i64 > 0, "fork result {}", clone.x[0] as i64);
    }

    // A's release woke B: it reaps the zombie with its exact status.
    let mut resumed = carrick_el1_abi::TrapFrame::default();
    let woken_on_second = fixture.zone.slot(second.slot).queued() > 0;
    if woken_on_second {
        assert_eq!(
            second.switch_next(fixture, &mut resumed),
            carrick_el1_abi::Action::Served
        );
    } else {
        let current = fixture.zone.slot(slot0).current().unwrap();
        if current != sibling {
            assert!(fixture.zone.requeue_preempted(slot0, current).is_queued());
            loop {
                assert_eq!(
                    harness.switch_next(&mut cpu, &mut resumed),
                    carrick_el1_abi::Action::Served
                );
                let now = fixture.zone.slot(slot0).current().unwrap();
                if now == sibling {
                    break;
                }
                assert!(fixture.zone.requeue_preempted(slot0, now).is_queued());
            }
        }
    }
    assert_eq!(
        resumed.x[0] as i64,
        i64::from(zombie_pid),
        "B's wait4 after the release"
    );
    assert_eq!(
        status.get::<i32>(0),
        LinuxWaitStatus::from_wait_encoding(5 << 8).raw()
    );
}

#[test]
fn arm_wait4_reaps_zombie_while_sibling_fork_holds_birth_reservation() {
    wait4_reaps_zombie_while_sibling_holds_birth_reservation(false);
}

#[test]
fn arm_wait4_reaps_zombie_while_sibling_vfork_holds_birth_reservation() {
    wait4_reaps_zombie_while_sibling_holds_birth_reservation(true);
}

/// #2109: a glibc thread of a native fork child, pinned with
/// `sched_setaffinity` to CPU 1, ends with a raw `exit` while its leader and
/// a sibling stay live. It runs from the zone on CPU 1's slot, whose executor
/// waits in the guest with no host task loaded: nothing on the host can take
/// the thread's exit there. glibc registers a robust list for every thread,
/// and before the fix the ring declined that exit (`ExitRobust`) into host
/// custody: the vector captured the SVC for that executor, which had no task
/// to give it to, and the carrier died ("tried to park off-guest").
#[test]
fn arm_pinned_glibc_member_raw_exit_on_an_idle_executor_retires_in_ring() {
    use carrick_el1_abi::{Lifecycle, LifecycleDecline};
    use carrick_personality_linux::dispatch::CompletionRoute;
    let mut h = setup_native_owned_ring_birth_before_first_entry();
    let zone = h.env.fixture.zone;
    zone.publish_carrier_cpu_count(2);
    let counters = carrick_el1_abi::Counters::new();
    // The leader pins the new thread to CPU 1 before it first runs.
    let mask = carrick_test_support::GuestUserBuffer::from_value(1u64 << 1);
    let mut pin = carrick_el1_abi::TrapFrame::default();
    pin.x[8] = 122;
    pin.x[..3].copy_from_slice(&[u64::from(h.born_tid), 8, mask.arg()]);
    h.env.call(
        SlotId::new(0),
        h.target_page,
        h.leader_control,
        &counters,
        &mut pin,
        &mut h.leader_cpu,
    );
    assert_eq!(pin.x[0], 0);
    // Slot 3's executor waits in the guest on CPU 1 with no host task.
    let pinned = SlotId::new(3);
    zone.drive(pinned, 4);
    zone.publish_slot(pinned, 0, Some(1), 0);
    zone.enter_guest(pinned);
    let mut cpu = crate::sched::FakeCpu::default();
    assert_eq!(
        h.env.switch_in(pinned, &mut cpu),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(zone.slot(pinned).current(), Some(h.born_record));
    assert_eq!(zone.slot(pinned).host_record(), None);
    assert!(!zone.current_affinity_excludes_cpu(pinned));

    let mut call = |nr: u64, args: &[u64]| {
        let mut frame = carrick_el1_abi::TrapFrame::default();
        frame.x[8] = nr;
        frame.x[..args.len()].copy_from_slice(args);
        let route = h.env.call(
            pinned,
            h.target_page,
            h.born_control,
            &counters,
            &mut frame,
            &mut cpu,
        );
        (route, frame.x[0] as i64)
    };
    // glibc's thread start: its own clear_child_tid word and robust list.
    let child_tid = carrick_test_support::GuestUserBuffer::from_value(h.born_tid);
    assert_eq!(call(96, &[child_tid.arg()]).1, i64::from(h.born_tid));
    let robust = carrick_test_support::GuestUserBuffer::zeroed(24);
    assert_eq!(call(99, &[robust.arg(), 24]).1, 0);
    assert_ne!(h.born_control.robust_list().0, 0);

    let live = h.target_page.live();
    let (route, _) = call(93, &[0]);
    assert_ne!(
        route,
        CompletionRoute::HostCustody,
        "the raw exit left for an executor with no host task loaded"
    );
    assert_eq!(
        counters.lifecycle_declines[LifecycleDecline::ExitRobust as usize].load(Ordering::Relaxed),
        0,
        "a registered robust list declined the raw exit"
    );
    assert_eq!(route, CompletionRoute::Suspended);
    // Retired in ring: one fewer live member, its clear_child_tid word
    // cleared for the joiner, and the slot no longer runs it.
    assert_eq!(h.target_page.live(), live - 1);
    assert_eq!(child_tid.get::<u32>(0), 0);
    assert_ne!(zone.slot(pinned).current(), Some(h.born_record));

    // The sibling is still live and keeps running.
    let mut gettid = carrick_el1_abi::TrapFrame::default();
    gettid.x[8] = 178;
    h.env.call(
        SlotId::new(1),
        h.target_page,
        h.sibling_control,
        &counters,
        &mut gettid,
        &mut h.sibling_cpu,
    );
    assert!(gettid.x[0] as i64 > 0);
}
