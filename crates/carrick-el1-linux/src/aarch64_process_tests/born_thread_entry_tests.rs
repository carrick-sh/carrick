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
        frame.esr = 0x15 << 26;
        frame.slot = u64::from(self.fixture.slot.raw());
        let mut resume_cpu = ProductionResumeCpu {
            inner: core::mem::take(cpu),
            service: &mut self.resume_service,
        };
        let counters = carrick_el1_abi::Counters::new();
        let cache = carrick_el1_abi::InotifyNameCache::new();
        let route = super::super::dispatch::dispatch_arm_syscall_with_native_process(
            frame,
            &counters,
            core::slice::from_ref(self.task),
            &[],
            &[],
            &[],
            &[],
            &cache,
            Some(crate::dispatch::Zone {
                tables: self.fixture.zone,
                cpu: &mut resume_cpu,
                user: &crate::sched::HardwareUserWord,
            }),
            None,
            Some(&LoadedVenue),
            page,
            control,
            &saved.native,
            ttbr0,
            &mut self.dispatch_service,
            |_| core::ptr::null_mut(),
        )
        .expect("production ARM native process dispatch");
        *cpu = core::mem::take(&mut resume_cpu.inner);
        self.settle_doorbells();
        route
    }

    fn switch_next(
        &mut self,
        cpu: &mut crate::sched::FakeCpu,
        frame: &mut carrick_el1_abi::TrapFrame,
    ) -> carrick_el1_abi::Action {
        self.settle_doorbells();
        let mut switch = ProductionResumeCpu {
            inner: core::mem::take(cpu),
            service: &mut self.resume_service,
        };
        let counters = carrick_el1_abi::Counters::new();
        let mut handoff = None;
        let mut zone = crate::dispatch::Zone {
            tables: self.fixture.zone,
            cpu: &mut switch,
            user: &crate::sched::HardwareUserWord,
        };
        let action = super::super::dispatch::native_scheduler(
            &mut zone,
            self.task,
            &counters,
            self.fixture.slot,
            &mut handoff,
        )
        .idle_entry(frame, 0);
        *cpu = core::mem::take(&mut switch.inner);
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
        run: impl FnOnce(&mut dyn carrick_personality_linux::lifecycle::ProcessNative) -> R,
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
        self.with_current_entry(cpu, |entry| {
            entry
                .as_ipc_venue()
                .expect("native IPC venue")
                .msgget(key, msgflg)
                .expect("msgget")
        })
    }

    fn msgrcv_current(
        &mut self,
        msqid: i32,
        msgp: u64,
        msgsz: usize,
        msgtyp: i64,
        msgflg: i32,
        cpu: &mut crate::sched::FakeCpu,
        switched_frame: &mut carrick_el1_abi::TrapFrame,
    ) -> Result<carrick_personality_linux::ipc::IpcOutcome, i64> {
        let result = self.with_current_entry(cpu, |entry| {
            entry
                .as_ipc_venue()
                .expect("native IPC venue")
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
            assert_eq!(
                self.switch_next(cpu, switched_frame),
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
        self.with_current_entry(cpu, |entry| {
            entry
                .as_ipc_venue()
                .expect("native IPC venue")
                .msgsnd(msqid, mtype, mtext, msgflg)
        })
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
            let mut rcv_switched = carrick_el1_abi::TrapFrame::default();
            let rcv =
                harness.msgrcv_current(qid, rx_buf.arg(), 8, 0, 0, &mut cpu, &mut rcv_switched);
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
            let mut rcv_switched = carrick_el1_abi::TrapFrame::default();
            let rcv =
                harness.msgrcv_current(qid, rx_buf.arg(), 8, 0, 0, &mut cpu, &mut rcv_switched);
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
