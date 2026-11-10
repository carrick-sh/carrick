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

/// Exact `raw_clone_thread` flags used by `fixtures/embed-el1-sched/src/threads.rs`
/// in `tgkill_after_clone`: `CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
/// CLONE_THREAD | CLONE_SYSVSEM | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID`.
const TGKILL_AFTER_CLONE_FLAGS: u64 = 0x0035_0f00;
const LINUX_SIGUSR1: u64 = 10;
const LINUX_SIGUSR2: u64 = 12;

fn init_guest_slot(fixture: &'static Fixture, slot: SlotId) {
    fixture.zone.drive(slot, 1);
    fixture.zone.publish_slot(slot, 0, None, 0);
    fixture.zone.enter_guest(slot);
}

fn switch_in_slot(
    fixture: &'static Fixture,
    slot: SlotId,
    task: &'static CurrentTask,
    cpu: &mut crate::sched::FakeCpu,
    frame: &mut carrick_el1_abi::TrapFrame,
) -> carrick_el1_abi::Action {
    let mut service = Aarch64NativeProcessService::with_crossing(
        task,
        slot,
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
    let action =
        super::super::dispatch::native_scheduler(&mut zone, task, &counters, slot, &mut handoff)
            .idle_entry(frame, 0);
    *cpu = core::mem::take(&mut switch.inner);
    action
}

#[allow(clippy::too_many_arguments)]
fn loaded_call_on_slot<X: ForkStockCrossing>(
    fixture: &'static Fixture,
    tasks: &'static [CurrentTask; 4],
    slot: SlotId,
    page: &'static ThreadLifecyclePage,
    control: &'static ThreadControlSlot,
    service: &mut Aarch64NativeProcessService<'static, X>,
    counters: &carrick_el1_abi::Counters,
    frame: &mut carrick_el1_abi::TrapFrame,
    cpu: &mut crate::sched::FakeCpu,
) -> Result<carrick_personality_linux::dispatch::CompletionRoute, NativeProcessError> {
    let cache = Box::new(carrick_el1_abi::InotifyNameCache::new());
    let current = fixture.zone.slot(slot).current().unwrap();
    // SAFETY: `slot` exclusively owns `current` while OnCpu.
    let saved = unsafe { *fixture.zone.record(current).ctx_mut() };
    let ttbr0 = cpu.ttbr.0;
    frame.slot = u64::from(slot.raw());
    frame.esr = 0x15 << 26;
    service.slot = slot;
    service.task = &tasks[slot.index()];
    super::super::dispatch::dispatch_arm_syscall_with_native_process(
        frame,
        counters,
        tasks,
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

#[allow(clippy::too_many_arguments)]
fn poll_signal_once_on_slot<X: ForkStockCrossing>(
    fixture: &'static Fixture,
    tasks: &'static [CurrentTask; 4],
    slot: SlotId,
    page: &'static ThreadLifecyclePage,
    control: &'static ThreadControlSlot,
    service: &mut Aarch64NativeProcessService<'static, X>,
    cpu: &mut crate::sched::FakeCpu,
    sig: u64,
) -> i64 {
    let sigset = carrick_test_support::GuestUserBuffer::from_value(1u64 << (sig - 1));
    let zero_ts = carrick_test_support::GuestUserBuffer::from_value([0i64, 0i64]);
    let counters = carrick_el1_abi::Counters::new();
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = 137; // SYS_rt_sigtimedwait
    frame.x[0] = sigset.arg();
    frame.x[1] = 0;
    frame.x[2] = zero_ts.arg();
    frame.x[3] = 8;
    loaded_call_on_slot(
        fixture, tasks, slot, page, control, service, &counters, &mut frame, cpu,
    )
    .expect("rt_sigtimedwait must dispatch cleanly");
    frame.x[0] as i64
}

#[allow(clippy::too_many_arguments)]
fn install_noop_handler_on_slot<X: ForkStockCrossing>(
    fixture: &'static Fixture,
    tasks: &'static [CurrentTask; 4],
    slot: SlotId,
    page: &'static ThreadLifecyclePage,
    control: &'static ThreadControlSlot,
    service: &mut Aarch64NativeProcessService<'static, X>,
    cpu: &mut crate::sched::FakeCpu,
    sig: u64,
) {
    // Linux kernel_sigaction layout on AArch64: [sa_handler, sa_flags, sa_mask].
    let act = carrick_test_support::GuestUserBuffer::from_value([0x40_1000u64, 0u64, 0u64]);
    let counters = carrick_el1_abi::Counters::new();
    let mut frame = carrick_el1_abi::TrapFrame::default();
    frame.x[8] = 134; // SYS_rt_sigaction
    frame.x[0] = sig;
    frame.x[1] = act.arg();
    frame.x[2] = 0;
    frame.x[3] = 8;
    loaded_call_on_slot(
        fixture, tasks, slot, page, control, service, &counters, &mut frame, cpu,
    )
    .expect("rt_sigaction must dispatch cleanly");
    assert_eq!(frame.x[0] as i64, 0, "rt_sigaction({sig}) failed");
}

struct NativeOwnedTwoThreadHarness {
    fixture: &'static Fixture,
    tasks: &'static [CurrentTask; 4],
    crossing: &'static TestStockCrossing,
    peer_pid: u32,
    peer_page: &'static ThreadLifecyclePage,
    peer_control: &'static ThreadControlSlot,
    peer_cpu: crate::sched::FakeCpu,
    target_pid: u32,
    target_page: &'static ThreadLifecyclePage,
    leader_control: &'static ThreadControlSlot,
    leader_cpu: crate::sched::FakeCpu,
    sibling_control: &'static ThreadControlSlot,
    sibling_cpu: crate::sched::FakeCpu,
    born_record: RecordId,
    born_tid: u32,
    born_control: &'static ThreadControlSlot,
}

/// Build the exact #2030 native-owned birth topology with TWO live entered
/// threads of `P_target` (slots 0 and 1) plus a live peer process `P_peer`
/// (slot 2), then clone a 3rd thread `born` on slot 0 and hold it queued
/// BEFORE its first entry.
fn setup_native_owned_ring_birth_before_first_entry() -> NativeOwnedTwoThreadHarness {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    fixture.zone.spaces.set_idle_ttbr(0x30000);
    let tasks: &'static [CurrentTask; 4] =
        Box::leak(Box::new(core::array::from_fn(|_| CurrentTask::new())));
    let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
    let stock_pages: Vec<u64> = (0..24).map(|i| 0x20000 + i * 0x1000).collect();
    let crossing: &'static TestStockCrossing =
        Box::leak(Box::new(TestStockCrossing::new(&stock_pages)));
    let mut boot_service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        crossing,
    )
    .with_words(words);
    let mut boot_cpu = crate::sched::FakeCpu {
        ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
        ..Default::default()
    };
    // Root (PID 41) forks native child P_target AND native child P_peer so both
    // processes have saved parked contexts and unrestricted slot affinity.
    let mut fork_frame = carrick_el1_abi::TrapFrame::default();
    fork_frame.x[8] = 220;
    fork_frame.x[0] = 17;
    arm_call_with_cpu(
        fixture,
        fixture.control,
        &mut boot_service,
        &mut fork_frame,
        &mut boot_cpu,
    )
    .unwrap();
    let target_pid_from_fork = fork_frame.x[0] as i64;
    assert!(
        target_pid_from_fork > 0,
        "fork target rc={target_pid_from_fork}"
    );
    let target_leader = fixture.zone.runnable_head(fixture.slot).unwrap();
    let target_identity = fixture.zone.record(target_leader).identity();
    let target_page = unsafe { &*(target_identity.lifecycle_page as *const ThreadLifecyclePage) };
    let leader_control = unsafe { &*(target_identity.control_slot as *const ThreadControlSlot) };

    let mut fork_peer = carrick_el1_abi::TrapFrame::default();
    fork_peer.x[8] = 220;
    fork_peer.x[0] = 17;
    arm_call_with_cpu(
        fixture,
        fixture.control,
        &mut boot_service,
        &mut fork_peer,
        &mut boot_cpu,
    )
    .unwrap();
    let peer_pid_from_fork = fork_peer.x[0] as i64;
    assert!(
        peer_pid_from_fork > target_pid_from_fork,
        "fork peer rc={peer_pid_from_fork}"
    );

    // Switch P_target onto slot 0 and P_peer onto slot 2 so both processes stay
    // live on separate slots.
    let mut leader_cpu = crate::sched::FakeCpu::default();
    let mut dummy = carrick_el1_abi::TrapFrame::default();
    fixture.zone.publish_slot(SlotId::new(0), 0, None, 0);
    assert_eq!(
        switch_in_slot(
            fixture,
            SlotId::new(0),
            &tasks[0],
            &mut leader_cpu,
            &mut dummy
        ),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(
        fixture.zone.slot(SlotId::new(0)).current(),
        Some(target_leader)
    );
    let target_pid = tasks[0].visible_pid().unwrap();
    assert_eq!(i64::from(target_pid), target_pid_from_fork);

    // Slot 2 steals `P_peer` via production switch-in.
    init_guest_slot(fixture, SlotId::new(2));
    let mut peer_cpu = crate::sched::FakeCpu::default();
    assert_eq!(
        switch_in_slot(
            fixture,
            SlotId::new(2),
            &tasks[2],
            &mut peer_cpu,
            &mut dummy
        ),
        carrick_el1_abi::Action::Served
    );
    let peer_record = fixture.zone.slot(SlotId::new(2)).current().unwrap();
    let peer_identity = fixture.zone.record(peer_record).identity();
    let peer_page = unsafe { &*(peer_identity.lifecycle_page as *const ThreadLifecyclePage) };
    let peer_control = unsafe { &*(peer_identity.control_slot as *const ThreadControlSlot) };
    let peer_pid = tasks[2].visible_pid().unwrap();
    assert_eq!(i64::from(peer_pid), peer_pid_from_fork);

    let mut leader_service = Aarch64NativeProcessService::with_crossing(
        &tasks[0],
        SlotId::new(0),
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        crossing,
    )
    .with_words(words);
    install_noop_handler_on_slot(
        fixture,
        tasks,
        SlotId::new(0),
        target_page,
        leader_control,
        &mut leader_service,
        &mut leader_cpu,
        LINUX_SIGUSR1,
    );
    install_noop_handler_on_slot(
        fixture,
        tasks,
        SlotId::new(0),
        target_page,
        leader_control,
        &mut leader_service,
        &mut leader_cpu,
        LINUX_SIGUSR2,
    );

    // P_target clones sibling #1 and switches it in on slot 1 + runs its first
    // syscall (GETTID) so P_target has TWO live entered threads simultaneously.
    let stack1 = carrick_test_support::GuestUserBuffer::zeroed(8192);
    let ptid1 = carrick_test_support::GuestUserBuffer::from_value(0u32);
    let ctid1 = carrick_test_support::GuestUserBuffer::from_value(0xffffu32);
    let counters = carrick_el1_abi::Counters::new();
    let mut clone1 = carrick_el1_abi::TrapFrame::default();
    clone1.x[8] = 220;
    clone1.x[..5].copy_from_slice(&[
        TGKILL_AFTER_CLONE_FLAGS,
        stack1.arg() + 8192,
        ptid1.arg(),
        0,
        ctid1.arg(),
    ]);
    loaded_call_on_slot(
        fixture,
        tasks,
        SlotId::new(0),
        target_page,
        leader_control,
        &mut leader_service,
        &counters,
        &mut clone1,
        &mut leader_cpu,
    )
    .unwrap();
    let sib1_tid = clone1.x[0] as i64;
    assert!(sib1_tid > i64::from(target_pid), "sib1 clone rc={sib1_tid}");
    let sib1_record = fixture.zone.runnable_head(SlotId::new(0)).unwrap();
    let sib1_control = unsafe {
        &*(fixture.zone.record(sib1_record).identity().control_slot as *const ThreadControlSlot)
    };

    init_guest_slot(fixture, SlotId::new(1));
    let mut sibling_cpu = crate::sched::FakeCpu::default();
    assert_eq!(
        switch_in_slot(
            fixture,
            SlotId::new(1),
            &tasks[1],
            &mut sibling_cpu,
            &mut dummy
        ),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(
        fixture.zone.slot(SlotId::new(1)).current(),
        Some(sib1_record)
    );
    let mut sib_service = Aarch64NativeProcessService::with_crossing(
        &tasks[1],
        SlotId::new(1),
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        crossing,
    )
    .with_words(words);
    let mut gettid = carrick_el1_abi::TrapFrame::default();
    gettid.x[8] = 178; // SYS_gettid
    loaded_call_on_slot(
        fixture,
        tasks,
        SlotId::new(1),
        target_page,
        sib1_control,
        &mut sib_service,
        &counters,
        &mut gettid,
        &mut sibling_cpu,
    )
    .unwrap();
    assert_eq!(gettid.x[0] as i64, sib1_tid);

    // Now P_target (with 2 live threads on slots 0 & 1, plus live peer P_peer on
    // slot 2) clones a 3rd thread `born` on slot 0 and holds it BEFORE first entry.
    let stack2 = carrick_test_support::GuestUserBuffer::zeroed(8192);
    let ptid2 = carrick_test_support::GuestUserBuffer::from_value(0u32);
    let ctid2 = carrick_test_support::GuestUserBuffer::from_value(0xffffu32);
    let mut clone2 = carrick_el1_abi::TrapFrame::default();
    clone2.x[8] = 220;
    clone2.x[..5].copy_from_slice(&[
        TGKILL_AFTER_CLONE_FLAGS,
        stack2.arg() + 8192,
        ptid2.arg(),
        0,
        ctid2.arg(),
    ]);
    loaded_call_on_slot(
        fixture,
        tasks,
        SlotId::new(0),
        target_page,
        leader_control,
        &mut leader_service,
        &counters,
        &mut clone2,
        &mut leader_cpu,
    )
    .unwrap();
    let born_tid = clone2.x[0] as i64;
    assert!(born_tid > sib1_tid, "born clone rc={born_tid}");
    assert_eq!(ptid2.get::<u32>(0), born_tid as u32);
    let born_record = fixture
        .zone
        .runnable_head(SlotId::new(0))
        .expect("born thread is queued on slot 0 and has never been selected");
    let born_control = unsafe {
        &*(fixture.zone.record(born_record).identity().control_slot as *const ThreadControlSlot)
    };
    assert_eq!(
        counters.lifecycle_declines[carrick_el1_abi::LifecycleDecline::ClonePoolEmpty as usize]
            .load(Ordering::Relaxed),
        0
    );

    NativeOwnedTwoThreadHarness {
        fixture,
        tasks,
        crossing,
        peer_pid,
        peer_page,
        peer_control,
        peer_cpu,
        target_pid,
        target_page,
        leader_control,
        leader_cpu,
        sibling_control: sib1_control,
        sibling_cpu,
        born_record,
        born_tid: born_tid as u32,
        born_control,
    }
}

/// #1974 / #2030 control (birth kind a1, `tgkill` half): when a process WITH
/// native `thread_stock` (every native `fork` child on ARM) has two live threads
/// and clones a third, `#2030`'s `enqueue_born -> venue.enqueue_thread` both
/// registers the member AND transitions its zone record to `Claim::Queued`
/// before `clone` returns. An immediate `tgkill(tgid, born_tid, SIGUSR1)`
/// before `born`'s first entry returns 0 and queues `SIGUSR1` once on `born`.
#[test]
fn arm_native_owned_ring_born_tgkill_before_first_entry_queues_signal_once() {
    let mut h = setup_native_owned_ring_birth_before_first_entry();
    assert_ne!(h.peer_pid, h.target_pid);
    let words = Box::leak(Box::new(h.fixture.tables.live(&h.fixture.maintenance)));
    let counters = carrick_el1_abi::Counters::new();
    let mut leader_service = Aarch64NativeProcessService::with_crossing(
        &h.tasks[0],
        SlotId::new(0),
        h.fixture.zone,
        h.fixture.region.table(),
        NonZeroU64::MIN,
        h.crossing,
    )
    .with_words(words);

    let mut tgkill = carrick_el1_abi::TrapFrame::default();
    tgkill.x[8] = 131; // SYS_tgkill
    tgkill.x[0] = u64::from(h.target_pid);
    tgkill.x[1] = u64::from(h.born_tid);
    tgkill.x[2] = LINUX_SIGUSR1;
    loaded_call_on_slot(
        h.fixture,
        h.tasks,
        SlotId::new(0),
        h.target_page,
        h.leader_control,
        &mut leader_service,
        &counters,
        &mut tgkill,
        &mut h.leader_cpu,
    )
    .unwrap();
    assert_eq!(
        tgkill.x[0] as i64, 0,
        "native-owned ring-born tgkill before first entry must return 0"
    );

    // Neither live sibling in P_target holds SIGUSR1.
    assert_eq!(
        poll_signal_once_on_slot(
            h.fixture,
            h.tasks,
            SlotId::new(0),
            h.target_page,
            h.leader_control,
            &mut leader_service,
            &mut h.leader_cpu,
            LINUX_SIGUSR1,
        ),
        -11
    );
    let mut sib_service = Aarch64NativeProcessService::with_crossing(
        &h.tasks[1],
        SlotId::new(1),
        h.fixture.zone,
        h.fixture.region.table(),
        NonZeroU64::MIN,
        h.crossing,
    )
    .with_words(words);
    assert_eq!(
        poll_signal_once_on_slot(
            h.fixture,
            h.tasks,
            SlotId::new(1),
            h.target_page,
            h.sibling_control,
            &mut sib_service,
            &mut h.sibling_cpu,
            LINUX_SIGUSR1,
        ),
        -11
    );

    // Switch `born` in on slot 3 for its very first entry: SIGUSR1 is pending
    // once and a second non-blocking poll returns EAGAIN (-11).
    init_guest_slot(h.fixture, SlotId::new(3));
    let mut born_cpu = crate::sched::FakeCpu::default();
    let mut dummy = carrick_el1_abi::TrapFrame::default();
    assert_eq!(
        switch_in_slot(
            h.fixture,
            SlotId::new(3),
            &h.tasks[3],
            &mut born_cpu,
            &mut dummy
        ),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(
        h.fixture.zone.slot(SlotId::new(3)).current(),
        Some(h.born_record)
    );
    let mut born_service = Aarch64NativeProcessService::with_crossing(
        &h.tasks[3],
        SlotId::new(3),
        h.fixture.zone,
        h.fixture.region.table(),
        NonZeroU64::MIN,
        h.crossing,
    )
    .with_words(words);
    assert_eq!(
        poll_signal_once_on_slot(
            h.fixture,
            h.tasks,
            SlotId::new(3),
            h.target_page,
            h.born_control,
            &mut born_service,
            &mut born_cpu,
            LINUX_SIGUSR1,
        ),
        LINUX_SIGUSR1 as i64,
        "SIGUSR1 must be pending on the born thread at its first entry"
    );
    assert_eq!(
        poll_signal_once_on_slot(
            h.fixture,
            h.tasks,
            SlotId::new(3),
            h.target_page,
            h.born_control,
            &mut born_service,
            &mut born_cpu,
            LINUX_SIGUSR1,
        ),
        -11,
        "SIGUSR1 must be queued once on the born thread"
    );
}

/// #1974 red witness (birth kind a1, peer `kill(tid, SIGUSR2)` half): even when
/// `#2030` registers a native-owned ring birth before first entry so `tgkill`
/// returns 0, the second live process `P_peer` calling `kill(born_tid, SIGUSR2)`
/// before first entry STILL fails with `-3` (`ESRCH`) on `main` (`e7883869a2`)
/// because `NativeProcessEntry::kill` matches only `namespace_pid == target_pid`.
/// In `tgkill_after_clone` that leaves `HANDLED2` timing out `16 * 10s = 160s > 120s`
/// even when `#2016` gives the ARM root native thread stock without `#1994`.
#[test]
fn arm_native_owned_ring_born_peer_kill_before_first_entry() {
    let mut h = setup_native_owned_ring_birth_before_first_entry();
    let words = Box::leak(Box::new(h.fixture.tables.live(&h.fixture.maintenance)));
    let counters = carrick_el1_abi::Counters::new();
    let mut leader_service = Aarch64NativeProcessService::with_crossing(
        &h.tasks[0],
        SlotId::new(0),
        h.fixture.zone,
        h.fixture.region.table(),
        NonZeroU64::MIN,
        h.crossing,
    )
    .with_words(words);
    let mut tgkill = carrick_el1_abi::TrapFrame::default();
    tgkill.x[8] = 131; // SYS_tgkill
    tgkill.x[0] = u64::from(h.target_pid);
    tgkill.x[1] = u64::from(h.born_tid);
    tgkill.x[2] = LINUX_SIGUSR1;
    loaded_call_on_slot(
        h.fixture,
        h.tasks,
        SlotId::new(0),
        h.target_page,
        h.leader_control,
        &mut leader_service,
        &counters,
        &mut tgkill,
        &mut h.leader_cpu,
    )
    .unwrap();
    assert_eq!(tgkill.x[0] as i64, 0);

    // Live peer process P_peer on slot 2 sends `kill(born_tid, SIGUSR2)` before
    // `born` has ever entered.
    let mut peer_service = Aarch64NativeProcessService::with_crossing(
        &h.tasks[2],
        SlotId::new(2),
        h.fixture.zone,
        h.fixture.region.table(),
        NonZeroU64::MIN,
        h.crossing,
    )
    .with_words(words);
    let mut peer_kill = carrick_el1_abi::TrapFrame::default();
    peer_kill.x[8] = 129; // SYS_kill
    peer_kill.x[0] = u64::from(h.born_tid);
    peer_kill.x[1] = LINUX_SIGUSR2;
    loaded_call_on_slot(
        h.fixture,
        h.tasks,
        SlotId::new(2),
        h.peer_page,
        h.peer_control,
        &mut peer_service,
        &counters,
        &mut peer_kill,
        &mut h.peer_cpu,
    )
    .unwrap();
    assert_eq!(
        peer_kill.x[0] as i64, 0,
        "peer kill(born_tid, SIGUSR2) before first entry must return 0"
    );
}

/// Stock one host-supplied ring pool entry on the ARM root's `ThreadLifecyclePage`,
/// matching how `ThreadLedger` primes the pool after round 0 of `tgkill_after_clone`.
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
    let entry = fixture
        .page
        .stock(
            0,
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

/// Set up the exact `tgkill_after_clone` topology where the **ARM root** (`P_root`,
/// PID 41, `thread_stock: None` on `main`) has forked a live peer process `P_peer`
/// (running on slot 2) AND already has a second live entered sibling thread
/// (running on slot 1). Slot 0 runs `P_root`'s leader.
#[allow(clippy::type_complexity)]
fn setup_arm_root_two_live_threads_and_peer() -> (
    &'static Fixture,
    &'static [CurrentTask; 4],
    &'static TestStockCrossing,
    crate::sched::FakeCpu,
    &'static ThreadControlSlot,
    crate::sched::FakeCpu,
    &'static ThreadControlSlot,
    &'static ThreadLifecyclePage,
    crate::sched::FakeCpu,
) {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    fixture.zone.spaces.set_idle_ttbr(0x30000);
    let tasks: &'static [CurrentTask; 4] =
        Box::leak(Box::new(core::array::from_fn(|_| CurrentTask::new())));
    let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
    let stock_pages: Vec<u64> = (0..24).map(|i| 0x20000 + i * 0x1000).collect();
    let crossing: &'static TestStockCrossing =
        Box::leak(Box::new(TestStockCrossing::new(&stock_pages)));

    // Admit ARM root on slot 0 and fork P_peer (as `two_process` does in `threads.rs:190`).
    let root_record = fixture
        .zone
        .current_or_new(SlotId::new(0), fixture.leader)
        .unwrap();
    fixture
        .control
        .bind_zone_record(fixture.zone.record_ref(root_record));
    unsafe {
        *fixture.zone.record(root_record).ctx_mut() =
            Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    }
    let mut boot_service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        SlotId::new(0),
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        crossing,
    )
    .with_words(words);
    let mut root_cpu = crate::sched::FakeCpu {
        ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
        ..Default::default()
    };
    let mut fork_frame = carrick_el1_abi::TrapFrame::default();
    fork_frame.x[8] = 220;
    fork_frame.x[0] = 17;
    arm_call_with_cpu(
        fixture,
        fixture.control,
        &mut boot_service,
        &mut fork_frame,
        &mut root_cpu,
    )
    .unwrap();
    let peer_pid = fork_frame.x[0] as i64;
    assert!(peer_pid > 41, "fork peer rc={peer_pid}");
    let peer_record = fixture.zone.runnable_head(SlotId::new(0)).unwrap();
    let peer_identity = fixture.zone.record(peer_record).identity();
    let peer_page = unsafe { &*(peer_identity.lifecycle_page as *const ThreadLifecyclePage) };
    let peer_control = unsafe { &*(peer_identity.control_slot as *const ThreadControlSlot) };

    // Copy root's task state onto tasks[0] so `loaded_call_on_slot` drives slot 0 cleanly.
    tasks[0].set(
        El1TaskId::from_linux_tid(fixture.leader.tid as i32),
        carrick_el1_abi::SnapshotGeneration::from_raw(fixture.leader.generation),
        fixture.leader.file_table,
    );
    tasks[0].mm.key.store(fixture.leader.mm, Ordering::Release);
    tasks[0]
        .mm
        .thread_generation
        .store(fixture.leader.serial, Ordering::Release);
    tasks[0].publish_visible_pid(41);
    tasks[0].publish_root_generation(fixture.address.generation);
    tasks[0].publish_lifecycle(
        fixture.page as *const _ as u64,
        fixture.control as *const _ as u64,
    );

    // Switch live peer process P_peer onto slot 2.
    init_guest_slot(fixture, SlotId::new(2));
    let mut peer_cpu = crate::sched::FakeCpu::default();
    let mut dummy = carrick_el1_abi::TrapFrame::default();
    assert_eq!(
        switch_in_slot(
            fixture,
            SlotId::new(2),
            &tasks[2],
            &mut peer_cpu,
            &mut dummy
        ),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(
        fixture.zone.slot(SlotId::new(2)).current(),
        Some(peer_record)
    );

    // Bring up a second live entered thread of P_root (TID 43) on slot 1 via
    // its real first syscall entry (`register_thread` during `SYS_gettid`).
    let sib_control = host_born_sibling(fixture, 43);
    run_as_leader(fixture);
    let sib_identity = sib_control.host_birth_identity().unwrap();
    tasks[1].set(
        El1TaskId::from_linux_tid(sib_identity.task().raw() as i32),
        carrick_el1_abi::SnapshotGeneration::from_raw(sib_identity.birth().raw()),
        fixture.leader.file_table,
    );
    tasks[1].mm.key.store(fixture.leader.mm, Ordering::Release);
    tasks[1]
        .mm
        .thread_generation
        .store(sib_identity.thread().raw(), Ordering::Release);
    tasks[1].publish_visible_pid(41);
    tasks[1].publish_root_generation(fixture.address.generation);
    tasks[1].publish_lifecycle(
        fixture.page as *const _ as u64,
        sib_control as *const _ as u64,
    );
    init_guest_slot(fixture, SlotId::new(1));
    fixture.zone.publish_slot(SlotId::new(1), 1, Some(0), 1);
    fixture.zone.install_space(SlotId::new(1), 1).unwrap();
    let sib_record = fixture
        .zone
        .current_or_new(
            SlotId::new(1),
            ThreadIdentity {
                tid: sib_identity.task().raw(),
                serial: sib_identity.thread().raw(),
                mm: fixture.leader.mm,
                file_table: fixture.leader.file_table,
                generation: sib_identity.birth().raw(),
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 1,
                lifecycle_page: fixture.page as *const _ as u64,
                control_slot: sib_control as *const _ as u64,
            },
        )
        .unwrap();
    sib_control.bind_zone_record(fixture.zone.record_ref(sib_record));
    let mut sib_cpu = crate::sched::FakeCpu {
        ttbr: (fixture_ttbr0(fixture), fixture_ttbr0(fixture)),
        ..Default::default()
    };
    let mut sib_service = Aarch64NativeProcessService::with_crossing(
        &tasks[1],
        SlotId::new(1),
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        crossing,
    )
    .with_words(words);
    let counters = carrick_el1_abi::Counters::new();
    let mut gettid = carrick_el1_abi::TrapFrame::default();
    gettid.x[8] = 178; // SYS_gettid adopts the sibling into P_root's native owner
    loaded_call_on_slot(
        fixture,
        tasks,
        SlotId::new(1),
        fixture.page,
        sib_control,
        &mut sib_service,
        &counters,
        &mut gettid,
        &mut sib_cpu,
    )
    .unwrap();
    assert_eq!(gettid.x[0] as i64, 43);

    // Install SIGUSR1 and SIGUSR2 handlers on P_root (as `tgkill_after_clone` does).
    let mut root_service = Aarch64NativeProcessService::with_crossing(
        &tasks[0],
        SlotId::new(0),
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        crossing,
    )
    .with_words(words);
    install_noop_handler_on_slot(
        fixture,
        tasks,
        SlotId::new(0),
        fixture.page,
        fixture.control,
        &mut root_service,
        &mut root_cpu,
        LINUX_SIGUSR1,
    );
    install_noop_handler_on_slot(
        fixture,
        tasks,
        SlotId::new(0),
        fixture.page,
        fixture.control,
        &mut root_service,
        &mut root_cpu,
        LINUX_SIGUSR2,
    );

    (
        fixture,
        tasks,
        crossing,
        root_cpu,
        sib_control,
        sib_cpu,
        peer_control,
        peer_page,
        peer_cpu,
    )
}

/// #1974 red witness (birth kind a2 — ARM root unmanaged ring-born, rounds 1..15
/// of `tgkill_after_clone`): `tgkill_after_clone` runs its `clone` loop in the
/// ARM root (`parent`), which on `main` (`e7883869a2`) has `thread_stock: None`.
/// `#2030` gated `venue.enqueue_thread` on `retained.has_native_execution_owner()`,
/// which is `false` without `thread_stock`, so `enqueue_born` bypasses
/// `register_native_birth` and leaves `child_slot.zone_record() == None`.
/// Both `tgkill(tgid, born_tid, SIGUSR1)` and peer `kill(born_tid, SIGUSR2)`
/// before first entry fail with `-3` (`ESRCH`).
#[test]
fn arm_root_ring_born_tgkill_and_peer_kill_before_first_entry() {
    let (
        fixture,
        tasks,
        crossing,
        mut root_cpu,
        _sib_control,
        _sib_cpu,
        peer_control,
        peer_page,
        mut peer_cpu,
    ) = setup_arm_root_two_live_threads_and_peer();
    let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
    let born_control = stock_arm_root_pool_identity(fixture, 44, 1);

    let counters = carrick_el1_abi::Counters::new();
    let mut root_service = Aarch64NativeProcessService::with_crossing(
        &tasks[0],
        SlotId::new(0),
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        crossing,
    )
    .with_words(words);
    let stack = carrick_test_support::GuestUserBuffer::zeroed(8192);
    let ptid = carrick_test_support::GuestUserBuffer::from_value(0u32);
    let ctid = carrick_test_support::GuestUserBuffer::from_value(0xffffu32);
    let mut clone = carrick_el1_abi::TrapFrame::default();
    clone.x[8] = 220;
    clone.x[..5].copy_from_slice(&[
        TGKILL_AFTER_CLONE_FLAGS,
        stack.arg() + 8192,
        ptid.arg(),
        0,
        ctid.arg(),
    ]);
    loaded_call_on_slot(
        fixture,
        tasks,
        SlotId::new(0),
        fixture.page,
        fixture.control,
        &mut root_service,
        &counters,
        &mut clone,
        &mut root_cpu,
    )
    .unwrap();
    assert_eq!(clone.x[0] as i64, 44, "clone served in ring on ARM root");
    assert_eq!(ptid.get::<u32>(0), 44);
    assert_eq!(
        counters.lifecycle_declines[carrick_el1_abi::LifecycleDecline::ClonePoolEmpty as usize]
            .load(Ordering::Relaxed),
        0,
        "round 1+ ring-born clone has zero ClonePoolEmpty declines"
    );
    assert_eq!(
        born_control.zone_record(),
        None,
        "#2030 bypassed ARM root ring birth: control has no bound zone_record"
    );

    let mut tgkill = carrick_el1_abi::TrapFrame::default();
    tgkill.x[8] = 131; // SYS_tgkill
    tgkill.x[0] = 41;
    tgkill.x[1] = 44;
    tgkill.x[2] = LINUX_SIGUSR1;
    loaded_call_on_slot(
        fixture,
        tasks,
        SlotId::new(0),
        fixture.page,
        fixture.control,
        &mut root_service,
        &counters,
        &mut tgkill,
        &mut root_cpu,
    )
    .unwrap();
    let tgkill_rc = tgkill.x[0] as i64;

    let mut peer_service = Aarch64NativeProcessService::with_crossing(
        &tasks[2],
        SlotId::new(2),
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        crossing,
    )
    .with_words(words);
    let mut peer_kill = carrick_el1_abi::TrapFrame::default();
    peer_kill.x[8] = 129; // SYS_kill
    peer_kill.x[0] = 44;
    peer_kill.x[1] = LINUX_SIGUSR2;
    loaded_call_on_slot(
        fixture,
        tasks,
        SlotId::new(2),
        peer_page,
        peer_control,
        &mut peer_service,
        &counters,
        &mut peer_kill,
        &mut peer_cpu,
    )
    .unwrap();
    let peer_kill_rc = peer_kill.x[0] as i64;

    assert_eq!(
        (tgkill_rc, peer_kill_rc),
        (0, 0),
        "ARM root ring-born thread before first entry must accept both tgkill and peer kill(tid)"
    );
}

/// #1974 red witness (birth kind b — host-issued `ClonePoolEmpty` decline,
/// round 0 of `tgkill_after_clone`): with two live threads in `P_root` plus
/// live peer process `P_peer` and an empty ring pool, `SYS_clone` declines
/// with `ClonePoolEmpty` (`CompletionRoute::Forward`) and the host issues the
/// child (`HostBornMember` state 2). Before the child's first entry runs
/// `register_thread`, both `tgkill(41, 44, SIGUSR1)` and peer `kill(44, SIGUSR2)`
/// fail with `-3` (`ESRCH`) on `main` (`e7883869a2`).
#[test]
fn arm_host_issued_clone_pool_empty_tgkill_and_peer_kill_before_first_entry() {
    let (
        fixture,
        tasks,
        crossing,
        mut root_cpu,
        _sib_control,
        _sib_cpu,
        peer_control,
        peer_page,
        mut peer_cpu,
    ) = setup_arm_root_two_live_threads_and_peer();
    let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));

    let counters = carrick_el1_abi::Counters::new();
    let mut root_service = Aarch64NativeProcessService::with_crossing(
        &tasks[0],
        SlotId::new(0),
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        crossing,
    )
    .with_words(words);
    let stack = carrick_test_support::GuestUserBuffer::zeroed(8192);
    let ptid = carrick_test_support::GuestUserBuffer::from_value(0u32);
    let ctid = carrick_test_support::GuestUserBuffer::from_value(0xffffu32);
    let mut clone = carrick_el1_abi::TrapFrame::default();
    clone.x[8] = 220;
    clone.x[..5].copy_from_slice(&[
        TGKILL_AFTER_CLONE_FLAGS,
        stack.arg() + 8192,
        ptid.arg(),
        0,
        ctid.arg(),
    ]);
    let route = loaded_call_on_slot(
        fixture,
        tasks,
        SlotId::new(0),
        fixture.page,
        fixture.control,
        &mut root_service,
        &counters,
        &mut clone,
        &mut root_cpu,
    )
    .unwrap();
    assert_eq!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Forward,
        "empty ring pool must decline clone to the host"
    );
    assert_eq!(
        counters.lifecycle_declines[carrick_el1_abi::LifecycleDecline::ClonePoolEmpty as usize]
            .load(Ordering::Relaxed),
        1
    );

    // Host completes the forwarded clone, publishing a HostBornMember (visible TID 44),
    // and returns 44 to the cloning parent before the child's first entry.
    let _host_child_control = host_born_sibling(fixture, 44);
    run_as_leader(fixture);

    let mut tgkill = carrick_el1_abi::TrapFrame::default();
    tgkill.x[8] = 131; // SYS_tgkill
    tgkill.x[0] = 41;
    tgkill.x[1] = 44;
    tgkill.x[2] = LINUX_SIGUSR1;
    loaded_call_on_slot(
        fixture,
        tasks,
        SlotId::new(0),
        fixture.page,
        fixture.control,
        &mut root_service,
        &counters,
        &mut tgkill,
        &mut root_cpu,
    )
    .unwrap();
    let tgkill_rc = tgkill.x[0] as i64;

    let mut peer_service = Aarch64NativeProcessService::with_crossing(
        &tasks[2],
        SlotId::new(2),
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        crossing,
    )
    .with_words(words);
    let mut peer_kill = carrick_el1_abi::TrapFrame::default();
    peer_kill.x[8] = 129; // SYS_kill
    peer_kill.x[0] = 44;
    peer_kill.x[1] = LINUX_SIGUSR2;
    loaded_call_on_slot(
        fixture,
        tasks,
        SlotId::new(2),
        peer_page,
        peer_control,
        &mut peer_service,
        &counters,
        &mut peer_kill,
        &mut peer_cpu,
    )
    .unwrap();
    let peer_kill_rc = peer_kill.x[0] as i64;

    assert_eq!(
        (tgkill_rc, peer_kill_rc),
        (0, 0),
        "host-issued ClonePoolEmpty thread before first entry must accept both tgkill and peer kill(tid)"
    );
}

/// Reviewer's `Claim::Free` hazard check on `#2030`: during `serve_clone`
/// (`crates/carrick-personality-linux/src/lifecycle.rs:1405-1485`), `outputs.publish`
/// writes `PTID` to shared user memory while the allocated birth record is still
/// `Claim::Free` (before `enqueue_born -> enqueue_thread -> requeue_preempted`).
/// Even though `retain_native_birth` bound `child_slot.zone_record()` and
/// `page.publish` set `EntryState::Born`, both `signal_record_exists`
/// (`native_process_runtime.rs:149-159`) and `zone.live(record)` (`3366`) reject
/// `Claim::Free`, so a live sibling reading `PTID` and calling `tgkill` before
/// `requeue_preempted` gets `-3` (`ESRCH`).
#[test]
fn arm_mid_clone_claim_free_birth_before_requeue_fails_sibling_tgkill() {
    use carrick_el1_abi::Lifecycle;
    let mut h = setup_native_owned_ring_birth_before_first_entry();
    let words = Box::leak(Box::new(h.fixture.tables.live(&h.fixture.maintenance)));
    let mut leader_service = Aarch64NativeProcessService::with_crossing(
        &h.tasks[0],
        SlotId::new(0),
        h.fixture.zone,
        h.fixture.region.table(),
        NonZeroU64::MIN,
        h.crossing,
    )
    .with_words(words);

    // Advance through the exact `serve_clone` steps up to `publish`, stopping
    // right before `enqueue_born` (`requeue_preempted`), so the birth is published
    // (`EntryState::Born`, `PTID` visible) while its record is still `Claim::Free`.
    let claim_free_tid = with_process_entry(
        BornInZoneSource {
            zone: h.fixture.zone,
            slot: SlotId::new(0),
        },
        &h.tasks[0],
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
            let claimed = h
                .target_page
                .claim_any()
                .expect("native stock entry available");
            let entry = claimed.entry();
            let identity = h.target_page.identity(entry).unwrap();
            let address = h.target_page.control_address(entry).unwrap();
            let child_slot = unsafe { &*(address as *const ThreadControlSlot) };
            let _ = child_slot.publish_visible_tid(identity.visible_tid);
            let record_id = h
                .fixture
                .zone
                .alloc_record(ThreadIdentity {
                    tid: u64::from(identity.tid),
                    serial: identity.thread_serial,
                    mm: h.fixture.zone.record(h.born_record).identity().mm,
                    file_table: 0,
                    generation: 0,
                    affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                    affinity: 1,
                    lifecycle_page: h.target_page as *const _ as u64,
                    control_slot: address,
                })
                .unwrap();
            let record = h.fixture.zone.record_ref(record_id);
            child_slot
                .reset_for_birth(carrick_el1_abi::BlockedMask(0), 0, entry)
                .unwrap();
            process.bind_thread_birth(record, child_slot).unwrap();
            assert!(h.fixture.zone.issue_native_birth(record_id));
            Lifecycle::thread_born(h.target_page).unwrap();
            h.target_page
                .record_born(
                    claimed,
                    carrick_el1_abi::BornRecord {
                        caller_task: 0,
                        caller_serial: 0,
                        clone_flags: TGKILL_AFTER_CLONE_FLAGS,
                        clear_child_tid: 0,
                        blocked: carrick_el1_abi::BlockedMask(0),
                    },
                )
                .unwrap();
            assert_eq!(
                h.fixture.zone.record(record_id).claim(),
                carrick_sched_core::Claim::Free
            );
            identity.visible_tid
        },
    )
    .unwrap();

    // Sibling on slot 1 observes `claim_free_tid` (published via `PTID` before
    // `enqueue_born`) and immediately calls `SYS_tgkill(target_pid, claim_free_tid, SIGUSR1)`.
    let counters = carrick_el1_abi::Counters::new();
    let mut sib_service = Aarch64NativeProcessService::with_crossing(
        &h.tasks[1],
        SlotId::new(1),
        h.fixture.zone,
        h.fixture.region.table(),
        NonZeroU64::MIN,
        h.crossing,
    )
    .with_words(words);
    let mut tgkill = carrick_el1_abi::TrapFrame::default();
    tgkill.x[8] = 131; // SYS_tgkill
    tgkill.x[0] = u64::from(h.target_pid);
    tgkill.x[1] = u64::from(claim_free_tid);
    tgkill.x[2] = LINUX_SIGUSR1;
    loaded_call_on_slot(
        h.fixture,
        h.tasks,
        SlotId::new(1),
        h.target_page,
        h.sibling_control,
        &mut sib_service,
        &counters,
        &mut tgkill,
        &mut h.sibling_cpu,
    )
    .unwrap();
    assert_eq!(
        tgkill.x[0] as i64, 0,
        "sibling tgkill during pre-requeue Claim::Free window must resolve"
    );
}
