//! #2620 part A: ARM production-entry witnesses for a fork+exec child polling a
//! host socket across ~20 rounds before `_exit(7)` while its parent waits in
//! `wait4(-1)`.
//!
//! When a host-file `ppoll` resumes from `ObjectWaitKey::native_host_ready` on
//! an idle ARM vCPU (`!native_service_doorbell()`), `continue_host_file`
//! republishes the record via `publish_pending_host_file` and parks with
//! `NativeResume::Left(None)`. Without marking pending host work, `Sched::idle`
//! enters `wait_for_interrupt` with `CurrentTask.service_notice` stranded on
//! slot 0 and the parent's `wait4(-1)` hangs.

use super::*;
use crate::native_process_runtime::{NativeResume, NativeServiceCall};
use crate::sched::LinuxSchedEntry;
use carrick_core_abi::service::{
    ExecAdoptionReceipt, ExecSuccessorBacking, ExecSuccessorEntry, ExecSuccessorManifest,
    ServiceCell, ServiceOperation,
};
use carrick_kernel::el1_ipc::HostTable;
use carrick_sched_core::{ShortLockSpin, WakeEffects};
use std::net::UdpSocket;
use std::time::{Duration, Instant};

const POLL_ROUNDS: usize = 20;
const CHILD_EXIT_CODE: u8 = 7;

#[test]
fn serial_host_arm_fork_exec_child_polls_never_ready_host_socket_twenty_rounds() {
    run_arm_fork_exec_child_socket_poll(false);
}

#[test]
fn serial_host_arm_fork_exec_child_polls_ready_host_socket_twenty_rounds() {
    run_arm_fork_exec_child_socket_poll(true);
}

struct RestoreRegion(usize);
impl Drop for RestoreRegion {
    fn drop(&mut self) {
        carrick_el1_abi::record_el1_region_host_ptr(self.0);
    }
}

struct RestoreGuestSched;
impl Drop for RestoreGuestSched {
    fn drop(&mut self) {
        carrick_kernel::el1_zone::enable(false);
    }
}

struct UnregisterRoot {
    runtime: Arc<NativeProcessRuntime<'static, AddressContext<RootGpa>, Aarch64ParkedContext>>,
}
impl Drop for UnregisterRoot {
    fn drop(&mut self) {
        registry().unregister_root_for_test(&self.runtime);
    }
}

fn wfi_kick_bell() -> &'static (std::sync::Mutex<u64>, std::sync::Condvar) {
    type Bell = (std::sync::Mutex<u64>, std::sync::Condvar);
    static BELL: std::sync::OnceLock<Bell> = std::sync::OnceLock::new();
    // The test binary's kicker, registered for the rest of the process.
    static KICKER: std::sync::OnceLock<carrick_kernel::el1_zone::SlotKickerRegistration> =
        std::sync::OnceLock::new();
    let bell = BELL.get_or_init(|| (std::sync::Mutex::new(0u64), std::sync::Condvar::new()));
    KICKER.get_or_init(|| {
        carrick_kernel::el1_zone::register_slot_kicker(Box::new(|_| {
            if let Some((lock, cvar)) = BELL.get() {
                let mut epoch = lock.lock().unwrap();
                *epoch = epoch.wrapping_add(1);
                cvar.notify_all();
            }
        }))
    });
    bell
}

struct ArmWfiCpu<'a> {
    inner: crate::sched::FakeCpu,
    fixture: &'static Fixture,
    service: &'a mut Aarch64NativeProcessService<'static, &'static TestStockCrossing>,
    on_wfi: &'a mut Option<Box<dyn FnOnce()>>,
    deadline: Instant,
    timed_out_in_wfi: bool,
}

impl crate::sched::ThreadCpu for ArmWfiCpu<'_> {
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
        _: &ZoneTables<Aarch64ParkedContext>,
        _: &CurrentTask,
        _: SlotId,
        record: RecordId,
    ) -> crate::sched::ResumeAction {
        crate::aarch64_process::resume_production_with_service(
            self.fixture.zone,
            &self.fixture.task,
            self.fixture.slot,
            record,
            self.service,
        )
    }

    fn set_translation(&mut self, ttbr0: u64, ttbr1: u64) {
        self.inner.set_translation(ttbr0, ttbr1);
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

    fn send_sgi(&mut self, target: u64) {
        self.inner.send_sgi(target);
    }

    fn ack_irq(&mut self) -> u32 {
        self.inner.ack_irq()
    }

    fn end_irq(&mut self, intid: u32) {
        self.inner.end_irq(intid);
    }

    fn wait_for_interrupt(&mut self) {
        self.inner.wfis += 1;
        if !self.inner.pending.is_empty() {
            return;
        }
        if let Some(cval) = self.inner.timer {
            self.inner.now = self.inner.now.max(cval);
            return;
        }
        if let Some(trigger) = self.on_wfi.take() {
            trigger();
        }
        let (lock, cvar) = wfi_kick_bell();
        let mut guard = lock.lock().unwrap();
        while !self.fixture.task.linux.has_pending_host_work()
            && self.fixture.zone.slot(self.fixture.slot).queued() == 0
            && !self.fixture.zone.head_needs_host(self.fixture.slot)
        {
            let Some(remaining) = self.deadline.checked_duration_since(Instant::now()) else {
                self.timed_out_in_wfi = true;
                // Force Sched::idle to unwind cleanly so the assertion below
                // reports the exact stranded service_notice state.
                self.fixture.task.linux.mark_pending_host_work();
                return;
            };
            let (next_guard, _) = cvar.wait_timeout(guard, remaining).unwrap();
            guard = next_guard;
        }
    }

    fn spin(&mut self) {
        self.inner.spin();
    }

    fn own_sgi_target(&self) -> u64 {
        self.inner.own_sgi_target()
    }
}

struct ResidentUser;
impl crate::file::MemoryValidator for ResidentUser {
    fn readable_bytes(&self, address: u64, len: usize) -> usize {
        crate::file::HardwareValidator.readable_bytes(address, len)
    }
    fn writable_bytes(&self, address: u64, len: usize) -> usize {
        crate::file::HardwareValidator.writable_bytes(address, len)
    }
}

struct TaskLifecycleVenue;
impl crate::lifecycle::LifecycleVenue for TaskLifecycleVenue {
    fn thread<'a>(
        &'a self,
        task: &'a CurrentTask,
    ) -> Option<crate::lifecycle::LifecycleThread<'a>> {
        let (page, slot) = task.lifecycle_refs()?;
        Some(crate::lifecycle::LifecycleThread { page, slot })
    }
    fn born_slot(
        &self,
        _page: &ThreadLifecyclePage,
        _entry: carrick_el1_abi::EntryRef,
    ) -> Option<&ThreadControlSlot> {
        None
    }
}

fn run_arm_fork_exec_child_socket_poll(become_ready: bool) {
    let start = Instant::now();
    let deadline = start + Duration::from_secs(2);

    let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::new();
    let launch_root = dispatcher.capture_one_task_context().unwrap();
    let installed = carrick_kernel::dispatch::exec_files::native_exec_capability(&launch_root);
    let kernel = Arc::clone(launch_root.kernel());
    let owner: &'static _ = Box::leak(Box::new(kernel.ipc().unwrap()));
    let wait_service = carrick_kernel::kernel::continuation::CarrierWaitService::new(Arc::new(
        carrick_kernel::kernel::Scheduler::new(Arc::clone(&kernel)),
    ));
    wait_service.serve_host_readiness();

    let task_serial = launch_root.task().key().serial.raw();
    let root_file_table = launch_root.resources().files().id().raw();
    let page = Box::leak(Box::new(ThreadLifecyclePage::new()));
    let control = Box::leak(Box::new(ThreadControlSlot::new()));
    let fixture = Box::leak(Box::new(Fixture::with_identity(
        0x10000,
        asid(1),
        page,
        control,
        ThreadIdentity {
            tid: 41,
            serial: 101,
            mm: 1,
            file_table: root_file_table,
            generation: task_serial,
            affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
            affinity: 1,
            lifecycle_page: page as *const _ as u64,
            control_slot: control as *const _ as u64,
        },
    )));
    let metadata_scope = MetadataScope::new(fixture);
    let _restore_region = RestoreRegion(carrick_el1_abi::get_el1_region_host_ptr());
    carrick_el1_abi::record_el1_region_host_ptr(fixture.region.ptr.as_ptr() as usize);
    let _restore_sched = RestoreGuestSched;
    carrick_kernel::el1_zone::enable(true);
    fixture.zone.spaces.set_idle_ttbr(0x9000);
    fixture
        .zone
        .bind_ipc_operation_slots(
            owner.region().operation_slot_generation(),
            &ShortLockSpin,
            &|owned| {
                let _ = owned.into_parts();
            },
        )
        .unwrap();
    let root_table = Arc::new(HostTable::create(owner.clone(), 64, 64).unwrap());
    let map = carrick_el1_abi::ipc_table_map_host().unwrap();
    map.publish(root_file_table, root_table.id().to_raw())
        .unwrap();

    let counters: &'static _ = Box::leak(Box::new(carrick_el1_abi::Counters::new()));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let parked = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    let pages: Vec<_> = (0..64).map(|n| 0x20000 + n * 0x1000).collect();
    let mut crossing = TestStockCrossing::new(&pages);
    crossing.metadata_in_el1_window = true;
    crossing.metadata_allocations = Arc::clone(&metadata_scope.allocations);
    crossing.ipc = Some((owner.clone(), map));
    crossing.installed_exec_capability = Some(installed);
    *crossing.root_cwd.lock().unwrap() = b"/tmp".to_vec();
    let crossing: &'static TestStockCrossing = Box::leak(Box::new(crossing));
    let words: &'static _ = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));

    let runtime = Arc::new(
        NativeProcessRuntime::admit_fresh_root::<Aarch64Mmu>(
            source,
            &fixture.task,
            fixture.page,
            fixture.control,
            fixture.address,
            fixture.address,
            parked,
        )
        .unwrap(),
    );
    registry()
        .register_root(runtime.clone(), source, &fixture.task, fixture.address)
        .unwrap();
    let _unregister = UnregisterRoot {
        runtime: Arc::clone(&runtime),
    };

    let parent_status = carrick_test_support::GuestUserBuffer::from_value(-1_i32);
    let parent_key = TaskKey {
        id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
        serial: TaskSerial::from_raw_u64(task_serial).unwrap(),
    };
    let (child_pid, child_key) = {
        let mut service = Aarch64NativeProcessService::with_crossing(
            &fixture.task,
            fixture.slot,
            fixture.zone,
            fixture.region.table(),
            NonZeroU64::MIN,
            crossing,
        )
        .with_words(words);
        let mut entry = runtime
            .enter(source, &fixture.task, parked, &mut service)
            .unwrap();
        let LifecycleOutcome::Returned { result, .. } = entry.fork(ProcessForkChildTid::NONE)
        else {
            panic!("fork must return");
        };
        let pid = u32::try_from(result.raw()).expect("positive child pid");
        (pid, runtime.namespace_child_key(parent_key, pid).unwrap())
    };
    let parent_binding = runtime.task_binding(parent_key).unwrap();
    let child_binding = runtime.task_binding(child_key).unwrap();
    // SAFETY: stopped fixture owns the parent's current record before wait4 parks it.
    unsafe {
        *fixture.zone.record(parent_binding.record.id).ctx_mut() = parent_binding.words;
    }
    {
        let mut service = Aarch64NativeProcessService::with_crossing(
            &fixture.task,
            fixture.slot,
            fixture.zone,
            fixture.region.table(),
            NonZeroU64::MIN,
            crossing,
        )
        .with_words(words);
        let mut entry = runtime
            .enter_registered(
                registry(),
                source,
                &fixture.task,
                parent_binding.address,
                &parent_binding.words,
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            entry.wait4(
                ProcessWaitPid::from_syscall_argument(u64::MAX),
                parent_status.va(),
                LinuxWaitOptions::empty(),
                UserVa::new(0),
            ),
            LifecycleOutcome::Transferred { .. }
        ));
        assert!(entry.take_handoff_receipt().is_some());
    }
    if let Some(doorbell) = fixture.task.linux.take_host_work_doorbell() {
        doorbell.settled();
    }

    // Select the forked child and exec `/bin/poll-child` through the production exec service.
    activate_target(source, &fixture.task, &child_binding);
    let mut exec_physical = crate::native_process_runtime::host_test_support::Physical {
        zone: fixture.zone,
        page: fixture.page,
        controls: &[],
        copies: Vec::new(),
        tid_words: std::collections::BTreeMap::new(),
        tid_wakes: 0,
        tid_writes: Vec::new(),
        child_copy_error: None,
        prepare_copy_error: None,
        child_copy_error_at: None,
        on_copy_complete: None,
        native_ipc: Some(owner.region()),
        refuse_copy: false,
        waker_slot: fixture.slot,
        on_signal_clock: None,
    };
    let exec_path = b"/bin/poll-child\0";
    let mut exec_payload = vec![0; carrick_core_abi::service::EXEC_PAYLOAD_HEADER_BYTES];
    exec_payload.extend_from_slice(exec_path);
    carrick_core_abi::service::encode_exec_payload_header(
        &mut exec_payload,
        carrick_core_abi::service::ExecCall::Execve,
        exec_path.len(),
        0,
        0,
    )
    .unwrap();
    {
        let mut entry = runtime
            .enter_registered(
                registry(),
                source,
                &fixture.task,
                child_binding.address,
                &child_binding.words,
                &mut exec_physical,
            )
            .unwrap();
        assert!(matches!(
            entry.begin_exec_service(
                exec_payload.into_boxed_slice(),
                None,
                NativeServiceCall::new(carrick_guest_arch::NativeOrdinal::new(221), counters),
            ),
            Ok(NativeResume::Left(None))
        ));
        assert!(entry.take_handoff_receipt().is_some());
    }
    let exec_root_gpa = 0xb00000_u64;
    let exec_asid = asid(103);
    {
        let selector = fixture.task.service_notice.take().unwrap().unwrap();
        let member = fixture.zone.record(selector.record.id).identity();
        // SAFETY: the forked child's live record retains its control slot.
        let child_control = unsafe { &*(member.control_slot as *const ThreadControlSlot) };
        // SAFETY: claim the exact published exec request under its service queue.
        let queue = fixture
            .zone
            .object_wait(
                carrick_sched_core::object_wait::ObjectWaitKey::native_service(selector.record)
                    .unwrap(),
                &ShortLockSpin,
                &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned),
            )
            .unwrap();
        let ticket = unsafe {
            ServiceCell::claim_notice(&child_control.service, selector, NonZeroU64::MIN, member)
        }
        .unwrap();
        let identity = ticket.request().identity;
        // SAFETY: the service owner retains the manifest box through acknowledgment.
        let manifest =
            unsafe { &mut *(ticket.reply_address().unwrap().raw() as *mut ExecSuccessorManifest) };
        let receipt = ExecAdoptionReceipt::checked(NonZeroU64::new(91).unwrap()).unwrap();
        *manifest = manifest
            .seal(
                identity,
                receipt,
                ExecSuccessorBacking {
                    root: RootGpa::page_aligned(FrameGpa::new(exec_root_gpa)).unwrap(),
                    asid: exec_asid,
                    asid_generation: NonZeroU64::new(105).unwrap(),
                },
                ExecSuccessorEntry {
                    entry: UserVa::new(0x400000),
                    stack_pointer: UserVa::new(0x7ffff000),
                },
            )
            .unwrap();
        assert!(
            ticket
                .publish_exec_prepared(receipt, (), |_, ()| {})
                .is_ok()
        );
        let mut effects = WakeEffects::default();
        queue.notify_object(fixture.slot, &mut effects).unwrap();
    }
    let selected = activate_target(source, &fixture.task, &child_binding);
    assert_eq!(selected.record, child_binding.record.id);
    {
        // SAFETY: this lane owns the selected child record.
        let saved = unsafe { runtime.record_binding(child_binding.record) }
            .unwrap()
            .words;
        let mut entry = runtime
            .enter_registered(
                registry(),
                source,
                &fixture.task,
                child_binding.address,
                &saved,
                &mut exec_physical,
            )
            .unwrap();
        assert!(matches!(
            entry.resume_checkpoint(|_| Ok(None)),
            Ok(NativeResume::NoPending)
        ));
    }
    // Publish the committed exec successor space in the zone so Sched::idle_entry
    // installs it cleanly as an idle carrier executor (no host task loaded).
    // SAFETY: selected child record is still held on this slot.
    let successor_binding = unsafe { runtime.record_binding(child_binding.record) }.unwrap();
    let succ_mm = successor_binding.address.mm.raw().get();
    let succ_ttbr0 = (u64::from(exec_asid.raw()) << 48) | exec_root_gpa;
    if fixture.zone.spaces.find(succ_mm).is_none() {
        let space = fixture
            .zone
            .spaces
            .publish_closed(succ_mm, succ_ttbr0, succ_ttbr0)
            .unwrap();
        fixture.zone.spaces.open(space);
    }
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, child_binding.record.id)
            .is_queued()
    );
    let _ = crate::sched::leave_space(
        fixture.zone,
        fixture.slot,
        &mut crate::sched::FakeCpu::default(),
    );
    fixture.zone.drive(fixture.slot, 1);
    if let Some(doorbell) = fixture.task.linux.take_host_work_doorbell() {
        doorbell.settled();
    }

    let drain_carrier_service = |round: usize| {
        if let Some(selector) = fixture.task.service_notice.take().unwrap() {
            let member = fixture.zone.record(selector.record.id).identity();
            // SAFETY: live native member retains its control slot until retirement.
            let member_control = unsafe { &*(member.control_slot as *const ThreadControlSlot) };
            let wait_key =
                carrick_sched_core::object_wait::ObjectWaitKey::native_service(selector.record)
                    .unwrap();
            let queue = fixture
                .zone
                .object_wait(wait_key, &ShortLockSpin, &|owned| {
                    crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
                })
                .unwrap();
            // SAFETY: claim under the member's service queue, matching carrier intake.
            let ticket = unsafe {
                ServiceCell::claim_notice(
                    &member_control.service,
                    selector,
                    NonZeroU64::MIN,
                    member,
                )
            }
            .unwrap();
            match ticket.request().operation {
                ServiceOperation::HostFile { payload, .. } => {
                    // SAFETY: ticket retains the staged host-file buffer until completion.
                    let bytes = unsafe {
                        core::slice::from_raw_parts_mut(
                            payload.ring_storage().raw() as *mut u8,
                            payload.length().raw() as usize,
                        )
                    };
                    let served = dispatcher
                        .serve_native_host_file_for(bytes, None, selector.record)
                        .unwrap_or_else(|_| {
                            panic!("carrier refused native host-file call at round {round}")
                        });
                    if let Some(revision) = served.host_ready_wait {
                        let wait = carrick_core_abi::PortalOwnerWait::host_readiness(
                            ticket.request().identity.birth.mm,
                            revision,
                        );
                        assert!(ticket.complete_wait(wait).is_ok());
                    } else {
                        assert!(ticket.complete(true).is_ok());
                    }
                }
                other => panic!("unexpected native service operation {other:?} at round {round}"),
            }
            let mut effects = WakeEffects::default();
            queue.notify_object(fixture.slot, &mut effects).unwrap();
        }
        if let Some(doorbell) = fixture.task.linux.take_host_work_doorbell() {
            doorbell.settled();
        }
    };

    let run_idle_until_child_or_parent = |round: usize,
                                          frame: &mut carrick_el1_abi::TrapFrame,
                                          on_wfi: &mut Option<Box<dyn FnOnce()>>|
     -> bool {
        loop {
            let mut arm_service = Aarch64NativeProcessService::with_crossing(
                &fixture.task,
                fixture.slot,
                fixture.zone,
                fixture.region.table(),
                NonZeroU64::MIN,
                crossing,
            )
            .with_words(words);
            let mut cpu = ArmWfiCpu {
                inner: crate::sched::FakeCpu {
                    ttbr: (0x9000, 0x9000),
                    ..Default::default()
                },
                fixture,
                service: &mut arm_service,
                on_wfi,
                deadline,
                timed_out_in_wfi: false,
            };
            let action = {
                let mut sched = crate::sched::Sched {
                    zone: fixture.zone,
                    slot: fixture.slot,
                    task: &fixture.task,
                    cpu: &mut cpu,
                    user: &crate::sched::HardwareUserWord,
                    counters,
                    handoff: None,
                };
                sched.serve_idle_entry(frame)
            };
            if cpu.timed_out_in_wfi {
                let stranded = fixture.task.service_notice.take().unwrap();
                panic!(
                    "ARM vCPU hung in WFI before 2s deadline at poll round {round}: \
                         stranded_service_notice={stranded:?}"
                );
            }
            match action {
                carrick_el1_abi::Action::Served => return true,
                carrick_el1_abi::Action::Idle => {
                    drain_carrier_service(round);
                    if fixture.zone.head_needs_host(fixture.slot) {
                        return false;
                    }
                }
                other => panic!("unexpected idle_entry action {other:?} at round {round}"),
            }
        }
    };

    let mut frame = carrick_el1_abi::TrapFrame {
        slot: fixture.slot.index() as u64,
        ..Default::default()
    };
    assert!(
        run_idle_until_child_or_parent(0, &mut frame, &mut None),
        "exec successor must be scheduled first"
    );

    let child_host_call = |round: usize,
                           frame: &mut carrick_el1_abi::TrapFrame,
                           nr: u64,
                           args: [u64; 6],
                           mut on_wfi: Option<Box<dyn FnOnce()>>|
     -> i64 {
        frame.esr = 0x15 << 26;
        frame.elr = 0x400004;
        frame.x[8] = nr;
        frame.x[..6].copy_from_slice(&args);
        let child_table_id = fixture.task.linux.file_table.load(Ordering::Acquire);
        let raw = map.lookup(child_table_id).unwrap();
        let table_words = [raw.authority, raw.index, raw.generation];
        let venue = crate::ipc::IpcVenue {
            region: owner.region(),
            tables: &crate::ipc::MapTables(map),
        };
        let begin = match crate::dispatch::native_service_decision(
            frame,
            &fixture.task,
            carrick_el1_abi::Action::Forward,
            None,
            counters,
            || crate::native_process_runtime::NativeThreadGroupOwner::ForkChild,
            |frame| {
                crate::dispatch::native_host_file_stage(
                    frame,
                    &fixture.task,
                    &ResidentUser,
                    table_words,
                    carrick_core_abi::service::ServiceOrigin::Descendant,
                    |fd| crate::ipc::native_descriptor(&venue, table_words, fd),
                    &mut |_| 0usize,
                )
            },
        ) {
            crate::dispatch::NativeServiceDecision::Reply(result) => return result,
            crate::dispatch::NativeServiceDecision::Begin(begin) => begin,
            other => panic!(
                "expected Begin for syscall {nr}, declined={}",
                matches!(other, crate::dispatch::NativeServiceDecision::Decline)
            ),
        };
        let mut saved = Aarch64ParkedContext::ZERO;
        let mut fake_cpu = crate::sched::FakeCpu {
            ttbr: (succ_ttbr0, succ_ttbr0),
            ..Default::default()
        };
        crate::sched::ThreadCpu::save(
            &mut fake_cpu,
            frame,
            &mut saved,
            crate::sched::CpuExitCause::Svc,
        );
        let (page_ref, control_ref) = fixture.task.lifecycle_refs().unwrap();
        let mut arm_service = Aarch64NativeProcessService::with_crossing(
            &fixture.task,
            fixture.slot,
            fixture.zone,
            fixture.region.table(),
            NonZeroU64::MIN,
            crossing,
        )
        .with_words(words);
        let (result, phase) = crate::aarch64_process::with_process_entry(
            source,
            &fixture.task,
            &saved.native,
            succ_ttbr0,
            page_ref,
            control_ref,
            &mut arm_service,
            |process| {
                crate::dispatch::begin_native_service(
                    process,
                    frame.x[8],
                    begin,
                    None,
                    counters,
                    counters,
                    || None,
                )
            },
        )
        .unwrap();
        let resumed = crate::dispatch::native_service_completion(result, phase).unwrap();
        match resumed {
            NativeResume::Left(None) => {
                let _ =
                    crate::dispatch::native_service_idle(fixture.zone, fixture.slot, &mut fake_cpu);
                drain_carrier_service(round);
                assert!(
                    run_idle_until_child_or_parent(round, frame, &mut on_wfi),
                    "child must resume from syscall {nr} at round {round}"
                );
                frame.x[0] as i64
            }
            NativeResume::Returned(val) => val.raw(),
            _ => panic!("unexpected service resume for syscall {nr}"),
        }
    };

    // User memory layout inside one GuestUserBuffer:
    //   [0..16]   sockaddr_in (AF_INET = 2, port = 0, addr = 127.0.0.1)
    //   [16..20]  socklen_t = 16
    //   [32..40]  struct pollfd { fd, events = POLLIN, revents }
    //   [48..64]  struct timespec { tv_sec = 0, tv_nsec }
    //   [64..68]  rx byte scratch
    let mut user = carrick_test_support::GuestUserBuffer::zeroed(256);
    // AF_INET (2), port 0, 127.0.0.1
    user.as_mut_bytes()[0..2].copy_from_slice(&2u16.to_ne_bytes());
    user.as_mut_bytes()[4..8].copy_from_slice(&[127, 0, 0, 1]);
    user.as_mut_bytes()[16..20].copy_from_slice(&16u32.to_ne_bytes());

    // AArch64 numbers: socket=198, bind=200, getsockname=204, recvfrom=207, ppoll=73, exit=93
    let sock_fd = child_host_call(0, &mut frame, 198, [2, 2, 0, 0, 0, 0], None);
    assert!(
        sock_fd >= 0,
        "socket(AF_INET, SOCK_DGRAM, 0) failed: {sock_fd}"
    );
    assert_eq!(
        child_host_call(
            0,
            &mut frame,
            200,
            [sock_fd as u64, user.arg(), 16, 0, 0, 0],
            None,
        ),
        0,
        "bind(127.0.0.1:0) must succeed"
    );
    assert_eq!(
        child_host_call(
            0,
            &mut frame,
            204,
            [sock_fd as u64, user.arg(), user.arg() + 16, 0, 0, 0],
            None,
        ),
        0,
        "getsockname must succeed"
    );
    let bound_port = u16::from_be_bytes(user.as_bytes()[2..4].try_into().unwrap());
    assert_ne!(bound_port, 0);

    let sender = become_ready.then(|| {
        use std::os::fd::FromRawFd;
        // SAFETY: fresh AF_INET datagram descriptor owned solely by this UdpSocket.
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        assert!(raw >= 0, "host test datagram socket");
        unsafe { UdpSocket::from_raw_fd(raw) }
    });
    let timeout_ns: i64 = if become_ready {
        500_000_000
    } else {
        50_000_000
    };
    user.as_mut_bytes()[48..56].copy_from_slice(&0i64.to_ne_bytes());
    user.as_mut_bytes()[56..64].copy_from_slice(&timeout_ns.to_ne_bytes());

    for round in 0..POLL_ROUNDS {
        user.as_mut_bytes()[32..36].copy_from_slice(&(sock_fd as i32).to_ne_bytes());
        user.as_mut_bytes()[36..38].copy_from_slice(&libc::POLLIN.to_ne_bytes());
        user.as_mut_bytes()[38..40].copy_from_slice(&0x7fff_i16.to_ne_bytes());

        let on_wfi: Option<Box<dyn FnOnce()>> = sender.as_ref().map(|tx| {
            let tx = tx.try_clone().unwrap();
            let byte = [b'A' + (round as u8 % 26)];
            Box::new(move || {
                tx.send_to(&byte, ("127.0.0.1", bound_port)).unwrap();
            }) as Box<dyn FnOnce()>
        });

        let ready = child_host_call(
            round,
            &mut frame,
            73,
            [user.arg() + 32, 1, user.arg() + 48, 0, 8, 0],
            on_wfi,
        );

        let revents = i16::from_ne_bytes(user.as_bytes()[38..40].try_into().unwrap());
        if become_ready {
            assert_eq!(ready, 1, "round {round}: ready socket ppoll must return 1");
            assert_ne!(
                revents & libc::POLLIN,
                0,
                "round {round}: revents {revents:#x} must report POLLIN"
            );
            user.as_mut_bytes()[64] = 0;
            let got = child_host_call(
                round,
                &mut frame,
                207,
                [sock_fd as u64, user.arg() + 64, 1, 0, 0, 0],
                None,
            );
            assert_eq!(got, 1, "round {round}: recvfrom must drain one byte");
            assert_eq!(user.as_bytes()[64], b'A' + (round as u8 % 26));
        } else {
            assert_eq!(
                ready, 0,
                "round {round}: never-ready socket ppoll(50ms) must time out with 0"
            );
            assert_eq!(
                revents, 0,
                "round {round}: timed-out ppoll must clear revents"
            );
        }
    }

    // Child calls `_exit(7)` (SYS_EXIT = 93 on AArch64) through production dispatch.
    frame.esr = 0x15 << 26;
    frame.elr = 0x400004;
    frame.x[8] = 93;
    frame.x[0] = u64::from(CHILD_EXIT_CODE);
    let mut saved = Aarch64ParkedContext::ZERO;
    let mut exit_cpu = crate::sched::FakeCpu {
        ttbr: (succ_ttbr0, succ_ttbr0),
        ..Default::default()
    };
    crate::sched::ThreadCpu::save(
        &mut exit_cpu,
        &frame,
        &mut saved,
        crate::sched::CpuExitCause::Svc,
    );
    let (page_ref, control_ref) = fixture.task.lifecycle_refs().unwrap();
    let names = carrick_el1_abi::InotifyNameCache::new();
    *crossing.zone.lock().unwrap() = Some(fixture.zone);
    *crossing.child.lock().unwrap() = Some((
        crate::common_entry::execution_binding(&fixture.task),
        successor_binding.address,
    ));
    {
        let mut arm_service = Aarch64NativeProcessService::with_crossing(
            &fixture.task,
            fixture.slot,
            fixture.zone,
            fixture.region.table(),
            NonZeroU64::MIN,
            crossing,
        )
        .with_words(words);
        let route = crate::dispatch::dispatch_arm_syscall_with_native_process(
            &mut frame,
            counters,
            core::slice::from_ref(&fixture.task),
            &[],
            &[],
            &[],
            &[],
            &names,
            Some(crate::dispatch::Zone {
                tables: fixture.zone,
                cpu: &mut exit_cpu,
                user: &crate::sched::HardwareUserWord,
            }),
            None,
            Some(&TaskLifecycleVenue),
            page_ref,
            control_ref,
            &saved.native,
            succ_ttbr0,
            &mut arm_service,
            |_| core::ptr::null_mut(),
        )
        .unwrap();
        assert_eq!(
            route,
            carrick_personality_linux::dispatch::CompletionRoute::Suspended
        );
        let _ = crate::dispatch::native_service_idle(fixture.zone, fixture.slot, &mut exit_cpu);
    }
    drain_carrier_service(POLL_ROUNDS);

    // The child's `_exit(7)` woke the parent parked in `wait4(-1)`;
    // `Sched::serve_idle_entry` switches the parent in, resumes its `wait4`
    // checkpoint in ring, and returns `Action::Served` with the reaped child.
    assert!(
        run_idle_until_child_or_parent(POLL_ROUNDS, &mut frame, &mut None),
        "idle entry must resume the woken parent in wait4(-1)"
    );
    assert_eq!(
        fixture.zone.slot(fixture.slot).current(),
        Some(parent_binding.record.id),
        "woken parent must be the running record after wait4(-1) completes"
    );
    assert_eq!(
        frame.x[0],
        u64::from(child_pid),
        "parent wait4(-1) must return the exited child's pid"
    );
    assert_eq!(
        parent_status.get::<i32>(0),
        LinuxWaitStatus::exited(CHILD_EXIT_CODE).raw(),
        "parent wait4(-1) must observe WIFEXITED with status 7"
    );
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "parent wait4(-1) must complete within 2s, took {elapsed:?}"
    );

    drop(launch_root);
    drop(wait_service);
    drop(dispatcher);
}
