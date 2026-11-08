//! Production native futex adapter contention witnesses on both contexts.
use super::*;
use carrick_core::user_copy::{CopyOutcome, GuestCopyRequest, UserCopy};
use carrick_guest_arch::{Access, GuestLen};
use carrick_personality_linux::sched::FutexCall;
use carrick_sched_core::{ShortLockSpin, spaces::notification::SpaceWaitCause};

struct Fixture<C: ProcessContext + 'static> {
    zone: &'static ZoneTables<C>,
    registry: &'static NativeProcessRegistry<'static, AddressContext<RootGpa>, C>,
    runtime: Arc<NativeProcessRuntime<'static, AddressContext<RootGpa>, C>>,
    task: &'static CurrentTask,
    control: &'static ThreadControlSlot,
    page: &'static ThreadLifecyclePage,
    address: AddressContext<RootGpa>,
    slot: SlotId,
    record: RecordRef,
}
impl<C: ProcessContext + 'static> Fixture<C> {
    fn new<B: carrick_mmu_core::owner_mmu::OwnerForkMmu>(
        make: impl Fn(AddressContext<RootGpa>) -> C,
    ) -> Self {
        let binding = ExecutionBinding {
            task: carrick_core_abi::EntryTaskKey::from_raw(41),
            generation: carrick_core_abi::SnapshotGeneration::from_raw(11),
            mm: carrick_core_abi::EntryMmKey::from_raw(1),
            thread_generation: carrick_core_abi::EntryThreadGeneration::from_raw(101),
        };
        let process = binding.task;
        let process_birth =
            carrick_core_abi::BirthSerial::of_task(TaskSerial::from_raw_u64(11).unwrap());
        let layout = std::alloc::Layout::new::<ZoneTables<C>>();
        // SAFETY: one aligned allocation owns this zero-valid compact zone for
        // the entire leaked host-test fixture lifetime.
        let zone = unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables<C>>();
            assert!(!ptr.is_null());
            Box::leak(Box::from_raw(ptr))
        };
        let page = Box::leak(Box::new(ThreadLifecyclePage::new()));
        let control = Box::leak(Box::new(ThreadControlSlot::new()));
        let task = Box::leak(Box::new(CurrentTask::new()));
        let tid = binding.task.raw();
        let mm = binding.mm.raw();
        let root = 0x1000;
        let slot = SlotId::new(0);
        task.set(
            carrick_el1_abi::El1TaskId::from_linux_tid(tid as i32),
            binding.generation,
            5,
        );
        task.mm.key.store(mm, Ordering::Release);
        task.mm
            .thread_generation
            .store(binding.thread_generation.raw(), Ordering::Release);
        task.publish_visible_pid(process.raw() as u32);
        task.publish_lifecycle(page as *const _ as u64, control as *const _ as u64);
        control.publish_host_birth_identity(
            carrick_core::terminal::ThreadBirthIdentity::from_parts(
                binding.task,
                process_birth,
                binding.thread_generation,
            )
            .unwrap(),
        );
        let address = AddressContext {
            root: RootGpa::page_aligned(FrameGpa::new(root)).unwrap(),
            mm: MmGeneration::new(NonZeroU64::new(mm).unwrap()),
            generation: ContextGeneration::new(NonZeroU64::MIN),
        };
        zone.mm_issuer().observe_existing(address.mm);
        let space = zone.spaces.publish_closed(mm, root, 0).unwrap();
        zone.spaces.open(space);
        zone.drive(slot, 1);
        zone.publish_slot(slot, 1, Some(0), 1);
        zone.enter_guest(slot);
        zone.install_space(slot, mm).unwrap();
        zone.current_or_new(
            slot,
            carrick_el1_abi::ThreadIdentity {
                tid,
                serial: binding.thread_generation.raw(),
                mm,
                file_table: 5,
                generation: binding.generation.raw(),
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 1,
                lifecycle_page: page as *const _ as u64,
                control_slot: control as *const _ as u64,
            },
        )
        .unwrap();
        let source = BornInZoneSource { zone, slot };
        let runtime = Arc::new(
            NativeProcessRuntime::admit_fresh_root::<B>(
                source,
                task,
                page,
                control,
                address,
                address,
                make(address),
            )
            .unwrap(),
        );
        let registry = Box::leak(Box::new(NativeProcessRegistry::new()));
        registry
            .register_root(runtime.clone(), source, task, address)
            .unwrap();
        let record = registry
            .state
            .lock()
            .members
            .values()
            .next()
            .unwrap()
            .record;
        control.bind_zone_record(record);
        task.publish_lifecycle(page as *const _ as u64, control as *const _ as u64);
        Self {
            zone,
            registry,
            runtime,
            task,
            control,
            page,
            address,
            slot,
            record,
        }
    }
}

impl<C: ProcessContext> Drop for Fixture<C> {
    fn drop(&mut self) {
        let key = self.runtime.graph.lock().root_key;
        self.registry.unregister_process(&self.runtime, key);
    }
}

struct Copy {
    refuse_word: bool,
    loads: usize,
    word: u32,
}
impl UserCopy for Copy {
    fn copy_in(&mut self, dst: &mut [u8], src: UserVa) -> CopyOutcome {
        assert_eq!(dst.len(), 8);
        dst.copy_from_slice(&(if src.raw() == 0x2000 { 1_u64 } else { 0 }).to_le_bytes());
        CopyOutcome::Done
    }
    fn copy_out(&mut self, _: UserVa, _: &[u8]) -> CopyOutcome {
        panic!("wait only reads")
    }
    fn atomic_load_u32(&mut self, address: UserVa, out: &mut u32) -> CopyOutcome {
        assert_eq!(address, UserVa::new(0x1000));
        self.loads += 1;
        if core::mem::take(&mut self.refuse_word) {
            CopyOutcome::NotYet(GuestCopyRequest {
                address,
                len: GuestLen::new(4),
                access: Access::Read,
            })
        } else {
            *out = self.word;
            CopyOutcome::Done
        }
    }
}

fn episode<C: ProcessContext + 'static, B: carrick_mmu_core::owner_mmu::OwnerForkMmu>(
    make: impl Fn(AddressContext<RootGpa>) -> C,
    mapping: bool,
    timed: bool,
) {
    let fixture = Fixture::<C>::new::<B>(&make);
    let zone = fixture.zone;
    assert!(zone.mark_native_owned(fixture.record.id));
    let mut service = Physical {
        zone,
        page: fixture.page,
        controls: core::slice::from_ref(fixture.control),
        copies: Vec::new(),
        tid_words: BTreeMap::new(),
        tid_wakes: 0,
        tid_writes: Vec::new(),
        child_copy_error: None,
        prepare_copy_error: None,
        child_copy_error_at: None,
        on_copy_complete: None,
        native_ipc: None,
        refuse_copy: false,
        on_signal_clock: None,
    };
    let handle = service.service_mm_handle(&fixture.address).unwrap();
    let space = zone.space_entry(NonZeroU64::new(1).unwrap()).unwrap();
    space
        .admit_notifications(handle.incarnation(), &ShortLockSpin, &|effects| {
            let _ = effects.deliver_handbacks(&mut |_| {});
        })
        .unwrap();
    let observed = space
        .notifications(handle.incarnation())
        .unwrap()
        .observe(SpaceWaitCause::Gate);
    let access = crate::sched::object_wait::space_access(zone, fixture.slot);
    access.raise(space.index());
    // SAFETY: this fixture retains the exact admitted owner and closed gate.
    let wait = unsafe {
        carrick_core_abi::PortalOwnerWait::from_owner(
            handle,
            carrick_core_abi::PortalWaitCause::Gate,
            observed.revision(),
        )
    };
    FUTEX_MAPPING.with(|slot| {
        slot.set(Some(if mapping {
            Err(NativeProcessError::OwnerWait(wait))
        } else {
            Ok(true)
        }))
    });
    // The x86 input-copy venue cannot supply a mapping wait. A mapping refusal
    // must use the returned owner notification without calling this venue.
    service.prepare_copy_error = Some(if mapping {
        NativeProcessError::Unsupported
    } else {
        NativeProcessError::OwnerWait(wait)
    });
    let source = BornInZoneSource {
        zone,
        slot: fixture.slot,
    };
    let saved = make(fixture.address);
    let mut copy = Copy {
        refuse_word: !mapping,
        loads: 0,
        word: 0,
    };
    let call = FutexCall {
        args: [0x1000, 0, 0, if timed { 0x2000 } else { 0 }, 0, 0],
    };
    {
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                source,
                fixture.task,
                fixture.address,
                &saved,
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            entry.native_futex(call, &mut copy),
            Some(LifecycleOutcome::Transferred { .. })
        ));
        assert!(
            entry.take_run_failure().is_none(),
            "mapping Busy must retain its owner notification"
        );
        assert!(
            entry.take_handoff_receipt().is_some(),
            "must release execution capacity"
        );
    }
    assert!(zone.slot(fixture.slot).current().is_none());
    assert_eq!(
        zone.slot(fixture.slot).queued(),
        0,
        "no redispatch while owner gate remains closed"
    );
    assert_eq!(copy.loads, usize::from(!mapping));
    FUTEX_MAPPING.with(|slot| slot.set(Some(Ok(true))));
    service.prepare_copy_error = None;
    access.lower(space.index());
    assert_eq!(
        zone.switch_in_full(fixture.slot).unwrap().record,
        fixture.record.id
    );
    zone.counters.el1_timeouts.store(1, Ordering::Release);
    let saved = unsafe { *zone.record(fixture.record.id).ctx_mut() };
    let mut entry = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            source,
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    assert!(matches!(
        entry.resume_checkpoint(|_| Ok(None)),
        Ok(NativeResume::RetrySyscall)
    ));
    assert!(matches!(
        entry.native_futex(call, &mut copy),
        Some(LifecycleOutcome::Transferred { .. })
    ));
    assert!(entry.take_run_failure().is_none());
    assert!(entry.take_handoff_receipt().is_some());
    assert_eq!(copy.loads, 1 + usize::from(!mapping));
    if timed {
        assert_eq!(
            zone.timer_deadline(fixture.slot),
            Some(2000),
            "one second admitted at tick 1000 must not restart at tick 2000"
        );
    }
    FUTEX_MAPPING.with(|slot| slot.set(None));
}

fn arm_words(address: AddressContext<RootGpa>) -> carrick_sched_core::Aarch64ParkedContext {
    carrick_sched_core::Aarch64ParkedContext::from_parts(carrick_el1_abi::ThreadCtx::ZERO, address)
}

#[test]
fn native_futex_mapping_owner_busy_once_x86() {
    episode::<ParkedContextWords, carrick_mmu_core::x86::owner_mmu::X86Mmu>(words, true, false);
}
#[test]
fn native_futex_mapping_owner_busy_once_aarch64() {
    episode::<carrick_sched_core::Aarch64ParkedContext, carrick_mmu_core::owner_mmu::Aarch64Mmu>(
        arm_words, true, false,
    );
}

#[test]
fn native_futex_mapping_deadline_starts_at_first_attempt_x86() {
    episode::<ParkedContextWords, carrick_mmu_core::x86::owner_mmu::X86Mmu>(words, true, true);
}
#[test]
fn native_futex_mapping_deadline_starts_at_first_attempt_aarch64() {
    episode::<carrick_sched_core::Aarch64ParkedContext, carrick_mmu_core::owner_mmu::Aarch64Mmu>(
        arm_words, true, true,
    );
}
#[test]
fn native_futex_word_deadline_starts_at_first_attempt_x86() {
    episode::<ParkedContextWords, carrick_mmu_core::x86::owner_mmu::X86Mmu>(words, false, true);
}
#[test]
fn native_futex_word_deadline_starts_at_first_attempt_aarch64() {
    episode::<carrick_sched_core::Aarch64ParkedContext, carrick_mmu_core::owner_mmu::Aarch64Mmu>(
        arm_words, false, true,
    );
}

/// A native frame routes exit through the common lifecycle dispatcher on
/// either context type, without selecting the separate ARM scheduler adapter.
struct ExitFrame(carrick_personality_linux::crossing::HostCrossingSet);
impl carrick_personality_linux::dispatch::SyscallFrame for ExitFrame {
    fn canonical_ordinal(&self) -> carrick_syscall_abi::CanonicalNr {
        carrick_syscall_abi::CanonicalNr::new(carrick_personality_linux::lifecycle::SYS_EXIT as u64)
    }
    fn argument(&self, _: usize) -> Option<u64> {
        Some(0)
    }
    fn result(&self) -> carrick_guest_arch::NativeReturnWord {
        carrick_guest_arch::NativeReturnWord(0)
    }
    fn set_result(&mut self, _: carrick_guest_arch::NativeReturnWord) {}
    fn slot(&self) -> Option<SlotId> {
        Some(SlotId::new(1))
    }
    fn task_index(&self) -> usize {
        0
    }
    fn user_sp(&self) -> Option<UserVa> {
        Some(UserVa::new(0x8000))
    }
}
impl crate::dispatch::GuestDispatchFrame for ExitFrame {
    fn native_number(&self) -> carrick_guest_arch::NativeOrdinal {
        carrick_guest_arch::NativeOrdinal::new(match self.0 {
            carrick_personality_linux::crossing::HostCrossingSet::X86 => 60,
            carrick_personality_linux::crossing::HostCrossingSet::Aarch64 => 93,
        })
    }
    fn crossing_set(&self) -> carrick_personality_linux::crossing::HostCrossingSet {
        self.0
    }
    fn arm_frame(&mut self) -> Option<&mut carrick_el1_abi::TrapFrame> {
        None
    }
    fn arm_frame_ref(&self) -> Option<&carrick_el1_abi::TrapFrame> {
        None
    }
    fn arm_scheduler(&self) -> bool {
        false
    }
    fn robust_publications(&self) -> Option<&core::sync::atomic::AtomicU64> {
        None
    }
}

fn clear_tid_stopped_join_driver<C, B>(
    make: impl Fn(AddressContext<RootGpa>) -> C,
    isa: carrick_personality_linux::crossing::HostCrossingSet,
) where
    C: ProcessContext + crate::dispatch::DispatchContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
{
    use carrick_el1_abi::{BornRecord, EntryIdentity, Lifecycle, ThreadIdentity};
    use carrick_personality_linux::dispatch::{CompletionRoute, dispatch};
    use carrick_sched_core::{Claim, WakeRefusal};
    let fixture = Fixture::<C>::new::<B>(&make);
    let zone = fixture.zone;
    // Publish an actual Born lifecycle member, then authenticate it through
    // the production registry. Only physical user memory is substituted.
    let control = Box::leak(Box::new(ThreadControlSlot::new()));
    let birth = carrick_core_abi::BirthSerial::of_task(TaskSerial::from_raw_u64(12).unwrap());
    let member = fixture
        .page
        .stock(
            0,
            EntryIdentity {
                tid: 42,
                visible_tid: 42,
                thread_serial: 102,
                birth,
                uid_credit: 0,
            },
        )
        .unwrap();
    fixture
        .page
        .bind_control_address(member, control as *const _ as u64)
        .unwrap();
    control
        .reset_for_birth(carrick_el1_abi::BlockedMask(0), 0, member)
        .unwrap();
    assert!(control.publish_visible_tid(42));
    control.publish_host_birth_identity(
        carrick_core::terminal::ThreadBirthIdentity::from_parts(
            carrick_core_abi::EntryTaskKey::from_raw(42),
            birth,
            carrick_core_abi::EntryThreadGeneration::from_raw(102),
        )
        .unwrap(),
    );
    let claim = fixture.page.claim(member).unwrap();
    fixture
        .page
        .record_born(
            claim,
            BornRecord {
                caller_task: 41,
                caller_serial: 101,
                clone_flags: 0x10000,
                clear_child_tid: 0x1000,
                blocked: carrick_el1_abi::BlockedMask(0),
            },
        )
        .unwrap();
    fixture.page.thread_born().unwrap();
    fixture.page.publish(member).unwrap();
    control.set_clear_child_tid(0x1000);
    let task = Box::leak(Box::new(CurrentTask::new()));
    task.set(
        carrick_el1_abi::El1TaskId::from_linux_tid(42),
        carrick_core_abi::SnapshotGeneration::from_raw(12),
        5,
    );
    task.mm.key.store(1, Ordering::Release);
    task.mm.thread_generation.store(102, Ordering::Release);
    task.publish_visible_pid(41);
    task.publish_root_generation(fixture.address.generation);
    task.publish_lifecycle(fixture.page as *const _ as u64, control as *const _ as u64);
    let child_slot = SlotId::new(1);
    zone.drive(child_slot, 2);
    zone.publish_slot(child_slot, 1, Some(1), 2);
    zone.enter_guest(child_slot);
    zone.install_space(child_slot, 1).unwrap();
    let child = zone
        .alloc_record(ThreadIdentity {
            tid: 42,
            serial: 102,
            mm: 1,
            file_table: 5,
            generation: 12,
            affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
            affinity: 2,
            lifecycle_page: fixture.page as *const _ as u64,
            control_slot: control as *const _ as u64,
        })
        .unwrap();
    // A ring-born member has no host home or continuation.
    assert!(zone.mark_native_owned(child));
    // SAFETY: this newly allocated record is unpublished and fixture-owned.
    unsafe {
        *zone.record(child).ctx_mut() = make(fixture.address);
    }
    assert!(zone.requeue_preempted(child_slot, child).is_queued());
    assert_eq!(zone.switch_in_full(child_slot).unwrap().record, child);
    control.bind_zone_record(zone.record_ref(child));
    let child_source = BornInZoneSource {
        zone,
        slot: child_slot,
    };
    fixture
        .registry
        .register_thread(child_source, task, fixture.address, fixture.page, control)
        .unwrap();
    assert!(zone.mark_native_owned(child));
    assert!(zone.mark_native_owned(fixture.record.id));
    let mut service = Physical {
        zone,
        page: fixture.page,
        controls: core::slice::from_ref(control),
        copies: Vec::new(),
        tid_words: BTreeMap::from([((1, 0x1000), 42)]),
        tid_wakes: 0,
        tid_writes: Vec::new(),
        child_copy_error: None,
        prepare_copy_error: None,
        child_copy_error_at: None,
        on_copy_complete: None,
        native_ipc: None,
        refuse_copy: false,
        on_signal_clock: None,
    };
    FUTEX_MAPPING.with(|slot| slot.set(Some(Ok(true))));
    // Enroll the joiner through the registered native futex syscall. Its
    // affinity permits CPU 0 only; CPU 1 continues running the exiting member.
    let mut copy = Copy {
        refuse_word: false,
        loads: 0,
        word: 42,
    };
    {
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                BornInZoneSource {
                    zone,
                    slot: fixture.slot,
                },
                fixture.task,
                fixture.address,
                &make(fixture.address),
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            entry.native_futex(
                FutexCall {
                    args: [0x1000, 0, 42, 0x2000, 0, 0],
                },
                &mut copy
            ),
            Some(LifecycleOutcome::Transferred { .. })
        ));
        assert!(entry.take_handoff_receipt().is_some());
        assert!(entry.take_run_failure().is_none());
    }
    zone.leave_guest(fixture.slot, &ShortLockSpin);
    assert!(zone.step_away(
        fixture.slot,
        1,
        &mut |_| panic!("no ready records"),
        &mut |_| panic!("no placement")
    ));
    let key = carrick_personality_linux::sched::MmFutexKey::shared_private(UserVa::new(0x1000))
        .unwrap()
        .scheduler_address();
    let guard = zone.short_lock(
        ZoneTables::<C>::bucket_of_with_context(1, key),
        &ShortLockSpin,
    );
    assert_eq!(
        zone.wake_placed(
            &guard,
            1,
            key,
            u32::MAX,
            1,
            Waker::El1 { slot: child_slot },
            &mut [],
            &mut WakeEffects::default()
        ),
        Err(WakeRefusal::Unplaceable),
        "schedule must actually withhold the only eligible driver"
    );
    drop(guard);
    struct Venue<'a> {
        page: &'a ThreadLifecyclePage,
        control: &'a ThreadControlSlot,
    }
    impl crate::thread_setup::LifecycleVenue for Venue<'_> {
        fn thread<'a>(
            &'a self,
            _: &'a CurrentTask,
        ) -> Option<carrick_personality_linux::thread::LifecycleThread<'a>> {
            Some(carrick_personality_linux::thread::LifecycleThread {
                page: self.page,
                slot: self.control,
            })
        }
        fn born_slot(&self, _: &ThreadLifecyclePage, _: EntryRef) -> Option<&ThreadControlSlot> {
            None
        }
    }
    let venue = Venue {
        page: fixture.page,
        control,
    };
    let counters = carrick_el1_abi::Counters::new();
    let names = carrick_el1_abi::InotifyNameCache::new();
    {
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                child_source,
                task,
                fixture.address,
                &make(fixture.address),
                &mut service,
            )
            .unwrap();
        let mut pending: crate::dispatch::El1PendingFamilies<
            '_,
            '_,
            _,
            crate::sched::FakeCpu,
            crate::sched::HardwareUserWord,
            _,
            C,
        > = crate::dispatch::El1PendingFamilies {
            handoff: None,
            lifecycle_user: None,
            frame: &mut ExitFrame(isa),
            counters: &counters,
            current_tasks: core::slice::from_ref(task),
            fd_map: &[],
            object_table: &[],
            open_table: &[],
            inotify_table: &[],
            name_cache: &names,
            zone: None,
            ipc: None,
            lifecycle: Some(&venue),
            process: Some(entry.as_mut()),
            source: Some(child_source),
            anonymous: None,
            cache_lookup: |_| core::ptr::null_mut(),
        };
        assert_eq!(
            dispatch(
                carrick_syscall_abi::CanonicalNr::new(
                    carrick_personality_linux::lifecycle::SYS_EXIT as u64
                )
                .raw(),
                u64::MAX,
                &mut pending
            ),
            CompletionRoute::Suspended,
            "raw nonfinal exit must never forward to host custody"
        );
        drop(pending);
        // The dispatcher consumed and authenticated the terminal receipt.
        assert!(entry.take_handoff_receipt().is_none());
        assert!(entry.take_run_failure().is_none());
    }
    assert!(
        task.service_notice.take().unwrap().is_none(),
        "no host service forward"
    );
    assert!(!control.host_exit_requested(), "no host terminal custody");
    assert!(zone.slot(child_slot).current().is_none());
    assert_eq!(fixture.page.live(), 1);
    assert_eq!(control.clear_child_tid(), 0);
    assert_eq!(service.tid_writes, [(1, 0x1000, 0)]);
    assert!(matches!(
        zone.record(fixture.record.id).claim(),
        Claim::Queued { .. }
    ));
    // Fixed scheduler steps only: no polling or host blocking waits. The guest
    // wait above is timed, and returning the driver consumes one completion.
    zone.step_back(fixture.slot, 1);
    zone.enter_guest(fixture.slot);
    zone.install_space(fixture.slot, 1).unwrap();
    let selected = zone.switch_in_full(fixture.slot).unwrap();
    assert_eq!(selected.record, fixture.record.id);
    assert_eq!(selected.result, Some(0));
    assert_eq!(
        zone.expire_timer(
            fixture.slot,
            2000,
            carrick_personality_linux::sched::ETIMEDOUT_RESULT,
            &|owned| {
                crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
            },
        ),
        Ok(false),
        "the old timed wait must not complete a second time",
    );
    assert_eq!(zone.timer_node_count(), 0);
    let mut entry = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            &make(fixture.address),
            &mut service,
        )
        .unwrap();
    assert!(matches!(
        entry.resume_checkpoint(|_| Ok(None)),
        Ok(NativeResume::NoPending)
    ));
    assert!(entry.take_handoff_receipt().is_none());
    assert!(entry.take_run_failure().is_none());
    assert!(
        matches!(entry.native_futex(FutexCall { args: [0x1000, 1, 1, 0, 0, 0] }, &mut copy),
        Some(LifecycleOutcome::Returned { result, .. }) if result.raw() == 0),
        "exit consumed the join wait exactly once"
    );
    assert_eq!(zone.slot(fixture.slot).queued(), 0);
    assert_eq!(zone.slot(child_slot).queued(), 0);
    FUTEX_MAPPING.with(|slot| slot.set(None));
}

#[test]
fn native_clear_tid_stopped_join_driver_x86() {
    clear_tid_stopped_join_driver::<ParkedContextWords, carrick_mmu_core::x86::owner_mmu::X86Mmu>(
        words,
        carrick_personality_linux::crossing::HostCrossingSet::X86,
    );
}
#[test]
fn native_clear_tid_stopped_join_driver_aarch64() {
    clear_tid_stopped_join_driver::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(
        arm_words,
        carrick_personality_linux::crossing::HostCrossingSet::Aarch64,
    );
}
