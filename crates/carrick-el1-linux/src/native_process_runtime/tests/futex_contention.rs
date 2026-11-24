//! Production native futex adapter contention witnesses on both contexts.
use super::*;
use carrick_core::user_copy::{CopyOutcome, GuestCopyRequest, UserCopy};
use carrick_guest_arch::{Access, GuestLen};
use carrick_personality_linux::sched::FutexCall;
use carrick_sched_core::process::identity_allocator::ClaimKind;
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
        // SAFETY: one lazily committed mapping owns this zero-valid compact zone for
        // the entire leaked host-test fixture lifetime.
        let zone = carrick_zeroed_pages::ZeroedBox::leak(unsafe {
            carrick_zeroed_pages::ZeroedBox::<ZoneTables<C>>::new_zeroed()
        });
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
        seed_fixture_namespace(zone, task, page);
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

#[test]
fn native_misaligned_realtime_bitset_futex_x86_is_einval() {
    let fixture =
        Fixture::<ParkedContextWords>::new::<carrick_mmu_core::x86::owner_mmu::X86Mmu>(words);
    let zone = fixture.zone;
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
        waker_slot: carrick_sched_core::SlotId::new(0),
        on_signal_clock: None,
    };
    let source = BornInZoneSource {
        zone,
        slot: fixture.slot,
    };
    let saved = words(fixture.address);
    let mut copy = Copy {
        refuse_word: false,
        loads: 0,
        word: 0,
    };
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
    for offset in [1, 2, 3] {
        for mask in [0, 1, u32::MAX as u64] {
            let outcome = entry.native_futex(
                FutexCall {
                    args: [0x1000 + offset, 393, 1, 0, 0, mask],
                },
                &mut copy,
            );
            assert!(
                matches!(outcome, Some(LifecycleOutcome::Returned { result, .. }) if result.raw() == -22),
                "misaligned op 393 must return errno 22, not decline to errno 38"
            );
            assert_eq!(copy.loads, 0, "invalid operand requires no memory access");
        }
    }
}

fn episode<
    C: ProcessContext + carrick_sched_core::CensusContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
>(
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
        waker_slot: carrick_sched_core::SlotId::new(0),
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
    let park = zone.parked_futex_snapshot(fixture.record).unwrap();
    let compared = park.enrollment.unwrap();
    assert_eq!(compared.address, UserVa::new(0x1000));
    assert_eq!(compared.expected, copy.word);
    assert_eq!(compared.observed, copy.word);
    if timed {
        assert_eq!(
            zone.timer_deadline(fixture.slot),
            Some(2000),
            "one second admitted at tick 1000 must not restart at tick 2000"
        );
    }
    FUTEX_MAPPING.with(|slot| slot.set(None));
}

/// #2306: a Busy mapping probe is "not now". The futex keeps its exact
/// syscall in the owner-service continuation and reruns after the carrier
/// settles, never ending the run (the former run failure) or returning EAGAIN.
fn busy_once_episode<C: ProcessContext + 'static, B: carrick_mmu_core::owner_mmu::OwnerForkMmu>(
    make: impl Fn(AddressContext<RootGpa>) -> C,
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
        waker_slot: carrick_sched_core::SlotId::new(0),
        on_signal_clock: None,
    };
    FUTEX_MAPPING.with(|slot| slot.set(Some(Err(NativeProcessError::Busy))));
    let source = BornInZoneSource {
        zone,
        slot: fixture.slot,
    };
    let saved = make(fixture.address);
    let mut copy = Copy {
        refuse_word: false,
        loads: 0,
        word: 0,
    };
    let call = FutexCall {
        args: [0x1000, 0, 0, 0, 0, 0],
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
        assert_eq!(
            entry.take_run_failure(),
            None,
            "a Busy mapping probe is not now, never a run failure"
        );
        assert!(
            entry.take_handoff_receipt().is_some(),
            "must release execution capacity"
        );
    }
    assert!(zone.slot(fixture.slot).current().is_none());
    assert_eq!(copy.loads, 0, "no word is read before the mapping admits");
    FUTEX_MAPPING.with(|slot| slot.set(Some(Ok(true))));
    assert!(matches!(
        super::complete_carrier_work(zone, fixture.task, fixture.slot, fixture.record),
        carrick_core_abi::service::ServiceOperation::CarrierWork { .. }
    ));
    assert_eq!(
        zone.switch_in_full(fixture.slot).unwrap().record,
        fixture.record.id
    );
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
    // The rerun admits the mapping and parks on the unchanged word.
    assert!(matches!(
        entry.native_futex(call, &mut copy),
        Some(LifecycleOutcome::Transferred { .. })
    ));
    assert!(entry.take_run_failure().is_none());
    assert!(entry.take_handoff_receipt().is_some());
    assert_eq!(copy.loads, 1);
    FUTEX_MAPPING.with(|slot| slot.set(None));
}

#[test]
fn native_futex_mapping_busy_once_then_waits_x86() {
    busy_once_episode::<ParkedContextWords, carrick_mmu_core::x86::owner_mmu::X86Mmu>(words);
}
#[test]
fn native_futex_mapping_busy_once_then_waits_aarch64() {
    busy_once_episode::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(arm_words);
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
    join: [u64; 6],
) where
    C: ProcessContext + crate::dispatch::DispatchContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
{
    use carrick_el1_abi::{BornRecord, EntryIdentity, Lifecycle, ThreadIdentity};
    use carrick_personality_linux::dispatch::{CompletionRoute, dispatch};
    use carrick_sched_core::Claim;
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
    zone.namespace().with_view(&ShortLockSpin, |ns| {
        ns.reserve_exact(42, ClaimKind::Thread).unwrap();
    });
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
        waker_slot: carrick_sched_core::SlotId::new(0),
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
            entry.native_futex(FutexCall { args: join }, &mut copy),
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
    // The exiting member's entry runs on its own slot, as its production
    // service does.
    service.waker_slot = child_slot;
    crate::sched::object_wait::clear_test_wake_trace();
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
        {
            let mut pending: crate::dispatch::El1PendingFamilies<
                '_,
                '_,
                _,
                crate::sched::FakeCpu,
                crate::sched::HardwareUserWord,
                _,
                C,
            > = crate::dispatch::El1PendingFamilies {
                futex_argument0: None,
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
        }
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
    // The joiner's only driver is away: the wake still finished in the ring
    // (#1941), and the production wake queued the joiner on that driver's
    // slot, which owns it and serves it at `step_back`. Nothing is left on
    // the exiting member's slot for a host boundary to relocate (#1961
    // review: no shipping boundary relocates a waker's queue).
    assert!(
        matches!(
            zone.record(fixture.record.id).claim(),
            Claim::Queued { slot, .. } if slot == fixture.slot
        ),
        "the joiner waits on its own driver's slot: {:?}",
        zone.record(fixture.record.id).claim()
    );
    assert_eq!(zone.slot(child_slot).queued(), 0);
    assert_eq!(zone.counters.el1_misplaced.load(Ordering::Acquire), 0);
    // The waker's production effects ring no doorbell, on its slot or any
    // other, and send no SGI: the joiner's slot is stopped, and its driver
    // owes itself the reschedule on re-entry (`reschedule_owed`).
    assert_eq!(
        crate::sched::object_wait::test_host_work_trace(),
        [],
        "no host boundary owed for the joiner"
    );
    assert_eq!(crate::sched::object_wait::test_wake_trace(), []);
    assert!(zone.reschedule_owed(fixture.slot));
    service.waker_slot = fixture.slot;
    // Fixed scheduler steps only: no polling or host blocking waits. The guest
    // wait above is timed, and returning the driver consumes one completion.
    zone.step_back(fixture.slot, 1);
    zone.enter_guest(fixture.slot);
    zone.install_space(fixture.slot, 1).unwrap();
    let selected = zone.switch_in_full(fixture.slot).unwrap();
    assert_eq!(selected.record, fixture.record.id);
    assert_eq!(selected.result, Some(0));
    if join[3] != 0 {
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
    }
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

/// A timed shared `FUTEX_WAIT` on the clear-child-tid word.
const TIMED_SHARED_WAIT: [u64; 6] = [0x1000, 0, 42, 0x2000, 0, 0];
/// glibc's `pthread_join` wait as traced in the Docker oracle (#2124): shared
/// `FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME` (op 265), no timeout, and
/// `FUTEX_BITSET_MATCH_ANY`. Linux answers 0 once the exit clears the tid.
const GLIBC_PTHREAD_JOIN_WAIT: [u64; 6] = [0x1000, 265, 42, 0, 0, 0xffff_ffff];

#[test]
fn native_clear_tid_stopped_join_driver_x86() {
    clear_tid_stopped_join_driver::<ParkedContextWords, carrick_mmu_core::x86::owner_mmu::X86Mmu>(
        words,
        carrick_personality_linux::crossing::HostCrossingSet::X86,
        TIMED_SHARED_WAIT,
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
        TIMED_SHARED_WAIT,
    );
}
/// The x86 CPL0 native futex entry. AArch64 EL1 serves futex on its
/// scheduler instead; its witness drives that production entry
/// (`aarch64_process_tests::arm_glibc_pthread_join_shared_bitset_wait_wakes_on_child_exit`).
#[test]
fn native_glibc_pthread_join_shared_bitset_wait_x86() {
    clear_tid_stopped_join_driver::<ParkedContextWords, carrick_mmu_core::x86::owner_mmu::X86Mmu>(
        words,
        carrick_personality_linux::crossing::HostCrossingSet::X86,
        GLIBC_PTHREAD_JOIN_WAIT,
    );
}

// ---------------------------------------------------------------------------
// Real mapping-root contention (issue #1922).
//
// The episodes above inject the refusal through the host-test service, so they
// cannot show what the real reservation owner returns. These two witnesses hold
// an actual admitted, notified mapping root on one slot and drive the
// production `private_anonymous_futex_mapping` on another. The owner must
// answer with its own `PortalOwnerWait` on the first probe (enrolled once, no
// retry while the root is held) and admit the same query after the real
// release. Both ISA portal paths are covered: the AArch64 EL1 portal over
// `Aarch64ParkedContext` and the x86 CPL0 portal over `ParkedContextWords`.
// ---------------------------------------------------------------------------

use carrick_core_abi::PortalWaitCause;

const HELD_SLOT: u32 = 1;
const PROBE_SLOT: u32 = 2;

/// A different slot owns the real root; the probe must return that holder's
/// notification, stay parked without a redispatch, and succeed after release.
fn contention_keeps_owner_notification<
    'a,
    P: carrick_core_abi::PinnedMetadataExtent,
    Policy: carrick_core::mm::reservation::ReservationPolicy,
    Geometry: carrick_core::mm::reservation::ReservationGeometry,
    Venue: carrick_core::mm::transaction::OwnerVenue<C>,
    B: carrick_mmu_core::owner_mmu::OwnerMmu,
    C: ProcessContext + 'static,
>(
    portal: &carrick_core::mm::transaction::MmPortal<'a, P, Policy, Geometry, Venue, B, C>,
    zone: &ZoneTables<C>,
    handle: carrick_core_abi::El1MmHandle,
    address: UserVa,
) {
    let mut held = portal
        .root(handle.mm(), HELD_SLOT)
        .expect("the holder takes the real admitted root");
    assert!(
        held.mapping(address.raw()).is_some(),
        "the held root must hold the private anonymous mapping under test"
    );

    let wait = match private_anonymous_futex_mapping(portal, handle, PROBE_SLOT, address) {
        Err(NativeProcessError::OwnerWait(wait)) => wait,
        other => panic!("real root contention must return the owner's wait, got {other:?}"),
    };
    assert_eq!(
        wait.cause(),
        PortalWaitCause::Reservations,
        "mapping admission contends on the reservation root"
    );
    assert_eq!(wait.handle(), handle, "the wait names the authenticated MM");
    assert!(
        held.mapping(address.raw()).is_some(),
        "the probe must not retry or steal the root while the holder owns it"
    );
    let entry = zone
        .space_entry(NonZeroU64::new(handle.mm().raw()).unwrap())
        .expect("the admitted MM has a live space entry");
    let observed = entry
        .notifications(handle.incarnation())
        .expect("the live notification source matches the handle")
        .observe(SpaceWaitCause::Reservations);
    assert_eq!(
        wait.revision(),
        observed.revision(),
        "the wait carries the revision observed before the root lock probe"
    );

    // Enrol the exact returned wait once, as the production owner-wait path
    // does, and prove only the real release can complete it.
    let enrollment =
        carrick_core_abi::wait::PortalWaitEnrollment::for_owner(zone, handle, wait).unwrap();
    let record = zone
        .alloc_record(ThreadIdentity {
            tid: 909,
            serial: 1,
            mm: handle.mm().raw(),
            file_table: 1,
            generation: 1,
            affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
            affinity: 0,
            lifecycle_page: 0,
            control_slot: 0,
        })
        .unwrap();
    let operation = carrick_sched_core::object_wait::OperationToken::new(701, 11).unwrap();
    enrollment
        .park_host(record, operation, &|effects| {
            let _ = effects.defer_handbacks();
        })
        .unwrap();
    assert!(matches!(
        zone.record(record).claim(),
        carrick_sched_core::Claim::Parked { .. }
    ));
    let mut delivered = Vec::new();
    zone.take_completion_handbacks(&carrick_sched_core::BoundedSpin(0), &mut |record| {
        delivered.push(record)
    });
    assert!(
        delivered.is_empty(),
        "no redispatch or handback while the holder still owns the root"
    );

    drop(held);
    zone.take_completion_handbacks(&carrick_sched_core::BoundedSpin(0), &mut |record| {
        delivered.push(record)
    });
    assert_eq!(
        delivered,
        [zone.record_ref(record)],
        "the real root release delivers exactly one handback"
    );
    zone.take_completion_handbacks(&carrick_sched_core::BoundedSpin(0), &mut |_| {
        panic!("a single release must not complete the waiter twice")
    });
    zone.free_record(record);

    // The same authenticated handle now acquires the released root and answers
    // from the real mapping tree.
    assert_eq!(
        private_anonymous_futex_mapping(portal, handle, PROBE_SLOT, address),
        Ok(true),
        "the private anonymous mapping is admitted after release"
    );
    assert_eq!(
        private_anonymous_futex_mapping(
            portal,
            handle,
            PROBE_SLOT,
            UserVa::new(address.raw() + 0x0100_0000)
        ),
        Ok(false),
        "an address outside the mapping stays unadmitted"
    );
}

fn x86_deliver(
    _: &ZoneTables<carrick_sched_core::ParkedContextWords>,
    _: carrick_sched_core::Waker,
    effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
        '_,
        carrick_sched_core::ParkedContextWords,
    >,
) {
    // The VM-free carrier boundary retains the completed record for
    // `take_completion_handbacks`; the guest venue owns SGI delivery.
    let _ = effects.defer_handbacks();
}

struct X86Venue;
impl carrick_core::mm::transaction::OwnerVenue<carrick_sched_core::ParkedContextWords>
    for X86Venue
{
    fn space_access(
        zone: &ZoneTables<carrick_sched_core::ParkedContextWords>,
        slot: SlotId,
    ) -> carrick_sched_core::spaces::notification::SpaceAccess<
        '_,
        carrick_sched_core::ParkedContextWords,
    > {
        carrick_core::wait::space_access(zone, slot, x86_deliver)
    }
    fn deliver_completion(
        _: &ZoneTables<carrick_sched_core::ParkedContextWords>,
        _: SlotId,
        effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_sched_core::ParkedContextWords,
        >,
    ) {
        let _ = effects.defer_handbacks();
    }
    fn encode_error(_: carrick_core::mm::transaction::MmError) -> u32 {
        1
    }
    fn cancelled_copy_code() -> u32 {
        1
    }
}

#[test]
fn real_mapping_root_contention_keeps_notification_aarch64() {
    use crate::mm_portal::test_support::{ROOT, Region, VA, admit_notified, nodes};
    let region = Region::new();
    let zone = region.zone();
    let mm = admit_notified(&region, 77, ROOT, 1, 0);
    let view = nodes(&region);
    let portal: crate::mm_portal::MmPortal<'_, crate::mm_portal::test_support::NoPin> =
        crate::mm_portal::MmPortal::new(
            NonZeroU64::new(1).unwrap(),
            region.table(),
            &zone.spaces,
            &view,
        )
        .with_zone(zone)
        .unwrap();
    let handle = portal.admitted_handle(mm, 0).unwrap();
    contention_keeps_owner_notification(&portal, zone, handle, UserVa::new(VA));
}

#[test]
fn real_mapping_root_contention_keeps_notification_x86() {
    use crate::mm_portal::test_support::{
        NoPin, ROOT, Region, VA, admit_notified_x86, x86_nodes, x86_roots, x86_zone,
    };
    type X86Portal<'a> = carrick_core::mm::transaction::MmPortal<
        'a,
        NoPin,
        carrick_personality_linux::mm::LinuxReservationPolicy,
        carrick_el1::memory::reservations::X86Cpl0ReservationGeometry,
        X86Venue,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
        carrick_sched_core::ParkedContextWords,
    >;
    let region = Region::new();
    let zone = x86_zone(&region);
    let mm = admit_notified_x86(&region, 77, ROOT, 1, 0);
    let view = x86_nodes(&region);
    let portal: X86Portal<'_> = carrick_core::mm::transaction::MmPortal::new(
        NonZeroU64::new(1).unwrap(),
        x86_roots(&region),
        &zone.spaces,
        &view,
    )
    .with_zone(zone)
    .unwrap()
    .with_mmu(carrick_mmu_core::x86::owner_mmu::X86Mmu);
    let handle = portal.admitted_handle(mm, 0).unwrap();
    contention_keeps_owner_notification(&portal, zone, handle, UserVa::new(VA));
}

struct ExitStatusFrame(
    carrick_personality_linux::crossing::HostCrossingSet,
    SlotId,
    u64,
);
impl carrick_personality_linux::dispatch::SyscallFrame for ExitStatusFrame {
    fn canonical_ordinal(&self) -> carrick_syscall_abi::CanonicalNr {
        carrick_syscall_abi::CanonicalNr::new(carrick_personality_linux::lifecycle::SYS_EXIT as u64)
    }
    fn argument(&self, index: usize) -> Option<u64> {
        Some(if index == 0 { self.2 } else { 0 })
    }
    fn result(&self) -> carrick_guest_arch::NativeReturnWord {
        carrick_guest_arch::NativeReturnWord(0)
    }
    fn set_result(&mut self, _: carrick_guest_arch::NativeReturnWord) {}
    fn slot(&self) -> Option<SlotId> {
        Some(self.1)
    }
    fn task_index(&self) -> usize {
        0
    }
    fn user_sp(&self) -> Option<UserVa> {
        Some(UserVa::new(0x8000))
    }
}
impl crate::dispatch::GuestDispatchFrame for ExitStatusFrame {
    fn restart_syscall(&mut self) {}
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

fn spawn_registered_born_member<C: ProcessContext + 'static>(
    fixture: &Fixture<C>,
    make: &impl Fn(AddressContext<RootGpa>) -> C,
    control: &'static ThreadControlSlot,
    stock_index: usize,
) -> (&'static CurrentTask, carrick_el1_abi::RecordId) {
    use carrick_el1_abi::{BornRecord, EntryIdentity, Lifecycle, ThreadIdentity};
    let slot = SlotId::new((stock_index + 1) as u8);
    let cpu_id = (stock_index + 1) as u32;
    let tid = 42 + stock_index as u32;
    let serial = 102 + stock_index as u64;
    let zone = fixture.zone;
    let affinity = 1u64 << cpu_id;
    zone.drive(slot, u64::from(cpu_id + 1));
    zone.publish_slot(slot, 1, Some(cpu_id), affinity);
    zone.enter_guest(slot);
    zone.install_space(slot, 1).unwrap();

    let birth = carrick_core_abi::BirthSerial::of_task(TaskSerial::from_raw_u64(serial).unwrap());
    let entry = fixture
        .page
        .stock(
            stock_index,
            EntryIdentity {
                tid,
                visible_tid: tid,
                thread_serial: serial,
                birth,
                uid_credit: 0,
            },
        )
        .unwrap();
    fixture
        .page
        .bind_control_address(entry, control as *const _ as u64)
        .unwrap();
    control
        .reset_for_birth(carrick_el1_abi::BlockedMask(0), 0, entry)
        .unwrap();
    assert!(control.publish_visible_tid(tid));
    control.publish_host_birth_identity(
        carrick_core::terminal::ThreadBirthIdentity::from_parts(
            carrick_core_abi::EntryTaskKey::from_raw(u64::from(tid)),
            birth,
            carrick_core_abi::EntryThreadGeneration::from_raw(serial),
        )
        .unwrap(),
    );
    let claim = fixture.page.claim(entry).unwrap();
    fixture
        .page
        .record_born(
            claim,
            BornRecord {
                caller_task: 41,
                caller_serial: 101,
                clone_flags: 0x10000,
                clear_child_tid: 0,
                blocked: carrick_el1_abi::BlockedMask(0),
            },
        )
        .unwrap();
    fixture.page.thread_born().unwrap();
    fixture.page.publish(entry).unwrap();

    let task = Box::leak(Box::new(CurrentTask::new()));
    task.set(
        carrick_el1_abi::El1TaskId::from_linux_tid(tid as i32),
        carrick_core_abi::SnapshotGeneration::from_raw(serial),
        5,
    );
    task.mm.key.store(1, Ordering::Release);
    task.mm.thread_generation.store(serial, Ordering::Release);
    task.publish_visible_pid(41);
    task.publish_root_generation(fixture.address.generation);
    task.publish_lifecycle(fixture.page as *const _ as u64, control as *const _ as u64);
    zone.namespace().with_view(&ShortLockSpin, |ns| {
        ns.reserve_exact(tid as i32, ClaimKind::Thread).unwrap();
    });

    let record = zone
        .alloc_record(ThreadIdentity {
            tid: u64::from(tid),
            serial,
            mm: 1,
            file_table: 5,
            generation: serial,
            affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
            affinity,
            lifecycle_page: fixture.page as *const _ as u64,
            control_slot: control as *const _ as u64,
        })
        .unwrap();
    assert!(zone.mark_native_owned(record));
    // SAFETY: this newly allocated record is unpublished and fixture-owned.
    unsafe {
        *zone.record(record).ctx_mut() = make(fixture.address);
    }
    assert!(zone.requeue_preempted(slot, record).is_queued());
    assert_eq!(zone.switch_in_full(slot).unwrap().record, record);
    control.bind_zone_record(zone.record_ref(record));
    fixture
        .registry
        .register_thread(
            BornInZoneSource { zone, slot },
            task,
            fixture.address,
            fixture.page,
            control,
        )
        .unwrap();
    assert!(zone.mark_native_owned(record));
    (task, record)
}

/// #2932: when a member has already passed `resume_owned_continuation` and
/// `raw_exit_is_process` (`page.live() == 3`), and its leader concurrently
/// closes the lifecycle gate in `exit_group(38)` (`page.live() == 2`), the
/// member's raw `SYS_exit` (`x86` 60 / `aarch64` 93) must retire in ring
/// (`Suspended`, never `HostCustody`) and wake the closing leader.
fn closing_group_raw_exit_retires_in_ring<C, B>(
    make: impl Fn(AddressContext<RootGpa>) -> C,
    isa: carrick_personality_linux::crossing::HostCrossingSet,
) where
    C: ProcessContext + crate::dispatch::DispatchContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
{
    use carrick_el1_abi::Lifecycle;
    use carrick_personality_linux::dispatch::{CompletionRoute, dispatch};

    let fixture = Fixture::<C>::new::<B>(&make);
    let zone = fixture.zone;
    assert!(zone.mark_native_owned(fixture.record.id));
    let slot1 = SlotId::new(1);
    let slot2 = SlotId::new(2);

    let controls = Box::leak(Box::new([
        ThreadControlSlot::new(),
        ThreadControlSlot::new(),
    ]));
    let control1 = &controls[0];
    let control2 = &controls[1];
    let (task1, member1) = spawn_registered_born_member(&fixture, &make, control1, 0);
    let (task2, member2) = spawn_registered_born_member(&fixture, &make, control2, 1);
    assert_eq!(fixture.page.live(), 3);

    struct ClosingRaceVenue<'a, F> {
        page: &'a ThreadLifecyclePage,
        control: &'a ThreadControlSlot,
        close_group: core::cell::RefCell<Option<F>>,
        calls: core::cell::Cell<usize>,
    }
    impl<F: FnOnce()> crate::thread_setup::LifecycleVenue for ClosingRaceVenue<'_, F> {
        fn thread<'a>(
            &'a self,
            _: &'a CurrentTask,
        ) -> Option<carrick_personality_linux::thread::LifecycleThread<'a>> {
            let seen = self.calls.get();
            self.calls.set(seen + 1);
            if seen == 1
                && let Some(close) = self.close_group.borrow_mut().take()
            {
                close();
            }
            Some(carrick_personality_linux::thread::LifecycleThread {
                page: self.page,
                slot: self.control,
            })
        }
        fn born_slot(&self, _: &ThreadLifecyclePage, _: EntryRef) -> Option<&ThreadControlSlot> {
            None
        }
    }

    let mut service1 = Physical {
        zone,
        page: fixture.page,
        controls: &controls[..],
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
        waker_slot: slot1,
        on_signal_clock: None,
    };

    let counters = carrick_el1_abi::Counters::new();
    let names = carrick_el1_abi::InotifyNameCache::new();
    {
        let member1_ref = zone.record_ref(member1);
        let venue = ClosingRaceVenue {
            page: fixture.page,
            control: control1,
            close_group: core::cell::RefCell::new(Some(|| {
                let mut leader_service = Physical {
                    zone,
                    page: fixture.page,
                    controls: &controls[..],
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
                    waker_slot: fixture.slot,
                    on_signal_clock: None,
                };
                let mut leader = fixture
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
                        &mut leader_service,
                    )
                    .unwrap();
                assert!(matches!(
                    leader.exit_group(38),
                    LifecycleOutcome::Transferred { .. }
                ));
                assert!(leader.take_handoff_receipt().is_some());
                assert!(leader.take_run_failure().is_none());
                zone.clear_current(fixture.slot);
                assert_eq!(fixture.page.gate(), carrick_el1_abi::GateState::Closed);
                assert_eq!(fixture.page.live(), 2);
            })),
            calls: core::cell::Cell::new(0),
        };
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                BornInZoneSource { zone, slot: slot1 },
                task1,
                fixture.address,
                &make(fixture.address),
                &mut service1,
            )
            .unwrap();
        {
            let mut frame = ExitStatusFrame(isa, slot1, 0);
            let mut pending: crate::dispatch::El1PendingFamilies<
                '_,
                '_,
                _,
                crate::sched::FakeCpu,
                crate::sched::HardwareUserWord,
                _,
                C,
            > = crate::dispatch::El1PendingFamilies {
                futex_argument0: None,
                handoff: None,
                lifecycle_user: None,
                frame: &mut frame,
                counters: &counters,
                current_tasks: core::slice::from_ref(task1),
                fd_map: &[],
                object_table: &[],
                open_table: &[],
                inotify_table: &[],
                name_cache: &names,
                zone: None,
                ipc: None,
                lifecycle: Some(&venue),
                process: Some(entry.as_mut()),
                source: Some(BornInZoneSource { zone, slot: slot1 }),
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
                    &mut pending,
                ),
                CompletionRoute::Suspended,
                "closing-group raw exit on {isa:?} must retire in ring, not host custody"
            );
        }
        assert_eq!(
            counters.lifecycle_declines[carrick_el1_abi::LifecycleDecline::ExitGate as usize]
                .load(Ordering::Acquire),
            1
        );
        assert!(entry.take_handoff_receipt().is_none());
        assert!(entry.take_run_failure().is_none());
        drop(entry);
        assert!(zone.slot(slot1).current().is_none());
        assert!(zone.live(member1_ref).is_none());
        assert_eq!(fixture.page.live(), 1);
    }

    {
        let member2_ref = zone.record_ref(member2);
        let venue = ClosingRaceVenue {
            page: fixture.page,
            control: control2,
            close_group: core::cell::RefCell::new(None::<fn()>),
            calls: core::cell::Cell::new(0),
        };
        let mut service2 = Physical {
            zone,
            page: fixture.page,
            controls: &controls[..],
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
            waker_slot: slot2,
            on_signal_clock: None,
        };
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                BornInZoneSource { zone, slot: slot2 },
                task2,
                fixture.address,
                &make(fixture.address),
                &mut service2,
            )
            .unwrap();
        {
            let mut frame = ExitStatusFrame(isa, slot2, 0);
            let mut pending: crate::dispatch::El1PendingFamilies<
                '_,
                '_,
                _,
                crate::sched::FakeCpu,
                crate::sched::HardwareUserWord,
                _,
                C,
            > = crate::dispatch::El1PendingFamilies {
                futex_argument0: None,
                handoff: None,
                lifecycle_user: None,
                frame: &mut frame,
                counters: &counters,
                current_tasks: core::slice::from_ref(task2),
                fd_map: &[],
                object_table: &[],
                open_table: &[],
                inotify_table: &[],
                name_cache: &names,
                zone: None,
                ipc: None,
                lifecycle: Some(&venue),
                process: Some(entry.as_mut()),
                source: Some(BornInZoneSource { zone, slot: slot2 }),
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
                    &mut pending,
                ),
                CompletionRoute::Suspended,
            );
        }
        assert!(entry.take_handoff_receipt().is_none());
        assert!(entry.take_run_failure().is_none());
        drop(entry);
        assert!(zone.slot(slot2).current().is_none());
        assert!(zone.live(member2_ref).is_none());
        assert_eq!(fixture.page.live(), 0);
    }

    let woken_slot = [fixture.slot, slot1, slot2]
        .into_iter()
        .find(|slot| zone.slot(*slot).queued() != 0)
        .expect("final member retirement wakes the closing leader");
    zone.install_space(woken_slot, 1).unwrap();
    assert_eq!(
        zone.switch_in_full(woken_slot).unwrap().record,
        fixture.record.id
    );
    let mut leader_service = Physical {
        zone,
        page: fixture.page,
        controls: &controls[..],
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
        waker_slot: woken_slot,
        on_signal_clock: None,
    };
    let mut leader = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone,
                slot: woken_slot,
            },
            fixture.task,
            fixture.address,
            &make(fixture.address),
            &mut leader_service,
        )
        .unwrap();
    let resumed = leader.resume_checkpoint(|_| Ok(None)).unwrap();
    let NativeResume::Left(Some(status)) = resumed else {
        panic!("expected closing root exit status");
    };
    assert_eq!(
        status.to_termination_status(),
        carrick_sched_core::process::TerminationStatus::exited(38)
    );
}

#[test]
fn closing_group_raw_exit_retires_in_ring_x86() {
    ENTRYLESS_RETIREMENT.with(|owner| owner.set(EntrylessRetirement::Ring));
    closing_group_raw_exit_retires_in_ring::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(
        words,
        carrick_personality_linux::crossing::HostCrossingSet::X86,
    );
    ENTRYLESS_RETIREMENT.with(|owner| owner.set(EntrylessRetirement::HostThread));
}

#[test]
fn closing_group_raw_exit_retires_in_ring_aarch64() {
    closing_group_raw_exit_retires_in_ring::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(
        arm_words,
        carrick_personality_linux::crossing::HostCrossingSet::Aarch64,
    );
}

/// #2932: if two threads concurrently call raw `SYS_exit`, both observe
/// `raw_exit_is_process == false` (`page.live() == 2`), and the sibling finishes
/// reserving the penultimate unit before `serve_exit` reaches `reserve_member`,
/// the losing caller hits `ExitLast` (`Floor`) with `GateState::Open` and must
/// transition to `process_exit_group` in ring rather than `HostCustody`.
fn concurrent_raw_exit_floor_race_becomes_process_exit<C, B>(
    make: impl Fn(AddressContext<RootGpa>) -> C,
    isa: carrick_personality_linux::crossing::HostCrossingSet,
) where
    C: ProcessContext + crate::dispatch::DispatchContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
{
    use carrick_el1_abi::Lifecycle;
    use carrick_personality_linux::dispatch::{CompletionRoute, dispatch};

    let fixture = Fixture::<C>::new::<B>(&make);
    let zone = fixture.zone;
    assert!(zone.mark_native_owned(fixture.record.id));
    let member_slot = SlotId::new(1);

    let control = Box::leak(Box::new(ThreadControlSlot::new()));
    let (task, _member) = spawn_registered_born_member(&fixture, &make, control, 0);
    assert_eq!(fixture.page.live(), 2);
    assert_eq!(
        zone.release_current(fixture.slot, fixture.record.id, &ShortLockSpin),
        carrick_sched_core::CurrentRelease::Released
    );

    struct FloorRaceVenue<'a> {
        page: &'a ThreadLifecyclePage,
        caller: &'a ThreadControlSlot,
        retired_sibling: &'a ThreadControlSlot,
        calls: core::cell::Cell<usize>,
    }
    impl crate::thread_setup::LifecycleVenue for FloorRaceVenue<'_> {
        fn thread<'a>(
            &'a self,
            _: &'a CurrentTask,
        ) -> Option<carrick_personality_linux::thread::LifecycleThread<'a>> {
            let seen = self.calls.get();
            self.calls.set(seen + 1);
            if seen == 1 {
                // Simulate the sibling completing its nonfinal raw exit right
                // after `invoke` checked `raw_exit_is_process(thread.page)`.
                self.page.reserve_nonfinal_exit().unwrap().publish();
                let birth = self.retired_sibling.host_birth_identity().unwrap();
                self.page
                    .publish_exact_host_retirement(self.retired_sibling, birth.retirement());
            }
            Some(carrick_personality_linux::thread::LifecycleThread {
                page: self.page,
                slot: self.caller,
            })
        }
        fn born_slot(&self, _: &ThreadLifecyclePage, _: EntryRef) -> Option<&ThreadControlSlot> {
            None
        }
    }

    let mut service = Physical {
        zone,
        page: fixture.page,
        controls: core::slice::from_ref(control),
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
        waker_slot: member_slot,
        on_signal_clock: None,
    };
    let venue = FloorRaceVenue {
        page: fixture.page,
        caller: control,
        retired_sibling: fixture.control,
        calls: core::cell::Cell::new(0),
    };
    let counters = carrick_el1_abi::Counters::new();
    let names = carrick_el1_abi::InotifyNameCache::new();
    let mut entry = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone,
                slot: member_slot,
            },
            task,
            fixture.address,
            &make(fixture.address),
            &mut service,
        )
        .unwrap();
    {
        let mut frame = ExitStatusFrame(isa, member_slot, 38);
        let mut pending: crate::dispatch::El1PendingFamilies<
            '_,
            '_,
            _,
            crate::sched::FakeCpu,
            crate::sched::HardwareUserWord,
            _,
            C,
        > = crate::dispatch::El1PendingFamilies {
            futex_argument0: None,
            handoff: None,
            lifecycle_user: None,
            frame: &mut frame,
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
            source: Some(BornInZoneSource {
                zone,
                slot: member_slot,
            }),
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
                &mut pending,
            ),
            CompletionRoute::Suspended,
            "floor-race raw exit on {isa:?} must become process exit in ring, not host custody"
        );
    }
    assert_eq!(
        counters.lifecycle_declines[carrick_el1_abi::LifecycleDecline::ExitLast as usize]
            .load(Ordering::Acquire),
        1
    );
    assert!(entry.take_handoff_receipt().is_none());
    assert!(entry.take_run_failure().is_none());
    let status = entry
        .take_root_exit()
        .expect("last surviving thread's raw exit publishes process exit");
    assert_eq!(
        status.to_termination_status(),
        carrick_sched_core::process::TerminationStatus::exited(38)
    );
    assert_eq!(fixture.page.live(), 0);
    assert!(zone.slot(member_slot).current().is_none());
}

#[test]
fn concurrent_raw_exit_floor_race_becomes_process_exit_x86() {
    ENTRYLESS_RETIREMENT.with(|owner| owner.set(EntrylessRetirement::Ring));
    concurrent_raw_exit_floor_race_becomes_process_exit::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(
        words,
        carrick_personality_linux::crossing::HostCrossingSet::X86,
    );
    ENTRYLESS_RETIREMENT.with(|owner| owner.set(EntrylessRetirement::HostThread));
}

#[test]
fn concurrent_raw_exit_floor_race_becomes_process_exit_aarch64() {
    concurrent_raw_exit_floor_race_becomes_process_exit::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(
        arm_words,
        carrick_personality_linux::crossing::HostCrossingSet::Aarch64,
    );
}

fn arm_syscall_words(address: AddressContext<RootGpa>) -> carrick_sched_core::Aarch64ParkedContext {
    let mut native = carrick_el1_abi::ThreadCtx::ZERO;
    native.pc = 0x40_0004;
    native.sp_el0 = 0x80_0000;
    carrick_sched_core::Aarch64ParkedContext::from_parts(native, address)
}

/// #2932 verifier blocker: peer A enters raw `SYS_exit(0)` with
/// `CLONE_CHILD_CLEARTID` (`0x4000`) and reserves the penultimate live unit
/// (`page.live() == 1`), so peer A's reservation is still refundable when
/// caller B enters raw `SYS_exit(38)`. Caller B must never promote its thread
/// exit to `exit_group`: it must enrol on the reservation owner's release and
/// park, then after peer A's `NotYet` child-TID copy restores `page.live() == 2`
/// and wakes caller B, caller B reruns `SYS_exit(38)` and retires only itself
/// in ring while peer A remains live.
fn refundable_peer_raw_exit_parks_then_retires_as_thread_exit<C, B>(
    make: &'static dyn Fn(AddressContext<RootGpa>) -> C,
    isa: carrick_personality_linux::crossing::HostCrossingSet,
) where
    C: ProcessContext + crate::dispatch::DispatchContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
{
    use carrick_el1_abi::Lifecycle;
    use carrick_personality_linux::dispatch::{CompletionRoute, dispatch};

    let fixture: &'static Fixture<C> = Box::leak(Box::new(Fixture::<C>::new::<B>(make)));
    let zone = fixture.zone;
    assert!(zone.mark_native_owned(fixture.record.id));
    let slot1 = SlotId::new(1);
    let slot2 = SlotId::new(2);

    let controls: &'static [ThreadControlSlot; 2] = Box::leak(Box::new([
        ThreadControlSlot::new(),
        ThreadControlSlot::new(),
    ]));
    let control1 = &controls[0];
    let control2 = &controls[1];
    let (task1, member1) = spawn_registered_born_member(fixture, &make, control1, 0);
    let (task2, member2) = spawn_registered_born_member(fixture, &make, control2, 1);
    control1.set_clear_child_tid(0x4000);
    assert_eq!(fixture.page.live(), 3);

    // Retire the leader's membership so the two ring-born members own the final
    // two live units (`page.live() == 2`).
    assert_eq!(
        zone.release_current(fixture.slot, fixture.record.id, &ShortLockSpin),
        carrick_sched_core::CurrentRelease::Released
    );
    fixture.page.reserve_nonfinal_exit().unwrap().publish();
    let leader_birth = fixture.control.host_birth_identity().unwrap();
    fixture
        .page
        .publish_exact_host_retirement(fixture.control, leader_birth.retirement());
    assert_eq!(fixture.page.live(), 2);

    struct MemberVenue<'a> {
        page: &'a ThreadLifecyclePage,
        control: &'a ThreadControlSlot,
    }
    impl crate::thread_setup::LifecycleVenue for MemberVenue<'_> {
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

    let member1_ref = zone.record_ref(member1);
    let member2_ref = zone.record_ref(member2);
    let caller_b_ran = Arc::new(core::sync::atomic::AtomicBool::new(false));
    let caller_b_ran_hook = caller_b_ran.clone();

    fail_signal_copies(&[NativeProcessError::Busy]);
    ENTROPY_PREPARE_BUSY_ONCE.with(|busy| busy.set(true));
    set_before_signal_copy_hook(Box::new(move |address| {
        assert_eq!(address, UserVa::new(0x4000));
        assert_eq!(
            fixture.page.live(),
            1,
            "peer A must hold its refundable reservation during clear_child_tid copy"
        );
        let counters_b = carrick_el1_abi::Counters::new();
        let names_b = carrick_el1_abi::InotifyNameCache::new();
        let venue_b = MemberVenue {
            page: fixture.page,
            control: control2,
        };
        let mut service_b = Physical {
            zone,
            page: fixture.page,
            controls: &controls[..],
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
            waker_slot: slot2,
            on_signal_clock: None,
        };
        let mut entry_b = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                BornInZoneSource { zone, slot: slot2 },
                task2,
                fixture.address,
                &make(fixture.address),
                &mut service_b,
            )
            .unwrap();
        let route_b = {
            let mut frame_b = ExitStatusFrame(isa, slot2, 38);
            let mut pending_b: crate::dispatch::El1PendingFamilies<
                '_,
                '_,
                _,
                crate::sched::FakeCpu,
                crate::sched::HardwareUserWord,
                _,
                C,
            > = crate::dispatch::El1PendingFamilies {
                futex_argument0: None,
                handoff: None,
                lifecycle_user: None,
                frame: &mut frame_b,
                counters: &counters_b,
                current_tasks: core::slice::from_ref(task2),
                fd_map: &[],
                object_table: &[],
                open_table: &[],
                inotify_table: &[],
                name_cache: &names_b,
                zone: None,
                ipc: None,
                lifecycle: Some(&venue_b),
                process: Some(entry_b.as_mut()),
                source: Some(BornInZoneSource { zone, slot: slot2 }),
                anonymous: None,
                cache_lookup: |_| core::ptr::null_mut(),
            };
            dispatch(
                carrick_syscall_abi::CanonicalNr::new(
                    carrick_personality_linux::lifecycle::SYS_EXIT as u64,
                )
                .raw(),
                u64::MAX,
                &mut pending_b,
            )
        };
        assert_eq!(
            route_b,
            CompletionRoute::Suspended,
            "caller B raw exit on {isa:?} must suspend on peer A's refundable reservation"
        );
        assert_eq!(
            fixture.page.gate(),
            carrick_el1_abi::GateState::Open,
            "caller B raw exit promoted to exit_group while peer A's reservation was refundable"
        );
        assert!(
            entry_b.take_root_exit().is_none(),
            "caller B raw exit published root exit while peer A's reservation was refundable"
        );
        assert!(
            entry_b.take_handoff_receipt().is_none(),
            "dispatch must consume caller B's handoff receipt on CompletionRoute::Suspended"
        );
        assert!(zone.slot(slot2).current().is_none());
        assert!(entry_b.take_run_failure().is_none());
        assert!(
            matches!(
                zone.record(member2).claim(),
                carrick_sched_core::Claim::Parked { .. }
            ),
            "caller B must park enrolled on reservation release"
        );
        caller_b_ran_hook.store(true, Ordering::Release);
    }));

    let counters_a = carrick_el1_abi::Counters::new();
    let names_a = carrick_el1_abi::InotifyNameCache::new();
    let venue_a = MemberVenue {
        page: fixture.page,
        control: control1,
    };
    let mut service_a = Physical {
        zone,
        page: fixture.page,
        controls: &controls[..],
        copies: Vec::new(),
        tid_words: BTreeMap::from([((1, 0x4000), 42)]),
        tid_wakes: 0,
        tid_writes: Vec::new(),
        child_copy_error: None,
        prepare_copy_error: None,
        child_copy_error_at: None,
        on_copy_complete: None,
        native_ipc: None,
        refuse_copy: false,
        waker_slot: slot1,
        on_signal_clock: None,
    };
    let mut entry_a = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource { zone, slot: slot1 },
            task1,
            fixture.address,
            &make(fixture.address),
            &mut service_a,
        )
        .unwrap();
    {
        let mut frame_a = ExitStatusFrame(isa, slot1, 0);
        let mut pending_a: crate::dispatch::El1PendingFamilies<
            '_,
            '_,
            _,
            crate::sched::FakeCpu,
            crate::sched::HardwareUserWord,
            _,
            C,
        > = crate::dispatch::El1PendingFamilies {
            futex_argument0: None,
            handoff: None,
            lifecycle_user: None,
            frame: &mut frame_a,
            counters: &counters_a,
            current_tasks: core::slice::from_ref(task1),
            fd_map: &[],
            object_table: &[],
            open_table: &[],
            inotify_table: &[],
            name_cache: &names_a,
            zone: None,
            ipc: None,
            lifecycle: Some(&venue_a),
            process: Some(entry_a.as_mut()),
            source: Some(BornInZoneSource { zone, slot: slot1 }),
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
                &mut pending_a,
            ),
            CompletionRoute::Suspended,
            "peer A NotYet clear_child_tid copy must park peer A after refunding its reservation"
        );
    }
    assert!(caller_b_ran.load(Ordering::Acquire));
    assert!(entry_a.take_handoff_receipt().is_none());
    assert!(zone.slot(slot1).current().is_none());
    assert!(entry_a.take_run_failure().is_none());
    drop(entry_a);
    assert_eq!(
        fixture.page.live(),
        2,
        "peer A NotYet rollback must restore live count to 2"
    );
    assert!(zone.live(member1_ref).is_some(), "peer A remains live");
    assert_eq!(
        zone.slot(slot2).queued(),
        1,
        "peer A's reservation release must wake parked caller B"
    );

    // Caller B resumes its parked SYS_exit(38) and retires only itself in ring.
    zone.install_space(slot2, 1).unwrap();
    assert_eq!(zone.switch_in_full(slot2).unwrap().record, member2);
    // SAFETY: `member2` was just selected on `slot2`.
    let saved_b = unsafe { fixture.runtime.record_binding(member2_ref) }
        .unwrap()
        .words;
    let mut service_b = Physical {
        zone,
        page: fixture.page,
        controls: &controls[..],
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
        waker_slot: slot2,
        on_signal_clock: None,
    };
    let mut entry_b = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource { zone, slot: slot2 },
            task2,
            fixture.address,
            &saved_b,
            &mut service_b,
        )
        .unwrap();
    let resumed_b = entry_b.resume_checkpoint(|_| Ok(None)).unwrap();
    assert!(
        matches!(
            resumed_b,
            NativeResume::RetrySyscall | NativeResume::RetrySavedSyscall
        ),
        "resumed caller B must rerun its saved SYS_exit"
    );
    drop(entry_b);

    let counters_rerun = carrick_el1_abi::Counters::new();
    let names_rerun = carrick_el1_abi::InotifyNameCache::new();
    let venue_b = MemberVenue {
        page: fixture.page,
        control: control2,
    };
    let mut entry_b = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource { zone, slot: slot2 },
            task2,
            fixture.address,
            &saved_b,
            &mut service_b,
        )
        .unwrap();
    {
        let mut frame_b = ExitStatusFrame(isa, slot2, 38);
        let mut pending_b: crate::dispatch::El1PendingFamilies<
            '_,
            '_,
            _,
            crate::sched::FakeCpu,
            crate::sched::HardwareUserWord,
            _,
            C,
        > = crate::dispatch::El1PendingFamilies {
            futex_argument0: None,
            handoff: None,
            lifecycle_user: None,
            frame: &mut frame_b,
            counters: &counters_rerun,
            current_tasks: core::slice::from_ref(task2),
            fd_map: &[],
            object_table: &[],
            open_table: &[],
            inotify_table: &[],
            name_cache: &names_rerun,
            zone: None,
            ipc: None,
            lifecycle: Some(&venue_b),
            process: Some(entry_b.as_mut()),
            source: Some(BornInZoneSource { zone, slot: slot2 }),
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
                &mut pending_b,
            ),
            CompletionRoute::Suspended,
            "rerun SYS_exit(38) on {isa:?} must retire caller B in ring"
        );
    }
    assert_eq!(fixture.page.gate(), carrick_el1_abi::GateState::Open);
    assert!(entry_b.take_root_exit().is_none());
    assert!(entry_b.take_handoff_receipt().is_none());
    assert!(entry_b.take_run_failure().is_none());
    drop(entry_b);
    assert!(zone.live(member2_ref).is_none());
    assert!(
        zone.live(member1_ref).is_some(),
        "peer A must still be live"
    );
    assert_eq!(fixture.page.live(), 1);
}

#[test]
fn refundable_peer_raw_exit_parks_then_retires_as_thread_exit_x86() {
    ENTRYLESS_RETIREMENT.with(|owner| owner.set(EntrylessRetirement::Ring));
    refundable_peer_raw_exit_parks_then_retires_as_thread_exit::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(
        &words,
        carrick_personality_linux::crossing::HostCrossingSet::X86,
    );
    ENTRYLESS_RETIREMENT.with(|owner| owner.set(EntrylessRetirement::HostThread));
}

#[test]
fn refundable_peer_raw_exit_parks_then_retires_as_thread_exit_aarch64() {
    refundable_peer_raw_exit_parks_then_retires_as_thread_exit::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(
        &arm_syscall_words,
        carrick_personality_linux::crossing::HostCrossingSet::Aarch64,
    );
}

/// #2932 verifier blocker ("Busy once, then success"): peer A holds a
/// refundable reservation when caller B hits `Floor`, and peer A refunds that
/// reservation (`live` rebounds `1 -> 2`) right before caller B's reservation
/// wait bucket enrollment probes under the bucket lock. Caller B must reach the
/// reservation owner's wait bucket (never spin in-ring without enrolling),
/// observe the released reservation under the bucket lock, probe once, and
/// retire only itself in ring without promoting to `exit_group`.
fn refundable_peer_rebound_before_enrol_probes_once_and_retires<C, B>(
    make: impl Fn(AddressContext<RootGpa>) -> C,
    isa: carrick_personality_linux::crossing::HostCrossingSet,
) where
    C: ProcessContext + crate::dispatch::DispatchContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
{
    use carrick_el1_abi::Lifecycle;
    use carrick_personality_linux::dispatch::{CompletionRoute, dispatch};

    let fixture = Fixture::<C>::new::<B>(&make);
    let zone = fixture.zone;
    assert!(zone.mark_native_owned(fixture.record.id));
    let slot2 = SlotId::new(2);

    let controls = Box::leak(Box::new([
        ThreadControlSlot::new(),
        ThreadControlSlot::new(),
    ]));
    let control1 = &controls[0];
    let control2 = &controls[1];
    let (_task1, member1) = spawn_registered_born_member(&fixture, &make, control1, 0);
    let (task2, member2) = spawn_registered_born_member(&fixture, &make, control2, 1);
    assert_eq!(fixture.page.live(), 3);

    assert_eq!(
        zone.release_current(fixture.slot, fixture.record.id, &ShortLockSpin),
        carrick_sched_core::CurrentRelease::Released
    );
    fixture.page.reserve_nonfinal_exit().unwrap().publish();
    let leader_birth = fixture.control.host_birth_identity().unwrap();
    fixture
        .page
        .publish_exact_host_retirement(fixture.control, leader_birth.retirement());
    assert_eq!(fixture.page.live(), 2);

    let member1_ref = zone.record_ref(member1);
    let member2_ref = zone.record_ref(member2);
    let bucket_contended = core::sync::atomic::AtomicBool::new(false);
    let finished = core::sync::atomic::AtomicBool::new(false);
    let (start_tx, start_rx) = std::sync::mpsc::channel();
    let (armed_tx, armed_rx) = std::sync::mpsc::channel();

    struct ReboundVenue<'a> {
        page: &'a ThreadLifecyclePage,
        caller: &'a ThreadControlSlot,
        calls: core::cell::Cell<usize>,
        arm_peer: core::cell::RefCell<
            Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
        >,
    }
    impl crate::thread_setup::LifecycleVenue for ReboundVenue<'_> {
        fn thread<'a>(
            &'a self,
            _: &'a CurrentTask,
        ) -> Option<carrick_personality_linux::thread::LifecycleThread<'a>> {
            let seen = self.calls.get();
            self.calls.set(seen + 1);
            if seen == 1
                && let Some((tx, rx)) = self.arm_peer.borrow_mut().take()
            {
                tx.send(()).unwrap();
                rx.recv().unwrap();
            }
            Some(carrick_personality_linux::thread::LifecycleThread {
                page: self.page,
                slot: self.caller,
            })
        }
        fn born_slot(&self, _: &ThreadLifecyclePage, _: EntryRef) -> Option<&ThreadControlSlot> {
            None
        }
    }

    let probe = |attempt: u32| {
        if attempt == LOCK_SPINS {
            bucket_contended.store(true, Ordering::Release);
        }
    };

    let bucket_contended_ref = &bucket_contended;
    let finished_ref = &finished;
    let page = fixture.page;
    std::thread::scope(|scope| {
        scope.spawn(move || {
            if start_rx.recv().is_err() {
                return;
            }
            let identity = carrick_core::terminal::ThreadTerminalIdentity::from_exit(
                ExecutionBinding {
                    task: carrick_core_abi::EntryTaskKey::from_raw(42),
                    generation: carrick_core_abi::SnapshotGeneration::from_raw(102),
                    mm: carrick_core_abi::EntryMmKey::from_raw(1),
                    thread_generation: carrick_core_abi::EntryThreadGeneration::from_raw(102),
                },
                control1.entry(),
                carrick_sched_core::process::TerminationStatus::exited(0),
            )
            .unwrap();
            let (_custody, held_membership) = carrick_core::terminal::TerminalCustody::<
                carrick_core::terminal::Thread,
                carrick_core::terminal::Live,
            >::admitted(identity)
            .begin()
            .reserve_member(page, control1)
            .map_err(|(_, error)| error)
            .unwrap();
            assert_eq!(page.live(), 1);
            let guards: Vec<_> = (0..carrick_sched_core::ZONE_BUCKETS)
                .map(|bucket| {
                    zone.lock(bucket, &carrick_sched_core::BoundedSpin(0))
                        .unwrap()
                })
                .collect();
            armed_tx.send(()).unwrap();
            while !bucket_contended_ref.load(Ordering::Acquire)
                && !finished_ref.load(Ordering::Acquire)
            {
                std::thread::yield_now();
            }
            // Peer A's NotYet rollback restores `page.live() == 2` right before
            // caller B acquires the reservation wait bucket lock and probes.
            drop(held_membership);
            drop(guards);
        });

        let counters = carrick_el1_abi::Counters::new();
        let names = carrick_el1_abi::InotifyNameCache::new();
        let venue = ReboundVenue {
            page: fixture.page,
            caller: control2,
            calls: core::cell::Cell::new(0),
            arm_peer: core::cell::RefCell::new(Some((start_tx, armed_rx))),
        };
        let mut service = Physical {
            zone,
            page: fixture.page,
            controls: &controls[..],
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
            waker_slot: slot2,
            on_signal_clock: None,
        };
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                BornInZoneSource { zone, slot: slot2 },
                task2,
                fixture.address,
                &make(fixture.address),
                &mut service,
            )
            .unwrap();
        entry.publication_wait_probe = Some(&probe);
        let route = {
            let mut frame = ExitStatusFrame(isa, slot2, 38);
            let mut pending: crate::dispatch::El1PendingFamilies<
                '_,
                '_,
                _,
                crate::sched::FakeCpu,
                crate::sched::HardwareUserWord,
                _,
                C,
            > = crate::dispatch::El1PendingFamilies {
                futex_argument0: None,
                handoff: None,
                lifecycle_user: None,
                frame: &mut frame,
                counters: &counters,
                current_tasks: core::slice::from_ref(task2),
                fd_map: &[],
                object_table: &[],
                open_table: &[],
                inotify_table: &[],
                name_cache: &names,
                zone: None,
                ipc: None,
                lifecycle: Some(&venue),
                process: Some(entry.as_mut()),
                source: Some(BornInZoneSource { zone, slot: slot2 }),
                anonymous: None,
                cache_lookup: |_| core::ptr::null_mut(),
            };
            dispatch(
                carrick_syscall_abi::CanonicalNr::new(
                    carrick_personality_linux::lifecycle::SYS_EXIT as u64,
                )
                .raw(),
                u64::MAX,
                &mut pending,
            )
        };
        entry.publication_wait_probe = None;
        finished.store(true, Ordering::Release);
        assert_eq!(route, CompletionRoute::Suspended);
        assert!(
            bucket_contended.load(Ordering::Acquire),
            "caller B must enrol on the reservation wait bucket before probing once"
        );
        assert_eq!(
            fixture.page.gate(),
            carrick_el1_abi::GateState::Open,
            "caller B promoted raw exit to exit_group while peer A's reservation was refundable"
        );
        assert!(
            entry.take_root_exit().is_none(),
            "caller B published root exit while peer A's reservation was refundable"
        );
        assert_eq!(
            counters.lifecycle_declines[carrick_el1_abi::LifecycleDecline::ExitLast as usize]
                .load(Ordering::Acquire),
            1
        );
        assert!(entry.take_handoff_receipt().is_none());
        assert!(entry.take_run_failure().is_none());
    });

    assert!(zone.live(member2_ref).is_none());
    assert!(zone.live(member1_ref).is_some(), "peer A remains live");
    assert_eq!(fixture.page.live(), 1);
}

#[test]
fn refundable_peer_rebound_before_enrol_probes_once_and_retires_x86() {
    ENTRYLESS_RETIREMENT.with(|owner| owner.set(EntrylessRetirement::Ring));
    refundable_peer_rebound_before_enrol_probes_once_and_retires::<
        ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(
        words,
        carrick_personality_linux::crossing::HostCrossingSet::X86,
    );
    ENTRYLESS_RETIREMENT.with(|owner| owner.set(EntrylessRetirement::HostThread));
}

#[test]
fn refundable_peer_rebound_before_enrol_probes_once_and_retires_aarch64() {
    refundable_peer_rebound_before_enrol_probes_once_and_retires::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(
        arm_syscall_words,
        carrick_personality_linux::crossing::HostCrossingSet::Aarch64,
    );
}
