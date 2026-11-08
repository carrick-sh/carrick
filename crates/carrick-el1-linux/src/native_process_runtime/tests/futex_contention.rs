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
            *out = 0;
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
