//! VM-free production ring/host entry integration. Only physical MM service
//! and the hardware run are replaced; graph admission and host clone are real.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use carrick_el1_abi::{BornInZoneSource, CurrentTask, Lifecycle};
use carrick_el1_linux::native_process_runtime::{
    NativeForkPreparation, NativeLifecycleResources, NativeProcessEntry, NativeProcessError,
    NativeProcessRegistry, NativeProcessRuntime, NativeProcessService,
};
use carrick_guest_arch::{
    AddressContext, ContextGeneration, FrameGpa, MmGeneration, RootGpa, UserVa,
};
use carrick_personality_linux::lifecycle::{LinuxWaitStatus, ProcessNative};
use std::num::NonZeroU64;

type Words = Aarch64ParkedContext;
type Address = AddressContext<RootGpa>;
#[derive(Default)]
struct NoPhysicalCrossings {
    effects: Vec<carrick_sched_core::WakeEffects>,
}
impl<'a> NativeProcessService<'a, Words> for NoPhysicalCrossings {
    type Mm = Address;
    type PreparedMm = Address;
    type Born = Address;
    fn prepare_mm(
        &mut self,
        _: &Address,
        _: &Words,
        _: MmGeneration,
    ) -> Result<Address, NativeProcessError> {
        panic!("affinity must not cross to MM service")
    }
    fn prepared_mm(&self, _: &Address) -> Address {
        unreachable!()
    }
    fn prepared_context(&self, _: &Address) -> Address {
        unreachable!()
    }
    fn child_lifecycle(&self, _: &Address) -> NativeLifecycleResources<'a> {
        unreachable!()
    }
    fn commit_mm(&mut self, _: Address) -> Result<Address, (NativeProcessError, Address)> {
        unreachable!()
    }
    fn abort_mm(&mut self, _: Address) -> Result<(), (NativeProcessError, Address)> {
        unreachable!()
    }
    fn settle_mm(&mut self, _: Address) -> Result<(), (NativeProcessError, Address)> {
        unreachable!()
    }
    fn copy_status(
        &mut self,
        _: &Address,
        _: UserVa,
        _: LinuxWaitStatus,
    ) -> Result<(), NativeProcessError> {
        unreachable!()
    }
    fn quarantine_prepared(&mut self, _: Address) {
        unreachable!()
    }
    fn quarantine_fork(&mut self, _: NativeForkPreparation<'a, Address, Address, Words>) {
        unreachable!()
    }
    fn quarantine_born(&mut self, _: Address) {
        unreachable!()
    }
    fn retire_mm(&mut self, _: Address) {
        unreachable!()
    }
    fn request_ingress_producer_boundary(&mut self) {
        panic!("affinity must not leave ingress publication unsettled")
    }
    fn wake_effects(&mut self, effects: carrick_sched_core::WakeEffects) {
        self.effects.push(effects);
    }
}

// Exercise the production El1PendingFamilies venue, including checked copy.
fn ring_call(
    process: &mut dyn ProcessNative<Words>,
    current: &[CurrentTask],
    zone: &ZoneTables,
    index: u8,
    number: u64,
    tid: u32,
    mask: &mut u64,
) -> i64 {
    ring_call_route(process, current, zone, index, number, tid, mask).0
}

fn ring_call_route(
    process: &mut dyn ProcessNative<Words>,
    current: &[CurrentTask],
    zone: &ZoneTables,
    index: u8,
    number: u64,
    tid: u32,
    mask: &mut u64,
) -> (i64, carrick_personality_linux::dispatch::CompletionRoute) {
    let mut frame = carrick_el1_abi::TrapFrame {
        slot: u64::from(index),
        ..Default::default()
    };
    frame.x[8] = number;
    frame.x[0] = u64::from(tid);
    frame.x[1] = 8;
    frame.x[2] = core::ptr::from_mut(mask).expose_provenance() as u64;
    let counters = carrick_el1_abi::Counters::default();
    let mut cpu = carrick_el1_linux::sched::FakeCpu::default();
    let route = carrick_el1_linux::dispatch::dispatch_syscall_with_native(
        &mut frame,
        &counters,
        current,
        &[],
        &[],
        &[],
        &[],
        &carrick_el1_abi::InotifyNameCache::new(),
        Some(carrick_el1_linux::dispatch::Zone {
            tables: zone,
            cpu: &mut cpu,
            user: &carrick_el1_linux::sched::HardwareUserWord,
        }),
        None,
        None,
        Some(process),
        Some(BornInZoneSource {
            zone,
            slot: SlotId::new(index),
        }),
        None,
        |_| core::ptr::null_mut(),
    );
    assert!(matches!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Served
            | carrick_personality_linux::dispatch::CompletionRoute::WithWork
            | carrick_personality_linux::dispatch::CompletionRoute::Suspended
    ));
    assert_eq!(
        counters.refused[number as usize].load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    (frame.x[0] as i64, route)
}

fn publish_current(
    context: &carrick_kernel::kernel::KernelContext,
    current: &CurrentTask,
    zone: &ZoneTables,
    slot: SlotId,
    address: Address,
) {
    let thread = context.thread();
    let page = thread.control_lease().lifecycle();
    // SAFETY: both aliases name the fixture's retained, directly mapped control.
    unsafe {
        thread
            .control_slot()
            .publish_affinity_aliases(carrick_guest_arch::GuestVa::new(
                core::ptr::from_ref(thread.control_slot()).expose_provenance() as u64,
            ));
    }
    let tid = thread.key().tid.raw();
    assert!(thread.control_slot().publish_visible_tid(tid as u32));
    let generation = carrick_el1_abi::SnapshotGeneration::INITIAL;
    current.set(
        carrick_el1_abi::El1TaskId::from_linux_tid(tid),
        generation,
        context.resources().files().id().raw(),
    );
    current
        .mm
        .key
        .store(address.mm.raw().get(), std::sync::atomic::Ordering::Release);
    current.mm.thread_generation.store(
        thread.key().serial.raw(),
        std::sync::atomic::Ordering::Release,
    );
    current.publish_visible_pid(context.task().key().id.raw() as u32);
    current.publish_lifecycle(
        &*page as *const _ as u64,
        thread.control_slot() as *const _ as u64,
    );
    zone.drive(slot, 1);
    zone.publish_slot(slot, address.mm.raw().get(), Some(slot.raw() as u32), 3);
    zone.enter_guest(slot);
    zone.install_space(slot, address.mm.raw().get()).unwrap();
    let record = zone
        .current_or_new(
            slot,
            ThreadIdentity {
                tid: tid as u64,
                serial: thread.key().serial.raw(),
                mm: address.mm.raw().get(),
                file_table: context.resources().files().id().raw(),
                generation: generation.raw(),
                affinity: 3,
                affinity_source: thread.control_slot().affinity_source(),
                lifecycle_page: &*page as *const _ as u64,
                control_slot: thread.control_slot() as *const _ as u64,
            },
        )
        .unwrap();
    thread
        .control_slot()
        .bind_zone_record(zone.record_ref(record));
}

fn with_pair(run: impl FnOnce(Pair<'_, '_>)) {
    use carrick_kernel::kernel::ClonePlan;
    let (process, root) = crate::hvpatch::process_context_for_tests(73_703);
    root.thread().set_affinity(carrick_hal::CpuAffinity::all(2));
    let zone = carrick_test_support::TestEl1Region::zeroed();
    // A separate typed allocation avoids putting ZoneTables on a Rust stack.
    let zone = unsafe {
        &*zone
            .as_ptr()
            .add(carrick_el1_abi::EL1_ZONE_OFFSET as usize)
            .cast::<ZoneTables>()
    };
    zone.publish_carrier_cpu_count(2);
    let address = Address {
        root: RootGpa::page_aligned(FrameGpa::new(0x1000)).unwrap(),
        mm: MmGeneration::new(NonZeroU64::new(root.shared().mm().id().raw()).unwrap()),
        generation: ContextGeneration::new(NonZeroU64::MIN),
    };
    let words = Words::from_parts(carrick_sched_core::ThreadCtx::ZERO, address);
    let space = zone
        .spaces
        .publish_closed(address.mm.raw().get(), 0x1000, 0)
        .unwrap();
    zone.spaces.open(space);
    let current = [CurrentTask::new(), CurrentTask::new()];
    publish_current(&root, &current[0], zone, SlotId::new(0), address);
    let source = BornInZoneSource {
        zone,
        slot: SlotId::new(0),
    };
    let page = root.thread().control_lease().lifecycle();
    let sibling;
    let registry = Box::leak(Box::new(NativeProcessRegistry::default()));
    let runtime = Arc::new(
        NativeProcessRuntime::admit_fresh_root::<carrick_mmu_core::owner_mmu::Aarch64Mmu>(
            source,
            &current[0],
            &page,
            root.thread().control_slot(),
            address,
            address,
            words,
        )
        .unwrap(),
    );
    registry
        .register_root(Arc::clone(&runtime), source, &current[0], address)
        .unwrap();
    sibling = root
        .kernel()
        .reserve_thread_clone(
            &root,
            ClonePlan::from_flags(
                carrick_abi::LinuxCloneFlags::THREAD
                    | carrick_abi::LinuxCloneFlags::FILES
                    | carrick_abi::LinuxCloneFlags::SIGHAND
                    | carrick_abi::LinuxCloneFlags::VM,
            )
            .unwrap(),
            None,
        )
        .unwrap()
        .prepare(ThreadId::synthetic_for_tests(73_704))
        .unwrap()
        .commit_for_el1()
        .unwrap()
        .start_thread()
        .unwrap()
        .into_context();
    assert_eq!(
        sibling.thread().affinity().words()[0],
        3,
        "host clone must inherit the caller mask"
    );
    publish_current(&sibling, &current[1], zone, SlotId::new(1), address);
    let second_source = BornInZoneSource {
        zone,
        slot: SlotId::new(1),
    };
    let expected_birth =
        carrick_kernel::kernel::host_birth_identity(sibling.task().key(), sibling.thread().key())
            .unwrap();
    assert_eq!(
        sibling.thread().control_slot().host_birth_identity(),
        Some(expected_birth)
    );
    assert!(
        (0..carrick_el1_abi::THREAD_POOL_ENTRIES)
            .any(|i| page.host_birth_identity(i) == Some(expected_birth))
    );
    assert_eq!(page.live(), 2);
    assert_eq!(
        root.resources().files().id(),
        sibling.resources().files().id()
    );
    registry
        .register_thread(
            second_source,
            &current[1],
            address,
            &page,
            sibling.thread().control_slot(),
        )
        .unwrap();
    assert_eq!(
        root.task()
            .threads()
            .iter()
            .map(|thread| thread.key())
            .collect::<std::collections::HashSet<_>>(),
        std::collections::HashSet::from([root.thread().key(), sibling.thread().key()]),
    );
    run(Pair {
        root: &root,
        sibling: &sibling,
        process: &process,
        zone,
        current: &current,
        runtime: &runtime,
        registry,
        address,
        words,
    });
}

struct Pair<'r, 'a> {
    root: &'r carrick_kernel::kernel::KernelContext,
    sibling: &'r carrick_kernel::kernel::KernelContext,
    process: &'r crate::hvpatch::ProcessContext,
    zone: &'a ZoneTables,
    current: &'a [CurrentTask; 2],
    runtime: &'r Arc<NativeProcessRuntime<'a, Address, Words>>,
    registry: &'a NativeProcessRegistry<'a, Address, Words>,
    address: Address,
    words: Words,
}

fn enter_native<'r, 'a: 'r>(
    pair: &'r Pair<'_, 'a>,
    index: usize,
    service: &'r mut NoPhysicalCrossings,
) -> Box<NativeProcessEntry<'r, 'a, Address, Words, NoPhysicalCrossings>> {
    pair.runtime
        .enter_registered(
            pair.registry,
            BornInZoneSource {
                zone: pair.zone,
                slot: SlotId::from_index(index).unwrap(),
            },
            &pair.current[index],
            pair.address,
            &pair.words,
            service,
        )
        .unwrap()
}

#[test]
fn production_venue_affinity_survives_host_affinity_round_trip() {
    with_pair(|p| {
        let mut physical = NoPhysicalCrossings::default();
        for (index, mask) in [(0, 1u64), (1, 2u64)] {
            let mut entry = enter_native(&p, usize::from(index), &mut physical);
            let mut mask = mask;
            assert_eq!(
                ring_call(entry.as_mut(), p.current, p.zone, index, 122, 0, &mut mask),
                0
            );
        }
        let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::new();
        dispatcher.bind_hvpatch_process(Arc::new(p.process.clone()));
        let registry_host = crate::thread::ThreadRegistry::new(p.root.thread().registry_id());
        let futex = crate::thread::FutexTable::new();
        let mut memory = carrick_kernel::dispatch::LinearMemory::new(0x8000, vec![0; 8]);
        for (index, context, before, after) in [(0, p.root, 1, 2u64), (1, p.sibling, 2, 1u64)] {
            let slot = SlotId::new(index);
            p.zone.leave_guest(slot, &HostLockWait);
            let captured = context
                .task_binding()
                .capture(context.thread().key().tid)
                .unwrap();
            let mut executor = dispatcher.enter_mm_executor().unwrap();
            let host_get = dispatcher
                .dispatch_threaded_with_mm_executor(
                    &mut executor,
                    &captured,
                    carrick_kernel::dispatch::SyscallRequest::new(
                        123,
                        crate::compat::SyscallArgs::from([0, 8, 0x8000, 0, 0, 0]),
                    ),
                    &mut memory,
                    &crate::compat::CompatReporter::default(),
                    carrick_kernel::dispatch::ThreadCtx::new(
                        context.thread().registry_id(),
                        &registry_host,
                        &futex,
                    ),
                )
                .unwrap();
            assert!(matches!(
                host_get,
                carrick_kernel::dispatch::DispatchOutcome::Returned { value: 8 }
            ));
            assert_eq!(
                u64::from_le_bytes(
                    carrick_kernel::dispatch::GuestMemory::read_bytes_raw(&memory, 0x8000, 8)
                        .unwrap()
                        .try_into()
                        .unwrap()
                ),
                before
            );
            // A real host-served SET interleaves with the ring writer.
            carrick_kernel::dispatch::GuestMemory::write_bytes_raw(
                &mut memory,
                0x8000,
                &after.to_le_bytes(),
            )
            .unwrap();
            let outcome = dispatcher
                .dispatch_threaded_with_mm_executor(
                    &mut executor,
                    &captured,
                    carrick_kernel::dispatch::SyscallRequest::new(
                        122,
                        crate::compat::SyscallArgs::from([0, 8, 0x8000, 0, 0, 0]),
                    ),
                    &mut memory,
                    &crate::compat::CompatReporter::default(),
                    carrick_kernel::dispatch::ThreadCtx::new(
                        context.thread().registry_id(),
                        &registry_host,
                        &futex,
                    ),
                )
                .unwrap();
            assert!(matches!(
                outcome,
                carrick_kernel::dispatch::DispatchOutcome::Returned { value: 0 }
            ));
            let placement = run_guest(Some(context.thread()), Some((p.zone, slot)), || {
                p.zone.slot(slot).affinity()
            });
            let mut entry = enter_native(&p, usize::from(index), &mut physical);
            let mut observed = 0;
            assert_eq!(
                ring_call(
                    entry.as_mut(),
                    p.current,
                    p.zone,
                    index,
                    123,
                    0,
                    &mut observed
                ),
                8
            );
            let record = context.thread().control_slot().zone_record().unwrap();
            assert_eq!(
                (placement, observed, p.zone.record(record.id).affinity()),
                (after, after, after),
                "host affinity changes must update live placement reads, not a stale projection"
            );
        }
    });
}

#[derive(Debug, Default)]
struct RecordedKick {
    binding: parking_lot::Mutex<Option<carrick_kernel::kernel::ExecutorBinding>>,
    delivered: std::sync::atomic::AtomicUsize,
}
impl carrick_kernel::kernel::ExecutorKick for RecordedKick {
    fn try_bind(&self, binding: carrick_kernel::kernel::ExecutorBinding) -> bool {
        let mut slot = self.binding.lock();
        if slot.is_some() {
            return false;
        }
        *slot = Some(binding);
        true
    }
    fn unbind(&self, binding: carrick_kernel::kernel::ExecutorBinding) {
        let mut slot = self.binding.lock();
        if *slot == Some(binding) {
            *slot = None;
        }
    }
    fn rebind_exact_with(
        &self,
        old: carrick_kernel::kernel::ExecutorBinding,
        new: carrick_kernel::kernel::ExecutorBinding,
        publish: &mut dyn FnMut() -> bool,
    ) -> bool {
        let mut slot = self.binding.lock();
        if *slot != Some(old) || !publish() {
            return false;
        }
        *slot = Some(new);
        true
    }
    fn deliver_exact(&self, token: carrick_kernel::kernel::ExecutorKickToken) -> bool {
        if *self.binding.lock() != Some(token.binding()) {
            return false;
        }
        self.delivered
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        true
    }
    fn current_binding(&self) -> Option<carrick_kernel::kernel::ExecutorBinding> {
        *self.binding.lock()
    }
}

#[test]
fn production_venue_remote_affinity_migrates_running_sibling_without_tick() {
    remote_affinity_migration(false);
}

#[test]
fn production_venue_host_route_migrates_running_sibling_without_tick() {
    remote_affinity_migration(true);
}

fn remote_affinity_migration(host_route: bool) {
    use carrick_hal::{CpuAffinity, GuestCpuId, GuestCpuPolicy};
    use carrick_kernel::kernel::Scheduler;
    use std::sync::mpsc;
    use std::time::Duration;
    with_pair(|p| {
        p.root
            .thread()
            .set_affinity(CpuAffinity::single(GuestCpuId::new(0)));
        p.sibling
            .thread()
            .set_affinity(CpuAffinity::single(GuestCpuId::new(1)));
        for context in [p.root, p.sibling] {
            context
                .thread()
                .publish_initial_task_state(crate::vcpu_loop::executor::tests::task_state(
                    context, 31,
                ))
                .unwrap();
        }
        let scheduler = Scheduler::new_with_policy(
            Arc::clone(p.root.kernel()),
            Arc::new(GuestCpuPolicy::new(2)),
        );
        let kicks = [
            Arc::new(RecordedKick::default()),
            Arc::new(RecordedKick::default()),
        ];
        let ex0 = scheduler
            .register_executor_bound(kicks[0].clone(), Some(GuestCpuId::new(0)), false)
            .unwrap();
        let ex1 = scheduler
            .register_executor_bound(kicks[1].clone(), Some(GuestCpuId::new(1)), false)
            .unwrap();
        scheduler.make_runnable(p.root.thread().key()).unwrap();
        scheduler.make_runnable(p.sibling.thread().key()).unwrap();
        let running_caller = scheduler.take(&ex0).unwrap();
        let running_target = scheduler.take(&ex1).unwrap();
        let target_slot = SlotId::new(1);
        let route = if host_route {
            carrick_sched_core::HOST_RESCHEDULE_TARGET
        } else {
            carrick_guest_arch::sgi_target_of(1)
        };
        p.zone.slot(target_slot).set_sgi_target(route);
        // Production attaches once after backend publication, before entry.
        assert!(running_target.lease().attach_affinity_slot(target_slot));

        assert_eq!(
            scheduler.queued_len(),
            0,
            "no fairness demand may supply the kick"
        );
        let (ready_tx, ready_rx) = mpsc::channel();
        let (irq_tx, irq_rx) = mpsc::channel();
        let zone = p.zone;
        let task = &p.current[1];
        let target = Arc::clone(p.sibling.thread());
        std::thread::scope(|scope| {
            let worker = scope.spawn(move || {
                run_guest(Some(&target), Some((zone, SlotId::new(1))), || {
                    ready_tx.send(()).unwrap();
                    irq_rx
                        .recv_timeout(Duration::from_secs(5))
                        .expect("remote ring change must deliver a reschedule");
                    if host_route {
                        assert!(
                            task.linux.has_pending_host_work(),
                            "host kick must carry owed return work"
                        );
                    } else {
                        let mut cpu = carrick_el1_linux::sched::FakeCpu::default();
                        let before = cpu.now;
                        cpu.pending.push_back(carrick_el1_abi::GIC_RESCHED_INTID);
                        let counters = carrick_el1_abi::Counters::default();
                        let mut sched = carrick_el1_linux::sched::Sched {
                            zone,
                            slot: SlotId::new(1),
                            task,
                            cpu: &mut cpu,
                            user: &carrick_el1_linux::sched::HardwareUserWord,
                            counters: &counters,
                            handoff: None,
                        };
                        let action =
                            sched.interrupt(&mut carrick_el1_abi::TrapFrame::default(), u64::MAX);
                        assert_eq!(
                            action,
                            carrick_el1_abi::Action::Forward,
                            "excluded live residency must leave EL0"
                        );
                        assert_eq!(cpu.now, before, "no timer advancement supplies migration");
                    }
                });
            });
            ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let mut service = NoPhysicalCrossings::default();
            let mut entry = enter_native(&p, 0, &mut service);
            let tid = p.sibling.thread().control_slot().visible_tid().unwrap();
            let mut widen = 3;
            assert_eq!(
                ring_call(entry.as_mut(), p.current, p.zone, 0, 122, tid, &mut widen),
                0
            );
            drop(entry);
            assert!(service.effects.is_empty(), "widening owes zero kicks");
            let mut entry = enter_native(&p, 0, &mut service);
            let mut narrow = 1;
            assert_eq!(
                ring_call(entry.as_mut(), p.current, p.zone, 0, 122, tid, &mut narrow),
                0
            );
            drop(entry);
            assert_eq!(
                service.effects.len(),
                1,
                "one successful remote set owes one exact residency notification"
            );
            assert_eq!(
                service.effects[0].sgi_slots().collect::<Vec<_>>(),
                [SlotId::new(1)]
            );
            assert_eq!(
                p.root.thread().affinity().words()[0],
                1,
                "caller mask is independent"
            );
            let mut delivered = Vec::new();
            carrick_el1_linux::sched::object_wait::deliver_effects_with(
                p.zone,
                Some(SlotId::new(0)),
                carrick_sched_core::Waker::El1 {
                    slot: SlotId::new(0),
                },
                service.effects[0],
                false,
                |slot, target| {
                    use carrick_el1_linux::sched::ThreadCpu;
                    let mut sender = carrick_el1_linux::sched::FakeCpu::default();
                    sender.send_resched(slot, target);
                    if host_route {
                        assert_eq!(sender.sgis, [carrick_sched_core::HOST_RESCHEDULE_TARGET]);
                        p.current[1].linux.mark_pending_host_work();
                    }
                    delivered.push(slot);
                    irq_tx.send(()).unwrap();
                },
                (|_| {}, || {}),
            );
            assert_eq!(
                delivered,
                [SlotId::new(1)],
                "one kick must reach exactly the running sibling"
            );
            worker.join().unwrap();
        });
        assert!(scheduler.should_preempt(&running_target));
        scheduler.settle_runnable(running_target).unwrap();
        scheduler.settle_exited(running_caller).unwrap();
        let migrated = scheduler.take(&ex0).unwrap();
        assert_eq!(migrated.thread_key(), p.sibling.thread().key());
        assert_eq!(migrated.guest_cpu(), GuestCpuId::new(0));
        assert_eq!(p.sibling.thread().affinity().words()[0], 1);
        scheduler.settle_exited(migrated).unwrap();
    });
}

#[test]
fn production_venue_switched_self_affinity_keeps_host_loaded_source() {
    switched_self_affinity(false);
}

#[test]
fn production_venue_switched_self_exclusion_migrates_before_return_without_irq() {
    switched_self_affinity(true);
}

fn switched_self_affinity(exclude: bool) {
    use carrick_el1_linux::sched::{FakeCpu, HardwareUserWord, Sched, ThreadCpu};
    use std::sync::atomic::Ordering;

    with_pair(|p| {
        let slot = SlotId::new(0);
        let previous_slot = SlotId::new(1);
        let sibling = p.sibling.thread().control_slot().zone_record().unwrap();
        let caller_tid = p.root.thread().key().tid.raw() as u64;
        let sibling_tid = p.sibling.thread().key().tid.raw() as u64;
        assert_eq!(p.root.task().threads().len(), 2);
        assert_eq!(p.zone.slot(slot).affinity(), 3);
        assert_eq!(p.zone.slot(previous_slot).host_record(), Some(sibling.id));

        // Settle the stopped sibling's real home record through the ordinary
        // preemption/drain/unhome protocol, then queue that same incarnation
        // on CPU 0. Its identity and control came from commit_for_el1 above.
        let mut cpu = FakeCpu::default();
        let mut frame = carrick_el1_abi::TrapFrame::default();
        // SAFETY: the fixture owns this stopped, unpublished home record.
        let saved = unsafe { p.zone.record(sibling.id).ctx_mut() };
        *saved = p.words;
        cpu.save(&frame, saved);
        p.zone.requeue_preempted(previous_slot, sibling.id);
        p.zone.leave_guest(previous_slot, &HostLockWait);
        let mut handed_back = Vec::new();
        p.zone.drain_slot(previous_slot, &mut |record, discarded| {
            assert!(!discarded);
            handed_back.push(record);
        });
        assert_eq!(handed_back, [sibling]);
        p.zone.unhome(previous_slot, sibling.id, 3);
        assert!(p.zone.requeue_on(slot, sibling.id).is_some());
        if exclude {
            p.zone.enter_guest(previous_slot);
            p.zone.enter_idle(previous_slot, false);
        }

        run_guest(Some(p.root.thread()), Some((p.zone, slot)), || {
            let counters = carrick_el1_abi::Counters::default();
            let mut sched = Sched {
                zone: p.zone,
                slot,
                task: &p.current[0],
                cpu: &mut cpu,
                user: &HardwareUserWord,
                counters: &counters,
                handoff: None,
            };
            assert_eq!(
                p.current[0].execution.task.load(Ordering::Acquire),
                caller_tid
            );
            assert_eq!(
                sched.yield_queued(&mut frame),
                Some(carrick_core::Served::Returned { switched: true })
            );
            assert_eq!(p.zone.slot(slot).current(), Some(sibling.id));
            assert_eq!(
                p.current[0].execution.task.load(Ordering::Acquire),
                sibling_tid,
                "Sched::load must publish B before B enters production dispatch"
            );
            assert_ne!(p.zone.slot(slot).host_record(), Some(sibling.id));
            assert_eq!(p.zone.slot(slot).affinity(), 3);

            let mut physical = NoPhysicalCrossings::default();
            let mut entry = enter_native(&p, 0, &mut physical);
            let expected = if exclude { 2 } else { 1 };
            let mut mask = expected;
            let (result, route) =
                ring_call_route(entry.as_mut(), p.current, p.zone, 0, 122, 0, &mut mask);
            assert_eq!(result, 0);
            if exclude {
                assert_eq!(
                    p.current[0].linux.take_served_boundary(),
                    Some(carrick_el1_abi::ServedBoundary::Completed),
                    "migration must retain the owned completed host return boundary"
                );
                assert_eq!(
                    route,
                    carrick_personality_linux::dispatch::CompletionRoute::WithWork,
                    "self exclusion must stop at its owned host completion before guest return"
                );
                assert_eq!(p.zone.slot(slot).current(), Some(sibling.id));
                assert_eq!(
                    p.zone.handback_current(slot, sibling.id),
                    carrick_sched_core::CurrentHandback::HandedBack
                );
                // The stopped completed record goes through host claims. The
                // live authority must exclude CPU 0 before any guest entry.
                use carrick_hal::{GuestCpuId, GuestCpuPolicy};
                use carrick_kernel::kernel::Scheduler;
                p.sibling
                    .thread()
                    .publish_initial_task_state(crate::vcpu_loop::executor::tests::task_state(
                        p.sibling, 32,
                    ))
                    .unwrap();
                let scheduler = Scheduler::new_with_policy(
                    Arc::clone(p.root.kernel()),
                    Arc::new(GuestCpuPolicy::new(2)),
                );
                let ex0 = scheduler
                    .register_executor_bound(
                        Arc::new(RecordedKick::default()),
                        Some(GuestCpuId::new(0)),
                        false,
                    )
                    .unwrap();
                let ex1 = scheduler
                    .register_executor_bound(
                        Arc::new(RecordedKick::default()),
                        Some(GuestCpuId::new(1)),
                        false,
                    )
                    .unwrap();
                scheduler.make_runnable(p.sibling.thread().key()).unwrap();
                assert!(scheduler.try_take(&ex0).unwrap().is_none());
                let migrated = scheduler.take(&ex1).unwrap();
                assert_eq!(migrated.thread_key(), p.sibling.thread().key());
                assert_eq!(migrated.guest_cpu(), GuestCpuId::new(1));
                scheduler.settle_exited(migrated).unwrap();
            }
            drop(entry);
            assert_eq!(p.sibling.thread().affinity().words()[0], expected);
            assert_eq!(p.root.thread().affinity().words()[0], 3);
            assert_eq!(
                p.zone.slot(slot).affinity(),
                3,
                "B's self-set must preserve the affinity source of host-loaded A"
            );
            assert_eq!(p.zone.record(sibling.id).affinity(), expected);

            p.root
                .thread()
                .set_affinity(carrick_hal::CpuAffinity::from_words(&[2]));
            assert_eq!(
                p.zone.slot(slot).affinity(),
                2,
                "the retained slot source must continue to read A's live authority"
            );
            assert_eq!(p.sibling.thread().affinity().words()[0], expected);
        });
    });
}

#[test]
fn affinity_reentry_preserves_retired_terminal_custody() {
    let bootstrap = carrick_kernel::kernel::RootBootstrap::for_reference_model(
        78_703,
        carrick_hal::ThreadId::synthetic_for_tests(78_703),
        "affinity reentry".into(),
    )
    .unwrap();
    let (_, context) = carrick_kernel::kernel::Kernel::bootstrap_root(bootstrap).unwrap();
    let region = carrick_test_support::TestEl1Region::zeroed();
    // SAFETY: TestEl1Region owns aligned, zero-valid ABI storage for this scope.
    let zone = unsafe {
        &*region
            .as_ptr()
            .add(carrick_el1_abi::EL1_ZONE_OFFSET as usize)
            .cast::<ZoneTables>()
    };
    let slot = SlotId::new(1);
    zone.publish_slot_with_affinity(
        slot,
        7,
        Some(1),
        context.thread().control_slot().affinity_source(),
    );
    let identity = ThreadIdentity {
        tid: 1,
        serial: 2,
        mm: 7,
        file_table: 1,
        generation: 1,
        affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
        affinity: 3,
        lifecycle_page: 0,
        control_slot: 0,
    };
    zone.publish_terminal(slot, identity);
    assert!(zone.accept_terminal(slot, identity));
    run_guest(Some(context.thread()), Some((zone, slot)), || {
        assert!(
            zone.terminal_matches(slot, identity, carrick_sched_core::TerminalPhase::Retired),
            "affinity refresh cannot erase an owed child wake's retirement receipt"
        );
        assert_eq!(zone.slot(slot).mm(), 7);
        assert_eq!(zone.slot(slot).bound_cpu(), Some(1));
    });
}

#[test]
fn production_venue_remote_set_prompts_a_record_without_host_residency() {
    with_pair(|p| {
        let slot = SlotId::new(1);
        let record = p.sibling.thread().control_slot().zone_record().unwrap().id;
        p.zone.requeue_preempted(slot, record);
        assert_eq!(p.zone.switch_in_full(slot).unwrap().record, record);
        let mut physical = NoPhysicalCrossings::default();
        let mut entry = enter_native(&p, 0, &mut physical);
        let mut mask = 1;
        assert_eq!(
            ring_call(
                entry.as_mut(),
                p.current,
                p.zone,
                0,
                122,
                u32::try_from(p.sibling.thread().key().tid.raw()).unwrap(),
                &mut mask
            ),
            0
        );
        drop(entry);
        let prompts: Vec<_> = physical
            .effects
            .iter()
            .flat_map(|e| e.sgi_slots())
            .collect();
        assert_eq!(prompts, [slot]);
    });
}
