//! Production forks, IPC parks and host final-close publication with no guest CPU.
use super::*;
use carrick_el1::substrate::file::UserCopy;
use carrick_el1_abi::ipc::{IpcBacking, fd, pipe::End};
use carrick_kernel::el1_ipc::{HostIpc, HostTable, IpcLimits};
use carrick_sched_core::{Claim, ShortLockSpin};
use std::sync::Arc;
use zerocopy::IntoBytes;

struct NoCopy;
impl UserCopy for NoCopy {
    fn copy_in(&mut self, _: &mut [u8], _: u64) -> bool {
        panic!("an empty-pipe read must not copy input")
    }
    fn copy_out(&mut self, _: u64, _: &[u8]) -> bool {
        panic!("EOF must not publish bytes")
    }
}

#[derive(Clone, Copy, Default)]
struct SignalCase {
    restart: bool,
    before_enrollment: bool,
    epoll: bool,
    partial: bool,
    eof_race: bool,
}

struct ByteCopy;
impl UserCopy for ByteCopy {
    fn copy_in(&mut self, dst: &mut [u8], _: u64) -> bool {
        dst.fill(b'q');
        true
    }
    fn copy_out(&mut self, _: u64, bytes: &[u8]) -> bool {
        assert_eq!(bytes, b"q");
        true
    }
}

struct SignalCopy<'a>(&'a mut dyn FnMut());
impl UserCopy for SignalCopy<'_> {
    fn copy_in(&mut self, _: &mut [u8], _: u64) -> bool {
        panic!("read copies only output")
    }
    fn copy_out(&mut self, _: u64, bytes: &[u8]) -> bool {
        assert_eq!(bytes, b"q");
        (self.0)();
        true
    }
}

#[test]
fn serial_host_two_native_children_pipe_eof_wake_without_a_guest_executor() {
    two_native_children_pipe_eof_wake(false, None);
}

#[test]
fn serial_host_two_native_children_pipe_eof_wake_with_the_executor_away() {
    two_native_children_pipe_eof_wake(true, None);
}

#[test]
fn serial_host_two_native_children_pipe_signal_with_the_executor_away() {
    two_native_children_pipe_eof_wake(true, Some(SignalCase::default()));
}

#[test]
fn serial_host_two_native_children_pipe_signal_sa_restart_with_the_executor_away() {
    two_native_children_pipe_eof_wake(
        true,
        Some(SignalCase {
            restart: true,
            ..Default::default()
        }),
    );
}

#[test]
fn serial_host_two_native_children_pipe_signal_without_executor_release() {
    two_native_children_pipe_eof_wake(false, Some(SignalCase::default()));
}

#[test]
fn serial_host_two_native_children_pipe_signal_before_enrollment() {
    two_native_children_pipe_eof_wake(
        true,
        Some(SignalCase {
            before_enrollment: true,
            ..Default::default()
        }),
    );
}

#[test]
fn serial_host_two_native_children_timed_epoll_signal_never_restarts() {
    two_native_children_pipe_eof_wake(
        true,
        Some(SignalCase {
            restart: true,
            epoll: true,
            ..Default::default()
        }),
    );
}

#[test]
fn serial_host_two_native_children_pipe_partial_read_preserves_committed_byte() {
    two_native_children_pipe_eof_wake(
        false,
        Some(SignalCase {
            restart: true,
            partial: true,
            ..Default::default()
        }),
    );
}

#[test]
fn serial_host_two_native_children_pipe_signal_races_peer_eof_exactly_once() {
    two_native_children_pipe_eof_wake(
        true,
        Some(SignalCase {
            eof_race: true,
            ..Default::default()
        }),
    );
}

fn two_native_children_pipe_eof_wake(away: bool, signal: Option<SignalCase>) {
    use carrick_personality_linux::signal::{
        ProcessSignals, SignalInfo, SignalProcessSelector, SignalRequest,
    };
    use carrick_signal_core::policy::{Action, ActionFlags, Disposition, HandlerAddress, Signal};
    let fixture = Fixture::new(0x10000, asid(1));
    let sender_task = CurrentTask::new();
    struct RestoreRegion(usize);
    impl Drop for RestoreRegion {
        fn drop(&mut self) {
            carrick_el1_abi::record_el1_region_host_ptr(self.0);
        }
    }
    let _restore = RestoreRegion(carrick_el1_abi::get_el1_region_host_ptr());
    carrick_el1_abi::record_el1_region_host_ptr(fixture.region.ptr.as_ptr() as usize);
    if signal.is_some() {
        fixture
            .control
            .initialize_affinity(carrick_core::affinity::CpuAffinity::from_words(&[3]));
        fixture
            .zone
            .record(fixture.zone.slot(fixture.slot).host_record().unwrap())
            .set_affinity(3);
        fixture.zone.publish_carrier_cpu_count(2);
    }
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let parked = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
    let words = fixture.tables.live(&fixture.maintenance);
    let runtime = NativeProcessRuntime::admit_fresh_root::<Aarch64Mmu>(
        source,
        &fixture.task,
        fixture.page,
        fixture.control,
        fixture.address,
        fixture.address,
        parked,
    )
    .unwrap();
    let owner = Arc::new(
        HostIpc::with_limits(
            1 << 20,
            IpcLimits {
                descriptions: carrick_el1_abi::ipc::IPC_OFD_SEGMENT,
                ..IpcLimits::ZONE
            },
        )
        .unwrap(),
    );
    let table = Arc::new(HostTable::create(Arc::clone(&owner), 64, 64).unwrap());
    let object = owner.create_pipe(65536).unwrap();
    let read_backing = if signal.is_some_and(|case| case.epoll) {
        IpcBacking::Epoll {
            object: owner.create_epoll().unwrap(),
        }
    } else {
        IpcBacking::Pipe {
            object,
            end: End::Reader,
        }
    };
    let reader = owner
        .admit_description(fd::Description::new(
            read_backing.encode(),
            fd::AccessMode::ReadOnly,
            fd::StatusFlags::default(),
        ))
        .unwrap();
    let writer = owner
        .admit_description(fd::Description::new(
            IpcBacking::Pipe {
                object,
                end: End::Writer,
            }
            .encode(),
            fd::AccessMode::WriteOnly,
            fd::StatusFlags::default(),
        ))
        .unwrap();
    reader.install(table.id(), fd::Fd(3), false).unwrap();
    writer.install(table.id(), fd::Fd(4), false).unwrap();
    let region = Box::leak(carrick_test_support::TestEl1Region::zeroed());
    // SAFETY: aligned ABI storage retained for all inherited table bindings.
    let map = unsafe {
        &*region
            .as_ptr()
            .add(carrick_el1_abi::EL1_IPC_TABLE_MAP_OFFSET as usize)
            .cast::<carrick_el1_abi::ipc_tables::IpcTableMap>()
    };
    map.publish(5, table.id().to_raw()).unwrap();
    let pages: Vec<_> = (0..32).map(|n| 0x20000 + n * 0x1000).collect();
    let mut crossing = TestStockCrossing::new(&pages);
    crossing.metadata_in_el1_window = true;
    crossing.ipc = Some((Arc::clone(&owner), map));
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        &crossing,
    )
    .with_words(&words);
    let parent = TaskKey {
        id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
        serial: TaskSerial::from_raw_u64(11).unwrap(),
    };
    let children: [_; 2] = core::array::from_fn(|_| {
        let mut entry = runtime
            .enter(source, &fixture.task, parked, &mut service)
            .unwrap();
        let LifecycleOutcome::Returned { result, .. } = entry.fork(ProcessForkChildTid::NONE)
        else {
            panic!("native fork must return");
        };
        assert!(result.raw() > 0, "fork errno: {}", -result.raw());
        let child = runtime
            .namespace_child_key(parent, result.raw() as u32)
            .unwrap();
        runtime.task_binding(child).unwrap()
    });
    assert_ne!(children[0].address.mm, children[1].address.mm);
    let parent_binding = runtime.task_binding(parent).unwrap();
    fixture
        .zone
        .requeue_preempted(fixture.slot, parent_binding.record.id);
    let sender_slot = SlotId::new(1);
    let sender_source = BornInZoneSource {
        zone: fixture.zone,
        slot: sender_slot,
    };
    let mut sender_service = Aarch64NativeProcessService::with_crossing(
        &sender_task,
        sender_slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        &crossing,
    )
    .with_words(&words);
    let mut sender = if signal.is_some() {
        fixture
            .zone
            .unhome(fixture.slot, parent_binding.record.id, 3);
        assert_eq!(
            fixture.zone.claim_for_host(
                parent_binding.record,
                None,
                carrick_sched_core::Handback::Resumed,
                &ShortLockSpin
            ),
            carrick_sched_core::HostClaim::Claimed
        );
        fixture.zone.drive(sender_slot, 2);
        fixture.zone.publish_slot(
            sender_slot,
            parent_binding.address.mm.raw().get(),
            Some(1),
            3,
        );
        fixture.zone.enter_guest(sender_slot);
        fixture
            .zone
            .install_space(sender_slot, parent_binding.address.mm.raw().get())
            .unwrap();
        fixture
            .zone
            .requeue_on(sender_slot, parent_binding.record.id)
            .unwrap();
        activate_target(sender_source, &sender_task, &parent_binding);
        Some(
            runtime
                .enter(
                    sender_source,
                    &sender_task,
                    parent_binding.words,
                    &mut sender_service,
                )
                .unwrap(),
        )
    } else {
        None
    };
    let tables = crate::ipc::MapTables(map);
    let venue = crate::ipc::IpcVenue {
        region: owner.region(),
        tables: &tables,
    };
    let counters = carrick_el1_abi::Counters::new();
    let mut cpu = crate::sched::FakeCpu::default();
    let call = |cpu: &mut crate::sched::FakeCpu,
                frame: &mut carrick_el1_abi::TrapFrame,
                interrupt: &mut dyn FnMut() -> bool| {
        let mut sched = crate::sched::Sched {
            handoff: None,
            zone: fixture.zone,
            slot: fixture.slot,
            task: &fixture.task,
            cpu,
            user: &crate::sched::HardwareUserWord,
            counters: &counters,
        };
        crate::ipc::serve_ipc_with_signals(
            &mut sched,
            frame,
            &venue,
            &mut NoCopy,
            signal.is_some(),
            interrupt,
        )
        .0
    };
    let frame_for_call = || {
        let mut frame = carrick_el1_abi::TrapFrame {
            elr: 0x4004,
            slot: fixture.slot.raw() as u64,
            ..Default::default()
        };
        frame.x[8] = if signal.is_some_and(|case| case.epoll) {
            22
        } else {
            63
        };
        frame.x[0] = 3;
        frame.x[1] = 0x4000;
        frame.x[2] = 8;
        frame.x[3] = 500;
        frame
    };
    let write_byte = || {
        let mut cpu = crate::sched::FakeCpu::default();
        let mut sched = crate::sched::Sched {
            handoff: None,
            zone: fixture.zone,
            slot: sender_slot,
            task: &sender_task,
            cpu: &mut cpu,
            user: &crate::sched::HardwareUserWord,
            counters: &counters,
        };
        let mut frame = carrick_el1_abi::TrapFrame {
            elr: 0x5004,
            slot: u64::from(sender_slot.raw()),
            ..Default::default()
        };
        frame.x[8] = 64;
        frame.x[0] = 4;
        frame.x[1] = 0x8000;
        frame.x[2] = 1;
        assert_eq!(
            crate::ipc::serve_ipc(&mut sched, &mut frame, &venue, &mut ByteCopy),
            crate::ipc::IpcServed::Returned { switched: false }
        );
        assert_eq!(frame.x[0], 1, "the live peer writes one byte");
        if sender_task.linux.has_pending_host_work() {
            // The real write may wake a foreign MM on its driver's queue.
            // Model its ordinary host boundary: the shipping relocation and
            // handback owners place the readers, retaining the live sender.
            fixture.zone.leave_guest(sender_slot, &ShortLockSpin);
            carrick_kernel::el1_zone::with_test_zone(fixture.zone, || {
                fixture.zone.relocate(
                    sender_slot,
                    Some(parent_binding.address.mm.raw().get()),
                    &mut |record, discard| {
                        assert!(!discard);
                        carrick_kernel::el1_zone::hand_back(&[record]);
                    },
                    &mut |placement| {
                        if placement.resched {
                            carrick_kernel::el1_zone::resched_slot(placement.slot);
                        }
                    },
                );
            });
            if let Some(work) = sender_task.linux.take_host_work_doorbell() {
                work.settled();
            }
            fixture.zone.enter_guest(sender_slot);
        }
    };
    let mut saved = Vec::new();
    for child in &children {
        if signal.is_some() {
            let identity = fixture.zone.record(child.record.id).identity();
            // SAFETY: production fork retained this exact child's control for
            // the fixture lifetime. Its policy deliberately owns CPU zero.
            let control = unsafe { &*(identity.control_slot as *const ThreadControlSlot) };
            control.initialize_affinity(carrick_core::affinity::CpuAffinity::from_words(&[1]));
            fixture.zone.record(child.record.id).set_affinity(1);
        }
        activate_target(source, &fixture.task, child);
        assert!(fixture.zone.record(child.record.id).is_native_owned());
        if let Some(case) = signal {
            runtime
                .enter(source, &fixture.task, child.words, &mut service)
                .unwrap()
                .rt_sigaction(
                    Signal::from_number(10).unwrap(),
                    Some(Action {
                        disposition: Disposition::Handler(HandlerAddress(0x700000)),
                        flags: ActionFlags {
                            restart: case.restart,
                            ..Default::default()
                        },
                        ..Action::default()
                    }),
                )
                .unwrap();
        }
        // Pending boundary work makes the real adapter leave after publishing
        // its park, rather than selecting the still-live parent or sibling.
        fixture.task.linux.mark_pending_host_work();
        if signal.is_some_and(|case| case.before_enrollment) {
            sender
                .as_mut()
                .unwrap()
                .kill(
                    SignalProcessSelector::from_abi(u64::from(child.visible_pid)),
                    SignalRequest::from_abi(10).unwrap(),
                    SignalInfo::Generated(None),
                )
                .unwrap();
        }
        let mut frame = frame_for_call();
        let served = if signal.is_some() {
            let mut entry = runtime
                .enter(source, &fixture.task, child.words, &mut service)
                .unwrap();
            call(&mut cpu, &mut frame, &mut || entry.interrupt_pending_wait())
        } else {
            call(&mut cpu, &mut frame, &mut || false)
        };
        assert_eq!(served, crate::ipc::IpcServed::Idle);
        assert!(matches!(
            fixture.zone.record(child.record.id).claim(),
            Claim::Parked { .. } | Claim::Transferring { .. }
        ));
        assert!(
            fixture.zone.slot(fixture.slot).current().is_none(),
            "park releases execution"
        );
        saved.push(
            fixture
                .zone
                .record(child.record.id)
                .object_wait_census()
                .unwrap(),
        );
    }
    fixture.zone.leave_guest(fixture.slot, &ShortLockSpin);
    if away {
        assert!(fixture.zone.step_away(
            fixture.slot,
            1,
            &mut |record| {
                assert!(
                    signal.is_none(),
                    "the signal sender stays on its own live driver"
                );
                assert_eq!(record, parent_binding.record);
            },
            &mut |_| panic!("the fixture has no second driver"),
        ));
        assert!(!fixture.zone.slot(fixture.slot).is_live());
    }
    if signal.is_some() {
        let race = if signal.is_some_and(|case| case.eof_race) {
            drop(writer);
            for child in &children {
                let raw = map
                    .lookup(fixture.zone.record(child.record.id).identity().file_table)
                    .unwrap();
                if let Some(description) = owner
                    .region()
                    .fd(ShortLockSpin)
                    .close(fd::TableId::from_raw(raw), fd::Fd(4))
                    .unwrap()
                {
                    owner.release(description.backing).unwrap();
                }
            }
            let table = table.clone();
            let zone = fixture.zone;
            let (done, finished) = std::sync::mpsc::channel();
            // Test-owned peer publication. The bounded completion wait below
            // precedes join; production never creates this host thread.
            #[allow(clippy::disallowed_methods)]
            let thread = std::thread::spawn(move || {
                carrick_kernel::el1_zone::with_test_zone(zone, || table.close(fd::Fd(4)).unwrap());
                done.send(()).unwrap();
            });
            Some((thread, finished))
        } else {
            None
        };
        for child in &children {
            if signal.is_some_and(|case| case.before_enrollment || case.partial) {
                continue;
            }
            sender
                .as_mut()
                .unwrap()
                .kill(
                    SignalProcessSelector::from_abi(u64::from(child.visible_pid)),
                    SignalRequest::from_abi(10).unwrap(),
                    SignalInfo::Generated(None),
                )
                .unwrap();
        }
        if let Some((thread, finished)) = race {
            finished
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("peer EOF publication must finish");
            thread.join().unwrap();
        }
        if signal.is_some_and(|case| case.partial) {
            fixture.zone.enter_guest(fixture.slot);
            write_byte();
        }
        carrick_kernel::el1_zone::with_test_zone(fixture.zone, || {
            carrick_kernel::el1_zone::hand_back_completions();
        });
        for (child, operation) in children.iter().zip(&saved) {
            let resumed = fixture
                .zone
                .record(child.record.id)
                .object_wait_census()
                .unwrap();
            assert_eq!(
                (resumed.operation, resumed.operation_generation),
                (operation.operation, operation.operation_generation)
            );
            assert_eq!(resumed.queue, 0, "detach exactly this waiter");
            assert!(
                matches!(
                    fixture.zone.record(child.record.id).claim(),
                    Claim::Queued { .. }
                ),
                "caught signal must release the native pipe park while the driver is away: {:?}; handback={:?}; Signal claims={}",
                fixture.zone.record(child.record.id).claim(),
                fixture.zone.record(child.record.id).handback(),
                fixture.zone.counters.host_claims[carrick_sched_core::Handback::Signal as usize]
                    .load(Ordering::Relaxed)
            );
        }
        assert_eq!(fixture.zone.slot(fixture.slot).queued(), 2);
        carrick_kernel::el1_zone::with_test_zone(fixture.zone, || {
            carrick_kernel::el1_zone::hand_back_completions()
        });
        assert_eq!(
            fixture.zone.slot(fixture.slot).queued(),
            2,
            "no duplicate publication"
        );
        if let Some(work) = fixture.task.linux.take_host_work_doorbell() {
            work.settled();
        }
        if away {
            fixture.zone.step_back(fixture.slot, 1);
        }
        fixture.zone.enter_guest(fixture.slot);
        for (index, child) in children.iter().enumerate() {
            if index > 0 && signal.is_some_and(|case| case.partial) {
                write_byte();
            }
            let switched = activate_target(source, &fixture.task, child);
            assert_eq!(
                switched.result, None,
                "retained syscall arguments survive handback"
            );
            let mut frame = carrick_el1_abi::TrapFrame {
                slot: u64::from(fixture.slot.raw()),
                ..Default::default()
            };
            // SAFETY: activate_target owns this child's OnCpu record. Restore
            // its saved SVC context, then model executing that SVC again.
            let context = unsafe { fixture.zone.record(child.record.id).ctx_mut() };
            crate::sched::ThreadCpu::load(&mut cpu, &mut frame, context);
            frame.elr += 4;
            assert_eq!(frame.x[0], 3);
            assert_eq!(
                frame.x[8],
                if signal.is_some_and(|case| case.epoll) {
                    22
                } else {
                    63
                }
            );
            let mut entry = runtime
                .enter(source, &fixture.task, child.words, &mut service)
                .unwrap();
            let served = if signal.is_some_and(|case| case.partial) {
                let mut notify = || {
                    sender
                        .as_mut()
                        .unwrap()
                        .kill(
                            SignalProcessSelector::from_abi(u64::from(child.visible_pid)),
                            SignalRequest::from_abi(10).unwrap(),
                            SignalInfo::Generated(None),
                        )
                        .unwrap()
                };
                let mut sched = crate::sched::Sched {
                    handoff: None,
                    zone: fixture.zone,
                    slot: fixture.slot,
                    task: &fixture.task,
                    cpu: &mut cpu,
                    user: &crate::sched::HardwareUserWord,
                    counters: &counters,
                };
                crate::ipc::serve_ipc_with_signals(
                    &mut sched,
                    &mut frame,
                    &venue,
                    &mut SignalCopy(&mut notify),
                    true,
                    &mut || entry.interrupt_pending_wait(),
                )
                .0
            } else {
                call(&mut cpu, &mut frame, &mut || entry.interrupt_pending_wait())
            };
            assert_eq!(served, crate::ipc::IpcServed::Returned { switched: false });
            let returned = frame.x[0] as i64;
            if signal.is_some_and(|case| case.partial) {
                assert_eq!(returned, 1);
            } else if signal.is_some_and(|case| case.eof_race) {
                assert!(
                    matches!(returned, -4 | 0),
                    "signal/EOF has one winning owner: {returned}"
                );
            } else {
                assert_eq!(
                    returned, -4,
                    "the blocked read is interrupted before handler publication"
                );
            }
            assert!(!fixture.zone.record(child.record.id).has_object_operation());
            let mut stack = Box::new(ArmWaitSignalStack([0; 16384]));
            let stack_base = stack.0.as_mut_ptr() as u64;
            assert!(entry.signal_checkpoint_needed());
            let control = fixture.task.lifecycle_refs().unwrap().1;
            let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
            assert_eq!(
                crate::signal_delivery::deliver_signal_with_control(
                    &fixture.task,
                    control,
                    &mut entry,
                    &mut frame,
                    fp.as_bytes(),
                    &mut ArmWaitSignalMachine {
                        user_sp: UserVa::new(stack_base + stack.0.len() as u64),
                        backend: ArmWaitSignalBackend,
                    }
                ),
                None
            );
            assert_eq!(frame.elr, 0x700000, "publish the real handler");
            assert_eq!(frame.x[0], 10);
            let offset = usize::try_from(frame.x[1].checked_sub(stack_base).unwrap()).unwrap();
            let decoded = carrick_personality_linux::signal::arm::decode(
                &stack.0[offset..],
                UserVa::new(frame.x[1]),
                true,
            )
            .unwrap();
            assert_eq!(
                (decoded.pc.raw(), decoded.regs[0]),
                if signal.is_some_and(|case| case.restart && !case.epoll && !case.partial) {
                    (0x4000, 3)
                } else {
                    (0x4004, returned as u64)
                },
                "the handler's saved context obeys SA_RESTART"
            );
            assert!(
                !entry.signal_checkpoint_needed(),
                "delivery consumes the signal once"
            );
            drop(entry);
            if signal.is_some_and(|case| case.restart && !case.epoll && !case.partial) {
                write_byte();
                // The decoded handler context is the VM-free sigreturn
                // authority. Execute its restarted read after the peer write.
                let mut restarted = frame_for_call();
                restarted.x = decoded.regs;
                restarted.elr = decoded.pc.raw() + 4;
                let mut sched = crate::sched::Sched {
                    handoff: None,
                    zone: fixture.zone,
                    slot: fixture.slot,
                    task: &fixture.task,
                    cpu: &mut cpu,
                    user: &crate::sched::HardwareUserWord,
                    counters: &counters,
                };
                assert_eq!(
                    crate::ipc::serve_ipc(&mut sched, &mut restarted, &venue, &mut ByteCopy),
                    crate::ipc::IpcServed::Returned { switched: false }
                );
                assert_eq!(
                    restarted.x[0], 1,
                    "restarted read completes after the peer writes"
                );
            }
            fixture
                .zone
                .requeue_preempted(fixture.slot, child.record.id);
        }
        assert_eq!(fixture.zone.counters.el1_parks.load(Ordering::Relaxed), 2);
        return;
    }
    // Every inherited writer is closed in the host venue while both children
    // remain alive. The final close runs the shipping ObjectWakeDelivery path.
    carrick_kernel::el1_zone::with_test_zone(fixture.zone, || {
        drop(writer);
        table.close(fd::Fd(4)).unwrap();
        for child in &children {
            let raw = map
                .lookup(fixture.zone.record(child.record.id).identity().file_table)
                .unwrap();
            let child_table = fd::TableId::from_raw(raw);
            if let Some(description) = owner
                .region()
                .fd(ShortLockSpin)
                .close(child_table, fd::Fd(4))
                .unwrap()
            {
                owner.release(description.backing).unwrap();
            }
        }
    });
    for (child, operation) in children.iter().zip(saved) {
        assert!(
            runtime.task_binding(child.key).is_some(),
            "peer stays alive"
        );
        let record = fixture.zone.record(child.record.id);
        assert!(
            matches!(record.claim(), Claim::Queued { .. }),
            "native IPC wake has no host continuation: {:?}",
            record.claim()
        );
        let resumed = record.object_wait_census().unwrap();
        assert_eq!(
            (resumed.operation, resumed.operation_generation),
            (operation.operation, operation.operation_generation),
            "retain exact operation"
        );
        assert_eq!(resumed.queue, 0);
    }
    if away {
        fixture.zone.step_back(fixture.slot, 1);
    }
    fixture.zone.enter_guest(fixture.slot);
    for child in &children {
        activate_target(source, &fixture.task, child);
        let mut frame = carrick_el1_abi::TrapFrame {
            elr: 0x4004,
            slot: fixture.slot.raw() as u64,
            ..Default::default()
        };
        frame.x[8] = 63;
        frame.x[0] = 3;
        frame.x[1] = 0x4000;
        frame.x[2] = 8;
        assert_eq!(
            call(&mut cpu, &mut frame, &mut || false),
            crate::ipc::IpcServed::Returned { switched: false }
        );
        assert_eq!(frame.x[0], 0, "the same read completes EOF, never replays");
        assert!(!fixture.zone.record(child.record.id).has_object_operation());
        fixture
            .zone
            .requeue_preempted(fixture.slot, child.record.id);
    }
    assert_eq!(fixture.zone.counters.el1_parks.load(Ordering::Relaxed), 2);
}

#[test]
fn serial_host_deliverable_signal_does_not_cancel_mm_edit_conflict() {
    use crate::mm_portal::{TransferIntent, prepare_transfer, test_support};
    use carrick_personality_linux::signal::{
        ProcessSignals, SignalInfo, SignalProcessSelector, SignalRequest,
    };
    use carrick_signal_core::policy::{Action, Disposition, HandlerAddress, Signal};

    struct RootRegistration<'a> {
        registry: &'a NativeProcessRegistry<'a, Mm, Aarch64ParkedContext>,
        runtime: Arc<NativeProcessRuntime<'a, Mm, Aarch64ParkedContext>>,
    }
    impl Drop for RootRegistration<'_> {
        fn drop(&mut self) {
            self.registry.unregister_root_for_test(&self.runtime);
        }
    }

    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    let parked = Aarch64ParkedContext::from_parts(ThreadCtx::ZERO, fixture.address);
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
    let owner_registry = registry();
    owner_registry
        .register_root(runtime.clone(), source, &fixture.task, fixture.address)
        .unwrap();
    let _registration = RootRegistration {
        registry: owner_registry,
        runtime: runtime.clone(),
    };
    let binding = runtime
        .task_binding(TaskKey {
            id: carrick_personality_linux::identity::task_id_from_linux_pid(41).unwrap(),
            serial: TaskSerial::from_raw_u64(11).unwrap(),
        })
        .unwrap();
    fixture
        .zone
        .requeue_preempted(fixture.slot, binding.record.id);
    activate_target(source, &fixture.task, &binding);
    // SAFETY: this fixture exclusively selected the exact registered root.
    unsafe {
        *fixture.zone.record(binding.record.id).ctx_mut() = parked;
    }
    assert!(fixture.zone.record(binding.record.id).is_native_owned());
    let mut service = fixture.process_service();
    let mut entry = runtime
        .enter(source, &fixture.task, parked, &mut service)
        .unwrap();
    entry
        .rt_sigaction(
            Signal::from_number(10).unwrap(),
            Some(Action {
                disposition: Disposition::Handler(HandlerAddress(0x700000)),
                ..Action::default()
            }),
        )
        .unwrap();
    let view = test_support::nodes(fixture.region);
    let portal = crate::mm_portal::MmPortal::new(
        NonZeroU64::MIN,
        fixture.region.table(),
        &fixture.zone.spaces,
        &view,
    )
    .with_zone(fixture.zone)
    .unwrap();
    let mm = ReservationMm::new(1).unwrap();
    let transfer = portal
        .begin(
            portal.admitted_handle(mm, 0).unwrap(),
            crate::mm_portal::GuestVa::new(test_support::VA),
            4096,
            TransferIntent::UserWrite,
            0,
        )
        .unwrap();
    let request = test_support::selected(test_support::select(&portal, &transfer, &fixture.tables))
        .request(
            TransferIntent::UserWrite,
            carrick_el1_abi::PortalRetainedData {
                record: NonZeroU64::MIN,
                vm_generation: NonZeroU64::MIN,
                owner: None,
            },
        )
        .unwrap();
    let permit = prepare_transfer(
        &portal,
        request,
        &fixture.tables.live(&fixture.maintenance),
        0,
    )
    .unwrap()
    .unwrap();
    let key = portal.prepared_wait_key(transfer.handle).unwrap();
    let record = fixture.zone.slot(fixture.slot).current().unwrap();
    let mut cpu = crate::sched::FakeCpu::default();
    let counters = carrick_el1_abi::Counters::new();
    let mut frame = carrick_el1_abi::TrapFrame {
        elr: 0x4004,
        ..Default::default()
    };
    frame.x[8] = 215;
    frame.x[0] = test_support::VA;
    frame.x[1] = 4096;
    fixture.task.linux.mark_pending_host_work();
    let mut sched = crate::sched::Sched {
        handoff: None,
        zone: fixture.zone,
        slot: fixture.slot,
        task: &fixture.task,
        cpu: &mut cpu,
        user: &crate::sched::HardwareUserWord,
        counters: &counters,
    };
    assert!(matches!(
        crate::mm_portal::park_prepared_edit(&mut sched, &mut frame, fixture.region.table()),
        Some(crate::sched::Served::Idle)
    ));
    assert!(matches!(
        fixture.zone.record(record).claim(),
        Claim::Parked { .. }
    ));
    let retained = fixture.zone.record(record).object_wait_census().unwrap();
    entry
        .kill(
            SignalProcessSelector::from_abi(41),
            SignalRequest::from_abi(10).unwrap(),
            SignalInfo::Generated(None),
        )
        .unwrap();
    assert!(
        entry.interrupt_pending_wait(),
        "the caught signal is deliverable"
    );
    assert!(
        matches!(fixture.zone.record(record).claim(), Claim::Parked { .. }),
        "a signal must not cancel the MM edit-conflict park"
    );
    assert_eq!(
        fixture
            .zone
            .object_queue_census(key.index())
            .unwrap()
            .waiters,
        1
    );
    assert!(entry.take_run_failure().is_none());
    let after_signal = fixture.zone.record(record).object_wait_census().unwrap();
    assert_eq!(
        (after_signal.operation, after_signal.operation_generation),
        (retained.operation, retained.operation_generation),
        "the MM owner retains the same edit operation"
    );
    portal.cancel_prepared(permit, request, 0).unwrap();
    assert_eq!(
        fixture
            .zone
            .object_queue_census(key.index())
            .unwrap()
            .waiters,
        0,
        "the prepared-transfer owner releases its edit waiter"
    );
    let weak_runtime = Arc::downgrade(&runtime);
    drop(entry);
    drop(_registration);
    drop(runtime);
    assert!(
        owner_registry
            .for_record(fixture.zone, binding.record)
            .is_none()
    );
    assert_eq!(
        weak_runtime.strong_count(),
        0,
        "registry teardown must release the root runtime and its signal summary"
    );
}
