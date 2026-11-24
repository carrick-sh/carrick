//! A process-exit owner retains its exact continuation across host requests.
use super::{add_service_sibling, native_exec_fixture, words};
use crate::native_process_runtime::NativeResume;
use carrick_el1_abi::{BornInZoneSource, ExecutionBinding, Lifecycle};
use carrick_personality_linux::lifecycle::{LifecycleOutcome, LinuxWaitStatus, ProcessNative};

/// Exact native report retained for the VM-free executor adapter.
#[derive(Debug)]
pub struct NativeTerminalFailure {
    pub binding: ExecutionBinding,
    pub cause: carrick_core_abi::NativeRunFailureCause,
}

/// Run two real native members through terminal park, handback and exit.
/// Only physical memory service is substituted by the enclosing host fixture.
pub fn run() -> Result<LinuxWaitStatus, NativeTerminalFailure> {
    let fixture = native_exec_fixture();
    let sibling = add_service_sibling(&fixture, None);
    assert!(sibling.service_ticket.is_none());
    let live_members = fixture.page.live();
    assert_eq!(live_members, 2);
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, fixture.record.id)
            .is_queued()
    );
    assert_eq!(
        fixture.zone.switch_in(fixture.slot),
        Some(fixture.record.id)
    );
    assert!(matches!(
        fixture.zone.claim_for_host(
            fixture.record,
            None,
            carrick_sched_core::Handback::Control,
            &carrick_sched_core::ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
        ),
        carrick_sched_core::HostClaim::El1Held { .. }
    ));
    let mut service = fixture.service();
    let saved = words(fixture.address);
    let mut owner = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    assert!(matches!(
        owner.exit_group(0),
        LifecycleOutcome::Transferred { .. }
    ));
    if let Some(cause) = owner.take_run_failure() {
        return Err(NativeTerminalFailure {
            binding: owner.binding,
            cause,
        });
    }
    let owner_record_exists = fixture.zone.live(fixture.record).is_some();
    assert!(owner_record_exists);
    assert!(owner.take_handoff_receipt().is_some());
    drop(owner);
    let live_members = fixture.page.live();
    assert_eq!(live_members, 1);
    assert!(sibling.control.host_exit_requested());
    // A requested group exit has not yet retired this exact sibling.
    assert_eq!(
        carrick_core::terminal::missing_zone_continuation(
            sibling.control,
            sibling.control.host_birth_identity().unwrap(),
            sibling.control.host_birth_identity(),
            sibling.record,
            sibling.control.zone_record(),
        ),
        carrick_core::terminal::MissingContinuationVerdict::InvariantViolation
    );

    let mut sibling_service = fixture.service();
    let mut member = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling.slot,
            },
            sibling.task,
            fixture.address,
            &saved,
            &mut sibling_service,
        )
        .unwrap();
    assert!(matches!(
        member.exit_group(9),
        LifecycleOutcome::Transferred { .. }
    ));
    if let Some(cause) = member.take_run_failure() {
        return Err(NativeTerminalFailure {
            binding: member.binding,
            cause,
        });
    }
    assert!(member.take_handoff_receipt().is_some());
    drop(member);
    let live_members = fixture.page.live();
    assert_eq!(live_members, 0);
    let sibling_record_retired = fixture.zone.live(sibling.record).is_none();
    assert!(sibling_record_retired);
    use carrick_core::terminal::{MissingContinuationVerdict, missing_zone_continuation};
    let birth = sibling.control.host_birth_identity().unwrap();
    assert_eq!(
        missing_zone_continuation(
            sibling.control,
            birth,
            Some(birth),
            sibling.record,
            sibling.control.zone_record(),
        ),
        MissingContinuationVerdict::Terminal
    );
    // A recycled/foreign binding cannot borrow this member's terminal receipt.
    assert_eq!(
        missing_zone_continuation(
            sibling.control,
            birth,
            Some(birth),
            fixture.record,
            sibling.control.zone_record(),
        ),
        MissingContinuationVerdict::InvariantViolation
    );
    assert_eq!(
        missing_zone_continuation(
            sibling.control,
            birth,
            fixture.control.host_birth_identity(),
            sibling.record,
            sibling.control.zone_record(),
        ),
        MissingContinuationVerdict::InvariantViolation
    );

    // The existing host handback reloads a fresh home record and renews its
    // retained native registry binding before entering the owner checkpoint.
    let record = fixture.zone.take_service_head(fixture.slot).unwrap();
    assert_eq!(record, fixture.record);
    let identity = fixture.zone.record(record.id).identity();
    fixture.zone.free_record(record.id);
    let home = fixture.zone.current_or_new(fixture.slot, identity).unwrap();
    fixture
        .registry
        .rehome_entry(
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            fixture.page,
            fixture.control,
        )
        .unwrap()
        .unwrap();
    assert_ne!(fixture.zone.record_ref(home), record);
    let mut owner = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    let resumed = owner
        .resume_checkpoint(|_| Ok(None))
        .map_err(|cause| NativeTerminalFailure {
            binding: owner.binding,
            cause,
        })?;
    assert_eq!(owner.take_run_failure(), None);
    let NativeResume::Left(Some(status)) = resumed else {
        panic!("terminal owner did not publish its status");
    };
    Ok(status)
}

#[cfg(test)]
#[test]
fn exit_group_host_request_before_terminal_park_retains_owner() {
    assert_eq!(run().unwrap(), LinuxWaitStatus::exited(0));
}

#[cfg(test)]
#[test]
fn run_failed_never_mints_terminal_load_authority() {
    let fixture = native_exec_fixture();
    let _sibling = add_service_sibling(&fixture, None);
    assert_eq!(fixture.page.live(), 2);
    let mut service = fixture.service();
    let saved = words(fixture.address);
    let mut owner = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    owner.run_failed(carrick_core_abi::NativeRunFailureReason::NativeQuarantined);
    assert_eq!(
        owner.take_run_failure().map(|cause| cause.reason),
        Some(carrick_core_abi::NativeRunFailureReason::NativeQuarantined)
    );
    assert!(fixture.zone.live(fixture.record).is_none());
    let birth = fixture.control.host_birth_identity().unwrap();
    assert_eq!(
        carrick_core::terminal::missing_zone_continuation(
            fixture.control,
            birth,
            Some(birth),
            fixture.record,
            fixture.control.zone_record(),
        ),
        carrick_core::terminal::MissingContinuationVerdict::InvariantViolation,
        "run_failed cleanup must never mint ordinary terminal authority"
    );
}

#[cfg(test)]
#[test]
fn losing_entryless_exit_group_publishes_terminal_before_record_release() {
    use super::super::PendingCloseOperation;
    use carrick_sched_core::object_wait::OwnerEntry;
    let fixture = native_exec_fixture();
    let sibling = add_service_sibling(&fixture, None);
    assert_eq!(fixture.page.live(), 2);
    assert!(fixture.control.entry().is_none());
    assert!(
        fixture
            .zone
            .requeue_preempted(fixture.slot, fixture.record.id)
            .is_queued()
    );
    assert_eq!(
        fixture.zone.switch_in(fixture.slot),
        Some(fixture.record.id)
    );
    let saved = words(fixture.address);
    let mut sibling_service = fixture.service();
    let mut owner = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling.slot,
            },
            sibling.task,
            fixture.address,
            &saved,
            &mut sibling_service,
        )
        .unwrap();
    owner
        .begin_closing(PendingCloseOperation::Exit {
            status: LinuxWaitStatus::exited(0),
            entry: OwnerEntry::Syscall,
        })
        .unwrap();
    let mut service = fixture.service();
    let mut loser = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    let (page, channel) = loser
        .begin_closing(PendingCloseOperation::Exit {
            status: LinuxWaitStatus::exited(9),
            entry: OwnerEntry::Exception,
        })
        .unwrap();
    assert!(matches!(
        fixture.zone.claim_for_host(
            fixture.record,
            None,
            carrick_sched_core::Handback::Control,
            &carrick_sched_core::ShortLockSpin,
            &|owned| crate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
        ),
        carrick_sched_core::HostClaim::El1Held { .. }
    ));
    assert!(
        loser
            .park_pending_exit(page, &channel, OwnerEntry::Exception)
            .unwrap()
            .is_some()
    );
    assert!(fixture.zone.live(fixture.record).is_none());
    let birth = fixture.control.host_birth_identity().unwrap();
    assert_eq!(
        carrick_core::terminal::missing_zone_continuation(
            fixture.control,
            birth,
            Some(birth),
            fixture.record,
            fixture.control.zone_record(),
        ),
        carrick_core::terminal::MissingContinuationVerdict::Terminal,
        "losing entry-less caller released its saved continuation without terminal custody"
    );
    assert_eq!(
        fixture.page.live(),
        0,
        "each of the two callers owns one live unit"
    );
}

#[cfg(test)]
#[test]
fn losing_pool_exit_group_does_not_reserve_membership_twice() {
    use super::super::PendingCloseOperation;
    use carrick_sched_core::object_wait::OwnerEntry;
    let fixture = native_exec_fixture();
    let sibling = add_service_sibling(&fixture, None);
    assert_eq!(fixture.page.live(), 2);
    assert!(
        fixture
            .zone
            .requeue_preempted(sibling.slot, sibling.record.id)
            .is_queued()
    );
    assert_eq!(
        fixture.zone.switch_in(sibling.slot),
        Some(sibling.record.id)
    );
    assert!(fixture.zone.live(sibling.record).is_some());
    let saved = words(fixture.address);
    let mut service = fixture.service();
    let mut owner = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    owner
        .begin_closing(PendingCloseOperation::Exit {
            status: LinuxWaitStatus::exited(0),
            entry: OwnerEntry::Syscall,
        })
        .unwrap();
    let mut sibling_service = fixture.service();
    let mut loser = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling.slot,
            },
            sibling.task,
            fixture.address,
            &saved,
            &mut sibling_service,
        )
        .unwrap();
    let (page, channel) = loser
        .begin_closing(PendingCloseOperation::Exit {
            status: LinuxWaitStatus::exited(9),
            entry: OwnerEntry::Syscall,
        })
        .unwrap();
    assert_eq!(page.live(), 0);
    assert!(
        loser
            .park_pending_exit(page, &channel, OwnerEntry::Syscall)
            .unwrap()
            .is_some()
    );
    assert!(fixture.zone.live(sibling.record).is_none());
    let graph_cleanup =
        carrick_core::terminal::reserve_host_thread_exit_membership(page, sibling.control)
            .expect("losing caller already consumed its exact membership");
    graph_cleanup
        .retire_published(
            sibling.control.entry().unwrap(),
            sibling.control,
            &carrick_core::lifecycle::RegistryWriteHeld::for_test(),
        )
        .unwrap();
    assert_eq!(page.live(), 0);
}

#[cfg(test)]
#[test]
fn losing_exit_group_keeps_host_reserved_membership_and_live_record() {
    use super::super::PendingCloseOperation;
    use carrick_sched_core::object_wait::OwnerEntry;
    let fixture = native_exec_fixture();
    let _ = super::super::host_test_support::take_terminal_vacates();
    let sibling = add_service_sibling(&fixture, None);
    assert_eq!(fixture.page.live(), 2);
    assert!(
        fixture
            .zone
            .requeue_preempted(sibling.slot, sibling.record.id)
            .is_queued()
    );
    assert_eq!(
        fixture.zone.switch_in(sibling.slot),
        Some(sibling.record.id)
    );
    assert!(fixture.zone.live(sibling.record).is_some());
    let installed = fixture.zone.installed_space(sibling.slot);
    assert_ne!(
        installed, 0,
        "the switched-in sibling runs in its process space"
    );
    let saved = words(fixture.address);
    let mut service = fixture.service();
    let mut owner = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    owner
        .begin_closing(PendingCloseOperation::Exit {
            status: LinuxWaitStatus::exited(0),
            entry: OwnerEntry::Syscall,
        })
        .unwrap();
    let host =
        carrick_core::terminal::reserve_host_thread_exit_membership(fixture.page, sibling.control)
            .unwrap();
    assert_eq!(fixture.page.live(), 0);
    let mut sibling_service = fixture.service();
    let mut loser = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling.slot,
            },
            sibling.task,
            fixture.address,
            &saved,
            &mut sibling_service,
        )
        .unwrap();
    let (page, channel) = loser
        .begin_closing(PendingCloseOperation::Exit {
            status: LinuxWaitStatus::exited(9),
            entry: OwnerEntry::Exception,
        })
        .unwrap();
    assert!(matches!(
        loser
            .park_pending_exit(page, &channel, OwnerEntry::Exception)
            .unwrap(),
        Some(LifecycleOutcome::HostCustody)
    ));
    assert!(fixture.zone.live(sibling.record).is_some());
    assert_eq!(
        super::super::host_test_support::take_terminal_vacates(),
        0,
        "host custody must keep the installed process translation live"
    );
    assert_eq!(
        fixture.zone.installed_space(sibling.slot),
        installed,
        "host custody keeps the slot's space occupancy with its translation"
    );
    assert_eq!(page.live(), 0);
    assert!(
        host.commit_zone_retirement(&carrick_core::lifecycle::RegistryWriteHeld::for_test())
            .retire_published(
                sibling.control.entry().unwrap(),
                sibling.control,
                &carrick_core::lifecycle::RegistryWriteHeld::for_test()
            )
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        loser
            .park_pending_exit(page, &channel, OwnerEntry::Exception)
            .unwrap(),
        Some(LifecycleOutcome::Transferred { .. })
    ));
    assert!(fixture.zone.live(sibling.record).is_none());
    assert_eq!(super::super::host_test_support::take_terminal_vacates(), 1);
    assert_eq!(
        fixture.zone.installed_space(sibling.slot),
        0,
        "the released member's slot holds no process space"
    );
    assert_eq!(page.live(), 0);
}

#[cfg(test)]
#[test]
fn retiring_host_issued_sibling_refuses_tgkill_with_esrch() {
    use carrick_personality_linux::signal::{
        ProcessSignals, SignalInfo, SignalRequest, SignalThreadSelector,
    };
    let fixture = native_exec_fixture();
    let sibling = super::add_signal_sibling(&fixture, None, true);
    assert_eq!(fixture.page.live(), 2);
    let _reserved =
        carrick_core::terminal::reserve_host_thread_exit_membership(fixture.page, sibling.control)
            .unwrap();
    let saved = words(fixture.address);
    let mut service = fixture.service();
    let mut sender = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            &saved,
            &mut service,
        )
        .unwrap();
    assert_eq!(
        sender.tgkill(
            SignalThreadSelector::from_abi(41),
            SignalThreadSelector::from_abi(42),
            SignalRequest::Probe,
            SignalInfo::Generated(None),
        ),
        Err(carrick_syscall_abi::LINUX_ESRCH),
    );
}

#[cfg(test)]
struct RawExitStatusFrame(
    carrick_personality_linux::crossing::HostCrossingSet,
    carrick_sched_core::SlotId,
    u64,
);

#[cfg(test)]
impl carrick_personality_linux::dispatch::SyscallFrame for RawExitStatusFrame {
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
    fn slot(&self) -> Option<carrick_sched_core::SlotId> {
        Some(self.1)
    }
    fn task_index(&self) -> usize {
        0
    }
    fn user_sp(&self) -> Option<super::UserVa> {
        Some(super::UserVa::new(0x8000))
    }
}

#[cfg(test)]
impl crate::dispatch::GuestDispatchFrame for RawExitStatusFrame {
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

#[cfg(test)]
fn arm_syscall_words(
    address: super::AddressContext<super::RootGpa>,
) -> carrick_sched_core::Aarch64ParkedContext {
    let mut native = carrick_el1_abi::ThreadCtx::ZERO;
    native.pc = 0x40_0004;
    native.sp_el0 = 0x80_0000;
    carrick_sched_core::Aarch64ParkedContext::from_parts(native, address)
}

#[cfg(test)]
fn spawn_born_sibling<C: super::ProcessContext + 'static>(
    fixture: &super::NativeSignalFixture<C>,
    make_words: fn(super::AddressContext<super::RootGpa>) -> C,
) -> (
    &'static carrick_el1_abi::CurrentTask,
    &'static carrick_el1_abi::ThreadControlSlot,
    carrick_sched_core::SlotId,
    carrick_sched_core::RecordRef,
) {
    use carrick_el1_abi::{BornRecord, EntryIdentity, Lifecycle, ThreadIdentity};
    use core::sync::atomic::Ordering;

    let slot = carrick_sched_core::SlotId::new(1);
    let tid = 42_u32;
    let serial = 102_u64;
    let affinity = 1_u64 << 1;
    let zone = fixture.zone;
    zone.drive(slot, 2);
    zone.publish_slot(slot, 1, Some(1), affinity);
    zone.enter_guest(slot);
    zone.install_space(slot, 1).unwrap();

    let control = Box::leak(Box::new(carrick_el1_abi::ThreadControlSlot::new()));
    let birth =
        carrick_core_abi::BirthSerial::of_task(super::TaskSerial::from_raw_u64(serial).unwrap());
    let entry = fixture
        .page
        .stock(
            0,
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
                clone_flags: 0x0001_0000,
                clear_child_tid: 0,
                blocked: carrick_el1_abi::BlockedMask(0),
            },
        )
        .unwrap();
    fixture.page.thread_born().unwrap();
    fixture.page.publish(entry).unwrap();

    let task = Box::leak(Box::new(carrick_el1_abi::CurrentTask::new()));
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
    zone.namespace()
        .with_view(&carrick_sched_core::ShortLockSpin, |ns| {
            ns.reserve_exact(tid as i32, super::ClaimKind::Thread)
                .unwrap();
        });

    let record_id = zone
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
    assert!(zone.mark_native_owned(record_id));
    // SAFETY: newly allocated unpublished fixture record.
    unsafe {
        *zone.record(record_id).ctx_mut() = make_words(fixture.address);
    }
    assert!(zone.requeue_preempted(slot, record_id).is_queued());
    assert_eq!(zone.switch_in_full(slot).unwrap().record, record_id);
    let record = zone.record_ref(record_id);
    control.bind_zone_record(record);
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
    assert!(zone.mark_native_owned(record_id));
    (task, control, slot, record)
}

/// #2932: when peer A holds a refundable reservation inside `serve_exit`'s
/// `clear_child_tid` copy, the leader's raw `SYS_exit(38)` must not promote to
/// `exit_group` while peer A's reservation can still roll back. Instead it
/// parks on reservation release; once peer A commits its exit, the woken
/// leader reruns `SYS_exit(38)` and retires the process as the sole survivor.
#[cfg(test)]
fn refundable_peer_commit_wakes_parked_raw_exit_to_retire_process<C, B>(
    make_words: fn(super::AddressContext<super::RootGpa>) -> C,
    isa: carrick_personality_linux::crossing::HostCrossingSet,
) where
    C: super::ProcessContext + crate::dispatch::DispatchContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
{
    use carrick_personality_linux::dispatch::{CompletionRoute, dispatch};
    use core::sync::atomic::{AtomicBool, Ordering};

    let fixture: &'static super::NativeSignalFixture<C> =
        Box::leak(Box::new(super::native_exec_fixture_for::<C, B>(make_words)));
    let (sibling_task, sibling_control, sibling_slot, sibling_record) =
        spawn_born_sibling(fixture, make_words);
    assert!(fixture.zone.mark_native_owned(fixture.record.id));
    sibling_control.set_clear_child_tid(0x4000);
    assert_eq!(fixture.page.live(), 2);

    struct SingleVenue<'a> {
        page: &'a carrick_el1_abi::ThreadLifecyclePage,
        control: &'a carrick_el1_abi::ThreadControlSlot,
    }
    impl crate::thread_setup::LifecycleVenue for SingleVenue<'_> {
        fn thread<'a>(
            &'a self,
            _: &'a carrick_el1_abi::CurrentTask,
        ) -> Option<carrick_personality_linux::thread::LifecycleThread<'a>> {
            Some(carrick_personality_linux::thread::LifecycleThread {
                page: self.page,
                slot: self.control,
            })
        }
        fn born_slot(
            &self,
            _: &carrick_el1_abi::ThreadLifecyclePage,
            _: carrick_el1_abi::EntryRef,
        ) -> Option<&carrick_el1_abi::ThreadControlSlot> {
            None
        }
    }

    let leader_parked = std::sync::Arc::new(AtomicBool::new(false));
    let leader_parked_hook = leader_parked.clone();
    super::set_before_signal_copy_hook(Box::new(move |address| {
        assert_eq!(address, super::UserVa::new(0x4000));
        assert_eq!(fixture.page.live(), 1);

        let counters = carrick_el1_abi::Counters::new();
        let names = carrick_el1_abi::InotifyNameCache::new();
        let venue = SingleVenue {
            page: fixture.page,
            control: fixture.control,
        };
        let mut service = fixture.service();
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                BornInZoneSource {
                    zone: fixture.zone,
                    slot: fixture.slot,
                },
                fixture.task,
                fixture.address,
                &make_words(fixture.address),
                &mut service,
            )
            .unwrap();
        let route = {
            let mut frame = RawExitStatusFrame(isa, fixture.slot, 38);
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
                current_tasks: core::slice::from_ref(fixture.task),
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
                    zone: fixture.zone,
                    slot: fixture.slot,
                }),
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
        assert_eq!(route, CompletionRoute::Suspended);
        assert_eq!(
            fixture.page.gate(),
            carrick_el1_abi::GateState::Open,
            "leader raw exit promoted to exit_group while sibling's reservation was refundable"
        );
        assert!(entry.take_root_exit().is_none());
        assert!(entry.take_handoff_receipt().is_none());
        assert!(fixture.zone.slot(fixture.slot).current().is_none());
        assert!(entry.take_run_failure().is_none());
        assert!(matches!(
            fixture.zone.record(fixture.record.id).claim(),
            carrick_sched_core::Claim::Parked { .. }
        ));
        leader_parked_hook.store(true, Ordering::Release);
    }));

    let counters_a = carrick_el1_abi::Counters::new();
    let names_a = carrick_el1_abi::InotifyNameCache::new();
    let venue_a = SingleVenue {
        page: fixture.page,
        control: sibling_control,
    };
    let mut service_a = fixture.service();
    service_a.waker_slot = sibling_slot;
    service_a.tid_words.insert((1, 0x4000), 42);
    let mut entry_a = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling_slot,
            },
            sibling_task,
            fixture.address,
            &make_words(fixture.address),
            &mut service_a,
        )
        .unwrap();
    {
        let mut frame_a = RawExitStatusFrame(isa, sibling_slot, 0);
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
            current_tasks: core::slice::from_ref(sibling_task),
            fd_map: &[],
            object_table: &[],
            open_table: &[],
            inotify_table: &[],
            name_cache: &names_a,
            zone: None,
            ipc: None,
            lifecycle: Some(&venue_a),
            process: Some(entry_a.as_mut()),
            source: Some(BornInZoneSource {
                zone: fixture.zone,
                slot: sibling_slot,
            }),
            anonymous: None,
            cache_lookup: |_| core::ptr::null_mut(),
        };
        assert_eq!(
            dispatch(
                carrick_syscall_abi::CanonicalNr::new(
                    carrick_personality_linux::lifecycle::SYS_EXIT as u64,
                )
                .raw(),
                u64::MAX,
                &mut pending_a,
            ),
            CompletionRoute::Suspended,
        );
    }
    assert!(leader_parked.load(Ordering::Acquire));
    assert_eq!(fixture.page.gate(), carrick_el1_abi::GateState::Open);
    assert!(entry_a.take_root_exit().is_none());
    assert!(entry_a.take_run_failure().is_none());
    drop(entry_a);
    assert!(fixture.zone.live(sibling_record).is_none());
    assert_eq!(fixture.page.live(), 1);
    assert_eq!(
        fixture.zone.slot(fixture.slot).queued(),
        1,
        "sibling reservation commit must wake parked leader raw exit"
    );

    fixture.zone.install_space(fixture.slot, 1).unwrap();
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        fixture.record.id
    );
    // SAFETY: `fixture.record` was just selected on `fixture.slot`.
    let saved_leader = unsafe { fixture.runtime.record_binding(fixture.record) }
        .unwrap()
        .words;
    let mut service_leader = fixture.service();
    let mut entry_leader = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            &saved_leader,
            &mut service_leader,
        )
        .unwrap();
    let resumed = entry_leader.resume_checkpoint(|_| Ok(None)).unwrap();
    assert!(matches!(
        resumed,
        NativeResume::RetrySyscall | NativeResume::RetrySavedSyscall
    ));
    drop(entry_leader);

    let counters_final = carrick_el1_abi::Counters::new();
    let names_final = carrick_el1_abi::InotifyNameCache::new();
    let venue_final = SingleVenue {
        page: fixture.page,
        control: fixture.control,
    };
    let mut entry_leader = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            &saved_leader,
            &mut service_leader,
        )
        .unwrap();
    {
        let mut frame_final = RawExitStatusFrame(isa, fixture.slot, 38);
        let mut pending_final: crate::dispatch::El1PendingFamilies<
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
            frame: &mut frame_final,
            counters: &counters_final,
            current_tasks: core::slice::from_ref(fixture.task),
            fd_map: &[],
            object_table: &[],
            open_table: &[],
            inotify_table: &[],
            name_cache: &names_final,
            zone: None,
            ipc: None,
            lifecycle: Some(&venue_final),
            process: Some(entry_leader.as_mut()),
            source: Some(BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            }),
            anonymous: None,
            cache_lookup: |_| core::ptr::null_mut(),
        };
        assert_eq!(
            dispatch(
                carrick_syscall_abi::CanonicalNr::new(
                    carrick_personality_linux::lifecycle::SYS_EXIT as u64,
                )
                .raw(),
                u64::MAX,
                &mut pending_final,
            ),
            CompletionRoute::Suspended,
        );
    }
    assert_eq!(fixture.page.gate(), carrick_el1_abi::GateState::Closed);
    assert_eq!(
        entry_leader.take_root_exit(),
        Some(LinuxWaitStatus::exited(38))
    );
    assert!(entry_leader.take_handoff_receipt().is_none());
    assert!(entry_leader.take_run_failure().is_none());
    assert!(fixture.zone.live(fixture.record).is_none());
    assert_eq!(fixture.page.live(), 0);
}

#[cfg(test)]
#[test]
fn refundable_peer_commit_wakes_parked_raw_exit_to_retire_process_x86() {
    super::ENTRYLESS_RETIREMENT.with(|owner| owner.set(super::EntrylessRetirement::Ring));
    refundable_peer_commit_wakes_parked_raw_exit_to_retire_process::<
        super::ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(
        words,
        carrick_personality_linux::crossing::HostCrossingSet::X86,
    );
    super::ENTRYLESS_RETIREMENT.with(|owner| owner.set(super::EntrylessRetirement::HostThread));
}

#[cfg(test)]
#[test]
fn refundable_peer_commit_wakes_parked_raw_exit_to_retire_process_aarch64() {
    refundable_peer_commit_wakes_parked_raw_exit_to_retire_process::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(
        arm_syscall_words,
        carrick_personality_linux::crossing::HostCrossingSet::Aarch64,
    );
}

/// The one-thread lifecycle venue a raw-exit witness dispatches through.
#[cfg(test)]
struct RawExitVenue<'a> {
    page: &'a carrick_el1_abi::ThreadLifecyclePage,
    control: &'a carrick_el1_abi::ThreadControlSlot,
}

#[cfg(test)]
impl crate::thread_setup::LifecycleVenue for RawExitVenue<'_> {
    fn thread<'a>(
        &'a self,
        _: &'a carrick_el1_abi::CurrentTask,
    ) -> Option<carrick_personality_linux::thread::LifecycleThread<'a>> {
        Some(carrick_personality_linux::thread::LifecycleThread {
            page: self.page,
            slot: self.control,
        })
    }
    fn born_slot(
        &self,
        _: &carrick_el1_abi::ThreadLifecyclePage,
        _: carrick_el1_abi::EntryRef,
    ) -> Option<&carrick_el1_abi::ThreadControlSlot> {
        None
    }
}

/// Dispatch one raw `exit(status)` through the production personality
/// dispatch, with `process` as the member's native process venue.
#[cfg(test)]
fn dispatch_raw_exit<'ipc, C>(
    source: BornInZoneSource<'static, C>,
    task: &'static carrick_el1_abi::CurrentTask,
    page: &'static carrick_el1_abi::ThreadLifecyclePage,
    control: &'static carrick_el1_abi::ThreadControlSlot,
    process: &mut dyn ProcessNative<'ipc, C>,
    isa: carrick_personality_linux::crossing::HostCrossingSet,
    status: u64,
) -> carrick_personality_linux::dispatch::CompletionRoute
where
    C: super::ProcessContext + crate::dispatch::DispatchContext + 'static,
{
    let counters = carrick_el1_abi::Counters::new();
    let names = carrick_el1_abi::InotifyNameCache::new();
    let venue = RawExitVenue { page, control };
    let mut frame = RawExitStatusFrame(isa, source.slot, status);
    let mut pending: crate::dispatch::El1PendingFamilies<
        '_,
        'ipc,
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
        process: Some(process),
        source: Some(source),
        anonymous: None,
        cache_lookup: |_| core::ptr::null_mut(),
    };
    carrick_personality_linux::dispatch::dispatch(
        carrick_syscall_abi::CanonicalNr::new(
            carrick_personality_linux::lifecycle::SYS_EXIT as u64,
        )
        .raw(),
        u64::MAX,
        &mut pending,
    )
}

/// #2974 review P0-2: a nonfinal raw exit whose `release_current` refuses
/// before any scheduler rollback restores its refundable live unit. A peer
/// raw exit parked on that reservation must be woken by that restoration:
/// a deferred wake that nothing drains leaves the peer parked with the
/// lifecycle gate open forever.
#[cfg(test)]
fn refused_nonfinal_release_wakes_parked_raw_exit<C, B>(
    make_words: fn(super::AddressContext<super::RootGpa>) -> C,
    isa: carrick_personality_linux::crossing::HostCrossingSet,
) where
    C: super::ProcessContext + crate::dispatch::DispatchContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
{
    use carrick_personality_linux::dispatch::CompletionRoute;
    use core::sync::atomic::{AtomicBool, Ordering};

    let fixture: &'static super::NativeSignalFixture<C> =
        Box::leak(Box::new(super::native_exec_fixture_for::<C, B>(make_words)));
    let (sibling_task, sibling_control, sibling_slot, sibling_record) =
        spawn_born_sibling(fixture, make_words);
    assert!(fixture.zone.mark_native_owned(fixture.record.id));
    sibling_control.set_clear_child_tid(0x4000);
    assert_eq!(fixture.page.live(), 2);

    let leader_parked = std::sync::Arc::new(AtomicBool::new(false));
    let leader_parked_hook = leader_parked.clone();
    super::set_before_signal_copy_hook(Box::new(move |address| {
        assert_eq!(address, super::UserVa::new(0x4000));
        // The sibling holds the refundable live unit: the leader is at the
        // floor and parks on the reservation's release.
        assert_eq!(fixture.page.live(), 1);
        let mut service = fixture.service();
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                BornInZoneSource {
                    zone: fixture.zone,
                    slot: fixture.slot,
                },
                fixture.task,
                fixture.address,
                &make_words(fixture.address),
                &mut service,
            )
            .unwrap();
        assert_eq!(
            dispatch_raw_exit(
                BornInZoneSource {
                    zone: fixture.zone,
                    slot: fixture.slot,
                },
                fixture.task,
                fixture.page,
                fixture.control,
                entry.as_mut(),
                isa,
                38,
            ),
            CompletionRoute::Suspended
        );
        assert!(entry.take_run_failure().is_none());
        assert!(matches!(
            fixture.zone.record(fixture.record.id).claim(),
            carrick_sched_core::Claim::Parked { .. }
        ));
        // The sibling's exact record stops being its lane's current one
        // before release: `retire_current` refuses ahead of the scheduler's
        // commit or rollback, with its membership still reserved.
        fixture.zone.clear_current(sibling_slot);
        leader_parked_hook.store(true, Ordering::Release);
    }));

    let mut service_a = fixture.service();
    service_a.waker_slot = sibling_slot;
    service_a.tid_words.insert((1, 0x4000), 42);
    let mut entry_a = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling_slot,
            },
            sibling_task,
            fixture.address,
            &make_words(fixture.address),
            &mut service_a,
        )
        .unwrap();
    let _ = dispatch_raw_exit(
        BornInZoneSource {
            zone: fixture.zone,
            slot: sibling_slot,
        },
        sibling_task,
        fixture.page,
        sibling_control,
        entry_a.as_mut(),
        isa,
        0,
    );
    assert!(leader_parked.load(Ordering::Acquire));
    assert!(entry_a.take_run_failure().is_none());
    drop(entry_a);
    assert!(
        fixture.zone.live(sibling_record).is_some(),
        "the refused release keeps the sibling's record"
    );
    assert_eq!(
        fixture.page.live(),
        2,
        "the refused release restores the sibling's live unit"
    );
    assert_eq!(fixture.page.gate(), carrick_el1_abi::GateState::Open);
    assert_eq!(
        fixture.zone.slot(fixture.slot).queued(),
        1,
        "a refused nonfinal release must wake the raw exit parked on its reservation"
    );
}

#[cfg(test)]
#[test]
fn refused_nonfinal_release_wakes_parked_raw_exit_x86() {
    super::ENTRYLESS_RETIREMENT.with(|owner| owner.set(super::EntrylessRetirement::Ring));
    refused_nonfinal_release_wakes_parked_raw_exit::<
        super::ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(
        words,
        carrick_personality_linux::crossing::HostCrossingSet::X86,
    );
    super::ENTRYLESS_RETIREMENT.with(|owner| owner.set(super::EntrylessRetirement::HostThread));
}

#[cfg(test)]
#[test]
fn refused_nonfinal_release_wakes_parked_raw_exit_aarch64() {
    refused_nonfinal_release_wakes_parked_raw_exit::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(
        arm_syscall_words,
        carrick_personality_linux::crossing::HostCrossingSet::Aarch64,
    );
}

/// #2974 review P0-1: a raw `exit` never returns to user mode (`_exit(2)`),
/// so a raw exit woken from its reservation park is still exiting. A caught
/// signal pending when it resumes must not run its handler there: a
/// detached thread may already have unmapped its own stack. The shared
/// user-return gate both ISAs run after a resumed retry leaves the saved
/// `exit` untouched, and the rerun `exit` retires the process with its own
/// status rather than the handler running in the middle of exit.
#[cfg(test)]
fn resumed_raw_exit_runs_no_pending_signal_handler<C, B>(
    make_words: fn(super::AddressContext<super::RootGpa>) -> C,
    isa: carrick_personality_linux::crossing::HostCrossingSet,
) where
    C: super::ProcessContext + crate::dispatch::DispatchContext + 'static,
    B: carrick_mmu_core::owner_mmu::OwnerForkMmu,
    super::HostArmSignalMachine:
        crate::signal_delivery::SignalMachine<C, Backend = super::HostArmBackend>,
{
    use carrick_personality_linux::dispatch::CompletionRoute;
    use carrick_signal_core::policy::{Action, Disposition, HandlerAddress, Signal};
    use core::sync::atomic::{AtomicBool, Ordering};
    use zerocopy::IntoBytes;

    let fixture: &'static super::NativeSignalFixture<C> =
        Box::leak(Box::new(super::native_exec_fixture_for::<C, B>(make_words)));
    let (sibling_task, sibling_control, sibling_slot, sibling_record) =
        spawn_born_sibling(fixture, make_words);
    assert!(fixture.zone.mark_native_owned(fixture.record.id));
    sibling_control.set_clear_child_tid(0x4000);
    assert_eq!(fixture.page.live(), 2);

    let leader_parked = std::sync::Arc::new(AtomicBool::new(false));
    let leader_parked_hook = leader_parked.clone();
    super::set_before_signal_copy_hook(Box::new(move |address| {
        assert_eq!(address, super::UserVa::new(0x4000));
        assert_eq!(fixture.page.live(), 1);
        let mut service = fixture.service();
        let mut entry = fixture
            .runtime
            .enter_registered(
                fixture.registry,
                BornInZoneSource {
                    zone: fixture.zone,
                    slot: fixture.slot,
                },
                fixture.task,
                fixture.address,
                &make_words(fixture.address),
                &mut service,
            )
            .unwrap();
        assert_eq!(
            dispatch_raw_exit(
                BornInZoneSource {
                    zone: fixture.zone,
                    slot: fixture.slot,
                },
                fixture.task,
                fixture.page,
                fixture.control,
                entry.as_mut(),
                isa,
                38,
            ),
            CompletionRoute::Suspended
        );
        assert!(entry.take_run_failure().is_none());
        leader_parked_hook.store(true, Ordering::Release);
    }));

    let mut service_a = fixture.service();
    service_a.waker_slot = sibling_slot;
    service_a.tid_words.insert((1, 0x4000), 42);
    let mut entry_a = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling_slot,
            },
            sibling_task,
            fixture.address,
            &make_words(fixture.address),
            &mut service_a,
        )
        .unwrap();
    assert_eq!(
        dispatch_raw_exit(
            BornInZoneSource {
                zone: fixture.zone,
                slot: sibling_slot,
            },
            sibling_task,
            fixture.page,
            sibling_control,
            entry_a.as_mut(),
            isa,
            0,
        ),
        CompletionRoute::Suspended
    );
    assert!(leader_parked.load(Ordering::Acquire));
    assert!(entry_a.take_run_failure().is_none());
    drop(entry_a);
    assert!(fixture.zone.live(sibling_record).is_none());
    assert_eq!(fixture.zone.slot(fixture.slot).queued(), 1);

    fixture.zone.install_space(fixture.slot, 1).unwrap();
    assert_eq!(
        fixture.zone.switch_in_full(fixture.slot).unwrap().record,
        fixture.record.id
    );
    // SAFETY: `fixture.record` was just selected on `fixture.slot`.
    let saved_leader = unsafe { fixture.runtime.record_binding(fixture.record) }
        .unwrap()
        .words;
    let mut service_leader = fixture.service();
    let mut entry_leader = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            &saved_leader,
            &mut service_leader,
        )
        .unwrap();
    // A caught SIGUSR1 is pending for the parked exit's thread when it
    // resumes, as Go's preemption signal or a SIGCHLD can be.
    let usr1 = Signal::from_number(10).unwrap();
    let handler = Action {
        disposition: Disposition::Handler(HandlerAddress(0x40_0100)),
        ..Default::default()
    };
    carrick_personality_linux::signal::ProcessSignals::rt_sigaction(
        &mut *entry_leader,
        usr1,
        Some(handler),
    )
    .unwrap();
    fixture
        .runtime
        .current_signals(fixture.task)
        .unwrap()
        .enqueue_thread(fixture.record, usr1, None);

    let resumed = entry_leader.resume_checkpoint(|_| Ok(None)).unwrap();
    assert!(matches!(
        resumed,
        NativeResume::RetrySyscall | NativeResume::RetrySavedSyscall
    ));
    // The user-return gate a resumed retry passes through on x86 CPL0 and on
    // ARM EL1 before the saved `exit` instruction runs again.
    assert!(
        !entry_leader.signal_checkpoint_needed(),
        "an exiting thread owes no signal checkpoint"
    );
    let mut frame = carrick_el1_abi::TrapFrame {
        elr: 0x40_0000,
        ..Default::default()
    };
    frame.x[0] = 38;
    frame.x[8] = 93;
    let before = frame;
    let fp = carrick_syscall_abi::LinuxFpsimdContext::empty();
    let route = crate::signal_delivery::deliver_signal_on_syscall_return(
        fixture.task,
        fixture.control,
        &mut entry_leader,
        &mut frame,
        fp.as_bytes(),
        &mut super::HostArmSignalMachine {
            backend: super::HostArmBackend,
        },
    );
    assert_eq!(route, None);
    assert_eq!(
        (frame.elr, frame.x[0], frame.x[8]),
        (before.elr, before.x[0], before.x[8]),
        "a resumed raw exit must rerun as exit, never enter a signal handler"
    );
    assert!(entry_leader.take_run_failure().is_none());
    drop(entry_leader);

    let mut entry_leader = fixture
        .runtime
        .enter_registered(
            fixture.registry,
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.address,
            &saved_leader,
            &mut service_leader,
        )
        .unwrap();
    assert_eq!(
        dispatch_raw_exit(
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot,
            },
            fixture.task,
            fixture.page,
            fixture.control,
            entry_leader.as_mut(),
            isa,
            38,
        ),
        CompletionRoute::Suspended
    );
    assert_eq!(fixture.page.gate(), carrick_el1_abi::GateState::Closed);
    assert_eq!(
        entry_leader.take_root_exit(),
        Some(LinuxWaitStatus::exited(38)),
        "the rerun exit retires the process with its own status"
    );
    assert!(entry_leader.take_run_failure().is_none());
    assert_eq!(fixture.page.live(), 0);
}

#[cfg(test)]
#[test]
fn resumed_raw_exit_runs_no_pending_signal_handler_x86() {
    super::ENTRYLESS_RETIREMENT.with(|owner| owner.set(super::EntrylessRetirement::Ring));
    resumed_raw_exit_runs_no_pending_signal_handler::<
        super::ParkedContextWords,
        carrick_mmu_core::x86::owner_mmu::X86Mmu,
    >(
        words,
        carrick_personality_linux::crossing::HostCrossingSet::X86,
    );
    super::ENTRYLESS_RETIREMENT.with(|owner| owner.set(super::EntrylessRetirement::HostThread));
}

#[cfg(test)]
#[test]
fn resumed_raw_exit_runs_no_pending_signal_handler_aarch64() {
    resumed_raw_exit_runs_no_pending_signal_handler::<
        carrick_sched_core::Aarch64ParkedContext,
        carrick_mmu_core::owner_mmu::Aarch64Mmu,
    >(
        arm_syscall_words,
        carrick_personality_linux::crossing::HostCrossingSet::Aarch64,
    );
}
