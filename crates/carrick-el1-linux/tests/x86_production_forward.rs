//! The host build of the library uses the same Unavailable file authority as
//! the production CPL0 image. Keep the x86 no-venue routing out of cfg(test).
//!
//! This target shares carrick-el1-linux's dev-dependencies, which enable
//! `carrick-el1/host-test` for the library's unit tests. The claim still
//! holds: the no-venue routing is chosen by carrick-el1-linux's own
//! `cfg(any(test, feature = "host-test"))`, which is off for this target, and
//! carrick-el1's host-test items are test doubles, a bounded wake trace and
//! a copy-fault flag that the no-venue witnesses leave unset. The native
//! input-completion witness below injects a guarded-copy refusal after admission. The
//! no-venue witnesses pass unchanged with that dev feature removed (#690 review);
//! the explicit input-copy failure injection requires the dev feature.
#![allow(clippy::panic)]

use carrick_el1_abi::{Action, Counters, CurrentTask, El1TaskId, InotifyNameCache, TrapFrame};
use carrick_el1_linux::{dispatch, sched};
use carrick_guest_arch::{NativeReturnWord, SlotId, UserVa};
use carrick_personality_linux::dispatch::SyscallFrame;
use carrick_personality_linux::entry::decode_x86_64;
use carrick_syscall_abi::CanonicalNr;
use core::sync::atomic::{AtomicU64, Ordering};

struct X86Frame<'a> {
    native: carrick_guest_arch::NativeOrdinal,
    canonical: CanonicalNr,
    args: [u64; 6],
    rax: u64,
    isa_unsupported: &'a AtomicU64,
}

impl SyscallFrame for X86Frame<'_> {
    fn canonical_ordinal(&self) -> CanonicalNr {
        self.canonical
    }
    fn argument(&self, index: usize) -> Option<u64> {
        self.args.get(index).copied()
    }
    fn result(&self) -> NativeReturnWord {
        NativeReturnWord(self.rax)
    }
    fn set_result(&mut self, result: NativeReturnWord) {
        self.rax = result.0;
    }
    fn slot(&self) -> Option<SlotId> {
        Some(SlotId::new(0))
    }
    fn user_sp(&self) -> Option<UserVa> {
        Some(UserVa::new(0x7fff_0000))
    }
}

impl dispatch::GuestDispatchFrame for X86Frame<'_> {
    fn native_number(&self) -> carrick_guest_arch::NativeOrdinal {
        self.native
    }

    fn crossing_set(&self) -> carrick_personality_linux::crossing::HostCrossingSet {
        carrick_personality_linux::crossing::HostCrossingSet::X86
    }

    fn arm_frame(&mut self) -> Option<&mut TrapFrame> {
        None
    }
    fn arm_frame_ref(&self) -> Option<&TrapFrame> {
        None
    }
    fn arm_scheduler(&self) -> bool {
        false
    }
    fn robust_publications(&self) -> Option<&core::sync::atomic::AtomicU64> {
        None
    }
    fn record_isa_unsupported_forward(&self) {
        self.isa_unsupported.fetch_add(1, Ordering::Relaxed);
    }
}

// No native scheduling venue is supplied. Any CPU hook would be a bug.
struct NoCpu;
impl sched::ThreadCpu for NoCpu {
    fn save(
        &mut self,
        _: &TrapFrame,
        _: &mut carrick_el1_abi::Aarch64ParkedContext,
        _: sched::CpuExitCause,
    ) {
        panic!("no CPU venue");
    }
    fn load(&mut self, _: &mut TrapFrame, _: &carrick_el1_abi::Aarch64ParkedContext) {
        panic!("no CPU venue");
    }
    fn set_translation(&mut self, _: u64, _: u64) {
        panic!("no CPU venue");
    }
    fn live_ttbr0(&self) -> Option<u64> {
        None
    }
    fn invalidate_asid(&mut self, _: u64) {
        panic!("no CPU venue");
    }
    fn now(&self) -> u64 {
        panic!("no CPU venue");
    }
    fn freq(&self) -> u64 {
        panic!("no CPU venue");
    }
    fn set_timer(&mut self, _: Option<u64>) {
        panic!("no CPU venue");
    }
    fn send_sgi(&mut self, _: u64) {
        panic!("no CPU venue");
    }
    fn ack_irq(&mut self) -> u32 {
        panic!("no CPU venue");
    }
    fn end_irq(&mut self, _: u32) {
        panic!("no CPU venue");
    }
    fn wait_for_interrupt(&mut self) {
        panic!("no CPU venue");
    }
    fn spin(&mut self) {
        panic!("no CPU venue");
    }
    fn own_sgi_target(&self) -> u64 {
        panic!("no CPU venue");
    }
}

#[test]
fn production_x86_family_absences_obey_crossings_without_user_memory() {
    let tasks = [CurrentTask::new()];
    tasks[0].set(
        El1TaskId::from_linux_tid(41),
        carrick_el1_abi::SnapshotGeneration::from_raw(1),
        7,
    );
    let counters = Counters::new();
    let names = InotifyNameCache::new();
    let isa_unsupported = AtomicU64::new(0);
    // The file table is live, but the carrier published no file, IPC or MM
    // venue. Invalid user pointers make an accidental copy observable.
    let args = [3, 0xffff_ffff_ffff_f000, 8, 0, 0, 0];
    for (family, native) in [
        ("anonymous brk", 12),
        ("anonymous mmap", 9),
        ("anonymous mprotect", 10),
        ("anonymous munmap", 11),
        ("IPC read", 0),
        ("IPC write", 1),
        ("IPC epoll_pwait", 281),
        ("futex", 202),
        ("loader openat", 257),
        ("loader legacy access", 21),
        ("loader fstat", 5),
        ("loader newfstatat", 262),
        ("file seek", 8),
        ("file pread", 17),
        ("file pwrite", 18),
        ("inotify add", 254),
        ("inotify remove", 255),
        ("lifecycle sigprocmask", 14),
        ("lifecycle sigaltstack", 131),
        ("signal-return transport", 15),
        ("clone", 56),
        ("fork", 57),
        ("wait4", 61),
        ("getpid decline", 39),
        ("gettid decline", 186),
    ] {
        for work in [false, true] {
            if work {
                tasks[0].linux.mark_pending_host_work();
            } else {
                if let Some(doorbell) = tasks[0].linux.take_host_work_doorbell() {
                    doorbell.settled();
                }
            }
            let call = decode_x86_64(native, args, 0x7fff_0000);
            assert_ne!(call.canonical.raw(), u64::MAX, "{family} must decode");
            let mut frame = X86Frame {
                native: call.native,
                canonical: call.canonical,
                args: call.args,
                rax: 0xfeed,
                isa_unsupported: &isa_unsupported,
            };
            let before_isa = isa_unsupported.load(Ordering::Relaxed);
            let bucket = if native == 57 { 512 } else { native as usize };
            let before_refused = counters.refused[bucket].load(Ordering::Relaxed);
            let action = dispatch::dispatch_syscall_with_lifecycle(
                &mut frame,
                &counters,
                &tasks,
                &[],
                &[],
                &[],
                &[],
                &names,
                None::<dispatch::Zone<'_, NoCpu, sched::HardwareUserWord>>,
                None,
                None,
                None,
                |_| core::ptr::null_mut(),
            );
            let allowed = matches!(native, 0 | 1 | 5 | 8 | 17 | 18 | 20 | 21 | 257 | 262 | 281);
            assert_eq!(
                action,
                if allowed {
                    Action::Forward
                } else {
                    if work {
                        Action::ServedWithWork
                    } else {
                        Action::Served
                    }
                },
                "{family}"
            );
            assert_eq!(
                frame.rax as i64,
                if allowed { 0xfeed } else { -38 },
                "{family}"
            );
            if native == 202 {
                let mut diagnostic = String::new();
                counters.write_syscall_frames(&mut diagnostic).unwrap();
                assert!(diagnostic.contains("futex-error"), "{diagnostic}");
                assert!(diagnostic.contains("result=-38 errno=38"), "{diagnostic}");
                assert!(
                    diagnostic.contains("address=0x3 op=18446744073709547520"),
                    "{diagnostic}"
                );
            }
            assert_eq!(
                counters.refused[bucket].load(Ordering::Relaxed) - before_refused,
                u64::from(!allowed),
                "{family}"
            );
            assert_eq!(
                isa_unsupported.load(Ordering::Relaxed) - before_isa,
                u64::from(!work && matches!(native, 202)),
                "{family} must distinguish ISA refusal from semantic forwarding"
            );
            assert_eq!(
                counters
                    .served
                    .get(call.canonical.raw() as usize)
                    .map_or(0, |count| count.load(Ordering::Relaxed)),
                0,
                "{family} must not record a guest service"
            );
            assert_eq!(
                tasks[0].linux.take_served_boundary(),
                if work && !allowed {
                    Some(carrick_el1_abi::ServedBoundary::Completed)
                } else {
                    None
                },
                "{family} work={work}"
            );
        }
    }
}

#[test]
fn x86_context_selects_x86_crossings_without_arm_aperture() {
    use dispatch::GuestDispatchFrame;
    let counter = AtomicU64::new(0);
    let frame = X86Frame {
        native: carrick_guest_arch::NativeOrdinal::new(0),
        canonical: CanonicalNr::new(63),
        args: [0; 6],
        rax: 0,
        isa_unsupported: &counter,
    };
    assert_eq!(
        frame.crossing_set(),
        carrick_personality_linux::crossing::HostCrossingSet::X86
    );
    assert!(frame.crossing_strict(|| panic!("x86 must not read ARM aperture")));
}

#[test]
fn x86_unported_refusal_counts_native_ordinal_not_canonical_ordinal() {
    let tasks = [CurrentTask::new()];
    tasks[0].set(
        El1TaskId::from_linux_tid(41),
        carrick_el1_abi::SnapshotGeneration::from_raw(1),
        7,
    );
    let counters = Counters::new();
    let names = InotifyNameCache::new();
    let isa_unsupported = AtomicU64::new(0);
    let call = decode_x86_64(102, [0; 6], 0x7fff_0000); // getuid -> canonical 174
    let mut frame = X86Frame {
        native: call.native,
        canonical: call.canonical,
        args: call.args,
        rax: 102,
        isa_unsupported: &isa_unsupported,
    };
    let action = dispatch::dispatch_syscall_with_lifecycle(
        &mut frame,
        &counters,
        &tasks,
        &[],
        &[],
        &[],
        &[],
        &names,
        None::<dispatch::Zone<'_, NoCpu, sched::HardwareUserWord>>,
        None,
        None,
        None,
        |_| core::ptr::null_mut(),
    );
    assert_eq!(action, Action::Served);
    assert_eq!(frame.rax as i64, -38);
    assert_eq!(counters.refused[102].load(Ordering::Relaxed), 1);
    assert_eq!(counters.refused[174].load(Ordering::Relaxed), 0);
}

#[test]
fn child_exit_releases_control_custody_before_retire_mm_reclaims_stock() {
    use carrick_core::lifecycle::MemberControlCustody;
    use carrick_el1_abi::{
        BornInZoneSource, DelegatedOpenFile, FD_MAP_CAPACITY, FdMapSlot, ThreadControlSlot,
        ThreadIdentity, ThreadLifecyclePage,
    };
    use carrick_el1_linux::native_process_runtime::{
        NativeForkPreparation, NativeLifecycleResources, NativeProcessError, NativeProcessRegistry,
        NativeProcessRuntime, NativeProcessService,
    };
    use carrick_guest_arch::{AddressContext, ContextGeneration, FrameGpa, MmGeneration, RootGpa};
    use carrick_hal::birth_serial::test_support::OwnedBirthZone;
    use carrick_kernel::kernel::{Container, Kernel, LaunchContext, RootBootstrap, RunId};
    use carrick_mmu_core::x86::owner_mmu::X86Mmu;
    use carrick_personality_linux::lifecycle::{LifecycleOutcome, LinuxWaitStatus, ProcessNative};
    use carrick_sched_core::{ParkedContextWords, WakeEffects, X86_XSAVE_BYTES, ZoneTables};
    use core::num::NonZeroU64;
    use std::sync::Arc;

    struct StockReclaimingService<'a> {
        zone: &'a ZoneTables<ParkedContextWords>,
        child_page: &'a ThreadLifecyclePage,
        child_controls: &'a [ThreadControlSlot; 9],
        task: &'a CurrentTask,
        fd_map: [FdMapSlot; FD_MAP_CAPACITY],
        opens: [DelegatedOpenFile; 1],
        retired_count: usize,
        retired_fd_tables: Vec<u64>,
    }

    fn context_words(address: AddressContext<RootGpa>) -> ParkedContextWords {
        ParkedContextWords::from_parts([0; 20], address, 0, 0, [0; X86_XSAVE_BYTES])
    }

    impl<'a> NativeProcessService<'a, ParkedContextWords> for StockReclaimingService<'a> {
        fn vacate_terminal_space(
            &mut self,
            source: carrick_el1_abi::BornInZoneSource<'a, ParkedContextWords>,
        ) -> Result<(), NativeProcessError> {
            let _ = source;
            Ok(())
        }

        type Mm = AddressContext<RootGpa>;
        type PreparedMm = AddressContext<RootGpa>;
        type Born = AddressContext<RootGpa>;
        fn service_mm_handle(
            &self,
            mm: &Self::Mm,
        ) -> Result<carrick_core_abi::El1MmHandle, NativeProcessError> {
            self.zone
                .spaces
                .find(mm.mm.raw().get())
                .ok_or(NativeProcessError::Stale)?;
            // SAFETY: this test venue owns these never-reused synthetic MM roots.
            Ok(unsafe {
                carrick_core_abi::El1MmHandle::from_admitted_owner(
                    NonZeroU64::MIN,
                    carrick_core_abi::ReservationMm::new(mm.mm.raw().get())
                        .ok_or(NativeProcessError::Stale)?,
                    NonZeroU64::MIN,
                )
            })
        }

        fn prepare_mm(
            &mut self,
            parent: &Self::Mm,
            _: &ParkedContextWords,
            child: MmGeneration,
        ) -> Result<Self::PreparedMm, NativeProcessError> {
            assert_ne!(
                child, parent.mm,
                "fork child MM must differ from its live parent"
            );
            let address = AddressContext {
                root: RootGpa::page_aligned(FrameGpa::new(0x2000)).unwrap(),
                mm: child,
                generation: ContextGeneration::new(NonZeroU64::MIN),
            };
            self.zone
                .spaces
                .publish_closed(child.raw().get(), address.root.address().raw(), 0)
                .ok_or(NativeProcessError::Exhausted)?;
            Ok(address)
        }

        fn prepared_mm(&self, p: &Self::PreparedMm) -> Self::Mm {
            *p
        }

        fn prepared_context(&self, p: &Self::PreparedMm) -> AddressContext<RootGpa> {
            *p
        }

        fn child_lifecycle(&self, _: &Self::PreparedMm) -> NativeLifecycleResources<'a> {
            NativeLifecycleResources {
                page: self.child_page,
                controls: self.child_controls,
            }
        }

        fn commit_mm(
            &mut self,
            p: Self::PreparedMm,
        ) -> Result<Self::Born, (NativeProcessError, Self::PreparedMm)> {
            Ok(p)
        }

        fn abort_mm(
            &mut self,
            _: Self::PreparedMm,
        ) -> Result<(), (NativeProcessError, Self::PreparedMm)> {
            Ok(())
        }

        fn settle_mm(&mut self, b: Self::Born) -> Result<(), (NativeProcessError, Self::Born)> {
            self.zone
                .spaces
                .open(self.zone.spaces.find(b.mm.raw().get()).unwrap());
            Ok(())
        }

        fn copy_status(
            &mut self,
            _: &Self::Mm,
            _: UserVa,
            _: LinuxWaitStatus,
        ) -> Result<(), NativeProcessError> {
            Ok(())
        }

        fn quarantine_prepared(&mut self, _: Self::PreparedMm) {
            panic!("unexpected quarantine");
        }

        fn quarantine_fork(
            &mut self,
            _: NativeForkPreparation<'a, Self::Mm, Self::PreparedMm, ParkedContextWords>,
        ) {
            panic!("unexpected fork quarantine");
        }

        fn quarantine_born(&mut self, _: Self::Born) {
            panic!("unexpected quarantine");
        }

        fn retire_mm(&mut self, _: Self::Mm) {
            assert!(
                self.child_controls
                    .iter()
                    .all(|control| !control.graph_referenced()),
                "retiring a fork child MM must not leave control custody alive on its loaned stock"
            );
            for control in self.child_controls {
                control
                    .reset_for_host_birth(carrick_el1_abi::BlockedMask(0))
                    .expect("unreferenced control resets through interior mutability");
            }
            self.retired_count += 1;
        }

        fn wake_effects(&mut self, _: WakeEffects) {}

        fn request_ingress_producer_boundary(&mut self) {}

        fn child_file_table(&self, _parent_table: u64, issued: u64) -> u64 {
            issued
        }

        fn retire_fd_table(&mut self, table: u64) {
            carrick_el1_linux::file_table::retire_fd_map(&self.fd_map, &self.opens, table);
            self.task.linux.mark_pending_host_work();
            self.retired_fd_tables.push(table);
        }
    }

    let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
    let zone = unsafe {
        let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables<ParkedContextWords>>();
        assert!(!ptr.is_null());
        Box::from_raw(ptr)
    };
    let zone = Arc::from(zone);
    // Keep the production root and its claims alive throughout native child
    // retirement. Bootstrap binds the same namespace authority native admission
    // uses; scheduler publication below only projects these issued identities.
    let bootstrap = RootBootstrap::for_prepared_launch(
        41,
        carrick_hal::ThreadId::synthetic_for_tests(41),
        "stock-reclaim".into(),
        Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
            "stock-reclaim",
        )))),
        Arc::new(carrick_hal::NullHostSignalBridge::default()),
    )
    .unwrap()
    .with_birth_source(Arc::new(OwnedBirthZone::new(Arc::clone(&zone))));
    let (_kernel, root) = Kernel::bootstrap_root(bootstrap).unwrap();
    let root_task = root.task().key();
    let root_thread = root.thread().key();
    let generation = carrick_el1_abi::SnapshotGeneration::INITIAL;
    let registry = Box::leak(Box::new(NativeProcessRegistry::<
        AddressContext<RootGpa>,
        ParkedContextWords,
    >::new()));
    let page = Box::new(ThreadLifecyclePage::new());
    let control = Box::new(ThreadControlSlot::new());
    let child_page = Box::new(ThreadLifecyclePage::new());
    let child_controls: Box<[ThreadControlSlot; 9]> =
        Box::new(core::array::from_fn(|_| ThreadControlSlot::new()));
    let task = CurrentTask::new();
    let peer_task = CurrentTask::new();
    task.set(El1TaskId::from_linux_tid(root_task.id.raw()), generation, 5);
    task.mm.key.store(1, Ordering::Release);
    task.mm
        .thread_generation
        .store(root_thread.serial.raw(), Ordering::Release);
    task.publish_visible_pid(root_task.id.raw() as u32);
    task.publish_lifecycle(&*page as *const _ as u64, &*control as *const _ as u64);
    // The host records the leader's birth identity when it allocates the slot.
    control.publish_host_birth_identity(
        carrick_core::terminal::ThreadBirthIdentity::from_parts(
            carrick_core_abi::EntryTaskKey::from_raw(root_task.id.raw() as u64),
            carrick_core_abi::BirthSerial::of_task(root_task.serial),
            carrick_core_abi::EntryThreadGeneration::from_raw(root_thread.serial.raw()),
        )
        .unwrap(),
    );
    let address = AddressContext {
        root: RootGpa::page_aligned(FrameGpa::new(0x1000)).unwrap(),
        mm: MmGeneration::new(NonZeroU64::MIN),
        generation: ContextGeneration::new(NonZeroU64::MIN),
    };
    let slot = SlotId::new(0);
    let peer_slot = SlotId::new(1);
    let space = zone.spaces.publish_closed(1, 0x1000, 0).unwrap();
    zone.spaces.open(space);
    zone.drive(slot, 1);
    zone.publish_slot(slot, 1, Some(0), 1);
    zone.enter_guest(slot);
    zone.install_space(slot, 1).unwrap();
    zone.drive(peer_slot, 2);
    zone.publish_slot(peer_slot, 1, Some(1), 2);
    zone.enter_guest(peer_slot);
    zone.current_or_new(
        slot,
        ThreadIdentity {
            tid: root_task.id.raw() as u64,
            serial: root_thread.serial.raw(),
            mm: 1,
            file_table: 5,
            generation: generation.raw(),
            affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
            affinity: 3,
            lifecycle_page: &*page as *const _ as u64,
            control_slot: &*control as *const _ as u64,
        },
    )
    .unwrap();
    let source = BornInZoneSource { zone: &zone, slot };
    let mut service = StockReclaimingService {
        zone: &zone,
        child_page: &child_page,
        child_controls: &child_controls,
        task: &peer_task,
        fd_map: [const { FdMapSlot::new() }; FD_MAP_CAPACITY],
        opens: [const { DelegatedOpenFile::new() }; 1],
        retired_count: 0,
        retired_fd_tables: Vec::new(),
    };
    zone.mm_issuer().observe_existing(address.mm);
    let runtime = Arc::new(
        NativeProcessRuntime::admit_fresh_root::<X86Mmu>(
            source,
            &task,
            &page,
            &control,
            address,
            address,
            context_words(address),
        )
        .unwrap(),
    );
    registry
        .register_root(runtime.clone(), source, &task, address)
        .unwrap();
    let child_pid = {
        let mut parent_entry = runtime
            .enter_registered(
                registry,
                source,
                &task,
                address,
                &context_words(address),
                &mut service,
            )
            .unwrap();
        let LifecycleOutcome::Returned { result, .. } =
            parent_entry.fork(carrick_personality_linux::lifecycle::ProcessForkChildTid::NONE)
        else {
            panic!("expected fork success");
        };
        result.raw() as u32
    };
    // The unported x86 affinity venue has no published carrier topology.
    // Fork inherits the parent's unpublished control mask, not the fixture's
    // numeric scheduler mask (3). A live alias must not turn that zero into
    // an empty allowed-CPU set and strand the child.
    assert_eq!(zone.carrier_affinity_mask(), None);
    assert_eq!(control.affinity().words(), &[0]);
    let child_control = child_controls
        .iter()
        .find(|control| control.visible_tid() == Some(child_pid))
        .unwrap();
    assert_eq!(child_control.affinity().words(), &[0]);
    assert_eq!(child_control.affinity_source().load(), Some(0));
    assert!(zone.enter_idle(peer_slot, true));
    let mut effects = WakeEffects::default();
    assert_eq!(zone.migrate_queued(slot, &mut effects), 1);
    assert_eq!(effects.sgi_slots().collect::<Vec<_>>(), vec![peer_slot]);
    zone.leave_idle(peer_slot);
    let selected = zone.switch_in_full(peer_slot).unwrap();
    let child_record = zone.record_ref(selected.record);
    let state = unsafe { runtime.record_binding(child_record) }.unwrap();
    let identity = zone.record(selected.record).identity();
    zone.install_space(peer_slot, state.address.mm.raw().get())
        .unwrap();
    peer_task.set(
        El1TaskId::from_linux_tid(i32::try_from(identity.tid).unwrap()),
        carrick_el1_abi::SnapshotGeneration::from_raw(identity.generation),
        identity.file_table,
    );
    peer_task
        .mm
        .key
        .store(state.address.mm.raw().get(), Ordering::Release);
    peer_task
        .mm
        .thread_generation
        .store(identity.serial, Ordering::Release);
    peer_task.publish_visible_pid(child_pid);
    peer_task.publish_lifecycle(identity.lifecycle_page, identity.control_slot);
    // Give the child the last reference to a host-backed open file description
    // in its file table so `retire_fd_table` -> `retire_fd_map` exercises
    // `OpenRelease::Terminal` (`mark_pending_host_work_for_file_tables`) as
    // well as `retire_fd_table`'s `mark_pending_host_work`.
    assert!(service.opens[0].lifetime.initialize(1, false));
    service.opens[0].generation.store(1, Ordering::Release);
    service.fd_map[0].set(identity.file_table, 3, 1, 1);
    let peer_source = BornInZoneSource {
        zone: &zone,
        slot: peer_slot,
    };
    {
        let mut child_entry = runtime
            .enter_registered(
                registry,
                peer_source,
                &peer_task,
                state.address,
                &state.words,
                &mut service,
            )
            .unwrap();
        assert!(matches!(
            child_entry.exit_group(0),
            LifecycleOutcome::Transferred {
                progress: carrick_core::Served::Idle,
                ..
            }
        ));
    }
    assert_eq!(service.retired_count, 1);
    assert_eq!(service.retired_fd_tables, vec![identity.file_table]);
    assert!(
        !service.opens[0].lifetime.retain(1),
        "child exit must release the last reference to its open file description"
    );
    assert!(
        peer_task.linux.has_pending_host_work(),
        "retire_fd_table marks pending_host_work while the exiting child owns CurrentTask"
    );
    assert!(
        !child_controls[0].graph_referenced(),
        "dropping NativeProcessEntry after exit_group must not underflow reclaimed control stock"
    );
    assert!(
        MemberControlCustody::retain(&child_controls[0]).is_ok(),
        "reclaimed control stock must accept a fresh retain after child exit completes"
    );
    // The exiting child still owns the work boundary here. The host must
    // consume its pending wake before the peer can inherit this CPU slot.
    let delivered = peer_task
        .linux
        .take_host_work_doorbell()
        .map(|doorbell| doorbell.settled())
        .is_some();
    assert!(
        delivered,
        "terminal fd release must reach the host work boundary"
    );
    peer_task.set(El1TaskId::from_linux_tid(root_task.id.raw()), generation, 5);
    assert!(!peer_task.linux.has_pending_host_work());
}

// #1901: pathname classification must precede authoritative descriptor lookup.
// Both register decoders drive the real shared dispatcher with a live IPC table.
#[derive(Clone, Copy)]
enum AtEmptyPathCase {
    CwdEmpty,
    CwdDot,
    AbsoluteBadFd,
    Pipe,
    BadFlagsBadFd,
    RelativeBadFd,
    RelativePipe,
    NullPipe,
    NullBadFd,
}

fn at_empty_path_dispatch(x86: bool, case: AtEmptyPathCase) {
    use carrick_abi::{LINUX_AT_EMPTY_PATH, LINUX_AT_FDCWD, LinuxStat, LinuxX8664Stat};
    use carrick_el1_abi::ipc::{IpcBacking, fd, pipe::End};
    use carrick_el1_linux::ipc::{IpcVenue, MapTables};
    use carrick_kernel::el1_ipc::{HostIpc, HostTable};
    use carrick_personality_linux::dispatch::CompletionRoute;
    use carrick_personality_linux::native_host_file::{
        HostFileCall, HostFileStage, InZoneKind, NativeDescriptor, NativeNamespace,
    };
    use carrick_test_support::GuestUserBuffer;
    use std::sync::Arc;

    let owner = Arc::new(HostIpc::new(1 << 20).unwrap());
    let table = HostTable::create(Arc::clone(&owner), 64, 8).unwrap();
    let object = owner.create_pipe(65536).unwrap();
    let reader = owner
        .admit_description(fd::Description::new(
            IpcBacking::Pipe {
                object,
                end: End::Reader,
            }
            .encode(),
            fd::AccessMode::ReadOnly,
            fd::StatusFlags::default(),
        ))
        .unwrap();
    reader.install(table.id(), fd::Fd(3), false).unwrap();
    let region = carrick_test_support::TestEl1Region::zeroed();
    // SAFETY: TestEl1Region provides ABI-aligned zeroed storage for this map.
    let map = unsafe {
        &*region
            .as_ptr()
            .add(carrick_el1_abi::EL1_IPC_TABLE_MAP_OFFSET as usize)
            .cast::<carrick_el1_abi::ipc_tables::IpcTableMap>()
    };
    map.publish_owned(7, table.id().to_raw()).unwrap();
    let tables = MapTables(map);
    let venue = IpcVenue {
        region: owner.region(),
        tables: &tables,
    };
    let task = CurrentTask::new();
    task.set(
        El1TaskId::from_linux_tid(41),
        carrick_el1_abi::SnapshotGeneration::from_raw(1),
        7,
    );
    let counters = Counters::new();
    let names = InotifyNameCache::new();
    let (dirfd, path): (i32, &[u8]) = match case {
        AtEmptyPathCase::CwdEmpty => (LINUX_AT_FDCWD as i32, b"\0"),
        AtEmptyPathCase::CwdDot => (LINUX_AT_FDCWD as i32, b".\0"),
        AtEmptyPathCase::AbsoluteBadFd => (63, b"/\0"),
        AtEmptyPathCase::Pipe => (3, b"\0"),
        AtEmptyPathCase::BadFlagsBadFd => (63, b"\0"),
        AtEmptyPathCase::RelativeBadFd => (63, b".\0"),
        AtEmptyPathCase::RelativePipe => (3, b".\0"),
        AtEmptyPathCase::NullPipe => (3, b"\0"),
        AtEmptyPathCase::NullBadFd => (63, b"\0"),
    };
    let flags = LINUX_AT_EMPTY_PATH
        | if matches!(case, AtEmptyPathCase::BadFlagsBadFd) {
            0x8000_0000
        } else {
            0
        };
    let path = GuestUserBuffer::from_bytes(path);
    let path_arg = if matches!(case, AtEmptyPathCase::NullPipe | AtEmptyPathCase::NullBadFd) {
        0
    } else {
        path.arg()
    };
    let output = GuestUserBuffer::zeroed(if x86 {
        core::mem::size_of::<LinuxX8664Stat>()
    } else {
        core::mem::size_of::<LinuxStat>()
    });
    let args = [dirfd as u64, path_arg, output.arg(), flags, 0, 0];
    let mut arm = TrapFrame {
        esr: 0x15 << 26,
        elr: 0x4004,
        ..Default::default()
    };
    arm.x[8] = carrick_personality_linux::crossing::nr::NEWFSTATAT.raw();
    arm.x[..6].copy_from_slice(&args);
    let isa_unsupported = AtomicU64::new(0);
    let call = decode_x86_64(262, args, 0x7fff_0000);
    let mut amd = X86Frame {
        native: call.native,
        canonical: call.canonical,
        args,
        rax: 0xfeed,
        isa_unsupported: &isa_unsupported,
    };
    let (route, result) = if x86 {
        let route = dispatch::dispatch_syscall_with_native::<
            _,
            NoCpu,
            sched::HardwareUserWord,
            _,
            carrick_el1_abi::Aarch64ParkedContext,
        >(
            &mut amd,
            &counters,
            core::slice::from_ref(&task),
            &[],
            &[],
            &[],
            &[],
            &names,
            None,
            Some(&venue),
            None,
            None,
            None,
            None,
            |_| core::ptr::null_mut(),
        );
        (route, amd.rax as i64)
    } else {
        let route = dispatch::dispatch_syscall_with_native::<
            _,
            NoCpu,
            sched::HardwareUserWord,
            _,
            carrick_el1_abi::Aarch64ParkedContext,
        >(
            &mut arm,
            &counters,
            core::slice::from_ref(&task),
            &[],
            &[],
            &[],
            &[],
            &names,
            None,
            Some(&venue),
            None,
            None,
            None,
            None,
            |_| core::ptr::null_mut(),
        );
        (route, arm.x[0] as i64)
    };
    if matches!(case, AtEmptyPathCase::BadFlagsBadFd) {
        assert_eq!(route, CompletionRoute::Served);
        assert_eq!(result, -22, "invalid flags must precede EBADF(9)");
        assert!(output.as_bytes().iter().all(|byte| *byte == 0));
    } else if matches!(case, AtEmptyPathCase::NullBadFd) {
        assert_eq!(route, CompletionRoute::Served);
        assert_eq!(result, -9, "NULL AT_EMPTY_PATH must select the descriptor");
        assert!(output.as_bytes().iter().all(|byte| *byte == 0));
    } else if matches!(case, AtEmptyPathCase::Pipe | AtEmptyPathCase::NullPipe) {
        assert_eq!(route, CompletionRoute::Served, "pipe query stays in ring");
        assert_eq!(result, 0);
        let mode = if x86 {
            zerocopy::FromBytes::read_from_bytes(output.as_bytes())
                .map(|s: LinuxX8664Stat| s.st_mode)
                .unwrap()
        } else {
            zerocopy::FromBytes::read_from_bytes(output.as_bytes())
                .map(|s: LinuxStat| s.st_mode)
                .unwrap()
        };
        assert_eq!(mode & carrick_abi::LINUX_S_IFMT, carrick_abi::LINUX_S_IFIFO);
    } else {
        assert_eq!(
            route,
            CompletionRoute::Forward,
            "path owner must receive the call; result {result} (EBADF = -9)"
        );
        assert_eq!(result, if x86 { 0xfeed } else { dirfd as i64 });
        assert!(output.as_bytes().iter().all(|byte| *byte == 0));
        if matches!(
            case,
            AtEmptyPathCase::RelativeBadFd | AtEmptyPathCase::RelativePipe
        ) {
            let mut resolved = Vec::new();
            let stage = dispatch::stage_native_host_file(
                HostFileCall::Newfstatat {
                    dirfd,
                    path: path.arg(),
                    statbuf: output.arg(),
                    flags,
                    layout: carrick_personality_linux::native_host_file::StatLayout::Generic,
                },
                &task,
                &carrick_el1_linux::file::HardwareValidator,
                &mut NativeNamespace {
                    table: [1, 2, 3],
                    resolve: &mut |fd| {
                        resolved.push(fd);
                        let descriptor = match owner
                            .region()
                            .fd(fd::BoundedSpin(1024))
                            .get(table.id(), fd::Fd(fd))
                        {
                            Ok(description) => {
                                let Some(IpcBacking::Pipe { object, .. }) =
                                    IpcBacking::decode(description.backing)
                                else {
                                    panic!("fixture descriptor must name a pipe");
                                };
                                NativeDescriptor::InZone(InZoneKind::Pipe(
                                    carrick_abi::LinuxPipeIdentity::new(
                                        object.index(),
                                        object.generation(),
                                    ),
                                ))
                            }
                            Err(fd::Error::BadFd) => NativeDescriptor::Absent,
                            Err(error) => panic!("unexpected descriptor error: {error:?}"),
                        };
                        Some(descriptor)
                    },
                    releases: &mut |_| 0,
                },
            );
            let Some(HostFileStage::Returned(result)) = stage else {
                panic!("relative path must complete with a descriptor error");
            };
            assert_eq!(
                result,
                carrick_personality_linux::abi::entry::SyscallResult::new(
                    if matches!(case, AtEmptyPathCase::RelativeBadFd) {
                        -9
                    } else {
                        -20
                    }
                ),
                "relative path requires EBADF(9) or ENOTDIR(20)"
            );
            assert_eq!(resolved, [dirfd]);
            assert!(output.as_bytes().iter().all(|byte| *byte == 0));
            return;
        }
        // Continue the handoff through the existing shared Newfstatat path
        // owner: cwd and absolute paths must stage a path request without
        // consulting the descriptor namespace at all.
        let Some(HostFileStage::Request {
            mut record,
            resolves_path,
            output: staged_output,
            ..
        }) = dispatch::stage_native_host_file(
            HostFileCall::Newfstatat {
                dirfd,
                path: path.arg(),
                statbuf: output.arg(),
                flags: LINUX_AT_EMPTY_PATH,
                layout: carrick_personality_linux::native_host_file::StatLayout::Generic,
            },
            &task,
            &carrick_el1_linux::file::HardwareValidator,
            &mut NativeNamespace {
                table: [1, 2, 3],
                resolve: &mut |_| panic!("path form must not resolve dirfd"),
                releases: &mut |_| 0,
            },
        )
        else {
            panic!("existing path owner must stage newfstatat");
        };
        assert!(resolves_path);
        assert_eq!(staged_output.unwrap().address, output.arg());
        let view = carrick_core_abi::host_file::HostFileRequestView::parse(&mut record).unwrap();
        assert_eq!(
            view.header().op,
            carrick_core_abi::host_file::HostFileOp::Newfstatat
        );
        assert_eq!(view.header().fd, LINUX_AT_FDCWD as i32);
        assert_eq!(
            view.input(),
            if matches!(case, AtEmptyPathCase::AbsoluteBadFd) {
                b"/"
            } else {
                b"."
            }
        );
    }
}

#[test]
fn at_empty_path_arm_cwd_empty() {
    at_empty_path_dispatch(false, AtEmptyPathCase::CwdEmpty);
}
#[test]
fn at_empty_path_arm_cwd_dot() {
    at_empty_path_dispatch(false, AtEmptyPathCase::CwdDot);
}
#[test]
fn at_empty_path_arm_absolute_bad_fd() {
    at_empty_path_dispatch(false, AtEmptyPathCase::AbsoluteBadFd);
}
#[test]
fn at_empty_path_arm_pipe_control() {
    at_empty_path_dispatch(false, AtEmptyPathCase::Pipe);
}
#[test]
fn at_empty_path_x86_cwd_empty() {
    at_empty_path_dispatch(true, AtEmptyPathCase::CwdEmpty);
}
#[test]
fn at_empty_path_x86_cwd_dot() {
    at_empty_path_dispatch(true, AtEmptyPathCase::CwdDot);
}
#[test]
fn at_empty_path_x86_absolute_bad_fd() {
    at_empty_path_dispatch(true, AtEmptyPathCase::AbsoluteBadFd);
}
#[test]
fn at_empty_path_x86_pipe_control() {
    at_empty_path_dispatch(true, AtEmptyPathCase::Pipe);
}

#[test]
fn at_empty_path_arm_bad_flags_bad_fd() {
    at_empty_path_dispatch(false, AtEmptyPathCase::BadFlagsBadFd);
}
#[test]
fn at_empty_path_x86_bad_flags_bad_fd() {
    at_empty_path_dispatch(true, AtEmptyPathCase::BadFlagsBadFd);
}
#[test]
fn at_empty_path_arm_relative_bad_fd() {
    at_empty_path_dispatch(false, AtEmptyPathCase::RelativeBadFd);
}
#[test]
fn at_empty_path_x86_relative_bad_fd() {
    at_empty_path_dispatch(true, AtEmptyPathCase::RelativeBadFd);
}
#[test]
fn at_empty_path_arm_relative_pipe() {
    at_empty_path_dispatch(false, AtEmptyPathCase::RelativePipe);
}
#[test]
fn at_empty_path_x86_relative_pipe() {
    at_empty_path_dispatch(true, AtEmptyPathCase::RelativePipe);
}

#[test]
fn at_empty_path_arm_null_pipe() {
    at_empty_path_dispatch(false, AtEmptyPathCase::NullPipe);
}
#[test]
fn at_empty_path_x86_null_pipe() {
    at_empty_path_dispatch(true, AtEmptyPathCase::NullPipe);
}
#[test]
fn at_empty_path_arm_null_bad_fd() {
    at_empty_path_dispatch(false, AtEmptyPathCase::NullBadFd);
}
#[test]
fn at_empty_path_x86_null_bad_fd() {
    at_empty_path_dispatch(true, AtEmptyPathCase::NullBadFd);
}

/// Host pointers stand in for resident guest memory, as the unit tests do.
struct ResidentUser;
impl carrick_el1_linux::file::MemoryValidator for ResidentUser {
    fn writable_bytes(&self, _user_va: u64, len: usize) -> usize {
        len
    }
    fn readable_bytes(&self, _user_va: u64, len: usize) -> usize {
        len
    }
}

fn x86_exec_dispatch(native: u64, args: [u64; 6], counters: &Counters) -> (Action, i64, u64) {
    let tasks = [CurrentTask::new()];
    tasks[0].set(
        El1TaskId::from_linux_tid(41),
        carrick_el1_abi::SnapshotGeneration::from_raw(1),
        7,
    );
    let names = InotifyNameCache::new();
    let isa_unsupported = AtomicU64::new(0);
    let call = decode_x86_64(native, args, 0x7fff_0000);
    let mut frame = X86Frame {
        native: call.native,
        canonical: call.canonical,
        args: call.args,
        rax: 0xfeed,
        isa_unsupported: &isa_unsupported,
    };
    let action = dispatch::dispatch_syscall_with_lifecycle(
        &mut frame,
        counters,
        &tasks,
        &[],
        &[],
        &[],
        &[],
        &names,
        None::<dispatch::Zone<'_, NoCpu, sched::HardwareUserWord>>,
        None,
        None,
        None,
        |_| core::ptr::null_mut(),
    );
    (action, frame.rax as i64, call.canonical.raw())
}

// x86 execve (59) and execveat (322) reach the native service route instead
// of the Unported refusal: the production dispatcher no longer answers them,
// the CPL0 completion arm does (staging, or the unclaimed refusal).
#[test]
fn x86_exec_routes_to_the_native_service_not_unported() {
    for (native, args) in [(59, [1, 2, 3, 0, 0, 0]), (322, [4, 1, 2, 3, 0, 0])] {
        let counters = Counters::new();
        let (action, rax, canonical) = x86_exec_dispatch(native, args, &counters);
        assert!(canonical == 221 || canonical == 281);
        assert_eq!(action, Action::Forward, "native {native}");
        assert_eq!(
            rax, 0xfeed,
            "native {native}: the dispatcher must not answer"
        );
        assert_eq!(
            counters.refused[native as usize].load(Ordering::Relaxed),
            0,
            "native {native}: the CPL0 completion arm owns the refusal"
        );
    }
}

// The claim gate is neutral: only a fork child's exec is the native owner's.
#[test]
fn x86_exec_claim_is_a_fork_child_only() {
    use carrick_el1_linux::native_process_runtime::NativeThreadGroupOwner as Owner;
    assert!(dispatch::native_exec_claimed(|| Owner::ForkChild));
    assert!(!dispatch::native_exec_claimed(|| Owner::Root));
    assert!(!dispatch::native_exec_claimed(|| Owner::Unowned));
}

// A claimed x86 child's execve/execveat is staged through the neutral body
// from the decoded x86 registers, then refused with a counted ring ENOSYS.
#[test]
fn x86_child_exec_is_staged_then_counted_enosys() {
    use carrick_el1_linux::exec_stage::ExecStageRequest;
    let path = b"/bin/static\0";
    let arg = b"static\0";
    let env = b"A=B\0";
    let argv: [u64; 2] = [arg.as_ptr() as u64, 0];
    let envp: [u64; 2] = [env.as_ptr() as u64, 0];
    let task = CurrentTask::new();
    for (native, args) in [
        (
            59,
            [
                path.as_ptr() as u64,
                argv.as_ptr() as u64,
                envp.as_ptr() as u64,
                0,
                0,
                0,
            ],
        ),
        (
            322,
            [
                (-100i64) as u64,
                path.as_ptr() as u64,
                argv.as_ptr() as u64,
                envp.as_ptr() as u64,
                0,
                0,
            ],
        ),
    ] {
        let call = decode_x86_64(native, args, 0x7fff_0000);
        let request = ExecStageRequest::from_canonical(call.canonical.raw(), call.args)
            .expect("exec decodes to a stage request");
        let counters = Counters::new();
        let result = dispatch::settle_native_exec_without_successor(
            &task,
            &ResidentUser,
            request,
            call.native,
            &counters,
        );
        assert_eq!(result, -38, "native {native}");
        assert_eq!(
            counters.refused[native as usize].load(Ordering::Relaxed),
            1,
            "native {native}: counted once, on the native ordinal"
        );
        // An unreadable argument vector is EFAULT, never a host exit.
        let bad = ExecStageRequest { argv: 0, ..request };
        struct Refuse;
        impl carrick_el1_linux::file::MemoryValidator for Refuse {
            fn writable_bytes(&self, _: u64, _: usize) -> usize {
                0
            }
            fn readable_bytes(&self, _: u64, _: usize) -> usize {
                0
            }
        }
        let counters = Counters::new();
        let result = dispatch::settle_native_exec_without_successor(
            &task,
            &Refuse,
            bad,
            call.native,
            &counters,
        );
        assert_eq!(result, -14, "native {native}");
        assert_eq!(counters.refused[native as usize].load(Ordering::Relaxed), 0);
    }
}

#[test]
fn x86_clone_child_serves_stdout_stat_write_and_own_redirect() {
    use carrick_abi::{
        LINUX_AT_EMPTY_PATH, LINUX_AT_FDCWD, LINUX_O_CREAT, LINUX_O_TRUNC, LINUX_O_WRONLY,
    };
    use carrick_core_abi::service::ServiceOrigin;
    use carrick_el1_abi::{
        BornInZoneSource, DelegatedOpenFile, FD_MAP_CAPACITY, FdMapSlot, ThreadControlSlot,
        ThreadIdentity, ThreadLifecyclePage,
    };
    use carrick_el1_linux::file_table::admit_stdio;
    use carrick_el1_linux::ipc::{IpcVenue, MapTables};
    use carrick_el1_linux::native_process_runtime::{
        NativeForkPreparation, NativeLifecycleResources, NativeProcessError, NativeProcessRegistry,
        NativeProcessRuntime, NativeProcessService,
    };
    use carrick_guest_arch::{AddressContext, ContextGeneration, FrameGpa, MmGeneration, RootGpa};
    use carrick_hal::birth_serial::test_support::OwnedBirthZone;
    use carrick_kernel::dispatch::SyscallDispatcher;
    use carrick_kernel::el1_ipc::HostIpc;
    use carrick_mmu_core::x86::owner_mmu::X86Mmu;
    use carrick_personality_linux::dispatch::CompletionRoute;
    use carrick_personality_linux::lifecycle::LinuxWaitStatus;
    use carrick_personality_linux::native_host_file::{
        DescriptionAccess, HostFileCall, HostFileStage, LINUX_STATX_BYTES, NativeDescriptor,
        NativeNamespace,
    };
    use carrick_sched_core::{ParkedContextWords, WakeEffects, X86_XSAVE_BYTES, ZoneTables};
    use carrick_test_support::{GuestUserBuffer, TestEl1Region};
    use core::num::NonZeroU64;
    use std::sync::Arc;

    struct Cpl0TestService<'a> {
        zone: &'a ZoneTables<ParkedContextWords>,
        child_page: &'a ThreadLifecyclePage,
        child_controls: &'a [ThreadControlSlot; 9],
        task: &'a CurrentTask,
        owner: Arc<HostIpc>,
        map: &'a carrick_el1_abi::ipc_tables::IpcTableMap,
        fd_map: [FdMapSlot; FD_MAP_CAPACITY],
        opens: [DelegatedOpenFile; 16],
        next_root_page: u64,
        prepare_synchronously: bool,
    }

    fn context_words(address: AddressContext<RootGpa>) -> ParkedContextWords {
        ParkedContextWords::from_parts([0; 20], address, 0, 0, [0; X86_XSAVE_BYTES])
    }

    impl<'a> NativeProcessService<'a, ParkedContextWords> for Cpl0TestService<'a> {
        fn vacate_terminal_space(
            &mut self,
            source: carrick_el1_abi::BornInZoneSource<'a, ParkedContextWords>,
        ) -> Result<(), NativeProcessError> {
            let _ = source;
            Ok(())
        }

        type Mm = AddressContext<RootGpa>;
        type PreparedMm = AddressContext<RootGpa>;
        type Born = AddressContext<RootGpa>;

        fn service_mm_handle(
            &self,
            mm: &Self::Mm,
        ) -> Result<carrick_core_abi::El1MmHandle, NativeProcessError> {
            self.zone
                .spaces
                .find(mm.mm.raw().get())
                .ok_or(NativeProcessError::Stale)?;
            Ok(unsafe {
                carrick_core_abi::El1MmHandle::from_admitted_owner(
                    NonZeroU64::MIN,
                    carrick_core_abi::ReservationMm::new(mm.mm.raw().get())
                        .ok_or(NativeProcessError::Stale)?,
                    NonZeroU64::MIN,
                )
            })
        }

        fn prepare_owned_read(
            &mut self,
            _: &Self::Mm,
            request: carrick_core::user_copy::GuestCopyRequest,
        ) -> Result<(), NativeProcessError> {
            // Deliberately unreadable timeout and atomic-word inputs must
            // reach their exact-MM owner.
            assert!(matches!(
                (request.address.raw(), request.len.raw()),
                (1, 16) | (0x2000, 4)
            ));
            assert_eq!(request.access, carrick_guest_arch::Access::Read);
            if self.prepare_synchronously {
                Ok(())
            } else {
                Err(NativeProcessError::Fault)
            }
        }

        fn prepare_mm(
            &mut self,
            parent: &Self::Mm,
            _: &ParkedContextWords,
            child: MmGeneration,
        ) -> Result<Self::PreparedMm, NativeProcessError> {
            assert_ne!(child, parent.mm);
            let gpa = self.next_root_page;
            self.next_root_page += 0x1000;
            let address = AddressContext {
                root: RootGpa::page_aligned(FrameGpa::new(gpa)).unwrap(),
                mm: child,
                generation: ContextGeneration::new(NonZeroU64::MIN),
            };
            self.zone
                .spaces
                .publish_closed(child.raw().get(), address.root.address().raw(), 0)
                .ok_or(NativeProcessError::Exhausted)?;
            Ok(address)
        }

        fn prepared_mm(&self, p: &Self::PreparedMm) -> Self::Mm {
            *p
        }

        fn prepared_context(&self, p: &Self::PreparedMm) -> AddressContext<RootGpa> {
            *p
        }

        fn child_lifecycle(&self, _: &Self::PreparedMm) -> NativeLifecycleResources<'a> {
            NativeLifecycleResources {
                page: self.child_page,
                controls: self.child_controls,
            }
        }

        fn commit_mm(
            &mut self,
            p: Self::PreparedMm,
        ) -> Result<Self::Born, (NativeProcessError, Self::PreparedMm)> {
            Ok(p)
        }

        fn abort_mm(
            &mut self,
            _: Self::PreparedMm,
        ) -> Result<(), (NativeProcessError, Self::PreparedMm)> {
            Ok(())
        }

        fn settle_mm(&mut self, b: Self::Born) -> Result<(), (NativeProcessError, Self::Born)> {
            self.zone
                .spaces
                .open(self.zone.spaces.find(b.mm.raw().get()).unwrap());
            Ok(())
        }

        fn copy_status(
            &mut self,
            _: &Self::Mm,
            _: UserVa,
            _: LinuxWaitStatus,
        ) -> Result<(), NativeProcessError> {
            Ok(())
        }

        fn quarantine_prepared(&mut self, _: Self::PreparedMm) {
            panic!("unexpected quarantine");
        }

        fn quarantine_fork(
            &mut self,
            _: NativeForkPreparation<'a, Self::Mm, Self::PreparedMm, ParkedContextWords>,
        ) {
            panic!("unexpected fork quarantine");
        }

        fn quarantine_born(&mut self, _: Self::Born) {
            panic!("unexpected quarantine");
        }

        fn retire_mm(&mut self, _: Self::Mm) {}
        fn wake_effects(&mut self, _: WakeEffects) {}
        fn request_ingress_producer_boundary(&mut self) {}

        fn child_file_table(&self, _parent_table: u64, issued: u64) -> u64 {
            issued
        }

        fn fork_fd_table(
            &mut self,
            parent_table: u64,
            child_table: u64,
        ) -> Result<(), NativeProcessError> {
            carrick_el1_linux::file_table::fork_native_namespace(
                &self.fd_map,
                &self.opens,
                Some((self.owner.region(), self.map)),
                parent_table,
                child_table,
            )
        }

        fn retire_fd_table(&mut self, table: u64) {
            carrick_el1_linux::file_table::retire_native_namespace(
                &self.fd_map,
                &self.opens,
                Some((self.owner.region(), self.map)),
                table,
                self.task,
            )
            .unwrap();
        }
    }

    struct Cpl0Frame<'a> {
        pc: u64,
        call: carrick_personality_linux::entry::CanonicalCall,
        rax: u64,
        slot: SlotId,
        file_table: u64,
        fd_map: &'a [FdMapSlot],
        opens: &'a [DelegatedOpenFile],
        task: &'a CurrentTask,
        venue: &'a IpcVenue<'a>,
        origin: ServiceOrigin,
        staged: Option<HostFileStage>,
    }

    impl SyscallFrame for Cpl0Frame<'_> {
        fn canonical_ordinal(&self) -> CanonicalNr {
            self.call.canonical
        }
        fn argument(&self, index: usize) -> Option<u64> {
            self.call.args.get(index).copied()
        }
        fn result(&self) -> NativeReturnWord {
            NativeReturnWord(self.rax)
        }
        fn set_result(&mut self, result: NativeReturnWord) {
            self.rax = result.0;
        }
        fn slot(&self) -> Option<SlotId> {
            Some(self.slot)
        }
        fn user_sp(&self) -> Option<UserVa> {
            Some(self.call.stack)
        }
    }

    impl dispatch::GuestDispatchFrame for Cpl0Frame<'_> {
        fn restart_syscall(&mut self) {
            self.pc -= 2;
        }
        fn native_number(&self) -> carrick_guest_arch::NativeOrdinal {
            self.call.native
        }
        fn crossing_set(&self) -> carrick_personality_linux::crossing::HostCrossingSet {
            carrick_personality_linux::crossing::HostCrossingSet::X86
        }
        fn settles_owed_work_at_continuation_boundary(&self) -> bool {
            true
        }
        fn may_serve_descriptor(&self) -> bool {
            [
                carrick_personality_linux::crossing::nr::CLOSE,
                carrick_personality_linux::crossing::nr::DUP,
                carrick_personality_linux::crossing::nr::DUP3,
            ]
            .contains(&CanonicalNr(self.call.canonical.raw()))
                || self.call.canonical.raw() == carrick_syscall_abi::CARRICK_PRIVATE_X86_DUP2
        }
        fn preflight_host_crossing(
            &mut self,
            ordinal: u64,
        ) -> carrick_personality_linux::dispatch::HostCrossingPreflight {
            // The production CPL0 venue's resolver, over this frame's tables.
            let (venue, task) = (self.venue, self.task);
            carrick_el1_linux::crossing_operand::resolve_crossing_operand(
                carrick_personality_linux::crossing::HostCrossingSet::X86,
                CanonicalNr::new(ordinal),
                &self.call.args,
                |fd| {
                    carrick_el1_linux::crossing_operand::classify_fd_operand(
                        self.fd_map,
                        self.opens,
                        self.file_table,
                        fd,
                        |fd| {
                            let table = carrick_el1_linux::ipc::native_table(venue, task)?;
                            carrick_el1_linux::ipc::native_descriptor(venue, table, fd)
                        },
                    )
                },
                |_| None,
            )
            .preflight()
        }
        fn stage_native_host_file(&mut self) -> bool {
            let Some(decoded) =
                HostFileCall::decode(CanonicalNr::new(self.call.canonical.raw()), &self.call.args)
            else {
                return false;
            };
            let admitted = if decoded.uses_child_mutation_venue()
                || matches!(
                    decoded,
                    HostFileCall::Write { .. } | HostFileCall::Writev { .. }
                ) {
                self.origin != ServiceOrigin::Initial
            } else {
                matches!(
                    decoded,
                    HostFileCall::Openat { .. }
                        | HostFileCall::Faccessat { .. }
                        | HostFileCall::Statx { .. }
                )
            };
            if !admitted {
                return false;
            }
            let Some(table) = carrick_el1_linux::ipc::native_table(self.venue, self.task) else {
                return false;
            };
            let venue = self.venue;
            let mut resolve = |fd| carrick_el1_linux::ipc::native_descriptor(venue, table, fd);
            let mut releases = |_: &mut [carrick_core_abi::host_file::MapSourceReply]| 0;
            self.staged = Some(
                dispatch::stage_native_host_file(
                    decoded,
                    self.task,
                    &carrick_el1_linux::file::HardwareValidator,
                    &mut NativeNamespace {
                        table,
                        resolve: &mut resolve,
                        releases: &mut releases,
                    },
                )
                .unwrap_or(HostFileStage::InRing),
            );
            true
        }
        fn release_host_object(
            &mut self,
            _binding: carrick_el1_abi::HostObjectBinding,
            _handle: u32,
            _incarnation: u64,
        ) -> bool {
            true
        }
        fn operation_resume_pc(
            &self,
        ) -> Option<carrick_el1::substrate::sched::object_wait::OperationResumePc> {
            carrick_el1::substrate::sched::object_wait::OperationResumePc::from_raw(0x4000)
        }
        fn arm_frame(&mut self) -> Option<&mut TrapFrame> {
            None
        }
        fn arm_frame_ref(&self) -> Option<&TrapFrame> {
            None
        }
        fn arm_scheduler(&self) -> bool {
            false
        }
        fn robust_publications(&self) -> Option<&core::sync::atomic::AtomicU64> {
            None
        }
    }

    let layout = std::alloc::Layout::new::<ZoneTables<ParkedContextWords>>();
    let zone = unsafe {
        let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables<ParkedContextWords>>();
        assert!(!ptr.is_null());
        Box::from_raw(ptr)
    };
    // The fixture leaks its long-lived state so the plain `call_x86` helper
    // below can take a `Cpl0TestService<'static>` without macros.
    let zone_owner: &'static Arc<ZoneTables<ParkedContextWords>> =
        Box::leak(Box::new(Arc::from(zone)));
    let zone: &'static ZoneTables<ParkedContextWords> = zone_owner;
    let dispatcher = SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().unwrap();
    context
        .kernel()
        .bind_initial_birth_source(Arc::new(OwnedBirthZone::new(Arc::clone(zone_owner))))
        .unwrap();
    let owner: &'static _ = Box::leak(Box::new(context.kernel().ipc().unwrap()));
    let files = context.resources().files();
    let root_table_key = files.id().raw();

    let region: &'static _ = Box::leak(Box::new(TestEl1Region::zeroed()));
    let map = unsafe {
        &*region
            .as_ptr()
            .add(carrick_el1_abi::EL1_IPC_TABLE_MAP_OFFSET as usize)
            .cast::<carrick_el1_abi::ipc_tables::IpcTableMap>()
    };
    files.publish_ipc(Arc::clone(owner), map).unwrap();
    let tables: &'static _ = Box::leak(Box::new(MapTables(map)));
    let venue = IpcVenue {
        region: owner.region(),
        tables,
    };

    let root_task = context.task().key();
    let root_thread = context.thread().key();
    let generation = carrick_el1_abi::SnapshotGeneration::INITIAL;
    let registry = Box::leak(Box::new(NativeProcessRegistry::<
        AddressContext<RootGpa>,
        ParkedContextWords,
    >::new()));
    #[cfg(target_os = "linux")]
    let (page, child_page, control, child_controls) = {
        // CurrentTask authenticates lifecycle pointers in the metadata window.
        // Keep these ABI records in a TestEl1Region mapped at that production
        // address, rather than unrelated heap addresses that cannot be imported.
        let metadata_len = core::mem::size_of::<TestEl1Region>();
        let metadata_base = carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE as *mut libc::c_void;
        // SAFETY: request anonymous writable storage without replacing an existing
        // mapping; the returned address is checked before constructing any view.
        let mapped = unsafe {
            libc::mmap(
                metadata_base,
                metadata_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        assert_eq!(mapped, metadata_base);
        // SAFETY: the zeroed mapping is aligned and remains owned until this test
        // process exits. No other test maps this fixture's metadata window.
        let metadata = unsafe { &mut *mapped.cast::<TestEl1Region>() };
        let page_bytes = core::mem::size_of::<ThreadLifecyclePage>().div_ceil(16384) * 16384;
        let controls_offset = page_bytes * 2;
        assert!(
            controls_offset + core::mem::size_of::<ThreadControlSlot>() * 10
                <= metadata_len.min(carrick_el1_abi::EL1_DYNAMIC_METADATA_SIZE as usize)
        );
        // SAFETY: these aligned, disjoint ABI ranges fit inside the mapped region.
        // Each is initialized before reference publication and lives until exit.
        unsafe {
            let base = metadata.as_mut_ptr();
            let page = base.cast::<ThreadLifecyclePage>();
            let child = base.add(page_bytes).cast::<ThreadLifecyclePage>();
            let control = base.add(controls_offset).cast::<ThreadControlSlot>();
            let children = control.add(1).cast::<[ThreadControlSlot; 9]>();
            page.write(ThreadLifecyclePage::new());
            child.write(ThreadLifecyclePage::new());
            control.write(ThreadControlSlot::new());
            children.write(core::array::from_fn(|_| ThreadControlSlot::new()));
            (&*page, &*child, &*control, &*children)
        }
    };
    #[cfg(not(target_os = "linux"))]
    let (page, child_page, control, child_controls) = {
        let page: &'static ThreadLifecyclePage = Box::leak(Box::new(ThreadLifecyclePage::new()));
        let control: &'static ThreadControlSlot = Box::leak(Box::new(ThreadControlSlot::new()));
        let child_page: &'static ThreadLifecyclePage =
            Box::leak(Box::new(ThreadLifecyclePage::new()));
        let child_controls: &'static [ThreadControlSlot; 9] =
            Box::leak(Box::new(core::array::from_fn(|_| ThreadControlSlot::new())));
        (page, child_page, control, child_controls)
    };
    let tasks: &'static [CurrentTask; 2] =
        Box::leak(Box::new([CurrentTask::new(), CurrentTask::new()]));
    let [task, peer_task] = tasks;
    task.set(
        El1TaskId::from_linux_tid(root_task.id.raw()),
        generation,
        root_table_key,
    );
    task.mm.key.store(1, Ordering::Release);
    task.mm
        .thread_generation
        .store(root_thread.serial.raw(), Ordering::Release);
    task.publish_visible_pid(root_task.id.raw() as u32);
    task.publish_lifecycle(page as *const _ as u64, control as *const _ as u64);
    control.publish_host_birth_identity(
        carrick_core::terminal::ThreadBirthIdentity::from_parts(
            carrick_core_abi::EntryTaskKey::from_raw(root_task.id.raw() as u64),
            carrick_core_abi::BirthSerial::of_task(root_task.serial),
            carrick_core_abi::EntryThreadGeneration::from_raw(root_thread.serial.raw()),
        )
        .unwrap(),
    );
    let address = AddressContext {
        root: RootGpa::page_aligned(FrameGpa::new(0x1000)).unwrap(),
        mm: MmGeneration::new(NonZeroU64::MIN),
        generation: ContextGeneration::new(NonZeroU64::MIN),
    };
    let slot = SlotId::new(0);
    let peer_slot = SlotId::new(1);
    let space = zone.spaces.publish_closed(1, 0x1000, 0).unwrap();
    zone.spaces.open(space);
    zone.drive(slot, 1);
    zone.publish_slot(slot, 1, Some(0), 1);
    zone.enter_guest(slot);
    zone.install_space(slot, 1).unwrap();
    zone.drive(peer_slot, 2);
    zone.publish_slot(peer_slot, 1, Some(1), 2);
    zone.enter_guest(peer_slot);
    zone.current_or_new(
        slot,
        ThreadIdentity {
            tid: root_task.id.raw() as u64,
            serial: root_thread.serial.raw(),
            mm: 1,
            file_table: root_table_key,
            generation: generation.raw(),
            affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
            affinity: 3,
            lifecycle_page: page as *const _ as u64,
            control_slot: control as *const _ as u64,
        },
    )
    .unwrap();
    let source = BornInZoneSource { zone, slot };
    let mut service = Box::new(Cpl0TestService {
        zone,
        child_page,
        child_controls,
        task: peer_task,
        owner: Arc::clone(owner),
        map,
        fd_map: [const { FdMapSlot::new() }; FD_MAP_CAPACITY],
        opens: [const { DelegatedOpenFile::new() }; 16],
        next_root_page: 0x2000,
        prepare_synchronously: false,
    });
    admit_stdio(
        &service.fd_map,
        &service.opens,
        &[],
        root_table_key,
        [true; 3],
    );
    zone.mm_issuer().observe_existing(address.mm);

    let counters = Counters::new();
    let names = InotifyNameCache::new();
    let host_root_resources =
        carrick_kernel::dispatch::resources::HostRootResources::capture(&context);

    let settle_staged = |staged: Option<HostFileStage>, origin: ServiceOrigin| -> i64 {
        match staged {
            Some(HostFileStage::Request {
                record,
                output,
                resolves_path,
                ..
            }) => {
                let mut record = record.into_vec();
                let served = if origin == ServiceOrigin::Initial {
                    dispatcher.serve_host_root_file(&host_root_resources, &mut record)
                } else {
                    if resolves_path {
                        let mut access = Vec::new();
                        carrick_core_abi::host_file::AccessContext::encode_into(
                            &mut access,
                            carrick_core_abi::host_file::AccessIds::default(),
                            0o022,
                            None,
                            b"/",
                            None,
                        )
                        .unwrap();
                        record = carrick_personality_linux::native_host_file::stamp_access_context(
                            &record, &access,
                        )
                        .unwrap()
                        .into_vec();
                    }
                    carrick_personality_linux::native_host_file::stamp_write_file_size_limit::<()>(
                        &mut record,
                        || Ok(u64::MAX),
                    )
                    .unwrap();
                    dispatcher.serve_native_host_file(&mut record, None)
                };
                match served {
                    Ok(_) => {
                        let parsed = carrick_core_abi::host_file::reply(&record)
                            .expect("served host-file record must contain a valid reply");
                        if let Some(out) = output
                            && !parsed.output.is_empty()
                        {
                            let dst = unsafe {
                                core::slice::from_raw_parts_mut(
                                    out.address as *mut u8,
                                    parsed.output.len(),
                                )
                            };
                            dst.copy_from_slice(parsed.output);
                        }
                        parsed.result
                    }
                    Err(_) => carrick_syscall_abi::LINUX_ENOSYS.guest_retval(),
                }
            }
            Some(HostFileStage::Returned(res)) => res.raw(),
            other => panic!("expected staged host-file request, got {other:?}"),
        }
    };

    /// One task's position at the production x86 dispatch entry.
    struct X86Caller<'c> {
        slot: SlotId,
        file_table: u64,
        task: &'static CurrentTask,
        source: BornInZoneSource<'static, ParkedContextWords>,
        origin: ServiceOrigin,
        /// `None` before native process registration (`process = None`).
        registered: Option<X86Registration<'c>>,
    }

    #[derive(Clone, Copy)]
    struct X86Registration<'c> {
        runtime: &'c NativeProcessRuntime<'static, AddressContext<RootGpa>, ParkedContextWords>,
        registry: &'c NativeProcessRegistry<'static, AddressContext<RootGpa>, ParkedContextWords>,
        address: AddressContext<RootGpa>,
        words: &'c ParkedContextWords,
    }

    // Observe the real dispatcher's copy adapter without replacing the native
    // process implementation or its admission/completion path.
    struct ObserveFutex<'p, 'c> {
        inner: &'p mut dyn carrick_el1_linux::lifecycle::ProcessNative<'static, ParkedContextWords>,
        loads: &'c core::cell::Cell<usize>,
    }
    impl carrick_el1_linux::lifecycle::ProcessNative<'static, ParkedContextWords>
        for ObserveFutex<'_, '_>
    {
        fn binding(&self) -> carrick_core_abi::ExecutionBinding {
            self.inner.binding()
        }
        fn is_root_process(&self) -> bool {
            self.inner.is_root_process()
        }
        fn wait_guest_copy(
            &mut self,
            _: carrick_core::user_copy::GuestCopyRequest,
        ) -> carrick_personality_linux::lifecycle::LifecycleOutcome {
            panic!("unexpected copy wait")
        }
        fn fork(
            &mut self,
            _: carrick_personality_linux::lifecycle::ProcessForkChildTid,
        ) -> carrick_personality_linux::lifecycle::LifecycleOutcome {
            panic!("futex observer only")
        }
        fn wait4(
            &mut self,
            _: carrick_personality_linux::lifecycle::ProcessWaitPid,
            _: UserVa,
            _: carrick_personality_linux::lifecycle::LinuxWaitOptions,
            _: UserVa,
        ) -> carrick_personality_linux::lifecycle::LifecycleOutcome {
            panic!("futex observer only")
        }
        fn exit_group(&mut self, _: u8) -> carrick_personality_linux::lifecycle::LifecycleOutcome {
            panic!("futex observer only")
        }
        fn native_futex(
            &mut self,
            call: carrick_personality_linux::sched::FutexCall,
            copy: &mut dyn carrick_core::user_copy::UserCopy,
        ) -> Option<carrick_personality_linux::lifecycle::LifecycleOutcome> {
            struct CountCopy<'a, 'b> {
                inner: &'a mut dyn carrick_core::user_copy::UserCopy,
                loads: &'b core::cell::Cell<usize>,
            }
            impl carrick_core::user_copy::UserCopy for CountCopy<'_, '_> {
                fn copy_in(
                    &mut self,
                    dst: &mut [u8],
                    src: UserVa,
                ) -> carrick_core::user_copy::CopyOutcome {
                    self.loads.set(self.loads.get() + 1);
                    self.inner.copy_in(dst, src)
                }
                fn copy_out(
                    &mut self,
                    _: UserVa,
                    _: &[u8],
                ) -> carrick_core::user_copy::CopyOutcome {
                    panic!("futex wait cannot write user memory")
                }
                fn atomic_load_u32(
                    &mut self,
                    address: UserVa,
                    value: &mut u32,
                ) -> carrick_core::user_copy::CopyOutcome {
                    self.loads.set(self.loads.get() + 1);
                    if address.raw() == 0x2000 {
                        return carrick_core::user_copy::CopyOutcome::NotYet(
                            carrick_core::user_copy::GuestCopyRequest {
                                address,
                                len: carrick_guest_arch::GuestLen::new(4),
                                access: carrick_guest_arch::Access::Read,
                            },
                        );
                    }
                    self.inner.atomic_load_u32(address, value)
                }
            }
            self.inner.native_futex(
                call,
                &mut CountCopy {
                    inner: copy,
                    loads: self.loads,
                },
            )
        }
    }

    struct X86Env<'e> {
        loads: &'e core::cell::Cell<usize>,
        counters: &'e Counters,
        tasks: &'e [CurrentTask],
        names: &'e InotifyNameCache,
        venue: &'e IpcVenue<'static>,
        settle: &'e dyn Fn(Option<HostFileStage>, ServiceOrigin) -> i64,
    }

    fn call_x86(
        env: &X86Env<'_>,
        caller: &X86Caller<'_>,
        service: &mut Cpl0TestService<'static>,
        native_nr: u64,
        args: [u64; 6],
    ) -> (CompletionRoute, i64) {
        let synchronous = service.prepare_synchronously;
        let fd_map_ptr = &service.fd_map[..] as *const [FdMapSlot];
        let opens_ptr = &service.opens[..] as *const [DelegatedOpenFile];
        let mut entry = caller.registered.map(move |r| {
            r.runtime
                .enter_registered(
                    r.registry,
                    caller.source,
                    caller.task,
                    r.address,
                    r.words,
                    service,
                )
                .unwrap()
        });
        // SAFETY: fd_map and opens live inside the caller's heap-pinned
        // `service`, which outlives this call and is not reallocated.
        let (fd_map, opens) = unsafe { (&*fd_map_ptr, &*opens_ptr) };
        let mut frame = Cpl0Frame {
            pc: 0x4002,
            call: decode_x86_64(native_nr, args, 0x7fff_0000),
            rax: native_nr,
            slot: caller.slot,
            file_table: caller.file_table,
            fd_map,
            opens,
            task: caller.task,
            venue: env.venue,
            origin: caller.origin,
            staged: None,
        };
        let mut observer;
        let process: Option<
            &mut dyn carrick_el1_linux::lifecycle::ProcessNative<'static, ParkedContextWords>,
        > = match &mut entry {
            Some(entry) if native_nr == 202 => {
                observer = ObserveFutex {
                    inner: &mut **entry,
                    loads: env.loads,
                };
                Some(&mut observer)
            }
            Some(entry) => Some(&mut **entry),
            None => None,
        };
        let route = dispatch::dispatch_syscall_with_native(
            &mut frame,
            env.counters,
            env.tasks,
            fd_map,
            &[],
            opens,
            &[],
            env.names,
            None::<dispatch::Zone<'_, NoCpu, sched::HardwareUserWord>>,
            Some(env.venue),
            None,
            process,
            Some(caller.source),
            None,
            |_| core::ptr::null_mut(),
        );
        if native_nr == 202 && synchronous {
            assert_eq!(
                route,
                CompletionRoute::Served,
                "native preparation must be admitted"
            );
            assert_eq!(
                frame.pc, 0x4000,
                "synchronous futex preparation must re-execute syscall"
            );
            assert_eq!(frame.rax, 202);
            assert_eq!(frame.call.args, args);
        }
        let staged = frame.staged.take();
        let rax = frame.rax as i64;
        drop(entry);
        if route == CompletionRoute::Forward && staged.is_some() {
            (route, (env.settle)(staged, caller.origin))
        } else {
            (route, rax)
        }
    }

    let loads = core::cell::Cell::new(0);
    let env = X86Env {
        loads: &loads,
        counters: &counters,
        tasks,
        names: &names,
        venue: &venue,
        settle: &settle_staged,
    };

    // Pre-clone root runs with a published host binding (`table_of(task)`) before
    // native process registration (`process = None`); its host-opened files
    // keep the host FileTable as their owner.
    let pre_clone_root = X86Caller {
        slot,
        file_table: root_table_key,
        task,
        source,
        origin: ServiceOrigin::Initial,
        registered: None,
    };

    // 1. Root opens /dev/null through the host -> fd 3, projected into fd-core.
    let out_path = GuestUserBuffer::from_bytes(b"/dev/null\0");
    let (open_route, opened_fd) = call_x86(
        &env,
        &pre_clone_root,
        &mut service,
        257,
        [
            LINUX_AT_FDCWD,
            out_path.arg(),
            LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_TRUNC,
            0o600,
            0,
            0,
        ],
    );
    assert_eq!(open_route, CompletionRoute::Forward);
    assert_eq!(opened_fd, 3);

    // 2. x86 root stdio redirection is not expressible here yet: x86 routes
    // no fcntl (no host crossing, no ring server; -ENOSYS on main), and this
    // harness's legacy root dup of implicit stdio returns -EBADF on main. The
    // ARM witness `arm_root_shell_redirect_then_clone_serves_child_stdout_*`
    // covers the root redirect; this test covers the x86 child side.

    // 3. Admit root and clone child through production x86 dispatch.
    let runtime = Arc::new(
        NativeProcessRuntime::admit_fresh_root::<X86Mmu>(
            source,
            task,
            page,
            control,
            address,
            address,
            context_words(address),
        )
        .unwrap(),
    );
    registry
        .register_root(runtime.clone(), source, task, address)
        .unwrap();

    let root_words = context_words(address);
    let root = X86Caller {
        registered: Some(X86Registration {
            runtime: &runtime,
            registry,
            address,
            words: &root_words,
        }),
        ..pre_clone_root
    };

    let (clone_route, child_pid) = call_x86(&env, &root, &mut service, 56, [17, 0, 0, 0, 0, 0]);
    assert_eq!(clone_route, CompletionRoute::Served);
    assert!(child_pid > 0, "x86 clone failed with {child_pid}");
    if let Some(doorbell) = task.linux.take_host_work_doorbell() {
        doorbell.settled();
    }
    let _ = task.linux.take_served_boundary();

    assert!(zone.enter_idle(peer_slot, true));
    let mut effects = WakeEffects::default();
    assert_eq!(zone.migrate_queued(slot, &mut effects), 1);
    zone.leave_idle(peer_slot);
    let selected = zone.switch_in_full(peer_slot).unwrap();
    let child_record = zone.record_ref(selected.record);
    let state = unsafe { runtime.record_binding(child_record) }.unwrap();
    let identity = zone.record(selected.record).identity();
    zone.install_space(peer_slot, state.address.mm.raw().get())
        .unwrap();
    peer_task.set(
        El1TaskId::from_linux_tid(i32::try_from(identity.tid).unwrap()),
        carrick_el1_abi::SnapshotGeneration::from_raw(identity.generation),
        identity.file_table,
    );
    peer_task
        .mm
        .key
        .store(state.address.mm.raw().get(), Ordering::Release);
    peer_task
        .mm
        .thread_generation
        .store(identity.serial, Ordering::Release);
    peer_task.publish_visible_pid(child_pid as u32);
    peer_task.publish_lifecycle(identity.lifecycle_page, identity.control_slot);

    let child_table = carrick_el1_linux::ipc::native_table(&venue, peer_task).unwrap();
    assert_eq!(
        carrick_el1_linux::ipc::native_descriptor(&venue, child_table, 1),
        Some(NativeDescriptor::HostBacked {
            access: DescriptionAccess::ReadWrite,
        }),
    );
    assert_eq!(
        carrick_el1_linux::ipc::native_descriptor(&venue, child_table, 10),
        Some(NativeDescriptor::Absent),
    );

    let peer_source = BornInZoneSource {
        zone,
        slot: peer_slot,
    };
    let child = X86Caller {
        slot: peer_slot,
        file_table: identity.file_table,
        task: peer_task,
        source: peer_source,
        origin: ServiceOrigin::Descendant,
        registered: Some(X86Registration {
            runtime: &runtime,
            registry,
            address: state.address,
            words: &state.words,
        }),
    };

    for offset in [1, 2, 3] {
        for mask in [0, 0xffff_ffff] {
            let (route, result) = call_x86(
                &env,
                &child,
                &mut service,
                202,
                [0x1000 + offset, 393, 1, 0, 0, mask],
            );
            assert_eq!(
                route,
                CompletionRoute::Served,
                "offset={offset} mask={mask}"
            );
            assert_eq!(
                result, -22,
                "op 393 must return errno 22, not errno 38; offset={offset} mask={mask}"
            );
            assert_eq!(
                loads.get(),
                0,
                "invalid operands require zero user-memory loads"
            );
        }
    }
    let mut diagnostic = String::new();
    counters.write_futex_errors(&mut diagnostic).unwrap();
    let samples: Vec<_> = diagnostic
        .lines()
        .filter(|line| line.contains("futex-error sample="))
        .collect();
    assert_eq!(samples.len(), 6, "{diagnostic}");
    for sample in samples {
        assert!(sample.contains("op=393"), "{sample}");
        assert!(sample.contains("result=-22 errno=22"), "{sample}");
    }

    // Same NotYet-to-owner-fault shape as ARM: the native futex owner
    // settles preparation, and production completion must publish -EFAULT.
    let before_loads = loads.get();
    let (route, result) = call_x86(&env, &child, &mut service, 202, [0x2000, 128, 1, 0, 0, 0]);
    assert_eq!(route, CompletionRoute::Served);
    assert_eq!(result, -14, "copy fault must replace the syscall register");
    assert_eq!(loads.get(), before_loads + 1);

    let mut diagnostic = String::new();
    counters.write_futex_errors(&mut diagnostic).unwrap();
    assert!(
        diagnostic
            .lines()
            .any(|line| line.contains("address=0x2000") && line.contains("result=-14 errno=14")),
        "{diagnostic}"
    );

    // The native owner supplies the missing atomic word synchronously. Return
    // through the production dispatcher must replay, preserving every operand.
    service.prepare_synchronously = true;
    let (route, _) = call_x86(&env, &child, &mut service, 202, [0x2000, 128, 1, 0, 0, 0]);
    assert_eq!(route, CompletionRoute::Served);
    service.prepare_synchronously = false;

    // Child stats fd 1 (statx AT_EMPTY_PATH) and writes fd 1.
    let empty = GuestUserBuffer::from_bytes(b"\0");
    let statx_buf = GuestUserBuffer::zeroed(LINUX_STATX_BYTES);
    let (stat_route, stat_ret) = call_x86(
        &env,
        &child,
        &mut service,
        332,
        [
            1,
            empty.arg(),
            LINUX_AT_EMPTY_PATH,
            0x7ff,
            statx_buf.arg(),
            0,
        ],
    );
    assert_eq!(stat_route, CompletionRoute::Forward);
    assert_eq!(
        stat_ret, 0,
        "x86 child statx(1, AT_EMPTY_PATH) returned {stat_ret} (ENOSYS = -38)"
    );

    let msg = GuestUserBuffer::from_bytes(b"child-ok\n");
    let (write_route, write_ret) =
        call_x86(&env, &child, &mut service, 1, [1, msg.arg(), 9, 0, 0, 0]);
    assert_eq!(write_route, CompletionRoute::Forward);
    assert_eq!(
        write_ret, 9,
        "x86 child write(1) returned {write_ret} (ENOSYS = -38)"
    );
    assert_eq!(dispatcher.stdout(), b"child-ok\n");

    // Child redirects its own fd 1 to fd 3 (ring-opened NativeOpenFile with no
    // fd_map entry) and writes: stage_native_host_file must run ahead of
    // preflight_host_crossing so fd 1 is not rejected with -EBADF.
    let (child_dup3_route, child_dup3_ret) =
        call_x86(&env, &child, &mut service, 292, [3, 1, 0, 0, 0, 0]);
    assert_eq!(
        (child_dup3_route, child_dup3_ret),
        (CompletionRoute::Served, 1)
    );
    let file_msg = GuestUserBuffer::from_bytes(b"redir-ok\n");
    let (file_write_route, file_write_ret) = call_x86(
        &env,
        &child,
        &mut service,
        1,
        [1, file_msg.arg(), 9, 0, 0, 0],
    );
    assert_eq!(
        (file_write_route, file_write_ret),
        (CompletionRoute::Forward, 9),
        "x86 child write(1) after dup3(3, 1) must stage against fd-core instead of failing preflight_host_crossing"
    );

    #[cfg(target_os = "linux")]
    let (epoll, events) = {
        // A native child creates this epoll in ring. Its wait must use the
        // same descriptor authority through the production CPL0 frame.
        let (route, epoll) = call_x86(&env, &child, &mut service, 291, [0; 6]);
        assert_eq!(route, CompletionRoute::Served);
        assert!(epoll >= 0);
        let events = GuestUserBuffer::zeroed(12);
        let live_identity = zone.record(child_record.id).identity();
        assert_eq!(
            live_identity,
            carrick_el1_linux::sched::identity_of(peer_task, live_identity.affinity)
        );
        let (route, result) = call_x86(
            &env,
            &child,
            &mut service,
            281,
            [epoll as u64, events.arg(), 1, 0, 0, 0],
        );
        assert_eq!(
            (route, result),
            (CompletionRoute::Served, 0),
            "canonical {:?}, ipc leaves {:?}",
            decode_x86_64(281, [0; 6], 0).canonical,
            counters
                .ipc_leaves
                .iter()
                .map(|c| c.load(Ordering::Relaxed))
                .collect::<Vec<_>>()
        );

        struct RestoreCopyFault;
        impl Drop for RestoreCopyFault {
            fn drop(&mut self) {
                carrick_el1::substrate::file::SIMULATE_COPY_FAULT
                    .with(|fault| fault.store(false, Ordering::Relaxed));
            }
        }
        let fault_result = {
            // The host fixture has no EL1 exception fixup. Inject at that
            // instruction boundary; the dispatch and input owner remain real.
            carrick_el1::substrate::file::SIMULATE_COPY_FAULT
                .with(|fault| fault.store(true, Ordering::Relaxed));
            let _restore = RestoreCopyFault;
            call_x86(
                &env,
                &child,
                &mut service,
                441,
                [epoll as u64, events.arg(), 1, 1, 0, 0],
            )
        };
        assert_eq!(
            fault_result,
            (CompletionRoute::Served, -14),
            "input owner EFAULT must replace the native ordinal in rax"
        );
        let (route, event) = call_x86(&env, &child, &mut service, 290, [0; 6]);
        assert_eq!(route, CompletionRoute::Served);
        assert!(event >= 0);
        let mut interest = [0u8; 12];
        interest[..4].copy_from_slice(&1u32.to_ne_bytes());
        interest[4..].copy_from_slice(&0x1671u64.to_ne_bytes());
        let interest = GuestUserBuffer::from_bytes(&interest);
        assert_eq!(
            call_x86(
                &env,
                &child,
                &mut service,
                233,
                [epoll as u64, 1, event as u64, interest.arg(), 0, 0]
            ),
            (CompletionRoute::Served, 0)
        );
        let value = GuestUserBuffer::from_value(1u64);
        assert_eq!(
            call_x86(
                &env,
                &child,
                &mut service,
                1,
                [event as u64, value.arg(), 8, 0, 0, 0]
            ),
            (CompletionRoute::Served, 8)
        );
        assert_eq!(
            call_x86(
                &env,
                &child,
                &mut service,
                281,
                [epoll as u64, events.arg(), 1, u64::MAX, 0, 0]
            ),
            (CompletionRoute::Served, 1)
        );
        assert_eq!(&events.as_bytes()[4..], &0x1671u64.to_ne_bytes());
        let read_value = GuestUserBuffer::zeroed(8);
        assert_eq!(
            call_x86(
                &env,
                &child,
                &mut service,
                0,
                [event as u64, read_value.arg(), 8, 0, 0, 0]
            ),
            (CompletionRoute::Served, 8)
        );
        let timeout = GuestUserBuffer::zeroed(16);
        assert_eq!(
            call_x86(
                &env,
                &child,
                &mut service,
                441,
                [epoll as u64, events.arg(), 1, timeout.arg(), 0, 0]
            ),
            (CompletionRoute::Served, 0)
        );

        (epoll, events)
    };

    // Two-live-process table isolation on x86 CPL0 while both root and child remain live:
    // Child closes fd 3; root's fd 3 stays open and root can dup(3) -> 4.
    let (_, child_close_3) = call_x86(&env, &child, &mut service, 3, [3, 0, 0, 0, 0, 0]);
    assert_eq!(child_close_3, 0);
    let (_, child_dup_closed) = call_x86(&env, &child, &mut service, 32, [3, 0, 0, 0, 0, 0]);
    assert_eq!(child_dup_closed, -9, "child closed fd 3 must return -EBADF");
    let (_, root_dup_3) = call_x86(&env, &root, &mut service, 32, [3, 0, 0, 0, 0, 0]);
    assert_eq!(
        root_dup_3, 4,
        "child close(3) must not close live root's fd 3"
    );
    // Root closes fd 1; child's redirected fd 1 stays open and dup(1) -> 3 in child.
    let (_, root_close_1) = call_x86(&env, &root, &mut service, 3, [1, 0, 0, 0, 0, 0]);
    assert_eq!(root_close_1, 0);
    let (_, root_dup_closed_1) = call_x86(&env, &root, &mut service, 32, [1, 0, 0, 0, 0, 0]);
    assert_eq!(root_dup_closed_1, -9);
    let (_, child_dup_1) = call_x86(&env, &child, &mut service, 32, [1, 0, 0, 0, 0, 0]);
    assert_eq!(
        child_dup_1, 3,
        "root close(1) must not close live child's fd 1"
    );
    #[cfg(target_os = "linux")]
    {
        let (wait_route, _) = call_x86(
            &env,
            &child,
            &mut service,
            281,
            [epoll as u64, events.arg(), 1, u64::MAX, 0, 0],
        );
        assert_eq!(wait_route, CompletionRoute::Suspended);
        assert!(zone.slot(peer_slot).current().is_none());
        assert!(zone.record(child_record.id).has_object_operation());
    }
}

// #2160: every epoll_pwait the ring hands to the host names its cause in
// `ipc_leaves`, on the production entry of both ISAs.
fn epoll_pwait_leave(
    x86: bool,
    with_venue: bool,
    work: bool,
    leave: carrick_el1_abi::IpcLeave,
) -> [u64; carrick_el1_abi::IpcLeave::COUNT] {
    use carrick_el1_abi::ipc::{IpcBacking, fd};
    use carrick_el1_linux::ipc::{IpcVenue, MapTables};
    use carrick_kernel::el1_ipc::{HostIpc, HostTable};
    use carrick_personality_linux::dispatch::CompletionRoute;
    use std::sync::Arc;

    let owner = Arc::new(HostIpc::new(1 << 20).unwrap());
    let table = HostTable::create(Arc::clone(&owner), 64, 8).unwrap();
    let object = owner.create_epoll().unwrap();
    let epoll = owner
        .admit_description(fd::Description::new(
            IpcBacking::Epoll { object }.encode(),
            fd::AccessMode::ReadWrite,
            fd::StatusFlags::default(),
        ))
        .unwrap();
    epoll.install(table.id(), fd::Fd(3), false).unwrap();
    let region = carrick_test_support::TestEl1Region::zeroed();
    // SAFETY: TestEl1Region provides ABI-aligned zeroed storage for this map.
    let map = unsafe {
        &*region
            .as_ptr()
            .add(carrick_el1_abi::EL1_IPC_TABLE_MAP_OFFSET as usize)
            .cast::<carrick_el1_abi::ipc_tables::IpcTableMap>()
    };
    map.publish_owned(7, table.id().to_raw()).unwrap();
    let tables = MapTables(map);
    let venue = IpcVenue {
        region: owner.region(),
        tables: &tables,
    };
    let task = CurrentTask::new();
    task.set(
        El1TaskId::from_linux_tid(41),
        carrick_el1_abi::SnapshotGeneration::from_raw(1),
        7,
    );
    if work {
        task.linux.mark_pending_host_work();
    }
    let counters = Counters::new();
    let names = InotifyNameCache::new();
    let events = carrick_test_support::GuestUserBuffer::zeroed(16);
    let args = [3, events.arg(), 1, 0, 0, 0];
    let mut arm = TrapFrame {
        esr: 0x15 << 26,
        elr: 0x4004,
        ..Default::default()
    };
    arm.x[8] = carrick_personality_linux::crossing::nr::EPOLL_PWAIT.raw();
    arm.x[..6].copy_from_slice(&args);
    let isa_unsupported = AtomicU64::new(0);
    let call = decode_x86_64(281, args, 0x7fff_0000);
    let mut amd = X86Frame {
        native: call.native,
        canonical: call.canonical,
        args,
        rax: 0xfeed,
        isa_unsupported: &isa_unsupported,
    };
    let ipc = with_venue.then_some(&venue);
    let route = if x86 {
        dispatch::dispatch_syscall_with_native::<
            _,
            NoCpu,
            sched::HardwareUserWord,
            _,
            carrick_el1_abi::Aarch64ParkedContext,
        >(
            &mut amd,
            &counters,
            core::slice::from_ref(&task),
            &[],
            &[],
            &[],
            &[],
            &names,
            None,
            ipc,
            None,
            None,
            None,
            None,
            |_| core::ptr::null_mut(),
        )
    } else {
        dispatch::dispatch_syscall_with_native::<
            _,
            NoCpu,
            sched::HardwareUserWord,
            _,
            carrick_el1_abi::Aarch64ParkedContext,
        >(
            &mut arm,
            &counters,
            core::slice::from_ref(&task),
            &[],
            &[],
            &[],
            &[],
            &names,
            None,
            ipc,
            None,
            None,
            None,
            None,
            |_| core::ptr::null_mut(),
        )
    };
    // Pending host work only changes how the unserved call is completed.
    assert!(
        matches!(route, CompletionRoute::Forward | CompletionRoute::WithWork),
        "x86={x86} venue={with_venue} work={work}: {route:?}"
    );
    let counts = core::array::from_fn(|i| counters.ipc_leaves[i].load(Ordering::Relaxed));
    assert_eq!(
        counts.iter().sum::<u64>(),
        1,
        "x86={x86} venue={with_venue} work={work}: exactly one named leave, got {:?}",
        carrick_el1_abi::IpcLeave::ALL
            .iter()
            .filter(|l| counts[**l as usize] != 0)
            .map(|l| l.name())
            .collect::<Vec<_>>()
    );
    assert_eq!(counts[leave as usize], 1, "x86={x86} venue={with_venue}");
    counts
}

#[test]
fn epoll_pwait_without_an_ipc_venue_is_a_counted_leave() {
    use carrick_el1_abi::IpcLeave::EpollNoVenue;
    for x86 in [false, true] {
        for work in [false, true] {
            epoll_pwait_leave(x86, false, work, EpollNoVenue);
        }
    }
}

#[test]
fn epoll_pwait_without_an_execution_binding_is_a_counted_leave() {
    use carrick_el1_abi::IpcLeave::EpollNoExecution;
    for x86 in [false, true] {
        epoll_pwait_leave(x86, true, false, EpollNoExecution);
    }
}
