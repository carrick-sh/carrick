//! The host build of the library uses the same Unavailable file authority as
//! the production CPL0 image. Keep the x86 no-venue routing out of cfg(test).
//!
//! This target shares carrick-el1-linux's dev-dependencies, which enable
//! `carrick-el1/host-test` for the library's unit tests. The claim still
//! holds: the no-venue routing is chosen by carrick-el1-linux's own
//! `cfg(any(test, feature = "host-test"))`, which is off for this target, and
//! carrick-el1's host-test items are test doubles, a bounded wake trace and
//! an unset copy-fault flag that production routing never selects. The
//! witnesses pass unchanged with that dev feature removed (#690 review).
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
}

fn at_empty_path_dispatch(x86: bool, case: AtEmptyPathCase) {
    use carrick_abi::{LINUX_AT_EMPTY_PATH, LINUX_AT_FDCWD, LinuxStat, LinuxX8664Stat};
    use carrick_el1_abi::ipc::{IpcBacking, fd, pipe::End};
    use carrick_el1_linux::ipc::{IpcVenue, MapTables};
    use carrick_kernel::el1_ipc::{HostIpc, HostTable};
    use carrick_personality_linux::dispatch::CompletionRoute;
    use carrick_personality_linux::native_host_file::{
        HostFileCall, HostFileStage, NativeNamespace,
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
    };
    let path = GuestUserBuffer::from_bytes(path);
    let output = GuestUserBuffer::zeroed(if x86 {
        core::mem::size_of::<LinuxX8664Stat>()
    } else {
        core::mem::size_of::<LinuxStat>()
    });
    let args = [
        dirfd as u64,
        path.arg(),
        output.arg(),
        LINUX_AT_EMPTY_PATH,
        0,
        0,
    ];
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
    if matches!(case, AtEmptyPathCase::Pipe) {
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
